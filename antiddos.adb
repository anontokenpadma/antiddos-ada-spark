--  rideconnect.adb
--  =====================================================================
--  Layer-7 DDoS-protecting reverse proxy written in Ada 2022 / SPARK.
--  Single source file; builds to a single static executable.
--
--  Usage:  rideconnect LISTEN_PORT TARGET_HOST TARGET_PORT
--  e.g.:   rideconnect 8080 127.0.0.1 3000
--
--  Protection implemented (all at HTTP layer 7):
--    * per-IP token-bucket rate limiting              (SPARK-proved core)
--    * per-IP and total concurrent connection caps
--    * request head / URI / body size limits
--    * header-read timeout (slowloris), keep-alive idle timeout
--    * strict request parsing: method whitelist, HTTP/1.0-1.1 only,
--      Host required for 1.1, obs-fold rejection, duplicate or comma
--      Content-Length rejection, TE+CL smuggling defense, chunked
--      body size capping
--    * backend connect/read/send timeouts, response framing aware
--      relay (Content-Length / chunked / close-delimited), HTTP
--      keep-alive with per-connection request cap
--  =====================================================================

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Calendar;
with Ada.Real_Time;
with Ada.Exceptions;
with Ada.Streams;
with GNAT.Sockets;
with GNAT.OS_Lib;

procedure Rideconnect with SPARK_Mode => On is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;

   subtype Byte is Ada.Streams.Stream_Element;
   subtype Byte_Array is Ada.Streams.Stream_Element_Array;
   subtype SEO is Ada.Streams.Stream_Element_Offset;

   --  ===================== Configuration =====================

   Max_Head_Size    : constant SEO := 16 * 1024;
   Max_Uri_Size     : constant SEO := 8 * 1024;
   Max_Chunk_Line   : constant SEO := 1 * 1024;
   Max_Error_Buf    : constant SEO := 1024;
   Rly_Size         : constant SEO := 16 * 1024;
   Reader_Buf_Size  : constant SEO := 16 * 1024;
   Max_Buckets      : constant := 4096;

   subtype Head_Buffer is Byte_Array (1 .. Max_Head_Size);

   type Config_Type is record
      Rate            : Positive := 20;               -- tokens per second per IP
      Burst           : Positive := 40;               -- token bucket capacity
      Max_Per_IP      : Positive := 16;               -- max concurrent conns per IP
      Max_Total       : Positive := 1024;             -- max concurrent conns total
      Max_Body        : Natural  := 4 * 1024 * 1024;  -- max request body size
      Max_Reqs        : Positive := 200;              -- max requests per connection
      Header_Timeout  : Duration := 10.0;             -- request head read (slowloris)
      Idle_Timeout    : Duration := 30.0;             -- keep-alive idle timeout
      Backend_Timeout : Duration := 30.0;             -- backend read/send timeout
      Connect_Timeout : Duration := 5.0;              -- backend connect timeout
   end record;

   --  ===================== Http_Parser (SPARK) =====================

   package Http_Parser is

      type Http_Method is
        (M_GET, M_POST, M_PUT, M_DELETE, M_HEAD, M_OPTIONS, M_PATCH, M_UNKNOWN);

      type Http_Version is (V_1_0, V_1_1, V_UNKNOWN);

      type Line_Info is record
         Valid     : Boolean := False;
         Method    : Http_Method := M_UNKNOWN;
         Version   : Http_Version := V_UNKNOWN;
         Uri_Start : SEO := 0;
         Uri_Last  : SEO := 0;
         Line_End  : SEO := 0;    -- index of LF that ends the request line
         Is_1_1    : Boolean := False;
      end record;

      type Header_Info is record
         Valid          : Boolean := False;
         Has_Host       : Boolean := False;
         Has_Content_Length : Boolean := False;
         Content_Length : Natural := 0;   -- sentinel 1_000_000_001 if clamped
         Chunked        : Boolean := False;
         Bad_Transfer_Encoding : Boolean := False;
         Expect_100     : Boolean := False;
         Has_Close      : Boolean := False;
         Has_Keep_Alive : Boolean := False;
      end record;

      type Framing is (Frame_By_Length, Frame_Chunked, Frame_Close, Frame_None);

      type Response_Info is record
         Valid           : Boolean := False;
         Status          : Natural := 0;
         Is_1xx          : Boolean := False;
         Frame_Kind      : Framing := Frame_None;
         Body_Length     : Natural := 0;
         Connection_Close : Boolean := False;
      end record;

      function Find_Head_End
        (Buf : Byte_Array; Start, Last : SEO) return SEO;
      --  Index of last byte of the blank-line terminator (CRLFCRLF or LFLF),
      --  or 0 when the terminator is not present in Buf (Start .. Last).

      function Parse_Request_Line
        (Buf : Byte_Array; Start, Last : SEO) return Line_Info;
      --  Parse "METHOD SP URI SP HTTP/x.y" located at the start of the head.
      --  Last is the head end index as returned by Find_Head_End.

      function Scan_Headers
        (Buf : Byte_Array; Start, Last : SEO) return Header_Info;
      --  Validate and extract fields from all header lines in [Start, Last].

      function Parse_Response
        (Buf : Byte_Array; Start, Last : SEO; Method_Is_Head : Boolean)
         return Response_Info;
      --  Parse "HTTP/x.y STATUS ..." plus headers and derive body framing.

      function Parse_Hex
        (Buf : Byte_Array; Start, Last : SEO) return Natural;
      --  Hex digits in [Start, Last] (stop at ';' or CR/LF); 0 if invalid.
      --  A leading '0' followed by ';'/CR/LF yields 0 (valid last-chunk).

   end Http_Parser;

   package body Http_Parser is

      function Is_Digit (B : Byte) return Boolean is
        (B >= Byte (Character'Pos ('0')) and then B <= Byte (Character'Pos ('9')));

      function Is_Upper (B : Byte) return Boolean is
        (B >= Byte (Character'Pos ('A')) and then B <= Byte (Character'Pos ('Z')));

      function Is_Token_Char (B : Byte) return Boolean is
        (B >= Byte (Character'Pos ('!')) and then B <= Byte (Character'Pos ('~'))
         and then B /= Byte (Character'Pos (ASCII.DEL)));

      function Is_Value_Char (B : Byte) return Boolean is
        (B = Byte (Character'Pos (ASCII.HT)) or else
         (B >= Byte (Character'Pos (' ')) and then
          B /= Byte (Character'Pos (ASCII.DEL))));

      function Is_Uri_Char (B : Byte) return Boolean is
        (B >= Byte (Character'Pos ('!')) and then B <= Byte (Character'Pos ('~'))
         and then B /= Byte (Character'Pos ('#')));

      function Char_Upper (B : Byte) return Byte is
        (if B >= Byte (Character'Pos ('a')) and then B <= Byte (Character'Pos ('z'))
         then B - 32 else B);

      function Char_Equal_CI (B : Byte; C : Character) return Boolean is
        (Char_Upper (B) = Char_Upper (Byte (Character'Pos (C))));

      function Matches
        (Buf : Byte_Array; Pos : SEO; S : String) return Boolean
      is
      begin
         if Pos < Buf'First or else Pos + SEO (S'Length) - 1 > Buf'Last then
            return False;
         end if;
         for K in S'Range loop
            if Buf (Pos + SEO (K - S'First)) /= Byte (Character'Pos (S (K))) then
               return False;
            end if;
            pragma Loop_Invariant
              (Pos + SEO (K - S'First) in Pos .. Pos + SEO (S'Length) - 1);
         end loop;
         return True;
      end Matches;

      function Matches_CI
        (Buf : Byte_Array; Pos : SEO; S : String) return Boolean
      is
      begin
         if Pos < Buf'First or else Pos + SEO (S'Length) - 1 > Buf'Last then
            return False;
         end if;
         for K in S'Range loop
            if not Char_Equal_CI (Buf (Pos + SEO (K - S'First)), S (K)) then
               return False;
            end if;
            pragma Loop_Invariant
              (Pos + SEO (K - S'First) in Pos .. Pos + SEO (S'Length) - 1);
         end loop;
         return True;
      end Matches_CI;

      function Name_Matches
        (Buf : Byte_Array; S, L : SEO; Name : String) return Boolean
      is
      begin
         if S < Buf'First or else L > Buf'Last or else L < S then
            return False;
         end if;
         if L - S + 1 /= SEO (Name'Length) then
            return False;
         end if;
         for K in Name'Range loop
            if not Char_Equal_CI (Buf (S + SEO (K - Name'First)), Name (K)) then
               return False;
            end if;
            pragma Loop_Invariant (S + SEO (K - Name'First) in S .. L);
         end loop;
         return True;
      end Name_Matches;

      function Find_Byte
        (Buf : Byte_Array; S, L : SEO; C : Byte) return SEO
      is
      begin
         for I in S .. L loop
            if Buf (I) = C then
               return I;
            end if;
            pragma Loop_Invariant (for all J in S .. I - 1 => Buf (J) /= C);
         end loop;
         return 0;
      end Find_Byte;

      function Contains_Token_CI
        (Buf : Byte_Array; S, L : SEO; Tok : String) return Boolean
      is
         I : SEO := S;
      begin
         if S > L then
            return False;
         end if;         while I <= L loop
            pragma Loop_Invariant (I in S .. L + 1);
            pragma Loop_Variant (Increases => I);
            if Buf (I) = Byte (Character'Pos (','))
              or else Buf (I) = Byte (Character'Pos (' '))
              or else Buf (I) = Byte (Character'Pos (ASCII.HT))
            then
               I := I + 1;
            else
               declare
                  J : SEO := I;
               begin
                  while J <= L
                    and then Buf (J) /= Byte (Character'Pos (','))
                    and then Buf (J) /= Byte (Character'Pos (' '))


                    and then Buf (J) /= Byte (Character'Pos (ASCII.HT))
                  loop
                     pragma Loop_Invariant (J in I .. L + 1);
                     pragma Loop_Variant (Increases => J);
                     J := J + 1;
                  end loop;
                  if J - I = SEO (Tok'Length)
                    and then Matches_CI (Buf, I, Tok)
                  then
                     return True;
                  end if;
                  I := J + 1;
               end;
            end if;
         end loop;
         return False;
      end Contains_Token_CI;

      type Decimal_Result is record
         Valid   : Boolean := False;
         Value   : Natural := 0;
      end record;

      Clamp_Max : constant := 1_000_000_000;
      Clamp_Sentinel : constant Natural := 1_000_000_001;

      function Parse_Decimal
        (Buf : Byte_Array; S, L : SEO) return Decimal_Result
      is
         Res : Decimal_Result;
         V : Long_Long_Integer := 0;
      begin
         if S > L then
            return Res;
         end if;
         for I in S .. L loop
            if not Is_Digit (Buf (I)) then
               return Res;
            end if;
            V := V * 10 + Long_Long_Integer (Buf (I) - 48);
            pragma Loop_Invariant (V >= 0);
            if V > Clamp_Max then
               Res.Valid := True;
               Res.Value := Clamp_Sentinel;
               return Res;
            end if;
         end loop;
         Res.Valid := True;
         Res.Value := Natural (V);
         return Res;
      end Parse_Decimal;

      function Find_Head_End
        (Buf : Byte_Array; Start, Last : SEO) return SEO
      is
      begin
         if Start > Last or else Start < Buf'First or else Last > Buf'Last then
            return 0;
         end if;
         for I in Start .. Last - 1 loop
            pragma Loop_Invariant (I in Start .. Last - 1);
            if I + 3 <= Last
              and then Buf (I) = 13 and then Buf (I + 1) = 10
              and then Buf (I + 2) = 13 and then Buf (I + 3) = 10
            then
               return I + 3;
            end if;
            if I + 1 <= Last
              and then Buf (I) = 10 and then Buf (I + 1) = 10
            then
               return I + 1;
            end if;
         end loop;
         return 0;
      end Find_Head_End;

      function Parse_Hex
        (Buf : Byte_Array; Start, Last : SEO) return Natural
      is
         V : Long_Long_Integer := 0;
         D : Long_Long_Integer;
      begin
         if Start > Last then
            return 0;
         end if;
         for I in Start .. Last loop
            pragma Loop_Invariant (V >= 0 and then V <= 2**31);
            exit when Buf (I) = Byte (Character'Pos (';'))
              or else Buf (I) = 13 or else Buf (I) = 10;
            if Is_Digit (Buf (I)) then
               D := Long_Long_Integer (Buf (I) - 48);
            elsif Buf (I) >= Byte (Character'Pos ('a'))
              and then Buf (I) <= Byte (Character'Pos ('f'))
            then
               D := Long_Long_Integer (Buf (I) - 87);
            elsif Buf (I) >= Byte (Character'Pos ('A'))
              and then Buf (I) <= Byte (Character'Pos ('F'))
            then
               D := Long_Long_Integer (Buf (I) - 55);
            else
               return 0;
            end if;
            V := V * 16 + D;
            if V > 2**31 then
               return 0;
            end if;
         end loop;
         return Natural (V);
      end Parse_Hex;

      function Parse_Request_Line
        (Buf : Byte_Array; Start, Last : SEO) return Line_Info
      is
         Res : Line_Info;
         Line_End : SEO;
         Cont_Last : SEO;
         I : SEO;
         M_Len : SEO;
      begin
         if Start < Buf'First or else Last > Buf'Last or else Start > Last then
            return Res;
         end if;
         Line_End := Find_Byte (Buf, Start, Last, 10);
         if Line_End = 0 then
            return Res;
         end if;
         Res.Line_End := Line_End;
         Cont_Last := Line_End - 1;
         if Buf (Cont_Last) = 13 then
            Cont_Last := Cont_Last - 1;
         end if;
         if Cont_Last < Start then
            return Res;
         end if;
         --  Method: run of uppercase letters
         I := Start;
         while I <= Cont_Last and then Is_Upper (Buf (I)) loop
            pragma Loop_Invariant (I in Start .. Cont_Last + 1);
            pragma Loop_Variant (Increases => I);
            I := I + 1;
         end loop;
         M_Len := I - Start;
         if M_Len < 3 or else M_Len > 7 then
            return Res;
         end if;
         if M_Len = 3 and then Matches (Buf, Start, "GET") then
            Res.Method := M_GET;
         elsif M_Len = 4 and then Matches (Buf, Start, "POST") then
            Res.Method := M_POST;
         elsif M_Len = 4 and then Matches (Buf, Start, "HEAD") then
            Res.Method := M_HEAD;
         elsif M_Len = 3 and then Matches (Buf, Start, "PUT") then
            Res.Method := M_PUT;
         elsif M_Len = 6 and then Matches (Buf, Start, "DELETE") then
            Res.Method := M_DELETE;
         elsif M_Len = 7 and then Matches (Buf, Start, "OPTIONS") then
            Res.Method := M_OPTIONS;
         elsif M_Len = 5 and then Matches (Buf, Start, "PATCH") then
            Res.Method := M_PATCH;
         else
            Res.Method := M_UNKNOWN;
         end if;
         if I > Cont_Last or else Buf (I) /= 32 then
            return Res;
         end if;
         while I <= Cont_Last and then Buf (I) = 32 loop
            pragma Loop_Invariant (I in Start .. Cont_Last + 1);
            pragma Loop_Variant (Increases => I);
            I := I + 1;
         end loop;
         --  URI
         if I > Cont_Last then
            return Res;
         end if;
         Res.Uri_Start := I;
         while I <= Cont_Last and then Is_Uri_Char (Buf (I)) loop
            pragma Loop_Invariant (I in Start .. Cont_Last + 1);
            pragma Loop_Variant (Increases => I);
            I := I + 1;
         end loop;
         Res.Uri_Last := I - 1;
         if Buf (Res.Uri_Start) /= Byte (Character'Pos ('/')) then
            return Res;
         end if;
         if I > Cont_Last or else Buf (I) /= 32 then
            return Res;
         end if;
         while I <= Cont_Last and then Buf (I) = 32 loop
            pragma Loop_Invariant (I in Start .. Cont_Last + 1);
            pragma Loop_Variant (Increases => I);
            I := I + 1;
         end loop;
         --  Version
         if I + 7 > Cont_Last then
            return Res;
         end if;
         if Matches (Buf, I, "HTTP/") then
            if Matches (Buf, I, "HTTP/1.0") then
               Res.Version := V_1_0;
               I := I + 8;
            elsif Matches (Buf, I, "HTTP/1.1") then
               Res.Version := V_1_1;
               I := I + 8;
            else
               Res.Version := V_UNKNOWN;
               I := Cont_Last + 1;
            end if;
         else
            return Res;
         end if;
         if I - 1 /= Cont_Last then
            return Res;
         end if;
         Res.Is_1_1 := Res.Version = V_1_1;
         Res.Valid := True;
         return Res;
      end Parse_Request_Line;

      function Scan_Headers
        (Buf : Byte_Array; Start, Last : SEO) return Header_Info
      is
         Res : Header_Info;
         I : SEO := Start;
      begin
         Res.Valid := True;
         if Start > Last then
            Res.Valid := False;
            return Res;
         end if;
         while I <= Last loop
            pragma Loop_Invariant (I in Start .. Last + 1);
            pragma Loop_Variant (Increases => I);
            --  Blank line ends the header block
            if Buf (I) = 10 then
               exit;
            end if;
            if Buf (I) = 13 and then I + 1 <= Last and then Buf (I + 1) = 10 then
               exit;
            end if;
            --  Reject obs-fold (continuation line)
            if Buf (I) = 32 or else Buf (I) = Byte (Character'Pos (ASCII.HT)) then
               Res.Valid := False;
               exit;
            end if;
            declare
               Line_End : constant SEO := Find_Byte (Buf, I, Last, 10);
               Colon : SEO;
               VStart, VEnd : SEO;
               Name_Ok : Boolean := True;
               Val_Ok : Boolean := True;
            begin
               if Line_End = 0 then
                  Res.Valid := False;
                  exit;
               end if;
               Colon := Find_Byte (Buf, I, Line_End - 1, Byte (Character'Pos (':')));
               if Colon = 0 then
                  Res.Valid := False;
                  exit;
               end if;
               for K in I .. Colon - 1 loop
                  if not Is_Token_Char (Buf (K)) then
                     Name_Ok := False;
                  end if;
                  pragma Loop_Invariant (K in I .. Colon - 1);
               end loop;
               VStart := Colon + 1;
               while VStart <= Line_End - 1
                 and then (Buf (VStart) = 32
                           or else Buf (VStart) = Byte (Character'Pos (ASCII.HT)))
               loop
                  pragma Loop_Invariant (VStart in Colon + 1 .. Line_End);
                  VStart := VStart + 1;
               end loop;
               VEnd := Line_End - 1;
               if VEnd >= VStart and then Buf (VEnd) = 13 then
                  VEnd := VEnd - 1;
               end if;
               while VEnd >= VStart
                 and then (Buf (VEnd) = 32
                           or else Buf (VEnd) = Byte (Character'Pos (ASCII.HT)))
               loop
                  pragma Loop_Invariant (VEnd in VStart - 1 .. Line_End - 1);
                  VEnd := VEnd - 1;
               end loop;
               for K in VStart .. VEnd loop
                  if not Is_Value_Char (Buf (K)) then
                     Val_Ok := False;
                  end if;
                  pragma Loop_Invariant (K in VStart .. VEnd);
               end loop;
               if not Name_Ok or else not Val_Ok then
                  Res.Valid := False;
                  exit;
               end if;
               if Name_Matches (Buf, I, Colon - 1, "host") then
                  if VEnd < VStart then
                     Res.Valid := False;
                     exit;
                  end if;
                  Res.Has_Host := True;
               elsif Name_Matches (Buf, I, Colon - 1, "content-length") then
                  if Res.Has_Content_Length then
                     Res.Valid := False;
                     exit;
                  end if;
                  declare
                     D : constant Decimal_Result := Parse_Decimal (Buf, VStart, VEnd);
                  begin
                     if not D.Valid then
                        Res.Valid := False;
                        exit;
                     end if;
                     Res.Has_Content_Length := True;
                     Res.Content_Length := D.Value;
                  end;
               elsif Name_Matches (Buf, I, Colon - 1, "transfer-encoding") then
                  if Contains_Token_CI (Buf, VStart, VEnd, "chunked") then
                     if Res.Chunked then
                        Res.Valid := False;
                        exit;
                     end if;
                     Res.Chunked := True;
                  else
                     Res.Bad_Transfer_Encoding := True;
                  end if;
               elsif Name_Matches (Buf, I, Colon - 1, "connection") then
                  if Contains_Token_CI (Buf, VStart, VEnd, "close") then
                     Res.Has_Close := True;
                  end if;
                  if Contains_Token_CI (Buf, VStart, VEnd, "keep-alive") then
                     Res.Has_Keep_Alive := True;
                  end if;
               elsif Name_Matches (Buf, I, Colon - 1, "expect") then
                  if Contains_Token_CI (Buf, VStart, VEnd, "100-continue") then
                     Res.Expect_100 := True;
                  end if;
               end if;
               I := Line_End + 1;
            end;
         end loop;
         return Res;
      end Scan_Headers;

      function Parse_Response
        (Buf : Byte_Array; Start, Last : SEO; Method_Is_Head : Boolean)
         return Response_Info
      is
         Res : Response_Info;
         Line_End : SEO;
         I : SEO;
         Hdrs : Header_Info;
      begin
         if Start < Buf'First or else Last > Buf'Last or else Start > Last then
            return Res;
         end if;
         Line_End := Find_Byte (Buf, Start, Last, 10);
         if Line_End = 0 or else Line_End - Start < 11 then
            return Res;
         end if;
         if not Matches (Buf, Start, "HTTP/") then
            return Res;
         end if;
         if not Is_Digit (Buf (Start + 5)) or else Buf (Start + 6) /= 46
           or else not Is_Digit (Buf (Start + 7))
         then
            return Res;
         end if;
         I := Start + 8;
         if Buf (I) /= 32 then
            return Res;
         end if;
         if I + 3 > Line_End - 1 then
            return Res;
         end if;
         if not Is_Digit (Buf (I + 1)) or else not Is_Digit (Buf (I + 2))
           or else not Is_Digit (Buf (I + 3))
         then
            return Res;
         end if;
         Res.Status := Natural (Buf (I + 1) - 48) * 100
                     + Natural (Buf (I + 2) - 48) * 10
                     + Natural (Buf (I + 3) - 48);
         Res.Valid := True;
         Res.Is_1xx := Res.Status in 100 .. 199;
         Hdrs := Scan_Headers (Buf, Line_End + 1, Last);
         if not Hdrs.Valid then
            Res.Valid := False;
            return Res;
         end if;
         Res.Connection_Close := Hdrs.Has_Close;
         if Method_Is_Head or else Res.Status in 100 .. 199
           or else Res.Status = 204 or else Res.Status = 304
         then
            Res.Frame_Kind := Frame_None;
         elsif Hdrs.Chunked then
            Res.Frame_Kind := Frame_Chunked;
         elsif Hdrs.Has_Content_Length then
            Res.Frame_Kind := Frame_By_Length;
            Res.Body_Length := Hdrs.Content_Length;
         else
            Res.Frame_Kind := Frame_Close;
         end if;
         return Res;
      end Parse_Response;

   end Http_Parser;

   --  ===================== Rate_Limiter (SPARK) =====================

   package Rate_Limiter is

      type IP_Addr is array (1 .. 4) of Byte;

      type Token_Count is range 0 .. 1_000_000_000;
      type Time_Count is range 0 .. 2**62;

      subtype Bucket_Index is Integer range -1 .. Max_Buckets - 1;
      subtype Table_Index is Bucket_Index range 0 .. Max_Buckets - 1;
      Not_Found : constant Bucket_Index := -1;

      type Bucket is record
         Active : Boolean := False;
         IP     : IP_Addr := [others => 0];
         Tokens : Token_Count := 0;
         Last   : Time_Count := 0;
      end record;

      type Bucket_Table is array (Table_Index) of Bucket;

      function Find
        (T : Bucket_Table; IP : IP_Addr) return Bucket_Index;

      procedure Consume
        (T       : in out Bucket_Table;
         IP      : IP_Addr;
         Now     : Time_Count;
         Rate    : Token_Count;
         Burst   : Token_Count;
         Allowed : out Boolean)
      with
        Pre => Rate >= 1 and then Rate <= 10_000
          and then Burst >= Rate and then Burst <= 1_000_000;

      function Retry_After
        (T : Bucket_Table; IP : IP_Addr; Now : Time_Count; Rate : Token_Count)
         return Natural
      with
        Pre => Rate >= 1 and then Rate <= 10_000;

   end Rate_Limiter;

   package body Rate_Limiter is

      Max_Elapsed : constant Time_Count := 3600;

      function Find
        (T : Bucket_Table; IP : IP_Addr) return Bucket_Index
      is
      begin
         for I in Table_Index loop
            if T (I).Active and then T (I).IP = IP then
               return I;
            end if;
            pragma Loop_Invariant (I in Table_Index'First .. Table_Index'Last);
         end loop;
         return Not_Found;
      end Find;

      function Find_Free_Or_Evict (T : Bucket_Table) return Table_Index is
         Min_I : Table_Index := 0;
      begin
         for I in Table_Index loop
            if not T (I).Active then
               return I;
            end if;
            pragma Loop_Invariant (I in Table_Index'First .. Table_Index'Last);
         end loop;
         for I in Table_Index'Succ (Table_Index'First) .. Table_Index'Last loop
            if T (I).Last < T (Min_I).Last then
               Min_I := I;
            end if;
            pragma Loop_Invariant (Min_I in Table_Index'First .. Table_Index'Last);
         end loop;
         return Min_I;
      end Find_Free_Or_Evict;

      procedure Consume
        (T       : in out Bucket_Table;
         IP      : IP_Addr;
         Now     : Time_Count;
         Rate    : Token_Count;
         Burst   : Token_Count;
         Allowed : out Boolean)
      is
         Idx : Bucket_Index;
      begin
         Idx := Find (T, IP);
         if Idx = Not_Found then
            Idx := Find_Free_Or_Evict (T);
            T (Idx) := (Active => True, IP => IP,
                        Tokens => Burst - 1, Last => Now);
            Allowed := True;
         else
            declare
               Elapsed : Token_Count;
               Added   : Token_Count;
            begin
               if Now >= T (Idx).Last then
                  if Now - T (Idx).Last >= Max_Elapsed then
                     Elapsed := Token_Count (Max_Elapsed);
                  else
                     Elapsed := Token_Count (Now - T (Idx).Last);
                  end if;
               else
                  Elapsed := 0;
               end if;
               Added := Elapsed * Rate;
               T (Idx).Tokens := Token_Count'Min (Burst, T (Idx).Tokens + Added);
               T (Idx).Last := Now;
               if T (Idx).Tokens >= 1 then
                  T (Idx).Tokens := T (Idx).Tokens - 1;
                  Allowed := True;
               else
                  Allowed := False;
               end if;
            end;
         end if;
      end Consume;

      function Retry_After
        (T : Bucket_Table; IP : IP_Addr; Now : Time_Count; Rate : Token_Count)
         return Natural
      is
         Idx : constant Bucket_Index := Find (T, IP);
         Tok : Token_Count;
         Elapsed : Token_Count;
      begin
         if Idx = Not_Found then
            return 0;
         end if;
         Tok := T (Idx).Tokens;
         if Now >= T (Idx).Last then
            if Now - T (Idx).Last >= Max_Elapsed then
               Elapsed := Token_Count (Max_Elapsed);
            else
               Elapsed := Token_Count (Now - T (Idx).Last);
            end if;
            Tok := Token_Count'Min (1_000_000,
                                    Tok + Elapsed * Rate);
         end if;
         if Tok >= 1 then
            return 0;
         end if;
         return Natural ((1 - Tok) / Rate) + 1;
      end Retry_After;

   end Rate_Limiter;

   --  ===================== Errors (SPARK) =====================

   package Errors is

      type Error_Kind is
        (E_Bad_Request, E_Method_Not_Allowed, E_Timeout, E_Payload_Too_Large,
         E_Uri_Too_Long, E_Too_Many_Requests, E_Header_Too_Large,
         E_Not_Implemented, E_Unavailable, E_Bad_Gateway, E_Gateway_Timeout,
         E_Version_Not_Supported);

      procedure Build
        (Kind        : Error_Kind;
         Retry_After : Natural;
         Buf         : in out Byte_Array;
         Len         : out SEO)
      with
        Pre => Buf'Length >= Max_Error_Buf;

   end Errors;

   package body Errors is

      function Code_Of (Kind : Error_Kind) return Natural is
        (case Kind is
            when E_Bad_Request => 400,
            when E_Method_Not_Allowed => 405,
            when E_Timeout => 408,
            when E_Payload_Too_Large => 413,
            when E_Uri_Too_Long => 414,
            when E_Too_Many_Requests => 429,
            when E_Header_Too_Large => 431,
            when E_Not_Implemented => 501,
            when E_Unavailable => 503,
            when E_Bad_Gateway => 502,
            when E_Gateway_Timeout => 504,
            when E_Version_Not_Supported => 505);

      function Reason_Of (Kind : Error_Kind) return String is
        (case Kind is
            when E_Bad_Request => "Bad Request",
            when E_Method_Not_Allowed => "Method Not Allowed",
            when E_Timeout => "Request Timeout",
            when E_Payload_Too_Large => "Payload Too Large",
            when E_Uri_Too_Long => "URI Too Long",
            when E_Too_Many_Requests => "Too Many Requests",
            when E_Header_Too_Large => "Request Header Fields Too Large",
            when E_Not_Implemented => "Not Implemented",
            when E_Unavailable => "Service Unavailable",
            when E_Bad_Gateway => "Bad Gateway",
            when E_Gateway_Timeout => "Gateway Timeout",
            when E_Version_Not_Supported => "HTTP Version Not Supported");

      procedure Put
        (Buf : in out Byte_Array; Pos : in out SEO; S : String)
        with
          Pre => Pos >= Buf'First
            and then Pos + SEO (S'Length) - 1 <= Buf'Last;

      procedure Put
        (Buf : in out Byte_Array; Pos : in out SEO; S : String)
      is
      begin
         for K in S'Range loop
            Buf (Pos) := Byte (Character'Pos (S (K)));
            Pos := Pos + 1;
            pragma Loop_Invariant (Pos <= Buf'Last + 1);
         end loop;
      end Put;

      procedure Put_Int
        (Buf : in out Byte_Array; Pos : in out SEO; V : Natural)
        with
          Pre => Pos >= Buf'First and then Pos + 10 <= Buf'Last;

      procedure Put_Int
        (Buf : in out Byte_Array; Pos : in out SEO; V : Natural)
      is
         Digs : String (1 .. 10);
         N : Natural := V;
         D : Natural := 0;
      begin
         if V = 0 then
            Buf (Pos) := 48;
            Pos := Pos + 1;
            return;
         end if;
         while N > 0 loop
            D := D + 1;
            Digs (D) := Character'Val (48 + N mod 10);
            N := N / 10;
            pragma Loop_Invariant (D in 1 .. 10 and then N >= 0);
         end loop;
         for K in reverse 1 .. D loop
            Buf (Pos) := Byte (Character'Pos (Digs (K)));
            Pos := Pos + 1;
            pragma Loop_Invariant (Pos <= Buf'Last + 1);
         end loop;
      end Put_Int;

      procedure Build
        (Kind        : Error_Kind;
         Retry_After : Natural;
         Buf         : in out Byte_Array;
         Len         : out SEO)
      is
         Pos : SEO := Buf'First;
         Reason : constant String := Reason_Of (Kind);
         Body_T : constant String := Natural'Image (Code_Of (Kind))
                   & " " & Reason & ASCII.LF;
         Code : constant Natural := Code_Of (Kind);
      begin
         Put (Buf, Pos, "HTTP/1.1 ");
         Put_Int (Buf, Pos, Code);
         Put (Buf, Pos, " ");
         Put (Buf, Pos, Reason);
         Put (Buf, Pos, ASCII.CR & ASCII.LF);
         if Kind = E_Too_Many_Requests then
            Put (Buf, Pos, "Retry-After: ");
            Put_Int (Buf, Pos, Retry_After);
            Put (Buf, Pos, ASCII.CR & ASCII.LF);
         end if;
         if Kind = E_Method_Not_Allowed then
            Put (Buf, Pos,
                 "Allow: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH"
                 & ASCII.CR & ASCII.LF);
         end if;
         Put (Buf, Pos, "Content-Type: text/plain" & ASCII.CR & ASCII.LF);
         Put (Buf, Pos, "Content-Length: ");
         Put_Int (Buf, Pos, Body_T'Length);
         Put (Buf, Pos, ASCII.CR & ASCII.LF & ASCII.CR & ASCII.LF);
         Put (Buf, Pos, Body_T);
         Len := Pos - 1;
      end Build;

   end Errors;

   --  ===================== IO (spec; body is SPARK Off) =====================

   package IO is

      function Now_Seconds return Rate_Limiter.Time_Count;
      function Arg_Count return Natural;
      function Get_Arg (N : Positive) return String;
      function Get_Env (Name : String) return String;
      procedure Print_Usage;
      procedure Run
        (Listen_Port : Positive;
         Target_Host : String;
         Target_Port : Positive;
         Cfg         : Config_Type);

   end IO;

   --  ===================== Cli (SPARK) =====================

   package Cli is

      Max_Host_Len : constant := 255;

      type Args_Info is record
         Ok          : Boolean := False;
         Listen_Port : Natural := 0;
         Target_Port : Natural := 0;
         Host_Len    : Natural := 0;
         Host        : String (1 .. Max_Host_Len) := [others => ' '];
      end record;

      function Parse_Unsigned (S : String; Max : Natural) return Natural
        with Post =>
          (if Parse_Unsigned'Result /= 0
           then Parse_Unsigned'Result in 1 .. Max);
      --  0 when S is not a valid decimal number in 1 .. Max.

      function Parse_Args (A1, A2, A3 : String) return Args_Info
        with Post =>
          (if Parse_Args'Result.Ok then
             Parse_Args'Result.Listen_Port in 1 .. 65535 and
             Parse_Args'Result.Target_Port in 1 .. 65535 and
             Parse_Args'Result.Host_Len  in 1 .. Max_Host_Len);

      function Load_Config return Config_Type;

   end Cli;

   package body Cli is

      function Parse_Unsigned (S : String; Max : Natural) return Natural is
         V : Long_Long_Integer := 0;
         Started : Boolean := False;
      begin
         for K in S'Range loop
            pragma Loop_Invariant (V <= Long_Long_Integer (Max));
            if S (K) in '0' .. '9' then
               Started := True;
               V := V * 10 + Long_Long_Integer (Character'Pos (S (K)) - 48);
               if V > Long_Long_Integer (Max) then
                  return 0;
               end if;
            elsif S (K) = ' ' then
               null;  -- tolerate stray spaces
            else
               return 0;
            end if;
         end loop;
         if not Started or else V = 0 then
            return 0;
         end if;
         return Natural (V);
      end Parse_Unsigned;

      function Parse_Args (A1, A2, A3 : String) return Args_Info is
         Res : Args_Info;
         Ok_Host : Boolean := True;
      begin
         Res.Listen_Port := Parse_Unsigned (A1, 65535);
         Res.Target_Port := Parse_Unsigned (A3, 65535);
         if A2'Length < 1 or else A2'Length > Max_Host_Len then
            Ok_Host := False;
         else
            for K in A2'Range loop
               if A2 (K) < Character'Val (33) or else A2 (K) > Character'Val (126) then
                  Ok_Host := False;
               end if;
            end loop;
         end if;
         if Res.Listen_Port = 0 or else Res.Target_Port = 0 or else not Ok_Host then
            return Res;
         end if;
         Res.Host_Len := A2'Length;
         for K in A2'Range loop
            Res.Host (K - A2'First + 1) := A2 (K);
         end loop;
         Res.Ok := True;
         return Res;
      end Parse_Args;

      function Load_Config return Config_Type is
         C : Config_Type;
         V : Natural;
      begin
         V := Parse_Unsigned (IO.Get_Env ("RC_RATE"), 10_000);
         if V /= 0 then
            C.Rate := V;
         end if;
         V := Parse_Unsigned (IO.Get_Env ("RC_BURST"), 1_000_000);
         if V /= 0 then
            C.Burst := V;
         end if;
         if C.Burst < C.Rate then
            C.Burst := C.Rate;
         end if;
         V := Parse_Unsigned (IO.Get_Env ("RC_MAX_PER_IP"), 10_000);
         if V /= 0 then
            C.Max_Per_IP := V;
         end if;
         V := Parse_Unsigned (IO.Get_Env ("RC_MAX_TOTAL"), 100_000);
         if V /= 0 then
            C.Max_Total := V;
         end if;
         V := Parse_Unsigned (IO.Get_Env ("RC_MAX_BODY_MB"), 64);
         if V /= 0 then
            C.Max_Body := V * 1024 * 1024;
         end if;
         V := Parse_Unsigned (IO.Get_Env ("RC_MAX_REQS"), 10_000);
         if V /= 0 then
            C.Max_Reqs := V;
         end if;
         V := Parse_Unsigned (IO.Get_Env ("RC_HEADER_TIMEOUT"), 300);
         if V /= 0 then
            C.Header_Timeout := Duration (V);
         end if;
         V := Parse_Unsigned (IO.Get_Env ("RC_IDLE_TIMEOUT"), 3600);
         if V /= 0 then
            C.Idle_Timeout := Duration (V);
         end if;
         V := Parse_Unsigned (IO.Get_Env ("RC_BACKEND_TIMEOUT"), 3600);
         if V /= 0 then
            C.Backend_Timeout := Duration (V);
         end if;
         V := Parse_Unsigned (IO.Get_Env ("RC_CONNECT_TIMEOUT"), 300);
         if V /= 0 then
            C.Connect_Timeout := Duration (V);
         end if;
         return C;
      end Load_Config;

   end Cli;

   package body IO is
      pragma SPARK_Mode (Off);

      use GNAT.Sockets;
      use type GNAT.Sockets.Socket_Type;
      use type Http_Parser.Http_Method;
      use type Http_Parser.Http_Version;
      use type Http_Parser.Framing;
      use type Rate_Limiter.IP_Addr;

      type IO_Status is (IO_Ok, IO_Eof, IO_Timeout, IO_Too_Large, IO_Error);

      --  ---------- basic services ----------

      T0 : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;

      function Now_Seconds return Rate_Limiter.Time_Count is
         use Ada.Real_Time;
      begin
         return Rate_Limiter.Time_Count
           (Long_Long_Integer (To_Duration (Clock - T0)));
      end Now_Seconds;

      function Arg_Count return Natural is
      begin
         return Ada.Command_Line.Argument_Count;
      end Arg_Count;

      function Get_Arg (N : Positive) return String is
      begin
         return Ada.Command_Line.Argument (N);
      end Get_Arg;

      function Get_Env (Name : String) return String is
      begin
         return GNAT.OS_Lib.Getenv (Name).all;
      end Get_Env;

      procedure Print_Usage is
      begin
         Ada.Text_IO.Put_Line
           ("Usage: rideconnect LISTEN_PORT TARGET_HOST TARGET_PORT");
         Ada.Text_IO.Put_Line
           ("  e.g.: rideconnect 8080 127.0.0.1 3000");
         Ada.Text_IO.New_Line;
         Ada.Text_IO.Put_Line
           ("Layer-7 DDoS-protecting reverse proxy (Ada 2022 / SPARK).");
         Ada.Text_IO.New_Line;
         Ada.Text_IO.Put_Line ("Environment overrides (optional):");
         Ada.Text_IO.Put_Line
           ("  RC_RATE=20             tokens per second per client IP");
         Ada.Text_IO.Put_Line
           ("  RC_BURST=40            token bucket capacity (burst)");
         Ada.Text_IO.Put_Line
           ("  RC_MAX_PER_IP=16       max concurrent connections per IP");
         Ada.Text_IO.Put_Line
           ("  RC_MAX_TOTAL=1024      max concurrent connections total");
         Ada.Text_IO.Put_Line
           ("  RC_MAX_BODY_MB=4       max request body size (MB)");
         Ada.Text_IO.Put_Line
           ("  RC_MAX_REQS=200        max requests per connection");
         Ada.Text_IO.Put_Line
           ("  RC_HEADER_TIMEOUT=10   request-head read timeout, seconds");
         Ada.Text_IO.Put_Line
           ("  RC_IDLE_TIMEOUT=30     keep-alive idle timeout, seconds");
         Ada.Text_IO.Put_Line
           ("  RC_BACKEND_TIMEOUT=30  backend read/send timeout, seconds");
         Ada.Text_IO.Put_Line
           ("  RC_CONNECT_TIMEOUT=5   backend connect timeout, seconds");
      end Print_Usage;

      function Pad (V : Natural) return String is
         Img : constant String := Natural'Image (V);
      begin
         if V < 10 then
            return "0" & Img (2 .. Img'Last);
         end if;
         return Img (2 .. Img'Last);
      end Pad;

      procedure Log (Msg : String) is
         use Ada.Calendar;
         Now  : constant Time := Clock;
         Y    : Year_Number;
         M    : Month_Number;
         D    : Day_Number;
         Secs : Day_Duration;
         H, Mi, S : Natural;
      begin
         Split (Now, Y, M, D, Secs);
         H  := Natural (Secs) / 3600;
         Mi := (Natural (Secs) mod 3600) / 60;
         S  := Natural (Secs) mod 60;
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            Integer'Image (Integer (Y)) & "-" & Pad (Integer (M)) & "-"
            & Pad (Integer (D)) & " " & Pad (H) & ":" & Pad (Mi) & ":"
            & Pad (S) & "  " & Msg);
      end Log;

      --  ---------- low level socket helpers ----------

      procedure Set_Timeout (S : Socket_Type; T : Duration) is
      begin
         Set_Socket_Option (S, Socket_Level,
                            (Name => Receive_Timeout, Timeout => T));
         Set_Socket_Option (S, Socket_Level,
                            (Name => Send_Timeout, Timeout => T));
      end Set_Timeout;

      procedure Send_All
        (S : Socket_Type; Data : Byte_Array; Ok : out Boolean)
      is
         Pos : SEO := Data'First;
         Last : SEO;
      begin
         Ok := True;
         while Pos <= Data'Last loop
            Send_Socket (S, Data (Pos .. Data'Last), Last);
            if Last < Pos then
               Ok := False;
               return;
            end if;
            Pos := Last + 1;
         end loop;
      exception
         when Socket_Error =>
            Ok := False;
      end Send_All;

      procedure Recv_Some
        (S : Socket_Type; Buf : out Byte_Array;
         Count : out SEO; St : out IO_Status)
      is
         Last : SEO;
      begin
         Receive_Socket (S, Buf, Last);
         if Last >= Buf'First then
            Count := Last - Buf'First + 1;
            St := IO_Ok;
         else
            Count := 0;
            St := IO_Eof;
         end if;
      exception
         when Socket_Error =>
            Count := 0;
            St := IO_Timeout;
      end Recv_Some;

      --  ---------- buffered reader (chunked parsing) ----------

      type Reader is record
         S   : Socket_Type;
         Buf : Byte_Array (1 .. Reader_Buf_Size) := [others => 0];
         Pos : SEO := 1;
         Len : SEO := 0;
      end record;

      procedure Reader_Read_Up_To
        (R : in out Reader; Buf : out Byte_Array;
         Count : out SEO; St : out IO_Status)
      is
         N : SEO := 0;
         Cnt : SEO;
         RSt : IO_Status;
      begin
         St := IO_Ok;
         --  serve whatever is already buffered
         while R.Pos <= R.Len and then N < Buf'Length loop
            Buf (Buf'First + N) := R.Buf (R.Pos);
            R.Pos := R.Pos + 1;
            N := N + 1;
         end loop;
         --  one socket read (into the reader's own buffer, so surplus
         --  bytes are preserved) if more room is needed
         if N < Buf'Length and then R.Pos > R.Len then
            Recv_Some (R.S, R.Buf, Cnt, RSt);
            case RSt is
               when IO_Ok =>
                  R.Pos := 1;
                  R.Len := Cnt;
                  while R.Pos <= R.Len and then N < Buf'Length loop
                     Buf (Buf'First + N) := R.Buf (R.Pos);
                     R.Pos := R.Pos + 1;
                     N := N + 1;
                  end loop;
               when IO_Eof =>
                  St := IO_Eof;
               when others =>
                  St := RSt;
            end case;
         end if;
         Count := N;
      end Reader_Read_Up_To;

      procedure Reader_Read_Byte
        (R : in out Reader; B : out Byte; St : out IO_Status)
      is
         One : Byte_Array (1 .. 1);
         Count : SEO;
      begin
         Reader_Read_Up_To (R, One, Count, St);
         if Count = 1 then
            B := One (1);
            St := IO_Ok;
         end if;
      end Reader_Read_Byte;

      procedure Reader_Read_Line
        (R : in out Reader; Line : out Byte_Array;
         Len : out SEO; St : out IO_Status)
      is
         N : SEO := 0;
         B : Byte;
         BSt : IO_Status;
      begin
         Len := 0;
         loop
            if N >= Line'Length then
               St := IO_Too_Large;
               return;
            end if;
            Reader_Read_Byte (R, B, BSt);
            case BSt is
               when IO_Ok =>
                  N := N + 1;
                  Line (Line'First + N - 1) := B;
                  if B = 10 then
                     Len := N;
                     St := IO_Ok;
                     return;
                  end if;
               when others =>
                  St := BSt;
                  return;
            end case;
         end loop;
      end Reader_Read_Line;

      procedure Reader_Read_Head
        (R : in out Reader; Buf : out Head_Buffer;
         Len : out SEO; St : out IO_Status)
      is
         Pos : SEO := 0;
         B   : Byte;
         BSt : IO_Status;
      begin
         Len := 0;
         St := IO_Ok;
         loop
            if Pos >= Buf'Last then
               St := IO_Too_Large;
               return;
            end if;
            Reader_Read_Byte (R, B, BSt);
            case BSt is
               when IO_Ok =>
                  null;
               when IO_Eof =>
                  Len := Pos;
                  St := (if Pos = 0 then IO_Eof else IO_Error);
                  return;
               when others =>
                  Len := Pos;
                  St := BSt;
                  return;
            end case;
            Pos := Pos + 1;
            Buf (Buf'First + Pos - 1) := B;
            if B = 10 then
               --  terminator "\r\n\r\n" ending at this LF
               if Pos >= 4
                 and then Buf (Buf'First + Pos - 4) = 13
                 and then Buf (Buf'First + Pos - 3) = 10
                 and then Buf (Buf'First + Pos - 2) = 13
                 and then Buf (Buf'First + Pos - 1) = 10
               then
                  Len := Pos;
                  St := IO_Ok;
                  return;
               end if;
               --  terminator "\n\n" ending at this LF
               if Pos >= 2
                 and then Buf (Buf'First + Pos - 2) = 10
                 and then Buf (Buf'First + Pos - 1) = 10
               then
                  Len := Pos;
                  St := IO_Ok;
                  return;
               end if;
            end if;
         end loop;
      end Reader_Read_Head;

      --  ---------- relay primitives ----------

      procedure Relay_By_Length
        (R : in out Reader; To : Socket_Type; N : Natural; Ok : out Boolean)
      is
         Remaining : SEO := SEO (N);
         Buf : Byte_Array (1 .. Rly_Size);
         Count : SEO;
         St : IO_Status;
      begin
         Ok := True;
         while Remaining > 0 loop
            Reader_Read_Up_To
              (R, Buf (1 .. SEO'Min (Remaining, Buf'Length)), Count, St);
            case St is
               when IO_Ok =>
                  if Count = 0 then
                     Ok := False;
                     return;
                  end if;
                  Send_All (To, Buf (1 .. Count), Ok);
                  if not Ok then
                     return;
                  end if;
                  Remaining := Remaining - Count;
               when IO_Eof =>
                  if Count > 0 then
                     Send_All (To, Buf (1 .. Count), Ok);
                  end if;
                  Ok := False;   --  body truncated
                  return;
               when others =>
                  Ok := False;
                  return;
            end case;
         end loop;
      end Relay_By_Length;

      procedure Relay_Until_Eof
        (R : in out Reader; To : Socket_Type; Ok : out Boolean)
      is
         Buf : Byte_Array (1 .. Rly_Size);
         Count : SEO;
         St : IO_Status;
      begin
         Ok := True;
         loop
            Reader_Read_Up_To (R, Buf, Count, St);
            case St is
               when IO_Ok =>
                  if Count = 0 then
                     return;
                  end if;
                  Send_All (To, Buf (1 .. Count), Ok);
                  if not Ok then
                     return;
                  end if;
               when IO_Eof =>
                  if Count > 0 then
                     Send_All (To, Buf (1 .. Count), Ok);
                  end if;
                  return;
               when others =>
                  Ok := False;
                  return;
            end case;
         end loop;
      end Relay_Until_Eof;

      procedure Relay_Chunked
        (R : in out Reader; To : Socket_Type;
         Max_Total : Natural; Ok : out Boolean)
      is
         Line : Byte_Array (1 .. Max_Chunk_Line);
         Ln   : SEO;
         St   : IO_Status;
         Sz   : Natural;
         Total : Long_Long_Integer := 0;
         Buf  : Byte_Array (1 .. Rly_Size);
         Count : SEO;
      begin
         Ok := True;
         loop
            Reader_Read_Line (R, Line, Ln, St);
            if St /= IO_Ok then
               Ok := False;
               return;
            end if;
            Send_All (To, Line (1 .. Ln), Ok);
            if not Ok then
               return;
            end if;
            --  strip trailing CR/LF before parsing size
            declare
               Sz_Last : SEO := Ln - 1;
            begin
               if Sz_Last >= 1 and then Line (Sz_Last) = 10 then
                  Sz_Last := Sz_Last - 1;
               end if;
               if Sz_Last >= 1 and then Line (Sz_Last) = 13 then
                  Sz_Last := Sz_Last - 1;
               end if;
               Sz := Http_Parser.Parse_Hex (Line (1 .. Sz_Last), 1, Sz_Last);
            end;
            --  "0" size line (possibly with extensions) ends the body
            if Ln >= 1 and then Line (1) = 48 then
               --  verify it really is the terminator: 0 followed by ';' or CR/LF
               if Sz = 0 then
                  --  relay trailers until blank line
                  loop
                     Reader_Read_Line (R, Line, Ln, St);
                     if St /= IO_Ok then
                        Ok := False;
                        return;
                     end if;
                     Send_All (To, Line (1 .. Ln), Ok);
                     if not Ok then
                        return;
                     end if;
                     exit when Ln <= 2;
                  end loop;
                  return;
               end if;
            end if;
            if Sz = 0 then
               Ok := False;   -- malformed chunk size
               return;
            end if;
            Total := Total + Long_Long_Integer (Sz);
            if Total > Long_Long_Integer (Max_Total) then
               Ok := False;
               return;
            end if;
            --  relay Sz data bytes then the trailing CRLF
            declare
               Remaining : SEO := SEO (Sz);
            begin
               while Remaining > 0 loop
                  Reader_Read_Up_To
                    (R, Buf (1 .. SEO'Min (Remaining, Buf'Length)), Count, St);
                  if St /= IO_Ok or else Count = 0 then
                     Ok := False;
                     return;
                  end if;
                  Send_All (To, Buf (1 .. Count), Ok);
                  if not Ok then
                     return;
                  end if;
                  Remaining := Remaining - Count;
               end loop;
            end;
            --  relay the CRLF that terminates the chunk data
            declare
               B1 : Byte;
               B2 : Byte;
               S1 : IO_Status;
               S2 : IO_Status;
               Crlf : Byte_Array (1 .. 2);
            begin
               Reader_Read_Byte (R, B1, S1);
               if S1 /= IO_Ok then
                  Ok := False;
                  return;
               end if;
               Reader_Read_Byte (R, B2, S2);
               if S2 /= IO_Ok then
                  Ok := False;
                  return;
               end if;
               Crlf (1) := B1;
               Crlf (2) := B2;
               Send_All (To, Crlf, Ok);
               if not Ok then
                  return;
               end if;
            end;
         end loop;
      end Relay_Chunked;

      --  ---------- error responses ----------

      procedure Send_Error
        (S : Socket_Type; Kind : Errors.Error_Kind; Retry : Natural)
      is
         Buf : Byte_Array (1 .. Max_Error_Buf);
         Len : SEO;
         Ok : Boolean;
      begin
         Errors.Build (Kind, Retry, Buf, Len);
         Send_All (S, Buf (1 .. Len), Ok);
      end Send_Error;

      --  ---------- connection accounting ----------

      type Conn_Entry is record
         Active : Boolean := False;
         IP     : Rate_Limiter.IP_Addr := [others => 0];
         Count  : Natural := 0;
      end record;

      type Conn_Entry_Table is array (0 .. Max_Buckets - 1) of Conn_Entry;

      protected type Conn_Guard is
         procedure Try_Add
           (IP : Rate_Limiter.IP_Addr;
            Max_Per_IP : Positive;
            Max_Total  : Positive;
            Ok : out Boolean);
         procedure Remove (IP : Rate_Limiter.IP_Addr);
      private
         Table : Conn_Entry_Table := [others => (Active => False, others => <>)];
         Total_Count : Natural := 0;
      end Conn_Guard;

      protected body Conn_Guard is

         function Find (IP : Rate_Limiter.IP_Addr) return Integer is
         begin
            for I in Table'Range loop
               if Table (I).Active and then Table (I).IP = IP then
                  return I;
               end if;
            end loop;
            return -1;
         end Find;

         function Slot return Integer is
            Min_I : Integer := 0;
         begin
            for I in Table'Range loop
               if not Table (I).Active then
                  return I;
               end if;
            end loop;
            for I in Table'First + 1 .. Table'Last loop
               if Table (I).Count < Table (Min_I).Count then
                  Min_I := I;
               end if;
            end loop;
            return Min_I;
         end Slot;

         procedure Try_Add
           (IP : Rate_Limiter.IP_Addr;
            Max_Per_IP : Positive;
            Max_Total  : Positive;
            Ok : out Boolean)
         is
            Idx : Integer;
         begin
            if Total_Count >= Max_Total then
               Ok := False;
               return;
            end if;
            Idx := Find (IP);
            if Idx < 0 then
               Idx := Slot;
               Table (Idx) := (Active => True, IP => IP, Count => 0);
            end if;
            if Table (Idx).Count >= Max_Per_IP then
               Ok := False;
               return;
            end if;
            Table (Idx).Count := Table (Idx).Count + 1;
            Total_Count := Total_Count + 1;
            Ok := True;
         end Try_Add;

         procedure Remove (IP : Rate_Limiter.IP_Addr) is
            Idx : constant Integer := Find (IP);
         begin
            if Idx >= 0 and then Table (Idx).Count > 0 then
               Table (Idx).Count := Table (Idx).Count - 1;
               if Table (Idx).Count = 0 then
                  Table (Idx).Active := False;
               end if;
               if Total_Count > 0 then
                  Total_Count := Total_Count - 1;
               end if;
            end if;
         end Remove;

      end Conn_Guard;

      --  ---------- rate limiting guard ----------

      protected type Rate_Guard is
         procedure Check
           (IP      : Rate_Limiter.IP_Addr;
            Rate    : Rate_Limiter.Token_Count;
            Burst   : Rate_Limiter.Token_Count;
            Allowed : out Boolean);
         function Retry_After
           (IP   : Rate_Limiter.IP_Addr;
            Rate : Rate_Limiter.Token_Count) return Natural;
      private
         Table : Rate_Limiter.Bucket_Table := [others => (Active => False, others => <>)];
      end Rate_Guard;

      protected body Rate_Guard is

         procedure Check
           (IP      : Rate_Limiter.IP_Addr;
            Rate    : Rate_Limiter.Token_Count;
            Burst   : Rate_Limiter.Token_Count;
            Allowed : out Boolean)
         is
         begin
            Rate_Limiter.Consume (Table, IP, Now_Seconds, Rate, Burst, Allowed);
         end Check;

         function Retry_After
           (IP   : Rate_Limiter.IP_Addr;
            Rate : Rate_Limiter.Token_Count) return Natural
         is
         begin
            return Rate_Limiter.Retry_After (Table, IP, Now_Seconds, Rate);
         end Retry_After;

      end Rate_Guard;

      --  ---------- response relay ----------

      procedure Relay_Response_Body
        (Client : Socket_Type; R : in out Reader;
         Resp : Http_Parser.Response_Info; Ok : out Boolean)
      is
      begin
         Ok := True;
         case Resp.Frame_Kind is
            when Http_Parser.Frame_None =>
               null;
            when Http_Parser.Frame_By_Length =>
               Relay_By_Length (R, Client, Resp.Body_Length, Ok);
            when Http_Parser.Frame_Chunked =>
               Relay_Chunked (R, Client, Natural'Last / 2, Ok);
            when Http_Parser.Frame_Close =>
               Relay_Until_Eof (R, Client, Ok);
         end case;
      end Relay_Response_Body;

      --  ---------- one request end to end ----------

      procedure Forward_Request
        (Client    : Socket_Type;
         Head      : Head_Buffer;
         H_End     : SEO;
         Line      : Http_Parser.Line_Info;
         Hdrs      : Http_Parser.Header_Info;
         CR        : in out Reader;
         Target    : Sock_Addr_Type;
         Cfg       : Config_Type;
         Keep_Open : out Boolean)
      is
         Backend : Socket_Type;
         St  : Selector_Status;
         Ok  : Boolean;
         Is_Head : constant Boolean := Line.Method = Http_Parser.M_HEAD;
      begin
         Keep_Open := False;
         begin
            Create_Socket (Backend, Family_Inet, Socket_Stream);
         exception
            when Socket_Error =>
               Send_Error (Client, Errors.E_Unavailable, 0);
               return;
         end;
         Set_Timeout (Backend, Cfg.Backend_Timeout);
         begin
            Connect_Socket (Backend, Target, Cfg.Connect_Timeout, null, St);
            if St /= Completed then
               Log ("backend connect timed out");
               Send_Error (Client, Errors.E_Gateway_Timeout, 0);
               Close_Socket (Backend);
               return;
            end if;
         exception
            when Socket_Error =>
               Log ("backend connect failed");
               Send_Error (Client, Errors.E_Bad_Gateway, 0);
               Close_Socket (Backend);
               return;
         end;
         declare
            BR : Reader := (S => Backend, others => <>);
         begin
            Send_All (Backend, Head (1 .. H_End), Ok);
         if not Ok then
            Close_Socket (Backend);
            return;
         end if;
         --  Expect: 100-continue: the backend may answer before we send the body
         if Hdrs.Expect_100 then
            declare
               R_Head : Head_Buffer;
               R_Len  : SEO;
               R_St   : IO_Status;
               Resp   : Http_Parser.Response_Info;
            begin
               Reader_Read_Head (BR, R_Head, R_Len, R_St);
               if R_St /= IO_Ok then
                  Close_Socket (Backend);
                  Send_Error (Client, Errors.E_Bad_Gateway, 0);
                  return;
               end if;
               Resp :=
                 Http_Parser.Parse_Response (R_Head (1 .. R_Len), 1, R_Len,
                                             Is_Head);
               if not Resp.Valid then
                  Close_Socket (Backend);
                  Send_Error (Client, Errors.E_Bad_Gateway, 0);
                  return;
               end if;
               if Resp.Is_1xx then
                  Send_All (Client, R_Head (1 .. R_Len), Ok);
                  if not Ok then
                     Close_Socket (Backend);
                     return;
                  end if;
               else
                  --  backend rejected the request before seeing the body
                  Send_All (Client, R_Head (1 .. R_Len), Ok);
                  Relay_Response_Body (Client, BR, Resp, Ok);
                  Close_Socket (Backend);
                  return;
               end if;
            end;
         end if;
         --  forward the request body (CR keeps any leftover bytes from the
         --  head read, so nothing is lost or duplicated)
         declare
            Body_Ok : Boolean := True;
         begin
            if Hdrs.Chunked then
               Relay_Chunked (CR, Backend, Cfg.Max_Body, Body_Ok);
            elsif Hdrs.Has_Content_Length then
               Relay_By_Length (CR, Backend, Hdrs.Content_Length, Body_Ok);
            end if;
            if not Body_Ok then
               Send_Error (Client, Errors.E_Payload_Too_Large, 0);
               Close_Socket (Backend);
               return;
            end if;
         end;
         Shutdown_Socket (Backend, Shut_Write);
         --  read the final response (skipping interim 1xx)
         declare
            R_Head : Head_Buffer;
            R_Len  : SEO;
            R_St   : IO_Status;
            Resp   : Http_Parser.Response_Info;
         begin
            loop
               Reader_Read_Head (BR, R_Head, R_Len, R_St);
               case R_St is
                  when IO_Ok =>
                     null;
                  when IO_Timeout =>
                     Send_Error (Client, Errors.E_Gateway_Timeout, 0);
                     Close_Socket (Backend);
                     return;
                  when others =>
                     Send_Error (Client, Errors.E_Bad_Gateway, 0);
                     Close_Socket (Backend);
                     return;
               end case;
               Resp :=
                 Http_Parser.Parse_Response (R_Head (1 .. R_Len), 1, R_Len,
                                             Is_Head);
               if not Resp.Valid then
                  Send_Error (Client, Errors.E_Bad_Gateway, 0);
                  Close_Socket (Backend);
                  return;
               end if;
               Send_All (Client, R_Head (1 .. R_Len), Ok);
               if not Ok then
                  Close_Socket (Backend);
                  return;
               end if;
               exit when not Resp.Is_1xx;
            end loop;
            Relay_Response_Body (Client, BR, Resp, Ok);
            Close_Socket (Backend);
            if not Ok then
               return;
            end if;
            declare
               Client_Keep : constant Boolean :=
                 (Line.Is_1_1 and then not Hdrs.Has_Close)
                 or else Hdrs.Has_Keep_Alive;
               Backend_Close : constant Boolean :=
                 Resp.Connection_Close
                 or else Resp.Frame_Kind = Http_Parser.Frame_Close;
            begin
               Keep_Open := Client_Keep and then not Backend_Close;
            end;
         end;
         end;
      exception
         when E : others =>
            Log ("forward error: " & Ada.Exceptions.Exception_Name (E)
                 & " " & Ada.Exceptions.Exception_Information (E));
            begin
               Close_Socket (Backend);
            exception
               when others =>
                  null;
            end;
            Keep_Open := False;
      end Forward_Request;

      --  ---------- one connection (keep-alive loop) ----------

      procedure Handle_One
        (Client : Socket_Type;
         Peer   : Rate_Limiter.IP_Addr;
         Target : Sock_Addr_Type;
         Cfg    : Config_Type;
         RGuard : in out Rate_Guard)
      is
         Head : Head_Buffer;
         CR : Reader := (S => Client, others => <>);
         Requests : Natural := 0;
      begin
         Set_Timeout (Client, Cfg.Header_Timeout);
         loop
            declare
               H_Len : SEO;
               H_St : IO_Status;
               H_End : SEO;
               Line : Http_Parser.Line_Info;
               Hdrs : Http_Parser.Header_Info;
               Keep_Open : Boolean;
            begin
               Reader_Read_Head (CR, Head, H_Len, H_St);
               case H_St is
                  when IO_Eof =>
                     return;
                  when IO_Timeout =>
                     if H_Len > 0 then
                        Send_Error (Client, Errors.E_Timeout, 0);
                     end if;
                     return;
                  when IO_Too_Large =>
                     Send_Error (Client, Errors.E_Header_Too_Large, 0);
                     return;
                  when IO_Error =>
                     Send_Error (Client, Errors.E_Bad_Request, 0);
                     return;
                  when IO_Ok =>
                     null;
               end case;
               H_End :=
                 Http_Parser.Find_Head_End (Head (1 .. H_Len), 1, H_Len);
               Line :=
                 Http_Parser.Parse_Request_Line (Head (1 .. H_Len), 1, H_End);
               if not Line.Valid then
                  Send_Error (Client, Errors.E_Bad_Request, 0);
                  return;
               end if;
               if Line.Method = Http_Parser.M_UNKNOWN then
                  Send_Error (Client, Errors.E_Method_Not_Allowed, 0);
                  return;
               end if;
               if Line.Version = Http_Parser.V_UNKNOWN then
                  Send_Error (Client, Errors.E_Version_Not_Supported, 0);
                  return;
               end if;
               if Line.Uri_Last - Line.Uri_Start + 1 > Max_Uri_Size then
                  Send_Error (Client, Errors.E_Uri_Too_Long, 0);
                  return;
               end if;
               Hdrs :=
                 Http_Parser.Scan_Headers (Head (1 .. H_Len),
                                           Line.Line_End + 1, H_End);
               if not Hdrs.Valid then
                  Send_Error (Client, Errors.E_Bad_Request, 0);
                  return;
               end if;
               if Line.Is_1_1 and then not Hdrs.Has_Host then
                  Send_Error (Client, Errors.E_Bad_Request, 0);
                  return;
               end if;
               if Hdrs.Bad_Transfer_Encoding then
                  Send_Error (Client, Errors.E_Not_Implemented, 0);
                  return;
               end if;
               if Hdrs.Chunked and then Hdrs.Has_Content_Length then
                  Send_Error (Client, Errors.E_Bad_Request, 0);
                  return;
               end if;
               if Hdrs.Has_Content_Length
                 and then Hdrs.Content_Length > Cfg.Max_Body
               then
                  Send_Error (Client, Errors.E_Payload_Too_Large, 0);
                  return;
               end if;
               declare
                  Allowed : Boolean;
               begin
                  RGuard.Check (Peer,
                                Rate_Limiter.Token_Count (Cfg.Rate),
                                Rate_Limiter.Token_Count (Cfg.Burst),
                                Allowed);
                  if not Allowed then
                     Send_Error
                       (Client, Errors.E_Too_Many_Requests,
                        RGuard.Retry_After
                          (Peer, Rate_Limiter.Token_Count (Cfg.Rate)));
                     return;
                  end if;
               end;
               Forward_Request
                 (Client, Head, H_End, Line, Hdrs, CR, Target, Cfg, Keep_Open);
               Requests := Requests + 1;
               if not Keep_Open or else Requests >= Cfg.Max_Reqs then
                  return;
               end if;
               Set_Timeout (Client, Cfg.Idle_Timeout);
            end;
         end loop;
      end Handle_One;

      --  ---------- server ----------

      function Trim_Int (N : Natural) return String is
         Img : constant String := Natural'Image (N);
      begin
         return Img (2 .. Img'Last);
      end Trim_Int;

      procedure Run
        (Listen_Port : Positive;
         Target_Host : String;
         Target_Port : Positive;
         Cfg         : Config_Type)
      is
         Listener : Socket_Type;
         Target_Addr : Sock_Addr_Type;
         RGuard : Rate_Guard;
         CGuard : Conn_Guard;

         task type Handler is
            entry Start
              (C : Socket_Type;
               P : Rate_Limiter.IP_Addr;
               T : Sock_Addr_Type;
               G : Config_Type);
         end Handler;

         type Handler_Acc is access Handler;

         task body Handler is
            Client : Socket_Type;
            Peer   : Rate_Limiter.IP_Addr;
            Target : Sock_Addr_Type;
            Cfg    : Config_Type;
         begin
            accept Start
              (C : Socket_Type;
               P : Rate_Limiter.IP_Addr;
               T : Sock_Addr_Type;
               G : Config_Type)
            do
               Client := C;
               Peer   := P;
               Target := T;
               Cfg    := G;
            end Start;
            Handle_One (Client, Peer, Target, Cfg, RGuard);
            begin
               --  flush queued data (e.g. an error response) before closing,
               --  otherwise a RST may discard it before the peer reads it
               Shutdown_Socket (Client, Shut_Write);
            exception
               when Socket_Error =>
                  null;
            end;
            Close_Socket (Client);
            CGuard.Remove (Peer);
         exception
            when E : others =>
               Log ("handler error: " & Ada.Exceptions.Exception_Name (E)
                    & " " & Ada.Exceptions.Exception_Information (E));
               begin
                  Close_Socket (Client);
               exception
                  when others =>
                     null;
               end;
               CGuard.Remove (Peer);
         end Handler;

      begin
         --  resolve the backend address
         begin
            declare
               Infos : constant Address_Info_Array :=
                 Get_Address_Info
                   (Target_Host, Trim_Int (Target_Port),
                    Family_Inet, Socket_Stream, IP_Protocol_For_IP_Level);
            begin
               if Infos'Length = 0 then
                  Log ("cannot resolve target host: " & Target_Host);
                  return;
               end if;
               Target_Addr := Infos (Infos'First).Addr;
            end;
         exception
            when Host_Error =>
               Log ("cannot resolve target host: " & Target_Host);
               return;
         end;
         --  listener socket
         begin
            Create_Socket (Listener, Family_Inet, Socket_Stream);
            Set_Socket_Option
              (Listener, Socket_Level,
               (Name => Reuse_Address, Enabled => True));
            Bind_Socket
              (Listener,
               (Family => Family_Inet,
                Addr   => Any_Inet_Addr,
                Port   => Port_Type (Listen_Port)));
            Listen_Socket (Listener, 128);
         exception
            when E : others =>
               Log ("listener setup failed: "
                    & Ada.Exceptions.Exception_Name (E));
               return;
         end;
         Log ("listening on 0.0.0.0:" & Trim_Int (Listen_Port)
              & " -> " & Target_Host & ":" & Trim_Int (Target_Port)
              & "   rate=" & Trim_Int (Cfg.Rate) & "/s"
              & " burst=" & Trim_Int (Cfg.Burst)
              & " max_per_ip=" & Trim_Int (Cfg.Max_Per_IP)
              & " max_total=" & Trim_Int (Cfg.Max_Total)
              & " max_body=" & Trim_Int (Cfg.Max_Body / (1024 * 1024))
              & "MB");
         --  accept loop
         loop
            declare
               Client : Socket_Type;
               Addr   : Sock_Addr_Type;
               Peer   : Rate_Limiter.IP_Addr := [others => 0];
               Accepted : Boolean := False;
               Ok : Boolean;
               H : Handler_Acc;
            begin
               Accept_Socket (Listener, Client, Addr);
               for I in 1 .. 4 loop
                  Peer (I) := Byte (Addr.Addr.Sin_V4 (I));
               end loop;
               CGuard.Try_Add (Peer, Cfg.Max_Per_IP, Cfg.Max_Total, Ok);
               if not Ok then
                  Log ("reject connection from " & Image (Addr.Addr)
                       & " (connection limit)");
                  Send_Error (Client, Errors.E_Unavailable, 0);
                  begin
                     Shutdown_Socket (Client, Shut_Write);
                  exception
                     when Socket_Error =>
                        null;
                  end;
                  Close_Socket (Client);
               else
                  Accepted := True;
                  H := new Handler;
                  H.Start (Client, Peer, Target_Addr, Cfg);
               end if;
            exception
               when Socket_Error =>
                  Log ("accept error");
                  delay 0.1;
               when Storage_Error | Tasking_Error =>
                  Log ("accept resource error");
                  if Accepted then
                     CGuard.Remove (Peer);
                  end if;
                  begin
                     Close_Socket (Client);
                  exception
                     when others =>
                        null;
                  end;
            end;
         end loop;
      end Run;

   end IO;

begin
   if IO.Arg_Count /= 3 then
      IO.Print_Usage;
      return;
   end if;
   declare
      Args : constant Cli.Args_Info :=
        Cli.Parse_Args (IO.Get_Arg (1), IO.Get_Arg (2), IO.Get_Arg (3));
   begin
      if not Args.Ok then
         IO.Print_Usage;
         return;
      end if;
      IO.Run (Args.Listen_Port,
              Args.Host (1 .. Args.Host_Len),
              Args.Target_Port,
              Cli.Load_Config);
   end;
end Rideconnect;

