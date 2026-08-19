--  rideconnect.adb
--  =====================================================================
--  Layer-7 DDoS-protecting reverse proxy written in Ada 2022 / SPARK.
--  Builds to a single static executable (main unit rideconnect.adb plus
--  the library-level graceful_shutdown.{ads,adb} signal helper).
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
with Ada.Streams.Stream_IO;
with Interfaces;
with System;
with GNAT.Sockets;
with GNAT.OS_Lib;
with Graceful_Shutdown;

procedure Rideconnect is
   pragma SPARK_Mode (On);

   --  RtlGenRandom (SystemFunction036) resolves from advapi32 on Windows
   --  (mingw-w64 links it by default).  On POSIX the symbol is left
   --  unresolved and never called (/dev/urandom is used instead), so
   --  allow the linker to keep it unresolved there.
   pragma Linker_Options ("-Wl,--unresolved-symbols=ignore-all");
   function RtlGenRandom (Buf : System.Address; Len : Natural) return Integer;
   pragma Import (Stdcall, RtlGenRandom, "SystemFunction036");

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
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
   subtype Chunk_Line_Buf is Byte_Array (1 .. Max_Chunk_Line);
   subtype Error_Buffer is Byte_Array (1 .. Max_Error_Buf);

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
        (Buf : Head_Buffer; Start, Last : SEO) return SEO;
      --  Index of last byte of the blank-line terminator (CRLFCRLF or LFLF),
      --  or 0 when the terminator is not present in Buf (Start .. Last).

      function Parse_Request_Line
        (Buf : Head_Buffer; Start, Last : SEO) return Line_Info;
      --  Parse "METHOD SP URI SP HTTP/x.y" located at the start of the head.
      --  Last is the head end index as returned by Find_Head_End.

      function Scan_Headers
        (Buf : Head_Buffer; Start, Last : SEO) return Header_Info;
      --  Validate and extract fields from all header lines in [Start, Last].

      function Parse_Response
        (Buf : Head_Buffer; Start, Last : SEO; Method_Is_Head : Boolean)
         return Response_Info;
      --  Parse "HTTP/x.y STATUS ..." plus headers and derive body framing.

      function Parse_Hex
        (Buf : Chunk_Line_Buf; Start, Last : SEO) return Natural;
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
        (Buf : Head_Buffer; Pos : SEO; S : String) return Boolean
      is
      begin
         if Pos < Buf'First
           or else SEO (S'Length) > Buf'Last - Pos + 1
         then
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
        (Buf : Head_Buffer; Pos : SEO; S : String) return Boolean
      is
      begin
         if Pos < Buf'First
           or else SEO (S'Length) > Buf'Last - Pos + 1
         then
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
        (Buf : Head_Buffer; S, L : SEO; Name : String) return Boolean
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
        (Buf : Head_Buffer; S, L : SEO; C : Byte) return SEO
      is
      begin
         if S < Buf'First or else L > Buf'Last or else S > L + 1 then
            return 0;
         end if;
         for I in S .. L loop
            if Buf (I) = C then
               return I;
            end if;
            pragma Loop_Invariant (I in S .. L);
         end loop;
         return 0;
      end Find_Byte;

      function Contains_Token_CI
        (Buf : Head_Buffer; S, L : SEO; Tok : String) return Boolean
      is
         I : SEO := S;
      begin
         if S < Buf'First or else L > Buf'Last or else S > L then
            return False;
         end if;
         while I <= L loop
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
        (Buf : Head_Buffer; S, L : SEO) return Decimal_Result
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
        (Buf : Head_Buffer; Start, Last : SEO) return SEO
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
        (Buf : Chunk_Line_Buf; Start, Last : SEO) return Natural
      is
         V : Long_Long_Integer := 0;
         D : Long_Long_Integer;
      begin
         if Start < Buf'First or else Last > Buf'Last or else Start > Last then
            return 0;
         end if;
         for I in Start .. Last loop
            pragma Loop_Invariant (V >= 0
                                   and then V <= Long_Long_Integer (Natural'Last));
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
            if V > Long_Long_Integer (Natural'Last) then
               return 0;
            end if;
         end loop;
         return Natural (V);
      end Parse_Hex;

      function Parse_Request_Line
        (Buf : Head_Buffer; Start, Last : SEO) return Line_Info
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
         if Cont_Last >= Start and then Buf (Cont_Last) = 13 then
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
        (Buf : Head_Buffer; Start, Last : SEO) return Header_Info
      is
         Res : Header_Info;
         I : SEO := Start;
      begin
         Res.Valid := True;
         if Start < Buf'First or else Last > Buf'Last or else Start > Last then
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
                  pragma Loop_Variant (Increases => VStart);
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
                  pragma Loop_Variant (Decreases => VEnd);
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
        (Buf : Head_Buffer; Start, Last : SEO; Method_Is_Head : Boolean)
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
         Buf         : in out Error_Buffer;
         Len         : out SEO);

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

      function Reason_Of (Kind : Error_Kind) return String
        with Post => Reason_Of'Result'Length <= 33;

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
        (Buf : in out Error_Buffer; Pos : in out SEO; S : String)
        with
          Pre  =>
            Pos >= Buf'First
              and then Pos <= Buf'Last
              and then SEO (S'Length) <= Buf'Last - Pos + 1,
          Post => Pos = Pos'Old + SEO (S'Length);

      procedure Put
        (Buf : in out Error_Buffer; Pos : in out SEO; S : String)
      is
         Init : constant SEO := Pos;
      begin
         for I in S'Range loop
            pragma Loop_Invariant
              (Pos >= Buf'First
               and then Pos <= Buf'Last + 1
               and then Pos = Init + SEO (I - S'First + 1) - 1);
            Buf (Pos) := Byte (Character'Pos (S (I)));
            Pos := Pos + 1;
         end loop;
      end Put;

      procedure Put_Int
        (Buf : in out Error_Buffer; Pos : in out SEO; V : Natural)
        with
          Pre  => Pos >= Buf'First and then Pos <= Buf'Last - 10,
          Post => Pos >= Buf'First and then Pos <= Pos'Old + 11;

      procedure Put_Int
        (Buf : in out Error_Buffer; Pos : in out SEO; V : Natural)
      is
         Digs : String (1 .. 10) := [others => ' '];
         N : Natural := V;
         D : Natural := 0;
         Init : constant SEO := Pos;
      begin
         if V = 0 then
            Buf (Pos) := 48;
            Pos := Pos + 1;
            return;
         end if;
         while N > 0 and then D < 10 loop
            D := D + 1;
            Digs (D) := Character'Val (48 + N mod 10);
            N := N / 10;
            pragma Loop_Invariant (D in 1 .. 10 and then N >= 0);
         end loop;
         for K in reverse 1 .. D loop
            Buf (Pos) := Byte (Character'Pos (Digs (K)));
            Pos := Pos + 1;
            pragma Loop_Invariant
              (Pos >= Buf'First
               and then Pos = Init + SEO (D - K + 1)
               and then Pos <= Buf'Last);
         end loop;
      end Put_Int;

      procedure Build
        (Kind        : Error_Kind;
         Retry_After : Natural;
         Buf         : in out Error_Buffer;
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

   --  ===================== Crypto & TLS (non-SPARK) =====================
   --  Self-contained TLS 1.3 termination (RFC 8446) with pure-Ada
   --  primitives: SHA-256/384/512, HMAC, HKDF (RFC 5869),
   --  AES-128-GCM (NIST SP 800-38D), ChaCha20-Poly1305
   --  (RFC 8439), X25519 (RFC 7748), P-256 ECDSA (RFC 6979 deterministic),
   --  RSA PKCS#1 v1.5/PSS, ASN.1 DER/PEM parsing.
   --  SPARK_Mode Off: like IO, this layer is runtime-checked (the
   --  SPARK-proved core above stays untouched).

   package Crypto is
      pragma SPARK_Mode (Off);

      --  ---------- entropy ----------
      procedure Random_Bytes (B : out Byte_Array);

      --  ---------- digests ----------
      subtype Digest_256 is Byte_Array (1 .. 32);
      subtype Digest_384 is Byte_Array (1 .. 48);
      subtype Digest_512 is Byte_Array (1 .. 64);

      type SHA256_Ctx is private;
      type SHA384_Ctx is private;
      procedure SHA256_Init   (C : out SHA256_Ctx);
      procedure SHA256_Update (C : in out SHA256_Ctx; M : Byte_Array);
      function  SHA256_Final  (C : in out SHA256_Ctx) return Digest_256;
      procedure SHA384_Init   (C : out SHA384_Ctx);
      procedure SHA384_Update (C : in out SHA384_Ctx; M : Byte_Array);
      function  SHA384_Final  (C : in out SHA384_Ctx) return Digest_384;

      function SHA256 (M : Byte_Array) return Digest_256;
      function SHA384 (M : Byte_Array) return Digest_384;
      function SHA512 (M : Byte_Array) return Digest_512;

      --  ---------- HMAC / HKDF (RFC 5869) ----------
      function HMAC_SHA256 (Key, M : Byte_Array) return Digest_256;
      function HMAC_SHA384 (Key, M : Byte_Array) return Digest_384;
      function HKDF_Extract (Salt, IKM : Byte_Array) return Digest_256;
      function HKDF_Expand
        (PRK : Byte_Array; Info : Byte_Array; Len : Positive)
         return Byte_Array;
      function HKDF_Expand_Label
        (Secret : Byte_Array; Label : String; Ctx : Byte_Array;
         Len : Positive) return Byte_Array;

      --  ---------- AEAD ----------
      subtype AES_Key  is Byte_Array (1 .. 16);
      subtype Tag_16   is Byte_Array (1 .. 16);

      procedure AES128GCM_Seal
        (Key, Nonce : Byte_Array; AAD, Plain : Byte_Array;
         Cipher : out Byte_Array; Cipher_Len : out SEO;
         Tag : out Tag_16; Ok : out Boolean);
      --  Open: returns plaintext length, -1 on auth failure
      function AES128GCM_Open
        (Key, Nonce : Byte_Array; AAD, Cipher : Byte_Array;
         Tag : Tag_16; Plain : out Byte_Array) return SEO;

      procedure ChaCha20Poly1305_Seal
        (Key, Nonce : Byte_Array; AAD, Plain : Byte_Array;
         Cipher : out Byte_Array; Cipher_Len : out SEO;
         Tag : out Tag_16; Ok : out Boolean);
      function ChaCha20Poly1305_Open
        (Key, Nonce : Byte_Array; AAD, Cipher : Byte_Array;
         Tag : Tag_16; Plain : out Byte_Array) return SEO;

      --  ---------- X25519 (RFC 7748) ----------
      subtype X25519_Key is Byte_Array (1 .. 32);
      procedure X25519_Keygen (Sk : out X25519_Key; Pk : out X25519_Key);
      function X25519 (Sk, Pk : X25519_Key) return X25519_Key;

      --  ---------- P-256 (secp256r1) ----------
      type P256_Pub is record
         X, Y : Byte_Array (1 .. 32) := [others => 0];
      end record;
      subtype P256_Priv is Byte_Array (1 .. 32);
      procedure P256_Keygen (Sk : out P256_Priv; Pk : out P256_Pub);
      function P256_ECDH (Sk : P256_Priv; Pk : P256_Pub) return Byte_Array;
      --  returns DER-encoded (r, s) of SHA-256(Msg), RFC 6979
      function P256_ECDSA_Sign
        (Sk : P256_Priv; Msg : Byte_Array) return Byte_Array;
      function P256_ECDSA_Verify
        (Pk : P256_Pub; Msg : Byte_Array; Sig : Byte_Array) return Boolean;

      --  ---------- RSA (PKCS#1 v1.5 + PSS, CRT private op) ----------
      Max_RSA_Key : constant := 4096 / 8;      --  512 bytes
      Max_RSA_Mod : constant := 256;           --  2048-bit modulus default
      type RSA_Priv is record
         Valid : Boolean := False;
         N_Len, D_Len, P_Len, Q_Len : Natural := 0;
         DP_Len, DQ_Len, QI_Len : Natural := 0;
         E_Len : Natural := 0;
         N, D, P, Q, DP, DQ, QI : Byte_Array (1 .. Max_RSA_Key) :=
           [others => 0];
         E : Byte_Array (1 .. 8) := [others => 0];
      end record;
      function RSA_Sign_PKCS1 (Key : RSA_Priv; Hash : Digest_256)
                               return Byte_Array;
      function RSA_Sign_PSS   (Key : RSA_Priv; Hash : Digest_256)
                               return Byte_Array;
      function RSA_Verify_PKCS1
        (N, E : Byte_Array; Sig : Byte_Array; Hash : Digest_256)
         return Boolean;
      function RSA_Verify_PSS
        (N, E : Byte_Array; Sig : Byte_Array; Hash : Digest_256)
         return Boolean;

      --  ---------- ASN.1 / PEM ----------
      --  returns DER length (>0) or 0 on failure
      function Load_PEM_Cert (Pem : String; Der : out Byte_Array) return SEO;
      function Load_PEM_Key
        (Pem : String; Rsa : out RSA_Priv; P256 : out P256_Priv;
         Is_RSA : out Boolean) return Boolean;
      function Cert_Pub_Is_RSA  (Der : Byte_Array) return Boolean;
      function Cert_Pub_Is_P256 (Der : Byte_Array) return Boolean;
      function Cert_Pub_N_E
        (Der : Byte_Array; N : out Byte_Array; N_Len : out Natural;
         E : out Byte_Array; E_Len : out Natural) return Boolean;
      function Cert_Pub_P256
        (Der : Byte_Array; X, Y : out Byte_Array) return Boolean;
      --  verify that private key matches certificate public key
      function Cert_Self_Check
        (Der : Byte_Array; Rsa : RSA_Priv; P256 : P256_Priv;
         Is_RSA : Boolean) return Boolean;

      --  ---------- TLS ----------
      TLS_Max_Plain  : constant := 16 * 1024 + 256;   --  plaintext record
      TLS_Max_Record : constant := 16 * 1024 + 2048 + 256;
      TLS_Max_Cert   : constant := 16 * 1024;
      TLS_Max_Chain  : constant := 32 * 1024;

      type TLS_Conn is private;

      procedure TLS_Init
        (C : out TLS_Conn; Cert : Byte_Array; Cert_Len : SEO;
         Rsa : RSA_Priv; P256 : P256_Priv; Is_RSA : Boolean;
         Ok : out Boolean);
      --  server handshake; on failure an alert is sent and Ok=False
      procedure TLS_Server_Handshake
        (C : in out TLS_Conn; Sock : GNAT.Sockets.Socket_Type;
         Ok : out Boolean);
      --  read decrypted application data (Count=0 on EOF / alert)
      procedure TLS_Read
        (C : in out TLS_Conn; Sock : GNAT.Sockets.Socket_Type;
         Buf : out Byte_Array; Count : out SEO;
         Eof : out Boolean; Ok : out Boolean);
      procedure TLS_Write
        (C : in out TLS_Conn; Sock : GNAT.Sockets.Socket_Type;
         Data : Byte_Array; Ok : out Boolean);
      procedure TLS_Close_Notify
        (C : in out TLS_Conn; Sock : GNAT.Sockets.Socket_Type);

      --  ---------- self test (RFC/NIST vectors) ----------
      function Self_Test return Boolean;

   private

      type SHA256_Ctx is record
         H    : Byte_Array (1 .. 32) := (others => 0);
         Buf  : Byte_Array (1 .. 64) := (others => 0);
         Len  : SEO := 0;
         Bits : Byte_Array (1 .. 8) := (others => 0);   --  big-endian 64-bit
      end record;

      type SHA384_Ctx is record
         H    : Byte_Array (1 .. 64) := (others => 0);
         Buf  : Byte_Array (1 .. 128) := (others => 0);
         Len  : SEO := 0;
         Bits : Byte_Array (1 .. 16) := (others => 0);  --  big-endian 128-bit
      end record;

      type TLS_Conn is record
         --  configuration
         Cert : Byte_Array (1 .. TLS_Max_Cert) := [others => 0];
         Cert_Len : SEO := 0;
         Cert_Is_RSA  : Boolean := False;
         Rsa  : RSA_Priv;
         P256 : P256_Priv := [others => 0];
         --  negotiated
         Is_TLS13 : Boolean := False;
         Cipher   : Natural := 0;    --  1=AES128GCM, 2=ChaCha20
         ECDHE_X  : Boolean := False; --  true if X25519, false if P-256
         Handshake_Done : Boolean := False;
         Peer_Finished_Ok : Boolean := False;
         --  record layer (keys are 16 bytes for AES-128-GCM, 32 for ChaCha20)
         In_Key, Out_Key : Byte_Array (1 .. 32) := [others => 0];
         In_IV, Out_IV   : Byte_Array (1 .. 12) := [others => 0];
         In_Seq, Out_Seq : Byte_Array (1 .. 8) := [others => 0];
         --  TLS 1.3 traffic secrets
         Ap_Secret : Digest_256 := [others => 0];
         --  handshake transcript (TLS 1.3: incremental SHA-256)
         Tr : SHA256_Ctx;
         Tr_Done : Digest_256 := [others => 0];
         --  decrypted-but-unread application data
         Plain : Byte_Array (1 .. TLS_Max_Plain) := [others => 0];
         Plain_Pos, Plain_Len : SEO := 0;
         --  pending input record header (partial reads)
         Hdr : Byte_Array (1 .. 5) := [others => 0];
         Hdr_Pos : Natural := 0;
         Rec_Left : Natural := 0;
         Rec_Type : Natural := 0;
         Rec_Buf  : Byte_Array (1 .. TLS_Max_Record) := [others => 0];
         Rec_Buf_Len : Natural := 0;
         Closed : Boolean := False;
      end record;

   end Crypto;

   package body Crypto is
      pragma SPARK_Mode (Off);

      use Interfaces;

      subtype Unsigned_32 is Interfaces.Unsigned_32;
      subtype Unsigned_64 is Interfaces.Unsigned_64;
      subtype Unsigned_16 is Interfaces.Unsigned_16;

      --  ==================== entropy ====================
      --  POSIX: /dev/urandom.  Windows: SystemFunction036 (RtlGenRandom,
      --  advapi32 is linked by default by mingw-w64).  The weak import
      --  resolves to null on non-Windows, so it is never called there.

      procedure Random_Bytes (B : out Byte_Array) is
      begin
         --  POSIX: /dev/urandom (always available on Linux/macOS)
         declare
            use Ada.Streams.Stream_IO;
            F : File_Type;
         begin
            Open (F, In_File, "/dev/urandom");
            for K in B'Range loop
               Byte'Read (Stream (F), B (K));
            end loop;
            Close (F);
            return;
         exception
            when others =>
               null;   --  not POSIX: fall through to the Windows API
         end;
         --  Windows: SystemFunction036 (RtlGenRandom)
         if RtlGenRandom (B'Address, B'Length) /= 0 then
            return;
         end if;
         --  last resort (no OS entropy at all): xorshift64* from the clock
         --  (never expected to run; kept so the server can still start)
         declare
            use Ada.Real_Time;
            Seed : Unsigned_64 :=
              Unsigned_64 (To_Duration (Clock - Time_First) * 1.0e9);
         begin
            for K in B'Range loop
               Seed := Seed xor (Seed * 7);
               Seed := Seed xor Shift_Right (Seed, 13);
               Seed := Seed xor (Seed * 9);
               B (K) := Byte (Seed and 16#FF#);
            end loop;
         end;
      end Random_Bytes;

      --  ==================== endian helpers ====================

      function BE16 (B : Byte_Array; I : SEO) return Unsigned_16 is
      begin
         return Shift_Left (Unsigned_16 (B (I)), 8)
           or Unsigned_16 (B (I + 1));
      end BE16;

      function BE24 (B : Byte_Array; I : SEO) return Natural is
      begin
         return Natural (B (I)) * 65536 + Natural (B (I + 1)) * 256
           + Natural (B (I + 2));
      end BE24;

      function BE32 (B : Byte_Array; I : SEO) return Unsigned_32 is
      begin
         return Shift_Left (Unsigned_32 (B (I)), 24)
           or Shift_Left (Unsigned_32 (B (I + 1)), 16)
           or Shift_Left (Unsigned_32 (B (I + 2)), 8)
           or Unsigned_32 (B (I + 3));
      end BE32;

      function BE64 (B : Byte_Array; I : SEO) return Unsigned_64 is
      begin
         return Shift_Left (Unsigned_64 (BE32 (B, I)), 32)
           or Unsigned_64 (BE32 (B, I + 4));
      end BE64;

      procedure Set_BE16 (B : in out Byte_Array; I : SEO; V : Unsigned_16) is
      begin
         B (I)     := Byte (Shift_Right (V, 8) and 16#FF#);
         B (I + 1) := Byte (V and 16#FF#);
      end Set_BE16;

      procedure Set_BE32 (B : in out Byte_Array; I : SEO; V : Unsigned_32) is
      begin
         B (I)     := Byte (Shift_Right (V, 24) and 16#FF#);
         B (I + 1) := Byte (Shift_Right (V, 16) and 16#FF#);
         B (I + 2) := Byte (Shift_Right (V, 8) and 16#FF#);
         B (I + 3) := Byte (V and 16#FF#);
      end Set_BE32;

      procedure Set_BE64 (B : in out Byte_Array; I : SEO; V : Unsigned_64) is
      begin
         Set_BE32 (B, I, Unsigned_32 (Shift_Right (V, 32)));
         Set_BE32 (B, I + 4, Unsigned_32 (V and 16#FFFF_FFFF#));
      end Set_BE64;

      function RotR (V : Unsigned_32; N : Natural) return Unsigned_32 is
      begin
         return Shift_Right (V, N) or Shift_Left (V, 32 - N);
      end RotR;

      function RotR64 (V : Unsigned_64; N : Natural) return Unsigned_64 is
      begin
         return Shift_Right (V, N) or Shift_Left (V, 64 - N);
      end RotR64;

      --  ==================== SHA-256 ====================

      K256 : constant array (1 .. 64) of Unsigned_32 :=
        (16#428A2F98#, 16#71374491#, 16#B5C0FBCF#, 16#E9B5DBA5#,
         16#3956C25B#, 16#59F111F1#, 16#923F82A4#, 16#AB1C5ED5#,
         16#D807AA98#, 16#12835B01#, 16#243185BE#, 16#550C7DC3#,
         16#72BE5D74#, 16#80DEB1FE#, 16#9BDC06A7#, 16#C19BF174#,
         16#E49B69C1#, 16#EFBE4786#, 16#0FC19DC6#, 16#240CA1CC#,
         16#2DE92C6F#, 16#4A7484AA#, 16#5CB0A9DC#, 16#76F988DA#,
         16#983E5152#, 16#A831C66D#, 16#B00327C8#, 16#BF597FC7#,
         16#C6E00BF3#, 16#D5A79147#, 16#06CA6351#, 16#14292967#,
         16#27B70A85#, 16#2E1B2138#, 16#4D2C6DFC#, 16#53380D13#,
         16#650A7354#, 16#766A0ABB#, 16#81C2C92E#, 16#92722C85#,
         16#A2BFE8A1#, 16#A81A664B#, 16#C24B8B70#, 16#C76C51A3#,
         16#D192E819#, 16#D6990624#, 16#F40E3585#, 16#106AA070#,
         16#19A4C116#, 16#1E376C08#, 16#2748774C#, 16#34B0BCB5#,
         16#391C0CB3#, 16#4ED8AA4A#, 16#5B9CCA4F#, 16#682E6FF3#,
         16#748F82EE#, 16#78A5636F#, 16#84C87814#, 16#8CC70208#,
         16#90BEFFFA#, 16#A4506CEB#, 16#BEF9A3F7#, 16#C67178F2#);

      procedure SHA256_Compress (H : in out Byte_Array; Block : Byte_Array) is
         W  : array (1 .. 64) of Unsigned_32;
         A, B, C, D, E, F, G, Hh : Unsigned_32;
         S0, S1, Ch, Maj, T1, T2 : Unsigned_32;
      begin
         for I in 1 .. 16 loop
            W (I) := BE32 (Block, SEO ((I - 1) * 4 + 1));
         end loop;
         for I in 17 .. 64 loop
            S0 := RotR (W (I - 15), 7) xor RotR (W (I - 15), 18)
              xor Shift_Right (W (I - 15), 3);
            S1 := RotR (W (I - 2), 17) xor RotR (W (I - 2), 19)
              xor Shift_Right (W (I - 2), 10);
            W (I) := W (I - 16) + S0 + W (I - 7) + S1;
         end loop;
         A := BE32 (H, 1);  B := BE32 (H, 5);  C := BE32 (H, 9);
         D := BE32 (H, 13); E := BE32 (H, 17); F := BE32 (H, 21);
         G := BE32 (H, 25); Hh := BE32 (H, 29);
         for I in 1 .. 64 loop
            S1 := RotR (E, 6) xor RotR (E, 11) xor RotR (E, 25);
            Ch := (E and F) xor ((not E) and G);
            T1 := Hh + S1 + Ch + K256 (I) + W (I);
            S0 := RotR (A, 2) xor RotR (A, 13) xor RotR (A, 22);
            Maj := (A and B) xor (A and C) xor (B and C);
            T2 := S0 + Maj;
            Hh := G; G := F; F := E; E := D + T1;
            D := C; C := B; B := A; A := T1 + T2;
         end loop;
         Set_BE32 (H, 1,  A + BE32 (H, 1));
         Set_BE32 (H, 5,  B + BE32 (H, 5));
         Set_BE32 (H, 9,  C + BE32 (H, 9));
         Set_BE32 (H, 13, D + BE32 (H, 13));
         Set_BE32 (H, 17, E + BE32 (H, 17));
         Set_BE32 (H, 21, F + BE32 (H, 21));
         Set_BE32 (H, 25, G + BE32 (H, 25));
         Set_BE32 (H, 29, Hh + BE32 (H, 29));
      end SHA256_Compress;

      procedure SHA256_Init (C : out SHA256_Ctx) is
         V : constant array (1 .. 8) of Unsigned_32 :=
           (16#6A09E667#, 16#BB67AE85#, 16#3C6EF372#, 16#A54FF53A#,
            16#510E527F#, 16#9B05688C#, 16#1F83D9AB#, 16#5BE0CD19#);
      begin
         for I in 1 .. 8 loop
            Set_BE32 (C.H, SEO ((I - 1) * 4 + 1), V (I));
         end loop;
         C.Buf := [others => 0];
         C.Len := 0;
         C.Bits := [others => 0];
      end SHA256_Init;

      procedure SHA256_Update (C : in out SHA256_Ctx; M : Byte_Array) is
         I : SEO := M'First;
      begin
         --  fold message length into the 64-bit big-endian bit counter
         declare
            Add : Unsigned_64 := Unsigned_64 (M'Length) * 8;
            Carry : Unsigned_64;
         begin
            for K in reverse 1 .. 8 loop
               Carry := Unsigned_64 (C.Bits (SEO (K))) + (Add and 16#FF#);
               C.Bits (SEO (K)) := Byte (Carry and 16#FF#);
               Add := Shift_Right (Add, 8) + Shift_Right (Carry, 8);
            end loop;
         end;
         while I <= M'Last loop
            C.Len := C.Len + 1;
            C.Buf (SEO (C.Len)) := M (I);
            if C.Len = 64 then
               SHA256_Compress (C.H, C.Buf);
               C.Len := 0;
            end if;
            I := I + 1;
         end loop;
      end SHA256_Update;

      function SHA256_Final (C : in out SHA256_Ctx) return Digest_256 is
         Res : Digest_256;
      begin
         --  padding: 0x80, zeros, 64-bit length
         C.Len := C.Len + 1;
         C.Buf (SEO (C.Len)) := 16#80#;
         while C.Len < 56 loop
            C.Len := C.Len + 1;
            C.Buf (SEO (C.Len)) := 0;
         end loop;
         if C.Len > 56 then
            while C.Len < 64 loop
               C.Len := C.Len + 1;
               C.Buf (SEO (C.Len)) := 0;
            end loop;
            SHA256_Compress (C.H, C.Buf);
            C.Len := 0;
            while C.Len < 56 loop
               C.Len := C.Len + 1;
               C.Buf (SEO (C.Len)) := 0;
            end loop;
         end if;
         C.Buf (57 .. 64) := C.Bits;
         SHA256_Compress (C.H, C.Buf);
         Res := C.H;
         return Res;
      end SHA256_Final;

      function SHA256 (M : Byte_Array) return Digest_256 is
         C : SHA256_Ctx;
      begin
         SHA256_Init (C);
         SHA256_Update (C, M);
         return SHA256_Final (C);
      end SHA256;

      --  ==================== SHA-384 / SHA-512 ====================

      K512 : constant array (1 .. 80) of Unsigned_64 :=
        (16#428A2F98D728AE22#, 16#7137449123EF65CD#,
         16#B5C0FBCFEC4D3B2F#, 16#E9B5DBA58189DBBC#,
         16#3956C25BF348B538#, 16#59F111F1B605D019#,
         16#923F82A4AF194F9B#, 16#AB1C5ED5DA6D8118#,
         16#D807AA98A3030242#, 16#12835B0145706FBE#,
         16#243185BE4EE4B28C#, 16#550C7DC3D5FFB4E2#,
         16#72BE5D74F27B896F#, 16#80DEB1FE3B1696B1#,
         16#9BDC06A725C71235#, 16#C19BF174CF692694#,
         16#E49B69C19EF14AD2#, 16#EFBE4786384F25E3#,
         16#0FC19DC68B8CD5B5#, 16#240CA1CC77AC9C65#,
         16#2DE92C6F592B0275#, 16#4A7484AA6EA6E483#,
         16#5CB0A9DCBD41FBD4#, 16#76F988DA831153B5#,
         16#983E5152EE66DFAB#, 16#A831C66D2DB43210#,
         16#B00327C898FB213F#, 16#BF597FC7BEEF0EE4#,
         16#C6E00BF33DA88FC2#, 16#D5A79147930AA725#,
         16#06CA6351E003826F#, 16#142929670A0E6E70#,
         16#27B70A8546D22FFC#, 16#2E1B21385C26C926#,
         16#4D2C6DFC5AC42AED#, 16#53380D139D95B3DF#,
         16#650A73548BAF63DE#, 16#766A0ABB3C77B2A8#,
         16#81C2C92E47EDAEE6#, 16#92722C851482353B#,
         16#A2BFE8A14CF10364#, 16#A81A664BBC423001#,
         16#C24B8B70D0F89791#, 16#C76C51A30654BE30#,
         16#D192E819D6EF5218#, 16#D69906245565A910#,
         16#F40E35855771202A#, 16#106AA07032BBD1B8#,
         16#19A4C116B8D2D0C8#, 16#1E376C085141AB53#,
         16#2748774CDF8EEB99#, 16#34B0BCB5E19B48A8#,
         16#391C0CB3C5C95A63#, 16#4ED8AA4AE3418ACB#,
         16#5B9CCA4F7763E373#, 16#682E6FF3D6B2B8A3#,
         16#748F82EE5DEFB2FC#, 16#78A5636F43172F60#,
         16#84C87814A1F0AB72#, 16#8CC702081A6439EC#,
         16#90BEFFFA23631E28#, 16#A4506CEBDE82BDE9#,
         16#BEF9A3F7B2C67915#, 16#C67178F2E372532B#,
         16#CA273ECEEA26619C#, 16#D186B8C721C0C207#,
         16#EADA7DD6CDE0EB1E#, 16#F57D4F7FEE6ED178#,
         16#06F067AA72176FBA#, 16#0A637DC5A2C898A6#,
         16#113F9804BEF90DAE#, 16#1B710B35131C471B#,
         16#28DB77F523047D84#, 16#32CAAB7B40C72493#,
         16#3C9EBE0A15C9BEBC#, 16#431D67C49C100D4C#,
         16#4CC5D4BECB3E42B6#, 16#597F299CFC657E2A#,
         16#5FCB6FAB3AD6FAEC#, 16#6C44198C4A475817#);

      procedure SHA512_Compress
        (H : in out Byte_Array; Block : Byte_Array) is
         W  : array (1 .. 80) of Unsigned_64;
         A, B, C, D, E, F, G, Hh : Unsigned_64;
         S0, S1, Ch, Maj, T1, T2 : Unsigned_64;
      begin
         for I in 1 .. 16 loop
            W (I) := BE64 (Block, SEO ((I - 1) * 8 + 1));
         end loop;
         for I in 17 .. 80 loop
            S0 := RotR64 (W (I - 15), 1) xor RotR64 (W (I - 15), 8)
              xor Shift_Right (W (I - 15), 7);
            S1 := RotR64 (W (I - 2), 19) xor RotR64 (W (I - 2), 61)
              xor Shift_Right (W (I - 2), 6);
            W (I) := W (I - 16) + S0 + W (I - 7) + S1;
         end loop;
         A := BE64 (H, 1);   B := BE64 (H, 9);
         C := BE64 (H, 17);  D := BE64 (H, 25);
         E := BE64 (H, 33);  F := BE64 (H, 41);
         G := BE64 (H, 49);  Hh := BE64 (H, 57);
         for I in 1 .. 80 loop
            S1 := RotR64 (E, 14) xor RotR64 (E, 18) xor RotR64 (E, 41);
            Ch := (E and F) xor ((not E) and G);
            T1 := Hh + S1 + Ch + K512 (I) + W (I);
            S0 := RotR64 (A, 28) xor RotR64 (A, 34) xor RotR64 (A, 39);
            Maj := (A and B) xor (A and C) xor (B and C);
            T2 := S0 + Maj;
            Hh := G; G := F; F := E; E := D + T1;
            D := C; C := B; B := A; A := T1 + T2;
         end loop;
         Set_BE64 (H, 1,  A + BE64 (H, 1));
         Set_BE64 (H, 9,  B + BE64 (H, 9));
         Set_BE64 (H, 17, C + BE64 (H, 17));
         Set_BE64 (H, 25, D + BE64 (H, 25));
         Set_BE64 (H, 33, E + BE64 (H, 33));
         Set_BE64 (H, 41, F + BE64 (H, 41));
         Set_BE64 (H, 49, G + BE64 (H, 49));
         Set_BE64 (H, 57, Hh + BE64 (H, 57));
      end SHA512_Compress;

      procedure SHA384_Init (C : out SHA384_Ctx) is
         V : constant array (1 .. 8) of Unsigned_64 :=
           (16#CBBB9D5DC1059ED8#, 16#629A292A367CD507#,
            16#9159015A3070DD17#, 16#152FECD8F70E5939#,
            16#67332667FFC00B31#, 16#8EB44A8768581511#,
            16#DB0C2E0D64F98FA7#, 16#47B5481DBEFA4FA4#);
      begin
         for I in 1 .. 8 loop
            Set_BE64 (C.H, SEO ((I - 1) * 8 + 1), V (I));
         end loop;
         C.Buf := [others => 0];
         C.Len := 0;
         C.Bits := [others => 0];
      end SHA384_Init;

      procedure SHA512_Init (C : out SHA384_Ctx) is
         V : constant array (1 .. 8) of Unsigned_64 :=
           (16#6A09E667F3BCC908#, 16#BB67AE8584CAA73B#,
            16#3C6EF372FE94F82B#, 16#A54FF53A5F1D36F1#,
            16#510E527FADE682D1#, 16#9B05688C2B3E6C1F#,
            16#1F83D9ABFB41BD6B#, 16#5BE0CD19137E2179#);
      begin
         for I in 1 .. 8 loop
            Set_BE64 (C.H, SEO ((I - 1) * 8 + 1), V (I));
         end loop;
         C.Buf := [others => 0];
         C.Len := 0;
         C.Bits := [others => 0];
      end SHA512_Init;

      procedure SHA384_Update (C : in out SHA384_Ctx; M : Byte_Array) is
         I : SEO := M'First;
      begin
         declare
            Add : Unsigned_64 := Unsigned_64 (M'Length) * 8;
            Carry : Unsigned_64;
         begin
            for K in reverse 1 .. 16 loop
               Carry := Unsigned_64 (C.Bits (SEO (K))) + (Add and 16#FF#);
               C.Bits (SEO (K)) := Byte (Carry and 16#FF#);
               Add := Shift_Right (Add, 8) + Shift_Right (Carry, 8);
            end loop;
         end;
         while I <= M'Last loop
            C.Len := C.Len + 1;
            C.Buf (SEO (C.Len)) := M (I);
            if C.Len = 128 then
               SHA512_Compress (C.H, C.Buf);
               C.Len := 0;
            end if;
            I := I + 1;
         end loop;
      end SHA384_Update;

      function SHA384_Final (C : in out SHA384_Ctx) return Digest_384 is
         Res : Digest_384;
      begin
         C.Len := C.Len + 1;
         C.Buf (SEO (C.Len)) := 16#80#;
         while C.Len < 112 loop
            C.Len := C.Len + 1;
            C.Buf (SEO (C.Len)) := 0;
         end loop;
         if C.Len > 112 then
            while C.Len < 128 loop
               C.Len := C.Len + 1;
               C.Buf (SEO (C.Len)) := 0;
            end loop;
            SHA512_Compress (C.H, C.Buf);
            C.Len := 0;
            while C.Len < 112 loop
               C.Len := C.Len + 1;
               C.Buf (SEO (C.Len)) := 0;
            end loop;
         end if;
         C.Buf (113 .. 128) := C.Bits;
         SHA512_Compress (C.H, C.Buf);
         Res := C.H (1 .. 48);
         return Res;
      end SHA384_Final;

      function SHA384 (M : Byte_Array) return Digest_384 is
         C : SHA384_Ctx;
      begin
         SHA384_Init (C);
         SHA384_Update (C, M);
         return SHA384_Final (C);
      end SHA384;

      procedure SHA512_Finish (C : in out SHA384_Ctx; Out_Buf : out Byte_Array);

      function SHA512 (M : Byte_Array) return Digest_512 is
         C : SHA384_Ctx;
      begin
         SHA512_Init (C);
         SHA384_Update (C, M);
         declare
            Full : Byte_Array (1 .. 64);
         begin
            SHA512_Finish (C, Full);
            return Full;
         end;
      end SHA512;

      procedure SHA512_Finish (C : in out SHA384_Ctx; Out_Buf : out Byte_Array) is
         HB : Byte_Array (1 .. 64);
      begin
         C.Len := C.Len + 1;
         C.Buf (SEO (C.Len)) := 16#80#;
         while C.Len < 112 loop
            C.Len := C.Len + 1;
            C.Buf (SEO (C.Len)) := 0;
         end loop;
         if C.Len > 112 then
            while C.Len < 128 loop
               C.Len := C.Len + 1;
               C.Buf (SEO (C.Len)) := 0;
            end loop;
            SHA512_Compress (C.H, C.Buf);
            C.Len := 0;
            while C.Len < 112 loop
               C.Len := C.Len + 1;
               C.Buf (SEO (C.Len)) := 0;
            end loop;
         end if;
         C.Buf (113 .. 128) := C.Bits;
         SHA512_Compress (C.H, C.Buf);
         for I in 1 .. 8 loop
            HB (SEO ((I - 1) * 8 + 1) .. SEO (I * 8)) :=
              C.H (SEO ((I - 1) * 8 + 1) .. SEO (I * 8));
         end loop;
         Out_Buf (1 .. 64) := HB;
      end SHA512_Finish;

      --  ==================== HMAC ====================

      function HMAC_SHA256 (Key, M : Byte_Array) return Digest_256 is
         K   : Byte_Array (1 .. 64) := [others => 0];
         Ipad : Byte_Array (1 .. 64);
         Opad : Byte_Array (1 .. 64);
         Inner : Digest_256;
      begin
         if Key'Length > 64 then
            K (1 .. 32) := SHA256 (Key);
         else
            K (1 .. Key'Length) := Key;
         end if;
         for I in 1 .. 64 loop
            Ipad (SEO (I)) := K (SEO (I)) xor 16#36#;
            Opad (SEO (I)) := K (SEO (I)) xor 16#5C#;
         end loop;
         Inner := SHA256 (Ipad & M);
         return SHA256 (Opad & Inner);
      end HMAC_SHA256;

      function HMAC_SHA384 (Key, M : Byte_Array) return Digest_384 is
         K   : Byte_Array (1 .. 128) := [others => 0];
         Ipad : Byte_Array (1 .. 128);
         Opad : Byte_Array (1 .. 128);
         Inner : Digest_384;
      begin
         if Key'Length > 128 then
            K (1 .. 48) := SHA384 (Key);
         else
            K (1 .. Key'Length) := Key;
         end if;
         for I in 1 .. 128 loop
            Ipad (SEO (I)) := K (SEO (I)) xor 16#36#;
            Opad (SEO (I)) := K (SEO (I)) xor 16#5C#;
         end loop;
         Inner := SHA384 (Ipad & M);
         return SHA384 (Opad & Inner);
      end HMAC_SHA384;

      --  ==================== HKDF (RFC 5869) ====================

      function HKDF_Extract (Salt, IKM : Byte_Array) return Digest_256 is
         S : Byte_Array (1 .. 32) := [others => 0];
      begin
         if Salt'Length > 0 then
            S (1 .. Salt'Length) := Salt;
         end if;
         return HMAC_SHA256 (S, IKM);
      end HKDF_Extract;

      function HKDF_Expand
        (PRK : Byte_Array; Info : Byte_Array; Len : Positive)
         return Byte_Array
      is
         T : Byte_Array (1 .. 32 * 255) := [others => 0];
         T_Len : Natural := 0;
         Out_Buf : Byte_Array (1 .. SEO (Len));
         N : Natural := 0;
         Idx : Natural := 0;
         Prev : Byte_Array (1 .. 32) := [others => 0];
         Prev_Len : Natural := 0;
      begin
         if Len > 32 * 255 then
            raise Program_Error;
         end if;
         while T_Len < Len loop
            N := N + 1;
            Prev_Len := 32 + Prev_Len;
            T (SEO (Idx + 1) .. SEO (Idx + 32)) :=
              HMAC_SHA256 (PRK, Prev (1 .. SEO (Prev_Len - 32))
                            & Info & Byte (N));
            Prev (1 .. 32) := T (SEO (Idx + 1) .. SEO (Idx + 32));
            Prev_Len := 32;
            Idx := Idx + 32;
            T_Len := T_Len + 32;
         end loop;
         Out_Buf := T (1 .. SEO (Len));
         return Out_Buf;
      end HKDF_Expand;

      function HKDF_Expand_Label
        (Secret : Byte_Array; Label : String; Ctx : Byte_Array;
         Len : Positive) return Byte_Array
      is
         Info : Byte_Array (1 .. 512) := [others => 0];
         P : SEO := 1;
         L : Natural := Len;
      begin
         --  HkdfLabel: uint16 length || "tls13 " + Label || context
         Info (P) := Byte (Shift_Right (Unsigned_16 (L), 8) and 16#FF#);
         Info (P + 1) := Byte (Unsigned_16 (L) and 16#FF#);
         P := P + 2;
         Info (P) := Byte (6 + Label'Length);
         P := P + 1;
         Info (P .. P + 6) :=
           (Character'Pos ('t'), Character'Pos ('l'), Character'Pos ('s'),
            Character'Pos ('1'), Character'Pos ('3'), Character'Pos (' '),
            Character'Pos (Label (Label'First)));
         P := P + 7;
         if Label'Length > 1 then
            for I in Label'First + 1 .. Label'Last loop
               Info (P) := Character'Pos (Label (I));
               P := P + 1;
            end loop;
         end if;
         Info (P) := Byte (Ctx'Length);
         P := P + 1;
         if Ctx'Length > 0 then
            Info (P .. P + Ctx'Length - 1) := Ctx;
            P := P + Ctx'Length;
         end if;
         return HKDF_Expand (Secret, Info (1 .. P - 1), Len);
      end HKDF_Expand_Label;

      --  ==================== AES-128 ====================

      SBOX : constant array (0 .. 255) of Byte :=
        (16#63#,16#7C#,16#77#,16#7B#,16#F2#,16#6B#,16#6F#,16#C5#,
         16#30#,16#01#,16#67#,16#2B#,16#FE#,16#D7#,16#AB#,16#76#,
         16#CA#,16#82#,16#C9#,16#7D#,16#FA#,16#59#,16#47#,16#F0#,
         16#AD#,16#D4#,16#A2#,16#AF#,16#9C#,16#A4#,16#72#,16#C0#,
         16#B7#,16#FD#,16#93#,16#26#,16#36#,16#3F#,16#F7#,16#CC#,
         16#34#,16#A5#,16#E5#,16#F1#,16#71#,16#D8#,16#31#,16#15#,
         16#04#,16#C7#,16#23#,16#C3#,16#18#,16#96#,16#05#,16#9A#,
         16#07#,16#12#,16#80#,16#E2#,16#EB#,16#27#,16#B2#,16#75#,
         16#09#,16#83#,16#2C#,16#1A#,16#1B#,16#6E#,16#5A#,16#A0#,
         16#52#,16#3B#,16#D6#,16#B3#,16#29#,16#E3#,16#2F#,16#84#,
         16#53#,16#D1#,16#00#,16#ED#,16#20#,16#FC#,16#B1#,16#5B#,
         16#6A#,16#CB#,16#BE#,16#39#,16#4A#,16#4C#,16#58#,16#CF#,
         16#D0#,16#EF#,16#AA#,16#FB#,16#43#,16#4D#,16#33#,16#85#,
         16#45#,16#F9#,16#02#,16#7F#,16#50#,16#3C#,16#9F#,16#A8#,
         16#51#,16#A3#,16#40#,16#8F#,16#92#,16#9D#,16#38#,16#F5#,
         16#BC#,16#B6#,16#DA#,16#21#,16#10#,16#FF#,16#F3#,16#D2#,
         16#CD#,16#0C#,16#13#,16#EC#,16#5F#,16#97#,16#44#,16#17#,
         16#C4#,16#A7#,16#7E#,16#3D#,16#64#,16#5D#,16#19#,16#73#,
         16#60#,16#81#,16#4F#,16#DC#,16#22#,16#2A#,16#90#,16#88#,
         16#46#,16#EE#,16#B8#,16#14#,16#DE#,16#5E#,16#0B#,16#DB#,
         16#E0#,16#32#,16#3A#,16#0A#,16#49#,16#06#,16#24#,16#5C#,
         16#C2#,16#D3#,16#AC#,16#62#,16#91#,16#95#,16#E4#,16#79#,
         16#E7#,16#C8#,16#37#,16#6D#,16#8D#,16#D5#,16#4E#,16#A9#,
         16#6C#,16#56#,16#F4#,16#EA#,16#65#,16#7A#,16#AE#,16#08#,
         16#BA#,16#78#,16#25#,16#2E#,16#1C#,16#A6#,16#B4#,16#C6#,
         16#E8#,16#DD#,16#74#,16#1F#,16#4B#,16#BD#,16#8B#,16#8A#,
         16#70#,16#3E#,16#B5#,16#66#,16#48#,16#03#,16#F6#,16#0E#,
         16#61#,16#35#,16#57#,16#B9#,16#86#,16#C1#,16#1D#,16#9E#,
         16#E1#,16#F8#,16#98#,16#11#,16#69#,16#D9#,16#8E#,16#94#,
         16#9B#,16#1E#,16#87#,16#E9#,16#CE#,16#55#,16#28#,16#DF#,
         16#8C#,16#A1#,16#89#,16#0D#,16#BF#,16#E6#,16#42#,16#68#,
         16#41#,16#99#,16#2D#,16#0F#,16#B0#,16#54#,16#BB#,16#16#);

      procedure AES128_ExpandKey (Key : Byte_Array; W : out Byte_Array) is
         --  W: 176 bytes (44 words)
         Tmp : array (1 .. 4) of Byte;
         Rcon : Byte := 16#01#;
      begin
         W (1 .. 16) := Key;
         for I in 1 .. 10 loop
            Tmp (1) := W (SEO (I * 16 - 3));
            Tmp (2) := W (SEO (I * 16 - 2));
            Tmp (3) := W (SEO (I * 16 - 1));
            Tmp (4) := W (SEO (I * 16));
            --  RotWord + SubWord: [b0,b1,b2,b3] -> [S(b1),S(b2),S(b3),S(b0)]
            declare
               B0 : constant Byte := Tmp (1);
            begin
               Tmp (1) := SBOX (Natural (Tmp (2)));
               Tmp (2) := SBOX (Natural (Tmp (3)));
               Tmp (3) := SBOX (Natural (Tmp (4)));
               Tmp (4) := SBOX (Natural (B0));
            end;
            Tmp (1) := Tmp (1) xor Rcon;
            for J in 1 .. 4 loop
               W (SEO (I * 16 + J)) := W (SEO ((I - 1) * 16 + J)) xor Tmp (J);
            end loop;
            for J in 1 .. 4 loop
               W (SEO (I * 16 + 4 + J)) :=
                 W (SEO (I * 16 + J)) xor W (SEO ((I - 1) * 16 + 4 + J));
            end loop;
            for J in 1 .. 4 loop
               W (SEO (I * 16 + 8 + J)) :=
                 W (SEO (I * 16 + 4 + J)) xor W (SEO ((I - 1) * 16 + 8 + J));
            end loop;
            for J in 1 .. 4 loop
               W (SEO (I * 16 + 12 + J)) :=
                 W (SEO (I * 16 + 8 + J)) xor W (SEO ((I - 1) * 16 + 12 + J));
            end loop;
            declare
               V : Unsigned_32 := Shift_Left (Unsigned_32 (Rcon), 1);
            begin
               if (Rcon and 16#80#) /= 0 then
                  V := V xor 16#1B#;
               end if;
               Rcon := Byte (V and 16#FF#);
            end;
         end loop;
      end AES128_ExpandKey;

      procedure AES128_Encrypt_Block
        (W : Byte_Array; In_Block : Byte_Array; Out_Block : out Byte_Array)
      is
         S : array (1 .. 16) of Byte;
         T : array (1 .. 16) of Byte;
      begin
         for I in 1 .. 16 loop
            S (I) := In_Block (SEO (I)) xor W (SEO (I));
         end loop;
         for Rnd in 1 .. 9 loop
            --  SubBytes + ShiftRows + MixColumns + AddRoundKey
            for I in 0 .. 3 loop      --  columns
               for J in 0 .. 3 loop   --  rows
                  T (J * 4 + I + 1) :=
                    SBOX (Natural (S (((I + J) mod 4) * 4 + I + 1)));
               end loop;
            end loop;
            for Col in 0 .. 3 loop
               declare
                  A0 : constant Byte := T (Col * 4 + 1);
                  A1 : constant Byte := T (Col * 4 + 2);
                  A2 : constant Byte := T (Col * 4 + 3);
                  A3 : constant Byte := T (Col * 4 + 4);
                  function GM (X : Byte) return Byte is
                     V : Unsigned_32 := Shift_Left (Unsigned_32 (X), 1);
                  begin
                     if (X and 16#80#) /= 0 then
                        V := V xor 16#1B#;
                     end if;
                     return Byte (V and 16#FF#);
                  end GM;
               begin
                  S (Col * 4 + 1) := GM (A0) xor GM (A1) xor A1
                    xor A2 xor A3 xor W (SEO (Rnd * 16 + Col * 4 + 1));
                  S (Col * 4 + 2) := A0 xor GM (A1) xor GM (A2) xor A2
                    xor A3 xor W (SEO (Rnd * 16 + Col * 4 + 2));
                  S (Col * 4 + 3) := A0 xor A1 xor GM (A2) xor GM (A3)
                    xor A3 xor W (SEO (Rnd * 16 + Col * 4 + 3));
                  S (Col * 4 + 4) := GM (A0) xor A0 xor A1 xor A2
                    xor GM (A3) xor W (SEO (Rnd * 16 + Col * 4 + 4));
               end;
            end loop;
         end loop;
         --  final round: SubBytes + ShiftRows + AddRoundKey
         for I in 0 .. 3 loop
            for J in 0 .. 3 loop
               T (J * 4 + I + 1) :=
                 SBOX (Natural (S (((I + J) mod 4) * 4 + I + 1)));
            end loop;
         end loop;
         for I in 1 .. 16 loop
            Out_Block (SEO (I)) := T (I) xor W (SEO (160 + I));
         end loop;
      end AES128_Encrypt_Block;

      procedure AES128_CTR_XOR
        (W : Byte_Array; IV : Byte_Array; IV_Pos : Natural;
         Data : in out Byte_Array)
      is
         Ctr : Byte_Array (1 .. 16) := [others => 0];
         Ks  : Byte_Array (1 .. 16);
         Off : Natural := 1;
         Cpos : Natural;
      begin
         Ctr (1 .. IV'Length) := IV;
         while Off <= Data'Length loop
            AES128_Encrypt_Block (W, Ctr, Ks);
            Cpos := 1;
            while Off <= Data'Length and then Cpos <= 16 loop
               Data (Data'First + SEO (Off - 1)) :=
                 Data (Data'First + SEO (Off - 1)) xor Ks (SEO (Cpos));
               Off := Off + 1;
               Cpos := Cpos + 1;
            end loop;
            --  increment counter (big-endian, last 4 bytes)
            for I in reverse 12 .. 16 loop
               Ctr (SEO (I)) := Ctr (SEO (I)) + 1;
               exit when Ctr (SEO (I)) /= 0;
            end loop;
         end loop;
      end AES128_CTR_XOR;

      --  ==================== GHASH (GCM) ====================

      function GCM_Mul (X, Y : Byte_Array) return Byte_Array is
         --  GF(2^128) multiplication, NIST SP 800-38D Algorithm 1:
         --  process X bits MSB-first, V shifts RIGHT, R = 0xE1 (high byte).
         Z : Byte_Array (1 .. 16) := [others => 0];
         V : Byte_Array (1 .. 16) := Y;
         Lsb   : Boolean;
         Carry : Unsigned_32;
         Nxt   : Unsigned_32;
      begin
         for I in 1 .. 128 loop
            declare
               B : constant Natural := (I - 1) / 8 + 1;
               Bit : constant Natural := 7 - ((I - 1) mod 8);
            begin
               if (X (SEO (B)) and Byte (2 ** Bit)) /= 0 then
                  for J in 1 .. 16 loop
                     Z (SEO (J)) := Z (SEO (J)) xor V (SEO (J));
                  end loop;
               end if;
               --  V >>= 1 (right shift across bytes), then reduce if LSB was set
               Lsb := (V (16) and 1) /= 0;
               Carry := 0;
               for J in 1 .. 16 loop
                  Nxt := Shift_Left (Unsigned_32 (V (SEO (J)) and 1), 7);
                  V (SEO (J)) := Byte
                    ((Shift_Right (Unsigned_32 (V (SEO (J))), 1) or Carry)
                     and 16#FF#);
                  Carry := Nxt;
               end loop;
               if Lsb then
                  V (1) := V (1) xor 16#E1#;
               end if;
            end;
         end loop;
         return Z;
      end GCM_Mul;

      function Xor16 (A, B : Byte_Array) return Byte_Array is
         R : Byte_Array (1 .. 16) := A (1 .. 16);
      begin
         for K in 1 .. 16 loop
            R (SEO (K)) := R (SEO (K)) xor B (SEO (K));
         end loop;
         return R;
      end Xor16;

      function AES128GCM_Tag
        (Key, Nonce, AAD, Cipher : Byte_Array) return Tag_16
      is
         --  tag = E(K, J0) xor GHASH(H, AAD||pad||Cipher||pad||len(A)||len(C))
         W  : Byte_Array (1 .. 176);
         H  : Byte_Array (1 .. 16);
         J0 : Byte_Array (1 .. 16) := [others => 0];
         S  : Byte_Array (1 .. 16) := [others => 0];
         E  : Byte_Array (1 .. 16);
         Tmp : Byte_Array (1 .. 16);
         A_Len, C_Len : Byte_Array (1 .. 8);
         N16 : Byte_Array (1 .. 16);
         I : Natural := 0;
      begin
         AES128_ExpandKey (Key, W);
         declare
            Z : Byte_Array (1 .. 16) := [others => 0];
         begin
            AES128_Encrypt_Block (W, Z, H);
         end;
         J0 (1 .. 12) := Nonce;
         J0 (16) := 1;
         Tmp := [others => 0];
         I := 0;
         while I < AAD'Length loop
            Tmp (SEO (I mod 16 + 1)) := AAD (AAD'First + SEO (I));
            I := I + 1;
            if I mod 16 = 0 then
               S := GCM_Mul (Xor16 (S, Tmp), H);
               Tmp := [others => 0];
            end if;
         end loop;
         if I mod 16 /= 0 then
            S := GCM_Mul (Xor16 (S, Tmp), H);
            Tmp := [others => 0];
         end if;
         I := 0;
         while I < Cipher'Length loop
            Tmp (SEO (I mod 16 + 1)) := Cipher (Cipher'First + SEO (I));
            I := I + 1;
            if I mod 16 = 0 then
               S := GCM_Mul (Xor16 (S, Tmp), H);
               Tmp := [others => 0];
            end if;
         end loop;
         if I mod 16 /= 0 then
            S := GCM_Mul (Xor16 (S, Tmp), H);
         end if;
         Set_BE64 (A_Len, 1, Unsigned_64 (AAD'Length) * 8);
         Set_BE64 (C_Len, 1, Unsigned_64 (Cipher'Length) * 8);
         N16 := A_Len & C_Len;
         S := GCM_Mul (Xor16 (S, N16), H);
         AES128_Encrypt_Block (W, J0, E);
         for K in 1 .. 16 loop
            E (SEO (K)) := E (SEO (K)) xor S (SEO (K));
         end loop;
         return E;
      end AES128GCM_Tag;

      procedure AES128GCM_Seal
        (Key, Nonce : Byte_Array; AAD, Plain : Byte_Array;
         Cipher : out Byte_Array; Cipher_Len : out SEO;
         Tag : out Tag_16; Ok : out Boolean)
      is
         W  : Byte_Array (1 .. 176);
         J0 : Byte_Array (1 .. 16) := [others => 0];
         Ctr : Byte_Array (1 .. 16);
      begin
         Ok := False;
         if Nonce'Length /= 12 or Cipher'Length < Plain'Length then
            return;
         end if;
         AES128_ExpandKey (Key, W);
         J0 (1 .. 12) := Nonce;
         J0 (16) := 1;
         --  encrypt plaintext with counter starting at J0+1
         Ctr := J0;
         for K in reverse 12 .. 16 loop
            Ctr (SEO (K)) := Ctr (SEO (K)) + 1;
            exit when Ctr (SEO (K)) /= 0;
         end loop;
         Cipher (1 .. Plain'Length) := Plain;
         AES128_CTR_XOR (W, Ctr, 1, Cipher (1 .. Plain'Length));
         Tag := AES128GCM_Tag (Key, Nonce, AAD, Cipher (1 .. Plain'Length));
         Cipher_Len := Plain'Length;
         Ok := True;
      end AES128GCM_Seal;

      function AES128GCM_Open
        (Key, Nonce : Byte_Array; AAD, Cipher : Byte_Array;
         Tag : Tag_16; Plain : out Byte_Array) return SEO
      is
         W  : Byte_Array (1 .. 176);
         J0 : Byte_Array (1 .. 16) := [others => 0];
         Ctr : Byte_Array (1 .. 16);
         Calc_Tag : Tag_16;
      begin
         if Nonce'Length /= 12 or Cipher'Length > Plain'Length then
            return -1;
         end if;
         AES128_ExpandKey (Key, W);
         J0 (1 .. 12) := Nonce;
         J0 (16) := 1;
         Ctr := J0;
         for K in reverse 12 .. 16 loop
            Ctr (SEO (K)) := Ctr (SEO (K)) + 1;
            exit when Ctr (SEO (K)) /= 0;
         end loop;
         Plain (1 .. Cipher'Length) := Cipher;
         AES128_CTR_XOR (W, Ctr, 1, Plain (1 .. Cipher'Length));
         Calc_Tag := AES128GCM_Tag (Key, Nonce, AAD, Cipher);
         for K in 1 .. 16 loop
            if Calc_Tag (SEO (K)) /= Tag (SEO (K)) then
               return -1;
            end if;
         end loop;
         return Cipher'Length;
      end AES128GCM_Open;

      --  ==================== ChaCha20-Poly1305 (RFC 8439) ====================

      function ROTL32 (V : Unsigned_32; N : Natural) return Unsigned_32 is
      begin
         return Shift_Left (V, N) or Shift_Right (V, 32 - N);
      end ROTL32;

      procedure ChaCha20_Block
        (Key : Byte_Array; Counter : Unsigned_32; Nonce : Byte_Array;
         Out_Block : out Byte_Array)  --  64 bytes
      is
         type S16 is array (1 .. 16) of Unsigned_32;
         State : S16;
         X     : S16;
         C     : constant array (1 .. 4) of Unsigned_32 :=
           (16#61707865#, 16#3320646E#, 16#79622D32#, 16#6B206574#);

         function LE32b (B : Byte_Array; I : SEO) return Unsigned_32 is
         begin
            return Unsigned_32 (B (I))
              or Shift_Left (Unsigned_32 (B (I + 1)), 8)
              or Shift_Left (Unsigned_32 (B (I + 2)), 16)
              or Shift_Left (Unsigned_32 (B (I + 3)), 24);
         end LE32b;

         procedure Set_LE32b (B : in out Byte_Array; I : SEO; V : Unsigned_32) is
         begin
            B (I)     := Byte (V and 16#FF#);
            B (I + 1) := Byte (Shift_Right (V, 8) and 16#FF#);
            B (I + 2) := Byte (Shift_Right (V, 16) and 16#FF#);
            B (I + 3) := Byte (Shift_Right (V, 24) and 16#FF#);
         end Set_LE32b;

         procedure QR (A, B, Cc, D : in out Unsigned_32) is
            A0 : Unsigned_32 := A;
            B0 : Unsigned_32 := B;
            C0 : Unsigned_32 := Cc;
            D0 : Unsigned_32 := D;
         begin
            A0 := A0 + B0;  D0 := D0 xor A0;  D0 := ROTL32 (D0, 16);
            C0 := C0 + D0;  B0 := B0 xor C0;  B0 := ROTL32 (B0, 12);
            A0 := A0 + B0;  D0 := D0 xor A0;  D0 := ROTL32 (D0, 8);
            C0 := C0 + D0;  B0 := B0 xor C0;  B0 := ROTL32 (B0, 7);
            A := A0; B := B0; Cc := C0; D := D0;
         end QR;
      begin
         State (1) := C (1); State (2) := C (2);
         State (3) := C (3); State (4) := C (4);
         State (5 .. 8) := (LE32b (Key, 1), LE32b (Key, 5),
                            LE32b (Key, 9), LE32b (Key, 13));
         State (9 .. 12) := (LE32b (Key, 17), LE32b (Key, 21),
                             LE32b (Key, 25), LE32b (Key, 29));
         State (13) := Counter;
         State (14) := LE32b (Nonce, 1);
         State (15) := LE32b (Nonce, 5);
         State (16) := LE32b (Nonce, 9);
         X := State;
         for I in 1 .. 10 loop
            --  column round
            QR (X (1),  X (5),  X (9),  X (13));
            QR (X (2),  X (6),  X (10), X (14));
            QR (X (3),  X (7),  X (11), X (15));
            QR (X (4),  X (8),  X (12), X (16));
            --  diagonal round
            QR (X (1),  X (6),  X (11), X (16));
            QR (X (2),  X (7),  X (12), X (13));
            QR (X (3),  X (8),  X (9),  X (14));
            QR (X (4),  X (5),  X (10), X (15));
         end loop;
         for I in 1 .. 16 loop
            Set_LE32b (Out_Block, SEO ((I - 1) * 4 + 1), X (I) + State (I));
         end loop;
      end ChaCha20_Block;

      procedure ChaCha20_XOR
        (Key : Byte_Array; Nonce : Byte_Array; Counter : Unsigned_32;
         Data : in out Byte_Array)
      is
         Block : Byte_Array (1 .. 64);
         Ctr : Unsigned_32 := Counter;
         Off : Natural := 1;
      begin
         while Off <= Data'Length loop
            ChaCha20_Block (Key, Ctr, Nonce, Block);
            for I in 1 .. 64 loop
               exit when Off > Data'Length;
               Data (Data'First + SEO (Off - 1)) :=
                 Data (Data'First + SEO (Off - 1)) xor Block (SEO (I));
               Off := Off + 1;
            end loop;
            Ctr := Ctr + 1;
         end loop;
      end ChaCha20_XOR;

      function LE32 (B : Byte_Array; I : SEO) return Unsigned_32 is
      begin
         return Unsigned_32 (B (I))
           or Shift_Left (Unsigned_32 (B (I + 1)), 8)
           or Shift_Left (Unsigned_32 (B (I + 2)), 16)
           or Shift_Left (Unsigned_32 (B (I + 3)), 24);
      end LE32;

      function LE64 (B : Byte_Array; I : SEO) return Unsigned_64 is
      begin
         return Unsigned_64 (LE32 (B, I))
           or Shift_Left (Unsigned_64 (LE32 (B, I + 4)), 32);
      end LE64;

      procedure Set_LE64 (B : in out Byte_Array; I : SEO; V : Unsigned_64) is
      begin
         B (I)     := Byte (V and 16#FF#);
         B (I + 1) := Byte (Shift_Right (V, 8) and 16#FF#);
         B (I + 2) := Byte (Shift_Right (V, 16) and 16#FF#);
         B (I + 3) := Byte (Shift_Right (V, 24) and 16#FF#);
         B (I + 4) := Byte (Shift_Right (V, 32) and 16#FF#);
         B (I + 5) := Byte (Shift_Right (V, 40) and 16#FF#);
         B (I + 6) := Byte (Shift_Right (V, 48) and 16#FF#);
         B (I + 7) := Byte (Shift_Right (V, 56) and 16#FF#);
      end Set_LE64;

      function Poly1305
        (Key : Byte_Array; Msg : Byte_Array) return Byte_Array  --  16 bytes
      is
         --  5x26-bit limb arithmetic (poly1305-donna style)
         R : array (0 .. 4) of Unsigned_64 := [others => 0];
         H : array (0 .. 4) of Unsigned_64 := [others => 0];
         D : array (0 .. 8) of Unsigned_64;
         C : Unsigned_64;
         W0, W1, W2, W3 : Unsigned_32;
         P : Natural := 0;
         Tag : Byte_Array (1 .. 16);
         H_lo, H_hi, S_lo, S_hi, Sum_lo, Sum_hi : Unsigned_64;
      begin
         --  load r (little-endian) and clamp (RFC 8439 2.5.1)
         W0 := LE32 (Key, 1);  W1 := LE32 (Key, 5);
         W2 := LE32 (Key, 9);  W3 := LE32 (Key, 13);
         R (0) := Unsigned_64 (W0) and 16#3FF_FFFF#;
         R (1) := (Shift_Right (Unsigned_64 (W0), 26)
                   or Shift_Left (Unsigned_64 (W1) and 16#FFFFF#, 6))
                   and 16#3FFFF03#;
         R (2) := (Shift_Right (Unsigned_64 (W1), 20)
                   or Shift_Left (Unsigned_64 (W2) and 16#3FFF#, 12))
                   and 16#3FFC0FF#;
         R (3) := (Shift_Right (Unsigned_64 (W2), 14)
                   or Shift_Left (Unsigned_64 (W3) and 16#FF#, 18))
                   and 16#3F03FFF#;
         R (4) := Shift_Right (Unsigned_64 (W3), 8) and 16#FFFFF#;
         --  process blocks: 16 message bytes (+1 terminating byte)
         while P < Msg'Length loop
            declare
               B   : array (0 .. 4) of Unsigned_64 := [others => 0];
               N   : Natural := 0;
               Blk : Byte_Array (1 .. 17) := [others => 0];
               LB1, LB2 : Unsigned_64;
            begin
               while P < Msg'Length and then N < 16 loop
                  Blk (SEO (N + 1)) := Msg (Msg'First + SEO (P));
                  P := P + 1;
                  N := N + 1;
               end loop;
               Blk (SEO (N + 1)) := 1;
               --  bytes 1..8 little-endian -> bits 0..63
               LB1 := 0;
               for I in reverse 1 .. 8 loop
                  LB1 := Shift_Left (LB1, 8) or Unsigned_64 (Blk (SEO (I)));
               end loop;
               --  bytes 9..16 little-endian -> bits 64..127
               LB2 := 0;
               for I in reverse 9 .. 16 loop
                  LB2 := Shift_Left (LB2, 8) or Unsigned_64 (Blk (SEO (I)));
               end loop;
               B (0) := LB1 and 16#3FF_FFFF#;
               B (1) := Shift_Right (LB1, 26) and 16#3FF_FFFF#;
               B (2) := Shift_Right (LB1, 52)
                 or Shift_Left (LB2 and 16#3FFF#, 12);
               B (3) := Shift_Right (LB2, 14) and 16#3FF_FFFF#;
               B (4) := Shift_Right (LB2, 40)
                 or Shift_Left (Unsigned_64 (Blk (SEO (17))), 24);
               --  h += b (with carry propagation)
               H (0) := H (0) + B (0);
               C := Shift_Right (H (0), 26);  H (0) := H (0) and 16#3FF_FFFF#;
               H (1) := H (1) + B (1) + C;
               C := Shift_Right (H (1), 26);  H (1) := H (1) and 16#3FF_FFFF#;
               H (2) := H (2) + B (2) + C;
               C := Shift_Right (H (2), 26);  H (2) := H (2) and 16#3FF_FFFF#;
               H (3) := H (3) + B (3) + C;
               C := Shift_Right (H (3), 26);  H (3) := H (3) and 16#3FF_FFFF#;
               H (4) := H (4) + B (4) + C;
               C := Shift_Right (H (4), 26);  H (4) := H (4) and 16#3FF_FFFF#;
               H (0) := H (0) + 5 * C;
               --  h *= r (schoolbook, 25 products into 9 limbs)
               D := [others => 0];
               for I in 0 .. 4 loop
                  for J in 0 .. 4 loop
                     D (I + J) := D (I + J) + H (I) * R (J);
                  end loop;
               end loop;
               --  reduce mod 2^130-5: fold D5..D8 (2^130 = 5)
               D (0) := D (0) + 5 * D (5);
               D (1) := D (1) + 5 * D (6);
               D (2) := D (2) + 5 * D (7);
               D (3) := D (3) + 5 * D (8);
               C := Shift_Right (D (0), 26);  D (0) := D (0) and 16#3FF_FFFF#;
               D (1) := D (1) + C;
               C := Shift_Right (D (1), 26);  D (1) := D (1) and 16#3FF_FFFF#;
               D (2) := D (2) + C;
               C := Shift_Right (D (2), 26);  D (2) := D (2) and 16#3FF_FFFF#;
               D (3) := D (3) + C;
               C := Shift_Right (D (3), 26);  D (3) := D (3) and 16#3FF_FFFF#;
               D (4) := D (4) + C;
               C := Shift_Right (D (4), 26);  D (4) := D (4) and 16#3FF_FFFF#;
               D (0) := D (0) + 5 * C;
               C := Shift_Right (D (0), 26);  D (0) := D (0) and 16#3FF_FFFF#;
               D (1) := D (1) + C;
               H := (D (0), D (1), D (2), D (3), D (4));
            end;
         end loop;
         --  tag = (h + s) mod 2^128, little-endian
         H_lo := H (0) or Shift_Left (H (1), 26)
           or Shift_Left (H (2) and 16#FFF#, 52);
         H_hi := Shift_Right (H (2), 12)
           or Shift_Left (H (3), 14)
           or Shift_Left (H (4) and 16#FF_FFFF#, 40);
         S_lo := LE64 (Key, 17);
         S_hi := LE64 (Key, 25);
         Sum_lo := H_lo + S_lo;
         Sum_hi := H_hi + S_hi;
         if Sum_lo < H_lo then
            Sum_hi := Sum_hi + 1;
         end if;
         Set_LE64 (Tag, 1, Sum_lo);
         Set_LE64 (Tag, 9, Sum_hi);
         return Tag;
      end Poly1305;

      function ChaCha20Poly1305_Tag
        (Key, Nonce, AAD, Cipher : Byte_Array) return Tag_16
      is
         --  Poly1305 over AAD || pad16(AAD) || CT || pad16(CT) || len(AAD) || len(CT)
         Pk  : Byte_Array (1 .. 32);
         Blk : Byte_Array (1 .. 64);
         A_Len, C_Len : Byte_Array (1 .. 8);
      begin
         --  Poly1305 key = ChaCha20 block 0 (first 32 bytes)
         ChaCha20_Block (Key, 0, Nonce, Blk);
         Pk := Blk (1 .. 32);
         declare
            Pad_AAD : constant Natural := (16 - (AAD'Length mod 16)) mod 16;
            Pad_CT  : constant Natural := (16 - (Cipher'Length mod 16)) mod 16;
            Total   : constant Natural :=
              AAD'Length + Pad_AAD + Cipher'Length + Pad_CT + 16;
            Mac_Data : Byte_Array (1 .. SEO (Total));
            Mac_Len  : Natural := 0;
         begin
            Mac_Data := [others => 0];
            if AAD'Length > 0 then
               Mac_Data (1 .. AAD'Length) := AAD;
               Mac_Len := AAD'Length + Pad_AAD;
            end if;
            if Cipher'Length > 0 then
               Mac_Data (SEO (Mac_Len + 1) .. SEO (Mac_Len + Cipher'Length)) :=
                 Cipher;
               Mac_Len := Mac_Len + Cipher'Length + Pad_CT;
            end if;
            Set_LE64 (A_Len, 1, Unsigned_64 (AAD'Length));
            Set_LE64 (C_Len, 1, Unsigned_64 (Cipher'Length));
            Mac_Data (SEO (Mac_Len + 1) .. SEO (Mac_Len + 8)) := A_Len;
            Mac_Data (SEO (Mac_Len + 9) .. SEO (Mac_Len + 16)) := C_Len;
            return Poly1305 (Pk, Mac_Data (1 .. SEO (Mac_Len + 16)));
         end;
      end ChaCha20Poly1305_Tag;

      procedure ChaCha20Poly1305_Seal
        (Key, Nonce : Byte_Array; AAD, Plain : Byte_Array;
         Cipher : out Byte_Array; Cipher_Len : out SEO;
         Tag : out Tag_16; Ok : out Boolean)
      is
      begin
         Ok := False;
         if Key'Length /= 32 or Nonce'Length /= 12
           or Cipher'Length < Plain'Length
         then
            return;
         end if;
         --  encrypt with counter starting at 1
         Cipher (1 .. Plain'Length) := Plain;
         ChaCha20_XOR (Key, Nonce, 1, Cipher (1 .. Plain'Length));
         Tag := ChaCha20Poly1305_Tag (Key, Nonce, AAD, Cipher (1 .. Plain'Length));
         Cipher_Len := Plain'Length;
         Ok := True;
      end ChaCha20Poly1305_Seal;

      function ChaCha20Poly1305_Open
        (Key, Nonce : Byte_Array; AAD, Cipher : Byte_Array;
         Tag : Tag_16; Plain : out Byte_Array) return SEO
      is
         Calc_Tag : Tag_16;
      begin
         if Key'Length /= 32 or Nonce'Length /= 12
           or Cipher'Length > Plain'Length
         then
            return -1;
         end if;
         Plain (1 .. Cipher'Length) := Cipher;
         ChaCha20_XOR (Key, Nonce, 1, Plain (1 .. Cipher'Length));
         Calc_Tag := ChaCha20Poly1305_Tag (Key, Nonce, AAD, Cipher);
         for K in 1 .. 16 loop
            if Calc_Tag (SEO (K)) /= Tag (SEO (K)) then
               return -1;
            end if;
         end loop;
         return Cipher'Length;
      end ChaCha20Poly1305_Open;

      --  ==================== X25519 (RFC 7748) ====================
      --  field arithmetic mod p = 2^255-19, 8x32-bit little-endian limbs.
      --  Multiplication is schoolbook 32x32 -> 64, then reduction uses
      --  2^256 = 38 (mod p) on the high limbs, followed by a conditional
      --  subtraction of p.  (Same construction as the RFC 7748 reference.)

      subtype Limbs8 is Byte_Array (1 .. 32);

      --  p = 2^255 - 19, as 8 x 32-bit little-endian limbs
      P_L : constant array (0 .. 7) of Unsigned_32 :=
        (16#FFFF_FFED#, 16#FFFF_FFFF#, 16#FFFF_FFFF#, 16#FFFF_FFFF#,
         16#FFFF_FFFF#, 16#FFFF_FFFF#, 16#FFFF_FFFF#, 16#7FFF_FFFF#);

      type L8 is array (0 .. 7) of Unsigned_32;

      procedure Set_LE32 (B : in out Byte_Array; I : SEO; V : Unsigned_32) is
      begin
         B (I)     := Byte (V and 16#FF#);
         B (I + 1) := Byte (Shift_Right (V, 8) and 16#FF#);
         B (I + 2) := Byte (Shift_Right (V, 16) and 16#FF#);
         B (I + 3) := Byte (Shift_Right (V, 24) and 16#FF#);
      end Set_LE32;

      procedure L8_To (R : out Limbs8; A : L8) is
      begin
         for I in 0 .. 7 loop
            Set_LE32 (R, SEO (I * 4 + 1), A (I));
         end loop;
      end L8_To;

      --  A := A - p when A >= p (assumes A < 2^256)
      procedure Sub_P_If_GE (A : in out L8) is
         GE     : Boolean := False;
         Eq     : Boolean := True;
         Borrow : Unsigned_128;
         S      : Unsigned_128;
      begin
         for I in reverse 0 .. 7 loop
            if A (I) > P_L (I) then
               GE := True; Eq := False; exit;
            elsif A (I) < P_L (I) then
               Eq := False; exit;
            end if;
         end loop;
         if Eq then GE := True; end if;
         if GE then
            Borrow := 0;
            for I in 0 .. 7 loop
               S := Unsigned_128 (A (I)) - Unsigned_128 (P_L (I)) - Borrow;
               A (I) := Unsigned_32 (S and 16#FFFF_FFFF#);
               Borrow := (if S > 16#FFFF_FFFF# then 1 else 0);
            end loop;
         end if;
      end Sub_P_If_GE;

      procedure F_Add (R : out Limbs8; A, B : Limbs8) is
         L : L8;
         C : Unsigned_128 := 0;
         S : Unsigned_128;
      begin
         for I in 0 .. 7 loop
            S := C + Unsigned_128 (LE32 (A, SEO (I * 4 + 1)))
                   + Unsigned_128 (LE32 (B, SEO (I * 4 + 1)));
            L (I) := Unsigned_32 (S and 16#FFFF_FFFF#);
            C := Shift_Right (S, 32);
         end loop;
         Sub_P_If_GE (L);
         L8_To (R, L);
      end F_Add;

      procedure F_Sub (R : out Limbs8; A, B : Limbs8) is
         L : L8;
         Borrow : Unsigned_128 := 0;
         S : Unsigned_128;
         C : Unsigned_128;
      begin
         for I in 0 .. 7 loop
            S := Unsigned_128 (LE32 (A, SEO (I * 4 + 1)))
                   - Unsigned_128 (LE32 (B, SEO (I * 4 + 1))) - Borrow;
            L (I) := Unsigned_32 (S and 16#FFFF_FFFF#);
            Borrow := (if S > 16#FFFF_FFFF# then 1 else 0);
         end loop;
         if Borrow /= 0 then
            C := 0;
            for I in 0 .. 7 loop
               S := Unsigned_128 (L (I)) + Unsigned_128 (P_L (I)) + C;
               L (I) := Unsigned_32 (S and 16#FFFF_FFFF#);
               C := Shift_Right (S, 32);
            end loop;
         end if;
         L8_To (R, L);
      end F_Sub;

      procedure F_Mul (R : out Limbs8; A, B : Limbs8) is
         C : array (0 .. 15) of Unsigned_128 := [others => 0];
         L : L8;
         X, Y : L8;
         S : Unsigned_128;
         Carry : Unsigned_128;
         Add : Unsigned_128;
      begin
         for I in 0 .. 7 loop
            X (I) := LE32 (A, SEO (I * 4 + 1));
            Y (I) := LE32 (B, SEO (I * 4 + 1));
         end loop;
         for I in 0 .. 7 loop
            for J in 0 .. 7 loop
               C (I + J) := C (I + J)
                 + Unsigned_128 (X (I)) * Unsigned_128 (Y (J));
            end loop;
         end loop;
         --  fold: 2^(32*K) = 38 * 2^(32*(K-8)) for K >= 8
         for K in 8 .. 15 loop
            C (K - 8) := C (K - 8) + C (K) * 38;
         end loop;
         Carry := 0;
         for I in 0 .. 7 loop
            S := C (I) + Carry;
            L (I) := Unsigned_32 (S and 16#FFFF_FFFF#);
            Carry := Shift_Right (S, 32);
         end loop;
         --  fold final carry: Carry * 2^256 = Carry * 38 (mod p)
         Add := Carry * 38;
         for I in 0 .. 7 loop
            S := Unsigned_128 (L (I)) + Add;
            L (I) := Unsigned_32 (S and 16#FFFF_FFFF#);
            Add := Shift_Right (S, 32);
            exit when Add = 0;
         end loop;
         Sub_P_If_GE (L);
         Sub_P_If_GE (L);
         L8_To (R, L);
      end F_Mul;

      procedure F_Sqr (R : out Limbs8; A : Limbs8) is
      begin
         F_Mul (R, A, A);
      end F_Sqr;

      function F_Is_Zero (A : Limbs8) return Boolean is
      begin
         for I in 1 .. 32 loop
            if A (SEO (I)) /= 0 then
               return False;
            end if;
         end loop;
         return True;
      end F_Is_Zero;

      procedure F_Pow
        (R : out Limbs8; A : Limbs8; Exp_LE : Byte_Array)
      is
         --  R = A^Exp mod p; Exp given little-endian (MSB-first square-and-multiply)
         Res : Limbs8 := [others => 0];
      begin
         Res (1) := 1;
         for I in reverse Exp_LE'Range loop
            for B in reverse 0 .. 7 loop
               F_Sqr (Res, Res);
               if (Exp_LE (I) and Byte (2 ** B)) /= 0 then
                  F_Mul (Res, Res, A);
               end if;
            end loop;
         end loop;
         R := Res;
      end F_Pow;

      procedure F_Inv (R : out Limbs8; A : Limbs8) is
         --  a^(p-2) mod p;  p-2 = 0x7FFF...FFEB
         Exp : constant Byte_Array (1 .. 32) :=
           (16#EB#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
            16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
            16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
            16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#7F#);
      begin
         F_Pow (R, A, Exp);
      end F_Inv;

      procedure F_Sqrt (R : out Limbs8; A : Limbs8) is
         --  a^((p-5)/8) mod p;  (p-5)/8 = 2^252 - 3 = 0x0FFF...FFFD
         Exp : constant Byte_Array (1 .. 32) :=
           (16#FD#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
            16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
            16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
            16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#0F#);
      begin
         F_Pow (R, A, Exp);
      end F_Sqrt;

      --  X25519 Montgomery ladder (RFC 7748 section 5)

      A24_F : constant Limbs8 :=
        (16#41#, 16#DB#, 16#01#, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

      procedure C_Swap (Swap : Boolean; A, B : in out Limbs8) is
         Tmp : Limbs8;
      begin
         if Swap then
            Tmp := A; A := B; B := Tmp;
         end if;
      end C_Swap;

      procedure X25519_Ladder
        (R : out Limbs8; K : Byte_Array; U : Limbs8)
      is
         X1 : Limbs8 := U;
         X2 : Limbs8 := [others => 0];
         Z2 : Limbs8 := [others => 0];
         X3 : Limbs8 := U;
         Z3 : Limbs8 := [others => 0];
         A, AA, B, BB, E, C, D, DA, CB, T1, T2 : Limbs8;
         Swap : Boolean := False;
         KB : Byte_Array (1 .. 32);
      begin
         X2 (1) := 1;
         Z3 (1) := 1;
         --  clamp the scalar
         KB := K;
         KB (1) := Byte (Unsigned_32 (KB (1)) and 16#F8#);
         KB (32) := Byte (Unsigned_32 (KB (32)) or 16#40#);
         KB (32) := Byte (Unsigned_32 (KB (32)) and 16#7F#);
         for T in reverse 0 .. 254 loop
            declare
               Bit : constant Boolean :=
                 (KB (SEO (T / 8 + 1)) and Byte (2 ** (T mod 8))) /= 0;
            begin
               Swap := Swap xor Bit;
               C_Swap (Swap, X2, X3);
               C_Swap (Swap, Z2, Z3);
               Swap := Bit;
               F_Add (A, X2, Z2);
               F_Sqr (AA, A);
               F_Sub (B, X2, Z2);
               F_Sqr (BB, B);
               F_Sub (E, AA, BB);
               F_Add (C, X3, Z3);
               F_Sub (D, X3, Z3);
               F_Mul (DA, D, A);
               F_Mul (CB, C, B);
               F_Add (T1, DA, CB);
               F_Sqr (T1, T1);
               F_Sub (T2, DA, CB);
               F_Sqr (T2, T2);
               X3 := T1;
               F_Mul (T2, X1, T2);
               Z3 := T2;
               F_Mul (T1, AA, BB);
               X2 := T1;
               F_Mul (T2, E, A24_F);       --  a24*E
               F_Add (T1, AA, T2);         --  AA + a24*E
               F_Mul (Z2, E, T1);          --  z2 = E * (AA + a24*E)
            end;
         end loop;
         C_Swap (Swap, X2, X3);
         C_Swap (Swap, Z2, Z3);
         declare
            Inv_Z : Limbs8;
            Res : Limbs8;
         begin
            F_Inv (Inv_Z, Z2);
            F_Mul (Res, X2, Inv_Z);
            R := Res;
         end;
      end X25519_Ladder;

      --  ==================== generic big integers ====================
      --  64-bit little-endian limbs, Unsigned_128 arithmetic.
      --  Used by P-256 and RSA.

      subtype U128 is Interfaces.Unsigned_128;
      MaxL : constant := 64;               --  4096 bits

      type U64_Arr is array (1 .. MaxL) of Unsigned_64;

      type BI is record
         Len : Natural := 0;               --  number of significant limbs
         L : U64_Arr := [others => 0];
      end record;

      function BI_Zero return BI is
      begin
         return (Len => 0, L => [others => 0]);
      end BI_Zero;

      function BI_One return BI is
         R : BI;
      begin
         R.Len := 1;
         R.L (1) := 1;
         return R;
      end BI_One;

      function BI_Is_Zero (A : BI) return Boolean is
      begin
         return A.Len = 0;
      end BI_Is_Zero;

      procedure BI_Norm (A : in out BI) is
      begin
         while A.Len > 0 and then A.L (A.Len) = 0 loop
            A.Len := A.Len - 1;
         end loop;
      end BI_Norm;

      function BI_Cmp (A, B : BI) return Integer is
         I : Natural;
      begin
         if A.Len /= B.Len then
            return (if A.Len > B.Len then 1 else -1);
         end if;
         I := A.Len;
         while I >= 1 loop
            if A.L (I) /= B.L (I) then
               return (if A.L (I) > B.L (I) then 1 else -1);
            end if;
            I := I - 1;
         end loop;
         return 0;
      end BI_Cmp;

      function BI_Add (A, B : BI) return BI is
         Carry : U128 := 0;
         N : constant Natural := Natural'Max (A.Len, B.Len);
         R : BI := BI_Zero;
      begin
         for I in 1 .. N loop
            Carry := Carry + U128 (A.L (I)) + U128 (B.L (I));
            R.L (I) := Unsigned_64 (Carry and 16#FFFF_FFFF_FFFF_FFFF#);
            Carry := Shift_Right (Carry, 64);
         end loop;
         if Carry /= 0 then
            R.L (N + 1) := Unsigned_64 (Carry);
            R.Len := N + 1;
         else
            R.Len := N;
         end if;
         BI_Norm (R);
         return R;
      end BI_Add;

      --  R = A - B, requires A >= B
      function BI_Sub (A, B : BI) return BI is
         Borrow : U128 := 0;
         R : BI := BI_Zero;
      begin
         R.Len := A.Len;
         for I in 1 .. A.Len loop
            Borrow := U128 (A.L (I)) - U128 (B.L (I)) - Borrow;
            R.L (I) := Unsigned_64 (Borrow and 16#FFFF_FFFF_FFFF_FFFF#);
            Borrow := (if Borrow > 16#FFFF_FFFF_FFFF_FFFF# then 1 else 0);
         end loop;
         BI_Norm (R);
         return R;
      end BI_Sub;

      function BI_Shl_Bit (A : BI; N : Natural) return BI is
         R : BI;
         W : Natural := N / 64;
         B : Natural := N mod 64;
      begin
         R := BI_Zero;
         if A.Len = 0 then
            return R;
         end if;
         for I in reverse 1 .. A.Len loop
            if I + W <= MaxL then
               R.L (I + W) := R.L (I + W)
                 or Shift_Left (A.L (I), B);
            end if;
            if B > 0 and then I + W + 1 <= MaxL then
               R.L (I + W + 1) := R.L (I + W + 1)
                 or Shift_Right (A.L (I), 64 - B);
            end if;
         end loop;
         R.Len := A.Len + W + (if B > 0 then 1 else 0);
         BI_Norm (R);
         return R;
      end BI_Shl_Bit;

      procedure BI_Mul (R : out BI; A, B : BI) is
         P : array (1 .. MaxL * 2 + 2) of Unsigned_64 := [others => 0];
         Prod : U128;
         K : Natural;
         N : Natural := A.Len + B.Len;
      begin
         R := BI_Zero;
         --  schoolbook, adding each 64x64=128-bit product with full carry
         for I in 1 .. A.Len loop
            for J in 1 .. B.Len loop
               Prod := U128 (A.L (I)) * U128 (B.L (J));
               K := I + J - 1;
               --  add low limb
               Prod := Prod + U128 (P (K));
               P (K) := Unsigned_64 (Prod and 16#FFFF_FFFF_FFFF_FFFF#);
               Prod := Shift_Right (Prod, 64);
               --  propagate carry through higher limbs
               while Prod /= 0 loop
                  K := K + 1;
                  Prod := Prod + U128 (P (K));
                  P (K) := Unsigned_64 (Prod and 16#FFFF_FFFF_FFFF_FFFF#);
                  Prod := Shift_Right (Prod, 64);
               end loop;
            end loop;
         end loop;
         for I in 1 .. N loop
            R.L (I) := P (I);
         end loop;
         R.Len := N;
         BI_Norm (R);
      end BI_Mul;

      function BI_Leading_Zeros (V : Unsigned_64) return Natural is
         N : Natural := 0;
      begin
         while N < 64 and then
           (V and Shift_Left (1, 63 - N)) = 0
         loop
            N := N + 1;
         end loop;
         return N;
      end BI_Leading_Zeros;

      --  R = Num mod Den  (long division, bit by bit)
      function BI_Mod (Num, Den : BI) return BI is
         R : BI := BI_Zero;
         Bits : constant Natural :=
           (if Num.Len = 0 then 0
            else Num.Len * 64 - BI_Leading_Zeros (Num.L (Num.Len)));
      begin
         if BI_Is_Zero (Den) then
            raise Program_Error;
         end if;
         if BI_Cmp (Num, Den) < 0 then
            return Num;
         end if;
         for I in reverse 0 .. Bits - 1 loop
            declare
               Bit : constant Unsigned_64 :=
                 (Shift_Right (Num.L (I / 64 + 1), I mod 64)) and 1;
            begin
               R := BI_Shl_Bit (R, 1);
               if Bit = 1 then
                  R := BI_Add (R, BI_One);
               end if;
               if BI_Cmp (R, Den) >= 0 then
                  R := BI_Sub (R, Den);
               end if;
            end;
         end loop;
         return R;
      end BI_Mod;

      function BI_From_LE (B : Byte_Array) return BI is
         R : BI := BI_Zero;
         N : Natural := B'Length / 8;
      begin
         R.Len := N;
         for I in 1 .. N loop
            R.L (I) := LE64 (B, B'First + SEO ((I - 1) * 8));
         end loop;
         if B'Length mod 8 /= 0 then
            declare
               V : Unsigned_64 := 0;
               Base : constant SEO := B'First + SEO (N * 8);
            begin
               for K in 0 .. (B'Length mod 8) - 1 loop
                  V := V or Shift_Left (Unsigned_64 (B (Base + SEO (K))), K * 8);
               end loop;
               R.Len := N + 1;
               R.L (N + 1) := V;
            end;
         end if;
         BI_Norm (R);
         return R;
      end BI_From_LE;

      function BI_From_BE (B : Byte_Array) return BI is
         Rev : Byte_Array (B'Range);
      begin
         for I in B'Range loop
            Rev (I) := B (B'First + B'Last - I);
         end loop;
         return BI_From_LE (Rev);
      end BI_From_BE;

      procedure BI_To_LE (A : BI; B : out Byte_Array) is
         N : constant Natural := (A.Len * 8);
      begin
         B := [others => 0];
         for I in 1 .. A.Len loop
            if (I - 1) * 8 + 8 <= B'Length then
               Set_LE64 (B, SEO ((I - 1) * 8 + 1), A.L (I));
            else
               declare
                  V : Unsigned_64 := A.L (I);
               begin
                  for K in 0 .. B'Length - (I - 1) * 8 - 1 loop
                     B (SEO ((I - 1) * 8 + 1 + K)) :=
                       Byte (Shift_Right (V, K * 8) and 16#FF#);
                  end loop;
               end;
            end if;
         end loop;
      end BI_To_LE;

      function BI_Mod_Mul (A, B, M : BI) return BI is
         P : BI;
      begin
         BI_Mul (P, A, B);
         return BI_Mod (P, M);
      end BI_Mod_Mul;

      function BI_Shr (A : BI; N : Natural) return BI is
         R : BI := A;
         W : Natural := N / 64;
         B : Natural := N mod 64;
      begin
         if W > 0 then
            if W >= R.Len then
               return BI_Zero;
            end if;
            for I in 1 .. R.Len - W loop
               R.L (I) := R.L (I + W);
            end loop;
            for I in R.Len - W + 1 .. MaxL loop
               R.L (I) := 0;
            end loop;
            R.Len := R.Len - W;
         end if;
         if B > 0 then
            for I in 1 .. R.Len loop
               R.L (I) := Shift_Right (R.L (I), B);
               if I < R.Len then
                  R.L (I) := R.L (I)
                    or Shift_Left (R.L (I + 1), 64 - B);
               end if;
            end loop;
         end if;
         BI_Norm (R);
         return R;
      end BI_Shr;
      function BI_Mod_Exp (Base, Exp, M : BI) return BI is
         Res : BI := BI_One;
         T   : BI := Base;
         E   : BI := Exp;
      begin
         if BI_Is_Zero (M) then
            raise Program_Error;
         end if;
         --  square-and-multiply, LSB-first
         while not BI_Is_Zero (E) loop
            if (E.L (1) and 1) = 1 then
               Res := BI_Mod_Mul (Res, T, M);
            end if;
            T := BI_Mod_Mul (T, T, M);
            E := BI_Shr (E, 1);
         end loop;
         return Res;
      end BI_Mod_Exp;


      --  ==================== P-256 (secp256r1) ====================

      function Hex_B (S : String) return Byte_Array is
         R : Byte_Array (1 .. S'Length / 2);
         V : Natural;
         C : Character;
      begin
         for I in 1 .. R'Length loop
            V := 0;
            for J in 0 .. 1 loop
               C := S (S'First + (I - 1) * 2 + J);
               if C in '0' .. '9' then
                  V := V * 16 + Character'Pos (C) - 48;
               elsif C in 'A' .. 'F' then
                  V := V * 16 + Character'Pos (C) - 55;
               else
                  V := V * 16 + Character'Pos (C) - 87;
               end if;
            end loop;
            R (SEO (I)) := Byte (V);
         end loop;
         return R;
      end Hex_B;

      procedure BI_To_BE (A : BI; B : out Byte_Array) is
         LE : Byte_Array (1 .. B'Length);
      begin
         BI_To_LE (A, LE);
         for I in 1 .. B'Length loop
            B (SEO (I)) := LE (SEO (B'Length - I + 1));
         end loop;
      end BI_To_BE;

      P256_P : constant BI :=
        BI_From_BE (Hex_B
          ("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));
      P256_N : constant BI :=
        BI_From_BE (Hex_B
          ("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));
      P256_N2 : constant BI := BI_Sub (P256_N, BI_From_BE (Hex_B
        ("0000000000000000000000000000000000000000000000000000000000000002")));
      P256_P2 : constant BI := BI_Sub (P256_P, BI_From_BE (Hex_B
        ("0000000000000000000000000000000000000000000000000000000000000002")));
      P256_GX : constant BI :=
        BI_From_BE (Hex_B
          ("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"));
      P256_GY : constant BI :=
        BI_From_BE (Hex_B
          ("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));

      type PPoint is record
         X, Y, Z : BI;
      end record;

      function PM (A, B : BI) return BI is
      begin
         return BI_Mod (BI_Add (A, B), P256_P);
      end PM;

      function PS (A, B : BI) return BI is
         S : BI;
      begin
         if BI_Cmp (A, B) >= 0 then
            S := BI_Sub (A, B);
         else
            S := BI_Sub (BI_Add (A, P256_P), B);
         end if;
         return S;
      end PS;

      function PMul (A, B : BI) return BI is
      begin
         return BI_Mod_Mul (A, B, P256_P);
      end PMul;

      function PDbl2 (A : BI) return BI is
      begin
         return PM (A, A);
      end PDbl2;

      function P_Double (P : PPoint) return PPoint is
         A, B, C, D, E, F, T, Z2, Z4 : BI;
         X3, Y3, Z3 : BI;
      begin
         if BI_Is_Zero (P.Z) then
            return (X => BI_Zero, Y => BI_One, Z => BI_Zero);
         end if;
         A := PMul (P.X, P.X);
         B := PMul (P.Y, P.Y);
         C := PMul (B, B);
         T := PMul (PM (P.X, B), PM (P.X, B));
         --  D = 2*((X1+B)^2 - A - C)
         D := PM (PS (PS (T, A), C), PS (PS (T, A), C));
         --  M = 3*X1^2 + a*Z1^4 with a = p-3, so M = 3*X1^2 - 3*Z1^4
         Z2 := PMul (P.Z, P.Z);
         Z4 := PMul (Z2, Z2);
         E := PS (PM (PM (A, A), A), PM (PM (Z4, Z4), Z4));
         F := PMul (E, E);
         X3 := PS (F, PDbl2 (D));
         Y3 := PS (PMul (E, PS (D, X3)), PDbl2 (PDbl2 (PDbl2 (C))));
         Z3 := PMul (PDbl2 (P.Y), P.Z);
         return (X => X3, Y => Y3, Z => Z3);
      end P_Double;

      --  mixed addition: Q is affine (Z = 1)
      function P_Add (P : PPoint; QX, QY : BI) return PPoint is
         Z1Z1, U2, S2, H, HH, I, J, R, V, T : BI;
         X3, Y3, Z3 : BI;
      begin
         if BI_Is_Zero (P.Z) then
            return (X => QX, Y => QY, Z => BI_One);
         end if;
         Z1Z1 := PMul (P.Z, P.Z);
         U2 := PMul (QX, Z1Z1);
         S2 := PMul (PMul (QY, P.Z), Z1Z1);
         H := PS (U2, P.X);
         if BI_Is_Zero (H) then
            --  P == Q or P == -Q
            if BI_Is_Zero (PS (S2, P.Y)) then
               return P_Double (P);
            else
               return (X => BI_One, Y => BI_One, Z => BI_Zero);
            end if;
         end if;
         HH := PMul (H, H);
         I := PM (PDbl2 (HH), PDbl2 (HH));
         J := PMul (H, I);
         R := PDbl2 (PS (S2, P.Y));
         V := PMul (P.X, I);
         X3 := PS (PS (PMul (R, R), J), PDbl2 (V));
         Y3 := PS (PMul (R, PS (V, X3)), PDbl2 (PMul (P.Y, J)));
         T := PMul (PM (P.Z, H), PM (P.Z, H));
         Z3 := PS (PS (T, Z1Z1), HH);
         return (X => X3, Y => Y3, Z => Z3);
      end P_Add;

      --  Convert a Jacobian point (X, Y, Z) to affine (X/Z^2, Y/Z^3).
      function P_To_Affine (P : PPoint) return PPoint is
         ZInv, ZInv2, ZInv3 : BI;
      begin
         if BI_Is_Zero (P.Z) then
            return (X => BI_Zero, Y => BI_Zero, Z => BI_Zero);
         end if;
         ZInv := BI_Mod_Exp (P.Z, P256_P2, P256_P);
         ZInv2 := PMul (ZInv, ZInv);
         ZInv3 := PMul (ZInv2, ZInv);
         return (X => PMul (P.X, ZInv2), Y => PMul (P.Y, ZInv3), Z => BI_One);
      end P_To_Affine;

      --  R = k * G (G affine, k < n)
      function P_Scalar_Mult_G (K : BI) return PPoint is
         R : PPoint := (X => BI_Zero, Y => BI_One, Z => BI_Zero);
         Bits : constant Natural :=
           (if K.Len = 0 then 0
            else K.Len * 64 - BI_Leading_Zeros (K.L (K.Len)));
      begin
         for I in reverse 0 .. Bits - 1 loop
            R := P_Double (R);
            if (Shift_Right (K.L (I / 64 + 1), I mod 64) and 1) = 1 then
               R := P_Add (R, P256_GX, P256_GY);
            end if;
         end loop;
         return R;
      end P_Scalar_Mult_G;

      --  R = k * P (P affine)
      function P_Scalar_Mult (K : BI; PX, PY : BI) return PPoint is
         R : PPoint := (X => BI_Zero, Y => BI_One, Z => BI_Zero);
         Bits : constant Natural :=
           (if K.Len = 0 then 0
            else K.Len * 64 - BI_Leading_Zeros (K.L (K.Len)));
      begin
         for I in reverse 0 .. Bits - 1 loop
            R := P_Double (R);
            if (Shift_Right (K.L (I / 64 + 1), I mod 64) and 1) = 1 then
               R := P_Add (R, PX, PY);
            end if;
         end loop;
         return R;
      end P_Scalar_Mult;

      function BI_To_BE32 (A : BI) return Byte_Array is
         B : Byte_Array (1 .. 32);
         LE : Byte_Array (1 .. 32);
      begin
         BI_To_LE (A, LE);
         for I in 1 .. 32 loop
            B (SEO (I)) := LE (SEO (33 - I));
         end loop;
         return B;
      end BI_To_BE32;

      procedure P256_Keygen (Sk : out P256_Priv; Pk : out P256_Pub) is
         D : Byte_Array (1 .. 32);
         K : BI;
         Q : PPoint;
      begin
         loop
            Random_Bytes (D);
            K := BI_Mod (BI_From_BE (D), P256_N);
            exit when not BI_Is_Zero (K);
         end loop;
         Q := P_Scalar_Mult_G (K);
         Q := P_To_Affine (Q);
         Sk := D;
         Pk := (X => BI_To_BE32 (Q.X), Y => BI_To_BE32 (Q.Y));
      end P256_Keygen;

      function P256_ECDH (Sk : P256_Priv; Pk : P256_Pub) return Byte_Array is
         K : constant BI := BI_Mod (BI_From_BE (Sk), P256_N);
         Q : constant PPoint :=
           P_Scalar_Mult (K, BI_From_BE (Pk.X), BI_From_BE (Pk.Y));
      begin
         if BI_Is_Zero (Q.Z) then
            return Byte_Array'(1 .. 32 => 0);
         end if;
         return BI_To_BE32 (P_To_Affine (Q).X);
      end P256_ECDH;

      --  DER encode of an INTEGER (positive, < 2^256)
      function DER_Int (V : BI) return Byte_Array is
         T : constant Byte_Array (1 .. 32) := BI_To_BE32 (V);
         L : Natural := 1;
      begin
         while L <= 32 and then T (SEO (L)) = 0 loop
            L := L + 1;
         end loop;
         if L > 32 then
            return (2, 1, 0);
         end if;
         if T (SEO (L)) >= 16#80# then
            declare
               R : Byte_Array (1 .. 35);
            begin
               R (1) := 2;
               R (2) := Byte (33 - L + 1);
               R (3) := 0;
               R (SEO (4) .. SEO (4 + 32 - L)) := T (SEO (L) .. 32);
               return R (1 .. SEO (3 + 32 - L + 1));
            end;
         else
            declare
               R : Byte_Array (1 .. 35);
            begin
               R (1) := 2;
               R (2) := Byte (33 - L);
               R (SEO (3) .. SEO (3 + 32 - L)) := T (SEO (L) .. 32);
               return R (1 .. SEO (2 + 32 - L + 1));
            end;
         end if;
      end DER_Int;

      --  RFC 6979 deterministic ECDSA (SHA-256)
      function P256_ECDSA_Sign
        (Sk : P256_Priv; Msg : Byte_Array) return Byte_Array
      is
         H1  : constant Digest_256 := SHA256 (Msg);
         Z   : constant BI := BI_Mod (BI_From_BE (H1), P256_N);
         X   : constant BI := BI_Mod (BI_From_BE (Sk), P256_N);
         V   : Byte_Array (1 .. 32) := [others => 16#01#];
         Kb  : Byte_Array (1 .. 32) := [others => 0];
         Tmp : Byte_Array (1 .. 97);
         K   : BI;
         Rpt : PPoint;
         R, S, KInv, Sig : BI;
      begin
         --  K = HMAC(K, V || 0x00 || int2octets(x) || bits2octets(h1))
         Tmp (1 .. 32) := V;
         Tmp (33) := 0;
         Tmp (34 .. 65) := Sk;
         Tmp (66 .. 97) := BI_To_BE32 (Z);
         Kb := HMAC_SHA256 (Kb, Tmp (1 .. 97));
         V := HMAC_SHA256 (Kb, V);
         Tmp (1 .. 32) := V;
         Tmp (33) := 1;
         Tmp (34 .. 65) := Sk;
         Tmp (66 .. 97) := BI_To_BE32 (Z);
         Kb := HMAC_SHA256 (Kb, Tmp (1 .. 97));
         V := HMAC_SHA256 (Kb, V);
         loop
            V := HMAC_SHA256 (Kb, V);
            K := BI_Mod (BI_From_BE (V), P256_N);
            if not BI_Is_Zero (K) then
               Rpt := P_Scalar_Mult_G (K);
               R := BI_Mod (P_To_Affine (Rpt).X, P256_N);
               if not BI_Is_Zero (R) then
                  --  s = k^-1 (z + r*x) mod n
                  Sig := BI_Mod (BI_Add (Z, BI_Mod_Mul (R, X, P256_N)),
                                 P256_N);
                  KInv := BI_Mod_Exp (K, P256_N2, P256_N);
                  S := BI_Mod_Mul (KInv, Sig, P256_N);
                  if not BI_Is_Zero (S) then
                     declare
                        Rr : constant Byte_Array := DER_Int (R);
                        Ss : constant Byte_Array := DER_Int (S);
                        Res : Byte_Array (1 .. 80);
                     begin
                        Res (1) := 16#30#;
                        Res (2) := Byte (Rr'Length + Ss'Length);
                        Res (3 .. 2 + Rr'Length) := Rr;
                        Res (3 + Rr'Length .. 2 + Rr'Length + Ss'Length) := Ss;
                        return Res (1 .. Rr'Length + Ss'Length + 2);
                     end;
                  end if;
               end if;
            end if;
            --  retry: K = HMAC(K, V || 0x00); V = HMAC(K, V)
            Tmp (1 .. 32) := V;
            Tmp (33) := 0;
            Kb := HMAC_SHA256 (Kb, Tmp (1 .. 33));
            V := HMAC_SHA256 (Kb, V);
         end loop;
      end P256_ECDSA_Sign;

      --  Jacobian + Jacobian addition (for ECDSA verify)
      function P_Add_JJ (P, Q : PPoint) return PPoint is
         Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, R, V, T : BI;
         X3, Y3, Z3 : BI;
      begin
         if BI_Is_Zero (P.Z) then
            return Q;
         end if;
         if BI_Is_Zero (Q.Z) then
            return P;
         end if;
         Z1Z1 := PMul (P.Z, P.Z);
         Z2Z2 := PMul (Q.Z, Q.Z);
         U1 := PMul (P.X, Z2Z2);
         U2 := PMul (Q.X, Z1Z1);
         S1 := PMul (PMul (P.Y, Q.Z), Z2Z2);
         S2 := PMul (PMul (Q.Y, P.Z), Z1Z1);
         H := PS (U2, U1);
         if BI_Is_Zero (H) then
            if BI_Is_Zero (PS (S2, S1)) then
               return P_Double (P);
            else
               return (X => BI_One, Y => BI_One, Z => BI_Zero);
            end if;
         end if;
         I := PM (PDbl2 (PMul (H, H)), PDbl2 (PMul (H, H)));
         J := PMul (H, I);
         R := PDbl2 (PS (S2, S1));
         V := PMul (U1, I);
         X3 := PS (PS (PMul (R, R), J), PDbl2 (V));
         Y3 := PS (PMul (R, PS (V, X3)), PDbl2 (PMul (S1, J)));
         T := PMul (PM (P.Z, Q.Z), PM (P.Z, Q.Z));
         Z3 := PMul (PS (PS (T, Z1Z1), Z2Z2), H);
         return (X => X3, Y => Y3, Z => Z3);
      end P_Add_JJ;

      P256_B : constant BI :=
        BI_From_BE (Hex_B
          ("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"));

      function P_On_Curve (PX, PY : BI) return Boolean is
         L  : constant BI := PMul (PY, PY);
         X3 : constant BI := PMul (PMul (PX, PX), PX);
         --  y^2 = x^3 - 3x + b  (a = p - 3)
         R  : constant BI := PM (PS (X3, PM (PDbl2 (PX), PX)), P256_B);
      begin
         return BI_Cmp (L, R) = 0;
      end P_On_Curve;

      function P256_ECDSA_Verify
        (Pk : P256_Pub; Msg : Byte_Array; Sig : Byte_Array) return Boolean
      is
         H1 : constant Digest_256 := SHA256 (Msg);
         Z  : constant BI := BI_Mod (BI_From_BE (H1), P256_N);
         PX : constant BI := BI_From_BE (Pk.X);
         PY : constant BI := BI_From_BE (Pk.Y);
         R, S : BI;
         W, U1, U2 : BI;
         Pt : PPoint;
      begin
         if Sig'Length < 8 or Sig (1) /= 16#30# then
            return False;
         end if;
         --  parse SEQUENCE { INTEGER r, INTEGER s }
         if Sig (3) /= 2 then
            return False;
         end if;
         declare
            R_Len : constant Natural := Natural (Sig (4));
            S_Off : Natural;
            S_Len : Natural;
         begin
            if R_Len = 0 or R_Len > 33 or 5 + R_Len > Sig'Length then
               return False;
            end if;
            R := BI_From_BE (Sig (5 .. SEO (4 + R_Len)));
            S_Off := 5 + R_Len;
            if S_Off + 1 > Sig'Length or Sig (SEO (S_Off)) /= 2 then
               return False;
            end if;
            S_Len := Natural (Sig (SEO (S_Off + 1)));
            if S_Len = 0 or S_Len > 33
              or S_Off + 1 + S_Len > Sig'Length
            then
               return False;
            end if;
            S := BI_From_BE (Sig (SEO (S_Off + 2) .. SEO (S_Off + 1 + S_Len)));
         end;
         if BI_Is_Zero (R) or BI_Is_Zero (S)
           or BI_Cmp (R, P256_N) >= 0 or BI_Cmp (S, P256_N) >= 0
         then
            return False;
         end if;
         if not P_On_Curve (PX, PY) then
            return False;
         end if;
         W := BI_Mod_Exp (S, P256_N2, P256_N);
         U1 := BI_Mod_Mul (Z, W, P256_N);
         U2 := BI_Mod_Mul (R, W, P256_N);
         Pt := P_Add_JJ (P_Scalar_Mult_G (U1),
                         P_Scalar_Mult (U2, PX, PY));
         if BI_Is_Zero (Pt.Z) then
            return False;
         end if;
         Pt := P_To_Affine (Pt);
         return BI_Cmp (BI_Mod (Pt.X, P256_N), R) = 0;
      end P256_ECDSA_Verify;

      --  ==================== RSA ====================
      --  PKCS#1 v1.5 and PSS signatures, CRT private operation.

      function BI_From_Key (B : Byte_Array; L : Natural) return BI is
      begin
         if L = 0 then
            return BI_Zero;
         end if;
         return BI_From_BE (B (1 .. SEO (L)));
      end BI_From_Key;

      procedure RSA_CRT (Key : RSA_Priv; M : BI; S : out BI) is
         P : constant BI := BI_From_Key (Key.P, Key.P_Len);
         Q : constant BI := BI_From_Key (Key.Q, Key.Q_Len);
         N : constant BI := BI_From_Key (Key.N, Key.N_Len);
         M1 : BI := BI_Mod_Exp (M, BI_From_Key (Key.DP, Key.DP_Len), P);
         M2 : BI := BI_Mod_Exp (M, BI_From_Key (Key.DQ, Key.DQ_Len), Q);
         H : BI;
      begin
         --  h = qInv * (m1 - m2) mod p  ((m1 - m2) may be negative)
         if BI_Cmp (M1, M2) >= 0 then
            H := BI_Mod_Mul (BI_From_Key (Key.QI, Key.QI_Len),
                             BI_Sub (M1, M2), P);
         else
            H := BI_Mod_Mul (BI_From_Key (Key.QI, Key.QI_Len),
                             BI_Sub (BI_Add (M1, P), M2), P);
         end if;
         S := BI_Mod (BI_Add (M2, BI_Mod_Mul (H, Q, N)), N);
      end RSA_CRT;

      procedure RSA_Public_Op
        (N, E : BI; M : BI; S : out BI)
      is
      begin
         S := BI_Mod_Exp (M, E, N);
      end RSA_Public_Op;

      --  EMSA-PKCS1-v1_5 encode (SHA-256): 0x00 0x01 FF..FF 0x00 || DigestInfo || H
      procedure EMSA_PKCS1
        (K : Natural; Hash : Digest_256; EM : out Byte_Array)
      is
         DI : constant Byte_Array (1 .. 19) :=
           (16#30#, 16#31#, 16#30#, 16#0D#, 16#06#, 16#09#, 16#60#,
            16#86#, 16#48#, 16#01#, 16#65#, 16#03#, 16#04#, 16#02#,
            16#01#, 16#05#, 16#00#, 16#04#, 16#20#);
         N : constant Natural := K - 3 - DI'Length - 32;
      begin
         EM (1) := 0;
         EM (2) := 1;
         for I in 3 .. 2 + N loop
            EM (SEO (I)) := 16#FF#;
         end loop;
         EM (SEO (N + 3)) := 0;
         EM (SEO (N + 4) .. SEO (N + 3 + DI'Length)) := DI;
         EM (SEO (N + 4 + DI'Length) .. SEO (K)) := Hash;
      end EMSA_PKCS1;

      function RSA_Sign_PKCS1 (Key : RSA_Priv; Hash : Digest_256)
                               return Byte_Array
      is
         EM : Byte_Array (1 .. SEO (Key.N_Len));
         M  : BI;
         S  : BI;
         Out_B : Byte_Array (1 .. SEO (Key.N_Len));
      begin
         if not Key.Valid or Key.N_Len = 0 then
            return Byte_Array'(1 .. 32 => 0);
         end if;
         EMSA_PKCS1 (Key.N_Len, Hash, EM);
         M := BI_From_BE (EM);
         RSA_CRT (Key, M, S);
         BI_To_BE (S, Out_B);
         return Out_B;
      end RSA_Sign_PKCS1;

      function RSA_Verify_PKCS1
        (N, E : Byte_Array; Sig : Byte_Array; Hash : Digest_256)
         return Boolean
      is
         K : constant Natural := N'Length;
         EM : Byte_Array (1 .. SEO (K));
         EM2 : Byte_Array (1 .. SEO (K));
         S : BI;
         M : BI;
      begin
         if Sig'Length /= K or K < 51 + 11 then
            return False;
         end if;
         S := BI_From_BE (Sig);
         if BI_Cmp (S, BI_From_BE (N)) >= 0 then
            return False;
         end if;
         RSA_Public_Op (BI_From_BE (N), BI_From_BE (E), S, M);
         BI_To_BE (M, EM);
         EMSA_PKCS1 (K, Hash, EM2);
         for I in 1 .. K loop
            if EM (SEO (I)) /= EM2 (SEO (I)) then
               return False;
            end if;
         end loop;
         return True;
      end RSA_Verify_PKCS1;

      --  MGF1 (SHA-256)
      function MGF1 (Seed : Byte_Array; Len : Natural) return Byte_Array is
         Res : Byte_Array (1 .. SEO (Len));
         Cnt : Unsigned_32 := 0;
         Hsh : Digest_256;
         Tmp : Byte_Array (1 .. 36);
         P : Natural := 1;
      begin
         while P <= Len loop
            Tmp (1 .. Seed'Length) := Seed;
            Set_BE32 (Tmp, SEO (Seed'Length + 1), Cnt);
            Hsh := SHA256 (Tmp (1 .. SEO (Seed'Length + 4)));
            if P + 32 - 1 <= Len then
               Res (SEO (P) .. SEO (P + 31)) := Hsh;
               P := P + 32;
            else
               Res (SEO (P) .. SEO (Len)) := Hsh (1 .. SEO (Len - P + 1));
               P := Len + 1;
            end if;
            Cnt := Cnt + 1;
         end loop;
         return Res;
      end MGF1;

      --  EMSA-PSS encode (SHA-256, salt length = 32)
      procedure EMSA_PSS
        (EmLen : Natural; Hash : Digest_256; Salt : Byte_Array;
         EM : out Byte_Array)
      is
         M1 : Byte_Array (1 .. 72);
         H  : Digest_256;
         DB : Byte_Array (1 .. SEO (EmLen - 32 - 1));
         DbMask : Byte_Array (1 .. SEO (EmLen - 32 - 1));
         MaskedDB : Byte_Array (1 .. SEO (EmLen - 32 - 1));
         PS : Natural := EmLen - 32 - 32 - 2;
         Tmp : Byte_Array (1 .. 36);
      begin
         M1 := [others => 0];
         M1 (1 .. 8) := [others => 0];
         M1 (9 .. 40) := Hash;
         M1 (41 .. 72) := Salt;
         H := SHA256 (M1);
         DB := [others => 0];
         for I in 1 .. PS loop
            DB (SEO (I)) := 0;
         end loop;
         DB (SEO (PS + 1)) := 1;
         DB (SEO (PS + 2) .. SEO (PS + 1 + 32)) := Salt;
         DbMask := MGF1 (H, DB'Length);
         for I in 1 .. DB'Length loop
            MaskedDB (SEO (I)) := DB (SEO (I)) xor DbMask (SEO (I));
         end loop;
         --  step 11: clear the leftmost 8*EmLen - emBits bits of the first
         --  octet. For a 2048-bit modulus emBits = modBits - 1 = 2047, so one
         --  bit (the top bit) is cleared, guaranteeing EM < n.
         MaskedDB (1) := MaskedDB (1) and 16#7F#;
         EM (1 .. SEO (EmLen - 33)) := MaskedDB;
         EM (SEO (EmLen - 32) .. SEO (EmLen - 1)) := H;
         EM (SEO (EmLen)) := 16#BC#;
      end EMSA_PSS;

      function RSA_Sign_PSS (Key : RSA_Priv; Hash : Digest_256)
                             return Byte_Array
      is
         EM : Byte_Array (1 .. SEO (Key.N_Len));
         Salt : Byte_Array (1 .. 32);
         M  : BI;
         S  : BI;
         Out_B : Byte_Array (1 .. SEO (Key.N_Len));
      begin
         if not Key.Valid or Key.N_Len = 0 then
            return Byte_Array'(1 .. 32 => 0);
         end if;
         Random_Bytes (Salt);
         EMSA_PSS (Key.N_Len, Hash, Salt, EM);
         M := BI_From_BE (EM);
         RSA_CRT (Key, M, S);
         BI_To_BE (S, Out_B);
         return Out_B;
      end RSA_Sign_PSS;

      function RSA_Verify_PSS
        (N, E : Byte_Array; Sig : Byte_Array; Hash : Digest_256)
         return Boolean
      is
         K : constant Natural := N'Length;
         EM : Byte_Array (1 .. SEO (K));
         S : BI;
         M : BI;
         DbMask : Byte_Array (1 .. SEO (K - 32 - 1));
         DB : Byte_Array (1 .. SEO (K - 32 - 1));
         H2 : Digest_256;
         M1 : Byte_Array (1 .. 72);
         OK : Boolean := False;
         PS : Natural;
      begin
         if Sig'Length /= K or K < 32 + 32 + 2 then
            return False;
         end if;
         S := BI_From_BE (Sig);
         if BI_Cmp (S, BI_From_BE (N)) >= 0 then
            return False;
         end if;
         RSA_Public_Op (BI_From_BE (N), BI_From_BE (E), S, M);
         BI_To_BE (M, EM);
         if EM (SEO (K)) /= 16#BC# then
            return False;
         end if;
         DbMask := MGF1 (EM (SEO (K - 32) .. SEO (K - 1)), K - 33);
         for I in 1 .. K - 33 loop
            DB (SEO (I)) := EM (SEO (I)) xor DbMask (SEO (I));
         end loop;
         --  clear the leftmost 8*K - emBits bits (the top bit for a 2048-bit
         --  modulus, emBits = 2047) before checking the PS zero padding.
         DB (1) := DB (1) and 16#7F#;
         --  DB = PS (zeros) || 0x01 || salt. With a 32-byte salt the 0x01
         --  sits at position emLen - sLen - hLen - 1 = K - 65.
         PS := 1;
         while PS < K - 65 and then DB (SEO (PS)) = 0 loop
            PS := PS + 1;
         end loop;
         if PS = K - 65 and then DB (SEO (PS)) = 1 then
            M1 := [others => 0];
            M1 (9 .. 40) := Hash;
            M1 (41 .. 72) := DB (SEO (PS + 1) .. SEO (PS + 32));
            H2 := SHA256 (M1);
            OK := True;
            for I in 1 .. 32 loop
               if H2 (SEO (I)) /= EM (SEO (K - 32 - 1 + I)) then
                  OK := False;
               end if;
            end loop;
         end if;
         return OK;
      end RSA_Verify_PSS;

      procedure X25519_Keygen (Sk : out X25519_Key; Pk : out X25519_Key) is
      begin
         Random_Bytes (Sk);
         Sk (1) := Byte (Unsigned_32 (Sk (1)) and 16#F8#);
         Sk (32) := Byte ((Unsigned_32 (Sk (32)) or 16#40#) and 16#7F#);
         declare
            Base : Limbs8 := [others => 0];
            Out_L : Limbs8;
         begin
            Base (1) := 9;
            X25519_Ladder (Out_L, Sk, Base);
            Pk := Out_L;
         end;
      end X25519_Keygen;

      function X25519 (Sk, Pk : X25519_Key) return X25519_Key is
         Out_L : Limbs8;
         U : Limbs8 := Pk;
      begin
         X25519_Ladder (Out_L, Sk, U);
         return Out_L;
      end X25519;

      --  ==================== ASN.1 DER / PEM ====================

      procedure DER_TLV
        (B : Byte_Array; Pos : Positive;
         Tag : out Byte; Len : out Natural; Data_At : out Natural;
         OK : out Boolean)
      is
         L : Natural;
         LB : Byte;
      begin
         OK := False;
         if SEO (Pos) > B'Last then
            return;
         end if;
         Tag := B (SEO (Pos));
         if SEO (Pos + 1) > B'Last then
            return;
         end if;
         LB := B (SEO (Pos + 1));
         if LB < 16#80# then
            L := Natural (LB);
            Data_At := Pos + 2;
         elsif LB = 16#81# then
            if SEO (Pos + 2) > B'Last then
               return;
            end if;
            L := Natural (B (SEO (Pos + 2)));
            Data_At := Pos + 3;
         elsif LB = 16#82# then
            if SEO (Pos + 3) > B'Last then
               return;
            end if;
            L := Natural (B (SEO (Pos + 2))) * 256 + Natural (B (SEO (Pos + 3)));
            Data_At := Pos + 4;
         else
            return;   --  length > 64 KiB unsupported
         end if;
         if SEO (Data_At + L - 1) > B'Last then
            return;
         end if;
         Len := L;
         OK := True;
      end DER_TLV;

      function OID_Match (B : Byte_Array; Pos : Positive;
                          OID : Byte_Array) return Boolean is
         Tag : Byte;
         Len : Natural;
         Data_At : Natural;
         OK : Boolean;
      begin
         DER_TLV (B, Pos, Tag, Len, Data_At, OK);
         return OK and then Tag = 16#06# and then Len = OID'Length
           and then B (SEO (Data_At) .. SEO (Data_At + Len - 1)) = OID;
      end OID_Match;

      OID_RSA : constant Byte_Array (1 .. 9) :=
        (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#01#);
      OID_EC  : constant Byte_Array (1 .. 7) :=
        (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#02#, 16#01#);
      OID_P256 : constant Byte_Array (1 .. 8) :=
        (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#);

      --  read the INTEGER at Pos, return its positive value as BI
      function DER_INT_BI (B : Byte_Array; Pos : Positive;
                           Val : out BI) return Boolean is
         Tag : Byte;
         Len : Natural;
         Data_At : Natural;
         OK : Boolean;
      begin
         DER_TLV (B, Pos, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#02# or Len = 0 then
            return False;
         end if;
         --  skip a leading 0x00 (positive encoding)
         if B (SEO (Data_At)) = 0 then
            Data_At := Data_At + 1;
            Len := Len - 1;
            if Len = 0 then
               Val := BI_Zero;
               return True;
            end if;
         end if;
         Val := BI_From_BE (B (SEO (Data_At) .. SEO (Data_At + Len - 1)));
         return True;
      end DER_INT_BI;

      --  read the INTEGER at Pos, copy its bytes (MSB-first, no 0x00)
      function DER_INT_Bytes
        (B : Byte_Array; Pos : Positive;
         Out_B : out Byte_Array; Out_Len : out Natural) return Boolean
      is
         Tag : Byte;
         Len : Natural;
         Data_At : Natural;
         OK : Boolean;
      begin
         DER_TLV (B, Pos, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#02# or Len = 0 then
            return False;
         end if;
         if B (SEO (Data_At)) = 0 then
            Data_At := Data_At + 1;
            Len := Len - 1;
         end if;
         if Len > Out_B'Length then
            return False;
         end if;
         Out_B (1 .. SEO (Len)) := B (SEO (Data_At) .. SEO (Data_At + Len - 1));
         Out_Len := Len;
         return True;
      end DER_INT_Bytes;

      --  PKCS#1: SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }
      function Parse_PKCS1 (Der : Byte_Array; Rsa : out RSA_Priv)
                            return Boolean
      is
         Tag : Byte;
         Len : Natural;
         Data_At : Natural;
         OK : Boolean;
         V : BI;
         P : Natural;
      begin
         DER_TLV (Der, 1, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         P := Data_At;
         --  version
         if not DER_INT_BI (Der, P, V) then
            return False;
         end if;
         DER_TLV (Der, P, Tag, Len, Data_At, OK);
         P := Data_At + Len;
         --  n
         if not DER_INT_Bytes (Der, P, Rsa.N, Rsa.N_Len) then
            return False;
         end if;
         DER_TLV (Der, P, Tag, Len, Data_At, OK);
         P := Data_At + Len;
         --  e
         if not DER_INT_Bytes (Der, P, Rsa.E, Rsa.E_Len) then
            return False;
         end if;
         DER_TLV (Der, P, Tag, Len, Data_At, OK);
         P := Data_At + Len;
         --  d
         if not DER_INT_Bytes (Der, P, Rsa.D, Rsa.D_Len) then
            return False;
         end if;
         DER_TLV (Der, P, Tag, Len, Data_At, OK);
         P := Data_At + Len;
         --  p
         if not DER_INT_Bytes (Der, P, Rsa.P, Rsa.P_Len) then
            return False;
         end if;
         DER_TLV (Der, P, Tag, Len, Data_At, OK);
         P := Data_At + Len;
         --  q
         if not DER_INT_Bytes (Der, P, Rsa.Q, Rsa.Q_Len) then
            return False;
         end if;
         DER_TLV (Der, P, Tag, Len, Data_At, OK);
         P := Data_At + Len;
         --  dP
         if not DER_INT_Bytes (Der, P, Rsa.DP, Rsa.DP_Len) then
            return False;
         end if;
         DER_TLV (Der, P, Tag, Len, Data_At, OK);
         P := Data_At + Len;
         --  dQ
         if not DER_INT_Bytes (Der, P, Rsa.DQ, Rsa.DQ_Len) then
            return False;
         end if;
         DER_TLV (Der, P, Tag, Len, Data_At, OK);
         P := Data_At + Len;
         --  qInv
         if not DER_INT_Bytes (Der, P, Rsa.QI, Rsa.QI_Len) then
            return False;
         end if;
         Rsa.Valid := Rsa.N_Len > 0 and Rsa.D_Len > 0
           and Rsa.P_Len > 0 and Rsa.Q_Len > 0;
         return Rsa.Valid;
      end Parse_PKCS1;

      --  SEC1 ECPrivateKey: SEQUENCE { version, privateKey OCTET STRING, ... }
      function Parse_SEC1 (Der : Byte_Array; P256 : out P256_Priv)
                           return Boolean
      is
         Tag : Byte;
         Len : Natural;
         Data_At : Natural;
         OK : Boolean;
      begin
         DER_TLV (Der, 1, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         --  version INTEGER
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#02# then
            return False;
         end if;
         Data_At := Data_At + Len;
         --  privateKey OCTET STRING
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#04# or Len /= 32 then
            return False;
         end if;
         P256 := Der (SEO (Data_At) .. SEO (Data_At + 31));
         return True;
      end Parse_SEC1;

      --  PKCS#8: SEQUENCE { version, alg SEQUENCE { OID, params }, OCTET STRING }
      function Parse_PKCS8
        (Der : Byte_Array; Rsa : out RSA_Priv; P256 : out P256_Priv;
         Is_RSA : out Boolean) return Boolean
      is
         Tag : Byte;
         Len : Natural;
         Data_At : Natural;
         OK : Boolean;
         Alg_At : Natural;
         OID_At : Natural;
         Inner_At : Natural;
         Inner_Len : Natural;
      begin
         Is_RSA := False;
         DER_TLV (Der, 1, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         --  version
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#02# then
            return False;
         end if;
         Alg_At := Data_At + Len;
         --  AlgorithmIdentifier
         DER_TLV (Der, Alg_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         OID_At := Data_At;
         Inner_At := Data_At + Len;
         --  OCTET STRING with the wrapped key
         DER_TLV (Der, Inner_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#04# then
            return False;
         end if;
         if OID_Match (Der, OID_At, OID_RSA) then
            Is_RSA := True;
            declare
               W : Byte_Array (1 .. 4096) := [others => 0];
            begin
               W (1 .. SEO (Len)) := Der (SEO (Data_At) .. SEO (Data_At + Len - 1));
               return Parse_PKCS1 (W (1 .. SEO (Len)), Rsa);
            end;
         elsif OID_Match (Der, OID_At, OID_EC) then
            declare
               W : Byte_Array (1 .. 4096) := [others => 0];
            begin
               W (1 .. SEO (Len)) := Der (SEO (Data_At) .. SEO (Data_At + Len - 1));
               return Parse_SEC1 (W (1 .. SEO (Len)), P256);
            end;
         else
            return False;
         end if;
      end Parse_PKCS8;

      function B64_Val (C : Character) return Integer is
      begin
         if C in 'A' .. 'Z' then
            return Character'Pos (C) - 65;
         elsif C in 'a' .. 'z' then
            return Character'Pos (C) - 71;
         elsif C in '0' .. '9' then
            return Character'Pos (C) + 4;
         elsif C = '+' then
            return 62;
         elsif C = '/' then
            return 63;
         else
            return -1;
         end if;
      end B64_Val;

      function B64_Decode
        (S : String; Out_B : out Byte_Array; Out_Len : out Natural)
         return Boolean
      is
         Acc : Natural := 0;
         Bits : Natural := 0;
         N : Natural := 0;
         V : Integer;
      begin
         Out_Len := 0;
         for I in S'Range loop
            if S (I) = '=' then
               exit;
            end if;
            V := B64_Val (S (I));
            if V < 0 then
               --  tolerate whitespace/CR/LF
               if S (I) in ' ' | ASCII.HT | ASCII.CR | ASCII.LF then
                  null;
               else
                  return False;
               end if;
            else
               Acc := Acc * 64 + V;
               Bits := Bits + 6;
               if Bits >= 8 then
                  Bits := Bits - 8;
                  N := N + 1;
                  if N > Out_B'Length then
                     return False;
                  end if;
                  Out_B (SEO (N)) := Byte (Shift_Right (Unsigned_32 (Acc), Bits)
                                     and 16#FF#);
                  --  keep only the remaining low bits for the next byte
                  Acc := Acc mod (2 ** Bits);
               end if;
            end if;
         end loop;
         Out_Len := N;
         return True;
      end B64_Decode;

      procedure Find_PEM_Body
        (Pem : String; Marker : String;
         B_First : out Natural; B_Last : out Natural; Found : out Boolean)
      is
         B_At : Natural := 0;
         E_At : Natural := 0;
         Start : Natural;
      begin
         Found := False;
         B_First := 0;
         B_Last := 0;
         for I in Pem'First .. Pem'Last - Marker'Length + 1 loop
            if Pem (I .. I + Marker'Length - 1) = Marker then
               B_At := I;
               exit;
            end if;
         end loop;
         if B_At = 0 then
            return;
         end if;
         Start := B_At + Marker'Length;
         for I in Start .. Pem'Last - 8 loop
            if Pem (I .. I + 8) = "-----END " then
               E_At := I;
               exit;
            end if;
         end loop;
         if E_At = 0 then
            return;
         end if;
         B_First := Start;
         B_Last := E_At - 1;
         Found := True;
      end Find_PEM_Body;

      function Load_PEM_Cert (Pem : String; Der : out Byte_Array) return SEO is
         B_First, B_Last : Natural;
         Found : Boolean;
         L : Natural;
      begin
         Find_PEM_Body
           (Pem, "-----BEGIN CERTIFICATE-----", B_First, B_Last, Found);
         if not Found then
            return 0;
         end if;
         if not B64_Decode (Pem (B_First .. B_Last), Der, L) then
            return 0;
         end if;
         return SEO (L);
      end Load_PEM_Cert;

      function Load_PEM_Key
        (Pem : String; Rsa : out RSA_Priv; P256 : out P256_Priv;
         Is_RSA : out Boolean) return Boolean
      is
         B_First, B_Last : Natural;
         Found : Boolean;
         L : Natural;
         Der : Byte_Array (1 .. 4096);
      begin
         Rsa.Valid := False;
         Is_RSA := False;
         Find_PEM_Body
           (Pem, "-----BEGIN RSA PRIVATE KEY-----", B_First, B_Last, Found);
         if Found then
            if not B64_Decode (Pem (B_First .. B_Last), Der, L) then
               return False;
            end if;
            Is_RSA := True;
            return Parse_PKCS1 (Der (1 .. SEO (L)), Rsa);
         end if;
         Find_PEM_Body
           (Pem, "-----BEGIN EC PRIVATE KEY-----", B_First, B_Last, Found);
         if Found then
            if not B64_Decode (Pem (B_First .. B_Last), Der, L) then
               return False;
            end if;
            return Parse_SEC1 (Der (1 .. SEO (L)), P256);
         end if;
         Find_PEM_Body
           (Pem, "-----BEGIN PRIVATE KEY-----", B_First, B_Last, Found);
         if Found then
            if not B64_Decode (Pem (B_First .. B_Last), Der, L) then
               return False;
            end if;
            return Parse_PKCS8 (Der (1 .. SEO (L)), Rsa, P256, Is_RSA);
         end if;
         return False;
      end Load_PEM_Key;

      --  walk tbsCertificate children to find subjectPublicKeyInfo
      function Cert_SPKI (Der : Byte_Array; Spki_At : out Natural;
                          Spki_Len : out Natural) return Boolean
      is
         Tag : Byte;
         Len : Natural;
         Data_At : Natural;
         OK : Boolean;
         P : Natural;
         Tbs_Start : Natural;
         Tbs_End   : Natural;
         Count : Natural := 0;
      begin
         DER_TLV (Der, 1, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         --  tbsCertificate
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         Tbs_Start := Data_At;
         Tbs_End   := Data_At + Len;
         P := Tbs_Start;
         while P < Tbs_End loop
            DER_TLV (Der, P, Tag, Len, Data_At, OK);
            if not OK then
               return False;
            end if;
            if Tag = 16#A0# then
               null;   --  [0] version: skip
            else
               Count := Count + 1;
               if Count = 6 then
                  Spki_At := P;
                  Spki_Len := Len + (Data_At - P);
                  return True;
               end if;
            end if;
            P := Data_At + Len;
         end loop;
         return False;
      end Cert_SPKI;

      function Cert_Pub_Is_RSA (Der : Byte_Array) return Boolean is
         Spki_At, Spki_Len : Natural;
         Tag : Byte;
         Len : Natural;
         Data_At : Natural;
         OK : Boolean;
      begin
         if not Cert_SPKI (Der, Spki_At, Spki_Len) then
            return False;
         end if;
         --  SPKI: SEQUENCE { alg SEQ { OID, ... }, BIT STRING }
         DER_TLV (Der, Spki_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         return OID_Match (Der, Data_At, OID_RSA);
      end Cert_Pub_Is_RSA;

      function Cert_Pub_Is_P256 (Der : Byte_Array) return Boolean is
         Spki_At, Spki_Len : Natural;
         Tag : Byte;
         Len : Natural;
         Data_At : Natural;
         OK : Boolean;
         Param_At : Natural;
      begin
         if not Cert_SPKI (Der, Spki_At, Spki_Len) then
            return False;
         end if;
         DER_TLV (Der, Spki_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         if not OID_Match (Der, Data_At, OID_EC) then
            return False;
         end if;
         --  params: OID prime256v1 follows the ecPublicKey OID
         Param_At := Data_At + 2 + OID_EC'Length;
         return OID_Match (Der, Param_At, OID_P256);
      end Cert_Pub_Is_P256;

      function Cert_Pub_N_E
        (Der : Byte_Array; N : out Byte_Array; N_Len : out Natural;
         E : out Byte_Array; E_Len : out Natural) return Boolean
      is
         Spki_At, Spki_Len : Natural;
         Tag : Byte;
         Len : Natural;
         Data_At : Natural;
         OK : Boolean;
      begin
         if not Cert_SPKI (Der, Spki_At, Spki_Len) then
            return False;
         end if;
         DER_TLV (Der, Spki_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         Data_At := Data_At + Len;
         --  BIT STRING
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#03# then
            return False;
         end if;
         if Len < 1 then
            return False;
         end if;
         Data_At := Data_At + 1;   --  unused bits byte
         Len := Len - 1;
         --  RSAPublicKey ::= SEQUENCE { n, e }
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         if not DER_INT_Bytes (Der, Data_At, N, N_Len) then
            return False;
         end if;
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK then
            return False;
         end if;
         Data_At := Data_At + Len;
         if not DER_INT_Bytes (Der, Data_At, E, E_Len) then
            return False;
         end if;
         return True;
      end Cert_Pub_N_E;

      function Cert_Pub_P256
        (Der : Byte_Array; X, Y : out Byte_Array) return Boolean
      is
         Spki_At, Spki_Len : Natural;
         Tag : Byte;
         Len : Natural;
         Data_At : Natural;
         OK : Boolean;
      begin
         if not Cert_SPKI (Der, Spki_At, Spki_Len) then
            return False;
         end if;
         DER_TLV (Der, Spki_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#30# then
            return False;
         end if;
         Data_At := Data_At + Len;
         DER_TLV (Der, Data_At, Tag, Len, Data_At, OK);
         if not OK or Tag /= 16#03# then
            return False;
         end if;
         if Len /= 66 or Der (SEO (Data_At)) /= 0 then
            return False;
         end if;
         --  0x04 || X(32) || Y(32)
         if Der (SEO (Data_At + 1)) /= 16#04# then
            return False;
         end if;
         X := Der (SEO (Data_At + 2) .. SEO (Data_At + 33));
         Y := Der (SEO (Data_At + 34) .. SEO (Data_At + 65));
         return True;
      end Cert_Pub_P256;

      function Cert_Self_Check
        (Der : Byte_Array; Rsa : RSA_Priv; P256 : P256_Priv;
         Is_RSA : Boolean) return Boolean
      is
         CN : Byte_Array (1 .. 512);
         CL : Natural;
         CE : Byte_Array (1 .. 8);
         EL : Natural;
         CX, CY : Byte_Array (1 .. 32);
      begin
         if Is_RSA then
            if not Cert_Pub_N_E (Der, CN, CL, CE, EL) then
               return False;
            end if;
            if CL /= Rsa.N_Len then
               return False;
            end if;
            for I in 1 .. CL loop
               if CN (SEO (I)) /= Rsa.N (SEO (I)) then
                  return False;
               end if;
            end loop;
            return True;
         else
            if not Cert_Pub_P256 (Der, CX, CY) then
               return False;
            end if;
            --  check d*G matches the certificate public key
            declare
               Q : constant PPoint :=
                 P_To_Affine
                   (P_Scalar_Mult_G (BI_Mod (BI_From_BE (P256), P256_N)));
               QX : constant Byte_Array (1 .. 32) := BI_To_BE32 (Q.X);
               QY : constant Byte_Array (1 .. 32) := BI_To_BE32 (Q.Y);
            begin
               for I in 1 .. 32 loop
                  if QX (SEO (I)) /= CX (SEO (I)) or QY (SEO (I)) /= CY (SEO (I)) then
                     return False;
                  end if;
               end loop;
               return True;
            end;
         end if;
      end Cert_Self_Check;

      --  ==================== self test ====================

      function Hex_Str (B : Byte_Array) return String is
         H : constant String := "0123456789abcdef";
         R : String (1 .. B'Length * 2);
      begin
         for I in B'Range loop
            R (Integer ((I - B'First) * 2 + 1)) :=
              H (Natural (B (I) / 16) + 1);
            R (Integer ((I - B'First) * 2 + 2)) :=
              H (Natural (B (I) mod 16) + 1);
         end loop;
         return R;
      end Hex_Str;

      function Self_Test return Boolean is
         OK : Boolean := True;
         H : Digest_256;
         H3 : Digest_384;
         H5 : Digest_512;
         T : Tag_16;
         CL : SEO;
         R : SEO;
         CT : Byte_Array (1 .. 200);
         PT : Byte_Array (1 .. 200);
         K : X25519_Key;
         Sk1, Sk2 : X25519_Key;
         Pk1, Pk2 : X25519_Key;
         Sh1, Sh2 : X25519_Key;
         E1, E2 : P256_Priv;
         Q1, Q2 : P256_Pub;
         S : Byte_Array (1 .. 80);
         Sig_Len : SEO;
         M : Byte_Array (1 .. 200) :=
           [others => Character'Pos ('x')];
      begin
         --  SHA-256 (FIPS 180-4 "abc")
         H := SHA256 (Hex_B ("616263"));
         if Hex_Str (H) /=
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
         then
            Ada.Text_IO.Put_Line ("SELFTEST SHA256 fail: " & Hex_Str (H));
            OK := False;
         end if;
         Ada.Text_IO.Put_Line ("step sha384");
         --  SHA-384
         H3 := SHA384 (Hex_B ("616263"));
         if Hex_Str (H3) /=
           "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" &
           "8086072ba1e7cc2358baeca134c825a7"
         then
            Ada.Text_IO.Put_Line ("SELFTEST SHA384 fail: " & Hex_Str (H3));
            OK := False;
         end if;
         Ada.Text_IO.Put_Line ("step sha512");
         --  SHA-512
         H5 := SHA512 (Hex_B ("616263"));
         if Hex_Str (H5) /=
           "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" &
           "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
         then
            Ada.Text_IO.Put_Line ("SELFTEST SHA512 fail: " & Hex_Str (H5));
            OK := False;
         end if;
         Ada.Text_IO.Put_Line ("step hmac");
         --  HMAC-SHA256 (RFC 4231 test 1)
         H := HMAC_SHA256
           (Hex_B ("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            Hex_B ("4869205468657265"));
         if Hex_Str (H) /=
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
         then
            Ada.Text_IO.Put_Line ("SELFTEST HMAC fail: " & Hex_Str (H));
            OK := False;
         end if;
         Ada.Text_IO.Put_Line ("step gcm");
         --  AES-128-GCM (NIST SP 800-38D test case 17)
         AES128GCM_Seal
           (Hex_B ("feffe9928665731c6d6a8f9467308308"),
            Hex_B ("cafebabefacedbaddecaf888"),
            Hex_B ("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
            Hex_B ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a" &
                   "318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
            CT, CL, T, OK);
         if not OK then
            Ada.Text_IO.Put_Line ("SELFTEST GCM seal failed");
            return False;
         end if;
         if Hex_Str (CT (1 .. SEO (Natural (CL)))) /=
           "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" &
           "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
           or Hex_Str (T) /=
             "5bc94fbc3221a5db94fae95ae7121a47"
         then
            Ada.Text_IO.Put_Line ("SELFTEST GCM vector fail");
            OK := False;
         end if;
         R := AES128GCM_Open
           (Hex_B ("feffe9928665731c6d6a8f9467308308"),
            Hex_B ("cafebabefacedbaddecaf888"),
            Hex_B ("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
            CT (1 .. SEO (Natural (CL))), T, PT);
         if R /= 60 then
            Ada.Text_IO.Put_Line ("SELFTEST GCM open fail");
            OK := False;
         end if;
         Ada.Text_IO.Put_Line ("step chacha");
         --  ChaCha20-Poly1305 (RFC 8439 2.8.2)
         ChaCha20Poly1305_Seal
           (Hex_B ("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
            Hex_B ("070000004041424344454647"),
            Hex_B ("50515253c0c1c2c3c4c5c6c7"),
            Hex_B ("4c616469657320616e642047656e746c656d656e206f662074686520636c6173" &
                   "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" &
                   "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" &
                   "637265656e20776f756c642062652069742e"),
            CT, CL, T, OK);
         if not OK then
            Ada.Text_IO.Put_Line ("SELFTEST ChaCha seal failed");
            return False;
         end if;
         if Hex_Str (CT (1 .. SEO (Natural (CL)))) /=
           "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63" &
           "dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692" &
           "ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff" &
           "4def08e4b7a9de576d26586cec64b6116"
           or Hex_Str (T) /= "1ae10b594f09e26a7e902ecbd0600691"
         then
            Ada.Text_IO.Put_Line ("SELFTEST ChaCha vector fail");
            OK := False;
         end if;
         R := ChaCha20Poly1305_Open
           (Hex_B ("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
            Hex_B ("070000004041424344454647"),
            Hex_B ("50515253c0c1c2c3c4c5c6c7"),
            CT (1 .. SEO (Natural (CL))), T, PT);
         if R /= 114 then
            Ada.Text_IO.Put_Line ("SELFTEST ChaCha open fail");
            OK := False;
         end if;
         Ada.Text_IO.Put_Line ("step x25519");
         --  X25519 (RFC 7748 vector 1)
         K := Hex_B
           ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
         declare
            U : constant X25519_Key := Hex_B
              ("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
            Out_V : constant X25519_Key := X25519 (K, U);
         begin
            if Hex_Str (Out_V) /=
              "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
            then
               Ada.Text_IO.Put_Line ("SELFTEST X25519 fail: " & Hex_Str (Out_V));
               OK := False;
            end if;
         end;
         --  X25519 ECDH roundtrip
         X25519_Keygen (Sk1, Pk1);
         X25519_Keygen (Sk2, Pk2);
         Sh1 := X25519 (Sk1, Pk2);
         Sh2 := X25519 (Sk2, Pk1);
         for I in 1 .. 32 loop
            if Sh1 (SEO (I)) /= Sh2 (SEO (I)) then
               Ada.Text_IO.Put_Line ("SELFTEST X25519 ECDH fail");
               OK := False;
               exit;
            end if;
         end loop;
         Ada.Text_IO.Put_Line ("step p256");
         --  P-256 sign/verify roundtrip
         P256_Keygen (E1, Q1);
         declare
            Sig : constant Byte_Array := P256_ECDSA_Sign (E1, M (1 .. 64));
         begin
            S (1 .. Sig'Length) := Sig;
            Sig_Len := Sig'Length;
         end;
         if not P256_ECDSA_Verify (Q1, M (1 .. 64), S (1 .. SEO (Natural (Sig_Len))))
         then
            Ada.Text_IO.Put_Line ("SELFTEST P256 sign/verify fail");
            OK := False;
         end if;
         --  P-256 ECDH roundtrip
         P256_Keygen (E2, Q2);
         declare
            H1 : constant Byte_Array (1 .. 32) :=
              P256_ECDH (E1, Q2);
            H2 : constant Byte_Array (1 .. 32) :=
              P256_ECDH (E2, Q1);
         begin
            for I in 1 .. 32 loop
               if H1 (SEO (I)) /= H2 (SEO (I)) then
                  Ada.Text_IO.Put_Line ("SELFTEST P256 ECDH fail");
                  OK := False;
                  exit;
               end if;
            end loop;
         end;

         Ada.Text_IO.Put_Line ("step rsa");
         --  RSA-PSS sign/verify roundtrip (2048-bit test key, CRT)
         declare
            K : RSA_Priv;
            SigR : Byte_Array (1 .. 256);
         begin
            K.Valid := True;
            K.N_Len := 256;
            K.P_Len := 128;
            K.Q_Len := 128;
            K.DP_Len := 128;
            K.DQ_Len := 128;
            K.QI_Len := 128;
            K.E_Len := 3;
            K.N (1 .. 256) := Hex_B (
              "ab6a942708ba3dae6a0ddf160af73415434ae348f25015b31ee89ea44de7" &
              "5d217f66c9fbc7e0539b21fae5d36db667e93bb2b9b9421d636bea8571ba" &
              "96c7086d8c86897e6a09bd42bf1a5af8ff1c33de7cabbc29f954548fdb94" &
              "2ed34e25cd659bb3355531d6184275cd8fec6f571d02b94e4ad552bde1ce" &
              "cfa8c372f89bd98549fff6f88a29e40e67dcb662c6140a23c6f3c4e3d7a9" &
              "ceb71e3a1f6849e85eacb6caba20e96a8c0bafe2683f88985bcc7864d343" &
              "5c9b70621536bfeb26d672bc94f0f1d6718549a71d3fba73f6e59ca42289" &
              "89ddab0a5d46203c340d12f2c7c1863bc425d2f18bdcb1e55b441a9b62b6" &
              "59557eb25b2cb5bbfca65ea6ac999c8b");
            K.P (1 .. 128) := Hex_B (
              "d4318b695ffd76cf9246dfa47966f636e55e025e3a6f75bae9a57358a0d6" &
              "c119ded6d096bb5c0414352983d0b05205ddad8278e3d012e4b186926d51" &
              "94fa57648c567f245bdacc7e644bb3b00b708a7f0b2c7bf14b2307bc1db2" &
              "f6caef6f96ddb153d6247162ebe0ff969dece64b8b6a1a30de47a2abba51" &
              "477e67998cc6f209");
            K.Q (1 .. 128) := Hex_B (
              "cecdf40eef80011e527c687074eca9ff04fa92efbf758e8792b4134bb257" &
              "e69372c580e3836e393d9b9e8d476ad09559c683633375a0a0763e577e57" &
              "d8fbc05970e381d75d44ffd0a5f987ca6de26d490334f6da0e9ae92d6fa9" &
              "e359138264b9ea5e9cd036f4ba7d1dfc63161b7b54c762645da4b3c42138" &
              "84f5fecd7a326ef3");
            K.DP (1 .. 128) := Hex_B (
              "b267797c3e3d7ff0235f3d572ecf37818e350d2ea658e21625ad7a9e7094" &
              "3ec47e8c03d24772a4e74c8f3c0970c575b31cd7cec653421f4f770293b0" &
              "fcddc22e82a392c0420e62d27d86fc6bae228fff22a8e3084b910746cd7d" &
              "936baa061b45077ba256ff92191a122a535b43810e9545b202a11e0ede56" &
              "ca12680e3cc363e9");
            K.DQ (1 .. 128) := Hex_B (
              "0ca8f703e30d87040030b5840ce46013c88e3e6886e3ff71b53d68e0fd6d" &
              "fc2392a71c98d0f6f2721f10b9bd61809b63ff8f138796efda62e2b62079" &
              "e842a127d88d54e986402f18ead037cbe0a637e27c5bc5b0dbac08124bff" &
              "ae77498675fc1ba8e718a8049b56057be9e4f491bc42e87714747cbcc8fb" &
              "d8c7e66d55c9b899");
            K.QI (1 .. 128) := Hex_B (
              "b16b91cca6a7a4740bd8f02e6b72db08d1f1c9978237410f9feb4c82d5a0" &
              "5242ac9e5f2830e20a6858e755eddfa99d0749b380703044fc9684e21aa1" &
              "e21fa7a33c5378e0e6e57de0b2d3bbe4b5d648c013d9814152d15ccaec6d" &
              "92d7e693ae9c759350576c34fcdea4198106503cac771e269f85c925744b" &
              "e3d6950070e9afe2");
            K.E (1 .. 3) := Hex_B ("010001");
            SigR := RSA_Sign_PSS (K, SHA256 (M (1 .. 64)));
            if not RSA_Verify_PSS
              (K.N (1 .. 256), K.E (1 .. 3), SigR, SHA256 (M (1 .. 64)))
            then
               Ada.Text_IO.Put_Line ("SELFTEST RSA PSS roundtrip fail");
               OK := False;
            end if;
         end;
         return OK;
      end Self_Test;

      --  ==================== TLS ====================
      --  (full implementation follows)

      procedure TLS_Init
        (C : out TLS_Conn; Cert : Byte_Array; Cert_Len : SEO;
         Rsa : RSA_Priv; P256 : P256_Priv; Is_RSA : Boolean;
         Ok : out Boolean)
      is
      begin
         C := (Cert => [others => 0], Cert_Len => 0, Cert_Is_RSA => Is_RSA,
               Rsa => Rsa, P256 => P256, others => <>);
         C.Cert (1 .. Cert_Len) := Cert (1 .. Cert_Len);
         C.Cert_Len := Cert_Len;
         Ok := True;
      end TLS_Init;

      --  ==================== TLS wire helpers ====================

      type T_Recv_St is (T_Recv_Ok, T_Recv_Eof, T_Recv_Err);

      Empty_BA : constant Byte_Array (1 .. 0) := (others => 0);

      function Str_B (S : String) return Byte_Array is
         R : Byte_Array (1 .. S'Length);
      begin
         for I in 1 .. S'Length loop
            R (SEO (I)) := Character'Pos (S (S'First + I - 1));
         end loop;
         return R;
      end Str_B;

      function SHA256_Empty return Digest_256 is
         C : SHA256_Ctx;
      begin
         SHA256_Init (C);
         return SHA256_Final (C);
      end SHA256_Empty;

      procedure T_Send_All
        (S : GNAT.Sockets.Socket_Type; Data : Byte_Array; Ok : out Boolean)
      is
         Pos : SEO := Data'First;
         Last : SEO;
      begin
         Ok := True;
         while Pos <= Data'Last loop
            GNAT.Sockets.Send_Socket (S, Data (Pos .. Data'Last), Last);
            if Last < Pos then
               Ok := False;
               return;
            end if;
            Pos := Last + 1;
         end loop;
      exception
         when GNAT.Sockets.Socket_Error =>
            Ok := False;
      end T_Send_All;

      --  receive exactly N bytes into Buf(1..N)
      procedure T_Recv_Exact
        (S : GNAT.Sockets.Socket_Type; Buf : out Byte_Array; N : Natural;
         St : out T_Recv_St)
      is
         Got : SEO := 0;
         Last : SEO;
      begin
         St := T_Recv_Ok;
         while Got < SEO (N) loop
            GNAT.Sockets.Receive_Socket
              (S, Buf (Buf'First + Got .. Buf'First + SEO (N) - 1), Last);
            if Last < Buf'First + Got then
               St := T_Recv_Eof;
               return;
            end if;
            Got := Last - Buf'First + 1;
         end loop;
      exception
         when GNAT.Sockets.Socket_Error =>
            St := T_Recv_Err;
      end T_Recv_Exact;

      procedure TLS_Nonce (IV : Byte_Array; Seq : Byte_Array;
                           Nonce : out Byte_Array) is
      begin
         Nonce (1 .. 4) := IV (1 .. 4);
         for I in 1 .. 8 loop
            Nonce (SEO (4 + I)) := IV (SEO (4 + I)) xor Seq (SEO (I));
         end loop;
      end TLS_Nonce;

      procedure TLS_Inc_Seq (Seq : in out Byte_Array) is
      begin
         for I in reverse Seq'Range loop
            Seq (I) := Seq (I) + 1;
            exit when Seq (I) /= 0;
         end loop;
      end TLS_Inc_Seq;

      procedure TLS_Seal
        (C : TLS_Conn; Key, Nonce : Byte_Array; AAD, Plain : Byte_Array;
         Cipher : out Byte_Array; CL : out SEO; Tag : out Tag_16;
         Ok : out Boolean)
      is
      begin
         if C.Cipher = 1 then
            AES128GCM_Seal (Key, Nonce, AAD, Plain, Cipher, CL, Tag, Ok);
         else
            ChaCha20Poly1305_Seal (Key, Nonce, AAD, Plain, Cipher, CL, Tag, Ok);
         end if;
      end TLS_Seal;

      function TLS_Open
        (C : TLS_Conn; Key, Nonce : Byte_Array; AAD, Cipher : Byte_Array;
         Tag : Tag_16; Plain : out Byte_Array) return SEO
      is
      begin
         if C.Cipher = 1 then
            return AES128GCM_Open (Key, Nonce, AAD, Cipher, Tag, Plain);
         else
            return ChaCha20Poly1305_Open (Key, Nonce, AAD, Cipher, Tag, Plain);
         end if;
      end TLS_Open;

      function TLS_Key_Len (C : TLS_Conn) return Natural is
      begin
         return (if C.Cipher = 1 then 16 else 32);
      end TLS_Key_Len;

      --  send one encrypted record (TLS 1.3 unified record, outer type 23)
      procedure TLS_Send_Record
        (C : in out TLS_Conn; S : GNAT.Sockets.Socket_Type;
         Inner : Byte; Data : Byte_Array; Ok : out Boolean)
      is
         Hdr    : Byte_Array (1 .. 5);
         Plain  : Byte_Array (1 .. TLS_Max_Plain + 1) := [others => 0];
         Cipher : Byte_Array (1 .. TLS_Max_Record) := [others => 0];
         Frame  : Byte_Array (1 .. 5 + TLS_Max_Record) := [others => 0];
         CL : SEO;
         Tag : Tag_16;
         Nonce : Byte_Array (1 .. 12);
         Klen : constant Natural := TLS_Key_Len (C);
      begin
         Ok := False;
         if Data'Length > TLS_Max_Plain then
            return;
         end if;
         Plain (1 .. Data'Length) := Data;
         Plain (SEO (Data'Length + 1)) := Inner;
         Hdr (1) := 23;
         Hdr (2) := 3;
         Hdr (3) := 3;
         Set_BE16 (Hdr, 4, Unsigned_16 (Data'Length + 1 + 16));
         TLS_Nonce (C.Out_IV, C.Out_Seq, Nonce);
         TLS_Seal (C, C.Out_Key (1 .. SEO (Klen)), Nonce, Hdr,
                   Plain (1 .. SEO (Data'Length + 1)), Cipher, CL, Tag, Ok);
         if not Ok then
            return;
         end if;
         Frame (1 .. 5) := Hdr;
         Frame (6 .. 5 + CL) := Cipher (1 .. CL);
         Frame (SEO (5 + CL + 1) .. SEO (5 + CL + 16)) := Tag;
         T_Send_All (S, Frame (1 .. SEO (5 + CL + 16)), Ok);
         if Ok then
            TLS_Inc_Seq (C.Out_Seq);
         end if;
      end TLS_Send_Record;

      --  read one record: header + payload (no decryption)
      procedure TLS_Recv_Raw
        (S : GNAT.Sockets.Socket_Type;
         Typ : out Natural; Data : out Byte_Array; Len : out Natural;
         Ok : out Boolean; Eof : out Boolean)
      is
         Hdr : Byte_Array (1 .. 5);
         St : T_Recv_St;
         Rec_Len : Natural;
      begin
         Ok := False; Eof := False; Typ := 0; Len := 0;
         T_Recv_Exact (S, Hdr, 5, St);
         if St = T_Recv_Eof then
            Eof := True;
            return;
         elsif St /= T_Recv_Ok then
            return;
         end if;
         Typ := Natural (Hdr (1));
         Rec_Len := Natural (BE16 (Hdr, 4));
         if Rec_Len > TLS_Max_Record then
            return;
         end if;
         T_Recv_Exact (S, Data, Rec_Len, St);
         if St /= T_Recv_Ok then
            Eof := (St = T_Recv_Eof);
            return;
         end if;
         Len := Rec_Len;
         Ok := True;
      end TLS_Recv_Raw;

      --  decrypt an encrypted record (outer type 23); advances In_Seq on success
      procedure TLS_Decrypt
        (C : in out TLS_Conn; Hdr : Byte_Array;
         Payload : Byte_Array; Payload_Len : Natural;
         Inner : out Natural; Data : out Byte_Array; Len : out Natural;
         Ok : out Boolean)
      is
         Nonce : Byte_Array (1 .. 12);
         Tag   : Tag_16;
         Plain : Byte_Array (1 .. TLS_Max_Plain + 1) := [others => 0];
         Plen  : SEO;
         Klen  : constant Natural := TLS_Key_Len (C);
      begin
         Ok := False; Inner := 0; Len := 0;
         if Payload_Len < 17 then
            return;
         end if;
         TLS_Nonce (C.In_IV, C.In_Seq, Nonce);
         Tag := Payload (SEO (Payload_Len - 15) .. SEO (Payload_Len));
         Plen := TLS_Open (C, C.In_Key (1 .. SEO (Klen)), Nonce, Hdr,
                           Payload (1 .. SEO (Payload_Len - 16)), Tag, Plain);
         if Plen < 0 then
            return;
         end if;
         TLS_Inc_Seq (C.In_Seq);
         Inner := Natural (Plain (Plen));
         Len := Natural (Plen - 1);
         if Len > 0 then
            Data (1 .. SEO (Len)) := Plain (1 .. Plen - 1);
         end if;
         Ok := True;
      end TLS_Decrypt;

      --  append a full handshake message to the transcript and send it
      procedure HS_Send
        (C : in out TLS_Conn; S : GNAT.Sockets.Socket_Type;
         Typ : Byte; Body_Data : Byte_Array; Encrypted : Boolean;
         Ok : out Boolean)
      is
         Msg  : Byte_Array (1 .. 4 + TLS_Max_Record) := [others => 0];
         Rec  : Byte_Array (1 .. 5 + 4 + TLS_Max_Record) := [others => 0];
         MLen : constant Natural := 4 + Body_Data'Length;
      begin
         Ok := False;
         Msg (1) := Typ;
         Msg (2) := Byte ((Body_Data'Length / 65536) mod 256);
         Msg (3) := Byte ((Body_Data'Length / 256) mod 256);
         Msg (4) := Byte (Body_Data'Length mod 256);
         Msg (5 .. 4 + Body_Data'Length) := Body_Data;
         SHA256_Update (C.Tr, Msg (1 .. SEO (MLen)));
         if Encrypted then
            TLS_Send_Record (C, S, 22, Msg (1 .. SEO (MLen)), Ok);
         else
            Rec (1) := 22;
            Rec (2) := 3;
            Rec (3) := 3;
            Set_BE16 (Rec, 4, Unsigned_16 (MLen));
            Rec (6 .. SEO (5 + MLen)) := Msg (1 .. SEO (MLen));
            T_Send_All (S, Rec (1 .. SEO (5 + MLen)), Ok);
         end if;
      end HS_Send;

      function Tr_Hash (C : TLS_Conn) return Digest_256 is
         Tmp : SHA256_Ctx := C.Tr;
      begin
         return SHA256_Final (Tmp);
      end Tr_Hash;

      function Derive_Secret
        (Secret : Byte_Array; Label : String; Ctx : Byte_Array)
         return Byte_Array
      is
      begin
         return HKDF_Expand_Label (Secret, Label, Ctx, 32);
      end Derive_Secret;

      --  ==================== TLS 1.3 server handshake ====================

      procedure TLS_Server_Handshake
        (C : in out TLS_Conn; Sock : GNAT.Sockets.Socket_Type;
         Ok : out Boolean)
      is
         Payload : Byte_Array (1 .. TLS_Max_Record) := [others => 0];
         Hdr     : Byte_Array (1 .. 5);
         St      : T_Recv_St;
         Rec_Typ : Natural;
         Rec_Len : Natural;

         --  ClientHello parse results
         CH_Body : Byte_Array (1 .. TLS_Max_Record) := [others => 0];
         CH_Len  : Natural := 0;
         Session_Id : Byte_Array (1 .. 32) := [others => 0];
         Session_Id_Len : Natural := 0;
         Client_Group : Unsigned_16 := 0;
         Client_Key : Byte_Array (1 .. 65) := [others => 0];
         Client_Key_Len : Natural := 0;
         Has_TLS13 : Boolean := False;
         Cipher_Ok : Boolean := False;

         --  negotiated
         Picked_Cipher : Unsigned_16 := 0;
         Use_X : Boolean := False;
         Key_Len : Natural := 0;
         Group : Unsigned_16 := 0;
         Shared : Byte_Array (1 .. 32) := [others => 0];
         Server_Key_Share : Byte_Array (1 .. 65) := [others => 0];

         --  key schedule
         Zero32  : constant Byte_Array (1 .. 32) := [others => 0];
         Empty_H : constant Digest_256 := SHA256_Empty;
         Early   : Digest_256;
         Derived : Byte_Array (1 .. 32);
         Hs      : Byte_Array (1 .. 32);
         Client_HS, Server_HS : Byte_Array (1 .. 32);
         Ms      : Byte_Array (1 .. 32);
         Client_AP, Server_AP : Byte_Array (1 .. 32);
         Fin_Key : Byte_Array (1 .. 32);
         Klen     : Natural;

         --  message building
         SH : Byte_Array (1 .. 2048) := [others => 0];
         Pos : SEO;
         Verify_Data : Byte_Array (1 .. 32);
         Inner : Natural;
         Plain : Byte_Array (1 .. TLS_Max_Plain + 1) := [others => 0];
         Plen  : Natural;
         Signed_Data : Byte_Array (1 .. 64 + 33 + 1 + 32) := [others => 0];
         Sig : Byte_Array (1 .. 512) := [others => 0];
         Sig_Len : Natural := 0;
      begin
         Ok := False;
         SHA256_Init (C.Tr);
         C.Handshake_Done := False;
         C.Peer_Finished_Ok := False;
         C.Is_TLS13 := False;
         C.In_Seq := [others => 0];
         C.Out_Seq := [others => 0];

         --  1. read ClientHello (plaintext handshake record)
         TLS_Recv_Raw (Sock, Rec_Typ, Payload, Rec_Len, Ok, C.Closed);
         if not Ok then
            return;
         end if;
         if Rec_Typ /= 22 or Rec_Len < 4 then
            return;
         end if;
         if Natural (Payload (1)) /= 1 then
            return;
         end if;
         CH_Len := BE24 (Payload, 2);
         if 4 + CH_Len > Rec_Len then
            return;
         end if;
         --  transcript = ClientHello handshake message
         SHA256_Update (C.Tr, Payload (1 .. SEO (4 + CH_Len)));
         CH_Body (1 .. SEO (CH_Len)) := Payload (5 .. SEO (4 + CH_Len));

         --  2. parse ClientHello body
         declare
            Off : SEO := 1;
            Sl  : Natural;
            Cs_Len : Natural;
            Comp_Len : Natural;
            Ext_Len : Natural;
         begin
            if CH_Len < 38 then
               return;
            end if;
            Off := Off + 2;                     --  legacy_version
            Off := Off + 32;                    --  random
            Sl := Natural (CH_Body (Off));
            Off := Off + 1;
            if Sl > 32 or Off + SEO (Sl) - 1 > SEO (CH_Len) then
               return;
            end if;
            Session_Id (1 .. SEO (Sl)) := CH_Body (Off .. SEO (Off + SEO (Sl) - 1));
            Session_Id_Len := Sl;
            Off := Off + SEO (Sl);
            if Off + 2 > SEO (CH_Len) then
               return;
            end if;
            Cs_Len := Natural (BE16 (CH_Body, Off));
            Off := Off + 2;
            if Cs_Len mod 2 /= 0 or Off + SEO (Cs_Len) - 1 > SEO (CH_Len) then
               return;
            end if;
            declare
               I : SEO := Off;
            begin
               while I < Off + SEO (Cs_Len) loop
                  declare
                     CS : constant Unsigned_16 := BE16 (CH_Body, I);
                  begin
                     if CS = 16#1301# then
                        Picked_Cipher := CS;
                        Cipher_Ok := True;
                     elsif CS = 16#1303# and then not Cipher_Ok then
                        Picked_Cipher := CS;
                        Cipher_Ok := True;
                     end if;
                  end;
                  I := I + 2;
               end loop;
            end;
            Off := Off + SEO (Cs_Len);
            if Off > SEO (CH_Len) then
               return;
            end if;
            Comp_Len := Natural (CH_Body (Off));
            Off := Off + 1;
            if Off + SEO (Comp_Len) - 1 > SEO (CH_Len) then
               return;
            end if;
            Off := Off + SEO (Comp_Len);
            if Off + 2 > SEO (CH_Len) then
               return;
            end if;
            Ext_Len := Natural (BE16 (CH_Body, Off));
            Off := Off + 2;
            if Off + SEO (Ext_Len) - 1 > SEO (CH_Len) then
               return;
            end if;
            --  iterate extensions
            declare
               E : SEO := Off;
               EEnd : constant SEO := Off + SEO (Ext_Len) - 1;
            begin
               while E + 3 <= EEnd loop
                  declare
                     EType : constant Unsigned_16 := BE16 (CH_Body, E);
                     ELen  : constant Natural := Natural (BE16 (CH_Body, E + 2));
                  begin
                     if E + 4 + SEO (ELen) - 1 > EEnd then
                        return;
                     end if;
                     if EType = 43 then
                        --  supported_versions: 1 byte len + versions
                        if ELen >= 3 then
                           declare
                              I  : SEO := E + 5;
                           begin
                              while I < E + 4 + SEO (ELen) loop
                                 if BE16 (CH_Body, I) = 16#0304# then
                                    Has_TLS13 := True;
                                 end if;
                                 I := I + 2;
                              end loop;
                           end;
                        end if;
                     elsif EType = 51 then
                        --  key_share: client_shares_len + list of
                        --  { group(2), key_len(2), key }. The first share may
                        --  be a GREASE value, so scan for a group we support.
                        if ELen >= 6 then
                           declare
                              Shares_End : constant SEO :=
                                E + 4 + SEO (ELen) - 1;
                              S : SEO := E + 6;   --  group of first share
                           begin
                              Client_Key_Len := 0;
                              while S + 3 <= Shares_End loop
                                 declare
                                    G  : constant Unsigned_16 := BE16 (CH_Body, S);
                                    KL : constant Natural :=
                                      Natural (BE16 (CH_Body, S + 2));
                                 begin
                                    if S + 4 + SEO (KL) - 1 > Shares_End then
                                       exit;
                                    end if;
                                    if (G = 16#001D# and then KL = 32)
                                      or else (G = 16#0017# and then KL = 65)
                                    then
                                       Client_Group := G;
                                       Client_Key_Len := KL;
                                       Client_Key (1 .. SEO (KL)) :=
                                         CH_Body (S + 4 ..
                                           SEO (S + 4 + SEO (KL) - 1));
                                       exit;
                                    end if;
                                    S := S + 4 + SEO (KL);
                                 end;
                              end loop;
                           end;
                        end if;
                     end if;
                  end;
                  E := E + 4 + SEO (Natural (BE16 (CH_Body, E + 2)));
               end loop;
            end;
         end;

         if not Has_TLS13 or not Cipher_Ok then
            return;
         end if;

         --  3. choose group + generate server key share
         if Client_Group = 16#001D# and then Client_Key_Len = 32 then
            Use_X := True;
            Group := 16#001D#;
            Key_Len := 32;
         elsif Client_Group = 16#0017# and then Client_Key_Len = 65 then
            Use_X := False;
            Group := 16#0017#;
            Key_Len := 65;
         else
            return;
         end if;

         if Use_X then
            declare
               Sk : X25519_Key;
               Pk : X25519_Key;
            begin
               X25519_Keygen (Sk, Pk);
               Server_Key_Share (1 .. 32) := Pk;
               Shared := X25519 (Sk, Client_Key (1 .. 32));
            end;
         else
            declare
               Sk : P256_Priv;
               Pk : P256_Pub;
            begin
               P256_Keygen (Sk, Pk);
               Server_Key_Share (1) := 4;
               Server_Key_Share (2 .. 33) := Pk.X;
               Server_Key_Share (34 .. 65) := Pk.Y;
               Shared := P256_ECDH
                 (Sk, (X => Client_Key (2 .. 33), Y => Client_Key (34 .. 65)));
            end;
         end if;

         --  4. build ServerHello
         SH (1) := 3;
         SH (2) := 3;
         Random_Bytes (SH (3 .. 34));
         SH (35) := Byte (Session_Id_Len);
         SH (36 .. SEO (35 + Session_Id_Len)) := Session_Id (1 .. SEO (Session_Id_Len));
         Pos := 36 + SEO (Session_Id_Len);
         Set_BE16 (SH, Pos, Picked_Cipher);
         Pos := Pos + 2;
         SH (Pos) := 0;
         Pos := Pos + 1;
         Set_BE16 (SH, Pos, Unsigned_16 (14 + Key_Len));
         Pos := Pos + 2;
         Set_BE16 (SH, Pos, 43);
         Pos := Pos + 2;
         Set_BE16 (SH, Pos, 2);
         Pos := Pos + 2;
         SH (Pos) := 3;
         SH (Pos + 1) := 4;
         Pos := Pos + 2;
         Set_BE16 (SH, Pos, 51);
         Pos := Pos + 2;
         Set_BE16 (SH, Pos, Unsigned_16 (4 + Key_Len));
         Pos := Pos + 2;
         Set_BE16 (SH, Pos, Group);
         Pos := Pos + 2;
         Set_BE16 (SH, Pos, Unsigned_16 (Key_Len));
         Pos := Pos + 2;
         SH (Pos .. SEO (Pos + SEO (Key_Len) - 1)) :=
           Server_Key_Share (1 .. SEO (Key_Len));
         Pos := Pos + SEO (Key_Len);

         C.Is_TLS13 := True;
         C.Cipher := (if Picked_Cipher = 16#1301# then 1 else 2);
         C.ECDHE_X := Use_X;
         Klen := TLS_Key_Len (C);

         HS_Send (C, Sock, 2, SH (1 .. SEO (Pos - 1)), False, Ok);
         if not Ok then
            return;
         end if;

         --  5. key schedule: handshake secrets from ClientHello..ServerHello
         Early := HKDF_Extract (Zero32, Zero32);
         Derived := Derive_Secret (Early, "derived", Empty_H);
         Hs := HKDF_Extract (Derived, Shared);
         Client_HS := Derive_Secret (Hs, "c hs traffic", Tr_Hash (C));
         Server_HS := Derive_Secret (Hs, "s hs traffic", Tr_Hash (C));
         C.Out_Key (1 .. SEO (Klen)) := HKDF_Expand_Label (Server_HS, "key", Empty_BA, Klen);
         C.Out_IV := HKDF_Expand_Label (Server_HS, "iv", Empty_BA, 12);
         C.In_Key (1 .. SEO (Klen)) := HKDF_Expand_Label (Client_HS, "key", Empty_BA, Klen);
         C.In_IV := HKDF_Expand_Label (Client_HS, "iv", Empty_BA, 12);

         --  6. EncryptedExtensions (empty)
         declare
            EE : constant Byte_Array (1 .. 2) := [0, 0];
         begin
            HS_Send (C, Sock, 8, EE, True, Ok);
         end;
         if not Ok then
            return;
         end if;

         --  7. Certificate
         declare
            Cert_Msg : Byte_Array (1 .. TLS_Max_Cert + 16) := [others => 0];
            List_Len : constant Natural := 3 + Natural (C.Cert_Len) + 2;
            P : SEO := 1;
         begin
            Cert_Msg (P) := 0;                       --  request context len
            P := P + 1;
            Cert_Msg (P) := Byte ((List_Len / 65536) mod 256);
            Cert_Msg (P + 1) := Byte ((List_Len / 256) mod 256);
            Cert_Msg (P + 2) := Byte (List_Len mod 256);
            P := P + 3;
            Cert_Msg (P) := Byte ((Natural (C.Cert_Len) / 65536) mod 256);
            Cert_Msg (P + 1) := Byte ((Natural (C.Cert_Len) / 256) mod 256);
            Cert_Msg (P + 2) := Byte (Natural (C.Cert_Len) mod 256);
            P := P + 3;
            Cert_Msg (P .. SEO (P + C.Cert_Len - 1)) := C.Cert (1 .. C.Cert_Len);
            P := P + C.Cert_Len;
            Cert_Msg (P) := 0;                       --  extensions len = 0
            Cert_Msg (P + 1) := 0;
            P := P + 2;
            HS_Send (C, Sock, 11, Cert_Msg (1 .. SEO (P - 1)), True, Ok);
         end;
         if not Ok then
            return;
         end if;

         --  8. CertificateVerify
         Signed_Data (1 .. 64) := [others => 16#20#];
         Signed_Data (65 .. 97) := Str_B ("TLS 1.3, server CertificateVerify");
         Signed_Data (98) := 0;
         Signed_Data (99 .. 130) := Tr_Hash (C);
         if C.Cert_Is_RSA then
            Sig_Len := 0;
            Sig := [others => 0];
            declare
               R : constant Byte_Array :=
                 RSA_Sign_PSS (C.Rsa, SHA256 (Signed_Data));
            begin
               Sig (1 .. R'Length) := R;
               Sig_Len := R'Length;
            end;
         else
            declare
               R : constant Byte_Array := P256_ECDSA_Sign (C.P256, Signed_Data);
            begin
               Sig (1 .. R'Length) := R;
               Sig_Len := R'Length;
            end;
         end if;
         declare
            CV : Byte_Array (1 .. 4 + 512) := [others => 0];
            P : SEO := 1;
         begin
            if C.Cert_Is_RSA then
               Set_BE16 (CV, P, 16#0804#);   --  rsa_pss_rsae_sha256 (TLS 1.3)
            else
               Set_BE16 (CV, P, 16#0403#);
            end if;
            P := P + 2;
            Set_BE16 (CV, P, Unsigned_16 (Sig_Len));
            P := P + 2;
            CV (P .. SEO (P + SEO (Sig_Len) - 1)) := Sig (1 .. SEO (Sig_Len));
            P := P + SEO (Sig_Len);
            HS_Send (C, Sock, 15, CV (1 .. SEO (P - 1)), True, Ok);
         end;
         if not Ok then
            return;
         end if;

         --  9. server Finished
         Fin_Key := HKDF_Expand_Label (Server_HS, "finished", Empty_BA, 32);
         Verify_Data := HMAC_SHA256 (Fin_Key, Tr_Hash (C));
         HS_Send (C, Sock, 20, Verify_Data, True, Ok);
         if not Ok then
            return;
         end if;

         --  10. application traffic secrets from ClientHello..server Finished
         Derived := Derive_Secret (Hs, "derived", Empty_H);
         Ms := HKDF_Extract (Derived, Zero32);
         Client_AP := Derive_Secret (Ms, "c ap traffic", Tr_Hash (C));
         Server_AP := Derive_Secret (Ms, "s ap traffic", Tr_Hash (C));

         --  11. read client Finished (skip any CCS record first)
         loop
            T_Recv_Exact (Sock, Hdr, 5, St);
            if St /= T_Recv_Ok then
               return;
            end if;
            Rec_Typ := Natural (Hdr (1));
            Rec_Len := Natural (BE16 (Hdr, 4));
            if Rec_Len > TLS_Max_Record then
               return;
            end if;
            T_Recv_Exact (Sock, Payload, Rec_Len, St);
            if St /= T_Recv_Ok then
               return;
            end if;
            exit when Rec_Typ = 23;
            if Rec_Typ /= 20 then
               return;
            end if;
         end loop;
         TLS_Decrypt (C, Hdr, Payload, Rec_Len, Inner, Plain, Plen, Ok);
         if not Ok then
            return;
         end if;
         if Inner /= 22 or Plen < 4 then
            return;
         end if;
         if Natural (Plain (1)) /= 20 then
            return;
         end if;
         if BE24 (Plain, 2) /= 32 or Plen /= 36 then
            return;
         end if;
         declare
            Client_Fin_Key : constant Byte_Array (1 .. 32) :=
              HKDF_Expand_Label (Client_HS, "finished", Empty_BA, 32);
            Expected : constant Digest_256 :=
              HMAC_SHA256 (Client_Fin_Key, Tr_Hash (C));
         begin
            for I in 1 .. 32 loop
               if Plain (SEO (I + 4)) /= Expected (SEO (I)) then
                  return;
               end if;
            end loop;
         end;
         --  transcript += client Finished (for completeness)
         SHA256_Update (C.Tr, Plain (1 .. 36));

         --  12. switch to application traffic keys
         C.Out_Key := [others => 0];
         C.In_Key := [others => 0];
         C.Out_Key (1 .. SEO (Klen)) := HKDF_Expand_Label (Server_AP, "key", Empty_BA, Klen);
         C.Out_IV := HKDF_Expand_Label (Server_AP, "iv", Empty_BA, 12);
         C.In_Key (1 .. SEO (Klen)) := HKDF_Expand_Label (Client_AP, "key", Empty_BA, Klen);
         C.In_IV := HKDF_Expand_Label (Client_AP, "iv", Empty_BA, 12);
         C.Out_Seq := [others => 0];
         C.In_Seq := [others => 0];
         C.Peer_Finished_Ok := True;
         C.Handshake_Done := True;
         Ok := True;
      exception
         when E : others =>
            Ok := False;
            Ada.Text_IO.Put_Line
              (Ada.Text_IO.Standard_Error,
               "TLS handshake error: " & Ada.Exceptions.Exception_Name (E));
            Ada.Text_IO.Put_Line
              (Ada.Text_IO.Standard_Error,
               "TLS handshake info: " & Ada.Exceptions.Exception_Information (E));
      end TLS_Server_Handshake;

      procedure TLS_Read
        (C : in out TLS_Conn; Sock : GNAT.Sockets.Socket_Type;
         Buf : out Byte_Array; Count : out SEO;
         Eof : out Boolean; Ok : out Boolean)
      is
         Hdr  : Byte_Array (1 .. 5);
         Payload : Byte_Array (1 .. TLS_Max_Record) := [others => 0];
         Inner : Natural;
         Plain : Byte_Array (1 .. TLS_Max_Plain + 1) := [others => 0];
         Plen  : Natural;
         Rec_Typ, Rec_Len : Natural;
         St : T_Recv_St;
      begin
         Count := 0; Eof := False; Ok := False;
         if not C.Handshake_Done then
            return;
         end if;
         loop
            --  serve buffered plaintext first
            if C.Plain_Len > 0 and then C.Plain_Pos <= C.Plain_Len then
               declare
                  N : constant SEO := SEO'Min
                    (C.Plain_Len - C.Plain_Pos + 1, Buf'Length);
               begin
                  Buf (Buf'First .. Buf'First + N - 1) :=
                    C.Plain (C.Plain_Pos .. SEO (C.Plain_Pos + N - 1));
                  C.Plain_Pos := C.Plain_Pos + N;
                  if C.Plain_Pos > C.Plain_Len then
                     C.Plain_Pos := 1;
                     C.Plain_Len := 0;
                  end if;
                  Count := N;
                  Ok := True;
                  return;
               end;
            end if;
            --  read + decrypt next record
            T_Recv_Exact (Sock, Hdr, 5, St);
            if St = T_Recv_Eof then
               Eof := True;
               Ok := True;
               return;
            elsif St /= T_Recv_Ok then
               return;
            end if;
            Rec_Typ := Natural (Hdr (1));
            Rec_Len := Natural (BE16 (Hdr, 4));
            if Rec_Typ /= 23 or Rec_Len > TLS_Max_Record or Rec_Len < 17 then
               return;
            end if;
            T_Recv_Exact (Sock, Payload, Rec_Len, St);
            if St /= T_Recv_Ok then
               Eof := (St = T_Recv_Eof);
               return;
            end if;
            TLS_Decrypt (C, Hdr, Payload, Rec_Len, Inner, Plain, Plen, Ok);
            if not Ok then
               return;
            end if;
            if Inner = 23 then
               --  application data
               C.Plain (1 .. SEO (Plen)) := Plain (1 .. SEO (Plen));
               C.Plain_Len := SEO (Plen);
               C.Plain_Pos := 1;
               if Plen = 0 then
                  C.Plain_Len := 0;
               end if;
            elsif Inner = 21 then
               --  alert
               if Plen >= 2 and then Natural (Plain (2)) = 0 then
                  Eof := True;
                  Ok := True;
               else
                  Ok := False;
               end if;
               return;
            else
               --  post-handshake handshake message: ignore and continue
               null;
            end if;
         end loop;
      exception
         when GNAT.Sockets.Socket_Error =>
            Ok := False;
      end TLS_Read;

      procedure TLS_Write
        (C : in out TLS_Conn; Sock : GNAT.Sockets.Socket_Type;
         Data : Byte_Array; Ok : out Boolean)
      is
         Off : SEO := Data'First;
      begin
         Ok := True;
         if not C.Handshake_Done then
            Ok := False;
            return;
         end if;
         if Data'Length = 0 then
            return;
         end if;
         while Off <= Data'Last loop
            declare
               N : constant SEO := SEO'Min (SEO (TLS_Max_Plain), Data'Last - Off + 1);
            begin
               TLS_Send_Record (C, Sock, 23, Data (Off .. SEO (Off + N - 1)), Ok);
               if not Ok then
                  return;
               end if;
               Off := Off + N;
            end;
         end loop;
      end TLS_Write;

      procedure TLS_Close_Notify
        (C : in out TLS_Conn; Sock : GNAT.Sockets.Socket_Type)
      is
         Alert : Byte_Array (1 .. 2);
         Ok : Boolean;
      begin
         if C.Handshake_Done and then not C.Closed then
            Alert (1) := 1;   --  warning
            Alert (2) := 0;   --  close_notify
            TLS_Send_Record (C, Sock, 21, Alert, Ok);
         end if;
         C.Closed := True;
      exception
         when GNAT.Sockets.Socket_Error =>
            null;
      end TLS_Close_Notify;

   end Crypto;

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
      procedure Start;

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
            pragma Loop_Invariant
              (V >= 0 and then V <= Long_Long_Integer (Max));
            if S (K) in '0' .. '9' then
               Started := True;
               pragma Assert (V <= Long_Long_Integer (Natural'Last));
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
         pragma Assert (V <= Long_Long_Integer (Natural'Last));
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

      --  ---------- TLS termination config ----------

      TLS_Enabled : Boolean := False;
      TLS_Cert_DER : Byte_Array (1 .. Crypto.TLS_Max_Cert) := [others => 0];
      TLS_Cert_Len : SEO := 0;
      TLS_Rsa : Crypto.RSA_Priv;
      TLS_P256 : Crypto.P256_Priv := [others => 0];
      TLS_Is_RSA : Boolean := False;

      function Read_File (Path : String) return String is
         use Ada.Streams.Stream_IO;
         F : File_Type;
         Buf : Ada.Streams.Stream_Element_Array (1 .. 65536) := [others => 0];
         Last : Ada.Streams.Stream_Element_Offset;
         Res : String (1 .. 65536);
         Len : Natural;
      begin
         if Path = "" then
            return "";
         end if;
         Open (F, In_File, Path);
         if Size (F) = 0 or Size (F) > 65536 then
            Close (F);
            return "";
         end if;
         Read (F, Buf, Last);
         Close (F);
         Len := Natural (Last);
         for I in 1 .. Len loop
            Res (I) := Character'Val (Buf (SEO (I)));
         end loop;
         return Res (1 .. Len);
      exception
         when others =>
            return "";
      end Read_File;

      --  abstraction over a client connection: plain TCP or TLS-terminated
      type Client_Link is record
         S      : Socket_Type;
         TLS_On : Boolean := False;
         TLSC   : access Crypto.TLS_Conn := null;
      end record;

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
         Ada.Text_IO.Put_Line
           ("  RC_TLS_CERT=/path/cert.pem   enable TLS termination (PEM cert)");
         Ada.Text_IO.Put_Line
           ("  RC_TLS_KEY=/path/key.pem    TLS private key (RSA or EC P-256)");
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

      procedure Client_Send
        (L : in out Client_Link; Data : Byte_Array; Ok : out Boolean)
      is
      begin
         if L.TLS_On then
            Crypto.TLS_Write (L.TLSC.all, L.S, Data, Ok);
         else
            Send_All (L.S, Data, Ok);
         end if;
      end Client_Send;

      function Load_TLS return Boolean is
         Cert_Pem : constant String := Read_File (Get_Env ("RC_TLS_CERT"));
         Key_Pem  : constant String := Read_File (Get_Env ("RC_TLS_KEY"));
         Der : Byte_Array (1 .. Crypto.TLS_Max_Cert) := [others => 0];
         Der_Len : SEO;
         Is_RSA : Boolean;
      begin
         TLS_Enabled := False;
         if Cert_Pem = "" or Key_Pem = "" then
            return False;
         end if;
         Der_Len := Crypto.Load_PEM_Cert (Cert_Pem, Der);
         if Der_Len = 0 then
            Log ("TLS: cannot parse certificate PEM");
            return False;
         end if;
         Log ("TLS: cert DER len=" & Natural'Image (Natural (Der_Len)));
         if not Crypto.Load_PEM_Key (Key_Pem, TLS_Rsa, TLS_P256, Is_RSA) then
            Log ("TLS: cannot parse private key PEM");
            return False;
         end if;
         Log ("TLS: key loaded is_rsa=" & Boolean'Image (Is_RSA));
         if not Crypto.Cert_Self_Check
           (Der (1 .. Der_Len), TLS_Rsa, TLS_P256, Is_RSA)
         then
            Log ("TLS: private key does not match certificate");
            return False;
         end if;
         TLS_Cert_DER (1 .. Der_Len) := Der (1 .. Der_Len);
         TLS_Cert_Len := Der_Len;
         TLS_Is_RSA := Is_RSA;
         TLS_Enabled := True;
         return True;
      end Load_TLS;

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
         S      : Socket_Type;
         TLS_On : Boolean := False;
         TLSC   : access Crypto.TLS_Conn := null;
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
         Eof : Boolean;
         Ok  : Boolean;
      begin
         St := IO_Ok;
         if R.TLS_On then
            Crypto.TLS_Read (R.TLSC.all, R.S, Buf, Count, Eof, Ok);
            if Ok then
               if Count > 0 then
                  St := IO_Ok;
               else
                  St := (if Eof then IO_Eof else IO_Error);
               end if;
            else
               St := IO_Timeout;
            end if;
            return;
         end if;
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
        (R : in out Reader; To : in out Client_Link; N : Natural; Ok : out Boolean)
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
                  Client_Send (To, Buf (1 .. Count), Ok);
                  if not Ok then
                     return;
                  end if;
                  Remaining := Remaining - Count;
               when IO_Eof =>
                  if Count > 0 then
                     Client_Send (To, Buf (1 .. Count), Ok);
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
        (R : in out Reader; To : in out Client_Link; Ok : out Boolean)
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
                  Client_Send (To, Buf (1 .. Count), Ok);
                  if not Ok then
                     return;
                  end if;
               when IO_Eof =>
                  if Count > 0 then
                     Client_Send (To, Buf (1 .. Count), Ok);
                  end if;
                  return;
               when others =>
                  Ok := False;
                  return;
            end case;
         end loop;
      end Relay_Until_Eof;

      procedure Relay_Chunked
        (R : in out Reader; To : in out Client_Link;
         Max_Total : Natural; Ok : out Boolean)
      is
         Line : Chunk_Line_Buf;
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
            Client_Send (To, Line (1 .. Ln), Ok);
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
               Sz := Http_Parser.Parse_Hex (Line, 1, Sz_Last);
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
                     Client_Send (To, Line (1 .. Ln), Ok);
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
                  Client_Send (To, Buf (1 .. Count), Ok);
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
               Client_Send (To, Crlf, Ok);
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
         Buf : Error_Buffer;
         Len : SEO;
         Ok : Boolean;
      begin
         Errors.Build (Kind, Retry, Buf, Len);
         Send_All (S, Buf (1 .. Len), Ok);
      end Send_Error;

      procedure Send_Error
        (L : in out Client_Link; Kind : Errors.Error_Kind; Retry : Natural)
      is
         Buf : Error_Buffer;
         Len : SEO;
         Ok : Boolean;
      begin
         Errors.Build (Kind, Retry, Buf, Len);
         Client_Send (L, Buf (1 .. Len), Ok);
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
         function Total return Natural;
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

         function Total return Natural is
         begin
            return Total_Count;
         end Total;

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
        (Client : in out Client_Link; R : in out Reader;
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
        (Client    : in out Client_Link;
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
         Backend_Link : Client_Link;
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
         Backend_Link := (S => Backend, TLS_On => False, TLSC => null);
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
                 Http_Parser.Parse_Response (R_Head, 1, R_Len,
                                             Is_Head);
               if not Resp.Valid then
                  Close_Socket (Backend);
                  Send_Error (Client, Errors.E_Bad_Gateway, 0);
                  return;
               end if;
               if Resp.Is_1xx then
                  Client_Send (Client, R_Head (1 .. R_Len), Ok);
                  if not Ok then
                     Close_Socket (Backend);
                     return;
                  end if;
               else
                  --  backend rejected the request before seeing the body
                  Client_Send (Client, R_Head (1 .. R_Len), Ok);
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
               Relay_Chunked (CR, Backend_Link, Cfg.Max_Body, Body_Ok);
            elsif Hdrs.Has_Content_Length then
               Relay_By_Length (CR, Backend_Link, Hdrs.Content_Length, Body_Ok);
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
                 Http_Parser.Parse_Response (R_Head, 1, R_Len,
                                             Is_Head);
               if not Resp.Valid then
                  Send_Error (Client, Errors.E_Bad_Gateway, 0);
                  Close_Socket (Backend);
                  return;
               end if;
               Client_Send (Client, R_Head (1 .. R_Len), Ok);
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
         CR : Reader;
         C_Link : Client_Link := (S => Client, TLS_On => False, TLSC => null);
         TLSC : aliased Crypto.TLS_Conn;
         Requests : Natural := 0;
         Ok : Boolean;

         procedure Run_Loop is
         begin
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
                           Send_Error (C_Link, Errors.E_Timeout, 0);
                        end if;
                        return;
                     when IO_Too_Large =>
                        Send_Error (C_Link, Errors.E_Header_Too_Large, 0);
                        return;
                     when IO_Error =>
                        Send_Error (C_Link, Errors.E_Bad_Request, 0);
                        return;
                     when IO_Ok =>
                        null;
                  end case;
                  H_End :=
                    Http_Parser.Find_Head_End (Head, 1, H_Len);
                  Line :=
                    Http_Parser.Parse_Request_Line (Head, 1, H_End);
                  if not Line.Valid then
                     Send_Error (C_Link, Errors.E_Bad_Request, 0);
                     return;
                  end if;
                  if Line.Method = Http_Parser.M_UNKNOWN then
                     Send_Error (C_Link, Errors.E_Method_Not_Allowed, 0);
                     return;
                  end if;
                  if Line.Version = Http_Parser.V_UNKNOWN then
                     Send_Error (C_Link, Errors.E_Version_Not_Supported, 0);
                     return;
                  end if;
                  if Line.Uri_Last - Line.Uri_Start + 1 > Max_Uri_Size then
                     Send_Error (C_Link, Errors.E_Uri_Too_Long, 0);
                     return;
                  end if;
                  Hdrs :=
                    Http_Parser.Scan_Headers (Head,
                                              Line.Line_End + 1, H_End);
                  if not Hdrs.Valid then
                     Send_Error (C_Link, Errors.E_Bad_Request, 0);
                     return;
                  end if;
                  if Line.Is_1_1 and then not Hdrs.Has_Host then
                     Send_Error (C_Link, Errors.E_Bad_Request, 0);
                     return;
                  end if;
                  if Hdrs.Bad_Transfer_Encoding then
                     Send_Error (C_Link, Errors.E_Not_Implemented, 0);
                     return;
                  end if;
                  if Hdrs.Chunked and then Hdrs.Has_Content_Length then
                     Send_Error (C_Link, Errors.E_Bad_Request, 0);
                     return;
                  end if;
                  if Hdrs.Has_Content_Length
                    and then Hdrs.Content_Length > Cfg.Max_Body
                  then
                     Send_Error (C_Link, Errors.E_Payload_Too_Large, 0);
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
                          (C_Link, Errors.E_Too_Many_Requests,
                           RGuard.Retry_After
                             (Peer, Rate_Limiter.Token_Count (Cfg.Rate)));
                        return;
                     end if;
                  end;
                  Forward_Request
                    (C_Link, Head, H_End, Line, Hdrs, CR, Target, Cfg,
                     Keep_Open);
                  Requests := Requests + 1;
                  if not Keep_Open or else Requests >= Cfg.Max_Reqs then
                     return;
                  end if;
                  Set_Timeout (Client, Cfg.Idle_Timeout);
               end;
            end loop;
         end Run_Loop;

      begin
         Set_Timeout (Client, Cfg.Header_Timeout);
         if TLS_Enabled then
            Crypto.TLS_Init
              (TLSC, TLS_Cert_DER, TLS_Cert_Len, TLS_Rsa, TLS_P256,
               TLS_Is_RSA, Ok);
            if not Ok then
               return;
            end if;
            Crypto.TLS_Server_Handshake (TLSC, Client, Ok);
            if not Ok then
               Crypto.TLS_Close_Notify (TLSC, Client);
               return;
            end if;
            C_Link := (S => Client, TLS_On => True,
                       TLSC => TLSC'Unchecked_Access);
         end if;
         CR := (S => Client, TLS_On => C_Link.TLS_On, TLSC => C_Link.TLSC,
                others => <>);
         Run_Loop;
         if C_Link.TLS_On then
            Crypto.TLS_Close_Notify (C_Link.TLSC.all, Client);
         end if;
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
         --  stop cleanly on SIGINT/SIGTERM
         Graceful_Shutdown.Install;
         --  optional TLS termination (RC_TLS_CERT + RC_TLS_KEY)
         if not Load_TLS then
            TLS_Enabled := False;
         end if;
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
              & "MB"
              & (if TLS_Enabled then "   TLS=on" else ""));
         --  accept loop (polled so SIGINT/SIGTERM can interrupt it)
         loop
            declare
               Client : Socket_Type;
               Addr   : Sock_Addr_Type;
               Peer   : Rate_Limiter.IP_Addr := [others => 0];
               Accepted : Boolean := False;
               Ok : Boolean;
               H : Handler_Acc;
               Status : Selector_Status;
            begin
               Accept_Socket (Listener, Client, Addr, 0.5, Status => Status);
               if Graceful_Shutdown.Requested then
                  exit;
               end if;
               if Status /= Completed then
                  null;   --  timeout: poll again for the shutdown flag
               else
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
               end if;
            exception
               when Socket_Error =>
                  if Graceful_Shutdown.Requested then
                     exit;
                  end if;
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

         --  graceful shutdown: stop listening, drain in-flight connections
         begin
            Close_Socket (Listener);
         exception
            when Socket_Error =>
               null;
         end;
         Log ("shutting down: draining active connections");
         declare
            use Ada.Real_Time;
            Deadline : constant Time := Clock + Milliseconds (10_000);
         begin
            while CGuard.Total > 0 and then Clock < Deadline loop
               delay 0.1;
            end loop;
         end;
         Log ("shutdown complete");
      end Run;

      procedure Start is
      begin
         if Get_Env ("RC_SELF_TEST") = "1" then
            if Crypto.Self_Test then
               Ada.Text_IO.Put_Line ("SELFTEST: ALL PASS");
            else
               Ada.Text_IO.Put_Line ("SELFTEST: FAIL");
            end if;
            return;
         end if;
         if Arg_Count /= 3 then
            Print_Usage;
            return;
         end if;
         declare
            Args : constant Cli.Args_Info :=
              Cli.Parse_Args (Get_Arg (1), Get_Arg (2), Get_Arg (3));
         begin
            if not Args.Ok then
               Print_Usage;
               return;
            end if;
            Run (Args.Listen_Port,
                 Args.Host (1 .. Args.Host_Len),
                 Args.Target_Port,
                 Cli.Load_Config);
         end;
      end Start;

   end IO;

begin
   IO.Start;
end Rideconnect;

