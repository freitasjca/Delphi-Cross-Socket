program CnPackHashTests;

{$I zLib.inc}

{$IFNDEF FPC}
  {$APPTYPE CONSOLE}
{$ENDIF}

(*
  CnPackHashTests - incremental hashing through Utils.Hash and the vendored
  CnPack subset (fork-only; upstream does not vendor CnPack).

  Why it exists: CnSHA2's SHA512Update (also used by SHA-384) copied the bytes
  left over after a processed block to Data[DataLen] using the OLD DataLen,
  instead of Data[0]. A digest is therefore wrong whenever one Update leaves a
  partial block and the next Update completes that block and leaves a
  remainder - 10 + 290 bytes, for example. With 100 + 100 + 100 the copy also
  ran past the end of the 128-byte block buffer. Fixed upstream in cnvcl
  0d2ce92 (2026-10-05). One-shot hashing and block-aligned updates were never
  affected, which is why nothing in the library noticed: Utils.Hash's stream
  helpers read in 32 KiB chunks.

  Every algorithm DCS takes from CnPack (MD5, SHA-1, SHA-256, SHA-384,
  SHA-512) hashes the same 300-byte message under seven split patterns and
  must match the digest Python's hashlib computed for the whole message. MD5,
  SHA-1 and SHA-256 are the controls; they share no code with the defect. On
  the subset vendored before fork v1.0.17, SHA-384 and SHA-512 FAIL the three
  splits marked [*] below - 6 failures in all; afterwards everything passes.

  Exit code: the number of failed checks; 0 = all passed.
*)

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  SysUtils,
  Utils.Hash;

const
  MSG_LEN = 300;

  // Python: M = bytes(i % 256 for i in range(300)); hashlib.<alg>(M).hexdigest()
  HEX_MD5    = '17b3839204f7b81a93eb2718b1379e6f';
  HEX_SHA1   = 'bf77ecf143ceb21f1676c34b8d89c8bb3c43cc4e';
  HEX_SHA256 = '7728ae2f2c36e2aaafbe79ca14c87ae2f89e7c88c4390ecbbf82dce88706958d';
  HEX_SHA384 = '69672aca50c4279e4cdf788380294d7655bc68c7949e273318d60817f3262cff' +
               '54e8c78ceaae0853e0a7adf36f392d38';
  HEX_SHA512 = 'f1dca2eb677b303265b0b9baff0e061202818f35c1470a69bbaa9bb66025e948' +
               'd90e565e69642506c6213aef3cf9e929357a59da263deb34d1236dbdcda279b3';

  // FIPS 180-2 test vectors for "abc" - checks the reference itself.
  HEX_ABC_SHA384 = 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed' +
                   '8086072ba1e7cc2358baeca134c825a7';
  HEX_ABC_SHA512 = 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
                   '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f';

  SPLIT_COUNT = 7;
  // Piece sizes, 0-terminated; each row sums to MSG_LEN.
  SPLITS: array[0..SPLIT_COUNT - 1, 0..3] of Integer = (
    (300,   0,   0, 0),   // one-shot (control)
    ( 10, 290,   0, 0),   // [*] partial block, then completes it with a remainder
    (100, 100, 100, 0),   // [*] the remainder also overran the 128-byte buffer
    (129, 171,   0, 0),   // [*] partial after one block, then a remainder again
    ( 64,  64, 172, 0),   // completes a block exactly - nothing left over
    (127,   1, 172, 0),   // completes a block exactly - nothing left over
    (  1, 127, 172, 0));  // completes a block exactly - nothing left over

var
  GMsg: TBytes;
  GFailed: Integer = 0;
  GPassed: Integer = 0;

function ToHex(const ABytes: TBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Length(ABytes) - 1 do
    Result := Result + IntToHex(ABytes[I], 2);
end;

procedure Check(const ACondition: Boolean; const ALabel, ADetail: string);
begin
  if ACondition then
  begin
    Inc(GPassed);
    Writeln('  PASS  ', ALabel);
  end
  else
  begin
    Inc(GFailed);
    Writeln('  FAIL  ', ALabel, '  ', ADetail);
  end;
end;

function SplitLabel(const ARow: Integer): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to 3 do
  begin
    if SPLITS[ARow, I] = 0 then
      Break;
    if Result <> '' then
      Result := Result + '+';
    Result := Result + IntToStr(SPLITS[ARow, I]);
  end;
end;

function HashInPieces(const AClass: THashClass; const ARow: Integer): string;
var
  LHash: THashBase;
  LOffset, I: Integer;
begin
  LHash := AClass.Create;   // THashBase.Create calls Start
  try
    LOffset := 0;
    for I := 0 to 3 do
    begin
      if SPLITS[ARow, I] = 0 then
        Break;
      LHash.Update(@GMsg[LOffset], SPLITS[ARow, I]);
      Inc(LOffset, SPLITS[ARow, I]);
    end;
    Result := ToHex(LHash.Finish);
  finally
    LHash.Free;
  end;
end;

function HashOf(const AClass: THashClass; const AData: TBytes): string;
var
  LHash: THashBase;
begin
  LHash := AClass.Create;
  try
    if Length(AData) > 0 then
      LHash.Update(@AData[0], Length(AData));
    Result := ToHex(LHash.Finish);
  finally
    LHash.Free;
  end;
end;

procedure TestAlgorithm(const AName: string; const AClass: THashClass;
  const AExpected: string);
var
  LRow: Integer;
  LGot: string;
begin
  Writeln('[', AName, ']');
  for LRow := 0 to SPLIT_COUNT - 1 do
  begin
    LGot := HashInPieces(AClass, LRow);
    Check(SameText(LGot, AExpected),
      Format('%s  %s', [AName, SplitLabel(LRow)]),
      Format('got %s', [LowerCase(LGot)]));
  end;
end;

procedure TestReferenceVectors;
var
  LAbc: TBytes;
begin
  Writeln('[reference vectors, "abc"]');
  SetLength(LAbc, 3);
  LAbc[0] := Ord('a');
  LAbc[1] := Ord('b');
  LAbc[2] := Ord('c');
  Check(SameText(HashOf(THashSHA384, LAbc), HEX_ABC_SHA384),
    'SHA-384("abc") = FIPS 180-2', '');
  Check(SameText(HashOf(THashSHA512, LAbc), HEX_ABC_SHA512),
    'SHA-512("abc") = FIPS 180-2', '');
end;

var
  I: Integer;
begin
  try
    SetLength(GMsg, MSG_LEN);
    for I := 0 to MSG_LEN - 1 do
      GMsg[I] := Byte(I mod 256);

    Writeln('CnPack hashing through Utils.Hash - 300-byte message, 7 split patterns');
    Writeln;
    TestReferenceVectors;
    TestAlgorithm('MD5',     THashMD5,    HEX_MD5);
    TestAlgorithm('SHA-1',   THashSHA1,   HEX_SHA1);
    TestAlgorithm('SHA-256', THashSHA256, HEX_SHA256);
    TestAlgorithm('SHA-384', THashSHA384, HEX_SHA384);
    TestAlgorithm('SHA-512', THashSHA512, HEX_SHA512);

    Writeln;
    Writeln(Format('Results: %d passed, %d failed', [GPassed, GFailed]));
  except
    on E: Exception do
    begin
      Writeln('FATAL ', E.ClassName, ': ', E.Message);
      Inc(GFailed);
    end;
  end;
  ExitCode := GFailed;
end.
