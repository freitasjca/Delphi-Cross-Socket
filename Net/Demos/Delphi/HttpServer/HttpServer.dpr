program HttpServer;

{$APPTYPE CONSOLE}

{$I zLib.inc}

uses
  SysUtils,
  Classes,
  Net.CrossSocket.Base in '..\..\..\Net.CrossSocket.Base.pas',
  Net.CrossHttpServer in '..\..\..\Net.CrossHttpServer.pas',
  Net.CrossHttpParams in '..\..\..\Net.CrossHttpParams.pas',
  Net.OpenSSL in '..\..\..\Net.OpenSSL.pas',
  Utils.Utils in '..\..\..\..\Utils\Utils.Utils.pas',
  Utils.Hash in '..\..\..\..\Utils\Utils.Hash.pas',
  DTF.Hash in '..\..\..\..\DelphiToFPC\DTF.Hash.pas',
  CnAES in '..\..\..\..\CnPack\Crypto\CnAES.pas',
  CnBase64 in '..\..\..\..\CnPack\Crypto\CnBase64.pas',
  CnConsts in '..\..\..\..\CnPack\Crypto\CnConsts.pas',
  CnDES in '..\..\..\..\CnPack\Crypto\CnDES.pas',
  CnFloat in '..\..\..\..\CnPack\Crypto\CnFloat.pas',
  CnKDF in '..\..\..\..\CnPack\Crypto\CnKDF.pas',
  CnMD5 in '..\..\..\..\CnPack\Crypto\CnMD5.pas',
  CnNative in '..\..\..\..\CnPack\Crypto\CnNative.pas',
  CnPemUtils in '..\..\..\..\CnPack\Crypto\CnPemUtils.pas',
  CnRandom in '..\..\..\..\CnPack\Crypto\CnRandom.pas',
  CnSHA1 in '..\..\..\..\CnPack\Crypto\CnSHA1.pas',
  CnSHA2 in '..\..\..\..\CnPack\Crypto\CnSHA2.pas',
  CnSHA3 in '..\..\..\..\CnPack\Crypto\CnSHA3.pas',
  CnSM3 in '..\..\..\..\CnPack\Crypto\CnSM3.pas',
  Net.CrossHttpParser in '..\..\..\Net.CrossHttpParser.pas',
  Net.CrossHttpRouter in '..\..\..\Net.CrossHttpRouter.pas',
  Net.CrossHttpRouterDirUtils in '..\..\..\Net.CrossHttpRouterDirUtils.pas',
  Utils.AnonymousThread in '..\..\..\..\Utils\Utils.AnonymousThread.pas',
  Utils.ArrayUtils in '..\..\..\..\Utils\Utils.ArrayUtils.pas',
  Utils.DateTime in '..\..\..\..\Utils\Utils.DateTime.pas';

var
  __HttpServer: ICrossHttpServer;

procedure TestCrossHttpServer;
var
  LResponseStr: string;
begin
  LResponseStr := TOSVersion.ToString + '<br>Hello World!';

  //__HttpServer := TCrossHttpServer.Create(0, True);
  __HttpServer := TCrossHttpServer.Create(0, False);
  if __HttpServer.Ssl then
  begin
    __HttpServer.SetCertificateFile('server.crt');
    __HttpServer.SetPrivateKeyFile('server.key');
  end;

  __HttpServer.Port := 9010;
  __HttpServer.Start(
      procedure(const AListen: ICrossListen; const ASuccess: Boolean)
      begin
        if ASuccess then
        begin
          if __HttpServer.Ssl then
            Writeln('HTTP server(ssl: ' + TSSLTools.LibSSL + ' & ' + TSSLTools.LibCRYPTO + ') listen on [', AListen.LocalAddr, ':' , AListen.LocalPort, ']')
          else
            Writeln('HTTP server listen on [', AListen.LocalAddr, ':' , AListen.LocalPort, ']');
        end;
      end);

  __HttpServer.Get('/',
    procedure(const ARequest: ICrossHttpRequest; const AResponse: ICrossHttpResponse; var AHandled: Boolean)
    begin
      AResponse.Send(LResponseStr);
      AHandled := True;
    end);

  __HttpServer.Get('/ping',
    procedure(const ARequest: ICrossHttpRequest; const AResponse: ICrossHttpResponse; var AHandled: Boolean)
    begin
      AResponse.Send('pong');
      AHandled := True;
    end);

  __HttpServer.Post('/upload',
    procedure(const ARequest: ICrossHttpRequest; const AResponse: ICrossHttpResponse; var AHandled: Boolean)
    var
      LHashStr: string;
      LFormField: TFormField;
    begin
      LHashStr := '';
      if (ARequest.BodyType = btMultiPart) then
      begin
        for LFormField in (ARequest.Body as THttpMultiPartFormData) do
        begin
          if (LFormField.ContentType <> '') then
          begin
            if (LHashStr <> '') then
              LHashStr := LHashStr + sLineBreak;

            LHashStr := LHashStr + 'FileName: ' + LFormField.FileName + sLineBreak;
            LHashStr := LHashStr + 'MD5: ' + THashMD5.GetHashStringFromStream(LFormField.Value) + sLineBreak;
            LHashStr := LHashStr + 'SHA1: ' + THashSHA1.GetHashStringFromStream(LFormField.Value) + sLineBreak;
          end;
        end;
      end;

      AResponse.Send(LHashStr);
      AHandled := True;
    end);
end;

begin
  // 如果 openssl 运行库名称与默认名称不一致, 请自行用以下代码修改
  // TSSLTools.LibSSL := 'libssl.so';
  // TSSLTools.LibCRYPTO := 'libcrypto.so';

  TestCrossHttpServer;
  Readln;
end.

