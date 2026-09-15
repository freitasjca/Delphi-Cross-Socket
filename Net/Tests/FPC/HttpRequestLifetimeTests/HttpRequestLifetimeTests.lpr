program HttpRequestLifetimeTests;

{$I ..\..\..\..\zLib.inc}

uses
  SysUtils, Classes
  {$IFDEF FPC}
  ,DTF.RTL in '..\..\..\..\DelphiToFPC\DTF.RTL.pas'
  {$ENDIF}
  ,Utils.SyncObjs in '..\..\..\..\Utils\Utils.SyncObjs.pas'
  ,Net.SocketAPI in '..\..\..\Net.SocketAPI.pas'
  ,Net.CrossSocket.Base in '..\..\..\Net.CrossSocket.Base.pas'
  ,Net.CrossSocket.Iocp in '..\..\..\Net.CrossSocket.Iocp.pas'
  ,Net.CrossSocket in '..\..\..\Net.CrossSocket.pas'
  ,Net.CrossSslSocket.Base in '..\..\..\Net.CrossSslSocket.Base.pas'
  ,Net.CrossSslSocket.OpenSSL in '..\..\..\Net.CrossSslSocket.OpenSSL.pas'
  ,Net.CrossSslSocket in '..\..\..\Net.CrossSslSocket.pas'
  ,Net.CrossServer in '..\..\..\Net.CrossServer.pas'
  ,Net.CrossHttpUtils in '..\..\..\Net.CrossHttpUtils.pas'
  ,Net.CrossHttpParams in '..\..\..\Net.CrossHttpParams.pas'
  ,Net.CrossHttpParser in '..\..\..\Net.CrossHttpParser.pas'
  ,Net.CrossHttpServer in '..\..\..\Net.CrossHttpServer.pas'
  ,Net.CrossWebSocketParser in '..\..\..\Net.CrossWebSocketParser.pas'
  ,Net.CrossWebSocketServer in '..\..\..\Net.CrossWebSocketServer.pas'
  ;

type
  TTestProc = procedure;

  TTestConnection = class(TCrossWebSocketConnection)
  private
    FClosedForTest: Boolean;
  protected
    procedure DirectSend(const ABuffer: Pointer; const ACount: Integer;
      const ACallback: TCrossConnectionCallback = nil); override;
  public
    SentData: AnsiString;
    procedure Feed(const AData: AnsiString);
    procedure CloseForTest;
    destructor Destroy; override;
  end;

  TTestServer = class(TCrossWebSocketServer)
  protected
    procedure DoOnRequestBegin(const AConnection: ICrossHttpConnection;
      const ARequest: ICrossHttpRequest; const AResponse: ICrossHttpResponse); override;
    procedure DoOnRequest(const AConnection: ICrossHttpConnection;
      const ARequest: ICrossHttpRequest; const AResponse: ICrossHttpResponse); override;
  end;

  TRequestReader = class(TThread)
  private
    FConnection: ICrossHttpConnection;
    FReads: Integer;
  protected
    procedure Execute; override;
  public
    ErrorText: string;
    constructor Create(const AConnection: ICrossHttpConnection);
    function ReadCount: Integer;
  end;

var
  DestroyedConnections: Integer;
  FailedTests: Integer;

procedure Check(const AValue: Boolean; const AMessage: string);
begin
  if not AValue then
    raise Exception.Create(AMessage);
end;

procedure TTestConnection.DirectSend(const ABuffer: Pointer;
  const ACount: Integer; const ACallback: TCrossConnectionCallback);
var
  LData: AnsiString;
begin
  // 仅替代网络写入；仍运行真实 HTTP 解析、响应队列及 WebSocket 升级逻辑。
  SetString(LData, PAnsiChar(ABuffer), ACount);
  SentData := SentData + LData;
  if Assigned(ACallback) then
    ACallback(Self, True);
end;

procedure TTestConnection.Feed(const AData: AnsiString);
var
  LBuffer: Pointer;
  LLength, LBefore: Integer;
begin
  LBuffer := PAnsiChar(AData);
  LLength := Length(AData);
  _LockRecv;
  try
    while LLength > 0 do
    begin
      LBefore := LLength;
      ParseRecvData(LBuffer, LLength);
      Check(LLength < LBefore, '解析器未消费输入');
    end;
  finally
    _UnlockRecv;
  end;
end;

procedure TTestConnection.CloseForTest;
begin
  if FClosedForTest then Exit;
  FClosedForTest := True;
  // 测试连接使用 INVALID_SOCKET，不加入服务器连接表。
  // 显式进入真实关闭清理，避免公开 Close 的无 socket 分支跳过清理。
  ConnectStatus := csClosed;
  InternalClose;
end;

destructor TTestConnection.Destroy;
begin
  inherited;
  Inc(DestroyedConnections);
end;

procedure TTestServer.DoOnRequestBegin(const AConnection: ICrossHttpConnection;
  const ARequest: ICrossHttpRequest; const AResponse: ICrossHttpResponse);
begin
  Check(AConnection.Request = ARequest, 'Begin 事件之前尚未发布完整请求');
  Check(AResponse.Request = ARequest, '响应绑定到了错误请求');
  inherited;
end;

procedure TTestServer.DoOnRequest(const AConnection: ICrossHttpConnection;
  const ARequest: ICrossHttpRequest; const AResponse: ICrossHttpResponse);
begin
  if ARequest.Header['Upgrade'] = 'websocket' then
    inherited
  else
    AResponse.Send('ok');
end;

constructor TRequestReader.Create(const AConnection: ICrossHttpConnection);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FConnection := AConnection;
end;

function TRequestReader.ReadCount: Integer;
begin
  Result := AtomicCmpExchange(FReads, 0, 0);
end;

procedure TRequestReader.Execute;
var
  LRequest: ICrossHttpRequest;
begin
  try
    while not Terminated do
    begin
      LRequest := FConnection.Request;
      Check(LRequest <> nil, '并发读取丢失最后完整请求');
      Check(LRequest.Path = '/' + LRequest.Header['X-Id'],
        '读取到了半个请求或不一致字段');
      AtomicIncrement(FReads);
    end;
  except
    on E: Exception do
      ErrorText := E.ClassName + ': ' + E.Message;
  end;
end;

procedure OpenTest(out AServer: ICrossHttpServer;
  out AConnection: ICrossHttpConnection; out AObject: TTestConnection);
var
  LServer: TTestServer;
begin
  LServer := TTestServer.Create(1, False);
  AServer := LServer;
  AObject := TTestConnection.Create(LServer, INVALID_SOCKET, ctAccept, '', nil);
  AConnection := AObject;
  AObject.ConnectStatus := csConnected;
end;

function RequestText(const APath: AnsiString): AnsiString;
begin
  Result := 'GET ' + APath + ' HTTP/1.1'#13#10 +
    'Host: localhost'#13#10#13#10;
end;

procedure TestFirstRequest;
var
  LServer: ICrossHttpServer;
  LConnection: ICrossHttpConnection;
  LObject: TTestConnection;
begin
  OpenTest(LServer, LConnection, LObject);
  try
    Check(LConnection.Request = nil, '新连接不应具有完整请求');
    LObject.Feed('GET /first HTTP/1.1'#13#10'Host: localhost'#13#10);
    Check(LConnection.Request = nil, '未完成的首个请求被提前发布');
    LObject.Feed(#13#10);
    Check(LConnection.Request.Path = '/first', '首个完整请求未发布');
  finally
    LObject.CloseForTest;
  end;
end;

procedure TestNextRequestAndBody;
var
  LServer: ICrossHttpServer;
  LConnection: ICrossHttpConnection;
  LObject: TTestConnection;
  LFirst, LSecond: ICrossHttpRequest;
  LBody: AnsiString;
begin
  OpenTest(LServer, LConnection, LObject);
  try
    LObject.Feed(RequestText('/first?key=value'));
    LFirst := LConnection.Request;
    LObject.Feed('POST /second HTTP/1.1'#13#10'Host: localhost'#13#10 +
      'Content-Type: application/octet-stream'#13#10 +
      'Content-Length: 4'#13#10#13#10'ab');
    Check(LConnection.Request = LFirst, '接收下一请求 Body 时替换了完整请求');
    LObject.Feed('cd');
    LSecond := LConnection.Request;
    Check(LSecond <> LFirst, '完整请求未切换对象');
    Check(LSecond.Path = '/second', '完整请求路径错误');
    Check(LFirst.Path = '/first', '旧请求数据被覆盖');
    Check(LFirst.Query['key'] = 'value', '旧请求参数被覆盖');
    LFirst := nil;
    LObject.CloseForTest;
    Check(LConnection.Request = LSecond, '关闭时丢失最后完整请求');
    Check(LSecond.Connection = nil, '关闭后仍保留反向连接引用');
    LConnection := nil;
    SetLength(LBody, 4);
    LSecond.RawBody.Position := 0;
    LSecond.RawBody.ReadBuffer(LBody[1], 4);
    Check(LBody = 'abcd', '连接释放后 Body 不可读');
  finally
    // LConnection=nil 后 LObject 已可能释放。
    if LConnection <> nil then LObject.CloseForTest;
  end;
end;

procedure TestCloseDuringNextRequest;
var
  LServer: ICrossHttpServer;
  LConnection: ICrossHttpConnection;
  LObject: TTestConnection;
  LRequest: ICrossHttpRequest;
  LBefore: Integer;
begin
  LBefore := DestroyedConnections;
  OpenTest(LServer, LConnection, LObject);
  try
    LObject.Feed(RequestText('/complete'));
    LRequest := LConnection.Request;
    LObject.Feed('POST /partial HTTP/1.1'#13#10'Host: localhost'#13#10 +
      'Content-Length: 5'#13#10#13#10'x');
    LObject.CloseForTest;
    Check(LConnection.Request = LRequest, '关闭时用半个请求替换了完整请求');
    Check(LRequest.Connection = nil, '未解除上一完整请求的反向引用');
    LConnection := nil;
    Check(DestroyedConnections = LBefore + 1, '连接存在循环引用，未析构');
    Check(LRequest.Path = '/complete', '连接析构后请求不可读');
  finally
    if LConnection <> nil then LObject.CloseForTest;
  end;
end;

procedure TestPipeline;
var
  LServer: ICrossHttpServer;
  LConnection: ICrossHttpConnection;
  LObject: TTestConnection;
begin
  OpenTest(LServer, LConnection, LObject);
  try
    LObject.Feed(RequestText('/one') + RequestText('/two'));
    Check(LConnection.Request.Path = '/two', '流水线最后请求错误');
    Check(LConnection.Pending = 0, '响应队列未完成');
  finally
    LObject.CloseForTest;
  end;
end;

procedure TestWebSocket;
var
  LServer: ICrossHttpServer;
  LConnection: ICrossHttpConnection;
  LObject: TTestConnection;
  LHandshake: ICrossHttpRequest;
  LBefore: Integer;
begin
  LBefore := DestroyedConnections;
  OpenTest(LServer, LConnection, LObject);
  try
    LObject.Feed('GET /ws?room=demo HTTP/1.1'#13#10 +
      'Host: localhost'#13#10'Upgrade: websocket'#13#10 +
      'Connection: Upgrade'#13#10 +
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=='#13#10 +
      'Sec-WebSocket-Version: 13'#13#10#13#10);
    Check(LObject.IsWebSocket, '没有进入 WebSocket 模式');
    Check(Pos(AnsiString('101 Switching Protocols'), LObject.SentData) > 0, '未完成握手响应');
    LHandshake := LConnection.Request;
    Check(LHandshake.Path = '/ws', '握手请求路径错误');
    // 客户端掩码 PING 帧，空负载。
    LObject.Feed(AnsiString(#$89#$80#$01#$02#$03#$04));
    Check(LConnection.Request = LHandshake, 'WebSocket 帧替换了握手请求');
    LObject.CloseForTest;
    Check(LConnection.Request = LHandshake, 'WebSocket 关闭后丢失握手请求');
    Check(LHandshake.Connection = nil, '握手请求的连接引用未解除');
    LConnection := nil;
    Check(DestroyedConnections = LBefore + 1, 'WebSocket 连接存在循环引用');
    Check(LHandshake.Query['room'] = 'demo', '连接析构后握手参数不可读');
  finally
    if LConnection <> nil then LObject.CloseForTest;
  end;
end;

procedure WaitForReads(const AReader: TRequestReader; const ATarget: Integer);
var
  I: Integer;
begin
  for I := 1 to 5000 do
  begin
    if AReader.ReadCount >= ATarget then Exit;
    TThread.Sleep(1);
  end;
  raise Exception.Create('并发读取未在限定时间内完成');
end;

procedure TestConcurrentRead;
var
  LServer: ICrossHttpServer;
  LConnection: ICrossHttpConnection;
  LObject: TTestConnection;
  LReader: TRequestReader;
  I, LTarget: Integer;
  LId: AnsiString;
begin
  OpenTest(LServer, LConnection, LObject);
  LReader := nil;
  try
    LObject.Feed('GET /0 HTTP/1.1'#13#10 +
      'Host: localhost'#13#10'X-Id: 0'#13#10#13#10);
    LReader := TRequestReader.Create(LConnection);
    LReader.Start;
    WaitForReads(LReader, 100);
    for I := 1 to 1000 do
    begin
      LId := AnsiString(IntToStr(I));
      LObject.Feed('GET /' + LId + ' HTTP/1.1'#13#10 +
        'Host: localhost'#13#10'X-Id: ' + LId + #13#10);
      // 给读取线程观察半个请求的机会。
      if I mod 10 = 0 then TThread.Sleep(1);
      LObject.Feed(#13#10);
    end;
    LObject.CloseForTest;
    LTarget := LReader.ReadCount + 100;
    WaitForReads(LReader, LTarget);
  finally
    if LReader <> nil then
    begin
      LReader.Terminate;
      LReader.WaitFor;
      try
        Check(LReader.ErrorText = '', LReader.ErrorText);
      finally
        LReader.Free;
        LObject.CloseForTest;
      end;
    end else
      LObject.CloseForTest;
  end;
end;

procedure RunTest(const AName: string; const ATest: TTestProc);
begin
  try
    ATest();
    Writeln('PASS: ', AName);
  except
    on E: Exception do
    begin
      Inc(FailedTests);
      Writeln('FAIL: ', AName, ': ', E.ClassName, ': ', E.Message);
    end;
  end;
end;

begin
  SetTextCodePage(Output, 65001);
  RunTest('首次完整请求', TestFirstRequest);
  RunTest('下一请求 Body 与旧接口保活', TestNextRequestAndBody);
  RunTest('下一请求未完成时关闭及循环引用释放', TestCloseDuringNextRequest);
  RunTest('HTTP pipelining', TestPipeline);
  RunTest('WebSocket 握手请求保留', TestWebSocket);
  RunTest('并发读取、发布与关闭', TestConcurrentRead);
  if FailedTests <> 0 then Halt(1);
  Writeln('HttpRequestLifetimeTests: PASS (6/6)');
end.
