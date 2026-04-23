unit Net.CrossSslSocket.Base;

interface

{$I zLib.inc}

uses
  SysUtils,
  Classes,

  Net.CrossSocket.Base,
  Net.CrossSocket,
  Net.CrossSslSocket.Types,

  Utils.IOUtils;

type
  ICrossSslConnection = interface(ICrossConnection)
  ['{7B7B1DE2-8EDE-4F10-8193-2769D29C59FB}']
    function GetSsl: Boolean;

    /// <summary>
    ///   获取 SSL 详细信息(在连接成功之后调用)
    /// </summary>
    function GetSslInfo(var ASslInfo: TSslInfo): Boolean;

    /// <summary>
    ///   是否已启用 SSL
    /// </summary>
    property Ssl: Boolean read GetSsl;
  end;

  /// <summary>
  ///   SSL Socket
  /// </summary>
  /// <remarks>
  ///   正确的使用步骤:
  ///   <list type="number">
  ///     <item>
  ///       SetCertificateificate 或 SetCertificateificateFile
  ///     </item>
  ///     <item>
  ///       SetPrivateKey 或 SetPrivateKeyFile, 客户端不需要这一步
  ///     </item>
  ///     <item>
  ///       Connect / Listen
  ///     </item>
  ///   </list>
  /// </remarks>
  ICrossSslSocket = interface(ICrossSocket)
  ['{A4765486-A0F1-4EFD-BC39-FA16AED21A6A}']
    function GetSsl: Boolean;

    /// <summary>
    ///   从内存加载证书
    /// </summary>
    /// <param name="ACertBuf">
    ///   证书缓冲区
    /// </param>
    /// <param name="ACertBufSize">
    ///   证书缓冲区大小
    /// </param>
    procedure SetCertificate(const ACertBuf: Pointer; const ACertBufSize: Integer); overload;

    /// <summary>
    ///   从字符串加载证书
    /// </summary>
    /// <param name="ACertStr">
    ///   证书字符串
    /// </param>
    procedure SetCertificate(const ACertStr: string); overload;

    /// <summary>
    ///   从文件加载证书
    /// </summary>
    /// <param name="ACertFile">
    ///   证书文件
    /// </param>
    procedure SetCertificateFile(const ACertFile: string);

    /// <summary>
    ///   从内存加载私钥
    /// </summary>
    /// <param name="APKeyBuf">
    ///   私钥缓冲区
    /// </param>
    /// <param name="APKeyBufSize">
    ///   私钥缓冲区大小
    /// </param>
    procedure SetPrivateKey(const APKeyBuf: Pointer; const APKeyBufSize: Integer); overload;

    /// <summary>
    ///   从字符串加载私钥
    /// </summary>
    /// <param name="APKeyStr">
    ///   私钥字符串
    /// </param>
    procedure SetPrivateKey(const APKeyStr: string); overload;

    /// <summary>
    ///   从文件加载私钥
    /// </summary>
    /// <param name="APKeyFile">
    ///   私钥文件
    /// </param>
    procedure SetPrivateKeyFile(const APKeyFile: string);

    // ── mTLS (mutual TLS / client-certificate authentication) ────────────────
    // [MTLS-1] Load the CA certificate used to verify client certificates.
    //   Call before Listen/Start.  Required when VerifyPeer = True.
    //   The concrete implementation (TCrossOpenSslSocket) calls
    //   SSL_CTX_add_client_CA + X509_STORE_add_cert on its private FContext.

    /// <summary>
    ///   从内存加载CA证书 (mTLS: 客户端证书验证)
    /// </summary>
    procedure SetCACertificate(const ACACertBuf: Pointer;
      const ACACertBufSize: Integer); overload;

    /// <summary>
    ///   从字节数组加载CA证书
    /// </summary>
    procedure SetCACertificate(const ACACertBytes: TBytes); overload;

    /// <summary>
    ///   从字符串加载CA证书
    /// </summary>
    procedure SetCACertificate(const ACACertStr: string); overload;

    /// <summary>
    ///   从文件加载CA证书
    /// </summary>
    procedure SetCACertificateFile(const ACACertFile: string);

    // [MTLS-2] Enable or disable client-certificate verification.
    //   SSL_VERIFY_NONE (False)  = server-only TLS — no client cert required.
    //   SSL_VERIFY_PEER (True)   = server requests client cert.
    //   Combined with SSL_VERIFY_FAIL_IF_NO_PEER_CERT so that a missing or
    //   invalid certificate aborts the handshake rather than continuing.

    /// <summary>
    ///   启用/禁用客户端证书验证 (mTLS)
    /// </summary>
    procedure SetVerifyPeer(const AVerify: Boolean);

    /// <summary>
    ///   是否已启用 SSL
    /// </summary>
    property Ssl: Boolean read GetSsl;
  end;

  TCrossSslListenBase = class(TCrossListen);

  TCrossSslConnectionBase = class(TCrossConnection, ICrossSslConnection)
  protected
    function GetSsl: Boolean;
  public
    function GetSslInfo(var ASslInfo: TSslInfo): Boolean; virtual;

    property Ssl: Boolean read GetSsl;
  end;

  TCrossSslSocketBase = class(TCrossSocket, ICrossSslSocket)
  private
    FSsl: Boolean;
  protected
    function GetSsl: Boolean;
  public
    constructor Create(const AIoThreads: Integer; const ASsl: Boolean); reintroduce; virtual;

    procedure SetCertificate(const ACertBuf: Pointer; const ACertBufSize: Integer); overload; virtual; abstract;
    procedure SetCertificate(const ACertBytes: TBytes); overload; virtual;
    procedure SetCertificate(const ACertStr: string); overload; virtual;
    procedure SetCertificateFile(const ACertFile: string); virtual;

    procedure SetPrivateKey(const APKeyBuf: Pointer; const APKeyBufSize: Integer); overload; virtual; abstract;
    procedure SetPrivateKey(const APKeyBytes: TBytes); overload; virtual;
    procedure SetPrivateKey(const APKeyStr: string); overload; virtual;
    procedure SetPrivateKeyFile(const APKeyFile: string); virtual;

    // ── mTLS ─────────────────────────────────────────────────────────────────
    // [MTLS-1] SetCACertificate — abstract; implemented by TCrossOpenSslSocket.
    //   Calls SSL_CTX_add_client_CA(FContext, LCACert) to add the CA to the
    //   list of acceptable client CAs sent in the TLS handshake, and
    //   X509_STORE_add_cert(SSL_CTX_get_cert_store(FContext), LCACert) so
    //   OpenSSL can verify the client certificate against the CA chain.
    procedure SetCACertificate(const ACACertBuf: Pointer;
      const ACACertBufSize: Integer); overload; virtual; abstract;
    procedure SetCACertificate(const ACACertBytes: TBytes); overload; virtual;
    procedure SetCACertificate(const ACACertStr: string); overload; virtual;
    procedure SetCACertificateFile(const ACACertFile: string); virtual;

    // [MTLS-2] SetVerifyPeer — abstract; implemented by TCrossOpenSslSocket.
    //   AVerify = True  → SSL_CTX_set_verify(FContext,
    //                        SSL_VERIFY_PEER or SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nil)
    //   AVerify = False → SSL_CTX_set_verify(FContext, SSL_VERIFY_NONE, nil)
    procedure SetVerifyPeer(const AVerify: Boolean); virtual; abstract;

    property Ssl: Boolean read GetSsl;
  end;

implementation

{ TCrossSslSocketBase }

constructor TCrossSslSocketBase.Create(const AIoThreads: Integer;
  const ASsl: Boolean);
begin
  inherited Create(AIoThreads);

  FSsl := ASsl;
end;

function TCrossSslSocketBase.GetSsl: Boolean;
begin
  Result := FSsl;
end;

procedure TCrossSslSocketBase.SetCertificate(const ACertBytes: TBytes);
begin
  SetCertificate(Pointer(ACertBytes), Length(ACertBytes));
end;

procedure TCrossSslSocketBase.SetCertificate(const ACertStr: string);
begin
  SetCertificate(TEncoding.ANSI.GetBytes(ACertStr));
end;

procedure TCrossSslSocketBase.SetCertificateFile(const ACertFile: string);
begin
  SetCertificate(TFileUtils.ReadAllBytes(ACertFile));
end;

procedure TCrossSslSocketBase.SetPrivateKey(const APKeyBytes: TBytes);
begin
  SetPrivateKey(Pointer(APKeyBytes), Length(APKeyBytes));
end;

procedure TCrossSslSocketBase.SetPrivateKey(const APKeyStr: string);
begin
  SetPrivateKey(TEncoding.ANSI.GetBytes(APKeyStr));
end;

procedure TCrossSslSocketBase.SetPrivateKeyFile(const APKeyFile: string);
begin
  SetPrivateKey(TFileUtils.ReadAllBytes(APKeyFile));
end;

// ── mTLS convenience overloads ────────────────────────────────────────────────
// These follow the same pattern as SetCertificate/SetPrivateKey:
// convert to bytes/pointer and delegate to the abstract primitive.

procedure TCrossSslSocketBase.SetCACertificate(const ACACertBytes: TBytes);
begin
  SetCACertificate(Pointer(ACACertBytes), Length(ACACertBytes));
end;

procedure TCrossSslSocketBase.SetCACertificate(const ACACertStr: string);
begin
  SetCACertificate(TEncoding.ANSI.GetBytes(ACACertStr));
end;

procedure TCrossSslSocketBase.SetCACertificateFile(const ACACertFile: string);
begin
  SetCACertificate(TFileUtils.ReadAllBytes(ACACertFile));
end;

{ TCrossSslConnectionBase }

function TCrossSslConnectionBase.GetSsl: Boolean;
begin
  Result := TCrossSslSocketBase(Owner).Ssl;
end;

function TCrossSslConnectionBase.GetSslInfo(var ASslInfo: TSslInfo): Boolean;
begin
  Result := False;
end;

end.
