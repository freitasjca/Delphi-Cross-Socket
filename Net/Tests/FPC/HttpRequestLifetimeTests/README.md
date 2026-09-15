# 最近完整请求生命周期测试

验证 `Connection.Request` 在 HTTP 与 WebSocket 连接上的保留语义。测试工程显式绑定仓库中的 HTTP/WebSocket 单元；编译方式沿用相邻的 `TlsCipherSuitesTests`，不修改全局 FPC/Lazarus 配置。

## 测试边界

运行真实 HTTP 解析、响应队列及 WebSocket 握手/帧处理逻辑。仅将 `DirectSend` 替换为同步成功的内存发送器；测试连接使用 `INVALID_SOCKET`，显式调用真实 `InternalClose` 清理。因此这是组件回归测试，不是真实网络集成测试。

六个用例覆盖：

1. 新连接及首个半请求返回 `nil`，完整解析后发布，Begin 事件能取得本次请求。
2. 下一请求 Body 未完成时继续返回旧请求，完成后替换；旧请求路径和 Query 保持不变，最后请求 Body 在连接释放后可读。
3. A 已完成、B 未完成时关闭，保留 A，解除 A/B 对连接的引用；通过析构计数验证连接能够释放。
4. 同一批数据中的两个 HTTP 请求按序解析，最后返回第二个请求，响应队列正常完成。
5. WebSocket 升级返回 101，PING 帧不替换握手请求；关闭及连接释放后仍能读取握手参数。
6. 一个线程反复读取完整请求，另一个线程发布 1000 次请求，随后关闭连接。验证读取与发布、读取与关闭并发时接口有效、路径与请求头一致。

第 6 项没有让解析与关闭彼此并发；不覆盖现有解析器/关闭流程的全部竞态，也不保证业务对 Header、Params、Session 或 Body 的并发修改安全。

## 构建与运行

在本目录运行，工具路径按本机安装位置替换。现有依赖（包括 cncrypto）通过本机已有搜索路径提供，测试不安装或修改依赖。

```powershell
& 'D:\Design\FreePascal\lazarus\lazbuild.exe' --build-all --skip-dependencies HttpRequestLifetimeTests.lpi
& '.\bin\x86_64-win64\HttpRequestLifetimeTests.exe'

New-Item -ItemType Directory -Force -Path bin\delphi-win64,lib\delphi-win64 | Out-Null
& 'D:\Design\Delphi\D13.1\bin\dcc64.exe' -Q -B `
  '-NSSystem;System.Win;Winapi' `
  '-U..\..\..;..\..\..\..\Utils;D:\Design\Delphi\D13.1\lib\win64\release' `
  '-I..\..\..\..;..\..\..' '-Ebin\delphi-win64' '-N0lib\delphi-win64' `
  HttpRequestLifetimeTests.dpr
& '.\bin\delphi-win64\HttpRequestLifetimeTests.exe'
```

通过时输出 `HttpRequestLifetimeTests: PASS (6/6)`，失败返回退出码 1。构建输出位于忽略的 `bin/`、`lib/`。

## 本轮结果（2026-09-12）

- 修改前 Delphi 测试复现 5 项失败，只有 HTTP pipelining 用例通过。
- 修改后 Delphi 13.1 Win64、FPC 3.3.1 Win64 均编译通过，测试各 6/6 通过。
- Delphi WebSocketServer 示例 Release/Win64 正式工程构建通过。
- Delphi HttpServer 示例构建停在未修改的 `HttpServer.dpr:71-72`：`GetHashString` 实参不匹配（E2250）。
- FPC HttpServer、WebSocketServer 示例的 Windows-X64 构建均停在第 9 行：缺少 `LazUTF8` 搜索路径。本测试工程自身包含 lazutils 搜索路径且构建通过；没有修改示例或全局配置。
- 未进行真实网络、TLS、非 Windows 平台或完整解析/关闭并发验证。
- Pascal 源文件保留 UTF-8 BOM；工作区检查使用 `git -c core.whitespace=cr-at-eol diff --check`，适配仓库已有 CRLF。
