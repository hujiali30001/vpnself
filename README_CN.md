# Furun VPN —— 智能路由 VPN

浏览器 HTTP/HTTPS 流量通过加密 TLS 隧道转发到日本 VPS。
DNS 在服务端解析，自动区分国内直连和境外代理。

## 架构

```
浏览器 --HTTP--> 本地代理 (127.0.0.1:1080) --TLS连接池(N条)--> 日本VPS --TCP--> 目标网站
```

## 快速开始

### 服务端部署（日本 Windows Server）

1. 将 `FurunVPNServer_Console.exe` 和 `server_config.json` 上传到 VPS
2. 首次运行自动生成自签名 TLS 证书（有效期 10 年）
3. 监听 `0.0.0.0:8443`，确保防火墙放行该端口

### 客户端安装

1. 下载 `FurunVPN.exe`，无需安装，解压即用
2. 首次运行自动创建 `client_config.json`
3. 填写服务器 IP、端口、密钥，点击"连接"
4. 程序自动设置 Windows 系统代理，浏览器无需手动配置

### 日志

- `logs/client.log` / `logs/server.log` —— INFO 级别（仅重要事件）
- 日志自动轮转：5MB / 文件，保留 5 个备份
- 需要详细日志时，将配置中的 `log_level` 改为 `DEBUG`

### 从源码构建

依赖：Python 3.10+, PyQt6, cryptography, PyInstaller

```powershell
pip install -r requirements.txt
python -m PyInstaller --noconfirm client.spec
python -m PyInstaller --noconfirm server_console.spec
```

## 功能特性

| 特性 | 说明 |
|----------|------|
| 智能路由 | 域名/IP 规则 + 中国 IP 库自动分流 |
| HTTP 代理 | 支持 CONNECT / GET / POST 全方法 |
| 服务端 DNS | 域名在日本侧解析，获取面向日本的最优 IP |
| TLS 连接池 | N 条并行 TLS 1.2+ 连接，轮询分发流 |
| 自动重连 | 指数退避重试（3s ~ 15s, 最多 5 次） |
| 健康监控 | 50s 内检测死连接，触发重连 |
| 空闲检测 | 服务端 120s 无数据自动清理静默断开的客户端 |
| 系统托盘 | 最小化到托盘，右键菜单操作 |
| 规则编辑器 | GUI 内编辑域名和 IP CIDR 路由规则 |
| 日志轮转 | 自动管理文件大小和备份数量 |

## 配置参考

### 客户端（client_config.json）

| 键 | 默认值 | 说明 |
|-----|--------|------|
| server_host | （必填） | 日本 VPS IP 或域名 |
| server_port | 8443 | 服务端监听端口 |
| psk | （必填） | 预共享密钥 |
| socks5_port | 1080 | 本地代理监听端口 |
| verify_cert | false | 是否验证服务端 TLS 证书 |
| auto_connect | false | 启动时自动连接 |
| auto_set_system_proxy | true | 自动设置 Windows 系统代理 |
| pool_size | 128 | 并行隧道数量（1-128） |
| connect_timeout | 10 | TLS 握手超时（秒） |
| optimistic_connect | false | 不等 CONNECT_OK 直接发数据（每连接省 ~1 RTT；实验性） |
| log_level | INFO | 日志级别：DEBUG / INFO |

### 服务端（server_config.json）

| 键 | 默认值 | 说明 |
|-----|--------|------|
| listen_host | 0.0.0.0 | 监听地址 |
| listen_port | 8443 | 监听端口 |
| psk | （必填） | 预共享密钥 |
| tls_cert_file | server.crt | TLS 证书路径 |
| tls_key_file | server.key | TLS 私钥路径 |
| max_connections | 200 | 最大并发出站连接数 |
| idle_timeout | 120 | 客户端空闲超时（秒） |
| log_level | INFO | 日志级别 |

## 说明 / 已知限制

- **仅 IPv4 出站。** 服务端只通过 IPv4（`AF_INET`）解析并连接目标，纯 IPv6 目标无法访问。
- **明文 HTTP 连接复用。** 对非加密 HTTP（非 HTTPS/CONNECT），keep-alive 的代理连接会绑定到首个目标主机；同一连接复用去往不同主机的请求不会重新路由。HTTPS（绝大多数流量）不受影响。
- **TLS 信任。** 默认客户端接受服务端自签证书（`verify_cert=false`），仅靠 PSK 保护。若要防御在途 MITM,请固定证书:把服务端 `server.crt` 拷到客户端,设 `tls_cert_file` 指向它并 `verify_cert=true`。
- **乐观流水线为实验特性。** `optimistic_connect=true` 每连接省一个往返,但目标不可达会表现为连接被断开而非立即 502。默认关闭,测试满意后再启用。
