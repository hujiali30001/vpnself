# Furun VPN —— 技术文档

## 整体架构

```
浏览器
  |
  | HTTP 代理协议 (127.0.0.1:1080)
  v
http_proxy.py           --> 解析 CONNECT / GET / POST
  |
  | route()
  v
router.py               --> 规则匹配 + 熔断检查 + DNS 缓存
  |
  +-- DIRECT（中国IP / 规则直连）
  |       |
  |       v
  |   asyncio.open_connection（本地直连）
  |
  +-- PROXY（境外IP / 规则代理）
          |
          v
      tunnel.py          --> 复用 TLS 隧道，多路流
          |
          | 二进制帧协议（9 字节头）
          v
      tunnel_server.py   --> 服务端帧分发
          |
          v
      forward_proxy.py   --> 日本侧 DNS 解析 + TCP 连接目标
```

## 通信协议

单条 TLS 1.2+ 连接通过二进制帧协议多路复用 N 个流（大端序）：

```
[0:4] uint32  帧总长度（含头部）
[4:8] uint32  流 ID
[8]   uint8   命令类型
[9:]  bytes   载荷
```

命令集：

| 命令 | 值 | 方向 | 用途 |
|------|----|------|------|
| AUTH | 6 | C->S | PSK 认证 |
| CONNECT_OK | 4 | S->C | 认证成功 / 流连接成功 |
| CONNECT | 1 | C->S | 打开到 host:port 的流 |
| CONNECT_FAIL | 5 | S->C | 流连接失败 |
| DATA | 2 | 双向 | 流数据载荷 |
| CLOSE | 3 | 双向 | 关闭流 |
| PING | 9 | C->S | 心跳（30s 间隔） |
| PONG | 10 | S->C | 心跳响应 |

## 项目结构

```
vpnself/
+-- client/                     # 客户端代码
|   +-- main.py                 # 入口（PyQt6 GUI 启动器）
|   +-- gui/
|   |   +-- main_window.py      # 主窗口（连接管理/统计/托盘）
|   |   +-- log_viewer.py       # 嵌入式日志面板
|   |   +-- rule_editor.py      # 路由规则编辑器对话框
|   |   +-- styles.py           # 界面样式（Catppuccin Mocha 主题）
|   +-- core/
|   |   +-- tunnel.py           # TLS 隧道客户端，流管理
|   |   +-- http_proxy.py       # HTTP CONNECT + GET/POST 代理
|   |   +-- router.py           # 路由编排 + 流包装器
|   |   +-- rule_engine.py      # 域名/IP 规则匹配引擎
|   |   +-- geoip.py            # 中国 IP 检测（预计算网络对象）
|   |   +-- circuit_breaker.py  # 失败追踪 + TLS 拒绝检测
|   +-- config/
|       +-- settings.py         # 配置加载/保存（支持 frozen 模式）
|       +-- default_rules.json  # 默认路由规则
+-- server/                     # 服务端代码
|   +-- console_main.py         # 控制台入口（无需 GUI）
|   +-- tunnel_server.py        # TLS 服务端，客户端处理，帧分发
|   +-- forward_proxy.py        # 向目标发起 TCP 连接
|   +-- config.py               # 配置加载/保存（支持 frozen 模式）
+-- common/                     # 公共模块
|   +-- protocol.py             # 二进制帧打包/解包
|   +-- crypto.py               # TLS 上下文工厂
|   +-- utils.py                # 日志设置，DNS 助手，IP 工具
+-- client.spec                 # PyInstaller 客户端配置
+-- server_console.spec         # PyInstaller 服务端配置
+-- dist/                       # 构建产物
|   +-- FurunVPN.exe            # 客户端 EXE（~38MB）
|   +-- FurunVPNServer_Console.exe  # 服务端 EXE（~11MB）
+-- requirements.txt
```

## 关键设计决策

### HTTP CONNECT 代理（而非 SOCKS）

浏览器发送 `CONNECT host:port HTTP/1.1`，携带域名。服务端在日本侧解析 DNS，消除本地 DNS 污染（返回中国优化 IP 导致日本 VPS 无法连接的问题）。

同时处理普通 HTTP GET/POST 请求：将完整 URL 改写为相对路径后转发到目标。

### 智能路由引擎

```
route(host, port):
  1. DNS 解析（run_in_executor，非阻塞，5 分钟缓存）
  2. 特殊 IP？-> DIRECT（localhost、局域网等）
  3. 规则引擎评估（域名 > IP CIDR > 中国IP > 默认）
  4. 熔断器检查 -> BLOCK（如果 IP 被封）
  5. 分流决策：
     - DIRECT -> asyncio.open_connection 本地直连
     - PROXY  -> tunnel.create_stream 走隧道
     - BLOCK  -> 返回 None（快速失败）
```

规则优先级（从高到低）：
1. 域名精确匹配（google.com -> 代理）
2. 域名通配符匹配（*.googleapis.com -> 代理，基于后缀匹配）
3. IP CIDR 匹配（中国 IP 段 -> 直连）
4. 默认动作

### 熔断器

自动学习不可达 IP，避免重复超时等待：

- **触发条件**：连接超时 或 TLS 拒绝（发送 <= 200 字节，接收 <= 7 字节）
- **阈值**：TLS 拒绝首次即封；超时需 3 次失败
- **冷却**：120 秒后自动解封
- **持久化**：状态保存到 `logs/circuit_breaker.json`，重启后恢复
- **淘汰**：最多追踪 500 个 IP，保留最近有失败记录的前 500 个
- **保存**：基于时间戳的去抖机制（无 threading.Timer）

### 健康监控

客户端 `_health_check_loop` 每 10 秒运行：
- 追踪 `_last_rx_time`（最后一次收到帧的 monotonic 时间戳）
- 超过 50 秒无数据 -> 判定连接死 -> 断开 + 自动重连

### 空闲检测

服务端 `_handle_client` 用 `asyncio.wait_for(timeout=120s)` 包装 `reader.read()`：
- 客户端每 30 秒发 PING，任何 120 秒无数据意味着客户端已死
- 空闲超时关闭连接，释放资源

### DNS 缓存

客户端 Router 中 5 分钟 TTL 的 DNS 缓存：
- 避免为重复 DNS 查询频繁 spawn `run_in_executor` 线程
- 缓存键为 hostname，值为 (过期时间, IP)

### 缓冲区优化

读循环用位置变量 `pos` 跟踪消费位置，而非每帧 `buf = buf[consumed:]`：
- 每个 `read()` 周期只压缩一次缓冲区，而非每帧一次
- 显著减少高吞吐连接下的内存分配

## 超时参数速查

| 组件 | 超时 | 用途 |
|------|------|------|
| TLS 握手 | 10s | 客户端连接服务端 |
| AUTH 响应 | 10s | PSK 验证 |
| 服务端 DNS 解析 | 3s | VPS DNS 查询 |
| 服务端 TCP 连接 | 5s | VPS -> 目标 |
| 客户端 CONNECT 等待 | 10s | 等待 CONNECT_OK |
| HTTP 代理请求行 | 10s | 读取 CONNECT/GET 行 |
| HTTP 头部读取 | 5s | 每行头部 |
| 本地直连 | 10s | 直连目标 |
| PING 间隔 | 30s | 保活 |
| 健康检查 | 10s 间隔 / 50s 阈值 | 死连接检测 |
| 服务端空闲超时 | 120s | 客户端静默断开 |
| 熔断冷却 | 120s | 被封 IP 解冻 |
| 中继超时 | 10s | 一侧关闭后等待另一侧 |
| 自动重连 | 3s~15s，最多 5 次 | 指数退避 |

## HTTPS 数据流（完整链路）

```
1. Chrome：    CONNECT www.google.com:443 HTTP/1.1
2. http_proxy：解析 CONNECT -> router.route("www.google.com", 443)
3. router：   DNS 缓存命中/未命中 -> rule_engine.evaluate -> Action.PROXY
4. router：   tunnel.create_stream("www.google.com", 443, timeout=10.0)
5. tunnel：   pack_connect(sid, host, port) -> 写入 TLS 隧道
6. server：   forward_proxy.connect_target -> DNS(3s) + TCP(5s) -> 目标
7. server：   pack_connect_ok(sid) -> 写回 CONNECT_OK
8. tunnel：   _connect_future 完成 -> 流就绪
9. http_proxy：HTTP/1.1 200 Connection Established -> Chrome
10. Chrome <-> Google TLS 握手透传
11. 中继完成 -> router.record_stream_result(host, sent, recv)
```

## 安全性

- TLS 1.2+ 全程加密（AES-256-GCM）
- PSK 预共享密钥二次认证
- 本地代理仅监听 127.0.0.1，不对外暴露
- 可选服务端证书验证（verify_cert 配置项）
- 日志不记录敏感信息
