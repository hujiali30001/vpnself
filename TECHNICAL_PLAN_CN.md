# Furun VPN —— 技术方案

## 1. 产品概述

Furun VPN 是一套智能分流 VPN 系统。服务端部署于日本 Windows Server，客户端运行于本地 Windows。核心能力是**智能路由**：浏览器 HTTP/HTTPS 流量通过 HTTP CONNECT 代理接入，系统根据域名规则、IP 规则和中国 IP 库自动判断每个请求应走国内直连还是通过日本服务器代理，DNS 在日本侧解析以获取最优 IP。

适用场景：开发者需要访问境外网站（Google、GitHub、ChatGPT 等），同时保持国内网站全速访问。

## 2. 系统架构

```
+--------------------------------------+
|           客户端（本地 PC）            |
|                                      |
|  +----------+  +-----------------+   |
|  | PyQt GUI |  | HTTP CONNECT    |   |
|  | 管理界面  |  | 代理(127.0.0.1  |   |
|  |          |  |    :1080)      |   |
|  +----------+  +-------+--------+   |
|                        |             |
|               +--------+--------+   |
|               |   智能路由引擎   |   |
|               ++---------------+   |
|                |        |           |
|         DIRECT |        | PROXY     |
|                |        |           |
|                | +------+------+    |
|                | |  TLS 隧道   |    |
|                | | (TLS 1.2+)  |    |
|                | |  多路复用    |    |
|                | +------+------+    |
+----------------+        |           |
                          | 互联网     |
+----------------+        |           |
| 服务端（日本）  |        |           |
|                |        |           |
| +--------------+--------+-------+   |
| |      TLS 隧道终结点           |   |
| |   （帧分发、流管理）           |   |
| +--------------+---------------+   |
|                |                    |
| +--------------+---------------+   |
| |    转发代理（出口）           |   |
| |  （DNS 解析 + TCP 连接）      |   |
| +--------------+---------------+   |
|                |                    |
+----------------+--------------------+
                 |
           互联网目标服务器
```

## 3. 数据流

```
浏览器 --HTTP--> 本地代理(127.0.0.1:1080) --TLS隧道--> 日本VPS --TCP--> 目标
                 |                                |               |
                 | 智能路由判決                    |               DNS解析（日本侧）
                 +-- 中国IP      -> DIRECT（本地直连）
                 +-- 规则直连    -> DIRECT
                 +-- 境外IP      -> PROXY（走隧道）
                 +-- 熔断拦截    -> REJECT（快速失败）
```

## 4. 核心技术模块

### 4.1 通信协议

单条 TLS 连接通过二进制帧协议多路复用 N 个流：

```
帧格式（大端序）：
  [0:4] uint32  帧总长度（含头部）
  [4:8] uint32  流 ID
  [8]   uint8   命令类型
  [9:]  bytes   载荷

命令集：
  AUTH(6)     -> PSK 认证
  CONNECT(1)  -> 打开到 host:port 的流
  DATA(2)     -> 流数据
  CLOSE(3)    -> 关闭流
  PING/PONG   -> 30s 心跳保活
```

### 4.2 HTTP CONNECT 代理

浏览器发送 `CONNECT host:port HTTP/1.1`，携带域名。服务端在日本侧调用 `asyncio.open_connection(host, port)` 连接目标，DNS 解析在服务端完成——消除本地 DNS 污染。

同时处理普通 HTTP GET/POST 请求：将完整 URL 改写为相对路径后转发至目标。

### 4.3 智能路由引擎

```python
route(host, port):
  1. DNS 解析（run_in_executor，非阻塞，5 分钟缓存）
  2. 特殊 IP 检查（localhost、局域网）-> DIRECT
  3. 规则引擎评估（域名 > IP CIDR > 中国IP > 默认）
  4. 熔断器检查 -> BLOCK（如果 IP 被封）
  5. 分流：
     - DIRECT -> asyncio.open_connection 本地直连
     - PROXY  -> tunnel.create_stream 走隧道
     - BLOCK  -> 返回 None
```

规则优先级（从高到低）：
1. 域名精确匹配（如 google.com -> 代理）
2. 域名通配符匹配（*.googleapis.com -> 代理，基于后缀匹配，无 fnmatch 开销）
3. IP CIDR 匹配（预计算 ipaddress 对象，O(1) 包含判断）
4. 中国 IP 库匹配（APNIC 验证的分配段）
5. 默认动作

### 4.4 熔断器

自动学习不可达 IP，避免重复超时等待：

- **触发条件**：连接超时 或 TLS 拒绝（发送 <= 200 字节，接收 <= 7 字节）
- **阈值**：TLS 拒绝首次即封；超时需 3 次失败
- **冷却**：120 秒自动解封
- **持久化**：状态保存到 `logs/circuit_breaker.json`，重启恢复
- **淘汰**：最多 500 个 IP，按最近失败时间保留
- **保存**：基于时间戳的去抖，无额外线程

### 4.5 连接健康与恢复

**客户端健康监控**：`_health_check_loop` 每 10 秒运行，追踪 `_last_rx_time`（monotonic）。超过 50 秒无数据 -> 判定连接死 -> 断开 -> 自动重连。

**服务端空闲检测**：用 `asyncio.wait_for(timeout=120s)` 包装 `reader.read()`。客户端每 30 秒发 PING，120 秒无数据意味着客户端已死。

**自动重连**：隧道断开触发 `on_disconnect` 回调，客户端重试：
- 最多 5 次
- 间隔：3s -> 6s -> 9s -> 12s -> 15s（指数退避）
- UI 显示"重连中"状态
- 手动断开禁用自动重连

### 4.6 系统代理自动管理

- 连接时：清除旧代理 -> 写入 `http=127.0.0.1:1080;https=127.0.0.1:1080` -> InternetSetOptionW 通知刷新
- 断开时：ProxyEnable=0 -> 删除 ProxyServer -> InternetSetOptionW 通知刷新

### 4.7 DNS 缓存

客户端 5 分钟 TTL DNS 缓存，避免每次连接 spawn 线程做 DNS：
- 缓存键：hostname
- 值：(过期时间戳, IP 地址)
- 过期条目在访问时自动清除

### 4.8 缓冲区优化

读循环用位置变量 `pos` 跟踪已消费字节，替代每帧 `buf = buf[consumed:]`：
- 每个 `read()` 周期只压缩一次缓冲区
- 显著减少高负载下的内存分配

## 5. 项目结构

```
vpnself/
+-- client/                     # 客户端源码
|   +-- main.py                 # 入口（PyQt6 GUI）
|   +-- gui/
|   |   +-- main_window.py      # 主窗口（连接/统计/托盘）
|   |   +-- log_viewer.py       # 嵌入式日志面板
|   |   +-- rule_editor.py      # 规则编辑器
|   |   +-- styles.py           # UI 主题
|   +-- core/
|   |   +-- tunnel.py           # TLS 隧道客户端
|   |   +-- http_proxy.py       # HTTP CONNECT + GET/POST 代理
|   |   +-- router.py           # 路由编排
|   |   +-- rule_engine.py      # 规则匹配引擎
|   |   +-- geoip.py            # 中国 IP 检测
|   |   +-- circuit_breaker.py  # 失败追踪
|   +-- config/
|       +-- settings.py         # 配置管理
|       +-- default_rules.json  # 默认规则
+-- server/                     # 服务端源码
|   +-- console_main.py         # 控制台入口
|   +-- tunnel_server.py        # TLS 服务端
|   +-- forward_proxy.py        # 转发代理出口
|   +-- config.py               # 配置管理
+-- common/                     # 公共模块
|   +-- protocol.py             # 二进制帧协议
|   +-- crypto.py               # TLS 上下文
|   +-- utils.py                # 日志/DNS/IP 工具
+-- client.spec                 # PyInstaller 客户端配置
+-- server_console.spec         # PyInstaller 服务端配置
+-- dist/                       # 构建输出
|   +-- FurunVPN.exe            # 客户端（~38MB）
|   +-- FurunVPNServer_Console.exe  # 服务端（~11MB）
```

## 6. 技术选型

| 模块 | 技术 |
|------|------|
| GUI 框架 | PyQt6 |
| 异步网络 | asyncio |
| 加密 | cryptography（TLS） |
| TLS | Python ssl（TLS_AES_256_GCM_SHA384） |
| 中国 IP 识别 | 内置 IP 段列表（APNIC 数据，预计算 ipaddress 对象） |
| 系统代理 | winreg + InternetSetOptionW |
| 打包分发 | PyInstaller |
| 日志 | logging + RotatingFileHandler |

## 7. 部署架构

### 服务端（日本 Windows Server 2012+）

- 上传 `FurunVPNServer_Console.exe` 和 `server_config.json`
- 首次启动自动生成自签名 TLS 证书（10 年）
- 监听 0.0.0.0:8443，防火墙需放行
- 无需安装 Python 运行时
- 可选：注册为 Windows 服务实现开机自启

### 客户端（本地 Windows 10/11）

- 下载 `FurunVPN.exe`，绿色免安装
- 首次运行自动创建配置文件
- 填写服务器 IP、端口、密钥，点击连接
- 自动设置系统代理，浏览器零配置
- 支持最小化到托盘，右键菜单操作

## 8. 安全设计

- TLS 1.2+ 全程加密（AES-256-GCM）
- PSK 预共享密钥二次认证
- 本地代理仅监听 127.0.0.1，不对外暴露
- 可选服务端证书验证
- 日志不记录敏感信息

## 9. 超时参数

| 参数 | 值 | 说明 |
|------|----|------|
| TLS 握手超时 | 10s | 客户端连服务端 |
| AUTH 超时 | 10s | PSK 验证 |
| 服务端 DNS | 3s | VPS DNS 查询 |
| 服务端 TCP 连接 | 5s | VPS 连目标 |
| 客户端 CONNECT 等待 | 10s | 等待 CONNECT_OK |
| 本地直连超时 | 10s | DIRECT 连接 |
| PING 间隔 | 30s | 保活 |
| 健康检查 | 10s/50s | 死连接检测 |
| 服务端空闲 | 120s | 客户端静默断开 |
| 熔断冷却 | 120s | IP 解冻 |
| 自动重连 | 3s~15s x5 | 指数退避 |

## 10. 性能指标

| 指标 | 数值 |
|------|------|
| 最大并发流 | 200（可配置） |
| 隧道多路复用 | 单连接承载 N 流 |
| 缓冲区大小 | 64KB |
| 日志轮转 | 5MB x 5 文件 |
| 客户端 EXE | ~38MB |
| 服务端 EXE | ~11MB |
| PING 延迟 | <100ms（日本-中国） |
| TLS 握手 | <300ms |
| DNS 缓存 TTL | 300s |
