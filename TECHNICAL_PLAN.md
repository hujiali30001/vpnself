# Furun VPN -- Technical Design Plan

## 1. Product Overview

Furun VPN is a smart split-routing VPN system. Server deployed on Japan Windows Server, client runs on local Windows. Core capability is **intelligent routing**: browser HTTP/HTTPS traffic enters through HTTP CONNECT proxy, system auto-decides direct vs proxy per request based on domain rules, IP rules, and China IP database. DNS resolved on Japan side for optimal IP.

Target users: developers needing access to overseas sites (Google, GitHub, ChatGPT) while maintaining full speed for domestic sites.

## 2. System Architecture

```
+--------------------------------------+
|           Client (Local PC)          |
|                                      |
|  +----------+  +----------------+    |
|  | PyQt GUI |  | HTTP CONNECT   |    |
|  | Manager  |  | Proxy(127.0.0.1 |    |
|  |          |  |    :1080)      |    |
|  +----------+  +-------+--------+    |
|                        |             |
|               +--------+--------+    |
|               | Smart Routing   |    |
|               | Engine          |    |
|               ++---------------+    |
|                |        |            |
|         DIRECT |        | PROXY      |
|                |        |            |
|                | +------+------+     |
|                | | TLS Tunnel  |     |
|                | | (TLS 1.2+)  |     |
|                | | Multi-stream|     |
|                | +------+------+     |
+----------------+        |            |
                          | Internet   |
+----------------+        |            |
| Server (Japan) |        |            |
|                |        |            |
| +--------------+--------+-------+    |
| |  TLS Tunnel Endpoint          |    |
| |  (Frame dispatch, streams)    |    |
| +--------------+----------------+    |
|                |                     |
| +--------------+----------------+    |
| |  Forward Proxy (outbound)     |    |
| |  (DNS resolve + TCP connect)  |    |
| +--------------+----------------+    |
|                |                     |
+----------------+---------------------+
                 |
        Internet Target Servers
```

## 3. Data Flow

```
Browser --HTTP--> Local Proxy(127.0.0.1:1080) --TLS Tunnel--> Japan VPS --TCP--> Target
                 |                                |               |
                 | Smart Route Decision           |               DNS resolve (Japan side)
                 +-- China IP     -> DIRECT (local direct)
                 +-- Rule direct  -> DIRECT
                 +-- Overseas IP  -> PROXY (tunnel)
                 +-- CB blocked   -> REJECT (fast fail)
```

## 4. Core Technical Modules

### 4.1 Communication Protocol

Single TLS connection multiplexes N streams via binary frame protocol:

```
Frame format (big-endian):
  [0:4] uint32  Frame total length (including header)
  [4:8] uint32  Stream ID
  [8]   uint8   Command type
  [9:]  bytes   Payload

Command set:
  AUTH(6)     -> PSK authentication
  CONNECT(1)  -> Open stream to host:port
  DATA(2)     -> Stream data
  CLOSE(3)    -> Close stream
  PING/PONG   -> 30s heartbeat keepalive
```

### 4.2 HTTP CONNECT Proxy

Browser sends `CONNECT host:port HTTP/1.1`, carrying domain name. Server calls `asyncio.open_connection(host, port)` to connect target on Japan side, DNS resolution happens on server -- eliminates local DNS pollution.

Also handles plain HTTP GET/POST: rewrites full URL to relative path then forwards.

### 4.3 Smart Routing Engine

```python
route(host, port):
  1. DNS resolve (run_in_executor, non-blocking, 5-min cache)
  2. Special IP check (localhost, LAN) -> DIRECT
  3. Rule engine evaluate (domain > IP CIDR > China IP > default)
  4. Circuit breaker check -> BLOCK if IP blocked
  5. Split:
     - DIRECT -> asyncio.open_connection local direct
     - PROXY  -> tunnel.create_stream via Japan
     - BLOCK  -> return None
```

Rule priority (high to low):
1. Exact domain match (e.g. google.com -> proxy)
2. Wildcard domain match (*.googleapis.com -> proxy, suffix-based, no fnmatch)
3. IP CIDR match (pre-computed ipaddress objects for O(1) containment check)
4. China IP database match (APNIC-verified allocations)
5. Default action

### 4.4 Circuit Breaker

Auto-learns unreachable IPs to avoid repeated timeout waits:

- **Trigger**: Connection timeout or TLS reject (sent <= 200 bytes, recv <= 7 bytes)
- **Threshold**: Blocks on first TLS reject; timeout needs 3 failures
- **Cooldown**: 120 seconds auto-unblock
- **Persistence**: State saved to `logs/circuit_breaker.json`
- **Eviction**: Max 500 tracked IPs, keeps most recently failed
- **Save**: Timestamp-based debounce (no threading.Timer)

### 4.5 Connection Health & Recovery

**Client Health Monitor**: `_health_check_loop` runs every 10s, tracks `_last_rx_time` (monotonic). If no data for 50s, connection presumed dead -> disconnect -> auto-reconnect.

**Server Idle Detection**: Wraps `reader.read()` with `asyncio.wait_for(timeout=120s)`. Client sends PING every 30s, so 120s gap means client is dead.

**Auto Reconnect**: Tunnel drop triggers `on_disconnect` callback. Client retries:
- Max 5 attempts
- Interval: 3s -> 6s -> 9s -> 12s -> 15s (exponential backoff)
- UI shows "reconnecting" status
- Manual disconnect disables auto-reconnect

### 4.6 System Proxy Auto Management

- On connect: clear old proxy -> write `http=127.0.0.1:1080;https=127.0.0.1:1080` -> InternetSetOptionW notify refresh
- On disconnect: ProxyEnable=0 -> delete ProxyServer -> InternetSetOptionW notify refresh

### 4.7 DNS Caching

Client-side 5-minute TTL DNS cache avoids per-connection thread spawn:
- Cache key: hostname
- Value: (expiry_timestamp, ip_address)
- Expired entries auto-removed on access

### 4.8 Buffer Optimization

Read loops use position tracking instead of per-frame buffer slicing:
- `pos` variable tracks consumed bytes
- Buffer compacted once per `read()` cycle, not once per frame
- Significantly reduces memory allocation under load

## 5. Project Structure

```
vpnself/
+-- client/                     # Client source
|   +-- main.py                 # Entry (PyQt6 GUI launcher)
|   +-- gui/
|   |   +-- main_window.py      # Main window (connection/stats/tray)
|   |   +-- log_viewer.py       # Embedded log panel
|   |   +-- rule_editor.py      # Rule editor dialog
|   |   +-- styles.py           # UI theme (Catppuccin Mocha)
|   +-- core/
|   |   +-- tunnel.py           # TLS tunnel client, stream mgmt
|   |   +-- http_proxy.py       # HTTP CONNECT + GET/POST proxy
|   |   +-- router.py           # Routing orchestration
|   |   +-- rule_engine.py      # Rule matching engine
|   |   +-- geoip.py            # China IP detection
|   |   +-- circuit_breaker.py  # Failure tracking
|   +-- config/
|       +-- settings.py         # Config load/save
|       +-- default_rules.json  # Default rules
+-- server/                     # Server source
|   +-- console_main.py         # Console entry
|   +-- tunnel_server.py        # TLS server, frame dispatch
|   +-- forward_proxy.py        # Outbound TCP connections
|   +-- config.py               # Config load/save
+-- common/                     # Shared modules
|   +-- protocol.py             # Binary frame pack/unpack
|   +-- crypto.py               # TLS context factory
|   +-- utils.py                # Logging, DNS, IP tools
+-- client.spec                 # PyInstaller client spec
+-- server_console.spec         # PyInstaller server spec
+-- dist/                       # Build output
|   +-- FurunVPN.exe            # Client (~38MB)
|   +-- FurunVPNServer_Console.exe  # Server (~11MB)
```

## 6. Tech Stack

| Module | Technology |
|--------|-----------|
| GUI framework | PyQt6 |
| Async networking | asyncio |
| Encryption | cryptography (TLS) |
| TLS | Python ssl (TLS_AES_256_GCM_SHA384) |
| China IP detection | Built-in IP range list (APNIC data, pre-computed ipaddress objects) |
| System proxy | winreg + InternetSetOptionW |
| Packaging | PyInstaller |
| Logging | logging + RotatingFileHandler |

## 7. Deployment

### Server (Japan Windows Server 2012+)

- Upload `FurunVPNServer_Console.exe` and `server_config.json`
- First run auto-generates self-signed TLS cert (10-year)
- Listens on 0.0.0.0:8443, firewall must allow
- No Python runtime needed
- Optional: register as Windows service for auto-start

### Client (Local Windows 10/11)

- Download `FurunVPN.exe`, portable
- First run auto-creates config
- Fill in server IP, port, PSK, click Connect
- Auto-sets system proxy, browser needs no config
- Supports minimize to tray, right-click menu

## 8. Security Design

- TLS 1.2+ full encryption (AES-256-GCM)
- PSK pre-shared key secondary authentication
- Local proxy listens 127.0.0.1 only
- Optional server certificate verification
- Logs exclude sensitive data

## 9. Timeout Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| TLS handshake | 10s | Client -> server |
| AUTH response | 10s | PSK verification |
| Server DNS | 3s | VPS DNS lookup |
| Server TCP connect | 5s | VPS -> target |
| Client CONNECT wait | 10s | Wait for CONNECT_OK |
| Local direct | 10s | Direct connection |
| PING interval | 30s | Keepalive |
| Health check | 10s / 50s | Dead connection detection |
| Server idle | 120s | Client silent disconnect |
| CB cooldown | 120s | Blocked IP thaw |
| Auto-reconnect | 3s~15s x5 | Exponential backoff |

## 10. Performance

| Metric | Value |
|--------|-------|
| Max concurrent streams | 200 (configurable) |
| Tunnel multiplexing | Single connection carries N streams |
| Buffer size | 64KB |
| Log rotation | 5MB x 5 files |
| Client EXE size | ~38MB |
| Server EXE size | ~11MB |
| PING latency | <100ms (Japan-China) |
| TLS handshake | <300ms |
| DNS cache TTL | 300s |
