# Furun VPN -- Technical Documentation

## Overall Architecture

```
Browser
  |
  | HTTP Proxy Protocol (127.0.0.1:1080)
  v
http_proxy.py           --> Parse CONNECT / GET / POST
  |
  | route()
  v
router.py               --> Rule matching + CB check + DNS cache
  |
  +-- DIRECT (China IP / rule match)
  |       |
  |       v
  |   asyncio.open_connection (local direct)
  |
  +-- PROXY (overseas IP / rule match)
          |
          v
      tunnel.py          --> TLS connection pool, 4-16 parallel tunnels
          |
          | Binary frame protocol (9-byte header)
          v
      tunnel_server.py   --> Server-side frame dispatch
          |
          v
      forward_proxy.py   --> Japan-side DNS resolve + TCP connect
```

## Communication Protocol

Multiple parallel TLS 1.2+ TCP connections carry multiplexed streams via binary frame protocol (big-endian). Client uses a connection pool (default 4 tunnels) with round-robin stream distribution:

```
[0:4] uint32  Total length (header + payload)
[4:8] uint32  Stream ID
[8]   uint8   Command type
[9:]  bytes   Payload
```

Commands:

| Command | Value | Direction | Purpose |
|---------|-------|-----------|---------|
| AUTH | 6 | C->S | PSK authentication |
| CONNECT_OK | 4 | S->C | Auth success / stream connect OK |
| CONNECT | 1 | C->S | Open stream to host:port |
| CONNECT_FAIL | 5 | S->C | Stream connect failed |
| DATA | 2 | Bidirectional | Stream data payload |
| CLOSE | 3 | Bidirectional | Close stream |
| PING | 9 | C->S | Heartbeat (30s interval) |
| PONG | 10 | S->C | Heartbeat response |

## Project Structure

```
vpnself/
+-- client/                     # Client code
|   +-- main.py                 # Entry: PyQt6 GUI launcher
|   +-- gui/
|   |   +-- main_window.py      # Main window: connect/disconnect/stats/tray
|   |   +-- log_viewer.py       # Embedded log panel
|   |   +-- rule_editor.py      # Routing rule editor dialog
|   |   +-- styles.py           # UI styles (Catppuccin Mocha theme)
|   +-- core/
|   |   +-- tunnel.py           # TLS tunnel client, stream management, connection pool
|   |   +-- http_proxy.py       # HTTP CONNECT + GET/POST proxy
|   |   +-- router.py           # Routing orchestration + stream wrappers
|   |   +-- rule_engine.py      # Domain/IP rule matching engine
|   |   +-- geoip.py            # China IP detection (pre-computed networks)
|   |   +-- circuit_breaker.py  # Failure tracking, TLS reject detection
|   +-- config/
|       +-- settings.py         # Config load/save (frozen-aware)
|       +-- default_rules.json  # Default routing rules
+-- server/                     # Server code
|   +-- console_main.py         # Console entry (no GUI needed)
|   +-- tunnel_server.py        # TLS server, client handler, frame dispatch
|   +-- forward_proxy.py        # Outbound TCP connections (client_id isolated)
|   +-- config.py               # Config load/save (frozen-aware)
+-- common/                     # Shared modules
|   +-- protocol.py             # Binary frame pack/unpack
|   +-- crypto.py               # TLS context factory
|   +-- utils.py                # Logging setup, DNS helpers, IP tools
+-- client.spec                 # PyInstaller client config
+-- server_console.spec         # PyInstaller server config
+-- dist/                       # Build output
|   +-- FurunVPN.exe            # Client EXE (~38MB)
|   +-- FurunVPNServer_Console.exe  # Server EXE (~11MB)
+-- requirements.txt
```

## Key Design Decisions

### HTTP CONNECT Proxy (not SOCKS)

Browser sends `CONNECT host:port HTTP/1.1`, carrying domain name. Server resolves DNS on Japan side, eliminating local DNS pollution (Chinese optimized IPs unreachable from Japan).

Also handles plain HTTP GET/POST: rewrites full URL to relative path, forwards to target.

### Smart Routing Engine

```
route(host, port):
  1. DNS resolve (run_in_executor, non-blocking, 5-min cache)
  2. Special IP? -> DIRECT (localhost, LAN, etc.)
  3. Rule engine evaluate (domain > IP CIDR > China IP > default)
  4. Circuit breaker check -> BLOCK if IP is blocked
  5. Split decision:
     - DIRECT -> asyncio.open_connection local direct
     - PROXY  -> tunnel.create_stream via Japan
     - BLOCK  -> return None (fast fail)
```

Rule priority (high to low):
1. Exact domain match (google.com -> proxy)
2. Wildcard domain match (*.googleapis.com -> proxy, suffix-based)
3. IP CIDR match (direct for China IP ranges)
4. Default action

### Circuit Breaker

Tracks failures per IP to avoid repeated timeout waits:

- **Trigger**: Connection timeout or TLS reject (sent <= 200 bytes, recv <= 7 bytes)
- **Threshold**: Blocks after first TLS reject; timeout requires 3 failures
- **Cooldown**: 120 seconds then auto-unblock
- **Persistence**: State saved to `logs/circuit_breaker.json`, survives restart
- **Eviction**: Max 500 tracked IPs, keeps most recently failed

### Health Monitor

Client-side `_health_check_loop` runs every 10s:
- Tracks `_last_rx_time` (monotonic timestamp of last received frame)
- If no data for 50s -> connection presumed dead -> disconnect + auto-reconnect

### Idle Detection

Server-side `_handle_client` wraps `reader.read()` with `asyncio.wait_for(timeout=120s)`:
- Client sends PING every 30s, so any 120s gap means client is dead
- Idle timeout closes connection, releases resources

### Connection Pool

The client maintains N parallel TLS tunnels to the server (configurable, default 4):

- **Distribution**: Round-robin across connected tunnels, skipping any that are down
- **Fault tolerance**: Each tunnel auto-reconnects independently on failure
- **Server isolation**: Each tunnel gets a unique `client_id` on the server; `ForwardProxy` keys relays by `(client_id, stream_id)` to prevent namespace collisions
- **DNS optimization**: Server-side DNS resolution happens outside the connection semaphore to prevent head-of-line blocking

### DNS Cache

Client-side 5-minute TTL DNS cache in Router:
- Avoids spawning `run_in_executor` thread for repeated DNS lookups
- Cache key is hostname, value is (expiry, IP)

### Buffer Optimization

Read loops use position tracking (`pos` variable) instead of per-frame `buf = buf[consumed:]`:
- Buffer only compacted once per `read()` cycle, not once per frame
- Reduces memory allocation for high-throughput connections

## Timeout Reference

| Component | Timeout | Purpose |
|-----------|---------|---------|
| TLS handshake | 10s | Client connects to server |
| AUTH response | 10s | PSK verification |
| Server DNS resolve | 3s | VPS DNS lookup |
| Server TCP connect | 5s | VPS -> target |
| Client CONNECT wait | 10s | Wait for CONNECT_OK |
| HTTP proxy request line | 10s | Read CONNECT/GET line |
| HTTP header read | 5s | Per line |
| Local direct connect | 10s | Direct to target |
| PING interval | 30s | Keepalive |
| Health check | 10s interval, 50s threshold | Dead connection detection |
| Server idle timeout | 120s | Client silent disconnect |
| Circuit breaker cooldown | 120s | Blocked IP thaw |
| Relay timeout (HTTP) | 10s | One side closed, wait for other |
| Pool reconnect | 5s~30s, per-tunnel | Individual tunnel backoff |
| Auto-reconnect | 3s~15s, max 5 attempts | Exponential backoff |

## HTTPS Data Flow (Complete)

```
1. Chrome:     CONNECT www.google.com:443 HTTP/1.1
2. http_proxy: Parse CONNECT -> router.route("www.google.com", 443)
3. router:     DNS cache hit/miss -> rule_engine.evaluate -> Action.PROXY
4. router:     pool.create_stream("www.google.com", 443, timeout=10.0)
5. tunnel:     pack_connect(sid, host, port) -> write to TLS tunnel
6. server:     forward_proxy.connect_target -> DNS(3s) + TCP(5s) -> target
7. server:     pack_connect_ok(sid) -> write CONNECT_OK back
8. tunnel:     _connect_future resolved -> stream ready
9. http_proxy: HTTP/1.1 200 Connection Established -> Chrome
10. Chrome <-> Google TLS handshake through relay
11. Relay done -> router.record_stream_result(host, sent, recv)
```

## Security

- TLS 1.2+ full encryption (AES-256-GCM)
- PSK pre-shared key secondary authentication
- Local proxy listens 127.0.0.1 only, not exposed to network
- Optional server certificate verification (verify_cert config)
- Logs do not record sensitive information
