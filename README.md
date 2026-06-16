# Furun VPN -- Smart Routing VPN

Browser HTTP/HTTPS traffic forwarded through encrypted TLS tunnel to Japan VPS.
DNS resolved on server side. Automatic split routing: domestic direct, overseas proxy.

## Architecture

```
Browser --HTTP--> Local Proxy (127.0.0.1:1080) --TLS Pool (N connections)--> Japan VPS --TCP--> Target
```

## Quick Start

### Server Deployment (Japan Windows Server)

1. Upload `FurunVPNServer_Console.exe` and `server_config.json` to VPS
2. First run auto-generates self-signed TLS certificate (10-year validity)
3. Listens on `0.0.0.0:8443`, ensure firewall allows this port

### Client Installation

1. Download `FurunVPN.exe`, no installation required
2. First run auto-creates `client_config.json`
3. Enter server IP, port, and PSK, click Connect
4. Program auto-sets Windows system proxy, browser requires zero config

### Logs

- `logs/client.log` / `logs/server.log` -- INFO level (important events only)
- Auto-rotated: 5MB per file, keep 5 backups
- Set `log_level` to `DEBUG` in config for verbose tracing

### Build from Source

Requirements: Python 3.10+, PyQt6, cryptography, PyInstaller

```powershell
pip install -r requirements.txt
python -m PyInstaller --noconfirm client.spec
python -m PyInstaller --noconfirm server_console.spec
```

## Features

| Feature | Description |
|----------|------------|
| Smart Routing | Domain/IP rules + China IP database auto-split |
| HTTP Proxy | Supports CONNECT / GET / POST all methods |
| Server-side DNS | Domain resolved in Japan, gets optimal IP for Japan VPS |
| TLS Tunnel Pool | N parallel TLS 1.2+ connections, round-robin stream distribution |
| Auto Reconnect | Exponential backoff retry (3s ~ 15s, max 5 attempts) |
| Health Monitor | Detects dead connections within 50s, triggers reconnect |
| Idle Detection | Server drops silent clients after 120s |
| System Tray | Minimize to tray, right-click menu operation |
| Rule Editor | GUI rule editor for domain and IP CIDR rules |
| Log Rotation | Auto-managed file size and backup count |

## Configuration

### Client (client_config.json)

| Key | Default | Description |
|-----|---------|-------------|
| server_host | (required) | Japan VPS IP or domain |
| server_port | 8443 | Server listen port |
| psk | (required) | Pre-shared key |
| socks5_port | 1080 | Local proxy listen port |
| verify_cert | false | Verify server TLS certificate |
| auto_connect | false | Auto-connect on startup |
| auto_set_system_proxy | true | Auto-set Windows system proxy |
| pool_size | 128 | Parallel tunnel connections (1-128) |
| connect_timeout | 10 | TLS handshake timeout (seconds) |
| optimistic_connect | false | Pipeline data without waiting for CONNECT_OK (saves ~1 RTT/conn; experimental) |
| log_level | INFO | Log level: DEBUG / INFO |

### Server (server_config.json)

| Key | Default | Description |
|-----|---------|-------------|
| listen_host | 0.0.0.0 | Listen address |
| listen_port | 8443 | Listen port |
| psk | (required) | Pre-shared key |
| tls_cert_file | server.crt | TLS certificate path |
| tls_key_file | server.key | TLS private key path |
| max_connections | 200 | Max concurrent outbound connections |
| idle_timeout | 120 | Client idle timeout (seconds) |
| log_level | INFO | Log level |

## Notes / Limitations

- **IPv4-only egress.** The server resolves and connects to targets over IPv4 (`AF_INET`) only; IPv6-only destinations are not reachable.
- **Plain-HTTP connection reuse.** For unencrypted HTTP (not HTTPS/CONNECT), a keep-alive proxy connection is pinned to its first target host; a reused connection to a different host is not re-routed. HTTPS — the vast majority of traffic — is unaffected.
- **TLS trust.** By default the client accepts the server's self-signed certificate (`verify_cert=false`) and relies on the PSK. For protection against an in-path MITM, pin the certificate: copy the server's `server.crt` to the client, set `tls_cert_file` to it and `verify_cert=true`.
- **Optimistic pipelining is experimental.** `optimistic_connect=true` removes one round-trip per connection but reports target-unreachable as a dropped connection instead of an immediate 502. Off by default; enable after testing your link.
