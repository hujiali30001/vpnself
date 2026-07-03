"""
Furun VPN - Server Console Entry Point

纯控制台版本，适合 Windows Server 无桌面环境运行。
"""

import sys
import asyncio
import logging
import ssl
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from common.utils import setup_logging, get_logger
from server.config import load_config
from server.tunnel_server import TunnelServer


def generate_self_signed_cert(cert_file: str, key_file: str, san_names=None):
    """Generate a self-signed TLS certificate.

    ``san_names`` is an optional list of DNS names / IP addresses to embed as
    SubjectAlternativeName entries. Modern TLS clients verify the hostname
    against the SAN (not the CN), so without at least one SAN the client's
    ``verify_cert=true`` path (certificate pinning) can never succeed. localhost
    is always included.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    import ipaddress as _ip

    now = datetime.datetime.now(datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Furun VPN Server")])

    # Build SAN entries: IPs become IPAddress, everything else a DNSName.
    raw_names = ["localhost", "127.0.0.1"] + list(san_names or [])
    san_entries = []
    seen = set()
    for n in raw_names:
        n = str(n).strip()
        if not n or n in seen:
            continue
        seen.add(n)
        try:
            san_entries.append(x509.IPAddress(_ip.ip_address(n)))
        except ValueError:
            san_entries.append(x509.DNSName(n))

    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_file, key_file


async def main():
    config = load_config()
    # Normalize the log level: the config value is case-sensitive free text, so
    # 'debug' (resolving to the logging.debug function) or a typo would crash
    # setup_logging. Default to INFO on anything unrecognized.
    level_name = str(config.get("log_level", "INFO")).upper()
    log_level = getattr(logging, level_name, logging.INFO)
    if not isinstance(log_level, int):
        log_level = logging.INFO
    setup_logging("furun", level=log_level, log_dir=Path("logs"), log_name="server", console=True, file_rotate=True)
    log = get_logger("server.console")

    log.info("=" * 60)
    log.info("Furun VPN 服务端 (控制台模式) 启动中...")
    log.info("监听: %s:%d", config["listen_host"], config["listen_port"])
    log.info("最大连接数: %d", config.get("max_connections", 200))
    log.info("密钥: %s", "*" * min(len(config["psk"]), 16))
    log.info("=" * 60)

    # Fail closed: never authenticate clients against the public placeholder PSK.
    # This also catches an unreadable config that silently fell back to defaults.
    if config.get("psk", "") in ("", "changeme_psk_replace_with_generated_key"):
        log.error("拒绝启动：PSK 仍为默认占位值或为空。请在 server_config.json 中设置强随机密钥后重试。")
        return

    cert_file = config["tls_cert_file"]
    key_file = config["tls_key_file"]
    if not Path(cert_file).exists() or not Path(key_file).exists():
        log.info("生成自签名 TLS 证书 (有效期 10 年)...")
        # tls_san (optional list in config): the server's public IP/domain names,
        # required for clients that enable verify_cert (hostname pinning).
        generate_self_signed_cert(cert_file, key_file, config.get("tls_san"))
        log.info("证书已生成: %s / %s", cert_file, key_file)

    server = TunnelServer(config)
    try:
        await server.start_with_ssl()
    except KeyboardInterrupt:
        log.info("收到停止信号")
        await server.stop()
    except ssl.SSLError as e:
        log.error("SSL 错误: %s", e, exc_info=True)
    except OSError as e:
        log.error("网络错误: %s (端口 %d 是否被占用?)", e, config["listen_port"])
    except Exception as e:
        log.error("严重错误: %s", e, exc_info=True)
    finally:
        log.info("Furun VPN 服务端已停止")


if __name__ == "__main__":
    asyncio.run(main())
