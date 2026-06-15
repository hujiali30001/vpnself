"""
Furun VPN - Client Configuration
"""

import json
import sys
from pathlib import Path

DEFAULT_CONFIG = {
    "server_host": "your_jp_server_ip_or_domain",
    "server_port": 8443,
    "psk": "changeme_psk_replace_with_generated_key",
    "tls_cert_file": "",
    "socks5_host": "127.0.0.1",
    "socks5_port": 1080,
    "connect_timeout": 10,
    "verify_cert": False,
    "auto_connect": False,
    "auto_set_system_proxy": True,
    "log_level": "INFO",
    "log_file": "",
    "pool_size": 128,
}


def _get_config_dir() -> Path:
    """Get the directory where config files live."""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def load_config(path: Path | None = None) -> dict:
    """Load client configuration from JSON, creating default if needed."""
    p = path or (_get_config_dir() / "client_config.json")
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            merged = {**DEFAULT_CONFIG, **cfg}
            return merged
        except (json.JSONDecodeError, OSError):
            pass
    with open(p, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    return dict(DEFAULT_CONFIG)


def save_config(config: dict, path: Path | None = None):
    """Save client configuration to JSON."""
    p = path or (_get_config_dir() / "client_config.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
