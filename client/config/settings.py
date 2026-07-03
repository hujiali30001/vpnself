"""
Furun VPN - Client Configuration
"""

import json
import os
import sys
from pathlib import Path

from common.utils import get_logger

log = get_logger("client.config")


def _atomic_write_json(path: Path, data: dict):
    """Write JSON to ``path`` atomically (tmp file + os.replace).

    A crash/power loss mid-write leaves the original file intact rather than a
    truncated one, so an interrupted save can never silently reset the config.
    """
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass  # best-effort durability; some filesystems don't support it
    os.replace(tmp, path)

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
    "optimistic_connect": False,
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
            if not isinstance(cfg, dict):
                # Valid JSON but not an object (null/list/number) -> the merge
                # below would raise TypeError; treat as corrupt instead.
                raise ValueError("config root must be a JSON object")
            return {**DEFAULT_CONFIG, **cfg}
        except (json.JSONDecodeError, ValueError, TypeError, OSError) as e:
            # Preserve the unreadable file rather than destroying it, so an
            # interrupted save that truncated it doesn't permanently lose the
            # user's server_host / psk (recoverable from the .bak).
            log.warning("client_config.json at %s is unreadable (%s) -- "
                        "backing up to .bak and regenerating with defaults", p, e)
            try:
                p.replace(p.with_name(p.name + ".bak"))
            except OSError:
                pass
    # Create/regenerate the default config. A write failure (e.g. read-only
    # install dir) must not crash startup -- fall back to in-memory defaults.
    try:
        _atomic_write_json(p, DEFAULT_CONFIG)
    except OSError as e:
        log.warning("Could not write default client_config.json at %s: %s", p, e)
    return dict(DEFAULT_CONFIG)


def save_config(config: dict, path: Path | None = None) -> bool:
    """Save client configuration to JSON atomically. Returns True on success."""
    p = path or (_get_config_dir() / "client_config.json")
    try:
        _atomic_write_json(p, config)
        return True
    except OSError as e:
        log.error("保存配置失败 %s: %s", p, e)
        return False
