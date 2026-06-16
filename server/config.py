"""
Furun VPN - Server Configuration
"""

import json
import sys
from pathlib import Path

from common.utils import get_logger

log = get_logger("server.config")

DEFAULT_CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 8443,
    "psk": "changeme_psk_replace_with_generated_key",
    "tls_cert_file": "server.crt",
    "tls_key_file": "server.key",
    "max_connections": 200,
    "idle_timeout": 120,
    "log_file": "server.log",
    "log_level": "INFO",
}


def _get_config_dir() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def _get_config_path() -> Path:
    return _get_config_dir() / "server_config.json"


def load_config(path: Path | None = None) -> dict:
    """Load server configuration from JSON, creating default if needed."""
    p = path or _get_config_path()
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            merged = {**DEFAULT_CONFIG, **cfg}
        except (json.JSONDecodeError, OSError) as e:
            log.warning("server_config.json at %s is unreadable (%s) -- "
                        "using built-in defaults (check PSK!)", p, e)
            merged = dict(DEFAULT_CONFIG)
    else:
        merged = dict(DEFAULT_CONFIG)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2)

    return _resolve_paths(merged)


def save_config(config: dict, path: Path | None = None):
    """Save server configuration to JSON (writes non-resolved paths)."""
    p = path or _get_config_path()
    clean = {k: v for k, v in config.items()
             if k not in ("_resolved_",)}
    with open(p, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2)


def _resolve_paths(config: dict) -> dict:
    """Resolve relative file paths in config to absolute paths."""
    base = _get_config_dir()
    cfg = dict(config)
    for key in ("tls_cert_file", "tls_key_file", "log_file"):
        val = cfg.get(key)
        if val and not Path(val).is_absolute():
            cfg[key] = str(base / val)
    return cfg
