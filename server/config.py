"""
Furun VPN - Server Configuration
"""

import json
import os
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
    # Optional: public DNS names / IPs to embed in the auto-generated cert's
    # SubjectAlternativeName. Required for clients that set verify_cert=true.
    "tls_san": [],
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
            if not isinstance(cfg, dict):
                raise ValueError("config root must be a JSON object")
            merged = {**DEFAULT_CONFIG, **cfg}
        except (json.JSONDecodeError, ValueError, OSError) as e:
            # Preserve the corrupt file as .bak so the operator can recover
            # the PSK and other settings rather than losing them silently.
            log.warning("server_config.json at %s is unreadable (%s) -- "
                        "backing up to .bak and using built-in defaults (check PSK!)", p, e)
            try:
                p.replace(p.with_name(p.name + ".bak"))
            except OSError:
                pass
            merged = dict(DEFAULT_CONFIG)
    else:
        merged = dict(DEFAULT_CONFIG)
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(merged, f, indent=2)
        except OSError as e:
            log.warning("Could not write default server_config.json at %s: %s", p, e)

    return _resolve_paths(merged)


def save_config(config: dict, path: Path | None = None):
    """Save server configuration to JSON using an atomic write.

    Writes to a .tmp file, fsyncs for durability, then renames it over the
    target so a crash mid-write never leaves a truncated config file.
    """
    p = path or _get_config_path()
    clean = {k: v for k, v in config.items()
             if k not in ("_resolved_",)}
    tmp = p.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _resolve_paths(config: dict) -> dict:
    """Resolve relative file paths in config to absolute paths."""
    base = _get_config_dir()
    cfg = dict(config)
    for key in ("tls_cert_file", "tls_key_file", "log_file"):
        val = cfg.get(key)
        if val and not Path(val).is_absolute():
            cfg[key] = str(base / val)
    return cfg
