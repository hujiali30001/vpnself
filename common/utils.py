"""
Furun VPN - Utility Functions

Logging setup with rotating files, console output, and optional
Qt signal bridging for GUI integration.
"""

import logging
import logging.handlers
import sys
import socket
import ipaddress
import os
from datetime import datetime
from pathlib import Path


# --- Logging ---

LOG_FORMAT = "%(asctime)s.%(msecs)03d [%(levelname)-5s] %(name)s | %(message)s"
LOG_DATE_FORMAT = "%m-%d %H:%M:%S"

# Module-level log accessor for the Qt bridge
_qt_handler: logging.Handler | None = None


def get_qt_handler() -> logging.Handler | None:
    """Return the current Qt log handler, if registered."""
    return _qt_handler


def create_qt_handler(signal) -> logging.Handler:
    """
    Create a logging handler that emits log records via a Qt signal.
    The signal must accept two str args: (message, level).
    """
    global _qt_handler

    class _QtHandler(logging.Handler):
        def emit(self, record: logging.LogRecord):
            try:
                msg = self.format(record)
                signal.emit(msg, record.levelname)
            except Exception:
                self.handleError(record)

    handler = _QtHandler()
    handler.setLevel(logging.DEBUG)
    fmt = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    handler.setFormatter(fmt)
    _qt_handler = handler
    return handler


def setup_logging(name: str = "furun",
                  level: int = logging.INFO,
                  log_dir: str | Path | None = None,
                  log_name: str = "furun",
                  console: bool = True,
                  file_rotate: bool = True,
                  debug_file: bool = False,
                  qt_handler: logging.Handler | None = None):
    """
    Configure the root logger for the entire application.

    Parameters
    ----------
    name : str
        Root logger name ("furun").
    level : int
        Logging level (e.g. logging.DEBUG).
    log_dir : str | Path | None
        Directory for rotating log files. Default: ./logs/.
    console : bool
        Enable console (stdout) output.
    file_rotate : bool
        Enable rotating file logs.
    debug_file : bool
        If True, also create a *_debug.log file capturing DEBUG level.
        Default False to avoid I/O overhead from dual files.
    qt_handler : logging.Handler | None
        Optional Qt signal handler for GUI display.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()
    logger.propagate = False  # Prevent double-logging via root

    # Console handler
    if console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(level)
        fmt = logging.Formatter("%(asctime)s [%(levelname)-5s] %(name)s | %(message)s",
                                datefmt=LOG_DATE_FORMAT)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

    # Rotating file handler
    if file_rotate:
        if log_dir is None:
            log_dir = Path(os.getcwd()) / "logs"
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)

        log_path = log_dir / f"{log_name}.log"
        fh = logging.handlers.RotatingFileHandler(
            str(log_path),
            maxBytes=5 * 1024 * 1024,  # 5 MB per file
            backupCount=5,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)  # File always captures debug
        fmt = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        if debug_file:
            # Optional separate debug-level handler for verbose tracing
            debug_path = log_dir / f"{log_name}_debug.log"
            dh = logging.handlers.RotatingFileHandler(
                str(debug_path),
                maxBytes=10 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
            )
            dh.setLevel(logging.DEBUG)
            dh.setFormatter(fmt)
            logger.addHandler(dh)

    # Qt signal handler
    if qt_handler:
        logger.addHandler(qt_handler)

    # Suppress noisy third-party loggers
    for lib in ("asyncio", "PIL", "matplotlib"):
        logging.getLogger(lib).setLevel(logging.WARNING)

    return logger


def get_logger(module_name: str) -> logging.Logger:
    """Get a child logger under the 'furun' namespace."""
    return logging.getLogger(f"furun.{module_name}")


def get_data_path(*parts: str) -> Path:
    """Get a data file path that works in both source and frozen EXE modes.

    When frozen by PyInstaller, resolves relative to the EXE directory.
    When running from source, resolves relative to the project root (parent of common/).
    """
    if getattr(sys, "frozen", False):
        # PyInstaller extracts data files into sys._MEIPASS, not next to EXE
        base = Path(sys._MEIPASS)
    else:
        # Running from source: go up from common/ to project root
        base = Path(__file__).parent.parent
    return base.joinpath(*parts)

# --- Network Helpers ---

def is_ip_address(host: str) -> bool:
    """Check if a host string is a plain IP address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def resolve_host(host: str, port: int = 80) -> str:
    """Resolve a hostname to an IP address. Returns host unchanged if it is already an IP."""
    if is_ip_address(host):
        return host
    try:
        info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        if info:
            return info[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return host


def ip_in_network(ip_str: str, network_str: str) -> bool:
    """Check if an IP address belongs to a CIDR network."""
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(network_str)
    except ValueError:
        return False


    """Ensure a directory exists and return its Path."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


    """Return current UTC timestamp in ISO format."""
    return datetime.utcnow().isoformat() + "Z"
