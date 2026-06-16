"""
Furun VPN - Client Entry Point

Launches the PyQt GUI application with proper logging configuration.
"""

import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QTimer

from common.utils import setup_logging, create_qt_handler, get_logger
from client.config.settings import load_config as load_client_config
from client.gui.main_window import MainWindow


def main():
    # High-DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("Furun VPN")
    app.setOrganizationName("Furun")
    app.setQuitOnLastWindowClosed(False)

    # Load config early for log level
    config = load_client_config()
    log_level = getattr(logging, config.get("log_level", "INFO"))

    # Setup logging BEFORE creating the window
    # Use EXE directory when frozen, source dir when running from source
    if getattr(sys, "frozen", False):
        log_dir = Path(sys.executable).parent / "logs"
    else:
        log_dir = Path(__file__).parent / "logs"
    setup_logging(
        "furun",
        level=log_level,
        log_dir=log_dir,
        console=True,
        file_rotate=True,
        log_name="client",
        debug_file=False,
        qt_handler=None,  # Wired after window creation
    )
    log = get_logger("client.main")
    log.info("=" * 60)
    log.info("Furun VPN Client starting...")
    log.info("Log level: %s", config.get("log_level", "INFO"))
    log.info("Log dir: %s", log_dir)
    log.info("=" * 60)

    # Create main window
    window = MainWindow()

    # Wire Qt log handler
    qt_handler = create_qt_handler(window.log_message)
    logging.getLogger("furun").addHandler(qt_handler)
    log.debug("Qt log handler attached to GUI")

    window.show()

    # Auto-connect if configured
    if config.get("auto_connect", False):
        log.info("Auto-connect enabled, triggering connection...")
        QTimer.singleShot(1000, window._toggle_connection)

    exit_code = app.exec()

    log.info("Furun VPN Client shutting down (exit code: %d)", exit_code)
    window.cleanup()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
