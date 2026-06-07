# -*- mode: python ; coding: utf-8 -*-
"""
Furun VPN Server (GUI) - PyInstaller Spec (optimized)
"""

from pathlib import Path

project_root = Path(SPECPATH)

pyqt_hidden = [
    "PyQt6.QtCore",
    "PyQt6.QtGui",
    "PyQt6.QtWidgets",
    "PyQt6.sip",
]

a = Analysis(
    [str(project_root / "server" / "gui_main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=[],
    hiddenimports=[
        "common",
        "common.protocol",
        "common.crypto",
        "common.utils",
        "server.tunnel_server",
        "server.forward_proxy",
        "server.config",
        "server.console_main",
        "server.gui.server_window",
        "client.gui.log_viewer",
        "cryptography",
        "cryptography.hazmat.backends.openssl",
        "cryptography.hazmat.primitives",
        "cryptography.hazmat.primitives.asymmetric",
        "cryptography.x509",
    ] + pyqt_hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "PIL",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="FurunVPNServer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
