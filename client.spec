# -*- mode: python ; coding: utf-8 -*-
"""
Furun VPN Client - PyInstaller Spec (optimized)
"""

from pathlib import Path

project_root = Path(SPECPATH)

# Only the Qt modules we actually use - no need to scan all 200+ submodules
pyqt_hidden = [
    "PyQt6.QtCore",
    "PyQt6.QtGui",
    "PyQt6.QtWidgets",
    "PyQt6.sip",
]

a = Analysis(
    [str(project_root / "client" / "main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=[],
    hiddenimports=[
        "common",
        "common.protocol",
        "common.crypto",
        "common.utils",
        "client.core.tunnel",
        "client.core.http_proxy",
        "client.core.router",
        "client.core.rule_engine",
        "client.core.geoip",
        "client.core.circuit_breaker",
        "client.config.settings",
        "client.gui.styles",
        "client.gui.rule_editor",
        "client.gui.log_viewer",
        "client.gui.main_window",
        "cryptography",
        "cryptography.hazmat.backends.openssl",
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
    name="FurunVPN",
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
