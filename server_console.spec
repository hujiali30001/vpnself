# -*- mode: python ; coding: utf-8 -*-
"""
Furun VPN Server (Console) - PyInstaller Spec
Lightweight server EXE with no GUI dependencies. ~11 MB.
"""

from pathlib import Path

project_root = Path(SPECPATH)

a = Analysis(
    [str(project_root / "server" / "console_main.py")],
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
        "cryptography",
        "cryptography.hazmat.backends.openssl",
        "cryptography.hazmat.primitives",
        "cryptography.hazmat.primitives.asymmetric",
        "cryptography.x509",
    ],
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
        "PyQt6",
        "PyQt6.sip",
        "client",
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
    name="FurunVPNServer_Console",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

