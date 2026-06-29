# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = []
hiddenimports += collect_submodules('flask')
hiddenimports += collect_submodules('werkzeug')
# M10: 방화벽 클라이언트가 함수 내부에서 lazy import하므로 명시 (FortiGate REST/SSH).
hiddenimports += ['requests', 'paramiko']
hiddenimports += collect_submodules('netmiko')


a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=[('web', 'web'), ('config.yaml', '.'), ('fixtures', 'fixtures')],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='netdash',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # SEC: Visible console = transparent process. A hidden background
                   # server that opens network ports + auto-launches a browser looks like
                   # a backdoor/dropper to EDR/SmartScreen. A console window makes the
                   # process visible and user-controllable (close window to stop).
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
