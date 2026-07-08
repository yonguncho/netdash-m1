# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules, collect_all

hiddenimports = []
hiddenimports += collect_submodules('flask')
hiddenimports += collect_submodules('werkzeug')
hiddenimports += ['requests']
# 웹 SSH 터미널(WebSocket)
hiddenimports += ['flask_sock', 'simple_websocket', 'wsproto']
# PPTX 구성도 자동 생성
hiddenimports += ['pptx', 'PIL', 'PIL.Image', 'PIL.ImageDraw', 'PIL.ImageFont']
_pptx_d, _pptx_b, _pptx_h = collect_all('pptx')
datas += _pptx_d; binaries += _pptx_b; hiddenimports += _pptx_h
# DPAPI 자격증명 암호화(win32crypt). 미번들 시 암호화가 None→자격증명 저장 실패.
hiddenimports += ['win32crypt', 'win32api', 'pywintypes']

datas = [('web', 'web'), ('config.yaml', '.'), ('fixtures', 'fixtures')]
binaries = []

# 스위치/방화벽 SSH·REST가 함수 내부에서 lazy import → 전체 수집 필요.
# netmiko는 서브모듈 + ntc-templates 데이터 파일까지 있어야 동작(collect_all).
for _pkg in ('netmiko', 'paramiko'):
    _d, _b, _h = collect_all(_pkg)
    datas += _d
    binaries += _b
    hiddenimports += _h


a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
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
