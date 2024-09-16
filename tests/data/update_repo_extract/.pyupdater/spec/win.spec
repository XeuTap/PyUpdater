# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\TRAFOLO\\repo\\pyupdater_source\\tests\\data\\update_repo_extract\\app_extract_01.py'],
    pathex=['C:\\TRAFOLO\\repo\\pyupdater_source\\tests\\data\\update_repo_extract', 'C:\\TRAFOLO\\repo\\pyupdater_source\\tests\\data\\update_repo_extract'],
    binaries=[('C:\\TRAFOLO\\repo\\pyupdater_source\\tests\\data\\update_repo_extract\\updater.exe', '.')],
    datas=[],
    hiddenimports=[],
    hookspath=['C:\\TRAFOLO\\repo\\pyupdater_source\\pyupdater\\hooks'],
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
    name='win',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
