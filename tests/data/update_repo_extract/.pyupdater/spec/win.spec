# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\TRAFOLO\\repo\\pyupdater_source\\tests\\data\\update_repo_extract\\app_extract_02.py'],
    pathex=['C:\\TRAFOLO\\repo\\pyupdater_source\\tests\\data\\update_repo_extract', 'C:\\TRAFOLO\\repo\\pyupdater_source\\tests\\data\\update_repo_extract'],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=['C:\\TRAFOLO\\repo\\pyupdater_source\\pyupdater\\hooks'],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='win',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='win',
)
