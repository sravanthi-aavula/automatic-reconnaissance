
# -*- mode: python ; coding: utf-8 -*-
block_cipher = None
a = Analysis(
    ['C:/Users/srava/Downloads/Supraja_project/Supraja_project/2.py'],
    pathex=[],
    binaries=[],
    datas=[ ('output', 'output') ],
    hiddenimports=['whois', 'dns.resolver', 'requests', 'bs4', 'builtwith', 'cryptography', 'selenium', 'fpdf'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='recon_tool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='recon_tool',
)
