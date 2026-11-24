#!/usr/bin/env python3
"""DXMT's Direct3D 9 format gate lets the luminance formats be render targets
(dxmt 3d62913: e82c864 + 3d62913), while keeping them out of StretchRect
format conversions.

A program that builds one-channel targets (ambient occlusion, blur passes,
masks) through its engine's format table asks CreateTexture for D3DFMT_L8
with D3DUSAGE_RENDERTARGET. isColorRTFormat() in dxmt/src/d3d9/d3d9_format.cpp
refused it ("CreateTexture: format 50 not render-target-capable"), the
engine got no target and the program sat on its loading screen with both of
its threads parked. Native drivers and DXVK allow L8 targets: the storage
(R8Unorm) is colour-renderable on every Metal GPU.

Checks, on the pinned DXMT source:
  - isColorRTFormat() returns true for D3DFMT_L8, D3DFMT_A8L8 and D3DFMT_L16
    behind the MADEIRA_D3D9_LUMINANCE_RT switch (0 = refuse, as before);
  - the three formats still map to a colour-renderable Metal format for the
    render-target usage (D3DFormatToMetal only rejects them for depth);
  - CheckDeviceFormatConversionProbe() excludes D3DFMT_L8, D3DFMT_A8L8 and
    D3DFMT_L16 from StretchRect conversions on both source and destination
    sides (3d62913, matching wined3d's conversion table);
  - the config catalog carries env.MADEIRA_D3D9_LUMINANCE_RT (default 1).
"""
from pathlib import Path
import re
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
dxmt = root / 'dxmt'


def dxmt_git_cmd(*args: str):
    if not shutil.which('git'):
        return None
    if (dxmt / '.git').exists():
        return ['git', '--no-optional-locks', '-C', str(dxmt), *args]
    common = subprocess.run(['git', '--no-optional-locks', 'rev-parse', '--git-common-dir'],
                            cwd=root, capture_output=True, text=True)
    if common.returncode == 0:
        mod = (root / common.stdout.strip()).resolve() / 'modules/dxmt'
        if mod.is_dir():
            return ['git', '--no-optional-locks', f'--git-dir={mod}', '--work-tree=/tmp', *args]
    return None


def read_dxmt_file(rel: str) -> str:
    """Read from the repository's pinned dxmt commit when git is available so
    a worktree whose shared dxmt checkout sits on another commit still tests
    the recorded pin without touching that checkout."""
    if dxmt_git_cmd('rev-parse', '--git-dir') is not None:
        ls = subprocess.run(['git', '--no-optional-locks', 'ls-files', '-s', 'dxmt'], cwd=root,
                            capture_output=True, text=True)
        parts = ls.stdout.split()
        pin = parts[1] if len(parts) >= 2 else 'HEAD'
        show = subprocess.run(dxmt_git_cmd('show', f'{pin}:{rel}'),
                              capture_output=True, text=True)
        if show.returncode == 0:
            return show.stdout
    return (dxmt / rel).read_text(encoding='utf-8', errors='replace')


fmt = read_dxmt_file('src/d3d9/d3d9_format.cpp')
iface = read_dxmt_file('src/d3d9/d3d9_interface.cpp')
catalog = (root / 'app/Madeira/ConfigCatalog.generated.swift').read_text(encoding='utf-8', errors='replace')
failures = []


def check(cond, what):
    if not cond:
        failures.append(what)
        print('FAIL:', what)


m = re.search(r'\nbool\nisColorRTFormat\(D3DFORMAT format\) \{(.*?)\n\}\n', fmt, re.S)
check(m, 'isColorRTFormat() not found')
body = m.group(1) if m else ''
lum = re.search(r'case D3DFMT_L8:\s*case D3DFMT_A8L8:\s*case D3DFMT_L16: \{(.*?)\n  \}', body, re.S)
check(lum, 'isColorRTFormat() lacks the L8 / A8L8 / L16 case')
if lum:
    check('env::getEnvVar("MADEIRA_D3D9_LUMINANCE_RT") != "0"' in lum.group(1)
          and 'return luminanceRT;' in lum.group(1),
          'the luminance case must return the MADEIRA_D3D9_LUMINANCE_RT switch (default on)')
check('#include "util_env.hpp"' in fmt, 'd3d9_format.cpp must include util_env.hpp for the switch')

for name, metal in (('D3DFMT_L8', 'WMTPixelFormatR8Unorm'), ('D3DFMT_A8L8', 'WMTPixelFormatRG8Unorm'),
                    ('D3DFMT_L16', 'WMTPixelFormatR16Unorm')):
    mm = re.search(r'case %s:.*?return usage == D3D9FormatUsage::DepthStencil \? WMTPixelFormatInvalid : (\w+);'
                   % name, fmt, re.S)
    check(mm and mm.group(1) == metal,
          '%s must map to %s for every usage but depth (got %s)' % (name, metal, mm.group(1) if mm else None))

probe = re.search(r'MTLD3D9Interface::CheckDeviceFormatConversionProbe\((.*?)\n\}\n', iface, re.S)
check(probe is not None, 'CheckDeviceFormatConversionProbe() not found in d3d9_interface.cpp')
if probe:
    pbody = probe.group(1)
    check('isColorRTFormat(f) && f != D3DFMT_L8 && f != D3DFMT_A8L8 && f != D3DFMT_L16' in pbody
          and 'simple_rgb(SourceFormat)' in pbody and 'simple_rgb(TargetFormat)' in pbody,
          'CheckDeviceFormatConversionProbe() must exclude L8 / A8L8 / L16 from StretchRect conversions on both sides')

check('key: "env.MADEIRA_D3D9_LUMINANCE_RT"' in catalog and 'defaultValue: "1"' in
      catalog[catalog.find('key: "env.MADEIRA_D3D9_LUMINANCE_RT"'):][:400],
      'ConfigCatalog.generated.swift lacks env.MADEIRA_D3D9_LUMINANCE_RT (default 1)')

if failures:
    print('%d failure(s)' % len(failures))
    sys.exit(1)
print('OK: L8 / A8L8 / L16 render targets allowed behind MADEIRA_D3D9_LUMINANCE_RT, StretchRect excluded')
