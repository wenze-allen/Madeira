#!/usr/bin/env python3
"""Every port function the native code declares extern has a definition the app link can find.

The 21e6697 app link stopped on four undefined symbols that no host check had seen:
ios_addr_max_prot (called by an upstream pick whose definition came in a later upstream
commit), ios_atom_arg (called by the wine pin, defined by an upstream class_ios.c change not
taken) and madeira_frame_mark / madeira_swap_overlay_stats (called by the dxmt pin, defined
with upstream app features not carried; declared weak, which ld64 still has to resolve).

Static scan, no compiler: the `extern` function declarations named ios_*, madeira_*, winios_*
or wine_ios_* in the native sources the app links (build/*-unix, the wineserver, wine's ntdll,
win32u and server, DXMT's unix side, madeira-d3d12's unix side, app/Madeira) must each have a
non-static definition somewhere in those trees: a C, Objective-C or C++ function body
(extern "C" included), or a Swift @_cdecl. A static definition does not count: it cannot satisfy
another file's reference (wine/dlls/win32u/window.c's non-iOS ios_atom_arg is one).
"""
import re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DECL_ROOTS = ['build/ntdll-unix', 'build/win32u-unix', 'build/wineserver', 'build/crypto-unix', 'build/wineios-drv',
              'dxmt/src/winemetal/unix', 'dxmt/src/nativemetal', 'wine/dlls/win32u', 'wine/dlls/ntdll/unix',
              'wine/server', 'madeira-d3d12/src/unix', 'app/Madeira']
DEF_ROOTS = ['build', 'dxmt/src', 'madeira-d3d12/src', 'app', 'wine/dlls/win32u', 'wine/dlls/ntdll/unix', 'wine/server']
EXTS = {'.c', '.m', '.mm', '.cpp', '.h', '.swift'}
DECL = re.compile(r'\bextern\s+(?:"C"\s+)?[\w\s\*]*?\b((?:ios|madeira|winios|wine_ios)_\w+)\s*\([^;{]*?\)'
                  r'\s*(?:__attribute__\s*\(\([^;]*?\)\)\s*)*;', re.S)
failures = 0


def check(cond, text):
    global failures
    print(('PASS: ' if cond else 'FAIL: ') + text)
    if not cond:
        failures += 1


texts = {}
for root in DEF_ROOTS + DECL_ROOTS:
    base = ROOT / root
    if not base.exists():
        continue
    for p in base.rglob('*'):
        if p.suffix in EXTS and p not in texts and p.is_file():
            texts[p] = p.read_text(encoding='utf-8', errors='replace')

decls = {}
for p, t in texts.items():
    rel = p.relative_to(ROOT).as_posix()
    if p.suffix != '.swift' and any(rel.startswith(d + '/') for d in DECL_ROOTS):
        for m in DECL.finditer(t):
            decls.setdefault(m.group(1), set()).add(rel)


def definition(name):
    body = re.compile(r'^(?:extern\s+"C"\s+)?(?!extern\b|static\b|#|//|/\*| \*|\s)[^\n;]*?\b%s\s*\(' % re.escape(name), re.M)
    for p, t in texts.items():
        if name not in t:
            continue
        if p.suffix == '.swift':
            if '@_cdecl("%s")' % name in t:
                return p
            continue
        for m in body.finditer(t):
            rest = t[m.end():m.end() + 4000]
            brace, semi = rest.find('{'), rest.find(';')
            if brace >= 0 and (semi < 0 or brace < semi):
                return p
    return None


check(len(decls) > 100, '%d extern port functions declared in the linked native sources' % len(decls))
missing = [(n, sorted(f)) for n, f in sorted(decls.items()) if not definition(n)]
for name, files in missing:
    print('    no definition: %s (declared in %s)' % (name, ', '.join(files[:3])))
check(not missing, 'each has a non-static definition (%d without)' % len(missing))

print(f'check-native-link-externs: {"OK" if not failures else f"{failures} FAILED"}')
sys.exit(1 if failures else 0)
