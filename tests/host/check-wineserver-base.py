#!/usr/bin/env python3
"""build/wineserver/make-base.sh makes the base libwineserver.a that
build/wineserver/build.sh swaps its own objects into (the archive is
git-ignored and not published, so a clean checkout has none). Static checks:

  - make-base.sh compiles with build.sh's CC_FLAGS, entry for entry;
  - its BASE_SOURCES and the server objects build.sh replaces are disjoint,
    and together are every .c in wine/server/Makefile.in's SOURCES (a server
    source in neither list would be missing from the archive; one in both
    would be compiled twice);
  - build.sh runs make-base.sh when it finds no base archive.
"""
import re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
build = (ROOT / 'build/wineserver/build.sh').read_text()
base = (ROOT / 'build/wineserver/make-base.sh').read_text()
makefile = (ROOT / 'wine/server/Makefile.in').read_text()
failures = 0


def check(cond, text):
    global failures
    print(('PASS: ' if cond else 'FAIL: ') + text)
    if not cond:
        failures += 1


def array(src, name):
    m = re.search(r'^%s=\(\n(.*?)^\)' % name, src, re.M | re.S)
    if not m:
        return None
    lines = [l.strip() for l in m.group(1).splitlines() if not l.strip().startswith('#')]   # comment lines inside
    return ' '.join(lines).split()


cc_build, cc_base = array(build, 'CC_FLAGS'), array(base, 'CC_FLAGS')
check(cc_build is not None and cc_build == cc_base, "make-base.sh's CC_FLAGS are build.sh's")

sources = re.search(r'^SOURCES\s*=\s*\\\n(.*?)(?:\n\s*\n|\Z)', makefile, re.M | re.S).group(1)
server = {Path(s.strip().rstrip('\\').strip()).stem for s in sources.split('\n')
          if s.strip().rstrip('\\').strip().endswith('.c')}
base_sources = set(array(base, 'BASE_SOURCES') or [])
replaced = set()
for entry in array(build, 'PATCHED_FILES') or []:
    obj = entry.strip('"').split(':')[-1]
    if obj.endswith('.o') and obj[:-2] in server:
        replaced.add(obj[:-2])
check(len(server) > 30 and len(replaced) > 10, 'the server SOURCES and build.sh\'s replacements were read (%d, %d)'
      % (len(server), len(replaced)))
check(not (base_sources & replaced), 'no server source is in both lists: %s' % (sorted(base_sources & replaced) or '-'))
check(base_sources | replaced == server,
      'BASE_SOURCES and the replaced objects are every server source (missing %s, unknown %s)'
      % (sorted(server - base_sources - replaced) or '-', sorted(base_sources - server) or '-'))

m = re.search(r'if \[ ! -f "\$OBJ_DIR/libwineserver\.a" \]; then(.*?)\nfi\n', build, re.S)
check(m is not None and 'bash "$BUILD_DIR/make-base.sh"' in m.group(1)
      and m.group(1).index('cp "$APP_LIB"') < m.group(1).index('make-base.sh'),
      'build.sh copies an existing app archive, and otherwise runs make-base.sh')
check(re.search(r'^set -e$', build, re.M) is not None, 'build.sh stops when make-base.sh fails (set -e)')

print(f'check-wineserver-base: {"OK" if not failures else f"{failures} FAILED"}')
sys.exit(1 if failures else 0)
