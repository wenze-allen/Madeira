#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Every field the pinned Dock host writes to its report is one the app keeps; no Swift needed.

The host (madeira-dock src/*.c) writes `[steam-host] <round> <field>=<number>`
lines; the app (app/Madeira/MadeiraDock.swift) keeps only the fields on its
allow-list. The two lists lived in two repositories with nothing comparing
them, and 40 of the 130 fields the host writes were dropped, among them
launch-request-submitted, launch-game-running and launch-host-result: the
starting screen could not tell "Steam accepted the launch" or "the game is
running" from "License confirmed", and saw the end of a launch only once
Valve's client had shut down.

Fields the app does not keep on purpose:
  - install-scm*: written by `dockhost.exe --start-services` (round ml2014) to
    stderr only, before any report file is opened (check-dock-report.py);
  - session-callback-id: kept as the one field session-callback-ids.
Needs python3 only.
"""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[2]
host = root / 'madeira-dock/src'
if not host.exists():
    print('SKIP: madeira-dock not checked out; report field cross-check not run')
    raise SystemExit(0)

written = set()
for path in sorted(host.glob('*.c')):
    source = path.read_text()
    written |= set(re.findall(r'\bevent\("([A-Za-z0-9_-]+)"', source))
    written |= set(re.findall(r'\bsymbol\(module, "([A-Za-z0-9_]+)"\)', source))
    written |= set(re.findall(r'\bstart_manager\(o, &manager, "([a-z0-9-]+)"\)', source))
# Every o->event / event call names its field with a literal, or is one of the two
# forwarding helpers whose callers are counted above.
for path in sorted(host.glob('*.c')):
    for line in path.read_text().splitlines():
        call = re.search(r'\bevent\(([^",)][^,]*),', line)
        if call and 'static void event(' not in line:
            assert call.group(1).strip() in ('name', 'started_stage'), f'{path.name}: field not a literal: {line.strip()}'

app = (root / 'app/Madeira/MadeiraDock.swift').read_text()
listing = app[app.index('static let reportAllowed: Set<String> = ['):]
listing = listing[:listing.index(']')]
allowed = set(re.findall(r'"([^"]+)"', re.sub(r'//[^\n]*', '', listing)))
assert 'key == "session-callback-id"' in app, 'session-callback-id is special-cased by the parser'

skipped = {f for f in written if f.startswith('install-scm')} | {'session-callback-id'}
missing = sorted(written - skipped - allowed)
assert not missing, f'host fields the app drops: {missing}'
assert len(written) > 100, f'only {len(written)} host fields found: the patterns no longer match the host'
print(f'PASS: all {len(written - skipped)} report fields the pinned host writes are kept by the app '
      f'({len(skipped)} deliberately not: {", ".join(sorted(skipped))})')
unused = sorted(allowed - written)
if unused:
    print(f'NOTE: allowed but not written by the pinned host: {", ".join(unused)}')
