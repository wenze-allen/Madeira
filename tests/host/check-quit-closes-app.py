#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Quit game and the starting screen's Close session close Madeira; no Swift needed.

A second Wine session cannot start in one app run (LibraryModel.sessionsThisRun), and
Quit used to send only Alt+F4: the game closed, Madeira stayed open, and the next game
asked for a restart. "Upload saves and close Madeira" already ended the app (exit(0)).
Quit still asks the game first, so it can save; Madeira then closes when the session
ends, or LibraryModel.closeGrace s after the game stopped running when the rest of
Windows does not end by itself (a Dock host still shutting Steam down, or stuck).
Needs python3 only.
"""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[2]
library = (root / 'app/Madeira/Library.swift').read_text(encoding='utf-8')
failures = 0


def require(condition, label):
    global failures
    print(('PASS: ' if condition else 'FAIL: ') + label)
    if not condition:
        failures += 1


def body(source, start):
    text = source[source.index(start):]
    return text[:text.index('\n    }\n')]


quit = body(library, '    func requestQuit() {')
require('winios_post_key(0x12, 1); winios_post_key(0x73, 1)' in quit and 'closing = Self.quitClosesApp' in quit
        and quit.index('winios_post_key(0x73, 1)') < quit.index('closing = Self.quitClosesApp'),
        'Quit asks the game to close (Alt+F4) first, then waits to close Madeira')
require('MadeiraConfig.flag("MADEIRA_QUIT_CLOSES_APP")' in library, 'MADEIRA_QUIT_CLOSES_APP=0 keeps the old Quit')

finish = body(library, '    private func finish() {')
require(finish.rstrip().endswith('if closing { closeApp(reason: "the session ended after Quit") }'),
        'a session that ends after Quit closes Madeira, after the usual return to the library')
poll = body(library, '    private func poll() {')
require('wineserver_is_running() == 0 { finish(); return }' in poll and 'if closing { closeOnceStopped() }' in poll,
        'every poll after Quit checks whether the game still runs')

stopped = body(library, '    private func closeOnceStopped() {')
require('report.fields["launch-game-running"] == "1" && report.fields["launch-game-ended"] == nil' in stopped
        and 'report.launchResult == nil' in stopped and 'wine_process_is_running() != 0' in stopped,
        "a Dock session's game runs by the host's report; any other session's by the launched program")
require('if running { gameStoppedAt = nil; return }' in stopped and 'Date().timeIntervalSince(stopped) >= Self.closeGrace' in stopped,
        'Madeira closes closeGrace s after the game stopped, never while it runs (an exit dialog may be up)')

registry = (root / 'wine/server/registry.c')
grace = float(re.search(r'static let closeGrace = ([0-9.]+)', library).group(1))
if registry.exists():
    period = int(re.search(r'save_period = (\d+) \* -TICKS_PER_SEC', registry.read_text(errors='replace')).group(1))
    require(grace > period, f'the grace ({grace:g} s) outlasts the registry save period ({period} s)')
else:
    print('SKIP: wine not checked out; registry save period not compared')

close = body(library, '    func closeApp(reason: String) {')
require('guard !appClosing else { return }' in close and 'saveCurrentProfile()' in close
        and 'MadeiraDock.cleanup()' in close and 'exit(0)' in close
        and close.index('saveCurrentProfile()') < close.index('exit(0)')
        and close.index('MadeiraDock.cleanup()') < close.index('exit(0)'),
        "closing saves the game's profile and removes a Dock sign-in transfer first, once")

menu = library[library.index('                if model.closing {\n                    // Quit was pressed'):]
menu = menu[:menu.index('}.frame(maxWidth: .infinity, alignment: .leading).padding(22)')]
require('model.closeApp(reason: "Close Madeira now")' in menu and 'Label("Close Madeira now"' in menu
        and 'model.requestQuit()' in menu and 'Label("Quit game"' in menu,
        'the session menu offers Quit game, then Close Madeira now while Madeira waits')
require(library.count('model.closeApp(reason: "Close Madeira now")') == 3,
        'Close Madeira now is in the session menu and both starting-screen layouts')

print('FAILURES: %d' % failures if failures else 'PASS: Quit closes Madeira')
raise SystemExit(1 if failures else 0)
