#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""The environment, one Wine session per app run, the main thread; no compiler needed.

1. Wine's start-up copy of the host environment (env_ios.c get_initial_environment) walks
   `environ` without libc's lock, and the app's code writes the same array: a setenv that grows
   it would free it under the walk. The walk holds madeira_env_lock; writes the app makes once
   Wine runs go through madeira_env_set / madeira_env_unset (WineProcessBridge.m), which take
   that lock and log each name once. Those writers: the debugger detach (MADEIRA_DETACHED, after
   Wine started), MadeiraDock.cleanup (a failed start, Quit), and the session-end block.
2. Settings read once per app run (about 60 getenv switches cached in ntdll, win32u, the
   wineserver and Winios) keep the first session's values, and the wineserver keeps its
   permanent objects. One Wine session per app run is enforced where every session starts
   (ContentView.runWineFullSequence), not only by the library.
3. winios_metal_layer_for_hwnd and winios_vulkan_layer_for_hwnd waited for the main thread with
   dispatch_sync, without a limit, from a Wine thread that may hold Wine or DXMT locks. Both
   run on the main thread through one bounded wait, and their callers handle a layer that did
   not come (the swapchain fails instead of the app hanging).
Needs python3 only.
"""
from pathlib import Path
import re, sys

root = Path(__file__).resolve().parents[2]
failures = 0


def check(cond, what):
    global failures
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        failures += 1


def body(text, start):
    t = text[text.index(start):]
    return t[:t.index("\n}\n")]


# ---- 1. the environment
env = (root / "build/ntdll-unix/env_ios.c").read_text(errors="replace")
outer = body(env, "static WCHAR *get_initial_environment( SIZE_T *pos, SIZE_T *size )\n{")
check(outer.index("madeira_env_lock();") < outer.index("get_initial_environment_locked( pos, size );")
      < outer.index("madeira_env_unlock();"), "the environment walk holds madeira_env_lock")
code = re.sub(r"/\*.*?\*/", "", env, flags=re.S)
walks = [m.start() for m in re.finditer(r"for \((?:char \*\*)?e = environ;", code)]
locked = code[code.index("static WCHAR *get_initial_environment_locked( SIZE_T *pos, SIZE_T *size )\n{"):]
locked = locked[:locked.index("\n}\n")]
host = code[code.index("static BOOL host_var_exists("):]
host = host[:host.index("\n}\n")]
check(len(walks) == 3 and all(code[w:w + 40] in locked or code[w:w + 40] in host for w in walks),
      "every raw walk of environ is in the locked function or host_var_exists")
check(len(re.findall(r"\bhost_var_exists\(", code)) == 2 and "host_var_exists( str )" in locked,
      "host_var_exists is only reached from the locked walk")

bridge = (root / "app/Madeira/WineProcessBridge.m").read_text()
for fn in ("int madeira_env_set(const char *name, const char *value) {", "int madeira_env_unset(const char *name) {"):
    b = body(bridge, fn)
    check(b.index("madeira_env_lock();") < b.index("env(name") < b.index("madeira_env_unlock();") and "madeira_env_note(name);" in b,
          fn.split("(")[0].split()[-1] + " takes the walk's lock and logs the name")
end = bridge[bridge.index("        g_wine_running = 0;\n        /* ml1184:"):bridge.index("        // Stop wineserver to prevent CPU spin")]
check("unsetenv(" not in end.replace("madeira_env_unset(", "") and end.count("madeira_env_unset(") >= 10,
      "the session-end block unsets through madeira_env_unset (Wine's other threads still run there)")
header = (root / "app/Madeira/WineProcessBridge.h").read_text()
check("int madeira_env_set(const char *name, const char *value);" in header and "int madeira_env_unset(const char *name);" in header,
      "Swift sees the wrappers")
stik = (root / "app/Madeira/StikJITHelper.swift").read_text()
detach = stik[stik.index("    static func detachDebugger() {"):]
detach = detach[:detach.index("\n    }\n")]
check('madeira_env_set("MADEIRA_DETACHED", "1")' in detach and 'setenv("MADEIRA_DETACHED"' not in detach,
      "the debugger detach (after Wine started) writes through the wrapper")
dock = (root / "app/Madeira/MadeiraDock.swift").read_text()
cleanup = dock[dock.index("    @MainActor static func cleanup() {"):]
cleanup = cleanup[:cleanup.index("\n    }\n")]
check('madeira_env_unset("MADEIRA_DOCK_AUTH_FILE")' in cleanup and "unsetenv(" not in cleanup,
      "MadeiraDock.cleanup (called while a session runs) unsets through the wrapper")

# ---- 2. one session per run
content = (root / "app/Madeira/ContentView.swift").read_text()
seq = content[content.index("    private func runWineFullSequence(profile: LibraryEntry? = nil) {"):]
check(seq.index("if Self.wineSessionsThisRun > 0 {") < seq.index("guard jit_check_debugged()")
      and 'guard !MadeiraConfig.flag("MADEIRA_ONE_SESSION_PER_RUN") else {' in seq[:seq.index("guard jit_check_debugged()")],
      "every Wine session start checks the one-session rule first")
start = content[content.index("    private func startWineProcess() {"):]
start = start[:start.index("\n    }\n")]
check(start.index("let result = wine_process_start(winePrefixPath)") < start.index("Self.wineSessionsThisRun += 1"),
      "a started Wine session is counted")

# ---- 3. the main thread
winios = (root / "app/Madeira/Winios/Winios.m").read_text()
helper = body(winios, "static BOOL winios_run_on_main_bounded(void (^make)(void), const char *what, void *hwnd) {")
check("dispatch_sync(" not in helper and "dispatch_semaphore_wait(made, dispatch_time(" in helper and "return NO;" in helper,
      "the main-thread run waits with a bound")
for fn in ("CAMetalLayer *winios_metal_layer_for_hwnd(void *hwnd) {", "CAMetalLayer *winios_vulkan_layer_for_hwnd(void *hwnd) {"):
    b = body(winios, fn)
    check("dispatch_sync(" not in b and "winios_run_on_main_bounded(make, " in b and "return nil;" in b,
          fn.split("(")[0].split("*")[-1] + " makes its layer through the bounded run")
check(re.search(r"#define WINIOS_LAYER_WAIT_S (\d+)", winios) and 0 < int(re.search(r"#define WINIOS_LAYER_WAIT_S (\d+)", winios).group(1)) <= 30,
      "the bound is a few seconds")
shim = (root / "app/Madeira/IOSDisplayShim.m").read_text()
check("CAMetalLayer *layer = winios_metal_layer_for_hwnd(hwnd);\n        if (!layer)" in shim
      and "CAMetalLayer *layer = winios_vulkan_layer_for_hwnd(hwnd);\n        return layer ? " in shim,
      "both callers handle no layer (the swapchain creation fails)")

print("FAILED: %d" % failures if failures else "PASS: the environment lock, one session per run, the bounded layer wait")
sys.exit(1 if failures else 0)
