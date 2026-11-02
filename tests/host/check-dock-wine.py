#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""The built Madeira Dock host (dockhost.exe) under desktop Wine: its report on the paths that
need no Steam client.

madeira-dock/src/main.c writes host-result on every exit path BEFORE Valve's client is shut down
(no time limit) and probe-result after it; the app ends a start at host-result. Runs, each in a
new Wine prefix:
  1. no Steam client folder: client-file-or-identity-error, host-result=20, probe-result=20,
     exit code 20, host-result before probe-result;
  2. a client folder whose steamclient64.dll is not a pinned build: refused by the identity check
     without being loaded, the same order;
  3. --start-services: Wine's service manager answers ("services already" -- desktop Wine starts
     services.exe with any program; only Madeira's iOS Wine needs it started).
A session with Valve's client needs Valve's files and is not run.

Needs wine and dockhost.exe: app/Madeira/arm64ec-windows/dockhost.exe (gitignored), else built
with build/madeira-dock/build.sh when LLVM_MINGW names an llvm-mingw bin folder. Prints NOTOOL
and exits 3 without them.
"""
from pathlib import Path
import os, shutil, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
exe = root / "app/Madeira/arm64ec-windows/dockhost.exe"
wine = shutil.which("wine")
if not wine:
    print("NOTOOL: no wine")
    sys.exit(3)
if os.environ.get("LLVM_MINGW"):
    subprocess.run(["bash", str(root / "build/madeira-dock/build.sh")], check=True, stdout=subprocess.DEVNULL)
if not exe.exists():
    print("NOTOOL: no dockhost.exe (set LLVM_MINGW to an llvm-mingw bin folder to build it)")
    sys.exit(3)

failures = 0


def check(cond, what):
    global failures
    print(("PASS " if cond else "FAIL ") + what, flush=True)
    if not cond:
        failures += 1


def fields(text):
    out = []
    for line in text.replace("\r", "").splitlines():
        parts = line.split(" ")
        if len(parts) == 3 and parts[0] == "[steam-host]" and "=" in parts[2]:
            out.append(tuple(parts[2].split("=", 1)))
    return out


prefix = tempfile.mkdtemp(prefix="madeira-dock-wine-")
env = dict(os.environ, WINEPREFIX=prefix, WINEDEBUG="-all", WINEDLLOVERRIDES="mscoree,mshtml=")
env.pop("DISPLAY", None)
try:
    subprocess.run(["wineboot", "-i"], env=env, check=True, capture_output=True, timeout=600)
    drive = Path(prefix) / "drive_c"
    shutil.copy(exe, drive / "dockhost.exe")
    report = drive / "madeira-dock.txt"

    def host(extra, *args):
        if report.exists():
            report.unlink()
        r = subprocess.run([wine, "C:\\dockhost.exe", *args], env=dict(env, **extra), capture_output=True,
                           text=True, timeout=300)
        return r, (fields(report.read_text(errors="replace")) if report.exists() else [])

    base = {"MADEIRA_STEAM_HOST_PROBE": "1", "MADEIRA_STEAM_HOST_LOG": "C:\\madeira-dock.txt"}
    for name, extra in (("no Steam client folder", {}),
                        ("an unknown steamclient64.dll", {"MADEIRA_STEAM_HOST_CLIENT_DIR": "C:\\FakeSteam"})):
        if extra:
            (drive / "FakeSteam").mkdir(exist_ok=True)
            (drive / "FakeSteam/steamclient64.dll").write_bytes(os.urandom(4096))
        r, f = host(dict(base, **extra))
        keys = [k for k, _ in f]
        value = dict(f)
        check("host-result" in keys and "probe-result" in keys and keys.index("host-result") < keys.index("probe-result")
              and keys[-1] == "probe-result", "%s: host-result, then probe-result last (%s)" % (name, " ".join(keys)))
        check(value.get("host-result") == value.get("probe-result") == "20" and r.returncode == 20 and "client-file-or-identity-error" in value,
              "%s: refused at the client check, result 20, exit %d" % (name, r.returncode))
        check("load-client-begin" not in value, "%s: nothing was loaded" % name)
    r = subprocess.run([wine, "C:\\dockhost.exe", "--start-services"], env=env, capture_output=True, text=True, timeout=300)
    out = r.stdout.replace("\r", "").strip()
    check(r.returncode == 0 and out in ("services already", "services started"),
          "--start-services: Wine's service manager answers (%r, exit %d)" % (out, r.returncode))
finally:
    subprocess.run(["wineserver", "-k"], env=env, capture_output=True)
    shutil.rmtree(prefix, ignore_errors=True)

print("FAILED: %d" % failures if failures else "PASS: dockhost.exe under Wine reports host-result before probe-result")
sys.exit(1 if failures else 0)
