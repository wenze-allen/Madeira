#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Runs every tests/host/check-*.py and sorts the results; exit 1 when any check fails.

  PASS     the check exited 0;
  NOTOOL   it stopped because a tool this machine lacks is missing (swift / swiftc / xcrun, a
           configured Wine tree) and printed no FAIL line before, or its only failure is
           compiling production Swift that imports an Apple-only module (needs macOS);
  FAIL     everything else -- including a check that printed a FAIL line and THEN stopped on a
           missing tool: its text-level assertions ran, and one of them failed;
  FLAKY    failed while the others ran beside it, passed when run again alone (a timing-sensitive
           check under load, e.g. check-fastsync.py's semaphore race); reported, not a failure.

The last rule is the one a by-hand count got wrong: check-dock-start-screen.py's source
assertions run before it needs swiftc, so a broken assertion there read as "no swiftc".

  python3 tests/host/run-all.py [-j N] [--only REGEX] [--notool-ok]

--notool-ok: NOTOOL does not fail the run (the default: it does not; use --strict to make
NOTOOL fail too, for a machine that is meant to have every tool, such as macOS CI).
"""
from pathlib import Path
import argparse, concurrent.futures, os, re, subprocess, sys, time

here = Path(__file__).resolve().parent
NOTOOL = [
    r"No such file or directory: '[^']*\b(swiftc|swift|xcrun|xcodebuild)'",
    r"FileNotFoundError: \[Errno 2\] No such file or directory: '[^']*swiftly[^']*'",
    r"SKIP-FAIL: .*(config\.h is missing|configured Wine)",
    r"\b(xcrun|swiftc): (command )?not found",
    r"^NOTOOL: ",          # a check that says so itself (check-dock-wine.py: no wine / no dockhost.exe)
]
# Swift on a non-Apple host has no Apple frameworks: a check whose only failure is compiling
# production code that imports one needs macOS (its FAIL line is that compile step).
APPLE_ONLY = r"error: no such module '(Darwin|CryptoKit|UIKit|SwiftUI|AppKit|Network|AVFoundation|GameController|Metal|QuartzCore|CoreGraphics|os)'"


def run(path, timeout):
    t0 = time.time()
    try:
        r = subprocess.run([sys.executable, str(path)], capture_output=True, text=True, timeout=timeout,
                           cwd=str(here.parents[1]))
        out, code = r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired as e:
        out, code = (e.stdout or "") + (e.stderr or "") if isinstance(e.stdout, str) else "", "timeout"
    dt = time.time() - t0
    if code == 0:
        return "PASS", dt, ""
    fail_lines = [l for l in out.splitlines() if re.match(r"\s*FAIL\b", l)]
    notool = any(re.search(p, out, re.M) for p in NOTOOL)
    if notool and not fail_lines:
        return "NOTOOL", dt, next(l for l in out.splitlines()[::-1] if any(re.search(p, l, re.M) for p in NOTOOL))
    apple = re.search(APPLE_ONLY, out)
    if apple and fail_lines and all("compile" in l for l in fail_lines):
        return "NOTOOL", dt, "needs macOS: Swift here has no module %s" % apple.group(1)
    reason = fail_lines[0] if fail_lines else (out.strip().splitlines() or ["exit %s" % code])[-1]
    return "FAIL", dt, reason[:300]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-j", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--only", default="")
    ap.add_argument("--strict", action="store_true", help="NOTOOL fails the run")
    ap.add_argument("--timeout", type=int, default=1800)
    a = ap.parse_args()
    checks = sorted(p for p in here.glob("check-*.py") if re.search(a.only, p.name))
    results = {}
    with concurrent.futures.ThreadPoolExecutor(a.j) as pool:
        futures = {pool.submit(run, p, a.timeout): p for p in checks}
        for f in concurrent.futures.as_completed(futures):
            p = futures[f]
            results[p.name] = f.result()
            print("%-7s %6.1fs  %s%s" % (results[p.name][0], results[p.name][1], p.name,
                                          ("  -- " + results[p.name][2]) if results[p.name][0] != "PASS" else ""), flush=True)
    for name in sorted(n for n, v in results.items() if v[0] == "FAIL"):
        again = run(here / name, a.timeout)
        if again[0] == "PASS":
            results[name] = ("FLAKY", again[1], "failed beside the others (%s), passed alone" % results[name][2][:120])
            print("FLAKY   %s  -- %s" % (name, results[name][2]), flush=True)
    counts = {k: sum(1 for v in results.values() if v[0] == k) for k in ("PASS", "NOTOOL", "FAIL", "FLAKY")}
    print("\n%d checks: %d PASS, %d NOTOOL, %d FAIL, %d FLAKY" % (len(results), counts["PASS"], counts["NOTOOL"],
                                                                counts["FAIL"], counts["FLAKY"]))
    for name in sorted(n for n, v in results.items() if v[0] == "FAIL"):
        print("  FAIL   %s: %s" % (name, results[name][2]))
    sys.exit(1 if counts["FAIL"] or (a.strict and counts["NOTOOL"]) else 0)


if __name__ == "__main__":
    main()
