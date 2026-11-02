#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""The split translation units of build/ntdll-unix stay one unit each; no compiler needed.

virtual_ios.c (34,063 lines) and signal_arm64_ios.c (15,964 lines) were split for size into
contiguous parts that the main file #includes at their places (virtual_ios_*.c,
signal_arm64_ios_*.c); the split moved text and changed nothing else. This keeps it that way:
  - every part is #included exactly once, by its own main file, and no part file is left over;
  - each part starts with its two-line header and is a whole preprocessor region: its #if / #endif
    balance, it never closes a conditional it did not open, and it does not end inside a comment
    or on a line continuation (an #include after it would be glued or swallowed);
  - neither build script compiles a part on its own;
  - tests/host/source_unit.py puts the parts back (what the other host checks read), and the
    result has each part's text exactly once, in order.
Needs python3 only.
"""
from pathlib import Path
import re, sys

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_unit import PART_LINE, part_body, parts, unit_text

d = root / "build/ntdll-unix"
failures = 0


def check(cond, what):
    global failures
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        failures += 1


def strip_code(line, in_comment):
    out, i = [], 0
    while i < len(line):
        if in_comment:
            j = line.find("*/", i)
            if j < 0: return "".join(out), True
            i, in_comment = j + 2, False
        elif line.startswith("/*", i): in_comment, i = True, i + 2
        elif line.startswith("//", i): break
        elif line[i] in "\"'":
            q, i = line[i], i + 1
            while i < len(line) and line[i] != q: i += 2 if line[i] == "\\" else 1
            i += 1
        else: out.append(line[i]); i += 1
    return "".join(out), in_comment


def region_ok(text):
    """Balanced conditionals, never below the start, not ending in a comment or a continuation."""
    depth, low, in_comment = 0, 0, False
    for line in text.splitlines():
        code, in_comment = strip_code(line, in_comment)
        m = None if in_comment and not code else re.match(r"\s*#\s*(if|ifdef|ifndef|endif)\b", code)
        if m:
            depth += -1 if m.group(1) == "endif" else 1
            low = min(low, depth)
    return depth == 0 and low == 0 and not in_comment and not text.rstrip("\n").endswith("\\") and text.endswith("\n")


mains = {"virtual_ios.c": "virtual_ios_", "signal_arm64_ios.c": "signal_arm64_ios_"}
build = (d / "build.sh").read_text() + (d / "compile_patched.sh").read_text()
for main, prefix in mains.items():
    path = d / main
    listed = parts(path)
    on_disk = sorted(d.glob(prefix + "*.c"))
    check(len(listed) >= 2 and len(set(listed)) == len(listed), "%s #includes %d parts, each once" % (main, len(listed)))
    check(sorted(listed) == on_disk, "%s: no part file is left over or missing" % main)
    for part in listed:
        text = part.read_text()
        head = text.split("\n", 2)
        check(head[0].startswith("/* Part of %s, #included from it at this place" % main) and head[1].startswith(" * on its own."),
              "%s: header" % part.name)
        check(region_ok(part_body(part)), "%s: a whole preprocessor region" % part.name)
        check(part.name not in build, "%s is not compiled on its own" % part.name)
    unit = unit_text(path)
    pos, ordered = 0, True
    for part in listed:
        k = unit.find(part_body(part), pos)
        ordered = ordered and k >= pos
        pos = k + len(part_body(part))
    check(ordered and not PART_LINE.search(unit), "%s: unit_text has every part in order and no #include of a part left" % main)
    check(len(unit.splitlines()) > 5 * len(path.read_text().splitlines()), "%s: %d lines in the file, %d in the unit" % (
        main, len(path.read_text().splitlines()), len(unit.splitlines())))

print("FAILED: %d" % failures if failures else "PASS: the split units are whole")
sys.exit(1 if failures else 0)
