# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""The text of a translation unit split into #included parts, with every part in its place.

build/ntdll-unix/virtual_ios.c and signal_arm64_ios.c are split for size: each keeps the head of
the unit and #includes contiguous parts (virtual_ios_*.c, signal_arm64_ios_*.c) at their places,
each starting with a two-line header comment. A host check that reads such a file as text reads
unit_text(path) instead, which is the file as it was before the split, byte for byte
(tests/host/check-source-parts.py checks that every part is used once and balanced).
"""
from pathlib import Path
import re

PART_LINE = re.compile(r'^#include "(\w+_ios_\w+\.c)"   /\* [^\n]* \*/\n', re.M)


def part_body(path, errors=None):
    """A part without its two-line header."""
    text = Path(path).read_text(errors=errors) if errors else Path(path).read_text()
    return text.split("\n", 2)[2]


def unit_text(path, errors=None):
    path = Path(path)
    text = path.read_text(errors=errors) if errors else path.read_text()
    return PART_LINE.sub(lambda m: part_body(path.parent / m.group(1), errors), text)


def parts(path):
    """The part files a unit #includes, in order."""
    return [Path(path).parent / name for name in PART_LINE.findall(Path(path).read_text())]


def unit_of(path):
    """The file a part belongs to (its name), or the file's own name."""
    path = Path(path)
    for main in path.parent.glob("*.c"):
        if main != path and path in parts(main):
            return main.name
    return path.name
