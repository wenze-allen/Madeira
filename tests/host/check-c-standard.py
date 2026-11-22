#!/usr/bin/env python3
"""docs/C-STANDARD.md for the files it lists: M-AC-1 (a clean compile with GCC and Clang under its
warnings, -Werror) and M-AC-2 (clang-tidy with tests/host/c-standard.clang-tidy reports nothing).

Each listed file is compiled as the translation unit the device builds (the glue includes the
core, wg_parser_av_ios.c), at -O2 so GCC's flow-based warnings run. Wine's and FFmpeg's headers
are system headers. Nothing is run.

Environment: MADEIRA_WINE_BUILD (a configured Wine build tree whose include/ holds config.h and
the widl-generated headers; default: wine/build-macos), MADEIRA_FFMPEG_TARBALL.
"""
from pathlib import Path
import os, re, shutil, subprocess, sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_ffmpeg import host_ffmpeg, MEDIA_FLAGS

root = Path(__file__).resolve().parents[2]
wine = root / "wine"
wine_build = Path(os.environ.get("MADEIRA_WINE_BUILD") or wine / "build-macos")

# The files under the standard (docs/C-STANDARD.md, SCOPE): a file is added once it is clean.
# Each is a translation unit; the files it includes from build/ntdll-unix are covered with it.
UNITS = []
COVERED = []

WARNINGS = ("-std=gnu17 -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion -Wdouble-promotion "
            "-Wformat=2 -Wundef -Wcast-qual -Wwrite-strings -Wvla -Wstrict-prototypes "
            "-Wmissing-prototypes -Wimplicit-fallthrough -Werror").split()

doc = (root / "docs/C-STANDARD.md").read_text()
assert " ".join(WARNINGS) == " ".join(" ".join(doc.split("### M-AC-1")[1].split("Wine's and")[0]
                                               .split("with:")[1].split()).split()), \
    "the flags here and in docs/C-STANDARD.md, M-AC-1, differ"
for f in COVERED:
    assert "`%s`" % f in doc, "docs/C-STANDARD.md, SCOPE, does not list %s" % f

tools = {t: shutil.which(t) for t in ["gcc", "clang", "clang-tidy"]}
missing = [t for t, p in tools.items() if not p]
if missing:
    print("NOTOOL: %s not found" % ", ".join(missing))
    sys.exit(0)
for need in [wine_build / "include/config.h", wine_build / "include/mfobjects.h"]:
    if not need.exists():
        sys.exit("SKIP-FAIL: %s is missing; point MADEIRA_WINE_BUILD at a configured Wine tree" % need)
tarball = os.environ.get("MADEIRA_FFMPEG_TARBALL") or str(root / "build/ffmpeg/src/ffmpeg-7.1.5.tar.xz")
ffmpeg = host_ffmpeg(MEDIA_FLAGS, tarball, tag="asf-")

args = ["-include", str(wine_build / "include/config.h"),
        "-I" + str(root / "build/ntdll-unix"), "-I" + str(wine / "dlls/winegstreamer"),
        "-isystem", str(wine_build / "include"), "-isystem", str(wine / "include"),
        "-isystem", str(ffmpeg / "include"),
        "-D__WINESRC__", "-D_NTSYSTEM_", "-D_ACRTIMP=", "-DWINBASEAPI=", "-DWINE_UNIX_LIB"]
failed = []
for unit in UNITS:
    src = str(root / unit)
    for cc in ["gcc", "clang"]:
        r = subprocess.run([tools[cc], "-O2", "-c", "-o", os.devnull] + WARNINGS + args + [src],
                           capture_output=True, text=True)
        found = [l for l in r.stderr.splitlines() if re.search(r": (warning|error): ", l)]
        if r.returncode or found:
            failed.append("%s with %s: %d diagnostics" % (unit, cc, len(found)))
            print("\n".join(found[:40]))
        else:
            print("PASS: %s compiles cleanly with %s under M-AC-1" % (unit, cc))
    r = subprocess.run([tools["clang-tidy"], "--quiet", "--config-file=%s" % (root / "tests/host/c-standard.clang-tidy"),
                        "--warnings-as-errors=*", src, "--", "-std=gnu17"] + args,
                       capture_output=True, text=True, timeout=900)
    found = [l for l in (r.stdout + r.stderr).splitlines() if re.search(r": (warning|error): ", l)]
    if r.returncode or found:
        failed.append("%s: clang-tidy, %d findings" % (unit, len(found)))
        print("\n".join(found[:60]))
    else:
        print("PASS: %s is clang-tidy clean under M-AC-2" % unit)

if failed:
    sys.exit("FAIL: docs/C-STANDARD.md: " + "; ".join(failed))
print("PASS: the files under docs/C-STANDARD.md (%s) meet M-AC-1 and M-AC-2" % (", ".join(COVERED) or "none yet"))
