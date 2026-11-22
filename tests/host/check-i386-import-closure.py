#!/usr/bin/env python3
"""The i386 farm's import-closure report (build/wine-i386/build.sh) counts only real gaps.

The report looked each imported DLL up with `echo "$present" | grep -qx` under pipefail. When
grep found its line and exited before echo had written the whole list, echo died of SIGPIPE,
the pipeline failed, and a DLL that was in the farm counted as missing: a false
"N missing imports" warning in build-mac.sh. The farm's list is some 20 KB; this check makes it
far larger than a pipe buffer, with the imported DLL sorted first, so the old lookup fails every
time.

It runs the production block, cut out of build.sh, under `set -euo pipefail` on a farm of:
- a PE (built here with llvm-mingw) that imports aaa.dll and kernel32.dll;
- aaa.dll, and filler files with long names;
and checks the count is 1 (kernel32.dll is not in this farm) and names only kernel32.dll. Then
the same without aaa.dll: 2. Nothing is run but the shell block and llvm-mingw's tools.
"""
from pathlib import Path
import os, shutil, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
build = (root / "build/wine-i386/build.sh").read_text()
start = build.index("# ----------------------------------------------------------- import closure")
end = build.index("missing imports ==\"", start)
block = build[start:build.index("\n", end) + 1]
assert '| grep -qx "$l"' not in block, "the piped lookup is back"

tools = {}
for name in ["i686-w64-mingw32-clang", "llvm-dlltool", "llvm-objdump"]:
    found = shutil.which(name) or shutil.which(name, path=os.path.expanduser("~/.local/share/madeira-tools/llvm-mingw/bin"))
    if not found:
        print("NOTOOL: %s not found (llvm-mingw)" % name)
        sys.exit(0)
    tools[name] = found

with tempfile.TemporaryDirectory() as t:
    t = Path(t)
    (t / "aaa.def").write_text("LIBRARY aaa.dll\nEXPORTS\naaa_function\n")
    subprocess.run([tools["llvm-dlltool"], "-m", "i386", "-d", str(t / "aaa.def"), "-l", str(t / "libaaa.a")], check=True)
    (t / "user.c").write_text("void __stdcall Sleep(unsigned int);\nvoid aaa_function(void);\n"
                              "int main(void) { aaa_function(); Sleep(0); return 0; }\n")
    dest = t / "farm"; dest.mkdir()
    subprocess.run([tools["i686-w64-mingw32-clang"], "-O1", "-o", str(dest / "user.exe"), str(t / "user.c"),
                    "-L" + str(t), "-laaa", "-lkernel32"], check=True)
    out = subprocess.run([tools["llvm-objdump"], "-p", str(dest / "user.exe")], capture_output=True, text=True).stdout
    assert "DLL Name: aaa.dll" in out and "DLL Name: KERNEL32.dll" in out, out[-2000:]
    (dest / "aaa.dll").write_bytes(b"")
    for i in range(800):
        (dest / ("zz-filler-%04d-%s.dat" % (i, "x" * 220))).write_bytes(b"")
    listing = sum(len(n) + 1 for n in os.listdir(dest))
    assert listing > 2 * 65536, listing   # well past a pipe buffer (64 KB on Linux, 16-64 KB on macOS)

    def run():
        script = "set -euo pipefail\nDEST=%s\nOBJDUMP=%s\n%s" % (dest, tools["llvm-objdump"], block)
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=600)
        assert r.returncode == 0, r.stdout + r.stderr
        lines = r.stdout.splitlines()
        return [l for l in lines if l.startswith("missing import:")], lines[-1]

    missing, summary = run()
    assert missing == ["missing import: user.exe -> KERNEL32.dll"], missing
    assert summary.endswith(", 1 missing imports =="), summary
    (dest / "aaa.dll").unlink()
    missing, summary = run()
    assert sorted(missing) == ["missing import: user.exe -> KERNEL32.dll", "missing import: user.exe -> aaa.dll"], missing
    assert summary.endswith(", 2 missing imports =="), summary
print("PASS: the i386 import-closure report counts only DLLs that are not in the farm "
      "(a %d KB name list, the imported DLL first, under pipefail)" % (listing // 1024))
