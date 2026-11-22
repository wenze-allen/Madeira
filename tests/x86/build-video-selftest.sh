#!/bin/bash
# Build the 32-bit on-device video self-test, video-selftest-x86.exe.
#
# Usage: ./build-video-selftest.sh
#
# 1. Generates video-selftest.{wmv,mpg,avi,m1v,dat} (plus a temporary C header
#    with embedded fallback copies) via make-video-clips.py using the cached
#    host FFmpeg build from tests/host/host_ffmpeg.py.
# 2. Compiles video-selftest-x86.c for i686 (-nostdlib -ffreestanding -Wall -Werror)
#    and checks its PE format, static import table, and LARGE_ADDRESS_AWARE bit.
# 3. Stages video-selftest-x86.exe and all five clips into app/Madeira/i386-windows/
#    so an IPA build bundles them into syswow64.
set -e

NAME=video-selftest-x86
CLIPS="video-selftest.wmv video-selftest.mpg video-selftest.avi video-selftest.m1v video-selftest.dat"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
APP_BUNDLE="$REPO_ROOT/app/Madeira/i386-windows"

if [ -n "${LLVM_MINGW:-}" ] && [ -x "$LLVM_MINGW/bin/i686-w64-mingw32-clang" ]; then
    TOOLCHAIN="$LLVM_MINGW/bin"
elif [ -n "${LLVM_MINGW:-}" ] && [ -x "$LLVM_MINGW/i686-w64-mingw32-clang" ]; then
    TOOLCHAIN="$LLVM_MINGW"
elif [ -x "$REPO_ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin/i686-w64-mingw32-clang" ]; then
    TOOLCHAIN="$REPO_ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
elif command -v i686-w64-mingw32-clang >/dev/null 2>&1; then
    TOOLCHAIN="$(dirname "$(command -v i686-w64-mingw32-clang)")"
elif [ -x "$HOME/.local/share/madeira-tools/llvm-mingw/bin/i686-w64-mingw32-clang" ]; then
    TOOLCHAIN="$HOME/.local/share/madeira-tools/llvm-mingw/bin"
else
    echo "ERROR: i686-w64-mingw32-clang not found (set LLVM_MINGW or PATH)." >&2
    exit 1
fi

CC="$TOOLCHAIN/i686-w64-mingw32-clang"
if [ -x "$TOOLCHAIN/i686-w64-mingw32-objdump" ]; then
    OBJDUMP="$TOOLCHAIN/i686-w64-mingw32-objdump"
elif [ -x "$TOOLCHAIN/llvm-objdump" ]; then
    OBJDUMP="$TOOLCHAIN/llvm-objdump"
else
    OBJDUMP=""
fi

TMP_BASE="${TMPDIR:-/tmp}"
TMP_BASE="${TMP_BASE%/}"
TMP_DIR="$(mktemp -d "$TMP_BASE/madeira-video-selftest.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

cd "$SCRIPT_DIR"

echo "=== generating short WMV, MPEG-1, AVI, M1V and VideoCD DAT test clips ==="
python3 "$SCRIPT_DIR/make-video-clips.py" "$SCRIPT_DIR" --header "$TMP_DIR/video-selftest-clips.h"
for c in $CLIPS; do
    ls -la "$SCRIPT_DIR/$c"
done

echo ""
echo "=== building $NAME.exe (i386 PE, no CRT, -Wall -Werror) ==="
"$CC" -O2 -g -Wall -Wextra -Werror -Wno-unused-parameter \
    -nostdlib -ffreestanding \
    -static-libgcc -Wno-unused-command-line-argument \
    -I"$TMP_DIR" \
    -Wl,--entry=_start \
    -Wl,--large-address-aware \
    -o "$NAME.exe" "$NAME.c" \
    -lmfplat -lmf -lmfreadwrite -lmfuuid -lwmcodecdspuuid \
    -lstrmiids -lwinmm -luser32 -lole32 -luuid -lkernel32

ls -la "$NAME.exe"

if [ -n "$OBJDUMP" ]; then
    echo ""
    echo "=== machine type (file format) ==="
    "$OBJDUMP" -f "$NAME.exe" || true
fi

echo ""
echo "=== asserting PE32 format, import allowlist, and LARGE_ADDRESS_AWARE ==="
python3 - "$NAME.exe" <<'PY'
import struct, sys

pe = open(sys.argv[1], "rb").read()
if pe[:2] != b"MZ":
    sys.exit("FAILED: missing MZ header")
pe_off = struct.unpack_from("<I", pe, 0x3C)[0]
if pe[pe_off:pe_off + 4] != b"PE\x00\x00":
    sys.exit("FAILED: missing PE signature")
machine, nsec, _, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", pe, pe_off + 4)
opt_off = pe_off + 24
magic = struct.unpack_from("<H", pe, opt_off)[0]
if machine != 0x014C or magic != 0x010B:
    sys.exit("FAILED: expected i386 PE32 (0x014c/0x010b), got 0x%x/0x%x" % (machine, magic))

num_rva = struct.unpack_from("<I", pe, opt_off + 92)[0]
imp_rva, imp_sz = struct.unpack_from("<II", pe, opt_off + 96 + 8) if num_rva > 1 else (0, 0)
sec_off = opt_off + opt_size
secs = []
for i in range(nsec):
    _, vsz, vrva, rsz, rptr = struct.unpack_from("<8sIIII", pe, sec_off + i * 40)
    secs.append((vrva, max(vsz, rsz), rptr, rsz))

def rva_off(rva):
    for vrva, span, rptr, rsz in secs:
        if vrva <= rva < vrva + span and rva - vrva < rsz:
            return rptr + (rva - vrva)
    sys.exit("FAILED: unmapped RVA 0x%x" % rva)

imports = set()
if imp_rva and imp_sz:
    off = rva_off(imp_rva)
    while True:
        ilt, _, _, name_rva, iat = struct.unpack_from("<IIIII", pe, off)
        if not (ilt or name_rva or iat):
            break
        noff = rva_off(name_rva)
        end = pe.index(b"\x00", noff)
        imports.add(pe[noff:end].decode("ascii").lower())
        off += 20

for dll in sorted(imports):
    print(dll)
allowed = {"kernel32.dll", "user32.dll", "ole32.dll", "winmm.dll", "mfplat.dll", "mf.dll", "mfreadwrite.dll"}
if not imports:
    sys.exit("FAILED: PE import table is empty")
unexpected = sorted(imports - allowed)
if unexpected:
    print("UNEXPECTED IMPORT: " + ", ".join(unexpected))
    sys.exit("FAILED: decoders/splitters must be reached via COM and wmvcore/gdi32 via LoadLibrary.")

if not (chars & 0x0020):
    sys.exit("FAILED: LARGE_ADDRESS_AWARE not set.")
print("LARGE_ADDRESS_AWARE present")
PY

echo ""
echo "=== checking the DLLs it needs are in the i386 farm ==="
missing=0
for dll in winegstreamer.dll wmadmod.dll wmvcore.dll quartz.dll evr.dll \
           mf.dll mfplat.dll mfreadwrite.dll msvproc.dll mciqtz32.dll winmm.dll \
           msdmo.dll ddraw.dll wined3d.dll gdi32.dll ole32.dll user32.dll; do
    if [ -f "$APP_BUNDLE/$dll" ]; then
        ls -la "$APP_BUNDLE/$dll"
    else
        echo "WARNING: $APP_BUNDLE/$dll is missing."
        missing=1
    fi
done
if [ "$missing" != 0 ]; then
    echo ""
    echo "NOTE: build the i386 farm (build/wine-i386/build.sh) before packaging"
    echo "      an IPA to run $NAME.exe on the iPad."
fi

mkdir -p "$APP_BUNDLE"
cp "$NAME.exe" "$APP_BUNDLE/$NAME.exe"
for c in $CLIPS; do
    cp "$SCRIPT_DIR/$c" "$APP_BUNDLE/$c"
done
echo ""
echo "=== staged to $APP_BUNDLE/ ==="
ls -la "$APP_BUNDLE/$NAME.exe"
for c in $CLIPS; do
    ls -la "$APP_BUNDLE/$c"
done
echo "Done. Launch with env.MADEIRA_EXE = $NAME.exe in madeira.cfg (exit 0 = all 10 passed)."
