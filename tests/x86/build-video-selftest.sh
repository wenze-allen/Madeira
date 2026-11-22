#!/bin/bash
# Build the 32-bit on-device video self-test, video-selftest-x86.exe.
#
# Usage: ./build-video-selftest.sh
#
# 1. Generates video-selftest.wmv and video-selftest.mpg (plus a temporary C
#    header with embedded fallback copies) via make-video-clips.py using the
#    cached host FFmpeg build from tests/host/host_ffmpeg.py.
# 2. Compiles video-selftest-x86.c for i686 (-nostdlib -ffreestanding -Wall -Werror)
#    and checks its PE format, static import table, and LARGE_ADDRESS_AWARE bit.
# 3. Stages video-selftest-x86.exe, video-selftest.wmv, and video-selftest.mpg
#    into app/Madeira/i386-windows/ so an IPA build bundles them into syswow64.
set -e

NAME=video-selftest-x86
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
OBJDUMP="$TOOLCHAIN/i686-w64-mingw32-objdump"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/madeira-video-selftest.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

cd "$SCRIPT_DIR"

echo "=== generating short WMV and MPEG-1 test clips ==="
python3 "$SCRIPT_DIR/make-video-clips.py" "$SCRIPT_DIR" --header "$TMP_DIR/video-selftest-clips.h"
ls -la "$SCRIPT_DIR/video-selftest.wmv" "$SCRIPT_DIR/video-selftest.mpg"

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

echo ""
echo "=== machine type (file format) ==="
"$OBJDUMP" -f "$NAME.exe"

echo ""
echo "=== asserting the import set ==="
imports=$("$OBJDUMP" -p "$NAME.exe" | sed -n 's/^\s*DLL Name: //p' | tr 'A-Z' 'a-z' | sort -u)
echo "$imports"
unexpected=0
for dll in $imports; do
    case "$dll" in
        kernel32.dll|user32.dll|ole32.dll|winmm.dll|mfplat.dll|mf.dll|mfreadwrite.dll) ;;
        *) echo "UNEXPECTED IMPORT: $dll"; unexpected=1 ;;
    esac
done
if [ "$unexpected" != 0 ]; then
    echo "FAILED: decoders/splitters must be reached via COM and wmvcore.dll via LoadLibrary."
    exit 1
fi

echo ""
echo "=== asserting the large-address-aware bit is set ==="
if "$OBJDUMP" -p "$NAME.exe" | grep -q "LARGE_ADDRESS_AWARE"; then
    echo "LARGE_ADDRESS_AWARE present"
else
    chars=$("$TOOLCHAIN/llvm-readobj" --file-headers "$NAME.exe" \
            | sed -n 's/.*IMAGE_FILE_LARGE_ADDRESS_AWARE.*/yes/p' | head -1)
    if [ "$chars" = yes ]; then
        echo "LARGE_ADDRESS_AWARE present (readobj)"
    else
        echo "FAILED: LARGE_ADDRESS_AWARE not set."
        exit 1
    fi
fi

echo ""
echo "=== checking the DLLs it needs are in the i386 farm ==="
missing=0
for dll in winegstreamer.dll wmadmod.dll wmvcore.dll quartz.dll evr.dll \
           mf.dll mfplat.dll mfreadwrite.dll mciqtz32.dll winmm.dll \
           msdmo.dll ole32.dll user32.dll; do
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
cp "$SCRIPT_DIR/video-selftest.wmv" "$APP_BUNDLE/video-selftest.wmv"
cp "$SCRIPT_DIR/video-selftest.mpg" "$APP_BUNDLE/video-selftest.mpg"
echo ""
echo "=== staged to $APP_BUNDLE/ ==="
ls -la "$APP_BUNDLE/$NAME.exe" "$APP_BUNDLE/video-selftest.wmv" "$APP_BUNDLE/video-selftest.mpg"
echo "Done. Launch with env.MADEIRA_EXE = $NAME.exe in madeira.cfg (exit 0 = all 6 passed)."
