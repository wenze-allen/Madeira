#!/bin/bash
# Configure wine/build-macos, the host-configured Wine tree whose include/
# (config.h and the widl-generated headers: wtypes.h, dwrite.h, mfobjects.h,
# ...) build/ntdll-unix, build/wineserver and build/win32u-unix compile
# against. Nothing else creates it, and without it every ntdll-unix file
# fails on its forced -include of build-macos/include/config.h.
#
# This follows upstream's tools/build/build-wine.sh, with no Homebrew: it needs
# bison 3 and flex on PATH (macOS ships bison 2.3, which Wine's configure
# rejects; build/build-mac.sh builds bison 3 into toolchains/host-tools) and
# llvm-mingw under toolchains/ (configure checks the aarch64 PE compiler).
# FreeType and GnuTLS are not looked for: the iOS units that use them define
# what they need themselves (build/win32u-unix/config_ios.h, freetype_ios.c,
# build/ntdll-unix/dwrite_freetype_ios.c and the GnuTLS defines in
# build/ntdll-unix/build.sh).
set -eu
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MINGW="$R/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
B="$R/wine/build-macos"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 8)}"

[ -x "$R/wine/configure" ] || { echo "ERROR: the wine submodule is missing" >&2; exit 1; }
[ -x "$MINGW/aarch64-w64-mingw32-clang" ] || { echo "ERROR: llvm-mingw is missing at $MINGW (docs/BUILDING.md)" >&2; exit 1; }
export PATH="$MINGW:$PATH"
v="$(bison --version 2>/dev/null | head -1 | sed 's/.* //')"
case "$v" in
    [3-9].*) ;;
    *) echo "ERROR: Wine needs bison 3 or newer on PATH; found '${v:-none}' (build/build-mac.sh builds one)" >&2; exit 1 ;;
esac
command -v flex >/dev/null || { echo "ERROR: flex is missing" >&2; exit 1; }

mkdir -p "$B"
if [ ! -f "$B/config.status" ]; then
    (cd "$B" && ../configure --enable-archs=aarch64 --disable-tests --without-x \
                             --without-freetype --without-gnutls --enable-winegstreamer)
fi
# The unix-side libraries read only config.h, the build tools and the
# widl-generated headers, so only those are built.
make -C "$B" -j"$JOBS" tools/all include/all
for h in include/config.h include/wtypes.h include/dwrite.h include/dwrite_3.h include/mfobjects.h; do
    [ -f "$B/$h" ] || { echo "ERROR: $B/$h was not generated" >&2; exit 1; }
done
echo "wine/build-macos ready"
