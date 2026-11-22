#!/bin/bash
# Build Madeira.ipa on a Mac from this checkout: no sudo, no Homebrew, and
# nothing installed outside this folder.
#
#   build/build-mac.sh              every step below, then dist/Madeira-<rev>-Debug-unsigned.ipa
#   build/build-mac.sh --check      only the checks made before building (Xcode, SDKs, Metal,
#                                   disk, sources)
#   build/build-mac.sh --plan       list the steps, and whether each would run or is up to date
#   build/build-mac.sh --from STEP  start at STEP (after the checks and the host tools)
#   build/build-mac.sh --only STEP  run STEP alone
#   build/build-mac.sh --no-mono    do not fetch Wine Mono (.NET programs then cannot run)
#
# Environment:
#   MADEIRA_XCODE=/path/Xcode.app  the Xcode to use. Default: the selected one if it has
#                                  the iOS SDK, else the first Xcode*.app found in
#                                  /Applications, ~/Applications, ~/Downloads, ~/Desktop.
#                                  It is passed as DEVELOPER_DIR (xcode-select -s needs
#                                  an administrator).
#   MADEIRA_VCRUNTIME_DIR=dir      a folder with the 14 Microsoft VC++ runtime DLLs
#                                  (tools/fetch-vcruntime.md). Without it they are
#                                  downloaded from Microsoft and extracted with 7-Zip.
#   JOBS=n                         parallel jobs (default: every core)
#   MADEIRA_FORCE=1                rebuild every step, ignoring what is up to date
#   MADEIRA_BUILD_SELFTEST=0       skip building and bundling video-selftest-x86.exe
#
# Where things go:
#   toolchains/host-tools          cmake, ninja, meson (a Python venv), bison 3, 7zz, and
#                                  Rust when no rustup is installed; versions and hashes
#                                  are pinned below
#   toolchains/mac-build           logs/, stamps/ (what each step was built from),
#                                  DerivedData/
#   dist/                          the IPA and its build record
#
# What the 21e6697 Mac build (BUILD-STEPS.md, 2026-11-05) hit, and what covers it here:
#   app link: undefined ios_addr_max_prot, ios_atom_arg and DXMT's two frame-mark
#     functions                  tests/host/check-native-link-externs.py, run first
#   airconv's Metal headers not made; the tessellation atomic rejected by the Xcode 27
#     beta's Metal compiler      build/dxmt-ios/build.sh makes them, after
#                                  build/dxmt-patches/apply.sh; checked after the step
#   no base libwineserver.a      build/wineserver/make-base.sh, run by build.sh
#   FEX: options, archives and version for a snapshot   build/fex-ios/build.sh
#   no LLVM iOS script           build/llvm-ios/build.sh
#   no Dock in the IPA           the dock step; the IPA check fails without dockhost.exe
#   no Wine Mono in the IPA      the mono step (unless --no-mono); checked in the IPA
#   Xcode at a non-standard path, no admin   MADEIRA_XCODE / DEVELOPER_DIR, no sudo
# and what a clean tree hits that the builder worked around by hand:
#   wine/build-macos had no recipe              build/wine-macos/configure.sh
#   libdxmt_combined.a was only ever refreshed  build/dxmt-ios/build.sh makes it
#   Homebrew's llvm-objcopy                     llvm-mingw's (build/wineserver/build.sh)
#   bison 3, cmake, ninja, meson from Homebrew  built or installed into toolchains/host-tools
#   a stale native cache                        every library is rebuilt from this checkout;
#                                               a step is skipped only when the stamp of
#                                               its inputs matches
#
# Debug and unsigned, like the build that was tested on an iPad: Debug is the configuration
# that runs games (docs/BUILDING.md), and the sideloading tool signs the IPA.
set -euo pipefail

R="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="${MADEIRA_TOOLS:-$R/toolchains/host-tools}"
STATE="$R/toolchains/mac-build"
LOGS="$STATE/logs"
STAMPS="$STATE/stamps"
DERIVED="$STATE/DerivedData"
DIST="$R/dist"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 8)}"

LLVM_MINGW_VER=20260421
LLVM_MINGW_NAME="llvm-mingw-$LLVM_MINGW_VER-ucrt-macos-universal"
LLVM_MINGW_SHA256=bd85a3975723815cef28dbbd2ca2cb0c926f6b348a12a0453f39f7af273cb3f7
MINGW="$R/toolchains/$LLVM_MINGW_NAME"
BISON_VER=3.8.2
BISON_SHA256=9bba0214ccf7f1079c5d59210045227bcf619519840ebfa80cd3849cff5a5bf2
SEVENZIP_URL=https://www.7-zip.org/a/7z2501-mac.tar.xz
SEVENZIP_SHA256=26aa75bc262bb10bf0805617b95569c3035c2c590a99f7db55c7e9607b2685e0
# cmake stays below 4: CMake 4 refuses projects that declare a minimum below 3.5.
# meson stays at 1.11.1: 1.12 marks DLLs as console programs.
PY_PKGS="cmake==3.31.6 ninja==1.11.1.4 meson==1.11.1"
FREETYPE_TAG=VER-2-13-3
VCRUNTIME_DLLS="concrt140.dll msvcp140.dll msvcp140_1.dll msvcp140_2.dll msvcp140_atomic_wait.dll
msvcp140_codecvt_ids.dll vcamp140.dll vccorlib140.dll vcomp140.dll vcruntime140.dll
vcruntime140_1.dll vcruntime140_threads.dll mfc140.dll mfc140u.dll"
SELFTEST_FILES="video-selftest-x86.exe video-selftest.wmv video-selftest.mpg video-selftest.avi
video-selftest.m1v video-selftest.dat"

STEPS="tools llvm-mingw wine-host gnutls ffmpeg freetype ntdll-unix wineserver win32u-unix
llvm-ios fex-ios dxmt-ios rppairing dock vcruntime mono i386 selftest licences app ipa"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '    WARNING: %s\n' "$*" >&2; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

MODE=build FROM="" ONLY="" MONO=1 SELFTEST=1
[ "${MADEIRA_BUILD_SELFTEST:-1}" != 0 ] || SELFTEST=0
while [ $# -gt 0 ]; do
    case "$1" in
        --check) MODE=check ;;
        --plan) MODE=plan ;;
        --from) FROM="${2:-}"; shift ;;
        --only) ONLY="${2:-}"; shift ;;
        --no-mono) MONO=0 ;;
        -h|--help) sed -n '2,/^set -euo pipefail/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
    shift
done
for s in ${FROM:+"$FROM"} ${ONLY:+"$ONLY"}; do
    case " $(echo $STEPS) " in *" $s "*) ;; *) die "no step '$s'; the steps are: $(echo $STEPS)" ;; esac
done

# A user's compiler settings must not reach the configure scripts.
unset CC CXX CPP CFLAGS CXXFLAGS CPPFLAGS LDFLAGS OBJC OBJCFLAGS SDKROOT MACOSX_DEPLOYMENT_TARGET \
      IPHONEOS_DEPLOYMENT_TARGET CPATH LIBRARY_PATH PKG_CONFIG_PATH 2>/dev/null || true
export JOBS CMAKE_BUILD_PARALLEL_LEVEL="$JOBS"
export PATH="$TOOLS/bin:$PATH"

# ------------------------------------------------------------------ stamps
# A step's key is a hash of what it is built from; the step is skipped while
# its stamp holds the same key and its outputs are there.
sha_text()  { shasum -a 256 | cut -c1-64; }
hash_paths() {   # files and directories, by content
    local p
    for p in "$@"; do
        if [ -d "$R/$p" ]; then
            (cd "$R" && find "$p" -type f ! -name '.DS_Store' | LC_ALL=C sort | while IFS= read -r f; do
                printf '%s %s\n' "$(shasum -a 256 < "$f" | cut -c1-64)" "$f"; done)
        elif [ -f "$R/$p" ]; then
            printf '%s %s\n' "$(shasum -a 256 < "$R/$p" | cut -c1-64)" "$p"
        else
            printf 'absent %s\n' "$p"
        fi
    done
}
sub_state() {    # the commit a submodule has checked out, and a hash of its local changes
    local d="$R/$1"
    if git -C "$d" rev-parse HEAD >/dev/null 2>&1; then
        printf '%s %s %s\n' "$1" "$(git -C "$d" rev-parse HEAD)" "$(git -C "$d" diff HEAD 2>/dev/null | sha_text)"
    else
        printf '%s %s\n' "$1" "$(awk -v n="$1" '$1 == n { print $2 }' "$R/SNAPSHOT-REVISIONS.txt" 2>/dev/null)"
    fi
}
step_key() {
    case "$1" in
        tools)      echo "$PY_PKGS bison-$BISON_VER" ;;
        llvm-mingw) echo "$LLVM_MINGW_NAME $LLVM_MINGW_SHA256" ;;
        wine-host)  { sub_state wine; hash_paths build/wine-macos/configure.sh; } | sha_text ;;
        gnutls)     hash_paths build/gnutls-ios/build.sh build/gnutls-ios/src/SHA256SUMS | sha_text ;;
        ffmpeg)     hash_paths build/ffmpeg/build.sh build/ffmpeg/src/SHA256SUMS | sha_text ;;
        freetype)   { echo "$FREETYPE_TAG"; hash_paths build/freetype-ios/build.sh; } | sha_text ;;
        llvm-ios)   hash_paths build/llvm-ios/build.sh | sha_text ;;
        mono)       hash_paths build/wine-mono/pin.sh build/wine-mono/fetch.sh | sha_text ;;
        i386)       { sub_state wine; sub_state dxmt; hash_paths build/wine-i386/build.sh build/dxmt-patches; } | sha_text ;;
        selftest)   { echo "$LLVM_MINGW_NAME $LLVM_MINGW_SHA256"; hash_paths tests/x86/build-video-selftest.sh tests/x86/video-selftest-x86.c tests/x86/make-video-clips.py tests/host/host_ffmpeg.py build/ffmpeg/src/SHA256SUMS; } | sha_text ;;
        *)          echo "" ;;   # always run (cheap, or incremental by itself)
    esac
}
stamp_ok() { [ -z "${MADEIRA_FORCE:-}" ] && [ -n "$2" ] && [ -f "$STAMPS/$1" ] && [ "$(cat "$STAMPS/$1")" = "$2" ]; }
stamp_write() { mkdir -p "$STAMPS"; [ -z "$2" ] || printf '%s\n' "$2" > "$STAMPS/$1"; }

# Outputs that must exist for a step to count as done.
step_outputs() {
    case "$1" in
        tools)      echo "$TOOLS/bin/cmake $TOOLS/bin/ninja $TOOLS/bin/meson $TOOLS/bin/bison" ;;
        llvm-mingw) echo "$MINGW/bin/arm64ec-w64-mingw32-clang $MINGW/bin/i686-w64-mingw32-clang $MINGW/bin/x86_64-w64-mingw32-clang $MINGW/bin/llvm-objcopy" ;;
        wine-host)  echo "$R/wine/build-macos/include/config.h $R/wine/build-macos/include/wtypes.h $R/wine/build-macos/include/dwrite.h $R/wine/build-macos/include/mfobjects.h" ;;
        gnutls)     echo "$R/toolchains/gnutls-ios/lib/libgnutls.a $R/toolchains/gnutls-ios/lib/libnettle.a $R/toolchains/gnutls-ios/include/gnutls/gnutls.h" ;;
        ffmpeg)     echo "$R/app/Madeira/libavformat.a $R/app/Madeira/libavcodec.a $R/app/Madeira/libswresample.a $R/app/Madeira/libavutil.a $R/toolchains/ffmpeg-ios/include/libavformat/avformat.h" ;;
        freetype)   echo "$R/build/freetype-ios/build/libfreetype.a" ;;
        ntdll-unix) echo "$R/app/Madeira/libntdll_unix.a" ;;
        wineserver) echo "$R/app/Madeira/libwineserver.a" ;;
        win32u-unix) echo "$R/app/Madeira/libwin32u_unix.a" ;;
        llvm-ios)   echo "$R/toolchains/llvm-ios-build/lib/libLLVMSupport.a $R/toolchains/llvm-ios-build/lib/libLLVMCore.a $R/toolchains/llvm-ios-build/include/llvm/Config/llvm-config.h" ;;
        fex-ios)    echo "$R/FEX/build-ios/FEXCore/Source/libFEXCore.a $R/FEX/build-ios/FEXCore/Source/libFEXCore_Base.a $R/FEX/build-ios/FEXCore/Source/libJemallocLibs.a $R/FEX/build-ios/External/fmt/libfmt.a $R/FEX/build-ios/External/cephes/libcephes_128bit.a $R/FEX/build-ios/External/SoftFloat-3e/libsoftfloat_3e.a $R/FEX/build-ios/External/xxhash/cmake_unofficial/libxxhash.a" ;;
        dxmt-ios)   echo "$R/app/Madeira/libdxmt_combined.a $R/build/dxmt-ios/shader-headers/air_msad.h $R/build/dxmt-ios/shader-headers/air_samplepos.h $R/build/dxmt-ios/shader-headers/air_tessellation.h $R/build/dxmt-ios/shader-headers/dxmt_command.h" ;;
        rppairing)  echo "$R/app/Madeira/libmadeira_rppairing.a" ;;
        dock)       echo "$R/app/Madeira/arm64ec-windows/dockhost.exe $R/app/Madeira/arm64ec-windows/dock-notices.txt" ;;
        vcruntime)  for d in $VCRUNTIME_DLLS; do printf '%s ' "$R/app/Madeira/x86_64-vcruntime/$d"; done; echo ;;
        mono)       echo "$R/build/wine-mono/$(mono_dir)/lib/mono/4.5/mscorlib.dll" ;;
        i386)       echo "$R/app/Madeira/i386-windows/kernel32.dll $R/app/Madeira/i386-windows/ntdll.dll $R/app/Madeira/i386-windows/mf.dll $R/app/Madeira/i386-windows/d3d9.dll $R/app/Madeira/i386-windows/winemetal.dll" ;;
        selftest)   for d in $SELFTEST_FILES; do printf '%s ' "$R/app/Madeira/i386-windows/$d"; done; echo ;;
        app)        echo "$DERIVED/Build/Products/Debug-iphoneos/Madeira.app/Info.plist" ;;
        *)          echo "" ;;
    esac
}
outputs_present() { local f; for f in $(step_outputs "$1"); do [ -e "$f" ] || return 1; done; return 0; }
# The steps whose script writes its outputs on every run: those must be newer than the
# step's start, so a library a script only warned about (and left from an older build)
# is caught here, not at the app link or on a device. The others build incrementally.
FRESH_STEPS="ntdll-unix wineserver win32u-unix dxmt-ios dock selftest app"
outputs_done() {
    local f missing="" fresh=0
    case " $(echo $FRESH_STEPS) " in *" $1 "*) fresh=1 ;; esac
    for f in $(step_outputs "$1"); do
        if [ ! -e "$f" ]; then missing="$missing ${f#"$R"/}"
        elif [ "$fresh" = 1 ] && [ "$f" -ot "$STATE/.step-start" ]; then missing="$missing ${f#"$R"/}(not rebuilt)"; fi
    done
    [ -z "$missing" ] || die "step $1 did not produce:$missing (log: ${LOG#"$R"/})"
}
mono_dir() { (. "$R/build/wine-mono/pin.sh" && echo "wine-mono-$WINE_MONO_VER"); }

# ------------------------------------------------------------------ checks
select_xcode() {
    if [ -n "${MADEIRA_XCODE:-}" ]; then
        [ -d "$MADEIRA_XCODE/Contents/Developer" ] || die "MADEIRA_XCODE=$MADEIRA_XCODE is not an Xcode.app"
        export DEVELOPER_DIR="$MADEIRA_XCODE/Contents/Developer"
    elif ! xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1; then
        # The selected developer folder has no iOS SDK (only the Command Line Tools, or
        # an Xcode outside /Applications): use one found, through DEVELOPER_DIR.
        local x found=""
        for x in /Applications/Xcode.app /Applications/Xcode*.app "$HOME"/Applications/Xcode*.app \
                 "$HOME"/Downloads/Xcode*.app "$HOME"/Desktop/Xcode*.app; do
            if [ -d "$x/Contents/Developer/Platforms/iPhoneOS.platform" ]; then found="$x"; break; fi
        done
        [ -n "$found" ] || die "no Xcode with the iOS SDK found; set MADEIRA_XCODE=/path/to/Xcode.app"
        export DEVELOPER_DIR="$found/Contents/Developer"
    fi
    SDK="$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)" || die "the iOS SDK is not in ${DEVELOPER_DIR:-$(xcode-select -p 2>/dev/null)}"
    XCODE_VERSION="$(xcodebuild -version 2>/dev/null | tr '\n' ' ')"
    note "Xcode: $XCODE_VERSION(${DEVELOPER_DIR:-$(xcode-select -p 2>/dev/null)})"
    note "iOS SDK: $SDK"
}

preflight() {
    say "Checks"
    [ "$(uname -s)" = Darwin ] || die "this builds on macOS only"
    [ "$(id -u)" != 0 ] || die "do not run this as root: nothing here needs it"
    note "macOS $(sw_vers -productVersion 2>/dev/null) on $(uname -m), $JOBS jobs"
    select_xcode
    if ! xcodebuild -license check >/dev/null 2>&1; then
        die "the Xcode license is not accepted for this Xcode. Accepting it needs an administrator
       (sudo xcodebuild -license accept, or opening Xcode once as one); this script does not use sudo."
    fi
    xcodebuild -checkFirstLaunchStatus >/dev/null 2>&1 ||
        warn "Xcode reports first-launch tasks not done (xcodebuild -runFirstLaunch needs an administrator); the build may still work"
    if ! xcrun -sdk macosx metal --version >/dev/null 2>&1; then
        note "Metal toolchain missing: xcodebuild -downloadComponent MetalToolchain"
        xcodebuild -downloadComponent MetalToolchain >/dev/null 2>&1 || true
        xcrun -sdk macosx metal --version >/dev/null 2>&1 ||
            die "no Metal compiler (xcrun metal). Get it in Xcode > Settings > Components, then run this again."
    fi
    note "Metal: $(xcrun -sdk macosx metal --version 2>&1 | head -1)"
    for t in git curl shasum tar make python3 xxd perl flex m4 zip unzip ditto codesign; do
        command -v "$t" >/dev/null || die "$t is missing (it comes with macOS or the Xcode command line tools)"
    done
    local kb; kb="$(df -Pk "$R" | awk 'NR == 2 { print $4 }')"
    [ "$kb" -ge $((25 * 1024 * 1024)) ] || die "only $((kb / 1024 / 1024)) GB free under $R; a full build needs about 40 GB"
    [ "$kb" -ge $((40 * 1024 * 1024)) ] || warn "$((kb / 1024 / 1024)) GB free; a full build needs about 40 GB"

    # The sources: the submodules at their recorded commits.
    local f
    for f in wine/configure dxmt/meson.build FEX/CMakeLists.txt madeira-dock/src/main.c \
             app/Madeira.xcodeproj/project.pbxproj app/Madeira/prefix-template.tar.gz \
             app/Madeira/d3d12/libmetalirconverter.dylib app/Madeira/arm64ec-windows/xtajit64.dll; do
        [ -e "$R/$f" ] || die "$f is missing: this needs the whole checkout, with its submodules"
    done
    if [ -e "$R/.git" ] && [ -f "$R/.gitmodules" ]; then
        local bad
        bad="$(git -C "$R" submodule status 2>/dev/null | grep -E '^[-+U]' || true)"
        [ -z "$bad" ] || die "submodules not at their recorded commits ('-' missing, '+' other commit):
$bad
       run: git submodule update --init --recursive"
        bad="$(git -C "$R" submodule status --recursive 2>/dev/null | grep -E '^-' || true)"
        [ -z "$bad" ] || warn "nested submodules not checked out (only a problem if a build needs them): $(echo "$bad" | awk '{print $2}' | tr '\n' ' ')"
    elif [ ! -e "$R/FEX/.git" ] && [ -z "${FEX_HASH:-}" ] && [ ! -f "$R/SNAPSHOT-REVISIONS.txt" ]; then
        die "FEX is not a git checkout: set FEX_HASH, or keep SNAPSHOT-REVISIONS.txt next to the snapshot"
    fi
    # The DXMT build patches must apply to the pinned DXMT (or be applied already).
    for f in "$R"/build/dxmt-patches/*.patch; do
        [ -f "$f" ] || continue
        git -C "$R/dxmt" apply --check "$f" 2>/dev/null || git -C "$R/dxmt" apply --reverse --check "$f" 2>/dev/null ||
            die "build/dxmt-patches/$(basename "$f") does not apply to dxmt $(git -C "$R/dxmt" rev-parse --short HEAD 2>/dev/null)"
    done
    # The checks that would have stopped the 21e6697 build before the app link.
    for f in check-native-link-externs.py check-wineserver-base.py; do
        python3 "$R/tests/host/$f" >"$LOGS/check-$f.log" 2>&1 ||
            die "tests/host/$f failed (log: ${LOGS#"$R"/}/check-$f.log):
$(tail -5 "$LOGS/check-$f.log")"
        note "tests/host/$f: OK"
    done
}

# ------------------------------------------------------------------ host tools
fetch() {   # fetch URL FILE SHA256
    [ -f "$2" ] && [ "$(shasum -a 256 < "$2" | cut -c1-64)" = "$3" ] && return 0
    curl -fL --retry 3 --proto '=https' -o "$2.part" "$1"
    [ "$(shasum -a 256 < "$2.part" | cut -c1-64)" = "$3" ] || { rm -f "$2.part"; die "$1: SHA-256 mismatch"; }
    mv "$2.part" "$2"
}
bison_ok() { command -v bison >/dev/null && bison --version 2>/dev/null | head -1 | grep -Eq ' [3-9]\.'; }

s_tools() {
    mkdir -p "$TOOLS/bin" "$TOOLS/src"
    if [ ! -x "$TOOLS/venv/bin/meson" ] || ! stamp_ok tools-py "$PY_PKGS"; then
        rm -rf "$TOOLS/venv"
        python3 -m venv "$TOOLS/venv"
        "$TOOLS/venv/bin/python3" -m pip install --quiet --upgrade pip
        "$TOOLS/venv/bin/python3" -m pip install --quiet $PY_PKGS
        stamp_write tools-py "$PY_PKGS"
    fi
    local t
    for t in cmake ctest cpack ninja meson; do ln -sf "$TOOLS/venv/bin/$t" "$TOOLS/bin/$t"; done
    if [ ! -x "$TOOLS/bin/bison" ] || ! "$TOOLS/bin/bison" --version | head -1 | grep -q " $BISON_VER\$"; then
        fetch "https://ftp.gnu.org/gnu/bison/bison-$BISON_VER.tar.xz" "$TOOLS/src/bison-$BISON_VER.tar.xz" "$BISON_SHA256"
        rm -rf "$TOOLS/src/bison-$BISON_VER"
        tar -xJf "$TOOLS/src/bison-$BISON_VER.tar.xz" -C "$TOOLS/src"
        (cd "$TOOLS/src/bison-$BISON_VER" && ./configure --prefix="$TOOLS" --disable-nls && make -j"$JOBS" && make install)
    fi
    cmake --version | head -1; ninja --version; meson --version; bison --version | head -1
}

ensure_7zz() {
    command -v 7zz >/dev/null && return 0
    fetch "$SEVENZIP_URL" "$TOOLS/src/7z-mac.tar.xz" "$SEVENZIP_SHA256"
    mkdir -p "$TOOLS/src/7z" && tar -xJf "$TOOLS/src/7z-mac.tar.xz" -C "$TOOLS/src/7z"
    cp "$TOOLS/src/7z/7zz" "$TOOLS/bin/7zz" && chmod +x "$TOOLS/bin/7zz"
}

ensure_rust() {
    if ! command -v cargo >/dev/null && [ -x "$TOOLS/cargo/bin/cargo" ]; then
        export CARGO_HOME="$TOOLS/cargo" RUSTUP_HOME="$TOOLS/rustup" PATH="$TOOLS/cargo/bin:$PATH"
    fi
    if ! command -v cargo >/dev/null; then
        # rustup's own installer, into toolchains/host-tools (no shell profile is changed).
        local triple
        case "$(uname -m)" in arm64) triple=aarch64-apple-darwin ;; *) triple=x86_64-apple-darwin ;; esac
        local u="https://static.rust-lang.org/rustup/dist/$triple/rustup-init"
        curl -fL --retry 3 --proto '=https' -o "$TOOLS/src/rustup-init" "$u"
        [ "$(shasum -a 256 < "$TOOLS/src/rustup-init" | cut -c1-64)" = "$(curl -fsSL --proto '=https' "$u.sha256" | cut -c1-64)" ] ||
            die "rustup-init: SHA-256 mismatch"
        chmod +x "$TOOLS/src/rustup-init"
        export CARGO_HOME="$TOOLS/cargo" RUSTUP_HOME="$TOOLS/rustup" PATH="$TOOLS/cargo/bin:$PATH"
        "$TOOLS/src/rustup-init" -y --no-modify-path --profile minimal --default-toolchain stable
    fi
    if command -v rustup >/dev/null; then
        rustup target list --installed | grep -qx aarch64-apple-ios || rustup target add aarch64-apple-ios
    else
        rustc --print target-list | grep -qx aarch64-apple-ios ||
            die "this Rust has no aarch64-apple-ios target and no rustup to add it"
    fi
    cargo --version
}

# ------------------------------------------------------------------ steps
s_llvm-mingw() {
    if [ ! -x "$MINGW/bin/arm64ec-w64-mingw32-clang" ]; then
        mkdir -p "$R/toolchains"
        fetch "https://github.com/mstorsjo/llvm-mingw/releases/download/$LLVM_MINGW_VER/$LLVM_MINGW_NAME.tar.xz" \
              "$R/toolchains/$LLVM_MINGW_NAME.tar.xz" "$LLVM_MINGW_SHA256"
        tar -xJf "$R/toolchains/$LLVM_MINGW_NAME.tar.xz" -C "$R/toolchains"
    fi
    "$MINGW/bin/arm64ec-w64-mingw32-clang" --version | head -1
}
s_wine-host()  { bash "$R/build/wine-macos/configure.sh"; }
s_gnutls() {
    # Its parts are skipped by their .done files; when the recipe changed, start over.
    stamp_ok gnutls "$(step_key gnutls)" || rm -rf "$R/build/gnutls-ios/obj" "$R/toolchains/gnutls-ios"
    bash "$R/build/gnutls-ios/build.sh"
}
s_ffmpeg()     { bash "$R/build/ffmpeg/build.sh"; }
s_freetype() {
    local src="$R/research/freetype"
    if [ ! -d "$src/.git" ] || [ "$(git -C "$src" describe --tags --exact-match 2>/dev/null)" != "$FREETYPE_TAG" ]; then
        rm -rf "$src"
        git clone --depth 1 --branch "$FREETYPE_TAG" https://github.com/freetype/freetype.git "$src"
    fi
    rm -rf "$R/build/freetype-ios/build"
    bash "$R/build/freetype-ios/build.sh"
}
no_failed() { ! grep -E '(^|[[:space:]])FAILED' "$LOG" >/dev/null || die "step $1 failed to compile: $(grep -E 'FAILED|^Failed:' "$LOG" | tr '\n' ' ') (log: ${LOG#"$R"/})"; }
s_ntdll-unix() { bash "$R/build/ntdll-unix/build.sh"; }
s_wineserver() { bash "$R/build/wineserver/build.sh"; }
s_win32u-unix() { bash "$R/build/win32u-unix/build.sh"; }
s_llvm-ios()   { bash "$R/build/llvm-ios/build.sh"; }
s_fex-ios()    { bash "$R/build/fex-ios/build.sh"; }
s_dxmt-ios()   { bash "$R/build/dxmt-ios/build.sh"; }
s_rppairing()  { ensure_rust; bash "$R/build/rppairing-ios/build.sh"; }
s_dock()       { bash "$R/build/madeira-dock/build.sh"; }
s_vcruntime() {
    local d dest="$R/app/Madeira/x86_64-vcruntime" all=1
    for d in $VCRUNTIME_DLLS; do [ -f "$dest/$d" ] || all=0; done
    if [ "$all" = 0 ] && [ -n "${MADEIRA_VCRUNTIME_DIR:-}" ]; then
        mkdir -p "$dest"
        for d in $VCRUNTIME_DLLS; do
            [ -f "$MADEIRA_VCRUNTIME_DIR/$d" ] || die "MADEIRA_VCRUNTIME_DIR has no $d"
            cp "$MADEIRA_VCRUNTIME_DIR/$d" "$dest/$d"
        done
    elif [ "$all" = 0 ]; then
        ensure_7zz
        bash "$R/tools/fetch-vcruntime.sh"
    fi
    python3 "$R/tests/host/check-vcruntime.py" --strict
}
s_mono()       { bash "$R/build/wine-mono/fetch.sh"; }
s_i386()       { bash "$R/build/wine-i386/build.sh"; }
s_selftest()   { LLVM_MINGW="$MINGW" bash "$R/tests/x86/build-video-selftest.sh"; }
s_licences()   { bash "$R/build/stage-licenses.sh"; }
s_app() {
    rm -rf "$DERIVED/Build/Products/Debug-iphoneos/Madeira.app"
    xcodebuild -project "$R/app/Madeira.xcodeproj" -scheme Madeira -configuration Debug \
        -destination generic/platform=iOS -derivedDataPath "$DERIVED" -jobs "$JOBS" \
        ENABLE_USER_SCRIPT_SANDBOXING=NO CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
        CODE_SIGN_IDENTITY= build
}
s_ipa() {
    local app="$DERIVED/Build/Products/Debug-iphoneos/Madeira.app" rev name
    [ -d "$app" ] || die "no Madeira.app: run the app step"
    rev="$(git -C "$R" rev-parse --short HEAD 2>/dev/null || echo snapshot)"
    name="Madeira-$rev-Debug-unsigned"
    mkdir -p "$DIST"
    rm -rf "$DIST/Payload" "$DIST/$name.ipa"
    mkdir -p "$DIST/Payload"
    ditto "$app" "$DIST/Payload/Madeira.app"
    (cd "$DIST" && zip -qry "$name.ipa" Payload)
    rm -rf "$DIST/Payload"
    unzip -tq "$DIST/$name.ipa" >/dev/null
    python3 - "$DIST/$name.ipa" "$MONO" "$SELFTEST" <<'PY'
# What the IPA must carry; the 21e6697 IPA lacked the Dock and Wine Mono.
import sys, zipfile
ipa, mono, selftest = sys.argv[1], sys.argv[2] == "1", sys.argv[3] == "1"
names = set(zipfile.ZipFile(ipa).namelist())
A = "Payload/Madeira.app/"
need = ["Info.plist", "Madeira", "prefix-template.tar.gz", "default.metallib",
        "arm64ec-windows/dockhost.exe", "arm64ec-windows/dock-notices.txt", "arm64ec-windows/xtajit64.dll",
        "arm64ec-windows/ntdll.dll", "aarch64-windows/ntdll.dll", "d3d12/libmetalirconverter.dylib",
        "licenses/LICENSE-MADEIRA-GPL-3.0.txt", "licenses/LICENSE-MADEIRA-EXCEPTION.txt"]
need += ["i386-windows/" + d for d in ("ntdll.dll", "kernel32.dll", "mf.dll", "winegstreamer.dll",
                                       "d3d9.dll", "d3d9-emulated.dll", "winemetal.dll", "d3d11.dll", "dxgi.dll")]
if selftest:
    need += ["i386-windows/" + d for d in ("video-selftest-x86.exe", "video-selftest.wmv", "video-selftest.mpg",
                                           "video-selftest.avi", "video-selftest.m1v", "video-selftest.dat")]
need += ["x86_64-vcruntime/" + d for d in """concrt140.dll msvcp140.dll msvcp140_1.dll msvcp140_2.dll
    msvcp140_atomic_wait.dll msvcp140_codecvt_ids.dll vcamp140.dll vccorlib140.dll vcomp140.dll vcruntime140.dll
    vcruntime140_1.dll vcruntime140_threads.dll mfc140.dll mfc140u.dll""".split()]
missing = [n for n in need if A + n not in names]
i386 = [n for n in names if n.startswith(A + "i386-windows/") and not n.endswith("/")]
if len(i386) < 600:
    missing.append("i386-windows (only %d files)" % len(i386))
if not any(n.startswith(A + "PlugIns/") and ".appex/" in n for n in names):
    missing.append("PlugIns/*.appex (the JIT helper)")
if not any(n.startswith(A + "Frameworks/StikJIT.framework/") for n in names):
    missing.append("Frameworks/StikJIT.framework")
if mono and not any(n.startswith(A + "wine-mono/") for n in names):
    missing.append("wine-mono/ (Wine Mono)")
# The app's code is this checkout's: the RGB32 default and the first-buffer log of 7b91fe2.
z = zipfile.ZipFile(ipa)
code = b"".join(z.read(A + n) for n in ("Madeira.debug.dylib", "Madeira") if A + n in names)
for marker in (b"first picture delivered", b"using rgb32"):
    if marker not in code:
        missing.append("the app code has no '%s' (stale libntdll_unix.a?)" % marker.decode())
if missing:
    sys.exit("IPA is incomplete:\n  " + "\n  ".join(missing))
print("IPA contents: OK (%d entries, %d in i386-windows, Wine Mono %s, selftest %s)"
      % (len(names), len(i386), "in" if mono else "left out", "in" if selftest else "left out"))
PY
    {
        echo "Madeira $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Info.plist" 2>/dev/null) ($(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Info.plist" 2>/dev/null)), Debug, unsigned"
        echo "built $(date -u '+%Y-%m-%d %H:%M UTC') by build/build-mac.sh"
        echo "Xcode: $XCODE_VERSION"
        echo "iOS SDK: $SDK"
        echo "sha256: $(shasum -a 256 < "$DIST/$name.ipa" | cut -c1-64)"
        echo "revisions:"
        if git -C "$R" rev-parse HEAD >/dev/null 2>&1; then
            echo "  . $(git -C "$R" rev-parse HEAD)$(git -C "$R" diff --quiet HEAD 2>/dev/null || echo ' (with local changes)')"
            git -C "$R" submodule status 2>/dev/null | sed 's/^/  /'
        else
            sed 's/^/  /' "$R/SNAPSHOT-REVISIONS.txt" 2>/dev/null || echo "  (not a git checkout)"
        fi
    } > "$DIST/$name.txt"
    cat "$DIST/$name.txt"
    note "IPA: ${DIST#"$R"/}/$name.ipa ($(du -h "$DIST/$name.ipa" | cut -f1))"
}

# What each step must have done, beyond producing its outputs.
step_verify() {
    case "$1" in
        ntdll-unix|win32u-unix|dxmt-ios) no_failed "$1" ;;
    esac
    case "$1" in
        win32u-unix) grep -q 'merged libfreetype.a' "$LOG" || die "win32u-unix: FreeType was not merged, the app would have no fonts (log: ${LOG#"$R"/})" ;;
        wineserver)  grep -q 'symbol rename + repack OK' "$LOG" || die "wineserver: the symbol renames did not run (log: ${LOG#"$R"/})" ;;
        llvm-ios)    [ "$(ls "$R"/toolchains/llvm-ios-build/lib/libLLVM*.a | wc -l)" -ge 30 ] || die "llvm-ios: too few LLVM libraries" ;;
        dxmt-ios)    grep -Eq '^dxmt-patches: (applied |.* already applied)' "$LOG" ||
                         die "dxmt-ios: the DXMT patches were not applied (log: ${LOG#"$R"/})" ;;
        i386)        if ! grep -q ', 0 missing imports' "$LOG"; then warn "i386: $(grep 'missing imports' "$LOG" | tail -1)"; fi ;;
    esac
}

# ------------------------------------------------------------------ driver
mkdir -p "$LOGS" "$STAMPS"
if [ "$MODE" = plan ]; then
    say "Plan"
    for s in $STEPS; do
        k="$(step_key "$s")"
        if [ "$s" = mono ] && [ "$MONO" = 0 ]; then st="skipped (--no-mono)"
        elif [ "$s" = selftest ] && [ "$SELFTEST" = 0 ]; then st="skipped (MADEIRA_BUILD_SELFTEST=0)"
        elif stamp_ok "$s" "$k" && outputs_present "$s"; then st="up to date"
        else st="runs"; fi
        printf '    %-12s %s\n' "$s" "$st"
    done
    exit 0
fi

CAFFEINATE=""
if command -v caffeinate >/dev/null; then caffeinate -dims -w $$ & CAFFEINATE=$!; fi
trap '[ -z "$CAFFEINATE" ] || kill "$CAFFEINATE" 2>/dev/null || true' EXIT

preflight
[ "$MODE" = check ] && { say "Checks passed"; exit 0; }

n=0 started=0
[ -n "$FROM$ONLY" ] || started=1
for s in $STEPS; do
    n=$((n + 1))
    if [ -n "$ONLY" ]; then
        [ "$s" = "$ONLY" ] || continue
    elif [ "$started" = 0 ]; then
        if [ "$s" = "$FROM" ]; then started=1
        elif [ "$s" != tools ]; then continue   # the host tools are always made sure of
        fi
    fi
    if [ "$s" = mono ] && [ "$MONO" = 0 ]; then say "$s: skipped (--no-mono)"; continue; fi
    if [ "$s" = selftest ] && [ "$SELFTEST" = 0 ]; then say "$s: skipped (MADEIRA_BUILD_SELFTEST=0)"; continue; fi
    k="$(step_key "$s")"
    if stamp_ok "$s" "$k" && outputs_present "$s"; then say "$s: up to date"; continue; fi
    LOG="$LOGS/$(printf '%02d' "$n")-$s.log"
    say "$s (log: ${LOG#"$R"/})"
    touch "$STATE/.step-start"
    sleep 1   # outputs written in this second count as newer than the marker
    # Not `if ! ( ... )`: bash ignores set -e inside a subshell it tests, so a command
    # failing in the middle of a step would go unnoticed.
    set +e
    ( set -e; cd "$R"; "s_$s" ) > "$LOG" 2>&1
    rc=$?
    set -e
    if [ "$s" = selftest ] && { [ "$rc" != 0 ] || ! outputs_present selftest ||
                                ! grep -q 'LARGE_ADDRESS_AWARE present' "$LOG"; }; then
        # The self-test is a convenience: an IPA without it still serves, so its failure
        # does not cost the build. What it left is removed, and the IPA check does not
        # ask for it.
        tail -40 "$LOG" >&2
        warn "selftest failed (log: ${LOG#"$R"/}); the IPA goes without video-selftest-x86.exe"
        for d in $SELFTEST_FILES; do rm -f "$R/app/Madeira/i386-windows/$d"; done
        SELFTEST=0
        continue
    fi
    if [ "$rc" != 0 ]; then
        tail -40 "$LOG" >&2
        die "step $s failed (log: ${LOG#"$R"/})"
    fi
    outputs_done "$s"
    step_verify "$s"
    stamp_write "$s" "$k"
    [ "$s" != ipa ] || sed -n '/^IPA contents:/,$p' "$LOG"
done
say "Done"
