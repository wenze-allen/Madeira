#!/usr/bin/env python3
"""build/build-mac.sh, the sudo-free Mac build: checked against what the 21e6697 Mac build
(BUILD-STEPS.md, 2026-11-05) ran into, without a Mac.

1. Source checks:
   - no sudo, no Homebrew install, no xcode-select switch, no licence acceptance, in the
     driver or in any script it runs;
   - nothing a macOS /bin/bash 3.2 lacks;
   - the step order the dependencies need;
   - the pinned tool versions (cmake below 4, meson 1.11.1, bison 3) and their hashes;
   - the xcodebuild settings of the build that ran on the iPad;
   - every script the driver calls exists;
   - the fixes for what a clean tree hits: wine/build-macos has a recipe,
     libdxmt_combined.a is made when absent, llvm-objcopy without Homebrew;
   - the IPA check asks for what the 21e6697 IPA lacked (the Dock, Wine Mono).
2. A mock Mac on this host. A copy of the driver runs in a scratch tree whose build scripts
   are stubs writing the outputs the real ones write. uname, xcrun, xcodebuild, sysctl, df,
   ditto, codesign, caffeinate, sudo and brew are stand-ins. The run is checked:
   - the full run, its order and its IPA;
   - a second run, where only what changed is rebuilt;
   - --plan, --only, --from and --no-mono;
   - an Xcode found in ~/Downloads, used through DEVELOPER_DIR.
   Then a broken input is injected for each failure the 21e6697 build met or could have met,
   and the driver must stop with the right message, never asking for sudo:
   - an undefined link symbol;
   - a compile FAILED that the script only reported;
   - a library left over from an older build;
   - FreeType not merged;
   - the DXMT patches not applied;
   - no dockhost.exe, or no Dock in the app;
   - no Wine Mono;
   - stale unix-side code in the app;
   - the Xcode licence not accepted;
   - no Metal compiler.
"""
import os, re, shutil, stat, subprocess, sys, tempfile, textwrap, zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[2]
driver = (root / "build/build-mac.sh").read_text()
failures = []


def check(cond, what):
    print(("PASS: " if cond else "FAIL: ") + what)
    if not cond:
        failures.append(what)


def code(text):
    """Shell text without comments, heredoc bodies and the text of quoted strings (a message
    that tells the user to run sudo is not a call to sudo)."""
    out, heredoc = [], None
    for line in text.splitlines():
        if heredoc:
            if line.strip() == heredoc:
                heredoc = None
            continue
        m = re.search(r"<<-?\s*'?(\w+)'?", line)
        if m and not line.lstrip().startswith("#"):
            heredoc = m.group(1)
        out.append(line)
    res, q, i, t = [], None, 0, "\n".join(out)
    while i < len(t):
        c = t[i]
        if q is None and c == "#" and (i == 0 or t[i - 1] in " \t\n"):
            while i < len(t) and t[i] != "\n":
                i += 1
            continue
        if q is None and c in "\"'":
            q = c
        elif q == c:
            q = None
        elif q == '"' and c == "\\":
            i += 2
            continue
        elif q is not None and c != "\n":
            c = " "
        res.append(c)
        i += 1
    return "".join(res)


# ------------------------------------------------------------------ 1. source checks
steps = re.search(r'^STEPS="([^"]*)"', driver, re.M).group(1).split()
check(steps == ["tools", "llvm-mingw", "wine-host", "gnutls", "ffmpeg", "freetype", "ntdll-unix", "wineserver",
                "win32u-unix", "llvm-ios", "fex-ios", "dxmt-ios", "rppairing", "dock", "vcruntime", "mono", "i386",
                "selftest", "licences", "app", "ipa"], "the steps, in an order their inputs allow: %s" % " ".join(steps))
before = lambda a, b: steps.index(a) < steps.index(b)
for a, b in [("tools", "wine-host"), ("llvm-mingw", "wine-host"), ("wine-host", "ntdll-unix"), ("wine-host", "wineserver"),
             ("wine-host", "win32u-unix"), ("gnutls", "ntdll-unix"), ("ffmpeg", "ntdll-unix"), ("freetype", "win32u-unix"),
             ("llvm-ios", "dxmt-ios"), ("llvm-mingw", "dock"), ("llvm-mingw", "i386"), ("tools", "i386"),
             ("llvm-mingw", "selftest"), ("i386", "selftest"), ("selftest", "licences")]:
    check(before(a, b), "%s runs before %s" % (a, b))
for s in steps:
    if s != "app" and s != "ipa":
        check(before(s, "app"), "%s runs before the app" % s)
check(re.search(r"^s_%s\(\)" % re.escape("ipa"), driver, re.M) and all(re.search(r"^s_%s\(\)" % re.escape(s), driver, re.M) for s in steps),
      "every step has its function")

called = sorted(set(re.findall(r'bash "\$R/((?:build|tools|tests)/[\w./-]+\.sh)"', driver)))
check(len(called) >= 15, "the driver runs %d repository scripts" % len(called))
for c in called:
    check((root / c).is_file(), "%s exists" % c)
scripts = [root / "build/build-mac.sh"] + [root / c for c in called] + [root / "build/wineserver/make-base.sh",
                                                                         root / "build/dxmt-patches/apply.sh"]
for p in scripts:
    t = code(p.read_text())
    rel = p.relative_to(root)
    check(not re.search(r"(^|[;&|(]\s*|\s)sudo\s", t), "%s: no sudo" % rel)
    check(not re.search(r"\bbrew\s+install\b", t), "%s: no Homebrew install" % rel)
    check(not re.search(r"xcode-select\s+(-s|--switch|--install|-r|--reset)", t), "%s: no xcode-select switch" % rel)
    check(not re.search(r"-license\s+accept|-runFirstLaunch", t), "%s: no licence acceptance or first-launch install" % rel)
bash4 = [(r"declare\s+-A|local\s+-A", "associative arrays"), (r"\bmapfile\b|\breadarray\b", "mapfile"),
         (r"\$\{\w+(,,|\^\^)", "case conversion"), (r"\|&", "|&"), (r"&>>", "&>>"), (r"\[\[\s+-v\s", "[[ -v"),
         (r"\$\{\w+\[-\d+\]\}", "negative indices"), (r"\bcoproc\b", "coproc"), (r"local\s+-n\b|declare\s+-n\b", "namerefs"),
         (r"\bwait\s+-n\b", "wait -n"), (r"printf\s+'%\(", "printf %(")]
dt = code(driver)
for pat, what in bash4:
    check(not re.search(pat, dt), "build-mac.sh: no %s (macOS /bin/bash is 3.2)" % what)
check(driver.startswith("#!/bin/bash\n"), "build-mac.sh runs with /bin/bash")

pins = dict(re.findall(r'^(\w+)=([^\s#]+)', driver, re.M))
py = re.search(r'^PY_PKGS="([^"]*)"', driver, re.M).group(1).split()
cm = [p for p in py if p.startswith("cmake==")][0].split("==")[1]
check(int(cm.split(".")[0]) == 3, "cmake pinned below 4 (%s): CMake 4 refuses minimums below 3.5" % cm)
check("meson==1.11.1" in py, "meson pinned to 1.11.1: 1.12 marks DLLs as console programs")
check(any(p.startswith("ninja==") for p in py), "ninja pinned")
check(pins.get("BISON_VER", "").startswith("3.") and re.fullmatch(r"[0-9a-f]{64}", pins.get("BISON_SHA256", "")),
      "bison 3 pinned with its SHA-256 (macOS ships 2.3; Wine's configure rejects it)")
check(re.fullmatch(r"[0-9a-f]{64}", pins.get("SEVENZIP_SHA256", "")) is not None, "7-Zip pinned with its SHA-256")
building = (root / "docs/BUILDING.md").read_text()
check(pins.get("LLVM_MINGW_SHA256") and pins["LLVM_MINGW_SHA256"] in building and pins.get("LLVM_MINGW_VER") == "20260421",
      "llvm-mingw 20260421 with the SHA-256 docs/BUILDING.md records")
xb = driver[driver.index("s_app() {"):]
xb = xb[:xb.index("\n}\n")]
for s in ["-configuration Debug", "-scheme Madeira", "generic/platform=iOS", "ENABLE_USER_SCRIPT_SANDBOXING=NO",
          "CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO", "CODE_SIGN_IDENTITY= "]:
    check(s in xb, "xcodebuild: %s (as the build that ran on the iPad)" % s.strip())
check("export DEVELOPER_DIR=" in driver and "MADEIRA_XCODE" in driver, "Xcode chosen through DEVELOPER_DIR / MADEIRA_XCODE")
check(re.search(r"check-native-link-externs\.py check-wineserver-base\.py", driver) is not None,
      "the link-symbol and wineserver-base checks run before building")
vc_driver = re.search(r'VCRUNTIME_DLLS="([^"]*)"', driver, re.S).group(1).split()
vc_fetch = re.findall(r'^\s+"(\w+\.dll)"', (root / "tools/fetch-vcruntime.sh").read_text(), re.M)
check(sorted(vc_driver) == sorted(vc_fetch) and len(vc_driver) == 14, "the 14 VC++ runtime DLLs, as tools/fetch-vcruntime.sh")
ipa_check = driver[driver.index("python3 - \"$DIST/$name.ipa\""):]
for s in ["arm64ec-windows/dockhost.exe", "arm64ec-windows/dock-notices.txt", "wine-mono/", "i386-windows",
          "video-selftest-x86.exe", "x86_64-vcruntime/", "mf.dll", "first picture delivered", "using rgb32"]:
    check(s in ipa_check, "the IPA check asks for %s" % s)
cfg = (root / "build/wine-macos/configure.sh").read_text()
check("--without-freetype --without-gnutls --enable-winegstreamer" in cfg and "include/all" in cfg and "brew" not in code(cfg),
      "build/wine-macos/configure.sh: the host tree, with no Homebrew")
for h in ["config.h", "wtypes.h", "dwrite.h", "dwrite_3.h", "mfobjects.h"]:
    check("include/" + h in cfg, "build/wine-macos/configure.sh checks include/%s" % h)
dx = (root / "build/dxmt-ios/build.sh").read_text()
check(re.search(r'libtool -static -o "\$COMBINED" "\$OBJ_DIR"/\*\.o "\$\{LLVM_LIBS\[@\]\}"', dx) is not None
      and 'cp "$COMBINED" "$APP_COPY"' in dx, "build/dxmt-ios/build.sh makes libdxmt_combined.a when there is none, and stages it")
check(dx.index("apply.sh") < dx.index("air_tessellation"), "the DXMT patches go in before the Metal headers are made")
ws = (root / "build/wineserver/build.sh").read_text()
check("toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin/llvm-objcopy" in ws and "no llvm-objcopy" in ws,
      "build/wineserver/build.sh finds llvm-mingw's llvm-objcopy (no Homebrew llvm)")
check("make-base.sh" in ws, "build/wineserver/build.sh makes its base archive when there is none")

# ------------------------------------------------------------------ 2. mock Mac
OUTPUTS = {}   # step -> outputs, read back from the driver itself
def sh(text):
    return textwrap.dedent(text).lstrip()

def mkexe(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(sh(text))
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

def stub(tree, rel, body):
    """A stand-in for a repository script: records its run, then does `body`."""
    mkexe(tree / rel, "#!/bin/bash\nset -eu\nR=\"$(cd \"$(dirname \"$0\")/../..\" && pwd)\"\n"
          "echo \"%s\" >> \"$TRACE\"\n" % rel + sh(body).replace("@A@", "$R/app/Madeira"))

def make_tree(tmp):
    t = tmp / "Madeira"
    (t / "build").mkdir(parents=True)
    shutil.copy(root / "build/build-mac.sh", t / "build/build-mac.sh")
    for f in ["wine/configure", "dxmt/meson.build", "FEX/CMakeLists.txt", "madeira-dock/src/main.c",
              "app/Madeira.xcodeproj/project.pbxproj", "app/Madeira/prefix-template.tar.gz",
              "app/Madeira/d3d12/libmetalirconverter.dylib", "app/Madeira/arm64ec-windows/xtajit64.dll",
              "app/Madeira/arm64ec-windows/ntdll.dll", "app/Madeira/aarch64-windows/ntdll.dll",
              "build/wine-i386/build.sh", "build/wine-macos/configure.sh", "build/llvm-ios/build.sh",
              "build/freetype-ios/build.sh", "build/dxmt-patches/README.md",
              "tests/x86/video-selftest-x86.c", "tests/x86/make-video-clips.py", "tests/host/host_ffmpeg.py"]:
        (t / f).parent.mkdir(parents=True, exist_ok=True)
        (t / f).write_text("x\n")
    (t / "build/gnutls-ios/src").mkdir(parents=True)
    (t / "build/gnutls-ios/src/SHA256SUMS").write_text("x\n")
    (t / "build/ffmpeg/src").mkdir(parents=True)
    (t / "build/ffmpeg/src/SHA256SUMS").write_text("x\n")
    (t / "build/wine-mono").mkdir(parents=True)
    shutil.copy(root / "build/wine-mono/pin.sh", t / "build/wine-mono/pin.sh")
    (t / "SNAPSHOT-REVISIONS.txt").write_text("Path\tCommit\nFEX\t1dc6ed4932bd231df1c53dd7b8043ffdee0ac34a\nwine\t340e8b5d\ndxmt\t1f617cd\n")
    for c in ["check-native-link-externs.py", "check-wineserver-base.py", "check-vcruntime.py"]:
        mkexe(t / "tests/host" / c, "import os, sys\nprint('%s: OK')\nsys.exit(1 if os.environ.get('FAKE_FAIL_%s') else 0)\n"
              % (c, re.sub(r"\W", "_", c).upper()))
    stub(t, "build/wine-macos/configure.sh", """
        bison --version | head -1 | grep -q ' 3\\.' || { echo 'bison 3 needed'; exit 1; }
        mkdir -p "$R/wine/build-macos/include"
        for h in config.h wtypes.h dwrite.h dwrite_3.h mfobjects.h; do echo x > "$R/wine/build-macos/include/$h"; done
        echo "wine/build-macos ready"
    """)
    stub(t, "build/gnutls-ios/build.sh", """
        mkdir -p "$R/toolchains/gnutls-ios/lib" "$R/toolchains/gnutls-ios/include/gnutls"
        for l in gnutls nettle; do echo x > "$R/toolchains/gnutls-ios/lib/lib$l.a"; done
        echo x > "$R/toolchains/gnutls-ios/include/gnutls/gnutls.h"
    """)
    stub(t, "build/ffmpeg/build.sh", """
        mkdir -p "$R/toolchains/ffmpeg-ios/include/libavformat" "@A@"
        for l in avformat avcodec swresample avutil; do echo x > "@A@/lib$l.a"; done
        echo x > "$R/toolchains/ffmpeg-ios/include/libavformat/avformat.h"
    """)
    stub(t, "build/freetype-ios/build.sh", """
        mkdir -p "$R/build/freetype-ios/build"; echo x > "$R/build/freetype-ios/build/libfreetype.a"
    """)
    stub(t, "build/ntdll-unix/build.sh", """
        echo "  virtual... ${FAKE_NTDLL_FAIL:-OK}"
        [ -n "${FAKE_NTDLL_STALE:-}" ] || printf 'first picture delivered %s\\n' "${FAKE_MARKER:-using rgb32}" > "@A@/libntdll_unix.a"
        echo Done!
    """)
    stub(t, "build/wineserver/build.sh", """
        echo "  symbol rename + repack OK"; echo x > "@A@/libwineserver.a"
    """)
    stub(t, "build/win32u-unix/build.sh", """
        [ -n "${FAKE_NO_FREETYPE:-}" ] && echo "WARNING: no libfreetype.a — fonts will be disabled" || echo "merged libfreetype.a"
        echo x > "@A@/libwin32u_unix.a"
    """)
    stub(t, "build/llvm-ios/build.sh", """
        mkdir -p "$R/toolchains/llvm-ios-build/lib" "$R/toolchains/llvm-ios-build/include/llvm/Config"
        for i in $(seq 1 40); do echo x > "$R/toolchains/llvm-ios-build/lib/libLLVMPart$i.a"; done
        echo x > "$R/toolchains/llvm-ios-build/lib/libLLVMSupport.a"; echo x > "$R/toolchains/llvm-ios-build/lib/libLLVMCore.a"
        echo x > "$R/toolchains/llvm-ios-build/include/llvm/Config/llvm-config.h"
    """)
    stub(t, "build/fex-ios/build.sh", """
        B="$R/FEX/build-ios"
        mkdir -p "$B/FEXCore/Source" "$B/External/fmt" "$B/External/cephes" "$B/External/SoftFloat-3e" "$B/External/xxhash/cmake_unofficial"
        for f in FEXCore/Source/libFEXCore.a FEXCore/Source/libFEXCore_Base.a FEXCore/Source/libJemallocLibs.a External/fmt/libfmt.a \\
                 External/cephes/libcephes_128bit.a External/SoftFloat-3e/libsoftfloat_3e.a External/xxhash/cmake_unofficial/libxxhash.a; do
            echo x > "$B/$f"; done
    """)
    stub(t, "build/dxmt-ios/build.sh", """
        [ -n "${FAKE_NO_PATCH:-}" ] || echo "dxmt-patches: applied 0001-airconv-tessellation-atomic.patch"
        mkdir -p "$R/build/dxmt-ios/shader-headers"
        for h in air_msad air_samplepos air_tessellation dxmt_command; do echo x > "$R/build/dxmt-ios/shader-headers/$h.h"; done
        echo x > "@A@/libdxmt_combined.a"; echo "Staged: app/Madeira/libdxmt_combined.a"
    """)
    stub(t, "build/rppairing-ios/build.sh", 'echo x > "@A@/libmadeira_rppairing.a"\n')
    stub(t, "build/madeira-dock/build.sh", """
        mkdir -p "@A@/arm64ec-windows"
        [ -n "${FAKE_NO_DOCKHOST:-}" ] || echo x > "@A@/arm64ec-windows/dockhost.exe"
        echo x > "@A@/arm64ec-windows/dock-notices.txt"
    """)
    stub(t, "tools/fetch-vcruntime.sh", 'echo "download not expected"; exit 1\n')
    stub(t, "build/wine-mono/fetch.sh", """
        . "$R/build/wine-mono/pin.sh"
        mkdir -p "$R/build/wine-mono/wine-mono-$WINE_MONO_VER/lib/mono/4.5"
        echo x > "$R/build/wine-mono/wine-mono-$WINE_MONO_VER/lib/mono/4.5/mscorlib.dll"
    """)
    stub(t, "build/wine-i386/build.sh", """
        mkdir -p "@A@/i386-windows"
        for i in $(seq 1 700); do echo x > "@A@/i386-windows/mod$i.dll"; done
        for d in ntdll kernel32 mf winegstreamer d3d9 d3d9-emulated winemetal d3d11 dxgi; do echo x > "@A@/i386-windows/$d.dll"; done
        echo "== 709 files in app/Madeira/i386-windows, 0 missing imports =="
    """)
    stub(t, "tests/x86/build-video-selftest.sh", """
        [ -x "${LLVM_MINGW:-}/bin/i686-w64-mingw32-clang" ] || { echo "missing LLVM_MINGW"; exit 1; }
        [ -z "${FAKE_SELFTEST_FAIL:-}" ] || { echo "the host FFmpeg did not build"; exit 1; }
        mkdir -p "@A@/i386-windows"
        if [ -z "${FAKE_NO_SELFTEST:-}" ]; then
            for f in video-selftest-x86.exe video-selftest.wmv video-selftest.mpg video-selftest.avi video-selftest.m1v video-selftest.dat; do
                echo MZ > "@A@/i386-windows/$f"
            done
        fi
        [ -n "${FAKE_NO_SELFTEST_LAA:-}" ] || echo "LARGE_ADDRESS_AWARE present"
    """)
    stub(t, "build/stage-licenses.sh", """
        mkdir -p "@A@/licenses"; echo x > "@A@/licenses/LICENSE-MADEIRA-GPL-3.0.txt"; echo x > "@A@/licenses/LICENSE-MADEIRA-EXCEPTION.txt"
    """)
    # The stub scripts sit at build/<x>/build.sh, so their R is two levels up; stage-licenses.sh
    # and tools/ are one level down.
    for rel in ["build/stage-licenses.sh", "tools/fetch-vcruntime.sh"]:
        p = t / rel
        p.write_text(p.read_text().replace('$(dirname "$0")/../..', '$(dirname "$0")/..'))
    return t

def make_bin(tmp, home):
    b = tmp / "bin"
    rec = 'echo "$(basename "$0") $*" >> "$CALLS"\n'
    mkexe(b / "uname", '#!/bin/bash\ncase "${1:-}" in -m) echo arm64 ;; *) echo Darwin ;; esac\n')
    mkexe(b / "sw_vers", '#!/bin/bash\necho 26.1\n')
    mkexe(b / "sysctl", '#!/bin/bash\necho 4\n')
    mkexe(b / "df", '#!/bin/bash\necho "Filesystem 1024-blocks Used Available Capacity Mounted"\necho "/dev/disk 999999999 1 99999999 1% /"\n')
    mkexe(b / "caffeinate", "#!/bin/bash\nexit 0\n")
    mkexe(b / "codesign", "#!/bin/bash\nexit 0\n")
    mkexe(b / "xxd", "#!/bin/bash\nexit 0\n")
    mkexe(b / "ditto", '#!/bin/bash\ncp -R "$1" "$2"\n')
    for x in ["sudo", "brew"]:
        mkexe(b / x, "#!/bin/bash\n" + rec + "exit 1\n")
    mkexe(b / "xcode-select", '#!/bin/bash\n' + rec + 'echo "$FAKE_SELECTED"\n')
    mkexe(b / "xcrun", "#!/bin/bash\n" + rec + sh("""
        dev="${DEVELOPER_DIR:-$FAKE_SELECTED}"
        case "$*" in
          *"--show-sdk-path"*)
            [ -d "$dev/Platforms/iPhoneOS.platform" ] || exit 1
            echo "$dev/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk" ;;
          *"metal --version"*) [ -z "${FAKE_NO_METAL:-}" ] || exit 1; echo "Apple metal version 32023.1" ;;
          *) exit 1 ;;
        esac
    """))
    mkexe(b / "xcodebuild", "#!/bin/bash\n" + rec + sh("""
        case "$1" in
          -version) echo "Xcode 27.3"; echo "Build version 27C5020n"; exit 0 ;;
          -license) [ -z "${FAKE_NO_LICENSE:-}" ]; exit $? ;;
          -checkFirstLaunchStatus) exit 0 ;;
          -downloadComponent) exit 1 ;;
        esac
        echo "DEVELOPER_DIR=${DEVELOPER_DIR:-}" >> "$CALLS"
        dd=""; prev=""
        for a in "$@"; do [ "$prev" = -derivedDataPath ] && dd="$a"; prev="$a"; done
        R="$(cd "$(dirname "$0")/../Madeira" && pwd)"
        app="$dd/Build/Products/Debug-iphoneos/Madeira.app"
        mkdir -p "$app/PlugIns/MadeiraJITHelper.appex" "$app/Frameworks/StikJIT.framework"
        echo x > "$app/PlugIns/MadeiraJITHelper.appex/Helper"; echo x > "$app/Frameworks/StikJIT.framework/StikJIT"
        echo x > "$app/Info.plist"; echo x > "$app/Madeira"; echo x > "$app/default.metallib"
        cat "$R/app/Madeira/libntdll_unix.a" > "$app/Madeira.debug.dylib"
        for d in arm64ec-windows aarch64-windows i386-windows x86_64-vcruntime d3d12 licenses; do cp -R "$R/app/Madeira/$d" "$app/"; done
        cp "$R/app/Madeira/prefix-template.tar.gz" "$app/"
        [ -z "${FAKE_APP_NO_DOCK:-}" ] || rm -f "$app/arm64ec-windows/dockhost.exe"
        for m in "$R"/build/wine-mono/wine-mono-*/; do [ -d "$m" ] && cp -R "$m" "$app/wine-mono"; done
        echo "** BUILD SUCCEEDED **"
    """))
    # The selected developer folder: the Command Line Tools only (no iOS SDK). The Xcode is in ~/Downloads.
    clt = tmp / "CommandLineTools"
    (clt / "usr/bin").mkdir(parents=True)
    xc = home / "Downloads/Xcode-beta.app/Contents/Developer/Platforms/iPhoneOS.platform"
    xc.mkdir(parents=True)
    # host tools already made (the tools step then only checks them) and a stand-in llvm-mingw and Rust
    tools = tmp / "Madeira/toolchains/host-tools"
    for name in ["cmake", "ctest", "cpack", "ninja", "meson"]:
        mkexe(tools / "venv/bin" / name, '#!/bin/bash\necho "%s 0.0"\n' % name)
    mkexe(tools / "bin/bison", '#!/bin/bash\necho "bison (GNU Bison) 3.8.2"\n')
    py_pkgs = re.search(r'^PY_PKGS="([^"]*)"', driver, re.M).group(1)
    (tmp / "Madeira/toolchains/mac-build/stamps").mkdir(parents=True)
    (tmp / "Madeira/toolchains/mac-build/stamps/tools-py").write_text(py_pkgs + "\n")
    mingw = tmp / "Madeira/toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin"
    for name in ["arm64ec-w64-mingw32-clang", "i686-w64-mingw32-clang", "x86_64-w64-mingw32-clang", "llvm-objcopy"]:
        mkexe(mingw / name, '#!/bin/bash\necho "clang version 22"\n')
    mkexe(b / "cargo", '#!/bin/bash\necho "cargo 1.91.0"\n')
    mkexe(b / "rustup", '#!/bin/bash\necho aarch64-apple-ios\n')
    vc = tmp / "vcruntime"
    vc.mkdir()
    for d in vc_driver:
        (vc / d).write_text("MZ\n")
    return b, clt

def run(tmp, args=(), **env):
    home = tmp / "home"
    e = {k: v for k, v in os.environ.items() if not k.startswith(("MADEIRA_", "FAKE_", "DEVELOPER_DIR"))}
    e.update(PATH="%s:%s" % (tmp / "bin", os.environ["PATH"]), HOME=str(home), TRACE=str(tmp / "trace"),
             CALLS=str(tmp / "calls"), FAKE_SELECTED=str(tmp / "CommandLineTools"),
             MADEIRA_VCRUNTIME_DIR=str(tmp / "vcruntime"))
    e.update(env)
    for f in ["trace", "calls"]:
        (tmp / f).write_text("")
    p = subprocess.run(["/bin/bash", str(tmp / "Madeira/build/build-mac.sh")] + list(args), env=e,
                       capture_output=True, text=True, timeout=600)
    return p.returncode, p.stdout + p.stderr, (tmp / "trace").read_text().split(), (tmp / "calls").read_text()

with tempfile.TemporaryDirectory(prefix="madeira-mac-build-") as d:
    tmp = Path(d)
    tree = make_tree(tmp)
    (tmp / "home").mkdir()
    make_bin(tmp, tmp / "home")
    order = ["build/wine-macos/configure.sh", "build/gnutls-ios/build.sh", "build/ffmpeg/build.sh", "build/freetype-ios/build.sh",
             "build/ntdll-unix/build.sh", "build/wineserver/build.sh", "build/win32u-unix/build.sh", "build/llvm-ios/build.sh",
             "build/fex-ios/build.sh", "build/dxmt-ios/build.sh", "build/rppairing-ios/build.sh", "build/madeira-dock/build.sh",
             "build/wine-mono/fetch.sh", "build/wine-i386/build.sh", "tests/x86/build-video-selftest.sh", "build/stage-licenses.sh"]

    # freetype's step clones FreeType when research/freetype is not that tag; give it one.
    ft = tree / "research/freetype"
    ft.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(ft)], check=True)
    subprocess.run(["git", "-C", str(ft), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "t"], check=True)
    subprocess.run(["git", "-C", str(ft), "tag", "VER-2-13-3"], check=True)

    rc, out, trace, calls = run(tmp)
    check(rc == 0, "mock Mac: the full run succeeds" + ("" if rc == 0 else ":\n" + out[-3000:]))
    check(trace == order, "mock Mac: the scripts ran in the step order" + ("" if trace == order else ": %s" % trace))
    check("sudo" not in calls and "brew" not in calls, "mock Mac: neither sudo nor brew was called")
    xcode = str(tmp / "home/Downloads/Xcode-beta.app/Contents/Developer")
    check("DEVELOPER_DIR=" + xcode in calls, "mock Mac: the Xcode in ~/Downloads was used through DEVELOPER_DIR")
    check("tests/host/check-native-link-externs.py: OK" in out and "tests/host/check-wineserver-base.py: OK" in out,
          "mock Mac: the link-symbol and wineserver-base checks ran first")
    ipas = sorted((tree / "dist").glob("*.ipa"))
    check(len(ipas) == 1 and "IPA contents: OK" in out, "mock Mac: one IPA, and its contents check passed")
    if ipas:
        n = zipfile.ZipFile(ipas[0]).namelist()
        check("Payload/Madeira.app/arm64ec-windows/dockhost.exe" in n and any("/wine-mono/" in x for x in n),
              "mock Mac: the IPA has the Dock and Wine Mono")
        check("Payload/Madeira.app/i386-windows/video-selftest-x86.exe" in n
              and "Payload/Madeira.app/i386-windows/video-selftest.avi" in n
              and "Payload/Madeira.app/i386-windows/video-selftest.dat" in n,
              "mock Mac: the IPA has video-selftest-x86.exe and its clips in i386-windows")
        rec = ipas[0].with_suffix(".txt").read_text()
        check("Xcode 27.3" in rec and "sha256:" in rec and "revisions:" in rec, "mock Mac: the build record names Xcode, the hash and the revisions")

    rc, out, trace, calls = run(tmp, ["--plan"])
    plan = dict(re.findall(r"^\s+(\S+)\s+(up to date|runs|skipped.*)$", out, re.M))
    keyed = ["tools", "llvm-mingw", "wine-host", "gnutls", "ffmpeg", "freetype", "llvm-ios", "mono", "i386", "selftest"]
    check(rc == 0 and all(plan.get(s) == "up to date" for s in keyed) and plan.get("ntdll-unix") == "runs" and plan.get("app") == "runs",
          "mock Mac: --plan shows the built inputs up to date and the unix side and app to run" + ("" if rc == 0 else out[-800:]))
    check(trace == [], "mock Mac: --plan ran nothing")

    rc, out, trace, calls = run(tmp, ["--plan"], MADEIRA_BUILD_SELFTEST="0")
    plan_skip = dict(re.findall(r"^\s+(\S+)\s+(up to date|runs|skipped.*)$", out, re.M))
    check(rc == 0 and plan_skip.get("selftest") == "skipped (MADEIRA_BUILD_SELFTEST=0)",
          "mock Mac: --plan shows selftest skipped when MADEIRA_BUILD_SELFTEST=0")

    rc, out, trace, calls = run(tmp)
    check(rc == 0 and trace == ["build/ntdll-unix/build.sh", "build/wineserver/build.sh", "build/win32u-unix/build.sh",
                                "build/fex-ios/build.sh", "build/dxmt-ios/build.sh", "build/rppairing-ios/build.sh",
                                "build/madeira-dock/build.sh", "build/stage-licenses.sh"],
          "mock Mac: a second run rebuilds only what is not stamped" + ("" if rc == 0 else out[-1500:]) + " %s" % trace)

    (tree / "build/wine-i386/build.sh").write_text((tree / "build/wine-i386/build.sh").read_text() + "\n# changed\n")
    rc, out, trace, calls = run(tmp, ["--from", "i386"])
    check(rc == 0 and trace == ["build/wine-i386/build.sh", "build/stage-licenses.sh"],
          "mock Mac: a changed i386 recipe rebuilds the i386 farm (--from i386)" + ("" if rc == 0 else out[-1500:]) + " %s" % trace)

    (tree / "tests/x86/video-selftest-x86.c").write_text((tree / "tests/x86/video-selftest-x86.c").read_text() + "/* changed */\n")
    rc, out, trace, calls = run(tmp, ["--from", "selftest"])
    check(rc == 0 and trace == ["tests/x86/build-video-selftest.sh", "build/stage-licenses.sh"],
          "mock Mac: a changed selftest source rebuilds selftest before licences/app (--from selftest)"
          + ("" if rc == 0 else out[-1500:]) + " %s" % trace)

    for sf in (tree / "app/Madeira/i386-windows").glob("video-selftest*"):
        sf.unlink()
    rc, out, trace, calls = run(tmp, ["--from", "selftest"], MADEIRA_BUILD_SELFTEST="0")
    check(rc == 0 and "tests/x86/build-video-selftest.sh" not in trace
          and "selftest: skipped (MADEIRA_BUILD_SELFTEST=0)" in out and "selftest left out" in out,
          "mock Mac: MADEIRA_BUILD_SELFTEST=0 skips selftest and builds an IPA without it"
          + ("" if rc == 0 else out[-1500:]))

    rc, out, trace, calls = run(tmp, ["--only", "dock"])
    check(rc == 0 and trace == ["build/madeira-dock/build.sh"], "mock Mac: --only dock runs that step alone %s" % trace)

    def fails(what, msg, args=(), **env):
        rc, out, trace, calls = run(tmp, list(args), **env)
        ok = rc != 0 and msg in out and "sudo" not in calls
        check(ok, "mock Mac stops on %s ('%s')" % (what, msg) + ("" if ok else ":\n" + out[-1500:]))
        return trace

    fails("an undefined link symbol (the 21e6697 app link)", "check-native-link-externs.py failed",
          FAKE_FAIL_CHECK_NATIVE_LINK_EXTERNS_PY="1")
    fails("an app without video-selftest-x86.exe when selftest is enabled", "i386-windows/video-selftest-x86.exe", ["--only", "ipa"])
    # A self-test that fails to build costs the IPA only the self-test.
    for what, env in [("its script fails", {"FAKE_SELFTEST_FAIL": "1"}),
                      ("it lacks LARGE_ADDRESS_AWARE", {"FAKE_NO_SELFTEST_LAA": "1"}),
                      ("it writes no exe", {"FAKE_NO_SELFTEST": "1"})]:
        rc, out, trace, calls = run(tmp, ["--from", "selftest"], MADEIRA_FORCE="1", **env)
        left = [f.name for f in (tree / "app/Madeira/i386-windows").glob("video-selftest*")]
        check(rc == 0 and "the IPA goes without video-selftest-x86.exe" in out and "selftest left out" in out
              and not left and trace[-1:] == ["build/stage-licenses.sh"],
              "mock Mac: when %s, the build warns and makes the IPA without the self-test" % what
              + ("" if rc == 0 else ":\n" + out[-1500:]))
    run(tmp, ["--only", "selftest"], MADEIRA_FORCE="1")
    run(tmp, ["--only", "app"])
    t = fails("an undefined link symbol (before any step builds)", "check-native-link-externs.py failed",
              FAKE_FAIL_CHECK_NATIVE_LINK_EXTERNS_PY="1")
    check(t == [], "mock Mac: nothing is built before that check")
    fails("a compile FAILED the script only reported", "step ntdll-unix failed to compile", ["--only", "ntdll-unix"],
          FAKE_NTDLL_FAIL="FAILED")
    fails("a libntdll_unix.a left from an older build", "libntdll_unix.a(not rebuilt)", ["--only", "ntdll-unix"], FAKE_NTDLL_STALE="1")
    fails("FreeType not merged into win32u", "FreeType was not merged", ["--only", "win32u-unix"], FAKE_NO_FREETYPE="1")
    fails("the DXMT patches not applied", "the DXMT patches were not applied", ["--only", "dxmt-ios"], FAKE_NO_PATCH="1")
    fails("no dockhost.exe from the Dock build", "dockhost.exe", ["--only", "dock"], FAKE_NO_DOCKHOST="1")
    run(tmp, ["--only", "dock"])
    run(tmp, ["--only", "app"], FAKE_APP_NO_DOCK="1")
    fails("an app without the Dock (the 21e6697 IPA)", "arm64ec-windows/dockhost.exe", ["--only", "ipa"])
    run(tmp, ["--only", "ntdll-unix"], FAKE_MARKER="using nv12")
    run(tmp, ["--only", "app"])
    fails("stale unix-side code in the app", "stale libntdll_unix.a", ["--only", "ipa"])
    run(tmp, ["--only", "ntdll-unix"])
    shutil.rmtree(next((tree / "build/wine-mono").glob("wine-mono-*")))
    run(tmp, ["--only", "app"])
    fails("an app without Wine Mono (the 21e6697 IPA)", "wine-mono/ (Wine Mono)", ["--only", "ipa"])
    rc, out, trace, calls = run(tmp, ["--only", "ipa", "--no-mono"])
    check(rc == 0 and "Wine Mono left out" in out, "mock Mac: --no-mono builds an IPA without Wine Mono")
    fails("the Xcode licence not accepted", "needs an administrator", ["--check"], FAKE_NO_LICENSE="1")
    fails("no Metal compiler", "no Metal compiler", ["--check"], FAKE_NO_METAL="1")
    rc, out, trace, calls = run(tmp, ["--check"])
    check(rc == 0 and "Checks passed" in out and trace == [], "mock Mac: --check checks and builds nothing")
    rc, out, trace, calls = run(tmp, ["--only", "nosuch"])
    check(rc != 0 and "no step 'nosuch'" in out, "mock Mac: an unknown step is refused")

if failures:
    print("%d check(s) failed" % len(failures))
    sys.exit(1)
print("check-mac-build: OK")
