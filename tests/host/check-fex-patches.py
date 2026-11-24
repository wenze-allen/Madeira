#!/usr/bin/env python3
"""Host checks for Madeira's FEX build patches (build/fex-patches/).

The iOS host page is 16 KB and Wine gives a host page the union of its four
4 KB guest pages' protections. FEX armed its self-modifying-code write trap
(PAGE_EXECUTE_READ) on single 4 KB pages, so a trapped 4 KB page sharing a
16 KB host page with an untrapped or hot 4 KB page stayed writable: guest
writes never faulted and translated code went stale (Aokana, The Escapists 2,
Project Zomboid).

Checks (host-only, never modifies the shared FEX checkout):
  1. build/fex-patches/README.md and apply.sh exist, keep the Madeira-only /
     not-for-FEX-Emu notice, and use only bash 3.2 features;
  2. every build/fex-patches/*.patch applies cleanly to the pinned FEX
     checkout (git apply --check, verified to leave FEX untouched), and 0001
     defines MADEIRA_TRAP_PAGE_SIZE = 0x4000 under FEX_IOS_HOST across trap,
     untrap, invalidation and hot-page tracking;
  3. build/fex-arm64ec/build.sh and build/fex-wow64/build.sh run apply.sh
     before cmake configure, pass FEX_IOS_HOST and pinned-dependency flags,
     and docs/WOW64.md + docs/BUILDING.md document build/fex-patches;
  4. behavioral run in a scratch git repo with a mock cmake: first build
     applies 0001 before cmake -S and retries a partial CMakeCache.txt,
     second build skips the already-applied patch, --revert restores the file
     byte-for-byte, and a conflicting tree fails cleanly;
  5. shipped xtajit.dll and xtajit64.dll carry the 16 KB SMC trap machine code
     in HandleRWXAccessViolation (located via its '[smc-hot] page ' xref).
"""

import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FEX = ROOT / "FEX"
PATCH_DIR = ROOT / "build/fex-patches"
PATCH_0001 = PATCH_DIR / "0001-windows-ios-smc-traps-per-16k-host-page.patch"
APPLY_SH = PATCH_DIR / "apply.sh"
README_MD = PATCH_DIR / "README.md"

if not (FEX / "Source/Windows/Common/InvalidationTracker.cpp").is_file():
    sys.exit(f"SKIP-FAIL: {FEX} is missing (submodules not checked out)")

failures = []


def check(cond: bool, what: str):
    print(("PASS: " if cond else "FAIL: ") + what)
    if not cond:
        failures.append(what)


# ------------------------------------------------------------------ 1. patch metadata & apply.sh
check(README_MD.is_file(), "build/fex-patches/README.md exists")
readme = README_MD.read_text(encoding="utf-8") if README_MD.is_file() else ""
check(
    "0001-windows-ios-smc-traps-per-16k-host-page.patch" in readme
    and "not to be sent to FEX-Emu" in readme,
    "build/fex-patches/README.md names 0001 and states patches are Madeira-only, not for FEX-Emu",
)

check(APPLY_SH.is_file() and os.access(APPLY_SH, os.X_OK), "build/fex-patches/apply.sh exists and is executable")
apply_text = APPLY_SH.read_text(encoding="utf-8") if APPLY_SH.is_file() else ""
check(apply_text.startswith("#!/bin/bash\n"), "apply.sh runs with /bin/bash")
bash4 = [
    (r"declare\s+-A|local\s+-A", "associative arrays"),
    (r"\bmapfile\b|\breadarray\b", "mapfile"),
    (r"\$\{\w+(,,|\^\^)", "case conversion"),
    (r"\|&", "|&"),
    (r"&>>", "&>>"),
    (r"\[\[\s+-v\s", "[[ -v"),
]
for pat, desc in bash4:
    check(not re.search(pat, apply_text), f"apply.sh: no {desc} (macOS /bin/bash 3.2)")

# ------------------------------------------------------------------ 2. git apply --check on pinned FEX
patches = sorted(PATCH_DIR.glob("*.patch"))
check(PATCH_0001 in patches, "0001-windows-ios-smc-traps-per-16k-host-page.patch is present")

status_before = subprocess.check_output(["git", "-C", str(FEX), "status", "--porcelain"], text=True)
for p in patches:
    fwd = subprocess.run(["git", "-C", str(FEX), "apply", "--check", str(p)], capture_output=True, text=True)
    check(
        fwd.returncode == 0,
        f"{p.name} applies cleanly to pinned FEX via git apply --check"
        + ("" if fwd.returncode == 0 else f": {fwd.stderr.strip()}"),
    )
status_after = subprocess.check_output(["git", "-C", str(FEX), "status", "--porcelain"], text=True)
check(status_before == status_after, "git apply --check left the shared FEX checkout untouched")

p0001 = PATCH_0001.read_text(encoding="utf-8")
for snippet, desc in [
    ("#ifdef FEX_IOS_HOST\n", "FEX_IOS_HOST guard"),
    ("static constexpr uint64_t MADEIRA_TRAP_PAGE_SIZE = 0x4000;", "16 KB trap page size"),
    ("static constexpr uint64_t MADEIRA_TRAP_PAGE_MASK = ~(MADEIRA_TRAP_PAGE_SIZE - 1);", "trap page mask"),
    ("CountSMCWriteFault(FaultAddress & MADEIRA_TRAP_PAGE_MASK)", "host-page hot fault counting"),
    ("InvalidateIntervalInternalLocked(TrapPage, MADEIRA_TRAP_PAGE_SIZE);", "whole host-page invalidation"),
    ("for (uint64_t Page = TrapPage; Page < TrapPage + MADEIRA_TRAP_PAGE_SIZE; Page += FEXCore::Utils::FEX_PAGE_SIZE)",
     "per-4KB-page untrap loop across the 16 KB host page"),
    ("HotFaults[(Page / MADEIRA_TRAP_PAGE_SIZE) % HotFaultSlots]", "host-page HotFaults indexing"),
    ("const auto End = (Address + Size + MADEIRA_TRAP_PAGE_SIZE - 1) & MADEIRA_TRAP_PAGE_MASK;",
     "whole host-page ProtectRWXIntervalsInternal rounding"),
]:
    check(snippet in p0001, f"0001 patch carries {desc}")

# ------------------------------------------------------------------ 3. build scripts & docs
for arch in ("arm64ec", "wow64"):
    rel = f"build/fex-{arch}/build.sh"
    txt = (ROOT / rel).read_text(encoding="utf-8")
    apply_pos = txt.find('bash "$R/build/fex-patches/apply.sh"')
    cmake_pos = txt.find('cmake -S "$R/FEX"')
    check(
        0 <= apply_pos < cmake_pos,
        f"{rel} runs build/fex-patches/apply.sh before cmake configure",
    )
    check(
        "-DFEX_IOS_HOST_BUILD=ON" in txt
        and "-DCMAKE_CXX_FLAGS=-DFEX_IOS_HOST" in txt
        and "-DCMAKE_DISABLE_FIND_PACKAGE_fmt=ON" in txt
        and "-DCMAKE_POLICY_VERSION_MINIMUM=3.5" in txt,
        f"{rel} passes FEX_IOS_HOST, bundled-dependency, and policy-minimum CMake flags",
    )

fex_cmake = (FEX / "CMakeLists.txt").read_text(encoding="utf-8")
check(
    "if (NOT APPLE)" in fex_cmake and "add_subdirectory(Source/)" in fex_cmake,
    "FEX/CMakeLists.txt skips Source/ on APPLE (build/fex-ios builds FEXCore only)",
)

wow64_doc = (ROOT / "docs/WOW64.md").read_text(encoding="utf-8")
building_doc = (ROOT / "docs/BUILDING.md").read_text(encoding="utf-8")
check("build/fex-patches" in wow64_doc and "16 KB" in wow64_doc, "docs/WOW64.md documents build/fex-patches and 0001")
check("build/fex-patches" in building_doc and "16 KB" in building_doc, "docs/BUILDING.md documents build/fex-patches and 0001")

# ------------------------------------------------------------------ 4. behavioral mock run
orig_tracker = (FEX / "Source/Windows/Common/InvalidationTracker.cpp").read_bytes()
with tempfile.TemporaryDirectory(prefix="check-fex-patches-") as d:
    tmp = Path(d)
    fex_tmp = tmp / "FEX"
    (fex_tmp / "Source/Windows/Common").mkdir(parents=True)
    (fex_tmp / "Source/Windows/Common/InvalidationTracker.cpp").write_bytes(orig_tracker)
    subprocess.run(["git", "init", "-q", str(fex_tmp)], check=True)
    subprocess.run(["git", "-C", str(fex_tmp), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(fex_tmp), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "pin"],
        check=True,
    )

    shutil.copytree(PATCH_DIR, tmp / "build/fex-patches")
    for arch in ("arm64ec", "wow64"):
        dst = tmp / f"build/fex-{arch}/build.sh"
        dst.parent.mkdir(parents=True)
        shutil.copy2(ROOT / f"build/fex-{arch}/build.sh", dst)
        # Pre-populate a partial CMakeCache.txt as upstream's test_partial_fex_configure_is_retried did.
        cache = fex_tmp / f"build-{arch}/CMakeCache.txt"
        cache.parent.mkdir(parents=True)
        cache.write_text("partial configure\n", encoding="utf-8")
    (tmp / "app/Madeira/aarch64-windows").mkdir(parents=True)

    mock_bin = tmp / "bin"
    mock_bin.mkdir()
    mock_cmake = mock_bin / "cmake"
    mock_cmake.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'if [ "$1" = -S ]; then\n'
        '  grep -q "MADEIRA_TRAP_PAGE_SIZE = 0x4000" "$2/Source/Windows/Common/InvalidationTracker.cpp"\n'
        '  touch "$CONFIGURED"\n'
        "else\n"
        '  test -f "$CONFIGURED"\n'
        '  mkdir -p "$(dirname "$BINARY")"\n'
        '  echo binary > "$BINARY"\n'
        "fi\n",
        encoding="utf-8",
    )
    mock_cmake.chmod(mock_cmake.stat().st_mode | stat.S_IXUSR)

    base_env = dict(os.environ, PATH=f"{mock_bin}{os.pathsep}{os.environ['PATH']}")

    r1 = subprocess.run(
        ["bash", str(tmp / "build/fex-arm64ec/build.sh")],
        cwd=tmp,
        env=dict(base_env, CONFIGURED=str(tmp / "arm64ec.cfg"), BINARY=str(fex_tmp / "build-arm64ec/Bin/libarm64ecfex.dll")),
        capture_output=True,
        text=True,
    )
    check(
        r1.returncode == 0
        and "fex-patches: applied 0001-windows-ios-smc-traps-per-16k-host-page.patch" in r1.stdout
        and (tmp / "app/Madeira/arm64ec-windows/xtajit64.dll").is_file(),
        "mock build (arm64ec): applies 0001 before cmake -S, retries partial configure, and stages xtajit64.dll",
    )

    r2 = subprocess.run(
        ["bash", str(tmp / "build/fex-wow64/build.sh")],
        cwd=tmp,
        env=dict(base_env, CONFIGURED=str(tmp / "wow64.cfg"), BINARY=str(fex_tmp / "build-wow64/Bin/libwow64fex.dll")),
        capture_output=True,
        text=True,
    )
    check(
        r2.returncode == 0
        and "fex-patches: 0001-windows-ios-smc-traps-per-16k-host-page.patch already applied" in r2.stdout
        and (tmp / "app/Madeira/aarch64-windows/xtajit.dll").is_file(),
        "mock build (wow64): skips already-applied 0001, retries partial configure, and stages xtajit.dll",
    )

    r3 = subprocess.run(["bash", str(tmp / "build/fex-patches/apply.sh"), "--revert"], cwd=tmp, capture_output=True, text=True)
    check(
        r3.returncode == 0
        and "fex-patches: reverted 0001-windows-ios-smc-traps-per-16k-host-page.patch" in r3.stdout
        and (fex_tmp / "Source/Windows/Common/InvalidationTracker.cpp").read_bytes() == orig_tracker,
        "apply.sh --revert restores InvalidationTracker.cpp byte-for-byte",
    )

    (fex_tmp / "Source/Windows/Common/InvalidationTracker.cpp").write_text("unrelated file\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(fex_tmp), "commit", "-am", "conflict", "-q"], check=True)
    r4 = subprocess.run(["bash", str(tmp / "build/fex-patches/apply.sh")], cwd=tmp, capture_output=True, text=True)
    check(
        r4.returncode != 0 and "does not apply on FEX" in r4.stderr,
        "apply.sh exits non-zero with clear message when a patch does not apply",
    )


# ------------------------------------------------------------------ 5. shipped DLL machine-code check
def verify_dll_has_16k_smc_traps(dll_path: Path):
    data = dll_path.read_bytes()
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24
    image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
    exc_rva, exc_size = struct.unpack_from("<II", data, opt_off + 112 + 3 * 8)
    sec_off = opt_off + opt_size
    sections = []
    for i in range(num_sec):
        s = sec_off + i * 40
        name = data[s:s + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, s + 8)
        sections.append((name, rva, vsize, raw_ptr, raw_size))

    def rva_to_off(rva: int):
        for _, srva, vsize, raw_ptr, raw_size in sections:
            if srva <= rva < srva + max(vsize, raw_size):
                return raw_ptr + (rva - srva)
        return None

    # Find '[smc-hot] page ' VA in .rdata
    idx = data.find(b"[smc-hot] page ")
    if idx < 0:
        return False, "missing '[smc-hot] page ' string"
    str_va = None
    for _, srva, _, raw_ptr, raw_size in sections:
        if raw_ptr <= idx < raw_ptr + raw_size:
            str_va = image_base + srva + (idx - raw_ptr)
            break
    if str_va is None:
        return False, "could not map string offset to VA"
    target_page, target_off = str_va & ~0xFFF, str_va & 0xFFF

    # Locate ADRP + ADD referencing '[smc-hot] page ' inside .text
    text_sec = [s for s in sections if s[0] == ".text"][0]
    _, trva, tvsize, traw, trsize = text_sec
    tspan = min(tvsize, trsize)
    xref_rva = None
    for off in range(0, tspan - 4, 4):
        insn = struct.unpack_from("<I", data, traw + off)[0]
        if (insn & 0x9F000000) == 0x90000000:
            rd = insn & 0x1F
            imm = (((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 0x3)
            if imm & (1 << 20):
                imm -= 1 << 21
            pc_va = image_base + trva + off
            if (pc_va & ~0xFFF) + (imm << 12) == target_page:
                for k in range(1, 7):
                    if off + 4 * k >= tspan:
                        break
                    i2 = struct.unpack_from("<I", data, traw + off + 4 * k)[0]
                    if (i2 & 0xFFC00000) == 0x91000000 and ((i2 >> 5) & 0x1F) == rd and ((i2 >> 10) & 0xFFF) == target_off:
                        xref_rva = trva + off
                        break
        if xref_rva is not None:
            break
    if xref_rva is None:
        return False, "no ADRP+ADD xref to '[smc-hot] page '"

    # Find enclosing function bounds in .pdata (ARM64 uses DataDirectory[3];
    # ARM64EC leaves DataDirectory[3] empty and stores ARM64 unwind entries in .pdata)
    if exc_rva and exc_size:
        poff, psize = rva_to_off(exc_rva), exc_size
    else:
        psec = [s for s in sections if s[0] == ".pdata"][0]
        poff, psize = psec[3], min(psec[2], psec[4])
    fn_rva = fn_len = None
    for i in range(0, psize, 8):
        brva, unwind = struct.unpack_from("<II", data, poff + i)
        if brva == 0 and unwind == 0:
            continue
        if unwind & 0x3:
            flen = ((unwind >> 2) & 0x7FF) * 4
        else:
            hdr = struct.unpack_from("<I", data, rva_to_off(unwind))[0]
            flen = (hdr & 0x3FFFF) * 4
        if brva <= xref_rva < brva + flen:
            fn_rva, fn_len = brva, flen
            break
    if fn_rva is None:
        return False, "could not find enclosing .pdata entry for HandleRWXAccessViolation"

    fn_off = rva_to_off(fn_rva)
    insns = [struct.unpack_from("<I", data, fn_off + j)[0] for j in range(0, fn_len, 4)]
    # ARM64 64-bit AND immediate with ~0x3fff (0xffffffffffffc000):
    # sf=1, opc=00, 100100, N=1, immr=50 (0x32), imms=49 (0x31) -> top 22 bits = 0x9272c400 >> 10
    has_16k_mask = any((ins & 0xFFFFFC00) == 0x9272C400 for ins in insns)
    # mov wN, #0x4000 or mov xN, #0x4000 (MOVZ hw=0, imm16=0x4000 -> (ins & 0x7FFFE0) == 0x080000 with opc=10)
    has_mov_0x4000 = any((ins & 0x7FFFFFE0) == 0x52880000 for ins in insns)
    return (
        has_16k_mask and has_mov_0x4000,
        f"fn_rva=0x{fn_rva:x} len={fn_len} has_16k_mask={has_16k_mask} has_mov_0x4000={has_mov_0x4000}",
    )


for rel in ("app/Madeira/aarch64-windows/xtajit.dll", "app/Madeira/arm64ec-windows/xtajit64.dll"):
    ok, detail = verify_dll_has_16k_smc_traps(ROOT / rel)
    check(ok, f"{rel} HandleRWXAccessViolation uses 16 KB trap page mask & size ({detail})")

if failures:
    print(f"\n{len(failures)} check(s) failed", file=sys.stderr)
    sys.exit(1)
print("check-fex-patches: OK")
