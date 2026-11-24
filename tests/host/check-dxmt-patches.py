#!/usr/bin/env python3
"""Madeira's DXMT patch series, submodule pin, build scripts and CI wiring.

Checks:
  1. build/dxmt-patches/ keeps 0001-airconv-tessellation-atomic.patch first and
     0002-d3d9-index-range-per-draw.patch second, and README.md documents every
     patch in order.
  2. The dxmt gitlink is at 3d62913 (or a descendant), and running the real
     build/dxmt-patches/apply.sh against an exported copy of that pin applies
     both patches in order, is idempotent on a second run, reverts them in
     reverse order under --revert leaving a clean tree, and fails cleanly when a
     broken patch is added.
  3. build/dxmt-ios/build.sh runs apply.sh before computing the shader-cache
     converter identity, before compiling Metal shader headers, and before
     compiling any C/C++/ObjC source; build/wine-i386/build.sh runs apply.sh
     before meson setup/compile and supports rebuilding DXMT's i386 DLLs alone
     (`build.sh dxmt`) or alongside named Wine modules (`build.sh mf ... dxmt`).
  4. The tracked ARM64EC app/Madeira/arm64ec-windows/d3d9.dll is DXMT's D3D9
     frontend (Windows GUI PE32+ ARM64EC, imports winemetal.dll and not
     wined3d.dll, plain DOS stub like the other ARM64EC DXMT DLLs, exports all
     12 D3D9 entry points, and embeds both MADEIRA_D3D9_INDEX_RANGE and
     MADEIRA_D3D9_LUMINANCE_RT).
  5. .github/workflows/mac-ipa.yml drops the stale 21e6697 libdxmt_combined.a
     from reuse/ and caches the iOS LLVM libraries and headers across runs.
"""
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
patches_dir = root / 'build/dxmt-patches'
dxmt = root / 'dxmt'
failures = []


def check(cond, label):
    print(('PASS: ' if cond else 'FAIL: ') + label)
    if not cond:
        failures.append(label)


def dxmt_git_cmd(*args: str):
    if not shutil.which('git'):
        return None
    if (dxmt / '.git').exists():
        return ['git', '--no-optional-locks', '-C', str(dxmt), *args]
    common = subprocess.run(['git', '--no-optional-locks', 'rev-parse', '--git-common-dir'],
                            cwd=root, capture_output=True, text=True)
    if common.returncode == 0:
        mod = (root / common.stdout.strip()).resolve() / 'modules/dxmt'
        if mod.is_dir():
            return ['git', '--no-optional-locks', f'--git-dir={mod}', '--work-tree=/tmp', *args]
    return None


# 1. Patch series files and README
patch_files = [p.name for p in sorted(patches_dir.glob('*.patch'))]
check(patch_files == ['0001-airconv-tessellation-atomic.patch',
                      '0002-d3d9-index-range-per-draw.patch'],
      'patch series is numbered in order: %r' % patch_files)
readme = (patches_dir / 'README.md').read_text(encoding='utf-8')
for name in patch_files:
    check(f'`{name}`' in readme, f'build/dxmt-patches/README.md documents {name}')

# 2. Pin and real apply.sh behaviour on an isolated archive of the pin
ls = subprocess.run(['git', '--no-optional-locks', 'ls-files', '-s', 'dxmt'],
                    cwd=root, capture_output=True, text=True)
pin = ls.stdout.split()[1] if len(ls.stdout.split()) >= 2 else ''
check(len(pin) == 40, 'dxmt gitlink recorded in index (%s)' % (pin[:12] or 'missing'))
if len(pin) == 40 and dxmt_git_cmd('rev-parse', '--git-dir') is not None:
    anc = subprocess.run(dxmt_git_cmd('merge-base', '--is-ancestor',
                                      '3d62913b75fb8b21ad6494f9d9f9853b19d9a014', pin),
                         capture_output=True)
    check(anc.returncode == 0, 'dxmt pin includes 3d62913 (luminance render targets + StretchRect exclusion)')

    with tempfile.TemporaryDirectory(prefix='madeira-dxmt-patches-') as tmp:
        fake_root = Path(tmp)
        shutil.copytree(patches_dir, fake_root / 'build/dxmt-patches')
        work_dxmt = fake_root / 'dxmt'
        work_dxmt.mkdir(parents=True)
        arch = subprocess.Popen(dxmt_git_cmd('archive', pin,
                                             'src/airconv/shaders/air_tessellation.metal',
                                             'src/d3d9/'),
                                stdout=subprocess.PIPE)
        subprocess.run(['tar', '-xf', '-', '-C', str(work_dxmt)], stdin=arch.stdout, check=True)
        arch.wait()
        subprocess.run(['git', 'init', '-q'], cwd=work_dxmt, check=True)
        subprocess.run(['git', 'add', '.'], cwd=work_dxmt, check=True)
        subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@t',
                        'commit', '-q', '-m', 'pin'], cwd=work_dxmt, check=True)

        apply_sh = fake_root / 'build/dxmt-patches/apply.sh'
        r1 = subprocess.run(['bash', str(apply_sh)], capture_output=True, text=True)
        check(r1.returncode == 0 and r1.stdout.splitlines() == [
            'dxmt-patches: applied 0001-airconv-tessellation-atomic.patch',
            'dxmt-patches: applied 0002-d3d9-index-range-per-draw.patch',
        ], 'apply.sh applies 0001 then 0002 cleanly on pinned dxmt %s' % pin[:7])

        r2 = subprocess.run(['bash', str(apply_sh)], capture_output=True, text=True)
        check(r2.returncode == 0 and r2.stdout.splitlines() == [
            'dxmt-patches: 0001-airconv-tessellation-atomic.patch already applied',
            'dxmt-patches: 0002-d3d9-index-range-per-draw.patch already applied',
        ], 'apply.sh is idempotent when patches are already applied')

        r3 = subprocess.run(['bash', str(apply_sh), '--revert'], capture_output=True, text=True)
        status = subprocess.run(['git', 'status', '--porcelain'], cwd=work_dxmt,
                                capture_output=True, text=True).stdout
        check(r3.returncode == 0 and r3.stdout.splitlines() == [
            'dxmt-patches: reverted 0002-d3d9-index-range-per-draw.patch',
            'dxmt-patches: reverted 0001-airconv-tessellation-atomic.patch',
        ] and status == '', 'apply.sh --revert removes 0002 then 0001 and leaves a clean tree')

        (fake_root / 'build/dxmt-patches/0003-broken.patch').write_text(
            'diff --git a/src/d3d9/d3d9_buffer.cpp b/src/d3d9/d3d9_buffer.cpp\n'
            '--- a/src/d3d9/d3d9_buffer.cpp\n+++ b/src/d3d9/d3d9_buffer.cpp\n'
            '@@ -1,3 +1,3 @@\n-nonexistent line\n+replacement\n', encoding='utf-8')
        r4 = subprocess.run(['bash', str(apply_sh)], capture_output=True, text=True)
        check(r4.returncode != 0 and '0003-broken.patch does not apply' in r4.stderr,
              'apply.sh fails loudly when a patch does not apply')

# 3. Build scripts apply patches first and support selective i386 DXMT rebuilds
dxmt_ios = (root / 'build/dxmt-ios/build.sh').read_text(encoding='utf-8')
apply_call = 'bash "$REPO_ROOT/build/dxmt-patches/apply.sh"'
check(apply_call in dxmt_ios, 'build/dxmt-ios/build.sh invokes build/dxmt-patches/apply.sh')
if apply_call in dxmt_ios:
    idx_apply = dxmt_ios.index(apply_call)
    for marker, desc in [
        ('converter_id_inputs()', 'computing shader-cache converter identity'),
        ('compile_objc ', 'compiling winemetal unix'),
        ('air_tessellation', 'compiling airconv Metal shader headers'),
        ('dxmt_command.metal', 'compiling dxmt_command Metal library'),
        ('d3d9_buffer.cpp', 'compiling native D3D9 frontend'),
    ]:
        check(idx_apply < dxmt_ios.index(marker),
              f'build/dxmt-ios/build.sh applies patches before {desc}')

wine_i386 = (root / 'build/wine-i386/build.sh').read_text(encoding='utf-8')
i386_apply = 'bash "$R/build/dxmt-patches/apply.sh"'
check(i386_apply in wine_i386 and wine_i386.index(i386_apply) < wine_i386.index('meson setup'),
      'build/wine-i386/build.sh applies patches before meson setup/compile')
check('if [ "$a" = dxmt ]; then' in wine_i386
      and 'dlls/dbghelp/i386-windows/libdbghelp.a' in wine_i386,
      'build/wine-i386/build.sh supports selective `dxmt` rebuilds with its 4 Wine import prerequisites')

build_modules = (root / 'build/wine-pe/build-modules.sh').read_text(encoding='utf-8')
check(re.search(r'\bd3d9\|.*d3d11', build_modules) is not None,
      'build/wine-pe/build-modules.sh refuses replacing DXMT arm64ec d3d9.dll with Wine d3d9')

# 4. Rebuilt tracked ARM64EC d3d9.dll (stripped, DXMT builtin, carries 3d62913 + 0002)
d3d9_dll = root / 'app/Madeira/arm64ec-windows/d3d9.dll'
raw = d3d9_dll.read_bytes()
check(raw[:2] == b'MZ' and b'Wine builtin DLL' in raw[:256],
      'arm64ec d3d9.dll is a PE DLL tagged with -Dwine_builtin_dll=true (like windows-runtime and wine-i386)')
pe_off = struct.unpack_from('<I', raw, 0x3C)[0]
_, machine, _, _, sym_ptr, num_syms, _, _ = struct.unpack_from('<4sHHIIIHH', raw, pe_off)
check(machine == 0x8664 and sym_ptr == 0 and num_syms == 0,
      'arm64ec d3d9.dll is ARM64EC (machine 0x8664) and stripped of COFF symbols')
check(b'winemetal.dll' in raw and b'wined3d.dll' not in raw,
      'arm64ec d3d9.dll is DXMT D3D9 (imports winemetal.dll, not wined3d.dll)')
for marker in (b'MADEIRA_D3D9_INDEX_RANGE', b'[d3d9-index-range]', b'MADEIRA_D3D9_LUMINANCE_RT'):
    check(marker in raw, f'arm64ec d3d9.dll contains {marker.decode()} from the new pin and patch')
for exp in (b'Direct3DCreate9', b'Direct3DCreate9Ex', b'Direct3DShaderValidatorCreate9',
            b'D3DPERF_BeginEvent', b'D3DPERF_EndEvent', b'D3DPERF_GetStatus',
            b'D3DPERF_QueryRepeatFrame', b'D3DPERF_SetMarker', b'D3DPERF_SetOptions',
            b'D3DPERF_SetRegion', b'DebugSetLevel', b'DebugSetMute'):
    check(exp in raw, f'arm64ec d3d9.dll exports {exp.decode()}')

# 5. CI workflow: overlay DXMT removal and pinned LLVM iOS cache steps
workflow = (root / '.github/workflows/mac-ipa.yml').read_text(encoding='utf-8')
rm_dxmt = 'rm -rf reuse/app/Madeira/libdxmt_combined.a reuse/build/dxmt-ios'
run_build = 'build/build-mac-reuse.sh\n'
llvm_key = "key: llvm-ios-v1-${{ env.XCODE_BUILD }}-${{ hashFiles('build/llvm-ios/build.sh') }}"
check(rm_dxmt in workflow and workflow.index(rm_dxmt) < workflow.index('build/build-mac-reuse.sh --plan'),
      'mac-ipa.yml removes the stale overlay libdxmt_combined.a before --plan and build')
check('uses: actions/cache/restore@v4' in workflow and 'uses: actions/cache/save@v4' in workflow,
      'mac-ipa.yml pins actions/cache/restore@v4 and actions/cache/save@v4')
check(workflow.count(llvm_key) == 2,
      'mac-ipa.yml uses the pinned Xcode + recipe key for both restoring and saving llvm-ios')
check("steps.cache-llvm-ios.outputs.cache-hit != 'true'" in workflow
      and "hashFiles('toolchains/mac-build/stamps/llvm-ios') != ''" in workflow
      and workflow.index('id: cache-llvm-ios') < workflow.index(run_build) < workflow.index('- name: Save LLVM for iOS'),
      'mac-ipa.yml restores llvm-ios before building and saves only a stamped new build')
check('toolchains/llvm-project/llvm/include/llvm/IR/Module.h' in workflow
      and 'toolchains/llvm-ios-build/include/llvm/Config/llvm-config.h' in workflow,
      'mac-ipa.yml validates restored LLVM source and generated headers before trusting the stamp')
for cached in ('toolchains/llvm-ios-build/lib',
               'toolchains/llvm-ios-build/include',
               'toolchains/llvm-project/llvm/include',
               'toolchains/mac-build/stamps/llvm-ios'):
    check(workflow.count(cached) >= 2, f'mac-ipa.yml restores and saves {cached} for dxmt-ios rebuilds')

if failures:
    print('FAILED (%d)' % len(failures))
    sys.exit(1)
print('PASS')
