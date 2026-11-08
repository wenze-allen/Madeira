#!/usr/bin/env python3
"""An AnyCPU IL-only PE32 .NET image is not promoted to ARM64 while the ARM64 set has no
mscoree.dll (build/wineserver/mapping_ios.c, upstream's MADEIRA_ILONLY_WOW64 fix from 0a2e6ed);
no Wine runs.

Upstream marks an IL-only PE32 image without COMIMAGE_FLAGS_32BITREQUIRED "native ready", so it
runs as a native ARM64 process. That process loads mscoree.dll from the aarch64 set, which has
none (Wine Mono has no ARM64 build), and the image ended with c000007b. Without the flag it runs
as WoW64 with the i386 mscoree.dll, as 32BITREQUIRED programs already do.

Compiles ios_native_has_mscoree and ios_ilonly_image_flags out of the source and checks, on a
WINEDLLPATH of temporary directories:
  - no aarch64-windows/mscoree.dll on the path: AnyCPU images lose ComPlusNativeReady;
  - one in any path directory: they keep it, as upstream;
  - 32BITREQUIRED never has it, 32BITPREFERRED keeps ComPlusPrefer32bit, ILOnly is always set;
  - a native machine other than ARM64, or no path, answers upstream's way.
Then checks that get_image_params uses them behind the switch.
Needs python3 and a C compiler.
"""
from pathlib import Path
import subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
src = (root / "build/wineserver/mapping_ios.c").read_text()
ok = True


def check(what, cond):
    global ok
    print(("PASS: " if cond else "FAIL: ") + what)
    ok &= bool(cond)


def function(sig):
    a = src.index(sig)
    return src[a:src.index("\n}\n", a) + 3]


has = function("static int ios_native_has_mscoree( const char *dll_path, unsigned short native )\n{")
flags = function("static unsigned int ios_ilonly_image_flags( DWORD clr_flags, int native_runs_ilonly )\n{")
check("get_image_params asks only while the switch is on",
      "int native_ilonly = !ios_ilonly_wow64_enabled() ||\n"
      "                                ios_native_has_mscoree( getenv( \"WINEDLLPATH\" ), native_machine );" in src
      and "mapping->image.image_flags |= ios_ilonly_image_flags( clr.Flags, native_ilonly );" in src)
check("upstream's unconditional ComPlusNativeReady is gone",
      "                mapping->image.image_flags |= IMAGE_FLAGS_ComPlusNativeReady;\n" not in
      src[src.index("static unsigned int get_image_params("):])
check("the switch is read from madeira.cfg first, then the environment",
      'madeira_cfg_get( "env.MADEIRA_ILONLY_WOW64", buf, sizeof(buf) )' in src and 'getenv( "MADEIRA_ILONLY_WOW64" )' in src)

harness = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef unsigned int DWORD;
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define COMIMAGE_FLAGS_ILONLY 1
#define COMIMAGE_FLAGS_32BITREQUIRED 2
#define COMIMAGE_FLAGS_32BITPREFERRED 0x20000
#define IMAGE_FLAGS_ComPlusNativeReady 0x01
#define IMAGE_FLAGS_ComPlusILOnly 0x02
#define IMAGE_FLAGS_ComPlusPrefer32bit 0x10
''' + has + flags + r'''
static int fails;
static void expect( const char *what, unsigned got, unsigned want )
{
    if (got != want) { printf( "FAIL: %s: %#x, want %#x\n", what, got, want ); fails++; }
    else printf( "PASS: %s\n", what );
}
int main( int argc, char **argv )
{
    const char *without = argv[1], *with = argv[2];
    int n_without = ios_native_has_mscoree( without, IMAGE_FILE_MACHINE_ARM64 );
    int n_with = ios_native_has_mscoree( with, IMAGE_FILE_MACHINE_ARM64 );
    expect( "no aarch64 mscoree.dll on the path: the native machine cannot run IL-only", n_without, 0 );
    expect( "one in the second path directory: it can", n_with, 1 );
    expect( "a native machine other than ARM64: upstream's answer", ios_native_has_mscoree( without, IMAGE_FILE_MACHINE_AMD64 ), 1 );
    expect( "no WINEDLLPATH: upstream's answer", ios_native_has_mscoree( NULL, IMAGE_FILE_MACHINE_ARM64 ), 1 );
    expect( "an empty WINEDLLPATH: upstream's answer", ios_native_has_mscoree( "", IMAGE_FILE_MACHINE_ARM64 ), 1 );
    expect( "AnyCPU, no ARM64 mscoree: ILOnly only (runs as WoW64)", ios_ilonly_image_flags( COMIMAGE_FLAGS_ILONLY, n_without ),
            IMAGE_FLAGS_ComPlusILOnly );
    expect( "AnyCPU, ARM64 mscoree: native ready, as upstream", ios_ilonly_image_flags( COMIMAGE_FLAGS_ILONLY, n_with ),
            IMAGE_FLAGS_ComPlusILOnly | IMAGE_FLAGS_ComPlusNativeReady );
    expect( "32BITREQUIRED: never native ready", ios_ilonly_image_flags( COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_32BITREQUIRED, 1 ),
            IMAGE_FLAGS_ComPlusILOnly );
    expect( "32BITPREFERRED keeps Prefer32bit", ios_ilonly_image_flags( COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_32BITPREFERRED, 0 ),
            IMAGE_FLAGS_ComPlusILOnly | IMAGE_FLAGS_ComPlusPrefer32bit );
    return fails != 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    for sub in ("a/aarch64-windows", "a/i386-windows", "b/aarch64-windows"):
        (d / sub).mkdir(parents=True)
    (d / "a/i386-windows/mscoree.dll").write_bytes(b"MZ")
    (d / "a/aarch64-windows/kernel32.dll").write_bytes(b"MZ")
    (d / "b/aarch64-windows/mscoree.dll").write_bytes(b"MZ")
    c = d / "t.c"
    c.write_text(harness)
    exe = d / "t"
    cc = subprocess.run(["cc", "-std=c11", "-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                         "-Wall", "-o", str(exe), str(c)], capture_output=True, text=True)
    if cc.returncode:
        sys.exit("FAIL: the helpers did not compile:\n" + cc.stderr[-3000:])
    r = subprocess.run([str(exe), "%s/a:%s/missing" % (d, d), "%s/a:%s/b" % (d, d)], capture_output=True, text=True)
    print(r.stdout, end="")
    if r.returncode:
        ok = False
        print(r.stderr[-2000:])
if not ok:
    sys.exit(1)
print("check-ilonly-machine: OK")
