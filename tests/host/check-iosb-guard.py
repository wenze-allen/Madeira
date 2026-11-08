#!/usr/bin/env python3
"""An async I/O completion in a 32-bit process stores its IO_STATUS_BLOCK32 only where it lands
(ios_set_async_iosb in build/ntdll-unix/server_ios.c, upstream's MADEIRA_IOSB_DEAD_TARGET fix from
0a2e6ed); no Wine runs.

ntdll picks the 32-bit status-block layout from the calling pseudo-process, so 64-bit native code
running inside a 32-bit process hands back a stale stack value as the address. The store faulted
on an unmapped page and the redelivery guard looped on it.

Compiles the guard out of the source with the probes, set_async_iosb, in_wow64_call and
ios_wow_base stubbed, and checks:
  - an address in the process's own 4 GB window is stored without a probe;
  - below the 4 GB floor only the sub-floor/low-allocation probe decides;
  - above it the mapping probe decides, and a hole drops the store with an [iosb-guard] line;
  - an address whose 8 bytes wrap is dropped;
  - a 64-bit process, a NULL status block and env.MADEIRA_IOSB_DEAD_TARGET = 0 always store;
  - invoke_system_apc's async completion goes through the guard.
Needs python3 and a C compiler.
"""
from pathlib import Path
import os, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
src = (root / "build/ntdll-unix/server_ios.c").read_text()
a = src.index("extern int ios_iosb_probe_mapped( unsigned long long addr, unsigned long long len );")
b = src.index("    set_async_iosb( iosb, status, info );\n}\n", a) + len("    set_async_iosb( iosb, status, info );\n}\n")
guard = src[a:b]
ok = True


def check(what, cond):
    global ok
    print(("PASS: " if cond else "FAIL: ") + what)
    ok &= bool(cond)


check("invoke_system_apc's async completion goes through the guard",
      "            ios_set_async_iosb( call->async_io.sb, result->async_io.status, info );\n" in src
      and "            set_async_iosb( call->async_io.sb, result->async_io.status, info );\n" not in src)
emu = (root / "build/ntdll-unix/signal_arm64_ios_emulate.c").read_text()
check("the two probes are defined in the signal unit",
      "int ios_iosb_probe_mapped( unsigned long long addr, unsigned long long len )\n{" in emu
      and "int ios_iosb_probe_served_low( unsigned long long addr, unsigned long long len )\n{" in emu)

harness = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long client_ptr_t;
typedef unsigned int NTSTATUS;
typedef unsigned long ULONG_PTR;
static int wow, stored, probed_low, probed_map, low_answer, map_answer;
static unsigned long long window;
static int in_wow64_call( void ) { return wow; }
static unsigned long long ios_wow_base( void ) { return window; }
static void set_async_iosb( client_ptr_t iosb, NTSTATUS status, ULONG_PTR info ) { stored++; }
int ios_iosb_probe_mapped( unsigned long long addr, unsigned long long len ) { probed_map++; return map_answer; }
int ios_iosb_probe_served_low( unsigned long long addr, unsigned long long len ) { probed_low++; return low_answer; }
''' + guard + r'''
static int fails;
static void run( const char *what, int w, unsigned long long win, client_ptr_t iosb, int low, int map,
                 int want_stored, int want_low, int want_map )
{
    wow = w; window = win; low_answer = low; map_answer = map;
    stored = probed_low = probed_map = 0;
    ios_set_async_iosb( iosb, 0x103, 0x40 );
    if (stored != want_stored || probed_low != want_low || probed_map != want_map)
    {
        printf( "FAIL: %s: stored=%d low=%d map=%d, want %d %d %d\n", what, stored, probed_low, probed_map,
                want_stored, want_low, want_map );
        fails++;
    }
    else printf( "PASS: %s\n", what );
}
int main( int argc, char **argv )
{
    int off = argc > 1 && !strcmp( argv[1], "off" );
    if (off)
    {
        run( "switch off: a hole is stored anyway", 1, 0x400000000ull, 0x7000000000ull, 0, 0, 1, 0, 0 );
        return fails != 0;
    }
    run( "own window: stored, no probe", 1, 0x400000000ull, 0x400012340ull, 0, 0, 1, 0, 0 );
    run( "own window, last 8 bytes", 1, 0x400000000ull, 0x4fffffff8ull, 0, 0, 1, 0, 0 );
    run( "below the floor, served: stored", 1, 0x400000000ull, 0x00401000ull, 1, 0, 1, 1, 0 );
    run( "below the floor, not served: dropped", 1, 0x400000000ull, 0x00401000ull, 0, 1, 0, 1, 0 );
    run( "above the floor, mapped: stored", 1, 0x400000000ull, 0x7000000000ull, 0, 1, 1, 0, 1 );
    run( "above the floor, a hole: dropped", 1, 0x400000000ull, 0x7000000000ull, 1, 0, 0, 0, 1 );
    run( "past the window, a hole: dropped", 1, 0x400000000ull, 0x500000000ull, 1, 0, 0, 0, 1 );
    run( "wraps: dropped", 1, 0x400000000ull, 0xfffffffffffffffcull, 1, 1, 0, 0, 0 );
    run( "no window known: the probe decides", 1, 0, 0x400012340ull, 0, 0, 0, 0, 1 );
    run( "64-bit process: stored, no probe", 0, 0, 0x7000000000ull, 0, 0, 1, 0, 0 );
    run( "NULL status block: passed on, no probe", 1, 0x400000000ull, 0, 0, 0, 1, 0, 0 );
    return fails != 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    c = Path(d) / "t.c"
    c.write_text(harness)
    exe = Path(d) / "t"
    cc = subprocess.run(["cc", "-std=c11", "-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                         "-Wall", "-Wno-unused-variable", "-Wno-unused-function", "-o", str(exe), str(c)],
                        capture_output=True, text=True)
    if cc.returncode:
        sys.exit("FAIL: the guard did not compile:\n" + cc.stderr[-3000:])
    for mode, env in (("on", {}), ("off", {"MADEIRA_IOSB_DEAD_TARGET": "0"})):
        e = {k: v for k, v in os.environ.items() if k != "MADEIRA_IOSB_DEAD_TARGET"}
        e.update(env)
        r = subprocess.run([str(exe), mode], capture_output=True, text=True, env=e)
        print(r.stdout, end="")
        if r.returncode:
            ok = False
            print("FAIL (%s): %s" % (mode, r.stderr[-2000:]))
if not ok:
    sys.exit(1)
print("check-iosb-guard: OK")
