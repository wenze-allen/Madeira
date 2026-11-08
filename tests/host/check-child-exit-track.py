#!/usr/bin/env python3
"""The child table in build/ntdll-unix/process_ios.c stops counting a child whose process ended off
its boot thread (upstream's MADEIRA_CHILD_EXIT_TRACK, 0a2e6ed), and the redelivery storm guard can
end one child process instead of the app (MADEIRA_REDELIV_CHILD_ONLY); no Wine runs.

A child that ends on a worker thread never returns to its boot thread, so its slot was never
released and the launcher wait in WineProcessBridge.m waited for a program long dead. The slot now
learns the child's PEB when it registers (ios_child_slot_bind_peb) and is marked when the process
ends (ios_child_slot_exited), whichever thread ends it.

Compiles the table's code out of the source and checks:
  - a child bound to its PEB counts until it is marked ended, and for 2 s after (IOS_CHILD_EXIT_SETTLE);
  - past that it no longer counts, though its slot is still held;
  - env.MADEIRA_CHILD_EXIT_TRACK = 0 counts it until the slot is released, as before;
  - ios_child_slot_name finds a bound child by PEB, and answers "?" for anything else;
  - a released slot forgets its PEB; helpers do not count.
Then checks the wiring: the boot thread sets ios_child_slot_current, server_init_process_child binds
the PEB, process_exit_wrapper marks the exit, and the [redeliv] guard calls ios_storm_end_child_only
before task_terminate.
Needs python3 and a C compiler.
"""
from pathlib import Path
import os, re, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
src = (root / "build/ntdll-unix/process_ios.c").read_text()
srv = (root / "build/ntdll-unix/server_ios.c").read_text()
sig = (root / "build/ntdll-unix/signal_arm64_ios_deliver.c").read_text()
ok = True


def check(what, cond):
    global ok
    print(("PASS: " if cond else "FAIL: ") + what)
    ok &= bool(cond)


a = src.index("#define IOS_CHILD_SLOTS 32")
b = src.index("    pthread_mutex_unlock( &ios_child_lock );\n    return count;\n}\n", a) + \
    len("    pthread_mutex_unlock( &ios_child_lock );\n    return count;\n}\n")
table = src[a:b]

check("the boot thread records its slot",
      "    ios_child_slot_current = args->slot;" in src)
check("server_init_process_child binds the PEB",
      re.search(r"ios_register_proc_socket\( ios_jit_current_peb\(\), child_fd_socket \);\n(.*\n){0,4}\s*ios_child_slot_bind_peb\( ios_jit_current_peb\(\) \);", srv) is not None)
check("process_exit_wrapper marks the exit",
      re.search(r"ios_proc_sockets\[i\]\.peb = NULL;\n(.*\n){0,3}\s*ios_child_slot_exited\( dead_peb \);", srv) is not None)
check("the storm guard tries the child-only ending before task_terminate",
      re.search(r"if \(ios_storm_end_child_only\( thread, thread_teb, pc \)\)(.*\n){1,8}\s*dprintf\( 2, \"\[redeliv\] terminating process rev=ml465\\n\" \);\n\s*task_terminate",
                sig) is not None)
check("the child-only ending leaves out the first process and the fixed-base owner",
      "else if (ios_peb_is_live_child( peb ) && !ios_exe_win_owned_by( peb )) whole_process = 1;" in sig
      and "if (!ios_fault_pc_is_jit( pc )) return 0;" in sig)

harness = r'''
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
typedef unsigned short WCHAR;
typedef struct { unsigned short Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
static double fake_now;
#define clock_gettime(c, ts) ((ts)->tv_sec = (time_t)fake_now, (ts)->tv_nsec = (long)((fake_now - (time_t)fake_now) * 1e9), 0)
''' + table + r'''
static int fails;
static void expect( const char *what, int got, int want )
{
    if (got != want) { printf( "FAIL: %s: %d, want %d\n", what, got, want ); fails++; }
    else printf( "PASS: %s\n", what );
}
static int take( const char *name )
{
    WCHAR buf[64]; UNICODE_STRING s; unsigned i, n = strlen( name );
    for (i = 0; i < n; i++) buf[i] = name[i];
    s.Length = s.MaximumLength = n * sizeof(WCHAR); s.Buffer = buf;
    return ios_child_slot_take( &s );
}
int main( int argc, char **argv )
{
    int off = argc > 1 && !strcmp( argv[1], "off" );
    char nm[64];
    void *game = (void *)0x48ff84000, *helper = (void *)0x49ff84000;
    int g, h;

    fake_now = 100.0;
    g = take( "C:\\Games\\Game.exe" );
    ios_child_slot_current = g;
    ios_child_slot_bind_peb( game );
    h = take( "C:\\Games\\CrashHandler64.exe" );
    ios_child_slot_current = h;
    ios_child_slot_bind_peb( helper );
    if (off)
    {
        ios_child_slot_exited( game );
        fake_now = 200.0;
        expect( "switch off: an ended child counts until its slot is released", madeira_live_game_children( NULL, 0, -1 ), 1 );
        ios_child_slot_release( g );
        expect( "switch off: released, it no longer counts", madeira_live_game_children( NULL, 0, -1 ), 0 );
        return fails != 0;
    }
    expect( "a running child counts (the helper does not)", madeira_live_game_children( nm, sizeof(nm), -1 ), 1 );
    expect( "its name is listed", !strcmp( nm, "game.exe" ), 1 );
    expect( "the slot is found by PEB", ios_child_slot_name( game, nm, sizeof(nm) ), 1 );
    expect( "with its file name", !strcmp( nm, "game.exe" ), 1 );
    expect( "an unknown PEB is not found", ios_child_slot_name( (void *)0x1234000, nm, sizeof(nm) ), 0 );
    expect( "and answers ?", !strcmp( nm, "?" ), 1 );
    ios_child_slot_exited( game );
    fake_now = 101.5;
    expect( "ended 1.5 s ago: still counts (its boot thread may yet release it)", madeira_live_game_children( NULL, 0, -1 ), 1 );
    fake_now = 102.5;
    expect( "ended 2.5 s ago, never released: no longer counts", madeira_live_game_children( NULL, 0, -1 ), 0 );
    expect( "its slot is still held", ios_child_slots[g].used, 1 );
    ios_child_slot_release( g );
    expect( "a released slot forgets its PEB", ios_child_slot_name( game, nm, sizeof(nm) ), 0 );
    g = take( "C:\\Games\\Game2.exe" );
    expect( "a reused slot starts clean (not ended)", ios_child_slots[g].exited, 0 );
    expect( "and counts", madeira_live_game_children( NULL, 0, -1 ), 1 );
    return fails != 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    c = Path(d) / "t.c"
    c.write_text(harness)
    exe = Path(d) / "t"
    cc = subprocess.run(["cc", "-std=c11", "-O1", "-pthread", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                         "-Wall", "-Wno-unused-variable", "-Wno-unused-function", "-o", str(exe), str(c)],
                        capture_output=True, text=True)
    if cc.returncode:
        sys.exit("FAIL: the child table did not compile:\n" + cc.stderr[-3000:])
    for mode, env in (("on", {}), ("off", {"MADEIRA_CHILD_EXIT_TRACK": "0"})):
        e = {k: v for k, v in os.environ.items() if k != "MADEIRA_CHILD_EXIT_TRACK"}
        e.update(env)
        r = subprocess.run([str(exe), mode], capture_output=True, text=True, env=e)
        print(r.stdout, end="")
        if r.returncode:
            ok = False
            print("FAIL (%s): %s" % (mode, r.stderr[-2000:]))
if not ok:
    sys.exit(1)
print("check-child-exit-track: OK")
