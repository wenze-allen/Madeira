#!/usr/bin/env python3
"""Interleaved threads cannot defeat the memory livelock caps; no Wine runs.

Two caps in build/ntdll-unix/virtual_ios.c stop the ml461 placement livelock (V8's
512MB CodeRange granted, rejected and released forever, spilled into the FEX band
until the process starved):
  - the reserve->release cycle deny (ios_reserve_cycle_note / _count): a
    (tid, size) granted and released IOS_RESCYCLE_DENY times is refused;
  - the steer valve's per-tid intake cap (ios_steer_intake): IOS_STEER_CAP
    steered arenas per thread.
Both kept their counts in small tables chosen by a hash of the tid (8 slots by
(tid ^ size) & 7; 16 slots, never freed, then tid & 15). Wine's tids are multiples
of 4 and never reused here, so two threads shared a slot, reset each other's count
at every alternation, and neither cap ever applied.

Compiles the production functions against a fake clock and checks:
  - two threads cycling in turn are both denied at the threshold;
  - a key quiet for the idle window starts over; a denied key stays denied
    after it, and through 100 other keys filling the table;
  - two later threads in the old shared slot are each capped at 24 steers;
    a capped thread stays capped through 100 other threads; a thread that
    exited gives its slot up first;
  - 8 threads asking at once each get exactly the cap (the tables are locked).
Needs python3 and a C compiler.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
vm = (root / 'build/ntdll-unix/virtual_ios.c').read_text(errors='replace')


def between(first, last):
    start = vm.index(first)
    return vm[start:vm.index(last, start) + len(last)] + '\n'


cycle = between('#define IOS_RESCYCLE_SLOTS 64', '    return cycles;\n}')
dead = between('static unsigned char ios_tid_dead[8192];', 'ios_tid_dead[tid >> 3] |= (1u << (tid & 7));\n}')
dead += between('static int ios_tid_is_dead( unsigned tid )', '    return (ios_tid_dead[tid >> 3] >> (tid & 7)) & 1;\n}')
steer = between('#define IOS_STEER_CAP 24', '    return n < IOS_STEER_CAP;\n}')

# The old hashed tables are gone, and the callers use the helpers.
assert 'ios_rescycle[8]' not in vm and 'steer_tid[16]' not in vm and 'sslot = stid & 15' not in vm
assert 'if (cyc >= IOS_RESCYCLE_DENY)' in vm and 'if (ios_steer_intake( stid ))' in vm
assert '#define IOS_BIGRES_MAX 256' in vm and 'pthread_mutex_lock( &ios_bigres_lock );' in vm

code = r'''
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#define dprintf(fd, ...) ((void)0)
static unsigned long long fake_ms = 1000000;
static unsigned long long ios_now_ms( void ) { return __atomic_load_n( &fake_ms, __ATOMIC_RELAXED ); }
'''
code += cycle + dead + steer
code += r'''
#define CODERANGE 0x20000000ull
static int denied( unsigned tid ) { return ios_reserve_cycle_count( tid, CODERANGE ) >= IOS_RESCYCLE_DENY; }

static void *asker( void *arg )
{
    unsigned tid = (unsigned)(uintptr_t)arg, i, allowed = 0;
    for (i = 0; i < 40; i++) allowed += ios_steer_intake( tid );
    return (void *)(uintptr_t)allowed;
}

int main( void )
{
    unsigned i, a = 0x40, b = 0x48, allowed_a = 0, allowed_b = 0;

    /* Two threads cycling in turn: the old table put both in slot 0. */
    for (i = 0; i < IOS_RESCYCLE_DENY; i++)
    {
        assert( !denied( a ) && !denied( b ) );
        ios_reserve_cycle_note( a, CODERANGE ); ios_reserve_cycle_note( b, CODERANGE );
        fake_ms += 5;
    }
    assert( denied( a ) && denied( b ) );

    /* Quiet for the idle window: a key not yet denied starts over. */
    for (i = 0; i < IOS_RESCYCLE_DENY - 1; i++) ios_reserve_cycle_note( 0x80, CODERANGE );
    fake_ms += IOS_RESCYCLE_IDLE_MS + 1;
    assert( ios_reserve_cycle_count( 0x80, CODERANGE ) == 0 );
    ios_reserve_cycle_note( 0x80, CODERANGE );
    assert( ios_reserve_cycle_count( 0x80, CODERANGE ) == 1 );
    /* A denied key stays denied after the window and through 100 other keys. */
    assert( denied( a ) && denied( b ) );
    for (i = 0; i < 100; i++) { ios_reserve_cycle_note( 0x1000 + 4 * i, CODERANGE ); fake_ms += 1; }
    assert( denied( a ) && denied( b ) );
    /* Another size of the same thread is its own key. */
    assert( ios_reserve_cycle_count( a, 0x10000000ull ) == 0 );

    /* Steer: 16 earlier threads steered once (the old table was then full for good). */
    for (i = 0; i < 16; i++) assert( ios_steer_intake( 0x20 + 4 * i ) );
    /* Two later threads that the old table put in one slot (tid & 15), asking in turn. */
    for (i = 0; i < 40; i++) { allowed_a += ios_steer_intake( 0x100 ); allowed_b += ios_steer_intake( 0x110 ); }
    assert( allowed_a == IOS_STEER_CAP && allowed_b == IOS_STEER_CAP );
    /* A capped thread stays capped while 100 other threads steer once each. */
    for (i = 0; i < 100; i++) ios_steer_intake( 0x400 + 4 * i );
    assert( !ios_steer_intake( 0x100 ) && !ios_steer_intake( 0x110 ) );
    /* A thread that exited gives its slot up before any live one. */
    {
        unsigned victim = 0x400 + 4 * 99, slot, fresh = 0x2000;
        for (slot = 0; slot < IOS_STEER_TIDS && !(ios_steer_tid[slot].n && ios_steer_tid[slot].tid == victim); slot++);
        assert( slot < IOS_STEER_TIDS );
        ios_thread_died( victim );
        assert( ios_steer_intake( fresh ) && ios_steer_tid[slot].tid == fresh );
    }

    /* 8 threads at once, each with its own tid: each gets exactly the cap. */
    {
        pthread_t t[8];
        for (i = 0; i < 8; i++) pthread_create( &t[i], NULL, asker, (void *)(uintptr_t)(0x8000 + 4 * i) );
        for (i = 0; i < 8; i++)
        {
            void *got;
            pthread_join( t[i], &got );
            assert( (uintptr_t)got == IOS_STEER_CAP );
        }
    }
    puts( "PASS: two threads in turn are both denied / capped; idle keys start over; capped and denied keys stay" );
    return 0;
}
'''

cc = os.environ.get('CC') or shutil.which('cc') or shutil.which('gcc') or shutil.which('clang')
if not cc:
    print('SKIP: no C compiler')
    raise SystemExit(0)
with tempfile.TemporaryDirectory() as tmp:
    src, exe = Path(tmp) / 'caps.c', Path(tmp) / 'caps'
    src.write_text(code)
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Werror', '-Wno-unused-function', '-pthread']
    built = subprocess.run([cc, *flags, '-fsanitize=thread', str(src), '-o', str(exe)], capture_output=True)
    if built.returncode != 0:   # no ThreadSanitizer runtime: the counts are still checked
        print('NOTE: built without ThreadSanitizer')
        subprocess.run([cc, *flags, str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print('PASS: memory livelock caps')
