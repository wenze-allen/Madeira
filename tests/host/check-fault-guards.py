#!/usr/bin/env python3
"""Interleaved faults cannot defeat the exception server's give-up guards; no Wine runs.

Each guard counts repeats of one fault and gives up (surfaces it, breaks the
loop, dispatches it, or ends the storm) after N. They kept their counts in 16
slots chosen by a hash of the key, or in one global record, so two faults that
landed in one slot reset each other on every alternation and the guard never
tripped: two JIT-pool pages 256 KB apart re-faulted forever in exec-recover,
and two threads stuck in turn never reached the livelock breaker's 50.

Compiles the production ios_guard_slot and the guards' own counting code from
build/ntdll-unix/signal_arm64_ios.c against a fake clock and checks:
  - exec-recover / reclaim-recover: one page gives up on try 9 / 65; two pages
    256 KB apart (the old shared slot) faulting in turn both give up as soon;
    64 pages in turn all do; a page that faults again after the idle window
    starts over instead of being refused for its lifetime count;
  - livelock breaker: two threads stuck in turn (one old slot) are both broken
    on their 51st fault (the 50th repeat); one thread alternating two pcs over
    one address (ml261) is broken as soon; an exception delivered to the thread
    starts its count again; an advancing address (ml876) is not broken until the
    20000 storm ceiling;
  - delivery debounce: two keys that shared an old slot are both dispatched on
    their 3rd fault;
  - redelivery terminal: two threads that shared an old slot both reach 2000;
  - stale-heal ring: each hot VA queued once; 1024 VAs x 256 faults with no
    drain (in turn, or one VA after another) never fills the ring; a ring that
    is full refuses instead of overwriting, and the VA is queued at its next
    fault once there is room.
Needs python3 and a C compiler.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
sig = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()


def between(first, last):
    start = sig.index(first)
    return sig[start:sig.index(last, start) + len(last)] + '\n'


helper = between('#define IOS_GUARD_SLOTS 64', '    return victim;\n}')
xr = between('static struct ios_guard_table xr_tab;', 'else if (++xr_n[s] > 8) giveup = 1;')
rr = between('static struct ios_guard_table rr_tab;', 'else if (++rr_n[s] > 64) giveup = 1;')
stuck = between('static struct ios_guard_table stk_tab;', '                            stk[ss].page_n = 0;\n                        }')
deliv = between('static volatile unsigned ios_guest_deliv_seq[16];', '__ATOMIC_RELEASE );\n}')
rep = between('static struct ios_guard_table rep_tab;', 'if (++rep_n[slot] < 3) return 0;')
redeliv = between('static struct ios_guard_table redeliv_tab;', 'ios_smc_loop_diag( thread, pc, fault_addr, rec.ExceptionCode );   /* one-shot [smc-loop], log only */\n        }')
heal = between('#define IOS_STALE_VA_MAX 256', 'static void *ios_stale_va_scanner( void *arg )').rsplit('static void *', 1)[0]

# The old schemes are gone from every guard.
for old in ('xr_pg[16]', 'rr_pg[16]', 'rep[16]', 'redeliv[16]', 'stk[16]'):
    assert old not in sig, old
assert 'volatile int ios_stale_va_tail' not in sig and '__ATOMIC_RELEASE' in heal

code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define STDERR_FILENO 2
#define dprintf(fd, ...) ((void)0)
static uint64_t fake_now = 1000;
static uint64_t mach_absolute_time( void ) { return fake_now; }
int mach_timebase_info( void *p ) { unsigned int *tb = p; tb[0] = 125; tb[1] = 3; return 0; }   /* 24 MHz */
#define TICK_MS 24000ull
'''
code += helper
code += 'static int xr_step( uint64_t pg ) {\n' + xr + '    return giveup;\n}\n'
code += 'static int rr_step( uint64_t fa ) {\n' + rr + '    return giveup;\n}\n'
code += deliv
code += r'''
/* the livelock breaker's surroundings */
typedef void *thread_state_t;
typedef uint64_t mach_vm_address_t, mach_vm_size_t;
typedef unsigned int mach_msg_type_number_t, mach_port_t;
typedef struct { int protection, max_protection; } vm_region_basic_info_data_64_t;
typedef void *vm_region_info_t;
#define VM_REGION_BASIC_INFO_COUNT_64 9
#define VM_REGION_BASIC_INFO_64 9
#define MACH_PORT_NULL 0
#define KERN_SUCCESS 0
#define ARM_THREAD_STATE64 6
static int mach_task_self( void ) { return 0; }
static int mach_vm_region( int t, mach_vm_address_t *a, mach_vm_size_t *s, int f, vm_region_info_t i,
                           mach_msg_type_number_t *c, mach_port_t *o )
{ (void)t; (void)a; (void)s; (void)f; (void)i; (void)c; (void)o; return 1; }
#define __darwin_arm_thread_state64_get_sp(st) ((uint64_t)0x1000)
#define __darwin_arm_thread_state64_set_sp(st, v) ((void)0)
#define __darwin_arm_thread_state64_set_pc_fptr(st, p) ((void)0)
static int thread_set_state( uint64_t t, int f, thread_state_t s, int c ) { (void)t; (void)f; (void)s; (void)c; return 0; }
static int ios_fault_loop_guest_progress_on( void ) { return 0; }
#define ios_fault_loop_guest_progress(...) 0
static int breaker_step( uint64_t thread, uint64_t fault_pc_check, uint64_t fault_addr )
{
    struct { uint64_t __x[29]; } state = { { 0 } };
    int count = 0, handled = 0;
    {
'''
code += stuck
code += r'''
    }
    return handled;
}
static int rep_dispatch( uint64_t thread, uint64_t pc, uint64_t fault_addr )
{
'''
code += rep
code += r'''
    return 1;
}
/* the redelivery guard's surroundings: the rate and guest-RIP options off */
static int ios_fault_guard_rate_on( void ) { return 0; }
static void ios_fgr_run_begin( uint64_t *t0, uint64_t *p0 ) { (void)t0; (void)p0; }
static int ios_fgr_say_256( void ) { return 1; }
static void ios_smc_loop_diag( uint64_t t, uint64_t pc, uint64_t a, unsigned code ) { (void)t; (void)pc; (void)a; (void)code; }
static uint32_t redeliv_count( uint64_t thread, uint64_t pc, uint64_t fault_addr )
{
    const uint64_t redeliv_guest_rip = 0;
    struct { unsigned ExceptionCode; } rec = { 0 };
'''
code += redeliv.replace('static volatile int ios_redeliv_terminating;', '')
code += r'''
    return redeliv[rslot].n;
}
'''
code += heal
code += r'''
static void step( void ) { fake_now += 24; }   /* 1 us between faults */

int main( void )
{
    uint64_t a = 0x7ecaf00000ull, b = a + 0x40000;   /* 256 KB apart: one old slot */
    int i, k, ga = 0, gb = 0;

    /* exec-recover */
    for (i = 1; i <= 9; i++, step()) ga = xr_step( 0x7ed0000000ull );
    assert( ga );
    for (i = 1; i <= 9 && !(ga && gb); i++) { ga = xr_step( a ); step(); gb = xr_step( b ); step(); }
    assert( ga && gb && i - 1 == 9 );
    {   /* 64 pages in turn */
        int given[64] = { 0 }, round;
        for (round = 1; round <= 9; round++)
            for (k = 0; k < 64; k++, step()) given[k] = xr_step( 0x7e00000000ull + (uint64_t)k * 0x40000 );
        for (k = 0; k < 64; k++) assert( given[k] );
    }
    /* a page that faults again after the idle window starts over: 40 events, 3 s apart */
    for (i = 0; i < 40; i++) { fake_now += 3000 * TICK_MS; assert( !xr_step( 0x7ef0000000ull ) ); }

    /* reclaim-recover */
    ga = gb = 0;
    for (i = 1; i <= 65 && !(ga && gb); i++) { ga = rr_step( a ); step(); gb = rr_step( b ); step(); }
    assert( ga && gb && i - 1 == 65 );

    /* livelock breaker: two threads stuck in turn, in one old slot */
    {
        uint64_t ta = 0x1103, tb;
        for (tb = 0x1104; ios_fault_slot( ta ) != ios_fault_slot( tb ); tb++) ;
        fake_now += 3000 * TICK_MS;
        ga = gb = 0;
        for (i = 1; i <= 60 && !(ga && gb); i++)
        {
            ga |= breaker_step( ta, 0x13b5f2004ull, 0x73d16aff30ull ); step();
            gb |= breaker_step( tb, 0x1026b3188ull, 0x7400001000ull ); step();
        }
        assert( ga && gb && i - 1 == 51 );   /* the first fault opens the record */
    }
    /* a delivery to the thread between faults starts its count again */
    fake_now += 3000 * TICK_MS;
    for (i = 1, ga = 0; i <= 40; i++, step()) ga |= breaker_step( 0x1503, 0x13b5f2004ull, 0x73d16aff30ull );
    ios_note_guest_delivery( 0x1503 );
    for (i = 1; i <= 40; i++, step()) ga |= breaker_step( 0x1503, 0x13b5f2004ull, 0x73d16aff30ull );
    assert( !ga );
    for (i = 1; i <= 60 && !ga; i++, step()) ga = breaker_step( 0x1503, 0x13b5f2004ull, 0x73d16aff30ull );
    assert( ga && i - 1 == 11 );   /* 40 since the delivery, then the 50th repeat */
    /* ml261: one thread, two pcs, one address */
    fake_now += 3000 * TICK_MS;
    for (i = 1, ga = 0; i <= 60 && !ga; i++, step())
        ga = breaker_step( 0x1303, (i & 1) ? 0x13b5f2004ull : 0x1026b3188ull, 0x73d16aff30ull );
    assert( ga && i - 1 == 51 );
    /* ml876: same pc, advancing address = progress, broken only at the storm ceiling */
    fake_now += 3000 * TICK_MS;
    for (i = 1, ga = 0; i <= 20005 && !ga; i++, step())
        ga = breaker_step( 0x1403, 0x140001000ull, 0x7400200000ull + (uint64_t)(i % 2000) * 8 );
    assert( ga && i - 1 > 20000 );

    /* delivery debounce: keys equal in (key >> 4) & 15 */
    {
        uint64_t ka = ((uint64_t)0x1103 << 48) ^ 0x140001000ull ^ (0x7400001000ull << 1);
        uint64_t kb = ((uint64_t)0x1207 << 48) ^ 0x140002000ull ^ (0x7400003000ull << 1);
        int da = 0, db = 0;
        assert( ((ka >> 4) & 15) == ((kb >> 4) & 15) );
        fake_now += 3000 * TICK_MS;
        for (i = 1; i <= 3; i++)
        {
            da = rep_dispatch( 0x1103, 0x140001000ull, 0x7400001000ull ); step();
            db = rep_dispatch( 0x1207, 0x140002000ull, 0x7400003000ull ); step();
        }
        assert( da && db );
    }

    /* redelivery terminal: two threads, one old slot */
    {
        uint64_t ta = 0x1103, tb = 0;
        uint32_t na = 0, nb = 0;
        for (tb = 0x1104; ((ta * 0x9E3779B97F4A7C15ull) >> 60) != ((tb * 0x9E3779B97F4A7C15ull) >> 60); tb++) ;
        fake_now += 3000 * TICK_MS;
        for (i = 0; i < 2000; i++)
        {
            na = redeliv_count( ta, 0x140001000ull, 0x10 ); step();
            nb = redeliv_count( tb, 0x140002000ull, 0x20 ); step();
        }
        assert( na == 2000 && nb == 2000 );
    }

    /* stale-heal ring: 1024 VAs x 256 faults, nothing drained, in turn and one after another */
    for (k = 0; k < 256; k++)
        for (i = 0; i < 1024; i++) ios_stale_va_enqueue( 0x7100000000ull + (uint64_t)i * 16 );
    assert( ios_stale_va_tail <= IOS_STALE_VA_MAX && ios_stale_va_ring_full == 0 );
    memset( ios_stale_va_seen, 0, sizeof(ios_stale_va_seen) );
    memset( ios_stale_va_hits, 0, sizeof(ios_stale_va_hits) );
    memset( ios_stale_va_queue, 0, sizeof(ios_stale_va_queue) );
    ios_stale_va_seen_count = ios_stale_va_tail = ios_stale_va_head = 0;
    for (i = 0; i < 1024; i++)
        for (k = 0; k < 256; k++) ios_stale_va_enqueue( 0x7100000000ull + (uint64_t)i * 16 );
    assert( ios_stale_va_tail == 256 && ios_stale_va_ring_full == 0 );
    for (i = 0; i < 256; i++) assert( ios_stale_va_queue[i] == 0x7100000000ull + (uint64_t)i * 16 );
    /* a full ring refuses and asks again at the VA's next fault */
    ios_stale_va_seen_count = 1; ios_stale_va_seen[0] = 0x7200000000ull;
    ios_stale_va_hits[0] = IOS_STALE_VA_HEAL_THRESHOLD - 1;
    ios_stale_va_enqueue( 0x7200000000ull );
    assert( ios_stale_va_tail == 256 && ios_stale_va_ring_full == 1 );
    __atomic_store_n( &ios_stale_va_head, 1, __ATOMIC_RELEASE );
    ios_stale_va_enqueue( 0x7200000000ull );
    assert( ios_stale_va_tail == 257 && ios_stale_va_queue[0] == 0x7200000000ull );

    printf( "PASS: exec/reclaim-recover, livelock breaker (threads in turn, ml261 pcs, deliveries, ml876 progress), "
            "delivery debounce, redelivery terminal and stale-heal ring hold under interleaved faults\n" );
    return 0;
}
'''

cc = os.environ.get('CC') or shutil.which('cc') or shutil.which('clang') or shutil.which('gcc')
with tempfile.TemporaryDirectory(prefix='madeira-fault-guards-') as folder:
    source = Path(folder) / 'guards.c'
    binary = Path(folder) / 'guards'
    source.write_text(code)
    subprocess.run([cc, '-std=gnu11', '-O1', '-Wall', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-variable', '-Wno-unused-but-set-variable', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, stderr=subprocess.DEVNULL)
