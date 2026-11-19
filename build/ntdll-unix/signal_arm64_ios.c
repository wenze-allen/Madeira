/* Portions copyright 2026 thebcd69 (BCD): code taken from https://github.com/thebcd69/bcd-games
 * under GPL-3.0-or-later and modified for Madeira in October and November 2026. See THIRD-PARTY-NOTICES.md. */
/*
 * ARM64 signal handling routines
 *
 * Copyright 2010-2013 André Hentschel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#ifdef __aarch64__

#include "config.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#ifdef WINE_IOS
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <sys/sysctl.h>

/* iOS-Madeira ml674: XZR/WZR AS A STORE SOURCE MUST READ ZERO.
 *
 * arm_thread_state64_t is  __uint64_t __x[29]  followed by __fp, __lr, __sp --
 * so state.__x[31] is not out of bounds by accident, it lands EXACTLY on __sp.
 *
 * That makes register 31 behave correctly in one role and catastrophically in
 * the other:
 *   - as a BASE register (Rn), 31 means SP, and __x[31] IS __sp  -> correct
 *   - as a SOURCE register (Rt/Rt2/Rs), 31 means ZR              -> must be 0,
 *     but reads the stack pointer instead
 *
 * Because the base-register half works, the decoder reads as correct and this
 * survived a long time. What it actually did: every fault-emulated `str xzr` /
 * `stur xzr` / `stp xzr,xzr` into an alias-backed page wrote a STACK ADDRESS
 * where the guest asked for zero.
 *
 * Book of the Dead showed it precisely. RtlInitializeCriticalSectionEx emits
 *     stur xzr, [x19,#0x0c]      ; RecursionCount + half of OwningThread
 *     stur xzr, [x19,#0x14]      ; rest of OwningThread + half of LockSemaphore
 *     str  wzr, [x19,#0x1c]      ; rest of LockSemaphore
 * so a section on a Mono anon-RWX page was born holding SP fragments:
 *     RecursionCount = 0x23bbf660, LockSemaphore = 0x23bbf660_00000070
 * and the first NtReleaseSemaphore on it returned STATUS_INVALID_HANDLE.
 *
 * Scope is much wider than one crash: any zero-store into an alias-backed page
 * was corrupting memory this way. */
#define IOS_STORE_SRC(r) ((r) == 31 ? 0ULL : state.__x[r])

#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <pthread/pthread.h>
#include <pthread/qos.h>
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYSCALL_H
# include <syscall.h>
#else
# ifdef HAVE_SYS_SYSCALL_H
#  include <sys/syscall.h>
# endif
#endif
#ifdef HAVE_SYS_SIGNAL_H
# include <sys/signal.h>
#endif
#ifdef HAVE_SYS_UCONTEXT_H
# include <sys/ucontext.h>
#endif

#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/asm.h"
#include "unix_private.h"
#include "ios_wow.h"
#include "wine/debug.h"

/* defined at the bottom of this file with the [thread-stacks] dumper */
static const char *ios_pe_module_name( uint64_t base );
/* madeira-bcd: for the watchdog's guest-stack dump (server_ios.c). */
const char *ios_pe_module_name_ext( uint64_t base ) { return ios_pe_module_name( base ); }

WINE_DEFAULT_DEBUG_CHANNEL(seh);

/* X3 mixed-mode: user-mode entry points follow the current pseudo-process's
 * ntdll image (cross-arch children run a private ARM64EC ntdll). Falls back
 * to the session p* globals when the process has no private image. */
#include "ios_mixed.h"
#ifdef WINE_IOS
#include "ios_sc_runstate_diag.h"
#endif
#define IOS_PFUNC(name) __extension__ ({ \
    const struct ios_ntdll_funcs *_iosf = ios_cur_ntdll_funcs(); \
    _iosf ? _iosf->name : (void *)p##name; })

#define NTDLL_DWARF_H_NO_UNWINDER
#include "dwarf.h"

/* ml649: runtime diagnostic switch, defined in virtual_ios.c. Default OFF.
 * Gate the WORK, not the print — several probes do expensive reads first. */
extern volatile int madeira_diag_enabled;

/* madeira-bcd pool-low (virtual_ios.c, ios_jit_low_rx_global): region C, a third
 * debugger region below the executable window that holds FEX code buffers, outside
 * the pool span [rx, rx + size) but at the pool's RX->RW distance, so rw + (a - rx)
 * is still its writable alias. Every "is this pc / store target JIT code?" test in
 * this file that decides handling asks these as well; both are 0 without it. */
extern int ios_jit_low_contains( uintptr_t a );
extern int ios_jit_low_rw_contains( uintptr_t a );
extern uintptr_t ios_jit_low_rx_global;
extern size_t ios_jit_low_size_global;


/* ml648: defined in virtual_ios.c, called from the SWPAL emulation path. */
void ios_mono_bridge_capture( unsigned long long teb, unsigned long long frame,
                              unsigned long long host_pc, unsigned long long fault_addr );


/* ml255: storm gate -- see ios_storm_gate in virtual_ios.c for the rationale
 * (510 MB log from a 524k-iteration NULL-deref loop). */
static int ios_sig_storm_gate( unsigned long *n )
{
    unsigned long c = ++(*n);
    if (c <= 20) return 1;
    if (c <= 100000) return (c % 1000) == 0;
    return (c % 100000) == 0;
}

/***********************************************************************
 * signal context platform-specific definitions
 */
#ifdef linux

/* All Registers access - only for local access */
# define REG_sig(reg_name, context) ((context)->uc_mcontext.reg_name)
# define REGn_sig(reg_num, context) ((context)->uc_mcontext.regs[reg_num])

/* Special Registers access  */
# define SP_sig(context)            REG_sig(sp, context)    /* Stack pointer */
# define PC_sig(context)            REG_sig(pc, context)    /* Program counter */
# define PSTATE_sig(context)        REG_sig(pstate, context) /* Current State Register */
# define FP_sig(context)            REGn_sig(29, context)    /* Frame pointer */
# define LR_sig(context)            REGn_sig(30, context)    /* Link Register */

static struct _aarch64_ctx *get_extended_sigcontext( const ucontext_t *sigcontext, unsigned int magic )
{
    struct _aarch64_ctx *ctx = (struct _aarch64_ctx *)sigcontext->uc_mcontext.__reserved;
    while ((char *)ctx < (char *)(&sigcontext->uc_mcontext + 1) && ctx->magic && ctx->size)
    {
        if (ctx->magic == magic) return ctx;
        ctx = (struct _aarch64_ctx *)((char *)ctx + ctx->size);
    }
    return NULL;
}

static struct fpsimd_context *get_fpsimd_context( const ucontext_t *sigcontext )
{
    return (struct fpsimd_context *)get_extended_sigcontext( sigcontext, FPSIMD_MAGIC );
}

static DWORD64 get_fault_esr( ucontext_t *sigcontext )
{
    struct esr_context *esr = (struct esr_context *)get_extended_sigcontext( sigcontext, ESR_MAGIC );
    if (esr) return esr->esr;
    return 0;
}

#elif defined(__APPLE__)

/* All Registers access - only for local access */
# define REG_sig(reg_name, context) ((context)->uc_mcontext->__ss.__ ## reg_name)
# define REGn_sig(reg_num, context) ((context)->uc_mcontext->__ss.__x[reg_num])

/* Special Registers access  */
# define SP_sig(context)            REG_sig(sp, context)    /* Stack pointer */
# define PC_sig(context)            REG_sig(pc, context)    /* Program counter */
# define PSTATE_sig(context)        REG_sig(cpsr, context)  /* Current State Register */
# define FP_sig(context)            REG_sig(fp, context)    /* Frame pointer */
# define LR_sig(context)            REG_sig(lr, context)    /* Link Register */

static DWORD64 get_fault_esr( ucontext_t *sigcontext )
{
    return sigcontext->uc_mcontext->__es.__esr;
}

#endif /* linux */

/* stack layout when calling KiUserExceptionDispatcher */
struct exc_stack_layout
{
    CONTEXT              context;        /* 000 */
    CONTEXT_EX           context_ex;     /* 390 */
    EXCEPTION_RECORD     rec;            /* 3b0 */
    ULONG64              align;          /* 448 */
    ULONG64              redzone[2];     /* 450 */
};
C_ASSERT( offsetof(struct exc_stack_layout, rec) == 0x3b0 );
C_ASSERT( sizeof(struct exc_stack_layout) == 0x460 );

/* stack layout when calling KiUserApcDispatcher */
struct apc_stack_layout
{
    void                *func;           /* 000 APC to call*/
    ULONG64              args[3];        /* 008 function arguments */
    ULONG64              alertable;      /* 020 */
    ULONG64              align;          /* 028 */
    CONTEXT              context;        /* 030 */
    ULONG64              redzone[2];     /* 3c0 */
};
C_ASSERT( offsetof(struct apc_stack_layout, context) == 0x30 );
C_ASSERT( sizeof(struct apc_stack_layout) == 0x3d0 );

/* stack layout when calling KiUserCallbackDispatcher */
struct callback_stack_layout
{
    void                *args;           /* 000 arguments */
    ULONG                len;            /* 008 arguments len */
    ULONG                id;             /* 00c function id */
    ULONG64              unknown;        /* 010 */
    ULONG64              lr;             /* 018 */
    ULONG64              sp;             /* 020 sp+pc (machine frame) */
    ULONG64              pc;             /* 028 */
    BYTE                 args_data[0];   /* 030 copied argument data*/
};
C_ASSERT( offsetof(struct callback_stack_layout, sp) == 0x20 );
C_ASSERT( sizeof(struct callback_stack_layout) == 0x30 );

struct syscall_frame
{
    ULONG64               x[29];          /* 000 */
    ULONG64               fp;             /* 0e8 */
    ULONG64               lr;             /* 0f0 */
    ULONG64               sp;             /* 0f8 */
    ULONG64               pc;             /* 100 */
    ULONG                 cpsr;           /* 108 */
    ULONG                 restore_flags;  /* 10c */
    struct syscall_frame *prev_frame;     /* 110 */
    void                 *syscall_cfa;    /* 118 */
    ULONG                 syscall_id;     /* 120 */
    ULONG                 align;          /* 124 */
    ULONG                 fpcr;           /* 128 */
    ULONG                 fpsr;           /* 12c */
    NEON128               v[32];          /* 130 */
};

C_ASSERT( sizeof( struct syscall_frame ) == 0x330 );

#ifdef WINE_IOS
/* Written by __wine_syscall_dispatcher at entry to capture the actual x18 value.
 * Read by the watchdog to verify whether x18 is TEB or 0. */
volatile uint64_t g_wine_dispatcher_x18 = 0xDEADDEAD;
volatile int ios_signal_total = 0;
volatile int ios_signal_last = 0;
volatile int ios_signal_in_pe = 0;  /* signals while PC was in JIT pool */
/* Counter of how many times the dispatcher has been called */
volatile uint64_t g_wine_dispatcher_count = 0;
/* g_wine_unix_call_count is now in loader_ios.c (wrapper table) */
/* Written by __wine_syscall_dispatcher_return to capture frame->x[18] and frame->pc
 * BEFORE they are loaded into registers and we jump to PE code */
volatile uint64_t g_wine_return_x18 = 0xDEADDEAD;
volatile uint64_t g_wine_return_pc = 0xDEADDEAD;
volatile uint64_t g_wine_return_count = 0;
/* Saved right before ret/br to PE code */
volatile uint64_t g_wine_x18_before_ret = 0xDEADDEAD;
volatile uint64_t g_wine_x16_at_ret = 0xDEADDEAD;
/* Ring buffer of last 8 dispatcher_return PCs for crash diagnosis */
#define WINE_RET_RING_SIZE 8
volatile uint64_t g_wine_return_ring[WINE_RET_RING_SIZE];
volatile uint32_t g_wine_return_ring_idx = 0;
/* Counters accessible from BUS handler for crash diagnosis */
volatile int ios_total_segv_count = 0;
/* TEB backup for signal handler x18 restoration */
static __thread uintptr_t ios_teb_for_signals = 0;

/* TLS key for storing TEB, accessible via TPIDRRO_EL0 in patched PE code */
pthread_key_t ios_teb_tls_key = 0;
int ios_teb_tls_slot_offset = 0;  /* byte offset from TPIDRRO_EL0 base to TEB slot */
int ios_teb_tls_key_created = 0;

/*
 * Per-thread Mach exception handler for EXC_BAD_ACCESS.
 * ONE handler thread serves ALL Wine "process" threads.
 * Each Wine thread registers its Mach thread port, TEB, and trampoline
 * in a shared registry. The handler looks up the correct TEB/trampoline
 * for the faulting thread.
 *
 * Handles: x18=0 (TEB corruption), user_shared_data (0x7FFE0000) redirects,
 * and PE→JIT pool execution redirects.
 * Unhandled exceptions fall through to the POSIX SIGSEGV handler.
 */
/* ml515: forward decl — the Mach handler uses this ~4600 lines before the
 * definition, and with -Wno-implicit-function-declaration the call would
 * otherwise create an implicit NON-static declaration and collide with the
 * static definition. (Same trap as the ml488 file.c probe.) */
struct __darwin_arm_thread_state64;
static int ios_srcwatch_handle( const arm_thread_state64_t *st, uintptr_t addr );

static mach_port_t ios_exc_port = MACH_PORT_NULL;
static int ios_exc_handler_started = 0;
/* Whether the Mach delivery path classifies ESR alignment faults (see the
 * [unaligned-atomic] block in ios_mach_deliver_guest_exception_inner). Set
 * once before the exception server thread starts; MADEIRA_MACH_ALIGN_FAULT=0
 * turns it off. */
static int ios_mach_align_fault_enabled = 1;
static uintptr_t ios_exc_usd = 0;
volatile int64_t ios_exc_x18_fixes = 0;
volatile int64_t ios_exc_usd_fixes = 0;
volatile int ios_exc_thread_alive = 0;
volatile int ios_exc_msg_count = 0;
/* ml680: cost of a fault, measured rather than assumed. A 2026-07-03 note in
 * the receive loop already put the round trip at ~33us; this makes it a live
 * number for THIS workload so the W^X change has a before/after to beat.
 * t0 is stamped at message receipt and consumed by the store emulator. */
volatile unsigned long long ios_store_fault_t0 = 0;
volatile unsigned long long ios_store_fault_ticks = 0;
volatile unsigned long long ios_store_fault_n = 0;
volatile unsigned long long ios_store_fault_dropped = 0;   /* ml685 */
/* ml690: which thread is currently faulting. Set once per received exception on
 * the single handler thread, so no locking is needed. Attribution answers the
 * question the aggregate cannot: is the 34k faults/sec stalling the MAIN thread
 * (in which case W^X should move the frame rate) or only the tree worker (in
 * which case it buys a core but may not move FPS at all)? */
volatile unsigned int ios_cur_fault_port = 0;

/* ml691: pages demoted to RW by the W^X path, so an execute fault on one can be
 * recovered. Kept OUTSIDE the store handler's static so the exec path can reach
 * it. Restoring RX is synchronous -- the faulting thread does not resume until
 * the page is executable again -- and a page that reaches here is marked sticky
 * so it is never demoted a second time. */
/* ml694: RESTORED to the ml691 structure, which is the only W^X configuration
 * proven to work (192 demotions, 0 re-promotions, faults 45,464 -> 33,733/sec,
 * 1-2 -> 4-5 FPS over a full session).
 *
 * ml692 enlarged this to a 32,768-entry hash AND dropped the threshold 32 -> 8
 * in one build; it crashed. ml693 reverted only the threshold and crashed
 * IDENTICALLY -- same guest RIP, same wild read, after demoting the SAME FOUR
 * pages ml691 demoted safely. So neither "too many pages" nor "too early"
 * explains it, and the table change is the remaining difference. Enlarging it
 * again is off the table until execution/SMC correctness is enforced.
 *
 * KNOWN LIMITS of this mechanism, recorded so nobody reads it as production-safe:
 *   - Keyed by guest page address ONLY -- no PEB, alias generation, or mapping
 *     lifetime, so a reused address can inherit stale state.
 *   - An NX guest page does NOT guarantee an execution fault: FEX can keep
 *     running an already-cached host translation without ever touching the guest
 *     page. "0 re-promotions" therefore does NOT prove no demoted page was
 *     executed -- it only proves no fault was taken. That is the leading
 *     explanation for ml692/ml693's deterministic wild-pointer crash.
 *   - The durable fix is metadata owned by each live alias mapping (with
 *     generation/lifetime) wired into FEX's translation invalidation, not a
 *     second page-only registry. */
#define IOS_WX_MAX 256
struct ios_wx_page { unsigned long long page; volatile int demoted, sticky; };
struct ios_wx_page ios_wx_pages[IOS_WX_MAX];
static volatile unsigned ios_wx_repromotes;

/* ml694: one switch, resolved once, logged once. The ml691-693 gate read two
 * paths that can never exist (a container path with no UUID, and a CWD-relative
 * name), so it silently forced ENABLED on every run and the "disable it and
 * retest" A/B I offered was not actually possible. An env var reaches this
 * native side -- proven by MADEIRA_NO_DFE in ml597/598. */
int ios_wx_enabled( void )
{
    static int v = -1;
    if (v < 0)
    {
        /* ml695: OFF BY DEFAULT. This optimization has known stale-translation
         * and address-reuse hazards and has already produced deterministic
         * crashes in two builds; silent corruption on a fresh install would be
         * worse than a clean crash, and a kill switch a user must discover
         * afterward is not a substitute for a safe default. Opt in with
         * Documents/madeira-wx.txt containing 1.
         *
         * Native code reads ONLY this env value -- Swift owns the sandbox path
         * so that knowledge is not duplicated in two places. */
        const char *e = getenv( "MADEIRA_WX" );
        v = (e && e[0] == '1') ? 1 : 0;
        dprintf( STDERR_FILENO, "[wx] ml695 MADEIRA_WX=%s -> W^X %s (experimental, opt-in; threshold 32, %d slots)\n",
                 e ? e : "(unset)", v ? "ENABLED" : "DISABLED", IOS_WX_MAX );
    }
    return v;
}

int ios_wx_repromote( unsigned long long pc )
{
    unsigned long long pg = pc & ~0x3fffull;
    int i;
    for (i = 0; i < IOS_WX_MAX; i++)
    {
        if (ios_wx_pages[i].page != pg || !ios_wx_pages[i].demoted) continue;
        if (mprotect( (void *)(uintptr_t)pg, 0x4000, PROT_READ | PROT_EXEC ) == 0)
        {
            unsigned n = __sync_add_and_fetch( &ios_wx_repromotes, 1 );
            ios_wx_pages[i].demoted = 0;
            ios_wx_pages[i].sticky = 1;       /* never demote this page again */
            dprintf(STDERR_FILENO,
                "[wx] ml694 RE-PROMOTED 0x%llx to RX after an EXEC fault at 0x%llx "
                "(total=%u) -- this page holds CODE, not data\n", pg, pc, n);
            return 1;
        }
        dprintf(STDERR_FILENO, "[wx] ml694 re-promote mprotect FAILED 0x%llx errno=%d\n", pg, errno);
        return 0;
    }
    return 0;
}

/* Last thread that took an exec fault at a PE VA (i.e. made a native call
 * through the redirect path) — the game thread in practice. The [PROF]
 * sampler in server_ios.c follows this so it profiles the presenting
 * thread instead of whatever thread first hit signal_start_thread (which
 * died ~33s in and left [PROF] sampling a corpse). */
volatile mach_port_t ios_last_exec_fault_thread = MACH_PORT_NULL;

/* Real unix-side KUSER_SHARED_DATA address, for unix code (e.g. win32u's
 * get_tick_count) that would otherwise read the canonical 0x7ffe0000 and
 * eat a Mach fault per load. */
unsigned long long ios_get_real_usd(void)
{
    return (unsigned long long)ios_exc_usd;
}

/* ---- Self-healing stale-pointer patcher ----------------------------------
 * Mechanism-#2 exec faults: pool-resident module copies hold function
 * pointers that still carry PE VAs (lazily-written ARM64EC aux-IAT slots,
 * runtime GetProcAddress results — writes that happen pool-side AFTER the
 * NtProtect sync/translate pass ran). Each call through such a pointer
 * faults (~8K/s in gameplay, each suspending the calling thread for a full
 * handler round trip). The Mach handler enqueues every distinct faulted
 * PE VA here; a low-priority scanner thread hands it to
 * ios_jit_patch_stale_pointer (virtual_ios.c), which rewrites the import
 * (IAT / delay-IAT) slots of each module copy that hold that value to its
 * pool equivalent and, when that pass rewrites nothing, escalates to the
 * exact 8-byte value anywhere in the copy outside its .text (default on;
 * MADEIRA_NO_HEAL_ESCALATE=1 disables the escalation). Each stale pointer
 * faults a bounded number of times, then never again. FEX CodeBuffer ranges
 * are NOT scanned (guest-RIP constants live there). */
/* 64 → 256 (2026-07-07): with a desktop + several pseudo-processes the
 * boot one-shot VAs alone overflowed 64 slots, and the two-cube DXMT
 * fault storm's VA (child winemetal IAT → child EC ntdll map VA,
 * 315K faults) arrived late and was silently dropped — never tracked,
 * never healed. */
#define IOS_STALE_VA_MAX 256
/* Only heal a VA once it has exec-faulted this many times. Boot-time
 * one-shot redirects (thread entry points, DLL entry calls) fault a
 * handful of times and must NOT be healed — pool slots legitimately hold
 * some of those PE VAs (CONTEXT records, pending thread params), and
 * rewriting them broke boot (2026-07-04 freeze, pre-splash NULL-deref
 * livelock). The pathological stale pointers fault thousands of times per
 * second; a threshold cleanly separates the two populations. */
#define IOS_STALE_VA_HEAL_THRESHOLD 256
static uint64_t ios_stale_va_seen[IOS_STALE_VA_MAX];
static uint32_t ios_stale_va_hits[IOS_STALE_VA_MAX];
static volatile int ios_stale_va_seen_count = 0;
/* Single-producer (exc handler) / single-consumer (scanner) ring. `volatile`
 * orders nothing on ARM64, and the slot itself was a plain store, so the
 * scanner could see the new tail before the VA it publishes and heal a stale
 * slot instead; that VA is queued only once (at the threshold), so its heal
 * was then lost for good. The producer publishes the slot with a release
 * store of the tail and the consumer frees it with a release store of the
 * head; each reads the other's index with acquire. */
static uint64_t ios_stale_va_queue[IOS_STALE_VA_MAX];
static int ios_stale_va_head = 0;   /* written by scanner */
static int ios_stale_va_tail = 0;   /* written by exc handler */
static unsigned ios_stale_va_ring_full;   /* exc handler only */

static void ios_stale_va_enqueue( uint64_t va )
{
    int i, n = ios_stale_va_seen_count;
    for (i = 0; i < n; i++)
    {
        if (ios_stale_va_seen[i] == va)
        {
            if (++ios_stale_va_hits[i] == IOS_STALE_VA_HEAL_THRESHOLD)
            {
                int tail = ios_stale_va_tail;
                /* A VA is queued once and a hot entry is never evicted, so at most
                 * IOS_STALE_VA_MAX are ever queued and the ring cannot fill; refuse
                 * rather than overwrite an unread slot if that ever stops being true,
                 * and ask again at this VA's next fault. */
                if (tail - __atomic_load_n( &ios_stale_va_head, __ATOMIC_ACQUIRE ) >= IOS_STALE_VA_MAX)
                {
                    ios_stale_va_hits[i]--;
                    if (ios_stale_va_ring_full++ < 8)
                        fprintf( stderr, "[stale-heal] queue full: 0x%llx not queued yet (%u refused)\n",
                                 (unsigned long long)va, ios_stale_va_ring_full );
                    return;
                }
                ios_stale_va_queue[tail % IOS_STALE_VA_MAX] = va;
                __atomic_store_n( &ios_stale_va_tail, tail + 1, __ATOMIC_RELEASE );
                fprintf( stderr, "[stale-heal] 0x%llx crossed %d faults — queued for heal\n",
                         (unsigned long long)va, IOS_STALE_VA_HEAL_THRESHOLD );
            }
            return;
        }
    }
    if (n >= IOS_STALE_VA_MAX)
    {
        /* Table full: evict the coldest entry (boot one-shots sit at a
         * handful of hits) so pathological late-comers — a new child's
         * DXMT IAT — still get tracked. Only the single mach-handler
         * thread calls this, so the read-modify-write is safe. */
        int min_i = 0;
        uint32_t min_h = ios_stale_va_hits[0];
        for (i = 1; i < n; i++)
            if (ios_stale_va_hits[i] < min_h) { min_h = ios_stale_va_hits[i]; min_i = i; }
        if (min_h >= IOS_STALE_VA_HEAL_THRESHOLD) return;  /* everything hot — drop */
        ios_stale_va_seen[min_i] = va;
        ios_stale_va_hits[min_i] = 1;
        return;
    }
    ios_stale_va_seen[n] = va;
    ios_stale_va_hits[n] = 1;
    ios_stale_va_seen_count = n + 1;
}

static void *ios_stale_va_scanner( void *arg )
{
    extern int ios_jit_patch_stale_pointer( unsigned long long stale_va );
    /* Healing default-ON since 2026-07-07: the patcher first rewrites
     * IAT/delay-IAT slots (parsed from each pool copy's PE headers), which
     * hold nothing but call targets, so the 2026-07-04 breakage class —
     * arm64x metadata slots whose consumers need PE VAs for identity/range
     * comparisons — is not touched by that pass; it is the same transform
     * the NtProtect-time IAT-sync applies. When it rewrites nothing, the
     * default-on escalation (MADEIRA_NO_HEAL_ESCALATE=1 disables) rewrites
     * the exact value in the copy's non-.text data too: the DXMT unix-call
     * pointer lives in a .data global (ios_jit_patch_stale_pointer).
     * MADEIRA_NO_HEAL=1 reverts to dry-run reporting. */
    int do_heal = getenv( "MADEIRA_NO_HEAL" ) == NULL;
    pthread_setname_np( "wine-stale-heal" );
    { extern void ios_eco_native_self( const char *who ); ios_eco_native_self( "wine-stale-heal" ); }   /* madeira-bcd eco-native */
    for (;;)
    {
        int head = ios_stale_va_head;
        usleep( 100000 );
        while (head != __atomic_load_n( &ios_stale_va_tail, __ATOMIC_ACQUIRE ))
        {
            uint64_t va = ios_stale_va_queue[head % IOS_STALE_VA_MAX];
            head++;
            __atomic_store_n( &ios_stale_va_head, head, __ATOMIC_RELEASE );
            if (do_heal)
                ios_jit_patch_stale_pointer( va );
            else
                fprintf( stderr, "[stale-heal] (dry-run) hot stale VA 0x%llx — heal skipped (MADEIRA_NO_HEAL set)\n",
                         (unsigned long long)va );
        }
    }
    return NULL;
}

#include "signal_arm64_ios_guards.c"   /* the fault-guard counters, guest caller dumps and their helpers */
#include "signal_arm64_ios_mach.c"   /* the Mach exception server (ios_mach_exception_thread) */
#endif


#include "signal_arm64_ios_context.c"   /* thread contexts */
#include "signal_arm64_ios_deliver.c"   /* raising and delivering exceptions to the guest, user callbacks, syscall faults */
#include "signal_arm64_ios_segv.c"   /* segv_handler and ios_srcwatch (the bitmap-writer watch) */
#include "signal_arm64_ios_emulate.c"   /* ill_handler and the store, unaligned and sub-floor window emulation */
#include "signal_arm64_ios_handlers.c"   /* the other signal handlers */
#include "signal_arm64_ios_threads.c"   /* threading, thread start and the syscall dispatcher */
#endif  /* __aarch64__ */

#include "signal_arm64_ios_diag.c"   /* the all-thread stack sampler and other diagnostics */
