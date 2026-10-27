/*
 * Win32 virtual memory functions
 *
 * Copyright 1997, 2002, 2020 Alexandre Julliard
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

#include "config.h"
#include "../madeira_cfg.h"   /* ml1095: one config file */
#include <malloc/malloc.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <limits.h>
#include <pthread.h>
#include <sys/ioctl.h>
#ifdef WINE_IOS
/* Minimal Mach API decls to avoid <mach/mach.h>'s host_page_size symbol
 * clash with our static var of the same name. */
typedef int kern_return_t;
typedef unsigned int mach_port_t;
typedef unsigned long vm_address_t;
typedef unsigned long vm_size_t;
typedef int vm_prot_t;
extern mach_port_t mach_task_self_;
#define mach_task_self() mach_task_self_
#define KERN_SUCCESS 0
#define VM_PROT_READ  ((vm_prot_t) 0x01)
#define VM_PROT_WRITE ((vm_prot_t) 0x02)
#define VM_PROT_COPY  ((vm_prot_t) 0x10)
extern kern_return_t vm_protect(mach_port_t target_task, vm_address_t address,
                                vm_size_t size, int set_maximum,
                                vm_prot_t new_protection);
#endif
#ifdef HAVE_SYS_SYSINFO_H
# include <sys/sysinfo.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
# include <sys/sysctl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_QUEUE_H
# include <sys/queue.h>
#endif
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif
#ifdef HAVE_LIBPROCSTAT_H
# include <libprocstat.h>
#endif
#include <unistd.h>
#include <dlfcn.h>
#ifdef WINE_IOS
#include <libkern/OSCacheControl.h>
#endif
#include <CommonCrypto/CommonDigest.h>   /* CC_SHA256: the Social Club helper code checks */
#ifdef HAVE_VALGRIND_VALGRIND_H
# include <valgrind/valgrind.h>
#endif
#if defined(__APPLE__)
#define host_page_size mac_host_page_size
# include <mach/mach_init.h>
# include <mach/mach_vm.h>
# include <mach/task.h>
# include <mach/thread_state.h>
# include <mach/vm_map.h>
#undef host_page_size
#endif

#if defined(HAVE_LINUX_USERFAULTFD_H) && defined(HAVE_LINUX_FS_H)
# include <linux/userfaultfd.h>
# include <linux/fs.h>
#if defined(UFFD_FEATURE_WP_ASYNC) && defined(PM_SCAN_WP_MATCHING)
#define USE_UFFD_WRITEWATCH
#endif
#endif

#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/list.h"
#include "wine/rbtree.h"
#include "unix_private.h"
#include "ios_wow.h"
#include "wine/debug.h"

/* ml648: the Mono-bridge alias table is defined further down, but the anon-alias
 * teardown paths ABOVE it must retire entries too — an unmapped alias left live
 * would resolve a stale guest_rx to memory that no longer backs it. Declared here
 * so those earlier call sites do not create an implicit declaration. */
#include <stdint.h>
void ios_mono_alias_publish( uint64_t guest_rx, uint64_t host_rw, uint64_t size );
void ios_mono_alias_retire( uint64_t guest_rx );


WINE_DEFAULT_DEBUG_CHANNEL(virtual);
WINE_DECLARE_DEBUG_CHANNEL(module);
WINE_DECLARE_DEBUG_CHANNEL(virtual_ranges);

#ifdef WINE_IOS
/* JIT pool address translation table.
 * Maps PE code section addresses → JIT pool RX addresses.
 * Used by signal_arm64_ios.c to redirect entry points.
 * Bumped from 16 → 64 to fit games with many DLLs (Thumper loads 22+ unique
 * images; cube ~12-15). Silent overflow at 16 was costing us hours of
 * debugging — late modules' addresses fell through ios_jit_translate_addr
 * unchanged, leaking unix-mapped (non-executable) addresses to BLR. */
/* 512: desktop mode holds the session's full aarch64 image set PLUS every
 * pseudo-process child's x64/EC set in one table. 64 overflowed at exactly
 * the 65th image (Thumper under desktop, 2026-07-06): concrt140 copied but
 * never registered → raw-VA DllMain call → unfixable exec-fault loop. */
#define IOS_JIT_MAX_MAPPINGS 512
#define IOS_JIT_MAX_CODE_RANGES 96
struct ios_jit_mapping {
    void *pe_base;      /* Original PE image base address (unix mapping) */
    void *jit_base;     /* JIT pool RX address */
    size_t size;        /* Size of the mapping */
    size_t text_offset; /* Offset of .text section within image */
    size_t text_size;   /* Size of .text section (0 if unknown) */
    unsigned code_range_count;
    struct { size_t offset, size; } code_ranges[IOS_JIT_MAX_CODE_RANGES];
    uint64_t pe_image_base; /* PE optional header ImageBase */
    intptr_t reloc_delta;   /* JIT dest - PE ImageBase */
    unsigned int reloc_rva; /* RVA of .reloc section */
    unsigned int reloc_size;/* Size of .reloc data */
    void *owner_peb;    /* NULL = parent/default copy; else the PEB of the
                         * pseudo-process that owns this copy (S1 child
                         * processes get their own ntdll image so module
                         * lists / loader locks don't collide). Multiple
                         * entries may share one pe_base; translation picks
                         * the entry owned by the current thread's process,
                         * falling back to the NULL-owner (parent) entry. */
    void *map_peb;      /* PEB of the pseudo-process whose thread registered
                         * this copy (NULL = unknown). A NULL-owner copy is
                         * still used by the process that mapped the image, so
                         * a pointer into a per-process image (ntdll) stored in
                         * it belongs to that process's copy -- see
                         * ios_jit_patch_stale_pointer. */
    unsigned short machine_cached;  /* ml349: PE machine word, read fault-safely once */
    unsigned char  machine_valid;   /* 0 = machine_cached not yet populated */
    unsigned char  unmapped;        /* the PE view this copy was made from has been
                                     * unmapped (delete_view, SEC_IMAGE). The entry
                                     * stays live for laggard translations, but its
                                     * .data/.bss hold the unloaded module's state,
                                     * so an image mapped at the same base again
                                     * must not adopt it as is (ios_image_reload_mode). */
    unsigned char  hybrid_cached;   /* ml1245: image carries ARM64EC metadata */
    unsigned char  hybrid_valid;    /* 0 = hybrid_cached not yet populated */
    unsigned char  is_fex;          /* copy of FEX's ARM64EC module (xtajit64.dll) */
};
static struct ios_jit_mapping ios_jit_mappings[IOS_JIT_MAX_MAPPINGS];
static int ios_jit_mapping_count = 0;

/* JIT pool head bump allocator. Owned by mprotect_exec's PE-image copy path
 * (was a function-local static there); file-scope so the S1 per-child
 * ntdll copy allocates from the same cursor instead of guessing pool usage.
 * The pool TAIL is carved separately by NtAllocateVirtualMemoryEx for FEX
 * EC_CODE buffers. Static: internal linkage, no wineserver-style symbol
 * collision risk. */
static size_t jit_pool_offset = 0;

/* madeira-bcd SPLIT POOL (StikJITHelper.swift, `pool-split = 1` in madeira.cfg
 * or in a game's own file).
 *
 * Host-executable JIT memory can only live in the low band below the dyld
 * shared region (0x180000000): [0x70,0x80)G is guest/PartitionAlloc/FEX memory
 * (FEX treats a guest RIP >= 0x7400000000 as a bogus host RIP) and everything
 * between 0x180000000 and 0x7000000000 is the shared region, the kernel's
 * reserved jumbo range and the GPU carveout. Above the 128 MB executable
 * window the band holds [0x148000000, 0x180000000) = 896 MB, but iOS put the
 * main thread's stack in it (0x16d7..-0x16fd.. with the ASLR slide), so the
 * largest single run is 592-631 MB (GTA V Enhanced, 2026-10-02 16:00/16:19/
 * 16:33): the pool shrank to that and Social Club's 240 MB libcef.dll copy no
 * longer fit (bump 274 MB + FEX tail 160 MB). With pool-split the app also
 * takes the run above the stack (253-332 MB in every log) as a second debugger
 * region and maps both as ONE pool span [rx, rx + size): one RW alias with the
 * same RX->RW distance, so every range test and offset in this file and in FEX
 * holds for both parts. WINE_IOS_JIT_HOLE="<off>:<end>" (hex pool offsets)
 * names the part in between -- the stack plus the app's PROT_NONE
 * placeholders -- which is not pool memory: the head bump jumps over it, a
 * tail carve that would overlap it goes below it, and the pool warmer skips
 * it. Without WINE_IOS_JIT_HOLE both bounds stay 0 and every path below is
 * the unsplit one. */
static size_t ios_jit_hole_off, ios_jit_hole_end;

/* madeira-bcd POOL-MID (StikJITHelper.swift, `pool-mid`, on with pool-split; env
 * WINE_IOS_JIT_HOLE2="<off>:<end>", hex pool offsets). RDR2 on build 470
 * (2026-10-09 14:33): a 71 MB mapping sat in the band before the app's image-load
 * constructor ran, so the split pool came out as A 285 MB + B 319 MB (604 MB of
 * 896) around a 291 MB hole holding that mapping, 213 MB of FREE space and the
 * main thread's stack; the image copies ran the pool dry and d3dcompiler_47.dll
 * did not load (ERR_GFX_INIT). The app now takes such a free run between A and
 * B as a third debugger region M, aliased in the same span, and names a second
 * hole: hole 1 is then the part below M (the early mapping), hole 2 the part
 * above it (the stack). Hole 1 lies below hole 2. Without the env var both bounds
 * stay 0 and every helper below is the one-hole one. */
static size_t ios_jit_hole2_off, ios_jit_hole2_end;

/* madeira-bcd BIG-IMAGE SLOT (env MADEIRA_POOL_BIG_SLOT_MB = N, split pool only;
 * off by default). Ten processes each copy their own system DLLs into the pool
 * (GTA V Enhanced build 373, 2026-10-04 08:41: 326 images, 469 MB -- shell32
 * x7, steamclient64 x2, kernelbase x10), the head fills the run below the hole
 * and the FEX code buffers (tail) take the top of the run above it, so Social
 * Club's 240 MB libcef.dll fits in neither part although 330 MB are free:
 * EXHAUSTED for every SocialClubHelper.exe, "SC_INIT_ERR_WEBSITE_FAILED_LOAD".
 * With the slot, the N MB right above the hole go to one image of
 * IOS_POOL_BIG_MIN or more; for everything else (smaller images, the bump, the
 * tail) the allocator hole includes the slot, between ios_jit_hole_off_eff and
 * ios_jit_hole_end_eff. MADEIRA_POOL_BIG_SLOT_BELOW=1 puts the same slot below
 * the native hole instead; its default placement is still above. When the slot's
 * process dies, the slot is free again after the reuse grace. */
static size_t ios_jit_hole_off_eff, ios_jit_hole_end_eff; /* native hole plus the image slot */
static size_t ios_pool_big_off, ios_pool_big_size;
static int ios_pool_big_taken;
static time_t ios_pool_big_freed_at;
#define IOS_POOL_BIG_MIN (64u * 1024 * 1024)
static size_t ios_pool_head_reserve = 48u * 1024 * 1024;

/* A slot may sit on either side of the native hole. The default is still above
 * it; MADEIRA_POOL_BIG_SLOT_BELOW=1 opts into the lower side, leaving the upper
 * run contiguous for a later image. Keep at least 256MB below a lower slot for
 * the startup images. Both placements use the same ledger and reuse grace.
 * Only allocator bounds include the slot: the warmer's native hole is unchanged. */
static int ios_pool_big_layout( size_t total, size_t hole_off, size_t hole_end,
                                size_t want, int below, size_t *slot_off,
                                size_t *skip_off, size_t *skip_end )
{
    if (hole_end <= hole_off || hole_end > total || want < IOS_POOL_BIG_MIN ||
        (want & 0x3fff)) return 0;
    if (below)
    {
        if (want > hole_off || hole_off - want < 256u * 1024 * 1024) return 0;
        *slot_off = *skip_off = hole_off - want;
        *skip_end = hole_end;
    }
    else
    {
        if (want > total - hole_end) return 0;
        *slot_off = hole_end;
        *skip_off = hole_off;
        *skip_end = hole_end + want;
    }
    return 1;
}

/* Per-game headroom for future image copies, never less than the existing
 * 48MB guard. Larger code buffers that fit region C, and recycled buffers,
 * still bypass the pool-tail cap. Invalid values retain the old behavior. */
static size_t ios_pool_parse_head_reserve( const char *value )
{
    char *end;
    unsigned long mb;

    if (!value || *value < '0' || *value > '9') return 48u * 1024 * 1024;
    mb = strtoul( value, &end, 10 );
    if (*end || mb < 48 || mb > 256) return 48u * 1024 * 1024;
    return (size_t)mb << 20;
}

/* The offset a head allocation of `size` gets with the bump cursor at `cur`:
 * `cur`, or the end of the hole when [cur, cur + size) would reach into it. */
static size_t ios_pool_hole_head_place( size_t cur, size_t size, size_t hole_off, size_t hole_end )
{
    if (hole_end > hole_off && cur < hole_end && cur + size > hole_off) return hole_end;
    return cur;
}

/* Where a tail carve of `size` starts, counted down from the pool's end, when
 * `cur` bytes are reserved there: the carve is [total - start - size,
 * total - start). One that would overlap the hole starts at the hole instead,
 * i.e. lies directly below it (the span above it stays unused). */
static size_t ios_pool_hole_tail_start( size_t total, size_t cur, size_t size,
                                        size_t hole_off, size_t hole_end )
{
    size_t top;

    if (hole_end <= hole_off || hole_end > total || cur >= total) return cur;
    top = total - cur;
    if (top > hole_off && (top <= size || top - size < hole_end)) return total - hole_off;
    return cur;
}

/* Bytes of the hole between the head cursor and the bottom of the tail: what
 * `total - head - tail` counts as free although it can never be handed out. */
static size_t ios_pool_hole_between( size_t total, size_t head, size_t tail,
                                     size_t hole_off, size_t hole_end )
{
    if (hole_end <= hole_off || tail > total) return 0;
    return (head <= hole_off && total - tail >= hole_end) ? hole_end - hole_off : 0;
}

static size_t ios_pool_code_cap( size_t total, size_t head, size_t tail,
                                 size_t hole_off, size_t hole_end, size_t reserve )
{
    size_t hole = ios_pool_hole_between( total, head, tail, hole_off, hole_end );
    size_t room = 0, cap = 16u * 1024 * 1024;

    /* Subtract in stages so malformed or transient cursor values cannot wrap
     * into a generous budget. The existing 16MB minimum is unchanged. */
    if (head <= total && tail <= total - head && hole <= total - head - tail &&
        reserve < total - head - tail - hole)
        room = total - head - tail - hole - reserve;
    while (cap < 128u * 1024 * 1024 && cap * 2 <= room) cap *= 2;
    return cap;
}

/* madeira-bcd pool-mid: the one-hole helpers above applied to both holes (hole 1
 * below hole 2; with no second hole h2_off == h2_end == 0 and these are the
 * one-hole helpers). A head allocation jumps hole 1, then hole 2; a tail carve,
 * counted down from the top, jumps hole 2 first, then hole 1. */
static size_t ios_pool_holes_head_place( size_t cur, size_t size, size_t h1_off, size_t h1_end,
                                         size_t h2_off, size_t h2_end )
{
    return ios_pool_hole_head_place( ios_pool_hole_head_place( cur, size, h1_off, h1_end ), size, h2_off, h2_end );
}

static size_t ios_pool_holes_tail_start( size_t total, size_t cur, size_t size, size_t h1_off, size_t h1_end,
                                         size_t h2_off, size_t h2_end )
{
    return ios_pool_hole_tail_start( total, ios_pool_hole_tail_start( total, cur, size, h2_off, h2_end ),
                                     size, h1_off, h1_end );
}

static size_t ios_pool_holes_between( size_t total, size_t head, size_t tail, size_t h1_off, size_t h1_end,
                                      size_t h2_off, size_t h2_end )
{
    return ios_pool_hole_between( total, head, tail, h1_off, h1_end ) +
           ios_pool_hole_between( total, head, tail, h2_off, h2_end );
}

/* The pool memory in [lo, hi) outside both holes, in at most three pieces
 * (ascending, 16 KB granular; smaller pieces dropped): what a head jump or a tail
 * carve skipped over, which stays usable. Returns the number of pieces. */
static int ios_pool_skip_pieces( size_t lo, size_t hi, size_t h1_off, size_t h1_end,
                                 size_t h2_off, size_t h2_end, size_t piece_off[3], size_t piece_size[3] )
{
    size_t hole_lo[2] = { h1_off, h2_off }, hole_hi[2] = { h1_end, h2_end };
    size_t cur = lo;
    int n = 0, i;

    for (i = 0; i < 2 && cur < hi; i++)
    {
        if (hole_hi[i] <= hole_lo[i] || hole_hi[i] <= cur) continue;   /* no hole, or below the cursor */
        if (hole_lo[i] >= hi) break;
        if (hole_lo[i] > cur && hole_lo[i] - cur >= 0x4000)
        {
            piece_off[n] = cur;
            piece_size[n] = (hole_lo[i] - cur) & ~(size_t)0x3fff;
            n++;
        }
        cur = hole_hi[i];
    }
    if (cur < hi && hi - cur >= 0x4000)
    {
        piece_off[n] = cur;
        piece_size[n] = (hi - cur) & ~(size_t)0x3fff;
        n++;
    }
    return n;
}

/* 1 for a pool offset inside a hole (always 0 without a split). */
#define IOS_POOL_IN_HOLE(o) ((size_t)(o) - ios_jit_hole_off < ios_jit_hole_end - ios_jit_hole_off || \
                             (size_t)(o) - ios_jit_hole2_off < ios_jit_hole2_end - ios_jit_hole2_off)

/* madeira-bcd POOL-LOW (StikJITHelper.swift, `pool-low = 1` in madeira.cfg or in a
 * game's own file; env WINE_IOS_JIT_TAIL_REGION="<rx>:<size>", hex). Off by default.
 *
 * Every GTA V Enhanced log has a 416-476 MB free run BELOW the executable window
 * (ml1036 census: 0x126000000+416MB .. 0x122400000+476MB, ending at 0x140000000),
 * and build 374 (2026-10-04 09:25) ran the head dry at 557 of the 560 MB below the
 * hole while 112 MB of the pool were FEX code buffers. The run cannot join the pool
 * span: [rx, rx + size) would then contain the executable window, and everything
 * here and in FEX treats that range as pool memory. So the app takes it as a THIRD
 * debugger region, region C, outside the span, and maps its RW alias at the SAME
 * RX->RW distance as the pool (one reservation [C's RW, pool RW + size), the
 * part in between PROT_NONE), because FEX applies one DualMap::WriteOffset to
 * every code buffer. EC_CODE carves (FEX code buffers) come from C first,
 * and the pool tail takes over when C is full. Image copies stay in the main
 * pool by default; MADEIRA_POOL_LOW_IMAGES opts small failed copies into spare
 * C space. MADEIRA_POOL_RECYCLE_IMAGES can also return retired C code-buffer
 * ranges to the image freelist. Anonymous RWX stays in the main pool. C carves
 * live in ios_tail_carves like any other carve, their `off` the
 * (wrapping) distance from the pool's RX base, so rx + off and rw + off hold for
 * them too. What still has to know about C is everything that asks "is this
 * address in the pool?" for code: the signal and Mach handlers, NtContinue's
 * native resume, the carve free and lookup, the warmer, Wine's free-area scan and
 * the tripwires; they call ios_jit_low_contains / ios_jit_low_rw_contains. WoW64
 * processes never get a C carve: their FEX refuses an executable allocation
 * outside [WINE_IOS_JIT_RX, +SIZE) (AllocatorHooks.h). Without the env var the
 * size is 0 and every test below is false. */
uintptr_t ios_jit_low_rx_global, ios_jit_low_rw_global;
size_t ios_jit_low_size_global;
static volatile size_t ios_jit_low_reserved;   /* C's bump: bytes carved from its bottom */
static int ios_jit_low_full_logged;
#define IOS_POOL_LOW_MIN       (16u * 1024 * 1024)
#define IOS_POOL_LOW_CARVE_MAX 0x8000000u         /* TAIL_MAX: FEX's own branch-range limit */

/* 1 for an address in region C's RX side / RW side. Lock-free and async-signal-safe:
 * the Mach and signal handlers in signal_arm64_ios.c call these. */
int ios_jit_low_contains( uintptr_t a )
{
    size_t n = ios_jit_low_size_global;
    return n && a - ios_jit_low_rx_global < n;
}

int ios_jit_low_rw_contains( uintptr_t a )
{
    size_t n = ios_jit_low_size_global;
    return n && a - ios_jit_low_rw_global < n;
}

/* 1 when [a, a + size) touches region C's RX side, 2 its RW side, else 0. */
static int ios_jit_low_overlaps( uintptr_t a, size_t size )
{
    size_t n = ios_jit_low_size_global;

    if (!n || !size) return 0;
    if (a < ios_jit_low_rx_global + n && a + size > ios_jit_low_rx_global) return 1;
    if (a < ios_jit_low_rw_global + n && a + size > ios_jit_low_rw_global) return 2;
    return 0;
}

/* WINE_IOS_JIT_TAIL_REGION against the pool: 1 with C's RX base and size when it
 * is page-aligned, at least IOS_POOL_LOW_MIN, entirely below the pool span (so it
 * can never overlap it or its hole) and its RW alias at the pool's distance does
 * not wrap; 0 for anything else, which leaves pool-low off. */
static int ios_pool_low_parse( const char *env, uint64_t pool_rx, uint64_t pool_rw, uint64_t pool_size,
                               uint64_t *rx_out, uint64_t *size_out )
{
    char *sep = NULL;
    uint64_t rx, size;

    if (!env || !*env || !pool_rx || !pool_rw || !pool_size) return 0;
    rx = strtoull( env, &sep, 16 );
    if (!sep || *sep != ':') return 0;
    size = strtoull( sep + 1, NULL, 16 );
    if (!rx || (rx & 0x3fff) || (size & 0x3fff) || size < IOS_POOL_LOW_MIN) return 0;
    if (rx < 0x100000000ULL || rx + size < rx || rx + size > pool_rx) return 0;
    if (pool_rw < pool_rx - rx) return 0;
    *rx_out = rx;
    *size_out = size;
    return 1;
}

/* Region C's bump: `want` bytes from C's bottom, or 0 when it does not fit (the
 * pool tail serves it then). Never consumes anything on failure. */
static int ios_pool_low_take( volatile size_t *reserved, size_t low_size, size_t want, size_t *off_out )
{
    size_t cur;

    do
    {
        cur = *reserved;
        if (want > low_size || cur > low_size - want) return 0;
    } while (!__sync_bool_compare_and_swap( reserved, cur, cur + want ));
    *off_out = cur;
    return 1;
}

/* The RW alias of a pool with region C is one reservation from C's RW side to the
 * pool's RW end: its base and length (what the Social Club layout checks). Without
 * C it is [rw, rw + size). */
static void ios_pool_alias_extent( uint64_t pool_rx, uint64_t pool_rw, uint64_t pool_size,
                                   uint64_t low_rx, uint64_t low_size, uint64_t *lo, uint64_t *span )
{
    *lo = pool_rw;
    *span = pool_size;
    if (low_size && low_rx < pool_rx && pool_rw >= pool_rx - low_rx)
    {
        *lo = pool_rw - (pool_rx - low_rx);
        *span = pool_size + (pool_rx - low_rx);
    }
}

/* Gives back a refused tail carve's reservation: `added` bytes taken when the
 * counter went to `mine`. Unsplit this is the old fetch-and-sub. Split, a carve
 * may have jumped the hole, so `added` is more than its size: it is given back
 * only while no later carve sits on top of it (else a later carve placed by the
 * lowered counter could overlap one placed below the hole); otherwise the
 * bytes stay reserved, which wastes them but never overlaps. */
static void ios_pool_tail_unreserve( volatile size_t *reserved, size_t mine, size_t added, int split )
{
    if (!split) __sync_fetch_and_sub( reserved, added );
    else __sync_bool_compare_and_swap( reserved, mine, mine - added );
}

/* ---- Pool reclamation (task #25) ----------------------------------------
 * The bump allocator never freed anything: 8 pseudo-processes consumed
 * 368.9/384MB (2026-07-07) and the 9th BUS-loop-locked the session. Every
 * head allocation is now recorded in a ledger tagged with the allocating
 * pseudo-process (ios_jit_current_peb() — module loads run on the owning
 * process's thread, same invariant the owner-aware IAT-sync relies on).
 * process_exit_wrapper releases the dead process's ranges into a free list
 * the allocator consults before bumping.
 *
 * Reuse is gated by a grace period: laggard threads of the dead process
 * (woken by their closing server fds) still run PE exit paths from the
 * process's pool copies for a moment after process_exit_wrapper. Freed
 * bytes stay intact until actually rehanded out, so execution from a
 * freed-but-unreused range stays valid during the grace window. */
static pthread_mutex_t ios_pool_lock = PTHREAD_MUTEX_INITIALIZER;

#define IOS_POOL_LEDGER_MAX 1024
struct ios_pool_alloc
{
    size_t off;         /* pool offset */
    size_t size;        /* bytes (page-aligned) */
    void  *peb;         /* allocating pseudo-process; NULL = session/unknown */
    uint64_t tag;       /* madeira-pool-same-image: image layout fingerprint, 0 = none */
};
static struct ios_pool_alloc ios_pool_ledger[IOS_POOL_LEDGER_MAX];
static int ios_pool_ledger_count;

#define IOS_POOL_FREE_MAX 1024  /* madeira-pool-same-image: whole poisoned ranges are kept */
#define IOS_POOL_REUSE_GRACE_SEC 3
/* Darwin madvise: MADV_FREE marks pages volatile; MADV_FREE_REUSE is the
 * documented cancel. Guard for older SDK headers. */
#ifndef MADV_FREE_REUSE
#define MADV_FREE_REUSE 8
#endif
struct ios_pool_free
{
    size_t off;
    size_t size;
    time_t freed_at;
    int    advised;   /* physical pages returned via MADV_FREE (post-grace) */
    uint64_t tag;     /* madeira-pool-same-image: layout of the image that held it, 0 = none */
};
static struct ios_pool_free ios_pool_freelist[IOS_POOL_FREE_MAX];
static int ios_pool_free_count;

/* ml224: describe a faulting address against the JIT-pool ledger.
 *
 * Steam/CEF dies on a 128-bit atomic whose target VirtualQuery reports as MEM_FREE:
 *   [caspal128] addr=0x1526120e0 misalign=0 region base=0x152612000 size=0x2fee000
 *               prot=0x1 type=MEM_PRIVATE state=0x10000   (0x10000 = MEM_FREE)
 * so the instruction and its alignment were never the problem -- the POINTER is dangling.
 * The address sits inside the pool's span yet is unmapped, which points at pool lifetime
 * rather than guest logic. Three candidates need different fixes, and only the ledger can
 * tell them apart:
 *   - it lands in a freelist entry  => reclamation released memory still referenced
 *   - it lands in a live mapping    => the mapping exists; the fault is something else
 *   - it lands in neither           => a hole; the guest pointer is simply stale/garbage
 * Reports all three plus the pool geometry, so "none of the above" is a real answer.
 * Caller supplies the buffer; no allocation, safe from a fault handler. */
void ios_jit_describe_pool_addr( const void *addr, char *buf, size_t buflen )
{
    /* these are defined further down this file; declare locally so the describer can sit
     * next to the freelist it reports on rather than being pushed below its data */
    extern void *ios_jit_rw_base_global;
    extern void *ios_jit_rx_base_global;
    extern size_t ios_jit_pool_size_global;
    extern const char *ios_pe_module_name( const void *image_base, size_t image_size );

    uintptr_t a = (uintptr_t)addr;
    uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    size_t ps = ios_jit_pool_size_global;
    uintptr_t base = 0;
    const char *which = NULL;
    size_t off;
    int i;

    if (!buf || !buflen) return;
    buf[0] = 0;
    if (!ps) { snprintf( buf, buflen, "pool not initialised" ); return; }

    /* madeira-bcd pool-low: region C holds FEX code buffers only */
    if (ios_jit_low_contains( a ) || ios_jit_low_rw_contains( a ))
    {
        int is_rx = ios_jit_low_contains( a );
        size_t loff = a - (is_rx ? ios_jit_low_rx_global : ios_jit_low_rw_global);
        snprintf( buf, buflen, "%s pool-low (region C) off=0x%lx of 0x%lx, carved 0x%lx -> FEX code buffer%s",
                  is_rx ? "RX" : "RW", (unsigned long)loff, (unsigned long)ios_jit_low_size_global,
                  (unsigned long)ios_jit_low_reserved, loff < ios_jit_low_reserved ? "" : " (NOT CARVED YET)" );
        return;
    }

    if (rw && a >= rw && a < rw + ps)      { base = rw; which = "RW"; }
    else if (rx && a >= rx && a < rx + ps) { base = rx; which = "RX"; }
    else { snprintf( buf, buflen, "OUTSIDE pool (rw=%p rx=%p size=0x%lx)",
                     (void *)rw, (void *)rx, (unsigned long)ps ); return; }

    off = a - base;

    for (i = 0; i < ios_pool_free_count; i++)
    {
        if (off >= ios_pool_freelist[i].off &&
            off < ios_pool_freelist[i].off + ios_pool_freelist[i].size)
        {
            snprintf( buf, buflen,
                      "%s pool off=0x%lx -> FREELIST[%d] off=0x%lx size=0x%lx advised=%d"
                      "  <== RECLAIMED MEMORY STILL REFERENCED",
                      which, (unsigned long)off, i,
                      (unsigned long)ios_pool_freelist[i].off,
                      (unsigned long)ios_pool_freelist[i].size,
                      ios_pool_freelist[i].advised );
            return;
        }
    }

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t jb = (uintptr_t)ios_jit_mappings[i].jit_base;
        size_t sz = ios_jit_mappings[i].size;

        if (jb && sz && a >= jb && a < jb + sz)
        {
            snprintf( buf, buflen,
                      "%s pool off=0x%lx -> LIVE mapping[%d] %s pe=%p jit=%p+0x%lx owner=%p",
                      which, (unsigned long)off, i,
                      ios_pe_module_name( ios_jit_mappings[i].pe_base, sz ),
                      ios_jit_mappings[i].pe_base, (void *)jb, (unsigned long)sz,
                      ios_jit_mappings[i].owner_peb );
            return;
        }
    }

    snprintf( buf, buflen, "%s pool off=0x%lx -> HOLE (no freelist entry, no live mapping;"
                           " %d mappings, %d freelist)", which, (unsigned long)off,
              ios_jit_mapping_count, ios_pool_free_count );
}
/* task #34: 1 if the most recent ios_pool_alloc_range served from the freelist,
 * 0 if it came off the virgin bump. Read immediately after the call by the
 * copy-verify probe so a failed copy can be attributed to reuse or not. */
static int ios_pool_last_alloc_reused;
static __thread int ios_pool_last_same_image;

/* Defined next to decommit_pages; declared here so the allocator can check a
 * range against the LIVE ledger before handing it out (task #34 double-handout
 * detector). */
static int ios_pool_live_overlap( uintptr_t rw_start, size_t size,
                                  size_t *off_out, void **peb_out );

void *ios_jit_current_peb(void);
/* ml966: defined further down but called from the sub-floor registration site
 * above it, so it needs a prototype here (the build passes
 * -Wno-implicit-function-declaration, which would otherwise turn the call into
 * a conflicting non-static declaration). */
static void ios_lowalloc_note_qualifying_image( unsigned long long pref_base, int relocs_stripped );
/* ml1100: image low-alias, see the block at the sub-floor registration site. */
static void ios_image_lowalias_register( unsigned long long pref_base, unsigned long long real_base,
                                         unsigned long long size, const char *why );
static void ios_image_lowalias_retire( unsigned long long real_base );
extern void *ios_jit_rw_base_global;  /* defined below */
extern void *ios_jit_rx_base_global;  /* defined below */

/* ml90 (task #35): walk the Mach map and report every free gap >= 1GB, so we
 * size the jumbo-reserve problem against real numbers instead of guesses.
 * CEF asks for ~144GB (4x PartitionAlloc 16GB pools + a 32GB region) and only
 * two land; this says exactly what is left and where. Gaps inside the GPU
 * carveout [64G,448G) are flagged — they are reported free by the map but are
 * CPU-walled (maxprot=0), so they can never satisfy a reserve. */
/* task #34 POOL WARMER — the compressor countermeasure (ml104 finding).
 *
 * The faulting pool page's content is BYTE-IDENTICAL to the on-disk DLL
 * (libarm64ecfex RVA 0xd0820, verified against FEX/build-arm64ec/Bin —
 * the "zeros" in earlier fault dumps were inter-function padding present in
 * the file, misread as corruption). So content is never destroyed; only
 * EXECUTABILITY is lost, deterministically on a COLD page (copied via the RW
 * alias, not yet executed), only under CEF memory pressure. That is the
 * signature of the compressor: a cold dirty anon page is compressed, the
 * first exec touch decompresses it into a FRESH physical page, and TXM's
 * exec blessing does not survive the frame replacement. It also explains the
 * reuse correlation as a time confound: late copies land on freelist ranges
 * AND under peak pressure.
 *
 * Countermeasure: touch every used pool page every ~2s so none ever reaches
 * the inactive queue. ~40k pages at 650MB = a few ms per cycle. Reads via the
 * RW alias keep the shared physical page active for the RX view too. This is
 * both the experiment (faults vanish => theory confirmed) and the mitigation. */
static volatile size_t ios_jit_tail_reserved;   /* defined below (tail EC_CODE carve) */
extern size_t ios_jit_pool_size_global;         /* defined below */
/* task #35 THE MEASUREMENT THAT DECIDES THE WHOLE PLAN.
 *
 * Everything else about the furniture ceiling is instrumentation of a means to
 * an end; this reports the END directly. CEF needs three 16GB-ALIGNED
 * PartitionAlloc pools, and PA's own slot walk tries these three addresses. So
 * the only question that matters is whether they are still free by the time PA
 * asks. The ml119 noise (111 relaxed placements, hundreds of Wine views) is
 * irrelevant if the answer stays "all three CLEAR" -- and if a slot is dirty,
 * this names the exact first occupant instead of leaving us to infer it from a
 * pool count. Called periodically, so we see WHEN a slot goes bad, not just
 * that it did. */
static void ios_bigres_report( const char *why );   /* defined below */
static void ios_band_census( const char *why );     /* defined below (madeira-bcd, RDR2) */

static void ios_slot_probe( const char *why )
{
    /* ml149: probe 0x7000000000 too — it is a genuine 16GB-ALIGNED candidate and
     * the ONLY route to a fourth pool. The GPU carveout [64G,448G) ends at
     * exactly 0x7000000000, and ios_usable_va_floor is 0x7038000000 (ml423), so only
     * the first 896MB of that slot is blocked. If that occupant is ours (or movable)
     * a fourth slot exists and the wall disappears without touching Chromium —
     * whose kPoolMaxSize is compile-time and not ours to change. Report what is
     * actually in there rather than assuming it is the xzone. */
    static const mach_vm_address_t slots[4] = { 0x7000000000ULL, 0x7400000000ULL,
                                                0x7800000000ULL, 0x7C00000000ULL };
    const mach_vm_size_t SLOT = 0x400000000ULL;   /* 16GB */
    int i;

    for (i = 0; i < 4; i++)
    {
        mach_vm_address_t lo = slots[i], hi = slots[i] + SLOT, addr = lo;
        mach_vm_size_t occupied = 0;
        mach_vm_address_t first_occ = 0;
        mach_vm_size_t first_sz = 0;
        int regions = 0;

        while (addr < hi)
        {
            mach_vm_size_t size = 0;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj = MACH_PORT_NULL;
            mach_vm_address_t q = addr;

            if (mach_vm_region( mach_task_self(), &q, &size, VM_REGION_BASIC_INFO_64,
                                (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS)
                break;
            if (q >= hi) break;                    /* nothing left inside the slot */
            if (q + size > hi) size = hi - q;
            if (!first_occ) { first_occ = q; first_sz = size; }
            occupied += size;
            regions++;
            addr = q + size;
        }
        if (occupied)
        {
            dprintf(2, "[slot#%d] 0x%llx+16GB DIRTY regions=%d occupied=%llu MB first=0x%llx+0x%llx (%s)\n",
                    i, (unsigned long long)lo, regions, (unsigned long long)(occupied >> 20),
                    (unsigned long long)first_occ, (unsigned long long)first_sz, why);
            /* ml149: for the 448G slot, enumerate the blockers with their
             * protections — that is what decides whether they are ours to move. */
            if (lo == 0x7000000000ULL)
            {
                mach_vm_address_t a2 = lo;
                int shown = 0;
                while (a2 < hi && shown < 8)
                {
                    mach_vm_size_t sz2 = 0;
                    vm_region_basic_info_data_64_t inf2;
                    mach_msg_type_number_t c2 = VM_REGION_BASIC_INFO_COUNT_64;
                    mach_port_t o2 = MACH_PORT_NULL;
                    mach_vm_address_t q2 = a2;
                    if (mach_vm_region( mach_task_self(), &q2, &sz2, VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&inf2, &c2, &o2 ) != KERN_SUCCESS) break;
                    if (q2 >= hi) break;
                    dprintf(2, "[slot#0]   blocker 0x%llx+0x%llx (%llu MB) prot=%x/%x shared=%d\n",
                            (unsigned long long)q2, (unsigned long long)sz2,
                            (unsigned long long)(sz2 >> 20), inf2.protection,
                            inf2.max_protection, inf2.shared);
                    shown++;
                    a2 = q2 + sz2;
                }
            }
        }
        else
            dprintf(2, "[slot#%d] 0x%llx+16GB CLEAR (%s)\n",
                    i, (unsigned long long)lo, why);
    }
}

/* task #35 THE LAST UNKNOWN: what is actually IN the furniture window?
 *
 * ml120 proved the window's 15.1GB is fully consumed, which is what makes three
 * pools impossible (48 + 17 > 63). But "consumed" does not distinguish genuine
 * demand from waste, and that distinction decides whether 3 pools are reachable
 * at all: if this is ~480 arenas of 32MB that nobody frees, reclaiming them
 * unlocks the third slot; if it is thread stacks and images, 2 pools is the
 * hard ceiling and CEF has to run on two. The 2GB that poisoned slot#0 was 64
 * regions of ~32MB, so a size histogram should be conclusive. Bucket by size
 * class, then name the biggest tenants. */
static void ios_window_inventory( const char *why, unsigned long long lo_arg, unsigned long long hi_arg )
{
    static const char *names[6] = { "<=64K", "<=1M", "<=8M", "<=64M", "<=512M", ">512M" };
    mach_vm_address_t addr = (mach_vm_address_t)lo_arg;
    const mach_vm_address_t hi = (mach_vm_address_t)hi_arg;
    mach_vm_size_t bytes[6] = { 0 }, big_sz[8] = { 0 };
    unsigned counts[6] = { 0 };
    mach_vm_address_t big_at[8] = { 0 };
    int big_pr[8] = { 0 };
    mach_vm_size_t total = 0;
    unsigned regions = 0;
    /* ml123: the 130 x 128MB regions are NOT one-per-thread (31 threads, 130
     * regions) and they come in CONTIGUOUS runs, so they are almost certainly
     * one large mapping each that mach reports split into 128MB map entries.
     * Individual entries therefore tell us nothing; coalesce adjacent entries
     * into RUNS and report the largest runs, plus Darwin's user_tag, which
     * names the allocator directly instead of leaving us to infer it. */
    mach_vm_address_t run_at = 0;
    mach_vm_size_t run_sz = 0;
    int run_tag = -1, run_pr = 0;
    mach_vm_size_t tagb[8] = { 0 };
    int tagid[8];
    int i, j, ntag = 0;
    /* ml366: free-hole accounting. Image loads need CONTIGUOUS space in this
     * window (map_image_view's limit_high is non-relaxable), so the number
     * that predicts a c0000017 DLL-load failure is the LARGEST FREE HOLE,
     * which nothing measured before. mach_vm_region skips holes, so the gap
     * between the previous region's end and the next region's start is free. */
    mach_vm_size_t free_total = 0, free_max = 0;
    mach_vm_address_t free_max_at = 0;

    for (i = 0; i < 8; i++) tagid[i] = -1;

    while (addr < hi)
    {
        mach_vm_size_t size = 0;
        vm_region_extended_info_data_t einfo;
        mach_msg_type_number_t cnt = VM_REGION_EXTENDED_INFO_COUNT;
        mach_port_t obj = MACH_PORT_NULL;
        mach_vm_address_t q = addr;
        int tag, prot;

        if (mach_vm_region( mach_task_self(), &q, &size, VM_REGION_EXTENDED_INFO,
                            (vm_region_info_t)&einfo, &cnt, &obj ) != KERN_SUCCESS)
            break;
        if (q > addr)   /* hole between previous region end and this one */
        {
            mach_vm_size_t gap = ((q < hi) ? q : hi) - addr;
            free_total += gap;
            if (gap > free_max) { free_max = gap; free_max_at = addr; }
        }
        if (q >= hi) break;
        if (q + size > hi) size = hi - q;
        tag = einfo.user_tag;
        prot = einfo.protection;

        i = size <= 0x10000 ? 0 : size <= 0x100000 ? 1 : size <= 0x800000 ? 2
          : size <= 0x4000000 ? 3 : size <= 0x20000000 ? 4 : 5;
        counts[i]++;
        bytes[i] += size;
        total += size;
        regions++;

        /* bytes-by-tag histogram (first 8 distinct tags seen) */
        for (j = 0; j < ntag; j++) if (tagid[j] == tag) break;
        if (j == ntag && ntag < 8) { tagid[ntag] = tag; ntag++; }
        if (j < 8) tagb[j] += size;

        /* coalesce into runs of same tag+prot */
        if (run_sz && q == run_at + run_sz && tag == run_tag && prot == run_pr)
            run_sz += size;
        else
        {
            if (run_sz)
                for (j = 0; j < 8; j++)
                    if (run_sz > big_sz[j])
                    {
                        int k;
                        for (k = 7; k > j; k--)
                        {
                            big_sz[k] = big_sz[k-1]; big_at[k] = big_at[k-1]; big_pr[k] = big_pr[k-1];
                        }
                        big_sz[j] = run_sz; big_at[j] = run_at;
                        big_pr[j] = (run_pr << 8) | (run_tag & 0xff);
                        break;
                    }
            run_at = q; run_sz = size; run_tag = tag; run_pr = prot;
        }
        addr = q + size;
        /* ml366: the old 4000-region backstop TRUNCATED the census — ml365
         * reported "occupied 12198 of 15232 MB" over exactly 4001 regions
         * while the window was in fact fuller; every occupancy number since
         * the window fragmented past 4000 regions was an undercount. Keep a
         * runaway backstop only. */
        if (regions > 100000) { dprintf(2, "[window] TRUNCATED at %u regions\n", regions); break; }
    }
    if (addr < hi)   /* tail hole after the last region */
    {
        mach_vm_size_t gap = hi - addr;
        free_total += gap;
        if (gap > free_max) { free_max = gap; free_max_at = addr; }
    }
    if (run_sz)
        for (j = 0; j < 8; j++)
            if (run_sz > big_sz[j])
            {
                int k;
                for (k = 7; k > j; k--)
                {
                    big_sz[k] = big_sz[k-1]; big_at[k] = big_at[k-1]; big_pr[k] = big_pr[k-1];
                }
                big_sz[j] = run_sz; big_at[j] = run_at;
                big_pr[j] = (run_pr << 8) | (run_tag & 0xff);
                break;
            }

    /* ml787: never report a window as free without checking the TASK CEILING
     * first.
     *
     * A region walk above the ceiling finds no mappings, because the range is
     * not in the task's map at all -- and the census then printed the whole
     * span as free. A 449GB window was read as 15GB of usable address space on
     * a task whose ceiling is 63GB, and used to argue for a placement that
     * could never have worked. "No mappings here" and "usable" are different
     * claims; this one now says which it is making. */
    {
        task_vm_info_data_t ceil_vmi;
        mach_msg_type_number_t ceil_cnt = TASK_VM_INFO_COUNT;
        unsigned long long task_max = 0;
        if (task_info( mach_task_self(), TASK_VM_INFO,
                       (task_info_t)&ceil_vmi, &ceil_cnt ) == KERN_SUCCESS)
            task_max = (unsigned long long)ceil_vmi.max_address;

        if (task_max && (unsigned long long)lo_arg >= task_max)
        {
            dprintf(2, "[window] 0x%llx..0x%llx OUTSIDE TASK MAP (ceiling 0x%llx) -- "
                    "no mappings found here because the range is not mapped at all; "
                    "this is NOT free space rev=ml787 (%s)\n",
                    (unsigned long long)lo_arg, (unsigned long long)hi_arg, task_max, why);
        }
        else
        {
            /* CLAMP the span to the ceiling rather than annotating it. A window
             * that starts below the ceiling and ends above it would otherwise
             * report the unmapped remainder as free -- the same untruth as the
             * fully-outside case, just harder to notice. */
            unsigned long long eff_hi = (unsigned long long)hi_arg;
            unsigned long long eff_free = (unsigned long long)free_total;
            unsigned long long eff_hole = (unsigned long long)free_max;
            int clamped = 0;
            if (task_max && eff_hi > task_max)
            {
                unsigned long long cut = eff_hi - task_max;
                eff_hi = task_max;
                clamped = 1;
                /* Everything above the ceiling was counted as a free hole. */
                eff_free = eff_free > cut ? eff_free - cut : 0;
                if (eff_hole > cut) eff_hole -= cut; else eff_hole = 0;
            }
            dprintf(2, "[window] 0x%llx..0x%llx regions=%u occupied=%llu MB of %llu MB "
                    "free=%llu MB maxhole=%llu MB@0x%llx rev=ml787%s (%s)\n",
                    (unsigned long long)lo_arg, eff_hi, regions,
                    (unsigned long long)(total >> 20),
                    (unsigned long long)((eff_hi - (unsigned long long)lo_arg) >> 20),
                    (unsigned long long)(eff_free >> 20),
                    (unsigned long long)(eff_hole >> 20),
                    (unsigned long long)free_max_at,
                    clamped ? " CLAMPED-TO-TASK-CEILING" : "", why);
        }
    }
    for (i = 0; i < 6; i++)
        if (counts[i])
            dprintf(2, "[window]   %-7s n=%-5u %llu MB\n",
                    names[i], counts[i], (unsigned long long)(bytes[i] >> 20));
    for (i = 0; i < 8 && big_sz[i]; i++)
        dprintf(2, "[window]   run#%d 0x%llx +0x%llx (%llu MB) prot=%x tag=%d\n",
                i, (unsigned long long)big_at[i], (unsigned long long)big_sz[i],
                (unsigned long long)(big_sz[i] >> 20), big_pr[i] >> 8, big_pr[i] & 0xff);
    for (i = 0; i < ntag; i++)
        dprintf(2, "[window]   tag%-4d %llu MB\n", tagid[i], (unsigned long long)(tagb[i] >> 20));
}

/* ml668: published by the footprint sampler below and read by its own cadence
 * logic; defined further down alongside ios_jit_pool_size_global. */
extern unsigned long long ios_last_footprint_mb;
extern int ios_fast_footprint;

/* madeira-bcd: how often the warmer's address-space sweeps run, in its ~2 s
 * cycles. In build 442's GTA V gameplay the [phys-map] walk covered ~182,000
 * regions in ~1.3 s at 60-70 % of a core every 10 s, and every third of those
 * also walked the four pool slots ([slot#2] alone ~72,000 regions) and the
 * furniture window: the warmer's whole cost, in bursts the game's saturated
 * P cores paid for. Page warming still runs every cycle; the .text sweep keeps
 * its cadence. MADEIRA_WARMER_SWEEP_CYCLES (default 30, ~1 min; 5 restores the
 * old 10 s map walk with the inventory every 15). */
/* madeira-bcd lean-diag (env.MADEIRA_LEAN_DIAG = 1, opt-in; server_ios.c reads the
 * same switch for its samplers). The warmer keeps warming every page every cycle
 * and keeps its [footprint] line; what is diagnostic only runs rarely: the map
 * walk ([phys-map], [holes<64G], [malloc-zones]) and the slot/window inventory
 * every 300 cycles (~10 min) instead of 30 -- in hzd486 the walk took 0.12-0.39 s
 * of P-core time a minute, 3.2 s once the CPU was clamped -- the .text max_prot
 * sweep every 30 cycles instead of 5, the CoreAnimation shmem replay and the
 * malloc zone check every 30 cycles instead of every one (the check's cost is
 * then logged, [lean-diag] zone-check), and mprotect_exec's ERR line (one per
 * call, ~400/s while Horizon Zero Dawn loads) after its first 200 only for every
 * 1000th call. */
static int ios_lean_diag_virtual( void )
{
    static int v = -1;
    if (v < 0)
    {
        const char *e = getenv( "MADEIRA_LEAN_DIAG" );
        v = e && *e && strcmp( e, "0" ) != 0;
    }
    return v;
}

/* set by the warmer thread when it starts, so mprotect_exec (which can run in a
 * fault path) never calls getenv itself; the first calls before that are logged */
static volatile int ios_lean_mprotect_on;

static int ios_lean_mprotect_log( void )
{
    static long n;
    long k;
    if (!ios_lean_mprotect_on) return 1;
    k = __atomic_add_fetch( &n, 1, __ATOMIC_RELAXED );
    if (k == 200)
        dprintf( 2, "[lean-diag] mprotect_exec: 200 calls logged, from now on 1 in 1000 (MADEIRA_LEAN_DIAG)\n" );
    return k <= 200 || !(k % 1000);
}

static unsigned ios_warmer_sweep_cycles( void )
{
    static unsigned v;
    if (!v)
    {
        /* cycles of ~2 s between the warmer's map walk and slot/window inventory (default 30; 5 = old). */
        const char *e = getenv( "MADEIRA_WARMER_SWEEP_CYCLES" );
        const char *lean = getenv( "MADEIRA_LEAN_DIAG" );   /* madeira-bcd lean-diag: 300 (~10 min) */
        unsigned long n = e && *e ? strtoul( e, NULL, 10 ) : 0;
        v = n >= 1 && n <= 100000 ? (unsigned)n : lean && *lean && strcmp( lean, "0" ) != 0 ? 300 : 30;
    }
    return v;
}

static void *ios_pool_warmer_thread( void *arg )
{
    unsigned cycle = 0;
    { extern void ios_eco_native_self( const char *who ); ios_eco_native_self( "pool-warmer" ); }   /* madeira-bcd eco-native */
    ios_lean_mprotect_on = ios_lean_diag_virtual();   /* madeira-bcd lean-diag: mprotect_exec thins its ERR line from now on */
    for (;;)
    {
        /* ml1060: THE MONITOR WAS A TENTH OF THE MACHINE. Above 2400 MB this loop
         * drops to a 250 ms cadence (ml668, written for a 4 GB device, so that the
         * terminal footprint burst is captured) -- but everything below is gated on
         * `cycle`, so the 8x faster cadence also ran the 120,000-region physical-map
         * walk every 1.25 s, re-touched every pool page four times a second, and
         * replayed four vm_allocate probes per cycle. Thread samples showed this
         * thread at ~30 % of a core in mach_msg for the entire benchmark. The fast
         * cadence now runs ONLY the one cheap footprint line; the full body keeps
         * its original ~2 s period regardless of footprint. */
        {
            static struct timespec last_full;
            struct timespec now_ts;
            double since;
            clock_gettime( CLOCK_MONOTONIC, &now_ts );
            since = (now_ts.tv_sec - last_full.tv_sec) + (now_ts.tv_nsec - last_full.tv_nsec) / 1e9;
            if (last_full.tv_sec && since < 1.9)
            {
                extern unsigned long long ios_last_footprint_mb;
                task_vm_info_data_t fvmi;
                mach_msg_type_number_t fcnt = TASK_VM_INFO_COUNT;
                if (task_info( mach_task_self(), TASK_VM_INFO, (task_info_t)&fvmi, &fcnt ) == KERN_SUCCESS)
                {
                    static unsigned long long fast_peak;
                    unsigned long long mb = (unsigned long long)fvmi.phys_footprint >> 20;
                    ios_last_footprint_mb = mb;
                    if (mb > fast_peak + 16)      /* only say something when it actually climbs */
                    {
                        fast_peak = mb;
                        dprintf( 2, "[footprint] rev=ml1060 fast phys=%llu MB compressed=%llu MB\n", mb,
                                 (unsigned long long)fvmi.compressed >> 20 );
                    }
                }
                usleep( 250000 );
                continue;
            }
            last_full = now_ts;
        }
        volatile const char *rw = (volatile const char *)ios_jit_rw_base_global;
        /* ml121: warm the RX ALIAS TOO. The warmer only ever touched the RW
         * alias, but execution faults on the RX one -- they are two separate
         * mach mappings of the same object, so residency established through RW
         * need not hold for RX. ml121 died exactly this way: [exec-recover]
         * pg=0x1243d8000 lost execute while the warmer was running, mprotect_rx
         * failed EACCES (as it ALWAYS does on blessed pool memory -- never
         * evidence), and the unrecoverable fault killed the CEF child. Reading
         * through an RX mapping is permitted and is the only touch that can
         * establish residency for the alias that actually executes. */
        volatile const char *rx = (volatile const char *)ios_jit_rx_base_global;
        size_t total = ios_jit_pool_size_global;
        if (rw && total)
        {
            size_t head = jit_pool_offset;               /* snapshot; only grows */
            size_t tail = ios_jit_tail_reserved;
            size_t o, touched = 0;
            volatile char sink = 0;
            if (head > total) head = total;
            if (tail > total) tail = total;
            /* madeira-bcd split pool: the hole is not pool memory (its RW side
             * is PROT_NONE, its RX side the main thread's stack) -- skip it. */
            for (o = 0; o < head; o += 0x4000) { if (IOS_POOL_IN_HOLE(o)) continue; sink += rw[o]; touched++; }
            for (o = total - tail; o < total; o += 0x4000) { if (IOS_POOL_IN_HOLE(o)) continue; sink += rw[o]; touched++; }
            if (rx)
            {
                for (o = 0; o < head; o += 0x4000) { if (IOS_POOL_IN_HOLE(o)) continue; sink += rx[o]; touched++; }
                for (o = total - tail; o < total; o += 0x4000) { if (IOS_POOL_IN_HOLE(o)) continue; sink += rx[o]; touched++; }
            }
            /* madeira-bcd pool-low: region C's carved part holds FEX code buffers
             * exactly like the tail -- warm both of its aliases too. */
            if (ios_jit_low_size_global)
            {
                volatile const char *lrw = (volatile const char *)ios_jit_low_rw_global;
                volatile const char *lrx = (volatile const char *)ios_jit_low_rx_global;
                size_t used = ios_jit_low_reserved;
                if (used > ios_jit_low_size_global) used = ios_jit_low_size_global;
                for (o = 0; o < used; o += 0x4000) { sink += lrw[o]; sink += lrx[o]; touched += 2; }
            }
            (void)sink;
            cycle++;
            if (cycle == 1 || (cycle % 30) == 0)
                dprintf(2, "[pool-warmer] cycle=%u touched=%lu pages (head=0x%lx tail=0x%lx)\n",
                        cycle, (unsigned long)touched, (unsigned long)head, (unsigned long)tail);
            {
                extern void ios_wow_pressure_tick( unsigned cycle );
                ios_wow_pressure_tick( cycle );   /* ml2030: idle 32-bit placeholders back under band pressure */
            }
            /* task #35: report the three pool slots every ~30s on this existing
             * timer — see ios_slot_probe. Cheap (a few mach queries) and it is
             * the only signal that says whether the ceiling is doing its job. */
            /* ml136 CATCH THE REPLACEMENT WHEN IT HAPPENS, not at the exec fault.
             *
             * ml134 proved a live pool RX page had max_prot=0x3 when a healthy
             * one is 0x7 — max_protection only drops via a fresh mapping, so
             * something REPLACED it. Both Wine paths are now instrumented and
             * report zero ([jit-tripwire] fixed maps, [jit-clobber] kernel
             * picks), so the culprit is outside Wine's allocator and we cannot
             * catch it at the call. Instead sweep the used pool for pages that
             * have lost EXECUTE from max_prot. The warmer already walks exactly
             * this memory every 2s, so the sweep is nearly free, and it turns a
             * rare fatal symptom into an early located observation: we learn
             * WHICH range died and WHEN, and can correlate against whatever the
             * log shows happening in that window. */
            /* ml137 SWEEP ONLY .text — the first cut sampled the pool at 4MB
             * stride and flagged 9-11 pages per pass, but mapping those offsets
             * back to modules showed every one landed deep inside a copy
             * (shell32 +0x604000 of 0xbf0000, steamui +0x10c8000 of 0x123e000,
             * libavutil +0x288000/+0x688000) — .data/.rsrc/.reloc, which are
             * LEGITIMATELY RW in a pool copy. All false positives. The genuine
             * ml134 corruption was at libarm64ecfex+0xd06d0, i.e. in .text.
             * ios_jit_mappings already records text_offset/text_size per module,
             * so walk exactly those ranges: any .text page whose max_prot has
             * lost EXECUTE is real corruption, with no benign explanation. */
            if ((cycle % 5) == 0 && rx)
            if (!ios_lean_diag_virtual() || (cycle % 30) == 0)   /* madeira-bcd lean-diag: every 30 */
            {
                unsigned mi;
                size_t bad = 0, checked = 0;
                for (mi = 0; mi < ios_jit_mapping_count; mi++)
                {
                    uintptr_t jb = (uintptr_t)ios_jit_mappings[mi].jit_base;
                    size_t t_off = ios_jit_mappings[mi].text_offset;
                    size_t t_sz  = ios_jit_mappings[mi].text_size;
                    size_t o;

                    if (!jb || !t_sz) continue;
                    for (o = 0; o < t_sz; o += 0x40000)   /* 256KB stride inside .text */
                    {
                        mach_vm_address_t want = (mach_vm_address_t)(jb + t_off + o), a = want;
                        mach_vm_size_t rsz = 0;
                        vm_region_basic_info_data_64_t inf;
                        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
                        mach_port_t obj = MACH_PORT_NULL;

                        if (mach_vm_region( mach_task_self(), &a, &rsz, VM_REGION_BASIC_INFO_64,
                                            (vm_region_info_t)&inf, &cnt, &obj ) != KERN_SUCCESS)
                            break;
                        if (a > want) continue;                  /* hole */
                        checked++;
                        if (!(inf.max_protection & VM_PROT_EXECUTE) && bad++ < 8)
                            dprintf(2, "[pool-rot] TEXT LOST EXEC va=0x%llx mod_pool=0x%llx"
                                       " text+0x%lx prot=%x max=%x region=0x%llx+0x%llx cycle=%u\n",
                                    (unsigned long long)want, (unsigned long long)jb,
                                    (unsigned long)o, inf.protection, inf.max_protection,
                                    (unsigned long long)a, (unsigned long long)rsz, cycle);
                    }
                }
                if (bad)
                    dprintf(2, "[pool-rot] %lu of %lu sampled .text pages LOST EXEC (cycle=%u)\n",
                            (unsigned long)bad, (unsigned long)checked, cycle);
                else if (cycle % 15 == 0)
                    dprintf(2, "[pool-rot] clean: %lu .text pages sampled across %u mappings (cycle=%u)\n",
                            (unsigned long)checked, ios_jit_mapping_count, cycle);
            }
            if (cycle == 1 || (ios_warmer_sweep_cycles() == 5 ? (cycle % 15) == 0
                                                               : (cycle % ios_warmer_sweep_cycles()) == 0))
            {
                /* ml469 (wall #79): one-shot proof of whether TCP loopback
                 * works at all under this port — the webhelper's transport
                 * ws://localhost dial loop never completes and steam.exe's own
                 * connectivity test says NoLAN, but nothing on record shows a
                 * loopback connect succeeding here.  Raw BSD sockets, below
                 * wine, so a failure indicts the platform layer directly. */
                if (cycle == 1)
                {
                    extern void ios_loopback_selftest(void);
                    ios_loopback_selftest();
                }
                ios_slot_probe( "periodic" );
                /* ml121 probe-design fix: the inventory was wired ONLY to the
                 * jumbo-failure sites, and ml121 died before any jumbo call, so
                 * the one measurement that decides whether a 3rd pool is
                 * reachable never fired. Put it on the periodic timer too. */
                ios_window_inventory( "periodic", 0x7048000000ULL, 0x7400000000ULL );
                /* ml897: the band CoreAnimation's tag-51 vm_allocate lands in.
                 * ml896 measured KERN_NO_SPACE there in 36 of 110 cycles while
                 * every success sat in 0x724..0x76b; this says WHO occupies it. */
                {
                    extern unsigned long long ios_layerkit_lo, ios_layerkit_hi;   /* ml902: the MEASURED span */
                    if (ios_layerkit_hi) ios_window_inventory( "layerkit-span", ios_layerkit_lo, ios_layerkit_hi );
                }
                ios_bigres_report( "periodic" );
                ios_band_census( "periodic" );   /* env.MADEIRA_BAND_CENSUS = 1 only */
            }
            /* ml358 FOOTPRINT (every cycle, one line): phys_footprint is the
             * EXACT number jetsam kills on — everything else in this file
             * measures address space, which is not what got us killed (ml357:
             * "Terminated due to memory issue" with pools at 0% committed).
             * The breakdown discriminates who is spending: `internal` = our
             * dirty anonymous pages (JIT pool copies, guest heap), `compressed`
             * = what the compressor already absorbed, `phys_footprint` = the
             * ledger total. Peak is tracked so a pull after death still shows
             * how close the run got. */
            /* ml398 (task #60): sample the beacon-marked chrome_ipc pump
             * thread's Mach state each cycle — see ios_pump_sample() in
             * signal_arm64_ios.c. */
            {
                extern void ios_pump_sample(void);
                ios_pump_sample();
            }
            {
                task_vm_info_data_t vmi;
                mach_msg_type_number_t vmi_cnt = TASK_VM_INFO_COUNT;
                if (task_info( mach_task_self(), TASK_VM_INFO,
                               (task_info_t)&vmi, &vmi_cnt ) == KERN_SUCCESS)
                {
                    static unsigned long long peak_mb;
                    unsigned long long fp_mb = (unsigned long long)vmi.phys_footprint >> 20;
                    if (fp_mb > peak_mb) peak_mb = fp_mb;
                    ios_last_footprint_mb = fp_mb;      /* ml668: drives the sampler cadence */
                    /* ml896: replay CoreAnimation's shmem request EXACTLY. ml894 used
                     * plain ANYWHERE|PURGABLE and never saw a failure, but the
                     * disassembly of CA::Render::Shmem::new_shmem shows
                     *   vm_allocate(task, &addr, size, 0x33000003)
                     * = ANYWHERE | PURGABLE | VM_MAKE_TAG(51), and the tag picks
                     * the address range. Four variants isolate tag vs purgable. */
                    if (!ios_lean_diag_virtual() || cycle == 1 || (cycle % 30) == 0)   /* madeira-bcd lean-diag */
                    {
                        static kern_return_t last[4] = { -1, -1, -1, -1 };
                        static const int fl[4] = { 0x33000003, 0x33000001, 0x00000003, 0x00000001 };
                        static const char *nm[4] = { "tag51+purg", "tag51", "purg", "plain" };
                        vm_address_t a[4]; kern_return_t kr[4]; int i, changed = 0;
                        for (i = 0; i < 4; i++) {
                            a[i] = 0;
                            kr[i] = vm_allocate( mach_task_self(), &a[i], 0x19000, fl[i] );
                            if (kr[i] != last[i]) changed = 1;
                        }
                        if (changed || (cycle % 30) == 0)
                            dprintf(2, "[ca-shmem-probe] rev=ml896 %s: kr=%d 0x%lx | %s: kr=%d 0x%lx | %s: kr=%d 0x%lx | %s: kr=%d 0x%lx (cycle=%u)\n",
                                    nm[0], kr[0], (unsigned long)a[0], nm[1], kr[1], (unsigned long)a[1],
                                    nm[2], kr[2], (unsigned long)a[2], nm[3], kr[3], (unsigned long)a[3], cycle);
                        for (i = 0; i < 4; i++) {
                            last[i] = kr[i];
                            if (kr[i] == KERN_SUCCESS) vm_deallocate( mach_task_self(), a[i], 0x19000 );
                        }
                    }
                    dprintf(2, "[footprint] rev=ml358 phys=%llu MB (peak %llu) internal=%llu MB "
                            "compressed=%llu MB external=%llu MB reusable=%llu MB (cycle=%u)\n",
                            fp_mb, peak_mb,
                            (unsigned long long)vmi.internal >> 20,
                            (unsigned long long)vmi.compressed >> 20,
                            (unsigned long long)vmi.external >> 20,
                            (unsigned long long)vmi.reusable >> 20, cycle);
                }
            }
            /* ml566: WHEN does the host malloc zone become corrupt?
             *
             * ml565 settled the mechanism: at the fatal trap the process had
             * 868 MB of headroom and a 1 MB mach_vm_allocate SUCCEEDED, so the
             * libsystem_malloc BRK is NOT out-of-memory — the zone is genuinely
             * corrupt. wineserver's alloc_object is merely the next caller to
             * walk a damaged free list; it is the victim, not the culprit.
             *
             * Knowing WHO corrupts it starts with knowing WHEN. malloc_zone_check
             * walks and validates every zone, so the first cycle it fails brackets
             * the damage to a 2-second window that can be read straight off the
             * surrounding log. Note this whole app is ONE process: the zone is
             * shared by our Swift/ObjC code, wine, wineserver, FEX, DXMT and any
             * wild guest write, so the bracket is the only cheap way in.
             *
             * Self-calibrating: the first PASS is logged too, with its cost in ms.
             * Without that, silence would be ambiguous between "heap healthy" and
             * "probe never ran". If the cost turns out to be large we will see it
             * immediately and can back the interval off. */
            {
                extern boolean_t malloc_zone_check( malloc_zone_t *zone );
                static int zone_bad, zone_announced;
                if (!zone_bad && (!ios_lean_diag_virtual() || cycle == 1 || (cycle % 30) == 0))   /* madeira-bcd lean-diag */
                {
                    struct timeval t0, t1;
                    int ok;
                    gettimeofday( &t0, NULL );
                    ok = malloc_zone_check( NULL );
                    gettimeofday( &t1, NULL );
                    {
                        long ms = (t1.tv_sec - t0.tv_sec) * 1000
                                + (t1.tv_usec - t0.tv_usec) / 1000;
                        if (!ok)
                        {
                            zone_bad = 1;
                            dprintf(2, "[zone-check] *** HOST MALLOC ZONE FIRST FAILED AT cycle=%u "
                                       "(%ld ms) — corruption happened within the last ~2s; read the "
                                       "log immediately above this line rev=ml566\n", cycle, ms);
                        }
                        else if (!zone_announced)
                        {
                            zone_announced = 1;
                            dprintf(2, "[zone-check] armed and PASSING at cycle=%u (%ld ms per check) "
                                       "rev=ml566\n", cycle, ms);
                        }
                        else if (ios_lean_diag_virtual())   /* madeira-bcd lean-diag: what each (now rare) check costs */
                        {
                            static unsigned lean_said;
                            if (lean_said++ < 60)
                                dprintf(2, "[lean-diag] zone-check passed at cycle=%u in %ld ms\n", cycle, ms);
                        }
                    }
                }
            }

            /* ml359 WHERE does the footprint live? ml359 died at the kernel's
             * 4096MB high watermark (EXC_RESOURCE MEMORY/HWM) with internal at
             * 3043MB, and the totals above cannot attribute that to the pool
             * vs FEX lookup caches vs CEF heap. Walk the address space and
             * charge private-dirty+swapped pages to each region; the base
             * addresses identify the owner offline (pool = RX base, FEX bands,
             * PA pools, guest heap). Every 5th cycle plus cycle 2, because the
             * walk is tens of thousands of kernel calls. */
            if (cycle == 2 || (cycle % ios_warmer_sweep_cycles()) == 0)
            {
                struct { unsigned long long base, size, dirty, res, swap; unsigned tag; } top[12];
                unsigned long long dirty_by_tag[256];
                /* ml677: DIRTY IS NOT RESIDENCY. The top[12] rows carry res/swap
                 * but they are only the twelve dirtiest regions of the sweep, so
                 * summing THOSE and comparing against the full dirty_by_tag[]
                 * aggregate mixes a sample with a census -- which is exactly how
                 * I concluded "tag 100 is 1380MB of pinned GPU memory" when the
                 * true residency was never measured. Aggregate all three per tag,
                 * over EVERY region, so the comparison is like-for-like. */
                unsigned long long res_by_tag[256], swap_by_tag[256];
                /* ml360 BAND TOTALS: ml360's walk showed the top-12 misses most
                 * of the spend (2154MB tag-0 spread over 116k regions) and the
                 * JIT pool showed up NOWHERE despite ~460MB written — either
                 * its dirty pages are charged oddly or the region is shredded
                 * into thousands of entries. Aggregate dirty AND resident per
                 * address band so attribution can't hide in fragmentation.
                 * Pool bands must be tested FIRST: the RW alias (0x7000000000)
                 * sits numerically inside the guest range. */
                enum { B_POOL_RX, B_POOL_RW, B_HOST_LOW, B_GUEST, B_PA, B_FEX, B_OTHER, B_MAX };
                static const char *band_name[B_MAX] =
                    { "poolRX", "poolRW", "hostlow", "guest", "pa", "fex", "other" };
                unsigned long long band_dirty[B_MAX], band_res[B_MAX];
                /* ml1074: the four dirtiest regions of the two bands nobody can name
                 * from the totals (hostlow = everything below 64 GB that is not the
                 * pool; pa = 0x74..0x7c). The overall top-12 is always the game's own
                 * 128 MB arenas, so those bands were never attributed. */
                struct { unsigned long long base, size, dirty; unsigned tag, prot; } btop[B_MAX][4];
                memset(btop, 0, sizeof btop);
                uintptr_t prx = (uintptr_t)ios_jit_rx_base_global;
                uintptr_t prw = (uintptr_t)ios_jit_rw_base_global;
                size_t pps = ios_jit_pool_size_global;
                mach_vm_address_t raddr = 0;
                mach_vm_size_t rsize = 0;
                natural_t rdepth = 0;
                unsigned regions = 0, ti, tj;
                unsigned long long total_dirty = 0;
                /* ml894: HOLE CENSUS below 64GB. CoreAnimation's presentation-
                 * modifier shmem (what SwiftUI's async renderer allocates on
                 * every animation frame) is an UNTAGGED vm_allocate(ANYWHERE|
                 * PURGABLE) of ~100KB; two Enter presses at the game menu died
                 * on exactly that returning NULL (SwiftUICore commitAsyncValues
                 * force-unwraps the group). Untagged requests are confined to
                 * the default range, so record what is actually free down here:
                 * the largest gap, the total, and the LOWEST gap >= 128KB (a
                 * lowest-fit search would land there). */
                unsigned long long hole_prev_end = 0, hole_max = 0, hole_total = 0,
                                   hole_first_ok = 0, hole_first_ok_size = 0;
                unsigned hole_count = 0;
                memset( top, 0, sizeof(top) );
                memset( dirty_by_tag, 0, sizeof(dirty_by_tag) );
                memset( res_by_tag, 0, sizeof(res_by_tag) );
                memset( swap_by_tag, 0, sizeof(swap_by_tag) );
                memset( band_dirty, 0, sizeof(band_dirty) );
                memset( band_res, 0, sizeof(band_res) );
                struct timespec pm_t0, pm_t1;   /* madeira-bcd: what the walk costs */
                clock_gettime( CLOCK_MONOTONIC, &pm_t0 );
                for (;;)
                {
                    vm_region_submap_info_data_64_t info;
                    mach_msg_type_number_t icnt = VM_REGION_SUBMAP_INFO_COUNT_64;
                    unsigned long long d;
                    if (mach_vm_region_recurse( mach_task_self(), &raddr, &rsize, &rdepth,
                                                (vm_region_recurse_info_t)&info, &icnt ) != KERN_SUCCESS)
                        break;
                    if (info.is_submap) { rdepth++; continue; }
                    if (raddr < 0x1000000000ULL && raddr > hole_prev_end && hole_prev_end)
                    {
                        unsigned long long gap = raddr - hole_prev_end;
                        hole_total += gap;
                        if (gap > hole_max) hole_max = gap;
                        if (gap >= 0x20000) { hole_count++; if (!hole_first_ok) { hole_first_ok = hole_prev_end; hole_first_ok_size = gap; } }
                    }
                    if (raddr + rsize > hole_prev_end) hole_prev_end = raddr + rsize;
                    d = ((unsigned long long)info.pages_dirtied +
                         (unsigned long long)info.pages_swapped_out) << 14;
                    {
                        int b;
                        if (prx && raddr >= prx && raddr < prx + pps)      b = B_POOL_RX;
                        else if (prw && raddr >= prw && raddr < prw + pps) b = B_POOL_RW;
                        else if (raddr < 0x1000000000ULL)                  b = B_HOST_LOW;
                        else if (raddr >= 0x7000000000ULL && raddr < 0x7400000000ULL) b = B_GUEST;
                        else if (raddr >= 0x7400000000ULL && raddr < 0x7c00000000ULL) b = B_PA;
                        else if (raddr >= 0x7c00000000ULL && raddr < 0x8000000000ULL) b = B_FEX;
                        else b = B_OTHER;
                        band_dirty[b] += d;
                        band_res[b] += (unsigned long long)info.pages_resident << 14;
                        if (b == B_HOST_LOW || b == B_PA)
                        {
                            int w = 0, q;
                            for (q = 1; q < 4; q++) if (btop[b][q].dirty < btop[b][w].dirty) w = q;
                            if (d > btop[b][w].dirty)
                            {
                                btop[b][w].base = raddr; btop[b][w].size = rsize; btop[b][w].dirty = d;
                                btop[b][w].tag = info.user_tag; btop[b][w].prot = info.protection;
                            }
                        }
                    }
                    if (info.user_tag < 256)
                    {
                        res_by_tag[info.user_tag]  += (unsigned long long)info.pages_resident << 14;
                        swap_by_tag[info.user_tag] += (unsigned long long)info.pages_swapped_out << 14;
                    }
                    /* ml569: does the HOST MALLOC HEAP overlap memory we reserved?
                     *
                     * ml565-568 established the malloc BRK is real corruption, not OOM
                     * (830-950 MB free, vm_allocate succeeds at the trap), and that the
                     * trapping CALLER varies — sometimes alloc_object, sometimes wholly
                     * inside libsystem_malloc — so whoever allocates next is just the
                     * unlucky one, not the culprit. What does correlate, perfectly across
                     * 14 runs, is FOOTPRINT: traps at 3145-3339 MB, never at 3015-3114.
                     *
                     * A wild write to a roughly fixed address explains that: inert while
                     * the malloc heap is too small to reach it, fatal once the heap grows
                     * over it. The cheapest version of that story is that WE map on top of
                     * libmalloc's heap. The log already shows the converse happening
                     * ([pool-va] ... INSIDE RX pool <== foreign map/unmap), so the address
                     * spaces demonstrably interleave.
                     *
                     * Darwin tags malloc's own regions, so overlap is directly checkable.
                     * Prints the first few offenders AND a per-cycle count, so "no overlap"
                     * is a real negative rather than silence. */
                    {
                        unsigned t = info.user_tag;
                        int is_malloc = (t == 1 || t == 2 || t == 3 || t == 4 ||
                                         t == 6 || t == 7 || t == 8 || t == 9 || t == 11);
                        const char *bn = NULL;
                        if (prx && raddr >= prx && raddr < prx + pps)      bn = "JIT-POOL-RX";
                        else if (prw && raddr >= prw && raddr < prw + pps) bn = "JIT-POOL-RW";
                        else if (raddr < 0x1000000000ULL)                  bn = NULL; /* normal host */
                        else if (raddr >= 0x7000000000ULL && raddr < 0x7400000000ULL) bn = "GUEST";
                        else if (raddr >= 0x7400000000ULL && raddr < 0x7c00000000ULL) bn = "CEF-PA-POOL";
                        else if (raddr >= 0x7c00000000ULL && raddr < 0x8000000000ULL) bn = "FEX-HOST";
                        if (is_malloc && bn)
                        {
                            static unsigned long ovl;
                            if (++ovl <= 12)
                                dprintf(2, "[heap-overlap] MALLOC region 0x%llx+0x%llx tag=%u sits in "
                                           "the %s band — we and libmalloc share this VA rev=ml569\n",
                                        (unsigned long long)raddr, (unsigned long long)rsize, t, bn);
                        }
                    }
                    if (d)
                    {
                        total_dirty += d;
                        if (info.user_tag < 256) dirty_by_tag[info.user_tag] += d;
                        /* keep the 12 dirtiest regions (replace current min) */
                        for (ti = 0, tj = 0; ti < 12; ti++)
                            if (top[ti].dirty < top[tj].dirty) tj = ti;
                        if (d > top[tj].dirty)
                        {
                            top[tj].base = raddr; top[tj].size = rsize; top[tj].dirty = d;
                            top[tj].res = (unsigned long long)info.pages_resident << 14;
                            top[tj].swap = (unsigned long long)info.pages_swapped_out << 14;
                            top[tj].tag = info.user_tag;
                        }
                    }
                    raddr += rsize;
                    if (++regions > 200000) { dprintf(2, "[phys-map] TRUNCATED at %u regions\n", regions); break; }
                }
                clock_gettime( CLOCK_MONOTONIC, &pm_t1 );
                dprintf(2, "[phys-map] rev=ml359 cycle=%u regions=%u total_dirty=%llu MB (walk %ld ms; next in %u "
                           "cycles, MADEIRA_WARMER_SWEEP_CYCLES)\n",
                        cycle, regions, total_dirty >> 20,
                        (long)((pm_t1.tv_sec - pm_t0.tv_sec) * 1000 + (pm_t1.tv_nsec - pm_t0.tv_nsec) / 1000000),
                        ios_warmer_sweep_cycles());
                for (ti = 0; ti < 12; ti++)
                {
                    if (!top[ti].dirty) continue;
                    dprintf(2, "[phys-map]   0x%llx+0x%llx dirty=%llu MB res=%llu MB swap=%llu MB tag=%u\n",
                            top[ti].base, top[ti].size, top[ti].dirty >> 20,
                            top[ti].res >> 20, top[ti].swap >> 20, top[ti].tag);
                }
                for (ti = 0; ti < 256; ti++)
                    if ((dirty_by_tag[ti] >> 20) >= 32 || (res_by_tag[ti] >> 20) >= 32 ||
                        (swap_by_tag[ti] >> 20) >= 32)
                        dprintf(2, "[phys-map]   tag %u totals rev=ml677 dirty=%llu MB res=%llu MB swap=%llu MB\n",
                                ti, dirty_by_tag[ti] >> 20, res_by_tag[ti] >> 20, swap_by_tag[ti] >> 20);
                dprintf(2, "[phys-map] bands rev=ml360 (dirty/res MB):");
                for (ti = 0; ti < B_MAX; ti++)
                    dprintf(2, " %s=%llu/%llu", band_name[ti],
                            band_dirty[ti] >> 20, band_res[ti] >> 20);
                dprintf(2, "\n");
                for (ti = 0; ti < B_MAX; ti++)
                {
                    int q;
                    if (ti != B_HOST_LOW && ti != B_PA) continue;
                    dprintf(2, "[phys-map]   ml1074 %s dirtiest:", band_name[ti]);
                    for (q = 0; q < 4; q++) if (btop[ti][q].dirty)
                        dprintf(2, " 0x%llx+0x%llx=%lluMB(tag%u,prot%u)", btop[ti][q].base, btop[ti][q].size,
                                btop[ti][q].dirty >> 20, btop[ti][q].tag, btop[ti][q].prot);
                    dprintf(2, "\n");
                }
                dprintf(2, "[holes<64G] rev=ml894 free=%llu MB largest=%llu MB gaps>=128K=%u lowest=0x%llx+0x%llx (cycle=%u)\n",
                        hole_total >> 20, hole_max >> 20, hole_count, hole_first_ok, hole_first_ok_size, cycle);
                { extern void ios_swap_stats_line( void ); ios_swap_stats_line(); }   /* ml1077 */
                /* ml1071: NATIVE HEAP CENSUS. The `pa` band (0x74..0x7c, where libmalloc
                 * puts its regions) held 784 MB dirty at the last jetsam and nothing
                 * says whose it is: LLVM (4,000+ in-process shader compiles), Wine's
                 * unix side, the D3D12 runtime, madsync, audio rings. libmalloc knows
                 * per zone. */
                {
                    vm_address_t *zones = NULL; unsigned int nz = 0, zi;
                    if (malloc_get_all_zones( mach_task_self(), NULL, &zones, &nz ) == KERN_SUCCESS && zones)
                    {
                        char line[700]; int n = 0;
                        for (zi = 0; zi < nz && n < (int)sizeof(line) - 80; zi++)
                        {
                            malloc_zone_t *z = (malloc_zone_t *)zones[zi];
                            malloc_statistics_t st;
                            const char *nm;
                            if (!z) continue;
                            memset( &st, 0, sizeof(st) );
                            malloc_zone_statistics( z, &st );
                            nm = malloc_get_zone_name( z );
                            if (st.size_in_use < (4u << 20) && st.size_allocated < (16u << 20)) continue;
                            n += snprintf( line + n, sizeof(line) - n, " %s:used=%zuMB/alloc=%zuMB/blocks=%u",
                                           nm ? nm : "?", st.size_in_use >> 20, st.size_allocated >> 20, st.blocks_in_use );
                        }
                        dprintf( 2, "[malloc-zones] ml1071 %u zones (>=4 MB in use shown):%s\n", nz, n ? line : " (none)" );
                        /* ml1073: the array is libmalloc's OWN zone table, not a copy. ml1071
                         * vm_deallocate'd it and the next malloc in the process faulted on the
                         * freed metadata page (crash during desktop boot, ph-rdr39). Never free it. */
                    }
                }
            }
        }
        /* ml668: ADAPTIVE CADENCE. At a flat 2s the run kept ending BETWEEN
         * samples during texture upload, so every "peak" we quoted was a stale
         * lower bound -- ml664 reported 2733MB when loading was still climbing.
         * Once the footprint is within ~1.2GB of the 4096MB jetsam limit, drop
         * to 250ms so the terminal burst is actually captured. The expensive
         * region/band accounting above stays on the slow cycle; only the cheap
         * task_info() footprint line runs at the fast rate. */
        {
            extern unsigned long long ios_last_footprint_mb;
            extern int ios_fast_footprint;
            usleep( (ios_fast_footprint || ios_last_footprint_mb >= 2400) ? 250000 : 2000000 );
        }
    }
    return NULL;
}

/* task #34: WAS THE POOL COPY EVER CORRECT?
 *
 * Every diagnosis so far assumed the copy succeeded and something destroyed it
 * afterwards — four hypotheses, none confirmed. The untested alternative is
 * that stores into the pool are silently dropped, so a REUSED range simply
 * keeps whatever it held before (stale bytes, or zeros once the previous owner
 * was swept). That would explain the reuse correlation directly, and it fits
 * what the faults actually show: zeros in the instruction stream and the nls
 * poison 0xdead1 still intact at offsets the copy should have overwritten.
 *
 * Read back through the RX alias immediately after the memcpy and compare
 * against the source. Sampled (64 points) rather than a full compare, because
 * this runs for every module copy of every pseudo-process. A mismatch here
 * means the write path is at fault; a clean result means the content is
 * destroyed later and the writer is still at large. */
static void ios_jit_verify_copy( const char *src, const char *rx, size_t size,
                                 const char *name, size_t offset, int reused )
{
    const int SAMPLES = 64;
    size_t step = size / SAMPLES;
    size_t i, first_bad = 0;
    int bad = 0, zero = 0, checked = 0;

    if (!src || !rx || size < 8) return;
    if (step < 8) step = 8;

    for (i = 0; i + 8 <= size; i += step)
    {
        uint64_t a, b;
        memcpy( &a, src + i, 8 );
        memcpy( &b, rx  + i, 8 );
        checked++;
        if (a != b)
        {
            if (!bad) first_bad = i;
            bad++;
            if (!b) zero++;
        }
    }
    if (bad)
        dprintf(2, "[copy-verify] MISMATCH %s pool_off=0x%lx size=0x%lx: %d/%d samples differ (%d read ZERO), first +0x%lx — THE COPY DID NOT STICK [%s]\n",
                name ? name : "?", (unsigned long)offset, (unsigned long)size,
                bad, checked, zero, (unsigned long)first_bad,
                reused ? "REUSED range" : "virgin bump");
}

/* task #35 demand census — see NtAllocateVirtualMemory. One line per jumbo
 * reserve, carrying enough context to tell a retry from a new reservation. */
static unsigned          ios_jumbo_seq;
static unsigned long long ios_jumbo_last_ms;
static size_t            ios_jumbo_granted;      /* bytes actually handed out */
static unsigned          ios_jumbo_ok, ios_jumbo_fail;

static unsigned long long ios_now_ms( void )
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    return (unsigned long long)ts.tv_sec * 1000ull + (unsigned long long)(ts.tv_nsec / 1000000);
}


/* ml144 POOL ATTRIBUTION — which GUEST module is asking?
 *
 * CEF requests FOUR 16GB pools but PartitionAddressSpace::Init() reserves only
 * ONE plain (Regular) + ONE guarded (BRP). Two of each means Init() runs twice,
 * and ml144 ruled out the easy explanations: exactly one libcef.dll copy, one
 * chrome_elf.dll copy, and all eight reserves on the SAME peb and wtid. What is
 * left is that libcef.dll and chrome_elf.dll each statically link PartitionAlloc
 * and each initialise it on the loading thread — in real Chrome chrome_elf
 * exports the allocator and the main module defers to it, and that linkage may
 * not survive our loader.
 *
 * The caller is guest x86-64 running under FEX, so a native stack scan finds
 * thunks and IAT slots, not the requester (that mistake cost a run earlier).
 * Read FEX's live guest RIP instead — TEB+0x1788 -> CPUArea+0x30 -> state,
 * RIP at +0x18, the same chain the fault handler uses for [x86_live]. Print it
 * raw; resolving it against the [jit-pool] image table offline is exact and
 * needs no struct-layout assumptions here. */
static uint64_t ios_guest_rip_now(void)
{
    TEB *teb = NtCurrentTeb();
    void *cpuarea, *st;

    if (!teb) return 0;
    cpuarea = *(void **)((char *)teb + 0x1788);
    if ((uintptr_t)cpuarea < 0x10000) return 0;
    st = *(void **)((char *)cpuarea + 0x30);
    if ((uintptr_t)st < 0x10000) return 0;
    return ((uint64_t *)st)[0x18 / 8];
}

/* ml145: the above returns the NATIVE caller at a syscall boundary — every
 * reserve reported the same value and it resolved to kernelbase.dll+0x40124,
 * i.e. inside VirtualAlloc itself. State.RIP is only the guest RIP when the
 * fault happened inside JIT'd guest code; on an EC transition the guest context
 * is saved instead. init_thread_stack's own log gives the layout:
 *   ChpeV2CpuAreaInfo=0x15c410000 ... ContextAmd64=0x15c410050
 * so the x64 CONTEXT sits at CPUArea+0x50, and CONTEXT_AMD64.Rip is at +0xF8.
 * Read that for the actual guest RIP, and keep the native one too — the pair
 * tells us both WHO called and from WHERE. */
static uint64_t ios_guest_ctx_rip(void)
{
    TEB *teb = NtCurrentTeb();
    void *cpuarea;

    if (!teb) return 0;
    cpuarea = *(void **)((char *)teb + 0x1788);
    if ((uintptr_t)cpuarea < 0x10000) return 0;
    return *(uint64_t *)((char *)cpuarea + 0x50 + 0xF8);
}


/* ml147 POOL OWNERSHIP BY SEARCH — the unambiguous attribution.
 *
 * Two register-based attempts both returned NATIVE addresses rather than the
 * guest RIP (State.RIP gave kernelbase+0x40124, the caller inside VirtualAlloc;
 * CPUArea+0x50+0xF8 gave kernelbase+0x7c050). Interesting but not decisive.
 *
 * PartitionAlloc stores each granted pool base in its OWN globals, so if two PA
 * instances exist their pool bases live in two DIFFERENT modules' .data. Search
 * the module copies for the addresses we actually handed out: whichever module
 * holds them owns that pool. No register layout, no guest/native ambiguity.
 * Runs once, only when a jumbo reserve fails, and skips .text (a pool base can
 * only be stored in data). */
const char *ios_pe_module_name( const void *image_base, size_t image_size );

static void ios_pool_owner_search( const uint64_t *wanted, unsigned nwanted )
{
    /* ml148: the first cut matched 823 times across every module, because the
     * pool bases are "small int followed by zeros" — an 8-byte read at PE
     * offset 0x38 of a header whose e_lfanew is 0x78 IS 0x7800000000. Every
     * module hit at +0x38 for exactly that reason.
     *
     * Require a CLUSTER instead: two DIFFERENT pool values within 512 bytes.
     * PartitionAddressSpace keeps regular_pool_base_address_ and
     * brp_pool_base_address_ adjacent in one struct, so a real owner shows both;
     * a PE header cannot fake two distinct pool-shaped values side by side.
     * Also skip the first page (headers) outright. */
    unsigned mi, w;

    for (mi = 0; mi < ios_jit_mapping_count; mi++)
    {
        uintptr_t jb = (uintptr_t)ios_jit_mappings[mi].jit_base;
        size_t sz = ios_jit_mappings[mi].size;
        size_t t0 = ios_jit_mappings[mi].text_offset, t1 = t0 + ios_jit_mappings[mi].text_size;
        const uint64_t *p = (const uint64_t *)jb;
        size_t off, last_off = 0;
        uint64_t last_val = 0;
        int reported = 0;

        if (!jb || !sz || !ios_jit_mappings[mi].pe_base) continue;
        for (off = 0x1000; off + 8 <= sz && reported < 4; off += 8)
        {
            uint64_t v;
            if (ios_jit_mappings[mi].text_size && off >= t0 && off < t1) continue;
            v = p[off / 8];
            for (w = 0; w < nwanted; w++)
                if (v == wanted[w])
                {
                    if (last_val && v != last_val && off - last_off <= 512)
                    {
                        dprintf(2, "[pool-owner] CLUSTER in %s: 0x%llx at +0x%lx and 0x%llx at +0x%lx\n",
                                ios_pe_module_name( ios_jit_mappings[mi].pe_base,
                                                    ios_jit_mappings[mi].size ),
                                (unsigned long long)last_val, (unsigned long)last_off,
                                (unsigned long long)v, (unsigned long)off);
                        reported++;
                    }
                    last_val = v; last_off = off;
                    break;
                }
        }
    }
}


/* ml151 LAZY POOL RESERVATION (Tier 2, first cut).
 *
 * MEASURED: at the moment PartitionAlloc needs all four 16GB pools reserved, it
 * has committed essentially NOTHING — [bigres-use] showed 0MB in two pools and
 * <1MB in the third across 24 calls. The reservation at Init() is pure
 * address-space bookkeeping, so a pool does not need to be backed to be
 * accepted; it only needs the aligned base PA asked for.
 *
 * That matters because the arithmetic is otherwise unwinnable: four pools want
 * 64GB of RANGE, the usable window is ~64GB, and furniture needs ~14GB of it.
 * Treating a reservation as if it consumed real space is what made this look
 * impossible.
 *
 * FIRST CUT, deliberately minimal: when every real placement for a jumbo
 * reserve fails, hand PA a 16GB-aligned slot that no pool has taken and record
 * the range as SOFT — no backing. Commits land in NtAllocateVirtualMemory,
 * which we own, so there is no fault handling: materialise the sub-range there.
 *
 * KNOWN RISK, accepted for now and instrumented rather than hidden: the only
 * free aligned slot (0x7000000000) spans the furniture window, so a later PA
 * commit can land where furniture already lives. We do NOT fence furniture out
 * of it — that window is the only place furniture can go. Instead every commit
 * into a soft range is checked against the kernel map first and a collision is
 * reported loudly. PA bumps upward from a pool base and committed ~0% at Init,
 * so the margin should be large; if [soft-pool] COLLISION appears, this design
 * needs the full own-and-broker-the-window treatment before it can be trusted. */
#define IOS_SOFT_MAX 8
static struct { uint64_t base, size, committed; unsigned commits, collisions; unsigned cage; } ios_soft[IOS_SOFT_MAX];
static unsigned ios_soft_n;

/* ml433 (#72): the V8/cppgc cage holdback.
 *
 * Single-process CEF means exactly ONE process-wide cppgc/V8 cage: an 8GB
 * reservation the guest requires 8GB-ALIGNED. On Windows' 128TB that is free;
 * in our 64GB usable band the only 8GB-aligned stretch outside the PA pool
 * slots is [0x7200000000, 0x7400000000), and top-down furniture placement
 * fills its tail with DLL image copies long before CEF asks (~85s in). The
 * guest's fallback — reserve size+align-64K = 16383MB and trim — needs a 16GB
 * gap that cannot exist here, so PA retries three times and abort()s the
 * webhelper (ml432, one minute after the first-ever BrowserReady).
 *
 * So reserve the stretch at boot, before any furniture can land in it, and
 * hand it to the first 8GB jumbo ask. It deliberately stops 64KB short of
 * 0x7400000000: that page is the PA guard pool's home base (guard-style base
 * = slot - 64KB, see the jumbo walk), which stays REAL and untouched. The
 * guest is told it got the full 8GB — the top 64KB overlaps only PA's
 * never-committed forbidden zone, and a stray commit there is absorbed by an
 * ios_soft tail entry. */
/* madeira-bcd: 0x7a00000000 in Social Club layout 2 (IOS_SC2_CAGE_BASE). */
static ULONG_PTR ios_cage_base = 0x7200000000ULL;
#define IOS_CAGE_BASE      ios_cage_base
#define IOS_CAGE_REAL_SIZE 0x1ffff0000ULL   /* 8GB - 64KB */
static int ios_cage_holdback_live;
/* Set only after the lower window is carved. The unregistered PROT_NONE
 * remainder stays ours; the original whole-cage grant is then disabled. */
static int ios_cage_window_tail_live;

static int ios_soft_find( uint64_t addr )
{
    /* ml434: smallest matching range wins — the 4GB soft cages sit INSIDE the
     * 16GB soft pools' claimed ranges, and first-match would shadow them. */
    unsigned i;
    int best = -1;
    for (i = 0; i < ios_soft_n; i++)
        if (addr >= ios_soft[i].base && addr < ios_soft[i].base + ios_soft[i].size
            && (best < 0 || ios_soft[i].size < ios_soft[best].size))
            best = (int)i;
    return best;
}

/* Is this 16GB-aligned slot free of any pool we already handed out? */
static int ios_soft_slot_taken( uint64_t slot )
{
    unsigned i;
    for (i = 0; i < ios_soft_n; i++)
        if (ios_soft[i].base == slot) return 1;
    return 0;
}

static void ios_soft_report( const char *why )
{
    unsigned i;
    for (i = 0; i < ios_soft_n; i++)
        dprintf(2, "[soft-pool] 0x%llx +%lluMB committed=%lluMB in %u calls, %u collisions (%s)\n",
                (unsigned long long)ios_soft[i].base,
                (unsigned long long)(ios_soft[i].size >> 20),
                (unsigned long long)(ios_soft[i].committed >> 20),
                ios_soft[i].commits, ios_soft[i].collisions, why);
}

static void ios_bigres_note( void *base, size_t size );   /* defined below */

static int ios_safe_read64( uint64_t addr, uint64_t *out );
static void ios_jumbo_census( void *hint, size_t size, void *result, unsigned st )
{
    /* ml131: report the 512MB-reservation census alongside every jumbo call —
     * the warmer-tick schedule fired only at cycle 1, before Steam had made any
     * of them, so the one number that matters never appeared. */
    ios_bigres_report( st ? "jumbo fail" : "jumbo ok" );
    unsigned long long now = ios_now_ms();
    unsigned long long gap = ios_jumbo_last_ms ? now - ios_jumbo_last_ms : 0;

    ios_jumbo_last_ms = now;
    static uint64_t granted_bases[8];
    static unsigned granted_n;
    static int owner_searched;

    if (st) ios_jumbo_fail++;
    else  { ios_jumbo_ok++; ios_jumbo_granted += size;
            /* ml150: track how much of each GRANTED POOL is ever COMMITTED.
             * This is the number that decides whether lazy reservation can beat
             * the 4-pool wall. PA needs 4 x 16GB of ADDRESS RANGE, but if it
             * commits only a fraction of each, the untouched remainder is dead
             * space we currently pay full price for — and furniture could live
             * there instead. Steam's own reservations came in at 7-8%
             * ([bigres-use]); if the pools are similar, four pools plus ~14GB of
             * furniture fit in the 64GB window and the wall is an accounting
             * artifact rather than a hard limit. Reuse the same commit
             * attribution table. */
            if (result) ios_bigres_note( result, size );
            if (granted_n < 8 && result)
            {
                granted_bases[granted_n++] = (uint64_t)(uintptr_t)result;
                /* a guard-style reserve returns the FORBIDDEN ZONE base; PA
                 * records the pool proper, 64KB higher. Look for both. */
                if (granted_n < 8 && (size & 0xffff) == 0x10000 - 0)
                    granted_bases[granted_n++] = (uint64_t)(uintptr_t)result + 0x10000;
            } }
    if (st && granted_n && !owner_searched)
    {
        owner_searched = 1;
        dprintf(2, "[pool-owner] searching %u module copies for %u granted pool bases...\n",
                ios_jit_mapping_count, granted_n);
        ios_pool_owner_search( granted_bases, granted_n );
        dprintf(2, "[pool-owner] search done\n");
    }

    /* ml135: log the PEB and wine tid too. PA's Init() reserves exactly ONE
     * plain 16GB (Regular) + ONE guarded 16GB+forbidden-zone (BRP); we observe
     * TWO of each, which is the signature of Init() running twice. If the two
     * pairs carry DIFFERENT PEBs it is two libcef copies in our shared address
     * space (a pseudo-process artefact we can fix by properly enforcing
     * single-process); if they share a PEB it is four distinct pool TYPES and
     * the size is a Chromium compile-time constant we cannot change. Those two
     * answers have completely different fixes, so print the discriminator. */
    dprintf(2, "[jumbo#%u] +%llums tid=%lx wtid=%04x peb=%p nrip=0x%llx grip=0x%llx size=0x%lx (%lu MB) hint=%p -> %p st=0x%x | granted=%lu MB ok=%u fail=%u\n",
            ++ios_jumbo_seq, gap, (unsigned long)(uintptr_t)pthread_self(),
            NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0,
            NtCurrentTeb() ? NtCurrentTeb()->Peb : NULL,
            (unsigned long long)ios_guest_rip_now(),
            (unsigned long long)ios_guest_ctx_rip(),
            (unsigned long)size, (unsigned long)(size >> 20), hint, result, st,
            (unsigned long)(ios_jumbo_granted >> 20), ios_jumbo_ok, ios_jumbo_fail);
    /* madeira-bcd [jumbo-tls]: the main image's allocator stack at this point
     * (God of War keeps it in its TLS[0] block: index at +0xc, table at +0xf0).
     * GoW pushes its first heap before it reserves the arena this call makes;
     * the build 237 fault found the index at 0 and table[0] empty. Also reads
     * where that push would land if the index were zero-extended instead of
     * sign-extended (block + 0x8000000f0). */
    if (ios_jumbo_seq <= 4 && NtCurrentTeb())
    {
        uint64_t arr = 0, blk = 0, w8 = 0, t0 = 0, t1 = 0, zx = 0;
        void **blocks = NtCurrentTeb()->ThreadLocalStoragePointer;
        if (blocks && !ios_safe_read64( (uint64_t)(uintptr_t)blocks, &arr ) && arr)
        {
            blk = arr;
            int ok8 = !ios_safe_read64( blk + 0x8, &w8 );
            int ok0 = !ios_safe_read64( blk + 0xf0, &t0 );
            int ok1 = !ios_safe_read64( blk + 0xf8, &t1 );
            int okz = !ios_safe_read64( blk + 0x8000000f0ULL, &zx );
            dprintf( 2, "[jumbo-tls] #%u tls0=%p +0x8=%s0x%llx (index %d) table[0]=%s0x%llx table[1]=%s0x%llx | zext-target %p=%s0x%llx\n",
                     ios_jumbo_seq, (void *)(uintptr_t)blk, ok8 ? "" : "?", (unsigned long long)w8, (int)(w8 >> 32),
                     ok0 ? "" : "?", (unsigned long long)t0, ok1 ? "" : "?", (unsigned long long)t1,
                     (void *)(uintptr_t)(blk + 0x8000000f0ULL), okz ? "" : "unmapped ", (unsigned long long)zx );
        }
    }
}


/* ml130 IS THE GUEST'S 12GB ACTUALLY USED?
 *
 * The 512MB reserves are steam.exe's own: type=0x2000 is MEM_RESERVE with no
 * MEM_TOP_DOWN, and FEXCore::Allocator::VirtualAlloc unconditionally ORs in
 * MEM_TOP_DOWN, so these cannot come from FEX. 2 x 512MB per guest thread, 12+
 * threads = 12+GB of pure reservation. On Windows' 128TB that is free; in our
 * 63GB it is the entire third-pool deficit.
 *
 * Whether we can do anything about it hinges on ONE fact: does Steam ever
 * COMMIT inside these ranges, or is it reserve-and-never-touch? If commits are
 * a small fraction, the reservations are slack and a lazy/shrunk reservation
 * becomes thinkable. If Steam commits heavily, the demand is real and two pools
 * is the ceiling until CEF itself is made to want less. Record each range and
 * attribute every MEM_COMMIT that lands inside one. */
/* 48 -> 256: the release of a range is also what counts a reserve->release cycle
 * (ios_reserve_cycle_note), and Steam alone keeps 2 x 512MB per thread here, so a
 * full ledger left a placement livelock uncounted. Any guest thread reserves,
 * commits and frees, so the ledger has its own lock. */
#define IOS_BIGRES_MAX 256
static struct { uint64_t base, size, committed; unsigned commits; } ios_bigres_tab[IOS_BIGRES_MAX];
static unsigned ios_bigres_cnt;
static pthread_mutex_t ios_bigres_lock = PTHREAD_MUTEX_INITIALIZER;

static void ios_bigres_note( void *base, size_t size )
{
    static int full_logged;
    int full;

    if (!base) return;
    pthread_mutex_lock( &ios_bigres_lock );
    full = ios_bigres_cnt >= IOS_BIGRES_MAX;
    if (!full)
    {
        ios_bigres_tab[ios_bigres_cnt].base = (uint64_t)(uintptr_t)base;
        ios_bigres_tab[ios_bigres_cnt].size = size;
        ios_bigres_tab[ios_bigres_cnt].committed = 0;
        ios_bigres_tab[ios_bigres_cnt].commits = 0;
        ios_bigres_cnt++;
    }
    pthread_mutex_unlock( &ios_bigres_lock );
    if (full && !full_logged)
    {
        full_logged = 1;
        dprintf(2, "[bigres] ledger full (%u ranges): later big reserves are not tracked, nor their reserve->release cycles\n",
                IOS_BIGRES_MAX);
    }
}

static void ios_bigres_commit( void *addr, size_t size )
{
    uint64_t a = (uint64_t)(uintptr_t)addr;
    unsigned i;
    pthread_mutex_lock( &ios_bigres_lock );
    for (i = 0; i < ios_bigres_cnt; i++)
        if (a >= ios_bigres_tab[i].base && a < ios_bigres_tab[i].base + ios_bigres_tab[i].size)
        {
            ios_bigres_tab[i].committed += size;
            ios_bigres_tab[i].commits++;
            break;
        }
    pthread_mutex_unlock( &ios_bigres_lock );
}

/* ml435 (#73): FEX-band span lifecycle census. ml434 filled the band solid
 * (465 views, 86 failed 64MB scans -> code-buffer mprotect failures -> Crashpad)
 * with only ~52 of 109 created threads still alive — the discriminator between
 * "rpmalloc heaps recycle but demand outgrew 16GB" and "exited threads' spans
 * leak" is the ALLOC vs FREE count for >=16MB band regions. Pairs with the
 * [thr-term] probes in xtajit64 (same rev). */
static unsigned ios_span_alloc_n, ios_span_free_n;
static void ios_span_census( void *base, size_t size, int is_free )
{
    uintptr_t a = (uintptr_t)base;
    unsigned n;
    if (a < 0x7c00000000ULL || a >= 0x8000000000ULL || size < 0x1000000) return;
    n = is_free ? ++ios_span_free_n : ++ios_span_alloc_n;
    if (n <= 40 || !(n & 15))
        dprintf(2, "[span-census] %s #%u %p+0x%lx tid=%04x live=%d rev=ml435\n",
                is_free ? "FREE" : "ALLOC", n, base, (unsigned long)size,
                NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0,
                (int)ios_span_alloc_n - (int)ios_span_free_n);
}

/* iOS-Madeira ml462 (#77): reserve->release CYCLE tracker. The ml461 run died
 * of a guest placement livelock: V8's CodeRange (512MB, must sit within jump
 * distance of libcef's embedded builtins) reserved, got granted, REJECTED the
 * location, released, and retried forever — ping-ponging on the same two
 * kernel-pick addresses while the armed steer valve dutifully spilled the
 * churn into the FEX band until the process starved (2,243 rpmalloc spans,
 * 15.5GB reserved). A same-(tid,size) big reserve that has been GRANTED and
 * immediately RELEASED dozens of times will never converge — after the cap,
 * deny it outright so the guest takes its own named failure path instead of
 * spinning. Keyed on (tid, size to 16MB granularity).
 *
 * Exact key in a 64-slot table. It was 8 slots chosen by (tid ^ size16m) & 7,
 * evict-on-collision, and Wine's tids are multiples of 4 (server/process.c
 * ptid_from_index): for one size every thread fell in one of 2 slots, so two
 * threads cycling in turn reset each other's count to 1 and the deny never
 * fired. A key quiet for IOS_RESCYCLE_IDLE_MS starts over (the livelock cycles
 * back to back; an exact table would otherwise keep a thread's lifetime count),
 * except one already at IOS_RESCYCLE_DENY, which stays denied as before; a full
 * table replaces its least recently cycled key that is not denied. Any guest
 * thread frees memory, so the table has its own lock. */
#define IOS_RESCYCLE_SLOTS 64
#define IOS_RESCYCLE_IDLE_MS 10000ull
#define IOS_RESCYCLE_DENY 32
static struct { unsigned tid; uint64_t size16m; unsigned cycles; unsigned long long last_ms; } ios_rescycle[IOS_RESCYCLE_SLOTS];
static pthread_mutex_t ios_rescycle_lock = PTHREAD_MUTEX_INITIALIZER;

/* A slot is live while it has cycles and was cycled recently, or is denied. */
static int ios_rescycle_live( unsigned i, unsigned long long now )
{
    return ios_rescycle[i].cycles &&
           (ios_rescycle[i].cycles >= IOS_RESCYCLE_DENY || now - ios_rescycle[i].last_ms <= IOS_RESCYCLE_IDLE_MS);
}

static void ios_reserve_cycle_note( unsigned tid, uint64_t size )
{
    uint64_t s16 = size >> 24;
    unsigned long long now = ios_now_ms();
    unsigned i, slot = IOS_RESCYCLE_SLOTS;

    pthread_mutex_lock( &ios_rescycle_lock );
    for (i = 0; i < IOS_RESCYCLE_SLOTS; i++)
        if (ios_rescycle[i].cycles && ios_rescycle[i].tid == tid && ios_rescycle[i].size16m == s16)
        {
            if (!ios_rescycle_live( i, now )) ios_rescycle[i].cycles = 0;
            ios_rescycle[i].cycles++;
            ios_rescycle[i].last_ms = now;
            pthread_mutex_unlock( &ios_rescycle_lock );
            return;
        }
    for (i = 0; i < IOS_RESCYCLE_SLOTS; i++)
    {
        if (!ios_rescycle_live( i, now )) { slot = i; break; }
        if (ios_rescycle[i].cycles >= IOS_RESCYCLE_DENY) continue;
        if (slot == IOS_RESCYCLE_SLOTS || ios_rescycle[i].last_ms < ios_rescycle[slot].last_ms) slot = i;
    }
    if (slot == IOS_RESCYCLE_SLOTS) slot = (unsigned)(now % IOS_RESCYCLE_SLOTS);   /* all 64 denied */
    ios_rescycle[slot].tid = tid;
    ios_rescycle[slot].size16m = s16;
    ios_rescycle[slot].cycles = 1;
    ios_rescycle[slot].last_ms = now;
    pthread_mutex_unlock( &ios_rescycle_lock );
}
static unsigned ios_reserve_cycle_count( unsigned tid, uint64_t size )
{
    uint64_t s16 = size >> 24;
    unsigned long long now = ios_now_ms();
    unsigned i, cycles = 0;

    pthread_mutex_lock( &ios_rescycle_lock );
    for (i = 0; i < IOS_RESCYCLE_SLOTS; i++)
        if (ios_rescycle[i].cycles && ios_rescycle[i].tid == tid && ios_rescycle[i].size16m == s16)
        {
            if (ios_rescycle_live( i, now )) cycles = ios_rescycle[i].cycles;
            break;
        }
    pthread_mutex_unlock( &ios_rescycle_lock );
    return cycles;
}

/* ml433 (#72): drop released ranges so [bigres-use] stops double-counting the
 * guest's reserve/free alignment retries — ml432 reported 163,840MB "reserved"
 * when all but ~72GB had already been freed again (the same base regranted up
 * to 9 times). Exact-base match only: jumbo grants are released whole. */
static void ios_bigres_release( void *base )
{
    uint64_t a = (uint64_t)(uintptr_t)base, size = 0;
    unsigned i;
    pthread_mutex_lock( &ios_bigres_lock );
    for (i = 0; i < ios_bigres_cnt; i++)
    {
        if (ios_bigres_tab[i].base != a) continue;
        size = ios_bigres_tab[i].size;
        ios_bigres_tab[i] = ios_bigres_tab[--ios_bigres_cnt];
        break;
    }
    pthread_mutex_unlock( &ios_bigres_lock );
    if (!size) return;
    dprintf(2, "[bigres-free] 0x%llx +%lluMB released rev=ml433\n",
            (unsigned long long)a, (unsigned long long)(size >> 20));
    ios_reserve_cycle_note( NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0, size );
}

static void ios_bigres_report( const char *why )
{
    unsigned i;
    unsigned long long res = 0, com = 0, touched = 0;
    pthread_mutex_lock( &ios_bigres_lock );
    for (i = 0; i < ios_bigres_cnt; i++)
    {
        res += ios_bigres_tab[i].size;
        com += ios_bigres_tab[i].committed;
        if (ios_bigres_tab[i].committed) touched++;
    }
    dprintf(2, "[bigres-use] ranges=%u reserved=%llu MB committed=%llu MB (%llu%%) touched=%llu/%u (%s)\n",
            ios_bigres_cnt, res >> 20, com >> 20,
            res ? (com * 100) / res : 0, touched, ios_bigres_cnt, why);
    for (i = 0; i < ios_bigres_cnt; i++)
        if (ios_bigres_tab[i].size >= 0x40000000ULL)
            dprintf(2, "[bigres-use]   POOL 0x%llx +%lluMB committed=%lluMB (%llu%%) in %u calls\n",
                    ios_bigres_tab[i].base, ios_bigres_tab[i].size >> 20,
                    ios_bigres_tab[i].committed >> 20,
                    ios_bigres_tab[i].size ? (ios_bigres_tab[i].committed * 100) / ios_bigres_tab[i].size : 0,
                    ios_bigres_tab[i].commits);
    for (i = 0; i < ios_bigres_cnt && i < 8; i++)
        dprintf(2, "[bigres-use]   0x%llx +%lluMB committed=%lluMB in %u calls\n",
                ios_bigres_tab[i].base, ios_bigres_tab[i].size >> 20,
                ios_bigres_tab[i].committed >> 20, ios_bigres_tab[i].commits);
    pthread_mutex_unlock( &ios_bigres_lock );
}


/* ml139: verify a freshly-made pool copy's .text is EXECUTABLE, at page
 * granularity. Used by BOTH copy paths — the loader path that builds the first
 * copy of an image and ios_jit_copy_module_for_child that clones it per
 * pseudo-process. ml138 instrumented only the child path and reported nothing,
 * which I could not distinguish from "clean" until the faulting copy turned out
 * to come from the LOADER path (libarm64ecfex pool 0x11f638000). Always print a
 * verdict so silence can never again be mistaken for a pass. */

/* ml153 WINE DEBUG CHANNELS ARE NEVER RESOLVED IN POOL COPIES.
 *
 * struct __wine_debug_channel { unsigned char flags; char name[15]; } ships with
 * flags = 0xff, the "lazy init" sentinel (__WINE_DBCL_INIT = bit 7). The
 * compiled fast path is a bare bit test —
 *     ldrb w8,[x8,#0x40] ; tbz w8,#3,skip     (rpcrt4 NDRCContextUnmarshall)
 * — so an UNRESOLVED channel reads as TRACE-ENABLED, the TRACE block is entered,
 * and all of its arguments are evaluated before anything discovers the channel is
 * actually off. In rpcrt4 that means TRACE("*%p=(%p)...", CContext, *CContext)
 * dereferences the context handle: with a bad handle that is an instant fault,
 * which is exactly the 28x RtlLeaveCriticalSection / NDRCContextUnmarshall
 * cluster that stalls the webhelper's RPC handshake.
 *
 * Wine resolves these lazily per channel, so a module copied before a channel was
 * ever used keeps 0xff forever. Normalise them in the copy: ERR only (0x02),
 * matching WINEDEBUG=err+all. Costs nothing and removes TRACE argument
 * evaluation — and its pointer dereferences — from every copied DLL.
 *
 * Deliberately conservative: only a byte that is EXACTLY 0xff followed by a
 * plausible lowercase channel name and NUL padding to 16 bytes is touched. */
static int ios_jit_init_debug_channels( void *base, size_t image_size,
                                        size_t data_off, size_t data_size )
{
    unsigned char *p = (unsigned char *)base;
    size_t o;
    int fixed = 0;

    if (!base || !data_size || data_off + data_size > image_size) return 0;
    /* ml155: BOUND THE SCAN. The first cut walked every writable section in
     * full, which not only burned iterations but TOUCHED EVERY .data PAGE of
     * every one of ~150 module copies — forcing them all resident instead of
     * faulting lazily. That showed up as a large, user-visible slowdown in
     * desktop and Steam-updater init.
     *
     * Wine builtins keep their __wine_dbch_* table near the start of .data, and
     * the DLLs with multi-megabyte .data (libcef, steamui, shell32) are not Wine
     * builtins and have no channels at all. 256KB is 16 pages per section and
     * caught every channel the unbounded version did (7-44 per module). */
    if (data_size > 0x40000) data_size = 0x40000;
    for (o = data_off; o + 16 <= data_off + data_size; o += 8)
    {
        unsigned char *c = p + o;
        int i, namelen = 0;

        if (c[0] != 0xff) continue;
        for (i = 1; i < 16; i++)
        {
            unsigned char ch = c[i];
            if (ch == 0) break;
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_')) { namelen = -1; break; }
            namelen++;
        }
        if (namelen < 2 || namelen > 14) continue;
        for (i = 1 + namelen; i < 16; i++) if (c[i]) { namelen = -1; break; }
        if (namelen < 0) continue;
        c[0] = 0x02;   /* ERR only — see WINEDEBUG=err+all in WineProcessBridge.m */
        fixed++;
    }
    return fixed;
}

/* ml240: WHICH copy step poisons maxprot?
 *
 * The pool range is CLEAN at hand-out (24/24, all reused=0) yet isolated .text pages come
 * out with max=3 -- EXEC gone from maxprot, unraisable, so mprotect(RX) fails forever and
 * execution there faults NOEXEC. Between hand-out and verification the only memory
 * operations are the memcpy through the RW alias and sys_icache_invalidate on the RX
 * alias, so scanning after each pinpoints the culprit instead of guessing. */
static unsigned ios_jit_scan_nonexec( const char *label, const char *who,
                                      const void *rx_dest, size_t size )
{
    static int scans;
    unsigned bad = 0;
    size_t o;

    for (o = 0; o < size; o += 0x4000)
    {
        mach_vm_address_t want = (mach_vm_address_t)(uintptr_t)((const char *)rx_dest + o), a = want;
        mach_vm_size_t rsz = 0;
        vm_region_basic_info_data_64_t inf;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;

        if (mach_vm_region( mach_task_self(), &a, &rsz, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&inf, &cnt, &obj ) != KERN_SUCCESS) break;
        if (a > want) continue;
        if (!(inf.max_protection & VM_PROT_EXECUTE))
        {
            if (bad == 0 && scans < 30)
                dprintf( 2, "[poison-step] %s: FIRST non-exec at +0x%lx va=%p prot=%x max=%x (%s)\n",
                         label, (unsigned long)o, (void *)(uintptr_t)want,
                         inf.protection, inf.max_protection, who ? who : "?" );
            bad++;
        }
    }
    if (bad && scans < 30) { scans++;
        dprintf( 2, "[poison-step] %s: %u non-exec pages (%s)\n", label, bad, who ? who : "?" ); }
    return bad;
}

static void ios_jit_verify_text_exec( const char *who, const void *rx_dest, size_t image_size )
{
    static unsigned verified;
    size_t o, bad = 0, pages = 0, text_offset = 0, text_size = 0;

    if (!rx_dest || image_size < 0x1000) return;
    /* Derive the executable section from the copy's OWN PE headers so this
     * works from either copy path without needing the caller's locals. */
    {
        const IMAGE_DOS_HEADER *dos = rx_dest;
        const IMAGE_NT_HEADERS *nt;
        const IMAGE_SECTION_HEADER *sec;
        unsigned i;

        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        nt = (const IMAGE_NT_HEADERS *)((const char *)rx_dest + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;
        sec = IMAGE_FIRST_SECTION( nt );
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
            if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                sec[i].Misc.VirtualSize > text_size)
            {
                text_offset = sec[i].VirtualAddress;
                text_size = sec[i].Misc.VirtualSize;
            }
        if (!text_size || text_offset + text_size > image_size) return;

        /* ml156 REVERTED — see ios_jit_init_debug_channels. The normalisation
         * itself worked (7-44 channels per module) but the call site was wrong:
         * it wrote through rx_dest, the EXECUTE alias, instead of the RW alias
         * the copy path uses for content, and any false-positive match corrupts
         * real .data. Result: steam.exe died after 137 unix calls with exec
         * faults back. Re-do it against rw_dest with a stricter pattern before
         * re-enabling. */
    }
    for (o = 0; o < text_size; o += 0x4000)
    {
        mach_vm_address_t want = (mach_vm_address_t)(uintptr_t)((const char *)rx_dest + text_offset + o), a = want;
        mach_vm_size_t rsz = 0;
        vm_region_basic_info_data_64_t inf;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;

        if (mach_vm_region( mach_task_self(), &a, &rsz, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&inf, &cnt, &obj ) != KERN_SUCCESS) break;
        if (a > want) continue;
        pages++;
        if (!(inf.max_protection & VM_PROT_EXECUTE) && bad++ < 6)
            dprintf(2, "[copy-verify] %s BORN NON-EXEC text+0x%lx va=%p prot=%x max=%x\n",
                    who ? who : "?", (unsigned long)o, (void *)(uintptr_t)want,
                    inf.protection, inf.max_protection);
    }
    if (bad)
        dprintf(2, "[copy-verify] %s: %lu of %lu .text pages BORN NON-EXEC (copy @%p)\n",
                who ? who : "?", (unsigned long)bad, (unsigned long)pages, rx_dest);
    else if (verified++ < 25 || (verified % 40) == 0)
        dprintf(2, "[copy-verify] %s: OK, %lu .text pages executable (copy @%p)\n",
                who ? who : "?", (unsigned long)pages, rx_dest);
}


/* ml141 TASK #34 THE REAL FIX — remove the .text/.data page sharing.
 *
 * PE sections are 4KB-aligned but iOS hardware pages are 16KB, so a writable
 * section routinely begins part-way into a page whose earlier bytes are the
 * TAIL OF .text. The RW mprotect that makes .data writable then strips EXECUTE
 * from that page of live code, permanently (mprotect drops it from
 * max_protection on blessed memory). That is task #34: one dead page per
 * module, always 64KB-aligned, fatal only when execution finally reaches it —
 * which is why CEF dies in libarm64ecfex's JIT emitters and Thumper never does.
 *
 * ml141 first tried skipping the shared page (round the RW range UP). That did
 * remove every BORN NON-EXEC page, but a .data STXR into the now-read-only
 * shared page killed steam.exe after 61 unix calls — the SIGBUS store emulator
 * does not cover store-exclusive. Neither side can lose the page.
 *
 * So don't arbitrate: eliminate the overlap. Shift the copy's pool offset so
 * the first writable section lands exactly on a 16KB boundary. Everything below
 * it is RX either way, so .text being page-misaligned costs nothing, and no
 * page is ever both code and data. The shift is a deterministic function of the
 * image, so every copy of a DLL still gets an identical layout — the
 * precondition the .text-sharing/tramp-fold work depends on. */
static size_t ios_jit_data_align_delta( const void *image_base, size_t image_size )
{
    const IMAGE_DOS_HEADER *dos = image_base;
    const IMAGE_NT_HEADERS *nt;
    const IMAGE_SECTION_HEADER *sec;
    unsigned int first_w = 0;
    unsigned i;

    if (!image_base || image_size < 0x1000) return 0;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (const IMAGE_NT_HEADERS *)((const char *)image_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if ((sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) && sec[i].Misc.VirtualSize &&
            (!first_w || sec[i].VirtualAddress < first_w))
            first_w = sec[i].VirtualAddress;
    if (!first_w) return 0;
    return (0x4000 - (first_w & 0x3fff)) & 0x3fff;
}

static void ios_va_gap_probe( const char *why )
{
    const mach_vm_address_t CARVE_LO = 0x1000000000ULL;   /* 64G  */
    const mach_vm_address_t CARVE_HI = 0x7000000000ULL;   /* 448G */
    const mach_vm_address_t VA_TOP   = 0x8000000000ULL;   /* 512G */
    mach_vm_address_t addr = 0, prev_end = 0;
    unsigned long long usable_mb = 0;
    int gaps = 0;

    dprintf(2, "[va-gaps] ==== map walk (%s) ====\n", why);
    while (addr < VA_TOP)
    {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;

        if (mach_vm_region( mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS)
            break;
        if (addr > prev_end)
        {
            mach_vm_size_t gap = addr - prev_end;
            if (gap >= 0x40000000ULL)   /* >= 1GB is all we care about */
            {
                int carve = (prev_end >= CARVE_LO && prev_end < CARVE_HI);
                if (!carve) usable_mb += (unsigned long long)(gap >> 20);
                dprintf(2, "[va-gaps] FREE 0x%llx..0x%llx = %llu MB%s\n",
                        (unsigned long long)prev_end, (unsigned long long)addr,
                        (unsigned long long)(gap >> 20),
                        carve ? "  <-- GPU CARVEOUT, unusable" : "");
                if (++gaps >= 24) { dprintf(2, "[va-gaps] (truncated)\n"); break; }
            }
        }
        prev_end = addr + size;
        addr = prev_end;
    }
    if (prev_end < VA_TOP)
    {
        unsigned long long tail = (unsigned long long)((VA_TOP - prev_end) >> 20);
        usable_mb += tail;
        dprintf(2, "[va-gaps] FREE 0x%llx..0x%llx = %llu MB (top tail)\n",
                (unsigned long long)prev_end, (unsigned long long)VA_TOP, tail);
    }
    dprintf(2, "[va-gaps] ==== end: %llu MB (%llu GB) usable outside the carveout ====\n",
            usable_mb, usable_mb >> 10);
}

#include "virtual_ios_pool.c"   /* address-space probes and holds, the JIT pool and its module copies (IAT sync, aliases, stale-pointer heal) */
#include "virtual_ios_x18.c"   /* the x18 -> TPIDR_EL0 binary patcher */
#endif

struct preload_info
{
    void  *addr;
    size_t size;
};

struct reserved_area
{
    struct list entry;
    void       *base;
    size_t      size;
    /* ml799: FEX_ONLY. The emulator's arena is held in this same list so that
     * freed views return to Wine's free-range machinery like any other reserved
     * range -- but NOTHING generic may allocate from it. Wine's list carried no
     * kind, and map_reserved_area_inner() considers every entry, so adding the
     * 8GB arena untyped would let guest DLLs and unrelated heaps take it: the
     * exact collision the arena exists to end. Generic adds skip these entries
     * entirely (see mmap_add_reserved_area) so an adjacent range can never
     * silently coalesce the type away. */
    unsigned int fex_only;
    /* Madeira: THIN_ONLY. An arena for thin reservations (see ios_thin_reserve):
     * only heads placed by ios_thin_reserve may map here. Same exclusions as
     * fex_only, and generic placement never searches it. */
    unsigned int thin_only;
};

static struct list reserved_areas = LIST_INIT(reserved_areas);

/* ml814: per-request allocation-failure attribution.
 *
 * ml813 used a SHARED GLOBAL for this and it lied immediately: three different
 * requests on two threads all reported one identical 256KB Mach record, because
 * the global was only written by the fixed-map path and never reset. I then
 * read that stale value as the cause. Thread-local and reset at the top of
 * every map_view call, so a record either belongs to THIS request or is absent.
 *
 * stage: 0 none, 1 limits/params, 2 placement scan, 3 anon mmap,
 *        4 vprot table, 5 view struct, 6 fixed-map */
struct ios_af_rec { int stage; int err; unsigned long long addr, size; };
static __thread struct ios_af_rec ios_af;
static const char * const ios_af_stage_name[] = {
    "none", "limits/params", "placement-scan", "anon-mmap",
    "vprot-table", "view-struct", "fixed-map" };
static inline void ios_af_set( int stage, int err, const void *addr, size_t size )
{
    /* First failure wins: later stages are consequences of the first. */
    if (ios_af.stage) return;
    ios_af.stage = stage; ios_af.err = err;
    ios_af.addr = (unsigned long long)(uintptr_t)addr; ios_af.size = (unsigned long long)size;
}

/* ml797: the arena, for the PE side to hand to the emulator as plain data.
 * The setenv() calls at the reservation site stay for logging and for unix-side
 * consumers, but they can never reach rpmalloc's band selector -- it runs too
 * early to call anything that reads an environment. Zero means nothing was
 * reserved. Declared here because the reserved-area allocator below needs them. */
ULONG_PTR ios_fex_arena_base_unix = 0;
ULONG_PTR ios_fex_arena_end_unix = 0;

/* ml800: hand the arena to the PE side on request.
 *
 * This is the authoritative answer: these globals live in ntdll-unix, of which
 * there is exactly one per Mach task, so no image copy can make it stale. */
NTSTATUS unixcall_ios_get_fex_arena( void *args )
{
    struct ios_get_fex_arena_params *p = args;

    if (!p) return STATUS_INVALID_PARAMETER;
    p->base = (ULONG64)ios_fex_arena_base_unix;
    p->end  = (ULONG64)ios_fex_arena_end_unix;
    return STATUS_SUCCESS;
}

/* ml799: may this request be served from the FEX_ONLY arena?
 *
 * Only when the caller's address requirements are CONTAINED in the arena. That
 * is the whole exclusivity rule: FEX asks with [band_base, band_end], which
 * ntdll itself published, so its requests qualify and nothing else does. An
 * unconstrained request (limit_low 0, limit_high the top of the address space)
 * can never be contained, so generic placement is excluded by construction
 * rather than by a list of call sites someone has to remember to update. */
static int fex_arena_covers( const void *limit_low, const void *limit_high )
{
    ULONG_PTR lo = (ULONG_PTR)limit_low, hi = (ULONG_PTR)limit_high;
    static int wow_band = -1, logged;

    if (!ios_fex_arena_base_unix || !ios_fex_arena_end_unix) return 0;
    if (lo >= ios_fex_arena_base_unix && hi <= ios_fex_arena_end_unix) return 1;
    /* madeira-bcd [wow-band]: the WOW64 CPU module (xtajit.dll) is never handed
     * the arena (its ios_get_fex_arena unix call is unsupported), so its rpmalloc
     * band selector asks for the whole hardware FEX band [0x7c00000000,
     * 0x7fffffffff]. With env.MADEIRA_SC_PA_POOLS = 1/2 the arena starts at
     * 0x7d00000000, so that request is not contained, [0x7c..,0x7d..) is Social
     * Club's held cage and 32-63 GB is refused by the kernel: no band, rpmalloc
     * returns NULL, SEGV at 0x7f0 before any x86 code runs (32-bit vc_redist
     * started by the Rockstar Games Launcher installer). Serve exactly that
     * request from the arena; the caller clamps placement to the area, so it
     * stays inside. MADEIRA_WOW_FEX_BAND=0 turns this off. */
    if (wow_band < 0) { const char *e = getenv( "MADEIRA_WOW_FEX_BAND" ); wow_band = !(e && e[0] == '0'); }
    if (wow_band && lo == 0x7c00000000ULL && lo < ios_fex_arena_base_unix &&
        hi + 1 >= ios_fex_arena_end_unix && hi <= ios_fex_arena_end_unix)
    {
        if (logged++ < 4)
            dprintf( 2, "[wow-band] FEX hardware-band request [%p,%p] served from the FEX arena "
                        "[0x%lx,0x%lx) (MADEIRA_WOW_FEX_BAND=0 reverts)\n", limit_low, limit_high,
                     (unsigned long)ios_fex_arena_base_unix, (unsigned long)ios_fex_arena_end_unix );
        return 1;
    }
    return 0;
}

struct builtin_module
{
    struct list  entry;
    unsigned int refcount;
    void        *handle;
    void        *module;
    char        *unix_path;
    void        *unix_handle;
};

static struct list builtin_modules = LIST_INIT( builtin_modules );

struct file_view
{
    struct wine_rb_entry entry;  /* entry in global view tree */
    void         *base;          /* base address */
    size_t        size;          /* size in bytes */
    unsigned int  protect;       /* protection for all pages at allocation time and SEC_* flags */
    unsigned int  ios_flags;     /* IOS_VIEW_* */
};
#define IOS_VIEW_QUARANTINED 0x4   /* a dead thread's stack held by the stack quarantine */

/* per-page protection flags */
#define VPROT_READ       0x01
#define VPROT_WRITE      0x02
#define VPROT_EXEC       0x04
#define VPROT_WRITECOPY  0x08
#define VPROT_GUARD      0x10
#define VPROT_COMMITTED  0x20
#define VPROT_WRITEWATCH 0x40
/* per-mapping protection flags */
#define VPROT_ARM64EC          0x0100  /* view may contain ARM64EC code */
#define VPROT_SYSTEM           0x0200  /* system view (underlying mmap not under our control) */
#define VPROT_PLACEHOLDER      0x0400
#define VPROT_FREE_PLACEHOLDER 0x0800
/* madeira-bcd [x64-image]: a pure-x64 image view in an x64 process that gets no
 * JIT-pool copy; its code is host DATA that the emulator runs at the PE VA.
 * Set once by map_image_into_view (MADEIRA_X64_IMAGE_NOCOPY), read by
 * mprotect_exec. Follows the view through splits like VPROT_ARM64EC. */
#define VPROT_X64DATA          0x1000

/* Conversion from VPROT_* to Win32 flags */
static const BYTE VIRTUAL_Win32Flags[16] =
{
    PAGE_NOACCESS,              /* 0 */
    PAGE_READONLY,              /* READ */
    PAGE_READWRITE,             /* WRITE */
    PAGE_READWRITE,             /* READ | WRITE */
    PAGE_EXECUTE,               /* EXEC */
    PAGE_EXECUTE_READ,          /* READ | EXEC */
    PAGE_EXECUTE_READWRITE,     /* WRITE | EXEC */
    PAGE_EXECUTE_READWRITE,     /* READ | WRITE | EXEC */
    PAGE_WRITECOPY,             /* WRITECOPY */
    PAGE_WRITECOPY,             /* READ | WRITECOPY */
    PAGE_WRITECOPY,             /* WRITE | WRITECOPY */
    PAGE_WRITECOPY,             /* READ | WRITE | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* READ | EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY,     /* WRITE | EXEC | WRITECOPY */
    PAGE_EXECUTE_WRITECOPY      /* READ | WRITE | EXEC | WRITECOPY */
};

static struct wine_rb_tree views_tree;
static pthread_mutex_t virtual_mutex;

static const UINT page_shift = 12;
static const UINT_PTR page_mask = 0xfff;
static const UINT_PTR granularity_mask = 0xffff;

#ifdef __aarch64__
static UINT_PTR host_page_size;
static UINT_PTR host_page_mask;
#else
static const UINT_PTR host_page_size = 0x1000;
static const UINT_PTR host_page_mask = 0xfff;
#endif

/* Note: these are Windows limits, you cannot change them. */
#if defined(__i386__) || defined(__x86_64__)
static void *address_space_start = (void *)0x110000; /* keep DOS area clear */
#elif defined(WINE_IOS)
static void *address_space_start = (void *)0x100010000; /* above iOS 4GB __PAGEZERO */
#else
static void *address_space_start = (void *)0x10000;
#endif
#ifdef _WIN64
static void *address_space_limit = (void *)0x7fffffff0000;  /* top of the total available address space */
static void *user_space_limit    = (void *)0x7fffffff0000;  /* top of the user address space */

/* task #35 (ml105): FURNITURE CEILING — keep the top 16GB [0x7C00000000,
 * 0x8000000000) free of Wine furniture so PartitionAlloc's third 16GB pool can
 * land there. The ml96/ml105 census is deterministic: pools 1-2 take the 480G
 * and 464G slots (pool 2's guard-before layout also poisons the top 64KB of the
 * 448G slot, so evicting our RW alias would NOT help pool 3), and pool 3's
 * offset-0 slot walk tries 0x7C00000000 FIRST — it fails only because Wine's
 * top-down placement packs images/TEBs/stacks into [0x7e874c0000, top). Total
 * furniture there is ~6GB, and [0x7038000000, 0x73ffff0000) = 15.1GB is free to
 * hold it. Applied ONLY to kernel-pick placements smaller than 1GB with no
 * caller-imposed limits — jumbo reserves and explicit/fixed requests are
 * untouched. NOTE: the [reclaim-recover] data-fault band in signal_arm64_ios.c
 * watches this same [496G,512G) range for FEX arena recovery; if arenas move
 * below the ceiling, that band goes quiet — watch Thumper-under-pressure for a
 * regression and move the band with them if needed.
 *
 * ml106 REVISED: the first ceiling (0x7C00000000, 1GB size gate) backfired two
 * ways. (1) Furniture packed top-down to JUST under the ceiling, so the last
 * 64KB below 0x7C00000000 was always occupied and the 480G slot's top was
 * poisoned. (2) A 4GB guard-style tenant that does NOT go through
 * NtAllocateVirtualMemory (absent from the [jumbo#] census; likely a section
 * view or similar) landed at [0x7effff0000, 0x7fffff0000) and broke the 496G
 * slot. Result: ONE pool instead of two, chrome_elf died earlier. Fix: ceiling
 * at 464G-64KB so the guard pool's under-boundary bite lands on free space, and
 * a 16GB size gate so the 4GB tenant is clamped below too. Leaves
 * [0x73ffff0000, 0x8000000000) = 3 slots + guard margin exclusively for the
 * three PartitionAlloc pools.
 *
 * ml107-ml109 DISABLED (= 0): with the ceiling active, EVERY x64 EC child dies
 * at boot — Steam's children AND Thumper's (ml109: the baseline regressed from
 * 2s-to-splash to ~1min then app death). Mechanism fully identified: some FEX
 * boot-path error fires under the new layout → FEX LogMan::Msg::MFmtImpl
 * formats the message → FEXCore::Allocator::aligned_alloc returns NULL on that
 * thread (rpmalloc not thread-initialized) → unchecked memmove(NULL, msg, len)
 * → c0000005 in ntdll memcpy rva 0x5a4d4 (disassembly-confirmed at FEX rva
 * 0x10bd48). The crash is the LOGGER; the actual FEX complaint is unknown and
 * unknowable until the logger survives allocation failure. PREREQUISITE to
 * re-enabling: patch FEX's MFmtImpl to drop the message on alloc failure (or
 * fix rpmalloc thread-init on wine loader threads), THEN re-enable to read
 * what FEX is actually objecting to. The packing geometry itself (ceiling
 * 464G-64K + direction-aware walk) remains correct on paper.
 *
 * ml110 RE-ENABLED: the prerequisite landed — FEXCore AllocatorHooks now
 * lazily rpmalloc_thread_initialize at every hook (EnsureThreadHeap), so the
 * logger survives on uninitialized threads. Thumper verified clean on the new
 * FEX (ml110: ~10k frames, 0 faults) with the ceiling still off. This build
 * turns the ceiling back on: either the FEX objection was a non-fatal warning
 * and the three pools finally land, or the message prints and names it.
 *
 * ml120 THE ARITHMETIC CAME IN, AND 3 POOLS DO NOT FIT. Measured at the moment
 * PartitionAlloc asked:
 *   FREE 0x747fff0000..0x7800000000 = 14336 MB   (slot#0 poisoned from its base)
 *   FREE 0x7c00000000..0x8000000000 = 16384 MB   (slot#2 pristine)
 * and the 15.1GB furniture window was CONSUMED ENTIRELY -- absent from the free
 * list. The occupied run begins at exactly 0x73ffff0000, this ceiling: once the
 * window filled, the advisory relax valve handed out the next-lowest free
 * addresses, which march straight up into slot#0 (64 regions x ~32MB = 2GB).
 * So the valve that stops us dying is also what poisons the slots, and the
 * furniture demand for Steam is >15GB (~17GB and climbing) rather than the
 * ~6GB the ml105 census suggested. 48GB of pools + 17GB of furniture = 65GB in
 * a 63GB window: THREE POOLS ARE ARITHMETICALLY IMPOSSIBLE unless furniture
 * demand is cut, and whether it can be cut is unknown until we know what is in
 * those 15GB (see ios_window_inventory).
 *
 * Pool #2 additionally failed for a 64KB reason: PA's guard-style pool asks for
 * 0x400010000 = 16GB + 64KB, and slot#2 is EXACTLY 16GB with the top of the
 * address space above it, so the guard cannot overhang. A guard pool can only
 * sit at a slot that has 64KB free BELOW it.
 *
 * ml121 THEREFORE TARGETS TWO POOLS, DETERMINISTICALLY, instead of three
 * accidentally. Raising the ceiling to 0x77ffff0000 gives furniture
 * [0x7038000000, 0x77ffff0000) = 31GB (the 15GB it demonstrably needs plus 16GB
 * of headroom, so the relax valve should never fire and never poison anything),
 * and reserves [0x77ffff0000, 0x8000000000) = 32GB + 64KB, which fits exactly:
 *   guard pool -> 0x7800000000 with its 64KB overhang at 0x77ffff0000
 *   plain pool -> 0x7c00000000, exactly 16GB to the top of VA
 * That is the maximum this address space can hold, and it is 2x what ml120
 * achieved. Whether CEF runs on two pools is the next question; three needs a
 * furniture reduction that ios_window_inventory has to justify first.
 *
 * ml124 THIRD POOL BACK ON THE TABLE. The [window] run/tag probe named the
 * tenants at last: ~30 reservations of ~511MB (one per guest thread, 31 live)
 * = 15.4GB, plus ONE 4.06GB read-only run = the ARM64EC code bitmap, which was
 * sized for Windows' 128TB address space instead of iOS's 512GB. Sizing that
 * bitmap from host_addr_space_limit (see alloc_arm64ec_map) drops it 4.06GB ->
 * 16MB, taking furniture from 17.8GB to ~13.7GB -- under the 15.1GB that fits
 * below 0x7400000000. So the ceiling comes back down to 0x73ffff0000 and slot#0
 * is free again, giving the guard pool [0x73ffff0000, 0x7800000000) (its 64KB
 * overhang landing exactly on the ceiling, which is exclusive for furniture)
 * and the two plain pools 0x7800000000 and 0x7c00000000. Three pools.
 *
 * MARGIN IS THIN AND DOES NOT SCALE: 15.1 - 13.7 = ~1.4GB, and every further
 * guest thread costs ~512MB, so roughly three more threads exhausts it. Watch
 * [slot#0] -- if it goes DIRTY the relax valve has spilled into the pool slot
 * again and the per-thread FEX LookupCache reservation is the next thing that
 * has to shrink. */
/* ml125 REVERTED TO 0x77ffff0000. The 3-pool geometry was tried and FAILED:
 * with the window at 15.1GB, furniture (which the ml124 snapshot underestimated
 * — it keeps growing after the jumbo-failure moment it was measured at) filled
 * it to 99.5% (15403 of 15488 MB), the relax valve spilled into slot#0 AND
 * slot#1, the extra pressure revived the #34 pool exec-fault, and it stormed
 * 7.26 MILLION times. CEF never reached PartitionAlloc at all — strictly worse
 * than the 2-pool runs. The EC-bitmap reclaim is KEPT (it is a real 4GB and
 * gives this 31GB window more headroom than ml123 had), but a third pool needs
 * the ~512MB-per-thread FEXCore LookupCache reservation to shrink first; VA
 * freed elsewhere just gets absorbed by furniture growth. */
static const ULONG_PTR ios_furniture_ceiling = 0x73ffff0000;   /* ml132: 3-pool geometry, now with ios_spill_cap bounding the downside */

/* ml168: running total of 256MB..1GB MEM_RESERVE grants, used ONLY as a pressure
 * signal for the steering valve in NtAllocateVirtualMemory. Steam/CEF makes 2 x
 * 512MB reserve-only allocations per guest thread and commits ~1% of them; by
 * thread 13 that is 13.8GB of the 15.1GB furniture window, maxgap collapses to
 * 28MB, the next 512MB reserve FAILS and the caller stores through the NULL
 * (`stp x8,x20,[x0]`, x0=0 -> c0000005, ml166).
 *
 * Attribution resisted six approaches (four RIP-based -> all landed inside
 * VirtualAlloc itself; the guest x64 CONTEXT is all-zero so there is NO guest
 * context, i.e. the caller is native; and the native stack's frame order is
 * provably inconsistent — LdrInitializeThunk appeared ABOVE the syscall stub —
 * so its libarm64ecfex hits mix live and stale frames). The flags also exclude
 * every FEX site: type=0x2000 lacks MEM_TOP_DOWN which
 * FEXCore::Allocator::VirtualAlloc unconditionally ORs, CallRetStack is
 * MEM_TOP_DOWN|PAGE_NOACCESS, and the iOS LookupCache path passes Commit=true.
 *
 * So stop trying to name the caller and fix the placement instead. */
static unsigned long long ios_bigres_reserved_total;

/* ml207: furniture-window PRESSURE LATCH.
 *
 * The big-reserve steer valve used to arm only at ios_bigres_reserved_total > 8GB, chosen
 * so a Thumper run (which never gets near it) keeps byte-identical placement. But the
 * usable furniture window is only ~16GB, so that gate hands FEX's 512MB per-thread arenas
 * the first 8GB of it before steering starts. ml207 measured 16 of 25 reserves (8GB)
 * landing INSIDE the window; ml206 38 of 50 (19GB). What follows is starvation: a 1MB
 * thread stack cannot be placed, FEX reports "Failed to mprotect last page of code buffer",
 * the thread dies and steam.exe exits(1) — the shallow runs that have been blocking
 * verification, at 22k unix calls instead of 46k.
 *
 * So arm on the SYMPTOM instead of a guessed constant: the [va-scan] probe already knows
 * when the window is tight. A healthy scan costs "a handful of tryfixed calls"; ml207
 * ground 22747 of them. Latching here means a healthy run never arms the valve (Thumper
 * placement is unchanged, which is the property the 8GB gate existed to protect) while a
 * starving one steers every subsequent arena out of the window from the moment it is
 * genuinely tight. */
static int ios_va_pressure;

/* ml116 ROOT CAUSE of the ceiling regressions (disassembly + code-path proof,
 * no device run needed):
 *
 * With the ceiling active, map_view's kernel-pick branch sees
 * end < host_addr_space_limit, which diverts EVERY anonymous placement off
 * anon_mmap_alloc (kernel picks, essentially never fails) and onto Wine's own
 * map_free_area linear scan. That scan starts at address_space_start =
 * 0x100010000 and mmap-tryfixed steps by align_mask+1 until it reaches the
 * first Wine view (~0x72a5000000): ~455GB of address space that the ml108 gap
 * walk PROVED holds no free gap at all (iOS __PAGEZERO + the xzone/GPU
 * reservation). At 64KB steps that is ~7.4 MILLION failing mach_vm_map calls
 * for ONE allocation -- the ml107/ml109 "2s-to-splash became ~1min then death"
 * regression, and the multi-minute Steam stalls. Worse, try_map_free_area
 * bails out returning NULL on any errno that is not EEXIST/ENOMEM, so the
 * grind can end in a silent STATUS_NO_MEMORY: that is the NULL rpmalloc
 * returned to FEXCore::Context::ContextImpl::CreateThread in ml116
 * (libarm64ecfex+0x16178 stp [x0=NULL], x0 = aligned_alloc(0x1000,0x2000)).
 *
 * The ceiling's packing geometry was never the problem -- its scan FLOOR was
 * never raised to match. Nothing below this floor is mappable, so scanning it
 * is pure waste; clamping both ends keeps the search inside the one real
 * window and restores O(1) placement. */
/* ml364: MUST equal 0x7000000000 + the JIT pool size (the pool's RW alias is
 * remapped at exactly 0x7000000000 by StikJITHelper.allocatePool, and the
 * first thing wine allocates — the USD page — lands AT this floor because it
 * is a kernel-pick with this scan clamp). Pool grew 896MB→1152MB after ml363
 * died on pool exhaustion (bump 858/896MB, freelist 0) at MSM depth, so the
 * floor moves 0x7038000000 → 0x7048000000 in lockstep. */
/* ml668: the floor is DERIVED now. It was a hardcoded constant that had to be
 * hand-paired with poolSizeMB (the comment above says so in bold), which makes
 * any pool-size experiment a two-edit change with a silent, ugly failure if you
 * forget the second one. Computing it from the pool the app actually allocated
 * removes that trap entirely. Falls back to the 896MB pairing until the pool
 * size is published, which is before any use site runs. */
/* madeira-bcd: env.MADEIRA_SC_PA_POOLS layout, -1 until ios_sc_layout() ran
 * (virtual_init); layout 2 moves the floor above libcef's pools. */
static int ios_sc_layout_mode = -1;
/* madeira-bcd: env.MADEIRA_RDR2_VA_HOLD's geometry is in use (ios_sc2_rdr2_geometry);
 * it moves the floor down to the end of libcef.dll's smaller pools. */
static int ios_sc2_rdr2;

static inline ULONG_PTR ios_usable_va_floor_get(void)
{
    size_t sz = ios_jit_pool_size_global;
    if (ios_sc_layout_mode == 2 && ios_sc2_rdr2) return (ULONG_PTR)0x7010000000ULL;   /* IOS_SC2_RDR2_FLOOR */
    if (ios_sc_layout_mode == 2) return (ULONG_PTR)0x7100000000ULL;   /* IOS_SC2_FLOOR */
    /* madeira-bcd pool-low: the RW reservation starts with region C's alias, so the
     * pool's own alias sits higher than 0x7000000000; the floor is where it ends. */
    if (ios_jit_low_size_global && sz)
    {
        ULONG_PTR end = (ULONG_PTR)ios_jit_rw_base_global + sz;
        if (end > (ULONG_PTR)0x7000000000ULL + sz && end < (ULONG_PTR)0x7400000000ULL) return end;
    }
    return (ULONG_PTR)0x7000000000ULL + (ULONG_PTR)(sz ? sz : (896ULL << 20));
}
#define ios_usable_va_floor (ios_usable_va_floor_get())

/* ml132 SPILL CAP — makes the 3-pool experiment SAFE to run.
 *
 * Measured: real Wine furniture is only 2130 MB; the other 11604 MB of the
 * window is steam.exe reserving 23 x 512MB and committing 8% of it
 * ([bigres-use] reserved=11776 committed=965). Total 13.4GB, which does fit the
 * 15.1GB below 0x7400000000 — but with ~1.7GB of margin, and every further
 * guest thread costs another 1GB. ml125 ran exactly this geometry and failed
 * hard: the advisory relax valve spilled past the ceiling into slot#0 AND
 * slot#1, poisoning the two pools that already worked, and the pressure then
 * revived the #34 exec fault into a 7.26M-fault storm.
 *
 * The valve must stay (it is what stops an allocation failure from killing the
 * process), but it does not need to be allowed to eat the PROVEN slots. Cap the
 * spill at the top of slot#0: overflow may consume [0x7400000000,0x7800000000)
 * — the third-pool slot, which is what we are speculating with — and never
 * touches 0x7800000000 or 0x7c00000000. Worst case we fall back to the known-good
 * two pools instead of losing all three. Bounded downside, so the experiment is
 * worth running. 0 disables. */
static const ULONG_PTR ios_spill_cap = 0x7800000000;

/* ml170: DEDICATED SLOT FOR STEERED RESERVES.
 *
 * The steering valve worked -- 12 x 512MB moved above the ceiling and furniture
 * occupancy fell 13758MB -> 10160MB, taking the run from 18770 to 37175 unix
 * calls (deepest yet). But it steered into ios_spill_cap = 0x7800000000, which is
 * PartitionAlloc's slot 2, so [soft-pool] COLLISION went 12 -> 43 and pools
 * granted dropped 4 -> 3. Give the steered ranges their OWN slot instead.
 *
 * The top slot is the right one to give up: the ml135 census measured real CEF
 * demand at 3 x 16GB, and slots 0-2 (0x7000000000/0x7400000000/0x7800000000)
 * cover exactly that, leaving [0x7C00000000, 0x8000000000) = 16GB for steering --
 * enough for the ~14GB of 512MB reserves this workload makes. */
static const ULONG_PTR ios_steer_slot = 0x7C00000000;

/* ml173 THREAD-AWARE RECLAMATION of steered reserves (task #35/#36).
 *
 * PROVEN LEAK, once the [bigfree] probe was fixed: releases DO happen (32 of them,
 * all type=0x8000 MEM_RELEASE with size=0 as the Windows contract requires) but every
 * one is small — 0x1000..0x200000. NOT ONE 512MB range is ever released. So the owner
 * reserves 2 x 512MB per guest thread at thread start, commits ~1%, and never frees;
 * the count tracks run length (23 -> 27 -> 55) and no fixed slot size can hold it.
 *
 * Reclaiming on THREAD DEATH is the one rule that is airtight: a dead thread can never
 * commit into its reservation again, so releasing it cannot race a live owner. That is
 * why this is preferred over recycling any zero-commit range (which can steal a live
 * thread's untouched reservation) or aliasing (unsound in general).
 *
 * ios_thread_died() is called from the pthread_exit path in thread_ios.c. */
#define IOS_STEER_MAX 256
/* iOS-Madeira ml312 (task #54): `inuse` is set the moment ANY allocation lands inside a steered
 * arena, and blocks reclamation of that arena forever after. See ios_steer_reclaim_dead(). */
static struct { uint64_t base; uint64_t size; unsigned tid; unsigned freed; unsigned inuse; } ios_steer[IOS_STEER_MAX];
static unsigned ios_steer_n;
static unsigned char ios_tid_dead[8192];   /* bitmap, indexed by wine tid */

void ios_thread_died( unsigned tid )
{
    if (tid < sizeof(ios_tid_dead) * 8) ios_tid_dead[tid >> 3] |= (1u << (tid & 7));
}

/* ml181 BUG FIX (mine). Wine thread ids are SMALL AND RECYCLED (0x74, 0x98, 0xbc ...).
 * ios_tid_dead marked a tid dead permanently, so once a tid was reused by a new thread
 * the bitmap still read "dead" and the next exhaustion would release that LIVE thread's
 * 512MB arena. Those arenas hold FEX's CpuStateFrame (it sits at base+0x1140 — ml174/ml181
 * both show CPUArea+0x30 pointing inside a steered range), so freeing one under a running
 * thread produces exactly the STATE==0 faults we are chasing. Clear the bit whenever the
 * tid proves itself alive by making a reservation. */
static void ios_thread_alive( unsigned tid )
{
    if (tid < sizeof(ios_tid_dead) * 8) ios_tid_dead[tid >> 3] &= ~(1u << (tid & 7));
}

static int ios_tid_is_dead( unsigned tid )
{
    if (tid >= sizeof(ios_tid_dead) * 8) return 0;
    return (ios_tid_dead[tid >> 3] >> (tid & 7)) & 1;
}

/* ml462 (#77): the steer valve's per-tid intake cap (NtAllocateVirtualMemory). The
 * valve was sized for the ~25-55 legitimate leaked-per-thread reserves it was built
 * for (ml171); ml461's livelock fed it an INFINITE stream from two tids and it
 * spilled 15.5GB into the FEX band before the process starved. No sane consumer
 * needs more than IOS_STEER_CAP steered arenas; past that, stop feeding it.
 *
 * Keyed on the EXACT tid in a 64-slot table. It was 16 slots that were never
 * freed: once 16 threads had steered, every later thread went to slot tid & 15,
 * and Wine's tids are multiples of 4 and never reused here (server/process.c
 * ml400), so later threads shared 4 slots, two of them in one slot reset each
 * other's count at every ask, and the cap never applied. A full table replaces a
 * thread that has exited, else the one with the fewest arenas, so a capped thread
 * stays capped. Any guest thread reserves, so the table has its own lock. Returns
 * 1 when this ask may steer (and counts it), 0 at the cap. */
#define IOS_STEER_CAP 24
#define IOS_STEER_TIDS 64
static struct { unsigned tid; unsigned n; } ios_steer_tid[IOS_STEER_TIDS];
static pthread_mutex_t ios_steer_tid_lock = PTHREAD_MUTEX_INITIALIZER;

static int ios_steer_intake( unsigned tid )
{
    unsigned i, slot = IOS_STEER_TIDS, n;

    pthread_mutex_lock( &ios_steer_tid_lock );
    for (i = 0; i < IOS_STEER_TIDS; i++)
        if (ios_steer_tid[i].n && ios_steer_tid[i].tid == tid) { slot = i; break; }
    if (slot == IOS_STEER_TIDS)
    {
        for (i = 0; i < IOS_STEER_TIDS; i++)
        {
            if (!ios_steer_tid[i].n || ios_tid_is_dead( ios_steer_tid[i].tid )) { slot = i; break; }
            if (slot == IOS_STEER_TIDS || ios_steer_tid[i].n < ios_steer_tid[slot].n) slot = i;
        }
        ios_steer_tid[slot].tid = tid;
        ios_steer_tid[slot].n = 0;
    }
    n = ios_steer_tid[slot].n;
    if (n <= IOS_STEER_CAP) ios_steer_tid[slot].n++;   /* stops one past the cap: logged once */
    pthread_mutex_unlock( &ios_steer_tid_lock );
    if (n == IOS_STEER_CAP)
        dprintf(2, "[steer] tid=%04x CAPPED at %d steered arenas — refusing further FEX-band spill rev=ml462\n",
                tid, IOS_STEER_CAP);
    return n < IOS_STEER_CAP;
}

/* Release every steered range whose owning thread has exited. Returns bytes freed.
 * Called only from the steer path, which does NOT hold the virtual mutex (that is
 * taken inside allocate_virtual_memory), so re-entering the free path is safe here. */
static uint64_t ios_steer_reclaim_dead( void )
{
    uint64_t freed_total = 0;
    unsigned i;

    for (i = 0; i < ios_steer_n; i++)
    {
        void *addr;
        SIZE_T sz = 0;

        if (ios_steer[i].freed || !ios_steer[i].base) continue;
        if (!ios_tid_is_dead( ios_steer[i].tid )) continue;
        /* iOS-Madeira ml312 (task #54) -- THE FIX FOR THE VA DOUBLE-ALLOCATION.
         *
         * These 512MB ranges are FEX's jemalloc HEAP ARENAS, which are process-wide. Tagging one
         * with the thread that happened to trigger it and releasing it when that thread exits is
         * wrong: FEX allocates FEXMem_ThreadState / FEXMem_Lookup / FEXMem_CallRetStacks INSIDE
         * them, and those outlive the triggering thread. ml312 caught the consequence directly --
         * nine arenas came back from this function with freed=1 and were immediately reissued, and
         * the reissued VAs are exactly where the duplicate ThreadStates appear:
         *   0x7d00001000 owned by tids A8, AC and E4   (arena 0x7d00000000, reissued)
         *   0x7d40001000 owned by tids B0 and F0       (arena 0x7d40000000, reissued)
         * Two threads sharing a ThreadState share x28, so one thread's State.rip IS the other's;
         * sharing a CallRetStack means one pops the other's {guest_ret, host_label} pair and
         * branches into a foreign block. That is the #51/#52 signature and the variance source.
         *
         * Refuse to reclaim any arena something has allocated inside. Thread-exit is simply not
         * evidence that a process-wide arena is dead. Arenas never touched are still reclaimable,
         * so the pressure-relief this function exists for survives for the case it is valid in. */
        /* ml313 RETRACTION: the ml312 "KEEPING in-use arenas" guard here was built on a premise
         * ml313 then refuted. Two [vname] records at one address do NOT prove two live owners --
         * [vname] logs allocations but not frees, and the liveness test on ml313's two duplicate
         * ThreadStates showed the first owner went quiet ~20 lines after claiming, long before the
         * second claim: ordinary allocator reuse after thread exit, not a collision. The
         * ThreadState allocations also never appear in the [va-exit] syscall census (they are
         * jemalloc sub-allocations, invisible to VirtualAlloc), and ml313's arenas were each
         * reserved exactly once with zero reissues -- yet duplicates still appeared. So
         * reclaim-reissue was not causing them either.
         *
         * Blocking reclaim outright would risk VA exhaustion (#43) for no demonstrated benefit.
         * Keep the inuse flag as a DETECTOR instead: if reclaim ever releases an arena that has
         * interior allocations, say so loudly, so any later corruption in that range can be tied
         * to this event with evidence rather than theory. */
        /* iOS-Madeira ml330: the ml312 guard WAS right — restored, now with the evidence
         * the ml313 revert was waiting for.
         *
         * ml329 fired this detector 10 times, and cross-referencing [vname] against the
         * released ranges showed 28 live FEX structures sitting INSIDE arenas being
         * released — including FEXMem_ThreadState, FEX's per-thread CPU state. Releasing
         * the arena frees that VA; the next reservation is handed the same range, and two
         * owners write the same memory. That is exactly the corruption we kept crashing
         * on: FEX container nodes holding impossible pointers —
         *   ml326/ml328  IntrusivePooledAllocator::ClaimBufferImpl, list next == NULL
         *   ml329        GuestToHostMap::AddBlockExecutableRange, std::set child == 4
         * and #53 is refuted for these (ml329's [reclaim-census]: 0 pages zero-filled all
         * run), so page reclamation was never the source — VA double-ownership was.
         *
         * The arena belongs to a dead thread, but the allocations inside it OUTLIVE that
         * thread, so "owning thread exited" is not a licence to free the range. Skip it.
         * Note it stays skipped for the life of the process: an arena with live interior
         * allocations can never become safe to release just because more time passed.
         *
         * The ml313 objection was VA exhaustion (#43) for no demonstrated benefit. The
         * benefit is now demonstrated, and this is the narrow case — only arenas with
         * recorded interior allocations are spared; empty ones are still reclaimed. */
        if (ios_steer[i].inuse)
        {
            static int rc_note;
            if (rc_note++ < 12)
                dprintf(2, "[steer-reclaim] rev=ml332 SKIPPING release of arena #%u [0x%llx+0x%llx] "
                        "dead_tid=%04x — %u interior allocations still LIVE (outlive the thread); "
                        "releasing it is what corrupted FEX's containers (ml329)\n",
                        i, (unsigned long long)ios_steer[i].base,
                        (unsigned long long)ios_steer[i].size, ios_steer[i].tid, ios_steer[i].inuse);
            continue;
        }

        addr = (void *)(uintptr_t)ios_steer[i].base;
        if (!NtFreeVirtualMemory( NtCurrentProcess(), &addr, &sz, MEM_RELEASE ))
        {
            ios_steer[i].freed = 1;
            freed_total += ios_steer[i].size;
        }
    }
    if (freed_total)
        dprintf(2, "[steer-reclaim] released %lluMB from exited threads\n",
                (unsigned long long)(freed_total >> 20));
    return freed_total;
}

/* ml255: STORM GATE.
 *
 * ml255 wrote a 510 MB / 4.47-MILLION-line log because a NULL-deref loop ran
 * 524,186 times and three diagnostics fired on EVERY iteration: [va-scan] FAILED
 * (524k), [fault-rgn] (524k + 393k) and the setup_exception/TEB dumps (393k).
 * Device I/O that heavy is destructive on its own and it buried the one line that
 * mattered. These probes are all still worth having -- the FIRST few of each
 * settle the question -- so gate them instead of deleting them.
 *
 * Escalating schedule: every one of the first 20, then 1-in-1000, then
 * 1-in-100000 past 100k. A storm still proves it is a storm and still shows where
 * it ends, at ~1/1000th the bytes. */
static int ios_storm_gate( unsigned long *n )
{
    unsigned long c = ++(*n);
    if (c <= 20) return 1;
    if (c <= 100000) return (c % 1000) == 0;
    return (c % 100000) == 0;
}

/* [va-scan] probe: failing mmap-tryfixed attempts inside the current
 * map_free_area call. virtual_mutex is held throughout, so a plain global is
 * safe. Proves or refutes the grind above in one run. */
static unsigned int ios_va_scan_tries;
/* ml211: how many times the scan JUMPED over a foreign Mach region instead of
 * crawling a granule at a time. Reported next to tries= so the two are directly
 * comparable: before this, placing 1MB cost ~8000 tries and 0 skips. */
static unsigned int ios_va_scan_skips;

/* ml117: the grind is GONE (Thumper splash back to 2s) but a 512KB-aligned
 * 512MB request still FAILED in the 15.1GB window with tries=0 — i.e.
 * map_free_area rejected it on a structural guard without attempting a single
 * mmap, then handed rpmalloc the NULL that killed FEX's CreateThread. tries=0
 * narrows it to "no gap between Wine's own views was large enough", so record
 * the geometry map_free_area actually saw: the base/end AFTER
 * find_view_inside_range moved them, how many views were walked, the largest
 * gap found, and which guard ended the search. */
static void *ios_scan_base, *ios_scan_end;
static unsigned int ios_scan_views;
static size_t ios_scan_maxgap;
/* ml798: the gap AFTER the last view, up to `end`.
 *
 * maxgap only ever measured gaps that sit BEFORE a view, so when the walk ran
 * off the end of the view list the terminal region was never measured at all.
 * That made "maxgap=0x0" read as "not one byte of contiguous space anywhere",
 * and an 8GB band whose views stopped 2GB in was diagnosed as fragmented when
 * the kernel was simply REFUSING the rest (firstfail=0xc88000000 errno=12).
 * Reporting the tail separately keeps those two verdicts apart: a large tail
 * with a firstfail inside it means refusal, not occupancy. */
static size_t ios_scan_tailgap;
static int ios_scan_stop;   /* see ios_scan_stop_name() */

/* ml118 THE DISCRIMINATING QUESTION. The kernel's own walk reported ONE
 * contiguous free hole 0x7038120000..0x73ffdf0000 = 15484 MB, yet Wine's scan
 * reported 343 views with 2MB max gaps, and one failure showed 17 tryfixed
 * calls ALL failing inside a gap Wine believed was free. Those cannot both be
 * about occupancy. Two mutually exclusive explanations:
 *   (a) the window really is full of mappings Wine's view tree cannot see, or
 *   (b) the addresses are genuinely free and iOS is refusing the FIXED mapping
 *       (mach_vm_map returning KERN_INVALID_ADDRESS/KERN_NO_SPACE — a hazard
 *       try_map_free_area already documents for this platform).
 * (a) means the ceiling needs a smaller furniture budget; (b) means Wine's
 * fixed-address placement can never work here and the ceiling is unfixable, so
 * the pools must instead be pre-reserved at startup. Capture the first failing
 * address AND its errno, then ask the kernel what actually lives there. */
static void *ios_scan_fail_addr;
static int   ios_scan_fail_errno;

/* Describe what the kernel believes is at addr: the enclosing region, or the
 * hole it falls in. Non-destructive (query only). */
/* ml210: one-shot census of the furniture window.
 *
 * Every recent run grinds here — a 1MB request costs ~8000 tryfixed attempts and still
 * reports errno=12 — and FEX then dereferences a NULL returned by an 8KB
 * aligned_alloc (libarm64ecfex+0x16298, `stp x8,x20,[x0]` with x0=0, unchecked). That is
 * very likely why each run dies at a DIFFERENT small-offset null address (0x0, 0x8, 0x28,
 * 0x68): one exhaustion cause landing on whichever allocation runs first, not a race.
 *
 * Before guessing who consumes the window, measure it. Walks the real Mach map rather
 * than Wine's view bookkeeping, so it reports the truth even for foreign/FEX mappings,
 * and prints the largest free gap next to the largest regions — if the gap is big the
 * problem is placement, if it is tiny the window is genuinely full. */
static void ios_furniture_census( void )
{
    const mach_vm_address_t LO = 0x7000000000ULL, HI = 0x73ffff0000ULL;
    struct { unsigned long long base, size; unsigned prot; } top[16];
    unsigned ntop = 0, nregions = 0, k;
    unsigned long long mapped = 0, biggest_gap = 0, gap_at = 0, prev_end = LO;
    mach_vm_address_t a = LO;

    for (;;)
    {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        unsigned i, j;

        if (mach_vm_region( mach_task_self(), &a, &size, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS)
            break;
        if (a >= HI) break;

        if (a > prev_end && a - prev_end > biggest_gap)
        {
            biggest_gap = a - prev_end;
            gap_at = prev_end;
        }
        nregions++;
        mapped += size;

        for (i = 0; i < ntop && top[i].size >= (unsigned long long)size; i++) {}
        if (i < 16)
        {
            for (j = (ntop < 16 ? ntop : 15); j > i; j--) top[j] = top[j - 1];
            top[i].base = (unsigned long long)a;
            top[i].size = (unsigned long long)size;
            top[i].prot = (unsigned)info.protection;
            if (ntop < 16) ntop++;
        }
        prev_end = (unsigned long long)a + size;
        a += size;
    }
    if (HI > prev_end && HI - prev_end > biggest_gap)
    {
        biggest_gap = HI - prev_end;
        gap_at = prev_end;
    }

    dprintf( 2, "[furniture] window 0x%llx..0x%llx = %llu MB | regions=%u mapped=%llu MB "
                "free=%llu MB | biggest free gap=%llu MB at 0x%llx\n",
             (unsigned long long)LO, (unsigned long long)HI,
             (unsigned long long)((HI - LO) >> 20), nregions,
             mapped >> 20, (unsigned long long)(((HI - LO) - mapped) >> 20),
             biggest_gap >> 20, gap_at );
    for (k = 0; k < ntop; k++)
        dprintf( 2, "[furniture]   #%u 0x%llx +0x%llx (%llu MB) prot=%x\n",
                 k + 1, top[k].base, top[k].size, top[k].size >> 20, top[k].prot );
}

/* Describe what the kernel has at `addr` — or, when `len` is non-zero, across
 * the whole range [addr, addr+len).
 *
 * RANGE AWARENESS (device evidence, desktop run after the furniture-bias fix):
 * the single-address form printed "iOS REFUSED A FREE ADDRESS" whenever
 * mach_vm_region returned a region ABOVE addr — which is also true of a RANGE
 * whose first page is free and whose tail is occupied.  That is exactly the
 * 4 GB guest-window candidate on device (free from 0x7100000000, occupied from
 * 0x71fc120000), so the log accused iOS of refusing free VA when the real
 * verdict was "part of your range is taken".  A caller that knows the length of
 * the mapping it tried therefore passes it, and the refusal wording is reserved
 * for a range that really was free end to end. */
static void ios_va_describe_range( void *addr, ULONG_PTR len, char *buf, size_t buflen )
{
    mach_vm_address_t start = (mach_vm_address_t)(uintptr_t)addr;
    mach_vm_address_t end = start + (len ? (mach_vm_address_t)len : 1);
    mach_vm_address_t a = start;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;

    if (mach_vm_region( mach_task_self(), &a, &size, VM_REGION_BASIC_INFO_64,
                        (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS)
    {
        snprintf( buf, buflen, "no-region-above (free to end of VA)" );
        return;
    }
    if (a >= end)       /* nothing mapped anywhere in the requested range */
    {
        if (len)
            snprintf( buf, buflen, "FREE: all 0x%llx bytes from 0x%llx are free, next region 0x%llx "
                                   "(+0x%llx past the end) <-- iOS REFUSED A FREE RANGE",
                      (unsigned long long)len, (unsigned long long)start,
                      (unsigned long long)a, (unsigned long long)(a - end) );
        else
            snprintf( buf, buflen, "FREE hole, next region 0x%llx (+0x%llx away) <-- iOS REFUSED A FREE ADDRESS",
                      (unsigned long long)a, (unsigned long long)(a - start) );
        return;
    }
    if (a > start)      /* head free, tail taken: name the occupied sub-range */
    {
        snprintf( buf, buflen, "PARTIALLY OCCUPIED: free 0x%llx..0x%llx, then OCCUPIED 0x%llx+0x%llx "
                               "prot=%x/%x shared=%d (0x%llx of the range is not free)",
                  (unsigned long long)start, (unsigned long long)a,
                  (unsigned long long)a, (unsigned long long)size,
                  info.protection, info.max_protection, info.shared,
                  (unsigned long long)(end - a) );
        return;
    }
    snprintf( buf, buflen, "OCCUPIED 0x%llx+0x%llx prot=%x/%x shared=%d%s",
              (unsigned long long)a, (unsigned long long)size,
              info.protection, info.max_protection, info.shared,
              (len && a + size < end) ? " (and the range continues past this region)" : "" );
}

static void ios_va_describe( void *addr, char *buf, size_t buflen )
{
    ios_va_describe_range( addr, 0, buf, buflen );
}

static const char *ios_scan_stop_name( int stop )
{
    switch (stop)
    {
    case 0: return "walked-all-views";
    case 1: return "window<size@entry(bottom-up)";
    case 2: return "gaps-exhausted(bottom-up)";
    case 3: return "window<size@entry(top-down)";
    case 4: return "gaps-exhausted(top-down)";
    case 9: return "no-views-in-range";
    default: return "?";
    }
}
static void *working_set_limit   = (void *)0x7fffffff0000;  /* top of the current working set */
#else
static void *address_space_limit = (void *)0xc0000000;
static void *user_space_limit    = (void *)0x7fff0000;
static void *working_set_limit   = (void *)0x7fff0000;
#endif

static void *host_addr_space_limit;  /* top of the host virtual address space */

static struct file_view *arm64ec_view;

/* X3c: EC bitmap base for wiring EcCodeBitMap into cross-arch child PEBs
 * (alloc_arm64ec_map only sets it on the PEB current at first allocation). */
void *ios_arm64ec_bitmap_base(void)
{
    return arm64ec_view ? arm64ec_view->base : NULL;
}

ULONG_PTR user_space_wow_limit = 0;
struct _KUSER_SHARED_DATA *user_shared_data = (void *)0x7ffe0000;

/* TEB allocation blocks */
static void *teb_block;
static void **next_free_teb;
static int teb_block_pos;
static struct list teb_list = LIST_INIT( teb_list );

#define ROUND_ADDR(addr,mask) ((void *)((UINT_PTR)(addr) & ~(UINT_PTR)(mask)))
#define ROUND_SIZE(addr,size,mask) (((SIZE_T)(size) + ((UINT_PTR)(addr) & (mask)) + (mask)) & ~(UINT_PTR)(mask))

#define VIRTUAL_DEBUG_DUMP_VIEW(view) do { if (TRACE_ON(virtual)) dump_view(view); } while (0)
#define VIRTUAL_DEBUG_DUMP_RANGES() do { if (TRACE_ON(virtual_ranges)) dump_free_ranges(); } while (0)

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

#ifdef _WIN64  /* on 64-bit the page protection bytes use a 2-level table */
static const size_t pages_vprot_shift = 20;
static const size_t pages_vprot_mask = (1 << 20) - 1;
static size_t pages_vprot_size;
static BYTE **pages_vprot;
#else  /* on 32-bit we use a simple array with one byte per page */
static BYTE *pages_vprot;
#endif

static int use_kernel_writewatch;
#ifdef USE_UFFD_WRITEWATCH
static int uffd_fd, pagemap_fd;
#endif

static struct file_view *view_block_start, *view_block_end, *next_free_view;
static const size_t view_block_size = 0x100000;
static void *preload_reserve_start;
static void *preload_reserve_end;
static BOOL force_exec_prot;  /* whether to force PROT_EXEC on all PROT_READ mmaps */
/* ml1354: force_exec_prot is session-wide; a 32-bit process's own DEP-off state
 * lives in its guest window (ios_wow_force_exec_at, see the WoW64 windows). */
int ios_wow_force_exec_at( const void *addr );
#define FORCE_EXEC_AT(addr) (force_exec_prot || ios_wow_force_exec_at( addr ))
static BOOL enable_write_exceptions;  /* raise exception on writes to executable memory */

struct range_entry
{
    void *base;
    void *end;
};

static struct range_entry *free_ranges;
static struct range_entry *free_ranges_end;


static inline BOOL is_beyond_limit( const void *addr, size_t size, const void *limit )
{
    return (addr >= limit || (const char *)addr + size > (const char *)limit);
}

static inline BOOL is_vprot_exec_write( BYTE vprot )
{
    return (vprot & VPROT_EXEC) && (vprot & (VPROT_WRITE | VPROT_WRITECOPY));
}

/* task #34 [jit-tripwire]: defined below; forward-declared so the fixed-map
 * helpers above its definition can instrument JIT-pool-range clobbers. */
static void ios_jit_range_tripwire( const char *tag, const void *addr, size_t size,
                                    int prot, void *retaddr );

/* mmap() anonymous memory at a fixed address */
void *anon_mmap_fixed( void *start, size_t size, int prot, int flags )
{
    ios_pool_va_warn( "anon_mmap_fixed", start, size );
    assert( !((UINT_PTR)start & host_page_mask) );
    assert( !(size & host_page_mask) );

    ios_jit_range_tripwire( "anon_mmap_fixed", start, size, prot, __builtin_return_address(0) );
    return mmap( start, size, prot, MAP_PRIVATE | MAP_ANON | MAP_FIXED | flags, -1, 0 );
}

/* allocate anonymous mmap() memory at any address */
/* ml134: does [addr,addr+size) touch either JIT pool alias? */
static int ios_jit_pool_intersects( const void *addr, size_t size )
{
    uint64_t a = (uint64_t)(uintptr_t)addr, e = a + size;
    uint64_t rx = (uint64_t)(uintptr_t)ios_jit_rx_base_global;
    uint64_t rw = (uint64_t)(uintptr_t)ios_jit_rw_base_global;
    uint64_t sz = ios_jit_pool_size_global;

    if (!sz) return 0;
    if (rx && a < rx + sz && e > rx) return 1;
    if (rw && a < rw + sz && e > rw) return 1;
    if (ios_jit_low_overlaps( (uintptr_t)a, size )) return 1;   /* madeira-bcd pool-low: region C */
    return 0;
}

/* ml1041: how many 8-byte words can be read upward from `from` without leaving
 * the mapping it sits in.
 *
 * The [bigres] caller scan read 8KB upward from its frame with no limit. On the
 * syscall stack that runs off the top (sp=0x12a38fb50, stack end 0x12a390000)
 * and only ever "worked" because whatever followed the stack happened to be
 * mapped. When it was not, the probe took an AV inside NtAllocateVirtualMemory,
 * the fault was delivered to the guest, and a title died with its own "exited
 * unexpectedly" dialog -- on the very allocation the probe exists to observe,
 * and only on launches where the neighbouring page was unmapped, so it looked
 * like variance. A probe must not break what it measures: ask the kernel where
 * the region ends, and if that cannot be proven, read nothing. */
static int ios_ml1041_readable_words( const void *from, int want )
{
    mach_vm_address_t ra = (mach_vm_address_t)(uintptr_t)from;
    mach_vm_size_t rs = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t ri;
    mach_msg_type_number_t rc = VM_REGION_SUBMAP_INFO_COUNT_64;
    uint64_t room;

    for (;;)
    {
        if (mach_vm_region_recurse( mach_task_self(), &ra, &rs, &depth,
                                    (vm_region_recurse_info_t)&ri, &rc ) != KERN_SUCCESS) return 0;
        if (!ri.is_submap) break;
        depth++;
    }
    if (ra > (mach_vm_address_t)(uintptr_t)from) return 0;          /* `from` itself is unmapped */
    if (!(ri.protection & VM_PROT_READ)) return 0;
    room = ((uint64_t)(ra + rs) - (uint64_t)(uintptr_t)from) / 8;
    return room < (uint64_t)want ? (int)room : want;
}

/* ml1027: last-resort EXPLICIT PLACEMENT for an anonymous mapping.
 *
 * The ladder above asks the kernel to choose, five times, with five different
 * allocation tags. That covers tag-range placement -- but this kernel selects a
 * range by tag AND size, so every one of those attempts can be confined to
 * ranges that are full while other address space is mappable. When all five
 * fail we have proven nothing about the task map as a whole, which is exactly
 * what ml1025's own message says ("other ranges may still be free").
 *
 * The [holes<64G] probe cannot answer it either: it sums gaps BETWEEN mapped
 * regions and never counts the space above the highest mapping, so a small
 * "free" figure there does not mean the map is full.
 *
 * So walk the real map and place the mapping ourselves. BEST FIT -- the
 * smallest gap that fits -- because the whole reason we are here is that a
 * large request needs a large hole, and bisecting the biggest remaining hole to
 * satisfy a small one is how we got into this state. anon_mmap_tryfixed is
 * no-clobber, so a losing race simply fails and we try the next gap.
 *
 * Runs only after a failure that is otherwise fatal, and is bounded: one region
 * walk plus at most MAX_TRY placements. */
/* madeira-bcd: what the last complete walk proved. Every SocialClubHelper.exe
 * start runs V8's partially reserved sandbox, whose fallbacks ask for 16 GB,
 * 8 GB and 4 GB (with an 8 GB - 64 KB padded retry), ten times each: ~35
 * unhinted asks that cannot fit below the ceiling. Each ended in this walk over
 * ~157,000 regions, 170-380 ms under virtual_mutex, so ~9 s per start in which
 * every thread of every process waited for its own memory calls (442 logs, the
 * [jumbo#] +Nms gaps, both runs). The walk also sees the largest gap; while no
 * release has gone through this file since (ios_va_release_epoch) and for at
 * most IOS_PLACE_PROOF_NS, a larger request cannot be placed, so it fails here
 * without walking. Frees outside Wine (the system's own mappings) do not bump
 * the epoch; the time bound limits that. MADEIRA_PLACE_PROOF=0 walks every time. */
#define IOS_PLACE_PROOF_NS (2000ull * 1000 * 1000)
static unsigned long long ios_place_proof_gap;   /* 0: nothing proven */
static uint64_t ios_place_proof_ns;
static unsigned long ios_place_proof_epoch;
static unsigned long ios_place_proof_skips;

static uint64_t ios_place_now_ns( void )
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int ios_place_proof_enabled( void )
{
    static int on = -1;
    if (on < 0)
    {
        /* 0 walks the whole map on every failed large mapping; by default a failed walk is trusted for 2 s until a release. */
        const char *e = getenv( "MADEIRA_PLACE_PROOF" );
        on = !(e && e[0] == '0');
    }
    return on;
}

/* A reservation made after the proof came out of gaps that walk already
 * counted, so releasing it (whole or in part) cannot open a gap larger than the
 * proof allows and need not bump the epoch: V8's 4 GB step reserves 4 GB, finds
 * it misaligned and releases it before every padded retry. The next proof saw
 * them mapped, so it forgets them. virtual_mutex held. */
#define IOS_PLACE_FRESH 16
static struct { uint64_t base, size; } ios_place_fresh[IOS_PLACE_FRESH];
static unsigned int ios_place_fresh_next;

static void ios_place_note_new( const void *base, size_t size )
{
    unsigned int i;

    if (!ios_place_proof_ns || size < (64u << 20)) return;
    i = ios_place_fresh_next++ % IOS_PLACE_FRESH;
    ios_place_fresh[i].base = (uint64_t)(uintptr_t)base;
    ios_place_fresh[i].size = size;
}

static int ios_place_release_is_fresh( const void *start, size_t size )
{
    uint64_t a = (uint64_t)(uintptr_t)start;
    unsigned int i;

    for (i = 0; i < IOS_PLACE_FRESH; i++)
        if (ios_place_fresh[i].size && a >= ios_place_fresh[i].base &&
            a + size <= ios_place_fresh[i].base + ios_place_fresh[i].size) return 1;
    return 0;
}

/* Does a walk that ended with no gap of `largest` or more still hold for `size`? */
static int ios_place_proven_full( size_t size, uint64_t now )
{
    return ios_place_proof_enabled() && ios_place_proof_ns &&
           (unsigned long long)size > ios_place_proof_gap &&
           now - ios_place_proof_ns < IOS_PLACE_PROOF_NS &&
           ios_place_proof_epoch == __atomic_load_n( &ios_va_release_epoch, __ATOMIC_RELAXED );
}

static void *ios_ml1027_place( size_t size, int prot )
{
    mach_vm_address_t raddr = 0x100000000ull;   /* below this is images/furniture */
    mach_vm_address_t ceiling = 0;
    mach_vm_address_t prev_end = 0;
    mach_vm_address_t best_base = 0;
    unsigned long long best_gap = ~0ull;
    unsigned long long largest = 0;   /* any gap, the JIT pool's included: an upper bound */
    unsigned long epoch = __atomic_load_n( &ios_va_release_epoch, __ATOMIC_RELAXED );
    uint64_t t0 = ios_place_now_ns();
    unsigned regions = 0, gaps = 0;
    int truncated = 0;
    natural_t rdepth = 0;
    void *got;
    enum { MAX_TRY = 8 };

    if (ios_place_proven_full( size, t0 ))
    {
        unsigned long n = ++ios_place_proof_skips;
        if (n <= 8 || !(n % 64))
            dprintf( 2, "[mmap-place] #%lu size=0x%lx refused without a walk: the walk %llu ms ago "
                        "found no gap above %llu MB and nothing was released since "
                        "(MADEIRA_PLACE_PROOF=0 walks every time)\n",
                     n, (unsigned long)size, (unsigned long long)((t0 - ios_place_proof_ns) / 1000000),
                     ios_place_proof_gap >> 20 );
        return MAP_FAILED;
    }

    {
        task_vm_info_data_t vmi;
        mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;
        if (task_info( mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &cnt ) == KERN_SUCCESS)
            ceiling = (mach_vm_address_t)vmi.max_address;
    }
    if (!ceiling) return MAP_FAILED;

    /* Pass 1: find the smallest gap that fits. */
    for (;;)
    {
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t icnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        mach_vm_size_t rsize = 0;

        if (mach_vm_region_recurse( mach_task_self(), &raddr, &rsize, &rdepth,
                                    (vm_region_recurse_info_t)&info, &icnt ) != KERN_SUCCESS)
            break;
        if (info.is_submap) { rdepth++; continue; }
        if (raddr >= ceiling) break;
        if (prev_end && raddr > prev_end)
        {
            unsigned long long gap = (unsigned long long)(raddr - prev_end);
            if (gap > largest) largest = gap;
            if (gap >= size && gap < best_gap &&
                !ios_jit_pool_intersects( (void *)prev_end, size ))
            { best_gap = gap; best_base = prev_end; gaps++; }
        }
        if (raddr + rsize > prev_end) prev_end = raddr + rsize;
        /* ADVANCE. Without this, mach_vm_region_recurse keeps returning the SAME
         * region and the walk spins until the cap: the first version of this
         * function reported "200001 regions, highest_mapping_end=0x102d10000" on
         * a map whose regions run past 44G, then derived a bogus 60GB "tail"
         * from that stale prev_end. The existing [phys-map] walk advances like
         * this and completes in ~67k regions. */
        raddr += rsize;
        if (++regions > 200000) { truncated = 1; break; }
    }
    /* The tail above the highest mapping is free space too, and is the one the
     * gap-sum probes never see. */
    /* ...but only if the walk REACHED the top. A truncated walk knows nothing
     * about what lies above where it stopped. */
    if (!truncated && prev_end && prev_end < ceiling)
    {
        unsigned long long tail = (unsigned long long)(ceiling - prev_end);
        if (tail > largest) largest = tail;
        if (tail >= size && tail < best_gap &&
            !ios_jit_pool_intersects( (void *)prev_end, size ))
        { best_gap = tail; best_base = prev_end; gaps++; }
    }
    /* A complete walk bounds every gap from here on until something is released
     * (an empty map below the ceiling proves nothing: keep walking then). */
    if (!truncated && prev_end)
    {
        ios_place_proof_gap = largest;
        ios_place_proof_epoch = epoch;
        ios_place_proof_ns = ios_place_now_ns();
        memset( ios_place_fresh, 0, sizeof(ios_place_fresh) );
        ios_place_fresh_next = 0;
    }

    if (!best_base)
    {
        dprintf( 2, "[mmap-place] ml1027 NO GAP FITS size=0x%lx after %u regions "
                    "(ceiling=0x%llx walk_stopped_at=0x%llx tail=%llu MB gaps_seen=%u, largest gap "
                    "%llu MB, walk %llu ms)%s\n",
                 (unsigned long)size, regions, (unsigned long long)ceiling,
                 (unsigned long long)prev_end,
                 (unsigned long long)(ceiling > prev_end ? (ceiling - prev_end) >> 20 : 0),
                 gaps, largest >> 20, (unsigned long long)((ios_place_now_ns() - t0) / 1000000),
                 truncated ? " [TRUNCATED -- scan INCOMPLETE, NOT a verdict]"
                           : " -- the map really is full for this size" );
        return MAP_FAILED;
    }

    /* Pass 2: try the chosen gap, then walk upward from it a bounded number of
     * times in case someone else took it between the walk and the map. */
    {
        unsigned t;
        mach_vm_address_t base = best_base;

        for (t = 0; t < MAX_TRY; t++)
        {
            got = anon_mmap_tryfixed( (void *)base, size, prot, 0 );
            if (got != MAP_FAILED)
            {
                dprintf( 2, "[mmap-place] ml1027 PLACED size=0x%lx at %p prot=%d "
                            "(best-fit gap %llu MB of %u candidates, try %u) -- all five "
                            "kernel-chosen attempts had failed\n",
                         (unsigned long)size, got, prot, best_gap >> 20, gaps, t + 1 );
                return got;
            }
            base += (mach_vm_address_t)size;
            if (base + size > ceiling) break;
        }
    }
    dprintf( 2, "[mmap-place] ml1027 gap 0x%llx+%llu MB LOST THE RACE %d times size=0x%lx\n",
             (unsigned long long)best_base, best_gap >> 20, MAX_TRY, (unsigned long)size );
    return MAP_FAILED;
}

void *anon_mmap_alloc( size_t size, int prot )
{
    /* ml134 THE #34 CLOBBER, CAUGHT AT LAST.
     *
     * The faulting pool page reported prot=0x3 max_prot=0x3 — max_protection
     * can only DROP via a fresh mapping, never via mprotect, so the blessed RX
     * page (max_prot=0x7) had been REPLACED by a plain RW anon mapping. Not iOS
     * reclaiming a page: something mapped over our executable alias. That is
     * why mprotect(RX) and the read-touch both failed — there was nothing left
     * to restore.
     *
     * ios_jit_range_tripwire instruments every FIXED map and unmap and fired
     * ZERO times, which leaves exactly the case its own comment predicted: "a
     * munmap whose hole a later kernel-pick refilled". This function is that
     * kernel pick, and it was the one path never checked.
     *
     * Detect and REJECT: hold the offending mapping so the kernel cannot return
     * it again, retry, then release the held ones. Clobbering the pool is fatal
     * and unrecoverable, so paying a few extra mmaps to avoid it is always
     * right. Bounded at 8 tries, then accept-and-scream rather than fail the
     * allocation. */
    void *held[8];
    int nheld = 0, i;
    void *ret;

    assert( !(size & host_page_mask) );

    for (;;)
    {
        /* ml902: ask for HEAP-range placement FIRST. Untagged kernel picks
         * fill the default range, spill into CoreAnimation's tag-51 span once
         * that range is tight (ants45: 77 untagged failures, CA aborted at 13
         * min), and ml815 already proved the tagged form is the one that keeps
         * working under pressure. Untagged stays as the fallback. */
        ret = mmap( NULL, size, prot, MAP_PRIVATE | MAP_ANON, VM_MAKE_TAG( VM_MEMORY_MALLOC ), 0 );
        if (ret == MAP_FAILED) ret = mmap( NULL, size, prot, MAP_PRIVATE | MAP_ANON, -1, 0 );
        /* ml815 + ml1025: after the two attempts above, walk a ladder of
         * DISTINCT allocation tags before declaring the address space full.
         *
         * ml814 proved the fatal is an anonymous mmap returning ENOMEM well
         * below any real memory limit. I read "the kernel picks the address" as
         * "placement is therefore ruled out" -- that was wrong. This kernel
         * partitions the address space into ranges and selects one by
         * allocation TAG and size (vm_map_range_configure; the usable windows
         * demonstrably move between launches). A mapping can therefore be
         * confined to a range that is full while other windows are mappable.
         *
         * ml1025: ml815's retry had stopped being a retry. It asked again with
         * VM_MEMORY_MALLOC -- which ml902 had already made the FIRST attempt
         * above -- so the ladder was tagged(MALLOC), untagged, tagged(MALLOC):
         * three mmaps, two strategies, and the third byte-identical to the
         * first. It could only ever fail, and then logged "genuine exhaustion
         * of every range this allocation may use", which was never earned --
         * two ranges had been tried, not every range. A 0x2b414000 (~692MB)
         * RW request died on exactly that path after succeeding in four
         * consecutive earlier runs of the same binary, which is the signature
         * of placement, not exhaustion.
         *
         * So try tags that map to DIFFERENT ranges. These are the malloc size
         * classes plus an application-specific tag; tag 51 is deliberately
         * excluded because it is CoreAnimation's span, which ml902 went out of
         * its way to stop spilling into. This runs ONLY after a failure that is
         * otherwise fatal, so it cannot regress a working path, and it is a
         * bounded walk, not a loop. The log now names the tag that won, and
         * claims exhaustion only of the tags actually attempted. */
        if (ret == MAP_FAILED)
        {
            static const struct { int tag; const char *name; } ml1025_ladder[] = {
                { VM_MEMORY_MALLOC_LARGE,           "MALLOC_LARGE" },
                { VM_MEMORY_MALLOC_HUGE,            "MALLOC_HUGE" },
                { VM_MEMORY_APPLICATION_SPECIFIC_1, "APP_SPECIFIC_1" },
            };
            int saved = errno;
            static unsigned long tag_n;
            unsigned long tn = ++tag_n;
            unsigned int li;

            for (li = 0; li < ARRAY_SIZE(ml1025_ladder); li++)
            {
                void *tagged = mmap( NULL, size, prot, MAP_PRIVATE | MAP_ANON,
                                     VM_MAKE_TAG( ml1025_ladder[li].tag ), 0 );

                if (tagged == MAP_FAILED) continue;
                if (tn <= 32 || (tn % 256) == 0)
                    dprintf( 2, "[mmap-tag] ml1025 #%lu RECOVERED size=0x%lx prot=%d at %p "
                                "via tag %s(%d) after MALLOC+untagged both failed errno=%d "
                                "-- this is RANGE PLACEMENT, not exhaustion\n",
                             tn, (unsigned long)size, prot, tagged,
                             ml1025_ladder[li].name, ml1025_ladder[li].tag, saved );
                ret = tagged;
                break;
            }

            if (ret == MAP_FAILED)
            {
                if (tn <= 32)
                    dprintf( 2, "[mmap-tag] ml1025 #%lu ALL %u TAGS FAILED size=0x%lx prot=%d "
                                "untagged errno=%d last errno=%d -- MALLOC, untagged, "
                                "MALLOC_LARGE, MALLOC_HUGE and APP_SPECIFIC_1 were tried; "
                                "other ranges may still be free\n",
                             tn, (unsigned int)ARRAY_SIZE(ml1025_ladder) + 2,
                             (unsigned long)size, prot, saved, errno );
                errno = saved;
            }
        }
        /* ml1027: the kernel has refused five times; place it ourselves. */
        if (ret == MAP_FAILED)
        {
            int saved = errno;
            ret = ios_ml1027_place( size, prot );
            if (ret == MAP_FAILED) errno = saved;
        }
        /* ml1029: still nothing, and our own holdback may be the only thing in
         * the way. Carve it rather than fail -- see ios_jumbo_holdback_carve. */
        if (ret == MAP_FAILED)
        {
            int saved = errno;
            uintptr_t carved = ios_jumbo_holdback_carve( size );

            if (carved)
            {
                ret = anon_mmap_tryfixed( (void *)carved, size, prot, 0 );
                if (ret == MAP_FAILED)
                    dprintf( 2, "[jumbo-hold] ml1029 carved 0x%llx but the map there FAILED "
                                "errno=%d\n", (unsigned long long)carved, errno );
            }
            if (ret == MAP_FAILED) errno = saved;
        }
        if (ret == MAP_FAILED || !ios_jit_pool_intersects( ret, size )) break;
        dprintf( 2, "[jit-clobber] kernel-pick %p+0x%lx prot=%x landed INSIDE the JIT pool"
                    " (rx=%p rw=%p size=0x%lx) — rejecting, try %d\n",
                 ret, (unsigned long)size, prot, ios_jit_rx_base_global,
                 ios_jit_rw_base_global, (unsigned long)ios_jit_pool_size_global, nheld + 1 );
        if (nheld == 8)
        {
            dprintf( 2, "[jit-clobber] EXHAUSTED 8 retries — ACCEPTING a pool-overlapping"
                        " mapping at %p; expect an exec fault in this range\n", ret );
            break;
        }
        held[nheld++] = ret;
    }
    for (i = 0; i < nheld; i++) munmap( held[i], size );
    return ret;
}

/* task #34 [jit-tripwire]: ml74's fatal page (0x125114000, inside the JIT
 * pool RX view) faulted on EXECUTE with prot=RW max_prot=RW. max_prot can
 * only DROP via a fresh mapping, never via mprotect — so some path REPLACED
 * a pool code page with a plain RW anon mapping (MAP_FIXED clobber, or a
 * munmap whose hole a later kernel-pick refilled). Every wine unmap and
 * fixed-map flows through unmap_area / remove_reserved_area /
 * anon_mmap_fixed / anon_mmap_tryfixed: log any call intersecting the pool
 * RX view or its RW alias, with the instrumented site's return address, so
 * one device run names the culprit. Legit hits exist (pool tail EC_CODE
 * carves, decommit of pool-backed anon RWX) — the log includes the range so
 * they can be told apart from clobbers of live image-copy code. */
static void ios_jit_range_tripwire( const char *tag, const void *addr, size_t size,
                                    int prot, void *retaddr )
{
    uintptr_t a = (uintptr_t)addr, e = a + size;
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
    size_t ps = ios_jit_pool_size_global;
    static volatile int n;

    if (!ps || !addr || !size) return;
    if (!((rx && a < rx + ps && e > rx) || (rw && a < rw + ps && e > rw) ||
          ios_jit_low_overlaps( a, size ))) return;   /* madeira-bcd pool-low: region C too */
    if (__sync_fetch_and_add( &n, 1 ) > 300) return;
    dprintf(2, "[jit-tripwire] %s addr=%p size=0x%lx prot=%d caller=%p (pool rx=%p rw=%p)\n",
            tag, addr, (unsigned long)size, prot, retaddr, (void *)rx, (void *)rw);
}

#ifdef USE_UFFD_WRITEWATCH
static void kernel_writewatch_init(void)
{
    struct uffdio_api uffdio_api;

    uffd_fd = syscall( __NR_userfaultfd, O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY );
    if (uffd_fd == -1) return;

    uffdio_api.api = UFFD_API;
    uffdio_api.features = UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_WP_UNPOPULATED;
    if (ioctl( uffd_fd, UFFDIO_API, &uffdio_api ) || uffdio_api.api != UFFD_API)
    {
        close( uffd_fd );
        return;
    }
    pagemap_fd = open( "/proc/self/pagemap", O_CLOEXEC | O_RDONLY );
    if (pagemap_fd == -1)
    {
        ERR( "Error opening /proc/self/pagemap.\n" );
        close( uffd_fd );
        return;
    }
    use_kernel_writewatch = 1;
    TRACE( "Using kernel write watches.\n" );
}

static void kernel_writewatch_reset( void *start, SIZE_T len )
{
    struct pm_scan_arg arg = { 0 };

    len = ROUND_SIZE( start, len, host_page_mask );
    start = (char *)ROUND_ADDR( start, host_page_mask );

    arg.size = sizeof(arg);
    arg.start = (UINT_PTR)start;
    arg.end = arg.start + len;
    arg.flags = PM_SCAN_WP_MATCHING;
    arg.category_mask = PAGE_IS_WRITTEN;
    arg.return_mask = PAGE_IS_WRITTEN;
    if (ioctl( pagemap_fd, PAGEMAP_SCAN, &arg ) < 0)
        ERR( "ioctl(PAGEMAP_SCAN) failed, err %s.\n", strerror(errno) );
}

static void kernel_writewatch_register_range( struct file_view *view, void *base, size_t size )
{
    struct uffdio_register uffdio_register;
    struct uffdio_writeprotect wp;

    if (!(view->protect & VPROT_WRITEWATCH) || !use_kernel_writewatch) return;

    size = ROUND_SIZE( base, size, host_page_mask );
    base = (char *)ROUND_ADDR( base, host_page_mask );

    /* Transparent huge pages will result in larger areas reported as dirty. */
    madvise( base, size, MADV_NOHUGEPAGE );

    uffdio_register.range.start = (UINT_PTR)base;
    uffdio_register.range.len = size;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_WP;
    if (ioctl( uffd_fd, UFFDIO_REGISTER, &uffdio_register ) == -1)
    {
        ERR( "ioctl( UFFDIO_REGISTER ) failed, %s.\n", strerror(errno) );
        return;
    }

    if (!(uffdio_register.ioctls & UFFDIO_WRITEPROTECT))
    {
        ERR( "uffdio_register.ioctls %s.\n", wine_dbgstr_longlong(uffdio_register.ioctls) );
        return;
    }
    wp.range.start = (UINT_PTR)base;
    wp.range.len = size;
    wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;

    if (ioctl( uffd_fd, UFFDIO_WRITEPROTECT, &wp ) == -1)
        ERR( "ioctl( UFFDIO_WRITEPROTECT ) failed, %s.\n", strerror(errno) );
}

static void kernel_get_write_watches( void *base, SIZE_T size, void **buffer, ULONG_PTR *count, BOOL reset )
{
    struct pm_scan_arg arg = { 0 };
    struct page_region rgns[256];
    SIZE_T buffer_len = *count;
    char *addr, *next_addr;
    int rgn_count, i;
    size_t end, granularity = host_page_size / page_size;

    assert( !(size & page_mask) );

    end = (size_t)((char *)base + size);
    size = ROUND_SIZE( base, size, host_page_mask );
    addr = (char *)ROUND_ADDR( base, host_page_mask );

    arg.size = sizeof(arg);
    arg.vec = (ULONG_PTR)rgns;
    arg.vec_len = ARRAY_SIZE(rgns);
    if (reset) arg.flags |= PM_SCAN_WP_MATCHING;
    arg.category_mask = PAGE_IS_WRITTEN;
    arg.return_mask = PAGE_IS_WRITTEN;

    *count = 0;
    while (1)
    {
        arg.start = (UINT_PTR)addr;
        arg.end = arg.start + size;
        arg.max_pages = (buffer_len + granularity - 1) / granularity;

        if ((rgn_count = ioctl( pagemap_fd, PAGEMAP_SCAN, &arg )) < 0)
        {
            ERR( "ioctl( PAGEMAP_SCAN ) failed, error %s.\n", strerror(errno) );
            return;
        }
        if (!rgn_count) break;

        assert( rgn_count <= ARRAY_SIZE(rgns) );
        for (i = 0; i < rgn_count; ++i)
        {
            size_t c_addr = max( rgns[i].start, (size_t)base );

            rgns[i].end = min( rgns[i].end, end );
            assert( rgns[i].categories == PAGE_IS_WRITTEN );
            while (buffer_len && c_addr < rgns[i].end)
            {
                buffer[(*count)++] = (void *)c_addr;
                --buffer_len;
                c_addr += page_size;
            }
            if (!buffer_len) break;
        }
        if (!buffer_len || rgn_count < arg.vec_len) break;
        next_addr = (char *)(ULONG_PTR)arg.walk_end;
        assert( size >= next_addr - addr );
        if (!(size -= next_addr - addr)) break;
        addr = next_addr;
    }
}
#else
static void kernel_writewatch_init(void)
{
}

static void kernel_writewatch_reset( void *start, SIZE_T len )
{
}

static void kernel_writewatch_register_range( struct file_view *view, void *base, size_t size )
{
}

static void kernel_get_write_watches( void *base, SIZE_T size, void **buffer, ULONG_PTR *count, BOOL reset )
{
    assert( 0 );
}
#endif

static void mmap_add_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;
    struct list *ptr, *next;
    void *end, *area_end;

    assert( !((UINT_PTR)addr & host_page_mask) );
    assert( !(size & host_page_mask) );

    if (!((intptr_t)addr + size)) size--;  /* avoid wrap-around */
    end = (char *)addr + size;

    LIST_FOR_EACH( ptr, &reserved_areas )
    {
        area = LIST_ENTRY( ptr, struct reserved_area, entry );
        area_end = (char *)area->base + area->size;

        if (area->base > end) break;
        /* ml799: never merge a generic range into the FEX arena. Adjacency is
         * enough for the merge below to swallow it, and the type would vanish
         * with no diagnostic -- after which generic placement could allocate
         * inside the arena. Skipping keeps the insert position correct. */
        if (area->fex_only || area->thin_only) continue;
        if (area_end < addr) continue;
        if (area->base > addr)
        {
            area->size += (char *)area->base - (char *)addr;
            area->base = addr;
        }
        if (area_end >= end) return;

        /* try to merge with the following ones */
        while ((next = list_next( &reserved_areas, ptr )))
        {
            struct reserved_area *area_next = LIST_ENTRY( next, struct reserved_area, entry );
            void *next_end = (char *)area_next->base + area_next->size;

            if (area_next->base > end) break;
            list_remove( next );
            free( area_next );
            if (next_end >= end)
            {
                end = next_end;
                break;
            }
        }
        area->size = (char *)end - (char *)area->base;
        return;
    }

    if ((area = malloc( sizeof(*area) )))
    {
        area->base = addr;
        area->size = size;
        area->fex_only = 0;
        area->thin_only = 0;
        list_add_before( ptr, &area->entry );
    }
}

#include "virtual_ios_reserved.c"   /* reserved areas and the user-space limit */
#include "virtual_ios_wow64.c"   /* the WoW64 guest window (docs/WOW64.md) */
#include "virtual_ios_views.c"   /* builtin modules and unix libraries, free ranges, page protections, views */
#include "virtual_ios_socialclub.c"   /* Social Club's Chromium (madeira-bcd) */
#include "virtual_ios_protect.c"   /* protection changes, guest image checks, commits */
#include "virtual_ios_mapping.c"   /* mapping files and images, placeholders, arm64x relocations */
#include "virtual_ios_runtime.c"   /* virtual_init, system info, module mapping, TEBs, LDT, faults, locked I/O */
#include "virtual_ios_alloc.c"   /* the large address space and NtAllocateVirtualMemory */
#include "virtual_ios_free_query.c"   /* NtAllocateVirtualMemoryEx, NtFreeVirtualMemory, NtQueryVirtualMemory */
#include "virtual_ios_sections.c"   /* locking, sections and the rest of the virtual memory API */
