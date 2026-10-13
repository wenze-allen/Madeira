/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Address-space probes and holds, the JIT pool and its module copies (IAT sync, aliases, stale-pointer heal). Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *           ios_va_occupancy_probe                               (ml994)
 *
 * The other half of ios_va_gap_probe. That one prints only FREE gaps >= 1GB,
 * which is precisely the half that cannot answer the question rdr59..rdr62 keep
 * raising: the device's task map tops out at 63 GB, [holes<64G] measures ~6.6 GB
 * free with a largest hole of 4299 MB, and something owns the other ~56 GB.
 * Whether a >=6 GB contiguous reservation is obtainable at all depends entirely
 * on what that something is, and nothing in the log says.
 *
 * So: walk [0, 64G) and name every mapped region >= 64 MB with its Mach user_tag,
 * protections, share mode and resident pages. mach_vm_region_recurse, not
 * mach_vm_region -- the latter returns an object-name port on every call and
 * leaks it.
 */
/***********************************************************************
 *           ios_jumbo_holdback                                   (ml996)
 *
 * Hold the largest free VA hole from BOOT, for one large guest reservation.
 *
 * rdr64 measured the whole problem. The guest's reservation is a hard 8960 MB
 * (rdr61..rdr63: max(7/8 x reported_phys, 8960 MB), and no reported value
 * lowers it). At boot the largest hole below the 63 GB ceiling is 9947 MB --
 * enough. By the time the guest asks it is 8796 MB, because Wine's own
 * furniture took ~700 MB off the bottom (the PEB band lands there) and ~1143 MB
 * off the top. Short by ~164 MB after all that work.
 *
 * Hinting cannot fix that: the hardcoded jumbo slot walk runs from
 * 0x7C00000000 down to 0x6800000000, every candidate above this device's
 * 0xfc0000000 ceiling, so all of them fail by construction -- the same
 * hardcoded-band defect ml706 fixed for the FEX band. And a hint is useless
 * against a hole that is simply too small. The hole has to be RESERVED before
 * anything else can nibble it, which is what ml977 does for the fixed-base
 * image window and what ios_cage_holdback does for the 8GB V8 cage.
 *
 * OPT-IN via Documents/madeira-jumbo-mb.txt, so the default path is unchanged
 * and nothing regresses on hardware or for the titles that currently work. The
 * cost is real and must be measured, not assumed: holding ~9 GB forces Wine's
 * furniture into the remaining holes (4175 MB low, plus whatever the arena
 * leaves), and if that does not fit, the desktop breaks instead of the game.
 */
static uintptr_t ios_jumbo_hold_base;
static size_t    ios_jumbo_hold_size;
/* madeira-bcd: bumped by every release of address space through this file
 * (unmap_area, remove_reserved_area, the jumbo holdback, the V8 cage, the image
 * window, Social Club's slots and BRP hold); a placement walk that found no gap
 * stays true only while it is unchanged (ios_ml1027_place). */
static unsigned long ios_va_release_epoch;
static inline void ios_va_release_note( void )
{
    __atomic_add_fetch( &ios_va_release_epoch, 1, __ATOMIC_RELAXED );
}
/* ml1029: how much of the holdback must stay reserved for the ONE big guest
 * reservation. Anything above this may be carved off the TOP to satisfy an
 * allocation that would otherwise fail outright. Read from
 * madeira-jumbo-keep-mb.txt; 0 (absent) => keep everything, i.e. exactly the
 * pre-ml1029 behaviour. */
static size_t    ios_jumbo_hold_keep;
/* madeira-bcd: the smallest request the holdback goes to; 0 (jumbo-mb) => any.
 * env.MADEIRA_RDR2_VA_HOLD's hold goes only to RDR2.exe's 8960 MB: Social
 * Club's hinted 1 GB reserve (jumbo#19 in build 457's log) reaches the same
 * take() whenever its slot walk finds no room. */
static size_t    ios_jumbo_hold_min;

static void *anon_mmap_tryfixed( void *start, size_t size, int prot, int flags );

void ios_jumbo_holdback_init( void )
{
    static int done;
    unsigned long long want = 0, ceiling = 0;
    mach_vm_address_t addr = 0, prev_end = 0, best_at = 0;
    unsigned long long best = 0;
    task_vm_info_data_t vmi;
    mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;
    void *got;

    if (done) return;
    done = 1;

    want = (size_t)(madeira_cfg_int( "jumbo-mb", 0 ) * 1024ll * 1024ll);   /* ml1095: madeira.cfg jumbo-mb = N */
    if (!want) return;                       /* opt-in: absent or 0 => off */
    if (ios_jumbo_hold_size)                 /* madeira-bcd: env.MADEIRA_RDR2_VA_HOLD's hold, from virtual_init */
    {
        dprintf( 2, "[jumbo-hold] jumbo-mb = %llu ignored: 0x%llx +%llu MB is already held (MADEIRA_RDR2_VA_HOLD)\n",
                 want >> 20, (unsigned long long)ios_jumbo_hold_base,
                 (unsigned long long)(ios_jumbo_hold_size >> 20) );
        return;
    }

    /* ml1029: the keep floor, same units. ml1095: madeira.cfg jumbo-keep-mb = N */
    ios_jumbo_hold_keep = (size_t)(madeira_cfg_int( "jumbo-keep-mb", 0 ) * 1024ll * 1024ll);
    if (ios_jumbo_hold_keep)
        dprintf( 2, "[jumbo-hold] ml1029 keep floor from jumbo-keep-mb: "
                    "%llu MB (the rest of the holdback may be carved off the top)\n",
                 (unsigned long long)ios_jumbo_hold_keep >> 20 );

    if (task_info( mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &cnt ) == KERN_SUCCESS)
        ceiling = (unsigned long long)vmi.max_address;
    if (!ceiling) ceiling = 0x1000000000ull;

    /* largest free hole below the ceiling */
    while (addr < ceiling)
    {
        mach_vm_size_t size = 0;
        natural_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t c2 = VM_REGION_SUBMAP_INFO_COUNT_64;

        if (mach_vm_region_recurse( mach_task_self(), &addr, &size, &depth,
                                    (vm_region_recurse_info_t)&info, &c2 ) != KERN_SUCCESS)
            break;
        if (addr >= ceiling) break;
        if (addr > prev_end && (unsigned long long)(addr - prev_end) > best)
        {
            best = (unsigned long long)(addr - prev_end);
            best_at = prev_end;
        }
        prev_end = addr + size;
        addr = prev_end;
    }
    if (prev_end < ceiling && (unsigned long long)(ceiling - prev_end) > best)
    {
        best = (unsigned long long)(ceiling - prev_end);
        best_at = prev_end;
    }

    dprintf( 2, "[jumbo-hold] ml996 want=%llu MB; largest free hole 0x%llx +%llu MB "
             "(ceiling 0x%llx)\n", want >> 20, (unsigned long long)best_at, best >> 20,
             ceiling );
    if (best < want)
    {
        dprintf( 2, "[jumbo-hold] ml996 NOT holding: the largest hole is smaller than the "
                 "request. Nothing to reserve, and a partial hold would only fragment it\n" );
        return;
    }

    /* place at the TOP of the hole: Wine's furniture and the PEB band grow from
     * the bottom, so leaving the bottom free is what keeps them out of here. */
    {
        uintptr_t base = (uintptr_t)(best_at + (best - want));
        base &= ~(uintptr_t)0xffff;          /* 64K granule */
        got = anon_mmap_tryfixed( (void *)base, (size_t)want, PROT_NONE, MAP_NORESERVE );
        if (got == MAP_FAILED)
        {
            dprintf( 2, "[jumbo-hold] ml996 reserve of 0x%llx +%llu MB FAILED errno=%d -- not "
                     "overwriting anything; the guest reservation will fail as before\n",
                     (unsigned long long)base, want >> 20, errno );
            return;
        }
        ios_jumbo_hold_base = (uintptr_t)got;
        ios_jumbo_hold_size = (size_t)want;
        dprintf( 2, "[jumbo-hold] ml996 HELD 0x%llx +%llu MB PROT_NONE (no-overwrite) for one "
                 "large guest reservation\n",
                 (unsigned long long)ios_jumbo_hold_base, want >> 20 );
    }
}

/* Returns the held base if this request can be served from it, else 0. The
 * caller maps at that address; the hold is released first and consumed once. */
static uintptr_t ios_jumbo_holdback_take( size_t size )
{
    uintptr_t base = ios_jumbo_hold_base;

    if (!ios_jumbo_hold_size || size > ios_jumbo_hold_size || size < ios_jumbo_hold_min) return 0;
    dprintf( 2, "[jumbo-hold] ml996 releasing the holdback 0x%llx +%llu MB for a %llu MB "
             "request\n", (unsigned long long)base,
             (unsigned long long)ios_jumbo_hold_size >> 20,
             (unsigned long long)size >> 20 );
    munmap( (void *)base, ios_jumbo_hold_size );
    ios_va_release_note();
    ios_jumbo_hold_base = 0;
    ios_jumbo_hold_size = 0;
    return base;
}

/* ml1029: carve `size` off the TOP of the holdback, or 0 if it cannot be spared.
 *
 * WHY: the holdback reserves one large hole for the guest's single big
 * reservation. But the guest also makes a ~692MB commit during startup, and the
 * ORDER of the two varies between runs. rdr98 got the big ask first, which
 * consumed the holdback and left the 692MB ask free to use the released space --
 * that run reached the loading screen and rendered. rdr99 got the 692MB ask
 * FIRST, and it died: our own 9216MB holdback was the reason the placement scan
 * reported `gaps_seen=0`. We starved a request happening NOW to protect one that
 * might never come, and the game dies either way. That is the coin flip that has
 * made this failure look like variance for a dozen runs.
 *
 * Both fit: 8960 + 692 = 9652 MB inside the 9907 MB hole the holdback is cut
 * from. So serve both out of it -- take() hands out the BOTTOM (it returns
 * `base`), so carving comes off the TOP and the two never collide.
 *
 * The keep floor is a config value and defaults to "keep everything", so this
 * cannot change behaviour for the titles that depend on the arena/holdback
 * today unless it is explicitly turned on. */
static uintptr_t ios_jumbo_holdback_carve( size_t size )
{
    uintptr_t top, at;

    if (!ios_jumbo_hold_size || !ios_jumbo_hold_keep) return 0;
    if (size > ios_jumbo_hold_size) return 0;
    if (ios_jumbo_hold_size - size < ios_jumbo_hold_keep) return 0;

    top = ios_jumbo_hold_base + ios_jumbo_hold_size;
    at  = (top - size) & ~(uintptr_t)0xffff;      /* 64K granule */
    if (at < ios_jumbo_hold_base) return 0;
    size = (size_t)(top - at);
    if (ios_jumbo_hold_size - size < ios_jumbo_hold_keep) return 0;

    /* Release just this slice; the rest of the holdback stays PROT_NONE-held. */
    if (munmap( (void *)at, size ) != 0)
    {
        dprintf( 2, "[jumbo-hold] ml1029 carve munmap(0x%llx +%llu MB) FAILED errno=%d\n",
                 (unsigned long long)at, (unsigned long long)size >> 20, errno );
        return 0;
    }
    ios_va_release_note();
    ios_jumbo_hold_size -= size;
    dprintf( 2, "[jumbo-hold] ml1029 CARVED 0x%llx +%llu MB off the top; holdback now "
                "0x%llx +%llu MB (keep floor %llu MB) -- this request would otherwise have "
                "FAILED with the holdback as the only thing in its way\n",
             (unsigned long long)at, (unsigned long long)size >> 20,
             (unsigned long long)ios_jumbo_hold_base,
             (unsigned long long)ios_jumbo_hold_size >> 20,
             (unsigned long long)ios_jumbo_hold_keep >> 20 );
    return at;
}


static void ios_va_occupancy_probe( const char *why )
{
    const mach_vm_address_t LIMIT = 0x1000000000ULL;   /* 64G, the carveout floor */
    mach_vm_address_t addr = 0, prev_end = 0, biggest_at = 0;
    unsigned long long mapped_mb = 0, free_mb = 0, biggest = 0;
    int shown = 0, regions = 0;

    dprintf( 2, "[va-own] ==== occupancy below 64G (%s) ====\n", why );
    while (addr < LIMIT)
    {
        mach_vm_size_t size = 0;
        natural_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;

        if (mach_vm_region_recurse( mach_task_self(), &addr, &size, &depth,
                                    (vm_region_recurse_info_t)&info, &cnt ) != KERN_SUCCESS)
            break;
        if (addr >= LIMIT) break;
        if (addr > prev_end)
        {
            unsigned long long gap = (unsigned long long)(addr - prev_end);
            free_mb += gap >> 20;
            if (gap > biggest) { biggest = gap; biggest_at = prev_end; }
        }
        regions++;
        mapped_mb += (unsigned long long)(size >> 20);
        if (size >= 64ull * 1024 * 1024 && shown < 48)
        {
            dprintf( 2, "[va-own] 0x%011llx +%7llu MB prot=%x/%x tag=%-3u share=%u res=%u MB%s\n",
                     (unsigned long long)addr, (unsigned long long)(size >> 20),
                     info.protection, info.max_protection, info.user_tag,
                     info.share_mode,
                     (unsigned)(((unsigned long long)info.pages_resident * 4096) >> 20),
                     depth ? " (submap)" : "" );
            shown++;
        }
        prev_end = addr + size;
        addr = prev_end;
    }
    if (prev_end < LIMIT)
    {
        unsigned long long gap = (unsigned long long)(LIMIT - prev_end);
        free_mb += gap >> 20;
        if (gap > biggest) { biggest = gap; biggest_at = prev_end; }
    }
    dprintf( 2, "[va-own] ==== %d regions, mapped=%llu MB free=%llu MB largest_free=%llu MB "
             "at 0x%llx (listed %d of size >=64MB) ====\n",
             regions, mapped_mb, free_mb, biggest >> 20,
             (unsigned long long)biggest_at, shown );
}


/* ml89: report the RX alias's protections for a pool range, WITHOUT touching
 * them. The first version of this guard probed with mprotect(RX) and dropped
 * any range that returned EACCES — but 62 of 62 candidates failed and not one
 * succeeded, which is the signature of a probe that can never pass rather than
 * of 62 genuinely dead ranges. mprotect on debugger-blessed pool memory is
 * refused outright (same family as the share-probe's kr=2 on OVERWRITE), so it
 * says nothing about executability. mach_vm_region reads max_protection
 * directly and mutates nothing. Returns 1 if the range still permits exec. */
static int ios_pool_range_execable(size_t off, size_t range_size,
                                   unsigned int *cur_out, unsigned int *max_out)
{
    /* ml242 FIX: scan the WHOLE range, not just its first page.
     *
     * This guard existed and its intent was right, but it queried exactly one address --
     * rx_base + off -- so it only ever saw the START page. Every poisoned page measured
     * sits deeper in (+0x30000, +0x60000, +0x90000, +0xb0000, +0xd0000, +0xe0000), so the
     * start looked clean, the guard passed, and the range was recycled with a permanently
     * non-executable page inside it. That page later lands in a module's .text, mprotect(RX)
     * can never restore EXEC (maxprot only ever lowers), and execution there faults NOEXEC
     * -- killing the process (this run: dbghelp.dll+0x6da14).
     *
     * Measured discriminator: 29 of 29 poisoned ranges had reused=1; virgin bump memory was
     * never poisoned. So recycled VA carrying narrowed maxprot is the whole mechanism.
     *
     * Walks region-by-region (mach_vm_region returns each region's size) rather than page
     * by page, so this is O(regions) and cheap even for multi-MB ranges. */
    mach_vm_address_t base, a, end;

    if (!ios_jit_rx_base_global) return 1;
    base = (mach_vm_address_t)(uintptr_t)((char *)ios_jit_rx_base_global + off);
    end  = base + (range_size ? range_size : 1);

    for (a = base; a < end; )
    {
        mach_vm_address_t q = a;
        mach_vm_size_t sz = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;

        if (mach_vm_region( mach_task_self(), &q, &sz, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS)
            return 1;      /* can't tell — don't drop the range on a failed query */
        if (q >= end) break;
        if (q > a) { a = q; continue; }   /* gap: skip to the next real region */
        if (!sz) break;

        if (!(info.max_protection & VM_PROT_EXECUTE))
        {
            if (cur_out) *cur_out = (unsigned int)info.protection;
            if (max_out) *max_out = (unsigned int)info.max_protection;
            return 0;      /* poisoned somewhere in the range — refuse it */
        }
        if (a == base)
        {
            if (cur_out) *cur_out = (unsigned int)info.protection;
            if (max_out) *max_out = (unsigned int)info.max_protection;
        }
        a = q + sz;
    }
    return 1;
}

/* madeira-bcd: the parts of a POISONED freed range that are still executable.
 *
 * Every range the dead SocialClubHelper.exe processes freed was dropped as
 * POISONED (GTA V Enhanced, 2026-10-02 16:19: 103 ranges, 128 MB of a 608 MB
 * pool), and [pool-freechk] names the cause: single 16 KB regions with
 * cur=max=RW (share_mode 5) inside otherwise blessed code memory -- pages an
 * image's pool copy had aliased while it lived. Only those pages are lost; the
 * runs between them are as executable as virgin pool memory. `run_off` /
 * `run_size` get up to `max` such runs of at least 64 KB; returns their count.
 * `region` answers like mach_vm_region (base and size of the first region at
 * or above *addr, its max_prot); it is a parameter for the host test. */
typedef int (*ios_pool_region_fn)( uint64_t *addr, uint64_t *size, unsigned int *max_prot );

static int ios_pool_execable_runs( uint64_t base, size_t off, size_t size, ios_pool_region_fn region,
                                   size_t *run_off, size_t *run_size, int max )
{
    uint64_t a = base + off, end = base + off + size, run = 0;
    int n = 0, in_run = 0;

    while (a < end)
    {
        uint64_t q = a, sz = 0, next;
        unsigned int mp = 0;
        int exec;

        if (region( &q, &sz, &mp ) || !sz || q >= end) { q = end; sz = 0; }   /* nothing mapped to the end */
        if (q > a) { exec = 0; next = q; }                        /* unmapped gap [a, q) */
        else { exec = (mp & 4 /* VM_PROT_EXECUTE */) != 0; next = q + sz; }
        if (next > end) next = end;
        if (next <= a) { exec = 0; next = end; }                  /* nonsense answer: stop here */
        if (exec && !in_run) { run = a; in_run = 1; }
        if (!exec && in_run)
        {
            if (a - run >= 0x10000 && n < max) { run_off[n] = (size_t)(run - base); run_size[n] = (size_t)(a - run); n++; }
            in_run = 0;
        }
        a = next;
    }
    if (in_run && a - run >= 0x10000 && n < max) { run_off[n] = (size_t)(run - base); run_size[n] = (size_t)(a - run); n++; }
    return n;
}

/* madeira-bcd: put a freed range on the freelist (at most `max` entries),
 * merged with every adjacent entry `clean` accepts, so a dead process's
 * ranges, and a big range a small image was carved from, join up again.
 * Returns 0 when the list is full (the range is leaked, as before). */
typedef int (*ios_pool_clean_fn)( size_t off, size_t size );

static int ios_pool_range_execable( size_t off, size_t range_size, unsigned int *cur_out, unsigned int *max_out );
static int ios_pool_range_clean( size_t off, size_t size )
{
    return ios_pool_range_execable( off, size, NULL, NULL );
}

static int ios_pool_free_put( struct ios_pool_free *fl, int *n, int max, size_t off, size_t size, time_t now,
                              ios_pool_clean_fn clean )
{
    int i, merged;

    do
    {
        merged = 0;
        for (i = 0; i < *n; i++)
        {
            if (fl[i].off + fl[i].size != off && off + size != fl[i].off) continue;
            if (!clean( fl[i].off, fl[i].size )) continue;
            if (fl[i].off < off) off = fl[i].off;
            size += fl[i].size;
            fl[i] = fl[--*n];
            merged = 1;
            break;
        }
    } while (merged);
    if (*n >= max) return 0;
    fl[*n].off = off;
    fl[*n].size = size;
    fl[*n].freed_at = now;
    fl[*n].advised = 0;
    (*n)++;
    return 1;
}

static int ios_pool_mach_region( uint64_t *addr, uint64_t *size, unsigned int *max_prot )
{
    mach_vm_address_t q = (mach_vm_address_t)*addr;
    mach_vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;

    if (mach_vm_region( mach_task_self(), &q, &sz, VM_REGION_BASIC_INFO_64,
                        (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS) return -1;
    *addr = q;
    *size = sz;
    *max_prot = (unsigned int)info.max_protection;
    return 0;
}

/* iOS-Madeira: secondary user_VA → JIT pool aliases mapping for anonymous
 * RWX regions (e.g. FEX CodeBuffer). When user_VA is vm_remap'd from JIT pool
 * RX, writes via user_VA fault and the STR fault emulator looks up the RW
 * alias here. Execution faults at user_VA are redirected to the RX alias
 * (which is the only address that's actually executable on iOS TXM).
 * Declared above ios_pool_alloc_range so the allocator can purge stale
 * entries when it recycles a pool range. */
/* iOS-Madeira ml630: 32 -> 4096.
 *
 * ULTRAKILL/Mono ran the table dry: `[jit-pool] anon alias table FULL (32 slots)
 * -- writes to 0x705f9d0000 will NOT route!`. The new Mono code buffer then had NO
 * RW alias, so `stur q1,[x6,#-0x40]` into it could not be routed, became an
 * unhandled 0x80000002, and wine's unwinder then read the half-written unwind
 * metadata out of that same unpatched buffer and looped ~15.8M times until the
 * main thread's 8MB stack was gone. tid 007c exited and every Unity/DXMT worker
 * was orphaned -- all downstream of ONE exhausted 32-entry array.
 *
 * 4096 entries is ~128KB, still a flat array safe for the lock-free reader in the
 * signal handler. 64 would have been far too marginal: Mono keeps many buffers
 * live at once. ⛔ Do NOT "fix" this class by enlarging the guest stack -- that
 * only lets a runaway unwind run longer. */
#define IOS_JIT_MAX_ANON_ALIASES 4096
struct ios_jit_anon_alias {
    uintptr_t user_va;
    uintptr_t user_va_end;
    uintptr_t jit_rw_alias;
    uintptr_t jit_rx_alias;
};
static struct ios_jit_anon_alias ios_jit_anon_aliases[IOS_JIT_MAX_ANON_ALIASES];
static volatile int ios_jit_anon_alias_count = 0;
/* ml630: census — live entries, tombstones (reclaimed slots) and the high-water
 * mark, so "how close are we to the ceiling" is answerable from any run. */
static volatile int ios_jit_anon_alias_live = 0;
static volatile int ios_jit_anon_alias_hiwater = 0;
static volatile int ios_jit_anon_alias_tombstones = 0;
/* iOS-Madeira ml635: per-alias write telemetry.
 *
 * The iOS Mach write path emulates a store through the RW alias and then simply
 * advances PC — it NEVER invalidates FEX's cached translation, unlike the normal
 * ARM64EC path (Module.cpp HandleRWXAccessViolation). So FEX can translate a page
 * while it is still zeros, Mono can then fill it through millions of emulated
 * writes, and execution keeps following the STALE zero translation until it runs
 * off the end of the mapping. These counters decide that outright:
 *   write_gen  — bumped on every emulated write into this alias
 *   written    — bit per 16KB chunk that has EVER been written (first 32 chunks) */
static volatile unsigned int ios_alias_write_gen[IOS_JIT_MAX_ANON_ALIASES];
static volatile unsigned int ios_alias_written[IOS_JIT_MAX_ANON_ALIASES];
static volatile unsigned long long ios_alias_highest[IOS_JIT_MAX_ANON_ALIASES];

void ios_jit_anon_alias_note_write( unsigned long long addr )
{
    int n = ios_jit_anon_alias_count, i;
    for (i = 0; i < n; i++)
    {
        uintptr_t b = ios_jit_anon_aliases[i].user_va;
        if (!b || addr < b || addr >= ios_jit_anon_aliases[i].user_va_end) continue;
        __sync_add_and_fetch( &ios_alias_write_gen[i], 1 );
        {
            unsigned chunk = (unsigned)((addr - b) >> 14);   /* 16KB chunks */
            if (chunk < 32) __sync_or_and_fetch( &ios_alias_written[i], 1u << chunk );
            {   /* ml636: highest byte ever written — the tail question needs finer
                 * resolution than a 16KB bitmap. Monotonic CAS, no lock. */
                unsigned long long off = (addr - b) + 1, cur;
                do { cur = ios_alias_highest[i]; if (off <= cur) break; }
                while (!__sync_bool_compare_and_swap( &ios_alias_highest[i], cur, off ));
            }
        }
        return;
    }
}

/* madeira-bcd: the freelist entry a request of `want` bytes takes: the
 * SMALLEST grace-expired range in reach that holds it (first of equals), or -1.
 * First-fit carved the small images of a restarted process out of the big
 * range its predecessor's libcef.dll copy had freed (GTA log 2026-10-02 18:24:
 * "reused freed range off=0x148c0000 size=0x94000" inside the dead helper's
 * 0xefc0000 libcef range), so the next libcef.dll found no 239 MB run --
 * EXHAUSTED for helpers 2 to 19 while 256 ranges sat on the list. Best-fit
 * hands each image the range of its own size first. */
static int ios_pool_best_fit( const struct ios_pool_free *fl, int n, size_t want, time_t now,
                              size_t anchor_off, size_t max_dist )
{
    int i, best = -1;

    for (i = 0; i < n; i++)
    {
        size_t o = fl[i].off;
        if (fl[i].size < want) continue;
        if (now - fl[i].freed_at < IOS_POOL_REUSE_GRACE_SEC) continue;
        if (anchor_off != (size_t)-1 && (o > anchor_off ? o + want - anchor_off : anchor_off - o) > max_dist) continue;
        if (best < 0 || fl[i].size < fl[best].size) best = i;
    }
    return best;
}

/* madeira-bcd: leave a freed range of 32 MB or more that is over four times the
 * request to a big image when the bump can serve the request instead. In the
 * 18:24 log 20 of the dead helper's 51 ranges were POISONED at free, so their
 * images could not take their own ranges back and carved the libcef.dll one. */
static int ios_pool_keep_big( size_t range, size_t want, int bump_ok )
{
    return bump_ok && range >= 32u * 1024 * 1024 && range / 4 >= want;
}

/* Allocate a page-aligned range from the pool head: free list first
 * (grace-expired best-fit, ios_pool_best_fit; remainder returned to the
 * list), bump second.
 * Returns (size_t)-1 on exhaustion WITHOUT consuming any pool space (the
 * old fetch_and_add-then-check burned the offset on every failed retry).
 * `pool_limit` = usable head bytes (pool size minus tail reservation).
 *
 * anchor_off/max_dist (Steam S3 run 11 ROOT CAUSE): the x18 patcher emits
 * B/BL from a module's .text to its trampoline range — ARM64 imm26 reaches
 * only ±128MB, and with the 640MB pool + freelist fragmentation SHELL32's
 * tramps landed 230MB below its image. The encoder silently truncated the
 * offset (mod 256MB) → branches into untouched pool → the entire
 * "poison pointer / zeroed tramp" crash family (runs 7-11, proven by
 * imm26 0x90A311 == truncation of -0xDBD73BC). Pass anchor_off = the
 * image's pool offset and max_dist to force the range within branch
 * reach; (size_t)-1 anchor = unconstrained (old behavior). */
static size_t ios_pool_alloc_range_ex( size_t alloc_size, size_t pool_limit,
                                       size_t anchor_off, size_t max_dist )
{
    size_t off = (size_t)-1;
    time_t now = time( NULL );
    int i, bump_ok;

    /* Reclaimed image ranges can also live in region C. WoW64's emulator
     * accepts executable storage only inside the main pool span. */
    if (ios_jit_low_size_global && ios_wow_base() && anchor_off == (size_t)-1)
    {
        anchor_off = 0;
        max_dist = ios_jit_pool_size_global;
    }

#define IOS_POOL_IN_REACH(o) \
    (anchor_off == (size_t)-1 || \
     ((o) > anchor_off ? (o) + alloc_size - anchor_off : anchor_off - (o)) <= max_dist)

    pthread_mutex_lock( &ios_pool_lock );

    /* ml1052: a LARGE request that a freed range could serve, but only once its
     * grace expires, used to fall through to the bump allocator. A launcher
     * generation that maps a 117 MB fixed-base image and exits, followed at once
     * by the real process mapping the same image, therefore cost the pool 234 MB
     * of head for one program -- and the head's high-water mark is what the JIT
     * code buffers (the tail) are refused against. Waiting out the remaining
     * grace (<= 3 s, once, at process start) keeps the grace guarantee intact and
     * gives that space back to the code cache. */
    /* madeira-bcd: wait the same way for ANY request the bump cannot serve.
     * GTA build 364 (2026-10-03 21:00): RockstarService.exe exited, RECLAIM put
     * 25 MB on the freelist (freelist=20), and for the next 1.4 s every load in
     * the launcher (uxtheme, gameoverlayrenderer64, socialclub, netprofm,
     * rpcss.exe, d2d1) failed EXHAUSTED inside the 3 s grace -- the launcher
     * died at d2d1. pool_limit 0 (the tail's freelist-only take) keeps the old
     * rule. */
    int bump_short = 0;
    /* madeira-bcd: the big-image slot (ios_pool_big_off), once it is free and
     * past the reuse grace of its previous owner -- waited out here, as for a
     * freed range below: a restarted SocialClubHelper.exe asks again within it. */
    if (pool_limit && ios_pool_big_size && !ios_pool_big_taken && alloc_size >= IOS_POOL_BIG_MIN &&
        alloc_size <= ios_pool_big_size)
    {
        int waited = 0;
        while (now - ios_pool_big_freed_at < IOS_POOL_REUSE_GRACE_SEC && waited < 40)
        {
            pthread_mutex_unlock( &ios_pool_lock );
            { struct timespec ts = { 0, 100 * 1000 * 1000 }; nanosleep( &ts, NULL ); }
            waited++;
            pthread_mutex_lock( &ios_pool_lock );
            now = time( NULL );
        }
        if (waited)
            dprintf(2, "[pool-big] madeira-bcd waited %d00 ms for the slot's reuse grace\n", waited);
    }
    if (pool_limit && ios_pool_big_size && !ios_pool_big_taken && alloc_size >= IOS_POOL_BIG_MIN &&
        alloc_size <= ios_pool_big_size && now - ios_pool_big_freed_at >= IOS_POOL_REUSE_GRACE_SEC &&
        IOS_POOL_IN_REACH(ios_pool_big_off))
    {
        off = ios_pool_big_off;
        ios_pool_big_taken = 1;
        ios_pool_last_alloc_reused = 0;
        dprintf(2, "[pool-big] madeira-bcd 0x%lx bytes placed in the big-image slot at off 0x%lx (bump=0x%lx)\n",
                (unsigned long)alloc_size, (unsigned long)off, (unsigned long)jit_pool_offset);
    }
    else if (pool_limit && ios_pool_big_size && alloc_size >= IOS_POOL_BIG_MIN)
        dprintf(2, "[pool-big] madeira-bcd 0x%lx bytes: slot %s -- normal placement\n", (unsigned long)alloc_size,
                ios_pool_big_taken ? "taken" : alloc_size > ios_pool_big_size ? "too small"
                : now - ios_pool_big_freed_at < IOS_POOL_REUSE_GRACE_SEC ? "in its reuse grace" : "out of reach");
    if (pool_limit && off == (size_t)-1)
    {
        size_t cand = ios_pool_holes_head_place( jit_pool_offset, alloc_size, ios_jit_hole_off_eff, ios_jit_hole_end_eff,
                                                 ios_jit_hole2_off, ios_jit_hole2_end );
        bump_short = cand + alloc_size > pool_limit;
    }
    if (off == (size_t)-1 && (alloc_size >= 32u * 1024 * 1024 || bump_short))
    {
        int waited = 0;
        for (;;)
        {
            int ready = 0, pending = 0;
            now = time( NULL );
            for (i = 0; i < ios_pool_free_count; i++)
            {
                if (ios_pool_freelist[i].size < alloc_size) continue;
                if (!IOS_POOL_IN_REACH(ios_pool_freelist[i].off)) continue;
                if (now - ios_pool_freelist[i].freed_at < IOS_POOL_REUSE_GRACE_SEC) pending = 1; else ready = 1;
            }
            if (ready || !pending || waited >= 40) break;
            pthread_mutex_unlock( &ios_pool_lock );
            { struct timespec ts = { 0, 100 * 1000 * 1000 }; nanosleep( &ts, NULL ); }
            waited++;
            pthread_mutex_lock( &ios_pool_lock );
        }
        if (waited && bump_short)
        {
            static int pool_wait_n;
            if (pool_wait_n++ < 32)
                dprintf(2, "[pool-wait] bump short: waited %d00 ms for a freed range's grace to expire rather than "
                        "fail 0x%lx bytes (bump=0x%lx limit=0x%lx freelist=%d)\n", waited, (unsigned long)alloc_size,
                        (unsigned long)jit_pool_offset, (unsigned long)pool_limit, ios_pool_free_count);
        }
        else if (waited)
            dprintf(2, "[jit-pool] ml1052 waited %d00 ms for a freed range's grace to expire rather than bump 0x%lx bytes of head\n",
                    waited, (unsigned long)alloc_size);
        now = time( NULL );
    }

    /* Post-grace, return each freed range's physical pages to the OS.
     * NO_FOOTPRINT exempts the pool from OUR jetsam ledger, but dirty
     * pages still consume device RAM — 300MB of dead copies pressures
     * the rest of the system (prime suspect for StikDebug dying →
     * debugger-suspension freezes + "JIT detached"). Deferred past the
     * grace window so laggard exit threads never execute a purged page. */
    for (i = 0; i < ios_pool_free_count; i++)
    {
        if (ios_pool_freelist[i].advised) continue;
        if (now - ios_pool_freelist[i].freed_at < IOS_POOL_REUSE_GRACE_SEC) continue;
        /* task #34 belt: NEVER volatilize a range that overlaps a LIVE ledger
         * entry. Freelist and ledger are disjoint by design (free removes the
         * ledger entry), so any overlap here is an accounting bug — and
         * MADV_FREE on live pool memory is exactly the "iOS zero-harvests
         * executing code" death seen in ml74 (Steam pressure makes the
         * harvest actually happen; Thumper never pushed hard enough). Skip
         * the range, log loudly, and keep it un-advised so we re-check. */
        {
            int j, live_overlap = 0;
            size_t f_off = ios_pool_freelist[i].off, f_end = f_off + ios_pool_freelist[i].size;
            for (j = 0; j < ios_pool_ledger_count; j++)
            {
                size_t l_off = ios_pool_ledger[j].off, l_end = l_off + ios_pool_ledger[j].size;
                if (l_off < f_end && l_end > f_off) { live_overlap = 1; break; }
            }
            if (live_overlap)
            {
                dprintf(2, "[jit-pool] SWEEP SKIPPED live-overlap: freed off=0x%lx+0x%lx overlaps ledger off=0x%lx+0x%lx peb=%p — accounting bug, NOT volatilizing\n",
                        (unsigned long)f_off, (unsigned long)(f_end - f_off),
                        (unsigned long)ios_pool_ledger[j].off, (unsigned long)ios_pool_ledger[j].size,
                        ios_pool_ledger[j].peb);
                continue;
            }
        }
        /* ml87 (2026-07-27): DO NOT volatilize pool ranges. Ever.
         *
         * History: this was MADV_FREE, then MADV_FREE_REUSABLE on the theory
         * that the handout path's MADV_FREE_REUSE cancel was mispaired. ml87
         * disproved that — all 101 cancels returned 0 and libarm64ecfex STILL
         * died on a reused range (off=0x6844000, mprotect_rx=EACCES), exactly
         * as in ml76 (off=0x6c34000).
         *
         * The flavor was never the issue: BOTH marks let the kernel reclaim
         * the physical pages. The pool's RX alias is debugger-blessed
         * (jit26_prepare_region), and a reclaimed page re-faults as a FRESH,
         * UNBLESSED page — the mapping comes back max_prot=RW and mprotect(RX)
         * is refused forever. MADV_FREE_REUSE only helps if the kernel hasn't
         * taken the page yet; under CEF pressure (653MB pool + 212MB libcef)
         * it already has.
         *
         * Cost of not sweeping: dead copies stay resident, so pool RSS sits at
         * its high-water instead of shrinking. Range REUSE is untouched — the
         * freelist below still recycles pool VA — so this costs no address
         * space, only RAM. Note the sweep was originally added to relieve the
         * RAM pressure blamed for StikDebug dying (the freeze/detach); that
         * symptom may have been this corruption all along. */
        ios_pool_freelist[i].advised = 1;
    }

    /* each `continue` below has dropped or replaced entry i: pick again */
    {
        size_t bump_cand = ios_pool_holes_head_place( jit_pool_offset, alloc_size, ios_jit_hole_off_eff, ios_jit_hole_end_eff,
                                                      ios_jit_hole2_off, ios_jit_hole2_end );
        bump_ok = bump_cand + alloc_size <= pool_limit && IOS_POOL_IN_REACH(bump_cand);
    }
    while (off == (size_t)-1 &&
           (i = ios_pool_best_fit( ios_pool_freelist, ios_pool_free_count, alloc_size, now,
                                   anchor_off, max_dist )) >= 0)
    {
        if (ios_pool_keep_big( ios_pool_freelist[i].size, alloc_size, bump_ok ))
        {
            static unsigned kept_n;
            if (kept_n++ < 16)
                dprintf(2, "[jit-pool] 0x%lx bytes from the bump: the smallest freed range that fits is 0x%lx "
                        "(off=0x%lx), kept whole for a big image\n", (unsigned long)alloc_size,
                        (unsigned long)ios_pool_freelist[i].size, (unsigned long)ios_pool_freelist[i].off);
            break;
        }
        /* ml87/ml88 belt: never hand out a range that has genuinely lost its
         * exec blessing (in ml88 all 8 [exec-recover] deaths were on freelist
         * ranges, none on virgin bump pages). Now a read-only max_prot query —
         * see ios_pool_range_execable() for why the mprotect version was a
         * false positive that dropped all 62 candidates and disabled reuse
         * entirely (pool then bumped to 762MB of 896MB). */
        {
            unsigned int cur = 0, mx = 0;
            if (!ios_pool_range_execable( ios_pool_freelist[i].off,
                                          ios_pool_freelist[i].size, &cur, &mx ))
            {
                /* madeira-bcd: keep the range's executable runs (see
                 * ios_pool_execable_runs); a run found poisoned again (bit 2 of
                 * `advised`) is dropped whole, as every range used to be. */
                struct ios_pool_free bad = ios_pool_freelist[i];
                size_t r_off[16], r_size[16], kept = 0;
                int r, nr = (bad.advised & 2) ? 0
                          : ios_pool_execable_runs( (uint64_t)(uintptr_t)ios_jit_rx_base_global, bad.off, bad.size,
                                                    ios_pool_mach_region, r_off, r_size, 16 );

                ios_pool_freelist[i] = ios_pool_freelist[--ios_pool_free_count];
                for (r = 0; r < nr && ios_pool_free_count < IOS_POOL_FREE_MAX; r++)
                {
                    ios_pool_freelist[ios_pool_free_count].off = r_off[r];
                    ios_pool_freelist[ios_pool_free_count].size = r_size[r];
                    ios_pool_freelist[ios_pool_free_count].freed_at = bad.freed_at;
                    ios_pool_freelist[ios_pool_free_count].advised = bad.advised | 2;
                    ios_pool_free_count++;
                    kept += r_size[r];
                }
                dprintf(2, "[jit-pool] POISONED range off=0x%lx size=0x%lx cur=0x%x max=0x%x — %s"
                        " (0x%lx in %d executable runs kept on the freelist)\n",
                        (unsigned long)bad.off, (unsigned long)bad.size, cur, mx,
                        kept ? "only its non-executable pages dropped" : "dropped, NOT handed out",
                        (unsigned long)kept, r);
                continue;
            }
        }
        /* task #34 DOUBLE-HANDOUT DETECTOR. ml99 proved the copy itself is
         * correct (66 reuses, 0 [copy-verify] mismatches), so a pool page that
         * later reads back as zeros was overwritten AFTER it was written. The
         * writer that would correlate exactly with reuse is the allocator
         * handing this range to a second module while the first is still
         * loaded — the second memcpy then lands on top of live code. ml87
         * showed kernelbase and libarm64ecfex both reporting pool
         * 0x122844000; that was explained away as the bump pointer not
         * advancing on a freelist serve, which is true but does not rule this
         * out. Freelist and ledger are disjoint BY DESIGN (free removes the
         * ledger entry), so any overlap here is an accounting bug. Checked
         * BEFORE the entry is split so a refused range stays intact. */
        {
            size_t l_off = 0;
            void  *l_peb = NULL;
            if (ios_jit_rw_base_global &&
                ios_pool_live_overlap( (uintptr_t)ios_jit_rw_base_global + ios_pool_freelist[i].off,
                                       alloc_size, &l_off, &l_peb ))
            {
                dprintf(2, "[pool-dup] DOUBLE HANDOUT REFUSED: freelist off=0x%lx size=0x%lx overlaps LIVE ledger off=0x%lx peb=%p — second copy would have overwritten loaded code\n",
                        (unsigned long)ios_pool_freelist[i].off, (unsigned long)alloc_size,
                        (unsigned long)l_off, l_peb);
                ios_pool_freelist[i] = ios_pool_freelist[--ios_pool_free_count];
                continue;
            }
        }
        off = ios_pool_freelist[i].off;
        if (ios_pool_freelist[i].size > alloc_size)
        {
            ios_pool_freelist[i].off  += alloc_size;
            ios_pool_freelist[i].size -= alloc_size;
        }
        else
        {
            ios_pool_freelist[i] = ios_pool_freelist[--ios_pool_free_count];
        }
        /* Task #22 root cause (2026-07-10 Steam): the sweep above marked this
         * range volatile (MADV_FREE) and on Darwin that mark is NOT reliably
         * cleared by rewriting these entry-backed pages — reused ranges kept
         * getting harvested under the Steam download's memory pressure,
         * zeroing LIVE FEX LookupCache/CodeBuffer data (same page reclaimed
         * 4x at the same fault address, then the give-up → 24k-exception BUS
         * storm = the "freeze", which drowned StikDebug = the "detach", then
         * steam.exe died). MADV_FREE_REUSE is the documented cancel — apply
         * it BEFORE handing the range out so the new owner's writes stick. */
        {
            /* ml103: the MADV_FREE_REUSE that used to run here is GONE. It was
             * the documented cancel for MADV_FREE_REUSABLE — but the sweep no
             * longer marks anything reusable, so this call was unpaired. On
             * Darwin an unpaired REUSE is at best a no-op and at worst touches
             * the vm entry's reusable accounting itself. It is the last madvise
             * left in the pool allocation path, and exec faults on recycled
             * ranges persist with every other writer excluded (copy verifies
             * clean, no double-handout, no stale-alias memset, no module
             * zero-fill) — so this is the remaining single variable. */
            dprintf(2, "[jit-pool] reused freed range off=0x%lx size=0x%lx (freelist %d ranges) no-madvise\n",
                    (unsigned long)off, (unsigned long)alloc_size, ios_pool_free_count);
        }
        ios_pool_last_alloc_reused = 1;
        break;
    }

    if (off == (size_t)-1)
    {
        /* madeira-bcd split pool: never into a hole (ios_jit_hole_off, pool-mid's
         * ios_jit_hole2_off). Without a split `cand` is the cursor itself and this
         * is the old bump. */
        size_t cand = ios_pool_holes_head_place( jit_pool_offset, alloc_size,
                                                 ios_jit_hole_off_eff, ios_jit_hole_end_eff,
                                                 ios_jit_hole2_off, ios_jit_hole2_end );
        if (cand + alloc_size <= pool_limit
            && IOS_POOL_IN_REACH(cand))
        {
            if (cand != jit_pool_offset)
            {
                /* The runs below the hole(s) stay usable: hand them to the freelist
                 * as never-used ranges (no grace, nothing to advise), so the next
                 * image that fits there goes there. */
                size_t poff[3], psz[3], below = 0;
                int np = ios_pool_skip_pieces( jit_pool_offset, cand, ios_jit_hole_off_eff, ios_jit_hole_end_eff,
                                               ios_jit_hole2_off, ios_jit_hole2_end, poff, psz ), k;
                static int jump_n;
                for (k = 0; k < np; k++)
                {
                    below += psz[k];
                    if (ios_pool_free_count >= IOS_POOL_FREE_MAX) continue;
                    ios_pool_freelist[ios_pool_free_count].off = poff[k];
                    ios_pool_freelist[ios_pool_free_count].size = psz[k];
                    ios_pool_freelist[ios_pool_free_count].freed_at = 0;
                    ios_pool_freelist[ios_pool_free_count].advised = 1;
                    ios_pool_free_count++;
                }
                if (jump_n++ < 8)
                    dprintf(2, "[jit-pool] split pool: head 0x%lx+0x%lx would reach the hole [0x%lx,0x%lx)%s "
                            "-- placed above it at 0x%lx; the 0x%lx below it stays on the freelist\n",
                            (unsigned long)jit_pool_offset, (unsigned long)alloc_size,
                            (unsigned long)ios_jit_hole_off_eff, (unsigned long)ios_jit_hole_end_eff,
                            ios_jit_hole2_end > ios_jit_hole2_off ? " or hole 2" : "",
                            (unsigned long)cand, (unsigned long)below);
            }
            off = cand;
            jit_pool_offset = cand + alloc_size;
            ios_pool_last_alloc_reused = 0;
            /* ml89 CONTROL for the POISONED check above: report the same
             * max_prot for a range that has NEVER been freed. If virgin ranges
             * read max=0x7 while freed ranges read max=0x3, reuse really does
             * strip exec and the guard is sound. If both read the same, the
             * guard is measuring nothing and the exec faults have another
             * cause. Logged once every 16 bump allocations to stay quiet. */
            {
                static int bump_probe_n;
                if ((bump_probe_n++ & 15) == 0)
                {
                    unsigned int cur = 0, mx = 0;
                    int ok = ios_pool_range_execable( off, alloc_size, &cur, &mx );
                    dprintf(2, "[jit-pool] bump-probe off=0x%lx size=0x%lx cur=0x%x max=0x%x execable=%d (VIRGIN control)\n",
                            (unsigned long)off, (unsigned long)alloc_size, cur, mx, ok);
                }
            }
            /* ml103: the matching unpaired MADV_FREE_REUSE is gone here too —
             * see the freelist path above. Virgin pages were never marked
             * volatile in the first place, so this one had even less reason to
             * exist. No madvise now runs on any pool allocation path. */
        }
    }
#undef IOS_POOL_IN_REACH

    if (off != (size_t)-1)
    {
        /* Steam S3 run 9/10: purge STALE anon-alias entries whose pool range
         * overlaps the handed-out range. Aliases are only cleared on process
         * EXIT — a live process (steam.exe) that guest-frees an anon RWX
         * region leaves its entry behind, and once the pool range is
         * recycled (user32's x18 trampolines in the errorreporter child) any
         * guest MEM_DECOMMIT of the old user VA memsets the NEW occupant to
         * zero via decommit_pages' alias path → blr into zeros → fault storm. */
        {
            uintptr_t new_rw_start = (uintptr_t)ios_jit_rw_base_global + off;
            uintptr_t new_rw_end   = new_rw_start + alloc_size;
            for (i = 0; i < ios_jit_anon_alias_count; i++)
            {
                uintptr_t a_start, a_end;
                if (!ios_jit_anon_aliases[i].user_va) continue;
                a_start = ios_jit_anon_aliases[i].jit_rw_alias;
                a_end   = a_start + (ios_jit_anon_aliases[i].user_va_end
                                     - ios_jit_anon_aliases[i].user_va);
                if (a_start < new_rw_end && a_end > new_rw_start)
                {
                    dprintf(2, "[jit-pool] STALE alias purged on handout: user_va=%p rw=%p+0x%lx overlaps new range off=0x%lx+0x%lx\n",
                            (void *)ios_jit_anon_aliases[i].user_va, (void *)a_start,
                            (unsigned long)(a_end - a_start),
                            (unsigned long)off, (unsigned long)alloc_size);
                    ios_jit_anon_aliases[i].user_va_end = 0;
                    __sync_synchronize();
                    ios_mono_alias_retire( ios_jit_anon_aliases[i].user_va );  /* ml648: unmap/teardown */
                    ios_jit_anon_aliases[i].user_va = 0;
                }
            }
        }
        if (ios_pool_ledger_count < IOS_POOL_LEDGER_MAX)
        {
            ios_pool_ledger[ios_pool_ledger_count].off  = off;
            ios_pool_ledger[ios_pool_ledger_count].size = alloc_size;
            ios_pool_ledger[ios_pool_ledger_count].peb  = ios_jit_current_peb();
            ios_pool_ledger_count++;
        }
        else dprintf(2, "[jit-pool] ledger FULL — range off=0x%lx will never be reclaimed\n",
                     (unsigned long)off);
    }

    pthread_mutex_unlock( &ios_pool_lock );
    return off;
}

/* ml239: is a pool range ALREADY non-executable when handed out?
 *
 * copy-verify reports isolated .text pages BORN NON-EXEC with max=3 -- maxprot lacking
 * EXEC, which can never be raised again, so mprotect(RX) fails forever and execution there
 * faults NOEXEC (this run: dbghelp.dll+0x6da14, unhandled -> process death). Seen across
 * several modules: 1/295 in steamwebhelper, 2/72 in chromehtml, 1/40 in libswresample.
 *
 * Two candidates needing different fixes: the copy path poisons the page, or the pool
 * RECYCLES already-poisoned VA (68 freelist/reclaim events this run) so it arrives poisoned.
 * Checking maxprot at hand-out time -- BEFORE anything is written -- separates them.
 * VM_PROT_COPY was already ruled out (zero RW+COPY events in the failing run). */
static unsigned ios_pool_check_range_exec( size_t off, size_t size, int reused )
{
    extern void *ios_jit_rx_base_global;
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    static int checked;
    size_t o;
    unsigned bad = 0;

    /* ml241: do NOT cap the CHECK -- only the printing. The first version incremented a
     * shared counter on clean ranges too, so it sampled the first 24 allocations (all
     * clean) and never looked at the ones that were actually poisoned (winmm, setupapi,
     * ...). It reported "CLEAN at hand-out 24/24" and I wrongly concluded the copy path was
     * to blame; [poison-step] pre-memcpy then showed the pages already non-exec BEFORE the
     * copy. Check everything, print only what is interesting. */
    if (!rx) return 0;

    for (o = 0; o < size; o += 0x4000)
    {
        mach_vm_address_t want = (mach_vm_address_t)(rx + off + o), a = want;
        mach_vm_size_t rsz = 0;
        vm_region_basic_info_data_64_t inf;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;

        if (mach_vm_region( mach_task_self(), &a, &rsz, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&inf, &cnt, &obj ) != KERN_SUCCESS) break;
        if (a > want) continue;
        if (!(inf.max_protection & VM_PROT_EXECUTE))
        {
            if (bad++ == 0 && checked++ < 30)
            {
                /* ml248: name the OWNER. mprotect_exec never touches pool VA (0 calls, 20
                 * poisoned ranges), so nothing is narrowing maxprot in place -- the pages
                 * are being REPLACED by a different mapping. Guest PE images live in the
                 * same 0x1xxxxxxxx band as the pool, so the suspect is Wine's own allocator
                 * handing out VA that overlaps the pool and later unmapping/remapping it.
                 * The Mach user_tag identifies the allocator, and share_mode distinguishes
                 * our dual-mapped alias from an ordinary private mapping. */
                vm_region_extended_info_data_t ext;
                mach_msg_type_number_t ecnt = VM_REGION_EXTENDED_INFO_COUNT;
                mach_vm_address_t ea = want;
                mach_vm_size_t esz = 0;
                mach_port_t eobj = MACH_PORT_NULL;
                unsigned tag = 0, share = 0;

                if (mach_vm_region( mach_task_self(), &ea, &esz, VM_REGION_EXTENDED_INFO,
                                    (vm_region_info_t)&ext, &ecnt, &eobj ) == KERN_SUCCESS)
                { tag = ext.user_tag; share = ext.share_mode; }

                dprintf( 2, "[pool-poison] HANDED OUT NON-EXEC off=0x%lx +0x%lx va=%p prot=%x "
                            "max=%x reused=%d user_tag=%u share_mode=%u regionsz=0x%llx\n",
                         (unsigned long)off, (unsigned long)o, (void *)(uintptr_t)want,
                         inf.protection, inf.max_protection, reused, tag, share,
                         (unsigned long long)esz );
            }
        }
    }
    if (bad && checked < 30)
        dprintf( 2, "[pool-poison] off=0x%lx +0x%lx : %u poisoned pages, reused=%d\n",
                 (unsigned long)off, (unsigned long)size, bad, reused );
    return bad;
}

static size_t ios_pool_alloc_range( size_t alloc_size, size_t pool_limit )
{
    /* ml1351: QUARANTINE A RANGE THAT IS ALREADY NON-EXECUTABLE (port of the pre-reset
     * ml1970 guard).
     *
     * ml239 only reported such a range and handed it out anyway. Device logs 80-83: a
     * 32-bit game's DRM loader image was copied into the pool, and from the exact end
     * of that copy every later hand-out was born with maxprot RW ([pool-poison] HANDED
     * OUT NON-EXEC off=0xa848000...). The next process started in that session (the
     * windowed taskbar's in-session launcher: services.exe, then steam.exe) got its
     * ntdll copy there and faulted NOEXEC at LdrInitializeThunk's first instruction,
     * forever, one core at 100%. EXEC can never be restored to those pages, so leave
     * them allocated and take the next range. Bounded: at most 16 attempts and 64 MB
     * skipped per session, after which the report-only behaviour resumes rather than
     * draining the pool. MADEIRA_POOL_QUARANTINE=0 restores report-only at once. */
    static int quarantine = -1;
    static size_t skipped_total;
    int attempt;
    size_t off = (size_t)-1;

    if (quarantine < 0)
    {
        const char *e = getenv( "MADEIRA_POOL_QUARANTINE" );
        quarantine = !(e && e[0] == '0');
    }
    for (attempt = 0; attempt < 16; attempt++)
    {
        unsigned bad;
        off = ios_pool_alloc_range_ex( alloc_size, pool_limit, (size_t)-1, 0 );
        if (off == (size_t)-1) break;
        /* ml239: see ios_pool_check_range_exec. ios_pool_last_alloc_reused tells us whether
         * this came off the freelist or the virgin bump, which is exactly the discriminator. */
        bad = ios_pool_check_range_exec( off, alloc_size, ios_pool_last_alloc_reused );
        if (!bad || !quarantine || skipped_total + alloc_size > (64u << 20)) break;
        skipped_total += alloc_size;
        {
            static unsigned int n_q;
            if (++n_q <= 24)
                dprintf( 2, "[pool-quarantine] ml1351 off=0x%lx size=0x%lx poisoned=%u reused=%d "
                         "(maxprot lacks EXEC) left allocated; skipped=%lu KB\n",
                         (unsigned long)off, (unsigned long)alloc_size, bad,
                         ios_pool_last_alloc_reused, (unsigned long)(skipped_total >> 10) );
        }
        off = (size_t)-1;
    }
    return off;
}

/* Default-off overflow for small image copies. EC_CODE and images reserve
 * from the same atomic region-C cursor, so neither can overwrite the other.
 * Live code buffers, the low-VA margin and existing reuse grace are untouched. */
static size_t ios_pool_low_image_range( size_t alloc_size )
{
    const size_t reserve = 4u * 1024 * 1024;
    const char *env = getenv( "MADEIRA_POOL_LOW_IMAGES" );
    size_t off = (size_t)-1, cur = 0;
    void *peb;

    if (!env || strcmp( env, "1" ) || ios_wow_base() ||
        !ios_jit_low_size_global || !ios_jit_rx_base_global || !ios_jit_low_rw_global ||
        !alloc_size || (alloc_size & 0x3fff) || alloc_size > 16u * 1024 * 1024 ||
        ios_jit_low_size_global < reserve) return off;

    peb = ios_jit_current_peb();
    pthread_mutex_lock( &ios_pool_lock );
    if (ios_pool_ledger_count < IOS_POOL_LEDGER_MAX)
    {
        for (;;)
        {
            cur = ios_jit_low_reserved;
            if (alloc_size > ios_jit_low_size_global - reserve ||
                cur > ios_jit_low_size_global - reserve - alloc_size) break;
            off = (size_t)(ios_jit_low_rx_global + cur - (uintptr_t)ios_jit_rx_base_global);
            if (!ios_pool_range_clean( off, alloc_size ))
            {
                off = (size_t)-1;
                break;
            }
            if (__sync_bool_compare_and_swap( &ios_jit_low_reserved, cur, cur + alloc_size )) break;
            off = (size_t)-1;
        }
        if (off != (size_t)-1)
        {
            ios_pool_ledger[ios_pool_ledger_count].off = off;
            ios_pool_ledger[ios_pool_ledger_count].size = alloc_size;
            ios_pool_ledger[ios_pool_ledger_count].peb = peb;
            ios_pool_ledger_count++;
            ios_pool_last_alloc_reused = 0;
        }
    }
    pthread_mutex_unlock( &ios_pool_lock );
    if (off != (size_t)-1)
        dprintf( 2, "[pool-low] IMAGE rx=%p size=0x%lx peb=%p used=0x%lx/0x%lx "
                    "code_reserve=0x%lx head_used=0x%lx unchanged\n",
                 (void *)(ios_jit_low_rx_global + cur), (unsigned long)alloc_size, peb,
                 (unsigned long)(cur + alloc_size), (unsigned long)ios_jit_low_size_global,
                 (unsigned long)reserve, (unsigned long)jit_pool_offset );
    return off;
}

/* Failure-only, bounded bookkeeping snapshot. A grace-expired size fit is
 * not a promise of executable/owner-safe reuse; the normal allocator still
 * performs all of those checks. Never touch mappings or FEX/guest payloads. */
static void ios_pool_failure_census( size_t want )
{
    static size_t requests[8];
    static unsigned count;
    size_t free_bytes = 0, largest = 0, aged_bytes = 0, aged_largest = 0, poisoned = 0;
    size_t main_virgin = 0, c_used, c_virgin, c_image_virgin, hole;
    const size_t code_reserve = 4u * 1024 * 1024;
    unsigned raw_fit = 0, aged_fit = 0, i;
    time_t now = time( NULL );

    pthread_mutex_lock( &ios_pool_lock );
    for (i = 0; i < count; i++) if (requests[i] == want) goto done;
    if (count == ARRAY_SIZE(requests)) goto done;
    requests[count++] = want;
    for (i = 0; i < (unsigned)ios_pool_free_count; i++)
    {
        const struct ios_pool_free *entry = &ios_pool_freelist[i];
        free_bytes += entry->size;
        if (entry->size > largest) largest = entry->size;
        if (entry->size >= want) raw_fit++;
        if (entry->advised & 2) poisoned += entry->size;
        if (now - entry->freed_at < IOS_POOL_REUSE_GRACE_SEC) continue;
        aged_bytes += entry->size;
        if (entry->size > aged_largest) aged_largest = entry->size;
        if (entry->size >= want) aged_fit++;
    }
    hole = ios_pool_holes_between( ios_jit_pool_size_global, jit_pool_offset, ios_jit_tail_reserved,
                                   ios_jit_hole_off_eff, ios_jit_hole_end_eff, ios_jit_hole2_off, ios_jit_hole2_end );
    if (jit_pool_offset <= ios_jit_pool_size_global && ios_jit_tail_reserved <= ios_jit_pool_size_global - jit_pool_offset &&
        hole <= ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved)
        main_virgin = ios_jit_pool_size_global - jit_pool_offset - ios_jit_tail_reserved - hole;
    c_used = ios_jit_low_reserved;
    c_virgin = c_used < ios_jit_low_size_global ? ios_jit_low_size_global - c_used : 0;
    c_image_virgin = c_virgin > code_reserve ? c_virgin - code_reserve : 0;
    dprintf( 2, "[pool-capacity] failed_want=0x%lx entries=%u free_bytes=0x%lx largest=0x%lx "
                "aged_bytes=0x%lx aged_largest=0x%lx raw_size_fit=%u aged_size_fit=%u "
                "poison_marked_bytes=0x%lx main_virgin=0x%lx c_virgin=0x%lx c_image_virgin=0x%lx "
                "(bookkeeping only; reuse guards unchanged)\n",
             (unsigned long)want, (unsigned)ios_pool_free_count, (unsigned long)free_bytes,
             (unsigned long)largest, (unsigned long)aged_bytes, (unsigned long)aged_largest,
             raw_fit, aged_fit, (unsigned long)poisoned, (unsigned long)main_virgin,
             (unsigned long)c_virgin, (unsigned long)c_image_virgin );
done:
    pthread_mutex_unlock( &ios_pool_lock );
}

/* ml1039: hand a RECLAIMED head range to the code-buffer tail.
 *
 * The pool is two allocators facing each other: PE-image copies bump up from
 * the bottom, FEX code buffers carve down from the top, and the tail is refused
 * the moment it would cross the head's HIGH-WATER mark. But the high-water mark
 * never comes down. A launcher generation copies the 117MB main image, exits,
 * and its ranges are reclaimed -- onto a freelist that only the IMAGE allocator
 * reads. iPhone 18 Pro, mid-load:
 *
 *   TAIL REFUSED want=0x800000 tail_resv=0xb80c000 head_used=0x19664000/0x25000000
 *   [pool-tail] TOTALS live=176MB free=0MB
 *
 * 406MB "used" by the head, of which well over 100MB was free, while the JIT
 * could not get 1MB -- after which FEX cannot compile anything, including an
 * exception handler's continuation, and the run dies at pc=0.
 *
 * pool_limit=0 makes the bump path unwinnable, so this is "freelist or
 * nothing", and it inherits every guard the image path applies to recycled
 * ranges (grace period, exec-blessing check, double-handout detector, stale
 * alias purge). The ledger entry it records is REMOVED again: the ledger is
 * what per-process RECLAIM walks, and a range the tail carve table owns must
 * never be reclaimed out from under FEX when some pseudo-process exits. */
static size_t ios_pool_take_freed_for_tail( size_t alloc_size )
{
    size_t off = ios_pool_alloc_range_ex( alloc_size, 0, (size_t)-1, 0 );
    int i;

    if (off == (size_t)-1) return off;
    pthread_mutex_lock( &ios_pool_lock );
    for (i = ios_pool_ledger_count - 1; i >= 0; i--)
        if (ios_pool_ledger[i].off == off && ios_pool_ledger[i].size == alloc_size)
        {
            ios_pool_ledger[i] = ios_pool_ledger[--ios_pool_ledger_count];
            break;
        }
    pthread_mutex_unlock( &ios_pool_lock );
    return off;
}

/* Total bytes reserved from the pool TAIL by NtAllocateVirtualMemoryEx for
 * FEX EC_CODE buffers. File-scope so head and tail allocators can refuse to
 * cross each other: on 2026-07-06 (Thumper under desktop) the head cursor
 * grew past the bottom of a live tail-carved FEX CodeBuffer and late DLL
 * image copies memcpy'd over compiled blocks — neither side checked the
 * other. Reads of the opposing cursor are racy-but-monotonic: both only
 * grow, so a stale read can only make the check conservative late, never
 * un-refuse. */
static volatile size_t ios_jit_tail_reserved = 0;

/* ml438 (#74): tail EC-buffer FREE-LIST. tail_resv was monotonic — dead
 * threads' code buffers never returned their tail space, so long runs
 * exhausted the tail (ml436: 10 refusals at head 708MB + tail 188MB; ml437:
 * refusing even 1MB) and post-StikDebug-detach there is NO fallback (band
 * buffers can't be made executable detached). The pool is fully executable
 * from BOOT, so recycling tail carves needs no debugger: record every carve,
 * mark it free when FEXCore releases the buffer (NtFreeVirtualMemory of a
 * pool-tail rx address — no wine view exists for these), and serve future
 * asks first-fit from the free entries. No splitting: sizes are pow2-ish
 * (1..32MB after the ml437 MAX_CODE_SIZE cap), so first-fit-larger waste is
 * bounded and reuse is usually exact. */
#define IOS_TAIL_CARVE_MAX 256
struct ios_tail_carve
{
    size_t off;
    size_t size;
    int    free;
    time_t freed_at;
    void  *peb;       /* madeira-bcd: the pseudo-process it was handed to (NULL = unknown) */
    int    retired;   /* madeira-bcd: freed because that process exited, not by FEX */
};
static struct ios_tail_carve ios_tail_carves[IOS_TAIL_CARVE_MAX];

/* madeira-bcd pool-low: 1 for a carve offset in region C (`off` is its wrapping
 * distance from the pool's RX base, see ios_jit_low_rx_global). */
static int ios_tail_carve_in_low( size_t off )
{
    return ios_jit_low_contains( (uintptr_t)ios_jit_rx_base_global + off );
}

/* A tiny dispatcher allocation must not consume a whole retired code buffer
 * while region C can serve the tiny request. Keep the large buffer intact for
 * the next code-cache allocation; no live carve is split or migrated. */
static int ios_pool_preserve_code_carve( size_t available, size_t want, int low_fits )
{
    return low_fits && want <= 0x10000 && available >= 0x100000 && available / 4 >= want;
}

/* ml557 (#74 REGRESSION): is any thread's PC currently INSIDE this tail carve?
 *
 * ml438 made a MEM_RELEASE of a live tail EC-buffer carve mark it free for reuse,
 * to stop the tail space leaking forever. But it marks the carve free WITHOUT
 * asking whether a thread is still executing JIT code in it, and `tail REUSE`
 * hands the same range straight back out to the next requester, which then
 * compiles different code over it.
 *
 * ml556 caught exactly that: carve rx=0x1543f8000 size=0x1000000 was FREEd and
 * REUSEd eight times, and the fatal fault landed at host pc 0x154d4008c — INSIDE
 * that range — with garbage registers (base reg = 0x40 -> a NULL+0x40 atomic
 * load). A thread was running in code that had been recycled underneath it.
 *
 * That also explains why the fatal site MOVES between runs (frame clear /
 * PartitionAlloc refcount CHECK / NULL-this call): the victim depends on what
 * happened to be compiled into the recycled range.
 *
 * Frees are rare (33-53 per run), so a full thread scan here costs nothing
 * measurable. Refusing to free an occupied carve reinstates a BOUNDED leak —
 * which is what ml438 set out to fix — but a leak is strictly better than
 * executing recycled code, and the carve becomes freeable on the next release
 * once the thread has left. */
static int ios_tail_carve_scan( const void *base, size_t size, int strict )
{
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0, i;
    uintptr_t lo = (uintptr_t)base, hi = lo + size;
    mach_port_t self = mach_thread_self();
    int occupied = 0;

    if (task_threads( mach_task_self(), &threads, &count ) != KERN_SUCCESS)
    {
        mach_port_deallocate( mach_task_self(), self );
        return strict;                             /* unknown: old free policy, fail-closed transfer */
    }
    for (i = 0; i < count; i++)
    {
        arm_thread_state64_t st;
        mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
        if (threads[i] != self)
        {
            if (thread_get_state( threads[i], ARM_THREAD_STATE64,
                                  (thread_state_t)&st, &sc ) == KERN_SUCCESS)
            {
                uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc( st );
                if (pc >= lo && pc < hi) occupied = 1;
            }
            else if (strict) occupied = 1;
        }
        mach_port_deallocate( mach_task_self(), threads[i] );
    }
    mach_vm_deallocate( mach_task_self(), (mach_vm_address_t)threads,
                        count * sizeof(*threads) );
    mach_port_deallocate( mach_task_self(), self );
    return occupied;
}
static int ios_tail_carve_occupied( const void *base, size_t size )
{
    return ios_tail_carve_scan( base, size, 0 );
}
static unsigned ios_tail_carve_n;
static pthread_mutex_t ios_tail_carve_lock = PTHREAD_MUTEX_INITIALIZER;

/* madeira-bcd: a dead pseudo-process's FEX code buffers.
 *
 * FEX releases a code buffer when it rotates to a new one, never when its
 * process exits: NtTerminateProcess longjmps out of the calling thread and
 * nothing tears FEX down, so the process's last buffer stayed LIVE for the rest
 * of the session. GTA V Enhanced, first start after the Dock installs (build
 * 514, 2026-10-12 13:11): the exits of PlayGTAV.exe, the launcher before its
 * self-restart and four RockstarService.exe left 96 MB of region C and a 128 MB
 * tail buffer live, the tail stood at 0x18f38000, and every buffer the game
 * asked for was capped at 16 MB ("tail CAP: refusing 0x8000000 (cap
 * 0x1000000"): FEX retranslated its hot code over and over, about 7 fps. RDR2
 * at 12:57 the same way.
 *
 * ios_jit_reclaim_process now retires them: free again, but `retired`. A
 * retired carve is handed out, or lifts the code-buffer cap, only when the
 * image reuse grace has passed since the exit, and is handed out only when a
 * strict scan finds no thread's PC inside it (ios_tail_carve_scan): a laggard
 * thread of the dead process may still run for a moment, as in its image
 * copies. A buffer FEX releases itself keeps the old rules. Set
 * MADEIRA_POOL_CODE_EXIT_RECLAIM=0 to keep dead processes' buffers live. */
static int ios_tail_carve_ready( const struct ios_tail_carve *carve, time_t now )
{
    if (!carve->free) return 0;
    return !carve->retired || now - carve->freed_at >= IOS_POOL_REUSE_GRACE_SEC;
}

/* Retire `peb`'s live carves; the caller holds ios_tail_carve_lock. Returns
 * how many, and their bytes in *bytes. */
static unsigned ios_tail_carves_retire_owner( struct ios_tail_carve *carves, unsigned n, void *peb,
                                              time_t now, size_t *bytes )
{
    unsigned i, retired = 0;

    *bytes = 0;
    if (!peb) return 0;
    for (i = 0; i < n; i++)
    {
        if (carves[i].free || carves[i].peb != peb) continue;
        carves[i].free = 1;
        carves[i].retired = 1;
        carves[i].freed_at = now;
        carves[i].peb = NULL;
        *bytes += carves[i].size;
        retired++;
    }
    return retired;
}

/* A release by a thread of another process than the carve's owner: a dead
 * process's late release of a buffer that has since been handed on. */
static int ios_tail_carve_foreign_release( const struct ios_tail_carve *carve, void *caller_peb )
{
    return carve->peb && caller_peb && carve->peb != caller_peb;
}

static void ios_tail_carves_owner_died( void *peb )
{
    const char *env = getenv( "MADEIRA_POOL_CODE_EXIT_RECLAIM" );
    size_t bytes = 0;
    unsigned n;

    if (!peb || (env && !strcmp( env, "0" ))) return;
    pthread_mutex_lock( &ios_tail_carve_lock );
    n = ios_tail_carves_retire_owner( ios_tail_carves, ios_tail_carve_n, peb, time( NULL ), &bytes );
    pthread_mutex_unlock( &ios_tail_carve_lock );
    if (n)
        dprintf( 2, "[jit-pool] RECLAIM peb=%p: %u FEX code buffer(s) 0x%lx bytes retired to the carve free-list, "
                    "reusable after %ds once no thread runs in them (madeira-bcd)\n",
                 peb, n, (unsigned long)bytes, IOS_POOL_REUSE_GRACE_SEC );
}

/* Unlike the existing freelist's best-effort check, a cross-allocator transfer
 * needs proof that every byte is mapped and currently readable/executable.
 * A guard page, a gap, a failed query or narrowed max_prot refuses the transfer. */
static int ios_pool_recycle_range_ready( size_t off, size_t size )
{
    mach_vm_address_t a = (uintptr_t)ios_jit_rx_base_global + off, end = a + size;

    if (!size || end <= a) return 0;
    while (a < end)
    {
        mach_vm_address_t q = a;
        mach_vm_size_t n = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t status = mach_vm_region( mach_task_self(), &q, &n, VM_REGION_BASIC_INFO_64,
                                               (vm_region_info_t)&info, &count, &object );

        if (object != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), object );
        if (status != KERN_SUCCESS || q > a || !n || n > ~(mach_vm_size_t)0 - q || q + n <= a ||
            !(info.max_protection & VM_PROT_EXECUTE) ||
            (info.protection & (VM_PROT_READ | VM_PROT_EXECUTE)) != (VM_PROT_READ | VM_PROT_EXECUTE)) return 0;
        a = q + n < end ? q + n : end;
    }
    return 1;
}

/* Default-off transfer of a retired code-buffer range to the image allocator.
 * The free flag comes from FEX's normal release path; additionally require the
 * image reuse grace, clean executable pages and a successful empty PC scan.
 * Only region C is eligible, and only ranges/requests up to 64 MB. The normal
 * allocator then splits it, purges old aliases and records the image's owner.
 * No live buffer is resized and neither bump cursor nor tail budget changes.
 * Lock order is carve -> pool; other carve paths release one before taking the
 * other. Removal under both locks prevents code and image double-handout. */
static int ios_pool_recycle_code_range( size_t want )
{
    const char *env = getenv( "MADEIRA_POOL_RECYCLE_IMAGES" );
    const size_t limit = 64u * 1024 * 1024;
    unsigned i, best = ~0u;
    unsigned fitting = 0, recent = 0, dirty = 0, occupied = 0, carve_count;
    size_t off = 0, size = 0;
    time_t now = time( NULL ), freed_at = 0;
    int transferred = 0;

    if (!env || strcmp( env, "1" ) || ios_wow_base() ||
        !ios_jit_low_size_global || !ios_jit_rx_base_global || !ios_jit_rw_base_global ||
        !want || (want & 0x3fff) || want > limit) return 0;

    pthread_mutex_lock( &ios_tail_carve_lock );
    for (i = 0; i < ios_tail_carve_n; i++)
    {
        uintptr_t rx = (uintptr_t)ios_jit_rx_base_global + ios_tail_carves[i].off;
        size_t loff = rx - ios_jit_low_rx_global;
        size_t n = ios_tail_carves[i].size;
        time_t retired = ios_tail_carves[i].freed_at;

        if (!ios_tail_carves[i].free || n < want || n > limit || (n & 0x3fff) ||
            (rx & 0x3fff) || loff >= ios_jit_low_size_global || n > ios_jit_low_size_global - loff ||
            (best != ~0u && n >= ios_tail_carves[best].size)) continue;
        fitting++;
        if (!retired || retired > now || now - retired < IOS_POOL_REUSE_GRACE_SEC) { recent++; continue; }
        if (!ios_pool_recycle_range_ready( ios_tail_carves[i].off, n )) { dirty++; continue; }
        if (ios_tail_carve_scan( (void *)rx, n, 1 )) { occupied++; continue; }
        best = i;
    }
    if (best != ~0u)
    {
        size_t live_off;
        void *live_peb;

        off = ios_tail_carves[best].off;
        size = ios_tail_carves[best].size;
        freed_at = ios_tail_carves[best].freed_at;
        pthread_mutex_lock( &ios_pool_lock );
        if (ios_pool_ledger_count < IOS_POOL_LEDGER_MAX && ios_pool_free_count < IOS_POOL_FREE_MAX &&
            !ios_pool_live_overlap( (uintptr_t)ios_jit_rw_base_global + off, size, &live_off, &live_peb ) &&
            ios_pool_free_put( ios_pool_freelist, &ios_pool_free_count, IOS_POOL_FREE_MAX,
                               off, size, freed_at, ios_pool_range_clean ))
        {
            ios_tail_carves[best] = ios_tail_carves[--ios_tail_carve_n];
            transferred = 1;
        }
        pthread_mutex_unlock( &ios_pool_lock );
    }
    carve_count = ios_tail_carve_n;
    pthread_mutex_unlock( &ios_tail_carve_lock );
    if (transferred)
        dprintf( 2, "[pool-recycle] retired code rx=%p size=0x%lx age=%lus -> image freelist "
                    "(want=0x%lx, C cursor and live buffers unchanged)\n",
                 (void *)((uintptr_t)ios_jit_rx_base_global + off), (unsigned long)size,
                 (unsigned long)(now - freed_at), (unsigned long)want );
    else
    {
        static unsigned refused;
        if (__sync_add_and_fetch( &refused, 1 ) <= 16)
            dprintf( 2, "[pool-recycle] no transfer: want=0x%lx carves=%u free_fit=%u recent=%u "
                        "nonexec=%u occupied_or_unknown=%u (guards kept)\n",
                     (unsigned long)want, carve_count, fitting, recent, dirty, occupied );
    }
    return transferred;
}

/* iOS-Madeira ml613: WHICH TAIL CARVE DOES THIS HOST PC LIVE IN, AND IS IT FREE?
 *
 * ml612's crash faulted at host pc 0x15361d6d0, which is +0x496d0 into the 16MB
 * carve 0x1535d4000 — a carve that had been FREEd and REUSEd THREE times in the
 * preceding ~400 log lines, the last reuse two lines before the fault. That is
 * the tail-recycling race (#74 family) with a much shorter fuse than a single
 * reuse would suggest, and the existing ios_tail_carve_occupied() guard cannot
 * see it: it samples only threads whose PC is inside the carve at the instant of
 * the free, so dormant return addresses, linked blocks, dispatch-cache entries
 * and threads that enter the old code LATER all slip through.
 *
 * ⚠️ TRYLOCK ONLY. This is called from the Mach exception path; blocking on
 * ios_tail_carve_lock there would deadlock against whichever thread is mid-carve
 * and holding it — exactly the thread most likely to be involved. A busy lock
 * returns -1 and the caller reports "lock busy" rather than lying or hanging.
 *
 * Returns 1 found, 0 not-in-any-carve, -1 lock busy. */
int ios_tail_carve_lookup_trylock( unsigned long long rx_addr, unsigned *idx_out,
                                   unsigned long long *base_out, unsigned long long *size_out,
                                   int *free_out )
{
    uintptr_t rx_base = (uintptr_t)ios_jit_rx_base_global;
    unsigned i;
    int found = 0;

    /* madeira-bcd pool-low: a carve in region C lies below the pool (its `off`
     * wraps, rx_base + off is still its address) */
    if (!rx_base || (rx_addr < rx_base && !ios_jit_low_contains( (uintptr_t)rx_addr ))) return 0;
    if (pthread_mutex_trylock( &ios_tail_carve_lock ) != 0) return -1;
    for (i = 0; i < ios_tail_carve_n; i++)
    {
        uintptr_t lo = rx_base + ios_tail_carves[i].off;
        uintptr_t hi = lo + ios_tail_carves[i].size;
        if (rx_addr >= lo && rx_addr < hi)
        {
            if (idx_out)  *idx_out  = i;
            if (base_out) *base_out = (unsigned long long)lo;
            if (size_out) *size_out = (unsigned long long)ios_tail_carves[i].size;
            if (free_out) *free_out = ios_tail_carves[i].free;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock( &ios_tail_carve_lock );
    return found;
}

/* Exported JIT pool addresses for use by SIGBUS handler in signal_arm64_ios.c */
/* ml251: does anything MUNMAP/MMAP inside the JIT pool's VA?
 *
 * Two pool symptoms share one explanation and neither goes through mprotect_exec (which
 * logged ZERO pool calls): isolated single-page RW regions (poison, max=3 forever) and
 * MEM_FREE holes inside the pool span -- the latter is what the fatal CASPAL targets
 * (0x1541af700, state=MEM_FREE), i.e. a use-after-free of pool memory that ends runs.
 * Both are what you get if Wine's allocator believes pool VA is free and maps/unmaps
 * there. Guest PE images already share the 0x1xxxxxxxx band with the pool, so this is
 * plausible rather than speculative. Report any such call, with its caller tag. */
void ios_pool_va_warn( const char *who, const void *addr, size_t size )
{
    extern void *ios_jit_rx_base_global;
    extern void *ios_jit_rw_base_global;
    extern size_t ios_jit_pool_size_global;
    uintptr_t a = (uintptr_t)addr, rx = (uintptr_t)ios_jit_rx_base_global;
    uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
    size_t ps = ios_jit_pool_size_global;
    static int warned;

    if (!ps || warned >= 40) return;
    if (rx && a < rx + ps && a + size > rx)
    {
        warned++;
        dprintf( 2, "[pool-va] %s addr=%p size=0x%lx INSIDE RX pool off=0x%lx  <== foreign map/unmap\n",
                 who, addr, (unsigned long)size, (unsigned long)(a - rx) );
    }
    else if (rw && a < rw + ps && a + size > rw)
    {
        warned++;
        dprintf( 2, "[pool-va] %s addr=%p size=0x%lx INSIDE RW pool off=0x%lx  <== foreign map/unmap\n",
                 who, addr, (unsigned long)size, (unsigned long)(a - rw) );
    }
    else if (ios_jit_low_overlaps( a, size ))
    {
        warned++;
        dprintf( 2, "[pool-va] [pool-low] %s addr=%p size=0x%lx INSIDE region C's %s side  <== foreign map/unmap\n",
                 who, addr, (unsigned long)size, ios_jit_low_overlaps( a, size ) == 1 ? "RX" : "RW" );
    }
}

void *ios_jit_rx_base_global = NULL;
void *ios_jit_rw_base_global = NULL;
size_t ios_jit_pool_size_global = 0;
unsigned long long ios_last_footprint_mb = 0;   /* ml668: latest phys_footprint MB (decl above) */
int ios_fast_footprint = 0;                    /* ml670: set when d3d11 loads */

/* TEB restore trampoline in JIT pool.
 * iOS sigreturn does NOT restore x18 from the ucontext — it always zeroes
 * the platform register. So we can't fix x18 via signal handler return.
 * Instead, we write a small trampoline in the JIT pool (executable memory)
 * that loads x18 from a fixed location and jumps to the saved target.
 *
 * Per-thread trampoline slots in the reserved first page (0x4000 bytes):
 *   slot N at offset N*16:
 *     +0:  .quad TEB_address           (8 bytes)
 *     +8:  ldr x18, [pc, #-8]          (4 bytes) — 0x58FFFFD2
 *     +12: br x17                      (4 bytes) — 0xD61F0220
 *
 * Each Wine "process" thread gets its own slot with its own TEB address.
 * Slot 0 is the default (backward compatible with ios_jit_teb_trampoline).
 * Use all 1024 slots in the reserved 16KB page (1024 * 16 = 0x4000).
 *
 * Usage: SEGV/Mach handler sets x17 = target_PC, PC = thread's trampoline.
 * Trampoline runs: loads x18 = thread's TEB, jumps to x17 = target PC.
 */
void *ios_jit_teb_trampoline = NULL;  /* RX address of slot 0 trampoline (offset 8) */
#define IOS_JIT_TRAMPOLINE_SIZE 16    /* Bytes per trampoline slot */
/* Each fallback to slot 0 overwrites another thread's saved TEB. The page
 * is already reserved in full; slots above 255 require no new mapping or
 * pool budget. Keep lifetime-monotonic allocation; never recycle a slot
 * whose trampoline may still be referenced. */
#define IOS_JIT_MAX_SLOTS (0x4000 / IOS_JIT_TRAMPOLINE_SIZE)
static volatile int32_t ios_jit_next_slot = 0;  /* Next slot to allocate */

/* Allocate a per-thread trampoline slot. Returns slot index (0-based). */
int ios_jit_alloc_trampoline_slot(void)
{
    int slot = __sync_fetch_and_add(&ios_jit_next_slot, 1);
    if (slot >= IOS_JIT_MAX_SLOTS) return 0;  /* fallback to slot 0 */

    /* Write trampoline code to this slot's RW view */
    if (ios_jit_rw_base_global)
    {
        char *rw = (char *)ios_jit_rw_base_global + slot * 16;
        uint32_t *code = (uint32_t *)(rw + 8);
        code[0] = 0x58FFFFD2;  /* ldr x18, [pc-8] */
        code[1] = 0xD61F0220;  /* br x17 */
        if (ios_jit_rx_base_global)
            sys_icache_invalidate((char *)ios_jit_rx_base_global + slot * 16 + 8, 8);
    }
    return slot;
}

/* Write TEB address to a specific trampoline slot */
void ios_jit_set_teb_slot(int slot, uintptr_t teb)
{
    if (ios_jit_rw_base_global && slot >= 0 && slot < IOS_JIT_MAX_SLOTS)
    {
        *(volatile uint64_t *)((char *)ios_jit_rw_base_global + slot * 16) = teb;
    }
}

/* Get RX address of a trampoline slot's executable code */
void *ios_jit_get_trampoline(int slot)
{
    if (ios_jit_rx_base_global && slot >= 0 && slot < IOS_JIT_MAX_SLOTS)
        return (char *)ios_jit_rx_base_global + slot * 16 + 8;
    return NULL;
}

/* Reverse of the JIT translation: pool alias → original PE VA. For the
 * thread-stack dumper — a wedged thread executing PE code shows JIT-pool
 * pcs that dladdr can't name; this recovers "PE module base + offset". */
uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base )
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uint64_t jb = (uint64_t)(uintptr_t)ios_jit_mappings[i].jit_base;
        if (addr >= jb && addr < jb + ios_jit_mappings[i].size)
        {
            if (module_base) *module_base = (uint64_t)(uintptr_t)ios_jit_mappings[i].pe_base;
            return (uint64_t)(uintptr_t)ios_jit_mappings[i].pe_base + (addr - jb);
        }
    }
    if (module_base) *module_base = 0;
    return 0;
}

/* Callback registered by xtajit64 (via unix_ios_push_jit_aliases unix-call)
 * so future ios_jit_add_mapping calls automatically push aliases to FEX
 * too. Without this, late-loaded DLLs (e.g. dlopen after process init)
 * would have unregistered alias ranges and FEX would emit NoExecOp for
 * code in their copies. */
static void (*ios_jit_alias_pushback_cb)(unsigned long long, unsigned long long, unsigned long long) = NULL;
/* The process whose emulator owns ios_jit_alias_pushback_cb. Every x64
 * pseudo-process loads its OWN emulator (libarm64ecfex.dll at its own VA,
 * own pool copy, own alias table) and replaces the callback when it
 * registers, so the callback points into the pool copy of the last process
 * to register. ios_jit_reclaim_process drops it when that process exits.
 * ml1205: a sub-floor window is pushed only through its owner's callback
 * (ios_push_subfloor_window). */
static void *ios_jit_alias_pushback_peb = NULL;

/* madeira-bcd: PER-PROCESS alias pushes (env MADEIRA_ALIAS_PER_PROCESS, default
 * on; 0 restores the single last-registrant callback above).
 *
 * Each x64 pseudo-process has its own 256-entry IosAliasEntries table. Two
 * things filled the wrong ones (GTA V Enhanced, build 372, 2026-10-04 08:08 log):
 * an image mapped after a later process registered went to THAT process's table
 * (Launcher's d3d11/dxgi/oleaut32 to the RockstarService start helper's), and
 * every registration drained every process's mappings into the new table
 * (28, 114, 141, 166, 196, 232, then 250-268 pushes), so a RockstarService
 * started with a nearly full table. Its later WINTRUST.dll / cryptnet.dll
 * stayed unregistered, the delay-load stub ran from the pool copy with no
 * pool -> PE translation ("[iOS-xquery] MISS ... rev=" the same address,
 * "NoExec instruction in entry block"), the service died with c0000005, the
 * launcher reported "Failed to connect to the Rockstar Games Library Service",
 * and five restarts later the JIT pool was exhausted.
 *
 * Now each registered emulator keeps its own callback: an image goes to the
 * emulator of the process that maps it; a known process without one yet keeps
 * the image for its own drain, and only an image mapped with no PEB at all
 * goes to the last registrant as before. The drain pushes the registering
 * process's own and unattributed mappings first and other processes' only
 * while the table keeps IOS_ALIAS_DRAIN_RESERVE entries free. */
#define IOS_ALIAS_REG_MAX       32    /* emulators with a callback of their own */
#define IOS_FEX_ALIAS_MAX       256   /* kMaxEntries in FEX's IosJitAlias.cpp */
#define IOS_ALIAS_DRAIN_RESERVE 96
typedef void (*ios_alias_cb_t)(unsigned long long, unsigned long long, unsigned long long);
static struct { void *peb; ios_alias_cb_t cb; } ios_alias_cbs[IOS_ALIAS_REG_MAX];

static int ios_alias_per_process_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0)
    {
        /* Default on. 0 restores the old pushes: every image goes to the emulator
         * that registered last, and a registration drains every process's images. */
        const char *env = getenv( "MADEIRA_ALIAS_PER_PROCESS" );
        enabled = !(env && env[0] == '0' && !env[1]);
    }
    return enabled;
}

static ios_alias_cb_t ios_alias_cb_for( void *peb )
{
    int i;

    if (!peb || !ios_alias_per_process_enabled()) return NULL;
    /* acquire: ios_alias_cb_set writes the callback before the PEB */
    for (i = 0; i < IOS_ALIAS_REG_MAX; i++)
        if (__atomic_load_n( &ios_alias_cbs[i].peb, __ATOMIC_ACQUIRE ) == peb) return ios_alias_cbs[i].cb;
    return NULL;
}

static void ios_alias_cb_set( void *peb, ios_alias_cb_t cb )
{
    int i, slot = -1;

    if (!peb) return;
    for (i = 0; i < IOS_ALIAS_REG_MAX; i++)
    {
        if (ios_alias_cbs[i].peb == peb) { slot = i; break; }
        if (slot < 0 && !ios_alias_cbs[i].peb) slot = i;
    }
    if (slot < 0)
    {
        dprintf(2, "[alias-push] peb=%p: no free per-process callback slot (%d), "
                "its images go to the last registrant\n", peb, IOS_ALIAS_REG_MAX);
        return;
    }
    ios_alias_cbs[slot].cb = cb;
    __sync_synchronize();
    ios_alias_cbs[slot].peb = peb;
}

static void ios_alias_cb_drop( void *peb )
{
    int i;

    if (!peb) return;
    for (i = 0; i < IOS_ALIAS_REG_MAX; i++)
        if (ios_alias_cbs[i].peb == peb)
        {
            ios_alias_cbs[i].peb = NULL;
            __sync_synchronize();
            ios_alias_cbs[i].cb = NULL;
        }
}

void ios_jit_add_mapping(void *pe_base, void *jit_base, size_t size)
{
    ios_alias_cb_t own_cb;
    int i;

    /* Task #33: purge every entry whose PE range OVERLAPS the new image's.
     * A fresh PE image at [pe_base, pe_base+size) proves any overlapping
     * entry is STALE — two live images cannot occupy the same VA in the
     * single shared address space. The old module was unmapped (FreeLibrary
     * or pseudo-proc teardown) without this table hearing about it, and
     * mmap reused its VA. A surviving stale entry shadows the new one on
     * first-match: translate/sync_write of addresses in the overlap target
     * the DEAD pool copy (observed: CEF child's EC-ntdll dispatcher slot
     * synced into a dead copy while execution read the live copy's slot =
     * 0 → blr x16=0 null-exec storm). The old exact-pe_base dedupe was the
     * same disease — a LIVE image never reaches this call twice, because
     * mprotect_exec's already-copied check early-outs; only a stale entry
     * at the exact same VA could match, and returning kept translation on
     * the dead copy. Tombstone write order matches reclaim (size=0 first —
     * a zero-size entry matches no query — barrier, then pe_base=NULL) so
     * the lock-free readers never see a half-dead entry. */
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t eb = (uintptr_t)ios_jit_mappings[i].pe_base;
        uintptr_t nb = (uintptr_t)pe_base;
        if (!ios_jit_mappings[i].pe_base) continue;
        if (eb < nb + size && nb < eb + ios_jit_mappings[i].size)
        {
            dprintf(2, "[jit-pool] STALE image mapping purged on add: pe=%p+0x%lx jit=%p owner=%p"
                    " (overlaps new image %p+0x%lx)\n",
                    (void *)eb, (unsigned long)ios_jit_mappings[i].size,
                    ios_jit_mappings[i].jit_base, ios_jit_mappings[i].owner_peb,
                    pe_base, (unsigned long)size);
            ios_jit_mappings[i].size = 0;
            __sync_synchronize();
            ios_jit_mappings[i].pe_base = NULL;
        }
    }

    /* Task #25: prefer a tombstoned slot (pe_base==NULL, left by pool
     * reclamation) — long multi-process sessions would otherwise exhaust
     * the table even though reclaim keeps freeing entries. Fields are
     * written before pe_base (the readers' match key), with a barrier. */
    {
        int slot = -1;
        for (i = 0; i < ios_jit_mapping_count; i++)
            if (!ios_jit_mappings[i].pe_base) { slot = i; break; }
        if (slot < 0)
        {
            if (ios_jit_mapping_count >= IOS_JIT_MAX_MAPPINGS)
            {
                /* dprintf, NOT ERR: this file's ERRs are on the `virtual` channel,
                 * which the app's perf-default WINEDEBUG mutes (err-virtual) — the
                 * 64-slot overflow of 2026-07-06 was invisible for exactly that
                 * reason. Overflow leaks raw PE addresses through
                 * ios_jit_translate_addr unchanged → unfixable exec-fault loop. */
                dprintf(2, "[jit-pool] mapping table FULL (%d slots) — image pe_base=%p jit_base=%p "
                        "WILL FAIL TO TRANSLATE (exec-fault loop incoming) — bump IOS_JIT_MAX_MAPPINGS!\n",
                        IOS_JIT_MAX_MAPPINGS, pe_base, jit_base);
                return;
            }
            slot = ios_jit_mapping_count;
        }
        ios_jit_mappings[slot].jit_base = jit_base;
        ios_jit_mappings[slot].size = size;
        ios_jit_mappings[slot].text_offset = 0;
        ios_jit_mappings[slot].text_size = 0;
        ios_jit_mappings[slot].code_range_count = 0;
        ios_jit_mappings[slot].pe_image_base = 0;
        ios_jit_mappings[slot].reloc_delta = 0;
        ios_jit_mappings[slot].reloc_rva = 0;
        ios_jit_mappings[slot].reloc_size = 0;
        ios_jit_mappings[slot].owner_peb = NULL;
        ios_jit_mappings[slot].map_peb = ios_jit_current_peb();
        ios_jit_mappings[slot].machine_cached = 0;   /* ml349: slot reuse invalidates memo */
        ios_jit_mappings[slot].machine_valid = 0;
        ios_jit_mappings[slot].unmapped = 0;
        ios_jit_mappings[slot].hybrid_cached = 0;    /* ml1245: same for the EC memo */
        ios_jit_mappings[slot].hybrid_valid = 0;
        __sync_synchronize();
        ios_jit_mappings[slot].pe_base = pe_base;
        if (slot == ios_jit_mapping_count) ios_jit_mapping_count++;
    }

    /* If xtajit64 has already registered its alias-mapping push callback
     * (via the unix_ios_push_jit_aliases unix-call), forward this new
     * mapping to it too. Early mappings (added before xtajit64 loads) are
     * picked up by the iteration in unix_ios_push_jit_aliases. */
    if ((own_cb = ios_alias_cb_for( ios_jit_current_peb() )))
        own_cb((unsigned long long)(uintptr_t)pe_base, (unsigned long long)(uintptr_t)jit_base,
               (unsigned long long)size);
    /* madeira-bcd: per-process, a known process whose emulator has not
     * registered yet keeps its image to itself -- its drain pushes it (map_peb
     * == self). Handing it to the last registrant left a dead entry there once
     * the process exited and its pool range was reused: GTA V Enhanced build
     * 376 (2026-10-04 10:29), RockstarService.exe's "start" instance mapped its
     * exe before registering, the launcher's emulator got it, and the
     * launcher's cryptnet.dll later landed on that range and was reverse-
     * translated to the dead exe. */
    else if (!(ios_alias_per_process_enabled() && ios_jit_current_peb()))
    {
        /* Loaded once: a child's exit can clear it between a test and a call. */
        void (*cb)(unsigned long long, unsigned long long, unsigned long long) =
            __atomic_load_n(&ios_jit_alias_pushback_cb, __ATOMIC_ACQUIRE);
        if (cb)
            cb((unsigned long long)(uintptr_t)pe_base, (unsigned long long)(uintptr_t)jit_base,
               (unsigned long long)size);
    }
}

/* ml951: hand a sub-floor image window to FEX so QueryGuestExecutableRange can
 * answer for the low range. Reuses the alias-mapping callback deliberately: it
 * is already the PE-side-REDIRECTED pointer, hence callable from this native
 * Mach-O code. A fresh export would need its own PE binding, and an ARM64EC PE
 * entry point called directly from here is the ml613 crash (its first bytes are
 * the x64 entry thunk, fetched as ARM64). FEX routes a below-4GB first argument
 * into its query-only table -- see the ml951 block in IosJitAlias.cpp.
 *
 * Runtime off switch: MADEIRA_NO_SUBFLOOR_XQUERY=1 simply stops the push, which
 * leaves FEX's table empty and the fallback inert. Checked here because getenv
 * is safe on this side; it is NOT safe in FEX's early init (see the
 * ios_fex_band_base comment in libarm64ecfex.def). */
void ios_push_subfloor_window( unsigned long long low_base, unsigned long long real_base,
                               unsigned long long size, void *owner )
{
    static int disabled = -1;

    if (disabled < 0) disabled = (getenv( "MADEIRA_NO_SUBFLOOR_XQUERY" ) != NULL);
    if (disabled)
    {
        fprintf( stderr, "ml951: MADEIRA_NO_SUBFLOOR_XQUERY set — NOT pushing window %#llx\n",
                 low_base );
        return;
    }
    /* madeira-bcd: with per-process callbacks (ios_alias_cbs) the owner's own
     * emulator gets its window even after another process registered later,
     * which closes the gap named below. Without a registered owner callback the
     * catch-up loop of the owner's registration delivers it. */
    if (owner && ios_alias_per_process_enabled())
    {
        ios_alias_cb_t own_cb = ios_alias_cb_for( owner );
        if (!own_cb) return;   /* pushed later by the owner's catch-up loop */
        fprintf( stderr, "ml951: pushing sub-floor window guest %#llx+%#llx -> real %#llx to FEX (owner %p, own callback)\n",
                 low_base, size, real_base, owner );
        own_cb( low_base, real_base, size );
        return;
    }
    void (*cb)(unsigned long long, unsigned long long, unsigned long long) =
        __atomic_load_n(&ios_jit_alias_pushback_cb, __ATOMIC_ACQUIRE);   /* loaded once, as above */
    if (!cb) return;   /* pushed later by the catch-up loop */
    /* ml1205: another process's FEX. The owner's catch-up loop delivers it when
     * the owner's FEX starts later; a window the owner maps after another
     * process has replaced the callback is not pushed to the owner (one global
     * callback, a known gap). The owner is read after the callback: the register
     * path stores it before its release store of the callback. */
    if (owner && owner != ios_jit_alias_pushback_peb) return;
    fprintf( stderr, "ml951: pushing sub-floor window guest %#llx+%#llx -> real %#llx to FEX (owner %p)\n",
             low_base, size, real_base, owner );
    cb( low_base, real_base, size );
}

/* unix_ios_push_jit_aliases handler. Called from PE-side ntdll's
 * arm64ec_process_init_dispatchers after binding xtajit64's
 * BTCpu64IosAddAliasMapping. Stores the callback, then pushes all
 * currently-registered iOS JIT aliases through it. Future ios_jit_add_mapping
 * calls also push through the stored callback (see above). */
/* iOS-Madeira ml613: THIS MUST MATCH struct ios_push_jit_aliases_params IN
 * wine/dlls/ntdll/unixlib.h EXACTLY — ONE FIELD.
 *
 * ml549 added a second `rip_from_hostpc` member here but never added it to the
 * PE-side declaration, so `a->rip_from_hostpc` read a pointer-sized field PAST
 * the end of the caller's one-pointer struct and installed whatever happened to
 * follow it as a function pointer. Live undefined behaviour; it survived only
 * because every consumer is additionally gated on ios_fex_rip_resolved.
 *
 * ⛔ DO NOT "extend and version" this struct in place. An old one-field caller
 * gives the callee no way to discover whether bytes beyond it exist, so any
 * size/version field would itself be read out of bounds. If a richer ABI is
 * ever needed, add a NEW unix-call ordinal carrying its own size/version.
 *
 * Both FEX exports are now resolved by walking the already-mapped emulator
 * module at the end of this call instead of being passed in (see
 * ios_resolve_fex_exports). */
struct ios_push_jit_aliases_args {
    void (*callback)(unsigned long long, unsigned long long, unsigned long long);
};

/* ml549: consumed by the fault probes (srcwatch et al) so they can report the
 * instruction that actually executed instead of the block-granular RIP stored in
 * CpuStateFrame+0x18. NULL until xtajit64 binds, and on non-iOS/native paths. */
unsigned long long (*ios_fex_rip_from_hostpc_cb)(unsigned long long, unsigned long long) = NULL;
/* iOS-Madeira ml612: FEX's thread-exit lock-release hook (BTCpu64IosReleaseThreadHolds).
 * Resolved in ios_resolve_fex_exports alongside the exact-RIP export. */
unsigned int (*ios_fex_release_holds_cb)(unsigned long long *, unsigned int *, unsigned int *) = NULL;
/* ml551: set ONLY by a successful resolve. Never infer "resolved" from the pointer
 * being non-NULL -- ml550 found this global holding 0x6c6c642e65736162, i.e. the
 * ASCII "base.dll", so a non-NULL test both skipped the resolve AND let the fault
 * handler CALL a string as a function. That wild jump inside the Mach handler left
 * the srcwatch page protected, the guest's write never landed, and the window went
 * black -- we caused it. */
volatile int ios_fex_rip_resolved = 0;

/* ml549: resolve xtajit64's exact-RIP lookup WITHOUT touching PE-side ntdll.
 *
 * The obvious route (bind it in arm64ec_process_init_dispatchers and push the pointer
 * down) requires changing the unix-call struct, which changes an ABI shared with a
 * PREBUILT ntdll.dll -- an old ntdll would write one field while this side read two,
 * handing us a garbage pointer to call. Rebuilding that ntdll needs a strip+pad recipe
 * that is not in the tree, so this resolves the export here instead.
 *
 * Exact, no heuristics: ios_jit_mappings[] already records every mapped module's PE base
 * and size, and ios_pe_module_name() names them. Find the emulator module, walk its
 * export directory, done. Returns NULL (and says so) if anything is missing, so a failed
 * resolve can never be mistaken for "the lookup ran and found nothing". */
static void *ios_pe_find_export( const unsigned char *base, const char *want )
{
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_EXPORT_DIRECTORY *exp;
    const DWORD *names, *funcs;
    const WORD *ords;
    DWORD i, va, sz;

    if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (const IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    va = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    sz = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!va || !sz) return NULL;
    exp = (const IMAGE_EXPORT_DIRECTORY *)(base + va);
    names = (const DWORD *)(base + exp->AddressOfNames);
    ords  = (const WORD  *)(base + exp->AddressOfNameOrdinals);
    funcs = (const DWORD *)(base + exp->AddressOfFunctions);
    for (i = 0; i < exp->NumberOfNames; i++)
        if (!strcmp( (const char *)(base + names[i]), want ))
            return (void *)(base + funcs[ords[i]]);
    return NULL;
}

/* Versioned DATA from the rebuilt module. Offsets are compiler-produced;
 * neither a guessed CpuStateFrame tail nor an EC function call is safe. */
static unsigned ios_fex_branch_history_offset_unix;

static unsigned ios_fex_branch_layout_offset( const uint64_t layout[3] )
{
    unsigned offset = (uint32_t)layout[1], frame_size = layout[1] >> 32;
    if (layout[0] != UINT64_C(0x314744454742444d) ||
        (uint32_t)layout[2] != 272 || layout[2] >> 32 != 8 ||
        offset < 0x5c0 || (offset & 7) || frame_size > 32760 ||
        frame_size < 272 || offset > frame_size - 272) return 0;
    return offset;
}

unsigned ios_fex_branch_history_offset( void )
{
    return __atomic_load_n( &ios_fex_branch_history_offset_unix, __ATOMIC_ACQUIRE );
}

/* iOS-Madeira ml613: resolve BOTH FEX exports by walking the already-mapped
 * emulator module. Called at the END of unixcall_ios_push_jit_aliases — the
 * guaranteed initialization path — and RETRYABLE until it succeeds.
 *
 * ml612 hung the release-hook resolution off ios_resolve_fex_rip_lookup(), which
 * is only reached from a diagnostic path that did not run: ml612 shipped with
 * ios_fex_release_holds_cb permanently NULL, so its whole containment was inert
 * (verified — the run had zero [exact-rip] lines). Two rules come out of that:
 *
 *  1. Resolve on the path that ALWAYS runs, not on a probe's path.
 *  2. NEVER latch a failure. The old `static int tried` meant one early call
 *     before the module was mapped disabled resolution for the entire process
 *     lifetime. Now only success latches.
 *
 * Callbacks are published only after both lookups complete, and the resolved
 * flag is set LAST, so a concurrent reader either sees the old state or a fully
 * populated one — never a half-installed pair. */
void ios_resolve_fex_exports( void )
{
    int i;

    /* ml614: latch on the POINTERS, not on ios_fex_rip_resolved — that flag is
     * deliberately never set now (see below), so keying the early-out on it would
     * re-parse the PE export table on every call, and one caller is a fault path. */
    if (ios_fex_rip_from_hostpc_cb && ios_fex_release_holds_cb) return;  /* fully done */

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        void *rip_cb, *rel_cb;
        const char *nm = ios_pe_module_name( ios_jit_mappings[i].pe_base,
                                             ios_jit_mappings[i].size );
        if (!nm) continue;
        if (!strstr( nm, "xtajit64" ) && !strstr( nm, "arm64ecfex" )) continue;

        rip_cb = ios_pe_find_export( ios_jit_mappings[i].pe_base, "BTCpu64IosRipFromHostPC" );
        rel_cb = ios_pe_find_export( ios_jit_mappings[i].pe_base, "BTCpu64IosReleaseThreadHolds" );

        {
            const void *data = ios_pe_find_export( ios_jit_mappings[i].pe_base, "IosGuestBranchTraceLayout" );
            uintptr_t base = (uintptr_t)ios_jit_mappings[i].pe_base, address = (uintptr_t)data;
            size_t image_size = ios_jit_mappings[i].size;
            uint64_t layout[3] = {0};
            mach_vm_size_t got = 0;
            unsigned offset;
            if (data && image_size >= sizeof(layout) && address >= base &&
                address - base <= image_size - sizeof(layout) &&
                mach_vm_read_overwrite( mach_task_self(), address, sizeof(layout),
                    (mach_vm_address_t)layout, &got ) == KERN_SUCCESS && got == sizeof(layout) &&
                (offset = ios_fex_branch_layout_offset( layout )))
            {
                __atomic_store_n( &ios_fex_branch_history_offset_unix, offset, __ATOMIC_RELEASE );
                dprintf( 2, "[fex-edges] DATA layout v1 frame-offset=%u frame-size=%u history=272 capacity=8\n",
                         offset, (unsigned)(layout[1] >> 32) );
            }
        }

        /* Record the addresses for diagnostics. */
        if (rip_cb) ios_fex_rip_from_hostpc_cb = (void *)rip_cb;
        if (rel_cb) ios_fex_release_holds_cb = (void *)rel_cb;
        __sync_synchronize();

        /* ⛔⛔ ml614: DO NOT ARM ios_fex_rip_resolved.
         *
         * These are ARM64EC **PE** exports. They are NOT callable from this
         * (native Mach-O) code — their first bytes are the x64 entry thunk, which
         * a native `blr` fetches as ARM64 instructions. ml613 armed them and
         * crashed every single launch:
         *
         *   [xlate-exec] pc=0x71f99c4040 -> 0x125528040
         *   [av-detail]  hostpc=0x125528040 hinsn=0x48c48b48   (x64 `48 8b c4 48`)
         *   -> c0000005 in pthread_exit_wrapper, then c000001d
         *
         * ios_fex_rip_resolved gates the exact-RIP call in signal_arm64_ios.c.
         * That path had NEVER executed before ml613 (the old resolver was reached
         * only from a diagnostic entry point that never ran, and before that the
         * pointer came from an out-of-bounds struct read), so arming it was a new
         * live call, not a restoration.
         *
         * Re-arming requires EITHER a genuinely native ARM64 C-ABI bridge on FEX's
         * host side, OR making the call from code already running inside the
         * ARM64EC environment. Also PEB-key it first: this resolver latches the
         * FIRST libarm64ecfex.dll mapping globally, and there are several
         * pseudo-process instances in one Mach task. */
        dprintf( 2, "[fex-exports] ml614 module=%s base=%p rip_from_hostpc=%p release_holds=%p "
                    "(%s) -- RECORDED BUT NOT ARMED: EC PE exports are not callable "
                    "from native code (ml613 regression)\n",
                 nm, ios_jit_mappings[i].pe_base, rip_cb, rel_cb,
                 (rip_cb && rel_cb) ? "both found"
                                    : (rel_cb ? "release-only" : (rip_cb ? "rip-only" : "neither — will retry")) );
        return;
    }
    dprintf( 2, "[fex-exports] ml613 emulator module not in ios_jit_mappings (%d entries) "
                "-- will retry on the next alias push\n", ios_jit_mapping_count );
}

/* iOS-Madeira ml618: per-pseudo-process leaked-hold release callback.
 *
 * The pointer stored here MUST have come from the PE side's GET_PTR path
 * (arm64ec_redirect_ptr -> xlate_ios_jit), which yields an executable ARM64
 * alias in the JIT pool. ml613 stored a base+RVA pointer instead — the raw x64
 * entry thunk — and every launch died executing `48 8b c4 48...` as ARM64.
 * The PE side self-tests the pointer before registering it.
 *
 * PEB-keyed: several pseudo-processes share this Mach task, each with its own
 * FEX context and its own CodeInvalidationMutex. Using one global callback
 * would release against the wrong context. */
#define IOS_HOLD_RELEASE_MAX 32
static struct { void *peb; unsigned int (*cb)(void *, unsigned long long *, unsigned int *, unsigned int *); }
    ios_hold_release[IOS_HOLD_RELEASE_MAX];
static int ios_hold_release_n;

unsigned int (*ios_hold_release_lookup(void *peb))(void *, unsigned long long *, unsigned int *, unsigned int *)
{
    int i;
    for (i = 0; i < ios_hold_release_n; i++)
        if (ios_hold_release[i].peb == peb) return ios_hold_release[i].cb;
    return NULL;
}

struct ios_register_hold_release_args
{
    unsigned int size;
    unsigned int version;
    void *peb;
    void *callback;
};

NTSTATUS unixcall_ios_register_hold_release(void *args)
{
    struct ios_register_hold_release_args *p = args;
    int i;

    if (!p || p->size != sizeof(*p) || p->version != 1 || !p->peb || !p->callback)
    {
        dprintf(2, "[hold-release] ml618 REJECTED registration (size=%u want=%u version=%u peb=%p cb=%p)\n",
                p ? p->size : 0, (unsigned)sizeof(*p), p ? p->version : 0,
                p ? p->peb : NULL, p ? p->callback : NULL);
        return STATUS_INVALID_PARAMETER;
    }
    for (i = 0; i < ios_hold_release_n; i++)
        if (ios_hold_release[i].peb == p->peb)
        {
            ios_hold_release[i].cb = p->callback;
            dprintf(2, "[hold-release] ml618 re-registered peb=%p cb=%p slot=%d\n", p->peb, p->callback, i);
            return STATUS_SUCCESS;
        }
    if (ios_hold_release_n >= IOS_HOLD_RELEASE_MAX)
    {
        dprintf(2, "[hold-release] ml618 TABLE FULL (%d) — peb=%p will leak holds\n",
                ios_hold_release_n, p->peb);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ios_hold_release[ios_hold_release_n].peb = p->peb;
    ios_hold_release[ios_hold_release_n].cb  = p->callback;
    ios_hold_release_n++;
    dprintf(2, "[hold-release] ml618 registered peb=%p cb=%p (%d live)\n",
            p->peb, p->callback, ios_hold_release_n);
    return STATUS_SUCCESS;
}

/* A child pseudo-process's emulator must know the child's OWN ntdll copy.
 *
 * Every x64 pseudo-process starts its own emulator with its own alias table,
 * which unixcall_ios_push_jit_aliases fills when the emulator registers. A
 * child runs a private copy of ntdll (ios_jit_copy_module_for_child), but the
 * drain pushed only NULL-owner entries, so a child's emulator mapped ntdll to
 * the PARENT's copy and could not reverse-translate an address in its own.
 *
 * That kills a child at its first x64 syscall: ntdll's dispatch_syscall (EC
 * code running from the child's copy) sets the x64 Pc to
 * invoke_arm64ec_syscall through an ADRP, i.e. in the child's pool copy, and
 * resumes emulation there. FEX maps a pool-copy RIP back to its PE VA only
 * through this table ([pool-rip-fix]); in a child it missed, the frontend
 * refused the pool address as NoExec and the thread died on an access
 * violation (GTA V Enhanced's PlayGTAV.exe / GTA5_Enhanced.exe children,
 * Ghost of Tsushima's crs-handler.exe).
 *
 * FEX keeps one entry per PE range, so exactly one copy of an image is pushed:
 * the registering process's own copy if it has one, else the NULL-owner
 * entry. Other processes' copies are never pushed. A main process owns no
 * copies, so what it pushes is unchanged. */
static int ios_jit_owned_copy( void *pe_base, void *peb )
{
    int i;

    if (!pe_base || !peb) return -1;
    for (i = 0; i < ios_jit_mapping_count; i++)
        if (ios_jit_mappings[i].pe_base == pe_base && ios_jit_mappings[i].size &&
            ios_jit_mappings[i].owner_peb == peb)
            return i;
    return -1;
}

/* Does the drain for the emulator of process `own` push mapping i? */
static int ios_jit_alias_drain_wants( int i, void *own )
{
    void *owner = ios_jit_mappings[i].owner_peb;

    if (owner)
        return own && owner == own && ios_jit_mappings[i].pe_base && ios_jit_mappings[i].size;
    return ios_jit_owned_copy( ios_jit_mappings[i].pe_base, own ) < 0;
}

NTSTATUS unixcall_ios_push_jit_aliases(void *args)
{
    /* ml613: the ml549 stash that used to live here read a->rip_from_hostpc, a
     * field the PE-side struct never declared — an out-of-bounds read. Deleted;
     * both exports are resolved from the mapped module at the end of this call. */
    struct ios_push_jit_aliases_args *params = args;
    /* the registering process is the one running this unix call (PE ntdll's
     * arm64ec_process_init_dispatchers, on its first thread) */
    void *self = ios_jit_current_peb();
    int i, pass, pushed = 0, own_pushed = 0, others_left = 0;
    if (!params || !params->callback) return STATUS_INVALID_PARAMETER;
    ios_jit_alias_pushback_peb = self;
    __atomic_store_n(&ios_jit_alias_pushback_cb, params->callback, __ATOMIC_RELEASE);
    if (ios_alias_per_process_enabled()) ios_alias_cb_set( self, params->callback );

    /* ml951: any sub-floor window registered before xtajit64 loaded has not been
     * pushed yet — the per-registration push above needs this callback. Catch up,
     * with this process's own windows and the shared ones only (ml1205). */
    {
        extern int ios_subfloor_enum( int idx, unsigned long long *low,
                                      unsigned long long *real, unsigned long long *size,
                                      void **owner );
        unsigned long long lo, re, sz;
        void *own;
        int i;
        for (i = 0; ios_subfloor_enum( i, &lo, &re, &sz, &own ); i++)
            if (sz && (!own || own == self))
                ios_push_subfloor_window( lo, re, sz, own );
    }
    /* Drain current table to the callback. A child-owned copy shares pe_base
     * with the parent entry and FEX keeps one entry per PE range, so only one
     * of the two is pushed: the registering process's own copy if it has one,
     * else the parent entry (ios_jit_alias_drain_wants).
     * madeira-bcd: pass 0 pushes this process's own and unattributed mappings,
     * pass 1 other processes' while the table keeps IOS_ALIAS_DRAIN_RESERVE
     * free (see ios_alias_per_process_enabled); one pass when that is off. */
    for (pass = 0; pass < 2; pass++)
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        if (ios_alias_per_process_enabled() && self)
        {
            void *mapper = ios_jit_mappings[i].map_peb;
            int mine = ios_jit_mappings[i].owner_peb == self || !mapper || mapper == self;

            if (mine != !pass) continue;
            if (pass && ios_jit_alias_drain_wants( i, self ) &&
                pushed >= IOS_FEX_ALIAS_MAX - IOS_ALIAS_DRAIN_RESERVE)
            {
                others_left++;
                continue;
            }
        }
        else if (pass) break;
        if (!ios_jit_alias_drain_wants( i, self )) continue;
        if (ios_jit_mappings[i].owner_peb) own_pushed++;
        params->callback((unsigned long long)(uintptr_t)ios_jit_mappings[i].pe_base,
                         (unsigned long long)(uintptr_t)ios_jit_mappings[i].jit_base,
                         (unsigned long long)ios_jit_mappings[i].size);
        pushed++;
    }
    if (own_pushed)
        dprintf(2, "[alias-push] peb=%p registered its emulator: %d image(s) mapped to this "
                "process's own copy instead of the parent's\n", self, own_pushed);
    if (others_left)
        dprintf(2, "[alias-push] peb=%p: %d mapping(s) pushed, %d of other processes left out to keep "
                "%d table entries free (MADEIRA_ALIAS_PER_PROCESS)\n", self, pushed, others_left,
                IOS_ALIAS_DRAIN_RESERVE);
    /* ml613: the guaranteed init path — resolve both FEX exports here, where the
     * emulator module is certainly mapped, instead of from a diagnostic probe
     * (ml612's mistake) or from a dying thread inside pthread_exit (needlessly
     * risky: parsing exports while the thread holds FEX locks). */
    ios_resolve_fex_exports();
    ERR("unixcall_ios_push_jit_aliases: registered callback + drained %d mappings\n",
        ios_jit_mapping_count);
    return STATUS_SUCCESS;
}

/* ml630: returns 1 on success, 0 if no slot could be claimed. A caller that maps
 * new executable memory MUST NOT report success when this fails -- writes to that
 * range would then silently not route, which is exactly how the ULTRAKILL main
 * thread died. */
/* ============================ ml648 MONO BRIDGE ============================
 * See ios_mono_bridge.h for why this table is SEPARATE from IosAliasEntries.
 * Short version: Module.S's ios_ffs_xlate_loop rewrites control-flow targets
 * through that table, so a guest-RX -> RW pair in it would send calls into the
 * non-executable mapping. Only MonoBackpatcherWrite reads this one. */
#include "ios_mono_bridge.h"

struct ios_mono_bridge g_ios_mono_bridge = { .abi_version = 2 };  /* ml649: struct grew */

/* ml649: RUNTIME DIAGNOSTIC SWITCH.
 *
 * Default OFF (quiet/fast). The app toggles it live, which beats a separate
 * quiet build for the reason that matters to benchmarking: loud and quiet can
 * be compared inside ONE run, on the same scene at the same thermal state. Two
 * builds cannot give you that.
 *
 * ⚠️ Gate the WORK, not the PRINT. Several probes do an expensive read (Mach
 * calls, dual-map readback, hashing) and only then decide whether to format a
 * line; wrapping just the dprintf would save nothing. */
volatile int madeira_diag_enabled = 0;

void madeira_set_diag_enabled( int on )
{
    __atomic_store_n( &madeira_diag_enabled, on ? 1 : 0, __ATOMIC_RELAXED );
    /* Publish to FEX too — it is a separate PE and cannot see this global. */
    __atomic_store_n( &g_ios_mono_bridge.diag_enabled, on ? 1u : 0u, __ATOMIC_RELAXED );
    dprintf( 2, "[diag] ml649 diagnostics %s\n", on ? "ON" : "OFF (quiet)" );
}

int madeira_get_diag_enabled( void ) { return __atomic_load_n( &madeira_diag_enabled, __ATOMIC_RELAXED ); }

/* Faulting-thread registers are not trusted, and a probe must never fault
 * inside a fault. Every dereference on the capture path goes through here —
 * the same discipline the ml612 Floyd probe used. */
static int ios_safe_read64( uint64_t addr, uint64_t *out )
{
    mach_vm_size_t got = 0;
    if (addr < 0x1000 || (addr & 7)) return -1;
    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)addr,
                                8, (mach_vm_address_t)out, &got ) != KERN_SUCCESS)
        return -1;
    return got == 8 ? 0 : -1;
}

/* Sequence-lock publication. Live entries carry an ODD generation; the writer
 * bumps to EVEN first so any concurrent reader rejects the entry while its
 * fields are in flux, then bumps to ODD once they are settled. A reader that
 * samples the generation, reads, and samples again accepts only when both
 * samples are equal and odd — so a retired-and-reused slot can never be
 * mistaken for a live one, which is the case that would corrupt guest memory. */
void ios_mono_alias_publish( uint64_t guest_rx, uint64_t host_rw, uint64_t size )
{
    struct ios_mono_bridge *b = &g_ios_mono_bridge;
    unsigned int i, count = __atomic_load_n( &b->alias_count, __ATOMIC_ACQUIRE );

    for (i = 0; i < count; i++)
    {
        if (b->aliases[i].guest_rx != guest_rx) continue;
        __atomic_add_fetch( &b->aliases[i].generation, 1, __ATOMIC_RELEASE );   /* -> even, readers miss */
        b->aliases[i].host_rw = host_rw;
        b->aliases[i].size    = size;
        __atomic_add_fetch( &b->aliases[i].generation, 1, __ATOMIC_RELEASE );   /* -> odd, live again */
        return;
    }
    if (count >= IOS_MONO_MAX_ALIASES) return;   /* full: miss, never overwrite */

    b->aliases[count].guest_rx = guest_rx;
    b->aliases[count].host_rw  = host_rw;
    b->aliases[count].size     = size;
    __atomic_store_n( &b->aliases[count].generation, 1, __ATOMIC_RELEASE );     /* odd = live */
    __atomic_store_n( &b->alias_count, count + 1, __ATOMIC_RELEASE );
}

void ios_mono_alias_retire( uint64_t guest_rx )
{
    struct ios_mono_bridge *b = &g_ios_mono_bridge;
    unsigned int i, count = __atomic_load_n( &b->alias_count, __ATOMIC_ACQUIRE );

    for (i = 0; i < count; i++)
    {
        if (b->aliases[i].guest_rx != guest_rx) continue;
        if (b->aliases[i].generation & 1)
            __atomic_add_fetch( &b->aliases[i].generation, 1, __ATOMIC_RELEASE ); /* -> even, dead */
        return;
    }
}

/* Handed to FEX once, PE->unix via WINE_UNIX_CALL — the safe direction. The
 * reverse (native calling an ARM64EC export) is what killed every ml613 launch. */
NTSTATUS unixcall_ios_mono_bridge_ptr( void *args )
{
    /* ml648: publish the FEX code range HERE, not from FEX — this side owns the
     * JIT pool and knows its exact bounds. The Mach handler uses it to reject an
     * implausible BlockBegin BEFORE dereferencing it; if the pool is not up yet
     * the range stays 0, which disables that check rather than inventing one. */
    {
        extern void *ios_jit_rx_base_global;
        extern size_t ios_jit_pool_size_global;
        if (ios_jit_rx_base_global && ios_jit_pool_size_global)
        {
            g_ios_mono_bridge.code_lo = (uint64_t)ios_jit_rx_base_global;
            g_ios_mono_bridge.code_hi = (uint64_t)ios_jit_rx_base_global + ios_jit_pool_size_global;
        }
    }
    *(uint64_t *)args = (uint64_t)&g_ios_mono_bridge;
    /* ml648 LIVENESS, one line, once. Without it a quiet run cannot be told
     * apart from a dead one: "no qualifying SWPAL happened" and "the bridge was
     * never wired up at all" look identical in the log. Absence of a probe
     * string is not absence of the failure. FEX prints the companion lines once
     * it has published the offsets and once it arms Mono. */
    {
        static int once;
        if (!once++)
            dprintf(2, "[mono-bridge] ml648 REGISTERED bridge=%p abi=%u code=[%p,%p) -- awaiting FEX"
                       " offsets (capture stays inert until mono_base is armed)\n",
                    (void *)&g_ios_mono_bridge, g_ios_mono_bridge.abi_version,
                    (void *)g_ios_mono_bridge.code_lo, (void *)g_ios_mono_bridge.code_hi);
    }
    return 0;
}

/* Capture, called from the Mach SWPAL path. Records RAW FACTS ONLY: no guest
 * RIP reconstruction, no opcode decode, no allocation, no formatting, no locks.
 * Every interpretation happens later at the FEX safe point where
 * ios_fex_rip_from_hostpc() already exists. */
void ios_mono_bridge_capture( uint64_t teb, uint64_t frame, uint64_t host_pc, uint64_t fault_addr )
{
    struct ios_mono_bridge *b = &g_ios_mono_bridge;
    uint64_t block_begin, context = 0;
    unsigned int i;

    /* Key by PEB, not by process-globals: pseudo-processes share one address
     * space, so a single slot would let one process's fault mark another's
     * block. TEB->PEB is at +0x60. Safe-read it — x18 came from a faulting
     * thread and is not trusted. */
    if (!teb || ios_safe_read64( teb + 0x60, &context ) || !context) return;

    /* Offsets unpublished => FEX has not initialised => capture disabled. The
     * safe default: never guess a struct layout inside a fault handler. */
    if (!b->off_inline_jit_block_header && !b->off_block_tail && !b->off_tail_rip) return;
    if (!b->mono_base) { __atomic_add_fetch( &b->n_reject_unarmed, 1, __ATOMIC_RELAXED ); return; }
    if (!frame)        { __atomic_add_fetch( &b->n_reject_no_frame, 1, __ATOMIC_RELAXED ); return; }

    /* frame + off = InlineJITBlockHeader. Read defensively; this pointer comes
     * from a register in a faulting thread and is not trusted. */
    if (ios_safe_read64( frame + b->off_inline_jit_block_header, &block_begin ) || !block_begin)
    { __atomic_add_fetch( &b->n_reject_bad_block, 1, __ATOMIC_RELAXED ); return; }
    /* Must look like a JIT block, or we would hand FEX a wild pointer. madeira-bcd
     * pool-low: FEX's code buffers may also live in region C, outside [code_lo,
     * code_hi) (the pool span). */
    if (b->code_lo && (block_begin < b->code_lo || block_begin >= b->code_hi) &&
        !ios_jit_low_contains( (uintptr_t)block_begin ))
    { __atomic_add_fetch( &b->n_reject_outside_code, 1, __ATOMIC_RELAXED ); return; }

    for (i = 0; i < IOS_MONO_MAX_CONTEXTS; i++)
    {
        struct ios_mono_pending *p = &b->pending[i];
        uint64_t owner = __atomic_load_n( &p->context, __ATOMIC_ACQUIRE );

        if (owner != context)
        {
            if (owner) continue;
            if (!__atomic_compare_exchange_n( &p->context, &owner, context, 0,
                                              __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE )) continue;
        }
        /* One-shot per context: state 2 means FEX already activated. */
        if (__atomic_load_n( &p->state, __ATOMIC_ACQUIRE )) return;

        p->block_begin = block_begin;
        p->host_pc     = host_pc;
        p->fault_addr  = fault_addr;
        __atomic_store_n( &p->state, 1, __ATOMIC_RELEASE );      /* publish last */
        __atomic_add_fetch( &b->n_captured, 1, __ATOMIC_RELAXED );
        return;
    }
}
/* ========================== end ml648 MONO BRIDGE ========================= */

int ios_jit_anon_alias_add(void *user_va, size_t size, void *jit_rw_alias)
{
    int idx = -1, i;

    /* Task #25: reuse slots cleared by pool reclamation (user_va==0) — FEX
     * children each add aliases and the 32-slot table used to only grow.
     * Serialized by the pool lock (adds are rare: CodeBuffer allocations).
     * Write user_va LAST — it's the match key for the lock-free readers. */
    pthread_mutex_lock( &ios_pool_lock );

    /* iOS-Madeira ml625: AN OVERLAPPING LIVE ENTRY IS STALE BY CONSTRUCTION.
     *
     * Two live mappings cannot own the same guest VA, but this table used to
     * APPEND duplicates and ios_jit_anon_alias_lookup() returns the FIRST match
     * -- i.e. the OLDEST, now-dead backing. In the ml624 ULTRAKILL run Mono's
     * code buffer 0x7040220000 was remapped three times onto fresh 16KB pool
     * slots (0xa574000/0xa578000/0xa57c000) while the live code and its
     * UNWIND_INFO sat in the original 0xa0dc000 slot. The table kept handing out
     * the original while the guest VA had been overwritten with zeroed pages, so
     * RtlVirtualUnwind2 read unwind version 0 and looped ~15.8M times until the
     * 8MB guest stack was gone.
     *
     * Replace the slot in place so the table can never describe two backings for
     * one VA. (The real fix is upstream -- the remap is now idempotent -- but this
     * keeps the invariant true even if some other path ever re-registers.) */
    for (i = 0; i < ios_jit_anon_alias_count; i++)
    {
        if (!ios_jit_anon_aliases[i].user_va) continue;
        if ((uintptr_t)user_va < ios_jit_anon_aliases[i].user_va_end &&
            ios_jit_anon_aliases[i].user_va < (uintptr_t)user_va + size)
        {
            dprintf(2, "[jit-alias] ml625 REPLACE overlapping entry %d: old %p..%p rw=%p -> new %p+0x%lx rw=%p\n",
                    i, (void *)ios_jit_anon_aliases[i].user_va,
                    (void *)ios_jit_anon_aliases[i].user_va_end,
                    (void *)ios_jit_anon_aliases[i].jit_rw_alias,
                    user_va, (unsigned long)size, jit_rw_alias);
            idx = i;
            break;
        }
    }

    if (idx < 0)
        for (i = 0; i < ios_jit_anon_alias_count; i++)
            if (!ios_jit_anon_aliases[i].user_va) { idx = i; break; }
    if (idx < 0)
    {
        if (ios_jit_anon_alias_count >= IOS_JIT_MAX_ANON_ALIASES) {
            pthread_mutex_unlock( &ios_pool_lock );
            ERR("iOS JIT: anon alias table full (%d)\n", ios_jit_anon_alias_count);
            dprintf(2, "[jit-pool] anon alias table FULL (%d slots) — writes to %p will NOT route! "
                       "live=%d tombstones=%d hiwater=%d rev=ml630\n",
                    IOS_JIT_MAX_ANON_ALIASES, user_va, ios_jit_anon_alias_live,
                    ios_jit_anon_alias_tombstones, ios_jit_anon_alias_hiwater);
            return 0;
        }
        idx = ios_jit_anon_alias_count;
    }
    ios_jit_anon_aliases[idx].user_va_end = (uintptr_t)user_va + size;
    ios_jit_anon_aliases[idx].jit_rw_alias = (uintptr_t)jit_rw_alias;
    ios_jit_anon_aliases[idx].jit_rx_alias = 0;  /* set via _set_rx */
    __sync_synchronize();
    /* ml648: retire the slot's previous occupant before it is overwritten, or a
     * stale guest_rx would keep resolving to an RW alias that no longer backs it. */
    if (ios_jit_anon_aliases[idx].user_va && ios_jit_anon_aliases[idx].user_va != (uintptr_t)user_va)
        ios_mono_alias_retire( ios_jit_anon_aliases[idx].user_va );
    ios_jit_anon_aliases[idx].user_va = (uintptr_t)user_va;
    ios_mono_alias_publish( (uintptr_t)user_va, (uintptr_t)jit_rw_alias, size );
    if (idx == ios_jit_anon_alias_count) ios_jit_anon_alias_count = idx + 1;
    else ios_jit_anon_alias_tombstones++;   /* reclaimed a retired slot */
    if (++ios_jit_anon_alias_live > ios_jit_anon_alias_hiwater)
        ios_jit_anon_alias_hiwater = ios_jit_anon_alias_live;
    {
        /* Periodic census so the ceiling is never a surprise again. */
        static int census_n;
        if (ios_jit_anon_alias_live == 1 || (ios_jit_anon_alias_live % 64) == 0 || census_n < 4) {
            census_n++;
            dprintf(2, "[jit-alias] ml630 census live=%d used_slots=%d cap=%d hiwater=%d tombstones=%d\n",
                    ios_jit_anon_alias_live, ios_jit_anon_alias_count,
                    IOS_JIT_MAX_ANON_ALIASES, ios_jit_anon_alias_hiwater,
                    ios_jit_anon_alias_tombstones);
        }
    }
    pthread_mutex_unlock( &ios_pool_lock );
    return 1;
}

/* The guest released [base, base+len) (NtFreeVirtualMemory, MEM_RELEASE): drop every anon-RWX alias that starts
 * inside it. The table is keyed by guest address and was only emptied at process exit or when the pool range was
 * handed out again, so a later RWX allocation at the same address found the old entry (mprotect_exec reuses a live
 * alias that covers the range) and kept the old backing: stores routed through the stale alias went to the old pool
 * slot, not to the new memory. Every allocate/free cycle at a new address also left an entry behind, so the table
 * filled after 4096 of them. The pool backing itself stays charged to the process until it exits. Called with
 * virtual_mutex held; takes ios_pool_lock like ios_jit_retire_image. */
static void ios_jit_anon_alias_retire_range( void *base, size_t len )
{
    uintptr_t lo = (uintptr_t)base, hi = lo + len;
    int i, retired = 0;

    if (!ios_jit_anon_alias_count) return;
    pthread_mutex_lock( &ios_pool_lock );
    for (i = 0; i < ios_jit_anon_alias_count; i++)
    {
        uintptr_t b = ios_jit_anon_aliases[i].user_va;
        if (!b || b < lo || (len ? b >= hi : b != lo)) continue;
        ios_jit_anon_aliases[i].user_va_end = 0;     /* readers match on user_va and the end: close the range first */
        __sync_synchronize();
        ios_mono_alias_retire( b );
        ios_jit_anon_aliases[i].user_va = 0;
        ios_jit_anon_alias_live--;
        retired++;
    }
    pthread_mutex_unlock( &ios_pool_lock );
    if (retired)
    {
        static unsigned int logs;
        if (__sync_fetch_and_add( &logs, 1 ) < 8)
            dprintf( 2, "[jit-alias] guest free of %p+%#lx: retired %d anon-RWX alias(es)\n",
                     base, (unsigned long)len, retired );
    }
}

/* iOS-Madeira ml625: is [user_va, user_va+size) ALREADY backed by a live anon
 * alias? Used to make the anonymous-RWX remap idempotent -- see the call site in
 * the mprotect(PROT_EXEC) path. Returns 1 and fills the aliases (offset-adjusted
 * for the requested base) when an existing entry fully covers the request. */
/* iOS-Madeira ml631: read-only alias probe for the PE-side fault reporter.
 * Pure lookup — takes no locks, mutates nothing, safe to call from a fault path. */
NTSTATUS unixcall_ios_jit_alias_probe( void *args )
{
    struct ios_jit_alias_probe_params *p = args;
    int n, i;

    if (!p || p->size < sizeof(*p)) return STATUS_INVALID_PARAMETER;
    p->rw = p->base = p->end = 0;

    n = ios_jit_anon_alias_count;
    for (i = 0; i < n; i++)
    {
        uintptr_t b = ios_jit_anon_aliases[i].user_va;
        if (!b) continue;
        if (p->addr < b || p->addr >= ios_jit_anon_aliases[i].user_va_end) continue;
        p->rw   = (unsigned long long)(ios_jit_anon_aliases[i].jit_rw_alias + (p->addr - b));
        p->base = (unsigned long long)b;
        p->end  = (unsigned long long)ios_jit_anon_aliases[i].user_va_end;
        p->write_gen = ios_alias_write_gen[i];
        p->written   = ios_alias_written[i];
        p->highest   = ios_alias_highest[i];
        p->rw_base   = (unsigned long long)ios_jit_anon_aliases[i].jit_rw_alias;
        p->rx_base   = (unsigned long long)ios_jit_anon_aliases[i].jit_rx_alias;
        p->slot      = (unsigned)i;
        break;
    }
    /* ml636: NOTHING CONTAINS addr — try an alias that ENDS exactly there.
     *
     * The ULTRAKILL fatal RIP is one-past a 64KB Mono buffer (twice consecutively,
     * relocated), so "the alias containing RIP" is empty BY CONSTRUCTION and the
     * ml635 telemetry could never fire for it. The interesting alias is the one
     * that ENDS there. */
    if (!p->base)
    {
        n = ios_jit_anon_alias_count;
        for (i = 0; i < n; i++)
        {
            if (!ios_jit_anon_aliases[i].user_va) continue;
            if (ios_jit_anon_aliases[i].user_va_end != p->addr) continue;
            p->base      = (unsigned long long)ios_jit_anon_aliases[i].user_va;
            p->end       = (unsigned long long)ios_jit_anon_aliases[i].user_va_end;
            p->rw        = (unsigned long long)ios_jit_anon_aliases[i].jit_rw_alias;
            p->write_gen = ios_alias_write_gen[i];
            p->written   = ios_alias_written[i];
            p->highest   = ios_alias_highest[i];
            p->rw_base   = (unsigned long long)ios_jit_anon_aliases[i].jit_rw_alias;
            p->rx_base   = (unsigned long long)ios_jit_anon_aliases[i].jit_rx_alias;
            p->slot      = (unsigned)i;
            p->at_end    = 1;
            break;
        }
    }
    /* ml639: how many LIVE entries claim this same end? Retires the "maybe the probe
     * matched a stale duplicate" hypothesis by measurement instead of by argument. */
    if (p->base)
    {
        n = ios_jit_anon_alias_count;
        for (i = 0; i < n; i++)
            if (ios_jit_anon_aliases[i].user_va &&
                ios_jit_anon_aliases[i].user_va_end == p->end) p->dup_end++;
    }
    return STATUS_SUCCESS;
}

/* iOS-Madeira ml632: does [user_va, +size) OVERLAP any live anon-JIT alias?
 * find_cover() asks for full containment; the mixed-mapping bug is precisely a
 * PARTIAL overlap, so it needs its own test. Returns 1 and reports the entry. */
int ios_jit_anon_alias_overlaps(void *user_va, size_t size, uintptr_t *base_out, uintptr_t *end_out)
{
    uintptr_t lo = (uintptr_t)user_va, hi = lo + size;
    int n = ios_jit_anon_alias_count, i;

    for (i = 0; i < n; i++)
    {
        uintptr_t b = ios_jit_anon_aliases[i].user_va, e;
        if (!b) continue;
        e = ios_jit_anon_aliases[i].user_va_end;
        if (lo < e && b < hi)
        {
            if (base_out) *base_out = b;
            if (end_out)  *end_out  = e;
            return 1;
        }
    }
    return 0;
}

int ios_jit_anon_alias_find_cover(void *user_va, size_t size, void **rw_out, void **rx_out)
{
    uintptr_t lo = (uintptr_t)user_va, hi = lo + size;
    int n = ios_jit_anon_alias_count;
    int i;

    for (i = 0; i < n; i++)
    {
        uintptr_t base = ios_jit_anon_aliases[i].user_va;
        if (!base) continue;
        if (lo < base || hi > ios_jit_anon_aliases[i].user_va_end) continue;
        if (!ios_jit_anon_aliases[i].jit_rx_alias) continue; /* incomplete registration */
        if (rw_out) *rw_out = (void *)(ios_jit_anon_aliases[i].jit_rw_alias + (lo - base));
        if (rx_out) *rx_out = (void *)(ios_jit_anon_aliases[i].jit_rx_alias + (lo - base));
        return 1;
    }
    return 0;
}

void ios_jit_anon_alias_set_rx(void *user_va, void *jit_rx_alias)
{
    int n = ios_jit_anon_alias_count;
    int i;
    for (i = 0; i < n; i++) {
        if ((uintptr_t)user_va == ios_jit_anon_aliases[i].user_va) {
            ios_jit_anon_aliases[i].jit_rx_alias = (uintptr_t)jit_rx_alias;
            return;
        }
    }
}

uintptr_t ios_jit_anon_alias_lookup(uintptr_t fault_addr)
{
    int n = ios_jit_anon_alias_count;
    int i;
    for (i = 0; i < n; i++) {
        if (fault_addr >= ios_jit_anon_aliases[i].user_va &&
            fault_addr <  ios_jit_anon_aliases[i].user_va_end) {
            return ios_jit_anon_aliases[i].jit_rw_alias +
                   (fault_addr - ios_jit_anon_aliases[i].user_va);
        }
    }
    return 0;
}

uintptr_t ios_jit_anon_alias_lookup_rx(uintptr_t fault_addr)
{
    int n = ios_jit_anon_alias_count;
    int i;
    for (i = 0; i < n; i++) {
        if (fault_addr >= ios_jit_anon_aliases[i].user_va &&
            fault_addr <  ios_jit_anon_aliases[i].user_va_end) {
            if (!ios_jit_anon_aliases[i].jit_rx_alias) return 0;
            return ios_jit_anon_aliases[i].jit_rx_alias +
                   (fault_addr - ios_jit_anon_aliases[i].user_va);
        }
    }
    return 0;
}

void ios_jit_set_reloc_info(void *pe_base, uint64_t pe_image_base, intptr_t delta,
                            unsigned int reloc_rva, unsigned int reloc_size)
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        if (ios_jit_mappings[i].pe_base == pe_base)
        {
            ios_jit_mappings[i].pe_image_base = pe_image_base;
            ios_jit_mappings[i].reloc_delta = delta;
            ios_jit_mappings[i].reloc_rva = reloc_rva;
            ios_jit_mappings[i].reloc_size = reloc_size;
            return;
        }
    }
}

void ios_jit_set_text_section(void *pe_base, size_t text_offset, size_t text_size)
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        if (ios_jit_mappings[i].pe_base == pe_base)
        {
            unsigned r, count = __atomic_load_n( &ios_jit_mappings[i].code_range_count, __ATOMIC_RELAXED );
            if (text_offset <= ios_jit_mappings[i].size && text_size &&
                text_size <= ios_jit_mappings[i].size - text_offset)
            {
                for (r = 0; r < count && r < IOS_JIT_MAX_CODE_RANGES; r++)
                    if (ios_jit_mappings[i].code_ranges[r].offset == text_offset &&
                        ios_jit_mappings[i].code_ranges[r].size == text_size) break;
                if (r == count && count < IOS_JIT_MAX_CODE_RANGES)
                {
                    ios_jit_mappings[i].code_ranges[count].offset = text_offset;
                    ios_jit_mappings[i].code_ranges[count].size = text_size;
                    __atomic_store_n( &ios_jit_mappings[i].code_range_count, count + 1, __ATOMIC_RELEASE );
                }
            }
            /* Keep the LARGEST executable section. ARM64EC PEs have both
             * .text (large, ARM64 native) and .hexpthk (small, x86_64
             * fast-forward thunks). The x18 patcher needs to walk .text. */
            if (text_size > ios_jit_mappings[i].text_size)
            {
                ios_jit_mappings[i].text_offset = text_offset;
                ios_jit_mappings[i].text_size = text_size;
            }
            return;
        }
    }
}

/* Pointer classification needs every executable section. The largest-section
 * fields above remain the native x18 patcher's input. No PE-header walk on
 * each IAT slot; ranges are collected by the existing mapping section walk. */
static int ios_jit_code_bounds( const struct ios_jit_mapping *m, size_t off,
                                size_t *low, size_t *high )
{
    unsigned r, count = __atomic_load_n( &m->code_range_count, __ATOMIC_ACQUIRE );
    if (count > IOS_JIT_MAX_CODE_RANGES) return 0;
    for (r = 0; r <= count; r++)
    {
        size_t start = r < count ? m->code_ranges[r].offset : m->text_offset;
        size_t size = r < count ? m->code_ranges[r].size : m->text_size;
        if (start > m->size || !size || size > m->size - start ||
            off < start || off - start >= size) continue;
        *low = start;
        *high = start + size;
        return 1;
    }
    return 0;
}

/* Check if a JIT pool address is within a .text (executable code) section */
int ios_jit_addr_is_text(uintptr_t addr)
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t jit_base = (uintptr_t)ios_jit_mappings[i].jit_base;
        size_t t_off = ios_jit_mappings[i].text_offset;
        size_t t_sz  = ios_jit_mappings[i].text_size;
        if (t_sz && addr >= jit_base + t_off && addr < jit_base + t_off + t_sz)
            return 1;
    }
    return 0;
}

/* Set the TEB address in a specific JIT pool trampoline slot (with logging) */
void ios_jit_set_teb(uintptr_t teb)
{
    /* Legacy: writes to slot 0 for backward compatibility */
    ios_jit_set_teb_slot(0, teb);
    if (ios_jit_rw_base_global)
    {
        uint64_t readback = ios_jit_rx_base_global ?
            *(volatile uint64_t *)ios_jit_rx_base_global : 0;
        ERR("ios_jit_set_teb: wrote 0x%lx to RW %p, readback from RX %p = 0x%lx %s\n",
            (unsigned long)teb, ios_jit_rw_base_global,
            ios_jit_rx_base_global, (unsigned long)readback,
            readback == teb ? "OK" : "MISMATCH!");
    }
    else
    {
        ERR("ios_jit_set_teb: rw_base is NULL, cannot write TEB 0x%lx!\n",
            (unsigned long)teb);
    }
}

/* S1 pseudo-processes: identify the current thread's "process" by its
 * TEB->Peb. The TEB is read from the same TSD slot the x18 trampolines
 * use (async-signal-safe — the SEGV redirect runs on the faulting thread),
 * with a pthread-key fallback for early boot before the slot offset is
 * known. NULL = unknown → resolves to parent/default mapping entries. */
void *ios_jit_current_peb(void)
{
    extern pthread_key_t ios_teb_tls_key;
    extern int ios_teb_tls_slot_offset;
    char *cur_teb = NULL;

    if (ios_teb_tls_slot_offset)
    {
        uintptr_t tsd_base;
        __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tsd_base));
        tsd_base &= ~7ULL;
        cur_teb = *(char **)(tsd_base + ios_teb_tls_slot_offset);
    }
    if (!cur_teb && ios_teb_tls_key) cur_teb = pthread_getspecific(ios_teb_tls_key);
    if (!cur_teb) return NULL;
    return ((TEB *)cur_teb)->Peb;
}

/* Owner-aware main-image machine (X3 mixed-mode); registry in loader_ios.c. */
USHORT ios_cur_image_info_machine(void)
{
    extern const SECTION_IMAGE_INFORMATION *ios_cur_image_info(void);
    return ios_cur_image_info()->Machine;
}

/* Translate a PE address to a JIT pool address for a specific process.
 * An entry owned by `owner_peb` wins; otherwise the NULL-owner (parent)
 * entry applies. Child processes only own copies of ntdll — every other
 * module resolves to the shared parent copy via the fallback. */
void *ios_jit_translate_addr_for_owner(void *addr, void *owner_peb)
{
    int i, fallback = -1, any_live = -1;
    uintptr_t a = (uintptr_t)addr;

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t base = (uintptr_t)ios_jit_mappings[i].pe_base;
        if (a >= base && a < base + ios_jit_mappings[i].size)
        {
            if (ios_jit_mappings[i].owner_peb == owner_peb)
                return (void *)((uintptr_t)ios_jit_mappings[i].jit_base + (a - base));
            if (!ios_jit_mappings[i].owner_peb && fallback < 0) fallback = i;
            if (any_live < 0) any_live = i;
        }
    }
    if (fallback >= 0)
        return (void *)((uintptr_t)ios_jit_mappings[fallback].jit_base
                        + (a - (uintptr_t)ios_jit_mappings[fallback].pe_base));
    /* ml454 (#74): PE image ranges are globally unique in the single shared
     * address space — an entry CONTAINING the address IS the right copy even
     * when the caller's owner_peb doesn't match (observed: the renderer
     * thread's owner resolution missed for webhelper's xtajit64 copy and a
     * live in-range entry was refused → 65k-fault pass-through storm at the
     * GuestToHostMap dtor → the #74 lock re-entry chain).  The cross-copy
     * disease this owner check guards against needs a SAME-VA ambiguity,
     * which cannot exist here. */
    if (any_live >= 0)
    {
        static int xany_n;
        if (xany_n < 20)
        {
            xany_n++;
            dprintf(2, "[xlate-any] addr=%p owner=%p matched live entry pe=%p owner=%p (exact-owner miss) rev=ml454\n",
                    addr, owner_peb, ios_jit_mappings[any_live].pe_base,
                    ios_jit_mappings[any_live].owner_peb);
        }
        return (void *)((uintptr_t)ios_jit_mappings[any_live].jit_base
                        + (a - (uintptr_t)ios_jit_mappings[any_live].pe_base));
    }
    return addr;  /* Not in any mapping */
}

/* Which pool copy the NtProtectVirtualMemory IAT sync writes a changed region
 * of a PE image into.
 *
 * It used the FIRST mapping whose PE range holds the region. Images copied per
 * process (ntdll: the session copy, owner NULL, plus one private copy per
 * pseudo-process child) share one PE range, so a child's change to ntdll was
 * copied into the PARENT's copy and never into its own (GTA V Enhanced's
 * GTA5_Enhanced.exe child protecting ntdll). Same rule as
 * ios_jit_translate_addr_for_owner: the copy owned by the writing process
 * wins, else the first NULL-owner copy, else the first match. A process
 * without its own copy (every main process) gets the NULL-owner copy -- the
 * only one there is -- as before. Returns -1 when no copy holds the region. */
static int ios_iat_sync_pick_mapping( uintptr_t rgn_start, uintptr_t rgn_end, void *peb )
{
    int i, first = -1, fallback = -1;

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t pe_start = (uintptr_t)ios_jit_mappings[i].pe_base;
        uintptr_t pe_end = pe_start + ios_jit_mappings[i].size;

        if (!(rgn_start >= pe_start && rgn_end <= pe_end)) continue;
        if (first < 0) first = i;
        if (peb && ios_jit_mappings[i].owner_peb == peb) return i;
        if (!ios_jit_mappings[i].owner_peb && fallback < 0) fallback = i;
    }
    return fallback >= 0 ? fallback : first;
}

/* image-patch-test:begin (tests/host/check-image-patch-trace.py) */
/* Read-only diagnostics for short protect/write/restore sequences on DLL code.
 * Capture the requested byte range, not NtProtect's rounded page. The existing
 * owner-aware sync remains the authority; this does not repair a hook, change
 * permissions, copy code, or redirect native calls to an x64 stub. */
static void ios_trace_image_patch( void *requested, size_t length, unsigned int prot,
                                   unsigned int status )
{
    static unsigned int emitted;
    const char *enabled;
    uintptr_t start = (uintptr_t)requested, pe, pool;
    void *owner, *caller;
    unsigned int serial, i, n;
    unsigned char a[16], b[16];
    char parent[33], copy[33];
    mach_vm_size_t actual;
    int idx, got_parent, got_copy, saved_errno = errno;
    unsigned int read_bits = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                             PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    unsigned int exec_bits = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                             PAGE_EXECUTE_WRITECOPY;

    enabled = getenv( "MADEIRA_IMAGE_PATCH_TRACE" );
    if (!enabled || strcmp( enabled, "1" ) || status || !length || length > 16 ||
        start > UINTPTR_MAX - length || !(prot & read_bits) || !(prot & exec_bits) || (prot & PAGE_GUARD) ||
        __atomic_load_n( &emitted, __ATOMIC_RELAXED ) >= 64) goto out;
    if (!NtCurrentTeb()) goto out;
    caller = ios_jit_current_peb();
    idx = ios_iat_sync_pick_mapping( start, start + length, caller );
    if (idx < 0) goto out;
    pe = (uintptr_t)ios_jit_mappings[idx].pe_base;
    pool = (uintptr_t)ios_jit_mappings[idx].jit_base;
    owner = ios_jit_mappings[idx].owner_peb;
    if (start < pe || start - pe >= ios_jit_mappings[idx].size ||
        ios_jit_mappings[idx].size - (start - pe) < length ||
        !pool || pool > UINTPTR_MAX - (start - pe)) goto out;
    n = length;
    pool += start - pe;
    if (pool > UINTPTR_MAX - n) goto out;
    serial = __atomic_fetch_add( &emitted, 1, __ATOMIC_RELAXED );
    if (serial >= 64) goto out;
    actual = 0;
    got_parent = mach_vm_read_overwrite( mach_task_self(), start, n,
                                         (mach_vm_address_t)(uintptr_t)a, &actual ) == KERN_SUCCESS && actual == n;
    actual = 0;
    got_copy = mach_vm_read_overwrite( mach_task_self(), pool, n,
                                       (mach_vm_address_t)(uintptr_t)b, &actual ) == KERN_SUCCESS && actual == n;
    strcpy( parent, "unreadable" );
    strcpy( copy, "unreadable" );
    for (i = 0; got_parent && i < n; i++) snprintf( parent + 2 * i, 3, "%02x", a[i] );
    for (i = 0; got_copy && i < n; i++) snprintf( copy + 2 * i, 3, "%02x", b[i] );
    dprintf( 2, "[image-patch] #%u tid=%04x image=%p rva=%#lx len=%lu prot=%#x "
                 "owner=%p caller=%p pe=%s pool=%s %s\n",
             serial + 1, (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
             (void *)pe, (unsigned long)(start - pe), (unsigned long)length, prot, owner, caller,
             parent, copy, got_parent && got_copy ? (memcmp( a, b, n ) ? "DIFFERENT" : "MATCH") : "UNREADABLE" );
out:
    errno = saved_errno;
}
/* image-patch-test:end */

/* Translate a PE address to JIT pool address. Returns original if not mapped.
 * Owner-aware: resolves against the calling thread's process. */
void *ios_jit_translate_addr(void *addr)
{
    return ios_jit_translate_addr_for_owner(addr, ios_jit_current_peb());
}

/* IAT-range collector for the stale-pointer heal. The 2026-07-04 boot
 * breakage came from rewriting EVERY 8-byte slot holding the stale value
 * — that clobbered arm64x metadata slots whose consumers need PE VAs for
 * identity/range comparisons. IAT / delay-IAT slots hold nothing but call
 * targets, so restricting the rewrite to them is semantically safe (it's
 * the same transform the NtProtect-time IAT-sync applies). Headers are
 * read from the pool RW copy; RVAs are relocation-invariant. */
struct ios_iat_range { unsigned int rva, size; };

static int ios_collect_iat_ranges( const unsigned char *img, size_t img_size,
                                   struct ios_iat_range *out, int max_out )
{
    unsigned int e_lfanew, ndirs;
    const unsigned char *opt;
    const unsigned int *dir;
    int n = 0;

    if (img_size < 0x400 || img[0] != 'M' || img[1] != 'Z') return 0;
    e_lfanew = *(const unsigned int *)(img + 0x3c);
    if (e_lfanew < 0x40 || e_lfanew > img_size - 0x200) return 0;
    if (memcmp(img + e_lfanew, "PE\0\0", 4)) return 0;
    opt = img + e_lfanew + 24;
    if (*(const unsigned short *)opt != 0x20b) return 0;      /* PE32+ only */
    ndirs = *(const unsigned int *)(opt + 108);
    dir = (const unsigned int *)(opt + 112);                  /* {rva,size} pairs */

    /* Data directory 12: the IAT proper. */
    if (ndirs > 12 && dir[12*2] && dir[12*2+1] &&
        (size_t)dir[12*2] + dir[12*2+1] <= img_size && n < max_out)
    {
        out[n].rva = dir[12*2]; out[n].size = dir[12*2+1]; n++;
    }
    /* Directory 1: walk each import descriptor's FirstThunk array —
     * covers images whose dir-12 entry is absent or incomplete. */
    if (ndirs > 1 && dir[1*2] && dir[1*2] < img_size)
    {
        const unsigned char *desc = img + dir[1*2];
        while (desc + 20 <= img + img_size && n < max_out)
        {
            unsigned int oft = *(const unsigned int *)(desc + 0);
            unsigned int ft  = *(const unsigned int *)(desc + 16);
            if (!ft && !oft) break;
            if (ft && ft < img_size)
            {
                const uint64_t *t = (const uint64_t *)(img + ft);
                unsigned int cnt = 0;
                while ((const unsigned char *)(t + cnt + 1) <= img + img_size && t[cnt]) cnt++;
                if (cnt) { out[n].rva = ft; out[n].size = cnt * 8; n++; }
            }
            desc += 20;
        }
    }
    /* Directory 13: delay-load descriptors (ImportAddressTableRVA at +12). */
    if (ndirs > 13 && dir[13*2] && dir[13*2] < img_size)
    {
        const unsigned char *dd = img + dir[13*2];
        while (dd + 32 <= img + img_size && n < max_out)
        {
            unsigned int iat_rva = *(const unsigned int *)(dd + 12);
            unsigned int int_rva = *(const unsigned int *)(dd + 16);
            if (!iat_rva && !int_rva) break;
            if (iat_rva && iat_rva < img_size)
            {
                const uint64_t *t = (const uint64_t *)(img + iat_rva);
                unsigned int cnt = 0;
                while ((const unsigned char *)(t + cnt + 1) <= img + img_size && t[cnt]) cnt++;
                if (cnt) { out[n].rva = iat_rva; out[n].size = cnt * 8; n++; }
            }
            dd += 32;
        }
    }
    return n;
}

/* Which process's translation a healed slot gets. owner_peb is set only for
 * the per-process ntdll copies; every other copy -- a child's own emulator,
 * its exe, its DLLs -- has owner NULL, so a stale ntdll PE VA found in it was
 * rewritten to the SESSION's ntdll copy. GTA V Enhanced: the child's
 * KiUserExceptionDispatcher crossed the fault threshold, the heal rewrote the
 * slot in the child emulator's copy to the parent's ntdll, and the child's
 * next syscall ran the parent's ntdll (NoExec at the parent's
 * invoke_arm64ec_syscall). A NULL-owner copy is used by the process that
 * mapped it, so translate for that process (map_peb). A copy of an unknown
 * process is left alone when the target image has per-process copies: the
 * owner-aware exec-fault redirect keeps serving it. A main process owns no
 * copy, so its translation is the NULL-owner one as before. */
static int ios_va_has_owned_copy( uintptr_t va )
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t b = (uintptr_t)ios_jit_mappings[i].pe_base;
        if (b && ios_jit_mappings[i].owner_peb && va >= b && va < b + ios_jit_mappings[i].size) return 1;
    }
    return 0;
}

/* The process a slot in mapping i belongs to, for the heal's translation.
 * Returns 0 when the slot must not be healed. */
static int ios_heal_range_owner( int i, uintptr_t stale_va, void **owner )
{
    *owner = ios_jit_mappings[i].owner_peb;
    if (*owner) return 1;
    *owner = ios_jit_mappings[i].map_peb;
    if (*owner) return 1;
    return !ios_va_has_owned_copy( stale_va );
}

/* Self-heal one stale PE-VA pointer: rewrite IAT/delay-IAT slots in the
 * module-copy pool ranges that hold `stale_va` to its pool-VA equivalent.
 * Called from the heal scanner thread (signal_arm64_ios.c) for addresses
 * that exec-faulted 256+ times — i.e. values being BRANCHED to through
 * import slots the NtProtect-time IAT-sync missed (the two-cube DXMT
 * storm: child winemetal's pool IAT held the child EC ntdll's map VA for
 * __wine_unix_call → one Mach exception per Metal call). Scans only
 * registered module copies (never the FEX CodeBuffer tail). Writes go to
 * the RW alias; concurrent readers that still load the old value just
 * take one more fault-redirect, which is benign. */
int ios_jit_patch_stale_pointer(unsigned long long stale_va)
{
    int i, patched = 0, skipped = 0;
    void *target = ios_jit_translate_addr_for_owner((void *)(uintptr_t)stale_va, NULL);
    if (!ios_jit_rw_base_global || !ios_jit_rx_base_global) return 0;

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        /* Heal each pool range with ITS PROCESS's translation: a stale
         * ntdll PE-VA inside a child's copy (owned, or mapped by the child)
         * must point at the child's copy, not the parent's. */
        void *range_owner, *range_target;
        uintptr_t pool_off = (uintptr_t)ios_jit_mappings[i].jit_base
                           - (uintptr_t)ios_jit_rx_base_global;
        unsigned char *rw_img = (unsigned char *)ios_jit_rw_base_global + pool_off;
        struct ios_iat_range ranges[64];
        int nr, r;
        if (!ios_jit_mappings[i].pe_base || !ios_jit_mappings[i].size) continue;
        if (!ios_heal_range_owner( i, (uintptr_t)stale_va, &range_owner )) { skipped++; continue; }
        range_target = ios_jit_translate_addr_for_owner( (void *)(uintptr_t)stale_va, range_owner );
        if (range_target == (void *)(uintptr_t)stale_va) continue;
        nr = ios_collect_iat_ranges(rw_img, ios_jit_mappings[i].size, ranges, 64);
        for (r = 0; r < nr; r++)
        {
            uint64_t *p = (uint64_t *)(rw_img + ranges[r].rva);
            uint64_t *end = (uint64_t *)(rw_img + ranges[r].rva + (ranges[r].size & ~7u));
            for (; p < end; p++)
            {
                if (*p == stale_va)
                {
                    *p = (uint64_t)(uintptr_t)range_target;
                    patched++;
                }
            }
        }
    }
    /* Escalation (task #25 follow-through on the parked #23 "rewrote 0"
     * case): the DXMT unix-call storm pointer lives in a winecrt0-style
     * .data GLOBAL, not an IAT — the IAT-restricted pass finds nothing and
     * the same VA keeps costing one Mach exception per Metal call (118K+
     * observed; handler saturation = the desktop "freezes"). When the IAT
     * pass strikes out, scan each copy's data (whole image minus its known
     * .text) for the exact 8-byte value. Exact-match + the 256-fault
     * threshold that gates this function keep it far from the 2026-07-04
     * blind-rewrite failure mode. */
    /* Whole-.data exact-value scan+rewrite. DEFAULT-ON (2026-07-08:
     * confirmed NOT the cause of the Thumper menu→game freeze — that is
     * the pre-existing ~53.7s JIT-compile/debugger block, task #22, which
     * reproduced with this gated OFF). Set MADEIRA_NO_HEAL_ESCALATE=1 to
     * disable if a false-positive rewrite is ever suspected (it rewrites
     * ANY 8-byte word equal to the stale VA, a small coincidental-collision
     * risk on data-heavy x86 guests). */
    if (!patched && !getenv("MADEIRA_NO_HEAL_ESCALATE"))
    {
        for (i = 0; i < ios_jit_mapping_count; i++)
        {
            void *range_owner, *range_target;
            uintptr_t pool_off = (uintptr_t)ios_jit_mappings[i].jit_base
                               - (uintptr_t)ios_jit_rx_base_global;
            unsigned char *rw_img = (unsigned char *)ios_jit_rw_base_global + pool_off;
            size_t tx_start = ios_jit_mappings[i].text_offset;
            size_t tx_end   = tx_start + ios_jit_mappings[i].text_size;
            uint64_t *p   = (uint64_t *)rw_img;
            uint64_t *end = (uint64_t *)(rw_img + (ios_jit_mappings[i].size & ~(size_t)7));
            if (!ios_jit_mappings[i].pe_base || !ios_jit_mappings[i].size) continue;
            if (!ios_heal_range_owner( i, (uintptr_t)stale_va, &range_owner )) continue;
            range_target = ios_jit_translate_addr_for_owner( (void *)(uintptr_t)stale_va, range_owner );
            if (range_target == (void *)(uintptr_t)stale_va) continue;
            for (; p < end; p++)
            {
                size_t off = (size_t)((unsigned char *)p - rw_img);
                if (ios_jit_mappings[i].text_size && off >= tx_start && off < tx_end) continue;
                if (*p == stale_va)
                {
                    *p = (uint64_t)(uintptr_t)range_target;
                    patched++;
                }
            }
        }
        if (patched)
            fprintf(stderr, "[stale-heal] 0x%llx ESCALATED: rewrote %d data slot(s) outside IATs\n",
                    stale_va, patched);
    }
    /* fprintf, not ERR — the perf WINEDEBUG default mutes err+virtual and
     * this MUST stay visible (silent healing hid the 2026-07-04 boot
     * breakage). */
    fprintf(stderr, "[stale-heal] 0x%llx -> %p, rewrote %d slot(s)\n",
            stale_va, target, patched);
    if (skipped)
        fprintf(stderr, "[stale-heal] 0x%llx: %d cop(ies) of unknown process left to the owner-aware "
                "fault redirect (the target image has per-process copies)\n", stale_va, skipped);
    return patched;
}

/* madeira-bcd: aux-IAT heal (begin). An ARM64EC DLL calls an import through
 * a linker stub, `adrp x16, slot; ldr x16, [x16, #imm]; br x16`, whose slot is
 * in the image's AuxiliaryIAT. Windows' loader stores the native target there
 * when the import is EC code; Wine's never does, so the slot keeps its default,
 * the stub's own continuation: `adrp x11, iat; ldr x11, [x11, #imm]; adrp x10,
 * exit_thunk; add x10, ...; b helper`, which calls __os_arm64x_check_icall on
 * the main IAT value. Where that value is an x64 fast-forward thunk (the slot
 * kernel32 re-exports to x64 code keeps it, ml943), check_icall decodes it to
 * the export's PE address, which is not executable here: every call is one
 * Mach exec fault and a redirect to the image copy. GTA V Enhanced
 * (build 437) took ~17,000 a second, 90% of them kernel32!timeGetTime calling
 * ntdll!RtlQueryPerformanceCounter and RtlQueryPerformanceFrequency in the
 * Launcher, the game and Social Club, each stalling its thread for a round trip
 * through the exception thread (20-60% of a core).
 *
 * On such a redirect the fault handler hands us the faulting pc, lr and the
 * thread's process. When lr - 4 is a BL to that stub shape, the stub's slot
 * still holds the continuation, the continuation's main IAT value is the
 * target or a thunk that decodes to exactly it, and the caller's copy is used
 * by this process alone, the slot gets the copy address the redirect itself
 * uses for this process. The stub then branches there directly: the same
 * code, arguments and return address, minus the check_icall pass and the
 * fault. A later re-sync of the page that restores the default is healed again
 * by the next fault. MADEIRA_AUX_IAT_HEAL=0 leaves the slots alone. */
static int ios_aux_heal_enabled( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *e = getenv( "MADEIRA_AUX_IAT_HEAL" );  /* 0: EC import stubs keep the exec-fault redirect */
        cached = !(e && e[0] == '0' && !e[1]);
    }
    return cached;
}

static uintptr_t ios_aux_adrp_page( uintptr_t pc, uint32_t insn )
{
    int64_t imm = (int64_t)((((insn >> 5) & 0x7FFFFu) << 2) | ((insn >> 29) & 3u));
    imm = (imm << 43) >> 43;   /* sign-extend 21 bits */
    return (pc & ~(uintptr_t)0xFFF) + (uintptr_t)(imm << 12);
}

/* index of the one live mapping whose JIT copy holds `rx` (-1 when none, or
 * when a stale entry left by an unload still claims the range too) */
static int ios_aux_find_copy( uintptr_t rx )
{
    int i, found = -1;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t b = (uintptr_t)ios_jit_mappings[i].jit_base;
        size_t sz = ios_jit_mappings[i].size;
        if (!b || !sz || !ios_jit_mappings[i].pe_base || rx < b || rx >= b + sz) continue;
        if (found >= 0) return -1;
        found = i;
    }
    return found;
}

/* index of a live mapping whose PE image holds `pe`, or -1 */
static int ios_aux_find_pe( uintptr_t pe )
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t b = (uintptr_t)ios_jit_mappings[i].pe_base;
        size_t sz = ios_jit_mappings[i].size;
        if (b && sz && pe >= b && pe < b + sz) return i;
    }
    return -1;
}

/* `len` bytes at `addr` through the fault-safe reader (an image may have gone
 * away under a table entry the unload never cleared); 0 on success */
static int ios_aux_safe_read( uintptr_t addr, void *out, size_t len )
{
    unsigned char buf[24];
    uintptr_t a = addr & ~(uintptr_t)7;
    size_t pre = addr - a, w;
    if (len + pre > sizeof(buf)) return -1;
    for (w = 0; w < pre + len; w += 8)
        if (ios_safe_read64( (uint64_t)(a + w), (uint64_t *)(buf + w) )) return -1;
    memcpy( out, buf + pre, len );
    return 0;
}

int ios_jit_heal_aux_iat( uintptr_t fault_pc, uintptr_t lr, void *thread_peb, uintptr_t jit_pc )
{
    static const unsigned char ffs[10] = { 0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x20, 0x55, 0x5d, 0xe9 };
    static volatile int healed;
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global, rw = (uintptr_t)ios_jit_rw_base_global;
    size_t pool = ios_jit_pool_size_global;
    uintptr_t call, stub, cont, slot, main_slot, jb, end, pe_cont, text_lo, text_hi, pe;
    uint32_t bl, s0, s1, s2, c0, c1, lfanew, iat_rva, iat_size, rva;
    uint16_t magic;
    uint64_t cur, value;
    unsigned char thunk[14];
    int i, k, n;

    if (!ios_aux_heal_enabled() || !rx || !rw || !pool || !thread_peb) return 0;
    if ((lr & 3) || lr < rx + 4 || lr >= rx + pool) return 0;
    if (jit_pc < rx || jit_pc >= rx + pool) return 0;
    call = lr - 4;
    if ((i = ios_aux_find_copy( call )) < 0) return 0;
    /* the caller's copy must be this process's alone */
    if (ios_jit_mappings[i].owner_peb)
    {
        if (ios_jit_mappings[i].owner_peb != thread_peb) return 0;
    }
    else
    {
        if (ios_jit_mappings[i].map_peb != thread_peb) return 0;
        for (k = 0; k < ios_jit_mapping_count; k++)
            if (k != i && ios_jit_mappings[k].size && ios_jit_mappings[k].pe_base == ios_jit_mappings[i].pe_base) return 0;
    }
    jb = (uintptr_t)ios_jit_mappings[i].jit_base;
    end = jb + ios_jit_mappings[i].size;
    pe = (uintptr_t)ios_jit_mappings[i].pe_base;
    text_lo = jb + ios_jit_mappings[i].text_offset;
    text_hi = text_lo + ios_jit_mappings[i].text_size;
    if (end > rx + pool) return 0;

    /* the call, its stub and the stub's continuation: pool memory, always mapped */
    bl = *(volatile uint32_t *)call;
    if ((bl & 0xFC000000u) != 0x94000000u) return 0;                     /* BL imm26 */
    stub = call + (uintptr_t)((intptr_t)((int32_t)(bl << 6) >> 6) * 4);
    if ((stub & 3) || stub < jb || stub + 20 > end) return 0;
    s0 = ((volatile uint32_t *)stub)[0];
    s1 = ((volatile uint32_t *)stub)[1];
    s2 = ((volatile uint32_t *)stub)[2];
    if ((s0 & 0x9F00001Fu) != 0x90000010u) return 0;                     /* ADRP x16 */
    if ((s1 & 0xFFC003FFu) != 0xF9400210u) return 0;                     /* LDR x16, [x16, #imm] */
    if (s2 != 0xD61F0200u) return 0;                                      /* BR x16 */
    cont = stub + 12;
    c0 = ((volatile uint32_t *)cont)[0];
    c1 = ((volatile uint32_t *)cont)[1];
    if ((c0 & 0x9F00001Fu) != 0x9000000Bu) return 0;                     /* ADRP x11 */
    if ((c1 & 0xFFC003FFu) != 0xF940016Bu) return 0;                     /* LDR x11, [x11, #imm] */
    slot = ios_aux_adrp_page( stub, s0 ) + ((s1 >> 10) & 0xFFFu) * 8;
    main_slot = ios_aux_adrp_page( cont, c0 ) + ((c1 >> 10) & 0xFFFu) * 8;
    if ((slot & 7) || slot < jb || slot + 8 > end) return 0;
    if ((main_slot & 7) || main_slot < jb || main_slot + 8 > end) return 0;
    if (ios_jit_mappings[i].text_size && slot + 8 > text_lo && slot < text_hi) return 0;

    /* a static import: the main slot is in the image's IAT directory (a delay-load
     * slot, whose DLL may be unloaded again, is not); headers read fault-safely */
    if (ios_aux_safe_read( pe + 0x3c, &lfanew, 4 ) || lfanew < 0x40 || lfanew > 0x1000) return 0;
    if (ios_aux_safe_read( pe + lfanew, &rva, 4 ) || rva != 0x00004550u) return 0;          /* "PE\0\0" */
    if (ios_aux_safe_read( pe + lfanew + 24, &magic, 2 ) || magic != 0x20b) return 0;       /* PE32+ */
    if (ios_aux_safe_read( pe + lfanew + 24 + 112 + 8 * 12, &iat_rva, 4 )) return 0;        /* DataDirectory[IAT] */
    if (ios_aux_safe_read( pe + lfanew + 24 + 112 + 8 * 12 + 4, &iat_size, 4 )) return 0;
    rva = (uint32_t)(main_slot - jb);
    if (rva < iat_rva || (uint64_t)rva + 8 > (uint64_t)iat_rva + iat_size) return 0;

    /* still the default: the continuation, as a copy or a PE address */
    cur = *(volatile uint64_t *)slot;
    pe_cont = pe + (cont - jb);
    if (cur != cont && cur != pe_cont) return 0;

    /* the continuation's main IAT value is the target, or a thunk to exactly it */
    value = *(volatile uint64_t *)main_slot;
    if (value != fault_pc)
    {
        int32_t rel;
        if (ios_aux_find_pe( (uintptr_t)value ) < 0) return 0;
        if (ios_aux_safe_read( (uintptr_t)value, thunk, sizeof(thunk) )) return 0;
        if (memcmp( thunk, ffs, sizeof(ffs) )) return 0;
        memcpy( &rel, thunk + 10, 4 );
        if ((uintptr_t)value + 14 + (intptr_t)rel != fault_pc) return 0;
    }
    /* exactly where the redirect sends this process */
    if ((uintptr_t)ios_jit_translate_addr_for_owner( (void *)fault_pc, thread_peb ) != jit_pc) return 0;
    /* a caller copy without an owner serves every process that maps the image, so it
     * may only be sent to a target copy that is shared too, never to one process's own
     * (each child has its own ntdll copy) */
    if (!ios_jit_mappings[i].owner_peb)
    {
        int t = ios_aux_find_copy( jit_pc );
        if (t < 0 || ios_jit_mappings[t].owner_peb) return 0;
    }

    __atomic_store_n( (uint64_t *)(rw + (slot - rx)), (uint64_t)jit_pc, __ATOMIC_RELEASE );
    n = __sync_add_and_fetch( &healed, 1 );
    /* dprintf: this runs on the exception thread, which must not wait on stdio */
    if (n <= 32 || !(n % 256))
        dprintf( STDERR_FILENO, "[aux-iat-heal] #%d image %p (copy %p) +0x%lx calls %p: AuxiliaryIAT slot +0x%lx "
                 "now holds the copy %p, was the check_icall continuation; peb=%p (MADEIRA_AUX_IAT_HEAL=0 disables)\n",
                 n, (void *)pe, (void *)jb, (unsigned long)(call - jb), (void *)fault_pc,
                 (unsigned long)(slot - jb), (void *)jit_pc, thread_peb );
    return 1;
}
/* madeira-bcd: aux-IAT heal (end) */

/* task #24 [term-stack]: map a guest PE VA to its module base + size so
 * the terminate-time stack dump can self-attribute return addresses. */
unsigned long long ios_jit_module_base_for_va(unsigned long long va, unsigned long long *size_out)
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t b = (uintptr_t)ios_jit_mappings[i].pe_base;
        if (va >= b && va < b + ios_jit_mappings[i].size)
        {
            if (size_out) *size_out = ios_jit_mappings[i].size;
            return b;
        }
    }
    return 0;
}

/* task #34 [x86-ptr]: is `va` a GUEST INSTRUCTION address — a pointer into the
 * executable section of an x86-64 module?
 *
 * The iat-sync rewrites every image-looking pointer to its pool copy. Three
 * cases hide behind that:
 *   - pointer to DATA (any module)      -> translating is CORRECT, the pool
 *                                          copy is the live one
 *   - pointer to ARM64EC code (0xAA64)  -> translating is CORRECT, EC calls
 *                                          must land in the pool copy
 *   - pointer to x86-64 code (0x8664)   -> translating is POISON. FEX must see
 *                                          the guest PE address; a pool address
 *                                          in guest control flow is the
 *                                          [rip-leak] death (ml95, ml100).
 * A first attempt used peb->EcCodeBitMap as the discriminator and reported
 * 100.0% "non-EC" — useless, because that bitmap reads 0 for plain data too,
 * so it lumped the correct case in with the poison one. Section bounds plus the
 * PE machine word separate them properly. */
/* ml349: the header read must be FAULT-SAFE — a mapping whose PE header page is
 * unmapped (freed private copy, decommitted image) wedged the [x86-ptr] scan
 * thread forever (ml348: `ldr w1,[x0,#0x3c]` at 0x73e4a7003c, 8 identical
 * faults, run killed). Read once per mapping slot via mach_vm_read_overwrite
 * and memoize; ios_jit_add_mapping resets machine_valid on slot reuse. An
 * unreadable header yields 0, which every caller treats as "not x86". */
static unsigned short ios_jit_mapping_machine( int i )
{
    uintptr_t b  = (uintptr_t)ios_jit_mappings[i].pe_base;
    size_t    sz = ios_jit_mappings[i].size;

    if (!ios_jit_mappings[i].machine_valid)
    {
        unsigned int lfanew = 0;
        unsigned short mach = 0;
        mach_vm_size_t got = 0;
        if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(b + 0x3c), 4,
                                   (mach_vm_address_t)&lfanew, &got) != KERN_SUCCESS || got != 4
            || (size_t)lfanew + 6 > sz
            || mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(b + lfanew + 4), 2,
                                      (mach_vm_address_t)&mach, &got) != KERN_SUCCESS || got != 2)
        {
            static int hdr_unreadable_n;
            if (hdr_unreadable_n < 8)
                dprintf(2, "[x86-ptr] rev=ml349 mapping pe_base=%p+0x%lx header UNREADABLE"
                        " — classifying non-x86 (#%d)\n",
                        (void *)b, (unsigned long)sz, ++hdr_unreadable_n);
            mach = 0;
        }
        ios_jit_mappings[i].machine_cached = mach;
        ios_jit_mappings[i].machine_valid = 1;
    }
    return ios_jit_mappings[i].machine_cached;
}

/* ml1245: does mapping i run from its pool copy, i.e. is it ARM64EC or ARM64?
 *
 * The machine word cannot say: an ARM64EC image carries IMAGE_FILE_MACHINE_AMD64
 * exactly like a plain x64 one (every DLL in arm64ec-windows reads 0x8664 on disk,
 * and so did metro.exe). What marks it is a non-zero CHPEMetadataPointer in the
 * load config, the same test update_arm64ec_ranges applies. Fault-safe and
 * memoized per slot like ios_jit_mapping_machine; unreadable headers yield 0. */
static int ios_safe_read( uintptr_t addr, void *out, size_t len )
{
    mach_vm_size_t got = 0;
    return mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)addr, len,
                                   (mach_vm_address_t)out, &got ) == KERN_SUCCESS && got == len;
}

static int ios_jit_mapping_is_hybrid( int i )
{
    if (!ios_jit_mappings[i].hybrid_valid)
    {
        uintptr_t b  = (uintptr_t)ios_jit_mappings[i].pe_base;
        size_t    sz = ios_jit_mappings[i].size;
        unsigned short mach = ios_jit_mapping_machine( i );
        unsigned int lfanew = 0, cfg_size = 0;
        IMAGE_NT_HEADERS64 nt;
        IMAGE_DATA_DIRECTORY dir;
        ULONGLONG chpe = 0;
        int hybrid = 0;

        if (mach == 0xaa64 || mach == 0xa641) hybrid = 1;   /* ARM64 / ARM64X headers */
        else if (mach == 0x8664
                 && ios_safe_read( b + 0x3c, &lfanew, 4 ) && (size_t)lfanew + sizeof(nt) <= sz
                 && ios_safe_read( b + lfanew, &nt, sizeof(nt) )
                 && nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
                 && nt.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        {
            dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            if (dir.VirtualAddress && (size_t)dir.VirtualAddress + dir.Size <= sz
                && ios_safe_read( b + dir.VirtualAddress, &cfg_size, 4 )
                && min( dir.Size, cfg_size ) > offsetof( IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer )
                && ios_safe_read( b + dir.VirtualAddress
                                  + offsetof( IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer ),
                                  &chpe, sizeof(chpe) ))
                hybrid = chpe != 0;
        }
        ios_jit_mappings[i].hybrid_cached = hybrid;
        ios_jit_mappings[i].hybrid_valid = 1;
    }
    return ios_jit_mappings[i].hybrid_cached;
}

static int ios_va_is_x86_code( uint64_t va )
{
    int i;

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t b  = (uintptr_t)ios_jit_mappings[i].pe_base;
        size_t    sz = ios_jit_mappings[i].size;
        size_t    t_off, t_sz;
        uint64_t  off;

        if (!b || sz < 0x40 || va < b || va >= b + sz) continue;

        off   = va - b;
        if (!ios_jit_code_bounds( &ios_jit_mappings[i], off, &t_off, &t_sz )) return 0;

        /* Unreadable header → 0 → non-x86: translation stays on, which is the
         * correct behavior for EC/data and harmless for a dead copy. */
        return ios_jit_mapping_machine( i ) == 0x8664;  /* IMAGE_FILE_MACHINE_AMD64 */
    }
    return 0;
}

/* Bound a fatal-instruction snapshot to the registered x64 text section.
 * This only supplies addresses; the caller must read through Mach safely. */
int ios_jit_guest_code_window( uint64_t rip, uint64_t *image, uint64_t *start, size_t *length )
{
    int i;

    if (!ios_va_is_x86_code( rip )) return 0;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uint64_t b = (uint64_t)(uintptr_t)ios_jit_mappings[i].pe_base;
        size_t sz = ios_jit_mappings[i].size;
        size_t off, end;
        uint64_t low, high, before, after;

        if (!b || ios_jit_mappings[i].unmapped || b > UINT64_MAX - sz ||
            rip < b || rip - b >= sz ||
            !ios_jit_code_bounds( &ios_jit_mappings[i], rip - b, &off, &end )) continue;
        low = b + off;
        high = b + end;
        if (rip < low || rip >= high) continue;
        before = rip - low < 16 ? rip - low : 16;
        after = high - rip < 32 ? high - rip : 32;
        *image = b;
        *start = rip - before;
        *length = before + after;
        return 1;
    }
    return 0;
}

/* [xlate-exec] forensics: which mapping's pool range contains `addr`, and
 * who owns it. Names the COPY a thread is executing (session vs child),
 * which reverse_translate alone can't — copies share PE VAs. */
/* ml1123: for the CPU-split profiler -- is this executing address inside a pool
 * image copy? If so return the PE address it corresponds to (for offline
 * symbolisation against the [jit-pool] image table). Lock-free read, like
 * ios_jit_pool_copy_owner below; a torn read only misclassifies one sample. */
int ios_jit_pool_image_pc(uintptr_t pc, uintptr_t *pe_addr_out)
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t jb = (uintptr_t)ios_jit_mappings[i].jit_base;
        if (ios_jit_mappings[i].pe_base && pc >= jb && pc < jb + ios_jit_mappings[i].size)
        {
            if (pe_addr_out) *pe_addr_out = (uintptr_t)ios_jit_mappings[i].pe_base + (pc - jb);
            return 1;
        }
    }
    return 0;
}
void *ios_jit_pool_copy_owner(const void *addr, void **pe_base_out)
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t a = (uintptr_t)addr;
        uintptr_t jit_base = (uintptr_t)ios_jit_mappings[i].jit_base;
        if (a >= jit_base && a < jit_base + ios_jit_mappings[i].size)
        {
            if (pe_base_out) *pe_base_out = ios_jit_mappings[i].pe_base;
            return ios_jit_mappings[i].owner_peb;
        }
    }
    if (pe_base_out) *pe_base_out = NULL;
    return (void *)(uintptr_t)-1;  /* not in any pool mapping */
}

/* Reverse-translate a JIT pool address back to the original PE address.
 * Used when PE code passes ADRP-computed addresses to syscalls. */
void *ios_jit_reverse_translate_addr(const void *addr)
{
    int i;
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t a = (uintptr_t)addr;
        uintptr_t jit_base = (uintptr_t)ios_jit_mappings[i].jit_base;
        if (a >= jit_base && a < jit_base + ios_jit_mappings[i].size)
        {
            return (void *)((uintptr_t)ios_jit_mappings[i].pe_base + (a - jit_base));
        }
    }
    return (void *)addr;  /* Not in any JIT mapping */
}

/* Sync data written to original PE .data section to JIT pool copy.
 * Called after unix-side code (e.g. load_ntdll_functions) writes to PE data
 * that the JIT pool code needs to read. */
/* ml1017: is `off` (an offset into the PE image based at `img`) inside ANY
 * section marked EXECUTE?
 *
 * Not just .text: the mapping's text_offset/text_size records only the LARGEST
 * executable section, and a packed/DRM binary puts decrypted code in additional
 * executable sections. RDR2's offending page is at RVA 0x60eb000, past the
 * .reloc at 0x5e88000, so a .text-only test would never have covered it.
 * Walk the real section table instead. */
static int ios_img_off_is_exec( const void *img, size_t img_size, size_t off )
{
    const IMAGE_DOS_HEADER *dos = img;
    const IMAGE_NT_HEADERS *nt;
    const IMAGE_SECTION_HEADER *sec;
    unsigned i;

    if (!img || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if ((size_t)dos->e_lfanew + sizeof *nt > img_size) return 0;
    nt = (const IMAGE_NT_HEADERS *)((const char *)img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        size_t lo = sec[i].VirtualAddress;
        size_t vs = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (off < lo || off >= lo + vs) continue;
        return (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 1 : 0;
    }
    return 0;   /* outside every section: headers/padding, not code */
}

/* ml1244: bind an x64 importer's DATA imports to the copy that is actually live.
 *
 * An ARM64EC/ARM64 module executes from its pool copy and reaches its own
 * globals ADRP-relative, so every write it makes lands in the POOL copy's .data;
 * the PE-side .data keeps what the image file held. The iat-sync points an EC
 * importer's (pool-side) IAT at the pool copy, but a pure x64 importer is run by
 * FEX at its PE addresses, so it reads the PE-side IAT the loader filled with PE
 * addresses. For a function import that is right (the EC call path translates
 * it); for an exported VARIABLE it hands the guest a copy nothing ever writes.
 *
 * Metro 2033 Redux, 2026-09-27: metro.exe's VS2012 CRT startup reads `_acmdln`
 * straight from msvcr110's data export. msvcr110's DllMain had set it in the pool
 * copy, the PE copy was still NULL, and the command-line scan faulted on
 * `cmp byte [rbx],0x20` with rbx=0. Every pre-UCRT runtime (msvcr80..msvcr120,
 * msvcrt) exports its globals this way; UCRT apps go through __p__* getters.
 *
 * Called on the loader's restore call, while the thunks are still writable. Only
 * the importer's IAT directory is touched, and only slots whose target is a
 * non-executable section of an ARM64EC/ARM64 module. x64 targets keep PE
 * addresses: FEX runs their code at PE VAs, so their PE copy is the live one. */
static void ios_x64_iat_bind_live_data( char *base, size_t size )
{
    static int said, calls;
    uintptr_t rs = (uintptr_t)base, re = rs + size, pe, lo, hi, page = 0;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_DATA_DIRECTORY dir;
    unsigned int lfanew = 0;
    void *owner;
    uint64_t *p;
    int i, imp = -1, page_rd = 0, page_ok = 0, scanned = 0, bound = 0, unreadable = 0;

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t b = (uintptr_t)ios_jit_mappings[i].pe_base;
        if (b && rs >= b && re <= b + ios_jit_mappings[i].size) { imp = i; break; }
    }
    /* ml1245: a pure x64 importer only; an EC module reads its pool-side IAT */
    if (imp < 0 || ios_jit_mapping_machine( imp ) != 0x8664 || ios_jit_mapping_is_hybrid( imp )) return;

    /* The importer's headers are read fault-safe too, like its IAT pages below:
     * this runs on every protection change inside an x64 image, and a packer or
     * DRM stub may have made its own header page PAGE_NOACCESS. */
    pe = (uintptr_t)ios_jit_mappings[imp].pe_base;
    if (!ios_safe_read( pe + offsetof( IMAGE_DOS_HEADER, e_lfanew ), &lfanew, sizeof(lfanew) )
        || (size_t)lfanew + sizeof(nt) > ios_jit_mappings[imp].size
        || !ios_safe_read( pe + lfanew, &nt, sizeof(nt) )) return;
    if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IAT) return;
    dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    lo = pe + dir.VirtualAddress > rs ? pe + dir.VirtualAddress : rs;
    hi = pe + dir.VirtualAddress + dir.Size < re ? pe + dir.VirtualAddress + dir.Size : re;
    if (!dir.Size || lo >= hi) return;

    owner = ios_jit_current_peb();
    for (p = (uint64_t *)((lo + 7) & ~(uintptr_t)7); (uintptr_t)(p + 1) <= hi; p++)
    {
        uint64_t val;
        void *nv;
        int t;

        /* ml1169: look at the page BEFORE reading the slot. The restore call normally
         * arrives while the thunks are still RW, but a packer or DRM stub can leave
         * its IAT PAGE_NOACCESS/guarded, and reading that here would fault in unix
         * code. Unreadable: skip the slot; not writable: log it and leave it. */
        if (((uintptr_t)p & ~(uintptr_t)0x3fff) != page)
        {
            mach_vm_address_t a = (uintptr_t)p;
            mach_vm_size_t rsz = 0;
            vm_region_basic_info_data_64_t inf;
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj = MACH_PORT_NULL;

            page = (uintptr_t)p & ~(uintptr_t)0x3fff;
            page_rd = mach_vm_region( mach_task_self(), &a, &rsz, VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&inf, &cnt, &obj ) == KERN_SUCCESS
                      && a <= (uintptr_t)p && (inf.protection & VM_PROT_READ);
            page_ok = page_rd && (inf.protection & VM_PROT_WRITE);
        }
        if (!page_rd) { unreadable++; continue; }
        val = *p;
        if (!val) continue;
        scanned++;
        for (t = 0; t < ios_jit_mapping_count; t++)
        {
            uintptr_t b = (uintptr_t)ios_jit_mappings[t].pe_base;
            if (b && val >= b && val < b + ios_jit_mappings[t].size) break;
        }
        if (t == ios_jit_mapping_count) continue;
        /* ml1245: only targets that run from the pool. ml1244 tested the machine
         * word for 0xA641/0xAA64 here, which no EC DLL carries (they read 0x8664),
         * so on device it never bound a single slot. */
        if (!ios_jit_mapping_is_hybrid( t )) continue;
        if (ios_img_off_is_exec( ios_jit_mappings[t].pe_base, ios_jit_mappings[t].size,
                                 val - (uintptr_t)ios_jit_mappings[t].pe_base )) continue;
        nv = ios_jit_translate_addr_for_owner( (void *)(uintptr_t)val, owner );
        if ((uint64_t)(uintptr_t)nv == val) continue;

        if (said < 24)
        {
            said++;
            dprintf( 2, "[x64-data-imp] ml1245 %s slot %p: %#llx -> %p (data export of pe=%p)\n",
                     page_ok ? "BOUND" : "SKIP (page not writable)", p,
                     (unsigned long long)val, nv, ios_jit_mappings[t].pe_base );
        }
        if (page_ok) { *p = (uint64_t)(uintptr_t)nv; bound++; }
    }

    /* One line per x64 IAT window for the first few calls, then only windows
     * that bound something: a silent log must mean "never reached", not "maybe". */
    if (++calls <= 6 || (bound && calls <= 400))
        dprintf( 2, "[x64-data-imp] ml1245 importer pe=%p IAT window %p+%#lx: %d slot(s), %d data import(s) bound%s\n",
                 (void *)pe, (void *)lo, (unsigned long)(hi - lo), scanned, bound,
                 unreadable ? " (ml1169: unreadable IAT page(s) skipped)" : "" );
}

/* ml1017: OPT-IN via `madeira-iat-noexec.txt` = 1.
 *
 * Default OFF because the guard is UNPROVEN and possibly too broad: enabling it
 * declined 20,544 rewrites in one run, and a packed executable can mark its
 * import table executable too -- in which case this suppresses exactly the
 * rewrites the sync exists for (the rpcss milestone). It also did not fix the
 * crash it was written for. Returns 1 when the guard should be ACTIVE. */
static int ios_iat_skip_exec_dest( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        cached = madeira_cfg_bool( "iat-noexec", 0 );   /* ml1095: madeira.cfg iat-noexec = 1 */
        if (cached)
            dprintf( 2, "[iat-sync] ml1017 iat-noexec=1 -- declining rewrites whose "
                        "destination is in an executable section\n" );
    }
    return cached;
}

void ios_jit_sync_write(void *addr, size_t size)
{
    int i, fallback = -1;
    uintptr_t a = (uintptr_t)addr;
    void *cur_peb = ios_jit_current_peb();

    /* Owner-aware: sync into the copy the CURRENT process's PE code reads
     * (child init syncs into the child's ntdll copy; parent boot into the
     * parent's). Falls back to the NULL-owner entry like translate does. */
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t base = (uintptr_t)ios_jit_mappings[i].pe_base;
        if (a >= base && a < base + ios_jit_mappings[i].size)
        {
            if (ios_jit_mappings[i].owner_peb == cur_peb) { fallback = i; break; }
            if (!ios_jit_mappings[i].owner_peb && fallback < 0) fallback = i;
        }
    }
    if (fallback >= 0)
    {
        size_t off = a - (uintptr_t)ios_jit_mappings[fallback].pe_base;
        /* The JIT RW mapping is at ios_jit_rw_base_global + pool_offset.
         * The pool_offset = jit_base - jit_rx_base_global */
        uintptr_t pool_offset = (uintptr_t)ios_jit_mappings[fallback].jit_base
                              - (uintptr_t)ios_jit_rx_base_global;
        char *jit_rw_dest = (char *)ios_jit_rw_base_global + pool_offset + off;
        memcpy(jit_rw_dest, addr, size);
    }
}

/* RtlPcToFileHeader must know JIT-pool aliases.
 *
 * ARM64EC builtins run from their pool copy, so every address they compute
 * PC-relative -- their own code, .rdata, the C++ throw descriptors Wine emits
 * into .text -- is a pool VA that no loader entry covers. Wine's
 * _CxxThrowException stores RtlPcToFileHeader(ThrowInfo) as the throw's image
 * base: 0 for a pool VA, while the magic stays 0x19930520. Microsoft's
 * __CxxFrameHandler4 (a game's VCRUNTIME140_1) then reads 0 + RVA and dies.
 * Ghost of Tsushima: std::runtime_error from Wine's msvcp140 (ThrowInfo at
 * RVA 0x166a0, CatchableTypeArray 0x16694 = the fault address), after a save
 * and sometimes at start-up. The same lookup serves RTTI and
 * GetModuleHandleEx(FROM_ADDRESS).
 *
 * The PE ntdll is a prebuilt binary, so the pool copy of RtlPcToFileHeader is
 * patched in place: its third instruction, `mov x20, x0` (right after the
 * prologue saved x19-x21 and x30), becomes a BL to a six-instruction
 * trampoline in the padding after ntdll's .text that maps x0 through
 * ios_jit_reverse_translate_addr (identity for anything outside the pool),
 * performs the displaced `mov x20, x0` and returns. Every instruction is
 * checked first; any mismatch leaves the function alone. Idempotent. */
int ios_patch_rtl_pc_to_file_header( void *module, const void *export_addr )
{
    static const unsigned char ffs[10] = { 0x48,0x8b,0xc4,0x48,0x89,0x58,0x20,0x55,0x5d,0xe9 };
    extern void *ios_jit_reverse_translate_addr(const void *addr);
    const unsigned char *t = export_addr, *img = module;
    uintptr_t base = (uintptr_t)module, body_pe, rx_lo = (uintptr_t)ios_jit_rx_base_global;
    uint32_t e_lfanew, nsec, optsz, size_of_image, body_rva, sec_va = 0, sec_vs = 0, gap_end = 0, tramp_rva, i;
    const unsigned char *sh;
    char *base_rx, *body_rx, *tramp_rx, *body_rw, *tramp_rw;
    uint32_t *tw, bl, want_tramp[6] = { 0xa9bf7be1, 0x580000b0, 0xd63f0200, 0xa8c17be1, 0xaa0003f4, 0xd65f03c0 };
    int32_t rel;
    int64_t delta;
    int found = 0;

    if (!module || !export_addr || !rx_lo || !ios_jit_rw_base_global) return -1;
    /* the export is an x64 fast-forward thunk: mov rax,rsp; mov [rax+20h],rbx; push rbp; pop rbp; jmp body */
    if (memcmp( t, ffs, sizeof(ffs) )) { dprintf( 2, "[pc2fh] export %p is not the expected thunk -- not patched\n", t ); return -1; }
    memcpy( &rel, t + 10, 4 );
    body_pe = (uintptr_t)t + 14 + (intptr_t)rel;
    memcpy( &e_lfanew, img + 0x3c, 4 );
    nsec = *(const uint16_t *)(img + e_lfanew + 6);
    optsz = *(const uint16_t *)(img + e_lfanew + 20);
    memcpy( &size_of_image, img + e_lfanew + 24 + 56, 4 );
    if (body_pe <= base || body_pe - base >= size_of_image) return -1;
    body_rva = (uint32_t)(body_pe - base);
    sh = img + e_lfanew + 24 + optsz;
    for (i = 0; i < nsec; i++)
    {
        uint32_t vs, va;
        memcpy( &vs, sh + 40 * i + 8, 4 ); memcpy( &va, sh + 40 * i + 12, 4 );
        if (body_rva >= va && body_rva < va + vs) { sec_va = va; sec_vs = vs; found = 1; }
    }
    if (!found) return -1;
    gap_end = size_of_image;
    for (i = 0; i < nsec; i++)
    {
        uint32_t va;
        memcpy( &va, sh + 40 * i + 12, 4 );
        if (va > sec_va && va < gap_end) gap_end = va;
    }
    /* The trampoline goes in the tail of the section's LAST PAGE, past its
     * VirtualSize and before the next section: the only padding the pool copy
     * maps executable (whole 16 KB pages), and no section's virtual range, so
     * nothing in the image refers to it. It is not zero on the device (the
     * 16 KB mapping fills it from whatever follows .text in the file), so its
     * content is not a test; the pool-side check below only refuses bytes
     * another patcher changed. The end of the gap before the next section is
     * not usable: it lies outside the executable pages. */
    {
        uint32_t lo = ((sec_va + sec_vs + 15u) & ~15u) + 16u;
        uint32_t hi = (sec_va + sec_vs + 0x3fffu) & ~0x3fffu;
        if (hi > gap_end) hi = gap_end;
        if (lo + 48 > hi) { dprintf( 2, "[pc2fh] no room after .text in its last page (%08x..%08x) -- not patched\n", lo, hi ); return -1; }
        tramp_rva = lo;
    }

    base_rx = ios_jit_translate_addr( module );
    if ((uintptr_t)base_rx == base || (uintptr_t)base_rx < rx_lo || (uintptr_t)base_rx - rx_lo >= ios_jit_pool_size_global) return -1;
    body_rx = base_rx + body_rva; tramp_rx = base_rx + tramp_rva;
    body_rw = (char *)ios_jit_rw_base_global + ((uintptr_t)body_rx - rx_lo);
    tramp_rw = (char *)ios_jit_rw_base_global + ((uintptr_t)tramp_rx - rx_lo);
    tw = (uint32_t *)body_rx;
    delta = (int64_t)((intptr_t)tramp_rx - (intptr_t)(body_rx + 8));
    if (delta & 3 || delta >= (1ll << 27) || delta < -(1ll << 27)) return -1;
    bl = 0x94000000u | ((uint32_t)(delta >> 2) & 0x03ffffffu);
    if (tw[2] == bl) return 0;   /* this copy is already patched */
    if (tw[0] != 0xa9be53f3 || tw[1] != 0xa9017bf5 || tw[2] != 0xaa0003f4)
    {
        dprintf( 2, "[pc2fh] RtlPcToFileHeader at %p starts %08x %08x %08x, not the expected prologue -- not patched\n",
                 body_rx, tw[0], tw[1], tw[2] );
        return -1;
    }
    /* The pool copy's bytes there must be what the image has (or zero): anything
     * else means another patch already lives there. */
    {
        const unsigned char *pr = (const unsigned char *)tramp_rx, *ir = img + tramp_rva;
        int zero = 1;
        for (i = 0; i < 48; i++) if (pr[i]) { zero = 0; break; }
        if (!zero && memcmp( pr, ir, 48 ))
        {
            dprintf( 2, "[pc2fh] padding at %p differs from the image -- in use, not patched\n", tramp_rx );
            return -1;
        }
    }

    memcpy( tramp_rw, want_tramp, sizeof(want_tramp) );
    {
        uint64_t fn = (uint64_t)(uintptr_t)ios_jit_reverse_translate_addr;
        memcpy( tramp_rw + 24, &fn, 8 );   /* ldr x16 literal at +24 (8-aligned: tramp_rva is 16-aligned) */
    }
    sys_icache_invalidate( tramp_rx, 32 );
    __atomic_store_n( (uint32_t *)(body_rw + 8), bl, __ATOMIC_RELEASE );
    sys_icache_invalidate( body_rx + 8, 4 );
    dprintf( 2, "[pc2fh] RtlPcToFileHeader %p (pool %p) now maps JIT-pool aliases to their image; trampoline %p\n",
             (void *)body_pe, body_rx, tramp_rx );
    return 1;
}

/* The same patch for a pseudo-process child's PRIVATE ntdll copy
 * (ios_jit_copy_module_for_child). load_ntdll_functions patches the session's
 * copy only; a child's copy is a fresh memcpy of the unpatched image. The patch
 * finds its target through the owner-aware ios_jit_translate_addr, so called on
 * the child's boot thread (TEB->Peb = the child) it patches the child's copy,
 * which is the one the child's code calls into. `pe_addr` is any address inside
 * the shared ntdll image. */
int ios_patch_rtl_pc_to_file_header_current( const void *pe_addr )
{
    int i;

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        const unsigned char *b = ios_jit_mappings[i].pe_base;
        size_t sz = ios_jit_mappings[i].size;
        void *f;

        if (!b || !sz || ios_jit_mappings[i].owner_peb) continue;
        if ((const unsigned char *)pe_addr < b || (const unsigned char *)pe_addr >= b + sz) continue;
        f = ios_pe_find_export( b, "RtlPcToFileHeader" );
        return f ? ios_patch_rtl_pc_to_file_header( (void *)b, f ) : -1;
    }
    return -1;
}

/* madeira-bcd: NtProtectVirtualMemory's [exec-req] path must leave the syscall callback.
 *
 * The PE ntdll (app/Madeira/arm64ec-windows/ntdll.dll, a prebuilt binary of the
 * wine fork's dlls/ntdll/signal_arm64ec.c) wraps NtProtectVirtualMemory for the
 * emulator: enter_syscall_callback() sets CHPE_V2_CPU_AREA_INFO::InSyscallCallback,
 * the protection is changed, FEX is told (NotifyMemoryProtect ->
 * InvalidationTracker) and leave_syscall_callback() clears the flag again. The
 * ml283 [exec-req] probe in that wrapper -- taken for the first 64 requests per
 * ntdll copy that ask for an EXECUTE protection -- does its own syscall, log line
 * and notification and then `return st;` WITHOUT leave_syscall_callback(). In the
 * binary shipped until 7b56800 (function at VA 0x1800570f4) its three exits, 0x1800573bc
 * (cross-process), 0x1800573c8 (no NotifyMemoryProtect) and 0x1800573f8 (after the
 * notification), all branch to the epilogue at 0x180057514; only the non-exec
 * path passes 0x1800574d8 `ldr x8,[x18,#0x1788]; cbz x8; strb wzr,[x8,#1]`.
 *
 * So after one executable protect InSyscallCallback stays 1 on that thread until
 * FEX next compiles or links a block there (its dispatcher sets and clears the
 * flag around those calls, FEXCore Dispatcher.cpp EmitSignalGuardedRegion) or a
 * guest-visible exception passes ResetToConsistentState. Code that is already
 * compiled and linked -- a loop calling VirtualProtect -- does neither. In
 * between, every NtProtectVirtualMemory / NtAllocateVirtualMemory(Ex) /
 * NtFreeVirtualMemory / NtMapViewOfSection(Ex) wrapper on that thread sees the
 * flag, takes its raw path and tells FEX NOTHING -- no executable range added, no
 * range removed, no translated code invalidated -- and prints none of its probes.
 * Log PlayGTAV.exe 2026-10-02 10:51:28: [exec-req] #1 on tid 0024 (line 396), and
 * the next four NtMapViewOfSection on that thread -- the emulator's own image and
 * its imports -- report insc_before=1 entered=0 (lines 450-509), while the child
 * maps the same four with no [exec-req] before them and reports insc_before=0
 * entered=1 (1722-1755). A program that makes several ranges executable in a
 * row from code that is already compiled (a protector's section pass, a hooking
 * library) loses every request after the first.
 *
 * The PE ntdll cannot be rebuilt here, so the pool copy every ARM64EC caller runs
 * is patched in place, like [pc2fh], by retargeting the three branches:
 *   +0x04  b.eq -> +0x130 (exec cross-process block)  becomes  b.eq -> +0xf4, the
 *          identical block of the non-exec path, which falls into the clear;
 *   +0x10  cbz x11 -> +0x15c (epilogue)  becomes  cbz x11 -> +0x120 (the clear);
 *   +0x40  b -> +0x15c                   becomes  b -> +0x120.
 * (offsets from the probe's `tst w25, #0xff`, VA 0x1800573b8). Every instruction the
 * patched paths run is checked first, in the image and in the pool copy; any
 * mismatch leaves the copy alone. Idempotent. OPT-IN: MADEIRA_EXECREQ_LEAVE=1 (env,
 * or `env.MADEIRA_EXECREQ_LEAVE = 1` in a game's settings), because it changes
 * what the emulator is told after every executable protect in every game: it is
 * the upstream behaviour, but notifications the leak used to drop will arrive
 * (GTA V Enhanced).
 *
 * Wine 38aa753f98b (ml1259) added the missing leave_syscall_callback() in source,
 * and every ntdll.dll shipped since 7b56800 (2026-10-04) has it, so build 442 said
 * "not found" for every ntdll copy. That layout (ios_execreq_fixed_sig) is now
 * recognised: MADEIRA_EXECREQ_LEAVE=1 says once that there is nothing to patch
 * and writes nothing. */
#define IOS_EXECREQ_WORDS 17u
static const uint32_t ios_execreq_sig[IOS_EXECREQ_WORDS] = {
    0x72001f3f, /* +0x00 tst  w25, #0xff                 is_current              */
    0x54000960, /* +0x04 b.eq +0x130 -> exec cross-process notification   SITE A  */
    0xf00003c8, /* +0x08 adrp x8, (pNotifyMemoryProtect)                          */
    0xf947550b, /* +0x0c ldr  x11, [x8, #0xea8]                                   */
    0xb4000a6b, /* +0x10 cbz  x11, +0x15c -> epilogue                     SITE B  */
    0xb00003c8, /* +0x14 adrp x8, (icall checker)                                 */
    0xf94002c1, /* +0x18 ldr  x1, [x22]                  *size_ptr                */
    0xf94002a0, /* +0x1c ldr  x0, [x21]                  *addr_ptr                */
    0xf945c508, /* +0x20 ldr  x8, [x8, #0xb88]                                    */
    0xb000014a, /* +0x24 adrp x10, ...                                            */
    0x9126514a, /* +0x28 add  x10, x10, #0x994                                    */
    0xd63f0100, /* +0x2c blr  x8                                                  */
    0x2a1303e2, /* +0x30 mov  w2, w19                    new_prot                 */
    0x52800023, /* +0x34 mov  w3, #1                     After                    */
    0x2a1a03e4, /* +0x38 mov  w4, w26                    status                   */
    0xd63f0160, /* +0x3c blr  x11                        NotifyMemoryProtect      */
    0x14000047, /* +0x40 b    +0x15c -> epilogue                          SITE C  */
};
#define IOS_EXECREQ_SITE_A   0x04u
#define IOS_EXECREQ_SITE_B   0x10u
#define IOS_EXECREQ_SITE_C   0x40u
#define IOS_EXECREQ_XPROC_NX 0xf4u   /* cross-process post notification, non-exec path */
#define IOS_EXECREQ_CLEAR    0x120u  /* ldr x8,[x18,#0x1788]; cbz x8,epi; strb wzr,[x8,#1]; b epi */
#define IOS_EXECREQ_XPROC_X  0x130u  /* the same block on the exec path, no clear after it */
#define IOS_EXECREQ_EPILOGUE 0x15cu  /* mov w0, w26; ldp ...; ret */

static uint32_t ios_a64_b( uint32_t from, uint32_t to )
{
    return 0x14000000u | (((to - from) >> 2) & 0x03ffffffu);
}

static uint32_t ios_a64_bcond( uint32_t from, uint32_t to, uint32_t cond )
{
    return 0x54000000u | ((((to - from) >> 2) & 0x7ffffu) << 5) | cond;
}

static uint32_t ios_a64_cbz64( uint32_t from, uint32_t to, uint32_t rt )
{
    return 0xb4000000u | ((((to - from) >> 2) & 0x7ffffu) << 5) | rt;
}

static uint32_t ios_a64_bl_target( uint32_t pc, uint32_t insn )
{
    int32_t imm = (int32_t)(insn << 6) >> 6;   /* sign-extended imm26 */
    return pc + (uint32_t)(imm * 4);
}

static uint32_t ios_a64_imm19_target( uint32_t pc, uint32_t insn )
{
    int32_t imm = (int32_t)(insn << 8) >> 13;   /* sign-extended imm19: b.cond, cbz, cbnz */
    return pc + (uint32_t)(imm * 4);
}

static int ios_a64_is_branch( uint32_t insn )
{
    return (insn & 0x7c000000u) == 0x14000000u    /* b, bl */
        || (insn & 0xff000010u) == 0x54000000u    /* b.cond */
        || (insn & 0x7c000000u) == 0x34000000u    /* cbz, cbnz, tbz, tbnz */
        || (insn & 0xfe000000u) == 0xd6000000u;   /* br, blr, ret */
}

static int ios_execreq_leave_wanted( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        /* Default off. 1 makes NtProtectVirtualMemory's [exec-req] path clear
         * InSyscallCallback again, so the emulator hears about the memory changes
         * that follow an executable protect on the same thread (GTA V Enhanced,
         * the NoExec crash). */
        const char *e = getenv( "MADEIRA_EXECREQ_LEAVE" );
        cached = (e && e[0] == '1') ? 1 : 0;
    }
    return cached;
}

/* The words the three sites hold after the patch, computed from their offsets. */
static void ios_execreq_patched_words( uint32_t out[3] )
{
    out[0] = ios_a64_bcond( IOS_EXECREQ_SITE_A, IOS_EXECREQ_XPROC_NX, 0 /* eq */ );
    out[1] = ios_a64_cbz64( IOS_EXECREQ_SITE_B, IOS_EXECREQ_CLEAR, 11 );
    out[2] = ios_a64_b( IOS_EXECREQ_SITE_C, IOS_EXECREQ_CLEAR );
}

/* Are the blocks the patched branches reach what the patch was written against?
 * `w` is the function at the probe, in the image (check_x18 = 1) or in a pool copy
 * (check_x18 = 0: the x18 patcher replaces `ldr x8,[x18,#0x1788]` there with a
 * branch to its trampoline). */
static int ios_execreq_layout_ok( const uint32_t *w, int check_x18 )
{
    const uint32_t nx = IOS_EXECREQ_XPROC_NX / 4, xx = IOS_EXECREQ_XPROC_X / 4;
    const uint32_t clr = IOS_EXECREQ_CLEAR / 4, epi = IOS_EXECREQ_EPILOGUE / 4;
    unsigned i;

    /* the two cross-process blocks: ten identical instructions, then a BL to the
     * same send_cross_process_notification */
    for (i = 0; i < 10; i++) if (w[nx + i] != w[xx + i]) return 0;
    if (w[nx] != 0xf94002c3 /* ldr x3,[x22] */ || w[nx + 7] != 0xb90013fa /* str w26,[sp,#0x10] */) return 0;
    if ((w[nx + 10] & 0xfc000000u) != 0x94000000u || (w[xx + 10] & 0xfc000000u) != 0x94000000u) return 0;
    if (ios_a64_bl_target( (nx + 10) * 4, w[nx + 10] ) != ios_a64_bl_target( (xx + 10) * 4, w[xx + 10] )) return 0;
    /* the non-exec path's block falls straight into the clear */
    if (nx + 11 != clr) return 0;
    if (check_x18 && w[clr] != 0xf94bc648 /* ldr x8, [x18, #0x1788] */) return 0;
    if (w[clr + 1] != ios_a64_cbz64( (clr + 1) * 4, IOS_EXECREQ_EPILOGUE, 8 )) return 0;
    if (w[clr + 2] != 0x3900051f /* strb wzr, [x8, #1]: InSyscallCallback = 0 */) return 0;
    if (w[clr + 3] != ios_a64_b( (clr + 3) * 4, IOS_EXECREQ_EPILOGUE )) return 0;
    /* the epilogue returns the status every path keeps in w26 */
    if (w[epi] != 0x2a1a03e0 /* mov w0, w26 */ || w[epi + 6] != 0xd65f03c0 /* ret */) return 0;
    return 1;
}

/* The probe as wine 38aa753f98b builds it (VA 0x1800574d8 in 18c8f6d's ntdll.dll):
 * every exit runs leave_syscall_callback() -- `ldr x8,[x18,#0x1788]; cbz/cbnz x8;
 * strb wzr,[x8,#1]` -- before the epilogue. {word, mask}: what adrp and the
 * add/ldr offsets address, and the branch offsets, move with every rebuild. */
#define IOS_EXECREQ_FIXED_WORDS 19u
static const uint32_t ios_execreq_fixed_sig[IOS_EXECREQ_FIXED_WORDS][2] = {
    { 0x72001f3f, 0xffffffff }, /* +0x00 tst  w25, #0xff             is_current          */
    { 0x54000000, 0xff00001f }, /* +0x04 b.eq -> cross-process block, then the clear     */
    { 0x90000008, 0x9f00001f }, /* +0x08 adrp x8, (pNotifyMemoryProtect)                 */
    { 0xf940010b, 0xffc003ff }, /* +0x0c ldr  x11, [x8, #...]                            */
    { 0xb400000b, 0xff00001f }, /* +0x10 cbz  x11 -> the clear                           */
    { 0xf94002c1, 0xffffffff }, /* +0x14 ldr  x1, [x22]               *size_ptr          */
    { 0xf9400280, 0xffffffff }, /* +0x18 ldr  x0, [x20]               *addr_ptr          */
    { 0x90000008, 0x9f00001f }, /* +0x1c adrp x8, (icall checker)                        */
    { 0xf9400108, 0xffc003ff }, /* +0x20 ldr  x8, [x8, #...]                             */
    { 0x9000000a, 0x9f00001f }, /* +0x24 adrp x10, ...                                   */
    { 0x9100014a, 0xffc003ff }, /* +0x28 add  x10, x10, #...                             */
    { 0xd63f0100, 0xffffffff }, /* +0x2c blr  x8                                         */
    { 0x2a1303e2, 0xffffffff }, /* +0x30 mov  w2, w19                 new_prot           */
    { 0x52800023, 0xffffffff }, /* +0x34 mov  w3, #1                  After              */
    { 0x2a1a03e4, 0xffffffff }, /* +0x38 mov  w4, w26                 status             */
    { 0xd63f0160, 0xffffffff }, /* +0x3c blr  x11                     NotifyMemoryProtect */
    { 0xf94bc648, 0xffffffff }, /* +0x40 ldr  x8, [x18, #0x1788]      leave_syscall_callback() */
    { 0xb5000008, 0xff00001f }, /* +0x44 cbnz x8 -> the clear's strb                     */
    { 0x14000000, 0xfc000000 }, /* +0x48 b    -> epilogue                                */
};

/* Is `w` (the image at a `tst w25, #0xff`, `room` bytes before the section ends)
 * the fixed probe? Checks that each exit reaches the clear: the cross-process
 * block runs straight into it, the no-NotifyMemoryProtect exit branches to it,
 * the notified exit has its own copy, and the clear falls into the epilogue. */
static int ios_execreq_fixed_ok( const uint32_t *w, uint32_t room )
{
    uint32_t i, xp, clr, epi;

    for (i = 0; i < IOS_EXECREQ_FIXED_WORDS; i++)
        if ((w[i] & ios_execreq_fixed_sig[i][1]) != ios_execreq_fixed_sig[i][0]) return 0;
    xp = ios_a64_imm19_target( 0x04, w[1] );
    clr = ios_a64_imm19_target( 0x10, w[4] );
    epi = clr + 12;
    if (clr < (IOS_EXECREQ_FIXED_WORDS + 11) * 4 || clr >= room || room - clr < 12 + 7 * 4) return 0;
    if (w[clr / 4] != 0xf94bc648 /* ldr x8, [x18, #0x1788] */ ||
        w[clr / 4 + 1] != ios_a64_cbz64( clr + 4, epi, 8 ) ||
        w[clr / 4 + 2] != 0x3900051f /* strb wzr, [x8, #1]: InSyscallCallback = 0 */) return 0;
    if (w[epi / 4] != 0x2a1a03e0 /* mov w0, w26 */ || w[epi / 4 + 6] != 0xd65f03c0 /* ret */) return 0;
    if (ios_a64_imm19_target( 0x44, w[17] ) != clr + 8 || w[18] != ios_a64_b( 0x48, epi )) return 0;
    /* ten straight-line instructions and the BL to send_cross_process_notification */
    if (xp + 11 * 4 != clr || w[xp / 4] != 0xf94002c3 /* ldr x3,[x22] */ ||
        w[xp / 4 + 7] != 0xb90013fa /* str w26,[sp,#0x10] */) return 0;
    for (i = 0; i < 10; i++) if (ios_a64_is_branch( w[xp / 4 + i] )) return 0;
    return (w[xp / 4 + 10] & 0xfc000000u) == 0x94000000u;
}

/* The probe's RVA in the image's executable sections, or 0 unless found exactly
 * once: with the layout the patch was written against, or (fixed) as wine
 * 38aa753f98b builds it. */
static uint32_t ios_execreq_find( const unsigned char *img, int fixed )
{
    const uint32_t need = fixed ? IOS_EXECREQ_FIXED_WORDS * 4 : IOS_EXECREQ_EPILOGUE + 7 * 4;
    uint32_t e_lfanew, size_of_image, nsec, optsz, i, found = 0, hits = 0;
    const unsigned char *sh;

    if (img[0] != 'M' || img[1] != 'Z') return 0;
    memcpy( &e_lfanew, img + 0x3c, 4 );
    if (e_lfanew > 0x1000 || memcmp( img + e_lfanew, "PE\0\0", 4 )) return 0;
    nsec = *(const uint16_t *)(img + e_lfanew + 6);
    optsz = *(const uint16_t *)(img + e_lfanew + 20);
    memcpy( &size_of_image, img + e_lfanew + 24 + 56, 4 );
    sh = img + e_lfanew + 24 + optsz;
    for (i = 0; i < nsec; i++)
    {
        uint32_t vs, va, ch, off;
        memcpy( &vs, sh + 40 * i + 8, 4 ); memcpy( &va, sh + 40 * i + 12, 4 ); memcpy( &ch, sh + 40 * i + 36, 4 );
        if (!(ch & 0x20000000u /* IMAGE_SCN_MEM_EXECUTE */) || va >= size_of_image) continue;
        if (vs > size_of_image - va) vs = size_of_image - va;
        for (off = (va + 3) & ~3u; off + need <= va + vs; off += 4)
        {
            const uint32_t *w = (const uint32_t *)(img + off);

            if (w[0] != ios_execreq_sig[0]) continue;   /* tst w25, #0xff in both layouts */
            if (fixed ? !ios_execreq_fixed_ok( w, va + vs - off )
                      : (memcmp( w, ios_execreq_sig, sizeof(ios_execreq_sig) ) || !ios_execreq_layout_ok( w, 1 )))
                continue;
            found = off;
            hits++;
        }
    }
    return hits == 1 ? found : 0;
}

/* Patch the copy of `module` (the PE ntdll) that the CURRENT process runs:
 * ios_jit_translate_addr is owner-aware, so on a pseudo-process child's boot
 * thread this is the child's private copy. 1 patched, 0 already patched, not
 * wanted or not needed (the fixed probe), -1 refused (logged). */
int ios_patch_execreq_leave( void *module )
{
    static int said_off, said_fixed;
    const unsigned char *img = module;
    uintptr_t rx_lo = (uintptr_t)ios_jit_rx_base_global;
    uint32_t rva, want[3], i;
    char *base_rx, *fn_rx, *fn_rw;
    const uint32_t *pw;

    if (!ios_execreq_leave_wanted())
    {
        if (!said_off++)
            dprintf( 2, "[execreq-leave] off (MADEIRA_EXECREQ_LEAVE=1 makes NtProtectVirtualMemory's "
                        "[exec-req] path clear InSyscallCallback)\n" );
        return 0;
    }
    if (!module || !rx_lo || !ios_jit_rw_base_global) return -1;
    if (!(rva = ios_execreq_find( img, 0 )))
    {
        if ((rva = ios_execreq_find( img, 1 )))
        {
            if (!said_fixed++)
                dprintf( 2, "[execreq-leave] ntdll %p: NtProtectVirtualMemory's [exec-req] path already leaves the "
                            "syscall callback (rva %#x, wine 38aa753f98b) -- nothing to patch\n", module, rva );
            return 0;
        }
        dprintf( 2, "[execreq-leave] ntdll %p: the [exec-req] probe was not found exactly once with the "
                    "expected layout -- not patched (a different ntdll.dll build?)\n", module );
        return -1;
    }
    base_rx = ios_jit_translate_addr( module );
    if ((uintptr_t)base_rx == (uintptr_t)module || (uintptr_t)base_rx < rx_lo ||
        (uintptr_t)base_rx - rx_lo >= ios_jit_pool_size_global)
    {
        dprintf( 2, "[execreq-leave] ntdll %p has no pool copy for this process -- not patched\n", module );
        return -1;
    }
    fn_rx = base_rx + rva;
    fn_rw = (char *)ios_jit_rw_base_global + ((uintptr_t)fn_rx - rx_lo);
    pw = (const uint32_t *)fn_rx;
    ios_execreq_patched_words( want );
    if (pw[IOS_EXECREQ_SITE_A / 4] == want[0] && pw[IOS_EXECREQ_SITE_B / 4] == want[1] &&
        pw[IOS_EXECREQ_SITE_C / 4] == want[2])
        return 0;   /* this copy is already patched */
    for (i = 0; i < IOS_EXECREQ_WORDS; i++)
    {
        if (pw[i] != ios_execreq_sig[i])
        {
            dprintf( 2, "[execreq-leave] pool copy %p differs from the image at +%#x (%08x, image %08x) "
                        "-- not patched\n", fn_rx, i * 4, pw[i], ios_execreq_sig[i] );
            return -1;
        }
    }
    if (!ios_execreq_layout_ok( pw, 0 ))
    {
        dprintf( 2, "[execreq-leave] pool copy %p: the blocks the patch branches to differ from the image "
                    "-- not patched\n", fn_rx );
        return -1;
    }
    __atomic_store_n( (uint32_t *)(fn_rw + IOS_EXECREQ_SITE_B), want[1], __ATOMIC_RELEASE );
    __atomic_store_n( (uint32_t *)(fn_rw + IOS_EXECREQ_SITE_C), want[2], __ATOMIC_RELEASE );
    __atomic_store_n( (uint32_t *)(fn_rw + IOS_EXECREQ_SITE_A), want[0], __ATOMIC_RELEASE );
    sys_icache_invalidate( fn_rx, IOS_EXECREQ_SITE_C + 4 );
    dprintf( 2, "[execreq-leave] ntdll %p (pool %p): NtProtectVirtualMemory's [exec-req] path now clears "
                "InSyscallCallback (rva %#x: %08x %08x %08x)\n",
             module, fn_rx, rva, want[0], want[1], want[2] );
    return 1;
}

/* The same for a pseudo-process child's private ntdll copy; `pe_addr` is any
 * address inside the shared ntdll image (cf. ios_patch_rtl_pc_to_file_header_current). */
int ios_patch_execreq_leave_current( const void *pe_addr )
{
    int i;

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        const unsigned char *b = ios_jit_mappings[i].pe_base;
        size_t sz = ios_jit_mappings[i].size;

        if (!b || !sz || ios_jit_mappings[i].owner_peb) continue;
        if ((const unsigned char *)pe_addr < b || (const unsigned char *)pe_addr >= b + sz) continue;
        return ios_patch_execreq_leave( (void *)b );
    }
    return -1;
}

/* madeira-bcd: which PE section of a pool-copied image holds `va` (a NoExec
 * target, a protect request)? `va` may be a PE address or an address inside a
 * module's pool copy; for a pool address the text names the copy, its owner
 * and the process that mapped it (build 327: the child died in the PARENT's
 * ntdll copy, which a PE-only lookup could not name). Lock-free like the other
 * fault-path diagnostics: reads the mapping table and the image's own headers.
 * Writes the description into buf and the image's PE base into *img_base;
 * returns 0 when no pool-copied image covers va. */
int ios_image_section_describe( unsigned long long va, char *buf, size_t len, unsigned long long *img_base )
{
    int i, pass;

    for (pass = 0; pass < 2; pass++)
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        const unsigned char *pe = ios_jit_mappings[i].pe_base, *b = NULL;
        const unsigned char *in = pass ? (const unsigned char *)ios_jit_mappings[i].jit_base : pe;
        size_t sz = ios_jit_mappings[i].size;
        uint32_t e_lfanew = 0, nsec, optsz, s, off;
        const unsigned char *sh;
        char where[112];
        int k;

        if (!pe || !in || sz < 0x1000 || va < (uintptr_t)in || va >= (uintptr_t)in + sz) continue;
        if (img_base) *img_base = (uintptr_t)pe;
        off = (uint32_t)(va - (uintptr_t)in);
        if (pass)
            snprintf( where, sizeof(where), "POOL copy %p (owner=%p mapper=%p) of %p, rva %#x, ",
                      ios_jit_mappings[i].jit_base, ios_jit_mappings[i].owner_peb,
                      ios_jit_mappings[i].map_peb, (const void *)pe, off );
        else
            snprintf( where, sizeof(where), "rva %#x, ", off );
        /* The pool copy's headers first: they were copied when the image was
         * mapped, before a protector could wipe the live ones. */
        for (k = 0; k < 2; k++)
        {
            b = k ? pe : (const unsigned char *)ios_jit_mappings[i].jit_base;
            if (!b) continue;
            memcpy( &e_lfanew, b + 0x3c, 4 );
            if (e_lfanew <= 0x1000 - 0x200 && !memcmp( b + e_lfanew, "PE\0\0", 4 )) break;
        }
        if (k == 2)
        {
            snprintf( buf, len, "%s(image headers unreadable, rva %#x)", where, off );
            return 1;
        }
        nsec = *(const uint16_t *)(b + e_lfanew + 6);
        optsz = *(const uint16_t *)(b + e_lfanew + 20);
        sh = b + e_lfanew + 24 + optsz;
        for (s = 0; s < nsec && s < 96; s++)
        {
            char name[9];
            uint32_t vs, sva, raw, ch;

            if ((size_t)(sh + 40 * (s + 1) - b) > 0x1000) break;
            memcpy( name, sh + 40 * s, 8 ); name[8] = 0;
            memcpy( &vs, sh + 40 * s + 8, 4 ); memcpy( &sva, sh + 40 * s + 12, 4 );
            memcpy( &raw, sh + 40 * s + 16, 4 ); memcpy( &ch, sh + 40 * s + 36, 4 );
            if (!vs) vs = raw;
            if (off < sva || off - sva >= ((vs + 0xfffu) & ~0xfffu)) continue;
            snprintf( buf, len, "%ssection #%u '%s' rva %#x+%#x chars %#x (%s%s%s%s)", where, s, name, sva, vs, ch,
                      (ch & 0x40000000u) ? "R" : "-", (ch & 0x80000000u) ? "W" : "-",
                      (ch & 0x20000000u) ? "X" : "-", (ch & 0x00000020u) ? " CODE" : "" );
            return 1;
        }
        snprintf( buf, len, "%soutside every section (rva %#x, %u sections)", where, off, nsec );
        return 1;
    }
    return 0;
}

