/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Mapping files and images, placeholders, arm64x relocations. Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *           map_fixed_area
 *
 * Map a memory area at a fixed address.
 * virtual_mutex must be held by caller.
 */
#ifdef WINE_IOS
/* Madeira: set by ios_thin_reserve, with virtual_mutex held, while it maps a
 * head inside a thin arena. */
static int ios_thin_placing;
#endif

static NTSTATUS map_fixed_area( void *base, size_t size, int unix_prot )
{
    struct reserved_area *area;
    NTSTATUS status;
    char *start = base, *end = (char *)base + ROUND_SIZE( 0, size, host_page_mask );

    if ((UINT_PTR)base & host_page_mask) return STATUS_CONFLICTING_ADDRESSES;
    if (find_view_range( base, size )) return STATUS_CONFLICTING_ADDRESSES;
#ifdef WINE_IOS
    /* Madeira: every address in a thin arena lies inside some thin reservation's
     * range (or the arena's margin), so a fixed map there conflicts, as it would
     * on Windows. Only ios_thin_reserve places heads in it. */
    if (!ios_thin_placing)
    {
        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            if (area->base >= (void *)end) break;
            if (area->thin_only && (char *)area->base + area->size > start)
                return STATUS_CONFLICTING_ADDRESSES;
        }
    }
#endif

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        char *area_start = area->base;
        char *area_end = area_start + area->size;

        if (area_start >= end) break;
        if (area_end <= start) continue;
        if (area_start > start)
        {
            if (anon_mmap_tryfixed( start, area_start - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
            start = area_start;
        }
        if (area_end >= end)
        {
            if (anon_mmap_fixed( start, end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
            return STATUS_SUCCESS;
        }
        if (anon_mmap_fixed( start, area_end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
        start = area_end;
    }

    if (anon_mmap_tryfixed( start, end - start, unix_prot, 0 ) == MAP_FAILED) goto failed;
    return STATUS_SUCCESS;

failed:
    if (errno == ENOMEM)
    {
        ERR( "out of memory for %p-%p\n", base, (char *)base + size );
        status = STATUS_NO_MEMORY;
    }
    else if (errno == EEXIST) status = STATUS_CONFLICTING_ADDRESSES;
    else
    {
        ERR( "mmap error %s for %p-%p, unix_prot %#x\n",
             strerror(errno), base, (char *)base + size, unix_prot );
        status = STATUS_INVALID_PARAMETER;
    }
    unmap_area( base, start - (char *)base );
    return status;
}

/* madeira-bcd: [arena-guard] a fixed or hinted guest reservation never lands
 * in the FEX arena.
 *
 * map_reserved_area_inner keeps NULL-base requests out of the FEX_ONLY area
 * (ml799, fex_arena_covers), but a request that names its own base goes to
 * map_fixed_area, which treats every reserved area alike and maps over it with
 * anon_mmap_fixed, so a guest that picks an address inside the arena is given
 * the emulator's address space. SocialClubHelper.exe's V8 does exactly that:
 * 4 GB reserves at random hints through VirtualAlloc2, and one hint inside the
 * arena was granted there; FEX's 16 MB claims then failed and killed the
 * launcher or RDR2.exe (libarm64ecfex.dll+0xfe770 AV, +0x1175bc c000001d).
 *
 * Refuse such a request with STATUS_CONFLICTING_ADDRESSES, what it gets when
 * the range holds any view (find_view_range in map_fixed_area). A base address
 * is exact on Windows, never a preference, so callers already handle it: V8 and
 * PartitionAlloc retry without a hint (c0000018, then hint 0 -> 0x7240000000 in
 * the device log), a preferred image base relocates (map_image_view), and a
 * hinted reserve of 1 GB or more through NtAllocateVirtualMemory is placed
 * again by its own retry walk (task#29 plan C). FEX never asks with a base: its
 * reservations are NULL-base with MEM_ADDRESS_REQUIREMENTS in the arena
 * (AllocatorHooks.h, CallRetStack.h, rpmalloc's os_mmap), and
 * NtAllocateVirtualMemoryEx refuses a base together with limits. A request
 * whose limits lie in the arena still passes, the map_reserved_area_inner rule;
 * MEM_REPLACE_PLACEHOLDER returns before this. Called with virtual_mutex held.
 * The steering valve is kept out of the arena too (ios_steer_top_slot_usable),
 * so no guest NULL-base reserve is placed there either and a guest's release +
 * re-reserve at an aligned base inside its own reserve (V8's alignment
 * two-step, PartitionAlloc's TrimMapping) never meets this refusal.
 * MADEIRA_ARENA_GUARD=0 restores the old placement of both. */
static int ios_arena_guard_enabled(void)
{
    static int enabled = -1;
    int v = __atomic_load_n( &enabled, __ATOMIC_ACQUIRE );

    if (v < 0)
    {
        /* On by default. MADEIRA_ARENA_GUARD=0 lets a fixed or hinted guest reservation take FEX arena space again. */
        const char *e = getenv( "MADEIRA_ARENA_GUARD" );

        v = !(e && e[0] == '0');
        __atomic_store_n( &enabled, v, __ATOMIC_RELEASE );
    }
    return v;
}

static int ios_arena_guard_refuses( void *base, size_t size, ULONG_PTR limit_low, ULONG_PTR limit_high )
{
    static unsigned long refused_n;
    struct reserved_area *area;
    char *start = base, *end = (char *)base + ROUND_SIZE( 0, size, host_page_mask );

    if (!ios_arena_guard_enabled()) return 0;
    if (limit_high && fex_arena_covers( (void *)limit_low, (void *)limit_high )) return 0;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        char *area_start = area->base;
        char *area_end = area_start + area->size;

        if (area_start >= end) break;
        if (area_end <= start || !area->fex_only) continue;
        if (++refused_n <= 32 || !(refused_n % 256))
            dprintf( 2, "[arena-guard] #%lu refused fixed/hinted %p+0x%lx tid=%04x: overlaps the FEX arena %p..%p "
                        "-> STATUS_CONFLICTING_ADDRESSES, the caller places it elsewhere (MADEIRA_ARENA_GUARD=0 "
                        "reverts)\n", refused_n, base, (unsigned long)size,
                     NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0,
                     area_start, area_end );
        return 1;
    }
    return 0;
}

/* madeira-bcd: [arena-guard] may NtAllocateVirtualMemory's steering valve use
 * its top slot [ios_steer_slot, host_addr_space_limit)?
 *
 * Not when the FEX arena lies in it. That slot predates the arena: in layout 0
 * the arena IS [0x7c00000000, 0x8000000000), so fex_arena_covers accepts the
 * steer's limits outright, and in layouts 1/2 its [wow-band] clause accepts
 * [0x7c00000000, 0x8000000000] -- the device log shows "[wow-band] ... served
 * from the FEX arena" followed by "[steer] #1 ... -> above ceiling
 * 0x7f6b810000", a guest reserve inside FEX's range. What the arena leaves of
 * the slot is Social Club's native hold (layouts 1/2) or nothing (layout 0),
 * so skipping the whole slot loses nothing; the valve goes on to its
 * 0x7400000000 slot and then to normal placement, as it already did when the
 * top slot was full. */
static int ios_steer_top_slot_usable(void)
{
    static int said;

    if (!ios_arena_guard_enabled()) return 1;
    if (!ios_fex_arena_base_unix || ios_fex_arena_end_unix <= ios_steer_slot ||
        ios_fex_arena_base_unix >= (ULONG_PTR)host_addr_space_limit) return 1;
    if (!__atomic_exchange_n( &said, 1, __ATOMIC_RELAXED ))
        dprintf( 2, "[arena-guard] steering valve: the top slot [0x%lx,%p) holds the FEX arena [0x%lx,0x%lx); "
                    "steered reserves use the 0x7400000000 slot or normal placement (MADEIRA_ARENA_GUARD=0 "
                    "reverts)\n", (unsigned long)ios_steer_slot, host_addr_space_limit,
                 (unsigned long)ios_fex_arena_base_unix, (unsigned long)ios_fex_arena_end_unix );
    return 0;
}

/* madeira-bcd: [stack-spill] a 4 GB floor constrains nothing on iOS.
 *
 * init_thread_stack asks for every thread's kernel stack (1 MB), CHPE emulator
 * stack and WoW64 64-bit stack with limit_low = limit_4g, as upstream does to
 * keep them out of the low 4 GB. Nothing is ever mapped below 4 GB here (the
 * __PAGEZERO), but virtual_set_large_address_space resets address_space_start
 * to 0x10000 for a 64-bit program, so map_view's "limit_low at or below
 * address_space_start" test (ml119) never matches these requests. They scan
 * the low map from 4 GB on every thread creation (~260-300 refused tries each,
 * the [va-scan] SLOW lines) and, once the furniture band is full, fail with
 * STATUS_NO_MEMORY instead of taking the relax valve. RDR2 (build 460, log
 * 2026-10-08 23:59:11) froze that way four minutes into the story: RDR2.exe's
 * main thread retried CreateThread, every try ended in [va-scan] FAILED
 * window=0x100000000..0x73ffff0000 size=0x100000 and "[thr-create] FAILED at
 * kernel stack", while 1838 MB above the JIT pool's RW alias were free.
 * MADEIRA_THREAD_STACK_SPILL=1 treats a limit_low at or below 4 GB as absent:
 * the scan starts at the furniture floor, and a full band falls back to the
 * kernel's pick like any other relaxable request. Off by default. */
static int ios_stack_spill_enabled(void)
{
    static int enabled = -1;
    int v = __atomic_load_n( &enabled, __ATOMIC_ACQUIRE );

    if (v < 0)
    {
        const char *s = getenv( "MADEIRA_THREAD_STACK_SPILL" );

        v = s && s[0] == '1' && !s[1];
        __atomic_store_n( &enabled, v, __ATOMIC_RELEASE );
        if (v)
            dprintf( 2, "[stack-spill] MADEIRA_THREAD_STACK_SPILL=1: requests bounded only by a 4 GB floor "
                        "(thread kernel, emulator and WoW64 stacks) start at the furniture floor and use the "
                        "kernel's pick when the band is full\n" );
    }
    return v;
}

/***********************************************************************
 *           map_view
 *
 * Create a view and mmap the corresponding memory area.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_view( struct file_view **view_ret, void *base, size_t size,
                          unsigned int alloc_type, unsigned int vprot,
                          ULONG_PTR limit_low, ULONG_PTR limit_high, size_t align_mask )
{
    ios_af.stage = 0;   /* ml814: this request's attribution starts clean */
    int top_down = alloc_type & MEM_TOP_DOWN;
    void *ptr;
    int unix_prot = get_unix_prot( vprot );
    NTSTATUS status;

    if (!align_mask) align_mask = granularity_mask;
    assert( align_mask >= host_page_mask );

    if (alloc_type & MEM_REPLACE_PLACEHOLDER)
    {
        struct file_view *view;

        if (!(view = find_view( base, 0 ))) return STATUS_INVALID_PARAMETER;
        if (view->base != base || view->size != size) return STATUS_CONFLICTING_ADDRESSES;
        if (!(view->protect & VPROT_FREE_PLACEHOLDER)) return STATUS_INVALID_PARAMETER;

        TRACE( "found view %p, size %p, protect %#x.\n", view->base, (void *)view->size, view->protect );

        view->protect = vprot | VPROT_PLACEHOLDER;
        set_vprot( view, base, size, vprot );
        if (vprot & VPROT_WRITEWATCH)
        {
            kernel_writewatch_register_range( view, base, size );
            reset_write_watches( base, size );
        }
        *view_ret = view;
        return STATUS_SUCCESS;
    }

    if (limit_high && limit_low >= limit_high) return STATUS_INVALID_PARAMETER;

    if (use_kernel_writewatch && vprot & VPROT_WRITEWATCH)
        unix_prot = get_unix_prot( vprot & ~VPROT_WRITEWATCH );

    unix_prot &= ~PROT_EXEC;

    if (base)
    {
        if (is_beyond_limit( base, size, address_space_limit )) return STATUS_WORKING_SET_LIMIT_RANGE;
        if (limit_low && base < (void *)limit_low) return STATUS_CONFLICTING_ADDRESSES;
        if (limit_high && is_beyond_limit( base, size, (void *)limit_high )) return STATUS_CONFLICTING_ADDRESSES;
        if (is_beyond_limit( base, size, host_addr_space_limit )) return STATUS_CONFLICTING_ADDRESSES;
        /* madeira-bcd: [arena-guard] -- see ios_arena_guard_refuses */
        if (ios_arena_guard_refuses( base, size, limit_low, limit_high )) return STATUS_CONFLICTING_ADDRESSES;
        if ((status = map_fixed_area( base, size, unix_prot ))) return status;
        if (is_beyond_limit( base, size, working_set_limit )) working_set_limit = address_space_limit;
        ptr = base;
    }
    else
    {
        void *start = address_space_start;
        void *end = min( user_space_limit, host_addr_space_limit );
        void *wow_hi_start = NULL, *wow_hi_end = NULL;   /* madeira-bcd: band above the 32-bit windows */
        /* task #35 furniture ceiling — see its definition. Kernel-pick views
         * below 16GB (TEBs, stacks, anon views, section views incl. the 4GB
         * top-of-space tenant from ml106) stay below 464G-64K; only the PA
         * 16GB/32GB pool reserves may use the slots above. */
        int ceiling_relaxable = 0;
        int stack_spill = 0;   /* madeira-bcd: relaxable only through ios_stack_spill_enabled */
        if (ios_furniture_ceiling && !limit_high && size < 0x400000000ULL &&
            (void *)ios_furniture_ceiling < end)
        {
            end = (void *)ios_furniture_ceiling;
            /* Relaxable when the only *effective* constraint is ours. ml119
             * BUG: the first cut used !limit_low, so a caller passing a small
             * non-zero limit_low (<= address_space_start, i.e. not actually
             * constraining anything) disabled both the floor raise and the
             * fallback. Those calls kept scanning from 0x100010000 and burned
             * 21,875 failing mach_vm_map calls EACH — 1.42 MILLION across
             * ml119's 65 [va-scan] SLOW lines. A limit_low at or below
             * address_space_start is satisfied by any placement we would make
             * anyway, so treat it as absent: the floor is above it, and
             * relaxing reproduces exactly what a ceiling-disabled build does
             * for the same call. (top_down is a hint, not a contract, and is
             * knowingly dropped on the relax path.) */
            ceiling_relaxable = (limit_low <= (ULONG_PTR)address_space_start);
            /* madeira-bcd: [stack-spill] — see ios_stack_spill_enabled */
            if (!ceiling_relaxable && limit_low <= limit_4g && ios_stack_spill_enabled())
                ceiling_relaxable = stack_spill = 1;
        }
        size_t host_size = ROUND_SIZE( 0, size, host_page_mask );
        size_t unmap_size, view_size = host_size + align_mask + 1;
        int spill_tries = 0;

        if (limit_low && (void *)limit_low > start) start = (void *)limit_low;
        if (limit_high && (void *)limit_high < end) end = (char *)limit_high + 1;

#ifdef WINE_IOS
        /* WoW64 guest windows: a window is a Wine reserved area, so without
         * this the ordinary furniture search would place 64-bit views inside
         * a 32-bit pseudo-process's [B, B+4G) and starve it.  Requests that
         * ARE window-constrained (translated by ios_wow_translate_limits) keep
         * the window.  Advisory: if excluding the windows leaves no room, keep
         * the original range (the rule the furniture ceiling follows).  With no
         * window and no placeholder in the session this is skipped entirely. */
        if ((ios_wow_window_count || ios_wow_placeholder_count) &&
            !ios_wow_limits_in_window( limit_low, limit_high ))
        {
            void *excl_start = start, *excl_end = end;

            ios_wow_exclude_windows( &excl_start, &excl_end );
            if (excl_start < excl_end)
            {
                /* madeira-bcd: exclusion keeps the LOW side of a window, so a
                 * 64-bit program was confined below the first slot's placeholder
                 * (0x7038000000..0x7100000000, 3.2 GB) and never used the band
                 * above it. Remember that high side for when the low one is full. */
                if (excl_end < end)
                {
                    /* the whole space above the windows, not only up to the furniture
                     * ceiling: [0x7200000000, ceiling) was already taken on device (the
                     * fallback never placed anything there); a caller's own limit_high
                     * still bounds it */
                    void *hi_end = limit_high ? end : (void *)min( user_space_limit, host_addr_space_limit );
                    ios_wow_high_side( excl_end, hi_end, &wow_hi_start, &wow_hi_end );
                }
                start = excl_start; end = excl_end;
            }
        }

        /* Once the session is armed, keep the free 4 GB-aligned candidate slot
         * for the next 32-bit pseudo-process (see ios_wow_candidate_slot).  Only
         * for top-down picks, and only when ceiling_relaxable, i.e. when the
         * only constraints in force are ours and can be withdrawn again at the
         * "THE CEILING IS ADVISORY, NEVER FATAL" retry below. */
        if (top_down && ceiling_relaxable) end = ios_wow_bias_end( start, end );
#endif

        /* task #35 (ml116): raise the scan floor to match the ceiling — see
         * ios_usable_va_floor. Gated on end already being at/below the ceiling,
         * which is exactly the set of requests the ceiling put on the scan path
         * (clamped kernel-picks, plus images via map_image_view's limit_high).
         * Jumbo pool reserves keep end == host_addr_space_limit and so keep the
         * kernel-pick placement the ml96/ml105 census measured, and genuinely
         * low-limited callers (zero_bits / 4GB-capped) are far below the floor
         * and untouched. The window must still be able to hold the request. */
        /* ml118 BUG FIX: gate on ceiling_relaxable, not merely on end<=ceiling.
         * The first cut raised the floor for limit_low/limit_high callers too,
         * narrowing their window while giving them NO escape valve — a 1MB
         * request then hit a hard STATUS_NO_MEMORY (ml118 line 2471) and killed
         * Thumper with exit(3) two lines later. Never impose a constraint we
         * cannot also withdraw. */
        if (ceiling_relaxable && start < (void *)ios_usable_va_floor &&
            (char *)end > (char *)ios_usable_va_floor &&
            (size_t)((char *)end - (char *)ios_usable_va_floor) >= view_size)
            start = (void *)ios_usable_va_floor;

#ifdef WINE_IOS
        /* ml1070 [laa] LOW HALF FIRST for a SYNTHESISED 4 GB ceiling.
         *
         * See ios_wow_laa_synth.  The ceiling was raised for an image that never
         * declared IMAGE_FILE_LARGE_ADDRESS_AWARE, so wow64.dll's
         * default_zero_bits is 0xffffffff and every unhinted guest allocation —
         * every MEM_TOP_DOWN reserve above all — is searched from the top of the
         * window down.  Try the half the program was actually built for first.
         *
         * This is a PRE-ATTEMPT, not a constraint: it is one extra
         * map_reserved_area() call over the reserved-area tree (the guest window
         * IS a reserved area, so this is the path that serves guest allocations),
         * it is silent, and a NULL from it changes nothing — control falls into
         * exactly the pre-ml1070 code below with start/end untouched.  So it can
         * never turn a satisfiable allocation into STATUS_NO_MEMORY, which is the
         * ml118 rule ("never impose a constraint we cannot also withdraw").
         *
         * Only for requests whose two bounds are confined to a guest window:
         * host-side placements, and map_image_view's deliberate
         * high-half attempt for builtins (whose limit_low is B + 2 GB, so low_end
         * lands at or below start and the test below fails), are untouched. */
        if (ios_wow_laa_synth && ios_wow_laa_low_first() && !base &&
            ios_wow_limits_in_window( limit_low, limit_high ))
        {
            ULONG_PTR wb = ios_wow_base();
            void *low_end = (void *)(wb + limit_2g);

            /* Only a request whose range straddles 2 GB has anything to try: one
             * already confined below it, or deliberately above it, is not a spill. */
            int tried = wb && low_end > start && (char *)end > (char *)low_end &&
                        (size_t)((char *)low_end - (char *)start) >= view_size;

            if (tried &&
                (ptr = map_reserved_area( start, low_end, host_size, top_down,
                                          unix_prot, align_mask )))
            {
                static unsigned long lf_n;

                if (++lf_n <= 8 || !(lf_n % 512))
                    dprintf( 2, "[laa] ml1070 #%lu low-half placement %p+0x%lx (guest %p) for a "
                                "program whose header is not large-address-aware — the raised "
                                "ceiling stays, the high half is spill only (MADEIRA_LAA_LOWFIRST=0 "
                                "restores the old placement)\n",
                             lf_n, ptr, (unsigned long)size, (void *)((ULONG_PTR)ptr - wb) );
                goto done;
            }
            if (tried)
            {
                static unsigned long sp_n;

                /* The low half could not serve it.  Say so BEFORE spilling, because
                 * "the program got a bit-31 address" and "the program asked for one"
                 * are different findings and only this line separates them. */
                if (++sp_n <= 8 || !(sp_n % 64))
                    dprintf( 2, "[laa] ml1070 SPILL #%lu: no room below guest 2 GB for 0x%lx bytes "
                                "(%s, start=guest %p) — falling back to the whole window\n",
                             sp_n, (unsigned long)size, top_down ? "top-down" : "bottom-up",
                             (void *)((ULONG_PTR)start - wb) );
            }
        }
#endif

        if ((ptr = map_reserved_area( start, end, host_size, top_down, unix_prot, align_mask )))
        {
            TRACE( "got mem in reserved area %p-%p\n", ptr, (char *)ptr + size );
#ifdef WINE_IOS
            ios_fex_arena_headroom( start, end );
#endif
            goto done;
        }

        if (start > address_space_start || end < host_addr_space_limit || top_down)
        {
            unsigned int tries0 = ios_va_scan_tries;
            unsigned int skips0 = ios_va_scan_skips;

            ptr = map_free_area( start, end, host_size, top_down, unix_prot, align_mask );
#ifdef WINE_IOS
            /* the holdback is now a reserved area: place the view there */
            if (!ptr && ios_cage_release_on_exhaustion( start, end, view_size ))
                ptr = map_reserved_area( start, end, host_size, top_down, unix_prot, align_mask );
#endif
            /* [va-scan] the ml116/ml117 probe: a healthy scan costs a handful of
             * tryfixed calls. Hundreds means we are grinding unmappable VA;
             * ptr==NULL is the silent STATUS_NO_MEMORY that handed rpmalloc a
             * NULL. Either is the ceiling regression, so say so out loud — with
             * the geometry map_free_area actually saw, since ml117 failed with
             * tries=0 (rejected on a guard, no mmap attempted). */
            if (!ptr || ios_va_scan_tries - tries0 >= 64)
            {
                static int described;
                char what[128];

                /* ml207: latch furniture pressure — see ios_va_pressure. Deliberately a
                 * much stricter test than this probe's own 64-try "SLOW" threshold: an
                 * outright failure, or grinding on the order of a thousand attempts, is
                 * unambiguous exhaustion rather than ordinary fragmentation. */
                if (!ptr || ios_va_scan_tries - tries0 >= 1024)
                {
                    static int censused;

                    ios_va_pressure = 1;
                    if (!censused) { censused = 1; ios_furniture_census(); }
                }

                /* ml118 discriminator — see ios_scan_fail_addr. Rate-limited:
                 * the mach query is cheap but not free, and the first handful
                 * of verdicts settle the question. */
                what[0] = 0;
                if (ios_scan_fail_addr && described++ < 12)
                    ios_va_describe( ios_scan_fail_addr, what, sizeof(what) );

                {
                static unsigned long vs_storm;
                static unsigned vs_fails, vs_relaxed;
                /* ml366: FAILED must never be storm-gated — ml365's mmdevapi
                 * c0000017 loads left NO [va-scan] evidence because boot-time
                 * SLOW lines had already spent this site's storm budget. A
                 * failure is the one verdict worth a line every time (own
                 * generous cap so a retry loop cannot flood the log).
                 * madeira-bcd: a failure the unclamped retry absorbs gets its
                 * own smaller budget (64, then every 1024th): in GTA V
                 * Enhanced (log 2026-10-08 16:38:52, build 455) 256 of them
                 * had spent the cap 7 minutes into the session, so nothing
                 * could be seen when the Social Club helper failed to create
                 * a thread 6 minutes later. */
                if (ptr ? ios_storm_gate( &vs_storm )
                        : ceiling_relaxable ? (++vs_relaxed <= 64 || !(vs_relaxed % 1024)) : (vs_fails++ < 256))
                dprintf( 2, "[va-scan] %s window=%p..%p size=%p align=%p %s tries=%u skips=%u"
                            " | seen=%p..%p views=%u maxgap=%p tailgap=%p stop=%s"
                            " | firstfail=%p errno=%d(%s) %s%s\n",
                         ptr ? "SLOW" : "FAILED", start, end, (void *)size,
                         (void *)(align_mask + 1), top_down ? "top-down" : "bottom-up",
                         ios_va_scan_tries - tries0, ios_va_scan_skips - skips0,
                         ios_scan_base, ios_scan_end, ios_scan_views,
                         (void *)ios_scan_maxgap, (void *)ios_scan_tailgap,
                         ios_scan_stop_name( ios_scan_stop ),
                         ios_scan_fail_addr, ios_scan_fail_errno,
                         ios_scan_fail_errno ? strerror( ios_scan_fail_errno ) : "-", what,
                         ptr ? "" : (ceiling_relaxable ? "  --> relaxing ceiling, retrying unclamped"
                                                       : "  <-- STATUS_NO_MEMORY (callers see a NULL alloc)") );
                }
            }
#ifdef WINE_IOS
            if (!ptr) ios_fex_arena_census( start, end, size, align_mask );
            else ios_fex_arena_headroom( start, end );
#endif
            if (ptr)
            {
                TRACE( "got mem with map_free_area %p-%p\n", ptr, (char *)ptr + size );
                goto done;
            }
            /* madeira-bcd: the band below the 32-bit windows is full; use the
             * one above them before relaxing or failing (Ghost of Tsushima got
             * STATUS_NO_MEMORY for 1 MB with ~8 GB free above the placeholder
             * and stopped itself). */
            if (wow_hi_start && (size_t)((char *)wow_hi_end - (char *)wow_hi_start) >= view_size)
            {
                static unsigned long hi_n;

                ptr = map_reserved_area( wow_hi_start, wow_hi_end, host_size, top_down, unix_prot, align_mask );
                if (!ptr) ptr = map_free_area( wow_hi_start, wow_hi_end, host_size, top_down, unix_prot, align_mask );
                if (++hi_n <= 16 || !(hi_n % 256))
                    dprintf( 2, "[wow-window] #%lu band below the 32-bit windows full: 0x%lx bytes %s above them in %p..%p%s\n",
                             hi_n, (unsigned long)size, ptr ? "placed" : "NOT placed", wow_hi_start, wow_hi_end,
                             ptr ? "" : " (falling back as before)" );
                if (ptr) goto done;
            }
            /* ml117: THE CEILING IS ADVISORY, NEVER FATAL. It exists only to
             * bias Wine's furniture low so the top 16GB-aligned slots stay free
             * for PartitionAlloc; failing an allocation for it is strictly worse
             * than landing one view in a pool slot (worst case = 2 pools instead
             * of 3, versus a dead process). So when the clamped window cannot
             * satisfy the request, drop our own constraints and fall through to
             * the unclamped kernel pick below. Only constraints WE added are
             * dropped — a caller-supplied limit_high never sets
             * ceiling_relaxable, so its contract still holds. */
            if (!ceiling_relaxable)
            {
                ios_af_set( 2, ios_scan_fail_errno, ios_scan_fail_addr, size );
                return STATUS_NO_MEMORY;
            }
            start = address_space_start;
            end = min( user_space_limit, host_addr_space_limit );
            if (limit_low && (void *)limit_low > start) start = (void *)limit_low;
        }

        for (;;)
        {
            if ((ptr = anon_mmap_alloc( view_size, unix_prot )) == MAP_FAILED)
            {
                ios_af_set( 3, errno, NULL, view_size );
                status = (errno == ENOMEM) ? STATUS_NO_MEMORY : STATUS_INVALID_PARAMETER;
                ERR( "anon mmap error %s, size %p, unix_prot %#x\n",
                     strerror(errno), (void *)view_size, unix_prot );
                return status;
            }
            TRACE( "got mem with anon mmap %p-%p\n", ptr, (char *)ptr + size );
            /* ml132: keep spill out of the proven pool slots — see ios_spill_cap.
             * Bounded retries, then accept: never fail an allocation for this. */
            if (ios_spill_cap && spill_tries < 8 &&
                is_beyond_limit( ptr, view_size, (void *)ios_spill_cap ))
            {
                spill_tries++;
                ios_pool_va_warn( "munmap", ptr, view_size );
                munmap( ptr, view_size );
                continue;
            }
            /* if we got something beyond the user limit, unmap it and retry */
            if (!is_beyond_limit( ptr, view_size, user_space_limit )) break;
            unmap_size = unmap_area_above_user_limit( ptr, view_size );
            if (unmap_size) munmap( ptr, unmap_size );
        }
        ptr = unmap_extra_space( ptr, view_size, host_size, align_mask );
        if (stack_spill)
        {
            static unsigned long spill_n;

            if (++spill_n <= 16 || !(spill_n % 256))
                dprintf( 2, "[stack-spill] #%lu furniture band full: 0x%lx bytes with a 4 GB floor "
                            "placed at %p by the kernel's pick (MADEIRA_THREAD_STACK_SPILL)\n",
                         spill_n, (unsigned long)size, ptr );
        }
    }
done:
    status = create_view( view_ret, ptr, size, vprot );
    if (status != STATUS_SUCCESS) unmap_area( ptr, size );
    return status;
}


/* madeira-bcd swap-images (madeira.cfg or the game's own file `swap-images = 1`,
 * off by default; needs the swap tier, swap-mb, and env.MADEIRA_X64_IMAGE_NOCOPY = 1).
 *
 * A PE section is mmapped from its file only when its address and file offset
 * are 16 KB-aligned; an x64 PE has 4 KB sections at 512-byte file offsets, so
 * map_file_into_view_ex reads every section into ANONYMOUS memory, which
 * phys_footprint charges in full for the life of the image (compressed or not).
 * The 467 run (2026-10-09 13:09, line 38693) had libcef.dll's view at
 * 0x70d6b40000 228 MB dirty in two regions and both steamclient64.dll copies 22 MB
 * each; the pure-x64 images mapped before RDR2.exe (Steam's client, the
 * launcher, Social Club) add up to ~357 MB, and RDR2.exe and its DLLs ~160 MB.
 *
 * With the switch, a pure-x64 image (the same images VPROT_X64DATA marks: no
 * pool copy, the host never executes them) keeps being read exactly as before,
 * and afterwards each section's host-page interior moves to the swap tier's
 * file, whose dirty pages are "external" and not charged (ml1076):
 * map_file_into_view_ex notes the range (ios_swap_image_note, lock held),
 * virtual_map_image calls ios_swap_image_flush after leaving virtual_mutex, and
 * the copy into the file is a pwrite made outside the lock -- ml1081: nothing
 * that can block on the file may run while the lock is held. Edge host pages
 * shared with the header or a neighbouring section stay anonymous. EXEC and
 * WRITECOPY requests on such views no longer copy the range back
 * (set_protection): the host never executes them and every view is private. */
#define IOS_SWAP_IMAGE_PENDING 32
static _Thread_local int ios_swap_image_armed;     /* map_image_into_view's sections loop, for this image */
static _Thread_local unsigned ios_swap_image_npend;
static _Thread_local struct { char *va; size_t len; void *view_base; } ios_swap_image_pend[IOS_SWAP_IMAGE_PENDING];

/* Remember the host-page interior of [addr, addr+size), just read into the
 * anonymous memory of image view `view`. virtual_mutex held; no syscalls. */
static void ios_swap_image_note( const struct file_view *view, char *addr, size_t size )
{
    char *hs = (char *)(((uintptr_t)addr + host_page_mask) & ~(uintptr_t)host_page_mask);
    char *he = (char *)(((uintptr_t)addr + size) & ~(uintptr_t)host_page_mask);

    if (!ios_swap_image_armed || he <= hs || ios_swap_image_npend >= IOS_SWAP_IMAGE_PENDING) return;
    ios_swap_image_pend[ios_swap_image_npend].va = hs;
    ios_swap_image_pend[ios_swap_image_npend].len = he - hs;
    ios_swap_image_pend[ios_swap_image_npend].view_base = view->base;
    ios_swap_image_npend++;
}


/***********************************************************************
 *           map_file_into_view
 *
 * Wrapper for mmap() to map a file into a view, falling back to read if mmap fails.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_file_into_view_ex( struct file_view *view, int fd, size_t start, size_t size,
                                       off_t offset, unsigned int vprot, BOOL removable,
                                       BOOL for_image );

static NTSTATUS map_file_into_view( struct file_view *view, int fd, size_t start, size_t size,
                                    off_t offset, unsigned int vprot, BOOL removable )
{
    return map_file_into_view_ex( view, fd, start, size, offset, vprot, removable, TRUE );
}

/* ml561 (Sol's provenance recorder): remember HOW each file mapping was made.
 *
 * ml554 and ml559 both faulted at EXACTLY view_base+0x10000 — the 64KB Windows
 * allocation granularity — inside an 0x14000 region, with kr=10
 * (KERN_MEMORY_ERROR) on a page that was RW the whole time. Four 16KB pages
 * materialise; the fifth does not. The single most likely cause of "mapped, RW,
 * but cannot be materialised" is a file mapping that extends PAST END OF FILE:
 * POSIX gives SIGBUS for those pages, and Mach reports KERN_MEMORY_ERROR.
 *
 * Note map_size is rounded with the GUEST 4KB page_mask while iOS host pages are
 * 16KB, and nothing here compares offset+host_size against the file's real size.
 * This records the facts so the next fatal fault can say whether the backing
 * actually covered the view, instead of us guessing.
 *
 * Bounded, allocation-free, lock-free — safe to read from a signal handler.
 * Deliberately does NOT dup or retain the fd: doing so could accidentally repair
 * a lifetime bug and hide the very thing we are trying to see. */
#define IOS_MAP_RING 256
static struct {
    const char *base; size_t view_size, start, size, map_size, host_size;
    long long offset, file_size;
    unsigned long long dev, ino;
    int shared, for_image, valid;
} ios_map_ring[IOS_MAP_RING];
static volatile unsigned ios_map_ring_n;

static void ios_map_record( const void *view_base, size_t view_size, size_t start, size_t size,
                            size_t map_size, size_t host_size, int fd, long long offset,
                            int shared, int for_image )
{
    unsigned slot = __sync_fetch_and_add( &ios_map_ring_n, 1 ) % IOS_MAP_RING;
    struct stat st;
    ios_map_ring[slot].valid = 0;
    ios_map_ring[slot].base = (const char *)view_base;
    ios_map_ring[slot].view_size = view_size;
    ios_map_ring[slot].start = start;
    ios_map_ring[slot].size = size;
    ios_map_ring[slot].map_size = map_size;
    ios_map_ring[slot].host_size = host_size;
    ios_map_ring[slot].offset = offset;
    ios_map_ring[slot].shared = shared;
    ios_map_ring[slot].for_image = for_image;
    if (fd >= 0 && !fstat( fd, &st ))
    {
        ios_map_ring[slot].file_size = (long long)st.st_size;
        ios_map_ring[slot].dev = (unsigned long long)st.st_dev;
        ios_map_ring[slot].ino = (unsigned long long)st.st_ino;
    }
    else ios_map_ring[slot].file_size = -1;
    __sync_synchronize();
    ios_map_ring[slot].valid = 1;
}

/* Signal-handler-safe: describe the mapping containing `addr`, or say plainly
 * that no file mapping covers it (which is itself a real answer — it would mean
 * the page is anonymous and the EOF story is wrong). */
void ios_map_describe( const void *addr, char *out, size_t outlen )
{
    unsigned n = __sync_fetch_and_add( &ios_map_ring_n, 0 );
    unsigned lim = n < IOS_MAP_RING ? n : IOS_MAP_RING;
    const char *a = (const char *)addr;
    int best = -1;
    unsigned i;

    for (i = 0; i < lim; i++)
    {
        if (!ios_map_ring[i].valid) continue;
        if (a >= ios_map_ring[i].base + ios_map_ring[i].start &&
            a <  ios_map_ring[i].base + ios_map_ring[i].start + ios_map_ring[i].map_size)
            best = (int)i;                     /* later records win */
    }
    if (best < 0)
    {
        snprintf( out, outlen, "NO file mapping covers this address "
                               "(anonymous — EOF/backing story does NOT apply)" );
        return;
    }
    {
        long long end_needed = ios_map_ring[best].offset + (long long)ios_map_ring[best].host_size;
        snprintf( out, outlen,
                  "view=%p+0x%zx start=0x%zx size=0x%zx map=0x%zx host=0x%zx off=0x%llx "
                  "%s %s file_size=0x%llx dev=%llu ino=%llu need_off_end=0x%llx %s",
                  (void *)ios_map_ring[best].base, ios_map_ring[best].view_size,
                  ios_map_ring[best].start, ios_map_ring[best].size,
                  ios_map_ring[best].map_size, ios_map_ring[best].host_size,
                  ios_map_ring[best].offset,
                  ios_map_ring[best].shared ? "MAP_SHARED" : "MAP_PRIVATE",
                  ios_map_ring[best].for_image ? "image" : "section",
                  ios_map_ring[best].file_size, ios_map_ring[best].dev, ios_map_ring[best].ino,
                  end_needed,
                  ios_map_ring[best].file_size >= 0 && end_needed > ios_map_ring[best].file_size
                    ? "<== MAPPING EXTENDS PAST END OF FILE — unbacked tail, this is the bug"
                    : "<== backing covers the mapping; EOF is NOT the explanation" );
    }
}

static NTSTATUS map_file_into_view_ex( struct file_view *view, int fd, size_t start, size_t size,
                                       off_t offset, unsigned int vprot, BOOL removable,
                                       BOOL for_image )
{
    char *map_addr, *host_addr;
    size_t map_size, host_size;
    int prot = PROT_READ | PROT_WRITE;
    unsigned int flags = MAP_FIXED;

    assert( start < view->size );
    assert( start + size <= view->size );

    if (vprot & VPROT_WRITE) flags |= MAP_SHARED;
    else if (vprot & VPROT_WRITECOPY) flags |= MAP_PRIVATE;
    else
    {
        /* changes to the file are not guaranteed to be visible in read-only MAP_PRIVATE mappings,
         * but they are on Linux so we take advantage of it */
#if defined(__linux__) || defined(WINE_IOS)
        /* iOS: PE-image read-only sections need MAP_PRIVATE so Wine's PE
         * loader can mprotect them writable temporarily for IAT writes
         * (MAP_SHARED rejects mprotect upgrades with EINVAL on iOS). The
         * `for_image` parameter distinguishes those callers from
         * SEC_COMMIT shared sections (e.g. \KernelObjects\__wine_session)
         * which MUST be MAP_SHARED so the client sees server writes. */
        if (for_image)
            flags |= MAP_PRIVATE;  /* PE image — Wine's PE loader needs mprotect-upgrades */
        else
        {
            flags |= MAP_SHARED;   /* shared section — coherent with wineserver */
            prot &= ~PROT_WRITE;
        }
#else
        flags |= MAP_SHARED;
        prot &= ~PROT_WRITE;
#endif
    }

    map_size = ROUND_SIZE( start, size, page_mask );
    map_addr = ROUND_ADDR( (char *)view->base + start, page_mask );
    host_addr = ROUND_ADDR( (char *)view->base + start, host_page_mask );
    /* last page doesn't need to be a full page */
    if (map_addr + map_size >= (char *)view->base + view->size) host_size = map_size;
    else host_size = ROUND_SIZE( 0, map_size, host_page_mask );

    /* only try mmap if media is not removable (or if we require write access),
       and if alignment is correct */
    if ((!removable || (flags & MAP_SHARED)) && host_addr == map_addr && host_size == map_size)
    {
        /* iOS-Madeira ml563: THE DIRECT INVARIANT — check the backing BEFORE mapping.
         *
         * ml561 proved the Steam/CEF killer: a 0x40000 section view mmap'd over a
         * backing file of only 0x10000/0x20000 bytes. Every page past EOF is
         * unbacked, so Skia's 256x256 tile fill SIGBUSes the moment it crosses that
         * offset — fault offset == file size, exactly, 3/3 events, with the guest's
         * geometry provably correct.
         *
         * This check is synchronous and unconditional at the exact mmap: no ring
         * lookup, no address reuse, no wrap, no signal-handler inference, and the
         * file size is read at the moment it matters.
         *
         * REPAIR, carefully: growing a real on-disk file would corrupt user data
         * (a game asset, a save). wineserver unlinks anonymous section temp files
         * immediately after creating them, so `st_nlink == 0` identifies exactly
         * those — a pagefile-backed section, which Windows guarantees is fully
         * backed for its whole size. Growing THAT restores correct semantics rather
         * than papering over anything. Anything with a link count stays untouched
         * and is reported instead. */
        {
            struct stat mst;
            /* ml564: flag only when a WHOLE host page lies past EOF.
             *
             * ml563's predicate (`offset+host_size > st_size`) fired on every file
             * whose size is not page-aligned — 64/64 events were benign tails like
             * file_size=0xc2122 need=0xc3000, and they consumed the entire budget.
             * POSIX makes the final PARTIAL page of a mapping accessible and
             * zero-filled; only pages lying entirely beyond EOF fault. That is the
             * shape ml561 caught (file 0x10000, need 0x40000 — twelve whole pages
             * past the end), and it is the only shape worth a log line. */
            /* ml570: mst was READ BEFORE fstat FILLED IT here — an uninitialized
             * read (the value was recomputed afterwards, so the effect was benign,
             * but it was undefined behaviour and is fixed). */
            off_t eof_pages = 0;
            if (!fstat( fd, &mst ) &&
                (eof_pages = (((off_t)mst.st_size + (off_t)host_page_mask) & ~(off_t)host_page_mask),
                 eof_pages < (off_t)(offset + (off_t)host_size)))
            {
                static unsigned long eofn;
                int anon_section = (mst.st_nlink == 0) && (flags & MAP_SHARED) && !for_image;
                /* ml570: STOP GROWING THE FILE. The ml564 repair assumed the fd
                 * belonged to this section and was merely undersized. It probably
                 * does NOT: the iOS fd cache is `_Thread_local` while Windows
                 * handles are per-PROCESS, so a handle closed by one thread stays
                 * cached in another, and after wineserver recycles the numeric
                 * handle that thread maps the OLD inode. st_nlink==0 proves only
                 * "unlinked", never "the right object" — so ftruncate here extends
                 * an unrelated section and corrupts it, on top of hiding the
                 * identity bug. Report, do not mutate. */
                int repaired = -1;
                if (++eofn <= 64)
                    dprintf(2, "[map-eof] view=%p+0x%zx start=0x%zx size=0x%zx map=0x%zx "
                               "host=0x%zx off=0x%llx file_size=0x%llx need=0x%llx nlink=%u "
                               "dev=%llu ino=%llu %s %s -- %s wholepage rev=ml564\n",
                            view->base, view->size, start, size, map_size, host_size,
                            (unsigned long long)offset, (unsigned long long)mst.st_size,
                            (unsigned long long)(offset + (off_t)host_size),
                            (unsigned)mst.st_nlink,
                            (unsigned long long)mst.st_dev, (unsigned long long)mst.st_ino,
                            (flags & MAP_SHARED) ? "MAP_SHARED" : "MAP_PRIVATE",
                            for_image ? "image" : "section",
                            anon_section ? "SHORT anon section — NOT repairing (fd identity unproven; suspect stale _Thread_local fd cache)"
                            : "SHORT mapping with links — reporting only");
            }
        }
        if (mmap( host_addr, host_size, prot, flags, fd, offset ) != MAP_FAILED)
        {
            ios_map_record( view->base, view->size, start, size, map_size, host_size,
                            fd, (long long)offset, (flags & MAP_SHARED) != 0, for_image );
            return STATUS_SUCCESS;
        }

        switch (errno)
        {
        case EINVAL:  /* file offset is not page-aligned, fall back to read() */
            break;
        case ENOEXEC:
        case ENODEV:  /* filesystem doesn't support mmap(), fall back to read() */
            if (vprot & VPROT_WRITE)
            {
                ERR( "shared writable mmap not supported, broken filesystem?\n" );
                return STATUS_NOT_SUPPORTED;
            }
            break;
        case EACCES:
        case EPERM:  /* access error, fall back to read() */
            if (vprot & VPROT_WRITE)
            {
                dprintf(2, "[vmem-denied] shared-writable mmap EACCES/EPERM: addr=%p size=%p\n",
                        map_addr, (void *)map_size);
                return STATUS_ACCESS_DENIED;
            }
            break;
        default:
            ERR( "mmap error %s, range %p-%p, unix_prot %#x\n",
                 strerror(errno), map_addr, map_addr + map_size, prot );
            return STATUS_NO_MEMORY;
        }
    }

    if (vprot & VPROT_WRITE)
    {
        ERR( "unaligned shared mapping %p-%p not supported\n", map_addr, map_addr + map_size );
        return STATUS_INVALID_PARAMETER;
    }

    mprotect( map_addr, map_size, PROT_READ | PROT_WRITE );
    pread( fd, map_addr, size, offset );
#ifdef WINE_IOS
    if (for_image) ios_swap_image_note( view, map_addr, map_size );   /* madeira-bcd swap-images (off: a no-op) */
#endif
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           get_committed_size
 *
 * Get the size of the committed range with equal masked vprot bytes starting at base.
 * Also return the protections for the first page.
 */
static SIZE_T get_committed_size( struct file_view *view, void *base, size_t max_size, BYTE *vprot, BYTE vprot_mask )
{
    SIZE_T offset, size;

    base = ROUND_ADDR( base, page_mask );
    offset = (char *)base - (char *)view->base;

    if (view->protect & SEC_RESERVE)
    {
        size = 0;

        *vprot = get_page_vprot( base );

        SERVER_START_REQ( get_mapping_committed_range )
        {
            req->base   = wine_server_client_ptr( view->base );
            req->offset = offset;
            if (!wine_server_call( req ))
            {
                size = min( reply->size, max_size );
                if (reply->committed)
                {
                    *vprot |= VPROT_COMMITTED;
                    set_page_vprot_bits( base, size, VPROT_COMMITTED, 0 );
                }
            }
        }
        SERVER_END_REQ;

        if (!size || !(vprot_mask & ~VPROT_COMMITTED)) return size;
    }
    else size = min( view->size - offset, max_size );

    return get_vprot_range_size( base, size, vprot_mask, vprot );
}


/***********************************************************************
 *           decommit_pages
 *
 * Decommit some pages of a given view.
 * virtual_mutex must be held by caller.
 */
/* task #34 tripwire (ml92/ml94): does [rw_start, rw_start+size) intersect a
 * LIVE pool ledger range? The ledger tracks head allocations — loaded DLL
 * copies — while legitimate anon-alias decommits target FEX CodeBuffers carved
 * from the pool TAIL, which are not ledgered. So an overlap here is never
 * legitimate: it means the alias is stale (its range was freed and recycled to
 * a different module) and zeroing through it would blank live code. Returns the
 * offending ledger entry so the log can name the victim. */
static int ios_pool_live_overlap( uintptr_t rw_start, size_t size,
                                  size_t *off_out, void **peb_out )
{
    uintptr_t rw_base = (uintptr_t)ios_jit_rw_base_global;
    size_t s, e;
    int j;

    if (!rw_base || rw_start < rw_base) return 0;
    s = rw_start - rw_base;
    if (s >= ios_jit_pool_size_global) return 0;
    e = s + size;

    for (j = 0; j < ios_pool_ledger_count; j++)
    {
        size_t l_off = ios_pool_ledger[j].off;
        size_t l_end = l_off + ios_pool_ledger[j].size;
        if (l_off < e && l_end > s)
        {
            if (off_out) *off_out = l_off;
            if (peb_out) *peb_out = ios_pool_ledger[j].peb;
            return 1;
        }
    }
    return 0;
}

/* iOS-Madeira ml610 [dc-census]: HOW MUCH DOES A DECOMMIT ACTUALLY RETURN?
 *
 * Three builds have now argued about this from the memory curve instead of
 * measuring it. ml608 assumed the full 16MB callret clear was WASTING memory;
 * ml609 shrank it to 4MB and got ~388MB WORSE; the source then showed the clear
 * is a reclaim (anon_mmap_fixed drops the physical pages), so the shrink had
 * stranded the remainder. None of that is a measurement of bytes returned.
 *
 * This is. It runs at the reclaim site itself, which is also the only place the
 * Mach APIs are reachable — FEX's ResetCallRetStack() lives in an arm64ec PE
 * built by llvm-mingw, where __APPLE__ is undefined and mincore/mach_vm_region/
 * task_info do not exist.
 *
 * Two independent instruments, because they fail differently:
 *   - mincore() is EXACT for the byte range but only reports residency.
 *   - the Mach region walk reports dirty + swapped-out (i.e. compressed, which
 *     STILL counts toward the 4096MB jetsam limit — the thing mincore cannot
 *     see) but is REGION-granular, so it can over-count when a region extends
 *     past the range. `span` is logged so that over-count is visible rather
 *     than silent: span >> size means the counts include a neighbour.
 * phys_footprint is sampled too, and will contain unrelated noise from other
 * threads — it is a sanity check on the other two, not the primary number.
 */
struct ios_dc_census
{
    unsigned long long resident, dirty, swapped, span, mincore_res, footprint;
};

static void ios_dc_census_take( const void *addr, size_t len, struct ios_dc_census *out )
{
    mach_vm_address_t start = (mach_vm_address_t)(uintptr_t)addr;
    mach_vm_address_t end = start + len;
    mach_vm_address_t ra = start;
    natural_t depth = 0;
    int guard = 0;

    memset( out, 0, sizeof(*out) );

    while (ra < end && guard++ < 4096)
    {
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t icnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        mach_vm_size_t rs = 0;
        if (mach_vm_region_recurse( mach_task_self(), &ra, &rs, &depth,
                                    (vm_region_recurse_info_t)&info, &icnt ) != KERN_SUCCESS) break;
        if (ra >= end) break;
        if (info.is_submap) { depth++; continue; }
        out->resident += (unsigned long long)info.pages_resident    << 14;
        out->dirty    += (unsigned long long)info.pages_dirtied     << 14;
        out->swapped  += (unsigned long long)info.pages_swapped_out << 14;
        out->span     += (unsigned long long)rs;
        ra += rs;
        depth = 0;
    }

    {
        /* Stack-local so concurrent samples cannot corrupt each other's count.
         * 1024 entries covers 16MB at 16KB pages — exactly the callret stack. */
        char vec[1024];
        size_t ps = (size_t)host_page_mask + 1;
        size_t npages = ps ? len / ps : 0;
        if (npages && npages <= sizeof(vec) && !mincore( (void *)(uintptr_t)start, len, vec ))
        {
            size_t i;
            for (i = 0; i < npages; i++)
                if (vec[i] & MINCORE_INCORE) out->mincore_res += ps;
        }
    }

    {
        task_vm_info_data_t vmi;
        mach_msg_type_number_t c = TASK_VM_INFO_COUNT;
        if (task_info( mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &c ) == KERN_SUCCESS)
            out->footprint = (unsigned long long)vmi.phys_footprint;
    }
}

/* ---------------------------------------------------------------------------
 * ml1077: FILE-BACKED GUEST DATA TIER ("userspace swap").
 *
 * iOS has no anonymous swap: a process is killed at its footprint limit
 * (8192 MiB here) and RDR2's story mode grows past it. But iOS does write dirty
 * pages of a MAP_SHARED file mapping back to their file and evicts them, and
 * such pages are "external" -- phys_footprint, the number jetsam kills on, does
 * not charge them. Measured in-app on the phone (ml1076 canary): 512 MB written
 * through a shared mapping of an unlinked temp file -> footprint +2 MB, data
 * verified, F_PUNCHHOLE reads back zero and frees the pages.
 *
 * So: large, writable, non-executable guest commits in the guest band get their
 * 16 KB-aligned interior mapped MAP_SHARED from one sparse backing file (created
 * by the app with no file protection, path in MADEIRA_SWAP_FILE, cap in
 * MADEIRA_SWAP_MB). Decommit and release punch the file extent (zero on
 * recommit holds because a hole reads as zero); a later request for EXEC on a
 * backed range copies it back to anonymous memory first. Everything else --
 * JIT/FEX bands, images, sections, watch/guard/copy-on-write pages, sub-page
 * edges -- stays exactly as before. Opt-in; absent env => no-op.
 * Extent bookkeeping runs under virtual_mutex like the callers. */
#include <fcntl.h>
/* swap-tier core begin (tests/host/check-swap-coverage.py compiles the code up to "core end") */
static int      ios_swap_fd = -1;
static uint64_t ios_swap_cap, ios_swap_bump;
/* resv: the extent maps a whole reservation (wide at reserve time, broad), so a
 * decommit inside it punches the file in place (ml1257). key: the size asked for
 * (reservation or commit), the churn filter's unit; born: ns when it was backed
 * (ml1258). img: an image section's (madeira-bcd swap-images, ios_swap_image_map). */
static struct { char *va; size_t len; uint64_t off; int resv; size_t key; uint64_t born; int img; } ios_swap_ext[16384];
static unsigned ios_swap_n;
static struct { uint64_t off, len; } ios_swap_free[8192];
static unsigned ios_swap_nfree;
/* ml1297: ranges whose punch failed. They are never returned to the free list: a
 * later backing must read zero, and such a range may still hold its old
 * data. The offset space is lost, the disk blocks stay in use. */
static unsigned long long ios_swap_punch_leaks;
static unsigned long long ios_swap_bytes, ios_swap_peak, ios_swap_backs, ios_swap_releases, ios_swap_unbacks, ios_swap_refused;
/* madeira-bcd swap-images: image sections in the file now / at most, sections backed, refused */
static unsigned long long ios_swap_img_bytes, ios_swap_img_peak, ios_swap_img_backs, ios_swap_img_refused;

/* COVERAGE, FREE-SPACE REUSE AND A LOW-VOLUME CENSUS (only while the tier is on).
 *
 * With the rules above (one commit request of at least 8 MB, in the
 * 0x70..0x7c band) a 64-bit title that was killed at its footprint limit with
 * a 2 GB and a 4 GB tier had backed almost nothing: ~200 MB at peak, the cap
 * never approached. Its growth arrived as 1-4.5 MB MEM_RESERVE|MEM_COMMIT
 * blocks (every Wine heap block above ~508 KB is its own reserve+commit) and
 * as heaps committing 64 KB at a time. MADEIRA_SWAP_COVERAGE (madeira.cfg
 * env.MADEIRA_SWAP_COVERAGE) picks the rules; when it is unset, madeira.cfg
 * swap-mode = 2 means broad and anything else classic:
 *  - classic (default): the ml1077 rules, see below.
 *  - blocks: a commit request of at least 1 MB is enough.
 *    MADEIRA_SWAP_MIN_KB=N sets that floor (64 KB .. 4 GB).
 *  - wide: blocks, plus any writable Wine private view outside the band
 *    (allocations that spill past it once it is full), plus fresh writable
 *    reservations up to MADEIRA_SWAP_RESERVE_MAX_MB (default 256) mapped from
 *    the file PROT_NONE at reserve time, so that a heap committing 64 KB at a
 *    time commits file pages (a hole reads as zero).
 *  - broad (ml1257, device-verified: Metro 2033 Redux 3.3 -> 2.7 GB footprint):
 *    every fresh reservation of at least the floor (default 4 MB) up to 8 GB
 *    (MADEIRA_SWAP_RESERVE_MAX_MB, at most 16 GB: madeira-bcd) is
 *    backed WHOLE when it is made, committed or not (PROT_NONE where not), so
 *    every later commit inside it -- any size -- is an mprotect of file pages.
 *    Red Dead Redemption 2 reserves big and commits in small pieces; Metro 2033 Redux's heap never reaches
 *    the guest band at all. Commits of at least the floor elsewhere are backed
 *    too. Any address below FEX's band [0x7c, 0x80) except the JIT pool and the
 *    FEX arena. The file is a 128 GB sparse offset space and swap-mb caps the
 *    DISK it occupies (st_blocks), checked before each new backing. The cap is
 *    soft: dirty pages not yet written back are not in st_blocks, and a
 *    reservation backed before the cap was reached goes on committing.
 *    ml1258 churn filter (rule of ml1226): a size whose backed blocks die
 *    within 3 s of backing at least 8 times, and in at least half of its
 *    backings, stays anonymous from then on (Metro 2033 Redux reserved and freed 4 and
 *    16 MB blocks ~9 times a second: 1834 backings against ~170 lasting ones,
 *    every touched page a file fault and every free a 4-16 MB F_PUNCHHOLE).
 *  - classic (the default, spelled out): a single commit of at least 8 MB in the
 *    guest band, exactly as ml1077, including the plain free list and no census.
 *    madeira.cfg swap-min-mb = N moves that floor (ml1257).
 * madeira.cfg swap-min-mb also sets the floor of blocks, wide and broad unless
 * MADEIRA_SWAP_MIN_KB does. A decommit wholly inside a reservation extent (wide
 * or broad) punches the file range in place instead of replacing it with
 * anonymous memory, so the backing survives decommit/recommit (ml1257).
 * blocks, wide and broad never back the FEX arena, the JIT pool, placeholders or
 * ARM64EC views, return freed file ranges merged with their free neighbours
 * (a range ending at the bump pointer lowers it), and print a [swap] census
 * line at most every 30 s while anything changed: file-backed now/peak, file
 * offset use, the bytes of every commit request by the reason it was or was
 * not backed, and phys_footprint. The line is built in a stack buffer and
 * written with write(2); nothing here allocates. */
enum { IOS_SW_BACKED, IOS_SW_SMALL, IOS_SW_BAND, IOS_SW_FEXJIT, IOS_SW_PROT, IOS_SW_VIEW,
       IOS_SW_RECOMMIT, IOS_SW_PRESENT, IOS_SW_REFUSED, IOS_SW_MAPFAIL, IOS_SW_CHURN, IOS_SW_REASONS };
static const char * const ios_swap_reason_name[IOS_SW_REASONS] =
    { "backed", "small", "band", "fex/jit", "prot", "view", "recommit", "present", "refused", "mapfail", "churn" };
static int         ios_swap_v2;               /* blocks, wide or broad; 0 = classic */
static int         ios_swap_wide;
static int         ios_swap_broad;            /* ml1257 */
static size_t      ios_swap_min = 8u << 20;
static size_t      ios_swap_resv_max = 256u << 20;
static const char *ios_swap_mode = "classic";
static uint64_t    ios_swap_logical;          /* file offset space: the cap, or 128 GB sparse in broad */
static unsigned long long ios_swap_why_bytes[IOS_SW_REASONS];
static unsigned long long ios_swap_resv_bytes, ios_swap_resv_n, ios_swap_merges, ios_swap_bump_back, ios_swap_free_drop;
static unsigned long long ios_swap_holes, ios_swap_disk_refused, ios_swap_churn_skips;   /* ml1257 / ml1258 */
#define IOS_SWAP_CHURN_NS (3ull * 1000000000ull)
/* ml1226: hits = young deaths, backs = backings of the size; see ios_swap_churny */
static struct { size_t size; unsigned hits; unsigned backs; } ios_swap_churn[64];
static unsigned ios_swap_nchurn;    /* sizes tracked */
static unsigned ios_swap_nchurny;   /* sizes left anonymous */
#define IOS_SWAP_CHURN_MIN_YOUNG 8
/* ml1221: broad, the bytes of fresh reservations NOT taken whole, by reason (the
 * commit and reserve rules may still back parts of them). In the census. */
enum { IOS_SWK_PROT, IOS_SWK_VIEW, IOS_SWK_SMALL, IOS_SWK_BIG, IOS_SWK_FEXJIT, IOS_SWK_OVERLAP, IOS_SWK_CHURN, IOS_SWK_REASONS };
static const char * const ios_swap_skip_name[IOS_SWK_REASONS] =
    { "prot", "view", "small", "big", "fex/jit/band", "overlap", "churn" };
static unsigned long long ios_swap_skip_bytes[IOS_SWK_REASONS];
static void ios_swap_tick( int force );
static unsigned long long ios_swap_footprint_mb( void );   /* after the core: Mach */
static unsigned long long ios_swap_disk_used( void );      /* after the core: fstat of the file (ml1257) */
static void ios_swap_cfg( int *mode, int *min_mb );        /* after the core: madeira.cfg swap-mode / swap-min-mb */

static size_t ios_swap_env_size( const char *name, size_t def, unsigned shift, size_t lo, size_t hi )
{
    const char *e = getenv( name );
    unsigned long long v;
    if (!e || !*e) return def;
    v = strtoull( e, NULL, 10 );
    if (v > (hi >> shift)) return hi;
    v <<= shift;
    return v < lo ? lo : (size_t)v;
}

static void ios_swap_config( void )
{
    const char *cov = getenv( "MADEIRA_SWAP_COVERAGE" );
    int cfg_mode = 1, cfg_min_mb = 0;
    size_t cfg_min;
    char c;
    ios_swap_cfg( &cfg_mode, &cfg_min_mb );
    cfg_min = cfg_min_mb > 0 ? (size_t)cfg_min_mb << 20 : 0;
    ios_swap_v2 = 0; ios_swap_wide = 0; ios_swap_broad = 0; ios_swap_min = 8u << 20; ios_swap_mode = "classic";
    ios_swap_resv_max = 256u << 20;
    /* the env names the coverage when set; otherwise madeira.cfg swap-mode = 2
     * (ml1257) means broad. classic is the default: the wider modes back far more
     * of a game's memory with the file, and a game can run slower for it, so
     * they are opt-in. Any other value also means classic. */
    if (cov && *cov) c = (char)(cov[0] | 0x20);
    else c = cfg_mode >= 2 ? 'r' : 'c';
    if (c == 'b' && cov && cov[1] && (cov[1] | 0x20) == 'r') c = 'r';   /* "broad", not "blocks" */
    if (c != 'b' && c != 'w' && c != 'r')
    {
        if (cfg_min) ios_swap_min = cfg_min;   /* ml1257: swap-min-mb applies to classic too */
        return;
    }
    ios_swap_v2 = 1;
    ios_swap_wide = c == 'w';
    ios_swap_broad = c == 'r';
    ios_swap_mode = ios_swap_broad ? "broad" : ios_swap_wide ? "wide" : "blocks";
    ios_swap_min = ios_swap_env_size( "MADEIRA_SWAP_MIN_KB", cfg_min ? cfg_min : ios_swap_broad ? 4u << 20 : 1u << 20,
                                      10, 64u << 10, (size_t)1 << 32 );
    /* madeira-bcd: broad takes up to 16 GB when the env asks, so that RDR2.exe's
     * 8960 MB heap (env.MADEIRA_RDR2_VA_HOLD's hold) can be backed whole with
     * MADEIRA_SWAP_RESERVE_MAX_MB = 9216; unset it stays 8 GB. */
    if (ios_swap_broad)
        ios_swap_resv_max = ios_swap_env_size( "MADEIRA_SWAP_RESERVE_MAX_MB", (size_t)8 << 30, 20, 1u << 20, (size_t)16 << 30 );
    else
        ios_swap_resv_max = ios_swap_env_size( "MADEIRA_SWAP_RESERVE_MAX_MB", 256u << 20, 20, 1u << 20, (size_t)1 << 32 );
}

static void ios_swap_init( void )
{
    static int done;
    const char *f, *mb;
    if (done) return;
    done = 1;
    f = getenv( "MADEIRA_SWAP_FILE" ); mb = getenv( "MADEIRA_SWAP_MB" );
    if (!f || !*f || !mb) return;
    ios_swap_cap = (uint64_t)strtoull( mb, NULL, 10 ) << 20;
    if (ios_swap_cap < (64ull << 20)) return;
    ios_swap_fd = open( f, O_RDWR | O_CLOEXEC );
    if (ios_swap_fd < 0) { dprintf( 2, "[swap] ml1077 cannot open %s (errno %d): tier OFF\n", f, errno ); return; }
    ios_swap_config();
    ios_swap_logical = ios_swap_cap;
    if (ios_swap_broad && ios_swap_logical < (128ull << 30))
    {
        /* ml1257: sparse, so the size costs nothing; whole reservations draw on it */
        if (!ftruncate( ios_swap_fd, (off_t)(128ull << 30) )) ios_swap_logical = 128ull << 30;
        else dprintf( 2, "[swap] ml1257 cannot size the sparse file to 128 GB (errno %d): offset space = cap\n", errno );
    }
    if (ios_swap_logical == ios_swap_cap && ftruncate( ios_swap_fd, (off_t)ios_swap_cap )) { dprintf( 2, "[swap] ml1077 ftruncate failed (errno %d): tier OFF\n", errno ); close( ios_swap_fd ); ios_swap_fd = -1; return; }
    dprintf( 2, "[swap] ml1077 file-backed guest data tier ON: %s, cap %llu MB\n", f, (unsigned long long)(ios_swap_cap >> 20) );
    if (ios_swap_v2)
        dprintf( 2, "[swap] coverage=%s min=%zuKB reserve-max=%zuMB (MADEIRA_SWAP_COVERAGE=classic|blocks|wide|broad, "
                    "MADEIRA_SWAP_MIN_KB, MADEIRA_SWAP_RESERVE_MAX_MB; madeira.cfg swap-mode, swap-min-mb)%s\n",
                 ios_swap_mode, ios_swap_min >> 10, ios_swap_resv_max >> 20,
                 ios_swap_broad ? " -- ml1257 broad: whole reservations below FEX, holes on decommit, swap-mb caps the disk" : "" );
    else
        dprintf( 2, "[swap] coverage=classic: %zu MB commits in the guest band, no census\n", ios_swap_min >> 20 );
}
static uint64_t ios_swap_take( size_t len )
{
    unsigned i, best = ~0u;
    for (i = 0; i < ios_swap_nfree; i++)
        if (ios_swap_free[i].len >= len && (best == ~0u || ios_swap_free[i].len < ios_swap_free[best].len)) best = i;
    if (best != ~0u)
    {
        uint64_t off = ios_swap_free[best].off;
        if (ios_swap_free[best].len > len) { ios_swap_free[best].off += len; ios_swap_free[best].len -= len; }
        else ios_swap_free[best] = ios_swap_free[--ios_swap_nfree];
        return off;
    }
    if (ios_swap_bump + len > ios_swap_logical) return (uint64_t)-1;
    ios_swap_bump += len;
    return ios_swap_bump - len;
}
/* Return a file range to the free list. blocks/wide/broad: merged with the free
 * ranges it touches, and a range ending at the bump pointer lowers it. */
static void ios_swap_free_add( uint64_t off, uint64_t len )
{
    unsigned i;
    int merged = 1;
    if (!ios_swap_v2)
    {
        if (ios_swap_nfree < 8192) { ios_swap_free[ios_swap_nfree].off = off; ios_swap_free[ios_swap_nfree].len = len; ios_swap_nfree++; }
        return;
    }
    while (merged)
    {
        merged = 0;
        for (i = 0; i < ios_swap_nfree; i++)
        {
            if (ios_swap_free[i].off + ios_swap_free[i].len == off) off = ios_swap_free[i].off;
            else if (off + len != ios_swap_free[i].off) continue;
            len += ios_swap_free[i].len;
            ios_swap_free[i] = ios_swap_free[--ios_swap_nfree];
            ios_swap_merges++;
            merged = 1;
            break;
        }
    }
    if (off + len == ios_swap_bump) { ios_swap_bump = off; ios_swap_bump_back++; return; }
    if (ios_swap_nfree < 8192) { ios_swap_free[ios_swap_nfree].off = off; ios_swap_free[ios_swap_nfree].len = len; ios_swap_nfree++; }
    else ios_swap_free_drop++;   /* leaked offset space: later backings may be refused, never wrong */
}
static int ios_swap_punch_defer( uint64_t off, size_t len );   /* ml1291, below */
static void ios_swap_give( uint64_t off, size_t len )
{
    struct fpunchhole ph;
    if (ios_swap_punch_defer( off, len )) return;   /* ml1291: punched and freed off the virtual lock */
    memset( &ph, 0, sizeof(ph) );
    ph.fp_offset = (off_t)off; ph.fp_length = (off_t)len;
    if (fcntl( ios_swap_fd, F_PUNCHHOLE, &ph ))
    {
        static int said;
        if (said++ < 8) dprintf( 2, "[swap] ml1077 F_PUNCHHOLE off=%llu len=%zu failed errno=%d (range not reused, ml1297)\n", (unsigned long long)off, len, errno );
        ios_swap_punch_leaks++;
        return;
    }
    ios_swap_free_add( off, len );
}
static uint64_t ios_swap_now_ns( void )
{
    struct timespec ts;
#ifdef CLOCK_UPTIME_RAW
    clock_gettime( CLOCK_UPTIME_RAW, &ts );   /* ml1258: what the filter was measured with */
#else
    clock_gettime( CLOCK_MONOTONIC, &ts );
#endif
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* ml1291: the swap file's F_PUNCHHOLE off the virtual lock.
 *
 * Ori and the Will of the Wisps, 2026-10-07: two freezes of 18 s and 13 s with
 * every game thread idle, the main thread in fcntl() in both thread samples, a
 * job worker waiting on a mutex, the swap file's disk use growing meanwhile, and
 * each freeze ending exactly when the tier's release counter went up. A release
 * (ios_swap_release_range, a failed map) gives the file range back with
 * F_PUNCHHOLE, and APFS can hold that call for seconds behind the file's
 * writeback; it ran under virtual_mutex, so every thread that allocates, frees,
 * protects or faults through Wine waited for it.
 *
 * A given-back range is mapped by nothing any more (its view was replaced by
 * anonymous memory or is being unmapped), so the punch itself needs no lock.
 * ios_swap_give now queues it; a host thread punches it and only then, under
 * virtual_mutex, returns the range to the free list, so it cannot be handed to a
 * new backing before it reads as zero. A full queue or a thread that could not
 * start falls back to the synchronous punch. MADEIRA_SWAP_PUNCH_DEFER=0 keeps
 * every punch synchronous. Punches of 100 ms or more are logged, the in-place
 * decommit punch (ios_swap_punch_resv, still synchronous) included. */
#define IOS_SWAP_PQ 1024
static struct { uint64_t off, len; } ios_swap_pq[IOS_SWAP_PQ];
static unsigned ios_swap_pq_head, ios_swap_pq_n;
static pthread_mutex_t ios_swap_pq_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ios_swap_pq_cond = PTHREAD_COND_INITIALIZER;
static int ios_swap_pq_state;   /* 0 not started, 1 running, -1 off */
static unsigned long long ios_swap_pq_done, ios_swap_punch_slow, ios_swap_punch_max_ms;

static int ios_swap_punch_timed( uint64_t off, uint64_t len, const char *why )
{
    struct fpunchhole ph;
    uint64_t t0 = ios_swap_now_ns(), ms;
    int rc;
    memset( &ph, 0, sizeof(ph) );
    ph.fp_offset = (off_t)off; ph.fp_length = (off_t)len;
    if ((rc = fcntl( ios_swap_fd, F_PUNCHHOLE, &ph )))
    {
        static int said;
        if (said++ < 8) dprintf( 2, "[swap] ml1291 F_PUNCHHOLE (%s) off=%llu len=%llu failed errno=%d\n",
                                 why, (unsigned long long)off, (unsigned long long)len, errno );
    }
    ms = (ios_swap_now_ns() - t0) / 1000000;
    if (ms > ios_swap_punch_max_ms) ios_swap_punch_max_ms = ms;
    if (ms >= 100 && (++ios_swap_punch_slow <= 16 || (ios_swap_punch_slow % 64) == 0))
        dprintf( 2, "[swap] ml1291 F_PUNCHHOLE (%s) off=%llu len=%llu took %llu ms (%llu slow, max %llu ms)\n",
                 why, (unsigned long long)off, (unsigned long long)len, (unsigned long long)ms,
                 ios_swap_punch_slow, ios_swap_punch_max_ms );
    return rc;
}

static void *ios_swap_punch_thread( void *arg )
{
    sigset_t all;
    sigfillset( &all );
    pthread_sigmask( SIG_BLOCK, &all, NULL );
    pthread_setname_np( "madeira-swap-punch" );
    for (;;)
    {
        uint64_t off, len;
        int rc;
        pthread_mutex_lock( &ios_swap_pq_lock );
        while (!ios_swap_pq_n) pthread_cond_wait( &ios_swap_pq_cond, &ios_swap_pq_lock );
        off = ios_swap_pq[ios_swap_pq_head].off;
        len = ios_swap_pq[ios_swap_pq_head].len;
        ios_swap_pq_head = (ios_swap_pq_head + 1) % IOS_SWAP_PQ;
        ios_swap_pq_n--;
        pthread_mutex_unlock( &ios_swap_pq_lock );

        rc = ios_swap_punch_timed( off, len, "deferred" );

        pthread_mutex_lock( &virtual_mutex );   /* the free list and the bump live under it */
        if (rc) ios_swap_punch_leaks++;   /* ml1297: not reused */
        else ios_swap_free_add( off, len );
        ios_swap_pq_done++;
        pthread_mutex_unlock( &virtual_mutex );
    }
    return NULL;
}

/* Called with virtual_mutex held (every ios_swap_give caller is). */
static int ios_swap_punch_defer( uint64_t off, size_t len )
{
    int queued = 0;
    if (!ios_swap_pq_state)
    {
        /* MADEIRA_SWAP_PUNCH_DEFER=0 keeps every swap file punch synchronous, under the virtual lock. */
        const char *e = getenv( "MADEIRA_SWAP_PUNCH_DEFER" );
        pthread_t t;
        ios_swap_pq_state = -1;
        if (!(e && e[0] == '0') && !pthread_create( &t, NULL, ios_swap_punch_thread, NULL ))
        {
            pthread_detach( t );
            ios_swap_pq_state = 1;
        }
        dprintf( 2, "[swap] ml1291 deferred F_PUNCHHOLE %s\n",
                 ios_swap_pq_state > 0 ? "on" : (e && e[0] == '0') ? "off (MADEIRA_SWAP_PUNCH_DEFER=0)" : "off (no thread)" );
    }
    if (ios_swap_pq_state < 0) return 0;
    pthread_mutex_lock( &ios_swap_pq_lock );
    if (ios_swap_pq_n < IOS_SWAP_PQ)
    {
        unsigned slot = (ios_swap_pq_head + ios_swap_pq_n) % IOS_SWAP_PQ;
        ios_swap_pq[slot].off = off;
        ios_swap_pq[slot].len = len;
        ios_swap_pq_n++;
        queued = 1;
        pthread_cond_signal( &ios_swap_pq_cond );
    }
    pthread_mutex_unlock( &ios_swap_pq_lock );
    return queued;
}
/* ml1258, broad only: a size whose backed blocks die young stays anonymous.
 * ml1226: "twice" was too eager. Ori and the Will of the Wisps freed 13 backed
 * blocks in a 4.5-minute run, and two early young deaths each took 0x410000,
 * 0xfd0000, 0x1010000 and 0x4010000 out of the tier for good: 689 later blocks
 * of those sizes, ~1 GB of long-lived Unity heap, stayed anonymous and the game
 * was jetsammed. A size is churny now only after IOS_SWAP_CHURN_MIN_YOUNG young
 * deaths that are also at least half of its backings -- Metro 2033 Redux's 4 and 16 MB
 * blocks (~9 deaths a second, 1834 backings against ~170 lasting) still qualify
 * within a second. Once churny a size gets no more backings, so it stays so. */
static int ios_swap_churn_find( size_t size, int add )
{
    unsigned i;
    for (i = 0; i < ios_swap_nchurn; i++) if (ios_swap_churn[i].size == size) return (int)i;
    if (!add || ios_swap_nchurn == 64) return -1;
    ios_swap_churn[ios_swap_nchurn].size = size;
    ios_swap_churn[ios_swap_nchurn].hits = 0;
    ios_swap_churn[ios_swap_nchurn].backs = 0;
    return (int)ios_swap_nchurn++;
}
static int ios_swap_churn_is( unsigned i )
{
    return ios_swap_churn[i].hits >= IOS_SWAP_CHURN_MIN_YOUNG &&
           ios_swap_churn[i].hits * 2 >= ios_swap_churn[i].backs;
}
static int ios_swap_churny( size_t size )
{
    int i;
    if (!ios_swap_broad) return 0;
    i = ios_swap_churn_find( size, 0 );
    return i >= 0 && ios_swap_churn_is( (unsigned)i );
}
static void ios_swap_churn_backed( size_t size )
{
    int i;
    if (!ios_swap_broad) return;
    if ((i = ios_swap_churn_find( size, 1 )) >= 0) ios_swap_churn[i].backs++;
}
static void ios_swap_churn_note( size_t size, uint64_t lived_ns )
{
    int i = ios_swap_churn_find( size, 1 ), was;
    if (i < 0) return;
    was = ios_swap_churn_is( (unsigned)i );
    ios_swap_churn[i].hits++;
    if (!was && ios_swap_churn_is( (unsigned)i ))
    {
        ios_swap_nchurny++;
        dprintf( 2, "[swap] ml1226 churn: %u of %u backed blocks of 0x%zx were freed young (the last within %llu ms) -- "
                    "that size stays anonymous from now on (%u sizes)\n",
                 ios_swap_churn[i].hits, ios_swap_churn[i].backs, size,
                 (unsigned long long)(lived_ns / 1000000), ios_swap_nchurny );
    }
}
static int ios_swap_eligible( const void *base, size_t size, unsigned int vprot, struct file_view *view )
{
    uintptr_t b = (uintptr_t)base;
    if (ios_swap_fd < 0) return 0;
    if (!(vprot & VPROT_WRITE) || (vprot & (VPROT_EXEC | VPROT_WRITECOPY | VPROT_GUARD | VPROT_WRITEWATCH))) return 0;
    if (!view || !is_view_valloc( view ) || (view->protect & (SEC_FILE | SEC_IMAGE | SEC_RESERVE | VPROT_SYSTEM))) return 0;
    if (b < 0x7000000000ULL || b >= 0x7c00000000ULL) return 0;   /* the guest band only */
    if (size < ios_swap_min) return 0;   /* 8 MB unless madeira.cfg swap-min-mb (ml1257) */
    return 1;
}
/* blocks/wide/broad: why a range is (not) eligible; the census counts by this. */
static int ios_swap_is_fexjit( uintptr_t b, size_t size )
{
    uintptr_t e = b + size, rx = (uintptr_t)ios_jit_rx_base_global, rw = (uintptr_t)ios_jit_rw_base_global;
    size_t ps = ios_jit_pool_size_global;
    if (ios_fex_arena_base_unix && b < ios_fex_arena_end_unix && e > ios_fex_arena_base_unix) return 1;
    if (ps && rx && b < rx + ps && e > rx) return 1;
    if (ps && rw && b < rw + ps && e > rw) return 1;
    if (ios_jit_low_overlaps( b, size )) return 1;   /* madeira-bcd pool-low: region C */
    return 0;
}
static int ios_swap_why( const void *base, size_t size, unsigned int vprot, struct file_view *view )
{
    uintptr_t b = (uintptr_t)base;
    if (!(vprot & VPROT_WRITE) || (vprot & (VPROT_EXEC | VPROT_WRITECOPY | VPROT_GUARD | VPROT_WRITEWATCH))) return IOS_SW_PROT;
    if (!view || !is_view_valloc( view ) ||
        (view->protect & (SEC_FILE | SEC_IMAGE | SEC_RESERVE | VPROT_SYSTEM | VPROT_PLACEHOLDER |
                          VPROT_FREE_PLACEHOLDER | VPROT_ARM64EC | VPROT_WRITEWATCH))) return IOS_SW_VIEW;
    if (ios_swap_is_fexjit( b, size )) return IOS_SW_FEXJIT;
    if (ios_swap_broad) { if (b + size > 0x7c00000000ULL) return IOS_SW_BAND; }   /* ml1257: FEX's band and above */
    else if (!ios_swap_wide && (b < 0x7000000000ULL || b >= 0x7c00000000ULL)) return IOS_SW_BAND;
    if (size < ios_swap_min) return IOS_SW_SMALL;
    if (ios_swap_churny( size )) { ios_swap_churn_skips++; return IOS_SW_CHURN; }   /* ml1258 */
    return IOS_SW_BACKED;
}
static const char *ios_swap_map_tag = "";   /* ml1257: the "backed" log line names whole reservations */
/* Map the host-page interior of [base, base+size) from the file with
 * unix_prot. Returns IOS_SW_BACKED, IOS_SW_SMALL, IOS_SW_REFUSED or IOS_SW_MAPFAIL. */
static int ios_swap_map( void *base, size_t size, int unix_prot )
{
    char *hs = (char *)(((uintptr_t)base + host_page_mask) & ~(uintptr_t)host_page_mask);
    char *he = (char *)(((uintptr_t)base + size) & ~(uintptr_t)host_page_mask);
    size_t len; uint64_t off; void *p;
    if (he <= hs) return IOS_SW_SMALL;
    if (ios_swap_n >= 16384) { if (ios_swap_v2) ios_swap_refused++; return IOS_SW_REFUSED; }
    /* ml1257: in broad the cap is the disk the sparse file really occupies */
    if (ios_swap_broad && ios_swap_disk_used() >= ios_swap_cap) { ios_swap_disk_refused++; ios_swap_refused++; return IOS_SW_REFUSED; }
    len = he - hs;
    off = ios_swap_take( len );
    if (off == (uint64_t)-1) { ios_swap_refused++; return IOS_SW_REFUSED; }
    p = mmap( hs, len, unix_prot, MAP_FIXED | MAP_SHARED, ios_swap_fd, (off_t)off );
    if (p == MAP_FAILED)
    {
        static int said;
        if (said++ < 8) dprintf( 2, "[swap] ml1077 mmap MAP_SHARED %p+0x%zx failed errno=%d (range stays anonymous)\n", hs, len, errno );
        ios_swap_give( off, len );
        return IOS_SW_MAPFAIL;
    }
    ios_swap_ext[ios_swap_n].va = hs; ios_swap_ext[ios_swap_n].len = len; ios_swap_ext[ios_swap_n].off = off;
    ios_swap_ext[ios_swap_n].resv = 0; ios_swap_ext[ios_swap_n].key = size; ios_swap_ext[ios_swap_n].img = 0;
    ios_swap_ext[ios_swap_n].born = ios_swap_broad ? ios_swap_now_ns() : 0; ios_swap_n++;
    ios_swap_churn_backed( size );   /* ml1226 */
    ios_swap_bytes += len; if (ios_swap_bytes > ios_swap_peak) ios_swap_peak = ios_swap_bytes;
    ios_swap_backs++;
    /* ml1081: NO page touches under virtual_mutex. ml1078's first-touch timing loop
     * ran here with the lock held; in ph-rdr46 that thread sat in a single page-in
     * for a minute while the Mach exception thread (serving another thread's
     * routine crack write) waited for the lock -- process wedged. The canaries
     * measured the touch cost anyway: 2-40 us/page, no throttle up to 1.5 GB dirty
     * (6-9 GB/s then 2.6 GB/s). Whatever blocked that page-in, nothing that can
     * block may run while this lock is held. */
    /* ml1221: and every extent of 64 MB or more, so the big heaps are always named */
    if (ios_swap_backs <= 16 || (ios_swap_backs % 64) == 0 || len >= (64u << 20))
        dprintf( 2, "[swap] ml1077 backed %p+0x%zx%s (file off %llu MB): %llu MB in %u extents, peak %llu MB, %llu refused\n",
                 hs, len, ios_swap_map_tag, (unsigned long long)(off >> 20), ios_swap_bytes >> 20, ios_swap_n, ios_swap_peak >> 20, ios_swap_refused );
    return IOS_SW_BACKED;
}
static void ios_swap_back( void *base, size_t size, unsigned int vprot )
{
    /* ml1082: get_unix_prot() yields PROT_NONE for a vprot without VPROT_COMMITTED,
     * and the commit-on-existing path handed in the bare flags from
     * get_vprot_flags(): the 6th extent of every run so far was mapped prot=0
     * ("region ... prot=0 max=3 extpager=1" in ph-rdr49). Every access then
     * faulted into the Mach handler -- healed page by page while the lock was
     * free, deadlocked when the faulting thread held virtual_mutex (rdr45/46),
     * and misdelivered to the guest as an AV when a JIT block took it (rdr49:
     * RIP 0x170, process terminated). The extent is committed by definition. */
    ios_swap_map( base, size, get_unix_prot( vprot | VPROT_COMMITTED ) );
}
/* Drop file backing for whatever part of [base, base+size) has it. copy_back:
 * preserve contents in fresh anonymous memory (for an EXEC request); else the
 * caller is about to replace the mapping anyway and the data is discarded.
 *
 * A copy-back works on WHOLE host pages. The request is guest-page (4 KB)
 * granular, the extents are host-page (16 KB) aligned, and one host page can
 * only be mapped from one object: an edge inside a backed host page moves that
 * whole host page to anonymous memory, contents of its other guest pages
 * included, and the pages' own protections are re-applied afterwards.
 * set_protection() calls this BEFORE set_vprot (ml1257), so those are still the
 * old protections and set_vprot then applies the new ones to anonymous memory;
 * a source page that is not readable (uncommitted inside a reservation extent,
 * or a guard page) is made readable for the copy. Without a copy buffer or a
 * fresh anonymous mapping the range stays file-backed instead of losing its data. */
static void ios_swap_release_range( void *base, size_t size, int copy_back )
{
    char *lo = (char *)base, *hi = (char *)base + size;
    unsigned i = 0;
    unsigned long long releases_before = ios_swap_releases;
    uint64_t noted_born = 0;   /* ml1258: pieces of one split extent are one death */
    if (ios_swap_fd < 0 || !ios_swap_n) return;
    if (copy_back)
    {
        lo = (char *)((uintptr_t)lo & ~(uintptr_t)host_page_mask);
        hi = (char *)(((uintptr_t)hi + host_page_mask) & ~(uintptr_t)host_page_mask);
    }
    while (i < ios_swap_n)
    {
        char *a = ios_swap_ext[i].va, *b = a + ios_swap_ext[i].len;
        char *oa = a > lo ? a : lo, *ob = b < hi ? b : hi;
        if (oa >= ob) { i++; continue; }
        {
            uint64_t ooff = ios_swap_ext[i].off + (oa - a);
            size_t olen = ob - oa;
            if (copy_back)
            {
                void *tmp = malloc( olen );
                char *pg;
                if (!tmp)
                {
                    static int said;
                    if (said++ < 8) dprintf( 2, "[swap] copy-back of %p+0x%zx: no buffer, range stays file-backed\n", oa, olen );
                    i++;
                    continue;
                }
                for (pg = oa; pg < ob; pg += host_page_mask + 1)
                    if (!(get_unix_prot( get_host_page_vprot( pg ) ) & PROT_READ)) { mprotect( oa, olen, PROT_READ ); break; }
                memcpy( tmp, oa, olen );
                if (anon_mmap_fixed( oa, olen, PROT_READ | PROT_WRITE, 0 ) == MAP_FAILED)
                {
                    static int said;
                    if (said++ < 8) dprintf( 2, "[swap] copy-back of %p+0x%zx: anonymous map failed errno=%d, range stays file-backed\n", oa, olen, errno );
                    free( tmp );
                    mprotect_range( oa, olen, 0, 0 );
                    i++;
                    continue;
                }
                memcpy( oa, tmp, olen );
                free( tmp );
                mprotect_range( oa, olen, 0, 0 );
                ios_swap_unbacks++;
            }
            /* ml1293: the range's contents are dead (decommit/release), but its dirty pages would
             * still be written to the file by the pageout daemon -- I/O that slowed every other
             * fault on the file and the punch behind it. Discard them first: no writeback. */
            if (!copy_back) msync( oa, olen, MS_KILLPAGES );
            ios_swap_give( ooff, olen );
            ios_swap_bytes -= olen;
            if (ios_swap_ext[i].img) ios_swap_img_bytes -= olen;   /* madeira-bcd swap-images */
            ios_swap_releases++;
            /* trim the extent: up to two remaining pieces */
            if (oa == a && ob == b)
            {
                if (!copy_back && ios_swap_broad && ios_swap_ext[i].born != noted_born)   /* ml1258: freed whole; how long did it live? */
                {
                    uint64_t lived = ios_swap_now_ns() - ios_swap_ext[i].born;
                    noted_born = ios_swap_ext[i].born;
                    if (lived < IOS_SWAP_CHURN_NS) ios_swap_churn_note( ios_swap_ext[i].key, lived );
                }
                ios_swap_ext[i] = ios_swap_ext[--ios_swap_n];
                continue;
            }
            if (oa == a) { ios_swap_ext[i].va = ob; ios_swap_ext[i].off += olen; ios_swap_ext[i].len -= olen; i++; continue; }
            if (ob == b) { ios_swap_ext[i].len = oa - a; i++; continue; }
            if (ios_swap_n < 16384)
            {
                ios_swap_ext[ios_swap_n] = ios_swap_ext[i];   /* resv, key, born carry over */
                ios_swap_ext[ios_swap_n].va = ob; ios_swap_ext[ios_swap_n].off = ios_swap_ext[i].off + (ob - a);
                ios_swap_ext[ios_swap_n].len = b - ob; ios_swap_n++;
            }
            ios_swap_ext[i].len = oa - a; i++;
        }
    }
    if (ios_swap_releases != releases_before && (ios_swap_releases <= 16 || (ios_swap_releases % 64) == 0))
        dprintf( 2, "[swap] ml1077 released %p+0x%zx%s: %llu MB in %u extents, %llu releases, %llu unbacks\n",
                 base, size, copy_back ? " (copied back to anonymous)" : "", ios_swap_bytes >> 20, ios_swap_n, ios_swap_releases, ios_swap_unbacks );
}
/* ml1257: decommit inside a reservation extent. Punch the file range -- the
 * mapping stays, and a hole reads as zero -- instead of replacing it with
 * anonymous memory, which would leave every recommit anonymous. RW afterwards,
 * exactly like decommit_pages' anonymous mmap-over. 0 = not wholly inside one
 * reservation extent (or the punch failed): the caller releases as before.
 * [lo, lo+len) is host-page aligned (decommit_pages' host interior). */
static int ios_swap_punch_resv( char *lo, size_t len )
{
    unsigned i;
    if (ios_swap_fd < 0 || !ios_swap_n) return 0;
    for (i = 0; i < ios_swap_n; i++)
    {
        char *a = ios_swap_ext[i].va;
        if (!ios_swap_ext[i].resv || lo < a || lo + len > a + ios_swap_ext[i].len) continue;
        msync( lo, len, MS_KILLPAGES );   /* ml1293: drop the dead dirty pages before the punch */
        if (ios_swap_punch_timed( ios_swap_ext[i].off + (lo - a), len, "decommit" ))   /* ml1291: timed */
        {
            static int said;
            if (said++ < 8) dprintf( 2, "[swap] ml1257 hole %p+0x%zx failed errno=%d: releasing instead\n", lo, len, errno );
            return 0;
        }
        mprotect( lo, len, PROT_READ | PROT_WRITE );
        if (++ios_swap_holes <= 8 || (ios_swap_holes % 1024) == 0)
            dprintf( 2, "[swap] ml1257 decommit %p+0x%zx punched in place (%llu holes)\n", lo, len, ios_swap_holes );
        return 1;
    }
    return 0;
}
static int ios_swap_overlaps( const void *base, size_t size )
{
    unsigned i; const char *lo = base, *hi = (const char *)base + size;
    for (i = 0; i < ios_swap_n; i++)
        if (ios_swap_ext[i].va < hi && ios_swap_ext[i].va + ios_swap_ext[i].len > lo) return 1;
    return 0;
}
int ios_swap_overlaps_probe( const void *base, size_t size ) { return ios_swap_overlaps( base, size ); }
void ios_swap_stats_line( void )
{
    unsigned long long disk;
    if (ios_swap_fd < 0) return;
    disk = ios_swap_disk_used();
    dprintf( 2, "[swap] ml1077 stats: %llu MB file-backed now (peak %llu), %u extents, file used %llu of %llu MB, backs %llu releases %llu unbacks %llu refused %llu"
             " | coverage %s: disk %llu MB of %llu cap, reservations %llu, holes %llu, disk-full refusals %llu"
             " | ml1258 churn: %u sizes, %llu blocks left anonymous\n",
             ios_swap_bytes >> 20, ios_swap_peak >> 20, ios_swap_n, (unsigned long long)(ios_swap_bump >> 20),
             (unsigned long long)(ios_swap_logical >> 20), ios_swap_backs, ios_swap_releases, ios_swap_unbacks, ios_swap_refused,
             ios_swap_mode, disk >> 20, (unsigned long long)(ios_swap_cap >> 20), ios_swap_resv_n, ios_swap_holes,
             ios_swap_disk_refused, ios_swap_nchurny, ios_swap_churn_skips );
    if (ios_swap_img_backs || ios_swap_img_refused)   /* madeira-bcd swap-images */
        dprintf( 2, "[swap] swap-images: %llu MB of image sections in the file (peak %llu), %llu sections moved, %llu refused\n",
                 ios_swap_img_bytes >> 20, ios_swap_img_peak >> 20, ios_swap_img_backs, ios_swap_img_refused );
    dprintf( 2, "[swap] ml1291 punches: %llu deferred done, %u queued, %llu slow (>=100 ms), max %llu ms; ml1297 %llu ranges not reused after a failed punch\n",
             ios_swap_pq_done, ios_swap_pq_n, ios_swap_punch_slow, ios_swap_punch_max_ms, ios_swap_punch_leaks );
    /* ml1221: the census (bytes by reason) with every stats line, ~10 s, not only
     * after its own 30 s: Ori and the Will of the Wisps was jetsammed at 26 s and never printed one. */
    ios_swap_tick( 1 );
}
/* The census line, formatted by hand into a stack buffer (no stdio, no heap). */
static char *ios_swap_put( char *p, char *end, const char *s )
{
    while (*s && p < end) *p++ = *s++;
    return p;
}
static char *ios_swap_put_u( char *p, char *end, unsigned long long v )
{
    char t[20];
    int n = 0;
    do t[n++] = '0' + (char)(v % 10); while ((v /= 10) && n < 20);
    while (n && p < end) *p++ = t[--n];
    return p;
}
/* blocks/wide/broad: print the census when 30 s have passed since the last check
 * and anything changed (or 5 min passed); force prints now. */
static void ios_swap_tick( int force )
{
    static unsigned long long next_s, last_sum, last_print_s;
    struct timespec ts;
    unsigned long long now_s, sum = ios_swap_bytes + ios_swap_backs + ios_swap_releases + ios_swap_refused + ios_swap_resv_n + ios_swap_holes;
    char line[768], *p = line, *end = line + sizeof(line) - 1;
    int i;
    if (ios_swap_fd < 0 || !ios_swap_v2) return;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    now_s = (unsigned long long)ts.tv_sec;
    for (i = 0; i < IOS_SW_REASONS; i++) sum += ios_swap_why_bytes[i];
    if (!next_s) { next_s = now_s + 30; last_print_s = now_s; }
    if (!force && now_s < next_s) return;
    next_s = now_s + 30;
    if (!force && sum == last_sum && now_s - last_print_s < 300) return;
    last_sum = sum; last_print_s = now_s;
    p = ios_swap_put( p, end, "[swap] census file-backed now=" ); p = ios_swap_put_u( p, end, ios_swap_bytes >> 20 );
    p = ios_swap_put( p, end, "MB peak=" );       p = ios_swap_put_u( p, end, ios_swap_peak >> 20 );
    p = ios_swap_put( p, end, "MB extents=" );    p = ios_swap_put_u( p, end, ios_swap_n );
    p = ios_swap_put( p, end, " file=" );         p = ios_swap_put_u( p, end, ios_swap_bump >> 20 );
    p = ios_swap_put( p, end, "/" );              p = ios_swap_put_u( p, end, ios_swap_cap >> 20 );
    p = ios_swap_put( p, end, "MB free=" );       p = ios_swap_put_u( p, end, ios_swap_nfree );
    p = ios_swap_put( p, end, " merges=" );       p = ios_swap_put_u( p, end, ios_swap_merges );
    p = ios_swap_put( p, end, " | commit MB by reason:" );
    for (i = 0; i < IOS_SW_REASONS; i++)
    {
        p = ios_swap_put( p, end, " " ); p = ios_swap_put( p, end, ios_swap_reason_name[i] );
        p = ios_swap_put( p, end, "=" ); p = ios_swap_put_u( p, end, ios_swap_why_bytes[i] >> 20 );
    }
    p = ios_swap_put( p, end, " | reserve-backed " ); p = ios_swap_put_u( p, end, ios_swap_resv_n );
    p = ios_swap_put( p, end, " (" );                 p = ios_swap_put_u( p, end, ios_swap_resv_bytes >> 20 );
    p = ios_swap_put( p, end, "MB) holes=" );         p = ios_swap_put_u( p, end, ios_swap_holes );
    if (ios_swap_broad)
    {
        p = ios_swap_put( p, end, " disk=" );         p = ios_swap_put_u( p, end, ios_swap_disk_used() >> 20 );
        p = ios_swap_put( p, end, "MB churn-sizes=" ); p = ios_swap_put_u( p, end, ios_swap_nchurny );
        p = ios_swap_put( p, end, " | reservations not taken whole MB:" );   /* ml1221 */
        for (i = 0; i < IOS_SWK_REASONS; i++)
        {
            p = ios_swap_put( p, end, " " ); p = ios_swap_put( p, end, ios_swap_skip_name[i] );
            p = ios_swap_put( p, end, "=" ); p = ios_swap_put_u( p, end, ios_swap_skip_bytes[i] >> 20 );
        }
    }
    if (ios_swap_img_backs || ios_swap_img_refused)   /* madeira-bcd swap-images */
    {
        p = ios_swap_put( p, end, " | images=" );     p = ios_swap_put_u( p, end, ios_swap_img_bytes >> 20 );
        p = ios_swap_put( p, end, "MB peak=" );       p = ios_swap_put_u( p, end, ios_swap_img_peak >> 20 );
        p = ios_swap_put( p, end, "MB sections=" );   p = ios_swap_put_u( p, end, ios_swap_img_backs );
        p = ios_swap_put( p, end, " refused=" );      p = ios_swap_put_u( p, end, ios_swap_img_refused );
    }
    p = ios_swap_put( p, end, " | footprint=" );      p = ios_swap_put_u( p, end, ios_swap_footprint_mb() );
    p = ios_swap_put( p, end, "MB coverage=" );       p = ios_swap_put( p, end, ios_swap_mode );
    p = ios_swap_put( p, end, " min=" );              p = ios_swap_put_u( p, end, ios_swap_min >> 10 );
    p = ios_swap_put( p, end, "KB\n" );
    if (p == end) p[-1] = '\n';
    (void)!write( 2, line, p - line );
}
static void ios_swap_note( int why, size_t size )
{
    if (ios_swap_fd < 0 || !ios_swap_v2) return;
    ios_swap_why_bytes[why] += size;
    ios_swap_tick( 0 );
}
/* A fresh commit (MEM_COMMIT, with or without MEM_RESERVE) of [base, base+size).
 * classic runs the original rule unchanged. */
static void ios_swap_commit( void *base, size_t size, unsigned int vprot, struct file_view *view )
{
    int why;
    if (ios_swap_fd < 0) return;
    if (!ios_swap_v2) { if (ios_swap_eligible( base, size, vprot, view )) ios_swap_back( base, size, vprot ); return; }
    if ((ios_swap_wide || ios_swap_broad) && ios_swap_n && ios_swap_overlaps( base, size )) { ios_swap_note( IOS_SW_PRESENT, size ); return; }
    why = ios_swap_why( base, size, vprot, view );
    if (why == IOS_SW_BACKED) why = ios_swap_map( base, size, get_unix_prot( vprot | VPROT_COMMITTED ) );   /* ml1082 */
    ios_swap_note( why, size );
}
/* wide: a fresh WRITABLE reservation, mapped from the file PROT_NONE (what
 * map_view left there), so later commits are protection changes of file
 * pages. Holes read as zero, so every first commit is zero-filled. */
static void ios_swap_reserve( void *base, size_t size, unsigned int vprot, struct file_view *view )
{
    if (ios_swap_fd < 0 || !ios_swap_wide) return;
    if ((vprot & VPROT_COMMITTED) || size > ios_swap_resv_max) return;
    if (ios_swap_why( base, size, vprot, view ) != IOS_SW_BACKED) return;
    if (ios_swap_map( base, size, get_unix_prot( vprot ) ) != IOS_SW_BACKED) return;
    /* ml1257: decommit inside it punches in place, like broad's reservations, so a
     * small recommit stays file-backed instead of splitting the extent (wide has not
     * run on a device yet). */
    ios_swap_ext[ios_swap_n - 1].resv = 1;
    ios_swap_resv_n++;
    ios_swap_resv_bytes += size;
    ios_swap_tick( 0 );
}
/* ml1257 broad: back a whole NEW reservation when it is made, committed or not,
 * with the protection its pages have now (PROT_NONE where not committed), so
 * every commit inside it is an mprotect of file pages and a decommit a hole.
 * Returns 1 when it handled the view (backed, or refused by the file), 0 to let
 * the caller apply the commit/reserve rules. The caller has already excluded
 * ARM64EC code reservations and force_exec_prot. */
static int ios_swap_whole_resv( struct file_view *view, unsigned int vprot )
{
    uintptr_t b;
    int why;
    if (ios_swap_fd < 0 || !ios_swap_broad) return 0;
    b = (uintptr_t)view->base;
    if (vprot & (VPROT_EXEC | VPROT_WRITECOPY | VPROT_GUARD | VPROT_WRITEWATCH | VPROT_PLACEHOLDER))
    { ios_swap_skip_bytes[IOS_SWK_PROT] += view->size; return 0; }
    if (!is_view_valloc( view ) || (view->protect & (SEC_FILE | SEC_IMAGE | SEC_RESERVE | VPROT_SYSTEM | VPROT_WRITEWATCH |
                                                     VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER | VPROT_ARM64EC)))
    { ios_swap_skip_bytes[IOS_SWK_VIEW] += view->size; return 0; }
    if (view->size < ios_swap_min) { ios_swap_skip_bytes[IOS_SWK_SMALL] += view->size; return 0; }
    if (view->size > ios_swap_resv_max) { ios_swap_skip_bytes[IOS_SWK_BIG] += view->size; return 0; }
    if (ios_swap_is_fexjit( b, view->size ) || b + view->size > 0x7c00000000ULL)
    { ios_swap_skip_bytes[IOS_SWK_FEXJIT] += view->size; return 0; }
    if (ios_swap_n && ios_swap_overlaps( view->base, view->size )) { ios_swap_skip_bytes[IOS_SWK_OVERLAP] += view->size; return 0; }
    if (ios_swap_churny( view->size ))   /* ml1258 */
    { ios_swap_churn_skips++; ios_swap_skip_bytes[IOS_SWK_CHURN] += view->size; return 0; }
    ios_swap_map_tag = " (whole reservation, ml1257)";
    why = ios_swap_map( view->base, view->size, get_unix_prot( vprot ) );
    ios_swap_map_tag = "";
    if (why == IOS_SW_BACKED)
    {
        ios_swap_ext[ios_swap_n - 1].resv = 1;
        ios_swap_resv_n++;
        ios_swap_resv_bytes += view->size;
    }
    if (vprot & VPROT_COMMITTED) ios_swap_note( why, view->size );
    else ios_swap_tick( 0 );
    return 1;
}
/* madeira-bcd swap-images (see ios_swap_image_flush): the file side. With the
 * lock held, ios_swap_image_take reserves a file range for a section's
 * host-page interior (-1: tier off, extent table or disk full); the caller
 * copies the section into it with pwrite after leaving the lock, and with the
 * lock held again ios_swap_image_map maps the range over the anonymous copy
 * -- a MAP_FIXED that fails leaves the old mapping and its data in place on
 * Darwin, as for ios_swap_map -- or gives it back. No page is touched here.
 * Image extents never feed the churn filter (key 0, born 0) and never come
 * from the ml1150 pool, whose ranges a pwrite cannot reach. */
static uint64_t ios_swap_image_take( size_t len )
{
    uint64_t off;
    if (ios_swap_fd < 0 || !len || (len & host_page_mask) || ios_swap_n >= 16384) return (uint64_t)-1;
    if (ios_swap_broad && ios_swap_disk_used() >= ios_swap_cap) { ios_swap_disk_refused++; ios_swap_img_refused++; return (uint64_t)-1; }
    off = ios_swap_take( len );
    if (off == (uint64_t)-1) ios_swap_img_refused++;
    return off;
}
static int ios_swap_image_map( char *va, size_t len, uint64_t off )
{
    void *p;
    if (ios_swap_fd < 0) return 0;
    if (((uintptr_t)va & host_page_mask) || ios_swap_n >= 16384 || ios_swap_overlaps( va, len ))
    {
        ios_swap_give( off, len );
        ios_swap_img_refused++;
        return 0;
    }
    p = mmap( va, len, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, ios_swap_fd, (off_t)off );
    if (p == MAP_FAILED)
    {
        static int said;
        if (said++ < 8) dprintf( 2, "[swap] swap-images: mmap MAP_SHARED %p+0x%zx failed errno=%d (section stays anonymous)\n", va, len, errno );
        ios_swap_give( off, len );
        ios_swap_img_refused++;
        return 0;
    }
    ios_swap_ext[ios_swap_n].va = va; ios_swap_ext[ios_swap_n].len = len; ios_swap_ext[ios_swap_n].off = off;
    ios_swap_ext[ios_swap_n].resv = 0; ios_swap_ext[ios_swap_n].key = 0; ios_swap_ext[ios_swap_n].born = 0;
    ios_swap_ext[ios_swap_n].img = 1; ios_swap_n++;
    ios_swap_bytes += len; if (ios_swap_bytes > ios_swap_peak) ios_swap_peak = ios_swap_bytes;
    ios_swap_backs++;
    ios_swap_img_bytes += len; if (ios_swap_img_bytes > ios_swap_img_peak) ios_swap_img_peak = ios_swap_img_bytes;
    ios_swap_img_backs++;
    if (ios_swap_img_backs <= 16 || (ios_swap_img_backs % 64) == 0 || len >= (64u << 20))
        dprintf( 2, "[swap] swap-images: moved %p+0x%zx (image section, file off %llu MB): %llu MB of images in the file, "
                    "%llu MB file-backed in %u extents\n", va, len, (unsigned long long)(off >> 20),
                 ios_swap_img_bytes >> 20, ios_swap_bytes >> 20, ios_swap_n );
    ios_swap_tick( 0 );
    return 1;
}
/* swap-tier core end */
static unsigned long long ios_swap_footprint_mb( void )
{
    task_vm_info_data_t vmi;
    mach_msg_type_number_t c = TASK_VM_INFO_COUNT;
    if (task_info( mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &c ) != KERN_SUCCESS) return 0;
    return (unsigned long long)vmi.phys_footprint >> 20;
}
/* ml1257: the disk the sparse file really occupies (fstat: no page touches) */
static unsigned long long ios_swap_disk_used( void )
{
    struct stat st;
    if (ios_swap_fd < 0 || fstat( ios_swap_fd, &st )) return 0;
    return (unsigned long long)st.st_blocks * 512;
}

/* ml1257: madeira.cfg swap-mode = 2 selects broad coverage (when
 * env.MADEIRA_SWAP_COVERAGE is unset); swap-min-mb = N sets the floor. */
static void ios_swap_cfg( int *mode, int *min_mb )
{
    *mode = (int)madeira_cfg_int( "swap-mode", 1 );       /* ml1257: madeira.cfg swap-mode = 2 */
    *min_mb = (int)madeira_cfg_int( "swap-min-mb", 0 );   /* ml1257: madeira.cfg swap-min-mb = N */
}

/* madeira-bcd swap-images: the switch, read once; on only with the tier on.
 * virtual_mutex held (the first call starts the tier, as allocate_virtual_memory does). */
static int ios_swap_images_enabled( void )
{
    static int on = -1;
    if (on < 0)
    {
        /* 1: pure-x64 images' sections move to the swap tier's file after they are read (needs swap-mb and env.MADEIRA_X64_IMAGE_NOCOPY = 1). */
        on = madeira_cfg_bool( "swap-images", 0 );
        if (on)
        {
            ios_swap_init();
            if (ios_swap_fd < 0) on = 0;
            dprintf( 2, "[swap] swap-images %s (madeira.cfg swap-images = 1)\n",
                     on ? "on: sections of pure-x64 images move to the swap file after they are read"
                        : "requested but the swap tier is off (swap-mb): images stay anonymous" );
        }
    }
    return on;
}

/* madeira-bcd swap-images: move the sections ios_swap_image_note recorded on
 * this thread into the swap file. Called by virtual_map_image with
 * virtual_mutex RELEASED (ml1081). Per range: reserve the file range (lock),
 * pwrite the section's current bytes there (no lock: may block on the file),
 * then map it over the anonymous copy and re-apply the pages' protections
 * (lock), or give it back. Between the two locked steps nothing writes the
 * range: the view is not returned to its caller yet. Every step re-checks that
 * the range still lies in the same pure-x64 image view (VPROT_X64DATA) and is
 * not backed yet; `ok` = 0 (the image failed to map) drops the notes. */
static void ios_swap_image_flush( int ok )
{
    unsigned i, n = ios_swap_image_npend;
    ios_swap_image_npend = 0;
    for (i = 0; ok && i < n; i++)
    {
        char *va = ios_swap_image_pend[i].va;
        size_t len = ios_swap_image_pend[i].len;
        void *view_base = ios_swap_image_pend[i].view_base;
        struct file_view *view;
        uint64_t off = (uint64_t)-1;
        sigset_t sigset;
        ssize_t written;
        int err, same;

        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        view = find_view( va, len );
        if (view && view->base == view_base && (view->protect & SEC_IMAGE) && (view->protect & VPROT_X64DATA) &&
            !ios_swap_overlaps( va, len ))
            off = ios_swap_image_take( len );
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        if (off == (uint64_t)-1) continue;

        written = pwrite( ios_swap_fd, va, len, (off_t)off );
        err = written < 0 ? errno : 0;

        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        view = find_view( va, len );
        same = view && view->base == view_base && (view->protect & VPROT_X64DATA);
        if (written == (ssize_t)len && same)
        {
            if (ios_swap_image_map( va, len, off )) mprotect_range( va, len, 0, 0 );
        }
        else
        {
            static int said;
            if (said++ < 8)
                dprintf( 2, "[swap] swap-images: %p+0x%zx not moved (pwrite %zd of %zu, errno %d; view %s): stays anonymous\n",
                         va, len, written, len, err, same ? "unchanged" : view ? "changed" : "gone" );
            ios_swap_give( off, len );
            ios_swap_img_refused++;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    }
}

/* Zero the COMMITTED guest pages of [start, end), a part of a decommit range that the
 * host-page mmap-over in decommit_pages cannot cover. Windows accepts a MEM_DECOMMIT that
 * also spans reserved-but-never-committed pages and leaves those alone, and a host page
 * whose guest pages are all uncommitted is PROT_NONE: a plain memset over the range then
 * faults in host code with virtual_mutex held, and the calling thread is lost. Pages that
 * are not committed are skipped, as on Windows; they were zeroed when they were last
 * decommitted, or never committed at all. virtual_mutex held. Returns the bytes zeroed. */
static size_t ios_decommit_zero_committed( char *start, char *end )
{
    static unsigned long skipped, logs;
    size_t zeroed = 0;
    char *p, *next;

    for (p = start; p < end; p = next)
    {
        next = (char *)ROUND_ADDR( p, page_mask ) + page_size;
        if (next > end) next = end;
        if (get_page_vprot( p ) & VPROT_COMMITTED)
        {
            memset( p, 0, next - p );
            zeroed += next - p;
        }
        else skipped++;
    }
    if (zeroed != (size_t)(end - start) && (logs++ < 32 || !(logs % 1024)))
        dprintf( 2, "[decommit-skip] %p-%p zeroed=0x%lx: uncommitted guest pages left alone (%lu so far)\n",
                 start, end, (unsigned long)zeroed, skipped );
    return zeroed;
}

static NTSTATUS decommit_pages( struct file_view *view, char *base, size_t size )
{
    char *host_end, *host_start = (char *)ROUND_SIZE( 0, base, host_page_mask );
    /* ml293 probe state: which branch honoured the zero contract, and where to read back. */
    const char *dc_branch = "none";
    const void *dc_verify = NULL;
    size_t      dc_vsize  = 0;
    /* ml610 [dc-census] sample state. */
    struct ios_dc_census dc_before, dc_after;
    struct timeval dc_t0, dc_t1, dc_t2, dc_t3;
    int dc_sampled = 0;

    if (!size)
    {
        size = view->size;
        host_end = host_start + view->size;
    }
    else host_end = ROUND_ADDR( base + size, host_page_mask );

    /* ml610 [dc-census] BEFORE sample. Large ranges only (the 16MB callret
     * stacks and the LookupCache clears — the small-decommit flood would drown
     * the signal and cost far more than it measures). Hard-capped: this runs
     * with virtual_mutex held, and for callret resets it runs on the SWEEPER
     * with the code-buffer migration gate active, so an uncapped probe would
     * perturb exactly what it is measuring. The cost is logged per sample so
     * that judgement is checkable rather than asserted. */
    {
        static unsigned long dc_big_seen, dc_samples;
        if (size >= (4u << 20))
        {
            unsigned long n = ++dc_big_seen;
            if (dc_samples < 16 && (n <= 8 || (n % 512) == 0))
            {
                dc_samples++;
                dc_sampled = 1;
                gettimeofday( &dc_t0, NULL );
                ios_dc_census_take( base, size, &dc_before );
                gettimeofday( &dc_t1, NULL );
            }
        }
    }

    /* iOS-Madeira (task #22 real root cause, 2026-07-10): FEX's Windows
     * VirtualDontNeed() = MEM_DECOMMIT (often WITHOUT recommit — LookupCache
     * uses it as a cheap bzero on every cache clear) and then touches the
     * pages again assuming Linux MADV_DONTNEED semantics (still mapped,
     * reads return zero). The upstream PROT_NONE mmap-over therefore turned
     * every Steam module-load cache-clear into a recurring BUS-fault burst
     * on the SAME pages (retry#1..63 in one run), and on anon-RWX ranges it
     * silently DESTROYED the pool vm_remap alias (decoupled user VA from the
     * pool RW/RX views). Give decommit Linux-like semantics instead:
     *  - alias-backed range: memset the RW alias (zero contract), keep the
     *    mapping and the alias intact;
     *  - plain range: mmap-over RW (fresh zero pages, still accessible) and
     *    zero the partial host pages at the edges by hand. */
    {
        extern uintptr_t ios_jit_anon_alias_lookup(uintptr_t fault_addr);
        uintptr_t rw_alias = ios_jit_anon_alias_lookup( (uintptr_t)base );
        if (rw_alias)
        {
            /* ml92/ml94 [alias-tomb]: the exec faults that survived removing the
             * MADV sweep all landed on RECYCLED pool ranges whose instruction
             * stream read back as ZEROS (insn_stream 00000000 00000000, and the
             * nls poison 0xdead1 still intact) — the signature of this memset
             * firing through a stale alias, not of iOS harvesting a page. The
             * allocator's own comment predicted it: "any guest MEM_DECOMMIT of
             * the old user VA memsets the NEW occupant to zero via
             * decommit_pages' alias path -> blr into zeros -> fault storm."
             * Refuse it: zeroing a loaded DLL copy is never the right answer,
             * and the log names the victim so the claim is checkable. */
            size_t l_off = 0;
            void  *l_peb = NULL;
            if (ios_pool_live_overlap( rw_alias, size, &l_off, &l_peb ))
            {
                dprintf(2, "[alias-tomb] STALE alias decommit REFUSED: user_va=%p size=0x%lx rw_alias=0x%lx -> pool off=0x%lx (LIVE, peb=%p) — would have zeroed a loaded module\n",
                        base, (unsigned long)size, (unsigned long)rw_alias,
                        (unsigned long)l_off, l_peb);
                /* ml293: this branch DELIBERATELY skips zeroing. That is right for a loaded
                 * module, but it means the caller's decommit-as-bzero contract is broken for
                 * this range -- name it so, instead of leaving it indistinguishable from a
                 * range that was zeroed. */
                dc_branch = "alias-REFUSED(NOT zeroed)";
            }
            else
            {
                memset( (void *)rw_alias, 0, size );
                dc_branch = "alias-memset";
                dc_verify = (const void *)rw_alias;
                dc_vsize  = size;
            }
        }
        else if (host_start < host_end)
        {
            if (ios_swap_punch_resv( host_start, host_end - host_start ))   /* ml1257 */
                dc_branch = "swap-hole";   /* no read-back: no file-page touches under the lock (ml1081) */
            else
            {
                ios_swap_release_range( host_start, host_end - host_start, 0 );   /* ml1077 */
                anon_mmap_fixed( host_start, host_end - host_start, PROT_READ | PROT_WRITE, 0 );
                dc_branch = "mmap-over";
                dc_verify = host_start;
                dc_vsize  = host_end - host_start;
            }
            /* Zero the guest sub-ranges on partial host pages the mmap-over
             * couldn't cover — FEX relies on decommit-as-bzero, and stale
             * LookupCache entries surviving at the edges would run wrong
             * blocks. Only their committed guest pages: an edge host page
             * may hold none (see ios_decommit_zero_committed). */
            if ((char *)base < host_start) ios_decommit_zero_committed( base, host_start );
            if (host_end < (char *)base + size) ios_decommit_zero_committed( host_end, (char *)base + size );
        }
        else
        {
            /* Range lies within a single host page — no full page to remap;
             * zero its committed guest pages in place to honour the
             * decommit-as-bzero contract. The read-back below reads base's
             * guest page, so it runs only if that page was committed: an
             * uncommitted one was not zeroed and may be PROT_NONE. */
            size_t zeroed = ios_decommit_zero_committed( base, (char *)base + size );
            if (zeroed == size) dc_branch = "subpage-memset";
            else dc_branch = zeroed ? "subpage-memset-partial" : "subpage-uncommitted";
            if (get_page_vprot( base ) & VPROT_COMMITTED)
            {
                dc_verify = base;
                dc_vsize  = size;
            }
        }

        /* iOS-Madeira ml293 (task #52): VERIFY THE DECOMMIT ZERO CONTRACT IN THE PA ARENAS.
         *
         * Chromium's PartitionAlloc decommits slot spans and requires the pages to read
         * back as zero on recommit; its BackupRefPtr refcount lives in that metadata. A
         * stale (non-zero) refcount is exactly the failure chrome_elf reported: a "refcount"
         * PA_CHECK ending in `ud2` at chrome_elf+0xd7d70, with 0xAA poison and the caller
         * passing 0xEF (PA's quarantine byte).
         *
         * Every branch above believes it zeroed the range, so a report that merely echoed
         * the branch would prove nothing -- READ THE MEMORY BACK. Both outcomes are
         * reportable: OK confirms the contract holds and moves the hypothesis elsewhere,
         * while a non-zero offset plus the stale bytes names the bug outright. The
         * alias-REFUSED branch is reported without a read-back precisely because it does
         * not zero.
         *
         * Arena-band only, capped, so this cannot storm a log. */
        /* ml547: same census conversion as [commit-zero]. As written this was
         * arena-band only (excluding the GUEST band where CEF's render bitmap
         * lives) AND capped at 40 -- and in ml546 all 40 reports went to ONE
         * repeated FEX-band address (0x7c012a1000), so guest and pool decommits
         * were never measured at all. Unbounded counters, every anomaly logged,
         * only the OK lines rate-limited, totals on every line. */
        {
            static unsigned long dc_hi, dc_lo, dcbad_hi, dcbad_lo;
            int dc_isarena = ios_is_arena_addr( base );
            unsigned long dc_n = dc_isarena ? ++dc_hi : ++dc_lo;
            {
                if (dc_verify && dc_vsize)
                {
                    size_t chk = dc_vsize < 64 ? dc_vsize : 64;
                    long nz = ios_first_nonzero( dc_verify, chk );
                    if (nz < 0)
                    {
                        if (dc_n <= 8 || (dc_n % 4096) == 0)
                            dprintf( 2, "[decommit-zero] #%lu %s OK base=%p size=0x%lx branch=%s "
                                     "(zero) checked=%lu/%lu notzero=%lu/%lu rev=ml547\n",
                                     dc_n, dc_isarena ? "arena/pool" : "GUEST",
                                     base, (unsigned long)size, dc_branch,
                                     dc_lo, dc_hi, dcbad_lo, dcbad_hi );
                    }
                    else
                    {
                        /* print from the OFFENDING offset, not from base */
                        const unsigned char *b = (const unsigned char *)dc_verify + nz;
                        if (dc_isarena) dcbad_hi++; else dcbad_lo++;
                        dprintf( 2, "[decommit-zero] #%lu %s *** NOT ZEROED *** base=%p size=0x%lx "
                                 "branch=%s first_nonzero=+0x%lx checked=%lu/%lu notzero=%lu/%lu "
                                 "bytes@nz=%02x %02x %02x %02x %02x %02x %02x %02x rev=ml547\n",
                                 dc_n, dc_isarena ? "arena/pool" : "GUEST",
                                 base, (unsigned long)size, dc_branch, (unsigned long)nz,
                                 dc_lo, dc_hi, dcbad_lo, dcbad_hi,
                                 b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7] );
                    }
                }
                else if (!strcmp( dc_branch, "swap-hole" ))
                {
                    /* ml1258: a punched hole reads as zero; it is not read back only
                     * because that would fault file pages in under the lock. Rate-
                     * limited like the OK lines (swap log 1 had one per decommit). */
                    if (dc_n <= 8 || (dc_n % 4096) == 0)
                        dprintf( 2, "[decommit-zero] #%lu base=%p size=0x%lx branch=swap-hole "
                                 "(zero by hole, not read back)\n", dc_n, base, (unsigned long)size );
                }
                else
                    dprintf( 2, "[decommit-zero] #%lu base=%p size=0x%lx branch=%s "
                             "(no read-back: this branch does not zero)\n",
                             dc_n, base, (unsigned long)size, dc_branch );
            }
        }
    }
    /* ml610 [dc-census] AFTER sample + report. `returned` is the number three
     * builds have argued about without ever measuring it: dirty+swapped before
     * minus after, i.e. what this decommit actually handed back to the system.
     * A near-zero `returned` on a 16MB callret clear would mean the clear is
     * NOT a reclaim and ml609's premise was right after all — so this can
     * refute the change it ships with, which is the point. */
    if (dc_sampled)
    {
        long census_us, work_us;
        unsigned long long charged_before, charged_after;

        gettimeofday( &dc_t2, NULL );
        ios_dc_census_take( base, size, &dc_after );
        gettimeofday( &dc_t3, NULL );

        census_us = (long)((dc_t1.tv_sec - dc_t0.tv_sec) * 1000000 + (dc_t1.tv_usec - dc_t0.tv_usec))
                  + (long)((dc_t3.tv_sec - dc_t2.tv_sec) * 1000000 + (dc_t3.tv_usec - dc_t2.tv_usec));
        work_us   = (long)((dc_t2.tv_sec - dc_t1.tv_sec) * 1000000 + (dc_t2.tv_usec - dc_t1.tv_usec));

        charged_before = dc_before.dirty + dc_before.swapped;
        charged_after  = dc_after.dirty + dc_after.swapped;

        dprintf( 2, "[dc-census] ml610 base=%p size=%luKB branch=%s "
                 "dirty %lluKB->%lluKB swapped %lluKB->%lluKB charged %lluKB->%lluKB "
                 "returned=%lldKB | mincore_res %lluKB->%lluKB resident %lluKB->%lluKB "
                 "span=%lluKB(%s) fp %lluMB->%lluMB decommit_us=%ld census_us=%ld\n",
                 base, (unsigned long)(size >> 10), dc_branch,
                 dc_before.dirty >> 10, dc_after.dirty >> 10,
                 dc_before.swapped >> 10, dc_after.swapped >> 10,
                 charged_before >> 10, charged_after >> 10,
                 ((long long)charged_before - (long long)charged_after) >> 10,
                 dc_before.mincore_res >> 10, dc_after.mincore_res >> 10,
                 dc_before.resident >> 10, dc_after.resident >> 10,
                 dc_before.span >> 10,
                 dc_before.span > (unsigned long long)size ? "OVER-COUNTS: region exceeds range" : "clean",
                 dc_before.footprint >> 20, dc_after.footprint >> 20,
                 work_us, census_us );
    }

    set_page_vprot_bits( base, size, 0, VPROT_COMMITTED );
    if (host_start < host_end) kernel_writewatch_register_range( view, host_start, host_end - host_start );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           remove_pages_from_view
 *
 * Remove some pages of a given view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS remove_pages_from_view( struct file_view *view, char *base, size_t size )
{
    assert( size < view->size );

    if (view->base != base && base + size != (char *)view->base + view->size)
    {
        struct file_view *new_view = alloc_view();

        if (!new_view)
        {
            ERR( "out of memory for %p-%p\n", base, base + size );
            return STATUS_NO_MEMORY;
        }
        new_view->base    = base + size;
        new_view->size    = (char *)view->base + view->size - (char *)new_view->base;
        new_view->protect = view->protect;
        new_view->ios_flags = view->ios_flags;

        unregister_view( view );
        view->size = base - (char *)view->base;
        register_view( view );
        register_view( new_view );

        VIRTUAL_DEBUG_DUMP_VIEW( view );
        VIRTUAL_DEBUG_DUMP_VIEW( new_view );
    }
    else
    {
        unregister_view( view );
        if (view->base == base)
        {
            view->base = base + size;
            view->size -= size;
        }
        else view->size = base - (char *)view->base;

        register_view( view );
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           free_pages_preserve_placeholder
 *
 * Turn pages of a given view into a placeholder.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS free_pages_preserve_placeholder( struct file_view *view, char *base, size_t size )
{
    NTSTATUS status;

    if (!size) return STATUS_INVALID_PARAMETER_3;
    if (!(view->protect & VPROT_PLACEHOLDER)) return STATUS_CONFLICTING_ADDRESSES;
    if (view->protect & VPROT_FREE_PLACEHOLDER && size == view->size) return STATUS_CONFLICTING_ADDRESSES;

    if (size < view->size)
    {
        if ((UINT_PTR)base & host_page_mask ||
            ((size & host_page_mask) && base + size != (char *)view->base + view->size))
        {
            ERR( "unaligned partial free %p-%p\n", base, base + size );
            return STATUS_CONFLICTING_ADDRESSES;
        }

        status = remove_pages_from_view( view, base, size );
        if (status) return status;

        status = create_view( &view, base, size, VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER );
        if (status) return status;
    }

    view->protect = VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER;
    set_page_vprot( view->base, view->size, 0 );
    anon_mmap_fixed( view->base, ROUND_SIZE( 0, view->size, host_page_mask ), PROT_NONE, 0 );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           free_pages
 *
 * Free some pages of a given view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS free_pages( struct file_view *view, char *base, size_t size )
{
    char *host_base = (char *)ROUND_SIZE( 0, base, host_page_mask );
    char *host_end = base + size;
    NTSTATUS status;

    if (size == view->size)
    {
        assert( base == view->base );
        delete_view( view );
        return STATUS_SUCCESS;
    }

    /* new view needs to start on page boundary */

    if (view->base == base)  /* shrink from the start */
    {
        if (size & host_page_mask)
        {
            ERR( "unaligned partial free %p-%p\n", base, base + size );
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    else if (base + size < (char *)view->base + view->size)  /* create a hole */
    {
        if ((UINT_PTR)(base + size) & host_page_mask)
        {
            ERR( "unaligned partial free %p-%p\n", base, base + size );
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }

    status = remove_pages_from_view( view, base, size );
    if (!status)
    {
        set_page_vprot( base, size, 0 );
        if (view->protect & VPROT_ARM64EC) clear_arm64ec_range( base, size );
        if (host_base < host_end) unmap_area( host_base, host_end - host_base );
    }
    return status;
}


/***********************************************************************
 *           coalesce_placeholders
 *
 * Coalesce placeholder views.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS coalesce_placeholders( struct file_view *view, char *base, size_t size )
{
    struct rb_entry *next;
    struct file_view *curr_view, *next_view;
    unsigned int i, view_count = 0;
    size_t views_size = 0;

    if (!size) return STATUS_INVALID_PARAMETER_3;
    if (base != view->base) return STATUS_CONFLICTING_ADDRESSES;

    curr_view = view;
    while (curr_view->protect & VPROT_FREE_PLACEHOLDER)
    {
        ++view_count;
        views_size += curr_view->size;
        if (views_size >= size) break;
        if (!(next = rb_next( &curr_view->entry ))) break;
        next_view = RB_ENTRY_VALUE( next, struct file_view, entry );
        if ((char *)curr_view->base + curr_view->size != next_view->base) break;
        curr_view = next_view;
    }

    if (view_count < 2 || size != views_size) return STATUS_CONFLICTING_ADDRESSES;

    for (i = 1; i < view_count; ++i)
    {
        curr_view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
        unregister_view( curr_view );
        free_view( curr_view );
    }

    unregister_view( view );
    view->size = views_size;
    register_view( view );

    VIRTUAL_DEBUG_DUMP_VIEW( view );

    return STATUS_SUCCESS;
}


/***********************************************************************
 *           allocate_dos_memory
 *
 * Allocate the DOS memory range.
 */
static NTSTATUS allocate_dos_memory( struct file_view **view, unsigned int vprot )
{
    size_t size;
    void *addr = NULL;
    void * const low_64k = (void *)0x10000;
    const size_t dosmem_size = 0x110000;
    int unix_prot = get_unix_prot( vprot ) & ~PROT_EXEC;

    /* check for existing view */

    if (find_view_range( 0, dosmem_size )) return STATUS_CONFLICTING_ADDRESSES;

    /* check without the first 64K */

    if (mmap_is_in_reserved_area( low_64k, dosmem_size - 0x10000 ) != 1)
    {
        addr = anon_mmap_tryfixed( low_64k, dosmem_size - 0x10000, unix_prot, 0 );
        if (addr == MAP_FAILED) return map_view( view, NULL, dosmem_size, 0, vprot, 0, 0, 0 );
    }

    /* now try to allocate the low 64K too */

    if (mmap_is_in_reserved_area( NULL, 0x10000 ) != 1)
    {
        addr = anon_mmap_tryfixed( (void *)host_page_size, 0x10000 - host_page_size, unix_prot, 0 );
        if (addr != MAP_FAILED)
        {
            if (!anon_mmap_fixed( NULL, host_page_size, unix_prot, 0 ))
            {
                addr = NULL;
                TRACE( "successfully mapped low 64K range\n" );
            }
            else TRACE( "failed to map page 0\n" );
        }
        else
        {
            addr = low_64k;
            TRACE( "failed to map low 64K range\n" );
        }
    }

    /* now reserve the whole range */

    size = (char *)dosmem_size - (char *)addr;
    anon_mmap_fixed( addr, size, unix_prot, 0 );
    return create_view( view, addr, size, vprot );
}


/***********************************************************************
 *           map_pe_header
 *
 * Map the header of a PE file into memory.
 */
static NTSTATUS map_pe_header( void *ptr, size_t size, size_t map_size, int fd, BOOL *removable )
{
    if (!size) return STATUS_INVALID_IMAGE_FORMAT;

    map_size &= ~host_page_mask;

    if (!*removable && map_size)
    {
        if (mmap( ptr, map_size, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, 0 ) != MAP_FAILED)
        {
            if (size > map_size) pread( fd, (char *)ptr + map_size, size - map_size, map_size );
            return STATUS_SUCCESS;
        }
        switch (errno)
        {
        case EPERM:
        case EACCES:
            WARN( "noexec file system, falling back to read\n" );
            break;
        case ENOEXEC:
        case ENODEV:
            WARN( "file system doesn't support mmap, falling back to read\n" );
            break;
        default:
            ERR( "mmap error %s, range %p-%p\n", strerror(errno), ptr, (char *)ptr + size );
            return STATUS_NO_MEMORY;
        }
        *removable = TRUE;
    }
    pread( fd, ptr, size, 0 );
    return STATUS_SUCCESS;  /* page protections will be updated later */
}

#ifdef _WIN64

/***********************************************************************
 *           get_host_addr_space_limit
 */
/***********************************************************************
 *           ios_va_profile   (ml749)
 *
 * Does this task actually have usable VA between 32GB and 63GB?
 *
 * On the jailbroken research VM, FEX never gets an arena: both candidate
 * windows come back FAILED with tries=0, because both START above the ceiling
 * Wine believes it has --
 *     [0x7c00000000,0x800000000)  = 496GB..32GB   inverted
 *     [0x00c00000000,0x800000000) = 48GB..32GB    inverted
 * -- so the scanner never looks, FEXMem_ThreadState is never allocated, x28
 * stays NULL and init dereferences x28+0x7f0. cube dies before its first guest
 * instruction. On the phone the same fallback band works fine, and physical
 * iOS 26 proves a 64GB regime is sufficient, so the extended 448-512GB regime
 * is NOT required.
 *
 * The suspicion is that Wine UNDERESTIMATES the VM rather than the VM being
 * incapable. get_host_addr_space_limit() probes only POWERS OF TWO and, since
 * MAP_FIXED_NOREPLACE does not exist on Darwin, `addr` is a mere HINT the
 * kernel may ignore -- so an unhonoured hint at 32GB silently demotes the
 * conclusion to 16GB and reports a 32GB ceiling. By construction it can never
 * discover that 48-56GB is usable.
 *
 * Settle it by ASKING THE KERNEL DIRECTLY at fixed addresses, which is what the
 * power-of-two hint walk cannot do. mach_vm_allocate with VM_FLAGS_FIXED does
 * not clobber an existing mapping -- it returns KERN_NO_SPACE -- so this is
 * safe to run unconditionally, and every success is released immediately.
 */
static void ios_va_profile( const char *when )
{
    static const struct { unsigned long long addr; const char *band; } probes[] = {
        { 0x0880000000ULL, "32-40GB" }, { 0x0900000000ULL, "32-40GB" },
        { 0x0A00000000ULL, "40-48GB" }, { 0x0B00000000ULL, "40-48GB" },
        { 0x0C00000000ULL, "48-56GB" }, { 0x0D00000000ULL, "48-56GB" },
        { 0x0E00000000ULL, "56-63GB" }, { 0x0F00000000ULL, "56-63GB" },
        { 0x7C00000000ULL, "496GB (preferred FEX)" },
    };
    task_vm_info_data_t vmi;
    mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;
    unsigned i;

    if (task_info( mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &cnt ) == KERN_SUCCESS)
        dprintf( 2, "[va-profile] ml749 %s TASK_VM_INFO.max_address=%p (%.1f GB)\n",
                 when, (void *)(uintptr_t)vmi.max_address,
                 (double)vmi.max_address / (1024.0*1024.0*1024.0) );
    else
        dprintf( 2, "[va-profile] ml749 %s TASK_VM_INFO UNAVAILABLE\n", when );

    dprintf( 2, "[va-profile] ml749 %s host_addr_space_limit=%p address_space_limit=%p user_space_limit=%p\n",
             when, host_addr_space_limit, address_space_limit, user_space_limit );

    for (i = 0; i < ARRAY_SIZE(probes); i++)
    {
        mach_vm_address_t a = probes[i].addr;
        kern_return_t kr = mach_vm_allocate( mach_task_self(), &a, 0x4000, VM_FLAGS_FIXED );
        dprintf( 2, "[va-profile] ml749 %s fixed 16KB @ 0x%llx (%-22s) -> %s (kr=%d)\n",
                 when, probes[i].addr, probes[i].band,
                 kr == KERN_SUCCESS ? "MAPPABLE" : "refused", (int)kr );
        if (kr == KERN_SUCCESS) mach_vm_deallocate( mach_task_self(), a, 0x4000 );
    }
    /* ml898: measure the kernel's range for VM_MEMORY_LAYERKIT (51), the tag
     * CoreAnimation allocates its render shmem with. ml896 proved those
     * allocations interleave with Wine's guest views around 20-30 GB and hit
     * KERN_NO_SPACE a third of the time once a game is running. Fill the range
     * with 256 MB chunks until it refuses, record the span, give it all back.
     * Runs before any guest view exists, so the span is the kernel's, not ours. */
    {
        mach_vm_address_t got[128]; unsigned n = 0; kern_return_t kr = KERN_SUCCESS;
        mach_vm_address_t lo = ~0ULL, hi = 0;
        while (n < 128)
        {
            mach_vm_address_t a = 0;
            kr = mach_vm_allocate( mach_task_self(), &a, 256ULL << 20, VM_FLAGS_ANYWHERE | VM_MAKE_TAG(51) );
            if (kr != KERN_SUCCESS) break;
            got[n++] = a; if (a < lo) lo = a; if (a + (256ULL << 20) > hi) hi = a + (256ULL << 20);
        }
        dprintf( 2, "[layerkit-range] rev=ml898 %s: %u x 256MB tag-51 chunks before kr=%d; span 0x%llx..0x%llx (%llu MB) -- guest views must stay OUT of this\n",
                 when, n, kr, (unsigned long long)lo, (unsigned long long)hi, (unsigned long long)((hi - lo) >> 20) );
        if (n && !ios_layerkit_hi) { ios_layerkit_lo = lo; ios_layerkit_hi = hi; }   /* ml900: first measurement wins */
        while (n) { n--; mach_vm_deallocate( mach_task_self(), got[n], 256ULL << 20 ); }
    }
}


/***********************************************************************
 *           ios_clamp_user_space_limit                           (ml990)
 *
 * Never advertise more user address space than this device can actually map.
 *
 * rdr59 got RDR2 all the way to a successful D3D12CreateDevice, and it then
 * asked VirtualAlloc for 0x700000000 (28,672 MB) of MEM_RESERVE|PAGE_NOACCESS.
 * That failed with STATUS_NO_MEMORY: the largest free hole below the ceiling is
 * 4299 MB, and [va-gaps] measured only 6603 MB free in total.
 *
 * The request is not arbitrary. GlobalMemoryStatusEx derives ullTotalVirtual
 * from HighestUserAddress (kernelbase/memory.c:1436 minus LowestUserAddress),
 * HighestUserAddress comes from user_space_limit (virtual_ios.c:13146), and
 * that was still Windows' theoretical 0x7fffffff0000 = 128 TB -- while
 * TASK_VM_INFO.max_address on this device is 0xfc0000000 = 63.0 GB. Any engine
 * that sizes a reservation against the address space we advertise will ask for
 * something that can never exist here.
 *
 * So this is an accuracy fix, not a per-title workaround: 128 TB is the wrong
 * answer for every caller of GlobalMemoryStatusEx, GetSystemInfo's
 * lpMaximumApplicationAddress and NtQuerySystemInformation, on every iOS
 * device. ml124 already applied exactly this reasoning to size the ARM64EC code
 * bitmap ("nothing on iOS can be mapped at or above host_addr_space_limit");
 * this extends the same measured ceiling to what we tell applications.
 *
 * Correct on both targets without a special case: the jailbroken VM measures a
 * 63 GB ceiling, the A15 phone 512 GB, and in both cases nothing above
 * host_addr_space_limit is mappable.
 *
 * MADEIRA_WIDE_USER_VA=1 restores the old 128 TB claim.
 */
static void ios_clamp_user_space_limit( const char *when )
{
    static int disabled = -1;

    if (disabled < 0) disabled = getenv( "MADEIRA_WIDE_USER_VA" ) ? 1 : 0;
    if (disabled) return;
    if (!host_addr_space_limit || user_space_limit <= host_addr_space_limit) return;

    dprintf( 2, "ml990: %s user_space_limit %p -> %p -- refusing to advertise address space this "
             "device cannot map (HighestUserAddress / ullTotalVirtual / "
             "lpMaximumApplicationAddress all derive from it)\n",
             when, user_space_limit, host_addr_space_limit );
    user_space_limit = host_addr_space_limit;
}

static void *get_host_addr_space_limit(void)
{
    unsigned int flags = MAP_PRIVATE | MAP_ANON;
    UINT_PTR addr = (UINT_PTR)1 << 63;

#ifdef MAP_FIXED_NOREPLACE
    flags |= MAP_FIXED_NOREPLACE;
#endif

    while (addr >> 32)
    {
        void *ret = mmap( (void *)addr, host_page_size, PROT_NONE, flags, -1, 0 );
        if (ret != MAP_FAILED)
        {
            ios_pool_va_warn( "munmap", ret, host_page_size );
            munmap( ret, host_page_size );
            if (ret >= (void *)addr) break;
        }
        else if (errno == EEXIST) break;
        addr >>= 1;
    }
    /* ml122 THE TOP-SLOT UNLOCK. Upstream subtracts one allocation granule
     * here, which makes host_addr_space_limit 0x7fffff0000 on iOS: 64KB below
     * the true 512GB boundary. is_beyond_limit() treats limit as EXCLUSIVE
     * (addr + size > limit rejects), so that granule of conservatism rejects
     * any mapping ending exactly at 0x8000000000 -- which is every possible
     * 16GB reservation in the top slot [0x7c00000000, 0x8000000000). That is
     * why PartitionAlloc's plain pool kept falling through 0x7c00000000 to
     * 0x7800000000 (ml120, ml122), stealing the ONLY slot the guard-style pool
     * can use (a guard pool needs 64KB free below its 16GB boundary, and the
     * top slot has the end of the address space above it, so it can never host
     * one). Net effect: one pool instead of two. (addr << 1) is already the
     * first UNMAPPABLE address, which is exactly the exclusive bound
     * is_beyond_limit wants, so return it unmodified. */
    {
        /* ml749: PREFER THE KERNEL'S OWN ANSWER OVER THE POWER-OF-TWO WALK.
         *
         * The loop above can only ever conclude a POWER OF TWO -- 16GB, 32GB,
         * 64GB, nothing between -- and since MAP_FIXED_NOREPLACE does not exist
         * on Darwin, `addr` is only a HINT the kernel may decline, which is why
         * it has to check `ret >= addr`. One unhonoured hint therefore halves
         * the conclusion. On the jailbroken research VM that lands on 32GB
         * against a real 63GB ceiling, and every FEX arena window inverts:
         * [48GB,32GB) scans nothing, FEXMem_ThreadState is never allocated,
         * x28 stays NULL and cube dies at x28+0x7f0 before its first guest
         * instruction. Fixed 16KB reservations at 52, 55 and 57GB all succeed
         * there, so the range is real and only our estimate was wrong.
         *
         * TASK_VM_INFO.max_address is the map's actual ceiling and needs no
         * hint to be honoured. It is EXCLUSIVE, which is what is_beyond_limit()
         * wants, matching the ml122 note above.
         *
         * Only ever RAISE the walk's answer, never lower it: the walk is proven
         * on hardware, and a device reporting a small or bogus max_address must
         * not shrink a limit that already works. Both values are logged so the
         * two can be compared on any device. */
        void *walked = (void *)(addr << 1);
        task_vm_info_data_t vmi;
        mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;

        if (task_info( mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &cnt ) == KERN_SUCCESS)
        {
            void *kern = (void *)(uintptr_t)vmi.max_address;

            dprintf( 2, "[va-limit] ml749 walk=%p kernel_max=%p -> %s\n",
                     walked, kern, kern > walked ? "USING KERNEL (walk underestimated)" : "keeping walk" );
            if (kern > walked && (uintptr_t)kern >= 0x100000000ULL) return kern;
        }
        else dprintf( 2, "[va-limit] ml749 walk=%p kernel_max=UNAVAILABLE -> keeping walk\n", walked );

        return walked;
    }
}

#endif /* _WIN64 */

#ifdef __aarch64__

/***********************************************************************
 *           alloc_arm64ec_map
 */
static void alloc_arm64ec_map(void)
{
    unsigned int status;
    /* ml124: size the EC bitmap from the address space that can actually EXIST,
     * not Windows' theoretical one. Upstream uses address_space_limit =
     * 0x7fffffff0000 (128TB), and at one bit per 4KB page that is a 4.06GB
     * reservation -- measured as [window] run#0, the single largest tenant of
     * the furniture window. Nothing on iOS can be mapped at or above
     * host_addr_space_limit (0x8000000000 = 512GB), so every address that can
     * ever be marked indexes below 0x8000000000 >> 15 = 16MB. That is a 256x
     * cut for 4.06GB back, and unlike the ~512MB-per-thread FEX LookupCache
     * reservations it does not scale with thread count.
     *
     * Safe because every other bitmap user derives its byte index from the
     * ADDRESS being marked ((size_t)addr >> 12 / 8) and commits through
     * set_vprot on this same view -- none of them recompute the size from
     * address_space_limit, so none can index past the smaller view while the
     * VA ceiling holds. */
    ULONG_PTR ec_limit = (ULONG_PTR)address_space_limit;
    if (host_addr_space_limit && (ULONG_PTR)host_addr_space_limit < ec_limit)
        ec_limit = (ULONG_PTR)host_addr_space_limit;
    SIZE_T size = (ec_limit + page_size) >> (page_shift + 3);  /* one bit per page */

    size = ROUND_SIZE( 0, size, host_page_mask );
    status = map_view( &arm64ec_view, NULL, size, MEM_TOP_DOWN, VPROT_READ | VPROT_COMMITTED, 0, 0, 0 );
    if (status)
    {
        ERR( "failed to allocate ARM64EC map: %08x\n", status );
        exit(1);
    }
    peb->EcCodeBitMap = arm64ec_view->base;
    /* ml127: dprintf, not ERR — the `virtual` channel's ERR is suppressed in
     * this build, which is why this line has never once appeared in a log. */
    dprintf(2, "[ec-map] peb->EcCodeBitMap=%p size=0x%lx (%lu MB)\n",
            peb->EcCodeBitMap, (unsigned long)size, (unsigned long)(size >> 20));
}


/***********************************************************************
 *           update_arm64ec_ranges
 */
static void update_arm64ec_ranges( struct file_view *view, IMAGE_NT_HEADERS *nt,
                                   const IMAGE_DATA_DIRECTORY *dir, UINT *entry_point )
{
    const IMAGE_ARM64EC_METADATA *metadata;
    const IMAGE_CHPE_RANGE_ENTRY *map;
    char *base = view->base;
    const IMAGE_LOAD_CONFIG_DIRECTORY *cfg = (void *)(base + dir->VirtualAddress);
    ULONG i, size = min( dir->Size, cfg->Size );

    if (size <= offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer )) return;
    if (!cfg->CHPEMetadataPointer) return;
    if (!arm64ec_view) alloc_arm64ec_map();
    commit_arm64ec_map( view );
    metadata = (void *)(base + (cfg->CHPEMetadataPointer - nt->OptionalHeader.ImageBase));
    *entry_point = redirect_arm64ec_rva( base, nt->OptionalHeader.AddressOfEntryPoint, metadata );
    if (!metadata->CodeMap) return;
    map = (void *)(base + metadata->CodeMap);

    for (i = 0; i < metadata->CodeMapCount; i++)
    {
        if ((map[i].StartOffset & 0x3) != 1 /* arm64ec */) continue;
        set_arm64ec_range( base + (map[i].StartOffset & ~3), map[i].Length );
    }
}


/***********************************************************************
 *           apply_arm64x_relocations
 */
static void apply_arm64x_relocations( char *base, const IMAGE_BASE_RELOCATION *reloc, size_t size )
{
    const IMAGE_BASE_RELOCATION *reloc_end = (const IMAGE_BASE_RELOCATION *)((const char *)reloc + size);

    while (reloc < reloc_end - 1 && reloc->SizeOfBlock)
    {
        const USHORT *rel = (const USHORT *)(reloc + 1);
        const USHORT *rel_end = (const USHORT *)reloc + reloc->SizeOfBlock / sizeof(USHORT);
        char *page = base + reloc->VirtualAddress;

        while (rel < rel_end && *rel)
        {
            USHORT offset = *rel & 0xfff;
            USHORT type = (*rel >> 12) & 3;
            USHORT arg = *rel >> 14;
            int val;
            rel++;
            switch (type)
            {
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL:
                memset( page + offset, 0, 1 << arg );
                break;
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE:
                memcpy( page + offset, rel, 1 << arg );
                rel += (1 << arg) / sizeof(USHORT);
                break;
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA:
                val = (unsigned int)*rel++ * ((arg & 2) ? 8 : 4);
                if (arg & 1) val = -val;
                *(int *)(page + offset) += val;
                break;
            }
        }
        reloc = (const IMAGE_BASE_RELOCATION *)rel_end;
    }
}


/***********************************************************************
 *           update_arm64x_mapping
 */
static void update_arm64x_mapping( struct file_view *view, IMAGE_NT_HEADERS *nt,
                                   const IMAGE_DATA_DIRECTORY *dir, IMAGE_SECTION_HEADER *sections )
{
    const IMAGE_DYNAMIC_RELOCATION_TABLE *table;
    const char *ptr, *end;
    char *base = view->base;
    const IMAGE_LOAD_CONFIG_DIRECTORY *cfg = (void *)(base + dir->VirtualAddress);
    ULONG sec, offset, size = min( dir->Size, cfg->Size );

    if (size <= offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, DynamicValueRelocTableSection )) return;
    offset = cfg->DynamicValueRelocTableOffset;
    sec = cfg->DynamicValueRelocTableSection;
    if (!sec || sec > nt->FileHeader.NumberOfSections) return;
    if (offset >= sections[sec - 1].Misc.VirtualSize) return;
    table = (const IMAGE_DYNAMIC_RELOCATION_TABLE *)(base + sections[sec - 1].VirtualAddress + offset);
    ptr = (const char *)(table + 1);
    end = ptr + table->Size;
    switch (table->Version)
    {
    case 1:
        while (ptr < end)
        {
            const IMAGE_DYNAMIC_RELOCATION64 *dyn = (const IMAGE_DYNAMIC_RELOCATION64 *)ptr;
            if (dyn->Symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X)
            {
                apply_arm64x_relocations( base, (const IMAGE_BASE_RELOCATION *)(dyn + 1),
                                          dyn->BaseRelocSize );
                break;
            }
            ptr += sizeof(*dyn) + dyn->BaseRelocSize;
        }
        break;
    case 2:
        while (ptr < end)
        {
            const IMAGE_DYNAMIC_RELOCATION64_V2 *dyn = (const IMAGE_DYNAMIC_RELOCATION64_V2 *)ptr;
            if (dyn->Symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X)
            {
                apply_arm64x_relocations( base, (const IMAGE_BASE_RELOCATION *)(dyn + 1),
                                          dyn->FixupInfoSize );
                break;
            }
            ptr += dyn->HeaderSize + dyn->FixupInfoSize;
        }
        break;
    default:
        FIXME( "unsupported version %u\n", table->Version );
        break;
    }
}

#endif  /* __aarch64__ */

/***********************************************************************
 *           get_data_dir
 */
static IMAGE_DATA_DIRECTORY *get_data_dir( IMAGE_NT_HEADERS *nt, SIZE_T total_size, ULONG dir )
{
    IMAGE_DATA_DIRECTORY *data;

    switch (nt->OptionalHeader.Magic)
    {
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        if (dir >= ((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        data = &((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.DataDirectory[dir];
        break;
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        if (dir >= ((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.NumberOfRvaAndSizes) return NULL;
        data = &((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.DataDirectory[dir];
        break;
    default:
        return NULL;
    }
    if (!data->Size) return NULL;
    if (!data->VirtualAddress) return NULL;
    if (data->VirtualAddress >= total_size) return NULL;
    if (data->Size > total_size - data->VirtualAddress) return NULL;
    return data;
}


/***********************************************************************
 *           process_relocation_block
 *
 * Reimplementation of LdrProcessRelocationBlock.
 */
static IMAGE_BASE_RELOCATION *process_relocation_block( char *page, IMAGE_BASE_RELOCATION *rel,
                                                        INT_PTR delta )
{
    USHORT *reloc = (USHORT *)(rel + 1);
    unsigned int count;

    for (count = (rel->SizeOfBlock - sizeof(*rel)) / sizeof(USHORT); count; count--, reloc++)
    {
        USHORT offset = *reloc & 0xfff;
        switch (*reloc >> 12)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
            break;
        case IMAGE_REL_BASED_HIGH:
            *(short *)(page + offset) += HIWORD(delta);
            break;
        case IMAGE_REL_BASED_LOW:
            *(short *)(page + offset) += LOWORD(delta);
            break;
        case IMAGE_REL_BASED_HIGHLOW:
            *(int *)(page + offset) += delta;
            break;
        case IMAGE_REL_BASED_DIR64:
            *(INT64 *)(page + offset) += delta;
            break;
        case IMAGE_REL_BASED_THUMB_MOV32:
        {
            DWORD *inst = (DWORD *)(page + offset);
            WORD lo = ((inst[0] << 1) & 0x0800) + ((inst[0] << 12) & 0xf000) +
                      ((inst[0] >> 20) & 0x0700) + ((inst[0] >> 16) & 0x00ff);
            WORD hi = ((inst[1] << 1) & 0x0800) + ((inst[1] << 12) & 0xf000) +
                      ((inst[1] >> 20) & 0x0700) + ((inst[1] >> 16) & 0x00ff);
            DWORD imm = MAKELONG( lo, hi ) + delta;

            lo = LOWORD( imm );
            hi = HIWORD( imm );
            inst[0] = (inst[0] & 0x8f00fbf0) + ((lo >> 1) & 0x0400) + ((lo >> 12) & 0x000f) +
                                               ((lo << 20) & 0x70000000) + ((lo << 16) & 0xff0000);
            inst[1] = (inst[1] & 0x8f00fbf0) + ((hi >> 1) & 0x0400) + ((hi >> 12) & 0x000f) +
                                               ((hi << 20) & 0x70000000) + ((hi << 16) & 0xff0000);
            break;
        }
        default:
            FIXME( "Unknown/unsupported relocation %x\n", *reloc );
            return NULL;
        }
    }
    return (IMAGE_BASE_RELOCATION *)reloc;  /* return address of next block */
}


/* A shared writable image section that is not aligned to the host page is mapped private.
 *
 * A section marked IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE is file-mapped
 * MAP_SHARED from the server's shared-section file, so every process that maps
 * the image sees the same bytes.  mmap works in host pages (16 KB here) and PE
 * sections are aligned to 4 KB: a shared section that does not start and end on
 * a host page cannot be file-mapped without replacing its neighbours' bytes, so
 * map_file_into_view refuses it ("unaligned shared mapping"), the image load
 * failed with STATUS_INVALID_IMAGE_FORMAT and the program never started.  Such
 * a section is now loaded like any other writable section, from the image file:
 * its contents are right, but writes are not seen by other processes that map
 * the same image.  One log line names each section this happens to.
 */
static int ios_shared_section_private(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        /* 0 fails the load of an image whose shared writable section is not aligned to the
         * host page, as before; otherwise that section is mapped private. */
        const char *e = getenv( "MADEIRA_SHARED_SECTION_PRIVATE" );
        enabled = !(e && e[0] == '0');
    }
    return enabled;
}

/***********************************************************************
 *           ios_subfloor_window_held
 *
 * iOS-Madeira ml1204: does the ml938 window for `low` belong to a live
 * RELOCS_STRIPPED image other than `real`? Such an image runs at its low
 * addresses and cannot work without the window, while a relocatable image with
 * the same preferred base has been relocated and runs high. A Delphi program
 * (fixed 0x400000) loaded a relocatable plugin DLL with the same preferred base:
 * the plugin re-pointed the window, FEX then ran the plugin's bytes at the
 * program's RIPs and the program's data at 0x77e360 fell outside the window
 * (c0000005). Otherwise the last registration in a process wins. The holder's
 * headers are read fault-safe (mach_vm_read_overwrite): it may have made its
 * header page PAGE_NOACCESS. virtual_mutex must be held.
 */
static BOOL ios_subfloor_window_held( ULONG_PTR low, ULONG_PTR real )
{
    extern int ios_subfloor_enum( int idx, unsigned long long *low, unsigned long long *real,
                                  unsigned long long *size, void **owner );
    void *peb = ios_jit_current_peb(), *own;
    unsigned long long lo, re, sz;
    int i;

    for (i = 0; ios_subfloor_enum( i, &lo, &re, &sz, &own ); i++)
    {
        struct file_view *old;
        IMAGE_DOS_HEADER dos;
        IMAGE_FILE_HEADER fh;
        mach_vm_size_t got = 0;

        if (!sz || own != peb) continue;   /* ml1205: only this process's window */
        if (lo != low || re == real) continue;
        if (!(old = find_view( (void *)(ULONG_PTR)re, 0 ))) return FALSE;
        if (old->base != (void *)(ULONG_PTR)re || !(old->protect & SEC_IMAGE)) return FALSE;
        if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)re, sizeof(dos),
                                    (mach_vm_address_t)&dos, &got ) != KERN_SUCCESS || got != sizeof(dos))
            return FALSE;
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 ||
            (size_t)dos.e_lfanew + offsetof( IMAGE_NT_HEADERS, OptionalHeader ) > old->size)
            return FALSE;
        if (mach_vm_read_overwrite( mach_task_self(),
                                    (mach_vm_address_t)(re + dos.e_lfanew + offsetof( IMAGE_NT_HEADERS, FileHeader )),
                                    sizeof(fh), (mach_vm_address_t)&fh, &got ) != KERN_SUCCESS || got != sizeof(fh))
            return FALSE;
        return (fh.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0;
    }
    return FALSE;
}


/***********************************************************************
 *           map_image_into_view
 *
 * Map an executable (PE format) image into an existing view.
 * virtual_mutex must be held by caller.
 */
static NTSTATUS map_image_into_view( struct file_view *view, const UNICODE_STRING *nt_name, int fd,
                                     struct pe_image_info *image_info, USHORT machine,
                                     int shared_fd, BOOL removable )
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sections = NULL, *sec;
    IMAGE_DATA_DIRECTORY *imports, *dir;
    NTSTATUS status = STATUS_CONFLICTING_ADDRESSES;
    int i;
    off_t pos;
    struct stat st;
    char *header_end;
    char *ptr = view->base;
    SIZE_T header_size, header_map_size, total_size = view->size;
    SIZE_T align_mask = max( image_info->alignment - 1, page_mask );
    INT_PTR delta;

#ifdef WINE_IOS
    ios_wow_note_image( view->base, nt_name );   /* ml1282 */
#endif

    TRACE_(module)( "mapping PE file %s at %p-%p\n", debugstr_us(nt_name), ptr, ptr + total_size );

    /* Verbose per-section logging removed; error paths still log */

#ifdef WINE_IOS
    /* iOS: server hands us a high ASLR map_addr (e.g. 0x6fffff880000) that the
     * iOS user-space-limit rejects, so map_view falls back to a low address
     * (e.g. 0xebf6a0000). Wine's perform_relocations below uses
     * (image_info->map_addr - image_info->base) for delta — that produces the
     * WRONG delta if map_addr disagrees with ptr. Force them to match so all
     * ARM64 PC-relative relocations (ADRP/ADR/BRANCH26) target real addresses. */
    /* WoW64 guest window: an image mapped inside this process's window is
     * addressed by guest code as host - B, so the relocation target (and the
     * OptionalHeader.ImageBase written below) must be the GUEST base, not the
     * host mapping address.  Outside a window the two are the same. */
    if (image_info->map_addr)
    {
        uintptr_t reloc_base = (uintptr_t)ptr;

        if (ios_wow_in_window( ptr )) reloc_base -= ios_wow_base();
        if (image_info->map_addr != reloc_base)
        {
            ERR("iOS: forcing map_addr 0x%lx -> 0x%lx (view base %p%s) so reloc delta is correct\n",
                (unsigned long)image_info->map_addr, (unsigned long)reloc_base, ptr,
                reloc_base != (uintptr_t)ptr ? ", guest window" : "");
            image_info->map_addr = reloc_base;
        }
    }
#endif

    /* map the header */

    fstat( fd, &st );
    header_size = min( image_info->header_size, st.st_size );
    header_map_size = min( image_info->header_map_size, ROUND_SIZE( 0, st.st_size, host_page_mask ));
    if ((status = map_pe_header( view->base, header_size, header_map_size, fd, &removable )))
    {
        ERR("[map_image_into_view] map_pe_header FAILED: 0x%x st_size=0x%llx\n", status, (unsigned long long)st.st_size);
        return status;
    }

    status = STATUS_INVALID_IMAGE_FORMAT;  /* generic error */
    /* ml143 [img-fmt]: steamwebhelper's dbghelp.dll import fails with
     * c000007b AFTER dbghelp already mapped twice in this same run, and the
     * mixed-arch sysx64 fallback is never even attempted for it. This function
     * has seven distinct ways to return INVALID_IMAGE_FORMAT and the log says
     * only "failed (error c000007b)", so name the branch that actually fires
     * instead of inferring a third time. */
#define IOS_IMG_FAIL(n) do { \
        dprintf(2, "[img-fmt] %s: reject #%d (machine=0x%x sections=%u align=0x%x/0x%x flags=0x%x)\n", \
                debugstr_us(nt_name), (n), nt->FileHeader.Machine, \
                nt->FileHeader.NumberOfSections, \
                (unsigned)nt->OptionalHeader.FileAlignment, \
                (unsigned)nt->OptionalHeader.SectionAlignment, \
                (unsigned)image_info->image_flags); \
    } while (0)
    dos = (IMAGE_DOS_HEADER *)ptr;
    nt = (IMAGE_NT_HEADERS *)(ptr + dos->e_lfanew);
    header_end = ptr + ROUND_SIZE( 0, header_size, align_mask );
    memset( ptr + header_size, 0, header_end - (ptr + header_size) );
    if ((char *)(nt + 1) > header_end) do { IOS_IMG_FAIL(1); return status; } while (0);
    sec = IMAGE_FIRST_SECTION( nt );
    if ((char *)(sec + nt->FileHeader.NumberOfSections) > header_end) do { IOS_IMG_FAIL(2); return status; } while (0);
    if ((char *)(sec + nt->FileHeader.NumberOfSections) > ptr + image_info->header_map_size)
    {
        /* copy section data since it will get overwritten by a section mapping */
        if (!(sections = malloc( sizeof(*sections) * nt->FileHeader.NumberOfSections )))
            return STATUS_NO_MEMORY;
        memcpy( sections, sec, sizeof(*sections) * nt->FileHeader.NumberOfSections );
        sec = sections;
    }
    imports = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_IMPORT );

    /* check for non page-aligned binary */

    if (image_info->image_flags & IMAGE_FLAGS_ImageMappedFlat)
    {
        /* unaligned sections, this happens for native subsystem binaries */
        /* in that case Windows simply maps in the whole file */

        total_size = min( total_size, ROUND_SIZE( 0, st.st_size, page_mask ));
        if (map_file_into_view( view, fd, 0, total_size, 0, VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY,
                                removable ) != STATUS_SUCCESS) do { IOS_IMG_FAIL(3); goto done; } while (0);

        /* check that all sections are loaded at the right offset */
        if (nt->OptionalHeader.FileAlignment != nt->OptionalHeader.SectionAlignment) do { IOS_IMG_FAIL(4); goto done; } while (0);
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            if (sec[i].VirtualAddress != sec[i].PointerToRawData)
                do { IOS_IMG_FAIL(5); goto done; } while (0);  /* Windows refuses to load in that case too */
        }

        /* set the image protections */
        set_vprot( view, ptr, total_size, VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY | VPROT_EXEC );

        /* no relocations are performed on non page-aligned binaries */
        status = STATUS_SUCCESS;
        do { IOS_IMG_FAIL(6); goto done; } while (0);
    }


    /* map all the sections */

#ifdef WINE_IOS
    /* madeira-bcd swap-images: the sections of the images [x64-image] marks
     * below (same test, VPROT_ARM64EC aside: ios_swap_image_flush re-checks the
     * mark) are noted as they are read; see ios_swap_image_note. */
    ios_swap_image_npend = 0;
    ios_swap_image_armed = ios_swap_images_enabled() && ios_x64_image_nocopy_enabled() && !ios_map_resource_view &&
                           !ios_wow_base() && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
                           nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                           !image_info->is_hybrid && !image_info->wine_builtin;
#endif
    for (i = pos = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        static const SIZE_T sector_align = 0x1ff;
        SIZE_T map_size, file_start, file_size, end;

        if (!sec[i].Misc.VirtualSize)
            map_size = ROUND_SIZE( 0, sec[i].SizeOfRawData, align_mask );
        else
            map_size = ROUND_SIZE( 0, sec[i].Misc.VirtualSize, align_mask );

        /* file positions are rounded to sector boundaries regardless of OptionalHeader.FileAlignment */
        file_start = sec[i].PointerToRawData & ~sector_align;
        file_size = ROUND_SIZE( sec[i].PointerToRawData, sec[i].SizeOfRawData, sector_align );
        if (file_size > map_size) file_size = map_size;

        /* a few sanity checks */
        end = sec[i].VirtualAddress + ROUND_SIZE( sec[i].VirtualAddress, map_size, align_mask );
        if (sec[i].VirtualAddress > total_size || end > total_size || end < sec[i].VirtualAddress)
        {
            WARN_(module)( "%s section %.8s too large (%x+%lx/%lx)\n",
                           debugstr_us(nt_name), sec[i].Name, sec[i].VirtualAddress, map_size, total_size );
            do { IOS_IMG_FAIL(7); goto done; } while (0);
        }

        if ((sec[i].Characteristics & IMAGE_SCN_MEM_SHARED) &&
            (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            TRACE_(module)( "%s mapping shared section %.8s at %p off %x (%x) size %lx (%lx) flags %x\n",
                            debugstr_us(nt_name), sec[i].Name, ptr + sec[i].VirtualAddress,
                            sec[i].PointerToRawData, (int)pos, file_size, map_size,
                            sec[i].Characteristics );
            NTSTATUS shared_status = map_file_into_view( view, shared_fd, sec[i].VirtualAddress, map_size, pos,
                                                         VPROT_COMMITTED | VPROT_READ | VPROT_WRITE, FALSE );

            if (shared_status == STATUS_INVALID_PARAMETER && ios_shared_section_private())
            {
                /* not host-page aligned: see ios_shared_section_private */
                dprintf( 2, "[shared-section] %s section %.8s rva=0x%x size=0x%lx is not aligned to the "
                            "0x%lx-byte host page: mapped private, its writes are not shared between "
                            "processes (MADEIRA_SHARED_SECTION_PRIVATE=0 fails the load instead)\n",
                         debugstr_us(nt_name), sec[i].Name, (unsigned)sec[i].VirtualAddress,
                         (unsigned long)map_size, (unsigned long)host_page_size );
                pos += map_size;
                goto private_section;
            }
            if (shared_status != STATUS_SUCCESS)
            {
                ERR_(module)( "Could not map %s shared section %.8s\n", debugstr_us(nt_name), sec[i].Name );
                dprintf( 2, "[shared-section] %s section %.8s rva=0x%x size=0x%lx: shared mapping failed, "
                            "status=0x%x shared_fd=%d\n", debugstr_us(nt_name), sec[i].Name,
                         (unsigned)sec[i].VirtualAddress, (unsigned long)map_size,
                         (unsigned)shared_status, shared_fd );
                do { IOS_IMG_FAIL(8); goto done; } while (0);
            }

            /* check if the import directory falls inside this section */
            if (imports && imports->VirtualAddress >= sec[i].VirtualAddress &&
                imports->VirtualAddress < sec[i].VirtualAddress + map_size)
            {
                UINT_PTR base = imports->VirtualAddress & ~host_page_mask;
                UINT_PTR end = base + ROUND_SIZE( imports->VirtualAddress, imports->Size, host_page_mask );
                if (end > sec[i].VirtualAddress + map_size) end = sec[i].VirtualAddress + map_size;
                if (end > base)
                    map_file_into_view( view, shared_fd, base, end - base,
                                        pos + (base - sec[i].VirtualAddress),
                                        VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY, FALSE );
            }
            pos += map_size;
            continue;
        }

    private_section:
        TRACE_(module)( "mapping %s section %.8s at %p off %x size %x virt %x flags %x\n",
                        debugstr_us(nt_name), sec[i].Name, ptr + sec[i].VirtualAddress,
                        sec[i].PointerToRawData, sec[i].SizeOfRawData,
                        sec[i].Misc.VirtualSize, sec[i].Characteristics );

        if (!sec[i].PointerToRawData || !file_size) continue;

        /* Note: if the section is not aligned properly map_file_into_view will magically
         *       fall back to read(), so we don't need to check anything here.
         */
        end = file_start + file_size;
        if (sec[i].PointerToRawData >= st.st_size ||
            end > ((st.st_size + sector_align) & ~sector_align) ||
            end < file_start ||
            map_file_into_view( view, fd, sec[i].VirtualAddress, file_size, file_start,
                                VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY,
                                removable ) != STATUS_SUCCESS)
        {
            ERR_(module)( "Could not map %s section %.8s, file probably truncated\n",
                          debugstr_us(nt_name), sec[i].Name );
            do { IOS_IMG_FAIL(9); goto done; } while (0);
        }

        if (file_size & align_mask)
        {
            end = ROUND_SIZE( 0, file_size, align_mask );
            if (end > map_size) end = map_size;
            TRACE_(module)("clearing %p - %p\n",
                           ptr + sec[i].VirtualAddress + file_size,
                           ptr + sec[i].VirtualAddress + end );
            memset( ptr + sec[i].VirtualAddress + file_size, 0, end - file_size );
        }
    }
#ifdef WINE_IOS
    ios_swap_image_armed = 0;   /* madeira-bcd swap-images: only the sections loop notes */
#endif

#ifdef __aarch64__
    if ((dir = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG )))
    {
        if (image_info->machine == IMAGE_FILE_MACHINE_ARM64 &&
            (machine == IMAGE_FILE_MACHINE_AMD64 ||
             (!machine && ios_cur_image_info_machine() == IMAGE_FILE_MACHINE_AMD64)))
        {
            update_arm64x_mapping( view, nt, dir, sec );
            /* reload changed machine from NT header */
            image_info->machine = nt->FileHeader.Machine;
        }
        if (image_info->machine == IMAGE_FILE_MACHINE_AMD64)
            update_arm64ec_ranges( view, nt, dir, &image_info->entry_point );
    }
#endif
    /* sections mapped OK */
    if (machine && machine != nt->FileHeader.Machine)
    {
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }

    /* relocate to dynamic base */

    if (image_info->map_addr && (delta = image_info->map_addr - image_info->base))
    {
        TRACE_(module)( "relocating %s dynamic base %lx -> %lx mapped at %p\n", debugstr_us(nt_name),
                        (ULONG_PTR)image_info->base, (ULONG_PTR)image_info->map_addr, ptr );

        if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            ((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.ImageBase = image_info->map_addr;
        else
            ((IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.ImageBase = image_info->map_addr;

        /* ml949: DO NOT APPLY A RELOCS_STRIPPED IMAGE'S DIRECTORY.
         *
         * ml936 lets a sub-floor image be mapped high even though it declares
         * IMAGE_FILE_RELOCS_STRIPPED (it is that or refuse the load). Applying
         * its directory as well was wrong, and measurably so.
         *
         * A packed image measured here has 20 DIR64 entries whose targets are
         * all ZERO on disk -- because they are the immediates of `movabs reg,0`
         * instructions that the packer's own address arithmetic then consumes
         * (e.g. rva 0x120ab0 is the immediate of `movabs rax,0`, followed by
         * `add rbp,rax`). So "applying relocations" does not relocate pointers
         * here; it INJECTS THE RELOCATION DELTA AS A CONSTANT into that
         * arithmetic. RELOCS_STRIPPED is precisely the guarantee that the delta
         * is always zero, which makes every one of those a no-op on Windows.
         *
         * Consequence when the delta is not zero: the packer biases addresses
         * that must not move. Measured across SIX launches at six different
         * load bases, the first failing access is
         *     bad address - relocation delta == 0x7ffe02e8
         * i.e. KUSER_SHARED_DATA plus the module delta, computed into a stack
         * slot and dereferenced by `mov rbp,[r10]; mov eax,[rbp]` at
         * <image>+0x16969b. The ml938 sub-floor window cannot repair it: the
         * result is a HIGH address, outside the preferred-base window.
         *
         * So: map it high (nothing else is possible), rewrite ImageBase so that
         * anything reading the header computes a zero delta, and leave the
         * directory alone. The image's own preferred-base absolutes then stay
         * low and are serviced by the ml938 window, and no external address is
         * ever biased.
         *
         * ⛔ Do NOT instead subtract the delta from high addresses, and do not
         * extend this skip to images with a real (non-stripped) directory --
         * those must be relocated normally. */
        if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
        {
            fprintf( stderr, "ml949: %s RELOCS_STRIPPED, mapped at %p (preferred %#llx, delta %#llx): "
                     "ImageBase rewritten, directory NOT applied (its entries are delta-injection "
                     "immediates, not pointers)\n",
                     "sub-floor image", ptr, (unsigned long long)image_info->base,
                     (unsigned long long)delta );
        }
        else if ((dir = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_BASERELOC )))
        {
            IMAGE_BASE_RELOCATION *rel = (IMAGE_BASE_RELOCATION *)(ptr + dir->VirtualAddress);
            IMAGE_BASE_RELOCATION *end = (IMAGE_BASE_RELOCATION *)((char *)rel + dir->Size);

            while (rel && rel < end - 1 && rel->SizeOfBlock && rel->VirtualAddress < total_size)
                rel = process_relocation_block( ptr + rel->VirtualAddress, rel, delta );
        }
    }
#ifdef WINE_IOS
    /* ml1195: ml949's header rewrite, for a sub-floor image WITHOUT a dynamic base.
     * ml949 runs only when the server handed out a map_addr (a DYNAMIC_BASE
     * image). An executable with a fixed base below 4GB and RELOCS_STRIPPED (a
     * 64-bit Delphi program at 0x400000, characteristics 0x223) has no
     * map_addr; it was placed high by the fallback in
     * map_image_view, its header still said 0x400000, and ntdll's
     * perform_relocations refused it (STATUS_CONFLICTING_ADDRESSES, "failed to
     * create main module"). The same reasoning as ml949 holds: RELOCS_STRIPPED
     * promises a zero delta, so nothing is applied; the header names the real
     * base, and the image's own low absolutes are serviced by the ml938
     * sub-floor window registered just below. Only 64-bit images outside a WoW
     * guest window: a 32-bit image in a window is at its own guest address. */
    else if (!image_info->map_addr && image_info->base && image_info->base < 0x100000000ull &&
             (ULONG_PTR)ptr != image_info->base &&
             (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) &&
             nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && !ios_wow_in_window( ptr ))
    {
        ((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.ImageBase = (ULONG_PTR)ptr;
        fprintf( stderr, "ml1195: sub-floor image RELOCS_STRIPPED without a dynamic base, mapped at "
                 "%p (preferred %#llx): ImageBase rewritten, nothing relocated\n",
                 ptr, (unsigned long long)image_info->base );
    }
#endif

#ifdef WINE_IOS
    /* ml938: this image wanted a base iOS will never give us (the low 4GB is
     * outside every task's VM map -- see ios_register_subfloor_image). It has
     * been mapped high instead, and ml936 relocated whatever its directory
     * covered, but a packed image's directory typically covers almost nothing,
     * so absolute preferred-base addresses survive in its code and data.
     * Register the window so the Mach fault handler can service accesses to
     * it against THIS mapping -- same memory, so the two views cannot diverge.
     * Registered after relocation so real_base is final. */
    /* A PE32 image inside a WoW64 guest window lives at B + its guest base; the
     * session-wide sub-floor table would redirect one 32-bit process's accesses
     * into another's copy.  Outside a window this is the upstream rule. */
    if (image_info->base && image_info->base < 0x100000000ull
        && (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC || !ios_wow_in_window( ptr )))
    {
        extern void ios_register_subfloor_image( unsigned long long pref_base,
                                                 unsigned long long size,
                                                 unsigned long long real_base, void *owner );
        if (!(nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) &&
            ios_subfloor_window_held( image_info->base, (ULONG_PTR)ptr ))
            fprintf( stderr, "ml1204: sub-floor window %#llx stays on its RELOCS_STRIPPED image; "
                     "relocatable image at %p (relocated) not registered\n",
                     (unsigned long long)image_info->base, ptr );
        else
        ios_register_subfloor_image( (unsigned long long)image_info->base,
                                     (unsigned long long)total_size,
                                     (unsigned long long)(uintptr_t)ptr,
                                     ios_jit_current_peb() );   /* ml1205: owned by this process */
        /* ml966: record THIS pseudo-process as a candidate for low allocation,
         * but only for a relocs-stripped image -- see
         * ios_lowalloc_note_qualifying_image for why that pairing is the real
         * discriminator and why the global window table cannot be used here. */
        ios_lowalloc_note_qualifying_image(
            (unsigned long long)image_info->base,
            (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) ? 1 : 0 );
        /* ml1100: and give the NARROWED form of the high base a name too.
         * See ios_image_lowalias_register. */
        ios_image_lowalias_register( (unsigned long long)image_info->base,
                                     (unsigned long long)(uintptr_t)ptr,
                                     (unsigned long long)total_size, "sub-floor preferred base" );
    }
    /* madeira-bcd: [sc-rph], before the protections and the JIT-pool copy. */
    ios_sc_render_handler_patch( ptr, total_size, nt, sec, nt_name );

    /* madeira-bcd [x64-image]: decided before any protection is set, so both
     * the section pass and the eager copy loop below see the mark (see
     * ios_x64_image_is_host_data). update_arm64ec_ranges has run: a hybrid
     * image carries VPROT_ARM64EC by now. */
    if (ios_x64_image_nocopy_enabled() && !ios_map_resource_view && !ios_wow_base() &&
        nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
        nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        !(view->protect & VPROT_ARM64EC) && !image_info->is_hybrid && !image_info->wine_builtin)
    {
        static int x64_images;
        view->protect |= VPROT_X64DATA;
        if (x64_images++ < 64)
            dprintf( 2, "[x64-image] %s %p+0x%lx mapped without a pool copy (pure x64: the emulator runs "
                        "it at the PE VA; MADEIRA_X64_IMAGE_NOCOPY)\n",
                     debugstr_us(nt_name), ptr, (unsigned long)total_size );
    }
#endif

    /* set the image protections */

    set_vprot( view, ptr, ROUND_SIZE( 0, header_size, align_mask ), VPROT_COMMITTED | VPROT_READ );

#ifdef WINE_IOS
    int ios_noexec_resource = 0;
    ios_jit_copy_refused = 0;
    /* madeira-bcd: a .NET image keeps its pool copy (see ios_map_resource_view). */
    if (ios_map_resource_view && get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ))
        ios_map_resource_view = 0;
#endif
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        SIZE_T size;
        BYTE vprot = VPROT_COMMITTED;

        if (sec[i].Misc.VirtualSize)
            size = ROUND_SIZE( sec[i].VirtualAddress, sec[i].Misc.VirtualSize, align_mask );
        else
            size = ROUND_SIZE( sec[i].VirtualAddress, sec[i].SizeOfRawData, align_mask );

        if (sec[i].Characteristics & IMAGE_SCN_MEM_READ)    vprot |= VPROT_READ;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)   vprot |= VPROT_WRITECOPY;
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) vprot |= VPROT_EXEC;

        if (!set_vprot( view, ptr + sec[i].VirtualAddress, size, vprot ) && (vprot & VPROT_EXEC))
        {
            ERR( "failed to set %08x protection on %s section %.8s, noexec filesystem?\n",
                 sec[i].Characteristics, debugstr_us(nt_name), sec[i].Name );
#ifdef WINE_IOS
            /* madeira-bcd: the image got no JIT-pool copy (pool exhausted, or a
             * Social Club client's libcef.dll). Its code can never run here: the
             * load used to "succeed" and the first call into it died with an
             * exec AV (secur32.dll, imm32.dll in the GTA logs of 2026-10-02).
             * Fail the load instead, so the loader reports it. Only this case:
             * every other protection failure keeps the old path. */
            if (ios_resource_only_map( ios_jit_copy_refused, NtCurrentTeb()->Tib.ArbitraryUserPointer ))
            {
                static int resource_maps;
                if (resource_maps++ < 16)
                    dprintf( 2, "[jit-pool] %s: resource-only map (no loader name; GetFileVersionInfo / "
                             "LOAD_LIBRARY_AS_IMAGE_RESOURCE) of a refused image -- mapped without a pool copy "
                             "and without exec, the code never runs from it\n", debugstr_us(nt_name) );
                ios_jit_copy_refused = 0;
                ios_noexec_resource = 1;
                continue;
            }
            if (ios_jit_copy_refused)
            {
                static int refused_loads;
                if (refused_loads++ < 32)
                    dprintf( 2, "[jit-pool] %s: no JIT-pool copy for executable section %.8s -- the load "
                             "fails with STATUS_NO_MEMORY instead of mapping code that cannot run\n",
                             debugstr_us(nt_name), sec[i].Name );
                ios_jit_copy_refused = 0;
                status = STATUS_NO_MEMORY;
                goto done;
            }
#endif
        }
    }

#ifdef VALGRIND_LOAD_PDB_DEBUGINFO
    VALGRIND_LOAD_PDB_DEBUGINFO(fd, ptr, total_size, ptr - (char *)wine_server_get_ptr( image_info->base ));
#endif
    status = STATUS_SUCCESS;

#ifdef WINE_IOS
    /* Eagerly JIT-copy all EXEC sections right here — every PE load goes
     * through map_image_into_view, regardless of whether it's via
     * virtual_map_image (builtin flag) or any alternate path. */
    ERR("iOS map_image_into_view: view=%p EXEC fixup\n", ptr);
    for (int si = 0; si < nt->FileHeader.NumberOfSections && !ios_noexec_resource; si++)
    {
        if (!(sec[si].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        SIZE_T sec_size = sec[si].Misc.VirtualSize
            ? ROUND_SIZE(sec[si].VirtualAddress, sec[si].Misc.VirtualSize, align_mask)
            : ROUND_SIZE(sec[si].VirtualAddress, sec[si].SizeOfRawData, align_mask);
        void *sec_addr = ptr + sec[si].VirtualAddress;
        int prot = PROT_READ | PROT_EXEC;
        if (sec[si].Characteristics & IMAGE_SCN_MEM_WRITE) prot |= PROT_WRITE;
        ERR("iOS: eager JIT-copy section %.8s (addr=%p size=0x%lx)\n",
            sec[si].Name, sec_addr, (unsigned long)sec_size);
        mprotect_exec(sec_addr, sec_size, prot);
    }
    /* iOS: data sections were mapped MAP_PRIVATE + PROT_READ|PROT_WRITE
     * (see map_file_into_view) so they're already mprotect-able. No
     * post-hoc fixup needed. */
#endif

done:
#ifdef WINE_IOS
    ios_swap_image_armed = 0;   /* madeira-bcd swap-images: also on the failure paths out of the loop */
#endif
    free( sections );
    return status;
}


/***********************************************************************
 *             get_mapping_info
 */
static unsigned int get_mapping_info( HANDLE handle, ACCESS_MASK access, unsigned int *sec_flags,
                                      mem_size_t *full_size, HANDLE *shared_file,
                                      struct pe_image_info **info, UNICODE_STRING *nt_name,
                                      ANSI_STRING *exp_name )
{
    struct pe_image_info *image_info;
    SIZE_T namelen, total, size = 1024;
    unsigned int status;

    for (;;)
    {
        if (!(image_info = malloc( size ))) return STATUS_NO_MEMORY;

        SERVER_START_REQ( get_mapping_info )
        {
            req->handle = wine_server_obj_handle( handle );
            req->access = access;
            wine_server_set_reply( req, image_info, size );
            status = wine_server_call( req );
            *sec_flags   = reply->flags;
            *full_size   = reply->size;
            namelen      = reply->name_len;
            total        = reply->total;
            *shared_file = wine_server_ptr_handle( reply->shared_file );
        }
        SERVER_END_REQ;
        if (!status && total <= size) break;
        free( image_info );
        if (status) return status;
        if (*shared_file) NtClose( *shared_file );
        size = total;
    }

    if (total)
    {
        assert( total >= sizeof(*image_info) );
        total -= sizeof(*image_info);
        nt_name->Buffer = (WCHAR *)(image_info + 1);
        nt_name->Length = nt_name->MaximumLength = namelen;
        exp_name->Buffer = (char *)nt_name->Buffer + namelen;
        exp_name->Length = exp_name->MaximumLength = total - namelen;
        *info = image_info;
    }
    else free( image_info );

    return STATUS_SUCCESS;
}


/***********************************************************************
 *             map_image_view
 *
 * Map a view for a PE image at an appropriate address.
 */
static NTSTATUS map_image_view( struct file_view **view_ret, struct pe_image_info *image_info, SIZE_T size,
                                ULONG_PTR limit_low, ULONG_PTR limit_high, ULONG alloc_type,
                                BOOL is_builtin )
{
    unsigned int vprot = SEC_IMAGE | SEC_FILE | VPROT_COMMITTED | VPROT_READ | VPROT_EXEC | VPROT_WRITECOPY;
    void *base;
    NTSTATUS status;
    ULONG_PTR start, end;
    BOOL top_down = (image_info->image_charact & IMAGE_FILE_DLL) &&
                    (image_info->image_flags & IMAGE_FLAGS_ImageDynamicallyRelocated);
#ifdef WINE_IOS
    /* WoW64 guest window: a 32-bit image in a WoW pseudo-process belongs in
     * that process's window, and its preferred base (image_info->base, and
     * the server's ASLR map_addr) is a GUEST address.  Place at B + preferred
     * base when free, else anywhere in [B, B + HighestUserAddress].
     * map_image_into_view then relocates to host - B — see the guest-base
     * delta there. */
    ULONG_PTR wow_base = ios_wow_base();
    BOOL wow_image = wow_base && !is_machine_64bit( image_info->machine );
#else
    const ULONG_PTR wow_base = 0;
    const BOOL wow_image = FALSE;
#endif

    if (wow_image)
    {
#ifdef WINE_IOS
        /* The ceiling comes from ios_wow_image_ceiling(), not straight from
         * get_wow_user_space_limit(): the MAIN image is mapped before init_peb
         * publishes that global, and B + 0 is not a range (see the helper).
         * IOS_WOW_GUEST_FLOOR keeps guest 0 / the guest DOS area out of the
         * bottom-up scan below, exactly as the else branch does with
         * address_space_start for host placements. */
        limit_low  = wow_base + IOS_WOW_GUEST_FLOOR;
        limit_high = wow_base + ios_wow_image_ceiling( image_info );

        /* [laa] KEEP WINE'S OWN FURNITURE OUT OF THE LOW 2 GB.
         *
         * On Windows a non-large-address-aware program never sees anything in
         * [2G, 4G) at all; here it sees 742 builtin i386 modules competing with
         * it for the low half, which is what the [va-scan] FAILED evidence is
         * made of.  A BUILTIN image is Wine's furniture, not the app's: nothing
         * the app does depends on where it lands, because the app never names a
         * system DLL by a hardcoded address.  So when a high half exists (the
         * ceiling is above 2 GB, i.e. the image is LAA or the policy above made
         * it so), place builtins there first, top-down, and leave the low half
         * to the program.
         *
         * Gated on IMAGE_FLAGS_ImageDynamicallyRelocated — the same test
         * `top_down` above uses.  That flag means the server already assigned
         * this image a randomized base, i.e. it is relocatable; an image without
         * it keeps exactly today's placement, so we can never move something
         * that cannot be moved.  NATIVE (app-supplied) DLLs are untouched and
         * keep their preferred bases.
         *
         * Advisory, never fatal: on failure we fall straight through to the
         * ordinary preferred-base / full-window path below. */
        /* ml1070: MADEIRA_LAA_HIGH_IMAGES=0 keeps Wine's furniture below 2 GB as
         * well, so that NOTHING in the window has bit 31 set for a program whose
         * header never claimed it could read one.  That is the second half of the
         * A/B described at ios_wow_laa_synth; it costs the low-half headroom this
         * placement was introduced to win back, so it is opt-in and default off. */
        if (is_builtin && (image_info->image_flags & IMAGE_FLAGS_ImageDynamicallyRelocated) &&
            limit_high > wow_base + limit_2g && ios_wow_laa_high_images())
        {
            static unsigned hi_n, hi_fail;

            if (!map_view( view_ret, NULL, size, MEM_TOP_DOWN, vprot,
                           wow_base + limit_2g, limit_high, 0 ))
            {
                if (hi_n++ < 8 || !(hi_n % 64))
                    dprintf( 2, "[laa] builtin image #%u placed in the high half at guest %p "
                                "(+0x%lx), keeping the low 2 GB for the program\n",
                             hi_n, (void *)((ULONG_PTR)(*view_ret)->base - wow_base),
                             (unsigned long)size );
                return STATUS_SUCCESS;
            }
            if (hi_fail++ < 8)
                dprintf( 2, "[laa] builtin image (size 0x%lx) did not fit the high half; falling "
                            "back to the whole window\n", (unsigned long)size );
        }
#endif
    }
    else
    {
        limit_low = max( limit_low, (ULONG_PTR)address_space_start );  /* make sure the DOS area remains free */
        /* task #35 furniture ceiling: images pack below it (inclusive limit).
         * Disabled while ios_furniture_ceiling == 0 — see its definition. */
        if (!limit_high)
            limit_high = ios_furniture_ceiling ? min( (ULONG_PTR)user_space_limit, ios_furniture_ceiling - 1 )
                                               : (ULONG_PTR)user_space_limit;
    }

    /* first try the specified base */

    if (image_info->map_addr)
    {
        base = wine_server_get_ptr( image_info->map_addr );
        if ((ULONG_PTR)base != image_info->map_addr) base = NULL;
    }
    else
    {
        base = wine_server_get_ptr( image_info->base );
        if ((ULONG_PTR)base != image_info->base) base = NULL;
    }
    if (base && wow_image) base = (char *)base + wow_base;   /* guest -> host */
    /* ml985: entry probe for big images only (the main exe is the only thing at
     * this size), so the next log can distinguish three cases that rdr55 could
     * not: map_image_view was never called; it was called with base==NULL; or it
     * was called with the preferred base and map_view refused it. Absence of a
     * probe string is not absence of the failure -- so print before the branch,
     * not inside it. */
    if (size >= 64u * 1024u * 1024u)
        dprintf( 2, "ml985: map_image_view size=%#lx base=%p info_base=%#llx map_addr=%#llx "
                 "flags=%#x charact=%#x limits=%#lx..%#lx\n",
                 (unsigned long)size, base, (unsigned long long)image_info->base,
                 (unsigned long long)image_info->map_addr,
                 (unsigned int)image_info->image_flags,
                 (unsigned int)image_info->image_charact,
                 (unsigned long)limit_low, (unsigned long)limit_high );

    if (base)
    {
        /* see ios_exe_win_stripped_request */
        ios_exe_win_stripped_request = (image_info->image_charact & IMAGE_FILE_RELOCS_STRIPPED) != 0;
        status = map_view( view_ret, base, size, alloc_type, vprot, limit_low, limit_high, 0 );
        ios_exe_win_stripped_request = 0;
        /* ml988: commit or roll back a pending fixed-base claim. No-ops unless
         * ios_exe_win_claim granted this exact interval during the call above. */
        ios_exe_win_commit_claim( base, size, !status );
        if (!status) return status;

        /* ml985: the preferred base is refused. Report it UNCONDITIONALLY, with
         * the raw image_flags rather than an assumption about them -- rdr56
         * measured flags=0 for RDR2.exe (no DYNAMIC_BASE, no .reloc) and
         * flags=0x4 for the desktop's images, which is the discriminator this
         * line exists to record.
         *
         * NOTHING is retired from here. ml983/ml984 tried to free the dead
         * generation's image at this point, from inside virtual_map_image's
         * uninterrupted section and on a foreign process's behalf; rdr56/rdr57
         * both died at the delete_view call with no further output. Retirement
         * now happens where it belongs -- in ios_retire_own_fixed_base_image
         * plus ios_exe_win_mark_ready (ml988's two-phase handoff),
         * on the owner's own thread at its own exit, through
         * NtUnmapViewOfSection, which also drops the server-side memory_view
         * that the delete_view-only approach silently left behind. By the time
         * this runs, a correctly retired base is simply free and map_view above
         * succeeds on the first try. */
        {
            static int failn;
            /* ml986: rdr56 lost the line that mattered -- the 12 desktop refusals
             * used the whole budget before the main image reached it. Cap only
             * the small ones. */
            if (size >= 64u * 1024u * 1024u || failn++ < 12)
                dprintf( 2, "ml985: preferred base %p+%#lx REFUSED status=%#x "
                         "image_flags=%#x charact=%#x map_addr=%#llx info_base=%#llx\n",
                         base, (unsigned long)size, (unsigned int)status,
                         (unsigned int)image_info->image_flags,
                         (unsigned int)image_info->image_charact,
                         (unsigned long long)image_info->map_addr,
                         (unsigned long long)image_info->base );
        }
    }

    /* then some appropriate address range */

    if (wow_image)
    {
        start = limit_low;
        end = limit_high;
    }
    else if (image_info->base >= limit_4g)
    {
        start = max( limit_low, limit_4g );
        end = limit_high;
    }
    else
    {
        start = limit_low;
        end = min( limit_high, get_wow_user_space_limit() );
    }
    if (start < end && (start != limit_low || end != limit_high))
    {
        status = map_view( view_ret, NULL, size, top_down ? MEM_TOP_DOWN : 0, vprot, start, end, 0 );
        if (!status) return status;
    }

    /* then any suitable address */

    return map_view( view_ret, NULL, size, top_down ? MEM_TOP_DOWN : 0, vprot, limit_low, limit_high, 0 );
}


/***********************************************************************
 *             virtual_map_image
 *
 * Map a PE image section into memory.
 */
static NTSTATUS virtual_map_image( HANDLE mapping, void **addr_ptr, SIZE_T *size_ptr, HANDLE shared_file,
                                   ULONG_PTR limit_low, ULONG_PTR limit_high, ULONG alloc_type,
                                   USHORT machine, struct pe_image_info *image_info,
                                   UNICODE_STRING *nt_name, BOOL is_builtin, off_t offset)
{
    int unix_fd = -1, needs_close;
    int shared_fd = -1, shared_needs_close = 0;
    SIZE_T size = image_info->map_size;
    struct file_view *view;
    unsigned int status;
    sigset_t sigset;

    if (offset >= size)
        return STATUS_INVALID_PARAMETER;

    if ((status = server_get_unix_fd( mapping, 0, &unix_fd, &needs_close, NULL, NULL )))
        return status;

    if (shared_file && ((status = server_get_unix_fd( shared_file, FILE_READ_DATA|FILE_WRITE_DATA,
                                                      &shared_fd, &shared_needs_close, NULL, NULL ))))
    {
        if (needs_close) close( unix_fd );
        return status;
    }

    if (!image_info->map_addr &&
        (image_info->image_charact & IMAGE_FILE_DLL) &&
        (image_info->image_flags & IMAGE_FLAGS_ImageDynamicallyRelocated))
    {
        SERVER_START_REQ( get_image_map_address )
        {
            req->handle = wine_server_obj_handle( mapping );
            if (!wine_server_call( req )) image_info->map_addr = reply->addr;
        }
        SERVER_END_REQ;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    status = map_image_view( &view, image_info, size, limit_low, limit_high, alloc_type, is_builtin );
    /* ml366: NAME the image whose placement failed. ml365's mmdevapi load
     * returned c0000017 with zero attributable evidence — the [va-scan]
     * FAILED line was storm-gated and nothing tied a placement failure to a
     * DLL. One line here closes that gap for every future load failure. */
    if (status)
    {
        static unsigned imgfail;
        if (imgfail++ < 64)
            ERR( "[img-map-fail] rev=ml366 %s status=%x size=%zx limits=%lx..%lx\n",
                 nt_name ? debugstr_us(nt_name) : "?", status, (size_t)size,
                 (unsigned long)limit_low, (unsigned long)limit_high );
        goto done;
    }
    status = map_image_into_view( view, nt_name, unix_fd, image_info, machine, shared_fd, needs_close );
    if (status == STATUS_SUCCESS)
    {
        if (offset)
        {
            free_pages( view, view->base, offset );
            size -= offset;
        }

        image_info->base = wine_server_client_ptr( view->base );
        SERVER_START_REQ( map_image_view )
        {
            req->mapping = wine_server_obj_handle( mapping );
            req->base    = image_info->base;
            req->size    = size;
            req->entry   = image_info->entry_point;
            req->machine = image_info->machine;
            req->offset  = offset;
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
    }
    if (NT_SUCCESS(status))
    {
#ifdef WINE_IOS
        ERR("iOS virtual_map_image: view=%p is_builtin=%d offset=%ld\n",
            view->base, is_builtin, (long)offset);
#endif
        if (is_builtin && !offset) add_builtin_module( view->base, NULL );
#ifdef WINE_IOS
        /* For builtin images on iOS: eagerly trigger the JIT copy for each
         * EXEC section. Normally Wine relies on an mprotect(PROT_EXEC) call
         * from somewhere downstream to activate section execution, but for
         * our main .exe that path isn't hit (sections are mapped via
         * PROT_READ|PROT_WRITECOPY and no subsequent protect flips them to
         * EXEC). Without the JIT copy, triangle.exe's .text isn't executable
         * and we bus-fault on its first instruction.
         */
        if (is_builtin && !offset)
        {
            IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)view->base;
            if (dos && dos->e_magic == IMAGE_DOS_SIGNATURE)
            {
                IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)view->base + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE)
                {
                    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
                    SIZE_T align_mask = max(image_info->alignment - 1, page_mask);
                    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
                    {
                        if (!(s[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                        SIZE_T sec_size = s[i].Misc.VirtualSize
                            ? ROUND_SIZE(s[i].VirtualAddress, s[i].Misc.VirtualSize, align_mask)
                            : ROUND_SIZE(s[i].VirtualAddress, s[i].SizeOfRawData, align_mask);
                        void *sec_addr = (char *)view->base + s[i].VirtualAddress;
                        int prot = PROT_READ | PROT_EXEC;
                        if (s[i].Characteristics & IMAGE_SCN_MEM_WRITE) prot |= PROT_WRITE;
                        ERR("iOS: eager JIT-copy for builtin %s section (base=%p size=0x%lx)\n",
                            s[i].Name, sec_addr, (unsigned long)sec_size);
                        mprotect_exec(sec_addr, sec_size, prot);
                    }
                }
            }
        }
#endif
        *addr_ptr = view->base;
        *size_ptr = size;
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    else delete_view( view );

done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#ifdef WINE_IOS
    ios_swap_image_flush( NT_SUCCESS(status) );   /* madeira-bcd swap-images: outside the lock (ml1081) */
#endif
    if (needs_close) close( unix_fd );
    if (shared_needs_close) close( shared_fd );
    return status;
}


/***********************************************************************
 *             virtual_map_section
 *
 * Map a file section into memory.
 */
static unsigned int virtual_map_section( HANDLE handle, PVOID *addr_ptr, ULONG_PTR limit_low,
                                         ULONG_PTR limit_high, SIZE_T commit_size,
                                         const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                         ULONG alloc_type, ULONG protect, USHORT machine )
{
    unsigned int res;
    mem_size_t full_size;
    ACCESS_MASK access;
    SIZE_T size;
    struct pe_image_info *image_info = NULL;
    UNICODE_STRING nt_name;
    ANSI_STRING exp_name;
    void *base;
    int unix_handle = -1, needs_close;
    unsigned int vprot, sec_flags;
    struct file_view *view;
    HANDLE shared_file;
    LARGE_INTEGER offset;
    sigset_t sigset;

#ifdef WINE_IOS
    /* WoW64 guest window: same rule as allocate_virtual_memory — a ceiling
     * below 4 GB reaching NtMapViewOfSection[Ex] is a GUEST ceiling. */
    ios_wow_translate_limits( &limit_low, &limit_high );
#endif

    switch(protect)
    {
    case PAGE_NOACCESS:
    case PAGE_READONLY:
    case PAGE_WRITECOPY:
        access = SECTION_MAP_READ;
        break;
    case PAGE_READWRITE:
        access = SECTION_MAP_WRITE;
        break;
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_WRITECOPY:
        access = SECTION_MAP_READ | SECTION_MAP_EXECUTE;
        break;
    case PAGE_EXECUTE_READWRITE:
        access = SECTION_MAP_WRITE | SECTION_MAP_EXECUTE;
        break;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    res = get_mapping_info( handle, access, &sec_flags, &full_size, &shared_file,
                            &image_info, &nt_name, &exp_name );
    if (res)
    {
        dprintf(2, "[map-sec] get_mapping_info handle=%p access=0x%x -> 0x%x\n",
                handle, (unsigned)access, res);
        return res;
    }

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    if (image_info)
    {
        SECTION_IMAGE_INFORMATION info;
        ULONG64 prev = 0;

        if (NtCurrentTeb64())
        {
            prev = NtCurrentTeb64()->Tib.ArbitraryUserPointer;
            NtCurrentTeb64()->Tib.ArbitraryUserPointer = PtrToUlong(NtCurrentTeb()->Tib.ArbitraryUserPointer);
        }
        /* check if we can replace that mapping with the builtin */
        res = load_builtin( image_info, &nt_name, &exp_name, machine, &info,
                            addr_ptr, size_ptr, limit_low, limit_high, offset.QuadPart );
        if (res == STATUS_IMAGE_ALREADY_LOADED)
        {
#ifdef WINE_IOS
            /* madeira-bcd: no loader name and no execute access = a resource-only
             * view; it gets no pool copy (ios_map_resource_view). */
            ios_map_resource_view = !(access & SECTION_MAP_EXECUTE) &&
                                    !NtCurrentTeb()->Tib.ArbitraryUserPointer && ios_resource_map_nocopy();
            /* the fixed-base window's guard (ios_exe_win_resource_request) */
            ios_exe_win_resource_request = !(access & SECTION_MAP_EXECUTE) &&
                                           !NtCurrentTeb()->Tib.ArbitraryUserPointer;
#endif
            res = virtual_map_image( handle, addr_ptr, size_ptr, shared_file, limit_low, limit_high,
                                     alloc_type, machine, image_info, &nt_name, FALSE, offset.QuadPart );
#ifdef WINE_IOS
            ios_map_resource_view = 0;
            ios_exe_win_resource_request = 0;
#endif
        }
        if (shared_file) NtClose( shared_file );
        free( image_info );
        if (NtCurrentTeb64()) NtCurrentTeb64()->Tib.ArbitraryUserPointer = prev;
        return res;
    }

    base = *addr_ptr;
    if (offset.QuadPart >= full_size) return STATUS_INVALID_PARAMETER;
    if (*size_ptr)
    {
        size = *size_ptr;
        if (size > full_size - offset.QuadPart) return STATUS_INVALID_VIEW_SIZE;
    }
    else
    {
        size = full_size - offset.QuadPart;
        if (size != full_size - offset.QuadPart)  /* truncated */
        {
            WARN( "Files larger than 4Gb (%s) not supported on this platform\n",
                  wine_dbgstr_longlong(full_size) );
            return STATUS_INVALID_PARAMETER;
        }
    }
    if (!(size = ROUND_SIZE( 0, size, page_mask ))) return STATUS_INVALID_PARAMETER;  /* wrap-around */

    get_vprot_flags( protect, &vprot, FALSE );
    vprot |= sec_flags;
    if (!(sec_flags & SEC_RESERVE)) vprot |= VPROT_COMMITTED;

    if ((res = server_get_unix_fd( handle, 0, &unix_handle, &needs_close, NULL, NULL )))
    {
        dprintf(2, "[map-sec] server_get_unix_fd handle=%p -> 0x%x\n", handle, res);
        return res;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    res = map_view( &view, base, size, alloc_type, vprot, limit_low, limit_high, 0 );
    if (res) goto done;

    TRACE( "handle=%p size=%lx offset=%s\n", handle, size, wine_dbgstr_longlong(offset.QuadPart) );
    /* iOS: SEC_COMMIT shared sections (e.g. \KernelObjects\__wine_session) need
     * MAP_SHARED so the client view is coherent with wineserver writes. The
     * for_image=FALSE override tells map_file_into_view_ex to take the shared
     * path (default for_image=TRUE preserves PE-image MAP_PRIVATE behavior). */
    res = map_file_into_view_ex( view, unix_handle, 0, size, offset.QuadPart, vprot, needs_close, FALSE );
    if (res == STATUS_SUCCESS)
    {
        /* file mappings must always be accessible */
        mprotect_range( view->base, view->size, VPROT_COMMITTED, 0 );

        SERVER_START_REQ( map_view )
        {
            req->mapping = wine_server_obj_handle( handle );
            req->access  = access;
            req->base    = wine_server_client_ptr( view->base );
            req->size    = size;
            req->start   = offset.QuadPart;
            res = wine_server_call( req );
        }
        SERVER_END_REQ;
    }
    else ERR( "mapping %p %lx %s failed\n", view->base, size, wine_dbgstr_longlong(offset.QuadPart) );

    if (NT_SUCCESS(res))
    {
        *addr_ptr = view->base;
        *size_ptr = size;
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }
    else delete_view( view );

done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (needs_close) close( unix_handle );
    if (res) dprintf(2, "[map-sec] virtual_map_section handle=%p prot=0x%x size=%p -> 0x%x\n",
                     handle, (unsigned)protect, (void *)size, res);
    return res;
}


/* allocate some space for the virtual heap, if possible from a reserved area */
static void *alloc_virtual_heap( SIZE_T size )
{
    struct reserved_area *area;
    void *ret;

    size = ROUND_SIZE( 0, size, host_page_mask );

    LIST_FOR_EACH_ENTRY_REV( area, &reserved_areas, struct reserved_area, entry )
    {
        void *base = area->base;
        void *end = (char *)base + area->size;

        /* ml799: the virtual heap is Wine's own bookkeeping and is exactly the
         * kind of unconstrained allocation the arena must never serve. It also
         * must not widen address_space_limit to the arena's top: that number
         * feeds placement decisions elsewhere, and stretching it to cover a
         * range nothing generic may use would misreport the usable space. */
        if (area->fex_only || area->thin_only) continue;
        if (is_beyond_limit( base, area->size, address_space_limit ))
            address_space_limit = host_addr_space_limit = end;
        if (is_win64 && base < (void *)0x80000000) break;
        if (preload_reserve_end >= end)
        {
            if (preload_reserve_start <= base) continue;  /* no space in that area */
            if (preload_reserve_start < end) end = preload_reserve_start;
        }
        else if (preload_reserve_end > base)
        {
            if (preload_reserve_start <= base) base = preload_reserve_end;
            else if ((char *)end - (char *)preload_reserve_end >= size) base = preload_reserve_end;
            else end = preload_reserve_start;
        }
        if ((char *)end - (char *)base < size) continue;
        ret = anon_mmap_fixed( (char *)end - size, size, PROT_READ | PROT_WRITE, 0 );
        if (ret == MAP_FAILED) continue;
        mmap_remove_reserved_area( ret, size );
        return ret;
    }
    return anon_mmap_alloc( size, PROT_READ | PROT_WRITE );
}

/* is_wow64() also asks the calling thread's TEB (wine unix_private.h), so a
 * thread that carries a 32-bit TEB is WoW64 whatever the global says.  A
 * 64-bit thread has no 32-bit TEB and still gets the session-global
 * !!wow_peb, which is TRUE in every process once any 32-bit pseudo-process
 * has booted.  MADEIRA_WOW64_BY_TEB=0 restores the session-global answer. */
int ios_wow64_by_teb = 1;

/* get_extended_params(): a MEM_ADDRESS_REQUIREMENTS ceiling is a guest (WoW)
 * ceiling only in a process that owns a guest window.  Every other process
 * validates against the host ceiling, even after a 32-bit pseudo-process has
 * set the session-wide wow_peb.  MADEIRA_WOW_LIMIT_BY_WINDOW=0 restores the
 * session-wide is_wow64() fallback. */
static int ios_wow_limit_by_window = 1;

