/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Virtual_init, system info, module mapping, TEBs, LDT, faults, locked I/O. Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *           virtual_init
 */
/***********************************************************************
 *           ios_log_running_image_identity                       (ml989)
 *
 * Name the image that is ACTUALLY LOADED, not the one on disk.
 *
 * Twice this session a verified dprintf on an executed path produced nothing,
 * and both times my evidence that the right build was running was a sha256 of
 * the file. Astra's correction stands: disk equality does not identify a
 * running mapping. The LC_UUID of the loaded Mach-O does, and it is recorded in
 * the log by the process itself, so every future "was this the build that ran?"
 * is answerable from the log alone.
 */
static void ios_log_running_image_identity( void )
{
    Dl_info di;
    const struct mach_header_64 *mh;
    const struct load_command *lc;
    uint32_t i;

    memset( &di, 0, sizeof(di) );
    if (!dladdr( (const void *)ios_log_running_image_identity, &di ) || !di.dli_fbase)
    {
        dprintf( 2, "ml989: could not identify the running image (dladdr failed) pid=%d\n",
                 (int)getpid() );
        return;
    }
    mh = (const struct mach_header_64 *)di.dli_fbase;
    if (mh->magic != MH_MAGIC_64)
    {
        dprintf( 2, "ml989: running image %s at %p has magic %#x (not MH_MAGIC_64) pid=%d\n",
                 di.dli_fname ? di.dli_fname : "?", (void *)mh, mh->magic, (int)getpid() );
        return;
    }
    lc = (const struct load_command *)((const char *)mh + sizeof(*mh));
    for (i = 0; i < mh->ncmds; i++)
    {
        if (lc->cmd == LC_UUID)
        {
            const struct uuid_command *uc = (const struct uuid_command *)lc;
            dprintf( 2, "ml989: running image %s base=%p pid=%d LC_UUID="
                     "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
                     di.dli_fname ? di.dli_fname : "?", (void *)mh, (int)getpid(),
                     uc->uuid[0], uc->uuid[1], uc->uuid[2],  uc->uuid[3],
                     uc->uuid[4], uc->uuid[5], uc->uuid[6],  uc->uuid[7],
                     uc->uuid[8], uc->uuid[9], uc->uuid[10], uc->uuid[11],
                     uc->uuid[12], uc->uuid[13], uc->uuid[14], uc->uuid[15] );
            return;
        }
        if (!lc->cmdsize) break;
        lc = (const struct load_command *)((const char *)lc + lc->cmdsize);
    }
    dprintf( 2, "ml989: running image %s base=%p pid=%d has NO LC_UUID\n",
             di.dli_fname ? di.dli_fname : "?", (void *)mh, (int)getpid() );
}

void virtual_init(void)
{
    const struct preload_info **preload_info = dlsym( RTLD_DEFAULT, "wine_main_preload_info" );
    const char *preload;
    size_t size;
    int i;
    pthread_mutexattr_t attr;

    pthread_mutexattr_init( &attr );
    pthread_mutexattr_settype( &attr, PTHREAD_MUTEX_RECURSIVE );
    pthread_mutex_init( &virtual_mutex, &attr );
    pthread_mutexattr_destroy( &attr );

    ios_log_running_image_identity();   /* ml989 */

#ifdef __aarch64__
    host_page_size = sysconf( _SC_PAGESIZE );
    host_page_mask = host_page_size - 1;
    TRACE( "host page size: %uk\n", (UINT)host_page_size / 1024 );
#endif

#ifdef _WIN64
    host_addr_space_limit = get_host_addr_space_limit();
    TRACE( "host addr space limit: %p\n", host_addr_space_limit );
    ios_clamp_user_space_limit( "virtual_init" );   /* ml990 */
    /* ml749: unconditional -- this must be present in the log of the run that
     * FAILS, and a failing run is exactly when nobody thought to arm a flag. */
    ios_va_profile( "post-limit" );
#else
    host_addr_space_limit = address_space_limit;
#endif

    kernel_writewatch_init();

    if (preload_info && *preload_info)
        for (i = 0; (*preload_info)[i].size; i++)
            mmap_add_reserved_area( (*preload_info)[i].addr, (*preload_info)[i].size );

    mmap_init( preload_info ? *preload_info : NULL );

    if ((preload = getenv("WINEPRELOADRESERVE")))
    {
        unsigned long start, end;
        if (sscanf( preload, "%lx-%lx", &start, &end ) == 2)
        {
            preload_reserve_start = ROUND_ADDR( start, host_page_mask );
            preload_reserve_end = (void *)ROUND_SIZE( 0, end, host_page_mask );
            /* some apps start inside the DOS area */
            if (preload_reserve_start)
                address_space_start = min( address_space_start, preload_reserve_start );
        }
        unsetenv( "WINEPRELOADRESERVE" );
    }

    /* try to find space in a reserved area for the views and pages protection table */
#ifdef _WIN64
    pages_vprot_size = ((size_t)host_addr_space_limit >> page_shift >> pages_vprot_shift) + 1;
    size = 2 * view_block_size + pages_vprot_size * sizeof(*pages_vprot);
#else
    size = 2 * view_block_size + (1U << (32 - page_shift));
#endif
    view_block_start = alloc_virtual_heap( size );
    assert( view_block_start != MAP_FAILED );
    view_block_end = view_block_start + view_block_size / sizeof(*view_block_start);
    free_ranges = (void *)((char *)view_block_start + view_block_size);
    pages_vprot = (void *)((char *)view_block_start + 2 * view_block_size);
    wine_rb_init( &views_tree, compare_view );

    free_ranges[0].base = (void *)0;
    free_ranges[0].end = (void *)~0;
    free_ranges_end = free_ranges + 1;

    /* make the DOS area accessible (except the low 64K) to hide bugs in broken apps like Excel 2003 */
    size = (char *)address_space_start - (char *)0x10000;
    if (size && mmap_is_in_reserved_area( (void*)0x10000, size ) == 1)
        anon_mmap_fixed( (void *)0x10000, size, PROT_READ | PROT_WRITE, 0 );

    /* madeira-bcd: Social Club layout 2 holds its slots first and moves the
     * cage into chrome_elf's regular half (ios_sc2_boot_holds). */
    ios_sc2_boot_holds();
    if (ios_sc_layout_mode == 2) ios_cage_base = IOS_SC2_CAGE_BASE;

    /* ml433 (#72): hold back the only 8GB-aligned stretch in the guest band
     * before top-down placement can put furniture in it — see IOS_CAGE_BASE. */
    if (anon_mmap_fixed( (void *)(uintptr_t)IOS_CAGE_BASE, IOS_CAGE_REAL_SIZE, PROT_NONE, 0 ) != MAP_FAILED)
    {
        ios_cage_holdback_live = 1;
        dprintf( 2, "[cage] holdback reserved 0x%llx+0x%llx rev=ml433\n",
                 (unsigned long long)IOS_CAGE_BASE, (unsigned long long)IOS_CAGE_REAL_SIZE );
    }
    else dprintf( 2, "[cage] holdback reserve FAILED (errno %d) rev=ml433\n", errno );

    /* Guest windows are reserved lazily; this reserves nothing unless a
     * 32-bit main image was published or MADEIRA_WOW_PLACEHOLDERS=1 (see
     * ios_wow_session_start).  Last, after the holdback, whose first page
     * the lowest slot borrows as its guard. */
    ios_wow_session_start();
    {
        const char *e = getenv( "MADEIRA_WOW64_BY_TEB" );
        if (e && e[0] == '0') ios_wow64_by_teb = 0;
        e = getenv( "MADEIRA_WOW_LIMIT_BY_WINDOW" );
        if (e && e[0] == '0') ios_wow_limit_by_window = 0;
    }
}


/* madeira-bcd: 1 when the calling pseudo-process is a Chromium browser that
 * judges memory pressure by GlobalMemoryStatusEx: SocialClubHelper.exe or
 * steamwebhelper.exe (the last component of its PEB's image path, any case).
 * Used by ios_avail_phys for avail-phys-cef-mb. */
static int ios_avail_phys_chromium( void )
{
    static const char *const names[] = { "socialclubhelper.exe", "steamwebhelper.exe" };
    PEB *peb = ios_jit_current_peb();
    RTL_USER_PROCESS_PARAMETERS *pp = peb ? peb->ProcessParameters : NULL;
    const WCHAR *path;
    size_t len, base = 0, k, n;
    unsigned i;

    if (!pp || !(path = pp->ImagePathName.Buffer)) return 0;
    len = pp->ImagePathName.Length / sizeof(WCHAR);
    for (k = 0; k < len; k++) if (path[k] == '\\' || path[k] == '/') base = k + 1;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        n = strlen( names[i] );
        if (len - base != n) continue;
        for (k = 0; k < n; k++)
        {
            WCHAR c = path[base + k];
            if (c >= 'A' && c <= 'Z') c += 32;
            if (c != (WCHAR)names[i][k]) break;
        }
        if (k == n) return 1;
    }
    return 0;
}


/***********************************************************************
 *           ios_avail_phys
 *
 * madeira-bcd: madeira.cfg or the game's own file `avail-phys = 1`, opt-in
 * (owner's Red Dead Redemption 2 run of 2026-10-09 11:02). Wine's
 * get_performance_info (system.c) reports the whole phone's free + inactive
 * pages as SystemPerformanceInformation.AvailablePages, which is
 * GlobalMemoryStatusEx's ullAvailPhys, while this app dies at its own memory
 * limit (the total virtual_get_system_info reports, ml992). Windows programs
 * saw gigabytes available until iOS killed the app at 8184 MB, so Chromium's
 * memory pressure evaluator (SocialClubHelper.exe, steamwebhelper.exe), which
 * purges caches and collects garbage below 1000 MB (moderate) and 400 MB
 * (critical) available, never fired. With the switch the value is lowered to
 * what remains before the limit (os_proc_available_memory) when that is
 * smaller. Called by the patched get_performance_info
 * (Wine's avail-phys change); off, host_free comes back unchanged.
 *
 * madeira-bcd: avail-phys-cef-mb = N (madeira.cfg or the game's own file, MB,
 * 0 = off, independent of avail-phys) caps what Chromium browsers see -- Social
 * Club's SocialClubHelper.exe and Steam's steamwebhelper.exe, nothing else (see
 * ios_avail_phys_chromium) -- at N MB. The 467 run (2026-10-09 13:09) reached
 * Chromium's moderate level only at 7.3 GB, a minute into play, long after the
 * helper had grown: at RDR2.exe's start its V8 cage held 167 MB dirty, its
 * PartitionAlloc 88 MB, and its ANGLE device two 32 MB staging blocks. Below
 * 400 MB (e.g. 300) Chromium's Windows evaluator reports CRITICAL pressure on
 * every 5 s check from the helper's start (full V8 GC, PartitionAlloc and
 * discardable purges, Skia/tile caches dropped); 400-999 MB (e.g. 900)
 * reports MODERATE every 10 s. The game and the launcher keep the real figure.
 */
unsigned long long ios_avail_phys( unsigned long long host_free )
{
    extern size_t os_proc_available_memory( void );
    static int on = -1, band = -1, said, capped;
    static unsigned long long memsize, cef;
    unsigned long long left, value = host_free;
    int now;

    if (on < 0)
    {
        size_t len = sizeof(memsize);
        long long mb;
        if (sysctlbyname( "hw.memsize", &memsize, &len, NULL, 0 )) memsize = 0;
        on = madeira_cfg_bool( "avail-phys", 0 );   /* madeira.cfg avail-phys = 1 */
        if (on) dprintf( 2, "[avail-phys] on: available physical memory is what remains before this "
                         "app's memory limit (madeira.cfg avail-phys = 1)\n" );
        /* MB of available memory SocialClubHelper.exe / steamwebhelper.exe see at most (0 = off; 300 = Chromium's critical level). */
        mb = madeira_cfg_int( "avail-phys-cef-mb", 0 );
        cef = mb > 0 && mb <= 65536 ? (unsigned long long)mb << 20 : 0;
        if (cef) dprintf( 2, "[avail-phys] Chromium browsers (SocialClubHelper.exe, steamwebhelper.exe) see at most "
                          "%llu MB available: %s (madeira.cfg avail-phys-cef-mb = %lld)\n", cef >> 20,
                          mb < 400 ? "Chromium's critical level, purges every 5 s" :
                          mb < 1000 ? "Chromium's moderate level, purges every 10 s" : "no pressure level", mb );
    }
    if (on && (left = (unsigned long long)os_proc_available_memory()) &&
        !(memsize && left > memsize))   /* rdr61: a "no limit" sentinel larger than the machine is not a measurement */
    {
        now = left < (400ull << 20) ? 2 : left < (1000ull << 20) ? 1 : 0;
        if (now != band && said < 64)
        {
            said++;
            dprintf( 2, "[avail-phys] %llu MB left before the limit (host free %llu MB): %s\n",
                     left >> 20, host_free >> 20,
                     now == 2 ? "below 400 MB, Chromium's critical level" :
                     now == 1 ? "below 1000 MB, Chromium's moderate level" : "1000 MB or more" );
        }
        band = now;
        if (left < host_free) value = left;
    }
    /* madeira-bcd: avail-phys-cef-mb, the Chromium browsers only (see above) */
    if (cef && value > cef && ios_avail_phys_chromium())
    {
        if (capped++ < 4)
            dprintf( 2, "[avail-phys] a Chromium browser asked: %llu MB reported instead of %llu MB "
                     "(madeira.cfg avail-phys-cef-mb)\n", cef >> 20, value >> 20 );
        value = cef;
    }
    return value;
}


/***********************************************************************
 *           get_system_affinity_mask
 */
ULONG_PTR get_system_affinity_mask(void)
{
    ULONG num_cpus = peb->NumberOfProcessors;
    if (num_cpus >= sizeof(ULONG_PTR) * 8) return ~(ULONG_PTR)0;
    return ((ULONG_PTR)1 << num_cpus) - 1;
}

/***********************************************************************
 *           virtual_get_system_info
 */
void virtual_get_system_info( SYSTEM_BASIC_INFORMATION *info, BOOL wow64 )
{
#if defined(HAVE_SYSINFO) \
    && defined(HAVE_STRUCT_SYSINFO_TOTALRAM) && defined(HAVE_STRUCT_SYSINFO_MEM_UNIT)
    struct sysinfo sinfo;

    if (!sysinfo(&sinfo))
    {
        ULONG64 total = (ULONG64)sinfo.totalram * sinfo.mem_unit;
        info->MmHighestPhysicalPage = max(1, total / page_size);
    }
#elif defined(__APPLE__)
    /* sysconf(_SC_PHYS_PAGES) is buggy on macOS: in a 32-bit process, it
     * returns an error on Macs with >4GB of RAM.
     */
    INT64 memsize;
    size_t len = sizeof(memsize);

    if (!sysctlbyname( "hw.memsize", &memsize, &len, NULL, 0 ))
        info->MmHighestPhysicalPage = max(1, memsize / page_size);

    /* ml992: report the memory THIS PROCESS may use, not the machine's installed
     * RAM.
     *
     * On iOS an app is killed at its jetsam limit no matter how much RAM the
     * machine has, so hw.memsize is the wrong answer to "how much physical
     * memory is there". It is badly wrong on the jailbroken VM, where
     * hw.memsize reports the HOST Mac's RAM: rdr60 measured
     * MmNumberOfPhysicalPages=8382715 x 4096 = 32744 MB advertised, against a
     * 4096 MB jetsam limit.
     *
     * That is not cosmetic. rdr60 pinned the consequence exactly: RDR2 reserves
     * 7/8 of reported physical memory as address space -- 32768 x 7/8 = 28672 MB
     * = the 0x700000000 MEM_RESERVE that fails with STATUS_NO_MEMORY, against a
     * largest free hole of 4299 MB. Every engine that sizes texture pools,
     * streaming budgets or quality presets off GlobalMemoryStatusEx has been
     * doing it against 8x the memory it can actually have.
     *
     * The limit is MEASURED, not assumed: os_proc_available_memory() is what
     * remains before jetsam, and TASK_VM_INFO.phys_footprint is what is already
     * charged, so their sum is this process's effective total. Cached on first
     * use so the advertised total does not shrink as we allocate.
     *
     * MADEIRA_TOTAL_PHYS_MB=N overrides it (0 = report hw.memsize unchanged), so
     * the effect can be A/B'd without a rebuild -- RDR2's stated minimum is 8GB
     * of RAM, and if it gates on that, reporting the honest ~4GB may trade one
     * failure for another. That trade needs measuring, not guessing. */
    {
        static unsigned long long cached_limit = ~0ull;

        if (cached_limit == ~0ull)
        {
            const char *env = getenv( "MADEIRA_TOTAL_PHYS_MB" );

            cached_limit = 0;
            if (env && *env)
            {
                cached_limit = strtoull( env, NULL, 10 ) * 1024ull * 1024ull;
                dprintf( 2, "ml992: MADEIRA_TOTAL_PHYS_MB=%s -> %llu MB (override)\n",
                         env, cached_limit >> 20 );
            }
            /* ml993: a config file, matching how every other knob in this port is
             * set (madeira-pool.txt, madeira-remote.txt, madeira-dxmt.txt ...).
             * getenv alone is not reachable for the user on the device. */
            if (!cached_limit)
            {
                long long mb = madeira_cfg_int( "totalphys", 0 );   /* ml1095: madeira.cfg totalphys = N */
                if (mb > 0)
                {
                    cached_limit = (unsigned long long)mb * 1024ull * 1024ull;
                    dprintf( 2, "ml993: totalphys -> %llu MB (madeira.cfg)\n", cached_limit >> 20 );
                }
            }
            /* ml993: the real jetsam limit. This is the number that actually kills
             * us, and unlike os_proc_available_memory it is a limit rather than a
             * remaining-bytes estimate. Private API, so failure is expected on
             * some configurations and falls through quietly. */
            if (!cached_limit)
            {
                struct { int32_t active; uint32_t active_attr;
                         int32_t inactive; uint32_t inactive_attr; } props;
                extern int memorystatus_control( uint32_t command, int32_t pid, uint32_t flags,
                                                 void *buffer, size_t buffersize );

                memset( &props, 0, sizeof(props) );
                if (memorystatus_control( 8 /* GET_MEMLIMIT_PROPERTIES */, getpid(), 0,
                                          &props, sizeof(props) ) == 0 && props.active > 0)
                {
                    cached_limit = (unsigned long long)props.active * 1024ull * 1024ull;
                    dprintf( 2, "ml993: jetsam memlimit_active=%d MB inactive=%d MB -> using "
                             "%llu MB\n", props.active, props.inactive, cached_limit >> 20 );
                }
                else dprintf( 2, "ml993: memorystatus_control(GET_MEMLIMIT_PROPERTIES) "
                              "unavailable (errno=%d)\n", errno );
            }
            if (!cached_limit)
            {
                /* declared explicitly rather than relying on <os/proc.h> being
                 * reachable here: an implicit declaration would return int and
                 * silently truncate a byte count.
                 *
                 * rdr61: this returned 0x7ffffddb00000 (~2048 TB) -- a "no limit"
                 * sentinel, not a measurement. ml992 printed it and then declined
                 * to act on it, which was the right failure mode but still cost a
                 * run. The bound below is the actual lesson: a measured value
                 * larger than the machine's own RAM is not a measurement, and I
                 * should have rejected it by construction rather than relying on
                 * the clamp-only-downward test to absorb it. */
                extern size_t os_proc_available_memory( void );
                unsigned long long avail = (unsigned long long)os_proc_available_memory();
                unsigned long long footprint = 0;
                task_vm_info_data_t vmi;
                mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;

                if (task_info( mach_task_self(), TASK_VM_INFO,
                               (task_info_t)&vmi, &cnt ) == KERN_SUCCESS)
                    footprint = (unsigned long long)vmi.phys_footprint;
                if (avail) cached_limit = avail + footprint;
                dprintf( 2, "ml992: os_proc_available_memory=%llu MB + phys_footprint=%llu MB "
                         "= %llu MB (hw.memsize says %llu MB)\n",
                         avail >> 20, footprint >> 20, cached_limit >> 20,
                         (unsigned long long)memsize >> 20 );
                if (cached_limit > (unsigned long long)memsize)
                {
                    dprintf( 2, "ml993: REJECTED %llu MB -- larger than hw.memsize (%llu MB), so "
                             "it is a sentinel, not a limit\n",
                             cached_limit >> 20, (unsigned long long)memsize >> 20 );
                    cached_limit = 0;
                }
            }
            if (!cached_limit)
                dprintf( 2, "ml993: no usable memory limit from any source -- reporting "
                         "hw.memsize (%llu MB) unchanged\n",
                         (unsigned long long)memsize >> 20 );
        }
        if (cached_limit && cached_limit / page_size < (unsigned long long)info->MmHighestPhysicalPage)
        {
            { static int ml1053_said; if (ml1053_said++ < 3)   /* was ~4,000 lines a run */
            dprintf( 2, "ml992: clamping reported physical memory %llu MB -> %llu MB (jetsam "
                     "kills us at the limit regardless of installed RAM)\n",
                     ((unsigned long long)info->MmHighestPhysicalPage * page_size) >> 20,
                     cached_limit >> 20 ); }
            info->MmHighestPhysicalPage = max( 1, cached_limit / page_size );
        }
    }
#elif defined(_SC_PHYS_PAGES)
    LONG64 phys_pages = sysconf( _SC_PHYS_PAGES );

    info->MmHighestPhysicalPage = max(1, phys_pages);
#else
    info->MmHighestPhysicalPage = 0x7fffffff / page_size;
#endif

    info->unknown                 = 0;
    info->KeMaximumIncrement      = 0;  /* FIXME */
    info->PageSize                = page_size;
    info->MmLowestPhysicalPage    = 1;
    info->MmNumberOfPhysicalPages = info->MmHighestPhysicalPage - info->MmLowestPhysicalPage;
    info->AllocationGranularity   = granularity_mask + 1;
    info->LowestUserAddress       = (void *)0x10000;
    info->ActiveProcessorsAffinityMask = get_system_affinity_mask();
    info->NumberOfProcessors      = peb->NumberOfProcessors;
    if (wow64) info->HighestUserAddress = (char *)get_wow_user_space_limit() - 1;
    else info->HighestUserAddress = (char *)user_space_limit - 1;

    /* madeira-bcd: Social Club layout 2 -- see ios_sc2_reported_highest */
    if (!wow64 && ios_sc_layout_mode == 2 && ios_sc_cef_enabled())
    {
        ULONG_PTR real = (ULONG_PTR)info->HighestUserAddress;
        ULONG_PTR told = ios_sc2_reported_highest( real, wow64, ios_sc_layout_mode, ios_sc_current_is_helper() );

        if (told != real)
        {
            static void *said;
            void *peb = ios_jit_current_peb();

            info->HighestUserAddress = (void *)told;
            if (said != peb)
            {
                said = peb;
                dprintf( 2, "[sc-cef] layout 2: SocialClubHelper.exe (peb=%p) told HighestUserAddress=%p (V8 CHECKs "
                            "its 1 TB sandbox against lpMaximumApplicationAddress); placement keeps %p\n",
                         peb, (void *)told, (void *)real );
            }
        }
    }

    /* ml991: report, once, exactly what an application is told about memory.
     *
     * rdr59's wall is a 0x700000000 (28,672 MB) MEM_RESERVE that cannot be
     * satisfied. Offline disassembly of the caller's neighbourhood in the exe
     * shows a cached getter that calls GlobalMemoryStatusEx and keeps struct
     * +0x8 -- ullTotalPhys, NOT +0x28 ullTotalVirtual. 0x700000000 is exactly
     * 7 x 4GB. So the multiplier is probably against PHYSICAL memory, and
     * ml990's user_space_limit clamp (which only moves ullTotalVirtual) very
     * likely does NOT change the request.
     *
     * Rather than guess which number to change next, print every value that
     * feeds GlobalMemoryStatusEx and GetSystemInfo. ullTotalPhys and
     * ullTotalVirtual are computed here the same way kernelbase/memory.c:1432
     * and :1436 compute them, so the log carries what the game actually sees
     * and the next build can change ONE number on evidence. */
    {
        static int once;
        if (!once++)
        {
            unsigned long long phys = (unsigned long long)info->MmNumberOfPhysicalPages *
                                      (unsigned long long)info->PageSize;
            unsigned long long virt = (unsigned long long)((ULONG_PTR)info->HighestUserAddress -
                                                           (ULONG_PTR)info->LowestUserAddress + 1);
            dprintf( 2, "ml991: SystemBasicInformation wow=%d PageSize=%u AllocGranularity=%u "
                     "MmNumberOfPhysicalPages=%u LowestUserAddress=%p HighestUserAddress=%p\n",
                     wow64, (unsigned)info->PageSize, (unsigned)info->AllocationGranularity,
                     (unsigned)info->MmNumberOfPhysicalPages,
                     info->LowestUserAddress, info->HighestUserAddress );
            dprintf( 2, "ml991: => ullTotalPhys=%llu (%llu MB)  ullTotalVirtual=%llu (%llu MB)"
                     "  [the 28GB reserve is 0x700000000 = 7 x 4096MB]\n",
                     phys, phys >> 20, virt, virt >> 20 );
        }
    }
}

/* madeira-bcd: the highest user address placement may use -- what
 * virtual_get_system_info reports before ios_sc2_reported_highest widens it for
 * SocialClubHelper.exe. server_ios.c caps a remote allocation's or view's
 * limit_high with it: the widened value would fail get_extended_params' check
 * against user_space_limit. */
ULONG_PTR ios_highest_user_address( BOOL wow64 )
{
    return wow64 ? get_wow_user_space_limit() - 1 : (ULONG_PTR)user_space_limit - 1;
}


/***********************************************************************
 *           virtual_map_builtin_module
 */
NTSTATUS virtual_map_builtin_module( HANDLE mapping, void **module, SIZE_T *size,
                                     SECTION_IMAGE_INFORMATION *info, ULONG_PTR limit_low,
                                     ULONG_PTR limit_high, WORD machine, BOOL prefer_native, off_t offset )
{
    mem_size_t full_size;
    unsigned int sec_flags;
    HANDLE shared_file;
    struct pe_image_info *image_info = NULL;
    NTSTATUS status;
    UNICODE_STRING nt_name;
    ANSI_STRING exp_name;

    if ((status = get_mapping_info( mapping, SECTION_MAP_READ, &sec_flags, &full_size, &shared_file,
                                    &image_info, &nt_name, &exp_name )))
        return status;

    if (!image_info) return STATUS_INVALID_PARAMETER;

    *module = NULL;
    *size = 0;

    if (!image_info->wine_builtin) /* ignore non-builtins */
    {
        if (!image_info->wine_fakedll)
            WARN_(module)( "%s found in WINEDLLPATH but not a builtin, ignoring\n", debugstr_us(&nt_name) );
        status = STATUS_DLL_NOT_FOUND;
    }
    else if (prefer_native && (image_info->dll_charact & IMAGE_DLLCHARACTERISTICS_PREFER_NATIVE))
    {
        TRACE_(module)( "%s has prefer-native flag, ignoring builtin\n", debugstr_us(&nt_name) );
        status = STATUS_IMAGE_ALREADY_LOADED;
    }
    else
    {
        status = virtual_map_image( mapping, module, size, shared_file, limit_low, limit_high, 0,
                                    machine, image_info, &nt_name, TRUE, offset );
        virtual_fill_image_information( image_info, info );
    }

    if (shared_file) NtClose( shared_file );
    free( image_info );
    return status;
}


/***********************************************************************
 *           virtual_map_module
 */
NTSTATUS virtual_map_module( HANDLE mapping, void **module, SIZE_T *size, SECTION_IMAGE_INFORMATION *info,
                             ULONG_PTR limit_low, ULONG_PTR limit_high, USHORT machine )
{
    unsigned int status;
    mem_size_t full_size;
    unsigned int sec_flags;
    HANDLE shared_file;
    struct pe_image_info *image_info = NULL;
    UNICODE_STRING nt_name;
    ANSI_STRING exp_name;

    if ((status = get_mapping_info( mapping, SECTION_MAP_READ, &sec_flags, &full_size, &shared_file,
                                    &image_info, &nt_name, &exp_name )))
        return status;

    if (!image_info) return STATUS_INVALID_PARAMETER;

    *module = NULL;
    *size = 0;

    /* check if we can replace that mapping with the builtin */
    status = load_builtin( image_info, &nt_name, &exp_name, machine, info,
                           module, size, limit_low, limit_high, 0 );
    if (status == STATUS_IMAGE_ALREADY_LOADED)
    {
        ios_exe_win_wait_for_handoff( image_info );
        status = virtual_map_image( mapping, module, size, shared_file, limit_low, limit_high, 0,
                                    machine, image_info, &nt_name, FALSE, 0 );
        virtual_fill_image_information( image_info, info );
    }
    if (shared_file) NtClose( shared_file );
    free( image_info );
    return status;
}


/***********************************************************************
 *           virtual_create_builtin_view
 */
NTSTATUS virtual_create_builtin_view( void *module, const UNICODE_STRING *nt_name,
                                      struct pe_image_info *info, void *so_handle )
{
    NTSTATUS status;
    sigset_t sigset;
    IMAGE_DOS_HEADER *dos = module;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)dos + dos->e_lfanew);
    SIZE_T size = info->map_size;
    IMAGE_SECTION_HEADER *sec;
    struct file_view *view;
    void *base = wine_server_get_ptr( info->base );
    int i;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    status = create_view( &view, base, size, SEC_IMAGE | SEC_FILE | VPROT_SYSTEM |
                          VPROT_COMMITTED | VPROT_READ | VPROT_WRITECOPY | VPROT_EXEC );
    if (!status)
    {
        TRACE( "created %p-%p for %s\n", base, (char *)base + size, debugstr_us(nt_name) );

        /* The PE header is always read-only, no write, no execute. */
        set_page_vprot( base, page_size, VPROT_COMMITTED | VPROT_READ );

        sec = IMAGE_FIRST_SECTION( nt );
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            BYTE flags = VPROT_COMMITTED;

            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) flags |= VPROT_EXEC;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_READ) flags |= VPROT_READ;
            if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) flags |= VPROT_WRITE;
            set_page_vprot( (char *)base + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, flags );
        }

        SERVER_START_REQ( map_builtin_view )
        {
            wine_server_add_data( req, info, sizeof(*info) );
            wine_server_add_data( req, nt_name->Buffer, nt_name->Length );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;

        if (!status)
        {
            add_builtin_module( view->base, so_handle );
            VIRTUAL_DEBUG_DUMP_VIEW( view );
            if (is_beyond_limit( base, size, working_set_limit )) working_set_limit = address_space_limit;
        }
        else delete_view( view );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    return status;
}


/***********************************************************************
 *           virtual_relocate_module
 */
NTSTATUS virtual_relocate_module( void *module )
{
    char *ptr = module;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(ptr + ((IMAGE_DOS_HEADER *)module)->e_lfanew);
    IMAGE_DATA_DIRECTORY *relocs;
    IMAGE_BASE_RELOCATION *rel, *end;
    IMAGE_SECTION_HEADER *sec;
    ULONG total_size = ROUND_SIZE( 0, nt->OptionalHeader.SizeOfImage, page_mask );
    ULONG *protect_old, i;
    ULONG_PTR image_base;
    ULONG_PTR target_base = (ULONG_PTR)module;
    INT_PTR delta;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        image_base = ((const IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.ImageBase;
    else
        image_base = ((const IMAGE_NT_HEADERS32 *)nt)->OptionalHeader.ImageBase;

#ifdef WINE_IOS
    /* WoW64 guest window: relocate a window-resident image to its GUEST base
     * (host - B), which is the address its own 32-bit code will see. */
    if (ios_wow_in_window( module )) target_base -= ios_wow_base();
#endif

    if (!(delta = target_base - image_base)) return STATUS_SUCCESS;

    if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
    {
        ERR( "Need to relocate module from %p to %p, but relocation records are stripped\n",
             (void *)image_base, module );
        return STATUS_CONFLICTING_ADDRESSES;
    }

    TRACE( "%p -> %p\n", (void *)image_base, module );

    if (!(relocs = get_data_dir( nt, total_size, IMAGE_DIRECTORY_ENTRY_BASERELOC ))) return STATUS_SUCCESS;

    if (!(protect_old = malloc( nt->FileHeader.NumberOfSections * sizeof(*protect_old ))))
        return STATUS_NO_MEMORY;

    sec = IMAGE_FIRST_SECTION( nt );
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr = (char *)module + sec[i].VirtualAddress;
        SIZE_T size = sec[i].SizeOfRawData;
        NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, PAGE_READWRITE, &protect_old[i] );
    }


    rel = (IMAGE_BASE_RELOCATION *)((char *)module + relocs->VirtualAddress);
    end = (IMAGE_BASE_RELOCATION *)((char *)rel + relocs->Size);

    while (rel && rel < end - 1 && rel->SizeOfBlock && rel->VirtualAddress < total_size)
        rel = process_relocation_block( (char *)module + rel->VirtualAddress, rel, delta );

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        void *addr = (char *)module + sec[i].VirtualAddress;
        SIZE_T size = sec[i].SizeOfRawData;
        NtProtectVirtualMemory( NtCurrentProcess(), &addr, &size, protect_old[i], &protect_old[i] );
    }
    free( protect_old );
    return STATUS_SUCCESS;
}


/* set some initial values in a new TEB */
static TEB *init_teb( void *ptr, BOOL is_wow )
{
    struct ntdll_thread_data *thread_data;
    TEB *teb;
    TEB64 *teb64 = ptr;
    TEB32 *teb32 = (TEB32 *)((char *)ptr + teb_offset);
#ifdef WINE_IOS
    /* WoW64 guest window: every 32-bit-wide self-reference in the TEB pair is
     * a GUEST address.  The pair and the PEB pair are allocated inside the
     * window for a WoW pseudo-process (see virtual_alloc_teb), so
     * ios_wow_guest_addr() is host - B; outside a window it is the plain
     * truncating PtrToUlong this code used before. */
    PEB *proc_peb = ios_jit_current_peb();

    if (!proc_peb) proc_peb = peb;
#else
    PEB *proc_peb = peb;
#endif

#ifdef _WIN64
    teb = (TEB *)teb64;
    teb32->Peb = ios_wow_guest_addr( (char *)proc_peb + page_size );
    teb32->Tib.Self = ios_wow_guest_addr( teb32 );
    teb32->Tib.ExceptionList = ~0u;
    teb32->ActivationContextStackPointer = ios_wow_guest_addr( &teb32->ActivationContextStack );
    teb32->ActivationContextStack.FrameListCache.Flink =
        teb32->ActivationContextStack.FrameListCache.Blink =
            ios_wow_guest_addr( &teb32->ActivationContextStack.FrameListCache );
    teb32->StaticUnicodeString.Buffer = ios_wow_guest_addr( teb32->StaticUnicodeBuffer );
    teb32->StaticUnicodeString.MaximumLength = sizeof( teb32->StaticUnicodeBuffer );
    teb32->GdiBatchCount = ios_wow_guest_addr( teb64 );
    teb32->WowTebOffset  = -teb_offset;
    if (is_wow) teb64->WowTebOffset = teb_offset;
#else
    teb = (TEB *)teb32;
    teb32->Tib.ExceptionList = ~0u;
    teb64->Peb = PtrToUlong( (char *)peb - page_size );
    teb64->Tib.Self = PtrToUlong( teb64 );
    teb64->Tib.ExceptionList = PtrToUlong( teb32 );
    teb64->ActivationContextStackPointer = PtrToUlong( &teb64->ActivationContextStack );
    teb64->ActivationContextStack.FrameListCache.Flink =
        teb64->ActivationContextStack.FrameListCache.Blink =
            PtrToUlong( &teb64->ActivationContextStack.FrameListCache );
    teb64->StaticUnicodeString.Buffer = PtrToUlong( teb64->StaticUnicodeBuffer );
    teb64->StaticUnicodeString.MaximumLength = sizeof( teb64->StaticUnicodeBuffer );
    teb64->WowTebOffset = teb_offset;
    if (is_wow)
    {
        teb32->GdiBatchCount = PtrToUlong( teb64 );
        teb32->WowTebOffset  = -teb_offset;
    }
#endif
    teb->Peb = peb;
#ifdef WINE_IOS
    /* S1 pseudo-processes: a new thread belongs to its CREATOR's process.
     * The global `peb` is switched (permanently) to the child's PEB during
     * a child spawn, so parent threads created afterwards must not inherit
     * it. ios_jit_current_peb() resolves the creating thread's PEB and is
     * NULL-safe during early boot (falls back to the global). */
    {
        extern void *ios_jit_current_peb(void);
        void *creator_peb = ios_jit_current_peb();
        if (creator_peb) teb->Peb = creator_peb;
    }
#endif
    teb->Tib.Self = &teb->Tib;
    teb->Tib.StackBase = (void *)~0ul;
    teb->ActivationContextStackPointer = &teb->ActivationContextStack;
    InitializeListHead( &teb->ActivationContextStack.FrameListCache );
    teb->StaticUnicodeString.Buffer = teb->StaticUnicodeBuffer;
    teb->StaticUnicodeString.MaximumLength = sizeof(teb->StaticUnicodeBuffer);
    thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
    thread_data->request_fd = -1;
    thread_data->reply_fd   = -1;
    thread_data->wait_fd[0] = -1;
    thread_data->wait_fd[1] = -1;
    thread_data->alert_fd   = -1;
    list_add_head( &teb_list, &thread_data->entry );
    return teb;
}


/***********************************************************************
 *           virtual_alloc_first_teb
 */
TEB *virtual_alloc_first_teb(void)
{
    void *ptr;
    TEB *teb;
    unsigned int status;
    SIZE_T data_size = page_size;
    SIZE_T block_size = signal_stack_mask + 1;
    SIZE_T total = 32 * block_size;

    /* reserve space for shared user data */
#ifdef WINE_IOS
    /* iOS arm64 has mandatory 4GB __PAGEZERO — can't map at 0x7ffe0000 */
    user_shared_data = NULL;
#endif
    status = NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&user_shared_data, 0, &data_size,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_READONLY );
    if (status)
    {
        ERR( "wine: failed to map the shared user data: %08x\n", status );
        exit(1);
    }

#ifdef WINE_IOS
    /* ml952: KUSER_SHARED_DATA is a SUB-FLOOR WINDOW.
     *
     * Windows puts it at the architectural constant 0x7ffe0000, which iOS's
     * mandatory 4GB __PAGEZERO makes unmappable, so the block above relocates it
     * high. Everything that goes through Wine reads the relocated pointer and is
     * fine -- but guest code that reads the CONSTANT reads 0x7ffe0000, which is
     * simply absent, and that is invisible until a guest does it.
     *
     * Measured: with the ml949 relocation fix in place, a game's anti-tamper
     * layer polls `ldapr w8,[x29]` on 0x7ffe02e8 and took 2.3 MILLION Mach
     * exceptions at one pc without progressing -- almost certainly a spin
     * waiting for a timestamp to advance, which it never can while the read
     * faults. (Before ml949 the same read appeared as 0x7ffe02e8 + module delta,
     * which is how the relocation bug was originally found.)
     *
     * Register the canonical page as a sub-floor window onto the real one, so
     * those reads are serviced against live, advancing data by the same handler
     * that already services sub-floor image windows. This is a general gap, not
     * a per-title fix: any guest reading KUSER_SHARED_DATA directly hit it. */
    if (user_shared_data)
    {
        extern void ios_register_subfloor_image( unsigned long long pref_base,
                                                 unsigned long long size,
                                                 unsigned long long real_base, void *owner );
        ios_register_subfloor_image( 0x7ffe0000ull, (unsigned long long)page_size,
                                     (unsigned long long)(uintptr_t)user_shared_data,
                                     NULL );   /* ml1205: shared by every process */
        fprintf( stderr, "ml952: KUSER_SHARED_DATA window guest 0x7ffe0000+%#llx -> real %p\n",
                 (unsigned long long)page_size, user_shared_data );
    }
#endif

#ifdef WINE_IOS
    /* iOS 4GB __PAGEZERO blocks all addresses below 4GB — skip below-2GB
     * constraint.  BUT: for a 32-bit MAIN process (start_main_thread reserved
     * a window before calling us), the first TEB block and the PEB derived
     * from it must live inside that window, exactly like a child's block in
     * virtual_alloc_teb.  A guest 4G ceiling routes it through the same
     * ios_wow_translate_limits chokepoint into [B, B+2G); ios_wow_base()
     * resolves here via the owner fallback because the window is reserved but
     * not yet bound.  0 outside a window (the 64-bit case) keeps the old
     * behaviour.
     *
     * The ceiling is 2 GB, as upstream uses for the first TEB of a 64-bit
     * process, NOT 4 GB.  Third device run: a 4 GB ceiling put the first TEB
     * block at guest 0xFFFE0000 and the PEB pair at guest 0xFFFF0000, while the
     * main image was not large-address-aware (characteristics 0x102) — such
     * code treats every address >= 0x80000000 as invalid, so its own TEB32/PEB32
     * were unusable.  The image is not mapped yet here, so its LAA bit is not
     * knowable; 2 GB is the answer that is correct for both kinds of image
     * (Windows keeps the TEB low even for an LAA program), which is exactly why
     * upstream hardcodes it too. */
    {
        ULONG_PTR wb = ios_wow_base();
        ULONG_PTR teb_zbits = wb ? (limit_2g - 1) : 0;

        /* ml1040: KUSER_SHARED_DATA lives at guest 0x7ffe0000 and the top-down
         * search below would otherwise take exactly that address.  Hold it
         * first; ios_wow_map_user_shared_data() hands the reservation back when
         * it maps the real view.  See ios_wow_reserve_usd_slot. */
        if (wb) ios_wow_reserve_usd_slot( wb );

        NtAllocateVirtualMemory( NtCurrentProcess(), &teb_block, teb_zbits, &total,
                                 MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );
    }
#else
    NtAllocateVirtualMemory( NtCurrentProcess(), &teb_block, is_win64 ? limit_2g - 1 : 0, &total,
                             MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE );
#endif
    teb_block_pos = 30;
    ptr = (char *)teb_block + 30 * block_size;
    data_size = 2 * block_size;
    NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&ptr, 0, &data_size, MEM_COMMIT, PAGE_READWRITE );
    peb = (PEB *)((char *)teb_block + 31 * block_size + (is_win64 ? 0 : page_size));
#ifdef WINE_IOS
    ios_session_peb = peb;   /* see ios_wow_window_teardown */
#endif
    teb = init_teb( ptr, FALSE );
    pthread_key_create( &teb_key, NULL );
    pthread_setspecific( teb_key, teb );
    return teb;
}


/***********************************************************************
 *           virtual_alloc_teb
 */
NTSTATUS virtual_alloc_teb( TEB **ret_teb )
{
    sigset_t sigset;
    TEB *teb;
    void *ptr = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T block_size = signal_stack_mask + 1;
    BOOL is_wow = is_wow64();
#ifdef WINE_IOS
    /* WoW64 guest window: a 32-bit process's TEB64/TEB32 pair — and the PEB
     * pair that lives in the same block — must be addressable as guest
     * addresses, so the block comes out of THIS process's window instead of
     * the session-wide teb_block.  Each window keeps its own block/free list
     * (ios_wow_windows[].teb_block), because the session block is shared by
     * every pseudo-process and cannot be in any one process's window. */
    struct ios_wow_window *wow = ios_wow_slot_current();
    void **p_teb_block     = wow ? &wow->teb_block     : &teb_block;
    void ***p_next_free_teb = wow ? &wow->next_free_teb : &next_free_teb;
    int   *p_teb_block_pos = wow ? &wow->teb_block_pos : &teb_block_pos;

    /* Decide WoW-ness PER PROCESS, from this process's own
     * guest window, not from the session-wide wow_peb that is_wow64() reads.
     * A window exists if and only if the owning pseudo-process is 32-bit, so
     * this is exact — and it stops 64-bit threads created after a 32-bit child
     * has started from getting WowTebOffset set (which would hand them a
     * 32-bit stack and a CPU area in init_thread_stack). */
    is_wow = (wow != NULL);
#else
    void **p_teb_block     = &teb_block;
    void ***p_next_free_teb = &next_free_teb;
    int   *p_teb_block_pos = &teb_block_pos;
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (*p_next_free_teb)
    {
        ptr = *p_next_free_teb;
        *p_next_free_teb = *(void **)ptr;
        memset( ptr, 0, teb_size );
    }
    else
    {
        if (!*p_teb_block_pos)
        {
            SIZE_T total = 32 * block_size;
            /* a guest ceiling: allocate_virtual_memory turns it into
             * [B, B + user_space_wow_limit] for a windowed process */
            ULONG_PTR zbits = user_space_wow_limit;

#ifdef WINE_IOS
            /* Once published, user_space_wow_limit already IS the right ceiling
             * (2 GB or 4 GB by the main image's LAA bit).  Only a thread created
             * before init_peb publishes it lands here, and then the answer is
             * the conservative 2 GB: it is valid for an LAA image as well, while
             * 4 GB would hand a non-LAA program a TEB32/PEB32 above 0x80000000
             * (the third device run's 0xFFFE0000/0xFFFF0000). */
            if (wow && !zbits) zbits = limit_2g - 1;
            /* ml1210: user_space_wow_limit is session-wide and is set by the
             * first 32-bit process (0xffffffff once one ran), but it is a
             * GUEST ceiling: a 64-bit thread's next TEB block was being
             * reserved below 4GB, where iOS maps nothing. Once the first 32-TEB
             * block was used up, every new 64-bit thread failed (the server saw
             * EOF on its request fd and killed it), and a 64-bit program whose
             * worker thread could not be created stopped there. Upstream applies
             * a limit to WoW TEB blocks only. */
            if (!wow) zbits = 0;
#endif
            status = STATUS_NO_MEMORY;
#ifdef WINE_IOS
            /* [laa] TEB BLOCKS PREFER THE LOW 2 GB — and now have to say so out
             * loud, because ios_wow_ceiling_for_charact() may have raised
             * user_space_wow_limit to 4 GB for an image that never asked for it.
             * Windows keeps the TEB low even for a large-address-aware program,
             * the first block here is hardcoded to limit_2g for exactly that
             * reason, and the third device run showed what the alternative costs
             * (TEB32 at guest 0xFFFE0000, PEB32 at 0xFFFF0000, unusable to code
             * that treats the sign bit as an error flag).
             *
             * PREFER, not require: if the low half is full, a TEB above 2 GB is
             * still far better than a thread that cannot be created at all, so
             * this falls back to the published ceiling.  32 blocks of TEB per
             * reservation makes this rare enough to be a non-event. */
            if (wow && zbits > limit_2g - 1)
            {
                SIZE_T low_total = total;

                status = NtAllocateVirtualMemory( NtCurrentProcess(), &ptr, limit_2g - 1,
                                                  &low_total, MEM_RESERVE, PAGE_READWRITE );
                if (status)
                {
                    static int spilled;

                    if (spilled++ < 8)
                        dprintf( 2, "[laa] no room below guest 2 GB for a TEB block (status %x); "
                                    "falling back to the raised ceiling %p\n",
                                 (unsigned)status, (void *)zbits );
                }
                else total = low_total;
            }
#endif
            if (status && (status = NtAllocateVirtualMemory( NtCurrentProcess(), &ptr, zbits,
                                                             &total, MEM_RESERVE, PAGE_READWRITE )))
            {
                server_leave_uninterrupted_section( &virtual_mutex, &sigset );
                return status;
            }
            *p_teb_block = ptr;
            *p_teb_block_pos = 32;
        }
        ptr = ((char *)*p_teb_block + --*p_teb_block_pos * block_size);
        NtAllocateVirtualMemory( NtCurrentProcess(), (void **)&ptr, 0, &block_size,
                                 MEM_COMMIT, PAGE_READWRITE );
    }
#ifdef WINE_IOS
    /* LOUD, LOCAL FAILURE instead of a task-wide death.
     *
     * A thread of a 32-bit pseudo-process whose TEB block is outside that
     * process's guest window is unrunnable: init_teb derives TEB32 (and the FS
     * base FEX publishes) by TRUNCATING this host address, so the 32-bit view
     * of its own TEB points at unmapped guest memory and the very first TEB
     * access from x86 code faults — at a pc and on a thread where nothing can
     * recover, which is how it turned into a redelivery storm and took the
     * whole app down.  Refuse the thread here with a named log instead.  The
     * block is deliberately NOT pooled: it does not belong to this window and
     * we do not know whose it is, so dropping 32 KB of VA is the cheap answer.
     *
     * With the address-keyed free list in virtual_free_teb this should now be
     * unreachable; it stays as the assertion that makes a regression legible
     * in one line of log rather than 2,000 redeliveries. */
    if (wow && (ULONG_PTR)ptr - wow->base >= IOS_WOW_WINDOW_SIZE)
    {
        dprintf( 2, "[teb-window] REFUSING thread: TEB block %p is OUTSIDE this 32-bit "
                    "process's guest window [0x%llx, 0x%llx) — its TEB32/FS base would be "
                    "the truncated host address 0x%x and every TEB access from 32-bit code "
                    "would be wild\n", ptr, (unsigned long long)wow->base,
                 (unsigned long long)(wow->base + IOS_WOW_WINDOW_SIZE),
                 (unsigned)(ULONG_PTR)ptr );
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        return STATUS_NO_MEMORY;
    }
#endif
    *ret_teb = teb = init_teb( ptr, is_wow );

    if ((status = signal_alloc_thread( teb )))
    {
        *(void **)ptr = *p_next_free_teb;
        *p_next_free_teb = ptr;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *           virtual_free_teb
 */
/* madeira-bcd: STACK QUARANTINE. An exited thread's native stack is decommitted
 * but stays reserved for the next IOS_STACKQ_N thread stack frees before its
 * address range is released. Ghost of Tsushima's worker threads faulted
 * copying from a range that had been that stack and then held a fresh 2 MB
 * allocation, removed while the copies ran; if something still acts on a dead
 * thread's stack, it now meets the reservation instead of whatever the
 * program allocated there next, and the release below says so. */
#define IOS_STACKQ_N 8
static struct { void *base; size_t size; } ios_stackq[IOS_STACKQ_N];
static unsigned int ios_stackq_pos;
static void ios_stack_release( void *base )
{
    struct file_view *view;
    sigset_t sigset;
    size_t vsize = 0, oldsize = 0;
    void *old = NULL;
    SIZE_T size;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    view = find_view( base, 0 );
    if (view && view->base == base)
    {
        vsize = view->size;
        view->ios_flags |= IOS_VIEW_QUARANTINED;
        old = ios_stackq[ios_stackq_pos].base; oldsize = ios_stackq[ios_stackq_pos].size;
        ios_stackq[ios_stackq_pos].base = base; ios_stackq[ios_stackq_pos].size = vsize;
        ios_stackq_pos = (ios_stackq_pos + 1) % IOS_STACKQ_N;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (!vsize)
    {
        static int said;
        if (said++ < 16)
            dprintf( 2, "[stack-quarantine] %p is not the base of a view any more; released directly\n", base );
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &base, &size, MEM_RELEASE );
        return;
    }
    size = vsize;
    NtFreeVirtualMemory( GetCurrentProcess(), &base, &size, MEM_DECOMMIT );
    if (old)
    {
        int ok;
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        view = find_view( old, 0 );
        /* the mark, not base and size: a new stack of the same size may have taken the
         * range after someone else released the quarantined one */
        ok = view && view->base == old && view->size == oldsize && (view->ios_flags & IOS_VIEW_QUARANTINED);
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        if (ok)
        {
            size = 0;
            NtFreeVirtualMemory( GetCurrentProcess(), &old, &size, MEM_RELEASE );
        }
        else
        {
            static int said;
            if (said++ < 32)
                dprintf( 2, "[stack-quarantine] dead thread stack %p+0x%lx was FREED OR REPLACED by someone else while quarantined -- not released again\n",
                         old, (unsigned long)oldsize );
        }
    }
}

void virtual_free_teb( TEB *teb )
{
    struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&teb->GdiTebBatch;
    void *ptr;
    SIZE_T size;
    sigset_t sigset;
    WOW_TEB *wow_teb = get_wow_teb( teb );

    ios_vh_why = "TEB free (thread stacks)";   /* madeira-bcd: view history */
    if (teb->DeallocationStack) ios_stack_release( teb->DeallocationStack );   /* madeira-bcd: quarantined */
#ifdef __aarch64__
    if (teb->ChpeV2CpuAreaInfo)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), (void **)&teb->ChpeV2CpuAreaInfo, &size, MEM_RELEASE );
    }
#endif
    if (thread_data->kernel_stack)
    {
        size = 0;
        NtFreeVirtualMemory( GetCurrentProcess(), &thread_data->kernel_stack, &size, MEM_RELEASE );
    }
    if (wow_teb && (ptr = ULongToPtr( wow_teb->DeallocationStack )))
    {
        size = 0;
#ifdef WINE_IOS
        /* guest -> host: a WoW thread's 32-bit stack pointer is a guest
         * address.  Outside a window ios_wow_base() is 0 and this is the
         * classic identity. */
        ptr = (char *)ptr + ios_wow_base();
#endif
        NtFreeVirtualMemory( GetCurrentProcess(), &ptr, &size, MEM_RELEASE );
    }
    ios_vh_why = NULL;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    signal_free_thread( teb );
    list_remove( &thread_data->entry );
    ptr = teb;
    if (!is_win64) ptr = (char *)ptr - teb_offset;
#ifdef WINE_IOS
    /* Return the block to the list it CAME FROM, keyed on the address of the
     * block itself — never on the freeing thread's own window.
     *
     * DEVICE EVIDENCE (the run where a 32-bit thread's whole task died on
     * thread start): this used to read `ios_wow_slot_current()`, i.e. the
     * window of whoever happened to be running the free.  exit_thread does not
     * free its own TEB — it hands the PREVIOUS exiting thread's TEB to the NEXT
     * thread to exit (thread_ios.c, the `prev_teb` handoff), and those two
     * threads belong to different pseudo-processes all the time.  A 64-bit
     * thread's TEB out of the SESSION block (0x70ffec0000) was freed by a
     * 32-bit thread of a windowed pseudo-process, so it was pushed onto THAT
     * WINDOW's free list; the next thread created in that 32-bit process popped
     * it, and its TEB32/FS base became the truncated host address 0xffec2000.
     * Every TEB access from 32-bit code then read guest 0xffecxxxx — nothing is
     * mapped there — and the redelivery storm killed the whole app.
     *
     * Keying on the address is exact in BOTH directions and makes the old
     * one-directional guard below a plain sub-case: a block inside a window
     * that is no longer live matches no list and is dropped (its VA goes away
     * with the window), and a session block always goes back to the session. */
    {
        struct ios_wow_window *wow = ios_wow_live_slot_for_addr( ptr );
        void ***free_list = wow ? &wow->next_free_teb : &next_free_teb;

        /* NEVER put a block that lives inside a guest window on the SESSION
         * free list.  A laggard thread of a pseudo-process whose window has
         * already been released resolves no window any more (the slot is dead),
         * so it would have donated window VA to the session — and the next
         * 64-bit thread's TEB would then sit in a range that the next 32-bit
         * process is about to replace and fill with its own images.  Drop the
         * block instead: it is inside the window and goes away with it. */
        if (!wow && ios_wow_addr_in_any_window( ptr ))
            dprintf( 2, "[wow-window] TEB block %p dropped, not pooled: it belongs to a guest "
                        "window that is no longer live\n", ptr );
        else
        {
            *(void **)ptr = *free_list;
            *free_list = ptr;
        }
    }
#else
    *(void **)ptr = next_free_teb;
    next_free_teb = ptr;
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}


/* LDT support */

#if defined(__i386__) || defined(__x86_64__)

struct ldt_copy
{
    unsigned int    base[LDT_SIZE];
    struct ldt_bits bits[LDT_SIZE];
};
C_ASSERT( sizeof(struct ldt_copy) == 8 * LDT_SIZE );

static struct ldt_copy *ldt_copy;

UINT ldt_bitmap[LDT_SIZE / 32] = { ~0u };

/***********************************************************************
 *           ldt_update_entry
 */
WORD ldt_update_entry( WORD sel, LDT_ENTRY entry )
{
    unsigned int index = sel >> 3;

    if (!ldt_copy)
    {
        struct file_view *view;

#ifdef WINE_IOS
        if (map_view( &view, NULL, sizeof(*ldt_copy), MEM_TOP_DOWN,
                      VPROT_COMMITTED | VPROT_READ | VPROT_WRITE,
                      0, 0, 0 )) return 0;
#else
        if (map_view( &view, NULL, sizeof(*ldt_copy), MEM_TOP_DOWN,
                      VPROT_COMMITTED | VPROT_READ | VPROT_WRITE,
                      is_win64 ? limit_2g : 0, limit_4g, 0 )) return 0;
#endif
        ldt_copy = view->base;
        if (is_win64) wow_peb->SpareUlongs[0] = PtrToUlong( ldt_copy );
        else peb->SpareUlongs[0] = PtrToUlong( ldt_copy );
    }

    ldt_set_entry( sel, entry );
    ldt_copy->base[index]             = ldt_get_base( entry );
    ldt_copy->bits[index].limit       = entry.LimitLow | (entry.HighWord.Bits.LimitHi << 16);
    ldt_copy->bits[index].type        = entry.HighWord.Bits.Type;
    ldt_copy->bits[index].granularity = entry.HighWord.Bits.Granularity;
    ldt_copy->bits[index].default_big = entry.HighWord.Bits.Default_Big;
    ldt_bitmap[index / 32] |= 1u << (index & 31);
    return sel;
}

/***********************************************************************
 *           ldt_get_entry
 */
NTSTATUS ldt_get_entry( WORD sel, CLIENT_ID client_id, LDT_ENTRY *entry )
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned int base = 0;
    struct ldt_bits bits = { 0 };
    unsigned int idx = sel >> 3;

    if (client_id.UniqueProcess == NtCurrentTeb()->ClientId.UniqueProcess)
    {
        if (ldt_copy)
        {
            base = ldt_copy->base[idx];
            bits = ldt_copy->bits[idx];
        }
    }
    else
    {
        HANDLE process;
        ULONG ptr = 0;
        PEB32 *peb32 = NULL;

        if ((status = NtOpenProcess( &process, PROCESS_ALL_ACCESS, NULL, &client_id ))) return status;

        if (!is_win64)
        {
            PROCESS_BASIC_INFORMATION pbi;

            NtQueryInformationProcess( process, ProcessBasicInformation, &pbi, sizeof(pbi), NULL );
            peb32 = (PEB32 *)pbi.PebBaseAddress;
        }
        else NtQueryInformationProcess( process, ProcessWow64Information, &peb32, sizeof(peb32), NULL );

        if (!NtReadVirtualMemory( process, &peb32->SpareUlongs[0], &ptr, sizeof(ptr), NULL ) && ptr)
        {
            struct ldt_copy *ldt = ULongToPtr( ptr );
            NtReadVirtualMemory( process, &ldt->base[idx], &base, sizeof(base), NULL );
            NtReadVirtualMemory( process, &ldt->bits[idx], &bits, sizeof(bits), NULL );
        }
        NtClose( process );
    }

    if (base || bits.limit || bits.type) *entry = ldt_make_entry( base, bits );
    else status = STATUS_UNSUCCESSFUL;

    return status;
}

/******************************************************************************
 *           NtSetLdtEntries   (NTDLL.@)
 *           ZwSetLdtEntries   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetLdtEntries( ULONG sel1, ULONG entry1_low, ULONG entry1_high, ULONG sel2, ULONG entry2_low, ULONG entry2_high )
{
    sigset_t sigset;
    union { LDT_ENTRY entry; ULONG ul[2]; } entry;

    if (is_win64 && !is_wow64()) return STATUS_NOT_IMPLEMENTED;
    if (sel1 >> 16 || sel2 >> 16) return STATUS_INVALID_LDT_DESCRIPTOR;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (sel1)
    {
        entry.ul[0] = entry1_low;
        entry.ul[1] = entry1_high;
        ldt_update_entry( sel1, entry.entry );
    }
    if (sel2)
    {
        entry.ul[0] = entry2_low;
        entry.ul[1] = entry2_high;
        ldt_update_entry( sel2, entry.entry );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return STATUS_SUCCESS;
}

#else /* defined(__i386__) || defined(__x86_64__) */

/******************************************************************************
 *           NtSetLdtEntries   (NTDLL.@)
 *           ZwSetLdtEntries   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetLdtEntries( ULONG sel1, ULONG entry1_low, ULONG entry1_high, ULONG sel2, ULONG entry2_low, ULONG entry2_high )
{
    return STATUS_NOT_IMPLEMENTED;
}

#endif /* defined(__i386__) || defined(__x86_64__) */


/***********************************************************************
 *           virtual_clear_tls_index
 */
NTSTATUS virtual_clear_tls_index( ULONG index )
{
    struct ntdll_thread_data *thread_data;
    sigset_t sigset;
#ifdef WINE_IOS
    /* teb_list holds the threads of every pseudo-process in this task, but a
     * TLS index belongs to one process: TlsAlloc takes it from that process's
     * own PEB bitmap, so the same index in another process is unrelated.
     * Clear it only in the calling process's threads, as Windows does. */
    void *caller_peb = NtCurrentTeb()->Peb;
#endif

    if (index < TLS_MINIMUM_AVAILABLE)
    {
        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        LIST_FOR_EACH_ENTRY( thread_data, &teb_list, struct ntdll_thread_data, entry )
        {
            TEB *teb = CONTAINING_RECORD( thread_data, TEB, GdiTebBatch );
#ifdef _WIN64
            WOW_TEB *wow_teb = get_wow_teb( teb );
#endif
#ifdef WINE_IOS
            if (teb->Peb != caller_peb) continue;
#endif
#ifdef _WIN64
            if (wow_teb) wow_teb->TlsSlots[index] = 0;
            else
#endif
            teb->TlsSlots[index] = 0;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    }
    else
    {
        index -= TLS_MINIMUM_AVAILABLE;
        if (index >= 8 * sizeof(peb->TlsExpansionBitmapBits)) return STATUS_INVALID_PARAMETER;

        server_enter_uninterrupted_section( &virtual_mutex, &sigset );
        LIST_FOR_EACH_ENTRY( thread_data, &teb_list, struct ntdll_thread_data, entry )
        {
            TEB *teb = CONTAINING_RECORD( thread_data, TEB, GdiTebBatch );
#ifdef _WIN64
            WOW_TEB *wow_teb = get_wow_teb( teb );
#endif
#ifdef WINE_IOS
            if (teb->Peb != caller_peb) continue;
#endif
#ifdef _WIN64
            if (wow_teb)
            {
                if (wow_teb->TlsExpansionSlots)
                {
                    ULONG_PTR slots = wow_teb->TlsExpansionSlots;
#ifdef WINE_IOS
                    /* a guest address in the window this TEB lives in */
                    struct ios_wow_window *slot = ios_wow_slot_at_base(
                        (ULONG_PTR)teb & ~(IOS_WOW_WINDOW_SIZE - 1) );
                    if (slot) slots += slot->base;
#endif
                    ((ULONG *)slots)[index] = 0;
                }
            }
            else
#endif
            if (teb->TlsExpansionSlots) teb->TlsExpansionSlots[index] = 0;
        }
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    }
    return STATUS_SUCCESS;
}


/* madeira-bcd: [stack-floor] programs whose threads keep a smaller stack.
 *
 * ml422/ml423 give every guest thread stack at least 8 MB because Chromium's
 * renderer threads overflowed 4 MB under ARM64EC. All pseudo-processes share
 * one address space, so the floor is paid in furniture VA by every thread of
 * every program: RDR2.exe made 186 threads in build 460 (log 2026-10-08
 * 23:59:11), each with at least 8 MB of the band whose exhaustion froze it,
 * where a 1 MB request (the twelve logged ones) needs 1 MB on Windows.
 * MADEIRA_SMALL_STACK_EXES lists exe names
 * (comma or semicolon separated, case-insensitive, e.g. "RDR2.exe") whose
 * threads get what they ask for with a 2 MB minimum — twice the Windows
 * default, for the native frames ARM64EC adds — instead; every other program,
 * Chromium included, keeps 8 MB. Empty by default. */
#define IOS_SMALL_STACK_FLOOR (2 * 1024 * 1024)

/* 1 when the last component of `path` (len WCHARs) is one of the names in
 * `list`. */
static int ios_exe_name_in_list( const WCHAR *path, size_t len, const char *list )
{
    size_t base = 0, k, n;

    if (!path || !list) return 0;
    for (k = 0; k < len; k++) if (path[k] == '\\' || path[k] == '/') base = k + 1;
    while (*list)
    {
        const char *name = list, *e;

        while (*name == ' ') name++;
        e = name;
        while (*e && *e != ',' && *e != ';') e++;
        n = e - name;
        while (n && name[n - 1] == ' ') n--;
        if (n && n == len - base)
        {
            for (k = 0; k < n; k++)
            {
                WCHAR c = path[base + k];
                char w = name[k];

                if (c >= 'A' && c <= 'Z') c += 32;
                if (w >= 'A' && w <= 'Z') w += 32;
                if (c != (WCHAR)(unsigned char)w) break;
            }
            if (k == n) return 1;
        }
        list = *e ? e + 1 : e;
    }
    return 0;
}

/* The floor for a new guest thread stack of the calling pseudo-process. */
static SIZE_T ios_thread_stack_floor(void)
{
    const char *list = getenv( "MADEIRA_SMALL_STACK_EXES" );
    PEB *peb;
    RTL_USER_PROCESS_PARAMETERS *pp;

    if (!list || !*list) return 8 * 1024 * 1024;
    peb = ios_jit_current_peb();
    pp = peb ? peb->ProcessParameters : NULL;
    if (pp && ios_exe_name_in_list( pp->ImagePathName.Buffer, pp->ImagePathName.Length / sizeof(WCHAR), list ))
        return IOS_SMALL_STACK_FLOOR;
    return 8 * 1024 * 1024;
}

/***********************************************************************
 *           virtual_alloc_thread_stack
 */
NTSTATUS virtual_alloc_thread_stack( INITIAL_TEB *stack, ULONG_PTR limit_low, ULONG_PTR limit_high,
                                     SIZE_T reserve_size, SIZE_T commit_size, BOOL guard_page )
{
    struct file_view *view;
    NTSTATUS status;
    sigset_t sigset;
    SIZE_T size;

    {
        /* Owner-aware (X3): default stack sizes come from the calling
         * pseudo-process's main exe, not the session's. */
        extern const SECTION_IMAGE_INFORMATION *ios_cur_image_info(void);
        const SECTION_IMAGE_INFORMATION *ios_ii = ios_cur_image_info();
        if (!reserve_size) reserve_size = ios_ii->MaximumStackSize;
        if (!commit_size) commit_size = ios_ii->CommittedStackSize;
    }

    size = max( reserve_size, commit_size );
    if (size < 1024 * 1024) size = 1024 * 1024;  /* Xlib needs a large stack */
#ifdef WINE_IOS
    /* iOS-Madeira ml422 (#70): first CreateBrowser (ml421) died on a genuine
     * STACK_OVERFLOW — 256+ frames of libcef recursion ran a webhelper thread
     * stack dry. Chromium sizes its worker stacks for pure-x64 frames, but
     * under ARM64EC the emulated x64 frames interleave with native ARM64
     * frames (EC thunks, wine internals, our exception rethrows), which
     * consume MORE stack than the same call tree on real x64 Windows.
     * ml423: the 4MB floor was consumed too ([stack-ovf] reserve=0x400000) —
     * Chromium calibrates its renderer main threads for the 8MB Windows
     * default, so match it. Cost is VA only: the mapping is anonymous and
     * lazy, so untouched reserve pages never count against the 4096MB jetsam
     * footprint. If 8MB ALSO overflows, the [stack-ovf] three-window stack
     * fingerprint names the recursion cycle — chase that, not more size. */
    if (guard_page && size < 8 * 1024 * 1024)
    {
        /* madeira-bcd: MADEIRA_SMALL_STACK_EXES — see ios_thread_stack_floor */
        SIZE_T min_size = ios_thread_stack_floor();

        if (min_size < 8 * 1024 * 1024)
        {
            static int kept;
            if (kept < 12 && ++kept <= 12)
                dprintf( 2, "[stack-floor] madeira-bcd #%d thread stack reserve 0x%lx -> 0x%lx "
                            "(the program is in MADEIRA_SMALL_STACK_EXES)\n",
                         kept, (unsigned long)size, (unsigned long)max( size, min_size ) );
            size = max( size, min_size );
        }
        else
        {
            static int floored;
            if (floored < 12 && ++floored <= 12)
                dprintf( 2, "[stack-floor] rev=ml424 #%d thread stack reserve 0x%lx -> 0x800000\n",
                         floored, (unsigned long)size );
            size = 8 * 1024 * 1024;
        }
    }
#endif
    size = ROUND_SIZE( 0, size, granularity_mask );

#ifdef WINE_IOS
    /* WoW64 guest window: init_thread_stack passes the guest
     * user_space_wow_limit as limit_high for the 32-bit stack — translate it
     * into [B, B+limit] so the stack lands in the window.  The 64-bit and
     * kernel stacks pass limit_low = limit_4g / limit_high = 0 and are
     * untouched, so they keep landing in ordinary furniture. */
    ios_wow_translate_limits( &limit_low, &limit_high );
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    status = map_view( &view, NULL, size, 0, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED,
                       limit_low, limit_high, 0 );
    if (status != STATUS_SUCCESS) goto done;

#ifdef VALGRIND_STACK_REGISTER
    VALGRIND_STACK_REGISTER( view->base, (char *)view->base + view->size );
#endif

    /* setup no access guard page */
    if (guard_page)
    {
        set_page_vprot( view->base, host_page_size, 0 );
        set_page_vprot( (char *)view->base + host_page_size, host_page_size,
                        VPROT_READ | VPROT_WRITE | VPROT_COMMITTED | VPROT_GUARD );
        mprotect_range( view->base, 2 * host_page_size , 0, 0 );
    }
    VIRTUAL_DEBUG_DUMP_VIEW( view );

    /* note: limit is lower than base since the stack grows down */
    stack->OldStackBase = 0;
    stack->OldStackLimit = 0;
    stack->DeallocationStack = view->base;
    stack->StackBase = (char *)view->base + view->size;
    stack->StackLimit = (char *)view->base + (guard_page ? 2 * host_page_size : 0);
done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


static const WCHAR shared_data_nameW[] = {'\\','K','e','r','n','e','l','O','b','j','e','c','t','s',
                                          '\\','_','_','w','i','n','e','_','u','s','e','r','_','s','h','a','r','e','d','_','d','a','t','a',0};

/***********************************************************************
 *           virtual_map_user_shared_data
 */
void virtual_map_user_shared_data(void)
{
    UNICODE_STRING name_str = RTL_CONSTANT_STRING( shared_data_nameW );
    OBJECT_ATTRIBUTES attr = { sizeof(attr), 0, &name_str };
    unsigned int status;
    HANDLE section;
    int res, fd, needs_close;

    if ((status = NtOpenSection( &section, SECTION_ALL_ACCESS, &attr )))
    {
        ERR( "failed to open the USD section: %08x\n", status );
        exit(1);
    }
    if ((res = server_get_unix_fd( section, 0, &fd, &needs_close, NULL, NULL )) ||
        (user_shared_data != mmap( user_shared_data, page_size, PROT_READ, MAP_SHARED|MAP_FIXED, fd, 0 )))
    {
        ERR( "failed to remap the process USD: %d\n", res );
        exit(1);
    }
    if (needs_close) close( fd );
    NtClose( section );

    /* ml1001: SAY WHAT THE GUEST CLOCK READS, ONCE, AT THE MOMENT IT BECOMES
     * READABLE.  GetTickCount()/GetTickCount64() in kernelbase are three loads
     * from this page and nothing else, so this line IS what every guest program
     * will be told the time is.  It read 0 for the entire life of this port
     * (the server's publication was opt-in behind MADEIRA_USD_TIME), which is
     * indistinguishable in a log from "nobody asked" -- so print it rather than
     * infer it.  A zero here means the clock is frozen and any guest that keys
     * a data structure on the tick will collide every entry against every
     * other one.  Two reads, once per process. */
    {
        unsigned long long ms = ((unsigned long long)user_shared_data->TickCount.High1Time << 32)
                                | user_shared_data->TickCount.LowPart;
        dprintf( 2, "[usd-clock] ml1001 guest KUSER_SHARED_DATA at %p: GetTickCount64()=%llu ms "
                    "(TickCountMultiplier=0x%x) — %s\n",
                 (void *)user_shared_data, ms,
                 (unsigned)user_shared_data->TickCountMultiplier,
                 ms ? "ticking" : "*** FROZEN AT ZERO: every guest tick-keyed timer will collide "
                                  "(MADEIRA_USD_TIME=0 set?) ***" );
    }
}


#ifdef WINE_IOS
/***********************************************************************
 *           ios_wow_reserve_usd_slot / ios_wow_release_usd_slot   (ml1040)
 *
 * HOLD GUEST 0x7ffe0000 BEFORE THE FIRST TEB BLOCK IS ALLOCATED.
 *
 * `virtual_alloc_first_teb()` reserves the first TEB block with
 * MEM_TOP_DOWN under a 2 GB ceiling.  Inside a guest window that search
 * returns the highest free 128 KB below guest 0x80000000, which is
 * 0x7FFE0000 — the address KUSER_SHARED_DATA has occupied on every version
 * of Windows.  The device log shows exactly that: `[commit-zero] GUEST OK
 * base=B+0x7ffe0000 size=0x20000` for the TEB block, and no
 * `[wow-window] USD mapped` line afterwards, because the map then failed on
 * an address that was already taken.  Every 32-bit `GetTickCount()`,
 * `GetTickCount64()`, `InterruptTime` and `SystemTime` read then returned
 * whatever byte of the TEB happened to be at that offset — constant for the
 * life of the process.  A child pseudo-process was unaffected only because
 * its TEB block comes from a different allocator and lands low.
 *
 * The page cannot simply be mapped here: this runs before the server
 * connection exists, so the section cannot be opened yet.  Reserving the
 * address costs nothing and needs nobody, and the real mapping replaces the
 * reservation later from `ios_wow_map_user_shared_data()`.
 *
 * One granularity unit, because that is the unit MEM_RESERVE works in and
 * the unit the top-down search steps by; it also matches Windows, where
 * 0x7FFE0000..0x7FFF0000 belongs to the shared page and TEBs live below it.
 */
static void *ios_wow_usd_slot;

void ios_wow_reserve_usd_slot( ULONG_PTR base )
{
    void *addr = (void *)(base + 0x7ffe0000);
    SIZE_T size = 0x10000;
    unsigned int status;

    if (!base || ios_wow_usd_slot) return;
    status = NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size,
                                      MEM_RESERVE, PAGE_NOACCESS );
    if (!status) ios_wow_usd_slot = addr;
    dprintf( 2, "[usd-clock] wow: %s guest 0x7ffe0000 (host %p) for KUSER_SHARED_DATA "
                "before the first TEB block: status=%08x\n",
             status ? "FAILED to reserve" : "reserved",
             (void *)(base + 0x7ffe0000), status );
}

void ios_wow_release_usd_slot(void)
{
    SIZE_T size = 0;
    void *addr = ios_wow_usd_slot;

    if (!addr) return;
    ios_wow_usd_slot = NULL;
    NtFreeVirtualMemory( NtCurrentProcess(), &addr, &size, MEM_RELEASE );
}


/***********************************************************************
 *           ios_wow_map_user_shared_data
 *
 * KUSER_SHARED_DATA for the 32-bit view .  Guest code
 * reads the shared data at guest 0x7ffe0000; the 64-bit side cannot map it
 * there (XNU's 4 GB __PAGEZERO) and emulates the accesses in the fault
 * handler instead.  Inside a guest window the guest address is the HOST
 * address B + 0x7ffe0000, which is perfectly mappable — so map a second,
 * read-only view of the same shared page there and let the 32-bit side read
 * real memory.  The 64-bit emulation in signal_arm64_ios.c is untouched.
 */
void ios_wow_map_user_shared_data(void)
{
    UNICODE_STRING name_str = RTL_CONSTANT_STRING( shared_data_nameW );
    OBJECT_ATTRIBUTES attr = { sizeof(attr), 0, &name_str };
    ULONG_PTR base = ios_wow_base();
    LARGE_INTEGER offset = { { 0 } };
    SIZE_T size = 0;
    unsigned int status;
    HANDLE section;
    void *addr;

    if (!base)
    {
        /* ml1040: never silent. A 32-bit process with no window has no 0x7ffe0000
         * to map, but "there was no window" and "the mapping failed" used to look
         * identical in a log — which is exactly how a frozen guest clock hid. */
        dprintf( 2, "[usd-clock] wow: no guest window for this process — "
                    "32-bit KUSER_SHARED_DATA NOT mapped\n" );
        return;
    }
    addr = (void *)(base + 0x7ffe0000);

    /* ml1040: hand back the placeholder that virtual_alloc_first_teb parked here
     * to keep the address free (see ios_wow_reserve_usd_slot). */
    ios_wow_release_usd_slot();

    if ((status = NtOpenSection( &section, SECTION_MAP_READ, &attr )))
    {
        dprintf( 2, "[usd-clock] wow: cannot open the USD section: %08x — the 32-bit "
                    "clock will read whatever is at guest 0x7ffe0000\n", status );
        return;
    }
    status = NtMapViewOfSection( section, NtCurrentProcess(), &addr, 0, 0, &offset, &size,
                                 ViewShare, 0, PAGE_READONLY );
    NtClose( section );
    if (status)
    {
        /* ml1040: THIS LINE USED TO BE AN ERR(), WHICH MADEIRA_QUIET SWALLOWS.
         * The failure was therefore invisible, and the only symptom was that
         * GetTickCount() never moved for any 32-bit program in the process —
         * a stopped clock with no error anywhere, the 2026-09-28 shape exactly. */
        dprintf( 2, "[usd-clock] wow: *** FAILED to map KUSER_SHARED_DATA at guest "
                    "0x7ffe0000 (host %p): %08x — every 32-bit GetTickCount/"
                    "GetTickCount64/InterruptTime read is now whatever else lives "
                    "there ***\n", (void *)(base + 0x7ffe0000), status );
        return;
    }

    /* ml1040: PROVE IT ADVANCES, through the 32-bit view, not the 64-bit one.
     * The 64-bit [usd-clock] line already said "ticking" while the 32-bit view
     * was frozen, because they were different pages. Two reads a few hundred
     * nanoseconds apart cannot show a tick, so print the value and let the
     * second sample come from the guest's own test. */
    {
        const KUSER_SHARED_DATA *usd = addr;
        unsigned long long ms = ((unsigned long long)usd->TickCount.High1Time << 32)
                                | usd->TickCount.LowPart;

        dprintf( 2, "[usd-clock] wow mapped at host %p = guest 0x7ffe0000: "
                    "GetTickCount64()=%llu ms (TickCountMultiplier=0x%x) — %s\n",
                 addr, ms, (unsigned)usd->TickCountMultiplier,
                 ms ? "ticking" : "*** FROZEN AT ZERO ***" );
    }
}
#endif


/******************************************************************
 *		virtual_init_user_shared_data
 *
 * Initialize user shared data before running wineboot.
 */
void virtual_init_user_shared_data(void)
{
    UNICODE_STRING name_str = RTL_CONSTANT_STRING( shared_data_nameW );
    OBJECT_ATTRIBUTES attr = { sizeof(attr), 0, &name_str };
    SYSTEM_BASIC_INFORMATION info;
    KUSER_SHARED_DATA *data;
    unsigned int status;
    HANDLE section;
    int res, fd, needs_close;

    if ((status = NtOpenSection( &section, SECTION_ALL_ACCESS, &attr )))
    {
        ERR( "failed to open the USD section: %08x\n", status );
        exit(1);
    }
    if ((res = server_get_unix_fd( section, 0, &fd, &needs_close, NULL, NULL )) ||
        (data = mmap( NULL, sizeof(*data), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 )) == MAP_FAILED)
    {
        ERR( "failed to remap the process USD: %d\n", res );
        exit(1);
    }
    if (needs_close) close( fd );
    NtClose( section );

    virtual_get_system_info( &info, FALSE );

    data->TickCountMultiplier   = 1 << 24;
    data->LargePageMinimum      = 2 * 1024 * 1024;
    data->SystemCall            = 1;
    data->NumberOfPhysicalPages = info.MmNumberOfPhysicalPages;
    data->NXSupportPolicy       = NX_SUPPORT_POLICY_OPTIN;
    data->ActiveProcessorCount  = peb->NumberOfProcessors;
    data->ActiveGroupCount      = 1;

    switch (native_machine)
    {
    case IMAGE_FILE_MACHINE_I386:  data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL; break;
    case IMAGE_FILE_MACHINE_AMD64: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64; break;
    case IMAGE_FILE_MACHINE_ARMNT: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM; break;
    case IMAGE_FILE_MACHINE_ARM64: data->NativeProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64; break;
    }

    init_shared_data_cpuinfo( data );
    ios_pool_va_warn( "munmap", data, sizeof(*data) );
    munmap( data, sizeof(*data) );
}


struct thread_stack_info
{
    char  *start;
    char  *limit;
    char  *end;
    SIZE_T guaranteed;
    BOOL   is_wow;
};

/***********************************************************************
 *           is_inside_thread_stack
 */
static BOOL is_inside_thread_stack( void *ptr, struct thread_stack_info *stack )
{
    TEB *teb = NtCurrentTeb();
    WOW_TEB *wow_teb = get_wow_teb( teb );
    size_t min_guaranteed = max( page_size * (is_win64 ? 2 : 1), host_page_size );

    stack->start = teb->DeallocationStack;
    stack->limit = teb->Tib.StackLimit;
    stack->end   = teb->Tib.StackBase;
    stack->guaranteed = max( teb->GuaranteedStackBytes, min_guaranteed );
    stack->is_wow = FALSE;
    if ((char *)ptr > stack->start && (char *)ptr <= stack->end) return TRUE;

    if (!wow_teb) return FALSE;
    stack->start = ULongToPtr( wow_teb->DeallocationStack );
    stack->limit = ULongToPtr( wow_teb->Tib.StackLimit );
    stack->end   = ULongToPtr( wow_teb->Tib.StackBase );
    stack->guaranteed = max( wow_teb->GuaranteedStackBytes, min_guaranteed );
    stack->is_wow = TRUE;
    return ((char *)ptr > stack->start && (char *)ptr <= stack->end);
}


/***********************************************************************
 *           grow_thread_stack
 */
static NTSTATUS grow_thread_stack( char *page, struct thread_stack_info *stack_info )
{
    NTSTATUS ret = 0;

    set_page_vprot_bits( page, host_page_size, VPROT_COMMITTED, VPROT_GUARD );
    mprotect_range( page, host_page_size, 0, 0 );
    if (page >= stack_info->start + host_page_size + stack_info->guaranteed)
    {
        set_page_vprot_bits( page - host_page_size, host_page_size, VPROT_COMMITTED | VPROT_GUARD, 0 );
        mprotect_range( page - host_page_size, host_page_size, 0, 0 );
    }
    else  /* inside guaranteed space -> overflow exception */
    {
        page = stack_info->start + host_page_size;
        set_page_vprot_bits( page, stack_info->guaranteed, VPROT_COMMITTED, VPROT_GUARD );
        mprotect_range( page, stack_info->guaranteed, 0, 0 );
        ret = STATUS_STACK_OVERFLOW;
    }
    if (stack_info->is_wow)
    {
        WOW_TEB *wow_teb = get_wow_teb( NtCurrentTeb() );
        wow_teb->Tib.StackLimit = PtrToUlong( page );
    }
    else NtCurrentTeb()->Tib.StackLimit = page;
    return ret;
}


/***********************************************************************
 *           virtual_handle_fault
 */
NTSTATUS virtual_handle_fault( EXCEPTION_RECORD *rec, void *stack )
{
    NTSTATUS ret = STATUS_ACCESS_VIOLATION;
    ULONG_PTR err = rec->ExceptionInformation[0];
    void *addr = (void *)rec->ExceptionInformation[1];
    char *page = ROUND_ADDR( addr, host_page_mask );
    BYTE vprot;

    mutex_lock( &virtual_mutex );  /* no need for signal masking inside signal handler */
    vprot = get_host_page_vprot( page );

#ifdef __APPLE__
    /* Rosetta on Apple Silicon misreports certain write faults as read faults. */
    if (err == EXCEPTION_READ_FAULT && (get_unix_prot( vprot ) & PROT_READ))
    {
        WARN( "treating read fault in a readable page as a write fault, addr %p\n", addr );
        err = EXCEPTION_WRITE_FAULT;
    }
#endif

    if (!is_inside_signal_stack( stack ) && (vprot & VPROT_GUARD))
    {
        struct thread_stack_info stack_info;
        if (!is_inside_thread_stack( page, &stack_info ))
        {
            set_page_vprot_bits( page, host_page_size, 0, VPROT_GUARD );
            mprotect_range( page, host_page_size, 0, 0 );
            ret = STATUS_GUARD_PAGE_VIOLATION;
        }
        else ret = grow_thread_stack( page, &stack_info );
    }
    else if (err == EXCEPTION_WRITE_FAULT)
    {
        if (vprot & VPROT_WRITEWATCH)
        {
            if (enable_write_exceptions && is_vprot_exec_write( vprot ) && !ntdll_get_thread_data()->allow_writes)
            {
                rec->NumberParameters = 3;
                rec->ExceptionInformation[2] = STATUS_EXECUTABLE_MEMORY_WRITE;
                ret = STATUS_IN_PAGE_ERROR;
            }
            else
            {
                set_page_vprot_bits( page, host_page_size, 0, VPROT_WRITEWATCH );
                mprotect_range( page, host_page_size, 0, 0 );
            }
        }
        /* ignore fault if page is writable now */
        if (get_unix_prot( get_host_page_vprot( page )) & PROT_WRITE)
        {
            if ((vprot & VPROT_WRITEWATCH) || is_write_watch_range( page, 1 ))
                ret = STATUS_SUCCESS;
        }
    }
    else if (err == EXCEPTION_EXECUTE_FAULT && force_exec_prot && ios_wow_in_window( page ) &&
             (vprot & VPROT_COMMITTED) && (get_unix_prot( vprot ) & PROT_READ))
    {
        /* iOS-Madeira: DEP-OFF EXECUTE FAULT, host side.
         *
         * A process whose image lacks IMAGE_DLLCHARACTERISTICS_NX_COMPAT runs with DEP
         * disabled (wine/dlls/ntdll/loader.c:1930 sets MEM_EXECUTE_OPTION_ENABLE, which lands
         * in virtual_set_force_exec below), and on Windows executing from any committed
         * readable page is then legal.  Upstream needs no fault handling for that because
         * force_exec_prot adds PROT_EXEC to every PROT_READ mapping as it is made; a page that
         * predates the policy change is fixed up by virtual_set_force_exec's sweep.
         *
         * Here PROT_EXEC is not always grantable - iOS TXM refuses it outside the JIT pool, see
         * mprotect_exec's [force-exec] note - so the sweep can silently leave a page
         * non-executable and the fault is the only remaining notice.  Grant execute the same
         * way a PAGE_EXECUTE_READWRITE NtProtectVirtualMemory would: record VPROT_EXEC and
         * re-apply, and report success only if the kernel actually honoured it.  When it does
         * not, fall through to the normal access-violation report rather than resuming into a
         * page that still cannot execute - an unhandleable fault loop is worse than a clean AV.
         *
         * NOTE this is the HOST half only, and on this port the host half is the small half:
         * guest code is never host-executed, it is translated and run from the pool.  What
         * makes a guest page executable is FEX's InvalidationTracker (see the [dep-off]
         * promotion there), reached through NtSetInformationProcess(ProcessExecuteFlags) ->
         * wow64.dll -> BTCpuNotifyProcessExecuteFlagsChange.  Only for a page inside a 32-bit guest
         * window; everything else keeps the upstream report. */
        set_page_vprot_bits( page, host_page_size, VPROT_EXEC, 0 );
        if (!mprotect_range( page, host_page_size, 0, 0 )) ret = STATUS_SUCCESS;
        else set_page_vprot_bits( page, host_page_size, 0, VPROT_EXEC );
    }
    mutex_unlock( &virtual_mutex );
    rec->ExceptionCode = ret;
    return ret;
}

/* iOS-Madeira ml420 (#69): BUS self-heal support. ml419's fatal chain began
 * with a committed, plain-READ libcef .rdata page whose host protection had
 * been stripped BEHIND wine's back (no guest NtProtectVirtualMemory touched
 * the range — the stripper is a raw mprotect/mach_vm call). Report wine's
 * INTENDED unix prot for the page so bus_handler can put it back and resume
 * instead of dying. Returns -1 if wine has no committed view of the page.
 * Lock-free vprot peek (signal context — taking virtual_mutex here could
 * self-deadlock); racy reads are acceptable for a heal heuristic. */
int ios_page_expected_prot( const void *addr )
{
    BYTE vprot = get_page_vprot( addr );
    if (!(vprot & VPROT_COMMITTED)) return -1;
    return get_unix_prot( vprot );
}

/***********************************************************************
 *           ios_page_vprot_explain                               (ml998)
 *
 * Why does Wine believe this page is non-writable?
 *
 * rdr66 cleared the 8960 MB reservation and advanced into EMP.dll's code
 * decryption, where it faults writing 0x1464e8fc6 -- inside the main image's
 * second .text section. ml958 granted that whole section W at startup
 * ("already-copied section 0x145f66000+0x15c2000 ... plain RW kr=0 -- W
 * GRANTED"), yet at fault time ios_page_expected_prot() returns 5 (R|X, no W),
 * so [wr-strip] correctly declines to heal: the host did not strip anything,
 * Wine's own per-page vprot has no WRITE.
 *
 * The translated prot cannot say why. The raw vprot byte can: VPROT_WRITE
 * absent is a different bug from VPROT_WRITECOPY still pending (Wine maps
 * write-copy pages read-only until the first write and services the copy in
 * virtual_handle_fault), and different again from the page never having been
 * committed as writable. Guessing between those and demoting W^X on the basis
 * would be exactly the kind of speculative fix that has cost runs already.
 */
void ios_page_vprot_explain( const void *addr, const char *why )
{
    static int n;
    char *page = ROUND_ADDR( addr, host_page_mask );
    BYTE vp = get_page_vprot( addr );
    struct file_view *view;
    sigset_t sigset;

    if (n++ >= 12) return;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    view = find_view( (void *)addr, 0 );
    dprintf( 2, "ml998: [%s] %p vprot=%#02x { %s%s%s%s%s%s%s } unix_prot=%d\n",
             why, addr, vp,
             (vp & VPROT_COMMITTED) ? "COMMITTED " : "",
             (vp & VPROT_READ)      ? "READ "      : "",
             (vp & VPROT_WRITE)     ? "WRITE "     : "",
             (vp & VPROT_EXEC)      ? "EXEC "      : "",
             (vp & VPROT_WRITECOPY) ? "WRITECOPY " : "",
             (vp & VPROT_GUARD)     ? "GUARD "     : "",
             (vp & VPROT_WRITEWATCH)? "WRITEWATCH ": "",
             get_unix_prot( vp ) );
    if (view)
        dprintf( 2, "ml998: [%s]   view %p+%#lx protect=%#x { %s%s%s%s } page_off=%#lx\n",
                 why, view->base, (unsigned long)view->size, view->protect,
                 (view->protect & SEC_IMAGE)        ? "SEC_IMAGE "   : "",
                 (view->protect & VPROT_ARM64EC)    ? "ARM64EC "     : "",
                 (view->protect & VPROT_SYSTEM)     ? "SYSTEM "      : "",
                 (view->protect & VPROT_WRITECOPY)  ? "WRITECOPY "   : "",
                 (unsigned long)((char *)page - (char *)view->base) );
    else
        dprintf( 2, "ml998: [%s]   NO Wine view covers %p -- this page is not Wine-managed\n",
                 why, addr );
    /* the two neighbours: a section-boundary or page-crossing story shows here */
    dprintf( 2, "ml998: [%s]   neighbours prev=%#02x this=%#02x next=%#02x\n", why,
             get_page_vprot( page - host_page_size ), vp,
             get_page_vprot( page + host_page_size ) );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}

/* Steam S3 (task #29): when virtual_handle_fault can't service a fault,
 * dump the target's memory picture — is it in a Wine file_view (Wine should
 * manage it → our commit/vprot has a gap), or is it a FEX/foreign mapping
 * Wine doesn't know about? Plus vprot of the page and its neighbors (a
 * page-crossing write into an uncommitted next-page shows as this/next
 * differing). Decides whether the fix is Wine-side commit-on-fault or a
 * FEX guest-memory issue. */
void ios_dump_fault_region( void *addr )
{
    char *page = ROUND_ADDR( addr, host_page_mask );
    BYTE vp_prev, vp, vp_next;
    struct file_view *view;
    extern void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
    extern size_t ios_jit_pool_size_global;
    uintptr_t a = (uintptr_t)addr, rx = (uintptr_t)ios_jit_rx_base_global,
              rw = (uintptr_t)ios_jit_rw_base_global, sz = ios_jit_pool_size_global;
    const char *region = "unknown/foreign";

    {
        static unsigned long fr_storm;
        if (!ios_storm_gate( &fr_storm )) return;
    }
    mutex_lock( &virtual_mutex );
    vp_prev = get_host_page_vprot( page - host_page_size );
    vp      = get_host_page_vprot( page );
    vp_next = get_host_page_vprot( page + host_page_size );
    view = find_view( addr, 1 );
    if (rx && a >= rx && a < rx + sz) region = "JIT-POOL-RX (exec, RO)";
    else if (rw && a >= rw && a < rw + sz) region = "JIT-POOL-RW (alias)";
    else if (ios_jit_low_contains( a )) region = "JIT-POOL-LOW-RX (region C, FEX code)";
    else if (ios_jit_low_rw_contains( a )) region = "JIT-POOL-LOW-RW (region C alias)";
    dprintf( 2, "[fault-rgn] addr=%p page=%p vprot prev/this/next=%02x/%02x/%02x region=%s\n",
             addr, page, vp_prev, vp, vp_next, region );
    if (view)
        dprintf( 2, "[fault-rgn]   IN WINE VIEW base=%p size=0x%lx protect=0x%x off=0x%lx end=%p\n",
                 view->base, (unsigned long)view->size, view->protect,
                 (unsigned long)((char *)addr - (char *)view->base),
                 (char *)view->base + view->size );
    else
    {
        dprintf( 2, "[fault-rgn]   NO wine view — Wine doesn't own this addr (FEX/foreign mmap)\n" );
        ios_vh_dump( addr );   /* madeira-bcd */
    }
    mutex_unlock( &virtual_mutex );
}


/***********************************************************************
 *           virtual_setup_exception
 */

/* ml262: is every page of [addr, addr+size) mapped AND writable?
 *
 * Needed because virtual_setup_exception's "outside thread stack" branch is routine
 * in this port -- FEX guest stacks are not Wine views -- and it must not hand back
 * memory the caller cannot write. Walks region-by-region so a HOLE (mach_vm_region
 * returning a region that starts above the query address) is detected rather than
 * mistaken for the containing region. */
static int ios_range_writable( const void *addr, size_t size )
{
    mach_vm_address_t a = (mach_vm_address_t)(uintptr_t)addr;
    mach_vm_address_t end = a + (size ? size : 1);

    while (a < end)
    {
        mach_vm_address_t q = a;
        mach_vm_size_t sz = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;

        if (mach_vm_region( mach_task_self(), &q, &sz, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS)
            return 0;
        if (q > a) return 0;                             /* hole */
        if (!(info.protection & VM_PROT_WRITE)) return 0;
        a = q + sz;
    }
    return 1;
}

void *virtual_setup_exception( void *stack_ptr, size_t size, EXCEPTION_RECORD *rec )
{
    char *stack = stack_ptr;
    struct thread_stack_info stack_info;

    if (!is_inside_thread_stack( stack, &stack_info ))
    {
        if (is_inside_signal_stack( stack ))
        {
            ERR( "nested exception on signal stack addr %p stack %p\n", rec->ExceptionAddress, stack );
            abort_thread(1);
        }
        WARN( "exception outside of stack limits addr %p stack %p (%p-%p-%p)\n",
              rec->ExceptionAddress, stack, NtCurrentTeb()->DeallocationStack,
              NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase );
        /* ml262 LIVELOCK FIX: this branch used to return an UNVALIDATED pointer.
         *
         * "Outside a Wine thread stack" is routine in this port -- FEX guest stacks
         * are not Wine views -- so this is a hot path, and the caller immediately
         * copies EXCEPTION_RECORD + CONTEXT to whatever we return. When that landed
         * in an unmapped hole the copy faulted, which raised another exception down
         * this same path, which faulted again: an unbreakable loop. Measured twice --
         * 49,500 faults in ml261 and 53,000 in ml262, each consuming the entire run:
         *   [fault-stuck] page 0x73d16ac000 faulted 2048 times with NO progress
         *   [fault-stuck]   region 0x73d16b0000 +0x40000 prot=3/7   <- first region ABOVE
         *   sym pc=Madeira.debug.dylib`setup_raise_exception+0x104 (stp q1,q0,[x0,#0x1d0])
         * The write target sat 0x170 bytes BELOW the base of the guest stack region,
         * i.e. the guest stack was exhausted and the frame did not fit.
         *
         * An exception that cannot be delivered is unrecoverable, exactly like the two
         * cases above, so abort the thread instead of spinning forever. */
        if (!ios_range_writable( stack - size, size ))
        {
            ERR( "[exc-stack] cannot deliver exception: %p..%p not writable "
                 "(addr %p) -- aborting thread instead of faulting forever\n",
                 stack - size, stack, rec->ExceptionAddress );
            abort_thread(1);
        }
        return stack - size;
    }

    stack -= size;

    if (stack < stack_info.start + host_page_size)
    {
        /* stack overflow on last page, unrecoverable */
        UINT diff = stack_info.start + host_page_size - stack;
        ERR( "stack overflow %u bytes addr %p stack %p (%p-%p-%p)\n",
             diff, rec->ExceptionAddress, stack, stack_info.start, stack_info.limit, stack_info.end );
        abort_thread(1);
    }
    else if (stack < stack_info.limit)
    {
        char *page = ROUND_ADDR( stack, host_page_mask );
        mutex_lock( &virtual_mutex );  /* no need for signal masking inside signal handler */
        if ((get_host_page_vprot( page ) & VPROT_GUARD) && grow_thread_stack( page, &stack_info ))
        {
            rec->ExceptionCode = STATUS_STACK_OVERFLOW;
            rec->NumberParameters = 0;
        }
        mutex_unlock( &virtual_mutex );
    }
#if defined(VALGRIND_MAKE_MEM_UNDEFINED)
    VALGRIND_MAKE_MEM_UNDEFINED( stack, size );
#elif defined(VALGRIND_MAKE_WRITABLE)
    VALGRIND_MAKE_WRITABLE( stack, size );
#endif
    return stack;
}


/* ml369 (#63): cross-thread variants for in-Mach guest exception delivery.
 *
 * ml364-368 contain ZERO segv/ill/bus handler invocations: with StikDebug
 * attached, a fault our Mach handler declines goes to the task port, the
 * script's continue marks it HANDLED kernel-side, and BSD signal conversion
 * never happens (the stub cannot inject signals — no PT_THUPDATE). So wine's
 * whole signal-side delivery path is unreachable and any unfixable fault
 * spins at one pc until the script kills the process at 8 repeats.
 *
 * These helpers let the Mach exception-server thread run the same
 * fault-service + dispatch-frame logic against the FAULTING thread (which
 * the exception message keeps suspended). Current-thread dependencies are
 * parameterized away:
 *   - stack bounds come from the TARGET's TEB (no WOW branch: ARM64EC
 *     guests are 64-bit);
 *   - no abort_thread (that would kill the exception SERVER thread) —
 *     undeliverable returns NULL and the caller declines as before;
 *   - the enable_write_exceptions/allow_writes report branch acts as
 *     allow_writes (clears the watch) since ntdll_get_thread_data() would
 *     read the wrong thread. */
static BOOL is_inside_thread_stack_teb( void *ptr, struct thread_stack_info *stack, TEB *teb )
{
    size_t min_guaranteed = max( page_size * (is_win64 ? 2 : 1), host_page_size );

    stack->start = teb->DeallocationStack;
    stack->limit = teb->Tib.StackLimit;
    stack->end   = teb->Tib.StackBase;
    stack->guaranteed = max( teb->GuaranteedStackBytes, min_guaranteed );
    stack->is_wow = FALSE;
    return ((char *)ptr > stack->start && (char *)ptr <= stack->end);
}

static NTSTATUS grow_thread_stack_teb( char *page, struct thread_stack_info *stack_info, TEB *teb )
{
    NTSTATUS ret = 0;

    set_page_vprot_bits( page, host_page_size, VPROT_COMMITTED, VPROT_GUARD );
    mprotect_range( page, host_page_size, 0, 0 );
    if (page >= stack_info->start + host_page_size + stack_info->guaranteed)
    {
        set_page_vprot_bits( page - host_page_size, host_page_size, VPROT_COMMITTED | VPROT_GUARD, 0 );
        mprotect_range( page - host_page_size, host_page_size, 0, 0 );
    }
    else  /* inside guaranteed space -> overflow exception */
    {
        page = stack_info->start + host_page_size;
        set_page_vprot_bits( page, stack_info->guaranteed, VPROT_COMMITTED, VPROT_GUARD );
        mprotect_range( page, stack_info->guaranteed, 0, 0 );
        ret = STATUS_STACK_OVERFLOW;
    }
    teb->Tib.StackLimit = page;
    return ret;
}

/* ml374: the two entry points below run ON the Mach exception-server thread.
 * They raise ios_in_mach_exc for their whole extent so shared helpers (notably
 * mprotect_exec, reached via mprotect_range) skip wine log macros — see the
 * ios_in_mach_exc comment for why that is fatal rather than merely noisy. */
NTSTATUS ios_virtual_handle_fault_for_thread( EXCEPTION_RECORD *rec, TEB *teb )
{
    NTSTATUS ret = STATUS_ACCESS_VIOLATION;
    ULONG_PTR err = rec->ExceptionInformation[0];
    void *addr = (void *)rec->ExceptionInformation[1];
    char *page = ROUND_ADDR( addr, host_page_mask );
    BYTE vprot;

    mutex_lock( &virtual_mutex );
    vprot = get_host_page_vprot( page );

    if (err == EXCEPTION_READ_FAULT && (get_unix_prot( vprot ) & PROT_READ))
    {
        /* ml370: dprintf, NEVER a wine log macro — this runs on the Mach
         * exception-server thread, which has no TEB, and __wine_dbg_header's
         * per-thread read killed the server on the FIRST fault (fatal pc
         * symbolized to __wine_dbg_header+0x100). No fault service, no
         * delivery, whole app killed by the script. */
        static int reclass_logs;
        if (reclass_logs < 8)
        {
            reclass_logs++;
            dprintf( 2, "[mach-deliver] read fault on readable page -> write fault, addr %p\n", addr );
        }
        err = EXCEPTION_WRITE_FAULT;
    }

    /* the faulting thread was running guest/JIT code, never a signal
     * stack, so the is_inside_signal_stack() exclusion is vacuous here */
    if (vprot & VPROT_GUARD)
    {
        struct thread_stack_info stack_info;
        if (!is_inside_thread_stack_teb( page, &stack_info, teb ))
        {
            set_page_vprot_bits( page, host_page_size, 0, VPROT_GUARD );
            mprotect_range( page, host_page_size, 0, 0 );
            ret = STATUS_GUARD_PAGE_VIOLATION;
        }
        else ret = grow_thread_stack_teb( page, &stack_info, teb );
    }
    else if (err == EXCEPTION_WRITE_FAULT)
    {
        if (vprot & VPROT_WRITEWATCH)
        {
            set_page_vprot_bits( page, host_page_size, 0, VPROT_WRITEWATCH );
            mprotect_range( page, host_page_size, 0, 0 );
        }
        if (get_unix_prot( get_host_page_vprot( page )) & PROT_WRITE)
        {
            if ((vprot & VPROT_WRITEWATCH) || is_write_watch_range( page, 1 ))
                ret = STATUS_SUCCESS;
        }
    }
    mutex_unlock( &virtual_mutex );
    rec->ExceptionCode = ret;
    return ret;
}

void *ios_virtual_setup_exception_for_thread( void *stack_ptr, size_t size, EXCEPTION_RECORD *rec, TEB *teb )
{
    char *stack = stack_ptr;
    struct thread_stack_info stack_info;

    if (!is_inside_thread_stack_teb( stack, &stack_info, teb ))
    {
        /* routine in this port — FEX guest stacks are not Wine views */
        if (!ios_range_writable( stack - size, size )) return NULL;
        return stack - size;
    }

    stack -= size;
    if (stack < stack_info.start + host_page_size) return NULL;  /* overflow on last page */
    if (stack < stack_info.limit)
    {
        char *page = ROUND_ADDR( stack, host_page_mask );
        mutex_lock( &virtual_mutex );
        if ((get_host_page_vprot( page ) & VPROT_GUARD) &&
            grow_thread_stack_teb( page, &stack_info, teb ))
        {
            rec->ExceptionCode = STATUS_STACK_OVERFLOW;
            rec->NumberParameters = 0;
        }
        mutex_unlock( &virtual_mutex );
    }
    if (!ios_range_writable( stack, size )) return NULL;
    return stack;
}


/***********************************************************************
 *           check_write_access
 *
 * Check if the memory range is writable, temporarily disabling write watches if necessary.
 */
static NTSTATUS check_write_access( void *base, size_t size, BOOL *has_write_watch )
{
    size_t i;
    char *addr = ROUND_ADDR( base, host_page_mask );

    size = ROUND_SIZE( base, size, host_page_mask );
    for (i = 0; i < size; i += host_page_size)
    {
        BYTE vprot = get_host_page_vprot( addr + i );
        if (vprot & VPROT_WRITEWATCH) *has_write_watch = TRUE;
        if (!(get_unix_prot( vprot & ~VPROT_WRITEWATCH ) & PROT_WRITE))
            return STATUS_INVALID_USER_BUFFER;
    }
    if (*has_write_watch)
        mprotect_range( addr, size, 0, VPROT_WRITEWATCH );  /* temporarily enable write access */
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           virtual_locked_server_call
 */
unsigned int virtual_locked_server_call( void *req_ptr )
{
    struct __server_request_info * const req = req_ptr;
    sigset_t sigset;
    void *addr = req->reply_data;
    data_size_t size = req->u.req.request_header.reply_size;
    BOOL has_write_watch = FALSE;
    unsigned int ret;

    if (!size) return wine_server_call( req_ptr );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(ret = check_write_access( addr, size, &has_write_watch )))
    {
        ret = server_call_unlocked( req );
        if (has_write_watch) update_write_watches( addr, size, wine_server_reply_size( req ));
    }
    else memset( &req->u.reply, 0, sizeof(req->u.reply) );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           virtual_locked_read
 */
ssize_t virtual_locked_read( int fd, void *addr, size_t size )
{
    sigset_t sigset;
    BOOL has_write_watch = FALSE;
    int err = EFAULT;

    ssize_t ret = read( fd, addr, size );
    if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!check_write_access( addr, size, &has_write_watch ))
    {
        ret = read( fd, addr, size );
        err = errno;
        if (has_write_watch) update_write_watches( addr, size, max( 0, ret ));
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_locked_pread
 */
ssize_t virtual_locked_pread( int fd, void *addr, size_t size, off_t offset )
{
    sigset_t sigset;
    BOOL has_write_watch = FALSE;
    int err = EFAULT;

    ssize_t ret = pread( fd, addr, size, offset );
    if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!check_write_access( addr, size, &has_write_watch ))
    {
        ret = pread( fd, addr, size, offset );
        err = errno;
        if (has_write_watch) update_write_watches( addr, size, max( 0, ret ));
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_locked_recvmsg
 */
ssize_t virtual_locked_recvmsg( int fd, struct msghdr *hdr, int flags )
{
    sigset_t sigset;
    size_t i;
    BOOL has_write_watch = FALSE;
    int err = EFAULT;

    ssize_t ret = recvmsg( fd, hdr, flags );
    if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < hdr->msg_iovlen; i++)
        if (check_write_access( hdr->msg_iov[i].iov_base, hdr->msg_iov[i].iov_len, &has_write_watch ))
            break;
    if (i == hdr->msg_iovlen)
    {
        ret = recvmsg( fd, hdr, flags );
        err = errno;
    }
    if (has_write_watch)
        while (i--) update_write_watches( hdr->msg_iov[i].iov_base, hdr->msg_iov[i].iov_len, 0 );

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    errno = err;
    return ret;
}


/***********************************************************************
 *           virtual_is_valid_code_address
 */
BOOL virtual_is_valid_code_address( const void *addr, SIZE_T size )
{
    struct file_view *view;
    BOOL ret = FALSE;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((view = find_view( addr, size )))
        ret = !(view->protect & VPROT_SYSTEM);  /* system views are not visible to the app */
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           virtual_check_buffer_for_read
 *
 * Check if a memory buffer can be read, triggering page faults if needed for DIB section access.
 */
BOOL virtual_check_buffer_for_read( const void *ptr, SIZE_T size )
{
    if (!size) return TRUE;
    if (!ptr) return FALSE;

    __TRY
    {
        volatile const char *p = ptr;
        char dummy __attribute__((unused));
        SIZE_T count = size;

        while (count > host_page_size)
        {
            dummy = *p;
            p += host_page_size;
            count -= host_page_size;
        }
        dummy = p[0];
        dummy = p[count - 1];
    }
    __EXCEPT
    {
        return FALSE;
    }
    __ENDTRY
    return TRUE;
}


/***********************************************************************
 *           virtual_check_buffer_for_write
 *
 * Check if a memory buffer can be written to, triggering page faults if needed for write watches.
 */
BOOL virtual_check_buffer_for_write( void *ptr, SIZE_T size )
{
    if (!size) return TRUE;
    if (!ptr) return FALSE;

    __TRY
    {
        volatile char *p = ptr;
        SIZE_T count = size;

        while (count > host_page_size)
        {
            *p |= 0;
            p += host_page_size;
            count -= host_page_size;
        }
        p[0] |= 0;
        p[count - 1] |= 0;
    }
    __EXCEPT
    {
        return FALSE;
    }
    __ENDTRY
    return TRUE;
}


/***********************************************************************
 *           virtual_uninterrupted_read_memory
 *
 * Similar to NtReadVirtualMemory, but without wineserver calls. Moreover
 * permissions are checked before accessing each page, to ensure that no
 * exceptions can happen.
 */
SIZE_T virtual_uninterrupted_read_memory( const void *addr, void *buffer, SIZE_T size )
{
    struct file_view *view;
    sigset_t sigset;
    SIZE_T bytes_read = 0;

    if (!size) return 0;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((view = find_view( addr, size )))
    {
        if (!(view->protect & VPROT_SYSTEM))
        {
            while (bytes_read < size && (get_unix_prot( get_host_page_vprot( addr )) & PROT_READ))
            {
                SIZE_T block_size = min( size - bytes_read, host_page_size - ((UINT_PTR)addr & host_page_mask) );
                memcpy( buffer, addr, block_size );

                addr   = (const void *)((const char *)addr + block_size);
                buffer = (void *)((char *)buffer + block_size);
                bytes_read += block_size;
            }
        }
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return bytes_read;
}


/***********************************************************************
 *           virtual_uninterrupted_write_memory
 *
 * Similar to NtWriteVirtualMemory, but without wineserver calls. Moreover
 * permissions are checked before accessing each page, to ensure that no
 * exceptions can happen.
 */
NTSTATUS virtual_uninterrupted_write_memory( void *addr, const void *buffer, SIZE_T size )
{
    BOOL has_write_watch = FALSE;
    sigset_t sigset;
    NTSTATUS ret;

    if (!size) return STATUS_SUCCESS;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(ret = check_write_access( addr, size, &has_write_watch )))
    {
        memcpy( addr, buffer, size );
        if (has_write_watch) update_write_watches( addr, size, size );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           virtual_set_force_exec
 *
 * Whether to force exec prot on all views.
 */
void virtual_set_force_exec( BOOL enable )
{
    struct file_view *view;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!force_exec_prot != !enable)  /* change all existing views */
    {
        force_exec_prot = enable;

        WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
        {
            /* file mappings are always accessible */
            BYTE commit = is_view_valloc( view ) ? 0 : VPROT_COMMITTED;

            mprotect_range( view->base, view->size, commit, 0 );
        }
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}


/***********************************************************************
 *           virtual_manage_exec_writes
 */
void virtual_enable_write_exceptions( BOOL enable )
{
    struct file_view *view;
    sigset_t sigset;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!enable_write_exceptions && enable)  /* change all existing views */
    {
        WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
            if (set_page_vprot_exec_write_protect( view->base, view->size ))
                mprotect_range( view->base, view->size, 0, 0 );
    }
    enable_write_exceptions = enable;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}


/* free reserved areas within a given range */
static void free_reserved_memory( char *base, char *limit )
{
    struct reserved_area *area;

    for (;;)
    {
        int removed = 0;

        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            char *area_base = area->base;
            char *area_end = area_base + area->size;

            /* ml799: never free the FEX arena. It is held for the process
             * lifetime, and the 0x80000000..address_space_limit call below
             * spans it -- releasing it here would hand the emulator's address
             * space back to general use mid-run, silently. */
            if (area->fex_only || area->thin_only) continue;
            if (area_end <= base) continue;
            if (area_base >= limit) return;
            if (area_base < base) area_base = base;
            if (area_end > limit) area_end = limit;
            remove_reserved_area( area_base, area_end - area_base );
            removed = 1;
            break;
        }
        if (!removed) return;
    }
}

#ifndef _WIN64

/***********************************************************************
 *           virtual_release_address_space
 *
 * Release some address space once we have loaded and initialized the app.
 */
static void virtual_release_address_space(void)
{
#ifndef __APPLE__  /* On macOS, we still want to free some of low memory, for OpenGL resources */
    if (user_space_limit > (void *)limit_2g) return;
#endif
    free_reserved_memory( (char *)0x20000000, (char *)0x7f000000 );
}

#endif  /* _WIN64 */


