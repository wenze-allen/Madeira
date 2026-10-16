/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Protection changes, guest image checks, commits. Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *           mprotect_exec
 *
 * Wrapper for mprotect, adds PROT_EXEC if forced by force_exec_prot
 */
/* ml374: non-zero while the MACH EXCEPTION-SERVER thread is running wine's
 * page/SEH machinery on behalf of a faulting thread.
 *
 * That thread is a bare pthread with NO wine TEB, and every wine log macro
 * (ERR/WARN/TRACE/FIXME) ends in __wine_dbg_output, which reads thread-local
 * state and faults. It has now killed two runs from two different sites —
 * ml370 (__wine_dbg_header+0x100, my WARN in the cross-thread fault handler)
 * and ml374 (__wine_dbg_output+0x18, mprotect_exec's unconditional ERR reached
 * via mprotect_range). Both looked like guest crashes at a host pc with no log
 * lines, because the thread that logs is the thread that died.
 *
 * RULE: any code reachable from ios_mach_deliver_guest_exception must use
 * dprintf(2,...), never a wine log macro. This flag lets shared helpers that
 * legitimately log on normal threads stay silent on that one. */
volatile int ios_in_mach_exc;
/***********************************************************************
 *           ios_guest_image_is_host_data      (iOS-Madeira ml1030)
 *
 * TRUE for a page that belongs to a PE image mapped inside a WoW guest window.
 *
 * WHY THIS QUESTION EXISTS. Inside a guest window every SEC_IMAGE view is an
 * i386 PE by construction, and this port NEVER executes an i386 image from its
 * own VA: the emulator decodes those bytes as DATA and runs its own translation
 * out of the JIT pool.  So VPROT_EXEC on such a page is Wine bookkeeping with no
 * host meaning, while VPROT_WRITE is load-bearing -- it is what makes an inline
 * hook, a runtime relocation fixup, or the emulator's own SMC untrap land.
 *
 * Deliberately NOT "anything in the window": a guest's anonymous executable
 * memory is decided by its own rule (ios_guest_anon_rwx_is_host_data, below):
 * a managed runtime's code buffers keep the pool alias and the store emulator,
 * and those views are not SEC_IMAGE.  The test is the view, not the address
 * range.
 *
 * virtual_mutex is held by every caller that can reach here (mprotect_range from
 * set_vprot, and the map_image section loop), so find_view() is safe. */
static struct file_view *find_view( const void *addr, size_t size );

static int ios_guest_image_write_enabled(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *s = getenv( "MADEIRA_GUEST_IMAGE_WRITE" );
        cached = (s && (*s == '0' || *s == 'n' || *s == 'N')) ? 0 : 1;
    }
    return cached;
}

static int ios_guest_image_is_host_data( const void *base, size_t size )
{
#ifdef WINE_IOS
    struct file_view *view;

    if (!ios_guest_image_write_enabled()) return 0;
    if (!ios_wow_in_window( base )) return 0;
    if (!(view = find_view( base, size ))) return 0;
    return (view->protect & SEC_IMAGE) != 0;
#else
    return 0;
#endif
}

/* madeira-bcd [x64-image] (env MADEIRA_X64_IMAGE_NOCOPY = 1; default off, set
 * in the game's own file): A PURE-X64 IMAGE IS HOST DATA IN AN X64 PROCESS TOO.
 *
 * Every image an x64 pseudo-process loads is copied into the JIT pool, pure
 * x64 ones included: GTA V Enhanced build 422 (2026-10-07 07:59) carried
 * 454 MiB of such copies in the 889 MiB span (libcef.dll 239.7, the game exe
 * 91.3, steamclient64.dll x2 49.5, Launcher.exe 32.1, libGLESv2, socialclub,
 * tier0, chrome_elf, nvapi64 ...) next to ~450 MiB of hybrid Wine DLL copies,
 * and the game died at its third steamclient64.dll copy with the span full.
 *
 * The emulator never runs x64 code from a pool copy. FEX Core.cpp (ml315,
 * [pool-rip-fix]) rewrites any guest RIP that lands in a module's pool copy
 * back to the PE VA and re-enters the dispatcher ("No block is ever created
 * for the alias address"); the SMC intervals it tracks are PE-space (2341
 * `Add SMC interval` lines in that log, all at PE VAs); the EC bitmap is
 * PE-space; the alias table exists for ARM64EC native code, which really
 * executes from its copy. So a pure-x64 copy is dead weight: the i386
 * precedent is ml1030 above, where a 32-bit image page keeps VPROT_EXEC in
 * Wine's tables while the host page is R/W only, and 32-bit programs run.
 *
 * Marking: map_image_into_view sets VPROT_X64DATA on the view before the
 * section protections when the image is machine AMD64, carries no CHPE
 * metadata (update_arm64ec_ranges did not set VPROT_ARM64EC, and the server
 * did not call it hybrid), is not a Wine builtin, is not a resource-only map,
 * and the process is not WoW64. mprotect_exec then drops PROT_EXEC for such a
 * view exactly as ml1030 does: the eager copy loop makes no copy, set_vprot
 * still records VPROT_EXEC, and every later PAGE_EXECUTE_* request (the
 * emulator's SMC trap/untrap through NtProtectVirtualMemory) lands on plain
 * R or R/W. No alias entry is pushed for the image (IosAliasEntries has 256
 * slots). Hybrid images, builtins and everything else keep their copy.
 *
 * History: upstream's ml457 (2026-08-03) skipped the copy for pure x64 and
 * steam.exe died within seconds ("garbage target out of vstdlib's .fptable");
 * ml458 wrote "do not try a third time" without a root cause. That predates
 * ml710 (loader-safe interval registration), ml1030 and the child-process
 * alias work, so it is tested again behind this switch, off by default. The
 * failure to watch for is an exec AV / [iOS-noexec] at the first call into a
 * module logged by [x64-image]; 0 restores the copies. */
static int ios_x64_image_nocopy_enabled(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *s = getenv( "MADEIRA_X64_IMAGE_NOCOPY" );
        cached = (s && s[0] == '1' && !s[1]) ? 1 : 0;
    }
    return cached;
}

/* The request is host-page rounded (16 KB) while SizeOfImage is only 4 KB
 * aligned, so a last section's request ends up to 12 KB past the view: GTA V
 * Enhanced build 423 (2026-10-07 09:18), GTA5_Enhanced.exe 0x72d4840000+
 * 0x5b46000, last section request 0x72d9964000+0xa24000 ends 0x72da388000, 8 KB
 * past the view. find_view( base, size ) refused it, the ml348 "OUTSIDE nearest
 * image" path gave the 10 MB section an anonymous-RWX pool alias, its PE VA was
 * remapped onto blessed pool pages, and the game's TLS callback, which decrypts
 * that section byte by byte, took one emulated store fault per byte
 * ([fault-class] stride=1, 2 million hits, 2 MB done in a minute). So look the
 * view up by its start and accept a tail that stays inside the view's last host
 * page; views start on 64 KB boundaries, so no other view shares that page. */
#define IOS_X64_IMAGE_HOST_PAGE 0x4000u
static int ios_x64_image_view_covers( uintptr_t view_base, size_t view_size, uintptr_t base, size_t size )
{
    uintptr_t view_end = view_base + view_size;
    uintptr_t host_end = (view_end + IOS_X64_IMAGE_HOST_PAGE - 1) & ~(uintptr_t)(IOS_X64_IMAGE_HOST_PAGE - 1);

    if (base < view_base || base >= view_end) return 0;
    if (base + size < base) return 0;
    return base + size <= host_end;
}

static int ios_x64_image_is_host_data( const void *base, size_t size )
{
#ifdef WINE_IOS
    struct file_view *view;

    if (!ios_x64_image_nocopy_enabled()) return 0;
    if (!(view = find_view( base, 0 ))) return 0;
    if (!(view->protect & VPROT_X64DATA)) return 0;
    return ios_x64_image_view_covers( (uintptr_t)view->base, view->size, (uintptr_t)base, size );
#else
    return 0;
#endif
}


/* A guest's anonymous RWX data heap is plain read/write memory to the host.
 *
 * Some runtimes allocate their data heap PAGE_EXECUTE_READWRITE (Mono's Boehm
 * GC does). mprotect_exec cannot grant host exec, so it would back the heap
 * with a JIT-pool R+X slot and route every store through the store emulator.
 * Host exec is not needed: x86 bytes are decoded by FEX, never fetched by the
 * host, and FEX tracks SMC on RWX ranges itself through NtProtectVirtualMemory
 * (see ml1030). So PROT_EXEC is dropped for such a heap.
 *
 * Excluded, because they need (or already have) the pool path: EC_CODE requests
 * (ios_alloc_ec_code while the request is in flight, VPROT_ARM64EC afterwards),
 * the JIT pool, alias-backed ranges, images, file mappings, and views under
 * 64 KB (possible native thunk pages).
 *
 * Guest JIT code chunks are excluded too: guests patch them with unaligned
 * atomics, which must not land on a plain page FEX has armed for SMC. Two tests
 * keep them out. Only a view ALLOCATED read-write-execute qualifies (its
 * allocation protection, view->protect, has both VPROT_WRITE and VPROT_EXEC),
 * as a GC heap is: a JIT that allocates read-write and makes its code
 * executable later keeps the pool path. And code and data are told apart by
 * size, a heuristic: Boehm's heap chunks are an expansion plus one 4 KB page
 * (0x41000, ...), never a multiple of 64 KB, while Mono's code chunks, also
 * allocated RWX, are (0x100000). A data heap sized in 64 KB multiples just
 * keeps the pool path.
 *
 * The decision is per allocation and permanent. A page must not move to the
 * pool later: that copies and remaps a live page, and a store landing between
 * the two is lost.
 *
 * MADEIRA_GUEST_RWX_DATA=0 restores the previous behaviour. */
static int ios_alloc_ec_code;   /* set by allocate_virtual_memory under virtual_mutex */

static int ios_guest_rwx_data_enabled(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        /* On by default: a guest's anonymous RWX data heap (Mono's Boehm GC) is
         * plain read/write memory. 0 maps it through the JIT pool again, with
         * every store emulated, as before. */
        const char *s = getenv( "MADEIRA_GUEST_RWX_DATA" );
        cached = (s && (*s == '0' || *s == 'n' || *s == 'N')) ? 0 : 1;
    }
    return cached;
}

static int ios_guest_anon_rwx_view_ok( const struct file_view *view )
{
    if (!is_view_valloc( view )) return 0;
    if (view->protect & (SEC_IMAGE | VPROT_ARM64EC | VPROT_SYSTEM)) return 0;
    /* allocated RWX, not made executable after the fact: see above */
    if ((view->protect & (VPROT_WRITE | VPROT_EXEC)) != (VPROT_WRITE | VPROT_EXEC)) return 0;
    if (view->size < 0x10000) return 0;
    return (view->size & 0xffff) != 0;   /* data, not a code chunk: see above */
}

/* ml1279: anonymous RWX memory in a 32-bit guest window, code chunks included.
 *
 * Nothing there is ever executed by the host: FEX decodes the x86 bytes and runs its own
 * translation from its code buffer, so the window rule of ml1030 (image pages) holds for a
 * managed runtime's JIT chunks too. Through the JIT pool every store to such a chunk was a
 * Mach fault: Terraria's wine-mono emitted 25.2 M emulated stores into ~8 MB of 64 KB code
 * chunks in 7 minutes (~100 s of handler time, the main thread down to 30-40% busy), and
 * MADEIRA_WX's 256-page table was full after 20 s. As plain memory a chunk is written
 * freely until FEX arms it (PAGE_EXECUTE_READ -> PROT_READ); the next store faults once,
 * FEX invalidates and disarms (PAGE_EXECUTE_READWRITE -> read/write), as on Windows.
 * Same exclusions as below (EC_CODE requests, the pool, existing aliases, images, file
 * mappings), but no size heuristic and no ARM64EC view requirement.
 *
 * ml1282: automatic per window. It turns on in a window when Wine Mono's runtime
 * (libmono-2.0-x86.dll, loaded by mscoree) is mapped there -- verified on Terraria; a
 * Unity game loads its own mono-2.0-bdwgc.dll and is not matched. MADEIRA_WOW_RWX_PLAIN=0
 * never turns it on, =1 turns it on for every 32-bit window. */
static int ios_wow_rwx_plain_mode(void)
{
    static int cached = -2;
    if (cached == -2)
    {
        const char *s = getenv( "MADEIRA_WOW_RWX_PLAIN" );
        cached = !s || !*s ? -1 : (*s == '1') ? 1 : 0;
        dprintf( 2, "[wow-rwx] ml1279 MADEIRA_WOW_RWX_PLAIN=%s -> 32-bit guest RWX memory is %s\n",
                 s ? s : "(unset)",
                 cached == 1 ? "plain read/write in every 32-bit window" :
                 cached == 0 ? "pool-aliased (stores emulated)" :
                               "plain read/write in a window once Wine Mono is mapped there" );
    }
    return cached;
}

/* The window whose RWX memory is plain, or NULL. Lock-free reads of slot fields, like the
 * other window lookups on this path. */
static struct ios_wow_window *ios_wow_rwx_plain_window( const void *addr )
{
    int mode = ios_wow_rwx_plain_mode();
    struct ios_wow_window *w;

    if (!mode) return NULL;
    if (!(w = ios_wow_live_slot_for_addr( addr ))) return NULL;
    if (mode == 1 || __atomic_load_n( &w->wine_mono, __ATOMIC_ACQUIRE )) return w;
    return NULL;
}

/* Called for every image mapping: notice Wine Mono's 32-bit runtime. */
static void ios_wow_note_image( const void *base, const UNICODE_STRING *nt_name )
{
    static const WCHAR libmono[] = {'l','i','b','m','o','n','o','-','2','.','0','-','x','8','6','.','d','l','l'};
    const size_t n = ARRAY_SIZE( libmono );
    struct ios_wow_window *w;
    const WCHAR *name;
    size_t len, i;

    if (!nt_name || !nt_name->Buffer) return;
    len = nt_name->Length / sizeof(WCHAR);
    if (len < n) return;
    name = nt_name->Buffer + len - n;
    if (len > n && name[-1] != '\\' && name[-1] != '/') return;
    for (i = 0; i < n; i++)
    {
        WCHAR c = name[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != libmono[i]) return;
    }
    if (!(w = ios_wow_live_slot_for_addr( base ))) return;
    if (__atomic_exchange_n( &w->wine_mono, 1, __ATOMIC_ACQ_REL )) return;
    dprintf( 2, "[wow-rwx] ml1282 Wine Mono mapped at %p in window B=%p: its RWX memory is %s\n",
             base, (void *)w->base,
             ios_wow_rwx_plain_mode() ? "plain read/write from now on"
                                      : "still pool-aliased (MADEIRA_WOW_RWX_PLAIN=0)" );
}

static int ios_wow_rwx_view_ok( const struct file_view *view )
{
    if (!is_view_valloc( view )) return 0;
    if (view->protect & (SEC_IMAGE | VPROT_ARM64EC | VPROT_SYSTEM)) return 0;
    return 1;
}

/* The range is host-page rounded (16 KB) and can run past the end of a guest
 * allocation (0x41000 -> 0x44000), so every view it touches must qualify. */
static int ios_guest_anon_rwx_is_host_data( const void *base, size_t size )
{
#ifdef WINE_IOS
    extern int ios_jit_anon_alias_find_cover(void *, size_t, void **, void **);
    extern void *ios_jit_rx_base_global;
    extern size_t ios_jit_pool_size_global;
    void *cov_rw = NULL, *cov_rx = NULL;
    uintptr_t b = (uintptr_t)base, e = b + size, a, rx = (uintptr_t)ios_jit_rx_base_global;
    int any = 0;

    struct ios_wow_window *plain_w = (!ios_alloc_ec_code && e > b) ? ios_wow_rwx_plain_window( base ) : NULL;

    if (plain_w && e - 1 < plain_w->base + IOS_WOW_WINDOW_SIZE &&
        !(rx && e > rx && b < rx + ios_jit_pool_size_global) &&
        !ios_jit_anon_alias_find_cover( (void *)base, size, &cov_rw, &cov_rx ))
    {
        for (a = b; a < e; )
        {
            struct file_view *view = find_view( (const void *)a, 1 );
            if (!view) { a = (a + 0x1000) & ~(uintptr_t)0xfff; continue; }   /* rounding gap */
            if (!ios_wow_rwx_view_ok( view )) { any = -1; break; }
            any = 1;
            a = (uintptr_t)view->base + view->size;
        }
        if (any == 1) return 1;
        any = 0;
    }

    if (!ios_guest_rwx_data_enabled() || ios_alloc_ec_code || !arm64ec_view) return 0;
    if (e <= b) return 0;
    if (rx && e > rx && b < rx + ios_jit_pool_size_global) return 0;
    if (ios_jit_anon_alias_find_cover( (void *)base, size, &cov_rw, &cov_rx )) return 0;
    for (a = b; a < e; )
    {
        struct file_view *view = find_view( (const void *)a, 1 );
        if (!view) { a = (a + 0x1000) & ~(uintptr_t)0xfff; continue; }   /* rounding gap */
        if (!ios_guest_anon_rwx_view_ok( view )) return 0;
        any = 1;
        a = (uintptr_t)view->base + view->size;
    }
    return any;
#else
    return 0;
#endif
}


static inline int mprotect_exec( void *base, size_t size, int unix_prot )
{
#ifdef WINE_IOS
    /* iOS-Madeira ml1030: A 32-BIT IMAGE PAGE IS DATA TO THE HOST — SO STOP
     * ROUTING ITS WRITE REQUESTS THROUGH THE EXECUTABLE MACHINERY.
     *
     * THE SYMPTOM. A guest that inline-hooks builtin i386 ntdll (a byte store
     * over the first bytes of a syscall stub) faults forever: the device log
     * shows `wine_want=5 host_prot=1 (not a strip)` on an image page whose Mach
     * region reports `prot=1 max=3` — read-only, with no EXECUTE even permitted
     * — while the guest has already issued NtProtectVirtualMemory(
     * PAGE_EXECUTE_READWRITE) for exactly that 4 KB page (the emulator logs the
     * matching exec+write protection notification).
     *
     * THE MECHANISM. PAGE_EXECUTE_READWRITE on a SEC_IMAGE view becomes
     * VPROT_EXEC|VPROT_READ|VPROT_WRITECOPY, so get_unix_prot() hands this
     * function PROT_READ|PROT_WRITE|PROT_EXEC.  The only branch below that can
     * actually grant write on a region whose Mach max_protection lacks
     * VM_PROT_EXECUTE is the vm_protect() arm, and that arm is gated on
     * `!(unix_prot & PROT_EXEC)`.  With PROT_EXEC set, control instead enters
     * the JIT-pool arm, where a plain mprotect() is refused by the kernel
     * (max_protection has no EXECUTE) and the two remaining outcomes are
     * `mprotect(base, size, PROT_READ)` — read-only forever — or copying an
     * i386 image into the ARM64 JIT pool, which is worse.  Neither ever grants
     * write, so the store re-faults, the emulator untraps the page with another
     * PAGE_EXECUTE_READWRITE that lands in the same dead end, and the page is
     * reported as "faulted N times with NO progress".
     *
     * THE FIX. Drop the bit that has no host meaning.  The emulator's SMC
     * contract is preserved exactly, because it is expressed in the OTHER
     * direction: it arms the trap with PAGE_EXECUTE_READ (which still lands on
     * mprotect(PROT_READ) — unchanged behaviour) and disarms it with
     * PAGE_EXECUTE_READWRITE (which now genuinely grants write, after it has
     * invalidated the translations for the page).  A page the emulator has
     * never translated simply becomes writable with no fault at all, which is
     * also correct: there is nothing to invalidate.
     *
     * MADEIRA_GUEST_IMAGE_WRITE=0 restores the previous behaviour exactly. */
    if ((unix_prot & PROT_EXEC) && ios_guest_image_is_host_data( base, size ))
    {
        static unsigned long gid_n;
        if (++gid_n <= 24 && !ios_in_mach_exc)
            dprintf( 2, "[guest-image] ml1030 #%lu %p+0x%lx prot=%c%c%c — 32-bit image page, "
                        "EXEC has no host meaning here; applying %c%c- instead\n",
                     gid_n, base, (unsigned long)size,
                     (unix_prot & PROT_READ)  ? 'r' : '-',
                     (unix_prot & PROT_WRITE) ? 'w' : '-',
                     (unix_prot & PROT_EXEC)  ? 'x' : '-',
                     (unix_prot & PROT_READ)  ? 'r' : '-',
                     (unix_prot & PROT_WRITE) ? 'w' : '-' );
        unix_prot &= ~PROT_EXEC;
        if (!unix_prot) unix_prot = PROT_READ;   /* PAGE_EXECUTE alone: readable is the honest answer */
    }
    else if ((unix_prot & PROT_EXEC) && ios_guest_anon_rwx_is_host_data( base, size ))
    {
        static unsigned long grd_n;
        if (++grd_n <= 24 && !ios_in_mach_exc)
            dprintf( 2, "[guest-rwx] #%lu %p+0x%lx prot=%c%c%c — anonymous guest memory, "
                        "EXEC is FEX bookkeeping; applying %c%c- instead\n",
                     grd_n, base, (unsigned long)size,
                     (unix_prot & PROT_READ)  ? 'r' : '-',
                     (unix_prot & PROT_WRITE) ? 'w' : '-',
                     (unix_prot & PROT_EXEC)  ? 'x' : '-',
                     (unix_prot & PROT_READ)  ? 'r' : '-',
                     (unix_prot & PROT_WRITE) ? 'w' : '-' );
        unix_prot &= ~PROT_EXEC;
        if (!unix_prot) unix_prot = PROT_READ;
    }

    /* madeira-bcd [x64-image]: see ios_x64_image_is_host_data. Same contract as
     * ml1030, for a pure-x64 image view in an x64 process: the bit has no host
     * meaning, the page keeps VPROT_EXEC in Wine's tables, no pool copy. */
    if ((unix_prot & PROT_EXEC) && ios_x64_image_is_host_data( base, size ))
    {
        static unsigned long x64_n;
        if (++x64_n <= 24 && !ios_in_mach_exc)
            dprintf( 2, "[x64-image] #%lu %p+0x%lx prot=%c%c%c -- pure-x64 image page, EXEC has no host "
                        "meaning here (the emulator runs it at the PE VA); applying %c%c- (MADEIRA_X64_IMAGE_NOCOPY)\n",
                     x64_n, base, (unsigned long)size,
                     (unix_prot & PROT_READ)  ? 'r' : '-',
                     (unix_prot & PROT_WRITE) ? 'w' : '-',
                     (unix_prot & PROT_EXEC)  ? 'x' : '-',
                     (unix_prot & PROT_READ)  ? 'r' : '-',
                     (unix_prot & PROT_WRITE) ? 'w' : '-' );
        unix_prot &= ~PROT_EXEC;
        if (!unix_prot) unix_prot = PROT_READ;
    }

    /* madeira-bcd: a resource-only image view (ios_map_resource_view) never runs
     * code, so no exec request made while mapping it may create anything
     * executable -- in particular not the ml348 "OUTSIDE nearest image"
     * anonymous-RWX alias that a last section whose 16 KB-rounded end passes
     * SizeOfImage falls into before the image refusal further down. That alias
     * is keyed by VA and outlives the view, so the next image mapped there ran
     * from it (gta-2237: "RockstarService.exe start" died at its entry stub, the
     * service never started and the launcher found no pipe). */
    if ((unix_prot & PROT_EXEC) && ios_map_resource_view)
    {
        static int resource_exec_n;
        if (resource_exec_n++ < 16)
            dprintf( 2, "[resource-map] exec request %p+0x%lx in a resource-only view refused "
                        "(no pool copy, no anon alias)\n", base, (unsigned long)size );
        ios_jit_copy_refused = 2;
        mprotect( base, size, PROT_READ );
        errno = ENOMEM;
        return -1;
    }

#endif

    /* ml247: catch WHO narrows maxprot on pool pages.
     *
     * Poison is created during a module's life (POISONED AT FREE, and predating
     * clear_arm64ec_range). The freelist guard now refuses poisoned ranges, but that
     * ORPHANS them -- 62 drops = 164MB from an 896MB pool now at 92% used, and FEX has
     * started failing allocations (NULL IREmitter -> str xzr,[x0,#0x378] with x0=0;
     * reclaim-recover ENOMEM). Recovering that VA means stopping the poison at source.
     *
     * mprotect_exec is the one hook every protection change funnels through. Its existing
     * ERR() output is swallowed by MADEIRA_QUIET, so log via dprintf, and only for pool
     * addresses so this cannot flood. */
    {
        extern void *ios_jit_rx_base_global;
        extern void *ios_jit_rw_base_global;
        extern size_t ios_jit_pool_size_global;
        uintptr_t b = (uintptr_t)base;
        uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
        uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
        size_t ps = ios_jit_pool_size_global;
        static int prot_n;

        if (ps && prot_n < 40 &&
            ((rx && b >= rx && b < rx + ps) || (rw && b >= rw && b < rw + ps)))
        {
            prot_n++;
            dprintf( 2, "[pool-prot] mprotect_exec base=%p size=0x%lx prot=%c%c%c alias=%s off=0x%lx\n",
                     base, (unsigned long)size,
                     (unix_prot & PROT_READ)  ? 'r' : '-',
                     (unix_prot & PROT_WRITE) ? 'w' : '-',
                     (unix_prot & PROT_EXEC)  ? 'x' : '-',
                     (rx && b >= rx && b < rx + ps) ? "RX" : "RW",
                     (unsigned long)((rx && b >= rx && b < rx + ps) ? b - rx : b - rw) );
        }
    }
    if (FORCE_EXEC_AT( base ) && (unix_prot & PROT_READ) && !(unix_prot & PROT_EXEC))
    {
        if (!ios_in_mach_exc)                   /* ml374: see ios_in_mach_exc */
            TRACE( "forcing exec permission on %p-%p\n", base, (char *)base + size - 1 );
        if (!mprotect( base, size, unix_prot | PROT_EXEC )) return 0;
        /* exec + write may legitimately fail, in that case fall back to write only */
#ifdef WINE_IOS
        /* iOS TXM refuses PROT_EXEC outside the JIT pool, so force_exec_prot (DEP
         * off, which load_native_dll() switches on for any module without
         * IMAGE_DLLCHARACTERISTICS_NX_COMPAT, i.e. most i386 mingw modules) can
         * never be honoured here.  Inside a 32-bit guest window guest code is
         * never executed from its own pages (it is translated into the JIT
         * pool), so apply the protection the caller asked for instead of
         * failing every PAGE_READONLY request with STATUS_ACCESS_DENIED.
         *
         * The same holds OUTSIDE the windows, where this used to keep the
         * upstream rule. A 32-bit process also runs 64-bit host images there
         * (wow64.dll, the emulator DLL, ntdll), and force_exec_prot is one flag
         * for the whole host process: once a 32-bit process has turned it on,
         * every later process sees it, 64-bit ones included. The loader makes
         * an import table writable, fills it, and puts PAGE_READONLY back; that
         * last request failed, and NtProtectVirtualMemory syncs an image's
         * JIT-pool copy only when the protection change succeeds, so the copy
         * that runs kept the unresolved table. wow64.dll then called its first
         * import through an entry that still held a name offset and every
         * 32-bit program died with an access violation at start; a 64-bit
         * program started after it died the same way. Nothing is gained by the
         * refusal: no page outside the JIT pool can be executable here.
         *
         * Only a 32-bit (WoW64) process can switch force_exec_prot on
         * (NtSetInformationProcess(ProcessExecuteFlags) refuses a 64-bit
         * process), so a run that never starts a 32-bit program never reaches
         * this line. */
        if (!(unix_prot & PROT_WRITE))
        {
            static unsigned int unforced_n;

            if (++unforced_n <= 4 && !ios_in_mach_exc)
                dprintf( 2, "[force-exec] PROT_EXEC unavailable; applying the requested protection "
                            "unforced at %p+0x%lx (%s a guest window)\n", base, (unsigned long)size,
                         ios_wow_in_window( base ) ? "inside" : "outside" );
        }
#else
        if (!(unix_prot & PROT_WRITE)) return -1;
#endif
    }

#ifdef WINE_IOS
    /* iOS-specific: when asked to make pages writable on a file-backed
     * mapping (e.g. the IAT in xtajit64's .rdata), POSIX mprotect succeeds
     * but the kernel silently keeps pages read-only (writes silently
     * no-op). The Mach vm_protect API succeeds where POSIX silently fails.
     *
     * Apply only on the PROT_WRITE-add path; non-write protect changes go
     * through the regular mprotect below. */
    if (!ios_in_mach_exc && ios_lean_mprotect_log())   /* ml374: see ios_in_mach_exc; madeira-bcd lean-diag */
        ERR("mprotect_exec(%p, 0x%lx, %c%c%c)\n", base, (unsigned long)size,
            (unix_prot & PROT_READ)  ? 'r' : '-',
            (unix_prot & PROT_WRITE) ? 'w' : '-',
            (unix_prot & PROT_EXEC)  ? 'x' : '-');
    if ((unix_prot & PROT_WRITE) && !(unix_prot & PROT_EXEC))
    {
        /* ml391 (task #60): try WITHOUT VM_PROT_COPY first.  COPY forcibly
         * privatizes the mapping object — on a MAP_SHARED section view it
         * silently disconnects the view from the section: writes land in a
         * private copy and every other pseudo-process reads the section's
         * original zeros ([sec-test] ZEROS; killed the SteamChrome
         * webhelper-init handshake and every CSharedMemStream).  When maxprot
         * permits WRITE (anon memory, temp-file-backed shared sections, the
         * JIT pool's vm_remap alias) the plain request succeeds and sharing
         * is preserved; it also re-asserts write past the iOS silent
         * mmap-downgrade.  Only when maxprot lacks WRITE (code-signed PE
         * files — the IAT case this path was built for) fall back to +COPY,
         * where privatizing is correct since PE data is per-process anyway. */
        kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)base, size,
                                      FALSE,  /* set_maximum */
                                      VM_PROT_READ | VM_PROT_WRITE);
        if (kr == KERN_SUCCESS) return 0;
        kr = vm_protect(mach_task_self(), (vm_address_t)base, size,
                        FALSE,  /* set_maximum */
                        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (kr == KERN_SUCCESS) {
            if (!ios_in_mach_exc)
                ERR("iOS vm_protect RW+COPY OK at %p+0x%lx (plain RW refused — privatized)\n",
                    base, (unsigned long)size);
            return 0;
        }
        if (!ios_in_mach_exc)
            ERR("iOS vm_protect RW failed kr=%d at %p+0x%lx — falling to mprotect\n",
                kr, base, (unsigned long)size);
    }

    if (unix_prot & PROT_EXEC)
    {
        /* iOS/TXM: mprotect(PROT_EXEC) is blocked. TXM only allows execution
         * from debugger-allocated pages at their ORIGINAL virtual addresses.
         * Remapping those pages elsewhere doesn't preserve execute permission.
         *
         * Strategy: Copy PE code sections into the pre-allocated JIT pool and
         * execute from the JIT pool's original RX addresses. Wine's entry points
         * (pLdrInitializeThunk etc.) are redirected via ios_jit_translate_addr().
         *
         * All relative branches (B/BL) within the code section are preserved
         * because the code is copied contiguously. ADRP/data references need
         * re-relocation which is handled by re-applying PE base relocations.
         */
        static void *jit_rx_base = NULL;
        static void *jit_rw_base = NULL;
        static size_t jit_pool_size = 0;
        /* jit_pool_offset promoted to file scope (S1: shared with the
         * per-child ntdll copy allocator). */
        static int jit_pool_init_done = 0;

        if (!jit_pool_init_done)
        {
            const char *rx_str = getenv("WINE_IOS_JIT_RX");
            const char *rw_str = getenv("WINE_IOS_JIT_RW");
            const char *sz_str = getenv("WINE_IOS_JIT_SIZE");
            if (rx_str && rw_str && sz_str)
            {
                jit_rx_base = (void *)strtoull(rx_str, NULL, 16);
                jit_rw_base = (void *)strtoull(rw_str, NULL, 16);
                jit_pool_size = (size_t)strtoull(sz_str, NULL, 16);
                /* Export for SIGBUS handler */
                ios_jit_rx_base_global = jit_rx_base;
                ios_jit_rw_base_global = jit_rw_base;
                ios_jit_pool_size_global = jit_pool_size;

                /* madeira-bcd split pool: the app names the hole between its two
                 * debugger regions (see ios_jit_hole_off). Anything malformed is
                 * ignored, which leaves the allocators exactly as without it. */
                {
                    const char *hole = getenv( "WINE_IOS_JIT_HOLE" );
                    if (hole && *hole)
                    {
                        char *sep = NULL;
                        unsigned long long h0 = strtoull( hole, &sep, 16 ), h1 = 0;
                        if (sep && *sep == ':') h1 = strtoull( sep + 1, NULL, 16 );
                        if (h0 >= 0x8000 && h1 > h0 && h1 < jit_pool_size &&
                            !(h0 & 0x3fff) && !(h1 & 0x3fff))
                        {
                            ios_jit_hole_off = (size_t)h0;
                            ios_jit_hole_end = (size_t)h1;
                            ios_jit_hole_off_eff = (size_t)h0;
                            ios_jit_hole_end_eff = (size_t)h1;
                            dprintf( 2, "[jit-pool] split pool: RX [%p,%p) + [%p,%p) as one span of 0x%lx; "
                                     "hole [0x%llx,0x%llx) (%llu MB: the main thread's stack) is never "
                                     "handed out -- images 0x%llx below it, FEX code from the top\n",
                                     jit_rx_base, (char *)jit_rx_base + h0,
                                     (char *)jit_rx_base + h1, (char *)jit_rx_base + jit_pool_size,
                                     (unsigned long)jit_pool_size, h0, h1, (h1 - h0) >> 20, h0 );
                        }
                        else
                            dprintf( 2, "[jit-pool] split pool: WINE_IOS_JIT_HOLE=%s ignored (pool size 0x%lx)\n",
                                     hole, (unsigned long)jit_pool_size );
                    }
                }
                /* madeira-bcd pool-mid: a second hole above the first, with the
                 * third region M between them (see ios_jit_hole2_off). Taken only
                 * with a valid first hole and at least 16 KB of M; anything else is
                 * ignored, which leaves the one-hole pool. */
                {
                    const char *hole2 = getenv( "WINE_IOS_JIT_HOLE2" );
                    if (hole2 && *hole2)
                    {
                        char *sep = NULL;
                        unsigned long long h0 = strtoull( hole2, &sep, 16 ), h1 = 0;
                        if (sep && *sep == ':') h1 = strtoull( sep + 1, NULL, 16 );
                        if (ios_jit_hole_end > ios_jit_hole_off && h0 >= ios_jit_hole_end + 0x4000 &&
                            h1 > h0 && h1 < jit_pool_size && !(h0 & 0x3fff) && !(h1 & 0x3fff))
                        {
                            ios_jit_hole2_off = (size_t)h0;
                            ios_jit_hole2_end = (size_t)h1;
                            dprintf( 2, "[jit-pool] pool-mid: third region RX [%p,%p) (%lu MB) between the holes; "
                                     "hole 2 [0x%llx,0x%llx) (%llu MB, the main thread's stack) is never handed out "
                                     "either; usable %lu MB of the 0x%lx span\n",
                                     (char *)jit_rx_base + ios_jit_hole_end, (char *)jit_rx_base + h0,
                                     (unsigned long)((h0 - ios_jit_hole_end) >> 20), h0, h1, (h1 - h0) >> 20,
                                     (unsigned long)((jit_pool_size - (ios_jit_hole_end - ios_jit_hole_off) - (h1 - h0)) >> 20),
                                     (unsigned long)jit_pool_size );
                        }
                        else
                            dprintf( 2, "[jit-pool] pool-mid: WINE_IOS_JIT_HOLE2=%s ignored (hole 1 [0x%lx,0x%lx), "
                                     "pool size 0x%lx)\n", hole2, (unsigned long)ios_jit_hole_off,
                                     (unsigned long)ios_jit_hole_end, (unsigned long)jit_pool_size );
                    }
                }
                /* The default big-image slot is above the hole. A game may
                 * request the lower side; if it cannot leave 256MB for startup
                 * images, retain the old upper placement instead. */
                {
                    /* N MB adjacent to a split-pool hole for one image of 64 MB or more (Social Club's libcef.dll); off by default. */
                    const char *big = getenv( "MADEIRA_POOL_BIG_SLOT_MB" );
                    /* 1 puts the existing image slot below the native hole; 0/default keeps it above. */
                    const char *lower = getenv( "MADEIRA_POOL_BIG_SLOT_BELOW" );
                    if (big && *big && strtoul( big, NULL, 10 ) && ios_jit_hole2_end > ios_jit_hole2_off)
                        dprintf( 2, "[pool-big] madeira-bcd MADEIRA_POOL_BIG_SLOT_MB=%s ignored: the pool has a second "
                                 "hole (pool-mid), the slot is laid out against one\n", big );
                    else if (big && *big && strtoul( big, NULL, 10 ))
                    {
                        unsigned long mb = strtoul( big, NULL, 10 );
                        size_t want = mb <= (SIZE_MAX >> 20) ? (size_t)mb << 20 : 0;
                        int below = lower && !strcmp( lower, "1" );
                        size_t slot, skip_off, skip_end;
                        int fits = ios_pool_big_layout( jit_pool_size, ios_jit_hole_off,
                                                         ios_jit_hole_end, want, below,
                                                         &slot, &skip_off, &skip_end );
                        if (!fits && below)
                        {
                            dprintf( 2, "[pool-big] lower slot unavailable with 256MB startup room; trying the default upper slot\n" );
                            below = 0;
                            fits = ios_pool_big_layout( jit_pool_size, ios_jit_hole_off,
                                                       ios_jit_hole_end, want, 0,
                                                       &slot, &skip_off, &skip_end );
                        }
                        if (fits)
                        {
                            ios_pool_big_off = slot;
                            ios_pool_big_size = want;
                            ios_jit_hole_off_eff = skip_off;
                            ios_jit_hole_end_eff = skip_end;
                            dprintf( 2, "[pool-big] madeira-bcd slot [0x%lx,0x%lx) (%lu MB) %s the hole for one "
                                     "image of %u MB or more; ordinary runs below=%lu MB above=%lu MB\n",
                                     (unsigned long)slot, (unsigned long)(slot + want),
                                     (unsigned long)(want >> 20), below ? "below" : "above", IOS_POOL_BIG_MIN >> 20,
                                     (unsigned long)(ios_jit_hole_off_eff >> 20),
                                     (unsigned long)((jit_pool_size - ios_jit_hole_end_eff) >> 20) );
                        }
                        else
                            dprintf( 2, "[pool-big] madeira-bcd MADEIRA_POOL_BIG_SLOT_MB=%s ignored: %s\n", big,
                                     ios_jit_hole_end <= ios_jit_hole_off ? "needs pool-split = 1 (no hole)"
                                     : want < IOS_POOL_BIG_MIN ? "smaller than 64 MB"
                                     : "larger than the run above the hole" );
                    }
                }
                /* 48 to 256 MB of image headroom in the FEX pool-tail budget;
                 * 48/default keeps the existing policy. Region C is unchanged. */
                ios_pool_head_reserve = ios_pool_parse_head_reserve( getenv( "MADEIRA_POOL_HEAD_RESERVE_MB" ) );
                dprintf( 2, "[pool-head] code-buffer budget targets %lu MB of image headroom (region C and recycled buffers unchanged)\n",
                         (unsigned long)(ios_pool_head_reserve >> 20) );
                /* madeira-bcd pool-low: region C (see ios_jit_low_rx_global). Taken only
                 * when its RX side is mapped executable, its RW side read-write, and a
                 * word written through the RW side reads back through the RX side --
                 * the proof that its alias really is at the pool's RX->RW distance,
                 * which FEX's single WriteOffset relies on. */
                {
                    const char *low = getenv( "WINE_IOS_JIT_TAIL_REGION" );
                    uint64_t lrx = 0, lsz = 0;
                    if (low && *low &&
                        ios_pool_low_parse( low, (uint64_t)(uintptr_t)jit_rx_base, (uint64_t)(uintptr_t)jit_rw_base,
                                            jit_pool_size, &lrx, &lsz ))
                    {
                        uintptr_t lrw = (uintptr_t)lrx + ((uintptr_t)jit_rw_base - (uintptr_t)jit_rx_base);
                        mach_vm_address_t qx = (mach_vm_address_t)lrx, qw = (mach_vm_address_t)lrw;
                        mach_vm_size_t sx = 0, sw = 0;
                        vm_region_basic_info_data_64_t ix = { 0 }, iw = { 0 };
                        mach_msg_type_number_t cx = VM_REGION_BASIC_INFO_COUNT_64, cw = VM_REGION_BASIC_INFO_COUNT_64;
                        mach_port_t ox = MACH_PORT_NULL, ow = MACH_PORT_NULL;
                        int ok = mach_vm_region( mach_task_self(), &qx, &sx, VM_REGION_BASIC_INFO_64,
                                                 (vm_region_info_t)&ix, &cx, &ox ) == KERN_SUCCESS &&
                                 mach_vm_region( mach_task_self(), &qw, &sw, VM_REGION_BASIC_INFO_64,
                                                 (vm_region_info_t)&iw, &cw, &ow ) == KERN_SUCCESS &&
                                 qx <= lrx && qw <= lrw &&
                                 (ix.max_protection & VM_PROT_EXECUTE) &&
                                 (iw.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE);
                        if (ok)
                        {
                            volatile uint64_t *pw = (volatile uint64_t *)lrw, *px = (volatile uint64_t *)(uintptr_t)lrx;
                            uint64_t keep = *pw, mark = 0x776f6c2d6c6f6f70ULL ^ (uint64_t)lrx;   /* "pool-low" */
                            *pw = mark;
                            ok = *px == mark;
                            *pw = keep;
                        }
                        if (ok)
                        {
                            ios_jit_low_rx_global = (uintptr_t)lrx;
                            ios_jit_low_rw_global = lrw;
                            __sync_synchronize();
                            ios_jit_low_size_global = (size_t)lsz;
                            dprintf( 2, "[pool-low] madeira-bcd region C RX [0x%llx,0x%llx) RW [%p,%p) (%llu MB) at the "
                                     "pool's RX->RW distance: FEX code buffers are carved here first, the pool "
                                     "tail takes over when it is full; WoW64 processes keep the tail\n",
                                     (unsigned long long)lrx, (unsigned long long)(lrx + lsz), (void *)lrw,
                                     (void *)(lrw + (uintptr_t)lsz), (unsigned long long)(lsz >> 20) );
                        }
                        else
                            dprintf( 2, "[pool-low] madeira-bcd WINE_IOS_JIT_TAIL_REGION=%s ignored: region C is not "
                                     "mapped as expected (RX max=0x%x at 0x%llx, RW prot=0x%x at 0x%llx) or its RW "
                                     "alias is not at the pool's distance -- code buffers stay in the pool tail\n",
                                     low, ix.max_protection, (unsigned long long)qx, iw.protection,
                                     (unsigned long long)qw );
                    }
                    else if (low && *low)
                        dprintf( 2, "[pool-low] madeira-bcd WINE_IOS_JIT_TAIL_REGION=%s ignored: not a page-aligned "
                                 "region of 16 MB or more below the pool [%p,+0x%lx) -- code buffers stay in the "
                                 "pool tail\n", low, jit_rx_base, (unsigned long)jit_pool_size );
                }

                /* ml91 (task #35): dump the VA map ONCE here, unconditionally.
                 * The first cut only probed on jumbo-reserve failure, so a
                 * Thumper run (which never issues one) produced no map at all —
                 * exactly when we needed to know why all six sub-64G candidates
                 * for the RW alias were refused. This is the baseline picture
                 * before CEF asks for anything. */
                ios_va_gap_probe( "jit pool init" );

                /* task #34: start the pool warmer (see ios_pool_warmer_thread).
                 * Keeps every used pool page off the inactive queue so the
                 * compressor never gets to replace a blessed page's frame. */
                {
                    pthread_t warm;
                    if (!pthread_create( &warm, NULL, ios_pool_warmer_thread, NULL ))
                        pthread_detach( warm );
                }

                /* Write TEB restore trampoline at start of JIT pool.
                 * TEB value (0 for now, set later by signal code) at offset 0,
                 * executable trampoline at offset 8. */
                {
                    uint32_t *tramp = (uint32_t *)((char *)jit_rw_base + 8);
                    /* offset 0: TEB address (8 bytes, initially 0) */
                    *(uint64_t *)jit_rw_base = 0;
                    /* offset 8: ldr x18, [pc, #-16]  — encoded as 0x58FFFFD2 */
                    tramp[0] = 0x58FFFFD2;
                    /* offset 12: br x17              — encoded as 0xD61F0220 */
                    tramp[1] = 0xD61F0220;
                    sys_icache_invalidate(jit_rx_base, 16);
                    ios_jit_teb_trampoline = (char *)jit_rx_base + 8;
                    /* Page-align the offset so PE images stay page-aligned
                     * (mprotect requires page-aligned addresses). */
                    jit_pool_offset = 0x4000;  /* one 16KB iOS page */
                    ERR("iOS JIT: TEB trampoline at %p (pool+8)\n", ios_jit_teb_trampoline);
                }

                ERR("iOS JIT pool: RX=%p RW=%p size=0x%lx\n",
                    jit_rx_base, jit_rw_base, (unsigned long)jit_pool_size);
            }
            jit_pool_init_done = 1;
        }

        /* iOS-Madeira ml640: AN OWNED ANON-JIT RANGE IS SETTLED — DECIDE IT FIRST.
         *
         * ROOT CAUSE, proven by the ml639 three-view hash:
         *   guest  = 0x706F9B0000  HASH16K aa4f0ea29a4c7f5c
         *   poolRX = 0x1268C8000   HASH16K 7a9fbb551062ff6b
         *   poolRW = 0x7009EEC000  HASH16K 7a9fbb551062ff6b   (slot=71, dup_end=1)
         *   => poolRX == poolRW, the GUEST vm_remap DETACHED.
         * The pool's dual-map is perfect and every emulated write lands in it; the guest
         * VA simply stops sharing those pages, so Mono writes valid code while FEX
         * executes stale bytes and then zeros, running to alias_end and dying with a
         * deterministic c0000005 (identical across four runs: write_gen=792,
         * highest=0x33fd, RIP_off=0x10000).
         *
         * WHY: this function re-enters on every 4KB W<->X transition and, before ever
         * asking whether a JIT already owns the range, it (a) calls plain mprotect()
         * just below and (b) falls into nearest-image classification. A managed
         * assembly Mono mapped as DATA sits immediately below Mono's buffer; its PE
         * header declares SizeOfImage 0x24000 while only 0x1f000 is mapped, so the
         * backward MZ scan claims [image, image+0x24000) — overlapping the first 16KB
         * of the alias. That 16KB is exactly the chunk holding all 792 writes and the
         * divergence. The anon-alias reuse check sits ~250 lines further down, far too
         * late to prevent any of it.
         *
         * So decide ownership FIRST. If a live alias fully covers the request this is an
         * ordinary JIT W<->X transition: the guest VA is already R+X via the pool
         * dual-map, Wine has already recorded the requested LOGICAL protection in
         * set_vprot(), and writes are meant to fault into the alias store emulator.
         * Nothing further is needed — and critically, nothing may re-map or re-classify
         * this range.
         *
         * ⛔ Only ordinary R/W/X transitions take this path. PROT_NONE, decommit,
         * release and teardown must keep their normal behaviour, so they are excluded.
         * ⛔ Do NOT "shrink" any image copy to dodge the overlap: the image path does not
         * remap the guest VA at all (it copies into the pool and registers a logical
         * translation), and truncating a genuine image would break relocations. The real
         * defect is that this object was classified as a native image at all — the
         * durable fix is Wine mapping identity / actual view bounds instead of trusting a
         * nearby MZ header's SizeOfImage. */
        if (unix_prot != PROT_NONE)
        {
            extern int ios_jit_anon_alias_find_cover(void *, size_t, void **, void **);
            void *cov_rw = NULL, *cov_rx = NULL;
            if (ios_jit_anon_alias_find_cover( base, size, &cov_rw, &cov_rx ))
            {
                static int own_n;
                if (own_n < 32)
                    dprintf(2, "[alias-own] ml640 #%d %p+0x%lx prot=%c%c%c OWNED by live anon JIT alias "
                               "(rx=%p rw=%p) — keeping the pool dual-map, no mprotect, no image lookup\n",
                            ++own_n, base, (unsigned long)size,
                            (unix_prot & PROT_READ)  ? 'r' : '-',
                            (unix_prot & PROT_WRITE) ? 'w' : '-',
                            (unix_prot & PROT_EXEC)  ? 'x' : '-',
                            cov_rx, cov_rw);
                return 0;
            }
        }

        /* Try normal mprotect first (works on non-TXM devices). On iOS TXM,
         * mprotect with PROT_EXEC may *appear* to succeed (return 0) without
         * actually granting EXEC — pages stay RW only. Verify by querying the
         * actual page protection via Mach vm_region_64; only return early if
         * EXEC was truly granted. */
        if (!mprotect( base, size, unix_prot ))
        {
            mach_vm_address_t addr = (mach_vm_address_t)base;
            mach_vm_size_t reg_size = 0;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj_name = MACH_PORT_NULL;
            kern_return_t qkr = mach_vm_region(mach_task_self(), &addr, &reg_size,
                                               VM_REGION_BASIC_INFO_64,
                                               (vm_region_info_t)&info,
                                               &info_cnt, &obj_name);
            if (qkr == KERN_SUCCESS && (info.protection & VM_PROT_EXECUTE))
            {
                /* ml999: the EXEC check alone is not the whole postcondition.
                 * Astra's rdr67 review: this fast path returns success as soon as
                 * EXEC is present, without requiring that a REQUESTED WRITE
                 * survived -- and iOS never grants W+X, so a request for RWX
                 * comes back RX and is reported as success. FEX's
                 * HandleRWXAccessViolation likewise ignores the
                 * NtProtectVirtualMemory status before reporting "handled", so a
                 * caller that asked for writable backing can be told it got it
                 * and then fault again on the very next store -- the second
                 * retry loop she warned about, after the classification fix
                 * removes the first one.
                 *
                 * Report only; do NOT change the return here. Whether the right
                 * answer is to fail the request, to drop EXEC and keep WRITE
                 * (the ml957 "backing stays non-exec, pool copy keeps X"
                 * policy), or to leave it to the caller depends on who asked,
                 * and that is the next run's discriminator rather than a guess. */
                if ((unix_prot & PROT_WRITE) && !(info.protection & VM_PROT_WRITE))
                {
                    static unsigned wsurv;
                    if (wsurv++ < 16)
                        dprintf( 2, "ml999: mprotect_exec %p+%#lx asked for W+X but only "
                                 "prot=%#x survived -- returning SUCCESS with WRITE DROPPED. "
                                 "A caller expecting writable backing will fault again\n",
                                 base, (unsigned long)size, info.protection );
                }
                return 0;  /* genuinely RX/RWX — done */
            }
            ERR("iOS mprotect(rwx) appeared to succeed but EXEC not actually granted "
                "at %p+0x%lx (qkr=%d prot=0x%x); falling through to JIT-pool path\n",
                base, (unsigned long)size, qkr, qkr == KERN_SUCCESS ? info.protection : -1);
        }

        if (!jit_rx_base || !jit_rw_base)
        {
            ERR("iOS JIT: no pool, cannot make %p+0x%lx executable\n",
                base, (unsigned long)size);
            return mprotect( base, size, unix_prot & ~PROT_EXEC );
        }

        /* Find the PE image base by scanning backward for MZ signature.
         * We need to copy the ENTIRE image (code + data) to preserve
         * ADRP-based PC-relative data references. */
        {
            void *image_base = NULL;
            size_t image_size = 0;
            char *scan = (char *)base;
            int i;
            /* an unmapped copy chosen for an in-place rebuild
             * (ios_image_reload_mode); used by the pool allocation below */
            void *reload_jit = NULL, *reload_pe = NULL;
            size_t reload_size = 0;

            /* Check if this image was already copied to JIT pool */
            for (i = 0; i < ios_jit_mapping_count; i++)
            {
                uintptr_t a = (uintptr_t)base;
                uintptr_t mb = (uintptr_t)ios_jit_mappings[i].pe_base;
                if (a >= mb && a < mb + ios_jit_mappings[i].size)
                {
                    /* ml352: containment alone LIES when the entry is STALE.
                     * rsaenh.dll unloaded, windows.ui.dll later mapped INSIDE
                     * rsaenh's old range; this early-out then skipped
                     * windows.ui's pool copy entirely, and every translate
                     * routed its code into rsaenh's dead copy — whose bytes at
                     * that offset are section padding: ZEROS → udf → dead run
                     * (ml351, and the run-to-run "variance" = VA-recycling
                     * roulette). The add_mapping stale-purge never fires
                     * because this early-out precedes it. Validate the entry:
                     * its pe_base must still hold a PE header whose
                     * SizeOfImage matches the entry. Fault-safe reads — the
                     * stale base may be unmapped. Invalid → skip the entry;
                     * the fresh copy below re-registers and add_mapping's
                     * overlap purge tombstones the stale one. */
                    {
                        unsigned short mz = 0;
                        unsigned int lfanew = 0, imgsz = 0;
                        mach_vm_size_t got = 0;
                        int entry_ok =
                            mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)mb, 2,
                                                   (mach_vm_address_t)&mz, &got) == KERN_SUCCESS &&
                            got == 2 && mz == 0x5A4D &&
                            mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(mb + 0x3c), 4,
                                                   (mach_vm_address_t)&lfanew, &got) == KERN_SUCCESS &&
                            got == 4 && lfanew && lfanew < 0x1000 &&
                            mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(mb + lfanew + 0x50), 4,
                                                   (mach_vm_address_t)&imgsz, &got) == KERN_SUCCESS &&
                            got == 4 &&
                            (imgsz == ios_jit_mappings[i].size ||
                             ((imgsz + 0x3fffu) & ~0x3fffu) == ios_jit_mappings[i].size);
                        if (!entry_ok)
                        {
                            dprintf(2, "[jit-pool] STALE containment rev=ml352: entry pe=%p+0x%lx "
                                    "no longer matches what is mapped there (mz=%04x lfanew=0x%x imgsz=0x%x) "
                                    "— ignoring entry, copying fresh image for %p\n",
                                    (void *)mb, (unsigned long)ios_jit_mappings[i].size,
                                    mz, lfanew, imgsz, base);
                            continue;
                        }
                    }
                    /* The same image mapped again at the base of an UNLOADED
                     * copy (the MZ/SizeOfImage check above cannot tell). That
                     * copy's .data/.bss hold the unloaded module's globals:
                     * rebuild it in place or make a new copy, never adopt it
                     * (ios_image_reload_mode). */
                    if (ios_jit_mappings[i].unmapped)
                    {
                        int mode = ios_image_reload_mode();
                        int same = mode == 1 &&
                                   ios_jit_same_headers( mb, (const unsigned char *)ios_jit_mappings[i].jit_base );
                        int choice = ios_jit_reload_choice( &ios_jit_mappings[i], same, mode );
                        static int reload_n;

                        if (choice && reload_n < 32)
                        {
                            reload_n++;
                            dprintf( 2, "[image-reload] %s %p+0x%lx loaded again at the base of its unloaded "
                                     "pool copy %p (owner=%p, headers %s) -> %s\n",
                                     ios_pe_module_name( (void *)mb, ios_jit_mappings[i].size ), (void *)mb,
                                     (unsigned long)ios_jit_mappings[i].size, ios_jit_mappings[i].jit_base,
                                     ios_jit_mappings[i].owner_peb,
                                     same ? "identical" : mode == 1 ? "differ" : "not compared",
                                     choice == 1 ? "rebuilding that copy in place (fresh .data/.bss)"
                                                 : "new pool copy" );
                        }
                        if (choice == 1)
                        {
                            reload_jit = ios_jit_mappings[i].jit_base;
                            reload_pe = (void *)mb;
                            reload_size = ios_jit_mappings[i].size;
                            break;
                        }
                        if (choice == 2) continue;
                    }
                    ERR("iOS JIT: %p already in mapping %d (%p+0x%lx)\n",
                        base, i, (void*)mb, (unsigned long)ios_jit_mappings[i].size);
                    /* If write was requested (e.g. IAT lives in a section that
                     * the linker also marked EXEC), grant RW on the PE-side
                     * page via Mach vm_protect. The JIT pool already has the
                     * executable copy at the original RX address; we don't
                     * need EXEC here. After writes land, NtProtectVirtualMemory's
                     * IAT-sync handler copies them to the JIT pool. */
                    if (unix_prot & PROT_WRITE)
                    {
                        /* ml958: this early-out is the path a SECOND executable
                         * section of an already-pool-copied image takes, and it
                         * had two defects that together left an RWX section's
                         * backing read-only.
                         *
                         * 1. PAGE ALIGNMENT. `base` is `view + sec->VirtualAddress`,
                         *    and PE section VAs are 4 KB-granular while this device's
                         *    page is 16 KB (vm_page_size). vm_protect requires a
                         *    page-aligned address and refuses an unaligned one
                         *    outright. Measured in rdr22: EMP.dll `.EMP` has
                         *    VirtualAddress 0x31000, so base was 0xa8a1d1000 --
                         *    4 KB-aligned, not 16 KB -- and the backing stayed R--
                         *    over exactly [0xa8a1d4000, 0xa8a204000), i.e. from the
                         *    next 16 KB boundary. Round the range out to whole pages.
                         *
                         * 2. +COPY WAS TRIED FIRST AND ALONE. ml391 established the
                         *    correct ladder for the non-exec write path: plain RW
                         *    first, +COPY only as a fallback, because VM_PROT_COPY
                         *    forcibly privatizes the mapping object and silently
                         *    disconnects a MAP_SHARED section view (writes land in a
                         *    private copy while every other pseudo-process reads the
                         *    original). This path never got that fix. rdr22 measured
                         *    max_prot=0x7 on the target, so plain RW is permitted and
                         *    is the right request.
                         *
                         * Rounding out can widen the grant into a partial page shared
                         * with a neighbouring section -- unavoidable with 16 KB pages
                         * against 4 KB section alignment, and for `.EMP` both
                         * neighbours (`.data2`, `.data3`) are already READ|WRITE. The
                         * alternative is the protect failing entirely, which is what
                         * was happening.
                         *
                         * Diagnostics here are dprintf, not ERR: every message on this
                         * path was an ERR, which MADEIRA_QUIET swallows, so the failure
                         * was invisible in three consecutive runs. */
                        uintptr_t pm    = (uintptr_t)vm_page_mask;
                        vm_address_t ab = (vm_address_t)((uintptr_t)base & ~pm);
                        vm_size_t    as = (vm_size_t)((((uintptr_t)base + size + pm) & ~pm)
                                                      - (uintptr_t)ab);
                        kern_return_t kr  = vm_protect( mach_task_self(), ab, as, FALSE,
                                                        VM_PROT_READ | VM_PROT_WRITE );
                        kern_return_t kr2 = KERN_SUCCESS;
                        static int ml958_n;

                        if (kr != KERN_SUCCESS)
                            kr2 = vm_protect( mach_task_self(), ab, as, FALSE,
                                              VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY );

                        if (ml958_n < 24)
                        {
                            ml958_n++;
                            dprintf( 2, "ml958: %s already-copied section %p+0x%lx (prot=%c%c%c) "
                                     "-> aligned %p+0x%lx: plain RW kr=%d%s -- %s\n",
                                     ios_pe_module_name( base, size ),
                                     base, (unsigned long)size,
                                     (unix_prot & PROT_READ)  ? 'r' : '-',
                                     (unix_prot & PROT_WRITE) ? 'w' : '-',
                                     (unix_prot & PROT_EXEC)  ? 'x' : '-',
                                     (void *)(uintptr_t)ab, (unsigned long)as, kr,
                                     (kr != KERN_SUCCESS) ? (kr2 == KERN_SUCCESS
                                         ? ", +COPY kr=0" : ", +COPY ALSO FAILED") : "",
                                     (kr == KERN_SUCCESS || kr2 == KERN_SUCCESS)
                                         ? "W GRANTED" : "still read-only" );
                        }
                        if (kr == KERN_SUCCESS || kr2 == KERN_SUCCESS) return 0;
                    }
                    mprotect( base, size, PROT_READ );
                    return 0;
                }
            }

            /* Scan backward to find MZ header (PE image start). Bound the
             * scan to a reasonable distance (max 64MB) so anonymous RWX
             * regions don't trigger long backward walks into unmapped memory.
             * Also probe each candidate page via mach_vm_region first to
             * confirm it's mapped before dereferencing. */
            char *scan_limit = (char *)((uintptr_t)base - 0x4000000);  /* 64MB */
            if (scan_limit < (char *)0x10000) scan_limit = (char *)0x10000;
            for (scan = (char *)((uintptr_t)base & ~0x3FFFUL); scan > scan_limit; scan -= 0x4000)
            {
                /* Probe page via mach_vm_region to skip unmapped gaps */
                {
                    mach_vm_address_t qa = (mach_vm_address_t)scan;
                    mach_vm_size_t qs = 0;
                    vm_region_basic_info_data_64_t qinfo;
                    mach_msg_type_number_t qcnt = VM_REGION_BASIC_INFO_COUNT_64;
                    mach_port_t qobj = MACH_PORT_NULL;
                    if (mach_vm_region(mach_task_self(), &qa, &qs,
                                       VM_REGION_BASIC_INFO_64,
                                       (vm_region_info_t)&qinfo, &qcnt, &qobj)
                        != KERN_SUCCESS) break;
                    /* If mach_vm_region returned a region above scan,
                     * scan is unmapped — skip ahead to that region's start. */
                    if ((char *)qa > scan) break;
                    /* Mapped but not readable (PROT_NONE reservation, or
                     * exec-only JIT page): dereferencing faults even though
                     * vm_region reports a region. A PE image is contiguously
                     * readable, so a non-readable page means we've walked
                     * below the image — stop the scan. (Seen 2026-07-03:
                     * X64ReturnInstr's anon-RWX VA sat above a PROT_NONE
                     * Wine reservation; the scan deref'd it, the resulting
                     * UNHANDLED faults derailed the whole redirect.) */
                    if (!(qinfo.protection & VM_PROT_READ)) break;
                }
                if (*(unsigned short *)scan == 0x5A4D)  /* MZ */
                {
                    unsigned int pe_off = *(unsigned int *)(scan + 0x3C);
                    if (pe_off < 0x1000 && *(unsigned int *)(scan + pe_off) == 0x00004550)  /* PE\0\0 */
                    {
                        image_base = scan;
                        /* SizeOfImage is at PE + 0x18 (optional header) + 0x38 (PE32+) */
                        image_size = *(unsigned int *)(scan + pe_off + 0x50);
                        break;
                    }
                }
            }

            /* ml348: the backward scan finds the NEAREST MZ below, which is not
             * necessarily the image this page belongs to. A standalone exec
             * allocation placed just above a module (ml347: a 4KB RWX page at
             * 0x73e30b0000, 0x40000 past advapi32's SizeOfImage end) was
             * attributed to that module, so the module got re-copied while the
             * page itself got neither exec nor a pool alias — left read-only
             * with no alias, every guest store to it faulted forever (STLR
             * w0,[x8], 8+ identical faults, thread dead). Range-check the hit;
             * on failure fall through to the anonymous-RWX path, which carves a
             * pool slot AND registers the alias the store emulator needs. */
            if (image_base &&
                ((uintptr_t)base < (uintptr_t)image_base ||
                 (uintptr_t)base + size > (uintptr_t)image_base + image_size))
            {
                dprintf(2, "[jit-pool] exec page %p+0x%lx is OUTSIDE nearest image %p+0x%lx "
                        "(%s) — treating as anonymous RWX rev=ml348\n",
                        base, (unsigned long)size, image_base, (unsigned long)image_size,
                        ios_pe_module_name(image_base, image_size));

                /* iOS-Madeira ml632: MIXED-MAPPING TRIPWIRE.
                 *
                 * This test is ALL-OR-NOTHING: if the request is not wholly inside the
                 * image it is treated as anonymous in its entirety — even the part that
                 * genuinely overlaps the image. Meanwhile ios_jit_sync_write's IAT sync
                 * accepts SUBRANGES by numerical containment alone, so the overlapping
                 * pages end up owned by BOTH registries.
                 *
                 * ULTRAKILL died on exactly that: anon alias [0x706e9b0000,0x706e9c0000)
                 * vs "image" [0x706e990000,0x706e9b4000) — a 16KB overlap — and
                 * `[iat-sync] region 0x706e9b3000+0x1000: translated 2 pointers` rewrote
                 * the page holding the bad block's entry at +0x33e0. Control then ran off
                 * into zero padding and died 0xc06 bytes later.
                 *
                 * Report the collision with both mappings' real Mach identity, so a
                 * genuine PE mapping can be told from a stale/adjacent MZ hit. */
                {
                    uintptr_t o_lo = (uintptr_t)base > (uintptr_t)image_base
                                   ? (uintptr_t)base : (uintptr_t)image_base;
                    uintptr_t o_hi = ((uintptr_t)base + size) < ((uintptr_t)image_base + image_size)
                                   ? ((uintptr_t)base + size) : ((uintptr_t)image_base + image_size);
                    if (o_lo < o_hi)
                    {
                        static int mixed_n;
                        if (mixed_n < 16)
                        {
                            mach_vm_address_t qa; mach_vm_size_t qs; 
                            vm_region_basic_info_data_64_t qi; mach_msg_type_number_t qc;
                            mach_port_t qo; kern_return_t qk;
                            unsigned rp = 0, ip = 0;
                            qa = (mach_vm_address_t)base; qs = 0; qc = VM_REGION_BASIC_INFO_COUNT_64;
                            qk = mach_vm_region( mach_task_self(), &qa, &qs, VM_REGION_BASIC_INFO_64,
                                                 (vm_region_info_t)&qi, &qc, &qo );
                            if (qk == KERN_SUCCESS) rp = qi.protection;
                            qa = (mach_vm_address_t)image_base; qs = 0; qc = VM_REGION_BASIC_INFO_COUNT_64;
                            qk = mach_vm_region( mach_task_self(), &qa, &qs, VM_REGION_BASIC_INFO_64,
                                                 (vm_region_info_t)&qi, &qc, &qo );
                            if (qk == KERN_SUCCESS) ip = qi.protection;
                            ++mixed_n;
                            dprintf(2, "[mixed-map] ml632 #%d COLLISION: request %p+0x%lx (prot=%u) vs image %p+0x%lx "
                                       "(prot=%u, %s) — OVERLAP [%p,%p) %lu KB claimed by BOTH registries\n",
                                    mixed_n, base, (unsigned long)size, rp,
                                    image_base, (unsigned long)image_size, ip,
                                    ios_pe_module_name(image_base, image_size),
                                    (void *)o_lo, (void *)o_hi, (unsigned long)((o_hi - o_lo) / 1024));
                        }
                    }
                }
                image_base = NULL;
                image_size = 0;
            }

            if (!image_base || !image_size)
            {
                /* iOS-Madeira: anonymous RWX request (e.g. FEX's CodeBuffer
                 * allocates a 16MB PAGE_EXECUTE_READWRITE region for runtime
                 * JIT). No PE header to copy. Strategy: take a slot from the
                 * JIT pool, vm_remap from `jit_rx_base + offset` into the
                 * caller's VA (which gives the caller's pages R+X via the
                 * dual-map), and record a `user_VA -> jit_rw_base + offset`
                 * alias so the STR-fault emulator routes writes through the
                 * RW alias. FEX writes via user_VA fault → emulator routes;
                 * FEX executes via user_VA → R+X works. */
                size_t page_size = 0x4000;
                size_t alloc_size = (size + page_size - 1) & ~(page_size - 1);

                /* iOS-Madeira ml625: NEVER RE-BACK A GUEST VA THAT IS ALREADY LIVE.
                 *
                 * vm_remap below uses VM_FLAGS_OVERWRITE and does NOT preserve the
                 * old contents, so re-running this path on a range that already holds
                 * emitted guest code DESTROYS it. That is exactly how the ml624 run
                 * died: Mono emitted x64 code + UNWIND_INFO into 0x7040220000, then
                 * this path ran three more times for the same VA, each taking a fresh
                 * zeroed 16KB pool slot. FEX kept executing its cached translation of
                 * code that no longer existed, wine read unwind version 0 from the
                 * zeroed metadata, and RtlVirtualUnwind2 spun ~15.8M times until the
                 * 8MB guest stack was exhausted.
                 *
                 * A repeat request is a RE-PROTECT, not a new allocation: keep the
                 * existing backing and just (re)assert R+X. */
                {
                    extern int ios_jit_anon_alias_find_cover(void *, size_t, void **, void **);
                    void *ex_rw = NULL, *ex_rx = NULL;
                    if (ios_jit_anon_alias_find_cover(base, alloc_size, &ex_rw, &ex_rx))
                    {
                        kern_return_t pkr = vm_protect(mach_task_self(),
                            (vm_address_t)base, alloc_size, FALSE,
                            VM_PROT_READ | VM_PROT_EXECUTE);
                        TEB *cur_teb = NtCurrentTeb();

                        /* ml626: OBSERVE the protection state, do NOT try to repair it.
                         *
                         * In the ml625 run the FIRST reuse returned kr=0 and every later
                         * one kr=2 (KERN_PROTECTION_FAILURE) for the same VA, with the
                         * 64KB region split and its first 16KB showing max=3 (RW, no
                         * EXEC) -- vm_protect can never grant EXEC once max has been
                         * lowered, so a "repair" via set_maximum=TRUE would not work
                         * anyway. It is also quite possibly FALLOUT from the failed
                         * SWPAL redelivery loop rather than a cause. Log cur/max so the
                         * next run says which, and change nothing yet. */
                        {
                            static int reuse_prot_n;
                            if (pkr != KERN_SUCCESS || reuse_prot_n < 16)
                            {
                                mach_vm_address_t q = (mach_vm_address_t)base;
                                mach_vm_size_t qsz = 0;
                                vm_region_basic_info_data_64_t qi;
                                mach_msg_type_number_t qc = VM_REGION_BASIC_INFO_COUNT_64;
                                mach_port_t qobj = MACH_PORT_NULL;
                                kern_return_t qkr = mach_vm_region( mach_task_self(), &q, &qsz,
                                        VM_REGION_BASIC_INFO_64, (vm_region_info_t)&qi, &qc, &qobj );
                                ++reuse_prot_n;
                                dprintf(2, "[jit-prot] ml626 #%d %p region=%p+0x%llx cur=%d max=%d "
                                        "(region kr=%d) after vm_protect(R+X) kr=%d\n",
                                        reuse_prot_n, base, (void *)(uintptr_t)q,
                                        (unsigned long long)qsz,
                                        qkr == KERN_SUCCESS ? qi.protection : -1,
                                        qkr == KERN_SUCCESS ? qi.max_protection : -1,
                                        (int)qkr, (int)pkr);
                            }
                        }

                        dprintf(2, "[jit-pool] anon RWX %p size=0x%lx REUSE existing alias "
                                "(rx=%p rw=%p) vm_protect kr=%d tid=%04x peb=%p rev=ml625\n",
                                base, (unsigned long)alloc_size, ex_rx, ex_rw, (int)pkr,
                                cur_teb ? (unsigned)(ULONG_PTR)cur_teb->ClientId.UniqueThread : 0u,
                                cur_teb ? (void *)cur_teb->Peb : NULL);
                        return 0;
                    }
                }

                /* ml630: DO NOT BURN A POOL RANGE WE CANNOT REGISTER.
                 *
                 * The ml629 run consumed three further pool ranges while repeatedly
                 * failing to register the SAME buffer, because the table check lived
                 * downstream of the allocation. Check first; an unregisterable mapping
                 * is worse than a refused one, since writes to it silently do not route. */
                if (ios_jit_anon_alias_count >= IOS_JIT_MAX_ANON_ALIASES)
                {
                    int free_slot = 0, ci;
                    for (ci = 0; ci < ios_jit_anon_alias_count; ci++)
                        if (!ios_jit_anon_aliases[ci].user_va) { free_slot = 1; break; }
                    if (!free_slot)
                    {
                        dprintf(2, "[jit-pool] anon RWX %p REFUSED: alias table full (%d, live=%d hiwater=%d) "
                                   "— refusing the mapping rather than shipping one whose writes cannot route "
                                   "rev=ml630\n",
                                base, IOS_JIT_MAX_ANON_ALIASES, ios_jit_anon_alias_live,
                                ios_jit_anon_alias_hiwater);
                        mprotect( base, size, PROT_READ );
                        errno = ENOMEM;
                        return -1;
                    }
                }

                size_t offset = ios_pool_alloc_range(alloc_size, jit_pool_size - ios_jit_tail_reserved);
                if (offset == (size_t)-1)
                {
                    ERR("iOS JIT: pool exhausted for anon RWX %p+0x%lx\n",
                        base, (unsigned long)size);
                    dprintf(2, "[jit-pool] EXHAUSTED (anon RWX): want=0x%lx bump=0x%lx/0x%lx tail_resv=0x%lx freelist=%d — FAILING allocation\n",
                            (unsigned long)alloc_size, (unsigned long)jit_pool_offset, (unsigned long)jit_pool_size,
                            (unsigned long)ios_jit_tail_reserved, ios_pool_free_count);
                    mprotect( base, size, PROT_READ );
                    errno = ENOMEM;
                    return -1;
                }

                /* iOS-Madeira ml634: PRESERVE THE GUEST'S EXISTING BYTES BEFORE REMAPPING.
                 *
                 * The vm_remap below uses VM_FLAGS_OVERWRITE to put a FRESH, ZERO-FILLED
                 * pool slot on top of `base`. The PE-image path a few hundred lines down
                 * memcpy()s the image into the pool first and invalidates the icache; this
                 * anonymous path never copied anything. So the very FIRST RW->RX transition
                 * of a Mono JIT buffer replaced everything Mono had already emitted with
                 * zeros.
                 *
                 * That explains the whole ULTRAKILL signature: RX and RW MATCH afterwards
                 * (both now view the same erased pool storage), FEX starts translating at
                 * base+0x33e0, sees `00 00` = `add byte [rax], al` all the way, and dies at
                 * +0x4006. ml625 only stopped destructive remapping on SUBSEQUENT
                 * re-protects — it never protected the initial transition.
                 *
                 * ⚠️ The +0x4000 overlap with the "nearest image" is an ACCOUNTING ARTIFACT,
                 * not the edge of real code: that image is a managed assembly Mono mapped as
                 * DATA (mapped size 0x1f000) whose PE header declares SizeOfImage 0x24000,
                 * and the backward MZ scan trusts the declared size. Do not read the
                 * boundary as "generated code ends here". */
                uint64_t ml634_pre_hash = 1469598103934665603ull;
                size_t   ml634_nonzero = 0;
                {
                    char *rw_dst = (char *)jit_rw_base + offset;
                    char *rx_dst = (char *)jit_rx_base + offset;
                    const unsigned char *src = (const unsigned char *)base;
                    size_t i;

                    for (i = 0; i < size; i++)
                    {
                        ml634_pre_hash = (ml634_pre_hash ^ src[i]) * 1099511628211ull;
                        if (src[i]) ml634_nonzero++;
                    }

                    memset( rw_dst, 0, alloc_size );
                    memcpy( rw_dst, src, size );
                    sys_icache_invalidate( rx_dst, alloc_size );

                    {
                        static int pre_n;
                        if (ml634_nonzero || pre_n < 24)   /* ml635: nonzero is ALWAYS reported */
                            dprintf(2, "[jit-copy] ml634 #%d PRE-REMAP %p+0x%lx: %lu/%lu bytes nonzero, fnv=%016llx "
                                       "— copied into pool off=0x%lx\n",
                                    ++pre_n, base, (unsigned long)size,
                                    (unsigned long)ml634_nonzero, (unsigned long)size,
                                    (unsigned long long)ml634_pre_hash, (unsigned long)offset);
                    }
                }

                vm_address_t target = (vm_address_t)base;
                vm_prot_t cur_prot = 0, max_prot = 0;
                kern_return_t kr = vm_remap(mach_task_self(),
                    &target, alloc_size, 0,
                    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                    mach_task_self(),
                    (vm_address_t)((char *)jit_rx_base + offset),
                    FALSE,
                    &cur_prot, &max_prot,
                    VM_INHERIT_DEFAULT);
                if (kr != KERN_SUCCESS)
                {
                    ERR("iOS JIT: anon RWX vm_remap failed kr=%d %p+0x%lx\n",
                        kr, base, (unsigned long)alloc_size);
                    mprotect( base, size, PROT_READ );
                    return 0;
                }

                /* iOS needs an explicit vm_protect to activate EXEC on the
                 * remapped pages — vm_remap reports cur_prot=R+X in its output
                 * but the kernel doesn't actually grant exec permission until
                 * we explicitly request it. */
                {
                    kern_return_t pkr = vm_protect(mach_task_self(),
                        (vm_address_t)base, alloc_size, FALSE,
                        VM_PROT_READ | VM_PROT_EXECUTE);
                    if (pkr != KERN_SUCCESS)
                    {
                        ERR("iOS JIT: anon RWX vm_protect(R+X) failed kr=%d %p+0x%lx\n",
                            pkr, base, (unsigned long)alloc_size);
                    }
                }

                /* Mark the JIT-pool slot as ARM64EC code so arm64x_check_call
                 * routes correctly (FEX-emitted code is treated as EC for
                 * dispatcher purposes). */
                if (arm64ec_view)
                {
                    char *jit_base = (char *)jit_rx_base + offset;
                    /* iOS-Madeira: 4KB-page indexing per arm64x_check_call ABI */
                    size_t bm_start = ((size_t)jit_base >> 12) / 8;
                    size_t bm_end   = (((size_t)jit_base + alloc_size) >> 12) / 8;
                    size_t bm_size  = ROUND_SIZE(bm_start, bm_end + 1 - bm_start, page_mask);
                    void *bm_page   = ROUND_ADDR((char *)arm64ec_view->base + bm_start, page_mask);
                    set_vprot(arm64ec_view, bm_page, bm_size,
                              VPROT_READ | VPROT_WRITE | VPROT_COMMITTED);
                    set_arm64ec_range(jit_base, alloc_size);
                }

                /* ml634: both views must now hash to what the guest had before the remap. */
                {
                    static int post_n;
                    if (post_n < 24)
                    {
                        const unsigned char *rxv = (const unsigned char *)base;
                        const unsigned char *rwv = (const unsigned char *)((char *)jit_rw_base + offset);
                        uint64_t hx = 1469598103934665603ull, hw = 1469598103934665603ull;
                        size_t i;
                        for (i = 0; i < size; i++)
                        {
                            hx = (hx ^ rxv[i]) * 1099511628211ull;
                            hw = (hw ^ rwv[i]) * 1099511628211ull;
                        }
                        ++post_n;
                        dprintf(2, "[jit-copy] ml634 #%d POST-REMAP rx=%016llx rw=%016llx pre=%016llx => %s\n",
                                post_n, (unsigned long long)hx, (unsigned long long)hw,
                                (unsigned long long)ml634_pre_hash,
                                (hx == ml634_pre_hash && hw == ml634_pre_hash)
                                    ? "PRESERVED"
                                    : "**CONTENT LOST** — the remap still erased the guest's bytes");
                    }
                }

                /* Record secondary alias for STR fault emulator and exec PC redirect. */
                extern int ios_jit_anon_alias_add(void *user_va, size_t size,
                                                  void *jit_rw_alias);
                extern void ios_jit_anon_alias_set_rx(void *user_va, void *jit_rx_alias);
                if (!ios_jit_anon_alias_add(base, alloc_size, (char *)jit_rw_base + offset))
                {
                    /* ml630: lost a race for the last slot. The remap already happened,
                     * so the honest move is to fail loudly here rather than return an
                     * executable mapping whose writes will not route. */
                    dprintf(2, "[jit-pool] anon RWX %p FAILED to register alias after remap "
                               "(pool off=0x%lx) — failing the request rev=ml630\n",
                            base, (unsigned long)offset);
                    mprotect( base, size, PROT_READ );
                    errno = ENOMEM;
                    return -1;
                }
                ios_jit_anon_alias_set_rx(base, (char *)jit_rx_base + offset);

                ERR("iOS JIT: anon RWX %p+0x%lx → pool offset 0x%lx (rx=%p rw=%p)"
                    " cur_prot=0x%x max_prot=0x%x\n",
                    base, (unsigned long)alloc_size, (unsigned long)offset,
                    (char *)jit_rx_base + offset, (char *)jit_rw_base + offset,
                    cur_prot, max_prot);
                {
                    TEB *cur_teb = NtCurrentTeb();
                    dprintf(2, "[jit-pool] anon RWX %p size=0x%lx → used=0x%lx/0x%lx NEW off=0x%lx tid=%04x peb=%p rev=ml625\n",
                            base, (unsigned long)alloc_size,
                            (unsigned long)(offset + alloc_size), (unsigned long)jit_pool_size,
                            (unsigned long)offset,
                            cur_teb ? (unsigned)(ULONG_PTR)cur_teb->ClientId.UniqueThread : 0u,
                            cur_teb ? (void *)cur_teb->Peb : NULL);
                }
                return 0;
            }

            /* madeira-bcd: a resource-only view (ios_map_resource_view) never
             * runs code: no pool copy, refused like a Social Club image below. */
            if (ios_map_resource_view)
            {
                static int resource_view_n;
                if (resource_view_n++ < 16)
                    dprintf(2, "[resource-map] %s %p+0x%lx mapped without a pool copy (no loader name, no "
                            "execute access: a version / resource query; env.MADEIRA_RESOURCE_MAP_COPY=1 copies)\n",
                            ios_pe_module_name( image_base, image_size ), image_base, (unsigned long)image_size);
                ios_jit_copy_refused = 2;
                mprotect( base, size, PROT_READ );
                errno = ENOMEM;
                return -1;
            }

            /* madeira-bcd: a Social Club client's libcef.dll and DLSS runtimes
             * get no pool copy (see ios_sc_cef_refuse): refused like an
             * exhausted pool, below. */
            const char *sc_mod = ios_pe_module_name( image_base, image_size );
            if (ios_sc_cef_enabled() && ios_sc_refused_name( sc_mod ) &&
                ios_sc_cef_refuse( sc_mod, 1, ios_sc_current_is_helper(), ios_sc_current_has_socialclub(),
                                   ios_sc_game_cef() ))
            {
                static int sc_refused_n;
                if (sc_refused_n++ < 8)
                    dprintf(2, "[sc-cef] %s %p+0x%lx refused in a Social Club client (peb=%p, not "
                            "SocialClubHelper.exe): %s, so the %lu MB of JIT pool stay free for Social Club's "
                            "Chromium in SocialClubHelper.exe -- the load fails as it did when the pool was "
                            "exhausted (env.MADEIRA_SC_CEF=0 loads it)\n",
                            sc_mod, image_base, (unsigned long)image_size, ios_jit_current_peb(),
                            ios_sc_name_is( sc_mod, "libcef.dll" ) ? "Chromium runs in the helper"
                                                                   : "DLSS needs NVIDIA's driver, not Metal",
                            (unsigned long)(image_size >> 20));
                ios_jit_copy_refused = 2;
                mprotect( base, size, PROT_READ );
                errno = ENOMEM;
                return -1;
            }

            /* ml457 REVERTED (ml458) — DO NOT RE-ATTEMPT skipping pool copies
             * for pure-x64 images.  The premise ("x64 runs only through FEX, so
             * its pool copy is never entered") is FALSE: x64 guest RIPs ARE
             * pool-copy aliases.  FEX decodes and dispatches x64 code at POOL
             * addresses — see [pool-rip-fix] (FEXCore Core.cpp), [exc-pool-rip]
             * (ARM64EC Module.cpp), and task #52's CompileBlock reverse-translate.
             * Removing the copy removes the execution substrate: ml457 (db 5840)
             * skipped steamexe.exe 38× and steam.exe died in seconds calling a
             * garbage target (pc=0, guest RIP=0x69) out of vstdlib's .fptable
             * indirection.  The 369MB of x64 copies is REAL cost, not waste.
             * Budget must come from elsewhere (dedup of duplicate EC copies,
             * CodeBuffer generation cap, or making the pool no-footprint so it
             * can grow past the jetsam-bound 896MB). */

            /* Align to 16KB page boundary.
             * task #34 .text sharing: fold the x18 trampoline region into
             * the image's own allocation at a FIXED image-relative offset
             * (right after the aligned image). Every copy of the same DLL
             * then patches identical PC-relative branches → patched .text
             * and tramps are byte-identical across copies (precondition for
             * page sharing). Also kills the 80MB-anchor dance: worst-case
             * text→tramp distance is now ≤ image size, far under ±128MB. */
            size_t page_size = 0x4000;
            size_t image_alloc = (image_size + page_size - 1) & ~(page_size - 1);
            size_t tramp_prealloc = ios_x18_tramp_prealloc_scan(image_base, image_size);
            size_t data_delta = ios_jit_data_align_delta(image_base, image_size);
            size_t alloc_size = image_alloc + tramp_prealloc + (data_delta ? page_size : 0);
            size_t offset;
            /* ios_image_reload_mode: the same image again at the base of its
             * unloaded copy -> rebuild that copy where it is. Its pool range
             * (already shifted by data_delta, x18 tramps right behind the
             * image) stays in this process's ledger, so nothing is allocated;
             * the copy below rewrites it from the new view (fresh .data/.bss),
             * redoes relocations and x18 patches (identical bytes for
             * identical code), and add_mapping re-registers the same jit
             * base, which the emulator sees as already known. */
            if (reload_jit && reload_pe == image_base && reload_size == image_size &&
                ios_pool_ledger_holds( (size_t)((char *)reload_jit - (char *)jit_rx_base),
                                       image_alloc + tramp_prealloc, ios_jit_current_peb() ))
            {
                offset = (size_t)((char *)reload_jit - (char *)jit_rx_base);
                ios_pool_last_alloc_reused = 0;
                dprintf(2, "[image-reload] %s rebuilt in place: pool %p (offset 0x%lx, size 0x%lx)\n",
                        ios_pe_module_name( image_base, image_size ), reload_jit,
                        (unsigned long)offset, (unsigned long)image_size);
            }
            else
            {
                if (reload_jit)
                    dprintf(2, "[image-reload] in-place rebuild dropped: image %p+0x%lx vs the "
                            "unloaded copy's %p+0x%lx, or its pool range is not this process's "
                            "ledger record of 0x%lx bytes -- new pool copy\n", image_base,
                            (unsigned long)image_size, reload_pe, (unsigned long)reload_size,
                            (unsigned long)(image_alloc + tramp_prealloc));
                reload_jit = NULL;
                offset = ios_pool_alloc_range_tagged(alloc_size, jit_pool_size - ios_jit_tail_reserved,
                                                     ios_pool_image_tag( image_base, image_size, alloc_size ));
                if (offset == (size_t)-1) offset = ios_pool_low_image_range( alloc_size );
                if (offset == (size_t)-1 && ios_pool_recycle_code_range( alloc_size ))
                    offset = ios_pool_alloc_range(alloc_size, jit_pool_size - ios_jit_tail_reserved);
            }
            if (!reload_jit && offset != (size_t)-1 && data_delta)
            {
                offset += data_delta;
                dprintf(2, "[data-align] %s shifted +0x%lx so .data lands on a 16KB page\n",
                        ios_pe_module_name( image_base, image_size ), (unsigned long)data_delta);
            }

            if (offset == (size_t)-1)
            {
                ios_pool_failure_census( alloc_size );
                ERR("iOS JIT: pool exhausted\n");
                /* Task #25: FAIL the protect instead of silently leaving the
                 * image R-only — the old path returned success and the first
                 * call into the module BUS-fault-looped, locking the whole
                 * session. -1/ENOMEM propagates up as a failed module load /
                 * failed process start, which the shell reports and survives. */
                dprintf(2, "[jit-pool] EXHAUSTED (image %p+0x%lx): want=0x%lx bump=0x%lx/0x%lx tail_resv=0x%lx freelist=%d — FAILING the load (was: silent BUS loop)\n",
                        image_base, (unsigned long)image_size, (unsigned long)alloc_size,
                        (unsigned long)jit_pool_offset, (unsigned long)jit_pool_size,
                        (unsigned long)ios_jit_tail_reserved, ios_pool_free_count);
                ios_jit_copy_refused = 1;   /* map_image_into_view fails the load */
                mprotect( base, size, PROT_READ );
                errno = ENOMEM;
                return -1;
            }

            /* Copy ENTIRE PE image to JIT pool (code + data + headers).
             * This preserves ADRP-based PC-relative references between sections. */
            ios_jit_scan_nonexec( "pre-memcpy", ios_pe_module_name( image_base, image_size ),
                                  (char *)jit_rx_base + offset, image_size );
            memcpy((char *)jit_rw_base + offset, image_base, image_size);
            ios_jit_scan_nonexec( "post-memcpy", ios_pe_module_name( image_base, image_size ),
                                  (char *)jit_rx_base + offset, image_size );
            sys_icache_invalidate((char *)jit_rx_base + offset, image_size);
            ios_jit_scan_nonexec( "post-icache", ios_pe_module_name( image_base, image_size ),
                                  (char *)jit_rx_base + offset, image_size );
            ios_jit_verify_copy( (const char *)image_base,
                                 (const char *)jit_rx_base + offset,
                                 image_size, ios_pe_module_name( image_base, image_size ),
                                 offset, ios_pool_last_alloc_reused );

            /* Record mapping for the entire image */
            ios_jit_add_mapping(image_base, (char *)jit_rx_base + offset, image_size);

            int image_in_low = ios_jit_low_contains( (uintptr_t)jit_rx_base + offset );
            size_t image_used = image_in_low ? ios_jit_low_reserved : offset + alloc_size;
            size_t image_budget = image_in_low ? ios_jit_low_size_global : jit_pool_size;

            ERR("iOS JIT: copied image %p+0x%lx → pool %p (offset 0x%lx, used 0x%lx/0x%lx)\n",
                image_base, (unsigned long)image_size, (char *)jit_rx_base + offset,
                (unsigned long)offset,
                (unsigned long)image_used, (unsigned long)image_budget);
            /* ml670: PHASE trigger for the fast sampler. ml668 only sped up
             * once a sample READ >=2800MB, which is unreachable here -- the last
             * observed value was 2481MB and the burst reached jetsam inside one
             * 2s window, so fast mode never engaged and we still have no real
             * terminal peak. Texture upload begins right after d3d11 loads, so
             * switch on the phase instead of on a level. */
            {
                const char *mn = ios_pe_module_name( image_base, image_size );
                if (mn && (strstr(mn, "d3d11") || strstr(mn, "D3D11")))
                    ios_fast_footprint = 1;
            }
            dprintf(2, "[jit-pool] image %p+0x%lx (%s) → pool %p used=0x%lx/0x%lx tramp+0x%lx%s\n",
                    image_base, (unsigned long)image_size,
                    ios_pe_module_name( image_base, image_size ), (char *)jit_rx_base + offset,
                    (unsigned long)image_used, (unsigned long)image_budget,
                    (unsigned long)tramp_prealloc, image_in_low ? " [pool-low] region C" : "");

            ios_jit_verify_text_exec( ios_pe_module_name( image_base, image_size ),
                                      (char *)jit_rx_base + offset, image_size );

            /* task #34 [share-probe]: DEFAULT-OFF (set MADEIRA_SHARE_PROBE=1).
             * ml79: running it inline here (pre-detach, on explorer's boot
             * thread) wedged the session — exec-at-alias hangs while the
             * debugger is attached. Gated + deferred to a scratch thread
             * that waits for CS_DEBUGGED to clear before probing. */
            {
                static int ios_share_probed;
                if (!ios_share_probed && getenv("MADEIRA_SHARE_PROBE"))
                {
                    pthread_t pt;
                    ios_share_probed = 1;
                    if (!pthread_create(&pt, NULL, ios_share_probe_thread, NULL))
                        pthread_detach(pt);
                }
            }

            /* Mark the JIT-pool range as ARM64EC code in the EcCodeBitMap —
             * but ONLY for ARM64EC hybrid PEs. ARM64EC binaries have
             * Machine=0x8664 (per Microsoft's ABI) just like pure x86_64,
             * so we can't distinguish via Machine. Use the presence of a
             * `.hexpthk` section as the discriminator (only ARM64EC PEs
             * have it). Pure x86_64 PEs (e.g. hello-x64.exe) must NOT be
             * marked EC because arm64x_check_call would then dispatch BL
             * directly into the JIT-pool copy of x86_64 instructions
             * (executed as ARM64 → garbage). Pure x86_64 entries fall
             * through to the dispatch_call_no_redirect path → xtajit64. */
            int is_arm64ec_hybrid = 0;
            {
                unsigned int pe_o = *(unsigned int *)((char *)jit_rw_base + offset + 0x3C);
                unsigned short num_s = *(unsigned short *)((char *)jit_rw_base + offset + pe_o + 6);
                unsigned short opt_s = *(unsigned short *)((char *)jit_rw_base + offset + pe_o + 0x14);
                char *sec = (char *)jit_rw_base + offset + pe_o + 0x18 + opt_s;
                int j;
                for (j = 0; j < num_s; j++, sec += 40)
                {
                    if (sec[0] == '.' && sec[1] == 'h' && sec[2] == 'e' && sec[3] == 'x' &&
                        sec[4] == 'p' && sec[5] == 't' && sec[6] == 'h' && sec[7] == 'k')
                    {
                        is_arm64ec_hybrid = 1;
                        break;
                    }
                }
            }
            if (arm64ec_view && is_arm64ec_hybrid)
            {
                char *jit_base = (char *)jit_rx_base + offset;
                char *rw_image = (char *)jit_rw_base + offset;
                /* iOS-Madeira: arm64x_check_call uses 4KB-page indexing always.
                 * Compute bitmap byte offsets with 12-bit shift so committed
                 * pages cover where set_arm64ec_range will write. */
                size_t bm_start = ((size_t)jit_base >> 12) / 8;
                size_t bm_end   = (((size_t)jit_base + image_size) >> 12) / 8;
                size_t bm_size  = ROUND_SIZE(bm_start, bm_end + 1 - bm_start, page_mask);
                void *bm_page   = ROUND_ADDR((char *)arm64ec_view->base + bm_start, page_mask);
                set_vprot(arm64ec_view, bm_page, bm_size,
                          VPROT_READ | VPROT_WRITE | VPROT_COMMITTED);
                /* CRITICAL FIX: ARM64EC PEs (ntdll, kernel32, ucrtbase, etc.)
                 * have INTERMIXED ARM64EC code AND x86_64 syscall stubs in
                 * their .text section. The IMAGE_ARM64EC_METADATA::CodeMap
                 * tells us which RVA ranges are which (StartOffset low 2 bits:
                 * 0=ARM64, 1=ARM64EC, 2=x86_64). Marking the entire image as
                 * EC causes arm64x_check_call to think x86_64 stubs are EC,
                 * which makes hybpatch thunks BR x11 directly into x86_64
                 * bytes (executed as ARM64 → garbage targets). */
                {
                    /* Parse the load config to find CHPEMetadataPointer */
                    unsigned int pe_o = *(unsigned int *)(rw_image + 0x3C);
                    unsigned short opt_s = *(unsigned short *)(rw_image + pe_o + 0x14);
                    char *opt_hdr = rw_image + pe_o + 0x18;
                    /* DataDirectories start at opt_hdr + 0x70 (PE32+) */
                    /* IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10, offset 10*8=0x50 from data dirs */
                    unsigned int load_cfg_rva = *(unsigned int *)(opt_hdr + 0x70 + 10*8);
                    unsigned int load_cfg_size = *(unsigned int *)(opt_hdr + 0x70 + 10*8 + 4);
                    int found_codemap = 0;
                    ERR("iOS JIT: load_cfg rva=0x%x size=0x%x\n", load_cfg_rva, load_cfg_size);
                    if (load_cfg_rva && load_cfg_size > 0xD0)
                    {
                        char *load_cfg = rw_image + load_cfg_rva;
                        /* CHPEMetadataPointer is at offset 0xC8 in IMAGE_LOAD_CONFIG_DIRECTORY64 */
                        uint64_t chpe_meta_va = *(uint64_t *)(load_cfg + 0xC8);
                        ERR("iOS JIT: chpe_meta_va=0x%llx pe_image_base=0x%llx\n",
                            (unsigned long long)chpe_meta_va,
                            (unsigned long long)*(uint64_t *)(opt_hdr + 0x18));
                        uint64_t pe_image_base = *(uint64_t *)(opt_hdr + 0x18);
                        if (chpe_meta_va && chpe_meta_va >= pe_image_base &&
                            chpe_meta_va < pe_image_base + image_size)
                        {
                            uint64_t chpe_meta_rva = chpe_meta_va - pe_image_base;
                            char *meta = rw_image + chpe_meta_rva;
                            /* IMAGE_ARM64EC_METADATA: CodeMap RVA at +0x4, CodeMapCount at +0x8 */
                            unsigned int code_map_rva = *(unsigned int *)(meta + 0x4);
                            unsigned int code_map_count = *(unsigned int *)(meta + 0x8);
                            if (code_map_rva && code_map_count)
                            {
                                /* IMAGE_CHPE_RANGE_ENTRY: 8 bytes each (StartOffset 32-bit, Length 32-bit) */
                                char *code_map = rw_image + code_map_rva;
                                int ec_count = 0, x64_count = 0, arm_count = 0;
                                for (unsigned int i = 0; i < code_map_count; i++)
                                {
                                    unsigned int start = *(unsigned int *)(code_map + i*8);
                                    unsigned int len   = *(unsigned int *)(code_map + i*8 + 4);
                                    int range_type = start & 0x3;
                                    unsigned int rva = start & ~0x3u;
                                    if (range_type == 1) /* ARM64EC */
                                    {
                                        set_arm64ec_range(jit_base + rva, len);
                                        ec_count++;
                                    }
                                    else if (range_type == 2) x64_count++;
                                    else if (range_type == 0) arm_count++;
                                }
                                ERR("iOS JIT: CodeMap parsed: %d ARM64EC ranges, %d x86_64, %d ARM64 entries (total %u)\n",
                                    ec_count, x64_count, arm_count, code_map_count);
                                found_codemap = 1;
                            }
                        }
                    }
                    if (!found_codemap)
                    {
                        /* Fallback: mark whole image as EC (old behavior, may misclassify x64 stubs) */
                        ERR("iOS JIT: no CodeMap found — falling back to coarse-mark whole image\n");
                        set_arm64ec_range(jit_base, image_size);
                    }
                }
                {
                    /* iOS-Madeira dual-map RX-side verification.
                     * Read the first 4 bytes of .text via RX alias and compare
                     * to the same offset via RW alias (which we just memcpy'd
                     * to). If they differ, the dual-map isn't aliased correctly
                     * for this page and FEX/Wine will fetch garbage on BL. */
                    if (image_size > 0x4000)
                    {
                        volatile uint32_t rx_byte0 = *(volatile uint32_t *)((char *)jit_rx_base + offset + 0x4000);
                        uint32_t rw_byte0 = *(uint32_t *)((char *)jit_rw_base + offset + 0x4000);
                        ERR("iOS JIT: dual-map RX[+0x4000]=0x%08x  RW[+0x4000]=0x%08x  match=%d\n",
                            rx_byte0, rw_byte0, rx_byte0 == rw_byte0);
                        /* Also probe a deeper offset (around middle of image) */
                        size_t deep = (image_size / 2) & ~3UL;
                        volatile uint32_t rx_mid = *(volatile uint32_t *)((char *)jit_rx_base + offset + deep);
                        uint32_t rw_mid = *(uint32_t *)((char *)jit_rw_base + offset + deep);
                        ERR("iOS JIT: dual-map RX[+0x%lx]=0x%08x  RW[+0x%lx]=0x%08x  match=%d\n",
                            (unsigned long)deep, rx_mid,
                            (unsigned long)deep, rw_mid, rx_mid == rw_mid);
                    }
                }
                {
                    /* Verify start, middle, and end words */
                    UINT64 *vmap = (UINT64 *)arm64ec_view->base;
                    size_t s_idx = ((size_t)jit_base) >> 12;
                    size_t e_idx = ((size_t)jit_base + image_size - 1) >> 12;
                    size_t m_idx = (s_idx + e_idx) / 2;
                    UINT64 sw = vmap[s_idx / 64], mw = vmap[m_idx / 64], ew = vmap[e_idx / 64];
                    ERR("iOS JIT: set_arm64ec_range(jit %p+0x%lx) hybrid bm=%p+0x%lx | start_pos=0x%lx word=0x%llx bit%d=%d | mid_pos=0x%lx word=0x%llx bit%d=%d | end_pos=0x%lx word=0x%llx bit%d=%d\n",
                        jit_base, (unsigned long)image_size, bm_page, (unsigned long)bm_size,
                        (unsigned long)(s_idx/64), (unsigned long long)sw, (int)(s_idx&63), (int)((sw>>(s_idx&63))&1),
                        (unsigned long)(m_idx/64), (unsigned long long)mw, (int)(m_idx&63), (int)((mw>>(m_idx&63))&1),
                        (unsigned long)(e_idx/64), (unsigned long long)ew, (int)(e_idx&63), (int)((ew>>(e_idx&63))&1));
                }
            }
            else
            {
                ERR("iOS JIT: NOT marking jit %p+0x%lx as EC (no .hexpthk section, pure x86_64)\n",
                    (char *)jit_rx_base + offset, (unsigned long)image_size);
            }

            /* Make data sections in JIT pool writable by remapping from RW view.
             * Parse PE section headers to find non-executable sections. */
            {
                unsigned int pe_off = *(unsigned int *)((char *)jit_rw_base + offset + 0x3C);
                unsigned short num_sections = *(unsigned short *)((char *)jit_rw_base + offset + pe_off + 6);
                unsigned short opt_hdr_size = *(unsigned short *)((char *)jit_rw_base + offset + pe_off + 0x14);
                char *section_hdr = (char *)jit_rw_base + offset + pe_off + 0x18 + opt_hdr_size;

                ERR("iOS JIT:   PE sections: %d, opt_hdr_size=0x%x\n", num_sections, opt_hdr_size);
                for (i = 0; i < num_sections; i++, section_hdr += 40)
                {
                    unsigned int sec_chars = *(unsigned int *)(section_hdr + 36);
                    unsigned int sec_rva = *(unsigned int *)(section_hdr + 12);
                    unsigned int sec_vsize = *(unsigned int *)(section_hdr + 8);

                    ERR("iOS JIT:   [%d] %.8s RVA=0x%x sz=0x%x chars=0x%x\n",
                        i, section_hdr, sec_rva, sec_vsize, sec_chars);

                    /* Track executable (.text) section for IAT sync protection */
                    if (sec_chars & 0x20000000)  /* IMAGE_SCN_MEM_EXECUTE */
                    {
                        ios_jit_set_text_section(image_base, sec_rva, sec_vsize);
                        ERR("iOS JIT:   recorded .text: offset=0x%x size=0x%x\n", sec_rva, sec_vsize);
                        continue;
                    }
                    if (!sec_vsize) continue;

                    /* Only writable sections (.data) need protection changes.
                     * Read-only sections (.rdata, .pdata, etc.) are fine as-is. */
                    if (sec_chars & 0x80000000)  /* IMAGE_SCN_MEM_WRITE */
                    {
                        /* ml140 TASK #34 ROOT CAUSE — THE ONE-PAGE .text KILLER.
                         *
                         * This rounded the writable section's start DOWN to a
                         * page boundary, so when a .data section begins partway
                         * into a page that also holds the TAIL OF .text, the
                         * mprotect below stripped EXECUTE from a page of live
                         * code. [copy-verify] caught it at birth in 7 modules at
                         * once — always exactly one page (two for chromehtml,
                         * where the 64KB round-down spans several 16KB pages),
                         * always at a 64KB-aligned offset, which is precisely
                         * what (sec_rva & ~(page_size-1)) produces.
                         *
                         * That is the whole of #34: the page is not reclaimed
                         * and not overwritten, it is mprotect'ed non-executable
                         * by US at copy time, and it only kills the process when
                         * execution finally reaches that part of .text — which
                         * is why CEF dies at libarm64ecfex+0xd06d0 while Thumper,
                         * which never calls those emitters, runs clean. It also
                         * explains max_prot=0x3: mprotect drops EXECUTE from
                         * max_protection on blessed memory permanently, so no
                         * later mprotect/read-touch could ever restore it.
                         *
                         * Round the writable range UP instead: never touch the
                         * page shared with preceding code. Writes landing in
                         * that shared page fall to the SIGBUS emulation path the
                         * failure branch below already relies on. */
                        /* ml141 REVERTED to the round-DOWN. Skipping the shared
                         * page (round-UP) removed every BORN NON-EXEC page, but
                         * traded an exec fault for an immediate STORE fault:
                         * steam.exe died after 61 unix calls with
                         *   BUS: unhandled store insn=0x880a7d09 (STXR)
                         * A .data write landing in the .text-shared page now hits
                         * a read-only page, and the SIGBUS store emulator does
                         * NOT cover store-exclusive — see
                         * reference_str_emulator_state.md. Losing the write is
                         * far worse than losing the exec: writes there are common
                         * and immediate, executing that .text tail is rare.
                         *
                         * The correct fix is to remove the SHARING, not to pick a
                         * loser: PE sections are 4KB-aligned while iOS pages are
                         * 16KB, so a .data section can always land mid-page on
                         * .text. Choose each image's pool offset so its first
                         * writable section starts on a 16KB boundary — everything
                         * before it is RX, so misaligning .text costs nothing. */
                        /* ml142: round the ABSOLUTE address, not the RVA. The
                         * ml141 data-align shift makes `offset` non-page-aligned
                         * (steamexe +0x2000, libarm64ecfex +0x3000), so
                         * base+offset+(rva & ~mask) is no longer page-aligned and
                         * mprotect rejects it — .data stayed read-only and the
                         * first STXR killed the process at 68 unix calls. With
                         * the shift in place .data IS absolutely page-aligned, so
                         * rounding the absolute address is exact: target lands on
                         * .data's first byte and no .text page is ever included. */
                        uintptr_t sec_abs = (uintptr_t)((char *)jit_rx_base + offset + sec_rva);
                        uintptr_t sec_abs_end = (sec_abs + sec_vsize + page_size - 1) & ~(page_size - 1);
                        void *target = (void *)(sec_abs & ~(uintptr_t)(page_size - 1));
                        size_t sec_page_size;
                        /* ml1351: NEVER PROTECT POOL PAGES BEYOND THIS COPY (port of the
                         * pre-reset ml1970 guard).
                         *
                         * A manually mapped image (a DRM loader's in-memory DLL, not a
                         * loader-mapped file) can declare a writable section that runs
                         * past the memory its mapper allocated -- and so past the
                         * image_size bytes copied here. The RW mprotect below then
                         * reached the NEXT pool pages. On blessed pool memory that drops
                         * EXECUTE from max_protection for good (ml140), so every later
                         * hand-out there was born non-executable: device logs 80-83 show
                         * [pool-poison] starting exactly at such an image's allocation
                         * end, after which every process started later in the session
                         * (the in-session launcher's services.exe and steam.exe) faulted
                         * at its ntdll copy's first instruction. Clamp to the pages this
                         * copy owns. MADEIRA_POOL_SECTION_CLAMP=0 restores the unclamped
                         * range. */
                        {
                            static int clamp = -1;
                            uintptr_t limit = ((uintptr_t)((char *)jit_rx_base + offset + image_size)
                                               + page_size - 1) & ~(uintptr_t)(page_size - 1);
                            if (clamp < 0)
                            {
                                const char *e = getenv( "MADEIRA_POOL_SECTION_CLAMP" );
                                clamp = !(e && e[0] == '0');
                            }
                            if (clamp && sec_abs_end > limit)
                            {
                                static unsigned int n_clamped;
                                if (++n_clamped <= 16)
                                    dprintf( 2, "[pool-guard] ml1351 %s section rva=0x%x vsize=0x%x runs past "
                                             "the 0x%lx-byte pool copy: RW limited to the copy's own pages\n",
                                             ios_pe_module_name( image_base, image_size ), sec_rva, sec_vsize,
                                             (unsigned long)image_size );
                                sec_abs_end = limit;
                            }
                            if (sec_abs_end <= (uintptr_t)target) continue;
                        }
                        sec_page_size = sec_abs_end - (uintptr_t)target;

                        /* Try mprotect to make data section writable (drops execute) */
                        if (mprotect(target, sec_page_size, PROT_READ | PROT_WRITE) == 0)
                        {
                            ERR("iOS JIT:     → mprotect RW at %p (0x%lx bytes) OK\n",
                                target, (unsigned long)sec_page_size);
                        }
                        else
                        {
                            ERR("iOS JIT:     → mprotect RW FAILED errno=%d (%s), writes handled via SIGBUS emulation\n",
                                errno, strerror(errno));
                        }
                    }
                }

                /* Apply DIR64 relocations to JIT pool copy.
                 * The unix-side mapping has UNRELOCATED data (still at PE ImageBase).
                 * Wine only relocates the NT-side (PE) view via map_image_into_view,
                 * but the unix-side view keeps original values.
                 * delta = jit_dest - PE_ImageBase */
                {
                    char *rw_image = (char *)jit_rw_base + offset;
                    uint64_t pe_image_base = *(uint64_t *)(rw_image + pe_off + 0x30);
                    intptr_t delta = (intptr_t)((char *)jit_rx_base + offset) - (intptr_t)pe_image_base;

                    ERR("iOS JIT:   PE ImageBase=0x%llx, unix_base=%p, jit_dest=%p, delta=0x%lx\n",
                        (unsigned long long)pe_image_base, image_base, (char *)jit_rx_base + offset, (long)delta);

                    unsigned int reloc_rva = *(unsigned int *)(rw_image + pe_off + 0xB0);
                    unsigned int reloc_sz  = *(unsigned int *)(rw_image + pe_off + 0xB4);

                    if (reloc_rva && reloc_sz && delta)
                    {
                        char *reloc_data = rw_image + reloc_rva;
                        char *block = reloc_data;
                        int fixup_count = 0;

                        ERR("iOS JIT:   relocations: RVA=0x%x size=0x%x delta=0x%lx\n",
                            reloc_rva, reloc_sz, (long)delta);

                        while (block < reloc_data + reloc_sz)
                        {
                            unsigned int block_rva  = *(unsigned int *)block;
                            unsigned int block_size = *(unsigned int *)(block + 4);
                            int j, num_entries;
                            unsigned short *entries;

                            if (!block_size || block_size < 8) break;

                            num_entries = (block_size - 8) / 2;
                            entries = (unsigned short *)(block + 8);

                            for (j = 0; j < num_entries; j++)
                            {
                                int type = entries[j] >> 12;
                                int off  = entries[j] & 0xFFF;

                                if (type == 0) continue;

                                if (type == 10)  /* IMAGE_REL_BASED_DIR64 */
                                {
                                    uint64_t *fixup = (uint64_t *)(rw_image + block_rva + off);
                                    uint64_t val = *fixup;
                                    if (val >= pe_image_base && val < pe_image_base + image_size)
                                    {
                                        *fixup += delta;
                                        fixup_count++;
                                    }
                                    else
                                    {
                                        /* Log first few skipped entries */
                                        static int skip_log = 0;
                                        if (skip_log < 5)
                                        {
                                            ERR("iOS JIT:   SKIP reloc at RVA 0x%x: val=0x%llx (outside image 0x%llx-0x%llx)\n",
                                                block_rva + off, (unsigned long long)val,
                                                (unsigned long long)pe_image_base,
                                                (unsigned long long)(pe_image_base + image_size));
                                            skip_log++;
                                        }
                                    }
                                }
                            }

                            block += block_size;
                        }

                        __asm__ __volatile__("dsb sy" ::: "memory");
                        sys_icache_invalidate((char *)jit_rx_base + offset, image_size);

                        ERR("iOS JIT:   applied %d DIR64 fixups (delta=0x%lx)\n",
                            fixup_count, (long)delta);
                    }

                    /* Store relocation info for later IAT sync re-application */
                    ios_jit_set_reloc_info(image_base, pe_image_base, delta,
                                          reloc_rva, reloc_sz);

                    /* Debug: show syscall_dispatcher value after relocation */
                    if (image_size > 0x64a70)
                    {
                        uint64_t rw_val = *(uint64_t *)(rw_image + 0x64a68);
                        ERR("iOS JIT:   syscall_dispatcher ptr relocated to 0x%llx\n",
                            (unsigned long long)rw_val);
                    }
                }

                /* Patch x18 references in .text → TPIDR_EL0 trampolines.
                 * Allocate trampoline space right after the PE image in the JIT pool.
                 *
                 * SKIP x18 patching for pure x86_64 PEs only.
                 * ARM64EC PEs report Machine=AMD64 (0x8664) in their header but their
                 * .text holds real ARM64 code that DOES need x18 patching. Detect
                 * ARM64EC by presence of a `.a64xrm` (ARM64EC reloc range map) section. */
                {
                    char *rw_image = (char *)jit_rw_base + offset;
                    USHORT pe_machine = *(USHORT *)(rw_image + pe_off + 4);
                    int is_arm64ec_pe = 0;
                    if (pe_machine != IMAGE_FILE_MACHINE_ARM64)
                    {
                        /* Walk section headers looking for .a64xrm */
                        unsigned short num_sec  = *(unsigned short *)(rw_image + pe_off + 6);
                        unsigned short opt_size = *(unsigned short *)(rw_image + pe_off + 0x14);
                        char *sh = rw_image + pe_off + 0x18 + opt_size;
                        for (int s = 0; s < num_sec; s++, sh += 40)
                        {
                            if (!memcmp(sh, ".a64xrm", 7)) { is_arm64ec_pe = 1; break; }
                        }
                    }
                    if (pe_machine != IMAGE_FILE_MACHINE_ARM64 && !is_arm64ec_pe)
                    {
                        ERR("iOS JIT: skipping x18 patcher for non-ARM64 PE (Machine=0x%x)\n",
                            pe_machine);
                        goto x18_patch_done;
                    }
                    if (is_arm64ec_pe)
                        ERR("iOS JIT: x18-patching ARM64EC PE (Machine=0x%x has .a64xrm)\n",
                            pe_machine);
                }
                {
                    /* Find .text section info from mapping table */
                    int map_idx;
                    size_t text_off = 0, text_sz = 0;
                    for (map_idx = 0; map_idx < ios_jit_mapping_count; map_idx++)
                    {
                        if (ios_jit_mappings[map_idx].pe_base == image_base)
                        {
                            text_off = ios_jit_mappings[map_idx].text_offset;
                            text_sz = ios_jit_mappings[map_idx].text_size;
                            break;
                        }
                    }
                    if (text_sz > 0)
                    {
                        /* Task #25: exact budget (was 100% of .text, ~99% wasted). */
                        extern size_t ios_jit_x18_tramp_need( const char *text, size_t text_size );
                        size_t tramp_budget = ios_jit_x18_tramp_need((char *)jit_rw_base + offset + text_off, text_sz);
                        size_t tramp_alloc = (tramp_budget + page_size - 1) & ~(page_size - 1);
                        /* task #34: fixed image-relative offset — the region
                         * pre-reserved in this image's own allocation. The
                         * pre-scan ran on the SOURCE image (identical bytes),
                         * so the budgets must agree; a mismatch means the
                         * copy diverged from the source and patching it
                         * would emit copy-specific branches — refuse (x18
                         * insns degrade to recoverable runtime faults). */
                        size_t tramp_pool_off = offset + image_alloc;
                        if (tramp_alloc > tramp_prealloc)
                        {
                            dprintf(2, "[x18-tramp] REFUSED: budget 0x%lx > prealloc 0x%lx (source/copy divergence?)\n",
                                    (unsigned long)tramp_alloc, (unsigned long)tramp_prealloc);
                            tramp_pool_off = (size_t)-1;
                        }
                        if (!tramp_alloc) tramp_pool_off = (size_t)-1;  /* no x18 refs — nothing to patch */

                        if (tramp_pool_off != (size_t)-1)
                        {
                            char *tramp_rw = (char *)jit_rw_base + tramp_pool_off;
                            char *tramp_rx = (char *)jit_rx_base + tramp_pool_off;
                            char *text_rw = (char *)jit_rw_base + offset + text_off;
                            char *text_rx = (char *)jit_rx_base + offset + text_off;

                            int patched = ios_jit_patch_x18(text_rw, text_rx, text_sz,
                                                            tramp_rw, tramp_rx, tramp_alloc);

                            if (patched > 0)
                            {
                                sys_icache_invalidate(text_rx, text_sz);
                                sys_icache_invalidate(tramp_rx, tramp_alloc);
                            }
                        }
                        else
                        {
                            ERR("iOS JIT: no space for x18 trampolines (need 0x%lx at 0x%lx)\n",
                                (unsigned long)tramp_alloc, (unsigned long)tramp_pool_off);
                        }
                    }
                }
                x18_patch_done: ;
            }

            /* ml957: honour a requested PROT_WRITE on the backing.
             *
             * This used to be an unconditional `mprotect(base, size, PROT_READ)`
             * ("leave original code section as read-only"), which is right for a
             * pure CODE section -- execution comes from the pool copy at its own
             * RX address, so the backing needs no X, and denying W kept it from
             * being written behind the pool's back.
             *
             * But it also silently discarded the caller's PROT_WRITE. Combined
             * with the `&& !(unix_prot & PROT_EXEC)` guard on the vm_protect
             * write path above, a section declaring BOTH execute and write --
             * an RWX self-modifying section -- could never be granted write
             * anywhere: the write path skipped it for being executable, and this
             * path stripped the write bit for being a code section.
             *
             * Measured (rdr21): EMP.dll's `.EMP` section, rva 0x31000-0x64000,
             * characteristics 0xe0000020 = CODE|EXECUTE|READ|WRITE, ended up
             * cur_prot=0x1 (R--) with max_prot=0x7. The guest stored a
             * STATUS_PENDING IO_STATUS_BLOCK into it from ReadFile+0xac
             * (`str w8,[x26]`, x26=0x1303aaa0) and the sub-floor handler had to
             * refuse the write, which became a c0000005 and killed the process.
             * The guest was entitled to that write; we had taken it away.
             *
             * Granting it cannot create a W+X mapping: the backing never carries
             * X (execution is from the pool copy, a separate mapping), so this is
             * R+W on a page that has no X. And for a sub-floor image the backing
             * is the canonical byte source -- ml954 made FEX's decoder read block
             * bytes from it -- so a write that lands there is the one FEX sees.
             *
             * CAVEAT (still owed, see handoff 14.5/14.8): for a section that is
             * CODE as well as WRITE, a guest write now changes bytes FEX may
             * already have JITted. Invalidation is not wired up yet. The
             * sub-floor window makes that tractable later, because every guest
             * write to a low address still traps through ios_subfloor_service;
             * that is the hook point, via a FEX-registered callback like ml951's.
             */
            if (unix_prot & PROT_WRITE)
            {
                kern_return_t wkr = vm_protect( mach_task_self(), (vm_address_t)base, size,
                                                FALSE, VM_PROT_READ | VM_PROT_WRITE );
                if (wkr != KERN_SUCCESS)
                    wkr = vm_protect( mach_task_self(), (vm_address_t)base, size,
                                      FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY );
                if (wkr != KERN_SUCCESS && mprotect( base, size, PROT_READ | PROT_WRITE ) != 0)
                {
                    dprintf( 2, "ml957: %s backing %p+0x%lx declares MEM_WRITE but W could not be "
                             "restored (vm_protect kr=%d, mprotect errno=%d) -- guest writes here "
                             "will be refused by the sub-floor handler\n",
                             ios_pe_module_name( image_base, image_size ),
                             base, (unsigned long)size, wkr, errno );
                }
                else
                {
                    dprintf( 2, "ml957: %s backing %p+0x%lx W RESTORED (section declares "
                             "EXECUTE|WRITE; backing stays non-exec, pool copy keeps X)\n",
                             ios_pe_module_name( image_base, image_size ),
                             base, (unsigned long)size );
                }
            }
            else
            {
                /* Pure code section: leave the backing read-only, as before. */
                mprotect( base, size, PROT_READ );
            }
            return 0;
        }
    }
#endif

    return mprotect( base, size, unix_prot );
}


#ifdef WINE_IOS
/***********************************************************************
 * S1 pseudo-processes: per-child ntdll copy.
 *
 * Child "processes" are thread groups in the same Mach task. All modules
 * except ntdll duplicate naturally (the child's loader maps them at fresh
 * VAs → mprotect_exec makes fresh pool copies). ntdll is special: it is
 * pre-mapped once by the unix side at a shared VA, and its .data holds
 * per-process loader state (module list, loader lock, hash table). A child
 * sharing the parent's ntdll .data corrupts both module lists — so each
 * child gets its own pool copy of the whole ntdll image, registered as an
 * owner_peb-tagged mapping entry. Translation picks the copy owned by the
 * current thread's process (see ios_jit_translate_addr_for_owner).
 *
 * The copy source is the LIVE unix-side view: file-state .data (PE-side
 * runtime writes go to the pool copies, never here) plus the handful of
 * unix-written runtime slots we WANT to inherit (syscall/unix-call
 * dispatchers, unixlib handle, xlate hooks — all unix .text addresses that
 * the reloc range-check leaves untouched). Slots holding PARENT-POOL
 * aliases (e.g. the Round-7 EC unix-call thunk) are rebased to the child
 * copy by the pool-pointer sweep below.
 */

/* Mark ARM64EC CodeMap ranges for a child copy (mirror of the parent path
 * in mprotect_exec, kept separate so the proven parent code is untouched).
 * No-op for non-hybrid images (no .hexpthk section). */
static void ios_jit_mark_ec_ranges_for_copy(char *rw_image, char *jit_base, size_t image_size)
{
    unsigned int pe_off = *(unsigned int *)(rw_image + 0x3C);
    unsigned short num_sec = *(unsigned short *)(rw_image + pe_off + 6);
    unsigned short opt_sz = *(unsigned short *)(rw_image + pe_off + 0x14);
    char *sec = rw_image + pe_off + 0x18 + opt_sz;
    int is_hybrid = 0, s;

    for (s = 0; s < num_sec; s++, sec += 40)
        if (!memcmp(sec, ".hexpthk", 8)) { is_hybrid = 1; break; }
    if (!is_hybrid || !arm64ec_view) return;

    {
        size_t bm_start = ((size_t)jit_base >> 12) / 8;
        size_t bm_end   = (((size_t)jit_base + image_size) >> 12) / 8;
        size_t bm_size  = ROUND_SIZE(bm_start, bm_end + 1 - bm_start, page_mask);
        void *bm_page   = ROUND_ADDR((char *)arm64ec_view->base + bm_start, page_mask);
        set_vprot(arm64ec_view, bm_page, bm_size, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED);
    }
    {
        char *opt_hdr = rw_image + pe_off + 0x18;
        unsigned int load_cfg_rva = *(unsigned int *)(opt_hdr + 0x70 + 10*8);
        unsigned int load_cfg_size = *(unsigned int *)(opt_hdr + 0x70 + 10*8 + 4);
        uint64_t pe_image_base = *(uint64_t *)(opt_hdr + 0x18);
        int found_codemap = 0;

        if (load_cfg_rva && load_cfg_size > 0xD0)
        {
            uint64_t chpe_meta_va = *(uint64_t *)(rw_image + load_cfg_rva + 0xC8);
            uint64_t meta_rva = (uint64_t)-1;
            /* This runs AFTER the child DIR64 pass, which rebases the
             * CHPEMetadataPointer slot from the header ImageBase to the
             * child's pool copy (jit_base). Accept either form — a failed
             * lookup falls back to flat-marking the whole image as EC,
             * which makes arm64x_check_call treat the raw x64 syscall
             * stubs as ARM and BR into them (X1 child ILL storm). */
            if (chpe_meta_va >= pe_image_base && chpe_meta_va < pe_image_base + image_size)
                meta_rva = chpe_meta_va - pe_image_base;
            else if (chpe_meta_va >= (uint64_t)(uintptr_t)jit_base &&
                     chpe_meta_va <  (uint64_t)(uintptr_t)jit_base + image_size)
                meta_rva = chpe_meta_va - (uint64_t)(uintptr_t)jit_base;
            if (meta_rva != (uint64_t)-1)
            {
                char *meta = rw_image + meta_rva;
                unsigned int code_map_rva = *(unsigned int *)(meta + 0x4);
                unsigned int code_map_count = *(unsigned int *)(meta + 0x8);
                if (code_map_rva && code_map_count)
                {
                    char *code_map = rw_image + code_map_rva;
                    unsigned int k, ec_marked = 0;
                    for (k = 0; k < code_map_count; k++)
                    {
                        unsigned int start = *(unsigned int *)(code_map + k*8);
                        unsigned int len   = *(unsigned int *)(code_map + k*8 + 4);
                        if ((start & 0x3) == 1)  /* ARM64EC range */
                        {
                            set_arm64ec_range(jit_base + (start & ~0x3u), len);
                            ec_marked++;
                        }
                    }
                    found_codemap = 1 + (int)ec_marked;
                }
            }
        }
        if (!found_codemap) set_arm64ec_range(jit_base, image_size);
        dprintf(2, "[child-ntdll] EC ranges marked for copy at %p (codemap=%d ec_ranges=%d)\n",
                jit_base, !!found_codemap, found_codemap ? found_codemap - 1 : 0);
    }
}

/* Copy the module containing `module_addr` into a fresh pool slot owned by
 * `child_peb`. Returns 0 on success. Idempotent per (module, child). */
int ios_jit_copy_module_for_child(void *module_addr, void *child_peb)
{
    const size_t pg = 0x4000;
    struct ios_jit_mapping *m = NULL;
    size_t alloc_size, offset;
    size_t child_tramp_prealloc = 0;
    char *rw_dest, *rx_dest, *src;
    uint64_t pe_image_base;
    intptr_t child_delta;
    unsigned int pe_off;
    int i;

    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t base = (uintptr_t)ios_jit_mappings[i].pe_base;
        if ((uintptr_t)module_addr >= base && (uintptr_t)module_addr < base + ios_jit_mappings[i].size)
        {
            if (ios_jit_mappings[i].owner_peb == child_peb) return 0;  /* already copied */
            if (!ios_jit_mappings[i].owner_peb) m = &ios_jit_mappings[i];
        }
    }
    if (!m || !ios_jit_rw_base_global)
    {
        dprintf(2, "[child-ntdll] no parent mapping found for %p\n", module_addr);
        return -1;
    }
    if (ios_jit_mapping_count >= IOS_JIT_MAX_MAPPINGS)
    {
        /* Full count is fine as long as reclamation left a tombstone the
         * append below can reuse. */
        int free_slot = 0;
        for (i = 0; i < ios_jit_mapping_count; i++)
            if (!ios_jit_mappings[i].pe_base) { free_slot = 1; break; }
        if (!free_slot)
        {
            dprintf(2, "[child-ntdll] mapping table FULL — cannot register child copy\n");
            return -1;
        }
    }

    alloc_size = (m->size + pg - 1) & ~(pg - 1);
    /* task #34: reserve the x18 trampoline region inside this allocation at
     * a fixed image-relative offset (mirrors the parent path — see the
     * mprotect_exec copy pipeline). Budget from the SOURCE bytes; identical
     * to what the post-memcpy scan would compute. */
    {
        extern size_t ios_jit_x18_tramp_need( const char *text, size_t text_size );
        child_tramp_prealloc = m->text_size
            ? ((ios_jit_x18_tramp_need((const char *)m->pe_base + m->text_offset, m->text_size) + pg - 1) & ~(pg - 1))
            : 0;
    }
    alloc_size += child_tramp_prealloc;
    {
        size_t data_delta = ios_jit_data_align_delta(m->pe_base, m->size);
        if (data_delta) alloc_size += pg;
        offset = ios_pool_alloc_range_tagged(alloc_size, ios_jit_pool_size_global - ios_jit_tail_reserved,
                                             ios_pool_image_tag( m->pe_base, m->size, alloc_size ));
        if (offset != (size_t)-1 && data_delta) offset += data_delta;
    }
    if (offset == (size_t)-1)
    {
        dprintf(2, "[child-ntdll] JIT pool exhausted (need 0x%lx, bump=0x%lx of 0x%lx, tail_resv=0x%lx, freelist=%d)\n",
                (unsigned long)alloc_size, (unsigned long)jit_pool_offset,
                (unsigned long)ios_jit_pool_size_global,
                (unsigned long)ios_jit_tail_reserved, ios_pool_free_count);
        return -1;
    }

    rw_dest = (char *)ios_jit_rw_base_global + offset;
    rx_dest = (char *)ios_jit_rx_base_global + offset;
    src = (char *)m->pe_base;

    memcpy(rw_dest, src, m->size);
    /* task #34: verify HERE, before relocations/x18 patching legitimately
     * diverge the copy from its source. This is the path that produces the
     * per-pseudo-process copies that keep dying (libarm64ecfex, rpcrt4). */
    sys_icache_invalidate(rx_dest, m->size);
    ios_jit_verify_copy( src, rx_dest, m->size,
                         ios_pe_module_name( src, m->size ),
                         offset, ios_pool_last_alloc_reused );

    pe_off = *(unsigned int *)(rw_dest + 0x3C);
    pe_image_base = m->pe_image_base ? m->pe_image_base
                                     : *(uint64_t *)(rw_dest + pe_off + 0x30);
    child_delta = (intptr_t)rx_dest - (intptr_t)pe_image_base;

    /* Writable sections → RW on the RX view (mirrors parent path; a failed
     * mprotect falls back to the STR fault emulator, just slower). */
    {
        unsigned short num_sec = *(unsigned short *)(rw_dest + pe_off + 6);
        unsigned short opt_sz = *(unsigned short *)(rw_dest + pe_off + 0x14);
        char *sec = rw_dest + pe_off + 0x18 + opt_sz;
        int s;
        for (s = 0; s < num_sec; s++, sec += 40)
        {
            unsigned int chars = *(unsigned int *)(sec + 36);
            unsigned int rva = *(unsigned int *)(sec + 12);
            unsigned int vsz = *(unsigned int *)(sec + 8);
            if ((chars & 0x80000000) && vsz)  /* IMAGE_SCN_MEM_WRITE */
            {
                size_t p_off = rva & ~(pg - 1);
                size_t p_end = ((size_t)rva + vsz + pg - 1) & ~(pg - 1);
                size_t p_lim = ((size_t)m->size + pg - 1) & ~(pg - 1);
                size_t p_sz;
                /* ml1351: as in the image copy, never reach past this copy's pages
                 * (MADEIRA_POOL_SECTION_CLAMP=0 restores the unclamped range). */
                if (p_end > p_lim && !(getenv( "MADEIRA_POOL_SECTION_CLAMP" ) &&
                                       getenv( "MADEIRA_POOL_SECTION_CLAMP" )[0] == '0'))
                    p_end = p_lim;
                if (p_end <= p_off) continue;
                p_sz = p_end - p_off;
                if (mprotect(rx_dest + p_off, p_sz, PROT_READ | PROT_WRITE) != 0)
                    dprintf(2, "[child-ntdll] mprotect RW failed for section RVA 0x%x (errno=%d)\n",
                            rva, errno);
            }
        }
    }

    /* DIR64 relocations with the child's delta. The unix view is
     * unrelocated (values at PE ImageBase); the range check preserves
     * runtime-written unix addresses (dispatchers, hooks). */
    if (m->reloc_rva && m->reloc_size)
    {
        char *reloc = rw_dest + m->reloc_rva;
        char *reloc_end = reloc + m->reloc_size;
        int fixups = 0;
        while (reloc < reloc_end)
        {
            unsigned int block_rva = *(unsigned int *)reloc;
            unsigned int block_size = *(unsigned int *)(reloc + 4);
            unsigned short *entries = (unsigned short *)(reloc + 8);
            int j, num;
            if (!block_size || block_size < 8) break;
            num = (block_size - 8) / 2;
            for (j = 0; j < num; j++)
            {
                if ((entries[j] >> 12) == 10)  /* IMAGE_REL_BASED_DIR64 */
                {
                    uint64_t *fixup = (uint64_t *)(rw_dest + block_rva + (entries[j] & 0xFFF));
                    if (*fixup >= pe_image_base && *fixup < pe_image_base + m->size)
                    {
                        *fixup += child_delta;
                        fixups++;
                    }
                }
            }
            reloc += block_size;
        }
        dprintf(2, "[child-ntdll] applied %d DIR64 fixups (delta=0x%lx)\n",
                fixups, (long)child_delta);
    }

    /* Pool-pointer sweep: unix-side code wrote a few slots with PARENT-POOL
     * aliases (e.g. the EC unix-call thunk, Round 7). Those are wrong for
     * the child — rebase any 8-aligned value inside the parent's pool copy
     * of THIS module to the child copy. The unix view only ever receives
     * unix-side writes, so matches are genuine. */
    {
        uintptr_t pj = (uintptr_t)m->jit_base;
        uint64_t *p = (uint64_t *)rw_dest;
        uint64_t *end = (uint64_t *)(rw_dest + (m->size & ~(size_t)7));
        int swept = 0;
        for (; p < end; p++)
        {
            if (*p >= pj && *p < pj + m->size)
            {
                uint64_t nv = (uintptr_t)rx_dest + (*p - pj);
                dprintf(2, "[child-ntdll]   pool-ptr rebase @+0x%lx: 0x%llx -> 0x%llx\n",
                        (unsigned long)((char *)p - rw_dest),
                        (unsigned long long)*p, (unsigned long long)nv);
                *p = nv;
                swept++;
            }
        }
        dprintf(2, "[child-ntdll] pool-pointer sweep: %d slot(s) rebased\n", swept);
    }

    /* x18-patch the child's .text with its own trampolines (fresh from the
     * unix view — the parent's patches live only in the parent's copy). */
    if (m->text_size && child_tramp_prealloc)
    {
        /* task #34: trampolines live in the fixed image-relative region
         * pre-reserved above — same offset in every copy, so patched .text
         * and tramps are byte-identical across copies (page-shareable). */
        size_t tramp_off = offset + (alloc_size - child_tramp_prealloc);
        int patched = ios_jit_patch_x18(
            rw_dest + m->text_offset, rx_dest + m->text_offset, m->text_size,
            (char *)ios_jit_rw_base_global + tramp_off,
            (char *)ios_jit_rx_base_global + tramp_off, child_tramp_prealloc);
        sys_icache_invalidate((char *)ios_jit_rx_base_global + tramp_off, child_tramp_prealloc);
        dprintf(2, "[child-ntdll] x18-patched %d instructions (tramps at image-relative +0x%lx)\n",
                patched, (unsigned long)(alloc_size - child_tramp_prealloc));
    }

    ios_jit_mark_ec_ranges_for_copy(rw_dest, rx_dest, m->size);

    __asm__ __volatile__("dsb sy" ::: "memory");
    sys_icache_invalidate(rx_dest, m->size);

    ios_jit_verify_text_exec( ios_pe_module_name( m->pe_base, m->size ), rx_dest, m->size );

    /* Register: APPEND an owned entry — the parent's entry stays intact.
     * Task #25: reuse a tombstoned slot when one exists; pe_base written
     * last (readers' match key) behind a barrier. */
    {
        int slot = -1, si;
        for (si = 0; si < ios_jit_mapping_count; si++)
            if (!ios_jit_mappings[si].pe_base) { slot = si; break; }
        if (slot < 0) slot = ios_jit_mapping_count;
        ios_jit_mappings[slot].machine_cached = 0;   /* a reused tombstone keeps no memo */
        ios_jit_mappings[slot].machine_valid = 0;
        ios_jit_mappings[slot].hybrid_cached = 0;
        ios_jit_mappings[slot].hybrid_valid = 0;
        ios_jit_mappings[slot].jit_base = rx_dest;
        ios_jit_mappings[slot].unmapped = 0;
        ios_jit_mappings[slot].size = m->size;
        ios_jit_mappings[slot].text_offset = m->text_offset;
        ios_jit_mappings[slot].text_size = m->text_size;
        ios_jit_mappings[slot].code_range_count = m->code_range_count;
        memcpy( ios_jit_mappings[slot].code_ranges, m->code_ranges, sizeof m->code_ranges );
        ios_jit_mappings[slot].pe_image_base = pe_image_base;
        ios_jit_mappings[slot].reloc_delta = child_delta;
        ios_jit_mappings[slot].reloc_rva = m->reloc_rva;
        ios_jit_mappings[slot].reloc_size = m->reloc_size;
        ios_jit_mappings[slot].owner_peb = child_peb;
        ios_jit_mappings[slot].map_peb = child_peb;
        __sync_synchronize();
        ios_jit_mappings[slot].pe_base = m->pe_base;
        if (slot == ios_jit_mapping_count) ios_jit_mapping_count++;
    }

    dprintf(2, "[child-ntdll] copied %p+0x%lx -> %p (pool+0x%lx) owner_peb=%p\n",
            m->pe_base, (unsigned long)m->size, rx_dest, (unsigned long)offset, child_peb);
    return 0;
}
#endif  /* WINE_IOS */


/***********************************************************************
 *           mprotect_range
 *
 * Call mprotect on a page range, applying the protections from the per-page byte.
 */
static int mprotect_range( void *base, size_t size, BYTE set, BYTE clear )
{
    size_t i, count;
    char *addr = ROUND_ADDR( base, host_page_mask );
    int prot, next;
    BYTE vprot;

    size = ROUND_SIZE( base, size, host_page_mask );

    vprot = get_host_page_vprot( addr );
    prot = get_unix_prot( (vprot & ~clear) | set );
    for (count = i = 1; i < size / host_page_size; i++, count++)
    {
        vprot = get_host_page_vprot( addr + count * host_page_size );
        next = get_unix_prot( (vprot & ~clear) | set );
        if (next == prot) continue;
        if (mprotect_exec( addr, count * host_page_size, prot )) return -1;
        addr += count * host_page_size;
        prot = next;
        count = 0;
    }
    return mprotect_exec( addr, count * host_page_size, prot );
}


/***********************************************************************
 *           set_vprot
 *
 * Change the protection of a range of pages.
 */
static BOOL set_vprot( struct file_view *view, void *base, size_t size, BYTE vprot )
{
    if (!use_kernel_writewatch && view->protect & VPROT_WRITEWATCH)
    {
        /* each page may need different protections depending on write watch flag */
        set_page_vprot_bits( base, size, vprot & ~VPROT_WRITEWATCH, ~vprot & ~VPROT_WRITEWATCH );
    }
    else
    {
        if (enable_write_exceptions && is_vprot_exec_write( vprot )) vprot |= VPROT_WRITEWATCH;
        else if (use_kernel_writewatch && view->protect & VPROT_WRITEWATCH) vprot &= ~VPROT_WRITEWATCH;
        set_page_vprot( base, size, vprot );
    }
    return !mprotect_range( base, size, 0, 0 );
}


/* iOS-Madeira ml293 (task #52): the PartitionAlloc-arena band. Steered arenas are placed
 * top-down at/above 0x7c00000000 and no guest PE image is ever mapped >= 0x7400000000
 * (verified across 13 runs: every [jit-pool] image base is 0x71-0x73), so this test is
 * unambiguous and needs no bounds table. */
static inline int ios_is_arena_addr( const void *p )
{
    return (uintptr_t)p >= 0x7400000000ULL;
}

/* Offset of the first non-zero byte in [p, p+n), or -1 if all zero. Exists so the
 * zero-contract probes VERIFY BY READING MEMORY BACK rather than trusting that a
 * memset/mmap-over was issued -- on iOS those can silently not do what was asked
 * (PROT_WRITE downgrade), which is exactly the class of bug being hunted. */
static long ios_first_nonzero( const void *p, size_t n )
{
    const unsigned char *b = (const unsigned char *)p;
    size_t i;
    for (i = 0; i < n; i++) if (b[i]) return (long)i;
    return -1;
}


/***********************************************************************
 *           set_protection
 *
 * Set page protections on a range of pages
 */
static NTSTATUS set_protection( struct file_view *view, void *base, SIZE_T size, ULONG protect )
{
    unsigned int vprot;
    NTSTATUS status;

    if ((status = get_vprot_flags( protect, &vprot, view->protect & SEC_IMAGE ))) return status;
    if (is_view_valloc( view ))
    {
        if (vprot & VPROT_WRITECOPY) return STATUS_INVALID_PAGE_PROTECTION;
    }
    else
    {
        BYTE access = vprot & (VPROT_READ | VPROT_WRITE | VPROT_EXEC);
        if ((view->protect & access) != access) return STATUS_INVALID_PAGE_PROTECTION;
    }

    /* ml1077: never execute from the tier. ml1257: BEFORE set_vprot, not after --
     * the copy-back maps anonymous RW, which used to overwrite the protection
     * set_vprot had just applied (a guard page came back writable), and an EXEC
     * mprotect on the shared file mapping must not be what decides the outcome.
     * madeira-bcd swap-images: a pure-x64 image view (VPROT_X64DATA) keeps its
     * file pages for EXEC and WRITECOPY -- mprotect_exec never gives its pages
     * host EXEC, and the file range is this view's alone -- so the emulator's SMC
     * protections and the loader's VirtualProtect calls do not pull its sections
     * back into anonymous memory; a GUARD request still does. */
    if ((vprot & VPROT_GUARD) || ((vprot & (VPROT_EXEC | VPROT_WRITECOPY)) && !(view->protect & VPROT_X64DATA)))
        ios_swap_release_range( base, size, 1 );
    if (!set_vprot( view, base, size, vprot | VPROT_COMMITTED ))
    {
        dprintf(2, "[vmem-denied] set_vprot failed: base=%p size=%p protect=0x%x\n",
                base, (void *)size, (unsigned)protect);
        return STATUS_ACCESS_DENIED;
    }

    /* iOS-Madeira ml638 A/B: NEVER MAKE AN ANON-JIT-ALIASED PAGE PHYSICALLY WRITABLE.
     *
     * The ULTRAKILL alias [0x705bc80000,0x705bc90000) starts COHERENT — an emulated
     * store at +0x1368 read back identically through RX and RW. By the crash the two
     * views hold DIFFERENT Mono methods around +0x337d, and the only events in between
     * are four NtProtectVirtualMemory transitions over the first 16KB — the same chunk
     * that holds all 792 tracked writes and the divergence.
     *
     * Making the guest VA physically writable lets the kernel privatise / COW-split it
     * from the pool RW alias: later guest writes land in the private copy while FEX
     * translates and executes the ORIGINAL pool pages, which still hold the old bytes
     * and zeros beyond. FEX then runs off the end of the buffer — the deterministic
     * one-past-the-end c0000005 we keep hitting.
     *
     * So: keep Wine's LOGICAL protection exactly as the guest asked (set_vprot above
     * already recorded it, so NtQueryVirtualMemory still answers correctly), but
     * re-assert the PHYSICAL protection as R+X. Every guest write then keeps faulting
     * into the alias store emulator and routing to the RW view, which is the design.
     * Decommit / release / no-access are untouched — this only refuses to hand out
     * physical write permission on memory a JIT alias owns.
     *
     * ⛔ If this fixes it, the durable form is to stop this page from ever being
     * physically writable in the first place, not to re-protect after the fact. */
    if ((vprot & VPROT_WRITE) && !(vprot & VPROT_GUARD))
    {
        uintptr_t ov_b = 0, ov_e = 0;
        extern int ios_jit_anon_alias_overlaps(void *, size_t, uintptr_t *, uintptr_t *);
        if (ios_jit_anon_alias_overlaps( base, size, &ov_b, &ov_e ))
        {
            int keep_exec = (vprot & VPROT_EXEC) || 1;   /* alias pages are executable by construction */
            int pr = PROT_READ | (keep_exec ? PROT_EXEC : 0);
            int rc = mprotect( base, size, pr );
            static int ab_n;
            if (ab_n < 24)
                dprintf(2, "[alias-prot] ml638 #%d %p+0x%lx requested prot=0x%x (vprot=0x%x) — logical kept, "
                           "PHYSICAL forced R%s (mprotect rc=%d) alias=[%p,%p)\n",
                        ++ab_n, base, (unsigned long)size, (unsigned)protect, vprot,
                        keep_exec ? "X" : "", rc, (void *)ov_b, (void *)ov_e);
        }
    }

    return STATUS_SUCCESS;
}


/***********************************************************************
 *           ios_verify_commit_zero      (iOS-Madeira ml293, task #52)
 *
 * The OTHER HALF of the decommit zero contract.
 *
 * [decommit-zero] proves the decommit side zeroed. That alone is not sufficient:
 * PartitionAlloc reads its BackupRefPtr refcount out of freshly RECOMMITTED metadata, so a
 * commit that hands back stale bytes fails identically even when every decommit was perfect.
 * Windows guarantees MEM_COMMIT yields zero-filled pages; verify we do too. Together the two
 * probes localise any break to one side or the other.
 *
 * Deliberately NOT placed inside set_protection: that function serves both MEM_COMMIT and
 * plain NtProtectVirtualMemory, so protect traffic would consume the report cap and starve
 * the commit signal -- a probe whose cap is spent on the case it is not measuring reports
 * nothing useful. Called only from the commit branches instead.
 *
 * Reads memory back rather than echoing intent, and only when the protection actually permits
 * reading, so the probe can never itself fault.
 */
static void ios_verify_commit_zero( const void *base, SIZE_T size, ULONG protect, int was_committed )
{
    /* ml544: PER-BAND budgets, and cover the GUEST band too.
     *
     * As written this probe could not see the memory the render hunt cares about,
     * for two independent reasons:
     *   1. `ios_is_arena_addr` is (p >= 0x7400000000), so the GUEST band is excluded
     *      outright — and CEF's render bitmap lives there (ml538 SRC bits were at
     *      0x7042ba0000).
     *   2. Even inside the covered range, all 40 reports in ml543 were spent on
     *      0x7c... FEX-band commits before any pool commit was sampled. That is
     *      exactly the starvation this probe's own comment warns about, happening
     *      to it anyway.
     * ⇒ its "0 STALE ON COMMIT" said nothing about tile memory.
     *
     * Why it matters: tile (0,1) of the login window holds blurred game-library
     * pixels from the SPLASH screen, surviving into a later page. Stale bytes in
     * RECOMMITTED memory would produce exactly that, and Windows guarantees
     * MEM_COMMIT yields zero-filled pages.
     *
     * Separate counters so a chatty band can never starve a quiet one. */
    /* ml545: CENSUS, not a capped sample.
     *
     * ml544 capped each band at 40 reports and the budget was exhausted during
     * WINE BOOT (last guest sample at log line 2384, all of them 0x7038.. thread
     * stacks) while the webhelper spawned at 4838 and the first CEF render was at
     * 15575 -- the ENTIRE CEF phase went unsampled, so "0 stale" said nothing about
     * tile memory. That is the third time a cap has defeated this probe, once after
     * I had already "fixed" it.
     *
     * Use the pattern that demonstrably works here (the [unaligned-guest] census,
     * whose emu=16 simd=0 other=0 IS trustworthy): counters are UNBOUNDED, every
     * anomaly is logged, only the uninteresting OK lines are rate-limited, and
     * every line carries the running totals -- so a silent log can never be
     * mistaken for a clean one. */
    static unsigned long ck_hi, ck_lo, stale_hi, stale_lo, recommit_n;
    unsigned long seq;
    int hi;

    if (!base || !size) return;
    if (protect & (PAGE_NOACCESS | PAGE_GUARD)) return;
    if (!(protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                     PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return;

    /* ml546 defect #1: only a FRESH commit (reserved/decommitted -> committed) is
     * required to read back as zero. Re-committing memory that is ALREADY committed
     * -- which is what a protection change looks like from here -- correctly PRESERVES
     * contents, so flagging it is a false positive. ml545 reported 3 such events at
     * one base with protect alternating 0x2/0x4/0x2, and I nearly read them as
     * violations. Count them separately instead of reporting them as stale. */
    if (was_committed) { ++recommit_n; return; }
    /* ml1078: a file-backed range (ml1077) reads as zero by construction (holes),
     * and walking it faults every sparse page in at ~2 ms each under
     * virtual_mutex: ph-rdr45 sat 90 s in this probe on a 692 MB arena with the
     * whole process waiting on the lock. */
    { extern int ios_swap_overlaps_probe( const void *, size_t ); if (ios_swap_overlaps_probe( base, size )) return; }

    hi = ios_is_arena_addr( base );
    seq = hi ? ++ck_hi : ++ck_lo;
    {
        size_t chk = size < 64 ? (size_t)size : 64;
        unsigned char snap[64];
        mach_vm_size_t got = 0;
        long nz;

        /* ml981: THIS PROBE RUNS UNDER virtual_mutex, SO IT MAY NEVER FAULT.
         *
         * The ml293 comment above claims the probe "can never itself fault"
         * because it checks the protection first — but it checks the protection
         * the CALLER ASKED FOR, not the one the page ended up with. When a
         * commit reports success while the host page stays PROT_NONE (device
         * logs t85:1195 / t86:5280, addr = the just-committed base, mach region
         * prot=0 max=7), the load below took EXC_BAD_ACCESS, and that is not a
         * recoverable fault here:
         *
         *   NtAllocateVirtualMemory holds virtual_mutex across this call
         *   -> the Mach message goes to wine-x18-exc
         *   -> the delivery path locks virtual_mutex (virtual_handle_fault,
         *      virtual_setup_exception, the [fault-rgn] dumper)
         *   -> that lock is held by the very thread whose fault it is servicing.
         *
         * Both threads stop forever (t86:6711 "Core_5 - Thread 0" parked at
         * ios_verify_commit_zero+0x80 run=3 cpu=0, t86:6607 wine-x18-exc in
         * __psynch_mutexwait on 0x1061a7078 = virtual_mutex), and every later
         * VirtualAlloc/VirtualProtect/VirtualFree/page-fault fixup in the whole
         * process queues behind them: the process sits at ~0 % CPU with nothing
         * in a server wait, which is why [srv-stuck] and [waiters] stayed silent.
         * A DIAGNOSTIC MUST NOT BE ABLE TO DO THAT.
         *
         * mach_vm_read_overwrite reads the same bytes without a load on this
         * thread: an inaccessible page comes back as a failed kern_return
         * instead of a fault. And a refused read is itself the signal we most
         * want — it means a MEM_COMMIT that returned STATUS_SUCCESS left memory
         * the guest cannot touch — so report it instead of swallowing it. */
        if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(uintptr_t)base,
                                    (mach_vm_size_t)chk, (mach_vm_address_t)(uintptr_t)snap,
                                    &got ) != KERN_SUCCESS || got != (mach_vm_size_t)chk)
        {
            BYTE hv = get_host_page_vprot( base );
            mach_vm_address_t ra = (mach_vm_address_t)(uintptr_t)base;
            mach_vm_size_t rs = 0;
            vm_region_basic_info_data_64_t ri;
            mach_msg_type_number_t rc = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t ro = MACH_PORT_NULL;
            int have_region = (mach_vm_region( mach_task_self(), &ra, &rs, VM_REGION_BASIC_INFO_64,
                                               (vm_region_info_t)&ri, &rc, &ro ) == KERN_SUCCESS);

            if (hi) stale_hi++; else stale_lo++;
            dprintf( 2, "[commit-noaccess] #%lu %s *** COMMIT SUCCEEDED BUT PAGE IS UNREADABLE *** "
                     "base=%p size=0x%lx protect=0x%x host_page_vprot=0x%02x unix_prot=0x%x "
                     "region=0x%llx+0x%llx prot=%d max=%d checked=%lu/%lu stale=%lu/%lu "
                     "recommit=%lu rev=ml981\n",
                     seq, hi ? "arena/pool" : "GUEST", base, (unsigned long)size,
                     (unsigned)protect, hv, (unsigned)get_unix_prot( hv ),
                     have_region ? (unsigned long long)ra : 0ull,
                     have_region ? (unsigned long long)rs : 0ull,
                     have_region ? ri.protection : -1, have_region ? ri.max_protection : -1,
                     ck_lo, ck_hi, stale_lo, stale_hi, recommit_n );
            return;
        }
        nz = ios_first_nonzero( snap, chk );
        if (nz < 0)
        {
            /* boring: first few, then sparse -- but the totals ride along */
            if (seq <= 8 || (seq % 4096) == 0)
                dprintf( 2, "[commit-zero] #%lu %s OK base=%p size=0x%lx protect=0x%x "
                         "(zero) checked=%lu/%lu stale=%lu/%lu recommit=%lu rev=ml546\n",
                         seq, hi ? "arena/pool" : "GUEST",
                         base, (unsigned long)size, (unsigned)protect,
                         ck_lo, ck_hi, stale_lo, stale_hi, recommit_n );
        }
        else
        {
            /* ml546 defect #2: ml545 printed bytes[0..7] from BASE while reporting
             * first_nonzero=+0x8 -- so it printed eight zeros and told us nothing
             * about the actual stale content. Print from the offending offset. */
            const unsigned char *b = snap + nz;      /* ml981: the Mach snapshot, same bytes */
            if (hi) stale_hi++; else stale_lo++;      /* ALWAYS logged: this is the signal */
            dprintf( 2, "[commit-zero] #%lu %s *** STALE ON COMMIT *** base=%p size=0x%lx "
                     "protect=0x%x first_nonzero=+0x%lx checked=%lu/%lu stale=%lu/%lu recommit=%lu "
                     "bytes@nz=%02x %02x %02x %02x %02x %02x %02x %02x rev=ml546\n",
                     seq, hi ? "arena/pool" : "GUEST",
                     base, (unsigned long)size, (unsigned)protect, (unsigned long)nz,
                     ck_lo, ck_hi, stale_lo, stale_hi, recommit_n,
                     b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7] );
        }
    }
}


/***********************************************************************
 *           commit_arm64ec_map
 *
 * Make sure that the pages corresponding to the address range of the view
 * are committed in the ARM64EC code map.
 */
static void commit_arm64ec_map( struct file_view *view )
{
    size_t start = ((size_t)view->base >> page_shift) / 8;
    size_t end = (((size_t)view->base + view->size) >> page_shift) / 8;
    size_t size = ROUND_SIZE( start, end + 1 - start, page_mask );
    void *base = ROUND_ADDR( (char *)arm64ec_view->base + start, page_mask );

    view->protect |= VPROT_ARM64EC;
    set_vprot( arm64ec_view, base, size, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED );
    ERR("commit_arm64ec_map: view@%p+0x%lx → bitmap %p+0x%lx (start_byte=0x%lx)\n",
        view->base, (unsigned long)view->size, base, (unsigned long)size,
        (unsigned long)start);
}


/***********************************************************************
 *           update_write_watches
 */
static void update_write_watches( void *base, size_t size, size_t accessed_size )
{
    TRACE( "updating watch %p-%p-%p\n", base, (char *)base + accessed_size, (char *)base + size );
    /* clear write watch flag on accessed pages */
    set_page_vprot_bits( base, accessed_size, 0, VPROT_WRITEWATCH );
    /* restore page protections on the entire range */
    mprotect_range( base, size, 0, 0 );
}


/***********************************************************************
 *           reset_write_watches
 *
 * Reset write watches in a memory range.
 */
static void reset_write_watches( void *base, SIZE_T size )
{
    if (use_kernel_writewatch)
    {
        kernel_writewatch_reset( base, size );
        if (!enable_write_exceptions) return;
        if (!set_page_vprot_exec_write_protect( base, size )) return;
    }
    else set_page_vprot_bits( base, size, VPROT_WRITEWATCH, 0 );

    mprotect_range( base, size, 0, 0 );
}


/***********************************************************************
 *           unmap_extra_space
 *
 * Release the extra memory while keeping the range starting on the alignment boundary.
 */
static inline void *unmap_extra_space( void *ptr, size_t total_size, size_t wanted_size, size_t align_mask )
{
    if ((ULONG_PTR)ptr & align_mask)
    {
        size_t extra = align_mask + 1 - ((ULONG_PTR)ptr & align_mask);
        ios_pool_va_warn( "munmap", ptr, extra );
        munmap( ptr, extra );
        ptr = (char *)ptr + extra;
        total_size -= extra;
    }
    if (total_size > wanted_size)
        ios_pool_va_warn( "munmap", (char *)ptr + wanted_size, total_size - wanted_size );
        munmap( (char *)ptr + wanted_size, total_size - wanted_size );
    return ptr;
}


/***********************************************************************
 *           find_reserved_free_area_outside_preloader
 *
 * Find a free area inside a reserved area, skipping the preloader reserved range.
 * virtual_mutex must be held by caller.
 */
static void *find_reserved_free_area_outside_preloader( void *start, void *end, size_t size,
                                                        int top_down, size_t align_mask )
{
    void *ret;

    if (preload_reserve_end >= end)
    {
        if (preload_reserve_start <= start) return NULL;  /* no space in that area */
        if (preload_reserve_start < end) end = preload_reserve_start;
    }
    else if (preload_reserve_start <= start)
    {
        if (preload_reserve_end > start) start = preload_reserve_end;
    }
    else /* range is split in two by the preloader reservation, try both parts */
    {
        if (top_down)
        {
            ret = find_reserved_free_area( preload_reserve_end, end, size, top_down, align_mask );
            if (ret) return ret;
            end = preload_reserve_start;
        }
        else
        {
            ret = find_reserved_free_area( start, preload_reserve_start, size, top_down, align_mask );
            if (ret) return ret;
            start = preload_reserve_end;
        }
    }
    return find_reserved_free_area( start, end, size, top_down, align_mask );
}

/***********************************************************************
 *           map_reserved_area
 *
 * Try to map some space inside a reserved area.
 * virtual_mutex must be held by caller.
 */
static void *map_reserved_area_inner( void *limit_low, void *limit_high, size_t size, int top_down,
                                      int unix_prot, size_t align_mask );

/* iOS-Madeira ml520 timing wrapper — see map_reserved_area_inner. */
static void *map_reserved_area( void *limit_low, void *limit_high, size_t size, int top_down,
                                int unix_prot, size_t align_mask )
{
    struct timespec t0, t1;
    void *r;
    double ms;
    static unsigned long slow_n;

    clock_gettime( CLOCK_MONOTONIC, &t0 );
    r = map_reserved_area_inner( limit_low, limit_high, size, top_down, unix_prot, align_mask );
    clock_gettime( CLOCK_MONOTONIC, &t1 );
    ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    if (ms > 250.0)
    {
        unsigned long n = ++slow_n;
        if (n <= 64 || (n % 256) == 0)
            ERR( "[va-slow] #%lu map_reserved_area took %.0f ms  size=0x%llx align=0x%llx "
                 "top_down=%d -> %p rev=ml520\n", n, ms, (unsigned long long)size,
                 (unsigned long long)align_mask, top_down, r );
    }
    return r;
}

static void *map_reserved_area_inner( void *limit_low, void *limit_high, size_t size, int top_down,
                                      int unix_prot, size_t align_mask )
{
    void *ptr = NULL;
    struct reserved_area *area;
    /* iOS-Madeira ml520: time the aligned VA reservation.
     *
     * ml519's freeze detector measured a 53.9s whole-app stall (t+32.7 →
     * t+86.6, 90 threads) and the FIRST thing to resume was a NEW FEX
     * thread initialising ([TI-IC] decoder/passmanager). Each FEX thread
     * reserves 2x128MB rpmalloc spans, and this function scans for aligned
     * free space with virtual_mutex held, issuing kernel mapping calls as
     * it goes — each of which takes the task's vm_map lock. A long scan
     * therefore stalls EVERY thread that page-faults, which is
     * indistinguishable from "the task was suspended" to any in-process
     * observer (exactly what #67's accuser concluded).
     *
     * If one call here accounts for the tens of seconds, the freeze is
     * OURS and this names it. If every call is fast, the VM path is
     * exonerated and the debugger theory stands. Timing only — no
     * behaviour change. */

    if (top_down)
    {
        LIST_FOR_EACH_ENTRY_REV( area, &reserved_areas, struct reserved_area, entry )
        {
            void *start = area->base;
            void *end = (char *)start + area->size;

            /* ml799: the FEX arena serves only requests contained in it. */
            if (area->fex_only && !fex_arena_covers( limit_low, limit_high )) continue;
            if (area->thin_only) continue;   /* Madeira: thin heads are placed at fixed slots */
            if (start >= limit_high) continue;
            if (end <= limit_low) return NULL;
            if (start < limit_low) start = (void *)ROUND_SIZE( 0, limit_low, host_page_mask );
            if (end > limit_high) end = ROUND_ADDR( limit_high, host_page_mask );
            ptr = find_reserved_free_area_outside_preloader( start, end, size, top_down, align_mask );
            if (ptr) break;
        }
    }
    else
    {
        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            void *start = area->base;
            void *end = (char *)start + area->size;

            /* ml799: the FEX arena serves only requests contained in it. */
            if (area->fex_only && !fex_arena_covers( limit_low, limit_high )) continue;
            if (area->thin_only) continue;   /* Madeira: thin heads are placed at fixed slots */
            if (start >= limit_high) return NULL;
            if (end <= limit_low) continue;
            if (start < limit_low) start = (void *)ROUND_SIZE( 0, limit_low, host_page_mask );
            if (end > limit_high) end = ROUND_ADDR( limit_high, host_page_mask );
            ptr = find_reserved_free_area_outside_preloader( start, end, size, top_down, align_mask );
            if (ptr) break;
        }
    }
    if (ptr && anon_mmap_fixed( ptr, size, unix_prot, 0 ) != ptr) ptr = NULL;
    return ptr;
}

