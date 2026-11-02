/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Reserved areas and the user-space limit. Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *           mmap_add_fex_reserved_area
 *
 * ml799: register the emulator's arena as a FEX_ONLY reserved range.
 *
 * Deliberately does NOT merge with anything. The arena is registered exactly
 * once, and merging is what would erase the kind. An overlap with an existing
 * range is a bug worth naming rather than absorbing: it would mean two owners
 * again, which is the condition this whole change exists to remove.
 */
static int mmap_add_fex_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;
    struct list *ptr;

    LIST_FOR_EACH( ptr, &reserved_areas )
    {
        area = LIST_ENTRY( ptr, struct reserved_area, entry );
        if (area->base > addr) break;
        if ((char *)area->base + area->size > (char *)addr)
        {
            ERR( "[fex-arena] ml799 REFUSING to register arena %p+%llx: it overlaps an existing "
                 "reserved range %p+%llx -- two owners again; not registering\n",
                 addr, (unsigned long long)size, area->base, (unsigned long long)area->size );
            return 0;
        }
    }

    if (!(area = malloc( sizeof(*area) )))
    {
        ERR( "[fex-arena] ml802 could not allocate a reserved-area record for %p+%llx\n",
             addr, (unsigned long long)size );
        return 0;
    }
    area->base = addr;
    area->size = size;
    area->fex_only = 1;
    area->thin_only = 0;
    list_add_before( ptr, &area->entry );
    ERR( "[fex-arena] ml799 registered FEX_ONLY reserved area %p..%p (%llu MB) -- generic "
         "placement cannot allocate here\n", addr, (char *)addr + size,
         (unsigned long long)(size >> 20) );
    return 1;
}

static void mmap_remove_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;
    struct list *ptr;

    assert( !((UINT_PTR)addr & host_page_mask) );
    assert( !(size & host_page_mask) );

    if (!((intptr_t)addr + size)) size--;  /* avoid wrap-around */

    ptr = list_head( &reserved_areas );
    /* find the first area covering address */
    while (ptr)
    {
        area = LIST_ENTRY( ptr, struct reserved_area, entry );
        if ((char *)area->base >= (char *)addr + size) break;  /* outside the range */
        if ((char *)area->base + area->size > (char *)addr)  /* overlaps range */
        {
            if (area->base >= addr)
            {
                if ((char *)area->base + area->size > (char *)addr + size)
                {
                    /* range overlaps beginning of area only -> shrink area */
                    area->size -= (char *)addr + size - (char *)area->base;
                    area->base = (char *)addr + size;
                    break;
                }
                else
                {
                    /* range contains the whole area -> remove area completely */
                    ptr = list_next( &reserved_areas, ptr );
                    list_remove( &area->entry );
                    free( area );
                    continue;
                }
            }
            else
            {
                if ((char *)area->base + area->size > (char *)addr + size)
                {
                    /* range is in the middle of area -> split area in two */
                    struct reserved_area *new_area = malloc( sizeof(*new_area) );
                    if (new_area)
                    {
                        new_area->base = (char *)addr + size;
                        new_area->size = (char *)area->base + area->size - (char *)new_area->base;
                        /* ml799: a split must carry the kind across. The tail half
                         * of a FEX_ONLY area is still FEX_ONLY; defaulting it to
                         * generic would quietly open the arena to everything. */
                        new_area->fex_only = area->fex_only;
                        new_area->thin_only = area->thin_only;
                        list_add_after( ptr, &new_area->entry );
                    }
                    area->size = (char *)addr - (char *)area->base;
                    break;
                }
                else
                {
                    /* range overlaps end of area only -> shrink area */
                    area->size = (char *)addr - (char *)area->base;
                }
            }
        }
        ptr = list_next( &reserved_areas, ptr );
    }
}

static int mmap_is_in_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        if (area->base > addr) break;
        if ((char *)area->base + area->size <= (char *)addr) continue;
        /* area must contain block completely */
        if ((char *)area->base + area->size < (char *)addr + size) return -1;
        return 1;
    }
    return 0;
}


/***********************************************************************
 *           unmap_area_above_user_limit
 *
 * Unmap memory that's above the user space limit, by replacing it with an empty mapping,
 * and return the remaining size below the limit. virtual_mutex must be held by caller.
 */
static size_t unmap_area_above_user_limit( void *addr, size_t size )
{
    size_t ret = 0;

    if (addr < user_space_limit)
    {
        ret = (char *)user_space_limit - (char *)addr;
        if (ret >= size) return size;  /* nothing is above limit */
        size -= ret;
        addr = user_space_limit;
    }
    anon_mmap_fixed( addr, size, PROT_NONE, MAP_NORESERVE );
    mmap_add_reserved_area( addr, size );
    return ret;
}


/* ml977: the reserved x64 executable window.
 *
 * The app holds [0x140000000, +256MB) from before the JIT pool is placed, so
 * neither the pool's RW alias nor any unrelated allocation can take the address
 * a fixed-base main image needs. A bare reservation would only move the problem
 * -- anon_mmap_tryfixed is no-clobber, so the loader's own fixed map would fail
 * against US instead of against the pool. This releases it on demand.
 *
 * The release rule is a SIZE floor, not first-come. rdr40/41 show five separate
 * requests for 0x140000000: 2 x 0x60000, 1 x 0x2c000, and 2 x 0x7528000. The
 * small ones are other images that merely share the default ImageBase and are
 * relocatable, so handing them the window would starve the one image that
 * cannot move. Only a request of at least 64MB that lies entirely inside the
 * window claims it.
 *
 * Known limitation, deliberately left visible for now: BOTH RDR2 maps are
 * 0x7528000, so the bootstrap process claims the window first and the final one
 * needs it after the bootstrap exits. Whether that works depends on the
 * bootstrap's image view actually being unmapped at teardown --
 * ios_jit_reclaim_process retires pool copies, which is NOT the same thing. If
 * the second claim fails, the log below says so explicitly rather than
 * pretending the image was relocated.
 *
 * ml983 closes that limitation. rdr53 measured the consequence exactly: the
 * launcher generation claimed the window, died (NtTerminateProcess inside
 * launc.dll), left its image view mapped, and the final RDR2.exe then landed at
 * 0x158110000 with status 0x40000003 (STATUS_IMAGE_NOT_AT_BASE). RDR2.exe has
 * NO .reloc directory and clears DYNAMIC_BASE (DllCharacteristics 0x8120), so
 * "not at base" means every absolute VA inside it still aims at 0x140000000 --
 * where the dead generation's image was still mapped, so the stale pointers
 * RESOLVED instead of faulting. call_tls_callbacks then ran with
 * module=0x158110000 but first=0x140116990: the final process executed the
 * corpse's code, reached the corpse's import slot for kernelbase!VirtualAlloc
 * (0xbc8c14f00, whose pool copy had already been reclaimed), identity-translated
 * it, and fetched an instruction from a file-backed page that is R-- with
 * max_prot RW-. iOS can never grant EXECUTE there, so it is an unrecoverable
 * PROTECTION_FAILURE.
 *
 * So the window must be re-grantable: when its occupant's pseudo-process has
 * been reclaimed, retire that one image view -- through delete_view, so the
 * vprot bytes, the EC code bitmap and the view tree all stay consistent -- and
 * hand the window to the next fixed-base map. Only the image's own interval is
 * touched ([0x140000000,0x147528000) for RDR2), never the whole 256MB window:
 * other allocations (thread stacks at 0x147f..., relocatable images sharing the
 * default ImageBase) live inside it and must survive. If the occupant's owner is
 * still LIVE we decline and say so -- two live processes both needing the same
 * fixed base is a real conflict, not something to paper over. */
static uint64_t ios_exe_win_base, ios_exe_win_size;
static int ios_exe_win_state = -1;          /* -1 unparsed, 1 held, 0 released/absent */

/* ml983: the image currently holding the window, and whether its owner is gone.
 * Only one image can occupy the window at a time, so a single record is the
 * whole registry -- no per-view owner field, and nothing for the rest of the
 * view tree to carry. ios_exe_win_img_peb is bound in init_peb (which is where
 * the owning PEB and the main module base are both known; the image is mapped
 * BEFORE the PEB is published, so the mapping thread cannot name the owner). */
static void    *ios_exe_win_img_base;
static size_t   ios_exe_win_img_size;
static void    *ios_exe_win_img_peb;
static int      ios_exe_win_img_dead;
static unsigned ios_exe_win_generation;

/* ml988: ownership state machine for the fixed-base executable window.
 *
 * Astra's review of ml987 found three real defects, one reproduced with an
 * isolated native test, and this replaces that implementation:
 *
 *  1. The re-reservation used anon_mmap_fixed, which is MAP_FIXED == OVERWRITE
 *     (virtual_ios.c:5005). NtUnmapViewOfSection releases virtual_mutex before
 *     returning, so between the unmap and the reservation another thread could
 *     allocate in the freed interval -- and MAP_FIXED would silently destroy it.
 *     Now the hold is anon_mmap_tryfixed, which is no-clobber by definition:
 *     contention becomes a NAMED failure and is never overwritten.
 *
 *  2. Reuse was published before the old generation's executable translations
 *     were reclaimed. Retirement must happen while the server connection is
 *     live (before the socket closes) but readiness must not be announced until
 *     after ios_jit_reclaim_process. Those are now two separate transitions:
 *     HELD_NOT_READY -> HELD_READY.
 *
 *  3. Ownership was mutated outside any transaction, and the occupant was
 *     recorded when the RESERVATION was released rather than when the image
 *     actually mapped -- so a failed map left a phantom owner. A claim is now
 *     pending until map_image_view commits or rolls it back.
 *
 * Note on locking: holding virtual_mutex excludes Wine's allocators but NOT
 * unrelated native mmap callers, which is exactly why the no-overwrite hold in
 * (1) is required rather than merely preferred.
 *
 * Lock order is strict and acyclic: ios_exewin_lock is a leaf. claim() runs
 * with virtual_mutex already held and then takes it; retirement takes it,
 * RELEASES it, and only then calls NtUnmapViewOfSection (which takes
 * virtual_mutex). Nothing ever holds the leaf while acquiring virtual_mutex. */
enum ios_exewin_state
{
    IOS_EXEWIN_FREE = 0,        /* nobody holds the fixed base */
    IOS_EXEWIN_OWNED,           /* an owner's image is mapped there */
    IOS_EXEWIN_RETIRING,        /* owner exiting; no claims, no address release */
    IOS_EXEWIN_HELD_NOT_READY,  /* image gone, interval held, old generation not yet quiesced */
    IOS_EXEWIN_HELD_READY,      /* old generation retired; the next claimant may take it */
    IOS_EXEWIN_CLAIMING,        /* reservation released, a fresh map is in flight */
};

static const char *ios_exewin_state_name( enum ios_exewin_state st )
{
    switch (st)
    {
    case IOS_EXEWIN_FREE:           return "FREE";
    case IOS_EXEWIN_OWNED:          return "OWNED";
    case IOS_EXEWIN_RETIRING:       return "RETIRING";
    case IOS_EXEWIN_HELD_NOT_READY: return "HELD_NOT_READY";
    case IOS_EXEWIN_HELD_READY:     return "HELD_READY";
    case IOS_EXEWIN_CLAIMING:       return "CLAIMING";
    }
    return "?";
}

static enum ios_exewin_state ios_exewin_st;
static pthread_mutex_t ios_exewin_lock = PTHREAD_MUTEX_INITIALIZER;

/* the interval held for the next generation (only ever the IMAGE's own range --
 * never the whole 256MB window, which by then contains live thread stacks) */
static void   *ios_exe_win_held_base;
static size_t  ios_exe_win_held_size;

/* a claim that has released the reservation but has not yet mapped */
static void   *ios_exewin_pending_base;
static size_t  ios_exewin_pending_size;

static void *anon_mmap_tryfixed( void *start, size_t size, int prot, int flags );
static void ios_exe_win_note_pending( const void *addr, size_t size );

/* ml989: allocation-free, format-free breadcrumbs for the retirement path.
 *
 * Astra's point: rdr57's complete final log line does NOT prove that its
 * dprintf RETURNED, so a deeper formatted probe cannot distinguish "printf
 * failed" from "call never entered" from "unmap died". These markers use a
 * pre-opened fd and a fixed-size write() with no formatting, no locks and no
 * allocation, and the write result is retained so a failed marker is itself
 * observable. They go to their own file, independent of fd 2.
 *
 * The retirement thread is also still before init_thread_stack() when the
 * mapping half runs (loader_ios.c:3284 -- unix_init_startup_info() loads the
 * image first), so its guest exception path is not fully set up and an absent
 * fault report proves nothing. That is why the marker file, not another ERR. */
static int ios_retire_trace_fd = -2;
static volatile int ios_retire_trace_armed;
static volatile int ios_retire_trace_lastwr = -99;

static void ios_retire_mark( const char *tag4 )
{
    if (ios_retire_trace_fd == -2)
    {
        const char *dir = getenv( "MADEIRA_DOCS_DIR" );
        char path[1024];
        size_t n = 0;

        ios_retire_trace_fd = -1;
        if (dir && *dir)
        {
            while (dir[n] && n < sizeof(path) - 32) { path[n] = dir[n]; n++; }
            { const char *f = "/madeira-retire-trace.txt"; size_t i = 0;
              while (f[i]) path[n++] = f[i++]; path[n] = 0; }
            ios_retire_trace_fd = open( path, O_WRONLY | O_CREAT | O_APPEND, 0644 );
        }
    }
    if (ios_retire_trace_fd < 0) return;
    ios_retire_trace_lastwr = (int)write( ios_retire_trace_fd, tag4, 4 );
}

static void ios_exe_win_init( void )
{
    const char *s = getenv( "WINE_IOS_EXE_WINDOW" );
    char *end = NULL;

    ios_exe_win_state = 0;
    if (!s || !*s) return;
    ios_exe_win_base = strtoull( s, &end, 16 );
    if (!end || *end != ':') { ios_exe_win_base = 0; return; }
    ios_exe_win_size = strtoull( end + 1, NULL, 16 );
    if (!ios_exe_win_base || !ios_exe_win_size) { ios_exe_win_base = 0; return; }
    ios_exe_win_state = 1;
    dprintf( 2, "ml977: executable window [%#llx,%#llx) is reserved; will be released to the "
             "first fixed map of >=64MB that fits inside it\n",
             (unsigned long long)ios_exe_win_base,
             (unsigned long long)(ios_exe_win_base + ios_exe_win_size) );
}

/* The image map_image_view is placing right now has its relocations stripped
 * (IMAGE_FILE_RELOCS_STRIPPED): it runs at its ImageBase or not at all.  Set
 * and cleared by map_image_view around its preferred-base attempt, under
 * virtual_mutex.
 *
 * The 64 MB floor below assumes that a small image at the default ImageBase is
 * relocatable, so it keeps the window for a later large fixed-base image.  A
 * small image with stripped relocations is refused by that floor, placed
 * elsewhere, and the loader then fails it with STATUS_CONFLICTING_ADDRESSES
 * ("failed to create main module ... c0000018"): the program can never start.
 * Such an image now gets the window whatever its size.
 *
 * ml1194: thread-local. ios_exe_win_claim runs inside anon_mmap_tryfixed, and
 * not every caller of that holds virtual_mutex (anon_mmap_alloc's ml1029 carve,
 * ios_jumbo_holdback_init, ios_retire_own_fixed_base_image), so a plain global
 * set by the mapping thread could also be read by another thread's request
 * that falls inside the window. */
static __thread int ios_exe_win_stripped_request;

static int ios_exe_win_small_fixed(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        /* 0 keeps the executable window from a fixed-base (relocations stripped) image smaller
         * than 64 MB, as before; such a program then fails to start. */
        const char *e = getenv( "MADEIRA_EXE_WINDOW_SMALL_FIXED" );
        enabled = !(e && e[0] == '0');
    }
    return enabled;
}

static int ios_exe_win_handoff_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0)
    {
        /* 0 restores the old fixed-base handoff: claims are matched without rounding the
         * image size to host pages, and a new main image never waits for the previous
         * owner of the executable window to exit. */
        const char *e = getenv( "MADEIRA_EXE_WINDOW_HANDOFF" );
        enabled = !(e && e[0] == '0');
    }
    return enabled;
}

/* A main image waiting in ios_exe_win_wait_for_handoff, and the pseudo-process
 * (PEB) whose exit it is waiting for. NtCreateUserProcess in that process polls
 * ios_exe_win_handoff_waits_on so it does not block on the child's start-up,
 * which cannot finish until the parent has exited. */
static volatile int ios_exewin_waiters;
static void * volatile ios_exewin_waiter_owner;

int ios_exe_win_handoff_waits_on( void *peb )
{
    return peb && ios_exewin_waiters > 0 && ios_exewin_waiter_owner == peb;
}

/* madeira-bcd: the image view virtual_map_section is placing right now is
 * resource-only: no execute access and not the loader's (no
 * ArbitraryUserPointer), i.e. LOAD_LIBRARY_AS_IMAGE_RESOURCE for a version or
 * resource query. Set and cleared there around virtual_map_image; thread-local
 * for the reason above.
 *
 * A Rockstar session reads Social-Club-Setup.exe's version that way
 * when the launcher starts (GTA V Enhanced, build 456, 18:47:27: a 0x7a7d000
 * view at its ImageBase 0x140000000). Being over the 64 MB floor, it took the
 * window; the view was gone a moment later, and SocialClubHelper.exe
 * (0x141c00000), its CPU area and its stack then filled [0x140000000,
 * 0x148000000), so every later map at 0x140000000 was REFUSED c0000018.
 * GTA5_Enhanced.exe moved high, but an image without relocations (RDR2.exe,
 * 0x7528000) runs nowhere else. With env.MADEIRA_FIXED_BASE_GUARD = 1 such a
 * view takes neither the window nor an interval held for the next generation;
 * it is mapped elsewhere, where a resource query works the same. Off by
 * default: in a GTA session it would move GTA5_Enhanced.exe to its
 * preferred base and SocialClubHelper.exe out of the window. */
static __thread int ios_exe_win_resource_request;

static int ios_fixed_base_guard(void)
{
    static int on = -1;

    if (on < 0)
    {
        const char *e = getenv( "MADEIRA_FIXED_BASE_GUARD" );
        on = e && e[0] == '1' && !e[1];
    }
    return on;
}

/* Returns 1 if the reservation was released for this request. */
static int ios_exe_win_claim( const void *addr, size_t size )
{
    uintptr_t a = (uintptr_t)addr;

    if (ios_exe_win_state < 0) ios_exe_win_init();
    /* ml983: the bounds and floor tests now run before the held/released test --
     * a released window still has to answer a matching request. */
    if (!ios_exe_win_base) return 0;
    if (a < ios_exe_win_base || a + size > ios_exe_win_base + ios_exe_win_size) return 0;
    if (size < 64u * 1024u * 1024u && ios_exe_win_stripped_request && ios_exe_win_small_fixed())
    {
        static int fixed_n;
        if (fixed_n++ < 8)
            dprintf( 2, "[exe-window] %p+%#lx is under the 64MB floor but its relocations are "
                     "stripped: it can only run at this base, so it gets the window "
                     "(MADEIRA_EXE_WINDOW_SMALL_FIXED=0 refuses it as before)\n",
                     addr, (unsigned long)size );
    }
    else if (size < 64u * 1024u * 1024u)
    {
        static int small_n;
        if (small_n++ < 8)
            dprintf( 2, "ml977: NOT releasing the window for %p+%#lx (under the 64MB floor) -- "
                     "a relocatable image sharing the default ImageBase must not starve the "
                     "fixed-base one\n", addr, (unsigned long)size );
        return 0;
    }
    if (ios_exe_win_resource_request && ios_fixed_base_guard())
    {
        static int guard_n;
        if (guard_n++ < 8)
            dprintf( 2, "[exe-window] guard: %p+%#lx is a resource-only image view (no execute access, "
                     "not the loader: a version or resource query); it does not take the fixed-base "
                     "window and is mapped elsewhere (MADEIRA_FIXED_BASE_GUARD)\n",
                     addr, (unsigned long)size );
        return 0;
    }
    if (ios_exe_win_state != 1)
    {
        /* ml988: the window itself is long gone, but the previous generation may
         * have handed its image interval back. Release exactly that interval --
         * never the window -- and only when the handoff is complete. */
        int granted = 0;

        pthread_mutex_lock( &ios_exewin_lock );
        if (!ios_exe_win_held_base ||
            (const void *)addr != ios_exe_win_held_base || size != ios_exe_win_held_size)
        {
            static int mism;
            if (ios_exe_win_held_base && mism++ < 4)
                dprintf( 2, "ml988: %p+%#lx does not match the held interval %p+%#lx "
                         "(state=%s) -- declining\n", addr, (unsigned long)size,
                         ios_exe_win_held_base, (unsigned long)ios_exe_win_held_size,
                         ios_exewin_state_name( ios_exewin_st ) );
        }
        else if (ios_exewin_st != IOS_EXEWIN_HELD_READY)
        {
            /* Astra: a new child must NOT quietly fall back to another base while
             * retirement is incomplete -- for a non-relocatable image that
             * produces exactly the rdr53..rdr55 corpse-execution failure. Name it. */
            dprintf( 2, "ml988: CONFLICT -- %p+%#lx wants the fixed base but the handoff is "
                     "state=%s, not HELD_READY; refusing to release the interval. The image "
                     "will be placed elsewhere, which for a non-relocatable PE is NOT "
                     "equivalent\n", addr, (unsigned long)size,
                     ios_exewin_state_name( ios_exewin_st ) );
        }
        else
        {
            kern_return_t kr = vm_deallocate( mach_task_self(),
                                              (vm_address_t)(uintptr_t)ios_exe_win_held_base,
                                              (vm_size_t)ios_exe_win_held_size );
            dprintf( 2, "ml988: releasing the held image interval %p+%#lx kr=%d "
                     "(HELD_READY -> CLAIMING)\n", ios_exe_win_held_base,
                     (unsigned long)ios_exe_win_held_size, (int)kr );
            if (kr == KERN_SUCCESS)
            {
                ios_va_release_note();
                ios_exewin_pending_base = ios_exe_win_held_base;
                ios_exewin_pending_size = ios_exe_win_held_size;
                ios_exe_win_held_base   = NULL;
                ios_exe_win_held_size   = 0;
                ios_exewin_st           = IOS_EXEWIN_CLAIMING;
                granted = 1;
            }
        }
        pthread_mutex_unlock( &ios_exewin_lock );
        return granted;
    }

    if (vm_deallocate( mach_task_self(), (vm_address_t)ios_exe_win_base,
                       (vm_size_t)ios_exe_win_size ) != KERN_SUCCESS)
    {
        dprintf( 2, "ml977: vm_deallocate of the window FAILED -- leaving it held\n" );
        return 0;
    }
    ios_va_release_note();
    ios_exe_win_state = 0;
    dprintf( 2, "ml977: RELEASED the executable window to %p+%#lx (fixed-base main image)\n",
             addr, (unsigned long)size );
    ios_exe_win_note_pending( addr, size );   /* ml988 */
    return 1;
}

/* ml988: a claim is PENDING until the image actually maps. Recording an owner at
 * reservation-release time (what ml987 did) leaves a phantom owner behind when
 * the map then fails. map_image_view commits or rolls back via
 * ios_exe_win_commit_claim(). */
static void ios_exe_win_note_pending( const void *addr, size_t size )
{
    pthread_mutex_lock( &ios_exewin_lock );
    ios_exewin_pending_base = (void *)(uintptr_t)addr;
    ios_exewin_pending_size = size;
    ios_exewin_st           = IOS_EXEWIN_CLAIMING;
    pthread_mutex_unlock( &ios_exewin_lock );
    dprintf( 2, "ml988: fixed base %p+%#lx CLAIMING (pending a successful map)\n",
             addr, (unsigned long)size );
}

/* Commit or roll back the pending claim. Called from map_image_view once the
 * fixed-base map has actually succeeded or failed. On rollback the interval is
 * re-held with a NO-OVERWRITE reservation, so a failed claim cannot damage
 * whatever now occupies the address. */
void ios_exe_win_commit_claim( void *base, size_t size, int mapped )
{
    unsigned gen = 0;
    int rolled_back = 0, lost = 0;

    /* The claim was noted by anon_mmap_tryfixed, which map_fixed_area calls with
     * the size rounded up to host pages; map_image_view passes SizeOfImage. An
     * image whose size is not a multiple of 16 KB never matched, so its claim
     * stayed CLAIMING for the rest of the session: it was never OWNED, never
     * retired at exit, and a second launch of the same program could not get
     * the base back. */
    if (ios_exe_win_handoff_enabled()) size = ROUND_SIZE( 0, size, host_page_mask );

    pthread_mutex_lock( &ios_exewin_lock );
    if (ios_exewin_st != IOS_EXEWIN_CLAIMING ||
        base != ios_exewin_pending_base || size != ios_exewin_pending_size)
    {
        pthread_mutex_unlock( &ios_exewin_lock );
        return;                                  /* not our claim */
    }
    ios_exewin_pending_base = NULL;
    ios_exewin_pending_size = 0;
    if (mapped)
    {
        ios_exe_win_img_base = base;
        ios_exe_win_img_size = size;
        ios_exe_win_img_peb  = NULL;             /* published by ios_exe_win_note_owner */
        ios_exe_win_img_dead = 0;
        gen = ++ios_exe_win_generation;
        ios_exewin_st = IOS_EXEWIN_OWNED;
    }
    else
    {
        ios_exewin_st = IOS_EXEWIN_FREE;         /* provisional; fixed up below */
        rolled_back = 1;
    }
    pthread_mutex_unlock( &ios_exewin_lock );

    if (!rolled_back)
    {
        dprintf( 2, "ml988: fixed base %p+%#lx is OWNED by gen %u (map succeeded; owner peb "
                 "not yet published)\n", base, (unsigned long)size, gen );
        return;
    }

    /* no-overwrite: if something already took the address, say so and leave it be */
    if (anon_mmap_tryfixed( base, size, PROT_NONE, MAP_NORESERVE ) == MAP_FAILED) lost = 1;

    pthread_mutex_lock( &ios_exewin_lock );
    if (ios_exewin_st == IOS_EXEWIN_FREE && !lost)
    {
        ios_exe_win_held_base = base;
        ios_exe_win_held_size = size;
        ios_exewin_st         = IOS_EXEWIN_HELD_READY;
    }
    pthread_mutex_unlock( &ios_exewin_lock );

    dprintf( 2, "ml988: map at the fixed base FAILED -- claim rolled back, interval %p+%#lx %s\n",
             base, (unsigned long)size,
             lost ? "could NOT be re-held (someone else took it); left untouched"
                  : "re-held PROT_NONE (no-overwrite)" );
}

/* ml983: bind the occupant to its pseudo-process. init_peb is the first point
 * where the owning PEB and the main module base are both known. */
void ios_exe_win_note_owner( void *module, void *owner_peb )
{
    if (!module || !owner_peb) return;
    if (module != ios_exe_win_img_base) return;
    if (ios_exe_win_img_peb == owner_peb) return;
    ios_exe_win_img_peb = owner_peb;
    dprintf( 2, "ml983: gen %u's image %p+%#lx is owned by peb=%p\n", ios_exe_win_generation,
             ios_exe_win_img_base, (unsigned long)ios_exe_win_img_size, owner_peb );
}

/* ml983: the occupant's pseudo-process has been reclaimed. Called from
 * ios_jit_reclaim_process, which by then has tombstoned every pool mapping and
 * retired every anon alias belonging to that PEB -- a stronger quiescence
 * statement than server EOF, because no FEX-translated code of that process can
 * be entered any more. */
static void ios_exe_win_note_dead_peb( void *dead_peb )
{
    if (!dead_peb || !ios_exe_win_img_base) return;
    if (dead_peb != ios_exe_win_img_peb || ios_exe_win_img_dead) return;
    ios_exe_win_img_dead = 1;
    dprintf( 2, "ml983: gen %u's window occupant %p+%#lx is now ownerless (peb=%p reclaimed) -- "
             "the window can be re-granted to the next >=64MB fixed map\n",
             ios_exe_win_generation, ios_exe_win_img_base,
             (unsigned long)ios_exe_win_img_size, dead_peb );
}

/* A program that starts a copy of itself and then exits works on Windows, where
 * every process has its own address space. Here the copy maps its main image
 * while the first instance still holds the fixed base, and an image with
 * stripped relocations cannot be placed anywhere else, so it fails with
 * STATUS_CONFLICTING_ADDRESSES. Wait, outside every lock, for the owner's exit
 * handoff (ios_retire_own_fixed_base_image, then ios_exe_win_mark_ready).
 * Called by virtual_map_module, which maps only the main image. On timeout the
 * map goes ahead and fails as before. */
static void ios_exe_win_wait_for_handoff( const struct pe_image_info *info )
{
    static int wait_ms = -1;
    static int logn;
    uintptr_t a, size;
    void *me = NtCurrentTeb()->Peb;
    int waited = 0, registered = 0;
    enum ios_exewin_state st = IOS_EXEWIN_FREE;
    unsigned gen = 0;

    if (wait_ms < 0)
    {
        /* how long a new main image with stripped relocations waits for the previous owner of
         * the executable window to exit, in milliseconds; 0 does not wait */
        const char *e = getenv( "MADEIRA_EXE_WINDOW_WAIT_MS" );
        wait_ms = e && *e ? atoi( e ) : 10000;
        if (wait_ms < 0) wait_ms = 0;
    }
    if (!wait_ms || !ios_exe_win_handoff_enabled()) return;
    if (!(info->image_charact & IMAGE_FILE_RELOCS_STRIPPED)) return;
    if (info->image_charact & IMAGE_FILE_DLL) return;
    if (!is_machine_64bit( info->machine ) || info->map_addr) return;

    if (ios_exe_win_state < 0) ios_exe_win_init();
    if (!ios_exe_win_base) return;
    a = (uintptr_t)wine_server_get_ptr( info->base );
    size = ROUND_SIZE( 0, info->map_size, host_page_mask );
    if (a < ios_exe_win_base || a + size > ios_exe_win_base + ios_exe_win_size) return;

    for (;;)
    {
        void *owner;
        int busy;

        pthread_mutex_lock( &ios_exewin_lock );
        st    = ios_exewin_st;
        owner = ios_exe_win_img_peb;
        gen   = ios_exe_win_generation;
        pthread_mutex_unlock( &ios_exewin_lock );

        busy = (st == IOS_EXEWIN_OWNED && owner != me) || st == IOS_EXEWIN_RETIRING ||
               st == IOS_EXEWIN_HELD_NOT_READY || st == IOS_EXEWIN_CLAIMING;
        if (!busy) break;
        if (owner) ios_exewin_waiter_owner = owner;
        if (!registered)
        {
            __atomic_add_fetch( &ios_exewin_waiters, 1, __ATOMIC_SEQ_CST );
            registered = 1;
            if (logn++ < 16)
                dprintf( 2, "[exe-window] %p+%#lx has stripped relocations and the fixed base is "
                         "still held by gen %u (peb=%p, state=%s): waiting up to %d ms for that "
                         "process to exit (MADEIRA_EXE_WINDOW_WAIT_MS)\n", (void *)a,
                         (unsigned long)size, gen, owner, ios_exewin_state_name( st ), wait_ms );
        }
        if (waited >= wait_ms) break;
        usleep( 10000 );
        waited += 10;
    }
    if (!registered) return;
    __atomic_sub_fetch( &ios_exewin_waiters, 1, __ATOMIC_SEQ_CST );
    if (!ios_exewin_waiters) ios_exewin_waiter_owner = NULL;
    dprintf( 2, "[exe-window] %s after %d ms (state=%s)\n",
             waited >= wait_ms ? "gave up waiting for the fixed base" : "fixed base handed back",
             waited, ios_exewin_state_name( st ) );
}

static void *anon_mmap_tryfixed( void *start, size_t size, int prot, int flags )
{
    ios_pool_va_warn( "anon_mmap_tryfixed", start, size );
    ios_exe_win_claim( start, size );   /* ml977: hand over the window if this is the one */
    void *ptr;

    /* no [jit-tripwire] here: tryfixed is no-clobber by definition (fails on
     * overlap), and ml75 showed it drowns the cap in pool-setup boot noise. */

#ifdef MAP_FIXED_NOREPLACE
    ptr = mmap( start, size, prot, MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#elif defined(MAP_TRYFIXED)
    ptr = mmap( start, size, prot, MAP_TRYFIXED | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
    ptr = mmap( start, size, prot, MAP_FIXED | MAP_EXCL | MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
    if (ptr == MAP_FAILED && errno == EINVAL) errno = EEXIST;
#elif defined(__APPLE__)
    mach_vm_address_t result = (mach_vm_address_t)start;
    kern_return_t ret = mach_vm_map( mach_task_self(), &result, size, 0, VM_FLAGS_FIXED,
                                     MEMORY_OBJECT_NULL, 0, 0, prot, VM_PROT_ALL, VM_INHERIT_COPY );

    if (!ret)
    {
        if ((ptr = anon_mmap_fixed( start, size, prot, flags )) == MAP_FAILED)
            mach_vm_deallocate( mach_task_self(), result, size );
    }
    else
    {
        /* ml813: keep the REAL reason.
         *
         * Everything except KERN_NO_SPACE was flattened to ENOMEM, so an
         * invalid-address rejection and a genuine out-of-space became
         * indistinguishable -- and a whole diagnosis was built on reading one as
         * the other. Record the raw kr so the allocation-failure probe can name
         * what the kernel actually said. */
        ios_af_set( 6, (int)ret, start, size );
        errno = (ret == KERN_NO_SPACE ? EEXIST : ENOMEM);
        ptr = MAP_FAILED;
    }
#else
    ptr = mmap( start, size, prot, MAP_PRIVATE | MAP_ANON | flags, -1, 0 );
#endif
    if (ptr != MAP_FAILED && ptr != start)
    {
        size = unmap_area_above_user_limit( ptr, size );
        if (size) munmap( ptr, size );
        ptr = MAP_FAILED;
        errno = EEXIST;
    }
    return ptr;
}

static void reserve_area( void *addr, void *end )
{
#ifdef __APPLE__

#ifdef __i386__
    static const mach_vm_address_t max_address = VM_MAX_ADDRESS;
#else
    static const mach_vm_address_t max_address = MACH_VM_MAX_ADDRESS;
#endif
    mach_vm_address_t address = (mach_vm_address_t)addr;
    mach_vm_address_t end_address = (mach_vm_address_t)end;

    if (!end_address || max_address < end_address)
        end_address = max_address;

    while (address < end_address)
    {
        mach_vm_address_t hole_address = address;
        kern_return_t ret;
        mach_vm_size_t size;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t dummy_object_name = MACH_PORT_NULL;

        /* find the mapped region at or above the current address. */
        ret = mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64,
                             (vm_region_info_t)&info, &count, &dummy_object_name);
        if (ret != KERN_SUCCESS)
        {
            address = max_address;
            size = 0;
        }

        if (end_address < address)
            address = end_address;
        if (hole_address < address)
        {
            /* found a hole, attempt to reserve it. */
            size_t hole_size = address - hole_address;
            mach_vm_address_t alloc_address = hole_address;

            ret = mach_vm_map( mach_task_self(), &alloc_address, hole_size, 0, VM_FLAGS_FIXED,
                               MEMORY_OBJECT_NULL, 0, 0, PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
            if (!ret) mmap_add_reserved_area( (void*)hole_address, hole_size );
            else if (ret == KERN_NO_SPACE)
            {
                /* something filled (part of) the hole before we could.
                   go back and look again. */
                address = hole_address;
                continue;
            }
        }
        address += size;
    }
#else
    size_t size = (char *)end - (char *)addr;

    if (!size) return;

    if (anon_mmap_tryfixed( addr, size, PROT_NONE, MAP_NORESERVE ) != MAP_FAILED)
    {
        mmap_add_reserved_area( addr, size );
        return;
    }
    size = (size / 2) & ~granularity_mask;
    if (size)
    {
        reserve_area( addr, (char *)addr + size );
        reserve_area( (char *)addr + size, end );
    }
#endif /* __APPLE__ */
}


static void mmap_init( const struct preload_info *preload_info )
{
#ifndef _WIN64
#ifndef __APPLE__
    char stack;
    char * const stack_ptr = &stack;
#endif
    char *user_space_limit = (char *)0x7ffe0000;
    int i;

    if (preload_info)
    {
        /* check for a reserved area starting at the user space limit */
        /* to avoid wasting time trying to allocate it again */
        for (i = 0; preload_info[i].size; i++)
        {
            if ((char *)preload_info[i].addr > user_space_limit) break;
            if ((char *)preload_info[i].addr + preload_info[i].size > user_space_limit)
            {
                user_space_limit = (char *)preload_info[i].addr + preload_info[i].size;
                break;
            }
        }
    }
    else reserve_area( (void *)0x00010000, (void *)0x40000000 );


#ifndef __APPLE__
    if (stack_ptr >= user_space_limit)
    {
        char *end = 0;
        char *base = stack_ptr - ((unsigned int)stack_ptr & granularity_mask) - (granularity_mask + 1);
        if (base > user_space_limit) reserve_area( user_space_limit, base );
        base = stack_ptr - ((unsigned int)stack_ptr & granularity_mask) + (granularity_mask + 1);
#if defined(linux) || defined(__FreeBSD__) || defined (__FreeBSD_kernel__) || defined(__DragonFly__)
        /* Heuristic: assume the stack is near the end of the address */
        /* space, this avoids a lot of futile allocation attempts */
        end = (char *)(((unsigned long)base + 0x0fffffff) & 0xf0000000);
#endif
        reserve_area( base, end );
    }
    else
#endif
        reserve_area( user_space_limit, 0 );

#else

    if (preload_info) return;
    /* if we don't have a preloader, try to reserve the space now */
    reserve_area( (void *)0x000000010000, (void *)0x000068000000 );
    reserve_area( (void *)0x00007f000000, (void *)0x00007fff0000 );
    reserve_area( (void *)0x7ffffe000000, (void *)0x7fffffff0000 );

#endif
}


