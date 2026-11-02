/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. The WoW64 guest window (docs/WOW64.md). Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *           get_wow_user_space_limit
 */
static ULONG_PTR get_wow_user_space_limit(void)
{
#ifdef _WIN64
    return user_space_wow_limit & ~granularity_mask;
#endif
    return (ULONG_PTR)user_space_limit;
}


#ifdef WINE_IOS
/* ==== WoW64 guest windows: registry and placement ==== */
/***********************************************************************
 *           WoW64 guest window (docs/WOW64.md)
 *
 * One reserved [B, B+4G) host range per 32-bit pseudo-process.  Reserved as
 * a Wine "reserved area" (PROT_NONE + mmap_add_reserved_area) so the whole
 * existing placement machinery works inside it: map_reserved_area places
 * window-constrained requests, map_fixed_area can honour a fixed address in
 * it, and unmap_area/delete_view restore PROT_NONE on free.
 *
 * LAZY.  Nothing here runs for a session that never starts a 32-bit program:
 * no window, no placeholder and no placement bias exist until the session is
 * ARMED (ios_wow_session_arm), which happens only when a 32-bit main image is
 * published by the app (ios_main_image_i386) or a 32-bit process asks for a
 * window.  A 64-bit-only session therefore places memory exactly as before.
 *
 * Placement rules: 4 GB-aligned, inside the furniture band
 * [ios_usable_va_floor, ios_furniture_ceiling) (or the low band on a small
 * address map, see ios_wow_band), below the CEF pools [0x7400000000,
 * 0x7c00000000) and the FEX band [0x7c00000000, 0x8000000000).
 */
#define IOS_WOW_MAX_WINDOWS 8
#define IOS_WOW_CEF_POOLS_START ((ULONG_PTR)0x7400000000)
#define IOS_WOW_FEX_BAND_END    ((ULONG_PTR)0x8000000000)

struct ios_wow_window
{
    void      *peb;             /* owning pseudo-process; NULL = unbound/free */
    ULONG_PTR  base;            /* B, 0 = free slot */
    unsigned   leaked;          /* window intentionally not torn down, see
                                   ios_wow_window_retire(); never reused and
                                   never matched by a lookup again */
    unsigned   dead;            /* the owning pseudo-process has EXITED and the
                                   window waits to be torn down by the next
                                   32-bit pseudo-process that wants a slot
                                   (release-on-next-adopt).  A dead slot still
                                   owns its VA and is still excluded from
                                   furniture placement, but no lookup resolves
                                   to it any more.  2 = teardown in progress. */
    void      *dead_peb;        /* the exited owner's PEB, kept for the deferred
                                   teardown (JIT ledger, fd cache) */
    time_t     released_at;     /* when the owner exited, see IOS_WOW_SETTLE_SEC */
    unsigned   guard_owned;     /* 1: the overrun guard page at B+4G is part of
                                   OUR reservation.  0: it is a pre-existing
                                   inaccessible neighbour we verified and
                                   borrowed (see ios_wow_window_try). */
    pthread_t  owner;           /* thread that reserved it while peb == NULL */
    /* per-process TEB block: a WoW process's TEB64/TEB32 pair must live in
     * its own window, so it cannot share the session-wide teb_block. */
    void      *teb_block;
    void     **next_free_teb;   /* same type as the session-wide next_free_teb */
    int        teb_block_pos;
    unsigned   wine_mono;       /* ml1279: libmono-2.0-x86.dll was mapped in this window, so its
                                   RWX memory is plain read/write from then on */
};
static struct ios_wow_window ios_wow_windows[IOS_WOW_MAX_WINDOWS];
static unsigned ios_wow_window_count;
static pthread_mutex_t ios_wow_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Set once the session can have a 32-bit process; see the LAZY note above. */
static int ios_wow_armed;

int ios_wow_session_armed(void)
{
    return __atomic_load_n( &ios_wow_armed, __ATOMIC_ACQUIRE );
}

void ios_wow_session_arm(void)
{
    if (!__atomic_exchange_n( &ios_wow_armed, 1, __ATOMIC_ACQ_REL ))
        dprintf( 2, "[wow-window] session armed: a 32-bit process is expected\n" );
}

/* PLACEHOLDERS.  A placeholder is a 4 GB-aligned slot reserved PROT_NONE ahead
 * of the 32-bit process that will use it, registered as a Wine reserved area
 * exactly as a real window is.  The process then ADOPTS it (ios_wow_window_try)
 * instead of mapping a fresh range.  The reason is device evidence: iOS places
 * anonymous memory for the system frameworks (Metal, libdispatch, malloc zone
 * growth) at the HIGHEST free hole, which is the slot directly below the [cage]
 * holdback, and Wine cannot bias those allocations.  A slot that is reserved
 * before the frameworks start keeps its hole.
 *
 * Placeholders are taken only when they are known to be needed: one slot at
 * session start when the app published a 32-bit main image (it is known before
 * virtual_init returns), or every slot of the band when MADEIRA_WOW_PLACEHOLDERS=1
 * (for 64-bit launchers that start 32-bit children on a crowded map).  A
 * placeholder is never unmapped: a release makes it unadopted again after the
 * teardown, so the next 32-bit process adopts exactly the same reservation. */
struct ios_wow_placeholder
{
    ULONG_PTR base;          /* 4 GB-aligned slot base, 0 = unused entry */
    unsigned  guard_owned;   /* same meaning as ios_wow_window.guard_owned */
    unsigned  adopted;       /* a pseudo-process has taken this slot over */
};
static struct ios_wow_placeholder ios_wow_placeholders[IOS_WOW_MAX_WINDOWS];
static unsigned ios_wow_placeholder_count;

static struct ios_wow_placeholder *ios_wow_placeholder_find( ULONG_PTR base )
{
    unsigned i;

    for (i = 0; i < ios_wow_placeholder_count; i++)
        if (ios_wow_placeholders[i].base == base) return &ios_wow_placeholders[i];
    return NULL;
}

/* Published by the app before __wine_main: nonzero when this session's MAIN
 * image is 32-bit.  The main image's machine is not known unix-side until
 * unix_init_startup_info, which runs after the first TEB is placed, so the app
 * (which already probes the target PE) says so up front.  0 = 64-bit/unknown. */
int ios_main_image_i386 = 0;

/* The session's own PEB (the first pseudo-process), captured in
 * virtual_alloc_first_teb().  The child path leaves the session global `peb`
 * pointing at the last child it booted, so a released guest window has to put
 * it back to something that still exists — see ios_wow_window_teardown(). */
static PEB *ios_session_peb;

/* OVERRUN GUARD PAGE.
 *
 * FEX adds a raw immediate offset AFTER the base for ldp/stp and the
 * non-temporal forms, so a guest access within ~1 KB of 0xffffffff computes
 * B + 4G + n instead of wrapping round to B + n.  The first byte past the
 * window must therefore never belong to anything else: reserve one extra host
 * page beyond [B, B+4G) and keep it PROT_NONE, so such an access faults
 * instead of silently corrupting the next window or a piece of furniture.  The
 * guard page is part of the RESERVATION but never part of the guest window:
 * ios_wow_in_window() and every ±B conversion use exactly IOS_WOW_WINDOW_SIZE.
 *
 * BORROWED GUARD.  When the only 4 GB-aligned candidate is an exactly-4 GB gap,
 * asking for 4 GB + one page fails.  ios_wow_window_try() then verifies that
 * the page at B+4G is ALREADY an existing region with protection VM_PROT_NONE
 * and, only then, reserves exactly 4 GB and records guard_owned = 0. */
static ULONG_PTR ios_wow_guard_size(void)
{
    return host_page_size ? (ULONG_PTR)host_page_size : (ULONG_PTR)0x4000;
}

/* How much VA a reserved slot owns: 4 GB plus the guard page when it is ours. */
static ULONG_PTR ios_wow_slot_reservation( const struct ios_wow_window *slot )
{
    return IOS_WOW_WINDOW_SIZE + (slot->guard_owned ? ios_wow_guard_size() : 0);
}

static struct ios_wow_window *ios_wow_slot_for_peb( void *peb_id )
{
    unsigned i, n = ios_wow_window_count;

    if (!peb_id) return NULL;
    for (i = 0; i < n; i++)
        if (ios_wow_windows[i].base && !ios_wow_windows[i].leaked &&
            !ios_wow_windows[i].dead &&
            ios_wow_windows[i].peb == peb_id) return &ios_wow_windows[i];
    return NULL;
}

/* The registry entry that owns `base`, whatever its state (live, dead or
 * leaked).  The adopt path must never hand a slot to a second process while
 * the first one's window is still standing. */
static struct ios_wow_window *ios_wow_slot_at_base( ULONG_PTR base )
{
    unsigned i, n = ios_wow_window_count;

    for (i = 0; i < n; i++)
        if (ios_wow_windows[i].base == base && base) return &ios_wow_windows[i];
    return NULL;
}

/* The calling thread's window: its pseudo-process's, or one this thread
 * reserved.  The owner fallback covers the boot gap in which the window is
 * already bound but the new process's TEB is not published yet, so
 * ios_jit_current_peb() cannot resolve the PEB.  `owner` is the owning
 * process's own boot thread, so the fallback can only resolve to that
 * process's window. */
static struct ios_wow_window *ios_wow_slot_current(void)
{
    struct ios_wow_window *slot;
    unsigned i, n = ios_wow_window_count;

    if (!n) return NULL;   /* no window in this session: nothing to resolve */
    if ((slot = ios_wow_slot_for_peb( ios_jit_current_peb() ))) return slot;
    for (i = 0; i < n; i++)
        if (ios_wow_windows[i].base && !ios_wow_windows[i].leaked &&
            !ios_wow_windows[i].dead &&
            pthread_equal( ios_wow_windows[i].owner, pthread_self() ))
            return &ios_wow_windows[i];
    return NULL;
}

/* Live windows (bound or reserved, not dead or leaked). */
static unsigned ios_wow_live_window_count(void)
{
    unsigned i, live = 0;

    for (i = 0; i < ios_wow_window_count; i++)
        if (ios_wow_windows[i].base && !ios_wow_windows[i].dead && !ios_wow_windows[i].leaked)
            live++;
    return live;
}

ULONG_PTR ios_wow_base_for_peb( void *peb_id )
{
    struct ios_wow_window *slot = ios_wow_slot_for_peb( peb_id );
    return slot ? slot->base : 0;
}

ULONG_PTR ios_wow_base(void)
{
    struct ios_wow_window *slot = ios_wow_slot_current();
    return slot ? slot->base : 0;
}

int ios_wow_in_window( const void *addr )
{
    ULONG_PTR base = ios_wow_base();
    return base && (ULONG_PTR)addr >= base && (ULONG_PTR)addr < base + IOS_WOW_WINDOW_SIZE;
}

ULONG ios_wow_guest_addr( const void *host )
{
    ULONG_PTR base = ios_wow_base();

    if (!host) return 0;
    if (base && (ULONG_PTR)host >= base && (ULONG_PTR)host < base + IOS_WOW_WINDOW_SIZE)
        return (ULONG)((ULONG_PTR)host - base);
    return PtrToUlong( host );   /* no window: unchanged (and truncating, as before) */
}

/* Is `addr` inside ANY guest window or placeholder of this session, whatever
 * its state?  Not the same question as ios_wow_in_window(), which asks about
 * the CALLER's window: this one is for session-wide bookkeeping that must not
 * hand a piece of window VA to a process that does not own the window (see the
 * TEB free-list guard in virtual_free_teb). */
static int ios_wow_addr_in_any_window( const void *addr )
{
    ULONG_PTR a = (ULONG_PTR)addr;
    unsigned i;

    for (i = 0; i < ios_wow_window_count; i++)
    {
        ULONG_PTR b = ios_wow_windows[i].base;
        if (b && a >= b && a < b + IOS_WOW_WINDOW_SIZE) return 1;
    }
    for (i = 0; i < ios_wow_placeholder_count; i++)
    {
        ULONG_PTR b = ios_wow_placeholders[i].base;
        if (b && a >= b && a < b + IOS_WOW_WINDOW_SIZE) return 1;
    }
    return 0;
}

/* The LIVE window that OWNS the VA at `addr`, or NULL if the address is not
 * inside any live window.
 *
 * This asks "where does this block live", not "who is asking" — which is the
 * only correct question for returning a block to a pool, because in this
 * session every pseudo-process shares one address space and one ntdll, and a
 * thread of process P routinely frees furniture that belongs to process Q.
 * (exit_thread hands the PREVIOUS exiting thread's TEB to the NEXT one:
 * thread_ios.c, the `prev_teb` handoff.)  Dead, leaked and placeholder ranges
 * deliberately do NOT match: their VA is about to be recycled, so a block
 * inside one must be dropped rather than pooled anywhere. */
static struct ios_wow_window *ios_wow_live_slot_for_addr( const void *addr )
{
    ULONG_PTR a = (ULONG_PTR)addr;
    unsigned i, n = ios_wow_window_count;

    for (i = 0; i < n; i++)
    {
        ULONG_PTR b = ios_wow_windows[i].base;
        if (!b || ios_wow_windows[i].leaked || ios_wow_windows[i].dead) continue;
        if (a >= b && a < b + IOS_WOW_WINDOW_SIZE) return &ios_wow_windows[i];
    }
    return NULL;
}

/* Guest addresses below this are never handed out, mirroring upstream Wine's
 * address_space_start = 0x110000 ("keep DOS area clear").  A bottom-up pick
 * inside a window returns the LOWEST free address of the range — host B, i.e.
 * GUEST 0 — which every ±B conversion and every guest NULL test would read as
 * NULL.  Upstream gets this for free because guest == host there. */
#define IOS_WOW_GUEST_FLOOR ((ULONG_PTR)0x110000)

void ios_wow_translate_limits( ULONG_PTR *limit_low, ULONG_PTR *limit_high )
{
    ULONG_PTR base = ios_wow_base(), low, high;

    if (!base) return;
    /* Only a ceiling below 4 GB is a guest-namespace number; 0 means
     * "unconstrained" (the 64-bit half of the process, which must keep
     * getting host addresses outside the window) and anything >= 4 GB is
     * already a host address. */
    if (!*limit_high || *limit_high >= IOS_WOW_WINDOW_SIZE) return;
    high = *limit_high;
    low  = (*limit_low < IOS_WOW_WINDOW_SIZE) ? *limit_low : 0;
    /* raise the floor, but never invert the caller's range */
    if (low < IOS_WOW_GUEST_FLOOR && high > IOS_WOW_GUEST_FLOOR) low = IOS_WOW_GUEST_FLOOR;
    *limit_low  = base + low;
    *limit_high = base + high;
}

/* A host placement ceiling may itself lie inside the current window (a third
 * slot below the furniture ceiling).  Testing only limit_high would then admit
 * native ARM64 images into the guest reservation.  A translated guest request
 * has BOTH bounds inside its own window; a host request spanning from
 * address_space_start to that ceiling does not.  MADEIRA_WOW_STRICT_LIMITS=0
 * restores the limit_high-only test. */
static int ios_wow_limits_in_window( ULONG_PTR low, ULONG_PTR high )
{
    ULONG_PTR base = ios_wow_base();
    int old_match = high && ios_wow_in_window( (void *)high );
    int match = old_match && low >= base && low <= high;
    static int enabled = -1;
    int policy = __atomic_load_n( &enabled, __ATOMIC_ACQUIRE );

    if (policy < 0)
    {
        const char *s = getenv( "MADEIRA_WOW_STRICT_LIMITS" );
        policy = !(s && !strcmp( s, "0" ));
        __atomic_store_n( &enabled, policy, __ATOMIC_RELEASE );
    }
    return policy ? match : old_match;
}

/***********************************************************************
 *           ios_laa_forced / ios_wow_ceiling_for_charact
 *
 * LARGE-ADDRESS-AWARE BY DEFAULT (the policy some Wine distributions ship as
 * WINE_LARGE_ADDRESS_AWARE=1 for 32-bit programs).
 *
 * WHY.  A non-large-address-aware image gets a 2 GB user space on Windows, and
 * a large 32-bit program fits in it THERE.  It does not fit here, because this
 * port spends guest VA that Windows does not:
 *   - Wine's builtin i386 DLL images (the farm has hundreds of modules and a
 *     large fraction of them load) all live inside [B, B+2G);
 *   - guest-visible allocations made on the program's behalf by emulated
 *     graphics frontends;
 *   - plus the fragmentation all of that leaves behind.
 * The observed end state is the [va-scan] FAILED triple (16 -> 8 -> 4 MB
 * fallbacks, maxgap=0x3c0000) followed by the CRT's exit(3).
 *
 * WHAT.  A 32-bit main image that does NOT carry IMAGE_FILE_LARGE_ADDRESS_AWARE
 * is given the full 4 GB window as its user space anyway.  MADEIRA_LAA=0 (env;
 * set in madeira.cfg) restores the 2 GB ceiling
 * for an A/B, because the risk this policy takes is real and generic: code that
 * stores a pointer in a signed int, or tests `if ((int)p < 0)`, breaks above
 * 0x80000000.  That is exactly the trade Proton makes by default.
 *
 * WHAT STAYS LOW regardless (unchanged by this policy, and deliberately so):
 * the first TEB block and the PEB32/TEB32 derived from it (virtual_alloc_teb
 * and the first-block allocation both hardcode limit_2g - 1), the
 * KUSER_SHARED_DATA emulation at guest 0x7ffe0000, and the process heap's first
 * segment (it is reserved before anything pushes past 2 GB, and nothing here
 * moves it).  Windows keeps the TEB low even for an LAA program, so this is the
 * same shape, not a concession.
 */
static BOOL ios_laa_forced(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        const char *e = getenv( "MADEIRA_LAA" );
        cached = !(e && *e && atoi( e ) == 0);
    }
    return cached;
}

/***********************************************************************
 *           ios_wow_laa_synth / ios_wow_laa_low_first / ios_wow_laa_high_images
 *
 * ml1070: A RAISED CEILING IS NOT A LICENCE TO PLACE HIGH.
 *
 * ios_laa_forced() above raises the user-space ceiling for an image whose own
 * header does NOT carry IMAGE_FILE_LARGE_ADDRESS_AWARE.  That is a deliberate
 * compatibility trade and it stays.  What did NOT follow from it, and was
 * nevertheless taken, is the second half: once the ceiling moves to 4 GB,
 * wow64.dll's default_zero_bits becomes `HighestUserAddress | 0x7fffffff` ==
 * 0xffffffff, so EVERY unhinted guest allocation — and in particular every
 * MEM_TOP_DOWN reserve, whose whole meaning is "as high as you can" — is now
 * searched from the top of the 4 GB window DOWN.  A program that never claimed
 * to handle a pointer with bit 31 set is then handed one for its main arena.
 *
 * On Windows the two halves are the same decision because the flag is the
 * program's own promise.  Here the promise is synthesised, so they have to be
 * separated:
 *
 *   - the CEILING stays raised: the address space is there when the low half
 *     genuinely runs out, which is the failure the policy was written for
 *     (16 -> 8 -> 4 MB fallbacks against a 3.75 MB largest gap);
 *   - the PLACEMENT prefers the low half: map_view() tries [floor, 2 GB) first
 *     for a kernel-pick inside the window and only spills above 0x80000000
 *     when the low half cannot serve the request.
 *
 * So a program that fits below 2 GB — every non-LAA program on Windows, by
 * construction — sees exactly the address space it was built for, and one that
 * does not still gets the extra half instead of dying.  No image, no title and
 * no allocation size appears anywhere in this rule.
 *
 * ios_wow_laa_synth is set from the ONE place that identifies the main image
 * (ios_wow_image_ceiling) and re-affirmed at init_peb; it is a session global
 * for the same reason user_space_wow_limit is, and is reset with it.
 *
 * Knobs: MADEIRA_LAA_LOWFIRST=0 restores the pre-ml1070 placement (high half
 * open to the program from the first allocation).  MADEIRA_LAA_HIGH_IMAGES=0
 * additionally keeps Wine's builtin images out of the high half, which is the
 * other half of the A/B: with it off, guest 32-bit ntdll goes back to a low
 * base and NOTHING in the window has bit 31 set.
 */
static int ios_wow_laa_synth;      /* the 4 GB ceiling was synthesised, not declared */

static void ios_wow_note_laa( WORD charact )
{
    ios_wow_laa_synth = !(charact & IMAGE_FILE_LARGE_ADDRESS_AWARE) && ios_laa_forced();
}

static BOOL ios_wow_laa_low_first(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        const char *e = getenv( "MADEIRA_LAA_LOWFIRST" );
        cached = !(e && *e && atoi( e ) == 0);
    }
    return cached;
}

static BOOL ios_wow_laa_high_images(void)
{
    static int cached = -1;

    if (cached < 0)
    {
        const char *e = getenv( "MADEIRA_LAA_HIGH_IMAGES" );
        cached = !(e && *e && atoi( e ) == 0);
    }
    return cached;
}

/* The guest user-space ceiling (inclusive) implied by an image's
 * characteristics, with the policy above applied.  Both places that used to
 * spell out "(charact & LARGE_ADDRESS_AWARE) ? limit_4g : limit_2g" now call
 * this, so ios_wow_image_ceiling() (which publishes before init_peb) and
 * virtual_set_large_address_space() (which publishes at init_peb) can never
 * disagree about the same image. */
static ULONG_PTR ios_wow_ceiling_for_charact( WORD charact )
{
    BOOL laa = !!(charact & IMAGE_FILE_LARGE_ADDRESS_AWARE);

    if (!laa && ios_laa_forced())
    {
        static int said;

        if (!said++)
            dprintf( 2, "[laa] 32-bit image is not large-address-aware; user space raised to 4 GB "
                        "(MADEIRA_LAA=0 keeps 2 GB)\n" );
        laa = TRUE;
    }
    return (laa ? limit_4g : limit_2g) - 1;
}

/***********************************************************************
 *           ios_wow_image_ceiling
 *
 * The GUEST 32-bit user-space ceiling to place an image under.
 *
 * user_space_wow_limit is normally published by
 * virtual_set_large_address_space(), which init_peb() calls — but the main
 * image is MAPPED BEFORE that: load_main_exe() runs inside
 * build_initial_params(), and init_peb() only follows it.  Third device run:
 * map_image_view()'s wow branch therefore computed
 * limit_high = B + get_wow_user_space_limit() = B + 0 == limit_low, and
 * map_view() rejected that on its "limit_high && limit_low >= limit_high"
 * test — so a perfectly good i386 main image failed to map with
 * STATUS_INVALID_PARAMETER (0xc000000d) and the loader punted to start.exe.
 *
 * So derive the ceiling from the image that defines it, with exactly the rule
 * virtual_set_large_address_space() applies later (large-address-aware -> 4 GB,
 * else 2 GB, minus one), and PUBLISH it, so every later consumer — TEB blocks,
 * the 32-bit stack, HighestUserAddress, every zero_bits translation — agrees
 * with the placement we just made.  Both computations then produce the same
 * number for the same image.
 *
 * WHICH image defines it: the main image.  A 32-bit non-DLL image mapped while
 * the limit is still unpublished IS the main image (a windowed pseudo-process
 * runs exactly one program image, and it has a window precisely because that
 * image is 32-bit).  A 32-bit DLL mapped that early — a child's 32-bit ntdll,
 * loaded before its exe — is NOT, so it gets the conservative 2 GB and
 * publishes nothing: raising the ceiling for a non-LAA program is the bug,
 * never lowering it for anyone.
 */
static ULONG_PTR ios_wow_image_ceiling( const struct pe_image_info *image_info )
{
    ULONG_PTR ceiling = get_wow_user_space_limit();
    WORD charact;
    BOOL is_main;

    if (ceiling) return ceiling;      /* already published: everybody agrees */

    if (main_image_info.Machine && !is_machine_64bit( main_image_info.Machine ))
    {
        charact = main_image_info.ImageCharacteristics;   /* main image known already */
        is_main = TRUE;
    }
    else if (!(image_info->image_charact & IMAGE_FILE_DLL))
    {
        charact = image_info->image_charact;              /* this IS the main image */
        is_main = TRUE;
    }
    else
    {
        charact = 0;                                      /* too early to know: 2 GB */
        is_main = FALSE;
    }

    /* A DLL mapped before the main image ("too early to know", charact == 0)
     * keeps the conservative 2 GB and publishes nothing — the LAA policy is a
     * statement about the PROGRAM, and raising a ceiling for an image we have
     * not identified is exactly the bug this branch exists to avoid. */
    if (!is_main) return ((limit_2g) - 1) & ~granularity_mask;

    ceiling = ios_wow_ceiling_for_charact( charact );
    user_space_wow_limit = ceiling;
    ios_wow_note_laa( charact );          /* ml1070: synthesised vs declared */
    ERR( "[wow-limit] published guest 32-bit ceiling %p from the main image "
         "(machine %04x characteristics %04x large-address-aware=%d forced-laa=%d) before init_peb\n",
         (void *)ceiling, image_info->machine, charact,
         !!(charact & IMAGE_FILE_LARGE_ADDRESS_AWARE),
         !(charact & IMAGE_FILE_LARGE_ADDRESS_AWARE) && ios_laa_forced() );
    return get_wow_user_space_limit();
}

/* Clamp [*start, *end) off the reserved slot [wb, we).  Keep the side BELOW
 * the slot whenever there is one: the side above the lowest slots is the
 * [cage] holdback, which no furniture can use.  Advisory: map_view drops the
 * clamp when it leaves no room. */
static void ios_wow_exclude_range( void **start, void **end, ULONG_PTR wb, ULONG_PTR we )
{
    if ((ULONG_PTR)*end <= wb || (ULONG_PTR)*start >= we) return;   /* no overlap */
    if ((ULONG_PTR)*start < wb) *end = (void *)wb;                  /* keep the low side */
    else if ((ULONG_PTR)*end > we) *start = (void *)we;             /* nothing below: keep the high side */
    /* else the request lies entirely inside the slot: leave it alone and let
       the caller's own fallback decide */
}

/* madeira-bcd: the part of [start, end) above every window and placeholder
 * that overlaps it (the side ios_wow_exclude_range drops). */
static void ios_wow_high_side( void *start, void *end, void **hs, void **he )
{
    ULONG_PTR lo = (ULONG_PTR)start, hi = (ULONG_PTR)end, moved;
    unsigned i;

    do
    {
        moved = 0;
        for (i = 0; i < ios_wow_window_count; i++)
        {
            ULONG_PTR wb = ios_wow_windows[i].base, we;
            if (!wb) continue;
            we = wb + ios_wow_slot_reservation( &ios_wow_windows[i] );
            if (wb < hi && we > lo) { lo = we; moved = 1; }
        }
        for (i = 0; i < ios_wow_placeholder_count; i++)
        {
            ULONG_PTR pb = ios_wow_placeholders[i].base, pe;
            if (!pb || ios_wow_placeholders[i].adopted) continue;
            pe = pb + IOS_WOW_WINDOW_SIZE + (ios_wow_placeholders[i].guard_owned ? ios_wow_guard_size() : 0);
            if (pb < hi && pe > lo) { lo = pe; moved = 1; }
        }
    } while (moved && lo < hi);
    if (lo < hi) { *hs = (void *)lo; *he = (void *)hi; }
}

/* Keep an UNCONSTRAINED kernel-pick placement out of every guest window and
 * placeholder.  A window is a Wine reserved area, so without this the ordinary
 * furniture search would hand out addresses inside a 32-bit process's window. */
static void ios_wow_exclude_windows( void **start, void **end )
{
    unsigned i, n = ios_wow_window_count;

    for (i = 0; i < n; i++)
    {
        ULONG_PTR wb = ios_wow_windows[i].base;

        if (!wb) continue;
        ios_wow_exclude_range( start, end, wb,
                               wb + ios_wow_slot_reservation( &ios_wow_windows[i] ) );
    }
    for (i = 0; i < ios_wow_placeholder_count; i++)
    {
        ULONG_PTR pb = ios_wow_placeholders[i].base;

        if (!pb || ios_wow_placeholders[i].adopted) continue;
        ios_wow_exclude_range( start, end, pb, pb + IOS_WOW_WINDOW_SIZE +
                               (ios_wow_placeholders[i].guard_owned ? ios_wow_guard_size() : 0) );
    }
}

/* ---- lazy-window policy (tests/host/check-lazy-windows.py compiles this) ---- */

/* The kernel's end of the user address map (TASK_VM_INFO.max_address), or 0
 * when the kernel does not say. */
static ULONG_PTR ios_wow_map_end(void)
{
    static ULONG_PTR kern_max;      /* 0 = not asked yet, 1 = unavailable */

    if (!kern_max)
    {
        task_vm_info_data_t vmi;
        mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;

        kern_max = 1;
        if (task_info( mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &cnt ) == KERN_SUCCESS &&
            vmi.max_address >= 0x100000000ULL)
            kern_max = (ULONG_PTR)vmi.max_address;
    }
    return kern_max > 1 ? kern_max : 0;
}

static unsigned long ios_wow_env_ulong( const char *name, unsigned long dflt )
{
    const char *e = getenv( name );
    return (e && *e) ? strtoul( e, NULL, 10 ) : dflt;
}

/***********************************************************************
 *           ios_wow_band
 *
 * The range guest-window candidates are drawn from.
 *
 * With a 512 GB user map this is the furniture band [ios_usable_va_floor,
 * ios_furniture_ceiling) capped below the CEF pools.  A device without that
 * much address space (TASK_VM_INFO.max_address = 0xfc0000000, 63 GB, on a
 * tablet without the extended-virtual-addressing entitlement) has no such band
 * at all.  Nothing about a guest window needs a HIGH address: FEX forms host
 * addresses as B + zext32(EA), so B only has to be 4 GB-aligned.  On such a
 * map candidates come from the low band [16 GB, 44 GB): above the image, the
 * malloc zones, the shared cache and the JIT pool's RW alias (all below
 * 16 GB), below the FEX host arena at 48 GB, and clear of the top-down
 * furniture that packs down from the end of the map.
 *
 * ios_wow_small_va_slots is then the MAXIMUM number of windows alive at once
 * (MADEIRA_WOW_SMALL_VA_SLOTS, default 2): windows are reserved one at a time,
 * when a 32-bit process starts, never ahead of time.  0 on a large map.
 */
static unsigned ios_wow_small_va_slots;
static void ios_wow_band( ULONG_PTR *floor, ULONG_PTR *ceil )
{
    static int announced;
    ULONG_PTR kern_max = ios_wow_map_end();

    *floor = ios_usable_va_floor;
    *ceil  = ios_furniture_ceiling ? ios_furniture_ceiling : (ULONG_PTR)user_space_limit;
    if (*ceil > IOS_WOW_CEF_POOLS_START) *ceil = IOS_WOW_CEF_POOLS_START;

    if (kern_max && kern_max < *floor + IOS_WOW_WINDOW_SIZE)
    {
        ULONG_PTR top = kern_max & ~(IOS_WOW_WINDOW_SIZE - 1);
        ULONG_PTR lo  = (ULONG_PTR)0x400000000ULL;                      /* 16 GB */
        ULONG_PTR hi  = top > 2 * IOS_WOW_WINDOW_SIZE ? top - 2 * IOS_WOW_WINDOW_SIZE : 0;
        unsigned long want = ios_wow_env_ulong( "MADEIRA_WOW_SMALL_VA_SLOTS", 2 );

        if (want < 1) want = 1;
        if (want > IOS_WOW_MAX_WINDOWS) want = IOS_WOW_MAX_WINDOWS;
        ios_wow_small_va_slots = (unsigned)want;
        if (hi > (ULONG_PTR)0xb00000000ULL) hi = (ULONG_PTR)0xb00000000ULL;   /* 44 GB */
        if (hi > lo + IOS_WOW_WINDOW_SIZE)
        {
            *floor = lo;
            *ceil  = hi;
        }
        if (!announced)
        {
            announced = 1;
            dprintf( 2, "[wow-window] small address map: it ends at %p, below the normal "
                        "guest-window band -- candidates come from [%p,%p), at most %u window(s) "
                        "at once\n", (void *)kern_max, (void *)*floor, (void *)*ceil,
                     ios_wow_small_va_slots );
        }
    }
}

/* Free VA in [4 GB, map_end): the sum of the holes between regions. */
static ULONG_PTR ios_wow_free_va( ULONG_PTR map_end )
{
    mach_vm_address_t addr = (mach_vm_address_t)0x100000000ULL;
    ULONG_PTR free_bytes = 0;
    unsigned regions = 0;

    while (addr < map_end && regions++ < 1000000)
    {
        mach_vm_address_t a = addr;
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;

        if (mach_vm_region( mach_task_self(), &a, &size, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS || a >= map_end)
        {
            free_bytes += map_end - addr;              /* free to the end of the map */
            break;
        }
        if (a > addr) free_bytes += a - addr;
        addr = a + size;
    }
    return free_bytes;
}

/* SMALL-MAP RULE: may this session take (another) 4 GB window?
 *
 * A window is refused, cleanly and once-logged, when the map is smaller than
 * MADEIRA_WOW_MIN_MAP_GB (default 48), or when taking it would leave less than
 * MADEIRA_WOW_MIN_FREE_GB (default 8) of free VA outside it.  The 32-bit
 * process then fails to start with STATUS_NO_MEMORY instead of squeezing the
 * 64-bit side of the session.  An unknown map size is not a reason to refuse:
 * the reservation itself then decides. */
static int ios_wow_map_allows_window(void)
{
    ULONG_PTR map_end = ios_wow_map_end();
    ULONG_PTR min_map, min_free, free_va;

    if (!map_end) return 1;
    min_map  = (ULONG_PTR)ios_wow_env_ulong( "MADEIRA_WOW_MIN_MAP_GB", 48 ) << 30;
    min_free = (ULONG_PTR)ios_wow_env_ulong( "MADEIRA_WOW_MIN_FREE_GB", 8 ) << 30;
    if (map_end < min_map)
    {
        dprintf( 2, "[wow-window] refused: map too small (ends at %p, MADEIRA_WOW_MIN_MAP_GB=%lu)\n",
                 (void *)map_end, (unsigned long)(min_map >> 30) );
        return 0;
    }
    free_va = ios_wow_free_va( map_end );
    if (free_va < IOS_WOW_WINDOW_SIZE + min_free)
    {
        dprintf( 2, "[wow-window] refused: map too small (%lu MB free VA; a window needs 4096 MB "
                    "plus MADEIRA_WOW_MIN_FREE_GB=%lu left over)\n",
                 (unsigned long)(free_va >> 20), (unsigned long)(min_free >> 30) );
        return 0;
    }
    return 1;
}

/* One slot below the FEX band's start: the top of the spill range. */
static int ios_wow_spill_walk;
#define IOS_WOW_SPILL_TOP ((ULONG_PTR)0x7b00000000)

static int ios_wow_band_ok( ULONG_PTR base, ULONG_PTR total )
{
    if (ios_wow_spill_walk)
        return base >= IOS_WOW_CEF_POOLS_START && base + total <= IOS_WOW_SPILL_TOP;
    if (base < IOS_WOW_CEF_POOLS_START && base + total > IOS_WOW_CEF_POOLS_START)
        return 0;   /* would cross into the CEF pools / FEX band */
    if (base >= IOS_WOW_CEF_POOLS_START && base < IOS_WOW_FEX_BAND_END) return 0;
    return 1;
}

/* Is [addr, addr+len) ALREADY covered by an existing region that no access can
 * touch?  A failed fixed mapping is not evidence (it says the VA is taken, not
 * that it is inaccessible), so query the region and require it to exist, to
 * contain addr and to carry protection VM_PROT_NONE. */
static int ios_wow_guard_neighbour_blocked( ULONG_PTR addr, ULONG_PTR len )
{
    mach_vm_address_t a = (mach_vm_address_t)addr;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;

    if (mach_vm_region( mach_task_self(), &a, &size, VM_REGION_BASIC_INFO_64,
                        (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS)
        return 0;                                   /* free to the end of the VA */
    if (a > (mach_vm_address_t)addr) return 0;      /* free hole at addr */
    if (info.protection != VM_PROT_NONE) return 0;  /* accessible neighbour */
    return a + size >= (mach_vm_address_t)addr + len;
}

/* A combined 4GB+page mapping may be refused even when the two pieces can
 * be reserved separately. Own the guard first, without replacing any live
 * mapping, then reserve the exact window. Publish only the complete pair;
 * a failed window attempt must release only the guard we just acquired.
 * Return -1 if cleanup failed, so the caller cannot borrow our leaked guard. */
static int ios_wow_window_try_separate_guard( ULONG_PTR base, ULONG_PTR guard )
{
    void *guard_base;

    if (guard > ~(ULONG_PTR)0 - IOS_WOW_WINDOW_SIZE ||
        base > ~(ULONG_PTR)0 - IOS_WOW_WINDOW_SIZE - guard ||
        !ios_wow_band_ok( base, IOS_WOW_WINDOW_SIZE + guard )) return 0;
    guard_base = (void *)(base + IOS_WOW_WINDOW_SIZE);
    if (anon_mmap_tryfixed( guard_base, guard, PROT_NONE, MAP_NORESERVE ) == MAP_FAILED)
        return 0;
    if (anon_mmap_tryfixed( (void *)base, IOS_WOW_WINDOW_SIZE,
                            PROT_NONE, MAP_NORESERVE ) == MAP_FAILED)
    {
        if (munmap( guard_base, guard ))
        {
            dprintf( 2, "[wow-window] B=%p: failed to release own guard page at %p: errno=%d\n",
                     (void *)base, guard_base, errno );
            return -1;
        }
        return 0;
    }
    mmap_add_reserved_area( (void *)base, IOS_WOW_WINDOW_SIZE + guard );
    dprintf( 2, "[wow-window] B=%p: reserved 4GB + own guard page in separate mappings (+0x%llx)\n",
             (void *)base, (unsigned long long)guard );
    return 1;
}

static int ios_wow_window_try( ULONG_PTR base, unsigned *guard_owned )
{
    ULONG_PTR guard = ios_wow_guard_size();
    struct ios_wow_placeholder *ph;
    struct ios_wow_window *slot;
    char what[256];
    int separate;

    *guard_owned = 0;
    if (base > ~(ULONG_PTR)0 - IOS_WOW_WINDOW_SIZE - guard) return 0;
    if (!ios_wow_band_ok( base, IOS_WOW_WINDOW_SIZE )) return 0;

    /* A slot still owned by a registry entry (live, dead-awaiting-teardown or
     * leaked) may not be handed to a second process. */
    if ((slot = ios_wow_slot_at_base( base )))
    {
        dprintf( 2, "[wow-window] B=%p REJECTED: the slot is %s\n", (void *)base,
                 slot->dead ? "still held by an exited process whose teardown did not complete" :
                 slot->leaked ? "abandoned by a process that is still alive inside it" :
                 "in use by a running 32-bit process" );
        return 0;
    }

    /* ADOPT the placeholder for this slot, if there is one.  Taking ownership
     * is all that happens: unmapping to remap would open the hole the
     * placeholder exists to keep. */
    if ((ph = ios_wow_placeholder_find( base )))
    {
        if (ph->adopted)
        {
            dprintf( 2, "[wow-window] B=%p REJECTED: its placeholder is already adopted\n",
                     (void *)base );
            return 0;
        }
        ph->adopted = 1;
        *guard_owned = ph->guard_owned;
        dprintf( 2, "[wow-window] adopted placeholder B=%p..%p guard=%s\n",
                 (void *)base, (void *)(base + IOS_WOW_WINDOW_SIZE),
                 ph->guard_owned ? "owned" : "borrowed" );
        return 1;
    }

    /* preferred: the 4 GB window plus our own guard page */
    if (ios_wow_band_ok( base, IOS_WOW_WINDOW_SIZE + guard ) &&
        anon_mmap_tryfixed( (void *)base, IOS_WOW_WINDOW_SIZE + guard,
                            PROT_NONE, MAP_NORESERVE ) != MAP_FAILED)
    {
        mmap_add_reserved_area( (void *)base, IOS_WOW_WINDOW_SIZE + guard );
        *guard_owned = 1;
        dprintf( 2, "[wow-window] B=%p: reserved 4GB + own guard page (+0x%llx)\n",
                 (void *)base, (unsigned long long)guard );
        return 1;
    }

    separate = ios_wow_window_try_separate_guard( base, guard );
    if (separate < 0) return 0;
    if (separate)
    {
        *guard_owned = 1;
        return 1;
    }

    /* an exactly-4GB gap: borrow the guard from the neighbour if — and only
     * if — the neighbour is already inaccessible */
    if (!ios_wow_guard_neighbour_blocked( base + IOS_WOW_WINDOW_SIZE, guard ))
    {
        ios_va_describe_range( (void *)base, IOS_WOW_WINDOW_SIZE, what, sizeof(what) );
        dprintf( 2, "[wow-window] B=%p: window body after failed reservations (%s)\n", (void *)base, what );
        ios_va_describe_range( (void *)(base + IOS_WOW_WINDOW_SIZE), guard, what, sizeof(what) );
        dprintf( 2, "[wow-window] B=%p REJECTED: 4GB+guard unavailable and the page at "
                    "%p is not an inaccessible neighbour (%s)\n",
                 (void *)base, (void *)(base + IOS_WOW_WINDOW_SIZE), what );
        return 0;
    }
    if (anon_mmap_tryfixed( (void *)base, IOS_WOW_WINDOW_SIZE,
                            PROT_NONE, MAP_NORESERVE ) == MAP_FAILED)
    {
        ios_va_describe_range( (void *)base, IOS_WOW_WINDOW_SIZE, what, sizeof(what) );
        dprintf( 2, "[wow-window] B=%p REJECTED: the 4GB range is not free (%s)\n",
                 (void *)base, what );
        return 0;
    }
    mmap_add_reserved_area( (void *)base, IOS_WOW_WINDOW_SIZE );
    dprintf( 2, "[wow-window] B=%p: reserved exactly 4GB; guard BORROWED from the "
                "pre-existing PROT_NONE region at %p\n",
             (void *)base, (void *)(base + IOS_WOW_WINDOW_SIZE) );
    return 1;
}

/* The lowest 4 GB-aligned slot a future 32-bit pseudo-process could still take,
 * or 0.  Same candidate rule as ios_wow_window_pick().
 *
 * Device evidence: the [cage] holdback leaves exactly ONE 4 GB-aligned
 * candidate in the furniture band, and MEM_TOP_DOWN placements (the session TEB
 * block first of all) go to the very top of what is left, i.e. into that
 * candidate; about 60 MB of furniture then made every later 32-bit child
 * unstartable.  So once the session is ARMED, map_view keeps top-down furniture
 * below the candidate (ios_wow_bias_end).  Never consulted before that. */
static ULONG_PTR ios_wow_candidate_slot(void)
{
    ULONG_PTR floor, ceil;
    ULONG_PTR cand;
    unsigned i, n;

    ios_wow_band( &floor, &ceil );
    if (ceil <= floor || ceil - floor < IOS_WOW_WINDOW_SIZE) return 0;

    n = ios_wow_window_count;
    for (cand = (floor + IOS_WOW_WINDOW_SIZE - 1) & ~(IOS_WOW_WINDOW_SIZE - 1);
         cand >= floor && cand + IOS_WOW_WINDOW_SIZE <= ceil;
         cand += IOS_WOW_WINDOW_SIZE)
    {
        int taken = 0;
        unsigned p;

        /* windows and placeholders are real reservations, excluded by
         * ios_wow_exclude_windows(); nothing left for the bias to protect */
        for (i = 0; i < n; i++)
            if (ios_wow_windows[i].base == cand) { taken = 1; break; }
        for (p = 0; p < ios_wow_placeholder_count && !taken; p++)
            if (ios_wow_placeholders[p].base == cand) taken = 1;
        if (!taken) return cand;
    }
    return 0;
}

/* map_view's top-down bias: the end of a top-down kernel pick, lowered below
 * the free candidate slot.  Only while the session is armed: a 64-bit-only
 * session gets `end` back unchanged and the band is never looked at. */
static void *ios_wow_bias_end( void *start, void *end )
{
    ULONG_PTR cand;

    if (!ios_wow_session_armed()) return end;
    cand = ios_wow_candidate_slot();
    if (cand && (void *)cand > start && (void *)cand < end) return (void *)cand;
    return end;
}

/***********************************************************************
 *           ios_wow_carve_holdback_slots
 *
 * A SECOND CONCURRENT 32-bit process: take a slot out of the [cage] holdback.
 *
 * The furniture band [0x7038000000, 0x73ffff0000) holds two 4 GB-aligned slots
 * that fit whole, 0x7100000000 and 0x7200000000, and the [cage] holdback
 * (8 GB - 64 KB from 0x7200000000, reserved in virtual_init for a V8/cppgc
 * reservation) covers the second.  A launcher that starts a 32-bit program
 * needs two windows at once.  This runs from ios_wow_window_pick() only after
 * every ordinary candidate has been refused, only while another 32-bit process
 * is alive, and only while nobody has asked for the holdback: a session that
 * never runs two concurrent 32-bit processes never reaches it, and the holdback
 * is never shrunk when no 32-bit process exists.
 *
 * WHAT IS CARVED.  One MAP_FIXED PROT_NONE replacement over VA the holdback
 * already owns (no munmap, so the kernel never sees a hole) plus a Wine
 * reserved area, recorded as an unadopted placeholder that the normal path
 * then adopts.  The guard page at B+4 GB is borrowed from the holdback
 * remainder, which stays PROT_NONE.  ios_cage_holdback_live is cleared: the
 * holdback is no longer contiguous and the grant path munmaps the whole range,
 * which would now remove a live guest window.
 *
 * Returns the lowest slot carved, or 0.  Called with ios_wow_mutex held. */
static ULONG_PTR ios_wow_carve_holdback_slots(void)
{
    ULONG_PTR floor  = ios_usable_va_floor;
    ULONG_PTR ceil   = ios_furniture_ceiling ? ios_furniture_ceiling : (ULONG_PTR)user_space_limit;
    ULONG_PTR guard  = ios_wow_guard_size();
    ULONG_PTR hb_end = IOS_CAGE_BASE + IOS_CAGE_REAL_SIZE;
    ULONG_PTR first  = 0;
    ULONG_PTR cand;
    unsigned made = 0;

    if (!ios_cage_holdback_live || !ios_wow_live_window_count()) return 0;
    if (ceil > IOS_WOW_CEF_POOLS_START) ceil = IOS_WOW_CEF_POOLS_START;

    for (cand = IOS_CAGE_BASE; cand + IOS_WOW_WINDOW_SIZE + guard <= hb_end;
         cand += IOS_WOW_WINDOW_SIZE)
    {
        if (cand < floor || cand + IOS_WOW_WINDOW_SIZE > ceil) continue;
        if (!ios_wow_band_ok( cand, IOS_WOW_WINDOW_SIZE )) continue;
        if (ios_wow_slot_at_base( cand ) || ios_wow_placeholder_find( cand )) continue;
        if (ios_wow_placeholder_count >= IOS_WOW_MAX_WINDOWS) break;

        /* replace, never unmap: this VA is ours already and must stay ours */
        if (anon_mmap_fixed( (void *)cand, IOS_WOW_WINDOW_SIZE, PROT_NONE, MAP_NORESERVE ) == MAP_FAILED)
        {
            ERR( "[cage] carve of B=%p out of the holdback FAILED (%s)\n",
                 (void *)cand, strerror(errno) );
            continue;
        }
        mmap_add_reserved_area( (void *)cand, IOS_WOW_WINDOW_SIZE );
        ios_wow_placeholders[ios_wow_placeholder_count].base        = cand;
        ios_wow_placeholders[ios_wow_placeholder_count].guard_owned = 0;
        ios_wow_placeholders[ios_wow_placeholder_count].adopted     = 0;
        ios_wow_placeholder_count++;
        if (!first) first = cand;
        made++;
        dprintf( 2, "[cage] carved guest-window slot B=%p..%p out of the holdback; its guard "
                    "page is borrowed from the holdback remainder [%p,%p)\n",
                 (void *)cand, (void *)(cand + IOS_WOW_WINDOW_SIZE),
                 (void *)(cand + IOS_WOW_WINDOW_SIZE), (void *)hb_end );
    }

    if (made)
    {
        ios_cage_holdback_live = 0;
        ios_cage_window_tail_live = 1;
        ERR( "[cage] holdback traded for %u guest-window slot(s): the 8GB V8/cppgc reservation "
             "can no longer be granted from 0x%llx this session\n",
             made, (unsigned long long)IOS_CAGE_BASE );
    }
    return first;
}

/* A launcher -> helper -> program chain needs a THIRD window.  After the carve,
 * finish the held upper half of the cage, [0x7300000000, 0x73ffff0000), on
 * demand.  The missing 64 KB and the guard are acquired together with
 * tryfixed, which refuses existing mappings (including a granted PA pool).
 * The guard stays a raw host reservation, not allocatable Wine space.
 * MADEIRA_WOW_EXTRA_WINDOW=0 disables it.  Called with ios_wow_mutex held. */
static ULONG_PTR ios_wow_extend_holdback_tail( unsigned *guard_owned )
{
    const ULONG_PTR held_end = IOS_CAGE_BASE + IOS_CAGE_REAL_SIZE;
    const ULONG_PTR base = held_end & ~(IOS_WOW_WINDOW_SIZE - 1);
    const ULONG_PTR end = base + IOS_WOW_WINDOW_SIZE;
    ULONG_PTR guard = ios_wow_guard_size();
    const char *policy = getenv( "MADEIRA_WOW_EXTRA_WINDOW" );
    struct ios_wow_placeholder *ph;

    if (policy && !strcmp( policy, "0" )) return 0;
    if (ios_wow_slot_at_base( base )) return 0;
    /* a released extra window keeps its placeholder: adopt it again */
    if ((ph = ios_wow_placeholder_find( base )))
        return !ph->adopted && ios_wow_window_try( base, guard_owned ) ? base : 0;
    if (!ios_cage_window_tail_live || ios_cage_holdback_live ||
        ios_wow_placeholder_count >= IOS_WOW_MAX_WINDOWS) return 0;
    if (anon_mmap_tryfixed( (void *)held_end, end - held_end + guard,
                            PROT_NONE, MAP_NORESERVE ) == MAP_FAILED)
    {
        dprintf( 2, "[wow-window] extra window unavailable: tail=%p size=0x%llx errno=%d\n",
                 (void *)held_end, (unsigned long long)(end - held_end + guard), errno );
        return 0;
    }
    mmap_add_reserved_area( (void *)base, IOS_WOW_WINDOW_SIZE );
    ph = &ios_wow_placeholders[ios_wow_placeholder_count++];
    ph->base = base;
    ph->guard_owned = 1;
    ph->adopted = 0;
    ios_cage_window_tail_live = 0;
    dprintf( 2, "[wow-window] extended the held cage tail: B=%p end=%p guard=0x%llx\n",
             (void *)base, (void *)end, (unsigned long long)guard );
    return ios_wow_window_try( base, guard_owned ) ? base : 0;
}

/* Give the unclaimed [cage] holdback to Wine's allocator when the band is
 * exhausted.
 *
 * The holdback is 8 GB of a ~15 GB furniture window. A session with no
 * Chromium never claims it, and a guest that reserves address space freely can
 * fill the rest, so that even a 1 MB request fails. Handing the holdback over
 * then costs nothing the session was going to use.
 *
 * Only for a failed request whose search range [start, end) could be served
 * from the holdback: anything else gains nothing from it, and the holdback
 * stays whole for the cage grant and the guest-window carve.
 *
 * WHAT IS HANDED OVER. The holdback becomes a Wine reserved area, as a guest
 * window is: the VA stays mapped PROT_NONE and ours, and map_reserved_area
 * places views in it. No munmap, so the kernel never sees a hole another
 * mapping could take. Its first host page is kept out: a guest window at
 * 0x7100000000 that found only an exact 4 GB gap borrowed its overrun guard
 * from it (ios_wow_window_try), and that page must stay inaccessible.
 * ios_cage_holdback_live is cleared, which disables the cage grant (it munmaps
 * the whole range) and the carve.
 *
 * Off unless MADEIRA_CAGE_RELEASE=1, which the app sets for a Madeira Dock
 * session (headless Steam client, no CEF). Called with virtual_mutex held.
 * Returns 1 if the holdback was handed over. */
static int ios_cage_release_on_exhaustion( void *start, void *end, size_t want )
{
    /* 1: when the guest band is exhausted, hand the unclaimed 8 GB V8 cage
     * holdback to it. Set by the app for a Madeira Dock session; off otherwise. */
    const char *e = getenv( "MADEIRA_CAGE_RELEASE" );
    const ULONG_PTR lo = IOS_CAGE_BASE + ios_wow_guard_size();
    const ULONG_PTR hi = IOS_CAGE_BASE + IOS_CAGE_REAL_SIZE;
    ULONG_PTR s = (ULONG_PTR)start > lo ? (ULONG_PTR)start : lo;
    ULONG_PTR t = (ULONG_PTR)end < hi ? (ULONG_PTR)end : hi;

    if (!ios_cage_holdback_live || !e || *e != '1') return 0;
    if (t <= s || t - s < want) return 0;
    mmap_add_reserved_area( (void *)lo, hi - lo );
    ios_cage_holdback_live = 0;
    dprintf( 2, "[cage] holdback handed to the allocator [%p,%p): the band is exhausted "
                "(request 0x%lx) and no V8 cage was asked for; its first page stays a guard\n",
             (void *)lo, (void *)hi, (unsigned long)want );
    return 1;
}

static ULONG_PTR ios_wow_window_pick( unsigned *guard_owned )
{
    ULONG_PTR floor, ceil;
    ULONG_PTR cand;

    ios_wow_band( &floor, &ceil );
    if (ceil <= floor || ceil - floor < IOS_WOW_WINDOW_SIZE) return 0;

    /* 4 GB-aligned only, lowest first.  B must be 4 GB-aligned: FEX forms host
     * addresses as [Xbase, Wea, UXTW], i.e. B + zext32(EA), which is only safe
     * against a 32-bit wrap at the top of the window when the low 32 bits of B
     * are zero. */
    for (cand = (floor + IOS_WOW_WINDOW_SIZE - 1) & ~(IOS_WOW_WINDOW_SIZE - 1);
         cand >= floor && cand + IOS_WOW_WINDOW_SIZE <= ceil;
         cand += IOS_WOW_WINDOW_SIZE)
        if (ios_wow_window_try( cand, guard_owned )) return cand;

    /* the band is out of slots: a concurrent 32-bit process may trade the
     * [cage] holdback for one (see ios_wow_carve_holdback_slots) */
    if ((cand = ios_wow_carve_holdback_slots()) && ios_wow_window_try( cand, guard_owned ))
        return cand;
    if ((cand = ios_wow_extend_holdback_tail( guard_owned ))) return cand;

    /* Still nothing: a 32-bit client with several 32-bit helpers can need more
     * windows than the band holds.  [0x7400000000, 0x7c00000000) is kept for a
     * 64-bit Chromium's PartitionAlloc pools, which a 32-bit client does not
     * use.  Spill into it top-down from 0x7a when the band is full; each slot
     * is checked free before it is taken, so pools already there are kept.
     * MADEIRA_WOW_SPILL_CEF=0 disables this. */
    {
        const char *e = getenv( "MADEIRA_WOW_SPILL_CEF" );
        if (!(e && e[0] == '0') && ceil <= IOS_WOW_CEF_POOLS_START && floor >= (ULONG_PTR)0x7000000000ULL)
        {
            ios_wow_spill_walk = 1;
            for (cand = IOS_WOW_SPILL_TOP - IOS_WOW_WINDOW_SIZE; cand >= IOS_WOW_CEF_POOLS_START;
                 cand -= IOS_WOW_WINDOW_SIZE)
            {
                if (ios_wow_window_try( cand, guard_owned ))
                {
                    ios_wow_spill_walk = 0;
                    dprintf( 2, "[wow-window] band full: spilled into the Chromium pool range "
                                "B=%p..%p (MADEIRA_WOW_SPILL_CEF=0 disables)\n",
                             (void *)cand, (void *)(cand + IOS_WOW_WINDOW_SIZE) );
                    return cand;
                }
            }
            ios_wow_spill_walk = 0;
        }
    }

    ERR( "[wow-window] no free 4GB-aligned slot in [%p,%p): a 32-bit process cannot start; "
         "the REJECTED lines above say what is in each candidate\n", (void *)floor, (void *)ceil );
    return 0;
}

/* Reserve up to `max` placeholders from the band, lowest first.  Called from
 * virtual_init (ios_wow_session_start) only, before any furniture exists. */
static void ios_wow_reserve_placeholders( unsigned max )
{
    ULONG_PTR floor, ceil;
    ULONG_PTR cand;

    ios_wow_band( &floor, &ceil );
    if (ceil <= floor || ceil - floor < IOS_WOW_WINDOW_SIZE) return;
    if (ios_wow_small_va_slots && max > ios_wow_small_va_slots) max = ios_wow_small_va_slots;

    pthread_mutex_lock( &ios_wow_mutex );
    for (cand = (floor + IOS_WOW_WINDOW_SIZE - 1) & ~(IOS_WOW_WINDOW_SIZE - 1);
         cand >= floor && cand + IOS_WOW_WINDOW_SIZE <= ceil;
         cand += IOS_WOW_WINDOW_SIZE)
    {
        unsigned guard_owned = 0;

        if (ios_wow_placeholder_count >= max || ios_wow_placeholder_count >= IOS_WOW_MAX_WINDOWS)
            break;
        if (!ios_wow_window_try( cand, &guard_owned )) continue;
        ios_wow_placeholders[ios_wow_placeholder_count].base        = cand;
        ios_wow_placeholders[ios_wow_placeholder_count].guard_owned = guard_owned;
        ios_wow_placeholders[ios_wow_placeholder_count].adopted     = 0;
        ios_wow_placeholder_count++;
        dprintf( 2, "[wow-window] placeholder reserved B=%p..%p (guard %s)\n",
                 (void *)cand, (void *)(cand + IOS_WOW_WINDOW_SIZE),
                 guard_owned ? "owned" : "borrowed" );
    }
    pthread_mutex_unlock( &ios_wow_mutex );
}

/***********************************************************************
 *           ios_wow_session_start
 *
 * virtual_init's hook, the last thing it does (after the [cage] holdback,
 * which the first slot borrows its guard page from).
 *
 *  - default, 64-bit main image: NOTHING.  No window and no placeholder is
 *    reserved and the session is not armed, so a 64-bit-only session keeps
 *    every byte of its address map (a small map loses nothing to 32-bit
 *    support that will never run).
 *  - 32-bit main image (ios_main_image_i386, published by the app): arm and
 *    reserve ONE placeholder for it, now, before the system frameworks can
 *    take the slot.  start_main_thread then adopts it.
 *  - MADEIRA_WOW_PLACEHOLDERS=1: arm and reserve a placeholder for every slot
 *    of the band (on a small map at most MADEIRA_WOW_SMALL_VA_SLOTS), for
 *    64-bit launchers that start 32-bit children on a crowded map.
 */
static void ios_wow_session_start(void)
{
    unsigned want;

    if (ios_wow_env_ulong( "MADEIRA_WOW_PLACEHOLDERS", 0 ) == 1) want = IOS_WOW_MAX_WINDOWS;
    else if (ios_main_image_i386) want = 1;
    else return;

    ios_wow_session_arm();
    if (!ios_wow_map_allows_window()) return;
    ios_wow_reserve_placeholders( want );
}
/* ---- end of lazy-window policy ---- */

/* Tear a dead window down.  Defined next to delete_view(), which it needs. */
static int ios_wow_window_teardown( ULONG_PTR base, void *dead_peb, unsigned guard_owned );

/* How long after a pseudo-process's exit the teardown waits before replacing
 * its window.  Nothing joins a pseudo-process's threads on iOS, so a laggard
 * thread can still be unwinding through the window for a moment after the
 * exit.  The teardown runs from the NEXT 32-bit process's boot, so in practice
 * the interval has long passed and nothing sleeps. */
#define IOS_WOW_SETTLE_SEC 3

/* The native D3D9 frontend's per-process teardown (dxmt,
 * src/d3d9/unix/d3d9_native_glue.cpp, linked through libdxmt_combined.a).
 * Native D3D9 objects, and the Metal objects behind them, hold host pointers
 * into the dead process's window; they have to be dropped before the window
 * is replaced with PROT_NONE and handed to the next 32-bit process.
 *
 * Weak, with this default: the linker rejects a weak REFERENCE that nothing
 * defines, so the fallback is a weak definition.  DXMT's definition is strong
 * and replaces it whenever its object is linked, which it is whenever the
 * d3d9shim table below is (the table's entries call into the same object).
 * The default therefore only runs with a DXMT that has the table but not this
 * hook; it says so once instead of leaking silently. */
void __attribute__((weak)) d3d9_native_window_teardown( unsigned long window_base )
{
    static int warned;

    if (warned) return;
    warned = 1;
    dprintf( 2, "[wow-window] B=%p: this build's DXMT has no d3d9_native_window_teardown; "
                "native D3D9 objects of exited 32-bit processes are not released\n",
             (void *)window_base );
}

/* RELEASE-ON-NEXT-ADOPT, step 2: tear down every window whose owner has exited.
 *
 * Runs at the top of ios_wow_window_reserve(), on the booting thread of the
 * next 32-bit pseudo-process, with no lock held.  At exit the dying thread is
 * still standing on its own TEB inside the window it would be unmapping. */
static void ios_wow_reclaim_dead_windows(void)
{
    unsigned i;

    for (i = 0; i < IOS_WOW_MAX_WINDOWS; i++)
    {
        ULONG_PTR base;
        void *dead_peb;
        unsigned guard_owned;
        time_t released_at, now;

        pthread_mutex_lock( &ios_wow_mutex );
        if (!ios_wow_windows[i].base || ios_wow_windows[i].dead != 1)
        {
            pthread_mutex_unlock( &ios_wow_mutex );
            continue;
        }
        base        = ios_wow_windows[i].base;
        dead_peb    = ios_wow_windows[i].dead_peb;
        guard_owned = ios_wow_windows[i].guard_owned;
        released_at = ios_wow_windows[i].released_at;
        ios_wow_windows[i].dead = 2;
        pthread_mutex_unlock( &ios_wow_mutex );

        now = time( NULL );
        if (released_at && now >= released_at && now - released_at < IOS_WOW_SETTLE_SEC)
        {
            struct timespec ts;

            ts.tv_sec  = IOS_WOW_SETTLE_SEC - (now - released_at);
            ts.tv_nsec = 0;
            nanosleep( &ts, NULL );
        }

        /* Worker threads of the exited process can stay asleep long after its
         * main thread is gone; their TEBs are inside the window.  Keep it (the
         * next process takes another slot) while any of them still exists.
         * MADEIRA_WOW_LIVE_WINDOW_GUARD=0 disables the check. */
        {
            extern int ios_thread_registry_range_busy( uintptr_t base, uintptr_t size );
            const char *env = getenv( "MADEIRA_WOW_LIVE_WINDOW_GUARD" );
            if ((!env || strcmp( env, "0" )) &&
                ios_thread_registry_range_busy( base, IOS_WOW_WINDOW_SIZE ))
            {
                pthread_mutex_lock( &ios_wow_mutex );
                ios_wow_windows[i].dead = 1;
                pthread_mutex_unlock( &ios_wow_mutex );
                continue;
            }
        }

        /* Before ios_wow_window_teardown(), which replaces the range with
         * PROT_NONE and purges its JIT code: native D3D9 objects are dropped
         * first, while the memory they point into still exists.  Keyed by the
         * window base, which the registry no longer resolves from the dead
         * PEB at this point.  No lock is held here; the call is idempotent,
         * so a teardown that fails and is retried later is harmless. */
        d3d9_native_window_teardown( (unsigned long)base );

        if (!ios_wow_window_teardown( base, dead_peb, guard_owned ))
        {
            pthread_mutex_lock( &ios_wow_mutex );
            ios_wow_windows[i].dead = 1;   /* still dead, still not reclaimable */
            pthread_mutex_unlock( &ios_wow_mutex );
            continue;
        }

        pthread_mutex_lock( &ios_wow_mutex );
        /* free the registry entry and hand the reservation back to its
         * placeholder, unadopted, or drop it from the registry */
        memset( &ios_wow_windows[i], 0, sizeof(ios_wow_windows[i]) );
        {
            struct ios_wow_placeholder *ph = ios_wow_placeholder_find( base );
            if (ph) ph->adopted = 0;
            else
            {
                /* no placeholder: keep the PROT_NONE reservation as one, so the
                 * slot is not handed back to the kernel (the teardown replaced
                 * it in place and it is still a Wine reserved area) */
                if (ios_wow_placeholder_count < IOS_WOW_MAX_WINDOWS)
                {
                    ph = &ios_wow_placeholders[ios_wow_placeholder_count++];
                    ph->base = base;
                    ph->guard_owned = guard_owned;
                    ph->adopted = 0;
                }
            }
        }
        pthread_mutex_unlock( &ios_wow_mutex );
    }
}

/***********************************************************************
 *           ios_wow_window_reserve
 *
 * Reserve a guest window for the calling thread (the boot thread of a 32-bit
 * pseudo-process).  Idempotent per thread: one window per process, never more.
 * Refused with STATUS_NO_MEMORY when the address map cannot afford one (see
 * ios_wow_map_allows_window) or, on a small map, when the maximum number of
 * concurrent windows is already alive.
 */
NTSTATUS ios_wow_window_reserve(void)
{
    struct ios_wow_window *slot = NULL;
    unsigned guard_owned = 0, held = 0;
    ULONG_PTR base, floor, ceil;
    unsigned i;

    ios_wow_session_arm();

    /* give back what a previous 32-bit pseudo-process left behind first —
     * this is what makes launcher -> program work */
    ios_wow_reclaim_dead_windows();

    pthread_mutex_lock( &ios_wow_mutex );
    if (ios_wow_slot_current())
    {
        pthread_mutex_unlock( &ios_wow_mutex );
        return STATUS_SUCCESS;   /* already have one */
    }
    for (i = 0; i < IOS_WOW_MAX_WINDOWS; i++)
    {
        if (ios_wow_windows[i].base) held++;
        else if (!slot) slot = &ios_wow_windows[i];
    }
    if (!slot)
    {
        pthread_mutex_unlock( &ios_wow_mutex );
        ERR( "[wow-window] registry full, cannot reserve a guest window\n" );
        return STATUS_NO_MEMORY;
    }
    ios_wow_band( &floor, &ceil );
    if (ios_wow_small_va_slots && held >= ios_wow_small_va_slots)
    {
        pthread_mutex_unlock( &ios_wow_mutex );
        dprintf( 2, "[wow-window] refused: map too small for another window (%u of at most %u "
                    "held; MADEIRA_WOW_SMALL_VA_SLOTS)\n", held, ios_wow_small_va_slots );
        return STATUS_NO_MEMORY;
    }
    /* a free placeholder is already reserved VA: adopting it costs nothing, so
     * only a fresh reservation has to pass the map rule */
    for (i = 0; i < ios_wow_placeholder_count; i++)
        if (!ios_wow_placeholders[i].adopted) break;
    if (i == ios_wow_placeholder_count && !ios_wow_map_allows_window())
    {
        pthread_mutex_unlock( &ios_wow_mutex );
        return STATUS_NO_MEMORY;
    }
    if (!(base = ios_wow_window_pick( &guard_owned )))
    {
        pthread_mutex_unlock( &ios_wow_mutex );
        return STATUS_NO_MEMORY;
    }
    slot->peb           = NULL;
    slot->owner         = pthread_self();
    slot->teb_block     = NULL;
    slot->next_free_teb = NULL;
    slot->teb_block_pos = 0;
    slot->wine_mono     = 0;
    slot->leaked        = 0;
    slot->dead          = 0;
    slot->dead_peb      = NULL;
    slot->released_at   = 0;
    slot->guard_owned   = guard_owned;
    slot->base          = base;
    __sync_synchronize();
    if (slot - ios_wow_windows >= (ptrdiff_t)ios_wow_window_count)
        ios_wow_window_count = (unsigned)(slot - ios_wow_windows) + 1;
    pthread_mutex_unlock( &ios_wow_mutex );
    dprintf( 2, "[wow-window] reserved B=%p..%p (slot %d) guard=%s\n", (void *)base,
             (void *)(base + IOS_WOW_WINDOW_SIZE), (int)(slot - ios_wow_windows),
             guard_owned ? "owned" : "borrowed" );
    return STATUS_SUCCESS;
}

void ios_wow_window_bind( void *peb_id )
{
    struct ios_wow_window *slot;

    pthread_mutex_lock( &ios_wow_mutex );
    if ((slot = ios_wow_slot_current()) && !slot->peb)
    {
        slot->peb = peb_id;
        dprintf( 2, "[wow-window] slot %d B=%p bound to peb=%p\n",
                 (int)(slot - ios_wow_windows), (void *)slot->base, peb_id );
    }
    pthread_mutex_unlock( &ios_wow_mutex );
}

/* ABANDON a window without ever giving the slot back.
 *
 * Not the exit path (that is ios_wow_window_mark_released).  This is the case
 * where a pseudo-process stops being a WoW process while STAYING ALIVE inside
 * its window (the loader's start.exe fallback for a main image that turned out
 * not to be a mappable 32-bit PE).  Its first TEB/PEB pair is already inside
 * the window and none of its threads is ever joined, so the VA can never be
 * reclaimed: unbind the slot, mark it leaked so it is never handed out again,
 * and keep the reservation so the range stays excluded from placement. */
static void ios_wow_window_retire( struct ios_wow_window *slot )
{
    ULONG_PTR base;
    void *peb_id;

    pthread_mutex_lock( &ios_wow_mutex );
    base = slot->base;
    peb_id = slot->peb;
    if (base && !slot->leaked && !slot->dead)
    {
        slot->leaked = 1;      /* keep base: the VA is still ours, just dead */
        slot->peb = NULL;
        slot->teb_block = NULL;
        slot->next_free_teb = NULL;
        slot->teb_block_pos = 0;
    }
    else base = 0;
    pthread_mutex_unlock( &ios_wow_mutex );
    if (base)
        ERR( "[wow-window] B=%p (peb=%p) abandoned but not unmapped: the process is still alive "
             "inside the window, so this slot serves no further 32-bit process this session\n",
             (void *)base, peb_id );
}

/* RELEASE-ON-NEXT-ADOPT, step 1: the owning pseudo-process has EXITED.
 *
 * The slot stops resolving for anybody and the owner's identity is recorded,
 * but the teardown itself waits for the next 32-bit process (see
 * ios_wow_reclaim_dead_windows): this runs on the dead process's own last
 * thread, which is still standing inside the range. */
static void ios_wow_window_mark_released( struct ios_wow_window *slot )
{
    ULONG_PTR base;
    void *peb_id;

    pthread_mutex_lock( &ios_wow_mutex );
    base   = slot->base;
    peb_id = slot->peb;
    if (base && !slot->leaked && !slot->dead)
    {
        slot->dead          = 1;
        slot->dead_peb      = peb_id;
        slot->released_at   = time( NULL );
        slot->peb           = NULL;
        slot->teb_block     = NULL;
        slot->next_free_teb = NULL;
        slot->teb_block_pos = 0;
    }
    else base = 0;
    pthread_mutex_unlock( &ios_wow_mutex );
    if (base)
        dprintf( 2, "[wow-window] slot %d B=%p released (owner peb=%p exited); torn down when the "
                    "next 32-bit process starts\n", (int)(slot - ios_wow_windows), (void *)base, peb_id );
}

/* Release the window owned by the calling thread's pseudo-process, from that
 * process's own exit path. */
void ios_wow_window_release_current(void)
{
    struct ios_wow_window *slot;

    pthread_mutex_lock( &ios_wow_mutex );
    slot = ios_wow_slot_current();
    pthread_mutex_unlock( &ios_wow_mutex );
    if (slot) ios_wow_window_mark_released( slot );
}

/* Abandon the calling thread's window for good — see ios_wow_window_retire(). */
void ios_wow_window_retire_current(void)
{
    struct ios_wow_window *slot;

    pthread_mutex_lock( &ios_wow_mutex );
    slot = ios_wow_slot_current();
    pthread_mutex_unlock( &ios_wow_mutex );
    if (slot) ios_wow_window_retire( slot );
}

void ios_wow_window_release( void *peb_id )
{
    struct ios_wow_window *slot;

    pthread_mutex_lock( &ios_wow_mutex );
    slot = ios_wow_slot_for_peb( peb_id );
    pthread_mutex_unlock( &ios_wow_mutex );
    if (slot) ios_wow_window_mark_released( slot );
}
/* ==== end of WoW64 guest windows ==== */
#else
int ios_main_image_i386 = 0;
int ios_wow_session_armed(void) { return 0; }
void ios_wow_session_arm(void) { }
ULONG_PTR ios_wow_base_for_peb( void *peb_id ) { return 0; }
ULONG_PTR ios_wow_base(void) { return 0; }
int ios_wow_in_window( const void *addr ) { return 0; }
ULONG ios_wow_guest_addr( const void *host ) { return PtrToUlong( host ); }
void ios_wow_translate_limits( ULONG_PTR *l, ULONG_PTR *h ) { }
NTSTATUS ios_wow_window_reserve(void) { return STATUS_NOT_SUPPORTED; }
void ios_wow_window_bind( void *peb_id ) { }
void ios_wow_window_release( void *peb_id ) { }
void ios_wow_window_release_current(void) { }
void ios_wow_window_retire_current(void) { }
#endif  /* WINE_IOS */


