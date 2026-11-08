/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. The large address space and NtAllocateVirtualMemory. Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *           virtual_set_large_address_space
 *
 * Enable use of a large address space when allowed by the application.
 */
void virtual_set_large_address_space(void)
{
#ifdef WINE_IOS
    /* This runs from init_peb on the BOOTING thread of each
     * pseudo-process, so ask that process's own guest window whether it is a
     * WoW process instead of the session-wide is_wow64().  Without this, every
     * 64-bit process that boots after a 32-bit child would take the WoW branch
     * and clamp user_space_wow_limit on its behalf.
     * NOTE user_space_wow_limit itself is still a session global — see the
     * "still global" list in the report. */
    BOOL wow = (ios_wow_base() != 0);
#else
    BOOL wow = is_wow64();
#endif

    if (is_win64)
    {
        if (!wow)
        {
            address_space_start = (void *)0x10000;
#ifndef __APPLE__  /* don't free the zerofill section on macOS */
            if ((main_image_info.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) &&
                (main_image_info.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
                free_reserved_memory( 0, (char *)0x7ffe0000 );
#endif
        }
#ifdef WINE_IOS
        /* Same rule, one spelling — see ios_wow_ceiling_for_charact().  When
         * ios_wow_image_ceiling() already published (the normal path: the main
         * image is mapped before init_peb runs), this recomputes the identical
         * number from the identical characteristics. */
        else
        {
            user_space_wow_limit = ios_wow_ceiling_for_charact( main_image_info.ImageCharacteristics );
            ios_wow_note_laa( main_image_info.ImageCharacteristics );   /* ml1070 */
        }
#else
        else user_space_wow_limit = ((main_image_info.ImageCharacteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) ? limit_4g : limit_2g) - 1;
#endif
    }
    else
    {
        if (!(main_image_info.ImageCharacteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)) return;
        free_reserved_memory( (char *)0x80000000, address_space_limit );
    }
    user_space_limit = working_set_limit = address_space_limit;
    ios_clamp_user_space_limit( "large-address-space" );   /* ml990 */
}


/***********************************************************************
 *             allocate_virtual_memory
 *
 * NtAllocateVirtualMemory[Ex] implementation.
 */
#ifdef WINE_IOS
static NTSTATUS allocate_virtual_memory( void **ret, SIZE_T *size_ptr, ULONG type, ULONG protect,
                                         ULONG_PTR limit_low, ULONG_PTR limit_high,
                                         ULONG_PTR align, ULONG attributes );

/* Madeira: THIN RESERVATIONS.
 *
 * Some programs reserve address space in 1 GB blocks (MEM_RESERVE, PAGE_READWRITE,
 * no address) and commit only a few MB at the start of each. On Windows that is
 * free. Here a device can map only ~64 GB, Wine and FEX already use part of it,
 * and every reservation takes its full size: one game reached 42 x 1 GB with
 * 6 MB committed, the 43rd failed with STATUS_NO_MEMORY, and it wrote through
 * the NULL.
 *
 * Once ios_thin_after bytes of such reservations have been made normally, the
 * next ones get only a real HEAD: a view of ios_thin_head bytes at a slot in a
 * thin arena, a THIN_ONLY reserved area. The caller is told it got the full
 * size. The rest of the range (the tail) overlaps the heads after it and the
 * arena's margin, all of it held by the arena, so nothing outside the arena can
 * be mapped there:
 *
 *   arena:  [head 0][g][head 1][g][head 2][g] ... [margin: IOS_THIN_MAX_SIZE]
 *   range 0: |<------------------- reported size ------------------->|
 *
 * - A commit inside the head is an ordinary commit.
 * - Each head is followed by a 1 MB guard (g) that no view covers. A range that
 *   grows contiguously past its head must commit into the guard first, which
 *   has no view, so the commit fails (STATUS_NOT_MAPPED_VIEW, as for any commit
 *   outside a view) instead of reaching the next head. That failure is logged
 *   as [thin] OVERFLOW.
 * - Only a commit that jumps past the guard straight into a later head can land
 *   in another reservation's memory; nothing can tell the two apart there.
 *   Raise MADEIRA_THIN_RESERVE_MB if a program does that.
 * - MEM_DECOMMIT past the head is clamped to the head (the tail holds nothing),
 *   and MEM_RELEASE of the base frees the head and its slot.
 * - NtQueryVirtualMemory reports a tail as MEM_RESERVE of the reservation.
 *
 * Environment (madeira-env.txt): MADEIRA_THIN_RESERVE=0 turns this off;
 * MADEIRA_THIN_RESERVE_MB sets the slot stride (default 64, 16-512);
 * MADEIRA_THIN_RESERVE_AFTER_GB sets how much is reserved normally first
 * (default 8). */
#define IOS_THIN_ARENAS   4
#define IOS_THIN_SLOTS    256
#define IOS_THIN_MAX      (IOS_THIN_ARENAS * IOS_THIN_SLOTS)
#define IOS_THIN_MIN_SIZE 0x40000000ULL    /* 1 GB */
#define IOS_THIN_MAX_SIZE 0x80000000ULL    /* 2 GB, also each arena's margin */
#define IOS_THIN_HEADS    0x100000000ULL   /* head slots per arena, at most */
#define IOS_THIN_GUARD    0x100000ULL      /* 1 MB */

struct ios_thin_arena
{
    ULONG_PTR     base;
    unsigned      nslots;
    unsigned char used[IOS_THIN_SLOTS];
};

struct ios_thin_res
{
    ULONG_PTR      base;      /* head base = reservation base */
    ULONG_PTR      size;      /* size the caller was given */
    ULONG_PTR      hw;        /* highest committed offset seen, for the log */
    ULONG          protect;
    unsigned short arena, slot;
    unsigned char  live, marks;
};

static struct ios_thin_arena ios_thin_arenas[IOS_THIN_ARENAS];
static unsigned ios_thin_arena_n;
static struct ios_thin_res ios_thin[IOS_THIN_MAX];
static unsigned ios_thin_n;          /* entries in use, live or not */
static unsigned ios_thin_live_n;     /* 0 = every thin hook is a no-op */
static unsigned ios_thin_grants;
static int ios_thin_mode = -1;       /* -1 unread, 0 off, 1 on */
static ULONG_PTR ios_thin_stride, ios_thin_head, ios_thin_after, ios_thin_seen;

static int ios_thin_config(void)
{
    const char *e;
    unsigned long mb, gb;

    if (ios_thin_mode >= 0) return ios_thin_mode;
    e = getenv( "MADEIRA_THIN_RESERVE" );
    ios_thin_mode = !(e && e[0] == '0');
    mb = (e = getenv( "MADEIRA_THIN_RESERVE_MB" )) ? strtoul( e, NULL, 10 ) : 64;
    if (mb < 16) mb = 16;
    if (mb > 512) mb = 512;
    gb = (e = getenv( "MADEIRA_THIN_RESERVE_AFTER_GB" )) ? strtoul( e, NULL, 10 ) : 8;
    ios_thin_stride = (ULONG_PTR)mb << 20;
    ios_thin_head   = ios_thin_stride - IOS_THIN_GUARD;
    ios_thin_after  = (ULONG_PTR)gb << 30;
    dprintf( 2, "[thin] %s: 1-2 GB read-write reserves get a %lu MB head once %lu GB of them "
                "were reserved normally\n", ios_thin_mode ? "on" : "off (MADEIRA_THIN_RESERVE=0)",
             (unsigned long)(ios_thin_head >> 20), gb );
    return ios_thin_mode;
}

/* Like mmap_add_fex_reserved_area: never merged, and an overlap is refused. */
static int mmap_add_thin_reserved_area( void *addr, SIZE_T size )
{
    struct reserved_area *area;
    struct list *ptr;

    LIST_FOR_EACH( ptr, &reserved_areas )
    {
        area = LIST_ENTRY( ptr, struct reserved_area, entry );
        if (area->base > addr) break;
        if ((char *)area->base + area->size > (char *)addr) return 0;
    }
    if (!(area = malloc( sizeof(*area) ))) return 0;
    area->base = addr;
    area->size = size;
    area->fex_only = 0;
    area->thin_only = 1;
    list_add_before( ptr, &area->entry );
    return 1;
}

/* virtual_mutex held. Halves the head span until the kernel finds room. */
static int ios_thin_new_arena(void)
{
    ULONG_PTR heads;

    if (ios_thin_arena_n >= IOS_THIN_ARENAS) return 0;
    for (heads = IOS_THIN_HEADS; heads >= IOS_THIN_HEADS / 4; heads /= 2)
    {
        ULONG_PTR span = heads + IOS_THIN_MAX_SIZE, total = span + granularity_mask + 1;
        ULONG_PTR p, base;
        struct ios_thin_arena *ar;
        unsigned n = heads / ios_thin_stride;

        if (n > IOS_THIN_SLOTS) n = IOS_THIN_SLOTS;
        if ((p = (ULONG_PTR)anon_mmap_alloc( total, PROT_NONE )) == (ULONG_PTR)MAP_FAILED) continue;
        base = (p + granularity_mask) & ~(ULONG_PTR)granularity_mask;
        if (base > p) munmap( (void *)p, base - p );
        if (p + total > base + span) munmap( (void *)(base + span), p + total - (base + span) );
        if (is_beyond_limit( (void *)base, span, user_space_limit ) ||
            !mmap_add_thin_reserved_area( (void *)base, span ))
        {
            munmap( (void *)base, span );
            continue;
        }
        ar = &ios_thin_arenas[ios_thin_arena_n++];
        ar->base = base;
        ar->nslots = n;
        memset( ar->used, 0, sizeof(ar->used) );
        dprintf( 2, "[thin] arena #%u [%p,%p): %u heads of %lu MB, %lu MB margin\n",
                 ios_thin_arena_n - 1, (void *)base, (void *)(base + span), n,
                 (unsigned long)(ios_thin_head >> 20), (unsigned long)(IOS_THIN_MAX_SIZE >> 20) );
        return 1;
    }
    dprintf( 2, "[thin] no room for another arena (%u in use): reserving normally\n", ios_thin_arena_n );
    return 0;
}

/* Called before the normal placement of every unhinted MEM_RESERVE. TRUE: done,
 * *status says how. */
static BOOL ios_thin_reserve( void **ret, SIZE_T *size_ptr, ULONG protect, NTSTATUS *status )
{
    SIZE_T size = ROUND_SIZE( 0, *size_ptr, granularity_mask );
    sigset_t sigset;
    unsigned a, s, r, pass;
    BOOL done = FALSE;

    if (protect != PAGE_READWRITE || size < IOS_THIN_MIN_SIZE || size > IOS_THIN_MAX_SIZE) return FALSE;
    if (!ios_thin_config()) return FALSE;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (ios_thin_seen < ios_thin_after)
    {
        ios_thin_seen += size;
        goto out;
    }
    for (r = 0; r < ios_thin_n; r++) if (!ios_thin[r].live) break;
    if (r == IOS_THIN_MAX) goto out;

    for (pass = 0; pass < 2 && !done; pass++)
    {
        if (pass && !ios_thin_new_arena()) break;
        for (a = pass ? ios_thin_arena_n - 1 : 0; a < ios_thin_arena_n && !done; a++)
        {
            struct ios_thin_arena *ar = &ios_thin_arenas[a];

            for (s = 0; s < ar->nslots && !done; s++)
            {
                void *head = (void *)(ar->base + (ULONG_PTR)s * ios_thin_stride);
                SIZE_T hs = ios_thin_head;
                NTSTATUS st;

                if (ar->used[s]) continue;
                ios_thin_placing = 1;
                st = allocate_virtual_memory( &head, &hs, MEM_RESERVE, protect, 0, 0, 0, 0 );
                ios_thin_placing = 0;
                if (st)
                {
                    /* nothing else maps here, so this is unexpected: retire the slot */
                    dprintf( 2, "[thin] head at %p failed (%08x); slot retired\n", head, (unsigned)st );
                    ar->used[s] = 2;
                    continue;
                }
                ar->used[s] = 1;
                ios_thin[r].base = (ULONG_PTR)head;
                ios_thin[r].size = size;
                ios_thin[r].hw = 0;
                ios_thin[r].protect = protect;
                ios_thin[r].arena = a;
                ios_thin[r].slot = s;
                ios_thin[r].marks = 0;
                ios_thin[r].live = 1;
                if (r == ios_thin_n) ios_thin_n++;
                ios_thin_live_n++;
                *ret = head;
                *size_ptr = size;
                *status = STATUS_SUCCESS;
                done = TRUE;
                if (++ios_thin_grants <= 64 || !(ios_thin_grants % 64))
                    dprintf( 2, "[thin] #%u %p: %lu MB reserved, %lu MB head (arena %u slot %u, %u live)\n",
                             ios_thin_grants, head, (unsigned long)(size >> 20),
                             (unsigned long)(ios_thin_head >> 20), a, s, ios_thin_live_n );
            }
        }
    }
out:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return done;
}

/* virtual_mutex held. The live entry whose head, or whose whole range, holds a.
 * Ranges overlap; the one with the highest base at or below a is the one whose
 * tail a is nearest the start of. */
static int ios_thin_find( ULONG_PTR a, BOOL head_only )
{
    unsigned i;
    int best = -1;

    for (i = 0; i < ios_thin_n; i++)
    {
        const struct ios_thin_res *t = &ios_thin[i];

        if (!t->live || a < t->base) continue;
        if (a >= t->base + (head_only ? ios_thin_head : t->size)) continue;
        if (best < 0 || t->base > ios_thin[best].base) best = i;
    }
    return best;
}

/* virtual_mutex held. Lowest live head base above a, or 0. */
static ULONG_PTR ios_thin_next_base( ULONG_PTR a )
{
    unsigned i;
    ULONG_PTR next = 0;

    for (i = 0; i < ios_thin_n; i++)
        if (ios_thin[i].live && ios_thin[i].base > a && (!next || ios_thin[i].base < next))
            next = ios_thin[i].base;
    return next;
}

/* Every commit at an explicit address while thin reservations are live: track
 * how far each head is used, and name a commit that ran past one. The commit
 * itself is left to the normal path, which fails it when no view covers it. */
static void ios_thin_note_commit( void *addr, SIZE_T size )
{
    ULONG_PTR a = (ULONG_PTR)addr, end = a + size;
    static unsigned overflow_logs;
    sigset_t sigset;
    int r;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((r = ios_thin_find( a, TRUE )) >= 0)
    {
        struct ios_thin_res *t = &ios_thin[r];

        if (end <= t->base + ios_thin_head)
        {
            ULONG_PTR used = end - t->base;
            unsigned pct;

            if (used > t->hw) t->hw = used;
            pct = (unsigned)(t->hw * 100 / ios_thin_head);
            if ((pct >= 25 && !(t->marks & 1)) || (pct >= 50 && !(t->marks & 2)) ||
                (pct >= 75 && !(t->marks & 4)))
            {
                t->marks |= (pct >= 25 ? 1 : 0) | (pct >= 50 ? 2 : 0) | (pct >= 75 ? 4 : 0);
                dprintf( 2, "[thin] %p: %u%% of its %lu MB head committed\n", (void *)t->base,
                         pct, (unsigned long)(ios_thin_head >> 20) );
            }
        }
        else if (overflow_logs++ < 64)
            dprintf( 2, "[thin] OVERFLOW: commit %p+0x%lx runs past the %lu MB head of %p "
                        "(highest commit so far +0x%lx); it fails. Raise MADEIRA_THIN_RESERVE_MB\n",
                     addr, (unsigned long)size, (unsigned long)(ios_thin_head >> 20),
                     (void *)t->base, (unsigned long)t->hw );
    }
    else if ((r = ios_thin_find( a, FALSE )) >= 0 && !find_view( addr, 0 ) && overflow_logs++ < 64)
        dprintf( 2, "[thin] OVERFLOW: commit %p+0x%lx is %lu MB into %p, past its %lu MB head "
                    "(highest commit so far +0x%lx); it fails. Raise MADEIRA_THIN_RESERVE_MB\n",
                 addr, (unsigned long)size, (unsigned long)((a - ios_thin[r].base) >> 20),
                 (void *)ios_thin[r].base, (unsigned long)(ios_thin_head >> 20),
                 (unsigned long)ios_thin[r].hw );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}

/* virtual_mutex held, MEM_DECOMMIT. Clamps a decommit that starts in a head
 * and runs into its tail. TRUE: base is in a tail, where nothing is committed,
 * so the decommit succeeds without doing anything. */
static BOOL ios_thin_decommit_fixup( void *base, SIZE_T *size )
{
    struct file_view *view = find_view( base, 0 );
    int r;

    if (view)
    {
        ULONG_PTR vend = (ULONG_PTR)view->base + view->size;

        if (*size && (ULONG_PTR)base + *size > vend && (r = ios_thin_find( (ULONG_PTR)base, TRUE )) >= 0 &&
            ios_thin[r].base == (ULONG_PTR)view->base &&
            (ULONG_PTR)base + *size <= ios_thin[r].base + ios_thin[r].size)
            *size = vend - (ULONG_PTR)base;
        return FALSE;
    }
    if ((r = ios_thin_find( (ULONG_PTR)base, FALSE )) < 0) return FALSE;
    if (!*size) *size = ios_thin[r].base + ios_thin[r].size - (ULONG_PTR)base;
    return TRUE;
}

/* virtual_mutex held, after a successful MEM_RELEASE at base. */
static void ios_thin_released( void *base )
{
    unsigned i;

    for (i = 0; i < ios_thin_n; i++)
    {
        struct ios_thin_res *t = &ios_thin[i];

        if (!t->live || t->base != (ULONG_PTR)base || find_view( base, 0 )) continue;
        ios_thin_arenas[t->arena].used[t->slot] = 0;
        t->live = 0;
        ios_thin_live_n--;
        dprintf( 2, "[thin] %p released (highest commit +0x%lx, %u live)\n", base,
                 (unsigned long)t->hw, ios_thin_live_n );
        return;
    }
}

/* After fill_basic_memory_info: report a thin tail as part of its reservation. */
static void ios_thin_fix_query( const void *addr, MEMORY_BASIC_INFORMATION *info )
{
    ULONG_PTR a = (ULONG_PTR)addr & ~page_mask, end, next;
    sigset_t sigset;
    int r;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (info->State == MEM_FREE && (r = ios_thin_find( a, FALSE )) >= 0)
    {
        end = ios_thin[r].base + ios_thin[r].size;
        if ((next = ios_thin_next_base( a )) && next < end) end = next;
        info->BaseAddress       = (void *)a;
        info->AllocationBase    = (void *)ios_thin[r].base;
        info->AllocationProtect = ios_thin[r].protect;
        info->RegionSize        = end - a;
        info->State             = MEM_RESERVE;
        info->Protect           = 0;
        info->Type              = MEM_PRIVATE;
    }
    else if (info->State == MEM_RESERVE &&
             (r = ios_thin_find( (ULONG_PTR)info->AllocationBase, TRUE )) >= 0 &&
             ios_thin[r].base == (ULONG_PTR)info->AllocationBase &&
             (ULONG_PTR)info->BaseAddress + info->RegionSize == ios_thin[r].base + ios_thin_head)
    {
        end = ios_thin[r].base + ios_thin[r].size;
        if ((next = ios_thin_next_base( ios_thin[r].base )) && next < end) end = next;
        info->RegionSize = end - (ULONG_PTR)info->BaseAddress;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}
#endif /* WINE_IOS */

static NTSTATUS allocate_virtual_memory( void **ret, SIZE_T *size_ptr, ULONG type, ULONG protect,
                                         ULONG_PTR limit_low, ULONG_PTR limit_high,
                                         ULONG_PTR align, ULONG attributes )
{
    void *base;
    unsigned int vprot;
    BOOL is_dos_memory = FALSE;
    struct file_view *view;
    sigset_t sigset;
    SIZE_T size = *size_ptr;
    NTSTATUS status = STATUS_SUCCESS;

#ifdef WINE_IOS
    /* WoW64 guest window: every ceiling that reaches here below 4 GB is a
     * GUEST-namespace number (a zero_bits limit from NtAllocateVirtualMemory or
     * a MEM_ADDRESS_REQUIREMENTS limit from NtAllocateVirtualMemoryEx); nothing
     * below 4 GB is mappable on iOS, so it can never be a host constraint.
     * A no-op for a process without a window. */
    ios_wow_translate_limits( &limit_low, &limit_high );

    /* Madeira: see ios_thin_reserve. */
    if (!*ret && type == MEM_RESERVE && !limit_low && !limit_high && !align && !attributes)
    {
        NTSTATUS thin_status;

        if (ios_thin_reserve( ret, size_ptr, protect, &thin_status )) return thin_status;
    }
    else if (*ret && (type & MEM_COMMIT) && !(type & MEM_RESERVE) && ios_thin_live_n)
        ios_thin_note_commit( *ret, *size_ptr );
#endif

    /* Round parameters to a page boundary */

    if (is_beyond_limit( 0, size, working_set_limit )) return STATUS_WORKING_SET_LIMIT_RANGE;

    if (*ret)
    {
        if (type & MEM_RESERVE && !(type & MEM_REPLACE_PLACEHOLDER)) /* Round down to 64k boundary */
            base = ROUND_ADDR( *ret, granularity_mask );
        else
            base = ROUND_ADDR( *ret, page_mask );
        size = (((UINT_PTR)*ret + size + page_mask) & ~page_mask) - (UINT_PTR)base;

        /* disallow low 64k, wrap-around and kernel space */
        if (((char *)base < (char *)0x10000) ||
            ((char *)base + size < (char *)base) ||
            is_beyond_limit( base, size, address_space_limit ))
        {
            /* address 1 is magic to mean DOS area */
            if (!base && *ret == (void *)1 && size == 0x110000) is_dos_memory = TRUE;
            else return STATUS_INVALID_PARAMETER;
        }
    }
    else
    {
        base = NULL;
        size = ROUND_SIZE( 0, size, page_mask );
    }

    /* Compute the alloc type flags */

    if (!(type & (MEM_COMMIT | MEM_RESERVE | MEM_RESET))
        || (type & MEM_REPLACE_PLACEHOLDER && !(type & MEM_RESERVE)))
    {
        WARN("called with wrong alloc type flags (%08x) !\n", type);
        return STATUS_INVALID_PARAMETER;
    }

    if (type & MEM_RESERVE_PLACEHOLDER && (protect != PAGE_NOACCESS)) return STATUS_INVALID_PARAMETER;
    if (!arm64ec_view && (attributes & MEM_EXTENDED_PARAMETER_EC_CODE)) return STATUS_INVALID_PARAMETER;

    /* Reserve the memory */

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    ios_alloc_ec_code = (attributes & MEM_EXTENDED_PARAMETER_EC_CODE) != 0;   /* see ios_guest_anon_rwx_is_host_data */

    if ((type & MEM_RESERVE) || !base)
    {
        if (!(status = get_vprot_flags( protect, &vprot, FALSE )))
        {
            if (type & MEM_COMMIT) vprot |= VPROT_COMMITTED;
            if (type & MEM_WRITE_WATCH) vprot |= VPROT_WRITEWATCH;
            if (type & MEM_RESERVE_PLACEHOLDER) vprot |= VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER;
            if (protect & PAGE_NOCACHE) vprot |= SEC_NOCACHE;

            if (vprot & VPROT_WRITECOPY) status = STATUS_INVALID_PAGE_PROTECTION;
            else if (is_dos_memory) status = allocate_dos_memory( &view, vprot );
            else status = map_view( &view, base, size, type, vprot, limit_low, limit_high,
                                    align ? align - 1 : granularity_mask );

            if (status == STATUS_SUCCESS)
            {
                base = view->base;
                ios_place_note_new( base, ROUND_SIZE( 0, view->size, host_page_mask ) );   /* see ios_place_fresh */
                if (vprot & VPROT_EXEC || FORCE_EXEC_AT( base )) mprotect_range( base, size, 0, 0 );
                ios_swap_init();
                /* ml1077 commit-time backing (classic runs it unchanged); wide also backs a
                 * writable reservation, never one for ARM64EC code. ml1257 broad backs the
                 * whole new reservation, committed or not, so commits inside it are mprotects */
                if (FORCE_EXEC_AT( base ) || (attributes & MEM_EXTENDED_PARAMETER_EC_CODE) || !ios_swap_whole_resv( view, vprot ))
                {
                    if (type & MEM_COMMIT) ios_swap_commit( base, size, vprot, view );
                    else if (!(attributes & MEM_EXTENDED_PARAMETER_EC_CODE)) ios_swap_reserve( base, size, vprot, view );
                }

                /* iOS-Madeira ml308 (task #54): DETECT VA HANDED OUT TWICE.
                 *
                 * ml308's [vname] map (which only became readable once ml294 turned the iOS
                 * VirtualName no-op into a range log) shows 50 OVERLAPPING FEX allocations,
                 * including EXACT DUPLICATES given to different threads:
                 *   FEXMem_ThreadState  [0x7d00001000..0x7d00004000]  tid A8 AND tid B0
                 *   FEXMem_Lookup       [0x73af1a0000..0x73b41a0000]  tid B4 AND tid C4 (80MB)
                 *   FEXMem_Lookup_L1    [0x73b41a0000..0x73b51a0000]  tid B4 AND tid C4 (16MB)
                 *   FEXMem_CallRetStacks overlapping by up to 16MB in several pairs
                 * Two threads sharing a ThreadState means the SAME x28, so one thread's
                 * State.rip is the other's; sharing a CallRetStack means one thread pops the
                 * other's {guest_ret, host_label} pair and branches to a foreign block's
                 * intra-block label. That is exactly the #51/#52 signature (host PC 0x2c-0x12b4
                 * into "the current" block, present in no guest GPR) and exactly why disabling
                 * the call-ret predictor helped -- it stopped consuming the foreign host half.
                 * It also explains the run-to-run variance, since damage depends on whether the
                 * colliding threads run concurrently.
                 *
                 * A8's ThreadState landed at <steered 512MB reservation base>+0x1000, and B0's
                 * landed on the identical address with no new [bigres] -- so later allocations
                 * are not excluding already-steered ranges. Report any allocation that lands
                 * inside a live ios_steer[] entry, naming both owners. Detection only; no
                 * behaviour change until the log says which path grants the collision. */
                /* ml309: the ml308 version above could only CONFIRM -- it printed nothing when it
                 * found no match, so "0 hits" was indistinguishable from "never reached" and from
                 * "ios_steer[] empty in this process". ml309 hit exactly that: the [vname] map still
                 * showed 3 exact-duplicate FEXMem_ThreadState ranges (tids A8/C0, B4/C4, D0/DC), the
                 * colliding bases 0x7d00000000 / 0x7dc0000000 / 0x7ec0000000 ARE all recorded steer
                 * bases, steer-reclaim never ran, and A8 and C0 are the same process (peb
                 * 0x115bc8000, per [thr-create] + the [tsd275] tid<->TEB mapping) -- yet zero
                 * [va-collide] lines. So log EVERY arena-band allocation with the match RESULT, which
                 * makes the negative readable: "no steer match" with ios_steer_n>0 means the table
                 * lacks the entry, whereas no lines at all means this code path is not on the path
                 * FEX's VirtualAlloc2 takes. */
                if ((uint64_t)(uintptr_t)base >= 0x7C00000000ULL)
                {
                    static int ac;
                    uint64_t nb = (uint64_t)(uintptr_t)base, ne = nb + size;
                    unsigned i, hit = (unsigned)-1;
                    for (i = 0; i < ios_steer_n; i++)
                    {
                        uint64_t sb, se;
                        if (!ios_steer[i].base) continue;
                        sb = ios_steer[i].base; se = sb + ios_steer[i].size;
                        if (ne <= sb || nb >= se) continue;
                        hit = i;
                        break;
                    }
                    if (ac++ < 40)
                    {
                        unsigned me = NtCurrentTeb()
                            ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0;
                        if (hit != (unsigned)-1)
                            dprintf( 2, "[va-arena] rev=ml309 alloc %p+0x%lx tid=%04x type=0x%x -> INSIDE "
                                     "steer#%u [0x%llx+0x%llx] owner_tid=%04x freed=%u steer_n=%u\n",
                                     base, (unsigned long)size, me, (unsigned)type, hit,
                                     (unsigned long long)ios_steer[hit].base,
                                     (unsigned long long)ios_steer[hit].size,
                                     ios_steer[hit].tid, ios_steer[hit].freed, ios_steer_n );
                        else
                            dprintf( 2, "[va-arena] rev=ml309 alloc %p+0x%lx tid=%04x type=0x%x -> no steer "
                                     "match (steer_n=%u)\n",
                                     base, (unsigned long)size, me, (unsigned)type, ios_steer_n );
                    }
                }
            }
        }
    }
    else if (type & MEM_RESET)
    {
        if (!(view = find_view( base, size ))) status = STATUS_NOT_MAPPED_VIEW;
        else
        {
            /* iOS-Madeira (task #22): never MADV_DONTNEED an anon-RWX pool
             * alias — discarding the shared entry pages silently zeroes the
             * pool RX view too (live FEX code/data). MEM_RESET is advisory,
             * so skipping it is legal. */
            extern uintptr_t ios_jit_anon_alias_lookup(uintptr_t fault_addr);
            if (!ios_jit_anon_alias_lookup( (uintptr_t)base ))
                madvise( base, size, MADV_DONTNEED );
        }
    }
    else  /* commit the pages */
    {
        int was_committed = (get_page_vprot( base ) & VPROT_COMMITTED) != 0;
        int any_committed = 0;   /* ml1077: only FRESH commits may be file-backed (a hole reads as zero) */
        { const char *pg; for (pg = base; pg < (const char *)base + size; pg += page_size) if (get_page_vprot( pg ) & VPROT_COMMITTED) { any_committed = 1; break; } }
        if (!(view = find_view( base, size ))) status = STATUS_NOT_MAPPED_VIEW;
        else if (view->protect & SEC_FILE) status = STATUS_ALREADY_COMMITTED;
        else if (view->protect & VPROT_FREE_PLACEHOLDER) status = STATUS_CONFLICTING_ADDRESSES;
        else if (!(status = set_protection( view, base, size, protect )))
        {
            unsigned int sv = 0;
            ios_swap_init();
            if (any_committed) ios_swap_note( IOS_SW_RECOMMIT, size );   /* census only; never backed */
            else if (!get_vprot_flags( protect, &sv, 0 )) ios_swap_commit( base, size, sv, view );
        }
        if (!status && view && (view->protect & SEC_RESERVE))
        {
            SERVER_START_REQ( add_mapping_committed_range )
            {
                req->base   = wine_server_client_ptr( view->base );
                req->offset = (char *)base - (char *)view->base;
                req->size   = size;
                wine_server_call( req );
            }
            SERVER_END_REQ;
        }
        /* ml293 (task #52): PA-arena recommit must read back as zero. */
        if (!status) ios_verify_commit_zero( base, size, protect, was_committed );
    }

    if (!status && (attributes & MEM_EXTENDED_PARAMETER_EC_CODE))
    {
        commit_arm64ec_map( view );
        set_arm64ec_range( base, size );
    }

    if (!status) VIRTUAL_DEBUG_DUMP_VIEW( view );

    ios_alloc_ec_code = 0;
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (status == STATUS_SUCCESS)
    {
        *ret = base;
        *size_ptr = size;
    }
    else if (status == STATUS_NO_MEMORY)
        ERR( "out of memory for allocation, base %p size %08lx\n", base, size );

    return status;
}


/***********************************************************************
 *             NtAllocateVirtualMemory   (NTDLL.@)
 *             ZwAllocateVirtualMemory   (NTDLL.@)
 */
#ifdef WINE_IOS
/* ml842 PROVENANCE PROBE.
 *
 * UE5 died with "FMallocBinned2 Attempt to free an unrecognized block
 * 0000000885560000", and that address appeared NOWHERE else in the log -- so we
 * could not say whether we ever handed it out, whether it was freed twice, or
 * whether it was never ours. "It is absent from the mapping logs" establishes
 * nothing on its own, which is exactly why this exists.
 *
 * Records every guest-band virtual allocation and release, capped, so the next
 * run can answer where a given pointer came from instead of inviting a guess.
 * Passive: it only prints.
 *
 * Set Documents/madeira-vmwatch.txt to a hex address to get a loud line when an
 * allocation COVERS it or a free TOUCHES it, which survives the line cap. */
static unsigned long ios_vm_alloc_logged, ios_vm_free_logged;
static UINT64 ios_vm_watch_addr;
static int ios_vm_watch_ready;

static UINT64 ios_vm_watch(void)
{
    if (!ios_vm_watch_ready)
    {
        char v[64];
        ios_vm_watch_ready = 1;
        if (madeira_cfg_get( "vmwatch", v, sizeof v ) && v[0])   /* ml1095: madeira.cfg vmwatch = 0x<hex> */
        {
            ios_vm_watch_addr = strtoull( v, NULL, 16 );
            if (ios_vm_watch_addr)
                dprintf( 2, "[vmwatch] ml842 watching 0x%llx\n",
                         (unsigned long long)ios_vm_watch_addr );
        }
    }
    return ios_vm_watch_addr;
}

/* Guest band only: FEX's own arenas and the JIT pool would bury the signal. */
static void ios_vm_note_alloc( void *base, SIZE_T size, ULONG type, ULONG protect,
                               UINT64 hint, UINT64 zbits, UINT64 lim )
{
    UINT64 b = (UINT64)(ULONG_PTR)base, w = ios_vm_watch();
    int covers = (w && b <= w && w < b + size);
    /* ml959: a result ABOVE the caller's requested limit is a contract
     * violation, and it is the open question from rdr23. EMP.dll faulted on
     * 0x5d5e0010 == (0x15d5e0000 + 0x10) truncated to 32 bits by its own
     * `movsxd r11, r11d` (EMP.dll rva 0x13bd8b, verified from the file), so it
     * requires its memory below 2 GB. Whether that is an explicit zero_bits
     * contract we broke, or an unstated dependence on Windows' bottom-up
     * placement, decides the fix -- and neither is visible in the old line,
     * which printed only the RESULT. Always log a violating or low-limited
     * request, regardless of the census budget. */
    int viol = (lim && b > lim);
    /* Bounded. A WoW64 process lives in its own 4 GB window, so every one of its
     * allocations carries zero_bits and lands "above" its 32-bit limit by design;
     * the uncapped branch below logged each of them: 127,000 lines (22 MB of a
     * 25 MB device log) in one 32-bit session, 3.5 million lines (562 MB) in a
     * longer one. WoW64 is skipped except for the watch address, and the
     * always-log branch is capped at 200. MADEIRA_VALLOC_LOG_ALL=1 restores the
     * old reach. */
    static int log_all = -1;
    static unsigned long special_logged;
    int special = viol || zbits;
    if (log_all < 0) { const char *e = getenv( "MADEIRA_VALLOC_LOG_ALL" ); log_all = e && e[0] == '1'; }
    if (!log_all && !covers && is_wow64()) return;
    if (b < 0x100000000ull && !viol && !zbits) return;
    if (covers || (special && (log_all || special_logged < 200)) || (!special && ios_vm_alloc_logged < 3000))
    {
        if (special && !covers && ++special_logged == 200)
            dprintf( 2, "[valloc] limited/violating allocations: first 200 logged, the rest are not "
                        "(MADEIRA_VALLOC_LOG_ALL=1 logs all)\n" );
        ios_vm_alloc_logged++;
        dprintf( 2, "[valloc] ml959 %s base=0x%llx size=0x%llx type=0x%x prot=0x%x tid=%04x"
                 " | req_hint=0x%llx zero_bits=0x%llx limit=0x%llx%s\n",
                 covers ? "COVERS-WATCH" : (viol ? "LIMIT-VIOLATED" : "#"),
                 (unsigned long long)b,
                 (unsigned long long)size, (unsigned)type, (unsigned)protect,
                 NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0,
                 (unsigned long long)hint, (unsigned long long)zbits,
                 (unsigned long long)lim,
                 viol ? "  <== RESULT EXCEEDS THE REQUESTED LIMIT" : "" );
    }
}

static void ios_vm_note_free( void *base, SIZE_T size, ULONG type )
{
    UINT64 b = (UINT64)(ULONG_PTR)base, w = ios_vm_watch();
    int hits = (w && b <= w && (size == 0 || w < b + size));
    if (b < 0x100000000ull) return;
    if (hits || ios_vm_free_logged < 3000)
    {
        ios_vm_free_logged++;
        dprintf( 2, "[vfree] ml842 %s base=0x%llx size=0x%llx type=0x%x tid=%04x\n",
                 hits ? "HITS-WATCH" : "#", (unsigned long long)b,
                 (unsigned long long)size, (unsigned)type,
                 NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0 );
    }
}
#endif

#ifdef WINE_IOS
/* ml844 [tls38]: WHEN does the exe's thread-local at static TLS block 0 +0x38
 * change from 0 to the FEX emulator stack top?
 *
 * Offline analysis of the UE5 shipping exe found that this 16-byte thread-local
 * is zeroed by a dynamic TLS initialiser at thread attach, freed by its
 * destructor at detach (FMemory::Free of the first word), and has NO other
 * address-taker anywhere in the image. So the value arrives by a path no static
 * scan can see. This polls the slot at two points every engine thread hits
 * constantly -- server waits and virtual allocations -- and logs the first
 * poll per thread and the first 0 -> non-zero transition, with the guest RIP
 * taken from the CPU area's saved x64 context (Rip is at +0xF8 of an AMD64
 * CONTEXT; ARM64EC_NT_CONTEXT is layout-compatible by design). That brackets
 * the writer to one syscall interval on a known guest thread. Passive. */
void ios_tls38_poll( const char *where )
{
    static struct { DWORD tid; int state; } seen[48];
    static unsigned nseen, lines;
    TEB *teb = NtCurrentTeb();
    void **blocks; ULONG64 v, top = 0, rip = 0, rsp = 0; DWORD tid; unsigned i, slot = ~0u;
    CHPE_V2_CPU_AREA_INFO *area;

    if (!teb || lines > 60) return;
    blocks = teb->ThreadLocalStoragePointer;
    if (!blocks || !blocks[0]) return;
    v = ((ULONG64 *)blocks[0])[7];
    tid = (DWORD)(ULONG_PTR)teb->ClientId.UniqueThread;
    for (i = 0; i < nseen; i++) if (seen[i].tid == tid) { slot = i; break; }
    if (slot == ~0u) { if (nseen >= 48) return; slot = nseen++; seen[slot].tid = tid; seen[slot].state = 0; }
    if (seen[slot].state == 0)
    {
        seen[slot].state = 1; lines++;
        dprintf( 2, "[tls38] ml844 tid=%04x first poll at %s: tls0+0x38=0x%llx (block=%p)\n",
                 (unsigned)tid, where, (unsigned long long)v, blocks[0] );
    }
    if (v && seen[slot].state == 1)
    {
        seen[slot].state = 2; lines++;
        area = teb->ChpeV2CpuAreaInfo;
        if (area)
        {
            top = area->EmulatorStackBase;
            if (area->ContextAmd64)
            {
                rip = *(ULONG64 *)((char *)area->ContextAmd64 + 0xF8);
                rsp = *(ULONG64 *)((char *)area->ContextAmd64 + 0x98);
            }
        }
        dprintf( 2, "[tls38] ml844 tid=%04x SET at %s: tls0+0x38=0x%llx %s top=0x%llx | guest Rip=0x%llx Rsp=0x%llx\n",
                 (unsigned)tid, where, (unsigned long long)v,
                 v == top ? "== EMULATOR STACK TOP" : "(not the stack top)",
                 (unsigned long long)top, (unsigned long long)rip, (unsigned long long)rsp );
    }
}
#endif

/**********************************************************************
 * ml966: BOUNDED LOW-ADDRESS ALLOCATION EXPERIMENT
 *
 * Evidence (handoff 21-22): EMP.dll's obfuscation VM walks a packed byte
 * stream with two cursors and stores into it at 16-, 32- AND 64-bit widths
 * through the same register (measured in .emp1: 100 / 57 / 74 instructions).
 * A pointer that goes in narrow and comes out wide loses its high half. rdr31
 * caught both copies of the same pointer in the stream at once -- full width
 * at R10-30 (next word 0x00000001) and narrow at R10+0 and R10-118 (next word
 * 0x00000000) -- and the guest dereferenced the narrow one:
 * allocation 0x15cdb0000, read 0x000000005cdb0010, SEGV at 0x5cdb0010,
 * reproduced across five runs with fresh ASLR each time.
 *
 * So a pointer this module round-trips must fit in 32 bits. iOS's mandatory
 * __PAGEZERO puts the floor at ~0x104000000, so a sub-4GB pointer cannot be a
 * real mapping; the backing has to live high and the guest has to be handed a
 * low address that our fault path translates.
 *
 * NOT a general allocator change, and deliberately NOT the ml938 image-window
 * table. Astra's constraint, which this follows: that table has global
 * last-writer-wins ownership, no retirement path, and translates on the
 * START address only -- all three are wrong for dynamic allocations. This is a
 * separate registry that carries the owning pseudo-process, checks the WHOLE
 * access span against the entry's bounds, and is retired on free.
 *
 * Also NOT truncated-pointer recovery: the guest address is taken from a fresh
 * reserved range below 2 GB, never derived by truncating the backing address.
 * Because it already fits in 32 bits, the guest's own narrowing becomes a
 * no-op rather than something we have to detect and undo.
 *
 * Scope limit: only the exact request shape that crashes (a 0x1000
 * MEM_COMMIT|MEM_RESERVE PAGE_READWRITE allocation with no hint and no
 * zero_bits, in a pseudo-process that has a sub-floor image loaded), capped at
 * IOS_LOWALLOC_MAX. Measured against rdr31: 25 allocations in the whole run
 * match that shape, 7 of them in the game process. Kill switch:
 * MADEIRA_NO_LOW_ALLOC=1.
 */
#define IOS_LOWALLOC_MAX   48   /* ml1100: was 16; images take slots too */
#define IOS_LOWALLOC_BASE  0x30000000ull   /* fresh + reserved; clear of the */
#define IOS_LOWALLOC_LIMIT 0x38000000ull   /* image windows, and < 2 GB      */
#define IOS_LOWALLOC_GRAN  0x10000ull      /* Windows allocation granularity */

struct ios_lowalloc_ent
{
    uint64_t guest_low;    /* the low guest address that resolves here */
    uint64_t size;         /* granularity-rounded span */
    uint64_t real_base;    /* the high backing */
    void    *owner_peb;    /* owning pseudo-process */
    int      active;
    int      kind;         /* 0 = ml966 arena (guest HOLDS the low address)
                            * 1 = ml969 alias  (guest holds the HIGH address;
                            *     the low name exists only for the narrowed
                            *     form the guest computes for itself) */
};
#define IOS_LA_ARENA 0
#define IOS_LA_ALIAS 1
static struct ios_lowalloc_ent ios_lowalloc[IOS_LOWALLOC_MAX];
static int      ios_lowalloc_count;
static uint64_t ios_lowalloc_bump = IOS_LOWALLOC_BASE;
static pthread_mutex_t ios_lowalloc_lock = PTHREAD_MUTEX_INITIALIZER;

/* ml968: the experiment is now OPT-IN and OFF by default.
 *
 * rdr33 returned its verdict and it is negative. With the scope fix in place
 * the redirect correctly hit only the packer-hosting process, and the launcher
 * then faulted inside Apple's own `memmove`:
 *   pc=libsystem_platform.dylib`_platform_memmove+0xa8  addr=0x30000000
 *   insn ad000c02 = stp q2,q3,[x0]   (32-byte SIMD pair store)
 *   [lowalloc] serviced ... 0x30000000 (32 byte span, write) -> backing ...
 * The guest handed its low pointer across the API boundary and native code
 * dereferenced it. Our handler services each such access correctly, but that
 * turns one memmove into one Mach exception per 32 bytes, and the callret stack
 * was measured at 4 MB / 100% full. The launcher never reached the point of
 * starting the game (zero 008c lines in the whole run).
 *
 * This is precisely Astra's constraint 4: emulating CPU accesses does not make
 * a low pointer usable by other APIs. Handing a low address to the guest is
 * therefore not viable without translating every API boundary that can receive
 * a buffer pointer, which is a far larger surface than this experiment.
 *
 * The machinery is kept -- registry, span-checked translation, ownership,
 * retirement, and all the probes -- because it is the substrate any future
 * attempt needs, and because the negative result is worth being able to
 * reproduce. Default OFF so the shipped build matches baseline behaviour.
 * Enable with MADEIRA_LOW_ALLOC=1. */
static int ios_lowalloc_enabled(void)
{
    static int dec = -1;
    if (dec < 0)
    {
        const char *on = getenv( "MADEIRA_LOW_ALLOC" );
        dec = (on && *on && *on != '0') ? 1 : 0;
        dprintf( 2, "ml968: low-address allocation experiment %s (range [%#llx,%#llx), cap %d)\n",
                 dec ? "ENABLED by MADEIRA_LOW_ALLOC" : "OFF by default -- see ml968 rationale",
                 IOS_LOWALLOC_BASE, IOS_LOWALLOC_LIMIT, IOS_LOWALLOC_MAX );
    }
    return dec;
}

/* Hand out a fresh low guest address for `real_base`. Returns 0 if the
 * experiment is full or the range is exhausted -- callers then keep the
 * ordinary high address, so failure here is never fatal. */
static uint64_t ios_lowalloc_reserve( uint64_t real_base, uint64_t size, void *peb )
{
    uint64_t rounded = (size + IOS_LOWALLOC_GRAN - 1) & ~(IOS_LOWALLOC_GRAN - 1);
    uint64_t low = 0;
    int i;

    pthread_mutex_lock( &ios_lowalloc_lock );
    if (ios_lowalloc_count < IOS_LOWALLOC_MAX &&
        ios_lowalloc_bump + rounded <= IOS_LOWALLOC_LIMIT)
    {
        i = ios_lowalloc_count++;
        low = ios_lowalloc_bump;
        ios_lowalloc_bump += rounded;
        ios_lowalloc[i].guest_low = low;
        ios_lowalloc[i].size      = rounded;
        ios_lowalloc[i].real_base = real_base;
        ios_lowalloc[i].owner_peb = peb;
        ios_lowalloc[i].active    = 1;
        ios_lowalloc[i].kind      = IOS_LA_ARENA;
    }
    pthread_mutex_unlock( &ios_lowalloc_lock );
    return low;
}

/**********************************************************************
 * ml969: OPTION C -- a pre-registered, refusable low ALIAS.
 *
 * rdr33 measured option A (hand the guest a low address) and it fails: the
 * guest passes the pointer across the API boundary and Apple's own `memmove`
 * faults on the unmapped address, one Mach exception per 32 bytes, and the
 * launcher never starts the game (handoff 23.3). The canonical pointer must
 * stay HIGH so every native, libc and kernel consumer sees a real mapping.
 *
 * So: leave the returned pointer alone, and additionally declare the low-32
 * form of the allocation as a second name for the same backing. The guest's VM
 * narrows pointers through its own byte stream (handoff 21.3); when it then
 * dereferences the narrowed form, that name resolves to the same memory.
 *
 * This is NOT recovery-by-guessing. Astra's objection was to inferring, on a
 * fault, that an invalid pointer "must have meant" a real one -- which is
 * unsound here because guest allocations span three high-32 bands (k=1, 0xb,
 * 0xd in rdr31), so `+0x100000000` is not a universal inverse. Instead both
 * addresses are known at the moment we create the allocation, the alias is
 * registered then, and registration REFUSES when it cannot be done safely.
 * Collisions are a registration-time decision, never a runtime ambiguity.
 *
 * Additive by construction: no pointer any caller receives changes, so unlike
 * option A this cannot alter the behaviour of code that never narrows. The
 * only difference is that an access to the low name is serviced instead of
 * faulting.
 *
 * Refused when the low range would overlap: an existing registry entry, a
 * registered sub-floor IMAGE window (an image's preferred base owns that
 * range), the ml966 arena, or the very bottom of the address space (a null
 * deref plus a small offset must keep crashing, not silently resolve).
 */
static int ios_lowalias_would_collide( uint64_t low, uint64_t size )
{
    extern int ios_subfloor_enum( int idx, unsigned long long *low, unsigned long long *real,
                                  unsigned long long *size, void **owner );
    unsigned long long wl = 0, wr = 0, ws = 0;
    int i;

    /* keep the first 16 MB unaliased so a null-ish dereference still faults */
    if (low < 0x1000000ull) return 1;
    /* must not shadow the arena, even though it is off by default */
    if (low < IOS_LOWALLOC_LIMIT && low + size > IOS_LOWALLOC_BASE) return 1;

    for (i = 0; ios_subfloor_enum( i, &wl, &wr, &ws, NULL ); i++)   /* any process's */
        if (ws && low < wl + ws && low + size > wl)
            return 1;                                  /* an image owns that range */

    for (i = 0; i < ios_lowalloc_count; i++)           /* caller holds the lock */
    {
        const struct ios_lowalloc_ent *e = &ios_lowalloc[i];
        if (!e->active) continue;
        if (low < e->guest_low + e->size && low + size > e->guest_low) return 1;
    }
    return 0;
}

/* Returns the declared low name, or 0 when refused (caller simply proceeds
 * with the ordinary high-only allocation). */
static uint64_t ios_lowalias_register( uint64_t real_base, uint64_t size, void *peb )
{
    uint64_t low     = real_base & 0xFFFFFFFFull;
    uint64_t rounded = (size + IOS_LOWALLOC_GRAN - 1) & ~(IOS_LOWALLOC_GRAN - 1);
    uint64_t out = 0;
    int i;

    if (real_base < 0x100000000ull) return 0;          /* already low: nothing to do */
    if (low + rounded < low) return 0;                 /* wraps the 32-bit boundary */
    if (low + rounded > 0x100000000ull) return 0;      /* alias would cross the floor */

    pthread_mutex_lock( &ios_lowalloc_lock );
    if (ios_lowalloc_count < IOS_LOWALLOC_MAX && !ios_lowalias_would_collide( low, rounded ))
    {
        i = ios_lowalloc_count++;
        ios_lowalloc[i].guest_low = low;
        ios_lowalloc[i].size      = rounded;
        ios_lowalloc[i].real_base = real_base;
        ios_lowalloc[i].owner_peb = peb;
        ios_lowalloc[i].active    = 1;
        ios_lowalloc[i].kind      = IOS_LA_ALIAS;
        out = low;
    }
    pthread_mutex_unlock( &ios_lowalloc_lock );
    return out;
}

/* Aliases are retired by their BACKING address, because that is the pointer the
 * guest holds and therefore the one it frees. */
static uint64_t ios_lowalias_retire_by_real( uint64_t real_base, void *peb )
{
    uint64_t low = 0;
    int i, n;

    pthread_mutex_lock( &ios_lowalloc_lock );
    n = ios_lowalloc_count;
    for (i = 0; i < n; i++)
    {
        struct ios_lowalloc_ent *e = &ios_lowalloc[i];
        if (!e->active || e->kind != IOS_LA_ALIAS) continue;
        if (e->real_base != real_base) continue;
        if (peb && e->owner_peb && peb != e->owner_peb) continue;
        low = e->guest_low;
        e->active = 0;
        break;
    }
    pthread_mutex_unlock( &ios_lowalloc_lock );
    return low;
}

static int ios_lowalias_enabled(void)
{
    static int dec = -1;
    if (dec < 0)
    {
        const char *off = getenv( "MADEIRA_NO_LOW_ALIAS" );
        dec = (off && *off && *off != '0') ? 0 : 1;
        dprintf( 2, "ml969: low-alias experiment %s -- returned pointers are UNCHANGED, "
                 "only the narrowed form gains a name\n",
                 dec ? "ENABLED (default)" : "DISABLED by MADEIRA_NO_LOW_ALIAS" );
    }
    return dec;
}

/* iOS-Madeira ml1201: the ml938 sub-floor IMAGE windows, for the VM calls.
 *
 * A 64-bit image with a fixed base below 4GB (a Delphi tool at 0x400000) is
 * mapped high; its own absolute addresses stay low and only the fault path
 * (ios_subfloor_service) and FEX's inline translation (ml1057) know the window.
 * NtProtectVirtualMemory on such an address found no view and failed with
 * STATUS_INVALID_PARAMETER: a Delphi program patching 5 bytes of its own code
 * (VirtualProtect(0x44e730, 5, PAGE_EXECUTE_READWRITE)) got the failure, raised
 * a Delphi exception and died (0x0eedfade). Translate a span that lies entirely
 * inside one of this process's image windows to the real mapping, as ml966 does
 * for low allocations. The KUSER_SHARED_DATA window (ml952, owner NULL) is not
 * an image: VirtualQuery/VirtualProtect at 0x7ffe0000 keep their own answer
 * (Windows refuses to make that page writable). MADEIRA_SUBFLOOR_VM=0 turns it
 * off. */
static int ios_subfloor_image_translate( unsigned long long addr, unsigned long long len,
                                         unsigned long long *real_out )
{
    extern int ios_subfloor_enum( int idx, unsigned long long *low, unsigned long long *real,
                                  unsigned long long *size, void **owner );
    static int on = -1;
    unsigned long long lo, re, sz;
    void *peb, *own;
    int i;

    if (on < 0)
    {
        const char *e = getenv( "MADEIRA_SUBFLOOR_VM" );   /* ml1201: 0 = VirtualProtect/VirtualQuery leave fixed-base image windows alone */
        on = !(e && e[0] == '0');
    }
    if (!on || addr >= 0x100000000ull) return 0;
    if (!len) len = 1;
    peb = ios_jit_current_peb();
    for (i = 0; ios_subfloor_enum( i, &lo, &re, &sz, &own ); i++)
    {
        /* ml1205: another process's window. The KUSER_SHARED_DATA window (ml952,
         * owner NULL) is no image: 0x7ffe0000 keeps its own answer. */
        if (own ? own != peb : lo == 0x7ffe0000ull) continue;
        if (!sz || !re || addr < lo || addr + len > lo + sz) continue;
        *real_out = re + (addr - lo);
        return 1;
    }
    return 0;
}

/* iOS-Madeira ml1206: start a RELOCS_STRIPPED sub-floor main image at its LOW
 * entry point. TransferAddress is the real mapping's, so the code started high
 * while every absolute pointer in the unrelocated image is low, and code that
 * mixes the two broke: a MinGW pseudo-relocator took its base from a
 * RIP-relative lea (real) and the pointer from .data (low), patched its own
 * `call` to rel32 0xb063263d and jumped to 0x1004238b0. On Windows both are the
 * same address; running at the low addresses keeps them equal here too. A
 * relocated image keeps its real entry (its pointers were moved high).
 * Called on the new process's own thread. MADEIRA_SUBFLOOR_LOWENTRY=0 turns it
 * off. */
void *ios_subfloor_low_entry( void *entry, ULONG image_charact )
{
    extern int ios_subfloor_enum( int idx, unsigned long long *low, unsigned long long *real,
                                  unsigned long long *size, void **owner );
    static int on = -1;
    unsigned long long lo, re, sz, e = (ULONG_PTR)entry;
    void *peb, *own;
    int i;

    if (on < 0)
    {
        const char *v = getenv( "MADEIRA_SUBFLOOR_LOWENTRY" );   /* ml1206: 0 = a fixed-base exe starts at its real (high) entry */
        on = !(v && v[0] == '0');
    }
    if (!on || !entry || !(image_charact & IMAGE_FILE_RELOCS_STRIPPED)) return entry;
    if (!(peb = ios_jit_current_peb())) return entry;
    for (i = 0; ios_subfloor_enum( i, &lo, &re, &sz, &own ); i++)
    {
        if (!sz || own != peb || e < re || e >= re + sz) continue;
        fprintf( stderr, "ml1206: RELOCS_STRIPPED sub-floor image starts at its low entry %#llx "
                 "(real %p)\n", lo + (e - re), entry );
        return (void *)(ULONG_PTR)(lo + (e - re));
    }
    return entry;
}

/**********************************************************************
 * ml1100: IMAGE LOW-ALIAS -- the ml969 alias, applied to a relocated image.
 *
 * Measured (dsr-log-codex-steamclient, 29.09): steam_api64.dll prefers
 * 0x3b400000, iOS cannot map below the 4 GB floor, so it was mapped at
 * 0x71fe0b0000 and that HIGH address is what LoadLibrary/GetModuleHandle hand
 * the guest. Unpacked code in steamclient64.dll then does
 *     8b 7b 30        mov    edi, [rbx+0x30]      ; HMODULE, 32-bit load
 *     48 63 57 3c     movsxd rdx, [rdi+0x3c]      ; e_lfanew  -> AV at 0xfe0b003c
 * i.e. the program itself narrows the module handle. On Windows and on Wine
 * for macOS a module whose preferred base is below 4 GB also LIVES below
 * 4 GB, so the narrowing is a no-op there. The ml938 window does not help:
 * it names the PREFERRED base (0x3b400000), while the narrowed value is the
 * low 32 bits of the ACTUAL base (0xfe0b0000).
 *
 * Fix: declare [real & 0xffffffff, +size) as a second name for the image,
 * exactly as ml969 does for 0x1000 RW allocations. Additive: no pointer any
 * caller receives changes; an access to the low name that used to raise
 * c0000005 is serviced by the Mach gate (ios_subfloor_service ->
 * ios_lowalloc_translate, whole-span bounds-checked) instead. Registration
 * refuses on collision with an image window, another alias, the ml966 arena
 * or the bottom 16 MB, so it can never shadow a real name.
 *
 * Scope: only images whose PREFERRED base is below 4 GB -- the images whose
 * authors were promised a sub-4 GB address by Windows. No module name is
 * hard-coded. Data accesses only: execution through the low name is not
 * provided (FEX is not told about it).
 * Kill switch: MADEIRA_NO_IMAGE_LOW_ALIAS=1 (and MADEIRA_NO_LOW_ALIAS=1). */
static int ios_image_lowalias_enabled(void)
{
    static int dec = -1;
    if (dec < 0)
    {
        const char *off = getenv( "MADEIRA_NO_IMAGE_LOW_ALIAS" );
        dec = (off && *off && *off != '0') ? 0 : 1;
        dprintf( 2, "ml1100: image low-alias %s\n",
                 dec ? "ENABLED (default)" : "DISABLED by MADEIRA_NO_IMAGE_LOW_ALIAS" );
    }
    return dec && ios_lowalias_enabled();
}

static void ios_image_lowalias_register( unsigned long long pref_base, unsigned long long real_base,
                                         unsigned long long size, const char *why )
{
    uint64_t alias;

    if (!ios_image_lowalias_enabled()) return;
    if (real_base < 0x100000000ull || !size) return;
    alias = ios_lowalias_register( real_base, size, ios_jit_current_peb() );
    dprintf( 2, "ml1100: image %#llx+%#llx (preferred %#llx, %s): low alias %s%#llx\n",
             real_base, size, pref_base, why,
             alias ? "" : "REFUSED (collision/table full/crosses 4GB) for ",
             alias ? (unsigned long long)alias : (real_base & 0xFFFFFFFFull) );
}

static void ios_image_lowalias_retire( unsigned long long real_base )
{
    uint64_t gone;

    if (real_base < 0x100000000ull) return;
    /* peb NULL: the view is being unmapped, whoever owned the name */
    gone = ios_lowalias_retire_by_real( real_base, NULL );
    if (gone)
        dprintf( 2, "ml1100: RETIRED image alias %#llx for %#llx on unmap\n",
                 (unsigned long long)gone, real_base );
}

/* Translate a WHOLE access span, not just its start. Returns 1 only when
 * [addr, addr+len) lies entirely inside one active entry. `len` 0 is treated
 * as 1 so a bare address query still bounds-checks. */
int ios_lowalloc_translate( unsigned long long addr, unsigned long long len,
                            unsigned long long *real_out, void **owner_out );
int ios_lowalloc_translate( unsigned long long addr, unsigned long long len,
                            unsigned long long *real_out, void **owner_out )
{
    int i, n, hit = 0;

    /* ml971: this used to fast-reject anything outside the ml966 ARENA range
     * [IOS_LOWALLOC_BASE, IOS_LOWALLOC_LIMIT). That was right when the arena
     * was the only producer, but an ml969 ALIAS is the low-32 form of whatever
     * address the allocator returned, so it can sit anywhere below 4 GB. The
     * stale reject made every alias lookup miss: rdr34/rdr35 both registered
     * the correct alias (fault 0x69410010 inside alias 0x69410000) and then
     * reported `serviced 0, REFUSED 0` -- the lookup returned 0 before ever
     * consulting the table, so the Mach gate skipped the service call and the
     * guest faulted anyway.
     *
     * Reject only at or above the floor, where no entry can ever live, and let
     * the per-entry span check below be authoritative. */
    if (addr >= 0x100000000ull) return 0;
    if (!len) len = 1;
    if (addr + len < addr) return 0;                       /* span overflow */

    pthread_mutex_lock( &ios_lowalloc_lock );
    n = ios_lowalloc_count;
    for (i = 0; i < n; i++)
    {
        const struct ios_lowalloc_ent *e = &ios_lowalloc[i];
        if (!e->active) continue;
        if (addr < e->guest_low) continue;
        if (addr + len > e->guest_low + e->size) continue; /* span must fit */
        if (real_out)  *real_out  = e->real_base + (addr - e->guest_low);
        if (owner_out) *owner_out = e->owner_peb;
        hit = 1;
        break;
    }
    pthread_mutex_unlock( &ios_lowalloc_lock );
    return hit;
}

/* Retire on free: returns the backing base so the caller can release it, and
 * marks the translation dead so no later access can resolve through it. */
static uint64_t ios_lowalloc_retire( uint64_t guest_low, void *peb )
{
    uint64_t real = 0;
    int i, n;

    pthread_mutex_lock( &ios_lowalloc_lock );
    n = ios_lowalloc_count;
    for (i = 0; i < n; i++)
    {
        struct ios_lowalloc_ent *e = &ios_lowalloc[i];
        if (!e->active) continue;
        if (guest_low < e->guest_low || guest_low >= e->guest_low + e->size) continue;
        if (peb && e->owner_peb && peb != e->owner_peb) continue;   /* not yours */
        real = e->real_base;
        e->active = 0;
        break;
    }
    pthread_mutex_unlock( &ios_lowalloc_lock );
    return real;
}

/* ml966 FIX (was a regression): which pseudo-processes may be redirected.
 *
 * The first version asked the ml938 window table whether ANY sub-floor image
 * was registered. That table is GLOBAL -- the very last-writer-wins ownership
 * Astra warned about -- and window #0 is KUSER_SHARED_DATA at 0x7ffe0000,
 * registered for every process at startup. So the test was true from the first
 * process onward and the DESKTOP got 13 low allocations (rdr32: all 13
 * LOW-ALLOC lines are tid=0024), which is why the taskbar never loaded. It
 * also violated Astra's explicit instruction not to redirect "every allocation
 * originating from a low-loaded module".
 *
 * Replaced with a per-peb set, populated only for an image that is BOTH
 * sub-floor AND RELOCS_STRIPPED. That pairing is the actual property of
 * interest: an image with its relocations stripped cannot be moved, so it
 * demands its preferred base, and a module that demands a sub-4GB base is
 * precisely one that may pack pointers into 32 bits. Measured against rdr27:
 * ml949 reports RELOCS_STRIPPED only for preferred base 0x13000000 -- the
 * packer module -- while opengl32.dll, the other sub-floor image (0x7a800000),
 * is not stripped and so does not qualify. No module name is hard-coded. */
#define IOS_LOWALLOC_QUAL_MAX 8
static void *ios_lowalloc_qual_peb[IOS_LOWALLOC_QUAL_MAX];
static int   ios_lowalloc_qual_count;

/* Called from the sub-floor image registration site, on the loading thread, so
 * ios_jit_current_peb() is that process's own identity. */
static void ios_lowalloc_note_qualifying_image( unsigned long long pref_base, int relocs_stripped )
{
    void *peb;
    int i;

    if (!relocs_stripped || !pref_base || pref_base >= 0x100000000ull) return;
    peb = ios_jit_current_peb();
    if (!peb) return;

    pthread_mutex_lock( &ios_lowalloc_lock );
    for (i = 0; i < ios_lowalloc_qual_count; i++)
        if (ios_lowalloc_qual_peb[i] == peb) { pthread_mutex_unlock( &ios_lowalloc_lock ); return; }
    if (ios_lowalloc_qual_count < IOS_LOWALLOC_QUAL_MAX)
    {
        ios_lowalloc_qual_peb[ios_lowalloc_qual_count++] = peb;
        pthread_mutex_unlock( &ios_lowalloc_lock );
        dprintf( 2, "ml966: peb=%p QUALIFIES for low allocation (loaded a RELOCS_STRIPPED sub-floor "
                 "image, preferred base %#llx)\n", peb, pref_base );
        return;
    }
    pthread_mutex_unlock( &ios_lowalloc_lock );
}

static int ios_lowalloc_process_qualifies(void)
{
    void *peb = ios_jit_current_peb();
    int i, hit = 0;

    if (!peb) return 0;
    pthread_mutex_lock( &ios_lowalloc_lock );
    for (i = 0; i < ios_lowalloc_qual_count; i++)
        if (ios_lowalloc_qual_peb[i] == peb) { hit = 1; break; }
    pthread_mutex_unlock( &ios_lowalloc_lock );
    return hit;
}

/***********************************************************************
 *           ios_sc_reap_dead                             (madeira-bcd)
 *
 * Release the reservations of SocialClubHelper.exe processes that have exited
 * (ios_sc_grants_owner_died) and hold their ranges again, so the next helper
 * finds the layout it booted with. Runs when a live helper makes a jumbo
 * request, seconds after the old one died (18:24 log: 9 s between the first
 * helper's death and the second's start), so no thread of the dead process can
 * still be using them. A range is freed only if a view still starts there.
 */
static void ios_sc_reap_dead( void )
{
    for (;;)
    {
        uint64_t view = 0, report = 0;
        void *peb = NULL;
        int i, kind = 0, found = 0;
        MEMORY_BASIC_INFORMATION mbi;
        NTSTATUS st = STATUS_MEMORY_NOT_ALLOCATED;

        pthread_mutex_lock( &ios_sc_grant_lock );
        for (i = 0; i < ios_sc_grant_n; i++)
        {
            if (!ios_sc_grants[i].dead) continue;
            view = ios_sc_grants[i].view;
            report = ios_sc_grants[i].report;
            peb = ios_sc_grants[i].peb;
            kind = ios_sc_grants[i].kind;
            ios_sc_grants[i] = ios_sc_grants[--ios_sc_grant_n];
            ios_sc_grant_dead_n--;
            found = 1;
            break;
        }
        pthread_mutex_unlock( &ios_sc_grant_lock );
        if (!found) return;

        if (!NtQueryVirtualMemory( NtCurrentProcess(), (void *)(ULONG_PTR)view, MemoryBasicInformation,
                                   &mbi, sizeof(mbi), NULL )
            && (uint64_t)(ULONG_PTR)mbi.AllocationBase == view && mbi.State != MEM_FREE)
        {
            void *b = (void *)(ULONG_PTR)view;
            SIZE_T s = 0;
            st = NtFreeVirtualMemory( NtCurrentProcess(), &b, &s, MEM_RELEASE );
        }
        if (!st) ios_sc_rehold( kind );
        dprintf( 2, "[sc-cef] reclaimed a dead SocialClubHelper.exe's reservation (peb=%p kind=%d): view 0x%llx "
                    "(given as 0x%llx) %s\n", peb, kind, (unsigned long long)view, (unsigned long long)report,
                 st ? "was already gone" : "released and held again" );
    }
}

/* Record a jumbo grant of the calling helper that no layout code recorded
 * (the V8 cage, a kernel pick): only a real view starting at `ret`. */
static void ios_sc_grant_note( void *ret, SIZE_T size )
{
    uint64_t r = (uint64_t)(ULONG_PTR)ret;
    MEMORY_BASIC_INFORMATION mbi;
    int i, known = 0;

    pthread_mutex_lock( &ios_sc_grant_lock );
    for (i = 0; i < ios_sc_grant_n; i++)
        if (ios_sc_grants[i].view == r || ios_sc_grants[i].report == r) known = 1;
    pthread_mutex_unlock( &ios_sc_grant_lock );
    if (known) return;
    if (NtQueryVirtualMemory( NtCurrentProcess(), ret, MemoryBasicInformation, &mbi, sizeof(mbi), NULL )
        || mbi.AllocationBase != ret || mbi.State == MEM_FREE) return;
    ios_sc_grant_add( r, r, size, size, r == (uint64_t)IOS_CAGE_BASE ? IOS_SC_K_CAGE : IOS_SC_K_OTHER,
                      ios_jit_current_peb() );
}

/* NtFreeVirtualMemory(MEM_RELEASE) of `base` by the calling process. Returns
 * 1 when it released an Oilpan grant of layout 2 (given as chrome_elf's base,
 * so the free names that) and *size is set; otherwise 0, with *rehold the kind
 * to hold again once a grant's own view at `base` is gone. */
static int ios_sc_grant_release( void *base, SIZE_T *size, int *rehold )
{
    uint64_t b = (uint64_t)(ULONG_PTR)base, oil_view = 0;
    void *peb;
    int i;

    *rehold = 0;
    if (!ios_sc_grant_n) return 0;
    peb = ios_jit_current_peb();
    pthread_mutex_lock( &ios_sc_grant_lock );
    for (i = 0; i < ios_sc_grant_n; i++)
    {
        if (ios_sc_grants[i].kind == IOS_SC2_OILPAN && ios_sc_grants[i].report == b
            && ios_sc_grants[i].peb == peb && !ios_sc_grants[i].dead)
        {
            oil_view = ios_sc_grants[i].view;
            ios_sc_grants[i] = ios_sc_grants[--ios_sc_grant_n];
            break;
        }
    }
    if (!oil_view)
        for (i = 0; i < ios_sc_grant_n; i++)
        {
            if (ios_sc_grants[i].view != b) continue;
            *rehold = ios_sc_grants[i].kind;
            if (ios_sc_grants[i].dead) ios_sc_grant_dead_n--;
            ios_sc_grants[i] = ios_sc_grants[--ios_sc_grant_n];
            break;
        }
    pthread_mutex_unlock( &ios_sc_grant_lock );
    if (!oil_view) return 0;
    {
        void *v = (void *)(ULONG_PTR)oil_view;
        SIZE_T s = 0;
        if (!NtFreeVirtualMemory( NtCurrentProcess(), &v, &s, MEM_RELEASE )) ios_sc_rehold( IOS_SC2_OILPAN );
    }
    dprintf( 2, "[sc-cef] layout 2: Oilpan's reservation 0x%llx released (its view 0x%llx)\n",
             (unsigned long long)b, (unsigned long long)oil_view );
    *size = 0x800000000ULL;
    return 1;
}

/* Layout 2: serve a SocialClubHelper.exe jumbo request from its slot. Returns 0
 * when the request is not one of the layout's (the generic path takes it), 1
 * with *st (and *pick / *sz on success) when it was decided here. */
static int ios_sc2_route( void *hint, SIZE_T size, ULONG type, ULONG protect, void **pick, SIZE_T *sz, NTSTATUS *st )
{
    void *peb = ios_jit_current_peb();
    int k = ios_sc2_classify( size, (uint64_t)(ULONG_PTR)hint, ios_sc2_held, ios_sc_grant_has( peb, IOS_SC2_E ),
                              ios_sc_grant_has( peb, IOS_SC2_L ), ios_sc_grant_has( peb, IOS_SC_K_CAGE ) );
    uint64_t base, report;
    void *p;
    SIZE_T s;

    if (k == IOS_SC2_NONE) return 0;
    if (k == IOS_SC2_REFUSE)
    {
        static unsigned refused;
        if (refused++ < 8)
            dprintf( 2, "[sc-cef] layout 2: 32 GB at a 32 GB boundary refused (hint %p, held 0x%x): both PartitionAlloc "
                        "blocks and Oilpan's are given, or this helper did not get both PartitionAlloc blocks -- "
                        "a fourth 32 GB block\n", hint, ios_sc2_held );
        *st = STATUS_NO_MEMORY;
        return 1;
    }
    base = ios_sc2_slots[k].base;
    ios_sc2_unhold( k );
    p = (void *)(ULONG_PTR)base;
    s = ios_sc2_slots[k].size;
    *st = allocate_virtual_memory( &p, &s, type, protect, 0, 0, 0, 0 );
    if (*st || (uint64_t)(ULONG_PTR)p != base)
    {
        if (!*st) { SIZE_T fs = 0; NtFreeVirtualMemory( NtCurrentProcess(), &p, &fs, MEM_RELEASE ); }
        ios_sc2_hold( k );
        dprintf( 2, "[sc-cef] layout 2: %s: [0x%llx,0x%llx) could not be reserved (st=0x%x)\n", ios_sc2_slots[k].what,
                 (unsigned long long)base, (unsigned long long)(base + ios_sc2_slots[k].size), (unsigned)*st );
        if (!*st) *st = STATUS_NO_MEMORY;
        return 1;
    }
    report = (k == IOS_SC2_OILPAN) ? IOS_SC2_E_BASE : base;
    ios_sc_grant_add( base, report, s, size, k, peb );
    *pick = (void *)(ULONG_PTR)report;
    *sz = size;
    dprintf( 2, "[sc-cef] layout 2: %s for SocialClubHelper.exe: 0x%llx (0x%lx asked), [0x%llx,0x%llx) reserved\n",
             ios_sc2_slots[k].what, (unsigned long long)report, (unsigned long)size,
             (unsigned long long)base, (unsigned long long)(base + ios_sc2_slots[k].size) );
    return 1;
}

/* ml433 (#72): map the boot cage holdback for an 8 GB ask -- see IOS_CAGE_BASE.
 * Shared by NtAllocateVirtualMemory's hinted-failure branch and, for
 * SocialClubHelper.exe's V8 sandbox in layout 2, NtAllocateVirtualMemoryEx
 * (ios_sc2_ex_cage). Returns the status; on success *pick / *sz are what the
 * caller is given: `asked` (the full 8 GB) at IOS_CAGE_BASE, whose real view is
 * 64 KB short -- an ios_soft tail entry absorbs a stray commit there. */
static NTSTATUS ios_cage_grant( ULONG type, ULONG protect, SIZE_T asked, void **pick, SIZE_T *sz, const char *rev )
{
    SIZE_T csz = IOS_CAGE_REAL_SIZE;
    NTSTATUS st;

    munmap( (void *)(uintptr_t)IOS_CAGE_BASE, IOS_CAGE_REAL_SIZE );
    ios_va_release_note();
    ios_cage_holdback_live = 0;
    *pick = (void *)(uintptr_t)IOS_CAGE_BASE;
    st = allocate_virtual_memory( pick, &csz, type, protect, 0, 0, 0, 0 );
    if (!st && (uintptr_t)*pick == IOS_CAGE_BASE)
    {
        *sz = asked;   /* report the full 8GB; the real view is 64K short */
        if (ios_soft_n < IOS_SOFT_MAX)
        {
            ios_soft[ios_soft_n].base = IOS_CAGE_BASE + IOS_CAGE_REAL_SIZE;
            ios_soft[ios_soft_n].size = 0x200000000ULL - IOS_CAGE_REAL_SIZE;
            ios_soft[ios_soft_n].cage = 1;
            ios_soft_n++;
        }
    }
    else if (!st) *sz = csz;   /* landed elsewhere: honest grant, no size lie */
    dprintf(2, "[cage] grant %p real=0x%llx reported=0x%lx st=0x%x rev=%s\n",
            *pick, (unsigned long long)IOS_CAGE_REAL_SIZE, (unsigned long)(st ? 0 : *sz), (unsigned)st, rev);
    return st;
}

/* Layout 2: is this SocialClubHelper.exe NtAllocateVirtualMemoryEx call V8's
 * 8 GB sandbox step? V8 allocates
 * through VirtualAlloc2 whenever kernelbase exports it (platform-win32.cc
 * VirtualAllocWrapper), so its sandbox never reaches NtAllocateVirtualMemory's
 * hinted-failure branch and the cage holdback there. Told 2 TB
 * (ios_sc2_reported_highest), V8 builds a partially reserved sandbox:
 * OS::Allocate(hint, size, 4 GB, kNoAccess) = VirtualAlloc2(hint, size,
 * MEM_RESERVE, PAGE_NOACCESS, no extended parameters), hinted then unhinted,
 * 512 GB halving to 8 GB (kSandboxMinimumReservationSize); the larger steps
 * fail as before. The 8 GB step gets the cage at its first call, hinted or
 * not: V8 takes any 4 GB-aligned base at or below half its limit
 * (AllocateInternal, InitializeAsPartiallyReservedSandbox), while its hint is
 * random below 1 TB and the 8 GB hole the unhinted call needs does not exist
 * (furniture's largest was 7885 MB in the 22:51 log). Gin's configurable pool
 * asks the same shape later; by then the holdback is gone. */
static int ios_sc2_ex_cage( SIZE_T size, ULONG type, ULONG protect, ULONG_PTR limit_low, ULONG_PTR limit_high,
                            ULONG_PTR align, ULONG attributes, int holdback_live )
{
    return holdback_live && size == 0x200000000ULL && type == MEM_RESERVE && protect == PAGE_NOACCESS &&
           !limit_low && !limit_high && !align && !attributes;
}

/* Layout 2: what a SocialClubHelper.exe commit [a, a + size) says about the
 * helper's grants g[0..n). *gi is the grant it concerns; *off the super
 * page's pool offset (metadata page commits), else the commit's end or offset
 * in the grant. Separated from the lookups for the host test. */
enum { IOS_SC2_C_OK, IOS_SC2_C_NEAR, IOS_SC2_C_PAST, IOS_SC2_C_BRP, IOS_SC2_C_BEYOND, IOS_SC2_C_N };
struct ios_sc2_gv { uint64_t view, real, report, asked; int kind; };

static int ios_sc2_commit_class( uint64_t a, uint64_t size, const struct ios_sc2_gv *g, int n, int *gi, uint64_t *off )
{
    int i, best = -1;

    for (i = 0; i < n; i++)
    {
        uint64_t rel = a - g[i].view, in;
        if (a < g[i].view || rel >= g[i].real) continue;
        *gi = i;
        if (g[i].kind == IOS_SC2_E || g[i].kind == IOS_SC2_L)
        {
            *off = a + size;
            return a + size > g[i].view + g[i].real - 0x20000000ULL ? IOS_SC2_C_NEAR : IOS_SC2_C_OK;
        }
        if (g[i].kind != IOS_SC2_J2 && g[i].kind != IOS_SC2_J2L) return IOS_SC2_C_OK;
        /* a metadata page: one 4 KB commit per new super page */
        in = rel & (IOS_SC2_SUPER_PAGE - 1);
        *off = rel - in;
        if (size != 0x1000) return IOS_SC2_C_OK;
        if (in == 0x3000) return IOS_SC2_C_BRP;
        if (in != 0x1000) return IOS_SC2_C_OK;
        if (*off >= IOS_SC2_POOL_REAL) return IOS_SC2_C_PAST;
        return *off >= IOS_SC2_POOL_REAL - 0x20000000ULL ? IOS_SC2_C_NEAR : IOS_SC2_C_OK;
    }
    /* in no grant's real view: the furniture window and the FEX arena have
     * their own users; elsewhere, the reported-but-unreserved part of a grant */
    if ((a >= ios_sc2_floor && a < IOS_SC2_J2_BASE) || a >= ios_sc2_arena_lo) return IOS_SC2_C_OK;
    for (i = 0; i < n; i++)
        if (g[i].view == g[i].report && a >= g[i].view + g[i].real && a < g[i].report + g[i].asked
            && (best < 0 || g[i].report > g[best].report)) best = i;
    if (best < 0) return IOS_SC2_C_OK;
    *gi = best;
    *off = a - g[best].report;
    return IOS_SC2_C_BEYOND;
}

static const char *ios_sc_kind_what( int kind )
{
    if (kind >= IOS_SC2_E && kind <= IOS_SC2_OILPAN) return ios_sc2_slots[kind].what;
    return kind == IOS_SC_K_CAGE ? "the V8 cage" : kind == IOS_SC_K_V1 ? "the layout 1 pools" : "a large reservation";
}

/* Layout 2: how far into each of its large grants a helper has committed, in
 * 256 MB steps (madeira-bcd). SocialClubHelper.exe died of Chromium's
 * out-of-memory exit after 24 minutes of GTA V Enhanced (log 2026-10-08
 * 13:39:08, build 451, 14:01:51); at 13:56 one of its commits had landed past
 * chrome_elf.dll's real 4 GB pool. These lines tell a pool that grows all
 * session long from one that jumps at the end. The metadata regions follow
 * their pools and are left out. Counted per helper; at most 64 lines. */
static void ios_sc2_note_growth( uint64_t a, uint64_t size, const struct ios_sc2_gv *gv, void *peb )
{
    static uint64_t high[IOS_SC_K_OTHER + 1];
    static void *high_peb[IOS_SC_K_OTHER + 1];
    static unsigned lines;
    uint64_t end = a + size - gv->view;
    int k = gv->kind;

    if (k < 0 || k > IOS_SC_K_OTHER || k == IOS_SC2_J2 || k == IOS_SC2_J2L) return;
    if (high_peb[k] != peb) { high_peb[k] = peb; high[k] = 0; }
    if (end <= high[k]) return;
    if ((end >> 28) > (high[k] >> 28) && lines < 64)
    {
        lines++;
        dprintf( 2, "[sc-cef] layout 2: SocialClubHelper.exe has committed %s up to +%llu MB (%llu MB real of "
                    "%llu MB reported)\n", ios_sc_kind_what( k ), (unsigned long long)(end >> 20),
                 (unsigned long long)(gv->real >> 20), (unsigned long long)(gv->asked >> 20) );
    }
    high[k] = end;
}

/* Layout 2: warn once per kind of trouble and grant when a helper's commit
 * shows a PartitionAlloc block running out of its real 4 GB, a BRP super page,
 * or a commit in the given-but-unreserved part of a grant. */
static void ios_sc2_note_commit( void *addr, SIZE_T size )
{
    static unsigned char warned[IOS_SC2_C_N][IOS_SC_K_OTHER + 1];
    struct ios_sc2_gv g[IOS_SC_GRANT_MAX];
    uint64_t a = (uint64_t)(ULONG_PTR)addr, off = 0;
    int i, n = 0, gi = -1, c, owner;
    void *peb;

    if (a < IOS_SC2_L_BASE || !ios_sc_grant_n || !ios_sc_current_is_helper()) return;
    peb = ios_jit_current_peb();
    pthread_mutex_lock( &ios_sc_grant_lock );
    for (i = 0; i < ios_sc_grant_n; i++)
    {
        if (ios_sc_grants[i].peb != peb || ios_sc_grants[i].dead) continue;
        g[n].view = ios_sc_grants[i].view;
        g[n].real = ios_sc_grants[i].real;
        g[n].report = ios_sc_grants[i].report;
        g[n].asked = ios_sc_grants[i].asked;
        g[n].kind = ios_sc_grants[i].kind;
        n++;
    }
    pthread_mutex_unlock( &ios_sc_grant_lock );
    c = ios_sc2_commit_class( a, size, g, n, &gi, &off );
    if (gi >= 0 && (c != IOS_SC2_C_OK || a - g[gi].view < g[gi].real))   /* a commit in this grant */
        ios_sc2_note_growth( a, size, &g[gi], peb );
    if (c == IOS_SC2_C_OK || g[gi].kind < 0 || g[gi].kind > IOS_SC_K_OTHER || warned[c][g[gi].kind]) return;
    warned[c][g[gi].kind] = 1;
    owner = g[gi].kind == IOS_SC2_J2 ? IOS_SC2_E : g[gi].kind == IOS_SC2_J2L ? IOS_SC2_L : g[gi].kind;
    if (c == IOS_SC2_C_NEAR && owner == g[gi].kind)
        dprintf( 2, "[sc-cef] layout 2: %s reached 0x%llx, within 512 MB of the end of its real 4 GB\n",
                 ios_sc_kind_what( owner ), (unsigned long long)off );
    else if (c == IOS_SC2_C_NEAR)
        dprintf( 2, "[sc-cef] layout 2: %s took a super page at pool offset 0x%llx (metadata 0x%llx), within "
                    "512 MB of the end of its real 4 GB\n", ios_sc_kind_what( owner ), (unsigned long long)off,
                 (unsigned long long)a );
    else if (c == IOS_SC2_C_PAST)
        dprintf( 2, "[sc-cef] layout 2: %s took a super page at pool offset 0x%llx (metadata 0x%llx), PAST its real "
                    "4 GB -- its pages land on other mappings\n", ios_sc_kind_what( owner ), (unsigned long long)off,
                 (unsigned long long)a );
    else if (c == IOS_SC2_C_BRP)
        dprintf( 2, "[sc-cef] layout 2: %s took a BackupRefPtr pool super page at offset 0x%llx (metadata 0x%llx) -- "
                    "that half is not reserved for it\n", ios_sc_kind_what( owner ), (unsigned long long)off,
                 (unsigned long long)a );
    else
    {
        MEMORY_BASIC_INFORMATION mbi;
        void *ab = NULL;
        if (!NtQueryVirtualMemory( NtCurrentProcess(), addr, MemoryBasicInformation, &mbi, sizeof(mbi), NULL ))
            ab = mbi.AllocationBase;
        dprintf( 2, "[sc-cef] layout 2: SocialClubHelper.exe commit 0x%llx+0x%lx is in %s's given-but-unreserved "
                    "[0x%llx,0x%llx) (allocation base %p) -- it lands on another mapping\n",
                 (unsigned long long)a, (unsigned long)size, ios_sc_kind_what( g[gi].kind ),
                 (unsigned long long)(g[gi].view + g[gi].real), (unsigned long long)(g[gi].report + g[gi].asked), ab );
    }
}

/***********************************************************************
 *           ios_sc_glued_pools                           (madeira-bcd)
 *
 * SocialClubHelper.exe's chrome_elf.dll asks for PartitionAlloc's glued core
 * pools: 32 GB on a 32 GB boundary (see IOS_SC_GLUED_BASE). The slot walk below
 * can only give 0x7400000000: PartitionAlloc freed it as misaligned three times,
 * then asked for 64 GB - 64 KB to align it itself and died at
 * chrome_elf.dll+0x13add4 with 0x80000003 (GTA log 2026-10-02 16:19, lines
 * 49107-49230: "[jumbo] kernel-pick reserve failed (0xc0000017) for
 * size=0xfffff0000"; five helpers, five deaths).
 *
 * With env.MADEIRA_SC_PA_POOLS = 1 (the arena moved at boot, the 4 GB under it
 * held): release the hold and reserve [0x7800000000, 0x7d00000000) as one real
 * view, the regular pool and the first 4 GB of the BackupRefPtr pool, and
 * report the 32 GB that was asked for. A helper started again after the first
 * one died gets the same range: ios_sc_reap_dead releases the dead one's view
 * and holds the 4 GB again. Returns 0 with the grant in *pick / *sz, else a
 * failure status with nothing reserved. */
static NTSTATUS ios_sc_glued_pools( void **pick, SIZE_T *sz, ULONG type, ULONG protect )
{
    void *lo = (void *)(uintptr_t)IOS_SC_GLUED_BASE;
    SIZE_T lsz = IOS_SC_BRP_HOLD_BASE + IOS_SC_BRP_HOLD_SIZE - IOS_SC_GLUED_BASE;   /* 20 GB */
    NTSTATUS st;

    if (!ios_sc_brp_layout)
    {
        static int said;
        if (!said++)
            dprintf( 2, "[sc-cef] SocialClubHelper.exe asks for PartitionAlloc's glued 32 GB pools at a 32 GB "
                        "boundary; without env.MADEIRA_SC_PA_POOLS=1 there is none to give (FEX's arena covers "
                        "0x7c00000000) -- its chrome_elf.dll will fail as before\n" );
        return STATUS_NO_MEMORY;
    }
    if (ios_sc_brp_held)
    {
        mach_vm_deallocate( mach_task_self(), IOS_SC_BRP_HOLD_BASE, IOS_SC_BRP_HOLD_SIZE );
        ios_sc_brp_held = 0;
    }
    st = allocate_virtual_memory( &lo, &lsz, type, protect, 0, 0, 0, 0 );
    if (st || (uintptr_t)lo != IOS_SC_GLUED_BASE)
    {
        mach_vm_address_t h = IOS_SC_BRP_HOLD_BASE;
        if (!st) { SIZE_T fsz = 0; void *fb = lo; NtFreeVirtualMemory( NtCurrentProcess(), &fb, &fsz, MEM_RELEASE ); }
        /* keep the 4 GB for a later helper if nothing took it meanwhile */
        if (mach_vm_map( mach_task_self(), &h, IOS_SC_BRP_HOLD_SIZE, 0, VM_FLAGS_FIXED, MEMORY_OBJECT_NULL, 0, 0,
                         PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY ) == KERN_SUCCESS)
            ios_sc_brp_held = 1;
        dprintf( 2, "[sc-cef] glued PartitionAlloc pools: [0x%llx,0x%llx) is not free (st=0x%x) -- falling back "
                    "to the slot walk\n", IOS_SC_GLUED_BASE, IOS_SC_BRP_HOLD_BASE + IOS_SC_BRP_HOLD_SIZE, (unsigned)st );
        return st ? st : STATUS_NO_MEMORY;
    }
    *pick = lo;
    *sz = IOS_SC_GLUED_SIZE;
    ios_sc_grant_add( IOS_SC_GLUED_BASE, IOS_SC_GLUED_BASE, lsz, IOS_SC_GLUED_SIZE, IOS_SC_K_V1, ios_jit_current_peb() );
    dprintf( 2, "[sc-cef] glued PartitionAlloc pools for SocialClubHelper.exe: 32 GB at 0x%llx; [0x%llx,0x%llx) "
                "reserved (regular pool + the first 4 GB of the BackupRefPtr pool), the rest of it lies over FEX's "
                "arena and is never reached\n",
             IOS_SC_GLUED_BASE, IOS_SC_GLUED_BASE, IOS_SC_BRP_HOLD_BASE + IOS_SC_BRP_HOLD_SIZE );
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI NtAllocateVirtualMemory( HANDLE process, PVOID *ret, ULONG_PTR zero_bits,
                                         SIZE_T *size_ptr, ULONG type, ULONG protect )
{
#ifdef WINE_IOS
    ios_tls38_poll( "valloc" );
#endif
    static const ULONG type_mask = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH | MEM_RESET;
    ULONG_PTR limit;
#ifdef WINE_IOS
    /* ml373: *ret is overwritten with the result, so the [guest-reserve] census
     * below cannot ask afterwards whether the caller supplied a hint — and a
     * hinted reserve is invisible to the steering valve (`!*ret`), which is a
     * different fix. Capture it here. */
    const int hint_was_set = (ret && *ret) ? 1 : 0;
    /* ml959: the VALUE too, not just whether one was supplied -- *ret is
     * overwritten with the result. */
    const UINT64 ios_req_hint = (ret && *ret) ? (UINT64)(ULONG_PTR)*ret : 0;
#endif

    TRACE("%p %p %08lx %x %08x\n", process, *ret, *size_ptr, type, protect );
#ifdef WINE_IOS
    /* ml284: does ANYTHING allocate/commit executable memory, and where?
     *
     * There is already an exec-allocation probe here using ERR(), but the `virtual` debug
     * channel is filtered by MADEIRA_QUIET -- err:virtual: appears ZERO times in the logs,
     * including the uncapped first-30 lines it should always emit. So its silence carries
     * no information, and I must not read "no exec allocations happen" from it. (That is
     * the same mistake as the [unexec] probe, whose filters made me wrongly retract the
     * V8-code-space theory.) Working probes on this side all use raw dprintf(2) --
     * [iat-sync], [jit-pool], [steer], [x86-ptr] -- so use that.
     *
     * Covers BOTH allocate entry points: [exec-req] hooks only NtProtectVirtualMemory, but
     * VirtualAlloc(MEM_COMMIT, PAGE_EXECUTE_READWRITE) grants exec through
     * NtAllocateVirtualMemory, and VirtualAlloc2/placeholders through the Ex variant --
     * which V8 commonly uses for its code cage. Unfiltered by address, capped only by
     * count, so silence here really does mean "never requested". */
    /* ml288: narrowed. The first cut logged EVERY exec allocation and fired 52 times in
     * ml287, each a dprintf(2) syscall inside NtAllocateVirtualMemory. CEF's own depth then
     * dropped from 8 verbose lines (pref_proxy_config_tracker, 3 runs running) to 4
     * (VariationsSetupComplete, 2 runs running) exactly when that probe shipped. Two runs is
     * not proof against variance, but a probe that may perturb what it measures has to go on
     * a diet -- and its finding is already banked: exec allocations DO happen, the two 16MB
     * PAGE_EXECUTE_READWRITE ones get no [jit-pool] anon RWX carve, and there is no
     * EXHAUSTED. Only the large ones carry information, so log those. */
    /* ml290: re-widened to ALL sizes (cap 20).
     *
     * [guest-caller] named the caller of the recurring fault: chrome_elf.dll (+0x6c4a2 on
     * two different threads, plus +0xd7d6e and +0x10d4c0). chrome_elf is Chromium's early
     * loader, and its job is installing INTERCEPTION THUNKS -- it patches ntdll entry points
     * to jump into thunk memory it allocates itself. If that memory is not executable, the
     * first call through a hooked function lands on a non-executable page: our fault
     * exactly, at a stable small offset, and unrelated to proxying (ruled out in ml290 --
     * the fault still fired 23x with --no-proxy-server active).
     *
     * The >=1MB narrowing I applied in ml288 hides precisely the evidence needed, because
     * interception allocations are ONE PAGE each -- e.g. the three consecutive
     * req_addr=0x73d172{c,d,e}000 size=0x1000 protect=0x40 requests seen earlier, at
     * explicit addresses in the ntdll band. Cap 20 keeps the syscall cost far below the 52
     * of the first cut while restoring the small-allocation signal, so each request can be
     * matched against the [jit-pool] anon RWX carves that follow. */
    if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
    {
        static int execalloc_n;
        if (execalloc_n < 20)
        {
            execalloc_n++;
            dprintf( 2, "[exec-alloc] %s #%d req_addr=%p size=0x%llx type=0x%x protect=0x%x\n",
                     "NtAllocateVirtualMemory", execalloc_n, ret ? *ret : NULL,
                     (unsigned long long)(size_ptr ? *size_ptr : 0), type, protect );
        }
    }
#endif

#ifdef WINE_IOS
    {
        static int alloc_dbg = 0;
        if (alloc_dbg++ < 30 || (protect & 0xF0))
            ERR("NtAllocateVirtualMemory: size=0x%lx type=0x%x prot=0x%x\n",
                (unsigned long)*size_ptr, type, protect);
    }
#endif

    if (!*size_ptr) return STATUS_INVALID_PARAMETER;
    if (zero_bits > 21 && zero_bits < 32) return STATUS_INVALID_PARAMETER_3;
    if (zero_bits > 32 && zero_bits < granularity_mask) return STATUS_INVALID_PARAMETER_3;
#ifndef _WIN64
    if (!is_old_wow64() && zero_bits >= 32) return STATUS_INVALID_PARAMETER_3;
#endif
    if (type & ~type_mask) return STATUS_INVALID_PARAMETER;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;
        unsigned int status;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc.type         = APC_VIRTUAL_ALLOC;
        call.virtual_alloc.addr         = wine_server_client_ptr( *ret );
        call.virtual_alloc.size         = *size_ptr;
        call.virtual_alloc.zero_bits    = zero_bits;
        call.virtual_alloc.op_type      = type;
        call.virtual_alloc.prot         = protect;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc.status == STATUS_SUCCESS)
        {
            *ret      = wine_server_get_ptr( result.virtual_alloc.addr );
            *size_ptr = result.virtual_alloc.size;
        }
        else
        {
            WARN( "cross-process allocation failed, process=%p base=%p size=%08lx status=%08x",
                  process, *ret, *size_ptr, result.virtual_alloc.status );
        }
        return result.virtual_alloc.status;
    }

    if (!*ret)
        limit = get_zero_bits_limit( zero_bits );
    else
        limit = 0;

#ifdef WINE_IOS
    {
        NTSTATUS st;
        /* task #35 DEMAND CENSUS: is CEF's ~144GB real, or is it retries?
         * The [jumbo] lines are one-per-call, and PartitionAlloc re-rolls a
         * fresh random hint when a reserve fails — so three failed 16GB lines
         * are equally consistent with ONE pool retried three times as with
         * three distinct pools. 144GB is hopeless against a 63GB window; ~80GB
         * (3 pools + one 32GB region) is closeable by freeing slots. Log every
         * jumbo call with a sequence number, inter-call gap and thread so
         * retries (same size, same tid, sub-ms apart) separate from distinct
         * reservations — and so a caller that DEGRADES after failure (asks
         * again smaller) shows up as a descending size run. */
        void  *jumbo_hint = *ret;
        size_t jumbo_size = *size_ptr;
        int    is_jumbo   = (jumbo_size >= 0x40000000 && (type & MEM_RESERVE));
        /* ml125 [bigres]: settle the furniture attribution WITHOUT an FEX build.
         * The [window] probe found ~30 runs of ~511MB and I inferred FEXCore's
         * per-thread LookupCache (TotalCacheSize = VirtualMemSize/4096*8 +
         * CODE_SIZE + MAX_L1_SIZE) — but I have now mis-attributed this twice
         * from size coincidences alone, so measure it instead: every reserve
         * between 256MB and the 1GB jumbo threshold, with a running total and
         * count. If ~31 of these land at exactly 0x1ff10000 the attribution is
         * proven and the page-pointer array is the thing to shrink; if they are
         * a mix of sizes it is something else entirely and the FEX redesign
         * would have been wasted work. */
        if ((type & MEM_COMMIT) && ios_bigres_cnt && *ret)
            ios_bigres_commit( *ret, *size_ptr );
        /* madeira-bcd: Social Club layout 2's PartitionAlloc blocks are 4 GB real */
        if ((type & MEM_COMMIT) && *ret && ios_sc_layout_mode == 2)
            ios_sc2_note_commit( *ret, *size_ptr );
        /* madeira-bcd: a helper's large ask first releases what dead helpers held */
        if (is_jumbo && ios_sc_grant_dead_n && ios_sc_cef_enabled() && ios_sc_current_is_helper())
            ios_sc_reap_dead();
        /* ml151: a commit landing in a SOFT pool range — see ios_soft. The range
         * was never backed, so materialise exactly this sub-range now. Check the
         * kernel map first: if something already owns the VA (furniture, most
         * likely, since the only free aligned slot overlaps the furniture
         * window) that is the collision this design has to be judged on, so say
         * so loudly rather than silently handing PA someone else's memory. */
        if ((type & MEM_COMMIT) && ios_soft_n && *ret)
        {
            int si = ios_soft_find( (uint64_t)(uintptr_t)*ret );
            if (si >= 0)
            {
                uint64_t want = (uint64_t)(uintptr_t)*ret & ~(uint64_t)host_page_mask;
                size_t need = ROUND_SIZE( (uintptr_t)*ret - want, *size_ptr, host_page_mask );
                mach_vm_address_t a = (mach_vm_address_t)want;
                mach_vm_size_t rsz = 0;
                vm_region_basic_info_data_64_t inf;
                mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
                mach_port_t obj = MACH_PORT_NULL;
                int occupied = 0;

                if (mach_vm_region( mach_task_self(), &a, &rsz, VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&inf, &cnt, &obj ) == KERN_SUCCESS && a <= want)
                    occupied = 1;

                /* ml152: ask WINE first, not just the kernel. The soft range
                 * spans the furniture window, so most commits landing in it are
                 * ordinary allocations committing memory they legitimately
                 * reserved — the first cut labelled all 33 of them COLLISION and
                 * buried the real signal. If Wine owns a view here it is not our
                 * business: fall through silently. A genuine collision is VA that
                 * Wine does NOT own yet something else has mapped. */
                if (find_view( (void *)(uintptr_t)want, need ))
                {
                    /* furniture's own commit — normal path, no bookkeeping.
                     * ml434 (#72): EXCEPT the soft cages, which deliberately sit
                     * inside the PA guard pool's real (mostly dead) reservation —
                     * their commits ride the guard view silently, so count them
                     * and log the first few. A commit near the guard pool's
                     * ACTIVE bottom would be the collision to watch for. */
                    if (ios_soft[si].cage)
                    {
                        ios_soft[si].commits++;
                        ios_soft[si].committed += need;
                        if (ios_soft[si].commits <= 8)
                            dprintf(2, "[cage-commit] #%u 0x%llx+0x%lx in soft cage 0x%llx (total %lluMB) rev=ml434\n",
                                    ios_soft[si].commits, (unsigned long long)want, (unsigned long)need,
                                    (unsigned long long)ios_soft[si].base,
                                    (unsigned long long)(ios_soft[si].committed >> 20));
                    }
                }
                else if (occupied)
                {
                    ios_soft[si].commits++;
                    ios_soft[si].collisions++;
                    dprintf(2, "[soft-pool] COLLISION: commit 0x%llx+0x%lx inside soft 0x%llx —"
                               " VA mapped but NOT a wine view (0x%llx+0x%llx prot=%x/%x)."
                               " Foreign mapping in the pool range.\n",
                            (unsigned long long)want, (unsigned long)need,
                            (unsigned long long)ios_soft[si].base,
                            (unsigned long long)a, (unsigned long long)rsz,
                            inf.protection, inf.max_protection);
                }
                else
                {
                    unsigned int svp = 0;
                    void *mp;
                    ios_soft[si].commits++;
                    get_vprot_flags( protect, &svp, FALSE );
                    mp = anon_mmap_fixed( (void *)(uintptr_t)want, need,
                                          get_unix_prot( (BYTE)(svp | VPROT_COMMITTED) ), 0 );
                    ios_soft[si].committed += need;
                    dprintf(2, "[soft-pool] materialised 0x%llx+0x%lx in soft 0x%llx -> %p"
                               " (total %lluMB in %u calls)\n",
                            (unsigned long long)want, (unsigned long)need,
                            (unsigned long long)ios_soft[si].base, mp,
                            (unsigned long long)(ios_soft[si].committed >> 20),
                            ios_soft[si].commits);
                    if (mp != MAP_FAILED) { *ret = (void *)(uintptr_t)want; *size_ptr = need; return STATUS_SUCCESS; }
                }
            }
        }
        if (jumbo_size >= 0x10000000 && jumbo_size < 0x40000000 && (type & MEM_RESERVE))
        {
            static unsigned bigres_n;
            static unsigned long long bigres_tot;
            bigres_n++;
            bigres_tot += jumbo_size;
            ios_bigres_reserved_total += jumbo_size;
            /* ml126: ATTRIBUTE BY PROCESS, not by size. All 23 were exactly
             * 512MB, which rules out FEXCore's LookupCache (a computed sum) and
             * the CallRetStack (16MB), and no FEX VirtualAlloc site asks for
             * 512MB either -- so this may well be the GUEST (V8's x64
             * kMaximalCodeRangeSize is 512MB, which would fit CEF). ERR gives
             * the wine tid prefix for free, and the PEB identifies WHICH
             * pseudo-process: correlate against the [init-peb]/NtCreateUserProcess
             * map. If these are steamwebhelper's PEB it is CEF/V8 and the fix is
             * a command-line flag, not an FEX redesign -- a completely different
             * and far cheaper answer than the one I was about to build. */
            /* ml127: use dprintf, NOT ERR. The `virtual` debug channel's ERR is
             * suppressed in this build (err:virtual: appears 0 times in a log
             * with 526 err:seh: lines), so routing this through ERR to get the
             * tid prefix silenced the probe completely — 23 lines in ml126, 0 in
             * ml127. Same reason alloc_arm64ec_map's ERR has never appeared in
             * any log. Read the tid out of the TEB instead. */
            /* ml129: FEX's own hook ENCODES which structure this is, and I was
             * simply not printing it. AllocatorHooks.h does
             *   VirtualAlloc(Base, Size, Commit ? MEM_RESERVE|MEM_COMMIT : MEM_RESERVE,
             *                Execute ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE)
             * so protect==0x40 (PAGE_EXECUTE_READWRITE) means an Execute
             * allocation -- a JIT code buffer (CPUBackend) or the dispatcher --
             * while 0x04 (PAGE_READWRITE) means data, and the MEM_COMMIT bit
             * separates the commit-upfront LookupCache path from pure reserves.
             * That splits the remaining candidates without an FEX build, and
             * without wiring a unixlib that iOS deliberately no-ops. */
            dprintf( 2, "[bigres] tid=%04x #%u size=0x%lx (%lu MB) type=0x%x prot=0x%x hint=%p peb=%p total=%llu MB\n",
                     NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0,
                     bigres_n, (unsigned long)jumbo_size,
                     (unsigned long)(jumbo_size >> 20), (unsigned)type, (unsigned)protect,
                     jumbo_hint, NtCurrentTeb() ? NtCurrentTeb()->Peb : NULL, bigres_tot >> 20 );
            /* ml128: NAME THE CALLER. Elimination has run out — it is exactly
             * 2 x 512MB per guest thread of steam.exe (peb=0x11da68000, 12 tids),
             * and it is NOT the LookupCache (VirtualMemSize = 1ULL<<33 makes
             * TotalCacheSize ~96MB, below this probe's 256MB floor), NOT the
             * CallRetStack (16MB), NOT the emulator stack (256KB), and no FEX
             * VirtualAlloc site asks for 512MB. So stop reasoning about sizes and
             * read the return addresses off the stack, the same way [exit-stk]
             * does. Module base + offset is enough — names come from the
             * [jit-pool] image lines in the same log. */
            /* ml166: this scan HAS been running every run and I had simply never read its
             * output. Symbolising it settles the owner and REFUTES two earlier claims:
             *   - the 512MB reserves ARE FEX's own: mod 0x73f09d0000 = libarm64ecfex.dll,
             *     +0x125834/+0x125860 -> VirtualAlloc, +0x1e7e08 -> $iexit_thunk$cdecl$i8$i8.
             *     So "type=0x2000 proves the caller is NOT FEX" (the AllocatorHooks
             *     MEM_TOP_DOWN note) does NOT hold here, and the ml128 claim "no FEX
             *     VirtualAlloc site asks for 512MB" is wrong.
             *   - but those are FEX's own ALLOCATOR frames, the nearest ones. The subsystem
             *     that asked is deeper, and the old limits hid it: 6 hits, bigres_n <= 4.
             *
             * Scan deeper, report more, and cover the LATE reservations (#18+) which are the
             * ones that exhaust the window: 27 x 512MB filled 13.8GB of 15.1GB while
             * committing 1%, maxgap fell to 28MB, a 512MB reserve FAILED, and the NULL
             * return was stored through (`stp x8,x20,[x0]` with x0=0). Which FEX subsystem
             * this is decides the fix: smaller per-thread arena vs relocation above the
             * ceiling vs soft reservation. */
            if (bigres_n <= 4 || (bigres_n >= 18 && bigres_n <= 30))
            {
                uint64_t *sp = (uint64_t *)__builtin_frame_address(0);
                int w, hits = 0, wmax = ios_ml1041_readable_words( sp, 1024 );
                for (w = 0; w < wmax && hits < 20; w++)
                {
                    uint64_t mod = 0, va = ios_jit_reverse_translate( sp[w], &mod );
                    if (va && mod && va != sp[w])
                    {
                        dprintf( 2, "[bigres]   caller#%u sp+0x%x: 0x%llx = mod 0x%llx +0x%llx\n",
                                 bigres_n, w * 8, (unsigned long long)sp[w],
                                 (unsigned long long)mod, (unsigned long long)(va - mod) );
                        hits++;
                    }
                }

                /* ml167 GUEST-STACK ATTRIBUTION — the one route not yet tried.
                 *
                 * The native scan above is NOT proof of ownership: it surfaces any
                 * code-like value on the stack, including DEAD frames from earlier FEX
                 * activity on that thread, and I over-trusted its libarm64ecfex hits last
                 * round. The flags actually EXCLUDE every FEX site I can enumerate —
                 * type=0x2000 has no MEM_TOP_DOWN, and FEXCore::Allocator::VirtualAlloc
                 * unconditionally ORs it (AllocatorHooks.h: Flags = (Commit?MEM_COMMIT:0)
                 * | MEM_RESERVE | MEM_TOP_DOWN); CallRetStack is MEM_TOP_DOWN+PAGE_NOACCESS;
                 * the iOS LookupCache path passes Commit=true (FEX_IOS_HOST=1 is global).
                 *
                 * All four earlier attribution attempts were RIP-based and returned NATIVE
                 * addresses inside VirtualAlloc itself. So walk the GUEST stack instead:
                 * the saved x64 CONTEXT is at CPUArea+0x50, Rsp at +0x98 (Rip at +0xF8, as
                 * the ios_guest_ctx_rip comment records). x86-64 return addresses there
                 * point at PE module VAs, which are STABLE all run (unlike pool copies the
                 * freelist recycles), so they resolve offline against [jit-pool] image.
                 *
                 * What this decides: 2 x 512MB per guest thread at 1% commit, with
                 * [bigres] total only ever GROWING, is either a size knob or a per-thread
                 * reservation never released on thread exit — both cheap and safe. Only if
                 * it is neither do we need overcommit/aliasing, which is unsound in general
                 * (an app is entitled to grow into a range it reserved). */
                {
                    TEB *t = NtCurrentTeb();
                    void *ca = t ? *(void **)((char *)t + 0x1788) : NULL;

                    if ((uintptr_t)ca >= 0x10000)
                    {
                        uint64_t grsp = *(uint64_t *)((char *)ca + 0x50 + 0x98);
                        uint64_t grip = *(uint64_t *)((char *)ca + 0x50 + 0xF8);

                        dprintf( 2, "[bigres]   guest#%u rsp=0x%llx rip=0x%llx\n",
                                 bigres_n, (unsigned long long)grsp,
                                 (unsigned long long)grip );
                        /* Only read the guest stack if Wine owns the range. A raw deref
                         * here would fault mid-syscall (this is not a signal handler, so
                         * it would surface as a real AV and cost the run). find_view is
                         * the header-free check already available in this TU. */
                        if (grsp >= 0x10000 && !(grsp & 7)
                            && find_view( (const void *)(uintptr_t)grsp, 0x1000 ))
                        {
                            const uint64_t *gs = (const uint64_t *)(uintptr_t)grsp;
                            int g, gh = 0;
                            for (g = 0; g < 256 && gh < 12; g++)
                            {
                                uint64_t v = gs[g];
                                if (v < 0x7300000000ULL || v >= 0x7400000000ULL) continue;
                                dprintf( 2, "[bigres]   guest#%u rsp+0x%x: 0x%llx\n",
                                         bigres_n, g * 8, (unsigned long long)v );
                                gh++;
                            }
                        }
                    }
                }
            }
        }
        /* task#29 CEF: PartitionAlloc (chrome_elf DllMain) reserves multi-GB
         * pools. iOS caps user VA at 0x8000000000 (39-bit; extended-VA is not
         * available to free personal teams) and wine's furniture (PE images,
         * TEBs, stacks, EC bitmap) clusters at the TOP of that space. */
        if (!*ret && *size_ptr >= 0x40000000 && (type & MEM_RESERVE) && !limit)
        {
            /* ml92 (task #35) MEASURED, replacing two generations of guesses.
             * The original target was [256G,480G) — written before the GPU
             * carveout was known, and 192GB of it is carveout, so it could
             * never be served. The replacement target [8G,64G) is no better:
             * the map walk shows the only free region below 64G is
             * 0..0x102454000 = __PAGEZERO, and 4G-64G is fully reserved
             * (malloc xzone). There is no middle zone. Usable VA is exactly
             * one window, 0x7038000000..0x7fffdf0000 (~63GB), which is what
             * the default search already targets — so skip the pointless
             * pre-attempt and let the hinted-retry slot walk below do the
             * work. Probe the map when we come up short. */
            st = allocate_virtual_memory( ret, size_ptr, type, protect, 0, limit, 0, 0 );
            if (st)
            {
                static int probed;
                dprintf(2, "[jumbo] kernel-pick reserve failed (0x%x) for size=0x%lx — top window is full\n",
                        (unsigned)st, (unsigned long)*size_ptr);
                /* ml997: serve it from the boot holdback HERE. rdr65 proved this
                 * is the branch that runs -- it printed the line above and then
                 * gave up, while ml996's take() sat in the hinted-retry branch
                 * further down and was never reached (no "releasing" line in the
                 * whole log). Confirm the live branch from a log before patching
                 * one; this is the third time in this effort that a hook went
                 * into a path the evidence never showed executing. */
                {
                    uintptr_t hb = ios_jumbo_holdback_take( *size_ptr );
                    if (hb)
                    {
                        void *pick2 = (void *)hb;
                        SIZE_T csz = *size_ptr;
                        unsigned int st3 = allocate_virtual_memory( &pick2, &csz, type, protect,
                                                                    0, 0, 0, 0 );
                        dprintf( 2, "[jumbo-hold] ml997 mapped at the holdback -> %p size=0x%lx "
                                 "st=0x%x\n", pick2, (unsigned long)csz, st3 );
                        if (!st3)
                        {
                            *ret = pick2;
                            *size_ptr = csz;
                            return STATUS_SUCCESS;
                        }
                    }
                }
                ios_band_census( "jumbo reserve failed" );   /* env.MADEIRA_BAND_CENSUS = 1 only */
                if (probed++ < 2)
                {
                    ios_va_gap_probe( "jumbo reserve failed" );
                    ios_va_occupancy_probe( "jumbo reserve failed" );   /* ml994 */
                    /* task #35: the gap walk says HOW MUCH is left; this says
                     * WHAT ate the window, which is what decides whether a
                     * third pool is reachable at all. */
                    ios_window_inventory( "jumbo reserve failed",
                                          ios_usable_va_floor, ios_furniture_ceiling );
                    ios_slot_probe( "jumbo reserve failed" );
                    ios_bigres_report( "jumbo reserve failed" );
                    ios_soft_report( "jumbo reserve failed" );
                }
            }
        }
        else
        {
            /* ml168 STEERING VALVE (task #35/#36): under furniture pressure, place
             * large RESERVE-ONLY, unhinted allocations ABOVE the furniture ceiling.
             *
             * Deliberately a PRESSURE VALVE, not a behaviour change: it arms only once
             * >8GB of 256MB..1GB reserves have already been granted, which never happens
             * in a Thumper run, so existing working cases keep their exact placement.
             * MEM_COMMIT requests are excluded — those are backed immediately and belong
             * where the allocator would normally put them; only reserve-only ranges (the
             * 1%-committed kind measured by [bigres-use]) get moved.
             *
             * Above the ceiling the space is the pool slots, which [bigres-use] shows at
             * 0% committed (POOL 0x7400000000/0x7800000000/0x7c00000000 all 0MB), so the
             * range is there to use. It is NOT free of risk: PartitionAlloc owns those
             * slots and could commit into one later, which the [soft-pool] COLLISION
             * detector would then report. That is why this stays pressure-gated and why
             * it always FALLS BACK to normal placement on failure — a steer that cannot
             * be served must never be worse than not steering. */
            int ios_steered = 0;

            /* ml373: floor 256MB -> 32MB.
             *
             * ml373 died with the guest window at 15195 MB of 15232 (free=36 MB,
             * maxhole=3 MB): steamclient64.dll (0x1964000 = 25 MB) could not be
             * mapped, c0000017 x28, webhelper dead — and the run logged ZERO
             * [steer] lines, i.e. the valve never fired once. The [window]
             * histogram says why: the guest band is eaten by n=88 reserves in the
             * <=512M bucket (8438 MB) and n=151 in the <=64M bucket (4993 MB),
             * while the valve only ever considered [256MB, 1GB). FEX is NOT the
             * hog — [vname] totals put 5.4GB of FEXMem_* correctly in [0x7c,0x80)
             * and only 81MB in the guest band — so this is Steam/CEF's own
             * reserve-only memory, exactly the 1%-committed kind this valve was
             * built to move.
             *
             * Same target band as before ([0x7c,0x80), which [vname] shows is
             * ~10GB free), same pressure gate, same fall-back-on-failure rule, so
             * a steer that cannot be served is still never worse than not
             * steering. The 1GB ceiling stays: >=1GB reserves are PartitionAlloc
             * pool business and go through the jumbo path above. */
            /* iOS-Madeira ml462 (#77): V8 CodeRange placement service + livelock
             * breaker. Signature: kernel-pick, reserve-only, PAGE_NOACCESS,
             * 512MB(+slop) — V8's kMaximalCodeRangeSize, wanting to land within
             * jump distance of libcef's embedded builtins in the module band
             * (its own preferred hint 0x71e0000000 collides with loaded DLLs
             * and everything the kernel picks elsewhere gets rejected+released;
             * ml461 looped this forever). Serve it from [0x7100000000,
             * 0x71c0000000) — free space directly below the module band, ~1GB
             * from the builtins. V8 redoes its own alignment two-step inside
             * the zone (the aligned re-reserve arrives hinted and the normal
             * path grants it). If the guest has already cycled 32 grants of
             * this shape, placement cannot satisfy it — deny outright so V8
             * fails NAMED in cef_log instead of eating the FEX band. */
            if (!*ret && !limit && (type & MEM_RESERVE) && !(type & MEM_COMMIT)
                && protect == PAGE_NOACCESS
                && *size_ptr >= 0x20000000 && *size_ptr <= 0x20100000)
            {
                unsigned ctid = NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0;
                unsigned cyc = ios_reserve_cycle_count( ctid, *size_ptr );
                static unsigned cr_logs;
                if (cyc >= IOS_RESCYCLE_DENY)
                {
                    if (cr_logs < 16)
                        dprintf(2, "[coderange] DENY tid=%04x size=0x%lx cycles=%u — placement livelock, failing honestly rev=ml462\n",
                                ctid, (unsigned long)*size_ptr, cyc);
                    cr_logs++;
                    return STATUS_NO_MEMORY;
                }
                {
                    SIZE_T cwant = *size_ptr;
                    void *csaved = *ret;
                    /* ml463: floor raised 0x7100000000 -> 0x7180000000. The
                     * ml462 run granted the zone BOTTOM (0x7100000000, ~3.5GB
                     * from the builtins) and V8 cycled 4 more grant/release
                     * rounds before settling — consistent with a ±2GB reach
                     * check (acceptable floor ~0x7162000000). Start inside the
                     * window so the first grant sticks. */
                    NTSTATUS cst = allocate_virtual_memory( ret, size_ptr, type, protect,
                                                            0x7180000000ULL, 0x71c0000000ULL, 0, 0 );
                    if (cr_logs < 16)
                        dprintf(2, "[coderange] #%u tid=%04x size=0x%lx cycles=%u -> %s %p rev=ml462\n",
                                cr_logs, ctid, (unsigned long)cwant, cyc,
                                cst ? "zone FULL, falling through" : "near-builtins zone", *ret);
                    cr_logs++;
                    if (!cst) { st = cst; ios_steered = 1; }
                    else { *ret = csaved; *size_ptr = cwant; }
                }
            }

            if (!ios_steered
                && !*ret && !limit && (type & MEM_RESERVE) && !(type & MEM_COMMIT)
                && *size_ptr >= 0x2000000 && *size_ptr < 0x40000000
                && (ios_bigres_reserved_total > (8ull << 30) || ios_va_pressure))
            {
                SIZE_T want = *size_ptr;
                void *saved = *ret;
                static unsigned steer_n;
                /* ml462 (#77): per-tid intake cap (ios_steer_intake); past it the ask
                 * falls through to the normal path and fails honestly. */
                unsigned stid = NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0;
                if (ios_steer_intake( stid ))
                {
                /* ml169: `limit` is 0 here ("unconstrained"), so passing it as limit_high
                 * described the EMPTY range [ios_spill_cap, 0) and every steer failed with
                 * *ret = 0x0. The upper bound has to be a real address: use the host VA
                 * ceiling, which is_beyond_limit treats as EXCLUSIVE. */
                /* madeira-bcd: [arena-guard] -- see ios_steer_top_slot_usable */
                int steer_top = ios_steer_top_slot_usable();
                NTSTATUS sst = !steer_top ? STATUS_NO_MEMORY :
                               allocate_virtual_memory( ret, size_ptr, type, protect,
                                                        ios_steer_slot,
                                                        (ULONG_PTR)host_addr_space_limit,
                                                        0, 0 );
                /* ml171: 16GB is not enough. Surviving longer spawns more threads, so
                 * the reserve count went 27 -> 55 (28160MB) and BOTH the steer slot and
                 * furniture reported va-scan FAILED maxgap=0 before the NULL deref.
                 * Fall back to the 0x7400000000 slot, which this run left UNGRANTED —
                 * pools landed on 0x7000000000, 0x73ffff0000 and 0x7800000000, matching
                 * the 3-pool census. That doubles steer capacity to ~32GB. */
                if (sst)
                {
                    *ret = saved; *size_ptr = want;
                    sst = allocate_virtual_memory( ret, size_ptr, type, protect,
                                                   0x7400000000ULL, ios_spill_cap, 0, 0 );
                }
                /* ml173: both steer slots full -> reclaim ranges owned by threads that
                 * have since exited, then retry once. This is what makes the steer
                 * region sustainable: the reserves leak per-thread, so without this any
                 * fixed capacity is exhausted by a long enough run. */
                if (sst && ios_steer_reclaim_dead())
                {
                    *ret = saved; *size_ptr = want;
                    sst = !steer_top ? STATUS_NO_MEMORY :
                          allocate_virtual_memory( ret, size_ptr, type, protect,
                                                   ios_steer_slot,
                                                   (ULONG_PTR)host_addr_space_limit, 0, 0 );
                    if (sst)
                    {
                        *ret = saved; *size_ptr = want;
                        sst = allocate_virtual_memory( ret, size_ptr, type, protect,
                                                       0x7400000000ULL, ios_spill_cap, 0, 0 );
                    }
                }
                if (!sst && ios_steer_n < IOS_STEER_MAX)
                {
                    ios_steer[ios_steer_n].base = (uint64_t)(uintptr_t)*ret;
                    ios_steer[ios_steer_n].size = want;
                    ios_steer[ios_steer_n].tid  =
                        NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0;
                    ios_thread_alive( ios_steer[ios_steer_n].tid );   /* tid recycling: see above */
                    ios_steer[ios_steer_n].freed = 0;
                    ios_steer_n++;
                }
                /* ml210: was 12, which was BELOW the ~25-50 reserves a Steam run makes, so
                 * the log count saturated and could not measure how many arenas actually
                 * got steered. */
                if (steer_n < 64)
                {
                    steer_n++;
                    dprintf(2, "[steer] #%u size=0x%lx reserved_total=%lluMB armed=%s -> %s %p\n",
                            steer_n, (unsigned long)want,
                            (unsigned long long)(ios_bigres_reserved_total >> 20),
                            ios_va_pressure ? "va-pressure" : "8GB-total",
                            sst ? "FAILED, falling back" : "above ceiling", *ret);
                }
                if (!sst) { st = sst; ios_steered = 1; }
                else { *ret = saved; *size_ptr = want; }   /* fall back to normal */
                }   /* ml462 per-tid cap else-block */
            }
            /* a reservation at the program's own address over its held releases (ios_fd_reuse) */
            if (!ios_steered && *ret) ios_fd_reuse( *ret, *size_ptr, type );
            if (!ios_steered)
                st = allocate_virtual_memory( ret, size_ptr, type, protect, 0, limit, 0, 0 );

            /* ml373 census: name what still lands in the guest band once the
             * valve has had its say. The [window] histogram gives sizes but no
             * owner, so a single wrong guess about WHO reserves the 8.4GB costs a
             * run. Reserve-only, >=8MB, guest band only, capped — and it prints
             * whether the request was hinted, since a hinted reserve is invisible
             * to the valve (`!*ret`) and would need a different fix. */
            if (!st && *ret && (type & MEM_RESERVE) && !(type & MEM_COMMIT)
                && *size_ptr >= 0x800000 && (ULONG_PTR)*ret < 0x7400000000ull)
            {
                static unsigned gb_n;
                static ULONG64 gb_total;
                gb_total += *size_ptr;
                if (gb_n++ < 48)
                    dprintf( 2, "[guest-reserve] #%u %p+0x%llx hinted=%d tid=%04x prot=0x%x "
                                "running_total=%lluMB\n",
                             gb_n, *ret, (unsigned long long)*size_ptr, hint_was_set,
                             NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0,
                             protect, (unsigned long long)(gb_total >> 20) );
            }
            /* task#29 CEF plan C: a HINTED jumbo reserve that fails placement
             * is retried as kernel-pick. Windows semantics say fail on
             * conflict, but PartitionAlloc-style callers use the returned
             * pointer (the hint is just ASLR seasoning) and its hints are
             * 47-bit randoms that can never fit under the iOS 512GB VA
             * ceiling. Serving from wherever we have room lets PA take its
             * aligned pool from the top hole instead of dying in the 32GB
             * fallback. Jumbo-only, loudly logged. */
            if (st && *ret && *size_ptr >= 0x40000000 && (type & MEM_RESERVE))
            {
                void *hint = *ret;
                void *pick = NULL;
                SIZE_T sz = *size_ptr;
                NTSTATUS st2 = STATUS_NO_MEMORY;
                /* Preserve the hint's offset within its natural alignment:
                 * PartitionAlloc hints (16GB boundary - 64KB) encode a
                 * guard-before-pool layout and it REJECTS a redirect that is
                 * merely 16GB-aligned (observed ml62: 0x7800000000 handed
                 * back three times, freed each time, then the fatal 32GB
                 * fallback). Walk the aligned slots in the usable top arena
                 * and try hint_offset-preserving fixed placements first. */
                ULONG_PTR align_unit = 0x400000000ULL;              /* 16GB */
                ULONG_PTR off = (ULONG_PTR)hint & (align_unit - 1);
                ULONG_PTR slot;
                /* ml106 packing rule: a guard-style reservation (off != 0,
                 * PartitionAlloc's boundary-minus-64KB layout) overhangs 64KB
                 * BELOW its slot, so placed high it poisons the slot beneath —
                 * that single overhang is why only 2 of 3 pools ever fit. Fill
                 * guard-style requests BOTTOM-UP from the ceiling (first cand
                 * 0x73ffff0000, whose overhang lands on furniture-free space by
                 * construction) and off=0 requests TOP-DOWN from 0x7C00000000.
                 * Perfect packing: [0x73ffff0000,0x78) guard, [0x78,0x7C) and
                 * [0x7C,0x8000000000) off=0 — all three pools fit. */
                /* ml122: start the guard walk at the first slot AT OR ABOVE the
                 * furniture ceiling. The old hardcoded 0x7400000000 base was
                 * written for the 0x73ffff0000 ceiling; with the ceiling now at
                 * 0x77ffff0000 that first candidate lands inside the furniture
                 * window and is guaranteed to fail, wasting an attempt. By
                 * construction ceiling == slot - 64KB, so the first viable
                 * guard candidate is exactly the ceiling itself. */
                ULONG_PTR guard_first = (ios_furniture_ceiling
                                         ? ((ios_furniture_ceiling + align_unit) & ~(align_unit - 1))
                                         : 0x7400000000ULL);
                /* madeira-bcd: SocialClubHelper.exe's glued 32 GB PartitionAlloc
                 * pools need a 32 GB boundary the slot walk below cannot give
                 * (it hands out 0x7400000000) -- see ios_sc_glued_pools. Every
                 * step below is skipped once st2 is 0. */
                /* Layout 2 (ios_sc2_route) decides the helper's asks it knows
                 * outright, and the helper never gets a soft grant: its big asks
                 * are PartitionAlloc, V8 and Oilpan reservations, which need
                 * memory that is really theirs (jumbo#3 of the 18:24 log died
                 * freeing the soft 0x7400000000). */
                int sc_helper = ios_sc_cef_enabled() && ios_sc_current_is_helper();
                int sc2 = sc_helper && ios_sc_layout_mode == 2;
                if (sc2 && ios_sc2_route( hint, *size_ptr, type, protect, &pick, &sz, &st2 ))
                    goto sc_decided;
                if (!sc2 && sc_helper && *size_ptr == 0x800000000ULL && !((ULONG_PTR)hint & (0x800000000ULL - 1)))
                    st2 = ios_sc_glued_pools( &pick, &sz, type, protect );
                if (st2 && off)
                {
                    for (slot = guard_first; slot <= 0x7C00000000ULL && st2; slot += align_unit)
                    {
                        void *cand = (void *)(slot + off - align_unit);
                        SIZE_T csz = *size_ptr;
                        pick = cand;
                        st2 = allocate_virtual_memory( &pick, &csz, type, protect, 0, 0, 0, 0 );
                        dprintf(2, "[jumbo] cand guard slot=0x%llx -> %p size=0x%lx st=0x%x\n",
                                (unsigned long long)slot, cand, (unsigned long)csz, (unsigned)st2);
                        if (!st2) sz = csz;
                    }
                }
                else if (st2) for (slot = 0x7C00000000ULL; slot >= 0x6800000000ULL && st2; slot -= align_unit)
                {
                    void *cand = (void *)slot;
                    SIZE_T csz = *size_ptr;
                    if ((ULONG_PTR)cand < 0x6000000000ULL) break;
                    pick = cand;
                    st2 = allocate_virtual_memory( &pick, &csz, type, protect, 0, 0, 0, 0 );
                    dprintf(2, "[jumbo] cand plain slot=0x%llx size=0x%lx st=0x%x\n",
                            (unsigned long long)slot, (unsigned long)csz, (unsigned)st2);
                    if (!st2) sz = csz;
                }
                /* ml996: the boot holdback, if this request fits it. */
                if (st2)
                {
                    uintptr_t hb = ios_jumbo_holdback_take( *size_ptr );
                    if (hb)
                    {
                        SIZE_T csz = *size_ptr;
                        pick = (void *)hb;
                        st2 = allocate_virtual_memory( &pick, &csz, type, protect, 0, 0, 0, 0 );
                        dprintf( 2, "[jumbo-hold] ml996 mapped at the holdback -> %p size=0x%lx "
                                 "st=0x%x\n", pick, (unsigned long)csz, (unsigned)st2 );
                        if (!st2) sz = csz;
                    }
                }
                /* ml433 (#72): an 8GB ask is the process-wide V8/cppgc cage and
                 * must come back 8GB-ALIGNED, or the guest frees it and dies in
                 * a 16GB overreserve retry loop — serve it from the boot
                 * holdback, the only aligned stretch left. See IOS_CAGE_BASE. */
                if (st2 && ios_cage_holdback_live && *size_ptr == 0x200000000ULL)
                    st2 = ios_cage_grant( type, protect, *size_ptr, &pick, &sz, "ml433" );
                /* ml434 (#72 layer 2): the 4GB ask is the cppgc caged heap and
                 * must come back 4GB-ALIGNED. By the time it arrives (~69s) the
                 * furniture window is 89% full (ml433: free=1701MB, maxhole
                 * 1557MB) — no real placement can EVER work, aligned or not. But
                 * the PA guard pool's real 16GB reservation [0x73ffff0000,
                 * 0x77ffff0000) has ~12MB committed at its very bottom and the
                 * two soft pools claiming that band have 0 commits ever, so
                 * SOFT-grant the cage deep inside the dead zone. Commits ride
                 * the guard view (see [cage-commit] in the soft handler); the
                 * collision to watch is BRP growing 8GB up from its bottom. */
                if (st2 && *size_ptr == 0x100000000ULL && !sc_helper)
                {
                    static const uint64_t cage4_slots[] = { 0x7600000000ULL, 0x7500000000ULL };
                    unsigned ci;
                    for (ci = 0; ci < 2 && st2; ci++)
                    {
                        if (ios_soft_slot_taken( cage4_slots[ci] )) continue;
                        if (ios_soft_n >= IOS_SOFT_MAX) break;
                        ios_soft[ios_soft_n].base = cage4_slots[ci];
                        ios_soft[ios_soft_n].size = 0x100000000ULL;
                        ios_soft[ios_soft_n].cage = 1;
                        ios_soft_n++;
                        pick = (void *)(uintptr_t)cage4_slots[ci];
                        sz = *size_ptr;
                        st2 = 0;
                        dprintf(2, "[cage] soft-grant %p size=0x%lx (4GB cage in PA guard dead zone) rev=ml434\n",
                                pick, (unsigned long)sz);
                    }
                }
                if (st2)
                {
                    pick = NULL;
                    sz = *size_ptr;
                    st2 = allocate_virtual_memory( &pick, &sz, type, protect, 0, 0, 0, 0 );
                }
            sc_decided:
                dprintf(2, "[jumbo] hinted reserve %p size=0x%lx failed (0x%x) — offset-preserving retry -> %p (0x%x)\n",
                        hint, (unsigned long)*size_ptr, (unsigned)st, pick, (unsigned)st2);
                if (st2)
                {
                    static int probed2;
                    if (probed2++ < 2)
                    {
                        ios_va_gap_probe( "hinted jumbo retry exhausted" );
                        ios_window_inventory( "hinted jumbo retry exhausted",
                                              ios_usable_va_floor, ios_furniture_ceiling );
                        ios_slot_probe( "hinted jumbo retry exhausted" );
                        ios_bigres_report( "hinted jumbo retry exhausted" );
                    }
                }
                if (!st2)
                {
                    *ret = pick;
                    *size_ptr = sz;
                    st = STATUS_SUCCESS;
                }
                else if (ios_soft_n < IOS_SOFT_MAX && *size_ptr >= 0x400000000ULL && !sc_helper)
                {
                    /* ml151: every real placement failed. Hand PA a 16GB-aligned
                     * slot nobody has taken and record it SOFT — see ios_soft.
                     * A guard-style request wants base = slot - 64KB; that guard
                     * page is a deliberate forbidden zone PA never commits, so it
                     * costs nothing that it may be unmappable. */
                    uint64_t slot;
                    for (slot = 0x7000000000ULL; slot < 0x8000000000ULL; slot += align_unit)
                    {
                        void *probe_addr = (void *)(uintptr_t)slot;
                        SIZE_T probe_sz = 0x10000;
                        NTSTATUS pst;

                        if (ios_soft_slot_taken( slot )) continue;
                        /* ml170: reserved for steered 512MB reserves (see
                         * ios_steer_slot) -- granting it as a pool is what caused
                         * the 43 collisions and cost us the 4th pool. */
                        if (slot == ios_steer_slot) continue;
                        /* ml213: never hand PA a slot that OVERLAPS THE FURNITURE WINDOW.
                         *
                         * The window starts at 0x7038000000, which is INSIDE
                         * [0x7000000000,0x7400000000), so every Wine/FEX allocation --
                         * including FEX's kernel-picked RWX JIT buffers -- packs the bottom
                         * of that slot. The [furniture] census measured 57347 foreign 16KB
                         * regions sitting there, and PA duly died on
                         *   [soft-pool] COLLISION: commit 0x7000200000+0x4000 inside soft
                         *   0x7000000000 -- VA mapped but NOT a wine view (prot=3/7)
                         * followed by a Chromium int3 (0x80000003) that aborted libcef
                         * init. A soft pool is only sound where nothing else allocates, and
                         * this is precisely where everything else allocates.
                         *
                         * Expressed as an overlap test rather than a hardcoded address so
                         * it stays correct if the window or the slot stride moves. */
                        if (slot < ios_furniture_ceiling
                            && slot + (uint64_t)*size_ptr > 0x7038000000ULL)
                            continue;
                        /* skip a slot that already holds a REAL pool: a 64KB
                         * probe reserve at its base would succeed only if free */
                        probe_addr = NULL; probe_sz = 0;
                        (void)probe_addr; (void)probe_sz; (void)pst;

                        ios_soft[ios_soft_n].base = slot;
                        ios_soft[ios_soft_n].size = *size_ptr;
                        ios_soft[ios_soft_n].committed = 0;
                        ios_soft[ios_soft_n].commits = 0;
                        ios_soft[ios_soft_n].collisions = 0;
                        ios_soft_n++;
                        *ret = (void *)(uintptr_t)(off ? slot + off - align_unit : slot);
                        st = STATUS_SUCCESS;
                        dprintf(2, "[soft-pool] GRANTED soft 0x%llx (base returned %p, size=0x%lx)"
                                   " — unbacked, commits materialise on demand\n",
                                (unsigned long long)slot, *ret, (unsigned long)*size_ptr);
                        break;
                    }
                }
            }
        }

        if (is_jumbo) ios_jumbo_census( jumbo_hint, jumbo_size, st ? NULL : *ret, (unsigned)st );
        /* madeira-bcd: remember a helper's large reservation for ios_sc_reap_dead */
        if (is_jumbo && !st && ios_sc_cef_enabled() && ios_sc_current_is_helper()) ios_sc_grant_note( *ret, *size_ptr );
        if (!st && *size_ptr >= 0x10000000 && *size_ptr < 0x40000000 && (type & MEM_RESERVE))
            ios_bigres_note( *ret, *size_ptr );
        if (!st) ios_span_census( *ret, *size_ptr, 0 );   /* ml435 (#73) */

        /* iOS-Madeira ml310 (task #54): SYSCALL-BOUNDARY census of arena-band allocations.
         *
         * ml310's [va-arena] probe inside allocate_virtual_memory's reserve branch logged 26 lines,
         * ALL of them size=0x20000000 type=0x2000 (jemalloc's MEM_RESERVE-only arenas) and NOT ONE
         * of the 0x3000 FEXMem_ThreadState allocations -- even though three of those landed on
         * duplicate addresses that run (0x7d00001000, 0x7d80001000, 0x7ea0001000). So the small
         * MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN allocations that actually collide are served by some
         * other path and that probe can never see them.
         *
         * Log here instead, at the syscall exit, where *ret is final no matter which internal route
         * produced it (normal allocate_virtual_memory, the steer retry ladder, the soft-pool commit
         * path, or the jumbo hint fallback). Placed in BOTH NtAllocateVirtualMemory and
         * NtAllocateVirtualMemoryEx because FEX's ARM64EC AllocatorHooks calls ::VirtualAlloc2, so
         * the Ex variant is the one FEX actually uses. Reports size/type/tid plus whether the
         * address falls inside a live ios_steer[] reservation. */
        /* ml311: gate on MEM_RESERVE. The ml310 cut logged every arena-band result and the 60-line
         * cap was consumed entirely by tid 006c's MEM_COMMIT-only (type=0x1000) 64KB commits
         * marching through its own jemalloc reservation -- all legitimate, and none of them the
         * FEXMem_ThreadState allocation being hunted, which carries
         * MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN (0x103000). Reserving allocations are the only ones
         * that can CHOOSE an address, so they are the only ones that can collide. */
        if (!st && *ret && (uint64_t)(uintptr_t)*ret >= 0x7C00000000ULL)
        {
            static int nc;
            uint64_t nb = (uint64_t)(uintptr_t)*ret;
            unsigned i, hit = (unsigned)-1;
            for (i = 0; i < ios_steer_n; i++)
            {
                if (!ios_steer[i].base) continue;
                if (nb < ios_steer[i].base || nb >= ios_steer[i].base + ios_steer[i].size) continue;
                hit = i; break;
            }
            /* ml312: mark the arena in use for EVERY allocation that lands in it, reserving or
             * committing alike -- a commit is just as much a claim on the memory as a reserve, and
             * the reclaim must not recycle either. Note this runs unconditionally, outside the
             * logging cap, so the flag can never depend on how much has been printed. */
            /* ml331: COUNT interior allocations instead of latching a flag. ml330 made the
             * flag permanent (an arena with any interior allocation was never released), which
             * fixed the corruption but leaked VA: ml330 reached 69 arenas / 35GB reserved in the
             * 64GB window CEF also needs, and FEXCore CreateThread's unchecked aligned_alloc
             * returned NULL and stored through it (#43 again). Refcount instead: bump here,
             * drop on interior MEM_RELEASE, and reclaim only at zero. */
            /* ml331b: bump ONLY on MEM_RESERVE. The ml312 flag deliberately counted commits
             * too, which was right for a latch but wrong for a refcount: a region that is
             * reserved then committed would bump twice and be released once, so the count
             * could never reach zero and the arena would leak exactly as in ml330. The
             * reservation is the claim on the range; MEM_RELEASE is its only counterpart. */
            /* ml332: REVERTED to latch semantics. The ml331 refcount gated bumps on
             * MEM_RESERVE, but jemalloc's interior activity is MEM_COMMIT inside the one
             * big reservation -- so every arena counted as empty, 8 arenas (4GB) were
             * released with live contents, and the GuestToHostMap corruption came straight
             * back (ml331 crash == ml329 crash, minutes after 'released 4096MB'). The
             * ml312 comment said it: a commit is as much a claim as a reserve. Deeper:
             * FEX's jemalloc heap is SHARED across threads, so 'owning thread died' was
             * never a valid release condition at all. VA pressure is solved by smaller
             * arenas (FEX side), not by releasing shared memory. */
            if (hit != (unsigned)-1 && nb != ios_steer[hit].base) ios_steer[hit].inuse = 1;

            if ((type & MEM_RESERVE) && nc++ < 80)
            {
                dprintf( 2, "[va-exit] rev=ml312 %p+0x%lx type=0x%x tid=%04x steer=%s%u freed=%u steer_n=%u\n",
                         *ret, (unsigned long)*size_ptr, (unsigned)type,
                         NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0,
                         hit == (unsigned)-1 ? "NONE#" : "INSIDE#",
                         hit == (unsigned)-1 ? ios_steer_n : hit,
                         hit == (unsigned)-1 ? 0 : ios_steer[hit].freed, ios_steer_n );
            }
        }
        /* ml813: name every FAILED guest allocation.
         *
         * A game died on "Ran out of memory allocating 32768 bytes with
         * alignment 0" at a 2GB footprint, and nothing in the log said which
         * request failed or why -- the reason had already been flattened to
         * ENOMEM several layers down. This prints the request as the caller made
         * it (jumbo_hint/jumbo_size are captured before *ret and *size_ptr are
         * overwritten), the status, and the last raw Mach result.
         *
         * Uncapped for the first 64 failures, then every 64th: a single failure
         * is the interesting one, and a storm should not hide it. */
        if (st != STATUS_SUCCESS)
        {
            static unsigned long af_n;
            unsigned long n = ++af_n;
            if (n <= 64 || (n % 64) == 0)
                dprintf( 2, "[alloc-fail] ml814 #%lu status=%08x hint=%p size=0x%llx type=0x%x "
                            "protect=0x%x tid=%04x | STAGE=%s err=%d at 0x%llx+0x%llx\n",
                         n, (unsigned)st, jumbo_hint, (unsigned long long)jumbo_size,
                         (unsigned)type, (unsigned)protect,
                         NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0,
                         ios_af.stage <= 6 ? ios_af_stage_name[ios_af.stage] : "?",
                         ios_af.err, ios_af.addr, ios_af.size );
        }
        if (!st && ret) ios_vm_note_alloc( *ret, size_ptr ? *size_ptr : 0, type, protect,
                                           ios_req_hint, (UINT64)zero_bits, (UINT64)limit );
        /* ml966: hand back a sub-2GB guest address for the one request shape
         * that crashes, so the guest's own narrowing of the pointer is a no-op.
         * Deliberately narrow: exact size, exact type, exact protection, no
         * hint, no zero_bits, current process only, and only in a
         * pseudo-process that has a sub-floor image loaded. Anything else keeps
         * the ordinary high address. If the reservation fails we also keep the
         * high address, so this can never turn a working allocation into a
         * failed one. */
        if (!st && ret && *ret && size_ptr &&
            ios_lowalloc_enabled() &&
            process == NtCurrentProcess() &&
            !ios_req_hint && !zero_bits &&
            *size_ptr == 0x1000 &&
            (type & (MEM_COMMIT | MEM_RESERVE)) == (MEM_COMMIT | MEM_RESERVE) &&
            !(type & ~(MEM_COMMIT | MEM_RESERVE)) &&
            protect == PAGE_READWRITE &&
            (UINT64)(ULONG_PTR)*ret >= 0x100000000ull &&
            ios_lowalloc_process_qualifies())
        {
            void *peb = ios_jit_current_peb();
            uint64_t real = (uint64_t)(ULONG_PTR)*ret;
            uint64_t low  = ios_lowalloc_reserve( real, (uint64_t)*size_ptr, peb );
            static int la_n;

            if (low)
            {
                if (la_n < 24)
                {
                    la_n++;
                    dprintf( 2, "ml966: LOW-ALLOC #%d guest %#llx+%#llx -> backing %#llx "
                             "(peb=%p tid=%04x) -- guest sees a sub-2GB address, narrowing is now a no-op\n",
                             la_n, (unsigned long long)low, (unsigned long long)*size_ptr,
                             (unsigned long long)real, peb,
                             NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0 );
                }
                *ret = (PVOID)(ULONG_PTR)low;
            }
            else if (la_n < 24)
            {
                la_n++;
                dprintf( 2, "ml966: low-alloc DECLINED (table full or range exhausted) for %#llx"
                         " -- keeping the high address\n", (unsigned long long)real );
            }
        }
        /* ml969 (option C): declare the low-32 form of this allocation as a
         * second name for the same backing, and DO NOT touch *ret -- the guest
         * keeps the high pointer, so every native/API consumer is unaffected.
         * Same qualifying shape as ml966; the two are mutually exclusive
         * because ml966 already returns a low address when it is on. */
        if (!st && ret && *ret && size_ptr &&
            ios_lowalias_enabled() && !ios_lowalloc_enabled() &&
            process == NtCurrentProcess() &&
            !ios_req_hint && !zero_bits &&
            *size_ptr == 0x1000 &&
            (type & (MEM_COMMIT | MEM_RESERVE)) == (MEM_COMMIT | MEM_RESERVE) &&
            !(type & ~(MEM_COMMIT | MEM_RESERVE)) &&
            protect == PAGE_READWRITE &&
            (UINT64)(ULONG_PTR)*ret >= 0x100000000ull &&
            ios_lowalloc_process_qualifies())
        {
            void *peb = ios_jit_current_peb();
            uint64_t real = (uint64_t)(ULONG_PTR)*ret;
            uint64_t alias = ios_lowalias_register( real, (uint64_t)*size_ptr, peb );
            static int lx_n;

            if (lx_n < 24)
            {
                lx_n++;
                if (alias)
                    dprintf( 2, "ml969: ALIAS #%d low %#llx+%#llx == backing %#llx (peb=%p tid=%04x) "
                             "-- guest still holds %#llx; the narrowed form now resolves\n",
                             lx_n, (unsigned long long)alias, (unsigned long long)*size_ptr,
                             (unsigned long long)real, peb,
                             NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0,
                             (unsigned long long)real );
                else
                    dprintf( 2, "ml969: alias REFUSED for backing %#llx (collision, table full, or "
                             "range unsuitable) -- allocation is unchanged and stays high-only\n",
                             (unsigned long long)real );
            }
        }
        return st;
    }
#else
    return allocate_virtual_memory( ret, size_ptr, type, protect, 0, limit, 0, 0 );
#endif
}


static NTSTATUS get_extended_params( const MEM_EXTENDED_PARAMETER *parameters, ULONG count,
                                     ULONG_PTR *limit_low, ULONG_PTR *limit_high, ULONG_PTR *align,
                                     ULONG *attributes, USHORT *machine )
{
    ULONG i, present = 0;

    if (count && !parameters) return STATUS_INVALID_PARAMETER;

    for (i = 0; i < count; ++i)
    {
        if (parameters[i].Type >= 32) return STATUS_INVALID_PARAMETER;
        if (present & (1u << parameters[i].Type)) return STATUS_INVALID_PARAMETER;
        present |= 1u << parameters[i].Type;

        switch (parameters[i].Type)
        {
        case MemExtendedParameterAddressRequirements:
        {
            MEM_ADDRESS_REQUIREMENTS *r = parameters[i].Pointer;
            ULONG_PTR limit;

#ifdef WINE_IOS
            /* In a process with a guest window the requirement is a GUEST
             * constraint only when its ceiling is below 4 GB (32-bit code
             * cannot name anything higher).  The CPU module's own allocators
             * in the same process pass explicit HIGH host bands and must be
             * validated against the host ceiling.
             *
             * A process WITHOUT a window of its own is a 64-bit process, and
             * must not fall back to is_wow64(): for a 64-bit thread that reads
             * the session-wide wow_peb, which every pseudo-process sees set
             * once any 32-bit program has booted.  The 64-bit process then had
             * its host band requests (the CPU module's per-thread lookup
             * cache at 0x7c00000000+) rejected with STATUS_INVALID_PARAMETER
             * against the 2/4 GB guest ceiling, before any placement ran. */
            if (ios_wow_base())
                limit = ((ULONG_PTR)r->HighestEndingAddress &&
                         (ULONG_PTR)r->HighestEndingAddress < IOS_WOW_WINDOW_SIZE)
                        ? get_wow_user_space_limit() : (ULONG_PTR)user_space_limit;
            else if (ios_wow_limit_by_window)
            {
                limit = (ULONG_PTR)user_space_limit;
                if (is_wow64())
                {
                    static int no_window_n;

                    if (no_window_n++ < 4)
                        dprintf( 2, "[wow-hostreq] range [%p,%p] from a process without a guest "
                                    "window while the session has a 32-bit process: validated "
                                    "against the host ceiling %p, not the guest ceiling %p "
                                    "(MADEIRA_WOW_LIMIT_BY_WINDOW=0 reverts)\n",
                                 r->LowestStartingAddress, r->HighestEndingAddress,
                                 (void *)limit, (void *)get_wow_user_space_limit() );
                }
            }
            else
#endif
            if (is_wow64()) limit = get_wow_user_space_limit();
            else limit = (ULONG_PTR)user_space_limit;

            if (r->Alignment)
            {
                if ((r->Alignment & (r->Alignment - 1)) || r->Alignment - 1 < granularity_mask)
                {
                    WARN( "Invalid alignment %lu.\n", r->Alignment );
                    return STATUS_INVALID_PARAMETER;
                }
                *align = r->Alignment;
            }
            if (r->LowestStartingAddress)
            {
                *limit_low = (ULONG_PTR)r->LowestStartingAddress;
                if (*limit_low >= limit || (*limit_low & granularity_mask))
                {
                    WARN( "Invalid limit %p.\n", r->LowestStartingAddress );
                    return STATUS_INVALID_PARAMETER;
                }
            }
            if (r->HighestEndingAddress)
            {
                *limit_high = (ULONG_PTR)r->HighestEndingAddress;
                if (*limit_high > limit ||
                    *limit_high <= *limit_low ||
                    ((*limit_high + 1) & (page_mask - 1)))
                {
                    WARN( "Invalid limit %p.\n", r->HighestEndingAddress );
                    return STATUS_INVALID_PARAMETER;
                }
            }
            break;
        }

        case MemExtendedParameterAttributeFlags:
            *attributes = parameters[i].ULong;
            break;

        case MemExtendedParameterImageMachine:
            *machine = parameters[i].ULong;
            break;

        case MemExtendedParameterNumaNode:
        case MemExtendedParameterPartitionHandle:
        case MemExtendedParameterUserPhysicalHandle:
            FIXME( "Parameter type %d is not supported.\n", parameters[i].Type );
            break;

        default:
            WARN( "Invalid parameter type %u\n", parameters[i].Type );
            return STATUS_INVALID_PARAMETER;
        }
    }
    return STATUS_SUCCESS;
}


