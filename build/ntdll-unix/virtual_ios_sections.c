/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Locking, sections and the rest of the virtual memory API. Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *             NtLockVirtualMemory   (NTDLL.@)
 *             ZwLockVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtLockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    unsigned int status = STATUS_SUCCESS;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_lock.type = APC_VIRTUAL_LOCK;
        call.virtual_lock.addr = wine_server_client_ptr( *addr );
        call.virtual_lock.size = *size;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_lock.status == STATUS_SUCCESS)
        {
            *addr = wine_server_get_ptr( result.virtual_lock.addr );
            *size = result.virtual_lock.size;
        }
        return result.virtual_lock.status;
    }

    *size = ROUND_SIZE( *addr, *size, page_mask );
    *addr = ROUND_ADDR( *addr, page_mask );

    if (mlock( ROUND_ADDR( *addr, host_page_mask ), ROUND_SIZE( *addr, *size, host_page_mask ) ))
    {
        dprintf(2, "[vmem-denied] mlock failed: addr=%p size=%p errno=%d\n",
                *addr, (void *)*size, errno);
        status = STATUS_ACCESS_DENIED;
    }
    return status;
}


/***********************************************************************
 *             NtUnlockVirtualMemory   (NTDLL.@)
 *             ZwUnlockVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnlockVirtualMemory( HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown )
{
    unsigned int status = STATUS_SUCCESS;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_unlock.type = APC_VIRTUAL_UNLOCK;
        call.virtual_unlock.addr = wine_server_client_ptr( *addr );
        call.virtual_unlock.size = *size;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_unlock.status == STATUS_SUCCESS)
        {
            *addr = wine_server_get_ptr( result.virtual_unlock.addr );
            *size = result.virtual_unlock.size;
        }
        return result.virtual_unlock.status;
    }

    *size = ROUND_SIZE( *addr, *size, page_mask );
    *addr = ROUND_ADDR( *addr, page_mask );

    if (munlock( ROUND_ADDR( *addr, host_page_mask ), ROUND_SIZE( *addr, *size, host_page_mask ) ))
        status = STATUS_ACCESS_DENIED;
    return status;
}


/***********************************************************************
 *             NtMapViewOfSection   (NTDLL.@)
 *             ZwMapViewOfSection   (NTDLL.@)
 */
NTSTATUS WINAPI NtMapViewOfSection( HANDLE handle, HANDLE process, PVOID *addr_ptr, ULONG_PTR zero_bits,
                                    SIZE_T commit_size, const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                    SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect )
{
    unsigned int res;
    SIZE_T mask = granularity_mask;
    LARGE_INTEGER offset;

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    TRACE("handle=%p process=%p addr=%p off=%s size=0x%lx alloc_type=0x%x access=0x%x\n",
          handle, process, *addr_ptr, wine_dbgstr_longlong(offset.QuadPart), *size_ptr, alloc_type, protect );

    /* Check parameters */
    if (zero_bits > 21 && zero_bits < 32)
        return STATUS_INVALID_PARAMETER_4;

    /* If both addr_ptr and zero_bits are passed, they have match */
    if (zero_bits && zero_bits < 32 && ((UINT_PTR)*addr_ptr >> (32 - zero_bits)))
        return STATUS_INVALID_PARAMETER_4;
    if (zero_bits >= 32 && ((UINT_PTR)*addr_ptr & ~zero_bits))
        return STATUS_INVALID_PARAMETER_4;

    if (!is_win64 && !is_wow64())
    {
        if (zero_bits >= 32) return STATUS_INVALID_PARAMETER_4;
        if (alloc_type & AT_ROUND_TO_PAGE)
        {
            *addr_ptr = ROUND_ADDR( *addr_ptr, page_mask );
            mask = page_mask;
        }
    }
    else if (alloc_type & AT_ROUND_TO_PAGE) return STATUS_INVALID_PARAMETER_9;

    if (alloc_type & MEM_REPLACE_PLACEHOLDER) mask = page_mask;
    if (offset.u.LowPart & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & host_page_mask)
    {
        ERR( "unaligned placeholder at %p\n", *addr_ptr );
        return STATUS_MAPPED_ALIGNMENT;
    }

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.map_view.type         = APC_MAP_VIEW;
        call.map_view.handle       = wine_server_obj_handle( handle );
        call.map_view.addr         = wine_server_client_ptr( *addr_ptr );
        call.map_view.size         = *size_ptr;
        call.map_view.offset       = offset.QuadPart;
        call.map_view.zero_bits    = zero_bits;
        call.map_view.alloc_type   = alloc_type;
        call.map_view.prot         = protect;
        res = server_queue_process_apc( process, &call, &result );
        if (res != STATUS_SUCCESS) return res;

        if (NT_SUCCESS(result.map_view.status))
        {
            *addr_ptr = wine_server_get_ptr( result.map_view.addr );
            *size_ptr = result.map_view.size;
        }
        return result.map_view.status;
    }

    return virtual_map_section( handle, addr_ptr, 0, get_zero_bits_limit( zero_bits ), commit_size,
                                offset_ptr, size_ptr, alloc_type, protect, 0 );
}

/***********************************************************************
 *             NtMapViewOfSectionEx   (NTDLL.@)
 *             ZwMapViewOfSectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtMapViewOfSectionEx( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                      const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr,
                                      ULONG alloc_type, ULONG protect,
                                      MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    ULONG_PTR limit_low = 0, limit_high = 0, align = 0;
    ULONG attributes = 0;
    USHORT machine = 0;
    unsigned int status;
    SIZE_T mask = granularity_mask;
    LARGE_INTEGER offset;

    offset.QuadPart = offset_ptr ? offset_ptr->QuadPart : 0;

    TRACE( "handle=%p process=%p addr=%p off=%s size=0x%lx alloc_type=0x%x access=0x%x\n",
           handle, process, *addr_ptr, wine_dbgstr_longlong(offset.QuadPart), *size_ptr, alloc_type, protect );

    status = get_extended_params( parameters, count, &limit_low, &limit_high,
                                  &align, &attributes, &machine );
    if (status) return status;

    if (align) return STATUS_INVALID_PARAMETER;
    if (*addr_ptr && (limit_low || limit_high)) return STATUS_INVALID_PARAMETER;

    if (alloc_type & AT_ROUND_TO_PAGE)
    {
        if (is_win64 || is_wow64()) return STATUS_INVALID_PARAMETER;
        *addr_ptr = ROUND_ADDR( *addr_ptr, page_mask );
        mask = page_mask;
    }

    if (alloc_type & MEM_REPLACE_PLACEHOLDER) mask = page_mask;
    if (offset.u.LowPart & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & mask) return STATUS_MAPPED_ALIGNMENT;
    if ((UINT_PTR)*addr_ptr & host_page_mask)
    {
        ERR( "unaligned placeholder at %p\n", *addr_ptr );
        return STATUS_MAPPED_ALIGNMENT;
    }

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.map_view_ex.type         = APC_MAP_VIEW_EX;
        call.map_view_ex.handle       = wine_server_obj_handle( handle );
        call.map_view_ex.addr         = wine_server_client_ptr( *addr_ptr );
        call.map_view_ex.size         = *size_ptr;
        call.map_view_ex.offset       = offset.QuadPart;
        call.map_view_ex.limit_low    = limit_low;
        call.map_view_ex.limit_high   = limit_high;
        call.map_view_ex.alloc_type   = alloc_type;
        call.map_view_ex.prot         = protect;
        call.map_view_ex.machine      = machine;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (NT_SUCCESS(result.map_view_ex.status))
        {
            *addr_ptr = wine_server_get_ptr( result.map_view_ex.addr );
            *size_ptr = result.map_view_ex.size;
        }
        return result.map_view_ex.status;
    }

    return virtual_map_section( handle, addr_ptr, limit_low, limit_high, 0,
                                offset_ptr, size_ptr, alloc_type, protect, machine );
}


/***********************************************************************
 *             unmap_view_of_section
 *
 * NtUnmapViewOfSection[Ex] implementation.
 */
static NTSTATUS unmap_view_of_section( HANDLE process, PVOID addr, ULONG flags )
{
    struct file_view *view;
    unsigned int status = STATUS_NOT_MAPPED_VIEW;
    sigset_t sigset;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.unmap_view.type = APC_UNMAP_VIEW;
        call.unmap_view.addr = wine_server_client_ptr( addr );
        call.unmap_view.flags = flags;
        status = server_queue_process_apc( process, &call, &result );
        if (status == STATUS_SUCCESS) status = result.unmap_view.status;
        return status;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(view = find_view( addr, 0 )) || is_view_valloc( view )) goto done;

    if (flags & MEM_PRESERVE_PLACEHOLDER && !(view->protect & VPROT_PLACEHOLDER))
    {
        status = STATUS_CONFLICTING_ADDRESSES;
        goto done;
    }
    if (view->protect & VPROT_SYSTEM)
    {
        struct builtin_module *builtin = get_builtin_module( view->base );

        if (builtin && builtin->refcount > 1)
        {
            TRACE( "not freeing in-use builtin %p\n", view->base );
            builtin->refcount--;
            server_leave_uninterrupted_section( &virtual_mutex, &sigset );
            return STATUS_SUCCESS;
        }
    }

    SERVER_START_REQ( unmap_view )
    {
        req->base = wine_server_client_ptr( view->base );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (!status)
    {
        if (view->protect & SEC_IMAGE) release_builtin_module( view->base );
#ifdef WINE_IOS
        /* ml1100: the low name must die with the mapping. */
        if (view->protect & SEC_IMAGE) ios_image_lowalias_retire( (unsigned long long)(uintptr_t)view->base );
#endif
        if (flags & MEM_PRESERVE_PLACEHOLDER) free_pages_preserve_placeholder( view, view->base, view->size );
        else delete_view( view );
    }
    else FIXME( "failed to unmap %p %x\n", view->base, status );
done:
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtUnmapViewOfSection   (NTDLL.@)
 *             ZwUnmapViewOfSection   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnmapViewOfSection( HANDLE process, PVOID addr )
{
    return unmap_view_of_section( process, addr, 0 );
}


/***********************************************************************
 *           ios_retire_own_fixed_base_image                      (ml988)
 *
 * Phase 1 of the fixed-base ownership handoff: retire THIS pseudo-process's
 * main image as it exits, so the next generation of a non-relocatable exe can
 * have the one address it is able to run at.
 *
 * Called from process_exit_wrapper BEFORE the master socket closes, because
 * NtUnmapViewOfSection's SERVER_START_REQ(unmap_view) needs a live connection
 * and this is the last moment we have one while still on the owning thread.
 *
 * It does NOT announce readiness. The address stays unclaimable until
 * ios_exe_win_mark_ready() runs after ios_jit_reclaim_process, because until
 * then this generation's pool mappings and FEX translations still exist and a
 * new claimant taking the same VA would be racing them.
 *
 * The hold is anon_mmap_tryfixed (no-clobber), never anon_mmap_fixed: the unmap
 * drops virtual_mutex before returning, so the interval is genuinely free for a
 * moment and another thread may legitimately take it. That is reported as a
 * named loss, never overwritten.
 *
 * MADEIRA_NO_IMAGE_RETIRE=1 disables the handoff entirely.
 */
void ios_retire_own_fixed_base_image( void *dying_peb )
{
    static int disabled = -1;
    void *base;
    size_t size;
    unsigned gen;
    unsigned int status;

    if (disabled < 0) disabled = getenv( "MADEIRA_NO_IMAGE_RETIRE" ) ? 1 : 0;
    if (disabled || !dying_peb) return;

    pthread_mutex_lock( &ios_exewin_lock );
    if (ios_exewin_st != IOS_EXEWIN_OWNED || !ios_exe_win_img_base ||
        dying_peb != ios_exe_win_img_peb)
    {
        pthread_mutex_unlock( &ios_exewin_lock );
        return;
    }
    base = ios_exe_win_img_base;
    size = ios_exe_win_img_size;
    gen  = ios_exe_win_generation;
    ios_exewin_st = IOS_EXEWIN_RETIRING;    /* claims refused from here on */
    pthread_mutex_unlock( &ios_exewin_lock );

    dprintf( 2, "ml988: gen %u owns the fixed-base main image %p+%#lx (peb=%p) and is exiting "
             "-- OWNED -> RETIRING, unmapping through NtUnmapViewOfSection\n",
             gen, base, (unsigned long)size, dying_peb );

    /* Not holding ios_exewin_lock here: this takes virtual_mutex, and the leaf
     * lock must never be held while acquiring it. */
    ios_retire_trace_armed = 1;                       /* ml989 */
    ios_retire_mark( "U0>\n" );                       /* about to call the unmap */
    status = NtUnmapViewOfSection( NtCurrentProcess(), base );
    ios_retire_mark( "U1<\n" );                       /* the unmap RETURNED */
    ios_retire_trace_armed = 0;
    dprintf( 2, "ml988: NtUnmapViewOfSection(%p) = %#x\n", base, status );
    dprintf( 2, "ml989: retire-trace fd=%d last write()=%d (markers are independent of fd 2)\n",
             ios_retire_trace_fd, ios_retire_trace_lastwr );

    if (status)
    {
        pthread_mutex_lock( &ios_exewin_lock );
        ios_exewin_st = IOS_EXEWIN_OWNED;   /* nothing changed; keep the old owner */
        pthread_mutex_unlock( &ios_exewin_lock );
        dprintf( 2, "ml988: unmap refused -- staying OWNED by gen %u; the next generation will "
                 "be placed elsewhere and this defect is NOT worked around\n", gen );
        return;
    }

    if (anon_mmap_tryfixed( base, size, PROT_NONE, MAP_NORESERVE ) == MAP_FAILED)
    {
        pthread_mutex_lock( &ios_exewin_lock );
        ios_exewin_st = IOS_EXEWIN_FREE;
        ios_exe_win_img_base = NULL;
        ios_exe_win_img_size = 0;
        ios_exe_win_img_peb  = NULL;
        ios_exe_win_img_dead = 0;
        pthread_mutex_unlock( &ios_exewin_lock );
        dprintf( 2, "ml988: LOST the interval %p+%#lx (errno=%d) -- another allocation took it "
                 "in the gap after the unmap. Leaving it alone; a MAP_FIXED hold here would "
                 "have destroyed it\n", base, (unsigned long)size, errno );
        return;
    }

    pthread_mutex_lock( &ios_exewin_lock );
    ios_exe_win_held_base = base;
    ios_exe_win_held_size = size;
    ios_exe_win_img_base  = NULL;
    ios_exe_win_img_size  = 0;
    ios_exe_win_img_peb   = NULL;
    ios_exe_win_img_dead  = 0;
    ios_exewin_st         = IOS_EXEWIN_HELD_NOT_READY;
    pthread_mutex_unlock( &ios_exewin_lock );

    dprintf( 2, "ml988: gen %u's image retired; %p+%#lx HELD PROT_NONE (no-overwrite) "
             "-- RETIRING -> HELD_NOT_READY, not claimable until the old generation's pool "
             "mappings are reclaimed\n", gen, base, (unsigned long)size );
}


/* ios_exe_win_owned_by: does this pseudo-process own the fixed-base main image (OWNED)?  The storm guard ends a child process from a
 * worker thread (server_ios.c, ios_end_child_process_async), which cannot do the retire above, so it leaves such a process to
 * the old whole-app ending. */
int ios_exe_win_owned_by( void *peb )
{
    int owned;

    if (!peb) return 0;
    pthread_mutex_lock( &ios_exewin_lock );
    owned = ios_exewin_st == IOS_EXEWIN_OWNED && peb == ios_exe_win_img_peb;
    pthread_mutex_unlock( &ios_exewin_lock );
    return owned;
}


/***********************************************************************
 *           ios_exe_win_mark_ready                               (ml988)
 *
 * Phase 2: the exiting generation's pool mappings and anon aliases have been
 * reclaimed, so the held interval may now be handed to a new claimant. Called
 * from process_exit_wrapper immediately after ios_jit_reclaim_process.
 *
 * This is NOT a proof that every native thread of that process has stopped --
 * thread_ios.c:1764 documents that a non-main-thread exit can leave siblings
 * running, and the pool's reuse grace is a delay, not a lifetime proof. It is
 * the strongest barrier currently available, and it is strictly stronger than
 * the server EOF that ml987 effectively relied on.
 */
void ios_exe_win_mark_ready( void *dead_peb )
{
    int promoted = 0;

    pthread_mutex_lock( &ios_exewin_lock );
    if (ios_exewin_st == IOS_EXEWIN_HELD_NOT_READY)
    {
        ios_exewin_st = IOS_EXEWIN_HELD_READY;
        promoted = 1;
    }
    pthread_mutex_unlock( &ios_exewin_lock );

    if (promoted)
        dprintf( 2, "ml988: pool mappings for peb=%p reclaimed -- %p+%#lx HELD_NOT_READY -> "
                 "HELD_READY; the next >=64MB fixed-base map may take it\n",
                 dead_peb, ios_exe_win_held_base, (unsigned long)ios_exe_win_held_size );
}

/***********************************************************************
 *             NtUnmapViewOfSectionEx   (NTDLL.@)
 *             ZwUnmapViewOfSectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI NtUnmapViewOfSectionEx( HANDLE process, PVOID addr, ULONG flags )
{
    static const ULONG type_mask = MEM_UNMAP_WITH_TRANSIENT_BOOST | MEM_PRESERVE_PLACEHOLDER;

    if (flags & ~type_mask)
    {
        WARN( "Unsupported flags %#x.\n", flags );
        return STATUS_INVALID_PARAMETER;
    }
    if (flags & MEM_UNMAP_WITH_TRANSIENT_BOOST) FIXME( "Ignoring MEM_UNMAP_WITH_TRANSIENT_BOOST.\n" );
    return unmap_view_of_section( process, addr, flags );
}

/******************************************************************************
 *             virtual_fill_image_information
 *
 * Helper for NtQuerySection.
 */
void virtual_fill_image_information( const struct pe_image_info *pe_info, SECTION_IMAGE_INFORMATION *info )
{
    info->TransferAddress             = wine_server_get_ptr( pe_info->base + pe_info->entry_point );
    info->ZeroBits                    = pe_info->zerobits;
    info->MaximumStackSize            = pe_info->stack_size;
    info->CommittedStackSize          = pe_info->stack_commit;
    info->SubSystemType               = pe_info->subsystem;
    info->MinorSubsystemVersion       = pe_info->subsystem_minor;
    info->MajorSubsystemVersion       = pe_info->subsystem_major;
    info->MajorOperatingSystemVersion = pe_info->osversion_major;
    info->MinorOperatingSystemVersion = pe_info->osversion_minor;
    info->ImageCharacteristics        = pe_info->image_charact;
    info->DllCharacteristics          = pe_info->dll_charact;
    info->Machine                     = pe_info->machine;
    info->ImageContainsCode           = pe_info->contains_code;
    info->ImageFlags                  = pe_info->image_flags;
    info->LoaderFlags                 = pe_info->loader_flags;
    info->ImageFileSize               = pe_info->file_size;
    info->CheckSum                    = pe_info->checksum;
#ifndef _WIN64 /* don't return 64-bit values to 32-bit processes */
    if (is_machine_64bit( pe_info->machine ))
    {
        info->TransferAddress = (void *)0x81231234;  /* sic */
        info->MaximumStackSize = 0x100000;
        info->CommittedStackSize = 0x10000;
    }
#endif
}

/* madeira-bcd [ucrt-shadow]: an x64 program's folder can carry Microsoft's
 * app-local UCRT (ucrtbase.dll). Wine turns api-ms-win-crt-* imports into the
 * bare name "ucrtbase.dll" and searches the program's folder first; upstream
 * Wine then swaps in the builtin in load_builtin(), but the iOS load_builtin()
 * keeps the file it found. The first importer is the emulator itself
 * (load_arm64ec_module), so that x64 DllMain runs while
 * __os_arm64x_check_icall is still the early stub that treats every target as
 * native: a native branch into x64 bytes, c000001d (RockstarService.exe of the
 * Rockstar Games Launcher). Windows 10+ never uses an app-local UCRT either.
 * Report such an image as built for another machine, so open_dll_file ->
 * is_valid_binary rejects it and the search goes on to system32 / the sysx64
 * mixed-arch fallback. MADEIRA_APP_UCRT=1 turns this off. */
static BOOL ios_ucrt_shadow_refused( HANDLE handle, const struct pe_image_info *pi )
{
    extern int ios_is_arm64ec_cur(void);
    static const char ucrt[] = "ucrtbase.dll";
    static int opt = -1, logged;
    struct pe_image_info *info = NULL;
    unsigned int sec_flags;
    mem_size_t full_size;
    HANDLE shared_file = 0;
    UNICODE_STRING nt_name;
    ANSI_STRING exp_name;
    const WCHAR *name;
    USHORT len, i;
    BOOL ret = FALSE;

    if (pi->machine != IMAGE_FILE_MACHINE_AMD64 || pi->is_hybrid || pi->wine_builtin) return FALSE;
    if (!ios_is_arm64ec_cur()) return FALSE;
    if (opt < 0) { const char *e = getenv( "MADEIRA_APP_UCRT" ); opt = (e && e[0] == '1'); }
    if (opt) return FALSE;
    memset( &nt_name, 0, sizeof(nt_name) );
    if (get_mapping_info( handle, SECTION_QUERY, &sec_flags, &full_size, &shared_file,
                          &info, &nt_name, &exp_name )) return FALSE;
    if (shared_file) NtClose( shared_file );
    if (!info) return FALSE;
    len = nt_name.Length / sizeof(WCHAR);
    name = nt_name.Buffer;
    for (i = 0; i < len; i++)
        if (nt_name.Buffer[i] == '\\' || nt_name.Buffer[i] == '/') name = nt_name.Buffer + i + 1;
    if (name) len -= name - nt_name.Buffer;
    if (name && len == sizeof(ucrt) - 1)
    {
        for (i = 0; i < len; i++)
        {
            WCHAR c = name[i];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (c != (WCHAR)ucrt[i]) break;
        }
        if (i == len)
        {
            ret = TRUE;
            if (logged++ < 8)
                dprintf( 2, "[ucrt-shadow] %s: plain x64 ucrtbase.dll outside the system farm in an "
                            "x64 (ARM64EC) process -- reported as not loadable so the loader keeps "
                            "searching and binds the system UCRT, as Windows 10+ does "
                            "(MADEIRA_APP_UCRT=1 reverts)\n", debugstr_us(&nt_name) );
        }
    }
    free( info );
    return ret;
}

/******************************************************************************
 *             NtQuerySection   (NTDLL.@)
 *             ZwQuerySection   (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySection( HANDLE handle, SECTION_INFORMATION_CLASS class, void *ptr,
                                SIZE_T size, SIZE_T *ret_size )
{
    unsigned int status;
    struct pe_image_info image_info;
    BOOL is_image = FALSE;

    switch (class)
    {
    case SectionBasicInformation:
        if (size < sizeof(SECTION_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
        break;
    case SectionImageInformation:
        if (size < sizeof(SECTION_IMAGE_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;
        break;
    default:
	FIXME( "class %u not implemented\n", class );
	return STATUS_NOT_IMPLEMENTED;
    }
    if (!ptr) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( get_mapping_info )
    {
        req->handle = wine_server_obj_handle( handle );
        req->access = SECTION_QUERY;
        wine_server_set_reply( req, &image_info, sizeof(image_info) );
        if (!(status = wine_server_call( req )))
        {
            if (class == SectionBasicInformation)
            {
                SECTION_BASIC_INFORMATION *info = ptr;
                info->Attributes    = reply->flags;
                info->BaseAddress   = NULL;
                info->Size.QuadPart = reply->size;
                if (ret_size) *ret_size = sizeof(*info);
            }
            else if (reply->flags & SEC_IMAGE)
            {
                SECTION_IMAGE_INFORMATION *info = ptr;
                virtual_fill_image_information( &image_info, info );
                if (ret_size) *ret_size = sizeof(*info);
                is_image = TRUE;
            }
            else status = STATUS_SECTION_NOT_IMAGE;
        }
    }
    SERVER_END_REQ;

    /* outside the request block: the helper makes its own server call */
    if (!status && is_image && ios_ucrt_shadow_refused( handle, &image_info ))
        ((SECTION_IMAGE_INFORMATION *)ptr)->Machine = IMAGE_FILE_MACHINE_UNKNOWN;

    return status;
}


/***********************************************************************
 *             NtFlushVirtualMemory   (NTDLL.@)
 *             ZwFlushVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushVirtualMemory( HANDLE process, LPCVOID *addr_ptr,
                                      SIZE_T *size_ptr, ULONG unknown )
{
    struct file_view *view;
    unsigned int status = STATUS_SUCCESS;
    sigset_t sigset;
    void *addr = ROUND_ADDR( *addr_ptr, page_mask );

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_flush.type = APC_VIRTUAL_FLUSH;
        call.virtual_flush.addr = wine_server_client_ptr( addr );
        call.virtual_flush.size = *size_ptr;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_flush.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_flush.addr );
            *size_ptr = result.virtual_flush.size;
        }
        return result.virtual_flush.status;
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!(view = find_view( addr, *size_ptr ))) status = STATUS_INVALID_PARAMETER;
    else
    {
        if (!*size_ptr) *size_ptr = view->size;
        *addr_ptr = addr;
#ifdef MS_ASYNC
        if (msync( ROUND_ADDR( addr, host_page_mask ), ROUND_SIZE( addr, *size_ptr, host_page_mask ), MS_ASYNC ))
            status = STATUS_NOT_MAPPED_DATA;
#endif
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtGetWriteWatch   (NTDLL.@)
 *             ZwGetWriteWatch   (NTDLL.@)
 */
NTSTATUS WINAPI NtGetWriteWatch( HANDLE process, ULONG flags, PVOID base, SIZE_T size, PVOID *addresses,
                                 ULONG_PTR *count, ULONG *granularity )
{
    NTSTATUS status = STATUS_SUCCESS;
    sigset_t sigset;

    size = ROUND_SIZE( base, size, page_mask );
    base = ROUND_ADDR( base, page_mask );

    if (!count || !granularity) return STATUS_ACCESS_VIOLATION;
    if (!*count || !size) return STATUS_INVALID_PARAMETER;
    if (flags & ~WRITE_WATCH_FLAG_RESET) return STATUS_INVALID_PARAMETER;

    if (!addresses) return STATUS_ACCESS_VIOLATION;

    TRACE( "%p %x %p-%p %p %lu\n", process, flags, base, (char *)base + size,
           addresses, *count );

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if (is_write_watch_range( base, size ))
    {
        ULONG_PTR pos = 0;
        char *addr = base;
        char *end = addr + size;

        if (use_kernel_writewatch)
            kernel_get_write_watches( base, size, addresses, count, flags & WRITE_WATCH_FLAG_RESET );
        else
        {
            while (pos < *count && addr < end)
            {
                if (!(get_page_vprot( addr ) & VPROT_WRITEWATCH)) addresses[pos++] = addr;
                addr += page_size;
            }
            size = addr - (char *)base;
            *count = pos;
        }
        if (flags & WRITE_WATCH_FLAG_RESET && (enable_write_exceptions || !use_kernel_writewatch))
        {
            if (use_kernel_writewatch)
                set_page_vprot_exec_write_protect( base, size );
            else
                set_page_vprot_bits( base, size, VPROT_WRITEWATCH, 0 );
            mprotect_range( base, size, 0, 0 );
        }
        *granularity = page_size;
    }
    else status = STATUS_INVALID_PARAMETER;

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtResetWriteWatch   (NTDLL.@)
 *             ZwResetWriteWatch   (NTDLL.@)
 */
NTSTATUS WINAPI NtResetWriteWatch( HANDLE process, PVOID base, SIZE_T size )
{
    NTSTATUS status = STATUS_SUCCESS;
    sigset_t sigset;

    size = ROUND_SIZE( base, size, page_mask );
    base = ROUND_ADDR( base, page_mask );

    TRACE( "%p %p-%p\n", process, base, (char *)base + size );

    if (!size) return STATUS_INVALID_PARAMETER;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if (is_write_watch_range( base, size ))
        reset_write_watches( base, size );
    else
        status = STATUS_INVALID_PARAMETER;

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *             NtReadVirtualMemory   (NTDLL.@)
 *             ZwReadVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtReadVirtualMemory( HANDLE process, const void *addr, void *buffer,
                                     SIZE_T size, SIZE_T *bytes_read )
{
    unsigned int status;

    if (!virtual_check_buffer_for_write( buffer, size ))
    {
        status = STATUS_ACCESS_VIOLATION;
        size = 0;
    }
    else if (process == GetCurrentProcess())
    {
        __TRY
        {
            memmove( buffer, addr, size );
            status = STATUS_SUCCESS;
        }
        __EXCEPT
        {
            status = STATUS_PARTIAL_COPY;
            size = 0;
        }
        __ENDTRY
    }
    else
    {
        SERVER_START_REQ( read_process_memory )
        {
            req->handle = wine_server_obj_handle( process );
            req->addr   = wine_server_client_ptr( addr );
            wine_server_set_reply( req, buffer, size );
            if ((status = wine_server_call( req ))) size = 0;
        }
        SERVER_END_REQ;
    }
    if (bytes_read) *bytes_read = size;
    return status;
}


/***********************************************************************
 *             NtWriteVirtualMemory   (NTDLL.@)
 *             ZwWriteVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtWriteVirtualMemory( HANDLE process, void *addr, const void *buffer,
                                      SIZE_T size, SIZE_T *bytes_written )
{
    unsigned int status;

    if (virtual_check_buffer_for_read( buffer, size ))
    {
        SERVER_START_REQ( write_process_memory )
        {
            req->handle     = wine_server_obj_handle( process );
            req->addr       = wine_server_client_ptr( addr );
            wine_server_add_data( req, buffer, size );
            status = wine_server_call( req );
            size = reply->written;
        }
        SERVER_END_REQ;
    }
    else
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    if (bytes_written) *bytes_written = size;
    return status;
}


/***********************************************************************
 *             NtAreMappedFilesTheSame   (NTDLL.@)
 *             ZwAreMappedFilesTheSame   (NTDLL.@)
 */
NTSTATUS WINAPI NtAreMappedFilesTheSame(PVOID addr1, PVOID addr2)
{
    struct file_view *view1, *view2;
    unsigned int status;
    sigset_t sigset;

    TRACE("%p %p\n", addr1, addr2);

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    view1 = find_view( addr1, 0 );
    view2 = find_view( addr2, 0 );

    if (!view1 || !view2)
        status = STATUS_INVALID_ADDRESS;
    else if (is_view_valloc( view1 ) || is_view_valloc( view2 ))
        status = STATUS_CONFLICTING_ADDRESSES;
    else if (view1 == view2)
        status = STATUS_SUCCESS;
    else if ((view1->protect & VPROT_SYSTEM) || (view2->protect & VPROT_SYSTEM))
        status = STATUS_NOT_SAME_DEVICE;
    else
    {
        SERVER_START_REQ( is_same_mapping )
        {
            req->base1 = wine_server_client_ptr( view1->base );
            req->base2 = wine_server_client_ptr( view2->base );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
    }

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


static NTSTATUS prefetch_memory( HANDLE process, ULONG_PTR count,
                                 PMEMORY_RANGE_ENTRY addresses, ULONG flags )
{
    ULONG_PTR i;
    PVOID base;
    SIZE_T size;
    static unsigned int once;

    if (!once++)
    {
        FIXME( "(process=%p,flags=%u) NtSetInformationVirtualMemory(VmPrefetchInformation) partial stub\n",
                process, flags );
    }

    for (i = 0; i < count; i++)
    {
        if (!addresses[i].NumberOfBytes) return STATUS_INVALID_PARAMETER_4;
    }

    if (process != NtCurrentProcess()) return STATUS_SUCCESS;

    for (i = 0; i < count; i++)
    {
        base = ROUND_ADDR( addresses[i].VirtualAddress, host_page_mask );
        size = ROUND_SIZE( addresses[i].VirtualAddress, addresses[i].NumberOfBytes, host_page_mask );
        madvise( base, size, MADV_WILLNEED );
    }

    return STATUS_SUCCESS;
}

static NTSTATUS set_dirty_state_information( ULONG_PTR count, MEMORY_RANGE_ENTRY *addresses )
{
    ULONG_PTR i;
    sigset_t sigset;
    NTSTATUS ret = STATUS_SUCCESS;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    for (i = 0; i < count; i++)
    {
        void *base = ROUND_ADDR( addresses[i].VirtualAddress, page_mask );
        SIZE_T size = ROUND_SIZE( addresses[i].VirtualAddress, addresses[i].NumberOfBytes, page_mask );
        struct file_view *view = find_view( base, size );

        if (!view)
        {
            ret = STATUS_MEMORY_NOT_ALLOCATED;
            break;
        }
        if (use_kernel_writewatch) reset_write_watches( base, size );
        else if (set_page_vprot_exec_write_protect( base, size ))
            mprotect_range( base, size, 0, 0 );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}

/***********************************************************************
 *           NtSetInformationVirtualMemory   (NTDLL.@)
 *           ZwSetInformationVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationVirtualMemory( HANDLE process,
                                               VIRTUAL_MEMORY_INFORMATION_CLASS info_class,
                                               ULONG_PTR count, PMEMORY_RANGE_ENTRY addresses,
                                               PVOID ptr, ULONG size )
{
    TRACE("(%p, info_class=%d, %lu, %p, %p, %u)\n",
          process, info_class, count, addresses, ptr, size);

    switch (info_class)
    {
    case VmPrefetchInformation:
        if (!ptr) return STATUS_INVALID_PARAMETER_5;
        if (size != sizeof(ULONG)) return STATUS_INVALID_PARAMETER_6;
        if (!count) return STATUS_INVALID_PARAMETER_3;
        return prefetch_memory( process, count, addresses, *(ULONG *)ptr );

    case VmPageDirtyStateInformation:
        if (process != GetCurrentProcess()) return STATUS_NOT_SUPPORTED;
        if (!enable_write_exceptions) return STATUS_NOT_SUPPORTED;
        if (!ptr) return STATUS_INVALID_PARAMETER_5;
        if (size != sizeof(ULONG)) return STATUS_INVALID_PARAMETER_6;
        if (*(ULONG *)ptr) return STATUS_INVALID_PARAMETER_5;
        if (!count) return STATUS_INVALID_PARAMETER_3;
        return set_dirty_state_information( count, addresses );

    default:
        FIXME("(%p,info_class=%d,%lu,%p,%p,%u) Unknown information class\n",
              process, info_class, count, addresses, ptr, size);
        return STATUS_INVALID_PARAMETER_2;
    }
}


/**********************************************************************
 *           NtFlushInstructionCache  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushInstructionCache( HANDLE handle, const void *addr, SIZE_T size )
{
#ifdef WINE_IOS
    /* ml1202: nothing is mapped below 4GB on iOS, and __clear_cache's `ic ivau`
     * on such an address faults (the sub-floor service cannot emulate cache
     * maintenance). A Delphi program at 0x400000 patched 5 bytes of its own
     * code and flushed them by their low address: SEGV in
     * sys_icache_invalidate, Delphi exception 0x0eedfade. Flush the real mapping
     * of a sub-floor image or low allocation; skip any other low address. FEX's
     * translations are dropped by the PE-side wrapper, which still gets the
     * guest's own address. */
    if (handle == GetCurrentProcess() && addr && (ULONG_PTR)addr < 0x100000000ull)
    {
        unsigned long long real = 0;
        static int fl_n;

        if (ios_subfloor_image_translate( (ULONG_PTR)addr, size, &real ) ||
            ios_lowalloc_translate( (ULONG_PTR)addr, size, &real, NULL ))
        {
            if (fl_n++ < 16)
                dprintf( 2, "ml1202: FLUSH-ICACHE on low guest %p size=%#lx -> real %#llx\n",
                         addr, (unsigned long)size, real );
            addr = (const void *)(ULONG_PTR)real;
        }
        else
        {
            if (fl_n++ < 16)
                dprintf( 2, "ml1202: FLUSH-ICACHE on unmapped low %p size=%#lx skipped\n",
                         addr, (unsigned long)size );
            return STATUS_SUCCESS;
        }
    }
#endif
#if defined(__x86_64__) || defined(__i386__)
    /* no-op */
#elif defined(WINE_IOS)   /* the guard <libkern/OSCacheControl.h> is included under */
    /* iOS-Madeira ml795: THIS WAS THE x64 CRASH.
     *
     * Our config.h does not define HAVE___CLEAR_CACHE, so this function used
     * to compile to the #else branch below: log one FIXME and flush nothing.
     * Every device log carries that FIXME, with the current-process handle,
     * which only the #else branch prints:
     *
     *   fixme:virtual:NtFlushInstructionCache 0xffffffffffffffff 0x155ffc004 644
     *
     * That caller is FEX. xtajit64.dll is a PE; it emits each JIT block
     * through the pool's RW alias and then calls FlushInstructionCache on the
     * RX address -- 0x155ffc004 is the first block past RXCursor, 644 bytes.
     * This is the only way the host ever learns that PE-side code wrote
     * instructions. Everything else in this file that writes code calls
     * sys_icache_invalidate itself; this was the one path that did not.
     *
     * With no invalidation the CPU executes whatever its icache already holds
     * for those addresses, and FEX prefills its code buffer with NOPs. So a
     * block runs its fresh lines, slides through a stale line of NOPs, and
     * resumes at the next line boundary -- in the middle of the block's own
     * metadata. Measured, not inferred:
     *
     *   * every faulting pc across five runs is 64-byte aligned (pc % 64 == 0:
     *     tail+24, tail+8, tail+24, tail+24, and DispatchPtr) -- the "three
     *     different offsets into JITCodeTail" were just wherever the next line
     *     boundary fell;
     *   * in the 2026-09-22 run every register written by line 0 of the block
     *     holds its new value (x10, x8, x6) and every one written by line 1
     *     does not (x9=1, x11=0, SP still the emulator stack), with no fault,
     *     no branch and no LR change in between;
     *   * Build 79's host binary, which runs these games, has the other branch:
     *     it carries "%p %p %ld other process not supported", defines
     *     ___clear_cache and imports sys_icache_invalidate.
     *
     * sys_icache_invalidate cleans the data cache to the point of unification
     * and invalidates the instruction cache over the range, which is what a
     * dual-mapped JIT needs after writing through the other alias. The RX
     * alias is readable, so it is a valid address for both. */
    if (handle == GetCurrentProcess())
    {
        static int seen;
        if (addr && size) sys_icache_invalidate( (void *)addr, size );
        /* Say so, a few times. The old build logged a FIXME here and flushed
         * nothing; the absence of that FIXME is weaker evidence than this. */
        if (seen < 3 && ++seen)
            dprintf( 2, "[icache] ml795 invalidated %p+%lu (call %d) -- the pre-fix build "
                     "flushed nothing here\n", addr, (unsigned long)size, seen );
    }
    else
    {
        static int once;
        if (!once++) FIXME( "%p %p %ld other process not supported\n", handle, addr, size );
    }
#elif defined(HAVE___CLEAR_CACHE)
    if (handle == GetCurrentProcess())
    {
        __clear_cache( (char *)addr, (char *)addr + size );
    }
    else
    {
        static int once;
        if (!once++) FIXME( "%p %p %ld other process not supported\n", handle, addr, size );
    }
#else
    static int once;
    if (!once++) FIXME( "%p %p %ld\n", handle, addr, size );
#endif
    return STATUS_SUCCESS;
}


#ifdef __APPLE__

static kern_return_t (*p_thread_get_register_pointer_values)( thread_t, uintptr_t*, size_t*, uintptr_t* );
static pthread_once_t tgrpvs_init_once = PTHREAD_ONCE_INIT;

static void tgrpvs_init(void)
{
    p_thread_get_register_pointer_values = dlsym( RTLD_DEFAULT, "thread_get_register_pointer_values" );
    if (!p_thread_get_register_pointer_values)
        FIXME( "thread_get_register_pointer_values not supported for NtFlushProcessWriteBuffers\n" );
}

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    /* Taken from https://github.com/dotnet/runtime/blob/7be37908e5a1cbb83b1062768c1649827eeaceaa/src/coreclr/pal/src/thread/process.cpp#L2799 */
    mach_msg_type_number_t count, i;
    thread_act_array_t threads;

    pthread_once( &tgrpvs_init_once, tgrpvs_init );
    if (!p_thread_get_register_pointer_values) return STATUS_SUCCESS;

    /* Get references to all threads of this process */
    if (task_threads( mach_task_self(), &threads, &count )) return STATUS_SUCCESS;

    for (i = 0; i < count; i++)
    {
        uintptr_t reg_values[128];
        size_t reg_count = ARRAY_SIZE( reg_values );
        uintptr_t sp;

        /* Request the thread's register pointer values to force the thread to go through a memory barrier */
        p_thread_get_register_pointer_values( threads[i], &sp, &reg_count, reg_values );
        mach_port_deallocate( mach_task_self(), threads[i] );
    }
    vm_deallocate( mach_task_self(), (vm_address_t)threads, count * sizeof(threads[0]) );
    return STATUS_SUCCESS;
}

#elif defined(__linux__) && defined(__NR_membarrier)

#define MEMBARRIER_CMD_PRIVATE_EXPEDITED            0x08
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED   0x10

static pthread_once_t membarrier_init_once = PTHREAD_ONCE_INIT;

static int membarrier( int cmd, unsigned int flags, int cpu_id )
{
    return syscall( __NR_membarrier, cmd, flags, cpu_id );
}

static void membarrier_init(void)
{
    if (membarrier( MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0 ))
        FIXME( "membarrier not supported for NtFlushProcessWriteBuffers\n" );
}

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    pthread_once( &membarrier_init_once, membarrier_init );
    membarrier( MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0 );
    return STATUS_SUCCESS;
}

#else /* __linux__ */

/**********************************************************************
 *           NtFlushProcessWriteBuffers  (NTDLL.@)
 */
NTSTATUS WINAPI NtFlushProcessWriteBuffers(void)
{
    static int once = 0;
    if (!once++) FIXME( "stub\n" );
    return STATUS_SUCCESS;
}

#endif

/**********************************************************************
 *           NtCreatePagingFile  (NTDLL.@)
 */
NTSTATUS WINAPI NtCreatePagingFile( UNICODE_STRING *name, LARGE_INTEGER *min_size,
                                    LARGE_INTEGER *max_size, LARGE_INTEGER *actual_size )
{
    FIXME( "(%s %p %p %p) stub\n", debugstr_us(name), min_size, max_size, actual_size );
    return STATUS_SUCCESS;
}

#ifndef _WIN64

/***********************************************************************
 *             NtWow64AllocateVirtualMemory64   (NTDLL.@)
 *             ZwWow64AllocateVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64AllocateVirtualMemory64( HANDLE process, ULONG64 *ret, ULONG64 zero_bits,
                                                ULONG64 *size_ptr, ULONG type, ULONG protect )
{
    void *base;
    SIZE_T size;
    unsigned int status;

    TRACE("%p %s %s %x %08x\n", process,
          wine_dbgstr_longlong(*ret), wine_dbgstr_longlong(*size_ptr), type, protect );

    if (!*size_ptr) return STATUS_INVALID_PARAMETER_4;
    if (zero_bits > 21 && zero_bits < 32) return STATUS_INVALID_PARAMETER_3;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc.type         = APC_VIRTUAL_ALLOC;
        call.virtual_alloc.addr         = *ret;
        call.virtual_alloc.size         = *size_ptr;
        call.virtual_alloc.zero_bits    = zero_bits;
        call.virtual_alloc.op_type      = type;
        call.virtual_alloc.prot         = protect;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc.status == STATUS_SUCCESS)
        {
            *ret      = result.virtual_alloc.addr;
            *size_ptr = result.virtual_alloc.size;
        }
        return result.virtual_alloc.status;
    }

    base = (void *)(ULONG_PTR)*ret;
    size = *size_ptr;
    if ((ULONG_PTR)base != *ret) return STATUS_CONFLICTING_ADDRESSES;
    if (size != *size_ptr) return STATUS_WORKING_SET_LIMIT_RANGE;

    status = NtAllocateVirtualMemory( process, &base, zero_bits, &size, type, protect );
    if (!status)
    {
        *ret = (ULONG_PTR)base;
        *size_ptr = size;
    }
    return status;
}


/***********************************************************************
 *             NtWow64ReadVirtualMemory64   (NTDLL.@)
 *             ZwWow64ReadVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64ReadVirtualMemory64( HANDLE process, ULONG64 addr, void *buffer,
                                            ULONG64 size, ULONG64 *bytes_read )
{
    unsigned int status;

    if (size > MAXLONG) size = MAXLONG;

    if (virtual_check_buffer_for_write( buffer, size ))
    {
        SERVER_START_REQ( read_process_memory )
        {
            req->handle = wine_server_obj_handle( process );
            req->addr   = addr;
            wine_server_set_reply( req, buffer, size );
            if ((status = wine_server_call( req ))) size = 0;
        }
        SERVER_END_REQ;
    }
    else
    {
        status = STATUS_ACCESS_VIOLATION;
        size = 0;
    }
    if (bytes_read) *bytes_read = size;
    return status;
}


/***********************************************************************
 *             NtWow64WriteVirtualMemory64   (NTDLL.@)
 *             ZwWow64WriteVirtualMemory64   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64WriteVirtualMemory64( HANDLE process, ULONG64 addr, const void *buffer,
                                             ULONG64 size, ULONG64 *bytes_written )
{
    unsigned int status;

    if (size > MAXLONG) size = MAXLONG;

    if (virtual_check_buffer_for_read( buffer, size ))
    {
        SERVER_START_REQ( write_process_memory )
        {
            req->handle     = wine_server_obj_handle( process );
            req->addr       = addr;
            wine_server_add_data( req, buffer, size );
            if ((status = wine_server_call( req ))) size = 0;
        }
        SERVER_END_REQ;
    }
    else
    {
        status = STATUS_PARTIAL_COPY;
        size = 0;
    }
    if (bytes_written) *bytes_written = size;
    return status;
}


/***********************************************************************
 *             NtWow64GetNativeSystemInformation   (NTDLL.@)
 *             ZwWow64GetNativeSystemInformation   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64GetNativeSystemInformation( SYSTEM_INFORMATION_CLASS class, void *info,
                                                   ULONG len, ULONG *retlen )
{
    NTSTATUS status;

    switch (class)
    {
    case SystemCpuInformation:
        status = NtQuerySystemInformation( class, info, len, retlen );
        if (!status && is_old_wow64())
        {
            SYSTEM_CPU_INFORMATION *cpu = info;

            if (cpu->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
                cpu->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
        }
        return status;
    case SystemBasicInformation:
    case SystemEmulationBasicInformation:
    case SystemEmulationProcessorInformation:
        return NtQuerySystemInformation( class, info, len, retlen );
    case SystemNativeBasicInformation:
        return NtQuerySystemInformation( SystemBasicInformation, info, len, retlen );
    default:
        if (is_old_wow64()) return STATUS_INVALID_INFO_CLASS;
        return NtQuerySystemInformation( class, info, len, retlen );
    }
}

/***********************************************************************
 *             NtWow64IsProcessorFeaturePresent   (NTDLL.@)
 *             ZwWow64IsProcessorFeaturePresent   (NTDLL.@)
 */
NTSTATUS WINAPI NtWow64IsProcessorFeaturePresent( UINT feature )
{
    return feature < PROCESSOR_FEATURE_MAX && user_shared_data->ProcessorFeatures[feature];
}

#endif  /* _WIN64 */
