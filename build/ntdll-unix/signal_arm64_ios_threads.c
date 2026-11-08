/* Part of signal_arm64_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Threading, thread start and the syscall dispatcher. Same copyright and licence as signal_arm64_ios.c. */
/**********************************************************************
 *             signal_init_threading
 */
void signal_init_threading(void)
{
}


/**********************************************************************
 *             signal_alloc_thread
 */
NTSTATUS signal_alloc_thread( TEB *teb )
{
    return STATUS_SUCCESS;
}


/**********************************************************************
 *             signal_free_thread
 */
void signal_free_thread( TEB *teb )
{
}


/**********************************************************************
 *		signal_init_process
 */
void signal_init_process(void)
{
    struct sigaction sig_act;
    struct ntdll_thread_data *thread_data = ntdll_get_thread_data();
    void *kernel_stack = (char *)thread_data->kernel_stack + kernel_stack_size;

    thread_data->syscall_frame = (struct syscall_frame *)kernel_stack - 1;

    signal_alloc_thread( NtCurrentTeb() );

#ifdef WINE_IOS
    /* Create TLS key for TEB storage (used by x18 binary patcher trampolines) */
    if (!ios_teb_tls_key_created)
    {
        pthread_key_create(&ios_teb_tls_key, NULL);
        ios_teb_tls_key_created = 1;
    }
#endif

    sig_act.sa_mask = server_block_set;
    sig_act.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;

    sig_act.sa_sigaction = int_handler;
    if (sigaction( SIGINT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = fpe_handler;
    if (sigaction( SIGFPE, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = abrt_handler;
    if (sigaction( SIGABRT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = quit_handler;
    if (sigaction( SIGQUIT, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = usr1_handler;
    if (sigaction( SIGUSR1, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = usr2_handler;
    if (sigaction( SIGUSR2, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = trap_handler;
    if (sigaction( SIGTRAP, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = segv_handler;
    if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = ill_handler;
    if (sigaction( SIGILL, &sig_act, NULL ) == -1) goto error;
    sig_act.sa_sigaction = bus_handler;
    if (sigaction( SIGBUS, &sig_act, NULL ) == -1) goto error;
    return;

 error:
    perror("sigaction");
    exit(1);
}


/***********************************************************************
 *           syscall_dispatcher_return_slowpath
 */
void syscall_dispatcher_return_slowpath(void)
{
    raise( SIGUSR2 );
}

/***********************************************************************
 *           init_syscall_frame
 */
/* host -> guest for a known window base, NULL-preserving */
static inline ULONG ios_wow_guest_in( const void *host, ULONG_PTR wow_base )
{
    return host ? (ULONG)((ULONG_PTR)host - wow_base) : 0;
}

void init_syscall_frame( LPTHREAD_START_ROUTINE entry, void *arg, BOOL suspend, TEB *teb )
{
    struct syscall_frame *frame = ((struct ntdll_thread_data *)&teb->GdiTebBatch)->syscall_frame;
    CONTEXT *ctx, context = { CONTEXT_ALL };
    I386_CONTEXT *i386_context;
    ARM_CONTEXT *arm_context;

    context.X0  = (DWORD64)entry;
    context.X1  = (DWORD64)arg;
    context.X18 = (DWORD64)teb;
    context.Sp  = (DWORD64)teb->Tib.StackBase;
    context.Pc  = (DWORD64)IOS_PFUNC(RtlUserThreadStart);

    /* Every register of the initial 32-bit context is a GUEST value.  `entry`
     * and `arg` arrive as host pointers, wow_peb is the host PEB32, and
     * pLdrSystemDllInitBlock->pRtlUserThreadStart is already published guest.
     * Without a guest window wow_base is 0 and this is the upstream code. */
    ULONG_PTR wow_base = ios_wow_base_for_peb( teb->Peb );
    /* A thread of a child process in its own guest window gets THAT process's PEB32 (the page
     * after its PEB), not the main process's wow_peb, when its argument is the PEB.
     * MADEIRA_WOW_CHILD_PEB=0 always passes wow_peb as before. */
    static int wow_child_peb = -1;
    if (wow_child_peb < 0)
    {
        const char *e = getenv( "MADEIRA_WOW_CHILD_PEB" );
        wow_child_peb = !(e && e[0] == '0');
    }
    void *proc_peb = wow_child_peb ? (void *)teb->Peb : (void *)peb;
    void *proc_wow_peb = (wow_child_peb && wow_base) ? (char *)teb->Peb + page_size : (void *)wow_peb;
#define IOS_WOW_GUEST_IN(ptr) ios_wow_guest_in( (ptr), wow_base )

    if ((i386_context = get_cpu_area( IMAGE_FILE_MACHINE_I386 )))
    {
        XMM_SAVE_AREA32 *fpu = (XMM_SAVE_AREA32 *)i386_context->ExtendedRegisters;
        i386_context->ContextFlags = CONTEXT_I386_ALL;
        i386_context->Eax = IOS_WOW_GUEST_IN( entry );
        i386_context->Ebx = IOS_WOW_GUEST_IN( (arg == proc_peb || arg == peb) ? proc_wow_peb : arg );
        i386_context->Esp = get_wow_teb( teb )->Tib.StackBase - 16;
        i386_context->Eip = pLdrSystemDllInitBlock->pRtlUserThreadStart;
        i386_context->SegCs = 0x23;
        i386_context->SegDs = 0x2b;
        i386_context->SegEs = 0x2b;
        i386_context->SegFs = 0x53;
        i386_context->SegGs = 0x2b;
        i386_context->SegSs = 0x2b;
        i386_context->EFlags = 0x202;
        fpu->ControlWord = 0x27f;
        fpu->MxCsr = 0x1f80;
        fpux_to_fpu( &i386_context->FloatSave, fpu );
    }
    else if ((arm_context = get_cpu_area( IMAGE_FILE_MACHINE_ARMNT )))
    {
        arm_context->ContextFlags = CONTEXT_ARM_ALL;
        arm_context->R0 = IOS_WOW_GUEST_IN( entry );
        arm_context->R1 = IOS_WOW_GUEST_IN( (arg == proc_peb || arg == peb) ? proc_wow_peb : arg );
        arm_context->Sp = get_wow_teb( teb )->Tib.StackBase;
        arm_context->Pc = pLdrSystemDllInitBlock->pRtlUserThreadStart;
        if (arm_context->Pc & 1) arm_context->Cpsr |= 0x20; /* thumb mode */
    }
#undef IOS_WOW_GUEST_IN

    if (suspend)
    {
        context.ContextFlags |= CONTEXT_EXCEPTION_REPORTING | CONTEXT_EXCEPTION_ACTIVE;
        wait_suspend( &context );
    }

    ctx = (CONTEXT *)((ULONG_PTR)context.Sp & ~15) - 1;
    *ctx = context;
    ctx->ContextFlags = CONTEXT_FULL;
    signal_set_full_context( ctx );

    frame->sp    = (ULONG64)ctx;
    frame->pc    = (ULONG64)IOS_PFUNC(LdrInitializeThunk);
    frame->x[0]  = (ULONG64)ctx;
    frame->x[18] = (ULONG64)teb;

#ifdef WINE_IOS
    /* Translate PE code addresses to JIT pool addresses.
     * On iOS/TXM, PE code pages can't be made executable. The code was
     * copied to the JIT pool by mprotect_exec. Redirect PC to execute
     * from the JIT pool's original RX address.
     *
     * IMPORTANT: fixup_for_fastpath must be called AFTER this redirect,
     * so frame->x[16] == frame->pc (JIT pool address). Otherwise the
     * fastpath check fails and the slowpath (SIGUSR2) is taken, which
     * relies on iOS kernel restoring X18 from ucontext — but iOS
     * overrides X18 (platform register) on signal return. */
    {
        extern void *ios_jit_translate_addr(void *addr);
        void *orig_pc = (void *)(uintptr_t)frame->pc;
        void *jit_pc = ios_jit_translate_addr(orig_pc);
        if (jit_pc != orig_pc)
        {
            frame->pc = (ULONG64)(uintptr_t)jit_pc;
            ERR("init_syscall_frame: redirected PC %p → %p (JIT pool)\n", orig_pc, jit_pc);
        }
    }
#endif

    syscall_frame_fixup_for_fastpath( frame );

#ifdef WINE_IOS
    /* Save TEB for signal handler recovery */
    ios_teb_for_signals = (uintptr_t)teb;

    /* Store TEB in pthread TLS slot — accessible via TPIDRRO_EL0 which
     * iOS preserves across context switches. TPIDR_EL0 is NOT safe (iOS zeros it).
     * The x18 binary patcher rewrites PE code to read TEB from this TLS slot. */
    {
        extern pthread_key_t ios_teb_tls_key;
        extern int ios_teb_tls_slot_offset;
        pthread_setspecific(ios_teb_tls_key, teb);
        /* Also compute the raw TSD slot offset for the patcher's trampolines */
        if (ios_teb_tls_slot_offset == 0)
        {
            uintptr_t tsd_base;
            __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tsd_base));
            tsd_base &= ~7ULL;
            /* Find our TEB in the TSD array */
            for (int s = 0; s < 512; s++)
            {
                if (*(void **)(tsd_base + s * 8) == teb)
                {
                    ios_teb_tls_slot_offset = s * 8;
                    ERR("init_syscall_frame: TEB at TSD slot %d (offset 0x%x from TPIDRRO_EL0)\n",
                        s, ios_teb_tls_slot_offset);
                    break;
                }
            }
        }
    }

    /* Allocate per-thread trampoline slot in JIT pool */
    {
        extern int ios_jit_alloc_trampoline_slot(void);
        extern void ios_jit_set_teb_slot(int slot, uintptr_t teb);
        extern void *ios_jit_get_trampoline(int slot);

        ios_my_slot = ios_jit_alloc_trampoline_slot();
        ios_jit_set_teb_slot(ios_my_slot, (uintptr_t)teb);
        ios_my_trampoline = ios_jit_get_trampoline(ios_my_slot);
        ERR("init_syscall_frame: allocated trampoline slot %d, tramp=%p, teb=%p\n",
            ios_my_slot, ios_my_trampoline, teb);
    }

    /* iOS x18 workaround: The kernel zeroes x18 on context switches.
     * Pages 0-0x1FFF are readable on this device (return 0) but are NOT
     * a VM mapping (mach_vm_region shows first region at ~0x104000000).
     * The readable pages are hardware/firmware behavior that can't be
     * modified via mach_vm_protect/deallocate.
     *
     * When x18=0, [x18+0x60] silently returns PEB=0 instead of faulting.
     * Derived registers get corrupted before SEGV fires, making the
     * trampoline retry useless.
     *
     * Solution: CREATE a VM mapping at address 0 containing TEB data.
     * This overrides the hardware zero-page behavior. When x18=0,
     * [x18+offset] reads real TEB data from our mapping.
     * If all mapping approaches fail, the Mach exception handler
     * is the last resort for x18 restoration. */
    /* 2026-07-03: attempt the page0 chain ONCE PER PROCESS, not per thread.
     * Page 0 is process-global (and can only hold one thread's TEB anyway),
     * so re-running M1-M8 on every new thread only re-fails. Worse, the M8
     * debugger BRK is FATAL on threads created after the debugger detaches:
     * with no debugger, the BRK trap unwinds through a handler chain that
     * (with x18=0 on a fresh thread) calls a raw non-executable ntdll PE
     * address → undispatchable BUS → NtTerminateProcess. Observed killing
     * Thumper's worker-thread spawn at ~2:30 (thread 0054, splash wall). */
    static int ios_page0_attempted = 0;
    if (ios_page0_attempted) {
        ERR("page0: already attempted by first thread — skipping (Mach handler covers x18=0)\n");
    } else {
        ios_page0_attempted = 1;
        kern_return_t kr;
        int mapped = 0;
        uintptr_t teb_page = (uintptr_t)teb & ~0x3FFFULL;
        uintptr_t teb_off = (uintptr_t)teb - teb_page;

        /* Diagnostic: what's at address 0 */
        mach_vm_address_t region_addr = 0;
        mach_vm_size_t region_size = 0;
        vm_region_basic_info_data_64_t rinfo = {0};
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj_name = MACH_PORT_NULL;
        kr = mach_vm_region(mach_task_self(), &region_addr, &region_size,
                            VM_REGION_BASIC_INFO_64, (vm_region_info_t)&rinfo,
                            &info_count, &obj_name);
        ERR("page0: first_region=%p size=0x%llx prot=%d/%d kr=%d teb=%p teb_page=%p off=0x%lx\n",
            (void*)region_addr, (unsigned long long)region_size,
            rinfo.protection, rinfo.max_protection, kr,
            teb, (void*)teb_page, (unsigned long)teb_off);

        /* M1: mach_vm_allocate at 0 with VM_FLAGS_FIXED */
        if (!mapped) {
            mach_vm_address_t target = 0;
            kr = mach_vm_allocate(mach_task_self(), &target, 0x4000, VM_FLAGS_FIXED);
            ERR("page0 M1 allocate(FIXED): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mach_vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 1;
            }
        }

        /* M2: mach_vm_map anonymous RW at 0, FIXED|OVERWRITE */
        if (!mapped) {
            mach_vm_address_t target = 0;
            kr = mach_vm_map(mach_task_self(), &target, 0x4000, 0,
                             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                             MACH_PORT_NULL, 0, FALSE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_INHERIT_NONE);
            ERR("page0 M2 map(RW,FIXED|OVERWRITE): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mach_vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 2;
            }
        }

        /* M3: mach_vm_map anonymous RW at 0, FIXED only (no OVERWRITE) */
        if (!mapped) {
            mach_vm_address_t target = 0;
            kr = mach_vm_map(mach_task_self(), &target, 0x4000, 0,
                             VM_FLAGS_FIXED,
                             MACH_PORT_NULL, 0, FALSE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_PROT_READ | VM_PROT_WRITE,
                             VM_INHERIT_NONE);
            ERR("page0 M3 map(RW,FIXED): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mach_vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 3;
            }
        }

        /* M4: mach_vm_remap TEB page at 0 (shared mirror) */
        if (!mapped) {
            mach_vm_address_t target = 0;
            vm_prot_t cur_prot, max_prot;
            kr = mach_vm_remap(mach_task_self(), &target, 0x4000, 0,
                               VM_FLAGS_FIXED, mach_task_self(),
                               (mach_vm_address_t)teb_page, FALSE,
                               &cur_prot, &max_prot, VM_INHERIT_NONE);
            ERR("page0 M4 remap(FIXED): kr=%d target=%p\n", kr, (void*)target);
            if (kr == KERN_SUCCESS && target == 0) mapped = 4;
        }

        /* M5: memory entry + mach_vm_map */
        if (!mapped) {
            memory_object_size_t entry_size = 0x4000;
            mach_port_t mem_entry = MACH_PORT_NULL;
            kr = mach_make_memory_entry_64(mach_task_self(), &entry_size,
                (mach_vm_address_t)teb_page,
                VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_VM_SHARE,
                &mem_entry, MACH_PORT_NULL);
            ERR("page0 M5 mem_entry: kr=%d\n", kr);
            if (kr == KERN_SUCCESS) {
                mach_vm_address_t target = 0;
                kr = mach_vm_map(mach_task_self(), &target, 0x4000, 0,
                    VM_FLAGS_FIXED,
                    mem_entry, 0, FALSE,
                    VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE,
                    VM_INHERIT_NONE);
                ERR("page0 M5 map: kr=%d target=%p\n", kr, (void*)target);
                if (kr == KERN_SUCCESS && target == 0) mapped = 5;
                mach_port_deallocate(mach_task_self(), mem_entry);
            }
        }

        /* M6: mmap MAP_FIXED at 0 */
        if (!mapped) {
            void *p = mmap(0, 0x4000, PROT_READ | PROT_WRITE,
                           MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0);
            ERR("page0 M6 mmap(RW,FIXED): p=%p errno=%d\n", p, p == MAP_FAILED ? errno : 0);
            if (p == (void*)0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                mprotect(0, 0x4000, PROT_READ);
                mapped = 6;
            }
        }

        /* M7: vm_allocate (32-bit API) at 0 */
        if (!mapped) {
            vm_address_t target = 0;
            kr = vm_allocate(mach_task_self(), &target, 0x4000, VM_FLAGS_FIXED);
            ERR("page0 M7 vm_allocate: kr=%d target=%p\n", kr, (void*)(uintptr_t)target);
            if (kr == KERN_SUCCESS && target == 0) {
                memcpy((void*)teb_off, (void*)teb_page, 0x4000 - teb_off);
                vm_protect(mach_task_self(), 0, 0x4000, FALSE, VM_PROT_READ);
                mapped = 7;
            }
        }

        if (mapped) {
            /* Verify: compare PEB pointer from addr 0 vs real TEB */
            uint64_t peb0 = *(volatile uint64_t *)(teb_off + 0x60);
            uint64_t peb_real = *(volatile uint64_t *)((uintptr_t)teb + 0x60);
            ERR("TEB MAPPED at addr 0 (M%d)! peb@0x60=%p real=%p %s\n",
                mapped, (void*)peb0, (void*)peb_real,
                peb0 == peb_real ? "MATCH" : "MISMATCH");

            /* Check region again to confirm real mapping exists */
            region_addr = 0;
            info_count = VM_REGION_BASIC_INFO_COUNT_64;
            kr = mach_vm_region(mach_task_self(), &region_addr, &region_size,
                                VM_REGION_BASIC_INFO_64, (vm_region_info_t)&rinfo,
                                &info_count, &obj_name);
            ERR("page0 post-map: region=%p size=0x%llx prot=%d/%d\n",
                (void*)region_addr, (unsigned long long)region_size,
                rinfo.protection, rinfo.max_protection);
        }

        /* M8: Ask the debugger to write TEB data to page 0 via BRK #0xf00d cmd 3.
         * The debugger may have kernel privileges that the app doesn't.
         * Uses GDB M (memory write) command to write TEB data at address 0. */
        if (!mapped) {
            ERR("page0: trying debugger (BRK #0xf00d, x16=3)...\n");
            register uintptr_t x0_val __asm__("x0") = (uintptr_t)teb;
            register size_t x1_val __asm__("x1") = 0x4000;
            register uintptr_t x0_result __asm__("x0");
            __asm__ volatile(
                "mov x16, #3\n"
                "brk #0xf00d\n"
                : "=r"(x0_result)
                : "r"(x0_val), "r"(x1_val)
                : "x16", "memory"
            );
            ERR("page0 M8 debugger: result=%lu\n", (unsigned long)x0_result);
            if (x0_result == 1) {
                /* Verify: read PEB from address 0+offset */
                uintptr_t teb_off = (uintptr_t)teb - ((uintptr_t)teb & ~0x3FFFULL);
                uint64_t peb0 = *(volatile uint64_t *)(teb_off + 0x60);
                uint64_t peb_real = *(volatile uint64_t *)((uintptr_t)teb + 0x60);
                ERR("page0 M8 verify: peb@0x%lx=%p real=%p %s\n",
                    (unsigned long)(teb_off + 0x60), (void*)peb0, (void*)peb_real,
                    peb0 == peb_real ? "MATCH" : "MISMATCH");
                if (peb0 == peb_real) mapped = 8;
            }
        }

        if (!mapped) {
            ERR("ALL page0 mapping approaches FAILED (including debugger) — relying on Mach handler only\n");
        }
    }
    /* Register this thread with the shared Mach exception handler.
     * First call creates the handler thread; all calls register the thread. */
    ios_setup_mach_exception_handler( pthread_mach_thread_np(pthread_self()),
                                       (uintptr_t)teb, ios_my_trampoline );
    /* Give the handler thread a moment to start (only needed for first thread) */
    if (!ios_exc_thread_alive) usleep(10000);
    ERR("init_syscall_frame: mach exc thread alive=%d, slot=%d\n",
        ios_exc_thread_alive, ios_my_slot);

    ERR("init_syscall_frame: signals_total=%d before PE entry\n", ios_signal_total);
    ERR("init_syscall_frame: frame=%p pc=%p x0=%p sp=%p x18=%p restore_flags=0x%x\n",
        frame, (void*)(uintptr_t)frame->pc, (void*)(uintptr_t)frame->x[0],
        (void*)(uintptr_t)frame->sp, (void*)(uintptr_t)frame->x[18], frame->restore_flags);

    /* Note: SIGALRM x18 watchdog was tried but abandoned — too disruptive
     * for PE code execution. The zero-page silent read issue remains:
     * when x18=0, [x18+0x60] returns PEB=0 from the hardware zero page
     * without faulting, so the Mach handler can't intervene. */
#endif

    pthread_sigmask( SIG_UNBLOCK, &server_block_set, NULL );
}


/***********************************************************************
 *           signal_start_thread
 */
__ASM_GLOBAL_FUNC( signal_start_thread,
                   "stp x29, x30, [sp,#-0xc0]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0xc0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xb8\n\t")
                   "mov x29, sp\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   "stp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   "stp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   "stp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   "stp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   "stp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "add x5, x29, #0xc0\n\t"     /* syscall_cfa */
                   /* set syscall frame */
                   "ldr x4, [x3, #0x378]\n\t"   /* thread_data->syscall_frame */
                   "cbnz x4, 1f\n\t"
                   "sub x4, sp, #0x330\n\t"     /* sizeof(struct syscall_frame) */
                   "str x4, [x3, #0x378]\n\t"   /* thread_data->syscall_frame */
                   "1:\tstr wzr, [x4, #0x10c]\n\t" /* frame->restore_flags */
                   "stp xzr, x5, [x4, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   /* switch to kernel stack */
                   "mov sp, x4\n\t"
                   "bl " __ASM_NAME("init_syscall_frame") "\n\t"
#if 0 /* WINE_IOS: use standard dispatcher_return which loads ALL registers
       * and routes through the TEB trampoline on iOS */
#else
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return")
#endif
                   )


/***********************************************************************
 *           __wine_syscall_dispatcher
 */
__ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                   "hint 34\n\t" /* bti c */
#ifdef WINE_IOS
                   /* iOS zeros x18 on context switches. Load TEB from TPIDRRO_EL0
                    * (pthread TLS) which iOS preserves. Fix x18 for frame saves. */
                   "mrs x10, TPIDRRO_EL0\n\t"
                   "and x10, x10, #~7\n\t"       /* clear CPU number bits */
                   "adrp x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGE\n\t"
                   "ldr w11, [x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGEOFF]\n\t"
                   "ldr x18, [x10, x11]\n\t"     /* x18 = TEB from TLS slot */
#endif
                   "ldr x10, [x18, #0x378]\n\t" /* thread_data->syscall_frame */
                   "stp x18, x19, [x10, #0x90]\n\t"
                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "mov x19, sp\n\t"
                   "stp x9, x19, [x10, #0xf0]\n\t"
                   "mrs x9, NZCV\n\t"
                   "stp x30, x9, [x10, #0x100]\n\t"
                   "str w8, [x10, #0x120]\n\t"
                   "mrs x9, FPCR\n\t"
                   "str w9, [x10, #0x128]\n\t"
                   "mrs x9, FPSR\n\t"
                   "str w9, [x10, #0x12c]\n\t"
                   "stp q0,  q1,  [x10, #0x130]\n\t"
                   "stp q2,  q3,  [x10, #0x150]\n\t"
                   "stp q4,  q5,  [x10, #0x170]\n\t"
                   "stp q6,  q7,  [x10, #0x190]\n\t"
                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
                   "stp q10, q11, [x10, #0x1d0]\n\t"
                   "stp q12, q13, [x10, #0x1f0]\n\t"
                   "stp q14, q15, [x10, #0x210]\n\t"
                   "stp q16, q17, [x10, #0x230]\n\t"
                   "stp q18, q19, [x10, #0x250]\n\t"
                   "stp q20, q21, [x10, #0x270]\n\t"
                   "stp q22, q23, [x10, #0x290]\n\t"
                   "stp q24, q25, [x10, #0x2b0]\n\t"
                   "stp q26, q27, [x10, #0x2d0]\n\t"
                   "stp q28, q29, [x10, #0x2f0]\n\t"
                   "stp q30, q31, [x10, #0x310]\n\t"
                   "mov x22, x10\n\t"
                   /* switch to kernel stack */
                   "mov sp, x10\n\t"
                   /* we're now on the kernel stack, stitch unwind info with previous frame */
                   __ASM_CFI_CFA_IS_AT2(x22, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")
                   "and x20, x8, #0xfff\n\t"    /* syscall number */
                   "ubfx x21, x8, #12, #2\n\t"  /* syscall table number */
                   "ldr x16, [x18, #0x370]\n\t" /* thread_data->syscall_table */
                   "add x21, x16, x21, lsl #5\n\t"
                   "ldr x16, [x21, #16]\n\t"    /* table->ServiceLimit */
                   "cmp x20, x16\n\t"
                   "bcs " __ASM_LOCAL_LABEL("bad_syscall") "\n\t"
                   "ldr x16, [x21, #24]\n\t"    /* table->ArgumentTable */
                   "ldrb w9, [x16, x20]\n\t"
                   "subs x9, x9, #64\n\t"
                   "bls 2f\n\t"
                   "sub sp, sp, x9\n\t"
                   "tbz x9, #3, 1f\n\t"
                   "sub sp, sp, #8\n"
                   "1:\tsub x9, x9, #8\n\t"
                   "ldr x10, [x19, x9]\n\t"
                   "str x10, [sp, x9]\n\t"
                   "cbnz x9, 1b\n"
                   "2:\tldr x16, [x21]\n\t"     /* table->ServiceTable */
                   "ldr x23, [x16, x20, lsl 3]\n\t"
                   "ldr w11, [x18, #0x380]\n\t" /* thread_data->syscall_trace */
                   "cbnz x11, " __ASM_LOCAL_LABEL("trace_syscall") "\n\t"
                   "blr x23\n\t"
                   "mov sp, x22\n"
                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") ":\n\t"
#ifdef WINE_IOS
                   /* Trace: capture frame->x[18] and frame->pc before they are loaded */
                   "ldr x10, [sp, #0x90]\n\t"   /* frame->x[18] - will become x18 */
                   "adrp x11, " __ASM_NAME("g_wine_return_x18") "@PAGE\n\t"
                   "str x10, [x11, " __ASM_NAME("g_wine_return_x18") "@PAGEOFF]\n\t"
                   "ldr x10, [sp, #0x100]\n\t"  /* frame->pc - will become ret target */
                   "adrp x11, " __ASM_NAME("g_wine_return_pc") "@PAGE\n\t"
                   "str x10, [x11, " __ASM_NAME("g_wine_return_pc") "@PAGEOFF]\n\t"
                   "adrp x11, " __ASM_NAME("g_wine_return_count") "@PAGE\n\t"
                   "ldr x10, [x11, " __ASM_NAME("g_wine_return_count") "@PAGEOFF]\n\t"
                   "add x10, x10, #1\n\t"
                   "str x10, [x11, " __ASM_NAME("g_wine_return_count") "@PAGEOFF]\n\t"
                   /* ring buffer: store frame->pc (at sp+0x100) into ring[idx & 7] */
                   "ldr x10, [sp, #0x100]\n\t"          /* frame->pc */
                   "adrp x11, " __ASM_NAME("g_wine_return_ring_idx") "@PAGE\n\t"
                   "ldr w12, [x11, " __ASM_NAME("g_wine_return_ring_idx") "@PAGEOFF]\n\t"
                   "and w13, w12, #7\n\t"                /* idx & 7 */
                   "add w12, w12, #1\n\t"
                   "str w12, [x11, " __ASM_NAME("g_wine_return_ring_idx") "@PAGEOFF]\n\t"
                   "adrp x11, " __ASM_NAME("g_wine_return_ring") "@PAGE\n\t"
                   "add x11, x11, " __ASM_NAME("g_wine_return_ring") "@PAGEOFF\n\t"
                   "str x10, [x11, x13, lsl #3]\n\t"    /* ring[idx&7] = frame->pc */
#endif
                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "tbz x16, #1, 2f\n\t"        /* CONTEXT_INTEGER */
                   "ldp x12, x13, [sp, #0x80]\n\t" /* frame->x[16..17] */
                   "ldp x14, x15, [sp, #0xf8]\n\t" /* frame->sp, frame->pc */
                   "cmp x12, x15\n\t"              /* frame->x16 == frame->pc? */
                   "ccmp x13, x14, #0, eq\n\t"     /* frame->x17 == frame->sp? */
                   "beq 1f\n\t"                    /* take slowpath if unequal */
                   "bl " __ASM_NAME("syscall_dispatcher_return_slowpath") "\n"
                   "1:\tldp x0, x1, [sp, #0x00]\n\t"
                   "ldp x2, x3, [sp, #0x10]\n\t"
                   "ldp x4, x5, [sp, #0x20]\n\t"
                   "ldp x6, x7, [sp, #0x30]\n\t"
                   "ldp x8, x9, [sp, #0x40]\n\t"
                   "ldp x10, x11, [sp, #0x50]\n\t"
                   "ldp x12, x13, [sp, #0x60]\n\t"
                   "ldp x14, x15, [sp, #0x70]\n"
                   "2:\tldp x18, x19, [sp, #0x90]\n\t"
#ifdef WINE_IOS
                   /* TPIDR_EL0 not used — iOS zeros it. TEB stored via pthread TLS (TPIDRRO_EL0). */
#endif
                   "ldp x20, x21, [sp, #0xa0]\n\t"
                   "ldp x22, x23, [sp, #0xb0]\n\t"
                   "ldp x24, x25, [sp, #0xc0]\n\t"
                   "ldp x26, x27, [sp, #0xd0]\n\t"
                   "ldp x28, x29, [sp, #0xe0]\n\t"
                   "tbz x16, #2, 1f\n\t"        /* CONTEXT_FLOATING_POINT */
                   "ldp q0,  q1,  [sp, #0x130]\n\t"
                   "ldp q2,  q3,  [sp, #0x150]\n\t"
                   "ldp q4,  q5,  [sp, #0x170]\n\t"
                   "ldp q6,  q7,  [sp, #0x190]\n\t"
                   "ldp q8,  q9,  [sp, #0x1b0]\n\t"
                   "ldp q10, q11, [sp, #0x1d0]\n\t"
                   "ldp q12, q13, [sp, #0x1f0]\n\t"
                   "ldp q14, q15, [sp, #0x210]\n\t"
                   "ldp q16, q17, [sp, #0x230]\n\t"
                   "ldp q18, q19, [sp, #0x250]\n\t"
                   "ldp q20, q21, [sp, #0x270]\n\t"
                   "ldp q22, q23, [sp, #0x290]\n\t"
                   "ldp q24, q25, [sp, #0x2b0]\n\t"
                   "ldp q26, q27, [sp, #0x2d0]\n\t"
                   "ldp q28, q29, [sp, #0x2f0]\n\t"
                   "ldp q30, q31, [sp, #0x310]\n\t"
                   "ldr w17, [sp, #0x128]\n\t"
                   "msr FPCR, x17\n\t"
                   "ldr w17, [sp, #0x12c]\n\t"
                   "msr FPSR, x17\n"
                   "1:\tldp x16, x17, [sp, #0x100]\n\t"
                   "msr NZCV, x17\n\t"
                   /* x18 was restored from frame->x[18] at label 2 above.
                    * This path does NOT go through sigreturn, so x18 survives.
                    * If a context switch zeroes x18 before PE code runs,
                    * the Mach exception handler fixes it via per-thread trampoline. */
                   "ldp x30, x17, [sp, #0xf0]\n\t"
                   /* switch to user stack */
                   "mov sp, x17\n\t"
                   "ret x16\n"

                   __ASM_LOCAL_LABEL("trace_syscall") ":\n\t"
                   "stp x0, x1, [sp, #-0x40]!\n\t"
                   "stp x2, x3, [sp, #0x10]\n\t"
                   "stp x4, x5, [sp, #0x20]\n\t"
                   "stp x6, x7, [sp, #0x30]\n\t"
                   "mov x0, x8\n\t"             /* id */
                   "mov x1, sp\n\t"             /* args */
                   "ldr x16, [x21, #24]\n\t"    /* table->ArgumentTable */
                   "ldrb w2, [x16, x20]\n\t"    /* len */
                   "bl " __ASM_NAME("trace_syscall") "\n\t"
                   "ldp x2, x3, [sp, #0x10]\n\t"
                   "ldp x4, x5, [sp, #0x20]\n\t"
                   "ldp x6, x7, [sp, #0x30]\n\t"
                   "ldp x0, x1, [sp], #0x40\n\t"
                   "blr x23\n"
                   "mov sp, x22\n"

                   __ASM_LOCAL_LABEL("trace_syscall_ret") ":\n\t"
                   "mov x21, x0\n\t"            /* retval */
                   "ldr w0, [sp, #0x120]\n\t"   /* frame->syscall_id */
                   "mov x1, x21\n\t"            /* retval */
                   "bl " __ASM_NAME("trace_sysret") "\n\t"
                   "mov x0, x21\n\t"            /* retval */
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n"

                   __ASM_LOCAL_LABEL("bad_syscall") ":\n\t"
                   "mov x0, #0xc0000000\n\t"    /* STATUS_INVALID_SYSTEM_SERVICE */
                   "movk x0, #0x001c\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )

__ASM_GLOBAL_FUNC( __wine_syscall_dispatcher_return,
                   "ldr w11, [x18, #0x380]\n\t" /* thread_data->syscall_trace */
                   "cbnz x11, " __ASM_LOCAL_LABEL("trace_syscall_ret") "\n\t"
                   "b " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") )


/***********************************************************************
 *           __wine_unix_call_dispatcher
 */
/***********************************************************************
 *           ios_unixlib_null_call
 *
 * Where __wine_unix_call_dispatcher sends a call it cannot make: a NULL
 * table (a DLL whose __wine_init_unix_call() failed and that called
 * WINE_UNIX_CALL anyway -- on this port a 32-bit module with no unix side,
 * which the loader refuses with STATUS_NOT_SUPPORTED), a code past any
 * builtin's funcs_count, or a NULL entry inside a real table.  Upstream
 * dereferences the table and the whole pseudo-process dies in the
 * dispatcher, on a host-side fault no guest handler can see.  Report the
 * caller once per module and answer STATUS_NOT_IMPLEMENTED, which is what
 * the caller's own error path already expects from a missing unix side.
 */
#define IOS_UNIXLIB_MAX_CODE     0x1000
#define IOS_UNIXLIB_MAX_CODE_STR "0x1000"

#define IOS_UNIXLIB_NULL_SEEN 32
static uint64_t ios_unixlib_null_seen[IOS_UNIXLIB_NULL_SEEN];
static unsigned int ios_unixlib_null_seen_count;

NTSTATUS __attribute__((used)) ios_unixlib_null_call( UINT64 handle, unsigned int code,
                                                      const void *ret_addr )
{
    uint64_t lr = (uint64_t)(uintptr_t)ret_addr, key = 0, rva = 0;
    const char *name = "?";
    unsigned int i;
    Dl_info di;
    extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
    uint64_t mod = 0, va;

    if (lr && (va = ios_jit_reverse_translate( lr, &mod )) && mod)
    {
        name = ios_pe_module_name( mod );
        rva  = va - mod;
        key  = mod;
    }
    else if (lr && dladdr( (void *)(uintptr_t)lr, &di ) && di.dli_fbase)
    {
        if (di.dli_fname) name = di.dli_fname;
        rva = lr - (uint64_t)(uintptr_t)di.dli_fbase;
        key = (uint64_t)(uintptr_t)di.dli_fbase;
    }
    else key = lr & ~0xfffull;

    for (i = 0; i < ios_unixlib_null_seen_count && i < IOS_UNIXLIB_NULL_SEEN; i++)
        if (ios_unixlib_null_seen[i] == key) return STATUS_NOT_IMPLEMENTED;
    if (ios_unixlib_null_seen_count < IOS_UNIXLIB_NULL_SEEN)
        ios_unixlib_null_seen[ios_unixlib_null_seen_count++] = key;

    dprintf( STDERR_FILENO,
             "[unixlib] call with %s from %s+0x%llx code=%u handle=0x%llx -> "
             "STATUS_NOT_IMPLEMENTED (this module has no unix side on this port; "
             "further calls from it are silent)\n",
             !handle ? "NULL handle" :
             code >= IOS_UNIXLIB_MAX_CODE ? "out-of-range code" : "NULL table entry",
             name, (unsigned long long)rva, code, (unsigned long long)handle );
    return STATUS_NOT_IMPLEMENTED;
}


__ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
                   "hint 34\n\t" /* bti c */
#ifdef WINE_IOS
                   "mrs x10, TPIDRRO_EL0\n\t"
                   "and x10, x10, #~7\n\t"
                   "adrp x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGE\n\t"
                   "ldr w11, [x11, " __ASM_NAME("ios_teb_tls_slot_offset") "@PAGEOFF]\n\t"
                   "ldr x18, [x10, x11]\n\t"     /* x18 = TEB from TLS */
#endif
                   "ldr x10, [x18, #0x378]\n\t" /* thread_data->syscall_frame */
                   "stp x18, x19, [x10, #0x90]\n\t"
                   "stp x20, x21, [x10, #0xa0]\n\t"
                   "stp x22, x23, [x10, #0xb0]\n\t"
                   "stp x24, x25, [x10, #0xc0]\n\t"
                   "stp x26, x27, [x10, #0xd0]\n\t"
                   "stp x28, x29, [x10, #0xe0]\n\t"
                   "stp q8,  q9,  [x10, #0x1b0]\n\t"
                   "stp q10, q11, [x10, #0x1d0]\n\t"
                   "stp q12, q13, [x10, #0x1f0]\n\t"
                   "stp q14, q15, [x10, #0x210]\n\t"
                   "mov x9, sp\n\t"
                   "stp x30, x9, [x10, #0xf0]\n\t"
                   "mrs x9, NZCV\n\t"
                   "stp x30, x9, [x10, #0x100]\n\t"
                   "mov x19, x10\n\t"
                   /* switch to kernel stack */
                   "mov sp, x10\n\t"
                   /* we're now on the kernel stack, stitch unwind info with previous frame */
                   __ASM_CFI_CFA_IS_AT2(x19, 0x98, 0x02) /* frame->syscall_cfa */
                   __ASM_CFI(".cfi_offset 29, -0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30, -0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19, -0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20, -0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21, -0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22, -0x98\n\t")
                   __ASM_CFI(".cfi_offset 23, -0x90\n\t")
                   __ASM_CFI(".cfi_offset 24, -0x88\n\t")
                   __ASM_CFI(".cfi_offset 25, -0x80\n\t")
                   __ASM_CFI(".cfi_offset 26, -0x78\n\t")
                   __ASM_CFI(".cfi_offset 27, -0x70\n\t")
                   __ASM_CFI(".cfi_offset 28, -0x68\n\t")
                   /* Never dereference a unixlib table the PE side never got.
                    * x0 is the table, x1 the code; a NULL table, a code past
                    * any builtin's funcs_count, or a NULL entry inside a real
                    * table all divert to ios_unixlib_null_call(), which logs
                    * once per caller module and returns STATUS_NOT_IMPLEMENTED.
                    * Three instructions on the hot path, against a host-side
                    * fault that killed the whole pseudo-process. */
                   "cbz x0, " __ASM_LOCAL_LABEL("unixcall_no_table") "\n\t"
                   "cmp x1, #" IOS_UNIXLIB_MAX_CODE_STR "\n\t"
                   "b.hs " __ASM_LOCAL_LABEL("unixcall_no_table") "\n\t"
                   "ldr x16, [x0, x1, lsl 3]\n\t"
                   "cbz x16, " __ASM_LOCAL_LABEL("unixcall_no_table") "\n\t"
                   "mov x0, x2\n\t"             /* args */
                   "blr x16\n"
                   __ASM_LOCAL_LABEL("unixcall_return") ":\n\t"
                   "ldr w16, [sp, #0x10c]\n\t"  /* frame->restore_flags */
                   "cbnz w16, " __ASM_LOCAL_LABEL("__wine_syscall_dispatcher_return") "\n\t"
                   __ASM_CFI_CFA_IS_AT2(sp, 0x98, 0x02) /* frame->syscall_cfa */
                   "ldp x18, x19, [sp, #0x90]\n\t"
                   /* iOS-Madeira 2026-07-04: REMOVED `msr TPIDR_EL0, x18`
                    * ("keep TPIDR_EL0 in sync"). Nothing of ours reads
                    * TPIDR_EL0 — every TEB recovery path (dispatchers, x18
                    * patcher trampolines, Mach handler) uses TPIDRRO_EL0 +
                    * TSD slot; the patcher header comment claiming
                    * TPIDR_EL0 was stale. Writing an OS-owned per-thread
                    * register on every unix-call return is pure risk:
                    * libsystem_malloc died with corrupted per-thread zone
                    * state (Metal texture allocs, 3 runs) right after
                    * UNIXCALL-DIRECT multiplied direct returns. */
                   "ldp x16, x17, [sp, #0xf8]\n\t"
                   /* switch to user stack */
                   "mov sp, x16\n\t"
                   "ret x17\n"

                   /* No table, no entry, or a code out of range: report it and
                    * return STATUS_NOT_IMPLEMENTED through the normal epilogue.
                    * x0/x1 still hold the handle and the code; x30 still holds
                    * the caller's return address (it was only SAVED to the
                    * frame above, never overwritten), and clobbering it with
                    * the `bl` is safe because the return uses x17 loaded from
                    * the frame, not x30. */
                   __ASM_LOCAL_LABEL("unixcall_no_table") ":\n\t"
                   "mov x2, x30\n\t"            /* ret_addr */
                   "bl " __ASM_NAME("ios_unixlib_null_call") "\n\t"
                   "b " __ASM_LOCAL_LABEL("unixcall_return") )

