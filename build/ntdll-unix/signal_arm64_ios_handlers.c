/* Part of signal_arm64_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. The other signal handlers. Same copyright and licence as signal_arm64_ios.c. */
/**********************************************************************
 *		bus_handler
 *
 * Handler for SIGBUS.
 */
static void bus_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_DATATYPE_MISALIGNMENT };
#ifdef WINE_IOS
    /* ml481 (#85): foreign-thread faults must not reach wine logging — see
     * ios_fault_is_foreign(). Must precede ios_make_wine_logging_safe(). */
    if (ios_fault_is_foreign( (void *)PC_sig( (ucontext_t *)sigcontext ), siginfo->si_addr ))
    {
        ios_decline_foreign_fault( signal, (void *)PC_sig( (ucontext_t *)sigcontext ), siginfo->si_addr );
        return;
    }
    ios_make_wine_logging_safe();   /* ml375: before any ERR/WARN — see helper */
    ios_track_signal( signal, sigcontext );
    static int bus_count = 0;
    bus_count++;
    if (bus_count <= 5)
    {
        uintptr_t bus_pc_val = (uintptr_t)PC_sig((ucontext_t*)sigcontext);
        uintptr_t bus_lr_val = (uintptr_t)LR_sig((ucontext_t*)sigcontext);
        /* iOS user space starts ~0x100000000; anything below is unmapped. */
        int bus_pc_ok = (bus_pc_val >= 0x100000000ULL);
        int bus_lr_ok = (bus_lr_val >= 0x100000000ULL + 4);
        uint32_t bus_insn = bus_pc_ok ? *(uint32_t*)bus_pc_val : 0;
        uint32_t bus_branch_insn = bus_lr_ok ? *(uint32_t*)(bus_lr_val - 4) : 0;
        ERR("BUS #%d: pc=%p addr=%p x16=%p x17=%p x18=%p lr=%p insn=0x%08x branch@lr-4=0x%08x%s\n",
            bus_count, (void*)bus_pc_val, siginfo->si_addr,
            (void*)REGn_sig(16, (ucontext_t*)sigcontext),
            (void*)REGn_sig(17, (ucontext_t*)sigcontext),
            (void*)REGn_sig(18, (ucontext_t*)sigcontext),
            (void*)bus_lr_val, bus_insn, bus_branch_insn,
            bus_pc_ok ? "" : " <unmappable PC>");
        /* Dump Mach handler .data fault diagnostic (first fault only) */
        if (bus_count == 1 && ios_exc_data_fault_count > 0)
        {
            ERR("  Mach 1st .data: pc=0x%llx lr=0x%llx sp=0x%llx cnt=%d\n",
                (unsigned long long)ios_exc_data_fault_pc,
                (unsigned long long)ios_exc_data_fault_lr,
                (unsigned long long)ios_exc_data_fault_sp,
                ios_exc_data_fault_count);
            ERR("  Mach regs: x0=%llx x1=%llx x2=%llx x3=%llx\n",
                (unsigned long long)ios_exc_data_x0,
                (unsigned long long)ios_exc_data_x1,
                (unsigned long long)ios_exc_data_x2,
                (unsigned long long)ios_exc_data_x3);
            ERR("  Mach regs: x16=%llx x17=%llx x18=%llx x29=%llx\n",
                (unsigned long long)ios_exc_data_x16,
                (unsigned long long)ios_exc_data_x17,
                (unsigned long long)ios_exc_data_x18,
                (unsigned long long)ios_exc_data_x29);
            ERR("  insn@LR=0x%08x frame_ptr=0x%llx frame->pc=0x%llx\n",
                ios_exc_data_insn_at_lr,
                (unsigned long long)ios_exc_data_fault_frame_ptr,
                (unsigned long long)ios_exc_data_fault_frame_pc);
        }
    }
    ucontext_t *bus_ctx = sigcontext;
    void *pc = (void *)PC_sig(bus_ctx);
    int is_exec_fault = (pc == siginfo->si_addr);

    /* 1. Execution fault (pc == fault_addr): redirect to JIT pool copy.
     * This handles indirect calls through function pointers, import tables, etc. */
    if (is_exec_fault)
    {
        extern void *ios_jit_translate_addr(void *addr);
        extern int ios_jit_addr_is_text(uintptr_t addr);
        extern void *ios_jit_rx_base_global;
        extern size_t ios_jit_pool_size_global;
        extern uintptr_t ios_jit_anon_alias_lookup_rx(uintptr_t fault_addr);

        void *jit_pc = ios_jit_translate_addr(pc);
        if (jit_pc == pc) {
            /* Try the anon-alias table (FEX CodeBuffer / runtime JIT) */
            uintptr_t rx_pc = ios_jit_anon_alias_lookup_rx((uintptr_t)pc);
            if (rx_pc) jit_pc = (void *)rx_pc;
        }
        if (jit_pc != pc)
        {
            /* Use trampoline to set x18 (sigreturn zeroes it on iOS) */
            if (ios_my_trampoline && ios_teb_for_signals)
            {
                REGn_sig(17, bus_ctx) = (uintptr_t)jit_pc;
                PC_sig(bus_ctx) = (uintptr_t)ios_my_trampoline;
            }
            else
            {
                PC_sig(bus_ctx) = (uintptr_t)jit_pc;
            }
            return;  /* Resume from JIT pool address */
        }

        /* Execution fault at address already in JIT pool (can't redirect).
         * This means code jumped into a non-executable section (.data, .rdata).
         * Do NOT fall through to store emulation — that would walk PC through
         * data bytes for thousands of faults. Log diagnostics and crash. */
        {
            uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
            size_t pool_sz = ios_jit_pool_size_global;
            if ((rx && (uintptr_t)pc >= rx && (uintptr_t)pc < rx + pool_sz) ||
                ios_jit_low_contains( (uintptr_t)pc ))   /* madeira-bcd pool-low */
            {
                extern volatile uint64_t g_wine_return_pc;
                extern volatile uint64_t g_wine_return_x18;
                extern volatile uint64_t g_wine_return_count;
                ERR("BUS EXEC in JIT .data: pc=%p (pool+0x%lx) lr=%p sp=%p\n",
                    pc, (unsigned long)((uintptr_t)pc - rx),
                    (void*)LR_sig(bus_ctx), (void*)SP_sig(bus_ctx));
                ERR("  x0=%p x1=%p x2=%p x3=%p\n",
                    (void*)REGn_sig(0, bus_ctx), (void*)REGn_sig(1, bus_ctx),
                    (void*)REGn_sig(2, bus_ctx), (void*)REGn_sig(3, bus_ctx));
                ERR("  x16=%p x17=%p x18=%p x29=%p\n",
                    (void*)REGn_sig(16, bus_ctx), (void*)REGn_sig(17, bus_ctx),
                    (void*)REGn_sig(18, bus_ctx), (void*)REGn_sig(29, bus_ctx));
                ERR("  last dispatcher_return: pc=%p x18=%p count=%llu\n",
                    (void*)(uintptr_t)g_wine_return_pc,
                    (void*)(uintptr_t)g_wine_return_x18,
                    (unsigned long long)g_wine_return_count);
                {
                    extern volatile uint64_t g_wine_dispatcher_count;
                    extern volatile int ios_total_segv_count;
                    /* Read instruction at LR-4 (the BL/BLR that set LR) */
                    uint32_t insn_lr_m4 = 0;
                    uintptr_t lr_val = (uintptr_t)LR_sig(bus_ctx);
                    if (lr_val >= 4) insn_lr_m4 = *(uint32_t *)(lr_val - 4);
                    ERR("  disp_entry=%llu segv_count=%d insn@LR-4=0x%08x\n",
                        (unsigned long long)g_wine_dispatcher_count,
                        ios_total_segv_count, insn_lr_m4);
                }
                ERR("  is_text=%d mach_data_faults=%d mach_x18_fixes=%lld\n",
                    ios_jit_addr_is_text((uintptr_t)pc),
                    ios_exc_data_fault_count, (long long)ios_exc_x18_fixes);
                /* Dump ring buffer of last 8 dispatcher_return PCs */
                {
                    extern volatile uint64_t g_wine_return_ring[8];
                    extern volatile uint32_t g_wine_return_ring_idx;
                    uint32_t ri = g_wine_return_ring_idx;
                    ERR("  ret ring (newest→oldest): %p %p %p %p %p %p %p %p\n",
                        (void*)(uintptr_t)g_wine_return_ring[(ri-1)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-2)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-3)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-4)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-5)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-6)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-7)&7],
                        (void*)(uintptr_t)g_wine_return_ring[(ri-8)&7]);
                }
                /* ml1353: GIVE UP ON AN UNRECOVERABLE EXEC FAULT.
                 *
                 * A pool page whose max protection has lost EXECUTE can never run
                 * code again (the ml1351 [pool-poison] class). When the faulting
                 * code is the process's own ntdll copy, the exception dispatcher
                 * sits on the same dead pages, so delivering the fault faults
                 * again at the dispatcher, forever: device log 81, two launched
                 * children at a full core each for the rest of the session. After
                 * 32 consecutive faults of one thread at one pc on such a page,
                 * end this pseudo-process (abort_process, run on the thread
                 * itself after this handler returns) instead.
                 * env.MADEIRA_POOL_NOEXEC_GIVEUP = 0 keeps the endless retry. */
                {
                    static int giveup = -1;
                    extern int ios_addr_max_prot( const void *addr, int *prot );
                    if (giveup < 0)
                    {
                        const char *e = getenv( "MADEIRA_POOL_NOEXEC_GIVEUP" );
                        giveup = !(e && e[0] == '0');
                    }
                    if (giveup)
                    {
                        int cur = -1, maxp = ios_addr_max_prot( pc, &cur );
                        if (maxp >= 0 && !(maxp & VM_PROT_EXECUTE))
                        {
                            static struct { uintptr_t teb, pc; unsigned int n; } trk[32];
                            static unsigned int trk_next;
                            uintptr_t fteb = (uintptr_t)REGn_sig(18, bus_ctx);
                            unsigned int i, slot = 32, n;

                            for (i = 0; i < 32; i++) if (trk[i].teb == fteb) { slot = i; break; }
                            if (slot == 32)
                            {
                                slot = trk_next++ % 32;
                                trk[slot].teb = fteb;
                                trk[slot].pc = 0;
                                trk[slot].n = 0;
                            }
                            if (trk[slot].pc != (uintptr_t)pc)
                            {
                                trk[slot].pc = (uintptr_t)pc;
                                trk[slot].n = 0;
                            }
                            n = ++trk[slot].n;
                            if (n >= 32)
                            {
                                TEB *cteb = NtCurrentTeb();
                                dprintf( 2, "[pool] ml1353 giving up: pid %04x tid %04x pc=%p (pool+0x%lx) "
                                         "faulted %u times in a row on a page whose max protection has no "
                                         "EXECUTE (prot=%x/%x); ending this process (c0000005) instead of "
                                         "retrying forever (env.MADEIRA_POOL_NOEXEC_GIVEUP=0 keeps retrying)\n",
                                         cteb ? (int)HandleToULong( cteb->ClientId.UniqueProcess ) : 0,
                                         cteb ? (int)HandleToULong( cteb->ClientId.UniqueThread ) : 0,
                                         pc, (unsigned long)((uintptr_t)pc - rx), n, cur, maxp );
                                trk[slot].teb = 0;
                                REGn_sig(0, bus_ctx) = STATUS_ACCESS_VIOLATION;
                                SP_sig(bus_ctx) &= ~(uintptr_t)15;
                                LR_sig(bus_ctx) = 0;
                                PC_sig(bus_ctx) = (uintptr_t)abort_process;
                                return;
                            }
                        }
                    }
                }
                /* Don't try store emulation, go straight to exception */
                goto bus_fatal;
            }
        }
    }

    /* 2. Data write fault (pc != fault_addr): code in JIT pool tries to write
     * to a data section in the JIT pool RX view. Emulate the store by
     * writing through the RW view instead. */
    {
        extern void *ios_jit_rx_base_global;
        extern void *ios_jit_rw_base_global;
        extern size_t ios_jit_pool_size_global;

        uintptr_t fault = (uintptr_t)siginfo->si_addr;
        uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
        uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
        size_t pool_sz = ios_jit_pool_size_global;

        /* madeira-bcd pool-low: a store into region C goes through its alias at
         * the same distance (rw_addr below holds for it unchanged) */
        if ((rx && fault >= rx && fault < rx + pool_sz) || (rx && rw && ios_jit_low_contains( fault )))
        {
            uintptr_t rw_addr = fault - rx + rw;
            uint32_t insn = *(uint32_t *)(uintptr_t)PC_sig(bus_ctx);

            if (ios_emulate_store(bus_ctx, insn, rw_addr))
            {
                PC_sig(bus_ctx) += 4;
                ios_fixup_x18_for_return( bus_ctx );
                return;  /* Resume after the emulated store */
            }
            /* ml264 (#45): NAME THE MEMORY, not the instruction.
             *
             * All four failing instructions in ml264 target the SAME address
             * 0x156a097b0 (pool offset 0x361b57b0, tail/JIT-code area) and all four
             * are ATOMICS of different widths:
             *   0x88eafe89  CAS   32-bit   x1
             *   0xc8f1fd60  CAS   64-bit   x1
             *   0x4866fd64  CASPAL 128-bit x1
             *   0x4866fe6a  CASPAL 128-bit x59
             * A location that rejects atomics at EVERY width is not an instruction
             * problem -- the Size==1 CASPAL implementation is in and working, and
             * [caspal128] is silent. On Apple silicon LSE atomics require normal
             * cacheable memory, and this pool is mach_vm_remap dual-mapped (RW alias
             * + RX alias), which is exactly the kind of mapping where they fault.
             *
             * Two readings need opposite fixes: (a) the whole dual-mapped pool
             * rejects atomics -- then FEX's own atomics on pool-resident structures
             * can never work there and the data must move; (b) only THIS page is bad
             * (reclaimed, or the single-page RW poison of task #41) -- a page-level
             * problem with a page-level fix. protection/max_protection/share_mode/
             * user_tag distinguish them. Capped; fires only on an already-fatal path. */
            {
                static int busrgn;
                if (busrgn++ < 10)
                {
                    mach_vm_address_t ba = (mach_vm_address_t)(uintptr_t)siginfo->si_addr;
                    mach_vm_size_t bs = 0;
                    vm_region_basic_info_data_64_t bbi;
                    mach_msg_type_number_t bbc = VM_REGION_BASIC_INFO_COUNT_64;
                    mach_port_t bbo = MACH_PORT_NULL;
                    mach_vm_address_t xa = (mach_vm_address_t)(uintptr_t)siginfo->si_addr;
                    mach_vm_size_t xs = 0;
                    vm_region_extended_info_data_t xi;
                    mach_msg_type_number_t xc = VM_REGION_EXTENDED_INFO_COUNT;
                    mach_port_t xo = MACH_PORT_NULL;
                    extern void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
                    extern size_t ios_jit_pool_size_global;
                    uintptr_t rxb = (uintptr_t)ios_jit_rx_base_global;
                    uintptr_t rwb = (uintptr_t)ios_jit_rw_base_global;
                    size_t psz = ios_jit_pool_size_global;
                    uintptr_t fa = (uintptr_t)siginfo->si_addr;
                    const char *where = "outside pool";

                    if (rxb && fa >= rxb && fa < rxb + psz) where = "JIT-POOL-RX (dual-mapped)";
                    else if (rwb && fa >= rwb && fa < rwb + psz) where = "JIT-POOL-RW (alias)";

                    if (mach_vm_region( mach_task_self(), &ba, &bs, VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&bbi, &bbc, &bbo ) == KERN_SUCCESS &&
                        mach_vm_region( mach_task_self(), &xa, &xs, VM_REGION_EXTENDED_INFO,
                                        (vm_region_info_t)&xi, &xc, &xo ) == KERN_SUCCESS)
                        ERR("[atomic-mem] addr=%p %s pooloff=0x%llx | region=0x%llx+0x%llx "
                            "prot=%d max=%d share_mode=%d user_tag=%d\n",
                            siginfo->si_addr, where,
                            (unsigned long long)(rxb && fa >= rxb ? fa - rxb : 0),
                            (unsigned long long)ba, (unsigned long long)bs,
                            bbi.protection, bbi.max_protection, xi.share_mode, xi.user_tag);
                    else
                        ERR("[atomic-mem] addr=%p %s -- mach_vm_region FAILED (unmapped?)\n",
                            siginfo->si_addr, where);
                }
            }
            ERR("BUS: unhandled store insn=0x%08x at pc=%p addr=%p\n",
                insn, pc, siginfo->si_addr);
        }

        /* 3. iOS-Madeira ml420 (#69, ml419 fatal chain): data fault with the
         * TARGET outside the pool. Two previously-unhandled sub-cases died
         * insanely here:
         *
         *   (a) Darwin delivers PROTECTION faults as SIGBUS (KERN_PROTECTION_
         *       FAILURE), not SIGSEGV — so every wine-legitimate PROT_NONE
         *       state (guard page, write-watch, commit-on-fault) that
         *       segv_handler repairs via virtual_handle_fault was unreachable
         *       from this handler and fell through to a bogus 80000002.
         *   (b) pc in the JIT pool + an UNREADABLE target page (ml419: emitted
         *       libcef sqlite code reading a stripped .rdata page): raising
         *       80000002 sent FEX down HandleUnalignedAccess (useless — the
         *       PAGE is the problem, not alignment) and the exception record
         *       carried the raw host pc into guest dispatch.
         *
         * Order: wine repair first; then a safe readability probe decides
         * honest-AV (unreadable) vs genuine-alignment 80000002 (readable). */
        if (!is_exec_fault && !(rx && fault >= rx && fault < rx + pool_sz) &&
            !(rx && rw && ios_jit_low_contains( fault )))   /* madeira-bcd pool-low */
        {
            EXCEPTION_RECORD vrec = { EXCEPTION_ACCESS_VIOLATION };
            mach_vm_size_t rd_out = 0;
            uint64_t rd_buf = 0;
            kern_return_t rd_kr;

            vrec.NumberParameters = 2;
            vrec.ExceptionInformation[0] = EXCEPTION_READ_FAULT;  /* refined below if the insn is a store */
            vrec.ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
            vrec.ExceptionAddress = (void *)PC_sig(bus_ctx);
            {
                uint32_t f_insn = *(uint32_t *)(uintptr_t)PC_sig(bus_ctx);
                /* The data abort's ESR says whether the access wrote (WnR, bit 6).
                 * The encoding guess below calls the LSE atomics (LDADD, SWP, CAS...:
                 * an x86 lock xadd / xchg) reads, because they have bit 22 set, so a
                 * write was reported to the guest as a read. MADEIRA_FAULT_ESR_DIR=0
                 * keeps the encoding guess alone. */
                static int esr_dir = -1;
                DWORD64 f_esr = get_fault_esr( bus_ctx );
                unsigned f_ec = (unsigned)(f_esr >> 26) & 0x3f;
                if (esr_dir < 0) { const char *e = getenv( "MADEIRA_FAULT_ESR_DIR" ); esr_dir = !(e && e[0] == '0'); }
                if (esr_dir && (f_ec == 0x24 || f_ec == 0x25))
                {
                    if (f_esr & 0x40) vrec.ExceptionInformation[0] = EXCEPTION_WRITE_FAULT;
                }
                /* loads have bit22 set in the ld/st register/immediate classes;
                 * good enough to label the fault direction for wine's repair */
                else if ((f_insn & 0x0a000000) == 0x08000000 && !(f_insn & 0x00400000))
                    vrec.ExceptionInformation[0] = EXCEPTION_WRITE_FAULT;
            }

            if (!virtual_handle_fault( &vrec, (void *)SP_sig(bus_ctx) ))
            {
                static int bus_healed;
                if (bus_healed < 16 && ++bus_healed <= 16)
                    ERR("[bus-heal] virtual_handle_fault repaired addr=%p (pc=%p) — "
                        "guard/watch/commit state, was fatal before ml420\n",
                        siginfo->si_addr, pc);
                ios_fixup_x18_for_return( bus_ctx );
                return;
            }

            /* [syscall-fault] the page cannot be repaired. If a system call is reading or writing it inside a __TRY (a
             * ReadProcessMemory probe of the process's own memory), that call fails; it must not become a guest exception. */
            if (ios_bus_syscall_fault( bus_ctx, &vrec ))
            {
                ios_fixup_x18_for_return( bus_ctx );
                return;
            }

            rd_kr = mach_vm_read_overwrite( mach_task_self(),
                                            (mach_vm_address_t)(uintptr_t)siginfo->si_addr & ~7ULL,
                                            8, (mach_vm_address_t)(uintptr_t)&rd_buf, &rd_out );

            /* name the memory once per class — this is the probe that finally
             * identifies WHAT state the page is in (ml419 had no region info) */
            {
                /* ml560: SEPARATE BUDGETS PER CLASS.
                 *
                 * ml559 lost the run that mattered to this cap. The single
                 * `busrgn2 < 10` counter was drained by ten early ALIGNMENT
                 * faults (69 of them that run), so when the fatal UNREADABLE
                 * fault arrived at cnt=127 there was no budget left and the
                 * region was never described. The noise class starved the
                 * subject class — an event cap where a per-subject cap was
                 * needed. Unreadable faults now have their own budget that
                 * alignment faults cannot touch. */
                static int busrgn2, busrgn_unread;
                int bus_is_unread = (rd_kr != KERN_SUCCESS);
                if (bus_is_unread ? (busrgn_unread++ < 8) : (busrgn2++ < 10))
                {
                    mach_vm_address_t ba = (mach_vm_address_t)(uintptr_t)siginfo->si_addr;
                    mach_vm_size_t bs = 0;
                    vm_region_basic_info_data_64_t bbi;
                    mach_msg_type_number_t bbc = VM_REGION_BASIC_INFO_COUNT_64;
                    mach_port_t bbo = MACH_PORT_NULL;
                    mach_vm_address_t xa = ba;
                    mach_vm_size_t xs = 0;
                    vm_region_extended_info_data_t xi;
                    mach_msg_type_number_t xc = VM_REGION_EXTENDED_INFO_COUNT;
                    mach_port_t xo = MACH_PORT_NULL;

                    ERR("[bus-rgn] si_code=%d addr=%p pc=%p pc_in_pool=%d readable=%d\n",
                        siginfo->si_code, siginfo->si_addr, pc,
                        ((rx && (uintptr_t)pc >= rx && (uintptr_t)pc < rx + pool_sz) ||
                         ios_jit_low_contains( (uintptr_t)pc )) ? 1 : 0,
                        rd_kr == KERN_SUCCESS);
                    if (mach_vm_region( mach_task_self(), &ba, &bs, VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&bbi, &bbc, &bbo ) == KERN_SUCCESS &&
                        mach_vm_region( mach_task_self(), &xa, &xs, VM_REGION_EXTENDED_INFO,
                                        (vm_region_info_t)&xi, &xc, &xo ) == KERN_SUCCESS)
                    {
                        ERR("[bus-rgn]   region=0x%llx+0x%llx prot=%d max=%d share_mode=%d user_tag=%d\n",
                            (unsigned long long)ba, (unsigned long long)bs,
                            bbi.protection, bbi.max_protection, xi.share_mode, xi.user_tag);

                        /* ml560: WHO OWNS THIS PAGE, and why can't it be materialised?
                         *
                         * ml559's fatal fault reported kr=10 (KERN_MEMORY_ERROR) on an
                         * address that was mapped, page-aligned, and RW both at handler
                         * entry and during the handler — yet a read probe of it FAILED.
                         * That is neither an absence fault nor a protection fault, so
                         * "protection was stripped" cannot be the explanation and the
                         * reheal below is a no-op for it.
                         *
                         * These fields separate the live hypotheses outright:
                         *   external_pager=1   -> section/file backed (a Valve or CEF
                         *                         shared-memory object) — suspect the
                         *                         backing object died or was truncated
                         *   external_pager=0   -> anonymous; then swapped_out>0 points at
                         *                         a compressor/decompression failure
                         *   purgeable VOLATILE/EMPTY -> the region was PURGED; the fix is
                         *                         ownership/lifetime, not protection
                         *   resident=0 + dirtied=0   -> never materialised at all
                         * user_tag names the allocator; shadow_depth/ref_count expose a
                         * broken COW chain. */
                        {
                            int purge_state = -1;
                            kern_return_t pk = mach_vm_purgable_control(
                                mach_task_self(), ba, VM_PURGABLE_GET_STATE,
                                (int *)&purge_state );
                            ERR("[bus-rgn]   OWNER extpager=%u resident=%u swapped=%u "
                                "dirtied=%u reusable=%u refcnt=%u shadow=%u  purgeable=%s(0x%x) "
                                "rev=ml560\n",
                                (unsigned)xi.external_pager, xi.pages_resident,
                                xi.pages_swapped_out, xi.pages_dirtied, xi.pages_reusable,
                                xi.ref_count, (unsigned)xi.shadow_depth,
                                pk != KERN_SUCCESS ? "not-purgeable" :
                                  ((purge_state & VM_PURGABLE_STATE_MASK) == VM_PURGABLE_EMPTY ? "EMPTY(PURGED)" :
                                   (purge_state & VM_PURGABLE_STATE_MASK) == VM_PURGABLE_VOLATILE ? "VOLATILE(can be purged)" :
                                   (purge_state & VM_PURGABLE_STATE_MASK) == VM_PURGABLE_NONVOLATILE ? "nonvolatile" : "other"),
                                pk == KERN_SUCCESS ? (unsigned)purge_state : 0u);
                            ERR("[bus-rgn]   VERDICT %s rev=ml560\n",
                                xi.external_pager
                                  ? "<== SECTION/FILE-BACKED — backing object is the suspect"
                                  : (xi.pages_swapped_out
                                       ? "<== ANONYMOUS + SWAPPED OUT — compressor/decompress suspect"
                                       : (xi.pages_resident == 0
                                            ? "<== ANONYMOUS, NEVER RESIDENT — never materialised"
                                            : "<== ANONYMOUS AND RESIDENT — none of the standard stories fit")));

                        /* ml561: WHO MADE THIS MAPPING, and which pages materialise?
                         *
                         * Two facts settle the "unbacked tail" story. First the
                         * provenance: if offset+host_size runs past the file's real
                         * size, the tail pages have no backing and touching them gives
                         * exactly this kr=10. Second the page census: probe every host
                         * page of the region and print which ones read — the prediction
                         * is that pages below +0x10000 succeed and the rest fail. If
                         * instead ALL pages read, the fault was transient and the whole
                         * EOF theory is wrong; the census says so either way. */
                        {
                            extern void ios_map_describe( const void *addr, char *out, size_t outlen );
                            char prov[420];
                            char census[96];
                            unsigned ci = 0;
                            mach_vm_address_t pa;
                            ios_map_describe( (const void *)(uintptr_t)ba, prov, sizeof(prov) );
                            ERR("[bus-rgn]   PROVENANCE %s rev=ml561\n", prov);
                            for (pa = ba; pa < ba + bs && ci < sizeof(census) - 2; pa += 0x4000)
                            {
                                unsigned char t; mach_vm_size_t got = 0;
                                census[ci++] = (mach_vm_read_overwrite( mach_task_self(), pa, 1,
                                                  (mach_vm_address_t)(uintptr_t)&t, &got )
                                                == KERN_SUCCESS && got == 1) ? '.' : 'X';
                            }
                            census[ci] = 0;
                            ERR("[bus-rgn]   PAGE-CENSUS 16KB pages from 0x%llx: [%s]  "
                                "('.'=materialises 'X'=fails; fault is at +0x%llx) rev=ml561\n",
                                (unsigned long long)ba, census,
                                (unsigned long long)((uintptr_t)siginfo->si_addr - (uintptr_t)ba));
                        }

                        /* ml561 (Sol's discriminator): DUMP THE GUEST FILL ARGUMENTS.
                         *
                         * The recurring victim is Skia's 2D 32-bit rect fill at
                         * libcef+0x41258F0, verified by disassembling the PHONE's
                         * libcef.dll:
                         *     fill32(dest=rcx, value=edx, width_dwords=r8d,
                         *            row_stride=r9, height=[rsp+0x30])
                         * ml554 and ml559 both faulted at EXACTLY region_base+0x10000
                         * (the 64KB Windows allocation granularity) in an 0x14000 region
                         * — i.e. four 16KB pages materialise and the fifth does not.
                         *
                         * Two stories fit, and these numbers separate them outright:
                         *   fill extent <= region end  -> the VIEW is right and the
                         *                                 BACKING is short (section
                         *                                 sizing/lifetime bug: mapping
                         *                                 past EOF gives exactly this)
                         *   fill extent >  region end  -> the guest OVERRAN; then the
                         *                                 width/stride/height tuple is
                         *                                 itself suspect, which would be
                         *                                 the first real bridge to the
                         *                                 tile-displacement bug
                         *
                         * No FEX reconstruction needed: under ARM64EC the guest regs ARE
                         * fixed ARM regs (rcx=x0, rdx=x1, r8=x2, r9=x3, r10=x4, rax=x8,
                         * rsp=x23) — confirmed by disassembling FEX's own output for this
                         * exact function. Reading the signal context cannot perturb FEX. */
                        /* ml562 CORRECTION: only interpret registers as fill arguments
                         * when the fault is actually the unreadable class. On ml561's
                         * ALIGNMENT faults this block printed "FILL OVERRUNS THE REGION —
                         * guest geometry is wrong" from registers that were not fill
                         * arguments at all — a confident verdict with no precondition.
                         * A probe that always renders a verdict is worse than silent. */
                        if (!bus_is_unread)
                            ERR("[fill-args] (skipped — not an unreadable-page fault; "
                                "registers are not fill arguments here) rev=ml562\n");
                        else
                        {
                            uint64_t g_rcx = REGn_sig(0,  bus_ctx);
                            uint64_t g_rdx = REGn_sig(1,  bus_ctx);
                            uint64_t g_r8  = REGn_sig(2,  bus_ctx);
                            uint64_t g_r9  = REGn_sig(3,  bus_ctx);
                            uint64_t g_r10 = REGn_sig(4,  bus_ctx);
                            uint64_t g_rax = REGn_sig(8,  bus_ctx);
                            uint64_t g_rsp = REGn_sig(23, bus_ctx);
                            uint32_t height = 0;
                            mach_vm_size_t hgot = 0;
                            int have_h = (mach_vm_read_overwrite( mach_task_self(),
                                            (mach_vm_address_t)(g_rsp + 0x30), 4,
                                            (mach_vm_address_t)(uintptr_t)&height,
                                            &hgot ) == KERN_SUCCESS && hgot == 4);
                            uint64_t w  = (uint32_t)g_r8, str = (uint32_t)g_r9;
                            uint64_t rows_left = (uint32_t)g_rax;
                            /* extent still to be written from the CURRENT row base */
                            uint64_t last = g_rcx + (rows_left ? (rows_left - 1) * str : 0)
                                                  + (w ? w * 4 : 0);
                            /* ml563 (Sol was right): gating on bus_is_unread is NOT a
                             * fill32 gate — any unreadable fault would still be decoded
                             * under the fill ABI. A RIP check needs the module base,
                             * which we do not have in a signal handler, so verify the
                             * REGISTER FILE is consistent with fill32 instead:
                             *   cursor r10 must BE the faulting address,
                             *   width/stride/height positive, row bytes <= stride,
                             *   row base <= cursor.
                             * All four held in ml561's three real events (r10 == addr,
                             * 256*4 == stride 1024, height 256). When they do not hold,
                             * say so and print NO verdict. */
                            int fill_ok = (g_r10 == (uint64_t)(uintptr_t)siginfo->si_addr) &&
                                          w > 0 && str > 0 && have_h && height > 0 &&
                                          (w * 4) <= str && g_rcx <= g_r10;
                            if (!fill_ok)
                            {
                                ERR("[fill-args] registers are NOT consistent with the fill32 ABI "
                                    "(r10=0x%llx vs addr=%p, width=%llu stride=%llu height=%u) "
                                    "— NOT interpreting, no verdict rev=ml563\n",
                                    (unsigned long long)g_r10, siginfo->si_addr,
                                    (unsigned long long)w, (unsigned long long)str, height);
                            }
                            else
                            ERR("[fill-args] rcx(dest_row)=0x%llx edx(val)=0x%08x "
                                "r8d(width_dw)=%llu r9(stride)=%llu r10(cursor)=0x%llx "
                                "eax(rows_left)=%llu rsp=0x%llx height@rsp+0x30=%s%u rev=ml561\n",
                                (unsigned long long)g_rcx, (unsigned)(uint32_t)g_rdx,
                                (unsigned long long)w, (unsigned long long)str,
                                (unsigned long long)g_r10, (unsigned long long)rows_left,
                                (unsigned long long)g_rsp, have_h ? "" : "UNREADABLE:", height);
                            if (fill_ok)
                            ERR("[fill-args]   region=[0x%llx,0x%llx)  cursor_off=0x%llx  "
                                "projected_last=0x%llx  %s rev=ml561\n",
                                (unsigned long long)ba, (unsigned long long)(ba + bs),
                                (unsigned long long)(g_r10 - ba),
                                (unsigned long long)last,
                                last <= (uint64_t)(ba + bs)
                                  ? "<== FILL FITS THE REGION — backing is short, NOT an overrun"
                                  : "<== FILL OVERRUNS THE REGION — guest geometry is wrong");
                        }
                        }
                    }
                    else
                        ERR("[bus-rgn]   mach_vm_region FAILED (address unmapped)\n");
                    {
                        extern void ios_dump_fault_region( void *addr );
                        ios_dump_fault_region( siginfo->si_addr );
                    }
                }
            }

            /* ml552: THE WRITE-SIDE TWIN of the reheal below.
             *
             * The existing reheal only fires when the page is UNREADABLE
             * (rd_kr != KERN_SUCCESS). But iOS strips PROT_WRITE while leaving
             * PROT_READ intact, and then the read probe SUCCEEDS, this whole
             * branch is skipped, and a plain guest store dies as a fatal
             * c0000005 -- with no reheal ever attempted.
             *
             * That is exactly the login-window crash: the faulting instruction
             * reconstructs to libcef+0x41258FB, the loop head of Chromium's
             * frame CLEAR (`movl %edx,(%r10)`), i.e. a STORE into the render
             * bitmap. Across 5 runs, every run that logged [bus-reheal] also
             * crashed and every run without it did not -- protection stripping
             * and the crash travel together.
             *
             * So: readable page + WRITE fault + wine expects PROT_WRITE + host
             * protection lacks it  =>  restore and resume, same as the read side.
             * Always logs the wine-vs-host comparison for the first few, so if
             * this case never actually occurs we find out instead of assuming.
             */
            if (ios_tlswatch_fault( siginfo->si_addr, pc, "bus" ))
            {
                ios_fixup_x18_for_return( bus_ctx );
                return;
            }
            if (rd_kr == KERN_SUCCESS)
            {
                DWORD64 esr = get_fault_esr( bus_ctx );
                int is_write = (int)((esr >> 6) & 1);          /* ISS.WnR */
                extern int ios_page_expected_prot( const void *addr );
                int want = ios_page_expected_prot( siginfo->si_addr );
                mach_vm_address_t ra = (mach_vm_address_t)(uintptr_t)siginfo->si_addr;
                mach_vm_size_t rs = 0;
                vm_region_basic_info_data_64_t rbi;
                mach_msg_type_number_t rc = VM_REGION_BASIC_INFO_COUNT_64;
                mach_port_t ro = MACH_PORT_NULL;
                int host_prot = -1;

                if (mach_vm_region( mach_task_self(), &ra, &rs, VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&rbi, &rc, &ro ) == KERN_SUCCESS)
                    host_prot = rbi.protection;

                {
                    static unsigned long wr_seen, wr_healed;
                    /* Logical RWX does not mean the host may grant W: the
                     * alias is RX by design. In particular, let FEX see CAS
                     * writes so it invalidates translated code before patching
                     * the RW alias. Healing here skips that invalidation and
                     * leaves CoreCLR repeatedly executing its old prestub. */
                    int aliased = ios_write_alias( (uintptr_t)siginfo->si_addr ) != 0;
                    int stripped = (is_write && (want & PROT_WRITE) && !aliased &&
                                    host_prot >= 0 && !(host_prot & VM_PROT_WRITE));
                    ++wr_seen;
                    if (wr_seen <= 12 || (wr_seen % 4096) == 0)
                        ERR("[wr-strip] #%lu addr=%p pc=%p esr=0x%llx write=%d "
                            "wine_want=%d host_prot=%d %s (seen=%lu healed=%lu) rev=ml552\n",
                            wr_seen, siginfo->si_addr, pc, (unsigned long long)esr,
                            is_write, want, host_prot,
                            aliased ? "(intentional alias protection)" :
                            stripped ? "<== HOST STRIPPED WRITE" : "(not a strip)",
                            wr_seen, wr_healed);

                    if (stripped)
                    {
                        enum { WR_HPAGE = 0x4000 };
                        char *hp = (char *)((uintptr_t)siginfo->si_addr & ~(uintptr_t)(WR_HPAGE - 1));
                        if (!mprotect( hp, WR_HPAGE, want ))
                        {
                            ++wr_healed;
                            ERR("[wr-strip] restored prot=%d on %p — resuming "
                                "(healed=%lu) rev=ml552\n", want, hp, wr_healed);
                            ios_fixup_x18_for_return( bus_ctx );
                            return;
                        }
                        ERR("[wr-strip] mprotect(%p, %d) FAILED errno=%d — falling to AV rev=ml552\n",
                            (void *)hp, want, errno);
                    }
                    else if (is_write)
                    {
                        /* ml998: not a strip -- Wine itself reports the page
                         * non-writable. Say WHY, with the raw vprot byte, before
                         * anyone is tempted to demote W^X on a guess. */
                        extern void ios_page_vprot_explain( const void *addr, const char *why );
                        ios_page_vprot_explain( siginfo->si_addr, "wr-strip-declined" );
                    }
                }
            }

            if (rd_kr != KERN_SUCCESS)
            {
                /* ml419's exact scenario: wine's bookkeeping says the page is
                 * committed+readable, but the HOST protection lost READ (a raw
                 * mprotect/mach call behind wine's back — no guest protect
                 * call touched the range all run). Put wine's intended prot
                 * back and resume; the [bus-rgn] dump above names the culprit
                 * region state for the real fix. Capped: a storm means the
                 * stripper is active and re-stripping — then die honestly. */
                extern int ios_page_expected_prot( const void *addr );
                int want = ios_page_expected_prot( siginfo->si_addr );
                if (want > 0 && (want & PROT_READ))
                {
                    static int rehealed;
                    if (rehealed < 8 && ++rehealed <= 8)
                    {
                        /* 16KB host pages; `host_page_size` in this file is the
                         * Mach FUNCTION, not a size (see the ml-era note above) */
                        enum { BUS_HPAGE = 0x4000 };
                        char *hpage = (char *)((uintptr_t)siginfo->si_addr & ~(uintptr_t)(BUS_HPAGE - 1));
                        if (!mprotect( hpage, BUS_HPAGE, want ))
                        {
                            /* ml560: the old text asserted "host had stripped it".
                             * ml559 disproved that for the fatal case: the same fault
                             * reported entryprot=3 nowprot=3 — protection was never
                             * stripped, the page simply could not be materialised
                             * (kr=10). Say what is actually known: the read probe
                             * failed and we re-applied wine's intended protection. */
                            ERR("[bus-reheal] #%d re-applied prot=%d on %p (read probe FAILED; "
                                "wine says committed+readable — NOT verified as a protection "
                                "strip, see [bus-rgn] OWNER/VERDICT) — resuming rev=ml560\n",
                                rehealed, want, hpage);
                            ios_fixup_x18_for_return( bus_ctx );
                            return;
                        }
                        ERR("[bus-reheal] #%d mprotect(%p, want=%d) FAILED errno=%d — falling to AV\n",
                            rehealed, (void *)hpage, want, errno);
                    }
                }
                /* unreadable target = an access violation, NOT misalignment.
                 * Deliver the honest AV; FEX's ResetToConsistentState takes the
                 * reconstruction path for c0000005 and rewrites the record to
                 * the true guest RIP (proven in ml419's fault #27 flow). */
                rec = vrec;
                ERR("BUS->AV: unreadable target addr=%p pc=%p rw=%d rev=ml420\n",
                    siginfo->si_addr, pc, (int)vrec.ExceptionInformation[0]);
                /* ml1043: this path printed neither registers nor a caller. A fault
                 * at FEX's rpfree+0x38 -- page->heap holding garbage -- could not be
                 * attributed: the pointer being freed (x0) and who freed it (lr and
                 * the frame chain) are exactly what decide between "metadata
                 * corruption" and "freed something rpmalloc never allocated". Frame
                 * records are read through mach_vm_read_overwrite, so a broken chain
                 * ends the walk instead of faulting inside the fault handler. */
                {
                    static int said;
                    if (said++ < 6)
                    {
                        ucontext_t *uc = sigcontext;
                        uint64_t fp = uc->uc_mcontext->__ss.__fp, i;
                        dprintf( 2, "[bus-regs] ml1043 x0=%llx x1=%llx x2=%llx x3=%llx x8=%llx x9=%llx x18=%llx lr=%llx sp=%llx\n",
                                 (unsigned long long)uc->uc_mcontext->__ss.__x[0], (unsigned long long)uc->uc_mcontext->__ss.__x[1],
                                 (unsigned long long)uc->uc_mcontext->__ss.__x[2], (unsigned long long)uc->uc_mcontext->__ss.__x[3],
                                 (unsigned long long)uc->uc_mcontext->__ss.__x[8], (unsigned long long)uc->uc_mcontext->__ss.__x[9],
                                 (unsigned long long)uc->uc_mcontext->__ss.__x[18], (unsigned long long)uc->uc_mcontext->__ss.__lr,
                                 (unsigned long long)uc->uc_mcontext->__ss.__sp );
                        for (i = 0; i < 12 && fp; i++)
                        {
                            uint64_t rec2[2] = {0, 0};
                            mach_vm_size_t got = 0;
                            if (mach_vm_read_overwrite( mach_task_self(), fp, sizeof rec2,
                                                        (mach_vm_address_t)(uintptr_t)rec2, &got ) != KERN_SUCCESS ||
                                got != sizeof rec2) break;
                            dprintf( 2, "[bus-regs] ml1043   frame[%llu] fp=%llx ret=%llx\n",
                                     (unsigned long long)i, (unsigned long long)fp, (unsigned long long)rec2[1] );
                            if (rec2[0] <= fp) break;
                            fp = rec2[0];
                        }
                    }
                }
                goto bus_fatal;
            }
            /* Darwin also reports data-abort permission faults as SIGBUS with
             * si_code == BUS_ADRALN. Readability does not authorize a store.
             * Keep the original context and dispatch an AV, allowing FEX's
             * SMC recovery or a guest exception handler to service it. Never
             * recursively fault inside the plain-access memcpy below.
             * Verified rdr67 ESR: 0x9200004f, write permission fault, not
             * the data-alignment fault status 0x21. */
            {
                unsigned esr = (unsigned)get_fault_esr( bus_ctx );
                unsigned ec = esr >> 26;
                if ((ec == 0x24 || ec == 0x25) && (esr & 0x3f) != 0x21)
                {
                    static unsigned protection_av_logs;
                    /* [syscall-fault] a permission fault of a system call's __TRY (a write probe of a read-only buffer, a read
                     * of a page that lost READ) fails the call, as above; guest code never reaches this (its stack pointer is not
                     * on the kernel stack and it has no jmp_buf). */
                    if (ios_bus_syscall_fault( bus_ctx, &vrec ))
                    {
                        ios_fixup_x18_for_return( bus_ctx );
                        return;
                    }
                    if (protection_av_logs++ < 16)
                        dprintf( 2, "[bus-data-av] pc=%p addr=%p esr=%08x rw=%lu\n",
                                 pc, siginfo->si_addr, esr,
                                 (unsigned long)vrec.ExceptionInformation[0] );
                    /* ml1048: NAME THE PAGE when the target is NOT the main image.
                     *
                     * The 16-line budget above is spent within seconds on the
                     * self-modifying writes into [0x140000000,0x148000000), which FEX
                     * services. The fault that kills the title is a different animal:
                     * a plain 8-byte store into ordinary anonymous DATA (0x17e3e908c,
                     * an arena that takes tens of thousands of successful stores per
                     * run) that arrives here as a write-PERMISSION fault, is declined
                     * by virtual_handle_fault, is not an SMC interval, and therefore
                     * reaches the guest as an AV it cannot survive. Deterministic: same
                     * guest RIP two runs running. What decides the fix is who made that
                     * page unwritable -- so record the ESR, the kernel's protection and
                     * max protection, the tag and the sharing mode. prot lacking W with
                     * max carrying it = someone mprotect()ed it; max lacking W = it was
                     * mapped that way; share_mode names COW/aliasing. */
                    {
                        uintptr_t fa = (uintptr_t)siginfo->si_addr;
                        static unsigned named;
                        if (!(fa >= 0x140000000ull && fa < 0x148000000ull) && named < 12)
                        {
                            mach_vm_address_t ra = (mach_vm_address_t)fa;
                            mach_vm_size_t rs = 0;
                            natural_t depth = 0;
                            vm_region_submap_info_data_64_t ri;
                            mach_msg_type_number_t rc = VM_REGION_SUBMAP_INFO_COUNT_64;
                            kern_return_t kr;
                            named++;
                            for (;;)
                            {
                                kr = mach_vm_region_recurse( mach_task_self(), &ra, &rs, &depth,
                                                             (vm_region_recurse_info_t)&ri, &rc );
                                if (kr != KERN_SUCCESS || !ri.is_submap) break;
                                depth++;
                            }
                            if (kr == KERN_SUCCESS)
                                dprintf( 2, "[bus-data-av] ml1048 NON-IMAGE target addr=%p pc=%p esr=%08x (fsc=%02x wnr=%u) | "
                                            "region=0x%llx+0x%llx prot=%d max=%d share_mode=%d user_tag=%u "
                                            "resident=%u dirtied=%u ref=%u shadow_depth=%u ext_pager=%u\n",
                                         siginfo->si_addr, pc, esr, esr & 0x3f, (esr >> 6) & 1,
                                         (unsigned long long)ra, (unsigned long long)rs, ri.protection,
                                         ri.max_protection, ri.share_mode, ri.user_tag,
                                         ri.pages_resident, ri.pages_dirtied, ri.ref_count,
                                         ri.shadow_depth, ri.external_pager );
                            else
                                dprintf( 2, "[bus-data-av] ml1048 NON-IMAGE target addr=%p pc=%p esr=%08x -- "
                                            "region lookup failed kr=%d\n", siginfo->si_addr, pc, esr, kr );
                            /* ...and Wine's own record of the same page, so the two views
                             * can be compared line against line. */
                            {
                                extern void ios_page_vprot_explain( const void *addr, const char *why );
                                extern int ios_page_expected_prot( const void *addr );
                                dprintf( 2, "[bus-data-av] ml1048 wine expects unix_prot=%d for %p\n",
                                         ios_page_expected_prot( siginfo->si_addr ), siginfo->si_addr );
                                ios_page_vprot_explain( siginfo->si_addr, "ml1048-non-image" );
                            }
                        }
                    }
                    /* ml1002: which guest module is decrypting? EMP.dll runs out
                     * of the emulated sub-floor window; the main image does not. */
                    ios_dump_guest_callers( "smc-write",
                                            (unsigned long long)bus_ctx->uc_mcontext->__ss.__x[28] );
                    /* ml1001: VERIFY THE SELF-MODIFYING WRITE ACTUALLY LANDS.
                     *
                     * This is the acceptance item Astra recorded as still owed:
                     * "actual backing writable, correct four bytes stored" was
                     * only ever satisfied indirectly, by the game reaching a
                     * second SMC address. All five rdr70 writes are MISALIGNED
                     * (0x1467df915 is odd-byte), which is precisely where our
                     * emulation can diverge from Windows/Wine -- and a dropped
                     * decryption store leaves stale ciphertext behind with no
                     * error anywhere.
                     *
                     * No instruction decoding and no register reads: snapshot
                     * the 16 bytes around the destination now, and on the NEXT
                     * entry re-read them and report whether they changed. A
                     * store that was supposed to land and left the bytes
                     * identical was dropped. That cannot be wrong about which
                     * register sourced the value. */
                    {
                        static mach_vm_address_t pend_addr;
                        static unsigned char pend_pre[16];
                        static uint32_t pend_insn;
                        static unsigned verify_n;
                        mach_vm_address_t base = (mach_vm_address_t)(uintptr_t)siginfo->si_addr & ~(mach_vm_address_t)7;
                        unsigned char now[16];
                        mach_vm_size_t vgot = 0;

                        if (pend_addr && verify_n < 16 &&
                            mach_vm_read_overwrite( mach_task_self(), pend_addr, sizeof(now),
                                                    (mach_vm_address_t)now, &vgot ) == KERN_SUCCESS &&
                            vgot == sizeof(now))
                        {
                            int same = !memcmp( now, pend_pre, sizeof(now) );
                            verify_n++;
                            dprintf( 2, "ml1001: previous SMC store at %#llx (insn=%08x) %s\n",
                                     (unsigned long long)pend_addr, pend_insn,
                                     same ? "LEFT THE BYTES UNCHANGED -- the store was DROPPED"
                                          : "changed the bytes (store landed)" );
                            if (!same)
                            {
                                unsigned i;
                                char b1[64], b2[64];
                                for (i = 0; i < 16; i++)
                                {
                                    sprintf( b1 + i * 3, "%02x ", pend_pre[i] );
                                    sprintf( b2 + i * 3, "%02x ", now[i] );
                                }
                                dprintf( 2, "ml1001:   before %s\nml1001:   after  %s\n", b1, b2 );
                            }
                        }
                        pend_insn = 0;
                        ios_fault_read_insn( (uint64_t)(uintptr_t)pc, &pend_insn );
                        if (mach_vm_read_overwrite( mach_task_self(), base, sizeof(pend_pre),
                                                    (mach_vm_address_t)pend_pre, &vgot ) == KERN_SUCCESS &&
                            vgot == sizeof(pend_pre))
                            pend_addr = base;
                        else
                            pend_addr = 0;
                    }
                    rec = vrec;
                    goto bus_fatal;
                }
            }
            /* iOS-Madeira ml479 (#83): readable target + BUS_ADRALN — emulate
             * PLAIN loads/stores in place before concluding "alignment fault →
             * 80000002". The 80000002 path only helps ATOMICS (FEX's unaligned
             * backpatcher); the 2026-08-04 Steam client does misaligned plain
             * 8-byte MOVs into a PA-band SM_COW region that alignment-faults
             * at the hardware level (prot=3, readable=1, si_code=1), and the
             * plain STR fell through FEX's handler into a fatal mislabeled
             * misalignment (webhelper death loop, ml478). x86 MOVs must simply
             * succeed. Atomic/exclusive/SIMD forms fail the decode below and
             * keep the existing 80000002 path unchanged. */
            if (siginfo->si_code == BUS_ADRALN)
            {
                uint32_t a_insn = *(uint32_t *)(uintptr_t)PC_sig(bus_ctx);
                /* ml498 census. The old counters CAPPED at 32/16 with no
                 * running total, so "32 emulated, 0 UNSUPPORTED" said nothing
                 * about how many faults actually happened or how many were
                 * refused — and this decode REFUSES SIMD (insn>>26&1). That
                 * matters now: the login window paints its glyphs correctly
                 * but leaves large background fills pure black, and a big
                 * solid fill is exactly where Skia uses wide vector stores
                 * while glyph blits stay byte-wise. If SIMD stores are being
                 * dropped, that asymmetry is explained. Counts are unbounded;
                 * only the log lines are rate-limited, and every line carries
                 * the totals so silence can never be mistaken for zero. */
                static unsigned long ua_emu_n, ua_simd_n, ua_other_n;
                if (ios_emulate_unaligned_guest_access(bus_ctx, a_insn, (uintptr_t)siginfo->si_addr))
                {
                    if (++ua_emu_n <= 16 || (ua_emu_n % 4096) == 0)
                        ERR("[unaligned-guest] emulated insn=0x%08x addr=%p pc=%p "
                            "(emu=%lu simd=%lu other=%lu) rev=ml498\n",
                            a_insn, siginfo->si_addr, pc, ua_emu_n, ua_simd_n, ua_other_n);
                    PC_sig(bus_ctx) += 4;
                    ios_fixup_x18_for_return( bus_ctx );
                    return;
                }
                /* madeira-bcd: an ordered/exclusive/LSE access in the app's own
                 * code -- ios_native_unaligned_emulate (the Launcher's `stlr` of
                 * build 454, which FEX took for guest code). */
                if (ios_native_unaligned_emulate( bus_ctx, a_insn, (uintptr_t)siginfo->si_addr,
                                                  (uint64_t)(uintptr_t)pc ))
                {
                    static unsigned long ua_native_sig;
                    if (++ua_native_sig <= 16 || (ua_native_sig % 4096) == 0)
                        ERR("[unaligned-native] signal-path pc=%p (app+0x%llx) insn=0x%08x addr=%p "
                            "emulated in place, not handed to FEX (#%lu)\n", pc,
                            (unsigned long long)((uint64_t)(uintptr_t)pc - ios_app_text_lo), a_insn,
                            siginfo->si_addr, ua_native_sig);
                    PC_sig(bus_ctx) += 4;
                    ios_fixup_x18_for_return( bus_ctx );
                    return;
                }
                {
                    /* Split the refusals: a SIMD load/store is the suspect,
                     * anything else is a different animal and must not hide
                     * inside one undifferentiated "UNSUPPORTED" bucket. */
                    int is_simd = (a_insn >> 26) & 1;
                    unsigned long n = is_simd ? ++ua_simd_n : ++ua_other_n;
                    if (n <= 16 || (n % 4096) == 0)
                        ERR("[unaligned-guest] REFUSED-%s insn=0x%08x addr=%p pc=%p "
                            "(emu=%lu simd=%lu other=%lu) -- keeping 80000002 rev=ml498\n",
                            is_simd ? "SIMD" : "OTHER", a_insn, siginfo->si_addr, pc,
                            ua_emu_n, ua_simd_n, ua_other_n);
                }
            }
            /* readable target: genuine alignment fault — keep 80000002 so FEX's
             * unaligned-access backpatcher handles it; its NtContinueNative
             * resume is now honored natively (signal_set_full_context ml420) */
        }
    }

bus_fatal:
    /* iOS-Madeira ml612: IS THIS A FEX EMULATOR-STACK OVERFLOW? (items 2-4)
     *
     * ml611 froze the whole app for 11 minutes because this exact fault was
     * classified as STATUS_DATATYPE_MISALIGNMENT. CrBrowserMain ran off the
     * bottom of its 256KB emulator stack inside a recursive fextl::set tree
     * deleter (libarm64ecfex.dll+0x12c10, `stp x19,x20,[sp,#-0x20]!` — a 32-byte
     * frame, so ~8,000 levels), the bogus 80000002 was dispatched, nothing
     * handled it, and the thread exited owning a CodeInvalidationMutex reader.
     *
     * A red-black tree cannot be 8,000 deep, so the left-spine is cyclic or
     * corrupt. Two diagnostics run here, both bounded and both using
     * mach_vm_read_overwrite so a probe can never fault inside the fault:
     *
     *  (2) SAVED-LR SCAN. Every recursive frame stores x30 at frame+0x18. Learn
     *      the recursive LR from the innermost frame and walk up in 0x20 steps
     *      while it repeats; the FIRST DIFFERENT LR is the original call site,
     *      which names the corrupted container without guessing. (Frontend's
     *      per-thread sets are only a hypothesis — this is what settles it.)
     *
     *  (3) FLOYD CYCLE CHECK over node->left (offset 0), tortoise/hare rather
     *      than a visited set: allocation-free by construction, which matters
     *      when the thing under investigation is allocator corruption.
     *
     * ⛔ Do NOT "fix" this by enlarging the emulator stack — that only postpones
     * a traversal that does not terminate. */
    /* iOS-Madeira ml620 [tree-caller]: RUN THE RECURSIVE-CALLER SCAN ON THE *BUS* PATH.
     *
     * ml619 put this scan in segv_handler and it never fired. The failure arrives
     * as SIGBUS, not SIGSEGV: ml619's thread death was
     *   BUS pc=0x129caafa0 addr=0x71da87fff0 insn=0xa9be53f3
     * and 0x129caafa0 reverse-translates to libarm64ecfex+0x12fa0 — the ENTRY of
     * the recursive fextl::set<uint64_t> tree deleter, i.e. its own prologue push
     * running off the bottom of a stack.
     *
     * ml612's [stack-ovf] block below also missed it, because that one is gated on
     * [EmulatorStackLimit, EmulatorStackBase) and this is a GUEST stack. So this
     * scan is deliberately ungated by stack identity — the only gate is the
     * self-identifying frame shape.
     *
     * Every recursive frame is 32 bytes with the saved LR at frame+0x18, and each
     * stores the same LR (the instruction after the recursive `bl`, RVA 0x12fc0 /
     * 0x12c30 for the two instantiations). Walk while it repeats; the FIRST
     * DIFFERENT LR is the original callsite, which names WHICH of the five sets in
     * DecodeInstructionsAtEntry is corrupt. */
    {
        uint64_t bsp = (uint64_t)SP_sig(bus_ctx);
        uint64_t lr0 = 0, lr1 = 0;
        mach_vm_size_t rg = 0;
        int k0 = mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(bsp + 0x18),
                                         sizeof(lr0), (mach_vm_address_t)&lr0, &rg ) == KERN_SUCCESS;
        int k1 = mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(bsp + 0x38),
                                         sizeof(lr1), (mach_vm_address_t)&lr1, &rg ) == KERN_SUCCESS;
        if (k0 && k1 && lr0 && lr0 == lr1)
        {
            static unsigned long tc_n;
            unsigned long n = ++tc_n;
            if (n <= 8)
            {
                uint64_t f = bsp, caller = 0, cframe = 0;
                unsigned depth = 0;
                for (; depth < 65536; depth++, f += 0x20)
                {
                    uint64_t lr = 0;
                    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(f + 0x18),
                                                sizeof(lr), (mach_vm_address_t)&lr, &rg ) != KERN_SUCCESS)
                        break;
                    if (lr != lr0) { caller = lr; cframe = f; break; }
                }
                dprintf( 2, "[tree-caller] ml620 #%lu BUS-path recursive 32B frames: recursive_lr=0x%llx "
                            "depth=%u ORIGINAL CALLER=%s0x%llx frame=0x%llx fault=%p pc=%p sp=0x%llx%s\n",
                         n, (unsigned long long)lr0, depth,
                         caller ? "" : "<not reached> ", (unsigned long long)caller,
                         (unsigned long long)cframe, siginfo->si_addr, pc, (unsigned long long)bsp,
                         (depth >= 65536) ? "  (hit cap — caller NOT found, not absent)" : "" );
            }
        }
    }

    if (!is_exec_fault)
    {
        TEB *so_teb = NtCurrentTeb();
        CHPE_V2_CPU_AREA_INFO *so_area = so_teb ? so_teb->ChpeV2CpuAreaInfo : NULL;
        uint64_t slimit = so_area ? (uint64_t)so_area->EmulatorStackLimit : 0;
        uint64_t sbase  = so_area ? (uint64_t)so_area->EmulatorStackBase : 0;
        uint64_t fault  = (uint64_t)(uintptr_t)siginfo->si_addr;

        /* Just below the limit = ran off the bottom. One page of slack covers a
         * multi-register push that straddles the boundary. */
        if (slimit && fault < slimit && fault + 0x4000 >= slimit)
        {
            static unsigned long so_n;
            unsigned long n = ++so_n;
            uint64_t sp = SP_sig(bus_ctx);
            uint64_t node = REGn_sig(1, bus_ctx);   /* x1 = node argument at entry */
            /* Re-read the faulting instruction here: a_insn is scoped to the
             * alignment-emulation block above and is not live at bus_fatal. */
            unsigned int so_insn = 0;
            {
                mach_vm_size_t g = 0;
                mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(uintptr_t)pc,
                                        sizeof(so_insn), (mach_vm_address_t)&so_insn, &g );
            }

            dprintf( 2, "[stack-ovf] ml612 #%lu EMULATOR STACK EXHAUSTED tid=%04x pc=%p addr=0x%llx "
                        "sp=0x%llx stack=[0x%llx..0x%llx] used=%lluKB insn=0x%08x -- reclassifying "
                        "80000002 -> c00000fd (STATUS_STACK_OVERFLOW)\n",
                     n, so_teb ? (unsigned int)(ULONG_PTR)so_teb->ClientId.UniqueThread : 0,
                     pc, (unsigned long long)fault, (unsigned long long)sp,
                     (unsigned long long)slimit, (unsigned long long)sbase,
                     (unsigned long long)((sbase > sp ? sbase - sp : 0) >> 10), so_insn );

            if (n <= 4)
            {
                /* (2) saved-LR scan */
                uint64_t f = sp, recur_lr = 0;
                unsigned depth = 0;
                for (; depth < 4096 && f + 0x20 <= sbase; depth++, f += 0x20)
                {
                    uint64_t lr = 0;
                    mach_vm_size_t got = 0;
                    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(f + 0x18),
                                                sizeof(lr), (mach_vm_address_t)&lr, &got ) != KERN_SUCCESS
                        || got != sizeof(lr))
                        break;
                    if (!depth) { recur_lr = lr; continue; }
                    if (lr != recur_lr)
                    {
                        dprintf( 2, "[stack-ovf] ml612   ORIGINAL CALLER after %u recursive frames: "
                                    "lr=0x%llx (recursive lr=0x%llx, frame=0x%llx) — this names the "
                                    "container being destroyed\n",
                                 depth, (unsigned long long)lr,
                                 (unsigned long long)recur_lr, (unsigned long long)f );
                        break;
                    }
                }
                if (depth >= 4096)
                    dprintf( 2, "[stack-ovf] ml612   scan hit the 4096-frame cap with lr still "
                                "0x%llx — caller not reached (cap, not absence)\n",
                             (unsigned long long)recur_lr );

                /* (3) Floyd cycle detection over node->left */
                {
                    uint64_t slow = node, fast = node;
                    unsigned steps = 0;
                    int cyclic = 0, readfail = 0;
                    while (steps < 100000 && slow && fast)
                    {
                        uint64_t a = 0, b = 0, c = 0;
                        mach_vm_size_t g = 0;
                        if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)slow,
                                                    sizeof(a), (mach_vm_address_t)&a, &g ) != KERN_SUCCESS)
                        { readfail = 1; break; }
                        if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)fast,
                                                    sizeof(b), (mach_vm_address_t)&b, &g ) != KERN_SUCCESS || !b)
                        { break; }
                        if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)b,
                                                    sizeof(c), (mach_vm_address_t)&c, &g ) != KERN_SUCCESS || !c)
                        { break; }
                        slow = a; fast = c; steps++;
                        if (slow && slow == fast) { cyclic = 1; break; }
                    }
                    dprintf( 2, "[stack-ovf] ml612   left-spine: node=0x%llx %s after %u steps%s\n",
                             (unsigned long long)node,
                             cyclic ? "*** CYCLE CONFIRMED ***" : (readfail ? "unreadable link" : "no cycle found"),
                             steps, (steps >= 100000) ? " (hit 100k cap — inconclusive, not clean)" : "" );
                }

                /* Fixed-size preview of the first links, no container involved. */
                {
                    uint64_t links[4] = {0, 0, 0, 0};
                    mach_vm_size_t g = 0;
                    if (node && mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)node,
                                                        sizeof(links), (mach_vm_address_t)links, &g ) == KERN_SUCCESS)
                        dprintf( 2, "[stack-ovf] ml612   node[0..3] left=0x%llx right=0x%llx "
                                    "parent=0x%llx +0x18=0x%llx\n",
                                 (unsigned long long)links[0], (unsigned long long)links[1],
                                 (unsigned long long)links[2], (unsigned long long)links[3] );
                }
            }

            rec.ExceptionCode = 0xC00000FDu; /* STATUS_STACK_OVERFLOW */
            rec.NumberParameters = 2;
            rec.ExceptionInformation[0] = 1; /* write */
            rec.ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
            /* Falls through to setup_exception below; the is_exec_fault branch
             * cannot fire here because this whole block is !is_exec_fault. */
        }
    }

    if (is_exec_fault)
    {
        /* ml345: an instruction-fetch abort on a readable-but-NX page arrives
         * as SIGBUS (KERN_PROTECTION_FAILURE), but it is an EXECUTE access
         * violation, not a data-alignment fault. Raising 80000002 here sent
         * FEX's unaligned-atomic handler decoding DATA bytes at the bogus pc
         * as atomics (ml344 "Unhandled non-JIT atomic" death). */
        rec.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
        rec.NumberParameters = 2;
        rec.ExceptionInformation[0] = EXCEPTION_EXECUTE_FAULT;
        rec.ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
    }
    { static unsigned long ml1055_bus; unsigned long k = __sync_add_and_fetch( &ml1055_bus, 1 );   /* 20,764 lines a run */
      if (k <= 40 || !(k % 1000)) ERR("BUS at pc=%p addr=%p exec=%d (#%lu, sampled) rev=ml345\n", pc, siginfo->si_addr, is_exec_fault, k); }
#endif
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		trap_handler
 *
 * Handler for SIGTRAP.
 */
static void trap_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { 0 };
    ucontext_t *context = sigcontext;
    CONTEXT ctx;
#ifdef WINE_IOS
    /* StikDebug protocol BRK #0xf00d with no debugger left to catch it —
     * e.g. the detach BRK re-executing after StikDebug lets go, on a
     * TEB-less app thread. Check at ENTRY, before any si_code dispatch:
     * iOS delivers BRK-derived SIGTRAPs with varying si_code, and letting
     * this fall into the wine exception path wedges the thread inside
     * nested fault logging (2026-07-06). Skip the insn, x0=0 (failure). */
    if (!(PC_sig( context ) & 3) && *(ULONG *)PC_sig( context ) == 0xd43e01a0)
    {
        dprintf(2, "[brk-f00d] skipped stray StikDebug BRK at pc=%p (si_code=%d)\n",
                (void *)PC_sig( context ), siginfo->si_code);
        REGn_sig( 0, context ) = 0;
        PC_sig( context ) += 4;
        return;
    }
    /* ml481 (#85): a BRK/trap raised by HOST code on a host thread (ml480: the
     * UI thread trapping inside libsystem_malloc) is never a guest exception —
     * adopting it wedged the app. Check before any logging or save_context. */
    if (ios_fault_is_foreign( (void *)PC_sig( context ), siginfo->si_addr ))
    {
        ios_decline_foreign_fault( signal, (void *)PC_sig( context ), siginfo->si_addr );
        return;
    }
    ios_track_signal( signal, context );
#endif

    rec.ExceptionAddress = (void *)PC_sig(context);
    save_context( &ctx, sigcontext );

    switch (siginfo->si_code)
    {
    case TRAP_TRACE:
        rec.ExceptionCode = EXCEPTION_SINGLE_STEP;
        break;
    case TRAP_BRKPT:
        /* debug exceptions do not update ESR on Linux, so we fetch the instruction directly. */
        if (!(PSTATE_sig( context ) & 0x10) && /* AArch64 (not WoW) */
            !(PC_sig( context ) & 3))
        {
            ULONG imm = (*(ULONG *)PC_sig( context ) >> 5) & 0xffff;
            switch (imm)
            {
            case 0xf00d:
                /* StikDebug JIT-protocol BRK (detach/prepare_region) with no
                 * debugger left to catch it — e.g. the detach BRK re-executes
                 * after StikDebug lets go, on a TEB-less app thread. This is
                 * an app-side handshake, never a guest exception: skip the
                 * insn, report failure in x0, and get out before any wine
                 * exception machinery (which wedged the detach thread inside
                 * dbg logging, 2026-07-06). */
                REGn_sig( 0, context ) = 0;
                PC_sig( context ) += 4;
                return;
            case 0xf000:
                ctx.Pc += 4;  /* skip the brk instruction */
                rec.ExceptionCode = EXCEPTION_BREAKPOINT;
                rec.NumberParameters = 1;
                break;
            case 0xf001:
                rec.ExceptionCode = STATUS_ASSERTION_FAILURE;
                break;
            case 0xf003:
                rec.ExceptionCode = STATUS_STACK_BUFFER_OVERRUN;
                rec.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
                rec.NumberParameters = 1;
                rec.ExceptionInformation[0] = ctx.X[0];
                NtRaiseException( &rec, &ctx, FALSE );
                break;
            case 0xf004:
                rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
                break;
            default:
                rec.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
                break;
            }
        }
        break;
    default:
        rec.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
        break;
    }

    setup_raise_exception( sigcontext, &rec, &ctx );
}

/**********************************************************************
 *		fpe_handler
 *
 * Handler for SIGFPE.
 */
static void fpe_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { 0 };
#ifdef WINE_IOS
    ios_track_signal( signal, sigcontext );
#endif

    switch (siginfo->si_code & 0xffff )
    {
#ifdef FPE_FLTSUB
    case FPE_FLTSUB:
        rec.ExceptionCode = EXCEPTION_ARRAY_BOUNDS_EXCEEDED;
        break;
#endif
#ifdef FPE_INTDIV
    case FPE_INTDIV:
        rec.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_INTOVF
    case FPE_INTOVF:
        rec.ExceptionCode = EXCEPTION_INT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTDIV
    case FPE_FLTDIV:
        rec.ExceptionCode = EXCEPTION_FLT_DIVIDE_BY_ZERO;
        break;
#endif
#ifdef FPE_FLTOVF
    case FPE_FLTOVF:
        rec.ExceptionCode = EXCEPTION_FLT_OVERFLOW;
        break;
#endif
#ifdef FPE_FLTUND
    case FPE_FLTUND:
        rec.ExceptionCode = EXCEPTION_FLT_UNDERFLOW;
        break;
#endif
#ifdef FPE_FLTRES
    case FPE_FLTRES:
        rec.ExceptionCode = EXCEPTION_FLT_INEXACT_RESULT;
        break;
#endif
#ifdef FPE_FLTINV
    case FPE_FLTINV:
#endif
    default:
        rec.ExceptionCode = EXCEPTION_FLT_INVALID_OPERATION;
        break;
    }
    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		int_handler
 *
 * Handler for SIGINT.
 */
static void int_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    HANDLE handle;
#ifdef WINE_IOS
    ios_track_signal( signal, sigcontext );
#endif

    if (!p__wine_ctrl_routine)
    {
#ifdef WINE_IOS
        ios_fixup_x18_for_return( sigcontext );
#endif
        return;
    }
    if (!NtCreateThreadEx( &handle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
                           p__wine_ctrl_routine, 0 /* CTRL_C_EVENT */, 0, 0, 0, 0, NULL ))
        NtClose( handle );
#ifdef WINE_IOS
    ios_fixup_x18_for_return( sigcontext );
#endif
}


/**********************************************************************
 *		abrt_handler
 *
 * Handler for SIGABRT.
 */
static void abrt_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_WINE_ASSERTION, EXCEPTION_NONCONTINUABLE };
#ifdef WINE_IOS
    /* ml784 (#85 again): SIGABRT is raised by HOST code too, and this handler
     * adopted it unconditionally.
     *
     * A SwiftUI AttributeGraph precondition failure called abort() on the UI
     * thread; abrt_handler treated it as a guest exception, and
     * ios_log_guest_exception then faulted on a thread with no TEB -- so the
     * crash report blamed our handler and the framework's own reason was never
     * printed. Same rule the other handlers already follow: only adopt faults
     * that belong to the emulated world.
     *
     * si_addr is meaningless for SIGABRT, so foreign-ness is judged on the PC
     * alone; a guest abort still comes from the pool or a guest band. */
    if (ios_fault_is_foreign( (void *)PC_sig( (ucontext_t *)sigcontext ), NULL ))
    {
        ios_decline_foreign_fault( signal, (void *)PC_sig( (ucontext_t *)sigcontext ), NULL );
        return;
    }
    ios_track_signal( signal, sigcontext );
#endif
    setup_exception( sigcontext, &rec );
}


#ifdef WINE_IOS
/* iOS-Madeira ml483 (#87): the thread-control handlers (SIGQUIT/USR1/USR2) all
 * reach ntdll_get_thread_data() — get_syscall_frame() reads TEB+0x378 and
 * is_inside_syscall() reads TEB+kernel_stack — on their FIRST statement, before
 * any check. Threads created directly by CEF/FEX have no TEB (NtCurrentTeb()
 * unix-side is the pthread key `ios_teb_tls_key`), so a signal landing on one
 * dereferences NULL. ml482's run died exactly there: SEGV #1 pc=usr2_handler+0x20
 * addr=0x378, insn `ldr x21,[x0,#0x378]` with x0=0 straight after the
 * NtCurrentTeb() call. These signals mean "suspend / set your context / quit" —
 * all no-ops for a thread wine does not manage — so bail out instead.
 * Async-signal-safe: pthread_getspecific only, no allocation. */
static int ios_thread_ctl_has_teb( void )
{
    return NtCurrentTeb() != NULL;
}
#endif

/**********************************************************************
 *		quit_handler
 *
 * Handler for SIGQUIT.
 */
static void quit_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    ucontext_t *context = sigcontext;
#ifdef WINE_IOS
    ios_track_signal( signal, context );
    if (!ios_thread_ctl_has_teb())
    {
        static int noteb_quit;
        if (noteb_quit < 4) { noteb_quit++;
            dprintf( 2, "[sig-noteb] SIGQUIT on a TEB-less thread — ignoring rev=ml483\n" ); }
        return;
    }
#endif
    if (!is_inside_syscall( SP_sig(context) )) user_mode_abort_thread( 0, get_syscall_frame() );
    abort_thread(0);
}


/**********************************************************************
 *		usr1_handler
 *
 * Handler for SIGUSR1, used to signal a thread that it got suspended.
 */
static void usr1_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    ucontext_t *ucontext = sigcontext;
    CONTEXT context;
#ifdef WINE_IOS
    ios_track_signal( signal, ucontext );
    if (!ios_thread_ctl_has_teb())      /* ml483 (#87) — see ios_thread_ctl_has_teb */
    {
        static int noteb_usr1;
        if (noteb_usr1 < 4) { noteb_usr1++;
            dprintf( 2, "[sig-noteb] SIGUSR1 (suspend) on a TEB-less thread — ignoring rev=ml483\n" ); }
        return;
    }
#endif
    if (is_inside_syscall( SP_sig(ucontext) ))
    {
        context.ContextFlags = CONTEXT_FULL | CONTEXT_EXCEPTION_REQUEST;
        NtGetContextThread( GetCurrentThread(), &context );
        wait_suspend( &context );
        NtSetContextThread( GetCurrentThread(), &context );
    }
    else
    {
        save_context( &context, ucontext );
        context.ContextFlags |= CONTEXT_EXCEPTION_REPORTING;
        wait_suspend( &context );
        restore_context( &context, ucontext );
#ifdef WINE_IOS
        ios_fixup_x18_for_return( ucontext );
#endif
    }
}


/**********************************************************************
 *		usr2_handler
 *
 * Handler for SIGUSR2, used to set a thread context.
 */
static void usr2_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
#ifdef WINE_IOS
    struct syscall_frame *frame;     /* ml483 (#87): fetched only after the TEB
                                      * check below — reading TEB+0x378 here is
                                      * what killed the ml482 run. */
#else
    struct syscall_frame *frame = get_syscall_frame();
#endif
    ucontext_t *context = sigcontext;
    DWORD i;
#ifdef WINE_IOS
    ios_track_signal( signal, context );
    if (!ios_thread_ctl_has_teb())
    {
        static int noteb_usr2;
        if (noteb_usr2 < 4) { noteb_usr2++;
            dprintf( 2, "[sig-noteb] SIGUSR2 (set-context) on a TEB-less thread — ignoring rev=ml483\n" ); }
        return;
    }
    frame = get_syscall_frame();
#endif

    if (!is_inside_syscall( SP_sig(context) ))
    {
#ifdef WINE_IOS
        ios_fixup_x18_for_return( context );
#endif
        return;
    }

    FP_sig(context)     = frame->fp;
    LR_sig(context)     = frame->lr;
    SP_sig(context)     = frame->sp;
    PC_sig(context)     = frame->pc;
    PSTATE_sig(context) = frame->cpsr;
    for (i = 0; i <= 28; i++) REGn_sig( i, context ) = frame->x[i];

#ifdef linux
    {
        struct fpsimd_context *fp = get_fpsimd_context( sigcontext );
        if (fp)
        {
            fp->fpcr = frame->fpcr;
            fp->fpsr = frame->fpsr;
            memcpy( fp->vregs, frame->v, sizeof(fp->vregs) );
        }
    }
#elif defined(__APPLE__)
    context->uc_mcontext->__ns.__fpcr = frame->fpcr;
    context->uc_mcontext->__ns.__fpsr = frame->fpsr;
    memcpy( context->uc_mcontext->__ns.__v, frame->v, sizeof(frame->v) );
#endif
}


/**********************************************************************
 *           get_thread_ldt_entry
 */
NTSTATUS get_thread_ldt_entry( HANDLE handle, THREAD_DESCRIPTOR_INFORMATION *info, ULONG len )
{
    return STATUS_NOT_IMPLEMENTED;
}


