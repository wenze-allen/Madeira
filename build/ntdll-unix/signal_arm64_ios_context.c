/* Part of signal_arm64_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Thread contexts. Same copyright and licence as signal_arm64_ios.c. */
/***********************************************************************
 *           context_init_empty_xstate
 *
 * Initializes a context's CONTEXT_EX structure to point to an empty xstate buffer
 */
static inline void context_init_empty_xstate( CONTEXT *context, void *xstate_buffer )
{
    CONTEXT_EX *xctx;

    xctx = (CONTEXT_EX *)(context + 1);
    xctx->Legacy.Length = sizeof(CONTEXT);
    xctx->Legacy.Offset = -(LONG)sizeof(CONTEXT);
    xctx->XState.Length = 0;
    xctx->XState.Offset = (BYTE *)xstate_buffer - (BYTE *)xctx;
    xctx->All.Length = sizeof(CONTEXT) + xctx->XState.Offset + xctx->XState.Length;
    xctx->All.Offset = -(LONG)sizeof(CONTEXT);
}

void set_process_instrumentation_callback( void *callback )
{
    if (callback) FIXME( "Not supported.\n" );
}


/***********************************************************************
 *           syscall_frame_fixup_for_fastpath
 *
 * Fixes up the given syscall frame such that the syscall dispatcher
 * can return via the fast path if CONTEXT_INTEGER is set in
 * restore_flags.
 *
 * Clobbers the frame's X16 and X17 register values.
 */
static void syscall_frame_fixup_for_fastpath( struct syscall_frame *frame )
{
    frame->x[16] = frame->pc;
    frame->x[17] = frame->sp;
}

/***********************************************************************
 *           save_fpu
 *
 * Set the FPU context from a sigcontext.
 */
static void save_fpu( CONTEXT *context, const ucontext_t *sigcontext )
{
#ifdef linux
    struct fpsimd_context *fp = get_fpsimd_context( sigcontext );

    if (!fp) return;
    context->ContextFlags |= CONTEXT_FLOATING_POINT;
    context->Fpcr = fp->fpcr;
    context->Fpsr = fp->fpsr;
    memcpy( context->V, fp->vregs, sizeof(context->V) );
#elif defined(__APPLE__)
    context->ContextFlags |= CONTEXT_FLOATING_POINT;
    context->Fpcr = sigcontext->uc_mcontext->__ns.__fpcr;
    context->Fpsr = sigcontext->uc_mcontext->__ns.__fpsr;
    memcpy( context->V, sigcontext->uc_mcontext->__ns.__v, sizeof(context->V) );
#endif
}


/***********************************************************************
 *           restore_fpu
 *
 * Restore the FPU context to a sigcontext.
 */
static void restore_fpu( const CONTEXT *context, ucontext_t *sigcontext )
{
#ifdef linux
    struct fpsimd_context *fp = get_fpsimd_context( sigcontext );

    if (!fp) return;
    fp->fpcr = context->Fpcr;
    fp->fpsr = context->Fpsr;
    memcpy( fp->vregs, context->V, sizeof(fp->vregs) );
#elif defined(__APPLE__)
    sigcontext->uc_mcontext->__ns.__fpcr = context->Fpcr;
    sigcontext->uc_mcontext->__ns.__fpsr = context->Fpsr;
    memcpy( sigcontext->uc_mcontext->__ns.__v, context->V, sizeof(context->V) );
#endif
}


/***********************************************************************
 *           save_context
 *
 * Set the register values from a sigcontext.
 */
static void save_context( CONTEXT *context, const ucontext_t *sigcontext )
{
    DWORD i;

    context->ContextFlags = CONTEXT_FULL;
    context->Fp   = FP_sig(sigcontext);     /* Frame pointer */
    context->Lr   = LR_sig(sigcontext);     /* Link register */
    context->Sp   = SP_sig(sigcontext);     /* Stack pointer */
    context->Pc   = PC_sig(sigcontext);     /* Program Counter */
    context->Cpsr = PSTATE_sig(sigcontext); /* Current State Register */
    for (i = 0; i <= 28; i++) context->X[i] = REGn_sig( i, sigcontext );
    save_fpu( context, sigcontext );
}


/***********************************************************************
 *           restore_context
 *
 * Build a sigcontext from the register values.
 */
static void restore_context( const CONTEXT *context, ucontext_t *sigcontext )
{
    DWORD i;

    FP_sig(sigcontext)     = context->Fp;   /* Frame pointer */
    LR_sig(sigcontext)     = context->Lr;   /* Link register */
    SP_sig(sigcontext)     = context->Sp;   /* Stack pointer */
    PC_sig(sigcontext)     = context->Pc;   /* Program Counter */
    PSTATE_sig(sigcontext) = context->Cpsr; /* Current State Register */
    for (i = 0; i <= 28; i++) REGn_sig( i, sigcontext ) = context->X[i];
    restore_fpu( context, sigcontext );
}


/***********************************************************************
 *           signal_set_full_context
 */
NTSTATUS signal_set_full_context( CONTEXT *context )
{
    extern int ios_is_arm64ec_cur(void);
    struct syscall_frame *frame = get_syscall_frame();
    ULONG_PTR ml944_req_pc = context->Pc, ml944_req_sp = context->Sp;
    DWORD ml944_req_flags = context->ContextFlags;
    NTSTATUS status = NtSetContextThread( GetCurrentThread(), context );

    if (!status && (context->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER)
        frame->restore_flags |= CONTEXT_INTEGER;

    /* iOS-Madeira diag (Thumper desktop ILL): the crash pc is entered with no
     * branch/register/immediate trail = a context restore. Log every resume
     * targeting the FEX tail-carve region (top 128MB of the pool) whose
     * first word is a data-word/NOP — plus the is_ec_code verdict, since
     * non-EC resumes get bounced through KiUserEmulationDispatcher. */
    {
        extern void *ios_jit_rx_base_global;
        extern size_t ios_jit_pool_size_global;
        uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
        size_t psz = ios_jit_pool_size_global;
        if (rx && psz && frame->pc >= rx + psz / 2 && frame->pc < rx + psz)
        {
            uint32_t w = *(uint32_t *)frame->pc;
            if ((w >> 16) == 0 || w == 0xd503201fu)
                dprintf(2, "[set-ctx] SUSPICIOUS resume: pc=%p first_insn=0x%08x is_ec=%d lr=%p sp=%p (Pc from context=%p)\n",
                        (void *)frame->pc, w, is_ec_code( frame->pc ),
                        (void *)frame->lr, (void *)frame->sp, (void *)context->Pc);
        }
    }

    /* ml945: PROBE THE DECISION, NOT THE BRANCH.
     *
     * ml944 put this inside the KiUserEmulationDispatcher bounce below. The
     * bounce was taken 0 times out of 60 VEH continues, so the probe was
     * silent and the run produced nothing -- I had gated the instrument on the
     * hypothesis it was meant to test. Log the inputs to the decision instead,
     * unconditionally, so a wrong hypothesis still yields data.
     *
     * Context: an anti-tamper VEH returns EXCEPTION_CONTINUE_EXECUTION with
     * Rip = <its own dll>+0x37ce0 (a valid address) and the guest resumes with
     * RIP 0, which CompileBlock then refuses 2001 times while the VEH
     * re-enters, until the [redeliv] guard kills the pseudo-process.
     *
     * What each field settles:
     *   req_*      -- did the modified Rip survive the PE-side conversion?
     *   frame pc   -- did NtSetContextThread(self) actually apply it? If this
     *                 is native EC code rather than the requested guest Rip,
     *                 CONTEXT_CONTROL was missing or self-set does not write pc.
     *   is_ec/cur  -- which way the branch below goes, and why.
     * Capped; every resume passes here, so this must stay cheap. */
    {
        /* ml946: DEDUPE BY THE VALUE THIS IS ABOUT, not a flat shot cap.
         *
         * ml945's 24-shot budget was spent by log line 1547; the resume I need
         * is at line 5571. 22 of the 24 were the SAME req pc (0xf93d763f0 —
         * thread-start resumes on ARM64 pseudo-processes, where ec_cur=0 is
         * correct and uninteresting). A flat cap samples whatever happens
         * first, which for a hot path is never the rare event. Keyed on req pc
         * instead: each distinct resume target gets exactly one line, so a
         * thousand identical thread starts cost one slot and the VEH's
         * continue target is guaranteed a slot.
         *
         * ⛔ Do not "fix" this by raising a flat cap -- that is what failed. */
        static ULONG_PTR ml946_seen[48];
        static int ml946_n;
        int ml946_i, ml946_dup = 0;

        for (ml946_i = 0; ml946_i < ml946_n; ml946_i++)
            if (ml946_seen[ml946_i] == ml944_req_pc) { ml946_dup = 1; break; }
        if (!ml946_dup && ml946_n < (int)(sizeof(ml946_seen)/sizeof(ml946_seen[0])))
        {
            ml946_seen[ml946_n++] = ml944_req_pc;
            dprintf( 2, "[set-ctx] ml946 distinct#%d tid=%04x req pc=%p sp=%p flags=%08x status=%08x | "
                     "frame pc=%p sp=%p | is_ec(frame.pc)=%d ec_cur=%d\n",
                     ml946_n,
                     (unsigned int)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
                     (void *)ml944_req_pc, (void *)ml944_req_sp,
                     (unsigned int)ml944_req_flags, (unsigned int)status,
                     (void *)frame->pc, (void *)frame->sp,
                     is_ec_code( frame->pc ), ios_is_arm64ec_cur() );
        }
    }

    if (ios_is_arm64ec_cur() && !is_ec_code( frame->pc ))   /* owner-aware (X3) */
    {
        /* iOS-Madeira ml420 (#69, ml419 root cause): the EcCodeBitMap only covers
         * PE space (#52), so a resume targeting the JIT pool — FEX's
         * NtContinueNative after handling a fault host-side ("Handled unaligned
         * atomic"), with Pc = the faulting host instruction — fails is_ec_code
         * and gets bounced through KiUserEmulationDispatcher, which installs the
         * HOST pc as the guest Rip (context_arm_to_x64 maps Pc→Rip verbatim).
         * The guest then "executes" FEX's own emitted code: xquery MISS → NoExec
         * trap → c0000005 (ml419 tid 0110, rip=0x155340848). Pool addresses only
         * ever hold ARM64 code (image copies + FEX emission) — a guest x64 RIP
         * is never a pool address — so any pool-pc resume is a NATIVE resume. */
        extern void *ios_jit_rx_base_global;
        extern size_t ios_jit_pool_size_global;
        uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
        size_t psz = ios_jit_pool_size_global;

        /* madeira-bcd pool-low: FEX's code buffers in region C are pool code
         * too -- a resume there bounced through the emulation dispatcher would
         * make the guest "execute" FEX's own code. */
        if ((rx && psz && frame->pc >= rx && frame->pc < rx + psz) ||
            ios_jit_low_contains( (uintptr_t)frame->pc ))
        {
            static int bounce_saved;
            if (bounce_saved < 16 && ++bounce_saved <= 16)
                ERR( "[ec-bounce-pool] native resume kept for pool pc=%p (off=0x%lx) lr=%p — "
                     "was: KiUserEmulationDispatcher bounce = guest executes host code\n",
                     (void *)frame->pc, (unsigned long)(frame->pc - rx), (void *)frame->lr );
        }
        else
        {
            CONTEXT *user_context = (CONTEXT *)((frame->sp - sizeof(CONTEXT)) & ~15);

            user_context->ContextFlags = CONTEXT_FULL;
            NtGetContextThread( GetCurrentThread(), user_context );
            /* ml944: WHERE DOES A GUEST-RIP RESUME LOSE ITS RIP?
             *
             * A VEH that returns EXCEPTION_CONTINUE_EXECUTION with a modified
             * Rip reaches here: the requested Pc is x64 guest code, so
             * is_ec_code() is correctly false and we bounce through
             * KiUserEmulationDispatcher, which reads the context from SP,
             * maps Pc->Rip and calls BeginSimulation. Measured once: an
             * anti-tamper VEH asked to continue at EMP.dll+0x37ce0 -- a valid
             * address -- and the guest resumed with RIP 0, which our
             * CompileBlock guard then refused 2001 times while the VEH
             * re-entered, until the [redeliv] guard killed the process.
             *
             * Reading the path statically did not settle it: the requested Pc
             * is written into the frame by NtSetContextThread and read back by
             * NtGetContextThread, and context_arm_to_x64 maps Pc->Rip
             * verbatim, so every hop looks correct. So measure each hop
             * instead of reasoning about it. If the Pc is still right at
             * `handoff` below, the loss is inside dispatch_emulation /
             * BeginSimulation; if it is already wrong, this names which hop.
             *
             * Gated to the bounce path and capped, so it costs a normal resume
             * nothing. */
            {
                static int ml944_shots;
                if (ml944_shots < 12)
                {
                    ml944_shots++;
                    /* ml947: the handoff Pc is CORRECT (measured, 12/12), so the
                     * RIP is lost downstream in dispatch_emulation ->
                     * context_arm_to_x64 -> pBeginSimulation. dispatch_emulation
                     * writes into get_arm64ec_cpu_area()->ContextAmd64 and then
                     * starts simulation from it, so a wrong TEB at this moment
                     * means the context lands in the wrong CPU area and
                     * simulation begins from a stale Rip -- which would be 0.
                     * This thread has repeatedly shown x18=0 and "no TEB owns
                     * sp", so check it. TEB+0x1788 = ChpeV2CpuAreaInfo,
                     * CpuArea+0x18 = ContextAmd64, +0xf8 = its Rip (the field
                     * BeginSimulation resumes from). Cross-check cpuarea
                     * against the [cpu-area] line logged for this tid. */
                    {
                        TEB *t = NtCurrentTeb();
                        void *cpuarea = t ? *(void **)((char *)t + 0x1788) : NULL;
                        void *ctx64 = cpuarea ? *(void **)((char *)cpuarea + 0x18) : NULL;
                        unsigned long long ctx64_rip = 0;
                        int ctx64_ok = 0;

                        if (ctx64)
                        {
                            mach_vm_size_t got = 0;
                            ctx64_ok = (mach_vm_read_overwrite( mach_task_self(),
                                            (mach_vm_address_t)((char *)ctx64 + 0xf8), 8,
                                            (mach_vm_address_t)&ctx64_rip, &got ) == KERN_SUCCESS
                                        && got == 8);
                        }
                        dprintf( 2, "[ec-bounce] ml947 #%d teb=%p cpuarea=%p ContextAmd64=%p "
                                 "its_Rip=%s%llx\n",
                                 ml944_shots, (void *)t, cpuarea, ctx64,
                                 ctx64_ok ? "0x" : "UNREADABLE 0x",
                                 (unsigned long long)ctx64_rip );
                    }
                    dprintf( 2, "[ec-bounce] ml944 #%d requested pc=%p sp=%p flags=%08x | "
                             "frame pc=%p sp=%p | handoff ctx=%p pc=%p sp=%p flags=%08x | is_ec=%d\n",
                             ml944_shots, (void *)ml944_req_pc, (void *)ml944_req_sp,
                             (unsigned int)ml944_req_flags,
                             (void *)frame->pc, (void *)frame->sp,
                             (void *)user_context, (void *)user_context->Pc,
                             (void *)user_context->Sp,
                             (unsigned int)user_context->ContextFlags,
                             is_ec_code( frame->pc ) );
                }
            }
            frame->sp = (ULONG_PTR)user_context;
            frame->pc = (ULONG_PTR)IOS_PFUNC(KiUserEmulationDispatcher);
        }
    }
    return status;
}


/***********************************************************************
 *              get_native_context
 */
void *get_native_context( CONTEXT *context )
{
    return context;
}


/***********************************************************************
 *              get_wow_context
 */
void *get_wow_context( CONTEXT *context )
{
    /* Owner-aware (X3): the CPU area machine follows the current thread's
     * pseudo-process, not the session's main exe. */
    extern const SECTION_IMAGE_INFORMATION *ios_cur_image_info(void);
    return get_cpu_area( ios_cur_image_info()->Machine );
}


/***********************************************************************
 *              NtSetContextThread  (NTDLL.@)
 *              ZwSetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetContextThread( HANDLE handle, const CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    NTSTATUS ret = STATUS_SUCCESS;
    BOOL self = (handle == GetCurrentThread());
    DWORD flags = context->ContextFlags & ~CONTEXT_ARM64;

    if (self && (flags & CONTEXT_DEBUG_REGISTERS)) self = FALSE;

    /* iOS-Madeira diag: companion to [set-ctx] in signal_set_full_context —
     * catch cross-thread PC rewrites into the FEX tail carve that land on
     * data words (suspend/invalidate machinery redirecting threads). */
    if (flags & CONTEXT_CONTROL)
    {
        extern void *ios_jit_rx_base_global;
        extern size_t ios_jit_pool_size_global;
        uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
        size_t psz = ios_jit_pool_size_global;
        if (rx && psz && context->Pc >= rx + psz / 2 && context->Pc < rx + psz)
        {
            uint32_t w = *(uint32_t *)context->Pc;
            if ((w >> 16) == 0 || w == 0xd503201fu)
                dprintf(2, "[set-ctx] SUSPICIOUS NtSetContextThread: self=%d pc=%p first_insn=0x%08x lr=%p\n",
                        self, (void *)context->Pc, w, (void *)context->Lr);
        }
    }

    if (!self)
    {
        ret = set_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_ARM64 );
        if (ret || !self) return ret;
    }

    if (flags & CONTEXT_INTEGER)
    {
        memcpy( frame->x, context->X, sizeof(context->X[0]) * 18 );
        /* skip x18 */
        memcpy( frame->x + 19, context->X + 19, sizeof(context->X[0]) * 10 );
    }
    if (flags & CONTEXT_CONTROL)
    {
        frame->fp    = context->Fp;
        frame->lr    = context->Lr;
        frame->sp    = context->Sp;
        frame->pc    = context->Pc;
        frame->cpsr  = context->Cpsr;
    }
    if (flags & CONTEXT_FLOATING_POINT)
    {
        frame->fpcr = context->Fpcr;
        frame->fpsr = context->Fpsr;
        memcpy( frame->v, context->V, sizeof(frame->v) );
    }
    if (flags & CONTEXT_ARM64_X18)
    {
        frame->x[18] = context->X[18];
    }
    if (flags & CONTEXT_DEBUG_REGISTERS) FIXME( "debug registers not supported\n" );
    frame->restore_flags |= flags & ~CONTEXT_INTEGER;
    return STATUS_SUCCESS;
}


/* A CROSS-THREAD CONTEXT WITHOUT ITS CONTROL REGISTERS.
 *
 * When the server has no native capture of the target it answers with the
 * integer registers only, and the ARM64EC wrapper hands an x64 caller
 * Rip = Rsp = 0 with no CONTEXT_CONTROL. Ghost of Tsushima's loading screen
 * froze on exactly that: one thread called GetThreadContext on another
 * thousands of times, getting rip 0 each time, while holding a critical
 * section the main thread waited on.
 *
 * The target's last x64 state is in its CPU area (ChpeV2CpuAreaInfo->
 * ContextAmd64, saved whenever it left emulated code). Its control registers
 * (Pc, Sp, Fp, Lr) are returned in the ARM64EC register mapping, which the
 * wrapper's context_arm_to_x64() turns back into x64 registers; X23/X28 are
 * cleared so the wrapper does not replace Pc/Sp with an emulator frame's. The
 * integer registers stay the server's. Threads of this process only: the TEB
 * pointer is read in this address space, through mach_vm_read_overwrite, so a
 * target that exits meanwhile cannot fault this thread.
 *
 * Opt-in, MADEIRA_CTX_CPU_AREA=1 (madeira.cfg env., or a game's own config):
 * the snapshot is the thread's last exit from emulated code, not where it is
 * now, so a caller that writes the context back (SetThreadContext, as a .NET
 * runtime redirecting a thread does) would move the thread back there.
 *
 * MADEIRA_CTX_CPU_AREA=2 also returns the snapshot's integer registers when the
 * caller asked for CONTEXT_INTEGER (the ARM64EC_NT_CONTEXT registers that hold
 * x64 state: X0-X12, X15, X19-X22 and X25-X27; the others are zeroed) and sets
 * Cpsr to 0, so the caller gets one x64 state from a single moment instead of
 * the snapshot's control registers next to the server's integer registers.
 * madeira-bcd has run this form by default since its build 213 (2026-09-28),
 * and its game lists were tested with it. */
static int ctx_peek( void *dst, const void *src, size_t size )
{
    mach_vm_size_t got = 0;
    return src && mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(uintptr_t)src, size,
                                          (mach_vm_address_t)(uintptr_t)dst, &got ) == KERN_SUCCESS && got == size;
}

static int get_context_from_amd64_area( HANDLE handle, CONTEXT *context, DWORD needed )
{
    static int on = -1;
    THREAD_BASIC_INFORMATION tbi;
    const TEB *teb;
    const CHPE_V2_CPU_AREA_INFO *cpu = NULL;
    const ARM64EC_NT_CONTEXT *ecp = NULL;
    ARM64EC_NT_CONTEXT ec;
    static LONG said;

    if (on < 0)
    {
        /* For a cross-thread GetThreadContext without control registers. 1: the target's
         * Pc/Sp/Fp/Lr from its last exit from emulated code (upstream's opt-in). 2: also
         * X0-X12, X15, X19-X22, X25-X27 and Cpsr = 0 from the same snapshot (madeira-bcd's
         * behaviour). Default off: a context written back would rewind the thread. */
        const char *env = getenv( "MADEIRA_CTX_CPU_AREA" );
        on = !env ? 0 : env[0] == '1' ? 1 : env[0] == '2' ? 2 : 0;
    }
    if (!on) return 0;
    if (NtQueryInformationThread( handle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL )) return 0;
    if (tbi.ClientId.UniqueProcess != NtCurrentTeb()->ClientId.UniqueProcess) return 0;
    if (!(teb = tbi.TebBaseAddress)) return 0;
    if (!ctx_peek( &cpu, &teb->ChpeV2CpuAreaInfo, sizeof(cpu) ) || !cpu) return 0;
    if (!ctx_peek( &ecp, &cpu->ContextAmd64, sizeof(ecp) ) || !ecp) return 0;
    if (!ctx_peek( &ec, ecp, sizeof(ec) )) return 0;
    if (!ec.Pc || !ec.Sp) return 0;
    if (on == 2 && (needed & (CONTEXT_INTEGER & ~CONTEXT_ARM64)))
    {
        memset( context->X, 0, sizeof(context->X[0]) * 29 );
        context->X[0] = ec.X0;   context->X[1] = ec.X1;   context->X[2] = ec.X2;   context->X[3] = ec.X3;
        context->X[4] = ec.X4;   context->X[5] = ec.X5;   context->X[6] = ec.X6;   context->X[7] = ec.X7;
        context->X[8] = ec.X8;   context->X[9] = ec.X9;   context->X[10] = ec.X10; context->X[11] = ec.X11;
        context->X[12] = ec.X12; context->X[15] = ec.X15;
        context->X[19] = ec.X19; context->X[20] = ec.X20; context->X[21] = ec.X21; context->X[22] = ec.X22;
        context->X[25] = ec.X25; context->X[26] = ec.X26; context->X[27] = ec.X27;
        context->ContextFlags |= CONTEXT_INTEGER;
    }
    context->X[23] = context->X[28] = 0;
    context->Fp = ec.Fp;
    context->Lr = ec.Lr;
    context->Sp = ec.Sp;
    context->Pc = ec.Pc;
    if (on == 2) context->Cpsr = 0;
    context->ContextFlags |= CONTEXT_CONTROL;
    if (InterlockedIncrement( &said ) <= 8)
        ERR( "[ctx] get handle=%p: no control registers from the server; "
             "returning the target's saved x64 %s rip=%p rsp=%p (MADEIRA_CTX_CPU_AREA=%d)\n",
             handle, on == 2 ? "state" : "Pc/Sp/Fp/Lr", (void *)ec.Pc, (void *)ec.Sp, on );
    return 1;
}

/***********************************************************************
 *              NtGetContextThread  (NTDLL.@)
 *              ZwGetContextThread  (NTDLL.@)
 */
NTSTATUS WINAPI NtGetContextThread( HANDLE handle, CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    DWORD needed_flags = context->ContextFlags & ~CONTEXT_ARM64;
    BOOL self = (handle == GetCurrentThread());

    if (!self)
    {
        NTSTATUS ret = get_thread_context( handle, context, &self, IMAGE_FILE_MACHINE_ARM64 );
        if (!ret && !self && (needed_flags & CONTEXT_CONTROL & ~CONTEXT_ARM64) &&
            (!(context->ContextFlags & CONTEXT_CONTROL & ~CONTEXT_ARM64) || !context->Pc))
            get_context_from_amd64_area( handle, context, needed_flags );
        if (ret || !self) return ret;
    }

    if (needed_flags & CONTEXT_INTEGER)
    {
        memcpy( context->X, frame->x, sizeof(context->X[0]) * 29 );
        context->ContextFlags |= CONTEXT_INTEGER;
    }
    if (needed_flags & CONTEXT_CONTROL)
    {
        context->Fp   = frame->fp;
        context->Lr   = frame->lr;
        context->Sp   = frame->sp;
        context->Pc   = frame->pc;
        context->Cpsr = frame->cpsr;
        context->ContextFlags |= CONTEXT_CONTROL;
    }
    if (needed_flags & CONTEXT_FLOATING_POINT)
    {
        context->Fpcr = frame->fpcr;
        context->Fpsr = frame->fpsr;
        memcpy( context->V, frame->v, sizeof(context->V) );
        context->ContextFlags |= CONTEXT_FLOATING_POINT;
    }
    if (needed_flags & CONTEXT_DEBUG_REGISTERS) FIXME( "debug registers not supported\n" );
    set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              set_thread_wow64_context
 */
NTSTATUS set_thread_wow64_context( HANDLE handle, const void *ctx, ULONG size )
{
    BOOL self = (handle == GetCurrentThread());
    USHORT machine;
    void *frame;

    switch (size)
    {
    case sizeof(I386_CONTEXT): machine = IMAGE_FILE_MACHINE_I386; break;
    case sizeof(ARM_CONTEXT): machine = IMAGE_FILE_MACHINE_ARMNT; break;
    default: return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!self)
    {
        NTSTATUS ret = set_thread_context( handle, ctx, &self, machine );
        if (ret || !self) return ret;
    }

    if (!(frame = get_cpu_area( machine ))) return STATUS_INVALID_PARAMETER;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    {
        I386_CONTEXT *wow_frame = frame;
        const I386_CONTEXT *context = ctx;
        DWORD flags = context->ContextFlags & ~CONTEXT_i386;

        if (flags & CONTEXT_I386_INTEGER)
        {
            wow_frame->Eax = context->Eax;
            wow_frame->Ebx = context->Ebx;
            wow_frame->Ecx = context->Ecx;
            wow_frame->Edx = context->Edx;
            wow_frame->Esi = context->Esi;
            wow_frame->Edi = context->Edi;
        }
        if (flags & CONTEXT_I386_CONTROL)
        {
            WOW64_CPURESERVED *cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED];

            wow_frame->Esp    = context->Esp;
            wow_frame->Ebp    = context->Ebp;
            wow_frame->Eip    = context->Eip;
            wow_frame->EFlags = context->EFlags;
            wow_frame->SegCs  = context->SegCs;
            wow_frame->SegSs  = context->SegSs;
            cpu->Flags |= WOW64_CPURESERVED_FLAG_RESET_STATE;
        }
        if (flags & CONTEXT_I386_SEGMENTS)
        {
            wow_frame->SegDs = context->SegDs;
            wow_frame->SegEs = context->SegEs;
            wow_frame->SegFs = context->SegFs;
            wow_frame->SegGs = context->SegGs;
        }
        if (flags & CONTEXT_I386_DEBUG_REGISTERS)
        {
            wow_frame->Dr0 = context->Dr0;
            wow_frame->Dr1 = context->Dr1;
            wow_frame->Dr2 = context->Dr2;
            wow_frame->Dr3 = context->Dr3;
            wow_frame->Dr6 = context->Dr6;
            wow_frame->Dr7 = context->Dr7;
        }
        if (flags & CONTEXT_I386_EXTENDED_REGISTERS)
        {
            memcpy( &wow_frame->ExtendedRegisters, context->ExtendedRegisters, sizeof(context->ExtendedRegisters) );
        }
        if (flags & CONTEXT_I386_FLOATING_POINT)
        {
            memcpy( &wow_frame->FloatSave, &context->FloatSave, sizeof(context->FloatSave) );
        }
        /* FIXME: CONTEXT_I386_XSTATE */
        break;
    }

    case IMAGE_FILE_MACHINE_ARMNT:
    {
        ARM_CONTEXT *wow_frame = frame;
        const ARM_CONTEXT *context = ctx;
        DWORD flags = context->ContextFlags & ~CONTEXT_ARM;

        if (flags & CONTEXT_INTEGER)
        {
            wow_frame->R0  = context->R0;
            wow_frame->R1  = context->R1;
            wow_frame->R2  = context->R2;
            wow_frame->R3  = context->R3;
            wow_frame->R4  = context->R4;
            wow_frame->R5  = context->R5;
            wow_frame->R6  = context->R6;
            wow_frame->R7  = context->R7;
            wow_frame->R8  = context->R8;
            wow_frame->R9  = context->R9;
            wow_frame->R10 = context->R10;
            wow_frame->R11 = context->R11;
            wow_frame->R12 = context->R12;
        }
        if (flags & CONTEXT_CONTROL)
        {
            wow_frame->Sp = context->Sp;
            wow_frame->Lr = context->Lr;
            wow_frame->Pc = context->Pc & ~1;
            wow_frame->Cpsr = context->Cpsr;
            if (context->Cpsr & 0x20) wow_frame->Pc |= 1; /* thumb */
        }
        if (flags & CONTEXT_FLOATING_POINT)
        {
            wow_frame->Fpscr = context->Fpscr;
            memcpy( wow_frame->D, context->D, sizeof(context->D) );
        }
        break;
    }

    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              get_thread_wow64_context
 */
NTSTATUS get_thread_wow64_context( HANDLE handle, void *ctx, ULONG size )
{
    BOOL self = (handle == GetCurrentThread());
    USHORT machine;
    void *frame;

    switch (size)
    {
    case sizeof(I386_CONTEXT): machine = IMAGE_FILE_MACHINE_I386; break;
    case sizeof(ARM_CONTEXT): machine = IMAGE_FILE_MACHINE_ARMNT; break;
    default: return STATUS_INFO_LENGTH_MISMATCH;
    }

    if (!self)
    {
        NTSTATUS ret = get_thread_context( handle, ctx, &self, machine );
        if (ret || !self) return ret;
    }

    if (!(frame = get_cpu_area( machine ))) return STATUS_INVALID_PARAMETER;

    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386:
    {
        I386_CONTEXT *wow_frame = frame, *context = ctx;
        DWORD needed_flags = context->ContextFlags & ~CONTEXT_i386;

        if (needed_flags & CONTEXT_I386_INTEGER)
        {
            context->Eax = wow_frame->Eax;
            context->Ebx = wow_frame->Ebx;
            context->Ecx = wow_frame->Ecx;
            context->Edx = wow_frame->Edx;
            context->Esi = wow_frame->Esi;
            context->Edi = wow_frame->Edi;
            context->ContextFlags |= CONTEXT_I386_INTEGER;
        }
        if (needed_flags & CONTEXT_I386_CONTROL)
        {
            context->Esp    = wow_frame->Esp;
            context->Ebp    = wow_frame->Ebp;
            context->Eip    = wow_frame->Eip;
            context->EFlags = wow_frame->EFlags;
            context->SegCs  = wow_frame->SegCs;
            context->SegSs  = wow_frame->SegSs;
            context->ContextFlags |= CONTEXT_I386_CONTROL;
        }
        if (needed_flags & CONTEXT_I386_SEGMENTS)
        {
            context->SegDs = wow_frame->SegDs;
            context->SegEs = wow_frame->SegEs;
            context->SegFs = wow_frame->SegFs;
            context->SegGs = wow_frame->SegGs;
            context->ContextFlags |= CONTEXT_I386_SEGMENTS;
        }
        if (needed_flags & CONTEXT_I386_EXTENDED_REGISTERS)
        {
            memcpy( context->ExtendedRegisters, &wow_frame->ExtendedRegisters, sizeof(context->ExtendedRegisters) );
            context->ContextFlags |= CONTEXT_I386_EXTENDED_REGISTERS;
        }
        if (needed_flags & CONTEXT_I386_FLOATING_POINT)
        {
            memcpy( &context->FloatSave, &wow_frame->FloatSave, sizeof(context->FloatSave) );
            context->ContextFlags |= CONTEXT_I386_FLOATING_POINT;
        }
        if (needed_flags & CONTEXT_I386_DEBUG_REGISTERS)
        {
            context->Dr0 = wow_frame->Dr0;
            context->Dr1 = wow_frame->Dr1;
            context->Dr2 = wow_frame->Dr2;
            context->Dr3 = wow_frame->Dr3;
            context->Dr6 = wow_frame->Dr6;
            context->Dr7 = wow_frame->Dr7;
        }
        /* FIXME: CONTEXT_I386_XSTATE */
        set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
        break;
    }

    case IMAGE_FILE_MACHINE_ARMNT:
    {
        ARM_CONTEXT *wow_frame = frame, *context = ctx;
        DWORD needed_flags = context->ContextFlags & ~CONTEXT_ARM;

        if (needed_flags & CONTEXT_INTEGER)
        {
            context->R0  = wow_frame->R0;
            context->R1  = wow_frame->R1;
            context->R2  = wow_frame->R2;
            context->R3  = wow_frame->R3;
            context->R4  = wow_frame->R4;
            context->R5  = wow_frame->R5;
            context->R6  = wow_frame->R6;
            context->R7  = wow_frame->R7;
            context->R8  = wow_frame->R8;
            context->R9  = wow_frame->R9;
            context->R10 = wow_frame->R10;
            context->R11 = wow_frame->R11;
            context->R12 = wow_frame->R12;
            context->ContextFlags |= CONTEXT_INTEGER;
        }
        if (needed_flags & CONTEXT_CONTROL)
        {
            context->Sp   = wow_frame->Sp;
            context->Lr   = wow_frame->Lr;
            context->Pc   = wow_frame->Pc;
            context->Cpsr = wow_frame->Cpsr;
            context->ContextFlags |= CONTEXT_CONTROL;
        }
        if (needed_flags & CONTEXT_FLOATING_POINT)
        {
            context->Fpscr = wow_frame->Fpscr;
            memcpy( context->D, wow_frame->D, sizeof(wow_frame->D) );
            context->ContextFlags |= CONTEXT_FLOATING_POINT;
        }
        set_context_exception_reporting_flags( &context->ContextFlags, CONTEXT_SERVICE_ACTIVE );
        break;
    }

    }
    return STATUS_SUCCESS;
}


#ifdef WINE_IOS
static inline void ios_fixup_x18_for_return( ucontext_t *context );
#endif

/***********************************************************************
 *           setup_raise_exception
 */
/* task #24 probe: Thumper's settings page dies via its own ExitProcess(-1)
 * with the actual failure invisible (handled guest exception / C++ throw /
 * OutputDebugString we never see). Log every exception dispatched to the
 * guest: code+address+params. DBG_PRINTEXCEPTION carries the game's own
 * debug string — print it. 0xE06D7363 = MSVC C++ throw. */
static void ios_log_guest_exception( const char *via, const EXCEPTION_RECORD *rec, ULONG64 pc )
{
    static volatile int exc_logged = 0;
    int n = __sync_add_and_fetch(&exc_logged, 1);
    if (n > 80) return;
    dprintf(2, "[exc-disp] %s tid=%04x code=%08x flags=%x addr=%p pc=%llx nparams=%u p0=%llx p1=%llx\n",
            via, (unsigned int)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
            (unsigned int)rec->ExceptionCode, (unsigned int)rec->ExceptionFlags,
            rec->ExceptionAddress, (unsigned long long)pc, (unsigned int)rec->NumberParameters,
            rec->NumberParameters > 0 ? (unsigned long long)rec->ExceptionInformation[0] : 0,
            rec->NumberParameters > 1 ? (unsigned long long)rec->ExceptionInformation[1] : 0);
    if (rec->ExceptionCode == 0x40010006 && rec->NumberParameters >= 2 &&
        rec->ExceptionInformation[1])   /* DBG_PRINTEXCEPTION_C: [0]=len [1]=char* */
        dprintf(2, "[exc-disp]   OutputDebugStringA: \"%.*s\"\n",
                (int)(rec->ExceptionInformation[0] > 512 ? 512 : rec->ExceptionInformation[0]),
                (const char *)rec->ExceptionInformation[1]);
    if (rec->ExceptionCode == 0x4001000a && rec->NumberParameters >= 2 &&
        rec->ExceptionInformation[1])   /* DBG_PRINTEXCEPTION_WIDE_C */
    {
        const WCHAR *ws = (const WCHAR *)rec->ExceptionInformation[1];
        char buf[256];
        int i;
        for (i = 0; i < 255 && ws[i]; i++) buf[i] = (ws[i] < 128) ? (char)ws[i] : '?';
        buf[i] = 0;
        dprintf(2, "[exc-disp]   OutputDebugStringW: \"%s\"\n", buf);
    }
}

static void setup_raise_exception( ucontext_t *sigcontext, EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct exc_stack_layout *stack;
    void *stack_ptr = (void *)(SP_sig(sigcontext) & ~15);
    NTSTATUS status;

    ios_log_guest_exception( "raise", rec, context->Pc );

    status = send_debug_event( rec, context, TRUE, TRUE );
    if (status == DBG_CONTINUE || status == DBG_EXCEPTION_HANDLED)
    {
        restore_context( context, sigcontext );
#ifdef WINE_IOS
        ios_fixup_x18_for_return( sigcontext );
#endif
        return;
    }

    /* fix up instruction pointer in context for EXCEPTION_BREAKPOINT */
    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT) context->Pc -= 4;

    stack = virtual_setup_exception( stack_ptr, sizeof(*stack), rec );
    stack->rec = *rec;
    stack->context = *context;
    context_init_empty_xstate( &stack->context, stack->redzone );

    SP_sig(sigcontext) = (ULONG_PTR)stack;
    PC_sig(sigcontext) = (ULONG_PTR)IOS_PFUNC(KiUserExceptionDispatcher);
    REGn_sig(18, sigcontext) = (ULONG_PTR)NtCurrentTeb();
#ifdef WINE_IOS
    /* iOS sigreturn zeroes x18 — route through trampoline */
    ios_fixup_x18_for_return( sigcontext );
#endif
}


