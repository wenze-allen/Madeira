/* Part of signal_arm64_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Raising and delivering exceptions to the guest, user callbacks, syscall faults. Same copyright and licence as signal_arm64_ios.c. */
/***********************************************************************
 *           setup_exception
 *
 * Modify the signal context to call the exception raise function.
 */
static void setup_exception( ucontext_t *sigcontext, EXCEPTION_RECORD *rec )
{
    CONTEXT context;

    rec->ExceptionAddress = (void *)PC_sig(sigcontext);
#ifdef WINE_IOS
    /* task#34 guest-exception-DISPATCH: when the faulting pc is inside a
     * JIT-pool IMAGE COPY, the guest-visible record must carry the PE VA —
     * handlers compare ExceptionAddress against module bounds and the SEH
     * machinery resolves unwind info by module. (pcs inside FEX-emitted
     * code translate to nothing here and are left alone — reconstructing
     * the guest RIP for those is ResetToConsistentState's job on the PE
     * side.) The resume context keeps the real host pc. */
    {
        extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
        uint64_t pe = ios_jit_reverse_translate( (uint64_t)PC_sig(sigcontext), NULL );
        if (pe)
        {
            rec->ExceptionAddress = (void *)(uintptr_t)pe;
            { static unsigned long pe_storm; if (ios_sig_storm_gate( &pe_storm ))
            ERR( "setup_exception: pool pc %p -> PE ExceptionAddress %p\n",
                 (void *)PC_sig(sigcontext), rec->ExceptionAddress ); }
        }
    }
#endif
    save_context( &context, sigcontext );
    setup_raise_exception( sigcontext, rec, &context );
}


#ifdef WINE_IOS
/***********************************************************************
 *           ios_mach_deliver_guest_exception  (ml369, #63)
 *
 * In-process guest exception delivery from the Mach exception-server
 * thread. ml364-368 contain ZERO segv/ill/bus handler invocations: with
 * StikDebug attached, a fault this handler declines (KERN_FAILURE) goes to
 * the task port; the script's continue marks the exception HANDLED
 * kernel-side and its C<signo> is not honored (the stub cannot inject
 * signals), so BSD conversion never happens — the instruction re-executes
 * unmoved until the script kills the whole app at 8 identical stops. That
 * is the entire "LDAPR undeliverable" family (ml362/366/367/368).
 *
 * So deliver here instead: run wine's fault service + dispatch-frame setup
 * against the FAULTING thread (kept suspended by the exception message),
 * write the new sp/pc/x18 back via the caller's thread_set_state, and reply
 * KERN_SUCCESS. thread_set_state restores x18 directly — no sigreturn
 * zeroing on this path, so no trampoline needed.
 *
 * Returns 0 = cannot deliver (caller declines exactly as before),
 *         1 = state rewritten to enter KiUserExceptionDispatcher,
 *         2 = fault serviced by page machinery (guard/watch): plain retry.
 */
/* Defined further down next to bus_handler (the signal path's user); forward
 * declared here because the Mach path must run the SAME emulator — see the
 * [unaligned-atomic] block below for why the two paths may not disagree. */
static int ios_emulate_unaligned_guest_access(ucontext_t *ctx, uint32_t insn, uintptr_t addr);
/* madeira-bcd: the same for an ordered/exclusive/LSE access in the app's own
 * code, which FEX cannot handle (defined after ios_emulate_store_rel); the
 * executable's __TEXT bounds it checks, filled on first use. */
static int ios_native_unaligned_emulate( ucontext_t *ctx, uint32_t insn, uintptr_t addr, uint64_t pc );
static uint64_t ios_app_text_lo, ios_app_text_hi;

static int ios_mach_deliver_guest_exception_inner( thread_t thread, arm_thread_state64_t *state,
                                                   arm_neon_state64_t *neon, int have_neon,
                                                   int exception, uintptr_t fault_addr,
                                                   uintptr_t thread_teb )
{
    extern void *ios_jit_rx_base_global;
    extern size_t ios_jit_pool_size_global;
    extern NTSTATUS ios_virtual_handle_fault_for_thread( EXCEPTION_RECORD *rec, TEB *teb );
    extern void *ios_virtual_setup_exception_for_thread( void *stack_ptr, size_t size,
                                                         EXCEPTION_RECORD *rec, TEB *teb );
    extern const struct ios_ntdll_funcs *ios_ntdll_funcs_for_peb( void *peb_id );
    extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );

    uint64_t pc = arm_thread_state64_get_pc( *state );
    uintptr_t rxb = (uintptr_t)ios_jit_rx_base_global;
    TEB *teb = NULL;
    void *dispatcher;
    EXCEPTION_RECORD rec = { 0 };
    struct exc_stack_layout frame;
    void *frame_addr;
    ucontext_t uc;
    struct __darwin_mcontext64 mc;
    static int deliver_logs;
    /* 2026-09-19: set when the ESR says this data abort is an ALIGNMENT fault
     * (DFSC 0b100001). Such a fault is serviceable — it is neither an access
     * violation nor a transient — so it skips wine's page machinery, the
     * transient-retry debounce and the redelivery terminal below. */
    int is_align = 0;

    /* Pick the faulting thread's TEB by STACK CONTAINMENT, not by
     * self-consistency alone.
     *
     * ml372: both candidates self-verified and pointed at teb
     * 0x73fffd0000, whose stack is [0x731E7C8000,0x731E8C0000) — but the
     * faulting sp was 0x73da05fba0, in a completely different region. The
     * frame was therefore written outside that TEB's stack, and wine's
     * own dispatcher rejected it downstream:
     *   call_seh_handlers invalid frame 73da060000 (731E7C8000-731E8C0000)
     *   NtRaiseException Exception frame is not in stack limits
     * => NtTerminateProcess(c0000005). A TEB that merely EXISTS is not
     * this thread's TEB; Tib.Self proves the struct is a TEB, nothing
     * more. The sp must lie in (DeallocationStack, Tib.StackBase], the
     * same test is_inside_thread_stack applies, or the exception cannot
     * be dispatched no matter how correct the frame is.
     *
     * All reads go through mach_vm_read_overwrite so a bad candidate
     * cannot fault this thread (it has no handler of its own). */
    {
        uint64_t cand[2] = { state->__x[18], (uint64_t)thread_teb };
        uint64_t sp = arm_thread_state64_get_sp( *state );
        int i;

        for (i = 0; i < 2; i++)
        {
            uint64_t self = 0, base = 0, dealloc = 0;
            mach_vm_size_t got = 0;

            if (cand[i] < 0x10000 || (cand[i] & 0xfff)) continue;
            if (mach_vm_read_overwrite( mach_task_self(),
                    (mach_vm_address_t)(cand[i] + 0x30), 8,
                    (mach_vm_address_t)&self, &got ) != KERN_SUCCESS
                || got != 8 || self != cand[i])
                continue;
            if (mach_vm_read_overwrite( mach_task_self(),
                    (mach_vm_address_t)(cand[i] + 0x08), 8,
                    (mach_vm_address_t)&base, &got ) != KERN_SUCCESS || got != 8)
                continue;
            if (mach_vm_read_overwrite( mach_task_self(),
                    (mach_vm_address_t)(cand[i] + 0x1478), 8,
                    (mach_vm_address_t)&dealloc, &got ) != KERN_SUCCESS || got != 8)
                continue;
            if (sp > dealloc && sp <= base)
            {
                teb = (TEB *)(uintptr_t)cand[i];
                break;
            }
            if (deliver_logs < 24)
                dprintf( 2, "[mach-deliver] rev=ml372 teb cand%d=0x%llx stack=(0x%llx,0x%llx] does NOT contain sp=0x%llx\n",
                         i, (unsigned long long)cand[i], (unsigned long long)dealloc,
                         (unsigned long long)base, (unsigned long long)sp );
        }
        if (!teb)
        {
            /* ml540: NATIVE (non-guest) THREAD -> DECLINE, before best-effort.
             *
             * ml539 was the first run of a guest exe that EXITS. After Wine's
             * clean teardown the SwiftUI UI thread faulted inside ICU
             * (ContentView.timeString -> udat_open -> SimpleDateFormat::
             * initialize -> _platform_strcmp) on a pointer into the dead Wine
             * thread's stack. Nothing to do with the guest — but the TASK-level
             * port we claimed for #67 routes it here anyway, and the ml378 path
             * below then pushed a guest exception frame onto a NATIVE stack.
             * One native crash became a 50-deep fault loop (footprint climbed
             * 1271->1800MB) that [fault-stuck] had to break with abort_thread.
             *
             * ml378's reason for never declining is also gone: it declined into
             * an ATTACHED StikDebug, which could not turn the fault into a
             * signal and re-stopped until the script killed the app at 8 stops.
             * We now detach early (#67), so a decline is KERN_FAILURE -> the
             * kernel's default handler -> an honest iOS crash report naming the
             * real faulting frame, which is strictly better than a fabricated
             * guest delivery that cannot work.
             *
             * All three conditions are required, so a genuine guest thread whose
             * stack we merely failed to attribute still gets best-effort:
             *   - not in the thread registry (exact match, no slot-0 fallback)
             *   - x18 == 0 (carries no guest TEB)
             *   - pc is inside a Mach-O image and OUTSIDE the JIT pool, i.e.
             *     host/system code (guest code runs from the pool, and PE
             *     modules are not Mach-O images so dladdr cannot name them) */
            {
                int in_pool = (rxb && pc >= rxb && pc < rxb + ios_jit_pool_size_global) ||
                              ios_jit_low_contains( (uintptr_t)pc );   /* madeira-bcd pool-low */
                Dl_info dli;

                if (!ios_thread_is_registered( thread ) && state->__x[18] == 0 && !in_pool
                    && dladdr( (const void *)(uintptr_t)pc, &dli ) != 0)
                {
                    static int native_declines;
                    if (native_declines < 16)
                    {
                        native_declines++;
                        dprintf( 2, "[mach-deliver] rev=ml540 NATIVE-THREAD DECLINE pc=0x%llx (%s`%s) "
                                    "sp=0x%llx addr=0x%llx -> kernel default handler\n",
                                 (unsigned long long)pc,
                                 dli.dli_fname ? dli.dli_fname : "?",
                                 dli.dli_sname ? dli.dli_sname : "?",
                                 (unsigned long long)sp, (unsigned long long)fault_addr );
                        /* ml1054: WHO called it. A native crash in objc_retain names the
                         * victim, never the culprit; the frame chain does. Read through
                         * mach_vm_read_overwrite so a bad fp cannot fault this thread. */
                        if (native_declines <= 3)
                        {
                            uint64_t fp = state->__fp, pair[2]; int f;
                            dprintf( 2, "[native-bt] ml1054 x0=%llx x1=%llx x8=%llx x16=%llx x17=%llx lr=%llx\n",
                                     (unsigned long long)state->__x[0], (unsigned long long)state->__x[1],
                                     (unsigned long long)state->__x[8], (unsigned long long)state->__x[16],
                                     (unsigned long long)state->__x[17], (unsigned long long)state->__lr );
                            {
                                Dl_info li;
                                uint64_t a = state->__lr & 0x0000007fffffffffULL;
                                if (dladdr( (const void *)(uintptr_t)a, &li ))
                                    dprintf( 2, "[native-bt] ml1054   lr  %llx %s`%s+0x%llx\n", (unsigned long long)a,
                                             li.dli_fname ? strrchr( li.dli_fname, '/' ) ? strrchr( li.dli_fname, '/' ) + 1 : li.dli_fname : "?",
                                             li.dli_sname ? li.dli_sname : "?",
                                             (unsigned long long)(a - (uint64_t)(uintptr_t)li.dli_saddr) );
                            }
                            for (f = 0; f < 24 && fp > 0x10000; f++)
                            {
                                mach_vm_size_t got = 0; Dl_info fi; uint64_t ra;
                                if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)fp, 16,
                                                            (mach_vm_address_t)pair, &got ) != KERN_SUCCESS || got != 16) break;
                                ra = pair[1] & 0x0000007fffffffffULL;   /* strip PAC */
                                if (!ra) break;
                                if (dladdr( (const void *)(uintptr_t)ra, &fi ))
                                    dprintf( 2, "[native-bt] ml1054   #%d %llx %s`%s+0x%llx\n", f, (unsigned long long)ra,
                                             fi.dli_fname ? strrchr( fi.dli_fname, '/' ) ? strrchr( fi.dli_fname, '/' ) + 1 : fi.dli_fname : "?",
                                             fi.dli_sname ? fi.dli_sname : "?",
                                             (unsigned long long)(ra - (uint64_t)(uintptr_t)fi.dli_saddr) );
                                else
                                    dprintf( 2, "[native-bt] ml1054   #%d %llx (no image)\n", f, (unsigned long long)ra );
                                if (pair[0] <= fp) break;
                                fp = pair[0];
                            }
                            {   /* ml1155: did WE free the object this thread is touching? (winemetal records
                                 * every release that dropped the last reference) */
                                extern const char *madeira_wmt_released_class( uintptr_t addr, uint64_t *ago ) __attribute__((weak_import));
                                int r;
                                if (madeira_wmt_released_class)
                                    for (r = 0; r < 2; r++)
                                    {
                                        uint64_t v = r ? state->__x[8] : state->__x[0], ago = 0;
                                        const char *cls = madeira_wmt_released_class( (uintptr_t)v, &ago );
                                        if (cls) dprintf( 2, "[native-bt] ml1155 x%d=%llx was FREED by our NSObject_release: class %s, %llu releases ago\n",
                                                          r ? 8 : 0, (unsigned long long)v, cls, (unsigned long long)ago );
                                        else dprintf( 2, "[native-bt] ml1155 x%d=%llx is not among the last 16384 objects our NSObject_release freed\n",
                                                      r ? 8 : 0, (unsigned long long)v );
                                    }
                            }
                        }
                    }
                    return 0;
                }
            }

            /* ml378: BEST-EFFORT DELIVERY instead of declining.
             *
             * ml372 declined here because a frame outside the TEB's stack made
             * call_seh_handlers reject it and NtRaiseException kill the process.
             * But declining is not the safe option it looked like: while
             * StikDebug is attached the declined fault cannot be converted to a
             * BSD signal at all, so it repeats until the script kills the WHOLE
             * app after 8 stops — which is exactly how ml378 died
             * (`DECLINE pc=0x14f5e36cc … no TEB owns this stack`, 8 repeats).
             *
             * The reason for declining is also gone: the ml377 ntdll fix makes a
             * first-step bad frame an ordinary UNHANDLED exception rather than
             * EXCEPTION_STACK_INVALID + immediate terminate. So delivering on the
             * guest's own stack now degrades to "the guest sees an unhandled
             * exception" (its filter runs, its pseudo-process dies) instead of
             * taking everything down.
             *
             * Use any SELF-CONSISTENT TEB (Tib.Self check already done above);
             * virtual_setup_exception's "outside thread stack" branch handles the
             * frame placement and verifies writability. */
            uint64_t cand2[2] = { state->__x[18], (uint64_t)thread_teb };
            int j;
            for (j = 0; j < 2 && !teb; j++)
            {
                uint64_t self = 0;
                mach_vm_size_t got = 0;
                if (cand2[j] < 0x10000 || (cand2[j] & 0xfff)) continue;
                if (mach_vm_read_overwrite( mach_task_self(),
                        (mach_vm_address_t)(cand2[j] + 0x30), 8,
                        (mach_vm_address_t)&self, &got ) == KERN_SUCCESS
                    && got == 8 && self == cand2[j])
                    teb = (TEB *)(uintptr_t)cand2[j];
            }
            if (deliver_logs < 24)
            {
                deliver_logs++;
                dprintf( 2, "[mach-deliver] rev=ml378 no TEB owns sp=0x%llx (pc=0x%llx x18=0x%llx "
                            "registry=0x%llx) -> %s\n",
                         (unsigned long long)sp, (unsigned long long)pc,
                         (unsigned long long)state->__x[18], (unsigned long long)thread_teb,
                         teb ? "BEST-EFFORT delivery on guest stack" : "DECLINE (no usable TEB at all)" );
            }
            if (!teb) return 0;
        }
        thread_teb = (uintptr_t)teb;
    }

    /* iOS-Madeira ml413 (#60/#66): xtajit64 stamps TEB->Instrumentation[8]
     * (+0x16f8) with the mutex address while a thread holds a FEX shared lock
     * (CodeInvalidationMutex read hold during CompileCode). Redirecting such a
     * thread to KiUserExceptionDispatcher abandons the compile without
     * unwinding — the read hold leaks and every later writer/reader parks
     * forever (the ml413 wedge: word=0x40010001). Log-only for now: prove or
     * refute this path before changing delivery behavior. */
    {
        static int deliver_hold_logs;
        uint64_t held_lock = 0;
        if (thread_teb)
            held_lock = *(volatile uint64_t *)((char *)(uintptr_t)thread_teb + 0x16f8);
        if (held_lock && deliver_hold_logs < 16)
        {
            deliver_hold_logs++;
            dprintf( 2, "[deliver-hold] teb=0x%llx tid=%04x HOLDS FEX shared lock @0x%llx at guest redirect "
                        "(pc=0x%llx addr=0x%llx) — this delivery leaks the read hold\n",
                     (unsigned long long)thread_teb,
                     *(volatile unsigned int *)((char *)(uintptr_t)thread_teb + 0x48),
                     (unsigned long long)held_lock,
                     (unsigned long long)pc, (unsigned long long)fault_addr );
        }
    }

    /* fabricate a ucontext over the fetched thread state so the existing
     * conversion helpers (save_context, sig macros) apply unchanged */
    memset( &uc, 0, sizeof(uc) );
    memset( &mc, 0, sizeof(mc) );
    mc.__ss = *state;
    if (have_neon) mc.__ns = *neon;
    {
        arm_exception_state64_t es;
        mach_msg_type_number_t ecount = ARM_EXCEPTION_STATE64_COUNT;
        if (thread_get_state( thread, ARM_EXCEPTION_STATE64,
                              (thread_state_t)&es, &ecount ) == KERN_SUCCESS)
            mc.__es = es;
        else
            mc.__es.__far = fault_addr;
    }
    uc.uc_mcontext = &mc;

    if (exception == EXC_BAD_INSTRUCTION)
        rec.ExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;
    else
    {
        uint32_t esr = (uint32_t)mc.__es.__esr, esr_ec = esr >> 26;
        NTSTATUS st;
        rec.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
        rec.NumberParameters = 2;
        if (esr_ec == 0x20 || esr_ec == 0x21) rec.ExceptionInformation[0] = EXCEPTION_EXECUTE_FAULT;
        else if (esr & 0x40) rec.ExceptionInformation[0] = EXCEPTION_WRITE_FAULT;
        else rec.ExceptionInformation[0] = EXCEPTION_READ_FAULT;
        rec.ExceptionInformation[1] = fault_addr;

        /* iOS-Madeira 2026-09-19 [unaligned-atomic]: AN ALIGNMENT FAULT IS NOT
         * AN ACCESS VIOLATION, ON EITHER DELIVERY PATH.
         *
         * A 32-bit title froze after its D3D9 device came up with 13 parked
         * waiters behind one guest critical section. The trigger was a JIT'd
         * x86 `xchg [mem],reg` — host `swpal w26,w4,[x24]` (0xb8fa8304) at
         * pool pc 0x138181c94 on guest address ...e32e, i.e. 2 mod 4. x86
         * permits unaligned atomics; ARM64 LSE atomics fault, and FEX exists
         * to fix exactly that. The log shows the two paths DISAGREEING about
         * the same fault, four lines apart:
         *
         *   bus_handler  -> esr=0x92000021 -> 80000002 -> FEX: "Handled
         *                   unaligned atomic: new pc: 138181C98"   (correct)
         *   this handler -> c0000005 READ 0x710553e32e -> FEX: "Reconstructing
         *                   context ... eip: 2E3733C0"             (fatal)
         *
         * FEX only emulates unaligned LSE atomics, it never back-patches them
         * (HandleAtomicMemOp returns 4 = skip, no code rewrite), so a guest
         * spin-acquire re-faults at the SAME host pc on every iteration. Under
         * the transient-retry debounce below the 1st and 2nd faults declined to
         * the BSD signal path and were fixed, and the 3rd was dispatched from
         * here as a bogus access violation — which is not raised at any guest
         * instruction that can handle it, so the thread unwound out of the
         * locked region and every later waiter parked forever.
         *
         * The ESR already says which it is and nothing else has to be guessed:
         * EC 0x24/0x25 is a data abort and DFSC (ISS[5:0]) 0b100001 is
         * "Alignment fault" — the same bits `bus_handler` reads. Plain
         * loads/stores are emulated in place here exactly as the signal path
         * does; anything else (LSE atomics, CAS/CASP, exclusives, LDAPR/STLR)
         * is dispatched as STATUS_DATATYPE_MISALIGNMENT so FEX's unaligned
         * machinery gets the same shot it gets from bus_handler.
         *
         * Safe on this thread: the emulator touches only GPRs of the fabricated
         * context (it refuses SIMD) and copies bytes through pointers in the
         * one shared Mach task, and it uses no wine log macros — both required
         * of anything running on the exception-server thread.
         *
         * MADEIRA_MACH_ALIGN_FAULT=0 restores the old classification (every
         * data abort here is c0000005) for a same-build A/B; it is read once
         * when the exception server starts, never from this thread. */
        is_align = ios_mach_align_fault_enabled &&
                   (esr_ec == 0x24 || esr_ec == 0x25) && (esr & 0x3F) == 0x21;
        if (is_align)
        {
            uint32_t a_insn = 0;
            mach_vm_size_t got = 0;
            static unsigned long ua_emu, ua_fex;

            if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)pc,
                                        sizeof(a_insn), (mach_vm_address_t)&a_insn,
                                        &got ) == KERN_SUCCESS && got == sizeof(a_insn) &&
                ios_emulate_unaligned_guest_access( &uc, a_insn, fault_addr ))
            {
                PC_sig(&uc) += 4;
                *state = mc.__ss;
                if (++ua_emu <= 16 || (ua_emu % 4096) == 0)
                    dprintf( 2, "[unaligned-atomic] mach-path pc=0x%llx insn=0x%08x addr=0x%llx "
                                "handled by emulation (plain ld/st) emu=%lu to-fex=%lu rev=2026-09-19\n",
                             (unsigned long long)pc, a_insn, (unsigned long long)fault_addr,
                             ua_emu, ua_fex );
                return 1;
            }
            /* madeira-bcd: an ordered/exclusive/LSE access in the app's own code
             * (ios_native_unaligned_emulate: the Launcher's `stlr` of build 454).
             * The app offset names the function offline: dladdr would take dyld's
             * lock on the exception thread for a fault that is recovered. */
            if (ios_native_unaligned_emulate( &uc, a_insn, fault_addr, (uint64_t)pc ))
            {
                static unsigned long ua_native;
                PC_sig(&uc) += 4;
                *state = mc.__ss;
                if (++ua_native <= 16 || (ua_native % 4096) == 0)
                    dprintf( 2, "[unaligned-native] mach-path pc=0x%llx (app+0x%llx) insn=0x%08x "
                                "addr=0x%llx emulated in place, not handed to FEX (#%lu)\n",
                             (unsigned long long)pc, (unsigned long long)((uint64_t)pc - ios_app_text_lo),
                             a_insn, (unsigned long long)fault_addr, ua_native );
                return 1;
            }

            rec.ExceptionCode = EXCEPTION_DATATYPE_MISALIGNMENT;
            rec.NumberParameters = 0;
            if (++ua_fex <= 32 || (ua_fex % 4096) == 0)
                dprintf( 2, "[unaligned-atomic] mach-path pc=0x%llx insn=0x%08x addr=0x%llx "
                            "handed to FEX as 80000002 (was c0000005 before 2026-09-19) "
                            "emu=%lu to-fex=%lu\n",
                         (unsigned long long)pc, a_insn, (unsigned long long)fault_addr,
                         ua_emu, ua_fex );
        }

        /* iOS-Madeira ml613 [av-detail]: THE THREE-WAY DISCRIMINATOR.
         *
         * ml612's fatal AV printed only ExceptionAddress, so read-vs-execute and
         * the actual faulting DATA address were both invisible — and a FEX
         * miscompile, a corrupted reconstructed register and a genuine Chromium
         * heap bug all produce an identical line. Everything needed is already
         * computed above; it just was not logged.
         *
         * ⚠️ These readings NARROW, they do not convict:
         *   p0=EXECUTE, p1==host pc      -> the JIT-carve lifecycle/protection
         *                                   path (tail recycling is the leading
         *                                   member of that family, not the only one)
         *   p0=READ, p1==RCX+8, wild RCX -> the guest really was dereferencing
         *                                   RCX; the wild value could still come
         *                                   from FEX, CEF, or a third writer
         *   p0=READ, p1!=RCX+8           -> suspect the context RECONSTRUCTION
         *                                   itself before blaming either side
         *
         * Original (pre-reconstruction) exception info is logged here; RCX/R8 are
         * read from the FEX guest state as it stands now. All memory reads go
         * through mach_vm_read_overwrite, and the carve lookup is TRYLOCK-only —
         * never block on ios_tail_carve_lock from a fault handler. */
        {
            static unsigned long av_n;
            unsigned long n = is_align ? 0 : ++av_n;   /* alignment faults are not AVs — see above */
            if (n && (n <= 24 || (n % 4096) == 0))
            {
                uint64_t hpc = (uint64_t)arm_thread_state64_get_pc( mc.__ss );
                unsigned int hinsn = 0;
                uint64_t rcx = 0, r8 = 0, rcx8 = 0;
                int have_regs = 0, rcx8_ok = 0;
                unsigned cidx = 0; unsigned long long cbase = 0, csize = 0; int cfree = 0, crc;
                mach_vm_size_t g = 0;

                mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)hpc,
                                        sizeof(hinsn), (mach_vm_address_t)&hinsn, &g );
                {
                    TEB *t = NtCurrentTeb();
                    CHPE_V2_CPU_AREA_INFO *ca = t ? t->ChpeV2CpuAreaInfo : NULL;
                    void *fx = ca ? *(void **)((char *)ca + 0x30) : NULL;
                    if (fx)
                    {
                        const uint64_t *gr = &((const uint64_t *)fx)[0x20 / 8];
                        rcx = gr[1];   /* RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8.. */
                        r8  = gr[8];
                        have_regs = 1;
                        rcx8_ok = (mach_vm_read_overwrite( mach_task_self(),
                                       (mach_vm_address_t)(rcx + 8), sizeof(rcx8),
                                       (mach_vm_address_t)&rcx8, &g ) == KERN_SUCCESS);
                    }
                }
                crc = ios_tail_carve_lookup_trylock( hpc, &cidx, &cbase, &csize, &cfree );

                dprintf( 2, "[av-detail] ml613 #%lu p0=%s p1=0x%llx hostpc=0x%llx hinsn=0x%08x "
                            "rcx=0x%llx r8=0x%llx [rcx+8]=%s0x%llx p1_is_rcx8=%d | carve=%s",
                         n,
                         rec.ExceptionInformation[0] == EXCEPTION_EXECUTE_FAULT ? "EXECUTE" :
                         rec.ExceptionInformation[0] == EXCEPTION_WRITE_FAULT   ? "WRITE" : "READ",
                         (unsigned long long)fault_addr, (unsigned long long)hpc, hinsn,
                         (unsigned long long)rcx, (unsigned long long)r8,
                         rcx8_ok ? "" : "<unreadable>", (unsigned long long)rcx8,
                         (have_regs && fault_addr == rcx + 8) ? 1 : 0,
                         crc < 0 ? "lock-busy" : (crc == 0 ? "none" : "") );
                if (crc > 0)
                    dprintf( 2, "idx=%u base=0x%llx size=0x%llx state=%s p1_in_carve=%d",
                             cidx, cbase, csize, cfree ? "FREE(recycled!)" : "live",
                             (fault_addr >= cbase && fault_addr < cbase + csize) ? 1 : 0 );
                dprintf( 2, " regs=%d rev=ml613\n", have_regs );

                /* iOS-Madeira ml619 [tree-caller]: NAME THE CORRUPTED CONTAINER.
                 *
                 * ml616/ml618 both died inside libc++'s recursive tree deleter for
                 * fextl::set<uint64_t> (libarm64ecfex+0x12fa0 and +0x12c10 — two
                 * instantiations of the same shape), following a corrupted left-child
                 * pointer. The registers cannot say WHICH set: the helper is shared,
                 * and Decoder::DecodeInstructionsAtEntry alone manipulates five
                 * (VisitedBlocks, BlocksToDecode, CurrentBlockTargets,
                 * BlockInfo.EntryPoints, BlockInfo.CodePages).
                 *
                 * The stack does say. Every recursive frame is exactly 32 bytes with
                 * the saved LR at frame+0x18, and every recursive frame stores the SAME
                 * LR (the instruction after the recursive `bl`). Walk up while it
                 * repeats; the FIRST DIFFERENT LR is the original callsite, which names
                 * the container.
                 *
                 * Self-calibrating and RVA-free: the gate is simply "the saved LR in two
                 * consecutive 32-byte frames is identical and non-zero", which no
                 * ordinary frame satisfies. Nothing is hardcoded, so it keeps working
                 * when FEX is rebuilt and the deleter moves. */
                {
                    uint64_t hsp = (uint64_t)arm_thread_state64_get_sp( mc.__ss );
                    uint64_t lr0 = 0, lr1 = 0;
                    mach_vm_size_t rg = 0;
                    int ok0 = mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(hsp + 0x18),
                                                      sizeof(lr0), (mach_vm_address_t)&lr0, &rg ) == KERN_SUCCESS;
                    int ok1 = mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(hsp + 0x38),
                                                      sizeof(lr1), (mach_vm_address_t)&lr1, &rg ) == KERN_SUCCESS;
                    if (ok0 && ok1 && lr0 && lr0 == lr1)
                    {
                        uint64_t f = hsp, caller = 0, prev_f = 0;
                        unsigned depth = 0;
                        for (; depth < 65536; depth++, f += 0x20)
                        {
                            uint64_t lr = 0;
                            if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(f + 0x18),
                                                        sizeof(lr), (mach_vm_address_t)&lr, &rg ) != KERN_SUCCESS)
                                break;
                            if (lr != lr0) { caller = lr; prev_f = f; break; }
                        }
                        dprintf( 2, "[tree-caller] ml619 recursive 32B frames: recursive_lr=0x%llx depth=%u "
                                    "ORIGINAL CALLER=%s0x%llx frame=0x%llx node=0x%llx sp=0x%llx%s\n",
                                 (unsigned long long)lr0, depth,
                                 caller ? "" : "<not reached> ", (unsigned long long)caller,
                                 (unsigned long long)prev_f, (unsigned long long)rcx,
                                 (unsigned long long)hsp,
                                 (depth >= 65536) ? "  (hit 65536-frame cap — caller NOT found, not absent)" : "" );
                    }
                }
            }
        }

        /* wine's page machinery gets first shot, on the FIRST occurrence —
         * the ml369 run showed the 0x712bXX..ed5c faults are guest-STACK
         * pages (guest rsp just below the address, one fault each across 4
         * sibling threads), exactly what virtual_handle_fault services; in
         * the Mach-only regime it had never run at all. Guard growth /
         * write-watch clears resume with no guest exception;
         * GUARD_PAGE_VIOLATION / STACK_OVERFLOW must be dispatched
         * immediately (wine semantics — state is consistent, no repeat
         * gating). */
        /* An alignment fault has no page to service, and this helper ENDS with
         * `rec->ExceptionCode = ret` — letting it run would overwrite the
         * 80000002 chosen above with c0000005 again. It still has to pass the
         * guest-pc gate below, so no `goto dispatch` here. */
        if (!is_align)
        {
            st = ios_virtual_handle_fault_for_thread( &rec, teb );
            if (!st)
            {
                if (deliver_logs < 24)
                {
                    deliver_logs++;
                    dprintf( 2, "[mach-deliver] rev=ml369 page-serviced pc=0x%llx addr=0x%llx (guard/watch), retrying\n",
                             (unsigned long long)pc, (unsigned long long)fault_addr );
                }
                return 2;
            }
            if (st != STATUS_ACCESS_VIOLATION) goto dispatch;
        }
    }

    /* only claim faults in plausibly GUEST-side execution:
     *   - the JIT pool (translated guest + FEX-emitted + pool-copied code),
     *   - pc < 4GB: nothing legitimate executes there (pool base is
     *     >= 0x119000000, dyld cache >= 0x180000000) — covers the pc=0
     *     zeroed-EC-dispatch family that killed the ml369 run,
     *   - the guest VA band (PE VAs / guest pointers as branch targets).
     * Host dylib and unix-side pcs keep the old decline path —
     * dispatching a guest exception on those contexts would be wrong. */
    if (!((rxb && pc >= rxb && pc < rxb + ios_jit_pool_size_global) ||
          ios_jit_low_contains( (uintptr_t)pc ) ||   /* madeira-bcd pool-low: FEX code in region C */
          pc < 0x100000000ULL ||
          (pc >= 0x7000000000ULL && pc < 0x7400000000ULL)))
        return 0;

    /* transient-retry absorption: races with concurrent mprotect / FEX
     * invalidation are fixed by re-execution and were free retries under
     * the decline regime. Dispatch only on the 3rd identical
     * (thread,pc,addr) fault — still well before the script's 8-stop kill.
     * Single server thread services all messages: no atomics needed. */
    /* The count is per exact key (ios_guard_slot). It was 16 slots chosen by
     * (key >> 4) & 15, so two faults whose keys shared a slot (two threads, or
     * one thread at two addresses) reset each other to 1 on every alternation:
     * neither was ever dispatched, and both went on being declined. */
    if (!is_align)
    {
        static struct ios_guard_table rep_tab;
        static uint32_t rep_n[IOS_GUARD_SLOTS];
        uint64_t key = ((uint64_t)thread << 48) ^ pc ^ ((uint64_t)fault_addr << 1);
        int rep_fresh;
        int slot = ios_guard_slot( &rep_tab, key, mach_absolute_time(), &rep_fresh );
        if (rep_fresh) { rep_n[slot] = 1; return 0; }
        if (++rep_n[slot] < 3) return 0;
    }

dispatch:
    /* resolve the dispatcher for the TARGET's pseudo-process (this thread
     * has no pseudo-process identity, so IOS_PFUNC would always fall back
     * to the session ntdll) */
    {
        void *peb_id = *(void **)(thread_teb + 0x60);
        const struct ios_ntdll_funcs *f = ios_ntdll_funcs_for_peb( peb_id );
        dispatcher = f ? f->KiUserExceptionDispatcher : (void *)pKiUserExceptionDispatcher;
    }
    if (!dispatcher) return 0;

    rec.ExceptionAddress = (void *)(uintptr_t)pc;
    {
        uint64_t pe = ios_jit_reverse_translate( pc, NULL );
        if (pe) rec.ExceptionAddress = (void *)(uintptr_t)pe;
    }

    frame_addr = ios_virtual_setup_exception_for_thread(
        (void *)(SP_sig(&uc) & ~15), sizeof(frame), &rec, teb );
    if (!frame_addr)
    {
        if (deliver_logs < 24)
        {
            deliver_logs++;
            dprintf( 2, "[mach-deliver] rev=ml369 CANNOT deliver pc=0x%llx addr=0x%llx sp=0x%llx (frame unwritable)\n",
                     (unsigned long long)pc, (unsigned long long)fault_addr,
                     (unsigned long long)SP_sig(&uc) );
        }
        return 0;
    }

    /* build the dispatch frame locally, then place it with mach_vm_write —
     * a raw store through a bad target sp would fault THIS thread, which
     * has no handler of its own and would wedge the whole app.
     * context_init_empty_xstate stores struct-relative offsets only, so
     * computing it in the local copy is exact. */
    memset( &frame, 0, sizeof(frame) );
    save_context( &frame.context, &uc );
    frame.rec = rec;
    context_init_empty_xstate( &frame.context, frame.redzone );

    if (mach_vm_write( mach_task_self(), (mach_vm_address_t)(uintptr_t)frame_addr,
                       (vm_offset_t)(uintptr_t)&frame, sizeof(frame) ) != KERN_SUCCESS)
    {
        if (deliver_logs < 24)
        {
            deliver_logs++;
            dprintf( 2, "[mach-deliver] rev=ml369 mach_vm_write FAILED frame=%p pc=0x%llx\n",
                     frame_addr, (unsigned long long)pc );
        }
        return 0;
    }

    SP_sig(&uc) = (ULONG_PTR)frame_addr;
    PC_sig(&uc) = (ULONG_PTR)dispatcher;
    REGn_sig(18, &uc) = thread_teb;

    *state = mc.__ss;
    ios_note_guest_delivery( (uint64_t)thread );   /* restarts [fault-stuck] */

    if (deliver_logs < 24 || (deliver_logs % 100) == 0)
        dprintf( 2, "[mach-deliver] rev=ml369 #%d code=%08x pc=0x%llx excaddr=%p addr=0x%llx frame=%p teb=%p disp=%p\n",
                 deliver_logs, (unsigned int)rec.ExceptionCode,
                 (unsigned long long)pc, rec.ExceptionAddress,
                 (unsigned long long)fault_addr, frame_addr, (void *)thread_teb, dispatcher );
    deliver_logs++;

    /* iOS-Madeira ml461 (#76): identical-fault redelivery TERMINAL. A host-C++
     * fault misdelivered down the guest SEH path can never be handled — the
     * guest restores the context and refaults, forever. ml452 stormed 65k×,
     * ml459 70k×, ml460 326,500× (rpmalloc free-list bucket holding x86 code
     * bytes; the wedged thread was the chrome-ipc pump and the run died of
     * log/CPU burn instead of saying anything). No legitimate guest pattern
     * redelivers the SAME (thread,pc,addr) thousands of times — handled
     * retries (redirects, USD, unaligned) never reach this point. This sits
     * at delivery-complete so every route counts, including the goto-dispatch
     * one that bypasses the rep[] debounce above. Single server thread: no
     * atomics needed. At the threshold: dump raw memory near the faulting
     * thread's pointer registers (the ml460 corruption lived at [x10+x9*8]
     * and register dumps were capped away long before the storm settled),
     * then terminate honestly. */
    /* 2026-09-19: EXEMPT ALIGNMENT FAULTS. The premise of this terminal is "no
     * legitimate guest pattern redelivers the SAME (thread,pc,addr) thousands
     * of times" — and the comment above already lists "unaligned" among the
     * handled retries that "never reach this point". That was true only while
     * this path mislabelled them c0000005; now that 80000002 is delivered from
     * here, an unaligned atomic in a guest spin-acquire legitimately redelivers
     * once per loop iteration (FEX emulates, it cannot back-patch an LSE
     * atomic), and counting those would kill the pseudo-process for making
     * progress. */
    if (!is_align)
    {
        /* Count CONSECUTIVE identical deliveries per thread, not lifetime hits
         * of a (thread,pc,addr) key. Slots used to be chosen by the key itself,
         * so a fault that recurs once per frame with real progress in between
         * kept its count for as long as no other key landed in its slot. Dark
         * Souls Remastered's Settings menu re-writes Arxan-guarded .text every
         * frame; each write is a self-modifying-code fault FEX handles, the
         * game keeps running, yet 7 keys cycling once per frame reached 2000 in
         * ~35 s and this guard killed a healthy game. A real storm refaults the
         * same instruction back to back on one thread, so the slot is chosen by
         * thread and any other fault on that thread restarts the run. */
        /* The thread's slot is found by exact thread port (ios_guard_slot). It
         * was one of 16 chosen by a hash of the port, so two storming threads
         * sharing a slot restarted each other's run on every delivery and the
         * terminal never fired. */
        static struct ios_guard_table redeliv_tab;
        static struct { uint64_t key; uint32_t n; } redeliv[IOS_GUARD_SLOTS];
        static volatile int ios_redeliv_terminating;
        uint64_t rkey = ((uint64_t)thread << 48) ^ pc ^ ((uint64_t)fault_addr << 1);
        int rfresh;
        int rslot = ios_guard_slot( &redeliv_tab, (uint64_t)thread, mach_absolute_time(), &rfresh );
        if (rfresh || redeliv[rslot].key != rkey)
        {
            redeliv[rslot].key = rkey;
            redeliv[rslot].n = 1;
        }
        else if (++redeliv[rslot].n == 256)
            dprintf( 2, "[redeliv] 256 identical redeliveries pc=0x%llx addr=0x%llx — storm forming rev=ml461\n",
                     (unsigned long long)pc, (unsigned long long)fault_addr );
        else if (redeliv[rslot].n >= 2000 && !ios_redeliv_terminating)
        {
            /* ml463: was `== 2000` + exit(76) — one shot, and exit() on iOS is
             * the wine_ios_exit shim which LONGJMPS instead of terminating (the
             * ml462 run sailed straight past its own death sentence and kept
             * storming with a fexlock held, 11 threads parked behind it).
             *
             * ml465: `>=` without a latch was worse — EVERY delivery past 2000
             * re-dumped the forensics, and the ml464 run wrote 4 MILLION lines
             * (22k dumps) because the kill did not stop delivery instantly.
             * Latch it: dump exactly once, then kill and keep killing. Mach
             * task_terminate first (unshimmable), then the raw _exit syscall,
             * then park this thread forever so it can never deliver again —
             * whichever lands first, no second dump is possible. */
            ios_redeliv_terminating = 1;
            static const int fregs[] = { 0, 8, 9, 10, 16, 19, 20 };
            unsigned fi;
            dprintf( 2, "[redeliv] 2000 identical redeliveries pc=0x%llx addr=0x%llx — unrecoverable host fault misdelivered to guest rev=ml461\n",
                     (unsigned long long)pc, (unsigned long long)fault_addr );
            for (fi = 0; fi < sizeof(fregs) / sizeof(fregs[0]); fi++)
            {
                uint64_t rv = state->__x[fregs[fi]];
                uint64_t words[8];
                mach_vm_size_t got = 0;
                if (rv < 0x1000 || rv >= 0x800000000000ull) continue;
                if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(rv & ~7ull), 64,
                                            (mach_vm_address_t)(uintptr_t)words, &got ) != KERN_SUCCESS || got != 64)
                {
                    dprintf( 2, "[redeliv-mem] x%d=0x%llx: <unmapped>\n", fregs[fi], (unsigned long long)rv );
                    continue;
                }
                dprintf( 2, "[redeliv-mem] x%d=0x%llx: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
                         fregs[fi], (unsigned long long)rv,
                         (unsigned long long)words[0], (unsigned long long)words[1],
                         (unsigned long long)words[2], (unsigned long long)words[3],
                         (unsigned long long)words[4], (unsigned long long)words[5],
                         (unsigned long long)words[6], (unsigned long long)words[7] );
            }
            dprintf( 2, "[redeliv] terminating process rev=ml465\n" );
            task_terminate( mach_task_self() );
            _exit( 76 );
            for (;;) pause();
        }
    }

    /* iOS-Madeira ml422 (#70): a webhelper thread died STATUS_STACK_OVERFLOW
     * right after the first CreateBrowser (ml421). Name the dying thread's
     * stack RESERVE so the verdict is direct: a Windows-sized (512KB/1MB)
     * stack overflowing = EC native-frame inflation → the ml422 4MB floor is
     * the fix; a 4MB stack STILL overflowing = pathological unbounded
     * recursion → chase the recursion instead. TEB Tib: StackBase +0x8,
     * StackLimit +0x10, DeallocationStack +0x1478. */
    if (rec.ExceptionCode == 0xC00000FD && thread_teb > 0x10000)
    {
        static int ovf_logs;
        if (ovf_logs < 8 && ++ovf_logs <= 8)
        {
            unsigned long long sb = *(unsigned long long *)(thread_teb + 0x8);
            unsigned long long sl = *(unsigned long long *)(thread_teb + 0x10);
            unsigned long long da = *(unsigned long long *)(thread_teb + 0x1478);
            dprintf( 2, "[stack-ovf] rev=ml424 teb=%p StackBase=0x%llx StackLimit=0x%llx "
                     "DeallocationStack=0x%llx reserve=0x%llx (floor now 0x800000)\n",
                     (void *)thread_teb, sb, sl, da, sb - da );

            /* ml424 (#70 round 2): a 4MB stack STILL overflowed and the SEH
             * unwinder's pcs went mid-instruction after ~4k frames (walking a
             * garbage chain), so the unwind cannot name the consumer. Sample
             * the RAW stack at three depths instead — real frames litter
             * return addresses, and a recursion cycle repeats at every depth.
             * Windows: just above the fault (freshest), mid-stack, and just
             * below StackBase (the recursion's entry). mach reads only. */
            if (sb > da && sb - da <= 0x4000000 && fault_addr > da && fault_addr < sb)
            {
                extern unsigned long long ios_jit_module_base_for_va(unsigned long long va, unsigned long long *size_out);
                static uint64_t ovf_buf[512];
                unsigned long long lo = (fault_addr + 0x3fffULL) & ~0x3fffULL;
                int w;
                for (w = 0; w < 3; w++)
                {
                    unsigned long long wbase = (w == 0) ? lo
                                             : (w == 1) ? lo + (sb - lo) / 2
                                             : sb - sizeof(ovf_buf);
                    mach_vm_size_t got = 0;
                    int wi, nw, whits = 0;
                    /* ml425 cycle-density: the ml424 fingerprint proved a repeating
                     * cycle but capped at 8 prints — COUNT every distinct code-like
                     * value across the whole window so frames-per-cycle is measured,
                     * not guessed (the logged cef cascade was only ~45 lines and
                     * cannot explain 8MB; the counts arbitrate). */
                    uint64_t uq[24]; int uqn[24]; int nuq = 0, total_code = 0;
                    if (wbase < lo) wbase = lo;
                    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)wbase,
                            sizeof(ovf_buf), (mach_vm_address_t)(uintptr_t)ovf_buf, &got ) != KERN_SUCCESS)
                        continue;
                    nw = (int)(got / 8);
                    for (wi = 0; wi < nw; wi++)
                    {
                        uint64_t v = ovf_buf[wi];
                        unsigned long long msz = 0;
                        unsigned long long mbase = ios_jit_module_base_for_va( v, &msz );
                        const unsigned char *mb;
                        const char *mname = "?";
                        unsigned int e_lf, exp_rva, name_rva;
                        int k;
                        if (!mbase) continue;
                        total_code++;
                        for (k = 0; k < nuq; k++) if (uq[k] == v) { uqn[k]++; break; }
                        if (k == nuq && nuq < 24) { uq[nuq] = v; uqn[nuq] = 1; nuq++; }
                        if (whits >= 8) continue;
                        mb = (const unsigned char *)(uintptr_t)mbase;
                        if (mb[0] == 'M' && mb[1] == 'Z' &&
                            (e_lf = *(const unsigned int *)(mb + 0x3c)) < 0x1000 &&
                            (exp_rva = *(const unsigned int *)(mb + e_lf + 0x88)) &&
                            exp_rva < msz &&
                            (name_rva = *(const unsigned int *)(mb + exp_rva + 0x0c)) &&
                            name_rva < msz)
                            mname = (const char *)(mb + name_rva);
                        else if (mb[0] == 'M' && mb[1] == 'Z')
                            mname = "(exe)";
                        dprintf( 2, "[stack-ovf]   w%d +%03x: %llx  %.32s+0x%llx\n",
                                 w, wi * 8, (unsigned long long)v, mname,
                                 (unsigned long long)(v - mbase) );
                        whits++;
                    }
                    dprintf( 2, "[stack-ovf]   w%d base=0x%llx scanned=%d code-like=%d distinct=%d\n",
                             w, wbase, nw, total_code, nuq );
                    {
                        int k;
                        for (k = 0; k < nuq; k++)
                            if (uqn[k] >= 4)
                                dprintf( 2, "[stack-ovf]   w%d density: %llx x%d\n",
                                         w, (unsigned long long)uq[k], uqn[k] );
                    }
                }
            }
        }
    }
    return 1;
}

/* ml374: the Mach exception-server thread has NO wine TEB, so every wine log
 * macro reachable from the delivery path dies inside __wine_dbg_output. Two
 * runs were lost to exactly that — ml370 (my WARN in the cross-thread fault
 * handler) and ml374 (mprotect_exec's unconditional ERR, reached via
 * mprotect_range while servicing a guard page) — and both presented as an
 * unexplained crash at a host pc with NO log lines, because the thread that
 * does the logging is the thread that died.
 *
 * Raising ios_in_mach_exc across the whole call lets shared helpers that
 * legitimately log on normal threads stay silent here, without every one of
 * them needing its own iOS special case. Wrapper rather than inline flag
 * management so no early return can leak the flag set — that would silence
 * wine's logging process-wide and destroy the next run's diagnostics. */
static int ios_mach_deliver_guest_exception( thread_t thread, arm_thread_state64_t *state,
                                             arm_neon_state64_t *neon, int have_neon,
                                             int exception, uintptr_t fault_addr,
                                             uintptr_t thread_teb )
{
    extern volatile int ios_in_mach_exc;
    int r;

    ios_in_mach_exc = 1;
    r = ios_mach_deliver_guest_exception_inner( thread, state, neon, have_neon,
                                                exception, fault_addr, thread_teb );
    ios_in_mach_exc = 0;
    return r;
}
#endif  /* WINE_IOS */


/***********************************************************************
 *           call_user_apc_dispatcher
 */
NTSTATUS call_user_apc_dispatcher( CONTEXT *context, unsigned int flags, ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3,
                                   PNTAPCFUNC func, NTSTATUS status )
{
    struct syscall_frame *frame = get_syscall_frame();
    ULONG64 sp = context ? context->Sp : frame->sp;
    struct apc_stack_layout *stack;

    if (flags) FIXME( "flags %#x are not supported.\n", flags );

    sp &= ~15;
    stack = (struct apc_stack_layout *)sp - 1;
    if (context)
    {
        memmove( &stack->context, context, sizeof(stack->context) );
        NtSetContextThread( GetCurrentThread(), &stack->context );
    }
    else
    {
        stack->context.ContextFlags = CONTEXT_FULL;
        NtGetContextThread( GetCurrentThread(), &stack->context );
        stack->context.X0 = status;
    }
    stack->func      = func;
    stack->args[0]   = arg1;
    stack->args[1]   = arg2;
    stack->args[2]   = arg3;
    stack->alertable = TRUE;

    frame->sp = (ULONG64)stack;
    frame->pc = (ULONG64)IOS_PFUNC(KiUserApcDispatcher);
    frame->restore_flags |= CONTEXT_CONTROL;
    syscall_frame_fixup_for_fastpath( frame );
    return status;
}


/***********************************************************************
 *           call_raise_user_exception_dispatcher
 */
void call_raise_user_exception_dispatcher(void)
{
    get_syscall_frame()->pc = (UINT64)pKiRaiseUserExceptionDispatcher;
}


/***********************************************************************
 *           call_user_exception_dispatcher
 */
NTSTATUS call_user_exception_dispatcher( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    struct syscall_frame *frame = get_syscall_frame();
    struct exc_stack_layout *stack;
    NTSTATUS status;

    ios_log_guest_exception( "dispatch", rec, context->Pc );

    status = NtSetContextThread( GetCurrentThread(), context );

    if (status) return status;
    stack = (struct exc_stack_layout *)(context->Sp & ~15) - 1;
    memmove( &stack->context, context, sizeof(*context) );
    memmove( &stack->rec, rec, sizeof(*rec) );
    context_init_empty_xstate( &stack->context, stack->redzone );

    frame->pc = (ULONG64)IOS_PFUNC(KiUserExceptionDispatcher);
    frame->sp = (ULONG64)stack;
    frame->restore_flags |= CONTEXT_CONTROL;
    syscall_frame_fixup_for_fastpath( frame );
    return status;
}


/***********************************************************************
 *           call_user_mode_callback
 */
extern NTSTATUS call_user_mode_callback( ULONG64 user_sp, void **ret_ptr, ULONG *ret_len,
                                         void *func, TEB *teb );
__ASM_GLOBAL_FUNC( call_user_mode_callback,
                   "stp x29, x30, [sp,#-0xd0]!\n\t"
                   __ASM_CFI(".cfi_def_cfa_offset 0xd0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xd0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xc8\n\t")
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
                   "stp d8,  d9,  [x29, #0x60]\n\t"
                   "stp d10, d11, [x29, #0x70]\n\t"
                   "stp d12, d13, [x29, #0x80]\n\t"
                   "stp d14, d15, [x29, #0x90]\n\t"
                   "stp x1, x2, [x29, #0xa0]\n\t" /* ret_ptr, ret_len */
                   "mov x18, x4\n\t"              /* teb */
                   "mrs x1, fpcr\n\t"
                   "mrs x2, fpsr\n\t"
                   "bfi x1, x2, #0, #32\n\t"
                   "ldr x2, [x18]\n\t"            /* teb->Tib.ExceptionList */
                   "stp x1, x2, [x29, #0xb0]\n\t"

                   "ldr x7, [x18, #0x378]\n\t"    /* thread_data->syscall_frame */
                   "sub x1, sp, #0x330\n\t"       /* sizeof(struct syscall_frame) */
                   "str x1, [x18, #0x378]\n\t"    /* thread_data->syscall_frame */
                   "add x8, x29, #0xd0\n\t"
                   "stp x7, x8, [x1, #0x110]\n\t" /* frame->prev_frame,syscall_cfa */
                   "ldr w11, [x18, #0x380]\n\t"   /* thread_data->syscall_trace */
                   "cbnz x11, 1f\n\t"
                   /* switch to user stack */
                   "mov sp, x0\n\t"               /* user_sp */
                   "br x3\n"
                   "1:\tmov x19, x18\n\t"         /* teb */
                   "mov x20, x0\n\t"              /* user_sp */
                   "mov x21, x3\n\t"              /* func */
                   "mov sp, x1\n\t"
                   "ldr x1, [x20]\n\t"            /* args */
                   "ldp w2, w0, [x20, #8]\n\t"    /* len, id */
                   "str x0, [x29, #0xc0]\n\t"     /* id */
                   "bl " __ASM_NAME("trace_usercall") "\n\t"
                   "mov x18, x19\n\t"             /* teb */
                   "mov sp, x20\n\t"              /* user_sp */
                   "br x21" )


/***********************************************************************
 *           user_mode_callback_return
 */
extern void DECLSPEC_NORETURN user_mode_callback_return( void *ret_ptr, ULONG ret_len,
                                                         NTSTATUS status, TEB *teb );
__ASM_GLOBAL_FUNC( user_mode_callback_return,
                   "ldr x4, [x3, #0x378]\n\t"     /* thread_data->syscall_frame */
                   "ldp x5, x29, [x4,#0x110]\n\t" /* prev_frame,syscall_cfa */
                   "str x5, [x3, #0x378]\n\t"     /* thread_data->syscall_frame */
                   "sub x29, x29, #0xd0\n\t"
                   __ASM_CFI(".cfi_def_cfa_register 29\n\t")
                   __ASM_CFI(".cfi_rel_offset 29,0x00\n\t")
                   __ASM_CFI(".cfi_rel_offset 30,0x08\n\t")
                   __ASM_CFI(".cfi_rel_offset 19,0x10\n\t")
                   __ASM_CFI(".cfi_rel_offset 20,0x18\n\t")
                   __ASM_CFI(".cfi_rel_offset 21,0x20\n\t")
                   __ASM_CFI(".cfi_rel_offset 22,0x28\n\t")
                   __ASM_CFI(".cfi_rel_offset 23,0x30\n\t")
                   __ASM_CFI(".cfi_rel_offset 24,0x38\n\t")
                   __ASM_CFI(".cfi_rel_offset 25,0x40\n\t")
                   __ASM_CFI(".cfi_rel_offset 26,0x48\n\t")
                   __ASM_CFI(".cfi_rel_offset 27,0x50\n\t")
                   __ASM_CFI(".cfi_rel_offset 28,0x58\n\t")
                   "ldp x5, x6, [x29, #0xb0]\n\t"
                   "str x6, [x3]\n\t"             /* teb->Tib.ExceptionList */
                   "msr fpcr, x5\n\t"
                   "lsr x5, x5, #32\n\t"
                   "msr fpsr, x5\n\t"
                   "ldp x5, x6, [x29, #0xa0]\n\t" /* ret_ptr, ret_len */
                   "str x0, [x5]\n\t"             /* ret_ptr */
                   "str w1, [x6]\n\t"             /* ret_len */
                   "ldr w11, [x3, #0x380]\n\t"    /* thread_data->syscall_trace */
                   "cbz x11, 1f\n\t"
                   "ldr w3, [x29, #0xc0]\n\t"     /* id */
                   "mov x19, x2\n\t"
                   "bl " __ASM_NAME("trace_userret") "\n\t"
                   "mov x2, x19\n"                /* status */
                   "1:\tldp x19, x20, [x29, #0x10]\n\t"
                   __ASM_CFI(".cfi_same_value 19\n\t")
                   __ASM_CFI(".cfi_same_value 20\n\t")
                   "ldp x21, x22, [x29, #0x20]\n\t"
                   __ASM_CFI(".cfi_same_value 21\n\t")
                   __ASM_CFI(".cfi_same_value 22\n\t")
                   "ldp x23, x24, [x29, #0x30]\n\t"
                   __ASM_CFI(".cfi_same_value 23\n\t")
                   __ASM_CFI(".cfi_same_value 24\n\t")
                   "ldp x25, x26, [x29, #0x40]\n\t"
                   __ASM_CFI(".cfi_same_value 25\n\t")
                   __ASM_CFI(".cfi_same_value 26\n\t")
                   "ldp x27, x28, [x29, #0x50]\n\t"
                   __ASM_CFI(".cfi_same_value 27\n\t")
                   __ASM_CFI(".cfi_same_value 28\n\t")
                   "ldp d8,  d9,  [x29, #0x60]\n\t"
                   "ldp d10, d11, [x29, #0x70]\n\t"
                   "ldp d12, d13, [x29, #0x80]\n\t"
                   "ldp d14, d15, [x29, #0x90]\n\t"
                   "mov x0, x2\n\t"               /* status */
                   "mov sp, x29\n\t"
                   "ldp x29, x30, [sp], #0xd0\n\t"
                   "ret" )


/***********************************************************************
 *           user_mode_abort_thread
 */
extern void DECLSPEC_NORETURN user_mode_abort_thread( NTSTATUS status, struct syscall_frame *frame );
__ASM_GLOBAL_FUNC( user_mode_abort_thread,
                   "ldr x1, [x1, #0x118]\n\t"    /* frame->syscall_cfa */
                   "sub x29, x1, #0xc0\n\t"
                   /* switch to kernel stack */
                   "mov sp, x29\n\t"
                   __ASM_CFI(".cfi_def_cfa 29,0xc0\n\t")
                   __ASM_CFI(".cfi_offset 29,-0xc0\n\t")
                   __ASM_CFI(".cfi_offset 30,-0xb8\n\t")
                   __ASM_CFI(".cfi_offset 19,-0xb0\n\t")
                   __ASM_CFI(".cfi_offset 20,-0xa8\n\t")
                   __ASM_CFI(".cfi_offset 21,-0xa0\n\t")
                   __ASM_CFI(".cfi_offset 22,-0x98\n\t")
                   __ASM_CFI(".cfi_offset 23,-0x90\n\t")
                   __ASM_CFI(".cfi_offset 24,-0x88\n\t")
                   __ASM_CFI(".cfi_offset 25,-0x80\n\t")
                   __ASM_CFI(".cfi_offset 26,-0x78\n\t")
                   __ASM_CFI(".cfi_offset 27,-0x70\n\t")
                   __ASM_CFI(".cfi_offset 28,-0x68\n\t")
                   "bl " __ASM_NAME("abort_thread") )


/***********************************************************************
 *           KeUserModeCallback
 */
NTSTATUS KeUserModeCallback( ULONG id, const void *args, ULONG len, void **ret_ptr, ULONG *ret_len )
{
    struct syscall_frame *frame = get_syscall_frame();
    ULONG64 sp = (frame->sp - offsetof( struct callback_stack_layout, args_data[len] ) - 16) & ~15;
    struct callback_stack_layout *stack = (struct callback_stack_layout *)sp;

    if ((char *)ntdll_get_thread_data()->kernel_stack + min_kernel_stack > (char *)&frame)
        return STATUS_STACK_OVERFLOW;

    stack->args = stack->args_data;
    stack->len  = len;
    stack->id   = id;
    stack->lr   = frame->lr;
    stack->sp   = frame->sp;
    stack->pc   = frame->pc;
    memcpy( stack->args_data, args, len );
    {
        /* Thing B (#16) diag: which dispatcher does this thread's callback
         * resolve to? A SESSION-peb thread resolving to a child's EC
         * dispatcher is the wedge precursor (explorer executing the child
         * EC ntdll's exit thunks → blr x16=1). Log the first few callbacks
         * per boot for context plus EVERY session-thread/child-dispatcher
         * cross-resolution (should never happen). */
        extern PEB *peb;
        void *disp = IOS_PFUNC(KiUserCallbackDispatcher);
        int cross = (disp != pKiUserCallbackDispatcher) && (NtCurrentTeb()->Peb == peb);
        static volatile int kcb_logged = 0;
        if ((kcb_logged < 5 || cross) && kcb_logged < 40)
        {
            __sync_add_and_fetch(&kcb_logged, 1);
            dprintf(2, "[kcb] tid=%04x teb=%p peb=%p id=%u disp=%p session_disp=%p%s\n",
                    (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
                    (void *)NtCurrentTeb(), (void *)NtCurrentTeb()->Peb, id,
                    disp, pKiUserCallbackDispatcher,
                    cross ? "  <-- SESSION THREAD, CHILD DISPATCHER (BUG)" : "");
        }
        return call_user_mode_callback( sp, ret_ptr, ret_len, disp, NtCurrentTeb() );
    }
}


/***********************************************************************
 *           NtCallbackReturn  (NTDLL.@)
 */
NTSTATUS WINAPI NtCallbackReturn( void *ret_ptr, ULONG ret_len, NTSTATUS status )
{
    if (!get_syscall_frame()->prev_frame) return STATUS_NO_CALLBACK_ACTIVE;
    user_mode_callback_return( ret_ptr, ret_len, status, NtCurrentTeb() );
}


/***********************************************************************
 *           handle_syscall_fault
 *
 * Handle a page fault happening during a system call.
 */
static BOOL handle_syscall_fault( ucontext_t *context, EXCEPTION_RECORD *rec )
{
    struct syscall_frame *frame = get_syscall_frame();
    DWORD i;

    if (!is_inside_syscall( SP_sig(context) )) return FALSE;

    TRACE( "code=%x flags=%x addr=%p pc=%p tid=%04x\n",
           rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress,
           (void *)PC_sig(context), GetCurrentThreadId() );
    for (i = 0; i < rec->NumberParameters; i++)
        TRACE( " info[%d]=%016lx\n", i, rec->ExceptionInformation[i] );

    TRACE("  x0=%016lx  x1=%016lx  x2=%016lx  x3=%016lx\n",
          (DWORD64)REGn_sig(0, context), (DWORD64)REGn_sig(1, context),
          (DWORD64)REGn_sig(2, context), (DWORD64)REGn_sig(3, context) );
    TRACE("  x4=%016lx  x5=%016lx  x6=%016lx  x7=%016lx\n",
          (DWORD64)REGn_sig(4, context), (DWORD64)REGn_sig(5, context),
          (DWORD64)REGn_sig(6, context), (DWORD64)REGn_sig(7, context) );
    TRACE("  x8=%016lx  x9=%016lx x10=%016lx x11=%016lx\n",
          (DWORD64)REGn_sig(8, context), (DWORD64)REGn_sig(9, context),
          (DWORD64)REGn_sig(10, context), (DWORD64)REGn_sig(11, context) );
    TRACE(" x12=%016lx x13=%016lx x14=%016lx x15=%016lx\n",
          (DWORD64)REGn_sig(12, context), (DWORD64)REGn_sig(13, context),
          (DWORD64)REGn_sig(14, context), (DWORD64)REGn_sig(15, context) );
    TRACE(" x16=%016lx x17=%016lx x18=%016lx x19=%016lx\n",
          (DWORD64)REGn_sig(16, context), (DWORD64)REGn_sig(17, context),
          (DWORD64)REGn_sig(18, context), (DWORD64)REGn_sig(19, context) );
    TRACE(" x20=%016lx x21=%016lx x22=%016lx x23=%016lx\n",
          (DWORD64)REGn_sig(20, context), (DWORD64)REGn_sig(21, context),
          (DWORD64)REGn_sig(22, context), (DWORD64)REGn_sig(23, context) );
    TRACE(" x24=%016lx x25=%016lx x26=%016lx x27=%016lx\n",
          (DWORD64)REGn_sig(24, context), (DWORD64)REGn_sig(25, context),
          (DWORD64)REGn_sig(26, context), (DWORD64)REGn_sig(27, context) );
    TRACE(" x28=%016lx  fp=%016lx  lr=%016lx  sp=%016lx\n",
          (DWORD64)REGn_sig(28, context), (DWORD64)FP_sig(context),
          (DWORD64)LR_sig(context), (DWORD64)SP_sig(context) );

    if (ntdll_get_thread_data()->jmp_buf)
    {
        TRACE( "returning to handler\n" );
        REGn_sig(0, context) = (ULONG_PTR)ntdll_get_thread_data()->jmp_buf;
        REGn_sig(1, context) = 1;
        PC_sig(context)      = (ULONG_PTR)longjmp;
        ntdll_get_thread_data()->jmp_buf = NULL;
    }
    else
    {
        TRACE( "returning to user mode ip=%p ret=%08x\n", (void *)frame->pc, rec->ExceptionCode );
        REGn_sig(0, context)  = rec->ExceptionCode;
        REGn_sig(18, context) = (ULONG_PTR)NtCurrentTeb();
        SP_sig(context)       = (ULONG_PTR)frame;
        PC_sig(context)       = (ULONG_PTR)__wine_syscall_dispatcher_return;
    }
    return TRUE;
}


/**********************************************************************
 *		ios_fixup_x18_for_return
 *
 * Called before returning from a signal handler on iOS.
 * iOS sigreturn zeroes x18 (the TEB/platform register).  If the
 * interrupted code was in the JIT pool, redirect through the TEB
 * trampoline so x18 is restored before the code resumes.
 */
#ifdef WINE_IOS
static inline void ios_fixup_x18_for_return( ucontext_t *context )
{
    extern void *ios_jit_rx_base_global;
    extern size_t ios_jit_pool_size_global;

    if (!ios_my_trampoline || !ios_teb_for_signals) return;

    uintptr_t pc = PC_sig(context);
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    size_t sz = ios_jit_pool_size_global;

    /* madeira-bcd pool-low: FEX code in region C needs x18 back exactly like
     * the pool tail's */
    if ((rx && pc >= rx && pc < rx + sz) || ios_jit_low_contains( pc ))
    {
        REGn_sig(17, context) = pc;
        PC_sig(context) = (uintptr_t)ios_my_trampoline;
    }
}

static inline void ios_track_signal( int sig, ucontext_t *context )
{
    extern void *ios_jit_rx_base_global;
    extern size_t ios_jit_pool_size_global;
    ios_signal_total++;
    ios_signal_last = sig;
    uintptr_t pc = PC_sig(context);
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    size_t sz = ios_jit_pool_size_global;
    if ((rx && pc >= rx && pc < rx + sz) || ios_jit_low_contains( pc ))   /* madeira-bcd pool-low */
        ios_signal_in_pe++;
}

#endif


