/* Part of signal_arm64_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Ill_handler and the store, unaligned and sub-floor window emulation. Same copyright and licence as signal_arm64_ios.c. */
/**********************************************************************
 *		ill_handler
 *
 * Handler for SIGILL.
 */
static void ill_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { EXCEPTION_ILLEGAL_INSTRUCTION };
    ucontext_t *context = sigcontext;
#ifdef WINE_IOS
    const int ill_dbg_ok = ios_make_wine_logging_safe();  /* ml375: before any ERR */
    ios_track_signal( signal, context );
    if (ill_dbg_ok) ERR("ILL at pc=%p\n", (void*)PC_sig(context));
    else dprintf( 2, "ILL at pc=%p (no TEB — wine logging unsafe)\n", (void*)PC_sig(context) );
    {
        /* iOS-Madeira diagnostic: when we ILL on a zero/empty page, dump full
         * register state + walk back FP chain to find who BR'd here. */
        uint64_t pc  = (uint64_t)PC_sig(context);
        uint64_t lr  = (uint64_t)REGn_sig(30, context);
        uint64_t fp  = (uint64_t)REGn_sig(29, context);
        uint64_t sp  = (uint64_t)arm_thread_state64_get_sp(context->uc_mcontext->__ss);
        uint64_t x0  = (uint64_t)REGn_sig(0,  context);
        uint64_t x9  = (uint64_t)REGn_sig(9,  context);
        uint64_t x16 = (uint64_t)REGn_sig(16, context);
        uint64_t x17 = (uint64_t)REGn_sig(17, context);
        uint64_t x18 = (uint64_t)REGn_sig(18, context);
        uint64_t x19 = (uint64_t)REGn_sig(19, context);
        ERR("ILL diag: pc=0x%llx lr=0x%llx fp=0x%llx sp=0x%llx\n",
            (unsigned long long)pc, (unsigned long long)lr,
            (unsigned long long)fp, (unsigned long long)sp);
        ERR("ILL diag: x0=0x%llx x9=0x%llx x16=0x%llx x17=0x%llx x18=0x%llx x19=0x%llx\n",
            (unsigned long long)x0, (unsigned long long)x9,
            (unsigned long long)x16, (unsigned long long)x17,
            (unsigned long long)x18, (unsigned long long)x19);
        /* Decode caller_insn at LR-4 (the BL/BLR that brought us here) */
        if (lr >= 0x100000000ULL && lr < 0x800000000ULL) {
            vm_size_t outsz = 4;
            uint32_t caller_insn = 0;
            if (vm_read_overwrite(mach_task_self(), lr - 4, 4,
                                  (vm_address_t)&caller_insn, &outsz) == KERN_SUCCESS)
                ERR("ILL diag: caller_insn @lr-4 = 0x%08x\n", caller_insn);
        }
        /* Walk back FP chain (each frame: fp[0]=prev_fp, fp[1]=saved_lr) */
        for (int frame = 0; frame < 8 && fp >= 0x100000000ULL && fp < 0x800000000ULL; frame++) {
            vm_size_t outsz = 8;
            uint64_t prev_fp = 0, saved_lr = 0;
            if (vm_read_overwrite(mach_task_self(), fp,     8, (vm_address_t)&prev_fp,  &outsz) != KERN_SUCCESS) break;
            outsz = 8;
            if (vm_read_overwrite(mach_task_self(), fp + 8, 8, (vm_address_t)&saved_lr, &outsz) != KERN_SUCCESS) break;
            ERR("ILL diag: frame[%d] fp=0x%llx saved_lr=0x%llx\n",
                frame, (unsigned long long)fp, (unsigned long long)saved_lr);
            if (prev_fp <= fp) break;
            fp = prev_fp;
        }
        /* iOS-Madeira 2026-07-06 (Thumper desktop ILL): both crashes were the
         * FEX dispatcher's ExitFunctionLinker thunk doing `ldr x2,[x28,#0x630];
         * blr x2` with a corrupted Pointers.ExitFunctionLink (pointed into a
         * mid-emission block tail instead of the C++ resolver). Dump the
         * evidence at crash time: x28 (STATE), x1 (link Record ptr), x2 (the
         * loaded target), the CpuStateFrame Pointers region around +0x630,
         * and the Record bytes — distinguishes single-field corruption vs
         * wild-store span vs corrupt Record. */
        {
            uint64_t x1  = (uint64_t)REGn_sig(1,  context);
            uint64_t x2  = (uint64_t)REGn_sig(2,  context);
            uint64_t x28 = (uint64_t)REGn_sig(28, context);
            uint64_t x6  = (uint64_t)REGn_sig(6,  context);
            uint64_t x10 = (uint64_t)REGn_sig(10, context);
            uint64_t x11 = (uint64_t)REGn_sig(11, context);
            ERR("ILL diag: x1=0x%llx x2=0x%llx x28=0x%llx\n",
                (unsigned long long)x1, (unsigned long long)x2, (unsigned long long)x28);
            /* x6 = guest RIP and x11 = branch target in FEX's inline exit
             * dispatch (`ret x11`); x10 = dispatcher's CompileBlock-return
             * target (`br x10`). Whichever equals pc names the faulting
             * branch. */
            ERR("ILL diag: x6=0x%llx x10=0x%llx x11=0x%llx (pc==x11? %d pc==x10? %d)\n",
                (unsigned long long)x6, (unsigned long long)x10, (unsigned long long)x11,
                x11 == pc, x10 == pc);
            /* FEX inline L1 exit-dispatch reads {L1Ptr, L1Mask} at STATE+0xa0
             * and the entry pair {host, guest} at L1Ptr + (rip & mask)<<?.
             * Dump the entry for x6 so a torn pair is visible at crash time.
             * Windows-heap frames live at 0x70xxxxxxxx — include them. */
            if (x28 >= 0x100000000ULL && x28 < 0x8000000000ULL)
            {
                uint64_t l1pair[2] = {0, 0}, entry[2] = {0, 0};
                vm_size_t osz = sizeof(l1pair);
                if (vm_read_overwrite(mach_task_self(), x28 + 0xa0, sizeof(l1pair),
                                      (vm_address_t)l1pair, &osz) == KERN_SUCCESS)
                {
                    /* mask is pre-shifted per dispatcher code: and x11, mask, rip<<4 */
                    uint64_t eaddr = l1pair[0] + ((x6 << 4) & l1pair[1]);
                    ERR("ILL diag: L1ptr=0x%llx L1mask=0x%llx entry@0x%llx\n",
                        (unsigned long long)l1pair[0], (unsigned long long)l1pair[1],
                        (unsigned long long)eaddr);
                    osz = sizeof(entry);
                    if (l1pair[0] &&
                        vm_read_overwrite(mach_task_self(), eaddr, sizeof(entry),
                                          (vm_address_t)entry, &osz) == KERN_SUCCESS)
                        ERR("ILL diag: L1 entry: host=0x%llx guest=0x%llx (guest==x6? %d host==pc? %d)\n",
                            (unsigned long long)entry[0], (unsigned long long)entry[1],
                            entry[1] == x6, entry[0] == pc);
                }
            }
            if (x28 >= 0x100000000ULL && x28 < 0x800000000ULL)
            {
                uint64_t words[32];
                vm_size_t outsz = sizeof(words);
                if (vm_read_overwrite(mach_task_self(), x28 + 0x5c0, sizeof(words),
                                      (vm_address_t)words, &outsz) == KERN_SUCCESS)
                {
                    for (int w = 0; w < 32; w += 4)
                        ERR("ILL diag: STATE+0x%03x: %016llx %016llx %016llx %016llx\n",
                            0x5c0 + w * 8,
                            (unsigned long long)words[w],   (unsigned long long)words[w+1],
                            (unsigned long long)words[w+2], (unsigned long long)words[w+3]);
                }
                /* State.rip lives in the first 0x100 of the frame */
                outsz = sizeof(words);
                if (vm_read_overwrite(mach_task_self(), x28, 0x40,
                                      (vm_address_t)words, &outsz) == KERN_SUCCESS)
                    ERR("ILL diag: STATE+0: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
                        (unsigned long long)words[0], (unsigned long long)words[1],
                        (unsigned long long)words[2], (unsigned long long)words[3],
                        (unsigned long long)words[4], (unsigned long long)words[5],
                        (unsigned long long)words[6], (unsigned long long)words[7]);
            }
            if (x1 >= 0x100000000ULL && x1 < 0x800000000ULL)
            {
                uint64_t rec[6];
                vm_size_t outsz = sizeof(rec);
                if (vm_read_overwrite(mach_task_self(), x1, sizeof(rec),
                                      (vm_address_t)rec, &outsz) == KERN_SUCCESS)
                    ERR("ILL diag: Record@x1: %016llx %016llx %016llx %016llx %016llx %016llx\n",
                        (unsigned long long)rec[0], (unsigned long long)rec[1],
                        (unsigned long long)rec[2], (unsigned long long)rec[3],
                        (unsigned long long)rec[4], (unsigned long long)rec[5]);
            }
        }
        /* iOS-Madeira: also dump JIT pool here (the Mach UNHANDLED path may not
         * fire for ILL since we deliver via setup_exception). One-shot. */
        {
            static volatile int ill_dumped = 0;
            if (__sync_bool_compare_and_swap(&ill_dumped, 0, 1))
                ios_dump_jit_pool( "ILL diag" );
        }
    }
#endif

    if (!(PSTATE_sig( context ) & 0x10) && /* AArch64 (not WoW) */
        !(PC_sig( context ) & 3))
    {
        ULONG instr = *(ULONG *)PC_sig( context );
        /* emulate mrs xN, CurrentEL */
        if ((instr & ~0x1f) == 0xd5384240) {
            ULONG reg = instr & 0x1f;
            /* ignore writes to xzr */
            if (reg != 31) REGn_sig(reg, context) = 0;
            PC_sig(context) += 4;
#ifdef WINE_IOS
            ios_fixup_x18_for_return( context );
#endif
            return;
        }
    }

    setup_exception( sigcontext, &rec );
}


/**********************************************************************
 *		ios_emulate_store
 *
 * Emulate an ARM64 store instruction, writing through the JIT pool's
 * RW view instead of the RX view. Returns 1 on success, 0 if the
 * instruction isn't a recognized store.
 */
#ifdef WINE_IOS
static inline uint64_t ios_get_reg(ucontext_t *ctx, int r)
{
    if (r == 31) return 0;  /* XZR */
    /* REGn_sig(0..30) works because __x[29]=__fp, __x[30]=__lr in memory layout */
    return REGn_sig(r, ctx);
}

static int ios_emulate_store(ucontext_t *ctx, uint32_t insn, uintptr_t rw_addr)
{
    int rt = insn & 0x1F;
    uint64_t rt_val = ios_get_reg(ctx, rt);

    /* STR/STRB/STRH (unsigned offset):
     * size[31:30] 111 0 01 00 imm12 Rn Rt
     * Matching bits [29:22] = 11100100 */
    if ((insn & 0x3FC00000) == 0x39000000)
    {
        int size = (insn >> 30) & 3;
        switch (size) {
            case 0: *(uint8_t *)rw_addr = (uint8_t)rt_val; return 1;
            case 1: *(uint16_t *)rw_addr = (uint16_t)rt_val; return 1;
            case 2: *(uint32_t *)rw_addr = (uint32_t)rt_val; return 1;
            case 3: *(uint64_t *)rw_addr = rt_val; return 1;
        }
    }

    /* STUR / STR pre-index / STR post-index (9-bit immediate):
     * size[31:30] 111 0 00 00 0 imm9 type Rn Rt
     * Matching bits [29:21] = 111000000 */
    if ((insn & 0x3FE00000) == 0x38000000)
    {
        int size = (insn >> 30) & 3;
        switch (size) {
            case 0: *(uint8_t *)rw_addr = (uint8_t)rt_val; return 1;
            case 1: *(uint16_t *)rw_addr = (uint16_t)rt_val; return 1;
            case 2: *(uint32_t *)rw_addr = (uint32_t)rt_val; return 1;
            case 3: *(uint64_t *)rw_addr = rt_val; return 1;
        }
    }

    /* STP (signed offset / pre-index / post-index):
     * opc[31:30] 101 0 0xx 0 imm7 Rt2 Rn Rt
     * Matching bits [29:25,22] = 10100_0, various x bits for variant */
    if ((insn & 0x3E400000) == 0x28000000)
    {
        int opc = (insn >> 30) & 3;
        int rt2 = (insn >> 10) & 0x1F;
        uint64_t rt2_val = ios_get_reg(ctx, rt2);

        if (opc & 2) {  /* 64-bit */
            *(uint64_t *)rw_addr = rt_val;
            *(uint64_t *)(rw_addr + 8) = rt2_val;
        } else {  /* 32-bit */
            *(uint32_t *)rw_addr = (uint32_t)rt_val;
            *(uint32_t *)(rw_addr + 4) = (uint32_t)rt2_val;
        }
        return 1;
    }

    /* STR (register offset):
     * size[31:30] 111 0 00 01 Rm option S 10 Rn Rt */
    if ((insn & 0x3FE00C00) == 0x38200800)
    {
        int size = (insn >> 30) & 3;
        switch (size) {
            case 0: *(uint8_t *)rw_addr = (uint8_t)rt_val; return 1;
            case 1: *(uint16_t *)rw_addr = (uint16_t)rt_val; return 1;
            case 2: *(uint32_t *)rw_addr = (uint32_t)rt_val; return 1;
            case 3: *(uint64_t *)rw_addr = rt_val; return 1;
        }
    }

    /* ml408 (#66→#60): CAS/CASA/CASL/CASAL Ws/Xs, Wt/Xt, [Xn] — LSE
     * compare-and-swap on the pool RX alias. The [atomic-mem] probe settled
     * ml264's open question: the page is R-X (prot=5), so ANY write faults —
     * reading (b) was right, and the fix is the same RW-alias redirect the
     * plain stores above use. Acquire/release collapse to SEQ_CST (stronger).
     * Rs receives the observed old value (zero-extended for W forms).
     * 1x00 1000 1L1 Rs o0 11111 Rn Rt — ml408 killer: 0x88eafe89
     * CASAL W10, W9, [X20]; ml264 also saw 0xc8f1fd60 CASAL X17, X0, [X11]. */
    if ((insn & 0xBFA07C00) == 0x88A07C00)
    {
        int rs = (insn >> 16) & 0x1F;
        int sz64 = (insn >> 30) & 1;
        static int cas_log;
        if (sz64)
        {
            uint64_t exp = ios_get_reg(ctx, rs);
            __atomic_compare_exchange_n((uint64_t *)rw_addr, &exp, rt_val,
                                        0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            if (rs != 31) REGn_sig(rs, ctx) = exp;
        }
        else
        {
            uint32_t exp = (uint32_t)ios_get_reg(ctx, rs);
            __atomic_compare_exchange_n((uint32_t *)rw_addr, &exp, (uint32_t)rt_val,
                                        0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            if (rs != 31) REGn_sig(rs, ctx) = exp;
        }
        if (cas_log++ < 8)
            ERR("[cas-emu] CAS%s insn=0x%08x rw=%p rs=%d rt=%d -> emulated on RW alias\n",
                sz64 ? "64" : "32", insn, (void *)rw_addr, rs, rt);
        return 1;
    }

    /* ml1208: CASB/CASH and their A/L/AL forms (0x08A07C00 / 0x48A07C00), which
     * FEX emits for `lock cmpxchg byte/word`. A 64-bit program with a fixed base
     * below 4 GB did one on its .bss at 0x741310 (`ml939 UNHANDLED encoding
     * 0x08ebff66` = casalb w11, w6, [x27]): SEGV, c0000005. Same contract as the
     * CAS branch above. An unaligned halfword cannot go through the hardware CAS,
     * so it is done non-atomically. */
    if ((insn & 0xBFA07C00) == 0x08A07C00)
    {
        int rs = (insn >> 16) & 0x1F;
        static int casbh_log;
        if (insn & 0x40000000)
        {
            uint16_t exp = (uint16_t)ios_get_reg(ctx, rs);
            if (rw_addr & 1)
            {
                uint16_t cur;
                memcpy( &cur, (void *)rw_addr, 2 );
                if (cur == exp) { uint16_t v = (uint16_t)rt_val; memcpy( (void *)rw_addr, &v, 2 ); }
                exp = cur;
            }
            else
                __atomic_compare_exchange_n((uint16_t *)rw_addr, &exp, (uint16_t)rt_val,
                                            0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            if (rs != 31) REGn_sig(rs, ctx) = exp;
        }
        else
        {
            uint8_t exp = (uint8_t)ios_get_reg(ctx, rs);
            __atomic_compare_exchange_n((uint8_t *)rw_addr, &exp, (uint8_t)rt_val,
                                        0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
            if (rs != 31) REGn_sig(rs, ctx) = exp;
        }
        if (casbh_log++ < 8)
            ERR("[cas-emu] ml1208 CAS%s insn=0x%08x rw=%p rs=%d rt=%d -> emulated\n",
                (insn & 0x40000000) ? "H" : "B", insn, (void *)rw_addr, rs, rt);
        return 1;
    }

    /* CASP/CASPA/CASPL/CASPAL pair forms (ml264: 0x4866fd64/0x4866fe6a):
     * 0sz0 1000 0L1 Rs o0 11111 Rn Rt, Rs/Rt even. Hardware caspal on the RW
     * alias so we stay atomic against FEX's own native RW-alias atomics. */
    if ((insn & 0xBFA07C00) == 0x08207C00)
    {
        int rs = (insn >> 16) & 0x1F;
        int sz64 = (insn >> 30) & 1;
        static int casp_log;
        uint64_t v0 = ios_get_reg(ctx, rs), v1 = ios_get_reg(ctx, rs + 1);
        uint64_t v2 = ios_get_reg(ctx, rt), v3 = ios_get_reg(ctx, rt + 1);
        register uint64_t c0 asm("x0") = v0;
        register uint64_t c1 asm("x1") = v1;
        register uint64_t c2 asm("x2") = v2;
        register uint64_t c3 asm("x3") = v3;
        if (sz64)
            asm volatile(".arch_extension lse\n\tcaspal x0, x1, x2, x3, [%4]"
                         : "+r"(c0), "+r"(c1)
                         : "r"(c2), "r"(c3), "r"(rw_addr)
                         : "memory");
        else
            asm volatile(".arch_extension lse\n\tcaspal w0, w1, w2, w3, [%4]"
                         : "+r"(c0), "+r"(c1)
                         : "r"(c2), "r"(c3), "r"(rw_addr)
                         : "memory");
        if (rs != 31)
        {
            REGn_sig(rs, ctx) = c0;
            REGn_sig(rs + 1, ctx) = c1;
        }
        if (casp_log++ < 8)
            ERR("[cas-emu] CASP%s insn=0x%08x rw=%p rs=%d rt=%d -> emulated on RW alias\n",
                sz64 ? "64" : "32", insn, (void *)rw_addr, rs, rt);
        return 1;
    }

    /* ml973: FP/SIMD stores -- every width, all three addressing forms.
     *
     * rdr36 ended on `ml939 UNHANDLED encoding 0x3d800000` = `str q0, [x0]`,
     * a 128-bit SIMD store in its UNSIGNED-OFFSET form, writing EMP.dll's
     * .data at rva 0x15290. ios_emulate_load matches that encoding and
     * correctly declines it as a store, ios_emulate_store_rel does not cover
     * SIMD singles, and THIS function had no SIMD branch at all -- so the
     * sub-floor service path had nothing to hand it to.
     *
     * (ml972 put this in ios_emulate_unaligned_guest_access by mistake, which
     * is a different function on a different path -- the Steam-era unaligned
     * emulator -- so it never ran. The sub-floor path is
     * ios_subfloor_service -> load, then store_rel, then THIS function.)
     *
     * Width follows the architectural size:opc[1] pairing, the same formula
     * ios_emulate_load and ios_subfloor_classify already use: size 00/01/10/11
     * with opc[1]==0 give 1/2/4/8 bytes, and size==00 with opc[1]==1 is the
     * 128-bit Q form. Any other size with opc[1] set is unallocated and is
     * declined rather than guessed at.
     *
     * No base-register writeback here, deliberately: ios_subfloor_writeback()
     * applies the pre/post index once, for loads and stores alike, after a
     * successful emulation. `rw_addr` already carries the computed offset. */
    if ((insn & 0x3F000000) == 0x3D000000 ||        /* unsigned offset */
        (insn & 0x3F200000) == 0x3C000000 ||        /* 9-bit immediate */
        (insn & 0x3F200C00) == 0x3C200800)          /* register offset */
    {
        const int v_size = (insn >> 30) & 3;
        const int v_opc  = (insn >> 22) & 3;
        int w;

        if (v_opc & 1) return 0;                    /* load -- not ours */
        if ((v_opc & 2) && v_size != 0) return 0;   /* unallocated */
        if (!ios_neon_valid) return 0;              /* ml974: __ns is not real */
        w = (v_size == 0 && (v_opc & 2)) ? 16 : (1 << v_size);
        {
            static unsigned long long simd_n;
            unsigned long long n = __sync_add_and_fetch( &simd_n, 1 );
            if (n <= 4 || (n & 0xFFFF) == 1)
                dprintf( 2, "[simd-str] ml973 #%llu emulated FP/SIMD store insn=%#010x "
                         "size=%d opc=%d width=%d addr=%#llx\n",
                         n, insn, v_size, v_opc, w, (unsigned long long)rw_addr );
        }
        memcpy( (void *)rw_addr, &ctx->uc_mcontext->__ns.__v[rt], w );
        return 1;
    }

    return 0;  /* unhandled instruction */
}

/**********************************************************************
 *		ios_emulate_unaligned_guest_access
 *
 * iOS-Madeira ml479 (#83): emulate a PLAIN (non-atomic) misaligned
 * load/store IN PLACE via memcpy and return 1, or 0 if the form isn't
 * safely emulatable. Guest x86 MOVs may be arbitrarily misaligned and
 * MUST succeed; some guest regions (PA-band SM_COW pages, hit by the
 * 2026-08-04 Steam client) alignment-fault them at the hardware level
 * (SIGBUS/BUS_ADRALN on a readable+writable page). memcpy is byte-wise
 * so it cannot re-raise the alignment fault inside the handler. Only
 * no-writeback addressing forms are accepted (unsigned offset, register
 * offset, unscaled LDUR/STUR, signed-offset LDP/STP) — pre/post-index
 * would need a base-register update and FEX doesn't emit them for guest
 * memory ops. Atomic/exclusive/SIMD forms return 0 so the caller keeps
 * the existing 80000002 path for FEX's unaligned-atomic machinery.
 */
static int ios_emulate_unaligned_guest_access(ucontext_t *ctx, uint32_t insn, uintptr_t addr)
{
    int rt = insn & 0x1F;

    if ((insn >> 26) & 1) return 0;  /* SIMD/FP: not handled here */

    /* Load/store register — three no-writeback addressing forms, common
     * size/opc decode:
     *   unsigned offset:  size 111 0 01 opc imm12       Rn Rt
     *   register offset:  size 111 0 00 opc 1 Rm opt S 10 Rn Rt
     *   unscaled (LDUR/STUR): size 111 0 00 opc 0 imm9 00 Rn Rt */
    if ((insn & 0x3F000000) == 0x39000000 ||        /* unsigned offset */
        (insn & 0x3F200C00) == 0x38200800 ||        /* register offset */
        (insn & 0x3F200C00) == 0x38000000)          /* unscaled */
    {
        int size = (insn >> 30) & 3;
        int opc  = (insn >> 22) & 3;
        unsigned nbytes = 1u << size;

        if (size == 3 && opc >= 2) return 0;        /* PRFM / undefined */
        if (size == 2 && opc == 3) return 0;        /* undefined */

        if (opc == 0)                               /* store */
        {
            uint64_t v = ios_get_reg(ctx, rt);
            memcpy((void *)addr, &v, nbytes);
        }
        else                                        /* load */
        {
            uint64_t v = 0;
            memcpy(&v, (const void *)addr, nbytes);
            if (opc >= 2)                           /* sign-extending */
            {
                int shift = 64 - 8 * (int)nbytes;
                int64_t sv = (int64_t)(v << shift) >> shift;
                v = (opc == 3) ? (uint64_t)(uint32_t)sv : (uint64_t)sv;
            }
            if (rt != 31) REGn_sig(rt, ctx) = v;
        }
        return 1;
    }

    /* LDP/STP signed offset (no writeback): opc 101 0 010 L imm7 Rt2 Rn Rt */
    if ((insn & 0x3F800000) == 0x29000000)
    {
        int opc2 = (insn >> 30) & 3;
        int L = (insn >> 22) & 1;
        int rt2 = (insn >> 10) & 0x1F;
        unsigned nb = (opc2 & 2) ? 8 : 4;

        if (opc2 == 3) return 0;                    /* undefined */
        if (opc2 == 1 && !L) return 0;              /* STGP/undefined */

        if (!L)
        {
            uint64_t v1 = ios_get_reg(ctx, rt), v2 = ios_get_reg(ctx, rt2);
            memcpy((void *)addr, &v1, nb);
            memcpy((void *)(addr + nb), &v2, nb);
        }
        else
        {
            uint64_t v1 = 0, v2 = 0;
            memcpy(&v1, (const void *)addr, nb);
            memcpy(&v2, (const void *)(addr + nb), nb);
            if (opc2 == 1)                          /* LDPSW */
            {
                v1 = (uint64_t)(int64_t)(int32_t)v1;
                v2 = (uint64_t)(int64_t)(int32_t)v2;
            }
            if (rt != 31) REGn_sig(rt, ctx) = v1;
            if (rt2 != 31) REGn_sig(rt2, ctx) = v2;
        }
        return 1;
    }

    /* iOS-Madeira ml593: STUR/LDUR Qt (128-bit SIMD, UNSCALED immediate)
     *   00 111 1 00 1x 0 imm9 00 Rn Rt   — 0x3c800000 (store) / 0x3cc00000 (load),
     *                                       bits[11:10] == 00 marks unscaled.
     *
     * THIS IS THE INSTRUCTION THAT KILLED THE FIRST SUCCESSFUL STEAM LOGIN
     * (ml592, db 7164). insn=0x3c9f00c0 = `stur q0,[x6,#-16]` to 0x7075e00fc6
     * (6 mod 16) on steamwebhelper's main thread while libcef brought up the
     * post-login UI. This decoder emulated 140 unaligned accesses that run and
     * refused exactly one — the first SIMD-width store it ever saw — which
     * became an unhandled SIGBUS and, since every Windows process here is a
     * thread in ONE Mach task, took the whole app down seconds after
     * `[Logged On]`.
     *
     * ⚠️ NO BASE-REGISTER WRITEBACK. 0x3c9f00c0 is the UNSCALED form; the
     * post-indexed `str q0,[x6],#-16` is 0x3c9f04c0 (bits[11:10] == 01). I first
     * decoded this as post-indexed, which would have added a bogus -16 to x6 on
     * every emulated store — silent translated-state corruption, far worse than
     * the crash it "fixed". Sol caught it; both encodings were then assembled to
     * confirm. addr already carries the imm9 offset, so the access needs nothing
     * but the copy. */
    if ((insn & 0xffa00c00) == 0x3c800000)
    {
        int is_load = (insn >> 22) & 1;
        void *v = &((ucontext_t *)ctx)->uc_mcontext->__ns.__v[rt];

        /* ml974: same hazard as the store path -- a zeroed __ns would be
         * written over guest memory, or a load would land in a block that is
         * never handed back. Pre-existing here; guarded for consistency,
         * because silent corruption is worse than an unhandled fault. */
        if (!ios_neon_valid) return 0;
        if (is_load) memcpy( v, (const void *)addr, 16 );
        else         memcpy( (void *)addr, v, 16 );
        return 1;
    }

    return 0;
}


/***********************************************************************
 *		ml938: SUB-FLOOR IMAGE WINDOWS  (emulate a mapping iOS denies us)
 *
 * iOS reserves the low 4GB of every task. __PAGEZERO sets the map's minimum
 * at exec and the kernel refuses any smaller value -- measured four ways, see
 * reference_ios_va_budget: a 128MB and a 16KB __PAGEZERO are both SIGKILLed at
 * exec, and that stays true with every real segment forced above 4GB, so it is
 * the pagezero SIZE, not segment placement. In a live process the floor reads
 * back as 0x104638000 and a FIXED map anywhere below it returns
 * KERN_INVALID_ADDRESS -- the range is outside the map, not merely occupied.
 * No process on this OS can have a lower floor, so a helper task would not
 * help either.
 *
 * That collides with a real and legal PE shape: an image whose preferred base
 * is below 4GB. Windows maps it there, so it is entitled to hold absolute
 * preferred-base addresses, and packed/obfuscated DLLs do exactly that -- one
 * measured here has 729 aligned 64-bit pointers into its own image in .rdata
 * against a relocation directory of 20 fixups. Relocating it is impossible
 * (the fixups do not cover them) and placing it is impossible (the address
 * does not exist). Both ends are closed.
 *
 * So stop trying to satisfy the address and SERVICE it instead. We cannot make
 * the page exist, but we do not have to: every access to it traps to our Mach
 * handler, which already sees the fault and already classifies the address
 * ("[fault_rip] ... addr=0x1301ad00 kr=1(INVALID_ADDRESS)"). Translate the
 * faulting address into the image's real mapping, emulate the instruction
 * against it, and step over. The guest's view is then exactly what Windows
 * would have given it, byte for byte, with no modification to the image: the
 * low window and the real mapping are the SAME memory, so reads and writes
 * cannot diverge.
 *
 * This is general, not per-image: the window is registered by the PE loader
 * for any image it maps whose preferred base is sub-floor. It also makes the
 * ml936 sub-floor relocation sound -- fixups that WERE applied point high and
 * resolve normally, the ones the directory never covered point low and land
 * here.
 *
 * COST, stated honestly: one Mach exception per access, and the page can never
 * be mapped so there is no amortisation -- this is ~25k/sec territory (the
 * ml648 SWPAL storm measured that rate). Fine for a startup-time unpacker,
 * not fine for a hot loop. The counters below exist to measure which one we
 * have; if the volume is bad the next step is a compile-time fixup in FEX for
 * blocks whose guest RIP lies inside a registered window (a 3-instruction
 * low-address redirect on the ~25 GenerateMemOperand/GetReg(Op->Addr) sites),
 * which costs nothing outside those blocks. Measure before building that.
 */
/* ml1205: windows belong to the pseudo-process that mapped the image. All
 * pseudo-processes share one address space, so a session-wide table could hold
 * only one image per low base: a program with a fixed base of 0x400000 started
 * another one with the same base, the child's window replaced the parent's and
 * the parent ran the child's bytes. A lookup now takes the PEB of the faulting
 * or calling thread; an owner of NULL (KUSER_SHARED_DATA) serves every process,
 * and a lookup without a known PEB falls back to any matching window (the old
 * behaviour). A process's windows are released when it exits
 * (ios_subfloor_release_owner). */
#define IOS_SUBFLOOR_MAX 32
#define IOS_SUBFLOOR_FLOOR 0x100000000ull

struct ios_subfloor_window
{
    uint64_t pref_base;   /* preferred base, below the floor: what the guest uses */
    uint64_t size;        /* SizeOfImage; 0 = free slot */
    uint64_t real_base;   /* where the loader actually mapped it */
    void    *owner_peb;   /* ml1205: the pseudo-process that mapped it, NULL = all */
};
static struct ios_subfloor_window ios_subfloor[IOS_SUBFLOOR_MAX];
static int ios_subfloor_count;
static pthread_mutex_t ios_subfloor_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long ios_subfloor_hits;
static unsigned long long ios_subfloor_unknown;
static unsigned long long ios_subfloor_refused;   /* ml956: backing inaccessible */

void ios_register_subfloor_image( unsigned long long pref_base, unsigned long long size,
                                  unsigned long long real_base, void *owner );
void ios_register_subfloor_image( unsigned long long pref_base, unsigned long long size,
                                  unsigned long long real_base, void *owner )
{
    extern void ios_push_subfloor_window( unsigned long long, unsigned long long,
                                          unsigned long long, void * );
    int i, slot = -1;

    if (!pref_base || !size || pref_base >= IOS_SUBFLOOR_FLOOR) return;
    pthread_mutex_lock( &ios_subfloor_lock );
    for (i = 0; i < ios_subfloor_count; i++)
    {
        if (!ios_subfloor[i].size)
        {
            if (slot < 0) slot = i;
            continue;
        }
        if (ios_subfloor[i].pref_base == pref_base && ios_subfloor[i].owner_peb == owner)
        {
            /* Re-registration within one process (the ml1204 check keeps a
             * relocatable image from getting here over a stripped one). */
            if (ios_subfloor[i].real_base != real_base)
                dprintf( 2, "[subfloor] ml938 window %#llx RE-POINTED %#llx -> %#llx "
                         "(owner %p)\n",
                         pref_base, (unsigned long long)ios_subfloor[i].real_base, real_base, owner );
            ios_subfloor[i].size = 0;
            __sync_synchronize();
            ios_subfloor[i].real_base = real_base;
            __sync_synchronize();
            ios_subfloor[i].size = size;
            pthread_mutex_unlock( &ios_subfloor_lock );
            /* ml951: FEX's copy must follow the re-point. */
            ios_push_subfloor_window( pref_base, real_base, size, owner );
            return;
        }
    }
    if (slot < 0)
    {
        if (ios_subfloor_count >= IOS_SUBFLOOR_MAX)
        {
            pthread_mutex_unlock( &ios_subfloor_lock );
            dprintf( 2, "[subfloor] ml938 window table FULL, dropping %#llx\n", pref_base );
            return;
        }
        slot = ios_subfloor_count;
    }
    i = slot;
    ios_subfloor[i].size      = 0;
    __sync_synchronize();
    ios_subfloor[i].pref_base = pref_base;
    ios_subfloor[i].real_base = real_base;
    ios_subfloor[i].owner_peb = owner;
    __sync_synchronize();
    ios_subfloor[i].size      = size;
    if (i == ios_subfloor_count)
    {
        __sync_synchronize();
        ios_subfloor_count = i + 1;
    }
    pthread_mutex_unlock( &ios_subfloor_lock );
    dprintf( 2, "[subfloor] ml938 window #%d: guest [%#llx,%#llx) -> real %#llx (%llu KB) owner %p\n",
             i, pref_base, pref_base + size, real_base, size / 1024, owner );
    /* ml951: FEX needs this too, so its executable-range query can answer for
     * the low window instead of refusing the entry block. */
    ios_push_subfloor_window( pref_base, real_base, size, owner );
}

/* ml1205: the pseudo-process is gone; free its windows. */
void ios_subfloor_release_owner( void *owner );
void ios_subfloor_release_owner( void *owner )
{
    int i;

    if (!owner) return;
    pthread_mutex_lock( &ios_subfloor_lock );
    for (i = 0; i < ios_subfloor_count; i++)
    {
        if (!ios_subfloor[i].size || ios_subfloor[i].owner_peb != owner) continue;
        dprintf( 2, "[subfloor] ml1205 window #%d %#llx -> %#llx released with its process %p\n",
                 i, (unsigned long long)ios_subfloor[i].pref_base,
                 (unsigned long long)ios_subfloor[i].real_base, owner );
        ios_subfloor[i].size = 0;
        __sync_synchronize();
    }
    pthread_mutex_unlock( &ios_subfloor_lock );
}

/* ml951: enumerate registered windows so virtual_ios.c can push any that were
 * registered before xtajit64's callback existed. Returns 0 when idx is past
 * the end. */
int ios_subfloor_enum( int idx, unsigned long long *low, unsigned long long *real,
                       unsigned long long *size, void **owner );
int ios_subfloor_enum( int idx, unsigned long long *low, unsigned long long *real,
                       unsigned long long *size, void **owner )
{
    uint64_t sz;

    if (idx < 0 || idx >= ios_subfloor_count) return 0;
    sz = ios_subfloor[idx].size;       /* 0 = free slot; read first, see register */
    __sync_synchronize();
    if (low)   *low   = ios_subfloor[idx].pref_base;
    if (real)  *real  = ios_subfloor[idx].real_base;
    if (owner) *owner = ios_subfloor[idx].owner_peb;
    if (size)  *size  = sz;
    return 1;
}

/* ml1205: the window `peb` sees at addr. Exact owner or a shared (NULL-owner)
 * window wins; with no known peb, the last matching window answers. */
static uintptr_t ios_subfloor_translate( uint64_t addr, void *peb )
{
    int i, n = ios_subfloor_count;
    uintptr_t any = 0;

    if (addr >= IOS_SUBFLOOR_FLOOR) return 0;   /* fast reject: the common case */
    for (i = 0; i < n; i++)
    {
        uint64_t sz = ios_subfloor[i].size, lo, re;
        void *own;

        if (!sz) continue;
        __sync_synchronize();
        lo = ios_subfloor[i].pref_base;
        re = ios_subfloor[i].real_base;
        own = ios_subfloor[i].owner_peb;
        if (addr < lo || addr >= lo + sz) continue;
        if (!own || own == peb) return (uintptr_t)(re + (addr - lo));
        if (!peb) any = (uintptr_t)(re + (addr - lo));
    }
    return any;
}

/* Two address probes for server_ios.c's check before an async I/O completion stores an IO_STATUS_BLOCK32
 * into a 32-bit process (server_ios.c, ios_set_async_iosb). Neither dereferences the address.
 *
 * ios_iosb_probe_mapped: is [addr, addr + len) inside the task's mappings, with ANY protection? Only a hole counts as "not mapped": a
 * page with the wrong protection may be healed by the fault path, and then the store happens as it always did. Mach region queries only,
 * the recurse form (no port is handed back per call). A failure other than "no region" answers "mapped": in doubt the store is left alone. */
int ios_iosb_probe_mapped( unsigned long long addr, unsigned long long len );
int ios_iosb_probe_mapped( unsigned long long addr, unsigned long long len )
{
    const unsigned long long end = addr + len;
    unsigned long long p = addr;

    if (end < addr) return 0;
    while (p < end)
    {
        mach_vm_address_t rb = (mach_vm_address_t)p;
        mach_vm_size_t    rs = 0;
        natural_t         depth = 0;
        vm_region_submap_short_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
        kern_return_t kr;

        memset( &info, 0, sizeof(info) );
        kr = mach_vm_region_recurse( mach_task_self(), &rb, &rs, &depth, (vm_region_recurse_info_t)&info, &cnt );
        if (kr == KERN_INVALID_ADDRESS) return 0;               /* nothing at or above p: a hole to the end of the address space */
        if (kr != KERN_SUCCESS || !rs) return 1;                /* cannot tell: leave the store alone */
        if (rb > (mach_vm_address_t)p) return 0;                /* the region starts past p: p is in a hole */
        p = rb + rs;
    }
    return 1;
}

/* ios_iosb_probe_served_low: below the iOS floor nothing can be mapped; an access there is only ever answered by the fault path's own
 * registries, a sub-floor image window (ml938) or a low allocation / alias (ml966, ml969). Ask them as the fault path does, for any
 * owner (a NULL peb), so a hit anywhere keeps the store. */
int ios_iosb_probe_served_low( unsigned long long addr, unsigned long long len );
int ios_iosb_probe_served_low( unsigned long long addr, unsigned long long len )
{
    extern int ios_lowalloc_translate( unsigned long long addr, unsigned long long len,
                                       unsigned long long *real_out, void **owner_out );
    unsigned long long real = 0;
    void *owner = NULL;

    if (ios_subfloor_translate( addr, NULL ) || ios_subfloor_translate( addr + (len ? len - 1 : 0), NULL )) return 1;
    return ios_lowalloc_translate( addr, len, &real, &owner );
}

/* Read `size` bytes at `a` with the opc-implied extension. memcpy, not a cast
 * deref: the faulting address can be unaligned (the case that found this was a
 * 64-bit load from ...2ce) and a typed deref lets the compiler assume it is
 * not. opc 01 = zero-extend, 10 = sign-extend to 64, 11 = sign-extend to 32. */
static uint64_t ios_ld_extend( uintptr_t a, int size, int opc )
{
    uint64_t v = 0;

    switch (size)
    {
    case 0: { uint8_t  t; memcpy( &t, (const void *)a, 1 ); v = opc >= 2 ? (uint64_t)(int64_t)(int8_t)t  : t; break; }
    case 1: { uint16_t t; memcpy( &t, (const void *)a, 2 ); v = opc >= 2 ? (uint64_t)(int64_t)(int16_t)t : t; break; }
    case 2: { uint32_t t; memcpy( &t, (const void *)a, 4 ); v = opc >= 2 ? (uint64_t)(int64_t)(int32_t)t : t; break; }
    default: memcpy( &v, (const void *)a, 8 ); break;
    }
    if (opc == 3) v = (uint32_t)v;   /* 32-bit destination: W-write zeroes the top */
    return v;
}

static void ios_ld_setreg( ucontext_t *ctx, int rt, uint64_t v )
{
    if (rt != 31) REGn_sig(rt, ctx) = v;   /* XZR discards */
}

/* ml974: returns 0 when the vector block is not real, so callers decline
 * instead of loading into a context the handler will never write back. */
static int ios_ld_setvec( ucontext_t *ctx, int rt, uintptr_t a, int bytes )
{
    unsigned char *v = (unsigned char *)&ctx->uc_mcontext->__ns.__v[rt];

    if (!ios_neon_valid) return 0;
    memset( v, 0, 16 );
    memcpy( v, (const void *)a, bytes );
    return 1;
}

/*
 * Emulate an ARM64 LOAD against `rd_addr`. Returns 1 if the encoding was
 * recognised. Covers exactly the gap reference_str_emulator_state.md records
 * as open ("All loads ... LDAR / LDAXR / LDAPR -- no emulator path"); LDAPRB
 * is what the sub-floor fault arrives on, because FEX's TSO emulation lowers
 * every guest x86 load to a load-acquire.
 *
 * Base-register writeback is NOT done here -- ios_subfloor_writeback() does it
 * once, for loads and stores alike, so the two paths cannot double-apply it.
 */
static int ios_emulate_load( ucontext_t *ctx, uint32_t insn, uintptr_t rd_addr )
{
    const int rt   = insn & 0x1F;
    const int size = (insn >> 30) & 3;
    const int opc  = (insn >> 22) & 3;

    /* LDAPR/LDAPRB/LDAPRH -- size 111 0 00 1 0 1 11111 1 1 00 00 Rn Rt */
    if ((insn & 0x3FFFFC00) == 0x38BFC000)
    {
        ios_ld_setreg( ctx, rt, ios_ld_extend( rd_addr, size, 1 ) );
        return 1;
    }

    /* ml1231: LDAPUR / LDAPURB / LDAPURH / LDAPURS* (FEAT_LRCPC2) --
     * size 011001 opc 0 imm9 00 Rn Rt. FEX emits these for guest loads once
     * the host reports LRCPC2. opc 01 zero-extends, 10 sign-extends to 64 and
     * 11 to 32, the same convention ios_ld_extend takes; opc 00 is STLUR. */
    if ((insn & 0x3F200C00) == 0x19000000)
    {
        if (opc == 0) return 0;                        /* STLUR* -- not ours */
        if ((size == 3 && opc >= 2) || (size == 2 && opc == 3)) return 0;   /* unallocated */
        ios_ld_setreg( ctx, rt, ios_ld_extend( rd_addr, size, opc ) );
        return 1;
    }

    /* LDAR / LDAXR / LDXR -- Rs and Rt2 both 11111 */
    if ((insn & 0x3FFFFC00) == 0x08DFFC00 ||    /* LDAR  */
        (insn & 0x3FFFFC00) == 0x085FFC00 ||    /* LDAXR */
        (insn & 0x3FFFFC00) == 0x085F7C00)      /* LDXR  */
    {
        ios_ld_setreg( ctx, rt, ios_ld_extend( rd_addr, size, 1 ) );
        return 1;
    }

    /* GPR unsigned offset -- size 111 0 01 opc imm12 Rn Rt. opc 00 is a store,
     * and size=11/opc=10 is PRFM (no register result, but stepping over it is
     * the correct effect). */
    if ((insn & 0x3F000000) == 0x39000000)
    {
        if (opc == 0) return 0;                        /* STR* -- not ours */
        if (size == 3 && opc == 2) return 1;           /* PRFM: nothing to do */
        ios_ld_setreg( ctx, rt, ios_ld_extend( rd_addr, size, opc ) );
        return 1;
    }

    /* GPR 9-bit immediate: LDUR / post-index / pre-index / LDTR */
    if ((insn & 0x3F200000) == 0x38000000)
    {
        if (opc == 0) return 0;                        /* STUR* -- not ours */
        if (size == 3 && opc == 2) return 1;           /* PRFUM */
        ios_ld_setreg( ctx, rt, ios_ld_extend( rd_addr, size, opc ) );
        return 1;
    }

    /* GPR register offset -- size 111 0 00 opc 1 Rm option S 10 Rn Rt */
    if ((insn & 0x3F200C00) == 0x38200800)
    {
        if (opc == 0) return 0;
        if (size == 3 && opc == 2) return 1;           /* PRFM (register) */
        ios_ld_setreg( ctx, rt, ios_ld_extend( rd_addr, size, opc ) );
        return 1;
    }

    /* LDP / LDPSW -- opc 101 0 0xx 1 imm7 Rt2 Rn Rt  (L=1 => bit22 set) */
    if ((insn & 0x3E400000) == 0x28400000)
    {
        const int rt2 = (insn >> 10) & 0x1F;
        const int pair_opc = (insn >> 30) & 3;

        if (pair_opc == 1)          /* LDPSW: two sign-extended 32-bit words */
        {
            ios_ld_setreg( ctx, rt,  ios_ld_extend( rd_addr,     2, 2 ) );
            ios_ld_setreg( ctx, rt2, ios_ld_extend( rd_addr + 4, 2, 2 ) );
        }
        else if (pair_opc & 2)      /* 64-bit pair */
        {
            ios_ld_setreg( ctx, rt,  ios_ld_extend( rd_addr,     3, 1 ) );
            ios_ld_setreg( ctx, rt2, ios_ld_extend( rd_addr + 8, 3, 1 ) );
        }
        else                        /* 32-bit pair */
        {
            ios_ld_setreg( ctx, rt,  ios_ld_extend( rd_addr,     2, 1 ) );
            ios_ld_setreg( ctx, rt2, ios_ld_extend( rd_addr + 4, 2, 1 ) );
        }
        return 1;
    }

    /* FP/SIMD. Width comes from size plus opc bit 23: size=00 with that bit
     * set is the 128-bit (Q) form, otherwise 1<<size. opc bit 22 is L. */
    if ((insn & 0x3F000000) == 0x3D000000 ||           /* unsigned offset */
        (insn & 0x3F200000) == 0x3C000000 ||           /* 9-bit immediate  */
        (insn & 0x3F200C00) == 0x3C200800)             /* register offset  */
    {
        int bytes;

        if (!(opc & 1)) return 0;                      /* store -- not ours */
        bytes = (size == 0 && (opc & 2)) ? 16 : (1 << size);
        /* ml974: decline if the vector block is not real -- a load into a
         * context the handler will not write back is silently wrong. */
        if (!ios_ld_setvec( ctx, rt, rd_addr, bytes )) return 0;
        return 1;
    }

    return 0;
}

/*
 * ml938: the RELEASE / EXCLUSIVE / LSE store surface, which ios_emulate_store
 * does not cover -- it has plain stores, STP and CAS, and the store-release
 * family is handled only in the unaligned-atomic path of the Mach handler,
 * which this route does not go through. Kept as its own function rather than
 * extending ios_emulate_store, so the BUS-handler caller of that helper keeps
 * exactly its current behaviour.
 *
 * Needed because FEX's TSO emulation lowers guest x86 accesses to acquire/
 * release forms: the first sub-floor fault arrived as LDAPRB, and the very
 * next access to the same byte was STLRB (guest `mov byte [rcx], r11b`).
 * Emulating a release store as a plain store is correct here -- we are single-
 * stepping one access inside a fault handler, so the barrier it implies has
 * already been satisfied by the trap and the return.
 *
 * Returns 1 if the encoding was recognised.
 */
static int ios_emulate_store_rel( ucontext_t *ctx, uint32_t insn, uintptr_t addr )
{
    const int rt   = insn & 0x1F;
    const int size = (insn >> 30) & 3;
    const int nbytes = 1 << size;

    /* STLR / STLRB / STLRH / STLR(64), and the STLLR (no-ordering) variants.
     * Rs and Rt2 are both 11111 here, which is what separates these from the
     * store-exclusive encodings below. */
    if ((insn & 0x3FFFFC00) == 0x089FFC00 ||     /* STLR*  (o0=1) */
        (insn & 0x3FFFFC00) == 0x089F7C00 ||     /* STLLR* (o0=0) */
        (insn & 0x3FE00C00) == 0x19000000)       /* ml1231: STLUR* (LRCPC2, imm9) */
    {
        uint64_t v = ios_get_reg( ctx, rt );
        memcpy( (void *)addr, &v, nbytes );
        return 1;
    }

    /* STXR / STLXR: emulate as a store that always succeeds and report that in
     * the status register. A monitor-based retry loop would otherwise spin for
     * ever, because our emulated store never sets the exclusive monitor. */
    if ((insn & 0x3FE0FC00) == 0x0800FC00 ||     /* STLXR */
        (insn & 0x3FE0FC00) == 0x08007C00)       /* STXR  */
    {
        const int rs = (insn >> 16) & 0x1F;
        uint64_t v = ios_get_reg( ctx, rt );

        memcpy( (void *)addr, &v, nbytes );
        if (rs != 31) REGn_sig(rs, ctx) = 0;     /* 0 == store succeeded */
        return 1;
    }

    /* LSE read-modify-write: SWP / LDADD / LDCLR / LDEOR / LDSET, any size and
     * any acquire/release combination. The old value goes to Rt (Rt==31 is the
     * ST<op> alias, which discards it). */
    if ((insn & 0x3F20FC00) == 0x38200000 ||     /* LDADD */
        (insn & 0x3F20FC00) == 0x38201000 ||     /* LDCLR */
        (insn & 0x3F20FC00) == 0x38202000 ||     /* LDEOR */
        (insn & 0x3F20FC00) == 0x38203000 ||     /* LDSET */
        (insn & 0x3F20FC00) == 0x38208000)       /* SWP   */
    {
        const int rs = (insn >> 16) & 0x1F;
        const int op = (insn >> 12) & 7;
        const int is_swp = (insn >> 15) & 1;
        uint64_t old = 0, src = ios_get_reg( ctx, rs ), nv;

        memcpy( &old, (const void *)addr, nbytes );
        if (is_swp)           nv = src;
        else switch (op)
        {
        case 0:  nv = old + src;  break;         /* LDADD */
        case 1:  nv = old & ~src; break;         /* LDCLR */
        case 2:  nv = old ^ src;  break;         /* LDEOR */
        default: nv = old | src;  break;         /* LDSET */
        }
        memcpy( (void *)addr, &nv, nbytes );
        if (rt != 31) REGn_sig(rt, ctx) = (size == 3) ? old : (uint32_t)old;
        return 1;
    }

    /* SIMD pair load/store (LDP/STP q,d,s) -- V=1, which the GPR pair paths in
     * ios_emulate_store and ios_emulate_load both decline.
     *
     * ml950: the mask was 0x3A000000, which omits bit 26 (V) while the compare
     * value 0x2C000000 sets it -- so the test was unsatisfiable and this whole
     * branch was dead code. It surfaced when FEX read guest code out of a
     * sub-floor window through the shared-cache memmove, whose `LDP q,q,[Xn],#imm`
     * (0xac400c22) was reported UNHANDLED. 0x3E000000 pins [29:27]=101, V=1 and
     * [25]=0, and stays disjoint from the GPR pair test (0x3E400000/0x28400000,
     * which requires V=0). */
    if ((insn & 0x3E000000) == 0x2C000000)
    {
        const int rt2   = (insn >> 10) & 0x1F;
        const int p_opc = (insn >> 30) & 3;
        const int is_ld = (insn >> 22) & 1;
        int w;

        if (p_opc == 3) return 0;                /* reserved */
        w = 4 << p_opc;                          /* 4 = S, 8 = D, 16 = Q */
        if (is_ld)
        {
            /* ml974: both halves or neither -- check before either write so a
             * refusal cannot leave one register updated. */
            if (!ios_neon_valid) return 0;
            ios_ld_setvec( ctx, rt,  addr,     w );
            ios_ld_setvec( ctx, rt2, addr + w, w );
        }
        else
        {
            /* ml974: never write a zeroed vector block over guest memory. */
            if (!ios_neon_valid) return 0;
            memcpy( (void *)addr,       &ctx->uc_mcontext->__ns.__v[rt],  w );
            memcpy( (void *)(addr + w), &ctx->uc_mcontext->__ns.__v[rt2], w );
        }
        return 1;
    }

    return 0;
}

/***********************************************************************
 *		ios_native_unaligned_emulate                    (madeira-bcd)
 *
 * An alignment fault in the app's OWN code (the Madeira executable's __TEXT:
 * the unix side, DXMT's native half, the app itself), not in FEX's
 * translations or a PE image. GTA V Enhanced's Rockstar Games Launcher died
 * on build 454 twice in a row (logs 2026-10-08 15:41:42 and 15:44:14): a
 * launcher thread ran `stlr w21, [x19]` (0x889ffe75) at Madeira+0xb5310c on
 * 0x14dac5b3f, then 0x118c86bcf -- a 4-byte release store that crosses a
 * 16-byte boundary, which faults even with LSE2. Both delivery paths handed
 * it to FEX as 80000002 ("[unaligned-atomic] mach-path ... to-fex",
 * "[unaligned-guest] REFUSED-OTHER"); FEX took the pc for guest code (NoExec
 * at pc+4), the thread raised c0000005, the Launcher exited and PlayGTAV.exe
 * showed its "Error" box, so the game never started. FEX's unaligned machinery
 * only knows its own code; for ours it can only fail.
 *
 * Here the access is done byte-wise between two full barriers and the thread
 * goes on at the next instruction: the release store, the acquire load, the
 * exclusive pair (the store always succeeds, as in ios_emulate_store_rel) and
 * the LSE read-modify-write family, none with base-register writeback. A
 * crossing access cannot be single-copy atomic on ARM anyway; x86, whose
 * pointers these are, does not promise it either. Returns 1 when emulated.
 * FEX's translations keep their own path: the pc must lie in the executable's
 * __TEXT. Safe on the exception-server thread: no wine log macros, and the
 * __TEXT bounds are read from the loaded Mach-O header once. */
static int ios_pc_in_app_text( uint64_t pc )
{
    if (!__atomic_load_n( &ios_app_text_hi, __ATOMIC_ACQUIRE ))
    {
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header( 0 );
        unsigned long size = 0;
        uint8_t *text = mh ? getsegmentdata( mh, "__TEXT", &size ) : NULL;

        if (!text || !size) return 0;
        ios_app_text_lo = (uint64_t)(uintptr_t)text;
        __atomic_store_n( &ios_app_text_hi, (uint64_t)(uintptr_t)text + size, __ATOMIC_RELEASE );
    }
    return pc >= ios_app_text_lo && pc < __atomic_load_n( &ios_app_text_hi, __ATOMIC_RELAXED );
}

/* The load side of the ordered and exclusive accesses: LDAR, LDLAR, LDAXR,
 * LDXR, LDAPR (RCpc) and LDAPUR (LRCPC2, zero-extending). Rt gets the value
 * zero-extended, as the instructions do. */
static int ios_emulate_load_acq( ucontext_t *ctx, uint32_t insn, uintptr_t addr )
{
    const int rt = insn & 0x1F;
    const int nbytes = 1 << ((insn >> 30) & 3);
    uint64_t v = 0;

    if ((insn & 0x3FFFFC00) == 0x08DFFC00 ||     /* LDAR*  */
        (insn & 0x3FFFFC00) == 0x08DF7C00 ||     /* LDLAR* */
        (insn & 0x3FFFFC00) == 0x085FFC00 ||     /* LDAXR* */
        (insn & 0x3FFFFC00) == 0x085F7C00 ||     /* LDXR*  */
        (insn & 0x3FFFFC00) == 0x38BFC000 ||     /* LDAPR* */
        (insn & 0x3FE00C00) == 0x19400000)       /* LDAPUR* */
    {
        memcpy( &v, (const void *)addr, nbytes );
        if (rt != 31) REGn_sig(rt, ctx) = v;
        return 1;
    }
    return 0;
}

static int ios_native_unaligned_emulate( ucontext_t *ctx, uint32_t insn, uintptr_t addr, uint64_t pc )
{
    int done;

    if (!insn || !ios_pc_in_app_text( pc )) return 0;
    if ((insn & 0x3E000000) == 0x2C000000) return 0;   /* SIMD pairs: writeback forms, not ours */
    __atomic_thread_fence( __ATOMIC_SEQ_CST );
    done = ios_emulate_store_rel( ctx, insn, addr ) || ios_emulate_load_acq( ctx, insn, addr );
    __atomic_thread_fence( __ATOMIC_SEQ_CST );
    return done;
}

/*
 * Apply base-register writeback for the pre/post-index forms, in the GUEST
 * (sub-floor) domain -- Rn holds a low address and must keep holding one.
 * Both cases are expressible from the faulting address alone: for post-index
 * the effective address IS Rn, for pre-index it is Rn plus the immediate.
 */
static void ios_subfloor_writeback( ucontext_t *ctx, uint32_t insn, uint64_t orig_addr )
{
    const int rn = (insn >> 5) & 0x1F;

    if (rn == 31) return;

    /* Single, 9-bit immediate: type[11:10] 01 = post-index, 11 = pre-index. */
    if ((insn & 0x3B200000) == 0x38000000)
    {
        const int type = (insn >> 10) & 3;
        int64_t imm9;

        if (type != 1 && type != 3) return;            /* LDUR/STUR/LDTR: none */
        imm9 = (int64_t)((insn >> 12) & 0x1FF);
        if (imm9 & 0x100) imm9 -= 0x200;
        REGn_sig(rn, ctx) = (type == 1) ? orig_addr + imm9 : orig_addr;
        return;
    }

    /* Pair: [25:23] 001 = post-index, 011 = pre-index, 010 = signed offset. */
    if ((insn & 0x3A000000) == 0x28000000)
    {
        const int kind  = (insn >> 23) & 3;
        const int is_v  = (insn >> 26) & 1;
        const int p_opc = (insn >> 30) & 3;
        int scale;
        int64_t imm7;

        if (kind != 1 && kind != 3) return;
        scale = is_v ? (4 << p_opc) : ((p_opc & 2) ? 8 : 4);
        imm7  = (int64_t)((insn >> 15) & 0x7F);
        if (imm7 & 0x40) imm7 -= 0x80;
        imm7 *= scale;
        REGn_sig(rn, ctx) = (kind == 1) ? orig_addr + imm7 : orig_addr;
    }
}

/*
 * Service one fault against a registered sub-floor window. Returns 1 if the
 * access was emulated and the caller should step the PC and resume.
 */
/*
 * ml956: what the faulting instruction would do to the backing, decided
 * WITHOUT touching it. The order and the masks mirror ios_emulate_load /
 * ios_emulate_store_rel / ios_emulate_store exactly -- including the
 * `opc == 0 -> return 0` guards that keep stores out of the load emulator --
 * so a classification can never disagree with the emulator that will actually
 * run. Returns 1 when the encoding is one of those three cover; *bytes is the
 * full access span and *is_write is set for stores AND for read-modify-write
 * atomics (which both read and write).
 *
 * Why this exists: ios_emulate_load/_store/_store_rel dereference their
 * address argument naked. That contract was written for the W^X pool path,
 * where the caller had already resolved a known-writable RW anon alias.
 * ios_subfloor_service passes a raw PE backing address instead, which can be
 * read-only (.text / .rdata), or stale, or gone. When that dereference faults,
 * the faulting thread IS the Mach exception thread: its own exception is sent
 * to the port that only it services, so it waits on itself for ever, and every
 * guest thread waiting for a fault reply parks behind it. rdr20 caught exactly
 * that -- "wine-x18-exc" stopped in ios_emulate_store+0x70 (str w9,[x2]) under
 * ios_subfloor_service, while a guest thread sat at ReadFile+0xac (str w8,[x26],
 * the STATUS_PENDING store that precedes NtReadFile) waiting for a reply that
 * could never come. Nothing logged, because a handler that faults inside
 * itself never reaches its own error path.
 */
static int ios_subfloor_classify( uint32_t insn, unsigned *bytes, int *is_write )
{
    const int size = (insn >> 30) & 3;
    const int opc  = (insn >> 22) & 3;

    *bytes    = 1u << size;
    *is_write = 0;

    /* ---- ios_emulate_load: pure loads (tried first, so it wins ties) ---- */
    if ((insn & 0x3FFFFC00) == 0x38BFC000) return 1;                /* LDAPR*  */
    if ((insn & 0x3F200C00) == 0x19000000 && opc != 0)              /* ml1231: LDAPUR* */
        return !((size == 3 && opc >= 2) || (size == 2 && opc == 3));
    if ((insn & 0x3FFFFC00) == 0x08DFFC00 ||                        /* LDAR    */
        (insn & 0x3FFFFC00) == 0x085FFC00 ||                        /* LDAXR   */
        (insn & 0x3FFFFC00) == 0x085F7C00) return 1;                /* LDXR    */
    if ((insn & 0x3F000000) == 0x39000000 && opc != 0) return 1;    /* LDR uimm */
    if ((insn & 0x3F200000) == 0x38000000 && opc != 0) return 1;    /* LDUR 9b  */
    if ((insn & 0x3F200C00) == 0x38200800 && opc != 0) return 1;    /* LDR reg  */
    if ((insn & 0x3E400000) == 0x28400000)                          /* LDP/LDPSW */
    {
        const int p = (insn >> 30) & 3;
        if (p == 3) return 0;
        *bytes = (p == 2) ? 16 : 8;   /* 64-bit pair, else two 32-bit halves */
        return 1;
    }
    if ((insn & 0x3F000000) == 0x3D000000 ||                        /* FP/SIMD  */
        (insn & 0x3F200000) == 0x3C000000 ||
        (insn & 0x3F200C00) == 0x3C200800)
    {
        /* width is size plus opc bit 23; opc bit 22 is L. */
        *bytes    = (size == 0 && (opc & 2)) ? 16u : (1u << size);
        *is_write = !(opc & 1);
        return 1;
    }

    /* ---- ios_emulate_store_rel: release / exclusive / LSE ---- */
    if ((insn & 0x3FFFFC00) == 0x089FFC00 ||                        /* STLR*   */
        (insn & 0x3FFFFC00) == 0x089F7C00 ||                        /* STLLR*  */
        (insn & 0x3FE00C00) == 0x19000000 ||                        /* ml1231: STLUR* */
        (insn & 0x3FE0FC00) == 0x0800FC00 ||                        /* STLXR   */
        (insn & 0x3FE0FC00) == 0x08007C00)                          /* STXR    */
    {
        *is_write = 1;
        return 1;
    }
    if ((insn & 0x3F20FC00) == 0x38200000 ||                        /* LDADD   */
        (insn & 0x3F20FC00) == 0x38201000 ||                        /* LDCLR   */
        (insn & 0x3F20FC00) == 0x38202000 ||                        /* LDEOR   */
        (insn & 0x3F20FC00) == 0x38203000 ||                        /* LDSET   */
        (insn & 0x3F20FC00) == 0x38208000)                          /* SWP     */
    {
        *is_write = 1;   /* RMW: needs read AND write */
        return 1;
    }
    if ((insn & 0x3E000000) == 0x2C000000)                          /* SIMD pair */
    {
        const int p = (insn >> 30) & 3;
        if (p == 3) return 0;                                       /* reserved */
        *bytes    = 2u * (4u << p);                                 /* S/D/Q pair */
        *is_write = !((insn >> 22) & 1);
        return 1;
    }

    /* ---- ios_emulate_store: plain stores, STP, CAS ---- */
    if ((insn & 0x3FC00000) == 0x39000000 ||                        /* STR uimm */
        (insn & 0x3FE00000) == 0x38000000 ||                        /* STUR 9b  */
        (insn & 0x3FE00C00) == 0x38200800)                          /* STR reg  */
    {
        *is_write = 1;
        return 1;
    }
    if ((insn & 0x3E400000) == 0x28000000)                          /* STP      */
    {
        const int p = (insn >> 30) & 3;
        if (p == 3) return 0;
        *bytes    = (p == 2) ? 16 : 8;
        *is_write = 1;
        return 1;
    }
    if ((insn & 0xBFA07C00) == 0x88A07C00 ||                        /* CAS*     */
        (insn & 0xBFA07C00) == 0x08207C00)
    {
        *bytes    = ((insn >> 30) & 1) ? 8u : 4u;
        *is_write = 1;                                              /* RMW      */
        return 1;
    }
    if ((insn & 0xBFA07C00) == 0x08A07C00)                          /* CASB/CASH (ml1208) */
    {
        *bytes    = ((insn >> 30) & 1) ? 2u : 1u;
        *is_write = 1;
        return 1;
    }
    if ((insn & 0xFFA00C00) == 0x3C800000)                          /* SIMD st  */
    {
        *bytes    = 16;
        *is_write = 1;
        return 1;
    }

    return 0;   /* not ours -- caller takes the existing UNHANDLED path */
}

/*
 * ml956: is [real, real + bytes) mapped, with the permission this access
 * needs? Answered with Mach region queries only -- never a dereference -- so
 * the exception thread cannot fault while deciding. Walks every region the
 * span touches, because a span can straddle a section boundary (R-X .text into
 * R-- .rdata) or run off the end of the mapping into a hole.
 *
 * mach_vm_region_recurse, not mach_vm_region: the latter hands back an
 * object-name port on every call. The existing mach_vm_region sites in this
 * file sit on rare diagnostic paths and leak it harmlessly, but this gate runs
 * once per serviced fault -- 462,849 times in rdr20 -- and would exhaust the
 * task's port table. The recurse form returns no port.
 */
static int ios_subfloor_backing_probe( uintptr_t real, unsigned bytes, int need_write,
                                       unsigned long long *rb_out, unsigned long long *rs_out,
                                       unsigned *cur_out, unsigned *max_out, int *kr_out )
{
    const uintptr_t end = real + bytes;
    uintptr_t p = real;

    *rb_out = 0; *rs_out = 0; *cur_out = 0; *max_out = 0; *kr_out = KERN_SUCCESS;

    if (end < real) return 0;                       /* span overflowed */

    while (p < end)
    {
        mach_vm_address_t rb = (mach_vm_address_t)p;
        mach_vm_size_t    rs = 0;
        natural_t         depth = 0;
        vm_region_submap_short_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
        kern_return_t kr;

        memset( &info, 0, sizeof(info) );
        kr = mach_vm_region_recurse( mach_task_self(), &rb, &rs, &depth,
                                     (vm_region_recurse_info_t)&info, &cnt );
        if (kr != KERN_SUCCESS) { *kr_out = (int)kr; return 0; }

        /* Record whatever region we are judging, so a refusal names it. */
        *rb_out  = (unsigned long long)rb;
        *rs_out  = (unsigned long long)rs;
        *cur_out = (unsigned)info.protection;
        *max_out = (unsigned)info.max_protection;

        /* The query returns the first region at or ABOVE rb. If it starts past
         * p, then p itself is in a hole -- unmapped. */
        if (rb > (mach_vm_address_t)p) return 0;
        if (!(info.protection & VM_PROT_READ)) return 0;
        if (need_write && !(info.protection & VM_PROT_WRITE)) return 0;
        if (!rs) return 0;                          /* no forward progress */

        p = (uintptr_t)(rb + rs);
    }
    return 1;
}

static int ios_subfloor_service( ucontext_t *ctx, void *fault_addr, const char *via, void *peb )
{
    uint64_t addr = (uint64_t)(uintptr_t)fault_addr;
    uintptr_t real = ios_subfloor_translate( addr, peb );
    uint32_t insn = 0;
    unsigned bytes = 0, span = 8;
    int is_write = 0, ok, cls = 0;
    unsigned long long rb = 0, rs = 0;
    unsigned cur = 0, mx = 0;
    int kr = 0;
    mach_vm_size_t got = 0;

    /* ml966: a translate miss is no longer fatal on its own -- a low guest
     * allocation is resolved further down, once the access span is known. But
     * reject anything that cannot possibly be one BEFORE doing the instruction
     * read and classification below: that work used to be skipped entirely for
     * a miss, and this is the general fault path, so paying for it on every
     * unrelated fault would be a real regression. The literals mirror
     * IOS_LOWALLOC_BASE/LIMIT in virtual_ios.c. */
    /* ml969 widens this: an alias can sit anywhere in the low 4 GB, not just in
     * the ml966 arena, so any SUB-FLOOR address has to be offered to the
     * registry. Addresses at or above the floor still reject immediately,
     * which is the common case and keeps the general fault path cheap. */
    if (!real && addr >= IOS_SUBFLOOR_FLOOR) return 0;

    /* ml956: read the faulting instruction through a failure-returning copy.
     * A naked deref of PC_sig here is the same self-fault hazard as the
     * backing access below -- an unmapped or stale PC would stop the exception
     * thread inside its own handler instead of reporting anything. */
    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(uintptr_t)PC_sig(ctx),
                                4, (mach_vm_address_t)&insn, &got ) != KERN_SUCCESS || got != 4)
    {
        static int pc_unreadable;
        if (pc_unreadable++ < 8)
            dprintf( 2, "[subfloor] ml956 via=%s DECLINING: pc=%#llx unreadable, guest %#llx -> real %#llx\n",
                     via, (unsigned long long)PC_sig(ctx), (unsigned long long)addr,
                     (unsigned long long)real );
        return 0;
    }

    /* ml956: decide what the access needs, then prove the backing can take it,
     * BEFORE handing the address to an emulator that dereferences it naked.
     * An address-translation hit is not permission to dereference its result. */
    cls = ios_subfloor_classify( insn, &bytes, &is_write );
    /* classify writes *bytes before it decides, so on a miss the value is a
     * guess -- use a conservative 8-byte span for bounds checks in that case
     * and keep the accessibility probe gated on the result, as before. */
    span = cls ? bytes : 8u;

    /* ml966: a low guest ALLOCATION resolves through its own registry, not the
     * ml938 image-window table. Checked here rather than in
     * ios_subfloor_translate on purpose: this is the first point where the
     * classified access SPAN is known, and the whole span has to be inside the
     * allocation's bounds. The image table translates on the start address
     * alone, which is safe enough for a fixed image but not for dynamic
     * allocations -- an access straddling the end must be refused, not
     * silently resolved into whatever follows the backing.
     *
     * Ownership is recorded and logged but not enforced here: this handler runs
     * on the Mach exception thread, not the faulting guest thread, so the
     * current peb is the handler's and cannot be compared. Ownership IS
     * enforced on the allocate/free paths, which run on the guest's own thread.
     * Sound for a single-owner experiment; a general mechanism would need the
     * faulting thread's identity plumbed through. */
    if (!real)
    {
        extern int ios_lowalloc_translate( unsigned long long addr, unsigned long long len,
                                           unsigned long long *real_out, void **owner_out );
        unsigned long long lo_real = 0;
        void *lo_owner = NULL;
        if (ios_lowalloc_translate( addr, span, &lo_real, &lo_owner ))
        {
            static unsigned long long la_hits;
            real = (uintptr_t)lo_real;
            if ((++la_hits & 0xFFF) == 1)
                dprintf( 2, "[lowalloc] ml966 serviced %llu access(es); latest guest %#llx (%u byte span, %s)"
                         " -> backing %#llx owner=%p\n",
                         la_hits, (unsigned long long)addr, span,
                         is_write ? "write" : "read", lo_real, lo_owner );
        }
        else
        {
            static int la_miss;
            /* A low address in the experiment's range that no live allocation
             * covers: either a span running off the end, or an access after
             * the translation was retired. Both must be refused, and both are
             * worth naming -- a retired-translation access is a use-after-free
             * in the guest, not something to paper over. */
            if (la_miss < 16)
            {
                la_miss++;
                dprintf( 2, "[lowalloc] ml966 REFUSED guest %#llx (%u byte span%s): no live allocation "
                         "covers it (off-the-end, or translation already retired)\n",
                         (unsigned long long)addr, span, cls ? "" : ", encoding unknown so span assumed" );
            }
            return 0;
        }
    }

    if (cls &&
        !ios_subfloor_backing_probe( real, bytes, is_write, &rb, &rs, &cur, &mx, &kr ))
    {
        /* Capture, then decline. Declining lands on exactly the path an
         * unknown encoding already takes, so it cannot regress anything --
         * and unlike a dereference it cannot wedge the handler. The guest
         * thread gets the normal fault disposition instead of a reply that
         * never arrives. Keyed on the distinct guest page so a hot loop
         * cannot flood the log (ml945's lesson). */
        static uint64_t seen_pg[16];
        static int nseen_pg;
        int i, fresh = 1;
        uint64_t pg = addr & ~0xFFFULL;

        ios_subfloor_refused++;
        for (i = 0; i < nseen_pg; i++) if (seen_pg[i] == pg) { fresh = 0; break; }
        if (fresh && nseen_pg < 16) seen_pg[nseen_pg++] = pg;
        if (fresh)
        {
            extern uintptr_t ios_jit_anon_alias_lookup(uintptr_t fault_addr);
            extern void *ios_jit_translate_addr(void *addr);
            uintptr_t rw_alias = ios_jit_anon_alias_lookup( real );
            void *pool_copy = ios_jit_translate_addr( (void *)real );

            dprintf( 2, "[subfloor] ml956 via=%s REFUSED %s of %u byte(s): guest %#llx -> real %#llx "
                     "insn=%#010x pc=%#llx | backing region %#llx+%#llx cur_prot=%#x max_prot=%#x kr=%d "
                     "| anon_rw_alias=%#llx pool_copy=%#llx\n",
                     via, is_write ? "WRITE" : "read", bytes,
                     (unsigned long long)addr, (unsigned long long)real, insn,
                     (unsigned long long)PC_sig(ctx), rb, rs, cur, mx, kr,
                     (unsigned long long)rw_alias,
                     (unsigned long long)(pool_copy == (void *)real ? 0 : (uintptr_t)pool_copy) );
        }
        return 0;
    }

    /* ml1000: the emulator chain tries LOAD first and never consults is_write,
     * which ios_subfloor_classify has already decided from the encoding. If the
     * emulator that claims the instruction disagrees with that decision, the
     * access was serviced INCORRECTLY and silently: a store claimed by the load
     * emulator is DROPPED (stale bytes survive), and a load claimed by a store
     * emulator WRITES over guest data. Either one corrupts the guest invisibly,
     * and this path serviced 20,481 accesses in rdr69 with "0 unhandled".
     *
     * rdr69's motivation: the DRM's launcher-check code resolves its imports
     * (GetModuleFileNameW, PathFileExistsW, SHGetFolderPathA, CreateFileA,
     * ReadFile, GetFileSize, CreateProcessA, MessageBoxA, MessageBoxTimeoutA,
     * ExitProcess, _itoa, memcpy) by name, and two of those names arrive
     * TRUNCATED to a single character ("a", "k" -- the latter consistent with
     * "kernel32"). Single-byte truncation is what a misplaced byte store does,
     * and the subfloor traffic is full of size=00 byte accesses
     * (insn=0x38bfc041 family). This does not yet prove that link -- it makes
     * the misservice observable instead of silent. */
    {
        char claimed = 0;

        ok = ios_emulate_load( ctx, insn, real );
        if (ok) claimed = 'L';
        if (!ok) { ok = ios_emulate_store_rel( ctx, insn, real ); if (ok) claimed = 'R'; }
        if (!ok) { ok = ios_emulate_store( ctx, insn, real );     if (ok) claimed = 'S'; }

        if (ok && cls && ((is_write && claimed == 'L') || (!is_write && claimed != 'L')))
        {
            static unsigned miss_n;
            if (miss_n++ < 32)
                dprintf( 2, "ml1000: SUBFLOOR MISSERVICE insn=%08x classify=%s(%u bytes) but "
                         "emulated as %s -- guest %#llx real %#llx pc %#llx via=%s\n",
                         insn, is_write ? "WRITE" : "read", bytes,
                         claimed == 'L' ? "LOAD" : (claimed == 'R' ? "STORE_REL" : "STORE"),
                         (unsigned long long)addr, (unsigned long long)real,
                         (unsigned long long)PC_sig(ctx), via );
        }
        /* Byte-width writes of NUL are the specific truncation candidate: one of
         * these landing mid-string turns "kernel32" into "k". Log the value and
         * the four bytes that follow so a truncated table entry is visible in
         * the log rather than inferred from a failed LoadLibrary later. */
        if (ok && cls && is_write && bytes == 1)
        {
            unsigned char v = *(volatile unsigned char *)real;
            if (!v)
            {
                static unsigned nul_n;
                if (nul_n++ < 24)
                {
                    unsigned char nb[5] = { 0 };
                    mach_vm_size_t ngot = 0;
                    mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(real + 1), 4,
                                            (mach_vm_address_t)nb, &ngot );
                    dprintf( 2, "ml1000: subfloor wrote NUL at guest %#llx (real %#llx) insn=%08x;"
                             " next4=%02x %02x %02x %02x (%c%c%c%c)\n",
                             (unsigned long long)addr, (unsigned long long)real, insn,
                             nb[0], nb[1], nb[2], nb[3],
                             nb[0] > 31 && nb[0] < 127 ? nb[0] : '.',
                             nb[1] > 31 && nb[1] < 127 ? nb[1] : '.',
                             nb[2] > 31 && nb[2] < 127 ? nb[2] : '.',
                             nb[3] > 31 && nb[3] < 127 ? nb[3] : '.' );
                }
            }
        }
    }
    if (!ok)
    {
        /* An encoding we do not cover. Say so once per distinct encoding and
         * let the normal fault path take it -- identical to today's behaviour,
         * so an unknown instruction cannot regress anything, and the log names
         * the exact word to add. */
        static uint32_t seen[16];
        static int nseen;
        int i;

        ios_subfloor_unknown++;
        for (i = 0; i < nseen; i++) if (seen[i] == insn) return 0;
        if (nseen < 16) seen[nseen++] = insn;
        dprintf( 2, "[subfloor] ml939 via=%s UNHANDLED encoding %#010x at pc=%#llx for guest addr %#llx "
                 "(real %#llx) -- add it to ios_emulate_load/store\n",
                 via, insn, (unsigned long long)PC_sig(ctx), (unsigned long long)addr,
                 (unsigned long long)real );
        return 0;
    }

    ios_subfloor_writeback( ctx, insn, addr );
    /* ml1055: WHO is touching the window. One run serviced 12,029,953 of these
     * through the Mach exception path (~18,000 a second, a fifth of all running
     * CPU samples were in mach_msg). Whether the accessor is the sub-floor
     * image's own code or the main image decides the fix (translate at JIT time
     * for blocks that live in the window, vs backpatching arbitrary sites), so
     * attribute each hit to the page of the guest RIP in the FEX frame. */
    {
        static struct { uint64_t page; unsigned long long n; } hist[48];
        static unsigned long long no_frame;
        uint64_t x28 = REGn_sig( 28, ctx ), grip = 0;
        mach_vm_size_t got = 0;
        int h;
        if (x28 >= 0x100000000ULL && x28 < 0xfffffff000000000ULL &&
            mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(x28 + 0x18), 8,
                                    (mach_vm_address_t)&grip, &got ) == KERN_SUCCESS && got == 8 && grip)
        {
            uint64_t page = grip >> 12;
            for (h = 0; h < 48; h++)
            {
                if (hist[h].page == page) { hist[h].n++; break; }
                if (!hist[h].page) { hist[h].page = page; hist[h].n = 1; break; }
            }
        }
        else no_frame++;
        if ((ios_subfloor_hits & 0xFFFFF) == 0xFFFFF)
        {
            char line[1500]; int n = 0;
            for (h = 0; h < 48 && hist[h].page; h++)
                if (hist[h].n > 2000)
                    n += snprintf( line + n, sizeof(line) - n, " %llx:%llu", (unsigned long long)hist[h].page << 12, hist[h].n );
            dprintf( 2, "[subfloor] ml1055 accessor guest-RIP pages after %llu hits (no FEX frame: %llu):%s\n",
                     ios_subfloor_hits + 1, no_frame, n ? line : " (none above 2000)" );
        }
    }
    if ((++ios_subfloor_hits & 0xFFF) == 1)
        dprintf( 2, "[subfloor] ml956 serviced %llu access(es) (%llu unhandled, %llu refused) via=%s; "
                 "latest guest %#llx -> real %#llx insn=%#010x\n",
                 ios_subfloor_hits, ios_subfloor_unknown, ios_subfloor_refused, via,
                 (unsigned long long)addr, (unsigned long long)real, insn );
    return 1;
}
#endif


