/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. The x18 -> TPIDR_EL0 binary patcher. Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *           ios_jit_patch_x18  (x18 → TPIDR_EL0 binary patcher)
 *
 * Scans a PE .text section for all ARM64 instructions that reference x18
 * and replaces each with a branch to a generated trampoline.
 * The trampoline reads TEB from TPIDR_EL0 (preserved by iOS across context
 * switches, unlike x18) and performs the original operation.
 *
 * This eliminates the "zero-page silent read" problem entirely — patched
 * code never touches x18, so iOS zeroing it has no effect.
 */

/* Check if an ARM64 instruction references x18 as a register operand.
 * Returns the role (which field contains x18) or 0 if no x18 reference. */
#define X18_ROLE_NONE 0
#define X18_ROLE_RN   1  /* bits[9:5] = base register for loads/stores/data-proc */
#define X18_ROLE_RM   2  /* bits[20:16] = second register (MOV, register offset) */
#define X18_ROLE_RT2  3  /* bits[14:10] = second register in LDP/STP */

static int ios_insn_x18_role(uint32_t insn)
{
    /* Quick reject: check if 18 appears in any relevant field */
    int rn = (insn >> 5) & 0x1f;
    int rm = (insn >> 16) & 0x1f;
    int rt2 = (insn >> 10) & 0x1f;
    if (rn != 18 && rm != 18 && rt2 != 18) return X18_ROLE_NONE;

    /* Classify instruction to verify the field is actually a register */
    uint32_t top8 = insn >> 24;
    uint32_t top11 = insn >> 21;

    /* LDR/STR (unsigned immediate) — top2=1x, [27:24]=x111, [29]=1 */
    if ((top8 & 0x3F) == 0x39 || (top8 & 0x3F) == 0x3D ||  /* 0b0011 1001, 0b0011 1101 */
        (top8 & 0x3F) == 0xB9 || (top8 & 0x3F) == 0xBD ||  /* 0b1011 1001, 0b1011 1101 */
        (top8 & 0x3F) == 0xF9 || (top8 & 0x3F) == 0xFD ||  /* 0b1111 1001, 0b1111 1101 */
        (top8 & 0x3F) == 0x79 || (top8 & 0x3F) == 0x7D)    /* 0b0111 1001, 0b0111 1101 */
    {
        if (rn == 18) return X18_ROLE_RN;
    }

    /* LDR/STR (register offset) — [29:27]=111, V=0, [25:24]=00, [21]=1,
     * [11:10]=10; size [31:30] and opc [23:22] are DON'T-CARES.
     * iOS-Madeira 2026-07-04: mask was 0x3E7/0x1C1 which demanded
     * insn[30]==0 AND insn[22]==0 — i.e. only 8/32-bit STORES matched.
     * Every register-offset LOAD off x18 (`ldrb w8,[x18,x8]` — win32u's
     * hottest TEB poll) went unpatched and cost one Mach fault per visit
     * whenever x18 was 0 (~14%% of game-thread samples once
     * UNIXCALL-DIRECT removed the constant x18 refresh). */
    if ((top11 & 0x1F9) == 0x1C1 && ((insn >> 10) & 3) == 2)
    {
        if (rn == 18) return X18_ROLE_RN;
        if (rm == 18) return X18_ROLE_RM;
    }

    /* LDR/STR (pre/post-indexed) — [31:21]=1x111000xx0 */
    if ((top11 & 0x3E7) == 0x1C0)
    {
        if (rn == 18) return X18_ROLE_RN;
    }

    /* LDP/STP (signed offset, pre/post-indexed) — [31:25]=x0101x01 or x0101x00 */
    if ((top8 & 0x3E) == 0x28 || (top8 & 0x3E) == 0x2C ||  /* x010 100x, x010 110x */
        (top8 & 0x3E) == 0xA8 || (top8 & 0x3E) == 0xAC ||  /* 1010 100x, 1010 110x */
        (top8 & 0x3E) == 0x68 || (top8 & 0x3E) == 0x6C)    /* 0110 100x, 0110 110x */
    {
        if (rn == 18) return X18_ROLE_RN;
        if (rt2 == 18) return X18_ROLE_RT2;
    }

    /* MOV (register) = ORR Rd, XZR, Rm — [31:21]=x01 0101 0000 */
    if ((top11 & 0x7FF) == 0x150 || (top11 & 0x7FF) == 0x550)
    {
        if (rm == 18) return X18_ROLE_RM;
    }

    /* ADD/SUB (immediate) — [31:24]=sf op S 10001. madeira-bcd: the mask was
     * 0x5F, which kept op (bit 30) and so matched ADD only: every SUB off x18
     * went unpatched and read the raw (zeroed) x18. 0x1F takes ADD, ADDS, SUB
     * and SUBS, as the comment always said. */
    if ((top8 & 0x1F) == 0x11)
    {
        if (rn == 18) return X18_ROLE_RN;
    }

    /* ADD/SUB (register) — [31:24]=sf op S 01011 (same mask fix as above) */
    if ((top8 & 0x1F) == 0x0B)
    {
        if (rn == 18) return X18_ROLE_RN;
        if (rm == 18) return X18_ROLE_RM;
    }

    return X18_ROLE_NONE;
}

/* madeira-bcd: the destination of an ADD/SUB (immediate or register) that reads
 * x18 once, when that destination can carry the TEB instead of x18: not x18,
 * not 31 (SP or XZR), and not the instruction's other source. -1 otherwise.
 *
 * Such an instruction used to take the "via x18" trampoline (load x18 from
 * TPIDRRO_EL0, run the instruction unchanged). If iOS preempts the thread
 * between the load and the instruction it zeroes x18, and unlike a load or a
 * store the ADD does not fault: it computes a small address that faults later,
 * somewhere the handler cannot repair ([x18-decline]). Wine's debug channel
 * buffer is get_info() = NtCurrentTeb() + 0x2000 + sizeof(TEB32), so with the
 * TEB read as 0 its output lands at 0x3404: RockstarService.exe died that way
 * in ntdll's printf padding loop (GTA V Enhanced build 375, 2026-10-04 09:52,
 * `pc ntdll+0x63458 ... writing to 0x3404`, x18=0), the self-restarted
 * Rockstar Games Launcher on 2026-10-03 23:21, and God of War's 0x3404 SEGVs.
 * With the destination as scratch x18 is never touched. */
static int ios_x18_arith_dest(uint32_t insn, int role)
{
    uint32_t top8 = insn >> 24;
    int rd = insn & 0x1f, rn = (insn >> 5) & 0x1f, rm = (insn >> 16) & 0x1f;

    if (rd == 18 || rd == 31) return -1;
    if ((top8 & 0x1F) == 0x11)                       /* ADD/SUB (immediate) */
        return (role == X18_ROLE_RN && rn == 18) ? rd : -1;
    if ((top8 & 0x1F) == 0x0B)                       /* ADD/SUB (register) */
    {
        if (rn == 18 && rm == 18) return -1;
        if (role == X18_ROLE_RN && rn == 18 && rm != rd) return rd;
        if (role == X18_ROLE_RM && rm == 18 && rn != rd) return rd;
    }
    return -1;
}

/* Replace x18 in an instruction with a different register */
static uint32_t ios_insn_replace_x18(uint32_t insn, int role, int scratch)
{
    switch (role)
    {
    case X18_ROLE_RN:  return (insn & ~(0x1f << 5)) | (scratch << 5);
    case X18_ROLE_RM:  return (insn & ~(0x1f << 16)) | (scratch << 16);
    case X18_ROLE_RT2: return (insn & ~(0x1f << 10)) | (scratch << 10);
    default:           return insn;
    }
}

/* Patch all x18 references in a PE .text section.
 * text_rw/text_rx: RW and RX views of the .text section
 * text_size: size of .text in bytes
 * tramp_rw/tramp_rx: RW and RX views of the trampoline area
 * tramp_size: available space for trampolines
 * Returns number of instructions patched. */
/* Literal-pool data map builder — see the guard comment in
 * ios_jit_patch_x18. Shared by the patcher and the trampoline-need
 * counter. Caller frees. NULL on alloc failure (callers degrade to the
 * unguarded pre-2026-07-07 behavior). */
/* One BIT per 4-byte instruction word; see ios_x18_build_data_map. Every reader
 * must use this -- an open-coded index is how the teb-tsd retarget pass read past
 * the end of the allocation. `off` is a BYTE offset into .text. */
#define IOS_X18_DATA_WORD(dm, off)     ((dm)[(((size_t)(off)) / 4) >> 3] & (1 << ((((size_t)(off)) / 4) & 7)))

static unsigned char *ios_x18_build_data_map( const char *text, size_t text_size )
{
    unsigned char *data_map = calloc( 1, text_size / 32 + 1 );
    if (!data_map) return NULL;
    for (size_t i = 0; i < text_size; i += 4)
    {
        uint32_t insn = *(const uint32_t *)(text + i);
        uint32_t top8 = insn >> 24;
        size_t lit_bytes;
        int64_t imm19;
        size_t tgt;
        switch (top8)
        {
        case 0x18: case 0x1C: case 0x98: lit_bytes = 4;  break;  /* LDR Wt/St, LDRSW */
        case 0x58: case 0x5C: case 0xD8: lit_bytes = 8;  break;  /* LDR Xt/Dt, PRFM  */
        case 0x9C:                       lit_bytes = 16; break;  /* LDR Qt           */
        default: continue;
        }
        imm19 = (int64_t)(int32_t)(insn << 8) >> 13;  /* sign-extend bits[23:5] */
        tgt = i + (size_t)(imm19 * 4);
        if (imm19 * 4 + (int64_t)i < 0 || tgt >= text_size) continue;
        for (size_t b = tgt; b < tgt + lit_bytes && b < text_size; b += 4)
            data_map[(b / 4) >> 3] |= 1 << ((b / 4) & 7);
    }
    return data_map;
}

/* Task #25: exact trampoline budget. The old callers reserved 100% of
 * .text for trampolines and used ~1% (894 patches × 28B ≈ 25KB against a
 * 2.2MB reservation for ntdll) — with per-child copies of every DLL that
 * waste was ~HALF the pool (4 apps hit 368/384MB). Count the actual
 * patch sites and size the reservation to fit. */
size_t ios_jit_x18_tramp_need( const char *text, size_t text_size )
{
    unsigned char *data_map = ios_x18_build_data_map( text, text_size );
    size_t need = 0;
    for (size_t i = 0; i < text_size; i += 4)
    {
        uint32_t insn = *(const uint32_t *)(text + i);
        if (data_map && (data_map[(i / 4) >> 3] & (1 << ((i / 4) & 7)))) continue;
        if (ios_insn_x18_role( insn ) != X18_ROLE_NONE) need += 32;
    }
    free( data_map );
    /* Slack: the patcher's per-site max is 32B; pad one page so a
     * count/patch drift (e.g. data_map alloc failing in one of the two
     * passes) can't run the patcher out of space. */
    return need + 0x1000;
}

int ios_jit_patch_x18(char *text_rw, char *text_rx, size_t text_size,
                       char *tramp_rw, char *tramp_rx, size_t tramp_size)
{
    size_t tramp_off = 0;
    int count = 0;
    int skipped = 0;
    int lit_skipped = 0;
    int ldr_scratch = 0;   /* ml7xx: patched via the destination register */
    int x18_scratch = 0;   /* ml7xx: patched via x18 itself */
    unsigned char *data_map = NULL;
    extern int ios_teb_tls_slot_offset;

    /* B/BL reach guard (Steam S3 run 11 root cause): imm26 spans ±128MB.
     * The patcher used to encode out-of-range tramp offsets silently
     * truncated mod 256MB → branches into untouched pool (the run 7-11
     * "poison pointer" crash family). The allocator now anchors tramp
     * ranges near the image; this guard makes an out-of-reach pair a hard
     * REFUSAL (unpatched x18 insns degrade to recoverable runtime faults,
     * a truncated branch is fatal). */
    {
        intptr_t d1 = (tramp_rx + tramp_size) - text_rx;
        intptr_t d2 = tramp_rx - (text_rx + text_size);
        if (d1 > 0x7C00000 || d1 < -0x7C00000 || d2 > 0x7C00000 || d2 < -0x7C00000)
        {
            dprintf(2, "[x18-tramp] REFUSED: tramp %p+0x%lx out of B/BL reach of text %p+0x%lx\n",
                    tramp_rx, (unsigned long)tramp_size, text_rx, (unsigned long)text_size);
            return 0;
        }
    }

    /* Literal-pool guard (2026-07-07, conhost boot-death): .text embeds
     * DATA — every syscall stub ends `ldr x16, <lit>; ldr x16,[x16]; blr
     * x16; ret; <8-byte slot address>`. The literal's VALUE depends on the
     * copy's pool base (DIR64-rebased), and for bases in 0x128xxxxxxx the
     * low word decoded as LDP with rt2=18 → the patcher stamped a branch
     * over the literal → the stub loaded a garbage dispatcher → BLR to
     * junk on the child's FIRST syscall. Pure address lottery; also
     * latent for session copies (image VAs 0x7fb9.../0x7ff9... make
     * 0xB9/0xF9-topped literals = LDR-class false matches).
     * Fix: pre-scan for LDR (literal) instructions and mark their target
     * words as data; never patch a data word. False LDR-literal decodes
     * (data that happens to look like one) only mark extra words as data
     * — an unpatched real instruction degrades to a recoverable runtime
     * fault, while a patched literal is fatal. Asymmetry favors skipping. */
    data_map = ios_x18_build_data_map( text_rw, text_size );

    /* Pass 0: retarget hand-written TEB-from-TSD reads.
     *
     * FEX's Module.S contains the same three-instruction sequence this
     * patcher emits, written by hand and assembled with a fixed slot:
     *
     *     mrs xN, TPIDRRO_EL0
     *     and xN, xN, #~7
     *     ldr xN, [xN, #<slot*8>]
     *
     * The slot is not knowable at assembly time -- it is whichever raw TSD
     * slot backs our pthread key in this process -- so rewrite the immediate
     * here, where the offset is already discovered and we are already editing
     * .text through its RW alias before it is ever executed.
     *
     * The triplet is matched in full and all three registers must agree, so a
     * stray LDR with a coincidental immediate cannot be hit. Literal-pool
     * words are excluded via data_map for the same reason as the x18 pass. */
    /* The "offset not discovered yet" case is FATAL-BY-SILENCE and must not stay
     * quiet. If an image carrying the triplet is patched before the TSD slot is
     * known, the pass is skipped, the PLACEHOLDER immediate survives, and every
     * TEB read in that image returns whatever pthread keeps in slot 0x898 -- a
     * wrong pointer used as the TEB, with no fault to catch it. The ordering is
     * sound today (the slot is published during early ntdll-unix init, long
     * before any PE is copied), so this is insurance, not a known path. */
    if (!ios_teb_tls_slot_offset && text_size >= 12)
    {
        for (size_t i = 0; i + 12 <= text_size; i += 4)
        {
            uint32_t i0 = *(uint32_t *)(text_rw + i);
            unsigned reg = i0 & 0x1f;
            if ((i0 & 0xffffffe0) != 0xd53bd060) continue;
            if (*(uint32_t *)(text_rw + i + 4) != (0x927df000u | (reg << 5) | reg)) continue;
            if ((*(uint32_t *)(text_rw + i + 8) & 0xffc003ff) != (0xf9400000u | (reg << 5) | reg))
                continue;
            dprintf(2, "[teb-tsd] FATAL-BY-SILENCE: .text %p contains a hand-written TSD read at +0x%lx but the "
                       "slot offset is NOT KNOWN YET -- the placeholder immediate will survive and "
                       "this image will read a stranger's TSD word as its TEB\n",
                    text_rx, (unsigned long)i);
            break;
        }
    }

    if (ios_teb_tls_slot_offset && text_size >= 12)
    {
        const uint32_t want_imm = (uint32_t)(ios_teb_tls_slot_offset / 8) << 10;
        static int announced;
        int found = 0, retargeted = 0;

        /* Liveness beacon: without it, "no retarget line" is ambiguous between
         * "the pass never ran" and "it ran and matched nothing" -- and the
         * first cut of this probe used ERR(), which is muted in this file, so
         * it could not report at all. */
        if (!announced)
        {
            announced = 1;
            dprintf(2, "[teb-tsd] retarget pass armed, offset=0x%x\n", ios_teb_tls_slot_offset);
        }

        for (size_t i = 0; i + 12 <= text_size; i += 4)
        {
            uint32_t i0, i1, i2;
            unsigned reg;

            /* This read used to be `data_map[i / 4]`, one BYTE per instruction
             * word. ios_x18_build_data_map allocates `text_size / 32 + 1` bytes
             * and stores ONE BIT per word -- the x18 pass below reads it as
             * `dm[(i/4) >> 3] & (1 << ((i/4) & 7))`. The byte form was wrong
             * twice over: it read out of bounds from the eighth of .text onwards
             * (for a 2 MB .text, ~512 KB past the end of a 132 KB allocation),
             * and whatever heap byte it found there made the triplet look like
             * a literal pool and be SKIPPED. Whether a given build of the CPU
             * module was patched therefore depended on where its linker put the
             * triplets: one build's sat inside the first eighth and worked, the
             * next build's sat past it, kept the placeholder slot, read a
             * stranger's TSD word as the TEB and faulted at 0x1788 on the first
             * transition into the emulator. */
            if (data_map && (IOS_X18_DATA_WORD( data_map, i ) ||
                             IOS_X18_DATA_WORD( data_map, i + 4 ) ||
                             IOS_X18_DATA_WORD( data_map, i + 8 )))
                continue;

            i0 = *(uint32_t *)(text_rw + i);
            if ((i0 & 0xffffffe0) != 0xd53bd060) continue;      /* mrs xN, TPIDRRO_EL0 */
            reg = i0 & 0x1f;

            i1 = *(uint32_t *)(text_rw + i + 4);
            /* and xN, xN, #0xfffffffffffffff8 */
            if (i1 != (0x927df000u | (reg << 5) | reg)) continue;

            i2 = *(uint32_t *)(text_rw + i + 8);
            /* ldr xN, [xN, #imm12*8] -- same register throughout */
            if ((i2 & 0xffc003ff) != (0xf9400000u | (reg << 5) | reg)) continue;

            found++;
            if ((i2 & 0x003ffc00) == want_imm) continue;        /* already correct */

            *(uint32_t *)(text_rw + i + 8) = (i2 & ~0x003ffc00u) | want_imm;
            retargeted++;
        }

        /* Report whenever the module HAS such reads, so found>0/retargeted==0
         * (already correct) is distinguishable from found==0 (none present). */
        if (found)
            dprintf(2, "[teb-tsd] .text %p: found %d static TSD read(s), retargeted %d to offset 0x%x\n",
                    text_rx, found, retargeted, ios_teb_tls_slot_offset);
    }

    for (size_t i = 0; i < text_size; i += 4)
    {
        uint32_t insn = *(uint32_t *)(text_rw + i);
        int role;
        if (data_map && (data_map[(i / 4) >> 3] & (1 << ((i / 4) & 7))))
        {
            if (ios_insn_x18_role(insn) != X18_ROLE_NONE) lit_skipped++;
            continue;
        }
        role = ios_insn_x18_role(insn);
        if (role == X18_ROLE_NONE) continue;

        /* ml7xx SP-ALIGN: no trampoline form below touches the stack, so the
         * old x16/x17 scratch selection (and its "both in use, give up" skip)
         * is gone. It was never a register-pressure problem -- it was that
         * saving the scratch meant `str xN, [sp, #-16]!`, and AArch64 faults
         * that store outright when SP is not 16-byte aligned:
         *
         *   kr=259 == EXC_ARM_SP_ALIGN   sp=0x703881f4d8   sp % 16 == 8
         *
         * An 8-mod-16 SP is not corruption. It is what x86-64 hands us: `call`
         * pushes the return address, so guest RSP is 8 (mod 16) for the whole
         * body of a called function, and ARM64EC carries that straight into
         * SP. Native ARM64 keeps SP aligned, which is why the arm64 cube never
         * hit this and only the x64 path died -- every single time, at the
         * first instruction of a trampoline.
         *
         * So: never use the stack. Three forms, safest first. */
        int rt = insn & 0x1f;
        int rn = (insn >> 5) & 0x1f;
        int rm = (insn >> 16) & 0x1f;
        (void)rn; (void)rm;

        /* Check trampoline space (max 6 instructions = 24 bytes per trampoline) */
        if (tramp_off + 24 > tramp_size)
        {
            ERR("x18 patcher: out of trampoline space at %d patches\n", count);
            break;
        }

        uintptr_t insn_rx = (uintptr_t)(text_rx + i);
        uintptr_t tramp_rx_addr = (uintptr_t)(tramp_rx + tramp_off);
        uintptr_t return_rx = insn_rx + 4;

        /* TEB load sequence (3 instructions, uses TPIDRRO_EL0 which iOS preserves):
         *   mrs xSCRATCH, TPIDRRO_EL0
         *   and xSCRATCH, xSCRATCH, #~7   (clear CPU number from low 3 bits)
         *   ldr xSCRATCH, [xSCRATCH, #SLOT_OFFSET]  (load TEB from TLS slot)
         */
        extern int ios_teb_tls_slot_offset;
        int slot_off = ios_teb_tls_slot_offset;

        /* Check if this is MOV xN, x18 (special case — load TEB directly into dest) */
        int is_mov_from_x18 = (role == X18_ROLE_RM) &&
            ((insn & 0xFFE0FFE0) == 0xAA0003E0) && rm == 18;

        /* LDR (unsigned immediate), integer, 32- or 64-bit, x18 as the base.
         * 41 of xtajit64.dll's 115 x18 references are this shape. */
        int is_int_ldr_imm = (role == X18_ROLE_RN) &&
            (((insn & 0xFFC00000) == 0xF9400000) ||      /* ldr xT, [x18,#imm] */
             ((insn & 0xFFC00000) == 0xB9400000)) &&     /* ldr wT, [x18,#imm] */
            rt != 31 && rt != 18;

        /* madeira-bcd: ADD/SUB off x18 with a usable destination (see
         * ios_x18_arith_dest): same form as the LDR below. */
        int arith_rd = (!is_mov_from_x18 && !is_int_ldr_imm) ? ios_x18_arith_dest(insn, role) : -1;

        if (is_mov_from_x18)
        {
            int rd = insn & 0x1f;
            /* mrs xRd, TPIDRRO_EL0 */
            *(uint32_t *)(tramp_rw + tramp_off) = 0xD53BD060 | rd;
            tramp_off += 4;
            /* and xRd, xRd, #~7 (immediate: 0xFFFFFFFFFFFFFFF8 = immr=0 imms=0x3C) */
            *(uint32_t *)(tramp_rw + tramp_off) = 0x927DF000 | (rd << 5) | rd;
            tramp_off += 4;
            /* ldr xRd, [xRd, #slot_off] */
            *(uint32_t *)(tramp_rw + tramp_off) = 0xF9400000 | ((slot_off / 8) << 10) | (rd << 5) | rd;
            tramp_off += 4;
        }
        else if (is_int_ldr_imm)
        {
            /* LDR (unsigned immediate) off x18. The destination register is
             * about to be overwritten by this very instruction, so it can be
             * the scratch: nothing to save, nothing to restore.
             *   mrs xRt, TPIDRRO_EL0
             *   and xRt, xRt, #~7
             *   ldr xRt, [xRt, #slot_off]
             *   ldr xRt, [xRt, #orig_imm]     (x18 -> xRt)
             * A 32-bit form (ldr wT) still writes the full 64-bit register in
             * the three setup instructions and narrows only on the last, which
             * is the semantics the original had. */
            if (tramp_off + 24 > tramp_size)
            {
                ERR("x18 patcher: out of trampoline space at %d patches\n", count);
                break;
            }
            *(uint32_t *)(tramp_rw + tramp_off) = 0xD53BD060 | rt;
            tramp_off += 4;
            *(uint32_t *)(tramp_rw + tramp_off) = 0x927DF000 | (rt << 5) | rt;
            tramp_off += 4;
            *(uint32_t *)(tramp_rw + tramp_off) = 0xF9400000 | ((slot_off / 8) << 10) | (rt << 5) | rt;
            tramp_off += 4;
            *(uint32_t *)(tramp_rw + tramp_off) = ios_insn_replace_x18(insn, role, rt);
            tramp_off += 4;
            ldr_scratch++;
        }
        else if (arith_rd >= 0)
        {
            /*   mrs xRd, TPIDRRO_EL0
             *   and xRd, xRd, #~7
             *   ldr xRd, [xRd, #slot_off]
             *   add/sub xRd, xRd, <the other operand>   (x18 -> xRd)
             * Counted with the destination-register forms. */
            if (tramp_off + 20 > tramp_size)
            {
                ERR("x18 patcher: out of trampoline space at %d patches\n", count);
                break;
            }
            *(uint32_t *)(tramp_rw + tramp_off) = 0xD53BD060 | arith_rd;
            tramp_off += 4;
            *(uint32_t *)(tramp_rw + tramp_off) = 0x927DF000 | (arith_rd << 5) | arith_rd;
            tramp_off += 4;
            *(uint32_t *)(tramp_rw + tramp_off) = 0xF9400000 | ((slot_off / 8) << 10) | (arith_rd << 5) | arith_rd;
            tramp_off += 4;
            *(uint32_t *)(tramp_rw + tramp_off) = ios_insn_replace_x18(insn, role, arith_rd);
            tramp_off += 4;
            ldr_scratch++;
        }
        else
        {
            /* Stores, LDP, and arithmetic: the operands must all survive, so
             * there is no free destination register to borrow. Use x18 itself.
             *   mrs x18, TPIDRRO_EL0
             *   and x18, x18, #~7
             *   ldr x18, [x18, #slot_off]
             *   <original instruction, byte for byte>
             *
             * The header above says patched code must never touch x18, because
             * iOS zeroes it and a stale x18 read silently returns page zero.
             * That reasoning holds for code that READS x18 expecting the TEB.
             * Here x18 is written from TPIDRRO_EL0 and consumed one
             * instruction later, so the value is never stale -- and if the
             * thread is preempted in that window, x18 comes back zero and the
             * original instruction faults on the zero page, which the handler
             * already recovers. A rare recoverable fault beats the certain
             * SP-align kill this replaces. */
            if (tramp_off + 20 > tramp_size)
            {
                ERR("x18 patcher: out of trampoline space at %d patches\n", count);
                break;
            }
            *(uint32_t *)(tramp_rw + tramp_off) = 0xD53BD060 | 18;
            tramp_off += 4;
            *(uint32_t *)(tramp_rw + tramp_off) = 0x927DF000 | (18 << 5) | 18;
            tramp_off += 4;
            *(uint32_t *)(tramp_rw + tramp_off) = 0xF9400000 | ((slot_off / 8) << 10) | (18 << 5) | 18;
            tramp_off += 4;
            *(uint32_t *)(tramp_rw + tramp_off) = insn;
            tramp_off += 4;
            x18_scratch++;
        }

        /* Branch back to return address */
        intptr_t ret_delta = (intptr_t)return_rx - (intptr_t)(tramp_rx + tramp_off);
        *(uint32_t *)(tramp_rw + tramp_off) = 0x14000000 | ((ret_delta >> 2) & 0x3FFFFFF);
        tramp_off += 4;

        /* Patch original instruction: B <trampoline> */
        intptr_t fwd_delta = (intptr_t)tramp_rx_addr - (intptr_t)insn_rx;
        uint32_t b_insn = 0x14000000 | ((fwd_delta >> 2) & 0x3FFFFFF);
        *(uint32_t *)(text_rw + i) = b_insn;

        if (count < 2)
        {
            ERR("  patch[%d]: text+0x%lx orig=0x%08x → B 0x%08x delta=%ld slot_off=0x%x\n",
                count, (unsigned long)i, insn, b_insn, (long)fwd_delta, slot_off);
            /* Dump first trampoline instructions */
            size_t t_start = tramp_off - (is_mov_from_x18 ? 12 : 24) - 4; /* back to start */
            for (int d = 0; d <= (is_mov_from_x18 ? 3 : 6); d++)
                ERR("    tramp[%d]=0x%08x\n", d, *(uint32_t *)(tramp_rw + t_start + d * 4));
        }

        count++;
    }

    /* ml1005: dprintf, not ERR. The `virtual` channel is muted -- rdr73 has
     * ZERO err:virtual: lines in 25,688 -- so this summary has never once
     * reached a log, and "the x18 patcher did not run" was unprovable either
     * way. The file already knows this trap ("dprintf, not ERR (err-virtual
     * muted)" three lines below) and the most important line in the function
     * was still an ERR.
     *
     * Print the RANGE, not just the counts: rdr73 died because
     * arm64x_check_call at 0x12ef9a200 -- inside the GAME process's own ntdll
     * pool copy -- reported "cc[0] is NOT a B — patcher missed it", while each
     * pseudo-process gets its own copy (007c=0x12349e200, 0084=0x12701a200,
     * 008c=0x12ef9a200). Whether a patcher run ever covered that address is
     * exactly what the counts alone cannot say. */
    if (count > 0 || skipped > 0 || text_size)
        dprintf(2, "[x18-patch] ml1005 text=%p+%#lx (rw=%p) patched=%d skipped=%d "
                "tramp=%p+%#lx used=%lu\n",
                text_rx, (unsigned long)text_size, text_rw, count, skipped,
                tramp_rx, (unsigned long)tramp_size, (unsigned long)tramp_off);
    /* dprintf, not ERR: err-virtual is muted, and after the SP-align fix the
     * split is the thing to check on-device -- no trampoline may touch SP. */
    if (count > 0)
        dprintf(2, "[x18-tramp] .text %p: %d patched -- %d via dest reg, %d via x18, "
                   "%d MOV-direct; 0 use the stack (was: all of them, and x86 hands "
                   "us an 8-mod-16 SP)\n",
                text_rx, count, ldr_scratch, x18_scratch,
                count - ldr_scratch - x18_scratch);
    /* dprintf, not ERR (err-virtual muted): literal words the x18 matcher
     * WOULD have clobbered — nonzero = a dodged conhost-class boot death. */
    if (lit_skipped)
        dprintf(2, "[x18-lit] %d literal-pool word(s) matched x18 patterns — skipped (data, not code)\n",
                lit_skipped);
    free( data_map );

    /* Verify: log first patched instruction's encoding */
    if (count > 0)
    {
        for (size_t i = 0; i < text_size; i += 4)
        {
            uint32_t insn = *(uint32_t *)(text_rw + i);
            if ((insn >> 26) == 5)  /* found a B instruction (our patch) */
            {
                int32_t imm26 = (int32_t)(insn & 0x3FFFFFF);
                if (imm26 & 0x2000000) imm26 |= (int32_t)0xFC000000;
                intptr_t delta = (intptr_t)imm26 << 2;
                ERR("  verify: text+0x%lx insn=0x%08x B delta=%ld target=%p tramp_rx=%p\n",
                    (unsigned long)i, insn, (long)delta,
                    (void*)((uintptr_t)(text_rx + i) + delta), (void*)tramp_rx);
                /* Check first trampoline instruction */
                ERR("  tramp[0]=0x%08x tramp[1]=0x%08x\n",
                    *(uint32_t *)tramp_rw, *(uint32_t *)(tramp_rw + 4));
                break;
            }
        }
    }

    return count;
}

