/* Part of signal_arm64_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. The Mach exception server (ios_mach_exception_thread). Same copyright and licence as signal_arm64_ios.c. */
/* ml1242: the JIT-pool dump is sparse, and MADEIRA_JIT_DUMP=0 turns it off.
 *
 * Both one-shot dumps used to write the whole 896MB RW alias. The production
 * pool is not NO_FOOTPRINT (see jit_make_region_no_footprint), and a read fault
 * on an untouched page of it materialises a real zero page, so the dump alone
 * charged ~600MB to phys_footprint: Hollow Knight went 2169 -> 2755MB while it
 * ran and hit the 4096MB jetsam limit four seconds later. Pages mincore()
 * reports neither resident nor paged out were never written; they stay holes,
 * so file offsets still equal pool offsets (head copies and tail CodeBuffers). */
static void ios_dump_jit_pool( const char *why )
{
    extern void *ios_jit_rw_base_global;
    extern size_t ios_jit_pool_size_global;
    const size_t chunk = 0x100000;
    size_t ps = vm_page_size, total = ios_jit_pool_size_global, written = 0, off, i;
    const char *docs;
    char path[512], vec[256];   /* one byte per page of a 1MB chunk, down to 4KB pages */
    int fd;

    const char *jd = getenv( "MADEIRA_JIT_DUMP" );
    /* 0: no Documents/fex-jit-dump.bin; by default the JIT pool is written (sparse) on the
     * first mach UNHANDLED / SIGILL, and pulled with the log (ml1242) */
    if ((jd && jd[0] == '0') || !ios_jit_rw_base_global || !total) return;
    docs = getenv( "MADEIRA_DOCS_DIR" );
    snprintf( path, sizeof(path), "%s/fex-jit-dump.bin", docs ? docs : "/tmp" );
    if ((fd = open( path, O_WRONLY | O_CREAT | O_TRUNC, 0644 )) < 0)
    {
        dprintf( 2, "[jit-dump] ml1242 %s: open failed errno=%d path=%s\n", why, errno, path );
        return;
    }
    for (off = 0; off < total; off += chunk)
    {
        size_t len = total - off < chunk ? total - off : chunk;
        char *base = (char *)ios_jit_rw_base_global + off;
        int have_vec = len / ps <= sizeof(vec) && !mincore( base, len, vec );

        for (i = 0; i < len; i += ps)
        {
            size_t n = len - i < ps ? len - i : ps;
            if (have_vec && !(vec[i / ps] & (MINCORE_INCORE | MINCORE_PAGED_OUT))) continue;
            if (pwrite( fd, base + i, n, off + i ) != (ssize_t)n) goto done;
            written += n;
        }
    }
done:
    ftruncate( fd, total );
    close( fd );
    dprintf( 2, "[jit-dump] ml1242 %s: wrote %zu of %zu pool bytes to %s (untouched pages left as holes)\n",
             why, written, total, path );
}

/* The [fault-stuck] loop breaker in ios_mach_exception_thread keeps its state per thread (an
 * exact ios_guard_slot record), and every exception delivered to the guest starts that
 * thread's count again; the delivery count is kept in 16 slots chosen by thread. It was one app-wide
 * (page, pc, address) count, so faults of many threads at one instruction, or one thread's
 * handled int3 or single-step exceptions there, read as a livelock: the thread was diverted
 * to abort_thread and no exception reached the program. Windows delivers every one. A
 * livelock is one thread re-faulting with no delivery in between; that is still broken. */
static volatile unsigned ios_guest_deliv_seq[16];

static inline int ios_fault_slot( uint64_t thread )
{
    return (int)((thread * 0x9E3779B97F4A7C15ull) >> 60);
}

static inline void ios_note_guest_delivery( uint64_t thread )
{
    __atomic_add_fetch( &ios_guest_deliv_seq[ios_fault_slot( thread )], 1, __ATOMIC_RELEASE );
}

/* ml1289: a store into aliased pages that CROSSES a 16 KB page boundary.
 *
 * The older cases of the write-fault store emulator (STR/STRB/STRH/STP/STUR,
 * GPR and SIMD&FP, in ios_mach_exception_thread) write the whole access at
 * alias(fault_addr): they take fault_addr as the start of the access and
 * assume the alias goes on past the end of its page. A store that crosses a
 * page breaks both: fault_addr need not be its first byte, and the next page
 * may belong to another alias range or have none, so the bytes land at the
 * wrong place or past the end of the first range's RW view. ml1276 and
 * upstream's ml1283 already handle their encodings per page; this does the
 * same for the rest, and only for crossing stores, so every other store keeps
 * its existing case. The address comes from the registers, each page takes
 * its own alias (a page without one that is plain writable memory is written
 * directly), the store is refused when a page has neither, and the base
 * register is written back after the whole store for the indexed forms.
 * Store-release forms are left alone: a crossing STLR/STLUR is misaligned and
 * takes the alignment-fault path instead.
 *
 * Returns 1 (written), -1 (refused: a page of the store has no alias) or 0
 * (not a crossing store this helper decodes; the per-encoding cases run).
 * ml1292: also called by the thread sampler (server_ios.c) to complete a store
 * the kernel keeps faulting on, with the thread suspended. */
int ios_store_split_crossing( uint32_t insn, arm_thread_state64_t *st,
                                     const arm_neon_state64_t *neon,
                                     uintptr_t rx, uintptr_t rw, size_t sz )
{
    extern uintptr_t ios_jit_anon_alias_lookup( uintptr_t fault_addr );
    extern void ios_jit_anon_alias_note_write( unsigned long long );
    const unsigned rt = insn & 31, rn = (insn >> 5) & 31, size = insn >> 30, v = (insn >> 26) & 1;
    const unsigned opc = (insn >> 22) & 3;
    const uint64_t base = rn == 31 ? st->__sp : st->__x[rn];
    uint8_t src[32];
    uint64_t ea, a, x0, x1;
    int64_t imm = 0;
    int wb = 0, pair = 0;
    unsigned bytes, elem, rt2 = (insn >> 10) & 31, parts = 0, done = 0, i, part_len[2];
    uintptr_t part_rw[2];

    if ((insn & 0x3a000000u) == 0x28000000u)                    /* STP/STNP and SIMD&FP pairs */
    {
        const unsigned mode = (insn >> 23) & 3;              /* 0 stnp, 1 post, 2 offset, 3 pre */
        if ((insn >> 22) & 1) return 0;                      /* loads */
        if (v) elem = size == 3 ? 0 : 4u << size;            /* S, D, Q */
        else   elem = size == 0 ? 4 : size == 2 ? 8 : 0;     /* W, X (01 is STGP) */
        if (!elem) return 0;
        imm = (((int64_t)((insn >> 15) & 0x7f)) << 57 >> 57) * (int64_t)elem;
        ea = mode == 1 ? base : base + (uint64_t)imm;
        wb = mode == 1 || mode == 3;
        bytes = 2 * elem;
        pair = 1;
    }
    else if ((insn & 0x3b000000u) == 0x38000000u || (insn & 0x3b000000u) == 0x39000000u)
    {
        /* single-register LDR/STR families: a store has opc 00 (GPR) or opc<0> = 0 (SIMD&FP) */
        if (v ? (opc & 1) : opc != 0) return 0;
        elem = v && (opc & 2) ? (size == 0 ? 16u : 0u) : 1u << size;
        if (!elem) return 0;
        if ((insn & 0x3b000000u) == 0x39000000u)                 /* unsigned offset */
            ea = base + ((uint64_t)((insn >> 10) & 0xfff) * elem);
        else if ((insn & 0x00200c00u) == 0x00200800u)            /* register offset */
        {
            const unsigned option = (insn >> 13) & 7, rm = (insn >> 16) & 31;
            uint64_t off = rm == 31 ? 0 : st->__x[rm];
            if (!(option & 2)) return 0;
            if (option == 2) off = (uint32_t)off;
            else if (option == 6) off = (uint64_t)(int64_t)(int32_t)off;
            if (insn & 0x1000) off *= elem;
            ea = base + off;
        }
        else if (!(insn & 0x00200000u))                          /* unscaled, post, pre */
        {
            const unsigned idx = (insn >> 10) & 3;
            if (idx == 2) return 0;                                /* unprivileged */
            imm = ((int64_t)((insn >> 12) & 0x1ff)) << 55 >> 55;
            ea = idx == 1 ? base : base + (uint64_t)imm;
            wb = idx == 1 || idx == 3;
        }
        else return 0;
        bytes = elem;
    }
    else return 0;

    if (((ea ^ (ea + bytes - 1)) & ~(uint64_t)0x3fff) == 0) return 0;   /* within one page */
    if (v && !neon) return 0;

    if (v)
    {
        memcpy( src, &neon->__v[rt], elem );
        if (pair) memcpy( src + elem, &neon->__v[rt2], elem );
    }
    else
    {
        x0 = rt == 31 ? 0 : st->__x[rt];
        x1 = rt2 == 31 ? 0 : st->__x[rt2];
        memcpy( src, &x0, elem );
        if (pair) memcpy( src + elem, &x1, elem );
    }

    while (done < bytes && parts < 2)
    {
        unsigned len = bytes - done;
        a = ea + done;
        if (len > 0x4000 - (a & 0x3fff)) len = 0x4000 - (unsigned)(a & 0x3fff);
        part_rw[parts] = (rx && rw && sz && a >= rx && a - rx <= sz - len)
                         ? rw + (a - rx) : ios_jit_anon_alias_lookup( (uintptr_t)a );
        if (!part_rw[parts])
        {
            /* A page with no alias that is plain writable memory (the aliased page is
             * the one that faulted) takes its bytes directly. */
            mach_vm_address_t ra = (mach_vm_address_t)a;
            mach_vm_size_t rs = 0;
            vm_region_basic_info_data_64_t ri;
            mach_msg_type_number_t rc = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t ro = MACH_PORT_NULL;
            if (mach_vm_region( mach_task_self(), &ra, &rs, VM_REGION_BASIC_INFO_64,
                                (vm_region_info_t)&ri, &rc, &ro ) == KERN_SUCCESS &&
                ra <= a && a + len <= ra + rs && (ri.protection & VM_PROT_WRITE))
                part_rw[parts] = (uintptr_t)a;
            if (ro != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), ro );
        }
        if (!part_rw[parts]) break;
        part_len[parts++] = len;
        done += len;
    }
    {
        static int split_n;
        if (split_n < 8)
            dprintf( STDERR_FILENO, "[split-store] ml1289 #%d insn=0x%08x bytes=%u ea=0x%llx parts=%u %s\n",
                     ++split_n, insn, bytes, (unsigned long long)ea, parts,
                     done == bytes ? "emulated" : "REFUSED: a page of the store has no alias and is not writable" );
    }
    if (done != bytes) return -1;
    for (i = 0, done = 0; i < parts; done += part_len[i], i++)
    {
        memcpy( (void *)part_rw[i], src + done, part_len[i] );
        ios_jit_anon_alias_note_write( (unsigned long long)(ea + done) );
    }
    if (wb)
    {
        if (rn == 31) st->__sp = base + (uint64_t)imm;
        else          st->__x[rn] = base + (uint64_t)imm;
    }
    return 1;
}

static void *ios_mach_exception_thread( void *arg )
{
    mach_port_t port = (mach_port_t)(uintptr_t)arg;

    /* Name this thread for debugging */
    pthread_setname_np("wine-x18-exc");

    /* 2026-07-04 perf: this thread is effectively an interrupt handler —
     * every STR emulation, exec-fault redirect, and USD read (~2,600 per
     * present-group in gameplay) suspends the faulting thread until THIS
     * thread services the message. At default QoS it is E-core-eligible
     * and can be preempted by every USER_INTERACTIVE game thread — each
     * fault then pays scheduling latency on top of handling cost. Run it
     * as hot as its clients. */
    pthread_set_qos_class_self_np( QOS_CLASS_USER_INTERACTIVE, 0 );

    ios_exc_thread_alive = 1;

    for (;;)
    {
        /* Use a large buffer to handle any message variant */
        union {
            ios_exc_request_t typed;
            char buf[1024];
        } msg;
        kern_return_t kr = mach_msg( &msg.typed.head, MACH_RCV_MSG, 0,
                                      sizeof(msg), port,
                                      MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL );
        if (kr != KERN_SUCCESS) continue;

        ios_exc_request_t *req = &msg.typed;
        ios_exc_msg_count++;
        ios_cur_fault_port = req->thread.name;              /* ml690 */
        ios_store_fault_t0 = mach_absolute_time();          /* ml680 */

        thread_t thread = req->thread.name;
        int handled = 0;

        /* 2026-07-03 storm probe: ~40K Mach exceptions PER PRESENT measured
         * in the menu phase (~all of the 1.4s frame time at ~33us each).
         * Sample every 4096th message: exception type + faulting PC + insn
         * so the trap source is nameable from one run. */
        /* ml649: gate the WORK. This costs two Mach round-trips (thread_get_state
         * + vm_read_overwrite) per sample, so checking the flag before them is the
         * point — checking it before the dprintf would save nothing. */
        if ((ios_exc_msg_count % 200000) == 0 && ios_store_fault_n)
        {   /* ml680: mach_timebase converts ticks to ns once. ONE handler thread
             * serves every Wine thread, so this total is a hard serialised
             * ceiling on the whole app, not a per-thread cost. */
            /* mach_timebase_info_data_t is not visible in this TU's header set;
             * the struct is two uint32s and the call takes it by pointer. */
            struct { unsigned int numer, denom; } tb = {0, 0};
            extern int mach_timebase_info(void *);
            unsigned long long n = ios_store_fault_n, tk = ios_store_fault_ticks;
            mach_timebase_info(&tb);
            {
                unsigned long long ns = tb.denom ? (tk * tb.numer) / tb.denom : tk;
                dprintf(STDERR_FILENO,
                    "[fault-cost] ml685 emulated-store faults=%llu total=%llu ms avg=%llu ns "
                    "dropped=%llu (one handler thread serves all threads)\n",
                    n, ns / 1000000ull, ns / n, ios_store_fault_dropped);
            }
        }
        if (madeira_diag_enabled && (ios_exc_msg_count & 0xFFF) == 0)
        {
            arm_thread_state64_t pstate;
            mach_msg_type_number_t pcount = ARM_THREAD_STATE64_COUNT;
            if (thread_get_state( thread, ARM_THREAD_STATE64,
                                  (thread_state_t)&pstate, &pcount ) == KERN_SUCCESS)
            {
                uint64_t ppc = arm_thread_state64_get_pc( pstate );
                uint32_t pinsn = 0;
                vm_size_t psz = sizeof(pinsn);
                vm_read_overwrite( mach_task_self(), ppc, sizeof(pinsn),
                                   (vm_address_t)&pinsn, &psz );
                dprintf(STDERR_FILENO,
                        "[EXC_SAMPLE] #%d exc=%d code0=0x%llx pc=0x%llx insn=0x%08x lr=0x%llx\n",
                        ios_exc_msg_count, req->exception,
                        (unsigned long long)(req->code_count > 1 ? req->code[1] : req->code[0]),
                        (unsigned long long)ppc, pinsn,
                        (unsigned long long)pstate.__lr);
            }
        }

        /* ml523 (#67): count EXC_BREAKPOINT arrivals and name the BRK immediate.
         *
         * These used to go to StikDebug's task port. FEX's JIT emits
         * `brk #0xCAFE` (0xd4395fc0) inline for Arm64JITCore::EmitSuspendInterruptCheck,
         * so every thread-pause check is a trap the debugger had to service —
         * and a debugger pegged at 97% in its own busy-wait takes ~54s to reply
         * while the WHOLE TASK is stopped waiting. That is #67.
         *
         * We now own the mask and decline (handled stays 0 => KERN_FAILURE),
         * which escalates to the host default => BSD SIGTRAP => trap_handler,
         * where the 0xf00d and generic-trap cases already live. That is the
         * same end state madeira-jit.js produced with forwardSignal(), minus the
         * round-trip to a starved debugger.
         *
         * Bounded so a suspend-check storm cannot flood the log, but the FIRST
         * ones always print — they are what must line up against a [freeze] GAP. */
        if (req->exception == EXC_BREAKPOINT)
        {
            static volatile int bp_count;
            int n = __sync_add_and_fetch( &bp_count, 1 );
            if (n <= 12 || (n % 500) == 0)
            {
                arm_thread_state64_t bs;
                mach_msg_type_number_t bc = ARM_THREAD_STATE64_COUNT;
                uint64_t bpc = 0; uint32_t binsn = 0;
                if (thread_get_state( thread, ARM_THREAD_STATE64,
                                      (thread_state_t)&bs, &bc ) == KERN_SUCCESS)
                {
                    vm_size_t bsz = sizeof(binsn);
                    bpc = arm_thread_state64_get_pc( bs );
                    vm_read_overwrite( mach_task_self(), bpc, sizeof(binsn),
                                       (vm_address_t)&binsn, &bsz );
                }
                dprintf(STDERR_FILENO,
                        "[task-exc] BREAKPOINT #%d pc=0x%llx insn=0x%08x imm=0x%x %s rev=ml523\n",
                        n, (unsigned long long)bpc, binsn, (binsn >> 5) & 0xffff,
                        binsn == 0xd4395fc0 ? "FEX-SuspendCheck(0xCAFE)"
                        : binsn == 0xd43e01a0 ? "StikDebug-protocol(0xf00d)" : "other");

                /* ml559: NAME the trapping image.
                 *
                 * ml558 died on `BRK #1` (== __builtin_trap) at 0x191d52284 on a
                 * thread that is not ours — i.e. inside a SYSTEM library — and the
                 * whole task went with it, so no in-process probe could report why.
                 * A bare hex pc left me guessing which library it was, and guessing
                 * is exactly what has been wrong repeatedly here. dladdr costs
                 * nothing and turns the address into an answer. LR names the caller,
                 * which is the part that actually identifies the failing operation. */
                if (bpc && ((binsn & 0xffe0001fu) == 0xd4200000u))
                {
                    Dl_info di_pc, di_lr;
                    uint64_t blr = arm_thread_state64_get_lr( bs );
                    int okp = dladdr( (void *)(uintptr_t)bpc, &di_pc );
                    int okl = dladdr( (void *)(uintptr_t)blr, &di_lr );
                    dprintf(STDERR_FILENO,
                            "[task-exc]   TRAP-SYM pc=%s`%s+0x%llx  lr=0x%llx %s`%s+0x%llx rev=ml559\n",
                            okp && di_pc.dli_fname ? di_pc.dli_fname : "?",
                            okp && di_pc.dli_sname ? di_pc.dli_sname : "?",
                            okp && di_pc.dli_saddr ? (unsigned long long)(bpc - (uintptr_t)di_pc.dli_saddr) : 0ull,
                            (unsigned long long)blr,
                            okl && di_lr.dli_fname ? di_lr.dli_fname : "?",
                            okl && di_lr.dli_sname ? di_lr.dli_sname : "?",
                            okl && di_lr.dli_saddr ? (unsigned long long)(blr - (uintptr_t)di_lr.dli_saddr) : 0ull);

                    /* ml565: is this malloc trap OUT OF MEMORY, or real corruption?
                     *
                     * The trap is libsystem_malloc called from wineserver's
                     * alloc_object. Across 11 runs it separates PERFECTLY by memory
                     * footprint — traps at 3197-3339 MB, never at 3015-3114 MB — while
                     * run LENGTH does not predict it (ml560b ran 95 cycles, 5x longer
                     * than most, at the lowest footprint of all, and never trapped).
                     * So the mechanism is likelier pressure than accumulated damage,
                     * but that is unproven and these are the numbers that settle it.
                     *
                     * DO NOT call malloc here. The trapping thread is INSIDE malloc
                     * holding its lock; allocating from this handler thread could block
                     * on that lock and wedge the whole app — a probe that destroys what
                     * it measures. mach_vm_allocate goes straight to the VM and touches
                     * no malloc state. task_vm_info.limit_bytes_remaining is the kernel's
                     * own answer for how much headroom the process has left. */
                    if (okp && di_pc.dli_fname && strstr( di_pc.dli_fname, "libsystem_malloc" ))
                    {
                        task_vm_info_data_t vmi;
                        mach_msg_type_number_t vcnt = TASK_VM_INFO_COUNT;
                        mach_vm_address_t probe = 0;
                        kern_return_t ak = mach_vm_allocate( mach_task_self(), &probe,
                                                             1024 * 1024, VM_FLAGS_ANYWHERE );
                        if (ak == KERN_SUCCESS) mach_vm_deallocate( mach_task_self(), probe, 1024 * 1024 );
                        if (task_info( mach_task_self(), TASK_VM_INFO,
                                       (task_info_t)&vmi, &vcnt ) == KERN_SUCCESS)
                            dprintf(STDERR_FILENO,
                                    "[malloc-trap] phys_footprint=%llu MB limit_remaining=%lld MB "
                                    "compressed=%llu MB 1MB-vm_allocate=%s -- %s rev=ml573\n",
                                    (unsigned long long)(vmi.phys_footprint >> 20),
                                    (long long)((long long)vmi.limit_bytes_remaining >> 20),
                                    (unsigned long long)(vmi.compressed >> 20),
                                    ak == KERN_SUCCESS ? "OK" : "FAILED",
                                    ak != KERN_SUCCESS
                                      ? "<== allocation FAILED here too — consistent with exhaustion"
                                      : "<== allocation SUCCEEDS here, so this trap is not simple "
                                        "exhaustion (the libmalloc branch below is the actual proof)");
                        else
                            dprintf(STDERR_FILENO,
                                    "[malloc-trap] task_info(TASK_VM_INFO) FAILED; "
                                    "1MB-vm_allocate=%s rev=ml565\n",
                                    ak == KERN_SUCCESS ? "OK" : "FAILED");

                        /* ml567: WHAT did malloc choke on, and what is written there?
                         *
                         * ml565/566 proved this is real corruption, not OOM. Across 13
                         * runs it separates perfectly by FOOTPRINT (traps 3197-3339 MB,
                         * never 3015-3114 MB) while duration does not predict it at all
                         * (23 cycles traps at 3268 MB; 24 cycles is clean at 3114 MB).
                         * Not-exhaustion + footprint-predicts fits a WILD WRITE TO A
                         * ROUGHLY FIXED ADDRESS: harmless while the malloc zone is small
                         * enough not to cover it, fatal once the zone grows past it.
                         *
                         * libsystem_malloc traps with the offending block in hand, so its
                         * registers carry that pointer. Dump them, and hexdump around any
                         * that look like heap pointers. This project already has a known
                         * corrupter that writes ASCII where it does not own (#78/#88/#89;
                         * ml491 identified the payload as our own SwiftUI logStore text).
                         * If that text shows up here, the two are the same bug — and if
                         * the bytes are poison or guest data instead, that says so too. */
                        {
                            int r;
                            char line[160];
                            int n = snprintf( line, sizeof(line), "[malloc-trap] regs:" );
                            for (r = 0; r <= 8 && n < (int)sizeof(line) - 24; r++)
                                n += snprintf( line + n, sizeof(line) - n, " x%d=0x%llx",
                                               r, (unsigned long long)bs.__x[r] );
                            dprintf(STDERR_FILENO, "%s rev=ml567\n", line);

                            /* ml573 (Sol's plan): the allocator's own view of the damage.
                             *
                             * At this trap libmalloc has the offending block in hand. The
                             * literal it is about to print is "BUG IN CLIENT OF LIBMALLOC:
                             * memory corruption of free block" — that branch, not our
                             * vm_allocate probe, is what proves corruption. Decode what it
                             * saw:
                             *   x19 = object_ops*      (alloc_object's argument)
                             *   x20 = requested size   (mem_alloc's argument)
                             *   x0  = zone, x1 = xzone, x4 = bad block
                             * A freed block's first word is the freelist pointer XORed with
                             * a per-zone cookie, so `cookie ^ block` is what SHOULD be there.
                             *   actual0 != expected0            -> first word overwritten
                             *   actual0 == expected0, integrity -> second/PAC word overwritten
                             * ml572 showed two bad blocks sharing the high half 59 4f d0 5e
                             * with differing low bytes — exactly a cookie signature — so this
                             * should decode cleanly. */
                            {
                                uint64_t zone = bs.__x[0], xzone = bs.__x[1], bad = bs.__x[4];
                                uint64_t cookie = 0, class_size = 0, a0 = 0, a1 = 0;
                                unsigned char integrity = 0;
                                mach_vm_size_t g = 0;
                                int have_cookie, have_a0;

                                dprintf(STDERR_FILENO,
                                        "[malloc-trap] x19(ops)=0x%llx x20(req_size)=%llu "
                                        "fp=0x%llx sp=0x%llx lr=0x%llx rev=ml573\n",
                                        (unsigned long long)bs.__x[19], (unsigned long long)bs.__x[20],
                                        (unsigned long long)arm_thread_state64_get_fp( bs ),
                                        (unsigned long long)arm_thread_state64_get_sp( bs ),
                                        (unsigned long long)arm_thread_state64_get_lr( bs ));

#define IOS_RD64(addr, out) (mach_vm_read_overwrite( mach_task_self(), \
            (mach_vm_address_t)(addr), 8, (mach_vm_address_t)(uintptr_t)&(out), &g ) \
            == KERN_SUCCESS && g == 8)
                                have_cookie = IOS_RD64( zone + 0x150, cookie );
                                (void)IOS_RD64( xzone + 0x30, class_size );
                                have_a0 = IOS_RD64( bad, a0 );
                                (void)IOS_RD64( bad + 8, a1 );
                                (void)mach_vm_read_overwrite( mach_task_self(),
                                        (mach_vm_address_t)(zone + 0x10b), 1,
                                        (mach_vm_address_t)(uintptr_t)&integrity, &g );
                                if (have_cookie && have_a0)
                                {
                                    uint64_t expected0 = cookie ^ bad;
                                    dprintf(STDERR_FILENO,
                                            "[malloc-trap] zone=0x%llx xzone=0x%llx bad_block=0x%llx "
                                            "class_size=%llu integrity=0x%02x\n"
                                            "[malloc-trap]   cookie=0x%llx expected0=0x%llx "
                                            "actual0=0x%llx actual1=0x%llx -- %s rev=ml573\n",
                                            (unsigned long long)zone, (unsigned long long)xzone,
                                            (unsigned long long)bad, (unsigned long long)class_size,
                                            integrity, (unsigned long long)cookie,
                                            (unsigned long long)expected0, (unsigned long long)a0,
                                            (unsigned long long)a1,
                                            a0 != expected0
                                              ? "<== FIRST freelist word overwritten after free"
                                              : (integrity
                                                   ? "<== first word intact; SECOND/PAC word is the "
                                                     "damaged one"
                                                   : "<== first word matches the cookie — the damage "
                                                     "is elsewhere in the block"));
                                }
                                else
                                    dprintf(STDERR_FILENO,
                                            "[malloc-trap] could not read zone/block fields "
                                            "(zone=0x%llx bad=0x%llx) rev=ml573\n",
                                            (unsigned long long)zone, (unsigned long long)bad);

                                /* Whole freed block, raw. Stale pointer-like fields can name
                                 * its previous owner; a body of 0xaa would implicate a Wine
                                 * DEBUG_OBJECTS object. 32 bytes was too little. */
                                if (bad && class_size && class_size <= 0x400)
                                {
                                    unsigned char blk[0x400];
                                    mach_vm_size_t bg = 0;
                                    if (mach_vm_read_overwrite( mach_task_self(),
                                            (mach_vm_address_t)bad, class_size,
                                            (mach_vm_address_t)(uintptr_t)blk, &bg ) == KERN_SUCCESS)
                                    {
                                        unsigned o;
                                        for (o = 0; o < bg; o += 32)
                                        {
                                            char hx[3 * 32 + 1]; unsigned k, lim = (bg - o) < 32 ? (unsigned)(bg - o) : 32;
                                            for (k = 0; k < lim; k++) snprintf( hx + k * 3, 4, "%02x ", blk[o + k] );
                                            hx[lim * 3] = 0;
                                            dprintf(STDERR_FILENO, "[malloc-trap]   blk+%03x: %s rev=ml573\n", o, hx);
                                        }
                                    }
                                }

                                /* Frame-pointer chain, raw PCs only. Deliberately NOT
                                 * backtrace()/malloc_size()/Swift logging — all of those are
                                 * allocator-backed and libmalloc is mid-trap. */
                                {
                                    uint64_t fp = arm_thread_state64_get_fp( bs );
                                    char fr[320]; int fn = snprintf( fr, sizeof(fr), "[malloc-trap] fpchain:" );
                                    int d;
                                    for (d = 0; d < 12 && fp && !(fp & 15) && fn < (int)sizeof(fr) - 20; d++)
                                    {
                                        uint64_t nextfp = 0, pc = 0;
                                        if (!IOS_RD64( fp, nextfp ) || !IOS_RD64( fp + 8, pc )) break;
                                        fn += snprintf( fr + fn, sizeof(fr) - fn, " 0x%llx", (unsigned long long)pc );
                                        if (nextfp <= fp) break;
                                        fp = nextfp;
                                    }
                                    dprintf(STDERR_FILENO, "%s rev=ml573\n", fr);
                                }
#undef IOS_RD64
                            }

                            for (r = 0; r <= 8; r++)
                            {
                                uint64_t v = bs.__x[r];
                                unsigned char buf[32];
                                mach_vm_size_t got = 0;
                                int i, printable = 0;
                                char hex[3 * sizeof(buf) + 1], asc[sizeof(buf) + 1];
                                /* only plausible host-heap pointers, 16-byte aligned */
                                if (v < 0x100000000ull || v >= 0x740000000000ull || (v & 15)) continue;
                                if (mach_vm_read_overwrite( mach_task_self(),
                                        (mach_vm_address_t)(v & ~15ull), sizeof(buf),
                                        (mach_vm_address_t)(uintptr_t)buf, &got ) != KERN_SUCCESS
                                    || got != sizeof(buf))
                                    continue;
                                for (i = 0; i < (int)sizeof(buf); i++)
                                {
                                    snprintf( hex + i * 3, 4, "%02x ", buf[i] );
                                    asc[i] = (buf[i] >= 0x20 && buf[i] < 0x7f) ? buf[i] : '.';
                                    if (asc[i] != '.') printable++;
                                }
                                asc[sizeof(buf)] = 0;
                                dprintf(STDERR_FILENO,
                                        "[malloc-trap]   x%d=0x%llx: %s |%s|%s rev=ml567\n",
                                        r, (unsigned long long)v, hex, asc,
                                        printable >= 24 ? "  <== ASCII TEXT — matches the "
                                                          "#78/#88/#89 wild-write payload" : "");
                            }
                        }
                    }
                }

                /* ml554: an "other" BRK is a GUEST int3 — and on this port that has
                 * turned out to be PartitionAlloc's BackupRefPtr `refcount` CHECK
                 * deliberately aborting (chrome_elf+0xD7D6E; the helper at +0xD7D30
                 * sets Crashpad annotation "refcount" then crashes at line 452).
                 *
                 * The CHECK names the VICTIM, never the writer -- but it is handed the
                 * OFFENDING VALUE in edx, and the helper's first act is
                 * `movl %edx,%r8d`, so r8 still holds it at the int3. That value is the
                 * fingerprint: ASCII means the #78/#88 text-corrupter family, a poison
                 * pattern (0xEF/0xAB) means freed-memory reuse, a pointer-looking value
                 * means something else entirely.
                 *
                 * Dump the guest register file plus an ASCII decode of r8 and of the
                 * whole set. Cheap: only for non-FEX, non-StikDebug breakpoints, which
                 * are rare by construction. */
                if (binsn != 0xd4395fc0 && binsn != 0xd43e01a0)
                {
                    uint64_t x28v = bs.__x[28], grip = 0, gregs[16];
                    mach_vm_size_t got = 0;
                    int gi, ok = 0;
                    if (x28v &&
                        mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(x28v + 0x18),
                                                sizeof(grip), (mach_vm_address_t)&grip, &got ) == KERN_SUCCESS
                        && got == sizeof(grip) &&
                        /* ml578: gregs live at x28+0x20, NOT x28+0. Our own ml272
                         * note in this file already had it right ("rip=0x18
                         * gregs=0x20 gregs[RSP]=0x40") — reading from +0 grabbed
                         * the frame header and only part of the array, so every
                         * [int3-guest] register we have read was garbage. */
                        mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(x28v + 0x20),
                                                sizeof(gregs), (mach_vm_address_t)gregs, &got ) == KERN_SUCCESS
                        && got == sizeof(gregs))
                        ok = 1;

                    dprintf(STDERR_FILENO,
                            "[int3-guest] guest_rip=0x%llx x28=0x%llx read=%d rev=ml554\n",
                            (unsigned long long)grip, (unsigned long long)x28v, ok);
                    if (ok)
                    {
                        /* ml578: the GUEST register file — 16 entries, FEX order.
                         * Printed separately and explicitly labelled; the host ARM
                         * dump below is a different thing and was previously being
                         * mislabelled as guest state. Naively swapping bs.__x for
                         * gregs would also have run off the end: 31 vs 16. */
                        static const char *gn[16] = { "RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI",
                                                      "R8","R9","R10","R11","R12","R13","R14","R15" };
                        for (gi = 0; gi < 16; gi += 4)
                            dprintf(STDERR_FILENO,
                                    "[int3-guest]   GUEST %s=0x%016llx %s=0x%016llx "
                                    "%s=0x%016llx %s=0x%016llx rev=ml578\n",
                                    gn[gi],     (unsigned long long)gregs[gi],
                                    gn[gi + 1], (unsigned long long)gregs[gi + 1],
                                    gn[gi + 2], (unsigned long long)gregs[gi + 2],
                                    gn[gi + 3], (unsigned long long)gregs[gi + 3]);
                        /* Host x0..x30 too: FEX's SRA mapping is not assumed anywhere
                         * here, so print both and identify the value offline. */
                        for (gi = 0; gi < 31; gi += 4)
                            dprintf(STDERR_FILENO,
                                    "[int3-guest]   HOST x%-2d=0x%016llx x%-2d=0x%016llx "
                                    "x%-2d=0x%016llx x%-2d=0x%016llx\n",
                                    gi, (unsigned long long)bs.__x[gi],
                                    gi + 1, (unsigned long long)(gi + 1 < 31 ? bs.__x[gi + 1] : 0),
                                    gi + 2, (unsigned long long)(gi + 2 < 31 ? bs.__x[gi + 2] : 0),
                                    gi + 3, (unsigned long long)(gi + 3 < 31 ? bs.__x[gi + 3] : 0));
                        for (gi = 0; gi < 31; gi++)
                        {
                            unsigned long long v = bs.__x[gi];
                            char a[9]; int k;
                            for (k = 0; k < 8; k++)
                            { unsigned char c = (unsigned char)(v >> (8 * k)); a[k] = (c >= 32 && c < 127) ? c : '.'; }
                            a[8] = 0;
                            if (a[0] != '.' && a[1] != '.' && a[2] != '.')
                                dprintf(STDERR_FILENO,
                                        "[int3-guest]   ASCII x%d = \"%s\"  <== text in a register\n", gi, a);
                        }

                        /* iOS-Madeira ml616 [brp-contain]: WHICH PartitionAlloc callsite
                         * asserted, and on WHAT value.
                         *
                         * Chromium's BackupRefPtr refcount assertion is `int3; int3; ud2`
                         * preceded by a "refcount" diagnostic. It has killed ml602, ml603,
                         * ml607 and ml615 with a byte-identical signature: after the int3,
                         * Chrome's OWN handler runs with State.rip = 0xEFEFEFEFEFEFEFEF
                         * (freed poison), producing the read fault at 0x1e051d9c8dfd8.
                         *
                         * The registers here cannot name the offender: the assertion
                         * routine makes two calls before executing int3, so guest/host R8
                         * is already clobbered. The values survive on the STACK:
                         *   [guest RSP+0x38] = the offending refcount value
                         *   [guest RSP+0x48] = the direct caller's return address
                         * Five PartitionAlloc callsites can reach this; the return address
                         * is what distinguishes them.
                         *
                         * Self-identifying match, no module base needed: the guest bytes at
                         * rip-1 are the literal `CC CC 0F 0B` fatal pattern. That is why
                         * this cannot fire on an ordinary debugger breakpoint.
                         *
                         * ⚠️ Probe only — this does NOT contain the crash. Containment is
                         * deliberately NOT in this build: it must terminate the whole
                         * steamwebhelper pseudo-process, release FEX holds, and be proven
                         * to respawn and reach BrowserReady, or it merely renames the
                         * failure (webhelper owns the entire single-process CEF UI).
                         *
                         * ⛔ Do not try to suppress this with --disable-features: we already
                         * pass PartitionAllocBackupRefPtr and the assertion still runs. */
                        {
                            unsigned char pat[4] = {0, 0, 0, 0};
                            unsigned long long guest_rsp = gregs[4];   /* RAX,RCX,RDX,RBX,RSP,... */
                            mach_vm_size_t pg = 0;
                            int pat_ok = (grip > 1) &&
                                mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(grip - 1),
                                                        sizeof(pat), (mach_vm_address_t)pat, &pg ) == KERN_SUCCESS;
                            if (pat_ok && pat[0] == 0xCC && pat[1] == 0xCC && pat[2] == 0x0F && pat[3] == 0x0B)
                            {
                                unsigned long long offender = 0, caller = 0;
                                int o_ok, c_ok;
                                o_ok = mach_vm_read_overwrite( mach_task_self(),
                                          (mach_vm_address_t)(guest_rsp + 0x38), sizeof(offender),
                                          (mach_vm_address_t)&offender, &pg ) == KERN_SUCCESS;
                                c_ok = mach_vm_read_overwrite( mach_task_self(),
                                          (mach_vm_address_t)(guest_rsp + 0x48), sizeof(caller),
                                          (mach_vm_address_t)&caller, &pg ) == KERN_SUCCESS;
                                dprintf(STDERR_FILENO,
                                        "[brp-contain] ml616 BackupRefPtr refcount assertion: int3 at guest 0x%llx "
                                        "rsp=0x%llx offender=%s0x%llx caller=%s0x%llx pid=%04x tid=%04x "
                                        "-- caller names WHICH of the 5 PA callsites; NOT contained in this build\n",
                                        (unsigned long long)(grip - 1), guest_rsp,
                                        o_ok ? "" : "<unreadable>", offender,
                                        c_ok ? "" : "<unreadable>", caller,
                                        NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess : 0,
                                        NtCurrentTeb() ? (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0);
                            }
                        }
                    }
                }
            }
        }

        /* Look up per-thread TEB and trampoline for the faulting thread */
        uintptr_t thread_teb = 0;
        void *thread_trampoline = NULL;
        ios_lookup_thread( thread, &thread_teb, &thread_trampoline );

        /* Get faulting thread's register state */
        arm_thread_state64_t state;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        kr = thread_get_state( thread, ARM_THREAD_STATE64,
                               (thread_state_t)&state, &count );
        /* Also fetch NEON (SIMD/FP) state for STR/STP-q emulation */
        arm_neon_state64_t neon_state;
        mach_msg_type_number_t neon_count = ARM_NEON_STATE64_COUNT;
        int have_neon = (thread_get_state(thread, ARM_NEON_STATE64,
                                          (thread_state_t)&neon_state, &neon_count) == KERN_SUCCESS);
        if (kr == KERN_SUCCESS)
        {
            uintptr_t fault_addr = (uintptr_t)req->code[1];
#ifdef WINE_IOS
            /* ml939: THE SUB-FLOOR SERVICE BELONGS HERE, NOT IN segv_handler.
             *
             * ml938 put it in segv_handler and the emulation itself was correct --
             * both accesses were serviced and the guest ran on past them -- but
             * every resume corrupted FEX: "[CALLRET_OOB] UNDERFLOW callret_sp="
             * reporting exactly <pc+4>, then a rip-leak (guest RIP holding a pool
             * address), then c000001d.
             *
             * Cause: iOS sigreturn always zeroes x18, so a signal that resumes at a
             * JIT-pool PC must go through ios_fixup_x18_for_return(), which diverts
             * to the per-thread trampoline and carries the resume address in x17
             * (`ldr x18,[pc,#-8]; br x17`). It never restores x17 -- and x17 is
             * FEX's callret stack pointer. The SIGNAL path therefore CANNOT resume
             * into JIT code without destroying FEX state, for any fault, not just
             * ours. That is precisely why this handler already carries its own
             * unaligned-atomic emulator instead of leaving it to ios_emulate_store:
             * thread_set_state restores x18 directly, so there is no trampoline and
             * no x17 clobber. The same reasoning puts us here.
             *
             * ml953: MOVED TO THE FRONT OF THE EXC_BAD_ACCESS PATH.
             *
             * It used to sit after every other path had declined, which sounded
             * conservative and was wrong. Measured: once the guest started
             * reading KUSER_SHARED_DATA at 0x7ffe02e8 -- a registered window,
             * LDAPR, an encoding the emulator covers -- the serviced counter
             * froze at 598,017 and the app took 1.3M identical exceptions at one
             * pc. No UNHANDLED line either, so this code was never reached: an
             * earlier handler claimed the fault, resumed without fixing
             * anything, and looped. Its own diagnostics are capped, so after the
             * cap it did that silently.
             *
             * Going first is safe BY CONSTRUCTION, which is the same argument
             * the segv-side gate uses: the address is below iOS's 4GB floor, so
             * nothing in this task -- Wine view, FEX arena, JIT pool, W^X alias
             * or foreign mmap -- can be mapped there, and no other handler can
             * legitimately own it. An address outside every registered window
             * falls through untouched, so non-sub-floor faults keep their exact
             * current ordering. */
            if (!handled && req->exception == EXC_BAD_ACCESS)
            {
                /* ml1205: the faulting thread's own process decides the window */
                void *sf_peb = thread_teb ? ((TEB *)thread_teb)->Peb : NULL;
                uintptr_t sf_real = ios_subfloor_translate( (uint64_t)fault_addr, sf_peb );
                /* ml970: the gate has to admit low ALIASES too, not just image
                 * windows. ml969 registered the alias correctly (rdr34: 12
                 * registered, 0 refused, 2 retired) and the fault address
                 * 0x6aae0010 was inside alias 0x6aae0000 -- but the registry
                 * lookup lives inside ios_subfloor_service, and this gate
                 * skipped the whole block because the IMAGE translate returned
                 * 0. So the alias was never consulted: `serviced` and `REFUSED`
                 * were both zero while the guest still faulted.
                 *
                 * A 1-byte probe is enough to decide ENTRY; the authoritative
                 * whole-span bounds check stays inside the service function, so
                 * an access that starts inside an allocation but runs off its
                 * end is still refused there rather than resolved. */
                int sf_low = 0;
                /* literal because IOS_SUBFLOOR_FLOOR is defined further down
                 * this file; same value (0x100000000). */
                if (!sf_real && (uint64_t)fault_addr < 0x100000000ull)
                {
                    extern int ios_lowalloc_translate( unsigned long long addr,
                                                       unsigned long long len,
                                                       unsigned long long *real_out,
                                                       void **owner_out );
                    sf_low = ios_lowalloc_translate( (uint64_t)fault_addr, 1, NULL, NULL );
                }

                if (sf_real || sf_low)
                {
                    /* The emulators take a ucontext. arm_thread_state64_t IS the
                     * struct a ucontext's mcontext embeds as __ss, and
                     * arm_neon_state64_t is __ns, so a stack mcontext aliases the
                     * Mach state field-for-field -- no accessor refactor needed, and
                     * copying __ss back is what the thread_set_state below ships.
                     * __typeof__ rather than naming _STRUCT_MCONTEXT so this cannot
                     * drift from whatever ucontext_t actually holds. */
                    __typeof__( *(((ucontext_t *)0)->uc_mcontext) ) sf_mc;
                    ucontext_t sf_uc;

                    memset( &sf_mc, 0, sizeof(sf_mc) );
                    memset( &sf_uc, 0, sizeof(sf_uc) );
                    sf_mc.__ss = state;
                    if (have_neon) sf_mc.__ns = neon_state;
                    sf_uc.uc_mcontext = &sf_mc;
                    /* ml974: tell the emulators whether __ns is real. */
                    ios_neon_valid = have_neon;
                    if (!have_neon)
                    {
                        static int nn;
                        if (nn++ < 8)
                            dprintf( 2, "[neon] ml974 ARM_NEON_STATE64 unavailable for this fault "
                                     "(addr=%#llx) -- SIMD emulation will DECLINE rather than "
                                     "read/write a zeroed vector block\n",
                                     (unsigned long long)fault_addr );
                    }

                    if (ios_subfloor_service( &sf_uc, (void *)fault_addr, "mach", sf_peb ))
                    {
                        uint64_t sf_pc;

                        state = sf_mc.__ss;
                        sf_pc = (uint64_t)__darwin_arm_thread_state64_get_pc( state );
                        __darwin_arm_thread_state64_set_pc_fptr( state,
                                                                 (void *)(uintptr_t)(sf_pc + 4) );
                        if (have_neon)
                        {
                            neon_state = sf_mc.__ns;
                            thread_set_state( thread, ARM_NEON_STATE64,
                                              (thread_state_t)&neon_state, neon_count );
                        }
                        handled = 1;
                    }
                }
            }
#endif

            /* ml555: snapshot the protection AT HANDLER ENTRY, and keep the kernel's
             * own verdict from code[0].
             *
             * ml554 reported the fatal clear-routine fault as landing on an address that
             * was MAPPED and READ|WRITE -- which would mean a store to a perfectly
             * writable page faulted. But that reading is unsafe: the region query in
             * [fault_rip] happens ~1500 lines later, AFTER srcwatch and the page
             * machinery have run and possibly re-protected the page. So the "hostprot=3"
             * may simply be the state after we healed it, not the state that faulted.
             *
             * Capture it here, before anything can touch it, and report BOTH. If entry
             * and log-time disagree, something healed the page mid-handler and the fault
             * is a RACE; if they agree at RW, the store really did fault on writable
             * memory and it is something else entirely.
             *
             * code[0] is the kernel's classification: KERN_INVALID_ADDRESS(1) = nothing
             * mapped, KERN_PROTECTION_FAILURE(2) = mapped but access denied. That alone
             * separates "wild pointer" from "protection" without any inference. */
            int entry_prot = -1;
            unsigned long long entry_rbase = 0, entry_rsize = 0;
            const unsigned long long fault_kr = (unsigned long long)req->code[0];
            {
                mach_vm_address_t ea = (mach_vm_address_t)fault_addr;
                mach_vm_size_t es = 0;
                vm_region_basic_info_data_64_t ebi;
                mach_msg_type_number_t ec2 = VM_REGION_BASIC_INFO_COUNT_64;
                mach_port_t eo = MACH_PORT_NULL;
                if (fault_addr &&
                    mach_vm_region( mach_task_self(), &ea, &es, VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&ebi, &ec2, &eo ) == KERN_SUCCESS)
                { entry_prot = ebi.protection; entry_rbase = (unsigned long long)ea;
                  entry_rsize = (unsigned long long)es; }
            }

            /* 0. ml515: source-bitmap watch. MUST run before every other
             * classification — these are deliberate protection faults we
             * armed ourselves, and any later stage would mistake them for a
             * guest AV (which is exactly what killed ml514's runs). On a hit
             * we log the writer, unprotect that one page, and resume the
             * thread with its state untouched. */
            int srcwatch_hit = ios_srcwatch_handle( &state, fault_addr );
            if (srcwatch_hit) handled = 1;

            /* 1. Redirect user_shared_data accesses (0x7FFE0000)
             *
             * madeira-bcd: only when the sub-floor service above did NOT already
             * emulate the access. It runs first (ml953) and handles KUSER, after
             * which this scan used to run anyway on the resumed state and rebase
             * every register holding a 0x7FFE**** value -- including registers
             * that were only data. A protected game (The Adventures of Elliot)
             * keeps the constant 0x7ffe0283 in rcx while it reads KUSER through
             * another register; rcx came back as the real address and the
             * pointer it computed was off by exactly ios_exc_usd - 0x7FFE0000. */
            if (!handled && !srcwatch_hit && fault_addr >= 0x7FFE0000 && fault_addr < 0x7FFF0000 && ios_exc_usd)
            {
                for (int reg = 0; reg <= 28; reg++)
                {
                    if (state.__x[reg] >= 0x7FFE0000 && state.__x[reg] < 0x7FFF0000)
                        state.__x[reg] = ios_exc_usd + (state.__x[reg] - 0x7FFE0000);
                }
                ios_exc_usd_fixes++;
                handled = 1;
            }

            /* 2. Redirect execution faults at original PE mappings to JIT pool.
             * The PE-side loader calls DLL entry points at original mapping
             * addresses which aren't executable on iOS. Translate to JIT. */
            if (!srcwatch_hit)
            {
                extern void *ios_jit_rx_base_global;
                extern size_t ios_jit_pool_size_global;
                extern int ios_jit_addr_is_text(uintptr_t addr);
                extern void *ios_jit_translate_addr_for_owner(void *addr, void *owner_peb);

                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);
                int is_exec_fault = (fault_addr == (uintptr_t)fault_pc);

                /* ml454 (#74): the trampoline requirement gated the WHOLE
                 * redirect block, but only the in-pool x18-fix branch uses
                 * it — the outside-pool image→pool translate applies a plain
                 * PC rewrite (+ x18 via state) and needs no trampoline.  A
                 * thread with no registered trampoline (the ml452 renderer)
                 * lost ALL redirects and its image-VA exec fault stormed
                 * 65k× through guest SEH, re-entering the emission locks. */
                if (is_exec_fault)
                {
                    uintptr_t jit_rx = (uintptr_t)ios_jit_rx_base_global;
                    size_t jit_sz = ios_jit_pool_size_global;

                    /* madeira-bcd pool-low: region C is pool code too (nothing there
                     * is an image, so this branch does nothing for it -- as for the
                     * tail -- instead of trying an image translation) */
                    if ((fault_pc >= jit_rx && fault_pc < jit_rx + jit_sz) ||
                        ios_jit_low_contains( (uintptr_t)fault_pc ))
                    {
                        /* Exec fault IN JIT pool — only fixable if in .text (x18 issue) */
                        if (ios_jit_addr_is_text(fault_pc) && state.__x[18] == 0 && thread_teb && thread_trampoline)
                        {
                            state.__x[17] = fault_pc;
                            __darwin_arm_thread_state64_set_pc_fptr(state, thread_trampoline);
                            ios_exc_x18_fixes++;
                            handled = 1;
                        }
                    }
                    else
                    {
                        /* Exec fault OUTSIDE JIT pool RX — try translations.
                         * IMPORTANT: this handler runs on its own thread, so
                         * translation must use the FAULTING thread's process
                         * (its registered TEB->Peb), not ours — a child
                         * thread's ntdll fault must redirect to the child's
                         * copy (S1 pseudo-processes). */
                        void *jit_pc;
                        void *fault_owner_peb = thread_teb ? ((TEB *)thread_teb)->Peb : NULL;
                        ios_last_exec_fault_thread = thread;

                        /* ml691 W^X RE-PROMOTE. If a page we demoted to RW is
                         * ever executed, restore RX here -- synchronously, before
                         * the faulting thread resumes. This is the recovery hook
                         * a NOEXEC fault could not otherwise provide, because FEX
                         * normally executes its own translated host code and never
                         * touches the guest page. Reaching this path at all means
                         * the "data page" assumption was wrong for that page, so
                         * it is put back and never demoted again. */
                        {
                            extern int ios_wx_repromote( unsigned long long );
                            if (ios_wx_repromote( (unsigned long long)fault_pc ))
                            {
                                /* RX restored: mark handled and skip the
                                 * translate/heal path below. Resuming re-runs the
                                 * faulting instruction against the restored page. */
                                handled = 1;
                            }
                        }
                        if (!handled)
                        {
                        }
                        jit_pc = ios_jit_translate_addr_for_owner((void *)(uintptr_t)fault_pc,
                                                                  fault_owner_peb);
                        /* Module-mapping hit = a stale PE-VA pointer somewhere
                         * in the pool — queue it for the heal scanner so this
                         * address only ever faults once. */
                        if (jit_pc != (void *)(uintptr_t)fault_pc)
                            ios_stale_va_enqueue((uint64_t)fault_pc);
                        /* [xlate-exec] pseudo-process forensics: every
                         * image-VA exec fault is an ownership decision —
                         * log which copy the thread was routed to. A child
                         * thread landing in a session-owned copy (owner=0
                         * while its teb->peb is a child peb) is the
                         * cross-copy migration that kills thread exit. */
                        {
                            extern void *ios_jit_pool_copy_owner(const void *addr, void **pe_base_out);
                            /* Child threads only — the session's own boot
                             * takes thousands of these and drowned the
                             * budget (2026-07-07 run: all 128 entries spent
                             * before services.exe even spawned). */
                            if (fault_owner_peb && peb && fault_owner_peb != (void *)peb)
                            {
                                static volatile int xe_count = 0;
                                int xe = __sync_add_and_fetch(&xe_count, 1);
                                if (xe <= 256 || (xe % 1024) == 0)
                                {
                                    void *copy_pe = NULL;
                                    void *copy_owner = ios_jit_pool_copy_owner(jit_pc, &copy_pe);
                                    dprintf(STDERR_FILENO,
                                        "[xlate-exec] #%d teb=%p owner=%p pc=%p -> %p (copy pe=%p copy_owner=%p)\n",
                                        xe, (void *)thread_teb, fault_owner_peb,
                                        (void *)(uintptr_t)fault_pc, jit_pc, copy_pe, copy_owner);
                                }
                            }
                        }
                        if (jit_pc == (void *)(uintptr_t)fault_pc)
                        {
                            /* iOS-Madeira: if PC is in JIT pool RW alias range,
                             * redirect to RX alias (= PC - pool_size). FEX's
                             * emitted code lives at RX alias addresses, but
                             * sometimes a BR/BLR computes the RW alias via
                             * emitter math when our redirect interacts with
                             * vm_remap. */
                            extern void *ios_jit_rw_base_global;
                            extern size_t ios_jit_pool_size_global;
                            uintptr_t rw_base = (uintptr_t)ios_jit_rw_base_global;
                            uintptr_t rx_base2 = (uintptr_t)ios_jit_rx_base_global;
                            if (rw_base && rx_base2 && ios_jit_pool_size_global &&
                                ((fault_pc >= rw_base &&
                                  fault_pc < rw_base + ios_jit_pool_size_global) ||
                                 ios_jit_low_rw_contains( (uintptr_t)fault_pc )))   /* madeira-bcd pool-low */
                            {
                                uintptr_t rx_pc = (uintptr_t)fault_pc - rw_base + rx_base2;
                                jit_pc = (void *)rx_pc;
                            }
                        }
                        if (jit_pc == (void *)(uintptr_t)fault_pc)
                        {
                            /* Not a known PE-image translation. Try the anon-alias
                             * table (FEX CodeBuffer / runtime JIT regions vm_remap'd
                             * from the JIT pool) — those have a separate RX alias
                             * that's actually executable. */
                            extern uintptr_t ios_jit_anon_alias_lookup_rx(uintptr_t);
                            uintptr_t rx_pc = ios_jit_anon_alias_lookup_rx((uintptr_t)fault_pc);
                            if (rx_pc) jit_pc = (void *)rx_pc;
                        }
                        if (jit_pc != (void *)(uintptr_t)fault_pc)
                        {
                            /* Plain pc redirect — even with x18==0. The old
                             * x18-restore trampoline clobbered x17, which is
                             * LIVE in FEX-emitted code (callret scratch) and
                             * in ARM64EC thunks. If the redirect target's
                             * code needs the TEB, its [x18,#imm] access
                             * faults and case 3 emulates it clobber-free. */
                            if (thread_teb && state.__x[18] == 0)
                            {
                                static volatile int redir2_count = 0;
                                int t2 = __sync_add_and_fetch(&redir2_count, 1);
                                if (t2 <= 10 || (t2 % 4096) == 0)
                                    dprintf(STDERR_FILENO,
                                        "[x18-redir2] #%d pc=%p -> jit=%p (x18 set via state)\n",
                                        t2, (void*)(uintptr_t)fault_pc, jit_pc);
                                /* Same set_state x18 experiment as case 3. */
                                state.__x[18] = thread_teb;
                            }
                            /* ml1059: WHICH addresses get executed through their non-executable
                             * backing. Each is a whole Mach exception per CALL (a pointer from
                             * GetProcAddress, a vtable, a callback). One such pointer inside FEX's
                             * block lookup was costing the exception thread half a core; count the
                             * rest so they can be fixed at the source rather than discovered one
                             * profile at a time. Single writer (this handler thread). */
                            {
                                static struct { uintptr_t pc; uintptr_t lr; unsigned long n; } top[64];
                                static unsigned long total;
                                int h, slot = -1;
                                for (h = 0; h < 64; h++)
                                {
                                    if (top[h].pc == (uintptr_t)fault_pc) { top[h].n++; slot = h; break; }
                                    if (!top[h].pc && slot < 0) slot = h;
                                }
                                /* ml1106: the CALLER too (lr at the fault = who jumped here), so a hot
                                 * target can be traced to the thunk or table that holds its address. */
                                if (h == 64 && slot >= 0) { top[slot].pc = (uintptr_t)fault_pc; top[slot].lr = (uintptr_t)__darwin_arm_thread_state64_get_lr(state); top[slot].n = 1; }
                                if (!(++total % 100000))
                                {
                                    char line[900]; int n = 0, k;
                                    for (k = 0; k < 8; k++)
                                    {
                                        int best = -1;
                                        for (h = 0; h < 64; h++) if (top[h].n && (best < 0 || top[h].n > top[best].n)) best = h;
                                        if (best < 0 || top[best].n < 50) break;
                                        n += snprintf( line + n, sizeof(line) - n, " %p(lr %p)=%lu", (void *)top[best].pc, (void *)top[best].lr, top[best].n );
                                        top[best].n = 0; top[best].pc = 0; top[best].lr = 0;
                                    }
                                    dprintf( STDERR_FILENO, "[exec-redir] ml1059 %lu executions through non-executable backing so far; "
                                             "hottest in the last 100000:%s\n", total, n ? line : " (none above 50)" );
                                    memset( top, 0, sizeof(top) );
                                }
                            }
                            /* madeira-bcd: an EC import stub that reached this
                             * PE address through check_icall gets the copy
                             * address in its AuxiliaryIAT slot, so its next
                             * call does not fault (virtual_ios.c aux-IAT heal) */
                            {
                                extern int ios_jit_heal_aux_iat( uintptr_t fault_pc, uintptr_t lr,
                                                                 void *thread_peb, uintptr_t jit_pc );
                                ios_jit_heal_aux_iat( (uintptr_t)fault_pc,
                                                      (uintptr_t)__darwin_arm_thread_state64_get_lr(state),
                                                      fault_owner_peb, (uintptr_t)jit_pc );
                            }
                            __darwin_arm_thread_state64_set_pc_fptr(state, jit_pc);
                            ios_exc_x18_fixes++;
                            handled = 1;
                        }
                    }
                }
            }

            /* 3. Emulate [x18, #imm] accesses when x18 == 0.
             * iOS zeros x18 on context switch. EC/FEX code reads the TEB
             * through x18; with x18==0 the effective address IS the TEB
             * offset, so we can complete the access in-handler against the
             * real TEB (teb + fault_addr) and advance pc. Rn==18 in the
             * faulting instruction is the exact discriminator — a fault
             * with any other base register is NOT x18-caused and falls
             * through to real fault handling.
             *
             * This REPLACES the old x18-restore trampoline for data faults.
             * The trampoline clobbered x17 (its jump register) — fatal when
             * the interrupted code held a live value there. Two confirmed
             * kills (2026-07-04, after UNIXCALL-DIRECT widened the x18==0
             * windows): (a) FEX emitter loop `str w16,[x15,x17]` re-executed
             * with x17=pc → garbage address → eternal UNHANDLED; (b) ntdll
             * EC TEB-read sites trampolined with live x17 (pool pointers,
             * FP constants observed) → silent state corruption → heap
             * damage → libsystem_malloc died inside Metal texture creation.
             * Emulation clobbers NOTHING. x18 stays 0 afterwards; each
             * subsequent TEB access costs one fault until the next context
             * switch restores nothing — acceptable, bounded, correct. */
            if (!handled && state.__x[18] == 0 && thread_teb)
            {
                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);
                int is_exec_fault = (fault_addr == (uintptr_t)fault_pc);

                if (!is_exec_fault && fault_addr < 0x10000 &&
                    fault_pc >= 0x100000000ULL)
                {
                    uint32_t insn; ios_fault_read_insn( (uint64_t)(uintptr_t)fault_pc, &insn );  /* ml982 */
                    int rn = (insn >> 5) & 0x1f;

                    /* ml157 PROBE (#36): the webhelper dies here. FEX emitted
                     * `movz w1,#0; ldr x1,[x1]` — the page-0 address was
                     * materialised into a SCRATCH register, so rn!=18 and the
                     * emulator above declines, making the fault fatal (5
                     * recursive repeats -> thread exit -> steam exit(1)).
                     *
                     * The open question is whether address 0 here is a TEB
                     * offset FEX spilled to a scratch reg, or a genuine guest
                     * NULL deref. Emulating the wrong one silently corrupts,
                     * so DO NOT widen the discriminator until this says which.
                     *
                     * Discriminators printed:
                     *  - the 16 insns before pc: an x18 SPILL (`mov xN,x18` /
                     *    `mrs`+TEB math) means TEB access; a guest-address
                     *    computation (adds/shifts from FEX guest regs) means a
                     *    real NULL deref.
                     *  - base reg VALUE vs fault_addr: equal => the register
                     *    literally held the small offset.
                     * Capped at 4 reports so a fault storm can't flood. */
                    /* A base register computed from x18 one instruction earlier */
                    int x18_derived = ios_x18_derived_base( fault_pc, rn );
                    if (x18_derived)
                    {
                        static int ios_x18_derived_reports;
                        if (ios_x18_derived_reports++ < 8)
                            ERR( "[x18-derived] #%d pc=%p insn=%08x base x%d from x18 -> "
                                 "TEB+0x%lx emulated\n", ios_x18_derived_reports, (void *)(uintptr_t)fault_pc,
                                 insn, rn, (unsigned long)fault_addr );
                    }

                    if (rn != 18 && !x18_derived)
                    {
                        static int ios_x18_decline_reports;
                        if (ios_x18_decline_reports < 4)
                        {
                            const uint32_t *w = (const uint32_t *)(uintptr_t)fault_pc;
                            char buf[512];
                            int n = 0, k;
                            /* __x[] is x0..x28 only; fp/lr/sp are separate
                             * members and rn==31 is xzr/sp. Never index past 28. */
                            uint64_t rn_val = (rn < 29) ? state.__x[rn] :
                                              (rn == 29) ? state.__fp :
                                              (rn == 30) ? state.__lr : state.__sp;
                            ios_x18_decline_reports++;
                            for (k = -16; k <= 4 && n < (int)sizeof(buf) - 16; k++)
                                n += snprintf( buf + n, sizeof(buf) - n, "%s%08x",
                                               k ? " " : " [", w[k] ) + (k ? 0 : 0);
                            snprintf( buf + n, sizeof(buf) - n, "]" );
                            ERR( "[x18-decline] #%d pc=%p fault_addr=0x%lx insn=%08x rn=%d "
                                 "xRn=0x%llx (rn_val==fault_addr? %d) x18=0 teb=%p\n",
                                 ios_x18_decline_reports, (void *)(uintptr_t)fault_pc,
                                 (unsigned long)fault_addr, insn, rn,
                                 (unsigned long long)rn_val,
                                 rn_val == fault_addr, (void *)thread_teb );
                            ERR( "[x18-decline] #%d insns pc-64..pc+16:%s\n",
                                 ios_x18_decline_reports, buf );
                        }
                    }

                    if (rn == 18 || x18_derived)
                    {
                        uintptr_t ea = thread_teb + fault_addr;
                        int rt = insn & 0x1f;
                        int emulated = 0;

                        switch (insn & 0xffc00000)
                        {
                        /* unsigned-offset immediate loads, base x18 */
                        case 0xf9400000: /* LDR Xt */
                            /* The x18 patcher's "via x18" trampoline (mrs x18 / and /
                             * ldr x18,[x18,#slot] / insn) preempted before its ldr: that
                             * ldr reads the TSD slot holding the TEB, so x18 gets the TEB
                             * itself, not the TEB field at the slot's offset. */
                            if (rt == 18 && rn == 18 && ios_teb_tls_slot_offset &&
                                fault_addr == (uintptr_t)ios_teb_tls_slot_offset)
                                state.__x[18] = thread_teb;
                            else if (rt != 31) state.__x[rt] = *(uint64_t *)ea;
                            emulated = 1; break;
                        case 0xb9400000: /* LDR Wt (zero-extend) */
                            if (rt != 31) state.__x[rt] = *(uint32_t *)ea;
                            emulated = 1; break;
                        case 0x39400000: /* LDRB Wt */
                            if (rt != 31) state.__x[rt] = *(uint8_t *)ea;
                            emulated = 1; break;
                        case 0x79400000: /* LDRH Wt */
                            if (rt != 31) state.__x[rt] = *(uint16_t *)ea;
                            emulated = 1; break;
                        /* unsigned-offset immediate stores, base x18 */
                        case 0xf9000000: /* STR Xt */
                            *(uint64_t *)ea = (rt == 31) ? 0 : state.__x[rt];
                            emulated = 1; break;
                        case 0xb9000000: /* STR Wt */
                            *(uint32_t *)ea = (rt == 31) ? 0 : (uint32_t)state.__x[rt];
                            emulated = 1; break;
                        case 0x39000000: /* STRB Wt */
                            *(uint8_t *)ea = (rt == 31) ? 0 : (uint8_t)state.__x[rt];
                            emulated = 1; break;
                        case 0x79000000: /* STRH Wt */
                            *(uint16_t *)ea = (rt == 31) ? 0 : (uint16_t)state.__x[rt];
                            emulated = 1; break;
                        default: break;
                        }

                        /* LDP/STP Xt,Xt2,[x18,#imm] signed-offset (no writeback) */
                        if (!emulated && (insn & 0xffc00000) == 0xa9400000)
                        {
                            int rt2 = (insn >> 10) & 0x1f;
                            if (rt != 31)  state.__x[rt]  = *(uint64_t *)ea;
                            if (rt2 != 31) state.__x[rt2] = *(uint64_t *)(ea + 8);
                            emulated = 1;
                        }
                        else if (!emulated && (insn & 0xffc00000) == 0xa9000000)
                        {
                            int rt2 = (insn >> 10) & 0x1f;
                            *(uint64_t *)ea       = (rt == 31)  ? 0 : state.__x[rt];
                            *(uint64_t *)(ea + 8) = (rt2 == 31) ? 0 : state.__x[rt2];
                            emulated = 1;
                        }

                        /* GPR register-offset (`ldrb w8,[x18,x8]` killed boot
                         * 2026-07-04 19:39) and unscaled-immediate (LDUR/STUR)
                         * families, any size, loads+stores+signed loads. The
                         * hardware already computed the offset into fault_addr,
                         * so only size/opc/Rt semantics matter here. */
                        if (!emulated &&
                            ((insn & 0x3f200c00) == 0x38200800 ||   /* register offset */
                             (insn & 0x3f200c00) == 0x38000000))    /* unscaled imm9 */
                        {
                            int size = (insn >> 30) & 3;   /* 0=B 1=H 2=W 3=X */
                            int opc  = (insn >> 22) & 3;   /* 0=ST 1=LD 2/3=LDS */
                            uint64_t val = 0;
                            emulated = 1;
                            if (opc == 0)               /* store */
                            {
                                val = (rt == 31) ? 0 : state.__x[rt];
                                switch (size)
                                {
                                case 0: *(uint8_t  *)ea = (uint8_t)val;  break;
                                case 1: *(uint16_t *)ea = (uint16_t)val; break;
                                case 2: *(uint32_t *)ea = (uint32_t)val; break;
                                case 3: *(uint64_t *)ea = val;           break;
                                }
                            }
                            else if (opc == 1)          /* zero-extending load */
                            {
                                switch (size)
                                {
                                case 0: val = *(uint8_t  *)ea; break;
                                case 1: val = *(uint16_t *)ea; break;
                                case 2: val = *(uint32_t *)ea; break;
                                case 3: val = *(uint64_t *)ea; break;
                                }
                                if (rt != 31) state.__x[rt] = val;
                            }
                            else if (size == 3 && opc == 2)
                            {
                                /* PRFM (register/unscaled) — prefetch, no-op */
                            }
                            else                        /* sign-extending load */
                            {
                                int64_t sval = 0;
                                switch (size)
                                {
                                case 0: sval = *(int8_t  *)ea; break;
                                case 1: sval = *(int16_t *)ea; break;
                                case 2: sval = *(int32_t *)ea; break; /* LDRSW */
                                }
                                if (opc == 3) /* 32-bit target: Wt, zero upper */
                                    sval = (int64_t)(uint32_t)(int32_t)sval;
                                if (rt != 31) state.__x[rt] = (uint64_t)sval;
                            }
                        }

                        /* SIMD/FP register-offset + unsigned-offset loads/
                         * stores, base x18 (V=1, bit 26). `LDR Q0,[x18,x8]`
                         * (insn 3ce86a40) crashed the crypt32 cert-verify
                         * SIMD memcpy 2026-07-05. ea = thread_teb+fault_addr
                         * (hw already added the offset). Access width from
                         * {size, opc<1>}: size0+opc<1> = 128-bit Q, else
                         * 1<<size bytes (B/H/S/D). opc<0> (bit22): 1=load,
                         * 0=store. Loads write neon_state.__v[rt] (zeroing
                         * the upper lanes) and push it back immediately;
                         * stores read from it. */
                        if (!emulated && have_neon &&
                            ((insn & 0x3f200c00) == 0x3c200800 ||   /* SIMD register offset */
                             (insn & 0x3f000000) == 0x3d000000))    /* SIMD unsigned-offset imm */
                        {
                            int size = (insn >> 30) & 3;
                            int opc  = (insn >> 22) & 3;
                            int bytes = (size == 0 && (opc & 2)) ? 16 : (1 << size);
                            if (opc & 1)   /* load */
                            {
                                memset(&neon_state.__v[rt], 0, 16);
                                memcpy(&neon_state.__v[rt], (void *)ea, bytes);
                                thread_set_state(thread, ARM_NEON_STATE64,
                                                 (thread_state_t)&neon_state, neon_count);
                            }
                            else           /* store */
                            {
                                memcpy((void *)ea, &neon_state.__v[rt], bytes);
                            }
                            emulated = 1;
                        }

                        if (emulated)
                        {
                            static volatile int emul3_count = 0;
                            int e3 = __sync_add_and_fetch(&emul3_count, 1);
                            if (e3 <= 20 || (e3 % 4096) == 0)
                                dprintf(STDERR_FILENO,
                                    "[x18-emul3] #%d pc=%p insn=%08x teb+0x%llx rt=%d\n",
                                    e3, (void*)(uintptr_t)fault_pc, insn,
                                    (unsigned long long)fault_addr, rt);
                            /* EXPERIMENT: also set x18 in the written-back
                             * state. Project lore says thread_set_state
                             * doesn't preserve x18 — from early testing that
                             * may have been confounded. If it DOES stick,
                             * the silent-copy hole (NtCurrentTeb = mov
                             * x0,x18 propagating 0 without faulting) closes
                             * and emul3 should fire ~once per context
                             * switch instead of once per TEB access. Free
                             * either way — verify via emul3 rate + next-
                             * fault x18 values in the log. */
                            state.__x[18] = thread_teb;
                            __darwin_arm_thread_state64_set_pc_fptr(
                                state, (void *)(uintptr_t)(fault_pc + 4));
                            ios_exc_x18_fixes++;
                            handled = 1;
                        }
                        else
                        {
                            /* x18-based but unrecognized encoding (writeback,
                             * register-offset, SIMD...). Log it — needs a new
                             * case above, NOT the old x17-clobbering
                             * trampoline. Falls through to real handling. */
                            dprintf(STDERR_FILENO,
                                "[x18-emul3] UNRECOGNIZED insn=%08x pc=%p teb+0x%llx\n",
                                insn, (void*)(uintptr_t)fault_pc,
                                (unsigned long long)fault_addr);
                        }
                    }
                }
            }

            /* 3.5. FEX unaligned LDAR/LDAPR/STLR backpatch.
             *
             * x86 has TSO ordering. FEX's MemoryOps lowers x86 TSO loads/stores
             * to ARM64 LDAPR/STLR (alignment-strict). Some x86 binaries do
             * legal *unaligned* loads (e.g. steamclient64.dll's packed
             * unpacker: `movl (%rsi),%ebx` with rsi unaligned) — those fault
             * on the LDAPR. FEX's HandleUnalignedAccess (Arm64.cpp:2072)
             * already knows how to recover by atomically rewriting the
             * instruction to LDR+DMB_LD (or DMB+STR for STLR). It only fires
             * on Windows EXCEPTION_DATATYPE_MISALIGNMENT — on iOS the Mach
             * handler sees EXC_BAD_ACCESS first.
             *
             * Replicate the FEX backpatch here so iOS gets the same recovery.
             * Encoding constants from FEX/FEXCore/Source/Utils/ArchHelpers/Arm64.cpp. */
            if (!handled)
            {
                extern void *ios_jit_rx_base_global;
                extern void *ios_jit_rw_base_global;
                extern size_t ios_jit_pool_size_global;
                uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
                uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
                size_t sz = ios_jit_pool_size_global;
                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);

                /* madeira-bcd pool-low: FEX code in region C is backpatched the same
                 * way; its alias is at the same distance, so rw + (pc - rx) holds. */
                if (rx && rw && sz && ((fault_pc >= rx && fault_pc < rx + sz) ||
                                       ios_jit_low_contains( (uintptr_t)fault_pc )))
                {
                    uintptr_t rw_pc = rw + (fault_pc - rx);
                    uint32_t insn; ios_fault_read_insn( (uint64_t)(uintptr_t)fault_pc, &insn );  /* ml982 */

                    /* ml431 (#71): per-thread LL/SC monitor for the misaligned
                     * exclusive emulation below. Only ever touched on the single
                     * Mach exception-server thread — no locking. */
                    enum { IOS_EXCL_MON_SLOTS = 64 };
                    static struct {
                        mach_port_t thr;
                        uint64_t addr;
                        uint64_t val;
                        uint8_t size;
                        uint8_t valid;
                    } ios_excl_mon[IOS_EXCL_MON_SLOTS];

                    static const uint32_t LDAXR_MASK  = 0x3FFFFC00u;
                    static const uint32_t LDAR_INST   = 0x08DFFC00u;
                    static const uint32_t LDAPR_INST  = 0x38BFC000u;
                    static const uint32_t STLR_INST   = 0x089FFC00u;
                    static const uint32_t RCPC2_MASK  = 0x3FE00C00u;
                    static const uint32_t LDAPUR_INST = 0x19400000u;
                    static const uint32_t STLUR_INST  = 0x19000000u;
                    static const uint32_t LDR_INST    = 0x387F6800u; /* LDR (imm), unsigned-offset 0 */
                    static const uint32_t STR_INST    = 0x383F6800u;
                    static const uint32_t LDUR_INST   = 0x38400000u;
                    static const uint32_t STUR_INST   = 0x38000000u;
                    static const uint32_t DMB         = 0xD5033BBFu; /* dmb ish */
                    static const uint32_t DMB_LD      = 0xD5033DBFu; /* dmb ishld */

                    int patched = 0;
                    int adjust_pc = 0;
                    uint32_t prev_slot = 0;   /* ml962: slot contents before the barrier overwrites it */

                    /* iOS-Madeira: gate the LDAR/STLR rewrite on the access
                     * being ACTUALLY unaligned for its size. The Mach
                     * EXC_BAD_ACCESS we catch here also covers plain guest
                     * NULL-derefs (addr=0x0, 0x8, ...). Those are aligned and
                     * must be raised as a normal SEGV — rewriting an LDAR/
                     * STLR there only delays the same fault and corrupts the
                     * exception path. Size encoded in insn[31:30]:
                     *   00=byte (always aligned), 01=halfword, 10=word, 11=dword. */
                    {
                        uint32_t access_size_lg2 = (insn >> 30) & 0x3;
                        uint64_t align_mask = (access_size_lg2 == 0) ? 0
                                            : ((1ULL << access_size_lg2) - 1);
                        /* iOS-Madeira ml624 — BYTE ACCESSES MUST *ALWAYS* SKIP.
                         *
                         * The comment above is correct: an 8-bit access can never be
                         * misaligned. But `if (align_mask && ...)` made byte the ONE size
                         * that NEVER took the skip, because align_mask is 0 for it. Every
                         * faulting STLRB therefore fell into the STLR -> DMB+STR backpatch
                         * below, which writes the half-barrier to rw_pc-4.
                         *
                         * For 16/32/64-bit that slot is a nop FEX reserves for exactly this
                         * purpose ("Half-barrier once back-patched", MemoryOps.cpp). For
                         * 8-bit FEX deliberately emits NO nop ("8bit load is always aligned
                         * to natural alignment") -- so rw_pc-4 is a LIVE INSTRUCTION and the
                         * backpatch DESTROYS it.
                         *
                         * That is the ULTRAKILL wall, byte for byte. Mono's emitter store
                         *     91000806  add   x6, x0, #2      <- computes the ADDRESS
                         *     089ffcc8  stlrb w8, [x6]
                         * was rewritten in place to
                         *     d5033bbf  dmb   ish             <- ate the add
                         *     383f68c8  strb  w8, [x6, xzr]
                         * so x6 still held the stale 0x44 from the preceding `or al,0x44`
                         * and the store went to address 0x44. The ml623 capture proved the
                         * IR, the RA and the emitted bytes were all CORRECT at compile time;
                         * this handler is what changed them afterwards.
                         *
                         * A faulting STLRB is never an unaligned atomic -- it is a write to
                         * a page we map RX (here Mono's freshly allocated RWX code buffer),
                         * and the JIT-alias store emulator further down already performs
                         * that store correctly through the RW alias and advances the PC.
                         * Skip, and let it. 16/32/64-bit recovery is unchanged. */
                        if (!align_mask || ((uint64_t)fault_addr & align_mask) == 0) {
                            if (!align_mask) {
                                static int ios_byte_skip_count = 0;
                                if (ios_byte_skip_count < 16) {
                                    ios_byte_skip_count++;
                                    fprintf(stderr, "[unalign-byte] ml624 #%d SKIP backpatch: byte access cannot be "
                                                    "unaligned; insn=%08x pc=%p addr=%p -> alias emulator "
                                                    "(pc-4 preserved)\n",
                                            ios_byte_skip_count, insn, (void *)fault_pc,
                                            (void *)fault_addr);
                                }
                            }
                            /* Aligned — this is a genuine SEGV/BUS, not an
                             * unaligned-atomic-needs-backpatch case. Skip. */
                            goto skip_unaligned_backpatch;
                        }
                    }

                    /* madeira-bcd: ALREADY BACKPATCHED BY A CONCURRENT FAULT.
                     *
                     * Two threads running the same block hit the same unaligned
                     * LDAPR/STLR at once. This handler runs on the one Mach
                     * exception-server thread, so it rewrites the instruction for
                     * the first fault and then reads the SECOND thread's fault
                     * with the plain LDR/STR (LDUR/STUR) already in place -- which
                     * matches none of the atomic forms below, so the fault went out
                     * as unhandled and the guest took an access violation on a
                     * legal unaligned load. God of War's intro video decode threads
                     * (build 239, logs 2026-09-30 10:49 / 10:51: `ldr x8,[x27,xzr]`,
                     * `str xzr,[x6,xzr]` at kr=0x101, several threads, same pc).
                     *
                     * A plain LDR/STR cannot raise an alignment fault on normal
                     * memory, so kr == EXC_ARM_DA_ALIGN with one of our rewritten
                     * forms (and its half-barrier in the neighbouring slot) means the
                     * fault came from the pre-patch instruction. Re-run it: at pc for
                     * the loads (barrier after), at pc-4 for the stores (barrier
                     * before). The patching fault already invalidated the icache. */
                    if (fault_kr == 0x101 /* EXC_ARM_DA_ALIGN */)
                    {
                        uint32_t next_slot = __atomic_load_n((volatile uint32_t *)(rw_pc + 4), __ATOMIC_ACQUIRE);
                        uint32_t prev_slot_now = __atomic_load_n((volatile uint32_t *)(rw_pc - 4), __ATOMIC_ACQUIRE);
                        int resume = 0;   /* 1 = at pc, -4 = at pc-4 */
                        if (((insn & LDAXR_MASK) == LDR_INST || (insn & RCPC2_MASK) == LDUR_INST) && next_slot == DMB_LD)
                            resume = 1;
                        else if (((insn & LDAXR_MASK) == STR_INST || (insn & RCPC2_MASK) == STUR_INST) && prev_slot_now == DMB)
                            resume = -4;
                        if (resume)
                        {
                            static volatile int rp_count;
                            int n = __sync_add_and_fetch(&rp_count, 1);
                            if (resume < 0)
                                __darwin_arm_thread_state64_set_pc_fptr(state, (void *)(uintptr_t)(fault_pc - 4));
                            if (n <= 16 || (n % 256) == 0)
                                dprintf(STDERR_FILENO,
                                        "[mach_exc] UNALIGNED-REPATCHED madeira-bcd #%d pc=0x%llx insn=0x%08x addr=0x%llx "
                                        "-- rewritten by a concurrent fault, re-run%s\n",
                                        n, (unsigned long long)fault_pc, insn, (unsigned long long)fault_addr,
                                        resume < 0 ? " from the barrier" : "");
                            handled = 1;
                            goto skip_unaligned_backpatch;
                        }
                    }

                    if ((insn & LDAXR_MASK) == LDAR_INST ||
                        (insn & LDAXR_MASK) == LDAPR_INST)
                    {
                        /* LDAR/LDAPR → LDR + DMB_LD. Replace instruction in
                         * place with the regular LDR; FEX reserves the next
                         * slot for the half-barrier. */
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint32_t new_ldr = LDR_INST | (Size << 30) | (Rn << 5) | Rt;
                        prev_slot = __atomic_load_n((volatile uint32_t *)(rw_pc + 4), __ATOMIC_ACQUIRE);
                        __atomic_store_n((volatile uint32_t *)(rw_pc + 4), DMB_LD, __ATOMIC_RELEASE);
                        __atomic_store_n((volatile uint32_t *)rw_pc,         new_ldr, __ATOMIC_RELEASE);
                        sys_icache_invalidate((void *)fault_pc, 8);
                        patched = 1;
                    }
                    else if ((insn & LDAXR_MASK) == STLR_INST)
                    {
                        /* STLR → DMB + STR. Half-barrier overwrites the slot
                         * before the STLR; PC backs up by 4. */
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint32_t new_str = STR_INST | (Size << 30) | (Rn << 5) | Rt;
                        prev_slot = __atomic_load_n((volatile uint32_t *)(rw_pc - 4), __ATOMIC_ACQUIRE);
                        __atomic_store_n((volatile uint32_t *)(rw_pc - 4), DMB, __ATOMIC_RELEASE);
                        __atomic_store_n((volatile uint32_t *)rw_pc,       new_str, __ATOMIC_RELEASE);
                        sys_icache_invalidate((void *)(fault_pc - 4), 8);
                        adjust_pc = -4;
                        patched = 1;
                    }
                    else if ((insn & RCPC2_MASK) == LDAPUR_INST)
                    {
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint32_t new_ldur = LDUR_INST | (Size << 30) | (Rn << 5) | Rt
                                           | (insn & (0x1FFu << 12));
                        prev_slot = __atomic_load_n((volatile uint32_t *)(rw_pc + 4), __ATOMIC_ACQUIRE);
                        __atomic_store_n((volatile uint32_t *)(rw_pc + 4), DMB_LD,   __ATOMIC_RELEASE);
                        __atomic_store_n((volatile uint32_t *)rw_pc,         new_ldur, __ATOMIC_RELEASE);
                        sys_icache_invalidate((void *)fault_pc, 8);
                        patched = 1;
                    }
                    else if ((insn & RCPC2_MASK) == STLUR_INST)
                    {
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint32_t new_stur = STUR_INST | (Size << 30) | (Rn << 5) | Rt
                                           | (insn & (0x1FFu << 12));
                        prev_slot = __atomic_load_n((volatile uint32_t *)(rw_pc - 4), __ATOMIC_ACQUIRE);
                        __atomic_store_n((volatile uint32_t *)(rw_pc - 4), DMB,      __ATOMIC_RELEASE);
                        __atomic_store_n((volatile uint32_t *)rw_pc,         new_stur, __ATOMIC_RELEASE);
                        sys_icache_invalidate((void *)(fault_pc - 4), 8);
                        adjust_pc = -4;
                        patched = 1;
                    }
                    /* iOS-Madeira ml431 (#71): misaligned EXCLUSIVE / CAS family.
                     *
                     * ml430: Valve's IPCWrapper embeds a CRITICAL_SECTION at an
                     * odd offset inside a packed shm struct (legal on x86 —
                     * misaligned LOCK ops are architectural there). wine's EC
                     * ntdll TryEnterCriticalSection CAS (ldaxr/stlxr on
                     * LockCount at crit+8) alignment-faults on it. Routing the
                     * fault through the guest-exception path costs ~ms per
                     * instruction (FEX emulates one insn per round-trip), which
                     * stretched an instantaneous acquire until the IPC partner
                     * retired the shm view mid-acquire -> use-after-free AV ->
                     * Crashpad terminate, in the CreateResponse->BrowserReady
                     * gap.
                     *
                     * These cases MUST NOT patch the code: the pool-copied
                     * ntdll .text is shared by every aligned CS in the process;
                     * rewriting ldaxr/stlxr would destroy their atomicity.
                     * Instead emulate the single faulting instruction here with
                     * an LL/SC monitor. This entire block runs on the single
                     * Mach exception-server thread, so all emulated accesses
                     * are naturally serialized (no lock needed); the only
                     * unserialized racers are plain stores from other threads,
                     * which x86 split-lock semantics don't protect against
                     * either. mach_vm_read/write keep a freed view from
                     * faulting the server thread — on failure fall through to
                     * the honest-AV delivery. */
                    else if ((insn & LDAXR_MASK) == 0x085FFC00u ||  /* LDAXR* */
                             (insn & LDAXR_MASK) == 0x085F7C00u)    /* LDXR* */
                    {
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint64_t addr = (Rn == 31) ? __darwin_arm_thread_state64_get_sp(state)
                                                   : state.__x[Rn];
                        uint64_t val = 0;
                        mach_vm_size_t got = 0;
                        if (mach_vm_read_overwrite( mach_task_self(), addr, 1u << Size,
                                                    (mach_vm_address_t)&val, &got ) == KERN_SUCCESS
                            && got == (1u << Size))
                        {
                            int mi, free_mi = -1;
                            if (Rt != 31) state.__x[Rt] = val;
                            for (mi = 0; mi < IOS_EXCL_MON_SLOTS; mi++)
                            {
                                if (ios_excl_mon[mi].valid && ios_excl_mon[mi].thr == thread) break;
                                if (!ios_excl_mon[mi].valid && free_mi < 0) free_mi = mi;
                            }
                            if (mi == IOS_EXCL_MON_SLOTS) mi = (free_mi >= 0) ? free_mi : 0;
                            ios_excl_mon[mi].thr = thread;
                            ios_excl_mon[mi].addr = addr;
                            ios_excl_mon[mi].val = val;
                            ios_excl_mon[mi].size = (uint8_t)Size;
                            ios_excl_mon[mi].valid = 1;
                            __darwin_arm_thread_state64_set_pc_fptr(
                                state, (void *)(uintptr_t)(fault_pc + 4));
                            static volatile int ex_count;
                            int n = __sync_add_and_fetch(&ex_count, 1);
                            if (n <= 8 || (n % 256) == 0)
                                dprintf(STDERR_FILENO,
                                        "[mach_exc] UNALIGNED-EXCL rev=ml431 #%d LDAXR pc=0x%llx addr=0x%llx "
                                        "size=%u val=0x%llx\n",
                                        n, (unsigned long long)fault_pc,
                                        (unsigned long long)addr, 1u << Size,
                                        (unsigned long long)val);
                            handled = 1;
                        }
                    }
                    else if ((insn & 0x3FE0FC00u) == 0x0800FC00u ||  /* STLXR* */
                             (insn & 0x3FE0FC00u) == 0x08007C00u)    /* STXR* */
                    {
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rs = (insn >> 16) & 0x1F;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint64_t addr = (Rn == 31) ? __darwin_arm_thread_state64_get_sp(state)
                                                   : state.__x[Rn];
                        uint64_t szmask = (Size == 3) ? ~0ULL : ((1ULL << (8u << Size)) - 1);
                        uint64_t stval = (Rt == 31) ? 0 : (state.__x[Rt] & szmask);
                        uint64_t status = 1;   /* fail-by-default -> loop retries the LDAXR */
                        int mi;
                        for (mi = 0; mi < IOS_EXCL_MON_SLOTS; mi++)
                            if (ios_excl_mon[mi].valid && ios_excl_mon[mi].thr == thread) break;
                        if (mi < IOS_EXCL_MON_SLOTS && ios_excl_mon[mi].addr == addr
                            && ios_excl_mon[mi].size == (uint8_t)Size)
                        {
                            uint64_t cur = 0;
                            mach_vm_size_t got = 0;
                            ios_excl_mon[mi].valid = 0;
                            if (mach_vm_read_overwrite( mach_task_self(), addr, 1u << Size,
                                                        (mach_vm_address_t)&cur, &got ) == KERN_SUCCESS
                                && got == (1u << Size)
                                && (cur & szmask) == (ios_excl_mon[mi].val & szmask)
                                && mach_vm_write( mach_task_self(), addr,
                                                  (vm_offset_t)(uintptr_t)&stval,
                                                  1u << Size ) == KERN_SUCCESS)
                                status = 0;
                        }
                        else if (mi < IOS_EXCL_MON_SLOTS)
                            ios_excl_mon[mi].valid = 0;
                        if (Rs != 31) state.__x[Rs] = status;
                        __darwin_arm_thread_state64_set_pc_fptr(
                            state, (void *)(uintptr_t)(fault_pc + 4));
                        static volatile int sx_count;
                        int n = __sync_add_and_fetch(&sx_count, 1);
                        if (n <= 8 || (n % 256) == 0)
                            dprintf(STDERR_FILENO,
                                    "[mach_exc] UNALIGNED-EXCL rev=ml431 #%d STLXR pc=0x%llx addr=0x%llx "
                                    "size=%u status=%llu\n",
                                    n, (unsigned long long)fault_pc,
                                    (unsigned long long)addr, 1u << Size,
                                    (unsigned long long)status);
                        handled = 1;
                    }
                    else if ((insn & 0x3FA07C00u) == 0x08A07C00u)    /* CAS/CASA/CASL/CASAL */
                    {
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rs = (insn >> 16) & 0x1F;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint64_t addr = (Rn == 31) ? __darwin_arm_thread_state64_get_sp(state)
                                                   : state.__x[Rn];
                        uint64_t szmask = (Size == 3) ? ~0ULL : ((1ULL << (8u << Size)) - 1);
                        uint64_t cmp = ((Rs == 31) ? 0 : state.__x[Rs]) & szmask;
                        uint64_t stval = ((Rt == 31) ? 0 : state.__x[Rt]) & szmask;
                        uint64_t cur = 0;
                        mach_vm_size_t got = 0;
                        if (mach_vm_read_overwrite( mach_task_self(), addr, 1u << Size,
                                                    (mach_vm_address_t)&cur, &got ) == KERN_SUCCESS
                            && got == (1u << Size))
                        {
                            int stored = 0;
                            if ((cur & szmask) == cmp)
                                stored = (mach_vm_write( mach_task_self(), addr,
                                                         (vm_offset_t)(uintptr_t)&stval,
                                                         1u << Size ) == KERN_SUCCESS);
                            if ((cur & szmask) == cmp && !stored)
                                goto skip_unaligned_backpatch;  /* write failed: honest AV path */
                            if (Rs != 31) state.__x[Rs] = cur & szmask;  /* CAS returns old value in Rs */
                            __darwin_arm_thread_state64_set_pc_fptr(
                                state, (void *)(uintptr_t)(fault_pc + 4));
                            static volatile int cas_count;
                            int n = __sync_add_and_fetch(&cas_count, 1);
                            if (n <= 8 || (n % 256) == 0)
                                dprintf(STDERR_FILENO,
                                        "[mach_exc] UNALIGNED-EXCL rev=ml431 #%d CAS pc=0x%llx addr=0x%llx "
                                        "size=%u old=0x%llx swapped=%d\n",
                                        n, (unsigned long long)fault_pc,
                                        (unsigned long long)addr, 1u << Size,
                                        (unsigned long long)cur, (cur & szmask) == cmp);
                            handled = 1;
                        }
                    }

                    /* madeira-bcd: misaligned LSE atomic memory operations.
                     *
                     * x86 `lock add/xadd/and/or/xor/xchg` on a misaligned operand is
                     * legal and FEX lowers it to LDADD/LDCLR/LDEOR/LDSET/SWP (with
                     * A/L), which alignment-fault here like CAS does. God of War on
                     * build 241 (logs 2026-09-30 11:20 and 11:21): `ldaddal w7, w8,
                     * [x6]` on 0x...b6267e, guest 0x1408df521, the frame after the
                     * intro videos. Emulated like the CAS above: read, compute,
                     * write through mach_vm on the single exception-server thread,
                     * old value to Rt, pc + 4. Never patched: the same instruction
                     * also serves aligned operands. LDAPR shares the family bits
                     * (o3=1, opc=100) and is left to the backpatch above. */
                    else if (!handled && (insn & 0x3F200C00u) == 0x38200000u &&
                             (((insn >> 15) & 1) == 0 || ((insn >> 12) & 7) == 0))
                    {
                        uint32_t Size = (insn >> 30) & 0x3;
                        uint32_t Rs = (insn >> 16) & 0x1F;
                        uint32_t Rn = (insn >> 5) & 0x1F;
                        uint32_t Rt = insn & 0x1F;
                        uint32_t o3 = (insn >> 15) & 1;
                        uint32_t opc = (insn >> 12) & 7;
                        uint32_t nbytes = 1u << Size;
                        uint64_t addr = (Rn == 31) ? __darwin_arm_thread_state64_get_sp(state)
                                                   : state.__x[Rn];
                        uint64_t szmask = (Size == 3) ? ~0ULL : ((1ULL << (8u << Size)) - 1);
                        uint64_t sbit = 1ULL << ((8u << Size) - 1);
                        uint64_t opnd = ((Rs == 31) ? 0 : state.__x[Rs]) & szmask;
                        uint64_t cur = 0, nv = 0;
                        mach_vm_size_t got = 0;
                        if (mach_vm_read_overwrite( mach_task_self(), addr, nbytes,
                                                    (mach_vm_address_t)&cur, &got ) == KERN_SUCCESS
                            && got == nbytes)
                        {
                            int64_t sc, so;
                            cur &= szmask;
                            sc = (int64_t)((cur ^ sbit) - sbit);
                            so = (int64_t)((opnd ^ sbit) - sbit);
                            if (o3) nv = opnd;                                   /* SWP */
                            else switch (opc)
                            {
                            case 0: nv = cur + opnd; break;                      /* LDADD */
                            case 1: nv = cur & ~opnd; break;                     /* LDCLR */
                            case 2: nv = cur ^ opnd; break;                      /* LDEOR */
                            case 3: nv = cur | opnd; break;                      /* LDSET */
                            case 4: nv = (sc > so) ? cur : opnd; break;          /* LDSMAX */
                            case 5: nv = (sc < so) ? cur : opnd; break;          /* LDSMIN */
                            case 6: nv = (cur > opnd) ? cur : opnd; break;       /* LDUMAX */
                            default: nv = (cur < opnd) ? cur : opnd; break;      /* LDUMIN */
                            }
                            nv &= szmask;
                            if (mach_vm_write( mach_task_self(), addr, (vm_offset_t)(uintptr_t)&nv,
                                               nbytes ) != KERN_SUCCESS)
                                goto skip_unaligned_backpatch;  /* write failed: honest AV path */
                            if (Rt != 31) state.__x[Rt] = cur;
                            __darwin_arm_thread_state64_set_pc_fptr(
                                state, (void *)(uintptr_t)(fault_pc + 4));
                            {
                                static volatile int lse_count;
                                int n = __sync_add_and_fetch(&lse_count, 1);
                                if (n <= 8 || (n % 256) == 0)
                                    dprintf(STDERR_FILENO,
                                            "[mach_exc] UNALIGNED-LSE madeira-bcd #%d %s pc=0x%llx addr=0x%llx "
                                            "size=%u old=0x%llx new=0x%llx\n",
                                            n, o3 ? "SWP" : (const char *[]){"LDADD","LDCLR","LDEOR","LDSET",
                                                                              "LDSMAX","LDSMIN","LDUMAX","LDUMIN"}[opc],
                                            (unsigned long long)fault_pc, (unsigned long long)addr, nbytes,
                                            (unsigned long long)cur, (unsigned long long)nv);
                            }
                            handled = 1;
                        }
                    }

                    if (patched)
                    {
                        if (adjust_pc)
                            __darwin_arm_thread_state64_set_pc_fptr(state, (void *)(fault_pc + adjust_pc));
                        static volatile int ub_count = 0;
                        int n = __sync_add_and_fetch(&ub_count, 1);
                        if (n <= 5 || (n % 100) == 0)
                            dprintf(STDERR_FILENO,
                                    "[mach_exc] UNALIGNED-BACKPATCH #%d pc=0x%llx insn=0x%08x addr=0x%llx kind=%s\n",
                                    n, (unsigned long long)fault_pc, insn,
                                    (unsigned long long)fault_addr,
                                    adjust_pc ? "STLR/STLUR" : "LDAR/LDAPR/LDAPUR");
                        /* ml962: this transform writes its half-barrier into a
                         * NEIGHBOURING slot -- rw_pc+4 for the load forms, rw_pc-4
                         * for the store forms -- on the assumption that FEX reserved
                         * that slot. If it did not, the barrier DESTROYS a real
                         * instruction, permanently, in JIT code that will be
                         * re-executed. A destroyed instruction that contributed the
                         * high half of a 64-bit value would produce exactly the
                         * truncation we are chasing, and rdr27 shows 200+ of these
                         * landing on the same guest stack page as R10 (0x...19e,
                         * 0x...20e, 0x...34e vs R10 0x...1b6, all mod 8 == 6).
                         *
                         * So report what was in the slot. `prev_slot` was captured
                         * BEFORE the overwrite. 0xd503201f is NOP = reserved and the
                         * assumption holds; anything else means we are clobbering
                         * real code. Diagnostic only -- no behaviour change yet,
                         * because declining to patch here has no proven fallback. */
                        /* ml963: NAME THE WRITER of the truncated operand.
                         *
                         * ml962 settled that [R10] is already truncated in memory
                         * (0x000000005d450010, high half zero) while the SAME
                         * structure holds a 33-bit pointer full width a few bytes
                         * away -- so this is not a blanket storage failure, it is one
                         * field. The writer was invisible because this report is
                         * capped every-100th; the logged addresses (0x...34e,
                         * 0x...20e, 0x...19e) simply were not it.
                         *
                         * R10's low 12 bits are 0x1b6 in all four runs
                         * (0x16b7ff1b6 / 0x16a1cf1b6 / 0x16977f1b6 / 0x16bccf1b6):
                         * ASLR moves the page, not the offset within it. So filter on
                         * the offset and catch every access to that neighbourhood
                         * regardless of the count.
                         *
                         * The ACCESS SIZE decides who is at fault, and the register
                         * value decides it beyond doubt, because the backpatch runs
                         * BEFORE the store re-executes -- so state.__x[Rt] is exactly
                         * the value about to be written:
                         *   size=4 (32-bit store) and Rt holds the full 64-bit
                         *     pointer  => the GUEST is storing only 32 bits by
                         *     design; the allocation genuinely must be low.
                         *   size=8 (64-bit store) and Rt holds the full pointer, yet
                         *     memory ends up truncated => OUR emulation dropped the
                         *     high word.
                         *   Rt itself already truncated => the truncation happened
                         *     even earlier, in the value's computation. */
                        if ((fault_addr & 0xFFFu) >= 0x190u && (fault_addr & 0xFFFu) <= 0x1d0u)
                        {
                            static volatile int w_count;
                            int wn = __sync_add_and_fetch(&w_count, 1);
                            /* ml964: WATCH THE FIELD, not the instruction.
                             *
                             * ml963 settled that the guest stores FULL-WIDTH
                             * pointers here with 64-bit STLR (0x15ced0011 at
                             * off=0x1ae, high32=1) and that **nothing** faults at
                             * off=0x1b6 -- the field that reads back truncated. So
                             * the corrupting write does not go through this path at
                             * all, and no caught store even covers byte 0x1ba, the
                             * one byte that differs from the correct pointer.
                             *
                             * Chasing the writer instruction has now failed twice.
                             * Watch the memory instead: sample the 8 bytes at the
                             * field on every neighbouring fault and shout on the
                             * transition from full-width to truncated. That bounds
                             * the corruption between two known events, which is what
                             * the search needs -- an ordinary (non-atomic) store, a
                             * bulk copy, or a producer further upstream all look
                             * identical from the instruction side but differ in WHEN.
                             *
                             * The offset is stable across ASLR (0x1b6 in five runs),
                             * so derive the field from the faulting page. */
                            {
                                const mach_vm_address_t fld =
                                    (mach_vm_address_t)((fault_addr & ~0xFFFull) | 0x1b6ull);
                                static volatile uint64_t last_val;
                                static volatile int shouted;
                                uint64_t cur = 0;
                                mach_vm_size_t fg = 0;

                                if (mach_vm_read_overwrite( mach_task_self(), fld, 8,
                                                            (mach_vm_address_t)&cur, &fg ) == KERN_SUCCESS
                                    && fg == 8)
                                {
                                    uint64_t prev = last_val;
                                    last_val = cur;
                                    /* full-width -> truncated, i.e. the high word was
                                     * dropped while the low word kept its shape */
                                    if (prev && (prev >> 32) && !(cur >> 32)
                                        && (uint32_t)prev == (uint32_t)cur && shouted < 4)
                                    {
                                        shouted++;
                                        dprintf(STDERR_FILENO,
                                                "[field] ml964 *** TRUNCATION HAPPENED HERE *** addr=0x%llx "
                                                "was=0x%016llx now=0x%016llx | immediately after event #%d "
                                                "%s off=0x%03x insn=0x%08x pc=0x%llx\n",
                                                (unsigned long long)fld,
                                                (unsigned long long)prev, (unsigned long long)cur, wn,
                                                adjust_pc ? "STORE" : "load",
                                                (unsigned)(fault_addr & 0xFFFu), insn,
                                                (unsigned long long)fault_pc);
                                    }
                                    if (wn <= 96)
                                        dprintf(STDERR_FILENO,
                                                "[field] ml964 #%d after %s off=0x%03x: [0x%llx]=0x%016llx (high32=0x%08llx)\n",
                                                wn, adjust_pc ? "STORE" : "load",
                                                (unsigned)(fault_addr & 0xFFFu),
                                                (unsigned long long)fld, (unsigned long long)cur,
                                                (unsigned long long)(cur >> 32));
                                }
                            }
                            if (wn <= 96)
                            {
                                uint32_t wSize = (insn >> 30) & 0x3u;
                                uint32_t wRt   = insn & 0x1Fu;
                                uint32_t wRn   = (insn >> 5) & 0x1Fu;
                                uint64_t wval  = (wRt == 31) ? 0 : state.__x[wRt];
                                dprintf(STDERR_FILENO,
                                        "[writer] ml963 #%d %s addr=0x%llx (off=0x%03x) insn=0x%08x "
                                        "bytes=%u Rt=x%u Rn=x%u Rt_val=0x%016llx high32=0x%08llx pc=0x%llx -- %s\n",
                                        wn, adjust_pc ? "STORE" : "load",
                                        (unsigned long long)fault_addr,
                                        (unsigned)(fault_addr & 0xFFFu), insn,
                                        1u << wSize, wRt, wRn,
                                        (unsigned long long)wval,
                                        (unsigned long long)(wval >> 32),
                                        (unsigned long long)fault_pc,
                                        !adjust_pc ? "(load, not the writer)"
                                          : (wSize != 3) ? "32-bit-or-narrower STORE => guest truncates by design"
                                          : (wval >> 32) ? "64-bit STORE of a FULL-WIDTH value"
                                          : (wval >= 0x80000000ull) ? "64-bit STORE, Rt looks like a TRUNCATED pointer"
                                                         : "64-bit STORE of a small value (flags/count, not a pointer)");
                            }
                        }
                        if (n <= 24)
                            dprintf(STDERR_FILENO,
                                    "[mach_exc] ml962 backpatch slot %s pc%+d held 0x%08x -- %s\n",
                                    adjust_pc ? "BEFORE" : "AFTER",
                                    adjust_pc ? -4 : 4, prev_slot,
                                    (prev_slot == 0xd503201fu) ? "NOP (reserved, assumption holds)"
                                                               : "NOT A NOP -- REAL INSTRUCTION CLOBBERED");
                        handled = 1;
                    }
                skip_unaligned_backpatch: ;
                }
            }

            /* 4. Emulate stores to JIT-pool RX aliases by redirecting them
             * to the corresponding JIT-pool RW alias address. iOS dual-map
             * blocks W on the RX side even with vm_protect+VM_PROT_COPY,
             * so STR/STP instructions whose target lands in JIT-pool RX
             * have to be emulated. The instruction's other side-effects
             * (Rt unchanged, no flag updates) are nil for STR/STP/STRB/STRH. */
            if (!handled)
            {
                extern void *ios_jit_rx_base_global;
                extern void *ios_jit_rw_base_global;
                extern size_t ios_jit_pool_size_global;
                extern uintptr_t ios_jit_anon_alias_lookup(uintptr_t fault_addr);
                uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
                uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
                size_t sz = ios_jit_pool_size_global;
                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);
                /* Two cases: (a) fault on JIT pool RX directly, route via the
                 * RW alias by offset translation. (b) fault on a user-VA that
                 * was vm_remap'd from JIT pool RX (e.g. FEX CodeBuffer): use
                 * the secondary alias table to find the user_VA → RW alias
                 * mapping. */
                uintptr_t rw_addr = 0;
                /* madeira-bcd pool-low: a store into region C (FEX code buffers) is
                 * routed the same way -- its alias is at the pool's distance. in_low
                 * keeps the bounds checks below to C's own extent. */
                int in_low = rx && rw && sz && ios_jit_low_contains( (uintptr_t)fault_addr );
                int in_jit = (rx && rw && sz &&
                              fault_addr >= rx && fault_addr < rx + sz) || in_low;
                if (in_jit) {
                    rw_addr = rw + (fault_addr - rx);
                } else {
                    rw_addr = ios_jit_anon_alias_lookup(fault_addr);
                }
                /* ml348 DISCRIMINATOR: a write fault with NO alias is a
                 * different bug from a write fault whose instruction we can't
                 * decode, and the two need opposite fixes. Without this the
                 * handler just declines and the thread spins on one address
                 * (ml347). Report which case it is, plus the page's ACTUAL
                 * protection — "r-x, no alias" names an exec-downgraded page
                 * that never got dual-mapped. Capped. */
                if (!rw_addr && (uintptr_t)fault_pc >= 0x100000000ULL)
                {
                    static int noalias_n;
                    if (noalias_n < 8)
                    {
                        mach_vm_address_t na = (mach_vm_address_t)fault_addr;
                        mach_vm_size_t ns = 0;
                        vm_region_basic_info_data_64_t ni;
                        mach_msg_type_number_t nc = VM_REGION_BASIC_INFO_COUNT_64;
                        mach_port_t no = MACH_PORT_NULL;
                        uint32_t ninsn = 0;
                        mach_vm_size_t ngot = 0;
                        noalias_n++;
                        mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)fault_pc, 4,
                                               (mach_vm_address_t)&ninsn, &ngot);
                        if (mach_vm_region(mach_task_self(), &na, &ns, VM_REGION_BASIC_INFO_64,
                                           (vm_region_info_t)&ni, &nc, &no) == KERN_SUCCESS)
                            dprintf(STDERR_FILENO,
                                "[store-noalias] #%d rev=ml348 addr=0x%llx insn=0x%08x pc=0x%llx "
                                "NO pool/anon alias | region 0x%llx+0x%llx prot=%d max=%d "
                                "(prot without W = exec-downgraded page that never got dual-mapped)\n",
                                noalias_n, (unsigned long long)fault_addr, ninsn,
                                (unsigned long long)fault_pc,
                                (unsigned long long)na, (unsigned long long)ns,
                                ni.protection, ni.max_protection);
                        else
                            dprintf(STDERR_FILENO,
                                "[store-noalias] #%d rev=ml348 addr=0x%llx insn=0x%08x pc=0x%llx "
                                "NO alias and NO region (unmapped) — genuine bad pointer\n",
                                noalias_n, (unsigned long long)fault_addr, ninsn,
                                (unsigned long long)fault_pc);
                    }
                }
                /* FEX's exception handler completes some guest accesses itself
                 * (ml657: DoCAS / RunCASPAL), after HandleRWXAccessViolation has
                 * already invalidated the page. Its store must land through the
                 * alias. Dispatching it again re-enters the handler while it holds
                 * ThreadCreationMutex; the faults nest until the exception stack
                 * overflows and the thread dies holding the lock (Stardew freeze,
                 * 200111). Translated guest code is never in an image copy, so its
                 * stores still reach FEX first. */
                int honor_guest_prot = 1;
                if (rw_addr && ios_alias_write_is_trapped( fault_addr ) &&
                    ios_jit_pool_pc_is_fex( (uintptr_t)fault_pc ))
                {
                    static unsigned fex_alias_logs;
                    honor_guest_prot = 0;
                    if (fex_alias_logs++ < 16)
                        dprintf( 2, "[alias-protection] completing FEX handler write pc=%llx addr=%llx\n",
                                 (unsigned long long)fault_pc, (unsigned long long)fault_addr );
                }
                if (rw_addr && honor_guest_prot && ios_alias_write_is_trapped( fault_addr ))
                {
                    static unsigned trapped_alias_logs;
                    if (trapped_alias_logs++ < 16)
                        dprintf( 2, "[alias-protection] dispatching guest write fault pc=%llx addr=%llx\n",
                                 (unsigned long long)fault_pc, (unsigned long long)fault_addr );
                    goto dispatch_guest_fault;
                }
                if (rw_addr && (uintptr_t)fault_pc >= 0x100000000ULL)
                {
                    uint32_t insn; ios_fault_read_insn( (uint64_t)(uintptr_t)fault_pc, &insn );  /* ml982 */
                    int emulated = 0;
                    uintptr_t alias_fault = 0;
                    /* STP (SIMD&FP, signed offset, 128-bit Q): 10 101 1 1 0 0 0 imm7 Rt2 Rn Rt
                     *   pattern bits 31-22: 10 1011 1000  → top10 = 0x2B8 (= bits 31..22)
                     *   So mask 0xFFC00000 = top10. Match 0x2B8 << 22 = 0xAE000000? Hmm.
                     * Actually: STP q0,q1,[xn,#imm] is `1010 1101 0010 ... `
                     * STP q,q (signed offset): 0xAD0 (top 12), so mask 0xFFE00000 == 0xAD000000.
                     * STP q,q (pre/post-index variants): 0xAD8, 0xACC, etc.
                     * For now, emulate the family: top 7 bits = 0b1010110, bit 31:25 = 0x56,
                     * mask 0xFE000000 matches 0xAC000000 — covers 64/128-bit SIMD STP variants. */
                    /* iOS-Madeira ml629: Q-PAIR STORES — ALL FOUR ADDRESSING MODES.
                     *
                     * The previous test pinned bit23 to 0:
                     *     (insn & 0xFEC00000) == 0xAC000000 || == 0xAD000000
                     * which covers only the two NON-WRITEBACK forms (non-temporal STNP,
                     * bits25:23=000, and signed-offset STP, 010). ULTRAKILL/Mono copies into
                     * its JIT buffer with a 32-byte NEON loop whose store is POST-INDEXED:
                     *     0xac814570 = STP Q16, Q17, [X11], #32     (bits25:23 = 001)
                     * so it fell through to [store-undecoded], the write never completed, and
                     * the process exited 0x80000002. The neighbouring loads in the stream
                     * (0xacc14590 = LDP Q16,Q17,[X12],#32) confirm the memcpy shape.
                     *
                     * Encoding: opc=10 101 V=1 mode(bits25:23) L(bit22) imm7 Rt2 Rn Rt
                     *   000 non-temporal   no writeback
                     *   001 post-index     writeback; store at the OLD base
                     *   010 signed offset  no writeback
                     *   011 pre-index      writeback; store at the NEW base
                     * Mask 0xFE400000 == 0xAC000000 fixes opc/101/V and L=0, leaving the mode
                     * free. L=1 (loads) is deliberately excluded: this is the WRITE-fault
                     * alias path, and reads from the RX view are already permitted.
                     *
                     * 🔑 fault_addr is ALWAYS the effective address the CPU actually used, so
                     * rw_addr is already right in every mode. Only Rn's writeback must be
                     * synthesised, and it derives from fault_addr without trusting the
                     * register: post -> base_new = fault_addr + off; pre -> base_new =
                     * fault_addr (which already includes off).
                     * ⚠️ Omitting that writeback would leave the copy loop on one address
                     * forever — trading a crash for a spin, which is strictly worse.
                     *
                     * STP Q is not architecturally one atomic 32-byte transaction, so two
                     * 16-byte copies are correct. Rn==31 is SP, never __x[31]. */
                    /* ml1289: a store that crosses a 16 KB page is written per page here;
                     * every other store goes on to its per-encoding case below. */
                    const int split_r = ios_store_split_crossing( insn, &state, have_neon ? &neon_state : NULL,
                                                                  rx, rw, sz );
                    if (split_r)
                    {
                        if (split_r > 0) emulated = 1;
                    }
                    else if (have_neon && (insn & 0xFE400000) == 0xAC000000)
                    {
                        const int mode = (insn >> 23) & 0x3; /* 0 stnp, 1 post, 2 offset, 3 pre */
                        const int rt   = insn & 0x1f;
                        const int rt2  = (insn >> 10) & 0x1f;
                        const int rn   = (insn >> 5) & 0x1f;
                        int64_t imm7   = (int64_t)((insn >> 15) & 0x7f);
                        if (imm7 & 0x40) imm7 -= 0x80;          /* sign-extend 7 bits */
                        const int64_t off = imm7 * 16;          /* Q registers scale by 16 */

                        uint64_t base_old = rn == 31 ? state.__sp : rn == 30 ? state.__lr :
                                            rn == 29 ? state.__fp : state.__x[rn];
                        uintptr_t effective = mode == 1 ? base_old : base_old + off;
                        unsigned char values[32];
                        memcpy( values, &neon_state.__v[rt], 16 );
                        memcpy( values + 16, &neon_state.__v[rt2], 16 );
                        if (fault_addr >= effective && fault_addr - effective < sizeof(values) &&
                            ios_alias_write( effective, values, sizeof(values), &alias_fault, honor_guest_prot ))
                        {
                            uint64_t base_new = base_old;
                            int wb = (mode == 1 || mode == 3);

                            if (wb)
                            {
                                base_new = base_old + (uint64_t)off;
                                if (rn == 31) state.__sp = base_new;
                                else if (rn == 30) state.__lr = base_new;
                                else if (rn == 29) state.__fp = base_new;
                                else state.__x[rn] = base_new;
                            }
                            emulated = 1;
                            {
                                static int stp_n;
                                if (stp_n < 8)
                                    dprintf(STDERR_FILENO,
                                        "[stp-emul] ml629 #%d insn=0x%08x mode=%s off=%+lld Rt=q%d Rt2=q%d "
                                        "Rn=%s%d addr=0x%llx rw=0x%llx base 0x%llx -> 0x%llx%s\n",
                                        ++stp_n, insn,
                                        mode == 0 ? "stnp" : mode == 1 ? "post" : mode == 2 ? "offset" : "pre",
                                        (long long)off, rt, rt2, rn == 31 ? "s" : "x", rn,
                                        (unsigned long long)fault_addr, (unsigned long long)rw_addr,
                                        (unsigned long long)base_old, (unsigned long long)base_new,
                                        wb ? " (writeback)" : " (no writeback)");
                            }
                        }
                    }
                    /* STR (immediate, unsigned offset, 64-bit): 1111 1001 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0xf9000000)
                    {
                        int rt = insn & 0x1f;
                        uint64_t value = IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                    }
                    /* STR (immediate, unsigned offset, 32-bit): 1011 1001 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0xb9000000)
                    {
                        int rt = insn & 0x1f;
                        uint32_t value = (uint32_t)IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                    }
                    /* STRB (immediate, unsigned offset, 8-bit): 0011 1001 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0x39000000)
                    {
                        int rt = insn & 0x1f;
                        uint8_t value = (uint8_t)IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                    }
                    /* STRH (immediate, unsigned offset, 16-bit): 0111 1001 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0x79000000)
                    {
                        int rt = insn & 0x1f;
                        uint16_t value = (uint16_t)IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                    }
                    /* A native heap initializer uses pre-index STP on an
                     * executable allocation. Complete it through the alias;
                     * making the whole host page writable would bypass SMC. */
                    else if ((insn & 0x7e400000u) == 0x28000000u)
                    {
                        uint64_t gpr[32];
                        memcpy( gpr, state.__x, sizeof(state.__x) );
                        gpr[29] = state.__fp;
                        gpr[30] = state.__lr;
                        gpr[31] = state.__sp;
                        if (ios_alias_store_pair( insn, fault_addr, gpr, &alias_fault, honor_guest_prot ))
                        {
                            memcpy( state.__x, gpr, sizeof(state.__x) );
                            state.__fp = gpr[29];
                            state.__lr = gpr[30];
                            state.__sp = gpr[31];
                            emulated = 1;
                        }
                    }
                    /* STR (register, 64-bit): 1111 1000 001 Rm option S 10 Rn Rt */
                    else if ((insn & 0xffe00c00) == 0xf8200800)
                    {
                        int rt = insn & 0x1f;
                        uint64_t value = IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                    }
                    /* STLR (Store-Release Register, 64-bit):
                     *   1100 1000 1001 1111 1111 11nn nnnt tttt   (mask 0xfffffc00, val 0xc89ffc00)
                     * Used by FEX's HandleUnalignedAccess backpatch
                     * (`std::atomic_ref<uint32_t>(PC).store(..., release)` → STLR).
                     * Without this we infinite-loop on unaligned atomic faults
                     * because FEX can't patch its own JIT block on iOS RX-only memory. */
                    else if ((insn & 0xfffffc00) == 0xc89ffc00)
                    {
                        int rt = insn & 0x1f;
                        __atomic_store_n((uint64_t *)rw_addr, IOS_STORE_SRC(rt), __ATOMIC_RELEASE);
                        emulated = 1;
                    }
                    /* STLR (Store-Release Register, 32-bit):
                     *   1000 1000 1001 1111 1111 11nn nnnt tttt   (mask 0xfffffc00, val 0x889ffc00)
                     * Same use case — FEX's backpatch is a 32-bit instruction store. */
                    else if ((insn & 0xfffffc00) == 0x889ffc00)
                    {
                        int rt = insn & 0x1f;
                        __atomic_store_n((uint32_t *)rw_addr, (uint32_t)IOS_STORE_SRC(rt), __ATOMIC_RELEASE);
                        emulated = 1;
                    }
                    /* STLRH (Store-Release 16-bit):
                     *   0100 1000 1001 1111 1111 11nn nnnt tttt   (mask 0xfffffc00, val 0x489ffc00) */
                    else if ((insn & 0xfffffc00) == 0x489ffc00)
                    {
                        int rt = insn & 0x1f;
                        __atomic_store_n((uint16_t *)rw_addr, (uint16_t)IOS_STORE_SRC(rt), __ATOMIC_RELEASE);
                        emulated = 1;
                    }
                    /* STLRB (Store-Release 8-bit):
                     *   0000 1000 1001 1111 1111 11nn nnnt tttt   (mask 0xfffffc00, val 0x089ffc00) */
                    else if ((insn & 0xfffffc00) == 0x089ffc00)
                    {
                        int rt = insn & 0x1f;
                        __atomic_store_n((uint8_t *)rw_addr, (uint8_t)IOS_STORE_SRC(rt), __ATOMIC_RELEASE);
                        emulated = 1;
                    }
                    /* ml1231: STLURB/STLURH/STLUR (FEAT_LRCPC2, store-release with an
                     * unscaled 9-bit offset), what FEX emits for guest stores once the
                     * host reports LRCPC2:
                     *   ss01 1001 000i iiii iiii 00nn nnnt tttt   (mask 0x3fe00c00, val 0x19000000)
                     * fault_addr already includes the offset. A guest store can be
                     * misaligned, so the bytes are copied after a release fence rather
                     * than with an atomic store that could itself alignment-fault. */
                    else if ((insn & 0x3fe00c00) == 0x19000000)
                    {
                        int rt = insn & 0x1f;
                        uint64_t v = IOS_STORE_SRC(rt);
                        __atomic_thread_fence(__ATOMIC_RELEASE);
                        emulated = ios_alias_write( fault_addr, &v, 1u << (insn >> 30), &alias_fault, honor_guest_prot );
                    }
                    /* STR (register, 32-bit): 1011 1000 001 Rm option S 10 Rn Rt */
                    else if ((insn & 0xffe00c00) == 0xb8200800)
                    {
                        int rt = insn & 0x1f;
                        uint32_t value = (uint32_t)IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                    }
                    /* STR (immediate, post/pre-index, 64-bit): 1111 1000 00 0imm9 0[10]1 Rn Rt */
                    else if ((insn & 0xffe00000) == 0xf8000000 && (insn & 0x800) == 0)
                    {
                        int rt = insn & 0x1f;
                        uint64_t value = IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                        /* Post-index (bits 11:10 = 01) / pre-index (bits 11:10 = 11):
                         * MUST update Rn += signed imm9. Without this, memcpy-style
                         * loops would write the same address forever. */
                        int idx_mode = (insn >> 10) & 3;  // bits 11:10
                        if (emulated && (idx_mode == 1 || idx_mode == 3))
                        {
                            int rn = (insn >> 5) & 0x1f;
                            int imm9 = (insn >> 12) & 0x1ff;
                            if (imm9 & 0x100) imm9 |= ~0x1ff;  // sign-extend 9-bit
                            state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                        }
                    }
                    /* STR (immediate, post/pre-index, 32-bit): 1011 1000 00 0imm9 0[10]1 Rn Rt */
                    else if ((insn & 0xffe00000) == 0xb8000000 && (insn & 0x800) == 0)
                    {
                        int rt = insn & 0x1f;
                        uint32_t value = (uint32_t)IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                        int idx_mode = (insn >> 10) & 3;
                        if (emulated && (idx_mode == 1 || idx_mode == 3))
                        {
                            int rn = (insn >> 5) & 0x1f;
                            int imm9 = (insn >> 12) & 0x1ff;
                            if (imm9 & 0x100) imm9 |= ~0x1ff;
                            state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                        }
                    }
                    /* STRB (immediate, post/pre-index, 8-bit): 0011 1000 00 0imm9 0[10]1 Rn Rt
                     * Hits when iOS memcpy handles the trailing bytes after the
                     * 8-byte D-store loop completes (660 bytes = 82*8 + 4 bytes
                     * tail; the tail is byte-by-byte). */
                    else if ((insn & 0xffe00000) == 0x38000000 && (insn & 0x800) == 0)
                    {
                        int rt = insn & 0x1f;
                        uint8_t value = (uint8_t)IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                        int idx_mode = (insn >> 10) & 3;
                        if (emulated && (idx_mode == 1 || idx_mode == 3))
                        {
                            int rn = (insn >> 5) & 0x1f;
                            int imm9 = (insn >> 12) & 0x1ff;
                            if (imm9 & 0x100) imm9 |= ~0x1ff;
                            state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                        }
                    }
                    /* STRH (immediate, post/pre-index, 16-bit): 0111 1000 00 0imm9 0[10]1 Rn Rt */
                    else if ((insn & 0xffe00000) == 0x78000000 && (insn & 0x800) == 0)
                    {
                        int rt = insn & 0x1f;
                        uint16_t value = (uint16_t)IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                        int idx_mode = (insn >> 10) & 3;
                        if (emulated && (idx_mode == 1 || idx_mode == 3))
                        {
                            int rn = (insn >> 5) & 0x1f;
                            int imm9 = (insn >> 12) & 0x1ff;
                            if (imm9 & 0x100) imm9 |= ~0x1ff;
                            state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                        }
                    }
                    /* SIMD/FP STR (immediate, post/pre-index, D-reg = 64-bit):
                     * 11 111 1 00 00 0 imm9 idx Rn Rt   — encoding 0xfc000400 base.
                     * The fc008600 = `str d0, [x16], #8` from iOS memcpy hits
                     * this when copying compiled FEX blocks to RX-only memory. */
                    else if ((insn & 0xffe00000) == 0xfc000000 && (insn & 0xc00) != 0)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            /* Low 64 bits of the 128-bit Q-reg = D-reg. */
                            emulated = ios_alias_write( fault_addr, &neon_state.__v[rt], 8, &alias_fault, honor_guest_prot );
                            int idx_mode = (insn >> 10) & 3;
                            if (emulated && (idx_mode == 1 || idx_mode == 3))
                            {
                                int rn = (insn >> 5) & 0x1f;
                                int imm9 = (insn >> 12) & 0x1ff;
                                if (imm9 & 0x100) imm9 |= ~0x1ff;
                                state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                            }
                        }
                    }
                    /* SIMD/FP STR (immediate, post/pre-index, S-reg = 32-bit):
                     * 10 111 1 00 00 0 imm9 idx Rn Rt   — base 0xbc000400. */
                    else if ((insn & 0xffe00000) == 0xbc000000 && (insn & 0xc00) != 0)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            emulated = ios_alias_write( fault_addr, &neon_state.__v[rt], 4, &alias_fault, honor_guest_prot );
                            int idx_mode = (insn >> 10) & 3;
                            if (emulated && (idx_mode == 1 || idx_mode == 3))
                            {
                                int rn = (insn >> 5) & 0x1f;
                                int imm9 = (insn >> 12) & 0x1ff;
                                if (imm9 & 0x100) imm9 |= ~0x1ff;
                                state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                            }
                        }
                    }
                    /* SIMD/FP STR (immediate, post/pre-index, Q-reg = 128-bit):
                     * 00 111 1 00 10 0 imm9 idx Rn Rt   — base 0x3c800400. */
                    else if ((insn & 0xffe00000) == 0x3c800000 && (insn & 0xc00) != 0)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            emulated = ios_alias_write( fault_addr, &neon_state.__v[rt], 16, &alias_fault, honor_guest_prot );
                            int idx_mode = (insn >> 10) & 3;
                            if (emulated && (idx_mode == 1 || idx_mode == 3))
                            {
                                int rn = (insn >> 5) & 0x1f;
                                int imm9 = (insn >> 12) & 0x1ff;
                                if (imm9 & 0x100) imm9 |= ~0x1ff;
                                state.__x[rn] = (uint64_t)((int64_t)state.__x[rn] + imm9);
                            }
                        }
                    }
                    /* SIMD/FP STUR (immediate, UNSCALED, Q-reg = 128-bit):
                     * 00 111 1 00 10 0 imm9 00 Rn Rt   — 0x3c800000, bits[11:10]==00.
                     * The pre/post-index branch above requires (insn & 0xc00) != 0,
                     * so the unscaled form fell straight through to "undecoded" —
                     * the [store-undecoded] "ADD THIS ENCODING" line in ml592.
                     * NO writeback: unscaled STUR does not modify Rn (the
                     * post-indexed encoding is 0x3c9f04c0, not 0x3c9f00c0). */
                    else if ((insn & 0xffe00c00) == 0x3c800000)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            emulated = ios_alias_write( fault_addr, &neon_state.__v[rt], 16, &alias_fault, honor_guest_prot );
                        }
                    }
                    /* GPR STR (immediate, unsigned offset, 64-bit X-reg):
                     *   1111 1001 00 imm12 Rn Rt   (base 0xf9000000, mask 0xffc00000)
                     * Hits for `str xN, [xM, #imm]` and `str xN, [xM]` —
                     * what the C compiler emits for `*ptr = uint64_value`.
                     * Wine's PE loader / ARM64EC compiler-generated code triggers this
                     * when initializing data in a page that's been mprotect'd RX-only
                     * on iOS. fault_addr already includes the imm12 offset. */
                    else if ((insn & 0xffc00000) == 0xf9000000)
                    {
                        int rt = insn & 0x1f;
                        uint64_t value = IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                    }
                    /* GPR STR (immediate, unsigned offset, 32-bit W-reg):
                     *   1011 1001 00 imm12 Rn Rt   (base 0xb9000000, mask 0xffc00000)
                     * `*ptr32 = uint32_value` analogue. */
                    else if ((insn & 0xffc00000) == 0xb9000000)
                    {
                        int rt = insn & 0x1f;
                        uint32_t value = (uint32_t)IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                    }
                    /* SIMD/FP STR (immediate, unsigned offset, D-reg): 11 111 1 01 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0xfd000000)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            emulated = ios_alias_write( fault_addr, &neon_state.__v[rt], 8, &alias_fault, honor_guest_prot );
                        }
                    }
                    /* SIMD/FP STR (immediate, unsigned offset, S-reg): 10 111 1 01 00 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0xbd000000)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            emulated = ios_alias_write( fault_addr, &neon_state.__v[rt], 4, &alias_fault, honor_guest_prot );
                        }
                    }
                    /* SIMD/FP STR (immediate, unsigned offset, Q-reg): 00 111 1 01 10 imm12 Rn Rt */
                    else if ((insn & 0xffc00000) == 0x3d800000)
                    {
                        int rt = insn & 0x1f;
                        if (have_neon)
                        {
                            emulated = ios_alias_write( fault_addr, &neon_state.__v[rt], 16, &alias_fault, honor_guest_prot );
                        }
                    }
                    /* ml350: STRB (register offset): 0011 1000 001 Rm opt S 10 Rn Rt
                     * (mask 0xffe00c00, val 0x38200800). FEX's own STLRB backpatch
                     * rewrites to DMB+`strb wN,[xM,xzr]` — chrome_elf writing its
                     * interception thunk bytes to an anon-RWX page hit this and
                     * looped (ml349: insn 0x383f68c8). fault_addr is already the
                     * final address; no base/offset math needed. */
                    else if ((insn & 0xffe00c00) == 0x38200800)
                    {
                        int rt = insn & 0x1f;
                        uint8_t value = (uint8_t)IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                    }
                    /* ml350: STRH (register offset): 0111 1000 001 ... (val 0x78200800) */
                    else if ((insn & 0xffe00c00) == 0x78200800)
                    {
                        int rt = insn & 0x1f;
                        uint16_t value = (uint16_t)IOS_STORE_SRC(rt);
                        emulated = ios_alias_write( fault_addr, &value, sizeof(value), &alias_fault, honor_guest_prot );
                    }
                    /* ml1276: SIMD&FP STR (register offset), B/H/S/D/Q:
                     *   size 111 1 00 opc(1)0 1 Rm option S 10 Rn Rt
                     *   mask 0x3f600c00, value 0x3c200800; opc<1> picks Q (size 00 only).
                     * FEX addresses 32-bit guest memory as [x19, wN, uxtw] (x19 = the
                     * guest window), so a guest SSE store becomes STR qN, [x19, wM, uxtw].
                     * Terraria's Mono x86 JIT copied into its RWX code buffer with one
                     * (0x3cab4a70) and, undecoded, looped through FEX's SMC handler 2000
                     * times: FEX re-granted RWX, the alias page stays physically RX.
                     * The address is taken from the registers rather than fault_addr,
                     * which need not be the start of an access that crosses into the
                     * faulting page; each 16 KB page of the destination takes its own
                     * alias, and the store is refused unless all of it has one. */
                    else if ((insn & 0x3f600c00) == 0x3c200800)
                    {
                        const unsigned size = insn >> 30;
                        const unsigned bytes = ((insn >> 23) & 1) ? (size == 0 ? 16u : 0u) : (1u << size);
                        const unsigned option = (insn >> 13) & 7;
                        const int rt = insn & 0x1f, rn = (insn >> 5) & 0x1f, rm = (insn >> 16) & 0x1f;

                        if (have_neon && bytes && (option & 2))  /* option<1> = 0 is unallocated */
                        {
                            uint64_t off = IOS_STORE_SRC(rm), ea, a;
                            uintptr_t part_rw[2];
                            unsigned part_len[2], parts = 0, done = 0, i;

                            if (option == 2) off = (uint32_t)off;                        /* UXTW */
                            else if (option == 6) off = (uint64_t)(int64_t)(int32_t)off; /* SXTW */
                            if (insn & 0x1000) off <<= __builtin_ctz(bytes);
                            ea = (rn == 31 ? state.__sp : state.__x[rn]) + off;
                            while (done < bytes && parts < 2)
                            {
                                unsigned len = bytes - done;
                                a = ea + done;
                                if (len > 0x4000 - (a & 0x3fff)) len = 0x4000 - (unsigned)(a & 0x3fff);
                                part_rw[parts] = (rx && rw && sz && a >= rx && a - rx <= sz - len)
                                                 ? rw + (a - rx) : ios_jit_anon_alias_lookup( (uintptr_t)a );
                                if (!part_rw[parts]) break;
                                part_len[parts++] = len;
                                done += len;
                            }
                            if (done == bytes)
                            {
                                const uint8_t *src = (const uint8_t *)&neon_state.__v[rt];
                                for (i = 0, done = 0; i < parts; done += part_len[i], i++)
                                    memcpy( (void *)part_rw[i], src + done, part_len[i] );
                                emulated = 1;
                            }
                            {
                                static int simd_reg_n;
                                if (simd_reg_n < 4)
                                    dprintf(STDERR_FILENO,
                                        "[simd-str-reg] ml1276 #%d insn=0x%08x bytes=%u ea=0x%llx fault=0x%llx parts=%u %s\n",
                                        ++simd_reg_n, insn, bytes, (unsigned long long)ea,
                                        (unsigned long long)fault_addr, parts,
                                        emulated ? "emulated" : "REFUSED: a page of the store has no alias");
                            }
                        }
                    }
                    /* ml1283: the immediate-offset pair and SIMD&FP stores the cases above
                     * miss, with the base writeback the indexed forms need:
                     *   STP/STNP Wt|Xt, post-index, pre-index, non-temporal:
                     *     sf 0 101 0 0 mode(2) 0 imm7 Rt2 Rn Rt, mask 0x7e400000 val 0x28000000
                     *     (mode 10, signed offset, is matched earlier);
                     *   SIMD&FP STUR and STR post-/pre-index, B/H/S/D/Q:
                     *     size 111 1 00 opc(1)0 0 imm9 mode(2) Rn Rt, mask 0x3f600000 val 0x3c000000
                     *     (mode 00 unscaled, 01 post, 11 pre; 10 is unallocated).
                     * A 64-bit .NET program reached both, each an access violation while
                     * undecoded: ntdll's own STP X9, X8, [X10, #0x80]! (0xa9882149)
                     * initialising a critical section mscoree had placed in RWX memory,
                     * and Mono's x86 JIT writing a float into its code buffer, translated
                     * as STUR S0, [X19, #41] (0xbc029260). As ml1276: the address comes from
                     * the registers, each 16 KB page takes its own alias, the store is
                     * refused unless all of it has one, and Rn is written back only after
                     * the whole store. Rn == 31 is SP. */
                    else if (((insn & 0x7e400000) == 0x28000000 && ((insn >> 23) & 3) != 2)
                             || ((insn & 0x3f600000) == 0x3c000000 && ((insn >> 10) & 3) != 2))
                    {
                        const int pair = (insn & 0x3c000000) == 0x28000000;
                        const int rt = insn & 0x1f, rn = (insn >> 5) & 0x1f;
                        uint8_t src[16];
                        unsigned bytes = 0;
                        int64_t imm = 0;
                        int post = 0, wb = 0;

                        if (pair)
                        {
                            const unsigned mode = (insn >> 23) & 3;   /* 0 stnp, 1 post, 3 pre */
                            const unsigned elem = (insn >> 31) ? 8u : 4u;
                            int64_t imm7 = (int64_t)((insn >> 15) & 0x7f);
                            uint64_t a = IOS_STORE_SRC(rt), b = IOS_STORE_SRC((insn >> 10) & 0x1f);
                            if (imm7 & 0x40) imm7 -= 0x80;
                            imm = imm7 * (int64_t)elem;
                            post = mode == 1;
                            wb = mode == 1 || mode == 3;
                            bytes = 2 * elem;
                            memcpy( src, &a, elem );
                            memcpy( src + elem, &b, elem );
                        }
                        else if (have_neon)
                        {
                            const unsigned size = insn >> 30, mode = (insn >> 10) & 3;
                            int64_t imm9 = (int64_t)((insn >> 12) & 0x1ff);
                            if (imm9 & 0x100) imm9 -= 0x200;
                            imm = imm9;
                            post = mode == 1;
                            wb = mode != 0;
                            bytes = ((insn >> 23) & 1) ? (size == 0 ? 16u : 0u) : (1u << size);
                            memcpy( src, &neon_state.__v[rt], 16 );
                        }
                        if (bytes)
                        {
                            const uint64_t base = rn == 31 ? state.__sp : state.__x[rn];
                            const uint64_t ea = post ? base : base + (uint64_t)imm;
                            uint64_t a;
                            uintptr_t part_rw[2];
                            unsigned part_len[2], parts = 0, done = 0, i;

                            while (done < bytes && parts < 2)
                            {
                                unsigned len = bytes - done;
                                a = ea + done;
                                if (len > 0x4000 - (a & 0x3fff)) len = 0x4000 - (unsigned)(a & 0x3fff);
                                part_rw[parts] = (rx && rw && sz && a >= rx && a - rx <= sz - len)
                                                 ? rw + (a - rx) : ios_jit_anon_alias_lookup( (uintptr_t)a );
                                if (!part_rw[parts]) break;
                                part_len[parts++] = len;
                                done += len;
                            }
                            if (done == bytes)
                            {
                                for (i = 0, done = 0; i < parts; done += part_len[i], i++)
                                    memcpy( (void *)part_rw[i], src + done, part_len[i] );
                                if (wb)
                                {
                                    if (rn == 31) state.__sp = base + (uint64_t)imm;
                                    else          state.__x[rn] = base + (uint64_t)imm;
                                }
                                emulated = 1;
                            }
                            {
                                static int imm_store_n;
                                if (imm_store_n < 4)
                                    dprintf(STDERR_FILENO,
                                        "[imm-store] ml1283 #%d insn=0x%08x %s bytes=%u ea=0x%llx fault=0x%llx%s %s\n",
                                        ++imm_store_n, insn, pair ? "stp" : "simd", bytes,
                                        (unsigned long long)ea, (unsigned long long)fault_addr,
                                        wb ? " (writeback)" : "",
                                        emulated ? "emulated" : "REFUSED: a page of the store has no alias");
                            }
                        }
                    }
                    /* ml1284: STXR / STLXR Ws, Wt|Xt, [Xn] into an aliased page.
                     *   size 001000 0 0 0 Rs o0 11111 Rn Rt, mask 0x3fe07c00 val 0x08007c00
                     * The paired LDXR/LDAXR read the RX view and succeeded; only the store
                     * faults, so the exclusive monitor never sees it and replaying it as a
                     * plain store would lose a racing update. ntdll's RtlEnterCriticalSection
                     * (LDAXR W9, [X8]; ADD W10, W9, #1; STLXR W11, W10, [X8]) reached this on
                     * a critical section a 64-bit .NET runtime keeps in its RWX memory.
                     * The LL/SC pair becomes a compare-and-swap on the RW alias: the expected
                     * value is the register the matching load filled, found by scanning back
                     * at most 8 instructions for an LDXR/LDAXR of the same Rn and size. An
                     * ADD/SUB(S) immediate between that updates that register in place (the
                     * InterlockedDecrement shape LDAXR W9; SUBS W9, W9, #1; STLXR W10, W9 of
                     * RtlLeaveCriticalSection) is undone to recover the loaded value; any
                     * other instruction that may write it (anything but a branch on it)
                     * refuses the emulation. Ws = 0 when the swap succeeds and
                     * 1 when the value changed, so the guest's loop retries as on hardware.
                     * Every write to such a page traps and is handled on the one Mach
                     * exception thread, and the CAS is a real atomic on the shared pages. */
                    else if ((insn & 0x3fe07c00) == 0x08007c00)
                    {
                        const unsigned size = insn >> 30;
                        const int rs = (insn >> 16) & 0x1f, rn = (insn >> 5) & 0x1f, rt = insn & 0x1f;
                        const uint64_t mask = size == 3 ? ~0ull : ((1ull << (8u << size)) - 1);
                        const uint64_t ea = rn == 31 ? state.__sp : state.__x[rn];
                        int ld_rt = -1, k, clobbered = 0;
                        uint64_t delta = 0;   /* what in-place ADD/SUB immediates added to it */
                        uint32_t prev;

                        for (k = 1; k <= 8 && ld_rt < 0 && !clobbered; k++)
                        {
                            if (!ios_fault_read_insn( (uint64_t)(uintptr_t)fault_pc - 4u * k, &prev )) break;
                            if ((prev & 0x3fff7c00) == 0x085f7c00 && (prev >> 30) == size
                                && (int)((prev >> 5) & 0x1f) == rn)
                                ld_rt = prev & 0x1f;                       /* LDXR / LDAXR */
                        }
                        if (ld_rt >= 0 && ld_rt != 31)
                        {
                            for (k = k - 2; k >= 1 && !clobbered; k--)  /* the instructions between */
                            {
                                if (!ios_fault_read_insn( (uint64_t)(uintptr_t)fault_pc - 4u * k, &prev )) { clobbered = 1; break; }
                                if ((int)(prev & 0x1f) != ld_rt) continue;
                                if ((prev & 0x7e000000) == 0x34000000          /* CBZ / CBNZ */
                                    || (prev & 0x7e000000) == 0x36000000       /* TBZ / TBNZ */
                                    || (prev & 0xff000010) == 0x54000000)      /* B.cond */
                                    continue;
                                /* ADD/SUB(S) immediate, Rd == Rn == the loaded register, at the
                                 * load's width: sf op S 100010 sh imm12 Rn Rd */
                                if ((prev & 0x1f800000) == 0x11000000 && (int)((prev >> 5) & 0x1f) == ld_rt
                                    && (prev >> 31) == (size == 3))
                                {
                                    uint64_t imm = (prev >> 10) & 0xfff;
                                    if (prev & 0x400000) imm <<= 12;
                                    delta += (prev & 0x40000000) ? (uint64_t)0 - imm : imm;
                                    continue;
                                }
                                clobbered = 1;
                            }
                        }
                        if (ld_rt >= 0 && ld_rt != 31 && !clobbered && rw_addr && !(ea & ((1u << size) - 1))
                            && (uint64_t)fault_addr == ea)
                        {
                            const uint64_t expect = (state.__x[ld_rt] - delta) & mask, val = IOS_STORE_SRC(rt) & mask;
                            int ok = 0;
                            switch (size)
                            {
                            case 0: { uint8_t  e = (uint8_t)expect;  ok = __atomic_compare_exchange_n( (uint8_t  *)rw_addr, &e, (uint8_t)val,  0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ); break; }
                            case 1: { uint16_t e = (uint16_t)expect; ok = __atomic_compare_exchange_n( (uint16_t *)rw_addr, &e, (uint16_t)val, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ); break; }
                            case 2: { uint32_t e = (uint32_t)expect; ok = __atomic_compare_exchange_n( (uint32_t *)rw_addr, &e, (uint32_t)val, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ); break; }
                            default:{ uint64_t e = expect;           ok = __atomic_compare_exchange_n( (uint64_t *)rw_addr, &e, val,           0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ); break; }
                            }
                            if (rs != 31) state.__x[rs] = ok ? 0 : 1;
                            emulated = 1;
                        }
                        {
                            static int excl_n;
                            if (excl_n < 8)
                                dprintf(STDERR_FILENO,
                                    "[excl-store] ml1284 #%d insn=0x%08x size=%u ea=0x%llx load-reg=%d delta=%lld%s %s\n",
                                    ++excl_n, insn, 1u << size, (unsigned long long)ea, ld_rt,
                                    (long long)delta, clobbered ? " (overwritten)" : "",
                                    emulated ? (rs != 31 && state.__x[rs] ? "emulated: value changed, retry" : "emulated")
                                             : "REFUSED: no matching LDXR/LDAXR");
                        }
                    }


                    /* iOS-Madeira ml626: SWP{A}{L}{B,H} — ATOMIC SWAP.
                     *
                     * Encoding (atomic memory operation, o3=1 opc=000):
                     *   size(2) 111 V=0 00 A R 1 Rs(5) o3=1 opc(3)=000 00 Rn(5) Rt(5)
                     *   mask 0x3F20FC00, value 0x38208000
                     * Semantics: old = mem[Rn]; mem[Rn] = Rs; Rt = old.
                     *
                     * ULTRAKILL/Mono reached this as `SWPAL X26, X26, [X6]`
                     * (insn 0xf8fa80da) writing into its own JIT code buffer. The alias
                     * resolved correctly (the ml350 discriminator said so) but there was
                     * no decode, so the write never completed and the ml461 guard counted
                     * 2,000 identical redeliveries before terminating the process.
                     *
                     * ⚠️ THIS MUST BE GENUINELY ATOMIC. FEX emits SWPAL precisely to
                     * preserve an x86 LOCK XCHG; a read-then-write here would silently
                     * drop that guarantee — the same defect already on record against the
                     * #71 unaligned-atomic emulator. __ATOMIC_SEQ_CST is STRONGER than
                     * SWPAL's acquire-release, which is safe rather than wrong. The RW
                     * alias maps the SAME physical pages as the faulting RX view, so the
                     * atomic applies to the memory the guest actually shares.
                     *
                     * Not extended to LDADD/LDCLR/LDSET/CAS here: in this run those came
                     * only AFTER the mishandled SWPAL, inside FEX's exception path, as
                     * fallout. They have since appeared on their own (a JVM's LDADDAL on
                     * anonymous RWX memory) and have their own case below. */
                    else if ((insn & 0x3F20FC00) == 0x38208000)
                    {
                        int size_lg2 = (insn >> 30) & 0x3;
                        int rs = (insn >> 16) & 0x1f;   /* value to store  */
                        int rt = insn & 0x1f;           /* old value lands here */
                        uint64_t align_mask = (1ULL << size_lg2) - 1;

                        /* An unaligned atomic cannot be emulated atomically. Fall through
                         * to the discriminator rather than quietly doing something weaker. */
                        if (rw_addr & align_mask)
                        {
                            static int swp_unalign_n;
                            if (swp_unalign_n < 4)
                                dprintf(STDERR_FILENO,
                                    "[swp-emul] ml626 #%d REFUSING unaligned atomic: insn=0x%08x size=%d "
                                    "addr=0x%llx rw=0x%llx\n",
                                    ++swp_unalign_n, insn, 1 << size_lg2,
                                    (unsigned long long)fault_addr, (unsigned long long)rw_addr);
                        }
                        else
                        {
                            uint64_t in = (rs == 31) ? 0 : state.__x[rs];
                            uint64_t old;
                            switch (size_lg2)
                            {
                            case 0:  old = __atomic_exchange_n((uint8_t  *)rw_addr, (uint8_t )in, __ATOMIC_SEQ_CST); break;
                            case 1:  old = __atomic_exchange_n((uint16_t *)rw_addr, (uint16_t)in, __ATOMIC_SEQ_CST); break;
                            case 2:  old = __atomic_exchange_n((uint32_t *)rw_addr, (uint32_t)in, __ATOMIC_SEQ_CST); break;
                            default: old = __atomic_exchange_n((uint64_t *)rw_addr,           in, __ATOMIC_SEQ_CST); break;
                            }
                            if (rt != 31) state.__x[rt] = old;  /* XZR discards the result */
                            emulated = 1;

                            /* ml648: THIS is Mono's backpatcher, and this is the fault
                             * FEX has never been allowed to see.
                             *
                             * On Windows the write traps, HandleRWXAccessViolation runs,
                             * DetectMonoBackpatcherBlock recognises the XCHG and recompiles
                             * the block so the store becomes a direct MonoBackpatcherWrite
                             * call — no fault at all. On iOS we emulate here first, so that
                             * optimisation has never once fired: [mono-cfg] says HOOKS
                             * ARMED yet "Detected mono backpatcher" appears zero times,
                             * and the bill is 40,639 exceptions/sec mean, 88,064 peak.
                             *
                             * Record RAW FACTS ONLY. No guest-RIP reconstruction, no opcode
                             * decode, no allocation, no formatting, no locks, and above all
                             * no call into ARM64EC code (ml613 crashed every launch doing
                             * that). x28 is FEX's state frame, x18 the TEB; both are just
                             * numbers here and are treated as untrusted. Everything is
                             * interpreted later at the FEX safe point. */
                            if (size_lg2 == 3)
                                ios_mono_bridge_capture( state.__x[18], state.__x[28],
                                                         (uint64_t)state.__pc,
                                                         (uint64_t)fault_addr );
                            {
                                static int swp_n;
                                if (swp_n < 8)
                                    dprintf(STDERR_FILENO,
                                        "[swp-emul] ml626 #%d insn=0x%08x size=%d Rs=x%d Rt=x%d addr=0x%llx "
                                        "rw=0x%llx in=0x%llx old=0x%llx\n",
                                        ++swp_n, insn, 1 << size_lg2, rs, rt,
                                        (unsigned long long)fault_addr, (unsigned long long)rw_addr,
                                        (unsigned long long)in, (unsigned long long)old);
                            }
                        }
                    }
                    /* LD<OP> and CAS, the other read-modify-write atomics. FEX lowers a guest
                     * LOCK ADD/SUB/XADD/INC/DEC to LDADDAL, LOCK AND to LDCLRAL, LOCK OR to
                     * LDSETAL, LOCK XOR to LDEORAL and LOCK CMPXCHG to CASAL. A bundled JVM
                     * ran LDADDAL W6, W0, [X1] (0xb8e60020) on anonymous RWX memory; with no
                     * case here the add never happened and the fault went back to the guest.
                     * ios_mach_emulate_rmw does each as one atomic on the RW alias, in every
                     * size and ordering, x29/x30 included. CAS only off the pool: FEX's own
                     * CASAL on the pool keeps the block below. Misaligned is refused, as for
                     * SWP. */
                    else if ((insn & 0x3f20cc00u) == 0x38200000u ||               /* LD<OP> */
                             (!in_jit && (insn & 0x3fa07c00u) == 0x08a07c00u))     /* CAS */
                    {
                        uint64_t gpr[32];

                        memcpy( gpr, state.__x, sizeof(state.__x) );
                        gpr[29] = state.__fp;
                        gpr[30] = state.__lr;
                        gpr[31] = state.__sp;
                        if (ios_mach_emulate_rmw( insn, rw_addr, gpr ))
                        {
                            memcpy( state.__x, gpr, sizeof(state.__x) );
                            state.__fp = gpr[29];
                            state.__lr = gpr[30];
                            emulated = 1;
                        }
                        {
                            static int rmw_n;
                            if (rmw_n < 8)
                                dprintf(STDERR_FILENO,
                                    "[mach-rmw] #%d insn=0x%08x pc=0x%llx addr=0x%llx rw=0x%llx %s\n",
                                    ++rmw_n, insn, (unsigned long long)fault_pc,
                                    (unsigned long long)fault_addr, (unsigned long long)rw_addr,
                                    emulated ? "emulated" : "REFUSED: misaligned");
                        }
                    }
                    /* FEX's native backpatch lock uses CASAL on the pool RX
                     * view. Handle it before Mach-to-guest delivery; otherwise
                     * a host-runtime fault escapes into the guest's VEH.
                     * Deliberately limited to full-width accesses within the
                     * existing pool alias; no new mapping or permission grant. */
                    if (!emulated && in_jit &&
                        (insn & 0xbfa07c00u) == 0x88a07c00u)
                    {
                        unsigned cas_width = (insn & 0x40000000u) ? 8 : 4;
                        /* madeira-bcd pool-low: within region C for a lock word there */
                        int cas_inside = in_low
                            ? ios_jit_low_size_global >= cas_width &&
                              fault_addr - ios_jit_low_rx_global <= ios_jit_low_size_global - cas_width
                            : sz >= cas_width && fault_addr - rx <= sz - cas_width;
                        if (cas_inside &&
                            ios_mach_emulate_cas(insn, rw_addr, state.__x))
                        {
                            static unsigned cas_mach_logs;
                            emulated = 1;
                            if (cas_mach_logs++ < 16)
                                dprintf(STDERR_FILENO,
                                        "[mach-cas] insn=%08x pc=%llx addr=%llx rw=%llx width=%u\n",
                                        insn, (unsigned long long)fault_pc,
                                        (unsigned long long)fault_addr,
                                        (unsigned long long)rw_addr, cas_width);
                        }
                    }
                    /* The host FAR can identify the first byte even when a
                     * later guest page blocks a spanning store. Dispatch the
                     * blocked page, leaving PC, registers and all bytes intact,
                     * so FEX invalidates that page before the next retry. */
                    if (!emulated && (insn & 0xbfa07c00u) == 0x08207c00u)
                    {
                        unsigned rn = (insn >> 5) & 31;
                        unsigned casp_width = (insn & 0x40000000u) ? 16 : 8;
                        uint64_t base = rn == 31 ? state.__sp : rn == 30 ? state.__lr :
                                        rn == 29 ? state.__fp : state.__x[rn];
                        uintptr_t casp_rw = ios_write_alias( (uintptr_t)base );
                        if (fault_addr >= base && fault_addr - base < casp_width &&
                            casp_rw && ios_write_alias( (uintptr_t)base + casp_width - 1 ) ==
                                       casp_rw + casp_width - 1 &&
                            !(honor_guest_prot && ios_alias_write_is_trapped( (uintptr_t)base )) &&
                            ios_mach_emulate_casp( insn, casp_rw, state.__x ))
                        {
                            static unsigned casp_mach_logs;
                            emulated = 1;
                            if (casp_mach_logs++ < 16)
                                dprintf( STDERR_FILENO, "[mach-casp] insn=%08x pc=%llx addr=%llx rw=%llx\n",
                                         insn, (unsigned long long)fault_pc,
                                         (unsigned long long)base, (unsigned long long)casp_rw );
                        }
                    }
                    if (!emulated && alias_fault && honor_guest_prot)
                    {
                        fault_addr = alias_fault;
                        goto dispatch_guest_fault;
                    }
                    /* ml350 DISCRIMINATOR: alias EXISTS but the instruction is not
                     * in this decode list — every such miss previously cost a full
                     * run to name (ml349's STRB-reg took one). Print the insn so
                     * the next gap is a one-line diagnosis. Capped. */
                    if (!emulated)
                    {
                        static int undecoded_n;
                        if (undecoded_n < 8)
                            dprintf(STDERR_FILENO,
                                "[store-undecoded] #%d rev=ml350 insn=0x%08x pc=0x%llx addr=0x%llx "
                                "rw_addr=0x%llx — alias OK, ADD THIS ENCODING to the case-4 emulator\n",
                                ++undecoded_n, insn, (unsigned long long)fault_pc,
                                (unsigned long long)fault_addr, (unsigned long long)rw_addr);
                    }
                    if (emulated)
                    {
                        /* ml635: record that this alias page was written. FEX's cached
                         * translation is NOT invalidated here (the ARM64EC path would call
                         * HandleRWXAccessViolation); this counter is what proves whether a
                         * page was filled AFTER its translation was compiled. */
                        {
                            extern void ios_jit_anon_alias_note_write( unsigned long long );
                            ios_jit_anon_alias_note_write( (unsigned long long)fault_addr );

                            /* ================ ml691 PAGE-GRANULAR W^X ==========
                             *
                             * ml690 attributed 98% of ~8.7M emulated stores to
                             * ONE thread -- port 0x8d5b == wine tid 007c == the
                             * Book of the Dead MAIN thread, which also holds
                             * fexlock while it runs. Every one of those faults is
                             * a Mach round trip that suspends the frame-critical
                             * thread, serviced by a single handler running at 86%
                             * duty. That is the largest measured cost in the app.
                             *
                             * WHY THIS IS SAFER THAN IT LOOKS: the ml635 comment
                             * in this file records that this path "NEVER
                             * invalidates FEX's cached translation". So the fault
                             * buys no coherence TODAY -- it is pure cost. Letting
                             * the store land directly loses nothing we currently
                             * have.
                             *
                             * Mechanism: drop PROT_EXEC and add PROT_WRITE on the
                             * guest page. FEX never executes the guest page (it
                             * executes its own translated host code), so removing
                             * exec is inert for normal operation -- and if
                             * anything ever DOES execute there we take an exec
                             * fault and can promote back, which is the re-promote
                             * hook a NOEXEC fault could not otherwise give us.
                             *
                             * Demote only after a page has faulted repeatedly, so
                             * one-off writes never change page state. Disable at
                             * runtime with Documents/madeira-wx.txt containing 0. */
                            {
                                /* ml693: BACK TO 32. ml691 proved threshold 32 safe over
                                 * 192 demotions with zero re-promotions; ml692 changed the
                                 * table size AND dropped the threshold to 8 in one build and
                                 * crashed the main thread early (c0000005 reading
                                 * 0x7049f04be820, far outside the 512GB user VA). Because two
                                 * variables moved together the run cannot say which caused it,
                                 * so revert to the proven value and keep ONLY the table fix --
                                 * the table was the measured limiter, the threshold was not. */
                                /* ml694: EXACT ml691 shape -- 256-entry linear table,
                                 * threshold 32. This is the configuration that ran a full
                                 * session cleanly; the 32K hash is reverted, not resized. */
                                enum { WX_SLOTS = 256, WX_THRESHOLD = 32 };
                                static struct { unsigned long long page; unsigned n, done; } wx[WX_SLOTS];
                                static volatile unsigned wx_demoted, wx_failed, wx_full;
                                unsigned long long pg = (unsigned long long)fault_addr & ~0x3fffull;
                                extern int ios_wx_enabled( void );
                                int wi, victim = -1;

                                if (ios_wx_enabled())
                                {
                                    for (wi = 0; wi < WX_SLOTS; wi++)
                                    {
                                        if (wx[wi].page == pg) break;
                                        if (!wx[wi].page && victim < 0) victim = wi;
                                    }
                                    if (wi == WX_SLOTS)
                                    {
                                        if (victim < 0) { __sync_add_and_fetch( &wx_full, 1 ); goto wx_done; }
                                        wi = victim; wx[wi].page = pg; wx[wi].n = 0; wx[wi].done = 0;
                                    }
                                    if (!wx[wi].done && ++wx[wi].n >= WX_THRESHOLD)
                                    {
                                        int q, sticky = 0, slot = -1;
                                        wx[wi].done = 1;
                                        for (q = 0; q < IOS_WX_MAX; q++)
                                        {
                                            if (ios_wx_pages[q].page == pg)
                                            { sticky = ios_wx_pages[q].sticky; slot = q; break; }
                                            if (!ios_wx_pages[q].page && slot < 0) slot = q;
                                        }
                                        if (sticky) goto wx_done;      /* proven to hold code */
                                        if (mprotect( (void *)(uintptr_t)pg, 0x4000,
                                                      PROT_READ | PROT_WRITE ) == 0)
                                        {
                                            unsigned d = __sync_add_and_fetch( &wx_demoted, 1 );
                                            if (slot >= 0)
                                            { ios_wx_pages[slot].page = pg; ios_wx_pages[slot].demoted = 1; }
                                            if (d <= 4 || (d & 0x3f) == 0)
                                                dprintf(STDERR_FILENO,
                                                    "[wx] ml694 demoted=%u failed=%u table-full=%u "
                                                    "(latest 0x%llx)\n", d, wx_failed, wx_full, pg);
                                        }
                                        else
                                        {
                                            unsigned f = __sync_add_and_fetch( &wx_failed, 1 );
                                            if (f <= 4)
                                                dprintf(STDERR_FILENO,
                                                    "[wx] ml694 mprotect FAILED 0x%llx errno=%d\n", pg, errno);
                                        }
                                    }
                                }
wx_done: ;
                            }
                        }
                        /* Advance PC past the emulated instruction */
                        __darwin_arm_thread_state64_set_pc_fptr(state,
                            (void *)(uintptr_t)(fault_pc + 4));
                        handled = 1;
                        static volatile int emul_count = 0;
                        int ec = __sync_add_and_fetch(&emul_count, 1);

                        /* ============ ml680 WHAT DOES A FAULT ACTUALLY COST? ==
                         *
                         * I have twice asserted "37,000 Mach round trips/sec at
                         * ~20us each = most of a core" without ever measuring
                         * the round trip. If it is really 20us the storm is the
                         * frame rate; if it is 2us it costs ~7% of one core and
                         * the W^X rebuild would be aimed at the wrong target.
                         *
                         * ios_store_fault_t0 is stamped at handler ENTRY (see
                         * the exception entry point), so this covers the whole
                         * kernel->handler->emulate path, not just the store. */
                        {
                            extern volatile unsigned long long ios_store_fault_t0;
                            extern volatile unsigned long long ios_store_fault_ticks;
                            extern volatile unsigned long long ios_store_fault_n;
                            extern volatile unsigned long long ios_store_fault_dropped;
                            /* ml685: the ml680 version was WRONG and its late totals
                             * (6.1e12 ms) must not be used. t0 is a single plain
                             * global; when the store is emulated on a different
                             * thread than the one that stamped it, `now - t0` can
                             * UNDERFLOW an unsigned 64-bit and add ~2^64 ticks. One
                             * race poisons the accumulator permanently, which is why
                             * the early samples (~3.3us) were sane and everything
                             * after was garbage.
                             *
                             * Take the sample only when it is self-evidently valid,
                             * and drop implausible ones into a separate counter so a
                             * discarded sample is visible rather than silent. */
                            {
                                unsigned long long t0 = ios_store_fault_t0;
                                unsigned long long now = mach_absolute_time();
                                ios_store_fault_t0 = 0;
                                if (t0 && now > t0)
                                {
                                    unsigned long long dt = now - t0;
                                    /* 24M ticks ~= 1s at the 24MHz timebase: any
                                     * store taking longer than that is a stale
                                     * pairing, not a measurement. */
                                    if (dt < 24000000ull)
                                    {
                                        __sync_add_and_fetch(&ios_store_fault_ticks, dt);
                                        __sync_add_and_fetch(&ios_store_fault_n, 1);
                                    }
                                    else
                                        __sync_add_and_fetch(&ios_store_fault_dropped, 1);
                                }
                                else if (t0)
                                    __sync_add_and_fetch(&ios_store_fault_dropped, 1);
                            }
                        }

                        /* ============ ml678 FAULT CLASSIFIER ==================
                         *
                         * ml677 sampled 13,299 of 13.3M faults as LOG LINES and
                         * I then matched their instruction ENCODING against the
                         * spinning worker's block and declared them the same
                         * code. They are not: 0 of 13,299 fault pcs and 0 of
                         * 3,248 EXC_SAMPLE pcs fall inside that block. c89ffcc1
                         * is FEX's TSO lowering of an ordinary store and occurs
                         * all over translated code, so encoding proves nothing.
                         *
                         * Aggregate IN-PROBE by host pc instead -- real event
                         * counts, not sampled lines -- and carry the facts that
                         * identify the emitter: the block-granular guest RIP
                         * from FEX's ThreadState (x28+0x18, a plain load: NEVER
                         * call an EC export from a fault path, ml613), the
                         * target page, and how many distinct pages that pc hits
                         * (one page = a hot data structure, many = a memcpy-like
                         * sweep). */
                        {
                            enum { FC_SLOTS = 24 };
                            enum { FC_PAGESET = 64, FC_SAMPLES = 12 };
                            static struct {
                                unsigned long long pc, rip, page, page2;
                                unsigned long long hits; unsigned pages_seen;
                                unsigned long long lo, hi, prev, stride;
                                unsigned restarts, nset;
                                unsigned long long pset[FC_PAGESET];
                                unsigned nsmp;
                                struct { unsigned long long hits, rsp, rcx, rdx, r8, addr; } smp[FC_SAMPLES];
                            } fc[FC_SLOTS];
                            static volatile int fc_lock;
                            unsigned long long fpage = (unsigned long long)fault_addr & ~0x3fffull;
                            unsigned long long grip = 0;
                            /* x28 = FEX ThreadState; +0x18 = State.rip for this block */
                            if (state.__x[28] > 0x10000)
                            {
                                mach_vm_size_t g = 0;
                                if (mach_vm_read_overwrite(mach_task_self(),
                                        (mach_vm_address_t)(state.__x[28] + 0x18), 8,
                                        (mach_vm_address_t)&grip, &g) != KERN_SUCCESS || g != 8)
                                    grip = 0;
                            }
                            if (!__sync_lock_test_and_set(&fc_lock, 1))
                            {
                                int fi, victim = 0;
                                for (fi = 0; fi < FC_SLOTS; fi++)
                                {
                                    if (fc[fi].pc == (unsigned long long)fault_pc) break;
                                    if (!fc[fi].pc) { victim = fi; break; }
                                    if (fc[fi].hits < fc[victim].hits) victim = fi;
                                }
                                if (fi == FC_SLOTS) fi = victim;
                                if (fc[fi].pc != (unsigned long long)fault_pc)
                                {
                                    fc[fi].pc = (unsigned long long)fault_pc;
                                    fc[fi].rip = grip; fc[fi].page = fpage;
                                    fc[fi].page2 = 0; fc[fi].hits = 0; fc[fi].pages_seen = 1;
                                }
                                fc[fi].hits++;
                                if (fpage != fc[fi].page && fpage != fc[fi].page2)
                                { fc[fi].page2 = fpage; fc[fi].pages_seen++; }

                                /* ml725: IS THE DOMINANT SITE ONE BULK COPY, OR THE SAME
                                 * COPY RESTARTING FOREVER?
                                 *
                                 * One site produced ~43M of ~44M emulated stores. Whether
                                 * removing the per-store Mach fault is worth anything
                                 * depends entirely on which of those it is: a genuine
                                 * copy gets ~1000x faster, a retry livelock just spins
                                 * faster and the game still never renders.
                                 *
                                 * Two prior readings from this very probe were wrong and
                                 * must not be repeated. `rip` here is FEX's block-level
                                 * State.rip, NOT the faulting instruction -- it names the
                                 * surrounding block/call site only. And `pages_seen`
                                 * remembers just TWO pages, so alternating over three or
                                 * more inflates it without bound; the 7.6M it reported is
                                 * not a cardinality. The exact guest RIP is NOT
                                 * obtainable here: BTCpu64IosRipFromHostPC is an ARM64EC
                                 * PE export and calling it from this native handler is
                                 * what crashed every launch in ml613.
                                 *
                                 * So measure what IS available natively: the fault-address
                                 * sequence. Ascending with a fixed stride and a
                                 * monotonically rising span = a bulk copy. Addresses that
                                 * jump backwards to a previous low-water mark = restarts,
                                 * and the count says how many. A small saturating page set
                                 * gives a cardinality that is honest about its own limit.
                                 */
                                if (fc[fi].hits == 1) {
                                    fc[fi].lo = fc[fi].hi = (unsigned long long)fault_addr;
                                    fc[fi].prev = (unsigned long long)fault_addr;
                                    fc[fi].restarts = 0; fc[fi].stride = 0; fc[fi].nset = 0;
                                } else {
                                    unsigned long long a = (unsigned long long)fault_addr;
                                    if (a < fc[fi].lo) fc[fi].lo = a;
                                    if (a > fc[fi].hi) fc[fi].hi = a;
                                    if (a > fc[fi].prev) {
                                        unsigned long long d = a - fc[fi].prev;
                                        if (d <= 64 && (!fc[fi].stride || d == fc[fi].stride))
                                            fc[fi].stride = d;
                                    } else if (a + 0x10000 < fc[fi].prev) {
                                        fc[fi].restarts++;   /* big backward jump */
                                    }
                                    fc[fi].prev = a;
                                }
                                /* ml726: SAMPLE THE CALL FRAME AND ARGUMENTS.
                                 *
                                 * ml725's `restarts` counter cannot answer the question it
                                 * was built for: it increments on ANY backward destination
                                 * jump over 64KiB, so sequential memcpys to unrelated
                                 * destinations inflate it exactly like a retry would. Its
                                 * value must NOT be divided by hits to infer a copy length
                                 * -- that denominator is backward jumps, not invocations.
                                 *
                                 * What separates "one slow copy", "the same copy retried"
                                 * and "many legitimate copies" is the call frame and the
                                 * arguments over time. Windows x64 puts memcpy's dst/src/len
                                 * in RCX/RDX/R8, and FEX's SRA keeps those in x0/x1/x2 with
                                 * RSP in x23 -- all readable here without touching FEX.
                                 *
                                 * A constant RSP with dst/len resetting to the same values
                                 * is a retry. A marching dst with RSP constant is one long
                                 * copy. Changing RSP with changing args is ordinary work
                                 * made slow by the fault cost -- and only in that last case
                                 * is optimising the store path the thing that reaches a
                                 * frame. Sampled sparsely so the fault path stays cheap. */
                                if ((fc[fi].hits % 250000ull) == 1 && fc[fi].nsmp < FC_SAMPLES) {
                                    unsigned si2 = fc[fi].nsmp++;
                                    fc[fi].smp[si2].hits = fc[fi].hits;
                                    fc[fi].smp[si2].rsp  = (unsigned long long)state.__x[23];
                                    fc[fi].smp[si2].rcx  = (unsigned long long)state.__x[0];
                                    fc[fi].smp[si2].rdx  = (unsigned long long)state.__x[1];
                                    fc[fi].smp[si2].r8   = (unsigned long long)state.__x[2];
                                    fc[fi].smp[si2].addr = (unsigned long long)fault_addr;
                                }

                                {   /* saturating distinct-page set, honest about its cap */
                                    unsigned pi; int seen = 0;
                                    for (pi = 0; pi < fc[fi].nset; pi++)
                                        if (fc[fi].pset[pi] == fpage) { seen = 1; break; }
                                    if (!seen && fc[fi].nset < FC_PAGESET) fc[fi].pset[fc[fi].nset++] = fpage;
                                }

                                /* ml690: attribute faults to the ORIGINATING thread.
                                 * The aggregate rate cannot say whether the main
                                 * thread is the one being stalled -- and that is
                                 * exactly what decides whether W^X moves the frame
                                 * rate or merely frees a core. */
                                {
                                    enum { FP_SLOTS = 24 };
                                    static struct { unsigned port; unsigned long long n; } fp[FP_SLOTS];
                                    unsigned pi;
                                    extern volatile unsigned int ios_cur_fault_port;
                                    for (pi = 0; pi < FP_SLOTS; pi++)
                                    {
                                        if (fp[pi].port == ios_cur_fault_port) { fp[pi].n++; break; }
                                        if (!fp[pi].port) { fp[pi].port = ios_cur_fault_port; fp[pi].n = 1; break; }
                                    }
                                    if ((ec % 400000) == 0)
                                    {
                                        unsigned q;
                                        dprintf(STDERR_FILENO, "[fault-by-thread] ml690 after %d stores:\n", ec);
                                        for (q = 0; q < FP_SLOTS; q++)
                                            if (fp[q].port)
                                                dprintf(STDERR_FILENO,
                                                    "[fault-by-thread]   port=0x%x faults=%llu (%llu%%)\n",
                                                    fp[q].port, fp[q].n,
                                                    (fp[q].n * 100ull) / (unsigned long long)ec);
                                    }
                                }
                                if ((ec % 200000) == 0)
                                {
                                    int k;
                                    dprintf(STDERR_FILENO,
                                        "[fault-class] ml678 ==== %d emulated stores so far ====\n", ec);
                                    for (k = 0; k < FC_SLOTS; k++)
                                    {
                                        if (!fc[k].hits) continue;
                                        dprintf(STDERR_FILENO,
                                                "[fault-class]   pc=0x%llx blockRIP=0x%llx hits=%llu "
                                                "page=0x%llx pages2slot=%u | ml725 span=[0x%llx..0x%llx] "
                                                "=%lluKB stride=%llu restarts=%u pages%s%u\n",
                                                fc[k].pc, fc[k].rip, fc[k].hits,
                                                fc[k].page, fc[k].pages_seen,
                                                fc[k].lo, fc[k].hi,
                                                (fc[k].hi >= fc[k].lo) ? (fc[k].hi - fc[k].lo) / 1024 : 0,
                                                fc[k].stride, fc[k].restarts,
                                                (fc[k].nset >= FC_PAGESET) ? ">=" : "=", fc[k].nset);
                                        if (fc[k].hits > 1000000ull) {
                                            unsigned sj;
                                            for (sj = 0; sj < fc[k].nsmp; sj++)
                                                dprintf(STDERR_FILENO,
                                                    "[fault-args] ml726 pc=0x%llx @%lluk rsp=0x%llx "
                                                    "rcx/dst=0x%llx rdx/src=0x%llx r8/len=0x%llx addr=0x%llx\n",
                                                    fc[k].pc, fc[k].smp[sj].hits / 1000ull,
                                                    fc[k].smp[sj].rsp, fc[k].smp[sj].rcx,
                                                    fc[k].smp[sj].rdx, fc[k].smp[sj].r8,
                                                    fc[k].smp[sj].addr);
                                        }
                                    }
                                }
                                __sync_lock_release(&fc_lock);
                            }
                        }
                        if (madeira_diag_enabled && (ec <= 5 || (ec % 1000) == 0))
                        {   /* ml649: the readback below touches both aliases */
                            /* Verify dual-map sharing: read back via the RX
                             * (original) address and compare to what we wrote
                             * via RW. If they match, the dual-map is working
                             * end-to-end. */
                            uint64_t rw_val = *(uint64_t *)rw_addr;
                            uint64_t rx_val = *(uint64_t *)fault_addr;
                            dprintf(STDERR_FILENO,
                                "[mach_exc] EMULATED STR #%d pc=%p insn=%08x rx=%p→rw=%p"
                                " | dual-map readback rx=%llx rw=%llx %s\n",
                                ec, (void*)(uintptr_t)fault_pc, insn,
                                (void*)fault_addr, (void*)rw_addr,
                                (unsigned long long)rx_val,
                                (unsigned long long)rw_val,
                                (rx_val == rw_val) ? "OK" : "MISMATCH");
                        }
                    }
                }
            }

            /* iOS-Madeira RECLAIM RECOVERY (FEX-2607 Thumper): a page that Wine/FEX
             * consider committed can be reclaimed by iOS under memory pressure —
             * 2607's per-thread 96MB LookupCaches push the app over the jetsam
             * limit, so committed L1/L2/code pages get dropped and the re-access
             * faults with no other handler -> terminate. Force the page back with
             * mprotect(RW); it returns zero-filled, which is functionally correct
             * for FEX's caches (a zero L1/L2 slot reads as "empty" -> FEX
             * recompiles). Gated to the FEX host-arena band (~0x7Cxx..0x80xx) so
             * it can't mask guest/dyld/null-deref faults, with a per-page repeat
             * guard (ios_guard_slot: exact page, not a shared hash slot) so an
             * ineffective mprotect can't spin forever. */
            {
                uint64_t fa = (uint64_t)fault_addr;
                uint64_t fault_pc = (uint64_t)__darwin_arm_thread_state64_get_pc(state);

                /* task #34 (ml74): EXECUTE fault on a code page — the RW grant
                 * below can never fix it (observed: retry#1..51 on
                 * 0x7ecaf00000, RW mprotect "succeeds", same fault forever;
                 * and the fatal walk in the pool RX view at 0x125115ce0 whose
                 * page had become prot=RW max_prot=RW). Handle code ranges
                 * FIRST: try to restore R|X — works when the pool/copy
                 * mapping is intact and only lost its protection. If mprotect
                 * RX fails, max_prot lost X = the mapping was REPLACED (see
                 * [jit-tripwire] in virtual_ios.c) — nothing in-handler can
                 * fix that; log the vm_region ground truth and fall through
                 * so the fault surfaces instead of spinning. */
                /* ml578: an EXC_BREAKPOINT must NEVER enter execute-recovery.
                 * The EXC_BREAKPOINT branch far above has no `continue`, so a
                 * guest int3 falls through to here — and a breakpoint's fault
                 * address EQUALS its pc, making `fa == fault_pc` trivially true.
                 * We then "recover" a page that was never faulting, resume, hit
                 * the same int3 and repeat: ONE deliberate Chromium abort
                 * (chrome_elf+0xD7D30, the BackupRefPtr refcount CHECK) became
                 * NINE identical breakpoints in ml577. The store-emulation path
                 * above is harmless only by luck — BRK (0xd4200020) matches no
                 * store pattern so it merely logs — but this one acts.
                 * Diagnosis by Sol. */
                if (!handled && fa == (uint64_t)fault_pc && req->exception != EXC_BREAKPOINT)
                {
                    extern void *ios_jit_rx_base_global;
                    extern size_t ios_jit_pool_size_global;
                    uint64_t rx = (uint64_t)(uintptr_t)ios_jit_rx_base_global;
                    int in_pool_rx = (rx && fa >= rx && fa < rx + ios_jit_pool_size_global) ||
                                     ios_jit_low_contains( (uintptr_t)fa );   /* madeira-bcd pool-low */
                    int in_band    = (fa >= 0x7C00000000ULL && fa < 0x8000000000ULL);

                    if (in_pool_rx || in_band)
                    {
                        enum { XR_PAGE = 0x4000 };
                        uint64_t pg = fa & ~(uint64_t)(XR_PAGE - 1);
                        /* Was 16 slots indexed by (pg >> 14) & 15: two pages 256 KB
                         * apart faulting in turn reset each other's count to 1,
                         * the 8-try limit never tripped and the read-touch below
                         * resumed both forever. Exact page now, 8 tries per page
                         * within IOS_GUARD_IDLE_MS of the previous one. */
                        static struct ios_guard_table xr_tab;
                        static uint32_t xr_n[IOS_GUARD_SLOTS];
                        int xr_fresh;
                        int s = ios_guard_slot( &xr_tab, pg, mach_absolute_time(), &xr_fresh );
                        int giveup = 0;
                        if (xr_fresh) xr_n[s] = 1;
                        else if (++xr_n[s] > 8) giveup = 1;
#ifndef MADV_FREE_REUSE
#define MADV_FREE_REUSE 8
#endif
                        if (!giveup)
                        {
                            /* Restore R|X. Works when the pool RX view / arm64ec
                             * pool-copy mapping is intact and only lost protection
                             * under reclaim. MADV_FREE_REUSE cancels any residual
                             * volatility so the page isn't immediately re-harvested. */
                            int mpr = mprotect( (void *)(uintptr_t)pg, XR_PAGE, PROT_READ | PROT_EXEC );
                            int errno_save = errno;
                            int reuse = madvise( (void *)(uintptr_t)pg, XR_PAGE, MADV_FREE_REUSE );
                            static volatile int xrc = 0;
                            int xrcn = __sync_fetch_and_add(&xrc, 1);
                            if (xrcn < 40 || (xrcn % 50) == 0)
                                dprintf(STDERR_FILENO,
                                    "[exec-recover] pg=0x%llx fault=0x%llx mprotect_rx=%d(errno=%d) reuse-cancel=%d retry#%u %s\n",
                                    (unsigned long long)pg, (unsigned long long)fa, mpr, errno_save,
                                    reuse, xr_n[s], in_pool_rx ? "pool-rx" : "band");
                            if (mpr == 0) handled = 1;
                            /* ml133: mprotect(RX) on debugger-blessed pool memory
                             * returns EACCES *unconditionally* — it is a platform
                             * rule (only StikDebug's original blessed mapping may
                             * be executable), NOT evidence that the mapping was
                             * replaced, and the comment below has been reading it
                             * that way for months. So recovery has never actually
                             * been attempted here.
                             *
                             * What we DO know (ml104 byte-compare): the faulting
                             * page is READABLE and its content is byte-identical
                             * to the on-disk DLL. So the mapping is intact and the
                             * page merely needs faulting back in. Force that from
                             * the kernel side with mach_vm_read_overwrite — a
                             * syscall, so it cannot itself fault this handler
                             * thread the way a user-space load could — then retry
                             * the instruction. If exec really is gone the retry
                             * re-faults and the giveup counter above (8 tries per
                             * page) surfaces it instead of spinning. */
                            else if (in_pool_rx)
                            {
                                uint64_t probe[2] = { 0, 0 };
                                mach_vm_size_t got = 0;
                                kern_return_t kr = mach_vm_read_overwrite(
                                        mach_task_self(), (mach_vm_address_t)pg, sizeof(probe),
                                        (mach_vm_address_t)&probe, &got );
                                if (kr == KERN_SUCCESS && got == sizeof(probe))
                                {
                                    sys_icache_invalidate( (void *)(uintptr_t)pg, XR_PAGE );
                                    handled = 1;
                                }
                                if (xrcn < 40 || (xrcn % 50) == 0)
                                    dprintf(STDERR_FILENO,
                                        "[exec-recover] pg=0x%llx read-touch kr=%d got=%llu word0=0x%llx -> %s\n",
                                        (unsigned long long)pg, (int)kr,
                                        (unsigned long long)got, (unsigned long long)probe[0],
                                        handled ? "RETRY" : "surface");
                            }
                            /* else: mprotect RX failed => max_prot lost EXECUTE =>
                             * the code page was REPLACED by a plain RW mapping
                             * ([jit-tripwire] names the culprit). Nothing here can
                             * re-add X; leave handled=0 and fall through to the
                             * unhandled path, which dumps vm_region ground truth
                             * and surfaces the fault instead of spinning forever. */
                        }
                    }
                }

                /* DATA fault reclaim recovery in the FEX host-arena band
                 * (FEX-2607 Thumper path): a page Wine/FEX consider committed
                 * gets reclaimed under memory pressure — 2607's per-thread 96MB
                 * LookupCaches push over the jetsam limit, so L1/L2/cache pages
                 * are dropped and the re-access faults with no other handler.
                 * Force the page back with mprotect(RW); zero-filled is correct
                 * for FEX's caches (a zero L1/L2 slot reads "empty" -> recompile).
                 * Gated to the host-arena band AND to non-execute faults so it
                 * can't shadow the R|X path above or mask guest/null-deref faults.
                 * Task #22: cap was >4 — Steam's download pressure re-harvested
                 * the same still-volatile page 5+ times; MADV_FREE_REUSE makes
                 * recovery permanent, the higher cap is a belt for residual
                 * volatility. */
                /* Correctness guard, NOT a fix for anything observed: this band
                 * ([496G,512G)) must never claim the JIT pool's own RW alias,
                 * because pool writes have their own STR-emulation path and this
                 * one "recovers" by mapping fresh ZERO pages. It is a no-op at
                 * the default alias placement (0x7000000000 is outside the
                 * band) and exists so a future relocation can't silently couple
                 * to this handler.
                 * HONEST NOTE: this was added on the theory that the band was
                 * why relocating the alias into it caused exec faults. It was
                 * NOT — ml98 kept the exclusion, kept the alias at
                 * 0x7c00000000, and still took 16 faults (ml97 also 16). The
                 * real coupling is still unidentified; do not cite this as the
                 * explanation. */
                {
                    extern void *ios_jit_rw_base_global;
                    extern size_t ios_jit_pool_size_global;
                    uintptr_t rwb = (uintptr_t)ios_jit_rw_base_global;
                    if (rwb && ios_jit_pool_size_global &&
                        ((fa >= rwb && fa < rwb + ios_jit_pool_size_global) ||
                         ios_jit_low_rw_contains( (uintptr_t)fa )))   /* madeira-bcd pool-low */
                        goto skip_reclaim_band;
                }
                if (!handled && fa != (uint64_t)fault_pc &&
                    fa >= 0x7C00000000ULL && fa < 0x8000000000ULL)
                {
                    /* Same exact-page guard as exec-recover above (it was the
                     * same 16-slot (pg >> 14) & 15 table, with the same
                     * alternating-pages reset). */
                    static struct ios_guard_table rr_tab;
                    static uint32_t rr_n[IOS_GUARD_SLOTS];
                    /* iOS uses 16KB host pages. NOTE: `host_page_size` in this
                     * file resolves to the Mach *function*, not a size — using
                     * it as a value gave a garbage mask (mprotect EINVAL). */
                    enum { RR_PAGE = 0x4000 };
                    uint64_t pg = fa & ~(uint64_t)(RR_PAGE - 1);
                    int rr_fresh;
                    int s = ios_guard_slot( &rr_tab, pg, mach_absolute_time(), &rr_fresh );
                    int giveup = 0;
                    if (rr_fresh) rr_n[s] = 1;
                    else if (++rr_n[s] > 64) giveup = 1;
                    if (!giveup)
                    {
                        /* ml95 (task #34): the "FEX host-arena band" assumption
                         * behind the zero-fill below is STALE. Wine's PE images
                         * now cluster in this same [496G,512G) band — ml95 took
                         * a fault on pg=0x7ed1be0000 (507.1G) which is a loaded
                         * MODULE BASE, and images were measured at 505.8G. For a
                         * FEX cache page a fresh zero page is correct (reads
                         * "empty" -> recompile); for a module it silently
                         * DESTROYS the code, and the thread then executes zeros
                         * or leaks a pool address into the guest RIP
                         * ([rip-leak] named exactly that module, rva 0x109835).
                         * Never zero-fill a page that belongs to a loaded image:
                         * restore protection if the mapping survives, otherwise
                         * surface the fault instead of corrupting it away. */
                        extern unsigned long long ios_jit_module_base_for_va( unsigned long long va,
                                                                              unsigned long long *size_out );
                        /* ml306 (task #53): capture Wine's committed-state BEFORE recovery mutates
                         * anything. This is THE discriminator for whether zero-fill is safe here:
                         *   VPROT_COMMITTED (0x20) set  -> page held live data; zeros = DATA LOSS or
                         *                                  a masked use-after-free. ml305's fatal
                         *                                  (null+0x90 through a pointer read from
                         *                                  this band, [reclaim-recover] firing
                         *                                  mid-exception) is the suspected result.
                         *   clear                       -> lazy-reservation first touch; zeros are
                         *                                  the contract and recovery is benign.
                         * Measurement only for now -- behaviour unchanged until at least one run
                         * says how the 2-4 events per run split. */
                        extern unsigned char ios_reclaim_page_vprot( unsigned long long va );
                        unsigned char pg_vprot = ios_reclaim_page_vprot( pg );
                        unsigned long long mod_size = 0;
                        unsigned long long mod_base = ios_jit_module_base_for_va( pg, &mod_size );
                        int mpr = mprotect( (void *)(uintptr_t)pg, RR_PAGE, PROT_READ | PROT_WRITE );
                        int errno_save = errno;
                        int used_mmap = 0;
                        if (mpr != 0 && !mod_base)  /* scratch page: fresh zeros ARE the contract */
                        {
                            void *r = mmap( (void *)(uintptr_t)pg, RR_PAGE, PROT_READ | PROT_WRITE,
                                            MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0 );
                            used_mmap = (r == (void *)(uintptr_t)pg);
                        }
                        else if (mpr != 0)
                        {
                            static volatile int mrc = 0;
                            if (__sync_fetch_and_add(&mrc, 1) < 24)
                                dprintf(STDERR_FILENO,
                                    "[reclaim-recover] REFUSED zero-fill of LOADED MODULE page pg=0x%llx module=0x%llx+0x%llx rva=0x%llx errno=%d — zeros would destroy code, surfacing fault\n",
                                    (unsigned long long)pg, mod_base, mod_size,
                                    (unsigned long long)(pg - mod_base), errno_save);
                        }
                        int reuse = madvise( (void *)(uintptr_t)pg, RR_PAGE, MADV_FREE_REUSE );
                        /* iOS-Madeira ml329 (#53 DISCRIMINATOR): remember every page we
                         * zero-fill, so a later crash can be tested against them instead
                         * of inferred.
                         *
                         * ml326+ml328 both died in FEXCore's IntrusivePooledAllocator
                         * (ClaimBufferImpl) reading a NULL `next` at offset 8 of a
                         * fextl::list node -- i.e. a list node full of zeros. Those nodes
                         * are aligned_alloc'd into FEX's jemalloc heap, which lives in the
                         * same [0x7c,0x80) band this recovery path re-mmaps. That makes
                         * "iOS reclaimed the page and we handed the allocator zeros" the
                         * leading hypothesis -- but the existing verdict string reads
                         * WINE's vprot, which is 0 for memory FEX allocated through its own
                         * VirtualAlloc2 path, so it prints "zeros OK" either way and cannot
                         * settle it. Record the pages; ios_reclaim_pages_report() prints
                         * them at the fatal SEGV so the two can be correlated directly. */
                        ios_reclaim_note_page( pg );
                        static volatile int rc = 0;
                        int rcn = __sync_fetch_and_add(&rc, 1);
                        if (rcn < 40 || (rcn % 50) == 0)
                            dprintf(STDERR_FILENO,
                                "[reclaim-recover] pg=0x%llx fault=0x%llx mprotect=%d(errno=%d) mmap=%d reuse-cancel=%d retry#%u vprot=0x%02x %s\n",
                                (unsigned long long)pg, (unsigned long long)fa, mpr, errno_save,
                                used_mmap, reuse, rr_n[s], pg_vprot,
                                (pg_vprot & 0x20) ? "WAS-COMMITTED(zeros=DATA-LOSS/UAF!)"
                                                  : "not-committed(lazy first touch, zeros OK)");
                        if (mpr == 0 || used_mmap) handled = 1;
                    }
                }
skip_reclaim_band: ;
            }

dispatch_guest_fault:
            /* madeira-bcd: a thread of an EXITED pseudo-process woke into its
             * reclaimed JIT copies; its ntdll copy is gone too, so guest SEH can
             * only re-fault until the ml461/ml465 terminal kills the whole app
             * (gta-2237: tid 014c, the thread-pool worker of the exited
             * "RockstarService.exe stop"). End that thread only -- never through
             * the exit wrappers, whose fds may belong to another thread by now. */
            if (!handled && thread_teb &&
                (req->exception == EXC_BAD_ACCESS || req->exception == EXC_BAD_INSTRUCTION))
            {
                extern int ios_peb_is_dead( const void *peb );
                void *zpeb = NULL;
                vm_size_t zsz = sizeof(zpeb);
                if (vm_read_overwrite( mach_task_self(), (vm_address_t)(thread_teb + offsetof(TEB, Peb)),
                                       sizeof(zpeb), (vm_address_t)&zpeb, &zsz ) == KERN_SUCCESS &&
                    zsz == sizeof(zpeb) && ios_peb_is_dead( zpeb ))
                {
                    static int zombie_n;
                    kern_return_t zkr = thread_terminate( thread );
                    if (zkr != KERN_SUCCESS) zkr = thread_suspend( thread );
                    if (zombie_n++ < 16)
                        dprintf( 2, "[zombie] teb=%p of exited peb=%p faulted pc=0x%llx addr=0x%llx -- "
                                    "ended this thread only (kr=%d)\n", (void *)thread_teb, zpeb,
                                 (unsigned long long)__darwin_arm_thread_state64_get_pc( state ),
                                 (unsigned long long)fault_addr, (int)zkr );
                    handled = 1;   /* thread_set_state on the ended thread below is harmless */
                }
            }

            /* ml369 (#63): last-resort in-process guest exception delivery.
             * Nothing above claimed the fault; declining it is a death
             * sentence under StikDebug (the stub cannot inject signals, so
             * wine's segv/bus/ill handlers are unreachable and the fault
             * spins at one pc until the script kills the app at 8 stops).
             * Deliver to the guest from here instead. d==2 means the page
             * machinery fixed it (guard/watch): resume with state as-is. */
            if (!handled && (req->exception == EXC_BAD_ACCESS ||
                             req->exception == EXC_BAD_INSTRUCTION))
            {
                if (ios_mach_deliver_guest_exception( thread, &state,
                        &neon_state, have_neon, req->exception,
                        fault_addr, thread_teb ))
                    handled = 1;
            }

            if (handled)
                thread_set_state( thread, ARM_THREAD_STATE64,
                                  (thread_state_t)&state, count );
            else
            {
                /* Rate-limit: log first 5 unhandled faults then every 100th */
                static volatile int unhandled_count = 0;
                int cnt = __sync_add_and_fetch(&unhandled_count, 1);
                /* iOS-Madeira: ALWAYS dump for "terminal-looking" faults
                 * — fault PC outside any plausible mapped region (low addr
                 * < 0x100000000 OR in dyld_shared_cache range 0x3xxxx00000+).
                 * Path-init memcpy faults happen at JIT-pool PCs and burn
                 * the cnt<=5 budget; without this terminal crashes were
                 * never dumped. */
                uint64_t fault_pc_check = (uint64_t)__darwin_arm_thread_state64_get_pc(state);
                int terminal_pc = (fault_pc_check < 0x100000000ULL ||
                                   (fault_pc_check >> 32) >= 0x300);
                /* iOS-Madeira 2026-05-15: compact per-fault line + first-seen
                 * guest RIP tracker. The Thumper fault loop has 13K+ UNHANDLED
                 * exceptions at JIT-pool PCs; the current cnt<=5 gate hides
                 * which guest function(s) the loop runs over. Capture State.RIP
                 * for every fault (cheap, ~80 bytes/line) so we can correlate
                 * fault PC ranges with guest RIPs offline. */
                {
                    uintptr_t teb_q = 0; void *tramp_q = NULL;
                    ios_lookup_thread(thread, &teb_q, &tramp_q);
                    void *fex_state_q = NULL;
                    if (teb_q)
                    {
                        void *cpuarea = *(void**)(teb_q + 0x1788);
                        if (cpuarea) fex_state_q = *(void**)((char*)cpuarea + 0x30);
                    }
                    uint64_t state_rip_q = fex_state_q ?
                        ((uint64_t*)fex_state_q)[0x18 / 8] : 0;
                    /* First-seen tracker: 32-slot hash by RIP. */
                    static volatile uint64_t seen_rip[32] = {0};
                    static volatile uint32_t seen_count[32] = {0};
                    int slot = (int)((state_rip_q >> 4) & 31);
                    int first_seen = 0;
                    if (seen_rip[slot] != state_rip_q)
                    {
                        /* Linear probe to find empty / matching slot */
                        int s;
                        for (s = 0; s < 32; s++)
                        {
                            int k = (slot + s) & 31;
                            if (seen_rip[k] == state_rip_q) { slot = k; break; }
                            if (seen_rip[k] == 0 &&
                                __sync_bool_compare_and_swap(&seen_rip[k], 0, state_rip_q))
                            { slot = k; first_seen = 1; break; }
                        }
                    }
                    __sync_add_and_fetch(&seen_count[slot], 1);

                    /* ml261 LIVELOCK BREAKER, keyed on the faulting PAGE.
                     *
                     * ml261 burned its whole run on 49,500+ faults at ONE address --
                     * previous runs peaked near 4,000. Signature:
                     *   insn f81f0ff3 = str x19,[sp,#-16]!   (a prologue push)
                     *   sp=0x73d16aff40, fault addr=0x73d16aff30  (16 bytes below sp)
                     *   [fault-rgn] page=0x73d16ac000 vprot prev/this/next=00/00/23
                     *   [fault-rgn] NO wine view -- Wine doesn't own this addr
                     * i.e. a stack growing into an UNCOMMITTED page (the page above IS
                     * committed) on a stack Wine does not own, so virtual_handle_fault
                     * declines, nothing commits it, and the access retries forever.
                     *
                     * The existing SEGV LOOP FATAL guard cannot catch this: it keys on
                     * the PC, and here two PCs alternate (0x13b5f2004 prologue and
                     * 0x1026b3188 memcpy) over the SAME page. Key on the page instead.
                     *
                     * This does NOT fix the missing commit -- it stops one page from
                     * eating an entire run, and dumps the region layout around it so the
                     * owner can be identified and the real fix aimed correctly. */
                    /* PER THREAD. The record used to be one global (page, pc, addr),
                     * so ANY other thread's unhandled fault in between reset it: two
                     * threads stuck in turn (or one stuck thread and another making
                     * progress elsewhere) never reached 50 and the run spun forever.
                     * Each thread now has its own record (ios_guard_slot, keyed by
                     * the thread port, not one of 16 slots chosen by a hash of it,
                     * where two threads stuck in turn still restarted each other's
                     * run); a record idle for IOS_GUARD_IDLE_MS starts over. An
                     * exception delivered to the thread also starts its run over
                     * (ios_note_guest_delivery); that count is kept per hashed slot
                     * (ios_guest_deliv_seq is also written from the faulting thread),
                     * so a delivery to another thread of that slot restarts it too. */
                    {
                        static struct ios_guard_table stk_tab;
                        static struct { uint64_t thread, page, pc, addr; uint32_t n, page_n; unsigned seq; } stk[IOS_GUARD_SLOTS];
                        int stk_fresh;
                        const int ss = ios_guard_slot( &stk_tab, (uint64_t)thread, mach_absolute_time(), &stk_fresh );
                        const unsigned dseq = __atomic_load_n( &ios_guest_deliv_seq[ios_fault_slot( (uint64_t)thread )],
                                                               __ATOMIC_ACQUIRE );
                        /* ml876: exact faulting ADDRESS, and a page-level storm
                         * counter. ml871-875 killed a UE 5.4 game thread here on
                         * every run: an SDK dll walked its import table with the
                         * classic VirtualProtect(entry,RW) / write / VirtualProtect
                         * (page,RO) pattern; on 16 KB host pages the RO of one 4 KB
                         * guest page strips W from the neighbour the guest had just
                         * made RW, [wr-strip] heals it and the thread advances to
                         * the NEXT entry -- a different address every time. Same
                         * (page,pc) 50x is therefore NOT "zero progress". Livelock
                         * = the SAME address re-faulting (ml261 sp-16 push, ml385
                         * NULL write, ml557 un-stuck heal); key on it. Keep a much
                         * larger page-level ceiling as the storm safety net. */
                        uint64_t fpage = (uint64_t)fault_addr & ~0x3fffull;
                        /* ml385: NULL-page faults keyed as 1, not 0 — `if (fpage &&`
                         * excluded them entirely and a NULL-write loop in
                         * server_ioctl_file ran 3.3M times with no breaker
                         * (StikDebug's 8-stop kill was the only breaker, and it
                         * had detached). */
                        if (!fpage) fpage = 1;

                        /* A record new to this thread, or an exception delivered to its
                         * delivery slot since its last fault, starts a new run (page 0 never
                         * matches, so the run is keyed again below). */
                        if (stk_fresh || stk[ss].thread != (uint64_t)thread || stk[ss].seq != dseq)
                        {
                            stk[ss].thread = (uint64_t)thread;
                            stk[ss].seq = dseq;
                            stk[ss].page = 0;
                        }

                        if (fpage == stk[ss].page && fault_pc_check == stk[ss].pc &&
                            (uint64_t)fault_addr != stk[ss].addr)
                        {
                            /* ml876: same page+pc but a NEW address = progress.
                             * Restart the exact-address count; keep the page
                             * storm count (ceiling 20000, logged every 1000). */
                            uint32_t pn = __sync_add_and_fetch(&stk[ss].page_n, 1);
                            stk[ss].addr = (uint64_t)fault_addr;
                            stk[ss].n = 0;
                            if ((pn % 1000) == 0)
                                dprintf(STDERR_FILENO,
                                    "[fault-stuck] ml876 page 0x%llx pc 0x%llx: %u faults, addresses advancing (last 0x%llx)\n",
                                    (unsigned long long)fpage, (unsigned long long)fault_pc_check, pn,
                                    (unsigned long long)fault_addr);
                            if (pn >= 20000) stk[ss].n = 49;   /* storm ceiling: next fault breaks */
                        }
                        /* The SAME address on the same page is no progress whichever
                         * pc takes it: ml261, the case this breaker was written for,
                         * alternated two pcs (prologue push, memcpy) over one stack
                         * address, and a (page, pc) match reset the count on every
                         * alternation, so it was never caught. */
                        if (fpage == stk[ss].page &&
                            (fault_pc_check == stk[ss].pc || (uint64_t)fault_addr == stk[ss].addr))
                        {
                            uint32_t n = __sync_add_and_fetch(&stk[ss].n, 1);
                            /* ml385 LOOP BREAKER: same page AND same pc (or the same
                             * address) 50 times with zero progress is a livelock, not a
                             * recoverable fault (guard/watch pages resolve in 1-3). Divert the
                             * thread to wine's abort_thread so the pseudo-process
                             * dies cleanly instead of eating the whole run. Native
                             * unix-code faults (dylib pc) can never be delivered
                             * to guest SEH anyway. */
                            if (n >= 50)
                            {
                                extern void abort_thread( int status );
                                uint64_t cur_sp = __darwin_arm_thread_state64_get_sp(state);
                                dprintf(STDERR_FILENO,
                                    "[fault-stuck] BREAKING LOOP: page 0x%llx pc 0x%llx repeated %u times "
                                    "-> diverting thread to abort_thread\n",
                                    (unsigned long long)fpage, (unsigned long long)fault_pc_check, n);
                                state.__x[0] = 1;
                                __darwin_arm_thread_state64_set_sp(state, cur_sp & ~0xfull);
                                __darwin_arm_thread_state64_set_pc_fptr(state, (void *)abort_thread);
                                thread_set_state( thread, ARM_THREAD_STATE64,
                                                  (thread_state_t)&state, count );
                                handled = 1;
                                stk[ss].n = 0;
                            }
                            /* ml369: was 2048, which NEVER fired — the
                             * debugger script kills the app after 8
                             * identical stops, so the region map has to
                             * print by the 6th fault to exist at all. */
                            /* ml1090: this map printed 426,000 times in one run (a
                             * thread re-faulting on a page the breaker below kept
                             * diverting), 3 million lines that were most of the
                             * run's memory growth. The first few say everything. */
                            static volatile uint32_t stuck_dumps;
                            if (n == 5 && __sync_add_and_fetch(&stuck_dumps, 1) <= 6)
                            {
                                mach_vm_address_t ra = (mach_vm_address_t)(fpage - 0x8000);
                                int i;
                                dprintf(STDERR_FILENO,
                                    "[fault-stuck] page 0x%llx faulted %u times with NO progress "
                                    "(pc=0x%llx sp=0x%llx) -- region map around it:\n",
                                    (unsigned long long)fpage, n,
                                    (unsigned long long)fault_pc_check,
                                    (unsigned long long)__darwin_arm_thread_state64_get_sp(state));
                                for (i = 0; i < 6; i++)
                                {
                                    mach_vm_size_t rs = 0;
                                    vm_region_basic_info_data_64_t rbi;
                                    mach_msg_type_number_t rc = VM_REGION_BASIC_INFO_COUNT_64;
                                    mach_port_t ro = MACH_PORT_NULL;
                                    mach_vm_address_t q = ra;
                                    if (mach_vm_region( mach_task_self(), &q, &rs,
                                                        VM_REGION_BASIC_INFO_64,
                                                        (vm_region_info_t)&rbi, &rc, &ro ) != KERN_SUCCESS)
                                    {
                                        dprintf(STDERR_FILENO,
                                            "[fault-stuck]   probe 0x%llx -> no region above\n",
                                            (unsigned long long)ra);
                                        break;
                                    }
                                    dprintf(STDERR_FILENO,
                                        "[fault-stuck]   region 0x%llx +0x%llx prot=%d/%d %s\n",
                                        (unsigned long long)q, (unsigned long long)rs,
                                        rbi.protection, rbi.max_protection,
                                        (q <= fpage && fpage < q + rs) ? "  <== FAULTING PAGE" : "");
                                    ra = q + rs;
                                }
                            }
                        }
                        else
                        {
                            stk[ss].page = fpage;
                            stk[ss].pc = fault_pc_check;
                            stk[ss].addr = (uint64_t)fault_addr;
                            stk[ss].n = 0;
                            stk[ss].page_n = 0;
                        }
                    }

                    if (cnt <= 50 || first_seen || (cnt % 500) == 0)
                    {
                        /* ml553: also report the FAULTING DATA ADDRESS and whether it is
                         * mapped at all. The login-window crash reconstructs to
                         * libcef+0x41258FB — the loop head of Chromium's frame clear
                         * (`movl %edx,(%r10)`) — so the question is whether that store's
                         * destination pointer is wild. This path DELIVERS the exception to
                         * the guest, so it never produces a [mach_exc] UNHANDLED record and
                         * the data address was the one thing never logged.
                         *
                         * Reads the region rather than trusting a flag: "unmapped" vs "mapped
                         * but wrong protection" point at completely different bugs (a bad
                         * pointer computation vs a protection race). */
                        {
                            mach_vm_address_t ra = (mach_vm_address_t)fault_addr;
                            mach_vm_size_t rs = 0;
                            vm_region_basic_info_data_64_t rbi;
                            mach_msg_type_number_t rc = VM_REGION_BASIC_INFO_COUNT_64;
                            mach_port_t ro = MACH_PORT_NULL;
                            int hp = -1;
                            unsigned long long rbase = 0, rsize = 0;
                            if (fault_addr &&
                                mach_vm_region( mach_task_self(), &ra, &rs, VM_REGION_BASIC_INFO_64,
                                                (vm_region_info_t)&rbi, &rc, &ro ) == KERN_SUCCESS)
                            { hp = rbi.protection; rbase = (unsigned long long)ra; rsize = (unsigned long long)rs; }
                            dprintf(STDERR_FILENO,
                                "[fault_rip] cnt=%d rip=0x%llx pc=0x%llx addr=0x%llx "
                                "kr=%llu(%s) entryprot=%d nowprot=%d region=0x%llx+0x%llx%s%s%s rev=ml555\n",
                                cnt, (unsigned long long)state_rip_q,
                                (unsigned long long)fault_pc_check,
                                (unsigned long long)fault_addr,
                                fault_kr,
                                fault_kr == 1 ? "INVALID_ADDRESS" :
                                fault_kr == 2 ? "PROTECTION_FAILURE" : "other",
                                entry_prot, hp, rbase, rsize,
                                entry_prot < 0 ? "  <== UNMAPPED AT ENTRY (wild pointer)" : "",
                                (entry_prot >= 0 && hp >= 0 && entry_prot != hp)
                                    ? "  <== PROT CHANGED MID-HANDLER (race)" : "",
                                first_seen ? " [first]" : "");
                        }
                    }
                    /* TEMP [rip-leak] task#34 ml64-class: guest RIP inside a
                     * JIT-POOL mapping means a pool-translated pointer leaked
                     * into guest control flow (guest must only ever see PE
                     * VAs; ml64 ran away executing dbghelp's pool ARM64 .text
                     * as x86). Name the module+RVA and dump the guest return
                     * stack so the SOURCE of the poisoned pointer is
                     * identifiable. Capped. STRIP BEFORE COMMIT. */
                    if (first_seen && state_rip_q)
                    {
                        extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
                        uint64_t mod_base = 0;
                        uint64_t pe = ios_jit_reverse_translate( state_rip_q, &mod_base );
                        static int leak_n;
                        if (pe && leak_n < 12)
                        {
                            uint64_t rsp = state.__x[23];  /* ARM64EC SRA: RSP=x23 */
                            uint64_t stk[8] = { 0 };
                            vm_size_t outsz = sizeof(stk);
                            leak_n++;
                            vm_read_overwrite( mach_task_self(), rsp, sizeof(stk),
                                               (vm_address_t)stk, &outsz );
                            dprintf(STDERR_FILENO,
                                "[rip-leak] guest RIP 0x%llx IS POOL addr = PE 0x%llx (module base 0x%llx rva 0x%llx)\n"
                                "[rip-leak] guest RSP=0x%llx stack: %llx %llx %llx %llx %llx %llx %llx %llx\n",
                                (unsigned long long)state_rip_q, (unsigned long long)pe,
                                (unsigned long long)mod_base,
                                (unsigned long long)(pe - mod_base),
                                (unsigned long long)rsp,
                                (unsigned long long)stk[0], (unsigned long long)stk[1],
                                (unsigned long long)stk[2], (unsigned long long)stk[3],
                                (unsigned long long)stk[4], (unsigned long long)stk[5],
                                (unsigned long long)stk[6], (unsigned long long)stk[7]);
                        }
                        /* task #34: reverse_translate returns 0 for a TOMBSTONED
                         * pool copy (owner cleared on unload/reclaim). That's the
                         * jsproxy-wall signature — the child pseudo-proc executing
                         * a pool copy its parent created and that's since been
                         * tombstoned. Name the owner directly so the parent/child
                         * ownership bug is unambiguous. */
                        if (!pe)
                        {
                            extern void *ios_jit_rx_base_global;
                            extern size_t ios_jit_pool_size_global;
                            extern void *ios_jit_pool_copy_owner(const void *addr, void **pe_base_out);
                            uint64_t rx = (uint64_t)(uintptr_t)ios_jit_rx_base_global;
                            if (rx && state_rip_q >= rx && state_rip_q < rx + ios_jit_pool_size_global)
                            {
                                void *tpe = NULL;
                                void *towner = ios_jit_pool_copy_owner( (void *)(uintptr_t)state_rip_q, &tpe );
                                dprintf(STDERR_FILENO,
                                    "[rip-tomb] guest RIP 0x%llx in POOL (off 0x%llx) but NO live mapping — copy_owner=%p pe=%p (tombstoned/foreign pool copy; cross-ref [jit-pool] image name)\n",
                                    (unsigned long long)state_rip_q,
                                    (unsigned long long)(state_rip_q - rx),
                                    towner, tpe);
                            }
                        }
                    }
                }
                /* ml125: a runaway exec-fault storm hit 7.26 MILLION faults;
                 * at one line per 100 that alone wrote 72k lines and a 314k-line
                 * log, which costs device I/O and buries everything useful.
                 * After the first 200 reports the rate drops to 1-in-100000 —
                 * still enough to prove a storm is running and show where it
                 * ends, without the flood. terminal_pc always reports. */
                if (cnt <= 5 || terminal_pc ||
                    (cnt <= 20000 ? (cnt % 100) == 0 : (cnt % 100000) == 0))
                {
                    uint64_t fault_pc = fault_pc_check;
                    dprintf(STDERR_FILENO, "[mach_exc] UNHANDLED #%d pc=%p addr=%p x18=%p type=%d lr=%p sp=%p x16=%p x17=%p\n",
                        cnt, (void*)(uintptr_t)fault_pc, (void*)fault_addr,
                        (void*)(uintptr_t)state.__x[18], req->exception,
                        (void*)(uintptr_t)state.__lr,
                        (void*)(uintptr_t)__darwin_arm_thread_state64_get_sp(state),
                        (void*)(uintptr_t)state.__x[16],
                        (void*)(uintptr_t)state.__x[17]);
                    /* ml254: 4797 of 4832 faults share ONE call site
                     * (libarm64ecfex+0x1e8060: adrp/ldr x8,[x8,#0x38]/ldr x16,[x8]/blr x16
                     * -- an indirect call through a pointer-to-pointer, i.e. an import
                     * slot) and ONE target, x16=0x155ffc138: pool offset 0x37ffc138, the
                     * LAST page of the pool, in the trampoline region above the `used`
                     * cursor. Control reaches tiny, ODD-aligned PCs (0x22d1, 0x22d5) --
                     * odd is why bus_handler reports exec=1 -- so the tramp RAN and then
                     * branched to garbage. The same high band held the earlier CASPAL
                     * use-after-free (0x1541af700, MEM_FREE).
                     *
                     * Three candidate causes need different fixes: (a) tramp bytes are
                     * zero/garbage -- it was never written or was overwritten; (b) tramp
                     * is intact but its embedded target is stale -- a lifetime bug;
                     * (c) the page is gone (MEM_FREE / reclaimed / non-exec) -- a mapping
                     * bug. Only the bytes plus the region info discriminate, so dump both.
                     * Self-targeting (tiny pc + x16 in pool) so a storm cannot flood it. */
                    {
                        extern void *ios_jit_rx_base_global;
                        extern size_t ios_jit_pool_size_global;
                        uint64_t x16v = (uint64_t)state.__x[16];
                        uint64_t rxb  = (uint64_t)(uintptr_t)ios_jit_rx_base_global;
                        static int tramp_dumps;
                        /* ml255/ml256: the ORIGINAL condition also required x16 to be a
                         * pool address, which was fitted to ml254's signature
                         * (x16=0x155ffc138) rather than to the invariant. Two runs later
                         * x16 was 0x0 / 0x4000 / 0x1fffffff and the probe correctly but
                         * uselessly declined. The invariant is the tiny bogus pc; x16 is
                         * the thing we are trying to LEARN about, so it must not gate. */
                        if (fault_pc < 0x10000 && tramp_dumps < 6)
                        {
                            mach_vm_address_t qa = (mach_vm_address_t)(x16v & ~0x3fffull);
                            mach_vm_size_t qs = 0;
                            vm_region_extended_info_data_t qi;
                            mach_msg_type_number_t qc = VM_REGION_EXTENDED_INFO_COUNT;
                            mach_port_t qo = MACH_PORT_NULL;
                            kern_return_t qkr;
                            /* extended info carries share_mode/user_tag but NOT
                             * max_protection; basic_64 carries max. Need both, and
                             * max is the one that says "can never be exec again". */
                            mach_vm_address_t ba = qa;
                            mach_vm_size_t bs = 0;
                            vm_region_basic_info_data_64_t bi;
                            mach_msg_type_number_t bc = VM_REGION_BASIC_INFO_COUNT_64;
                            mach_port_t bo = MACH_PORT_NULL;
                            int bmax = -1;

                            tramp_dumps++;
                            if (mach_vm_region( mach_task_self(), &ba, &bs,
                                                VM_REGION_BASIC_INFO_64,
                                                (vm_region_info_t)&bi, &bc, &bo ) == KERN_SUCCESS
                                && ba <= (x16v & ~0x3fffull))
                                bmax = bi.max_protection;
                            qkr = mach_vm_region( mach_task_self(), &qa, &qs,
                                                  VM_REGION_EXTENDED_INFO,
                                                  (vm_region_info_t)&qi, &qc, &qo );
                            if (qkr == KERN_SUCCESS && qa <= (x16v & ~0x3fffull))
                                dprintf(STDERR_FILENO,
                                    "[tramp-dump] x16=0x%llx pooloff=0x%llx REGION base=0x%llx size=0x%llx "
                                    "prot=0x%x max=0x%x share=%d tag=%d\n",
                                    (unsigned long long)x16v,
                                    (unsigned long long)(rxb ? x16v - rxb : 0),
                                    (unsigned long long)qa, (unsigned long long)qs,
                                    qi.protection, bmax,
                                    qi.share_mode, qi.user_tag);
                            else
                                dprintf(STDERR_FILENO,
                                    "[tramp-dump] x16=0x%llx pooloff=0x%llx REGION **NONE** (kr=%d, first region above = 0x%llx) "
                                    "-- page is NOT MAPPED\n",
                                    (unsigned long long)x16v,
                                    (unsigned long long)(rxb ? x16v - rxb : 0),
                                    qkr, (unsigned long long)qa);

                            /* the tramp's own words -- only if the page is readable */
                            if (qkr == KERN_SUCCESS && qa <= (x16v & ~0x3fffull) &&
                                (qi.protection & VM_PROT_READ))
                            {
                                const uint32_t *w = (const uint32_t *)(uintptr_t)x16v;
                                dprintf(STDERR_FILENO,
                                    "[tramp-dump]   words: %08x %08x %08x %08x %08x %08x\n",
                                    w[0], w[1], w[2], w[3], w[4], w[5]);
                            }
                        }
                    }
                    /* ml224: name the faulting address against the JIT-pool ledger.
                     *
                     * Steam/CEF dies on a 128-bit atomic whose target VirtualQuery
                     * reports MEM_FREE while sitting INSIDE the pool's span -- so the
                     * pointer is dangling, not misaligned, and pool lifetime is the
                     * suspect. Whether the range is on the reclaim freelist, still a live
                     * mapping, or neither picks between three different fixes, and this
                     * is the only place that can tell. Rate-limited with the dump it
                     * rides on, so a fault storm cannot flood the log. */
                    {
                        extern void ios_jit_describe_pool_addr( const void *addr, char *buf,
                                                                size_t buflen );
                        static int ledger_n;
                        char pooldesc[192];

                        /* ml225: riding the mach_exc limiter alone still produced 3790
                         * lines in one run, because a null-deref storm (addr=0x10/0xc/0x2)
                         * asks the ledger a question it can only answer "OUTSIDE pool".
                         * Only sub-pool-band addresses are interesting here, and cap the
                         * rest, so the interesting verdict cannot be buried. */
                        if (ledger_n < 40 && fault_addr >= 0x10000)
                        {
                            ledger_n++;
                            ios_jit_describe_pool_addr( (const void *)fault_addr, pooldesc,
                                                        sizeof(pooldesc) );
                            dprintf( STDERR_FILENO, "[mach_exc]   [pool-ledger] addr=%p : %s\n",
                                     (void *)fault_addr, pooldesc );
                        }
                    }
                    /* ml226: is the guest RSP TRUNCATED TO 32 BITS, or already garbage?
                     *
                     * The recurring fatal address family is 0x40001141 / 0x80001141 /
                     * 0xe0001141 -- all 32-bit values with identical low halves, reached
                     * through a guest PUSH (ldr x2,[x28,#0x40]; sub x2,x2,#0x10; str x0,[x2]).
                     * A 64-bit RSP does not look like that. One reading is an instruction
                     * writing RSP with 32-bit operand size (mov esp,eax semantics), which
                     * would be a FEX decode bug; the other is that RSP arrived corrupt from
                     * somewhere upstream, which is a different bug entirely.
                     *
                     * Decide it by dumping the guest state and the x86 bytes AT the guest
                     * RIP. If those bytes decode to a 32-bit write to RSP the first reading
                     * is confirmed; if they are an ordinary push/call then RSP was already
                     * wrong on entry and the truncation idea is dead. Prints the raw bytes
                     * rather than a verdict so it can say "neither". */
                    {
                        static int rsp_n;
                        uint64_t st28 = state.__x[28];
                        uint64_t cs[5];            /* +0x18 rip .. +0x38 */
                        uint64_t rsp = 0;
                        unsigned char code[16];
                        mach_vm_size_t g = 0;

                        if (rsp_n < 12 && st28 > 0x100000 &&
                            mach_vm_read_overwrite( mach_task_self(),
                                (mach_vm_address_t)(st28 + 0x18), sizeof(cs),
                                (mach_vm_address_t)cs, &g ) == KERN_SUCCESS && g == sizeof(cs) &&
                            mach_vm_read_overwrite( mach_task_self(),
                                (mach_vm_address_t)(st28 + 0x40), 8,
                                (mach_vm_address_t)&rsp, &g ) == KERN_SUCCESS)
                        {
                            rsp_n++;
                            dprintf( STDERR_FILENO,
                                     "[rsp-trunc] x28=%p guest_rip=%p rsp=%p rsp_hi32=%s\n",
                                     (void *)st28, (void *)cs[0], (void *)rsp,
                                     (rsp >> 32) ? "set (64-bit)" : "ZERO (looks truncated)" );
                            g = 0;
                            if (cs[0] && mach_vm_read_overwrite( mach_task_self(),
                                    (mach_vm_address_t)cs[0], sizeof(code),
                                    (mach_vm_address_t)code, &g ) == KERN_SUCCESS &&
                                g == sizeof(code))
                                dprintf( STDERR_FILENO,
                                         "[rsp-trunc]   x86 @rip: %02x %02x %02x %02x %02x %02x %02x %02x"
                                         " %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                         code[0],code[1],code[2],code[3],code[4],code[5],code[6],code[7],
                                         code[8],code[9],code[10],code[11],code[12],code[13],code[14],code[15] );
                            else
                                dprintf( STDERR_FILENO, "[rsp-trunc]   x86 @rip UNREADABLE\n" );

                            /* iOS-Madeira ml333: is the guest code we EXECUTE the guest code that was
                             * LOADED?
                             *
                             * ml332's fatal was c000001d with the bytes at guest RIP reading
                             * `cc 0f 0b` = int3; ud2 -- Chromium's IMMEDIATE_CRASH(). But the device's
                             * own libcef.dll has completely different bytes at that RVA (verified
                             * offline against the file pulled from the container; single libcef load,
                             * base confirmed). So in-memory guest code != on-disk guest code, and the
                             * three explanations need separating rather than guessing:
                             *   (a) the PE mapping is fine and only the POOL COPY we execute is wrong
                             *       -- a mapping/copy bug on our side,
                             *   (b) both differ from the file -- something overwrote guest code,
                             *   (c) the RIP is bogus and neither is meaningful.
                             * Print the same 16 bytes from the pool copy next to the PE mapping. If
                             * they differ, it is (a); if they agree but both differ from the file,
                             * it is (b). Either answer names the bug; silence is impossible because
                             * the translate result is printed even when it is an identity. */
                            {
                                extern void *ios_jit_translate_addr( void *addr );
                                unsigned char pcode[16];
                                void *pool_rip = ios_jit_translate_addr( (void *)cs[0] );

                                g = 0;
                                if (pool_rip && pool_rip != (void *)cs[0] &&
                                    mach_vm_read_overwrite( mach_task_self(),
                                        (mach_vm_address_t)pool_rip, sizeof(pcode),
                                        (mach_vm_address_t)pcode, &g ) == KERN_SUCCESS &&
                                    g == sizeof(pcode))
                                    dprintf( STDERR_FILENO,
                                             "[guest-code] rev=ml333 pool_rip=%p (PE %p): "
                                             "%02x %02x %02x %02x %02x %02x %02x %02x"
                                             " %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                             pool_rip, (void *)cs[0],
                                             pcode[0],pcode[1],pcode[2],pcode[3],pcode[4],pcode[5],pcode[6],pcode[7],
                                             pcode[8],pcode[9],pcode[10],pcode[11],pcode[12],pcode[13],pcode[14],pcode[15] );
                                else
                                    dprintf( STDERR_FILENO,
                                             "[guest-code] rev=ml333 pool_rip=%p (PE %p) -- %s\n",
                                             pool_rip, (void *)cs[0],
                                             (!pool_rip || pool_rip == (void *)cs[0])
                                                 ? "NO pool copy for this address (identity translate)"
                                                 : "pool copy UNREADABLE" );
                            }
                        }
                    }
                    /* [ec-fault-regs] the faulting insn f8686928 = ldr x8,[x9,x8]:
                     * addr = x9(base) + x8(index). Dump x8..x11 so we can name the
                     * table (EC bitmap? syscall-frame? LookupCache?) and why it's bad. */
                    if (cnt <= 3)
                    {
                        void *peb_ecbm = NULL; void *peb_p = NULL;
                        if (thread_teb) {
                            peb_p = ((TEB *)thread_teb)->Peb;
                            /* PEB->EcCodeBitMap read DIRECTLY (same struct is_ec_code
                             * uses). If this != 0 but x9==0, is_ec_code read a wrong
                             * offset / wrong peb; if this == 0, the field is really null
                             * for this thread's peb (timing / peb not wired). */
                            if (peb_p) peb_ecbm = ((PEB *)peb_p)->EcCodeBitMap;
                        }
                        dprintf(STDERR_FILENO, "[ec-fault-regs] x8=%p x9=%p x10=%p x11=%p x0=%p x2=%p | teb=%p peb=%p peb->EcCodeBitMap=%p\n",
                            (void*)(uintptr_t)state.__x[8], (void*)(uintptr_t)state.__x[9],
                            (void*)(uintptr_t)state.__x[10], (void*)(uintptr_t)state.__x[11],
                            (void*)(uintptr_t)state.__x[0], (void*)(uintptr_t)state.__x[2],
                            (void *)thread_teb, peb_p, peb_ecbm);
                    }
                    /* madeira-bcd [fault-full]: every register, and the host code
                     * that led up to the faulting instruction (JIT blocks compute
                     * the address a few instructions earlier), for the first two
                     * unhandled faults. God of War on build 234 reads 0x40 through
                     * LDAPR x27,[x6] and the short insn_stream cannot say where x6
                     * came from. */
                    /* madeira-bcd [fault-tls]: the thread's TLS[0] block (the main
                     * image's thread-locals) next to the image's TLS template. God of
                     * War (build 236) takes its current allocator from TLS[0]+0xc
                     * (index) / +0xf0 (table) / +0x18 and finds none. */
                    if (cnt == 1 && thread_teb)
                    {
                        uint64_t tlsarr = 0, blk = 0, peb = 0, img = 0;
                        mach_vm_size_t g = 0;
                        #define FT_RD(a, v) (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(a), sizeof(v), \
                                             (mach_vm_address_t)&(v), &g) == KERN_SUCCESS && g == sizeof(v))
                        if (FT_RD(thread_teb + 0x58, tlsarr) && tlsarr && FT_RD(tlsarr, blk) && blk)
                        {
                            uint64_t q[40];
                            int i;
                            if (FT_RD(blk, q))
                                for (i = 0; i < 40; i += 4)
                                    dprintf(STDERR_FILENO, "[fault-tls] tls0 %llx+%#x: %016llx %016llx %016llx %016llx\n",
                                        (unsigned long long)blk, i * 8, (unsigned long long)q[i],
                                        (unsigned long long)q[i + 1], (unsigned long long)q[i + 2],
                                        (unsigned long long)q[i + 3]);
                        }
                        if (FT_RD(thread_teb + 0x60, peb) && peb && FT_RD(peb + 0x10, img) && img)
                        {
                            uint32_t lfanew = 0, tls_rva = 0;
                            uint64_t dir[6];
                            if (FT_RD(img + 0x3c, lfanew) && FT_RD(img + lfanew + 0xd0, tls_rva) && tls_rva
                                && FT_RD(img + tls_rva, dir))
                            {
                                uint64_t q[40];
                                uint32_t idx = 0;
                                int i;
                                (void)FT_RD(dir[2], idx);
                                dprintf(STDERR_FILENO, "[fault-tls] image %llx tls dir: raw %llx-%llx index@%llx=%u callbacks %llx zerofill %llu\n",
                                    (unsigned long long)img, (unsigned long long)dir[0], (unsigned long long)dir[1],
                                    (unsigned long long)dir[2], idx, (unsigned long long)dir[3],
                                    (unsigned long long)(dir[4] & 0xffffffffULL));
                                if (FT_RD(dir[0], q))
                                    for (i = 0; i < 40; i += 4)
                                        dprintf(STDERR_FILENO, "[fault-tls] template +%#x: %016llx %016llx %016llx %016llx\n",
                                            i * 8, (unsigned long long)q[i], (unsigned long long)q[i + 1],
                                            (unsigned long long)q[i + 2], (unsigned long long)q[i + 3]);
                            }
                        }
                        #undef FT_RD
                    }
                    if (cnt <= 2)
                    {
                        int r;
                        for (r = 0; r < 29; r += 4)
                            dprintf(STDERR_FILENO, "[fault-full] x%d=%llx x%d=%llx x%d=%llx x%d=%llx\n",
                                r, (unsigned long long)state.__x[r],
                                r + 1, (unsigned long long)(r + 1 < 29 ? state.__x[r + 1] : state.__fp),
                                r + 2, (unsigned long long)(r + 2 < 29 ? state.__x[r + 2] : state.__lr),
                                r + 3, (unsigned long long)(r + 3 < 29 ? state.__x[r + 3] : state.__sp));
                        if ((uintptr_t)fault_pc >= 0x100000000ULL + 256)
                        {
                            uint32_t hc[68];
                            mach_vm_size_t got = 0;
                            if (mach_vm_read_overwrite( mach_task_self(),
                                                        (mach_vm_address_t)((uintptr_t)fault_pc - 256),
                                                        sizeof(hc), (mach_vm_address_t)hc, &got ) == KERN_SUCCESS
                                && got == sizeof(hc))
                            {
                                int w;
                                for (w = 0; w < 68; w += 8)
                                    dprintf(STDERR_FILENO, "[fault-host] %llx: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                                        (unsigned long long)((uintptr_t)fault_pc - 256 + w * 4),
                                        hc[w], hc[w + 1], hc[w + 2], hc[w + 3],
                                        w + 4 < 68 ? hc[w + 4] : 0, w + 5 < 68 ? hc[w + 5] : 0,
                                        w + 6 < 68 ? hc[w + 6] : 0, w + 7 < 68 ? hc[w + 7] : 0);
                            }
                        }
                    }
                    /* Read instruction at LR-4 to identify the BL/BLR */
                    if (cnt <= 3 && (uintptr_t)state.__lr >= 0x100000000ULL)
                    {
                        uint32_t *lr_p = (uint32_t*)(uintptr_t)(state.__lr - 4);
                        dprintf(STDERR_FILENO, "[mach_exc] caller_insn @lr-4=0x%p: 0x%08x\n",
                            (void*)lr_p, *lr_p);
                    }
                    /* Which pool COPY is pc in, and who owns it? Names the
                     * session-vs-child copy — the PE attribution below can't
                     * (all copies share PE VAs). owner=-1 = not pool. */
                    {
                        extern void *ios_jit_pool_copy_owner(const void *addr, void **pe_base_out);
                        void *copy_pe = NULL;
                        void *copy_owner = ios_jit_pool_copy_owner((void *)(uintptr_t)fault_pc, &copy_pe);
                        void *cur_teb_peb = thread_teb ? ((TEB *)thread_teb)->Peb : NULL;
                        dprintf(STDERR_FILENO,
                            "[mach_exc] pc pool-copy pe=%p owner=%p; thread teb=%p peb=%p\n",
                            copy_pe, copy_owner, (void *)thread_teb, cur_teb_peb);
                        /* [nls-probe] The first fault is upcase_unicode_to_utf8 (ntdll RVA
                         * 0x38aa8) reading the NLS upcase-table pointer at ntdll .data RVA
                         * 0xc04e0 via `adrp x16,0xc0000; ldr x7,[x16,#0x4e0]` — and getting
                         * NULL. Compare the value the POOL copy read (x16+0x4e0) against the
                         * PE mapping's own .data (copy_pe+0xc04e0). If PE!=0 && pool==0 the
                         * pool copy's .data is stale (fix = sync/share ntdll .data); if both
                         * 0 the PE global was never populated (fix is upstream NLS init). */
                        if (cnt <= 2 && copy_pe && (uintptr_t)copy_pe >= 0x100000000ULL)
                        {
                            uint64_t x16v = (uint64_t)state.__x[16];
                            uint64_t pool_v = (x16v >= 0x100000000ULL)
                                ? *(volatile uint64_t *)(uintptr_t)(x16v + 0x4e0) : 0xdead1;
                            uint64_t pe_v = *(volatile uint64_t *)((uintptr_t)copy_pe + 0xc04e0);
                            dprintf(STDERR_FILENO,
                                "[nls-probe] upcase ptr: pool[x16+0x4e0]=0x%llx  PE[pe+0xc04e0]=0x%llx  (x16=0x%llx pe=%p rva_pc=0x%llx)\n",
                                (unsigned long long)pool_v, (unsigned long long)pe_v,
                                (unsigned long long)x16v, copy_pe,
                                (unsigned long long)((uintptr_t)fault_pc - ((uintptr_t)fault_pc & ~0xfffffULL)));
                        }
                    }
                    /* ml982: `fault_pc >= 0x100000000` only says the address is
                     * above the iOS floor -- it says nothing about whether the
                     * page is mapped or readable, and this is the reporter for a
                     * fault that is frequently an unmapped or non-executable PC.
                     * Copy through a checked read instead of dereferencing. */
                    if ((uintptr_t)fault_pc >= 0x100000000ULL + 12)
                    {
                        uint32_t ins[7];
                        mach_vm_size_t got = 0;
                        if (mach_vm_read_overwrite( mach_task_self(),
                                                    (mach_vm_address_t)((uintptr_t)fault_pc - 12),
                                                    sizeof(ins), (mach_vm_address_t)ins,
                                                    &got ) == KERN_SUCCESS && got == sizeof(ins))
                            dprintf(STDERR_FILENO, "[mach_exc] insn_stream PC-12..PC+8: %08x %08x %08x [%08x] %08x %08x %08x\n",
                                ins[0], ins[1], ins[2], ins[3], ins[4], ins[5], ins[6]);
                        else
                            dprintf(STDERR_FILENO, "[mach_exc] ml982 insn_stream at pc=%#llx <unreadable> (got=%llu)\n",
                                (unsigned long long)fault_pc, (unsigned long long)got);
                    }
                    /* iOS-Madeira: symbolize pc/lr via dladdr — works for
                     * dyld-cache addresses in-process. Names the native
                     * subsystem when a fault lands in system frameworks
                     * (e.g. the 2026-07-04 post-UNIXCALL-DIRECT crash at
                     * 0x18521c0d0 was unattributable offline: DeviceSupport
                     * symbol tree only has lazily-extracted dylibs). */
                    {
                        /* ml982: initialise these and KEEP the lookup result.
                         *
                         * They were uninitialised locals whose dladdr() return was
                         * used to guard immediate use but then discarded. The
                         * one-shot prologue dump further down then tested
                         * `di_pc.dli_saddr` on its own and dereferenced it raw --
                         * so a FAILED lookup left stack garbage in dli_saddr and the
                         * dump read through it.
                         *
                         * That is the wedge in rdr44-52. The fault is at
                         * 0x9a4c0829c, the bootstrap kernelbase VirtualAlloc entry
                         * thunk, which is not a dyld image, so dladdr fails and the
                         * log prints `pc=?`. The handler then faulted on its own
                         * diagnostic load -- sampled at
                         * ios_mach_exception_thread+0x6660, which disassembles to
                         * `ldp w8,w9,[x25]` with x25 loaded from Dl_info+0x18
                         * (dli_saddr). Because the shared exception port is
                         * installed at TASK level as well as per-thread, the only
                         * handler faulted while servicing a fault and waited on
                         * itself: both it and the faulting game thread then sit at
                         * unchanged PCs with zero CPU forever, and not one
                         * `[mach_exc] fn+` row is ever printed. */
                        Dl_info di_pc, di_lr;
                        int pc_named = 0, lr_named = 0;
                        const char *pc_img = "?", *pc_sym = "?"; uint64_t pc_off = 0;
                        const char *lr_img = "?", *lr_sym = "?"; uint64_t lr_off = 0;
                        memset( &di_pc, 0, sizeof(di_pc) );
                        memset( &di_lr, 0, sizeof(di_lr) );
                        if ((pc_named = (dladdr((void*)(uintptr_t)fault_pc, &di_pc) != 0)))
                        {
                            if (di_pc.dli_fname) pc_img = di_pc.dli_fname;
                            if (di_pc.dli_sname) { pc_sym = di_pc.dli_sname;
                                pc_off = fault_pc - (uint64_t)(uintptr_t)di_pc.dli_saddr; }
                        }
                        if ((lr_named = (dladdr((void*)(uintptr_t)state.__lr, &di_lr) != 0)))
                        {
                            if (di_lr.dli_fname) lr_img = di_lr.dli_fname;
                            if (di_lr.dli_sname) { lr_sym = di_lr.dli_sname;
                                lr_off = state.__lr - (uint64_t)(uintptr_t)di_lr.dli_saddr; }
                        }
                        dprintf(STDERR_FILENO,
                            "[mach_exc] sym pc=%s`%s+0x%llx lr=%s`%s+0x%llx\n",
                            pc_img, pc_sym, (unsigned long long)pc_off,
                            lr_img, lr_sym, (unsigned long long)lr_off);
                        /* JIT-pool addresses: name the PE module + offset
                         * (same machinery as [thread-stacks]) so faults in
                         * copied PE code self-symbolize. */
                        {
                            extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
                            uint64_t mod, va;
                            if ((va = ios_jit_reverse_translate( fault_pc, &mod )))
                                dprintf(STDERR_FILENO, "[mach_exc] pc PE: %s+0x%llx (va=0x%llx)\n",
                                        ios_pe_module_name(mod), (unsigned long long)(va - mod),
                                        (unsigned long long)va);
                            /* [bucketscan-probe] Thumper dies in FEXCore GuestToHostMap::BlockList
                             * (ankerl unordered_dense) do_find (libarm64ecfex ~RVA 0x1d140-0x1d280,
                             * caller LookupCache::FindBlock) scanning its bucket array OFF THE END:
                             * loop `add x17,x11,w12,uxtw#3; ldr w1,[x17]` => x11=buckets base,
                             * w12=index, x17=x11+w12*8 walks unmapped guest mem. Dump base/index/
                             * scan-distance/key (NO deref — stay signal-safe) to tell UNINITIALIZED
                             * (x11 garbage/tiny, no valid array) from TORN-READ (x11 a valid heap
                             * ptr but distance huge => bounds/mask stale from a concurrent swap). */
                            {
                                uint64_t bs_mod, bs_va;
                                if ((bs_va = ios_jit_reverse_translate( fault_pc, &bs_mod )))
                                {
                                    uint64_t bs_rva = bs_va - bs_mod;
                                    /* [findblock-probe] LookupCache::FindBlock(x0=this=LookupCache*, x1=Thread,
                                     * x2=Address). Its L1 lookup faults at ~0x18c90: ldp x8,x9,[x0,#0x30] (x0[0x30]=
                                     * L1 base, x0[0x38]=L1 mask), x25=x8+(x9&x2)<<4, ldr [x25]. Capture x0 (the LIVE
                                     * LookupCache ptr — dead by do_find) + L1 fields to tell a BOGUS x0 (garbage/
                                     * guest ptr from the dispatcher/StateFrame) from a valid-but-corrupted cache. */
                                    if (bs_rva >= 0x18c70 && bs_rva < 0x18e20)
                                    {
                                        static volatile int fb_seen = 0;
                                        if (__sync_fetch_and_add(&fb_seen, 1) < 6)
                                        {
                                            uint64_t x0v = (uint64_t)state.__x[0];
                                            uint64_t l1base = 0xdead, l1mask = 0xdead;
                                            int host = (x0v >= 0x100000000ULL && x0v < 0x800000000000ULL);
                                            if (host) {
                                                l1base = *(volatile uint64_t *)(uintptr_t)(x0v + 0x30);
                                                l1mask = *(volatile uint64_t *)(uintptr_t)(x0v + 0x38);
                                            }
                                            dprintf(STDERR_FILENO,
                                                "[findblock-probe] rva=0x%llx x0(LookupCache)=0x%llx host=%d x1(Thread)=0x%llx x2(rip)=0x%llx L1base[0x30]=0x%llx L1mask[0x38]=0x%llx\n",
                                                (unsigned long long)bs_rva, (unsigned long long)x0v, host,
                                                (unsigned long long)state.__x[1], (unsigned long long)state.__x[2],
                                                (unsigned long long)l1base, (unsigned long long)l1mask);
                                        }
                                    }
                                    if (bs_rva >= 0x1d100 && bs_rva < 0x1d300)
                                    {
                                        static volatile int bs_seen = 0;
                                        if (__sync_fetch_and_add(&bs_seen, 1) < 6)
                                        {
                                            uint64_t x8v  = (uint64_t)state.__x[8];
                                            uint64_t x11v = (uint64_t)state.__x[11];
                                            uint64_t x12v = (uint64_t)state.__x[12];
                                            uint64_t x15v = (uint64_t)state.__x[15];
                                            uint64_t x17v = (uint64_t)state.__x[17];
                                            dprintf(STDERR_FILENO,
                                                "[bucketscan-probe] do_find rva=0x%llx x11(base)=0x%llx x17(cur)=0x%llx scan_dist=0x%llx(%llu buckets) x8=0x%llx x12(idx)=0x%llx x15(key)=0x%llx\n",
                                                (unsigned long long)bs_rva, (unsigned long long)x11v,
                                                (unsigned long long)x17v, (unsigned long long)(x17v - x11v),
                                                (unsigned long long)((x17v - x11v) / 8), (unsigned long long)x8v,
                                                (unsigned long long)x12v, (unsigned long long)x15v);
                                            /* Dump the actual bucket CONTENTS at x11 (m_buckets). This range is
                                             * mapped (the scan reads it up to x17). Each ankerl bucket = 8 bytes
                                             * {u32 dist_and_fingerprint, u32 value_idx}. All-zero => empty (do_find
                                             * would have stopped); small ascending d_a_f => a real map; random
                                             * huge values => uninitialized/torn/UAF backing store. Also dump
                                             * callee-saved regs so we can recover `this` (do_find: this[0x18]==
                                             * m_buckets, this[0x3e]=m_shifts) offline. */
                                            {
                                                uint64_t bk[6] = {0,0,0,0,0,0};
                                                if (x11v >= 0x100000000ULL && x11v < 0x800000000000ULL)
                                                    for (int bi = 0; bi < 6; bi++)
                                                        bk[bi] = *(volatile uint64_t *)(uintptr_t)(x11v + (uint64_t)bi * 8);
                                                dprintf(STDERR_FILENO,
                                                    "[bucketscan-probe] buckets@x11: %016llx %016llx %016llx %016llx %016llx %016llx | x0=%llx x9=%llx x10=%llx x19=%llx x20=%llx x21=%llx x22=%llx\n",
                                                    (unsigned long long)bk[0], (unsigned long long)bk[1],
                                                    (unsigned long long)bk[2], (unsigned long long)bk[3],
                                                    (unsigned long long)bk[4], (unsigned long long)bk[5],
                                                    (unsigned long long)state.__x[0], (unsigned long long)state.__x[9],
                                                    (unsigned long long)state.__x[10], (unsigned long long)state.__x[19],
                                                    (unsigned long long)state.__x[20], (unsigned long long)state.__x[21],
                                                    (unsigned long long)state.__x[22]);
                                                /* Recover the map `this`: do_find has this[0x18]==m_buckets(x11v).
                                                 * Whichever candidate reg, at +0x18, holds x11v is `this`. Then dump
                                                 * its ankerl fields to tell a real-but-corrupted map (sane values
                                                 * ptrs, only m_buckets bad) from a wrong/guest `this`. Guarded reads. */
                                                {
                                                    uint64_t cands[4] = { (uint64_t)state.__x[10], (uint64_t)state.__x[19],
                                                                          (uint64_t)state.__x[21], (uint64_t)state.__x[0] };
                                                    int found = 0;
                                                    for (int ci = 0; ci < 4 && !found; ci++) {
                                                        uint64_t th = cands[ci];
                                                        if (th < 0x100000000ULL || th >= 0x800000000000ULL) continue;
                                                        uint64_t mb = *(volatile uint64_t *)(uintptr_t)(th + 0x18);
                                                        if (mb != x11v) continue;
                                                        found = 1;
                                                        uint64_t vb  = *(volatile uint64_t *)(uintptr_t)(th + 0x0);
                                                        uint64_t ve  = *(volatile uint64_t *)(uintptr_t)(th + 0x8);
                                                        uint64_t f20 = *(volatile uint64_t *)(uintptr_t)(th + 0x20);
                                                        uint64_t f28 = *(volatile uint64_t *)(uintptr_t)(th + 0x28);
                                                        uint8_t  sh  = *(volatile uint8_t  *)(uintptr_t)(th + 0x3e);
                                                        dprintf(STDERR_FILENO,
                                                            "[bucketscan-probe] THIS=0x%llx(reg%d) values.begin=0x%llx end=0x%llx [0x20]=0x%llx [0x28]=0x%llx m_shifts=0x%x\n",
                                                            (unsigned long long)th, ci, (unsigned long long)vb,
                                                            (unsigned long long)ve, (unsigned long long)f20,
                                                            (unsigned long long)f28, sh);
                                                    }
                                                    if (!found)
                                                        dprintf(STDERR_FILENO,
                                                            "[bucketscan-probe] THIS not found in x0/x10/x19/x21 (map ptr not in loop regs)\n");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if ((va = ios_jit_reverse_translate( state.__lr, &mod )))
                                dprintf(STDERR_FILENO, "[mach_exc] lr PE: %s+0x%llx (va=0x%llx)\n",
                                        ios_pe_module_name(mod), (unsigned long long)(va - mod),
                                        (unsigned long long)va);
                            /* [nullfp-probe] When the fault is #arm64x_check_call with x11=0,
                             * the EC indirect-call TARGET is null. The caller pattern is
                             *   lr-0x1c: adrp xN, PAGE ;  lr-0xc: ldr x11,[xN,#OFF] ;  lr-4: blr x8
                             * Decode adrp+ldr to recover the target-global address, then read it
                             * from BOTH the pool COPY and the PE mapping. pool==0 && PE!=0 => the
                             * pool copy's .data was never relocated/synced (same class as the NLS
                             * casemap bug); both==0 => the static-init that populates it never ran. */
                            if (cnt <= 3 && va && (uintptr_t)state.__x[11] == 0 &&
                                (uintptr_t)state.__lr >= 0x100000000ULL)
                            {
                                uint64_t lr_rva = va - mod;
                                uint64_t pool_base = (uint64_t)state.__lr - lr_rva;
                                uint32_t *cp = (uint32_t *)(uintptr_t)state.__lr;
                                uint32_t adrp_i = cp[-7];   /* lr-0x1c */
                                uint32_t ldr_i  = cp[-3];   /* lr-0xc  */
                                int is_adrp = ((adrp_i >> 24) & 0x9f) == 0x90;
                                int is_ldr  = ((ldr_i  >> 22) & 0x3ff) == 0x3e5; /* LDR imm,64 unsigned */
                                if (is_adrp && is_ldr)
                                {
                                    int64_t immlo = (adrp_i >> 29) & 0x3;
                                    int64_t immhi = (adrp_i >> 5) & 0x7ffff;
                                    int64_t imm = (immhi << 2) | immlo;
                                    if (imm & (1LL << 20)) imm |= ~((1LL << 21) - 1);
                                    uint64_t adrp_pc = (uint64_t)state.__lr - 0x1c;
                                    uint64_t page = (adrp_pc & ~0xfffULL) + ((uint64_t)imm << 12);
                                    uint64_t off  = (uint64_t)((ldr_i >> 10) & 0xfff) << 3;
                                    uint64_t g_pool = page + off;
                                    uint64_t g_rva  = g_pool - pool_base;
                                    uint64_t gv_pool = *(volatile uint64_t *)(uintptr_t)g_pool;
                                    uint64_t gv_pe   = *(volatile uint64_t *)(uintptr_t)(mod + g_rva);
                                    dprintf(STDERR_FILENO,
                                        "[nullfp-probe] tgt-global rva=0x%llx pool[0x%llx]=0x%llx PE[0x%llx]=0x%llx mod=%s lr_rva=0x%llx\n",
                                        (unsigned long long)g_rva,
                                        (unsigned long long)g_pool, (unsigned long long)gv_pool,
                                        (unsigned long long)(mod + g_rva), (unsigned long long)gv_pe,
                                        ios_pe_module_name(mod), (unsigned long long)lr_rva);
                                }
                                else
                                    dprintf(STDERR_FILENO,
                                        "[nullfp-probe] caller not adrp+ldr: adrp_i=0x%08x ldr_i=0x%08x lr_rva=0x%llx mod=%s\n",
                                        adrp_i, ldr_i, (unsigned long long)(va - mod), ios_pe_module_name(mod));
                            }
                        }
                        /* fp-chain backtrace of the faulting thread — names
                         * the exact native call path (which Metal call fed
                         * free() a garbage pointer). Native code has honest
                         * x29 chains; stop on invalid fp. */
                        if (cnt <= 3)
                        {
                            uint64_t fp_walk = state.__fp;
                            int fr;
                            for (fr = 0; fr < 10 && fp_walk; fr++)
                            {
                                uint64_t frame_buf[2];
                                mach_vm_size_t got_fw = 0;
                                if (mach_vm_read_overwrite(mach_task_self(),
                                        (mach_vm_address_t)fp_walk, 16,
                                        (mach_vm_address_t)frame_buf, &got_fw)
                                        != KERN_SUCCESS || got_fw != 16)
                                    break;
                                {
                                    uint64_t ret_pc = frame_buf[1];
                                    Dl_info di_f;
                                    const char *f_img = "?", *f_sym = "?";
                                    uint64_t f_off = ret_pc;
                                    if (ret_pc > 0x4000 &&
                                        dladdr((void*)(uintptr_t)ret_pc, &di_f))
                                    {
                                        if (di_f.dli_fname) f_img = di_f.dli_fname;
                                        if (di_f.dli_sname) { f_sym = di_f.dli_sname;
                                            f_off = ret_pc - (uint64_t)(uintptr_t)di_f.dli_saddr; }
                                    }
                                    dprintf(STDERR_FILENO,
                                        "[mach_exc] bt[%d] 0x%llx %s`%s+0x%llx\n",
                                        fr, (unsigned long long)ret_pc,
                                        f_img, f_sym, (unsigned long long)f_off);
                                    if (ret_pc <= 0x4000) break;
                                }
                                fp_walk = frame_buf[0];
                            }
                        }
                        /* Stack scan ([term-stack] pattern): the exit-path
                         * crashers have no walkable fp chain, so reconstruct
                         * call history from return addresses left on the
                         * stack. Copy attribution per hit — the frame where
                         * copy_owner flips from a child peb to 0 (session)
                         * is where the thread crossed ntdll copies. */
                        if (cnt <= 3)
                        {
                            extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
                            extern void *ios_jit_pool_copy_owner(const void *addr, void **pe_base_out);
                            uint64_t sp_scan = __darwin_arm_thread_state64_get_sp(state);
                            int w2, hits = 0;
                            for (w2 = 0; w2 < 512 && hits < 24; w2++)
                            {
                                uint64_t slot_val;
                                mach_vm_size_t got_sv = 0;
                                if (mach_vm_read_overwrite(mach_task_self(),
                                        (mach_vm_address_t)(sp_scan + 8ull * w2), 8,
                                        (mach_vm_address_t)&slot_val, &got_sv)
                                        != KERN_SUCCESS || got_sv != 8)
                                    break;
                                {
                                    uint64_t mod3, va3;
                                    if ((va3 = ios_jit_reverse_translate( slot_val, &mod3 )) && va3 != slot_val)
                                    {
                                        void *cp3 = NULL;
                                        void *co3 = ios_jit_pool_copy_owner((void *)(uintptr_t)slot_val, &cp3);
                                        dprintf(STDERR_FILENO,
                                            "[exit-stk] sp+0x%x: 0x%llx = %s+0x%llx copy_owner=%p\n",
                                            w2 * 8, (unsigned long long)slot_val,
                                            ios_pe_module_name(mod3),
                                            (unsigned long long)(va3 - mod3), co3);
                                        hits++;
                                    }
                                }
                            }
                        }
                        /* One-shot: dump the faulting native function's
                         * prologue so we can see what per-thread/global
                         * state it reads (libsystem_malloc keeps dying on
                         * corrupt zone state — need its actual fastpath). */
                        static volatile int proto_dumped = 0;
                        /* ml982: a failed dladdr does NOT establish a usable
                         * dli_saddr, so require pc_named; and copy through a
                         * failure-returning read rather than dereferencing, so an
                         * address that is nameable but unreadable cannot park the
                         * exception server on its own load. Status AND length are
                         * both checked -- a short read crossing a page boundary
                         * must not be treated as success. */
                        if (pc_named && di_pc.dli_saddr && fault_pc >= 0x180000000ULL &&
                            __sync_bool_compare_and_swap(&proto_dumped, 0, 1))
                        {
                            uint32_t fp[40];
                            mach_vm_size_t got = 0;
                            if (mach_vm_read_overwrite( mach_task_self(),
                                                        (mach_vm_address_t)(uintptr_t)di_pc.dli_saddr,
                                                        sizeof(fp), (mach_vm_address_t)fp,
                                                        &got ) == KERN_SUCCESS && got == sizeof(fp))
                            {
                                int w;
                                for (w = 0; w < 40; w += 8)
                                    dprintf(STDERR_FILENO,
                                        "[mach_exc] fn+%03x: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                                        w * 4, fp[w], fp[w+1], fp[w+2], fp[w+3],
                                        fp[w+4], fp[w+5], fp[w+6], fp[w+7]);
                            }
                            else
                                dprintf(STDERR_FILENO,
                                        "[mach_exc] ml982 fn prologue at %p <unreadable> (got=%llu) "
                                        "-- continuing the normal exception path\n",
                                        di_pc.dli_saddr, (unsigned long long)got);
                        }
                    }
                    /* Thing B one-shot: a zero-page pc crawl means a thread
                     * took `blr x16` with x16==1 from an EC exit thunk
                     * ($iexit_thunk$ at EC ntdll+0x73040: adrp x8,+0x51
                     * pages; ldr x16,[x8,#0x480]; blr x16). Dump (a) the
                     * ARM64X dispatch slots of every private EC ntdll copy,
                     * (b) the qword the adrp ACTUALLY dereferenced computed
                     * from the execution-address lr (catches link-vs-exec
                     * address skew in pool copies), (c) x9 — exit-thunk
                     * convention: x9 = the x64 target being called — and
                     * (d) an fp-chain backtrace with PE attribution so the
                     * call path INTO the thunk names itself. */
                    static volatile int thunk_probe_shots = 0;
                    if (fault_pc < 0x1000 && thunk_probe_shots < 3)
                    {
                        extern void ios_dump_ec_dispatch_slots( unsigned long long lr_va, unsigned long long x9 );
                        extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
                        uint64_t lr_exec = state.__lr & 0x0000007fffffffffull;
                        uint64_t lr_mod = 0, lr_va = ios_jit_reverse_translate( lr_exec, &lr_mod );
                        uint64_t fp_walk;
                        int fr;
                        __sync_add_and_fetch(&thunk_probe_shots, 1);
                        dprintf(STDERR_FILENO,
                            "[thunk-slot] WEDGE pc=0x%llx lr_exec=0x%llx lr_va=0x%llx (%.32s) "
                            "x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx x4=0x%llx "
                            "x8=0x%llx x9=0x%llx x10=0x%llx x11=0x%llx fp=0x%llx\n",
                            (unsigned long long)fault_pc,
                            (unsigned long long)lr_exec, (unsigned long long)lr_va,
                            lr_mod ? ios_pe_module_name(lr_mod) : "?",
                            (unsigned long long)state.__x[0], (unsigned long long)state.__x[1],
                            (unsigned long long)state.__x[2], (unsigned long long)state.__x[3],
                            (unsigned long long)state.__x[4], (unsigned long long)state.__x[8],
                            (unsigned long long)state.__x[9], (unsigned long long)state.__x[10],
                            (unsigned long long)state.__x[11], (unsigned long long)state.__fp);
                        ios_dump_ec_dispatch_slots( lr_va ? lr_va : lr_exec,
                                                    state.__x[9] );
                        /* Exec-relative adrp target: adrp sits at lr-0xc;
                         * its immediate is +0x51 pages, ldr offset 0x480
                         * (fixed by the thunk's encoding — see disasm of
                         * arm64ec-windows/ntdll.dll +0x73048). */
                        {
                            uint64_t adrp_tgt = ((lr_exec - 0xc) & ~0xFFFULL) + 0x51000 + 0x480;
                            uint64_t slot_val = 0;
                            mach_vm_size_t got_sv = 0;
                            if (mach_vm_read_overwrite(mach_task_self(),
                                    (mach_vm_address_t)adrp_tgt, 8,
                                    (mach_vm_address_t)&slot_val, &got_sv) == KERN_SUCCESS && got_sv == 8)
                                dprintf(STDERR_FILENO,
                                    "[thunk-slot] exec-relative slot @0x%llx = 0x%llx\n",
                                    (unsigned long long)adrp_tgt, (unsigned long long)slot_val);
                            else
                                dprintf(STDERR_FILENO,
                                    "[thunk-slot] exec-relative slot @0x%llx UNREADABLE\n",
                                    (unsigned long long)adrp_tgt);
                        }
                        fp_walk = state.__fp;
                        for (fr = 0; fr < 16 && fp_walk; fr++)
                        {
                            uint64_t frame_buf[2];
                            mach_vm_size_t got_fw = 0;
                            uint64_t ret_pc, bt_mod, bt_va;
                            if (mach_vm_read_overwrite(mach_task_self(),
                                    (mach_vm_address_t)fp_walk, 16,
                                    (mach_vm_address_t)frame_buf, &got_fw) != KERN_SUCCESS || got_fw != 16)
                                break;
                            ret_pc = frame_buf[1] & 0x0000007fffffffffull;
                            if (ret_pc <= 0x4000) break;
                            bt_mod = 0;
                            bt_va = ios_jit_reverse_translate( ret_pc, &bt_mod );
                            if (bt_va)
                                dprintf(STDERR_FILENO,
                                    "[thunk-slot] bt[%d] 0x%llx PE %.32s+0x%llx (base=0x%llx)\n",
                                    fr, (unsigned long long)ret_pc,
                                    ios_pe_module_name(bt_mod),
                                    (unsigned long long)(bt_va - bt_mod),
                                    (unsigned long long)bt_mod);
                            else
                            {
                                Dl_info di_t;
                                const char *t_img = "?", *t_sym = "?";
                                uint64_t t_off = ret_pc;
                                if (dladdr((void*)(uintptr_t)ret_pc, &di_t))
                                {
                                    if (di_t.dli_fname) { t_img = strrchr(di_t.dli_fname, '/'); t_img = t_img ? t_img + 1 : di_t.dli_fname; }
                                    if (di_t.dli_sname) { t_sym = di_t.dli_sname; t_off = ret_pc - (uint64_t)(uintptr_t)di_t.dli_saddr; }
                                }
                                dprintf(STDERR_FILENO,
                                    "[thunk-slot] bt[%d] 0x%llx %s`%s+0x%llx\n",
                                    fr, (unsigned long long)ret_pc, t_img, t_sym,
                                    (unsigned long long)t_off);
                            }
                            fp_walk = frame_buf[0];
                        }
                    }
                    /* One-shot dump: on the first UNHANDLED exec fault, dump the
                     * JIT-pool RW alias contents around the relevant FEX CodeBuffer
                     * slots to a file. Lets us disassemble FEX-emitted ARM64 offline
                     * to verify codegen correctness independently. */
                    static volatile int dumped = 0;
                    if (cnt == 1 && __sync_bool_compare_and_swap(&dumped, 0, 1))
                        ios_dump_jit_pool( "mach UNHANDLED" );
                    /* Diagnostic: query the kernel for what VM region the fault PC lives in.
                     * Helps identify mystery regions (e.g. JIT pool guard zone, wineserver heap). */
                    if (cnt <= 3)
                    {
                        mach_vm_address_t qa = (mach_vm_address_t)fault_pc;
                        mach_vm_size_t qs = 0;
                        vm_region_basic_info_data_64_t qinfo;
                        mach_msg_type_number_t qcnt = VM_REGION_BASIC_INFO_COUNT_64;
                        mach_port_t qobj = MACH_PORT_NULL;
                        if (mach_vm_region(mach_task_self(), &qa, &qs,
                                           VM_REGION_BASIC_INFO_64,
                                           (vm_region_info_t)&qinfo, &qcnt, &qobj)
                            == KERN_SUCCESS)
                        {
                            dprintf(STDERR_FILENO,
                                "[mach_exc] vm_region: addr=0x%llx size=0x%llx prot=0x%x max_prot=0x%x inherit=%d shared=%d offset=0x%llx\n",
                                (unsigned long long)qa, (unsigned long long)qs,
                                qinfo.protection, qinfo.max_protection,
                                qinfo.inheritance, qinfo.shared,
                                (unsigned long long)qinfo.offset);
                        }
                    }

                    /* iOS-Madeira: dump x86 STATE on the first few faults. FEX rarely
                     * spills RSP/RSI/RDI etc to State.gregs[] (they live in static
                     * ARM regs x23/x25/x26 and only get spilled at SpillStaticRegs
                     * call sites — which most of __dyn_tls_init's path never hits).
                     * So the LIVE x86 register values are in state.__x[] of the
                     * faulted thread. ARM64EC SRA:
                     *   RAX=x8, RCX=x0 (pair0); RDX=x1, RBX=x27 (pair1);
                     *   RSP=x23, RBP=x29 (pair2); RSI=x25, RDI=x26 (pair3);
                     *   R8=x2, R9=x3, R10=x4, R11=x5; R12=x19, R13=x20, R14=x21, R15=x22.
                     * State pointer is reachable via TEB+0x1788 -> CPUArea+0x30.   */
                    /* Read State.RIP unconditionally so we can decide whether
                     * this fault is "interesting" (i.e., in known Thumper DXGI
                     * dispatch range 0x140079xxx-0x14007axxx). Dump full state
                     * for first 3 faults OR any interesting RIP. */
                    uintptr_t teb_out_pre = 0;
                    void *tramp_out_pre = NULL;
                    ios_lookup_thread(thread, &teb_out_pre, &tramp_out_pre);
                    void *fex_state_pre = NULL;
                    if (teb_out_pre)
                    {
                        void *cpuarea = *(void**)(teb_out_pre + 0x1788);
                        if (cpuarea) fex_state_pre = *(void**)((char*)cpuarea + 0x30);
                    }
                    uint64_t state_rip_pre = fex_state_pre ?
                        ((uint64_t*)fex_state_pre)[0x18 / 8] : 0;
                    int interesting_rip = (state_rip_pre >= 0x140079000 &&
                                           state_rip_pre <  0x14007b000) ||
                                          (state_rip_pre >= 0x1400e0000 &&
                                           state_rip_pre <  0x1400e1000);
                    if (cnt <= 3 || interesting_rip)
                    {
                        uintptr_t teb_out = teb_out_pre;
                        void *tramp_out = tramp_out_pre;
                        (void)tramp_out;
                        void *fex_state = fex_state_pre;
                        uint64_t state_rip = state_rip_pre;
                        uint64_t state_cret = fex_state ? ((uint64_t*)fex_state)[0xb0 / 8] : 0;
                        /* gs_cached is at CPUState offset 0x3e0 (after gregs,
                         * L1*, callret_sp, avx_high, xmm union, segment idxes,
                         * mxcsr, es/cs/ss/ds_cached). */
                        uint64_t state_gs = fex_state ? ((uint64_t*)fex_state)[0x3e0 / 8] : 0;
                        uint64_t teb_tls = teb_out ? *(uint64_t*)(teb_out + 0x58) : 0;
                        uint64_t gs_plus_58 = 0;
                        if (state_gs >= 0x10000 && state_gs < 0xfffffff000000000ULL)
                            gs_plus_58 = *(uint64_t*)(state_gs + 0x58);
                        dprintf(STDERR_FILENO,
                            "[x86_seg] State.gs_cached=0x%llx TEB=0x%llx TEB[0x58]=0x%llx *(gs_cached+0x58)=0x%llx\n",
                            (unsigned long long)state_gs,
                            (unsigned long long)teb_out,
                            (unsigned long long)teb_tls,
                            (unsigned long long)gs_plus_58);

                        /* LIVE x86 regs from host ARM thread state (ARM64EC SRA). */
                        uint64_t live_rax = state.__x[8];
                        uint64_t live_rcx = state.__x[0];
                        uint64_t live_rdx = state.__x[1];
                        uint64_t live_rbx = state.__x[27];
                        uint64_t live_rsp = state.__x[23];
                        /* x29 is __fp, NOT __x[29]: Darwin's __x holds only x0..x28,
                         * so the old form read one past the array. It happened to
                         * land on __fp and print the right value, but it was UB and
                         * the compiler flags it (-Warray-bounds). Same bits, legally. */
                        uint64_t live_rbp = state.__fp;
                        uint64_t live_rsi = state.__x[25];
                        uint64_t live_rdi = state.__x[26];
                        uint64_t live_r8  = state.__x[2];
                        uint64_t live_r9  = state.__x[3];
                        uint64_t live_r10 = state.__x[4];
                        uint64_t live_r11 = state.__x[5];
                        uint64_t live_r12 = state.__x[19];
                        uint64_t live_r13 = state.__x[20];
                        uint64_t live_r14 = state.__x[21];
                        uint64_t live_r15 = state.__x[22];
                        dprintf(STDERR_FILENO,
                            "[x86_live] RAX=0x%llx RCX=0x%llx RDX=0x%llx RBX=0x%llx RSP=0x%llx RBP=0x%llx RSI=0x%llx RDI=0x%llx\n"
                            "[x86_live]  R8=0x%llx  R9=0x%llx R10=0x%llx R11=0x%llx R12=0x%llx R13=0x%llx R14=0x%llx R15=0x%llx\n"
                            "[x86_live] State.RIP=0x%llx callret_sp=0x%llx\n",
                            (unsigned long long)live_rax, (unsigned long long)live_rcx,
                            (unsigned long long)live_rdx, (unsigned long long)live_rbx,
                            (unsigned long long)live_rsp, (unsigned long long)live_rbp,
                            (unsigned long long)live_rsi, (unsigned long long)live_rdi,
                            (unsigned long long)live_r8,  (unsigned long long)live_r9,
                            (unsigned long long)live_r10, (unsigned long long)live_r11,
                            (unsigned long long)live_r12, (unsigned long long)live_r13,
                            (unsigned long long)live_r14, (unsigned long long)live_r15,
                            (unsigned long long)state_rip, (unsigned long long)state_cret);

                        if (live_rsp >= 0x10000 && live_rsp < 0xfffffff000000000ULL)
                        {
                            uint64_t buf[16];
                            mach_vm_size_t got = 0;
                            kern_return_t kr = mach_vm_read_overwrite(
                                mach_task_self(),
                                (mach_vm_address_t)(live_rsp - 32),
                                sizeof(buf),
                                (mach_vm_address_t)buf, &got);
                            if (kr == KERN_SUCCESS && got >= 64)
                            {
                                dprintf(STDERR_FILENO,
                                    "[x86_stk] @RSP-32..-8: %016llx %016llx %016llx %016llx  (last = popped slot)\n",
                                    (unsigned long long)buf[0],
                                    (unsigned long long)buf[1],
                                    (unsigned long long)buf[2],
                                    (unsigned long long)buf[3]);
                                dprintf(STDERR_FILENO,
                                    "[x86_stk] @RSP+0..+24:  %016llx %016llx %016llx %016llx\n",
                                    (unsigned long long)buf[4],
                                    (unsigned long long)buf[5],
                                    (unsigned long long)buf[6],
                                    (unsigned long long)buf[7]);
                                dprintf(STDERR_FILENO,
                                    "[x86_stk] @RSP+32..+56: %016llx %016llx %016llx %016llx\n",
                                    (unsigned long long)buf[8],
                                    (unsigned long long)buf[9],
                                    (unsigned long long)buf[10],
                                    (unsigned long long)buf[11]);

                                /* ml382 CALLER HUNT for the "-1 pointer" family.
                                 *
                                 * Three runs (ml372/378/381) died identically:
                                 * fault addr 0xffffffffffe01000, insn f8bfc0da.
                                 * Decoded from the REAL chrome_elf.dll pulled off
                                 * the phone, the faulting function is
                                 * chrome_elf+0x65750 = PartitionRoot::Free(root,
                                 * ptr):
                                 *   test rdx,rdx / je end        <- handles NULL
                                 *   and r14, ~(2MB-1)            <- super-page base
                                 *   mov rdi,[r14+0x1000]         <- FAULTS
                                 * and the live regs had RDX = RSI = -1, R14 =
                                 * -1 & ~(2MB-1). So Chromium is freeing (void*)-1.
                                 * PA handles NULL but not -1, so SOMETHING handed
                                 * it -1 where NULL (or a real pointer) was due.
                                 *
                                 * The existing 12-qword window did not reach the
                                 * return address, so the caller is still unknown —
                                 * and guessing it is exactly what burned two
                                 * theories today. Dump a wide window ONLY for this
                                 * signature so the caller can be identified offline
                                 * (a stack qword whose preceding bytes decode as a
                                 * CALL is a real return address; a function START
                                 * preceded by ret+padding is just a callback
                                 * pointer, which is how 0x...9c110 was excluded). */
                                if (((uint64_t)fault_addr & 0xffffffff00000000ULL) == 0xffffffff00000000ULL)
                                {
                                    uint64_t wide[64];
                                    mach_vm_size_t wgot = 0;
                                    static int minus1_dumps;
                                    if (minus1_dumps < 2 &&
                                        mach_vm_read_overwrite( mach_task_self(),
                                            (mach_vm_address_t)live_rsp, sizeof(wide),
                                            (mach_vm_address_t)wide, &wgot ) == KERN_SUCCESS
                                        && wgot == sizeof(wide))
                                    {
                                        unsigned wi;
                                        minus1_dumps++;
                                        dprintf(STDERR_FILENO,
                                            "[minus1-stack] rev=ml382 fault=0x%llx rsp=0x%llx — 64 qwords "
                                            "(find the CALLER offline: qword whose preceding bytes are E8/FF15)\n",
                                            (unsigned long long)fault_addr,
                                            (unsigned long long)live_rsp);
                                        for (wi = 0; wi < 64; wi += 4)
                                            dprintf(STDERR_FILENO,
                                                "[minus1-stack]   +%03x: %016llx %016llx %016llx %016llx\n",
                                                wi * 8,
                                                (unsigned long long)wide[wi],
                                                (unsigned long long)wide[wi+1],
                                                (unsigned long long)wide[wi+2],
                                                (unsigned long long)wide[wi+3]);
                                    }
                                }
                            }
                            else
                            {
                                dprintf(STDERR_FILENO,
                                    "[x86_stk] vm_read RSP=0x%llx kr=%d got=%llu\n",
                                    (unsigned long long)live_rsp, kr,
                                    (unsigned long long)got);
                            }
                        }
                        else
                        {
                            dprintf(STDERR_FILENO,
                                "[x86_stk] live_rsp=0x%llx out of range — RSP not yet established\n",
                                (unsigned long long)live_rsp);
                        }

                        /* Dump [RBX..RBX+0x30] for stack-local objects: lets us
                         * see the full vector/struct state when the fault is on
                         * a `mov rax, [rcx]` chained from `mov rcx, [rbx]`. */
                        if (live_rbx >= 0x10000 && live_rbx < 0xfffffff000000000ULL)
                        {
                            uint64_t obj[7];
                            mach_vm_size_t got2 = 0;
                            kern_return_t kr2 = mach_vm_read_overwrite(
                                mach_task_self(),
                                (mach_vm_address_t)live_rbx,
                                sizeof(obj),
                                (mach_vm_address_t)obj, &got2);
                            if (kr2 == KERN_SUCCESS && got2 >= sizeof(obj))
                                dprintf(STDERR_FILENO,
                                    "[x86_obj] @RBX+0..+0x30: %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
                                    (unsigned long long)obj[0],
                                    (unsigned long long)obj[1],
                                    (unsigned long long)obj[2],
                                    (unsigned long long)obj[3],
                                    (unsigned long long)obj[4],
                                    (unsigned long long)obj[5],
                                    (unsigned long long)obj[6]);
                        }

                        /* Also dump [RCX..RCX+0x30] — when the fault is in a
                         * helper that took (rcx=this, ...) and `this` got
                         * clobbered by intermediate moves, the original `this`
                         * lives in RBX. But RCX itself often points to a
                         * destination buffer or an object whose state we want
                         * to inspect. */
                        if (live_rcx >= 0x10000 && live_rcx < 0xfffffff000000000ULL)
                        {
                            uint64_t obj[7];
                            mach_vm_size_t got_c = 0;
                            kern_return_t kr_c = mach_vm_read_overwrite(
                                mach_task_self(),
                                (mach_vm_address_t)live_rcx,
                                sizeof(obj),
                                (mach_vm_address_t)obj, &got_c);
                            if (kr_c == KERN_SUCCESS && got_c >= sizeof(obj))
                                dprintf(STDERR_FILENO,
                                    "[x86_dst] @RCX+0..+0x30: %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
                                    (unsigned long long)obj[0],
                                    (unsigned long long)obj[1],
                                    (unsigned long long)obj[2],
                                    (unsigned long long)obj[3],
                                    (unsigned long long)obj[4],
                                    (unsigned long long)obj[5],
                                    (unsigned long long)obj[6]);
                        }

                        /* Thumper-debug: also dump the static singleton slot
                         * at 0x140290a60+0x428. This is the "0x1400793d0
                         * caller" that the DXGI dispatch wrapper reads from.
                         * If it's the static placeholder 0x1401825a8, Thumper
                         * never initialized the real renderer wrapper at this
                         * slot. If it's something else, we need to see what. */
                        {
                            uint64_t static_slot = 0;
                            mach_vm_size_t got_ss = 0;
                            if (mach_vm_read_overwrite(mach_task_self(),
                                    (mach_vm_address_t)0x140290e88ULL, /* 0x140290a60+0x428 */
                                    sizeof(static_slot),
                                    (mach_vm_address_t)&static_slot, &got_ss)
                                == KERN_SUCCESS && got_ss == sizeof(static_slot))
                            {
                                dprintf(STDERR_FILENO,
                                    "[x86_thumper] [0x140290a60+0x428]=0x%llx",
                                    (unsigned long long)static_slot);
                                /* Walk the chain: renderer object → vtable → vtable[30] */
                                if (static_slot >= 0x10000 && static_slot < 0xfffffff000000000ULL)
                                {
                                    uint64_t vtable_ptr = 0;
                                    mach_vm_size_t got_v = 0;
                                    if (mach_vm_read_overwrite(mach_task_self(),
                                            (mach_vm_address_t)static_slot,
                                            sizeof(vtable_ptr),
                                            (mach_vm_address_t)&vtable_ptr, &got_v)
                                        == KERN_SUCCESS && got_v == sizeof(vtable_ptr))
                                    {
                                        dprintf(STDERR_FILENO, "  vtable=*[slot]=0x%llx",
                                            (unsigned long long)vtable_ptr);
                                        if (vtable_ptr >= 0x10000 && vtable_ptr < 0xfffffff000000000ULL)
                                        {
                                            /* Read full vtable slots [0..7] and [30] */
                                            uint64_t vt_entries[32];
                                            mach_vm_size_t got_ve = 0;
                                            if (mach_vm_read_overwrite(mach_task_self(),
                                                    (mach_vm_address_t)vtable_ptr,
                                                    sizeof(vt_entries),
                                                    (mach_vm_address_t)vt_entries, &got_ve)
                                                == KERN_SUCCESS && got_ve == sizeof(vt_entries))
                                            {
                                                dprintf(STDERR_FILENO,
                                                    "\n[x86_thumper]   vtable[0..3]: %016llx %016llx %016llx %016llx",
                                                    (unsigned long long)vt_entries[0],
                                                    (unsigned long long)vt_entries[1],
                                                    (unsigned long long)vt_entries[2],
                                                    (unsigned long long)vt_entries[3]);
                                                dprintf(STDERR_FILENO,
                                                    "\n[x86_thumper]   vtable[28..31] (target=[30]): %016llx %016llx ★%016llx %016llx",
                                                    (unsigned long long)vt_entries[28],
                                                    (unsigned long long)vt_entries[29],
                                                    (unsigned long long)vt_entries[30],
                                                    (unsigned long long)vt_entries[31]);
                                            }
                                        }
                                    }
                                }
                                dprintf(STDERR_FILENO, "\n");
                            }
                        }

                        /* Thumper-debug: when fault chain involves the renderer
                         * wrapper at guest RIP 0x140079390 (vtable[30] dispatch),
                         * dump the indirection chain [rcx+0x428] → [rax] → [r10+0xf0].
                         * Helps identify when [rcx+0x428] is the wrong type
                         * (vtable instead of object, etc.) per GPT diagnosis. */
                        if (live_rcx >= 0x10000 && live_rcx < 0xfffffff000000000ULL)
                        {
                            mach_vm_address_t f1_addr = (mach_vm_address_t)(live_rcx + 0x428);
                            uint64_t f1 = 0;
                            mach_vm_size_t got_f1 = 0;
                            if (mach_vm_read_overwrite(mach_task_self(), f1_addr,
                                    sizeof(f1), (mach_vm_address_t)&f1, &got_f1)
                                == KERN_SUCCESS && got_f1 == sizeof(f1))
                            {
                                dprintf(STDERR_FILENO, "[x86_dispatch] [RCX+0x428]=0x%llx",
                                    (unsigned long long)f1);
                                if (f1 >= 0x10000 && f1 < 0xfffffff000000000ULL)
                                {
                                    uint64_t f2 = 0;
                                    mach_vm_size_t got_f2 = 0;
                                    if (mach_vm_read_overwrite(mach_task_self(),
                                            (mach_vm_address_t)f1, sizeof(f2),
                                            (mach_vm_address_t)&f2, &got_f2)
                                        == KERN_SUCCESS && got_f2 == sizeof(f2))
                                    {
                                        dprintf(STDERR_FILENO, " [[+0x428]]=0x%llx",
                                            (unsigned long long)f2);
                                        if (f2 >= 0x10000 && f2 < 0xfffffff000000000ULL)
                                        {
                                            uint64_t slot30 = 0;
                                            mach_vm_size_t got_s = 0;
                                            if (mach_vm_read_overwrite(mach_task_self(),
                                                    (mach_vm_address_t)(f2 + 0xf0),
                                                    sizeof(slot30),
                                                    (mach_vm_address_t)&slot30, &got_s)
                                                == KERN_SUCCESS && got_s == sizeof(slot30))
                                            {
                                                dprintf(STDERR_FILENO,
                                                    " [+0xf0]=0x%llx (would-be vtable[30])",
                                                    (unsigned long long)slot30);
                                            }
                                        }
                                    }
                                }
                                dprintf(STDERR_FILENO, "\n");
                            }
                        }

                        /* Walk FEX's callret stack to recover the guest call chain.
                         * Each entry is 16 bytes: [0..7]=guest return RIP, [8..15]=host
                         * return PC. callret_sp points at the most-recently-pushed
                         * entry; entries grow DOWN (push pre-decrements by 0x10). */
                        if (state_cret >= 0x10000 && state_cret < 0xfffffff000000000ULL)
                        {
                            uint64_t cr[16]; /* up to 8 entries */
                            mach_vm_size_t got3 = 0;
                            kern_return_t kr3 = mach_vm_read_overwrite(
                                mach_task_self(),
                                (mach_vm_address_t)state_cret,
                                sizeof(cr),
                                (mach_vm_address_t)cr, &got3);
                            if (kr3 == KERN_SUCCESS && got3 >= sizeof(cr))
                            {
                                dprintf(STDERR_FILENO,
                                    "[x86_callret] guest call chain (most recent first):\n"
                                    "  [0] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [1] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [2] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [3] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [4] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [5] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [6] retRIP=0x%llx hostPC=0x%llx\n"
                                    "  [7] retRIP=0x%llx hostPC=0x%llx\n",
                                    (unsigned long long)cr[0],  (unsigned long long)cr[1],
                                    (unsigned long long)cr[2],  (unsigned long long)cr[3],
                                    (unsigned long long)cr[4],  (unsigned long long)cr[5],
                                    (unsigned long long)cr[6],  (unsigned long long)cr[7],
                                    (unsigned long long)cr[8],  (unsigned long long)cr[9],
                                    (unsigned long long)cr[10], (unsigned long long)cr[11],
                                    (unsigned long long)cr[12], (unsigned long long)cr[13],
                                    (unsigned long long)cr[14], (unsigned long long)cr[15]);
                                /* madeira-bcd [guest-fn]: the guest code of the two
                                 * innermost frames, so the faulting function can be
                                 * disassembled from the log: 48 bytes before each
                                 * return address, and 256 bytes of the function a
                                 * direct call (E8 rel32) right before it enters. */
                                {
                                    static int guest_fn_dumps;
                                    int e;
                                    for (e = 0; e < 2 && guest_fn_dumps < 4; e++)
                                    {
                                        uint64_t ret = cr[e * 2];
                                        uint8_t pre[48];
                                        mach_vm_size_t gp = 0;
                                        if (ret < 0x10000 + sizeof(pre) || ret >= 0x800000000000ULL) continue;
                                        if (mach_vm_read_overwrite(mach_task_self(),
                                                (mach_vm_address_t)(ret - sizeof(pre)), sizeof(pre),
                                                (mach_vm_address_t)pre, &gp) != KERN_SUCCESS || gp != sizeof(pre))
                                            continue;
                                        guest_fn_dumps++;
                                        {
                                            char hex[sizeof(pre) * 2 + 1];
                                            int b;
                                            for (b = 0; b < (int)sizeof(pre); b++)
                                                snprintf(hex + b * 2, 3, "%02x", pre[b]);
                                            dprintf(STDERR_FILENO, "[guest-fn] [%d] %llx-48: %s\n",
                                                e, (unsigned long long)ret, hex);
                                        }
                                        if (pre[sizeof(pre) - 5] == 0xe8)
                                        {
                                            int32_t rel;
                                            uint64_t tgt;
                                            uint8_t body[256];
                                            mach_vm_size_t gb = 0;
                                            memcpy(&rel, pre + sizeof(pre) - 4, sizeof(rel));
                                            tgt = ret + (int64_t)rel;
                                            if (mach_vm_read_overwrite(mach_task_self(),
                                                    (mach_vm_address_t)tgt, sizeof(body),
                                                    (mach_vm_address_t)body, &gb) == KERN_SUCCESS
                                                && gb == sizeof(body))
                                            {
                                                char hex[65];
                                                int off, b;
                                                for (off = 0; off < (int)sizeof(body); off += 32)
                                                {
                                                    for (b = 0; b < 32; b++)
                                                        snprintf(hex + b * 2, 3, "%02x", body[off + b]);
                                                    dprintf(STDERR_FILENO, "[guest-fn] [%d] callee %llx+%#x: %s\n",
                                                        e, (unsigned long long)tgt, off, hex);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        /* Build reply */
        ios_exc_reply_t reply;
        reply.head.msgh_bits = MACH_MSGH_BITS( MACH_MSGH_BITS_REMOTE(req->head.msgh_bits), 0 );
        reply.head.msgh_size = sizeof(reply);
        reply.head.msgh_remote_port = req->head.msgh_remote_port;
        reply.head.msgh_local_port = MACH_PORT_NULL;
        reply.head.msgh_id = req->head.msgh_id + 100;
        reply.ndr = NDR_record;
        reply.ret_code = handled ? KERN_SUCCESS : KERN_FAILURE;

        mach_msg( &reply.head, MACH_SEND_MSG, sizeof(reply), 0,
                  MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL );

        /* Deallocate the send rights we received */
        mach_port_deallocate( mach_task_self(), thread );
        mach_port_deallocate( mach_task_self(), req->task.name );
    }
    return NULL;
}

/* ml522 (#67): claim the TASK-level exception port for the fault masks we
 * already own per-thread.
 *
 * Until now the only registration we ever did was thread_set_exception_ports(),
 * so the TASK-level port belonged entirely to StikDebug. That is fine while the
 * debugger lives and fatal once it does not: when StikDebug goes away — jetsam
 * for its 48s-CPU-per-60s limit, or the user swiping it out of the app switcher
 * — the task port is left REGISTERED BUT UNSERVICED, and the first exception
 * that escalates past a thread port blocks the WHOLE TASK until the kernel
 * gives up on the dead name.
 *
 * That is #67. Measured at 53.9s / 53.7s / 54.2s across three unrelated runs
 * (Steam and Thumper, jetsam-kill and swipe-kill alike), and in the swipe run
 * bracketed by a single fault: [mach_exc] UNALIGNED-BACKPATCH #1 -> 53.9s of
 * whole-task silence -> #2. The cost is paid exactly ONCE — backpatches
 * #4..#200 afterwards were free — which is the signature of a one-shot dead
 * port teardown rather than per-fault work.
 *
 * Owning the task port ourselves removes the dead-name dependency outright,
 * and is also the precondition that makes a deliberate early detach safe.
 *
 * NOT claimed here: EXC_MASK_BREAKPOINT. BRK #0xf00d is the StikDebug JIT
 * protocol and must keep reaching the debugger while it is alive; after detach
 * a stray protocol BRK falls through to the BSD SIGTRAP path, which already
 * recognises it. Same reasoning as the per-thread mask (see ml353 note below).
 *
 * A fault we DECLINE at thread level now escalates to this same port and is
 * declined again, after which the kernel falls through to the host default and
 * delivers a BSD signal so wine's sigaction handlers run — the same end state
 * madeira-jit.js was hand-rolling with forwardSignal(). */
static void ios_install_task_exception_port(void)
{
    static int done = 0;
    exception_mask_t      old_masks[EXC_TYPES_COUNT];
    mach_port_t           old_ports[EXC_TYPES_COUNT];
    exception_behavior_t  old_behav[EXC_TYPES_COUNT];
    thread_state_flavor_t old_flav[EXC_TYPES_COUNT];
    mach_msg_type_number_t old_count = EXC_TYPES_COUNT, i;
    const char *gate;
    kern_return_t kr;

    if (done || ios_exc_port == MACH_PORT_NULL) return;
    done = 1;

    /* Opt-out only: this strictly removes a dependency on a port we do not own,
     * so it defaults ON. MADEIRA_TASK_EXC=0 restores the pre-ml522 behaviour for
     * a same-build A/B against the ~54s stall. */
    if ((gate = getenv( "MADEIRA_TASK_EXC" )) && gate[0] == '0')
    {
        ERR("[task-exc] DISABLED by MADEIRA_TASK_EXC=0 — task port stays with the debugger, "
            "#67's ~54s dead-port stall is expected rev=ml522\n");
        return;
    }

    /* ml523: EXC_MASK_BREAKPOINT is now claimed too. ml522 left it with the
     * debugger to keep BRK #0xf00d working, but the device log proved that was
     * the whole bug: both ~54s stalls in the 11:56/12:01 runs happened ~21s
     * after a FRESH StikDebug attach, i.e. with the debugger fully ALIVE. The
     * task is stopped waiting for a debugger that is starved by its own
     * busy-wait. FEX emits `brk #0xCAFE` inline for every suspend-interrupt
     * check, so trap traffic is continuous and unavoidable.
     * jit26_prepare_region already ran (Swift side, pre-wine) so the pool is
     * unaffected; jit26_detach()'s BRK now lands in trap_handler's 0xf00d case
     * instead of the debugger, which is harmless. */
    kr = task_swap_exception_ports( mach_task_self(),
                                    EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION |
                                    EXC_MASK_BREAKPOINT,
                                    ios_exc_port,
                                    (exception_behavior_t)(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
                                    ARM_THREAD_STATE64,
                                    old_masks, &old_count, old_ports, old_behav, old_flav );
    if (kr != KERN_SUCCESS)
    {
        ERR("[task-exc] task_swap_exception_ports FAILED kr=%d — the ~54s dead-port stall "
            "is STILL POSSIBLE rev=ml522\n", kr);
        return;
    }

    /* Log what we displaced. A non-null previous port is the debugger's, and is
     * precisely the name that would have gone dead underneath us. Release the
     * send rights the swap handed us — we never send to them. */
    ERR("[task-exc] INSTALLED ours=0x%x mask=ba+bi+brk displaced=%u rev=ml523\n",
        ios_exc_port, (unsigned)old_count);
    for (i = 0; i < old_count; i++)
    {
        ERR("[task-exc]   prev[%u] mask=0x%x port=0x%x behavior=0x%x flavor=%d%s\n",
            (unsigned)i, (unsigned)old_masks[i], (unsigned)old_ports[i],
            (unsigned)old_behav[i], (int)old_flav[i],
            old_ports[i] == MACH_PORT_NULL ? " (none — no debugger held it)" : " (debugger)");
        if (old_ports[i] != MACH_PORT_NULL)
            mach_port_deallocate( mach_task_self(), old_ports[i] );
    }
}

/* Register a Wine "process" thread with the shared Mach exception handler.
 * First call creates the shared port and handler thread.
 * Every call registers the thread and sets its exception ports. */
static int ios_pc_in_app_text( uint64_t pc );

static void ios_setup_mach_exception_handler( thread_t pe_thread, uintptr_t teb,
                                               void *trampoline )
{
    /* One-time initialization: create shared port and handler thread */
    if (!ios_exc_handler_started)
    {
        extern struct _KUSER_SHARED_DATA *user_shared_data;
        ios_exc_usd = (uintptr_t)user_shared_data;

        kern_return_t kr = mach_port_allocate( mach_task_self(),
                                                MACH_PORT_RIGHT_RECEIVE, &ios_exc_port );
        if (kr != KERN_SUCCESS) { ERR("mach exc port allocate: kr=%d\n", kr); return; }

        kr = mach_port_insert_right( mach_task_self(), ios_exc_port, ios_exc_port,
                                      MACH_MSG_TYPE_MAKE_SEND );
        if (kr != KERN_SUCCESS) { ERR("mach exc port insert: kr=%d\n", kr); return; }

        {
            const char *e = getenv( "MADEIRA_MACH_ALIGN_FAULT" );
            ios_mach_align_fault_enabled = !(e && e[0] == '0');
            if (!ios_mach_align_fault_enabled)
                ERR("[unaligned-atomic] Mach-path alignment classification DISABLED by "
                    "MADEIRA_MACH_ALIGN_FAULT=0: alignment faults are delivered as c0000005 there\n");
        }

        {
            /* the app's __TEXT range for the native-unaligned emulation, resolved here:
             * dyld's lookups do not belong on the exception thread */
            ios_pc_in_app_text( 0 );
        }

        pthread_t handler;
        pthread_create( &handler, NULL, ios_mach_exception_thread,
                        (void *)(uintptr_t)ios_exc_port );
        pthread_detach( handler );

        /* Stale-pointer heal scanner (see ios_stale_va_scanner above). */
        {
            pthread_t healer;
            pthread_create( &healer, NULL, ios_stale_va_scanner, NULL );
            pthread_detach( healer );
        }

        /* ml522 (#67): take the task-level port for our masks now that the
         * receive port and handler thread exist. Done here rather than at
         * detach time so there is never a window in which a fault can reach
         * a port whose owner has already died. */
        ios_install_task_exception_port();

        ios_exc_handler_started = 1;
    }

    /* Register this thread in the registry. */
    int idx = ios_thread_registry_add( pe_thread, teb, trampoline );

    /* Set exception port for this thread (shared port).
     * ml353: also claim EXC_BAD_INSTRUCTION. udf-class faults (executing
     * zeroed/garbage memory) previously bypassed us entirely and went
     * straight to StikDebug's task port — the app log was BLIND to the
     * instant-vanish deaths (ml351/ml354); only a hand-captured StikDebug
     * console named the pc. With the mask widened, the UNHANDLED dump
     * (pool-ledger, owner, insn stream, backtrace) self-documents them
     * before the decline escalates. EXC_BREAKPOINT (BRK JIT protocol) is a
     * DIFFERENT mask bit and still flows to StikDebug untouched. */
    kern_return_t kr = thread_set_exception_ports( pe_thread,
                                      EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION,
                                      ios_exc_port,
                                      (exception_behavior_t)(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
                                      ARM_THREAD_STATE64 );
    if (kr != KERN_SUCCESS) { ERR("mach exc set ports: kr=%d thread=0x%x\n", kr, pe_thread); return; }

    ERR("Mach exception handler registered thread 0x%x (idx=%d), teb=%p tramp=%p usd=%p mask=ba+bi rev=ml353\n",
        pe_thread, idx, (void*)teb, trampoline, (void*)ios_exc_usd);
}
