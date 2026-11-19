/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. NtAllocateVirtualMemoryEx, NtFreeVirtualMemory, NtQueryVirtualMemory. Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *             NtAllocateVirtualMemoryEx   (NTDLL.@)
 *             ZwAllocateVirtualMemoryEx   (NTDLL.@)
 */
/***********************************************************************
 *           ios_reserve_fex_arena   (ml756)
 *
 * Reserve FEX's host arena as a PLACEHOLDER, before any PE module loads.
 *
 * FEX used to pick its own band: probe a 16KB address, reserve 256MB, RELEASE
 * it, then declare the surrounding 4-8GB its own and hope later allocations
 * still won it. On the jailbroken research VM that fails two ways, and both
 * were observed. Sometimes no window exists at selection time -- one launch had
 * EVERY 4GB window from 32-63GB refuse even 16KB. Other times a window is found
 * and Wine then fills it: a selected 32-36GB band ended up holding 131 guest
 * images (PhysX, APEX, steam_api64, even libarm64ecfex), **70 of which were
 * already there before FEX chose it**, leaving an 11MB largest gap by the time
 * a 16MB FEX allocation failed. Probing a free hole says nothing about owning
 * the window.
 *
 * So Wine takes the arena first, and the RESERVATION IS THE CAPACITY PROBE --
 * no probe-and-release. Because the placeholder is a real Wine view, guest DLL
 * placement is excluded from it as a CONSEQUENCE rather than by a separate
 * mechanism. FEX later replaces placeholder slices instead of selecting a band.
 *
 * Sizes: hardware's dedicated high band is 16GB; the constrained regime wants
 * 8GB (4GB is demonstrably too tight -- FEX needs ~3.5GB of spans and code for
 * ~74 threads), with 4GB accepted only as an explicitly-logged limited arena.
 *
 * ⚠️ Runs ONCE per Mach task. Pseudo-processes share one address space, so the
 * arena must be reserved and published process-wide -- they must not each pick
 * one. The usual "ntdll-unix globals break pseudo-processes" rule is INVERTED
 * here: sharing is the intent.
 *
 * On failure it publishes nothing and returns quietly, leaving FEX's own
 * selector to behave exactly as before -- a failed reservation must never break
 * a configuration that works today.
 */
void ios_reserve_fex_arena(void)
{
    static int done;
    /* Several windows, largest first.
     *
     * The research VM's usable VA windows MOVE between launches, so a single
     * candidate is a coin flip: roughly half the launches ended with NO ARENA,
     * and every one of those died in FEX before its own logging init. A 4GB
     * reservation has been observed to work, so smaller is worth trying before
     * giving up -- the failure mode that matters is reserving NOTHING.
     * The VM's ceiling is 63GiB, so nothing above that can ever succeed. */
    static const struct { ULONG_PTR lo, hi; SIZE_T size; const char *what; } plan[] = {
        { 0x7c00000000ull, 0x7fffffffffull, 0x400000000ull, "hardware high band 16GB"  },
        { 0x0800000000ull, 0x0fffffffffull, 0x200000000ull, "constrained 8GB"          },
        { 0x0400000000ull, 0x07ffffffffull, 0x200000000ull, "8GB @16-32G"              },
        { 0x0200000000ull, 0x03ffffffffull, 0x200000000ull, "8GB @8-16G"               },
        { 0x0800000000ull, 0x0bffffffffull, 0x100000000ull, "4GB @32-48G"              },
        { 0x0c00000000ull, 0x0fbfffffffull, 0x100000000ull, "4GB @48-63G"              },
        { 0x0400000000ull, 0x07ffffffffull, 0x100000000ull, "4GB @16-32G"              },
        { 0x0200000000ull, 0x03ffffffffull, 0x100000000ull, "4GB @8-16G"               },
        { 0x0200000000ull, 0x0fbfffffffull, 0x080000000ull, "2GB anywhere low"         },
    };
    unsigned i;
    unsigned long long arena_task_max = 0;
    unsigned long long arena_size_cap = 0;   /* ml995 */

    if (done) return;
    done = 1;

    /* ml757: OPT-IN. This reservation is only half the design.
     *
     * FEX still runs ios_fex_band_select() and picks its own band, and on
     * hardware its ONLY candidate is [0x7c00000000,0x8000000000) -- exactly
     * what the 16GB reservation above takes. Reserving it therefore starves
     * FEX of the arena it was about to choose: no SELECTED line, no
     * FEXMem_ThreadState, dead before the first window. Shipping this
     * on-by-default regressed a working phone.
     *
     * The reservation is CORRECT and proven -- on the research VM it held 8GB
     * and kept all 123 guest images out of it, where the previous run had 131
     * inside FEX's band. It simply cannot be enabled until FEX consumes the
     * published range instead of selecting one. Until then: opt in with
     * Documents/madeira-arena.txt = 1, which is how the VM keeps testing it
     * while hardware stays on the proven path. */
    {
        /* ml786: the placeholder path is UNAVAILABLE, not merely off by default.
         *
         * Wine reserves a band; the emulator still runs its own selector and
         * picks a different one. Holding 8GB therefore pushes it into whatever
         * is left, and when that band is exhausted its 16MB requests fail, a
         * thread-creation path dereferences the NULL, the recursive fault
         * exhausts that thread's stack, and the thread dies OWNING
         * loader_section -- so the next module load blocks forever and the
         * process wedges with no error anywhere.
         *
         * An earlier change widened the search from three candidates to nine so
         * it would stop failing. That made an unfinished feature succeed more
         * often, which is the wrong direction: while the emulator selects
         * independently, a FAILED reservation is the safe outcome. The opt-in
         * returns only once it consumes WINE_IOS_FEX_ARENA_BASE/SIZE. */
        const char *opt = getenv( "MADEIRA_FEX_ARENA" );

        /* ml792 MILESTONE 1: "probe" proves the FULL reservation.
         *
         * Every earlier probe asked for 16KB or 256MB and then declared a
         * multi-GB window owned. That is not the same question: a window can
         * accept a small mapping and still have no contiguous 8GB hole. This
         * mode asks for the whole thing, holds it for the process lifetime,
         * and reports exactly what the kernel gave back.
         *
         * It is deliberately NOT the working feature. The emulator still runs
         * its own selector, so holding a band it does not consume makes x64
         * WORSE, not better -- that is the state that wedged the loader. This
         * mode exists to answer one question before anything is built on the
         * answer: can the range be reserved at all, and where? */
        if (opt && !strcmp( opt, "probe" ))
        {
            MEM_ADDRESS_REQUIREMENTS req;
            MEM_EXTENDED_PARAMETER param;
            void *base = NULL;
            SIZE_T size = 0x200000000ull;          /* 8GB, the whole thing */
            NTSTATUS status;

            memset( &req, 0, sizeof(req) );
            memset( &param, 0, sizeof(param) );
            req.LowestStartingAddress = (void *)0x0200000000ull;
            req.HighestEndingAddress  = (void *)0x0fbfffffffull;
            req.Alignment             = 0x10000;
            param.Type    = MemExtendedParameterAddressRequirements;
            param.Pointer = &req;

            status = NtAllocateVirtualMemoryEx( NtCurrentProcess(), &base, &size,
                                                MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
                                                PAGE_NOACCESS, &param, 1 );
            if (status)
                dprintf( 2, "[fex-arena] ml792 PROBE: full 8GB reservation FAILED status=%08x "
                            "in [0x200000000,0xfbfffffff] -- a contiguous 8GB hole does not exist "
                            "here at this point in startup\n", (unsigned)status );
            else
                dprintf( 2, "[fex-arena] ml792 PROBE: full 8GB RESERVED base=%p size=0x%llx and HELD "
                            "for the process lifetime. The emulator still selects its own band, so "
                            "x64 guests are EXPECTED TO FAIL this run -- this proves the range can "
                            "be taken, nothing more.\n", base, (unsigned long long)size );
            return;
        }

        /* ml799: ON by default, MADEIRA_FEX_ARENA=0 to disable.
         *
         * ml757 forced this off because the emulator ran its own selector
         * alongside the reservation, so holding a range only pushed FEX into
         * whatever was left. Both halves of that are now gone: ml797 hands the
         * range to FEX as plain data so it consumes rather than selects, and
         * the range is registered FEX_ONLY below so ordinary MEM_RESERVE
         * requests inside it are SERVED from it rather than refused over it.
         * An off switch stays, because this changes where every FEX allocation
         * lives and a one-variable A/B must remain possible. */
        if (opt && opt[0] == '0')
        {
            dprintf( 2, "[fex-arena] ml799 disabled by MADEIRA_FEX_ARENA=0 -- FEX selects its "
                        "own band, as before.\n" );
            return;
        }
    }

    /* ml801: the real ceiling, for judging placements the kernel chose for us. */
    {
        task_vm_info_data_t vmi;
        mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;
        if (task_info( mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &cnt ) == KERN_SUCCESS)
            arena_task_max = (unsigned long long)vmi.max_address;
    }

    /* ml995: cap the arena size from Documents/madeira-arena-mb.txt.
     *
     * rdr63 measured why this matters. At startup the usable VA below the 63 GB
     * ceiling is three holes: 4162 MB, 4992 MB and 9946 MB. The guest's own
     * reservation needs 8960 MB -- a hard floor, since rdr61..rdr63 proved the
     * request is max(7/8 x reported_phys, 8960 MB) and no memory-reporting value
     * lowers it. Only the 9946 MB hole can hold either the arena or the guest,
     * and the "constrained 8GB" step takes it: its FIXED placements all fell
     * inside CoreAnimation's range, so it kept an ANYWHERE placement that landed
     * at the bottom of that hole and left 1754 MB. The guest reservation then
     * fails with STATUS_NO_MEMORY.
     *
     * The arena had 8192 MB reserved and, per [va-own], 0 MB resident -- every
     * 128 MB sub-block inside it shows res=0. The ladder below already has 4 GB
     * steps and the comment above already records that "a 4GB reservation has
     * been observed to work"; they are simply never reached once 8 GB succeeds.
     * A 4 GB arena fits the 4992 MB hole and leaves the 9946 MB one for the
     * guest.
     *
     * This is a CAP, read from a file, with no default change: hardware keeps
     * the proven path and nothing regresses for the titles that depend on the
     * arena (Thumper, ULTRAKILL, Stray). If capping to 4 GB lets the guest
     * reservation through, the permanent fix is to make the size choice
     * adaptive -- never consume the largest free hole for a band that commits
     * nothing -- and that should land on evidence, not on this hypothesis. */
    {
        long long mb = madeira_cfg_int( "arena-mb", 0 );   /* ml1095: madeira.cfg arena-mb = N */
        if (mb > 0)
        {
            arena_size_cap = (unsigned long long)mb * 1024ull * 1024ull;
            dprintf( 2, "[fex-arena] ml995 size cap from arena-mb: %llu MB\n", arena_size_cap >> 20 );
        }
    }

    for (i = 0; i < ARRAY_SIZE(plan); i++)
    {
        if (arena_size_cap && (unsigned long long)plan[i].size > arena_size_cap)
        {
            dprintf( 2, "[fex-arena] ml995 SKIP %s (%llu MB) -- over the %llu MB cap\n",
                     plan[i].what, (unsigned long long)plan[i].size >> 20,
                     arena_size_cap >> 20 );
            continue;
        }
        /* ml799: hold the range NATIVELY as PROT_NONE, with no Windows view.
         *
         * A MEM_RESERVE_PLACEHOLDER view was the wrong instrument: it puts an
         * entry in Wine's view tree, and every later ordinary MEM_RESERVE from
         * rpmalloc/FEXCore/CallRetStack would then have to reserve OVER it and
         * fail. A native PROT_NONE mapping registered as a reserved area is the
         * shape Wine already knows how to allocate out of -- views are carved
         * from it normally, and unmap_area() restores PROT_NONE on free.
         *
         * VM_FLAGS_ANYWHERE with the window's base as the hint searches upward,
         * so the result must be CHECKED against the window rather than assumed:
         * a mapping that landed outside is worse than none, because the whole
         * point is that FEX and Wine agree on where the arena is. */
        mach_vm_address_t addr = (mach_vm_address_t)plan[i].lo;
        SIZE_T size = plan[i].size;
        void *base;
        kern_return_t kr;

        /* madeira-bcd: env.MADEIRA_SC_PA_POOLS = 1 moves the first candidate 4 GB
         * up and holds the 4 GB below it (ios_sc_pa_hold_arena); without it this
         * is never taken. */
        if (i == 0 && ios_sc_pa_hold_arena( &addr, &size )) goto sc_arena_placed;

        /* ml802: 64KiB alignment mask. Wine's allocation granularity is 64KiB and
         * FEX asks with Alignment=0x10000; a base that is merely page-aligned
         * would make the first granule unusable and silently shrink the arena. */
        kr = mach_vm_map( mach_task_self(), &addr, (mach_vm_size_t)size, 0xffff, VM_FLAGS_ANYWHERE,
                          MEMORY_OBJECT_NULL, 0, 0, PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
        if (kr != KERN_SUCCESS)
        {
            dprintf( 2, "[fex-arena] ml799 %s: native reserve FAILED kr=%d\n",
                     plan[i].what, (int)kr );
            continue;
        }
        if (ios_layerkit_hi && addr + size > ios_layerkit_lo && addr < ios_layerkit_hi)
        {
            /* ml900/ml901: the kernel put the arena inside CoreAnimation's tag-51
             * range (ants39: 8 of its 9.7 GB). Give it back and walk FIXED
             * candidates above the span (up to the task ceiling), then below it
             * (down to 8 GB), 1 GB apart. ml900 tried exactly one address each
             * way, both came back KERN_INVALID_ADDRESS, and the boot died with
             * no arena at all -- so if every candidate fails, take the ANYWHERE
             * placement back: a starved CoreAnimation is survivable, no arena is not. */
            mach_vm_address_t orig = addr, cand; unsigned tries = 0; kern_return_t k2 = KERN_FAILURE;
            mach_vm_deallocate( mach_task_self(), addr, (mach_vm_size_t)size );
            for (cand = (ios_layerkit_hi + 0xffff) & ~0xffffULL;
                 arena_task_max && cand + size <= arena_task_max && k2 != KERN_SUCCESS && tries < 64;
                 cand += 1ULL << 30, tries++)
            {
                addr = cand;
                k2 = mach_vm_map( mach_task_self(), &addr, (mach_vm_size_t)size, 0xffff, VM_FLAGS_FIXED,
                                  MEMORY_OBJECT_NULL, 0, 0, PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
            }
            for (cand = (ios_layerkit_lo - size) & ~0xffffULL;
                 ios_layerkit_lo >= size && cand >= 0x200000000ULL && k2 != KERN_SUCCESS && tries < 128;
                 cand -= 1ULL << 30, tries++)
            {
                addr = cand;
                k2 = mach_vm_map( mach_task_self(), &addr, (mach_vm_size_t)size, 0xffff, VM_FLAGS_FIXED,
                                  MEMORY_OBJECT_NULL, 0, 0, PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
                if (cand < (1ULL << 30)) break;
            }
            if (k2 != KERN_SUCCESS)
            {
                addr = orig;
                k2 = mach_vm_map( mach_task_self(), &addr, (mach_vm_size_t)size, 0xffff, VM_FLAGS_ANYWHERE,
                                  MEMORY_OBJECT_NULL, 0, 0, PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
                dprintf( 2, "[fex-arena] ml901 %s: no FIXED home outside CoreAnimation's range 0x%llx..0x%llx after %u tries; "
                            "keeping the ANYWHERE placement at 0x%llx (kr=%d) -- CoreAnimation may starve later\n",
                         plan[i].what, ios_layerkit_lo, ios_layerkit_hi, tries, (unsigned long long)addr, (int)k2 );
                if (k2 != KERN_SUCCESS) continue;
            }
            else
                dprintf( 2, "[fex-arena] ml901 %s: moved out of CoreAnimation's range 0x%llx..0x%llx to 0x%llx after %u tries\n",
                         plan[i].what, ios_layerkit_lo, ios_layerkit_hi, (unsigned long long)addr, tries );
        }
        if (addr < plan[i].lo || addr + size > plan[i].hi)
        {
            /* ml801: an out-of-window placement is NOT automatically wrong.
             *
             * VM_FLAGS_ANYWHERE treats the window base as a floor and searches
             * upward; it has no notion of the upper bound. ml799 discarded any
             * range that overran the window, and threw away two perfectly good
             * 8GB reservations in a row because the kernel started them 25GB in
             * -- inside the window, but ending past its top. That run fell
             * through to a 4GB candidate and Stray exhausted it at 57 threads.
             *
             * The windows are HINTS for steering placement. What must actually
             * be true is that the range is entirely mappable and that FEX is
             * told where it is -- which the ml800 hand-off does regardless of
             * which window it came from. So keep it when it fits under the task
             * ceiling, and say plainly that it was not where we asked. */
            if (arena_task_max && (unsigned long long)addr + size <= arena_task_max)
            {
                dprintf( 2, "[fex-arena] ml801 %s: kernel placed the range at 0x%llx, outside the "
                            "requested window [0x%llx,0x%llx] but entirely below the task ceiling "
                            "0x%llx -- KEEPING it; the window is a hint and the emulator is told "
                            "the real address\n", plan[i].what, (unsigned long long)addr,
                         (unsigned long long)plan[i].lo, (unsigned long long)plan[i].hi,
                         arena_task_max );
            }
            else
            {
                dprintf( 2, "[fex-arena] ml801 %s: kernel placed the range at 0x%llx+0x%llx, which "
                            "runs past the task ceiling 0x%llx -- releasing it; that range can "
                            "never be mapped\n", plan[i].what, (unsigned long long)addr,
                         (unsigned long long)size, arena_task_max );
                mach_vm_deallocate( mach_task_self(), addr, (mach_vm_size_t)size );
                continue;
            }
        }
    sc_arena_placed:
        base = (void *)(ULONG_PTR)addr;
        if (!mmap_add_fex_reserved_area( base, size ))
        {
            /* ml802: registration failed, so nothing would serve allocations
             * from this range -- but the mapping is still ours. Leaving it held
             * while publishing nothing is the worst of both worlds: FEX runs its
             * own selector and has LESS space than with no reservation at all,
             * which is exactly the ml757 failure. Give the range back. */
            ERR( "[fex-arena] ml802 registration FAILED for %p+%llx -- releasing the reservation "
                 "so the emulator's own selector is not left competing with a range Wine still "
                 "holds\n", base, (unsigned long long)size );
            mach_vm_deallocate( mach_task_self(), addr, (mach_vm_size_t)size );
            /* madeira-bcd: the moved arena failed -- drop the hold, retry this
             * candidate where it always was */
            if (ios_sc_brp_layout) { ios_sc_pa_drop_hold(); i--; }
            continue;
        }

        {
            /* ml793 step 2: publish an EXACT half-open range [base, base+size).
             *
             * The version is part of the contract, not decoration: the consumer
             * must be able to tell "no arena published" from "an arena
             * published by a build that meant something different". A silent
             * mismatch is how the two sides ended up believing different ranges
             * belonged to them. */
            char b[64];
            snprintf( b, sizeof(b), "%llx", (unsigned long long)(ULONG_PTR)base );
            setenv( "WINE_IOS_FEX_ARENA_BASE", b, 1 );
            snprintf( b, sizeof(b), "%llx", (unsigned long long)size );
            setenv( "WINE_IOS_FEX_ARENA_SIZE", b, 1 );
            snprintf( b, sizeof(b), "%llx", (unsigned long long)((ULONG_PTR)base + size) );
            setenv( "WINE_IOS_FEX_ARENA_END", b, 1 );   /* exclusive */
            setenv( "WINE_IOS_FEX_ARENA_VERSION", "1", 1 );
            ios_fex_arena_base_unix = (ULONG_PTR)base;
            ios_fex_arena_end_unix  = (ULONG_PTR)base + size;
            dprintf( 2, "[fex-arena] ml793 PUBLISHED [%p,0x%llx) size=0x%llx version=1 -- the "
                        "emulator must CONSUME this range; it must not run its own selector\n",
                     base, (unsigned long long)((ULONG_PTR)base + size),
                     (unsigned long long)size );
        }
        dprintf( 2, "[fex-arena] ml799 RESERVED %s base=%p size=0x%llx -- held natively as "
                    "PROT_NONE for the process lifetime and registered FEX_ONLY; generic "
                    "placement cannot allocate here\n",
                 plan[i].what, base, (unsigned long long)size );
        if (size < 0x200000000ull)
            dprintf( 2, "[fex-arena] ml774 WARNING: only 0x%llx bytes. Sufficient for small "
                        "guests; heavy titles are expected to exhaust it.\n",
                     (unsigned long long)size );
        return;
    }

    /* Every candidate failed. On the VM this reliably means the launch is dead:
     * FEX picks its own band and dies before its first log line. Say so in the
     * terms the operator needs -- relaunch, do not read anything into it. */
    dprintf( 2, "[fex-arena] ml774 NO ARENA RESERVED after %u candidates -- FEX will select "
                "its own band. On the research VM this launch is EXPECTED TO DIE before "
                "FEX initialises; relaunch rather than diagnosing it.\n",
             (unsigned)ARRAY_SIZE(plan) );
}

NTSTATUS WINAPI NtAllocateVirtualMemoryEx( HANDLE process, PVOID *ret, SIZE_T *size_ptr, ULONG type,
                                           ULONG protect, MEM_EXTENDED_PARAMETER *parameters,
                                           ULONG count )
{
    static const ULONG type_mask = MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH
                                   | MEM_RESET | MEM_RESERVE_PLACEHOLDER | MEM_REPLACE_PLACEHOLDER;
    ULONG_PTR limit_low = 0;
    ULONG_PTR limit_high = 0;
    ULONG_PTR align = 0;
    ULONG attributes = 0;
    USHORT machine = 0;
    unsigned int status;
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
                     "NtAllocateVirtualMemoryEx", execalloc_n, ret ? *ret : NULL,
                     (unsigned long long)(size_ptr ? *size_ptr : 0), type, protect );
        }
    }
#endif

    TRACE( "%p %p %08lx %x %08x %p %u\n",
          process, *ret, *size_ptr, type, protect, parameters, count );

    status = get_extended_params( parameters, count, &limit_low, &limit_high,
                                  &align, &attributes, &machine );
    if (status) return status;

#ifdef WINE_IOS
    {
        static int alloc_ex_dbg = 0;
        if (alloc_ex_dbg++ < 30)
            ERR("NtAllocateVirtualMemoryEx: size=0x%lx type=0x%x prot=0x%x attrs=0x%x machine=0x%x param_count=%u\n",
                (unsigned long)*size_ptr, type, protect, attributes, machine, count);
    }
#endif

    if (type & ~type_mask) return STATUS_INVALID_PARAMETER;
    if (*ret && (align || limit_low || limit_high)) return STATUS_INVALID_PARAMETER;
    if (!*size_ptr) return STATUS_INVALID_PARAMETER;

#ifdef WINE_IOS
    /* iOS-Madeira: For FEX-style EC_CODE RWX allocations, allocate from the
     * JIT pool RX range directly. This avoids the cross-region RIP-relative
     * addressing problem: when emit_VA == execute_VA (both are the JIT pool
     * RX alias), ADRP/ADR/B/BL offsets calculated at emit time work correctly
     * at execution time. iOS won't grant exec on arbitrary user_VA, but the
     * JIT pool RX alias (mapped via mach_make_memory_entry_64+vm_map) is
     * genuinely R+X. Writes via STR fault emulation route through the RW
     * alias at the same offset within the pool.
     *
     * Triggered by: NtAllocateVirtualMemoryEx with attrs containing
     * MEM_EXTENDED_PARAMETER_EC_CODE (0x40) and prot=PAGE_EXECUTE_READWRITE,
     * caller-supplied address NULL (kernel-pick). */
    if (process == NtCurrentProcess() &&
        (attributes & 0x40 /* MEM_EXTENDED_PARAMETER_EC_CODE_FLAG */) &&
        protect == PAGE_EXECUTE_READWRITE &&
        *ret == NULL &&
        ios_jit_rx_base_global && ios_jit_rw_base_global &&
        ios_jit_pool_size_global)
    {
        size_t alloc_size = (*size_ptr + 0x3FFF) & ~0x3FFFUL;
        /* madeira-bcd pool-low: region C (ios_jit_low_rx_global) serves this carve
         * first when it still has room; the pool's budget cap below only applies to
         * what goes to the tail. Never for a WoW64 process: its FEX refuses an
         * executable allocation outside the pool span. */
        int low_ok = ios_jit_low_size_global && !ios_wow_base();
        int low_fits = low_ok && alloc_size <= IOS_POOL_LOW_CARVE_MAX &&
                       alloc_size <= ios_jit_low_size_global &&
                       ios_jit_low_reserved <= ios_jit_low_size_global - alloc_size;
        int kept_large_carve = 0, kept_big_carve = 0, reuse_all_carves = 0, retired_busy = 0;
        size_t tail_cap = ~(size_t)0, budget_cap = ~(size_t)0;
        void *carve_peb = ios_jit_current_peb();   /* madeira-bcd: the carve's owner, see ios_tail_carve_ready */
        /* ml459 (#75): cap a single EC code buffer at 16MB. FEX asks for 32MB
         * once its buffers get hot, but an old generation stays pinned by any
         * thread still referencing it (see [pool-tail] PIN) — and a 32MB
         * generation pinned while 10% full wastes 29MB of a pool the head is
         * fighting us for (ml458: tail 214MB, head 682MB, died 1MB short).
         * Refusing the oversized ask is SAFE and already-exercised: FEX's
         * CodeBuffer ctor halves down the ladder on failure, and this run's own
         * log shows "exec alloc degraded 0x2000000 -> 0x400000" followed by
         * normal execution. Smaller generations waste less per pin; the
         * [pool-tail] census says whether pinning or churn dominates. */
        /* iOS-Madeira ml480 (#84): the flat 16MB refusal above made EVERY hot
         * thread rotate its code buffer constantly. ml479's run: 79 tail
         * events, 267k real compiles, and a compile-miss rate PINNED at ~19-20%
         * for the whole run (a warmed-up workload should approach 0). Each
         * rotation discards that thread's compiled code, so the SteamUI frame
         * thread spends its frames recompiling — Steam itself reported "frame
         * stalled for: 32818 ms", which is why its accept() loop only drains
         * the listen backlog every 2-3 minutes and CEF's ~12s websocket
         * handshake ALWAYS times out (the login window can never come up).
         *
         * Budget-aware cap instead of a flat one: grant 32MB while the tail is
         * under the watermark (measured peak tail_resv was 112MB of the 256MB
         * tail; head peaked 682MB of its 896MB budget), and fall back to the
         * proven 16MB refusal once the tail is loaded. Hot threads that rotate
         * early get big buffers; late/idle threads still get real ones, so the
         * ml436 exhaustion (10 refusals, 123 degraded threads) can't return. */
        {
            /* ml1052: the cap was 32 MB (16 MB once the tail passed 160 MB). FEX
             * keeps ONE shared code buffer per process and discards every
             * translation when it fills, so a program whose hot code does not
             * fit retranslates forever: one run measured 12.5M block lookups,
             * 5.5M real compiles (56 % hit rate), 390 buffer rotations, and a
             * quarter of all running CPU samples inside the compiler. The cap is
             * now what the pool can actually afford: up to 128 MB (the branch
             * range FEX itself limits a buffer to) with a headroom target between
             * the image head and the tail (48MB by default). */
            enum { TAIL_SMALL = 0x1000000 };
            size_t head_now = jit_pool_offset, tail_now = ios_jit_tail_reserved;
            /* Neither the native hole nor either placement of the image slot
             * is available to the tail. Default headroom remains 48MB. Pool-mid's
             * second hole is not room either: counted with the headroom. */
            size_t cap = ios_pool_code_cap( ios_jit_pool_size_global, head_now, tail_now,
                                            ios_jit_hole_off_eff, ios_jit_hole_end_eff,
                                            ios_pool_head_reserve +
                                            ios_pool_hole_between( ios_jit_pool_size_global, head_now, tail_now,
                                                                   ios_jit_hole2_off, ios_jit_hole2_end ) );
            /* A retired generation of this size already sitting on the carve
             * free-list costs the pool nothing new: never refuse that. */
            budget_cap = cap;
            if (alloc_size > cap)
            {
                unsigned fi;
                time_t now = time( NULL );
                pthread_mutex_lock( &ios_tail_carve_lock );
                for (fi = 0; fi < ios_tail_carve_n; fi++)
                    if (ios_tail_carve_ready( &ios_tail_carves[fi], now ) && ios_tail_carves[fi].size >= alloc_size &&
                        (low_ok || !ios_tail_carve_in_low( ios_tail_carves[fi].off ))) { cap = alloc_size; break; }
                pthread_mutex_unlock( &ios_tail_carve_lock );
            }
            tail_cap = cap;

            if (alloc_size > cap && !low_fits) {
                static int cap_log_n;
                if (cap_log_n < 16) {
                    cap_log_n++;
                    dprintf(2, "[jit-pool] tail CAP: refusing 0x%lx (cap 0x%lx, tail_resv=0x%lx) so FEX halves down rev=ml480\n",
                            (unsigned long)alloc_size, (unsigned long)cap,
                            (unsigned long)ios_jit_tail_reserved);
                }
                return STATUS_NO_MEMORY;
            }
            if (alloc_size > TAIL_SMALL && !low_fits) {
                static int big_log_n;
                if (big_log_n < 16) {
                    big_log_n++;
                    dprintf(2, "[jit-pool] tail BIG: granting 0x%lx (tail_resv=0x%lx) rev=ml480\n",
                            (unsigned long)alloc_size, (unsigned long)ios_jit_tail_reserved);
                }
            }
        }
        /* ml438 (#74): serve from the free-list first — see ios_tail_carves. */
retry_code_carve_reuse:
        {
            unsigned i, best = ~0u;
            time_t now = time( NULL );
            pthread_mutex_lock( &ios_tail_carve_lock );
            for (i = 0; i < ios_tail_carve_n; i++)
                if (ios_tail_carve_ready( &ios_tail_carves[i], now ) && ios_tail_carves[i].size >= alloc_size &&
                    (low_ok || !ios_tail_carve_in_low( ios_tail_carves[i].off )) &&   /* madeira-bcd pool-low */
                    (best == ~0u || ios_tail_carves[i].size < ios_tail_carves[best].size))
                    best = i;
            if (best != ~0u && !reuse_all_carves &&
                ios_pool_preserve_code_carve( ios_tail_carves[best].size, alloc_size, low_fits ))
            {
                kept_large_carve = 1;
                best = ~0u;
            }
            else if (best != ~0u && !reuse_all_carves &&
                     ios_pool_preserve_big_carve( ios_tail_carves[best].size, alloc_size, budget_cap ))
            {
                kept_big_carve = 1;
                best = ~0u;
            }
            /* madeira-bcd: a dead process's buffer, only when no thread runs in it;
             * a busy one starts its grace again and the next one is tried */
            if (best != ~0u && ios_tail_carves[best].retired &&
                ios_tail_carve_scan( (char *)ios_jit_rx_base_global + ios_tail_carves[best].off,
                                     ios_tail_carves[best].size, 1 ))
            {
                static unsigned busy_n;
                void *busy_rx = (char *)ios_jit_rx_base_global + ios_tail_carves[best].off;
                size_t busy_size = ios_tail_carves[best].size;

                ios_tail_carves[best].freed_at = now;
                pthread_mutex_unlock( &ios_tail_carve_lock );
                retired_busy = 1;
                if (++busy_n <= 32)
                    dprintf(2, "[jit-pool] tail REUSE skipped rx=%p size=0x%lx: a thread runs in this dead process's "
                            "buffer, or a thread's state could not be read (madeira-bcd)\n", busy_rx, (unsigned long)busy_size);
                goto retry_code_carve_reuse;
            }
            if (best != ~0u)
            {
                void *jit_rx = (char *)ios_jit_rx_base_global + ios_tail_carves[best].off;
                void *jit_rw = (char *)ios_jit_rw_base_global + ios_tail_carves[best].off;
                size_t got = ios_tail_carves[best].size;
                int was_retired = ios_tail_carves[best].retired;
                ios_tail_carves[best].free = 0;
                ios_tail_carves[best].retired = 0;
                ios_tail_carves[best].peb = carve_peb;
                pthread_mutex_unlock( &ios_tail_carve_lock );
                {
                    volatile uint32_t *rw_words = (volatile uint32_t *)jit_rw;
                    size_t nwords = got / sizeof(uint32_t);
                    for (size_t i2 = 0; i2 < nwords; i2++) rw_words[i2] = 0xd503201fu;  /* NOP-prefill, same as fresh carves */
                }
                *ret = jit_rx;
                *size_ptr = got;
                dprintf(2, "[jit-pool] tail REUSE rx=%p size=0x%lx (asked 0x%lx) free_left=%u rev=ml438%s%s\n",
                        jit_rx, (unsigned long)got, (unsigned long)alloc_size, ios_tail_carve_n,
                        ios_jit_low_contains( (uintptr_t)jit_rx ) ? " [pool-low] region C" : "",
                        was_retired ? " (a dead process's buffer)" : "");
                return STATUS_SUCCESS;
            }
            pthread_mutex_unlock( &ios_tail_carve_lock );
        }
        /* madeira-bcd: the cap was lifted for a dead process's buffer that a thread
         * still runs in, so the pool's budget applies again (FEX halves down) */
        if (retired_busy)
        {
            tail_cap = budget_cap;
            if (alloc_size > tail_cap && !low_fits)
            {
                dprintf(2, "[jit-pool] tail CAP: refusing 0x%lx (cap 0x%lx, tail_resv=0x%lx): the dead process's "
                        "buffer it counted on is still in use (madeira-bcd)\n", (unsigned long)alloc_size,
                        (unsigned long)tail_cap, (unsigned long)ios_jit_tail_reserved);
                return STATUS_NO_MEMORY;
            }
        }
        /* madeira-bcd pool-low: carve from region C's bottom. The carve goes into
         * ios_tail_carves with `off` = its (wrapping) distance from the pool's RX
         * base, so the free, reuse, lookup and census paths treat it like any other
         * carve, and rw + off is its RW alias (C's alias is at the same distance). */
        if (low_ok)
        {
            size_t loff;
            if (low_fits && ios_pool_low_take( &ios_jit_low_reserved, ios_jit_low_size_global, alloc_size, &loff ))
            {
                void *jit_rx = (void *)(ios_jit_low_rx_global + loff);
                volatile uint32_t *rw_words = (volatile uint32_t *)(ios_jit_low_rw_global + loff);
                size_t w, nwords = alloc_size / sizeof(uint32_t);

                for (w = 0; w < nwords; w++) rw_words[w] = 0xd503201fu;   /* NOP-prefill, as for tail carves */
                pthread_mutex_lock( &ios_tail_carve_lock );
                if (ios_tail_carve_n < IOS_TAIL_CARVE_MAX)
                {
                    ios_tail_carves[ios_tail_carve_n].off = (size_t)((uintptr_t)jit_rx - (uintptr_t)ios_jit_rx_base_global);
                    ios_tail_carves[ios_tail_carve_n].size = alloc_size;
                    ios_tail_carves[ios_tail_carve_n].free = 0;
                    ios_tail_carves[ios_tail_carve_n].freed_at = 0;
                    ios_tail_carves[ios_tail_carve_n].peb = carve_peb;
                    ios_tail_carves[ios_tail_carve_n].retired = 0;
                    ios_tail_carve_n++;
                }
                pthread_mutex_unlock( &ios_tail_carve_lock );
                dprintf(2, "[pool-low] EC_CODE rx=%p size=0x%lx from region C: used 0x%lx/0x%lx (pool tail_resv=0x%lx "
                        "head_used=0x%lx/0x%lx untouched)\n",
                        jit_rx, (unsigned long)alloc_size, (unsigned long)(loff + alloc_size),
                        (unsigned long)ios_jit_low_size_global, (unsigned long)ios_jit_tail_reserved,
                        (unsigned long)jit_pool_offset, (unsigned long)ios_jit_pool_size_global);
                *ret = jit_rx;
                *size_ptr = alloc_size;
                return STATUS_SUCCESS;
            }
            /* Another thread may have consumed C after the budget snapshot.
             * Retry the original freelist policy once, rather than leaking a
             * new tail carve or refusing an allocation that used to work. */
            if (kept_large_carve && !reuse_all_carves)
            {
                reuse_all_carves = 1;
                low_fits = 0;
                goto retry_code_carve_reuse;
            }
            if (alloc_size <= IOS_POOL_LOW_CARVE_MAX && ios_jit_low_full_logged < 4)
            {
                ios_jit_low_full_logged++;
                dprintf(2, "[pool-low] region C has 0x%lx of 0x%lx left, not enough for carve 0x%lx: it goes to the "
                        "pool tail (freed C carves are still reused first)\n",
                        (unsigned long)(ios_jit_low_size_global - ios_jit_low_reserved),
                        (unsigned long)ios_jit_low_size_global, (unsigned long)alloc_size);
            }
            /* C could not take it after all (another thread got there first):
             * the tail's budget cap applies, as it would have without C. */
            if (alloc_size > tail_cap)
            {
                dprintf(2, "[jit-pool] tail CAP: refusing 0x%lx (cap 0x%lx, tail_resv=0x%lx, region C full) so FEX "
                        "halves down [pool-low]\n", (unsigned long)alloc_size, (unsigned long)tail_cap,
                        (unsigned long)ios_jit_tail_reserved);
                return STATUS_NO_MEMORY;
            }
        }
        /* Reserve from the END of the JIT pool to avoid colliding with
         * mprotect_exec's PE-image copies which take from the start.
         * ios_jit_tail_reserved is the shared file-scope counter so the
         * head allocators can refuse to grow into tail-carved buffers. */
        size_t reserve_offset, tail_added, tail_skipped = 0;
        size_t skip_off[3], skip_size[3];
        int skip_n = 0;
        if (ios_jit_hole_end > ios_jit_hole_off)
        {
            /* madeira-bcd split pool: a carve that would overlap a hole goes
             * directly below it; the span it skips above the hole becomes a free
             * carve once this one is granted (pool-mid: up to two such spans,
             * the hole 2 one and the one between the holes). */
            size_t cur, start;
            do
            {
                cur = ios_jit_tail_reserved;
            start = ios_pool_holes_tail_start( ios_jit_pool_size_global, cur, alloc_size,
                                                   ios_jit_hole_off_eff, ios_jit_hole_end_eff,
                                                   ios_jit_hole2_off, ios_jit_hole2_end );
            } while (!__sync_bool_compare_and_swap( &ios_jit_tail_reserved, cur, start + alloc_size ));
            reserve_offset = start;
            tail_added = start + alloc_size - cur;
            if (start != cur && start <= ios_jit_pool_size_global && cur <= start)
            {
                int k;
                skip_n = ios_pool_skip_pieces( ios_jit_pool_size_global - start, ios_jit_pool_size_global - cur,
                                               ios_jit_hole_off_eff, ios_jit_hole_end_eff,
                                               ios_jit_hole2_off, ios_jit_hole2_end, skip_off, skip_size );
                for (k = 0; k < skip_n; k++) tail_skipped += skip_size[k];
            }
        }
        else
        {
            reserve_offset = __sync_fetch_and_add(&ios_jit_tail_reserved, alloc_size);
            tail_added = alloc_size;
        }
        size_t pool_tail_off = ios_jit_pool_size_global - reserve_offset - alloc_size;
        /* ml1052: was "tail may never exceed half the pool", a rule from a
         * workload whose HEAD was 700 MB. The real constraint is the collision. */
        if (reserve_offset + alloc_size > (ios_jit_pool_size_global / 4) * 3 ||
            pool_tail_off < jit_pool_offset)
        {
            /* ml1039: before refusing, take a reclaimed head range if one fits. */
            {
                size_t foff = ios_pool_take_freed_for_tail( alloc_size );
                if (foff != (size_t)-1)
                {
                    void *f_rx = (char *)ios_jit_rx_base_global + foff;
                    volatile uint32_t *f_rw = (volatile uint32_t *)((char *)ios_jit_rw_base_global + foff);
                    size_t w, nw = alloc_size / sizeof(uint32_t);

                    ios_pool_tail_unreserve( &ios_jit_tail_reserved, reserve_offset + alloc_size, tail_added,
                                             ios_jit_hole_end > ios_jit_hole_off );   /* not a tail carve */
                    for (w = 0; w < nw; w++) f_rw[w] = 0xd503201fu;             /* NOP-prefill, as for fresh carves */
                    pthread_mutex_lock( &ios_tail_carve_lock );
                    if (ios_tail_carve_n < IOS_TAIL_CARVE_MAX)
                    {
                        ios_tail_carves[ios_tail_carve_n].off = foff;
                        ios_tail_carves[ios_tail_carve_n].size = alloc_size;
                        ios_tail_carves[ios_tail_carve_n].free = 0;
                        ios_tail_carves[ios_tail_carve_n].freed_at = 0;
                        ios_tail_carves[ios_tail_carve_n].peb = carve_peb;
                        ios_tail_carves[ios_tail_carve_n].retired = 0;
                        ios_tail_carve_n++;
                    }
                    pthread_mutex_unlock( &ios_tail_carve_lock );
                    dprintf(2, "[jit-pool] ml1039 tail served from a RECLAIMED HEAD range rx=%p size=0x%lx "
                               "(tail_resv=0x%lx head_used=0x%lx/0x%lx) -- this request used to be REFUSED\n",
                            f_rx, (unsigned long)alloc_size, (unsigned long)ios_jit_tail_reserved,
                            (unsigned long)jit_pool_offset, (unsigned long)ios_jit_pool_size_global);
                    *ret = f_rx;
                    *size_ptr = alloc_size;
                    return STATUS_SUCCESS;
                }
            }
            /* iOS-Madeira ml421 (ml420 death): the old "fall through to normal
             * allocation" is ALWAYS fatal for FEX — the normal path hands back
             * guest-band memory whose exec-enable silently fails (ml363), and
             * ClearCache then wild-writes through the unusable buffer
             * (ml361/ml420: Arm64JITCore::ClearCache+0x5c, dest = 2x the
             * guest-band base). Fail the allocation HONESTLY instead: FEX's
             * CodeBuffer ctor (rev=ml364) sees NULL, halves the request down
             * to 1MB (small carves can still fit pool gaps), and if nothing
             * fits forces the diagnosable 0xdead fault. Also roll back the
             * tail reservation — the old path leaked it on every refusal. */
            ios_pool_tail_unreserve( &ios_jit_tail_reserved, reserve_offset + alloc_size, tail_added,
                                     ios_jit_hole_end > ios_jit_hole_off );
            /* a free carve was kept back for a bigger request: use it after all */
            if ((kept_large_carve || kept_big_carve) && !reuse_all_carves)
            {
                reuse_all_carves = 1;
                goto retry_code_carve_reuse;
            }
            ERR("NtAllocateVirtualMemoryEx iOS: JIT-pool tail exhausted for FEX EC_CODE %zu bytes\n",
                (size_t)*size_ptr);
            /* ml459 (#75): dump the carve table on the FIRST refusal — the
             * question the ml458 log could not answer is whether the 214MB
             * tail is LIVE (generations pinned by threads) or merely churned
             * and never returned. free=0 rows are the pinned set; cross-check
             * against [pool-tail] PIN lines to name their owners. */
            {
                static int census_done;
                if (!census_done)
                {
                    unsigned ci; size_t live = 0, freed = 0;
                    census_done = 1;
                    pthread_mutex_lock( &ios_tail_carve_lock );
                    for (ci = 0; ci < ios_tail_carve_n; ci++)
                    {
                        dprintf(2, "[pool-tail] carve[%u] off=0x%lx size=0x%lx %s rev=ml459%s\n",
                                ci, (unsigned long)ios_tail_carves[ci].off,
                                (unsigned long)ios_tail_carves[ci].size,
                                !ios_tail_carves[ci].free ? "LIVE" : ios_tail_carves[ci].retired ? "FREE (owner exited)" : "FREE",
                                ios_tail_carve_in_low( ios_tail_carves[ci].off ) ? " [pool-low] region C" : "");
                        if (ios_tail_carves[ci].free) freed += ios_tail_carves[ci].size;
                        else live += ios_tail_carves[ci].size;
                    }
                    pthread_mutex_unlock( &ios_tail_carve_lock );
                    dprintf(2, "[pool-tail] TOTALS carves=%u live=0x%lx (%lu MB) free=0x%lx (%lu MB) rev=ml459\n",
                            ios_tail_carve_n, (unsigned long)live, (unsigned long)(live >> 20),
                            (unsigned long)freed, (unsigned long)(freed >> 20));
                }
            }
            dprintf(2, "[jit-pool] TAIL REFUSED (FEX EC_CODE): want=0x%lx tail_resv=0x%lx head_used=0x%lx/0x%lx — REFUSING honestly rev=ml421 (was: fall to normal alloc = guest-band non-exec buffer = ClearCache wild write)\n",
                    (unsigned long)alloc_size, (unsigned long)reserve_offset,
                    (unsigned long)jit_pool_offset, (unsigned long)ios_jit_pool_size_global);
            return STATUS_NO_MEMORY;
        }
        else
        {
            void *jit_rx = (char *)ios_jit_rx_base_global + pool_tail_off;
            void *jit_rw = (char *)ios_jit_rw_base_global + pool_tail_off;

            /* tail-carve exec check: REFUSE A CARVE WHOSE FIRST PAGES CANNOT EXECUTE.
             *
             * In several 32-bit titles, after the program's unnamed image copy a run of
             * pool pages had lost EXEC for good (max_prot 3, "[pool-rot] ... LOST EXEC",
             * "[pool-poison] HANDED OUT NON-EXEC"), the pool was only 400-560 MB, and the 128 MB
             * code buffer FEX asked for lay on top of that run. Nothing checked it. FEX wrote its
             * first block through the RW alias, executed it at base+0x1c, got an exec fault
             * ([exec-recover] mprotect_rx=-1 errno=13; [fault_rip] ... entryprot=3), and the
             * guest exception dispatcher compiled into the same dead page faulted again until the
             * redelivery guard ended the process. Such a buffer can never run a block, so the
             * request is refused the way an exhausted tail is (ml421): FEX's CodeBuffer ctor
             * halves the size, which moves the next carve up, away from the run (a 64 MB or
             * 32 MB buffer lay above it in all three logs). Only the first 2 MB are looked at (the dead pages in the four logs lay at +0..+0x39e3c;
             * FEX's first blocks go there at once); a dead page deeper in is logged and the carve
             * kept, as before. A carve whose first 2 MB can execute is granted exactly as it was;
             * no log line, no change. */
            {
                enum { CARVE_EXEC_PREFIX = 0x200000 };   /* 2 MB: the dead pages in all four logs lay within it */
                size_t bad_at = 0;
                unsigned int bcur = 0, bmax = 0;
                /* env.MADEIRA_TAIL_CARVE_EXEC_CHECK = 0 turns the check off (every carve granted, as before). */
                static int carve_check = -1;
                if (carve_check < 0)
                {
                    const char *e = getenv( "MADEIRA_TAIL_CARVE_EXEC_CHECK" );
                    carve_check = !(e && e[0] == '0');
                }
                if (carve_check &&
                    ios_pool_range_first_nonexec( pool_tail_off, alloc_size, CARVE_EXEC_PREFIX, &bad_at, &bcur, &bmax ))
                {
                    static unsigned nonexec_n;
                    ios_pool_tail_unreserve( &ios_jit_tail_reserved, reserve_offset + alloc_size, tail_added,
                                             ios_jit_hole_end > ios_jit_hole_off );
                    if (nonexec_n++ < 16)
                        dprintf(2, "[jit-pool] tail carve NOT EXECUTABLE: want=0x%lx at rx=%p: +0x%lx has prot=%x "
                                   "max=%x (EXEC gone for good) -- REFUSING so FEX halves down, a buffer whose first "
                                   "blocks fault is fatal (tail_resv=0x%lx head_used=0x%lx/0x%lx)\n",
                                (unsigned long)alloc_size, jit_rx, (unsigned long)bad_at, bcur, bmax,
                                (unsigned long)reserve_offset, (unsigned long)jit_pool_offset,
                                (unsigned long)ios_jit_pool_size_global);
                    return STATUS_NO_MEMORY;
                }
                if (alloc_size > CARVE_EXEC_PREFIX)
                {
                    static unsigned deep_n;
                    if (deep_n < 8 &&
                        ios_pool_range_first_nonexec( pool_tail_off + CARVE_EXEC_PREFIX, alloc_size - CARVE_EXEC_PREFIX,
                                                      alloc_size, &bad_at, &bcur, &bmax ))
                    {
                        deep_n++;
                        dprintf(2, "[jit-pool] tail carve rx=%p size=0x%lx has a non-exec page at +0x%lx (prot=%x max=%x), "
                                   "beyond the first 2 MB: kept\n",
                                jit_rx, (unsigned long)alloc_size,
                                (unsigned long)(bad_at + CARVE_EXEC_PREFIX), bcur, bmax);
                    }
                }
            }

            *ret = jit_rx;
            *size_ptr = alloc_size;
            /* iOS-Madeira: pre-fill the buffer with NOPs (0xd503201f) via the RW
             * alias. FEX's emitter writes instructions one-at-a-time via
             * memcpy(WritePtr, &Word, 4); on iOS the underlying STR fault is
             * caught by our Mach handler. If the handler ever silently misses
             * a write encoding, the slot retains its prior content — which on
             * a freshly mapped JIT-pool tail is uninitialized memory that may
             * decode as INVALID instructions, causing ILL when execution falls
             * through. NOP-prefilling guarantees fall-through safety:
             * any failed-write slot decodes as a NOP, not garbage.
             *
             * This obsoletes the dispatcher SpillStaticRegs runtime patch in
             * xtajit64.dll (which only patched two known sites with hardcoded
             * encodings). Now the dispatcher emit lands either correctly or
             * as a NOP — either way the CPU doesn't ILL, and SpillStaticRegs
             * just spills fewer regs than expected at worst. */
            {
                volatile uint32_t *rw_words = (volatile uint32_t *)jit_rw;
                size_t nwords = alloc_size / sizeof(uint32_t);
                for (size_t i = 0; i < nwords; i++) rw_words[i] = 0xd503201fu;  /* NOP */
            }

            /* iOS-Madeira: do NOT call set_arm64ec_range here. FEX's CodeBuffer
             * holds compiled-from-x86 host ARM64 blocks, not ARM64EC PE code.
             * Marking it as EC causes the dispatcher's loop-top EC bitmap
             * check (which tests the GUEST RIP) to falsely route into ExitFunctionEC
             * and BR x9 directly into the (uninitialized) CodeBuffer when guest
             * RIP coincidentally lands here, producing UDF #0 faults.
             * Entry into the CodeBuffer is via FEX's own dispatcher BR, not via
             * arm64x_check_call, so EC marking is unneeded. */
            ERR("NtAllocateVirtualMemoryEx iOS: redirected EC_CODE %zu bytes to JIT pool tail rx=%p rw=%p NOP-prefilled\n",
                alloc_size, jit_rx, jit_rw);
            /* ml438 (#74): record the carve so a later free can recycle it. */
            pthread_mutex_lock( &ios_tail_carve_lock );
            if (ios_tail_carve_n < IOS_TAIL_CARVE_MAX)
            {
                ios_tail_carves[ios_tail_carve_n].off = pool_tail_off;
                ios_tail_carves[ios_tail_carve_n].size = alloc_size;
                ios_tail_carves[ios_tail_carve_n].free = 0;
                ios_tail_carves[ios_tail_carve_n].freed_at = 0;
                ios_tail_carves[ios_tail_carve_n].peb = carve_peb;
                ios_tail_carves[ios_tail_carve_n].retired = 0;
                ios_tail_carve_n++;
            }
            /* madeira-bcd split pool: this carve went below a hole; the span it
             * skipped above the hole is a never-used carve a smaller ask can take
             * (pool-mid: one per hole it jumped). */
            {
                int k;
                for (k = 0; k < skip_n; k++)
                {
                    if (skip_size[k] < 0x100000 || ios_tail_carve_n >= IOS_TAIL_CARVE_MAX) continue;
                    ios_tail_carves[ios_tail_carve_n].off = skip_off[k];
                    ios_tail_carves[ios_tail_carve_n].size = skip_size[k];
                    ios_tail_carves[ios_tail_carve_n].free = 1;
                    ios_tail_carves[ios_tail_carve_n].freed_at = 0;   /* never executed, outside region C */
                    ios_tail_carves[ios_tail_carve_n].peb = NULL;
                    ios_tail_carves[ios_tail_carve_n].retired = 0;
                    ios_tail_carve_n++;
                }
            }
            pthread_mutex_unlock( &ios_tail_carve_lock );
            if (tail_added != alloc_size)
                dprintf(2, "[jit-pool] split pool: tail carve 0x%lx would overlap the hole [0x%lx,0x%lx) -- "
                        "placed below it at off 0x%lx; 0x%lx above the hole kept as a free carve\n",
                        (unsigned long)alloc_size, (unsigned long)ios_jit_hole_off_eff,
                        (unsigned long)ios_jit_hole_end_eff, (unsigned long)pool_tail_off,
                        (unsigned long)tail_skipped);
            dprintf(2, "[jit-pool] tail EC_CODE rx=%p size=0x%lx tail_resv=0x%lx head_used=0x%lx/0x%lx\n",
                    jit_rx, (unsigned long)alloc_size,
                    (unsigned long)(reserve_offset + alloc_size),
                    (unsigned long)jit_pool_offset, (unsigned long)ios_jit_pool_size_global);
            return STATUS_SUCCESS;
        }
    }
#endif

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_alloc_ex.type         = APC_VIRTUAL_ALLOC_EX;
        call.virtual_alloc_ex.addr         = wine_server_client_ptr( *ret );
        call.virtual_alloc_ex.size         = *size_ptr;
        call.virtual_alloc_ex.limit_low    = limit_low;
        call.virtual_alloc_ex.limit_high   = limit_high;
        call.virtual_alloc_ex.align        = align;
        call.virtual_alloc_ex.op_type      = type;
        call.virtual_alloc_ex.prot         = protect;
        call.virtual_alloc_ex.attributes   = attributes;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_alloc_ex.status == STATUS_SUCCESS)
        {
            *ret      = wine_server_get_ptr( result.virtual_alloc_ex.addr );
            *size_ptr = result.virtual_alloc_ex.size;
        }
        return result.virtual_alloc_ex.status;
    }

#ifdef WINE_IOS
    {
        NTSTATUS st;
        /* ml92: the middle-zone steering that used to live here targeted
         * [256G,480G), which is 192GB GPU carveout — it could never succeed.
         * There is no middle zone at all (see NtAllocateVirtualMemory), so go
         * straight to the default search, and census jumbo calls the same way
         * so PartitionAlloc's demand is counted no matter which entry point
         * it uses. */
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

        /* madeira-bcd: Social Club layout 2. SocialClubHelper.exe's V8 reserves
         * and commits through VirtualAlloc2, so NtAllocateVirtualMemory's helper
         * bookkeeping is needed here too: its commits judged (ios_sc2_note_commit
         * says nothing at or above the FEX arena, which keeps the emulator's own
         * commits cheap), dead helpers' grants released before a large ask, the
         * V8 sandbox's 8 GB step given the cage (ios_sc2_ex_cage) and its large
         * grants remembered for ios_sc_reap_dead (ios_sc_grant_note). */
        {
            int sc2 = is_jumbo && ios_sc_layout_mode == 2 && ios_sc_cef_enabled() && ios_sc_current_is_helper();
            int caged = 0;

            if ((type & MEM_COMMIT) && *ret && ios_sc_layout_mode == 2 && (ULONG_PTR)*ret < ios_sc2_arena_lo)
                ios_sc2_note_commit( *ret, *size_ptr );
            if (sc2 && ios_sc_grant_dead_n) ios_sc_reap_dead();
            if (sc2 && ios_sc2_ex_cage( *size_ptr, type, protect, limit_low, limit_high, align, attributes,
                                        ios_cage_holdback_live ))
            {
                void *hint = *ret, *pick = NULL;
                SIZE_T sz = 0;

                st = ios_cage_grant( type, protect, *size_ptr, &pick, &sz, "sc2-ex" );
                dprintf( 2, "[sc-cef] layout 2: V8 sandbox's 8 GB step (VirtualAlloc2, hint %p) for SocialClubHelper.exe: "
                            "the cage -> %p (st=0x%x)\n", hint, st ? NULL : pick, (unsigned)st );
                if (!st)
                {
                    *ret = pick;
                    *size_ptr = sz;
                    caged = 1;
                }
            }
            /* a reservation at the program's own address over its held releases (ios_fd_reuse) */
            if (!caged && *ret) ios_fd_reuse( *ret, *size_ptr, type );
            if (!caged)
                st = allocate_virtual_memory( ret, size_ptr, type, protect,
                                              limit_low, limit_high, align, attributes );
            if (sc2 && !st) ios_sc_grant_note( *ret, *size_ptr );
        }

        if (is_jumbo) ios_jumbo_census( jumbo_hint, jumbo_size, st ? NULL : *ret, (unsigned)st );
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
        return st;
    }
#else
    return allocate_virtual_memory( ret, size_ptr, type, protect,
                                    limit_low, limit_high, align, attributes );
#endif
}


/***********************************************************************
 *             NtFreeVirtualMemory   (NTDLL.@)
 *             ZwFreeVirtualMemory   (NTDLL.@)
 */
#ifdef WINE_IOS
/* DELAYED RELEASE of mid-size guest allocations.
 *
 * Ghost of Tsushima crashed in every run the same way: a 1-2 MB block the
 * main thread allocated is MEM_RELEASEd by one job worker while other
 * workers are still copying out of it (the view was deleted 3-8 ms before
 * the fault), with fastsync on or off. Freed guest-band VA is handed out
 * again at once -- to the game, or to Metal/malloc -- so late accesses
 * either fault or scribble over someone else's objects (one run crashed in
 * Metal's command-buffer completion handler releasing a corrupted object).
 * A whole-view MEM_RELEASE of a private 1-16 MB allocation now succeeds
 * immediately but the mapping stays committed for MADEIRA_FREE_DELAY_MS
 * (opt-in: off by default, 2000 is the tested value), capped at 128 MB in
 * flight, and is released later. The race itself is not fixed; its victims
 * survive. Off by default because it holds up to 128 MB more for every game,
 * and a block cannot be reallocated at its own address while it is held. */
#define IOS_FD_N 256
static struct { char *base; size_t size; unsigned int ms; void *peb; } ios_fd_ring[IOS_FD_N];
static unsigned int ios_fd_n;
static size_t ios_fd_bytes;
static pthread_mutex_t ios_fd_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int ios_fd_bypass;
static int ios_fd_ms( void )
{
    static int v = -1;
    if (v < 0)
    {
        /* How long a released 1-16 MB guest allocation stays mapped before it is
         * really freed (default 0: freed at once; 2000 ms is the tested hold). */
        const char *e = getenv( "MADEIRA_FREE_DELAY_MS" );
        v = e ? atoi( e ) : 0;
        if (v < 0) v = 0;
    }
    return v;
}
static unsigned int ios_fd_now( void )
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    return (unsigned int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
/* release everything older than the delay (or everything past the cap) */
static void ios_fd_drain( int force_one )
{
    char *todo[IOS_FD_N]; unsigned int nt = 0, i, now = ios_fd_now();
    pthread_mutex_lock( &ios_fd_lock );
    for (i = 0; i < ios_fd_n; )
    {
        if ((int)(now - ios_fd_ring[i].ms) >= ios_fd_ms() || (force_one && i == 0) || ios_fd_bytes > (128u << 20))
        {
            todo[nt++] = ios_fd_ring[i].base;
            ios_fd_bytes -= ios_fd_ring[i].size;
            ios_fd_ring[i] = ios_fd_ring[--ios_fd_n];
            force_one = 0;
            continue;
        }
        i++;
    }
    pthread_mutex_unlock( &ios_fd_lock );
    for (i = 0; i < nt; i++)
    {
        void *b = todo[i]; SIZE_T sz = 0;
        ios_fd_bypass = 1;
        NtFreeVirtualMemory( NtCurrentProcess(), &b, &sz, MEM_RELEASE );
        ios_fd_bypass = 0;
    }
}
/* 1 = taken into quarantine (caller reports success), 2 = already quarantined */
static int ios_fd_take( char *base, SIZE_T *out_size )
{
    struct file_view *view;
    sigset_t sigset;
    size_t vsize = 0;
    unsigned int i;
    int ok = 0;
    if (ios_fd_bypass || !ios_fd_ms()) return 0;
    if ((uintptr_t)base < 0x7000000000ULL || (uintptr_t)base >= 0x7c00000000ULL) return 0;
    pthread_mutex_lock( &ios_fd_lock );
    for (i = 0; i < ios_fd_n; i++) if (ios_fd_ring[i].base == base) break;
    pthread_mutex_unlock( &ios_fd_lock );
    if (i < ios_fd_n) return 2;
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    view = find_view( base, 0 );
    if (view && view->base == base && is_view_valloc( view ) &&
        !(view->protect & (SEC_FILE | SEC_IMAGE | VPROT_SYSTEM)) &&
        view->size >= (1u << 20) && view->size <= (16u << 20))
    {
        vsize = view->size;
        ok = 1;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (!ok) return 0;
    if (ios_fd_n >= IOS_FD_N) ios_fd_drain( 1 );
    pthread_mutex_lock( &ios_fd_lock );
    /* Checked again under the lock: two threads releasing the same base can both
     * pass the check above, and holding it twice made the drain free it twice
     * (the second time, possibly someone's new allocation at that address). */
    for (i = 0; i < ios_fd_n; i++) if (ios_fd_ring[i].base == base) break;
    if (i < ios_fd_n)
    {
        pthread_mutex_unlock( &ios_fd_lock );
        return 2;
    }
    if (ios_fd_n < IOS_FD_N)
    {
        ios_fd_ring[ios_fd_n].base = base; ios_fd_ring[ios_fd_n].size = vsize; ios_fd_ring[ios_fd_n].ms = ios_fd_now();
        ios_fd_ring[ios_fd_n].peb = ios_jit_current_peb();   /* whose release it is (ios_fd_reuse) */
        ios_fd_n++; ios_fd_bytes += vsize;
    }
    else ok = 0;
    pthread_mutex_unlock( &ios_fd_lock );
    if (ok)
    {
        static unsigned long said;
        *out_size = vsize;
        if (++said <= 8 || !(said % 1024))
            dprintf( 2, "[free-delay] #%lu release of %p+0x%lx held for %d ms (%u in flight)\n",
                     said, base, (unsigned long)vsize, ios_fd_ms(), ios_fd_n );
    }
    return ok;
}
/* a held release is free memory to the program that released it.
 * Horizon Forbidden West (build 517, log 2026-10-13 08:49) allocated 2 MB or
 * 4 MB-4 KB, released it at once and then reserved the 2 MB-aligned address
 * inside it: the hold refused that with STATUS_CONFLICTING_ADDRESSES and the
 * game asked again forever (22.6 million failed requests in 70 s, no frame). A
 * reservation at an explicit address -- NtAllocateVirtualMemory[Ex] with
 * MEM_RESERVE, NtMapViewOfSection[Ex] with a base -- whose range meets the
 * same program's held releases and no other view now frees those held ranges
 * first, so it finds the address free, as on Windows. The delay cannot keep
 * alive memory that the program maps again itself; every other held range
 * keeps it. A range that also meets a live view, or a release by another
 * program of the session (they share one address space here, unlike on
 * Windows), fails as before, and placement without an address never comes
 * here. MADEIRA_FREE_DELAY_REUSE=0 keeps the old refusal. Returns how many
 * held ranges were freed. */
static int ios_fd_reuse_enabled( void )
{
    static int v = -1;
    /* MADEIRA_FREE_DELAY_REUSE=0: a reservation over held releases fails until the delay
     * runs out, as before; default 1: those held ranges are freed at once */
    if (v < 0) { const char *e = getenv( "MADEIRA_FREE_DELAY_REUSE" ); v = !(e && !strcmp( e, "0" )); }
    return v;
}
static unsigned int ios_fd_reuse( const void *addr, SIZE_T size, ULONG type )
{
    char *start, *end, *cur, *todo[IOS_FD_N];
    unsigned int idx[IOS_FD_N], n = 0, i, j;
    struct file_view *view;
    size_t bytes = 0;
    sigset_t sigset;
    void *peb;
    int live = 0;

    if (!(type & MEM_RESERVE) || (type & MEM_REPLACE_PLACEHOLDER) || !addr || !size || !ios_fd_ms()) return 0;
    start = ROUND_ADDR( addr, granularity_mask );   /* allocate_virtual_memory's rounding */
    end = ROUND_ADDR( (UINT_PTR)addr + size + page_mask, page_mask );
    if (end <= start) return 0;
    pthread_mutex_lock( &ios_fd_lock );
    for (i = 0; i < ios_fd_n; i++)
        if (ios_fd_ring[i].base < end && ios_fd_ring[i].base + ios_fd_ring[i].size > start) break;
    j = i < ios_fd_n;
    pthread_mutex_unlock( &ios_fd_lock );
    if (!j) return 0;   /* nothing held there: every other request */
    if (!ios_fd_reuse_enabled())
    {
        static int said_off;
        if (!said_off++)
            dprintf( 2, "[free-delay] MADEIRA_FREE_DELAY_REUSE=0: a reservation at %p+0x%lx over a held "
                        "release fails until the delay runs out\n", start, (unsigned long)(end - start) );
        return 0;
    }

    peb = ios_jit_current_peb();
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    pthread_mutex_lock( &ios_fd_lock );
    /* the held releases the range meets, by address; another program's refuses as a live view does */
    for (i = 0; i < ios_fd_n; i++)
    {
        if (ios_fd_ring[i].base >= end || ios_fd_ring[i].base + ios_fd_ring[i].size <= start) continue;
        if (ios_fd_ring[i].peb != peb) live = 1;
        for (j = n; j && ios_fd_ring[idx[j - 1]].base > ios_fd_ring[i].base; j--) idx[j] = idx[j - 1];
        idx[j] = i;
        n++;
    }
    /* each still one whole view, and no other view anywhere in the range */
    for (j = 0, cur = start; j < n && !live; j++)
    {
        char *b = ios_fd_ring[idx[j]].base;
        if (b > cur && find_view_range( cur, b - cur )) live = 1;
        else if (!(view = find_view( b, 0 )) || view->base != b || view->size != ios_fd_ring[idx[j]].size) live = 1;
        cur = b + ios_fd_ring[idx[j]].size;
    }
    if (!live && cur < end && find_view_range( cur, end - cur )) live = 1;
    if (!live)
    {
        /* out of the ring before they are freed, as in the drain: never freed twice */
        for (j = 0; j < n; j++)
        {
            todo[j] = ios_fd_ring[idx[j]].base;
            bytes += ios_fd_ring[idx[j]].size;
            ios_fd_ring[idx[j]].size = 0;
        }
        for (i = j = 0; i < ios_fd_n; i++) if (ios_fd_ring[i].size) ios_fd_ring[j++] = ios_fd_ring[i];
        ios_fd_n = j;
        ios_fd_bytes -= bytes;
    }
    pthread_mutex_unlock( &ios_fd_lock );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (live || !n)
    {
        static unsigned long kept;
        if (live && (++kept <= 8 || !(kept % 1024)))
            dprintf( 2, "[free-delay] #%lu reservation at %p+0x%lx also meets a live view or another "
                        "program's release: its %u held release(s) stay held\n", kept, start,
                     (unsigned long)(end - start), n );
        return 0;
    }
    for (j = 0; j < n; j++)
    {
        void *b = todo[j]; SIZE_T sz = 0;
        ios_fd_bypass = 1;
        NtFreeVirtualMemory( NtCurrentProcess(), &b, &sz, MEM_RELEASE );
        ios_fd_bypass = 0;
    }
    {
        static unsigned long said;
        if (++said <= 8 || !(said % 1024))
            dprintf( 2, "[free-delay] #%lu reservation at %p+0x%lx: %u held release(s) from %p (0x%lx bytes) "
                        "freed at once (%u in flight)\n", said, start, (unsigned long)(end - start), n, todo[0],
                     (unsigned long)bytes, ios_fd_n );
    }
    return n;
}
#endif

NTSTATUS WINAPI NtFreeVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr, ULONG type )
{
    struct file_view *view;
    char *base;
    sigset_t sigset;
    unsigned int status = STATUS_SUCCESS;
    LPVOID addr = *addr_ptr;
    SIZE_T size = *size_ptr;
#ifdef WINE_IOS
    int sc_rehold = 0;
#endif

    TRACE("%p %p %08lx %x\n", process, addr, size, type );

#ifdef WINE_IOS
    ios_vm_note_free( addr, size, type );
    /* ml966: a low guest allocation must be freed through its backing, and the
     * translation retired so nothing can resolve through it afterwards.
     * MEM_RELEASE retires; MEM_DECOMMIT keeps the mapping and so keeps the
     * translation alive. Ownership is enforced here because the calling thread
     * is the guest's, so its peb is the real one. */
    /* ml969: an alias is retired by the BACKING address, because that is the
     * pointer the guest holds and therefore the one it frees. Retire before the
     * mapping goes away so no later access can resolve through a dead name. */
    if (type & MEM_RELEASE)
    {
        uint64_t gone = ios_lowalias_retire_by_real( (uint64_t)(ULONG_PTR)addr,
                                                     ios_jit_current_peb() );
        if (gone)
        {
            static int lx_f;
            if (lx_f < 24)
            {
                lx_f++;
                dprintf( 2, "ml969: RETIRED alias %#llx for backing %p on free\n",
                         (unsigned long long)gone, addr );
            }
        }
    }
    {
        unsigned long long lo_real = 0;
        void *lo_owner = NULL;
        if (ios_lowalloc_translate( (unsigned long long)(ULONG_PTR)addr, size,
                                    &lo_real, &lo_owner ))
        {
            void *peb = ios_jit_current_peb();
            static int lf_n;
            if (lf_n < 24)
            {
                lf_n++;
                dprintf( 2, "ml966: FREE of low guest %p size=%#llx type=%#x -> backing %#llx "
                         "(owner=%p caller=%p)%s\n", addr, (unsigned long long)size,
                         (unsigned)type, lo_real, lo_owner, peb,
                         (type & MEM_RELEASE) ? " [retiring translation]" : " [decommit, kept]" );
            }
            if (type & MEM_RELEASE)
            {
                uint64_t retired = ios_lowalloc_retire( (uint64_t)(ULONG_PTR)addr, peb );
                if (!retired)
                    dprintf( 2, "ml966: FREE of low guest %p did NOT retire (ownership mismatch?) "
                             "-- refusing to free someone else's backing\n", addr );
                else
                {
                    addr = (LPVOID)(ULONG_PTR)retired;
                    *addr_ptr = addr;
                }
            }
            else
            {
                addr = (LPVOID)(ULONG_PTR)lo_real;
                *addr_ptr = addr;
            }
        }
    }
#endif

    /* ml171 LEAK PROBE: the 512MB reserves grow without bound (27 -> 55 across runs,
     * 28GB) and only ~1%% is ever committed. If the owner never RELEASES them the fix is
     * reclamation, not more address space; if it does release and our accounting still
     * grows, the leak is ours. Log every large free so the next run answers it. */
    /* ml172 FIX: the first cut gated logging on size >= 256MB, but Windows REQUIRES
     * size == 0 for MEM_RELEASE (VirtualFree(addr, 0, MEM_RELEASE)) — so the very calls
     * this probe exists to catch could never be logged, and its "0 frees" result was
     * meaningless. Log any MEM_RELEASE of an address in the steered/pool band, plus any
     * large explicit free, and resolve the real extent from the view. */
    if ((type & MEM_RELEASE) || size >= 0x10000000)
    {
        static unsigned freebig_n;
        uintptr_t fa = (uintptr_t)addr;

        if (freebig_n < 32 && (size >= 0x10000000 || fa >= 0x7000000000ULL))
        {
            struct file_view *fv = find_view( addr, 0 );
            freebig_n++;
            dprintf(2, "[bigfree] #%u addr=%p size=0x%lx type=0x%x view=%p viewsize=0x%lx\n",
                    freebig_n, addr, (unsigned long)size, (unsigned)type,
                    fv ? fv->base : NULL, fv ? (unsigned long)fv->size : 0ul);
        }
    }

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_free.type      = APC_VIRTUAL_FREE;
        call.virtual_free.addr      = wine_server_client_ptr( addr );
        call.virtual_free.size      = size;
        call.virtual_free.op_type   = type;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_free.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_free.addr );
            *size_ptr = result.virtual_free.size;
        }
        return result.virtual_free.status;
    }

    /* Fix the parameters */

    if (size) size = ROUND_SIZE( addr, size, page_mask );
    base = ROUND_ADDR( addr, page_mask );

#ifdef WINE_IOS
    if (!ios_fd_bypass)
    {
        ios_fd_drain( 0 );   /* releases whose delay has run out */
        if (type == MEM_RELEASE && !size && base == addr)
        {
            SIZE_T held = 0;
            int t = ios_fd_take( base, &held );
            if (t == 1) { *addr_ptr = base; *size_ptr = held; return STATUS_SUCCESS; }
            if (t == 2) return STATUS_MEMORY_NOT_ALLOCATED;
        }
    }
#endif

#ifdef WINE_IOS
    /* madeira-bcd: a Social Club helper's grant (ios_sc_grant_release) */
    if (type == MEM_RELEASE && !size)
    {
        SIZE_T served = 0;
        if (ios_sc_grant_release( base, &served, &sc_rehold ))
        {
            *addr_ptr = base;
            *size_ptr = served;
            return STATUS_SUCCESS;
        }
    }
#endif

    /* ml433 (#72): keep the jumbo ledger honest — see ios_bigres_release. */
    if (type & MEM_RELEASE) ios_bigres_release( base );
    /* ml435 (#73): band span lifecycle census — resolve MEM_RELEASE size=0 from the view. */
    if ((type & MEM_RELEASE) && (uintptr_t)base >= 0x7c00000000ULL)
    {
        struct file_view *sfv = find_view( base, 0 );
        ios_span_census( base, sfv ? sfv->size : size, 1 );
    }
    /* ml438 (#74): a MEM_RELEASE of a live tail EC-buffer carve has no wine
     * view — before this rev it error'd (FEXCore ignored it) and the tail
     * space leaked forever. Mark the carve free for reuse and succeed. */
    /* madeira-bcd pool-low: a carve in region C is released the same way; its
     * `off` is the same wrapping base - rx it was recorded with. */
    if ((type & MEM_RELEASE) && ios_jit_rx_base_global && ios_jit_pool_size_global &&
        (((char *)base >= (char *)ios_jit_rx_base_global &&
          (char *)base <  (char *)ios_jit_rx_base_global + ios_jit_pool_size_global) ||
         ios_jit_low_contains( (uintptr_t)base )))
    {
        unsigned i;
        size_t off = (size_t)((char *)base - (char *)ios_jit_rx_base_global);
        size_t carve_size = 0;
        void *caller_peb = ios_jit_current_peb();
        const char *defer_env = getenv( "MADEIRA_POOL_CODE_DEFER_FREE" );   /* 0: a FEX code buffer released while a thread runs in it is refused and stays live, as before */
        int defer_free = !(defer_env && !strcmp( defer_env, "0" ));
        pthread_mutex_lock( &ios_tail_carve_lock );
        for (i = 0; i < ios_tail_carve_n; i++)
        {
            if (ios_tail_carves[i].off != off || ios_tail_carves[i].free) continue;
            /* madeira-bcd: never a release by another process than the owner: a
             * dead process's late one, after its retired buffer was handed on */
            if (ios_tail_carve_foreign_release( &ios_tail_carves[i], caller_peb ))
            {
                static unsigned foreign_n;
                if (++foreign_n <= 16)
                    dprintf(2, "[jit-pool] tail FREE REFUSED rx=%p size=0x%lx: released by peb=%p, owned by "
                               "peb=%p (madeira-bcd)\n", base, (unsigned long)ios_tail_carves[i].size,
                            caller_peb, ios_tail_carves[i].peb);
                carve_size = 0;
                break;
            }
            /* ml557: do NOT recycle a carve a thread is still executing in. Refusing the
             * release leaked it for good, though: FEX releases a buffer once and never
             * again, so "freeable on the next release" never came. One game lost a
             * 128 MB buffer that way and ran its last 4 minutes on 16 MB ones. Free it as
             * retired instead, so reuse waits out the grace and its strict scan, exactly
             * as for a dead process's buffer. MADEIRA_POOL_CODE_DEFER_FREE=0 refuses it. */
            if (ios_tail_carve_occupied( base, ios_tail_carves[i].size ))
            {
                static unsigned long occ_n;
                if (!defer_free)
                {
                    if (++occ_n <= 16 || (occ_n % 256) == 0)
                        dprintf(2, "[jit-pool] tail FREE REFUSED rx=%p size=0x%lx — a thread's "
                                   "PC is inside it (occupied=%lu) rev=ml557\n",
                                base, (unsigned long)ios_tail_carves[i].size, occ_n);
                    carve_size = 0;
                    break;
                }
                if (++occ_n <= 16 || (occ_n % 256) == 0)
                    dprintf(2, "[jit-pool] tail FREE deferred rx=%p size=0x%lx — a thread's "
                               "PC is inside it (occupied=%lu): retired until it leaves rev=ml557\n",
                            base, (unsigned long)ios_tail_carves[i].size, occ_n);
                ios_tail_carves[i].retired = 1;
                ios_tail_carves[i].peb = NULL;
            }
            ios_tail_carves[i].free = 1;
            ios_tail_carves[i].freed_at = time( NULL );
            carve_size = ios_tail_carves[i].size;
            break;
        }
        pthread_mutex_unlock( &ios_tail_carve_lock );
        if (carve_size)
        {
            dprintf(2, "[jit-pool] tail FREE rx=%p size=0x%lx -> free-list rev=ml438%s\n",
                    (void *)base, (unsigned long)carve_size,
                    ios_jit_low_contains( (uintptr_t)base ) ? " [pool-low] region C" : "");
            *addr_ptr = base;
            *size_ptr = carve_size;
            return STATUS_SUCCESS;
        }
        /* pool address but not a live tail carve — fall through unchanged */
    }

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

#ifdef WINE_IOS
    /* Madeira: a thin reservation's tail holds nothing; see ios_thin_reserve. */
    if (ios_thin_live_n && type == MEM_DECOMMIT && base && ios_thin_decommit_fixup( base, &size ))
    {
        *addr_ptr = base;
        *size_ptr = size;
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        return STATUS_SUCCESS;
    }
#endif

    /* avoid freeing the DOS area when a broken app passes a NULL pointer */
    if (!base)
    {
#ifndef _WIN64
        /* address 1 is magic to mean release reserved space */
        if (addr == (void *)1 && !size && type == MEM_RELEASE) virtual_release_address_space();
        else
#endif
        status = STATUS_INVALID_PARAMETER;
    }
    else if (!(view = find_view( base, 0 ))) status = STATUS_MEMORY_NOT_ALLOCATED;
    else if (!is_view_valloc( view )) status = STATUS_INVALID_PARAMETER;
    else if (!size && base != view->base) status = STATUS_FREE_VM_NOT_AT_BASE;
    else if ((char *)view->base + view->size - base < size && !(type & MEM_COALESCE_PLACEHOLDERS))
             status = STATUS_UNABLE_TO_FREE_VM;
    else switch (type)
    {
    case MEM_DECOMMIT:
        status = decommit_pages( view, base, size );
        break;
    case MEM_RELEASE:
        if (!size) size = view->size;
        if (base == view->base && size == view->size)
            ios_vh_capture_free_site( view, __builtin_return_address(0) );
        status = free_pages( view, base, size );
#ifdef WINE_IOS
        if (!status) ios_jit_anon_alias_retire_range( base, size );
#endif
        ios_vh_free_site.valid = 0;
        break;
    case MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER:
        status = free_pages_preserve_placeholder( view, base, size );
        break;
    case MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS:
        status = coalesce_placeholders( view, base, size );
        break;
    case MEM_COALESCE_PLACEHOLDERS:
        status = STATUS_INVALID_PARAMETER_4;
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    if (status == STATUS_SUCCESS)
    {
        *addr_ptr = base;
        *size_ptr = size;
#ifdef WINE_IOS
        if ((type & MEM_RELEASE) && ios_thin_live_n) ios_thin_released( base );
#endif
    }
#ifdef WINE_IOS
    else
    {
        /* ml1285: a refused free was silent, and a runtime that asserts on VirtualFree
         * (Wine Mono's mono_vfree) died without saying which block or why. */
        static int refused_n;
        if (refused_n < 16)
        {
            struct file_view *rv = base ? find_view( base, 0 ) : NULL;
            refused_n++;
            dprintf( 2, "[free-refused] ml1285 #%d addr=%p size=%#lx type=%#x status=%#x view=%p+%#lx "
                     "protect=%#x valloc=%d tid=%04x\n", refused_n, addr, (unsigned long)size, (unsigned)type,
                     status, rv ? rv->base : NULL, rv ? (unsigned long)rv->size : 0UL,
                     rv ? (unsigned)rv->protect : 0u, rv ? is_view_valloc( rv ) : -1,
                     (unsigned)GetCurrentThreadId() );
        }
    }
#endif
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
#ifdef WINE_IOS
    if (sc_rehold && status == STATUS_SUCCESS) ios_sc_rehold( sc_rehold );
#endif
    return status;
}

#ifdef WINE_IOS
/* madeira-bcd: [ec-hook] -- a program's inline patch of a pool-copied image's code.
 *
 * A difference does not prove a guest hook: native x18 rewrites and loader
 * patches also differ from the PE view. Give ordinary differences, other x64
 * jumps and graphics x64 jumps separate budgets, so startup cannot hide a
 * later graphics patch. Inspect both views: a caller can write through a pool
 * function pointer, leaving the PE view unchanged. Include a shared opcode
 * prefix when only its operands differ. Called BEFORE synchronization on every
 * executable section, including .hexpthk. No code/protection changes. Regions up to 1 MB;
 * Off by default; MADEIRA_EC_HOOK_TRACE=1 turns it on. */

/* madeira-bcd: the report's reads of jump slots and targets, which cannot fault.
 * In a protector's packed section the "jumps" are random bytes, so their targets
 * are random addresses (PlayGTAV.exe's 'RNE0' on build 451; Ghost of Tsushima's
 * steam_api64.dll 'WUS0'/'WUS1' on 515, 2026-10-12 15:21). Read through
 * virtual_check_buffer_for_read, an address in a reserved region that never
 * materialises raised a SIGBUS that bus_handler hands to the guest without
 * honouring the __TRY; the next __TRY then asserted (0x80000101) and the game
 * ended at start. The kernel copy returns an error instead, and touches no
 * guard page or lazy commit of the guest's. */
static int ios_ec_hook_peek( uintptr_t addr, void *out, size_t size )
{
    mach_vm_size_t got = 0;

    if (addr < 0x10000 || addr + size < addr) return 0;
    return mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)addr, size,
                                   (mach_vm_address_t)(uintptr_t)out, &got ) == KERN_SUCCESS && got == size;
}

static size_t ios_ec_hook_jump_target( const unsigned char *at, size_t len, uintptr_t va,
                                      unsigned long long *target )
{
    if (len >= 5 && at[0] == 0xe9)
    {
        int32_t rel;
        memcpy( &rel, at + 1, sizeof(rel) );
        *target = va + 5 + rel;
        return 5;
    }
    if (len >= 6 && at[0] == 0xff && at[1] == 0x25)
    {
        int32_t rel;
        unsigned long long slot;
        memcpy( &rel, at + 2, sizeof(rel) );
        if (ios_ec_hook_peek( va + 6 + rel, &slot, sizeof(slot) )) *target = slot;
        return !rel && len >= 14 ? 14 : 6;
    }
    if (len >= 12 && at[0] == 0x48 && at[1] == 0xb8 && at[10] == 0xff && at[11] == 0xe0)
    {
        memcpy( target, at + 2, 8 );
        return 12;
    }
    return 0;
}

static void ios_ec_hook_report( int idx, const unsigned char *pe, const unsigned char *copy, size_t len )
{
    static unsigned counts[3];   /* differences: 8, other jumps: 16, graphics jumps: 32 */
    static const unsigned caps[3] = { 8, 16, 32 };
    static int on = -1;
    size_t i = 0;
    int runs = 0;

    if (on < 0)
    {
        const char *e = getenv( "MADEIRA_EC_HOOK_TRACE" );   /* 1: log [ec-hook] lines (code patches an image's pool copy misses); off by default */
        on = e && e[0] == '1';
    }
    if (!on || len > 0x100000) return;
    while (i < len && runs < 4)
    {
        size_t start, end, k;
        const unsigned char *at;
        unsigned long long target = 0;
        int jump = 0, bucket, pool_patch = 0, pass;
        unsigned serial;
        const char *module;
        char sec[160], tsec[160], pb[3 * 16 + 1], cb[3 * 16 + 1], tb[3 * 16 + 1];

        if (pe[i] == copy[i]) { i++; continue; }
        start = i;
        end = i;
        while (end < len && end - start < 64 && (pe[end] != copy[end] || (end + 1 < len && pe[end + 1] != copy[end + 1])))
            end++;
        i = end;
        /* Try the pool first: x18/relocation rewrites also live there, so the
         * byte pattern is diagnostic evidence, not proof of a guest hook.
         * The address used for a relative jump is the RX VA, never its RW alias. */
        for (pass = 0; pass < 2 && !jump; pass++)
        {
            const unsigned char *view = pass ? pe : copy;
            uintptr_t va = pass ? (uintptr_t)pe : (uintptr_t)ios_jit_mappings[idx].jit_base +
                ((uintptr_t)pe - (uintptr_t)ios_jit_mappings[idx].pe_base);
            size_t back;
            for (back = 0; back <= start && back < 14; back++)
            {
                size_t candidate = start - back, n;
                unsigned long long dest = 0;
                n = ios_ec_hook_jump_target( view + candidate, len - candidate, va + candidate, &dest );
                if (!n || candidate + n <= start || !memcmp( pe + candidate, copy + candidate, n )) continue;
                start = candidate;
                if (end < start + n) end = start + n;
                target = dest;
                pool_patch = !pass;
                jump = 1;
                break;
            }
        }
        i = end;
        at = pe + start;
        for (k = 0; k < 16 && start + k < len; k++)
        {
            snprintf( pb + 3 * k, 4, "%02x ", at[k] );
            snprintf( cb + 3 * k, 4, "%02x ", copy[start + k] );
        }
        pb[3 * k] = cb[3 * k] = 0;
        bucket = jump ? 1 : 0;
        module = ios_pe_module_name( ios_jit_mappings[idx].pe_base, ios_jit_mappings[idx].size );
        if (jump && module && (!strcasecmp( module, "dxgi.dll" ) || !strcasecmp( module, "d3d12.dll" ) ||
                               !strcasecmp( module, "madeira_d3d12.dll" ))) bucket = 2;
        if (__atomic_load_n( &counts[bucket], __ATOMIC_RELAXED ) >= caps[bucket]) continue;
        serial = __atomic_fetch_add( &counts[bucket], 1, __ATOMIC_RELAXED );
        if (serial >= caps[bucket]) continue;
        runs++;
        if (!ios_image_section_describe( (uintptr_t)at, sec, sizeof(sec), NULL ))
            snprintf( sec, sizeof(sec), "?" );
        tb[0] = 0;
        tsec[0] = 0;
        if (target)
        {
            unsigned char t[16];

            if (!ios_image_section_describe( target, tsec, sizeof(tsec), NULL ))
                snprintf( tsec, sizeof(tsec), "no pool copy" );
            if (ios_ec_hook_peek( (uintptr_t)target, t, sizeof(t) ))
                for (k = 0; k < 16; k++) snprintf( tb + 3 * k, 4, "%02x ", t[k] );
        }
        dprintf( 2, "[ec-hook] #%u scope=%s view=%s tid=%04x image %p (pool copy %p) %p+%#lx: %s | PE bytes: %s| pool before sync: %s| "
                    "jump -> %#llx (%s) bytes there: %s\n",
                 serial + 1, bucket == 2 ? "graphics-jump" : bucket == 1 ? "other-jump" : "difference",
                 jump ? pool_patch ? "pool" : "PE" : "difference",
                 (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
                 ios_jit_mappings[idx].pe_base, ios_jit_mappings[idx].jit_base, (const void *)at,
                 (unsigned long)(end - start), sec, pb, cb, target, target ? tsec : "-", tb[0] ? tb : "-" );
    }
}
#endif


/* Monotonic counter incremented on every successful NtProtectVirtualMemory call so
 * signal_arm64_ios.c's [redeliv] storm guard can distinguish a genuinely stuck fault
 * from a legitimate FEX SMC untrap -> retire -> recompile -> retrap cycle (seen in two
 * 32-bit titles that patch their own code). */
volatile unsigned long long ios_vprotect_seq = 0;

/***********************************************************************
 *             NtProtectVirtualMemory   (NTDLL.@)
 *             ZwProtectVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtProtectVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr,
                                        ULONG new_prot, ULONG *old_prot )
{
    struct file_view *view;
    sigset_t sigset;
    unsigned int status = STATUS_SUCCESS;
    char *base;
    BYTE vprot;
    SIZE_T size = *size_ptr;
    LPVOID addr = *addr_ptr;
    DWORD old;

#ifdef WINE_IOS
    LPVOID ios_patch_requested = addr;
    SIZE_T ios_patch_length = size;
    /* ml966: a protection change on a low guest allocation applies to the
     * backing. The whole span is bounds-checked, so a request that runs off
     * the end of the allocation is left alone rather than silently clipped. */
    {
        unsigned long long lo_real = 0;
        if (ios_lowalloc_translate( (unsigned long long)(ULONG_PTR)addr, size, &lo_real, NULL ))
        {
            static int lp_n;
            if (lp_n < 16)
            {
                lp_n++;
                dprintf( 2, "ml966: PROTECT on low guest %p size=%#llx new_prot=%#x -> backing %#llx\n",
                         addr, (unsigned long long)size, (unsigned)new_prot, lo_real );
            }
            addr = (LPVOID)(ULONG_PTR)lo_real;
            *addr_ptr = addr;
        }
        else if (ios_subfloor_image_translate( (unsigned long long)(ULONG_PTR)addr, size, &lo_real ))
        {
            static int sp_n;
            if (sp_n++ < 16)
                dprintf( 2, "ml1201: PROTECT on sub-floor image %p size=%#llx new_prot=%#x -> real %#llx\n",
                         addr, (unsigned long long)size, (unsigned)new_prot, lo_real );
            /* On success *addr_ptr comes back as the real page, so FEX registers
             * that page; its low-RIP translations are dropped when the program
             * flushes the instruction cache (ml1202). */
            addr = (LPVOID)(ULONG_PTR)lo_real;
        }
    }
    /* ml846: a marked request from the PE-side dispatcher arms the [tlswatch]
     * write watch on the thread's TLS block instead of changing protection. */
    if (size == 0x0BAD0038 && new_prot == PAGE_READONLY)
    {
        extern void ios_tlswatch_arm_block( void *block, const char *why );
        ios_tlswatch_arm_block( addr, "pe-unwind" );
        if (old_prot) *old_prot = PAGE_READWRITE;
        *size_ptr = 0;
        return STATUS_SUCCESS;
    }
    LPVOID ios_jit_orig_addr = NULL;  /* JIT pool RX addr if caller passed one */
    {
        LPVOID orig_addr = addr;
        LPVOID reversed = (LPVOID)ios_jit_reverse_translate_addr(addr);
        if (reversed != orig_addr)
        {
            /* Caller passed a JIT-pool RX address. Translate to parent for the
             * Wine-side protection update, but remember the original so we can
             * also flip the JIT-pool RX page's posix prot — otherwise a write
             * via the JIT-pool RX address (e.g. FEX's PatchCallChecker writing
             * to its own __ImageBase + RVA) faults because the RX side stays
             * read-only even after the parent becomes RW. */
            ios_jit_orig_addr = orig_addr;
            addr = reversed;
        }
        ERR("NtProtectVirtualMemory(orig=%p reversed=%p sz=0x%lx prot=0x%x)\n",
            orig_addr, addr, (unsigned long)*size_ptr, new_prot);
    }
#endif

    TRACE("%p %p %08lx %08x\n", process, addr, size, new_prot );

#ifdef WINE_IOS
    /* iOS: relax the NULL-old_prot rejection. Wine PE-side ntdll's arm64ec
     * notify-memory-protect path passes NULL when the caller doesn't care
     * about the old prot. Standard Windows would reject this with AV, but on
     * iOS that breaks our IAT-sync (which needs the protect change to apply)
     * — the JIT-pool slots stay zero, exit thunks BLR to garbage and SEGV.
     * Substitute a local sink so the protection change + IAT sync still run. */
    DWORD ios_old_prot_sink;
    if (!old_prot) old_prot = &ios_old_prot_sink;
#else
    if (!old_prot)
        return STATUS_ACCESS_VIOLATION;
#endif

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_protect.type = APC_VIRTUAL_PROTECT;
        call.virtual_protect.addr = wine_server_client_ptr( addr );
        call.virtual_protect.size = size;
        call.virtual_protect.prot = new_prot;
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_protect.status == STATUS_SUCCESS)
        {
            *addr_ptr = wine_server_get_ptr( result.virtual_protect.addr );
            *size_ptr = result.virtual_protect.size;
            *old_prot = result.virtual_protect.prot;
        }
        else *old_prot = PAGE_NOACCESS;
        return result.virtual_protect.status;
    }

    /* Fix the parameters */

    size = ROUND_SIZE( addr, size, page_mask );
    base = ROUND_ADDR( addr, page_mask );

#ifdef WINE_IOS
    /* ml1244: the loader's IAT restore call; the thunks are still writable here */
    ios_x64_iat_bind_live_data( base, size );
#endif

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if ((view = find_view( base, size )))
    {
        /* Make sure all the pages are committed */
        if (get_committed_size( view, base, size, &vprot, VPROT_COMMITTED ) >= size && (vprot & VPROT_COMMITTED))
        {
            old = get_win32_prot( vprot, view->protect );
            status = set_protection( view, base, size, new_prot );
        }
        else status = STATUS_NOT_COMMITTED;
    }
    else status = STATUS_INVALID_PARAMETER;

    if (!status)
    {
        __sync_fetch_and_add( &ios_vprotect_seq, 1 );
        VIRTUAL_DEBUG_DUMP_VIEW( view );
    }

#ifdef WINE_IOS
    /* madeira-bcd: [prot-img] -- protection changes of 64 KB or more on the
     * process's own main image, with the section they start in. GTA V Enhanced
     * died executing GTA5_Enhanced.exe+0x509a144, in sections the emulator was
     * never told were made executable. Whether the emulator WAS told cannot be
     * read here: the PE wrapper enters this syscall with InSyscallCallback set
     * on the notified path too (enter_syscall_callback() comes first), so the
     * flag is 1 either way (build 327: every line said insc=1, which meant
     * nothing, so it is gone). The answer is the PE side's [exec-req] line and
     * FEX's "Add SMC interval" after it. First 48 per session.
     * (GTA V Enhanced's NoExec crash.) */
    {
        static int prot_img_n;
        PEB *cur_peb = NtCurrentTeb() ? NtCurrentTeb()->Peb : NULL;

        if (view && (view->protect & SEC_IMAGE) && size >= 0x10000 && prot_img_n < 48 &&
            cur_peb && cur_peb->ImageBaseAddress == view->base)
        {
            extern int ios_image_section_describe( unsigned long long va, char *buf, size_t len,
                                                   unsigned long long *img_base );
            char sec[160];

            prot_img_n++;
            if (!ios_image_section_describe( (uintptr_t)base, sec, sizeof(sec), NULL ))
                snprintf( sec, sizeof(sec), "(no pool copy)" );
            dprintf( 2, "[prot-img] #%d tid=%04x %p+%#lx (rva %#lx) new_prot=%#x old=%#x status=%#x | %s\n",
                     prot_img_n, (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread, base,
                     (unsigned long)size, (unsigned long)((char *)base - (char *)view->base),
                     (unsigned)new_prot, status ? 0u : (unsigned)old, status, sec );
        }
    }
#endif

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

#ifdef WINE_IOS
    /* A refused read-only RESTORE inside a pool-copied image.
     *
     * The loader makes an import table writable, binds it, and restores the
     * section protection; the restore is what runs the IAT sync below, which
     * copies the bound slots into the image's JIT-pool copy -- the copy the
     * code actually runs from. When the host refuses that restore (set_vprot
     * fails on the 16 KB host page), the sync never ran and the copy kept the
     * unbound hint/name RVAs. 32-bit Crysis: wow64.dll relocated off its
     * preferred base, `[vmem-denied] set_vprot failed ... protect=0x2` on its
     * .rdata IAT page, then Wow64LdrpInitialize branched to a hint/name RVA.
     *
     * For a protection that keeps READ and drops WRITE on a pool-copied image,
     * leave the page as it is (more permissive than asked, never less) and
     * report success, so the sync still copies the parent -- the source of
     * truth. */
    if (status == STATUS_ACCESS_DENIED && view &&
        (new_prot & (PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) &&
        !(new_prot & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
    {
        int mi, in_pool_image = 0;
        for (mi = 0; mi < ios_jit_mapping_count; mi++)
        {
            uintptr_t ps = (uintptr_t)ios_jit_mappings[mi].pe_base;
            if ((uintptr_t)base >= ps && (uintptr_t)base + size <= ps + ios_jit_mappings[mi].size)
            {
                in_pool_image = 1;
                break;
            }
        }
        if (in_pool_image)
        {
            static int restore_lines;
            if (restore_lines++ < 16)
                dprintf( 2, "[vmem-denied] restore to 0x%x refused at %p+0x%lx inside a pool-copied image "
                            "-- page left as is, IAT sync runs\n",
                         (unsigned)new_prot, base, (unsigned long)size );
            status = STATUS_SUCCESS;
        }
    }
#endif

    if (status == STATUS_SUCCESS)
    {
        *addr_ptr = base;
        *size_ptr = size;
        *old_prot = old;

#ifdef WINE_IOS
        /* (Previously: also called mprotect_exec on the JIT-pool RX side
         * here, but that uses vm_protect+VM_PROT_COPY which makes the page
         * PRIVATE — breaking the dual-map sharing with the RW alias. We rely
         * on the Mach SEGV handler's STR emulation instead: stores to JIT-RX
         * are detected and redirected to the RW alias. Writes via RW alias
         * remain visible to subsequent reads via the RX alias because the
         * dual-mapping is preserved.) */

        /* After import resolution: PE loader makes IAT writable, fills it, then
         * restores protection. When write access is removed from a JIT-mapped region,
         * sync the data from original PE to JIT pool and translate function pointers.
         * Also fires on PAGE_READWRITE → PAGE_WRITECOPY (the pattern Wine's
         * arm64ec_update_hybrid_metadata uses to restore section protection
         * after writing dispatcher slots — without this the JIT-pool copy of
         * the metadata table never sees the SET_FUNC writes). */
        /* Always sync parent → JIT for any NtProtectVirtualMemory call on a
         * JIT-mapped region. The old/new comparison can't reliably detect
         * writes-then-restore patterns because get_win32_prot() reports the
         * section's allocation prot (PAGE_WRITECOPY for .data) — not the
         * actual per-page state — so RW→WRITECOPY transitions read as 0x8→0x8.
         * Over-syncing is OK: parent is always the source of truth. */
        ERR("iOS NtProtect-sync-check: base=%p sz=0x%lx old=0x%x new=0x%x\n",
            base, (unsigned long)size, old, new_prot);
        /* iOS-Madeira 2026-05-13: bail out if the new protection makes the
         * source region unreadable. The sync below memcpys from `base` into
         * the JIT pool. When the caller is revoking read access (e.g.
         * PAGE_NOACCESS=1, or any prot without READ bit), the source page
         * becomes inaccessible and memcpy faults inside Apple's iOS shared
         * cache (BUS at the SIMD LDP). Each fault is caught by SEH and the
         * memcpy creeps forward 0x20 bytes per fault — 300s of progress for
         * one stuck region. Thumper hit this on FMOD's PAGE_NOACCESS guard
         * pages. No data to copy when the parent is unreadable anyway. */
        {
            unsigned read_bits = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                 PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                 PAGE_EXECUTE_WRITECOPY;
            if (!(new_prot & read_bits))
            {
                ERR("iOS NtProtect-sync: SKIP (new_prot=0x%x has no READ bit)\n", new_prot);
                return status;
            }
        }
        if (1)
        {
            int idx;
            /* write into the copy of the WRITING process, not the first copy
             * of the image (see ios_iat_sync_pick_mapping) */
            int sync_pick = ios_iat_sync_pick_mapping( (uintptr_t)base, (uintptr_t)base + size,
                                                       ios_jit_current_peb() );
            ERR("iOS NtProtect-sync: triggered, scanning %d JIT mappings\n", ios_jit_mapping_count);
            for (idx = 0; idx < ios_jit_mapping_count; idx++)
            {
                uintptr_t pe_start = (uintptr_t)ios_jit_mappings[idx].pe_base;
                uintptr_t pe_end = pe_start + ios_jit_mappings[idx].size;
                uintptr_t rgn_start = (uintptr_t)base;
                uintptr_t rgn_end = rgn_start + size;

                if (idx != sync_pick) continue;
                if (rgn_start >= pe_start && rgn_end <= pe_end)
                {
                    /* iOS-Madeira ml632 A/B: DO NOT IAT-SYNC MEMORY OWNED BY AN ANON JIT ALIAS.
                     *
                     * Containment against the PE image is not sufficient ownership: the
                     * anon-RWX classifier above is all-or-nothing, so pages can be inside a
                     * PE image AND inside a live anonymous JIT alias. Writing the pool copy
                     * of the image over them clobbers whatever the guest JIT put there.
                     * The alias table is the stronger claim — it means a JIT actually took
                     * this memory — so it wins. */
                    uintptr_t ov_b = 0, ov_e = 0;
                    extern int ios_jit_anon_alias_overlaps(void *, size_t, uintptr_t *, uintptr_t *);
                    if (ios_jit_anon_alias_overlaps( base, size, &ov_b, &ov_e ))
                    {
                        static int skip_n;
                        if (skip_n < 16)
                            dprintf(2, "[mixed-map] ml632 SKIP iat-sync #%d region %p+0x%lx — owned by anon JIT alias "
                                       "[%p,%p) (image %p+0x%lx)\n",
                                    ++skip_n, base, (unsigned long)size, (void *)ov_b, (void *)ov_e,
                                    (void *)pe_start, (unsigned long)(pe_end - pe_start));
                        break;
                    }

                    /* Region is within this JIT-mapped PE image — sync to JIT pool.
                     * IMPORTANT: skip any overlap with .text (code) section to avoid
                     * overwriting JIT-relocated code with the original unix mapping copy. */
                    size_t off = rgn_start - pe_start;
                    uintptr_t pool_offset = (uintptr_t)ios_jit_mappings[idx].jit_base
                                          - (uintptr_t)ios_jit_rx_base_global;
                    char *jit_rw_dest = (char *)ios_jit_rw_base_global + pool_offset + off;
                    /* iOS-Madeira ml1199: words the pointer translation below must leave alone.
                     *
                     * That translation rewrites every 8-byte word whose value lies inside ANY
                     * live image (ml454 accepts any containing mapping) -- including constants
                     * that only look like addresses. In a session with a 32-bit process, its
                     * wow64.dll sits at [0x3fff90000, 0x400000000), and fmt's count_digits
                     * table in xtajit64's .rdata holds 0x3fffffc18 three times (the 1000..9999
                     * entries): a 64-bit child's sync "translated" them into wow64.dll's pool
                     * copy, fmt then counted 3 digits for 2048, and FEX died formatting its
                     * own log line in a 64-bit process started while a 32-bit one was alive
                     * (a diff of the copy against the image: 3 .rdata words differed).
                     *
                     * The pointers this sync must translate are relocation targets (DIR64
                     * entries of the image) and words the loader wrote at run time (IAT, CFG
                     * and CHPE pointers), which differ from what the copy already holds. A
                     * word that is identical in the image and in the copy and is no
                     * relocation target came from the file unchanged, so it is no pointer
                     * that needs a pool address. Only for images with a .reloc directory
                     * (a relocs-stripped image keeps the old rule) and regions up to 4MB;
                     * MADEIRA_IAT_SYNC_KEEP=0 restores the old rule. */
                    static unsigned char ios_sync_keep[0x10000];   /* 1 bit per word: 4MB */
                    /* The bitmap is one static shared by every thread of every pseudo-process,
                     * and this runs after virtual_mutex is released: two syncs at once would
                     * mix their bits (a pointer left untranslated, a constant translated).
                     * Held from building the bitmap to the end of the translation below. */
                    static pthread_mutex_t ios_sync_keep_lock = PTHREAD_MUTEX_INITIALIZER;
                    static int ios_sync_keep_on = -1;
                    int keep_ok = 0, keep_locked = 0;
                    unsigned long keep_hits = 0;
                    if (ios_sync_keep_on < 0)
                    {
                        const char *e = getenv( "MADEIRA_IAT_SYNC_KEEP" );   /* ml1199: 0 = the iat-sync translates unchanged file words too (old rule) */
                        ios_sync_keep_on = !(e && e[0] == '0');
                    }
                    if (ios_sync_keep_on && ios_jit_mappings[idx].reloc_rva && ios_jit_mappings[idx].reloc_size &&
                        !(off & 7) && size / 8 <= sizeof(ios_sync_keep) * 8)
                    {
                        const uint64_t *src = (const uint64_t *)base, *dst = (const uint64_t *)jit_rw_dest;
                        const char *rel = (const char *)ios_jit_rw_base_global + pool_offset
                                          + ios_jit_mappings[idx].reloc_rva;
                        pthread_mutex_lock( &ios_sync_keep_lock );
                        keep_locked = 1;
                        const char *rel_end = rel + ios_jit_mappings[idx].reloc_size;
                        size_t nw = size / 8, k;

                        memset( ios_sync_keep, 0, (nw + 7) / 8 );
                        for (k = 0; k < nw; k++)
                            if (src[k] == dst[k]) ios_sync_keep[k >> 3] |= (unsigned char)(1u << (k & 7));
                        while (rel + 8 <= rel_end)
                        {
                            unsigned int page = *(const unsigned int *)rel, bs = *(const unsigned int *)(rel + 4), j;
                            if (bs < 8 || rel + bs > rel_end) break;
                            for (j = 0; j < (bs - 8) / 2; j++)
                            {
                                unsigned short e = *(const unsigned short *)(rel + 8 + 2 * j);
                                size_t rva = page + (e & 0xfff), w;
                                if ((e >> 12) != 10 || rva + 8 <= off || rva >= off + size) continue;
                                for (w = (rva - off) / 8; w <= (rva + 7 - off) / 8 && w < nw; w++)
                                    ios_sync_keep[w >> 3] &= (unsigned char)~(1u << (w & 7));
                            }
                            rel += bs;
                        }
                        keep_ok = 1;
                    }

                    /* Compare code before any copy overwrites .hexpthk changes.
                     * Prefer the caller's byte range over the rounded host page. */
                    {
                        unsigned r, count = __atomic_load_n( &ios_jit_mappings[idx].code_range_count, __ATOMIC_ACQUIRE );
                        size_t trace_lo = off, trace_hi = off + size;
                        uintptr_t requested = (uintptr_t)ios_patch_requested;
                        if (requested >= rgn_start && requested <= rgn_end &&
                            ios_patch_length <= rgn_end - requested)
                        {
                            trace_lo = requested - pe_start;
                            trace_hi = trace_lo + ios_patch_length;
                        }
                        if (count > IOS_JIT_MAX_CODE_RANGES) count = 0;
                        for (r = 0; r < (count ? count : 1); r++)
                        {
                            size_t lo = count ? ios_jit_mappings[idx].code_ranges[r].offset : ios_jit_mappings[idx].text_offset;
                            size_t n = count ? ios_jit_mappings[idx].code_ranges[r].size : ios_jit_mappings[idx].text_size;
                            size_t hi;
                            if (lo > ios_jit_mappings[idx].size || n > ios_jit_mappings[idx].size - lo) continue;
                            hi = lo + n;
                            if (lo < trace_lo) lo = trace_lo;
                            if (hi > trace_hi) hi = trace_hi;
                            if (hi > lo)
                                ios_ec_hook_report( idx, (const unsigned char *)pe_start + lo,
                                    (const unsigned char *)ios_jit_rw_base_global + pool_offset + lo, hi - lo );
                        }
                    }

                    /* Determine .text section bounds within THIS region */
                    size_t text_off = ios_jit_mappings[idx].text_offset;
                    size_t text_sz  = ios_jit_mappings[idx].text_size;

                    /* Absolute range of .text within the PE image address space */
                    uintptr_t text_abs_start = pe_start + text_off;
                    uintptr_t text_abs_end   = text_abs_start + text_sz;

                    if (text_sz == 0 || text_abs_end <= rgn_start || text_abs_start >= rgn_end)
                    {
                        /* No overlap with .text — safe to copy whole region */
                        memcpy(jit_rw_dest, base, size);
                        ERR("iOS JIT IAT sync: full copy %p+0x%lx → JIT (no text overlap)\n",
                            base, (unsigned long)size);
                    }
                    else
                    {
                        /* Copy only the parts OUTSIDE .text */
                        size_t overlap_start = text_abs_start > rgn_start ? text_abs_start - rgn_start : 0;
                        size_t overlap_end   = text_abs_end   < rgn_end   ? text_abs_end   - rgn_start : size;

                        if (overlap_start > 0)
                            memcpy(jit_rw_dest, (char *)base, overlap_start);
                        if (overlap_end < size)
                            memcpy(jit_rw_dest + overlap_end, (char *)base + overlap_end, size - overlap_end);

                        ERR("iOS JIT IAT sync: partial copy %p+0x%lx → JIT (skipping text [0x%lx-0x%lx])\n",
                            base, (unsigned long)size,
                            (unsigned long)overlap_start, (unsigned long)overlap_end);
                    }

                    /* Re-apply DIR64 relocations within the synced region.
                     * The memcpy overwrote DIR64-relocated values with fresh
                     * unrelocated data from the unix mapping. Walk the PE reloc
                     * table and re-apply entries that fall within this region. */
                    if (ios_jit_mappings[idx].reloc_rva && ios_jit_mappings[idx].reloc_size
                        && ios_jit_mappings[idx].reloc_delta)
                    {
                        uintptr_t pe_start_addr = (uintptr_t)ios_jit_mappings[idx].pe_base;
                        uintptr_t pool_base = (uintptr_t)ios_jit_mappings[idx].jit_base
                                             - (uintptr_t)ios_jit_rx_base_global;
                        char *rw_image = (char *)ios_jit_rw_base_global + pool_base;
                        unsigned int r_rva = ios_jit_mappings[idx].reloc_rva;
                        unsigned int r_sz  = ios_jit_mappings[idx].reloc_size;
                        uint64_t img_base  = ios_jit_mappings[idx].pe_image_base;
                        intptr_t r_delta   = ios_jit_mappings[idx].reloc_delta;
                        size_t img_size    = ios_jit_mappings[idx].size;
                        /* Region bounds as offsets within the PE image */
                        size_t rgn_off_start = off;
                        size_t rgn_off_end   = off + size;
                        char *block = rw_image + r_rva;
                        char *block_end = block + r_sz;
                        int dir64_count = 0;

                        while (block < block_end)
                        {
                            unsigned int block_rva  = *(unsigned int *)block;
                            unsigned int block_size = *(unsigned int *)(block + 4);
                            int j2, num_entries;
                            unsigned short *entries;

                            if (!block_size || block_size < 8) break;
                            num_entries = (block_size - 8) / 2;
                            entries = (unsigned short *)(block + 8);

                            for (j2 = 0; j2 < num_entries; j2++)
                            {
                                int type = entries[j2] >> 12;
                                int eoff = entries[j2] & 0xFFF;
                                unsigned int fixup_rva = block_rva + eoff;

                                if (type == 0) continue;
                                if (type != 10) continue; /* IMAGE_REL_BASED_DIR64 */

                                /* Only fix entries within the synced region */
                                if (fixup_rva < rgn_off_start || fixup_rva + 8 > rgn_off_end)
                                    continue;

                                {
                                    uint64_t *fixup = (uint64_t *)(rw_image + fixup_rva);
                                    uint64_t val = *fixup;
                                    if (val >= img_base && val < img_base + img_size)
                                    {
                                        *fixup += r_delta;
                                        dir64_count++;
                                    }
                                }
                            }
                            block += block_size;
                        }
                        if (dir64_count)
                            ERR("iOS JIT IAT sync: re-applied %d DIR64 fixups in region %p+0x%lx\n",
                                dir64_count, base, (unsigned long)size);
                    }

                    /* Translate pointers: scan for 64-bit values that point to
                     * original PE image addresses and translate to JIT pool.
                     * Translates ALL pointers within a PE mapping (not just .text),
                     * since IAT sync copies relocated data from the PE-side view
                     * which has unix_base-relative pointers. These must become
                     * jit_base-relative to match the DIR64-fixuped JIT copy. */
                    {
                        /* OWNER-AWARE (2026-07-07): ntdll's image VA range
                         * matches the session copy AND every same-arch child
                         * copy — the old first-match scan always picked the
                         * session's entry, so child modules' ntdll imports
                         * pointed at the SESSION pool copy. services.exe's
                         * rpcrt4 IAT got session-copy Tp* → threadpool
                         * workers born executing the wrong ntdll → exit
                         * crash in LdrShutdownThread holding the session
                         * loader lock → rpcss never answered explorer's
                         * CoRegisterClassObject. The sync runs on the owning
                         * process's thread, so current-peb is the owner. */
                        void *sync_owner = ios_jit_current_peb();
                        uint64_t *p = (uint64_t *)jit_rw_dest;
                        uint64_t *end_p = (uint64_t *)(jit_rw_dest + (size & ~7));
                        int fixup_count = 0;
                        /* task #34 [ec-poison] PROBE ONLY — changes nothing.
                         *
                         * This loop rewrites EVERY 8-byte word whose value looks
                         * like a PE image address (24608 of them in
                         * steamwebhelper.exe alone, ml100). That is correct for
                         * an ARM64EC function pointer, which must reach the pool
                         * copy — and WRONG for an x86 one, which must stay a
                         * guest PE address so FEX can translate it. A poisoned
                         * x86 pointer sends the guest into the pool, which is
                         * exactly the [rip-leak] signature (ml95, ml100: guest
                         * RIP holding a pool address that reverse-translates to
                         * a real module+rva).
                         *
                         * peb->EcCodeBitMap already distinguishes the two. Count
                         * how many translations target NON-EC (x86) code before
                         * changing any behaviour — the sync fixed real bugs (the
                         * rpcss milestone depends on it), so it does not get
                         * narrowed on a hunch. */
                        /* ml102 FIX: do NOT rewrite pointers into x86-64 code.
                         * The probe measured 74985 of 133709 translations
                         * (56.08%) landing on x86 .text — each one a pool
                         * address planted where the guest expects a PE address,
                         * which is the [rip-leak] death (ml95/ml100: guest RIP
                         * holding a pool address that reverse-translates to a
                         * real module+rva). Data pointers and ARM64EC code
                         * pointers still translate, because for those the pool
                         * copy IS the live one — this only removes the case that
                         * is always wrong. Ratios varied per region (2/2,
                         * 6006/18029, 161/2240), which is what distinguishes
                         * this from the earlier EcCodeBitMap probe that reported
                         * a meaningless 100%. */
                        int x86skip = 0, execskip = 0;
                        uint64_t x86_first = 0, exec_first = 0;
                        /* ml1017: ONE section lookup per region, not per slot.
                         *
                         * The first version called a PE-header parse plus a full
                         * section walk for every translatable 8-byte slot --
                         * ~72,000 times in one run -- and the loading screen
                         * visibly crawled. A 4 KB region lies inside a single
                         * section in all but pathological cases, so resolve the
                         * region once and reuse it; a region that straddles a
                         * boundary is handled by testing both ends and only
                         * treating it as executable when both agree. */
                        const int skip_exec = ios_iat_skip_exec_dest();   /* ml1017 */
                        int region_is_exec = 0;
                        if (skip_exec)
                        {
                            size_t img_sz = (size_t)(pe_end - pe_start);
                            region_is_exec = ios_img_off_is_exec( (const void *)pe_start, img_sz, off ) &&
                                             ios_img_off_is_exec( (const void *)pe_start, img_sz,
                                                                  off + (size > 8 ? size - 8 : 0) );
                        }
                        /* ml1017: the .text window in REGION-RELATIVE bytes, the
                         * same arithmetic the partial memcpy above uses.
                         *
                         * My first attempt passed jit_rw_dest to a PE-header
                         * parser, but jit_rw_dest is the destination for THIS
                         * sub-region, not the image base -- the MZ check failed
                         * and the guard silently never fired (measured: 0 hits
                         * while the sync still reported "translated 4 pointers"
                         * on the offending page). The mapping already carries
                         * text_offset/text_size, so use those. */
                        size_t txt_lo = text_abs_start > rgn_start ? text_abs_start - rgn_start : 0;
                        size_t txt_hi = text_abs_end   < rgn_end   ? text_abs_end   - rgn_start : size;
                        if (!text_sz || text_abs_end <= rgn_start || text_abs_start >= rgn_end)
                            txt_lo = txt_hi = 0;   /* no overlap with this region */
                        while (p < end_p)
                        {
                            uint64_t val = *p;
                            size_t kw = (size_t)(p - (uint64_t *)jit_rw_dest);   /* ml1199 */
                            if (val && keep_ok && (ios_sync_keep[kw >> 3] & (1u << (kw & 7))))
                            {
                                if (ios_jit_translate_addr_for_owner( (void *)(uintptr_t)val, sync_owner )
                                    != (void *)(uintptr_t)val)
                                    keep_hits++;   /* a file constant that merely looks like an address */
                                p++;
                                continue;
                            }
                            if (val)
                            {
                                void *nv = ios_jit_translate_addr_for_owner(
                                        (void *)(uintptr_t)val, sync_owner);
                                if (nv != (void *)(uintptr_t)val)
                                {
                                    if (ios_va_is_x86_code( val ))
                                    {
                                        if (!x86skip) x86_first = val;
                                        x86skip++;
                                    }
                                    /* ml1017: never rewrite a slot that lies in
                                     * .text -- that is code, and an 8-byte window
                                     * over instructions can look translatable by
                                     * coincidence. The memcpy above already skips
                                     * .text for exactly this reason; this loop
                                     * never inherited that, and walked the whole
                                     * region including code. */
                                    else if (region_is_exec)
                                    {
                                        if (!execskip) exec_first = val;
                                        execskip++;
                                    }
                                    else
                                    {
                                        *p = (uint64_t)(uintptr_t)nv;
                                        fixup_count++;
                                    }
                                }
                            }
                            p++;
                        }
                        static int ml1017_said;   /* ml1017: 20,544 unbounded log lines was most of the slowdown */
                        if (execskip && ml1017_said++ < 32)
                            dprintf(2, "[iat-sync] ml1017 region %p+0x%lx: DECLINED %d rewrite(s) in EXECUTABLE sections "
                                    "(largest .text here is [+0x%lx,+0x%lx)) (first value 0x%llx) -- rewriting those corrupts the code FEX runs\n",
                                    base, (unsigned long)size, execskip,
                                    (unsigned long)txt_lo, (unsigned long)txt_hi,
                                    (unsigned long long)exec_first);
                        /* ml1051: 165,000 lines in one run. First 64, then 1 in 2000. */
                        static unsigned long ml1051_sync_n;
                        unsigned long ml1051_k = __sync_add_and_fetch(&ml1051_sync_n, 1);
                        int ml1051_say = ml1051_k <= 64 || !(ml1051_k % 2000);
                        if (x86skip && ml1051_say)
                            dprintf(2, "[x86-ptr] region %p+0x%lx: KEPT %d guest x86-CODE pointers (first 0x%llx), translated %d others\n",
                                    base, (unsigned long)size, x86skip,
                                    (unsigned long long)x86_first, fixup_count);
                        {
                            static int ml1199_said;
                            if (keep_hits && ml1199_said++ < 32)
                                dprintf(2, "[iat-sync] ml1199 region %p+0x%lx: kept %lu unchanged non-relocation word(s) "
                                        "that look like image addresses (file constants, not pointers)\n",
                                        base, (unsigned long)size, keep_hits);
                        }
                        /* dprintf, not ERR — the perf WINEDEBUG default mutes
                         * err+virtual and this is the owner-routing evidence. */
                        if (fixup_count && ml1051_say)
                            dprintf(2, "[iat-sync] region %p+0x%lx: translated %d pointers (owner=%p) [#%lu]\n",
                                    base, (unsigned long)size, fixup_count, sync_owner, ml1051_k);
                    }
                    if (keep_locked) pthread_mutex_unlock( &ios_sync_keep_lock );
                    break;
                }
            }
        }
#endif
    }
    else *old_prot = PAGE_NOACCESS;
    /* After the existing IAT sync, observe both copies without touching them. */
#ifdef WINE_IOS
    ios_trace_image_patch( ios_patch_requested, ios_patch_length, new_prot, status );
#endif
    return status;
}


static struct file_view *get_memory_region_size( char *base, char **region_start, char **region_end,
                                                 BOOL *fake_reserved )
{
    struct wine_rb_entry *ptr;
    struct file_view *view;

    *fake_reserved = FALSE;
    *region_start = NULL;
    *region_end = working_set_limit;

    ptr = views_tree.root;
    while (ptr)
    {
        view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );
        if ((char *)view->base > base)
        {
            *region_end = view->base;
            ptr = ptr->left;
        }
        else if ((char *)view->base + view->size <= base)
        {
            *region_start = (char *)view->base + view->size;
            ptr = ptr->right;
        }
        else
        {
            *region_start = view->base;
            *region_end = (char *)view->base + view->size;
            return view;
        }
    }
#ifdef __i386__
    {
        struct reserved_area *area;

        /* on i386, pretend that space outside of a reserved area is allocated,
         * so that the app doesn't believe it's fully available */
        LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
        {
            char *area_start = area->base;
            char *area_end = area_start + area->size;

            if (area_end <= base)
            {
                if (*region_start < area_end) *region_start = area_end;
                continue;
            }
            if (area_start <= base || area_start <= (char *)address_space_start)
            {
                if (area_end < *region_end) *region_end = area_end;
                return NULL;
            }
            /* report the remaining part of the 64K after the view as free */
            if ((UINT_PTR)*region_start & granularity_mask)
            {
                char *next = (char *)ROUND_ADDR( *region_start, granularity_mask ) + granularity_mask + 1;

                if (base < next)
                {
                    *region_end = min( next, *region_end );
                    return NULL;
                }
                else *region_start = base;
            }
            /* pretend it's allocated */
            if (area_start < *region_end) *region_end = area_start;
            break;
        }
        *fake_reserved = TRUE;
    }
#endif
    return NULL;
}


#ifdef WINE_IOS
/**********************************************************************
 * ml1101: VirtualQuery must not call memory MEM_FREE that VirtualAlloc
 * can never hand out.
 *
 * Measured (dsr-log-dearxan2, 29.09): a mod tool looks for a free block
 * within +-2 GB of a fixed-base exe at 0x140000000, starting at
 * 0xc3820000. VirtualQuery said MEM_FREE (the view tree is empty there),
 * the tool called VirtualAlloc(0xc3820000, 16MB, RESERVE|COMMIT, RWX), and
 * mach_vm_map answered KERN_INVALID_ADDRESS (ml814 STAGE=fixed-map err=1,
 * status c0000017): below the task's VM floor (iOS 4 GB __PAGEZERO and the
 * slid main binary) nothing can be mapped. The same run then burned 4000+
 * failed page-by-page requests at 0x7200000000.. (err=3 KERN_NO_SPACE):
 * host mappings (CoreAnimation, dyld, the JIT pool, ...) that are not Wine
 * views and were reported as MEM_FREE too.
 *
 * Windows semantics: MEM_FREE means "a VirtualAlloc at this address can
 * succeed". So for a range the view tree calls free:
 *   - below the map floor (max(address_space_start, TASK_VM_INFO
 *     min_address)) report MEM_RESERVE up to the floor;
 *   - otherwise ask the kernel where the next host mapping is. Host ranges
 *     inside a Wine reserved area stay free (map_fixed_area may overwrite
 *     them); any other host mapping ends the free region, and if it covers
 *     the queried address itself the answer is MEM_RESERVE for its extent.
 * Only the MEM_FREE answer is narrowed; views, commits and every allocation
 * path are untouched. Skipped in a WoW64 pseudo-process (32-bit guest
 * addresses keep their previous answer).
 * Kill switch: MADEIRA_NO_QUERY_CLIP=1. */
static int ios_query_clip_enabled(void)
{
    static int dec = -1;
    if (dec < 0)
    {
        const char *off = getenv( "MADEIRA_NO_QUERY_CLIP" );
        dec = (off && *off && *off != '0') ? 0 : 1;
        dprintf( 2, "ml1101: query clip %s\n",
                 dec ? "ENABLED (default)" : "DISABLED by MADEIRA_NO_QUERY_CLIP" );
    }
    return dec;
}

static char *ios_query_map_floor(void)
{
    static char *floor;

    if (!floor)
    {
        task_vm_info_data_t vmi;
        mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;
        char *f = (char *)address_space_start;

        if (task_info( mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &cnt ) == KERN_SUCCESS &&
            (char *)(uintptr_t)vmi.min_address > f)
            f = (char *)(uintptr_t)vmi.min_address;
        floor = f;
        dprintf( 2, "ml1101: query floor %p (address_space_start %p)\n", floor, address_space_start );
    }
    return floor;
}

/* First part of the host-occupied [lo,hi) that is NOT inside a Wine reserved
 * area (reserved_areas is sorted ascending). Returns 0 if all of it is. */
static int ios_query_first_blocked( char *lo, char *hi, char **bs, char **be )
{
    struct reserved_area *area;
    char *cur = lo;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        char *s = area->base, *e = s + area->size;

        if (e <= cur) continue;
        if (s >= hi) break;
        if (s > cur) { *bs = cur; *be = s; return 1; }
        cur = e;
        if (cur >= hi) return 0;
    }
    if (cur < hi) { *bs = cur; *be = hi; return 1; }
    return 0;
}

/* One kernel map entry at or above `at`: returns 0 if nothing is mapped above. */
static int ios_query_host_region( char *at, char **hs, char **he, int *prot, int *maxprot )
{
    mach_vm_address_t ra = (mach_vm_address_t)(uintptr_t)at;
    mach_vm_size_t rs = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;

    if (mach_vm_region( mach_task_self(), &ra, &rs, VM_REGION_BASIC_INFO_64,
                        (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS)
        return 0;
    if (obj != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), obj );
    *hs = (char *)(uintptr_t)ra;
    *he = *hs + rs;
    *prot = info.protection;
    *maxprot = info.max_protection;
    return 1;
}

int ios_addr_max_prot( const void *addr, int *prot )
{
    char *start, *end;
    int current, maximum;

    if (!ios_query_host_region( (char *)addr, &start, &end, &current, &maximum ) ||
        (uintptr_t)addr < (uintptr_t)start || (uintptr_t)addr >= (uintptr_t)end) return -1;
    if (prot) *prot = current;
    return maximum;
}

/* ml1101b: the JIT pool is ONE opaque block for this purpose.
 *
 * Measured (dsr-log-nearalloc, 29.09): with ml1101 a startup walker that
 * queries upward from 0 hung at 100% CPU (samples in mach_msg and
 * pthread_sigmask, stack get_committed_size <- get_basic_memory_info).
 * Cause (from the code): NtQueryVirtualMemory first passes the address
 * through ios_jit_reverse_translate_addr, so a query that lands INSIDE the RX
 * pool on an image copy is answered for the PE image (0x140000000...), whose
 * end lies BELOW the pool -- the walker's next address goes backwards and it
 * loops forever. Before ml1101 the free answer jumped over the pool, so no
 * walker ever landed inside it. Rule: no answer may end strictly inside a
 * pool span; an answer that reaches into a pool is extended to the pool's
 * end. The pool start itself is safe to land on: image copies are bumped
 * from a non-zero offset, so the first byte never reverse-translates. */
static void ios_query_pool_fix( char *base, char *end, char **region_end, BOOL *fake_reserved )
{
    char *spans[2][2];
    int i;

    spans[0][0] = ios_jit_rx_base_global;
    spans[1][0] = ios_jit_rw_base_global;
    for (i = 0; i < 2; i++)
    {
        char *lo = spans[i][0], *hi;

        if (!lo || !ios_jit_pool_size_global) continue;
        hi = lo + ios_jit_pool_size_global;
        if (hi > end) hi = end;
        if (hi <= base || *region_end <= lo) continue;          /* no overlap */
        if (*fake_reserved || base >= lo)
        {
            /* reserved answer touching the pool, or a query inside it: cover it all */
            *fake_reserved = TRUE;
            if (*region_end < hi) *region_end = hi;
        }
        else if (*region_end > lo) *region_end = lo;             /* free answer: stop at the pool */
    }
}

/* Called with virtual_mutex held, only for a range the view tree calls free. */
static void ios_query_clip_free( char *base, char **region_start, char **region_end,
                                 BOOL *fake_reserved )
{
    static int log_n;
    char *floor, *cur = base, *end = *region_end;
    char *hs, *he, *bs, *be, *first_hs = NULL;
    int guard, prot = 0, maxprot = 0, merged = 0;

    if (!ios_query_clip_enabled()) return;
    if (ios_wow_slot_current()) return;

    floor = ios_query_map_floor();
    if (base < floor)
    {
        *fake_reserved = TRUE;
        if (end > floor) *region_end = floor;
        if (log_n < 32)
        {
            log_n++;
            dprintf( 2, "[query-clip] ml1101 %p: FREE -> RESERVE [%p,%p) (below the map floor)\n",
                     base, *region_start, *region_end );
        }
        return;
    }

    for (guard = 0; guard < 64 && cur < end; guard++)
    {
        if (!ios_query_host_region( cur, &hs, &he, &prot, &maxprot )) break;
        if (hs >= end) break;             /* next host mapping lies past the free range */
        if (!first_hs) first_hs = hs;
        if (hs < cur) hs = cur;
        if (he > end) he = end;
        if (ios_query_first_blocked( hs, he, &bs, &be ))
        {
            if (bs > base) *region_end = bs;      /* free only up to the host mapping */
            else
            {
                /* the queried address itself is host-occupied: report it RESERVE and
                 * coalesce the contiguous occupied run (ml1101b: one answer per run,
                 * not one per kernel map entry -- 80k entries on a phone) */
                *fake_reserved = TRUE;
                if ((char *)first_hs > *region_start) *region_start = first_hs;
                while (be < end && merged < 1024)
                {
                    char *nhs, *nhe, *nbs, *nbe;
                    int np, nmp;

                    if (!ios_query_host_region( be, &nhs, &nhe, &np, &nmp )) break;
                    if (nhs > be) break;                              /* a real hole */
                    if (nhe > end) nhe = end;
                    if (!ios_query_first_blocked( be, nhe, &nbs, &nbe ) || nbs != be) break;
                    be = nbe;
                    merged++;
                }
                *region_end = be;
            }
            goto done;
        }
        cur = he;   /* host range entirely inside Wine reserved areas: allocatable */
    }
    if (cur > base && cur < end) *region_end = cur;   /* only what was verified */

done:
    ios_query_pool_fix( base, end, region_end, fake_reserved );
    if (log_n < 32 && (*fake_reserved || *region_end != end))
    {
        log_n++;
        dprintf( 2, "[query-clip] ml1101b %p: first host %p (prot=%d/%d) merged=%d -> %s up to %p\n",
                 base, first_hs, prot, maxprot, merged,
                 *fake_reserved ? "RESERVE" : "FREE", *region_end );
    }
}
#endif

static unsigned int fill_basic_memory_info( const void *addr, MEMORY_BASIC_INFORMATION *info )
{
    char *base, *alloc_base, *alloc_end;
    struct file_view *view;
    BOOL fake_reserved;
    sigset_t sigset;

    base = ROUND_ADDR( addr, page_mask );

    if (is_beyond_limit( base, 1, working_set_limit )) return STATUS_INVALID_PARAMETER;

    /* Find the view containing the address */

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    view = get_memory_region_size( base, &alloc_base, &alloc_end, &fake_reserved );
#ifdef WINE_IOS
    /* ml1101: MEM_FREE only where an allocation can actually land. */
    if (!view && !fake_reserved) ios_query_clip_free( base, &alloc_base, &alloc_end, &fake_reserved );
#endif

    /* Fill the info structure */

    info->BaseAddress = base;
    info->RegionSize  = alloc_end - base;

    if (!view)
    {
        if (fake_reserved)
        {
            info->State             = MEM_RESERVE;
            info->Protect           = PAGE_NOACCESS;
            info->AllocationBase    = alloc_base;
            info->AllocationProtect = PAGE_NOACCESS;
            info->Type              = MEM_PRIVATE;
        }
        else
        {
            info->State             = MEM_FREE;
            info->Protect           = PAGE_NOACCESS;
            info->AllocationBase    = 0;
            info->AllocationProtect = 0;
            info->Type              = 0;
        }
    }
    else
    {
        BYTE vprot;

        info->AllocationBase = alloc_base;
        info->RegionSize = get_committed_size( view, base, ~(size_t)0, &vprot, ~VPROT_WRITEWATCH );
        info->State = (vprot & VPROT_COMMITTED) ? MEM_COMMIT : MEM_RESERVE;
        info->Protect = (vprot & VPROT_COMMITTED) ? get_win32_prot( vprot, view->protect ) : 0;
        info->AllocationProtect = get_win32_prot( view->protect, view->protect );
        if (view->protect & SEC_IMAGE) info->Type = MEM_IMAGE;
        else if (view->protect & (SEC_FILE | SEC_RESERVE | SEC_COMMIT)) info->Type = MEM_MAPPED;
        else info->Type = MEM_PRIVATE;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    return STATUS_SUCCESS;
}

/* get basic information about a memory block */
static unsigned int get_basic_memory_info( HANDLE process, LPCVOID addr,
                                           MEMORY_BASIC_INFORMATION *info,
                                           SIZE_T len, SIZE_T *res_len )
{
    unsigned int status;

    if (len < sizeof(*info))
        return STATUS_INFO_LENGTH_MISMATCH;

    if (process != NtCurrentProcess())
    {
        union apc_call call;
        union apc_result result;

        memset( &call, 0, sizeof(call) );

        call.virtual_query.type = APC_VIRTUAL_QUERY;
        call.virtual_query.addr = wine_server_client_ptr( addr );
        status = server_queue_process_apc( process, &call, &result );
        if (status != STATUS_SUCCESS) return status;

        if (result.virtual_query.status == STATUS_SUCCESS)
        {
            info->BaseAddress       = wine_server_get_ptr( result.virtual_query.base );
            info->AllocationBase    = wine_server_get_ptr( result.virtual_query.alloc_base );
            info->RegionSize        = result.virtual_query.size;
            info->Protect           = result.virtual_query.prot;
            info->AllocationProtect = result.virtual_query.alloc_prot;
            info->State             = (DWORD)result.virtual_query.state << 12;
            info->Type              = (DWORD)result.virtual_query.alloc_type << 16;
            if (info->RegionSize != result.virtual_query.size)  /* truncated */
                return STATUS_INVALID_PARAMETER;  /* FIXME */
            if (res_len) *res_len = sizeof(*info);
        }
        return result.virtual_query.status;
    }

    if ((status = fill_basic_memory_info( addr, info ))) return status;
#ifdef WINE_IOS
    if (ios_thin_live_n) ios_thin_fix_query( addr, info );
#endif

    if (res_len) *res_len = sizeof(*info);
    return STATUS_SUCCESS;
}

static unsigned int get_memory_region_info( HANDLE process, LPCVOID addr, MEMORY_REGION_INFORMATION *info,
                                            SIZE_T len, SIZE_T *res_len )
{
    char *base, *region_start, *region_end;
    struct file_view *view;
    BYTE vprot, vprot_mask;
    BOOL fake_reserved;
    sigset_t sigset;
    SIZE_T size;

    if (len < FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize))
        return STATUS_INFO_LENGTH_MISMATCH;

    if (process != NtCurrentProcess())
    {
        FIXME("Unimplemented for other processes.\n");
        return STATUS_NOT_IMPLEMENTED;
    }

    base = ROUND_ADDR( addr, page_mask );

    if (is_beyond_limit( base, 1, working_set_limit )) return STATUS_INVALID_PARAMETER;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    if ((view = get_memory_region_size( base, &region_start, &region_end, &fake_reserved )))
    {
        info->AllocationBase = view->base;
        info->AllocationProtect = get_win32_prot( view->protect, view->protect );
        info->RegionType = 0; /* FIXME */
        if (len >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, CommitSize))
            info->RegionSize = view->size;
        if (len >= FIELD_OFFSET(MEMORY_REGION_INFORMATION, PartitionId))
        {
            base = region_start;
            info->CommitSize = 0;
            vprot_mask = VPROT_COMMITTED;
            if (!is_view_valloc( view )) vprot_mask |= PAGE_WRITECOPY;
            while (base != region_end &&
                   (size = get_committed_size( view, base, ~(size_t)0, &vprot, vprot_mask )))
            {
                if ((vprot & vprot_mask) == vprot_mask) info->CommitSize += size;
                base += size;
            }
        }
    }
    else
    {
        if (!fake_reserved)
        {
            server_leave_uninterrupted_section( &virtual_mutex, &sigset );
            return STATUS_INVALID_ADDRESS;
        }
        info->AllocationBase = region_start;
        info->AllocationProtect = PAGE_NOACCESS;
        info->RegionType = 0; /* FIXME */
        info->RegionSize = region_end - region_start;
        info->CommitSize = 0;
    }

    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (res_len) *res_len = sizeof(*info);
    return STATUS_SUCCESS;
}

struct working_set_info_ref
{
    char *addr;
    SIZE_T orig_index;
};

#if defined(HAVE_LIBPROCSTAT)
struct fill_working_set_info_data
{
    struct procstat *pstat;
    struct kinfo_proc *kip;
    unsigned int vmentry_count;
    struct kinfo_vmentry *vmentries;
};

static void init_fill_working_set_info_data( struct fill_working_set_info_data *d, char *end )
{
    unsigned int proc_count;

    d->kip = NULL;
    d->vmentry_count = 0;
    d->vmentries = NULL;

    if ((d->pstat = procstat_open_sysctl()))
        d->kip = procstat_getprocs( d->pstat, KERN_PROC_PID, getpid(), &proc_count );
    if (d->kip)
        d->vmentries = procstat_getvmmap( d->pstat, d->kip, &d->vmentry_count );
    if (!d->vmentries)
        WARN( "couldn't get process vmmap, errno %d\n", errno );
}

static void free_fill_working_set_info_data( struct fill_working_set_info_data *d )
{
    if (d->vmentries)
        procstat_freevmmap( d->pstat, d->vmentries );
    if (d->kip)
        procstat_freeprocs( d->pstat, d->kip );
    if (d->pstat)
        procstat_close( d->pstat );
}

static void fill_working_set_info( struct fill_working_set_info_data *d, struct file_view *view, BYTE vprot,
                                   struct working_set_info_ref *ref, SIZE_T count,
                                   MEMORY_WORKING_SET_EX_INFORMATION *info )
{
    SIZE_T i;
    int j;

    for (i = 0; i < count; ++i)
    {
        MEMORY_WORKING_SET_EX_INFORMATION *p = &info[ref[i].orig_index];
        struct kinfo_vmentry *entry = NULL;

        for (j = 0; j < d->vmentry_count; j++)
        {
            if (d->vmentries[j].kve_start <= (ULONG_PTR)p->VirtualAddress && (ULONG_PTR)p->VirtualAddress <= d->vmentries[j].kve_end)
            {
                entry = &d->vmentries[j];
                break;
            }
        }

        p->VirtualAttributes.Valid = !(vprot & VPROT_GUARD) && (vprot & 0x0f) && entry && entry->kve_type != KVME_TYPE_SWAP;
        p->VirtualAttributes.Shared = !is_view_valloc( view );
        if (p->VirtualAttributes.Shared && p->VirtualAttributes.Valid)
            p->VirtualAttributes.ShareCount = 1; /* FIXME */
        if (p->VirtualAttributes.Valid)
            p->VirtualAttributes.Win32Protection = get_win32_prot( vprot, view->protect );
    }
}
#else
static int pagemap_fd = -2;

struct fill_working_set_info_data
{
    UINT64 pm_buffer[256];
    SIZE_T buffer_start;
    ssize_t buffer_len;
    SIZE_T end_page;
};

static void init_fill_working_set_info_data( struct fill_working_set_info_data *d, char *end )
{
    d->buffer_start = 0;
    d->buffer_len = 0;
    d->end_page = (UINT_PTR)end / host_page_size;
    memset( d->pm_buffer, 0, sizeof(d->pm_buffer) );

    if (pagemap_fd != -2) return;

#ifdef O_CLOEXEC
    if ((pagemap_fd = open( "/proc/self/pagemap", O_RDONLY | O_CLOEXEC, 0 )) == -1 && errno == EINVAL)
#endif
        pagemap_fd = open( "/proc/self/pagemap", O_RDONLY, 0 );

    if (pagemap_fd == -1) WARN( "unable to open /proc/self/pagemap\n" );
    else fcntl(pagemap_fd, F_SETFD, FD_CLOEXEC);  /* in case O_CLOEXEC isn't supported */
}

static void free_fill_working_set_info_data( struct fill_working_set_info_data *d )
{
}

static void fill_working_set_info( struct fill_working_set_info_data *d, struct file_view *view, BYTE vprot,
                                   struct working_set_info_ref *ref, SIZE_T count,
                                   MEMORY_WORKING_SET_EX_INFORMATION *info )
{
    MEMORY_WORKING_SET_EX_INFORMATION *p;
    UINT64 pagemap;
    SIZE_T i, page;
    ssize_t len;

    for (i = 0; i < count; ++i)
    {
        page = (UINT_PTR)ref[i].addr / host_page_size;
        p = &info[ref[i].orig_index];

        assert(page >= d->buffer_start);
        if (page >= d->buffer_start + d->buffer_len)
        {
            d->buffer_start = page;
            len = min( sizeof(d->pm_buffer), (d->end_page - page) * sizeof(pagemap) );
            if (pagemap_fd != -1)
            {
                d->buffer_len = pread( pagemap_fd, d->pm_buffer, len, page * sizeof(pagemap) );
                if (d->buffer_len != len)
                {
                    d->buffer_len = max( d->buffer_len, 0 );
                    memset( d->pm_buffer + d->buffer_len / sizeof(pagemap), 0, len - d->buffer_len );
                }
            }
            d->buffer_len = len / sizeof(pagemap);
        }
        pagemap = d->pm_buffer[page - d->buffer_start];

        p->VirtualAttributes.Valid = !(vprot & VPROT_GUARD) && (vprot & 0x0f) && (pagemap >> 63);
        p->VirtualAttributes.Shared = !is_view_valloc( view ) && ((pagemap >> 61) & 1);
        if (p->VirtualAttributes.Shared && p->VirtualAttributes.Valid)
            p->VirtualAttributes.ShareCount = 1; /* FIXME */
        if (p->VirtualAttributes.Valid)
            p->VirtualAttributes.Win32Protection = get_win32_prot( vprot, view->protect );
    }
}
#endif

static int compare_working_set_info_ref( const void *a, const void *b )
{
    const struct working_set_info_ref *r1 = a, *r2 = b;

    if (r1->addr < r2->addr) return -1;
    return r1->addr > r2->addr;
}

static NTSTATUS get_working_set_ex( HANDLE process, LPCVOID addr,
                                    MEMORY_WORKING_SET_EX_INFORMATION *info,
                                    SIZE_T len, SIZE_T *res_len )
{
    struct working_set_info_ref ref_buffer[256], *ref = ref_buffer, *r;
    struct fill_working_set_info_data data;
    char *start, *end;
    SIZE_T i, count;
    struct file_view *view, *prev_view;
    sigset_t sigset;
    BYTE vprot;

    if (process != NtCurrentProcess())
    {
        FIXME( "(process=%p,addr=%p) Unimplemented information class: MemoryWorkingSetExInformation\n", process, addr );
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len < sizeof(*info)) return STATUS_INFO_LENGTH_MISMATCH;

    count = len / sizeof(*info);

    if (count > ARRAY_SIZE(ref_buffer)) ref = malloc( count * sizeof(*ref) );
    for (i = 0; i < count; ++i)
    {
        ref[i].orig_index = i;
        ref[i].addr = ROUND_ADDR( info[i].VirtualAddress, page_mask );
        info[i].VirtualAttributes.Flags = 0;
    }
    qsort( ref, count, sizeof(*ref), compare_working_set_info_ref );
    start = ref[0].addr;
    end = ref[count - 1].addr + page_size;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    init_fill_working_set_info_data( &data, end );

    view = find_view_range( start, end - start );
    while (view && (char *)view->base > start)
    {
        prev_view = RB_ENTRY_VALUE( rb_prev( &view->entry ), struct file_view, entry );
        if (!prev_view || (char *)prev_view->base + prev_view->size <= start) break;
        view = prev_view;
    }

    r = ref;
    while (view && (char *)view->base < end)
    {
        if (start < (char *)view->base) start = view->base;
        while (r != ref + count && r->addr < start) ++r;
        while (start != (char *)view->base + view->size && r != ref + count
               && r->addr < (char *)view->base + view->size)
        {
            start += get_committed_size( view, start, end - start, &vprot, ~VPROT_WRITEWATCH );
            i = 0;
            while (r + i != ref + count && r[i].addr < start) ++i;
            if (vprot & VPROT_COMMITTED) fill_working_set_info( &data, view, vprot, r, i, info );
            r += i;
        }
        if (r == ref + count) break;
        view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
    }

    free_fill_working_set_info_data( &data );
    if (ref != ref_buffer) free( ref );
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    if (res_len)
        *res_len = len;
    return STATUS_SUCCESS;
}

static unsigned int get_memory_section_name( HANDLE process, LPCVOID addr,
                                             MEMORY_SECTION_NAME *info, SIZE_T len, SIZE_T *ret_len )
{
    unsigned int status;

    if (!info) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( get_mapping_filename )
    {
        req->process = wine_server_obj_handle( process );
        req->addr = wine_server_client_ptr( addr );
        if (len > sizeof(*info) + sizeof(WCHAR))
            wine_server_set_reply( req, info + 1, len - sizeof(*info) - sizeof(WCHAR) );
        status = wine_server_call( req );
        if (!status || status == STATUS_BUFFER_OVERFLOW)
        {
            if (ret_len) *ret_len = sizeof(*info) + reply->len + sizeof(WCHAR);
            if (len < sizeof(*info)) status = STATUS_INFO_LENGTH_MISMATCH;
            if (!status)
            {
                info->SectionFileName.Buffer = (WCHAR *)(info + 1);
                info->SectionFileName.Length = reply->len;
                info->SectionFileName.MaximumLength = reply->len + sizeof(WCHAR);
                info->SectionFileName.Buffer[reply->len / sizeof(WCHAR)] = 0;
            }
        }
    }
    SERVER_END_REQ;
    return status;
}

static unsigned int get_memory_image_info( HANDLE process, LPCVOID addr, MEMORY_IMAGE_INFORMATION *info,
                                           SIZE_T len, SIZE_T *res_len )
{
    unsigned int status;

    if (len < sizeof(*info)) return STATUS_INFO_LENGTH_MISMATCH;
    memset( info, 0, sizeof(*info) );

    SERVER_START_REQ( get_image_view_info )
    {
        req->process = wine_server_obj_handle( process );
        req->addr = wine_server_client_ptr( addr );
        status = wine_server_call( req );
        if (!status && reply->base)
        {
            info->ImageBase = wine_server_get_ptr( reply->base );
            info->SizeOfImage = reply->size;
            info->ImageSigningLevel = 12;
        }
    }
    SERVER_END_REQ;

    if (status == STATUS_NOT_MAPPED_VIEW)
    {
        MEMORY_BASIC_INFORMATION basic_info;

        status = get_basic_memory_info( process, addr, &basic_info, sizeof(basic_info), NULL );
        if (status || basic_info.State == MEM_FREE) status = STATUS_INVALID_ADDRESS;
    }

    if (!status && res_len) *res_len = sizeof(*info);
    return status;
}


/* Wine-private MEMORY_INFORMATION_CLASS for the
 * PE-VA -> JIT-pool-copy translation below.  Kept local to the two files that
 * implement and use it (this one and wine/dlls/wow64/syscall.c) rather than
 * added to the public winternl.h enum, which this iOS tree does not own; the
 * value continues the MemoryWine* block (1000..1004 are taken). */
#define MemoryWineIosJitPoolAddress ((MEMORY_INFORMATION_CLASS)1005)
/* ml1203: the ml938 sub-floor image window holding addr, as three ULONG_PTRs
 * {low base, real base, size}. Used by PE-side RtlLookupFunctionTable
 * (wine/dlls/ntdll/unwind.c), which keeps the same value. */
#define MemoryWineIosSubfloorWindow ((MEMORY_INFORMATION_CLASS)1006)

/***********************************************************************
 *             NtQueryVirtualMemory   (NTDLL.@)
 *             ZwQueryVirtualMemory   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryVirtualMemory( HANDLE process, LPCVOID addr,
                                      MEMORY_INFORMATION_CLASS info_class,
                                      PVOID buffer, SIZE_T len, SIZE_T *res_len )
{
    NTSTATUS status;

#ifdef WINE_IOS
    if (info_class == MemoryWineIosSubfloorWindow)
    {
        extern int ios_subfloor_enum( int idx, unsigned long long *low, unsigned long long *real,
                                      unsigned long long *size, void **owner );
        static int on = -1;
        unsigned long long lo, re, sz;
        ULONG_PTR *out = buffer;
        void *peb = ios_jit_current_peb(), *own;
        int i;

        if (on < 0)
        {
            const char *e = getenv( "MADEIRA_SUBFLOOR_SEH" );   /* ml1203: 0 = no unwind data for code at a fixed-base image's low addresses */
            on = !(e && e[0] == '0');
        }
        if (!on || process != NtCurrentProcess()) return STATUS_INVALID_INFO_CLASS;
        if (len < 3 * sizeof(ULONG_PTR)) return STATUS_INFO_LENGTH_MISMATCH;
        for (i = 0; ios_subfloor_enum( i, &lo, &re, &sz, &own ); i++)
        {
            if (own && own != peb) continue;   /* ml1205 */
            if (!sz || !re || (ULONG_PTR)addr < lo || (ULONG_PTR)addr >= lo + sz) continue;
            out[0] = lo;
            out[1] = re;
            out[2] = sz;
            if (res_len) *res_len = 3 * sizeof(ULONG_PTR);
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_ADDRESS;
    }
    /* PE code in JIT pool computes addresses via ADRP relative to JIT PC.
     * Translate JIT addresses back to original PE addresses for VM queries. */
    addr = ios_jit_reverse_translate_addr(addr);
    /* ml966: VirtualQuery on a low guest allocation must describe the backing,
     * otherwise the guest sees "free" for memory it holds. */
    {
        unsigned long long lo_real = 0;
        if (ios_lowalloc_translate( (unsigned long long)(ULONG_PTR)addr, 1, &lo_real, NULL ))
        {
            static int lq_n;
            if (lq_n < 16)
            {
                lq_n++;
                dprintf( 2, "ml966: QUERY on low guest %p -> backing %#llx\n", addr, lo_real );
            }
            addr = (LPCVOID)(ULONG_PTR)lo_real;
        }
        else if (ios_subfloor_image_translate( (unsigned long long)(ULONG_PTR)addr, 1, &lo_real ))
        {
            static int sq_n;   /* ml1201: describe the sub-floor image's real mapping */
            if (sq_n++ < 16)
                dprintf( 2, "ml1201: QUERY on sub-floor image %p -> real %#llx\n", addr, lo_real );
            addr = (LPCVOID)(ULONG_PTR)lo_real;
        }
    }
#endif

    TRACE("(%p, %p, info_class=%d, %p, %ld, %p)\n",
          process, addr, info_class, buffer, len, res_len);

    switch(info_class)
    {
        case MemoryBasicInformation:
            return get_basic_memory_info( process, addr, buffer, len, res_len );

        case MemoryWorkingSetExInformation:
            return get_working_set_ex( process, addr, buffer, len, res_len );

        case MemoryMappedFilenameInformation:
            return get_memory_section_name( process, addr, buffer, len, res_len );

        case MemoryRegionInformation:
            return get_memory_region_info( process, addr, buffer, len, res_len );

        case MemoryImageInformation:
            return get_memory_image_info( process, addr, buffer, len, res_len );

        case MemoryWineLoadUnixLib:
        case MemoryWineLoadUnixLibWow64:
            if (len != sizeof(unixlib_handle_t)) return STATUS_INFO_LENGTH_MISMATCH;
            if (process == GetCurrentProcess())
            {
                void *module = (void *)addr;
                const void *funcs = NULL;

                status = load_builtin_unixlib( module, info_class == MemoryWineLoadUnixLibWow64, &funcs );
                if (!status) *(unixlib_handle_t *)buffer = (UINT_PTR)funcs;
                return status;
            }
            return STATUS_INVALID_HANDLE;

        case MemoryWineLoadUnixLibByName:
        case MemoryWineLoadUnixLibByNameWow64:
            if (process == GetCurrentProcess())
            {
                UINT64 res[2];
                const UNICODE_STRING *name = addr;
                NTSTATUS (*entry)(void);
                const void *funcs;
                void *handle;

                if ((status = load_unixlib_by_name( name, &handle )))
                {
#ifdef WINE_IOS
                    /* iOS-Madeira 2026-05-13: no .so files on iOS for audio
                     * drivers; provide static unix tables for wineios.drv
                     * (silent audio backend). Match by name; success path
                     * returns a magic non-NULL handle so subsequent
                     * MemoryWineUnloadUnixLib doesn't crash. */
                    char ascii[64] = {0};
                    unsigned int nlen = name->Length / sizeof(WCHAR);
                    if (nlen > 0 && nlen < sizeof(ascii))
                    {
                        for (unsigned int i = 0; i < nlen; i++)
                            ascii[i] = (char)(name->Buffer[i] & 0x7f);
                        ascii[nlen] = 0;
                        /* lowercase for substr matching */
                        for (char *p = ascii; *p; p++)
                            if (*p >= 'A' && *p <= 'Z') *p += 'a' - 'A';
                        if (strstr(ascii, "wineios") || strstr(ascii, "winecoreaudio") ||
                            strstr(ascii, "winealsa") || strstr(ascii, "winepulse") ||
                            strstr(ascii, "wineoss"))
                        {
                            /* a 32-bit mmdevapi reaches this as ...ByNameWow64 and
                             * gets the table that reads 32-bit argument blocks */
                            BOOL wow = (info_class == MemoryWineLoadUnixLibByNameWow64);
                            ERR("iOS: MemoryWineLoadUnixLibByName %s -> audio_null_ios %s table\n",
                                ascii, wow ? "wow64" : "64-bit");
                            res[0] = (UINT64)(UINT_PTR)1; /* magic non-NULL handle */
                            res[1] = (UINT64)(UINT_PTR)(wow ? (const void *)audio_null_ios_unix_call_wow64_funcs
                                                            : (const void *)audio_null_ios_unix_call_funcs);
                            memcpy( buffer, res, min( len, sizeof(res) ));
                            return STATUS_SUCCESS;
                        }
                    }
#endif
                    return status;
                }
                res[0] = (UINT_PTR)handle;
                if (!(status = get_unixlib_funcs( handle, info_class == MemoryWineLoadUnixLibByNameWow64,
                                                  &funcs, &entry )))
                {
                    res[1] = (UINT_PTR)funcs;
                    if (entry) status = entry();
                }
                if (status) dlclose( handle );
                else memcpy( buffer, res, min( len, sizeof(res) ));
                return status;
            }
            return STATUS_INVALID_HANDLE;

        case MemoryWineUnloadUnixLib:
            if (process == GetCurrentProcess())
            {
                const unixlib_module_t *handle = addr;

                if (!dlclose( (void *)(UINT_PTR)*handle )) return STATUS_SUCCESS;
            }
            return STATUS_INVALID_HANDLE;

#ifdef WINE_IOS
        /* PE VA -> executable JIT-pool copy.
         *
         * PE code cannot execute at its mapped address here, so every image's
         * code is copied into the dual-mapped pool and a Mach exception
         * redirects a PC that lands on the PE address.  Pointer tables that
         * PE code branches through are normally repaired in bulk — the
         * NtProtect-time [iat-sync] sweep for pointers living inside a pool
         * copy, the [stale-heal] escalation for the rest — but neither can
         * reach a table that is READ from the PE view of a read-only section
         * (the pool copy of that section is already correct, so the heal's
         * exact-value scan finds nothing and the same VA keeps costing one
         * Mach exception per call).  wow64.dll's copy of wow64win.dll's
         * ServiceTable is exactly that case.
         *
         * This class lets PE code ask for the pool address of a function it
         * is about to store in a private dispatch table, so the branch never
         * faults in the first place.  Returns `addr` unchanged when it is not
         * inside a pool-copied image (already-pool addresses included, which
         * makes the call idempotent). */
        case MemoryWineIosJitPoolAddress:
            if (len < sizeof(ULONG_PTR)) return STATUS_INFO_LENGTH_MISMATCH;
            if (process != GetCurrentProcess()) return STATUS_INVALID_HANDLE;
            *(ULONG_PTR *)buffer = (ULONG_PTR)ios_jit_translate_addr( (void *)addr );
            if (res_len) *res_len = sizeof(ULONG_PTR);
            return STATUS_SUCCESS;
#endif

        default:
            FIXME("(%p,%p,info_class=%d,%p,%ld,%p) Unknown information class\n",
                  process, addr, info_class, buffer, len, res_len);
            return STATUS_INVALID_INFO_CLASS;
    }
}


