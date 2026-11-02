/* Part of signal_arm64_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Segv_handler and ios_srcwatch (the bitmap-writer watch). Same copyright and licence as signal_arm64_ios.c. */
/**********************************************************************
 *		segv_handler
 *
 * Handler for SIGSEGV.
 */
static int dumped_page0;   /* ml180: one wide dump, for the page-0 fault only */

/* ml174: is a candidate FEX CpuStateFrame initialised? See the call site. */
static int probe_ptr_ok( uint64_t frame )
{
    uint64_t v = 0;
    mach_vm_size_t g = 0;

    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(frame + 0x40), 8,
                                (mach_vm_address_t)&v, &g ) != KERN_SUCCESS || g != 8)
        return 0;
    return v >= 0x100000000ull && v < 0x8000000000ull;
}

#ifdef WINE_IOS
/* ml375: make wine's own logging survivable in a signal handler.
 *
 * THREE runs (ml370/374/375) died at the identical instruction —
 * `__wine_dbg_header+0x100: ldr w8,[x25,#4]` — and I misread it twice because
 * my slide arithmetic anchored on the wrong symbol. Deriving the slide from
 * the FAULTING INSTRUCTION (search the dylib for the reported insn word, match
 * the delta to a symbol) instead of a guessed anchor is what finally pinned it.
 *
 * Cause: wine's ERR/WARN/TRACE reach __wine_dbg_header -> get_info() ->
 * ntdll_get_thread_data() -> NtCurrentTeb(), and on this port NtCurrentTeb()
 * resolves through TSD slot 275. A thread that never registered a TEB (threads
 * CEF/FEX create directly, and anything faulting before its [tsd275] SET) has
 * slot 275 == NULL, so the very first ERR in a handler dereferences NULL, which
 * raises another SIGSEGV at the SAME pc, forever — the debugger script then
 * kills the app after 8 identical stops. The handler dies reporting the fault
 * it was called to report, which is why the log ends with no explanation.
 *
 * This only became fatal once faults started reaching the BSD handlers again
 * (the ml372 DECLINE path), so it reads like a new bug but is long-latent.
 *
 * Fix: before ANY logging, guarantee slot 275 is non-NULL, falling back to the
 * process-wide signal TEB. Returns 0 when no TEB could be established, and
 * callers must then use dprintf(2,...) rather than a wine macro. */
static int ios_make_wine_logging_safe( void )
{
    extern pthread_key_t ios_teb_tls_key;
    extern int ios_teb_tls_key_created;
    uintptr_t tsd_base;
    void *teb;

    /* ml376 CORRECTION — ml375's version tested the WRONG SLOT and changed
     * nothing (zero [dbg-teb] lines, identical crash). Disassembling
     * __wine_dbg_header settled it instead of another guess:
     *   1f8628: bl _NtCurrentTeb
     *   1f862c: add x25, x0, #0x3000        <- x25 = TEB + 0x3000
     *   1f86ec: ldr w8, [x25, #4]           <- FAULTS
     * and _NtCurrentTeb is `ldr x0,[page+0xcf8]; b <stub>` =
     * pthread_getspecific(ios_teb_tls_key) — the PTHREAD KEY, not TSD slot
     * 275 (slot 275 is only the x18-patcher trampolines' copy; the two are
     * independent, and the [tsd275] dump prints them side by side for exactly
     * this reason). With no value for that key NtCurrentTeb() returns NULL,
     * x25 becomes 0x3000, and the read faults at 0x3004.
     *
     * ml376 log confirms such threads exist: `[mach_exc] UNHANDLED #4 …
     * x18=0x0`.
     *
     * Populate the key (and slot 275) from the best TEB available so every
     * wine log macro in the handler — not just the first — is safe. Returns 0
     * only when no TEB exists at all, in which case callers must dprintf. */
    if (ios_teb_tls_key_created && (teb = pthread_getspecific( ios_teb_tls_key )))
        return 1;

    teb = NULL;
    __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tsd_base));
    tsd_base &= ~7ULL;
    if (tsd_base && ios_teb_tls_slot_offset)
        teb = *(void **)(tsd_base + ios_teb_tls_slot_offset);
    if (!teb) teb = (void *)ios_teb_for_signals;
    if (!teb) return 0;

    /* Republish through the key that owns the slot; never poke a raw slot. */
    if (ios_teb_tls_key_created) pthread_setspecific( ios_teb_tls_key, teb );
    {
        static int borrow_n;
        if (borrow_n < 8)
        {
            borrow_n++;
            dprintf( 2, "[dbg-teb] rev=ml376 NtCurrentTeb() was NULL in a signal handler — "
                        "installed teb=%p (every wine ERR/WARN here would have faulted at 0x3004)\n",
                     teb );
        }
    }
    return 1;
}

/* iOS-Madeira ml481 (#85): is this fault FOREIGN — i.e. raised by a host
 * (Apple/SwiftUI/Metal) thread executing host code on host memory?
 *
 * ml480's freeze: the app's UI thread (port 0x103) was inside
 * swift_allocObject -> libsystem_malloc when a trap fired INSIDE malloc (so
 * the thread already held the malloc zone lock). trap_handler adopted it as a
 * guest exception, ios_log_guest_exception then faulted (no TEB on that
 * thread), segv_handler ran, and ios_make_wine_logging_safe called through a
 * not-yet-bound lazy stub -> dyld -> malloc -> the SAME zone lock. Deadlock:
 * sampled 22x at cpu=1000 with an unchanging sp. The UI froze for the rest of
 * the run while every other thread kept going, which is exactly what the user
 * sees as "a big freeze".
 *
 * Our handlers must only adopt faults that belong to the emulated world. A
 * thread qualifies as ours if it has a TEB (pthread key or TSD slot 275) or is
 * executing from the JIT pool / guest bands; a fault also stays ours when the
 * TARGET address is emulator-managed memory (wine guard pages, pool aliases),
 * since host threads legitimately touch those. Everything else is foreign.
 *
 * pthread_getspecific and the raw TSD read are async-signal-safe; nothing here
 * allocates, so this predicate can run before any logging. */
/***********************************************************************
 *		ios_srcwatch — catch the guest code that writes Chromium's bitmap
 *
 * iOS-Madeira ml514. The render corruption is a per-draw-op DESTINATION
 * error with a CONSTANT offset (~-550,-97): a panel written where it does
 * not belong with its true location left black, the QR halo displaced
 * independently of the QR it surrounds. Everything WE own is exonerated —
 * compositor, flush, GDI transport ([put-image] shows clean 1:1 700x440),
 * and the VGUI dialog renders perfectly through the SAME surface. And
 * every memory-ordering hypothesis is spent (scalar TSO correct, vector /
 * memcpy TSO no effect, all three Chromium concurrency switches inert).
 * What is left is Chromium computing wrong values under FEX — and since
 * upstream FEX runs Chromium correctly on Linux, the defect is in an
 * iOS-specific deviation of ours.
 *
 * To work backwards from pixels to code we need to know WHICH GUEST CODE
 * writes which region. mprotect the source bitmap read-only, then let the
 * faults name the writers: on each fault log the guest RIP (CpuStateFrame
 * at x28+0x18, same as the [guest-state] dump) plus the byte offset it
 * touched, unprotect that ONE page, and continue. The buffer is ~1.5MB =
 * ~96 pages, so a whole frame costs ~96 faults, not one per pixel.
 *
 * The offset is the payload: pages carrying the DISPLACED region will be
 * written by a different RIP (or the same RIP with different inputs) than
 * the pages that land correctly, and that RIP resolves to libcef+RVA via
 * the [jit-pool] image map — which is where FEX's translation of that
 * block can be dumped and audited.
 *
 * Safety: one-shot and env-gated. Arms once, self-disarms after
 * IOS_SRCWATCH_MAX faults or on any failure, and every page is unprotected
 * the first time it faults, so a page can never fault twice and no writer
 * can be starved. If arming fails the feature silently stays off — a
 * diagnostic must never break the path it measures.
 */
/* ml516: the cap counts DISTINCT pages, not faults. In ml516 two writers
 * burned 361 of 480 faults on THREE pages — the per-page unprotect did not
 * stick there (aliased mapping is the likely reason), so coverage starved
 * at ~113 pages instead of a full frame. A seen-bitmap makes each page
 * count once, and a repeat storm now self-limits instead of eating the
 * budget. */
#define IOS_SRCWATCH_MAX   400      /* total attributions */
#define IOS_SRCWATCH_PAGES 512      /* covers 8MB at 16K pages */
#define IOS_SRCWATCH_REPEAT_LIMIT 48
/* ml517: attributions to capture PER PAGE before leaving it open. The
 * ml517 run exposed a design flaw: libcef+0x41258f0 is a SOLID-COLOUR FILL
 * (movl %edx,(%r10) x4 / addq $0x10 / dest += stride) — Chromium clearing
 * the frame. It runs FIRST and touches EVERY page, so a one-shot
 * seen-bitmap attributed all 76 pages to the clear and left the content
 * painters — the writers that would name the displaced band — structurally
 * invisible. Re-protecting a page after each attribution makes its NEXT
 * writer fault too, at a cost of only ~N faults per page. */
#define IOS_SRCWATCH_PER_PAGE 3
#define IOS_SRCWATCH_RIPS 24        /* distinct writers tracked in the census */
#define IOS_SRCWATCH_TILE 254       /* Chromium tile pitch (256 less 1px border each side) */

static struct {
    volatile uintptr_t base;      /* page-aligned watch start, 0 = disarmed */
    volatile uintptr_t end;
    volatile int       pages;     /* distinct pages attributed */
    volatile int       repeats;   /* faults on already-unprotected pages */
    volatile int       armed;
    unsigned char      seen[IOS_SRCWATCH_PAGES];
    /* ml548: image geometry, so a fault offset can be reported as (x,y) and a
     * TILE COLUMN instead of a raw byte offset. Without this the log needs
     * offline arithmetic to mean anything, and the whole question is "which
     * tile column did this writer touch". */
    volatile unsigned   img_w, img_h, img_stride;
    volatile unsigned long row_lo, row_hi;   /* watched row band */
    /* per-writer tile-column census: which columns did each guest RIP write? */
    volatile uint64_t   rip_id[IOS_SRCWATCH_RIPS];
    volatile unsigned   rip_colmask[IOS_SRCWATCH_RIPS];
    volatile unsigned   rip_hits[IOS_SRCWATCH_RIPS];
    volatile int        rip_n;
} ios_srcwatch;

/* ml530: the watch arms ONCE (the ios_srcwatch.armed guard), so two call sites
 * competing for it means whichever runs first silently wins and the other is
 * never armed at all — a probe that reports nothing while looking healthy.
 * There are now two subjects:
 *
 *   "render" — win32u's dibdrv_PutImage, Chromium's SOURCE bitmap (the original
 *              use; hit a hard ceiling, see project_render_corruption_hunt)
 *   "js"     — the assembled steamui JS buffer in NtReadFile (#78: V8 reports
 *              `SyntaxError: Invalid or unexpected token` on source our file
 *              reads deliver 73/73 byte-perfect, so something writes to it
 *              afterwards)
 *
 * MADEIRA_SRCWATCH names which one to arm. "1" keeps the legacy render meaning. */
void ios_srcwatch_arm_for( const void *bits, unsigned long len, const char *tag )
{
    const char *want = getenv( "MADEIRA_SRCWATCH" );
    uintptr_t b, e;

    /* ml531: the floor and the once-only guard were both tuned for the render
     * subject and both silently killed the js subject.
     *
     *  - len < 0x10000 rejected EVERY contiguous JS buffer: the ones Steam reads
     *    in a single shot are 1-25KB (sp.js 2178, 716.js 5217, 9108.js 8426,
     *    2294.js 22495), so the ml530 control run logged seven "arming srcwatch"
     *    lines and produced ZERO [srcwatch] ARMED. A floor that rejects the whole
     *    population is a probe that cannot fire.
     *  - armed-once meant the FIRST small file (sp.js) would have taken the slot
     *    for the run even if the floor had allowed it, and the file that actually
     *    fails is loaded later. Re-arm instead, unprotecting the previous region
     *    first so no page is left write-protected without a handler tracking it —
     *    that would surface as a stray AV in whatever touched it next. */
    unsigned long floor = !strcmp( tag, "js" ) ? 0x400 : 0x10000;

    if (!want || !tag) return;
    if (strcmp( want, tag ) && !(!strcmp( want, "1" ) && !strcmp( tag, "render" ))) return;
    if (!bits || len < floor) return;

    if (ios_srcwatch.armed)
    {
        /* Release the previous subject before taking a new one. */
        uintptr_t ob = ios_srcwatch.base, oe = ios_srcwatch.end;
        ios_srcwatch.armed = 0;
        if (ob && oe > ob) mprotect( (void *)ob, oe - ob, PROT_READ | PROT_WRITE );
    }

    b = (uintptr_t)bits & ~(uintptr_t)0x3FFF;             /* 16K pages on iOS */
    e = ((uintptr_t)bits + len + 0x3FFF) & ~(uintptr_t)0x3FFF;

    if (mprotect( (void *)b, e - b, PROT_READ ) != 0)
    {
        ERR("[srcwatch] arm FAILED subject=%s bits=%p len=%lu errno=%d — staying off rev=ml530\n",
            tag, bits, len, errno);
        return;
    }
    ios_srcwatch.base = b;
    ios_srcwatch.end = e;
    ios_srcwatch.pages = 0;
    ios_srcwatch.repeats = 0;
    memset( (void *)ios_srcwatch.seen, 0, sizeof(ios_srcwatch.seen) );
    ios_srcwatch.armed = 1;
    /* ml549: resolve the exact-RIP export now — arming happens long after the
     * emulator module is mapped, and the resolver is one-shot. */
    { extern void ios_resolve_fex_exports( void ); ios_resolve_fex_exports(); }  /* ml613: retryable, resolves both */
    ERR("[srcwatch] ARMED subject=%s base=%p end=%p (%lu bytes, %lu pages) rev=ml530\n",
        tag, (void *)b, (void *)e, (unsigned long)(e - b), (unsigned long)((e - b) >> 14));
}

/* Legacy entry point: win32u's dibdrv_PutImage. */
void ios_srcwatch_arm( const void *bits, unsigned long len )
{
    ios_srcwatch_arm_for( bits, len, "render" );
}

/* ml548: geometry-aware arm.
 *
 * Two reasons this exists rather than reusing the plain entry point:
 *
 *  1. TARGETING. Arming the whole 1.2MB bitmap spreads a 400-attribution budget
 *     across ~76 pages, so the clear (which touches EVERY page first) dominates
 *     and the content painters — the writers that would name a displaced band —
 *     stay invisible. MADEIRA_SRCWATCH_ROWS=lo,hi restricts the watch to one
 *     horizontal band so the budget lands where displacement was measured.
 *  2. READABILITY. Storing stride lets a fault offset be reported as (x,y) and a
 *     tile column directly, instead of needing offline arithmetic to interpret.
 *
 * The band is chosen from the consensus-median analysis: pick rows where an
 * element is known to land in the wrong tile column. */
void ios_srcwatch_arm_geom( const void *bits, unsigned long len,
                            unsigned w, unsigned h, unsigned stride )
{
    const char *rows = getenv( "MADEIRA_SRCWATCH_ROWS" );
    unsigned long lo = 0, hi = h;
    const void *abits = bits;
    unsigned long alen = len;

    if (rows && stride)
    {
        char *endp = NULL;
        unsigned long a = strtoul( rows, &endp, 0 );
        unsigned long b = (endp && *endp == ',') ? strtoul( endp + 1, NULL, 0 ) : 0;
        if (b > a && b <= h)
        {
            lo = a; hi = b;
            abits = (const char *)bits + (size_t)lo * stride;
            alen  = (size_t)(hi - lo) * stride;
        }
    }
    ios_srcwatch.img_w = w;
    ios_srcwatch.img_h = h;
    ios_srcwatch.img_stride = stride;
    ios_srcwatch.row_lo = lo;
    ios_srcwatch.row_hi = hi;
    ios_srcwatch.rip_n = 0;
    memset( (void *)ios_srcwatch.rip_id, 0, sizeof(ios_srcwatch.rip_id) );
    memset( (void *)ios_srcwatch.rip_colmask, 0, sizeof(ios_srcwatch.rip_colmask) );
    memset( (void *)ios_srcwatch.rip_hits, 0, sizeof(ios_srcwatch.rip_hits) );
    ios_srcwatch_arm_for( abits, alen, "render" );
    if (ios_srcwatch.armed)
        ERR("[srcwatch] GEOM %ux%u stride=%u rows=[%lu,%lu) tile=%d rev=ml548\n",
            w, h, stride, lo, hi, IOS_SRCWATCH_TILE);
}

/* Census dump: which TILE COLUMNS did each writer touch? A painter that should
 * only ever touch one column but shows bits for two is the finding. */
void ios_srcwatch_census( void )
{
    int i;
    if (ios_srcwatch.rip_n <= 0) return;
    for (i = 0; i < ios_srcwatch.rip_n && i < IOS_SRCWATCH_RIPS; i++)
        ERR("[srcwatch-census] writer=%d guest_rip=%p hits=%u tile_cols=0x%x%s rev=ml548\n",
            i, (void *)(uintptr_t)ios_srcwatch.rip_id[i], ios_srcwatch.rip_hits[i],
            ios_srcwatch.rip_colmask[i],
            (ios_srcwatch.rip_colmask[i] & (ios_srcwatch.rip_colmask[i] - 1))
                ? "  <== MULTI-COLUMN" : "");
}

/* Returns 1 if the fault belonged to the watch and was consumed.
 *
 * ml515: called from the MACH exception handler, not segv_handler. ml514
 * hooked the BSD path and caught ZERO faults while turning the window
 * black on 2/2 runs — guest faults in this port are delivered in-Mach, so
 * the protection fault went to the guest as an AV and killed the paint.
 * Takes the Mach thread state directly for the same reason. */
static int ios_srcwatch_handle( const arm_thread_state64_t *st, uintptr_t addr )
{
    uintptr_t page;
    uint64_t x28, rip = 0, exact_rip = 0;
    mach_vm_size_t got = 0;
    int n;

    if (!ios_srcwatch.armed) return 0;
    if (addr < ios_srcwatch.base || addr >= ios_srcwatch.end) return 0;

    page = addr & ~(uintptr_t)0x3FFF;
    {
        unsigned long pidx = (page - ios_srcwatch.base) >> 14;

        /* Already attributed? Then the unprotect did not stick for this page.
         * Log the first few, then kill the whole protection rather than let a
         * repeat storm starve the pages we have not attributed yet. */
        if (pidx < IOS_SRCWATCH_PAGES && ios_srcwatch.seen[pidx] >= IOS_SRCWATCH_PER_PAGE)
        {
            /* Budget for this page spent — leave it open so it stops costing
             * faults, and count it only as a repeat for storm detection. */
            int r = ++ios_srcwatch.repeats;
            if (r >= IOS_SRCWATCH_REPEAT_LIMIT)
            {
                dprintf(STDERR_FILENO, "[srcwatch] repeat storm (%d) — unprotecting ALL and "
                        "disarming; %d attributions rev=ml517\n", r, ios_srcwatch.pages);
                { extern void ios_srcwatch_census( void ); ios_srcwatch_census(); }
                mprotect( (void *)ios_srcwatch.base, ios_srcwatch.end - ios_srcwatch.base,
                          PROT_READ | PROT_WRITE );
                ios_srcwatch.armed = 0;
            }
            else
                mprotect( (void *)page, 0x4000, PROT_READ | PROT_WRITE );
            return 1;
        }
        if (pidx < IOS_SRCWATCH_PAGES) ios_srcwatch.seen[pidx]++;
    }

    /* Guest RIP lives at CpuStateFrame+0x18 off x28 — same source the
     * [guest-state] dump uses. Read it defensively: a NULL or unreadable
     * x28 means a HOST thread wrote this page, which is itself a finding. */
    x28 = st->__x[28];
    if (x28) mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(x28 + 0x18),
                                     sizeof(rip), (mach_vm_address_t)&rip, &got );

    /* ml549: the RIP above is BLOCK-GRANULAR — FEX only syncs CpuStateFrame+0x18 at
     * block boundaries, so it names the calling block, not the instruction that
     * executed. ml548 disassembled one and got `movq %rbp,%rcx; callq` (call setup)
     * instead of a store, which is why the writer could never be identified.
     *
     * FEX keeps a host-PC -> guest-RIP table in every block tail and walks it for
     * exception reconstruction. ios_fex_rip_from_hostpc() is that same walk exported
     * as C. The block header pointer is CPUState offset 0 == x28+0, and the host PC
     * is right here in the fault state. Log BOTH so the difference is visible: if
     * exact == block on every fault, the lookup is not working and nothing below it
     * can be trusted. */
    {
        /* The lookup lives in xtajit64.dll (an ARM64EC PE), not in this Mach-O, so a
         * weak extern would silently resolve to NULL. Use the pointer xtajit64 pushes
         * down at init on the same unix-call that carries the JIT alias callback. */
        extern unsigned long long (*ios_fex_rip_from_hostpc_cb)( unsigned long long, unsigned long long );
        uint64_t blockhdr = 0;
        mach_vm_size_t bgot = 0;
        if (x28)
            mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)x28,
                                    sizeof(blockhdr), (mach_vm_address_t)&blockhdr, &bgot );
        /* ml551: gate on the RESOLVED FLAG, never on the pointer. Calling this
         * pointer while it held ASCII was what blacked out the window. */
        extern volatile int ios_fex_rip_resolved;
        if (ios_fex_rip_resolved && ios_fex_rip_from_hostpc_cb
            && bgot == sizeof(blockhdr) && blockhdr)
            exact_rip = ios_fex_rip_from_hostpc_cb(
                blockhdr, (uint64_t)__darwin_arm_thread_state64_get_pc(*st) );
    }

    n = ++ios_srcwatch.pages;
    {
        /* ml548: report the destination in IMAGE terms and record which tile
         * column this writer touched. A raw byte offset needs offline arithmetic
         * to interpret, and "which tile column" is the entire question. */
        unsigned long off = (unsigned long)(addr - ios_srcwatch.base);
        unsigned stride = ios_srcwatch.img_stride;
        unsigned long yy = 0, xx = 0; int col = -1;
        if (stride)
        {
            yy = ios_srcwatch.row_lo + off / stride;
            xx = (off % stride) / 4;
            col = (int)(xx / IOS_SRCWATCH_TILE);
        }
        dprintf(STDERR_FILENO,
            "[srcwatch] #%d off=+0x%lx -> x=%lu y=%lu tile_col=%d EXACT_rip=%p block_rip=%p host_pc=%p x28=%p%s rev=ml549\n",
            n, off, xx, yy, col,
            (void *)(uintptr_t)exact_rip,
            (void *)(uintptr_t)rip,
            (void *)(uintptr_t)__darwin_arm_thread_state64_get_pc(*st),
            (void *)(uintptr_t)x28,
            (got == sizeof(rip)) ? "" : "  (rip UNREADABLE => host writer)");

        if (col >= 0 && col < 32)
        {
            int i, slot = -1;
            for (i = 0; i < ios_srcwatch.rip_n && i < IOS_SRCWATCH_RIPS; i++)
                if (ios_srcwatch.rip_id[i] == rip) { slot = i; break; }
            if (slot < 0 && ios_srcwatch.rip_n < IOS_SRCWATCH_RIPS)
            {
                slot = ios_srcwatch.rip_n++;
                ios_srcwatch.rip_id[slot] = rip;
            }
            if (slot >= 0)
            {
                ios_srcwatch.rip_colmask[slot] |= (1u << col);
                ios_srcwatch.rip_hits[slot]++;
            }
        }
    }

    /* ml534: DUMP THE WHOLE REGISTER FILE — do not guess the mapping.
     *
     * ml533 assumed the Windows ARM64EC ABI (RAX=x8, RDX=x1, RSP=x23) and the
     * data immediately refuted it: "RAX" read 0x1b8,0x1b3,0x1ad,0x1a7 — i.e.
     * 440,435,429,423, a ROW COUNTER counting down from the buffer height (440),
     * and "[RSP]" yielded another stack address 0x2b8 away rather than a return
     * address. FEX uses its own `x64::SRA` span, not the EC ABI table.
     *
     * So stop guessing. Dump x0..x30 for the first few faults and identify the
     * registers OFFLINE by what they contain — the destination register must equal
     * the faulting address, a caller/return value lands in libcef's code range
     * (device base 0x71e1910000 + .text), and a stack pointer sits in the guest
     * stack band. That is self-calibrating: it cannot be wrong about the mapping
     * because it assumes none.
     *
     * Bounded to the first 8 faults — 2052 fired in ml533, and 31 registers each
     * would bury the log. */
    {
        /* ml535: budget the dumps PER DISTINCT WRITER, not globally.
         *
         * ml534 used one global budget of 8 and the CLEAR consumed every slot —
         * it runs first and marches page by page (faults at ...f0000, ...f4000,
         * ...f8000 with x0 advancing in step), exactly the starvation that capped
         * ml517. Meanwhile the writer we actually want is the CONTENT PAINTER:
         * this run it was the TOP writer at 1293 faults (guest_rip +0x582c89)
         * versus 1086 for the clear (+0x41258f0), and it got zero register dumps.
         *
         * A per-rip budget guarantees every distinct writer is sampled regardless
         * of who runs first or faults most. Same lesson as the ml516 cap that
         * counted EVENTS instead of DISTINCT SUBJECTS. */
        enum { SW_RIPS = 8, SW_PER_RIP = 2 };
        static volatile uint64_t seen_rip[SW_RIPS];
        static volatile int      seen_cnt[SW_RIPS];
        int slot = -1, i2, d = 0;

        for (i2 = 0; i2 < SW_RIPS; i2++)
        {
            if (seen_rip[i2] == rip) { slot = i2; break; }
            if (seen_rip[i2] == 0)   { seen_rip[i2] = rip; slot = i2; break; }
        }
        if (slot >= 0 && seen_cnt[slot] < SW_PER_RIP) d = ++seen_cnt[slot];

        if (d)
        {
            char buf[560];
            int off = 0, i;
            for (i = 0; i <= 30 && off < (int)sizeof(buf) - 24; i++)
                off += snprintf( buf + off, sizeof(buf) - off, "%s%d=%llx",
                                 i ? " x" : "x", i, (unsigned long long)st->__x[i] );
            dprintf(STDERR_FILENO,
                "[srcwatch]   #%d REGS writer=%d/%d guest_rip=%p fault=%p sp=%p lr=%p | %s rev=ml535\n",
                n, slot, d, (void *)(uintptr_t)rip, (void *)addr,
                (void *)(uintptr_t)__darwin_arm_thread_state64_get_sp(*st),
                (void *)(uintptr_t)__darwin_arm_thread_state64_get_lr(*st), buf);
        }
    }

    /* ml517: unprotect just long enough for THIS write to land, then the
     * page is re-armed on the next fault path below if its per-page budget
     * remains — that is what exposes the content painters behind the clear. */
    if (mprotect( (void *)page, 0x4000, PROT_READ | PROT_WRITE ) != 0)
    {
        dprintf(STDERR_FILENO, "[srcwatch] unprotect FAILED at %p errno=%d — DISARMING rev=ml515\n",
            (void *)page, errno);
        mprotect( (void *)ios_srcwatch.base, ios_srcwatch.end - ios_srcwatch.base,
                  PROT_READ | PROT_WRITE );
        ios_srcwatch.armed = 0;
        return 1;
    }

    {
        unsigned long pidx2 = (page - ios_srcwatch.base) >> 14;
        if (ios_srcwatch.armed && pidx2 < IOS_SRCWATCH_PAGES
            && ios_srcwatch.seen[pidx2] < IOS_SRCWATCH_PER_PAGE)
            mprotect( (void *)page, 0x4000, PROT_READ );   /* catch the next writer */
    }

    if (n >= IOS_SRCWATCH_MAX)
    {
        dprintf(STDERR_FILENO, "[srcwatch] cap %d DISTINCT pages reached — disarming "
                "(%d repeats) rev=ml516\n", IOS_SRCWATCH_MAX, ios_srcwatch.repeats);
        mprotect( (void *)ios_srcwatch.base, ios_srcwatch.end - ios_srcwatch.base,
                  PROT_READ | PROT_WRITE );
        ios_srcwatch.armed = 0;
    }
    return 1;
}

static int ios_fault_is_foreign( const void *pc, const void *addr )
{
    extern pthread_key_t ios_teb_tls_key;
    extern int ios_teb_tls_key_created;
    extern void *ios_jit_rx_base_global;
    extern void *ios_jit_rw_base_global;
    extern size_t ios_jit_pool_size_global;
    uintptr_t p = (uintptr_t)pc, a = (uintptr_t)addr, tsd_base = 0;
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
    size_t sz = ios_jit_pool_size_global;

    /* a registered wine/guest thread is always ours */
    if (ios_teb_tls_key_created && pthread_getspecific( ios_teb_tls_key )) return 0;
    __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tsd_base));
    tsd_base &= ~7ULL;
    if (tsd_base && ios_teb_tls_slot_offset &&
        *(void **)(tsd_base + ios_teb_tls_slot_offset)) return 0;

    /* TEB-less but running emulated code (threads CEF/FEX create directly) */
    if (sz && rx && p >= rx && p < rx + sz) return 0;
    if (sz && rw && p >= rw && p < rw + sz) return 0;
    if (ios_jit_low_contains( p ) || ios_jit_low_rw_contains( p )) return 0;   /* madeira-bcd pool-low */
    if (p >= 0x7000000000ull && p < 0x8000000000ull) return 0;  /* guest | PA | FEX bands */

    /* host code, but touching emulator-managed memory (guard page, pool alias,
     * guest buffer handed to Metal): the repair paths below are still correct */
    if (a)
    {
        if (sz && rx && a >= rx && a < rx + sz) return 0;
        if (sz && rw && a >= rw && a < rw + sz) return 0;
        if (ios_jit_low_contains( a ) || ios_jit_low_rw_contains( a )) return 0;   /* madeira-bcd pool-low */
        if (a >= 0x7000000000ull && a < 0x8000000000ull) return 0;
    }
    return 1;
}

/* Decline a foreign fault: report it with write(2)-only logging (the
 * interrupted thread may hold the malloc lock, so NOTHING here may allocate or
 * hit an unbound lazy stub), then restore the default disposition so the OS
 * reports honestly instead of us spinning forever inside our own handler. */
static void ios_decline_foreign_fault( int sig, const void *pc, const void *addr )
{
    static int declined_n;
    if (declined_n < 8)
    {
        declined_n++;
        dprintf( 2, "[host-fault] sig=%d pc=%p addr=%p on a NON-guest thread — declining to adopt "
                    "(would have deadlocked in our own handler) rev=ml481\n", sig, pc, addr );
    }
    signal( sig, SIG_DFL );
}
#endif

/* ---------------------------------------------------------------------------
 * ml845 [tlswatch]: catch the writer of the UE5 exe's thread-local at
 * static TLS block 0 +0x38 IN THE ACT.
 *
 * Established so far: the value is the thread's own FEX emulator stack top,
 * it appears during dispatch of the engine's thread-naming exception
 * (RaiseException 0x406D1388), and NOTHING in the executable writes that slot
 * -- every static form has been exhausted. So the writer is either a guest DLL
 * or our own dispatch code, and only a runtime trap can name it.
 *
 * Arm: in NtRaiseException for that code, make the block's host page(s)
 * read-only. Re-arm: from NtContinue on the same thread while the target word
 * is still untouched (dispatch continues through several NtContinue calls, so
 * an off-target write that steals the watch costs one interval, not the run).
 * Catch: in bus_handler, before the [wr-strip] heal that would otherwise
 * silently restore access, log the faulting PC (dladdr for native, raw for JIT
 * pool), the target offset, restore access and resume in place. Capped. */
#include <dlfcn.h>
static uintptr_t ios_tlswatch_block, ios_tlswatch_page, ios_tlswatch_len;
static DWORD ios_tlswatch_tid;
static int ios_tlswatch_armed, ios_tlswatch_hit, ios_tlswatch_faults;

void ios_tlswatch_arm_block( void *blockp, const char *why )
{
    TEB *teb = NtCurrentTeb();
    uintptr_t block, target;

    /* ml881: OPT-IN. The ml845 diagnosis is closed (ml848 fixed the TLS-slot
     * aliasing), but this stayed armed on every new thread, write-protecting
     * its 16 KB TLS page. A UE 5.4 worker's plain TLS-slot store compiles to
     * a store-release (stlr), which the bus-handler emulator refuses, and the
     * refusal became a DATATYPE_MISALIGNMENT exception delivered to the game
     * -- which then crashed inside its own crash reporter. */
    { static int enabled = -1; if (enabled < 0) enabled = getenv("MADEIRA_TLSWATCH") != NULL; if (!enabled) return; }
    if (ios_tlswatch_hit || ios_tlswatch_armed || !teb || !blockp) return;
    block = (uintptr_t)blockp;
    if (*(uint64_t *)(block + 0x38)) return;   /* nothing left to catch on this thread */
    target = block + 0x38;
    ios_tlswatch_page = target & ~(uintptr_t)0x3fff;
    ios_tlswatch_len = ((target + 0x20) > ios_tlswatch_page + 0x4000) ? 0x8000 : 0x4000;
    if (mprotect( (void *)ios_tlswatch_page, ios_tlswatch_len, PROT_READ ))
    {
        dprintf( 2, "[tlswatch] ml845 arm(%s) FAILED errno=%d page=%p\n", why, errno, (void *)ios_tlswatch_page );
        return;
    }
    ios_tlswatch_block = block;
    ios_tlswatch_tid = (DWORD)(ULONG_PTR)teb->ClientId.UniqueThread;
    ios_tlswatch_armed = 1;
    dprintf( 2, "[tlswatch] ml845 ARMED (%s) tid=%04x block=%p target=%p page=%p len=0x%zx value-now=0x%llx\n",
             why, (unsigned)ios_tlswatch_tid, (void *)block, (void *)target, (void *)ios_tlswatch_page,
             (size_t)ios_tlswatch_len, (unsigned long long)*(uint64_t *)target );
}

void ios_tlswatch_arm( const char *why )
{
    void **blocks = NtCurrentTeb() ? NtCurrentTeb()->ThreadLocalStoragePointer : NULL;
    if (blocks && blocks[0]) ios_tlswatch_arm_block( blocks[0], why );
}

void ios_tlswatch_rearm( const char *why )
{
    TEB *teb = NtCurrentTeb();
    if (ios_tlswatch_armed || ios_tlswatch_hit || !ios_tlswatch_block || !teb) return;
    if ((DWORD)(ULONG_PTR)teb->ClientId.UniqueThread != ios_tlswatch_tid) return;
    if (ios_tlswatch_faults >= 24) return;
    if (*(uint64_t *)(ios_tlswatch_block + 0x38))
    {
        /* Already written between faults: name that fact instead of watching a
         * slot that has nothing left to tell us. */
        dprintf( 2, "[tlswatch] ml845 target already set at rearm(%s): 0x%llx -- the write fell between "
                    "a heal and this rearm, or came from a thread the watch does not follow\n",
                 why, (unsigned long long)*(uint64_t *)(ios_tlswatch_block + 0x38) );
        ios_tlswatch_hit = 1;
        return;
    }
    if (!mprotect( (void *)ios_tlswatch_page, ios_tlswatch_len, PROT_READ )) ios_tlswatch_armed = 1;
}

/* Returns 1 when the fault was the watch and has been healed (caller resumes). */
static int ios_tlswatch_fault( const void *addr, const void *pc, const char *which )
{
    uintptr_t a = (uintptr_t)addr;
    Dl_info di;
    int in_target;
    long off;

    if (!ios_tlswatch_armed) return 0;
    if (a < ios_tlswatch_page || a >= ios_tlswatch_page + ios_tlswatch_len) return 0;
    ios_tlswatch_faults++;
    off = (long)(a - ios_tlswatch_block);
    in_target = (off >= 0x38 && off < 0x50);
    memset( &di, 0, sizeof di );
    dladdr( pc, &di );
    dprintf( 2, "[tlswatch] ml845 WRITE #%d via %s: addr=%p = block%+ld %s | pc=%p %s`%s+0x%llx tid=%04x\n",
             ios_tlswatch_faults, which, addr, off, in_target ? "<== TARGET WORD" : "(other data on the page)",
             pc, di.dli_fname ? strrchr( di.dli_fname, '/' ) ? strrchr( di.dli_fname, '/' ) + 1 : di.dli_fname : "(no image: JIT pool or guest)",
             di.dli_sname ? di.dli_sname : "?",
             di.dli_saddr ? (unsigned long long)((uintptr_t)pc - (uintptr_t)di.dli_saddr) : 0ull,
             (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
    mprotect( (void *)ios_tlswatch_page, ios_tlswatch_len, PROT_READ | PROT_WRITE );
    ios_tlswatch_armed = 0;
    if (in_target) ios_tlswatch_hit = 1;
    return 1;
}

#ifdef WINE_IOS
/* ml938: defined below next to the store emulator it reuses. */
static int ios_subfloor_service( ucontext_t *ctx, void *fault_addr, const char *via, void *peb );
#endif

static void segv_handler( int signal, siginfo_t *siginfo, void *sigcontext )
{
    EXCEPTION_RECORD rec = { 0 };
    ucontext_t *context = sigcontext;
    DWORD64 esr = get_fault_esr( context );
#ifdef WINE_IOS
    int dbg_ok;

    /* ml481 (#85): decide FOREIGN-ness before anything that could allocate —
     * ios_make_wine_logging_safe() itself is the call that deadlocked in ml480. */
    if (ios_fault_is_foreign( (void *)PC_sig( context ), siginfo->si_addr ))
    {
        ios_decline_foreign_fault( signal, (void *)PC_sig( context ), siginfo->si_addr );
        return;
    }
    dbg_ok = ios_make_wine_logging_safe();
#endif

#ifdef WINE_IOS
    ios_track_signal( signal, context );
    {
        static int segv_dump_count = 0;
        static int total_segv_count = 0;
        total_segv_count++;
        ios_total_segv_count = total_segv_count;
        void *pc = (void*)PC_sig(context);

        /* Read the NATIVE x18 (iOS platform register value in handler context) */
        uint64_t native_x18;
        __asm__ volatile("mov %0, x18" : "=r"(native_x18));

        /* Log first few SEGVs with both native and ucontext x18.
         * ml375: dprintf when no TEB could be established — a wine macro here
         * faults inside __wine_dbg_header and loops the handler forever. */
        if (total_segv_count <= 5 && !dbg_ok)
            dprintf( 2, "SEGV #%d: pc=%p addr=%p (no TEB — wine logging unsafe)\n",
                     total_segv_count, pc, siginfo->si_addr );
        else if (total_segv_count <= 5)
            ERR("SEGV #%d: pc=%p addr=%p uctx_x18=%p disp=%llu mach_exc=%d\n",
                total_segv_count, pc, siginfo->si_addr,
                (void*)REGn_sig(18, context),
                (unsigned long long)g_wine_dispatcher_count,
                ios_exc_msg_count);

        /* Execution fault at PE address → redirect to JIT pool */
        if (pc == siginfo->si_addr)
        {
            extern void *ios_jit_translate_addr(void *addr);
            void *jit_pc = ios_jit_translate_addr(pc);
            if (jit_pc != pc)
            {
                /* Use trampoline to set x18 (sigreturn zeroes it on iOS) */
                if (ios_my_trampoline && ios_teb_for_signals)
                {
                    REGn_sig(17, context) = (uintptr_t)jit_pc;
                    PC_sig(context) = (uintptr_t)ios_my_trampoline;
                }
                else
                {
                    PC_sig(context) = (uintptr_t)jit_pc;
                }
                return;
            }
        }

        /* Redirect user_shared_data accesses (0x7FFE0000) to our real allocation.
         * iOS __PAGEZERO prevents mapping at the standard Windows address.
         * Find the register holding 0x7FFE* and replace with real address. */
        {
            uintptr_t fault_addr = (uintptr_t)siginfo->si_addr;
            if (fault_addr >= 0x7FFE0000 && fault_addr < 0x7FFF0000)
            {
                extern struct _KUSER_SHARED_DATA *user_shared_data;
                uintptr_t real_usd = (uintptr_t)user_shared_data;
                if (real_usd && real_usd != 0x7FFE0000)
                {
                    int fixed = 0;
                    for (int reg = 0; reg <= 28; reg++)
                    {
                        uint64_t rval = REGn_sig(reg, context);
                        if (rval >= 0x7FFE0000 && rval < 0x7FFF0000)
                        {
                            REGn_sig(reg, context) = real_usd + (rval - 0x7FFE0000);
                            fixed = 1;
                        }
                    }
                    if (fixed)
                    {
                        static int usd_fix_count = 0;
                        if (usd_fix_count < 10)
                            ERR("USD redirect: addr=%p → real_usd=%p (fix #%d)\n",
                                (void*)fault_addr, (void*)real_usd, usd_fix_count);
                        usd_fix_count++;

                        /* Also fix x18 if zeroed, and route through trampoline */
                        extern void *ios_jit_rw_base_global;
                        if (REGn_sig(18, context) == 0 && ios_teb_for_signals && ios_my_trampoline)
                        {
                            if (ios_jit_rw_base_global && ios_my_slot >= 0)
                                *(uint64_t *)((char *)ios_jit_rw_base_global + ios_my_slot * 16) = ios_teb_for_signals;
                            REGn_sig(17, context) = PC_sig(context);
                            PC_sig(context) = (uintptr_t)ios_my_trampoline;
                        }
                        return;
                    }
                }
            }
        }

        /* If x18 is 0 and we have TEB backup, restore it directly.
         * iOS kernel zeroes x18 (platform register) on signal delivery.
         * The binary patcher is the real fix (rewrites x18 refs to use
         * a safe TEB load sequence). This is just a simple fallback.
         *
         * BUT: if the faulting PC is itself in low/unmapped memory (i.e. we
         * jumped to an unrelocated RVA), restoring x18 doesn't help — the
         * next SEGV will fire at the same PC. Fall through to the diagnostic
         * dump so the real cause is visible.
         *
         * AND (2026-07-06): only retry when the faulting instruction's base
         * register IS x18 (Rn==18, the same discriminator the Mach handler's
         * [x18,#imm] emulation uses). A fault with any other base register is
         * NOT x18-caused — retrying it swallows genuine guest access
         * violations in an infinite loop (Thumper desktop: `ldrh w7,[x7,...]`
         * on guest pointer 0x3f800018 = float 1.0 bits spun 6.8M times here
         * instead of being delivered to the game as an AV). */
        /* ml158 PROBE (#36): the webhelper dies on a fault this discriminator
         * declines. ml157 showed FEX emitted `movz w1,#0; ldr x1,[x1]` — the
         * page-0 address was materialised into a SCRATCH register, so Rn!=18
         * and we fall through to a fatal SEGV (5 repeats -> thread exit ->
         * steam exit(1)).
         *
         * ml158 note: the first cut of this probe went into the MACH handler,
         * but these faults arrive via segv_handler (this function), so it
         * never fired. Same probe, correct handler.
         *
         * Open question this answers: is address 0 here a TEB offset FEX
         * spilled to a scratch reg, or a genuine guest NULL deref? Emulating
         * the wrong one silently corrupts, so DO NOT widen the discriminator
         * until this says which. An x18 spill (`mov xN,x18`) in the preceding
         * instructions => TEB access; a guest-address computation => real NULL
         * deref (cf. the Thumper 0x3f800018 case that motivated Rn==18). */
        /* ml165 (#36): RECOVER A NULL FEX STATE REGISTER (x28).
         *
         * Report #1 caught `ldr w2,[x28,#0x5d0]` faulting with x28 == 0, inside a
         * function whose prologue is `... mov x28, x0` — so FEX was ENTERED with a NULL
         * CpuStateFrame in arg0 and propagated it into STATE. Surrounding registers place
         * it mid-PartitionAlloc-reservation (x27 == 0x400010000, exactly our jumbo pool
         * size; x21/x22 look like PA hints).
         *
         * The authoritative frame pointer is available and provably correct: the CPU area
         * at TEB+0x1788 holds it at +0x30 (FEX sets CPUArea->SuspendDoorbell from the same
         * frame at Module.cpp:1443), and in the SAME process/TEB of ml165 reports #3/#4
         * carried x28 == 0x7310001140 == CPUArea+0x30. So restoring x28 from CPUArea+0x30
         * and retrying restores exactly the value FEX itself would have used.
         *
         * This mirrors the accepted x18-restore-from-TSD-275 approach. Gated hard, because
         * x28 is an ordinary callee-saved register in non-FEX code and ALL our modules run
         * from the JIT pool:
         *   - x28 must be EXACTLY 0 (not merely small),
         *   - the faulting instruction's base register must BE x28,
         *   - the fault offset must be a plausible CpuStateFrame field (< 64KB),
         *   - CPUArea+0x30 must read back non-NULL, and the target field must be readable.
         * Reads go through mach_vm_read_overwrite so a bad CPU area cannot recurse the
         * handler. pc is NOT advanced: we fix the register and re-execute.
         *
         * If this restores the wrong thing we will see it immediately — the fault was
         * fatal anyway, so recovery is strictly better than dying, and every restore is
         * logged. */
        if (REGn_sig(28, context) == 0 && (uintptr_t)pc >= 0x100000000ULL
            && ios_teb_for_signals != 0)
        {
            uintptr_t fa = (uintptr_t)siginfo->si_addr;
            uint32_t insn = *(uint32_t *)pc;

            if (((insn >> 5) & 31) == 28 && fa < 0x10000)
            {
                uint64_t cpu_area = 0, frame = 0, probe = 0;
                mach_vm_size_t got = 0;

                if (mach_vm_read_overwrite( mach_task_self(),
                        (mach_vm_address_t)(ios_teb_for_signals + 0x1788), 8,
                        (mach_vm_address_t)&cpu_area, &got ) == KERN_SUCCESS && got == 8
                    && cpu_area
                    && mach_vm_read_overwrite( mach_task_self(),
                        (mach_vm_address_t)(cpu_area + 0x30), 8,
                        (mach_vm_address_t)&frame, &got ) == KERN_SUCCESS && got == 8
                    && frame
                    && mach_vm_read_overwrite( mach_task_self(),
                        (mach_vm_address_t)(frame + fa), 8,
                        (mach_vm_address_t)&probe, &got ) == KERN_SUCCESS && got == 8
                    /* ml174: the frame must also be INITIALISED, not merely readable.
                     * Restoring a readable-but-uninitialised frame is worse than not
                     * restoring at all: in ml174 x28 was set to 0x7c80001140 and the very
                     * next instruction did `ldr x2,[x28,#0x40]` -> garbage -> `str x0,[x2]`
                     * faulted at 0x80001131, and the bogus exception frame turned a
                     * contained thread-kill into "frame not in stack limits" and killed
                     * the whole process. FEX keeps a pointer at frame+0x40 (the sequence
                     * ldr/sub #0x10/str/store-through is a stack-style push), so require
                     * it to look like a real userspace pointer before trusting the frame. */
                    && probe_ptr_ok( frame ))
                {
                    static int ios_state_restores;

                    if (ios_state_restores < 12)
                    {
                        ios_state_restores++;
                        ERR( "[state-restore] #%d pc=%p insn=%08x off=0x%lx x28=0 -> %p "
                             "(CPUArea=%p) retrying\n", ios_state_restores, pc, insn,
                             (unsigned long)fa, (void *)(uintptr_t)frame,
                             (void *)(uintptr_t)cpu_area );
                    }
                    REGn_sig(28, context) = frame;
                    return;
                }
            }
        }

        {
            uintptr_t f_addr = (uintptr_t)siginfo->si_addr;
            uint32_t f_insn = ((uintptr_t)pc >= 0x100000000ULL) ? *(uint32_t *)pc : 0;
            int f_rn = (f_insn >> 5) & 31;
            static int ios_x18_decline_reports;

            if (REGn_sig(18, context) == 0 && ios_teb_for_signals != 0
                && (uintptr_t)pc >= 0x100000000ULL && f_addr < 0x10000
                && f_rn != 18 && ios_x18_decline_reports < 4)
            {
                const uint32_t *w = (const uint32_t *)pc;
                char buf[512];
                int n = 0, k;
                ios_x18_decline_reports++;
                for (k = -16; k <= 4 && n < (int)sizeof(buf) - 16; k++)
                    n += snprintf( buf + n, sizeof(buf) - n, "%s%08x",
                                   (k == -16) ? " [" : " ", w[k] );
                snprintf( buf + n, sizeof(buf) - n, "]" );
                ERR("[x18-decline] #%d pc=%p fault_addr=0x%lx insn=%08x rn=%d "
                    "xRn=%p (rn_val==fault_addr? %d) x18=0 teb=%p\n",
                    ios_x18_decline_reports, pc, (unsigned long)f_addr, f_insn, f_rn,
                    (void *)REGn_sig(f_rn, context),
                    (uintptr_t)REGn_sig(f_rn, context) == f_addr,
                    (void *)ios_teb_for_signals);
                ERR("[x18-decline] #%d insns pc-64..pc+16:%s\n",
                    ios_x18_decline_reports, buf);

                /* ml164 follow-up: 21 instruction words were not enough to NAME the
                 * emitted stub, and source archaeology has not pinned it either. Scan a
                 * wide window for STRUCTURAL markers whose encodings are unambiguous, so
                 * the stub identifies itself:
                 *
                 *   brk #0xCAFE = 0xd4395fc0  -> Arm64JITCore::EmitSuspendInterruptCheck
                 *                                (SuspendMagic; ARCHITECTURE_arm64ec only)
                 *   brk #0x0    = 0xd4200000  -> generic trap
                 *   mrs xN, TPIDRRO_EL0 (0xd53bd060 mask) -> IOS_LOAD_TEB / x18 patcher
                 *                                trampoline, i.e. a TEB-load site
                 *   msr TPIDR_EL0 (0xd51bd040 mask) -> MUST NEVER appear (corrupts Apple
                 *                                malloc); flag loudly if it does.
                 *
                 * Read through mach_vm_read_overwrite, never a raw deref: pc may sit near
                 * the start of its mapping and a fault inside this handler would recurse. */
                {
                    static uint32_t win[320];   /* pc-1024 .. pc+256 */
                    mach_vm_size_t got = 0;
                    uintptr_t base = (uintptr_t)pc - 1024;

                    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)base,
                                                sizeof(win), (mach_vm_address_t)win,
                                                &got ) == KERN_SUCCESS && got >= 4)
                    {
                        unsigned words = (unsigned)(got / 4), j;
                        int cafe = -1, brk0 = -1, tpidrro = -1, tpidrw = -1;

                        for (j = 0; j < words; j++)
                        {
                            uint32_t v = win[j];
                            int off = (int)(j * 4) - 1024;
                            if (v == 0xd4395fc0 && cafe < 0) cafe = off;
                            else if (v == 0xd4200000 && brk0 < 0) brk0 = off;
                            if ((v & 0xffffffe0) == 0xd53bd060 && tpidrro < 0) tpidrro = off;
                            if ((v & 0xffffffe0) == 0xd51bd040 && tpidrw < 0) tpidrw = off;
                        }
                        ERR("[x18-decline] #%d markers(words=%u): brk#CAFE@%d brk#0@%d "
                            "mrs_TPIDRRO@%d msr_TPIDR_EL0@%d%s\n",
                            ios_x18_decline_reports, words, cafe, brk0, tpidrro, tpidrw,
                            tpidrw >= 0 ? "  <-- ILLEGAL TPIDR_EL0 WRITE IN THIS BLOCK" : "");

                        /* ml179: the fault is ALWAYS at offset 0x650 of a 16KB-aligned
                         * block, and FEX's whole generated dispatcher is exactly
                         * MAX_DISPATCHER_CODE_SIZE = FEX_PAGE_SIZE*4 = 16KB
                         * (Dispatcher.cpp:48). So this pc is a FIXED location in the
                         * dispatcher, and 21 instruction words were never going to name
                         * it. Dump a wide raw window instead so it can be disassembled
                         * offline against Dispatcher.cpp's emission order — that is what
                         * finally identifies the stub, with no FEX rebuild.
                         * Emitted as 8 lines of 16 words to stay readable. */
                        /* ml180: gate on the PAGE-0 fault, not on report #1. The
                         * first qualifying fault in a run is often the NULL-CS one
                         * (RtlLeaveCriticalSection, addr=0x8), which consumed the single
                         * dump last run and told us nothing about the FEX site. Also drop
                         * the "dispatcher is 16KB" wording: 16KB-alignment of the pc is
                         * arithmetic, not evidence that the block IS FEX's dispatcher. */
                        /* ml191 CALLRET PROBE. The two guest RIPs that reach this
                         * trampoline are libcef+0x1900733 and +0x3b508f0. Decoding libcef
                         * forward from 0x1900733-16 gives a clean x86 stream
                         * (mov/mov/test/je/mov/call) in which the `call` STARTS ONE BYTE
                         * BEFORE that RIP — i.e. the guest arrived MID-INSTRUCTION. FEX
                         * then decodes garbage and raises NoExecOp (PARTIAL_DECODE_INST
                         * routes to the same handler as NOEXEC_INST), which is why this
                         * looked like a permissions bug when it is really a bad control
                         * flow target.
                         *
                         * So log where the target came from: FEX's call-return prediction
                         * stack. The ml174 dump showed the push sequence
                         *   ldr x2,[x28,#0x40]; sub x2,#0x10; str x2,[x28,#0x40]; str x0,[x2]
                         * ml193: the first cut guessed frame+0x40/+0x48 from that push and
                         * was WRONG — the probe self-reported it (in_range=0, and the
                         * "entries" decoded as ASCII text), which is exactly why it was
                         * built to validate. Offsets now COMPUTED from CPUState in
                         * CoreState.h rather than inferred:
                         *   +0x00 InlineJITBlockHeader, +0x08 DeferredSignalRefCount,
                         *   +0x10 pf_raw, +0x14 af_raw, +0x18 rip,
                         *   +0x20 gregs[16] (128B, ..0x9F), +0xA0 L1Pointer, +0xA8 L1Mask,
                         *   +0xB0 callret_sp, +0xB8 callret_sp_base
                         * CPUState is the first member of CpuStateFrame, so these are
                         * frame-relative. (+0x18 rip also matches the known state[0x18]
                         * native-PC note.) */
                        if (f_addr == 0 && REGn_sig(28, context) >= 0x100000000ULL)
                        {
                            uint64_t frame = REGn_sig(28, context);
                            uint64_t sp = 0, base = 0, ent[8] = {0};
                            mach_vm_size_t g = 0;
                            int ok_sp, ok_base, ok_ent = 0;

                            ok_sp = (mach_vm_read_overwrite( mach_task_self(),
                                        (mach_vm_address_t)(frame + 0xB0), 8,
                                        (mach_vm_address_t)&sp, &g ) == KERN_SUCCESS && g == 8);
                            ok_base = (mach_vm_read_overwrite( mach_task_self(),
                                        (mach_vm_address_t)(frame + 0xB8), 8,
                                        (mach_vm_address_t)&base, &g ) == KERN_SUCCESS && g == 8);
                            if (ok_sp && sp >= 0x10000)
                                ok_ent = (mach_vm_read_overwrite( mach_task_self(),
                                            (mach_vm_address_t)sp, sizeof(ent),
                                            (mach_vm_address_t)ent, &g ) == KERN_SUCCESS);
                            {
                                uint64_t grip = 0; mach_vm_size_t g2 = 0;
                                if (mach_vm_read_overwrite( mach_task_self(),
                                        (mach_vm_address_t)(frame + 0x18), 8,
                                        (mach_vm_address_t)&grip, &g2 ) == KERN_SUCCESS)
                                    ERR("[callret] State.rip=%p\n", (void *)(uintptr_t)grip);
                            }
                            ERR("[callret] frame=%p sp=%p(ok=%d) base=%p(ok=%d) in_range=%d\n",
                                (void *)(uintptr_t)frame, (void *)(uintptr_t)sp, ok_sp,
                                (void *)(uintptr_t)base, ok_base,
                                (ok_sp && ok_base && base && sp >= base && sp < base + 0x1000000));
                            if (ok_ent)
                                ERR("[callret] top (PREDICTION HISTORY — stale/completed frames expected, NOT an unwind): %llx %llx %llx %llx %llx %llx %llx %llx\n",
                                    (unsigned long long)ent[0], (unsigned long long)ent[1],
                                    (unsigned long long)ent[2], (unsigned long long)ent[3],
                                    (unsigned long long)ent[4], (unsigned long long)ent[5],
                                    (unsigned long long)ent[6], (unsigned long long)ent[7]);
                        }

                        if (f_addr == 0 && !dumped_page0 && (dumped_page0 = 1))
                        {
                            uintptr_t blk = (uintptr_t)pc & ~0x3fffULL;
                            unsigned row;

                            ERR("[disp-dump] block=%p pc=%p offset=0x%lx (16KB-aligned window)\n",
                                (void *)blk, pc, (unsigned long)((uintptr_t)pc - blk));
                            for (row = 0; row < 8; row++)
                            {
                                /* window: pc-0x200 .. pc+0x0 , 16 words per row */
                                const uint32_t *w2 = (const uint32_t *)((uintptr_t)pc - 0x200 + row * 64);
                                int off = -0x200 + (int)(row * 64);
                                char lb[256];
                                int ln = 0, q;
                                for (q = 0; q < 16 && ln < (int)sizeof(lb) - 12; q++)
                                    ln += snprintf( lb + ln, sizeof(lb) - ln, "%08x ",
                                                    win[(0x400 + off + q * 4) / 4] );
                                (void)w2;
                                ERR("[disp-dump] +%04x: %s\n",
                                    (unsigned)((uintptr_t)pc - blk + off), lb);
                            }
                        }
                    }
                    else
                        ERR("[x18-decline] #%d marker scan unreadable at %p\n",
                            ios_x18_decline_reports, (void *)base);
                }

                /* ml159 follow-up: the fatal webhelper fault is FEX's own
                 * `movz w1,#0; ldr x1,[x1]` sitting between two
                 * SpillStaticRegs (verified against Arm64Emitter.cpp: the
                 * trailing mrs FPCR / bic NEP|AH|FIZ / msr FPCR is literally
                 * SpillStaticRegs' first emission). Probe #2 showed FEX's
                 * STATE register x28 == 0 in this process. The segv dump
                 * prints x0-x3/x8-x10/x16-x20 but NOT x21-x28, so we cannot
                 * yet tell whether the fatal site ALSO has a null STATE.
                 *
                 * FEX spills guest regs to [x28,#N] and FPRs via x10=x28+0x1c0
                 * — so if x28 is sane here, the null pointer is a separate
                 * FEX constant; if x28 is 0, the whole FEX instance is
                 * uninitialised and the fix belongs in FEX per-process init.
                 * Also walk TEB -> CPUArea (TEB+0x1788) -> +0x30, the chain
                 * the EC dispatcher uses, since that is what FEX_IOS_HOST
                 * reads via TPIDRRO_EL0 + TSD slot 275. */
                ERR("[x18-decline] #%d x21=%p x22=%p x23=%p x24=%p\n",
                    ios_x18_decline_reports,
                    (void *)REGn_sig(21, context), (void *)REGn_sig(22, context),
                    (void *)REGn_sig(23, context), (void *)REGn_sig(24, context));
                ERR("[x18-decline] #%d x25=%p x26=%p x27=%p x28(STATE)=%p lr=%p sp=%p\n",
                    ios_x18_decline_reports,
                    (void *)REGn_sig(25, context), (void *)REGn_sig(26, context),
                    (void *)REGn_sig(27, context), (void *)REGn_sig(28, context),
                    (void *)REGn_sig(30, context), (void *)SP_sig(context));
                {
                    /* Read via mach_vm_read_overwrite, never a raw deref: a
                     * fault INSIDE the segv handler would recurse and hang
                     * the app instead of dying cleanly. */
                    uintptr_t teb = ios_teb_for_signals;
                    uint64_t cpu_area = 0, ca30 = 0;
                    mach_vm_size_t got = 0;
                    int ok1 = 0, ok2 = 0;

                    if (teb)
                        ok1 = (mach_vm_read_overwrite( mach_task_self(),
                                   (mach_vm_address_t)(teb + 0x1788), 8,
                                   (mach_vm_address_t)&cpu_area, &got ) == KERN_SUCCESS
                               && got == 8);
                    if (ok1 && cpu_area)
                        ok2 = (mach_vm_read_overwrite( mach_task_self(),
                                   (mach_vm_address_t)(cpu_area + 0x30), 8,
                                   (mach_vm_address_t)&ca30, &got ) == KERN_SUCCESS
                               && got == 8);
                    ERR("[x18-decline] #%d teb=%p CPUArea(teb+0x1788)=%p(ok=%d) "
                        "CPUArea+0x30=%p(ok=%d)\n",
                        ios_x18_decline_reports, (void *)teb,
                        (void *)(uintptr_t)cpu_area, ok1,
                        (void *)(uintptr_t)ca30, ok2);
                }
            }
        }

        if (REGn_sig(18, context) == 0 && ios_teb_for_signals != 0
            && (uintptr_t)pc >= 0x100000000ULL
            && ((*(uint32_t *)pc >> 5) & 31) == 18)
        {
            REGn_sig(18, context) = ios_teb_for_signals;
            return;
        }

        /* ml1047: BUDGET PER DISTINCT PC, not per run.
         *
         * The flat "first 20" was spent before it could matter: on the iPhone 18
         * Pro 16 of the 20 detailed dumps went to ONE pc (0x16cff4660, a routine
         * null read on the dispatcher path that is handled every time), so the
         * fault that actually killed the run -- a guest store through a bad
         * pointer -- printed no registers at all and could not be attributed. Two
         * dumps per pc keeps the routine site quiet and leaves room for the
         * fault nobody has seen yet. */
        int ml1047_dump = 0;
        {
            static struct { void *pc; int n; } seen[48];
            static int nseen;
            int si;
            for (si = 0; si < nseen; si++) if (seen[si].pc == pc) break;
            if (si == nseen && nseen < 48) { seen[nseen].pc = pc; seen[nseen].n = 0; nseen++; }
            if (si < 48 && seen[si].n < 2 && segv_dump_count < 40) { seen[si].n++; ml1047_dump = 1; }
        }
        if (ml1047_dump)
        {
            segv_dump_count++;
            /* Check TPIDR_EL0 — should hold TEB if binary patcher is working */
            uint64_t tpidr_el0;
            __asm__ volatile("mrs %0, TPIDR_EL0" : "=r"(tpidr_el0));
            /* ml209: TPIDR_EL0 is INFORMATIONAL ONLY. iOS owns and zeroes it, we removed
             * our `msr TPIDR_EL0, x18` on 2026-07-04, and nothing of ours reads it — TEB
             * recovery runs off TPIDRRO_EL0 + TSD slot 275, printed below. The old
             * "(expected ...)" wording cost a debugging detour by making a garbage value
             * here look like a root cause; it is not one. */
            ERR("SEGV at pc=%p addr=%p esr=0x%llx TPIDR_EL0=%p (informational only — TEB is tsd275 below)\n",
                pc, siginfo->si_addr, (unsigned long long)esr, (void*)tpidr_el0);
            ERR("  x0=%p x1=%p x2=%p x3=%p\n",
                (void*)REGn_sig(0, context), (void*)REGn_sig(1, context),
                (void*)REGn_sig(2, context), (void*)REGn_sig(3, context));
            ERR("  x8=%p x9=%p x10=%p x16=%p x17=%p x18=%p x19=%p x20=%p\n",
                (void*)REGn_sig(8, context),
                (void*)REGn_sig(9, context), (void*)REGn_sig(10, context),
                (void*)REGn_sig(16, context), (void*)REGn_sig(17, context),
                (void*)REGn_sig(18, context), (void*)REGn_sig(19, context),
                (void*)REGn_sig(20, context));
            ERR("  fp=%p lr=%p sp=%p\n",
                (void*)FP_sig(context), (void*)REGn_sig(30, context),
                (void*)SP_sig(context));
            /* task #24: settings threads fault in the TSD-275 thunk with a
             * NULL slot despite start_thread's write. Dump the live slot +
             * base at fault time, and dladdr any dyld-cache pc/lr so Apple
             * frames name themselves. */
            {
                extern pthread_key_t ios_teb_tls_key;
                uintptr_t tsd_base_now;
                __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tsd_base_now));
                tsd_base_now &= ~7ULL;
                extern int ios_teb_tls_slot_offset;
                ERR("  [teb-tsd] base=%p offset=0x%x raw=%p teb_key_val=%p\n",
                    (void*)tsd_base_now, ios_teb_tls_slot_offset,
                    ios_teb_tls_slot_offset
                        ? *(void **)(tsd_base_now + ios_teb_tls_slot_offset) : NULL,
                    pthread_getspecific(ios_teb_tls_key));
            }
            /* ml209: the libcef-init wall. A guest PUSH faulted writing to an address
             * Wine does not own, because the guest RSP held 0x40001141 while the thread's
             * real stack was [73d2130000..73d2170000]. The faulting block was
             *   ldr x2,[x28,#0x40] / sub x2,x2,#0x10 / str x2,[x28,#0x40] / str x0,[x2]
             * so x28 is FEX's live STATE pointer and +0x40 is gregs[4] = RSP.
             *
             * Dump the whole CPUState to split the two candidates, which need opposite
             * fixes: if only RSP is implausible the guest clobbered its own stack pointer;
             * if most gregs are garbage we are executing on an uninitialised or wrong
             * CpuStateFrame. The plausible-pointer count is the discriminator, and it is
             * printed alongside the raw values so a wrong assumption here is visible
             * rather than silently believed. */
            {
                uint64_t state = REGn_sig(28, context);
                uint64_t cs[17];              /* +0x18 rip, then gregs[0..15] */
                mach_vm_size_t got = 0;

                if (state && mach_vm_read_overwrite( mach_task_self(),
                        (mach_vm_address_t)(state + 0x18), sizeof(cs),
                        (mach_vm_address_t)cs, &got ) == KERN_SUCCESS && got == sizeof(cs))
                {
                    static const char * const gn[16] = {
                        "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                        "r8 ","r9 ","r10","r11","r12","r13","r14","r15" };
                    int i, plausible = 0;

                    ERR("  [guest-state] x28=%p rip=%p\n", (void*)state, (void*)cs[0]);
                    /* madeira-bcd: name the image section the guest RIP is in, and
                     * Wine's protection of its page. A NoExec trap (FEX's deliberate
                     * load from 0) inside an image means the emulator does not know
                     * the range as executable: an executable section here points at
                     * the emulator, a data section with an executable vprot at a
                     * protect it was never told about, a data section without one at
                     * a wrong jump target (GTA V Enhanced's NoExec crash). */
                    {
                        extern int ios_image_section_describe( unsigned long long va, char *buf, size_t len,
                                                               unsigned long long *img_base );
                        extern unsigned char ios_reclaim_page_vprot( unsigned long long va );
                        static int rip_sec_n;
                        char rsec[160];
                        unsigned long long ib = 0;

                        if (rip_sec_n < 8 && ios_image_section_describe( cs[0], rsec, sizeof(rsec), &ib ))
                        {
                            rip_sec_n++;
                            /* vprot is Wine's view of the address itself: meaningful
                             * for a PE address, 0 for a pool copy (not Wine-managed). */
                            ERR("  [guest-rip-sec] rip=%p in image %p: %s, vprot=%#x\n",
                                (void*)cs[0], (void*)ib, rsec,
                                (unsigned)ios_reclaim_page_vprot( cs[0] ));
                        }
                    }
                    /* ml885: State.rip is only the block ENTRY. Resolve the exact
                     * guest instruction from the block tail, and show its bytes,
                     * so a fault names the x86 instruction rather than the block.
                     * A resolved RIP that does not belong to the block the return
                     * address implies means the `ret` landed in the wrong block
                     * (callret / invalidation), not that the guest read garbage. */
                    {
                        extern uint64_t ios_native_rip_from_hostpc( uint64_t, uint64_t, const char ** );
                        uint64_t bb = 0, xrip = 0; const char *why = "";
                        mach_vm_size_t g2 = 0;
                        if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)state, 8,
                                                    (mach_vm_address_t)&bb, &g2 ) == KERN_SUCCESS && g2 == 8 && bb)
                            xrip = ios_native_rip_from_hostpc( bb, (uint64_t)(uintptr_t)pc, &why );
                        if (xrip)
                        {
                            extern unsigned long long ios_jit_module_base_for_va( unsigned long long, unsigned long long * );
                            unsigned long long sch_size = 0;
                            uint64_t sch_base = ios_jit_module_base_for_va( xrip, &sch_size );
                            /* Live SRA RBX/RSP, not potentially stale gregs. The
                             * dump itself accepts only the exact helper build
                             * and I/O pump fault range, and reads through Mach. */
                            if (sch_base) ios_sc_runstate_dump( sch_base, xrip, REGn_sig(27, context), REGn_sig(23, context) );
                            uint8_t xb[16]; mach_vm_size_t g3 = 0;
                            if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)xrip, sizeof(xb),
                                                        (mach_vm_address_t)xb, &g3 ) == KERN_SUCCESS && g3 == sizeof(xb))
                                ERR("  [guest-exact] ml885 block=%p rip=%p x86=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                    (void*)bb, (void*)xrip, xb[0],xb[1],xb[2],xb[3],xb[4],xb[5],xb[6],xb[7],xb[8],xb[9],xb[10],xb[11],xb[12],xb[13],xb[14],xb[15]);
                            else
                                ERR("  [guest-exact] ml885 block=%p rip=%p (bytes unreadable)\n", (void*)bb, (void*)xrip);
                        }
                        else ERR("  [guest-exact] ml885 block=%p unresolved: %s\n", (void*)bb, why);
                    }
                    for (i = 0; i < 16; i += 4)
                        ERR("  [guest-state]   %s=%p %s=%p %s=%p %s=%p\n",
                            gn[i],   (void*)cs[1+i], gn[i+1], (void*)cs[2+i],
                            gn[i+2], (void*)cs[3+i], gn[i+3], (void*)cs[4+i]);
                    for (i = 0; i < 16; i++)
                        if (cs[1+i] >= 0x100000000ull && cs[1+i] < 0x8000000000ull) plausible++;
                    ERR("  [guest-state] plausible-ptr gregs=%d/16 (low => uninitialised frame, "
                        "high => only rsp clobbered)\n", plausible);

                    /* ml962 (Astra step 3): capture the OPERAND, not the innocent
                     * final load.
                     *
                     * The faulting block is EMP.dll rva 0x13bd8b:
                     *   mov   rdx, [r10]          <- loads the pointer
                     *   ...
                     *   movzx r11w, byte ptr [rdx] <- faults
                     * so RDX/x1 is the faulting pointer and it was LOADED from
                     * [R10]; this block does not create it. Four runs show the
                     * fault address equals (latest allocation + 0x10) truncated to
                     * 32 bits, so something upstream discards the high half -- but
                     * NOT this block (verified: the host lowering is a 64-bit
                     * `ldapr x1,[x4]`).
                     *
                     * Printing the eight bytes actually in memory at [R10] splits
                     * the two remaining possibilities:
                     *   - operand already low in memory  => trace its WRITER;
                     *   - operand full width in memory   => the load returned low,
                     *     i.e. our own emulation/aliasing path is at fault.
                     * Failure-returning read, so an unmapped R10 cannot fault the
                     * handler. R10 has been 0x...1b6 in every run: mod 8 == 6, i.e.
                     * an UNALIGNED 8-byte access, which is why FEX's lowering is an
                     * acquire form at all and why this goes through our unaligned
                     * backpatch path. Surrounding bytes included per Astra. */
                    {
                        const uint64_t r10v = cs[1+10], rdxv = cs[1+2];
                        uint64_t at_r10 = 0;
                        unsigned char around[40];
                        mach_vm_size_t g4 = 0, g5 = 0;
                        int ok8, okA;

                        ok8 = (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)r10v, 8,
                                                       (mach_vm_address_t)&at_r10, &g4 ) == KERN_SUCCESS
                               && g4 == 8);
                        okA = (r10v >= 16) &&
                              (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(r10v - 16),
                                                       sizeof(around), (mach_vm_address_t)around,
                                                       &g5 ) == KERN_SUCCESS && g5 == sizeof(around));
                        if (ok8)
                            ERR("  [operand] ml962 R10=0x%llx (mod8=%u) [R10]=0x%016llx  RDX=0x%llx"
                                " | high32([R10])=0x%08llx %s\n",
                                (unsigned long long)r10v, (unsigned)(r10v & 7u),
                                (unsigned long long)at_r10, (unsigned long long)rdxv,
                                (unsigned long long)(at_r10 >> 32),
                                (at_r10 >> 32) ? "OPERAND IS FULL WIDTH -> the LOAD lost the high half"
                                               : "OPERAND ALREADY TRUNCATED IN MEMORY -> trace its WRITER");
                        else
                            ERR("  [operand] ml962 R10=0x%llx (mod8=%u) [R10] UNREADABLE got=%llu RDX=0x%llx\n",
                                (unsigned long long)r10v, (unsigned)(r10v & 7u),
                                (unsigned long long)g4, (unsigned long long)rdxv);
                        if (okA)
                        {
                            int bi;
                            char hex[40*3+1];
                            for (bi = 0; bi < (int)sizeof(around); bi++)
                                snprintf( hex + bi*3, 4, "%02x ", around[bi] );
                            ERR("  [operand] ml962 [R10-16 .. R10+23]: %s\n", hex);
                        }

                        /* ml965: prove the mixed-width round-trip.
                         *
                         * Offline disassembly of EMP.dll .emp1 at the verified file
                         * offset (anchored on the known bytes 49 8b 12) shows this is
                         * an OBFUSCATION VM, not a structure access:
                         *   mov rdx,[r10] / movzx r11w,[rdx] / add r10,6 /
                         *   mov word [r10],r11w / mov ebp,[r9] / add r9,4 / jmp ...
                         * r10 is a byte-stream cursor into a stack-resident VM
                         * context, advancing by 6, read 8 wide, written 2 wide. A
                         * capstone scan of 256 KB of .emp1 finds stores through that
                         * same cursor at THREE widths: 100 x 16-bit, 57 x 32-bit,
                         * 74 x 64-bit. So a value written narrow and read wide picks
                         * up whatever adjoins it -- which is exactly the observed
                         * (alloc + 0x10) with a zero high half, 5 runs running.
                         *
                         * What is still unproven is that THIS pointer went in through
                         * a narrow slot. Scan a wider window of the stream for the
                         * low 32 bits and report, for each occurrence, what follows:
                         * 0x00000001 means a full-width copy also exists in the
                         * stream (so the wide write happened and something else is
                         * wrong), zeros mean the only copy is narrow (round-trip
                         * confirmed). Bounded window, failure-returning read. */
                        {
                            unsigned char win[256];
                            mach_vm_size_t g6 = 0;
                            const uint64_t lo32 = (uint64_t)(uint32_t)at_r10;

                            if (ok8 && lo32 && r10v >= 128 &&
                                mach_vm_read_overwrite( mach_task_self(),
                                                        (mach_vm_address_t)(r10v - 128),
                                                        sizeof(win), (mach_vm_address_t)win,
                                                        &g6 ) == KERN_SUCCESS && g6 == sizeof(win))
                            {
                                int wi, found = 0;
                                for (wi = 0; wi + 8 <= (int)sizeof(win); wi++)
                                {
                                    uint32_t v32;
                                    uint32_t nxt;
                                    memcpy( &v32, win + wi, 4 );
                                    if (v32 != (uint32_t)lo32) continue;
                                    memcpy( &nxt, win + wi + 4, 4 );
                                    found++;
                                    ERR("  [stream] ml965 low32=0x%08x found at R10%+d, next 4 bytes = 0x%08x -- %s\n",
                                        (unsigned)v32, wi - 128, (unsigned)nxt,
                                        (nxt == 1u) ? "FULL-WIDTH copy present (wide write DID happen)"
                                        : (nxt == 0u) ? "adjoined by zeros (consistent with a narrow slot; "
                                                        "does NOT identify the writing instruction)"
                                                      : "adjoined by unrelated stream bytes");
                                    if (found >= 6) break;
                                }
                                if (!found)
                                    ERR("  [stream] ml965 low32=0x%08x not found anywhere in [R10-128,R10+128)\n",
                                        (unsigned)lo32);
                            }
                        }
                    }

                    /* ml212: NAME THE CALLER.
                     *
                     * The guest RIP is <arena>+0xe0080 — an address with no code — so FEX
                     * raised SIGSEGV through its deliberate `mov w1,#0; ldr x1,[x1]`
                     * trampoline (visible in insn_stream above). Nothing is corrupt: the
                     * CpuStateFrame is valid and the fault is FEX correctly reporting a
                     * bogus branch target. The open question is who branched there, and
                     * that offset has been byte-identical across runs and across three
                     * different arena bases, so it is computed, not random.
                     *
                     * FEX keeps guest return addresses on its callret stack
                     * (CPUState+0xB0 = sp, +0xB8 = base). Dump the top entries; resolving
                     * them offline against the [iOS-xins]/[jit-pool] bases names the
                     * function that jumped. Depth is printed too, so an empty or absurd
                     * stack is visible rather than silently mistaken for evidence. */
                    {
                        uint64_t cr[2] = { 0, 0 };
                        uint64_t ents[8];
                        mach_vm_size_t g2 = 0;

                        if (mach_vm_read_overwrite( mach_task_self(),
                                (mach_vm_address_t)(state + 0xB0), sizeof(cr),
                                (mach_vm_address_t)cr, &g2 ) == KERN_SUCCESS && g2 == sizeof(cr))
                        {
                            /* ml381 UNITS FIX. This printed (sp - base) / 8 and
                             * called it "depth", which is wrong twice over: the
                             * stack starts at base + 4MB (DefaultLocation) and
                             * grows DOWN, and entries are 16 bytes, not 8. An
                             * EMPTY stack therefore printed depth=524288 — and I
                             * read ml377's 500262 and ml380's 522626 as a
                             * half-million-entry LEAK and proposed chasing task
                             * #42, when the true occupancies were 12,013 and 831
                             * entries (4.6% and 0.3% of the window). Print what
                             * is actually being asked — entries USED — so it
                             * cannot be misread again. */
                            unsigned long long dflt = cr[1] + 0x400000;
                            unsigned long long used_b = (dflt > cr[0]) ? dflt - cr[0] : 0;

                            ERR("  [callret] sp=%p base=%p default=%p used=%llu entries (%llu bytes, %llu%% of 4MB)\n",
                                (void *)cr[0], (void *)cr[1], (void *)(uintptr_t)dflt,
                                used_b / 16, used_b, (used_b * 100) / 0x400000 );

                            /* ml213: the cap was 0x100000, but a real run had depth=168218
                             * (1.28MB of stack) and the dump was skipped for no good
                             * reason — only the TOP n*8 bytes are ever read, so the total
                             * size never mattered. Bound it generously, purely as a
                             * sanity check against a garbage sp/base pair. */
                            if (used_b && cr[0] - cr[1] <= 0x10000000)
                            {
                                /* ml381: qwords to dump from the top of the
                                 * stack — 2 qwords per 16-byte entry. */
                                unsigned long long qw = (used_b / 8);
                                unsigned n = qw > 8 ? 8 : (unsigned)qw;

                                if (mach_vm_read_overwrite( mach_task_self(),
                                        (mach_vm_address_t)(cr[0] - (uint64_t)n * 8),
                                        n * 8, (mach_vm_address_t)ents, &g2 ) == KERN_SUCCESS
                                    && g2 == n * 8)
                                {
                                    unsigned k;

                                    for (k = n; k-- > 0; )
                                        ERR("  [callret]   [-%u] %p\n", n - k, (void *)ents[k]);
                                }
                            }
                        }
                    }
                }
                else
                    ERR("  [guest-state] x28=%p UNREADABLE got=%llu\n",
                        (void*)state, (unsigned long long)got);
            }
            {
                uintptr_t sym_addrs[2] = { (uintptr_t)PC_sig(context), (uintptr_t)REGn_sig(30, context) };
                int si;
                for (si = 0; si < 2; si++)
                {
                    Dl_info di_s;
                    const char *img_s;
                    if (sym_addrs[si] >= 0x180000000ULL && (sym_addrs[si] >> 32) < 0x300 &&
                        dladdr((void *)sym_addrs[si], &di_s) && di_s.dli_sname)
                    {
                        img_s = di_s.dli_fname ? strrchr(di_s.dli_fname, '/') : NULL;
                        img_s = img_s ? img_s + 1 : (di_s.dli_fname ? di_s.dli_fname : "?");
                        ERR("  [sym] %s=%s`%s+0x%llx\n", si ? "lr" : "pc", img_s,
                            di_s.dli_sname,
                            (unsigned long long)(sym_addrs[si] - (uintptr_t)di_s.dli_saddr));
                    }
                }
            }
            if ((uintptr_t)PC_sig(context) >= 0x100000000ULL)
            {
                uint32_t *p = (uint32_t*)(uintptr_t)PC_sig(context);
                /* ml265 (#46): WIDE window when the fault PC is FEX-emitted code.
                 *
                 * The ml265 fatal is a DELIBERATE null deref in the dispatcher:
                 *   52800001  movz w1, #0        <- x1 set to 0 literally
                 *   f9400021  ldr  x1, [x1]      <- FAULTS
                 *   d53b440a  mrs  x10, fpcr     (FP-control setup)
                 * preceded by two `st1` SIMD stores -- the dispatcher's FP-save
                 * sequence. pc sits at pool offset 0x36ff8650, the tail EC_CODE area,
                 * i.e. code FEX EMITTED, not translated guest code.
                 *
                 * That matters because this port already patches "FEX's emitter on iOS
                 * produces garbage words in the dispatcher" (Module.cpp SpillStaticRegs
                 * scanner), whose own comment notes mis-patching "causes st1 faults
                 * later". 7 words is too narrow to tell a genuine emit from a corrupted
                 * one, and the offset relative to the dispatcher decides which documented
                 * site (+0x160 / +0x184 / +0x264) this is. Dump 24 words with the pool
                 * offset so the emitted sequence can be read offline against the
                 * expected layout. Capped; only for pool PCs. */
                {
                    extern void *ios_jit_rx_base_global;
                    extern size_t ios_jit_pool_size_global;
                    uintptr_t rxb = (uintptr_t)ios_jit_rx_base_global;
                    uintptr_t fpc = (uintptr_t)PC_sig(context);
                    static int wide_dumps;

                    if (((rxb && fpc >= rxb && fpc < rxb + ios_jit_pool_size_global) ||
                         ios_jit_low_contains( fpc )) &&   /* madeira-bcd pool-low */
                        wide_dumps < 4)
                    {
                        const uint32_t *w = (const uint32_t *)(fpc - 48);
                        int i;
                        wide_dumps++;
                        ERR("  [emit-dump] pc=0x%llx pooloff=0x%llx  PC-48..PC+44:\n",
                            (unsigned long long)fpc, (unsigned long long)(fpc - rxb));
                        for (i = 0; i < 24; i += 6)
                            ERR("  [emit-dump]   +%-4d %08x %08x %08x %08x %08x %08x\n",
                                (i - 12) * 4, w[i], w[i+1], w[i+2], w[i+3], w[i+4], w[i+5]);
                    }
                }
                /* ml270 (#48): WHERE does the corrupt guest RSP come from?
                 *
                 * Signature across runs: RSP alone is garbage while the other guest
                 * registers stay valid -- "plausible-ptr gregs=11/16", and the probe's own
                 * legend reads "high => only rsp clobbered". The bad value is structured,
                 * not random:
                 *   ml260 rsp=0x40001131  addr=0x40001131  addr=0xe0001131
                 *   ml270 rsp=0x80001131  addr=0x80001131
                 * low 28 bits constant at 0x0001131, only the TOP NIBBLE varies (4/8/e) --
                 * which is where ARM64 NZCV lives (4=Z, 8=N, e=NZC).
                 *
                 * In ARM64EC guest RSP is SRA register x23, spilled/filled via
                 * State.gregs[RSP]. Three outcomes need different fixes:
                 *   x23 garbage but gregs[RSP] VALID  -> a fill/spill bug clobbered the reg
                 *   both garbage                       -> corruption happened earlier
                 *   top nibble == flags[24] (NZCV)     -> a FLAGS word is being used as RSP
                 * Print all three rather than pattern-matching hex, which has misled before. */
                {
                    static int rspq;
                    /* Get the TEB the same way the [tsd275] dump above does — a POSIX
                     * signal handler has no mach thread_t to hand, and x18 is zero here. */
                    uintptr_t tsd_r;
                    uintptr_t teb_r;
                    __asm__ volatile("mrs %0, TPIDRRO_EL0" : "=r"(tsd_r));
                    tsd_r &= ~7ULL;
                    teb_r = ios_teb_tls_slot_offset
                        ? (uintptr_t)*(void **)(tsd_r + ios_teb_tls_slot_offset) : 0;

                    /* ml558: this probe KILLED ml557.
                     *
                     * TSD slot 275 is not ours -- pthread_exit_wrapper's own comment
                     * says so. On a NATIVE (non-wine) thread some Apple framework's
                     * value sits there, we read it as a TEB, and TEB+0x1788 came back
                     * 0x40; *(0x40+0x30) faulted at 0x70 inside the signal handler.
                     *
                     * Worse, the `rspq < 6` cap could never engage: rspq++ was BELOW
                     * the faulting load, so the counter never advanced and the probe
                     * re-faulted forever (5,000+ times in ml557) until the fault-stuck
                     * breaker diverted the thread into abort_thread.
                     *
                     * Two rules restored: (1) only look at TSD 275 on a thread we
                     * actually registered, (2) SPEND THE BUDGET FIRST -- increment
                     * before the risky deref, so a fault can cost at most 6 tries. */
                    if (rspq < 6 && ios_teb_is_registered(teb_r))
                    {
                        void *cpuarea_r;
                        rspq++;                       /* spend it BEFORE we can fault */
                        cpuarea_r = *(void**)(teb_r + 0x1788);
                        if ((uintptr_t)cpuarea_r < 0x10000)
                        {
                            ERR("  [rsp-trunc] cpuarea=%p implausible (TSD275 not a wine TEB) "
                                "-- skipping deref rev=ml558\n", cpuarea_r);
                            cpuarea_r = NULL;
                        }
                        if (cpuarea_r)
                        {
                            uint64_t *frame_r = *(uint64_t**)((char*)cpuarea_r + 0x30);
                            if (frame_r)
                            {
                                /* ml272: offsets CONFIRMED from FEX's own [state-offsets]
                                 * line -- rip=0x18 gregs=0x20 gregs[RSP]=0x40
                                 * callret_sp=0xb0 callret_sp_base=0xb8 flags=0x3f0.
                                 * The first cut of this probe read gregs[RSP] at 0x28,
                                 * which is gregs[1] = RCX, so every "gregs[RSP]=0" it
                                 * printed was meaningless. Also print callret_sp, since
                                 * the dispatcher's `ldr x17,[x28,#176]` reads exactly
                                 * that field and x17==0 is the #42 storm's trigger. */
                                ERR("  [rsp-forensics] x23(SRA RSP)=%p  gregs[RSP]=%p  "
                                    "NZCV/flags[24]=0x%08x  callret_sp=%p base=%p  x28=%p%s\n",
                                    (void*)(uintptr_t)REGn_sig(23, context),
                                    (void*)(uintptr_t)frame_r[0x40/8],
                                    (unsigned)((uint32_t*)frame_r)[0x408/4],
                                    (void*)(uintptr_t)frame_r[0xb0/8],
                                    (void*)(uintptr_t)frame_r[0xb8/8],
                                    (void*)frame_r,
                                    frame_r[0xb0/8] ? "" : "  <== callret_sp is ZERO (#42 trigger)");
                            }
                        }
                    }
                }
                /* iOS-Madeira ml329 (#53 discriminator): on a NULL-ish deref -- the exact
                 * shape of the IntrusivePooledAllocator crash (a list node read at
                 * offset 8 of a NULL `next`) -- state whether iOS zero-filled any page of
                 * FEX's host heap this run. Prints the verdict either way, so a run with
                 * no FEX-band recovery is a real negative that REFUTES #53 for this crash
                 * rather than silence. */
                if (siginfo->si_addr && (uintptr_t)siginfo->si_addr < 0x1000)
                {
                    extern void ios_reclaim_pages_report( const char *when, unsigned long long fault_addr );
                    ios_reclaim_pages_report( "fatal-segv", (unsigned long long)(uintptr_t)siginfo->si_addr );
                }
                ERR("  insn_stream PC-12..PC+8: %08x %08x %08x [%08x] %08x %08x %08x\n",
                    p[-3], p[-2], p[-1], p[0], p[1], p[2], p[3]);
            }
            else
                ERR("  insn=<unmappable PC, skipping read>\n");
            /* For tiny PC SEGVs through arm64x_check_call: probe LR-4 to
             * find the BLR that set up x11, and dump EC bitmap bit for x11
             * so we can see whether the bitmap fast-path should have taken
             * us out of arm64x_check_call. */
            if ((uintptr_t)PC_sig(context) < 0x100000000ULL)
            {
                extern PEB *peb;
                uintptr_t lr_val = (uintptr_t)REGn_sig(30, context);
                uintptr_t x11_at_seg = (uintptr_t)REGn_sig(11, context);
                ERR("  x11=%p lr=%p\n", (void*)x11_at_seg, (void*)lr_val);
                /* Decode the branch instruction at lr-4 to identify which
                 * register held the BR target at the time of the branch. */
                if (lr_val >= 0x100000004ULL)
                {
                    uint32_t branch_insn = *(uint32_t*)(lr_val - 4);
                    ERR("  branch@(lr-4)=%08x", branch_insn);
                    /* BR/BLR encoding: D61F0xxx (BR) or D63F0xxx (BLR) where
                     * bits 9:5 = Rn. */
                    if ((branch_insn & 0xFFFE0FFF) == 0xD61F0000) {
                        int rn = (branch_insn >> 5) & 0x1f;
                        ERR("    → BR x%d", rn);
                    } else if ((branch_insn & 0xFFFE0FFF) == 0xD63F0000) {
                        int rn = (branch_insn >> 5) & 0x1f;
                        ERR("    → BLR x%d", rn);
                    }
                    ERR("\n");
                    /* Dump 4 insns before the BLR — usually ADRP/ADRPL+LDR
                     * loading x16 from a dispatcher slot. Decode the slot
                     * address and the pointer it currently contains. */
                    if (lr_val >= 0x100000010ULL)
                    {
                        uint32_t i0 = *(uint32_t*)(lr_val - 16);
                        uint32_t i1 = *(uint32_t*)(lr_val - 12);
                        uint32_t i2 = *(uint32_t*)(lr_val - 8);
                        ERR("  call_site@(lr-16): %08x %08x %08x %08x\n",
                            i0, i1, i2, branch_insn);
                        /* Scan i0..i2 for an ADRP and following LDR loading
                         * x16, the BLR target. */
                        uint32_t insns[4] = { i0, i1, i2, branch_insn };
                        uintptr_t insn_pcs[4] = {
                            lr_val - 16, lr_val - 12, lr_val - 8, lr_val - 4 };
                        for (int k = 0; k < 3; k++)
                        {
                            uint32_t adrp = insns[k];
                            /* ADRP encoding: 1 | immlo[2] | 10000 | immhi[19] | Rd[5] */
                            if ((adrp & 0x9f000000) != 0x90000000) continue;
                            int rd = adrp & 0x1f;
                            int64_t immhi = (int64_t)((adrp >> 5) & 0x7ffff);
                            int64_t immlo = (int64_t)((adrp >> 29) & 3);
                            int64_t imm21 = (immhi << 2) | immlo;
                            if (imm21 & (1LL << 20)) imm21 |= (int64_t)0xffffffffffe00000;
                            uintptr_t adrp_pc = insn_pcs[k] & ~0xfffULL;
                            uintptr_t adrp_target = adrp_pc + (imm21 << 12);
                            ERR("    ADRP x%d → page %p (insn[%d]=%08x)\n",
                                rd, (void*)adrp_target, k, adrp);
                            /* Look for matching LDR in following insns. */
                            for (int m = k + 1; m < 4; m++)
                            {
                                uint32_t ldr = insns[m];
                                if ((ldr & 0xffc00000) != 0xf9400000) continue;
                                int rn_ldr = (ldr >> 5) & 0x1f;
                                int rt_ldr = ldr & 0x1f;
                                if (rn_ldr != rd) continue;
                                uint32_t imm12 = (ldr >> 10) & 0xfff;
                                uintptr_t slot_addr = adrp_target + (imm12 * 8);
                                ERR("    LDR x%d, [x%d, #0x%x] → slot=%p\n",
                                    rt_ldr, rn_ldr, imm12 * 8, (void*)slot_addr);
                                if (slot_addr >= 0x100000000ULL)
                                {
                                    void *slot_val = *(void**)slot_addr;
                                    extern uintptr_t ios_jit_reverse_translate_addr(void *addr);
                                    uintptr_t parent_slot = ios_jit_reverse_translate_addr((void*)slot_addr);
                                    void *parent_val = (parent_slot && parent_slot != slot_addr)
                                        ? *(void**)parent_slot : NULL;
                                    ERR("    JIT *slot = %p   parent@%p *slot = %p (expected %p)\n",
                                        slot_val, (void*)parent_slot, parent_val,
                                        peb ? peb->WerRegistrationData : NULL);
                                }
                                break;
                            }
                            break;
                        }
                    }
                }
                if (peb && peb->EcCodeBitMap && x11_at_seg >= 0x100000000ULL)
                {
                    uint64_t *bm = (uint64_t *)peb->EcCodeBitMap;
                    size_t page = x11_at_seg >> 12;
                    size_t blk  = page / 64;
                    int bit_in_blk = page & 63;
                    uint64_t blk_val = bm[blk];
                    int bit_set = (blk_val >> bit_in_blk) & 1;
                    ERR("  EcBitMap@%p: x11_page=0x%lx blk[%lx]=%llx bit=%d %s\n",
                        bm, (unsigned long)page, (unsigned long)blk,
                        (unsigned long long)blk_val, bit_set,
                        bit_set ? "(EC: fast-path SHOULD have taken)" : "(NOT EC: dispatch path taken)");
                }
                /* Dump the first 12 bytes at x11 (the called function's prologue)
                 * and at JIT-pool ntdll's __wine_dbg_header offset 0x5ed5c (the
                 * `ldr x11, [x18, #0x60]` instruction) to see whether our x18
                 * patcher replaced it with a B to a trampoline. */
                if (x11_at_seg >= 0x100000000ULL)
                {
                    uint32_t *p = (uint32_t *)x11_at_seg;
                    ERR("  callee prologue: %08x %08x %08x %08x\n",
                        p[0], p[1], p[2], p[3]);
                    /* If x11 is in __wine_dbg_header (0x5ed24), the LDR at
                     * +0x38 = +0xe (instr 14) is the patched one. Show it. */
                    uint32_t patched = p[14];
                    ERR("  callee[+0x38]=%08x (LDR x11,[x18,#0x60] should be B-tramp if patched)\n",
                        patched);
                    /* If patched is a B (top 6 bits = 0x05 = 0b000101), decode
                     * the target and dump trampoline bytes there. */
                    if ((patched >> 26) == 5)
                    {
                        int32_t imm26 = (int32_t)(patched & 0x3FFFFFF);
                        if (imm26 & 0x2000000) imm26 |= (int32_t)0xFC000000; /* sign-ext */
                        intptr_t b_target = (intptr_t)(&p[14]) + ((intptr_t)imm26 << 2);
                        if (b_target >= 0x100000000LL)
                        {
                            uint32_t *t = (uint32_t *)b_target;
                            ERR("  tramp@%p: %08x %08x %08x %08x %08x %08x %08x\n",
                                (void*)b_target, t[0], t[1], t[2], t[3], t[4], t[5], t[6]);
                        }
                        else
                        {
                            ERR("  tramp_target=%p (out of range, B-encoding bad)\n",
                                (void*)b_target);
                        }
                    }
                    /* Search the whole prologue for any instructions where bits
                     * encode 0x39cc-style tiny RVA — could the prologue itself
                     * contain a corrupted instruction whose immediate field is
                     * the target we ended up at? */
                    {
                        uintptr_t bad_pc = (uintptr_t)PC_sig(context);
                        for (int s = 0; s < 32; s++)
                        {
                            if ((p[s] & 0xfffff) == (bad_pc & 0xfffff))
                            {
                                ERR("  callee[+0x%02x]=%08x has imm matching bad PC low20\n",
                                    s*4, p[s]);
                                break;
                            }
                        }
                    }
                }
                /* Dump arm64x_check_call's first 8 instructions in JIT pool. We
                 * are crashing INSIDE that function (BLR x16 at lr-4). Its first
                 * instruction is `ldr x16, [x18, #0x60]` — the ONE x18-using
                 * insn in its body. The x18 patcher should have replaced it with
                 * a B to a trampoline. If the B's target decodes outside the JIT
                 * pool's trampoline area, that's the bug.
                 * Address is stashed in peb->WerRegistrationData by Wine's
                 * arm64ec_process_init. */
                {
                    uint32_t *cc = peb ? (uint32_t *)peb->WerRegistrationData : NULL;
                    if ((uintptr_t)cc >= 0x100000000ULL)
                    {
                        ERR("  arm64x_check_call@%p: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                            cc, cc[0], cc[1], cc[2], cc[3], cc[4], cc[5], cc[6], cc[7]);
                        /* If cc[0] is a B (top 6 bits = 0x05 = 0b000101), decode
                         * its target and dump the trampoline contents there. */
                        if ((cc[0] >> 26) == 5)
                        {
                            int32_t imm26 = (int32_t)(cc[0] & 0x3FFFFFF);
                            if (imm26 & 0x2000000) imm26 |= (int32_t)0xFC000000;
                            intptr_t b_target = (intptr_t)cc + ((intptr_t)imm26 << 2);
                            ERR("    cc[0] is B → target=%p (delta=%d insns)\n",
                                (void*)b_target, (int)imm26);
                            if (b_target >= 0x100000000LL)
                            {
                                uint32_t *t = (uint32_t *)b_target;
                                ERR("    cc-tramp@%p: %08x %08x %08x %08x %08x %08x %08x\n",
                                    (void*)b_target, t[0], t[1], t[2], t[3], t[4], t[5], t[6]);
                            }
                            else
                            {
                                ERR("    cc-tramp out of range — B encoding bad\n");
                            }
                        }
                        else
                        {
                            ERR("    cc[0] is NOT a B (opcode top6=%d) — patcher missed it\n",
                                (cc[0] >> 26));
                        }
                    }
                    else
                    {
                        ERR("  __os_arm64x_check_call=%p (not set or bad)\n", cc);
                    }
                }
            }
            /* Dump cpu_area (TEB.ChpeV2CpuAreaInfo) when PC is unmappable.
             * x17 typically holds cpu_area after enter_jit's chained loads,
             * so when we hit a tiny PC right after BR x16, x17 should still
             * have it. Bound-check x17 looks like a ~0x1xxxxxxxx pointer. */
            if ((uintptr_t)PC_sig(context) < 0x100000000ULL)
            {
                uintptr_t cpu_area_p = (uintptr_t)REGn_sig(17, context);
                if (cpu_area_p >= 0x100000000ULL && cpu_area_p < 0x800000000000ULL)
                {
                    uint64_t *ca = (uint64_t *)cpu_area_p;
                    ERR("  cpu_area@%p: [0x00]=%llx [0x08]=%llx [0x10]=%llx [0x18]=%llx\n",
                        (void*)cpu_area_p,
                        (unsigned long long)ca[0], (unsigned long long)ca[1],
                        (unsigned long long)ca[2], (unsigned long long)ca[3]);
                    ERR("              [0x20]=%llx [0x28]=%llx [0x30]=%llx [0x38]=%llx\n",
                        (unsigned long long)ca[4], (unsigned long long)ca[5],
                        (unsigned long long)ca[6], (unsigned long long)ca[7]);
                    ERR("              [0x40]=%llx [0x48]=%llx [0x50]=%llx [0x58]=%llx\n",
                        (unsigned long long)ca[8], (unsigned long long)ca[9],
                        (unsigned long long)ca[10], (unsigned long long)ca[11]);
                }
            }
        }
    }
#endif
    rec.NumberParameters = 2;
    if ((esr & 0xf0000000) == 0x80000000) rec.ExceptionInformation[0] = EXCEPTION_EXECUTE_FAULT;
    else if (esr & 0x40) rec.ExceptionInformation[0] = EXCEPTION_WRITE_FAULT;
    else rec.ExceptionInformation[0] = EXCEPTION_READ_FAULT;
    rec.ExceptionInformation[1] = (ULONG_PTR)siginfo->si_addr;
#ifdef WINE_IOS
    {
        static uintptr_t last_fault_pc = 0;
        static int fault_repeat_count = 0;
        uintptr_t this_pc = PC_sig(context);
        if (this_pc == last_fault_pc)
        {
            fault_repeat_count++;
            static unsigned long loop_storm;
            if (fault_repeat_count == 3 && ios_sig_storm_gate( &loop_storm ))
            {
                ERR("SEGV LOOP DETECTED: pc=%p addr=%p repeated %d times, dumping TEB+PEB\n",
                    (void*)this_pc, siginfo->si_addr, fault_repeat_count);
                /* Dump TEB */
                if (ios_teb_for_signals)
                {
                    uint64_t *teb = (uint64_t *)ios_teb_for_signals;
                    ERR("  TEB[0x00]=%p TEB[0x08]=%p TEB[0x10]=%p TEB[0x18]=%p\n",
                        (void*)teb[0], (void*)teb[1], (void*)teb[2], (void*)teb[3]);
                    ERR("  TEB[0x20]=%p TEB[0x28]=%p TEB[0x30]=%p TEB[0x38]=%p\n",
                        (void*)teb[4], (void*)teb[5], (void*)teb[6], (void*)teb[7]);
                    ERR("  TEB[0x40]=%p TEB[0x48]=%p TEB[0x50]=%p TEB[0x58]=%p\n",
                        (void*)teb[8], (void*)teb[9], (void*)teb[10], (void*)teb[11]);
                    ERR("  TEB[0x60]=%p TEB[0x68]=%p TEB[0x70]=%p TEB[0x78]=%p\n",
                        (void*)teb[12], (void*)teb[13], (void*)teb[14], (void*)teb[15]);
                    /* Dump PEB (TEB+0x60 is PEB pointer) */
                    uint64_t peb_addr = teb[12]; /* TEB[0x60] */
                    if (peb_addr > 0x10000)
                    {
                        uint64_t *peb = (uint64_t *)peb_addr;
                        ERR("  PEB @ %p:\n", (void*)peb_addr);
                        ERR("  PEB[0x00]=%p PEB[0x08]=%p PEB[0x10]=%p PEB[0x18]=%p\n",
                            (void*)peb[0], (void*)peb[1], (void*)peb[2], (void*)peb[3]);
                        ERR("  PEB[0x20]=%p PEB[0x28]=%p PEB[0x30]=%p PEB[0x38]=%p\n",
                            (void*)peb[4], (void*)peb[5], (void*)peb[6], (void*)peb[7]);
                        ERR("  PEB[0x40]=%p PEB[0x48]=%p PEB[0x50]=%p PEB[0x58]=%p\n",
                            (void*)peb[8], (void*)peb[9], (void*)peb[10], (void*)peb[11]);
                        ERR("  PEB[0x60]=%p PEB[0x68]=%p PEB[0x70]=%p PEB[0x78]=%p\n",
                            (void*)peb[12], (void*)peb[13], (void*)peb[14], (void*)peb[15]);
                        /* Dump PEB->Ldr (PEB+0x18) if it looks valid */
                        uint64_t ldr_addr = peb[3]; /* PEB[0x18] */
                        ERR("  PEB->Ldr = %p\n", (void*)ldr_addr);
                        if (ldr_addr > 0x10000)
                        {
                            uint64_t *ldr = (uint64_t *)ldr_addr;
                            ERR("  LDR[0x00]=%p LDR[0x08]=%p LDR[0x10]=%p LDR[0x18]=%p\n",
                                (void*)ldr[0], (void*)ldr[1], (void*)ldr[2], (void*)ldr[3]);
                            ERR("  LDR[0x20]=%p LDR[0x28]=%p LDR[0x30]=%p LDR[0x38]=%p\n",
                                (void*)ldr[4], (void*)ldr[5], (void*)ldr[6], (void*)ldr[7]);
                        }
                        else
                        {
                            ERR("  PEB->Ldr is INVALID (0x%lx)!\n", (unsigned long)ldr_addr);
                        }
                    }
                }
            }
            if (fault_repeat_count >= 5)
            {
                ERR("SEGV LOOP FATAL: pc=%p addr=%p after %d repeats, forcing thread exit\n",
                    (void*)this_pc, siginfo->si_addr, fault_repeat_count);
                /* Skip the faulting instruction and set return value to indicate failure */
                PC_sig(context) = PC_sig(context) + 4;
                REGn_sig(0, context) = 0xDEAD0001;
                ios_fixup_x18_for_return( context );
                last_fault_pc = 0;
                fault_repeat_count = 0;
                return;
            }
        }
        else
        {
            last_fault_pc = this_pc;
            fault_repeat_count = 1;
        }
    }
#endif
#ifdef WINE_IOS
    /* ml938: an access to a sub-floor image window -- a mapping iOS refuses to
     * let us create, emulated instead. Checked BEFORE virtual_handle_fault
     * because the gate cannot collide with anything: the address is below 4GB,
     * and nothing in this task -- Wine view, FEX arena, JIT pool or foreign
     * mmap -- can be mapped there at all. An encoding we do not recognise
     * falls straight through to the path below, unchanged. */
    {
        extern void *ios_jit_rx_base_global;
        extern size_t ios_jit_pool_size_global;
        uintptr_t sg_pc = (uintptr_t)PC_sig(context);
        uintptr_t sg_rx = (uintptr_t)ios_jit_rx_base_global;
        size_t sg_sz = ios_jit_pool_size_global;

        /* ml939: only for a NON-pool PC. A pool PC has to resume through the
         * x18 trampoline, which clobbers x17 = FEX's callret stack pointer, so
         * servicing it here would trade a clean fault for silent FEX-state
         * corruption -- measured in ml938. Those come through the Mach handler
         * instead, which sets thread state directly. */
        if (!(sg_rx && sg_pc >= sg_rx && sg_pc < sg_rx + sg_sz) &&
            !ios_jit_low_contains( sg_pc ) &&   /* madeira-bcd pool-low: region C is a pool PC too */
            ios_subfloor_service( context, siginfo->si_addr, "segv", ios_jit_current_peb() ))
        {
            PC_sig(context) = PC_sig(context) + 4;
            ios_fixup_x18_for_return( context );
            return;
        }
    }
#endif
    if (!virtual_handle_fault( &rec, (void *)SP_sig(context) ))
    {
#ifdef WINE_IOS
        ERR("virtual_handle_fault HANDLED addr=%p\n", siginfo->si_addr);
        ios_fixup_x18_for_return( context );
#endif
        return;
    }
    if (handle_syscall_fault( context, &rec ))
    {
#ifdef WINE_IOS
        ios_fixup_x18_for_return( context );
#endif
        return;
    }
#ifdef WINE_IOS
    ERR("setup_exception for SEGV at pc=%p addr=%p (virtual_handle_fault failed)\n",
        (void*)PC_sig(context), siginfo->si_addr);
    /* Steam S3 (task #29): name the native faulting code + the target
     * memory region so the unhandled-write fault is diagnosable. */
    {
        extern void ios_dump_fault_region( void *addr );
        Dl_info di;
        uint64_t pcv = (uint64_t)PC_sig(context);
        if (dladdr( (void *)(uintptr_t)pcv, &di ) && di.dli_fname)
            dprintf( 2, "[fault-pc] pc=%p = %s`%s+0x%llx (img base %p, slide-relative)\n",
                     (void *)(uintptr_t)pcv, di.dli_fname,
                     di.dli_sname ? di.dli_sname : "?",
                     (unsigned long long)(pcv - (uint64_t)(uintptr_t)(di.dli_saddr ? di.dli_saddr : di.dli_fbase)),
                     di.dli_fbase );
        ios_dump_fault_region( siginfo->si_addr );
    }
#endif
    setup_exception( context, &rec );
}


