/* Part of signal_arm64_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. The all-thread stack sampler and other diagnostics. Same copyright and licence as signal_arm64_ios.c. */
/* ============================================================ *
 * [thread-stacks] all-thread stack sampler — diagnoses wedged wine
 * threads (S2: explorer main leaves its message pump and blocks
 * forever; [srv-queues] showed wake_mask=0 with 20 posted messages
 * pending). Called from an app-side GCD timer (Winios.m) so it keeps
 * firing even when every wine thread is stuck. Samples WITHOUT
 * suspending — racy pc/fp reads are acceptable for stuck-thread
 * triage; a blocked thread's state is stable anyway.
 * ============================================================ */
/* Best-effort PE module name from the export directory at pe_base (the
 * original unix-view image stays mapped). Returns "(exe)" for images
 * without exports, "?" when headers look wrong. */
/* ml347: FAULT-SAFE. This runs on the Mach exception handler thread while a
 * module may be mid-load (PE pages unreadable). The old raw derefs nested-
 * faulted the handler thread inside its own dump loop — no reply ever sent,
 * original faulting thread parked (ml345) or the debugger killed the app
 * (ml346). Every read goes through mach_vm_read_overwrite. */
static const char *ios_pe_module_name( uint64_t base )
{
    static char namebuf[64];   /* single exception-handler thread only */
    unsigned char hdr[2];
    uint32_t e_lfanew = 0, pe_sig = 0, exp_rva = 0, name_rva = 0;
    mach_vm_size_t got = 0;
    uint64_t name_addr, page_left, want;

    if (!base) return "?";
    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)base, 2,
                               (mach_vm_address_t)hdr, &got) != KERN_SUCCESS || got != 2)
        return "?";
    if (hdr[0] != 'M' || hdr[1] != 'Z') return "?";
    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(base + 0x3c), 4,
                               (mach_vm_address_t)&e_lfanew, &got) != KERN_SUCCESS || got != 4)
        return "?";
    if (e_lfanew == 0 || e_lfanew > 0x1000) return "?";
    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(base + e_lfanew), 4,
                               (mach_vm_address_t)&pe_sig, &got) != KERN_SUCCESS || got != 4)
        return "?";
    if (pe_sig != 0x00004550) return "?";
    /* ml998: THE EXPORT DIRECTORY IS NOT AT THE SAME OFFSET IN PE32 AND PE32+.
     *
     * This read was hardcoded to e_lfanew+0x88, which is IMAGE_NT_HEADERS64's
     * DataDirectory[0] (OptionalHeader at +0x18, DataDirectory at +0x70).  In a
     * 32-bit image OptionalHeader32 puts DataDirectory at +0x60, so the export
     * directory is at e_lfanew+0x78 and +0x88 is DataDirectory[2] -- RESOURCE.
     * `exp_rva' was therefore the resource RVA, `name_rva' was read from offset
     * 0x0c of IMAGE_RESOURCE_DIRECTORY (NumberOfNamedEntries | NumberOfIdEntries
     * << 16, a small plausible-looking number that passes the range check), and
     * the "name" was 63 arbitrary bytes from that address.
     *
     * That is where the profiler's `Zx' and `PnQ' modules came from: r76 line
     * 6858 reports `jit by module: Zx=42.4% ... Zx=0.2%' -- the same two-letter
     * garbage twice, for two different images, at 21-44 % of all CPU.  Both are
     * 32-bit guest DLLs that the MZ probe had to name because they loaded after
     * the one-shot loader walk (see ios_gmod32_build).  SizeOfImage happens to
     * sit at +0x50 in BOTH layouts, which is why ios_gmod32_probe's own reads
     * were right and only the name was wrong.
     *
     * Pick the layout from OptionalHeader.Magic, the field that exists to say
     * which one it is. */
    {
        unsigned short magic = 0;
        uint32_t ddir_off;
        if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(base + e_lfanew + 0x18), 2,
                                   (mach_vm_address_t)&magic, &got) != KERN_SUCCESS || got != 2)
            return "?";
        if (magic == 0x010b) ddir_off = 0x78;        /* PE32  */
        else if (magic == 0x020b) ddir_off = 0x88;   /* PE32+ */
        else return "?";
        if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(base + e_lfanew + ddir_off), 4,
                                   (mach_vm_address_t)&exp_rva, &got) != KERN_SUCCESS || got != 4)
            return "?";
    }
    if (!exp_rva || exp_rva > 0x10000000) return "(exe)";
    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)(base + exp_rva + 0x0c), 4,
                               (mach_vm_address_t)&name_rva, &got) != KERN_SUCCESS || got != 4)
        return "(exe)";
    if (!name_rva || name_rva > 0x10000000) return "(exe)";
    /* Clamp the name read to the containing page so a mapped name page next
     * to an unmapped one doesn't fail the whole read. */
    name_addr = base + name_rva;
    page_left = 0x4000 - (name_addr & 0x3fff);
    want = sizeof(namebuf) - 1;
    if (want > page_left) want = page_left;
    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)name_addr, want,
                               (mach_vm_address_t)namebuf, &got) != KERN_SUCCESS || got == 0)
        return "(exe)";
    namebuf[got < sizeof(namebuf) ? got : sizeof(namebuf) - 1] = 0;
    namebuf[sizeof(namebuf) - 1] = 0;
    return namebuf;
}

/* ============================================================================
 * ml686 WAIT-CHAIN SNAPSHOT
 *
 * ml685 established that ONE Unity job worker sits at 100% CPU in a ~256-byte
 * loop for an entire run (34 of 35 samples, run_state=1 every time), polling a
 * word that holds its own address, while the render thread and DXMT's encoder
 * both wait. Memory, GPU sequence lag, the fault storm and compressor thrash
 * were each measured and eliminated as the cause of the ~1s frame gap.
 *
 * A spinning consumer is most likely a SYMPTOM: the interesting thread is
 * whichever producer should be filling that queue and isn't. A list of PCs
 * cannot show that -- an EDGE can ("render thread waits on object A, whose
 * owner is worker B"). So capture every thread at three points spanning a
 * frame period and record what each one is waiting ON, not just where it is.
 *
 * Runs from the sampler thread, never from a Mach exception handler, and never
 * suspends anything: reads are racy-but-stable for blocked threads, which is
 * exactly the population of interest. */
/* ============================================================================
 * ml688 NATIVE JIT RIP RESOLVER
 *
 * ml686 named the failure honestly: "callback NOT INSTALLED". The obvious move
 * -- arm ios_fex_rip_resolved -- is a TRAP. virtual_ios.c records that pointer
 * for DIAGNOSTICS ONLY and carries an explicit ml614 warning against arming it:
 * BTCpu64IosRipFromHostPC is an ARM64EC **PE** export, so a native `blr` fetches
 * its x64 entry thunk as ARM64 instructions. ml613 armed it and crashed every
 * launch. Arming it now would simply reproduce that.
 *
 * So resolve the RIP natively instead. FEX appends a host-PC -> guest-RIP table
 * to every JIT block (vl64pair entries in the block tail); this walks the same
 * table with our own decoder, reading everything through mach_vm_read_overwrite
 * so a corrupt header cannot fault the sampler.
 *
 * The decoder was validated OFFLINE against FEXCore's own Encode/Decode over
 * 18,919 cases spanning all four encodings -- 0 mismatches -- before shipping.
 * Returns 0 for "no answer"; *why gets the specific reason. */
struct ios_vlpair { uint64_t arm, rip; unsigned size; };

static struct ios_vlpair ios_vl64pair_decode( const uint8_t *d )
{
    struct ios_vlpair o;
    if ((d[0] >> 7) == 0)                        /* vl8 */
    {
        o.arm = ((uint64_t)(d[0] & 0xF) + 1) << 2;
        o.rip = (uint64_t)((d[0] >> 4) & 0x7) + 1;
        o.size = 1;
    }
    else if ((d[0] >> 6) == 0x2)                 /* vl16 */
    {
        int64_t rip6 = (int64_t)(int8_t)((d[0] & 0x3F) << 2) >> 2;   /* sign-extend 6 */
        o.arm = (uint64_t)(((int64_t)(int8_t)d[1]) << 2);
        o.rip = (uint64_t)rip6;
        o.size = 2;
    }
    else if (d[0] == 0xC0)                       /* vl32 */
    {
        int32_t a, r;
        memcpy( &a, d + 1, 4 ); memcpy( &r, d + 5, 4 );
        o.arm = (uint64_t)(int64_t)a; o.rip = (uint64_t)(int64_t)r; o.size = 9;
    }
    else                                          /* vl64 */
    {
        memcpy( &o.arm, d + 1, 8 ); memcpy( &o.rip, d + 9, 8 );
        o.size = 17;
    }
    return o;
}

uint64_t ios_native_rip_from_hostpc( uint64_t block_begin, uint64_t host_pc, const char **why )
{
    uint32_t off_tail = 0;
    struct { uint64_t size; uint64_t rip; uint64_t guest_size;
             uint32_t n_entries; uint32_t off_entries; } tail;
    mach_vm_size_t got = 0;
    uint8_t tab[512];
    uint64_t cur_host, cur_rip, tab_addr;
    uint32_t i, pos = 0;

    if (why) *why = "ok";
    if (!block_begin) { if (why) *why = "BlockBegin==0"; return 0; }

    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)block_begin,
            sizeof(off_tail), (mach_vm_address_t)&off_tail, &got ) != KERN_SUCCESS ||
        got != sizeof(off_tail))
    { if (why) *why = "header unreadable"; return 0; }

    if (off_tail < 4 || off_tail > (64u << 20))
    { if (why) *why = "OffsetToBlockTail implausible"; return 0; }

    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(block_begin + off_tail),
            sizeof(tail), (mach_vm_address_t)&tail, &got ) != KERN_SUCCESS || got != sizeof(tail))
    { if (why) *why = "tail unreadable"; return 0; }

    if (!tail.size || tail.size > (64u << 20))
    { if (why) *why = "block Size implausible"; return 0; }
    if (host_pc < block_begin || host_pc >= block_begin + tail.size)
    { if (why) *why = "hostPC outside block"; return 0; }
    if (tail.n_entries > 65536)
    { if (why) *why = "NumberOfRIPEntries implausible"; return 0; }

    tab_addr = block_begin + off_tail + tail.off_entries;
    cur_host = block_begin;
    cur_rip  = tail.rip;
    if (!tail.n_entries) { if (why) *why = "no RIP entries (block entry RIP)"; return cur_rip; }

    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)tab_addr,
            sizeof(tab), (mach_vm_address_t)tab, &got ) != KERN_SUCCESS || got < 32)
    { if (why) *why = "RIP table unreadable"; return 0; }

    for (i = 0; i < tail.n_entries; i++)
    {
        struct ios_vlpair e;
        if (pos + 17 > (uint32_t)got)
        {
            /* ml875: the table can exceed one 512-byte window; ml688 silently
             * stopped here and returned a PARTIAL RIP. Slide the window. */
            tab_addr += pos; pos = 0; got = 0;
            if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)tab_addr,
                    sizeof(tab), (mach_vm_address_t)tab, &got ) != KERN_SUCCESS || got < 17)
            { if (why) *why = "RIP table truncated"; return 0; }
        }
        e = ios_vl64pair_decode( tab + pos );
        pos += e.size;
        if (host_pc >= cur_host + e.arm) { cur_host += e.arm; cur_rip += e.rip; }
        else break;
    }
    return cur_rip;
}

static const char *ios_wait_api_name( uint64_t pc, const char *sym )
{
    if (!sym) return "?";
    /* the handful of primitives every Wine/Unity wait bottoms out in */
    if (strstr(sym, "__ulock_wait"))        return "ulock_wait(futex)";
    if (strstr(sym, "semaphore_wait"))      return "semaphore_wait";
    if (strstr(sym, "semaphore_timedwait")) return "semaphore_timedwait";
    if (strstr(sym, "__psynch_cvwait"))     return "cond_wait";
    if (strstr(sym, "__psynch_mutexwait"))  return "mutex_wait";
    if (strstr(sym, "read"))                return "read(wineserver)";
    if (strstr(sym, "select") || strstr(sym, "poll")) return "select/poll";
    if (strstr(sym, "mach_msg"))            return "mach_msg";
    if (strstr(sym, "kevent"))              return "kevent";
    return sym;
}

/* ============================================================================
 * ml689 GUEST MODULE MAP
 *
 * ml688's native resolver produced real guest RIPs (0x71fbdfef51 and friends)
 * but nothing could NAME them: the ios_jit_mappings table holds the ARM64EC PE
 * copies FEX made, not the x64 guest modules. So the hottest guest code in the
 * app stayed an anonymous address.
 *
 * Walk the guest loader list instead -- TEB->PEB->Ldr->InLoadOrderModuleList --
 * so every guest RIP resolves to Module+RVA and can be disassembled offline
 * against the file on the phone prefix. All reads bounded and fault-safe. */
#define IOS_GMOD_MAX 192
static struct { uint64_t base, size; char name[52]; } ios_gmods[IOS_GMOD_MAX];
static int ios_gmod_count = 0;

static void ios_guest_modmap_build( uint64_t teb )
{
    uint64_t peb = 0, ldr = 0, head, cur;
    mach_vm_size_t g = 0;
    int guard = 0;

    if (ios_gmod_count || !teb) return;
    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(teb + 0x60), 8,
                                (mach_vm_address_t)&peb, &g ) != KERN_SUCCESS || g != 8 || !peb) return;
    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(peb + 0x18), 8,
                                (mach_vm_address_t)&ldr, &g ) != KERN_SUCCESS || g != 8 || !ldr) return;

    head = ldr + 0x10;                       /* InLoadOrderModuleList */
    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)head, 8,
                                (mach_vm_address_t)&cur, &g ) != KERN_SUCCESS || g != 8) return;

    while (cur && cur != head && guard++ < IOS_GMOD_MAX && ios_gmod_count < IOS_GMOD_MAX)
    {
        uint64_t dllbase = 0, next = 0;
        uint32_t imgsize = 0;
        uint16_t nlen = 0;
        uint64_t nbuf = 0;

        /* LDR_DATA_TABLE_ENTRY (x64): DllBase +0x30, SizeOfImage +0x40,
         * BaseDllName UNICODE_STRING +0x58 (Length +0x58, Buffer +0x60) */
        if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cur + 0x30), 8,
                                    (mach_vm_address_t)&dllbase, &g ) != KERN_SUCCESS || g != 8) break;
        if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cur + 0x40), 4,
                                    (mach_vm_address_t)&imgsize, &g ) != KERN_SUCCESS || g != 4) break;
        mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cur + 0x58), 2,
                                (mach_vm_address_t)&nlen, &g );
        mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cur + 0x60), 8,
                                (mach_vm_address_t)&nbuf, &g );

        if (dllbase && imgsize && imgsize < (512u << 20))
        {
            char nm[52]; unsigned k, n = nlen / 2;
            memset( nm, 0, sizeof(nm) );
            if (n > sizeof(nm) - 1) n = sizeof(nm) - 1;
            for (k = 0; k < n && nbuf; k++)
            {
                uint16_t wc = 0;
                if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(nbuf + k * 2), 2,
                                            (mach_vm_address_t)&wc, &g ) != KERN_SUCCESS) break;
                nm[k] = (wc < 0x80) ? (char)wc : '?';
            }
            ios_gmods[ios_gmod_count].base = dllbase;
            ios_gmods[ios_gmod_count].size = imgsize;
            memcpy( ios_gmods[ios_gmod_count].name, nm, sizeof(nm) - 1 );
            ios_gmod_count++;
        }
        if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)cur, 8,
                                    (mach_vm_address_t)&next, &g ) != KERN_SUCCESS || g != 8) break;
        cur = next;
    }

    if (ios_gmod_count)
    {
        int i;
        fprintf(stderr, "[modmap] ml689 %d guest modules\n", ios_gmod_count);
        for (i = 0; i < ios_gmod_count; i++)
            fprintf(stderr, "[modmap]   0x%llx +0x%llx  %s\n",
                    (unsigned long long)ios_gmods[i].base,
                    (unsigned long long)ios_gmods[i].size, ios_gmods[i].name);
    }
}

static const char *ios_guest_module_for( uint64_t rip, uint64_t *rva )
{
    int i;
    for (i = 0; i < ios_gmod_count; i++)
        if (rip >= ios_gmods[i].base && rip < ios_gmods[i].base + ios_gmods[i].size)
        {
            if (rva) *rva = rip - ios_gmods[i].base;
            return ios_gmods[i].name;
        }
    if (rva) *rva = rip;
    return NULL;
}

/* ============================================================================
 * ml688 BOUNDED ALL-THREAD PROFILE
 *
 * Every FPS theory so far was chosen by picking a suspicious thread and arguing
 * from it; each was refuted by measurement (fault storm 24% of a core, GPU lag
 * 1-2, compressor thrash predated by the spin, buffer retention fixed with no
 * FPS change, lost wakeups 550/550 healthy). DXMT accounts for ~10-12ms and
 * Present is nearly free, so 900-1500ms per frame is unaccounted for.
 *
 * Stop selecting suspects and measure the remainder: sample EVERY thread for a
 * bounded window, resolve JIT PCs to exact guest RIPs natively, and aggregate.
 * Waiting threads are counted separately by wait API so "asleep" is never
 * confused with "busy". */
#define IOS_PROF_BUCKETS 96
#define IOS_PROF_SAMPLES 400

void ios_cpu_profile( const char *why, int ms_total )
{
    struct { char name[40]; uint64_t rip; uint64_t hostpc; unsigned port;
             unsigned running; unsigned waiting; } b[IOS_PROF_BUCKETS];
    unsigned nb = 0, iter, total_run = 0, total_wait = 0, resolved = 0, unresolved = 0;
    const int period_us = 2000;                      /* 500 Hz */
    int iters = ms_total * 1000 / period_us;
    if (iters > IOS_PROF_SAMPLES) iters = IOS_PROF_SAMPLES;
    memset( b, 0, sizeof(b) );

    for (iter = 0; iter < (unsigned)iters; iter++)
    {
        thread_act_array_t th;
        mach_msg_type_number_t cnt = 0, i;
        thread_t self = mach_thread_self();

        if (task_threads( mach_task_self(), &th, &cnt ) != KERN_SUCCESS) break;
        for (i = 0; i < cnt; i++)
        {
            arm_thread_state64_t st;
            mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
            struct thread_basic_info bi;
            mach_msg_type_number_t bc = THREAD_BASIC_INFO_COUNT;
            char tname[40] = "";
            pthread_t pt;
            uint64_t rip = 0, bb = 0;
            unsigned k;

            if (th[i] == self) continue;
            if (thread_get_state( th[i], ARM_THREAD_STATE64, (thread_state_t)&st, &sc ) != KERN_SUCCESS)
                goto next_thread;
            memset( &bi, 0, sizeof(bi) );
            if (thread_info( th[i], THREAD_BASIC_INFO, (thread_info_t)&bi, &bc ) != KERN_SUCCESS)
                goto next_thread;

            pt = pthread_from_mach_thread_np( th[i] );
            if (pt) pthread_getname_np( pt, tname, sizeof(tname) );

            if (st.__x[18] > 0x10000 && !(st.__x[18] & 0xfff))
                ios_guest_modmap_build( st.__x[18] );          /* ml689: once */

            if (bi.run_state != TH_STATE_RUNNING) { total_wait++; }
            else
            {
                mach_vm_size_t g = 0;
                total_run++;
                if (st.__x[28] > 0x10000 &&
                    mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)st.__x[28], 8,
                                            (mach_vm_address_t)&bb, &g ) == KERN_SUCCESS && g == 8 && bb)
                {
                    extern uint64_t ios_native_rip_from_hostpc( uint64_t, uint64_t, const char ** );
                    rip = ios_native_rip_from_hostpc( bb, st.__pc, NULL );
                    if (rip) resolved++; else unresolved++;
                }
            }

            /* bucket by (thread name, guest RIP) so the report names a function,
             * not just a thread */
            /* ml690 PROFILER BUG: the key was (name, rip). Every UNNAMED native
             * thread has name=="" and rip==0, so they all collapsed into ONE
             * bucket -- ml689's "duty 171/400 port=0x103" was an aggregate of
             * several threads wearing the port of whichever created the bucket,
             * not one thread at 43%. Key by MACH PORT, which is unique. */
            for (k = 0; k < nb; k++)
                if (b[k].port == (unsigned)th[i] && b[k].rip == rip) break;
            if (k == nb && nb < IOS_PROF_BUCKETS)
            {
                memcpy( b[nb].name, tname, sizeof(b[nb].name) - 1 );
                b[nb].port = th[i];   /* wine poisons strncpy */
                b[nb].name[sizeof(b[nb].name) - 1] = 0;
                b[nb].rip = rip; b[nb].hostpc = st.__pc; b[nb].port = th[i]; nb++;
            }
            if (k < IOS_PROF_BUCKETS)
            {
                if (bi.run_state == TH_STATE_RUNNING) b[k].running++;
                else b[k].waiting++;
            }
next_thread:
            mach_port_deallocate( mach_task_self(), th[i] );
        }
        vm_deallocate( mach_task_self(), (vm_address_t)th, cnt * sizeof(thread_t) );
        usleep( period_us );
    }

    fprintf(stderr, "[cpu-prof] ml688 why=%s window=%dms iters=%u  running-samples=%u waiting-samples=%u "
                    "| guestRIP resolved=%u unresolved=%u\n",
            why, ms_total, iter, total_run, total_wait, resolved, unresolved);
    {   /* top buckets by RUNNING samples -- where CPU time actually went */
        unsigned rank, shown[16], ns = 0;
        for (rank = 0; rank < 16; rank++)
        {
            unsigned best = ~0u, bestv = 0, k, q; int dup;
            for (k = 0; k < nb; k++)
            {
                for (dup = 0, q = 0; q < ns; q++) if (shown[q] == k) dup = 1;
                if (dup) continue;
                if (b[k].running > bestv) { bestv = b[k].running; best = k; }
            }
            if (best == ~0u || !bestv) break;
            shown[ns++] = best;
            {
                uint64_t rva = 0;
                const char *mod = b[best].rip ? ios_guest_module_for( b[best].rip, &rva ) : NULL;
                /* ml689: percentages are shares of RUNNING SAMPLES. Also print
                 * running/iters, which is the thread's runnable duty over the
                 * window -- the number that converts to "about N cores". */
                fprintf(stderr, "[cpu-prof]   %5.1f%% of running (duty %u/%u) \"%s\" port=0x%x "
                                "guest=%s+0x%llx rip=0x%llx hostPC=0x%llx\n",
                        total_run ? (100.0 * b[best].running / total_run) : 0.0,
                        b[best].running, (unsigned)iter, b[best].name, b[best].port,
                        mod ? mod : "?", (unsigned long long)rva,
                        (unsigned long long)b[best].rip, (unsigned long long)b[best].hostpc);
                if (rank < 3 && b[best].rip)
                {   /* the guest x86 at the hottest sites -- disassemble offline */
                    uint8_t gb[48]; mach_vm_size_t gg = 0;
                    if (mach_vm_read_overwrite( mach_task_self(),
                            (mach_vm_address_t)(b[best].rip & ~0xfULL), sizeof(gb),
                            (mach_vm_address_t)gb, &gg ) == KERN_SUCCESS && gg == sizeof(gb))
                    {
                        char hx[160]; int q;
                        for (q = 0; q < 48; q++) snprintf( hx + q * 3, 4, "%02x ", gb[q] );
                        fprintf(stderr, "[cpu-prof]     x86 @0x%llx: %s\n",
                                (unsigned long long)(b[best].rip & ~0xfULL), hx);
                    }
                }
            }
        }
    }
}

void ios_wait_chain_snapshot( const char *why )
{
    int round;
    for (round = 0; round < 3; round++)
    {
        thread_act_array_t th;
        mach_msg_type_number_t cnt = 0, i;
        thread_t self = mach_thread_self();
        const int delay_ms = (round == 0) ? 0 : (round == 1 ? 100 : 900);

        if (delay_ms) usleep( delay_ms * 1000 );
        if (task_threads( mach_task_self(), &th, &cnt ) != KERN_SUCCESS) return;

        fprintf(stderr, "[wait-chain] ml686 ==== round %d (t=+%dms) why=%s threads=%u ====\n",
                round, round == 0 ? 0 : (round == 1 ? 100 : 1000), why, cnt);

        for (i = 0; i < cnt; i++)
        {
            arm_thread_state64_t st;
            mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
            struct thread_basic_info bi;
            mach_msg_type_number_t bc = THREAD_BASIC_INFO_COUNT;
            char tname[64] = "";
            pthread_t pt;
            Dl_info di;
            const char *img = "?", *sym = NULL;
            uint64_t off = 0;

            if (th[i] == self) continue;
            if (thread_get_state( th[i], ARM_THREAD_STATE64, (thread_state_t)&st, &sc ) != KERN_SUCCESS)
                continue;
            memset( &bi, 0, sizeof(bi) );
            if (thread_info( th[i], THREAD_BASIC_INFO, (thread_info_t)&bi, &bc ) != KERN_SUCCESS)
            { bi.run_state = -1; bi.cpu_usage = -1; }

            pt = pthread_from_mach_thread_np( th[i] );
            if (pt) pthread_getname_np( pt, tname, sizeof(tname) );

            off = st.__pc;
            if (dladdr( (void *)(uintptr_t)st.__pc, &di ))
            {
                if (di.dli_fname) { img = strrchr(di.dli_fname, '/'); img = img ? img + 1 : di.dli_fname; }
                if (di.dli_sname) { sym = di.dli_sname; off = st.__pc - (uint64_t)(uintptr_t)di.dli_saddr; }
            }

            /* Only blocked threads carry a meaningful wait target; a RUNNING
             * thread's x0/x1 are just whatever it is computing. */
            if (bi.run_state == TH_STATE_RUNNING)
            {
                uint64_t bb = 0; mach_vm_size_t g = 0;
                if (st.__x[28] > 0x10000)
                    mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)st.__x[28], 8,
                                            (mach_vm_address_t)&bb, &g );
                fprintf(stderr, "[wait-chain]   RUNNING  \"%s\" cpu=%d pc=%s`%s+0x%llx BlockBegin=0x%llx\n",
                        tname, bi.cpu_usage, img, sym ? sym : "?",
                        (unsigned long long)off, (unsigned long long)bb);
            }
            else
            {
                /* x0..x3 are the wait arguments at the syscall boundary: for
                 * ulock_wait x1 is the address contended, for read x0 is the fd,
                 * for semaphore_wait x0 is the port. Print the object AND a
                 * peek at it, so an owner word is visible where one exists. */
                uint64_t obj = st.__x[1], peek = 0; mach_vm_size_t g = 0;
                int havepeek = (obj > 0x10000 && !(obj & 7) &&
                                mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)obj, 8,
                                                        (mach_vm_address_t)&peek, &g ) == KERN_SUCCESS && g == 8);
                fprintf(stderr, "[wait-chain]   WAIT     \"%s\" cpu=%d run=%d api=%s "
                                "x0=0x%llx obj/x1=0x%llx%s%016llx x2=0x%llx x3=0x%llx pc=%s`%s+0x%llx\n",
                        tname, bi.cpu_usage, bi.run_state, ios_wait_api_name( st.__pc, sym ),
                        (unsigned long long)st.__x[0], (unsigned long long)obj,
                        havepeek ? " val=" : " val=?", (unsigned long long)peek,
                        (unsigned long long)st.__x[2], (unsigned long long)st.__x[3],
                        img, sym ? sym : "?", (unsigned long long)off);
            }
            mach_port_deallocate( mach_task_self(), th[i] );
        }
        vm_deallocate( mach_task_self(), (vm_address_t)th, cnt * sizeof(thread_t) );
    }
}

void ios_dump_all_thread_stacks(void)
{
    thread_act_array_t threads;
    mach_msg_type_number_t count = 0, i;
    thread_t self = mach_thread_self();

    if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS) return;
    fprintf(stderr, "[thread-stacks] ---- %u threads ----\n", count);
    for (i = 0; i < count; i++)
    {
        arm_thread_state64_t st;
        mach_msg_type_number_t st_count = ARM_THREAD_STATE64_COUNT;
        char tname[64] = "";
        pthread_t pt;
        Dl_info di;
        const char *img = "?", *sym = "?";
        uint64_t off, fp_walk;
        int fr;

        if (threads[i] == self) goto next;
        if (thread_get_state(threads[i], ARM_THREAD_STATE64, (thread_state_t)&st, &st_count) != KERN_SUCCESS)
            goto next;

        pt = pthread_from_mach_thread_np(threads[i]);
        if (pt) pthread_getname_np(pt, tname, sizeof(tname));

        off = st.__pc;
        if (dladdr((void*)(uintptr_t)st.__pc, &di))
        {
            if (di.dli_fname) { img = strrchr(di.dli_fname, '/'); img = img ? img + 1 : di.dli_fname; }
            if (di.dli_sname) { sym = di.dli_sname; off = st.__pc - (uint64_t)(uintptr_t)di.dli_saddr; }
        }
        /* iOS-Madeira ml417 (#68): a pc alone can't tell "blocked in a wait"
         * from "stopped dead" from "spinning in a fault-retry loop".  ml417
         * showed FOUR threads (steam.exe's main among them, mid-DllMain of
         * steamclient64) sampled 37x at __wine_syscall_dispatcher+0xa8 —
         * `ldr x16,[x18,#0x370]`, which BLOCKS ON NOTHING.  run_state +
         * suspend_count separate the three cases outright, and at that exact
         * pc x8 still holds the wine syscall id and x18 the TEB, so the
         * blocked/looping syscall names itself. */
        {
            struct thread_basic_info bi;
            mach_msg_type_number_t bcnt = THREAD_BASIC_INFO_COUNT;
            memset(&bi, 0, sizeof(bi));
            if (thread_info(threads[i], THREAD_BASIC_INFO, (thread_info_t)&bi, &bcnt) != KERN_SUCCESS)
            {
                bi.run_state = -1;
                bi.suspend_count = -1;
            }
            /* Is the TEB word this pc dereferences (syscall table at TEB+0x370)
             * actually readable?  If not, the thread is fault-looping/parked on
             * an unmapped TEB rather than waiting on anything. */
            char tebstate[40] = "";
            if (st.__x[18] > 0x10000 && !(st.__x[18] & 0xfff))
            {
                uint64_t w = 0;
                mach_vm_size_t g = 0;
                /* ml585: also resolve the WINE TID from TEB->ClientId
                 * .UniqueThread (TEB+0x48). Without it every stack is keyed
                 * only by Mach port, and correlating a sample with
                 * [srv-queues]/[srv-stuck] means hunting for an unrelated
                 * line that happens to print both — which is exactly the
                 * detour that cost time on ml584. */
                uint64_t wtid = 0;
                mach_vm_size_t g2 = 0;
                int have_wtid = (mach_vm_read_overwrite(mach_task_self(),
                        (mach_vm_address_t)(st.__x[18] + 0x48), 8,
                        (mach_vm_address_t)&wtid, &g2) == KERN_SUCCESS && g2 == 8);
                if (mach_vm_read_overwrite(mach_task_self(),
                        (mach_vm_address_t)(st.__x[18] + 0x370), 8,
                        (mach_vm_address_t)&w, &g) == KERN_SUCCESS && g == 8)
                    snprintf(tebstate, sizeof(tebstate), " teb=0x%llx wtid=%04llx teb+370=0x%llx",
                             (unsigned long long)st.__x[18],
                             have_wtid ? (unsigned long long)wtid : 0ull,
                             (unsigned long long)w);
                else
                    snprintf(tebstate, sizeof(tebstate), " teb=0x%llx wtid=%04llx teb+370=UNREADABLE",
                             (unsigned long long)st.__x[18],
                             have_wtid ? (unsigned long long)wtid : 0ull);
            }
            fprintf(stderr, "[thread-stacks] port=0x%x \"%s\" pc=%s`%s+0x%llx run=%d susp=%d "
                    "cpu=%d x8=0x%llx x18=0x%llx sp=0x%llx%s\n",
                    threads[i], tname, img, sym, (unsigned long long)off,
                    bi.run_state, bi.suspend_count, bi.cpu_usage,
                    (unsigned long long)st.__x[8], (unsigned long long)st.__x[18],
                    (unsigned long long)arm_thread_state64_get_sp(st), tebstate);

            /* ================= ml677 SPIN SNAPSHOT =========================
             *
             * ml676 sampled "Background Job.Worker 1" 43 times out of 44 at
             * cpu 989-1000 with its pc confined to a 256-byte window
             * (0x133a9c7b4-0x133a9c8b4) and x8 invariant at 0x70340c2ce8 --
             * from cycle 104 (phys 1350MB) right through to cycle 2577
             * (4026MB). It spins the ENTIRE run and starts long before memory
             * gets tight, so memory pressure cannot be the cause. A pc alone
             * cannot say what the loop is; the instructions can.
             *
             * Fires once per thread, only after the SAME 4KB pc window has
             * been seen at high cpu MIN_HITS times, so a merely busy thread
             * never trips it and the cost is paid once.
             *
             * DISCIPLINE (ml613 died on exactly this): do NOT call any
             * ARM64EC PE export from here -- no RIP-reconstruction helper, no
             * FEX entry point. Capture NATIVE facts only, every read through
             * mach_vm_read_overwrite so a bad pointer cannot nest-fault this
             * handler thread. FEX keeps the guest CPU state pointer in x28,
             * so BlockBegin (x28+0) and State.rip (x28+0x18) are plain loads
             * we can validate before trusting. */
            if (bi.cpu_usage >= 900 && bi.run_state == TH_STATE_RUNNING)
            {
                /* ml728: MIN_HITS 4 -> 2. The spinner we are chasing was sampled only
                 * THREE times in a ten-minute run -- always at the same pc and cpu>=993,
                 * but never enough to satisfy a 4-hit threshold, so the snapshot that
                 * exists precisely for this case never fired. It also alternates with
                 * __ulock_wait2, so it is not continuously runnable and consecutive hits
                 * cannot be relied on. Two hits in one 4KB window at cpu>=900 is still
                 * far beyond anything a merely busy thread reaches, and the capture is
                 * one-shot per thread. */
                enum { SPIN_SLOTS = 8, MIN_HITS = 2 };
                static struct { unsigned port; uint64_t page; unsigned hits; unsigned done; } spin[SPIN_SLOTS];
                uint64_t page = st.__pc & ~0xfffull;
                int si, slot = -1, free_slot = -1;
                for (si = 0; si < SPIN_SLOTS; si++)
                {
                    if (spin[si].port == threads[i]) { slot = si; break; }
                    if (!spin[si].port && free_slot < 0) free_slot = si;
                }
                if (slot < 0 && free_slot >= 0)
                {
                    slot = free_slot;
                    spin[slot].port = threads[i];
                    spin[slot].page = page;
                    spin[slot].hits = 0;
                }
                if (slot >= 0)
                {
                    if (spin[slot].page != page) { spin[slot].page = page; spin[slot].hits = 1; }
                    else spin[slot].hits++;

                    if (spin[slot].hits >= MIN_HITS && !spin[slot].done)
                    {
                        uint32_t insn[128];          /* pc-256 .. pc+256 */
                        mach_vm_size_t got = 0;
                        uint64_t lo = st.__pc - 256;
                        int k;
                        spin[slot].done = 1;

                        /* ml686: the spinner is probably the victim. Capture what
                         * EVERY thread is waiting on, at the same moment, so the
                         * producer that should be feeding it is visible too. */
                        {
                            extern void ios_wait_chain_snapshot( const char * );
                            ios_wait_chain_snapshot( "spin-detected" );
                            {
                                extern void ios_cpu_profile( const char *, int );
                                ios_cpu_profile( "spin-detected", 800 );
                            }
                        }

                        fprintf(stderr, "[spin] ml677 THREAD \"%s\" port=0x%x SPINNING cpu=%d "
                                        "pc=0x%llx sp=0x%llx lr=0x%llx fp=0x%llx (hits=%u in one 4KB window)\n",
                                tname, threads[i], bi.cpu_usage,
                                (unsigned long long)st.__pc,
                                (unsigned long long)arm_thread_state64_get_sp(st),
                                (unsigned long long)st.__lr, (unsigned long long)st.__fp,
                                spin[slot].hits);

                        /* every GP register -- x8/x28 matter most, but an
                         * invariant register anywhere names the loop's input */
                        for (k = 0; k < 29; k += 4)
                            fprintf(stderr, "[spin]   x%-2d=0x%016llx x%-2d=0x%016llx x%-2d=0x%016llx x%-2d=0x%016llx\n",
                                    k,   (unsigned long long)st.__x[k],
                                    k+1, (unsigned long long)(k+1 < 29 ? st.__x[k+1] : 0),
                                    k+2, (unsigned long long)(k+2 < 29 ? st.__x[k+2] : 0),
                                    k+3, (unsigned long long)(k+3 < 29 ? st.__x[k+3] : 0));

                        /* FEX guest state via x28 -- validated, never trusted raw */
                        if (st.__x[28] > 0x10000)
                        {
                            uint64_t blockbegin = 0, griprip = 0;
                            mach_vm_size_t g1 = 0, g2 = 0;
                            int ok1 = (mach_vm_read_overwrite(mach_task_self(),
                                        (mach_vm_address_t)st.__x[28], 8,
                                        (mach_vm_address_t)&blockbegin, &g1) == KERN_SUCCESS && g1 == 8);
                            int ok2 = (mach_vm_read_overwrite(mach_task_self(),
                                        (mach_vm_address_t)(st.__x[28] + 0x18), 8,
                                        (mach_vm_address_t)&griprip, &g2) == KERN_SUCCESS && g2 == 8);
                            /* ml684: State.rip is only synced at BLOCK boundaries, so
                             * it names the calling block, not the spinning
                             * instruction -- ml683's value disassembled to the
                             * instruction after a GetTickCount64 call, nowhere near
                             * the captured atomic loop. Reconstruct the EXACT RIP
                             * from (BlockBegin, host PC) through the pointer
                             * xtajit64 pushes down; gate on the RESOLVED FLAG, never
                             * on the pointer (ml551 blacked out the window by calling
                             * it while it still held ASCII), and never link the EC
                             * export directly (ml613). */
                            {
                                /* ml686: ml684/685 printed a single "UNRESOLVED:0x0" for
                                 * every failure mode, so "the callback was never pushed
                                 * down" and "the walk ran and found nothing" looked
                                 * identical -- a probe that cannot distinguish a missing
                                 * mechanism from a real answer. Split every precondition
                                 * and name the one that failed. */
                                /* ml688: NATIVE walk. Never call the EC export
                                 * (ml613/ml614) -- this decodes the same table. */
                                extern uint64_t ios_native_rip_from_hostpc( uint64_t, uint64_t, const char ** );
                                const char *why = "ok";
                                uint64_t exact = ok1 ? ios_native_rip_from_hostpc( blockbegin, st.__pc, &why ) : 0;
                                if (!ok1) why = "CPUState+0 unreadable (no BlockBegin)";
                                fprintf(stderr, "[spin]   EXACT guest RIP=0x%llx why=%s\n"
                                                "[spin]     BlockBegin=0x%llx hostPC=0x%llx delta=+0x%llx "
                                                "State.rip=0x%llx (block-granular) resolved=%d cb=%p\n",
                                        (unsigned long long)exact, why,
                                        (unsigned long long)blockbegin, (unsigned long long)st.__pc,
                                        (unsigned long long)(st.__pc - blockbegin),
                                        (unsigned long long)griprip, 0, (void *)0);
                                {   /* the JIT block header itself -- extent/entry live here */
                                    uint64_t bh[6]; mach_vm_size_t bg = 0;
                                    if (blockbegin && mach_vm_read_overwrite(mach_task_self(),
                                            (mach_vm_address_t)blockbegin, sizeof(bh),
                                            (mach_vm_address_t)bh, &bg) == KERN_SUCCESS && bg == sizeof(bh))
                                        fprintf(stderr, "[spin]     block hdr: %016llx %016llx %016llx %016llx %016llx %016llx\n",
                                                (unsigned long long)bh[0], (unsigned long long)bh[1],
                                                (unsigned long long)bh[2], (unsigned long long)bh[3],
                                                (unsigned long long)bh[4], (unsigned long long)bh[5]);
                                }
                                if (exact)
                                {   /* the guest bytes at the real RIP name the loop */
                                    uint8_t gb[32];
                                    mach_vm_size_t gg = 0;
                                    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)exact,
                                            sizeof(gb), (mach_vm_address_t)gb, &gg) == KERN_SUCCESS &&
                                        gg == sizeof(gb))
                                    {
                                        char hex[100]; int q;
                                        for (q = 0; q < 32; q++)
                                            snprintf(hex + q * 3, 4, "%02x ", gb[q]);
                                        fprintf(stderr, "[spin]   guest bytes @0x%llx: %s\n",
                                                (unsigned long long)exact, hex);
                                    }
                                }
                            }
                            fprintf(stderr, "[spin]   x28=0x%llx BlockBegin=%s0x%llx State.rip=%s0x%llx\n",
                                    (unsigned long long)st.__x[28],
                                    ok1 ? "" : "UNREADABLE:", (unsigned long long)blockbegin,
                                    ok2 ? "" : "UNREADABLE:", (unsigned long long)griprip);
                            /* ml678: dump the ThreadState head rather than guess where
                             * the guest register file starts. RSP/RBP/the caller chain
                             * are all in here; decoding is free offline, and a wrong
                             * layout guess made on-device costs a whole run. */
                            {
                                uint64_t ts[64];
                                mach_vm_size_t g3 = 0;
                                if (mach_vm_read_overwrite(mach_task_self(),
                                        (mach_vm_address_t)st.__x[28], sizeof(ts),
                                        (mach_vm_address_t)ts, &g3) == KERN_SUCCESS && g3 == sizeof(ts))
                                {
                                    int q;
                                    for (q = 0; q < 64; q += 4)
                                        fprintf(stderr, "[spin]   TS+0x%03x: %016llx %016llx %016llx %016llx\n",
                                                q * 8,
                                                (unsigned long long)ts[q],   (unsigned long long)ts[q+1],
                                                (unsigned long long)ts[q+2], (unsigned long long)ts[q+3]);

                                    /* ======= ml729 [mono-state] NAME THE FATAL TRANSITION =======
                                     *
                                     * Two threads spin forever at libmono+0x2bf5d0 (`eb fe`)
                                     * immediately after Mono logs
                                     *   "Cannot transition thread %p from %s with DONE_BLOCKING"
                                     * Offline disassembly of the call site settles the ABI:
                                     *   1802bf5af  lea  r8, [rip+0xee975]   ; the format string
                                     *   1802bf5b8  mov  edx, 4              ; level
                                     *   1802bf5bd  call monoeg_g_log
                                     * so %p == r9 (thread info) and %s == [rsp+0x20] (the SOURCE
                                     * state name). Naming that state says whether the thread was
                                     * already BLOCKING, in a self-suspend, or in a state our
                                     * suspend machinery invented -- which is the difference
                                     * between a Mono bug and an emulation bug.
                                     *
                                     * WHICH RSP? gregs[REG_RSP] is only SPILLED at block
                                     * boundaries (same limitation that made State.rip name the
                                     * wrong instruction in ml684), while x23 is the SRA RSP and
                                     * is only meaningful where SRA is actually loaded. Neither
                                     * can be trusted blind, so dump BOTH, labelled. The
                                     * disassembly gives a free validator: whichever candidate
                                     * has a printable C string at +0x20 is the live one. */
                                    {
                                        uint64_t cands[2] = { ts[8], st.__x[23] };   /* gregs[4]=RSP, SRA RSP */
                                        const char *cname[2] = { "gregs[RSP]", "x23(SRA)" };
                                        int ci;

                                        fprintf(stderr, "[mono-state] guest args: rcx=0x%llx rdx=0x%llx "
                                                        "r8=0x%llx r9=0x%llx  (rip=0x%llx)\n",
                                                (unsigned long long)ts[5],  (unsigned long long)ts[6],
                                                (unsigned long long)ts[12], (unsigned long long)ts[13],
                                                (unsigned long long)ts[3]);

                                        for (ci = 0; ci < 2; ci++)
                                        {
                                            uint64_t rsp = cands[ci], sv[16];
                                            mach_vm_size_t g4 = 0;
                                            int w;
                                            if (rsp < 0x10000 || (rsp & 7))
                                            {
                                                fprintf(stderr, "[mono-state] %s=0x%llx -- implausible, skipped\n",
                                                        cname[ci], (unsigned long long)rsp);
                                                continue;
                                            }
                                            if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)rsp,
                                                    sizeof(sv), (mach_vm_address_t)sv, &g4) != KERN_SUCCESS ||
                                                g4 != sizeof(sv))
                                            {
                                                fprintf(stderr, "[mono-state] %s=0x%llx -- UNREADABLE\n",
                                                        cname[ci], (unsigned long long)rsp);
                                                continue;
                                            }
                                            for (w = 0; w < 16; w++)
                                            {
                                                char txt[65];
                                                int printable = 0;
                                                /* resolve the slot as a C string when it can be one --
                                                 * this is what names the state, and it is also the
                                                 * validator that says which RSP candidate was live */
                                                if (sv[w] > 0x10000)
                                                {
                                                    mach_vm_size_t g5 = 0;
                                                    if (mach_vm_read_overwrite(mach_task_self(),
                                                            (mach_vm_address_t)sv[w], 64,
                                                            (mach_vm_address_t)txt, &g5) == KERN_SUCCESS && g5 == 64)
                                                    {
                                                        int t;
                                                        txt[64] = 0;
                                                        for (t = 0; t < 64; t++)
                                                        {
                                                            if (txt[t] == 0) break;
                                                            if (txt[t] < 0x20 || txt[t] > 0x7e) { t = -1; break; }
                                                        }
                                                        /* demand a real terminated string of >=3 chars,
                                                         * so random pointer bytes do not read as text */
                                                        if (t >= 3) { txt[t] = 0; printable = 1; }
                                                    }
                                                }
                                                fprintf(stderr, "[mono-state] %s+0x%02x = %016llx%s%s%s\n",
                                                        cname[ci], w * 8, (unsigned long long)sv[w],
                                                        printable ? "  \"" : "",
                                                        printable ? txt : "",
                                                        printable ? "\"" : "");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else
                            fprintf(stderr, "[spin]   x28=0x%llx -- not a plausible CPU-state pointer\n",
                                    (unsigned long long)st.__x[28]);

                        /* ============ ml681 IS THE LOOP MAKING PROGRESS? =====
                         *
                         * ml677 showed six registers all holding one address
                         * (0x70330c40f8-family). Whether that word CHANGES is
                         * the difference between "contended lock, someone is
                         * winning" and "nobody owns it and this thread will
                         * spin forever". Sample it twice with a gap and diff.
                         * Also dump the 64 bytes around it -- a lock word's
                         * neighbours usually name the object. */
                        {
                            uint64_t cand[4] = { st.__x[8], st.__x[1], st.__x[2], st.__x[27] };
                            for (int c = 0; c < 4; c++)
                            {
                                uint64_t a = cand[c], v0 = 0, v1 = 0;
                                mach_vm_size_t g = 0;
                                if (a < 0x10000 || (a & 7)) continue;
                                if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)a,
                                        8, (mach_vm_address_t)&v0, &g) != KERN_SUCCESS || g != 8)
                                    continue;
                                /* ml686: sample densely over a full frame period and
                                 * report a BOUNDED SUMMARY. 50ms was too short to cover
                                 * a ~1s frame, and one line per sample would drown the
                                 * log; a value that changes and returns to the same
                                 * self-pointer would also read as "unchanged" if only
                                 * the endpoints were compared. Count transitions. */
                                {
                                    uint64_t prev = v0, distinct = 1, changes = 0, seen[4];
                                    int k, ns = 1;
                                    seen[0] = v0;
                                    for (k = 0; k < 120; k++)   /* 120 x 10ms = 1.2s */
                                    {
                                        uint64_t vn = 0;
                                        usleep(10000);
                                        if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)a,
                                                8, (mach_vm_address_t)&vn, &g) != KERN_SUCCESS || g != 8)
                                            break;
                                        if (vn != prev) { changes++; prev = vn; }
                                        {
                                            int dup = 0, q;
                                            for (q = 0; q < ns; q++) if (seen[q] == vn) dup = 1;
                                            if (!dup && ns < 4) { seen[ns++] = vn; distinct++; }
                                        }
                                        v1 = vn;
                                    }
                                    fprintf(stderr, "[spin]   watch addr=0x%llx over 1.2s: samples=120 "
                                                    "transitions=%llu distinct=%llu first=%016llx last=%016llx %s\n",
                                            (unsigned long long)a, (unsigned long long)changes,
                                            (unsigned long long)distinct,
                                            (unsigned long long)v0, (unsigned long long)v1,
                                            changes ? "CHANGES -- queue does turn over"
                                                    : "NEVER CHANGES across a full frame period");
                                }
                                {
                                    uint64_t nb[8];
                                    mach_vm_size_t g2 = 0;
                                    uint64_t base = a & ~63ull;
                                    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)base,
                                            sizeof(nb), (mach_vm_address_t)nb, &g2) == KERN_SUCCESS &&
                                        g2 == sizeof(nb))
                                        fprintf(stderr, "[spin]     0x%llx: %016llx %016llx %016llx %016llx "
                                                        "%016llx %016llx %016llx %016llx\n",
                                                (unsigned long long)base,
                                                (unsigned long long)nb[0], (unsigned long long)nb[1],
                                                (unsigned long long)nb[2], (unsigned long long)nb[3],
                                                (unsigned long long)nb[4], (unsigned long long)nb[5],
                                                (unsigned long long)nb[6], (unsigned long long)nb[7]);
                                }
                                break;   /* one candidate is enough */
                            }
                        }

                        /* ============ ml690 IS THE TREE CYCLIC? ==============
                         *
                         * The guest x86 at UnityPlayer+0x112ef.. is an ordered
                         * walk that also REWIRES links (stores into [r10]/[r8]/
                         * [rbx+8]) -- a deletion/rebalance, which must terminate.
                         * One worker living there for whole runs, with the
                         * watched word self-referential, is equally consistent
                         * with a CYCLIC tree as with heavy work, and those have
                         * opposite fixes: a cycle means our stores corrupted the
                         * structure, and making the loop faster would do nothing.
                         *
                         * Walk the child pointer at +0x08 from every plausible
                         * guest pointer in the host registers (the SRA mapping is
                         * not something to guess at) and report the first repeat.
                         * Bounded to 64 hops, all reads fault-safe. */
                        {
                            int ci;
                            for (ci = 0; ci < 29; ci++)
                            {
                                uint64_t root = st.__x[ci], seen[64];
                                int hops = 0, cyc = -1;
                                if (root < 0x7000000000ULL || root >= 0x7400000000ULL || (root & 7))
                                    continue;                     /* guest heap only */
                                for (hops = 0; hops < 64; hops++)
                                {
                                    uint64_t nxt = 0; mach_vm_size_t g2 = 0; int q;
                                    seen[hops] = root;
                                    if (mach_vm_read_overwrite(mach_task_self(),
                                            (mach_vm_address_t)(root + 8), 8,
                                            (mach_vm_address_t)&nxt, &g2) != KERN_SUCCESS || g2 != 8)
                                        break;
                                    if (!nxt || nxt < 0x7000000000ULL || nxt >= 0x7400000000ULL) break;
                                    for (q = 0; q <= hops; q++)
                                        if (seen[q] == nxt) { cyc = q; break; }
                                    if (cyc >= 0) break;
                                    root = nxt;
                                }
                                if (cyc >= 0)
                                    fprintf(stderr, "[tree] ml690 CYCLE from x%d: node 0x%llx repeats at hop %d "
                                                    "(walked %d) -- structure is circular\n",
                                            ci, (unsigned long long)seen[cyc], cyc, hops);
                                else if (hops >= 8)
                                    fprintf(stderr, "[tree] ml690 x%d chain depth %d, terminated cleanly "
                                                    "(no cycle in %d hops)\n", ci, hops, hops);
                            }
                        }

                        /* the loop body itself: 512 bytes centred on pc */
                        if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)lo,
                                                   sizeof(insn), (mach_vm_address_t)insn,
                                                   &got) == KERN_SUCCESS && got == sizeof(insn))
                        {
                            for (k = 0; k < 128; k += 8)
                            {
                                fprintf(stderr, "[spin]   %c0x%llx: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                                        (lo + k*4 <= st.__pc && st.__pc < lo + k*4 + 32) ? '>' : ' ',
                                        (unsigned long long)(lo + (uint64_t)k*4),
                                        insn[k], insn[k+1], insn[k+2], insn[k+3],
                                        insn[k+4], insn[k+5], insn[k+6], insn[k+7]);
                            }
                        }
                        else
                            fprintf(stderr, "[spin]   instruction window at 0x%llx UNREADABLE\n",
                                    (unsigned long long)lo);
                    }
                }
            }
        }
        {
            extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
            uint64_t mod = 0, pe_va = ios_jit_reverse_translate(st.__pc, &mod);
            if (pe_va)
                fprintf(stderr, "[thread-stacks]   pc is PE code: %.32s+0x%llx (base=0x%llx va=0x%llx)\n",
                        ios_pe_module_name(mod), (unsigned long long)(pe_va - mod),
                        (unsigned long long)mod, (unsigned long long)pe_va);
        }

        fp_walk = st.__fp;
        for (fr = 0; fr < 14 && fp_walk; fr++)
        {
            uint64_t frame_buf[2];
            mach_vm_size_t got_fw = 0;
            uint64_t ret_pc;

            if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)fp_walk, 16,
                                       (mach_vm_address_t)frame_buf, &got_fw) != KERN_SUCCESS || got_fw != 16)
                break;
            ret_pc = frame_buf[1] & 0x0000007fffffffffull;   /* strip PAC bits */
            if (ret_pc <= 0x4000) break;
            img = "?"; sym = "?"; off = ret_pc;
            if (dladdr((void*)(uintptr_t)ret_pc, &di))
            {
                if (di.dli_fname) { img = strrchr(di.dli_fname, '/'); img = img ? img + 1 : di.dli_fname; }
                if (di.dli_sname) { sym = di.dli_sname; off = ret_pc - (uint64_t)(uintptr_t)di.dli_saddr; }
            }
            {
                extern uint64_t ios_jit_reverse_translate( uint64_t addr, uint64_t *module_base );
                uint64_t mod = 0, pe_va = ios_jit_reverse_translate(ret_pc, &mod);
                if (pe_va)
                    fprintf(stderr, "[thread-stacks]   bt[%d] PE %.32s+0x%llx (va=0x%llx)\n",
                            fr, ios_pe_module_name(mod), (unsigned long long)(pe_va - mod),
                            (unsigned long long)pe_va);
                else
                    fprintf(stderr, "[thread-stacks]   bt[%d] %s`%s+0x%llx\n", fr, img, sym, (unsigned long long)off);
            }
            fp_walk = frame_buf[0];
        }
next:
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(*threads));
    mach_port_deallocate(mach_task_self(), self);
    fflush(stderr);
}
