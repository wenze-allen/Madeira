/* Part of signal_arm64_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. The fault-guard counters, guest caller dumps and their helpers. Same copyright and licence as signal_arm64_ios.c. */
/* ---- Fault-guard counters -------------------------------------------------
 * The exception server's give-up guards (exec-recover, reclaim-recover, the
 * livelock breaker, the delivery debounce and the redelivery terminal) count
 * repeats of one fault. They kept those counts in 16 slots chosen by a hash of
 * the key (or in one global record), so two faults whose keys shared a slot
 * reset each other's count on every alternation and the guard never tripped:
 * two pages 256 KB apart re-faulted forever in exec-recover, and two threads
 * faulting in turn did the same to the livelock breaker. A guard table matches
 * its key exactly. A slot whose key has been quiet for IOS_GUARD_IDLE_MS is
 * free again and its count starts over (a stuck fault repeats within
 * microseconds; a page reclaimed again minutes later is a new event, and
 * without this a collision-free table would hold every page's lifetime count);
 * when every slot is live the least recently hit one is replaced. Only the
 * single exception-server thread uses these, so no atomics. */
#define IOS_GUARD_SLOTS 64
#define IOS_GUARD_IDLE_MS 2000
struct ios_guard_table
{
    uint64_t key[IOS_GUARD_SLOTS];
    uint64_t last[IOS_GUARD_SLOTS];   /* mach_absolute_time of the last hit; 0 = empty */
};

static uint64_t ios_guard_idle_ticks( void )
{
    static uint64_t ticks;
    if (!ticks)
    {
        /* mach_timebase_info_data_t is not visible in this TU's header set;
         * the struct is two uint32s and the call takes it by pointer. */
        struct { unsigned int numer, denom; } tb = { 0, 0 };
        extern int mach_timebase_info( void * );
        mach_timebase_info( &tb );
        ticks = (tb.numer && tb.denom)
            ? (uint64_t)IOS_GUARD_IDLE_MS * 1000000ull * tb.denom / tb.numer
            : (uint64_t)IOS_GUARD_IDLE_MS * 24000ull;   /* the 24 MHz timebase */
    }
    return ticks;
}

/* The slot holding `key`, claimed when the key has none. *fresh is 1 when the
 * slot was just claimed or its key had gone idle: the caller starts its count
 * (and any per-slot state of its own) over. */
static int ios_guard_slot( struct ios_guard_table *t, uint64_t key, uint64_t now, int *fresh )
{
    uint64_t idle = ios_guard_idle_ticks();
    int i, victim = -1;

    if (!now) now = 1;
    for (i = 0; i < IOS_GUARD_SLOTS; i++)
    {
        if (t->last[i] && t->key[i] == key)
        {
            *fresh = now - t->last[i] > idle;
            t->last[i] = now;
            return i;
        }
    }
    for (i = 0; i < IOS_GUARD_SLOTS; i++)
    {
        if (!t->last[i] || now - t->last[i] > idle) { victim = i; break; }
        if (victim < 0 || t->last[i] < t->last[victim]) victim = i;
    }
    t->key[victim] = key;
    t->last[victim] = now;
    *fresh = 1;
    return victim;
}

/* Per-thread trampoline for signal handlers (runs on faulting thread) */
static __thread void *ios_my_trampoline = NULL;
static __thread int ios_my_slot = -1;

/* Thread registry: maps Mach thread port → TEB + trampoline.
 *
 * ml384: was 64. Steam runs register 90+ threads; entries past the cap were
 * silently DROPPED while the success ERR still printed, so every late-born
 * thread resolved to the slot-0 fallback = the INITIAL process's TEB. A
 * wrong-process TEB means the wrong per-PEB dispatcher, which walks the wrong
 * ntdll pool copy — services.exe died in LdrShutdownThread with wm=NULL that
 * way (ml383). The lookup also iterated to ios_thread_count (92+), reading
 * past the 64-entry array. */
#define IOS_MAX_WINE_THREADS 512

struct ios_thread_entry {
    thread_t mach_thread;
    uintptr_t teb;
    void *trampoline;
};
static struct ios_thread_entry ios_thread_registry[IOS_MAX_WINE_THREADS];
static volatile int32_t ios_thread_count = 0;
/* Writers (ios_thread_registry_add, ios_thread_registry_purge_range) hold this
 * so two of them never fill the same entry; the lookups stay lock-free. */
static pthread_mutex_t ios_thread_registry_lock = PTHREAD_MUTEX_INITIALIZER;

/* Exact-match registry probe — NO slot-0 fallback.
 *
 * ml540: ios_lookup_thread() returns 1 even when it fell back to slot 0, so no
 * caller can use it to answer "is this a guest thread at all?". Fault handling
 * needs exactly that: since #67 we hold the TASK-level exception port, so this
 * handler now sees faults from EVERY thread in the process — including the
 * SwiftUI UI thread, which has no TEB and must never be handed guest exception
 * delivery. */
/* ml559: read-only accessors so other TUs can walk the registry without the
 * array itself leaving this file (ntdll-unix globals crossing TUs have broken
 * pseudo-processes before — see the S1 CreateProcess rule). Lock-free, same
 * snapshot discipline as ios_thread_is_registered. */
int ios_thread_registry_count(void)
{
    int count = __sync_fetch_and_add(&ios_thread_count, 0);
    return count > IOS_MAX_WINE_THREADS ? IOS_MAX_WINE_THREADS : count;
}

uintptr_t ios_thread_registry_teb(int i)
{
    if (i < 0 || i >= IOS_MAX_WINE_THREADS) return 0;
    return ios_thread_registry[i].teb;
}

thread_t ios_thread_registry_mach(int i)
{
    if (i < 0 || i >= IOS_MAX_WINE_THREADS) return 0;
    return ios_thread_registry[i].mach_thread;
}

static int ios_thread_is_registered(thread_t mach_thread)
{
    int count = __sync_fetch_and_add(&ios_thread_count, 0);
    if (count > IOS_MAX_WINE_THREADS) count = IOS_MAX_WINE_THREADS;
    for (int i = 0; i < count; i++)
        if (ios_thread_registry[i].mach_thread == mach_thread) return 1;
    return 0;
}

/* ml558: is this pointer a TEB we actually installed?
 *
 * TSD slot 275 is NOT ours (see pthread_exit_wrapper) -- on a native thread it
 * holds whatever framework legitimately owns that key. Signal handlers that read
 * slot 275 must validate the value before dereferencing it, and must do so
 * WITHOUT locks or Mach traps. Scanning the registry for a matching TEB is both:
 * lock-free (same pattern as ios_thread_is_registered) and it answers the exact
 * question -- not "is this thread ours" but "is this VALUE one of ours". */
static int ios_teb_is_registered(uintptr_t teb)
{
    int count = __sync_fetch_and_add(&ios_thread_count, 0);
    if (!teb) return 0;
    if (count > IOS_MAX_WINE_THREADS) count = IOS_MAX_WINE_THREADS;
    for (int i = 0; i < count; i++)
        if (ios_thread_registry[i].teb == teb) return 1;
    return 0;
}

/* A released guest window is about to become PROT_NONE, and every TEB inside
 * it with it.  Entries naming those TEBs must go first: the registry is keyed
 * by Mach port, ports are recycled, and the exception path's port lookup would
 * otherwise hand the fault handler a pointer into the replaced range.  Only
 * called from the guest-window teardown (virtual_ios.c). */
int ios_thread_registry_purge_range( uintptr_t base, uintptr_t size )
{
    int count, purged = 0, i;

    pthread_mutex_lock( &ios_thread_registry_lock );
    count = ios_thread_registry_count();
    for (i = 0; i < count; i++)
    {
        uintptr_t teb = ios_thread_registry[i].teb;

        if (!teb || teb < base || teb - base >= size) continue;
        ios_thread_registry[i].mach_thread = 0;
        __sync_synchronize();
        ios_thread_registry[i].teb = 0;
        ios_thread_registry[i].trampoline = NULL;
        purged++;
    }
    pthread_mutex_unlock( &ios_thread_registry_lock );
    return purged;
}

/* Has the thread behind a registry port name exited?  The registry pins send
 * references on every name it stores, so an exited thread leaves a dead name
 * that thread_info refuses.  An unexpected query failure counts as alive. */
static int ios_thread_port_gone( thread_t port )
{
    struct thread_basic_info info;
    mach_msg_type_number_t length = THREAD_BASIC_INFO_COUNT;
    kern_return_t kr = thread_info( port, THREAD_BASIC_INFO, (thread_info_t)&info, &length );

    return kr == KERN_INVALID_ARGUMENT || kr == MACH_SEND_INVALID_DEST || kr == KERN_TERMINATED;
}

/* Is a thread whose TEB lies in [base, base+size) still alive?  An exited
 * process's workers can stay asleep long after its main thread is gone.  Only
 * the Mach thread's existence is asked, its TEB is never dereferenced; an
 * unexpected query failure counts as alive (keep the memory). */
int ios_thread_registry_range_busy( uintptr_t base, uintptr_t size )
{
    int count = ios_thread_registry_count(), i;

    for (i = 0; i < count; i++)
    {
        uintptr_t teb = ios_thread_registry[i].teb;
        thread_t port = ios_thread_registry[i].mach_thread;

        if (!port || !teb || teb < base || teb - base >= size) continue;
        if (!ios_thread_port_gone( port )) return 1;
    }
    return 0;
}

/* An entry a full registry may give to a new thread: one its guest window's
 * teardown purged, or one whose thread has exited.  Entry 0 is never taken, it
 * is what ios_lookup_thread falls back to.  Neither is an exited thread's entry
 * whose TEB still carries a FEX lock stamp (Instrumentation[6] or [8]):
 * ios_lock_census finds the hold of a thread that died with it through that
 * entry.  -1 when every entry belongs to a live thread. */
static int ios_thread_registry_reclaim( void )
{
    int i;

    for (i = 1; i < IOS_MAX_WINE_THREADS; i++)
    {
        thread_t port = ios_thread_registry[i].mach_thread;
        uintptr_t teb = ios_thread_registry[i].teb;
        uint64_t stamps[3] = { 0, 0, 0 };   /* TEB+0x16e8 [6], +0x16f0 [7], +0x16f8 [8] */
        mach_vm_size_t got = 0;

        if (!port) return i;
        if (!ios_thread_port_gone( port )) continue;
        if (teb && mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(teb + 0x16e8),
                                           sizeof(stamps), (mach_vm_address_t)stamps, &got ) == KERN_SUCCESS
            && got == sizeof(stamps) && (stamps[0] || stamps[2]))
            continue;
        return i;
    }
    return -1;
}

static int ios_thread_registry_reuse_enabled( void )
{
    static int enabled = -1;
    int v = __atomic_load_n( &enabled, __ATOMIC_ACQUIRE );

    if (v < 0)
    {
        /* On by default. MADEIRA_THREAD_REUSE=0 never gives a full thread registry's exited or purged entries to new threads (a session again registers 512 threads at most). */
        const char *e = getenv( "MADEIRA_THREAD_REUSE" );

        v = !(e && e[0] == '0');
        __atomic_store_n( &enabled, v, __ATOMIC_RELEASE );
    }
    return v;
}

/* Register a thread's port, TEB and trampoline; returns its entry, or -1.
 *
 * ml384: replace an existing entry for the same port first — the kernel
 * recycles thread port names, and a stale entry earlier in the array would
 * shadow the new registration in ios_lookup_thread (first match wins).
 *
 * Entries were never given back, so the registry filled after 512 threads
 * over the session's life, not 512 at once: a WoW64 game that keeps starting
 * and ending worker threads got there within minutes with a few dozen alive
 * (#397), and every later thread resolved to the slot-0 TEB.  A full registry
 * now gives the new thread an entry ios_thread_registry_reclaim finds free;
 * MADEIRA_THREAD_REUSE=0 turns that off. */
static int ios_thread_registry_add( thread_t pe_thread, uintptr_t teb, void *trampoline )
{
    int idx, reg_count;

    pthread_mutex_lock( &ios_thread_registry_lock );
    reg_count = ios_thread_registry_count();
    for (idx = 0; idx < reg_count; idx++)
        if (ios_thread_registry[idx].mach_thread == pe_thread) break;
    if (idx < reg_count)
    {
        /* ml390 (task #66): make the replace path LOUD.  If a name gets
         * recycled while its previous owner still has live guest state, this
         * overwrite silently redirects that thread's TEB resolution — and a
         * thread_set_state aimed at the new owner could land on the old one
         * (zeroed-state suspect).  old_teb!=0 && old_teb!=new_teb = the case
         * to correlate offline against [reg-miss] and fault dumps. */
        if (ios_thread_registry[idx].teb && ios_thread_registry[idx].teb != teb)
            ERR( "[thread-registry] REPLACE idx=%d port=0x%x old_teb=%p new_teb=%p\n",
                 idx, pe_thread, (void *)ios_thread_registry[idx].teb, (void *)teb );
    }
    else if (reg_count < IOS_MAX_WINE_THREADS)
        idx = __sync_fetch_and_add(&ios_thread_count, 1);
    else if (ios_thread_registry_reuse_enabled() && (idx = ios_thread_registry_reclaim()) >= 0)
    {
        static unsigned int reused;

        if (++reused <= 16 || !(reused % 256))
            ERR( "[thread-registry] REUSE #%u idx=%d port=0x%x old_port=0x%x old_teb=%p new_teb=%p\n",
                 reused, idx, pe_thread, ios_thread_registry[idx].mach_thread,
                 (void *)ios_thread_registry[idx].teb, (void *)teb );
        ios_thread_registry[idx].mach_thread = 0;
        __sync_synchronize();
    }
    else
    {
        ERR("[thread-registry] FULL (%d slots, %s) — thread 0x%x teb=%p NOT registered; "
            "Mach events on it will resolve to the slot-0 TEB (wrong process!)\n",
            IOS_MAX_WINE_THREADS, ios_thread_registry_reuse_enabled() ? "none free" : "MADEIRA_THREAD_REUSE=0",
            pe_thread, (void *)teb);
        idx = -1;
    }
    if (idx >= 0)
    {
        ios_thread_registry[idx].teb = teb;
        ios_thread_registry[idx].trampoline = trampoline;
        __sync_synchronize();
        ios_thread_registry[idx].mach_thread = pe_thread;
        /* ml401 (tasks #60/#66): EVERY registry port name proved
         * MACH_SEND_INVALID_DEST when the census sampler tried to use it —
         * something deallocates the mach_thread_self() ref after we store the
         * name, leaving the registry full of dead keys ([pump-sample] blind,
         * and dead names are exactly what the kernel recycles = the #66
         * wrong-thread hazard).  Pin extra send refs so the name outlives any
         * stray deallocate; dead-name lingering after thread exit is harmless
         * and prevents recycling. */
        {
            kern_return_t krr = mach_port_mod_refs( mach_task_self(), pe_thread,
                                                    MACH_PORT_RIGHT_SEND, 4 );
            if (krr != KERN_SUCCESS)
                ERR( "[thread-registry] mod_refs(+4) port=0x%x FAILED kr=%d\n", pe_thread, krr );
        }
    }
    pthread_mutex_unlock( &ios_thread_registry_lock );
    return idx;
}

static int ios_lookup_thread(thread_t mach_thread, uintptr_t *teb_out, void **tramp_out)
{
    int count = __sync_fetch_and_add(&ios_thread_count, 0);
    if (count > IOS_MAX_WINE_THREADS) count = IOS_MAX_WINE_THREADS;
    for (int i = 0; i < count; i++)
    {
        if (ios_thread_registry[i].mach_thread == mach_thread)
        {
            *teb_out = ios_thread_registry[i].teb;
            *tramp_out = ios_thread_registry[i].trampoline;
            return 1;
        }
    }
    /* Fallback: use first registered thread */
    /* ml390 (task #66): a thread that registered CORRECTLY (0184: idx=75 port
     * 0x4493 teb ok) later resolved to the slot-0 TEB here — either the
     * exception message named the thread differently than mach_thread_self()
     * did at registration (name drift), or the entry was clobbered.  Print the
     * sought name so it can be diffed against the registration line offline. */
    {
        static int miss_n;
        if (miss_n < 32)
        {
            miss_n++;
            ERR( "[reg-miss] #%d port=0x%x not in registry (count=%d) -> slot-0 fallback teb=%p\n",
                 miss_n, mach_thread, count, count > 0 ? (void *)ios_thread_registry[0].teb : NULL );
        }
    }
    if (count > 0)
    {
        *teb_out = ios_thread_registry[0].teb;
        *tramp_out = ios_thread_registry[0].trampoline;
        return 1;
    }
    *teb_out = 0;
    *tramp_out = NULL;
    return 0;
}

/* ml398 (task #60): the webhelper chrome_ipc pump thread wakes ONCE on
 * MasterStream_Event, reads a perfectly valid hello ([chrome-mem] proved the
 * bytes cross), then goes silent — no reply, no re-wait, no further wrapped
 * syscall.  The EC wrapper stamps TEB->Instrumentation[10] = 'PUMP' at that
 * wake; the census thread calls this every cycle to sample the thread's Mach
 * state.  RUNNING with a moving pc = userspace spin (pc locates it);
 * WAITING = blocked in a syscall the wrappers don't cover (pc/lr name it);
 * dead port = the thread died silently.  Candidate-TEB reads go through
 * mach_vm_read_overwrite so a stale registry entry cannot fault the census
 * thread.  Called from the virtual_ios.c census loop. */
/* ml405 (task #60): the wanderer often parks PRE-chorus, where no beacon
 * exists.  Census sweep, no beacon needed: every call, walk registry entries
 * (newest-first per TEB so corpses lose), and report every thread parked in
 * the ml404 __ulock_wait signature (WAITING + x0==0x1000001) — lock address
 * (x1), lock word (owner name for os_unfair_lock), and an 8-frame fp walk.
 * Each thread reported once (dedupe by port), 60 reports max. */
static void ios_lock_census(void)
{
    static int total_logged;
    static thread_t seen[64];
    static int nseen;
    int count = __sync_fetch_and_add(&ios_thread_count, 0);
    int i, s;
    if (count > IOS_MAX_WINE_THREADS) count = IOS_MAX_WINE_THREADS;

    /* iOS-Madeira ml414 (#60): the CodeInvalidationMutex read-holder is alive
     * somewhere — xtajit64 stamps TEB+0x16f8 (Instrumentation[8]) with the
     * mutex address while the shared lock is held (CompileCode).  ml414 proved
     * the leaker neither pthread_exits ([exit-hold] 0) nor gets a guest
     * redirect ([deliver-hold] 0) — it is parked/frozen in place.  Sweep every
     * registry thread for the stamp each census pass: names the holder AND
     * shows where it sits (pc/lr/bt) and whether the debugger froze it
     * (suspend_count).  A transient hit (mid-compile) is normal noise; the
     * same teb repeating with the same pc across passes = the leaker. */
    {
        static int hold_logged;
        for (i = count - 1; i >= 0 && hold_logged < 40; i--)
        {
            thread_t cand = ios_thread_registry[i].mach_thread;
            uintptr_t cteb = (uintptr_t)ios_thread_registry[i].teb;
            uint64_t held = 0;
            unsigned int ctid = 0;
            mach_vm_size_t mgot = 0;
            arm_thread_state64_t st;
            mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
            struct thread_basic_info bi;
            mach_msg_type_number_t bcnt = THREAD_BASIC_INFO_COUNT;
            uint64_t fp, frames[8] = { 0 };
            int fi;
            uint64_t srw_held = 0;
            if (!cand || !cteb) continue;
            if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cteb + 0x16f8), 8,
                                        (mach_vm_address_t)&held, &mgot ) != KERN_SUCCESS
                || mgot != 8)
                continue;
            /* ml446: slot 6 = CodeBufferWriteMutex ownership — a dead thread
             * holding ONLY that must not be skipped by the !held early-out */
            mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cteb + 0x16e8), 8,
                                    (mach_vm_address_t)&srw_held, &mgot );
            if (!held && !srw_held)
            {
                /* ml416: a converged rpmalloc-ownership repair leaves its
                 * breadcrumb (Instrumentation[4]) with the lock long released
                 * — report it once so the repair is visible even when the
                 * livelock never got to wedge anything. */
                static int crumb_logged;
                uint64_t crumb_owner = 0, crumb_heap = 0;
                if (crumb_logged >= 12) continue;
                mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cteb + 0x16d8), 8,
                                        (mach_vm_address_t)&crumb_owner, &mgot );
                mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cteb + 0x16e0), 8,
                                        (mach_vm_address_t)&crumb_heap, &mgot );
                if (!crumb_owner && !crumb_heap) continue;
                crumb_logged++;
                mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cteb + 0x48), 4,
                                        (mach_vm_address_t)&ctid, &mgot );
                dprintf(2, "[census-hold] RPMALLOC-REPAIR (converged) teb=0x%llx tid=%04x old_owner=0x%llx heap=0x%llx\n",
                        (unsigned long long)cteb, ctid, (unsigned long long)crumb_owner,
                        (unsigned long long)crumb_heap);
                continue;
            }
            mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cteb + 0x48), 4,
                                    (mach_vm_address_t)&ctid, &mgot );
            memset( &bi, 0, sizeof(bi) );
            {
                kern_return_t ti_kr = thread_info( cand, THREAD_BASIC_INFO, (thread_info_t)&bi, &bcnt );
                /* ml445 (#74): DEAD port + live TEB stamp = a cross-terminated
                 * thread ([thr-term] CROSS-TERM) died holding the FEX shared
                 * lock — the leak that stalls the world.  Recycling guard: if
                 * ANY live registry row uses this TEB, the stamp belongs to
                 * the live generation — do NOT touch it. */
                if (ti_kr != KERN_SUCCESS && held)
                {
                    static uint64_t reaped_tebs[16];
                    static int reaped_n;
                    int r, live = 0, already = 0;
                    for (r = 0; r < reaped_n; r++) if (reaped_tebs[r] == (uint64_t)cteb) already = 1;
                    for (r = 0; r < count && !live; r++)
                    {
                        struct thread_basic_info lbi;
                        mach_msg_type_number_t lcnt = THREAD_BASIC_INFO_COUNT;
                        if (r == i || (uintptr_t)ios_thread_registry[r].teb != cteb) continue;
                        if (ios_thread_registry[r].mach_thread &&
                            thread_info( ios_thread_registry[r].mach_thread, THREAD_BASIC_INFO,
                                         (thread_info_t)&lbi, &lcnt ) == KERN_SUCCESS)
                            live = 1;
                    }
                    if (!already && !live && reaped_n < 16)
                    {
                        extern void ios_wpm_reap_shared( unsigned long long mutex_addr, unsigned int depth,
                                                         unsigned long long dead_teb );
                        extern void ios_srw_reap_exclusive( unsigned long long lock_addr, unsigned long long dead_teb );
                        uint32_t depth = 1;
                        uint64_t srw_stamp = 0;
                        mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cteb + 0x16f0), 4,
                                                (mach_vm_address_t)&depth, &mgot );
                        if (!depth) depth = 1;
                        /* ml446: slot 6 = &CodeBufferWriteMutex while the JIT
                         * emission section holds it (JIT.cpp stamp) */
                        mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cteb + 0x16e8), 8,
                                                (mach_vm_address_t)&srw_stamp, &mgot );
                        reaped_tebs[reaped_n++] = (uint64_t)cteb;
                        dprintf(2, "[lock-reap] dead port=0x%x tid=%04x teb=0x%llx stamp=0x%llx depth=%u srw=0x%llx — reaping rev=ml446\n",
                                cand, ctid, (unsigned long long)cteb, (unsigned long long)held, depth,
                                (unsigned long long)srw_stamp);
                        ios_wpm_reap_shared( held, depth, (unsigned long long)cteb );
                        if (srw_stamp) ios_srw_reap_exclusive( srw_stamp, (unsigned long long)cteb );
                    }
                    else if (!already && live)
                        dprintf(2, "[lock-reap] dead port=0x%x teb=0x%llx stamp=0x%llx SKIPPED (teb recycled to live thread) rev=ml445\n",
                                cand, (unsigned long long)cteb, (unsigned long long)held);
                }
            }
            if (thread_get_state( cand, ARM_THREAD_STATE64, (thread_state_t)&st, &cnt ) != KERN_SUCCESS)
                memset( &st, 0, sizeof(st) );
            fp = st.__fp;
            for (fi = 0; fi < 8 && fp > 0x1000; fi++)
            {
                uint64_t rec[2] = { 0, 0 };
                mgot = 0;
                if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)fp, sizeof(rec),
                                            (mach_vm_address_t)rec, &mgot ) != KERN_SUCCESS) break;
                frames[fi] = rec[1];
                fp = rec[0];
            }
            hold_logged++;
            /* ml416: Instrumentation[4]/[5] are the rpmalloc ownership-repair
             * breadcrumbs (old owner_thread TEB / heap ptr) stamped by the
             * FEX-side drain fix — nonzero means the livelock repair FIRED. */
            {
                uint64_t crumb_owner = 0, crumb_heap = 0;
                mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cteb + 0x16d8), 8,
                                        (mach_vm_address_t)&crumb_owner, &mgot );
                mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(cteb + 0x16e0), 8,
                                        (mach_vm_address_t)&crumb_heap, &mgot );
                if (crumb_owner || crumb_heap)
                    dprintf(2, "[census-hold]   RPMALLOC-REPAIR breadcrumb teb=0x%llx: old_owner=0x%llx heap=0x%llx\n",
                            (unsigned long long)cteb, (unsigned long long)crumb_owner,
                            (unsigned long long)crumb_heap);
            }
            dprintf(2, "[census-hold] idx=%d port=0x%x teb=0x%llx tid=%04x HOLDS fexlock @0x%llx "
                    "run_state=%d susp=%d pc=0x%llx lr=0x%llx sp=0x%llx bt: %llx %llx %llx %llx %llx %llx %llx %llx\n",
                    i, cand, (unsigned long long)cteb, ctid, (unsigned long long)held,
                    bi.run_state, bi.suspend_count,
                    (unsigned long long)arm_thread_state64_get_pc( st ),
                    (unsigned long long)st.__lr,
                    (unsigned long long)arm_thread_state64_get_sp( st ),
                    (unsigned long long)frames[0], (unsigned long long)frames[1],
                    (unsigned long long)frames[2], (unsigned long long)frames[3],
                    (unsigned long long)frames[4], (unsigned long long)frames[5],
                    (unsigned long long)frames[6], (unsigned long long)frames[7]);
            /* ml443: what is the HOLDER itself waiting on?  ml442 showed
             * CrBrowserMain parked in an alert-wait while holding the
             * CodeInvalidationMutex write-locked, but its park never crossed
             * [waiters]' 60s bar (wakes keep resetting the age) — x-ref the
             * live registration and print its address + lock word NOW. */
            {
                extern int ios_alert_waiter_lookup( unsigned int tid, const void **addr, int *age_s, int *inf );
                const void *waddr = 0;
                int wage = 0, winf = 0;
                if (ios_alert_waiter_lookup( (unsigned int)ctid, &waddr, &wage, &winf ))
                {
                    unsigned int w = 0xdeaddead;
                    if (!((uintptr_t)waddr & 1) && (uintptr_t)waddr > 0x10000 && (uintptr_t)waddr < 0x8000000000ULL)
                    {
                        uint64_t al = (uintptr_t)waddr & ~3ULL;
                        uint32_t val = 0;
                        mach_vm_size_t wgot = 0;
                        if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)al, 4,
                                                    (mach_vm_address_t)&val, &wgot ) == KERN_SUCCESS && wgot == 4)
                            w = val;
                    }
                    dprintf(2, "[census-hold]   WAITING-ON addr=%p age=%ds %s w=%08x rev=ml443\n",
                            waddr, wage, winf ? "INF" : "TMO", w);
                }
            }
        }
    }

    if (total_logged >= 60) return;
    for (i = count - 1; i >= 0; i--)
    {
        thread_t cand = ios_thread_registry[i].mach_thread;
        arm_thread_state64_t st;
        mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
        struct thread_basic_info bi;
        mach_msg_type_number_t bcnt = THREAD_BASIC_INFO_COUNT;
        uint64_t fp, frames[8] = { 0 };
        uint32_t lockval = 0;
        vm_size_t got;
        int fi, dup = 0;
        if (!cand) continue;
        for (s = 0; s < nseen; s++) if (seen[s] == cand) dup = 1;
        if (dup) continue;
        if (thread_info( cand, THREAD_BASIC_INFO, (thread_info_t)&bi, &bcnt ) != KERN_SUCCESS)
            continue;
        if (bi.run_state != TH_STATE_WAITING) continue;
        if (thread_get_state( cand, ARM_THREAD_STATE64, (thread_state_t)&st, &cnt ) != KERN_SUCCESS)
            continue;
        if (st.__x[0] != 0x1000001) continue;   /* UL_COMPARE_AND_WAIT|ULF_NO_ERRNO */
        fp = st.__fp;
        for (fi = 0; fi < 8 && fp > 0x1000; fi++)
        {
            uint64_t rec[2] = { 0, 0 };
            got = 0;
            if (vm_read_overwrite( mach_task_self(), (vm_address_t)fp, sizeof(rec),
                                   (vm_address_t)rec, &got ) != KERN_SUCCESS) break;
            frames[fi] = rec[1];
            fp = rec[0];
        }
        if (st.__x[1] > 0x1000)
            vm_read_overwrite( mach_task_self(), (vm_address_t)st.__x[1], sizeof(lockval),
                               (vm_address_t)&lockval, &got );
        total_logged++;
        if (nseen < 64) seen[nseen++] = cand;
        dprintf(2, "[lock-census] idx=%d port=0x%x teb=%p pc=0x%llx lr=0x%llx x1=0x%llx "
                "x2=0x%llx lockval=0x%x bt: %llx %llx %llx %llx %llx %llx %llx %llx\n",
                i, cand, (void *)ios_thread_registry[i].teb,
                (unsigned long long)arm_thread_state64_get_pc( st ),
                (unsigned long long)st.__lr,
                (unsigned long long)st.__x[1],
                (unsigned long long)st.__x[2], lockval,
                (unsigned long long)frames[0], (unsigned long long)frames[1],
                (unsigned long long)frames[2], (unsigned long long)frames[3],
                (unsigned long long)frames[4], (unsigned long long)frames[5],
                (unsigned long long)frames[6], (unsigned long long)frames[7]);
        if (total_logged >= 60) return;
    }
}

/* ml406: beacon TEB list shared with sync.c's [alert-unix] tap.  The pump
 * entered an alert-wait post-wake WITHOUT passing the EC-side [pump-op]
 * wrapper (native-aarch64-ntdll routes bypass it); unix-side
 * NtWaitForAlertByThreadId is the choke point for ALL PE routes. */
uintptr_t ios_beacon_teb_list[4];
int ios_beacon_teb_count;

#define IOS_PUMP_MAX 4
extern void ios_alert_ring_dump(void);   /* ml439 (#74): unix/sync.c alert-flow probe */
extern void ios_alert_waiter_dump(void); /* ml440 (#74): >60s parkers + their lock words */
void ios_pump_sample(void)
{
    static int samples;
    static int nbeacons;
    static thread_t pump_port[IOS_PUMP_MAX];   /* 0 = needs (re-)resolve */
    static uintptr_t pump_teb[IOS_PUMP_MAX];
    int i, b;
    int count = __sync_fetch_and_add(&ios_thread_count, 0);
    if (count > IOS_MAX_WINE_THREADS) count = IOS_MAX_WINE_THREADS;

    ios_alert_ring_dump();   /* ml439: static ring during a parked-stall = wakes dying PE-side */
    ios_alert_waiter_dump(); /* ml440: name the lock the parked crowd is starving on */
    /* ml447: orphan-lock detector — collect live threads' TEB Instr[6]
     * CodeBufferWriteMutex stamps; a held-exclusive SRW with >=3 waiters that
     * NO live thread stamps (3 cycles running) has a vanished dead owner. */
    {
        extern void ios_orphan_check( const unsigned long long *live_stamps, int nstamps );
        unsigned long long stamps[64];
        int ns = 0, si;
        for (si = 0; si < count && ns < 64; si++)
        {
            struct thread_basic_info sbi;
            mach_msg_type_number_t scnt = THREAD_BASIC_INFO_COUNT;
            uint64_t stamp = 0;
            mach_vm_size_t sgot = 0;
            uintptr_t steb = ios_thread_registry[si].teb;
            if (!ios_thread_registry[si].mach_thread || !steb) continue;
            if (thread_info( ios_thread_registry[si].mach_thread, THREAD_BASIC_INFO,
                             (thread_info_t)&sbi, &scnt ) != KERN_SUCCESS) continue;
            if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(steb + 0x16e8), 8,
                                        (mach_vm_address_t)&stamp, &sgot ) != KERN_SUCCESS || sgot != 8) continue;
            if (stamp)
            {
                /* ml448: NAME the live S-holder — ml447 run showed the orphan
                 * detector correctly silent (holder alive+stamped) while the
                 * whole world queued behind S; this line is the only view of
                 * who owns it and pairs with its thread-stacks/census rows. */
                uint32_t stid = 0;
                mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(steb + 0x48), 4,
                                        (mach_vm_address_t)&stid, &sgot );
                dprintf(2, "[stamp-set] LIVE S-holder tid=%04x teb=0x%llx mutex=0x%llx rev=ml448\n",
                        stid, (unsigned long long)steb, (unsigned long long)stamp);
                stamps[ns++] = stamp;
            }
            /* ml468: the ml467 false orphan was a FEX lock whose LIVE holder
             * stamps Instrumentation[8] (fexlock, TEB+0x16f8), not [6] — feed
             * those stamps into the same live set so ios_orphan_check never
             * strikes a lock a running thread admits to holding. */
            if (ns < 64)
            {
                uint64_t fstamp = 0;
                if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(steb + 0x16f8), 8,
                                            (mach_vm_address_t)&fstamp, &sgot ) == KERN_SUCCESS
                    && sgot == 8 && fstamp)
                    stamps[ns++] = fstamp;
            }
        }
        ios_orphan_check( stamps, ns );
    }
    ios_lock_census();
    if (samples >= 120) return;
    /* discover beacon TEBs (ml399: server thread and pump can differ) */
    if (nbeacons < IOS_PUMP_MAX)
    {
        for (i = 0; i < count && nbeacons < IOS_PUMP_MAX; i++)
        {
            uintptr_t teb = ios_thread_registry[i].teb;
            uint64_t val = 0;
            vm_size_t got = 0;
            int known = 0;
            if (!teb) continue;
            for (b = 0; b < nbeacons; b++) if (pump_teb[b] == teb) known = 1;
            if (known) continue;
            if (vm_read_overwrite( mach_task_self(),
                    (vm_address_t)(teb + offsetof(TEB, Instrumentation) + 10 * sizeof(void *)),
                    sizeof(val), (vm_address_t)&val, &got ) != KERN_SUCCESS) continue;
            if (val == 0x504d5550)
            {
                pump_teb[nbeacons] = teb;
                pump_port[nbeacons] = 0;
                ios_beacon_teb_list[nbeacons] = teb;
                dprintf(2, "[pump-sample] beacon %d teb=%p (idx=%d)\n", nbeacons, (void *)teb, i);
                nbeacons++;
                ios_beacon_teb_count = nbeacons;
            }
        }
        if (!nbeacons) return;
    }
    /* resolve each beacon TEB to the NEWEST registry entry with a LIVE port.
     * ml402: TEB VAs recycle; forward first-match picked DEAD threads' stale
     * entries (dead names -> MACH_SEND_INVALID_DEST forever).  Scan backwards
     * and validate with thread_info before accepting; a beacon whose port
     * dies gets re-resolved next cycle, and "no live entry" is itself the
     * thread-death verdict. */
    for (b = 0; b < nbeacons; b++)
    {
        if (pump_port[b]) continue;
        for (i = count - 1; i >= 0; i--)
        {
            thread_t cand = ios_thread_registry[i].mach_thread;
            struct thread_basic_info bi;
            mach_msg_type_number_t bcnt = THREAD_BASIC_INFO_COUNT;
            if (ios_thread_registry[i].teb != pump_teb[b] || !cand) continue;
            if (thread_info( cand, THREAD_BASIC_INFO, (thread_info_t)&bi, &bcnt ) != KERN_SUCCESS)
                continue;
            pump_port[b] = cand;
            dprintf(2, "[pump-sample] beacon %d RESOLVED idx=%d port=0x%x teb=%p\n",
                    b, i, cand, (void *)pump_teb[b]);
            break;
        }
        if (!pump_port[b])
            dprintf(2, "[pump-sample] beacon %d teb=%p NO LIVE ENTRY (thread dead?)\n",
                    b, (void *)pump_teb[b]);
    }
    for (b = 0; b < nbeacons; b++)
    {
        arm_thread_state64_t st;
        mach_msg_type_number_t cnt = ARM_THREAD_STATE64_COUNT;
        struct thread_basic_info bi;
        mach_msg_type_number_t bcnt = THREAD_BASIC_INFO_COUNT;
        kern_return_t kr1, kr2;
        if (!pump_port[b]) continue;
        kr1 = thread_get_state( pump_port[b], ARM_THREAD_STATE64, (thread_state_t)&st, &cnt );
        kr2 = thread_info( pump_port[b], THREAD_BASIC_INFO, (thread_info_t)&bi, &bcnt );
        samples++;
        if (kr1 == KERN_SUCCESS)
        {
            /* ml404: both IPC threads park at the same shared-cache pc with
             * x0=0x1000001 (UL_COMPARE_AND_WAIT|ULF_NO_ERRNO = __ulock_wait).
             * Add the discriminators: x16 = trap number, x1 = ulock ADDRESS
             * (an os_unfair_lock word stores its OWNER's thread name), the
             * lock word's current value, and an 8-frame fp walk so the
             * non-shared-cache frames name the calling subsystem. All reads
             * fault-safe. */
            uint64_t fp = st.__fp;
            uint64_t frames[8] = { 0 };
            uint32_t lockval = 0;
            int fi;
            vm_size_t got;
            for (fi = 0; fi < 8 && fp > 0x1000; fi++)
            {
                uint64_t rec[2] = { 0, 0 };
                got = 0;
                if (vm_read_overwrite( mach_task_self(), (vm_address_t)fp, sizeof(rec),
                                       (vm_address_t)rec, &got ) != KERN_SUCCESS) break;
                frames[fi] = rec[1];
                fp = rec[0];
            }
            if (st.__x[1] > 0x1000)
                vm_read_overwrite( mach_task_self(), (vm_address_t)st.__x[1], sizeof(lockval),
                                   (vm_address_t)&lockval, &got );
            dprintf(2, "[pump-sample] b%d #%d pc=0x%llx lr=0x%llx sp=0x%llx x0=0x%llx "
                    "x1=0x%llx x2=0x%llx x16=0x%llx lockval=0x%x run_state=%d flags=%d "
                    "bt: %llx %llx %llx %llx %llx %llx %llx %llx\n",
                    b, samples,
                    (unsigned long long)arm_thread_state64_get_pc( st ),
                    (unsigned long long)st.__lr,
                    (unsigned long long)arm_thread_state64_get_sp( st ),
                    (unsigned long long)st.__x[0],
                    (unsigned long long)st.__x[1],
                    (unsigned long long)st.__x[2],
                    (unsigned long long)st.__x[16], lockval,
                    kr2 == KERN_SUCCESS ? bi.run_state : -1,
                    kr2 == KERN_SUCCESS ? bi.flags : -1,
                    (unsigned long long)frames[0], (unsigned long long)frames[1],
                    (unsigned long long)frames[2], (unsigned long long)frames[3],
                    (unsigned long long)frames[4], (unsigned long long)frames[5],
                    (unsigned long long)frames[6], (unsigned long long)frames[7]);
        }
        else
        {
            dprintf(2, "[pump-sample] b%d #%d port=0x%x DEAD kr1=%d -> re-resolving\n",
                    b, samples, pump_port[b], kr1);
            pump_port[b] = 0;
        }
    }
}

/* Diagnostic: first .data fault captured by Mach handler */
volatile uint64_t ios_exc_data_fault_pc = 0;
volatile uint64_t ios_exc_data_fault_lr = 0;
volatile uint64_t ios_exc_data_fault_sp = 0;
volatile uint64_t ios_exc_data_fault_frame_ptr = 0;
volatile uint64_t ios_exc_data_fault_frame_pc = 0;
volatile int ios_exc_data_fault_count = 0;
/* Additional register capture for first .data fault */
volatile uint64_t ios_exc_data_x0 = 0;
volatile uint64_t ios_exc_data_x1 = 0;
volatile uint64_t ios_exc_data_x2 = 0;
volatile uint64_t ios_exc_data_x3 = 0;
volatile uint64_t ios_exc_data_x16 = 0;
volatile uint64_t ios_exc_data_x17 = 0;
volatile uint64_t ios_exc_data_x18 = 0;
volatile uint64_t ios_exc_data_x29 = 0;
volatile uint32_t ios_exc_data_insn_at_lr = 0; /* instruction at LR (caller) */

/* Raw Mach exception message structures (64-bit codes) */
#pragma pack(4)
typedef struct {
    mach_msg_header_t head;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t ndr;
    exception_type_t exception;
    mach_msg_type_number_t code_count;
    int64_t code[2];
} ios_exc_request_t;

typedef struct {
    mach_msg_header_t head;
    NDR_record_t ndr;
    kern_return_t ret_code;
} ios_exc_reply_t;
#pragma pack()

/* iOS-Madeira ml329 (#53 discriminator): ring of pages the reclaim-recovery path
 * zero-filled. Written by the recovery site, dumped by ios_reclaim_pages_report()
 * from the fatal-SEGV path so "did iOS eat this allocator's memory?" is answered
 * from recorded fact rather than inferred from Wine's vprot (which reads 0 for
 * pages FEX allocated through its own VirtualAlloc2 path, so the existing verdict
 * string says "zeros OK" regardless and cannot settle the question). */
#define IOS_RRPAGE_MAX 128
static volatile unsigned long long ios_rr_pages[IOS_RRPAGE_MAX];
static volatile unsigned ios_rr_pages_n;

void ios_reclaim_note_page( unsigned long long pg );
void ios_reclaim_note_page( unsigned long long pg )
{
    unsigned slot = __sync_fetch_and_add( &ios_rr_pages_n, 1 );
    ios_rr_pages[slot % IOS_RRPAGE_MAX] = pg;
}

void ios_reclaim_pages_report( const char *when, unsigned long long fault_addr );
void ios_reclaim_pages_report( const char *when, unsigned long long fault_addr )
{
    unsigned total = ios_rr_pages_n;
    unsigned shown = total < IOS_RRPAGE_MAX ? total : IOS_RRPAGE_MAX;
    unsigned i, in_fex_band = 0;

    for (i = 0; i < shown; i++)
    {
        unsigned long long pg = ios_rr_pages[i];
        if (pg >= 0x7C00000000ULL && pg < 0x8000000000ULL) in_fex_band++;
    }
    dprintf( STDERR_FILENO,
             "[reclaim-census] rev=ml329 at=%s fault=0x%llx : %u pages zero-filled this run, "
             "%u of the last %u are in FEX's host heap band [0x7c,0x80) -- %s\n",
             when, fault_addr, total, in_fex_band, shown,
             in_fex_band ? "FEX HEAP WAS ZEROED, #53 is live for this crash"
                         : "none in FEX's heap; #53 does NOT explain this crash" );
    for (i = 0; i < shown && i < 16; i++)
        dprintf( STDERR_FILENO, "[reclaim-census]   pg[%u]=0x%llx%s\n", i,
                 (unsigned long long)ios_rr_pages[i],
                 (ios_rr_pages[i] >= 0x7C00000000ULL && ios_rr_pages[i] < 0x8000000000ULL) ? "  <== FEX heap" : "" );
}

/* ml369 (#63): defined after setup_exception (needs save_context and
 * struct exc_stack_layout); used by the exception loop below. */
static int ios_mach_deliver_guest_exception( thread_t thread, arm_thread_state64_t *state,
                                             arm_neon_state64_t *neon, int have_neon,
                                             int exception, uintptr_t fault_addr,
                                             uintptr_t thread_teb );

#ifdef WINE_IOS
/***********************************************************************
 *           ios_dump_guest_callers                              (ml1002)
 *
 * Who, in guest code, is calling us right now?
 *
 * rdr71 eliminated the three cheap explanations for the launcher failure:
 * export coverage is complete, the sub-floor emulator serviced 987,137
 * accesses with 0 misservice, and the self-modifying writes verifiably land
 * (ciphertext in, valid x86-64 out). What remains is the one structural
 * divergence from Windows/CrossOver: EMP.dll wants base 0x13000000, has its
 * relocations STRIPPED, and iOS's mandatory 4 GB __PAGEZERO makes that address
 * unmappable, so we map it high and service every access through the ml938
 * window.
 *
 * So the question worth answering is which module is running the API-resolution
 * loop that produces the failing LoadLibrary names -- the sub-floor EMP.dll at
 * 0x13xxxxxx, or the main image at 0x140xxxxxx. That is a fact about the guest,
 * and FEX's callret stack already records it; the fault path prints it as
 * [x86_callret]. This makes the same walk callable from ordinary Wine code.
 *
 * x28 is only a FEX frame on a guest thread, so this declines on any other
 * thread rather than inventing a chain. Frame layout per the fault path:
 * x28+0x18 = guest rip, gregs[0..15] follow.
 */
void ios_dump_guest_callers( const char *tag, unsigned long long x28 )
{
    uint64_t cret = 0;
    uint64_t cr[12];
    mach_vm_size_t got = 0;
    unsigned i;

    /* x28 comes from the SAVED context, never from the live register: inside a
     * signal handler the live x28 is whatever the handler's own code left
     * there, not the guest's FEX frame. */
    if (x28 < 0x10000 || x28 >= 0xfffffff000000000ULL) return;

    /* callret_sp lives in the FEX frame; read it the same way the fault path
     * does, through a failure-returning copy so a stale x28 cannot fault here. */
    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(x28 + 0xb0),
                                8, (mach_vm_address_t)&cret, &got ) != KERN_SUCCESS || got != 8)
        return;
    if (cret < 0x10000 || cret >= 0xfffffff000000000ULL) return;
    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)cret,
                                sizeof(cr), (mach_vm_address_t)cr, &got ) != KERN_SUCCESS ||
        got != sizeof(cr))
        return;

    /* ml1051: 16,753 of these (x7 lines) filled a quarter of a 46 MB log and the
     * log pipeline was ~12% of all running CPU samples. First 24, then 1 in 2000. */
    { static unsigned long ml1051_n; unsigned long k = __sync_add_and_fetch( &ml1051_n, 1 );
      if (k > 24 && (k % 2000)) return; }
    dprintf( 2, "ml1002: [%s] guest callers (most recent first), x28=%#llx callret=%#llx:\n",
             tag, (unsigned long long)x28, (unsigned long long)cret );
    for (i = 0; i < 6; i++)
    {
        uint64_t rip = cr[i * 2];
        const char *where = "?";
        if (rip >= 0x13000000ULL && rip < 0x1320f000ULL) where = "SUB-FLOOR EMP.dll (emulated window)";
        else if (rip >= 0x140000000ULL && rip < 0x147528000ULL) where = "main image";
        else if (rip >= 0x100000000ULL) where = "high module";
        dprintf( 2, "ml1002:   [%u] retRIP=%#llx  %s\n", i, (unsigned long long)rip, where );
    }
}


/* Executable aliases deliberately lack host write permission. Resolve only
 * live mappings; callers must also validate the end of a multi-byte access. */
static uintptr_t ios_write_alias( uintptr_t addr )
{
    extern void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
    extern size_t ios_jit_pool_size_global;
    extern uintptr_t ios_jit_anon_alias_lookup( uintptr_t );
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
    size_t size = ios_jit_pool_size_global;

    if (rx && rw && ((addr >= rx && addr - rx < size) || ios_jit_low_contains( addr )))
        return rw + (addr - rx);
    return ios_jit_anon_alias_lookup( addr );
}

/* The writable alias is a host implementation detail, not permission to
 * bypass a guest protection fault. FEX removes logical write permission
 * while a guest page has cached translations. Let its normal exception
 * handler invalidate those translations and restore logical write access
 * before emulating the retried store. Native pool writes have no guest
 * protection record and must retain their existing path. */
static int ios_alias_write_is_trapped( uintptr_t addr )
{
    extern void *ios_jit_rx_base_global;
    extern size_t ios_jit_pool_size_global;
    extern int ios_page_expected_prot( const void *addr );
    uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
    int prot;

    if ((rx && addr >= rx && addr - rx < ios_jit_pool_size_global) || ios_jit_low_contains( addr )) return 0;
    prot = ios_page_expected_prot( (const void *)addr );
    return prot >= 0 && !(prot & PROT_WRITE);
}

/* Adjacent guest pages need not occupy adjacent pool slots. Validate every
 * fragment before writing anything, then route each through its own alias.
 * Only ordinary stores use this; atomic RMW operations must remain atomic. */
static int ios_alias_write( uintptr_t addr, const void *source, size_t size, uintptr_t *blocked,
                            int honor_guest_prot )
{
    enum { PAGE = 0x4000, MAX_STORE = 32 };
    uintptr_t destinations[2];
    size_t lengths[2], done = 0;
    unsigned count = 0, i;

    *blocked = 0;
    if (!size || size > MAX_STORE || addr > UINTPTR_MAX - (size - 1)) return 0;
    while (done < size)
    {
        uintptr_t at = addr + done, rw = ios_write_alias( at );
        size_t length = PAGE - (at & (PAGE - 1));
        if (length > size - done) length = size - done;
        /* A store can cross a 4KB Wine protection boundary within one
         * 16KB alias page. At most 32 bytes means the endpoints cover all
         * protection pages touched by this fragment. */
        if (honor_guest_prot && ios_alias_write_is_trapped( at ))
        {
            *blocked = at;
            return 0;
        }
        if (honor_guest_prot && ios_alias_write_is_trapped( at + length - 1 ))
        {
            *blocked = (at + length - 1) & ~(uintptr_t)0xfff;
            return 0;
        }
        if (!rw || rw > UINTPTR_MAX - (length - 1) ||
            ios_write_alias( at + length - 1 ) != rw + length - 1) return 0;
        destinations[count] = rw;
        lengths[count++] = length;
        done += length;
    }
    done = 0;
    for (i = 0; i < count; ++i)
    {
        memcpy( (void *)destinations[i], (const unsigned char *)source + done, lengths[i] );
        done += lengths[i];
    }
    if (count > 1)
    {
        static unsigned logged;
        if (logged++ < 8)
            dprintf( 2, "[alias-span] routed %zu bytes at %p across %u guest pages\n",
                     size, (void *)addr, count );
    }
    return 1;
}

/* GPR STP/STNP, including pre/post-index writeback. gpr[31] is SP when
 * used as a base, but register 31 as a store source is always zero. */
static int ios_alias_store_pair( uint32_t insn, uintptr_t addr, uint64_t gpr[32], uintptr_t *blocked,
                                 int honor_guest_prot )
{
    unsigned rt = insn & 31, rt2 = (insn >> 10) & 31, rn = (insn >> 5) & 31;
    unsigned mode = (insn >> 23) & 3;
    unsigned width = (insn & 0x80000000u) ? 8 : 4;
    unsigned span = width * 2;
    uintptr_t effective;
    int64_t offset = (insn >> 15) & 0x7f;
    uint64_t values[2];

    /* Exclude loads, SIMD pairs and reserved opc encodings. */
    if ((insn & 0x7e400000u) != 0x28000000u) return 0;
    if ((mode == 1 || mode == 3) && rn != 31 && (rn == rt || rn == rt2)) return 0;
    if (offset & 0x40) offset -= 0x80;
    offset *= width;
    effective = mode == 1 ? gpr[rn] : gpr[rn] + offset;
    if (effective > UINTPTR_MAX - (span - 1) || addr < effective || addr - effective >= span) return 0;
    /* FAR may identify the second word. Translate the whole effective access,
     * rather than treating that fault address as the first store destination. */
    addr = effective;
    values[0] = rt == 31 ? 0 : gpr[rt];
    values[1] = rt2 == 31 ? 0 : gpr[rt2];
    if (width == 8)
    {
        if (!ios_alias_write( addr, values, sizeof(values), blocked, honor_guest_prot )) return 0;
    }
    else
    {
        uint32_t words[2] = { (uint32_t)values[0], (uint32_t)values[1] };
        if (!ios_alias_write( addr, words, sizeof(words), blocked, honor_guest_prot )) return 0;
    }
    if (mode == 1) gpr[rn] = addr + offset;
    else if (mode == 3) gpr[rn] = addr;
    return 1;
}

/* Signal-safe 32/64-bit CAS core, shared semantics with the BSD alias path.
 * Caller establishes full alias coverage. FP/LR encodings deliberately
 * decline: Darwin's __x array contains only x0..x28. No Wine logging here. */
static int ios_mach_emulate_cas(uint32_t insn, uintptr_t rw_addr, uint64_t gpr[29])
{
    unsigned rs, rt, width;
    uint64_t expected, desired;
    if ((insn & 0xbfa07c00u) != 0x88a07c00u) return 0;
    rs = (insn >> 16) & 31;
    rt = insn & 31;
    width = (insn & 0x40000000u) ? 8 : 4;
    if ((rs >= 29 && rs != 31) || (rt >= 29 && rt != 31)) return 0;
    if (!rw_addr || (rw_addr & (width - 1))) return 0;
    expected = rs == 31 ? 0 : gpr[rs];
    desired = rt == 31 ? 0 : gpr[rt];
    if (width == 8)
    {
        __atomic_compare_exchange_n((uint64_t *)rw_addr, &expected, desired,
                                    0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    }
    else
    {
        uint32_t expected32 = (uint32_t)expected;
        __atomic_compare_exchange_n((uint32_t *)rw_addr, &expected32, (uint32_t)desired,
                                    0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        expected = expected32;
    }
    if (rs != 31) gpr[rs] = expected;
    return 1;
}

/* CASP/CASPA/CASPL/CASPAL pair forms (0sz0 1000 0L1 Rs o0 11111 Rn Rt).
 * FEX's unaligned-atomic helpers (DoCAS, RunCASPAL) issue a 128-bit CASPAL on
 * guest memory from inside its exception handler. On an executable alias that
 * was just copied again into the pool, the access faults and nothing else
 * completes it: FEX re-enters its handler until the stack overflows. Run the
 * same hardware CASPAL on the RW alias so it stays atomic against other users
 * of that alias. Caller establishes full alias coverage. */
static int ios_mach_emulate_casp(uint32_t insn, uintptr_t rw_addr, uint64_t gpr[29])
{
    unsigned rs = (insn >> 16) & 31, rt = insn & 31;
    int wide = (insn >> 30) & 1;

    if ((insn & 0xbfa07c00u) != 0x08207c00u) return 0;
    if ((rs & 1) || (rt & 1) || rs + 1 >= 29 || rt + 1 >= 29) return 0;
    if (!rw_addr || (rw_addr & (wide ? 15 : 7))) return 0;
    {
        register uint64_t c0 asm("x0") = gpr[rs];
        register uint64_t c1 asm("x1") = gpr[rs + 1];
        register uint64_t c2 asm("x2") = gpr[rt];
        register uint64_t c3 asm("x3") = gpr[rt + 1];
        if (wide)
            asm volatile(".arch_extension lse\n\tcaspal x0, x1, x2, x3, [%4]"
                         : "+r"(c0), "+r"(c1) : "r"(c2), "r"(c3), "r"(rw_addr) : "memory");
        else
            asm volatile(".arch_extension lse\n\tcaspal w0, w1, w2, w3, [%4]"
                         : "+r"(c0), "+r"(c1) : "r"(c2), "r"(c3), "r"(rw_addr) : "memory");
        gpr[rs] = c0;
        gpr[rs + 1] = c1;
    }
    return 1;
}

/* ml938/ml939: defined far below, next to the store emulator they reuse.
 * Declared here because the Mach exception thread is the primary caller and
 * sits earlier in the file. */
static uintptr_t ios_subfloor_translate( uint64_t addr, void *peb );
extern void *ios_jit_current_peb(void);   /* virtual_ios.c */
extern int ios_jit_pool_pc_is_fex( uintptr_t pc );   /* virtual_ios.c */
static int ios_subfloor_service( ucontext_t *ctx, void *fault_addr, const char *via, void *peb );

/* LSE read-modify-write atomics for the Mach alias-store emulator, each done as
 * ONE host atomic on the RW alias, which maps the same physical pages as the
 * view that faulted:
 *   LD<OP>  size 111 0 00 A R 1 Rs 0 0 op(2) 00 Rn Rt (mask 0x3f20cc00, value
 *           0x38200000); op 00 LDADD, 01 LDCLR, 10 LDEOR, 11 LDSET. Rt gets the
 *           old value; Rt = 31 is the ST<OP> alias, which discards it.
 *   CAS     size 001000 1 L 1 Rs o0 11111 Rn Rt (mask 0x3fa07c00, value
 *           0x08a07c00). Rs holds the compare value and gets the old value.
 * Every size (B, H, W, X) and every acquire/release form. The operation is
 * __ATOMIC_SEQ_CST whatever A/R or L/o0 ask for, which is at least as strong as
 * each of them (the SWP case does the same); the exception and its reply
 * already order the faulting thread's own accesses around it. Old values are
 * zero-extended, as the B, H and W forms define. gpr[0..30] are x0..x30 (x29 =
 * FP, x30 = LR; FEX's JIT uses both); register 31 is the zero register in
 * both encodings, so gpr[31] is neither read nor written. Returns 0 with
 * nothing changed for any other encoding or a misaligned address, which these
 * builtins cannot do atomically. No Wine logging here. */
#define IOS_MACH_RMW(type) do { \
        type *p_ = (type *)rw_addr; \
        type e_ = (type)s; \
        if (cas) \
        { \
            __atomic_compare_exchange_n( p_, &e_, (type)t, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST ); \
            old = e_; \
        } \
        else switch ((insn >> 12) & 3) \
        { \
        case 0:  old = __atomic_fetch_add( p_, (type)s, __ATOMIC_SEQ_CST ); break; \
        case 1:  old = __atomic_fetch_and( p_, (type)~s, __ATOMIC_SEQ_CST ); break; \
        case 2:  old = __atomic_fetch_xor( p_, (type)s, __ATOMIC_SEQ_CST ); break; \
        default: old = __atomic_fetch_or( p_, (type)s, __ATOMIC_SEQ_CST ); break; \
        } \
    } while (0)
static int ios_mach_emulate_rmw( uint32_t insn, uintptr_t rw_addr, uint64_t gpr[32] )
{
    const unsigned size = insn >> 30, rs = (insn >> 16) & 31, rt = insn & 31;
    const int cas = (insn & 0x3fa07c00u) == 0x08a07c00u;
    uint64_t s, t, old = 0;

    if (!cas && (insn & 0x3f20cc00u) != 0x38200000u) return 0;
    if (!rw_addr || (rw_addr & ((1u << size) - 1))) return 0;
    s = rs == 31 ? 0 : gpr[rs];
    t = rt == 31 ? 0 : gpr[rt];
    switch (size)
    {
    case 0:  IOS_MACH_RMW( uint8_t );  break;
    case 1:  IOS_MACH_RMW( uint16_t ); break;
    case 2:  IOS_MACH_RMW( uint32_t ); break;
    default: IOS_MACH_RMW( uint64_t ); break;
    }
    if (cas && rs != 31) gpr[rs] = old;
    else if (!cas && rt != 31) gpr[rt] = old;
    return 1;
}
#undef IOS_MACH_RMW

/* ml974: is the ucontext's NEON state real?
 *
 * The Mach path builds a synthetic ucontext, memsets it to zero and fills
 * __ns ONLY `if (have_neon)` -- i.e. only when
 * thread_get_state(ARM_NEON_STATE64) succeeded. Every SIMD emulation path
 * reads or writes __ns.__v[], so when that fetch fails the zeroed block is
 * indistinguishable from genuinely zero vectors: a SIMD store would write
 * zeros over guest data, and a SIMD load would write into a block that is
 * never handed back. Both are silent corruption.
 *
 * Thread-local, defaulting to 1, so the signal/BUS callers -- which pass a
 * real ucontext from the kernel -- are unaffected and cannot race the Mach
 * thread's value. */
static __thread int ios_neon_valid = 1;
#endif

/* ml982: fetch the faulting instruction without dereferencing it.
 *
 * Three sites in the Mach handler did `*(uint32_t *)fault_pc` behind nothing
 * stronger than `fault_pc >= 0x100000000`, which only says the address is above
 * the iOS floor -- not that the page is mapped or readable. This is the handler
 * for faults that are routinely unmapped or non-executable PCs, and the shared
 * exception port is installed at task level, so a fault taken HERE waits on
 * this same handler and the process stops dead. That is the failure Astra
 * traced in rdr44-52, via a different unsafe read in the same function.
 *
 * Returns 0 and leaves *out at 0 when the word cannot be read. 0 matches none
 * of the encoding masks at any caller, so control flow is unchanged -- an
 * unreadable PC now behaves exactly like an unrecognised instruction instead of
 * wedging the handler. */
static int ios_fault_read_insn( uint64_t fault_pc, uint32_t *out )
{
    mach_vm_size_t got = 0;

    *out = 0;
    if (fault_pc < 0x100000000ULL) return 0;
    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)fault_pc, 4,
                                (mach_vm_address_t)out, &got ) != KERN_SUCCESS || got != 4)
    {
        static int unread_n;
        *out = 0;
        if (unread_n++ < 8)
            dprintf( 2, "[mach_exc] ml982 instruction at pc=%#llx UNREADABLE -- treating as an "
                     "unrecognised encoding rather than faulting inside the handler\n",
                     (unsigned long long)fault_pc );
        return 0;
    }
    return 1;
}

/* x18-derived base register.
 *
 * Wine's EC kernelbase TlsGetValue is `add x8, x18, w0, uxtw #3;
 * ldr x0, [x8, #0x1480]`: the TEB address is copied into another register one
 * instruction before the access, so when iOS has zeroed x18 the fault's base
 * register is x8, not x18, and the x18 emulation in the Mach handler declines
 * (Crysis Remastered worker thread: fault at 0x1570 = TLS slot 30, then the
 * process died). When the instruction right before the fault is an ADD/MOV
 * that wrote exactly this base register from x18, the base holds
 * (0 + offset) and fault_addr is the TEB offset, so the same TEB-relative
 * emulation is correct. Only ADD (extended/shifted register or immediate) and
 * MOV Xd,X18.
 * madeira-bcd: the other operand may be the destination itself, as in
 * `add x8, x18, x8, lsl #3`: the emulation reads only fault_addr. That form is
 * the one the x18 patcher runs "via x18" (its destination cannot carry the TEB),
 * and declining it killed Horizon Zero Dawn on build 500 (2026-10-11 19:17,
 * madeira_d3d12.dll+0x15ed4 reading 0x1508 = TEB 0 + TLS slot 17). */
static int ios_x18_derived_base( uint64_t fault_pc, int rn )
{
    uint32_t p;
    int rd, pn, pm;

    if (rn == 18 || rn >= 29 || !ios_fault_read_insn( fault_pc - 4, &p )) return 0;
    /* The x18 patcher (virtual_ios.c, "via x18" form) moves such an ADD into a
     * trampoline -- `mrs x18, TPIDRRO_EL0; and x18, x18, #~7; ldr x18, [x18,
     * #slot]; <ADD>; b back` -- and leaves `b tramp` at pc-4. TlsGetValue is
     * hot enough that a preemption between that ldr and the ADD (iOS zeroes
     * x18) does happen: build 264 died exactly there again. Follow the branch
     * when the trampoline has that shape and branches back to the fault. */
    if ((p & 0xfc000000u) == 0x14000000u)
    {
        int64_t imm = (int64_t)(int32_t)((p & 0x03ffffffu) << 6) >> 4;   /* sign-extended imm26 * 4 */
        uint64_t t = fault_pc - 4 + imm;
        uint32_t t0, t4;
        if (!ios_fault_read_insn( t, &t0 ) || t0 != (0xd53bd060u | 18)) return 0;
        if (!ios_fault_read_insn( t + 16, &t4 ) || (t4 & 0xfc000000u) != 0x14000000u) return 0;
        if (t + 16 + ((int64_t)(int32_t)((t4 & 0x03ffffffu) << 6) >> 4) != fault_pc) return 0;
        if (!ios_fault_read_insn( t + 12, &p )) return 0;
    }
    rd = p & 31; pn = (p >> 5) & 31; pm = (p >> 16) & 31;
    if (rd != rn) return 0;
    if ((p & 0xffe00000u) == 0x8b200000u) return pn == 18;                       /* ADD Xd, X18, Wm/Xm, ext */
    if ((p & 0xff200000u) == 0x8b000000u) return pn == 18 ||                     /* ADD Xd, X18, Xm, shift */
                                                 (pm == 18 && !((p >> 10) & 0x3f));
    if ((p & 0xff800000u) == 0x91000000u) return pn == 18;                       /* ADD Xd, X18, #imm */
    if ((p & 0xffffffe0u) == (0xaa0003e0u | (18u << 16))) return 1;              /* MOV Xd, X18 */
    return 0;
}

