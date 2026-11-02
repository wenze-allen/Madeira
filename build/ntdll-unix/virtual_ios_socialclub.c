/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Social Club's Chromium (madeira-bcd). Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *           Social Club's Chromium (madeira-bcd)
 *
 * Rockstar's Social Club runs its Chromium (CEF) in SocialClubHelper.exe: the
 * game's socialclub.dll starts it as the BROWSER process (its command line has
 * no --type=; process_ios.c makes it --single-process) and connects to it as a
 * client over \\.\pipe\chrome.rgsc_gameinst_0 (ipc.log: "Unable to create pipe
 * named "rgsc_gameinst_0" in client mode"). The game -- like the launcher --
 * also loads libcef.dll itself but never starts Chromium in it: the Proton log
 * of a working PC run shows GTA5_Enhanced.exe loading libcef.dll with no
 * Chromium thread, and every helper process coming from the launcher's browser.
 * Here that copy costs 240 MB of the JIT pool (it was EXHAUSTED for it in every
 * run on 2026-10-02) and its chrome_elf.dll would reserve a second
 * PartitionAlloc GigaCage in the shared guest window, leaving the helper
 * neither. So a Social Club client (a process with socialclub.dll mapped that
 * is not SocialClubHelper.exe) is refused libcef.dll exactly the way an
 * exhausted pool refuses an image: its load fails, as it has in every run so
 * far, and the pool and the address space stay free for the helper.
 * env.MADEIRA_SC_CEF = 0 turns this (and the helper's command line) off.
 */
static int ios_sc_cef_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0)
    {
        const char *e = getenv( "MADEIRA_SC_CEF" );
        enabled = !(e && e[0] == '0');
    }
    return enabled;
}

/* 1 when `name` (an image or module name, NUL-terminated) is `want`, ignoring
 * ASCII case. */
static int ios_sc_name_is( const char *name, const char *want )
{
    if (!name) return 0;
    for (; *name && *want; name++, want++)
    {
        char a = *name, b = *want;
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return !*name && !*want;
}

/* 1 when the path's last component (after '\' or '/') is SocialClubHelper.exe. */
static int ios_sc_path_is_helper( const WCHAR *path, size_t len )
{
    static const char helper[] = "socialclubhelper.exe";
    size_t base = 0, k, n = sizeof(helper) - 1;

    if (!path) return 0;
    for (k = 0; k < len; k++) if (path[k] == '\\' || path[k] == '/') base = k + 1;
    if (len - base != n) return 0;
    for (k = 0; k < n; k++)
    {
        WCHAR c = path[base + k];
        if (c >= 'A' && c <= 'Z') c += 32;
        if (c != (WCHAR)helper[k]) return 0;
    }
    return 1;
}

/* Is the calling pseudo-process SocialClubHelper.exe? (its PEB's image path) */
static int ios_sc_current_is_helper(void)
{
    PEB *peb = ios_jit_current_peb();
    RTL_USER_PROCESS_PARAMETERS *pp = peb ? peb->ProcessParameters : NULL;

    if (!pp || !pp->ImagePathName.Buffer) return 0;
    return ios_sc_path_is_helper( pp->ImagePathName.Buffer, pp->ImagePathName.Length / sizeof(WCHAR) );
}

/* madeira-bcd: [sc-rph] the renderer half of Social Club's pages under
 * --single-process.
 *
 * SocialClubHelper.exe picks its CefApp by process type: no --type= gets the
 * browser app, --type=renderer the renderer app. Only the renderer app's
 * GetRenderProcessHandler returns a handler (Rockstar's page bridge: it reads
 * "rgsc-ipc-channel-name" when a browser is created, logs "Renderer IPC
 * channel: ..." and connects the page to the launcher); the browser app's
 * returns NULL. A single-process Chromium asks the BROWSER app for the
 * renderer's handler, so that half never ran. GTA log 2026-10-04 12:56: the
 * launcher sent four navigations (two online, two offline file:// pages), each
 * naming a fresh channel rgsc_ipc_<pid>_channel_1, _2, ...; every page loaded
 * (load-start / load-end events came back over channel_0), nobody ever opened
 * those channels, and the launcher gave up "timed out loading both its online
 * and offline content" (SC_INIT_ERR_WEBSITE_FAILED_LOAD). A renderer process of
 * its own cannot exist here: layout 2 has room for one Chromium.
 *
 * For the one helper build analysed (TimeDateStamp 0x6a86d563, SizeOfImage
 * 0x244000) every byte this relies on is checked first. Then a 112-byte x64
 * thunk goes into the zero tail of .text (past SizeOfRawData, cleared by the
 * mapper above) and the browser app's GetRenderProcessHandler vtable slot
 * points to it. The thunk builds the helper's own renderer app once (its
 * operator new and constructor), keeps one reference to it in the zero tail of
 * .data's last page, and returns that app's handler through the helper's own
 * getter (which adds the caller's reference):
 *     push rbx; sub rsp,0x30; mov rbx,rdx
 *     mov rax,[cache]; test rax,rax; jnz have
 *     mov ecx,0x60; call new; test rax,rax; jz none
 *     mov rcx,rax; mov edx,1; call RendererApp::RendererApp
 *     mov [rsp+0x20],rax; AddRef through the virtual base; mov rax,[rsp+0x20]
 *     mov [cache],rax
 *   have: mov rcx,rax; mov rdx,rbx; call App::GetRenderProcessHandler
 *   out:  mov rax,rbx; add rsp,0x30; pop rbx; ret
 *   none: mov qword [rbx],0; jmp out
 * Applied after relocation and before the section protections, so the JIT-pool
 * copy of .text carries it. Any mismatch: nothing is written and the reason is
 * logged. env.MADEIRA_SC_RENDER_HANDLER = 0 turns it off; so does
 * env.MADEIRA_SC_CEF = 0 (no --single-process then).
 *
 * The Unix view can still have preferred-base pointers in its vtables. The
 * JIT-pool copy rebases the existing DIR64 entries, including both patched
 * vtable slots, so the slots must be written in their current base. Read that
 * base from a slot instead of assuming it is ptr. New pointers in the unused
 * .data tail have no DIR64 entries: those must name the mapped view directly
 * so the normal PE-to-JIT alias translation can resolve them. */
#define IOS_SCH_IMAGE_BASE  0x140000000ULL /* the helper's preferred base */
#define IOS_SCH_STAMP       0x6a86d563u
#define IOS_SCH_SIZE        0x244000u
#define IOS_SCH_TEXT        0x1000u      /* .text: VirtualSize 0x17f34c, raw 0x17f400 */
#define IOS_SCH_DATA        0x1cc000u    /* .data: VirtualSize 0x43bc */
#define IOS_SCH_THUNK       0x180800u
#define IOS_SCH_CACHE       0x1d0ff8u
#define IOS_SCH_VT_BROWSER  0x182268u    /* browser app's CefApp vtable */
#define IOS_SCH_VT_RENDERER 0x182658u    /* renderer app's CefApp vtable */
#define IOS_SCH_GET_HANDLER 0x51b0u      /* returns this+0x28 as a CefRefPtr */
#define IOS_SCH_GET_NULL    0x4330u      /* returns a NULL CefRefPtr */
#define IOS_SCH_SLOT_BROWSER  3          /* CefApp::GetBrowserProcessHandler */
#define IOS_SCH_SLOT_RENDERER 4          /* CefApp::GetRenderProcessHandler */
#define IOS_SCH_VT_RPH      0x182688u    /* CefRenderProcessHandler vtable */
#define IOS_SCH_WEBKIT      0x7e60u      /* OnWebKitInitialized */
#define IOS_SCH_CURRENT_LOOP 0x173090u   /* this thread's helper MessageLoop */
#define IOS_SCH_LOOP_CTOR   0x171770u
#define IOS_SCH_LOOP_WORK   0x172330u    /* DoWork, NOT DeletePendingTasks (0x172020) */
#define IOS_SCH_LOOP_DELAYED 0x1721c0u   /* DoDelayedWork */
#define IOS_SCH_LOOP_IDLE   0x1722a0u    /* DoIdleWork */
#define IOS_SCH_POST_TASK   0x181b08u    /* cef_post_delayed_task import slot */
#define IOS_SCH_LOOP_INIT   0x180880u
#define IOS_SCH_LOOP_PUMP   0x1808f0u
#define IOS_SCH_TASK_ADD    0x1809b0u
#define IOS_SCH_TASK_RELEASE 0x1809c0u
#define IOS_SCH_TASK_ONE    0x1809d0u
#define IOS_SCH_TASK_ANY    0x1809e0u
#define IOS_SCH_TASK        0x1d0c00u   /* cef_task_t + loop pointer + anchored refcount */
#define IOS_SCH_RUN_INSTALL 0x180a00u
#define IOS_SCH_RUN_RESTORE 0x180a80u
#define IOS_SCH_RUN_RING    0x1d0c40u   /* counter + 16 records (32 bytes each) */
#define IOS_SCH_RUN_RING_SIZE 520u
#define IOS_SCH_RENDER_DRAIN_SITE 0x48fa4u /* renderer-only call to drain helper work */
#define IOS_SCH_RENDER_DRAIN 0x180b70u
#define IOS_SCH_IPC_CONNECT 0x4ac10u
#define IOS_SCH_RENDER_CHANNEL_REPLY 0x48593u
#define IOS_SCH_RENDER_CHANNEL_KEEP  0x48598u
#define IOS_SCH_RENDER_CHANNEL_THUNK 0x180400u
#define IOS_SCH_IPC_TRACE   0x180b90u
#define IOS_SCH_IPC_COUNT   0x1d0e48u /* immediately after the RunState ring */
#define IOS_SCH_IPC_SPLIT   0x180c90u
#define IOS_SCH_IPC_CAPTURE 0x180db2u
#define IOS_SCH_IPC_STORE   0x180dc8u
#define IOS_SCH_IPC_ROLE    0x180ddfu
#define IOS_SCH_IPC_GLOBAL_LOOP 0x180dfbu
#define IOS_SCH_IPC_INITIAL_CONNECT 0x180e0au
#define IOS_SCH_IPC_DESTROY 0x180e19u
#define IOS_SCH_IPC_DIRECT  0x180edcu
#define IOS_SCH_IPC_CONTEXT 0x1d0e50u /* renderer manager + borrowed main command line */
#define IOS_SCH_UI_CTOR     0xd5040u  /* message 0x20005, four-byte payload */
#define IOS_SCH_UI_TRACE    0x180f30u
#define IOS_SCH_UI_COUNT    0x1d0e60u
#define IOS_SCH_UI_DELEGATE_CALLER 0x320afu


/* Source: tests/host/sc-renderer-channels.S. Preserve page channels within
 * the embedded client's 64-slot capacity; the original reply cleanup still runs. */
static const unsigned char ios_sch_renderer_channels[25] =
{
    0x83,0xb8,0x20,0x02,0x00,0x00,0x40,0x73,0x0b,0x45,0x31,0xc0,0x48,0x89,0xc1,0xe9,
    0x8b,0x81,0xec,0xff,0xe9,0x93,0x81,0xec,0xff,
};

static const unsigned char ios_sch_thunk[112] =
{
    0x53, 0x48,0x83,0xec,0x30, 0x48,0x89,0xd3,
    0x48,0x8b,0x05,0xe9,0x07,0x05,0x00, 0x48,0x85,0xc0, 0x75,0x3f,
    0xb9,0x60,0x00,0x00,0x00, 0xe8,0xea,0xde,0xfb,0xff, 0x48,0x85,0xc0, 0x74,0x44,
    0x48,0x89,0xc1, 0xba,0x01,0x00,0x00,0x00, 0xe8,0x70,0x61,0xe8,0xff,
    0x48,0x89,0x44,0x24,0x20, 0x48,0x8b,0x48,0x08, 0x48,0x63,0x49,0x04,
    0x48,0x8d,0x4c,0x08,0x08, 0x48,0x8b,0x11, 0xff,0x12,
    0x48,0x8b,0x44,0x24,0x20, 0x48,0x89,0x05,0xa5,0x07,0x05,0x00,
    0x48,0x89,0xc1, 0x48,0x89,0xda, 0xe8,0x52,0x49,0xe8,0xff,
    0x48,0x89,0xd8, 0x48,0x83,0xc4,0x30, 0x5b, 0xc3,
    0x48,0xc7,0x03,0x00,0x00,0x00,0x00, 0xeb,0xee,
};

/* Chromium creates the in-process renderer thread without the helper's
 * thread-local MessageLoop. Initialize it before the original WebKit callback;
 * only a newly created loop gets a CEF TID_RENDERER task. Existing helper loops
 * keep their own pump. Each task drives DoWork/DoDelayedWork/DoIdleWork with a
 * scoped RunState and a 32-iteration budget, then yields for at least 10 ms.
 * Source: tests/host/sc-render-loop.S; the host test assembles and executes it.
 * The loop and anchored task remain alive until the pseudo-process exits. */
static const unsigned char ios_sch_loop_thunk[363] =
{
    0x53,0x48,0x83,0xec,0x30,0x48,0x89,0xcb,0xc7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,
    0xe8,0xfb,0x27,0xff,0xff,0x48,0x85,0xc0,0x75,0x28,0xb9,0x60,0x01,0x00,0x00,0xe8,
    0x64,0xde,0xfb,0xff,0x48,0x85,0xc0,0x74,0x19,0x48,0x89,0xc1,0x31,0xd2,0xe8,0xbd,
    0x0e,0xff,0xff,0x48,0x89,0x05,0x76,0x03,0x05,0x00,0xc7,0x44,0x24,0x20,0x01,0x00,
    0x00,0x00,0x48,0x89,0xd9,0xe8,0x96,0x75,0xe8,0xff,0x83,0x7c,0x24,0x20,0x00,0x74,
    0x18,0xb9,0x06,0x00,0x00,0x00,0x48,0x8d,0x15,0x23,0x03,0x05,0x00,0x41,0xb8,0x0a,
    0x00,0x00,0x00,0xff,0x15,0x1f,0x12,0x00,0x00,0x48,0x83,0xc4,0x30,0x5b,0xc3,0x90,
    0x53,0x56,0x48,0x83,0xec,0x58,0x48,0x89,0xcb,0x48,0x8b,0x4b,0x30,0x48,0x85,0xc9,
    0x0f,0x84,0x94,0x00,0x00,0x00,0x48,0x8b,0x81,0x28,0x01,0x00,0x00,0x48,0x89,0x44,
    0x24,0x30,0xba,0x01,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x04,0x8b,0x10,0xff,0xc2,
    0x89,0x54,0x24,0x38,0xc7,0x44,0x24,0x3c,0x00,0x00,0x00,0x00,0x48,0xc7,0x44,0x24,
    0x40,0x00,0x00,0x00,0x00,0x48,0x8d,0x44,0x24,0x38,0x48,0x89,0x81,0x28,0x01,0x00,
    0x00,0xbe,0x20,0x00,0x00,0x00,0x48,0x8b,0x4b,0x30,0xe8,0xe1,0x19,0xff,0xff,0x88,
    0x44,0x24,0x28,0x48,0x8b,0x4b,0x30,0x48,0x8d,0x54,0x24,0x20,0xe8,0x5f,0x18,0xff,
    0xff,0x0a,0x44,0x24,0x28,0x74,0x06,0xff,0xce,0x75,0xdb,0xeb,0x09,0x48,0x8b,0x4b,
    0x30,0xe8,0x2a,0x19,0xff,0xff,0x48,0x8b,0x4b,0x30,0x48,0x8b,0x44,0x24,0x30,0x48,
    0x89,0x81,0x28,0x01,0x00,0x00,0xb9,0x06,0x00,0x00,0x00,0x48,0x89,0xda,0x41,0xb8,
    0x0a,0x00,0x00,0x00,0xff,0x15,0x6e,0x11,0x00,0x00,0x48,0x83,0xc4,0x58,0x5e,0x5b,
    0xc3,0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,0x0f,0x1f,0x40,0x00,
    0xf0,0xff,0x41,0x38,0xc3,0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,
    0xf0,0xff,0x49,0x38,0x31,0xc0,0xc3,0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,
    0x83,0x79,0x38,0x01,0x0f,0x94,0xc0,0x0f,0xb6,0xc0,0xc3,0x0f,0x1f,0x44,0x00,0x00,
    0x83,0x79,0x38,0x00,0x0f,0x95,0xc0,0x0f,0xb6,0xc0,0xc3,
};

/* Record only the two RunState pointer writes in MessagePumpWin::Run.
 * No printing or allocation on the normal path; dump the bounded ring only
 * when the matching helper faults. The hooks replay displaced instructions
 * and preserve flags/volatile registers. This is diagnostic, not a repair. */
static const unsigned char ios_sch_run_trace[365] =
{
    0x48,0x89,0x41,0x40,0x9c,0x50,0x51,0x52,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,
    0x48,0x83,0xec,0x60,0xf3,0x0f,0x7f,0x04,0x24,0xf3,0x0f,0x7f,0x4c,0x24,0x10,0xf3,
    0x0f,0x7f,0x54,0x24,0x20,0xf3,0x0f,0x7f,0x5c,0x24,0x30,0xf3,0x0f,0x7f,0x64,0x24,
    0x40,0xf3,0x0f,0x7f,0x6c,0x24,0x50,0x48,0x89,0xc2,0x41,0xb8,0x01,0x00,0x00,0x00,
    0xe8,0xcb,0x00,0x00,0x00,0xf3,0x0f,0x6f,0x04,0x24,0xf3,0x0f,0x6f,0x4c,0x24,0x10,
    0xf3,0x0f,0x6f,0x54,0x24,0x20,0xf3,0x0f,0x6f,0x5c,0x24,0x30,0xf3,0x0f,0x6f,0x64,
    0x24,0x40,0xf3,0x0f,0x6f,0x6c,0x24,0x50,0x48,0x83,0xc4,0x60,0x41,0x5b,0x41,0x5a,
    0x41,0x59,0x41,0x58,0x5a,0x59,0x58,0x9d,0x48,0x8b,0x01,0xe9,0xa8,0x36,0xff,0xff,
    0x48,0x89,0x7b,0x40,0x9c,0x50,0x51,0x52,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,
    0x48,0x83,0xec,0x60,0xf3,0x0f,0x7f,0x04,0x24,0xf3,0x0f,0x7f,0x4c,0x24,0x10,0xf3,
    0x0f,0x7f,0x54,0x24,0x20,0xf3,0x0f,0x7f,0x5c,0x24,0x30,0xf3,0x0f,0x7f,0x64,0x24,
    0x40,0xf3,0x0f,0x7f,0x6c,0x24,0x50,0x48,0x89,0xd9,0x48,0x89,0xfa,0x41,0xb8,0x02,
    0x00,0x00,0x00,0xe8,0x48,0x00,0x00,0x00,0xf3,0x0f,0x6f,0x04,0x24,0xf3,0x0f,0x6f,
    0x4c,0x24,0x10,0xf3,0x0f,0x6f,0x54,0x24,0x20,0xf3,0x0f,0x6f,0x5c,0x24,0x30,0xf3,
    0x0f,0x6f,0x64,0x24,0x40,0xf3,0x0f,0x6f,0x6c,0x24,0x50,0x48,0x83,0xc4,0x60,0x41,
    0x5b,0x41,0x5a,0x41,0x59,0x41,0x58,0x5a,0x59,0x58,0x9d,0x48,0x8b,0x5c,0x24,0x50,
    0xe9,0x2f,0x36,0xff,0xff,0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00,
    0x53,0x56,0x57,0x48,0x83,0xec,0x20,0x48,0x89,0xcb,0x48,0x89,0xd6,0x44,0x89,0xc7,
    0xff,0x15,0x82,0x09,0x00,0x00,0x41,0x89,0xc1,0x4c,0x8d,0x15,0x10,0x01,0x05,0x00,
    0xb8,0x01,0x00,0x00,0x00,0xf0,0x49,0x0f,0xc1,0x02,0x48,0x89,0xc1,0x83,0xe1,0x0f,
    0xc1,0xe1,0x05,0x4d,0x8d,0x54,0x0a,0x08,0x48,0xff,0xc0,0x49,0xc7,0x02,0x00,0x00,
    0x00,0x00,0x45,0x89,0x4a,0x08,0x41,0x89,0x7a,0x0c,0x49,0x89,0x5a,0x10,0x49,0x89,
    0x72,0x18,0x49,0x87,0x02,0x48,0x83,0xc4,0x20,0x5f,0x5e,0x5b,0xc3,
};

/* In --single-process, OnWebKitInitialized reaches the renderer branch of
 * the helper's CEF task dispatcher. Its original call to 0x11be60 drains the
 * browser's global I/O loop (0x1cea00), even while the browser thread runs it.
 * Use the TLS loop installed by the renderer adapter instead. Only this
 * renderer call site is redirected; the browser's original drain is intact.
 * RunUntilIdle still executes the pending work with its normal scoped state.
 * Source: tests/host/sc-render-drain.S. */
static const unsigned char ios_sch_render_drain[31] =
{
    0x48,0x83,0xec,0x28,0xe8,0x17,0x25,0xff,0xff,0x48,0x85,0xc0,0x74,0x0c,0x48,0x89,
    0xc1,0x48,0x83,0xc4,0x28,0xe9,0x26,0x1d,0xff,0xff,0x48,0x83,0xc4,0x28,0xc3,
};

/* Diagnose a separate --single-process assumption: the renderer's channel
 * response rebinds the process-wide IPC manager. Log its old/new channel and
 * caller before the original connect; at most eight lines, using the helper's
 * own logger. This does not replace the manager or change connection results.
 * Source: tests/host/sc-ipc-rebind.S. */
static const unsigned char ios_sch_ipc_rebind[256] =
{
    0x48,0x89,0x5c,0x24,0x18,0x9c,0x50,0x51,0x52,0x41,0x50,0x41,0x51,0x41,0x52,0x41,
    0x53,0x48,0x83,0xec,0x60,0xf3,0x0f,0x7f,0x04,0x24,0xf3,0x0f,0x7f,0x4c,0x24,0x10,
    0xf3,0x0f,0x7f,0x54,0x24,0x20,0xf3,0x0f,0x7f,0x5c,0x24,0x30,0xf3,0x0f,0x7f,0x64,
    0x24,0x40,0xf3,0x0f,0x7f,0x6c,0x24,0x50,0x83,0x3d,0x79,0x02,0x05,0x00,0x08,0x73,
    0x4c,0xb8,0x01,0x00,0x00,0x00,0xf0,0x0f,0xc1,0x05,0x6a,0x02,0x05,0x00,0x83,0xf8,
    0x08,0x73,0x3a,0x49,0x89,0xc8,0x4c,0x8d,0x49,0x50,0x48,0x83,0x79,0x68,0x07,0x76,
    0x04,0x4c,0x8b,0x49,0x50,0x48,0x83,0xec,0x48,0x48,0x89,0x54,0x24,0x20,0x48,0x8b,
    0x84,0x24,0xe8,0x00,0x00,0x00,0x48,0x89,0x44,0x24,0x28,0x48,0x8d,0x15,0x43,0x00,
    0x00,0x00,0x31,0xc9,0xe8,0x27,0x07,0xf9,0xff,0x48,0x83,0xc4,0x48,0xf3,0x0f,0x6f,
    0x04,0x24,0xf3,0x0f,0x6f,0x4c,0x24,0x10,0xf3,0x0f,0x6f,0x54,0x24,0x20,0xf3,0x0f,
    0x6f,0x5c,0x24,0x30,0xf3,0x0f,0x6f,0x64,0x24,0x40,0xf3,0x0f,0x6f,0x6c,0x24,0x50,
    0x48,0x83,0xc4,0x60,0x41,0x5b,0x41,0x5a,0x41,0x59,0x41,0x58,0x5a,0x59,0x58,0x9d,
    0xe9,0xc0,0x9f,0xec,0xff,0x5b,0x73,0x63,0x2d,0x69,0x70,0x63,0x5d,0x20,0x72,0x65,
    0x62,0x69,0x6e,0x64,0x20,0x6d,0x61,0x6e,0x61,0x67,0x65,0x72,0x3d,0x25,0x70,0x20,
    0x6f,0x6c,0x64,0x3d,0x25,0x2e,0x38,0x30,0x6c,0x73,0x20,0x6e,0x65,0x77,0x3d,0x25,
    0x2e,0x38,0x30,0x6c,0x73,0x20,0x63,0x61,0x6c,0x6c,0x65,0x72,0x3d,0x25,0x70,0x00,
};

/* A separately constructed renderer manager keeps the browser's channel and
 * disconnect callback intact. Initialize consumes its retained CefRefPtr;
 * the renderer uses its own role and waits for its channel response. The
 * browser's global loop and singleton remain owned by the original manager.
 * Source: tests/host/sc-ipc-split.S. */
static const unsigned char ios_sch_ipc_split[661] =
{
    0x9c,0x51,0x52,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x48,0x81,0xec,0x90,0x00,
    0x00,0x00,0xf3,0x0f,0x7f,0x44,0x24,0x30,0xf3,0x0f,0x7f,0x4c,0x24,0x40,0xf3,0x0f,
    0x7f,0x54,0x24,0x50,0xf3,0x0f,0x7f,0x5c,0x24,0x60,0xf3,0x0f,0x7f,0x64,0x24,0x70,
    0xf3,0x0f,0x7f,0xac,0x24,0x80,0x00,0x00,0x00,0xb9,0x06,0x00,0x00,0x00,0xff,0x15,
    0x24,0x0e,0x00,0x00,0x85,0xc0,0x0f,0x84,0x95,0x00,0x00,0x00,0x48,0x8b,0x05,0x6d,
    0x01,0x05,0x00,0x48,0x85,0xc0,0x0f,0x85,0x8c,0x00,0x00,0x00,0x48,0x83,0x3d,0x64,
    0x01,0x05,0x00,0x00,0x74,0x7b,0xb9,0x30,0x1a,0x00,0x00,0xe8,0x08,0xda,0xfb,0xff,
    0x48,0x85,0xc0,0x74,0x6c,0x48,0x89,0x05,0x44,0x01,0x05,0x00,0x48,0x89,0xc1,0xe8,
    0xec,0x96,0xec,0xff,0x48,0x8b,0x15,0x3d,0x01,0x05,0x00,0x48,0x89,0x54,0x24,0x20,
    0x48,0x8b,0x42,0x08,0x48,0x8d,0x4a,0x08,0x48,0x63,0x40,0x04,0x48,0x01,0xc1,0x48,
    0x8b,0x01,0xff,0x10,0x48,0x8d,0x54,0x24,0x20,0x48,0x8b,0x0d,0x10,0x01,0x05,0x00,
    0xe8,0x0b,0xad,0xec,0xff,0x0f,0xb6,0xc0,0x89,0x44,0x24,0x20,0x4c,0x8b,0x05,0xfd,
    0x00,0x05,0x00,0x4c,0x8b,0x0d,0x36,0xce,0x04,0x00,0x48,0x8d,0x15,0x94,0x01,0x00,
    0x00,0x31,0xc9,0xe8,0xd8,0x05,0xf9,0xff,0x48,0x8b,0x05,0xe1,0x00,0x05,0x00,0xeb,
    0x07,0x48,0x8b,0x05,0x18,0xce,0x04,0x00,0xf3,0x0f,0x6f,0x44,0x24,0x30,0xf3,0x0f,
    0x6f,0x4c,0x24,0x40,0xf3,0x0f,0x6f,0x54,0x24,0x50,0xf3,0x0f,0x6f,0x5c,0x24,0x60,
    0xf3,0x0f,0x6f,0x64,0x24,0x70,0xf3,0x0f,0x6f,0xac,0x24,0x80,0x00,0x00,0x00,0x48,
    0x81,0xc4,0x90,0x00,0x00,0x00,0x41,0x5b,0x41,0x5a,0x41,0x59,0x41,0x58,0x5a,0x59,
    0x9d,0xc3,0x48,0x89,0x5c,0x24,0x20,0x50,0x48,0x8b,0x02,0x48,0x89,0x05,0x96,0x00,
    0x05,0x00,0x58,0xe9,0x8d,0xac,0xec,0xff,0x9c,0x48,0x3b,0x1d,0x80,0x00,0x05,0x00,
    0x74,0x07,0x48,0x89,0x1d,0xb7,0xcd,0x04,0x00,0x9d,0xe9,0xeb,0x97,0xec,0xff,0x9c,
    0x4c,0x3b,0x35,0x69,0x00,0x05,0x00,0x75,0x05,0xb8,0x01,0x00,0x00,0x00,0x41,0x89,
    0x86,0xf0,0x00,0x00,0x00,0x9d,0xe9,0xb7,0xac,0xec,0xff,0x4c,0x3b,0x35,0x4e,0x00,
    0x05,0x00,0x74,0x05,0xe9,0x67,0xad,0xf9,0xff,0xc3,0x48,0x3b,0x0d,0x3f,0x00,0x05,
    0x00,0x74,0x05,0xe9,0xf8,0x9d,0xec,0xff,0xc3,0x9c,0x48,0x3b,0x3d,0x2f,0x00,0x05,
    0x00,0x0f,0x84,0xa4,0x00,0x00,0x00,0x50,0x51,0x52,0x41,0x50,0x41,0x51,0x41,0x52,
    0x41,0x53,0x48,0x81,0xec,0x90,0x00,0x00,0x00,0xf3,0x0f,0x7f,0x44,0x24,0x30,0xf3,
    0x0f,0x7f,0x4c,0x24,0x40,0xf3,0x0f,0x7f,0x54,0x24,0x50,0xf3,0x0f,0x7f,0x5c,0x24,
    0x60,0xf3,0x0f,0x7f,0x64,0x24,0x70,0xf3,0x0f,0x7f,0xac,0x24,0x80,0x00,0x00,0x00,
    0x48,0x8b,0x0d,0xe9,0xff,0x04,0x00,0x48,0x85,0xc9,0x74,0x19,0x48,0x89,0x4c,0x24,
    0x20,0xe8,0x6a,0x98,0xec,0xff,0x48,0x8b,0x4c,0x24,0x20,0xba,0x30,0x1a,0x00,0x00,
    0xe8,0xbf,0xd8,0xfb,0xff,0xf3,0x0f,0x6f,0x44,0x24,0x30,0xf3,0x0f,0x6f,0x4c,0x24,
    0x40,0xf3,0x0f,0x6f,0x54,0x24,0x50,0xf3,0x0f,0x6f,0x5c,0x24,0x60,0xf3,0x0f,0x6f,
    0x64,0x24,0x70,0xf3,0x0f,0x6f,0xac,0x24,0x80,0x00,0x00,0x00,0x48,0x81,0xc4,0x90,
    0x00,0x00,0x00,0x41,0x5b,0x41,0x5a,0x41,0x59,0x41,0x58,0x5a,0x59,0x58,0x9d,0x48,
    0x89,0x35,0xca,0xcc,0x04,0x00,0xe9,0x55,0x98,0xec,0xff,0x48,0xc7,0x05,0x7a,0xff,
    0x04,0x00,0x00,0x00,0x00,0x00,0x9d,0xe9,0x44,0x98,0xec,0xff,0x9c,0x50,0x48,0x83,
    0xec,0x20,0xe8,0xa9,0xa3,0xec,0xff,0x48,0x89,0xc3,0x48,0x83,0xc4,0x20,0x58,0x9d,
    0xe9,0x7e,0xcb,0xec,0xff,0x5b,0x73,0x63,0x2d,0x69,0x70,0x63,0x5d,0x20,0x72,0x65,
    0x6e,0x64,0x65,0x72,0x65,0x72,0x20,0x6d,0x61,0x6e,0x61,0x67,0x65,0x72,0x3d,0x25,
    0x70,0x20,0x62,0x72,0x6f,0x77,0x73,0x65,0x72,0x3d,0x25,0x70,0x20,0x69,0x6e,0x69,
    0x74,0x3d,0x25,0x75,0x00,
};

/* Record the source and caller of the early UI termination notification.
 * For the guarded window delegate call, also record its parent caller and
 * stored HWND. Other constructor callers do not expose those fields.
 * Resume the original constructor with its original inputs: no notification
 * is suppressed and its payload/delivery are unchanged. At most 16 records.
 * Source: tests/host/sc-ui-close.S. */
static const unsigned char ios_sch_ui_trace[190] =
{
    0x48,0x89,0x5c,0x24,0x10,0x51,0x52,0x48,0x83,0xec,0x38,0x83,0x3d,0x1e,0xff,0x04,
    0x00,0x10,0x73,0x5f,0xb8,0x01,0x00,0x00,0x00,0xf0,0x0f,0xc1,0x05,0x0f,0xff,0x04,
    0x00,0x83,0xf8,0x10,0x73,0x4d,0x44,0x8b,0x02,0x49,0x89,0xd1,0x48,0x8b,0x44,0x24,
    0x48,0x48,0x89,0x44,0x24,0x20,0x45,0x31,0xd2,0x4c,0x89,0x54,0x24,0x28,0x4c,0x89,
    0x54,0x24,0x30,0x4c,0x8d,0x15,0x35,0x11,0xeb,0xff,0x4c,0x39,0xd0,0x75,0x16,0x48,
    0x8b,0x44,0x24,0x78,0x48,0x89,0x44,0x24,0x28,0x49,0x8b,0x81,0x88,0x01,0x00,0x00,
    0x48,0x89,0x44,0x24,0x30,0x48,0x8d,0x15,0x12,0x00,0x00,0x00,0x31,0xc9,0xe8,0x9d,
    0x03,0xf9,0xff,0x48,0x83,0xc4,0x38,0x5a,0x59,0xe9,0x97,0x40,0xf5,0xff,0x5b,0x73,
    0x63,0x2d,0x75,0x69,0x5d,0x20,0x6d,0x73,0x67,0x32,0x30,0x30,0x30,0x35,0x20,0x76,
    0x61,0x6c,0x75,0x65,0x3d,0x25,0x75,0x20,0x73,0x6f,0x75,0x72,0x63,0x65,0x3d,0x25,
    0x70,0x20,0x63,0x61,0x6c,0x6c,0x65,0x72,0x3d,0x25,0x70,0x20,0x6f,0x72,0x69,0x67,
    0x69,0x6e,0x3d,0x25,0x70,0x20,0x68,0x77,0x6e,0x64,0x3d,0x25,0x70,0x00,
};

/* The helper code the thunk and the vtable change rely on (no relocations in
 * any of these ranges), as the SHA-256 of each range: the helper's own bytes
 * stay out of this source. */
static const struct { unsigned int rva; unsigned char len; unsigned char sha256[32]; } ios_sch_code[] =
{
    { IOS_SCH_GET_HANDLER, 0x3b, /* App::GetRenderProcessHandler / GetBrowserProcessHandler */
      { 0xbf,0xf1,0x79,0x08,0x92,0xbe,0x32,0xf0,0x8e,0x4a,0xd7,0x26,0x87,0x96,0x48,0x60,
        0xc0,0x66,0x80,0xfd,0x5e,0xb7,0x01,0x04,0x4b,0xc9,0xb4,0x42,0xaa,0x53,0xf8,0x55 } },
    { 0x69a0, 0x20, /* RendererApp::RendererApp(this, most_derived) */
      { 0x4e,0x07,0xd0,0x0c,0x75,0x05,0x64,0xaf,0x2c,0xca,0xca,0x6d,0x50,0x65,0xa3,0x7e,
        0x35,0xfe,0x67,0xb4,0x1a,0xc6,0x83,0xac,0x2a,0x79,0x8b,0x83,0x01,0x0f,0x08,0x44 } },
    { 0x13e708, 0x20, /* operator new */
      { 0x48,0x54,0x18,0xe9,0xe2,0x61,0x61,0xea,0x01,0x05,0x56,0x32,0xf4,0xc2,0xde,0x51,
        0x3b,0xee,0xe4,0xde,0x31,0x1b,0x14,0x2c,0x26,0xbd,0xfa,0x09,0x10,0x9d,0xd5,0x78 } },
    { IOS_SCH_GET_NULL, 0x0b,
      { 0x7e,0x90,0xc2,0x24,0x72,0x8a,0x8e,0x94,0xca,0x0a,0x73,0x81,0xc4,0x4b,0x1d,0x32,
        0x26,0x75,0x55,0xc7,0x55,0xfa,0xb1,0x86,0x74,0x12,0x92,0xf9,0x99,0xf2,0x54,0x46 } },
    /* app_get_render_process_handler (CefAppCppToC): the C++ call is slot 4 */
    { 0x7e267, 0x06,
      { 0xe7,0x74,0x7f,0xe6,0xd8,0xbe,0x61,0x5e,0x01,0x5d,0x32,0x45,0xb7,0x45,0x60,0xf3,
        0xa9,0x11,0x67,0xf3,0xa3,0x66,0x67,0xd8,0xc7,0x68,0x7b,0xe3,0xd7,0xc8,0x17,0xd3 } },
    { IOS_SCH_CURRENT_LOOP, 0x1f, /* MessageLoop::current (TLS initialization) */
      { 0x8a,0x32,0x50,0x49,0x56,0xac,0x6b,0x4c,0x61,0xe0,0x86,0x5e,0x83,0xfb,0xf9,0xc3,
        0x3c,0x43,0xdc,0xa9,0x3e,0xad,0x4d,0xc0,0xc6,0x59,0x0d,0xf9,0xd4,0x86,0x6d,0x54 } },
    { 0x1730ef, 0x10, /* MessageLoop::current (TLS getter tail) */
      { 0x5b,0x12,0xa4,0xa3,0x5c,0xcc,0x47,0x4f,0x3c,0x7e,0x75,0xf2,0xbd,0xb0,0x3b,0xae,
        0x79,0x02,0x30,0x12,0x08,0x81,0x2a,0xbd,0x39,0xa6,0x9d,0xdb,0xaa,0x1f,0x35,0xe3 } },
    { 0x176820, 0x09, /* TLS slot getter */
      { 0xb8,0x19,0x9b,0xa1,0x47,0x83,0x7d,0xcf,0x0e,0x15,0xb4,0x5f,0x3b,0x42,0x1d,0xf7,
        0x1d,0x31,0x0c,0x92,0xdf,0x5f,0x11,0xd6,0x43,0xa0,0x5f,0x02,0x4b,0x8f,0xc0,0x62 } },
    { IOS_SCH_LOOP_CTOR, 0x20, /* MessageLoop constructor */
      { 0x2f,0xf4,0x19,0xdc,0xd4,0xa6,0x8e,0xe7,0xaa,0xa7,0xbc,0x77,0x79,0xb0,0x7a,0x46,
        0xe8,0xe4,0x37,0x21,0xaa,0x19,0x8d,0xac,0x39,0x3b,0xda,0x86,0x6f,0xe2,0xb5,0xab } },
    { 0x17190a, 0x22, /* constructor installs this thread TLS loop */
      { 0xd1,0xc3,0x54,0xf1,0x2e,0x9e,0x53,0xa8,0x94,0x55,0x69,0x67,0xf1,0x32,0xad,0x20,
        0x69,0x31,0x0e,0xa4,0x89,0x02,0x5d,0xfd,0xc9,0x29,0xfd,0x41,0x67,0xae,0x14,0x73 } },
    { 0x1719b8, 0x19, /* constructor returns the loop */
      { 0x22,0xdc,0xce,0x41,0x82,0x58,0x6a,0xd4,0x99,0x1b,0x1d,0xa7,0x67,0x32,0x06,0xcc,
        0x19,0x96,0x29,0x33,0x39,0x9d,0x77,0x2e,0xfc,0xa2,0xf9,0xc1,0x69,0x73,0xe1,0x01 } },
    { IOS_SCH_LOOP_WORK, 0x20, /* DoWork */
      { 0x34,0x8f,0xed,0x98,0x95,0xa4,0xc7,0x2a,0x77,0xe8,0x00,0xd6,0x74,0xed,0xc4,0x5f,
        0x8a,0x8a,0xe2,0x5a,0x27,0xad,0x54,0x1a,0x3a,0xa0,0x6a,0xe4,0x18,0x71,0x3d,0xf7 } },
    { IOS_SCH_LOOP_DELAYED, 0x20, /* DoDelayedWork */
      { 0xaa,0xac,0x3b,0x50,0x8e,0x12,0x3e,0x76,0x82,0xcc,0xbe,0x44,0xbf,0xa9,0xfb,0x7c,
        0xd8,0xac,0x2e,0xbc,0xd3,0x9a,0x12,0xda,0x84,0x1c,0x5c,0x4b,0xfb,0x8b,0x5e,0xb6 } },
    { IOS_SCH_LOOP_IDLE, 0x20, /* DoIdleWork */
      { 0xb6,0x1e,0x07,0x66,0xa3,0x3c,0x55,0xa9,0x6b,0x7b,0x55,0xb1,0xc0,0x79,0x5c,0xee,
        0xb9,0x2a,0x93,0x0f,0xe2,0xa3,0xab,0x71,0xe8,0x7c,0xbf,0x74,0x0c,0x88,0x5f,0x52 } },
    { 0x1728b0, 0x40, /* scoped RunState layout and nesting */
      { 0x73,0x1e,0x73,0xa0,0xb2,0x9f,0x58,0x56,0x7a,0x17,0xb8,0xb5,0x93,0xf1,0x92,0x67,
        0x1f,0x2a,0xca,0x02,0xf2,0x1c,0x5c,0xa0,0x94,0x45,0x89,0xb1,0xad,0xab,0x70,0x32 } },
    { 0x1728f1, 0x1c, /* scoped RunState quit flag and restore */
      { 0xe5,0x39,0xde,0xc2,0x15,0x2a,0x4f,0x02,0x2b,0x08,0xfd,0xac,0x00,0x0e,0xdd,0xdc,
        0x2d,0x65,0xc3,0xa8,0xab,0xfa,0x56,0x01,0x07,0x08,0x0a,0x23,0xbb,0x52,0x31,0x43 } },
    { 0x174121, 0x07, /* MessagePumpWin::Run installs its stack RunState */
      { 0x09,0xca,0x84,0xfd,0xdb,0xbe,0xdb,0x9b,0x49,0x26,0x99,0x92,0x08,0xbb,0xf4,0xb9,
        0x35,0x14,0x26,0xe6,0xc1,0x19,0xef,0xff,0x65,0xc5,0x3e,0xc7,0xba,0xe1,0x8a,0x34 } },
    { 0x17412b, 0x09, /* Run restores the prior state and caller RBX */
      { 0x8b,0x8f,0x7f,0xd0,0x15,0xf4,0x66,0x74,0xe1,0x14,0x51,0xec,0x39,0x03,0x81,0x03,
        0x2d,0x8f,0x9e,0x16,0xfd,0x16,0x9b,0xa1,0x94,0x3b,0x14,0x98,0xc0,0x72,0x18,0x76 } },
    { 0x48f0f, 0x12, /* only the CEF TID_RENDERER branch reaches the patched call */
      { 0xa5,0x33,0x17,0x37,0x5a,0x81,0xe2,0x7f,0x54,0x41,0xe3,0xc9,0xb4,0x4c,0xef,0xca,
        0x39,0x59,0x15,0x78,0xb1,0x52,0x69,0x14,0xbf,0x1e,0x15,0xfa,0x66,0x3b,0x2d,0x41 } },
    { IOS_SCH_RENDER_DRAIN_SITE, 0x05,
      { 0x4e,0x1c,0x5e,0xdf,0x57,0x05,0x69,0x29,0x55,0x64,0x1b,0x60,0x21,0x31,0xa1,0x2c,
        0x8d,0x8f,0x93,0xa9,0x40,0x72,0x6e,0x4c,0xf2,0xdf,0x67,0x8e,0x48,0x96,0x8f,0x82 } },
    { 0x11be60, 0x11, /* original global browser drain remains unchanged */
      { 0xd3,0xbb,0xb6,0xee,0x32,0x9f,0x1c,0x48,0x41,0x66,0x45,0x24,0x5b,0x74,0x7c,0x88,
        0xea,0xaf,0x22,0x1c,0x52,0x4a,0xc3,0x23,0xf9,0xa1,0xa6,0x64,0x5d,0x5e,0xd8,0xe4 } },
    { IOS_SCH_IPC_CONNECT, 0x12, /* original connect prologue; replay the first instruction */
      { 0xa6,0x0d,0xa7,0xf4,0xe3,0x90,0xec,0x4e,0x38,0x20,0xbc,0xcf,0xa9,0x11,0x45,0x47,
        0x33,0xb2,0x79,0xd5,0xf6,0xb4,0x83,0x5d,0x5a,0x4f,0x62,0xf1,0xf2,0x4a,0x4d,0xcc } },
    { 0x4ac5b, 0x13, /* previous channel std::wstring, inline capacity 7 */
      { 0xea,0xad,0xf4,0x15,0xa2,0xcd,0x7d,0x2f,0x1a,0xa5,0x4f,0xb2,0x1c,0xac,0x76,0x1c,
        0xf6,0x4c,0x95,0xeb,0x75,0x82,0x28,0x33,0x0f,0x34,0xe4,0xcb,0xb5,0x3c,0x6a,0xa0 } },
    { IOS_SCH_RENDER_CHANNEL_REPLY, 0x19, /* renderer's Channel Response -> Connect(name, replace_old) */
      { 0x19,0xe9,0xb4,0xec,0x4b,0x2e,0xd8,0xa5,0x7f,0xa7,0xa2,0xa6,0x76,0xec,0x18,0x89,
        0xf7,0xca,0xaf,0x06,0x58,0xea,0x42,0xe1,0xa9,0x24,0x97,0x73,0xfb,0x98,0x69,0xe5 } },
    { 0x4add0, 0x3d, /* Connect removes the previous named channel only when replace_old is true */
      { 0x86,0x12,0xcb,0xa2,0xc0,0x74,0x0f,0x30,0xd2,0x55,0xb0,0x92,0x09,0x8c,0xb8,0xd3,
        0x5e,0x68,0xab,0xe6,0xd9,0x7f,0x12,0x58,0xcb,0x24,0xd5,0x99,0x7d,0x1d,0x8b,0x8e } },
    { 0x4abf0, 0xe, /* embedded IPC client appends a connection and increments its counts */
      { 0x1a,0x90,0x5d,0xa9,0xfd,0x37,0x16,0x45,0xff,0x9c,0x9a,0x1d,0x2b,0x30,0x26,0xfc,
        0x55,0x37,0x22,0xd4,0xf8,0xf3,0x1c,0xdb,0xcf,0x71,0x01,0xe1,0x47,0xd4,0xc3,0xef } },
    { 0x4af6f, 0x2c, /* explicit disconnect locates and closes only the named connection */
      { 0x43,0xd8,0x7c,0x93,0xb3,0x38,0x69,0x02,0x4e,0x93,0x46,0x6f,0xff,0x60,0xed,0x95,
        0x4d,0x7c,0x91,0x4e,0x9c,0xa0,0xb5,0x64,0x99,0x7d,0xda,0xd1,0x14,0x6e,0x5a,0x7a } },
    { 0x111340, 0x19, /* helper's existing variadic text logger */
      { 0xb9,0xe5,0xa5,0x4f,0x2d,0x30,0xba,0xea,0xa0,0x76,0x7c,0xbe,0xf3,0x81,0xa1,0xc3,
        0x5e,0x2d,0x2d,0x3f,0xce,0x48,0x62,0x7f,0x93,0x31,0x4d,0xe5,0x04,0x7b,0xd1,0x99 } },
    { 0x4b290, 0x8, /* original process-wide manager getter */
      { 0xb5,0x13,0xaa,0x18,0x97,0xf3,0xb3,0x32,0xd9,0x60,0xa5,0x72,0xa8,0x1c,0x53,0x59,
        0x1d,0x47,0x84,0xa9,0xe8,0x8e,0xf8,0x9a,0xca,0x43,0x4f,0x20,0x8b,0xac,0xd1,0xad } },
    { 0x4ba50, 0x5, /* Initialize entry; captures the live main command line */
      { 0x3e,0x66,0x9f,0x46,0xc2,0xd0,0xf4,0x82,0xb7,0x20,0xe4,0x37,0x17,0x86,0xb4,0x87,
        0xf5,0x6b,0x6c,0x56,0x5b,0x43,0x52,0x1a,0x5f,0x65,0xe8,0x99,0xcf,0xc7,0x87,0x95 } },
    { 0x4a5c3, 0x7, /* constructor singleton store */
      { 0xaf,0x40,0x73,0xa5,0x5f,0x20,0x24,0x59,0x87,0xd1,0x9b,0x14,0x50,0x92,0x2e,0xef,
        0xac,0xdf,0x68,0x45,0xd7,0x7d,0x05,0xb2,0xba,0xd2,0x48,0x09,0x67,0x98,0xde,0x40 } },
    { 0x4baab, 0x7, /* Initialize role store */
      { 0x0e,0x87,0x5d,0xc4,0x18,0xa1,0x92,0x01,0xc1,0xd2,0x6d,0x2f,0x91,0xb2,0x5c,0xd9,
        0x42,0x51,0xee,0x5a,0xbd,0xd5,0x67,0x91,0x7e,0x2a,0x3c,0xbc,0x04,0xf4,0x0d,0x0c } },
    { 0x4d255, 0xe, /* global browser loop initialization */
      { 0x1d,0x10,0xfd,0xcc,0x84,0xad,0x4d,0x72,0xac,0x59,0x11,0x88,0x17,0xd1,0x4e,0x69,
        0x33,0x90,0x83,0x65,0x67,0x20,0x25,0x08,0x3f,0xd1,0x7e,0x56,0xc4,0x9b,0xa3,0xcf } },
    { 0x4d2e0, 0x20, /* initial channel connection from the command line */
      { 0xf3,0x41,0x67,0x11,0xcb,0x5a,0x90,0x0e,0x6f,0x76,0x0a,0x8d,0xc9,0x29,0x41,0x91,
        0x93,0xcd,0x37,0x34,0x7c,0x64,0xa1,0x08,0x2f,0x6f,0x18,0x3f,0x86,0x9f,0x50,0x3c } },
    { 0x4a712, 0x11, /* destructor owned-object load and singleton clear */
      { 0x1e,0xcd,0x5c,0x3b,0xe8,0xd8,0x27,0x35,0x93,0xf4,0x44,0x4e,0xde,0xf1,0xd9,0xdc,
        0x7d,0xa7,0x87,0xe9,0x87,0x8c,0xe2,0xf5,0x7a,0x43,0x77,0xa5,0xd4,0x11,0xef,0x12 } },
    { 0x4a400, 0x2a, /* manager constructor ABI and initial fields */
      { 0x7c,0xf0,0x14,0x50,0x6e,0x58,0x18,0xa4,0x05,0xbe,0x4c,0x0b,0x9c,0xc9,0x77,0x1e,
        0xc8,0x66,0xa7,0x85,0xda,0x5b,0x64,0x75,0xea,0x26,0xe2,0xfb,0xe7,0x56,0x27,0xeb } },
    { 0x4a5b4, 0xf, /* embedded client construction and final owned-object field */
      { 0x8e,0xc2,0xb6,0x7c,0x85,0xf0,0xeb,0xcb,0x9a,0x10,0x95,0x14,0xd8,0xad,0x0f,0xe7,
        0xd3,0xa4,0xf3,0xe6,0x3f,0x64,0x3f,0x62,0xd4,0x76,0x47,0x81,0xd0,0xb0,0x04,0x5d } },
    { 0x4d408, 0x1e, /* Initialize consumes its by-value command-line reference */
      { 0xe8,0xcd,0xc5,0xe3,0x65,0x96,0xd4,0x39,0x5e,0x07,0xd4,0x6e,0xe0,0x65,0x11,0x5c,
        0xea,0xb3,0xe4,0x99,0x90,0x79,0x63,0x87,0xea,0xa6,0x85,0x13,0x21,0x2c,0xc5,0x3b } },
    { 0x4da6c, 0xc, /* inlined manager lookup, routed like the getter */
      { 0xec,0xdf,0x5a,0x02,0xf4,0xa4,0x81,0x39,0x69,0x91,0xe4,0x78,0xe0,0xcd,0x83,0x0e,
        0x2e,0xb9,0xe1,0xb2,0xe7,0xc1,0xaa,0x63,0x25,0x3d,0xd5,0x9e,0x33,0xfd,0x9b,0x2d } },
    { 0x13e708, 0x6, /* helper allocator */
      { 0x62,0x16,0x23,0xb2,0x92,0x26,0xf3,0x0f,0x50,0x05,0xd5,0x5f,0x71,0x9b,0xc1,0x5e,
        0x2c,0xba,0xda,0xf7,0xa1,0xae,0xaf,0xa0,0xb1,0xa2,0xf7,0x12,0x13,0x54,0x1d,0xd6 } },
    { 0x13e744, 0x6, /* helper sized deallocator */
      { 0x44,0x75,0x9e,0xb6,0x2a,0x9e,0x73,0x40,0xc2,0x81,0x32,0x00,0x54,0x1b,0x89,0x23,
        0x22,0xa8,0xd5,0xc3,0x26,0xca,0x76,0x38,0x61,0x41,0x81,0xaf,0xa3,0x94,0x7f,0x38 } },
    { IOS_SCH_UI_CTOR, 0x21, /* constructor inputs; R8/R9 are set before use */
      { 0xa6,0x75,0x1f,0x2a,0x0b,0x35,0x1c,0xb7,0xb2,0x25,0x84,0xe7,0x98,0x20,0x2d,0x32,
        0x7d,0x53,0xda,0xbd,0xc5,0x39,0x83,0xe2,0xc2,0x61,0x8d,0x2e,0xd0,0x37,0x42,0x5b } },
    { 0x12eb5, 0x5, /* first message 0x20005 constructor call */
      { 0x86,0x87,0xee,0x3c,0x02,0xbb,0xe7,0x5c,0x58,0x8e,0x72,0x76,0xf8,0x5f,0x77,0x27,
        0xe3,0x03,0x5a,0x83,0xd8,0x63,0x3a,0xeb,0x51,0xfc,0x28,0x2d,0xa0,0x37,0x3e,0x72 } },
    { 0x320aa, 0x5, /* second message 0x20005 constructor call */
      { 0xb1,0xad,0xfd,0x7b,0xe1,0x60,0x40,0x4f,0x2d,0x70,0xa0,0x86,0x7b,0x92,0x20,0x75,
        0x25,0x6f,0x32,0x40,0x64,0xab,0xc6,0x55,0xdd,0x97,0x89,0xcd,0xd3,0x83,0x39,0x49 } },
    { 0x32070, 0xf, /* delegate frame used to find its parent caller */
      { 0x52,0x10,0xcf,0xbe,0x1a,0x06,0x70,0x52,0x3d,0xff,0x9e,0xe2,0x6f,0x43,0x2b,0x98,
        0x55,0x12,0x63,0x9d,0x89,0x97,0x39,0xdf,0xd7,0x56,0x0c,0x1b,0x99,0x8d,0xe6,0xb6 } },
    { 0x320a3, 0x7, /* payload is the window owner's +0x10 field */
      { 0xf9,0xc7,0x19,0xd9,0x7e,0x0c,0x66,0x7d,0x7a,0x4f,0x48,0x72,0xc9,0xe6,0xca,0xb3,
        0xb1,0x39,0x52,0x02,0x94,0xb9,0x98,0x65,0x7d,0x50,0x55,0xc3,0xe4,0xd9,0xec,0x20 } },
    { 0x31f9a, 0x7, /* HWND is at owner+0x198, payload+0x188 */
      { 0xf5,0xfe,0x0d,0xe9,0xe2,0xe6,0x95,0xef,0x97,0x3f,0x7e,0x7f,0xd9,0x97,0x49,0x63,
        0x52,0xf7,0x8f,0x78,0xa6,0x6d,0xe4,0x3f,0xa2,0xc1,0xb4,0xd3,0xa0,0xc9,0x7a,0xc3 } },
    { IOS_SCH_WEBKIT, 0x20, /* original OnWebKitInitialized */
      { 0xbc,0x82,0x0b,0xdc,0x21,0xf3,0x40,0x92,0x13,0xf1,0xdc,0x15,0x6d,0xf0,0x7a,0x17,
        0x2a,0x96,0x76,0x0e,0x75,0x4f,0x1a,0x27,0xe8,0xc0,0x91,0x06,0xb8,0xea,0xf4,0x85 } },
};

/* Why `base` (SocialClubHelper.exe, mapped) cannot take the patch, or NULL when
 * it can; on success *vtbase is the guest base the CefApp vtables use (ptr when
 * the directory was applied, else the preferred base), which the thunk pointer
 * is written in. */
static const char *ios_sch_mismatch( const char *base, SIZE_T total_size, const IMAGE_NT_HEADERS *nt,
                                     const IMAGE_SECTION_HEADER *sec, ULONG64 *vtbase )
{
    const ULONG64 *vb = (const ULONG64 *)(base + IOS_SCH_VT_BROWSER);
    const ULONG64 *vr = (const ULONG64 *)(base + IOS_SCH_VT_RENDERER);
    const ULONG64 *vh = (const ULONG64 *)(base + IOS_SCH_VT_RPH);
    ULONG64 b = (ULONG64)(ULONG_PTR)base;
    int i, text = 0, data = 0;
    size_t k;

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return "not a 64-bit x64 image";
    if (nt->FileHeader.TimeDateStamp != IOS_SCH_STAMP || nt->OptionalHeader.SizeOfImage != IOS_SCH_SIZE ||
        total_size < IOS_SCH_SIZE) return "another build (TimeDateStamp / SizeOfImage)";
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (sec[i].VirtualAddress == IOS_SCH_TEXT && sec[i].Misc.VirtualSize == 0x17f34c &&
            sec[i].SizeOfRawData == 0x17f400 && (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) text = 1;
        if (sec[i].VirtualAddress == IOS_SCH_DATA && sec[i].Misc.VirtualSize == 0x43bc &&
            (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)) data = 1;
    }
    if (!text || !data) return "section layout differs";
    for (k = 0; k < sizeof(ios_sch_code) / sizeof(ios_sch_code[0]); k++)
    {
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256( base + ios_sch_code[k].rva, ios_sch_code[k].len, digest );
        if (memcmp( digest, ios_sch_code[k].sha256, sizeof(digest) )) return "code bytes differ";
    }
    /* The vtables carry guest pointers in one base -- ptr (directory applied)
     * or the preferred base (ml949 / sub-floor). Read it from one slot and
     * require the other three consistent, and the base one of the two. */
    *vtbase = vb[IOS_SCH_SLOT_BROWSER] - IOS_SCH_GET_HANDLER;
    if (*vtbase != b && *vtbase != IOS_SCH_IMAGE_BASE) return "CefApp vtable base is neither the view nor the preferred base";
    if (vb[IOS_SCH_SLOT_RENDERER] != *vtbase + IOS_SCH_GET_NULL ||
        vr[IOS_SCH_SLOT_BROWSER]  != *vtbase + IOS_SCH_GET_NULL ||
        vr[IOS_SCH_SLOT_RENDERER] != *vtbase + IOS_SCH_GET_HANDLER)
        return "CefApp vtables differ";
    if (vh[0] != *vtbase + IOS_SCH_WEBKIT) return "renderer OnWebKitInitialized differs";
    for (k = 0; k < sizeof(ios_sch_renderer_channels); k++)
        if (base[IOS_SCH_RENDER_CHANNEL_THUNK + k]) return "renderer channel .text tail not zero";
    for (k = 0; k < sizeof(ios_sch_thunk); k++)
        if (base[IOS_SCH_THUNK + k]) return ".text tail not zero";
    for (k = 0; k < sizeof(ios_sch_loop_thunk); k++)
        if (base[IOS_SCH_LOOP_INIT + k]) return "renderer loop .text tail not zero";
    for (k = 0; k < 64; k++)
        if (base[IOS_SCH_TASK + k]) return "renderer task .data tail not zero";
    for (k = 0; k < sizeof(ios_sch_run_trace); k++)
        if (base[IOS_SCH_RUN_INSTALL + k]) return "RunState trace .text tail not zero";
    for (k = 0; k < IOS_SCH_RUN_RING_SIZE; k++)
        if (base[IOS_SCH_RUN_RING + k]) return "RunState trace .data tail not zero";
    for (k = 0; k < sizeof(ios_sch_render_drain); k++)
        if (base[IOS_SCH_RENDER_DRAIN + k]) return "renderer drain .text tail not zero";
    for (k = 0; k < sizeof(ios_sch_ipc_rebind); k++)
        if (base[IOS_SCH_IPC_TRACE + k]) return "IPC trace .text tail not zero";
    if (*(const unsigned int *)(base + IOS_SCH_IPC_COUNT)) return "IPC trace counter not zero";
    for (k = 0; k < sizeof(ios_sch_ipc_split); k++)
        if (base[IOS_SCH_IPC_SPLIT + k]) return "IPC split .text tail not zero";
    for (k = 0; k < 16; k++)
        if (base[IOS_SCH_IPC_CONTEXT + k]) return "IPC split context not zero";
    for (k = 0; k < sizeof(ios_sch_ui_trace); k++)
        if (base[IOS_SCH_UI_TRACE + k]) return "UI notification trace .text tail not zero";
    if (*(const unsigned int *)(base + IOS_SCH_UI_COUNT)) return "UI notification trace counter not zero";
    if (*(const ULONG64 *)(base + IOS_SCH_CACHE)) return ".data tail not zero";
    return NULL;
}

static void ios_sc_render_handler_patch( char *base, SIZE_T total_size, const IMAGE_NT_HEADERS *nt,
                                         const IMAGE_SECTION_HEADER *sec, const UNICODE_STRING *nt_name )
{
    static int enabled = -1;
    const char *why;
    ULONG64 vtbase = 0;
    const char *ipc_setting = getenv( "MADEIRA_SC_IPC_SPLIT" );
    int ipc_split = !(ipc_setting && ipc_setting[0] == '0');

    if (enabled < 0)
    {
        const char *e = getenv( "MADEIRA_SC_RENDER_HANDLER" );
        enabled = !(e && e[0] == '0') && ios_sc_cef_enabled();
    }
    if (!enabled || !nt_name || !nt_name->Buffer ||
        !ios_sc_path_is_helper( nt_name->Buffer, nt_name->Length / sizeof(WCHAR) )) return;
    if ((why = ios_sch_mismatch( base, total_size, nt, sec, &vtbase )))
    {
        dprintf( 2, "[sc-rph] madeira-bcd: SocialClubHelper.exe at %p not patched: %s -- its pages get no "
                    "renderer bridge under --single-process (the launcher times out loading them)\n", base, why );
        return;
    }
    /* The thunk bytes go into the view (ptr); the slot carries the guest
     * pointer in the vtables' base (vtbase), which FEX runs through the alias. */
    memcpy( base + IOS_SCH_THUNK, ios_sch_thunk, sizeof(ios_sch_thunk) );
    memcpy( base + IOS_SCH_LOOP_INIT, ios_sch_loop_thunk, sizeof(ios_sch_loop_thunk) );
    memcpy( base + IOS_SCH_RUN_INSTALL, ios_sch_run_trace, sizeof(ios_sch_run_trace) );
    memcpy( base + IOS_SCH_RENDER_DRAIN, ios_sch_render_drain, sizeof(ios_sch_render_drain) );
    memcpy( base + IOS_SCH_IPC_TRACE, ios_sch_ipc_rebind, sizeof(ios_sch_ipc_rebind) );
    memcpy( base + IOS_SCH_UI_TRACE, ios_sch_ui_trace, sizeof(ios_sch_ui_trace) );
    {
        int32_t disp = (int32_t)(IOS_SCH_UI_TRACE - IOS_SCH_UI_CTOR - 5);
        base[IOS_SCH_UI_CTOR] = (char)0xe9;
        memcpy( base + IOS_SCH_UI_CTOR + 1, &disp, sizeof(disp) );
    }
    {
        int32_t disp = (int32_t)(IOS_SCH_IPC_TRACE - IOS_SCH_IPC_CONNECT - 5);
        base[IOS_SCH_IPC_CONNECT] = (char)0xe9;
        memcpy( base + IOS_SCH_IPC_CONNECT + 1, &disp, sizeof(disp) );
    }
    {
        int32_t disp = (int32_t)(IOS_SCH_RENDER_DRAIN - IOS_SCH_RENDER_DRAIN_SITE - 5);
        /* Keep CALL so the renderer dispatcher resumes after draining work. */
        base[IOS_SCH_RENDER_DRAIN_SITE] = (char)0xe8;
        memcpy( base + IOS_SCH_RENDER_DRAIN_SITE + 1, &disp, sizeof(disp) );
    }
    if (ipc_split)
    {
        /* Multiple pages share this renderer process. The helper's IPC client
         * already owns an indexed set of connections; a Channel Response must
         * add its channel without disconnecting the previous page's channel.
         * Keep the browser transport, explicit disconnects and window-close
         * notifications unchanged. The thunk also bounds the client's table;
         * the following TEST overwrites its flags. */
        static const struct { unsigned int site, dest, span; unsigned char opcode; } hook[] =
        {
            { 0x4b290, IOS_SCH_IPC_SPLIT, 7, 0xe9 },
            { 0x4ba50, IOS_SCH_IPC_CAPTURE, 5, 0xe9 },
            { 0x4a5c3, IOS_SCH_IPC_STORE, 7, 0xe9 },
            { 0x4baab, IOS_SCH_IPC_ROLE, 7, 0xe9 },
            { 0x4d255, IOS_SCH_IPC_GLOBAL_LOOP, 5, 0xe8 },
            { 0x4d2fb, IOS_SCH_IPC_INITIAL_CONNECT, 5, 0xe8 },
            { 0x4a719, IOS_SCH_IPC_DESTROY, 7, 0xe9 },
            { 0x4da6c, IOS_SCH_IPC_DIRECT, 7, 0xe9 },
            { IOS_SCH_RENDER_CHANNEL_KEEP, IOS_SCH_RENDER_CHANNEL_THUNK, 7, 0xe9 },
        };
        unsigned int k;
        memcpy( base + IOS_SCH_IPC_SPLIT, ios_sch_ipc_split, sizeof(ios_sch_ipc_split) );
        memcpy( base + IOS_SCH_RENDER_CHANNEL_THUNK, ios_sch_renderer_channels,
                sizeof(ios_sch_renderer_channels) );
        for (k = 0; k < ARRAY_SIZE(hook); k++)
        {
            int32_t disp = (int32_t)(hook[k].dest - hook[k].site - 5);
            base[hook[k].site] = (char)hook[k].opcode;
            memcpy( base + hook[k].site + 1, &disp, sizeof(disp) );
            memset( base + hook[k].site + 5, 0x90, hook[k].span - 5 );
        }
    }
    /* Both hooks branch within the image, so no new DIR64 pointer is needed. */
    {
        const unsigned int site[2] = { 0x174121, 0x17412b };
        const unsigned int dest[2] = { IOS_SCH_RUN_INSTALL, IOS_SCH_RUN_RESTORE };
        const unsigned int span[2] = { 7, 9 };
        int j;
        for (j = 0; j < 2; j++)
        {
            int32_t disp = (int32_t)(dest[j] - site[j] - 5);
            base[site[j]] = (char)0xe9;
            memcpy( base + site[j] + 1, &disp, sizeof(disp) );
            memset( base + site[j] + 5, 0x90, span[j] - 5 );
        }
    }

    /* Unlike the existing vtable slots, these new pointers have no DIR64
     * entries in the helper. Use the mapped view, not the vtable base: the
     * pool copy cannot rebase a new preferred-base function pointer.
     * The CEF task retains one owner reference for the image lifetime. CEF's
     * queued references can be released at shutdown without freeing the task
     * or a loop still referenced by the helper's IPC wait thread. */
    {
        ULONG64 callback_base = (ULONG64)(ULONG_PTR)base;
        ULONG64 task[8] = { 0x30, callback_base + IOS_SCH_TASK_ADD, callback_base + IOS_SCH_TASK_RELEASE,
                            callback_base + IOS_SCH_TASK_ONE, callback_base + IOS_SCH_TASK_ANY,
                            callback_base + IOS_SCH_LOOP_PUMP, 0, 1 };
        memcpy( base + IOS_SCH_TASK, task, sizeof(task) );
    }
    ((ULONG64 *)(base + IOS_SCH_VT_BROWSER))[IOS_SCH_SLOT_RENDERER] = vtbase + IOS_SCH_THUNK;
    ((ULONG64 *)(base + IOS_SCH_VT_RPH))[0] = vtbase + IOS_SCH_LOOP_INIT;
    dprintf( 2, "[sc-rph] madeira-bcd: SocialClubHelper.exe at %p (vtable base 0x%llx): the browser app now hands "
                "out its renderer app's CefRenderProcessHandler (thunk guest 0x%llx) -- the page bridge runs under "
                "--single-process; renderer MessageLoop adapter installed (CEF task, callback view base 0x%llx, "
                "10 ms delay, 32-work budget); bounded I/O RunState trace installed; "
                "renderer startup drains its own TLS loop; bounded IPC rebind trace installed; "
                "bounded UI notification trace installed; %s "
                "(MADEIRA_SC_RENDER_HANDLER=0 turns it off)\n",
             base, (unsigned long long)vtbase, (unsigned long long)(vtbase + IOS_SCH_THUNK),
             (unsigned long long)(ULONG_PTR)base,
             ipc_split ? "separate renderer IPC manager installed; renderer channels retained" : "IPC split disabled" );
}

/* Does the calling pseudo-process have socialclub.dll mapped? The table is read
 * under the pool lock, the images' export names outside it (the caller holds
 * virtual_mutex, so none of this process's images can be unmapped meanwhile). */
static int ios_sc_current_has_socialclub(void)
{
    void *peb = ios_jit_current_peb();
    struct { void *base; size_t size; } mine[256];
    int i, n = 0;

    if (!peb) return 0;
    pthread_mutex_lock( &ios_pool_lock );
    for (i = 0; i < ios_jit_mapping_count && n < (int)ARRAY_SIZE(mine); i++)
    {
        if (!ios_jit_mappings[i].pe_base || !ios_jit_mappings[i].size || ios_jit_mappings[i].unmapped) continue;
        if (ios_jit_mappings[i].map_peb != peb) continue;
        mine[n].base = ios_jit_mappings[i].pe_base;
        mine[n].size = ios_jit_mappings[i].size;
        n++;
    }
    pthread_mutex_unlock( &ios_pool_lock );
    for (i = 0; i < n; i++)
        if (ios_sc_name_is( ios_pe_module_name( mine[i].base, mine[i].size ), "socialclub.dll" )) return 1;
    return 0;
}

/* The images a Social Club client gets no pool copy of: libcef.dll (Chromium
 * runs in SocialClubHelper.exe) and NVIDIA's DLSS / frame generation runtimes,
 * which need NVIDIA's driver and can never run on Metal. GTA log 2026-10-02
 * 21:26: nvngx_dlss.dll's 28 MB copy left the first helper's libcef.dll 1.8 MB
 * short of the 239.75 MB it needs below the pool-split hole. */
static int ios_sc_refused_name( const char *module )
{
    return ios_sc_name_is( module, "libcef.dll" ) || ios_sc_name_is( module, "nvngx_dlss.dll" ) ||
           ios_sc_name_is( module, "nvngx_dlssg.dll" );
}

/* env.MADEIRA_SC_GAME_CEF = 1 (experiment): the game keeps its libcef.dll.
 * GTA log 2026-10-02 23:03 (file trace): GTA5_Enhanced.exe's socialclub.dll
 * probes the Social Club files, loads libcef.dll -- refused here -- and later
 * the helper connects (OnChannelConnected) but the game never asks it for a UI.
 * In the owner's working Proton log the game process loads chrome_elf.dll and
 * libcef.dll right after socialclub.dll (2028.2 s) and keeps both loaded until
 * it exits, so the refusal is the one difference left in the game process. */
static int ios_sc_game_cef(void)
{
    static int on = -1;
    if (on < 0)
    {
        const char *e = getenv( "MADEIRA_SC_GAME_CEF" );
        on = e && e[0] == '1';
    }
    return on;
}

/* The decision, separated from the lookups for the host test: refuse the copy
 * of `module` when it is one of those, the switch is on, the process is not
 * the helper and it is a Social Club client; `game_cef` keeps libcef.dll. */
static int ios_sc_cef_refuse( const char *module, int enabled, int is_helper, int has_socialclub, int game_cef )
{
    if (game_cef && ios_sc_name_is( module, "libcef.dll" )) return 0;
    return enabled && !is_helper && has_socialclub && ios_sc_refused_name( module );
}

/* A pool copy refused on this thread: 1 = pool exhausted, 2 = refused by
 * ios_sc_cef_refuse (a Social Club client's libcef.dll / DLSS runtime).
 * map_image_into_view then fails the load instead of mapping code that can
 * never run -- except a resource-only map of a refused image (see
 * ios_resource_only_map), which succeeds without executable code.
 * Thread-local: set and read by the one thread mapping. */
static _Thread_local int ios_jit_copy_refused;

/* madeira-bcd: an image view the loader is not mapping. Wine's loader
 * (ntdll load_dll) sets TEB ArbitraryUserPointer to the DLL name around the
 * map; kernelbase's LoadLibraryExW(LOAD_LIBRARY_AS_IMAGE_RESOURCE) -- what
 * GetFileVersionInfo uses -- maps the image section without it ("[map-notify]
 * SKIP (no ArbitraryUserPointer)"). GTA log 2026-10-02 23:39: the game's
 * socialclub.dll checks every Social Club component's version that way
 * ("Could not get libcef version" in socialclub.dll), and the refused libcef
 * copy failed that version query; allowed (env.MADEIRA_SC_GAME_CEF = 1) it
 * cost a 240 MB pool copy that nothing ever executed and left the helper's own
 * libcef.dll EXHAUSTED. A resource-only map of a policy-refused image now maps
 * without a pool copy and without exec; the code never runs there. */
static int ios_resource_only_map( int refused, const void *arbitrary_user_pointer )
{
    return refused == 2 && !arbitrary_user_pointer;
}

/* madeira-bcd: ANY image view the loader is not mapping and that asks for no
 * execute access gets no pool copy either -- kernelbase maps
 * LOAD_LIBRARY_AS_IMAGE_RESOURCE with FILE_MAP_READ (PAGE_READONLY). GTA build
 * 364 (2026-10-03 21:00): PlayGTAV.exe copied Launcher.exe (32 MB) twice for two
 * version queries and kept both copies until it exited; the pool ran out 1.4 s
 * later. Set by virtual_map_section around the map, cleared by
 * map_image_into_view for an image with a CLR header (CoreCLR maps its R2R
 * assemblies this way and runs code from them); mprotect_exec then refuses the
 * copy with 2, so ios_resource_only_map maps the view without exec. A later
 * NtProtectVirtualMemory(PAGE_EXECUTE*) on the view still copies (the flag is
 * clear by then). env.MADEIRA_RESOURCE_MAP_COPY = 1 copies as before. */
static _Thread_local int ios_map_resource_view;

static int ios_resource_map_nocopy(void)
{
    static int on = -1;
    if (on < 0)
    {
        const char *e = getenv( "MADEIRA_RESOURCE_MAP_COPY" );
        on = !(e && e[0] == '1' && !e[1]);
    }
    return on;
}

/* Social Club's PartitionAlloc pools (env.MADEIRA_SC_PA_POOLS = 1, opt-in).
 *
 * Its chrome_elf.dll reserves PartitionAlloc's core pools GLUED: one 32 GB
 * reservation, regular pool then BackupRefPtr pool, on a 32 GB boundary
 * (glue_core_pools, on by default since Chromium 128 -- which dates this build:
 * the 4 GB pools Chromium <= 110 used on Windows before 8.1 are long gone, and
 * kPoolMaxSize is a 16 GB constant on 64-bit Windows, so neither a Windows
 * version nor a command-line switch makes the request smaller). In the
 * 512 GB map the only such boundary outside the GPU carveout and the guest
 * window is 0x7800000000, and its upper 16 GB is FEX's arena, whose views start
 * at its very bottom ([va-arena] 0x7c00000000+) -- exactly where the BRP pool
 * hands out its first super pages. --disable-features=PartitionAllocBackupRefPtr
 * cannot be trusted to keep PartitionAlloc out of it: Steam's CEF here kept BRP
 * on with the switch (12 MB committed in its BRP pool, see the ml434 note; ml616
 * [brp-contain]). So, opted in, Wine boots with FEX's arena 4 GB higher,
 * [0x7d00000000, 0x8000000000) = 12 GB (FEX uses ~0.5 GB of it in GTA's logs),
 * and holds [0x7c00000000, 0x7d00000000) natively until SocialClubHelper.exe
 * asks: ios_sc_glued_pools then reserves [0x7800000000, 0x7d00000000) for real
 * -- the whole regular pool and the first 4 GB of the BRP pool, which
 * PartitionAlloc fills from the bottom -- and reports the 32 GB it asked for.
 * The remaining 12 GB of the BRP pool lie over FEX's arena and are reached only
 * past 4 GB of BRP super pages. */
#define IOS_SC_GLUED_BASE    0x7800000000ULL
#define IOS_SC_GLUED_SIZE    0x800000000ULL     /* 32 GB, what PartitionAlloc asks for */
#define IOS_SC_BRP_HOLD_BASE 0x7c00000000ULL
#define IOS_SC_BRP_HOLD_SIZE 0x100000000ULL     /* 4 GB */
#define IOS_SC_ARENA_BASE    0x7d00000000ULL
#define IOS_SC_ARENA_SIZE    0x300000000ULL     /* 12 GB */
static int ios_sc_brp_held;        /* [IOS_SC_BRP_HOLD_BASE, +4 GB) is held natively right now */
static int ios_sc_brp_layout;      /* the arena was moved for it at boot */

/* Social Club layout 2 (env.MADEIRA_SC_PA_POOLS = 2, opt-in; the app then puts
 * the JIT pool's RW alias at IOS_SC2_RW_ALIAS and holds [0x7000000000, +4 GB)
 * before Wine starts).
 *
 * A single-process Chromium of Chromium 128+ asks for THREE blocks of 32 GB on
 * a 32 GB boundary, and the 512 GB map has two such boundaries outside the GPU
 * carveout, 0x7000000000 and 0x7800000000:
 *   - chrome_elf.dll's PartitionAlloc (glued pools, jumbo#1 in the 18:24 log),
 *   - libcef.dll's own PartitionAlloc (jumbo#3; it died in FreePages on the
 *     soft grant 0x7400000000, STATUS_FREE_VM_NOT_AT_BASE in R10),
 *   - Oilpan's caged heap (CPPGC_POINTER_COMPRESSION + larger cage reserve
 *     2 x 16 GB aligned to 32 GB; the heap is [base+16 GB, +16 GB) (gin's
 *     kCageSize), handed out from its bottom, and 4 GB of it are real here).
 * Each PartitionAlloc copy then asks for 16 GB more, page-aligned at a random
 * hint (build 340: chrome_elf.dll jumbo#2, libcef.dll jumbo#4-8): its metadata
 * region (PartitionAddressSpace::InitMetadataRegionAndOffsets, Chromium 142+,
 * every client from 143). The metadata of the super page at pool offset X is
 * the 4 KB page at region + X + 4 KB (regular pool), + 12 KB (BRP pool),
 * + 20 KB (configurable pool), committed when the super page is first used.
 * What each really touches:
 *   - PartitionAlloc hands out super pages first-fit from the bottom of a pool
 *     (AddressPoolManager::Pool::FindChunk), and with BackupRefPtr off nothing
 *     goes to the BRP half; raw_ptr checks the BRP half of ITS OWN instance's
 *     block only. So a PartitionAlloc block needs its bottom free and its BRP
 *     half free of anything that instance's code points to.
 *   - A metadata region is used as far as the highest super page offset of
 *     its pools: < 4 GB for the regular pools here, < 8 GB for libcef's
 *     configurable pool (inside the V8 cage).
 *   - Oilpan never touches the lower 16 GB of its reservation.
 * Layout 2 (64 GB):
 *   [0x7000000000, 0x7100000000)  libcef.dll's regular pool, 4 GB really reserved
 *   [0x7100000000, 0x73ffff0000)  furniture window (floor 0x7100000000; 12 GB)
 *   [0x7400000000, 0x7600000000)  chrome_elf.dll's metadata region, 8 GB of 16
 *   [0x7600000000, 0x7800000000)  libcef.dll's metadata region, 8 GB of 16 --
 *                                 both in libcef's BRP half: PartitionAlloc's
 *                                 own memory only
 *   [0x7800000000, 0x7900000000)  chrome_elf.dll's regular pool, 4 GB
 *   [0x7900000000, +pool)         JIT pool RW alias (host-only, never a guest pointer)
 *   [0x7a00000000, 0x7c00000000)  V8 sandbox (its partially reserved 8 GB) / cage holdback
 *   [0x7c00000000, 0x7d00000000)  Oilpan's cage: its 32 GB block is chrome_elf's,
 *                                 0x7800000000, so it lies in chrome_elf's BRP half
 *   [0x7d00000000, 0x8000000000)  FEX arena, 12 GB (as layout 1)
 * The first 32 GB ask of SocialClubHelper.exe is chrome_elf.dll's (libcef.dll
 * imports it, so it initialises first), the second libcef.dll's; the third is
 * Oilpan's. Blink reserves Oilpan's cage BEFORE V8 initialises (Chromium 142:
 * InProcessRendererThread::Init -> Platform::InitializeBlink -> ProcessHeap::Init
 * -> cppgc::InitializeProcess; V8::Initialize runs later in RenderThreadImpl),
 * and V8 reserves its sandbox through VirtualAlloc2, i.e.
 * NtAllocateVirtualMemoryEx, which never comes here -- so a 32 GB ask at a 32 GB
 * boundary after both PartitionAlloc blocks can only be Oilpan's (the old rule
 * waited for the V8 cage and refused it). V8's
 * 8 GB sandbox step gets the cage in NtAllocateVirtualMemoryEx (ios_sc2_ex_cage).
 * A metadata region is asked for right after its pools, before the V8 cage, at a
 * hint that is not 4 GB-aligned. Every slot is held natively (PROT_NONE, no view)
 * until its ask. */
#define IOS_SC2_POOL_REAL   0x100000000ULL     /* 4 GB really reserved per PartitionAlloc block */
#define IOS_SC2_L_BASE      0x7000000000ULL
#define IOS_SC2_FLOOR       0x7100000000ULL
#define IOS_SC2_J2_BASE     0x7400000000ULL    /* chrome_elf.dll's metadata region */
#define IOS_SC2_J2L_BASE    0x7600000000ULL    /* libcef.dll's metadata region */
#define IOS_SC2_MD_ASK      0x400000000ULL     /* 16 GB asked per metadata region */
#define IOS_SC2_MD_REAL     0x200000000ULL     /* 8 GB really reserved */
#define IOS_SC2_SUPER_PAGE  0x200000ULL        /* PartitionAlloc's super page */
#define IOS_SC2_E_BASE      0x7800000000ULL
#define IOS_SC2_RW_ALIAS    0x7900000000ULL
#define IOS_SC2_RW_MAX      0x100000000ULL     /* the alias must end below the cage */
#define IOS_SC2_CAGE_BASE   0x7a00000000ULL
#define IOS_SC2_OILPAN_BASE 0x7c00000000ULL
#define IOS_SC2_OILPAN_SIZE 0x100000000ULL

enum { IOS_SC2_NONE, IOS_SC2_E, IOS_SC2_L, IOS_SC2_J2, IOS_SC2_J2L, IOS_SC2_OILPAN, IOS_SC2_REFUSE };
/* grant kinds beyond the slots */
enum { IOS_SC_K_V1 = 8, IOS_SC_K_CAGE, IOS_SC_K_OTHER };

/* Not const: env.MADEIRA_RDR2_VA_HOLD changes three entries at boot (ios_sc2_rdr2_geometry). */
static struct { uint64_t base, size; const char *what; } ios_sc2_slots[] =
{
    [IOS_SC2_E]      = { IOS_SC2_E_BASE,      IOS_SC2_POOL_REAL,   "chrome_elf.dll's PartitionAlloc pools" },
    [IOS_SC2_L]      = { IOS_SC2_L_BASE,      IOS_SC2_POOL_REAL,   "libcef.dll's PartitionAlloc pools" },
    [IOS_SC2_J2]     = { IOS_SC2_J2_BASE,     IOS_SC2_MD_REAL,     "chrome_elf.dll's PartitionAlloc metadata" },
    [IOS_SC2_J2L]    = { IOS_SC2_J2L_BASE,    IOS_SC2_MD_REAL,     "libcef.dll's PartitionAlloc metadata" },
    [IOS_SC2_OILPAN] = { IOS_SC2_OILPAN_BASE, IOS_SC2_OILPAN_SIZE, "Oilpan's caged heap" },
};
static unsigned ios_sc2_held;      /* bit k: slot k held natively right now */
static uint64_t ios_sc2_floor = IOS_SC2_FLOOR;   /* the furniture's floor: IOS_SC2_RDR2_FLOOR in that geometry */
static uint64_t ios_sc2_arena_lo = IOS_SC_ARENA_BASE;   /* the FEX arena's start: IOS_SC2_RDR2_ARENA_BASE there */

/* madeira-bcd (RDR2): layout 2 with room for RDR2.exe's start-up reserve.
 * Opt-in: env.MADEIRA_RDR2_VA_HOLD = 1, read only with layout 2; default off,
 * and off nothing below changes.
 *
 * RDR2.exe reserves 8960 MB in one block as it starts (build 457, log
 * 2026-10-08 21:20:59: the band's largest gap was 2775 MB, so it showed
 * "exited unexpectedly"). Layout 2 is sized for GTA V, and three of its
 * regions are far larger than what Social Club uses:
 *   - libcef.dll's pools: 4 GB real; no GTA V log (builds 451-457) has a
 *     growth line, so it never committed past 256 MB; 153 MB at 457's failure.
 *   - libcef.dll's metadata: 8 GB real; it follows those pools (the super
 *     page at pool offset X has its metadata at region + X + 4/12 KB).
 *   - chrome_elf.dll's metadata: 8 GB real; it follows chrome_elf.dll's pools,
 *     which reached +6450 MB in GTA V's longest session (455, 16:38:52).
 * With the switch the 8960 MB below chrome_elf.dll's pools, [0x75d0000000,
 * 0x7800000000), is held from boot as the jumbo holdback
 * (ios_jumbo_holdback_take): the first 8960 MB reserve the kernel cannot
 * place gets it, and nothing smaller (ios_jumbo_hold_min). Social Club's large
 * asks are its layout 2 slots, V8's VirtualAlloc2 (never that path) and one
 * hinted 1 GB.
 *
 * Build 460 (log 2026-10-08 23:59:11) then hung 4 minutes into the story: the
 * furniture window was full (12280 of 12288 MB: Social Club's V8 tables, 1.1 GB
 * of Metal's IOAccelerator mappings the kernel put there, RDR2's and every
 * process's stacks) and RDR2 could not create a thread (64 x "[thr-create]
 * FAILED at kernel stack"). Its censuses measured libcef.dll's pools at
 * +8 MB, its metadata at +154..166 MB and chrome_elf.dll's metadata (libcef's
 * BackupRefPtr data plus chrome_elf's own pages) at +158..174 MB. So the
 * furniture now takes most of the app's hold:
 *   [0x7000000000, +256 MB)   libcef.dll's pools
 *   [0x7010000000, ceiling)   furniture (floor IOS_SC2_RDR2_FLOOR: +3.75 GB)
 *   [0x7400000000, +6.25 GB)  chrome_elf.dll's metadata (libcef's BRP half starts here too)
 *   [0x7590000000, +1 GB)     libcef.dll's metadata
 *   [0x75d0000000, +8960 MB)  RDR2.exe's hold
 * The same run's FEX arena was 76-84 % used (9.1-10.4 of 12 GB, ~35 MB per
 * thread at 263 threads), the next wall once more threads fit, while
 * Oilpan's 4 GB cage used 21-33 MB. So Oilpan keeps 1 GB and the arena
 * starts right above it:
 *   [0x7c00000000, +1 GB)     Oilpan's caged heap
 *   [0x7c40000000, top)       FEX arena, 15 GB (IOS_SC2_RDR2_ARENA_BASE)
 * The RW alias, chrome_elf.dll's pools and the V8 cage keep their places. */
#define IOS_SC2_RDR2_HOLD_SIZE 0x230000000ULL   /* RDR2.exe's 8960 MB */
#define IOS_SC2_RDR2_HOLD_BASE (IOS_SC2_E_BASE - IOS_SC2_RDR2_HOLD_SIZE)
#define IOS_SC2_RDR2_L_REAL    0x10000000ULL    /* 256 MB of libcef.dll's pools */
#define IOS_SC2_RDR2_FLOOR     (IOS_SC2_L_BASE + IOS_SC2_RDR2_L_REAL)   /* ios_usable_va_floor_get */
#define IOS_SC2_RDR2_J2L_REAL  0x40000000ULL    /* 1 GB of libcef.dll's metadata */
#define IOS_SC2_RDR2_J2L_BASE  (IOS_SC2_RDR2_HOLD_BASE - IOS_SC2_RDR2_J2L_REAL)
#define IOS_SC2_RDR2_OILPAN_REAL 0x40000000ULL  /* 1 GB of Oilpan's caged heap */
#define IOS_SC2_RDR2_ARENA_BASE (IOS_SC2_OILPAN_BASE + IOS_SC2_RDR2_OILPAN_REAL)

static int ios_sc2_rdr2_hold_enabled(void)
{
    static int on = -1;
    if (on < 0)
    {
        /* 1: Social Club layout 2 keeps 8960 MB free for RDR2.exe (smaller PartitionAlloc regions); default 0. */
        const char *e = getenv( "MADEIRA_RDR2_VA_HOLD" );
        on = e && e[0] == '1' && !e[1];
    }
    return on;
}

static void ios_sc2_rdr2_geometry(void)
{
    ios_sc2_slots[IOS_SC2_L].size = IOS_SC2_RDR2_L_REAL;
    ios_sc2_slots[IOS_SC2_J2L].base = IOS_SC2_RDR2_J2L_BASE;
    ios_sc2_slots[IOS_SC2_J2L].size = IOS_SC2_RDR2_J2L_REAL;
    ios_sc2_slots[IOS_SC2_J2].size = IOS_SC2_RDR2_J2L_BASE - IOS_SC2_J2_BASE;
    ios_sc2_slots[IOS_SC2_OILPAN].size = IOS_SC2_RDR2_OILPAN_REAL;
    ios_sc2_floor = IOS_SC2_RDR2_FLOOR;
    ios_sc2_arena_lo = IOS_SC2_RDR2_ARENA_BASE;
    ios_sc2_rdr2 = 1;
}

/* env.MADEIRA_SC_PA_POOLS, the RW alias base and the pool span -> layout 0
 * (off), 1 or 2. Layout 2 needs the alias where the app put it for it, ending
 * below the cage. */
static int ios_sc_layout_pick( const char *env, unsigned long long rw_alias, unsigned long long span )
{
    if (!env || (env[0] != '1' && env[0] != '2')) return 0;
    if (env[0] == '2' && rw_alias == IOS_SC2_RW_ALIAS && span && span <= IOS_SC2_RW_MAX) return 2;
    return 1;
}

static int ios_sc_layout(void)
{
    if (ios_sc_layout_mode < 0)
    {
        const char *e = getenv( "MADEIRA_SC_PA_POOLS" ), *rw = getenv( "WINE_IOS_JIT_RW" );
        const char *sz = getenv( "WINE_IOS_JIT_SIZE" ), *rx = getenv( "WINE_IOS_JIT_RX" );
        const char *low = getenv( "WINE_IOS_JIT_TAIL_REGION" );
        unsigned long long a = rw ? strtoull( rw, NULL, 16 ) : 0, n = sz ? strtoull( sz, NULL, 16 ) : 0;
        unsigned long long x = rx ? strtoull( rx, NULL, 16 ) : 0;
        uint64_t lrx = 0, lsz = 0, lo = a, span = n;
        int m;
        /* madeira-bcd pool-low: the app's one RW reservation starts with region C's
         * alias, at 0x7900000000 for layout 2; the pool's own alias lies above it. */
        if (low && ios_pool_low_parse( low, x, a, n, &lrx, &lsz ))
            ios_pool_alias_extent( x, a, n, lrx, lsz, &lo, &span );
        m = ios_sc_layout_pick( e, lo, span );
        if (e && e[0] == '2' && m != 2)
            dprintf( 2, "[sc-cef] env.MADEIRA_SC_PA_POOLS=2 needs the JIT pool's RW alias at 0x%llx (it is at "
                        "0x%llx, 0x%llx bytes): layout 1\n", IOS_SC2_RW_ALIAS,
                     (unsigned long long)lo, (unsigned long long)span );
        ios_sc_layout_mode = m;
    }
    return ios_sc_layout_mode;
}

/* madeira-bcd (RDR2): what each piece of the 64 GB band really uses. Opt-in,
 * logging only: env.MADEIRA_BAND_CENSUS = 1 (default off).
 *
 * RDR2.exe reserves 8960 MB in one block as it starts (upstream: the larger
 * of 7/8 of the reported memory and 8960 MB). In its first run
 * (build 457, log 2026-10-08 21:20:59) that failed: only [0x7000000000,
 * 0x8000000000) has room for a block that size, Social Club's layout 2, the
 * furniture and the FEX arena fill it, and the largest gap left was 2775 MB.
 * Layout 2's pieces are sized for GTA V. Whether one of them can give up room
 * for RDR2 depends on how much of it is used, which nothing measured:
 * [bigres-use] counts commit calls, not pages, and [slot#N] counts mappings,
 * which our own PROT_NONE holds fill.
 *
 * One mach_vm_region walk over the band; each region is split over the
 * pieces it touches. Per piece: regions, mapped, used (any access, i.e.
 * committed), resident and dirty (dirtied + compressed) MB, the highest used
 * address as an offset into the piece (now and the highest seen this
 * session), and the largest unmapped gap. Resident and dirty pages count in
 * the piece where their region starts. Then the band's largest gap, aligned
 * to 64 KB as Wine places a reserve, and whether 8960 MB fits there. Runs with
 * the periodic slot probe and at a failed large reserve, 64 times at most. */
#define IOS_BAND_LO         0x7000000000ULL
#define IOS_BAND_HI         0x8000000000ULL
#define IOS_BAND_RDR2_ASK   0x230000000ULL     /* RDR2.exe's 8960 MB */
#define IOS_BAND_PIECES_MAX 12

struct ios_band_piece
{
    uint64_t lo, hi;
    const char *what;
    unsigned regions;
    uint64_t mapped, used, resident, dirty, top, gap;
};

static int ios_band_census_enabled(void)
{
    static int on = -1;
    if (on < 0)
    {
        /* 1: log what each piece of [0x7000000000, 0x8000000000) uses (RDR2's 8960 MB reserve); default 0. */
        const char *e = getenv( "MADEIRA_BAND_CENSUS" );
        on = e && e[0] == '1' && !e[1];
    }
    return on;
}

/* The pieces in address order, covering the band without gaps. The JIT pool's
 * RW alias [rw_lo, rw_hi) gets its own piece in layout 2 when it starts at
 * IOS_SC2_RW_ALIAS and ends below the cage; rdr2: MADEIRA_RDR2_VA_HOLD's
 * geometry (ios_sc2_rdr2_geometry). */
static int ios_band_pieces( struct ios_band_piece *p, int layout, int rdr2, uint64_t rw_lo, uint64_t rw_hi )
{
    int i, n = 0;

    memset( p, 0, sizeof(*p) * IOS_BAND_PIECES_MAX );
    if (layout == 2 && rdr2)
    {
        p[n].lo = IOS_SC2_L_BASE;          p[n++].what = "libcef.dll's pools";
        p[n].lo = IOS_SC2_RDR2_FLOOR;      p[n++].what = "furniture";
        p[n].lo = IOS_SC2_J2_BASE;         p[n++].what = "chrome_elf.dll's metadata";
        p[n].lo = IOS_SC2_RDR2_J2L_BASE;   p[n++].what = "libcef.dll's metadata";
        p[n].lo = IOS_SC2_RDR2_HOLD_BASE;  p[n++].what = "RDR2 hold";
        p[n].lo = IOS_SC2_E_BASE;          p[n++].what = "chrome_elf.dll's pools";
    }
    else if (layout == 2)
    {
        p[n].lo = IOS_SC2_L_BASE;      p[n++].what = "libcef.dll's pools";
        p[n].lo = IOS_SC2_FLOOR;       p[n++].what = "furniture";
        p[n].lo = IOS_SC2_J2_BASE;     p[n++].what = "chrome_elf.dll's metadata";
        p[n].lo = IOS_SC2_J2L_BASE;    p[n++].what = "libcef.dll's metadata";
        p[n].lo = IOS_SC2_E_BASE;      p[n++].what = "chrome_elf.dll's pools";
    }
    if (layout == 2)
    {
        if (rw_lo == IOS_SC2_RW_ALIAS && rw_hi > rw_lo && rw_hi < IOS_SC2_CAGE_BASE)
        {
            p[n].lo = IOS_SC2_RW_ALIAS; p[n++].what = "JIT pool RW alias";
            p[n].lo = rw_hi;            p[n++].what = "above the RW alias";
        }
        else
        {
            p[n].lo = IOS_SC2_RW_ALIAS; p[n++].what = "JIT pool RW alias and above";
        }
        p[n].lo = IOS_SC2_CAGE_BASE;   p[n++].what = "V8 cage";
        p[n].lo = IOS_SC2_OILPAN_BASE; p[n++].what = "Oilpan's cage";
        p[n].lo = rdr2 ? IOS_SC2_RDR2_ARENA_BASE : IOS_SC_ARENA_BASE;   p[n++].what = "FEX arena";
    }
    else
    {
        uint64_t a;
        for (a = IOS_BAND_LO; a < IOS_BAND_HI; a += 0x400000000ULL) { p[n].lo = a; p[n++].what = "16 GB slot"; }
    }
    for (i = 0; i < n; i++) p[i].hi = i + 1 < n ? p[i + 1].lo : IOS_BAND_HI;
    return n;
}

/* A region [lo, hi) with protection prot: split over the pieces it touches. */
static void ios_band_region( struct ios_band_piece *p, int n, uint64_t lo, uint64_t hi, int prot,
                             uint64_t resident, uint64_t dirty )
{
    int i;

    for (i = 0; i < n; i++)
    {
        uint64_t a = lo > p[i].lo ? lo : p[i].lo, b = hi < p[i].hi ? hi : p[i].hi;
        if (a >= b) continue;
        p[i].regions++;
        p[i].mapped += b - a;
        if (prot)
        {
            p[i].used += b - a;
            if (b - p[i].lo > p[i].top) p[i].top = b - p[i].lo;
        }
        if (lo >= p[i].lo && lo < p[i].hi) { p[i].resident += resident; p[i].dirty += dirty; }
    }
}

/* An unmapped gap [lo, hi): the largest per piece, and the band's largest
 * after aligning its start to 64 KB. */
static void ios_band_gap( struct ios_band_piece *p, int n, uint64_t lo, uint64_t hi, uint64_t *gap, uint64_t *gap_at )
{
    uint64_t start = (lo + 0xffff) & ~0xffffULL;
    int i;

    if (lo >= hi) return;
    for (i = 0; i < n; i++)
    {
        uint64_t a = lo > p[i].lo ? lo : p[i].lo, b = hi < p[i].hi ? hi : p[i].hi;
        if (a < b && b - a > p[i].gap) p[i].gap = b - a;
    }
    if (start < hi && hi - start > *gap) { *gap = hi - start; *gap_at = start; }
}

static void ios_band_census( const char *why )
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static uint64_t top_max[IOS_BAND_PIECES_MAX];
    static unsigned count;
    struct ios_band_piece p[IOS_BAND_PIECES_MAX];
    uint64_t addr = IOS_BAND_LO, hi = IOS_BAND_HI, gap = 0, gap_at = 0, rw_lo, rw_hi;
    task_vm_info_data_t vmi;
    mach_msg_type_number_t vcnt = TASK_VM_INFO_COUNT;
    unsigned walked = 0;
    struct tm tm;
    time_t now;
    int i, n;

    if (!ios_band_census_enabled() || pthread_mutex_trylock( &lock )) return;
    if (count >= 64) { pthread_mutex_unlock( &lock ); return; }
    count++;
    rw_lo = (uint64_t)(uintptr_t)ios_jit_rw_base_global;
    rw_hi = rw_lo + ios_jit_pool_size_global;
    if (ios_jit_low_size_global)
    {
        uint64_t l = (uint64_t)ios_jit_low_rw_global;
        if (l < rw_lo) rw_lo = l;
        if (l + ios_jit_low_size_global > rw_hi) rw_hi = l + ios_jit_low_size_global;
    }
    n = ios_band_pieces( p, ios_sc_layout_mode, ios_sc2_rdr2, rw_lo, rw_hi );
    if (task_info( mach_task_self(), TASK_VM_INFO, (task_info_t)&vmi, &vcnt ) == KERN_SUCCESS &&
        vmi.max_address && (uint64_t)vmi.max_address < hi)
        hi = (uint64_t)vmi.max_address;
    if (hi <= IOS_BAND_LO)
    {
        dprintf( 2, "[band] census #%u (%s): the task map ends at 0x%llx, below the band\n", count, why,
                 (unsigned long long)hi );
        pthread_mutex_unlock( &lock );
        return;
    }
    while (addr < hi)
    {
        mach_vm_address_t q = addr;
        mach_vm_size_t size = 0;
        vm_region_extended_info_data_t info;
        mach_msg_type_number_t cnt = VM_REGION_EXTENDED_INFO_COUNT;
        mach_port_t obj = MACH_PORT_NULL;
        uint64_t end;

        if (mach_vm_region( mach_task_self(), &q, &size, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&info,
                            &cnt, &obj ) != KERN_SUCCESS || q >= hi || !size)
        {
            ios_band_gap( p, n, addr, hi, &gap, &gap_at );
            break;
        }
        if (q > addr) ios_band_gap( p, n, addr, q, &gap, &gap_at );
        end = q + size > hi ? hi : q + size;
        ios_band_region( p, n, q > addr ? q : addr, end, info.protection,
                         (uint64_t)info.pages_resident << 14,
                         ((uint64_t)info.pages_dirtied + info.pages_swapped_out) << 14 );
        addr = end;
        if (++walked >= 1000000)
        {
            dprintf( 2, "[band] census #%u: stopped after %u regions at 0x%llx\n", count, walked,
                     (unsigned long long)addr );
            break;
        }
    }
    now = time( NULL );
    localtime_r( &now, &tm );
    dprintf( 2, "[band] census #%u (%s) %02d:%02d:%02d layout %d%s, [0x%llx,0x%llx) %u regions: largest gap %llu MB "
                "at 0x%llx -- RDR2.exe's 8960 MB reserve %s (MADEIRA_BAND_CENSUS)\n",
             count, why, tm.tm_hour, tm.tm_min, tm.tm_sec, ios_sc_layout_mode,
             ios_sc2_rdr2 ? " with MADEIRA_RDR2_VA_HOLD" : "", IOS_BAND_LO,
             (unsigned long long)hi, walked, (unsigned long long)(gap >> 20), (unsigned long long)gap_at,
             gap >= IOS_BAND_RDR2_ASK ? "fits" : "does not fit" );
    for (i = 0; i < n; i++)
    {
        if (p[i].top > top_max[i]) top_max[i] = p[i].top;
        dprintf( 2, "[band]   [0x%llx,0x%llx) %s: regions=%u mapped=%llu used=%llu resident=%llu dirty=%llu MB, "
                    "top +%llu MB (session +%llu MB), gap %llu MB\n",
                 (unsigned long long)p[i].lo, (unsigned long long)p[i].hi, p[i].what, p[i].regions,
                 (unsigned long long)(p[i].mapped >> 20), (unsigned long long)(p[i].used >> 20),
                 (unsigned long long)(p[i].resident >> 20), (unsigned long long)(p[i].dirty >> 20),
                 (unsigned long long)(p[i].top >> 20), (unsigned long long)(top_max[i] >> 20),
                 (unsigned long long)(p[i].gap >> 20) );
    }
    pthread_mutex_unlock( &lock );
}

/* Which slot a SocialClubHelper.exe reserve gets in layout 2. `held` has bit k
 * for each slot still held; `e_mine` / `l_mine` / `cage_mine`: this helper
 * already got chrome_elf's block / libcef's block / the V8 cage. NONE leaves
 * the request to the generic jumbo path; REFUSE fails it with nothing else
 * tried. */
static int ios_sc2_classify( uint64_t size, uint64_t hint, unsigned held, int e_mine, int l_mine, int cage_mine )
{
    /* Oilpan asks for 32 GB with a 16 GB-aligned random hint (393 jumbo#5:
     * 0x2be400000000). PartitionAlloc needs 32 GB alignment, so keep that
     * rule for E/L. Only this helper's third block can use the Oilpan slot:
     * both PA blocks belong to it and their holds have already been consumed.
     * The reported base remains 32 GB-aligned, satisfying either request. */
    if (size == 0x800000000ULL && hint && !(hint & (0x400000000ULL - 1)) &&
        e_mine && l_mine && !(held & ((1u << IOS_SC2_E) | (1u << IOS_SC2_L))) &&
        (held & (1u << IOS_SC2_OILPAN))) return IOS_SC2_OILPAN;
    if (size == 0x800000000ULL && hint && !(hint & (0x800000000ULL - 1)))
    {
        if (held & (1u << IOS_SC2_E)) return IOS_SC2_E;
        if (held & (1u << IOS_SC2_L)) return IOS_SC2_L;
        /* the third: Oilpan, before or after the V8 cage (see the layout comment) */
        if (e_mine && l_mine && (held & (1u << IOS_SC2_OILPAN))) return IOS_SC2_OILPAN;
        return IOS_SC2_REFUSE;
    }
    /* a metadata region: right after its pools, before the cage, hint not 4 GB-aligned */
    if (size == IOS_SC2_MD_ASK && (hint & 0xffffffffULL) && !cage_mine)
    {
        if ((held & (1u << IOS_SC2_J2)) && !(held & (1u << IOS_SC2_E)) && (held & (1u << IOS_SC2_L)))
            return IOS_SC2_J2;
        if ((held & (1u << IOS_SC2_J2L)) && !(held & (1u << IOS_SC2_L)))
            return IOS_SC2_J2L;
    }
    return IOS_SC2_NONE;
}

/* Layout 2: the HighestUserAddress SocialClubHelper.exe is told. V8 14
 * (Chromium 142) takes its address-space
 * limit as min(CPUID's virtual address bits - 1, lpMaximumApplicationAddress + 1
 * rounded up to a power of two) and CHECKs kSandboxSize (1 TB on Windows x64)
 * against it before reserving anything (sandbox.cc DetermineAddressSpaceLimit,
 * Sandbox::Initialize). ml990 clamps user_space_limit to the 512 GB this device
 * can map, so V8 gets 2^39 and dies on the CHECK. Told 2 TB (FEX's CPUID leaf
 * 0x80000008 says 48 bits), V8 passes it and goes straight to a partially
 * reserved sandbox: 512 GB halving to 8 GB, one hinted and one unhinted
 * VirtualAlloc2 per step. Anything above 512 GB still fails
 * (allocate_virtual_memory refuses a base past address_space_limit, map_view
 * finds no room for a size that large), and the 8 GB step gets the cage
 * (ios_sc2_ex_cage). Only the report changes: user_space_limit and every
 * placement keep the real limit, as do server_ios.c's remote-allocation limits
 * (ios_highest_user_address). Not for WoW64 (a guest limit), nor when the limit
 * is already wider (env.MADEIRA_WIDE_USER_VA). */
#define IOS_SC2_WIDE_HIGHEST 0x1ffffffffffULL   /* 2 TB - 1 */

static ULONG_PTR ios_sc2_reported_highest( ULONG_PTR real, int wow64, int layout, int helper )
{
    if (wow64 || layout != 2 || !helper || real >= IOS_SC2_WIDE_HIGHEST) return real;
    return IOS_SC2_WIDE_HIGHEST;
}

/* Hold slot k natively (PROT_NONE, no view). [0x7000000000, +4 GB) may already
 * be held by the app (StikJITHelper.swift): a PROT_NONE region covering it is
 * taken over as the hold. */
static int ios_sc2_hold( int k )
{
    mach_vm_address_t a = ios_sc2_slots[k].base;
    kern_return_t kr = mach_vm_map( mach_task_self(), &a, ios_sc2_slots[k].size, 0, VM_FLAGS_FIXED,
                                    MEMORY_OBJECT_NULL, 0, 0, PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
    if (kr != KERN_SUCCESS && k == IOS_SC2_L)
    {
        /* The app's hold may be one region or several (iOS can split an entry);
         * take it over if [base, base + size) is covered without gaps by
         * PROT_NONE regions only. */
        mach_vm_address_t cur = a, end = a + ios_sc2_slots[k].size;
        int ok = 1;
        while (cur < end)
        {
            mach_vm_address_t r = cur;
            mach_vm_size_t rs = 0;
            vm_region_basic_info_data_64_t inf = { 0 };
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj = MACH_PORT_NULL;
            if (mach_vm_region( mach_task_self(), &r, &rs, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&inf,
                                &cnt, &obj ) != KERN_SUCCESS || r != cur || inf.protection != VM_PROT_NONE)
            {
                dprintf( 2, "[sc-cef] layout 2: hold takeover stops at 0x%llx: region 0x%llx+0x%llx prot=%d "
                            "(map kr=%d)\n", (unsigned long long)cur, (unsigned long long)r,
                         (unsigned long long)rs, (int)inf.protection, (int)kr );
                ok = 0;
                break;
            }
            cur = r + rs;
        }
        if (ok) kr = KERN_SUCCESS;
    }
    if (kr != KERN_SUCCESS) return 0;
    ios_sc2_held |= 1u << k;
    return 1;
}

static void ios_sc2_unhold( int k )
{
    if (!(ios_sc2_held & (1u << k))) return;
    mach_vm_deallocate( mach_task_self(), ios_sc2_slots[k].base, ios_sc2_slots[k].size );
    ios_va_release_note();
    ios_sc2_held &= ~(1u << k);
}

/* [lo, hi): 1 when PROT_NONE regions cover it without a gap (a native hold),
 * 0 when nothing is mapped there, -1 otherwise. */
static int ios_sc2_none_only( mach_vm_address_t lo, mach_vm_address_t hi )
{
    mach_vm_address_t cur = lo;
    int seen = 0;

    while (cur < hi)
    {
        mach_vm_address_t r = cur;
        mach_vm_size_t rs = 0;
        vm_region_basic_info_data_64_t inf = { 0 };
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        if (mach_vm_region( mach_task_self(), &r, &rs, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&inf,
                            &cnt, &obj ) != KERN_SUCCESS || r >= hi)
            return seen ? -1 : 0;
        if (r > cur || inf.protection != VM_PROT_NONE) return -1;
        seen = 1;
        cur = r + rs;
    }
    return 1;
}

/* virtual_init: take the four slots before anything can land in them, or fall
 * back to layout 0 with nothing held. */
static void ios_sc2_boot_holds(void)
{
    int k;

    if (ios_sc_layout() != 2) return;
    if (ios_sc2_rdr2_hold_enabled()) ios_sc2_rdr2_geometry();
    for (k = IOS_SC2_E; k <= IOS_SC2_OILPAN; k++)
    {
        if (ios_sc2_hold( k )) continue;
        dprintf( 2, "[sc-cef] layout 2: could not hold [0x%llx,0x%llx) for %s -- layout 2 is off and "
                    "SocialClubHelper.exe's pools stay unplaced\n",
                 (unsigned long long)ios_sc2_slots[k].base,
                 (unsigned long long)(ios_sc2_slots[k].base + ios_sc2_slots[k].size), ios_sc2_slots[k].what );
        for (k = IOS_SC2_E; k <= IOS_SC2_OILPAN; k++) ios_sc2_unhold( k );
        ios_sc_layout_mode = 0;
        return;
    }
    if (!ios_sc2_rdr2)
    {
        dprintf( 2, "[sc-cef] layout 2: held libcef.dll's pools [0x%llx,+4 GB), PartitionAlloc metadata of chrome_elf.dll "
                    "[0x%llx,+8 GB) and libcef.dll [0x%llx,+8 GB), chrome_elf.dll's pools [0x%llx,+4 GB), Oilpan "
                    "[0x%llx,+4 GB); RW alias 0x%llx, V8 cage 0x%llx, furniture floor 0x%llx\n",
                 IOS_SC2_L_BASE, IOS_SC2_J2_BASE, IOS_SC2_J2L_BASE, IOS_SC2_E_BASE, IOS_SC2_OILPAN_BASE,
                 IOS_SC2_RW_ALIAS, IOS_SC2_CAGE_BASE, IOS_SC2_FLOOR );
        return;
    }
    dprintf( 2, "[sc-cef] layout 2 with MADEIRA_RDR2_VA_HOLD: held libcef.dll's pools [0x%llx,+%llu MB) and its "
                "PartitionAlloc metadata [0x%llx,+%llu MB), chrome_elf.dll's metadata [0x%llx,+%llu MB) and pools "
                "[0x%llx,+4 GB), Oilpan [0x%llx,+%llu MB); RW alias 0x%llx, V8 cage 0x%llx, furniture floor 0x%llx\n",
             (unsigned long long)ios_sc2_slots[IOS_SC2_L].base, (unsigned long long)(ios_sc2_slots[IOS_SC2_L].size >> 20),
             (unsigned long long)ios_sc2_slots[IOS_SC2_J2L].base, (unsigned long long)(ios_sc2_slots[IOS_SC2_J2L].size >> 20),
             (unsigned long long)ios_sc2_slots[IOS_SC2_J2].base, (unsigned long long)(ios_sc2_slots[IOS_SC2_J2].size >> 20),
             IOS_SC2_E_BASE, IOS_SC2_OILPAN_BASE, (unsigned long long)(ios_sc2_slots[IOS_SC2_OILPAN].size >> 20),
             IOS_SC2_RW_ALIAS, IOS_SC2_CAGE_BASE, IOS_SC2_RDR2_FLOOR );
    /* The app held [0x7000000000, +4 GB) for libcef.dll's pools; the slot took
     * its first 256 MB. Give the rest to the furniture, but only while it is
     * still the app's untouched PROT_NONE hold. */
    {
        int none = ios_sc2_none_only( IOS_SC2_RDR2_FLOOR, IOS_SC2_FLOOR );
        if (none > 0)
        {
            mach_vm_deallocate( mach_task_self(), IOS_SC2_RDR2_FLOOR, IOS_SC2_FLOOR - IOS_SC2_RDR2_FLOOR );
            ios_va_release_note();
        }
        dprintf( 2, "[sc-cef] MADEIRA_RDR2_VA_HOLD: [0x%llx,0x%llx) %s; the furniture starts at 0x%llx (%llu MB more)\n",
                 IOS_SC2_RDR2_FLOOR, IOS_SC2_FLOOR,
                 none > 0 ? "released from the app's hold" : none == 0 ? "was free" : "is partly mapped by something else",
                 IOS_SC2_RDR2_FLOOR, (IOS_SC2_FLOOR - IOS_SC2_RDR2_FLOOR) >> 20 );
    }
    {
        mach_vm_address_t a = IOS_SC2_RDR2_HOLD_BASE;
        kern_return_t kr = mach_vm_map( mach_task_self(), &a, IOS_SC2_RDR2_HOLD_SIZE, 0, VM_FLAGS_FIXED,
                                        MEMORY_OBJECT_NULL, 0, 0, PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
        if (kr != KERN_SUCCESS || ios_jumbo_hold_size)
        {
            if (kr == KERN_SUCCESS) mach_vm_deallocate( mach_task_self(), a, IOS_SC2_RDR2_HOLD_SIZE );
            dprintf( 2, "[sc-cef] MADEIRA_RDR2_VA_HOLD: could not hold [0x%llx,0x%llx) (kr=%d, holdback %llu MB) -- "
                        "an 8960 MB reserve fails as before\n", IOS_SC2_RDR2_HOLD_BASE,
                     IOS_SC2_RDR2_HOLD_BASE + IOS_SC2_RDR2_HOLD_SIZE, (int)kr,
                     (unsigned long long)(ios_jumbo_hold_size >> 20) );
            return;
        }
        ios_jumbo_hold_base = (uintptr_t)a;
        ios_jumbo_hold_size = (size_t)IOS_SC2_RDR2_HOLD_SIZE;
        ios_jumbo_hold_min = (size_t)IOS_SC2_RDR2_HOLD_SIZE;
        ios_jumbo_hold_keep = 0;
        dprintf( 2, "[sc-cef] MADEIRA_RDR2_VA_HOLD: [0x%llx,0x%llx) held for one 8960 MB reserve (RDR2.exe's): "
                    "the first one the kernel cannot place gets it ([jumbo-hold] lines); nothing smaller does\n",
                 IOS_SC2_RDR2_HOLD_BASE, IOS_SC2_RDR2_HOLD_BASE + IOS_SC2_RDR2_HOLD_SIZE );
    }
}

/* Reservations SocialClubHelper.exe got through the jumbo path, by owner, so a
 * dead helper's are released when the next helper asks (ios_sc_reap_dead): a
 * pseudo-process's views are not unmapped when it dies, and every restarted
 * helper found [0x7800000000, 0x7d00000000) still taken. `view` is the real
 * view ([view, view + real) is reserved), `report` the address the guest was
 * given (and `asked` its size). */
#define IOS_SC_GRANT_MAX 32
static struct { uint64_t view, report, real, asked; void *peb; int kind, dead; } ios_sc_grants[IOS_SC_GRANT_MAX];
static int ios_sc_grant_n, ios_sc_grant_dead_n;
static pthread_mutex_t ios_sc_grant_lock = PTHREAD_MUTEX_INITIALIZER;

static void ios_sc_grant_add( uint64_t view, uint64_t report, uint64_t real, uint64_t asked, int kind, void *peb )
{
    pthread_mutex_lock( &ios_sc_grant_lock );
    if (ios_sc_grant_n < IOS_SC_GRANT_MAX)
    {
        ios_sc_grants[ios_sc_grant_n].view = view;
        ios_sc_grants[ios_sc_grant_n].report = report;
        ios_sc_grants[ios_sc_grant_n].real = real;
        ios_sc_grants[ios_sc_grant_n].asked = asked;
        ios_sc_grants[ios_sc_grant_n].peb = peb;
        ios_sc_grants[ios_sc_grant_n].kind = kind;
        ios_sc_grants[ios_sc_grant_n].dead = 0;
        ios_sc_grant_n++;
    }
    pthread_mutex_unlock( &ios_sc_grant_lock );
}

/* Does the live helper `peb` hold a grant of this kind? */
static int ios_sc_grant_has( void *peb, int kind )
{
    int i, hit = 0;
    pthread_mutex_lock( &ios_sc_grant_lock );
    for (i = 0; i < ios_sc_grant_n; i++)
        if (ios_sc_grants[i].peb == peb && ios_sc_grants[i].kind == kind && !ios_sc_grants[i].dead) hit = 1;
    pthread_mutex_unlock( &ios_sc_grant_lock );
    return hit;
}

/* ios_jit_reclaim_process: this pseudo-process has exited. */
static void ios_sc_grants_owner_died( void *peb )
{
    int i, n = 0;
    if (!peb || !ios_sc_grant_n) return;
    pthread_mutex_lock( &ios_sc_grant_lock );
    for (i = 0; i < ios_sc_grant_n; i++)
        if (ios_sc_grants[i].peb == peb && !ios_sc_grants[i].dead) { ios_sc_grants[i].dead = 1; n++; }
    ios_sc_grant_dead_n += n;
    pthread_mutex_unlock( &ios_sc_grant_lock );
    if (n)
        dprintf( 2, "[sc-cef] SocialClubHelper.exe (peb=%p) exited holding %d large reservation(s); they are "
                    "released when the next helper asks\n", peb, n );
}

/* Hold again what a released grant of `kind` came out of. */
static void ios_sc_rehold( int kind )
{
    if (kind >= IOS_SC2_E && kind <= IOS_SC2_OILPAN)
    {
        if (ios_sc_layout_mode == 2) ios_sc2_hold( kind );
    }
    else if (kind == IOS_SC_K_V1)
    {
        mach_vm_address_t h = IOS_SC_BRP_HOLD_BASE;
        if (!ios_sc_brp_held &&
            mach_vm_map( mach_task_self(), &h, IOS_SC_BRP_HOLD_SIZE, 0, VM_FLAGS_FIXED, MEMORY_OBJECT_NULL, 0, 0,
                         PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY ) == KERN_SUCCESS)
            ios_sc_brp_held = 1;
    }
    else if (kind == IOS_SC_K_CAGE)
    {
        mach_vm_address_t h = IOS_CAGE_BASE;
        if (!ios_cage_holdback_live && !ios_cage_window_tail_live &&
            mach_vm_map( mach_task_self(), &h, IOS_CAGE_REAL_SIZE, 0, VM_FLAGS_FIXED, MEMORY_OBJECT_NULL, 0, 0,
                         PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY ) == KERN_SUCCESS)
            ios_cage_holdback_live = 1;
    }
}

/* The boot half: called once, for the FEX arena's first candidate. Holds the 4 GB
 * (layout 1; layout 2 holds it in ios_sc2_boot_holds) and maps the 12 GB arena
 * right above it (both PROT_NONE, as the arena always is). Returns 1 with the
 * arena in *addr / *size, or 0 with nothing held. */
static int ios_sc_pa_hold_arena( mach_vm_address_t *addr, SIZE_T *size )
{
    static int tried;
    mach_vm_address_t h = IOS_SC_BRP_HOLD_BASE, a = ios_sc2_arena_lo;
    mach_vm_size_t asz = 0x8000000000ULL - ios_sc2_arena_lo;   /* 12 GB; 15 GB with MADEIRA_RDR2_VA_HOLD */
    kern_return_t kr = KERN_SUCCESS;
    int mode = ios_sc_layout();

    if (tried || !mode) return 0;
    tried = 1;
    if (mode == 1)
        kr = mach_vm_map( mach_task_self(), &h, IOS_SC_BRP_HOLD_SIZE, 0, VM_FLAGS_FIXED, MEMORY_OBJECT_NULL, 0, 0,
                          PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
    if (kr == KERN_SUCCESS)
    {
        kr = mach_vm_map( mach_task_self(), &a, asz, 0xffff, VM_FLAGS_FIXED, MEMORY_OBJECT_NULL, 0, 0,
                          PROT_NONE, VM_PROT_ALL, VM_INHERIT_COPY );
        if (kr != KERN_SUCCESS && mode == 1) mach_vm_deallocate( mach_task_self(), h, IOS_SC_BRP_HOLD_SIZE );
    }
    if (kr != KERN_SUCCESS)
    {
        dprintf( 2, "[sc-cef] env.MADEIRA_SC_PA_POOLS=%d: could not take [0x%llx,0x%llx) (kr=%d) -- the FEX arena "
                    "stays where it was and SocialClubHelper.exe's PartitionAlloc pools cannot be placed\n",
                 mode, mode == 1 ? IOS_SC_BRP_HOLD_BASE : ios_sc2_arena_lo, ios_sc2_arena_lo + asz,
                 (int)kr );
        return 0;
    }
    ios_sc_brp_held = (mode == 1);
    ios_sc_brp_layout = 1;
    *addr = a;
    *size = asz;
    dprintf( 2, "[sc-cef] env.MADEIRA_SC_PA_POOLS=%d: FEX arena [0x%llx,0x%llx) (%llu GB); [0x%llx,0x%llx) held for "
                "SocialClubHelper.exe's %s\n", mode,
             (unsigned long long)ios_sc2_arena_lo, (unsigned long long)(ios_sc2_arena_lo + asz),
             (unsigned long long)(asz >> 30),
             IOS_SC_BRP_HOLD_BASE, IOS_SC_BRP_HOLD_BASE + IOS_SC_BRP_HOLD_SIZE,
             mode == 1 ? "PartitionAlloc pools" : "Oilpan cage" );
    return 1;
}

/* Undo of ios_sc_pa_hold_arena when the arena could not be registered. */
static void ios_sc_pa_drop_hold(void)
{
    if (ios_sc_brp_held) mach_vm_deallocate( mach_task_self(), IOS_SC_BRP_HOLD_BASE, IOS_SC_BRP_HOLD_SIZE );
    ios_va_release_note();
    ios_sc_brp_held = ios_sc_brp_layout = 0;
}


/* task #34 .text sharing: pre-scan a SOURCE PE (before the pool memcpy) for
 * the x18 trampoline budget, so the trampoline region can be folded into the
 * image's own pool allocation at a FIXED image-relative offset. Fixed-offset
 * tramps make the patched .text and the trampolines byte-identical across
 * pool copies of the same DLL (both branch directions are PC-relative), which
 * is the precondition for page-sharing copies. Returns the page-aligned tramp
 * bytes to reserve, or 0 when the x18 patcher will skip this image (pure
 * x86_64: Machine!=ARM64 and no .a64xrm section — mirrors the skip logic in
 * the patch stage; scanning x64 bytes would count garbage matches). */
static size_t ios_x18_tramp_prealloc_scan( const char *image, size_t image_size )
{
    extern size_t ios_jit_x18_tramp_need( const char *text, size_t text_size );
    const size_t pg = 0x4000;
    unsigned int pe_off;
    unsigned short machine, num_sec, opt_sz;
    const char *sec;
    size_t text_off = 0, text_sz = 0;
    int s, is_arm64ec = 0;

    if (!image || image_size < 0x400) return 0;
    if (image[0] != 'M' || image[1] != 'Z') return 0;
    pe_off = *(const unsigned int *)(image + 0x3C);
    if ((size_t)pe_off + 0x18 > image_size) return 0;
    machine = *(const unsigned short *)(image + pe_off + 4);
    num_sec = *(const unsigned short *)(image + pe_off + 6);
    opt_sz  = *(const unsigned short *)(image + pe_off + 0x14);
    sec = image + pe_off + 0x18 + opt_sz;
    if ((size_t)(sec - image) + (size_t)num_sec * 40 > image_size) return 0;
    for (s = 0; s < num_sec; s++, sec += 40)
    {
        unsigned int chars = *(const unsigned int *)(sec + 36);
        unsigned int rva   = *(const unsigned int *)(sec + 12);
        unsigned int vsz   = *(const unsigned int *)(sec + 8);
        if (!memcmp(sec, ".a64xrm", 7)) is_arm64ec = 1;
        /* Largest exec section = the .text the patcher walks (same rule as
         * ios_jit_set_text_section). */
        if ((chars & 0x20000000) && vsz > text_sz) { text_off = rva; text_sz = vsz; }
    }
    if (machine != IMAGE_FILE_MACHINE_ARM64 && !is_arm64ec) return 0;
    if (!text_sz || text_off + text_sz > image_size) return 0;
    return (ios_jit_x18_tramp_need(image + text_off, text_sz) + pg - 1) & ~(pg - 1);
}


/* [share-probe] logging: the LogStore periodically REWRITES madeira-log.txt
 * from its own buffer, destroying interleaved raw-stderr lines (ml85: the
 * probe's whole verdict vanished between pulls). Tee every probe line into
 * Documents/share-probe.txt (O_APPEND, own fd) so no rewrite can eat it. */
static void ios_probe_filelog(int fd_unused, const char *fmt, ...)
{
    va_list ap;
    char buf[512];
    int n;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
    write(2, buf, n);
    {
        static int pf = -2;
        if (pf == -2)
        {
            const char *wp = getenv("WINEPREFIX");
            pf = -1;
            if (wp && strlen(wp) < 440)
            {
                char path[512];
                snprintf(path, sizeof(path), "%s/../share-probe.txt", wp);
                pf = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
            }
        }
        if (pf >= 0) write(pf, buf, n);
    }
}
#define dprintf ios_probe_filelog

/* Watchdog exec: run the 2-insn probe function on a disposable thread with a
 * timeout, so an instruction-fetch wedge (ml79/ml85 signature) becomes a
 * logged verdict instead of a lost thread holding the whole probe hostage.
 * Returns the function's result, or INT_MIN on timeout. */
static volatile int ios_probe_exec_done;
static volatile int ios_probe_exec_ret;
static void *ios_probe_exec_helper(void *p)
{
    typedef int (*probe_fn)(void);
    int v = ((probe_fn)p)();
    ios_probe_exec_ret = v;
    __sync_synchronize();
    ios_probe_exec_done = 1;
    return NULL;
}
static int ios_probe_exec_timed(void *fn, int deciseconds)
{
    pthread_t t;
    int i;
    ios_probe_exec_done = 0;
    if (pthread_create(&t, NULL, ios_probe_exec_helper, fn)) return INT_MIN;
    pthread_detach(t);
    for (i = 0; i < deciseconds; i++)
    {
        if (ios_probe_exec_done) return ios_probe_exec_ret;
        usleep(100000);
    }
    return INT_MIN;
}

/* task #34 [share-probe] — one-shot go/no-go for one-RX-copy-per-DLL page
 * sharing: does the StikDebug execute blessing survive vm_remap(copy=FALSE)
 * of a blessed pool RX page to a SECOND in-pool VA, and does the dual-map
 * stay coherent through the share? Log-only; leaks 2×16KB pool slots (kept
 * mapped so the remapped pages are never recycled under someone else). */
static void ios_share_probe(void)
{
    extern void *ios_jit_rw_base_global;
    extern void *ios_jit_rx_base_global;
    extern size_t ios_jit_pool_size_global;
    typedef int (*probe_fn)(void);
    const size_t pg = 0x4000;
    size_t off1, off2;
    char *rx1, *rw1, *rx2, *rw2;
    vm_prot_t cur = 0, max = 0;
    kern_return_t kr;
    int r;

    if (!ios_jit_rx_base_global || !ios_jit_rw_base_global) return;
    dprintf(2, "[share-probe] start (rx_base=%p rw_base=%p)\n",
            ios_jit_rx_base_global, ios_jit_rw_base_global);
    off1 = ios_pool_alloc_range(pg, ios_jit_pool_size_global - ios_jit_tail_reserved);
    off2 = ios_pool_alloc_range(pg, ios_jit_pool_size_global - ios_jit_tail_reserved);
    if (off1 == (size_t)-1 || off2 == (size_t)-1)
    {
        dprintf(2, "[share-probe] pool alloc failed — probe skipped\n");
        return;
    }
    rx1 = (char *)ios_jit_rx_base_global + off1;
    rw1 = (char *)ios_jit_rw_base_global + off1;
    rx2 = (char *)ios_jit_rx_base_global + off2;
    rw2 = (char *)ios_jit_rw_base_global + off2;
    dprintf(2, "[share-probe] slots off1=0x%lx off2=0x%lx — writing code via master RW\n",
            (unsigned long)off1, (unsigned long)off2);

    ((uint32_t *)rw1)[0] = 0x52800540;  /* mov w0, #42 */
    ((uint32_t *)rw1)[1] = 0xD65F03C0;  /* ret */
    __asm__ __volatile__("dsb sy" ::: "memory");
    sys_icache_invalidate(rx1, pg);
    /* Read back through the RX alias BEFORE executing — a mismatch means
     * the dual-map is broken for this placement and executing would run
     * garbage (ml78: silent hang was the first pool execution at a toxic
     * pool base; never execute blind). */
    if (*(volatile uint32_t *)rx1 != 0x52800540)
    {
        dprintf(2, "[share-probe] ABORT: RX readback 0x%08x != written code (dual-map broken here)\n",
                *(volatile uint32_t *)rx1);
        return;
    }
    dprintf(2, "[share-probe] readback OK — executing at master %p\n", rx1);
    r = ((probe_fn)rx1)();
    dprintf(2, "[share-probe] exec at master %p -> %d (expect 42)\n", rx1, r);

    /* [purge-probe] THE ml76-wall suspect: is the debugger-allocated pool
     * PURGEABLE memory? (Allocator comment: virgin pool pages read back zero
     * under pressure — anon memory doesn't do that unless volatile/purgeable.)
     * GET_STATE per view; if any view reports purgeable+volatile, SET
     * NONVOLATILE and re-query — that one call would be the whole reclaim fix
     * (no vm_wire, no jetsam cost). KERN_INVALID_ARGUMENT = not purgeable. */
    {
        struct { const char *name; vm_address_t a; } views[3];
        int v;
        views[0].name = "pool-rx-base"; views[0].a = (vm_address_t)ios_jit_rx_base_global;
        views[1].name = "pool-rw-base"; views[1].a = (vm_address_t)ios_jit_rw_base_global;
        views[2].name = "master-slot ";  views[2].a = (vm_address_t)rx1;
        for (v = 0; v < 3; v++)
        {
            int state = -1;
            kern_return_t pk = vm_purgable_control(mach_task_self(), views[v].a,
                                                   VM_PURGABLE_GET_STATE, &state);
            dprintf(2, "[purge-probe] %s %p GET_STATE kr=%d state=%d%s\n",
                    views[v].name, (void *)views[v].a, pk, state,
                    pk == KERN_SUCCESS
                        ? (state == VM_PURGABLE_VOLATILE ? " (PURGEABLE+VOLATILE — the wall!)" :
                           state == VM_PURGABLE_NONVOLATILE ? " (purgeable, nonvolatile)" :
                           state == VM_PURGABLE_EMPTY ? " (purgeable, EMPTY)" : "")
                        : " (not purgeable)");
            if (pk == KERN_SUCCESS && state != VM_PURGABLE_NONVOLATILE)
            {
                int ns = VM_PURGABLE_NONVOLATILE;
                kern_return_t sk = vm_purgable_control(mach_task_self(), views[v].a,
                                                       VM_PURGABLE_SET_STATE, &ns);
                dprintf(2, "[purge-probe] %s SET NONVOLATILE kr=%d (old=%d)\n",
                        views[v].name, sk, ns);
            }
        }
    }

    /* CONTROL (ml85 confound): variant E execs on a fresh watchdog pthread.
     * If a bare pthread can't run blessed pool code AT ALL (no FEX/TEB/signal
     * setup), E's wedge is a thread artifact, not a remap verdict. Run the
     * MASTER page through the same watchdog path first. master-via-watchdog
     * == 42 → thread is fine, any E wedge is the remap. WEDGE here → the
     * whole E result is invalid (thread, not remap). */
    {
        int rc = ios_probe_exec_timed(rx1, 50);
        dprintf(2, "[share-probe] CONTROL master-via-watchdog -> %s\n",
                rc == INT_MIN ? "WEDGED (bare pthread can't exec pool code — E verdict would be INVALID)"
                              : (rc == 42 ? "42 OK (watchdog thread is fine — E wedge = the remap)"
                                          : "WRONG"));
    }

    /* Verdicts so far (ml77/79/85): OVERWRITE into pool RX kr=2; hole
     * dealloc kr=0 but refill remap kr=3; remap ANYWHERE gets kernel R+X but
     * EXEC WEDGES the thread — attached AND detached. Lore (stikdebug-jit):
     * self-created exec mappings don't work; only the debugger-allocated
     * range executes. Yet the PRODUCTION anon-RWX path executes pool pages
     * remapped OVERWRITE onto wine's pre-existing anon mmap regions daily.
     * Variant E = exact replica of that shape: mmap anon RW, OVERWRITE-remap
     * master page onto it, vm_protect RX, exec — on a WATCHDOG thread so a
     * wedge is a logged verdict, not a lost one. */
    {
        void *tgt = mmap(NULL, pg, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANON, -1, 0);
        vm_address_t target;
        if (tgt == MAP_FAILED)
        {
            dprintf(2, "[share-probe] E: mmap anon target failed errno=%d\n", errno);
            return;
        }
        dprintf(2, "[share-probe] E: anon RW target %p — OVERWRITE-remap from master %p\n", tgt, rx1);
        target = (vm_address_t)tgt;
        kr = vm_remap(mach_task_self(), &target, pg, 0,
                      VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(),
                      (vm_address_t)rx1, FALSE, &cur, &max, VM_INHERIT_DEFAULT);
        dprintf(2, "[share-probe] E: vm_remap kr=%d cur=0x%x max=0x%x\n", kr, cur, max);
        if (kr != KERN_SUCCESS) { dprintf(2, "[share-probe] VERDICT: NO-GO (E remap failed)\n"); return; }
        kr = vm_protect(mach_task_self(), target, pg, FALSE,
                        VM_PROT_READ | VM_PROT_EXECUTE);
        dprintf(2, "[share-probe] E: vm_protect(R+X) kr=%d\n", kr);
        {
            mach_vm_address_t qa = (mach_vm_address_t)target;
            mach_vm_size_t qs = 0;
            vm_region_basic_info_data_64_t qi = {0};
            mach_msg_type_number_t qc = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t qo = MACH_PORT_NULL;
            if (mach_vm_region(mach_task_self(), &qa, &qs, VM_REGION_BASIC_INFO_64,
                               (vm_region_info_t)&qi, &qc, &qo) == KERN_SUCCESS)
                dprintf(2, "[share-probe] E: region prot=0x%x max_prot=0x%x\n",
                        qi.protection, qi.max_protection);
        }
        sys_icache_invalidate(tgt, pg);
        if (*(volatile uint32_t *)tgt != *(volatile uint32_t *)rx1)
        {
            dprintf(2, "[share-probe] E: read mismatch tgt=0x%08x master=0x%08x\n",
                    *(volatile uint32_t *)tgt, *(volatile uint32_t *)rx1);
        }
        dprintf(2, "[share-probe] E: executing at %p (watchdog 5s)\n", tgt);
        r = ios_probe_exec_timed(tgt, 50);
        if (r == INT_MIN)
        {
            dprintf(2, "[share-probe] E: WEDGED (no return in 5s) — VERDICT: NO-GO (anon-replica exec dead too)\n");
            return;
        }
        dprintf(2, "[share-probe] E: exec -> %d (expect 42)%s\n", r, r == 42 ? " OK" : " WRONG");
        if (r != 42) { dprintf(2, "[share-probe] VERDICT: NO-GO (E wrong bytes)\n"); return; }

        /* Dual-map through the share: rewrite via the MASTER's RW view and
         * re-execute at the E alias — one physical page must serve master-RW
         * writes and alias-RX fetches. */
        ((uint32_t *)rw1)[0] = 0x52800560;  /* mov w0, #43 */
        __asm__ __volatile__("dsb sy" ::: "memory");
        sys_icache_invalidate(tgt, pg);
        r = ios_probe_exec_timed(tgt, 50);
        dprintf(2, "[share-probe] E: rewrite-via-master exec -> %d (expect 43) — VERDICT: %s\n",
                r, r == 43 ? "GO (anon-replica sharing works)" : "NO-GO (dual-map incoherent)");
    }
    (void)rx2; (void)rw2;
}


/* task #34 [share-probe] post-detach runner: the ml79 wedge happened with
 * StikDebug still ATTACHED (exec faults route to the debugger and hang), so
 * the exec-at-alias verdict was inconclusive. Wait for the app's REAL
 * jit26_detach on a scratch thread — worst case is a stuck background
 * thread, never a wedged boot. (ml81 lesson: CS_DEBUGGED is STICKY after
 * detach — that's why blessed JIT keeps working — so csops can't signal
 * detach; StikJITHelper.detachDebugger sets MADEIRA_DETACHED instead.
 * Desktop sessions detach on session exit or the 20-min maxWait cap.) */
static void *ios_share_probe_thread(void *arg)
{
    int i;
    for (i = 0; i < 900; i++)  /* ≤30min at 2s — covers the 20-min cap */
    {
        if (getenv("MADEIRA_DETACHED"))
        {
            dprintf(2, "[share-probe] debugger DETACHED (poll %d) — running post-detach probe\n", i);
            ios_share_probe();
            return NULL;
        }
        usleep(2000000);
    }
    dprintf(2, "[share-probe] no detach within 30min — probe skipped\n");
    return NULL;
}
#undef dprintf

