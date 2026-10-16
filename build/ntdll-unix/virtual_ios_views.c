/* Part of virtual_ios.c, #included from it at this place: one translation unit, never compiled
 * on its own. Builtin modules and unix libraries, free ranges, page protections, views. Same copyright and licence as virtual_ios.c. */
/***********************************************************************
 *           add_builtin_module
 */
static void add_builtin_module( void *module, void *handle )
{
    struct builtin_module *builtin;

    if (!(builtin = malloc( sizeof(*builtin) ))) return;
    builtin->handle      = handle;
    builtin->module      = module;
    builtin->refcount    = 1;
    builtin->unix_path   = NULL;
    builtin->unix_handle = NULL;
    list_add_tail( &builtin_modules, &builtin->entry );
}


/***********************************************************************
 *           get_builtin_module
 */
static struct builtin_module *get_builtin_module( void *module )
{
    struct builtin_module *builtin;

    LIST_FOR_EACH_ENTRY( builtin, &builtin_modules, struct builtin_module, entry )
        if (builtin->module == module) return builtin;

    return NULL;
}


/***********************************************************************
 *           release_builtin_module
 */
static void release_builtin_module( void *module )
{
    struct builtin_module *builtin = get_builtin_module( module );

    if (!builtin) return;
    if (--builtin->refcount) return;
    list_remove( &builtin->entry );
    if (builtin->handle) dlclose( builtin->handle );
    if (builtin->unix_handle) dlclose( builtin->unix_handle );
    free( builtin->unix_path );
    free( builtin );
}


/***********************************************************************
 *           get_builtin_so_handle
 */
void *get_builtin_so_handle( void *module )
{
    sigset_t sigset;
    void *ret = NULL;
    struct builtin_module *builtin;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((builtin = get_builtin_module( module )))
    {
        ret = builtin->handle;
        if (ret) builtin->refcount++;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return ret;
}


/***********************************************************************
 *           get_unixlib_funcs
 */
static NTSTATUS get_unixlib_funcs( void *so_handle, BOOL wow, const void **funcs, NTSTATUS (**entry)(void) )
{
    *funcs = dlsym( so_handle, wow ? "__wine_unix_call_wow64_funcs" : "__wine_unix_call_funcs" );
    *entry = dlsym( so_handle, "__wine_unix_lib_init" );
    return *funcs || *entry ? STATUS_SUCCESS : STATUS_ENTRYPOINT_NOT_FOUND;
}


/***********************************************************************
 *           load_builtin_unixlib
 */
#ifdef WINE_IOS
static NTSTATUS ios_stub_unix_call(void *args) {
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS ios_stub_unix_call_ok(void *args) {
    return STATUS_SUCCESS;
}

/* iOS-Madeira 2026-07-10: the unixlib "funcs" value handed back to the PE
 * side is a TABLE that __wine_unix_call_dispatcher indexes as
 * funcs[code](args) — storing a bare function there makes UNIX_CALL read
 * the stub's own instruction bytes as a pointer and blr to garbage (the
 * Steam vgui2/opengl32 crash). The no-unix-side fallback must therefore
 * be a table of stubs. 4096 slots covers the largest builtin enum
 * (opengl32 funcs_count = 3107). */
#define IOS_STUB_TABLE_SIZE 4096
static unixlib_entry_t ios_stub_unix_call_table[IOS_STUB_TABLE_SIZE];
/* opengl32 variant: process_attach / thread_attach / process_detach
 * (codes 0-2 in dlls/opengl32/unixlib.h) return SUCCESS so DllMain lets
 * the DLL load; every real wgl/gl call fails with NOT_SUPPORTED (no host
 * GL on iOS — DXMT is D3D-only, callers must treat GL as absent). */
static unixlib_entry_t ios_gl_stub_unix_call_table[IOS_STUB_TABLE_SIZE];

static pthread_once_t ios_stub_tables_once = PTHREAD_ONCE_INIT;
static void ios_init_stub_tables(void)
{
    unsigned int i;
    for (i = 0; i < IOS_STUB_TABLE_SIZE; i++)
        ios_stub_unix_call_table[i] = ios_gl_stub_unix_call_table[i] = ios_stub_unix_call;
    ios_gl_stub_unix_call_table[0] = ios_stub_unix_call_ok;  /* process_attach */
    ios_gl_stub_unix_call_table[1] = ios_stub_unix_call_ok;  /* thread_attach */
    ios_gl_stub_unix_call_table[2] = ios_stub_unix_call_ok;  /* process_detach */
}

/* DXMT's unix call table, statically linked into Madeira.app via
 * libdxmt_combined.a (originally __wine_unix_call_funcs, renamed in
 * winemetal_unix.c to avoid collision with our own ntdll table). */
extern const void *dxmt_winemetal_unix_call_funcs[];

/* DXMT's winemetal_unix.c, linked into the same image, reports per-frame
 * statistics into a "[frame]" instrument through the symbols below.  That
 * instrument is a diagnostic and is not part of this port, so this is its off
 * state: ios_frame_stats_on stays 0, which winemetal checks before any
 * per-frame hook, and the entry points it calls unconditionally do nothing.
 * Nothing here allocates, logs or takes a lock. */
int ios_frame_stats_on = 0;
void ios_frame_game_tick(void) { }
void ios_frame_encode_present( int skipped ) { }
void ios_frame_drawable_wait( unsigned long long ns ) { }
void ios_frame_gpu( unsigned long long gpu_ns, unsigned long long inflight ) { }
void ios_frame_note_display( int panel_hz, int intent_hz, int mode ) { }
void ios_frame_limiter( unsigned long long ns ) { }
void ios_frame_pass( unsigned kind, unsigned loads, unsigned stores, unsigned clears ) { }

/* iOS-Madeira 2026-05-13: null audio driver unix table. Implements the 37
 * mmdevapi audio funcs to provide a fake "iOS Null" render endpoint with
 * a real-time IAudioClock — enough for FMOD's rhythm-game timing engine
 * to advance past audio-gated splash/intro sequences. See audio_null_ios.c */
extern const void *audio_null_ios_unix_call_funcs[];

/* iOS-Madeira 2026-07-05 (Steam S0): network + crypto unix tables,
 * compiled from wine/dlls/<dll>/ sources into libntdll_unix.a with
 * -D__wine_unix_call_funcs=<dll>_unix_call_funcs (build/ntdll-unix/
 * build.sh compile_unixlib). The GnuTLS-backed ones (bcrypt, secur32,
 * crypt32) resolve libgnutls statically via build/crypto-unix/
 * gnutls_symtab_ios.c instead of dlopen. */
extern const void *ws2_32_unix_call_funcs[];
extern const void *bcrypt_unix_call_funcs[];
extern const void *secur32_unix_call_funcs[];
extern const void *crypt32_unix_call_funcs[];

/* iOS-Madeira 2026-08-03 (#79 transport): in-process NSI TCP connection
 * tables — nsiproxy.sys is not shipped, PE nsi.dll falls back to this
 * when \\.\Nsi can't be opened. See nsi_unixlib_ios.c */
extern const void *nsi_unix_call_funcs[];

/* dnsapi's unix side (the system resolver), compiled from upstream
 * dlls/dnsapi/libresolv.c by build/ntdll-unix/dnsapi_unixlib_ios.c. Without it
 * dnsapi.dll got the generic stub table below, so DnsQuery_* and the DNS
 * server list that iphlpapi's GetAdaptersAddresses asks for failed with
 * STATUS_NOT_SUPPORTED, and so did GetAdaptersAddresses itself. */
extern const void *dnsapi_unix_call_funcs[];

/* iOS-Madeira ml494 (#61 text wall): dwrite's unix side (freetype glyph
 * rasterisation). Without it every __wine_unix_call from dwrite.dll failed,
 * so get_glyph_bbox never ran and every glyph run reported an EMPTY bbox —
 * ml494 measured exactly that (12/12 [dwrite-bounds] EMPTY, [dwrite-ink]
 * never called). Chromium drew no text anywhere as a result. */
extern const void *dwrite_unix_call_funcs[];

/* MADEIRA 2026-09-19: winegstreamer's unix side, which upstream implements
 * with GStreamer (dlls/winegstreamer/wg_transform.c, wg_parser.c) and this
 * port implements with FFmpeg's libavcodec/libavformat plus VideoToolbox and
 * AudioToolbox (build/ntdll-unix/winegstreamer_unixlib_ios.c, which includes
 * wg_parser_av_ios.c).  Without it winegstreamer.dll could not load at all, so
 * CLSID_CWMADecMediaObject -> wmadmod.dll -> CLSID_wg_wma_decoder had no class
 * object, FAudio got no decoder for an xWMA/WMA voice, and xaudio2 played the
 * COMPRESSED bytes as PCM -- the static, and the 8x-full-scale peaks in the
 * audio census.  The table implements the wg_transform subset wma_decoder.c
 * uses (WMA family only) and the wg_parser behind quartz's MP3/WAV splitters
 * and Media Foundation's MP4 source; the wg_muxer entries return
 * STATUS_NOT_IMPLEMENTED. */
extern const void *winegstreamer_unix_call_funcs[];

/* win32u's unix init, statically linked via libwin32u_unix.a. Renamed
 * from __wine_unix_lib_init in build/win32u-unix/build.sh so future
 * statically-linked unix libs can keep their own init without colliding.
 * win32u doesn't use the unix_call_funcs dispatch — its PE side uses
 * __wine_syscall_dispatcher and slot 1 of KeServiceDescriptorTable,
 * which win32u_unix_lib_init() populates via KeAddSystemServiceTable. */
extern NTSTATUS win32u_unix_lib_init(void);

/* The 32-bit counterparts of the tables above.  An entry of a wow64 table
 * reads its argument block with the 32-bit layout and converts the guest
 * pointers inside it (+B, see ios_wow_host_ptr()), so a 32-bit caller must
 * never be handed a 64-bit table.  build.sh's compile_unixlib() renames each
 * compiled library's __wine_unix_call_wow64_funcs to <prefix>_unix_call_
 * wow64_funcs; the audio driver and NSI name theirs in the source, and
 * DXMT's winemetal_unix.c renames its own to
 * dxmt_winemetal_unix_call_wow64_funcs.  A library without one is refused for
 * a 32-bit caller. */
extern const void *dxmt_winemetal_unix_call_wow64_funcs[];
extern const void *ws2_32_unix_call_wow64_funcs[];
extern const void *bcrypt_unix_call_wow64_funcs[];
extern const void *secur32_unix_call_wow64_funcs[];
extern const void *crypt32_unix_call_wow64_funcs[];
extern const void *dwrite_unix_call_wow64_funcs[];
extern const void *audio_null_ios_unix_call_wow64_funcs[];
extern const void *nsi_unix_call_wow64_funcs[];
extern const void *dnsapi_unix_call_wow64_funcs[];
/* The native D3D9 frontend's table for the i386 d3d9shim.dll (dxmt,
 * generated by src/d3d9shim/gen_d3d9_thunks.py into d3d9_unix_table.c). */
extern const void *const dxmt_d3d9_unix_call_wow64_funcs[];
/* winegstreamer's is written by hand in winegstreamer_unixlib_ios.c, because
 * dlls/winegstreamer/unixlib.h carries no 32-bit param structs at all (nothing
 * upstream enters that unixlib from the other bitness).  The entries that
 * differ are the ones holding a struct wg_media_type (its union is a pointer,
 * so the struct is 24 bytes and not 32) and the two that hold a
 * struct wg_sample * -- including the guest pointer inside wg_sample->data,
 * which is where the caller's compressed input and PCM output actually live. */
extern const void *winegstreamer_unix_call_wow64_funcs[];

/* MADEIRA: winegstreamer's unix side is bound for 32-bit (wow64) callers.
 * A 64-bit (ARM64EC) caller gets it only with MADEIRA_WG_64BIT=1 (env, or
 * env.MADEIRA_WG_64BIT = 1 in madeira.cfg); by default it keeps the generic
 * stub table, as upstream. */
static BOOL ios_wg_64bit_opted_in(void)
{
    const char *e = getenv( "MADEIRA_WG_64BIT" );
    return e && e[0] == '1';
}

/* dnsapi's unix side is bound unless MADEIRA_DNSAPI_UNIXLIB=0, which keeps the
 * stub table (every dnsapi unix call STATUS_NOT_SUPPORTED) as before. */
static BOOL ios_dnsapi_unixlib_enabled(void)
{
    const char *e = getenv( "MADEIRA_DNSAPI_UNIXLIB" );
    return !(e && e[0] == '0');
}

/***********************************************************************
 *           ios_module_export_name
 *
 * MADEIRA name a mapped PE
 * from its export directory, for PE32 **and** PE32+.
 *
 * This used to walk the headers through IMAGE_NT_HEADERS, which in this
 * 64-bit build is IMAGE_NT_HEADERS64.  For an i386 image that is the wrong
 * struct: IMAGE_OPTIONAL_HEADER32 puts DataDirectory at +96 and
 * IMAGE_OPTIONAL_HEADER64 puts it at +112, so
 * DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] read through the 64-bit
 * spelling actually reads DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE] of
 * a 32-bit image.  None of the i386 builtins we ship has a resource
 * directory, so the RVA came back 0, every 32-bit module was named
 * "(unknown)", and the by-name match chain in load_builtin_unixlib() could
 * never recognise one.  (Device log: the i386 winemetal.dll at guest base
 * 0x7b4b0000 has its export directory at RVA 0xa618 and DataDirectory[2]
 * == 0, and was logged as "[unixlib] (unknown) -> wow64 table".)
 */
static const char *ios_module_export_name( const void *module )
{
    const IMAGE_DOS_HEADER *dos = module;
    const IMAGE_NT_HEADERS32 *nt;
    const IMAGE_EXPORT_DIRECTORY *exp;
    DWORD exp_rva = 0, dirs = 0, size_of_image = 0;

    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (const IMAGE_NT_HEADERS32 *)((const char *)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    /* Magic sits at the same offset in both optional headers; everything
     * after it does not. */
    switch (nt->OptionalHeader.Magic)
    {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        dirs = nt->OptionalHeader.NumberOfRvaAndSizes;
        size_of_image = nt->OptionalHeader.SizeOfImage;
        if (dirs > IMAGE_DIRECTORY_ENTRY_EXPORT)
            exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        break;
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
    {
        const IMAGE_NT_HEADERS64 *nt64 = (const IMAGE_NT_HEADERS64 *)nt;
        dirs = nt64->OptionalHeader.NumberOfRvaAndSizes;
        size_of_image = nt64->OptionalHeader.SizeOfImage;
        if (dirs > IMAGE_DIRECTORY_ENTRY_EXPORT)
            exp_rva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        break;
    }
    default:
        return NULL;
    }

    if (!exp_rva || !size_of_image) return NULL;
    if (exp_rva >= size_of_image || size_of_image - exp_rva < sizeof(*exp)) return NULL;
    exp = (const IMAGE_EXPORT_DIRECTORY *)((const char *)module + exp_rva);
    if (!exp->Name || exp->Name >= size_of_image) return NULL;
    return (const char *)module + exp->Name;
}


static unsigned int get_memory_section_name( HANDLE process, LPCVOID addr,
                                             MEMORY_SECTION_NAME *info, SIZE_T len, SIZE_T *ret_len );

/***********************************************************************
 *           ios_module_mapped_file_name
 *
 * MADEIRA: last-resort identification for a mapped image whose export
 * directory is missing or unreadable — ask the wineserver which file the
 * view came from and keep the lowercased basename.  This is the same
 * information FEX's image-map hook uses to name i386 images, and it is the
 * only name available for a PE that exports nothing.  Only used when the
 * export name and the builtin unix_path are both unavailable, so the server
 * round trip never lands on the hot path.
 */
static BOOL ios_module_mapped_file_name( const void *module, char *buf, size_t buflen )
{
    struct
    {
        MEMORY_SECTION_NAME info;
        WCHAR data[512];
    } sec;
    const WCHAR *name;
    unsigned int len, i, start = 0, out = 0;

    if (!buf || buflen < 2) return FALSE;
    buf[0] = 0;
    if (get_memory_section_name( GetCurrentProcess(), module, &sec.info, sizeof(sec), NULL ))
        return FALSE;

    name = sec.info.SectionFileName.Buffer;
    len = sec.info.SectionFileName.Length / sizeof(WCHAR);
    if (!name || !len) return FALSE;
    for (i = 0; i < len; i++)
        if (name[i] == '\\' || name[i] == '/') start = i + 1;
    for (i = start; i < len && out < buflen - 1; i++)
    {
        char c = (char)(name[i] & 0x7f);
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        buf[out++] = c;
    }
    buf[out] = 0;
    return out != 0;
}


/***********************************************************************
 *           ios_bind_unixlib_table
 *
 * Pick the 64-bit or the wow64 table for the calling process and log the
 * choice once per unixlib load.  funcs_wow64 == NULL means "this library
 * has no 32-bit table", which fails the load for a 32-bit caller instead
 * of binding a table whose argument layout does not match (no fake success).
 */
static NTSTATUS ios_bind_unixlib_table( void *module, const char *libname, BOOL wow,
                                        const void *funcs64, const void *funcs_wow64,
                                        const void **funcs )
{
    const void *table = wow ? funcs_wow64 : funcs64;

    if (!table)
    {
        /* MADEIRA 2026-09-15: dprintf, not ERR.  This file's debug channel is
         * `virtual`, and the app runs with WINEDEBUG=err+all,err-virtual
         * (WineProcessBridge.m:505) — so every refusal logged here has been
         * INVISIBLE, which is why log n60 shows dnsapi's DllMain complaining
         * and no [unixlib] line for it at all.  A library losing its unix side
         * is the first half of every NULL-handle crash and has to be loud. */
        dprintf( 2, "[unixlib] %s (module %p) has no unix side on this port: no %s unix call "
                 "table — failing the load rather than binding the %s table to a %s caller\n",
                 libname, module, wow ? "wow64" : "64-bit", wow ? "64-bit" : "wow64",
                 wow ? "32-bit" : "64-bit" );
        return STATUS_NOT_SUPPORTED;
    }
    dprintf( 2, "[unixlib] %s (module %p) -> %s table (%p)\n",
             libname, module, wow ? "wow64" : "64-bit", table );
    *funcs = table;
    return STATUS_SUCCESS;
}
#endif
static NTSTATUS load_builtin_unixlib( void *module, BOOL wow, const void **funcs )
{
    NTSTATUS (*entry)(void) = NULL;
    sigset_t sigset;
    NTSTATUS status = STATUS_DLL_NOT_FOUND;
    struct builtin_module *builtin;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((builtin = get_builtin_module( module )))
    {
        if (builtin->unix_path && !builtin->unix_handle)
        {
            builtin->unix_handle = dlopen( builtin->unix_path, RTLD_NOW );
            if (!builtin->unix_handle)
                WARN_(module)( "failed to load %s: %s\n", debugstr_a(builtin->unix_path), dlerror() );
        }
        if (builtin->unix_handle) status = get_unixlib_funcs( builtin->unix_handle, wow, funcs, &entry );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    if (!status && entry) status = entry();
#ifdef WINE_IOS
    /* On iOS, unix .so files aren't available for most DLLs.
     * Detect the special case where the unix_path names a DLL whose unix
     * side is statically linked into Madeira.app, and point funcs at that
     * table instead of the dummy stub. */
    if (status == STATUS_DLL_NOT_FOUND)
    {
        /* unix_path may not be set on iOS (our loader doesn't always call
         * set_builtin_unixlib_name), so fall back to reading the DLL name
         * from the PE export directory (ios_module_export_name() handles
         * both PE32 and PE32+ — see the note there; the 64-bit-only parse it
         * replaces named every i386 module "(unknown)"), and then to the
         * name of the file the view was mapped from. */
        const char *modname = ios_module_export_name( module );
        char secname[128];
        const char *up = NULL;
        const char *match;

        if ((builtin = get_builtin_module( module ))) up = builtin->unix_path;
        match = up ? up : modname;
        secname[0] = 0;
        /* a 32-bit caller only: a 64-bit module keeps the upstream matching */
        if (!match && wow && ios_module_mapped_file_name( module, secname, sizeof(secname) ))
            match = secname;
        /* Each branch only names the
         * library's pair of tables; ios_bind_unixlib_table() below picks the
         * one that matches the caller's bitness and logs it.  The stub tables
         * are listed for both because their entries ignore `args` entirely,
         * so they have no layout to get wrong. */
        const char *libname = NULL;
        const void *funcs64 = NULL, *funcs_wow64 = NULL;
        if (match && strstr(match, "winemetal")) {
            libname = "winemetal";
            funcs64 = (const void *)dxmt_winemetal_unix_call_funcs;
            funcs_wow64 = (const void *)dxmt_winemetal_unix_call_wow64_funcs;
        } else if (wow && ((match && strstr(match, "d3d9shim")) ||
                           (modname && strstr(modname, "d3d9shim")))) {
            /* The i386 D3D9 shim, bound to the native ARM64 frontend.  A
             * 32-bit caller only: a 64-bit module keeps the upstream matching
             * below.  Matched on "d3d9shim", not "d3d9": the emulated frontend
             * ships beside the shim as d3d9-emulated.dll, imports winemetal
             * rather than a d3d9 unix side, and must not get this table.
             * `modname` is tested as well as `match` because the shim is
             * installed as d3d9.dll, so a unix_path would read "d3d9.so"; its
             * PE export name stays d3d9shim.dll whatever the file is called. */
            libname = "d3d9shim";
            funcs_wow64 = (const void *)dxmt_d3d9_unix_call_wow64_funcs;
        } else if (match && (strstr(match, "wineios.drv") || strstr(match, "winecoreaudio") || strstr(match, "winealsa") || strstr(match, "winepulse"))) {
            /* NOTE: mmdevapi does NOT reach the driver through this by-module
             * path — __wine_load_unix_lib() asks for "wine<name>.drv" BY NAME
             * and NtQueryVirtualMemory(MemoryWineLoadUnixLibByName[Wow64])
             * binds the table there (see the audio branch in this file's
             * NtQueryVirtualMemory), so no .drv PE is ever mapped and the
             * i386 farm needs no driver file.  This branch stays for a module
             * that IS mapped (a real winealsa/winepulse PE in a prefix), and
             * now offers the wow64 table for the same reason. */
            libname = "audio_null_ios";
            funcs64 = (const void *)audio_null_ios_unix_call_funcs;
            funcs_wow64 = (const void *)audio_null_ios_unix_call_wow64_funcs;
        } else if (match && strstr(match, "ws2_32")) {
            libname = "ws2_32";
            funcs64 = (const void *)ws2_32_unix_call_funcs;
            funcs_wow64 = (const void *)ws2_32_unix_call_wow64_funcs;
        } else if (match && strstr(match, "bcrypt")) {
            libname = "bcrypt";
            funcs64 = (const void *)bcrypt_unix_call_funcs;
            funcs_wow64 = (const void *)bcrypt_unix_call_wow64_funcs;
        } else if (match && strstr(match, "secur32")) {
            libname = "secur32";
            funcs64 = (const void *)secur32_unix_call_funcs;
            funcs_wow64 = (const void *)secur32_unix_call_wow64_funcs;
        } else if (match && strstr(match, "crypt32")) {
            libname = "crypt32";
            funcs64 = (const void *)crypt32_unix_call_funcs;
            funcs_wow64 = (const void *)crypt32_unix_call_wow64_funcs;
        } else if (match && (strstr(match, "dwrite") || strstr(match, "DWrite"))) {
            /* case-insensitive on purpose: the PE export name is "DWrite.dll"
             * while the unix_path is "dwrite.so" — matching only one spelling
             * would silently leave the text stack dead again.
             *
             * MADEIRA: dwrite's wow64 table comes straight from the included
             * dlls/dwrite/freetype.c.  Its eight thunks now convert every
             * embedded pointer with ios_wow_host_ptr() (M5), including the two
             * array bases nested inside struct dwrite_outline32, so a 32-bit
             * dwrite.dll's font data, glyph outlines and OUT slots resolve
             * inside the guest window like ws2_32/bcrypt/secur32/crypt32. */
            libname = "dwrite (rev=ml494)";
            funcs64 = (const void *)dwrite_unix_call_funcs;
            funcs_wow64 = (const void *)dwrite_unix_call_wow64_funcs;
        } else if (match && strstr(match, "winegstreamer") && (wow || ios_wg_64bit_opted_in())) {
            /* MADEIRA 2026-09-19: matched before the generic fallback so the
             * DLL loads at all.  Upstream binds "winegstreamer.so"; the PE
             * export name is "winegstreamer.dll" — "winegstreamer" is the
             * substring both spellings share.  The wow64 table is real (not
             * the stub): a 32-bit title is the whole reason this exists, and
             * its thunks convert the struct wg_media_type / struct wg_sample
             * pointers that the 32-bit layouts place at different offsets.
             *
             * 64-bit (ARM64EC) callers are OPT-IN: unless MADEIRA_WG_64BIT=1
             * this branch is not taken for them, so they reach the generic
             * fallback below exactly as before this table existed and the
             * 64-bit engine's default behaviour does not change. */
            libname = wow ? "winegstreamer (wma + wg_parser, libav*)"
                          : "winegstreamer (wma + wg_parser, libav*; 64-bit opted in)";
            funcs64 = (const void *)winegstreamer_unix_call_funcs;
            funcs_wow64 = (const void *)winegstreamer_unix_call_wow64_funcs;
        } else if (match && strstr(match, "nsi.dll")) {
            libname = "nsi (rev=ml472)";
            funcs64 = (const void *)nsi_unix_call_funcs;
            funcs_wow64 = (const void *)nsi_unix_call_wow64_funcs;
        } else if (match && (strstr(match, "dnsapi") || strstr(match, "DNSAPI")) && ios_dnsapi_unixlib_enabled()) {
            /* "dnsapi" matches the export name and a unix_path of "dnsapi.so". */
            libname = "dnsapi (libresolv)";
            funcs64 = (const void *)dnsapi_unix_call_funcs;
            funcs_wow64 = (const void *)dnsapi_unix_call_wow64_funcs;
        } else if (match && strstr(match, "win32u")) {
            /* Register win32u's NtUser / NtGdi syscall table in slot 1.
             * Activating this causes user32 process_attach to crash until
             * wineserver shared-memory bringup is complete; gated on the
             * MADEIRA_WIN32U env var so we can flip it on for debugging. */
            pthread_once( &ios_stub_tables_once, ios_init_stub_tables );
            if (getenv("MADEIRA_WIN32U")) {
                NTSTATUS s = win32u_unix_lib_init();
                WARN_(module)("iOS: module %p (%s) -> win32u_unix_lib_init() = 0x%x (ACTIVE)\n",
                              module, match, s);
            } else {
                WARN_(module)("iOS: module %p (%s) -> win32u unix lib linked but dormant\n",
                              module, match);
            }
            libname = "win32u (stub table)";
            funcs64 = funcs_wow64 = (const void *)ios_stub_unix_call_table;
        } else if (match && strstr(match, "opengl32")) {
            pthread_once( &ios_stub_tables_once, ios_init_stub_tables );
            WARN_(module)("iOS: module %p (%s) -> GL-absent stub table (attach ok, wgl/gl NOT_SUPPORTED)\n",
                          module, match);
            libname = "opengl32 (GL-absent stub table)";
            funcs64 = funcs_wow64 = (const void *)ios_gl_stub_unix_call_table;
        } else {
            pthread_once( &ios_stub_tables_once, ios_init_stub_tables );
            WARN_(module)("iOS: no unix .so for module %p (unix_path=%s, modname=%s, mapped=%s), using stub table\n",
                          module, up ? up : "(null)", modname ? modname : "(null)",
                          secname[0] ? secname : "(null)");
            libname = modname ? modname : (up ? up : (secname[0] ? secname : "(unknown)"));
            funcs64 = (const void *)ios_stub_unix_call_table;
            /* No fake success: a 32-bit
             * caller must never be handed the stub table.  Its entries return
             * STATUS_NOT_SUPPORTED but leave every OUTPUT field of the argument
             * block untouched, and PE-side unix-call wrappers routinely ignore
             * the status and use those fields — so an unrecognised module turns
             * a missing unix side into uninitialised pointers in 32-bit code
             * and, eventually, a wild access somewhere in the guest window.
             * Fail the load loudly instead; the 64-bit path keeps the stub
             * table it has always had. */
            funcs_wow64 = NULL;
            if (wow)
                dprintf( 2, "[unixlib] UNRECOGNISED module %p (export name %s, unix_path %s, "
                         "mapped file %s) has no unix side on this port: no statically linked "
                         "wow64 unix call table matches — refusing with STATUS_NOT_SUPPORTED "
                         "instead of binding the stub table to a 32-bit caller\n",
                         module, modname ? modname : "(none)", up ? up : "(none)",
                         secname[0] ? secname : "(none)" );
        }
        status = ios_bind_unixlib_table( module, libname, wow, funcs64, funcs_wow64, funcs );
    }
#endif
    return status;
}


/***********************************************************************
 *           set_builtin_unixlib_name
 */
NTSTATUS set_builtin_unixlib_name( void *module, const char *name )
{
    sigset_t sigset;
    NTSTATUS status = STATUS_SUCCESS;
    struct builtin_module *builtin;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if ((builtin = get_builtin_module( module )))
    {
        if (!builtin->unix_path) builtin->unix_path = strdup( name );
        else status = STATUS_IMAGE_ALREADY_LOADED;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    return status;
}


/***********************************************************************
 *           free_ranges_lower_bound
 *
 * Returns the first range whose end is not less than addr, or end if there's none.
 */
static struct range_entry *free_ranges_lower_bound( void *addr )
{
    struct range_entry *begin = free_ranges;
    struct range_entry *end = free_ranges_end;
    struct range_entry *mid;

    while (begin < end)
    {
        mid = begin + (end - begin) / 2;
        if (mid->end < addr)
            begin = mid + 1;
        else
            end = mid;
    }

    return begin;
}

static void dump_free_ranges(void)
{
    struct range_entry *r;
    for (r = free_ranges; r != free_ranges_end; ++r)
        TRACE_(virtual_ranges)("%p - %p.\n", r->base, r->end);
}

/***********************************************************************
 *           free_ranges_insert_view
 *
 * Updates the free_ranges after a new view has been created.
 */
static void free_ranges_insert_view( struct file_view *view )
{
    void *view_base = ROUND_ADDR( view->base, granularity_mask );
    void *view_end = ROUND_ADDR( (char *)view->base + view->size + granularity_mask, granularity_mask );
    struct range_entry *range = free_ranges_lower_bound( view_base );
    struct range_entry *next = range + 1;

    /* free_ranges initial value is such that the view is either inside range or before another one. */
    assert( range != free_ranges_end );
    assert( range->end > view_base || next != free_ranges_end );

    /* Free ranges addresses are aligned at granularity_mask while the views may be not. */

    if (range->base > view_base)
        view_base = range->base;
    if (range->end < view_end)
        view_end = range->end;
    if (range->end == view_base && next->base >= view_end)
        view_end = view_base;

    TRACE_(virtual_ranges)( "%p - %p, aligned %p - %p.\n",
                            view->base, (char *)view->base + view->size, view_base, view_end );

    if (view_end <= view_base)
    {
        VIRTUAL_DEBUG_DUMP_RANGES();
        return;
    }

    /* this should never happen */
    if (range->base > view_base || range->end < view_end)
        ERR( "range %p - %p is already partially mapped\n", view_base, view_end );
    assert( range->base <= view_base && range->end >= view_end );

    /* need to split the range in two */
    if (range->base < view_base && range->end > view_end)
    {
        memmove( next + 1, next, (free_ranges_end - next) * sizeof(struct range_entry) );
        free_ranges_end += 1;
        if ((char *)free_ranges_end - (char *)free_ranges > view_block_size)
            ERR( "Free range sequence is full, trouble ahead!\n" );
        assert( (char *)free_ranges_end - (char *)free_ranges <= view_block_size );

        next->base = view_end;
        next->end = range->end;
        range->end = view_base;
    }
    else
    {
        /* otherwise we just have to shrink it */
        if (range->base < view_base)
            range->end = view_base;
        else
            range->base = view_end;

        if (range->base < range->end)
        {
            VIRTUAL_DEBUG_DUMP_RANGES();
            return;
        }
        /* and possibly remove it if it's now empty */
        memmove( range, next, (free_ranges_end - next) * sizeof(struct range_entry) );
        free_ranges_end -= 1;
        assert( free_ranges_end - free_ranges > 0 );
    }
    VIRTUAL_DEBUG_DUMP_RANGES();
}

/***********************************************************************
 *           free_ranges_remove_view
 *
 * Updates the free_ranges after a view has been destroyed.
 */
static void free_ranges_remove_view( struct file_view *view )
{
    void *view_base = ROUND_ADDR( view->base, granularity_mask );
    void *view_end = ROUND_ADDR( (char *)view->base + view->size + granularity_mask, granularity_mask );
    struct range_entry *range = free_ranges_lower_bound( view_base );
    struct range_entry *next = range + 1;

    /* Free ranges addresses are aligned at granularity_mask while the views may be not. */
    struct file_view *prev_view = RB_ENTRY_VALUE( rb_prev( &view->entry ), struct file_view, entry );
    struct file_view *next_view = RB_ENTRY_VALUE( rb_next( &view->entry ), struct file_view, entry );
    void *prev_view_base = prev_view ? ROUND_ADDR( prev_view->base, granularity_mask ) : NULL;
    void *prev_view_end = prev_view ? ROUND_ADDR( (char *)prev_view->base + prev_view->size + granularity_mask, granularity_mask ) : NULL;
    void *next_view_base = next_view ? ROUND_ADDR( next_view->base, granularity_mask ) : NULL;
    void *next_view_end = next_view ? ROUND_ADDR( (char *)next_view->base + next_view->size + granularity_mask, granularity_mask ) : NULL;

    if (prev_view_end && prev_view_end > view_base && prev_view_base < view_end)
        view_base = prev_view_end;
    if (next_view_base && next_view_base < view_end && next_view_end > view_base)
        view_end = next_view_base;

    TRACE_(virtual_ranges)( "%p - %p, aligned %p - %p.\n",
                            view->base, (char *)view->base + view->size, view_base, view_end );

    if (view_end <= view_base)
    {
        VIRTUAL_DEBUG_DUMP_RANGES();
        return;
    }
    /* free_ranges initial value is such that the view is either inside range or before another one. */
    assert( range != free_ranges_end );
    assert( range->end > view_base || next != free_ranges_end );

    /* this should never happen, but we can safely ignore it */
    if (range->base <= view_base && range->end >= view_end)
    {
        WARN( "range %p - %p is already unmapped\n", view_base, view_end );
        return;
    }

    /* this should never happen */
    if (range->base < view_end && range->end > view_base)
        ERR( "range %p - %p is already partially unmapped\n", view_base, view_end );
    assert( range->end <= view_base || range->base >= view_end );

    /* merge with next if possible */
    if (range->end == view_base && next->base == view_end)
    {
        range->end = next->end;
        memmove( next, next + 1, (free_ranges_end - next - 1) * sizeof(struct range_entry) );
        free_ranges_end -= 1;
        assert( free_ranges_end - free_ranges > 0 );
    }
    /* or try growing the range */
    else if (range->end == view_base)
        range->end = view_end;
    else if (range->base == view_end)
        range->base = view_base;
    /* otherwise create a new one */
    else
    {
        memmove( range + 1, range, (free_ranges_end - range) * sizeof(struct range_entry) );
        free_ranges_end += 1;
        if ((char *)free_ranges_end - (char *)free_ranges > view_block_size)
            ERR( "Free range sequence is full, trouble ahead!\n" );
        assert( (char *)free_ranges_end - (char *)free_ranges <= view_block_size );

        range->base = view_base;
        range->end = view_end;
    }
    VIRTUAL_DEBUG_DUMP_RANGES();
}


static inline int is_view_valloc( const struct file_view *view )
{
    return !(view->protect & (SEC_FILE | SEC_RESERVE | SEC_COMMIT));
}

/***********************************************************************
 *           get_page_vprot
 *
 * Return the page protection byte.
 */
static BYTE get_page_vprot( const void *addr )
{
    size_t idx = (size_t)addr >> page_shift;

#ifdef _WIN64
    if ((idx >> pages_vprot_shift) >= pages_vprot_size) return 0;
    if (!pages_vprot[idx >> pages_vprot_shift]) return 0;
    return pages_vprot[idx >> pages_vprot_shift][idx & pages_vprot_mask];
#else
    return pages_vprot[idx];
#endif
}

/* iOS-Madeira ml306 (task #53): lock-free vprot peek for the Mach reclaim handler.
 *
 * The [reclaim-recover] path in signal_arm64_ios.c re-mmaps arena-band pages whose host
 * mapping has vanished (mprotect ENOMEM), on the assumption that fresh zeros are correct.
 * That assumption was written for LookupCache pages; the band now holds FEX's entire host
 * heap, and ml305 died on a null+0x90 deref through a pointer that plausibly came from such
 * a zero-filled page. Whether zero-fill is safe hinges on one bit that only Wine knows:
 * VPROT_COMMITTED. Committed-then-vanished means data loss or use-after-free (zeros MASK a
 * real bug); never-committed means lazy-reservation first touch (zeros are the contract).
 *
 * Deliberately no locking: this is called from the Mach exception thread while the faulting
 * thread is suspended possibly holding virtual_mutex, so taking any lock could deadlock.
 * get_page_vprot is a plain two-level array read and the fault paths already use it this
 * way; a stale read only mislabels one diagnostic line. */
unsigned char ios_reclaim_page_vprot( unsigned long long va )
{
    return get_page_vprot( (const void *)(uintptr_t)va );
}


/***********************************************************************
 *           get_host_page_vprot
 *
 * Return the union of the page protection bytes of all the pages making up the host page.
 */
static BYTE get_host_page_vprot( const void *addr )
{
    size_t i, idx = (size_t)ROUND_ADDR( addr, host_page_mask ) >> page_shift;
    const BYTE *vprot_ptr;
    BYTE vprot = 0;

#ifdef _WIN64
    if ((idx >> pages_vprot_shift) >= pages_vprot_size) return 0;
    if (!pages_vprot[idx >> pages_vprot_shift]) return 0;
    assert( host_page_mask >> page_shift <= pages_vprot_mask );
    vprot_ptr = pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask);
#else
    vprot_ptr = pages_vprot + idx;
#endif
    for (i = 0; i < host_page_size / page_size; i++) vprot |= vprot_ptr[i];
    return vprot;
}


/***********************************************************************
 *           get_vprot_range_size
 *
 * Return the size of the region with equal masked vprot byte.
 * Also return the protections for the first page.
 * The function assumes that base and size are page aligned,
 * base + size does not wrap around and the range is within view so
 * vprot bytes are allocated for the range. */
static SIZE_T get_vprot_range_size( char *base, SIZE_T size, BYTE mask, BYTE *vprot )
{
    static const UINT_PTR word_from_byte = (UINT_PTR)0x101010101010101;
    static const UINT_PTR index_align_mask = sizeof(UINT_PTR) - 1;
    SIZE_T curr_idx, start_idx, end_idx, aligned_start_idx;
    UINT_PTR vprot_word, mask_word;
    const BYTE *vprot_ptr;

    TRACE("base %p, size %p, mask %#x.\n", base, (void *)size, mask);

    curr_idx = start_idx = (size_t)base >> page_shift;
    end_idx = start_idx + (size >> page_shift);

    aligned_start_idx = ROUND_SIZE( 0, start_idx, index_align_mask );
    if (aligned_start_idx > end_idx) aligned_start_idx = end_idx;

#ifdef _WIN64
    vprot_ptr = pages_vprot[curr_idx >> pages_vprot_shift] + (curr_idx & pages_vprot_mask);
#else
    vprot_ptr = pages_vprot + curr_idx;
#endif
    *vprot = *vprot_ptr;

    /* Page count page table is at least the multiples of sizeof(UINT_PTR)
     * so we don't have to worry about crossing the boundary on unaligned idx values. */

    for (; curr_idx < aligned_start_idx; ++curr_idx, ++vprot_ptr)
        if ((*vprot ^ *vprot_ptr) & mask) return (curr_idx - start_idx) << page_shift;

    vprot_word = word_from_byte * *vprot;
    mask_word = word_from_byte * mask;
    for (; curr_idx < end_idx; curr_idx += sizeof(UINT_PTR), vprot_ptr += sizeof(UINT_PTR))
    {
#ifdef _WIN64
        if (!(curr_idx & pages_vprot_mask)) vprot_ptr = pages_vprot[curr_idx >> pages_vprot_shift];
#endif
        if ((vprot_word ^ *(UINT_PTR *)vprot_ptr) & mask_word)
        {
            for (; curr_idx < end_idx; ++curr_idx, ++vprot_ptr)
                if ((*vprot ^ *vprot_ptr) & mask) break;
            return (curr_idx - start_idx) << page_shift;
        }
    }
    return size;
}

/***********************************************************************
 *           set_page_vprot
 *
 * Set a range of page protection bytes.
 */
static void set_page_vprot( const void *addr, size_t size, BYTE vprot )
{
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;

#ifdef _WIN64
    while (idx >> pages_vprot_shift != end >> pages_vprot_shift)
    {
        size_t dir_size = pages_vprot_mask + 1 - (idx & pages_vprot_mask);
        memset( pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask), vprot, dir_size );
        idx += dir_size;
    }
    memset( pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask), vprot, end - idx );
#else
    memset( pages_vprot + idx, vprot, end - idx );
#endif
}


/***********************************************************************
 *           set_page_vprot_bits
 *
 * Set or clear bits in a range of page protection bytes.
 */
static void set_page_vprot_bits( const void *addr, size_t size, BYTE set, BYTE clear )
{
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;

#ifdef _WIN64
    for ( ; idx < end; idx++)
    {
        BYTE *ptr = pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask);
        *ptr = (*ptr & ~clear) | set;
    }
#else
    for ( ; idx < end; idx++) pages_vprot[idx] = (pages_vprot[idx] & ~clear) | set;
#endif
}


/***********************************************************************
 *           set_page_vprot_exec_write_protect
 *
 * Write protect pages that are executable.
 */
static BOOL set_page_vprot_exec_write_protect( const void *addr, size_t size )
{
    BOOL ret = FALSE;
#ifdef _WIN64 /* only supported on 64-bit so assume 2-level table */
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;

    for ( ; idx < end; idx++)
    {
        BYTE *ptr = pages_vprot[idx >> pages_vprot_shift] + (idx & pages_vprot_mask);
        if (!is_vprot_exec_write( *ptr )) continue;
        *ptr |= VPROT_WRITEWATCH;
        ret = TRUE;
    }
#endif
    return ret;
}


/***********************************************************************
 *           alloc_pages_vprot
 *
 * Allocate the page protection bytes for a given range.
 */
static BOOL alloc_pages_vprot( const void *addr, size_t size )
{
#ifdef _WIN64
    size_t idx = (size_t)addr >> page_shift;
    size_t end = ((size_t)addr + size + page_mask) >> page_shift;
    size_t i;
    void *ptr;

    assert( end <= pages_vprot_size << pages_vprot_shift );
    for (i = idx >> pages_vprot_shift; i < (end + pages_vprot_mask) >> pages_vprot_shift; i++)
    {
        if (pages_vprot[i]) continue;
        if ((ptr = anon_mmap_alloc( pages_vprot_mask + 1, PROT_READ | PROT_WRITE )) == MAP_FAILED)
        {
            ERR( "anon mmap error %s for vprot table, size %08lx\n", strerror(errno), pages_vprot_mask + 1 );
            return FALSE;
        }
        pages_vprot[i] = ptr;
    }
#endif
    return TRUE;
}


static inline UINT64 maskbits( size_t idx )
{
    return ~(UINT64)0 << (idx & 63);
}

/***********************************************************************
 *           set_arm64ec_range
 */
static BOOL set_vprot( struct file_view *view, void *base, size_t size, BYTE vprot );  /* fwd-decl */
static void ios_swap_release_range( void *base, size_t size, int copy_back );   /* ml1077 fwd-decls */
static void ios_swap_init( void );
static int ios_swap_eligible( const void *base, size_t size, unsigned int vprot, struct file_view *view );
static void ios_swap_back( void *base, size_t size, unsigned int vprot );

static void set_arm64ec_range( const void *addr, size_t size )
{
    UINT64 *map = arm64ec_view->base;
    /* iOS-Madeira: arm64x_check_call hardcodes 4KB-page indexing per the
     * Windows ABI (`lsr x11, #12` and `lsr x11, #18`) regardless of host
     * page size. iOS uses 16KB pages (page_shift=14). Always use a 12-bit
     * shift here so check_call's reads land at the same bitmap byte we
     * write to. */
    const unsigned int ec_page_shift = 12;
    const size_t ec_page_mask = (1ULL << ec_page_shift) - 1;
    size_t idx = (size_t)addr >> ec_page_shift;
    size_t end = ((size_t)addr + size + ec_page_mask) >> ec_page_shift;
    size_t pos = idx / 64;
    size_t end_pos = end / 64;

    if (end_pos > pos)
    {
        map[pos++] |= maskbits( idx );
        while (pos < end_pos) map[pos++] = ~(UINT64)0;
        if (end & 63) map[pos] |= ~maskbits( end );
    }
    else map[pos] |= maskbits( idx ) & ~maskbits( end );
}

/* Exported: mark an arbitrary range (e.g. hand-written stubs in the pool's
 * reserved page) as ARM64EC code, committing the covering bitmap pages
 * first. Without the bit set, arm64x_check_call routes branches to the
 * range into the x86 emulator, which compiles the ARM64 bytes as x86
 * (observed: the unix-call x18-restore stub executed as guest RIP).
 * Returns 1 if marked, 0 if the EC bitmap doesn't exist yet (caller
 * must treat the range as NOT callable via checked indirect calls). */
int ios_jit_mark_ec_range( const void *addr, size_t size )
{
    if (!arm64ec_view) return 0;
    {
        size_t bm_start = ((size_t)addr >> 12) / 8;
        size_t bm_end   = (((size_t)addr + size) >> 12) / 8;
        size_t bm_size  = ROUND_SIZE( bm_start, bm_end + 1 - bm_start, page_mask );
        void *bm_page   = ROUND_ADDR( (char *)arm64ec_view->base + bm_start, page_mask );
        set_vprot( arm64ec_view, bm_page, bm_size, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED );
    }
    set_arm64ec_range( addr, size );
    return 1;
}

/* upstream's clear_arm64ec_range (defined below) is the inverse of
 * set_arm64ec_range; reclamation clears freed ranges so a reused range
 * that later hosts a pure-x64 copy doesn't keep stale EC bits (which
 * would make arm64x_check_call BL into x86-64 bytes as if ARM64). */
static void clear_arm64ec_range( const void *addr, size_t size );

/* Task #25: release everything a dead pseudo-process allocated from the
 * pool head. Called from process_exit_wrapper on the dying process's own
 * thread — its ranges become reusable after IOS_POOL_REUSE_GRACE_SEC (see
 * the ledger comment for why laggard exit threads make immediate reuse
 * unsafe). Mapping entries covering freed ranges are tombstoned
 * (size=0 → matches nothing; pe_base=NULL → slot reusable); anon RWX
 * aliases (FEX CodeBuffers) in freed ranges are cleared; EC bitmap bits
 * are cleared so a reused range starts with a clean call-routing slate. */
static void ios_sc_grants_owner_died( void *peb );

void ios_jit_reclaim_process( void *peb )
{
    size_t total = 0;
    int ranges = 0, maps_killed = 0, aliases_killed = 0;
    int i, j;
    char *rx_base = (char *)ios_jit_rx_base_global;

    /* madeira-bcd: its Social Club reservations go when the next helper asks */
    ios_sc_grants_owner_died( peb );
    if (!peb || !rx_base) return;

    /* The alias-push callback lives in the emulator of the LAST process that
     * registered one (ios_jit_alias_pushback_peb). If that process is the one
     * dying, its emulator's pool copy is reclaimed below and the next image
     * map anywhere would call freed (later reused) code. Drop the callback:
     * the next emulator to register gets the whole table from its drain. */
    ios_alias_cb_drop( peb );   /* madeira-bcd: its per-process callback too */
    if (peb == ios_jit_alias_pushback_peb && ios_jit_alias_pushback_cb)
    {
        dprintf(2, "[alias-push] peb=%p exits while its emulator receives the alias pushes: "
                "callback dropped before its pool copy is reclaimed\n", peb);
        __atomic_store_n(&ios_jit_alias_pushback_cb, NULL, __ATOMIC_RELEASE);
        ios_jit_alias_pushback_peb = NULL;
    }

    pthread_mutex_lock( &ios_pool_lock );

    for (i = 0; i < ios_pool_ledger_count; )
    {
        size_t off, size;
        if (ios_pool_ledger[i].peb != peb) { i++; continue; }
        off  = ios_pool_ledger[i].off;
        size = ios_pool_ledger[i].size;

        /* Tombstone mapping entries whose pool copy lives in this range.
         * Write order matters for the lock-free readers (translate /
         * fault handler): size=0 first — a zero-size entry matches no
         * query — then pe_base=NULL (the free-slot marker). */
        for (j = 0; j < ios_jit_mapping_count; j++)
        {
            char *jb = (char *)ios_jit_mappings[j].jit_base;
            if (!ios_jit_mappings[j].pe_base) continue;
            if (jb >= rx_base + off && jb < rx_base + off + size)
            {
                ios_jit_mappings[j].size = 0;
                __sync_synchronize();
                ios_jit_mappings[j].pe_base = NULL;
                maps_killed++;
            }
        }

        /* Clear anon RWX aliases (FEX CodeBuffers) backed by this range. */
        for (j = 0; j < ios_jit_anon_alias_count; j++)
        {
            uintptr_t rx = ios_jit_anon_aliases[j].jit_rx_alias;
            if (!ios_jit_anon_aliases[j].user_va) continue;
            if (rx >= (uintptr_t)(rx_base + off) && rx < (uintptr_t)(rx_base + off + size))
            {
                ios_jit_anon_aliases[j].user_va_end = 0;
                __sync_synchronize();
                ios_mono_alias_retire( ios_jit_anon_aliases[j].user_va );  /* ml648: unmap/teardown */
                ios_jit_anon_aliases[j].user_va = 0;
                aliases_killed++;
            }
        }

        /* ml244: bracket clear_arm64ec_range. The free-time check below fires on 20 ranges
         * ("narrowed during the module's life"), but it sits AFTER this call -- which
         * operates on the same pool range -- so it could be observing poison this very call
         * creates. Check immediately before to separate "already poisoned when we got here"
         * from "clear_arm64ec_range narrows it". */
        {
            unsigned int bcur = 0, bmax = 0;
            static int prechk;

            if (!ios_pool_range_execable( off, size, &bcur, &bmax ) && prechk++ < 20)
            {
                /* ml249: name the OWNER of the poisoned page here, not at hand-out -- the
                 * guard now rejects poisoned ranges before hand-out, so the probe there can
                 * never fire (0 hits vs 20 here). mprotect_exec is called ZERO times on pool
                 * VA, so nothing narrows maxprot in place; the pages must be REPLACED by a
                 * different mapping. Mach's user_tag identifies the allocator and share_mode
                 * distinguishes our dual-mapped alias from an ordinary private mapping, which
                 * is what tells us whether Wine handed out VA overlapping the pool. */
                extern void *ios_jit_rx_base_global;
                mach_vm_address_t ea = (mach_vm_address_t)(uintptr_t)((char *)ios_jit_rx_base_global + off);
                mach_vm_size_t esz = 0;
                vm_region_extended_info_data_t ext;
                mach_msg_type_number_t ecnt = VM_REGION_EXTENDED_INFO_COUNT;
                mach_port_t eobj = MACH_PORT_NULL;
                unsigned tag = 0, share = 0;
                size_t scan;

                /* walk to the first genuinely poisoned page inside the range */
                for (scan = 0; scan < size; scan += 0x4000)
                {
                    mach_vm_address_t a2 = (mach_vm_address_t)(uintptr_t)((char *)ios_jit_rx_base_global + off + scan), q = a2;
                    mach_vm_size_t s2 = 0;
                    vm_region_basic_info_data_64_t b2;
                    mach_msg_type_number_t c2 = VM_REGION_BASIC_INFO_COUNT_64;
                    mach_port_t o2 = MACH_PORT_NULL;

                    if (mach_vm_region( mach_task_self(), &q, &s2, VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&b2, &c2, &o2 ) != KERN_SUCCESS) break;
                    if (q > a2) continue;
                    if (!(b2.max_protection & VM_PROT_EXECUTE)) { ea = a2; break; }
                }
                if (mach_vm_region( mach_task_self(), &ea, &esz, VM_REGION_EXTENDED_INFO,
                                    (vm_region_info_t)&ext, &ecnt, &eobj ) == KERN_SUCCESS)
                { tag = ext.user_tag; share = ext.share_mode; }

                dprintf( 2, "[pool-freechk] PRE-CLEAR poisoned off=0x%lx size=0x%lx cur=0x%x max=0x%x"
                            " | page=%p user_tag=%u share_mode=%u regionsz=0x%llx\n",
                         (unsigned long)off, (unsigned long)size, bcur, bmax,
                         (void *)(uintptr_t)ea, tag, share, (unsigned long long)esz );
            }
        }
        if (arm64ec_view) clear_arm64ec_range( rx_base + off, size );

        /* ml243: is the range ALREADY poisoned when it is freed?
         *
         * The guard now refuses poisoned ranges (correct) but never recovers them -- 62
         * drops = 164MB orphaned from an 896MB pool, which already sits at 86% used. The
         * durable fix is to stop the poison being CREATED, so pin down when maxprot is
         * narrowed: during the module's life (poisoned here at free time) or later while
         * the range sits on the freelist (clean here, poisoned at reuse). Those need
         * completely different fixes. Self-targeting: prints only when poisoned. */
        {
            unsigned int fcur = 0, fmax = 0;
            static int freechk;

            if (!ios_pool_range_execable( off, size, &fcur, &fmax ) && freechk++ < 20)
                dprintf( 2, "[pool-freechk] POISONED AT FREE off=0x%lx size=0x%lx cur=0x%x max=0x%x"
                            "  <== narrowed during the module's life\n",
                         (unsigned long)off, (unsigned long)size, fcur, fmax );
        }

        /* madeira-bcd: a range in the big-image slot frees the slot (after the
         * grace) instead of going on the freelist, where small images would
         * carve it up. */
        if (ios_pool_big_size && off < ios_pool_big_off + ios_pool_big_size && off + size > ios_pool_big_off)
        {
            ios_pool_big_taken = 0;
            ios_pool_big_freed_at = time( NULL );
            total += size;
            ranges++;
            dprintf(2, "[pool-big] madeira-bcd slot freed by peb=%p (off 0x%lx size 0x%lx), reusable after %ds\n",
                    peb, (unsigned long)off, (unsigned long)size, IOS_POOL_REUSE_GRACE_SEC);
            ios_pool_ledger[i] = ios_pool_ledger[--ios_pool_ledger_count];
            continue;
        }
        /* madeira-pool-same-image: a POISONED range whose image is known goes
         * on whole, with its tag, so the next copy of that image can have all
         * of it -- the executable runs below are each smaller than the image
         * that needs them. A request for another image that reaches it later
         * still splits it into those runs, in the allocator. */
        if (ios_pool_ledger[i].tag && !ios_pool_range_clean( off, size ) &&
            ios_pool_free_count < IOS_POOL_FREE_MAX)
        {
            struct ios_pool_free *whole = &ios_pool_freelist[ios_pool_free_count++];
            whole->off = off;
            whole->size = size;
            whole->freed_at = time( NULL );
            whole->advised = 0;
            whole->tag = ios_pool_ledger[i].tag;
            total += size;
            ranges++;
            ios_pool_ledger[i] = ios_pool_ledger[--ios_pool_ledger_count];
            continue;
        }
        /* madeira-bcd: merged with its clean neighbours (ios_pool_free_put); a
         * POISONED range goes on as its executable runs, which merge too. The
         * MADV_FREE sweep that used to follow is gone (ml87), and nothing is
         * purged here: laggard exit threads may still run this range during
         * the grace window. */
        {
            size_t r_off[16], r_size[16];
            int r, nr = 1, put = 0;

            r_off[0] = off;
            r_size[0] = size;
            if (!ios_pool_range_clean( off, size ))
                nr = ios_pool_execable_runs( (uint64_t)(uintptr_t)rx_base, off, size, ios_pool_mach_region,
                                             r_off, r_size, 16 );
            for (r = 0; r < nr; r++)
                if (ios_pool_free_put( ios_pool_freelist, &ios_pool_free_count, IOS_POOL_FREE_MAX,
                                       r_off[r], r_size[r], time( NULL ), ios_pool_range_clean ))
                    put = 1;
                else dprintf(2, "[jit-pool] freelist FULL — leaking range off=0x%lx size=0x%lx\n",
                             (unsigned long)r_off[r], (unsigned long)r_size[r]);
            if (put) { total += size; ranges++; }
        }

        /* Remove ledger entry (swap-with-last). */
        ios_pool_ledger[i] = ios_pool_ledger[--ios_pool_ledger_count];
    }

    pthread_mutex_unlock( &ios_pool_lock );

    /* madeira-bcd: and its FEX code buffers (after the pool lock: the carve
     * lock is never taken under it) */
    ios_tail_carves_owner_died( peb );

    if (ranges || maps_killed)
        dprintf(2, "[jit-pool] RECLAIM peb=%p: %d ranges 0x%lx bytes freed (grace %ds), "
                "%d mappings tombstoned, %d anon aliases cleared; bump=0x%lx freelist=%d\n",
                peb, ranges, (unsigned long)total, IOS_POOL_REUSE_GRACE_SEC,
                maps_killed, aliases_killed,
                (unsigned long)jit_pool_offset, ios_pool_free_count);

    /* ml983: only now is the fixed-base window occupant safe to retire. This is
     * deliberately AFTER the ledger walk, not before it: the flag is what lets
     * another thread delete that image view, and it must not be observable while
     * this PEB's pool mappings and anon aliases are still live -- otherwise the
     * view could go while FEX-translated code referring to it is still entrant.
     * Server EOF alone would not carry that guarantee; completing this walk does. */
    ios_exe_win_note_dead_peb( peb );
}


/***********************************************************************
 *           clear_arm64ec_range
 */
static void clear_arm64ec_range( const void *addr, size_t size )
{
    UINT64 *map = arm64ec_view->base;
    /* ml113 (task #35 fallout, but a pre-existing bug): commit the covering
     * bitmap pages BEFORE writing, exactly as ios_jit_mark_ec_range does for
     * the set path. This clear runs from ios_jit_reclaim_process for EVERY
     * freed pool range — including copies whose EC bits were never set (pure
     * x86-64 images), whose bitmap coverage is therefore still uncommitted
     * reserve. The blind store then faults. It never crashed before only by
     * accident: the bitmap's old home (0x7ef1dc0000) sat inside the
     * [496G,512G) reclaim-recover band, which silently mprotect-committed
     * such faults; the furniture ceiling moved the bitmap to 0x72f1dc0000,
     * outside the band, and the first uncommitted clear killed a child at
     * exit (ios_jit_reclaim_process+0x1d4, fault 0x72f1de3e68 = qword for
     * pool VA ~0x11F340000). */
    {
        size_t bm_start = ((size_t)addr >> 12) / 8;
        size_t bm_end   = (((size_t)addr + size) >> 12) / 8;
        size_t bm_size  = ROUND_SIZE( bm_start, bm_end + 1 - bm_start, page_mask );
        void *bm_page   = ROUND_ADDR( (char *)arm64ec_view->base + bm_start, page_mask );
        /* set_vprot alone is the whole commit — it mprotects the covering
         * pages RW without zeroing, exactly as the set path proves.
         * (An mmap-over here would ZERO committed pages and wipe other
         * modules' EC bits.) */
        set_vprot( arm64ec_view, bm_page, bm_size, VPROT_READ | VPROT_WRITE | VPROT_COMMITTED );
    }
    const unsigned int ec_page_shift = 12;
    const size_t ec_page_mask = (1ULL << ec_page_shift) - 1;
    size_t idx = (size_t)addr >> ec_page_shift;
    size_t end = ((size_t)addr + size + ec_page_mask) >> ec_page_shift;
    size_t pos = idx / 64;
    size_t end_pos = end / 64;

    if (end_pos > pos)
    {
        map[pos++] &= ~maskbits( idx );
        while (pos < end_pos) map[pos++] = 0;
        if (end & 63) map[pos] &= maskbits( end );
    }
    else map[pos] &= ~maskbits( idx ) | maskbits( end );
}

/***********************************************************************
 *           clear_arm64ec_range_committed
 *
 * ml113 (task #35 fallout): commit-aware clear for the EXIT-TIME reclaim.
 * The EC bitmap is a sparse reservation — the set side commits covering
 * pages before writing (ios_jit_mark_ec_range), but the reclaim cleared
 * blindly and first-touched an uncommitted bitmap page inside
 * process_exit_wrapper's mach-handler context.
 *
 * SUPERSEDED, NO SUCH FUNCTION: the commit was folded into
 * clear_arm64ec_range itself (set_vprot before the clear). This header is all
 * that was left, and it had lost its terminator, so it was swallowing the
 * comment below it (-Wcomment). Kept for the ml113 rationale only.
 */


/***********************************************************************
 *           compare_view
 *
 * View comparison function used for the rb tree.
 */
static int compare_view( const void *addr, const struct wine_rb_entry *entry )
{
    struct file_view *view = WINE_RB_ENTRY_VALUE( entry, struct file_view, entry );

    if (addr < view->base) return -1;
    if (addr > view->base) return 1;
    return 0;
}


/***********************************************************************
 *           get_prot_str
 */
static const char *get_prot_str( BYTE prot )
{
    static char buffer[6];
    buffer[0] = (prot & VPROT_COMMITTED) ? 'c' : '-';
    buffer[1] = (prot & VPROT_GUARD) ? 'g' : ((prot & VPROT_WRITEWATCH) ? 'H' : '-');
    buffer[2] = (prot & VPROT_READ) ? 'r' : '-';
    buffer[3] = (prot & VPROT_WRITECOPY) ? 'W' : ((prot & VPROT_WRITE) ? 'w' : '-');
    buffer[4] = (prot & VPROT_EXEC) ? 'x' : '-';
    buffer[5] = 0;
    return buffer;
}


/***********************************************************************
 *           get_unix_prot
 *
 * Convert page protections to protection for mmap/mprotect.
 */
static int get_unix_prot( BYTE vprot )
{
    int prot = 0;
    if ((vprot & VPROT_COMMITTED) && !(vprot & VPROT_GUARD))
    {
        if (vprot & VPROT_READ) prot |= PROT_READ;
        if (vprot & VPROT_WRITE) prot |= PROT_WRITE | PROT_READ;
        if (vprot & VPROT_WRITECOPY) prot |= PROT_WRITE | PROT_READ;
        if (vprot & VPROT_EXEC) prot |= PROT_EXEC | PROT_READ;
        if (vprot & VPROT_WRITEWATCH) prot &= ~PROT_WRITE;
    }
    if (!prot) prot = PROT_NONE;
    return prot;
}


/***********************************************************************
 *           dump_view
 */
#ifdef WINE_IOS
/* Called with virtual_mutex held, only after a constrained FEX allocation
 * fails. Count live views, rather than ALLOC/COMMIT events (which count the
 * same span repeatedly). Read only Wine's native protection bookkeeping;
 * never read guest/FEX payloads or reclaim a live or dead thread's memory. */
static void ios_fex_arena_census( void *start, void *end, size_t request, size_t align_mask )
{
    struct fex_va_bucket { size_t size, bytes, committed; unsigned flags, views; } buckets[32] = {{0}};
    struct file_view *view;
    ULONG_PTR lo = ios_fex_arena_base_unix, hi = ios_fex_arena_end_unix, cursor;
    size_t covered = 0, committed = 0, overlap = 0, biggest = 0, aligned_biggest = 0;
    size_t other_bytes = 0, other_committed = 0;
    unsigned nviews = 0, holes = 0, used = 0, other_views = 0, i, j;
    static unsigned printed;

    if (printed || !lo || hi <= lo || (ULONG_PTR)start < lo || (ULONG_PTR)end > hi ||
        (ULONG_PTR)start >= (ULONG_PTR)end || !page_size) return;
    printed = 1;
    cursor = lo;
    WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
    {
        ULONG_PTR b = (ULONG_PTR)view->base, e, first, fresh, p;
        size_t vc = 0;

        if (b >= hi) break;
        e = view->size > ~(ULONG_PTR)0 - b ? ~(ULONG_PTR)0 : b + view->size;
        if (e <= lo || e <= b) continue;
        if (b < lo) b = lo;
        if (e > hi) e = hi;
        nviews++;
        if (b > cursor)
        {
            size_t gap = b - cursor;
            ULONG_PTR aligned;
            holes++;
            if (gap > biggest) biggest = gap;
            if (cursor <= ~(ULONG_PTR)0 - align_mask)
            {
                aligned = (cursor + align_mask) & ~(ULONG_PTR)align_mask;
                if (aligned < b && b - aligned > aligned_biggest) aligned_biggest = b - aligned;
            }
        }
        first = b;
        fresh = b > cursor ? b : cursor;
        if (b < cursor) overlap += (e < cursor ? e : cursor) - b;
        if (e > fresh) covered += e - fresh;
        if (e > cursor) cursor = e;
        for (p = first; p < e; )
        {
            size_t bytes = e - p < page_size ? e - p : page_size;
            if (get_page_vprot( (void *)p ) & VPROT_COMMITTED)
            {
                vc += bytes;
                if (p >= fresh) committed += bytes;
                else if (p + bytes > fresh) committed += p + bytes - fresh;
            }
            p += bytes;
        }
        for (i = 0; i < used; i++)
            if (buckets[i].size == view->size && buckets[i].flags == view->protect) break;
        if (i == used && used < ARRAY_SIZE(buckets))
        {
            buckets[i].size = view->size;
            buckets[i].flags = view->protect;
            used++;
        }
        if (i < used)
        {
            buckets[i].views++;
            buckets[i].bytes += e - b;
            buckets[i].committed += vc;
        }
        else
        {
            other_views++;
            other_bytes += e - b;
            other_committed += vc;
        }
    }
    if (cursor < hi)
    {
        size_t gap = hi - cursor;
        ULONG_PTR aligned;
        holes++;
        if (gap > biggest) biggest = gap;
        if (cursor <= ~(ULONG_PTR)0 - align_mask)
        {
            aligned = (cursor + align_mask) & ~(ULONG_PTR)align_mask;
            if (aligned < hi && hi - aligned > aligned_biggest) aligned_biggest = hi - aligned;
        }
    }
    dprintf( 2, "[fex-va] live arena=%p..%p failed_range=%p..%p request=0x%llx align_mask=0x%llx "
                "views=%u covered=0x%llx free=0x%llx committed=0x%llx overlap=0x%llx "
                "holes=%u maxgap=0x%llx max_aligned_gap=0x%llx (virtual bytes, not residency)\n",
             (void *)lo, (void *)hi, start, end, (unsigned long long)request, (unsigned long long)align_mask,
             nviews, (unsigned long long)covered, (unsigned long long)(hi - lo - covered),
             (unsigned long long)committed, (unsigned long long)overlap, holes,
             (unsigned long long)biggest, (unsigned long long)aligned_biggest );
    /* Largest consumers first, at most 32 buckets plus one overflow line. */
    for (i = 0; i < used; i++)
    {
        unsigned largest = i;
        struct fex_va_bucket tmp;
        for (j = i + 1; j < used; j++) if (buckets[j].bytes > buckets[largest].bytes) largest = j;
        tmp = buckets[i]; buckets[i] = buckets[largest]; buckets[largest] = tmp;
        dprintf( 2, "[fex-va] size=0x%llx view_flags=0x%x views=%u reserved=0x%llx committed=0x%llx\n",
                 (unsigned long long)buckets[i].size, buckets[i].flags, buckets[i].views,
                 (unsigned long long)buckets[i].bytes, (unsigned long long)buckets[i].committed );
    }
    if (other_views)
        dprintf( 2, "[fex-va] other_sizes views=%u reserved=0x%llx committed=0x%llx\n",
                 other_views, (unsigned long long)other_bytes, (unsigned long long)other_committed );
}

/* madeira-bcd: how close the FEX arena is to full while things still work.
 * Grand Theft Auto V Enhanced through the Rockstar Games Launcher (build 434,
 * log 2026-10-07 20:51) stopped in FEXAlloc with the arena 95% covered
 * (11.4 of 12 GB, 262 threads) and 593 MB free in 1052 holes, none with a
 * 4 MB-aligned 4 MB gap; the next start of the same build played. Without a
 * failure nothing said how close a run came. Called with virtual_mutex held
 * after a successful placement inside the arena: a line every 30 s and when
 * free space first drops below 3, 2, 1 and 0.5 GB (200 lines at most),
 * measured at most once a second. Views only, no page scan.
 * MADEIRA_FEX_HEADROOM_LOG=0 turns it off. */
static void ios_fex_arena_headroom( void *start, void *end )
{
    static const size_t marks[] = { 3ull << 30, 2ull << 30, 1ull << 30, 512ull << 20 };
    static unsigned next_mark, lines;
    static long long next_ns, next_walk_ns;
    static int on = -1;
    const ULONG_PTR align_mask = 0x3fffff;  /* rpmalloc's 4 MB medium pages, what failed */
    struct file_view *view;
    ULONG_PTR lo = ios_fex_arena_base_unix, hi = ios_fex_arena_end_unix, cursor;
    size_t covered = 0, biggest = 0, aligned_biggest = 0, free_bytes;
    unsigned nviews = 0, holes = 0, crossed = 0;
    struct timespec ts;
    long long now;

    if (on < 0) { const char *e = getenv( "MADEIRA_FEX_HEADROOM_LOG" ); on = !(e && e[0] == '0'); }  /* 0: no [fex-headroom] lines */
    if (!on || lines >= 200 || !lo || hi <= lo) return;
    if ((ULONG_PTR)start < lo || (ULONG_PTR)end > hi) return;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    now = (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    if (now < next_walk_ns) return;   /* the walk costs every view: once a second at most */
    next_walk_ns = now + 1000000000LL;

    cursor = lo;
    WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
    {
        ULONG_PTR b = (ULONG_PTR)view->base, e;

        if (b >= hi) break;
        e = view->size > ~(ULONG_PTR)0 - b ? ~(ULONG_PTR)0 : b + view->size;
        if (e <= lo || e <= b) continue;
        if (b < lo) b = lo;
        if (e > hi) e = hi;
        nviews++;
        if (b > cursor)
        {
            ULONG_PTR aligned = (cursor + align_mask) & ~align_mask;
            holes++;
            if (b - cursor > biggest) biggest = b - cursor;
            if (aligned < b && b - aligned > aligned_biggest) aligned_biggest = b - aligned;
        }
        if (e > cursor) { covered += e - (b > cursor ? b : cursor); cursor = e; }
    }
    if (cursor < hi)
    {
        ULONG_PTR aligned = (cursor + align_mask) & ~align_mask;
        holes++;
        if (hi - cursor > biggest) biggest = hi - cursor;
        if (aligned < hi && hi - aligned > aligned_biggest) aligned_biggest = hi - aligned;
    }
    free_bytes = hi - lo - covered;
    while (next_mark < ARRAY_SIZE(marks) && free_bytes < marks[next_mark]) { next_mark++; crossed = 1; }
    if (!crossed && now < next_ns) return;
    next_ns = now + 30000000000LL;
    lines++;
    dprintf( 2, "[fex-headroom] arena=%p..%p used=%lluMB free=%lluMB (%u%% used) holes=%u maxgap=%lluKB "
                "max_4mb_aligned_gap=%lluKB views=%u%s (MADEIRA_FEX_HEADROOM_LOG=0 disables)\n",
             (void *)lo, (void *)hi, (unsigned long long)(covered >> 20), (unsigned long long)(free_bytes >> 20),
             (unsigned)((unsigned long long)covered * 100 / (hi - lo)), holes,
             (unsigned long long)(biggest >> 10), (unsigned long long)(aligned_biggest >> 10), nviews,
             crossed ? " (threshold crossed)" : "" );
}
#endif

static void dump_view( struct file_view *view )
{
    UINT i, count;
    char *addr = view->base;
    BYTE prot = get_page_vprot( addr );

    TRACE( "View: %p - %p %s", addr, addr + view->size - 1, get_prot_str(view->protect) );
    if (view->protect & VPROT_SYSTEM)
        TRACE( " (builtin image)\n" );
    else if (view->protect & VPROT_FREE_PLACEHOLDER)
        TRACE( " (placeholder)\n" );
    else if (view->protect & SEC_IMAGE)
        TRACE( " (image)\n" );
    else if (view->protect & SEC_FILE)
        TRACE( " (file)\n" );
    else if (view->protect & (SEC_RESERVE | SEC_COMMIT))
        TRACE( " (anonymous)\n" );
    else
        TRACE( " (valloc)\n");

    for (count = i = 1; i < view->size >> page_shift; i++, count++)
    {
        BYTE next = get_page_vprot( addr + (count << page_shift) );
        if (next == prot) continue;
        TRACE( "      %p - %p %s\n",
                 addr, addr + (count << page_shift) - 1, get_prot_str(prot) );
        addr += (count << page_shift);
        prot = next;
        count = 0;
    }
    if (count)
        TRACE( "      %p - %p %s\n",
                 addr, addr + (count << page_shift) - 1, get_prot_str(prot) );
}


/***********************************************************************
 *           VIRTUAL_Dump
 */
#ifdef WINE_VM_DEBUG
static void VIRTUAL_Dump(void)
{
    sigset_t sigset;
    struct file_view *view;

    TRACE( "Dump of all virtual memory views:\n" );
    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
    {
        dump_view( view );
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
}
#endif


/***********************************************************************
 *           find_view
 *
 * Find the view containing a given address. virtual_mutex must be held by caller.
 *
 * PARAMS
 *      addr  [I] Address
 *
 * RETURNS
 *	View: Success
 *	NULL: Failure
 */
static struct file_view *find_view( const void *addr, size_t size )
{
    struct wine_rb_entry *ptr = views_tree.root;

    if ((const char *)addr + size < (const char *)addr) return NULL; /* overflow */

    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );

        if (view->base > addr) ptr = ptr->left;
        else if ((const char *)view->base + view->size <= (const char *)addr) ptr = ptr->right;
        else if ((const char *)view->base + view->size < (const char *)addr + size) break;  /* size too large */
        else return view;
    }
    return NULL;
}


/***********************************************************************
 *           is_write_watch_range
 */
static inline BOOL is_write_watch_range( const void *addr, size_t size )
{
    struct file_view *view = find_view( addr, size );
    return view && (view->protect & VPROT_WRITEWATCH);
}


/***********************************************************************
 *           find_view_range
 *
 * Find the first view overlapping at least part of the specified range.
 * virtual_mutex must be held by caller.
 */
static struct file_view *find_view_range( const void *addr, size_t size )
{
    struct wine_rb_entry *ptr = views_tree.root;

    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );

        if ((const char *)view->base >= (const char *)addr + size) ptr = ptr->left;
        else if ((const char *)view->base + view->size <= (const char *)addr) ptr = ptr->right;
        else return view;
    }
    return NULL;
}


/***********************************************************************
 *           find_view_inside_range
 *
 * Find first (resp. last, if top_down) view inside a range.
 * virtual_mutex must be held by caller.
 */
static struct wine_rb_entry *find_view_inside_range( void **base_ptr, void **end_ptr, int top_down )
{
    struct wine_rb_entry *first = NULL, *ptr = views_tree.root;
    void *base = *base_ptr, *end = *end_ptr;

    /* find the first (resp. last) view inside the range */
    while (ptr)
    {
        struct file_view *view = WINE_RB_ENTRY_VALUE( ptr, struct file_view, entry );
        if ((char *)view->base + view->size >= (char *)end)
        {
            end = min( end, view->base );
            ptr = ptr->left;
        }
        else if (view->base <= base)
        {
            base = max( (char *)base, (char *)view->base + view->size );
            ptr = ptr->right;
        }
        else
        {
            first = ptr;
            ptr = top_down ? ptr->right : ptr->left;
        }
    }

    *base_ptr = base;
    *end_ptr = end;
    return first;
}


/***********************************************************************
 *           try_map_free_area
 *
 * Try mmaping some expected free memory region, eventually stepping and
 * retrying inside it, and return where it actually succeeded, or NULL.
 */
/* ml211: ask Mach where the mapping occupying `addr` ends, so the scan can jump over it.
 *
 * Wine's rb tree only knows Wine's OWN views (53 in a Steam run), but the [furniture]
 * census found 57347 FOREIGN 16KB Mach regions packed solid from 0x7000000000 to
 * 0x7038000000. try_map_free_area steps one align granule at a time, so crossing those
 * costs one failed mmap each -- ~8000 syscalls to place a single 1MB allocation, while the
 * window still had 15.4GB contiguous free the entire time. The address space was never
 * exhausted; the scanner was crawling.
 *
 * Returns 1 and sets *out only when Mach confirms `addr` is inside a mapped region, so
 * this can only ever skip provably-occupied space. Anything else returns 0 and the caller
 * falls back to the plain step, which keeps a wrong answer here free of consequence.
 * Forward progress is guaranteed in both directions: bottom-up resumes past the region
 * end (> addr, since the region contains addr), top-down at region base - size (< addr). */
static int ios_skip_occupied( void *addr, size_t size, size_t align_mask,
                              int top_down, void **out )
{
    mach_vm_address_t a = (mach_vm_address_t)(uintptr_t)addr, rbase = a;
    mach_vm_size_t rsize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;

    if (mach_vm_region( mach_task_self(), &rbase, &rsize, VM_REGION_BASIC_INFO_64,
                        (vm_region_info_t)&info, &cnt, &obj ) != KERN_SUCCESS)
        return 0;
    if (rbase > a || !rsize)
        return 0;         /* addr is in a free hole: mmap failed for some other reason
                             (iOS refuses certain addresses), so stepping is correct */
    if (top_down)
    {
        if (rbase < (mach_vm_address_t)size) return 0;
        *out = ROUND_ADDR( (char *)(uintptr_t)rbase - size, align_mask );
    }
    else
    {
        mach_vm_address_t nxt = rbase + rsize;

        *out = (void *)(uintptr_t)((nxt + align_mask) & ~(mach_vm_address_t)align_mask);
    }
    return 1;
}

/* ml900: the kernel's range for VM_MEMORY_LAYERKIT (CoreAnimation's render
 * shmem), measured in ios_va_profile() before any guest view or emulator arena
 * exists. It is ~10 GB and randomised per launch; two runs proved that both the
 * emulator arena and the guest stacks landed inside it, CoreAnimation ran out
 * of space, and the app aborted in CA::Render::Encoder::grow (40 min in) or
 * trapped in SwiftUI's async renderer. Generic placement must never use it. */
unsigned long long ios_layerkit_lo, ios_layerkit_hi;
static int ios_layerkit_enforce = 1;          /* ml901: soft -- dropped if the exclusion would fail an allocation */
static unsigned long ios_layerkit_skips;
static inline int ios_in_layerkit( unsigned long long a, size_t size )
{
    return ios_layerkit_enforce && ios_layerkit_hi && a + size > ios_layerkit_lo && a < ios_layerkit_hi;
}

static void* try_map_free_area( void *base, void *end, ptrdiff_t step,
                                void *start, size_t size, int unix_prot )
{
    while (start && base <= start && (char*)start + size <= (char*)end)
    {
        /* ml253 ROOT-CAUSE FIX: never allocate inside the JIT pool.
         *
         * Wine's scanner walks straight through the pool -- measured, marching upward in
         * 0x10000 steps calling anon_mmap_tryfixed at every address:
         *   [pool-va] anon_mmap_tryfixed addr=0x11e800000 size=0x100000 INSIDE RX pool off=0x0
         *   [pool-va] anon_mmap_tryfixed addr=0x11e810000 ... off=0x10000   (etc)
         * Where the pool is mapped these fail (that is the scan grinding). Wherever the pool
         * has a HOLE they SUCCEED, installing a foreign one-page RW mapping -- exactly the
         * poison fingerprint (regionsz=0x4000, user_tag=0, max=RW, unraisable), which then
         * lands in a module's .text as a permanently non-executable page. When Wine later
         * releases such an allocation the hole becomes MEM_FREE inside the pool span, which
         * is what the fatal CASPAL dereferences (0x1541af700, state=MEM_FREE).
         *
         * One cause, three symptoms. The pool is ours; Wine must never hand out its VA.
         * Skipping the whole pool in one jump is also strictly faster than stepping it. */
        {
            extern void *ios_jit_rx_base_global;
            extern void *ios_jit_rw_base_global;
            extern size_t ios_jit_pool_size_global;
            uintptr_t a = (uintptr_t)start;
            uintptr_t rx = (uintptr_t)ios_jit_rx_base_global;
            uintptr_t rw = (uintptr_t)ios_jit_rw_base_global;
            size_t ps = ios_jit_pool_size_global;
            uintptr_t pool_end = 0, pool_base = 0;
            size_t low = ps ? ios_jit_low_size_global : 0;

            if (ps && rx && a + size > rx && a < rx + ps) { pool_base = rx; pool_end = rx + ps; }
            else if (ps && rw && a + size > rw && a < rw + ps) { pool_base = rw; pool_end = rw + ps; }
            /* madeira-bcd pool-low: region C's RX side, and on the RW side the whole
             * reservation below the pool's alias (C's alias and the PROT_NONE part
             * after it). The RX side between C and the pool is NOT skipped: the
             * executable window and the low images live there. */
            else if (low && a + size > ios_jit_low_rx_global && a < ios_jit_low_rx_global + low)
            { pool_base = ios_jit_low_rx_global; pool_end = ios_jit_low_rx_global + low; }
            else if (low && rw > ios_jit_low_rw_global && a + size > ios_jit_low_rw_global && a < rw)
            { pool_base = ios_jit_low_rw_global; pool_end = rw; }
            if (pool_end)
            {
                static int skipped;
                if (skipped++ < 8)
                    dprintf( 2, "[pool-va] SKIP scan over JIT pool at %p -> %p\n",
                             start, (void *)pool_end );
                if (step < 0)
                {
                    if (pool_base < size) break;
                    start = ROUND_ADDR( (char *)(pool_base - size), (size_t)(-step) - 1 );
                }
                else start = (void *)((pool_end + (size_t)step - 1) & ~((uintptr_t)step - 1));
                continue;
            }
        }
        if (ios_in_layerkit( (unsigned long long)(uintptr_t)start, size ))   /* ml900 */
        {
            static int skipped;
            ios_layerkit_skips++;
            if (skipped++ < 8)
                dprintf( 2, "[layerkit-range] SKIP scan over CoreAnimation's range at %p (0x%llx..0x%llx)\n",
                         start, ios_layerkit_lo, ios_layerkit_hi );
            if (step < 0)
            {
                if (ios_layerkit_lo < size) break;
                start = ROUND_ADDR( (char *)(uintptr_t)(ios_layerkit_lo - size), (size_t)(-step) - 1 );
            }
            else start = (void *)(uintptr_t)((ios_layerkit_hi + (size_t)step - 1) & ~((uintptr_t)step - 1));
            continue;
        }
        if (anon_mmap_tryfixed( start, size, unix_prot, 0 ) != MAP_FAILED) return start;
        TRACE( "Found free area is already mapped, start %p.\n", start );
        ios_va_scan_tries++;
        if (!ios_scan_fail_addr) { ios_scan_fail_addr = start; ios_scan_fail_errno = errno; }
#ifdef WINE_IOS
        /* iOS: mach_vm_map can return KERN_INVALID_ADDRESS (→ ENOMEM) at certain
         * addresses due to ASLR/system mappings.  Keep scanning instead of aborting. */
        if (errno != EEXIST && errno != ENOMEM)
#else
        if (errno != EEXIST)
#endif
        {
            ERR( "mmap() error %s, range %p-%p, unix_prot %#x.\n",
                 strerror(errno), start, (char *)start + size, unix_prot );
            return NULL;
        }
        if ((step > 0 && (char *)end - (char *)start < step) ||
            (step < 0 && (char *)start - (char *)base < -step) ||
            step == 0)
            break;
        /* ml211: jump over the whole occupying region instead of crawling one granule
         * at a time -- see ios_skip_occupied. Bounds are re-checked by the loop
         * condition, so an over-long jump simply ends the scan rather than escaping
         * the range. */
        {
            void *next = start;

            if (step && ios_skip_occupied( start, size, (size_t)(step < 0 ? -step : step) - 1,
                                           step < 0, &next )
                && next != start)
            {
                ios_va_scan_skips++;
                start = next;
            }
            else
                start = (char *)start + step;
        }
    }

    return NULL;
}


/***********************************************************************
 *           map_free_area
 *
 * Find a free area between views inside the specified range and map it.
 * virtual_mutex must be held by caller.
 */
static void *map_free_area_inner( void *base, void *end, size_t size, int top_down, int unix_prot, size_t align_mask );
static void *map_free_area( void *base, void *end, size_t size, int top_down, int unix_prot, size_t align_mask )
{
    unsigned long before = ios_layerkit_skips;
    void *r = map_free_area_inner( base, end, size, top_down, unix_prot, align_mask );
    if (!r && ios_layerkit_enforce && ios_layerkit_skips != before)
    {
        /* ml901: the only fit was inside CoreAnimation's range. Failing the
         * guest here is worse than starving CoreAnimation later, so stop
         * enforcing for the rest of the process and search again. */
        ios_layerkit_enforce = 0;
        dprintf( 2, "[layerkit-range] ml901 exclusion DROPPED: no free area of 0x%lx outside 0x%llx..0x%llx; "
                    "guest views may now enter CoreAnimation's range\n", (unsigned long)size, ios_layerkit_lo, ios_layerkit_hi );
        r = map_free_area_inner( base, end, size, top_down, unix_prot, align_mask );
    }
    return r;
}
static void *map_free_area_inner( void *base, void *end, size_t size, int top_down, int unix_prot, size_t align_mask )
{
    struct wine_rb_entry *first = find_view_inside_range( &base, &end, top_down );
    ptrdiff_t step = top_down ? -(align_mask + 1) : (align_mask + 1);
    void *start;

    /* ml749: AN INVERTED WINDOW IS NOT AN EMPTY SEARCH, IT IS A CONFIGURATION
     * BUG -- SAY SO.
     *
     * When a caller's window starts above its end -- which is what happens to
     * both FEX arena candidates once the host limit is believed to be 32GB,
     * [496GB,32GB) and [48GB,32GB) -- every loop below is skipped, the scan
     * reports tries=0 skips=0, and NULL comes back indistinguishable from
     * "searched hard, genuinely full". The caller then proceeds without an
     * arena and the real failure surfaces hundreds of instructions later as a
     * NULL x28 dereference at x28+0x7f0, in a different subsystem, with none of
     * this context attached. Name it at the point of truth instead. */
    if (base >= end)
        dprintf( 2, "[va-scan] ml749 INVERTED WINDOW base=%p >= end=%p size=%p "
                    "-- nothing will be scanned; caller will see 'no space' that is really 'no window'\n",
                 base, end, (void *)size );

    /* [va-scan] geometry probe — see ios_scan_base. */
    ios_scan_base = base;
    ios_scan_end = end;
    ios_scan_views = 0;
    ios_scan_maxgap = 0;
    ios_scan_tailgap = 0;
    ios_scan_stop = first ? 0 : 9;
    ios_scan_fail_addr = NULL;
    ios_scan_fail_errno = 0;

    if (top_down)
    {
        start = ROUND_ADDR( (char *)end - size, align_mask );
        if (start >= end || start < base) { ios_scan_stop = 3; return NULL; }

        while (first)
        {
            struct file_view *view = WINE_RB_ENTRY_VALUE( first, struct file_view, entry );
            char *gap_lo = (char *)view->base + view->size;

            ios_scan_views++;
            if ((char *)start + size > gap_lo && (size_t)((char *)start + size - gap_lo) > ios_scan_maxgap)
                ios_scan_maxgap = (char *)start + size - gap_lo;
            if ((start = try_map_free_area( gap_lo, (char *)start + size, step,
                                            start, size, unix_prot ))) break;
            start = ROUND_ADDR( (char *)view->base - size, align_mask );
            /* stop if remaining space is not large enough */
            if (!start || start >= end || start < base) { ios_scan_stop = 4; return NULL; }
            first = rb_prev( first );
        }
    }
    else
    {
        start = ROUND_ADDR( (char *)base + align_mask, align_mask );
        if (!start || start >= end || (char *)end - (char *)start < size) { ios_scan_stop = 1; return NULL; }

        while (first)
        {
            struct file_view *view = WINE_RB_ENTRY_VALUE( first, struct file_view, entry );

            ios_scan_views++;
            if ((char *)view->base > (char *)start && (size_t)((char *)view->base - (char *)start) > ios_scan_maxgap)
                ios_scan_maxgap = (char *)view->base - (char *)start;
            if ((start = try_map_free_area( start, view->base, step,
                                            start, size, unix_prot ))) break;
            start = ROUND_ADDR( (char *)view->base + view->size + align_mask, align_mask );
            /* stop if remaining space is not large enough */
            if (!start || start >= end || (char *)end - (char *)start < size) { ios_scan_stop = 2; return NULL; }
            first = rb_next( first );
        }
    }

    /* ml798: measure the terminal region before trying it, so a failure here is
     * distinguishable from having no space at all. */
    if (!first)
    {
        if (start && (char *)end > (char *)start)
            ios_scan_tailgap = (char *)end - (char *)start;
        if (ios_scan_tailgap > ios_scan_maxgap) ios_scan_maxgap = ios_scan_tailgap;
        start = try_map_free_area( base, end, step, start, size, unix_prot );
    }

    if (!start)
        ERR( "couldn't map free area in range %p-%p, size %p\n", base, end, (void *)size );

    return start;
}


/***********************************************************************
 *           find_reserved_free_area
 *
 * Find a free area between views inside the specified range.
 * virtual_mutex must be held by caller.
 * The range must be inside a reserved area.
 */
static void *find_reserved_free_area( void *base, void *end, size_t size, int top_down, size_t align_mask )
{
    struct range_entry *range;
    void *start;

    base = ROUND_ADDR( (char *)base + align_mask, align_mask );
    end = (char *)ROUND_ADDR( (char *)end - size, align_mask ) + size;

    if (top_down)
    {
        start = (char *)end - size;
        range = free_ranges_lower_bound( start );
        assert(range != free_ranges_end && range->end >= start);

        if ((char *)range->end - (char *)start < size) start = ROUND_ADDR( (char *)range->end - size, align_mask );
        do
        {
            if (start >= end || start < base || (char *)end - (char *)start < size) return NULL;
            if (start < range->end && start >= range->base && (char *)range->end - (char *)start >= size) break;
            if (--range < free_ranges) return NULL;
            start = ROUND_ADDR( (char *)range->end - size, align_mask );
        }
        while (1);
    }
    else
    {
        start = base;
        range = free_ranges_lower_bound( start );
        assert(range != free_ranges_end && range->end >= start);

        if (start < range->base) start = ROUND_ADDR( (char *)range->base + align_mask, align_mask );
        do
        {
            if (start >= end || start < base || (char *)end - (char *)start < size) return NULL;
            if (start < range->end && start >= range->base && (char *)range->end - (char *)start >= size) break;
            if (++range == free_ranges_end) return NULL;
            start = ROUND_ADDR( (char *)range->base + align_mask, align_mask );
        }
        while (1);
    }
    return start;
}


/***********************************************************************
 *           remove_reserved_area
 *
 * Remove a reserved area from the list maintained by libwine.
 * virtual_mutex must be held by caller.
 */
static void remove_reserved_area( void *addr, size_t size )
{
    struct file_view *view;
    size_t view_size;

    TRACE( "removing %p-%p\n", addr, (char *)addr + size );
    mmap_remove_reserved_area( addr, size );
    ios_va_release_note();

    /* unmap areas not covered by an existing view */
    WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
    {
        if ((char *)view->base >= (char *)addr + size) break;
        if ((char *)view->base + view->size <= (char *)addr) continue;
        if (view->base > addr)
        {
            ios_jit_range_tripwire( "remove_reserved_area", addr,
                                    (char *)view->base - (char *)addr, -1,
                                    __builtin_return_address(0) );
            ios_pool_va_warn( "munmap", addr, (char *)view->base - (char *)addr );
            munmap( addr, (char *)view->base - (char *)addr );
        }
        if ((char *)view->base + view->size > (char *)addr + size) return;
        view_size = ROUND_SIZE( view->base, view->size, host_page_mask );
        size = (char *)addr + size - ((char *)view->base + view_size);
        addr = (char *)view->base + view_size;
    }
    ios_jit_range_tripwire( "remove_reserved_area", addr, size, -1, __builtin_return_address(0) );
    ios_pool_va_warn( "munmap", addr, size );
    munmap( addr, size );
}


/***********************************************************************
 *           unmap_area
 *
 * Unmap an area, or simply replace it by an empty mapping if it is
 * in a reserved area. virtual_mutex must be held by caller.
 */
static void unmap_area( void *start, size_t size )
{
    struct reserved_area *area;
    void *end;

    assert( !((UINT_PTR)start & host_page_mask) );
    size = ROUND_SIZE( 0, size, host_page_mask );
    if (!ios_place_release_is_fresh( start, size )) ios_va_release_note();

    ios_jit_range_tripwire( "unmap_area", start, size, -1, __builtin_return_address(0) );

    if (!(size = unmap_area_above_user_limit( start, size ))) return;

    end = (char *)start + size;

    LIST_FOR_EACH_ENTRY( area, &reserved_areas, struct reserved_area, entry )
    {
        void *area_start = area->base;
        void *area_end = (char *)area_start + area->size;

        if (area_start >= end) break;
        if (area_end <= start) continue;
        if (area_start > start)
        {
            ios_pool_va_warn( "munmap", start, (char *)area_start - (char *)start );
            munmap( start, (char *)area_start - (char *)start );
            start = area_start;
        }
        if (area_end >= end)
        {
            anon_mmap_fixed( start, (char *)end - (char *)start, PROT_NONE, MAP_NORESERVE );
            return;
        }
        anon_mmap_fixed( start, (char *)area_end - (char *)start, PROT_NONE, MAP_NORESERVE );
        start = area_end;
    }
    ios_pool_va_warn( "munmap", start, (char *)end - (char *)start );
    munmap( start, (char *)end - (char *)start );
}


/***********************************************************************
 *           alloc_view
 *
 * Allocate a new view. virtual_mutex must be held by caller.
 */
static struct file_view *alloc_view(void)
{
    if (next_free_view)
    {
        struct file_view *ret = next_free_view;
        next_free_view = *(struct file_view **)ret;
        return ret;
    }
    if (view_block_start == view_block_end)
    {
        void *ptr = anon_mmap_alloc( view_block_size, PROT_READ | PROT_WRITE );
        if (ptr == MAP_FAILED) return NULL;
        view_block_start = ptr;
        view_block_end = view_block_start + view_block_size / sizeof(*view_block_start);
    }
    return view_block_start++;
}


/***********************************************************************
 *           free_view
 *
 * Free memory for view structure. virtual_mutex must be held by caller.
 */
static void free_view( struct file_view *view )
{
    *(struct file_view **)view = next_free_view;
    next_free_view = view;
}


/***********************************************************************
 *           unregister_view
 *
 * Remove view from the tree and update free ranges. virtual_mutex must be held by caller.
 */
static void unregister_view( struct file_view *view )
{
    if (mmap_is_in_reserved_area( view->base, view->size ))
        free_ranges_remove_view( view );
    wine_rb_remove( &views_tree, &view->entry );
}


/***********************************************************************
 *           ios_jit_retire_image
 *
 * Opt-in (MADEIRA_JIT_IMAGE_RETIRE=1, or env.MADEIRA_JIT_IMAGE_RETIRE = 1 in
 * madeira.cfg; off by default). FreeLibrary can release an image and the
 * loader can then map a DIFFERENT image of the same size at the same base.
 * mprotect_exec's already-copied check matches on the PE range and the MZ
 * header's SizeOfImage, so it accepts the unloaded module's pool copy and the
 * new module runs the old module's translated code. Tombstone every pool
 * mapping that overlaps the unmapped range before the VA can be reused, so
 * the next image mapped there gets a fresh copy. The pool bytes themselves
 * stay in the process ledger (recycling executable bytes here would race
 * laggard readers); the tombstone write order is the one ios_jit_add_mapping
 * and ios_jit_reclaim_process use. Called with virtual_mutex held; takes
 * ios_pool_lock, which never waits for virtual_mutex.
 * Not to be confused with MADEIRA_NO_IMAGE_RETIRE (ml988 generation handoff).
 */
static int ios_jit_image_retire_enabled(void)
{
    static int enabled = -1;
    if (enabled < 0)
    {
        const char *env = getenv( "MADEIRA_JIT_IMAGE_RETIRE" );
        enabled = env && env[0] == '1' && !env[1];
        if (enabled) dprintf( 2, "[jit-image-retire] enabled\n" );
    }
    return enabled;
}

static void ios_jit_retire_image( void *base, size_t size )
{
    uintptr_t start = (uintptr_t)base;
    int i, retired = 0;
    static unsigned int reports;

    if (!size) return;
    pthread_mutex_lock( &ios_pool_lock );
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t mapped = (uintptr_t)ios_jit_mappings[i].pe_base;
        size_t length = ios_jit_mappings[i].size;
        if (!mapped || !length) continue;
        /* Subtraction avoids overflowing either end of an address interval. */
        if (mapped >= start ? mapped - start >= size : start - mapped >= length) continue;
        ios_jit_mappings[i].size = 0;
        __sync_synchronize();
        ios_jit_mappings[i].pe_base = NULL;
        retired++;
    }
    pthread_mutex_unlock( &ios_pool_lock );
    if (retired && __atomic_fetch_add( &reports, 1, __ATOMIC_RELAXED ) < 32)
        dprintf( 2, "[jit-image-retire] unmapped=%p size=%#lx translations=%d\n",
                 base, (unsigned long)size, retired );
}

/***********************************************************************
 *           ios_image_reload_mode
 *
 * What a module loaded again at the SAME base, after an unload, gets for its
 * pool copy.
 *
 * The pool copy holds the whole image, .data and .bss included, and ARM64EC
 * and x64 code reach their globals PC-relative, i.e. in the pool copy. When
 * FreeLibrary unmaps an image and the loader maps the same file at the same
 * address again, mprotect_exec's already-copied check (ml352: MZ header and
 * SizeOfImage still match) adopted the old copy as is: the new module ran
 * with the unloaded module's globals. Its DLL_PROCESS_DETACH had already run
 * the static destructors, but the guard variables of function-local statics
 * still said "constructed", so the next call returned a destroyed object.
 * GTA V Enhanced loads dxgi.dll (DXMT), unloads it and loads it again at the
 * same base: dxmt::Config::getInstance() handed back the unordered_map whose
 * destructor had set the bucket array to NULL -> AV in find(). On Windows a
 * reloaded DLL always starts with fresh .data/.bss.
 *
 * MADEIRA_IMAGE_RELOAD (default 1):
 *   1  the same image reloaded at the same base by the same process gets its
 *      copy rebuilt in place (same pool address, fresh bytes, relocations and
 *      x18 patches redone); any other reuse of an unmapped copy gets a new
 *      copy (as for a different image).
 *   2  always a new copy (costs pool space per reload).
 *   0  old behaviour: the stale copy is adopted as is.
 * Only modules that are unloaded and loaded again at the same address are
 * affected; every other load is unchanged. */
static int ios_image_reload_mode(void)
{
    static int mode = -1;
    if (mode < 0)
    {
        const char *env = getenv( "MADEIRA_IMAGE_RELOAD" );
        int m = 1;
        if (env && env[0] >= '0' && env[0] <= '2' && !env[1]) m = env[0] - '0';
        if (m != 1) dprintf( 2, "[image-reload] mode=%d (%s)\n", m,
                             m == 2 ? "always a new pool copy" : "off: adopt the unloaded copy as is" );
        mode = m;
    }
    return mode;
}

/***********************************************************************
 *           ios_jit_note_image_unmapped
 *
 * delete_view of a SEC_IMAGE view: mark every pool copy made from that range
 * as unmapped. Nothing is tombstoned (translations of laggard pointers into
 * the unloaded module keep their old target, exactly as before); only
 * mprotect_exec's already-copied check reads the mark. Called with
 * virtual_mutex held; takes ios_pool_lock like ios_jit_retire_image. */
static void ios_jit_note_image_unmapped( void *base, size_t size )
{
    uintptr_t start = (uintptr_t)base;
    int i;

    if (!size || !ios_image_reload_mode()) return;
    pthread_mutex_lock( &ios_pool_lock );
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        uintptr_t mapped = (uintptr_t)ios_jit_mappings[i].pe_base;
        size_t length = ios_jit_mappings[i].size;
        if (!mapped || !length) continue;
        if (mapped >= start ? mapped - start >= size : start - mapped >= length) continue;
        ios_jit_mappings[i].unmapped = 1;
    }
    pthread_mutex_unlock( &ios_pool_lock );
}

/***********************************************************************
 *           ios_jit_reload_choice
 *
 * Decide what an unmapped entry means for an image mapped at its base again.
 * Pure (no memory access), so the host test can drive it:
 *   0  entry is live (not unmapped) or mode 0: the old early-out applies;
 *   1  rebuild the copy in place (mode 1, NULL owner, identical PE headers;
 *      mprotect_exec then also requires the copy's pool range to be a ledger
 *      record of the mapping process, see ios_pool_ledger_holds);
 *   2  ignore the entry, make a new copy (add_mapping purges the old one). */
static int ios_jit_reload_choice( const struct ios_jit_mapping *m, int same_headers, int mode )
{
    if (!m->unmapped || !mode) return 0;
    if (mode == 1 && !m->owner_peb && same_headers) return 1;
    return 2;
}

/***********************************************************************
 *           ios_jit_same_headers
 *
 * 1 when the image now mapped at `pe` has byte-identical PE headers (from
 * the start to the end of the section table) to the pool copy at `jit`,
 * which was copied from the old view before any loader write. The new view
 * is read fault-safely. A different file of the same size fails here and
 * gets a new copy instead of overwriting code an emulator may still hold
 * translations of. */
static int ios_jit_same_headers( uintptr_t pe, const unsigned char *jit )
{
    unsigned char now[0x400];
    unsigned int lfanew = 0, end, off;
    unsigned short nsec = 0, optsz = 0;
    mach_vm_size_t got = 0;

    if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(pe + 0x3c), 4,
                                (mach_vm_address_t)&lfanew, &got ) != KERN_SUCCESS || got != 4)
        return 0;
    if (!lfanew || lfanew >= 0x1000 || *(const unsigned int *)(jit + 0x3c) != lfanew) return 0;
    nsec  = *(const unsigned short *)(jit + lfanew + 6);
    optsz = *(const unsigned short *)(jit + lfanew + 0x14);
    end = lfanew + 0x18 + optsz + 40u * nsec;
    if (end > 0x1000) end = 0x1000;
    for (off = 0; off < end; off += sizeof(now))
    {
        unsigned int n = end - off < sizeof(now) ? end - off : (unsigned int)sizeof(now);
        if (mach_vm_read_overwrite( mach_task_self(), (mach_vm_address_t)(pe + off), n,
                                    (mach_vm_address_t)now, &got ) != KERN_SUCCESS || got != n)
            return 0;
        if (memcmp( now, jit + off, n )) return 0;
    }
    return 1;
}

/***********************************************************************
 *           ios_pool_ledger_holds
 *
 * 1 when one pool ledger record of process `peb` covers [off, off + need):
 * the in-place rebuild (ios_image_reload_mode) only rewrites bytes its first
 * copy was given, never a neighbour's (e.g. if a rebuilt image needed more
 * x18 trampoline space than the first copy reserved), and only in a range
 * that lives as long as the process now using it (reclaim frees by ledger
 * peb). */
static int ios_pool_ledger_holds( size_t off, size_t need, void *peb )
{
    int i, ok = 0;

    pthread_mutex_lock( &ios_pool_lock );
    for (i = 0; i < ios_pool_ledger_count && !ok; i++)
        ok = ios_pool_ledger[i].peb == peb && off >= ios_pool_ledger[i].off &&
             off - ios_pool_ledger[i].off <= ios_pool_ledger[i].size &&
             need <= ios_pool_ledger[i].size - (off - ios_pool_ledger[i].off);
    pthread_mutex_unlock( &ios_pool_lock );
    return ok;
}

/* madeira-bcd: VIEW HISTORY. Ghost of Tsushima's workers faulted copying 2 MB
 * out of 0x70eedd0040 -- a range with no Wine view by then, inside the native
 * stack of a thread that had exited, freed while the copies ran. Who created
 * and who removed the views there could not be read from any log. Every guest-
 * band view of 1 MB or more is recorded here when it is created and when it is
 * deleted (thread, time, why), and a fault on an address Wine does not own
 * prints the records that covered it (ios_dump_fault_region). Passive. */
/* A release site is captured at NtFreeVirtualMemory, before free_pages enters
 * delete_view.  A native return address alone usually names an ARM64EC thunk,
 * so also retain FEX's saved x64 context and return-address candidates from
 * its stack.  Nothing is unwound or printed on the hot free path. */
struct ios_vh_site
{
    void *native_return;
    uint64_t state_rip, ctx_rip, ctx_rsp, image_base;
    uint64_t image_returns[8];
    unsigned int nr_returns, valid;
    char *base;
};
struct ios_vh_rec
{
    char *base;
    size_t size;
    unsigned int protect, tid, ms;
    char kind;
    const char *why;
    struct ios_vh_site site;
};
#define IOS_VH_N 4096
static struct ios_vh_rec ios_vh_ring[IOS_VH_N];
static unsigned long ios_vh_pos;
static __thread const char *ios_vh_why;
static __thread struct ios_vh_site ios_vh_free_site;
static unsigned int ios_vh_ms( void )
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    return (unsigned int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
static void ios_vh_capture_free_site( const struct file_view *view, void *native_return )
{
    TEB *teb = NtCurrentTeb();
    struct ios_vh_site *site = &ios_vh_free_site;
    void *area;
    uintptr_t rsp, low, high, image_lo = 0, image_hi = 0;
    unsigned int i;

    site->valid = 0;
    if (view->size < (1u << 20) || (uintptr_t)view->base < 0x7000000000ULL ||
        (uintptr_t)view->base >= 0x7c00000000ULL || !teb) return;
    site->base = view->base;
    site->native_return = native_return;
    site->state_rip = ios_guest_rip_now();
    site->ctx_rip = ios_guest_ctx_rip();
    site->ctx_rsp = site->image_base = 0;
    site->nr_returns = 0;
    area = teb->ChpeV2CpuAreaInfo;
    if (area) site->ctx_rsp = *(uint64_t *)((char *)area + 0x50 + 0x98);

    /* Bound the scan to this thread's stack and 128 slots from saved RSP.
     * These are candidates, not a real unwind; saved EC context can be stale. */
    rsp = (uintptr_t)site->ctx_rsp;
    low = (uintptr_t)teb->Tib.StackLimit;
    high = (uintptr_t)teb->Tib.StackBase;
    if (teb->Peb && teb->Peb->ImageBaseAddress)
    {
        struct file_view *image = find_view( teb->Peb->ImageBaseAddress, 0 );
        if (image && (image->protect & SEC_IMAGE))
        {
            image_lo = (uintptr_t)image->base;
            image_hi = image_lo + image->size;
            site->image_base = image_lo;
        }
    }
    if (image_lo && rsp >= low && rsp < high && !(rsp & 7))
    {
        for (i = 0; i < 128 && high - rsp >= (i + 1) * sizeof(uint64_t) &&
                    site->nr_returns < ARRAY_SIZE(site->image_returns); i++)
        {
            uint64_t candidate = ((const uint64_t *)rsp)[i];
            if (candidate >= image_lo && candidate < image_hi)
                site->image_returns[site->nr_returns++] = candidate;
        }
    }
    site->valid = 1;
}
static void ios_vh_note( char kind, const struct file_view *view )
{
    struct ios_vh_rec *r;
    if (view->size < (1u << 20) || (uintptr_t)view->base < 0x7000000000ULL || (uintptr_t)view->base >= 0x7c00000000ULL) return;
    r = &ios_vh_ring[__atomic_fetch_add( &ios_vh_pos, 1, __ATOMIC_RELAXED ) % IOS_VH_N];
    r->base = view->base; r->size = view->size; r->protect = view->protect; r->kind = kind;
    r->tid = NtCurrentTeb() ? (unsigned int)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread : 0;
    r->ms = ios_vh_ms();
    r->why = ios_vh_why;
    r->site = kind == 'd' && ios_vh_free_site.valid &&
              ios_vh_free_site.base == view->base ? ios_vh_free_site : (struct ios_vh_site){0};
}
static void ios_vh_dump( const void *addr )
{
    unsigned long end = __atomic_load_n( &ios_vh_pos, __ATOMIC_RELAXED ), i, n = 0;
    unsigned int now = ios_vh_ms();
    for (i = end; i-- > 0 && end - i <= IOS_VH_N && n < 12; )
    {
        const struct ios_vh_rec *r = &ios_vh_ring[i % IOS_VH_N];
        if ((const char *)addr < r->base || (const char *)addr >= r->base + r->size) continue;
        dprintf( 2, "[fault-rgn]   history: view %p+0x%lx protect=0x%x %s by tid %04x %u ms ago%s%s\n",
                 r->base, (unsigned long)r->size, r->protect, r->kind == 'c' ? "CREATED" : "DELETED",
                 r->tid, now - r->ms, r->why ? " -- " : "", r->why ? r->why : "" );
        if (r->site.valid)
        {
            unsigned int j;
            dprintf( 2, "[free-origin] view=%p native-return=%p state-rip=%#llx ec-ctx-rip=%#llx "
                     "ec-ctx-rsp=%#llx main-image=%#llx candidates=%u (stack scan, not unwind)\n",
                     r->base, r->site.native_return, (unsigned long long)r->site.state_rip,
                     (unsigned long long)r->site.ctx_rip, (unsigned long long)r->site.ctx_rsp,
                     (unsigned long long)r->site.image_base, r->site.nr_returns );
            for (j = 0; j < r->site.nr_returns; j++)
                dprintf( 2, "[free-origin]   candidate[%u]=%#llx exe+rva=%#llx\n", j,
                         (unsigned long long)r->site.image_returns[j],
                         (unsigned long long)(r->site.image_returns[j] - r->site.image_base) );
        }
        n++;
    }
    if (!n) dprintf( 2, "[fault-rgn]   history: no view of 1 MB+ covered this address in the last %u records\n", IOS_VH_N );
}


/***********************************************************************
 *           delete_view
 *
 * Deletes a view. virtual_mutex must be held by caller.
 */
static void delete_view( struct file_view *view ) /* [in] View */
{
    ios_vh_note( 'd', view );   /* madeira-bcd: view history */
    /* ml989: entered BEFORE any field of `view` is read, so "call never
     * entered" is distinguishable from "died reading the view". */
    if (ios_retire_trace_armed) ios_retire_mark( "D0>\n" );
    if ((view->protect & SEC_IMAGE) && ios_jit_image_retire_enabled())
        ios_jit_retire_image( view->base, view->size );
    if (view->protect & SEC_IMAGE) ios_jit_note_image_unmapped( view->base, view->size );
    ios_swap_release_range( view->base, view->size, 0 );   /* ml1077 */
    if (!(view->protect & VPROT_SYSTEM)) unmap_area( view->base, view->size );
    if (ios_retire_trace_armed) ios_retire_mark( "D1u\n" );   /* unmap_area done */
    set_page_vprot( view->base, view->size, 0 );
    if (ios_retire_trace_armed) ios_retire_mark( "D2v\n" );   /* vprot cleared */
    if (view->protect & VPROT_ARM64EC) clear_arm64ec_range( view->base, view->size );
    if (ios_retire_trace_armed) ios_retire_mark( "D3e\n" );   /* ec range cleared */
    unregister_view( view );
    if (ios_retire_trace_armed) ios_retire_mark( "D4r\n" );   /* survived free_ranges asserts */
    free_view( view );
    if (ios_retire_trace_armed) ios_retire_mark( "D5<\n" );   /* delete_view complete */
}


/***********************************************************************
 *           register_view
 *
 * Add view to the tree and update free ranges. virtual_mutex must be held by caller.
 */
static void register_view( struct file_view *view )
{
    wine_rb_put( &views_tree, view->base, &view->entry );
    if (mmap_is_in_reserved_area( view->base, view->size ))
        free_ranges_insert_view( view );
}


/***********************************************************************
 *           create_view
 *
 * Create a view. virtual_mutex must be held by caller.
 */
static NTSTATUS create_view( struct file_view **view_ret, void *base, size_t size, unsigned int vprot )
{
    struct file_view *view;

    assert( !((UINT_PTR)base & host_page_mask) );
    assert( !(size & page_mask) );

    /* Check for overlapping views. This can happen if the previous view
     * was a system view that got unmapped behind our back. In that case
     * we recover by simply deleting it. */

    while ((view = find_view_range( base, size )))
    {
        TRACE( "overlapping view %p-%p for %p-%p\n",
               view->base, (char *)view->base + view->size, base, (char *)base + size );
        assert( view->protect & VPROT_SYSTEM );
        delete_view( view );
    }

    if (!alloc_pages_vprot( base, size ))
    {
        ios_af_set( 4, errno, base, size );
        return STATUS_NO_MEMORY;
    }

    /* Create the view structure */

    if (!(view = alloc_view()))
    {
        ios_af_set( 5, errno, base, size );
        FIXME( "out of memory for %p-%p\n", base, (char *)base + size );
        return STATUS_NO_MEMORY;
    }

    view->base    = base;
    view->size    = size;
    view->protect = vprot;
    view->ios_flags = 0;
    if (use_kernel_writewatch) vprot &= ~VPROT_WRITEWATCH;
    set_page_vprot( base, size, vprot );

    register_view( view );
    kernel_writewatch_register_range( view, view->base, view->size );
    ios_vh_note( 'c', view );   /* madeira-bcd: view history */

    *view_ret = view;
    return STATUS_SUCCESS;
}

#ifdef WINE_IOS
/***********************************************************************
 *           ios_jit_purge_window
 *
 * Drop every JIT-pool record that describes PE memory inside a guest window
 * that is being released.
 *
 * ios_jit_reclaim_process() already frees the pool ranges the dead PEB
 * allocated, and ios_jit_add_mapping()'s stale-containment logic would purge an
 * overlapping entry the next time an image is mapped at the same address.  But
 * relying on that means the table keeps entries whose pe_base is about to be
 * replaced by a DIFFERENT process's image at exactly the same guest address —
 * the window is handed back at the same B, so the next 32-bit process's ntdll,
 * kernel32 and exe land on the very same VAs — and until the purge-on-add
 * happens every translate/sync_write for an address in the overlap resolves to
 * the dead copy.  Make it explicit: at release, anything in [base, base+size)
 * is by definition gone.
 *
 * Entries are tombstoned in the order the lock-free readers require: size = 0
 * first (a zero-size entry matches no query), barrier, then pe_base = NULL. */
static void ios_jit_purge_window( ULONG_PTR base, ULONG_PTR size )
{
    int i, maps = 0, aliases = 0;

    pthread_mutex_lock( &ios_pool_lock );
    for (i = 0; i < ios_jit_mapping_count; i++)
    {
        ULONG_PTR eb = (ULONG_PTR)ios_jit_mappings[i].pe_base;

        if (!ios_jit_mappings[i].pe_base) continue;
        if (eb >= base + size || eb + ios_jit_mappings[i].size <= base) continue;
        dprintf( 2, "[jit-pool] image %p+0x%lx jit=%p owner_peb=%p purged: its guest window "
                    "%p+0x%llx is being released\n",
                 (void *)eb, (unsigned long)ios_jit_mappings[i].size,
                 ios_jit_mappings[i].jit_base, ios_jit_mappings[i].owner_peb,
                 (void *)base, (unsigned long long)size );
        ios_jit_mappings[i].size = 0;
        __sync_synchronize();
        ios_jit_mappings[i].pe_base = NULL;
        maps++;
    }
    for (i = 0; i < ios_jit_anon_alias_count; i++)
    {
        uintptr_t uv = ios_jit_anon_aliases[i].user_va;

        if (!uv) continue;
        if (uv >= base + size || ios_jit_anon_aliases[i].user_va_end <= base) continue;
        dprintf( 2, "[iOS-xrem] anon RWX alias %p..%p purged: its guest window %p is being "
                    "released\n", (void *)uv, (void *)ios_jit_anon_aliases[i].user_va_end,
                 (void *)base );
        ios_jit_anon_aliases[i].user_va_end = 0;
        __sync_synchronize();
        ios_mono_alias_retire( uv );
        ios_jit_anon_aliases[i].user_va = 0;
        aliases++;
    }
    pthread_mutex_unlock( &ios_pool_lock );
    dprintf( 2, "[jit-pool] window purge B=%p: %d image mapping(s), %d anon alias(es)\n",
             (void *)base, maps, aliases );
}


/***********************************************************************
 *           ios_wow_window_teardown
 *
 * RELEASE-ON-NEXT-ADOPT, step 2 (docs/WOW64.md).  Give a dead 32-bit
 * pseudo-process's guest window back to the slot, WITHOUT ever leaving a hole
 * the kernel could fill.
 *
 * The order is what matters:
 *
 *   1. Wine's bookkeeping for everything inside [B, B+4G) goes first — every
 *      file_view (the i386 images, the anon views, the USD second view at
 *      B+0x7ffe0000, the apiset view, the wow64 parameters block, the TEB/PEB
 *      pages, every thread stack, the BOP/unix-call page at guest 0x250000),
 *      then the pages_vprot bytes for the whole range.  Deleting a view inside
 *      a reserved area already replaces its pages with PROT_NONE rather than
 *      unmapping them, and it is what keeps free_ranges and views_tree
 *      consistent; doing it after the big mmap would leave the tree pointing at
 *      memory that is no longer what it says.
 *
 *   2. ONE mmap(MAP_FIXED, PROT_NONE, MAP_ANON|MAP_NORESERVE) over the whole
 *      4 GB.  A fixed mapping atomically discards whatever is under it, so
 *      there is never an instant in which the range is free — which is the
 *      reason a placeholder is never unmapped.  NO munmap, and the
 *      reserved-area entry and the FB3 guard page are deliberately untouched:
 *      an overrun past B+4G must keep faulting, and the next adopter needs the
 *      reservation to be exactly what it was.
 *
 *   3. The per-pseudo-process registries that are keyed by PEB and would
 *      otherwise answer for the NEXT process: a child's PEB is allocated inside
 *      the window, so the next 32-bit child's PEB very probably has the same
 *      host address as this dead one, and a surviving [proc-ident] entry would
 *      hand it the dead process's image info and private ntdll.
 *
 *   4. The session globals that point into the window.
 *
 * LIVE THREADS.  The precondition everybody wants — "no thread of the owner is
 * still running" — cannot be proved on iOS: pseudo-processes are threads of one
 * Mach task, NtTerminateProcess longjmps out of the CALLING thread only
 * (process_ios.c), nothing joins the others, and a pseudo-process's own boot TEB
 * is never freed, so counting teb_list entries with teb->Peb == dead_peb always
 * finds at least one and proves nothing.  What this function does instead:
 * unlink those TEBs from teb_list and report how many there were, wait out a
 * settle interval after the exit (see
 * IOS_WOW_SETTLE_SEC, and note that the teardown only runs when the NEXT 32-bit
 * process boots, which is at least one process creation later), and leave the
 * range PROT_NONE — so a laggard thread of the dead process FAULTS on its first
 * access instead of quietly writing into the next process's memory.  That is
 * strictly better than the previous behaviour, which was to leak the slot and
 * make every later 32-bit process fail to start.
 */
static int ios_wow_window_teardown( ULONG_PTR base, void *dead_peb, unsigned guard_owned )
{
    struct ntdll_thread_data *thread_data, *next_thread_data;
    struct file_view *batch[256];
    unsigned stale_tebs = 0;
    unsigned deleted = 0, straddlers = 0;
    sigset_t sigset;
    unsigned n, i;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );

    /* teb_list is threaded THROUGH THE TEBs themselves (the entry is a field of
     * the ntdll_thread_data inside each TEB), and this process's TEBs are inside
     * the window.  Unlink them before the memory goes: nothing removes them
     * otherwise — virtual_free_teb() is the only remover and a pseudo-process's
     * boot TEB is never freed — so the very next walker of teb_list
     * (virtual_clear_tls_index, for one) would step into PROT_NONE.
     * The criterion is the TEB's ADDRESS, not its PEB: what makes an entry
     * unusable is that its storage is about to be replaced. */
    LIST_FOR_EACH_ENTRY_SAFE( thread_data, next_thread_data, &teb_list,
                              struct ntdll_thread_data, entry )
    {
        TEB *t = CONTAINING_RECORD( thread_data, TEB, GdiTebBatch );

        if ((ULONG_PTR)t < base || (ULONG_PTR)t >= base + IOS_WOW_WINDOW_SIZE) continue;
        list_remove( &thread_data->entry );
        stale_tebs++;
    }

    /* 1. views, in batches so the rb tree is never walked while it is edited */
    do
    {
        struct file_view *view;

        n = 0;
        WINE_RB_FOR_EACH_ENTRY( view, &views_tree, struct file_view, entry )
        {
            ULONG_PTR vb = (ULONG_PTR)view->base;

            if (vb + view->size <= base) continue;
            if (vb >= base + IOS_WOW_WINDOW_SIZE) break;   /* tree is address-ordered */
            if (vb < base || vb + view->size > base + IOS_WOW_WINDOW_SIZE)
            {
                /* a view cannot legally straddle the window: everything in here
                 * was placed inside the reserved area.  Say so and leave it. */
                straddlers++;
                continue;
            }
            batch[n++] = view;
            if (n == ARRAY_SIZE(batch)) break;
        }
        for (i = 0; i < n; i++) delete_view( batch[i] );
        deleted += n;
    } while (n == ARRAY_SIZE(batch));

    /* 2. pages_vprot for the whole range (delete_view cleared the covered
     *    pages; this catches anything that was never a view) */
    if (alloc_pages_vprot( (void *)base, IOS_WOW_WINDOW_SIZE ))
        set_page_vprot( (void *)base, IOS_WOW_WINDOW_SIZE, 0 );

    /* 3. ONE fixed mapping over the whole window.  Deliberately not munmap +
     *    mmap: that would open the hole this whole mechanism exists to close. */
    if (anon_mmap_fixed( (void *)base, IOS_WOW_WINDOW_SIZE, PROT_NONE, MAP_NORESERVE ) == MAP_FAILED)
    {
        server_leave_uninterrupted_section( &virtual_mutex, &sigset );
        ERR( "[wow-window] teardown of B=%p FAILED: the single PROT_NONE replacement of the 4GB "
             "range returned %s. The slot stays dead and no 32-bit process will get it; nothing "
             "was handed back to the kernel.\n", (void *)base, strerror(errno) );
        return 0;
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );

    dprintf( 2, "[wow-window] teardown B=%p (owner peb=%p): %u view(s) deleted, %u straddling "
                "view(s) left alone, %u TEB(s) unlinked from teb_list (nothing frees a "
                "pseudo-process's boot TEB on iOS), 4GB replaced by ONE PROT_NONE mapping, "
                "guard=%s kept\n",
             (void *)base, dead_peb, deleted, straddlers, stale_tebs,
             guard_owned ? "owned" : "borrowed" );
    if (straddlers)
        ERR( "[wow-window] teardown B=%p: %u view(s) straddle the window boundary and were NOT "
             "deleted — their pages were replaced anyway, so Wine's bookkeeping for them is now "
             "wrong. Nothing should ever place a view across a guest window.\n",
             (void *)base, straddlers );

    /* 4. JIT-pool records: the dead process's pool ranges and copies, then
     *    anything at all that describes memory inside the window. */
    if (dead_peb)
    {
        extern void ios_jit_reclaim_process( void *peb );
        ios_jit_reclaim_process( dead_peb );
    }
    ios_jit_purge_window( base, IOS_WOW_WINDOW_SIZE );

    /* 5. registries keyed by the dead PEB: the next child's PEB is allocated
     *    at the same place inside the same window, so a survivor would answer
     *    for it. */
    {
        extern int ios_thread_registry_purge_range( uintptr_t base, uintptr_t size );
        ios_thread_registry_purge_range( (uintptr_t)base, (uintptr_t)IOS_WOW_WINDOW_SIZE );
    }
    if (dead_peb)
    {
        extern void ios_proc_ident_release( void *peb_id );
        extern void ios_fd_cache_release( void *peb );
        ios_proc_ident_release( dead_peb );
        ios_fd_cache_release( dead_peb );
    }

    /* 6. session globals that pointed into the window.  user_space_wow_limit is
     *    republished from the next 32-bit main image's large-address-aware bit
     *    (virtual_set_large_address_space); wow_peb is
     *    re-derived by that process's init_peb.
     *
     *    `peb` is the dangerous one: the child path deliberately leaves the
     *    session global pointing at the last child it booted (loader_ios.c,
     *    "peb stays as child_peb on this thread"), so after a 32-bit child dies
     *    the global names a PEB inside the window we have just made PROT_NONE,
     *    and the next unix-side `peb->...` on any thread would fault. */
    if ((ULONG_PTR)peb >= base && (ULONG_PTR)peb < base + IOS_WOW_WINDOW_SIZE)
    {
        if (ios_session_peb &&
            !((ULONG_PTR)ios_session_peb >= base &&
              (ULONG_PTR)ios_session_peb < base + IOS_WOW_WINDOW_SIZE))
        {
            dprintf( 2, "[wow-window] session global peb=%p was the released window's — put back "
                        "to the session PEB %p\n", peb, ios_session_peb );
            peb = ios_session_peb;
        }
        else
            ERR( "[wow-window] session global peb=%p is inside the released window %p and there is "
                 "no session PEB outside it — every later unix-side peb dereference will fault\n",
                 peb, (void *)base );
    }
    if (wow_peb && (ULONG_PTR)wow_peb >= base && (ULONG_PTR)wow_peb < base + IOS_WOW_WINDOW_SIZE)
    {
        dprintf( 2, "[wow-peb] session wow_peb=%p belonged to the released window — cleared\n",
                 wow_peb );
        wow_peb = NULL;
    }
    /*    user_space_wow_limit is a GUEST-namespace ceiling and a session global,
     *    so it belongs to every live 32-bit pseudo-process at once.  With more
     *    than one window slot in use (the [cage] carve) clearing it on one
     *    process's exit would strip the survivor's 32-bit ceiling mid-run:
     *    get_wow_user_space_limit() would read 0 and every later placement —
     *    TEB blocks, 32-bit stacks, images, every zero_bits translation — would
     *    lose its bound.  Only clear it when no live window is left. */
    if (user_space_wow_limit)
    {
        unsigned i, survivors = 0;

        pthread_mutex_lock( &ios_wow_mutex );
        for (i = 0; i < ios_wow_window_count; i++)
            if (ios_wow_windows[i].base && ios_wow_windows[i].base != base &&
                !ios_wow_windows[i].dead && !ios_wow_windows[i].leaked) survivors++;
        pthread_mutex_unlock( &ios_wow_mutex );

        if (survivors)
            dprintf( 2, "[wow-limit] KEPT (%p): %u other guest window(s) are still live and share "
                        "this guest ceiling\n", (void *)user_space_wow_limit, survivors );
        else
        {
            dprintf( 2, "[wow-limit] cleared (was %p): the next 32-bit main image publishes its own\n",
                     (void *)user_space_wow_limit );
            user_space_wow_limit = 0;
            ios_wow_laa_synth = 0;   /* same ceiling, same lifetime */
        }
    }
    return 1;
}
#endif  /* WINE_IOS */


/***********************************************************************
 *           get_win32_prot
 *
 * Convert page protections to Win32 flags.
 */
static DWORD get_win32_prot( BYTE vprot, unsigned int map_prot )
{
    DWORD ret = VIRTUAL_Win32Flags[vprot & 0x0f];
    if (vprot & VPROT_GUARD) ret |= PAGE_GUARD;
    if (map_prot & SEC_NOCACHE) ret |= PAGE_NOCACHE;
    return ret;
}


/***********************************************************************
 *           get_vprot_flags
 *
 * Build page protections from Win32 flags.
 */
static NTSTATUS get_vprot_flags( DWORD protect, unsigned int *vprot, BOOL image )
{
    switch(protect & 0xff)
    {
    case PAGE_READONLY:
        *vprot = VPROT_READ;
        break;
    case PAGE_READWRITE:
        if (image)
            *vprot = VPROT_READ | VPROT_WRITECOPY;
        else
            *vprot = VPROT_READ | VPROT_WRITE;
        break;
    case PAGE_WRITECOPY:
        *vprot = VPROT_READ | VPROT_WRITECOPY;
        break;
    case PAGE_EXECUTE:
        *vprot = VPROT_EXEC;
        break;
    case PAGE_EXECUTE_READ:
        *vprot = VPROT_EXEC | VPROT_READ;
        break;
    case PAGE_EXECUTE_READWRITE:
        if (image)
            *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITECOPY;
        else
            *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITE;
        break;
    case PAGE_EXECUTE_WRITECOPY:
        *vprot = VPROT_EXEC | VPROT_READ | VPROT_WRITECOPY;
        break;
    case PAGE_NOACCESS:
        *vprot = 0;
        break;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }
    if (protect & PAGE_GUARD) *vprot |= VPROT_GUARD;
    return STATUS_SUCCESS;
}


/* task #34 [jit-name]: read a mapped PE's own name from its export directory
 * (Name field), so the pool-copy log lines name the DLL instead of a bare
 * base address — needed to identify which module a pseudo-proc wrongly
 * executes across a self-relaunch. Bounds-checked against image_size; returns
 * "?" on any malformed/absent header. `image_base` must be the READABLE
 * mapped PE (RVA==offset). Not thread-safe on the returned pointer's contents,
 * but names live in the image's read-only .rdata so they're stable. */
const char *ios_pe_module_name( const void *image_base, size_t image_size )
{
    const unsigned char *b = image_base;
    uint32_t lfanew, exp_rva, name_rva;
    const unsigned char *pe;

    if (!b || image_size < 0x100) return "?";
    if (b[0] != 'M' || b[1] != 'Z') return "?";
    lfanew = *(const uint32_t *)(b + 0x3c);
    if ((size_t)lfanew + 0x90 > image_size) return "?";
    pe = b + lfanew;
    if (pe[0] != 'P' || pe[1] != 'E') return "?";
    if (*(const uint16_t *)(pe + 0x18) != 0x20b) return "?";   /* PE32+ only */
    exp_rva = *(const uint32_t *)(pe + 0x88);                  /* DataDir[0] Export VA */
    if (!exp_rva || (size_t)exp_rva + 0x10 > image_size) return "?";
    name_rva = *(const uint32_t *)(b + exp_rva + 0x0c);        /* IMAGE_EXPORT_DIRECTORY.Name */
    if (!name_rva || (size_t)name_rva + 1 > image_size) return "?";
    /* Ensure NUL within the image so the %s can't run off the mapping. */
    {
        size_t i, cap = image_size - name_rva;
        if (cap > 64) cap = 64;
        for (i = 0; i < cap; i++) if (b[name_rva + i] == 0) return (const char *)(b + name_rva);
        return "?";
    }
}


