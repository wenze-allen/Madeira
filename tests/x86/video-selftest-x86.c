/* video-selftest-x86.c -- on-device 32-bit video self-test.        (MADEIRA)
 *
 * Run this one i386 program on the iPad after each build to exercise every
 * video playback path visual novels use through WoW64:
 *
 *   [1/6] kirikiri2-wmv-dmo   Sabbat of the Witch's path: LoadLibrary
 *                             wmvcore.dll + GetProcAddress WMCreateSyncReader,
 *                             open ASF, SetReadStreamSamples(TRUE) on both
 *                             streams, feed compressed WMV/WMA packets to
 *                             CLSID_CWMVDecMediaObject and
 *                             CLSID_CWMADecMediaObject via IMediaObject, and
 *                             verify RGB32 frames + PCM samples + checksums.
 *   [2/6] kirikiri-mpeg1      Hand-built DirectShow graph (all ConnectDirect,
 *                             never RenderFile): AsyncReader -> MPEG1Splitter
 *                             -> CMpegVideoCodec -> bottom-up-only RGB32 sink,
 *                             and MPEG1Splitter -> CMpegAudioCodec -> null PCM
 *                             sink; check frame count, negotiated 320x240 from
 *                             the connection's media type, IAMStreamSelect
 *                             Count/Info on the splitter, then rewind with
 *                             IMediaPosition::put_CurrentPosition(0) and play
 *                             to EC_COMPLETE a second time.
 *   [3/6] dshow-renderfile    DirectShow RenderFile on the MPEG-1 clip with
 *                             the default renderer in a hidden window, running
 *                             to EC_COMPLETE.
 *   [4/6] mf-session-evr-sar  Senren Banka's path: ASF clip through
 *                             MFCreateMediaSession with EVR on a window and
 *                             SAR, checking IMFVideoDisplayControl's
 *                             GetCurrentImage returns a non-black image
 *                             mid-way, IMFPresentationClock::GetTime advances,
 *                             and playback reaches MESessionEnded.
 *   [5/6] mf-source-reader    MFCreateSourceReaderFromURL on the ASF clip,
 *                             decoding video to MFVideoFormat_RGB32 and
 *                             counting non-black frames.
 *   [6/6] mci-mpeg            mciSendString open/play/close on the MPEG-1
 *                             clip, waiting for playback completion.
 *
 * Report output goes both to console/stderr (captured by Madeira's device log)
 * and to a log file (%USERPROFILE%\Documents\video-selftest.log by default, or
 * MADEIRA_SELFTEST_LOG if set).
 *
 * Exit status: the number of paths that failed (0 = all 6 passed, 1..6 = count
 * of failed paths; 99 if basic Win32/COM initialisation or clip staging failed
 * before the paths could run).
 *
 * Built with -nostdlib -ffreestanding like wma-x86.c so the PE imports only
 * the system API DLLs it explicitly links against; decoders, splitters and
 * wmvcore.dll are reached through COM / LoadLibrary just as games reach them.
 */

#include <stddef.h>
#define COBJMACROS
#define CONST_VTABLE
#define INITGUID
#define NO_DSHOW_STRSAFE
#include <windows.h>
#include <objbase.h>
#include <mmsystem.h>
#include <mmreg.h>
#include <dshow.h>
#include <dmo.h>
#include <wmsdk.h>
#include <wmcodecdsp.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfobjects.h>
#include <mfreadwrite.h>
#include <mferror.h>
#include <evr.h>

#include "video-selftest-clips.h"

#ifndef NS_E_NO_MORE_SAMPLES
#define NS_E_NO_MORE_SAMPLES ((HRESULT)0xc00d0bcfL)
#endif

#define FNV1A_INIT 0x811c9dc5u
#define FNV1A_PRIME 0x01000193u

#define WATCHDOG_TIMEOUT_MS 90000u

static const GUID k_guid_null = { 0 };

/* -nostdlib: clang may lower struct zeroing/copying/comparison to these. */
void *memset( void *dst, int c, size_t n )
{
    unsigned char *p = dst;
    while (n--) *p++ = (unsigned char)c;
    return dst;
}

void *memcpy( void *dst, const void *src, size_t n )
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

int memcmp( const void *a, const void *b, size_t n )
{
    const unsigned char *pa = a, *pb = b;
    while (n--)
    {
        if (*pa != *pb) return (int)*pa - (int)*pb;
        pa++;
        pb++;
    }
    return 0;
}

/* 64-bit / 32-bit unsigned division without libgcc's __udivdi3. */
static DWORD u64_div_u32( ULONGLONG num, DWORD den )
{
    ULONGLONG rem = 0;
    DWORD quot = 0;
    int bit;

    if (!den) return 0;
    for (bit = 63; bit >= 0; bit--)
    {
        rem = (rem << 1) | ((num >> bit) & 1u);
        if (rem >= den)
        {
            rem -= den;
            if (bit < 32) quot |= (1u << bit);
        }
    }
    return quot;
}

static DWORD hns_to_ms( LONGLONG hns )
{
    if (hns <= 0) return 0;
    return u64_div_u32( (ULONGLONG)hns, 10000u );
}

/* -------------------------------------------------------------------------
 * Console + log-file writer (no CRT printf/strlen).
 * ------------------------------------------------------------------------- */

static HANDLE g_log_file = INVALID_HANDLE_VALUE;
static volatile LONG g_current_stage = 0;

static void write_raw( const char *msg, DWORD len )
{
    HANDLE h_err = GetStdHandle( STD_ERROR_HANDLE );
    HANDLE h_out = GetStdHandle( STD_OUTPUT_HANDLE );
    DWORD written;

    if (h_err && h_err != INVALID_HANDLE_VALUE)
    {
        written = 0;
        WriteFile( h_err, msg, len, &written, NULL );
    }
    if (h_out && h_out != INVALID_HANDLE_VALUE && h_out != h_err)
    {
        written = 0;
        WriteFile( h_out, msg, len, &written, NULL );
    }
    if (g_log_file != INVALID_HANDLE_VALUE)
    {
        written = 0;
        WriteFile( g_log_file, msg, len, &written, NULL );
    }
}

static void flush_log( void )
{
    if (g_log_file != INVALID_HANDLE_VALUE)
        FlushFileBuffers( g_log_file );
}

static void write_str( const char *s )
{
    if (!s) return;
    write_raw( s, (DWORD)lstrlenA( s ) );
}

static void write_wstr( const WCHAR *ws )
{
    char buf[128];
    DWORD pos = 0;

    if (!ws) return;
    while (*ws)
    {
        WCHAR ch = *ws++;
        buf[pos++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
        if (pos == sizeof(buf))
        {
            write_raw( buf, pos );
            pos = 0;
        }
    }
    if (pos) write_raw( buf, pos );
}

static void write_uint( DWORD value )
{
    char buf[16];
    DWORD i = sizeof(buf);

    if (!value) buf[--i] = '0';
    else while (value && i > 0)
    {
        buf[--i] = (char)('0' + (value % 10u));
        value /= 10u;
    }
    write_raw( buf + i, sizeof(buf) - i );
}

static void write_int( LONG value )
{
    if (value < 0)
    {
        write_raw( "-", 1 );
        write_uint( (DWORD)(-(LONGLONG)value) );
    }
    else
    {
        write_uint( (DWORD)value );
    }
}

static void write_hex32( DWORD v )
{
    static const char digits[] = "0123456789abcdef";
    char buf[10];
    int i;

    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 8; i++)
        buf[2 + i] = digits[(v >> ((7 - i) * 4)) & 0xf];
    write_raw( buf, 10 );
}

/* -------------------------------------------------------------------------
 * Wide-string path helpers and clip / log staging.
 * ------------------------------------------------------------------------- */

struct selftest_paths
{
    WCHAR exe_dir[MAX_PATH];
    WCHAR log_path[MAX_PATH];
    WCHAR wmv_path[MAX_PATH];
    WCHAR mpg_path[MAX_PATH];
    WCHAR wmv_url[MAX_PATH + 16];
    WCHAR tmp_buf[MAX_PATH];
    WCHAR cmd_buf[MAX_PATH + 64];
    WCHAR ret_buf[128];
    const char *wmv_origin;
    const char *mpg_origin;
};

static struct selftest_paths g_paths;

static void wstr_copy( WCHAR *dst, DWORD cap, const WCHAR *src )
{
    DWORD i = 0;
    if (!cap) return;
    while (src[i] && i + 1 < cap)
    {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
}

static void wstr_append( WCHAR *dst, DWORD cap, const WCHAR *suffix )
{
    DWORD len = (DWORD)lstrlenW( dst );
    DWORD i = 0;

    while (suffix[i] && len + i + 1 < cap)
    {
        dst[len + i] = suffix[i];
        i++;
    }
    if (len < cap) dst[len + i] = 0;
}

static void path_join( WCHAR *out, DWORD cap, const WCHAR *dir, const WCHAR *leaf )
{
    DWORD len;
    wstr_copy( out, cap, dir );
    len = (DWORD)lstrlenW( out );
    if (len > 0 && out[len - 1] != '\\' && out[len - 1] != '/')
        wstr_append( out, cap, L"\\" );
    wstr_append( out, cap, leaf );
}

static BOOL file_exists_w( const WCHAR *path )
{
    DWORD attr = GetFileAttributesW( path );
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static void make_file_url( WCHAR *url, DWORD cap, const WCHAR *dos_path )
{
    DWORD i = 0, pos = 0;
    static const WCHAR prefix[] = L"file:///";

    while (prefix[pos] && pos + 1 < cap)
    {
        url[pos] = prefix[pos];
        pos++;
    }
    while (dos_path[i] && pos + 1 < cap)
    {
        url[pos++] = (dos_path[i] == '\\') ? '/' : dos_path[i];
        i++;
    }
    url[pos] = 0;
}

static void init_exe_dir( void )
{
    DWORD len = GetModuleFileNameW( NULL, g_paths.exe_dir, MAX_PATH );
    if (!len || len >= MAX_PATH)
    {
        wstr_copy( g_paths.exe_dir, MAX_PATH, L"." );
        return;
    }
    while (len > 0 && g_paths.exe_dir[len - 1] != '\\' && g_paths.exe_dir[len - 1] != '/')
        len--;
    if (len > 0) g_paths.exe_dir[len - 1] = 0;
    else wstr_copy( g_paths.exe_dir, MAX_PATH, L"." );
}

static BOOL try_open_log( const WCHAR *candidate )
{
    HANDLE h = CreateFileW( candidate, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    g_log_file = h;
    wstr_copy( g_paths.log_path, MAX_PATH, candidate );
    return TRUE;
}

static void init_log_file( void )
{
    DWORD n;

    n = GetEnvironmentVariableW( L"MADEIRA_SELFTEST_LOG", g_paths.tmp_buf, MAX_PATH );
    if (n > 0 && n < MAX_PATH && try_open_log( g_paths.tmp_buf ))
        return;

    n = GetEnvironmentVariableW( L"USERPROFILE", g_paths.tmp_buf, MAX_PATH );
    if (n > 0 && n < MAX_PATH)
    {
        wstr_append( g_paths.tmp_buf, MAX_PATH, L"\\Documents\\video-selftest.log" );
        if (try_open_log( g_paths.tmp_buf )) return;
    }

    if (try_open_log( L"C:\\users\\madeira\\Documents\\video-selftest.log" ))
        return;

    path_join( g_paths.tmp_buf, MAX_PATH, g_paths.exe_dir, L"video-selftest.log" );
    if (try_open_log( g_paths.tmp_buf ))
        return;

    n = GetTempPathW( MAX_PATH, g_paths.tmp_buf );
    if (n > 0 && n < MAX_PATH)
    {
        path_join( g_paths.log_path, MAX_PATH, g_paths.tmp_buf, L"video-selftest.log" );
        if (try_open_log( g_paths.log_path )) return;
    }
    wstr_copy( g_paths.log_path, MAX_PATH, L"(stderr-only)" );
}

static BOOL write_embedded_clip( const WCHAR *dst, const unsigned char *bytes, DWORD size )
{
    HANDLE h = CreateFileW( dst, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
    DWORD written = 0;
    BOOL ok;

    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = WriteFile( h, bytes, size, &written, NULL ) && written == size;
    CloseHandle( h );
    return ok;
}

static BOOL stage_clip( const WCHAR *leaf, const unsigned char *bytes, DWORD size,
                        WCHAR *out_path, const char **out_origin )
{
    DWORD n;

    path_join( out_path, MAX_PATH, g_paths.exe_dir, leaf );
    if (file_exists_w( out_path ))
    {
        *out_origin = "beside-exe";
        return TRUE;
    }

    if (file_exists_w( leaf ))
    {
        n = GetFullPathNameW( leaf, MAX_PATH, out_path, NULL );
        if (n > 0 && n < MAX_PATH)
        {
            *out_origin = "cwd";
            return TRUE;
        }
    }

    n = GetTempPathW( MAX_PATH, g_paths.tmp_buf );
    if (n > 0 && n < MAX_PATH)
    {
        path_join( out_path, MAX_PATH, g_paths.tmp_buf, leaf );
        if (write_embedded_clip( out_path, bytes, size ))
        {
            *out_origin = "embedded-temp";
            return TRUE;
        }
    }

    n = GetEnvironmentVariableW( L"USERPROFILE", g_paths.tmp_buf, MAX_PATH );
    if (n > 0 && n < MAX_PATH)
    {
        wstr_append( g_paths.tmp_buf, MAX_PATH, L"\\Documents" );
        path_join( out_path, MAX_PATH, g_paths.tmp_buf, leaf );
        if (write_embedded_clip( out_path, bytes, size ))
        {
            *out_origin = "embedded-docs";
            return TRUE;
        }
    }
    return FALSE;
}

/* -------------------------------------------------------------------------
 * Pixel & audio verification helpers.
 * ------------------------------------------------------------------------- */

static DWORD hash_rgb32_and_check_nonblack( const BYTE *buf, DWORD width, DWORD height,
                                            LONG stride, DWORD *out_crc )
{
    DWORD crc = *out_crc;
    DWORD nonblack = 0;
    DWORD x, y;

    for (y = 0; y < height; y++)
    {
        const BYTE *row = (stride >= 0)
            ? (buf + y * (DWORD)stride)
            : (buf + (height - 1u - y) * (DWORD)(-stride));
        for (x = 0; x < width; x++)
        {
            BYTE b = row[x * 4u + 0u];
            BYTE g = row[x * 4u + 1u];
            BYTE r = row[x * 4u + 2u];
            if (r > 20u || g > 20u || b > 20u) nonblack++;
            /* Sample every 4th pixel for fast deterministic checksum across all rows. */
            if (((x + y) & 3u) == 0)
            {
                crc = (crc ^ b) * FNV1A_PRIME;
                crc = (crc ^ g) * FNV1A_PRIME;
                crc = (crc ^ r) * FNV1A_PRIME;
            }
        }
    }
    *out_crc = crc;
    return nonblack;
}

static DWORD hash_pcm_s16( const short *samples, DWORD sample_count, WORD channels,
                           int *io_prev_sign, DWORD *io_zero_crossings,
                           DWORD *io_peak, DWORD *io_crc )
{
    DWORD crc = *io_crc;
    DWORD peak = *io_peak;
    DWORD zc = *io_zero_crossings;
    int prev = *io_prev_sign;
    DWORD frames = (channels ? (sample_count / channels) : 0);
    DWORD i;
    const BYTE *raw = (const BYTE *)samples;
    DWORD raw_bytes = frames * channels * sizeof(short);

    for (i = 0; i < frames; i++)
    {
        int s = samples[i * channels];
        DWORD mag = (s < 0) ? (DWORD)(-s) : (DWORD)s;
        int sign = (s > 256) ? 1 : ((s < -256) ? -1 : 0);

        if (mag > peak) peak = mag;
        if (sign != 0)
        {
            if (prev != 0 && sign != prev) zc++;
            prev = sign;
        }
    }
    for (i = 0; i < raw_bytes; i += 4u)
        crc = (crc ^ raw[i]) * FNV1A_PRIME;

    *io_prev_sign = prev;
    *io_zero_crossings = zc;
    *io_peak = peak;
    *io_crc = crc;
    return frames;
}

static void pump_messages( void )
{
    MSG msg;
    while (PeekMessageW( &msg, NULL, 0, 0, PM_REMOVE ))
    {
        TranslateMessage( &msg );
        DispatchMessageW( &msg );
    }
}

/* -------------------------------------------------------------------------
 * Window class used by MF EVR (path 4) and MCI notify (path 6).
 * ------------------------------------------------------------------------- */

static volatile LONG g_mci_notified = 0;
static volatile WPARAM g_mci_notify_code = 0;
static ATOM g_wnd_atom = 0;

static LRESULT CALLBACK selftest_wndproc( HWND hwnd, UINT msg, WPARAM wp, LPARAM lp )
{
    if (msg == MM_MCINOTIFY)
    {
        g_mci_notify_code = wp;
        InterlockedExchange( &g_mci_notified, 1 );
        return 0;
    }
    return DefWindowProcW( hwnd, msg, wp, lp );
}

static HWND create_test_window( BOOL visible )
{
    if (!g_wnd_atom)
    {
        WNDCLASSW wc;
        memset( &wc, 0, sizeof(wc) );
        wc.lpfnWndProc = selftest_wndproc;
        wc.hInstance = GetModuleHandleW( NULL );
        wc.lpszClassName = L"MadeiraVideoSelftestWnd";
        g_wnd_atom = RegisterClassW( &wc );
    }
    return CreateWindowExW( 0, L"MadeiraVideoSelftestWnd", L"MadeiraVideoSelftest",
                            WS_POPUP | (visible ? WS_VISIBLE : 0),
                            32, 32, SELFTEST_CLIP_W, SELFTEST_CLIP_H,
                            NULL, NULL, GetModuleHandleW( NULL ), NULL );
}

/* =========================================================================
 * PATH 1: KiriKiri 2 WMV (IWMSyncReader compressed + WMV/WMA DMOs)
 * ========================================================================= */

struct static_media_buffer
{
    IMediaBuffer IMediaBuffer_iface;
    LONG refcount;
    BYTE *data;
    DWORD max_len;
    DWORD cur_len;
};

static inline struct static_media_buffer *impl_from_IMediaBuffer( IMediaBuffer *iface )
{
    return CONTAINING_RECORD( iface, struct static_media_buffer, IMediaBuffer_iface );
}

static HRESULT STDMETHODCALLTYPE mbuf_QueryInterface( IMediaBuffer *iface, REFIID riid, void **ppv )
{
    if (!ppv) return E_POINTER;
    if (IsEqualGUID( riid, &IID_IUnknown ) || IsEqualGUID( riid, &IID_IMediaBuffer ))
    {
        *ppv = iface;
        IMediaBuffer_AddRef( iface );
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE mbuf_AddRef( IMediaBuffer *iface )
{
    struct static_media_buffer *buf = impl_from_IMediaBuffer( iface );
    return (ULONG)InterlockedIncrement( &buf->refcount );
}

static ULONG STDMETHODCALLTYPE mbuf_Release( IMediaBuffer *iface )
{
    struct static_media_buffer *buf = impl_from_IMediaBuffer( iface );
    return (ULONG)InterlockedDecrement( &buf->refcount );
}

static HRESULT STDMETHODCALLTYPE mbuf_SetLength( IMediaBuffer *iface, DWORD len )
{
    struct static_media_buffer *buf = impl_from_IMediaBuffer( iface );
    if (len > buf->max_len) return E_INVALIDARG;
    buf->cur_len = len;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE mbuf_GetMaxLength( IMediaBuffer *iface, DWORD *max_len )
{
    struct static_media_buffer *buf = impl_from_IMediaBuffer( iface );
    if (!max_len) return E_POINTER;
    *max_len = buf->max_len;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE mbuf_GetBufferAndLength( IMediaBuffer *iface, BYTE **pp, DWORD *len )
{
    struct static_media_buffer *buf = impl_from_IMediaBuffer( iface );
    if (!pp && !len) return E_POINTER;
    if (pp) *pp = buf->data;
    if (len) *len = buf->cur_len;
    return S_OK;
}

static const IMediaBufferVtbl g_mbuf_vtbl =
{
    mbuf_QueryInterface,
    mbuf_AddRef,
    mbuf_Release,
    mbuf_SetLength,
    mbuf_GetMaxLength,
    mbuf_GetBufferAndLength,
};

static void mbuf_init( struct static_media_buffer *mb, BYTE *data, DWORD max_len, DWORD cur_len )
{
    mb->IMediaBuffer_iface.lpVtbl = &g_mbuf_vtbl;
    mb->refcount = 1;
    mb->data = data;
    mb->max_len = max_len;
    mb->cur_len = cur_len;
}

typedef HRESULT (WINAPI *pfn_WMCreateSyncReader)( IUnknown *unk_cert, DWORD rights, IWMSyncReader **out );

static BOOL run_path1_kirikiri2_wmv( void )
{
    HMODULE wmvcore = NULL;
    pfn_WMCreateSyncReader pWMCreateSyncReader;
    IWMSyncReader *reader = NULL;
    IWMProfile *profile = NULL;
    IMediaObject *v_dmo = NULL, *a_dmo = NULL;
    WM_MEDIA_TYPE *v_mt = NULL, *a_mt = NULL;
    WORD v_snum = 0, a_snum = 0;
    DWORD stream_count = 0, i;
    DWORD v_w = 0, v_h = 0;
    WORD a_ch = 0;
    DWORD a_rate = 0;
    VIDEOINFOHEADER vih_out;
    WAVEFORMATEX wfx_out;
    DMO_MEDIA_TYPE dmo_v_out, dmo_a_out;
    BYTE *v_buf = NULL, *a_buf = NULL;
    DWORD v_buf_cap = SELFTEST_CLIP_W * SELFTEST_CLIP_H * 4u;
    DWORD a_buf_cap = 65536u;
    struct static_media_buffer in_mb, out_v_mb, out_a_mb;
    DWORD v_pkts = 0, a_pkts = 0, v_frames = 0, v_nonblack_frames = 0;
    DWORD v_crc = FNV1A_INIT, a_crc = FNV1A_INIT;
    DWORD pcm_frames = 0, pcm_peak = 0, pcm_zc = 0, est_hz = 0;
    int pcm_prev_sign = 0;
    const char *step = "init";
    HRESULT hr = S_OK;
    BOOL ok = FALSE;

    wmvcore = LoadLibraryA( "wmvcore.dll" );
    if (!wmvcore) { step = "LoadLibrary(wmvcore.dll)"; hr = HRESULT_FROM_WIN32( GetLastError() ); goto out; }

    pWMCreateSyncReader = (pfn_WMCreateSyncReader)(void *)GetProcAddress( wmvcore, "WMCreateSyncReader" );
    if (!pWMCreateSyncReader) { step = "GetProcAddress(WMCreateSyncReader)"; hr = HRESULT_FROM_WIN32( GetLastError() ); goto out; }

    hr = pWMCreateSyncReader( NULL, 0, &reader );
    if (FAILED( hr ) || !reader) { step = "WMCreateSyncReader"; goto out; }

    hr = IWMSyncReader_Open( reader, g_paths.wmv_path );
    if (FAILED( hr )) { step = "IWMSyncReader::Open"; goto out; }

    hr = IWMSyncReader_QueryInterface( reader, &IID_IWMProfile, (void **)&profile );
    if (FAILED( hr ) || !profile) { step = "QueryInterface(IWMProfile)"; goto out; }

    hr = IWMProfile_GetStreamCount( profile, &stream_count );
    if (FAILED( hr ) || stream_count < 2) { step = "IWMProfile::GetStreamCount"; goto out; }

    for (i = 0; i < stream_count; i++)
    {
        IWMStreamConfig *cfg = NULL;
        IWMMediaProps *props = NULL;
        WM_MEDIA_TYPE *mt = NULL;
        DWORD cb = 0;
        WORD snum = 0;

        hr = IWMProfile_GetStream( profile, i, &cfg );
        if (FAILED( hr ) || !cfg) { step = "IWMProfile::GetStream"; goto out; }
        hr = IWMStreamConfig_GetStreamNumber( cfg, &snum );
        if (SUCCEEDED( hr ))
            hr = IWMStreamConfig_QueryInterface( cfg, &IID_IWMMediaProps, (void **)&props );
        if (SUCCEEDED( hr ) && props)
            hr = IWMMediaProps_GetMediaType( props, NULL, &cb );
        if (SUCCEEDED( hr ) && cb >= sizeof(WM_MEDIA_TYPE))
        {
            mt = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, cb );
            if (!mt) hr = E_OUTOFMEMORY;
            else hr = IWMMediaProps_GetMediaType( props, mt, &cb );
        }
        if (props) IWMMediaProps_Release( props );
        IWMStreamConfig_Release( cfg );
        if (FAILED( hr ) || !mt) { HeapFree( GetProcessHeap(), 0, mt ); step = "IWMMediaProps::GetMediaType"; goto out; }

        if (IsEqualGUID( &mt->majortype, &MEDIATYPE_Video ) && !v_mt)
        {
            v_mt = mt;
            v_snum = snum;
        }
        else if (IsEqualGUID( &mt->majortype, &MEDIATYPE_Audio ) && !a_mt)
        {
            a_mt = mt;
            a_snum = snum;
        }
        else
        {
            HeapFree( GetProcessHeap(), 0, mt );
        }
    }

    if (!v_mt || !a_mt || v_mt->cbFormat < sizeof(VIDEOINFOHEADER) || a_mt->cbFormat < sizeof(WAVEFORMATEX))
    {
        step = "missing ASF video/audio media type";
        hr = E_FAIL;
        goto out;
    }

    {
        const VIDEOINFOHEADER *vih = (const VIDEOINFOHEADER *)v_mt->pbFormat;
        const WAVEFORMATEX *wfx = (const WAVEFORMATEX *)a_mt->pbFormat;
        WORD snums[2] = { v_snum, a_snum };
        WMT_STREAM_SELECTION sels[2] = { WMT_ON, WMT_ON };
        BOOL comp_v = FALSE, comp_a = FALSE;

        v_w = (DWORD)vih->bmiHeader.biWidth;
        v_h = (vih->bmiHeader.biHeight < 0) ? (DWORD)(-vih->bmiHeader.biHeight) : (DWORD)vih->bmiHeader.biHeight;
        a_ch = wfx->nChannels;
        a_rate = wfx->nSamplesPerSec;

        hr = IWMSyncReader_SetStreamsSelected( reader, 2, snums, sels );
        if (FAILED( hr )) { step = "SetStreamsSelected"; goto out; }

        hr = IWMSyncReader_SetReadStreamSamples( reader, v_snum, TRUE );
        if (FAILED( hr )) { step = "SetReadStreamSamples(video)"; goto out; }

        hr = IWMSyncReader_SetReadStreamSamples( reader, a_snum, TRUE );
        if (FAILED( hr )) { step = "SetReadStreamSamples(audio)"; goto out; }

        if (FAILED( IWMSyncReader_GetReadStreamSamples( reader, v_snum, &comp_v ) ) ||
            FAILED( IWMSyncReader_GetReadStreamSamples( reader, a_snum, &comp_a ) ) ||
            !comp_v || !comp_a)
        {
            step = "GetReadStreamSamples!=TRUE";
            hr = E_FAIL;
            goto out;
        }
    }

    hr = CoCreateInstance( &CLSID_CWMVDecMediaObject, NULL, CLSCTX_INPROC_SERVER,
                           &IID_IMediaObject, (void **)&v_dmo );
    if (FAILED( hr ) || !v_dmo) { step = "CoCreateInstance(CWMVDecMediaObject)"; goto out; }

    hr = CoCreateInstance( &CLSID_CWMADecMediaObject, NULL, CLSCTX_INPROC_SERVER,
                           &IID_IMediaObject, (void **)&a_dmo );
    if (FAILED( hr ) || !a_dmo) { step = "CoCreateInstance(CWMADecMediaObject)"; goto out; }

    hr = IMediaObject_SetInputType( v_dmo, 0, (const DMO_MEDIA_TYPE *)v_mt, 0 );
    if (FAILED( hr )) { step = "WMV DMO SetInputType"; goto out; }

    memset( &vih_out, 0, sizeof(vih_out) );
    vih_out.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    vih_out.bmiHeader.biWidth = (LONG)v_w;
    vih_out.bmiHeader.biHeight = (LONG)v_h; /* bottom-up RGB32 */
    vih_out.bmiHeader.biPlanes = 1;
    vih_out.bmiHeader.biBitCount = 32;
    vih_out.bmiHeader.biCompression = BI_RGB;
    vih_out.bmiHeader.biSizeImage = v_w * v_h * 4u;

    memset( &dmo_v_out, 0, sizeof(dmo_v_out) );
    dmo_v_out.majortype = MEDIATYPE_Video;
    dmo_v_out.subtype = MEDIASUBTYPE_RGB32;
    dmo_v_out.bFixedSizeSamples = TRUE;
    dmo_v_out.lSampleSize = vih_out.bmiHeader.biSizeImage;
    dmo_v_out.formattype = FORMAT_VideoInfo;
    dmo_v_out.cbFormat = sizeof(vih_out);
    dmo_v_out.pbFormat = (BYTE *)&vih_out;

    hr = IMediaObject_SetOutputType( v_dmo, 0, &dmo_v_out, 0 );
    if (FAILED( hr )) { step = "WMV DMO SetOutputType(RGB32)"; goto out; }

    hr = IMediaObject_SetInputType( a_dmo, 0, (const DMO_MEDIA_TYPE *)a_mt, 0 );
    if (FAILED( hr )) { step = "WMA DMO SetInputType"; goto out; }

    memset( &wfx_out, 0, sizeof(wfx_out) );
    wfx_out.wFormatTag = WAVE_FORMAT_PCM;
    wfx_out.nChannels = a_ch;
    wfx_out.nSamplesPerSec = a_rate;
    wfx_out.wBitsPerSample = 16;
    wfx_out.nBlockAlign = (WORD)(a_ch * 2u);
    wfx_out.nAvgBytesPerSec = a_rate * (DWORD)wfx_out.nBlockAlign;

    memset( &dmo_a_out, 0, sizeof(dmo_a_out) );
    dmo_a_out.majortype = MEDIATYPE_Audio;
    dmo_a_out.subtype = MEDIASUBTYPE_PCM;
    dmo_a_out.bFixedSizeSamples = TRUE;
    dmo_a_out.lSampleSize = wfx_out.nBlockAlign;
    dmo_a_out.formattype = FORMAT_WaveFormatEx;
    dmo_a_out.cbFormat = sizeof(wfx_out);
    dmo_a_out.pbFormat = (BYTE *)&wfx_out;

    hr = IMediaObject_SetOutputType( a_dmo, 0, &dmo_a_out, 0 );
    if (FAILED( hr )) { step = "WMA DMO SetOutputType(PCM)"; goto out; }

    v_buf_cap = v_w * v_h * 4u;
    v_buf = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, v_buf_cap );
    a_buf = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, a_buf_cap );
    if (!v_buf || !a_buf) { step = "HeapAlloc"; hr = E_OUTOFMEMORY; goto out; }

    mbuf_init( &out_v_mb, v_buf, v_buf_cap, 0 );
    mbuf_init( &out_a_mb, a_buf, a_buf_cap, 0 );

    for (;;)
    {
        INSSBuffer *nss = NULL;
        QWORD cns_time = 0, cns_dur = 0;
        DWORD flags = 0, out_num = 0, pkt_len = 0, dmo_flags = 0, status = 0;
        WORD snum = 0;
        BYTE *pkt_ptr = NULL;

        hr = IWMSyncReader_GetNextSample( reader, 0, &nss, &cns_time, &cns_dur, &flags, &out_num, &snum );
        if (hr == NS_E_NO_MORE_SAMPLES)
        {
            hr = S_OK;
            break;
        }
        if (FAILED( hr ) || !nss) { step = "GetNextSample"; goto out; }

        hr = INSSBuffer_GetBufferAndLength( nss, &pkt_ptr, &pkt_len );
        if (FAILED( hr ) || !pkt_ptr)
        {
            INSSBuffer_Release( nss );
            step = "INSSBuffer::GetBufferAndLength";
            goto out;
        }

        mbuf_init( &in_mb, pkt_ptr, pkt_len, pkt_len );
        dmo_flags = DMO_INPUT_DATA_BUFFERF_TIME | DMO_INPUT_DATA_BUFFERF_TIMELENGTH;
        if (flags & WM_SF_CLEANPOINT) dmo_flags |= DMO_INPUT_DATA_BUFFERF_SYNCPOINT;

        if (snum == v_snum)
        {
            v_pkts++;
            hr = IMediaObject_ProcessInput( v_dmo, 0, &in_mb.IMediaBuffer_iface,
                                            dmo_flags, (REFERENCE_TIME)cns_time, (REFERENCE_TIME)cns_dur );
            INSSBuffer_Release( nss );
            if (FAILED( hr )) { step = "WMV ProcessInput"; goto out; }

            for (;;)
            {
                DMO_OUTPUT_DATA_BUFFER odb;
                memset( &odb, 0, sizeof(odb) );
                out_v_mb.cur_len = 0;
                odb.pBuffer = &out_v_mb.IMediaBuffer_iface;
                hr = IMediaObject_ProcessOutput( v_dmo, 0, 1, &odb, &status );
                if (FAILED( hr )) { step = "WMV ProcessOutput"; goto out; }
                if (out_v_mb.cur_len >= v_buf_cap)
                {
                    DWORD nb = hash_rgb32_and_check_nonblack( v_buf, v_w, v_h, (LONG)(v_w * 4u), &v_crc );
                    v_frames++;
                    if (nb > (v_w * v_h) / 10u) v_nonblack_frames++;
                }
                if (hr == S_FALSE || !(odb.dwStatus & DMO_OUTPUT_DATA_BUFFERF_INCOMPLETE))
                    break;
            }
        }
        else if (snum == a_snum)
        {
            a_pkts++;
            hr = IMediaObject_ProcessInput( a_dmo, 0, &in_mb.IMediaBuffer_iface,
                                            dmo_flags, (REFERENCE_TIME)cns_time, (REFERENCE_TIME)cns_dur );
            INSSBuffer_Release( nss );
            if (FAILED( hr )) { step = "WMA ProcessInput"; goto out; }

            for (;;)
            {
                DMO_OUTPUT_DATA_BUFFER odb;
                memset( &odb, 0, sizeof(odb) );
                out_a_mb.cur_len = 0;
                odb.pBuffer = &out_a_mb.IMediaBuffer_iface;
                hr = IMediaObject_ProcessOutput( a_dmo, 0, 1, &odb, &status );
                if (FAILED( hr )) { step = "WMA ProcessOutput"; goto out; }
                if (out_a_mb.cur_len > 0)
                {
                    pcm_frames += hash_pcm_s16( (const short *)a_buf, out_a_mb.cur_len / 2u, a_ch,
                                                &pcm_prev_sign, &pcm_zc, &pcm_peak, &a_crc );
                }
                if (hr == S_FALSE || (out_a_mb.cur_len == 0 && !(odb.dwStatus & DMO_OUTPUT_DATA_BUFFERF_INCOMPLETE)))
                    break;
            }
        }
        else
        {
            INSSBuffer_Release( nss );
        }
    }

    /* Drain any buffered decoder frames after discontinuity. */
    if (SUCCEEDED( IMediaObject_Discontinuity( v_dmo, 0 ) ))
    {
        DMO_OUTPUT_DATA_BUFFER odb;
        DWORD status = 0;
        memset( &odb, 0, sizeof(odb) );
        out_v_mb.cur_len = 0;
        odb.pBuffer = &out_v_mb.IMediaBuffer_iface;
        if (IMediaObject_ProcessOutput( v_dmo, 0, 1, &odb, &status ) == S_OK && out_v_mb.cur_len >= v_buf_cap)
        {
            DWORD nb = hash_rgb32_and_check_nonblack( v_buf, v_w, v_h, (LONG)(v_w * 4u), &v_crc );
            v_frames++;
            if (nb > (v_w * v_h) / 10u) v_nonblack_frames++;
        }
    }
    if (SUCCEEDED( IMediaObject_Discontinuity( a_dmo, 0 ) ))
    {
        for (;;)
        {
            DMO_OUTPUT_DATA_BUFFER odb;
            DWORD status = 0;
            memset( &odb, 0, sizeof(odb) );
            out_a_mb.cur_len = 0;
            odb.pBuffer = &out_a_mb.IMediaBuffer_iface;
            if (IMediaObject_ProcessOutput( a_dmo, 0, 1, &odb, &status ) != S_OK || !out_a_mb.cur_len)
                break;
            pcm_frames += hash_pcm_s16( (const short *)a_buf, out_a_mb.cur_len / 2u, a_ch,
                                        &pcm_prev_sign, &pcm_zc, &pcm_peak, &a_crc );
        }
    }

    if (pcm_frames > 0)
        est_hz = u64_div_u32( (ULONGLONG)pcm_zc * (ULONGLONG)a_rate, pcm_frames * 2u );

    if (v_w != SELFTEST_CLIP_W || v_h != SELFTEST_CLIP_H)
    {
        step = "unexpected ASF video dimensions";
        hr = E_FAIL;
        goto out;
    }
    if (v_frames < SELFTEST_CLIP_FRAMES - 5u || v_nonblack_frames != v_frames)
    {
        step = "decoded RGB32 frame count or non-black check";
        hr = E_FAIL;
        goto out;
    }
    if (pcm_frames < a_rate || pcm_peak < 4000u || est_hz < 380u || est_hz > 500u)
    {
        step = "decoded WMA PCM count/level/frequency check";
        hr = E_FAIL;
        goto out;
    }
    ok = TRUE;

out:
    if (reader) IWMSyncReader_Close( reader );
    if (a_dmo) IMediaObject_Release( a_dmo );
    if (v_dmo) IMediaObject_Release( v_dmo );
    if (profile) IWMProfile_Release( profile );
    if (reader) IWMSyncReader_Release( reader );
    if (v_mt) HeapFree( GetProcessHeap(), 0, v_mt );
    if (a_mt) HeapFree( GetProcessHeap(), 0, a_mt );
    if (v_buf) HeapFree( GetProcessHeap(), 0, v_buf );
    if (a_buf) HeapFree( GetProcessHeap(), 0, a_buf );
    if (wmvcore) FreeLibrary( wmvcore );

    if (ok)
    {
        write_str( "[1/6] PASS kirikiri2-wmv-dmo: pkts=" );
        write_uint( v_pkts );
        write_str( "+" );
        write_uint( a_pkts );
        write_str( " frames=" );
        write_uint( v_frames );
        write_str( " size=" );
        write_uint( v_w );
        write_str( "x" );
        write_uint( v_h );
        write_str( " rgb_crc=" );
        write_hex32( v_crc );
        write_str( " pcm_frames=" );
        write_uint( pcm_frames );
        write_str( " peak=" );
        write_uint( pcm_peak );
        write_str( " freq=" );
        write_uint( est_hz );
        write_str( "Hz pcm_crc=" );
        write_hex32( a_crc );
        write_str( "\n" );
    }
    else
    {
        write_str( "[1/6] FAIL kirikiri2-wmv-dmo: step=" );
        write_str( step );
        write_str( " hr=" );
        write_hex32( (DWORD)hr );
        write_str( " frames=" );
        write_uint( v_frames );
        write_str( " nonblack=" );
        write_uint( v_nonblack_frames );
        write_str( " pcm_frames=" );
        write_uint( pcm_frames );
        write_str( " peak=" );
        write_uint( pcm_peak );
        write_str( " freq=" );
        write_uint( est_hz );
        write_str( "Hz\n" );
    }
    flush_log();
    return ok;
}

/* =========================================================================
 * PATH 2: Custom DirectShow sink filters & hand-built KiriKiri MPEG-1 graph
 * ========================================================================= */

struct sink_filter
{
    IBaseFilter IBaseFilter_iface;
    IPin IPin_iface;
    IMemInputPin IMemInputPin_iface;
    LONG refcount;
    CRITICAL_SECTION cs;
    FILTER_STATE state;
    IFilterGraph *graph;
    IReferenceClock *clock;
    IUnknown *seek_unk;
    IPin *peer;
    AM_MEDIA_TYPE conn_mt;
    BOOL is_video;
    BOOL eos;
    BOOL notified_eos;
    /* Stats collected across Receive calls: */
    DWORD frames;
    DWORD nonblack_frames;
    DWORD crc;
    LONG conn_w;
    LONG conn_h;
    DWORD pcm_frames;
    DWORD pcm_peak;
    DWORD pcm_zc;
    int pcm_prev_sign;
    WORD pcm_channels;
    DWORD pcm_rate;
};

struct sink_enum_pins
{
    IEnumPins IEnumPins_iface;
    LONG refcount;
    struct sink_filter *owner;
    ULONG index;
};

static void free_mt_format( AM_MEDIA_TYPE *mt )
{
    if (mt->pbFormat)
    {
        CoTaskMemFree( mt->pbFormat );
        mt->pbFormat = NULL;
    }
    mt->cbFormat = 0;
    if (mt->pUnk)
    {
        IUnknown_Release( mt->pUnk );
        mt->pUnk = NULL;
    }
}

static void delete_media_type( AM_MEDIA_TYPE *mt )
{
    if (!mt) return;
    free_mt_format( mt );
    CoTaskMemFree( mt );
}

static HRESULT copy_media_type( AM_MEDIA_TYPE *dst, const AM_MEDIA_TYPE *src )
{
    memset( dst, 0, sizeof(*dst) );
    if (!src) return E_POINTER;
    *dst = *src;
    dst->pbFormat = NULL;
    dst->pUnk = NULL;
    if (src->cbFormat && src->pbFormat)
    {
        dst->pbFormat = CoTaskMemAlloc( src->cbFormat );
        if (!dst->pbFormat) return E_OUTOFMEMORY;
        memcpy( dst->pbFormat, src->pbFormat, src->cbFormat );
    }
    if (src->pUnk)
    {
        dst->pUnk = src->pUnk;
        IUnknown_AddRef( dst->pUnk );
    }
    return S_OK;
}

static inline struct sink_filter *sink_from_IBaseFilter( IBaseFilter *iface )
{
    return CONTAINING_RECORD( iface, struct sink_filter, IBaseFilter_iface );
}

static inline struct sink_filter *sink_from_IPin( IPin *iface )
{
    return CONTAINING_RECORD( iface, struct sink_filter, IPin_iface );
}

static inline struct sink_filter *sink_from_IMemInputPin( IMemInputPin *iface )
{
    return CONTAINING_RECORD( iface, struct sink_filter, IMemInputPin_iface );
}

static inline struct sink_enum_pins *enum_from_IEnumPins( IEnumPins *iface )
{
    return CONTAINING_RECORD( iface, struct sink_enum_pins, IEnumPins_iface );
}

static void sink_notify_ec_complete_locked( struct sink_filter *sink )
{
    IMediaEventSink *mes = NULL;

    if (sink->notified_eos || !sink->graph) return;
    sink->notified_eos = TRUE;
    if (SUCCEEDED( IFilterGraph_QueryInterface( sink->graph, &IID_IMediaEventSink, (void **)&mes ) ) && mes)
    {
        IMediaEventSink_Notify( mes, EC_COMPLETE, S_OK, (LONG_PTR)&sink->IBaseFilter_iface );
        IMediaEventSink_Release( mes );
    }
}

static HRESULT sink_check_media_type( struct sink_filter *sink, const AM_MEDIA_TYPE *pmt )
{
    if (!pmt) return E_POINTER;
    if (sink->is_video)
    {
        const VIDEOINFOHEADER *vih;
        /* KiriKiri buffer renderer rule: ONLY uncompressed RGB32 bottom-up (biHeight > 0). */
        if (!IsEqualGUID( &pmt->majortype, &MEDIATYPE_Video )) return S_FALSE;
        if (!IsEqualGUID( &pmt->subtype, &MEDIASUBTYPE_RGB32 )) return S_FALSE;
        if (!IsEqualGUID( &pmt->formattype, &FORMAT_VideoInfo )) return S_FALSE;
        if (!pmt->pbFormat || pmt->cbFormat < sizeof(VIDEOINFOHEADER)) return S_FALSE;
        vih = (const VIDEOINFOHEADER *)pmt->pbFormat;
        if (vih->bmiHeader.biCompression != BI_RGB) return S_FALSE;
        if (vih->bmiHeader.biBitCount != 32) return S_FALSE;
        if (vih->bmiHeader.biWidth <= 0 || vih->bmiHeader.biHeight <= 0) return S_FALSE;
        return S_OK;
    }
    else
    {
        const WAVEFORMATEX *wfx;
        if (!IsEqualGUID( &pmt->majortype, &MEDIATYPE_Audio )) return S_FALSE;
        if (!IsEqualGUID( &pmt->subtype, &MEDIASUBTYPE_PCM )) return S_FALSE;
        if (!IsEqualGUID( &pmt->formattype, &FORMAT_WaveFormatEx )) return S_FALSE;
        if (!pmt->pbFormat || pmt->cbFormat < sizeof(WAVEFORMATEX)) return S_FALSE;
        wfx = (const WAVEFORMATEX *)pmt->pbFormat;
        if (wfx->wFormatTag != WAVE_FORMAT_PCM || wfx->wBitsPerSample != 16 || wfx->nChannels == 0)
            return S_FALSE;
        return S_OK;
    }
}

/* --- IEnumPins --- */

static HRESULT STDMETHODCALLTYPE ep_QueryInterface( IEnumPins *iface, REFIID riid, void **ppv )
{
    if (!ppv) return E_POINTER;
    if (IsEqualGUID( riid, &IID_IUnknown ) || IsEqualGUID( riid, &IID_IEnumPins ))
    {
        *ppv = iface;
        IEnumPins_AddRef( iface );
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE ep_AddRef( IEnumPins *iface )
{
    struct sink_enum_pins *ep = enum_from_IEnumPins( iface );
    return (ULONG)InterlockedIncrement( &ep->refcount );
}

static ULONG STDMETHODCALLTYPE ep_Release( IEnumPins *iface )
{
    struct sink_enum_pins *ep = enum_from_IEnumPins( iface );
    LONG ref = InterlockedDecrement( &ep->refcount );
    if (!ref)
    {
        IBaseFilter_Release( &ep->owner->IBaseFilter_iface );
        HeapFree( GetProcessHeap(), 0, ep );
    }
    return (ULONG)ref;
}

static HRESULT STDMETHODCALLTYPE ep_Next( IEnumPins *iface, ULONG cPins, IPin **ppPins, ULONG *pcFetched )
{
    struct sink_enum_pins *ep = enum_from_IEnumPins( iface );
    ULONG fetched = 0;

    if (!ppPins) return E_POINTER;
    if (cPins > 1 && !pcFetched) return E_INVALIDARG;
    if (cPins > 0 && ep->index == 0)
    {
        ppPins[0] = &ep->owner->IPin_iface;
        IPin_AddRef( ppPins[0] );
        ep->index = 1;
        fetched = 1;
    }
    if (pcFetched) *pcFetched = fetched;
    return (fetched == cPins) ? S_OK : S_FALSE;
}

static HRESULT STDMETHODCALLTYPE ep_Skip( IEnumPins *iface, ULONG cPins )
{
    struct sink_enum_pins *ep = enum_from_IEnumPins( iface );
    ep->index += cPins;
    return (ep->index <= 1) ? S_OK : S_FALSE;
}

static HRESULT STDMETHODCALLTYPE ep_Reset( IEnumPins *iface )
{
    struct sink_enum_pins *ep = enum_from_IEnumPins( iface );
    ep->index = 0;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE ep_Clone( IEnumPins *iface, IEnumPins **ppEnum )
{
    struct sink_enum_pins *ep = enum_from_IEnumPins( iface );
    struct sink_enum_pins *copy;

    if (!ppEnum) return E_POINTER;
    copy = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*copy) );
    if (!copy) return E_OUTOFMEMORY;
    copy->IEnumPins_iface = ep->IEnumPins_iface;
    copy->refcount = 1;
    copy->owner = ep->owner;
    copy->index = ep->index;
    IBaseFilter_AddRef( &copy->owner->IBaseFilter_iface );
    *ppEnum = &copy->IEnumPins_iface;
    return S_OK;
}

static const IEnumPinsVtbl g_ep_vtbl =
{
    ep_QueryInterface,
    ep_AddRef,
    ep_Release,
    ep_Next,
    ep_Skip,
    ep_Reset,
    ep_Clone,
};

/* --- IBaseFilter --- */

static HRESULT STDMETHODCALLTYPE sf_QueryInterface( IBaseFilter *iface, REFIID riid, void **ppv )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    if (!ppv) return E_POINTER;
    if (IsEqualGUID( riid, &IID_IUnknown ) ||
        IsEqualGUID( riid, &IID_IPersist ) ||
        IsEqualGUID( riid, &IID_IMediaFilter ) ||
        IsEqualGUID( riid, &IID_IBaseFilter ))
    {
        *ppv = iface;
        IBaseFilter_AddRef( iface );
        return S_OK;
    }
    if (sink->seek_unk &&
        (IsEqualGUID( riid, &IID_IMediaSeeking ) || IsEqualGUID( riid, &IID_IMediaPosition )))
    {
        return IUnknown_QueryInterface( sink->seek_unk, riid, ppv );
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE sf_AddRef( IBaseFilter *iface )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    return (ULONG)InterlockedIncrement( &sink->refcount );
}

static ULONG STDMETHODCALLTYPE sf_Release( IBaseFilter *iface )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    LONG ref = InterlockedDecrement( &sink->refcount );
    if (!ref)
    {
        if (sink->seek_unk) IUnknown_Release( sink->seek_unk );
        if (sink->clock) IReferenceClock_Release( sink->clock );
        if (sink->peer) IPin_Release( sink->peer );
        free_mt_format( &sink->conn_mt );
        DeleteCriticalSection( &sink->cs );
        HeapFree( GetProcessHeap(), 0, sink );
    }
    return (ULONG)ref;
}

static HRESULT STDMETHODCALLTYPE sf_GetClassID( IBaseFilter *iface, CLSID *clsid )
{
    if (!clsid) return E_POINTER;
    *clsid = k_guid_null;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sf_Stop( IBaseFilter *iface )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    EnterCriticalSection( &sink->cs );
    sink->state = State_Stopped;
    sink->eos = FALSE;
    sink->notified_eos = FALSE;
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sf_Pause( IBaseFilter *iface )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    EnterCriticalSection( &sink->cs );
    if (sink->state == State_Stopped)
    {
        sink->eos = FALSE;
        sink->notified_eos = FALSE;
    }
    sink->state = State_Paused;
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sf_Run( IBaseFilter *iface, REFERENCE_TIME tStart )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    EnterCriticalSection( &sink->cs );
    sink->state = State_Running;
    sink->notified_eos = FALSE;
    if (sink->eos || !sink->peer)
        sink_notify_ec_complete_locked( sink );
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sf_GetState( IBaseFilter *iface, DWORD timeout, FILTER_STATE *state )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    if (!state) return E_POINTER;
    EnterCriticalSection( &sink->cs );
    *state = sink->state;
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sf_SetSyncSource( IBaseFilter *iface, IReferenceClock *clock )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    EnterCriticalSection( &sink->cs );
    if (clock) IReferenceClock_AddRef( clock );
    if (sink->clock) IReferenceClock_Release( sink->clock );
    sink->clock = clock;
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sf_GetSyncSource( IBaseFilter *iface, IReferenceClock **clock )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    if (!clock) return E_POINTER;
    EnterCriticalSection( &sink->cs );
    *clock = sink->clock;
    if (*clock) IReferenceClock_AddRef( *clock );
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sf_EnumPins( IBaseFilter *iface, IEnumPins **ppEnum )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    struct sink_enum_pins *ep;

    if (!ppEnum) return E_POINTER;
    ep = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ep) );
    if (!ep) return E_OUTOFMEMORY;
    ep->IEnumPins_iface.lpVtbl = &g_ep_vtbl;
    ep->refcount = 1;
    ep->owner = sink;
    ep->index = 0;
    IBaseFilter_AddRef( iface );
    *ppEnum = &ep->IEnumPins_iface;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sf_FindPin( IBaseFilter *iface, LPCWSTR id, IPin **ppPin )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    if (!ppPin) return E_POINTER;
    if (id && lstrcmpW( id, L"In" ) == 0)
    {
        *ppPin = &sink->IPin_iface;
        IPin_AddRef( *ppPin );
        return S_OK;
    }
    *ppPin = NULL;
    return VFW_E_NOT_FOUND;
}

static HRESULT STDMETHODCALLTYPE sf_QueryFilterInfo( IBaseFilter *iface, FILTER_INFO *info )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    if (!info) return E_POINTER;
    memset( info, 0, sizeof(*info) );
    wstr_copy( info->achName, MAX_FILTER_NAME, sink->is_video ? L"SelftestRGB32Sink" : L"SelftestAudioSink" );
    info->pGraph = sink->graph;
    if (info->pGraph) IFilterGraph_AddRef( info->pGraph );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sf_JoinFilterGraph( IBaseFilter *iface, IFilterGraph *graph, LPCWSTR name )
{
    struct sink_filter *sink = sink_from_IBaseFilter( iface );
    EnterCriticalSection( &sink->cs );
    sink->graph = graph; /* weak reference per DirectShow contract */
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sf_QueryVendorInfo( IBaseFilter *iface, LPWSTR *vendor )
{
    return E_NOTIMPL;
}

static const IBaseFilterVtbl g_sf_vtbl =
{
    sf_QueryInterface,
    sf_AddRef,
    sf_Release,
    sf_GetClassID,
    sf_Stop,
    sf_Pause,
    sf_Run,
    sf_GetState,
    sf_SetSyncSource,
    sf_GetSyncSource,
    sf_EnumPins,
    sf_FindPin,
    sf_QueryFilterInfo,
    sf_JoinFilterGraph,
    sf_QueryVendorInfo,
};

/* --- IPin & IMemInputPin --- */

static HRESULT STDMETHODCALLTYPE sp_QueryInterface( IPin *iface, REFIID riid, void **ppv )
{
    struct sink_filter *sink = sink_from_IPin( iface );
    if (!ppv) return E_POINTER;
    if (IsEqualGUID( riid, &IID_IUnknown ) || IsEqualGUID( riid, &IID_IPin ))
    {
        *ppv = iface;
        IPin_AddRef( iface );
        return S_OK;
    }
    if (IsEqualGUID( riid, &IID_IMemInputPin ))
    {
        *ppv = &sink->IMemInputPin_iface;
        IMemInputPin_AddRef( &sink->IMemInputPin_iface );
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE sp_AddRef( IPin *iface )
{
    return IBaseFilter_AddRef( &sink_from_IPin( iface )->IBaseFilter_iface );
}

static ULONG STDMETHODCALLTYPE sp_Release( IPin *iface )
{
    return IBaseFilter_Release( &sink_from_IPin( iface )->IBaseFilter_iface );
}

static HRESULT STDMETHODCALLTYPE sp_Connect( IPin *iface, IPin *recv_pin, const AM_MEDIA_TYPE *pmt )
{
    return E_UNEXPECTED; /* input pin */
}

static HRESULT STDMETHODCALLTYPE sp_ReceiveConnection( IPin *iface, IPin *connector, const AM_MEDIA_TYPE *pmt )
{
    struct sink_filter *sink = sink_from_IPin( iface );
    HRESULT hr;

    if (!connector || !pmt) return E_POINTER;
    if (sink_check_media_type( sink, pmt ) != S_OK)
        return VFW_E_TYPE_NOT_ACCEPTED;

    EnterCriticalSection( &sink->cs );
    if (sink->peer)
    {
        LeaveCriticalSection( &sink->cs );
        return VFW_E_ALREADY_CONNECTED;
    }
    hr = copy_media_type( &sink->conn_mt, pmt );
    if (SUCCEEDED( hr ))
    {
        sink->peer = connector;
        IPin_AddRef( connector );
        if (sink->is_video)
        {
            const VIDEOINFOHEADER *vih = (const VIDEOINFOHEADER *)pmt->pbFormat;
            sink->conn_w = vih->bmiHeader.biWidth;
            sink->conn_h = vih->bmiHeader.biHeight;
        }
        else
        {
            const WAVEFORMATEX *wfx = (const WAVEFORMATEX *)pmt->pbFormat;
            sink->pcm_channels = wfx->nChannels;
            sink->pcm_rate = wfx->nSamplesPerSec;
        }
    }
    LeaveCriticalSection( &sink->cs );
    return hr;
}

static HRESULT STDMETHODCALLTYPE sp_Disconnect( IPin *iface )
{
    struct sink_filter *sink = sink_from_IPin( iface );
    EnterCriticalSection( &sink->cs );
    if (!sink->peer)
    {
        LeaveCriticalSection( &sink->cs );
        return S_FALSE;
    }
    IPin_Release( sink->peer );
    sink->peer = NULL;
    free_mt_format( &sink->conn_mt );
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sp_ConnectedTo( IPin *iface, IPin **ppPin )
{
    struct sink_filter *sink = sink_from_IPin( iface );
    if (!ppPin) return E_POINTER;
    EnterCriticalSection( &sink->cs );
    *ppPin = sink->peer;
    if (*ppPin) IPin_AddRef( *ppPin );
    LeaveCriticalSection( &sink->cs );
    return *ppPin ? S_OK : VFW_E_NOT_CONNECTED;
}

static HRESULT STDMETHODCALLTYPE sp_ConnectionMediaType( IPin *iface, AM_MEDIA_TYPE *pmt )
{
    struct sink_filter *sink = sink_from_IPin( iface );
    HRESULT hr;
    if (!pmt) return E_POINTER;
    EnterCriticalSection( &sink->cs );
    if (!sink->peer) hr = VFW_E_NOT_CONNECTED;
    else hr = copy_media_type( pmt, &sink->conn_mt );
    LeaveCriticalSection( &sink->cs );
    return hr;
}

static HRESULT STDMETHODCALLTYPE sp_QueryPinInfo( IPin *iface, PIN_INFO *info )
{
    struct sink_filter *sink = sink_from_IPin( iface );
    if (!info) return E_POINTER;
    info->pFilter = &sink->IBaseFilter_iface;
    IBaseFilter_AddRef( info->pFilter );
    info->dir = PINDIR_INPUT;
    wstr_copy( info->achName, MAX_PIN_NAME, L"In" );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sp_QueryDirection( IPin *iface, PIN_DIRECTION *dir )
{
    if (!dir) return E_POINTER;
    *dir = PINDIR_INPUT;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sp_QueryId( IPin *iface, LPWSTR *id )
{
    if (!id) return E_POINTER;
    *id = CoTaskMemAlloc( 3 * sizeof(WCHAR) );
    if (!*id) return E_OUTOFMEMORY;
    wstr_copy( *id, 3, L"In" );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sp_QueryAccept( IPin *iface, const AM_MEDIA_TYPE *pmt )
{
    return sink_check_media_type( sink_from_IPin( iface ), pmt );
}

static HRESULT STDMETHODCALLTYPE sp_EnumMediaTypes( IPin *iface, IEnumMediaTypes **ppEnum )
{
    if (!ppEnum) return E_POINTER;
    *ppEnum = NULL;
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE sp_QueryInternalConnections( IPin *iface, IPin **apPin, ULONG *nPin )
{
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE sp_EndOfStream( IPin *iface )
{
    struct sink_filter *sink = sink_from_IPin( iface );
    EnterCriticalSection( &sink->cs );
    sink->eos = TRUE;
    if (sink->state == State_Running)
        sink_notify_ec_complete_locked( sink );
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sp_BeginFlush( IPin *iface )
{
    struct sink_filter *sink = sink_from_IPin( iface );
    EnterCriticalSection( &sink->cs );
    sink->eos = FALSE;
    sink->notified_eos = FALSE;
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sp_EndFlush( IPin *iface )
{
    struct sink_filter *sink = sink_from_IPin( iface );
    EnterCriticalSection( &sink->cs );
    sink->eos = FALSE;
    sink->notified_eos = FALSE;
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sp_NewSegment( IPin *iface, REFERENCE_TIME tStart, REFERENCE_TIME tStop, double rate )
{
    return S_OK;
}

static const IPinVtbl g_sp_vtbl =
{
    sp_QueryInterface,
    sp_AddRef,
    sp_Release,
    sp_Connect,
    sp_ReceiveConnection,
    sp_Disconnect,
    sp_ConnectedTo,
    sp_ConnectionMediaType,
    sp_QueryPinInfo,
    sp_QueryDirection,
    sp_QueryId,
    sp_QueryAccept,
    sp_EnumMediaTypes,
    sp_QueryInternalConnections,
    sp_EndOfStream,
    sp_BeginFlush,
    sp_EndFlush,
    sp_NewSegment,
};

static HRESULT STDMETHODCALLTYPE mip_QueryInterface( IMemInputPin *iface, REFIID riid, void **ppv )
{
    return sp_QueryInterface( &sink_from_IMemInputPin( iface )->IPin_iface, riid, ppv );
}

static ULONG STDMETHODCALLTYPE mip_AddRef( IMemInputPin *iface )
{
    return sp_AddRef( &sink_from_IMemInputPin( iface )->IPin_iface );
}

static ULONG STDMETHODCALLTYPE mip_Release( IMemInputPin *iface )
{
    return sp_Release( &sink_from_IMemInputPin( iface )->IPin_iface );
}

static HRESULT STDMETHODCALLTYPE mip_GetAllocator( IMemInputPin *iface, IMemAllocator **ppAlloc )
{
    if (!ppAlloc) return E_POINTER;
    *ppAlloc = NULL;
    return VFW_E_NO_ALLOCATOR;
}

static HRESULT STDMETHODCALLTYPE mip_NotifyAllocator( IMemInputPin *iface, IMemAllocator *alloc, WINBOOL ro )
{
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE mip_GetAllocatorRequirements( IMemInputPin *iface, ALLOCATOR_PROPERTIES *props )
{
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE mip_Receive( IMemInputPin *iface, IMediaSample *sample )
{
    struct sink_filter *sink = sink_from_IMemInputPin( iface );
    BYTE *ptr = NULL;
    LONG len;

    if (!sample) return E_POINTER;
    if (FAILED( IMediaSample_GetPointer( sample, &ptr ) ) || !ptr) return E_FAIL;
    len = IMediaSample_GetActualDataLength( sample );
    if (len <= 0) return S_OK;

    EnterCriticalSection( &sink->cs );
    if (sink->is_video)
    {
        DWORD w = (DWORD)sink->conn_w;
        DWORD h = (DWORD)sink->conn_h;
        if (w > 0 && h > 0 && (DWORD)len >= w * h * 4u)
        {
            DWORD nb = hash_rgb32_and_check_nonblack( ptr, w, h, (LONG)(w * 4u), &sink->crc );
            sink->frames++;
            if (nb > (w * h) / 10u) sink->nonblack_frames++;
        }
    }
    else if (sink->pcm_channels > 0)
    {
        sink->pcm_frames += hash_pcm_s16( (const short *)ptr, (DWORD)len / 2u, sink->pcm_channels,
                                          &sink->pcm_prev_sign, &sink->pcm_zc, &sink->pcm_peak, &sink->crc );
    }
    LeaveCriticalSection( &sink->cs );
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE mip_ReceiveMultiple( IMemInputPin *iface, IMediaSample **samples,
                                                      LONG count, LONG *processed )
{
    LONG i;
    if (processed) *processed = 0;
    for (i = 0; i < count; i++)
    {
        HRESULT hr = mip_Receive( iface, samples[i] );
        if (FAILED( hr )) return hr;
        if (processed) (*processed)++;
    }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE mip_ReceiveCanBlock( IMemInputPin *iface )
{
    return S_FALSE;
}

static const IMemInputPinVtbl g_mip_vtbl =
{
    mip_QueryInterface,
    mip_AddRef,
    mip_Release,
    mip_GetAllocator,
    mip_NotifyAllocator,
    mip_GetAllocatorRequirements,
    mip_Receive,
    mip_ReceiveMultiple,
    mip_ReceiveCanBlock,
};

static struct sink_filter *create_sink_filter( BOOL is_video )
{
    struct sink_filter *sink = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*sink) );
    ISeekingPassThru *spt = NULL;

    if (!sink) return NULL;
    sink->IBaseFilter_iface.lpVtbl = &g_sf_vtbl;
    sink->IPin_iface.lpVtbl = &g_sp_vtbl;
    sink->IMemInputPin_iface.lpVtbl = &g_mip_vtbl;
    sink->refcount = 1;
    sink->state = State_Stopped;
    sink->is_video = is_video;
    sink->crc = FNV1A_INIT;
    InitializeCriticalSection( &sink->cs );

    if (SUCCEEDED( CoCreateInstance( &CLSID_SeekingPassThru,
                                     (IUnknown *)&sink->IBaseFilter_iface,
                                     CLSCTX_INPROC_SERVER,
                                     &IID_IUnknown,
                                     (void **)&sink->seek_unk ) ) && sink->seek_unk)
    {
        if (SUCCEEDED( IUnknown_QueryInterface( sink->seek_unk, &IID_ISeekingPassThru, (void **)&spt ) ) && spt)
        {
            ISeekingPassThru_Init( spt, TRUE, &sink->IPin_iface );
            ISeekingPassThru_Release( spt );
        }
    }
    return sink;
}

static void reset_sink_stats( struct sink_filter *sink )
{
    EnterCriticalSection( &sink->cs );
    sink->frames = 0;
    sink->nonblack_frames = 0;
    sink->crc = FNV1A_INIT;
    sink->pcm_frames = 0;
    sink->pcm_peak = 0;
    sink->pcm_zc = 0;
    sink->pcm_prev_sign = 0;
    LeaveCriticalSection( &sink->cs );
}

static IPin *find_pin_by_dir( IBaseFilter *filter, PIN_DIRECTION want_dir, ULONG want_index )
{
    IEnumPins *ep = NULL;
    IPin *pin = NULL;
    ULONG found = 0;

    if (FAILED( IBaseFilter_EnumPins( filter, &ep ) ) || !ep) return NULL;
    while (IEnumPins_Next( ep, 1, &pin, NULL ) == S_OK)
    {
        PIN_DIRECTION dir = PINDIR_INPUT;
        if (SUCCEEDED( IPin_QueryDirection( pin, &dir ) ) && dir == want_dir)
        {
            if (found == want_index)
            {
                IEnumPins_Release( ep );
                return pin;
            }
            found++;
        }
        IPin_Release( pin );
    }
    IEnumPins_Release( ep );
    return NULL;
}

static HRESULT wait_dshow_completion( IMediaEvent *me, DWORD timeout_ms, LONG *out_code )
{
    DWORD waited = 0;
    *out_code = 0;
    while (waited < timeout_ms)
    {
        LONG ev_code = 0;
        HRESULT hr;
        pump_messages();
        hr = IMediaEvent_WaitForCompletion( me, 25, &ev_code );
        if (hr != E_ABORT)
        {
            *out_code = ev_code;
            return hr;
        }
        waited += 25u;
    }
    return E_ABORT;
}

static BOOL run_path2_kirikiri_mpeg1( void )
{
    IFilterGraph *fg = NULL;
    IMediaFilter *mf = NULL;
    IMediaControl *mc = NULL;
    IMediaEvent *me = NULL;
    IMediaPosition *mp = NULL;
    IBaseFilter *src = NULL, *splitter = NULL, *vdec = NULL, *adec = NULL;
    IFileSourceFilter *fsf = NULL;
    IAMStreamSelect *ss = NULL;
    struct sink_filter *vsink = NULL, *asink = NULL;
    IPin *src_out = NULL, *sp_in = NULL, *sp_out0 = NULL, *sp_out1 = NULL;
    IPin *vdec_in = NULL, *vdec_out = NULL, *adec_in = NULL, *adec_out = NULL;
    AM_MEDIA_TYPE cmt;
    DWORD ss_count = 0, i;
    BOOL ss_saw_video = FALSE, ss_saw_audio = FALSE;
    LONG conn_w = 0, conn_h = 0, ev_code = 0;
    DWORD frames1 = 0, frames2 = 0, pcm1 = 0, pcm2 = 0, crc1 = 0, crc2 = 0;
    const char *step = "init";
    HRESULT hr = S_OK;
    BOOL ok = FALSE;

    memset( &cmt, 0, sizeof(cmt) );

    vsink = create_sink_filter( TRUE );
    asink = create_sink_filter( FALSE );
    if (!vsink || !asink) { step = "create_sink_filter"; hr = E_OUTOFMEMORY; goto out; }

    /* Self-check the sink's strict bottom-up RGB32 rule: top-down (-240) must be refused. */
    {
        VIDEOINFOHEADER td_vih;
        AM_MEDIA_TYPE td_mt;
        memset( &td_vih, 0, sizeof(td_vih) );
        td_vih.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        td_vih.bmiHeader.biWidth = SELFTEST_CLIP_W;
        td_vih.bmiHeader.biHeight = -SELFTEST_CLIP_H;
        td_vih.bmiHeader.biPlanes = 1;
        td_vih.bmiHeader.biBitCount = 32;
        td_vih.bmiHeader.biCompression = BI_RGB;
        memset( &td_mt, 0, sizeof(td_mt) );
        td_mt.majortype = MEDIATYPE_Video;
        td_mt.subtype = MEDIASUBTYPE_RGB32;
        td_mt.formattype = FORMAT_VideoInfo;
        td_mt.cbFormat = sizeof(td_vih);
        td_mt.pbFormat = (BYTE *)&td_vih;
        if (IPin_QueryAccept( &vsink->IPin_iface, &td_mt ) == S_OK)
        {
            step = "vsink accepted top-down RGB32";
            hr = E_FAIL;
            goto out;
        }
    }

    hr = CoCreateInstance( &CLSID_FilterGraph, NULL, CLSCTX_INPROC_SERVER, &IID_IFilterGraph, (void **)&fg );
    if (FAILED( hr ) || !fg) { step = "CoCreateInstance(FilterGraph)"; goto out; }

    hr = CoCreateInstance( &CLSID_AsyncReader, NULL, CLSCTX_INPROC_SERVER, &IID_IBaseFilter, (void **)&src );
    if (FAILED( hr ) || !src) { step = "CoCreateInstance(AsyncReader)"; goto out; }

    hr = CoCreateInstance( &CLSID_MPEG1Splitter, NULL, CLSCTX_INPROC_SERVER, &IID_IBaseFilter, (void **)&splitter );
    if (FAILED( hr ) || !splitter) { step = "CoCreateInstance(MPEG1Splitter)"; goto out; }

    hr = CoCreateInstance( &CLSID_CMpegVideoCodec, NULL, CLSCTX_INPROC_SERVER, &IID_IBaseFilter, (void **)&vdec );
    if (FAILED( hr ) || !vdec) { step = "CoCreateInstance(CMpegVideoCodec)"; goto out; }

    hr = CoCreateInstance( &CLSID_CMpegAudioCodec, NULL, CLSCTX_INPROC_SERVER, &IID_IBaseFilter, (void **)&adec );
    if (FAILED( hr ) || !adec) { step = "CoCreateInstance(CMpegAudioCodec)"; goto out; }

    hr = IBaseFilter_QueryInterface( src, &IID_IFileSourceFilter, (void **)&fsf );
    if (FAILED( hr ) || !fsf) { step = "QueryInterface(IFileSourceFilter)"; goto out; }
    hr = IFileSourceFilter_Load( fsf, g_paths.mpg_path, NULL );
    if (FAILED( hr )) { step = "IFileSourceFilter::Load"; goto out; }

    if (FAILED( hr = IFilterGraph_AddFilter( fg, src, L"AsyncSrc" ) ) ||
        FAILED( hr = IFilterGraph_AddFilter( fg, splitter, L"MPEG1Splitter" ) ) ||
        FAILED( hr = IFilterGraph_AddFilter( fg, vdec, L"MPEGVideoDec" ) ) ||
        FAILED( hr = IFilterGraph_AddFilter( fg, adec, L"MPEGAudioDec" ) ) ||
        FAILED( hr = IFilterGraph_AddFilter( fg, &vsink->IBaseFilter_iface, L"RGB32Sink" ) ) ||
        FAILED( hr = IFilterGraph_AddFilter( fg, &asink->IBaseFilter_iface, L"AudioSink" ) ))
    {
        step = "IFilterGraph::AddFilter";
        goto out;
    }

    src_out = find_pin_by_dir( src, PINDIR_OUTPUT, 0 );
    sp_in = find_pin_by_dir( splitter, PINDIR_INPUT, 0 );
    if (!src_out || !sp_in) { step = "find AsyncReader/Splitter pins"; hr = E_FAIL; goto out; }

    hr = IFilterGraph_ConnectDirect( fg, src_out, sp_in, NULL );
    if (FAILED( hr )) { step = "ConnectDirect(AsyncReader->MPEG1Splitter)"; goto out; }

    sp_out0 = find_pin_by_dir( splitter, PINDIR_OUTPUT, 0 );
    sp_out1 = find_pin_by_dir( splitter, PINDIR_OUTPUT, 1 );
    vdec_in = find_pin_by_dir( vdec, PINDIR_INPUT, 0 );
    vdec_out = find_pin_by_dir( vdec, PINDIR_OUTPUT, 0 );
    adec_in = find_pin_by_dir( adec, PINDIR_INPUT, 0 );
    adec_out = find_pin_by_dir( adec, PINDIR_OUTPUT, 0 );
    if (!sp_out0 || !sp_out1 || !vdec_in || !vdec_out || !adec_in || !adec_out)
    {
        step = "find splitter/decoder pins";
        hr = E_FAIL;
        goto out;
    }

    /* Connect splitter outputs to the MPEG video and audio codecs via ConnectDirect. */
    if (SUCCEEDED( IFilterGraph_ConnectDirect( fg, sp_out0, vdec_in, NULL ) ))
    {
        hr = IFilterGraph_ConnectDirect( fg, sp_out1, adec_in, NULL );
        if (FAILED( hr )) { step = "ConnectDirect(splitter->CMpegAudioCodec)"; goto out; }
    }
    else
    {
        hr = IFilterGraph_ConnectDirect( fg, sp_out1, vdec_in, NULL );
        if (FAILED( hr )) { step = "ConnectDirect(splitter->CMpegVideoCodec)"; goto out; }
        hr = IFilterGraph_ConnectDirect( fg, sp_out0, adec_in, NULL );
        if (FAILED( hr )) { step = "ConnectDirect(splitter->CMpegAudioCodec)"; goto out; }
    }

    hr = IFilterGraph_ConnectDirect( fg, vdec_out, &vsink->IPin_iface, NULL );
    if (FAILED( hr )) { step = "ConnectDirect(CMpegVideoCodec->RGB32BottomUpSink)"; goto out; }

    hr = IFilterGraph_ConnectDirect( fg, adec_out, &asink->IPin_iface, NULL );
    if (FAILED( hr )) { step = "ConnectDirect(CMpegAudioCodec->AudioSink)"; goto out; }

    /* Verify size and bottom-up orientation from the connection's media type. */
    hr = IPin_ConnectionMediaType( &vsink->IPin_iface, &cmt );
    if (FAILED( hr ) || cmt.cbFormat < sizeof(VIDEOINFOHEADER) || !cmt.pbFormat)
    {
        step = "IPin::ConnectionMediaType";
        goto out;
    }
    {
        const VIDEOINFOHEADER *vih = (const VIDEOINFOHEADER *)cmt.pbFormat;
        conn_w = vih->bmiHeader.biWidth;
        conn_h = vih->bmiHeader.biHeight;
        if (!IsEqualGUID( &cmt.subtype, &MEDIASUBTYPE_RGB32 ) ||
            conn_w != SELFTEST_CLIP_W || conn_h != SELFTEST_CLIP_H)
        {
            step = "ConnectionMediaType not 320x240 bottom-up RGB32";
            hr = E_FAIL;
            goto out;
        }
    }
    free_mt_format( &cmt );

    /* Check IAMStreamSelect::Count and Info on CLSID_MPEG1Splitter. */
    hr = IBaseFilter_QueryInterface( splitter, &IID_IAMStreamSelect, (void **)&ss );
    if (FAILED( hr ) || !ss) { step = "QueryInterface(IAMStreamSelect)"; goto out; }

    hr = IAMStreamSelect_Count( ss, &ss_count );
    if (FAILED( hr ) || ss_count != 2) { step = "IAMStreamSelect::Count!=2"; if (SUCCEEDED( hr )) hr = E_FAIL; goto out; }

    for (i = 0; i < ss_count; i++)
    {
        AM_MEDIA_TYPE *info_mt = NULL;
        DWORD info_flags = 0;
        WCHAR *info_name = NULL;

        hr = IAMStreamSelect_Info( ss, (LONG)i, &info_mt, &info_flags, NULL, NULL, &info_name, NULL, NULL );
        if (info_name) CoTaskMemFree( info_name );
        if (FAILED( hr ) || !info_mt) { delete_media_type( info_mt ); step = "IAMStreamSelect::Info"; goto out; }

        if (IsEqualGUID( &info_mt->majortype, &MEDIATYPE_Video ))
        {
            if (info_mt->cbFormat >= sizeof(VIDEOINFOHEADER) && info_mt->pbFormat)
            {
                const VIDEOINFOHEADER *vih = (const VIDEOINFOHEADER *)info_mt->pbFormat;
                LONG h = (vih->bmiHeader.biHeight < 0) ? -vih->bmiHeader.biHeight : vih->bmiHeader.biHeight;
                if (vih->bmiHeader.biWidth == SELFTEST_CLIP_W && h == SELFTEST_CLIP_H)
                    ss_saw_video = TRUE;
            }
        }
        else if (IsEqualGUID( &info_mt->majortype, &MEDIATYPE_Audio ))
        {
            ss_saw_audio = TRUE;
        }
        delete_media_type( info_mt );
    }
    if (!ss_saw_video || !ss_saw_audio)
    {
        step = "IAMStreamSelect::Info video/audio metadata";
        hr = E_FAIL;
        goto out;
    }

    if (SUCCEEDED( IFilterGraph_QueryInterface( fg, &IID_IMediaFilter, (void **)&mf ) ) && mf)
        IMediaFilter_SetSyncSource( mf, NULL );

    if (FAILED( hr = IFilterGraph_QueryInterface( fg, &IID_IMediaControl, (void **)&mc ) ) ||
        FAILED( hr = IFilterGraph_QueryInterface( fg, &IID_IMediaEvent, (void **)&me ) ) ||
        FAILED( hr = IFilterGraph_QueryInterface( fg, &IID_IMediaPosition, (void **)&mp ) ))
    {
        step = "QueryInterface(IMediaControl/Event/Position)";
        goto out;
    }

    /* First play through to EC_COMPLETE. */
    hr = IMediaControl_Run( mc );
    if (FAILED( hr )) { step = "IMediaControl::Run(pass1)"; goto out; }

    hr = wait_dshow_completion( me, 15000u, &ev_code );
    if (FAILED( hr ) || ev_code != EC_COMPLETE) { step = "WaitForCompletion(pass1)"; goto out; }

    frames1 = vsink->frames;
    crc1 = vsink->crc;
    pcm1 = asink->pcm_frames;
    if (frames1 < SELFTEST_CLIP_FRAMES - 5u || vsink->nonblack_frames != frames1 || pcm1 < SELFTEST_AUDIO_RATE)
    {
        step = "pass1 frame/PCM counts";
        hr = E_FAIL;
        goto out;
    }

    /* Rewind with IMediaPosition::put_CurrentPosition(0) and play again. */
    hr = IMediaControl_Pause( mc );
    if (FAILED( hr )) { step = "IMediaControl::Pause"; goto out; }
    reset_sink_stats( vsink );
    reset_sink_stats( asink );

    hr = IMediaPosition_put_CurrentPosition( mp, 0.0 );
    if (FAILED( hr )) { step = "IMediaPosition::put_CurrentPosition(0)"; goto out; }

    hr = IMediaControl_Run( mc );
    if (FAILED( hr )) { step = "IMediaControl::Run(pass2)"; goto out; }

    hr = wait_dshow_completion( me, 15000u, &ev_code );
    if (FAILED( hr ) || ev_code != EC_COMPLETE) { step = "WaitForCompletion(pass2)"; goto out; }

    frames2 = vsink->frames;
    crc2 = vsink->crc;
    pcm2 = asink->pcm_frames;
    if (frames2 < SELFTEST_CLIP_FRAMES - 5u || vsink->nonblack_frames != frames2 || pcm2 < SELFTEST_AUDIO_RATE)
    {
        step = "pass2 frame/PCM counts after rewind";
        hr = E_FAIL;
        goto out;
    }
    ok = TRUE;

out:
    if (mc) IMediaControl_Stop( mc );
    free_mt_format( &cmt );
    if (adec_out) IPin_Release( adec_out );
    if (adec_in) IPin_Release( adec_in );
    if (vdec_out) IPin_Release( vdec_out );
    if (vdec_in) IPin_Release( vdec_in );
    if (sp_out1) IPin_Release( sp_out1 );
    if (sp_out0) IPin_Release( sp_out0 );
    if (sp_in) IPin_Release( sp_in );
    if (src_out) IPin_Release( src_out );
    if (ss) IAMStreamSelect_Release( ss );
    if (fsf) IFileSourceFilter_Release( fsf );
    if (mp) IMediaPosition_Release( mp );
    if (me) IMediaEvent_Release( me );
    if (mc) IMediaControl_Release( mc );
    if (mf) IMediaFilter_Release( mf );
    if (adec) IBaseFilter_Release( adec );
    if (vdec) IBaseFilter_Release( vdec );
    if (splitter) IBaseFilter_Release( splitter );
    if (src) IBaseFilter_Release( src );
    if (fg) IFilterGraph_Release( fg );
    if (asink) IBaseFilter_Release( &asink->IBaseFilter_iface );
    if (vsink) IBaseFilter_Release( &vsink->IBaseFilter_iface );

    if (ok)
    {
        write_str( "[2/6] PASS kirikiri-mpeg1: size=" );
        write_int( conn_w );
        write_str( "x" );
        write_int( conn_h );
        write_str( " streams=" );
        write_uint( ss_count );
        write_str( " pass1_frames=" );
        write_uint( frames1 );
        write_str( " pass2_frames=" );
        write_uint( frames2 );
        write_str( " pcm_frames=" );
        write_uint( pcm1 );
        write_str( "/" );
        write_uint( pcm2 );
        write_str( " rgb_crc=" );
        write_hex32( crc1 );
        write_str( "/" );
        write_hex32( crc2 );
        write_str( "\n" );
    }
    else
    {
        write_str( "[2/6] FAIL kirikiri-mpeg1: step=" );
        write_str( step );
        write_str( " hr=" );
        write_hex32( (DWORD)hr );
        write_str( " pass1_frames=" );
        write_uint( frames1 );
        write_str( " pass2_frames=" );
        write_uint( frames2 );
        write_str( "\n" );
    }
    flush_log();
    return ok;
}

/* =========================================================================
 * PATH 3: DirectShow RenderFile on MPEG-1 in a hidden window -> EC_COMPLETE
 * ========================================================================= */

static BOOL run_path3_dshow_renderfile( void )
{
    HWND hwnd = NULL;
    IGraphBuilder *gb = NULL;
    IVideoWindow *vw = NULL;
    IMediaControl *mc = NULL;
    IMediaEvent *me = NULL;
    LONG ev_code = 0;
    DWORD t0 = GetTickCount(), elapsed_ms = 0;
    const char *step = "init";
    HRESULT hr = S_OK;
    BOOL ok = FALSE;

    /* Hidden window (no WS_VISIBLE). */
    hwnd = create_test_window( FALSE );
    if (!hwnd) { step = "CreateWindowExW(hidden)"; hr = HRESULT_FROM_WIN32( GetLastError() ); goto out; }

    hr = CoCreateInstance( &CLSID_FilterGraph, NULL, CLSCTX_INPROC_SERVER, &IID_IGraphBuilder, (void **)&gb );
    if (FAILED( hr ) || !gb) { step = "CoCreateInstance(IGraphBuilder)"; goto out; }

    hr = IGraphBuilder_RenderFile( gb, g_paths.mpg_path, NULL );
    if (FAILED( hr )) { step = "IGraphBuilder::RenderFile"; goto out; }

    if (SUCCEEDED( IGraphBuilder_QueryInterface( gb, &IID_IVideoWindow, (void **)&vw ) ) && vw)
    {
        IVideoWindow_put_Owner( vw, (OAHWND)(ULONG_PTR)hwnd );
        IVideoWindow_put_WindowStyle( vw, WS_CHILD | WS_CLIPSIBLINGS );
        IVideoWindow_SetWindowPosition( vw, 0, 0, SELFTEST_CLIP_W, SELFTEST_CLIP_H );
        IVideoWindow_put_Visible( vw, OAFALSE );
    }

    if (FAILED( hr = IGraphBuilder_QueryInterface( gb, &IID_IMediaControl, (void **)&mc ) ) ||
        FAILED( hr = IGraphBuilder_QueryInterface( gb, &IID_IMediaEvent, (void **)&me ) ))
    {
        step = "QueryInterface(IMediaControl/IMediaEvent)";
        goto out;
    }

    hr = IMediaControl_Run( mc );
    if (FAILED( hr )) { step = "IMediaControl::Run"; goto out; }

    hr = wait_dshow_completion( me, 20000u, &ev_code );
    elapsed_ms = GetTickCount() - t0;
    if (FAILED( hr ) || ev_code != EC_COMPLETE) { step = "WaitForCompletion(EC_COMPLETE)"; goto out; }
    ok = TRUE;

out:
    if (mc) IMediaControl_Stop( mc );
    if (vw)
    {
        IVideoWindow_put_Visible( vw, OAFALSE );
        IVideoWindow_put_Owner( vw, 0 );
        IVideoWindow_Release( vw );
    }
    if (me) IMediaEvent_Release( me );
    if (mc) IMediaControl_Release( mc );
    if (gb) IGraphBuilder_Release( gb );
    if (hwnd) DestroyWindow( hwnd );

    if (ok)
    {
        write_str( "[3/6] PASS dshow-renderfile-mpeg: event=EC_COMPLETE elapsed=" );
        write_uint( elapsed_ms );
        write_str( "ms\n" );
    }
    else
    {
        write_str( "[3/6] FAIL dshow-renderfile-mpeg: step=" );
        write_str( step );
        write_str( " hr=" );
        write_hex32( (DWORD)hr );
        write_str( " ev_code=" );
        write_int( ev_code );
        write_str( "\n" );
    }
    flush_log();
    return ok;
}

/* =========================================================================
 * PATH 4: Media Foundation session (EVR on window + SAR, Senren Banka path)
 * ========================================================================= */

static DWORD count_dib_nonblack( const BITMAPINFOHEADER *bih, const BYTE *dib, DWORD dib_len )
{
    DWORD w, h, bpp, bytes_per_px, row_bytes, x, y, nonblack = 0;

    if (!bih || !dib || bih->biWidth <= 0 || bih->biHeight == 0) return 0;
    w = (DWORD)bih->biWidth;
    h = (bih->biHeight < 0) ? (DWORD)(-bih->biHeight) : (DWORD)bih->biHeight;
    bpp = bih->biBitCount ? bih->biBitCount : 32u;
    if (bpp != 24u && bpp != 32u) return 0;
    bytes_per_px = bpp / 8u;
    row_bytes = (w * bytes_per_px + 3u) & ~3u;
    if (dib_len < row_bytes * h) return 0;

    for (y = 0; y < h; y++)
    {
        const BYTE *row = dib + y * row_bytes;
        for (x = 0; x < w; x++)
        {
            BYTE b = row[x * bytes_per_px + 0u];
            BYTE g = row[x * bytes_per_px + 1u];
            BYTE r = row[x * bytes_per_px + 2u];
            if (r > 20u || g > 20u || b > 20u) nonblack++;
        }
    }
    return nonblack;
}

static BOOL run_path4_mf_session( void )
{
    BOOL mf_started = FALSE;
    HWND hwnd = NULL;
    IMFMediaSession *session = NULL;
    IMFSourceResolver *resolver = NULL;
    IUnknown *src_unk = NULL;
    IMFMediaSource *source = NULL;
    IMFPresentationDescriptor *pd = NULL;
    IMFTopology *topo = NULL;
    IMFClock *clock = NULL;
    IMFPresentationClock *pclock = NULL;
    IMFVideoDisplayControl *vdc = NULL;
    MF_OBJECT_TYPE obj_type = MF_OBJECT_INVALID;
    DWORD sd_count = 0, i, waited = 0;
    BOOL saw_video = FALSE, saw_audio = FALSE;
    BOOL session_started = FALSE, session_ended = FALSE, got_image = FALSE;
    BOOL have_clk_start = FALSE;
    MFTIME clk_start = 0, clk_max = 0, img_ts = 0;
    LONG img_w = 0, img_h = 0;
    DWORD img_nonblack = 0;
    HRESULT last_img_hr = E_PENDING;
    const char *step = "init";
    HRESULT hr = S_OK;
    BOOL ok = FALSE;

    hr = MFStartup( MF_VERSION, MFSTARTUP_FULL );
    if (FAILED( hr )) { step = "MFStartup"; goto out; }
    mf_started = TRUE;

    hwnd = create_test_window( TRUE );
    if (!hwnd) { step = "CreateWindowExW(EVR)"; hr = HRESULT_FROM_WIN32( GetLastError() ); goto out; }
    pump_messages();

    hr = MFCreateMediaSession( NULL, &session );
    if (FAILED( hr ) || !session) { step = "MFCreateMediaSession"; goto out; }

    hr = MFCreateSourceResolver( &resolver );
    if (FAILED( hr ) || !resolver) { step = "MFCreateSourceResolver"; goto out; }

    hr = IMFSourceResolver_CreateObjectFromURL( resolver, g_paths.wmv_url, MF_RESOLUTION_MEDIASOURCE,
                                                NULL, &obj_type, &src_unk );
    if (FAILED( hr ))
    {
        hr = IMFSourceResolver_CreateObjectFromURL( resolver, g_paths.wmv_path, MF_RESOLUTION_MEDIASOURCE,
                                                    NULL, &obj_type, &src_unk );
    }
    if (FAILED( hr ) || !src_unk) { step = "IMFSourceResolver::CreateObjectFromURL"; goto out; }

    hr = IUnknown_QueryInterface( src_unk, &IID_IMFMediaSource, (void **)&source );
    if (FAILED( hr ) || !source) { step = "QueryInterface(IMFMediaSource)"; goto out; }

    hr = IMFMediaSource_CreatePresentationDescriptor( source, &pd );
    if (FAILED( hr ) || !pd) { step = "CreatePresentationDescriptor"; goto out; }

    hr = IMFPresentationDescriptor_GetStreamDescriptorCount( pd, &sd_count );
    if (FAILED( hr ) || sd_count < 2) { step = "GetStreamDescriptorCount"; goto out; }

    hr = MFCreateTopology( &topo );
    if (FAILED( hr ) || !topo) { step = "MFCreateTopology"; goto out; }

    for (i = 0; i < sd_count; i++)
    {
        BOOL selected = FALSE;
        IMFStreamDescriptor *sd = NULL;
        IMFMediaTypeHandler *handler = NULL;
        IMFActivate *sink_act = NULL;
        IMFTopologyNode *src_node = NULL, *out_node = NULL;
        GUID major = k_guid_null;

        hr = IMFPresentationDescriptor_GetStreamDescriptorByIndex( pd, i, &selected, &sd );
        if (FAILED( hr ) || !sd) { step = "GetStreamDescriptorByIndex"; goto out; }
        if (!selected) IMFPresentationDescriptor_SelectStream( pd, i );

        hr = IMFStreamDescriptor_GetMediaTypeHandler( sd, &handler );
        if (SUCCEEDED( hr ) && handler)
            hr = IMFMediaTypeHandler_GetMajorType( handler, &major );
        if (handler) IMFMediaTypeHandler_Release( handler );
        if (FAILED( hr )) { IMFStreamDescriptor_Release( sd ); step = "GetMajorType"; goto out; }

        if (IsEqualGUID( &major, &MFMediaType_Video ))
        {
            hr = MFCreateVideoRendererActivate( hwnd, &sink_act );
            saw_video = TRUE;
        }
        else if (IsEqualGUID( &major, &MFMediaType_Audio ))
        {
            hr = MFCreateAudioRendererActivate( &sink_act );
            saw_audio = TRUE;
        }
        else
        {
            IMFStreamDescriptor_Release( sd );
            continue;
        }
        if (FAILED( hr ) || !sink_act)
        {
            IMFStreamDescriptor_Release( sd );
            step = "MFCreate{Video,Audio}RendererActivate";
            goto out;
        }

        hr = MFCreateTopologyNode( MF_TOPOLOGY_SOURCESTREAM_NODE, &src_node );
        if (SUCCEEDED( hr )) hr = MFCreateTopologyNode( MF_TOPOLOGY_OUTPUT_NODE, &out_node );
        if (SUCCEEDED( hr )) hr = IMFTopologyNode_SetUnknown( src_node, &MF_TOPONODE_SOURCE, (IUnknown *)source );
        if (SUCCEEDED( hr )) hr = IMFTopologyNode_SetUnknown( src_node, &MF_TOPONODE_PRESENTATION_DESCRIPTOR, (IUnknown *)pd );
        if (SUCCEEDED( hr )) hr = IMFTopologyNode_SetUnknown( src_node, &MF_TOPONODE_STREAM_DESCRIPTOR, (IUnknown *)sd );
        if (SUCCEEDED( hr )) hr = IMFTopologyNode_SetObject( out_node, (IUnknown *)sink_act );
        if (SUCCEEDED( hr )) hr = IMFTopologyNode_SetUINT32( out_node, &MF_TOPONODE_STREAMID, 0 );
        if (SUCCEEDED( hr )) hr = IMFTopology_AddNode( topo, src_node );
        if (SUCCEEDED( hr )) hr = IMFTopology_AddNode( topo, out_node );
        if (SUCCEEDED( hr )) hr = IMFTopologyNode_ConnectOutput( src_node, 0, out_node, 0 );

        if (out_node) IMFTopologyNode_Release( out_node );
        if (src_node) IMFTopologyNode_Release( src_node );
        IMFActivate_Release( sink_act );
        IMFStreamDescriptor_Release( sd );
        if (FAILED( hr )) { step = "build MF topology"; goto out; }
    }

    if (!saw_video || !saw_audio) { step = "ASF missing video or audio stream"; hr = E_FAIL; goto out; }

    if (SUCCEEDED( IMFMediaSession_GetClock( session, &clock ) ) && clock)
        IMFClock_QueryInterface( clock, &IID_IMFPresentationClock, (void **)&pclock );

    hr = IMFMediaSession_SetTopology( session, 0, topo );
    if (FAILED( hr )) { step = "IMFMediaSession::SetTopology"; goto out; }

    {
        PROPVARIANT start_pos;
        memset( &start_pos, 0, sizeof(start_pos) );
        start_pos.vt = VT_EMPTY;
        hr = IMFMediaSession_Start( session, &k_guid_null, &start_pos );
        if (FAILED( hr )) { step = "IMFMediaSession::Start"; goto out; }
    }

    while (waited < 25000u && !session_ended)
    {
        IMFMediaEvent *ev = NULL;
        pump_messages();

        while (IMFMediaSession_GetEvent( session, MF_EVENT_FLAG_NO_WAIT, &ev ) == S_OK && ev)
        {
            MediaEventType met = MEUnknown;
            HRESULT ev_hr = S_OK;
            IMFMediaEvent_GetType( ev, &met );
            IMFMediaEvent_GetStatus( ev, &ev_hr );

            if (FAILED( ev_hr ))
            {
                IMFMediaEvent_Release( ev );
                hr = ev_hr;
                step = "MF session event failed status";
                goto out;
            }
            if (met == MESessionTopologyStatus)
            {
                UINT32 status = 0;
                if (SUCCEEDED( IMFMediaEvent_GetUINT32( ev, &MF_EVENT_TOPOLOGY_STATUS, &status ) ) &&
                    status == MF_TOPOSTATUS_READY && !vdc)
                {
                    if (SUCCEEDED( MFGetService( (IUnknown *)session, &MR_VIDEO_RENDER_SERVICE,
                                                 &IID_IMFVideoDisplayControl, (void **)&vdc ) ) && vdc)
                    {
                        RECT rc = { 0, 0, SELFTEST_CLIP_W, SELFTEST_CLIP_H };
                        IMFVideoDisplayControl_SetVideoPosition( vdc, NULL, &rc );
                    }
                }
            }
            else if (met == MESessionStarted)
            {
                session_started = TRUE;
                if (!pclock && SUCCEEDED( IMFMediaSession_GetClock( session, &clock ) ) && clock)
                    IMFClock_QueryInterface( clock, &IID_IMFPresentationClock, (void **)&pclock );
            }
            else if (met == MESessionEnded)
            {
                session_ended = TRUE;
            }
            IMFMediaEvent_Release( ev );
        }

        if (session_started && pclock)
        {
            MFTIME now = 0;
            if (SUCCEEDED( IMFPresentationClock_GetTime( pclock, &now ) ))
            {
                if (!have_clk_start) { clk_start = now; have_clk_start = TRUE; }
                if (now > clk_max) clk_max = now;
            }
        }

        /* Capture a presented frame mid-way through the 2.0 s clip (once >= 200 ms). */
        if (session_started && !got_image && (clk_max >= 2000000 || waited >= 350u))
        {
            if (!vdc)
            {
                if (SUCCEEDED( MFGetService( (IUnknown *)session, &MR_VIDEO_RENDER_SERVICE,
                                             &IID_IMFVideoDisplayControl, (void **)&vdc ) ) && vdc)
                {
                    RECT rc = { 0, 0, SELFTEST_CLIP_W, SELFTEST_CLIP_H };
                    IMFVideoDisplayControl_SetVideoPosition( vdc, NULL, &rc );
                }
            }
            if (vdc)
            {
                BITMAPINFOHEADER bih;
                BYTE *dib = NULL;
                DWORD dib_len = 0;
                LONGLONG ts = 0;

                memset( &bih, 0, sizeof(bih) );
                bih.biSize = sizeof(bih);
                last_img_hr = IMFVideoDisplayControl_GetCurrentImage( vdc, &bih, &dib, &dib_len, &ts );
                if (SUCCEEDED( last_img_hr ) && dib)
                {
                    DWORD nb = count_dib_nonblack( &bih, dib, dib_len );
                    DWORD total_px = (DWORD)((bih.biWidth > 0 ? bih.biWidth : 1) *
                                             (bih.biHeight < 0 ? -bih.biHeight : (bih.biHeight > 0 ? bih.biHeight : 1)));
                    if (nb > total_px / 10u)
                    {
                        got_image = TRUE;
                        img_w = bih.biWidth;
                        img_h = bih.biHeight;
                        img_nonblack = nb;
                        img_ts = ts;
                    }
                    CoTaskMemFree( dib );
                }
            }
        }

        if (session_ended) break;
        Sleep( 20 );
        waited += 20u;
    }

    if (!session_ended) { step = "timeout waiting for MESessionEnded"; hr = E_ABORT; goto out; }
    if (!got_image) { step = "IMFVideoDisplayControl::GetCurrentImage non-black"; hr = last_img_hr; goto out; }
    if (!have_clk_start || clk_max <= clk_start || (clk_max - clk_start) < 5000000)
    {
        step = "IMFPresentationClock did not advance";
        hr = E_FAIL;
        goto out;
    }
    ok = TRUE;

out:
    if (vdc) IMFVideoDisplayControl_Release( vdc );
    if (pclock) IMFPresentationClock_Release( pclock );
    if (clock) IMFClock_Release( clock );
    if (session)
    {
        DWORD close_wait = 0;
        if (SUCCEEDED( IMFMediaSession_Close( session ) ))
        {
            while (close_wait < 2000u)
            {
                IMFMediaEvent *ev = NULL;
                MediaEventType met = MEUnknown;
                pump_messages();
                if (IMFMediaSession_GetEvent( session, MF_EVENT_FLAG_NO_WAIT, &ev ) == S_OK && ev)
                {
                    IMFMediaEvent_GetType( ev, &met );
                    IMFMediaEvent_Release( ev );
                    if (met == MESessionClosed) break;
                }
                Sleep( 10 );
                close_wait += 10u;
            }
        }
    }
    if (source) IMFMediaSource_Shutdown( source );
    if (session) IMFMediaSession_Shutdown( session );
    if (topo) IMFTopology_Release( topo );
    if (pd) IMFPresentationDescriptor_Release( pd );
    if (source) IMFMediaSource_Release( source );
    if (src_unk) IUnknown_Release( src_unk );
    if (resolver) IMFSourceResolver_Release( resolver );
    if (session) IMFMediaSession_Release( session );
    if (hwnd) DestroyWindow( hwnd );
    if (mf_started) MFShutdown();

    if (ok)
    {
        write_str( "[4/6] PASS mf-session-evr-sar: ended=1 image=" );
        write_int( img_w );
        write_str( "x" );
        write_int( img_h );
        write_str( " nonblack_px=" );
        write_uint( img_nonblack );
        write_str( " img_ts=" );
        write_uint( hns_to_ms( img_ts ) );
        write_str( "ms clock=" );
        write_uint( hns_to_ms( clk_start ) );
        write_str( "->" );
        write_uint( hns_to_ms( clk_max ) );
        write_str( "ms\n" );
    }
    else
    {
        write_str( "[4/6] FAIL mf-session-evr-sar: step=" );
        write_str( step );
        write_str( " hr=" );
        write_hex32( (DWORD)hr );
        write_str( " ended=" );
        write_uint( session_ended ? 1u : 0u );
        write_str( " got_image=" );
        write_uint( got_image ? 1u : 0u );
        write_str( " clock_max=" );
        write_uint( hns_to_ms( clk_max ) );
        write_str( "ms\n" );
    }
    flush_log();
    return ok;
}

/* =========================================================================
 * PATH 5: Media Foundation Source Reader -> RGB32
 * ========================================================================= */

static BOOL run_path5_mf_source_reader( void )
{
    BOOL mf_started = FALSE;
    IMFAttributes *attrs = NULL;
    IMFSourceReader *sreader = NULL;
    IMFMediaType *want_mt = NULL, *cur_mt = NULL;
    UINT64 frame_size = 0;
    DWORD sr_w = 0, sr_h = 0, frames = 0, nonblack_frames = 0, crc = FNV1A_INIT;
    const char *step = "init";
    HRESULT hr = S_OK;
    BOOL ok = FALSE;

    hr = MFStartup( MF_VERSION, MFSTARTUP_FULL );
    if (FAILED( hr )) { step = "MFStartup"; goto out; }
    mf_started = TRUE;

    hr = MFCreateAttributes( &attrs, 1 );
    if (FAILED( hr ) || !attrs) { step = "MFCreateAttributes"; goto out; }
    IMFAttributes_SetUINT32( attrs, &MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, TRUE );

    hr = MFCreateSourceReaderFromURL( g_paths.wmv_url, attrs, &sreader );
    if (FAILED( hr ))
        hr = MFCreateSourceReaderFromURL( g_paths.wmv_path, attrs, &sreader );
    if (FAILED( hr ) || !sreader) { step = "MFCreateSourceReaderFromURL"; goto out; }

    IMFSourceReader_SetStreamSelection( sreader, MF_SOURCE_READER_ALL_STREAMS, FALSE );
    hr = IMFSourceReader_SetStreamSelection( sreader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, TRUE );
    if (FAILED( hr )) { step = "SetStreamSelection(video)"; goto out; }

    hr = MFCreateMediaType( &want_mt );
    if (FAILED( hr ) || !want_mt) { step = "MFCreateMediaType"; goto out; }
    IMFMediaType_SetGUID( want_mt, &MF_MT_MAJOR_TYPE, &MFMediaType_Video );
    IMFMediaType_SetGUID( want_mt, &MF_MT_SUBTYPE, &MFVideoFormat_RGB32 );

    hr = IMFSourceReader_SetCurrentMediaType( sreader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, NULL, want_mt );
    if (FAILED( hr )) { step = "SetCurrentMediaType(RGB32)"; goto out; }

    hr = IMFSourceReader_GetCurrentMediaType( sreader, MF_SOURCE_READER_FIRST_VIDEO_STREAM, &cur_mt );
    if (FAILED( hr ) || !cur_mt) { step = "GetCurrentMediaType"; goto out; }
    if (SUCCEEDED( IMFMediaType_GetUINT64( cur_mt, &MF_MT_FRAME_SIZE, &frame_size ) ))
    {
        sr_w = (DWORD)(frame_size >> 32);
        sr_h = (DWORD)frame_size;
    }
    if (!sr_w || !sr_h) { sr_w = SELFTEST_CLIP_W; sr_h = SELFTEST_CLIP_H; }

    for (;;)
    {
        DWORD stream_idx = 0, sr_flags = 0;
        LONGLONG ts = 0;
        IMFSample *sample = NULL;

        hr = IMFSourceReader_ReadSample( sreader, MF_SOURCE_READER_FIRST_VIDEO_STREAM,
                                         0, &stream_idx, &sr_flags, &ts, &sample );
        if (FAILED( hr )) { step = "IMFSourceReader::ReadSample"; goto out; }
        if (sr_flags & MF_SOURCE_READERF_ERROR)
        {
            if (sample) IMFSample_Release( sample );
            step = "MF_SOURCE_READERF_ERROR";
            hr = E_FAIL;
            goto out;
        }
        if (sample)
        {
            IMFMediaBuffer *buf = NULL;
            BYTE *ptr = NULL;
            DWORD max_len = 0, cur_len = 0;

            if (SUCCEEDED( IMFSample_ConvertToContiguousBuffer( sample, &buf ) ) && buf)
            {
                if (SUCCEEDED( IMFMediaBuffer_Lock( buf, &ptr, &max_len, &cur_len ) ) && ptr)
                {
                    if (cur_len >= sr_w * sr_h * 4u)
                    {
                        DWORD nb = hash_rgb32_and_check_nonblack( ptr, sr_w, sr_h, (LONG)(sr_w * 4u), &crc );
                        frames++;
                        if (nb > (sr_w * sr_h) / 10u) nonblack_frames++;
                    }
                    IMFMediaBuffer_Unlock( buf );
                }
                IMFMediaBuffer_Release( buf );
            }
            IMFSample_Release( sample );
        }
        if (sr_flags & MF_SOURCE_READERF_ENDOFSTREAM)
            break;
    }

    if (sr_w != SELFTEST_CLIP_W || sr_h != SELFTEST_CLIP_H ||
        frames < SELFTEST_CLIP_FRAMES - 5u || nonblack_frames != frames)
    {
        step = "RGB32 frame count/size/non-black check";
        hr = E_FAIL;
        goto out;
    }
    ok = TRUE;

out:
    if (cur_mt) IMFMediaType_Release( cur_mt );
    if (want_mt) IMFMediaType_Release( want_mt );
    if (sreader) IMFSourceReader_Release( sreader );
    if (attrs) IMFAttributes_Release( attrs );
    if (mf_started) MFShutdown();

    if (ok)
    {
        write_str( "[5/6] PASS mf-source-reader: frames=" );
        write_uint( frames );
        write_str( " size=" );
        write_uint( sr_w );
        write_str( "x" );
        write_uint( sr_h );
        write_str( " rgb_crc=" );
        write_hex32( crc );
        write_str( "\n" );
    }
    else
    {
        write_str( "[5/6] FAIL mf-source-reader: step=" );
        write_str( step );
        write_str( " hr=" );
        write_hex32( (DWORD)hr );
        write_str( " frames=" );
        write_uint( frames );
        write_str( " nonblack=" );
        write_uint( nonblack_frames );
        write_str( "\n" );
    }
    flush_log();
    return ok;
}

/* =========================================================================
 * PATH 6: MCI mciSendString open / play / close on the MPEG-1 clip
 * ========================================================================= */

static BOOL run_path6_mci_mpeg( void )
{
    HWND hwnd = NULL;
    MCIERROR err = 0;
    BOOL opened = FALSE, completed = FALSE, ok = FALSE;
    DWORD waited = 0, t0 = GetTickCount(), elapsed_ms = 0;
    const char *step = "init";

    InterlockedExchange( &g_mci_notified, 0 );
    g_mci_notify_code = 0;

    hwnd = create_test_window( FALSE );
    if (!hwnd) { step = "CreateWindowExW(MCI)"; err = GetLastError(); goto out; }

    /* open "<mpg_path>" type mpegvideo alias selftest_mci */
    wstr_copy( g_paths.cmd_buf, MAX_PATH + 64, L"open \"" );
    wstr_append( g_paths.cmd_buf, MAX_PATH + 64, g_paths.mpg_path );
    wstr_append( g_paths.cmd_buf, MAX_PATH + 64, L"\" type mpegvideo alias selftest_mci" );

    err = mciSendStringW( g_paths.cmd_buf, g_paths.ret_buf, 128, NULL );
    if (err != 0)
    {
        /* Fallback without explicit type in case registry maps .mpg directly. */
        wstr_copy( g_paths.cmd_buf, MAX_PATH + 64, L"open \"" );
        wstr_append( g_paths.cmd_buf, MAX_PATH + 64, g_paths.mpg_path );
        wstr_append( g_paths.cmd_buf, MAX_PATH + 64, L"\" alias selftest_mci" );
        err = mciSendStringW( g_paths.cmd_buf, g_paths.ret_buf, 128, NULL );
    }
    if (err != 0) { step = "mci open"; goto out; }
    opened = TRUE;

    /* Hide the default MCI video window so the test stays unobtrusive. */
    mciSendStringW( L"window selftest_mci state hide", g_paths.ret_buf, 128, NULL );

    /* Wine's mciqtz32 play ignores MCI_WAIT, so use `notify` with a message pump
     * and also check `status selftest_mci mode` == "stopped". */
    err = mciSendStringW( L"play selftest_mci from 0 notify", g_paths.ret_buf, 128, hwnd );
    if (err != 0)
        err = mciSendStringW( L"play selftest_mci notify", g_paths.ret_buf, 128, hwnd );
    if (err != 0) { step = "mci play"; goto out; }

    while (waited < 20000u)
    {
        pump_messages();
        if (InterlockedCompareExchange( &g_mci_notified, 0, 0 ))
        {
            if (g_mci_notify_code == MCI_NOTIFY_SUCCESSFUL)
            {
                completed = TRUE;
                break;
            }
            step = "MM_MCINOTIFY non-successful";
            err = (MCIERROR)g_mci_notify_code;
            goto out;
        }
        if (waited >= 600u)
        {
            g_paths.ret_buf[0] = 0;
            if (mciSendStringW( L"status selftest_mci mode", g_paths.ret_buf, 128, NULL ) == 0 &&
                lstrcmpiW( g_paths.ret_buf, L"stopped" ) == 0)
            {
                completed = TRUE;
                break;
            }
        }
        Sleep( 25 );
        waited += 25u;
    }
    elapsed_ms = GetTickCount() - t0;
    if (!completed) { step = "timeout waiting for MCI completion"; err = MCIERR_HARDWARE; goto out; }

    err = mciSendStringW( L"close selftest_mci", g_paths.ret_buf, 128, NULL );
    opened = FALSE;
    if (err != 0) { step = "mci close"; goto out; }
    ok = TRUE;

out:
    if (opened) mciSendStringW( L"close selftest_mci", g_paths.ret_buf, 128, NULL );
    if (hwnd) DestroyWindow( hwnd );

    if (ok)
    {
        write_str( "[6/6] PASS mci-mpeg: notify=" );
        write_uint( (DWORD)g_mci_notify_code );
        write_str( " elapsed=" );
        write_uint( elapsed_ms );
        write_str( "ms\n" );
    }
    else
    {
        write_str( "[6/6] FAIL mci-mpeg: step=" );
        write_str( step );
        write_str( " mci_err=" );
        write_uint( (DWORD)err );
        write_str( "\n" );
    }
    flush_log();
    return ok;
}

/* =========================================================================
 * Watchdog and process entry point (`_start`)
 * ========================================================================= */

static DWORD WINAPI watchdog_thread( LPVOID param )
{
    Sleep( WATCHDOG_TIMEOUT_MS );
    write_str( "[WATCHDOG] FAIL timed out after " );
    write_uint( WATCHDOG_TIMEOUT_MS / 1000u );
    write_str( "s in path " );
    write_uint( (DWORD)InterlockedCompareExchange( &g_current_stage, 0, 0 ) );
    write_str( "\n" );
    flush_log();
    ExitProcess( 6 );
    return 0;
}

void __cdecl start( void )
{
    DWORD failed = 0;
    HRESULT hr;

    init_exe_dir();
    init_log_file();

    write_str( "=== Madeira video-selftest-x86 (32-bit WoW64) ===\n" );
    write_str( "log: " );
    write_wstr( g_paths.log_path );
    write_str( "\n" );

    CreateThread( NULL, 0, watchdog_thread, NULL, 0, NULL );

    if (!stage_clip( L"video-selftest.wmv", selftest_wmv_bytes, (DWORD)sizeof(selftest_wmv_bytes),
                     g_paths.wmv_path, &g_paths.wmv_origin ) ||
        !stage_clip( L"video-selftest.mpg", selftest_mpg_bytes, (DWORD)sizeof(selftest_mpg_bytes),
                     g_paths.mpg_path, &g_paths.mpg_origin ))
    {
        write_str( "FATAL: failed to locate or extract test clips\n" );
        flush_log();
        ExitProcess( 99 );
    }
    make_file_url( g_paths.wmv_url, MAX_PATH + 16, g_paths.wmv_path );

    write_str( "wmv: " );
    write_wstr( g_paths.wmv_path );
    write_str( " (" );
    write_str( g_paths.wmv_origin );
    write_str( ")\nmpg: " );
    write_wstr( g_paths.mpg_path );
    write_str( " (" );
    write_str( g_paths.mpg_origin );
    write_str( ")\n" );
    flush_log();

    hr = CoInitializeEx( NULL, COINIT_APARTMENTTHREADED );
    if (FAILED( hr ))
    {
        write_str( "FATAL: CoInitializeEx failed hr=" );
        write_hex32( (DWORD)hr );
        write_str( "\n" );
        flush_log();
        ExitProcess( 99 );
    }

    InterlockedExchange( &g_current_stage, 1 );
    if (!run_path1_kirikiri2_wmv()) failed++;

    InterlockedExchange( &g_current_stage, 2 );
    if (!run_path2_kirikiri_mpeg1()) failed++;

    InterlockedExchange( &g_current_stage, 3 );
    if (!run_path3_dshow_renderfile()) failed++;

    InterlockedExchange( &g_current_stage, 4 );
    if (!run_path4_mf_session()) failed++;

    InterlockedExchange( &g_current_stage, 5 );
    if (!run_path5_mf_source_reader()) failed++;

    InterlockedExchange( &g_current_stage, 6 );
    if (!run_path6_mci_mpeg()) failed++;

    CoUninitialize();

    write_str( "=== SUMMARY: " );
    write_uint( 6u - failed );
    write_str( "/6 passed, " );
    write_uint( failed );
    write_str( " failed (exit=" );
    write_uint( failed );
    write_str( ") ===\n" );
    flush_log();

    if (g_log_file != INVALID_HANDLE_VALUE)
        CloseHandle( g_log_file );

    ExitProcess( failed );
}
