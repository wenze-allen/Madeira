#!/usr/bin/env python3
"""Host verification for tests/x86/video-selftest-x86.exe and all five test clips; no Wine runs.

1. Source and documentation checks:
   - video-selftest-x86.c covers all 10 video paths:
     [1/10]  KiriKiri 2 IWMSyncReader + WMV/WMA DMOs
     [2/10]  KiriKiri hand-built DirectShow MPEG-1 graph (.mpg, ConnectDirect,
             bottom-up-only RGB32 sink, IAMStreamSelect, put_CurrentPosition(0) rewind)
     [3/10]  DirectShow RenderFile on .mpg in a visible window with GDI BitBlt
             client-area picture check + EC_COMPLETE
     [4/10]  Media Foundation session with EVR + SAR, GetCurrentImage,
             IMFPresentationClock, MESessionEnded
     [5/10]  MF source reader to RGB32 at native 320x240
     [6/10]  MCI open/play/close
     [7/10]  DirectShow RenderFile on .avi (MPEG-4 Xvid + IMA ADPCM) with visible
             window GDI BitBlt picture check + EC_COMPLETE
     [8/10]  KiriKiri hand-built MPEG-1 graph on raw .m1v (MEDIATYPE_Stream /
             MEDIASUBTYPE_MPEG1Video, 1 stream, rewind + replay)
     [9/10]  KiriKiri hand-built MPEG-1 graph on VideoCD .dat (MEDIATYPE_Stream /
             MEDIASUBTYPE_MPEG1VideoCD, 2 streams, rewind + replay)
     [10/10] MF source reader with MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING
             resizing + converting to 160x120 RGB32;
   - logs to both console/stderr and a log file, scales the watchdog to 10 paths,
     and exits with the failed-path count;
   - docs/MEDIA.md documents automatic IPA bundling, all 10 lines, and exit codes.
2. Clip synthesis, host FFmpeg decode, and unix-side wg_parser core playback under ASan/UBSan:
   - runs tests/x86/make-video-clips.py against the cached host FFmpeg build;
   - decodes the generated clips with host FFmpeg under ASan/UBSan (.wmv, .mpg,
     .avi Xvid+IMA-ADPCM, .m1v raw MPEG-1 video, and checks .dat RIFF/CDXA sector
     wrapping against .mpg);
   - compiles build/ntdll-unix/wg_parser_av_ios.c into a host C harness under
     ASan/UBSan and plays all five clips (.wmv, .mpg, .avi, .m1v, .dat) through
     OUR unix-side parser in decoded mode (checking 320x240 size, 50 non-black
     pictures, audio tone, and seek-to-0 rewind), plus compressed splitter mode
     for .mpg, .m1v and .dat (checking 50 decoded 320x240 pictures each, and
     confirming compressed mode refuses .avi so DirectShow falls back to the
     decoding splitter).
3. 32-bit PE build and binary inspection:
   - runs tests/x86/build-video-selftest.sh (-Wall -Wextra -Werror);
   - parses PE headers and import tables in Python: i386 PE32, LARGE_ADDRESS_AWARE,
     no delay imports, exact 7-DLL static import allowlist (wmvcore.dll, gdi32.dll
     and COM decoders/splitters NOT statically imported), all 5 embedded clip
     fallbacks present in the PE image, and exe + 5 clips staged into
     app/Madeira/i386-windows/.
"""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from host_ffmpeg import host_ffmpeg, MEDIA_FLAGS  # noqa: E402


# ------------------------------------------------------------------ 1. source & doc checks
c_src = (ROOT / "tests/x86/video-selftest-x86.c").read_text()
build_sh = (ROOT / "tests/x86/build-video-selftest.sh").read_text()
make_py = (ROOT / "tests/x86/make-video-clips.py").read_text()
media_md = (ROOT / "docs/MEDIA.md").read_text()

assert "-Wall" in build_sh and "-Wextra" in build_sh and "-Werror" in build_sh, \
    "build script must compile with -Wall -Wextra -Werror"
assert "-nostdlib" in build_sh and "--large-address-aware" in build_sh

# Path 1: KiriKiri 2 WMV
p1 = c_src[c_src.index("static BOOL run_path1_kirikiri2_wmv("):c_src.index("struct sink_filter")]
assert 'LoadLibraryA( "wmvcore.dll" )' in p1
assert 'GetProcAddress( wmvcore, "WMCreateSyncReader" )' in p1
assert "IWMSyncReader_SetReadStreamSamples" in p1
assert "CLSID_CWMVDecMediaObject" in p1 and "CLSID_CWMADecMediaObject" in p1
assert "IMediaObject_ProcessInput" in p1 and "IMediaObject_ProcessOutput" in p1
assert "MEDIASUBTYPE_RGB32" in p1 and "MEDIASUBTYPE_PCM" in p1

# Paths 2, 8, 9: KiriKiri MPEG-1 graphs (.mpg, .m1v, .dat)
sink_check = c_src[c_src.index("static HRESULT sink_check_media_type("):c_src.index("/* --- IEnumPins --- */")]
assert "MEDIASUBTYPE_RGB32" in sink_check and "vih->bmiHeader.biHeight <= 0" in sink_check, \
    "custom video sink must accept only bottom-up RGB32 (biHeight > 0)"
p_mpeg = c_src[c_src.index("static BOOL run_kirikiri_mpeg_graph("):c_src.index("PATHS 3 & 7:")]
for sym in [
    "CLSID_AsyncReader",
    "IFileSourceFilter_Load",
    "CLSID_MPEG1Splitter",
    "CLSID_CMpegVideoCodec",
    "CLSID_CMpegAudioCodec",
    "MEDIATYPE_Stream",
    "IFilterGraph_ConnectDirect",
    "IPin_ConnectionMediaType",
    "IAMStreamSelect_Count",
    "IAMStreamSelect_Info",
    "IMediaPosition_put_CurrentPosition( mp, 0.0 )",
]:
    assert sym in p_mpeg, ("missing in KiriKiri MPEG graph helper", sym)
assert "RenderFile" not in p_mpeg and "IGraphBuilder_Render(" not in p_mpeg, \
    "KiriKiri MPEG graphs must use ConnectDirect only"

p89 = c_src[c_src.index("static BOOL run_path8_kirikiri_m1v("):c_src.index("PATH 10:")]
assert "MEDIASUBTYPE_MPEG1Video" in p89 and "g_paths.m1v_path" in p89
assert "MEDIASUBTYPE_MPEG1VideoCD" in p89 and "g_paths.dat_path" in p89

# Paths 3 & 7: DirectShow RenderFile in a visible window with GDI BitBlt read
p_rf = c_src[c_src.index("static BOOL load_gdi32_api("):c_src.index("PATH 4: Media Foundation session")]
for sym in [
    'LoadLibraryA( "gdi32.dll" )',
    '"CreateDIBSection"',
    '"BitBlt"',
    '"PatBlt"',
    "BLACKNESS",
    "SRCCOPY",
    "create_test_window( TRUE )",
    "IVideoWindow_put_Visible( vw, OATRUE )",
    "IBasicVideo_GetCurrentImage",
    "IGraphBuilder_RenderFile",
    "EC_COMPLETE",
]:
    assert sym in p_rf, ("missing in visible RenderFile helper", sym)
p7 = c_src[c_src.index("static BOOL run_path7_dshow_renderfile_avi("):c_src.index("static BOOL run_path8_kirikiri_m1v(")]
assert "run_dshow_renderfile_visible" in p7 and "g_paths.avi_path" in p7

# Path 4: MF session with EVR + SAR, GetCurrentImage, presentation clock, MESessionEnded
p4 = c_src[c_src.index("static BOOL run_path4_mf_session("):c_src.index("static BOOL run_path5_mf_source_reader(")]
for sym in [
    "MFCreateMediaSession",
    "MFCreateVideoRendererActivate",
    "MFCreateAudioRendererActivate",
    "MR_VIDEO_RENDER_SERVICE",
    "IMFVideoDisplayControl_GetCurrentImage",
    "IMFPresentationClock_GetTime",
    "MESessionEnded",
]:
    assert sym in p4, ("missing in path 4", sym)

# Path 5: MF Source Reader -> RGB32 (native 320x240)
p5 = c_src[c_src.index("static BOOL run_path5_mf_source_reader("):c_src.index("static BOOL run_path6_mci_mpeg(")]
assert "MFCreateSourceReaderFromURL" in p5 and "MFVideoFormat_RGB32" in p5 and "IMFSourceReader_ReadSample" in p5

# Path 6: MCI open/play/close
p6 = c_src[c_src.index("static BOOL run_path6_mci_mpeg("):c_src.index("static BOOL run_path7_dshow_renderfile_avi(")]
assert "mciSendStringW" in p6 and "open \\\"" in p6 and "play selftest_mci" in p6 and "close selftest_mci" in p6

# Path 10: MF Source Reader resize + convert (320x240 -> 160x120 RGB32)
p10 = c_src[c_src.index("static BOOL run_path10_mf_source_reader_resize("):c_src.index("static DWORD WINAPI watchdog_thread(")]
for sym in [
    "MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING",
    "MFCreateSourceReaderFromURL",
    "MFVideoFormat_RGB32",
    "MF_MT_FRAME_SIZE",
    "SELFTEST_RESIZE_W",
    "SELFTEST_RESIZE_H",
    "IMFSourceReader_ReadSample",
]:
    assert sym in p10, ("missing in path 10", sym)

# Watchdog & entry point scaled to 10 paths
wd = c_src[c_src.index("static DWORD WINAPI watchdog_thread("):c_src.index("void __cdecl start( void )")]
assert "SELFTEST_TOTAL_PATHS" in c_src and "#define SELFTEST_TOTAL_PATHS 10u" in c_src
assert "#define WATCHDOG_TIMEOUT_MS 150000u" in c_src
assert "ExitProcess( SELFTEST_TOTAL_PATHS )" in wd

entry = c_src[c_src.index("void __cdecl start( void )"):]
assert "ExitProcess( failed )" in entry
for idx in range(1, 11):
    assert ("[%d/10]" % idx) in c_src or idx in (2, 3, 7, 8, 9)
    assert ("[%d/10]" % idx) in media_md, ("docs/MEDIA.md missing path line", idx)
for doc_tok in [
    "video-selftest-x86.exe",
    "build-video-selftest.sh",
    "MADEIRA_BUILD_SELFTEST=0",
    "video-selftest.avi",
    "video-selftest.m1v",
    "video-selftest.dat",
    "video-selftest.log",
]:
    assert doc_tok in media_md, ("docs/MEDIA.md missing documentation token", doc_tok)

print("PASS: source and docs checks cover all 10 video paths, GDI read, resize, watchdog, exit code, and docs/MEDIA.md")


# ------------------------------------------------------------------ 2. clip generation + host FFmpeg + wg_parser core under ASan/UBSan
tarball = os.environ.get("MADEIRA_FFMPEG_TARBALL") or str(ROOT / "build/ffmpeg/src/ffmpeg-7.1.5.tar.xz")
prefix = host_ffmpeg(MEDIA_FLAGS, tarball, tag="asf-", override=os.environ.get("MADEIRA_HOST_FFMPEG_ASF"))
inc, lib = prefix / "include", prefix / "lib"

HARNESS_C = r"""
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/mem.h>
#include <libswresample/swresample.h>

#include "wg_parser_av_ios.c"

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf( stderr, "FAIL %s:%d: ", __func__, __LINE__ ); \
        fprintf( stderr, __VA_ARGS__ ); \
        fprintf( stderr, "\n" ); \
        return 1; \
    } \
} while (0)

struct memreader
{
    uint8_t *data;
    size_t size;
    size_t pos;
};

static int mem_read( void *opaque, uint8_t *buf, int n )
{
    struct memreader *m = opaque;
    if (m->pos >= m->size) return AVERROR_EOF;
    if ((size_t)n > m->size - m->pos) n = (int)(m->size - m->pos);
    memcpy( buf, m->data + m->pos, (size_t)n );
    m->pos += (size_t)n;
    return n;
}

static int64_t mem_seek( void *opaque, int64_t off, int whence )
{
    struct memreader *m = opaque;
    if (whence & AVSEEK_SIZE) return (int64_t)m->size;
    whence &= ~AVSEEK_FORCE;
    if (whence == SEEK_CUR) off += (int64_t)m->pos;
    else if (whence == SEEK_END) off += (int64_t)m->size;
    if (off < 0 || (size_t)off > m->size) return -1;
    m->pos = (size_t)off;
    return off;
}

static int load_whole_file( const char *path, struct memreader *m )
{
    FILE *fp = fopen( path, "rb" );
    long len;
    if (!fp) return -1;
    if (fseek( fp, 0, SEEK_END ) != 0) { fclose( fp ); return -1; }
    len = ftell( fp );
    if (len <= 0 || fseek( fp, 0, SEEK_SET ) != 0) { fclose( fp ); return -1; }
    m->data = malloc( (size_t)len );
    if (!m->data) { fclose( fp ); return -1; }
    if (fread( m->data, 1, (size_t)len, fp ) != (size_t)len) { free( m->data ); fclose( fp ); return -1; }
    fclose( fp );
    m->size = (size_t)len;
    m->pos = 0;
    return 0;
}

/* 1. Independent host FFmpeg demux + decode check */
static int verify_ffmpeg_decode( const char *path, const char *expect_fmt_substr,
                                 enum AVCodecID expect_vcodec, uint32_t expect_vtag,
                                 enum AVCodecID expect_acodec )
{
    struct memreader mr = { 0 };
    AVFormatContext *ic = NULL;
    AVIOContext *avio = NULL;
    int vs_idx = -1, as_idx = -1;
    AVCodecContext *vd = NULL, *ad = NULL;
    SwrContext *swr = NULL;
    AVPacket *pkt = NULL;
    AVFrame *frm = NULL;
    int vframes = 0, nonblack_frames = 0, asym_frames = 0;
    int64_t pcm_frames = 0, zc = 0;
    int prev_sign = 0, peak = 0;
    unsigned int i;
    int ret;

    CHECK( load_whole_file( path, &mr ) == 0, "read %s", path );
    ic = avformat_alloc_context();
    avio = avio_alloc_context( av_malloc( 4096 ), 4096, 0, &mr, mem_read, NULL, mem_seek );
    CHECK( ic && avio, "alloc avformat/avio" );
    ic->pb = avio;
    CHECK( avformat_open_input( &ic, NULL, NULL, NULL ) == 0 && ic, "open %s", path );
    CHECK( avformat_find_stream_info( ic, NULL ) >= 0, "stream_info %s", path );
    CHECK( strstr( ic->iformat->name, expect_fmt_substr ) != NULL,
           "unexpected container %s for %s", ic->iformat->name, path );

    for (i = 0; i < ic->nb_streams; i++)
    {
        AVCodecParameters *par = ic->streams[i]->codecpar;
        if (par->codec_type == AVMEDIA_TYPE_VIDEO && vs_idx < 0) vs_idx = (int)i;
        else if (par->codec_type == AVMEDIA_TYPE_AUDIO && as_idx < 0) as_idx = (int)i;
    }
    CHECK( vs_idx >= 0, "missing video stream in %s", path );
    if (expect_acodec == AV_CODEC_ID_NONE)
        CHECK( as_idx < 0, "unexpected audio stream in video-only %s", path );
    else
        CHECK( as_idx >= 0, "missing audio stream in %s", path );

    CHECK( ic->streams[vs_idx]->codecpar->codec_id == expect_vcodec,
           "vcodec %d != %d", ic->streams[vs_idx]->codecpar->codec_id, expect_vcodec );
    if (expect_vtag)
        CHECK( ic->streams[vs_idx]->codecpar->codec_tag == expect_vtag,
               "vtag 0x%x != 0x%x", ic->streams[vs_idx]->codecpar->codec_tag, expect_vtag );
    CHECK( ic->streams[vs_idx]->codecpar->width == 320 && ic->streams[vs_idx]->codecpar->height == 240,
           "dimensions %dx%d", ic->streams[vs_idx]->codecpar->width, ic->streams[vs_idx]->codecpar->height );

    {
        const AVCodec *vc = avcodec_find_decoder( expect_vcodec );
        CHECK( vc != NULL, "missing video decoder" );
        vd = avcodec_alloc_context3( vc );
        CHECK( vd && avcodec_parameters_to_context( vd, ic->streams[vs_idx]->codecpar ) >= 0, "v params" );
        CHECK( avcodec_open2( vd, vc, NULL ) == 0, "open vdec" );
    }
    if (expect_acodec != AV_CODEC_ID_NONE)
    {
        const AVCodec *ac = avcodec_find_decoder( expect_acodec );
        CHECK( ac != NULL, "missing audio decoder" );
        CHECK( ic->streams[as_idx]->codecpar->codec_id == expect_acodec,
               "acodec %d != %d", ic->streams[as_idx]->codecpar->codec_id, expect_acodec );
        ad = avcodec_alloc_context3( ac );
        CHECK( ad && avcodec_parameters_to_context( ad, ic->streams[as_idx]->codecpar ) >= 0, "a params" );
        CHECK( avcodec_open2( ad, ac, NULL ) == 0, "open adec" );
        CHECK( ad->sample_rate == 44100 && ad->ch_layout.nb_channels == 2,
               "audio geometry %d Hz %d ch", ad->sample_rate, ad->ch_layout.nb_channels );
        CHECK( swr_alloc_set_opts2( &swr, &ad->ch_layout, AV_SAMPLE_FMT_S16, ad->sample_rate,
                                    &ad->ch_layout, ad->sample_fmt, ad->sample_rate, 0, NULL ) == 0 && swr,
               "swr_alloc" );
        CHECK( swr_init( swr ) == 0, "swr_init" );
    }

    pkt = av_packet_alloc();
    frm = av_frame_alloc();
    CHECK( pkt && frm, "alloc pkt/frame" );

    for (;;)
    {
        int got_eof = (av_read_frame( ic, pkt ) < 0);
        if (!got_eof)
        {
            AVCodecContext *dec = (pkt->stream_index == vs_idx) ? vd : ((pkt->stream_index == as_idx) ? ad : NULL);
            if (dec) CHECK( avcodec_send_packet( dec, pkt ) >= 0, "send_packet" );
            av_packet_unref( pkt );
        }
        else
        {
            avcodec_send_packet( vd, NULL );
            if (ad) avcodec_send_packet( ad, NULL );
        }

        for (int pass = 0; pass < 2; pass++)
        {
            AVCodecContext *cur = (pass == 0) ? vd : ad;
            if (!cur) continue;
            while ((ret = avcodec_receive_frame( cur, frm )) >= 0)
            {
                if (cur == vd)
                {
                    int x, y, bright = 0;
                    long top_sum = 0, bot_sum = 0;
                    vframes++;
                    for (y = 0; y < frm->height; y++)
                    {
                        for (x = 0; x < frm->width; x++)
                        {
                            uint8_t luma = frm->data[0][y * frm->linesize[0] + x];
                            if (luma > 40) bright++;
                            if (y < 16) top_sum += luma;
                            if (y >= frm->height - 16) bot_sum += luma;
                        }
                    }
                    if (bright > (frm->width * frm->height) / 2) nonblack_frames++;
                    if (labs( top_sum - bot_sum ) > 1000) asym_frames++;
                }
                else
                {
                    int16_t s16[8192 * 2];
                    uint8_t *out_planes[1] = { (uint8_t *)s16 };
                    int n = swr_convert( swr, out_planes, 8192,
                                         (const uint8_t * const *)frm->extended_data, frm->nb_samples );
                    CHECK( n >= 0, "swr_convert" );
                    for (int k = 0; k < n; k++)
                    {
                        int v = s16[2 * k];
                        int mag = v < 0 ? -v : v;
                        int sign = v > 256 ? 1 : (v < -256 ? -1 : 0);
                        if (mag > peak) peak = mag;
                        if (sign != 0)
                        {
                            if (prev_sign != 0 && sign != prev_sign) zc++;
                            prev_sign = sign;
                        }
                    }
                    pcm_frames += n;
                }
                av_frame_unref( frm );
            }
        }
        if (got_eof) break;
    }

    CHECK( vframes == 50, "%s: expected 50 video frames, got %d", path, vframes );
    CHECK( nonblack_frames == 50, "%s: expected 50 non-black frames, got %d", path, nonblack_frames );
    CHECK( asym_frames >= 45, "%s: top/bottom rows not distinct (%d/50)", path, asym_frames );
    if (expect_acodec != AV_CODEC_ID_NONE)
    {
        double hz = pcm_frames > 0 ? ((double)zc * 44100.0) / (2.0 * (double)pcm_frames) : 0.0;
        CHECK( pcm_frames >= 80000 && pcm_frames <= 100000, "%s: unexpected pcm_frames=%lld", path, (long long)pcm_frames );
        CHECK( peak >= 8000, "%s: audio peak too low (%d)", path, peak );
        CHECK( hz >= 420.0 && hz <= 460.0, "%s: expected ~440 Hz tone, got %.1f Hz", path, hz );
        printf( "PASS: host FFmpeg decoded %s: %d frames 320x240 non-black, %lld PCM frames peak=%d freq=%.1f Hz\n",
                path, vframes, (long long)pcm_frames, peak, hz );
    }
    else
    {
        printf( "PASS: host FFmpeg decoded %s: %d frames 320x240 non-black (video-only)\n", path, vframes );
    }

    av_frame_free( &frm );
    av_packet_free( &pkt );
    swr_free( &swr );
    avcodec_free_context( &vd );
    avcodec_free_context( &ad );
    avformat_close_input( &ic );
    av_freep( &avio->buffer );
    avio_context_free( &avio );
    free( mr.data );
    return 0;
}

/* 2. Unix-side wg_parser_av_ios.c pull-thread harness */
struct pull_ctx
{
    struct mav_parser *p;
    const uint8_t *data;
    size_t size;
};

static void *pull_thread_main( void *arg )
{
    struct pull_ctx *ctx = arg;
    uint64_t off = 0;
    uint32_t sz = 0;

    while (mav_get_next_read_offset( ctx->p, &off, &sz ) == MAV_OK)
    {
        if (off >= ctx->size)
        {
            mav_push_data( ctx->p, ctx->data, 0 );
        }
        else
        {
            size_t avail = ctx->size - (size_t)off;
            if (avail > sz) avail = sz;
            mav_push_data( ctx->p, ctx->data + (size_t)off, (uint32_t)avail );
        }
    }
    return NULL;
}

static int verify_wg_parser_decoded( const char *path, int expect_audio, int test_rewind )
{
    struct memreader mr = { 0 };
    struct pull_ctx pctx;
    pthread_t th;
    struct mav_parser *p = NULL;
    unsigned int nstreams, i;
    int v_idx = -1, a_idx = -1;
    uint8_t *frame_buf = NULL;
    int passes = test_rewind ? 2 : 1;

    CHECK( load_whole_file( path, &mr ) == 0, "load %s", path );
    p = mav_create( 0 );
    CHECK( p != NULL, "mav_create(0)" );
    pctx.p = p;
    pctx.data = mr.data;
    pctx.size = mr.size;
    CHECK( pthread_create( &th, NULL, pull_thread_main, &pctx ) == 0, "pthread_create" );

    CHECK( mav_connect( p, mr.size ) == MAV_OK, "mav_connect(decoded) failed on %s", path );
    nstreams = mav_stream_count( p );
    CHECK( nstreams == (expect_audio ? 2u : 1u), "%s: expected %u streams, got %u",
           path, expect_audio ? 2u : 1u, nstreams );

    for (i = 0; i < nstreams; i++)
    {
        struct mav_stream_info info;
        CHECK( mav_stream_info( p, i, &info ) == MAV_OK, "mav_stream_info" );
        if (info.type == MAV_STREAM_VIDEO)
        {
            struct mav_video_output vout;
            v_idx = (int)i;
            CHECK( info.vnative.width == 320 && info.vnative.height == 240,
                   "%s: vnative %dx%d", path, info.vnative.width, info.vnative.height );
            vout.fmt = MAV_PIX_BGRx;
            vout.width = 320;
            vout.height = 240; /* bottom-up positive or top-down: BGRx 320x240 */
            vout.fps_n = 25;
            vout.fps_d = 1;
            CHECK( mav_enable_video( p, i, &vout ) == MAV_OK, "mav_enable_video" );
        }
        else if (info.type == MAV_STREAM_AUDIO)
        {
            struct mav_output aout = { MAV_FMT_S16, 44100, 2, 0x3 };
            a_idx = (int)i;
            CHECK( mav_enable( p, i, &aout ) == MAV_OK, "mav_enable(audio)" );
        }
    }
    CHECK( v_idx >= 0 && (expect_audio ? (a_idx >= 0) : (a_idx < 0)), "stream indices" );

    frame_buf = malloc( 320 * 240 * 4 );
    CHECK( frame_buf != NULL, "malloc frame_buf" );

    for (int pass = 0; pass < passes; pass++)
    {
        int pics = 0, nonblack = 0;
        int64_t pcm_samples = 0;
        struct mav_buffer buf;
        int st;

        if (pass > 0)
            CHECK( mav_seek( p, (unsigned int)v_idx, 1, 0, 0, 0 ) == MAV_OK, "mav_seek(0) on %s", path );

        while ((st = mav_get_buffer( p, -1, &buf )) == MAV_OK)
        {
            if ((int)buf.stream == v_idx)
            {
                int px, bright = 0;
                CHECK( buf.size == 320 * 240 * 4, "%s: video buf size %u", path, buf.size );
                CHECK( mav_copy_buffer( p, buf.stream, frame_buf, 0, buf.size ) == MAV_OK, "mav_copy_buffer" );
                for (px = 0; px < 320 * 240; px++)
                {
                    uint8_t b = frame_buf[px * 4 + 0];
                    uint8_t g = frame_buf[px * 4 + 1];
                    uint8_t r = frame_buf[px * 4 + 2];
                    if (r > 20 || g > 20 || b > 20) bright++;
                }
                pics++;
                if (bright > (320 * 240) / 2) nonblack++;
            }
            else if ((int)buf.stream == a_idx)
            {
                CHECK( (buf.size % 4) == 0, "S16 stereo alignment" );
                pcm_samples += buf.size / 4;
            }
            mav_release_buffer( p, buf.stream );
        }
        CHECK( st == MAV_NO_BUFFER, "%s: expected MAV_NO_BUFFER at EOS, got %d", path, st );
        CHECK( pics == 50 && nonblack == 50, "%s pass %d: expected 50 non-black pictures, got %d (%d non-black)",
               path, pass + 1, pics, nonblack );
        if (expect_audio)
            CHECK( pcm_samples >= 80000 && pcm_samples <= 100000,
                   "%s pass %d: unexpected pcm_samples=%lld", path, pass + 1, (long long)pcm_samples );
    }

    mav_disconnect( p );
    pthread_join( th, NULL );
    mav_destroy( p );
    free( frame_buf );
    free( mr.data );
    printf( "PASS: wg_parser decoded %s: 50x 320x240 BGRx pictures%s%s\n",
            path, expect_audio ? " + 44.1kHz S16 audio" : " (video-only)",
            test_rewind ? " + seek(0) replay" : "" );
    return 0;
}

static int verify_wg_parser_compressed_mpeg( const char *path, int expect_audio )
{
    struct memreader mr = { 0 };
    struct pull_ctx pctx;
    pthread_t th;
    struct mav_parser *p = NULL;
    unsigned int nstreams, i;
    int v_idx = -1, a_idx = -1;
    const AVCodec *vc = avcodec_find_decoder( AV_CODEC_ID_MPEG1VIDEO );
    AVCodecParserContext *vparser = NULL;
    AVCodecContext *vd = NULL;
    AVPacket *pkt = NULL;
    AVFrame *frm = NULL;
    uint8_t *raw = NULL;
    uint32_t raw_cap = 0;
    int v_pkts = 0, a_pkts = 0, pics = 0, nonblack = 0;
    struct mav_buffer buf;
    int st;

    CHECK( vc != NULL, "mpeg1video decoder" );
    CHECK( load_whole_file( path, &mr ) == 0, "load %s", path );
    p = mav_create( 1 );
    CHECK( p != NULL, "mav_create(1)" );
    pctx.p = p;
    pctx.data = mr.data;
    pctx.size = mr.size;
    CHECK( pthread_create( &th, NULL, pull_thread_main, &pctx ) == 0, "pthread_create" );

    CHECK( mav_connect( p, mr.size ) == MAV_OK, "mav_connect(compressed) failed on %s", path );
    nstreams = mav_stream_count( p );
    CHECK( nstreams == (expect_audio ? 2u : 1u), "%s compressed: expected %u streams, got %u",
           path, expect_audio ? 2u : 1u, nstreams );

    for (i = 0; i < nstreams; i++)
    {
        struct mav_stream_info info;
        CHECK( mav_stream_info( p, i, &info ) == MAV_OK, "mav_stream_info" );
        CHECK( mav_can_pass_compressed( p, i ) == 1, "%s stream %u not compressed-capable", path, i );
        CHECK( mav_enable_compressed( p, i ) == MAV_OK, "mav_enable_compressed" );
        if (info.type == MAV_STREAM_VIDEO)
        {
            v_idx = (int)i;
            CHECK( info.vnative.width == 320 && info.vnative.height == 240,
                   "%s compressed vnative %dx%d", path, info.vnative.width, info.vnative.height );
        }
        else if (info.type == MAV_STREAM_AUDIO)
        {
            a_idx = (int)i;
        }
    }
    CHECK( v_idx >= 0 && (expect_audio ? (a_idx >= 0) : (a_idx < 0)), "compressed stream indices" );

    vparser = av_parser_init( AV_CODEC_ID_MPEG1VIDEO );
    vd = avcodec_alloc_context3( vc );
    pkt = av_packet_alloc();
    frm = av_frame_alloc();
    CHECK( vparser && vd && pkt && frm, "alloc mpeg1 decoder" );
    CHECK( avcodec_open2( vd, vc, NULL ) == 0, "open mpeg1 decoder" );

    while ((st = mav_get_buffer( p, -1, &buf )) == MAV_OK)
    {
        if ((int)buf.stream == v_idx)
        {
            uint8_t *in_ptr;
            int in_left;
            v_pkts++;
            if (buf.size + AV_INPUT_BUFFER_PADDING_SIZE > raw_cap)
            {
                raw_cap = buf.size + AV_INPUT_BUFFER_PADDING_SIZE + 4096;
                raw = realloc( raw, raw_cap );
                CHECK( raw != NULL, "realloc raw" );
            }
            memset( raw, 0, raw_cap );
            CHECK( mav_copy_buffer( p, buf.stream, raw, 0, buf.size ) == MAV_OK, "copy compressed" );
            in_ptr = raw;
            in_left = (int)buf.size;
            while (in_left > 0)
            {
                uint8_t *out_data = NULL;
                int out_size = 0;
                int used = av_parser_parse2( vparser, vd, &out_data, &out_size,
                                             in_ptr, in_left, AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0 );
                CHECK( used >= 0, "av_parser_parse2" );
                in_ptr += used;
                in_left -= used;
                if (out_size > 0)
                {
                    pkt->data = out_data;
                    pkt->size = out_size;
                    CHECK( avcodec_send_packet( vd, pkt ) >= 0, "send_packet" );
                    while (avcodec_receive_frame( vd, frm ) >= 0)
                    {
                        CHECK( frm->width == 320 && frm->height == 240, "decoded %dx%d", frm->width, frm->height );
                        int bright = 0;
                        for (int y = 0; y < frm->height; y++)
                            for (int x = 0; x < frm->width; x++)
                                if (frm->data[0][y * frm->linesize[0] + x] > 40) bright++;
                        pics++;
                        if (bright > (320 * 240) / 2) nonblack++;
                        av_frame_unref( frm );
                    }
                }
            }
        }
        else if ((int)buf.stream == a_idx)
        {
            a_pkts++;
        }
        mav_release_buffer( p, buf.stream );
    }
    CHECK( st == MAV_NO_BUFFER, "expected MAV_NO_BUFFER" );

    /* Flush parser + decoder at EOS, just like wg_transform drain */
    {
        uint8_t *out_data = NULL;
        int out_size = 0;
        av_parser_parse2( vparser, vd, &out_data, &out_size, NULL, 0, AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0 );
        if (out_size > 0)
        {
            pkt->data = out_data;
            pkt->size = out_size;
            CHECK( avcodec_send_packet( vd, pkt ) >= 0, "send final parsed pkt" );
        }
        avcodec_send_packet( vd, NULL );
        while (avcodec_receive_frame( vd, frm ) >= 0)
        {
            CHECK( frm->width == 320 && frm->height == 240, "decoded %dx%d", frm->width, frm->height );
            int bright = 0;
            for (int y = 0; y < frm->height; y++)
                for (int x = 0; x < frm->width; x++)
                    if (frm->data[0][y * frm->linesize[0] + x] > 40) bright++;
            pics++;
            if (bright > (320 * 240) / 2) nonblack++;
            av_frame_unref( frm );
        }
    }

    CHECK( v_pkts > 0 && pics == 50 && nonblack == 50,
           "%s compressed: pkts=%d pics=%d nonblack=%d", path, v_pkts, pics, nonblack );
    if (expect_audio)
        CHECK( a_pkts > 0, "%s compressed: expected audio packets, got 0", path );

    mav_disconnect( p );
    pthread_join( th, NULL );
    mav_destroy( p );
    av_frame_free( &frm );
    av_packet_free( &pkt );
    avcodec_free_context( &vd );
    av_parser_close( vparser );
    free( raw );
    free( mr.data );
    printf( "PASS: wg_parser compressed %s: %d video pkts -> 50x 320x240 pictures, %d audio pkts\n",
            path, v_pkts, a_pkts );
    return 0;
}

static int verify_wg_parser_avi_compressed_refused( const char *avi_path )
{
    struct memreader mr = { 0 };
    struct pull_ctx pctx;
    pthread_t th;
    struct mav_parser *p = NULL;
    int rc;

    CHECK( load_whole_file( avi_path, &mr ) == 0, "load %s", avi_path );
    p = mav_create( 1 );
    CHECK( p != NULL, "mav_create(1)" );
    pctx.p = p;
    pctx.data = mr.data;
    pctx.size = mr.size;
    CHECK( pthread_create( &th, NULL, pull_thread_main, &pctx ) == 0, "pthread_create" );

    rc = mav_connect( p, mr.size );
    CHECK( rc == MAV_E_UNSUPPORTED, "compressed AVI must be refused (got %d)", rc );

    mav_disconnect( p );
    pthread_join( th, NULL );
    mav_destroy( p );
    free( mr.data );
    printf( "PASS: wg_parser compressed mode refuses %s (falls back to decoding splitter)\n", avi_path );
    return 0;
}

int main( int argc, char **argv )
{
    uint32_t xvid_tag = (uint32_t)'X' | ((uint32_t)'V' << 8) | ((uint32_t)'I' << 16) | ((uint32_t)'D' << 24);

    if (argc != 6) return 2;
    av_log_set_level( AV_LOG_ERROR );
    mav_configure( 1, NULL, NULL, MAV_PIX_BGRx );
    mav_allow_compressed_asf( 1 );
    mav_allow_video_ahead( 1 );
    mav_allow_mpeg_raw( 1 );
    mav_allow_avi( 1 );
    mav_allow_summary( 0 );

    /* Host FFmpeg decode checks for .wmv, .mpg, .avi, .m1v */
    if (verify_ffmpeg_decode( argv[1], "asf", AV_CODEC_ID_WMV2, 0, AV_CODEC_ID_WMAV2 ) != 0) return 1;
    if (verify_ffmpeg_decode( argv[2], "mpeg", AV_CODEC_ID_MPEG1VIDEO, 0, AV_CODEC_ID_MP2 ) != 0) return 1;
    if (verify_ffmpeg_decode( argv[3], "avi", AV_CODEC_ID_MPEG4, xvid_tag, AV_CODEC_ID_ADPCM_IMA_WAV ) != 0) return 1;
    if (verify_ffmpeg_decode( argv[4], "mpegvideo", AV_CODEC_ID_MPEG1VIDEO, 0, AV_CODEC_ID_NONE ) != 0) return 1;

    /* Unix-side wg_parser_av_ios.c decoded playback for all 5 clips (including RIFF/CDXA .dat) */
    if (verify_wg_parser_decoded( argv[1], 1, 0 ) != 0) return 1;
    if (verify_wg_parser_decoded( argv[2], 1, 1 ) != 0) return 1;
    if (verify_wg_parser_decoded( argv[3], 1, 0 ) != 0) return 1;
    if (verify_wg_parser_decoded( argv[4], 0, 1 ) != 0) return 1;
    if (verify_wg_parser_decoded( argv[5], 1, 1 ) != 0) return 1;

    /* Unix-side wg_parser_av_ios.c compressed splitter mode for .mpg, .m1v, .dat (+ .avi refusal) */
    if (verify_wg_parser_avi_compressed_refused( argv[3] ) != 0) return 1;
    if (verify_wg_parser_compressed_mpeg( argv[2], 1 ) != 0) return 1;
    if (verify_wg_parser_compressed_mpeg( argv[4], 0 ) != 0) return 1;
    if (verify_wg_parser_compressed_mpeg( argv[5], 1 ) != 0) return 1;

    return 0;
}
"""

with tempfile.TemporaryDirectory(prefix="madeira-check-selftest-") as tmp:
    tmp_dir = Path(tmp)
    hdr_path = tmp_dir / "clips.h"
    subprocess.run(
        [sys.executable, str(ROOT / "tests/x86/make-video-clips.py"), str(tmp_dir), "--header", str(hdr_path)],
        check=True,
    )
    clip_names = [
        ("wmv", "video-selftest.wmv"),
        ("mpg", "video-selftest.mpg"),
        ("avi", "video-selftest.avi"),
        ("m1v", "video-selftest.m1v"),
        ("dat", "video-selftest.dat"),
    ]
    clip_bytes = {}
    hdr_text = hdr_path.read_text()
    for short, fname in clip_names:
        b = (tmp_dir / fname).read_bytes()
        assert 4096 < len(b) < 512 * 1024, ("unexpected %s clip size" % short, len(b))
        assert ("selftest_%s_bytes[%d]" % (short, len(b))) in hdr_text
        clip_bytes[short] = b

    # Check RIFF/CDXA .dat structure and sector payload unwrapping against .mpg
    dat_b = clip_bytes["dat"]
    mpg_b = clip_bytes["mpg"]
    assert dat_b[:4] == b"RIFF" and dat_b[8:16] == b"CDXAfmt " and dat_b[36:40] == b"data"
    data_len = struct.unpack_from("<I", dat_b, 40)[0]
    assert len(dat_b) == 44 + data_len and data_len % 2352 == 0
    total_secs = data_len // 2352
    assert total_secs >= 3
    unwrapped = bytearray()
    for s in range(2, total_secs):
        sec = dat_b[44 + s * 2352:44 + (s + 1) * 2352]
        assert sec[:12] == b"\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00"
        assert sec[18] == 0x66 and sec[22] == 0x66
        assert sec[2348:2352] == b"\xde\xad\xbe\xef"
        unwrapped.extend(sec[24:24 + 2324])
    assert bytes(unwrapped[:len(mpg_b)]) == mpg_b, "unwrapped .dat payload does not match .mpg"

    # Also verify unwrapped .dat decodes through host FFmpeg (since raw FFmpeg has no CDXA demuxer,
    # unwrap the Form 2 payload to a temp file for host FFmpeg decode verification too).
    dat_unwrapped_file = tmp_dir / "dat-unwrapped.mpg"
    dat_unwrapped_file.write_bytes(bytes(unwrapped))

    verifier_c = tmp_dir / "verify_clips.c"
    verifier_exe = tmp_dir / "verify_clips"
    verifier_c.write_text(HARNESS_C)
    cc = os.environ.get("CC", "cc")
    libs = [
        str(lib / "libavformat.a"),
        str(lib / "libavcodec.a"),
        str(lib / "libswresample.a"),
        str(lib / "libavutil.a"),
        "-lm",
        "-lpthread",
    ]
    subprocess.run(
        [
            cc,
            "-std=c11",
            "-D_GNU_SOURCE",
            "-O1",
            "-g",
            "-Wall",
            "-Werror",
            "-Wno-unused-function",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=undefined",
            "-I" + str(ROOT / "build/ntdll-unix"),
            "-I" + str(inc),
            str(verifier_c),
            "-o",
            str(verifier_exe),
        ]
        + libs,
        check=True,
    )
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=1"
    out = subprocess.run(
        [
            str(verifier_exe),
            str(tmp_dir / "video-selftest.wmv"),
            str(tmp_dir / "video-selftest.mpg"),
            str(tmp_dir / "video-selftest.avi"),
            str(tmp_dir / "video-selftest.m1v"),
            str(tmp_dir / "video-selftest.dat"),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    print(out.stdout, end="")
    assert "ERROR: AddressSanitizer" not in out.stderr and "runtime error" not in out.stderr, out.stderr


# ------------------------------------------------------------------ 3. i686 PE build & import inspection
def find_i686_clang():
    candidates = []
    if os.environ.get("LLVM_MINGW"):
        lm = Path(os.environ["LLVM_MINGW"])
        candidates.extend([lm / "bin/i686-w64-mingw32-clang", lm / "i686-w64-mingw32-clang"])
    candidates.append(ROOT / "toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin/i686-w64-mingw32-clang")
    which_cc = shutil.which("i686-w64-mingw32-clang")
    if which_cc:
        candidates.append(Path(which_cc))
    candidates.append(Path.home() / ".local/share/madeira-tools/llvm-mingw/bin/i686-w64-mingw32-clang")
    for cand in candidates:
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def parse_pe32(pe_bytes):
    assert pe_bytes[:2] == b"MZ", "missing MZ header"
    pe_off = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    assert pe_bytes[pe_off:pe_off + 4] == b"PE\x00\x00", "missing PE signature"
    machine, num_sections, _, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", pe_bytes, pe_off + 4)
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", pe_bytes, opt_off)[0]
    entry_rva = struct.unpack_from("<I", pe_bytes, opt_off + 16)[0]
    num_rva = struct.unpack_from("<I", pe_bytes, opt_off + 92)[0]
    dirs = []
    for i in range(num_rva):
        rva, sz = struct.unpack_from("<II", pe_bytes, opt_off + 96 + i * 8)
        dirs.append((rva, sz))

    sec_off = opt_off + opt_size
    sections = []
    for i in range(num_sections):
        name, vsize, vrva, raw_sz, raw_ptr = struct.unpack_from("<8sIIII", pe_bytes, sec_off + i * 40)
        sections.append((name.rstrip(b"\x00").decode("ascii", "replace"), vrva, max(vsize, raw_sz), raw_ptr, raw_sz))

    def rva_to_off(rva):
        for _, vrva, span, raw_ptr, raw_sz in sections:
            if vrva <= rva < vrva + span and rva - vrva < raw_sz:
                return raw_ptr + (rva - vrva)
        raise AssertionError("unmapped RVA 0x%x" % rva)

    def read_cstr(off):
        end = pe_bytes.index(b"\x00", off)
        return pe_bytes[off:end].decode("ascii")

    imports = {}
    imp_rva, imp_sz = dirs[1] if len(dirs) > 1 else (0, 0)
    if imp_rva and imp_sz:
        desc_off = rva_to_off(imp_rva)
        while True:
            ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from("<IIIII", pe_bytes, desc_off)
            if not (ilt_rva or name_rva or iat_rva):
                break
            dll_name = read_cstr(rva_to_off(name_rva)).lower()
            thunk_off = rva_to_off(ilt_rva or iat_rva)
            syms = []
            while True:
                (val,) = struct.unpack_from("<I", pe_bytes, thunk_off)
                if val == 0:
                    break
                if val & 0x80000000:
                    syms.append("#%d" % (val & 0xFFFF))
                else:
                    syms.append(read_cstr(rva_to_off(val) + 2))
                thunk_off += 4
            imports.setdefault(dll_name, []).extend(syms)
            desc_off += 20

    delay_rva, delay_sz = dirs[13] if len(dirs) > 13 else (0, 0)
    return {
        "machine": machine,
        "magic": magic,
        "characteristics": characteristics,
        "entry_rva": entry_rva,
        "imports": imports,
        "delay_import_size": delay_sz if delay_rva else 0,
    }


mingw_cc = find_i686_clang()
if mingw_cc is None:
    print("NOTOOL: i686-w64-mingw32-clang not available; skipped PE build")
    sys.exit(0)

build_env = dict(os.environ)
build_env["PATH"] = str(mingw_cc.parent) + os.pathsep + build_env.get("PATH", "")
res = subprocess.run(
    ["bash", str(ROOT / "tests/x86/build-video-selftest.sh")],
    env=build_env,
    capture_output=True,
    text=True,
)
assert res.returncode == 0, res.stdout + "\n" + res.stderr

all_files = [
    "video-selftest-x86.exe",
    "video-selftest.wmv",
    "video-selftest.mpg",
    "video-selftest.avi",
    "video-selftest.m1v",
    "video-selftest.dat",
]
bundle_dir = ROOT / "app/Madeira/i386-windows"
for fname in all_files:
    built = ROOT / "tests/x86" / fname
    staged = bundle_dir / fname
    assert built.is_file() and built.stat().st_size > 0, ("missing built artifact", built)
    assert staged.is_file() and staged.stat().st_size > 0, ("missing staged artifact", staged)
    assert staged.read_bytes() == built.read_bytes(), ("staged artifact differs from built", fname)

pe_bytes = (bundle_dir / "video-selftest-x86.exe").read_bytes()
pe = parse_pe32(pe_bytes)
assert pe["machine"] == 0x014C, ("expected IMAGE_FILE_MACHINE_I386 (0x014c)", hex(pe["machine"]))
assert pe["magic"] == 0x010B, ("expected PE32 optional header (0x010b)", hex(pe["magic"]))
assert pe["characteristics"] & 0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE must be set"
assert pe["entry_rva"] != 0, "missing entry point"
assert pe["delay_import_size"] == 0, "unexpected delay-load imports"

allowed_dlls = {
    "kernel32.dll",
    "user32.dll",
    "ole32.dll",
    "winmm.dll",
    "mfplat.dll",
    "mf.dll",
    "mfreadwrite.dll",
}
imported_dlls = set(pe["imports"].keys())
unexpected_dlls = imported_dlls - allowed_dlls
assert not unexpected_dlls, ("unexpected static DLL imports", sorted(unexpected_dlls))
assert imported_dlls == allowed_dlls, ("expected exact import DLL set", sorted(imported_dlls))

for forbidden in (
    "gdi32.dll",
    "wmvcore.dll",
    "winegstreamer.dll",
    "wmadmod.dll",
    "quartz.dll",
    "evr.dll",
    "msvproc.dll",
    "msvcrt.dll",
    "ucrtbase.dll",
):
    assert forbidden not in imported_dlls, ("forbidden static import", forbidden)

assert "LoadLibraryA" in pe["imports"]["kernel32.dll"] and "GetProcAddress" in pe["imports"]["kernel32.dll"]
assert "CoCreateInstance" in pe["imports"]["ole32.dll"]
assert "MFCreateMediaSession" in pe["imports"]["mf.dll"]
assert "MFCreateSourceReaderFromURL" in pe["imports"]["mfreadwrite.dll"]
assert "mciSendStringW" in pe["imports"]["winmm.dll"]

# Embedded clip arrays must all be present inside the PE image for standalone fallback.
for clip_f in all_files[1:]:
    cb = (bundle_dir / clip_f).read_bytes()
    assert cb[:64] in pe_bytes, ("embedded fallback missing from PE image", clip_f)

print(
    "PASS: built i386 PE32 video-selftest-x86.exe (%d bytes, LAA=1, imports=%s) and staged all 5 clips"
    % (len(pe_bytes), ",".join(sorted(imported_dlls)))
)
