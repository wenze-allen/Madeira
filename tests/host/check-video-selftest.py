#!/usr/bin/env python3
"""Host verification for tests/x86/video-selftest-x86.exe and its WMV/MPEG-1 clips; no Wine runs.

1. Source and documentation checks:
   - video-selftest-x86.c covers all six VN video paths (KiriKiri 2 IWMSyncReader +
     WMV/WMA DMOs; KiriKiri hand-built DirectShow MPEG-1 graph with ConnectDirect,
     bottom-up-only RGB32 sink, IAMStreamSelect, and IMediaPosition::put_CurrentPosition(0)
     rewind; DirectShow RenderFile in a hidden window; Media Foundation session with
     EVR + SAR, IMFVideoDisplayControl::GetCurrentImage and IMFPresentationClock;
     MF source reader to RGB32; MCI open/play/close), logs to both console/stderr and
     a log file, and exits with the failed-path count;
   - docs/MEDIA.md documents how to run it on device and what each line and exit code means.
2. Clip synthesis and decode under ASan/UBSan:
   - runs tests/x86/make-video-clips.py against the cached host FFmpeg build
     (MEDIA_FLAGS in tests/host/host_ffmpeg.py);
   - compiles a C verifier under ASan/UBSan against the host FFmpeg libraries to
     demux and decode both video-selftest.wmv and video-selftest.mpg, checking
     container format, codecs, dimensions (320x240), frame counts (50), non-black
     picture content, top-vs-bottom row asymmetry, and the 440 Hz stereo audio tone.
3. 32-bit PE build and binary inspection:
   - runs tests/x86/build-video-selftest.sh (which compiles with -Wall -Werror);
   - parses PE headers and import tables directly in Python: i386 PE32,
     LARGE_ADDRESS_AWARE, no delay imports, static imports restricted to core
     system/MF/WinMM DLLs (wmvcore.dll and COM decoders/splitters NOT statically
     imported), embedded clip bytes present in the image, and exe + clips staged
     into app/Madeira/i386-windows/.
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

assert "-Wall" in build_sh and "-Werror" in build_sh, "build script must compile with -Wall -Werror"
assert "-nostdlib" in build_sh and "--large-address-aware" in build_sh

# Path 1: KiriKiri 2 WMV
p1 = c_src[c_src.index("static BOOL run_path1_kirikiri2_wmv("):c_src.index("static struct sink_filter")]
assert 'LoadLibraryA( "wmvcore.dll" )' in p1
assert 'GetProcAddress( wmvcore, "WMCreateSyncReader" )' in p1
assert "IWMSyncReader_SetReadStreamSamples" in p1
assert "CLSID_CWMVDecMediaObject" in p1 and "CLSID_CWMADecMediaObject" in p1
assert "IMediaObject_ProcessInput" in p1 and "IMediaObject_ProcessOutput" in p1
assert "MEDIASUBTYPE_RGB32" in p1 and "MEDIASUBTYPE_PCM" in p1

# Path 2: KiriKiri MPEG-1 (hand-built ConnectDirect, bottom-up RGB32 only, IAMStreamSelect, rewind)
sink_check = c_src[c_src.index("static HRESULT sink_check_media_type("):c_src.index("/* --- IEnumPins --- */")]
assert "MEDIASUBTYPE_RGB32" in sink_check and "vih->bmiHeader.biHeight <= 0" in sink_check, \
    "custom video sink must accept only bottom-up RGB32 (biHeight > 0)"
p2 = c_src[c_src.index("static BOOL run_path2_kirikiri_mpeg1("):c_src.index("PATH 3: DirectShow RenderFile")]
for sym in [
    "CLSID_AsyncReader",
    "IFileSourceFilter_Load",
    "CLSID_MPEG1Splitter",
    "CLSID_CMpegVideoCodec",
    "CLSID_CMpegAudioCodec",
    "IFilterGraph_ConnectDirect",
    "IPin_ConnectionMediaType",
    "IAMStreamSelect_Count",
    "IAMStreamSelect_Info",
    "IMediaPosition_put_CurrentPosition( mp, 0.0 )",
]:
    assert sym in p2, ("missing in path 2", sym)
assert "RenderFile" not in p2 and "IGraphBuilder_Render(" not in p2, "path 2 must use ConnectDirect only"

# Path 3: DirectShow RenderFile in hidden window -> EC_COMPLETE
p3 = c_src[c_src.index("static BOOL run_path3_dshow_renderfile("):c_src.index("static DWORD count_dib_nonblack(")]
assert "create_test_window( FALSE )" in p3 and "IGraphBuilder_RenderFile" in p3 and "EC_COMPLETE" in p3

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

# Path 5: MF Source Reader -> RGB32
p5 = c_src[c_src.index("static BOOL run_path5_mf_source_reader("):c_src.index("static BOOL run_path6_mci_mpeg(")]
assert "MFCreateSourceReaderFromURL" in p5 and "MFVideoFormat_RGB32" in p5 and "IMFSourceReader_ReadSample" in p5

# Path 6: MCI open/play/close
p6 = c_src[c_src.index("static BOOL run_path6_mci_mpeg("):c_src.index("static DWORD WINAPI watchdog_thread(")]
assert "mciSendStringW" in p6 and "open \\\"" in p6 and "play selftest_mci" in p6 and "close selftest_mci" in p6

# Entry point exits with failed count & docs cover running + output lines
entry = c_src[c_src.index("void __cdecl start( void )"):]
assert "ExitProcess( failed )" in entry
for doc_tok in [
    "video-selftest-x86.exe",
    "build-video-selftest.sh",
    "[1/6]",
    "[2/6]",
    "[3/6]",
    "[4/6]",
    "[5/6]",
    "[6/6]",
    "video-selftest.log",
]:
    assert doc_tok in media_md, ("docs/MEDIA.md missing documentation token", doc_tok)

print("PASS: source and docs checks cover all 6 video paths, log report, exit code, and docs/MEDIA.md")


# ------------------------------------------------------------------ 2. clip generation + host FFmpeg decode
tarball = os.environ.get("MADEIRA_FFMPEG_TARBALL") or str(ROOT / "build/ffmpeg/src/ffmpeg-7.1.5.tar.xz")
prefix = host_ffmpeg(MEDIA_FLAGS, tarball, tag="asf-", override=os.environ.get("MADEIRA_HOST_FFMPEG_ASF"))
inc, lib = prefix / "include", prefix / "lib"

DECODE_VERIFIER_C = r"""
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/mem.h>
#include <libswresample/swresample.h>

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

static int verify_clip( const char *path, const char *expect_fmt_substr,
                        enum AVCodecID expect_vcodec, enum AVCodecID expect_acodec )
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
    int ret, rc = 1;

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
    CHECK( vs_idx >= 0 && as_idx >= 0, "missing video/audio stream in %s", path );
    CHECK( ic->streams[vs_idx]->codecpar->codec_id == expect_vcodec,
           "vcodec %d != %d", ic->streams[vs_idx]->codecpar->codec_id, expect_vcodec );
    CHECK( ic->streams[as_idx]->codecpar->codec_id == expect_acodec,
           "acodec %d != %d", ic->streams[as_idx]->codecpar->codec_id, expect_acodec );
    CHECK( ic->streams[vs_idx]->codecpar->width == 320 && ic->streams[vs_idx]->codecpar->height == 240,
           "dimensions %dx%d", ic->streams[vs_idx]->codecpar->width, ic->streams[vs_idx]->codecpar->height );

    {
        const AVCodec *vc = avcodec_find_decoder( expect_vcodec );
        const AVCodec *ac = avcodec_find_decoder( expect_acodec );
        CHECK( vc && ac, "missing decoder in host FFmpeg" );
        vd = avcodec_alloc_context3( vc );
        ad = avcodec_alloc_context3( ac );
        CHECK( vd && ad, "alloc codec ctx" );
        CHECK( avcodec_parameters_to_context( vd, ic->streams[vs_idx]->codecpar ) >= 0, "v params" );
        CHECK( avcodec_parameters_to_context( ad, ic->streams[as_idx]->codecpar ) >= 0, "a params" );
        CHECK( avcodec_open2( vd, vc, NULL ) == 0, "open vdec" );
        CHECK( avcodec_open2( ad, ac, NULL ) == 0, "open adec" );
    }

    CHECK( ad->sample_rate == 44100 && ad->ch_layout.nb_channels == 2,
           "audio geometry %d Hz %d ch", ad->sample_rate, ad->ch_layout.nb_channels );
    CHECK( swr_alloc_set_opts2( &swr, &ad->ch_layout, AV_SAMPLE_FMT_S16, ad->sample_rate,
                                &ad->ch_layout, ad->sample_fmt, ad->sample_rate, 0, NULL ) == 0 && swr,
           "swr_alloc" );
    CHECK( swr_init( swr ) == 0, "swr_init" );

    pkt = av_packet_alloc();
    frm = av_frame_alloc();
    CHECK( pkt && frm, "alloc pkt/frame" );

    for (;;)
    {
        int got_eof = (av_read_frame( ic, pkt ) < 0);
        AVCodecContext *dec = NULL;

        if (!got_eof)
        {
            if (pkt->stream_index == vs_idx) dec = vd;
            else if (pkt->stream_index == as_idx) dec = ad;
            if (dec) CHECK( avcodec_send_packet( dec, pkt ) >= 0, "send_packet" );
            av_packet_unref( pkt );
        }
        else
        {
            avcodec_send_packet( vd, NULL );
            avcodec_send_packet( ad, NULL );
        }

        for (int pass = 0; pass < 2; pass++)
        {
            AVCodecContext *cur = (pass == 0) ? vd : ad;
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

    double hz = pcm_frames > 0 ? ((double)zc * 44100.0) / (2.0 * (double)pcm_frames) : 0.0;
    CHECK( vframes == 50, "%s: expected 50 video frames, got %d", path, vframes );
    CHECK( nonblack_frames == 50, "%s: expected 50 non-black frames, got %d", path, nonblack_frames );
    CHECK( asym_frames >= 45, "%s: top/bottom rows not distinct (%d/50)", path, asym_frames );
    CHECK( pcm_frames >= 80000 && pcm_frames <= 100000, "%s: unexpected pcm_frames=%lld", path, (long long)pcm_frames );
    CHECK( peak >= 8000, "%s: audio peak too low (%d)", path, peak );
    CHECK( hz >= 420.0 && hz <= 460.0, "%s: expected ~440 Hz tone, got %.1f Hz", path, hz );

    printf( "PASS: decoded %s: %d frames 320x240 non-black, %lld PCM frames peak=%d freq=%.1f Hz\n",
            path, vframes, (long long)pcm_frames, peak, hz );
    rc = 0;

    av_frame_free( &frm );
    av_packet_free( &pkt );
    swr_free( &swr );
    avcodec_free_context( &vd );
    avcodec_free_context( &ad );
    avformat_close_input( &ic );
    av_freep( &avio->buffer );
    avio_context_free( &avio );
    free( mr.data );
    return rc;
}

int main( int argc, char **argv )
{
    if (argc != 3) return 2;
    av_log_set_level( AV_LOG_ERROR );
    if (verify_clip( argv[1], "asf", AV_CODEC_ID_WMV2, AV_CODEC_ID_WMAV2 ) != 0) return 1;
    if (verify_clip( argv[2], "mpeg", AV_CODEC_ID_MPEG1VIDEO, AV_CODEC_ID_MP2 ) != 0) return 1;
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
    wmv_file = tmp_dir / "video-selftest.wmv"
    mpg_file = tmp_dir / "video-selftest.mpg"
    wmv_bytes = wmv_file.read_bytes()
    mpg_bytes = mpg_file.read_bytes()
    assert 4096 < len(wmv_bytes) < 512 * 1024, ("unexpected WMV clip size", len(wmv_bytes))
    assert 4096 < len(mpg_bytes) < 512 * 1024, ("unexpected MPG clip size", len(mpg_bytes))
    hdr_text = hdr_path.read_text()
    assert ("selftest_wmv_bytes[%d]" % len(wmv_bytes)) in hdr_text
    assert ("selftest_mpg_bytes[%d]" % len(mpg_bytes)) in hdr_text

    verifier_c = tmp_dir / "verify_clips.c"
    verifier_exe = tmp_dir / "verify_clips"
    verifier_c.write_text(DECODE_VERIFIER_C)
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
            "-O1",
            "-g",
            "-Wall",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=undefined",
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
    out = subprocess.run([str(verifier_exe), str(wmv_file), str(mpg_file)], env=env, capture_output=True, text=True, check=True)
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

exe_built = ROOT / "tests/x86/video-selftest-x86.exe"
wmv_built = ROOT / "tests/x86/video-selftest.wmv"
mpg_built = ROOT / "tests/x86/video-selftest.mpg"
bundle_dir = ROOT / "app/Madeira/i386-windows"
exe_staged = bundle_dir / "video-selftest-x86.exe"
wmv_staged = bundle_dir / "video-selftest.wmv"
mpg_staged = bundle_dir / "video-selftest.mpg"

for p in (exe_built, wmv_built, mpg_built, exe_staged, wmv_staged, mpg_staged):
    assert p.is_file() and p.stat().st_size > 0, ("missing build/staged artifact", p)

pe_bytes = exe_staged.read_bytes()
assert pe_bytes == exe_built.read_bytes(), "staged exe differs from built exe"
assert wmv_staged.read_bytes() == wmv_built.read_bytes(), "staged WMV differs"
assert mpg_staged.read_bytes() == mpg_built.read_bytes(), "staged MPG differs"

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

for forbidden in ("wmvcore.dll", "winegstreamer.dll", "wmadmod.dll", "quartz.dll", "evr.dll", "msvcrt.dll", "ucrtbase.dll"):
    assert forbidden not in imported_dlls, ("forbidden static import", forbidden)

assert "LoadLibraryA" in pe["imports"]["kernel32.dll"] and "GetProcAddress" in pe["imports"]["kernel32.dll"]
assert "CoCreateInstance" in pe["imports"]["ole32.dll"]
assert "MFCreateMediaSession" in pe["imports"]["mf.dll"]
assert "MFCreateSourceReaderFromURL" in pe["imports"]["mfreadwrite.dll"]
assert "mciSendStringW" in pe["imports"]["winmm.dll"]

# Embedded clip arrays must be present inside the PE image for standalone fallback.
assert wmv_staged.read_bytes()[:64] in pe_bytes, "embedded WMV fallback missing from PE image"
assert mpg_staged.read_bytes()[:64] in pe_bytes, "embedded MPG fallback missing from PE image"

print(
    "PASS: built i386 PE32 video-selftest-x86.exe (%d bytes, LAA=1, imports=%s) and staged clips (%d + %d bytes)"
    % (len(pe_bytes), ",".join(sorted(imported_dlls)), wmv_staged.stat().st_size, mpg_staged.stat().st_size)
)
