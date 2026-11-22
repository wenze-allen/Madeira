#!/usr/bin/env python3
"""MPEG-1/2 video (.mpg, MPEG program streams) through the wg_parser core and the wg_transform
decoders, on the host; no Wine runs.

Older visual novels play their movies as MPEG-1 program streams through DirectShow. A graph that
RenderFile builds takes winegstreamer's decoding splitter; KiriKiri's krmovie builds its graph by
hand (quartz's MPEG-1 splitter, then CLSID_CMpegVideoCodec and CLSID_CMpegAudioCodec, into its
RGB32 buffer renderer or VMR-9), and BURIKO reads the picture size from the splitter's compressed
MPEG video format while connecting (krkrwine's notes and code). This port's parser knew no MPEG
program stream, and its wg_transform no MPEG decoder.

1. Source checks: build/ffmpeg/build.sh enables the mpegps and mpegvideo demuxers, the
   mpeg1video/mpeg2video decoders and the mpegvideo parser (still no H.264/HEVC/AAC); the glue
   reports and enables MPEG-1 video and MPEG audio as compressed formats; the MPEG audio decoder is
   a row of transform_kinds before the WMA decoder; the facts of the Wine pin this relies on
   (quartz's MPEG-1 splitter takes only those two formats, the decoders' probes).
2. Host FFmpeg (tests/host/host_ffmpeg.py MEDIA_FLAGS, shared with the ASF and WMV checks) with
   TEST-ONLY mpeg1video/mpeg2video/mp2 encoders and the mpeg/dvd/raw muxers.
3. The core under ASan/UBSan (and the threaded cases again under ThreadSanitizer):
   - an MPEG-1 program stream (mpeg1video with B-frames, MP2 audio): every picture bit-exact in
     NV12 against an independent decode, in order; one clock for audio and video (the streams
     keep the offset they have in the file); the tone; decoded ahead on a worker; an exact seek;
     a rewind to 0 after reading to the end (KiriKiri's put_CurrentPosition(0));
   - compressed output, as quartz's MPEG-1 splitter reads it: every packet of both streams with
     the file's bytes and keyframe flags; MADEIRA_WG_COMPRESSED=0 refuses the file;
   - an MPEG-2 program stream (the dvd muxer): decoded bit-exact; its video not passed compressed
     (no wg_format), its audio is;
   - an MPEG-1 elementary stream (.m1v) is refused: it has no presentation times to play or seek by,
     and quartz's MPEG-1 splitter does not take one either.
4. The glue under ASan/UBSan, through the unix call table (needs a configured Wine tree's headers,
   MADEIRA_WINE_BUILD, like check-wmv-transform.py):
   - BURIKO's and KiriKiri's splitter: a compressed-output parser reports WG_MAJOR_TYPE_VIDEO_MPEG1
     with the picture size and frame rate and WG_MAJOR_TYPE_AUDIO_MPEG1 with layer, rate and
     channels, and hands out packets once enabled with them;
   - the MPEG video decoder: quartz's probe (MPEG1Payload 1920x1080 to NV12, no sequence header);
     the elementary stream pushed in 997-byte pieces, every picture bit-exact; MPEG-2; RGB32
     bottom-up (KiriKiri's buffer renderer takes RGB32/ARGB32 bottom-up), every pixel within 1 of
     BT.601;
   - the MPEG audio decoder: quartz's probes (WAVE_FORMAT_MPEG layer II, MPEGLAYER3, to PCM16);
     MP2 pushed in 333-byte pieces to S16 and to float, the tone, gap-free timestamps; refusals;
   and again with MADEIRA_WG_MPEG_TRANSFORM=0: MPEG audio refused.
Needs python3, a C compiler and the FFmpeg tarball (build/ffmpeg/src).
"""
from pathlib import Path
import os, re, subprocess, sys, tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_ffmpeg import host_ffmpeg, MEDIA_FLAGS   # the shared host build, made under a lock

root = Path(__file__).resolve().parents[2]
ntdll_unix = root / "build/ntdll-unix"
core = ntdll_unix / "wg_parser_av_ios.c"
glue = (ntdll_unix / "winegstreamer_unixlib_ios.c").read_text()
wine = Path(os.environ.get("MADEIRA_WINE_SRC") or root / "wine")
wine_build = Path(os.environ.get("MADEIRA_WINE_BUILD") or wine / "build-macos")


def body(text, start, end="\n}\n"):
    a = text.index(start)
    return text[a:text.index(end, a)]


# ------------------------------------------------------------------ 1. source checks
ff = (root / "build/ffmpeg/build.sh").read_text()
args = ff[ff.index("CONFIG_ARGS=("):]
args = args[:args.index("\n)\n")]
assert "--enable-demuxer=mp3,wav,mov,asf,mpegps,mpegvideo" in args, "the MPEG program stream demuxer (and mpegvideo, its video probe)"
assert "--enable-decoder=mpeg1video,mpeg2video" in args, "the MPEG-1/2 video decoders"
assert "--enable-parser=mpegaudio,mpegvideo" in args, "the MPEG video parser"
for bad in ["h264", "hevc", "aac"]:
    assert not re.search(r"--enable-(decoder|parser)=[^\n]*\b%s\b" % bad, args), ("platform-decoded codec enabled", bad)
for flag in ["--disable-gpl", "--disable-nonfree", "--disable-version3", "--disable-everything"]:
    assert flag in args, ("LGPL-only configuration", flag)
codec_fmt = body(glue, "static NTSTATUS wgp_get_codec_format( wg_parser_stream_t handle, struct wg_format *format )\n{")
assert "case MAV_CODEC_MPEG_VIDEO:" in codec_fmt and "WG_MAJOR_TYPE_VIDEO_MPEG1" in codec_fmt
enable = body(glue, "static NTSTATUS wgp_enable(")
assert "WG_MAJOR_TYPE_VIDEO_MPEG1" in enable and "WG_MAJOR_TYPE_AUDIO_MPEG1" in enable
kinds = glue[glue.index("static const struct wg_transform_ops *const transform_kinds[] ="):]
kinds = kinds[:kinds.index("};")]
assert kinds.index("&mpa_transform_ops") < kinds.index("&wma_transform_ops"), "MPEG audio claimed before WMA"
assert 'getenv( "MADEIRA_WG_MPEG_TRANSFORM" )' in glue
parser = (wine / "dlls/winegstreamer/quartz_parser.c")
transform = (wine / "dlls/winegstreamer/quartz_transform.c")
if parser.exists() and transform.exists():
    qp = body(parser.read_text(), "static BOOL mpeg_splitter_filter_init_gst(")
    assert "WG_MAJOR_TYPE_VIDEO_MPEG1" in qp and "WG_MAJOR_TYPE_AUDIO_MPEG1" in qp, "the splitter takes only these"
    qt = transform.read_text()
    vprobe = body(qt, "HRESULT mpeg_video_codec_create(")
    assert "MEDIASUBTYPE_MPEG1Payload" in vprobe and "MEDIASUBTYPE_NV12" in vprobe and "1920" in vprobe
    aprobe = body(qt, "HRESULT mpeg_audio_codec_create(")
    assert "WAVE_FORMAT_MPEG" in aprobe and ".fwHeadLayer = 2" in aprobe
    l3probe = body(qt, "HRESULT mpeg_layer3_decoder_create(")
    assert "WAVE_FORMAT_MPEGLAYER3" in l3probe
    print("PASS: Wine's MPEG-1 splitter takes MPEG-1 video and MPEG audio only; the MPEG decoders' probes are "
          "the ones tested below")
print("PASS: FFmpeg has the MPEG program stream demuxer, the MPEG-1/2 decoders and parser (still "
      "no H.264/HEVC/AAC); the glue maps MPEG-1 video and MPEG audio compressed; MPEG audio is a transform kind")

# ------------------------------------------------------------------ 2. host FFmpeg
tarball = os.environ.get("MADEIRA_FFMPEG_TARBALL") or str(root / "build/ffmpeg/src/ffmpeg-7.1.5.tar.xz")
prefix = host_ffmpeg(MEDIA_FLAGS, tarball, tag="asf-", override=os.environ.get("MADEIRA_HOST_FFMPEG_ASF"))
inc, lib = prefix / "include", prefix / "lib"

# ------------------------------------------------------------------ shared C: inputs and references
common = r"""
#include <math.h>
#include <libavformat/avformat.h>

#define W 320
#define H 240
#define FPS 25
#define GOP 12
#define FRAMES 100              /* 4 s */
#define RATE 44100
#define TICK (10000000 / FPS)

/* ---- an encoded file in memory ---- */
struct membuf { uint8_t *data; size_t size, cap, pos; };
static int mem_write( void *o, const uint8_t *buf, int n )
{
    struct membuf *m = o;
    if (m->pos + n > m->cap) { m->cap = (m->pos + n) * 2; m->data = realloc( m->data, m->cap ); }
    memcpy( m->data + m->pos, buf, n ); m->pos += n; if (m->pos > m->size) m->size = m->pos;
    return n;
}
static int mem_read( void *o, uint8_t *buf, int n )
{
    struct membuf *m = o;
    if (m->pos >= m->size) return AVERROR_EOF;
    if ((size_t)n > m->size - m->pos) n = (int)(m->size - m->pos);
    memcpy( buf, m->data + m->pos, n ); m->pos += n;
    return n;
}
static int64_t mem_seek( void *o, int64_t off, int whence )
{
    struct membuf *m = o;
    if (whence & AVSEEK_SIZE) return m->size;
    whence &= ~AVSEEK_FORCE;
    if (whence == SEEK_CUR) off += m->pos; else if (whence == SEEK_END) off += m->size;
    if (off < 0) return -1;
    m->pos = off;
    return off;
}

static void put( AVFormatContext *oc, AVCodecContext *e, AVStream *st, AVFrame *f )
{
    AVPacket *pkt = av_packet_alloc();
    avcodec_send_frame( e, f );
    while (avcodec_receive_packet( e, pkt ) >= 0)
    {
        av_packet_rescale_ts( pkt, e->time_base, st->time_base );
        pkt->stream_index = st->index;
        av_interleaved_write_frame( oc, pkt );
    }
    av_packet_free( &pkt );
}

/* `muxer`: "mpeg" (MPEG-1 system), "dvd" (MPEG-2 program stream), "mpeg1video" / "mpeg2video" (the
 * video alone), "mp2" (the audio alone).  A moving pattern with B-frames, a 440 Hz MP2 tone. */
static uint8_t *make_mpeg( const char *muxer, enum AVCodecID vcodec, int audio, size_t *size )
{
    struct membuf m = {0};
    AVFormatContext *oc = NULL; AVCodecContext *ve = NULL, *ae = NULL; AVStream *vs = NULL, *as = NULL;
    AVFrame *vf = av_frame_alloc(), *af = av_frame_alloc(); int64_t apts = 0; int i, x, y;

    if (avformat_alloc_output_context2( &oc, NULL, muxer, NULL ) < 0 || !oc) return NULL;
    oc->pb = avio_alloc_context( av_malloc( 4096 ), 4096, 1, &m, NULL, mem_write, mem_seek );
    if (vcodec)
    {
        vs = avformat_new_stream( oc, NULL );
        ve = avcodec_alloc_context3( avcodec_find_encoder( vcodec ) );
        ve->width = W; ve->height = H; ve->time_base = (AVRational){ 1, FPS }; ve->framerate = (AVRational){ FPS, 1 };
        ve->pix_fmt = AV_PIX_FMT_YUV420P; ve->gop_size = GOP; ve->max_b_frames = 2; ve->bit_rate = 1500000;
        if (avcodec_open2( ve, ve->codec, NULL ) < 0) return NULL;
        avcodec_parameters_from_context( vs->codecpar, ve );
        vs->time_base = ve->time_base;
    }
    if (audio)
    {
        as = avformat_new_stream( oc, NULL );
        ae = avcodec_alloc_context3( avcodec_find_encoder( AV_CODEC_ID_MP2 ) );
        ae->sample_rate = RATE; ae->sample_fmt = AV_SAMPLE_FMT_S16; ae->bit_rate = 192000;
        av_channel_layout_default( &ae->ch_layout, 2 ); ae->time_base = (AVRational){ 1, RATE };
        if (avcodec_open2( ae, ae->codec, NULL ) < 0) return NULL;
        avcodec_parameters_from_context( as->codecpar, ae );
        as->time_base = ae->time_base;
    }
    if (avformat_write_header( oc, NULL ) < 0) return NULL;
    vf->format = AV_PIX_FMT_YUV420P; vf->width = W; vf->height = H; av_frame_get_buffer( vf, 0 );
    if (ae)
    {
        af->format = ae->sample_fmt; af->nb_samples = ae->frame_size; af->sample_rate = RATE;
        av_channel_layout_copy( &af->ch_layout, &ae->ch_layout ); av_frame_get_buffer( af, 0 );
    }
    for (i = 0; i < FRAMES; i++)
    {
        if (ve)
        {
            av_frame_make_writable( vf );
            for (y = 0; y < H; y++) for (x = 0; x < W; x++)
            {
                int box = x >= 20 + 3 * i && x < 70 + 3 * i && y >= 40 + i && y < 100 + i;
                vf->data[0][y * vf->linesize[0] + x] = box ? 220 : (uint8_t)(32 + ((x + 3 * i) / 16 % 2) * 120 + y / 4);
            }
            for (y = 0; y < H / 2; y++) for (x = 0; x < W / 2; x++)
            {
                vf->data[1][y * vf->linesize[1] + x] = (uint8_t)(90 + x / 2 + i);
                vf->data[2][y * vf->linesize[2] + x] = (uint8_t)(170 - y / 2);
            }
            vf->pts = i;
            put( oc, ve, vs, vf );
        }
        while (ae && apts * FPS < (int64_t)(i + 1) * RATE)
        {
            int n;
            av_frame_make_writable( af );
            for (n = 0; n < af->nb_samples; n++)
            {
                int16_t v = (int16_t)lrint( 0.4 * 32767 * sin( 2 * M_PI * 440 * (double)(apts + n) / RATE ) );
                ((int16_t *)af->data[0])[2 * n] = ((int16_t *)af->data[0])[2 * n + 1] = v;
            }
            af->pts = apts; apts += af->nb_samples;
            put( oc, ae, as, af );
        }
    }
    if (ve) put( oc, ve, vs, NULL );
    if (ae) put( oc, ae, as, NULL );
    av_write_trailer( oc );
    av_freep( &oc->pb->buffer );
    avio_context_free( &oc->pb );
    avformat_free_context( oc );
    avcodec_free_context( &ve ); avcodec_free_context( &ae ); av_frame_free( &vf ); av_frame_free( &af );
    *size = m.size;
    return m.data;
}

/* ---- the reference: the same file demuxed and decoded by libavformat + libavcodec directly ---- */
#define REF_SIZE (W * H * 3 / 2)
static uint8_t *ref_frames;     /* Y, U, V planes */
static int ref_count;
struct refpkt { int stream, key, size; int64_t pts; uint8_t *data; };
static struct refpkt *ref_pkts;
static int ref_pkt_count;
static int64_t ref_start[2];    /* the video's and the audio's first pts, 100 ns, from the file's earliest start */

static void free_reference( void )
{
    int i;
    for (i = 0; i < ref_pkt_count; i++) free( ref_pkts[i].data );
    free( ref_pkts ); ref_pkts = NULL; ref_pkt_count = 0;
    free( ref_frames ); ref_frames = NULL; ref_count = 0;
}

static int make_reference( const uint8_t *data, size_t size )
{
    struct membuf m = { (uint8_t *)data, size, size, 0 };
    AVFormatContext *fc = avformat_alloc_context(); AVCodecContext *d = NULL; AVPacket *pkt = av_packet_alloc();
    AVFrame *f = av_frame_alloc(); int vi = -1, y, eof; unsigned int i; int64_t start;

    free_reference();
    fc->pb = avio_alloc_context( av_malloc( 4096 ), 4096, 0, &m, mem_read, NULL, mem_seek );
    if (avformat_open_input( &fc, NULL, NULL, NULL ) || avformat_find_stream_info( fc, NULL ) < 0) return 1;
    start = fc->start_time == AV_NOPTS_VALUE ? 0 : fc->start_time;   /* an elementary stream has none */
    for (i = 0; i < fc->nb_streams; i++)
    {
        AVStream *st = fc->streams[i];
        int kind = st->codecpar->codec_type == AVMEDIA_TYPE_VIDEO ? 0 : 1;
        if (!kind) vi = i;
        ref_start[kind] = st->start_time == AV_NOPTS_VALUE ? 0
                         : av_rescale_q( st->start_time, st->time_base, (AVRational){ 1, 10000000 } )
                           - av_rescale_q( start, AV_TIME_BASE_Q, (AVRational){ 1, 10000000 } );
    }
    if (vi >= 0)
    {
        d = avcodec_alloc_context3( avcodec_find_decoder( fc->streams[vi]->codecpar->codec_id ) );
        avcodec_parameters_to_context( d, fc->streams[vi]->codecpar ); d->thread_count = 1;
        if (avcodec_open2( d, d->codec, NULL ) < 0) return 1;
    }
    ref_frames = calloc( FRAMES + 8, REF_SIZE );
    for (eof = 0; !eof;)
    {
        eof = av_read_frame( fc, pkt ) < 0;
        if (!eof && pkt->size)
        {
            struct refpkt *r;
            ref_pkts = realloc( ref_pkts, (ref_pkt_count + 1) * sizeof(*ref_pkts) );
            r = &ref_pkts[ref_pkt_count++];
            r->stream = pkt->stream_index; r->key = !!(pkt->flags & AV_PKT_FLAG_KEY); r->size = pkt->size;
            r->pts = pkt->pts == AV_NOPTS_VALUE ? INT64_MIN
                   : av_rescale_q( pkt->pts - av_rescale_q( start, AV_TIME_BASE_Q, fc->streams[pkt->stream_index]->time_base ),
                                   fc->streams[pkt->stream_index]->time_base, (AVRational){ 1, 10000000 } );
            r->data = malloc( pkt->size ); memcpy( r->data, pkt->data, pkt->size );
        }
        if (d && (eof || pkt->stream_index == vi))
        {
            avcodec_send_packet( d, eof ? NULL : pkt );
            while (avcodec_receive_frame( d, f ) >= 0)
            {
                uint8_t *o = ref_frames + (size_t)ref_count * REF_SIZE;
                if (f->format != AV_PIX_FMT_YUV420P || f->width != W || f->height != H || ref_count >= FRAMES + 8) return 1;
                for (y = 0; y < H; y++) memcpy( o + y * W, f->data[0] + y * f->linesize[0], W );
                for (y = 0; y < H / 2; y++)
                {
                    memcpy( o + W * H + y * (W / 2), f->data[1] + y * f->linesize[1], W / 2 );
                    memcpy( o + W * H * 5 / 4 + y * (W / 2), f->data[2] + y * f->linesize[2], W / 2 );
                }
                ref_count++;
                av_frame_unref( f );
            }
        }
        av_packet_unref( pkt );
    }
    avcodec_free_context( &d ); av_frame_free( &f ); av_packet_free( &pkt );
    av_freep( &fc->pb->buffer ); avio_context_free( &fc->pb ); avformat_close_input( &fc );
    return 0;
}

static int RY( int i, int x, int y ) { return ref_frames[(size_t)i * REF_SIZE + y * W + x]; }
static int RU( int i, int x, int y ) { return ref_frames[(size_t)i * REF_SIZE + W * H + (y / 2) * (W / 2) + x / 2]; }
static int RV( int i, int x, int y ) { return ref_frames[(size_t)i * REF_SIZE + W * H * 5 / 4 + (y / 2) * (W / 2) + x / 2]; }

/* NV12 (Y rows of `stride`, then interleaved CbCr) against reference picture `idx`, exactly */
static int nv12_matches( const uint8_t *buf, uint32_t stride, int idx )
{
    int x, y;
    for (y = 0; y < H; y++) for (x = 0; x < W; x++)
    {
        if (buf[(size_t)y * stride + x] != RY( idx, x, y )) return 0;
        if (!(y & 1) && !(x & 1) && (buf[(size_t)stride * H + (y / 2) * stride + x] != RU( idx, x, y )
                                     || buf[(size_t)stride * H + (y / 2) * stride + x + 1] != RV( idx, x, y )))
            return 0;
    }
    return 1;
}

/* the tone's fundamental and rms over the middle half of interleaved stereo samples */
static void analyse( const double *s, size_t frames, double *freq, double *rms )
{
    size_t a = frames / 4, b = frames - frames / 4, i, crossings = 0; double e = 0;
    for (i = a; i < b; i++)
    {
        e += s[i] * s[i];
        if (i > a && (s[i - 1] < 0) != (s[i] < 0)) crossings++;
    }
    *rms = sqrt( e / (b - a) );
    *freq = crossings / 2.0 * RATE / (b - a);
}
"""

core_harness = r"""
#include "wg_parser_av_ios.c"
#include <signal.h>
""" + common + r"""
static int failures;
#define CHECK(c, ...) do { if (!(c)) { printf( "FAIL %s:%d: ", __func__, __LINE__ ); printf( __VA_ARGS__ ); printf( "\n" ); fflush( stdout ); failures++; return 1; } } while (0)

/* ---- the PE side: media_source.c / quartz_parser.c read_thread() ---- */
struct source { const uint8_t *data; size_t size; volatile int running; struct mav_parser *p; pthread_t thread; };
static void *read_thread( void *arg )
{
    struct source *s = arg;
    while (__atomic_load_n( &s->running, __ATOMIC_ACQUIRE ))
    {
        uint64_t offset; uint32_t size;
        if (mav_get_next_read_offset( s->p, &offset, &size )) { usleep( 200 ); continue; }
        if (offset >= s->size) size = 0;
        else if (offset + size >= s->size) size = s->size - offset;
        mav_push_data( s->p, size ? s->data + offset : s->data, size );
    }
    return NULL;
}
static void src_start( struct source *s, struct mav_parser *p, const uint8_t *data, size_t size )
{
    memset( s, 0, sizeof(*s) ); s->data = data; s->size = size; s->p = p; s->running = 1;
    pthread_create( &s->thread, NULL, read_thread, s );
}
static void src_stop( struct source *s ) { mav_disconnect( s->p ); __atomic_store_n( &s->running, 0, __ATOMIC_RELEASE ); pthread_join( s->thread, NULL ); }

/* Decoded: every picture bit-exact in order, the tone, one clock, an exact seek, a rewind to 0. */
static int test_decoded( const uint8_t *data, size_t size, const char *name, const char *container, const char *codec,
                         int version, int audio )
{
    struct mav_parser *p = mav_create( 0 ); struct source s; struct mav_stream_info vi, ai; struct mav_buffer b;
    uint8_t *pic = malloc( REF_SIZE ); double *pcm = NULL; size_t frames = 0, cap = 0; int n = 0;
    int64_t first_v = -1, first_a = -1, target; double freq = 0, rms = 0;

    CHECK( !make_reference( data, size ) && ref_count == FRAMES, "%s: reference: %d pictures", name, ref_count );
    src_start( &s, p, data, size );
    CHECK( mav_connect( p, size ) == MAV_OK, "%s: connect", name );
    CHECK( (int)mav_stream_count( p ) == 1 + audio && mav_stream_info( p, 0, &vi ) == MAV_OK, "%s: streams", name );
    CHECK( vi.type == MAV_STREAM_VIDEO && vi.kind == MAV_CODEC_MPEG_VIDEO && (int)vi.version == version
           && !strcmp( vi.codec, codec ) && !strcmp( vi.container, container ) && !strcmp( vi.backend, "libavcodec" )
           && vi.vnative.width == W && vi.vnative.height == H && vi.vnative.fps_n == FPS * vi.vnative.fps_d,
           "%s: video info %s %s %s v%u %dx%d %u/%u", name, vi.codec, vi.container, vi.backend, vi.version,
           vi.vnative.width, vi.vnative.height, vi.vnative.fps_n, vi.vnative.fps_d );
    if (audio)
    {
        CHECK( mav_stream_info( p, 1, &ai ) == MAV_OK && ai.kind == MAV_CODEC_MPEG_AUDIO && ai.layer == 2
               && ai.native.rate == RATE && ai.native.channels == 2, "%s: audio info", name );
        CHECK( mav_enable( p, 1, &(struct mav_output){ MAV_FMT_S16, RATE, 2, 3 } ) == MAV_OK, "%s: S16", name );
    }
    CHECK( mav_seek( p, 0, 1, 0, 0, 0 ) == MAV_OK, "%s: seek 0", name );
    /* both streams on one thread, as Wine's media source asks for them */
    for (;;)
    {
        int got = 0;
        if (mav_get_buffer( p, 0, &b ) == MAV_OK)
        {
            got = 1;
            if (first_v < 0) first_v = b.pts;
            CHECK( b.size == REF_SIZE && mav_copy_buffer( p, 0, pic, 0, b.size ) == MAV_OK && nv12_matches( pic, W, n ),
                   "%s: picture %d differs from the reference", name, n );
            CHECK( llabs( (long long)(b.pts - first_v) - (long long)n * TICK ) <= 1, "%s: picture %d at %llu", name, n,
                   (unsigned long long)b.pts );
            mav_release_buffer( p, 0 ); n++;
        }
        while (audio && (!frames || first_a + (int64_t)frames * 10000000 / RATE < first_v + (int64_t)n * TICK)
               && mav_get_buffer( p, 1, &b ) == MAV_OK)
        {
            uint32_t k; int16_t *x = malloc( b.size );
            got = 1;
            if (first_a < 0) first_a = b.pts;
            mav_copy_buffer( p, 1, x, 0, b.size );
            if (frames + b.size / 4 > cap) { cap = (frames + b.size / 4) * 2; pcm = realloc( pcm, cap * sizeof(*pcm) ); }
            for (k = 0; k < b.size / 4; k++) pcm[frames + k] = x[2 * k] / 32768.0;
            frames += b.size / 4; free( x );
            mav_release_buffer( p, 1 );
        }
        if (!got) break;
    }
    CHECK( n == FRAMES, "%s: %d pictures", name, n );
    if (audio)
    {
        analyse( pcm, frames, &freq, &rms );
        CHECK( fabs( freq - 440 ) < 2.5 && rms > 0.2 && rms < 0.35, "%s: the tone: %.1f Hz rms %.3f", name, freq, rms );
        /* one clock: the streams start where the file says, from its earliest start */
        CHECK( llabs( (long long)(first_v - first_a) - (long long)(ref_start[0] - ref_start[1]) ) <= 200
               && (first_v < 200 || first_a < 200),
               "%s: video starts at %lld, audio at %lld; the file: %lld, %lld", name, (long long)first_v,
               (long long)first_a, (long long)ref_start[0], (long long)ref_start[1] );
    }
    /* KiriKiri's put_CurrentPosition(0) after the end: the first picture again */
    CHECK( mav_seek( p, 0, 1, 0, 0, 0 ) == MAV_OK && mav_get_buffer( p, 0, &b ) == MAV_OK && b.pts == (uint64_t)first_v,
           "%s: rewind to 0", name );
    CHECK( mav_copy_buffer( p, 0, pic, 0, b.size ) == MAV_OK && nv12_matches( pic, W, 0 ), "%s: rewind picture", name );
    mav_release_buffer( p, 0 );
    /* an exact seek into the middle, a picture group away from its start */
    target = first_v + 50 * TICK;
    CHECK( mav_seek( p, 0, 1, (uint64_t)target, 0, 0 ) == MAV_OK && mav_get_buffer( p, 0, &b ) == MAV_OK
           && (int64_t)b.pts == target, "%s: seek to %lld gave %llu", name, (long long)target, (unsigned long long)b.pts );
    CHECK( mav_copy_buffer( p, 0, pic, 0, b.size ) == MAV_OK && nv12_matches( pic, W, 50 ), "%s: the seek's picture", name );
    mav_release_buffer( p, 0 );
    if (audio)
        CHECK( mav_get_buffer( p, 1, &b ) == MAV_OK && llabs( (long long)b.pts - (long long)target ) <= 1,
               "%s: audio after the seek at %llu", name, (unsigned long long)b.pts );
    src_stop( &s ); mav_destroy( p ); free( pic ); free( pcm );
    printf( "PASS: %s: %d pictures bit-exact in NV12, in order at 40 ms steps%s; rewind to 0; exact seek to 2 s\n", name, n,
            audio ? ", the MP2 tone, audio and video on one clock" : "" );
    return 0;
}

/* Compressed, as quartz's MPEG-1 splitter reads it: every packet of both streams. */
static int test_compressed( const uint8_t *data, size_t size )
{
    struct mav_parser *p = mav_create( 1 ); struct source s; struct mav_stream_info vi, ai; struct mav_buffer b;
    uint8_t *buf = malloc( 1 << 20 ); int next[2] = { 0, 0 }, count[2] = { 0, 0 }, want[2] = { 0, 0 }, i;

    CHECK( !make_reference( data, size ), "reference" );
    for (i = 0; i < ref_pkt_count; i++) want[ref_pkts[i].stream]++;
    src_start( &s, p, data, size );
    CHECK( mav_connect( p, size ) == MAV_OK && mav_stream_count( p ) == 2, "a compressed-output parser connects" );
    CHECK( mav_stream_info( p, 0, &vi ) == MAV_OK && mav_stream_info( p, 1, &ai ) == MAV_OK
           && vi.kind == MAV_CODEC_MPEG_VIDEO && vi.version == 1 && ai.kind == MAV_CODEC_MPEG_AUDIO, "infos" );
    for (i = 0; i < 2; i++)
        CHECK( mav_can_pass_compressed( p, i ) && mav_enable_compressed( p, i ) == MAV_OK, "stream %d compressed", i );
    CHECK( mav_seek( p, 0, 1, 0, 0, 0 ) == MAV_OK, "seek 0" );
    while (mav_get_buffer( p, -1, &b ) == MAV_OK)
    {
        int st = b.stream; const struct refpkt *r;
        while (next[st] < ref_pkt_count && ref_pkts[next[st]].stream != st) next[st]++;
        CHECK( next[st] < ref_pkt_count, "stream %d: more packets than the file has", st );
        r = &ref_pkts[next[st]++];
        CHECK( b.size == (uint32_t)r->size && mav_copy_buffer( p, st, buf, 0, b.size ) == MAV_OK
               && !memcmp( buf, r->data, b.size ), "stream %d packet %d: the file's %d bytes (got %u)", st, count[st],
               r->size, b.size );
        CHECK( b.delta == !r->key, "stream %d packet %d: keyframe flag", st, count[st] );
        if (r->pts != INT64_MIN)
            CHECK( llabs( (long long)b.pts - (long long)r->pts ) <= 1, "stream %d packet %d: pts %llu, file %lld", st,
                   count[st], (unsigned long long)b.pts, (long long)r->pts );
        if (!count[st]) CHECK( b.discontinuity && (st || !b.delta), "stream %d starts with a discontinuity (and a keyframe)", st );
        count[st]++;
        mav_release_buffer( p, st );
    }
    CHECK( count[0] == want[0] && count[1] == want[1] && count[0] > 0 && count[1] > 0,
           "%d / %d video packets, %d / %d audio packets", count[0], want[0], count[1], want[1] );
    src_stop( &s ); mav_destroy( p );

    /* MADEIRA_WG_COMPRESSED=0: the splitter gives way to the decoding splitter */
    mav_allow_compressed_asf( 0 );
    p = mav_create( 1 ); src_start( &s, p, data, size );
    CHECK( mav_connect( p, size ) == MAV_E_UNSUPPORTED, "MADEIRA_WG_COMPRESSED=0 refuses the MPEG program stream" );
    src_stop( &s ); mav_destroy( p );
    mav_allow_compressed_asf( 1 );
    free( buf );
    printf( "PASS: MPEG-1 program stream compressed (quartz's MPEG-1 splitter): all %d video and %d audio packets with "
            "the file's bytes, keyframe flags and timestamps; MADEIRA_WG_COMPRESSED=0 refuses it\n", count[0], count[1] );
    return 0;
}

/* MPEG-2 has no wg_format: its video is decoded even in a compressed-output parser; the audio is passed. */
static int test_mpeg2_compressed( const uint8_t *data, size_t size )
{
    struct mav_parser *p = mav_create( 1 ); struct source s; struct mav_stream_info vi; struct mav_buffer b;
    uint8_t *pic = malloc( REF_SIZE ); int n = 0;

    CHECK( !make_reference( data, size ) && ref_count == FRAMES, "reference" );
    src_start( &s, p, data, size );
    CHECK( mav_connect( p, size ) == MAV_OK && mav_stream_count( p ) == 2 && mav_stream_info( p, 0, &vi ) == MAV_OK,
           "connect" );
    CHECK( !mav_can_pass_compressed( p, 0 ) && mav_can_pass_compressed( p, 1 ), "MPEG-2 video not passed, MP2 passed" );
    CHECK( mav_enable_compressed( p, 0 ) == MAV_E_PARAM, "MPEG-2 video compressed refused" );
    CHECK( mav_enable_video( p, 0, &vi.vnative ) == MAV_OK, "and decoded" );
    mav_disable( p, 1 );
    CHECK( mav_seek( p, 0, 1, 0, 0, 0 ) == MAV_OK, "seek" );
    while (mav_get_buffer( p, 0, &b ) == MAV_OK)
    {
        CHECK( mav_copy_buffer( p, 0, pic, 0, b.size ) == MAV_OK && nv12_matches( pic, W, n ), "picture %d", n );
        mav_release_buffer( p, 0 ); n++;
    }
    CHECK( n == FRAMES, "%d pictures", n );
    src_stop( &s ); mav_destroy( p ); free( pic );
    printf( "PASS: MPEG-2 program stream in a compressed-output parser: the video (no wg_format) decoded, %d pictures "
            "bit-exact; the MP2 passed\n", n );
    return 0;
}

static int test_es_refused( const uint8_t *data, size_t size )
{
    struct mav_parser *p = mav_create( 0 ); struct source s;

    src_start( &s, p, data, size );
    CHECK( mav_connect( p, size ) == MAV_E_UNSUPPORTED, "an MPEG-1 elementary stream is refused" );
    src_stop( &s ); mav_destroy( p );
    printf( "PASS: an MPEG-1 elementary stream (.m1v) is refused, not played with made-up times\n" );
    return 0;
}

int main( int argc, char **argv )
{
    size_t n1, n2, n3; uint8_t *ps1, *ps2, *es1;
    int threads = argc > 1 && !strcmp( argv[1], "threads" );

    alarm( 300 );
    setvbuf( stdout, NULL, _IONBF, 0 );
    av_log_set_level( AV_LOG_ERROR );
    mav_configure( 1, NULL, NULL, MAV_PIX_NV12 );
    ps1 = make_mpeg( "mpeg", AV_CODEC_ID_MPEG1VIDEO, 1, &n1 );
    ps2 = make_mpeg( "dvd", AV_CODEC_ID_MPEG2VIDEO, 1, &n2 );
    es1 = make_mpeg( "mpeg1video", AV_CODEC_ID_MPEG1VIDEO, 0, &n3 );
    CHECK( ps1 && ps2 && es1, "make the files" );
    if (test_decoded( ps1, n1, "MPEG-1 program stream", "mpeg", "mpeg1video", 1, 1 )) return 1;
    if (test_compressed( ps1, n1 )) return 1;
    if (!threads)
    {
        if (test_decoded( ps2, n2, "MPEG-2 program stream", "mpeg", "mpeg2video", 2, 1 )) return 1;
        if (test_mpeg2_compressed( ps2, n2 )) return 1;
        if (test_es_refused( es1, n3 )) return 1;
    }
    free_reference();
    free( ps1 ); free( ps2 ); free( es1 );
    return failures != 0;
}
"""

glue_harness = r"""
#include "winegstreamer_unixlib_ios.c"
#include <signal.h>
""" + common + r"""
const struct mav_video_backend mav_apple_video_backend;
const struct mav_audio_backend mav_apple_audio_backend;

static int failures;
#define CHECK(c, ...) do { if (!(c)) { printf( "FAIL %s:%d: ", __func__, __LINE__ ); printf( __VA_ARGS__ ); printf( "\n" ); fflush( stdout ); failures++; return 1; } } while (0)
static NTSTATUS call( unsigned int code, void *args ) { return __wine_unix_call_funcs[code]( args ); }

/* ---- media types ---- */
static const GUID fourcc_base = { 0, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71 } };
static const GUID sub_mpeg1_payload = { 0xe436eb81, 0x524f, 0x11ce, { 0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70 } };
static const GUID sub_mpeg2_video = { 0xe06d8026, 0xdb46, 0x11cf, { 0xb4, 0xd1, 0x00, 0x80, 0x5f, 0x6c, 0xbb, 0xea } };
#define FCC(a,b,c,d) ((UINT32)(a) | ((UINT32)(b) << 8) | ((UINT32)(c) << 16) | ((UINT32)(d) << 24))

static struct wg_media_type video_type( MFVIDEOFORMAT *f, const GUID *subtype, UINT32 data1, UINT32 w, UINT32 h,
                                         BOOL bottom_up )
{
    struct wg_media_type t;
    memset( f, 0, sizeof(*f) );
    f->dwSize = sizeof(*f);
    if (subtype) f->guidFormat = *subtype;
    else { f->guidFormat = fourcc_base; f->guidFormat.Data1 = data1; }
    f->videoInfo.dwWidth = w; f->videoInfo.dwHeight = h;
    f->videoInfo.FramesPerSecond.Numerator = FPS; f->videoInfo.FramesPerSecond.Denominator = 1;
    if (bottom_up) f->videoInfo.VideoFlags |= MFVideoFlag_BottomUpLinearRep;
    t.major = madeira_MFMediaType_Video; t.format_size = sizeof(*f); t.u.video = f;
    return t;
}

static struct wg_media_type audio_type( WAVEFORMATEX *w, UINT tag, UINT bits, UINT rate, UINT channels, UINT extra )
{
    struct wg_media_type t;
    memset( w, 0, sizeof(*w) + extra );
    w->wFormatTag = tag; w->nChannels = channels; w->nSamplesPerSec = rate; w->wBitsPerSample = bits;
    w->nBlockAlign = channels * bits / 8; w->nAvgBytesPerSec = rate * w->nBlockAlign; w->cbSize = extra;
    t.major = madeira_MFMediaType_Audio; t.format_size = sizeof(*w) + extra; t.u.audio = w;
    return t;
}

static wg_transform_t create( struct wg_media_type in, struct wg_media_type out, NTSTATUS *status )
{
    struct wg_transform_create_params c = {0};
    c.input_type = in; c.output_type = out; c.attrs.input_queue_length = 4;
    *status = call( unix_wg_transform_create, &c );
    return c.transform;
}
static void destroy( wg_transform_t t ) { call( unix_wg_transform_destroy, &t ); }

static HRESULT push( wg_transform_t t, const void *data, UINT32 size, INT64 pts )
{
    struct wg_transform_push_data_params p = {0}; struct wg_sample s = {0};
    s.data = (UINT64)(UINT_PTR)data; s.size = s.max_size = size;
    if (pts != INT64_MIN) { s.flags = WG_SAMPLE_FLAG_HAS_PTS; s.pts = pts; }
    p.transform = t; p.sample = &s;
    if (call( unix_wg_transform_push_data, &p )) return E_FAIL;
    return p.result;
}

static HRESULT read_one( wg_transform_t t, void *data, UINT32 max, struct wg_sample *s )
{
    struct wg_transform_read_data_params r = {0};
    memset( s, 0, sizeof(*s) );
    s->data = (UINT64)(UINT_PTR)data; s->max_size = max;
    r.transform = t; r.sample = s;
    if (call( unix_wg_transform_read_data, &r )) return E_FAIL;
    return r.result;
}

/* ---- BURIKO's and KiriKiri's splitter: the compressed formats, through the parser entries ---- */
struct gsource { const uint8_t *data; size_t size; volatile int running; wg_parser_t parser; pthread_t thread; };
static void *gread_thread( void *arg )
{
    struct gsource *s = arg;
    while (__atomic_load_n( &s->running, __ATOMIC_ACQUIRE ))
    {
        struct wg_parser_get_next_read_offset_params o = { s->parser };
        struct wg_parser_push_data_params d = { s->parser };
        if (call( unix_wg_parser_get_next_read_offset, &o )) { usleep( 200 ); continue; }
        if (o.offset >= s->size) o.size = 0;
        else if (o.offset + o.size >= s->size) o.size = s->size - o.offset;
        d.data = o.size ? s->data + o.offset : s->data; d.size = o.size;
        call( unix_wg_parser_push_data, &d );
    }
    return NULL;
}

static int test_splitter_formats( const uint8_t *data, size_t size )
{
    struct wg_parser_create_params c = { 0, 1 }; struct wg_parser_connect_params cn = {0};
    struct wg_parser_get_stream_count_params sc = {0}; struct wg_parser_get_stream_params gs[2];
    struct wg_format vf, af; struct gsource src; int i, packets = 0;

    CHECK( !call( unix_wg_parser_create, &c ) && c.parser, "compressed-output parser" );
    /* off Apple the glue configures the core without video (there is no VideoToolbox); MPEG video is
     * libavcodec's, which needs no platform backend */
    mav_configure( 1, NULL, NULL, MAV_PIX_BGRx );
    memset( &src, 0, sizeof(src) ); src.data = data; src.size = size; src.parser = c.parser; src.running = 1;
    pthread_create( &src.thread, NULL, gread_thread, &src );
    cn.parser = c.parser; cn.file_size = size;
    CHECK( !call( unix_wg_parser_connect, &cn ), "connect" );
    sc.parser = c.parser;
    CHECK( !call( unix_wg_parser_get_stream_count, &sc ) && sc.count == 2, "two streams" );
    for (i = 0; i < 2; i++)
    {
        gs[i].parser = c.parser; gs[i].index = i;
        CHECK( !call( unix_wg_parser_get_stream, &gs[i] ), "stream %d", i );
    }
    {
        struct wg_parser_stream_get_current_format_params f0 = { gs[0].stream, &vf }, f1 = { gs[1].stream, &af };
        CHECK( !call( unix_wg_parser_stream_get_current_format, &f0 ) && !call( unix_wg_parser_stream_get_current_format, &f1 ),
               "formats" );
    }
    /* what quartz's MPEG-1 splitter builds MPEG1VIDEOINFO / MPEG1WAVEFORMAT from */
    CHECK( vf.major_type == WG_MAJOR_TYPE_VIDEO_MPEG1 && vf.u.video.width == W && vf.u.video.height == H
           && vf.u.video.fps_n == FPS * vf.u.video.fps_d, "video %u %dx%d %u/%u", vf.major_type, vf.u.video.width,
           vf.u.video.height, vf.u.video.fps_n, vf.u.video.fps_d );
    CHECK( af.major_type == WG_MAJOR_TYPE_AUDIO_MPEG1 && af.u.audio.layer == 2 && af.u.audio.rate == RATE
           && af.u.audio.channels == 2, "audio %u layer %u %u Hz %u ch", af.major_type, af.u.audio.layer,
           af.u.audio.rate, af.u.audio.channels );
    {
        struct wg_parser_stream_enable_params e0 = { gs[0].stream, &vf }, e1 = { gs[1].stream, &af };
        struct wg_parser_stream_seek_params sk = { gs[0].stream, 1.0, 0, 0, AM_SEEKING_AbsolutePositioning, AM_SEEKING_NoPositioning };
        CHECK( !call( unix_wg_parser_stream_enable, &e0 ) && !call( unix_wg_parser_stream_enable, &e1 ), "enable compressed" );
        call( unix_wg_parser_stream_seek, &sk );
    }
    for (;;)
    {
        struct wg_parser_buffer b; struct wg_parser_stream_get_buffer_params g = { c.parser, gs[0].stream, &b };
        uint8_t head[4]; struct wg_parser_stream_copy_buffer_params cp = { gs[0].stream, head, 0, 4 };
        if (call( unix_wg_parser_stream_get_buffer, &g ) != S_OK) break;
        CHECK( !call( unix_wg_parser_stream_copy_buffer, &cp ), "copy" );
        if (!packets) CHECK( !memcmp( head, "\x00\x00\x01\xb3", 4 ) && !b.delta, "the first packet starts with the sequence header" );
        call( unix_wg_parser_stream_release_buffer, &gs[0].stream );
        packets++;
    }
    CHECK( packets >= FRAMES, "%d video packets", packets );
    call( unix_wg_parser_disconnect, &c.parser );
    __atomic_store_n( &src.running, 0, __ATOMIC_RELEASE ); pthread_join( src.thread, NULL );
    call( unix_wg_parser_destroy, &c.parser );
    printf( "PASS: the MPEG-1 splitter's formats: MPEG-1 video %dx%d at %u/%u (BURIKO reads its size there), MP2 layer %u "
            "%u Hz %u ch; %d packets from the sequence header on\n", vf.u.video.width, vf.u.video.height, vf.u.video.fps_n,
            vf.u.video.fps_d, af.u.audio.layer, af.u.audio.rate, af.u.audio.channels, packets );
    return 0;
}

/* ---- the MPEG video decoder (quartz's CLSID_CMpegVideoCodec) ---- */
static int decode_es( const uint8_t *es, size_t es_size, const GUID *subtype, const char *name, UINT32 out_fourcc,
                      BOOL bottom_up, int *pictures )
{
    MFVIDEOFORMAT fi, fo; NTSTATUS st; wg_transform_t t; size_t off = 0, frame = out_fourcc == FCC('N','V','1','2') ? REF_SIZE : W * H * 4;
    uint8_t *buf = malloc( frame ); struct wg_sample s; int n = 0, drained = 0; HRESULT hr;

    t = create( video_type( &fi, subtype, 0, W, H, FALSE ), video_type( &fo, NULL, out_fourcc, W, H, bottom_up ), &st );
    CHECK( !st && t, "%s: create (%#x)", name, (unsigned)st );
    for (;;)
    {
        if (off < es_size)
        {
            UINT32 chunk = es_size - off < 997 ? (UINT32)(es_size - off) : 997;
            hr = push( t, es + off, chunk, INT64_MIN );
            if (hr == S_OK) off += chunk;
            else CHECK( hr == MF_E_NOTACCEPTING, "%s: push %#x", name, (unsigned)hr );
        }
        else if (!drained) { CHECK( !call( unix_wg_transform_drain, &t ), "drain" ); drained = 1; }
        while ((hr = read_one( t, buf, (UINT32)frame, &s )) == S_OK)
        {
            CHECK( s.size == frame && n < FRAMES, "%s: picture %d size %u", name, n, s.size );
            if (out_fourcc == FCC('N','V','1','2'))
                CHECK( nv12_matches( buf, W, n ), "%s: picture %d differs from the reference", name, n );
            else
            {
                int x, y, worst = 0;
                for (y = 0; y < H; y += 7) for (x = 0; x < W; x += 5)
                {
                    const uint8_t *px = buf + (size_t)(bottom_up ? H - 1 - y : y) * W * 4 + x * 4;
                    double Y = 1.164383 * (RY( n, x, y ) - 16), U = RU( n, x, y ) - 128, V = RV( n, x, y ) - 128;
                    int r = (int)lround( fmin( 255, fmax( 0, Y + 1.596027 * V ) ) );
                    int g = (int)lround( fmin( 255, fmax( 0, Y - 0.391762 * U - 0.812968 * V ) ) );
                    int b = (int)lround( fmin( 255, fmax( 0, Y + 2.017232 * U ) ) );
                    int e = abs( px[2] - r ); if (abs( px[1] - g ) > e) e = abs( px[1] - g ); if (abs( px[0] - b ) > e) e = abs( px[0] - b );
                    if (e > worst) worst = e;
                }
                CHECK( worst <= 1, "%s: picture %d RGB error %d", name, n, worst );
            }
            n++;
        }
        CHECK( hr == MF_E_TRANSFORM_NEED_MORE_INPUT, "%s: read %#x", name, (unsigned)hr );
        if (drained) break;
    }
    destroy( t ); free( buf );
    *pictures = n;
    CHECK( n == FRAMES, "%s: %d pictures", name, n );
    return 0;
}

static int test_video( void )
{
    MFVIDEOFORMAT fi, fo; NTSTATUS st; wg_transform_t t; size_t n1, n2; uint8_t *es1, *es2; int pictures;

    /* quartz_transform.c mpeg_video_codec_create()'s probe: no sequence header, 1920x1080, NV12 */
    t = create( video_type( &fi, &sub_mpeg1_payload, 0, 1920, 1080, FALSE ),
                video_type( &fo, NULL, FCC('N','V','1','2'), 1920, 1080, FALSE ), &st );
    CHECK( !st && t, "the MPEG video decoder's probe (%#x)", (unsigned)st );
    destroy( t );
    t = create( video_type( &fi, NULL, FCC('M','P','G','1'), W, H, FALSE ),
                video_type( &fo, NULL, FCC('N','V','1','2'), W, H, FALSE ), &st );
    CHECK( !st && t, "MFVideoFormat_MPG1 too" );
    destroy( t );

    es1 = make_mpeg( "mpeg1video", AV_CODEC_ID_MPEG1VIDEO, 0, &n1 );
    es2 = make_mpeg( "mpeg2video", AV_CODEC_ID_MPEG2VIDEO, 0, &n2 );
    CHECK( es1 && es2, "the elementary streams" );
    CHECK( !make_reference( es1, n1 ) && ref_count == FRAMES, "MPEG-1 reference" );
    if (decode_es( es1, n1, &sub_mpeg1_payload, "MPEG-1 to NV12", FCC('N','V','1','2'), FALSE, &pictures )) return 1;
    if (decode_es( es1, n1, &sub_mpeg1_payload, "MPEG-1 to RGB32 bottom-up", 22, TRUE, &pictures )) return 1;
    CHECK( !make_reference( es2, n2 ) && ref_count == FRAMES, "MPEG-2 reference" );
    if (decode_es( es2, n2, &sub_mpeg2_video, "MPEG-2 to NV12", FCC('N','V','1','2'), FALSE, &pictures )) return 1;
    free( es1 ); free( es2 );
    printf( "PASS: the MPEG video decoder: quartz's probe (MPEG1Payload 1920x1080, no sequence header); the MPEG-1 and "
            "MPEG-2 elementary streams pushed in 997-byte pieces, %d pictures each bit-exact in NV12; RGB32 bottom-up "
            "within 1 of BT.601\n", pictures );
    return 0;
}

/* ---- the MPEG audio decoder (quartz's CLSID_CMpegAudioCodec / mpeg_layer3_decoder) ---- */
static int decode_mp2( const uint8_t *mp2, size_t size, BOOL flt, double *freq, double *rms, size_t *frames_out )
{
    struct { WAVEFORMATEX wfx; BYTE extra[22]; } in; WAVEFORMATEX out; NTSTATUS st; wg_transform_t t;
    size_t off = 0, frames = 0, cap = 0; double *pcm = NULL; uint8_t buf[65536]; struct wg_sample s; HRESULT hr;
    int64_t next_pts = 0; int drained = 0, gaps = 0;

    t = create( audio_type( &in.wfx, MADEIRA_WAVE_FORMAT_MPEG, 0, RATE, 2, 22 ),
                audio_type( &out, flt ? WAVE_FORMAT_IEEE_FLOAT : WAVE_FORMAT_PCM, flt ? 32 : 16, RATE, 2, 0 ), &st );
    CHECK( !st && t, "MP2 decoder (%#x)", (unsigned)st );
    for (;;)
    {
        if (off < size)
        {
            UINT32 chunk = size - off < 333 ? (UINT32)(size - off) : 333;
            hr = push( t, mp2 + off, chunk, off ? INT64_MIN : 0 );
            if (hr == S_OK) off += chunk;
            else CHECK( hr == MF_E_NOTACCEPTING, "push %#x", (unsigned)hr );
        }
        else if (!drained) { CHECK( !call( unix_wg_transform_drain, &t ), "drain" ); drained = 1; }
        while ((hr = read_one( t, buf, sizeof(buf), &s )) == S_OK)
        {
            UINT32 k, n = s.size / (flt ? 8 : 4);
            CHECK( (s.flags & WG_SAMPLE_FLAG_HAS_PTS) && (s.flags & WG_SAMPLE_FLAG_HAS_DURATION), "timestamps" );
            if (llabs( (long long)s.pts - (long long)next_pts ) > 1) gaps++;
            next_pts = s.pts + s.duration;
            if (frames + n > cap) { cap = (frames + n) * 2; pcm = realloc( pcm, cap * sizeof(*pcm) ); }
            for (k = 0; k < n; k++) pcm[frames + k] = flt ? ((float *)buf)[2 * k] : ((int16_t *)buf)[2 * k] / 32768.0;
            frames += n;
        }
        CHECK( hr == MF_E_TRANSFORM_NEED_MORE_INPUT, "read %#x", (unsigned)hr );
        if (drained) break;
    }
    destroy( t );
    CHECK( !gaps, "%d timestamp gaps", gaps );
    analyse( pcm, frames, freq, rms );
    free( pcm );
    *frames_out = frames;
    return 0;
}

static int test_audio( void )
{
    struct { WAVEFORMATEX wfx; BYTE extra[22]; } in; WAVEFORMATEX out; NTSTATUS st; wg_transform_t t;
    size_t size, frames_s16, frames_flt; uint8_t *mp2; double f1, r1, f2, r2;

    /* quartz_transform.c's probes: MPEG-1 layer II (MPEG1WAVEFORMAT.fwHeadLayer = 2), and MP3 */
    audio_type( &in.wfx, MADEIRA_WAVE_FORMAT_MPEG, 0, 44100, 1, 22 );
    *(WORD *)in.extra = 2;
    t = create( (struct wg_media_type){ madeira_MFMediaType_Audio, sizeof(in), { .audio = &in.wfx } },
                audio_type( &out, WAVE_FORMAT_PCM, 16, 44100, 1, 0 ), &st );
    CHECK( !st && t, "the MPEG audio decoder's probe (%#x)", (unsigned)st );
    destroy( t );
    t = create( audio_type( &in.wfx, MADEIRA_WAVE_FORMAT_MPEGLAYER3, 0, 44100, 1, 12 ),
                audio_type( &out, WAVE_FORMAT_PCM, 16, 44100, 1, 0 ), &st );
    CHECK( !st && t, "the layer-3 decoder's probe (%#x)", (unsigned)st );
    destroy( t );
    /* refusals: not PCM out; not MPEG audio channels */
    t = create( audio_type( &in.wfx, MADEIRA_WAVE_FORMAT_MPEG, 0, 44100, 2, 22 ), audio_type( &out, 0x1610, 16, 44100, 2, 0 ), &st );
    CHECK( st == STATUS_NOT_SUPPORTED && !t, "AAC out refused (%#x)", (unsigned)st );
    t = create( audio_type( &in.wfx, MADEIRA_WAVE_FORMAT_MPEG, 0, 44100, 6, 22 ), audio_type( &out, WAVE_FORMAT_PCM, 16, 44100, 2, 0 ), &st );
    CHECK( st == STATUS_NOT_SUPPORTED && !t, "six channels refused (%#x)", (unsigned)st );

    mp2 = make_mpeg( "mp2", AV_CODEC_ID_NONE, 1, &size );
    CHECK( mp2 && size > 10000, "the MP2 stream" );
    if (decode_mp2( mp2, size, FALSE, &f1, &r1, &frames_s16 ) || decode_mp2( mp2, size, TRUE, &f2, &r2, &frames_flt )) return 1;
    CHECK( fabs( f1 - 440 ) < 2.5 && r1 > 0.2 && r1 < 0.35 && fabs( f2 - 440 ) < 2.5 && r2 > 0.2 && r2 < 0.35,
           "the tone: S16 %.1f Hz rms %.3f, float %.1f Hz rms %.3f", f1, r1, f2, r2 );
    CHECK( llabs( (long long)frames_s16 - (long long)RATE * FRAMES / FPS ) < 2 * 1152 && frames_s16 == frames_flt,
           "%zu / %zu frames for %d", frames_s16, frames_flt, RATE * FRAMES / FPS );
    free( mp2 );
    printf( "PASS: the MPEG audio decoder: quartz's probes (layer II, MP3); MP2 pushed in 333-byte pieces, %zu frames "
            "to S16 (%.1f Hz, rms %.3f) and to float, gap-free timestamps; AAC out and six channels refused\n",
            frames_s16, f1, r1 );
    return 0;
}

static int test_switched_off( void )
{
    struct { WAVEFORMATEX wfx; BYTE extra[22]; } in; WAVEFORMATEX out; NTSTATUS st; wg_transform_t t;

    t = create( audio_type( &in.wfx, MADEIRA_WAVE_FORMAT_MPEG, 0, 44100, 1, 22 ), audio_type( &out, WAVE_FORMAT_PCM, 16, 44100, 1, 0 ), &st );
    CHECK( st == STATUS_NOT_SUPPORTED && !t, "MADEIRA_WG_MPEG_TRANSFORM=0 refuses MPEG audio (%#x)", (unsigned)st );
    printf( "PASS: MADEIRA_WG_MPEG_TRANSFORM=0 refuses the MPEG audio decoder\n" );
    return 0;
}

int main( int argc, char **argv )
{
    size_t n1; uint8_t *ps1;

    alarm( 300 );
    setvbuf( stdout, NULL, _IONBF, 0 );
    av_log_set_level( AV_LOG_ERROR );
    if (argc > 1 && !strcmp( argv[1], "off" )) return test_switched_off() || failures;
    ps1 = make_mpeg( "mpeg", AV_CODEC_ID_MPEG1VIDEO, 1, &n1 );
    CHECK( ps1, "the MPEG-1 program stream" );
    if (test_splitter_formats( ps1, n1 ) || test_video() || test_audio()) return 1;
    free( ps1 ); free_reference();
    return failures != 0;
}
"""

TAG = "[wg-parser] ml1990 "
env = {k: v for k, v in os.environ.items() if not k.startswith("MADEIRA_")}
libs = [str(lib / "libavformat.a"), str(lib / "libavcodec.a"), str(lib / "libswresample.a"),
        str(lib / "libavutil.a"), "-lm", "-lpthread"]
with tempfile.TemporaryDirectory() as t:
    # ---------------------------------------------------------------- 3. the core
    c = Path(t) / "mpeg.c"; c.write_text(core_harness)
    exe = Path(t) / "mpeg"
    base = ["cc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wno-unused-function", "-I" + str(core.parent), "-I" + str(inc),
            str(c)]
    subprocess.run(base + ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined", "-o", str(exe)] + libs,
                   check=True)
    aenv = dict(env, ASAN_OPTIONS="detect_leaks=1")
    out = subprocess.run([str(exe)], env=aenv, capture_output=True, text=True, timeout=600)
    print(out.stdout, end="")
    assert out.returncode == 0, out.stdout + out.stderr[-4000:]
    lines = [l for l in out.stderr.splitlines() if l.startswith(TAG)]
    assert any("connect container=mpeg stream=0 video codec=mpeg1video backend=libavcodec 320x240 fps=25/1 out=nv12" in l
               for l in lines), lines
    assert any("connect container=mpeg codec=mp2 layer=2 rate=44100 channels=2" in l for l in lines), lines
    assert any("video codec=mpeg2video backend=libavcodec" in l for l in lines), lines
    assert any("out=compressed" in l and "mpeg1video" in l for l in lines), lines
    assert any(l.endswith("stream 0: decoding ahead on a thread of its own (3 pictures)") for l in lines), lines
    assert any("connect refused (mpeg, compressed_out=1): compressed output requested" in l for l in lines), lines
    assert any("connect refused (mpegvideo, compressed_out=0): container not in the allowlist" in l for l in lines), lines
    assert any("stream 0 summary: container=mpeg codec=mpeg1video backend=libavcodec out=nv12 320x240 mode=ahead " in l
               for l in lines), lines
    assert any("stream 1 summary: container=mpeg codec=mp2 backend=libavcodec out=s16 44100Hz 2ch mode=on-demand " in l
               for l in lines), lines
    assert any("stream 0 summary: container=mpeg codec=mpeg1video backend=libavcodec out=compressed mode=compressed " in l
               for l in lines), lines
    assert "ERROR: AddressSanitizer" not in out.stderr and "runtime error" not in out.stderr, out.stderr[-4000:]

    tsan = Path(t) / "mpeg-tsan"
    r = subprocess.run(base + ["-fsanitize=thread", "-o", str(tsan)] + libs, capture_output=True, text=True)
    if r.returncode:
        print("NOTOOL: no ThreadSanitizer build here")
    else:
        tenv = dict(env, TSAN_OPTIONS="halt_on_error=1")
        out = subprocess.run([str(tsan), "threads"], env=tenv, capture_output=True, text=True, timeout=900)
        assert out.returncode == 0 and "WARNING: ThreadSanitizer" not in out.stderr, out.stdout + out.stderr[-6000:]
        print("PASS: ThreadSanitizer clean: the MPEG-1 program stream decoded ahead, sought, rewound and read compressed")

    # ---------------------------------------------------------------- 4. the glue
    for need in [wine_build / "include/config.h", wine_build / "include/mfobjects.h", wine / "dlls/winegstreamer/unixlib.h"]:
        if not need.exists():
            sys.exit("SKIP-FAIL: %s is missing; point MADEIRA_WINE_BUILD at a configured Wine tree "
                     "(the core's checks above passed)" % need)
    g = Path(t) / "mpeg_glue.c"; g.write_text(glue_harness)
    gexe = Path(t) / "mpeg_glue"
    cc = os.environ.get("CC", "cc")
    cmd = [cc, "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined",
           "-fno-strict-aliasing", "-Wno-int-conversion", "-Wno-implicit-function-declaration",
           "-include", str(wine_build / "include/config.h"),
           "-I" + str(ntdll_unix), "-I" + str(wine / "dlls/winegstreamer"),
           "-I" + str(wine_build / "include"), "-I" + str(wine / "include"), "-I" + str(inc),
           "-D__WINESRC__", "-D_NTSYSTEM_", "-D_ACRTIMP=", "-DWINBASEAPI=", "-DWINE_UNIX_LIB",
           str(g), "-o", str(gexe)] + libs
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        print(r.stdout[-6000:], r.stderr[-6000:])
        sys.exit("FAIL: the glue harness did not compile")
    for label, extra, argv, needles in [
        ("default", {}, [], ["[resampler] MPEG audio decoder created: MPEG-1 layer II 44100 Hz 2ch -> s16 44100 Hz 2ch",
                             "MPEG audio destroy: transform ",
                             "MPEG-1 layer II 44100 Hz 2ch -> s16 44100 Hz 2ch:",
                             "MPEG-1 layer II 44100 Hz 2ch -> f32 44100 Hz 2ch:",
                             "[wmv] decoder created fmt=MPEG-1 320x240",
                             "MPEG-1 320x240 -> nv12 320x240:",
                             "100 pictures out, 0 rejected by the decoder",
                             "MPEG-1 320x240 -> bgrx 320x240 bottom-up:",
                             "stream 0 summary: container=mpeg codec=mpeg1video backend=libavcodec out=compressed mode=compressed"]),
        ("MADEIRA_WG_MPEG_TRANSFORM=0", {"MADEIRA_WG_MPEG_TRANSFORM": "0"}, ["off"],
         ["MPEG audio: disabled by MADEIRA_WG_MPEG_TRANSFORM=0"]),
    ]:
        out = subprocess.run([str(gexe)] + argv, env=dict(aenv, **extra), capture_output=True, text=True, timeout=600)
        print(out.stdout, end="")
        assert out.returncode == 0, "%s:\n%s%s" % (label, out.stdout, out.stderr[-4000:])
        assert "ERROR: AddressSanitizer" not in out.stderr and "runtime error" not in out.stderr, out.stderr[-4000:]
        for needle in needles:
            assert needle in out.stderr, (label, needle, [l for l in out.stderr.splitlines() if l.startswith("[")][:30])
print("PASS: MPEG-1/2 program streams and the MPEG video and audio decoders")
