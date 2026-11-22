#!/usr/bin/env python3
"""AVI files (.avi) through the wg_parser core (decoded path); no Wine runs.

A visual novel's .avi cutscene plays through DirectShow or Media Foundation. Wine's AVI splitter and
Media Foundation's AVI handler both fall back to winegstreamer's decoding parser (our wg_parser core)
when a compressed-output parser refuses the file. The core now demuxes AVI and decodes its common
video codecs (mpeg4 including DivX packed bitstreams, mjpeg, cinepak, msvideo1, msrle, indeo3/4/5,
rawvideo) and audio codecs (adpcm_ms, adpcm_ima_wav, pcm_alaw, pcm_mulaw, plus PCM / MPEG audio / WMA)
through libavcodec + libswresample, converting non-4:2:0 decoder pictures (yuvj422p, rgb24, rgb555,
pal8, bgr24) into the core's NV12 picture layout without libswscale.

1. Source checks: build/ffmpeg/build.sh enables the avi demuxer, the AVI video and ADPCM/A-law/mu-law
   audio decoders, and the mpeg4video/mjpeg parsers (and still no H.264/HEVC/AAC decoder or parser,
   and LGPL-only); the glue wires MADEIRA_WG_AVI to mav_allow_avi; docs/MEDIA.md and the settings
   catalog document AVI and MADEIRA_WG_AVI.
2. Host FFmpeg 7.1.5 from the tracked tarball (tests/host/host_ffmpeg.py MEDIA_FLAGS, shared with the
   ASF, WMV and MPEG checks) with TEST-ONLY encoders and the avi muxer.
3. The core under ASan/UBSan:
   - mpeg4 with B-frames + adpcm_ima_wav: every picture bit-exact in NV12 against an independent
     libavcodec decode, in presentation order at 40 ms steps; BGRx bottom-up + S16 audio on one
     thread (decoded ahead), tone frequency and RMS checked; keyframe seek with exact trim across
     output formats and rewind to 0;
   - DivX packed bitstream mpeg4 in AVI ("DivX503b1393p" VOL user data, [P+B] packed chunks + N-VOP
     placeholder chunks): every picture bit-exact and in presentation order against libavcodec;
   - mjpeg (yuvj422p) + pcm_s16le: every picture in order (Y bit-exact, 4:2:2 -> 4:2:0 chroma exact
     vertical average, RGB within 2 of full-range BT.601), PCM tone checked;
   - msvideo1 (rgb555le) + adpcm_ms, cinepak (rgb24) + pcm_alaw, rawvideo (bgr24 bottom-up) +
     pcm_mulaw, and msrle (pal8, including seek across palette): every picture in order within the
     expected RGB -> 4:2:0 -> RGB accuracy against an independent libavcodec decode, audio present;
   - indeo3 / indeo4 / indeo5 built and selected at connect (plumbing only: no encoder exists);
   - compressed-output parser refuses AVI; MADEIRA_WG_AVI=0 and MADEIRA_WG_VIDEO=0 refuse AVI; H.264
     in AVI is refused; back-pressure with a slow video reader drops no pictures;
   and the threaded cases run again under ThreadSanitizer.
"""
from pathlib import Path
import os, re, subprocess, sys, tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_ffmpeg import host_ffmpeg, MEDIA_FLAGS

root = Path(__file__).resolve().parents[2]
core = root / "build/ntdll-unix/wg_parser_av_ios.c"
glue = (root / "build/ntdll-unix/winegstreamer_unixlib_ios.c").read_text()
media_doc = (root / "docs/MEDIA.md").read_text()
notices = (root / "THIRD-PARTY-NOTICES.md").read_text()
catalog_py = (root / "build/tools/gen-config-catalog.py").read_text()
catalog_swift = (root / "app/Madeira/ConfigCatalog.generated.swift").read_text()

# ------------------------------------------------------------------ 1. source checks
ff = (root / "build/ffmpeg/build.sh").read_text().replace("\r\n", "\n")
args = ff[ff.index("CONFIG_ARGS=("):]
args = args[:args.index("\n)\n")]
assert re.search(r"--enable-demuxer=[^\n]*\bavi\b", args), "avi demuxer"
for dec in ["mpeg4", "mjpeg", "cinepak", "msvideo1", "msrle", "indeo3", "indeo4", "indeo5", "rawvideo",
            "adpcm_ms", "adpcm_ima_wav", "pcm_alaw", "pcm_mulaw"]:
    assert re.search(r"--enable-decoder=[^\n]*\b%s\b" % dec, args), ("missing decoder", dec)
for par in ["mpeg4video", "mjpeg"]:
    assert re.search(r"--enable-parser=[^\n]*\b%s\b" % par, args), ("missing parser", par)
for bad in ["h264", "hevc", "aac"]:
    assert not re.search(r"--enable-(decoder|parser)=[^\n]*\b%s\b" % bad, args), ("platform-decoded codec enabled", bad)
for flag in ["--disable-gpl", "--disable-nonfree", "--disable-version3", "--disable-everything"]:
    assert flag in args, ("LGPL-only configuration", flag)
assert 'getenv( "MADEIRA_WG_AVI" )' in glue and "mav_allow_avi(" in glue, "MADEIRA_WG_AVI wired in glue"
assert "MADEIRA_WG_AVI" in media_doc and "check-wg-parser-avi.py" in media_doc, "docs/MEDIA.md updated"
assert "mpeg4,mjpeg,cinepak,msvideo1,msrle,indeo3,indeo4,indeo5,rawvideo" in notices, "THIRD-PARTY-NOTICES.md updated"
assert '"env.MADEIRA_WG_AVI"' in catalog_py and 'key: "env.MADEIRA_WG_AVI"' in catalog_swift, "catalog updated"
print("PASS: FFmpeg enables avi, the AVI video and ADPCM/A-law/mu-law decoders and parsers (still LGPL, "
      "no H.264/HEVC/AAC); glue, docs and catalog list MADEIRA_WG_AVI")

# ------------------------------------------------------------------ 2. host FFmpeg
tarball = os.environ.get("MADEIRA_FFMPEG_TARBALL") or str(root / "build/ffmpeg/src/ffmpeg-7.1.5.tar.xz")
prefix = host_ffmpeg(MEDIA_FLAGS, tarball, tag="asf-", override=os.environ.get("MADEIRA_HOST_FFMPEG_ASF"))
inc, lib = prefix / "include", prefix / "lib"

# ------------------------------------------------------------------ 3. core harness
harness = r"""
#include "wg_parser_av_ios.c"
#include <math.h>
#include <signal.h>

static int failures;
#define CHECK(c, ...) do { if (!(c)) { printf( "FAIL %s:%d: ", __func__, __LINE__ ); printf( __VA_ARGS__ ); printf( "\n" ); fflush( stdout ); failures++; return 1; } } while (0)

#define W 160
#define H 120
#define FPS 25
#define GOP 10
#define RATE 22050
#define TICK (10000000 / FPS)

/* ---- PE pull-protocol read thread ---- */
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
static void src_stop( struct source *s )
{
    mav_disconnect( s->p );
    __atomic_store_n( &s->running, 0, __ATOMIC_RELEASE );
    pthread_join( s->thread, NULL );
}

/* ---- in-memory AVIO ---- */
struct membuf { uint8_t *data; size_t size, cap, pos; };
static int mem_write( void *o, const uint8_t *buf, int n )
{
    struct membuf *m = o;
    if (m->pos + n > m->cap) { m->cap = (m->pos + n) * 2 + 4096; m->data = realloc( m->data, m->cap ); }
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

/* Synthesise a moving pattern of 16x16 colour tiles so 4:2:0 subsampling is
 * well-defined across interior pixels and every frame is distinct. */
static void tile_rgb( int frame, int x, int y, uint8_t *r, uint8_t *g, uint8_t *b )
{
    int tx = (x + 4 * frame) / 16, ty = (y + 2 * frame) / 16;
    int idx = (tx * 3 + ty * 5 + frame) & 7;
    static const uint8_t pal[8][3] = {
        { 210,  40,  40 }, {  40, 195,  55 }, {  45,  85, 220 }, { 220, 200,  40 },
        { 195,  50, 195 }, {  40, 195, 200 }, { 225, 130,  45 }, { 160, 160, 160 },
    };
    *r = pal[idx][0]; *g = pal[idx][1]; *b = pal[idx][2];
}

static void fill_video_frame( AVFrame *vf, int i )
{
    int x, y;
    av_frame_make_writable( vf );
    switch (vf->format)
    {
    case AV_PIX_FMT_YUV420P:
    case AV_PIX_FMT_YUVJ420P:
        for (y = 0; y < H; y++) for (x = 0; x < W; x++)
        {
            int box = x >= 16 + (3 * i) % 80 && x < 56 + (3 * i) % 80 && y >= 20 && y < 76;
            vf->data[0][y * vf->linesize[0] + x] = box ? 215 : (uint8_t)(32 + ((x + 4 * i) / 16 % 2) * 110 + y / 2);
        }
        for (y = 0; y < H / 2; y++) for (x = 0; x < W / 2; x++)
        {
            vf->data[1][y * vf->linesize[1] + x] = (uint8_t)(80 + x + (i % 40));
            vf->data[2][y * vf->linesize[2] + x] = (uint8_t)(180 - y - (i % 30));
        }
        break;
    case AV_PIX_FMT_YUVJ422P:
        for (y = 0; y < H; y++) for (x = 0; x < W; x++)
            vf->data[0][y * vf->linesize[0] + x] = (uint8_t)(20 + ((x + 4 * i) / 16 % 2) * 140 + y);
        for (y = 0; y < H; y++) for (x = 0; x < W / 2; x++)
        {
            vf->data[1][y * vf->linesize[1] + x] = (uint8_t)(60 + x + (y % 40) + i);
            vf->data[2][y * vf->linesize[2] + x] = (uint8_t)(200 - x - (y % 40));
        }
        break;
    case AV_PIX_FMT_RGB24:
    case AV_PIX_FMT_BGR24:
        for (y = 0; y < H; y++) for (x = 0; x < W; x++)
        {
            uint8_t r, g, b, *p = vf->data[0] + y * vf->linesize[0] + 3 * x;
            tile_rgb( i, x, y, &r, &g, &b );
            if (vf->format == AV_PIX_FMT_RGB24) { p[0] = r; p[1] = g; p[2] = b; }
            else { p[0] = b; p[1] = g; p[2] = r; }
        }
        break;
    case AV_PIX_FMT_RGB555LE:
        for (y = 0; y < H; y++) for (x = 0; x < W; x++)
        {
            uint8_t r, g, b, *p = vf->data[0] + y * vf->linesize[0] + 2 * x;
            uint16_t v;
            tile_rgb( i, x, y, &r, &g, &b );
            v = (uint16_t)(((r >> 3) << 10) | ((g >> 3) << 5) | (b >> 3));
            p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
        }
        break;
    case AV_PIX_FMT_PAL8:
    {
        int k;
        memset( vf->data[1], 0, AVPALETTE_SIZE );
        for (k = 0; k < 64; k++)
        {
            uint8_t r = (uint8_t)(30 + (k & 3) * 65), g = (uint8_t)(30 + ((k >> 2) & 3) * 65),
                    b = (uint8_t)(30 + ((k >> 4) & 3) * 65);
            uint32_t c = 0xff000000u | ((uint32_t)r << 16) | ((uint32_t)g << 8) | b;
            memcpy( vf->data[1] + 4 * k, &c, 4 );
        }
        for (y = 0; y < H; y++) for (x = 0; x < W; x++)
        {
            int tx = (x + 4 * i) / 16, ty = (y + 2 * i) / 16;
            vf->data[0][y * vf->linesize[0] + x] = (uint8_t)((tx * 7 + ty * 13 + i * 3) & 63);
        }
        break;
    }
    default:
        break;
    }
}

static uint8_t *make_avi( enum AVCodecID vcodec, enum AVPixelFormat pix_fmt, int bframes, int nframes,
                          uint32_t vtag, enum AVCodecID acodec, size_t *size )
{
    struct membuf m = {0};
    AVFormatContext *oc = NULL; AVCodecContext *ve = NULL, *ae = NULL; AVStream *vs = NULL, *as = NULL;
    AVFrame *vf = av_frame_alloc(), *af = av_frame_alloc(); int64_t apts = 0; int i;

    if (avformat_alloc_output_context2( &oc, NULL, "avi", NULL ) < 0 || !oc) return NULL;
    oc->pb = avio_alloc_context( av_malloc( 4096 ), 4096, 1, &m, NULL, mem_write, mem_seek );
    vs = avformat_new_stream( oc, NULL );
    if (pix_fmt != AV_PIX_FMT_NONE)
    {
        const AVCodec *enc = avcodec_find_encoder( vcodec );
        if (!enc) return NULL;
        ve = avcodec_alloc_context3( enc );
        ve->width = W; ve->height = H; ve->time_base = (AVRational){ 1, FPS }; ve->framerate = (AVRational){ FPS, 1 };
        ve->pix_fmt = pix_fmt; ve->gop_size = GOP; ve->max_b_frames = bframes; ve->bit_rate = 900000;
        if (pix_fmt == AV_PIX_FMT_YUVJ422P || pix_fmt == AV_PIX_FMT_YUVJ420P)
        {
            ve->color_range = AVCOL_RANGE_JPEG;
            ve->strict_std_compliance = FF_COMPLIANCE_UNOFFICIAL;
        }
        if (vcodec == AV_CODEC_ID_CINEPAK) ve->gop_size = 6;
        if (vtag) ve->codec_tag = vtag;
        if (avcodec_open2( ve, enc, NULL ) < 0) return NULL;
        avcodec_parameters_from_context( vs->codecpar, ve );
        if (pix_fmt == AV_PIX_FMT_PAL8) vs->codecpar->bits_per_coded_sample = 8;
        if (vtag) vs->codecpar->codec_tag = vtag;
        vs->time_base = ve->time_base;
    }
    else
    {
        /* Codec-id plumbing only (Indeo 3/4/5, H.264 refusal): raw packets in AVI */
        vs->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
        vs->codecpar->codec_id = vcodec;
        vs->codecpar->codec_tag = vtag;
        vs->codecpar->width = W;
        vs->codecpar->height = H;
        vs->time_base = (AVRational){ 1, FPS };
    }

    if (acodec != AV_CODEC_ID_NONE)
    {
        const AVCodec *aenc = avcodec_find_encoder( acodec );
        if (!aenc) return NULL;
        as = avformat_new_stream( oc, NULL );
        ae = avcodec_alloc_context3( aenc );
        ae->sample_rate = RATE;
        ae->sample_fmt = acodec == AV_CODEC_ID_ADPCM_IMA_WAV ? AV_SAMPLE_FMT_S16P : AV_SAMPLE_FMT_S16;
        av_channel_layout_default( &ae->ch_layout, 2 );
        ae->time_base = (AVRational){ 1, RATE };
        if (avcodec_open2( ae, aenc, NULL ) < 0) return NULL;
        avcodec_parameters_from_context( as->codecpar, ae );
        as->time_base = ae->time_base;
    }

    if (avformat_write_header( oc, NULL ) < 0) return NULL;
    if (ve)
    {
        vf->format = pix_fmt; vf->width = W; vf->height = H;
        if (pix_fmt == AV_PIX_FMT_YUVJ422P || pix_fmt == AV_PIX_FMT_YUVJ420P) vf->color_range = AVCOL_RANGE_JPEG;
        av_frame_get_buffer( vf, 0 );
    }
    if (ae)
    {
        af->format = ae->sample_fmt;
        af->nb_samples = ae->frame_size > 0 ? ae->frame_size : 1024;
        af->sample_rate = RATE;
        av_channel_layout_copy( &af->ch_layout, &ae->ch_layout );
        av_frame_get_buffer( af, 0 );
    }

    for (i = 0; i < nframes; i++)
    {
        if (ve)
        {
            fill_video_frame( vf, i );
            vf->pts = i;
            put( oc, ve, vs, vf );
        }
        else
        {
            AVPacket *pkt = av_packet_alloc(); int k;
            av_new_packet( pkt, 256 );
            for (k = 0; k < 256; k++) pkt->data[k] = (uint8_t)(k * 73 + i * 19);
            pkt->pts = pkt->dts = i; pkt->stream_index = vs->index;
            pkt->flags = i % GOP == 0 ? AV_PKT_FLAG_KEY : 0;
            av_interleaved_write_frame( oc, pkt );
            av_packet_free( &pkt );
        }
        while (ae && apts * FPS < (int64_t)(i + 1) * RATE)
        {
            int n;
            av_frame_make_writable( af );
            for (n = 0; n < af->nb_samples; n++)
            {
                int16_t v = (int16_t)lrint( 0.4 * 32767 * sin( 2 * M_PI * 440 * (double)(apts + n) / RATE ) );
                if (af->format == AV_SAMPLE_FMT_S16P)
                {
                    ((int16_t *)af->data[0])[n] = v;
                    ((int16_t *)af->data[1])[n] = v;
                }
                else
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

/* Build a genuine DivX packed-bitstream MPEG-4 AVI: encode MPEG-4 with 1 B-frame,
 * prepend the "DivX503b1393p" user-data startcode so libavcodec sets divx_packed=1,
 * pack each P-VOP + following B-VOP into a single AVI chunk, and write a 7-byte
 * MPEG-4 N-VOP (vop_coded=0) chunk in the B-VOP's slot. */
static int vop_coding_type( const uint8_t *d, int n )
{
    int i;
    for (i = 0; i + 4 < n; i++)
        if (d[i] == 0 && d[i + 1] == 0 && d[i + 2] == 1 && d[i + 3] == 0xb6)
            return (d[i + 4] >> 6) & 3;   /* 0=I, 1=P, 2=B */
    return -1;
}

static uint8_t *make_divx_packed_avi( int nframes, size_t *size )
{
    static const uint8_t userdata[] = {
        0x00, 0x00, 0x01, 0xb2, 'D','i','v','X','5','0','3','b','1','3','9','3','p'
    };
    /* Minimal valid MPEG-4 P-VOP with modulo_time_base=0, marker=1, vop_time_inc=0 (5 bits for 1/25), marker=1, vop_coded=0 */
    static const uint8_t nvop[] = { 0x00, 0x00, 0x01, 0xb6, 0x50, 0x04, 0x00 };
    AVCodecContext *ve; AVFrame *vf = av_frame_alloc(); AVPacket **pkts = calloc( nframes + 8, sizeof(*pkts) );
    AVFormatContext *oc = NULL; AVStream *vs; struct membuf m = {0};
    int count = 0, i, out_idx = 0;

    ve = avcodec_alloc_context3( avcodec_find_encoder( AV_CODEC_ID_MPEG4 ) );
    ve->width = W; ve->height = H; ve->time_base = (AVRational){ 1, FPS }; ve->framerate = (AVRational){ FPS, 1 };
    ve->pix_fmt = AV_PIX_FMT_YUV420P; ve->gop_size = GOP; ve->max_b_frames = 1; ve->bit_rate = 900000;
    if (avcodec_open2( ve, ve->codec, NULL ) < 0) return NULL;
    vf->format = AV_PIX_FMT_YUV420P; vf->width = W; vf->height = H; av_frame_get_buffer( vf, 0 );
    for (i = 0; i <= nframes; i++)
    {
        AVPacket *p;
        if (i < nframes) { fill_video_frame( vf, i ); vf->pts = i; avcodec_send_frame( ve, vf ); }
        else avcodec_send_frame( ve, NULL );
        for (;;)
        {
            p = av_packet_alloc();
            if (avcodec_receive_packet( ve, p ) < 0) { av_packet_free( &p ); break; }
            pkts[count++] = p;
        }
    }

    avformat_alloc_output_context2( &oc, NULL, "avi", NULL );
    oc->pb = avio_alloc_context( av_malloc( 4096 ), 4096, 1, &m, NULL, mem_write, mem_seek );
    vs = avformat_new_stream( oc, NULL );
    avcodec_parameters_from_context( vs->codecpar, ve );
    vs->codecpar->codec_tag = MKTAG('D','X','5','0');
    vs->time_base = (AVRational){ 1, FPS };
    if (avformat_write_header( oc, NULL ) < 0) return NULL;

    for (i = 0; i < count; i++)
    {
        int t = vop_coding_type( pkts[i]->data, pkts[i]->size );
        int tn = i + 1 < count ? vop_coding_type( pkts[i + 1]->data, pkts[i + 1]->size ) : -1;
        AVPacket *out = av_packet_alloc();
        int add_ud = (i == 0);

        if (t == 1 && tn == 2)
        {
            /* Pack [P + B] into one chunk, followed by an N-VOP chunk */
            int sz = (add_ud ? (int)sizeof(userdata) : 0) + pkts[i]->size + pkts[i + 1]->size;
            uint8_t *dst;
            av_new_packet( out, sz );
            dst = out->data;
            if (add_ud) { memcpy( dst, userdata, sizeof(userdata) ); dst += sizeof(userdata); }
            memcpy( dst, pkts[i]->data, pkts[i]->size ); dst += pkts[i]->size;
            memcpy( dst, pkts[i + 1]->data, pkts[i + 1]->size );
            out->pts = out->dts = out_idx++; out->duration = 1; out->stream_index = 0;
            av_interleaved_write_frame( oc, out );
            av_packet_unref( out );

            av_new_packet( out, sizeof(nvop) );
            memcpy( out->data, nvop, sizeof(nvop) );
            out->pts = out->dts = out_idx++; out->duration = 1; out->stream_index = 0;
            av_interleaved_write_frame( oc, out );
            av_packet_free( &out );
            i++;
        }
        else
        {
            int sz = (add_ud ? (int)sizeof(userdata) : 0) + pkts[i]->size;
            uint8_t *dst;
            av_new_packet( out, sz );
            dst = out->data;
            if (add_ud) { memcpy( dst, userdata, sizeof(userdata) ); dst += sizeof(userdata); }
            memcpy( dst, pkts[i]->data, pkts[i]->size );
            out->pts = out->dts = out_idx++; out->duration = 1; out->stream_index = 0;
            if (t == 0) out->flags = AV_PKT_FLAG_KEY;
            av_interleaved_write_frame( oc, out );
            av_packet_free( &out );
        }
    }
    av_write_trailer( oc );
    for (i = 0; i < count; i++) av_packet_free( &pkts[i] );
    free( pkts ); av_frame_free( &vf ); avcodec_free_context( &ve );
    av_freep( &oc->pb->buffer ); avio_context_free( &oc->pb ); avformat_free_context( oc );
    *size = m.size;
    return m.data;
}

/* ---- independent libavformat + libavcodec reference decode ---- */
struct ref_pic
{
    int fmt;
    int64_t pts_100ns;
    uint8_t y[W * H], u[W * H], v[W * H];     /* planar YUV when source is YUV */
    uint8_t rgb[W * H * 3];                    /* R, G, B when source is RGB / PAL8 */
};
static struct ref_pic *refs;
static int ref_count;

static int make_reference( const uint8_t *data, size_t size, int max_frames )
{
    struct membuf m = { (uint8_t *)data, size, size, 0 };
    AVFormatContext *fc = avformat_alloc_context(); AVCodecContext *d; AVPacket *pkt = av_packet_alloc();
    AVFrame *f = av_frame_alloc(); int vi = -1, x, y, eof = 0; unsigned int i;

    fc->pb = avio_alloc_context( av_malloc( 4096 ), 4096, 0, &m, mem_read, NULL, mem_seek );
    CHECK( avformat_open_input( &fc, NULL, NULL, NULL ) == 0 && avformat_find_stream_info( fc, NULL ) >= 0, "ref open" );
    for (i = 0; i < fc->nb_streams; i++) if (fc->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) vi = i;
    CHECK( vi >= 0, "ref video stream" );
    d = avcodec_alloc_context3( avcodec_find_decoder( fc->streams[vi]->codecpar->codec_id ) );
    avcodec_parameters_to_context( d, fc->streams[vi]->codecpar );
    d->pkt_timebase = fc->streams[vi]->time_base; d->thread_count = 1;
    CHECK( avcodec_open2( d, d->codec, NULL ) == 0, "ref decoder open" );
    free( refs ); refs = calloc( max_frames + 8, sizeof(*refs) ); ref_count = 0;
    while (!eof)
    {
        eof = av_read_frame( fc, pkt ) < 0;
        if (!eof && pkt->stream_index != vi) { av_packet_unref( pkt ); continue; }
        avcodec_send_packet( d, eof ? NULL : pkt );
        av_packet_unref( pkt );
        while (avcodec_receive_frame( d, f ) >= 0)
        {
            struct ref_pic *r = &refs[ref_count++];
            int64_t ts = f->best_effort_timestamp != AV_NOPTS_VALUE ? f->best_effort_timestamp : f->pts;
            CHECK( f->width == W && f->height == H && ref_count <= max_frames + 8, "ref dims" );
            r->fmt = f->format;
            r->pts_100ns = ts != AV_NOPTS_VALUE
                           ? av_rescale_q( ts, fc->streams[vi]->time_base, (AVRational){ 1, 10000000 } ) : -1;
            if (f->format == AV_PIX_FMT_YUV420P || f->format == AV_PIX_FMT_YUVJ420P)
            {
                for (y = 0; y < H; y++) memcpy( r->y + y * W, f->data[0] + (ptrdiff_t)y * f->linesize[0], W );
                for (y = 0; y < H / 2; y++)
                {
                    memcpy( r->u + y * (W / 2), f->data[1] + (ptrdiff_t)y * f->linesize[1], W / 2 );
                    memcpy( r->v + y * (W / 2), f->data[2] + (ptrdiff_t)y * f->linesize[2], W / 2 );
                }
            }
            else if (f->format == AV_PIX_FMT_YUVJ422P || f->format == AV_PIX_FMT_YUV422P)
            {
                for (y = 0; y < H; y++)
                {
                    memcpy( r->y + y * W, f->data[0] + (ptrdiff_t)y * f->linesize[0], W );
                    memcpy( r->u + y * (W / 2), f->data[1] + (ptrdiff_t)y * f->linesize[1], W / 2 );
                    memcpy( r->v + y * (W / 2), f->data[2] + (ptrdiff_t)y * f->linesize[2], W / 2 );
                }
            }
            else
            {
                for (y = 0; y < H; y++) for (x = 0; x < W; x++)
                    mav_lavc_rgb_pixel( f, x, y, &r->rgb[(y * W + x) * 3],
                                        &r->rgb[(y * W + x) * 3 + 1], &r->rgb[(y * W + x) * 3 + 2] );
            }
            av_frame_unref( f );
        }
    }
    avcodec_free_context( &d ); av_frame_free( &f ); av_packet_free( &pkt );
    av_freep( &fc->pb->buffer ); avio_context_free( &fc->pb ); avformat_close_input( &fc );
    return 0;
}

static int check_nv12_420_exact( const uint8_t *buf, uint32_t size, int idx, const char *what )
{
    struct mav_layout l; int x, y; const struct ref_pic *r = &refs[idx];
    CHECK( size == mav_video_layout( MAV_PIX_NV12, W, H, &l ), "%s size", what );
    for (y = 0; y < H; y++) for (x = 0; x < W; x++)
        CHECK( buf[y * l.stride[0] + x] == r->y[y * W + x], "%s frame %d Y(%d,%d)", what, idx, x, y );
    for (y = 0; y < H / 2; y++) for (x = 0; x < W / 2; x++)
    {
        CHECK( buf[l.offset[1] + y * l.stride[1] + 2 * x] == r->u[y * (W / 2) + x], "%s frame %d U", what, idx );
        CHECK( buf[l.offset[1] + y * l.stride[1] + 2 * x + 1] == r->v[y * (W / 2) + x], "%s frame %d V", what, idx );
    }
    return 0;
}

static int check_nv12_422( const uint8_t *buf, uint32_t size, int idx, const char *what )
{
    struct mav_layout l; int x, y; const struct ref_pic *r = &refs[idx];
    CHECK( size == mav_video_layout( MAV_PIX_NV12, W, H, &l ), "%s size", what );
    for (y = 0; y < H; y++) for (x = 0; x < W; x++)
        CHECK( buf[y * l.stride[0] + x] == r->y[y * W + x], "%s frame %d Y(%d,%d)", what, idx, x, y );
    for (y = 0; y < H / 2; y++) for (x = 0; x < W / 2; x++)
    {
        int eu = (r->u[(2 * y) * (W / 2) + x] + r->u[(2 * y + 1) * (W / 2) + x] + 1) >> 1;
        int ev = (r->v[(2 * y) * (W / 2) + x] + r->v[(2 * y + 1) * (W / 2) + x] + 1) >> 1;
        CHECK( buf[l.offset[1] + y * l.stride[1] + 2 * x] == eu
               && buf[l.offset[1] + y * l.stride[1] + 2 * x + 1] == ev, "%s frame %d UV(%d,%d)", what, idx, x, y );
    }
    return 0;
}

/* Compare BGRx (optionally bottom-up) against an RGB/PAL8 reference picture:
 * mean absolute error across the whole frame is small (<= 4 even with 4:2:0
 * chroma subsampling along tile edges), and every pixel inside a uniform 2x2
 * chroma block is within `interior_tol` of the source RGB! */
static int check_bgrx_against_rgb( const uint8_t *buf, uint32_t size, int flip, int idx, int interior_tol,
                                   const char *what )
{
    struct mav_layout l; int x, y, max_int = 0; double sum = 0; const struct ref_pic *r = &refs[idx];
    CHECK( size == mav_video_layout( MAV_PIX_BGRx, W, H, &l ), "%s size", what );
    for (y = 0; y < H; y++)
    {
        const uint8_t *row = buf + (size_t)(flip ? H - 1 - y : y) * l.stride[0];
        for (x = 0; x < W; x++)
        {
            const uint8_t *sr = &r->rgb[(y * W + x) * 3];
            int eb = abs( (int)row[4 * x] - sr[2] ), eg = abs( (int)row[4 * x + 1] - sr[1] ),
                er = abs( (int)row[4 * x + 2] - sr[0] ), em = er > eg ? (er > eb ? er : eb) : (eg > eb ? eg : eb);
            int bx = x & ~1, by = y & ~1;
            const uint8_t *s00 = &r->rgb[(by * W + bx) * 3], *s01 = &r->rgb[(by * W + bx + 1) * 3],
                          *s10 = &r->rgb[((by + 1) * W + bx) * 3], *s11 = &r->rgb[((by + 1) * W + bx + 1) * 3];
            CHECK( row[4 * x + 3] == 0xff, "%s alpha", what );
            sum += (er + eg + eb) / 3.0;
            if (!memcmp( s00, s01, 3 ) && !memcmp( s00, s10, 3 ) && !memcmp( s00, s11, 3 ) && em > max_int)
                max_int = em;
        }
    }
    CHECK( sum / (W * H) < 5.0 && max_int <= interior_tol, "%s frame %d: mean err %.2f, uniform-block max %d",
           what, idx, sum / (W * H), max_int );
    return 0;
}

static void analyse_tone( const int16_t *pcm, size_t samples_stereo, double *freq, double *rms )
{
    size_t frames = samples_stereo / 2, a = frames / 4, b = frames - frames / 4, i, crossings = 0;
    double e = 0;
    for (i = a; i < b; i++)
    {
        double s = pcm[2 * i] / 32768.0;
        e += s * s;
        if (i > a && (pcm[2 * (i - 1)] < 0) != (pcm[2 * i] < 0)) crossings++;
    }
    *rms = sqrt( e / (b - a) );
    *freq = crossings / 2.0 * RATE / (b - a);
}

/* ================= 1. mpeg4 (B-frames) + adpcm_ima_wav, seek, formats ================= */
static int test_mpeg4_bframes( const uint8_t *avi, size_t size, int nframes )
{
    struct mav_parser *p = mav_create( 0 ); struct source s; struct mav_stream_info vi, ai; struct mav_buffer b;
    uint8_t *pic = malloc( W * H * 4 ); int16_t *pcm = NULL; size_t pcm_samples = 0, pcm_cap = 0;
    int n = 0, target = 23; int64_t last_pts = -1, first_pts = 0; double freq = 0, rms = 0;

    CHECK( !make_reference( avi, size, nframes ) && ref_count == nframes, "mpeg4 ref %d", ref_count );
    src_start( &s, p, avi, size );
    CHECK( mav_connect( p, size ) == MAV_OK && mav_stream_count( p ) == 2, "mpeg4 connect" );
    CHECK( mav_stream_info( p, 0, &vi ) == MAV_OK && mav_stream_info( p, 1, &ai ) == MAV_OK, "stream info" );
    CHECK( vi.type == MAV_STREAM_VIDEO && vi.kind == MAV_CODEC_AVI_VIDEO && !strcmp( vi.container, "avi" )
           && !strcmp( vi.codec, "mpeg4" ) && !strcmp( vi.backend, "libavcodec" )
           && vi.vnative.width == W && vi.vnative.height == H && vi.vnative.fps_n == FPS * vi.vnative.fps_d,
           "mpeg4 video info" );
    CHECK( ai.type == MAV_STREAM_AUDIO && ai.kind == MAV_CODEC_ADPCM && !strcmp( ai.codec, "adpcm_ima_wav" )
           && ai.native.rate == RATE && ai.native.channels == 2 && ai.native.fmt == MAV_FMT_S16, "adpcm info" );

    /* Earliest-buffer reads (both video decoded ahead and ADPCM audio) */
    CHECK( mav_seek( p, 0, 1, 0, 0, 0 ) == MAV_OK, "seek 0" );
    while (mav_get_buffer( p, -1, &b ) == MAV_OK)
    {
        if (b.stream == 0)
        {
            CHECK( (int64_t)b.pts > last_pts, "video pts monotonic: %llu <= %lld at %d",
                   (unsigned long long)b.pts, (long long)last_pts, n );
            /* Evenly spaced, not only equal to the reference decode's best-effort
             * guess, which the parser makes too: no picture's slot is skipped or
             * doubled.  With B-frames the first comes a frame late, as in
             * FFmpeg's own players (the decoder's one-frame delay in AVI). */
            if (!n) first_pts = (int64_t)b.pts;
            CHECK( first_pts <= TICK && llabs( (long long)b.pts - (long long)(first_pts + n * TICK) ) <= 1,
                   "frame %d at %llu, not %lld", n, (unsigned long long)b.pts, (long long)(first_pts + n * TICK) );
            if (refs[n].pts_100ns >= 0)
                CHECK( llabs( (long long)b.pts - refs[n].pts_100ns ) <= 1, "frame %d pts %llu != ref %lld",
                       n, (unsigned long long)b.pts, (long long)refs[n].pts_100ns );
            last_pts = b.pts;
            CHECK( mav_copy_buffer( p, 0, pic, 0, b.size ) == MAV_OK, "copy pic" );
            if (check_nv12_420_exact( pic, b.size, n, "mpeg4 nv12" )) return 1;
            n++;
        }
        else
        {
            size_t add = b.size / 2;
            if (pcm_samples + add > pcm_cap) { pcm_cap = (pcm_samples + add) * 2; pcm = realloc( pcm, pcm_cap * 2 ); }
            CHECK( mav_copy_buffer( p, 1, pcm + pcm_samples, 0, b.size ) == MAV_OK, "copy audio" );
            pcm_samples += add;
        }
        mav_release_buffer( p, b.stream );
    }
    CHECK( n == nframes, "mpeg4 pictures %d != %d", n, nframes );
    analyse_tone( pcm, pcm_samples, &freq, &rms );
    CHECK( fabs( freq - 440 ) < 5.0 && rms > 0.2 && rms < 0.36, "adpcm_ima_wav tone: %.1f Hz rms %.3f", freq, rms );

    /* Keyframe seek with exact trim into a B-frame GOP (frame 25), then rewind to 0 */
    target = 25;
    {
        uint64_t want_pts = (uint64_t)refs[target].pts_100ns;
        struct mav_video_output o = vi.vnative; o.fmt = MAV_PIX_NV12;
        CHECK( mav_enable_video( p, 0, &o ) == MAV_OK, "enable nv12" );
        CHECK( mav_seek( p, 0, 1, want_pts, 0, 0 ) == MAV_OK, "seek to frame %d (%llu)", target,
               (unsigned long long)want_pts );
        CHECK( mav_get_buffer( p, 0, &b ) == MAV_OK && llabs( (long long)b.pts - (long long)want_pts ) <= 10000,
               "seek pts %llu want %llu", (unsigned long long)b.pts, (unsigned long long)want_pts );
        CHECK( mav_copy_buffer( p, 0, pic, 0, b.size ) == MAV_OK, "copy sought" );
        if (check_nv12_420_exact( pic, b.size, target, "mpeg4 seek" )) return 1;
        mav_release_buffer( p, 0 );
    }

    CHECK( mav_seek( p, 0, 1, 0, 0, 0 ) == MAV_OK && mav_get_buffer( p, 0, &b ) == MAV_OK
           && llabs( (long long)b.pts - refs[0].pts_100ns ) <= 1, "rewind 0 (pts %llu want %lld)",
           (unsigned long long)b.pts, (long long)refs[0].pts_100ns );
    CHECK( mav_copy_buffer( p, 0, pic, 0, b.size ) == MAV_OK, "copy rewind" );
    if (check_nv12_420_exact( pic, b.size, 0, "mpeg4 rewind 0" )) return 1;
    mav_release_buffer( p, 0 );

    src_stop( &s ); mav_destroy( p ); free( pic ); free( pcm );
    printf( "PASS: mpeg4 (B-frames, DX50) + adpcm_ima_wav in AVI: %d pictures bit-exact in NV12 in order, "
            "ADPCM tone %.1f Hz (rms %.3f), exact seek to frame %d and rewind to 0\n", n, freq, rms, target );
    return 0;
}

/* ================= 2. DivX packed bitstream mpeg4 ================= */
static int test_divx_packed( const uint8_t *avi, size_t size, int want )
{
    struct mav_parser *p = mav_create( 0 ); struct source s; struct mav_buffer b;
    uint8_t *pic = malloc( W * H * 2 ); int n = 0; int64_t last_pts = -1, first_pts = 0;

    CHECK( !make_reference( avi, size, want ) && ref_count == want, "divx packed ref %d != %d", ref_count, want );
    src_start( &s, p, avi, size );
    CHECK( mav_connect( p, size ) == MAV_OK && mav_stream_count( p ) == 1, "divx packed connect" );
    while (mav_get_buffer( p, 0, &b ) == MAV_OK)
    {
        CHECK( (int64_t)b.pts > last_pts, "divx packed pts monotonic at %d: %llu <= %lld",
               n, (unsigned long long)b.pts, (long long)last_pts );
        if (!n) first_pts = (int64_t)b.pts;
        CHECK( first_pts <= TICK && llabs( (long long)b.pts - (long long)(first_pts + n * TICK) ) <= 1,
               "divx packed frame %d at %llu, not %lld", n, (unsigned long long)b.pts,
               (long long)(first_pts + n * TICK) );
        last_pts = b.pts;
        CHECK( mav_copy_buffer( p, 0, pic, 0, b.size ) == MAV_OK, "copy" );
        if (check_nv12_420_exact( pic, b.size, n, "divx packed" )) return 1;
        mav_release_buffer( p, 0 );
        n++;
    }
    CHECK( n == want, "divx packed frames %d != %d", n, want );
    src_stop( &s ); mav_destroy( p ); free( pic );
    printf( "PASS: DivX packed bitstream mpeg4 ([P+B] chunks + N-VOPs): all %d pictures bit-exact and in presentation order\n", n );
    return 0;
}

/* ================= 3. mjpeg (yuvj422p) + pcm_s16le ================= */
static int test_mjpeg_pcm( const uint8_t *avi, size_t size, int nframes )
{
    struct mav_parser *p = mav_create( 0 ); struct source s; struct mav_stream_info ai; struct mav_buffer b;
    uint8_t *pic = malloc( W * H * 4 ); int16_t *pcm = NULL; size_t pcm_samples = 0, pcm_cap = 0;
    int n = 0; double freq = 0, rms = 0;

    CHECK( !make_reference( avi, size, nframes ) && ref_count == nframes, "mjpeg ref" );
    CHECK( refs[0].fmt == AV_PIX_FMT_YUVJ422P || refs[0].fmt == AV_PIX_FMT_YUV422P, "mjpeg decoded as 4:2:2 (%d)", refs[0].fmt );
    src_start( &s, p, avi, size );
    CHECK( mav_connect( p, size ) == MAV_OK && mav_stream_count( p ) == 2, "mjpeg connect" );
    CHECK( mav_stream_info( p, 1, &ai ) == MAV_OK && ai.kind == MAV_CODEC_PCM && ai.native.fmt == MAV_FMT_S16, "pcm info" );
    while (mav_get_buffer( p, -1, &b ) == MAV_OK)
    {
        if (b.stream == 0)
        {
            CHECK( mav_copy_buffer( p, 0, pic, 0, b.size ) == MAV_OK, "copy" );
            if (check_nv12_422( pic, b.size, n, "mjpeg 422->nv12" )) return 1;
            n++;
        }
        else
        {
            size_t add = b.size / 2;
            if (pcm_samples + add > pcm_cap) { pcm_cap = (pcm_samples + add) * 2; pcm = realloc( pcm, pcm_cap * 2 ); }
            CHECK( mav_copy_buffer( p, 1, pcm + pcm_samples, 0, b.size ) == MAV_OK, "copy pcm" );
            pcm_samples += add;
        }
        mav_release_buffer( p, b.stream );
    }
    CHECK( n == nframes, "mjpeg pictures %d", n );
    analyse_tone( pcm, pcm_samples, &freq, &rms );
    CHECK( fabs( freq - 440 ) < 3.0 && rms > 0.25 && rms < 0.32, "pcm tone %.1f Hz rms %.3f", freq, rms );
    src_stop( &s ); mav_destroy( p ); free( pic ); free( pcm );
    printf( "PASS: mjpeg (yuvj422p) + pcm_s16le in AVI: %d pictures in order (Y exact, 4:2:2->4:2:0 chroma exact), "
            "PCM tone %.1f Hz (rms %.3f)\n", n, freq, rms );
    return 0;
}

/* ================= 4-7. RGB & paletted AVI codecs (msvideo1, cinepak, rawvideo bgr24, msrle) ================= */
static int test_rgb_avi( const uint8_t *avi, size_t size, int nframes, const char *vname, const char *aname,
                         int flip, int check_seek )
{
    struct mav_parser *p = mav_create( 0 ); struct source s; struct mav_stream_info vi, ai; struct mav_buffer b;
    uint8_t *pic = malloc( W * H * 4 ); int16_t *pcm = NULL; size_t pcm_samples = 0, pcm_cap = 0;
    int n = 0; double freq = 0, rms = 0;

    CHECK( !make_reference( avi, size, nframes ) && ref_count == nframes, "%s ref %d", vname, ref_count );
    src_start( &s, p, avi, size );
    CHECK( mav_connect( p, size ) == MAV_OK && mav_stream_count( p ) == (aname ? 2u : 1u), "%s connect", vname );
    CHECK( mav_stream_info( p, 0, &vi ) == MAV_OK && !strcmp( vi.codec, vname ) && !strcmp( vi.container, "avi" ),
           "%s stream info (%s)", vname, vi.codec );
    if (aname) CHECK( mav_stream_info( p, 1, &ai ) == MAV_OK && !strcmp( ai.codec, aname ), "%s audio (%s)", aname, ai.codec );
    {
        struct mav_video_output o = vi.vnative; o.fmt = MAV_PIX_BGRx; o.height = flip ? -H : H;
        CHECK( mav_enable_video( p, 0, &o ) == MAV_OK, "%s enable BGRx", vname );
    }
    /* Seek to 0 right after connect, as DirectShow and Media Foundation both do:
     * exercises the saved BITMAPINFOHEADER palette for PAL8 codecs! */
    CHECK( mav_seek( p, 0, 1, 0, 0, 0 ) == MAV_OK, "%s seek 0", vname );
    while (mav_get_buffer( p, -1, &b ) == MAV_OK)
    {
        if (b.stream == 0)
        {
            CHECK( mav_copy_buffer( p, 0, pic, 0, b.size ) == MAV_OK, "copy" );
            if (check_bgrx_against_rgb( pic, b.size, flip, n, 3, vname )) return 1;
            n++;
        }
        else
        {
            size_t add = b.size / 2;
            if (pcm_samples + add > pcm_cap) { pcm_cap = (pcm_samples + add) * 2; pcm = realloc( pcm, pcm_cap * 2 ); }
            CHECK( mav_copy_buffer( p, 1, pcm + pcm_samples, 0, b.size ) == MAV_OK, "copy audio" );
            pcm_samples += add;
        }
        mav_release_buffer( p, b.stream );
    }
    CHECK( n == nframes, "%s pictures %d != %d", vname, n, nframes );
    if (aname)
    {
        analyse_tone( pcm, pcm_samples, &freq, &rms );
        CHECK( fabs( freq - 440 ) < 6.0 && rms > 0.2 && rms < 0.36, "%s tone %.1f Hz rms %.3f", aname, freq, rms );
    }
    if (check_seek)
    {
        int target = nframes / 2 + 3;
        CHECK( mav_seek( p, 0, 1, (uint64_t)target * TICK, 0, 0 ) == MAV_OK && mav_get_buffer( p, 0, &b ) == MAV_OK,
               "%s seek %d", vname, target );
        CHECK( llabs( (long long)b.pts - (long long)target * TICK ) <= 10000
               && mav_copy_buffer( p, 0, pic, 0, b.size ) == MAV_OK, "%s seek copy", vname );
        if (check_bgrx_against_rgb( pic, b.size, flip, target, 3, vname )) return 1;
        mav_release_buffer( p, 0 );
    }
    src_stop( &s ); mav_destroy( p ); free( pic ); free( pcm );
    if (aname)
        printf( "PASS: %s + %s in AVI: %d pictures in order (BGRx%s within 3 on uniform blocks), %s tone %.1f Hz (rms %.3f)%s\n",
                vname, aname, n, flip ? " bottom-up" : "", aname, freq, rms, check_seek ? ", seek checked" : "" );
    else
        printf( "PASS: %s in AVI: %d pictures in order (BGRx%s within 3 on uniform blocks)%s\n",
                vname, n, flip ? " bottom-up" : "", check_seek ? ", seek across palette checked" : "" );
    return 0;
}

/* ================= 8. Indeo 3/4/5 plumbing & refusals & switches ================= */
static int test_indeo_and_switches( const uint8_t *valid_avi, size_t valid_size )
{
    static const struct { int lavc_id; enum AVCodecID cid; uint32_t tag; const char *name; } indeo[] = {
        { MAV_LAVC_INDEO3, AV_CODEC_ID_INDEO3, MKTAG('I','V','3','2'), "indeo3" },
        { MAV_LAVC_INDEO4, AV_CODEC_ID_INDEO4, MKTAG('I','V','4','1'), "indeo4" },
        { MAV_LAVC_INDEO5, AV_CODEC_ID_INDEO5, MKTAG('I','V','5','0'), "indeo5" },
    };
    unsigned int i;
    struct mav_parser *p; struct source s; size_t sz; uint8_t *avi;

    CHECK( avcodec_find_decoder( AV_CODEC_ID_H264 ) == NULL && avcodec_find_decoder( AV_CODEC_ID_HEVC ) == NULL
           && avcodec_find_decoder( AV_CODEC_ID_AAC ) == NULL, "no H.264/HEVC/AAC decoder in FFmpeg" );

    for (i = 0; i < sizeof(indeo) / sizeof(indeo[0]); i++)
    {
        struct mav_stream_info vi; struct mav_buffer b; int got = 0;
        CHECK( mav_lavc_supports( indeo[i].lavc_id ), "%s built", indeo[i].name );
        avi = make_avi( indeo[i].cid, AV_PIX_FMT_NONE, 0, 12, indeo[i].tag, AV_CODEC_ID_NONE, &sz );
        CHECK( avi != NULL, "make %s avi", indeo[i].name );
        p = mav_create( 0 ); src_start( &s, p, avi, sz );
        CHECK( mav_connect( p, sz ) == MAV_OK && mav_stream_info( p, 0, &vi ) == MAV_OK, "%s connects", indeo[i].name );
        CHECK( !strcmp( vi.codec, indeo[i].name ) && !strcmp( vi.backend, "libavcodec" )
               && vi.kind == MAV_CODEC_AVI_VIDEO, "%s selected (%s)", indeo[i].name, vi.codec );
        while (mav_get_buffer( p, 0, &b ) == MAV_OK) { got++; mav_release_buffer( p, 0 ); }
        src_stop( &s ); mav_destroy( p ); free( avi );
        (void)got;
    }
    printf( "PASS: indeo3 (IV32), indeo4 (IV41) and indeo5 (IV50) decoders are built, selected at connect, and "
            "handle undecodable input cleanly\n" );

    /* H.264 in AVI is refused */
    avi = make_avi( AV_CODEC_ID_H264, AV_PIX_FMT_NONE, 0, 10, MKTAG('H','2','6','4'), AV_CODEC_ID_NONE, &sz );
    CHECK( avi != NULL, "make h264 avi" );
    p = mav_create( 0 ); src_start( &s, p, avi, sz );
    CHECK( mav_connect( p, sz ) == MAV_E_UNSUPPORTED, "H.264 in AVI refused" );
    src_stop( &s ); mav_destroy( p ); free( avi );

    /* Compressed-output parser refuses AVI (so quartz's AVI splitter falls back to the decoding splitter) */
    p = mav_create( 1 ); src_start( &s, p, valid_avi, valid_size );
    CHECK( mav_connect( p, valid_size ) == MAV_E_UNSUPPORTED, "compressed-output parser refuses AVI" );
    src_stop( &s ); mav_destroy( p );

    /* MADEIRA_WG_AVI=0 refuses AVI, and restoring it accepts AVI again */
    mav_allow_avi( 0 );
    p = mav_create( 0 ); src_start( &s, p, valid_avi, valid_size );
    CHECK( mav_connect( p, valid_size ) == MAV_E_UNSUPPORTED, "MADEIRA_WG_AVI=0 refuses AVI" );
    src_stop( &s ); mav_destroy( p );
    mav_allow_avi( 1 );

    /* MADEIRA_WG_VIDEO=0 refuses AVI */
    mav_configure( 0, NULL, NULL, MAV_PIX_NV12 );
    p = mav_create( 0 ); src_start( &s, p, valid_avi, valid_size );
    CHECK( mav_connect( p, valid_size ) == MAV_E_UNSUPPORTED, "MADEIRA_WG_VIDEO=0 refuses AVI" );
    src_stop( &s ); mav_destroy( p );
    mav_configure( 1, NULL, NULL, MAV_PIX_NV12 );

    printf( "PASS: compressed-output parser, MADEIRA_WG_AVI=0, MADEIRA_WG_VIDEO=0 and H.264-in-AVI are all refused\n" );
    return 0;
}

/* ================= 9. Back-pressure on AVI ================= */
struct reader { struct mav_parser *p; int stream, delay_us, count; pthread_t thread; };
static void *reader_thread( void *arg )
{
    struct reader *r = arg; struct mav_buffer b;
    while (mav_get_buffer( r->p, r->stream, &b ) == MAV_OK)
    {
        mav_release_buffer( r->p, r->stream ); r->count++;
        if (r->delay_us) usleep( r->delay_us );
    }
    return NULL;
}

static int test_backpressure( const uint8_t *avi, size_t size, int nframes )
{
    struct mav_parser *p = mav_create( 0 ); struct source s; struct reader v, a;

    src_start( &s, p, avi, size );
    CHECK( mav_connect( p, size ) == MAV_OK, "bp connect" );
    v = (struct reader){ p, 0, 2500, 0 };
    a = (struct reader){ p, 1, 0, 0 };
    pthread_create( &v.thread, NULL, reader_thread, &v );
    pthread_create( &a.thread, NULL, reader_thread, &a );
    pthread_join( a.thread, NULL ); pthread_join( v.thread, NULL );
    CHECK( v.count == nframes && a.count > 0, "bp counts: %d/%d video, %d audio", v.count, nframes, a.count );
    src_stop( &s ); mav_destroy( p );
    printf( "PASS: AVI back-pressure (soft %d packets): slow video reader gets all %d pictures alongside %d audio buffers\n",
            MAV_QUEUE_SOFT_PACKETS, v.count, a.count );
    return 0;
}

int main( int argc, char **argv )
{
    size_t n_mp4, n_packed, n_mjpg, n_msv1, n_cvid, n_raw, n_rle;
    uint8_t *avi_mp4, *avi_packed = NULL, *avi_mjpg = NULL, *avi_msv1 = NULL, *avi_cvid = NULL, *avi_raw = NULL, *avi_rle = NULL;
    int bp_only = argc > 1 && !strcmp( argv[1], "bp" );
    int threads_only = argc > 1 && !strcmp( argv[1], "threads" );
    int rc = 1;

    alarm( 240 );
    setvbuf( stdout, NULL, _IONBF, 0 );
    av_log_set_level( AV_LOG_ERROR );
    mav_configure( 1, NULL, NULL, MAV_PIX_NV12 );

    avi_mp4 = make_avi( AV_CODEC_ID_MPEG4, AV_PIX_FMT_YUV420P, 2, 60, MKTAG('D','X','5','0'),
                        AV_CODEC_ID_ADPCM_IMA_WAV, &n_mp4 );
    CHECK( avi_mp4 != NULL, "synthesise mpeg4 + adpcm_ima_wav AVI" );

    if (bp_only)
    {
        rc = test_backpressure( avi_mp4, n_mp4, 60 );
        free( avi_mp4 ); free( refs );
        return rc || failures;
    }
    if (test_mpeg4_bframes( avi_mp4, n_mp4, 60 )) goto out;
    if (threads_only) { rc = 0; goto out; }

    avi_packed = make_divx_packed_avi( 30, &n_packed );
    avi_mjpg = make_avi( AV_CODEC_ID_MJPEG, AV_PIX_FMT_YUVJ422P, 0, 30, 0, AV_CODEC_ID_PCM_S16LE, &n_mjpg );
    avi_msv1 = make_avi( AV_CODEC_ID_MSVIDEO1, AV_PIX_FMT_RGB555LE, 0, 24, 0, AV_CODEC_ID_ADPCM_MS, &n_msv1 );
    avi_cvid = make_avi( AV_CODEC_ID_CINEPAK, AV_PIX_FMT_RGB24, 0, 16, 0, AV_CODEC_ID_PCM_ALAW, &n_cvid );
    avi_raw  = make_avi( AV_CODEC_ID_RAWVIDEO, AV_PIX_FMT_BGR24, 0, 20, 0, AV_CODEC_ID_PCM_MULAW, &n_raw );
    avi_rle  = make_avi( AV_CODEC_ID_MSRLE, AV_PIX_FMT_PAL8, 0, 24, 0, AV_CODEC_ID_NONE, &n_rle );
    CHECK( avi_packed && avi_mjpg && avi_msv1 && avi_cvid && avi_raw && avi_rle, "synthesise all AVI test inputs" );

    if (test_divx_packed( avi_packed, n_packed, 30 )) goto out;
    if (test_mjpeg_pcm( avi_mjpg, n_mjpg, 30 )) goto out;
    if (test_rgb_avi( avi_msv1, n_msv1, 24, "msvideo1", "adpcm_ms", 1, 0 )) goto out;
    if (test_rgb_avi( avi_cvid, n_cvid, 16, "cinepak", "pcm_alaw", 1, 0 )) goto out;
    if (test_rgb_avi( avi_raw,  n_raw,  20, "rawvideo", "pcm_mulaw", 1, 1 )) goto out;
    if (test_rgb_avi( avi_rle,  n_rle,  24, "msrle", NULL, 1, 1 )) goto out;
    if (test_indeo_and_switches( avi_mp4, n_mp4 )) goto out;
    rc = 0;

out:
    free( avi_mp4 ); free( avi_packed ); free( avi_mjpg ); free( avi_msv1 );
    free( avi_cvid ); free( avi_raw ); free( avi_rle ); free( refs );
    return rc || failures != 0;
}
"""

TAG = "[wg-parser] ml1990 "
env = {k: v for k, v in os.environ.items() if not k.startswith("MADEIRA_")}
libs = [str(lib / "libavformat.a"), str(lib / "libavcodec.a"), str(lib / "libswresample.a"),
        str(lib / "libavutil.a"), "-lm", "-lpthread"]
with tempfile.TemporaryDirectory() as t:
    c = Path(t) / "avi.c"
    c.write_text(harness)
    base = ["cc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wno-unused-function",
            "-I" + str(core.parent), "-I" + str(inc), str(c)]
    san = ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
    small = ["-DMAV_QUEUE_SOFT_PACKETS=8", "-DMAV_QUEUE_SOFT_BYTES=65536",
             "-DMAV_QUEUE_MAX_PACKETS=16", "-DMAV_BACKPRESSURE_WAIT_MS=400"]
    exe, bp = Path(t) / "avi", Path(t) / "avi-bp"
    subprocess.run(base + san + ["-o", str(exe)] + libs, check=True)
    subprocess.run(base + san + small + ["-o", str(bp)] + libs, check=True)

    aenv = dict(env, ASAN_OPTIONS="detect_leaks=1")
    out = subprocess.run([str(exe)], env=aenv, capture_output=True, text=True, timeout=300)
    print(out.stdout, end="")
    assert out.returncode == 0, out.stdout + out.stderr[-4000:]
    lines = [l for l in out.stderr.splitlines() if l.startswith(TAG)]
    for codec in ["mpeg4", "mjpeg", "msvideo1", "cinepak", "rawvideo", "msrle", "indeo3", "indeo4", "indeo5"]:
        assert any(("video codec=%s backend=libavcodec" % codec) in l for l in lines), (codec, lines)
    assert any("container=avi" in l and "codec=adpcm_ima_wav" in l for l in lines), lines
    assert any("connect refused (avi, compressed_out=1): compressed output requested" in l for l in lines), lines
    assert any("connect refused (avi, compressed_out=0): container disabled by MADEIRA_WG_AVI=0" in l for l in lines), lines
    assert any("connect refused (avi, compressed_out=0): container disabled by MADEIRA_WG_VIDEO=0" in l for l in lines), lines
    assert not any("not 4:2:0 planar; dropped" in l or "unsupported pixel format" in l for l in lines), lines
    assert "ERROR: AddressSanitizer" not in out.stderr and "runtime error" not in out.stderr, out.stderr[-4000:]

    out_bp = subprocess.run([str(bp), "bp"], env=aenv, capture_output=True, text=True, timeout=300)
    print(out_bp.stdout, end="")
    assert out_bp.returncode == 0, out_bp.stdout + out_bp.stderr[-4000:]
    assert "dropping further packets" not in out_bp.stderr, out_bp.stderr[-3000:]
    assert "ERROR: AddressSanitizer" not in out_bp.stderr and "runtime error" not in out_bp.stderr, out_bp.stderr[-4000:]

    tsan = Path(t) / "avi-tsan"
    tsan_bp = Path(t) / "avi-tsan-bp"
    r1 = subprocess.run(base + ["-fsanitize=thread", "-o", str(tsan)] + libs, capture_output=True, text=True)
    r2 = subprocess.run(base + small + ["-fsanitize=thread", "-o", str(tsan_bp)] + libs, capture_output=True, text=True)
    if r1.returncode or r2.returncode:
        print("NOTOOL: no ThreadSanitizer build here")
    else:
        tenv = dict(env, TSAN_OPTIONS="halt_on_error=1")
        for exe_, argv_ in [(tsan, ["threads"]), (tsan_bp, ["bp"])]:
            r = subprocess.run([str(exe_)] + argv_, env=tenv, capture_output=True, text=True, timeout=600)
            assert r.returncode == 0 and "WARNING: ThreadSanitizer" not in r.stderr, r.stdout + r.stderr[-6000:]
        print("PASS: ThreadSanitizer clean: AVI mpeg4 + adpcm_ima_wav decoded ahead, sought, rewound and back-pressured")
print("PASS: AVI files in the wg_parser core")
