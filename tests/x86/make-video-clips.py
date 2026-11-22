#!/usr/bin/env python3
"""Build the short WMV and MPEG-1 test clips for tests/x86/video-selftest-x86.exe.

Uses the cached host FFmpeg build from tests/host/host_ffmpeg.py (MEDIA_FLAGS:
LGPL decoders/demuxers plus the test-only wmv2/wmav2/mpeg1video/mp2 encoders
and asf/mpeg1system muxers; custom AVIOContext is used because MEDIA_FLAGS
starts from --disable-everything with no file protocol) so no system ffmpeg
binary is needed.

Outputs in <out-dir> (default: tests/x86):
  video-selftest.wmv   ASF with 320x240 25 fps WMV8 (wmv2) + 44.1 kHz stereo WMA2 (440 Hz tone)
  video-selftest.mpg   MPEG-1 program stream with 320x240 25 fps MPEG-1 video + MP2 (440 Hz tone)
Optionally writes a C header (--header PATH) with clip geometry constants and
embedded byte arrays so video-selftest-x86.exe can also run standalone when the
clip files are not beside it.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tests/host"))
from host_ffmpeg import host_ffmpeg, MEDIA_FLAGS  # noqa: E402

CLIP_W = 320
CLIP_H = 240
CLIP_FPS = 25
CLIP_FRAMES = 50        # 2.0 s: quick on device, long enough for mid-way EVR capture
AUDIO_RATE = 44100
TONE_HZ = 440

GENERATOR_C = r"""
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/channel_layout.h>
#include <libavutil/mathematics.h>
#include <libavutil/mem.h>

#define W %d
#define H %d
#define FPS %d
#define FRAMES %d
#define RATE %d
#define TONE_HZ %d

struct membuf
{
    uint8_t *data;
    size_t size;
    size_t cap;
    size_t pos;
};

static int mem_write( void *opaque, const uint8_t *buf, int n )
{
    struct membuf *m = opaque;
    if (n <= 0) return 0;
    if (m->pos + (size_t)n > m->cap)
    {
        size_t new_cap = (m->pos + (size_t)n) * 2 + 4096;
        uint8_t *p = realloc( m->data, new_cap );
        if (!p) return AVERROR( ENOMEM );
        m->data = p;
        m->cap = new_cap;
    }
    memcpy( m->data + m->pos, buf, (size_t)n );
    m->pos += (size_t)n;
    if (m->pos > m->size) m->size = m->pos;
    return n;
}

static int64_t mem_seek( void *opaque, int64_t off, int whence )
{
    struct membuf *m = opaque;
    if (whence & AVSEEK_SIZE) return (int64_t)m->size;
    whence &= ~AVSEEK_FORCE;
    if (whence == SEEK_CUR) off += (int64_t)m->pos;
    else if (whence == SEEK_END) off += (int64_t)m->size;
    if (off < 0) return -1;
    if ((size_t)off > m->cap)
    {
        size_t new_cap = (size_t)off * 2 + 4096;
        uint8_t *p = realloc( m->data, new_cap );
        if (!p) return -1;
        memset( p + m->cap, 0, new_cap - m->cap );
        m->data = p;
        m->cap = new_cap;
    }
    m->pos = (size_t)off;
    if (m->pos > m->size) m->size = m->pos;
    return off;
}

static int flush_packets( AVFormatContext *oc, AVCodecContext *enc, AVStream *st, AVFrame *frame )
{
    AVPacket *pkt = av_packet_alloc();
    int ret;

    if (!pkt) return -1;
    ret = avcodec_send_frame( enc, frame );
    if (ret < 0) { av_packet_free( &pkt ); return ret; }
    while ((ret = avcodec_receive_packet( enc, pkt )) >= 0)
    {
        av_packet_rescale_ts( pkt, enc->time_base, st->time_base );
        pkt->stream_index = st->index;
        ret = av_interleaved_write_frame( oc, pkt );
        av_packet_unref( pkt );
        if (ret < 0) { av_packet_free( &pkt ); return ret; }
    }
    av_packet_free( &pkt );
    return (ret == AVERROR( EAGAIN ) || ret == AVERROR_EOF) ? 0 : ret;
}

/* Fill a YUV420P frame with bright, saturated colour bars, a vertical gradient
 * and a moving highlight square so every frame is unmistakably non-black in
 * RGB32 and top-down vs bottom-up rows differ. */
static void fill_video_frame( AVFrame *vf, int frame_idx )
{
    int x, y;

    av_frame_make_writable( vf );
    for (y = 0; y < H; y++)
    {
        for (x = 0; x < W; x++)
        {
            int box = (x >= 24 + 4 * frame_idx && x < 88 + 4 * frame_idx &&
                       y >= 32 + 2 * frame_idx && y < 96 + 2 * frame_idx);
            int bar = ((x + 4 * frame_idx) / 24) & 1;
            vf->data[0][y * vf->linesize[0] + x] =
                box ? 228 : (uint8_t)(64 + bar * 104 + (y * 44) / H);
        }
    }
    for (y = 0; y < H / 2; y++)
    {
        for (x = 0; x < W / 2; x++)
        {
            vf->data[1][y * vf->linesize[1] + x] = (uint8_t)(68 + (x * 116) / (W / 2));
            vf->data[2][y * vf->linesize[2] + x] = (uint8_t)(204 - (y * 120) / (H / 2));
        }
    }
    vf->pts = frame_idx;
}

static int write_clip( const char *path, const char *muxer_name,
                       enum AVCodecID vcodec_id, int vbitrate, int max_b_frames,
                       enum AVCodecID acodec_id, enum AVSampleFormat asample_fmt, int abitrate )
{
    struct membuf m = { 0 };
    AVFormatContext *oc = NULL;
    const AVCodec *vc = avcodec_find_encoder( vcodec_id );
    const AVCodec *ac = avcodec_find_encoder( acodec_id );
    AVCodecContext *ve = NULL, *ae = NULL;
    AVStream *vs = NULL, *as = NULL;
    AVFrame *vf = NULL, *af = NULL;
    uint8_t *io_buf = NULL;
    int64_t apts = 0;
    int i, rc = -1;

    if (!vc || !ac) { fprintf( stderr, "missing encoder for %%s\n", path ); goto out; }
    if (avformat_alloc_output_context2( &oc, NULL, muxer_name, NULL ) < 0 || !oc) goto out;

    io_buf = av_malloc( 4096 );
    if (!io_buf) goto out;
    oc->pb = avio_alloc_context( io_buf, 4096, 1, &m, NULL, mem_write, mem_seek );
    if (!oc->pb) { av_free( io_buf ); goto out; }

    vs = avformat_new_stream( oc, NULL );
    ve = avcodec_alloc_context3( vc );
    if (!vs || !ve) goto out;
    ve->width = W;
    ve->height = H;
    ve->time_base = (AVRational){ 1, FPS };
    ve->framerate = (AVRational){ FPS, 1 };
    ve->pix_fmt = AV_PIX_FMT_YUV420P;
    ve->gop_size = 10;
    ve->max_b_frames = max_b_frames;
    ve->bit_rate = vbitrate;
    if (oc->oformat->flags & AVFMT_GLOBALHEADER)
        ve->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
    if (avcodec_open2( ve, vc, NULL ) < 0) goto out;
    if (avcodec_parameters_from_context( vs->codecpar, ve ) < 0) goto out;
    vs->time_base = ve->time_base;

    as = avformat_new_stream( oc, NULL );
    ae = avcodec_alloc_context3( ac );
    if (!as || !ae) goto out;
    ae->sample_rate = RATE;
    ae->sample_fmt = asample_fmt;
    ae->bit_rate = abitrate;
    av_channel_layout_default( &ae->ch_layout, 2 );
    ae->time_base = (AVRational){ 1, RATE };
    if (oc->oformat->flags & AVFMT_GLOBALHEADER)
        ae->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
    if (avcodec_open2( ae, ac, NULL ) < 0) goto out;
    if (avcodec_parameters_from_context( as->codecpar, ae ) < 0) goto out;
    as->time_base = ae->time_base;

    if (avformat_write_header( oc, NULL ) < 0) goto out;

    vf = av_frame_alloc();
    af = av_frame_alloc();
    if (!vf || !af) goto out;
    vf->format = AV_PIX_FMT_YUV420P;
    vf->width = W;
    vf->height = H;
    if (av_frame_get_buffer( vf, 0 ) < 0) goto out;

    af->format = ae->sample_fmt;
    af->nb_samples = ae->frame_size ? ae->frame_size : 1024;
    af->sample_rate = RATE;
    if (av_channel_layout_copy( &af->ch_layout, &ae->ch_layout ) < 0) goto out;
    if (av_frame_get_buffer( af, 0 ) < 0) goto out;

    for (i = 0; i < FRAMES; i++)
    {
        fill_video_frame( vf, i );
        if (flush_packets( oc, ve, vs, vf ) < 0) goto out;

        while (apts * FPS < (int64_t)(i + 1) * RATE)
        {
            int n;
            av_frame_make_writable( af );
            for (n = 0; n < af->nb_samples; n++)
            {
                double s = 0.4 * sin( 2.0 * M_PI * TONE_HZ * (double)(apts + n) / (double)RATE );
                if (asample_fmt == AV_SAMPLE_FMT_FLTP)
                {
                    ((float *)af->data[0])[n] = (float)s;
                    ((float *)af->data[1])[n] = (float)s;
                }
                else
                {
                    int16_t v = (int16_t)lrint( s * 32767.0 );
                    ((int16_t *)af->data[0])[2 * n] = v;
                    ((int16_t *)af->data[0])[2 * n + 1] = v;
                }
            }
            af->pts = apts;
            apts += af->nb_samples;
            if (flush_packets( oc, ae, as, af ) < 0) goto out;
        }
    }

    if (flush_packets( oc, ve, vs, NULL ) < 0) goto out;
    if (flush_packets( oc, ae, as, NULL ) < 0) goto out;
    if (av_write_trailer( oc ) < 0) goto out;
    avio_flush( oc->pb );

    {
        FILE *fp = fopen( path, "wb" );
        if (!fp) goto out;
        if (fwrite( m.data, 1, m.size, fp ) != m.size)
        {
            fclose( fp );
            goto out;
        }
        if (fclose( fp ) != 0) goto out;
    }
    rc = 0;

out:
    if (oc && oc->pb)
    {
        av_freep( &oc->pb->buffer );
        avio_context_free( &oc->pb );
    }
    av_frame_free( &vf );
    av_frame_free( &af );
    avcodec_free_context( &ve );
    avcodec_free_context( &ae );
    avformat_free_context( oc );
    free( m.data );
    return rc;
}

int main( int argc, char **argv )
{
    if (argc != 3) return 2;
    av_log_set_level( AV_LOG_ERROR );
    if (write_clip( argv[1], "asf", AV_CODEC_ID_WMV2, 600000, 0,
                    AV_CODEC_ID_WMAV2, AV_SAMPLE_FMT_FLTP, 128000 ) < 0)
    {
        fprintf( stderr, "failed to write WMV clip: %%s\n", argv[1] );
        return 1;
    }
    if (write_clip( argv[2], "mpeg", AV_CODEC_ID_MPEG1VIDEO, 1200000, 2,
                    AV_CODEC_ID_MP2, AV_SAMPLE_FMT_S16, 160000 ) < 0)
    {
        fprintf( stderr, "failed to write MPEG-1 clip: %%s\n", argv[2] );
        return 1;
    }
    return 0;
}
""" % (CLIP_W, CLIP_H, CLIP_FPS, CLIP_FRAMES, AUDIO_RATE, TONE_HZ)


def format_c_array(name, data):
    lines = ["static const unsigned char %s[%d] =\n{" % (name, len(data))]
    for off in range(0, len(data), 16):
        chunk = ", ".join("0x%02x" % b for b in data[off:off + 16])
        lines.append("    " + chunk + ",")
    lines.append("};\n")
    return "\n".join(lines)


def make_clips(out_dir, header_path=None):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tarball = os.environ.get("MADEIRA_FFMPEG_TARBALL") or str(ROOT / "build/ffmpeg/src/ffmpeg-7.1.5.tar.xz")
    prefix = host_ffmpeg(MEDIA_FLAGS, tarball, tag="asf-", override=os.environ.get("MADEIRA_HOST_FFMPEG_ASF"))
    inc, lib = prefix / "include", prefix / "lib"
    cc = os.environ.get("CC", "cc")
    libs = [
        str(lib / "libavformat.a"),
        str(lib / "libavcodec.a"),
        str(lib / "libswresample.a"),
        str(lib / "libavutil.a"),
        "-lm",
        "-lpthread",
    ]
    wmv_path = out_dir / "video-selftest.wmv"
    mpg_path = out_dir / "video-selftest.mpg"
    with tempfile.TemporaryDirectory(prefix="madeira-clips-") as tmp:
        c_file = Path(tmp) / "gen_clips.c"
        exe_file = Path(tmp) / "gen_clips"
        c_file.write_text(GENERATOR_C)
        subprocess.run(
            [cc, "-std=c11", "-O2", "-Wall", "-Werror", "-I" + str(inc), str(c_file), "-o", str(exe_file)] + libs,
            check=True,
        )
        subprocess.run([str(exe_file), str(wmv_path), str(mpg_path)], check=True)

    wmv_bytes = wmv_path.read_bytes()
    mpg_bytes = mpg_path.read_bytes()
    if header_path:
        hdr = Path(header_path)
        hdr.parent.mkdir(parents=True, exist_ok=True)
        hdr.write_text(
            "/* Generated by tests/x86/make-video-clips.py -- do not edit by hand. */\n"
            "#ifndef MADEIRA_VIDEO_SELFTEST_CLIPS_H\n"
            "#define MADEIRA_VIDEO_SELFTEST_CLIPS_H\n\n"
            "#define SELFTEST_CLIP_W      %d\n"
            "#define SELFTEST_CLIP_H      %d\n"
            "#define SELFTEST_CLIP_FPS    %d\n"
            "#define SELFTEST_CLIP_FRAMES %d\n"
            "#define SELFTEST_AUDIO_RATE  %d\n"
            "#define SELFTEST_TONE_HZ     %d\n\n"
            "%s\n%s\n"
            "#endif /* MADEIRA_VIDEO_SELFTEST_CLIPS_H */\n"
            % (
                CLIP_W,
                CLIP_H,
                CLIP_FPS,
                CLIP_FRAMES,
                AUDIO_RATE,
                TONE_HZ,
                format_c_array("selftest_wmv_bytes", wmv_bytes),
                format_c_array("selftest_mpg_bytes", mpg_bytes),
            )
        )
    print(
        "wrote %s (%d bytes) and %s (%d bytes)"
        % (wmv_path, len(wmv_bytes), mpg_path, len(mpg_bytes))
    )
    return wmv_path, mpg_path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out_dir", nargs="?", default=str(HERE), help="directory for .wmv and .mpg outputs")
    ap.add_argument("--header", default="", help="optional path to write embedded C header")
    args = ap.parse_args()
    make_clips(args.out_dir, args.header or None)


if __name__ == "__main__":
    main()
