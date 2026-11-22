#!/usr/bin/env python3
"""Build the short test clips for tests/x86/video-selftest-x86.exe.

Uses the cached host FFmpeg build from tests/host/host_ffmpeg.py (MEDIA_FLAGS:
LGPL decoders/demuxers plus the test-only wmv2/wmav2/mpeg1video/mp2/mpeg4/
adpcm_ima_wav encoders and asf/mpeg1system/mpeg1video/avi muxers; custom
AVIOContext is used because MEDIA_FLAGS starts from --disable-everything with
no file protocol) so no system ffmpeg binary is needed.

Outputs in <out-dir> (default: tests/x86):
  video-selftest.wmv   ASF with 320x240 25 fps WMV8 (wmv2) + 44.1 kHz stereo WMA2 (440 Hz tone)
  video-selftest.mpg   MPEG-1 program stream with 320x240 25 fps MPEG-1 video + MP2 (440 Hz tone)
  video-selftest.avi   AVI with 320x240 25 fps MPEG-4 Part 2 (XVID) + IMA ADPCM stereo (440 Hz tone)
  video-selftest.m1v   Raw MPEG-1 video elementary stream, 320x240 25 fps (50 frames, B-frames)
  video-selftest.dat   RIFF/CDXA VideoCD .dat wrapping video-selftest.mpg in 2352-byte Mode 2 Form 2 sectors
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
CLIP_FRAMES = 50        # 2.0 s: quick on device, long enough for mid-way EVR/VMR capture
RESIZE_W = 160          # downscaled output size for IMFSourceReader video-processor path
RESIZE_H = 120
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

static int write_whole_file( const char *path, const uint8_t *data, size_t size )
{
    FILE *fp = fopen( path, "wb" );
    if (!fp) return -1;
    if (fwrite( data, 1, size, fp ) != size)
    {
        fclose( fp );
        return -1;
    }
    return fclose( fp ) == 0 ? 0 : -1;
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
 * and a moving highlight square so every frame is unmistakably non-black and
 * colourful in RGB32, and top-down vs bottom-up rows differ. */
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
                       enum AVCodecID vcodec_id, uint32_t vcodec_tag, int vbitrate, int max_b_frames,
                       enum AVCodecID acodec_id, enum AVSampleFormat asample_fmt, int abitrate,
                       uint8_t **out_bytes, size_t *out_size )
{
    struct membuf m = { 0 };
    AVFormatContext *oc = NULL;
    const AVCodec *vc = avcodec_find_encoder( vcodec_id );
    const AVCodec *ac = (acodec_id != AV_CODEC_ID_NONE) ? avcodec_find_encoder( acodec_id ) : NULL;
    AVCodecContext *ve = NULL, *ae = NULL;
    AVStream *vs = NULL, *as = NULL;
    AVFrame *vf = NULL, *af = NULL;
    uint8_t *io_buf = NULL;
    int64_t apts = 0;
    int i, rc = -1;

    if (!vc || (acodec_id != AV_CODEC_ID_NONE && !ac))
    {
        fprintf( stderr, "missing encoder for %%s\n", path );
        goto out;
    }
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
    if (vcodec_tag)
    {
        ve->codec_tag = vcodec_tag;
        vs->codecpar->codec_tag = vcodec_tag;
    }
    if (oc->oformat->flags & AVFMT_GLOBALHEADER)
        ve->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
    if (avcodec_open2( ve, vc, NULL ) < 0) goto out;
    if (avcodec_parameters_from_context( vs->codecpar, ve ) < 0) goto out;
    if (vcodec_tag) vs->codecpar->codec_tag = vcodec_tag;
    vs->time_base = ve->time_base;

    if (ac)
    {
        as = avformat_new_stream( oc, NULL );
        ae = avcodec_alloc_context3( ac );
        if (!as || !ae) goto out;
        ae->sample_rate = RATE;
        ae->sample_fmt = asample_fmt;
        if (abitrate > 0) ae->bit_rate = abitrate;
        av_channel_layout_default( &ae->ch_layout, 2 );
        ae->time_base = (AVRational){ 1, RATE };
        if (oc->oformat->flags & AVFMT_GLOBALHEADER)
            ae->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
        if (avcodec_open2( ae, ac, NULL ) < 0) goto out;
        if (avcodec_parameters_from_context( as->codecpar, ae ) < 0) goto out;
        as->time_base = ae->time_base;
    }

    if (avformat_write_header( oc, NULL ) < 0) goto out;

    vf = av_frame_alloc();
    if (!vf) goto out;
    vf->format = AV_PIX_FMT_YUV420P;
    vf->width = W;
    vf->height = H;
    if (av_frame_get_buffer( vf, 0 ) < 0) goto out;

    if (ae)
    {
        af = av_frame_alloc();
        if (!af) goto out;
        af->format = ae->sample_fmt;
        af->nb_samples = ae->frame_size ? ae->frame_size : 1024;
        af->sample_rate = RATE;
        if (av_channel_layout_copy( &af->ch_layout, &ae->ch_layout ) < 0) goto out;
        if (av_frame_get_buffer( af, 0 ) < 0) goto out;
    }

    for (i = 0; i < FRAMES; i++)
    {
        fill_video_frame( vf, i );
        if (flush_packets( oc, ve, vs, vf ) < 0) goto out;

        while (ae && apts * FPS < (int64_t)(i + 1) * RATE)
        {
            int n, count = af->nb_samples;
            int64_t target_samples = ((int64_t)FRAMES * RATE) / FPS;
            if (apts + count > target_samples && (ae->codec->capabilities & AV_CODEC_CAP_SMALL_LAST_FRAME))
                count = (int)(target_samples - apts);
            if (count <= 0) break;
            av_frame_make_writable( af );
            af->nb_samples = count;
            for (n = 0; n < count; n++)
            {
                double s = 0.4 * sin( 2.0 * M_PI * TONE_HZ * (double)(apts + n) / (double)RATE );
                if (asample_fmt == AV_SAMPLE_FMT_FLTP)
                {
                    ((float *)af->data[0])[n] = (float)s;
                    ((float *)af->data[1])[n] = (float)s;
                }
                else if (asample_fmt == AV_SAMPLE_FMT_S16P)
                {
                    int16_t v = (int16_t)lrint( s * 32767.0 );
                    ((int16_t *)af->data[0])[n] = v;
                    ((int16_t *)af->data[1])[n] = v;
                }
                else
                {
                    int16_t v = (int16_t)lrint( s * 32767.0 );
                    ((int16_t *)af->data[0])[2 * n] = v;
                    ((int16_t *)af->data[0])[2 * n + 1] = v;
                }
            }
            af->pts = apts;
            apts += count;
            if (flush_packets( oc, ae, as, af ) < 0) goto out;
            if (apts >= target_samples && (ae->codec->capabilities & AV_CODEC_CAP_SMALL_LAST_FRAME))
                break;
        }
    }

    if (flush_packets( oc, ve, vs, NULL ) < 0) goto out;
    if (ae && flush_packets( oc, ae, as, NULL ) < 0) goto out;
    if (av_write_trailer( oc ) < 0) goto out;
    avio_flush( oc->pb );

    if (write_whole_file( path, m.data, m.size ) < 0) goto out;
    if (out_bytes && out_size)
    {
        *out_bytes = m.data;
        *out_size = m.size;
        m.data = NULL;
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

/* White Book / CD-ROM XA RIFF/CDXA VideoCD .dat wrapper (same layout as
 * tests/host/check-wg-mpeg.py's make_vcd_dat): 44-byte RIFF/CDXA/fmt/data
 * header, 2 bumper sectors (an empty Form 2 pre-gap sector and a Form 1 ISO
 * data sector with fake MPEG start codes in body & ECC), then 2352-byte Mode 2
 * Form 2 sectors (24-byte sync/MSF/XA-subheader + 2324-byte payload + 4-byte
 * non-zero EDC trailer). */
static int write_vcd_dat( const char *path, const uint8_t *ps, size_t ps_size )
{
    static const uint8_t sync[12] = { 0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00 };
    size_t pre = 2, body = (ps_size + 2323) / 2324, total_sec = pre + body;
    uint32_t data_bytes = (uint32_t)(total_sec * 2352), riff_size = 36 + data_bytes;
    uint8_t *dat = calloc( 1, 44 + data_bytes );
    size_t s;
    int rc;

    if (!dat) return -1;
    memcpy( dat, "RIFF", 4 );
    dat[4] = (uint8_t)riff_size;
    dat[5] = (uint8_t)(riff_size >> 8);
    dat[6] = (uint8_t)(riff_size >> 16);
    dat[7] = (uint8_t)(riff_size >> 24);
    memcpy( dat + 8, "CDXAfmt ", 8 );
    dat[16] = 16;   /* 16-byte CDXA fmt chunk */
    memcpy( dat + 36, "data", 4 );
    dat[40] = (uint8_t)data_bytes;
    dat[41] = (uint8_t)(data_bytes >> 8);
    dat[42] = (uint8_t)(data_bytes >> 16);
    dat[43] = (uint8_t)(data_bytes >> 24);

    /* sector 0: empty Mode 2 Form 2 lead-in (submode 0x20, no content bits) */
    memcpy( dat + 44, sync, 12 );
    dat[44 + 13] = 2;
    dat[44 + 15] = 2;
    dat[44 + 18] = dat[44 + 22] = 0x20;

    /* sector 1: Mode 2 Form 1 ISO data sector (submode 0x08) with fake start codes in body & ECC */
    {
        uint8_t *s1 = dat + 44 + 2352;
        memcpy( s1, sync, 12 );
        s1[13] = 2;
        s1[14] = 1;
        s1[15] = 2;
        s1[18] = s1[22] = 0x08;
        memcpy( s1 + 24, "\x00\x00\x01\xba\x21\x00\x01\x00\x01\x80\x00\x01\x00\x00\x01\xe0", 16 );
        memcpy( s1 + 2072, "\x00\x00\x01\xba\x00\x00\x01\xe0\xde\xad\xbe\xef", 12 );
    }

    for (s = 0; s < body; s++)
    {
        uint8_t *sec = dat + 44 + (pre + s) * 2352;
        size_t off = s * 2324;
        size_t chunk = (ps_size - off > 2324) ? 2324 : (ps_size - off);
        memcpy( sec, sync, 12 );
        sec[12] = 0;
        sec[13] = 2;
        sec[14] = (uint8_t)((pre + s) %% 75);
        sec[15] = 2;
        sec[16] = sec[20] = 1;
        sec[17] = sec[21] = 1;
        sec[18] = sec[22] = 0x66;   /* Form 2, Video + Audio, Real-Time */
        memcpy( sec + 24, ps + off, chunk );
        memcpy( sec + 2348, "\xde\xad\xbe\xef", 4 );   /* non-zero EDC trailer */
    }
    rc = write_whole_file( path, dat, 44 + data_bytes );
    free( dat );
    return rc;
}

int main( int argc, char **argv )
{
    uint8_t *mpg_bytes = NULL;
    size_t mpg_size = 0;
    uint32_t xvid_tag = (uint32_t)'X' | ((uint32_t)'V' << 8) | ((uint32_t)'I' << 16) | ((uint32_t)'D' << 24);

    if (argc != 6) return 2;
    av_log_set_level( AV_LOG_ERROR );
    if (write_clip( argv[1], "asf", AV_CODEC_ID_WMV2, 0, 500000, 0,
                    AV_CODEC_ID_WMAV2, AV_SAMPLE_FMT_FLTP, 128000, NULL, NULL ) < 0)
    {
        fprintf( stderr, "failed to write WMV clip: %%s\n", argv[1] );
        return 1;
    }
    if (write_clip( argv[2], "mpeg", AV_CODEC_ID_MPEG1VIDEO, 0, 1000000, 2,
                    AV_CODEC_ID_MP2, AV_SAMPLE_FMT_S16, 128000, &mpg_bytes, &mpg_size ) < 0)
    {
        fprintf( stderr, "failed to write MPEG-1 clip: %%s\n", argv[2] );
        return 1;
    }
    if (write_clip( argv[3], "avi", AV_CODEC_ID_MPEG4, xvid_tag, 500000, 1,
                    AV_CODEC_ID_ADPCM_IMA_WAV, AV_SAMPLE_FMT_S16P, 0, NULL, NULL ) < 0)
    {
        free( mpg_bytes );
        fprintf( stderr, "failed to write AVI clip: %%s\n", argv[3] );
        return 1;
    }
    if (write_clip( argv[4], "mpeg1video", AV_CODEC_ID_MPEG1VIDEO, 0, 1000000, 2,
                    AV_CODEC_ID_NONE, AV_SAMPLE_FMT_NONE, 0, NULL, NULL ) < 0)
    {
        free( mpg_bytes );
        fprintf( stderr, "failed to write raw M1V clip: %%s\n", argv[4] );
        return 1;
    }
    if (write_vcd_dat( argv[5], mpg_bytes, mpg_size ) < 0)
    {
        free( mpg_bytes );
        fprintf( stderr, "failed to write VideoCD DAT clip: %%s\n", argv[5] );
        return 1;
    }
    free( mpg_bytes );
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
    avi_path = out_dir / "video-selftest.avi"
    m1v_path = out_dir / "video-selftest.m1v"
    dat_path = out_dir / "video-selftest.dat"
    with tempfile.TemporaryDirectory(prefix="madeira-clips-") as tmp:
        c_file = Path(tmp) / "gen_clips.c"
        exe_file = Path(tmp) / "gen_clips"
        c_file.write_text(GENERATOR_C)
        subprocess.run(
            [cc, "-std=c11", "-O2", "-Wall", "-Werror", "-I" + str(inc), str(c_file), "-o", str(exe_file)] + libs,
            check=True,
        )
        subprocess.run(
            [str(exe_file), str(wmv_path), str(mpg_path), str(avi_path), str(m1v_path), str(dat_path)],
            check=True,
        )

    wmv_bytes = wmv_path.read_bytes()
    mpg_bytes = mpg_path.read_bytes()
    avi_bytes = avi_path.read_bytes()
    m1v_bytes = m1v_path.read_bytes()
    dat_bytes = dat_path.read_bytes()
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
            "#define SELFTEST_RESIZE_W    %d\n"
            "#define SELFTEST_RESIZE_H    %d\n"
            "#define SELFTEST_AUDIO_RATE  %d\n"
            "#define SELFTEST_TONE_HZ     %d\n\n"
            "%s\n%s\n%s\n%s\n%s\n"
            "#endif /* MADEIRA_VIDEO_SELFTEST_CLIPS_H */\n"
            % (
                CLIP_W,
                CLIP_H,
                CLIP_FPS,
                CLIP_FRAMES,
                RESIZE_W,
                RESIZE_H,
                AUDIO_RATE,
                TONE_HZ,
                format_c_array("selftest_wmv_bytes", wmv_bytes),
                format_c_array("selftest_mpg_bytes", mpg_bytes),
                format_c_array("selftest_avi_bytes", avi_bytes),
                format_c_array("selftest_m1v_bytes", m1v_bytes),
                format_c_array("selftest_dat_bytes", dat_bytes),
            )
        )
    print(
        "wrote %s (%d B), %s (%d B), %s (%d B), %s (%d B), %s (%d B)"
        % (
            wmv_path.name, len(wmv_bytes),
            mpg_path.name, len(mpg_bytes),
            avi_path.name, len(avi_bytes),
            m1v_path.name, len(m1v_bytes),
            dat_path.name, len(dat_bytes),
        )
    )
    return wmv_path, mpg_path, avi_path, m1v_path, dat_path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out_dir", nargs="?", default=str(HERE), help="directory for generated clip outputs")
    ap.add_argument("--header", default="", help="optional path to write embedded C header")
    args = ap.parse_args()
    make_clips(args.out_dir, args.header or None)


if __name__ == "__main__":
    main()
