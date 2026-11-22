/* The wg_parser core for iOS: a pull demuxer + decoders on libavformat /
 * libavcodec / libswresample, with the platform decoders behind
 * wg_parser_backend_ios.h.                         (MADEIRA ml1980, ml1990)
 *
 * WHY THIS EXISTS
 * ---------------
 * ml1980: a 32-bit title plays its music as MP3 through DirectShow.  quartz's
 * autoplugger asks winegstreamer.dll for a splitter, and both candidates are
 * wg_parser users:
 *
 *   quartz:autoplug Failed to create filter for "MPEG-I Stream Splitter", hr 0x8007000e
 *   quartz:autoplug Failed to create filter for "GStreamer splitter filter", hr 0x8007000e
 *
 * 0x8007000e is quartz_parser.c parser_create()'s E_OUTOFMEMORY, which is what
 * it returns when wg_parser_create() fails -- and on this port every
 * wg_parser_* entry of the unix side returned STATUS_NOT_IMPLEMENTED, because
 * the upstream unix side is a GStreamer pipeline and there is no GStreamer on
 * iOS.
 *
 * ml1990: a 64-bit title opens its menu video (an MP4 embedded in one of its
 * data files) through Media Foundation's source resolver.  mfmp4srcsnk.dll is
 * absent, so the resolver falls back to winegstreamer's media source
 * (media_source.c), which is a wg_parser user too -- and this core refused the
 * MP4 ("no enabled demuxer recognised the stream").  The title reported
 * MF_E_UNSUPPORTED_BYTESTREAM_TYPE, retried about twelve times a second, and
 * its menu, which waits for the video, never appeared.  MP4/MOV with H.264 or
 * HEVC video and AAC (or MPEG audio / PCM) audio is now demuxed here and
 * decoded by VideoToolbox / AudioToolbox (wg_parser_apple_ios.c).
 * MADEIRA_WG_VIDEO=0 (read by the glue) restores the MP3/WAV-only behaviour.
 *
 * WHAT IS IMPLEMENTED
 * -------------------
 * The subset of wg_parser.c's semantics that quartz_parser.c and
 * media_source.c drive:
 *
 *   - the PULL protocol.  The PE side runs a read thread that loops on
 *     wg_parser_get_next_read_offset() (which BLOCKS until the parser wants
 *     bytes) and answers every request with wg_parser_push_data().  Here the
 *     demuxer's AVIOContext read callback is the requester: it publishes
 *     {offset, size}, wakes the read thread, and sleeps until push_data has
 *     copied the bytes straight into the AVIO buffer.  push_data with size 0
 *     is end of file, with a NULL pointer a read error.
 *
 *   - connect() probes and analyses on the caller's thread through that
 *     protocol.  The demuxer name, the probe score and every codec are checked
 *     against an allowlist, so content this port cannot play fails connect()
 *     with an error (quartz goes on to its next filter; media_source reports
 *     the failure) instead of being accepted and never producing a sample.
 *     An unsupported codec is logged with its libavcodec id.
 *
 *   - STREAMS.  An MP3/WAV file exposes its first audio stream.  An MP4, an
 *     ASF (WMV/WMA, the Windows Media Format reader's files: wm_reader.c) or
 *     an MPEG program stream (.mpg: MPEG-1/2 video, MPEG audio) exposes its
 *     first video stream and its first audio stream, in container order.  A
 *     file whose video cannot be decoded is refused outright; one whose audio
 *     cannot be decoded exposes the video alone (logged).  An ASF's Windows
 *     Media video and an MPEG program stream's MPEG-1/2 video are decoded
 *     here, in software, by libavcodec (mav_lavc_video), their WMA and MPEG
 *     audio by libavcodec too.
 *
 *   - one demuxer, several consumers.  wg_parser.c runs a GStreamer thread
 *     that parks one buffer per stream; here decoding is LAZY, on the thread
 *     that asks for a buffer, and a packet read for a stream other than the
 *     one being served is queued for that stream (dropped if it is disabled).
 *     A queue another thread reads holds back the reader that fills it once
 *     it passes a soft limit (mav_wait_drain), so a stream that falls behind
 *     no longer loses packets; past the hard limit (an unread stream only)
 *     the overflow is dropped and logged.  One buffer per stream is
 *     outstanding until release_buffer; S_FALSE at end of stream.
 *
 *   - video.  The native format reported by get_current_format is 4:2:0 NV12
 *     at the coded display size (MADEIRA_WG_VIDEO_FORMAT can choose another,
 *     see the glue), which media_source.c turns into NV12 / YV12 / YUY2 /
 *     I420 / IYUV media types.  stream_enable accepts NV12, I420, YV12, YUY2,
 *     UYVY, YVYU, BGRx (RGB32), BGRA (ARGB32), RGBA (ABGR32), BGR (RGB24, the
 *     WM reader's default), RGB16 (565) and RGB15 (555) at the native size,
 *     with a negative height meaning bottom-up rows, exactly as wg_format says.
 *     Frames are laid out the way GStreamer lays them out (4-byte aligned
 *     strides) because that is what wg_format_get_stride() / the PE side
 *     assume.  Decoded pictures come back in decode order and are re-ordered
 *     here by presentation time (a picture is final once the demuxer's decode
 *     time has reached it, which no later packet can undercut).
 *
 *   - "output_compressed" parsers (MPEG-I splitter, WAVE parser, AVI
 *     splitter) hand the COMPRESSED stream to a separate decoder filter.  This
 *     port has decoder filters for Windows Media and MPEG only, so they accept
 *     PCM, an ASF and an MPEG program stream; MP3 and MP4 are refused there
 *     and quartz then tries the decoding splitter.  An application that reads
 *     compressed samples (KiriKiri's movie plugin, into the WMV / WMA decoder
 *     DMOs; a graph built by hand on quartz's MPEG-1 splitter, into the MPEG
 *     video and audio decoders) gets an ASF's Windows Media streams and an
 *     MPEG program stream's MPEG-1 video and MPEG audio as the demuxer's
 *     packets (mav_enable_compressed); its other streams are decoded as usual
 *     (and quartz's MPEG-1 splitter, which takes nothing else, gives way to
 *     the decoding splitter).
 *
 *   - seek is accurate: the demuxer seeks at or before the target (to a video
 *     keyframe when there is video), decoders are flushed, and decoded output
 *     before the target is dropped (audio trimmed to the sample), so the first
 *     buffer after a seek starts at the requested time.  A stop position ends
 *     every stream there.  Seeking any stream seeks them all, as in wg_parser.c.
 *
 * This file does not include any Wine header.  winegstreamer_unixlib_ios.c
 * includes it and maps the Wine structures onto the small API below, and
 * tests/host/check-wg-parser.py compiles it on its own against a host
 * FFmpeg, with stub backends, to exercise it under ASan.
 *
 * LOGGING: "[wg-parser] ml1990 ..." on stderr.  At most MAV_MAX_LOGS distinct
 * lines per process; a line identical to an earlier one is repeated only at
 * its 2nd, 4th, 8th ... occurrence with the count, so a caller that retries a
 * refused file forever neither floods the log nor hides the first refusals.
 */

#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/channel_layout.h>
#include <libavutil/mathematics.h>
#include <libavutil/mem.h>
#include <libavutil/pixdesc.h>
#include <libavutil/samplefmt.h>
#include <libswresample/swresample.h>

#include "wg_parser_backend_ios.h"

/***********************************************************************
 *           API (used by winegstreamer_unixlib_ios.c and the host test)
 */

/* Same order as unixlib.h `enum wg_audio_format`; the glue asserts it. */
enum mav_sample_format
{
    MAV_FMT_UNKNOWN = 0,
    MAV_FMT_U8,
    MAV_FMT_S16,
    MAV_FMT_S24,
    MAV_FMT_S32,
    MAV_FMT_F32,
    MAV_FMT_F64,
};

/* The same VALUES as unixlib.h `enum wg_video_format`; the glue asserts it. */
enum mav_pixel_format
{
    MAV_PIX_UNKNOWN = 0,
    MAV_PIX_BGRA = 1,
    MAV_PIX_BGRx = 2,
    MAV_PIX_BGR = 3,            /* 24-bit, B G R bytes: the WM reader's default output */
    MAV_PIX_RGB15 = 4,          /* 16-bit x1r5g5b5, little-endian */
    MAV_PIX_RGB16 = 5,          /* 16-bit r5g6b5, little-endian */
    MAV_PIX_RGBA = 6,
    MAV_PIX_I420 = 8,
    MAV_PIX_NV12 = 9,
    MAV_PIX_UYVY = 11,
    MAV_PIX_YUY2 = 12,
    MAV_PIX_YV12 = 13,
    MAV_PIX_YVYU = 14,
};

enum mav_status
{
    MAV_OK = 0,
    MAV_NO_BUFFER = 1,          /* end of stream, or the stream is disabled */
    MAV_E_STATE = -1,           /* not connected / no buffer / no request pending */
    MAV_E_UNSUPPORTED = -2,     /* content this port does not handle */
    MAV_E_IO = -3,              /* the read protocol failed */
    MAV_E_NOMEM = -4,
    MAV_E_PARAM = -5,
};

enum mav_stream_type
{
    MAV_STREAM_AUDIO = 1,
    MAV_STREAM_VIDEO = 2,
};

enum mav_codec_kind
{
    MAV_CODEC_PCM = 1,
    MAV_CODEC_MPEG_AUDIO = 2,
    MAV_CODEC_AAC = 3,
    MAV_CODEC_H264 = 4,
    MAV_CODEC_HEVC = 5,
    MAV_CODEC_WMA = 6,          /* WMA v1/v2/Pro/Lossless in ASF, on libavcodec */
    MAV_CODEC_WMV = 7,          /* WMV7/8/9, VC-1, MS-MPEG4 in ASF, on libavcodec (mav_lavc_video) */
    MAV_CODEC_MPEG_VIDEO = 8,   /* MPEG-1 / MPEG-2 video in an MPEG program stream, on libavcodec */
    MAV_CODEC_ADPCM = 9,        /* ADPCM and A-law / mu-law audio, on libavcodec */
    MAV_CODEC_AVI_VIDEO = 10,   /* MPEG-4, MJPEG, Cinepak, MS Video 1, MS RLE, Indeo 3-5, raw video in AVI */
};

/* Which Windows Media video a MAV_CODEC_WMV stream is (wg_format's WMV
 * formats, mapped by the glue); 0 for the MS-MPEG4 family, which has none. */
enum mav_wmv_format
{
    MAV_WMV_NONE = 0,
    MAV_WMV_WMV1,
    MAV_WMV_WMV2,
    MAV_WMV_WMV3,
    MAV_WMV_WMVA,
    MAV_WMV_WVC1,
};

struct mav_output
{
    enum mav_sample_format fmt;
    uint32_t rate;
    uint32_t channels;
    uint32_t channel_mask;      /* WinMM order == AV_CH_* order for bits 0-17 */
};

struct mav_video_output
{
    enum mav_pixel_format fmt;
    int32_t width, height;      /* height < 0: bottom-up rows (wg_format) */
    uint32_t fps_n, fps_d;
};

struct mav_stream_info
{
    enum mav_stream_type type;
    char codec[32];             /* libavcodec's codec name, for the log */
    char container[16];
    char backend[16];           /* "libavcodec", or the platform backend's name */
    enum mav_codec_kind kind;
    uint32_t layer;             /* MPEG audio layer, 0 otherwise */
    uint32_t bitrate;
    struct mav_output native;   /* audio: what the stream decodes to by default */
    struct mav_video_output vnative;   /* video: likewise */
    uint32_t profile, level;    /* H.264 */
    uint32_t version;           /* WMA: 1, 2, 3 (Pro) or 4 (Lossless) */
    uint32_t block_align, depth;   /* WMA */
    enum mav_wmv_format wmv;    /* WMV */
    uint32_t codec_data_len;    /* AAC: AudioSpecificConfig; H.264: avcC; WMA / WMV: the
                                 * WAVEFORMATEX / BITMAPINFOHEADER extra bytes (if they fit) */
    uint8_t codec_data[64];
    uint64_t duration;          /* 100 ns, 0 when unknown */
};

struct mav_buffer
{
    uint64_t pts;               /* 100 ns, stream time */
    uint64_t duration;          /* 100 ns */
    uint32_t size;              /* bytes */
    uint32_t stream;            /* index of the stream it belongs to */
    int discontinuity;
    int delta;                  /* video: not a keyframe (informational) */
};

#define MAV_MAX_STREAMS 2

struct mav_parser;

static void mav_configure( int video_allowed, const struct mav_video_backend *video,
                           const struct mav_audio_backend *audio, enum mav_pixel_format native );
/* 0: a compressed-output parser refuses an ASF too, as before the WM reader's compressed samples */
static void mav_allow_compressed_asf( int allowed );
/* 0: video is decoded on the thread that asks for a buffer, as before mav_ahead_main */
static void mav_allow_video_ahead( int allowed );
/* 0: omit the per-stream playback summary lines (first buffer and disconnect) */
static void mav_allow_summary( int allowed );
/* 0: raw MPEG-1 video (.m1v) is refused and RIFF/CDXA (.dat) sectors are not unwrapped, as before */
static void mav_allow_mpeg_raw( int allowed );
/* 0: an AVI is refused at connect again, as before AVI support */
static void mav_allow_avi( int allowed );
static struct mav_parser *mav_create( int output_compressed );
static void mav_destroy( struct mav_parser *p );
static int mav_connect( struct mav_parser *p, uint64_t file_size );
static void mav_disconnect( struct mav_parser *p );
static int mav_get_next_read_offset( struct mav_parser *p, uint64_t *offset, uint32_t *size );
static int mav_push_data( struct mav_parser *p, const void *data, uint32_t size );
static unsigned int mav_stream_count( struct mav_parser *p );
static int mav_stream_info( struct mav_parser *p, unsigned int stream, struct mav_stream_info *info );
static int mav_current_output( struct mav_parser *p, unsigned int stream, struct mav_output *out );
static int mav_current_video( struct mav_parser *p, unsigned int stream, struct mav_video_output *out );
static int mav_enable( struct mav_parser *p, unsigned int stream, const struct mav_output *out );
static int mav_enable_video( struct mav_parser *p, unsigned int stream, const struct mav_video_output *out );
static void mav_disable( struct mav_parser *p, unsigned int stream );
/* compressed-output parsers: can the stream hand out its packets, and do so */
static int mav_can_pass_compressed( struct mav_parser *p, unsigned int stream );
static int mav_enable_compressed( struct mav_parser *p, unsigned int stream );
/* stream < 0: the earliest buffer of any enabled stream (buffer->stream says which) */
static int mav_get_buffer( struct mav_parser *p, int stream, struct mav_buffer *buffer );
static int mav_copy_buffer( struct mav_parser *p, unsigned int stream, void *dst, uint32_t offset, uint32_t size );
static void mav_release_buffer( struct mav_parser *p, unsigned int stream );
static int mav_seek( struct mav_parser *p, unsigned int stream, int set_start, uint64_t start,
                     int set_stop, uint64_t stop );

/***********************************************************************
 *           implementation
 */

#define MAV_TAG "[wg-parser] ml1990 "
#define MAV_MAX_LOGS 64
#define MAV_AVIO_BUFFER (64 * 1024)
/* One request is at most this many bytes; AVIO copes with short reads. */
#define MAV_MAX_REQUEST (1024 * 1024)
/* Bytes avformat_find_stream_info may read.  Enough for many seconds of any
 * stream here; it bounds the analysis of an MP3 carrying cover art, whose
 * (undecodable) picture stream would otherwise keep the analysis reading. */
#define MAV_PROBESIZE ((int64_t)256 * 1024)
/* mp3dec.c's probe gives AVPROBE_SCORE_EXTENSION / 4 to a file that starts
 * with an ID3v2 tag larger than the probe buffer; anything below that is the
 * "detected only with low score" guess that misreads other MPEG files. */
#define MAV_MIN_PROBE_SCORE (AVPROBE_SCORE_EXTENSION / 4)
/* An ISO media file with a recognisable ftyp/moov/mdat scores 100; half of
 * that is the floor for accepting one without a file name. */
#define MAV_MIN_MOV_PROBE_SCORE (AVPROBE_SCORE_MAX / 2)
/* An MPEG program stream's first pack and system headers score 26
 * (AVPROBE_SCORE_EXTENSION / 2 + 1), where libavformat's probe stops; the
 * scores below that are a stray start code or two. */
#define MAV_MIN_MPEG_PROBE_SCORE (AVPROBE_SCORE_EXTENSION / 2)
/* 100 ns: how far before the target an MPEG program stream is seeked (mav_seek) */
#define MAV_MPEG_SEEK_LEAD 10000000
/* Consecutive undecodable packets before the stream is ended rather than
 * spun on. */
#define MAV_MAX_DECODE_ERRORS 512
#define MAV_MAX_CHANNELS 8
/* Pictures held for presentation-order output beyond what the decode-time
 * rule releases (a stream without decode times, or a broken one). */
#define MAV_REORDER_MAX 16
/* Decode-ahead (mav_ahead_main): pictures a video stream's worker keeps ready,
 * plus the one handed out.  A 1080p RGB32 picture is 8 MB. */
#ifndef MAV_AHEAD_SLOTS
#define MAV_AHEAD_SLOTS 4
#endif
/* Packets queued for a stream nobody is reading from yet. */
#ifndef MAV_QUEUE_MAX_PACKETS   /* tests/host/check-wg-parser-asf.py builds with small limits */
#define MAV_QUEUE_MAX_PACKETS 16384
#endif
#ifndef MAV_QUEUE_MAX_BYTES
#define MAV_QUEUE_MAX_BYTES ((size_t)64 << 20)
#endif
/* Back-pressure (mav_wait_drain).  A stream whose queue passes these, while
 * another thread reads it, holds the reader that demuxes for it until it has
 * drained to three quarters of them; the hard limits above then only apply to
 * a stream nobody reads (MAV_BACKPRESSURE_WAIT_MS without a read).  A packet
 * dropped from a video stream breaks every picture up to its next keyframe. */
#ifndef MAV_QUEUE_SOFT_PACKETS
#define MAV_QUEUE_SOFT_PACKETS 1024
#endif
#ifndef MAV_QUEUE_SOFT_BYTES
#define MAV_QUEUE_SOFT_BYTES ((size_t)16 << 20)
#endif
#ifndef MAV_BACKPRESSURE_WAIT_MS
#define MAV_BACKPRESSURE_WAIT_MS 5000
#endif
#define MAV_MAX_DIMENSION 8192

#define MAV_MOV_NAME "mov,mp4,m4a,3gp,3g2,mj2"

/* ---- configuration (set once by the glue, or by the host test) ---- */
static int mav_video_allowed = 1;
static const struct mav_video_backend *mav_vbackend;
static const struct mav_audio_backend *mav_abackend;
static enum mav_pixel_format mav_native_pix = MAV_PIX_NV12;
static int mav_compressed_asf = 1;
static int mav_video_ahead = 1;
static int mav_summary = 1;
static int mav_mpeg_raw = 1;
static int mav_avi_allowed = 1;

static void mav_configure( int video_allowed, const struct mav_video_backend *video,
                           const struct mav_audio_backend *audio, enum mav_pixel_format native )
{
    mav_video_allowed = !!video_allowed;
    mav_vbackend = video;
    mav_abackend = audio;
    mav_native_pix = native ? native : MAV_PIX_NV12;
}

static void mav_allow_compressed_asf( int allowed )
{
    mav_compressed_asf = !!allowed;
}

static void mav_allow_video_ahead( int allowed )
{
    mav_video_ahead = !!allowed;
}

static void mav_allow_summary( int allowed )
{
    mav_summary = !!allowed;
}

static void mav_allow_mpeg_raw( int allowed )
{
    mav_mpeg_raw = !!allowed;
}

static void mav_allow_avi( int allowed )
{
    mav_avi_allowed = !!allowed;
}

/* ---- the log: bounded, and deduplicated ---- */
static pthread_mutex_t mav_log_lock = PTHREAD_MUTEX_INITIALIZER;
static struct { uint32_t hash; uint32_t count; } mav_log_seen[MAV_MAX_LOGS];
static unsigned int mav_log_distinct;
static int mav_log_capped;

static void mav_log( const char *fmt, ... ) __attribute__((format(printf, 1, 2)));
static void mav_log( const char *fmt, ... )
{
    char line[512];
    uint32_t hash = 2166136261u, count = 0;
    unsigned int i;
    va_list args;
    const char *c;

    va_start( args, fmt );
    vsnprintf( line, sizeof(line), fmt, args );
    va_end( args );
    for (c = line; *c; c++) hash = (hash ^ (uint8_t)*c) * 16777619u;

    pthread_mutex_lock( &mav_log_lock );
    for (i = 0; i < mav_log_distinct; i++)
        if (mav_log_seen[i].hash == hash)
        {
            count = ++mav_log_seen[i].count;
            break;
        }
    if (i == mav_log_distinct)
    {
        if (mav_log_distinct + 1 >= MAV_MAX_LOGS)
        {
            if (!mav_log_capped)
            {
                mav_log_capped = 1;
                dprintf( 2, MAV_TAG "further distinct parser lines suppressed after %u\n", MAV_MAX_LOGS - 1 );
            }
            pthread_mutex_unlock( &mav_log_lock );
            return;
        }
        mav_log_seen[mav_log_distinct].hash = hash;
        mav_log_seen[mav_log_distinct].count = count = 1;
        mav_log_distinct++;
    }
    pthread_mutex_unlock( &mav_log_lock );

    if (count == 1)
        dprintf( 2, MAV_TAG "%s\n", line );
    else if (!(count & (count - 1)))
        dprintf( 2, MAV_TAG "%s (repeat #%u)\n", line, count );
}

/* Left in AVCodecContext.opaque so a shared av_log callback can tell this
 * core's decoder from any other user of libavcodec in the process. */
static char mav_decoder_marker;
#define MAV_DECODER_MARKER ((void *)&mav_decoder_marker)

struct mav_vframe
{
    void *handle;               /* the backend's picture */
    int64_t pts, duration;      /* stream time base */
    uint64_t decode_ns;         /* time spent in the backend decoding it */
};

/***********************************************************************
 *           the libavcodec video backend (Windows Media video)
 *
 * WMV7/8 (wmv1, wmv2), WMV9 (wmv3), VC-1 (WMVA, WVC1) and MS-MPEG4 v1-v3 have
 * no platform decoder on iOS, so they are decoded here, in software, by
 * libavcodec, behind the same contract as the platform backend.  The decoders
 * produce 4:2:0 planar pictures, copied into the NV12 layout the contract
 * maps.  They reorder internally: pictures come out in presentation order
 * with their own timestamps, so the core releases them at once (no decode
 * timestamps in ASF to release them by), and they hold the last pictures back
 * until mav_lavc_drain at the end of the stream.
 */
enum
{
    MAV_LAVC_WMV1 = 64, MAV_LAVC_WMV2, MAV_LAVC_WMV3, MAV_LAVC_VC1,
    MAV_LAVC_MSMPEG4V1, MAV_LAVC_MSMPEG4V2, MAV_LAVC_MSMPEG4V3,
    MAV_LAVC_MPEG1, MAV_LAVC_MPEG2,
    MAV_LAVC_MPEG4, MAV_LAVC_MJPEG, MAV_LAVC_CINEPAK, MAV_LAVC_MSVIDEO1,
    MAV_LAVC_MSRLE, MAV_LAVC_INDEO3, MAV_LAVC_INDEO4, MAV_LAVC_INDEO5,
    MAV_LAVC_RAWVIDEO,
};

struct mav_lavc_vdec
{
    AVCodecContext *ctx;
    AVPacket *pkt;
    AVFrame *frame;
    unsigned int bad_format_logged;
    /* MPEG-1/2: an MPEG program stream seeks to a pack, not to a keyframe, and
     * the pictures that refer to what came before are garbage; they are
     * dropped until the first keyframe after opening or a flush. */
    int key_only, need_key;
    /* Paletted AVI streams: avidec attaches the BITMAPINFOHEADER palette as
     * AV_PKT_DATA_PALETTE once and clears its flag during stream analysis, so a
     * later seek (including the initial seek to 0) would leave rawvideo and
     * cinepak with an empty palette unless we re-send it after a flush. */
    uint8_t pal[AVPALETTE_SIZE];
    int has_pal, send_pal;
    /* An AVI's packet times are in decode order (its index): a picture takes
     * libavcodec's best-effort time, which follows the packets' dts. */
    int avi_timing;
};

struct mav_lavc_picture
{
    uint8_t *data;              /* Y plane, then the interleaved CbCr plane */
    uint32_t width, height, y_stride, uv_stride;
    int full_range;
};

static enum AVCodecID mav_lavc_codec_id( int codec )
{
    switch (codec)
    {
    case MAV_LAVC_WMV1:      return AV_CODEC_ID_WMV1;
    case MAV_LAVC_WMV2:      return AV_CODEC_ID_WMV2;
    case MAV_LAVC_WMV3:      return AV_CODEC_ID_WMV3;
    case MAV_LAVC_VC1:       return AV_CODEC_ID_VC1;
    case MAV_LAVC_MSMPEG4V1: return AV_CODEC_ID_MSMPEG4V1;
    case MAV_LAVC_MSMPEG4V2: return AV_CODEC_ID_MSMPEG4V2;
    case MAV_LAVC_MSMPEG4V3: return AV_CODEC_ID_MSMPEG4V3;
    case MAV_LAVC_MPEG1:     return AV_CODEC_ID_MPEG1VIDEO;
    case MAV_LAVC_MPEG2:     return AV_CODEC_ID_MPEG2VIDEO;
    case MAV_LAVC_MPEG4:     return AV_CODEC_ID_MPEG4;
    case MAV_LAVC_MJPEG:     return AV_CODEC_ID_MJPEG;
    case MAV_LAVC_CINEPAK:   return AV_CODEC_ID_CINEPAK;
    case MAV_LAVC_MSVIDEO1:  return AV_CODEC_ID_MSVIDEO1;
    case MAV_LAVC_MSRLE:     return AV_CODEC_ID_MSRLE;
    case MAV_LAVC_INDEO3:    return AV_CODEC_ID_INDEO3;
    case MAV_LAVC_INDEO4:    return AV_CODEC_ID_INDEO4;
    case MAV_LAVC_INDEO5:    return AV_CODEC_ID_INDEO5;
    case MAV_LAVC_RAWVIDEO:  return AV_CODEC_ID_RAWVIDEO;
    default:                 return AV_CODEC_ID_NONE;
    }
}

static int mav_lavc_supports( int codec )
{
    enum AVCodecID id = mav_lavc_codec_id( codec );
    return id != AV_CODEC_ID_NONE && avcodec_find_decoder( id ) != NULL;
}

static void mav_lavc_close( void *handle )
{
    struct mav_lavc_vdec *d = handle;

    if (!d) return;
    avcodec_free_context( &d->ctx );
    av_packet_free( &d->pkt );
    av_frame_free( &d->frame );
    free( d );
}

static void *mav_lavc_open( int codec, const uint8_t *extradata, uint32_t extradata_size,
                            uint32_t width, uint32_t height, char *why, size_t why_size )
{
    const AVCodec *dec = avcodec_find_decoder( mav_lavc_codec_id( codec ) );
    struct mav_lavc_vdec *d;

    if (!dec)
    {
        snprintf( why, why_size, "no decoder in this build" );
        return NULL;
    }
    if (!(d = calloc( 1, sizeof(*d) ))) return NULL;
    if (!(d->ctx = avcodec_alloc_context3( dec )) || !(d->pkt = av_packet_alloc()) || !(d->frame = av_frame_alloc()))
        goto fail;
    d->ctx->opaque = MAV_DECODER_MARKER;
    d->ctx->width = d->ctx->coded_width = (int)width;
    d->ctx->height = d->ctx->coded_height = (int)height;
    d->ctx->thread_count = 1;   /* every call is made under the parser's lock, one at a time */
    if (extradata_size)
    {
        if (!(d->ctx->extradata = av_mallocz( (size_t)extradata_size + AV_INPUT_BUFFER_PADDING_SIZE ))) goto fail;
        memcpy( d->ctx->extradata, extradata, extradata_size );
        d->ctx->extradata_size = (int)extradata_size;
    }
    if (avcodec_open2( d->ctx, dec, NULL ) < 0)
    {
        snprintf( why, why_size, "decoder did not open" );
        goto fail;
    }
    d->key_only = d->need_key = codec == MAV_LAVC_MPEG1 || codec == MAV_LAVC_MPEG2;
    return d;
fail:
    mav_lavc_close( d );
    return NULL;
}

/* Stream variant of mav_lavc_open for an AVI's video: its codecs (msrle,
 * msvideo1, cinepak, rawvideo, mpeg4) also need bits_per_coded_sample,
 * codec_tag, pixel format and any BITMAPINFOHEADER palette from codecpar.
 * ASF and MPEG streams keep mav_lavc_open. */
static void *mav_lavc_open_stream( int codec, const AVStream *st, char *why, size_t why_size )
{
    const AVCodec *dec = avcodec_find_decoder( mav_lavc_codec_id( codec ) );
    const AVCodecParameters *par = st->codecpar;
    struct mav_lavc_vdec *d;

    if (!dec)
    {
        snprintf( why, why_size, "no decoder in this build" );
        return NULL;
    }
    if (!(d = calloc( 1, sizeof(*d) ))) return NULL;
    if (!(d->ctx = avcodec_alloc_context3( dec )) || !(d->pkt = av_packet_alloc()) || !(d->frame = av_frame_alloc()))
        goto fail;
    d->ctx->opaque = MAV_DECODER_MARKER;
    if (avcodec_parameters_to_context( d->ctx, par ) < 0)
    {
        snprintf( why, why_size, "codec parameters rejected" );
        goto fail;
    }
    d->ctx->coded_width = d->ctx->width;
    d->ctx->coded_height = d->ctx->height;
    d->ctx->pkt_timebase = st->time_base;
    d->ctx->thread_count = 1;
    if (par->extradata && par->extradata_size > 0 && par->bits_per_coded_sample > 0 && par->bits_per_coded_sample <= 8)
    {
        int pal_size = (1 << par->bits_per_coded_sample) * 4;
        const uint8_t *pal_src;
        size_t i, n;

        if (pal_size > par->extradata_size) pal_size = par->extradata_size;
        pal_src = par->extradata + par->extradata_size - pal_size;
        if (pal_src - par->extradata >= 9 && !memcmp( par->extradata + par->extradata_size - 9, "BottomUp", 9 ))
            pal_src -= 9;
        n = (size_t)pal_size / 4;
        for (i = 0; i < n; i++)
        {
            uint32_t c = 0xff000000u | (uint32_t)pal_src[4 * i] | ((uint32_t)pal_src[4 * i + 1] << 8)
                         | ((uint32_t)pal_src[4 * i + 2] << 16);
            memcpy( d->pal + 4 * i, &c, 4 );
        }
        d->has_pal = d->send_pal = 1;
    }
    if (avcodec_open2( d->ctx, dec, NULL ) < 0)
    {
        snprintf( why, why_size, "decoder did not open" );
        goto fail;
    }
    d->key_only = d->need_key = codec == MAV_LAVC_MPEG1 || codec == MAV_LAVC_MPEG2;
    d->avi_timing = 1;
    return d;
fail:
    mav_lavc_close( d );
    return NULL;
}

static inline uint8_t mav_lavc_clip8( int v )
{
    return v < 0 ? 0 : v > 255 ? 255 : (uint8_t)v;
}

/* Signed row step: rawdec flips bottom-up AVI frames with a negative linesize. */
#define MAV_FROW(f, plane, row) ((f)->data[plane] + (ptrdiff_t)(row) * (f)->linesize[plane])

static inline void mav_lavc_rgb_pixel( const AVFrame *f, uint32_t x, uint32_t y, uint8_t *r, uint8_t *g, uint8_t *b )
{
    const uint8_t *row = MAV_FROW( f, 0, y );

    switch (f->format)
    {
    case AV_PIX_FMT_RGB24:
        *r = row[(size_t)3 * x]; *g = row[(size_t)3 * x + 1]; *b = row[(size_t)3 * x + 2];
        break;
    case AV_PIX_FMT_BGR24:
        *b = row[(size_t)3 * x]; *g = row[(size_t)3 * x + 1]; *r = row[(size_t)3 * x + 2];
        break;
    case AV_PIX_FMT_RGBA:
    case AV_PIX_FMT_RGB0:
        *r = row[(size_t)4 * x]; *g = row[(size_t)4 * x + 1]; *b = row[(size_t)4 * x + 2];
        break;
    case AV_PIX_FMT_BGRA:
    case AV_PIX_FMT_BGR0:
        *b = row[(size_t)4 * x]; *g = row[(size_t)4 * x + 1]; *r = row[(size_t)4 * x + 2];
        break;
    case AV_PIX_FMT_ARGB:
        *r = row[(size_t)4 * x + 1]; *g = row[(size_t)4 * x + 2]; *b = row[(size_t)4 * x + 3];
        break;
    case AV_PIX_FMT_ABGR:
        *b = row[(size_t)4 * x + 1]; *g = row[(size_t)4 * x + 2]; *r = row[(size_t)4 * x + 3];
        break;
    case AV_PIX_FMT_RGB555LE:
    case AV_PIX_FMT_BGR555LE:
    {
        uint16_t v = (uint16_t)(row[(size_t)2 * x] | (row[(size_t)2 * x + 1] << 8));
        uint8_t c0 = (uint8_t)((v >> 10) & 31), c1 = (uint8_t)((v >> 5) & 31), c2 = (uint8_t)(v & 31);
        c0 = (uint8_t)((c0 << 3) | (c0 >> 2));
        c1 = (uint8_t)((c1 << 3) | (c1 >> 2));
        c2 = (uint8_t)((c2 << 3) | (c2 >> 2));
        if (f->format == AV_PIX_FMT_RGB555LE) { *r = c0; *g = c1; *b = c2; }
        else { *b = c0; *g = c1; *r = c2; }
        break;
    }
    case AV_PIX_FMT_RGB565LE:
    case AV_PIX_FMT_BGR565LE:
    {
        uint16_t v = (uint16_t)(row[(size_t)2 * x] | (row[(size_t)2 * x + 1] << 8));
        uint8_t c0 = (uint8_t)(v >> 11), c1 = (uint8_t)((v >> 5) & 63), c2 = (uint8_t)(v & 31);
        c0 = (uint8_t)((c0 << 3) | (c0 >> 2));
        c1 = (uint8_t)((c1 << 2) | (c1 >> 4));
        c2 = (uint8_t)((c2 << 3) | (c2 >> 2));
        if (f->format == AV_PIX_FMT_RGB565LE) { *r = c0; *g = c1; *b = c2; }
        else { *b = c0; *g = c1; *r = c2; }
        break;
    }
    case AV_PIX_FMT_PAL8:
    {
        uint32_t c;
        memcpy( &c, f->data[1] + (size_t)row[x] * 4, 4 );
        *r = (uint8_t)(c >> 16); *g = (uint8_t)(c >> 8); *b = (uint8_t)c;
        break;
    }
    case AV_PIX_FMT_MONOWHITE:
    case AV_PIX_FMT_MONOBLACK:
    {
        int bit = (row[x >> 3] >> (7 - (x & 7))) & 1;
        *r = *g = *b = (f->format == AV_PIX_FMT_MONOBLACK ? bit : !bit) ? 255 : 0;
        break;
    }
    case AV_PIX_FMT_GBRP:
    case AV_PIX_FMT_GBRAP:
        *g = MAV_FROW( f, 0, y )[x];
        *b = MAV_FROW( f, 1, y )[x];
        *r = MAV_FROW( f, 2, y )[x];
        break;
    default:
        *r = *g = *b = 0;
        break;
    }
}

/* Copies or converts any decoder AVFrame (4:2:0 planar, MJPEG's 4:2:2/4:4:4,
 * Indeo's 4:1:0, Cinepak/rawvideo RGB, msvideo1 RGB555/PAL8, msrle PAL8/mono)
 * into the NV12 layout mav_convert_picture consumes, without libswscale. */
static int mav_lavc_fill_nv12( struct mav_lavc_picture *pic, const AVFrame *f )
{
    uint32_t w = pic->width, h = pic->height, cw = (w + 1) / 2, ch = (h + 1) / 2, x, y;
    uint8_t *y_dst = pic->data, *uv_dst = pic->data + (size_t)w * h;

    if (!f->data[0]) return 0;
    switch (f->format)
    {
    case AV_PIX_FMT_YUV420P:
    case AV_PIX_FMT_YUVJ420P:
    case AV_PIX_FMT_YUVA420P:
        if (!f->data[1] || !f->data[2]) return 0;
        pic->full_range = f->format == AV_PIX_FMT_YUVJ420P || f->color_range == AVCOL_RANGE_JPEG;
        for (y = 0; y < h; y++) memcpy( y_dst + (size_t)y * w, MAV_FROW( f, 0, y ), w );
        for (y = 0; y < ch; y++)
        {
            const uint8_t *u = MAV_FROW( f, 1, y ), *v = MAV_FROW( f, 2, y );
            uint8_t *uv = uv_dst + (size_t)y * pic->uv_stride;
            for (x = 0; x < cw; x++) { uv[(size_t)2 * x] = u[x]; uv[(size_t)2 * x + 1] = v[x]; }
        }
        return 1;

    case AV_PIX_FMT_NV12:
    case AV_PIX_FMT_NV21:
        if (!f->data[1]) return 0;
        pic->full_range = f->color_range == AVCOL_RANGE_JPEG;
        for (y = 0; y < h; y++) memcpy( y_dst + (size_t)y * w, MAV_FROW( f, 0, y ), w );
        for (y = 0; y < ch; y++)
        {
            const uint8_t *src = MAV_FROW( f, 1, y );
            uint8_t *uv = uv_dst + (size_t)y * pic->uv_stride;
            if (f->format == AV_PIX_FMT_NV12) memcpy( uv, src, (size_t)cw * 2 );
            else for (x = 0; x < cw; x++) { uv[(size_t)2 * x] = src[(size_t)2 * x + 1]; uv[(size_t)2 * x + 1] = src[(size_t)2 * x]; }
        }
        return 1;

    case AV_PIX_FMT_YUV422P:
    case AV_PIX_FMT_YUVJ422P:
    case AV_PIX_FMT_YUV444P:
    case AV_PIX_FMT_YUVJ444P:
    case AV_PIX_FMT_YUVA444P:
    case AV_PIX_FMT_YUV440P:
    case AV_PIX_FMT_YUVJ440P:
    case AV_PIX_FMT_YUV411P:
    case AV_PIX_FMT_YUVJ411P:
    case AV_PIX_FMT_YUV410P:
    {
        const AVPixFmtDescriptor *desc = av_pix_fmt_desc_get( f->format );
        uint32_t sw, sh;

        if (!desc || !f->data[1] || !f->data[2]) return 0;
        sw = desc->log2_chroma_w;
        sh = desc->log2_chroma_h;
        pic->full_range = f->color_range == AVCOL_RANGE_JPEG || f->format == AV_PIX_FMT_YUVJ422P
                          || f->format == AV_PIX_FMT_YUVJ444P || f->format == AV_PIX_FMT_YUVJ440P
                          || f->format == AV_PIX_FMT_YUVJ411P;
        for (y = 0; y < h; y++) memcpy( y_dst + (size_t)y * w, MAV_FROW( f, 0, y ), w );
        for (y = 0; y < ch; y++)
        {
            uint32_t y0 = (2 * y) >> sh, y1 = (2 * y + 1 < h ? 2 * y + 1 : h - 1) >> sh;
            const uint8_t *u0 = MAV_FROW( f, 1, y0 ), *u1 = MAV_FROW( f, 1, y1 );
            const uint8_t *v0 = MAV_FROW( f, 2, y0 ), *v1 = MAV_FROW( f, 2, y1 );
            uint8_t *uv = uv_dst + (size_t)y * pic->uv_stride;
            for (x = 0; x < cw; x++)
            {
                uint32_t x0 = (2 * x) >> sw, x1 = (2 * x + 1 < w ? 2 * x + 1 : w - 1) >> sw;
                uv[(size_t)2 * x] = (uint8_t)((u0[x0] + u0[x1] + u1[x0] + u1[x1] + 2) >> 2);
                uv[(size_t)2 * x + 1] = (uint8_t)((v0[x0] + v0[x1] + v1[x0] + v1[x1] + 2) >> 2);
            }
        }
        return 1;
    }

    case AV_PIX_FMT_YUYV422:
    case AV_PIX_FMT_UYVY422:
    case AV_PIX_FMT_YVYU422:
    {
        int y0 = f->format == AV_PIX_FMT_UYVY422 ? 1 : 0, y1 = y0 + 2;
        int uo = f->format == AV_PIX_FMT_YUYV422 ? 1 : f->format == AV_PIX_FMT_UYVY422 ? 0 : 3;
        int vo = f->format == AV_PIX_FMT_YUYV422 ? 3 : f->format == AV_PIX_FMT_UYVY422 ? 2 : 1;

        pic->full_range = f->color_range == AVCOL_RANGE_JPEG;
        for (y = 0; y < h; y++)
        {
            const uint8_t *s = MAV_FROW( f, 0, y );
            uint8_t *yd = y_dst + (size_t)y * w;
            for (x = 0; x < w; x += 2)
            {
                yd[x] = s[2 * x + y0];
                if (x + 1 < w) yd[x + 1] = s[2 * x + y1];
            }
        }
        for (y = 0; y < ch; y++)
        {
            const uint8_t *s0 = MAV_FROW( f, 0, 2 * y );
            const uint8_t *s1 = MAV_FROW( f, 0, 2 * y + 1 < h ? 2 * y + 1 : h - 1 );
            uint8_t *uv = uv_dst + (size_t)y * pic->uv_stride;
            for (x = 0; x < cw; x++)
            {
                uv[(size_t)2 * x] = (uint8_t)((s0[4 * x + uo] + s1[4 * x + uo] + 1) >> 1);
                uv[(size_t)2 * x + 1] = (uint8_t)((s0[4 * x + vo] + s1[4 * x + vo] + 1) >> 1);
            }
        }
        return 1;
    }

    case AV_PIX_FMT_GRAY8:
    case AV_PIX_FMT_YA8:
        pic->full_range = f->color_range != AVCOL_RANGE_MPEG;
        if (f->format == AV_PIX_FMT_GRAY8)
            for (y = 0; y < h; y++) memcpy( y_dst + (size_t)y * w, MAV_FROW( f, 0, y ), w );
        else
            for (y = 0; y < h; y++)
            {
                const uint8_t *s = MAV_FROW( f, 0, y );
                for (x = 0; x < w; x++) y_dst[(size_t)y * w + x] = s[(size_t)2 * x];
            }
        memset( uv_dst, 128, (size_t)pic->uv_stride * ch );
        return 1;

    case AV_PIX_FMT_PAL8:
        if (!f->data[1]) return 0;
        __attribute__((fallthrough));
    case AV_PIX_FMT_GBRP:
    case AV_PIX_FMT_GBRAP:
        if ((f->format == AV_PIX_FMT_GBRP || f->format == AV_PIX_FMT_GBRAP) && (!f->data[1] || !f->data[2]))
            return 0;
        __attribute__((fallthrough));
    case AV_PIX_FMT_RGB24:
    case AV_PIX_FMT_BGR24:
    case AV_PIX_FMT_RGBA:
    case AV_PIX_FMT_RGB0:
    case AV_PIX_FMT_BGRA:
    case AV_PIX_FMT_BGR0:
    case AV_PIX_FMT_ARGB:
    case AV_PIX_FMT_ABGR:
    case AV_PIX_FMT_RGB555LE:
    case AV_PIX_FMT_BGR555LE:
    case AV_PIX_FMT_RGB565LE:
    case AV_PIX_FMT_BGR565LE:
    case AV_PIX_FMT_MONOWHITE:
    case AV_PIX_FMT_MONOBLACK:
    {
        /* Exact studio-swing inverse of mav_yuv_coefs (BT.601 / BT.709): both
         * YUV and RGB callers get compliant values, with neutral gray at 128. */
        int bt709 = f->colorspace == AVCOL_SPC_BT709 ? 1
                  : (f->colorspace == AVCOL_SPC_BT470BG || f->colorspace == AVCOL_SPC_SMPTE170M
                     || f->colorspace == AVCOL_SPC_FCC) ? 0 : (h >= 720);
        int yr = bt709 ? 11966 : 16829, yg = bt709 ? 40254 : 33039, yb = bt709 ? 4064 : 6416;
        int ur = bt709 ? -6595 : -9714, ug = bt709 ? -22189 : -19070, ub = 28784;
        int vr = 28784, vg = bt709 ? -26145 : -24103, vb = bt709 ? -2639 : -4681;

        pic->full_range = 0;
        for (y = 0; y < ch; y++)
        {
            uint32_t y0 = 2 * y, y1 = y0 + 1 < h ? y0 + 1 : y0;
            uint8_t *yd0 = y_dst + (size_t)y0 * w, *yd1 = y_dst + (size_t)y1 * w;
            uint8_t *uv = uv_dst + (size_t)y * pic->uv_stride;

            for (x = 0; x < cw; x++)
            {
                uint32_t x0 = 2 * x, x1 = x0 + 1 < w ? x0 + 1 : x0;
                uint8_t r00, g00, b00, r01, g01, b01, r10, g10, b10, r11, g11, b11;
                int rs, gs, bs;

                mav_lavc_rgb_pixel( f, x0, y0, &r00, &g00, &b00 );
                yd0[x0] = (uint8_t)(16 + ((yr * r00 + yg * g00 + yb * b00 + 32768) >> 16));
                if (x1 != x0)
                {
                    mav_lavc_rgb_pixel( f, x1, y0, &r01, &g01, &b01 );
                    yd0[x1] = (uint8_t)(16 + ((yr * r01 + yg * g01 + yb * b01 + 32768) >> 16));
                }
                else { r01 = r00; g01 = g00; b01 = b00; }

                if (y1 != y0)
                {
                    mav_lavc_rgb_pixel( f, x0, y1, &r10, &g10, &b10 );
                    yd1[x0] = (uint8_t)(16 + ((yr * r10 + yg * g10 + yb * b10 + 32768) >> 16));
                    if (x1 != x0)
                    {
                        mav_lavc_rgb_pixel( f, x1, y1, &r11, &g11, &b11 );
                        yd1[x1] = (uint8_t)(16 + ((yr * r11 + yg * g11 + yb * b11 + 32768) >> 16));
                    }
                    else { r11 = r10; g11 = g10; b11 = b10; }
                }
                else { r10 = r00; g10 = g00; b10 = b00; r11 = r01; g11 = g01; b11 = b01; }

                rs = r00 + r01 + r10 + r11;
                gs = g00 + g01 + g10 + g11;
                bs = b00 + b01 + b10 + b11;
                uv[(size_t)2 * x] = mav_lavc_clip8( 128 + ((ur * rs + ug * gs + ub * bs + 131072) >> 18) );
                uv[(size_t)2 * x + 1] = mav_lavc_clip8( 128 + ((vr * rs + vg * gs + vb * bs + 131072) >> 18) );
            }
        }
        return 1;
    }

    default:
        return 0;
    }
}
#undef MAV_FROW

/* One decoded picture into its own NV12 copy, handed to `emit`. */
static void mav_lavc_emit( struct mav_lavc_vdec *d, const AVFrame *f, mav_vframe_emit emit, void *ctx )
{
    struct mav_lavc_picture *pic;
    uint32_t w = (uint32_t)f->width, h = (uint32_t)f->height, cw = (w + 1) / 2, ch = (h + 1) / 2;
    int64_t pts = d->avi_timing ? (f->best_effort_timestamp != AV_NOPTS_VALUE ? f->best_effort_timestamp : f->pts)
                                : (f->pts != AV_NOPTS_VALUE ? f->pts : f->best_effort_timestamp);

    if (d->need_key)
    {
        if (!(f->flags & AV_FRAME_FLAG_KEY)) return;
        d->need_key = 0;
    }
    if (!w || !h || w > MAV_MAX_DIMENSION || h > MAV_MAX_DIMENSION || !(pic = calloc( 1, sizeof(*pic) ))) return;
    pic->width = w;
    pic->height = h;
    pic->y_stride = w;
    pic->uv_stride = cw * 2;
    if (!(pic->data = malloc( (size_t)w * h + (size_t)pic->uv_stride * ch )) || !mav_lavc_fill_nv12( pic, f ))
    {
        if (pic->data && d->bad_format_logged++ < 3)
            mav_log( "%s: picture in unsupported pixel format %d; dropped", d->ctx->codec->name, f->format );
        free( pic->data );
        free( pic );
        return;
    }
    emit( ctx, pic, pts == AV_NOPTS_VALUE ? INT64_MIN : pts, f->duration > 0 ? f->duration : INT64_MIN );
}

static void mav_lavc_receive( struct mav_lavc_vdec *d, mav_vframe_emit emit, void *ctx )
{
    while (avcodec_receive_frame( d->ctx, d->frame ) >= 0)
    {
        mav_lavc_emit( d, d->frame, emit, ctx );
        av_frame_unref( d->frame );
    }
}

static int mav_lavc_decode( void *handle, const uint8_t *data, uint32_t size, int64_t pts, int64_t duration,
                            int keyframe, mav_vframe_emit emit, void *ctx )
{
    struct mav_lavc_vdec *d = handle;
    int err;

    if (size > INT_MAX || (size && !data) || av_new_packet( d->pkt, (int)size ) < 0) return -1;
    if (size) memcpy( d->pkt->data, data, size );
    d->pkt->pts = pts == INT64_MIN ? AV_NOPTS_VALUE : pts;
    d->pkt->dts = AV_NOPTS_VALUE;
    d->pkt->duration = duration == INT64_MIN ? 0 : duration;
    d->pkt->flags = keyframe ? AV_PKT_FLAG_KEY : 0;
    while ((err = avcodec_send_packet( d->ctx, d->pkt )) == AVERROR(EAGAIN))
        mav_lavc_receive( d, emit, ctx );
    av_packet_unref( d->pkt );
    if (err >= 0) mav_lavc_receive( d, emit, ctx );
    return err < 0 ? -1 : 0;
}

/* Stream packet decode: preserves dts (AVI index timestamps and B-frame pts
 * guessing), packet buffer references (rawvideo) and AV_PKT_DATA_PALETTE. */
static int mav_lavc_decode_packet( void *handle, const AVPacket *pkt, mav_vframe_emit emit, void *ctx )
{
    struct mav_lavc_vdec *d = handle;
    const AVPacket *in = pkt;
    int err;

    if (d->send_pal)
    {
        d->send_pal = 0;
        if (!av_packet_get_side_data( pkt, AV_PKT_DATA_PALETTE, NULL ) && av_packet_ref( d->pkt, pkt ) == 0)
        {
            uint8_t *sd = av_packet_new_side_data( d->pkt, AV_PKT_DATA_PALETTE, AVPALETTE_SIZE );
            if (sd) memcpy( sd, d->pal, AVPALETTE_SIZE );
            in = d->pkt;
        }
    }
    while ((err = avcodec_send_packet( d->ctx, in )) == AVERROR(EAGAIN))
        mav_lavc_receive( d, emit, ctx );
    if (in == d->pkt) av_packet_unref( d->pkt );
    if (err >= 0) mav_lavc_receive( d, emit, ctx );
    return err < 0 ? -1 : 0;
}

/* End of the stream: the pictures the decoder still holds. */
static void mav_lavc_drain( void *handle, mav_vframe_emit emit, void *ctx )
{
    struct mav_lavc_vdec *d = handle;

    if (avcodec_send_packet( d->ctx, NULL ) >= 0) mav_lavc_receive( d, emit, ctx );
}

static int mav_lavc_map( void *frame, struct mav_vplanes *planes )
{
    struct mav_lavc_picture *pic = frame;

    planes->y = pic->data;
    planes->uv = pic->data + (size_t)pic->width * pic->height;
    planes->y_stride = pic->y_stride;
    planes->uv_stride = pic->uv_stride;
    planes->width = pic->width;
    planes->height = pic->height;
    planes->full_range = pic->full_range;
    return 0;
}

static void mav_lavc_unmap( void *frame )
{
    (void)frame;
}

static void mav_lavc_release( void *frame )
{
    struct mav_lavc_picture *pic = frame;

    if (!pic) return;
    free( pic->data );
    free( pic );
}

static void mav_lavc_flush( void *handle )
{
    struct mav_lavc_vdec *d = handle;

    avcodec_flush_buffers( d->ctx );
    d->need_key = d->key_only;
    d->send_pal = d->has_pal;
}

static const struct mav_video_backend mav_lavc_video =
{
    "libavcodec", mav_lavc_supports, mav_lavc_open, mav_lavc_decode, mav_lavc_map, mav_lavc_unmap,
    mav_lavc_release, mav_lavc_flush, mav_lavc_close,
};

struct mav_stream // NOLINT(clang-analyzer-optin.performance.Padding): fields grouped by role; at most MAV_MAX_STREAMS (2) per parser
{
    unsigned int number;        /* index among the exposed streams */
    int av_index;               /* AVStream index */
    enum mav_stream_type type;
    struct mav_stream_info info;
    AVRational time_base;
    int64_t origin;             /* stream time base: the timestamp that is 0 */

    /* ---- audio ---- */
    AVCodecContext *dec;        /* libavcodec decoder (MPEG audio, PCM) */
    void *adec;                 /* backend decoder (AAC) */
    AVFrame *frame;
    AVFrame *bframe;            /* the backend decoder's output, persistent */
    int64_t apts[8];            /* pts of packets the backend has not answered yet */
    unsigned int apts_count;
    SwrContext *swr;
    int swr_in_fmt, swr_in_rate;
    AVChannelLayout swr_in_layout;
    struct mav_output out;

    /* ---- video ---- */
    const struct mav_video_backend *vbackend;   /* the platform's, or mav_lavc_video */
    void *vdec;
    struct mav_video_output vout;
    struct mav_vframe *reorder; /* sorted by pts */
    unsigned int reorder_count, reorder_cap;
    int64_t last_dts;           /* stream time base, INT64_MIN = none yet */
    int64_t last_vpts;
    int64_t frame_duration;     /* 100 ns, from the frame rate */
    int decode_order;           /* AVI on libavcodec: pictures keep the decoder's order (mav_vframe_emit_cb) */
    int64_t m1v_gop_base;       /* raw MPEG-1 ES: display index of the current GOP's tr=0 picture */
    int64_t m1v_gop_frames;     /* raw MPEG-1 ES: pictures seen so far in the current GOP */
    int64_t m1v_coded_frames;   /* raw MPEG-1 ES: coded picture index */
    int bt709;

    /* ---- packets ---- */
    AVPacket *pkt;              /* the packet being decoded */
    int pkt_pending;
    AVPacket **queue;
    unsigned int queue_head, queue_count, queue_cap;
    size_t queue_bytes;
    pthread_t reader;           /* the thread that last asked for this stream's buffers */
    int has_reader;
    int unread;                 /* not read for MAV_BACKPRESSURE_WAIT_MS: queued without waiting */

    /* ---- the one outstanding output buffer ---- */
    uint8_t *buf;
    size_t buf_cap;
    struct mav_buffer cur;
    int has_buffer;

    int enabled, eos, draining, discontinuity;
    int compressed;             /* hands out the demuxer's packets (mav_enable_compressed) */
    unsigned int skipped;       /* compressed video: delta frames dropped after a seek */

    /* ---- video decode-ahead (mav_ahead_main), all under the parser lock ---- */
    struct mav_parser *parser;
    struct mav_ahead_slot
    {
        uint8_t *buf;
        size_t cap;
        struct mav_buffer cur;
    } ahead[MAV_AHEAD_SLOTS];
    unsigned int ready[MAV_AHEAD_SLOTS];   /* slots holding pictures, oldest first */
    unsigned int ready_count;
    int out_slot;               /* the slot get_buffer handed out, -1 = none */
    int ahead_on;               /* a worker decodes this stream's pictures */
    int ahead_failed;           /* it could not be started: decoded on demand */
    int ahead_eos;              /* the worker has no more pictures */
    int ahead_stop;             /* the worker leaves */
    int busy;                   /* the worker decodes or converts without the lock */
    pthread_t ahead_thread;
    int64_t next_pts;           /* 100 ns */
    int64_t seek_target;        /* 100 ns, -1 = none */
    unsigned int decode_errors, errors_logged;
    int delivered;              /* a buffer has been handed out (logged once) */

    /* ---- playback summary (mav_log_summary), all under the parser lock ---- */
    int ahead_used;             /* decoded ahead at least once (ahead_on clears before teardown) */
    int cur_counted;            /* the currently held buffer was counted in stat_delivered */
    uint64_t stat_delivered;
    uint64_t stat_seek_trim;
    uint64_t stat_decode_errors;
    uint64_t stat_bp_drops;
    uint64_t wait_ns_sum, wait_ns_max;
    uint64_t decode_count, decode_ns_sum, decode_ns_max;
    uint64_t priming_decode_ns; /* video: backend decode calls that emitted no frame yet */
    uint64_t cur_audio_ns;      /* audio: decode + swr_convert accumulated for the next buffer */
};

struct mav_parser
{
    /* ---- the read protocol (io_lock) ---- */
    pthread_mutex_t io_lock;
    pthread_cond_t read_cond;   /* a request was published / disconnect */
    pthread_cond_t done_cond;   /* the request was answered / disconnect */
    int connected;
    struct
    {
        uint8_t *dest;
        uint64_t offset;
        uint32_t size;          /* non-zero while a request is outstanding */
        int done;
        int result;             /* bytes, 0 = EOF, < 0 = read error */
    } req;

    /* ---- demux / decode state (lock) ---- */
    pthread_mutex_t lock;
    int output_compressed;
    uint64_t file_size;
    uint64_t pos;               /* next byte offset the AVIO callback reads */

    AVIOContext *avio;
    AVFormatContext *fmt;
    AVPacket *read_pkt;
    int is_mov;
    int is_asf;
    int is_mpeg;                /* an MPEG program stream */
    int is_mpegvideo;           /* a raw MPEG-1 video elementary stream (.m1v / .mpv) */
    int is_cdxa;                /* RIFF/CDXA VideoCD .dat unwrapped to 2324-byte packs */
    uint64_t cdxa_data_offset;
    uint64_t cdxa_sectors;
    uint64_t logical_size;      /* unwrapped byte length when is_cdxa */
    uint8_t *cdxa_raw;
    int is_avi;
    int ready;                  /* connected and streams exposed */
    int demux_eof;
    unsigned int read_errors_logged;
    int64_t stop;               /* 100 ns, -1 = none */

    struct mav_stream *streams[MAV_MAX_STREAMS];
    unsigned int stream_count;

    /* ---- back-pressure (lock) ---- */
    pthread_cond_t drain_cond;  /* a queue shrank, a stream changed state, or closing */
    unsigned int bp_waiters;    /* readers inside mav_wait_drain */
    unsigned int generation;    /* bumped by seek: a waiter re-checks everything */
    int closing;                /* disconnect: waiters leave, then the streams go */

    /* ---- decode-ahead (lock) ---- */
    pthread_cond_t ahead_cond;  /* a picture is ready, a slot is free, a worker is idle, or closing */
    unsigned int ahead_hold;    /* threads that wait for the workers to stop between pictures */
    unsigned int ahead_waiters; /* get_buffer callers waiting for a picture */
};

/***********************************************************************
 *           the read protocol (and RIFF/CDXA VideoCD sector unwrapping)
 */
#define MAV_CDXA_SECTOR_SIZE 2352
#define MAV_CDXA_HEADER_SIZE 24
#define MAV_CDXA_FORM2_DATA  2324
#define MAV_CDXA_FORM1_DATA  2048
#define MAV_CDXA_BATCH       28

static const uint8_t mav_cdxa_sync[12] =
{
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
};

static uint32_t mav_le32( const uint8_t *b )
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static int mav_raw_read_once( struct mav_parser *p, uint64_t offset, uint8_t *dest, uint32_t size )
{
    int result;

    if (!size) return 0;
    if (p->file_size && offset >= p->file_size) return AVERROR_EOF;
    if (size > MAV_MAX_REQUEST) size = MAV_MAX_REQUEST;
    if (p->file_size && offset + size > p->file_size) size = (uint32_t)(p->file_size - offset);

    pthread_mutex_lock( &p->io_lock );
    if (!p->connected)
    {
        pthread_mutex_unlock( &p->io_lock );
        return AVERROR_EXIT;
    }
    p->req.dest = dest;
    p->req.offset = offset;
    p->req.size = size;
    p->req.done = 0;
    p->req.result = 0;
    pthread_cond_broadcast( &p->read_cond );
    while (!p->req.done && p->connected)
        pthread_cond_wait( &p->done_cond, &p->io_lock );
    if (!p->req.done)
    {
        /* disconnected while waiting: nobody will answer */
        p->req.size = 0;
        p->req.dest = NULL;
        pthread_mutex_unlock( &p->io_lock );
        return AVERROR_EXIT;
    }
    result = p->req.result;
    p->req.dest = NULL;
    pthread_mutex_unlock( &p->io_lock );

    if (result > 0) return result;
    return result ? AVERROR(EIO) : AVERROR_EOF;
}

static int mav_raw_read_full( struct mav_parser *p, uint64_t offset, uint8_t *dest, uint32_t size )
{
    uint32_t got = 0;

    while (got < size)
    {
        int r = mav_raw_read_once( p, offset + got, dest + got, size - got );
        if (r == AVERROR_EOF) break;
        if (r < 0) return got ? (int)got : r;
        got += (uint32_t)r;
    }
    return got ? (int)got : AVERROR_EOF;
}

/* VideoCD .dat files (MEDIASUBTYPE_MPEG1VideoCD) wrap raw 2352-byte CD-ROM XA
 * Mode 2 sectors in a RIFF/CDXA container.  FFmpeg's psxstr demuxer only knows
 * PlayStation STR video/audio sectors, and mpegps reads raw bytes -- including
 * the 24-byte sync/MSF/XA-subheader and 4-byte EDC every 2352 bytes -- which
 * corrupts any PES packet crossing a sector boundary.  Each sector maps to
 * 2324 logical bytes (Form 2's user payload, where White Book VideoCD stores
 * one 2324-byte MPEG-1 pack; empty pre-gap or Form 1 ISO sectors become zero
 * stuffing that mpegps skips), so byte seeking stays exact. */
static int mav_detect_cdxa( struct mav_parser *p )
{
    uint8_t hdr[64], sec[MAV_CDXA_HEADER_SIZE];
    uint64_t off = 12, data_off = 0, avail, sectors;
    uint32_t data_size = 0;
    int r, found = 0;

    if (p->file_size && p->file_size < 44) return 0;
    r = mav_raw_read_full( p, 0, hdr, sizeof(hdr) );
    if (r == AVERROR_EOF || (r > 0 && r < 44)) return 0;
    if (r < 0) return r;
    if (memcmp( hdr, "RIFF", 4 ) != 0 || memcmp( hdr + 8, "CDXA", 4 ) != 0) return 0;

    while (off + 8 <= 4096 && (!p->file_size || off + 8 <= p->file_size))
    {
        uint8_t ch[8];
        uint32_t csize;

        if (off + 8 <= (uint64_t)r) memcpy( ch, hdr + off, 8 );
        else if ((r = mav_raw_read_full( p, off, ch, 8 )) < 8)
            return r < 0 && r != AVERROR_EOF ? r : 0;
        csize = mav_le32( ch + 4 );
        if (!memcmp( ch, "data", 4 ))
        {
            data_off = off + 8;
            data_size = csize;
            found = 1;
            break;
        }
        off += 8 + (uint64_t)csize + (csize & 1);
    }
    if (!found) return 0;
    if (!mav_video_allowed || !mav_mpeg_raw) return AVERROR_PATCHWELCOME;
    if (p->file_size && p->file_size < data_off + MAV_CDXA_SECTOR_SIZE) return 0;

    r = mav_raw_read_full( p, data_off, sec, sizeof(sec) );
    if (r < (int)sizeof(sec)) return r < 0 && r != AVERROR_EOF ? r : 0;
    if (memcmp( sec, mav_cdxa_sync, 12 ) != 0 || sec[15] != 2) return 0;

    if (p->file_size)
    {
        avail = p->file_size - data_off;
        if (data_size >= MAV_CDXA_SECTOR_SIZE && (uint64_t)data_size < avail) avail = data_size;
        sectors = avail / MAV_CDXA_SECTOR_SIZE;
    }
    else
        sectors = data_size >= MAV_CDXA_SECTOR_SIZE ? (uint64_t)data_size / MAV_CDXA_SECTOR_SIZE : 0;
    if (p->file_size && !sectors) return 0;

    if (!(p->cdxa_raw = malloc( (size_t)MAV_CDXA_BATCH * MAV_CDXA_SECTOR_SIZE ))) return AVERROR(ENOMEM);
    p->is_cdxa = 1;
    p->cdxa_data_offset = data_off;
    p->cdxa_sectors = sectors;
    p->logical_size = sectors * MAV_CDXA_FORM2_DATA;
    mav_log( "cdxa: unwrapping RIFF/CDXA Mode 2 sectors at +%llu (%llu sectors, %llu unwrapped bytes)",
             (unsigned long long)data_off, (unsigned long long)sectors, (unsigned long long)p->logical_size );
    return 1;
}

static int mav_cdxa_read( struct mav_parser *p, uint8_t *dest, int size )
{
    int total = 0;

    if (p->logical_size && p->pos >= p->logical_size) return AVERROR_EOF;
    if (p->logical_size && (uint64_t)size > p->logical_size - p->pos)
        size = (int)(p->logical_size - p->pos);

    while (total < size)
    {
        uint64_t sec_idx = p->pos / MAV_CDXA_FORM2_DATA;
        uint32_t sec_off = (uint32_t)(p->pos % MAV_CDXA_FORM2_DATA);
        uint32_t want = ((uint32_t)(size - total) + sec_off + MAV_CDXA_FORM2_DATA - 1) / MAV_CDXA_FORM2_DATA;
        uint32_t got_secs, k;
        int r;

        if (want > MAV_CDXA_BATCH) want = MAV_CDXA_BATCH;
        if (p->cdxa_sectors && sec_idx >= p->cdxa_sectors) break;
        if (p->cdxa_sectors && want > p->cdxa_sectors - sec_idx)
            want = (uint32_t)(p->cdxa_sectors - sec_idx);

        r = mav_raw_read_full( p, p->cdxa_data_offset + sec_idx * MAV_CDXA_SECTOR_SIZE,
                               p->cdxa_raw, want * MAV_CDXA_SECTOR_SIZE );
        if (r < 0) return total ? total : r;
        got_secs = (uint32_t)r / MAV_CDXA_SECTOR_SIZE;
        if (!got_secs) break;

        for (k = 0; k < got_secs && total < size; k++)
        {
            const uint8_t *raw = p->cdxa_raw + (size_t)k * MAV_CDXA_SECTOR_SIZE;
            uint32_t chunk = MAV_CDXA_FORM2_DATA - sec_off;
            int xa_mode2 = !memcmp( raw, mav_cdxa_sync, 12 ) && raw[15] == 2;
            uint8_t submode = raw[18];
            int has_start = !raw[24] && !raw[25] && raw[26] == 1;

            if ((int)chunk > size - total) chunk = (uint32_t)(size - total);
            if (xa_mode2 && (submode & 0x20) && ((submode & 0x0e) || has_start))
            {
                /* Mode 2 Form 2: 24-byte header + 2324-byte VideoCD MPEG-1 pack + 4-byte EDC */
                memcpy( dest + total, raw + MAV_CDXA_HEADER_SIZE + sec_off, chunk );
            }
            else if (xa_mode2 && !(submode & 0x20) && (submode & 0x06) && has_start)
            {
                /* Mode 2 Form 1 carrying video/audio: 2048-byte user data, zeroing the ECC tail */
                uint32_t body = sec_off < MAV_CDXA_FORM1_DATA ? MAV_CDXA_FORM1_DATA - sec_off : 0;
                if (body > chunk) body = chunk;
                if (body) memcpy( dest + total, raw + MAV_CDXA_HEADER_SIZE + sec_off, body );
                if (chunk > body) memset( dest + total + body, 0, chunk - body );
            }
            else
            {
                /* Empty pre-gap/lead-out or Form 1 ISO data sector: zero stuffing */
                memset( dest + total, 0, chunk );
            }
            p->pos += chunk;
            total += (int)chunk;
            sec_off = 0;
        }
    }
    return total ? total : AVERROR_EOF;
}

static int mav_avio_read( void *opaque, uint8_t *dest, int size )
{
    struct mav_parser *p = opaque;
    int result;

    if (size <= 0) return AVERROR(EINVAL);
    if (p->is_cdxa) return mav_cdxa_read( p, dest, size );
    result = mav_raw_read_once( p, p->pos, dest, (uint32_t)size );
    if (result > 0) p->pos += result;
    return result;
}

static int64_t mav_avio_seek( void *opaque, int64_t offset, int whence )
{
    struct mav_parser *p = opaque;
    uint64_t size = p->is_cdxa ? p->logical_size : p->file_size;
    int64_t target;

    whence &= ~AVSEEK_FORCE;
    switch (whence)
    {
    case AVSEEK_SIZE:
        return size ? (int64_t)size : AVERROR(ENOSYS);
    case SEEK_SET:
        target = offset;
        break;
    case SEEK_CUR:
        target = (int64_t)p->pos + offset;
        break;
    case SEEK_END:
        if (!size) return AVERROR(ENOSYS);
        target = (int64_t)size + offset;
        break;
    default:
        return AVERROR(EINVAL);
    }
    if (target < 0) return AVERROR(EINVAL);
    p->pos = target;
    return target;
}

static int mav_get_next_read_offset( struct mav_parser *p, uint64_t *offset, uint32_t *size )
{
    pthread_mutex_lock( &p->io_lock );
    while (p->connected && !(p->req.size && !p->req.done))
        pthread_cond_wait( &p->read_cond, &p->io_lock );
    if (!p->connected)
    {
        pthread_mutex_unlock( &p->io_lock );
        return MAV_E_STATE;
    }
    *offset = p->req.offset;
    *size = p->req.size;
    pthread_mutex_unlock( &p->io_lock );
    return MAV_OK;
}

static int mav_push_data( struct mav_parser *p, const void *data, uint32_t size )
{
    pthread_mutex_lock( &p->io_lock );
    if (!p->req.size || p->req.done || !p->req.dest)
    {
        pthread_mutex_unlock( &p->io_lock );
        return MAV_E_STATE;
    }
    if (!data)
        p->req.result = -1;
    else if (!size)
        p->req.result = 0;
    else
    {
        uint32_t n = size < p->req.size ? size : p->req.size;
        memcpy( p->req.dest, data, n );
        p->req.result = (int)n;
    }
    p->req.done = 1;
    p->req.size = 0;
    pthread_cond_broadcast( &p->done_cond );
    pthread_mutex_unlock( &p->io_lock );
    return MAV_OK;
}

static void mav_set_connected( struct mav_parser *p, int connected )
{
    pthread_mutex_lock( &p->io_lock );
    p->connected = connected;
    p->req.size = 0;
    p->req.done = 0;
    p->req.dest = NULL;
    pthread_cond_broadcast( &p->read_cond );
    pthread_cond_broadcast( &p->done_cond );
    pthread_mutex_unlock( &p->io_lock );
}

/***********************************************************************
 *           lifetime
 */
static struct mav_parser *mav_create( int output_compressed )
{
    struct mav_parser *p = calloc( 1, sizeof(*p) );

    if (!p) return NULL;
    pthread_mutex_init( &p->io_lock, NULL );
    pthread_cond_init( &p->read_cond, NULL );
    pthread_cond_init( &p->done_cond, NULL );
    pthread_mutex_init( &p->lock, NULL );
    pthread_cond_init( &p->drain_cond, NULL );
    pthread_cond_init( &p->ahead_cond, NULL );
    p->output_compressed = !!output_compressed;
    p->stop = -1;
    return p;
}

static void mav_queue_clear( struct mav_stream *s )
{
    while (s->queue_count)
    {
        av_packet_free( &s->queue[s->queue_head] );
        s->queue_head++;
        s->queue_count--;
    }
    s->queue_head = 0;
    s->queue_bytes = 0;
}

static void mav_reorder_clear( struct mav_stream *s )
{
    unsigned int i;

    for (i = 0; i < s->reorder_count; i++)
        if (s->vbackend) s->vbackend->release( s->reorder[i].handle );
    s->reorder_count = 0;
}

/* ---- decode-ahead: the parts the rest of the parser needs ---- */

/* A worker produces this stream's pictures; get_buffer hands out its slots. */
static int mav_ahead_mode( const struct mav_stream *s )
{
    return s->ahead_on && !s->compressed;
}

/* The pictures the worker kept, and the one handed out, are dropped (a seek,
 * a new format, a disable). */
static void mav_ahead_reset( struct mav_stream *s )
{
    s->ready_count = 0;
    s->out_slot = -1;
    s->ahead_eos = 0;
    s->cur_counted = 0;
}

/* The caller (holding the lock) owns every stream's decoder state once this
 * returns: no worker is decoding or converting, and none starts a picture
 * until mav_ahead_resume.  A worker finishes the picture it is on first. */
static void mav_ahead_quiesce( struct mav_parser *p )
{
    unsigned int i;
    int busy;

    p->ahead_hold++;
    for (;;)
    {
        for (busy = 0, i = 0; i < p->stream_count; i++) busy |= p->streams[i]->busy;
        if (!busy) break;
        pthread_cond_wait( &p->ahead_cond, &p->lock );
    }
}

static void mav_ahead_resume( struct mav_parser *p )
{
    p->ahead_hold--;
    pthread_cond_broadcast( &p->ahead_cond );
}

/* Disconnect: every worker leaves and is joined, and every get_buffer caller
 * waiting for a picture has left, before the streams are freed.  Called with
 * the lock and closing set; the lock is dropped while joining. */
static void mav_ahead_stop_all( struct mav_parser *p )
{
    unsigned int i;

    while (p->ahead_waiters)
    {
        pthread_cond_broadcast( &p->ahead_cond );
        pthread_cond_wait( &p->drain_cond, &p->lock );
    }
    for (i = 0; i < p->stream_count; i++)
    {
        struct mav_stream *s = p->streams[i];
        pthread_t thread;

        if (!s->ahead_on) continue;
        s->ahead_stop = 1;
        thread = s->ahead_thread;
        pthread_cond_broadcast( &p->ahead_cond );
        pthread_cond_broadcast( &p->drain_cond );
        pthread_mutex_unlock( &p->lock );
        pthread_join( thread, NULL );
        pthread_mutex_lock( &p->lock );
        s->ahead_on = 0;
    }
}

static void mav_stream_free( struct mav_stream *s )
{
    unsigned int i;

    if (!s) return;
    for (i = 0; i < MAV_AHEAD_SLOTS; i++) free( s->ahead[i].buf );
    mav_reorder_clear( s );
    free( s->reorder );
    if (s->vdec && s->vbackend) s->vbackend->close( s->vdec );
    if (s->adec && mav_abackend) mav_abackend->close( s->adec );
    mav_queue_clear( s );
    free( s->queue );
    swr_free( &s->swr );
    av_channel_layout_uninit( &s->swr_in_layout );
    avcodec_free_context( &s->dec );
    av_packet_free( &s->pkt );
    av_frame_free( &s->frame );
    av_frame_free( &s->bframe );
    free( s->buf );
    free( s );
}

static void mav_teardown( struct mav_parser *p )
{
    unsigned int i;

    for (i = 0; i < MAV_MAX_STREAMS; i++)
    {
        mav_stream_free( p->streams[i] );
        p->streams[i] = NULL;
    }
    p->stream_count = 0;
    av_packet_free( &p->read_pkt );
    avformat_close_input( &p->fmt );
    if (p->avio)
    {
        av_freep( &p->avio->buffer );
        avio_context_free( &p->avio );
    }
    free( p->cdxa_raw );
    p->cdxa_raw = NULL;
    p->ready = p->is_mov = p->is_asf = p->is_mpeg = p->is_mpegvideo = p->is_cdxa = p->is_avi = p->demux_eof = 0;
    p->cdxa_data_offset = p->cdxa_sectors = p->logical_size = 0;
    p->read_errors_logged = 0;
    p->stop = -1;
}

static void mav_log_summary( const struct mav_parser *p, const struct mav_stream *s, const char *what );

static void mav_disconnect( struct mav_parser *p )
{
    /* Wake the PE read thread (it gets an error and exits once the filter
     * clears its own flag) and any demuxer read waiting for an answer, THEN
     * take the decode lock, which that read may be holding. */
    mav_set_connected( p, 0 );
    pthread_mutex_lock( &p->lock );
    /* A reader held by back-pressure sleeps without the lock: wake it, and
     * free nothing until it has left mav_wait_drain.  It finishes its request
     * under the lock, before this thread gets the lock back. */
    p->closing = 1;
    pthread_cond_broadcast( &p->drain_cond );
    pthread_cond_broadcast( &p->ahead_cond );
    while (p->bp_waiters) pthread_cond_wait( &p->drain_cond, &p->lock );
    mav_ahead_stop_all( p );
    if (p->ready && mav_summary)
    {
        unsigned int i;
        for (i = 0; i < p->stream_count; i++)
            mav_log_summary( p, p->streams[i], "summary" );
    }
    mav_teardown( p );
    p->closing = 0;
    pthread_mutex_unlock( &p->lock );
}

static void mav_destroy( struct mav_parser *p )
{
    if (!p) return;
    mav_disconnect( p );
    pthread_cond_destroy( &p->ahead_cond );
    pthread_cond_destroy( &p->drain_cond );
    pthread_mutex_destroy( &p->lock );
    pthread_cond_destroy( &p->done_cond );
    pthread_cond_destroy( &p->read_cond );
    pthread_mutex_destroy( &p->io_lock );
    free( p );
}

/***********************************************************************
 *           formats
 */
static enum AVSampleFormat mav_av_format( enum mav_sample_format fmt )
{
    switch (fmt)
    {
    case MAV_FMT_U8:  return AV_SAMPLE_FMT_U8;
    case MAV_FMT_S16: return AV_SAMPLE_FMT_S16;
    case MAV_FMT_S24: return AV_SAMPLE_FMT_S32;   /* packed to 3 bytes after conversion */
    case MAV_FMT_S32: return AV_SAMPLE_FMT_S32;
    case MAV_FMT_F32: return AV_SAMPLE_FMT_FLT;
    case MAV_FMT_F64: return AV_SAMPLE_FMT_DBL;
    default:          return AV_SAMPLE_FMT_NONE;
    }
}

static uint32_t mav_bytes_per_sample( enum mav_sample_format fmt )
{
    switch (fmt)
    {
    case MAV_FMT_U8:  return 1;
    case MAV_FMT_S16: return 2;
    case MAV_FMT_S24: return 3;
    case MAV_FMT_S32:
    case MAV_FMT_F32: return 4;
    case MAV_FMT_F64: return 8;
    default:          return 0;
    }
}

static const char *mav_format_name( enum mav_sample_format fmt )
{
    static const char *const names[] = { "unknown", "u8", "s16", "s24", "s32", "f32", "f64" };
    return (unsigned)fmt < sizeof(names) / sizeof(names[0]) ? names[fmt] : "?";
}

static const char *mav_pix_name( enum mav_pixel_format fmt )
{
    switch (fmt)
    {
    case MAV_PIX_BGRA: return "bgra";
    case MAV_PIX_BGRx: return "bgrx";
    case MAV_PIX_BGR:  return "bgr";
    case MAV_PIX_RGB15: return "rgb15";
    case MAV_PIX_RGB16: return "rgb16";
    case MAV_PIX_RGBA: return "rgba";
    case MAV_PIX_I420: return "i420";
    case MAV_PIX_NV12: return "nv12";
    case MAV_PIX_UYVY: return "uyvy";
    case MAV_PIX_YUY2: return "yuy2";
    case MAV_PIX_YV12: return "yv12";
    case MAV_PIX_YVYU: return "yvyu";
    default:           return "?";
    }
}

#define MAV_MAX_SUMMARIES 48
static unsigned int mav_summary_count;

static uint64_t mav_now_ns( void )
{
    struct timespec ts;

    if (!mav_summary || clock_gettime( CLOCK_MONOTONIC, &ts )) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* One line per stream on its first buffer and at disconnect, so a device log
 * names the container, codec, backend, negotiated output format and mode, and
 * separates "nothing requested downstream" (delivered=0) from bitstream errors,
 * unread-queue drops and slow decode/convert. */
static void mav_log_summary( const struct mav_parser *p, const struct mav_stream *s, const char *what )
{
    uint64_t dropped = s->stat_seek_trim + s->stat_decode_errors + s->stat_bp_drops;
    double wait_avg = s->stat_delivered ? (double)s->wait_ns_sum / (double)s->stat_delivered / 1e6 : 0.0;
    double wait_max = (double)s->wait_ns_max / 1e6;
    double dec_avg = s->decode_count ? (double)s->decode_ns_sum / (double)s->decode_count / 1e6 : 0.0;
    double dec_max = (double)s->decode_ns_max / 1e6;
    const char *mode = s->compressed ? "compressed"
                     : (s->type == MAV_STREAM_VIDEO
                        && (s->ahead_used || (!s->stat_delivered && mav_video_ahead && !s->ahead_failed)))
                       ? "ahead" : "on-demand";
    char out[48], dec[48] = "";
    unsigned int n;

    (void)p;
    if (s->compressed)
        snprintf( out, sizeof(out), "compressed" );
    else if (s->type == MAV_STREAM_VIDEO)
        snprintf( out, sizeof(out), "%s %dx%d", mav_pix_name( s->vout.fmt ), s->vout.width, s->vout.height );
    else
        snprintf( out, sizeof(out), "%s %uHz %uch", mav_format_name( s->out.fmt ), s->out.rate, s->out.channels );

    if (!s->compressed)
        snprintf( dec, sizeof(dec), " decode=%.2f/%.2fms", dec_avg, dec_max );

    /* Not through mav_log: the timings make every summary a distinct line, and
     * a game that plays many short clips would spend mav_log's distinct lines
     * on them, so the lines of the movie that fails afterwards would be lost.
     * The summaries have a budget of their own. */
    n = __atomic_add_fetch( &mav_summary_count, 1, __ATOMIC_RELAXED );
    if (n == MAV_MAX_SUMMARIES + 1)
        dprintf( 2, MAV_TAG "further stream summaries suppressed after %u\n", MAV_MAX_SUMMARIES );
    if (n > MAV_MAX_SUMMARIES) return;
    dprintf( 2, MAV_TAG "stream %u %s: container=%s codec=%s backend=%s out=%s mode=%s%s "
             "delivered=%llu dropped=%llu (trim=%llu errors=%llu bp=%llu) wait=%.2f/%.2fms%s\n",
             s->number, what, s->info.container, s->info.codec, s->info.backend, out, mode,
             s->enabled ? "" : " [disabled]",
             (unsigned long long)s->stat_delivered, (unsigned long long)dropped,
             (unsigned long long)s->stat_seek_trim, (unsigned long long)s->stat_decode_errors,
             (unsigned long long)s->stat_bp_drops, wait_avg, wait_max, dec );
}

#define MAV_ALIGN4(x) (((x) + 3u) & ~3u)

/* GStreamer's layout of a raw video frame (what wg_format_get_stride() and
 * the PE side assume): plane offsets and strides.  Returns the frame size. */
struct mav_layout
{
    uint32_t stride[3];
    size_t offset[3];
    uint32_t chroma_height;
    size_t size;
};

static size_t mav_video_layout( enum mav_pixel_format fmt, uint32_t w, uint32_t h, struct mav_layout *l )
{
    memset( l, 0, sizeof(*l) );
    l->chroma_height = (h + 1) / 2;
    switch (fmt)
    {
    case MAV_PIX_NV12:
        l->stride[0] = l->stride[1] = MAV_ALIGN4( w );
        l->offset[1] = (size_t)l->stride[0] * h;
        l->size = l->offset[1] + (size_t)l->stride[1] * l->chroma_height;
        break;
    case MAV_PIX_I420:
    case MAV_PIX_YV12:
        l->stride[0] = MAV_ALIGN4( w );
        l->stride[1] = l->stride[2] = MAV_ALIGN4( (w + 1) / 2 );
        l->offset[1] = (size_t)l->stride[0] * h;
        l->offset[2] = l->offset[1] + (size_t)l->stride[1] * l->chroma_height;
        l->size = l->offset[2] + (size_t)l->stride[2] * l->chroma_height;
        break;
    case MAV_PIX_YUY2:
    case MAV_PIX_UYVY:
    case MAV_PIX_YVYU:
    case MAV_PIX_RGB15:
    case MAV_PIX_RGB16:
        l->stride[0] = MAV_ALIGN4( w * 2 );
        l->size = (size_t)l->stride[0] * h;
        break;
    case MAV_PIX_BGR:
        l->stride[0] = MAV_ALIGN4( w * 3 );
        l->size = (size_t)l->stride[0] * h;
        break;
    case MAV_PIX_BGRA:
    case MAV_PIX_BGRx:
    case MAV_PIX_RGBA:
        l->stride[0] = w * 4;
        l->size = (size_t)l->stride[0] * h;
        break;
    default:
        return 0;
    }
    return l->size;
}

/* The codecs this port accepts, and what they decode to natively.  PCM keeps
 * its own sample format (a WAVE parser must hand it on unchanged); MPEG audio
 * is reported as S16, which is what every DirectShow audio renderer takes. */
static int mav_classify_audio( enum AVCodecID id, enum mav_codec_kind *kind, uint32_t *layer,
                               enum mav_sample_format *native )
{
    *layer = 0;
    *kind = MAV_CODEC_PCM;
    switch (id)
    {
    case AV_CODEC_ID_PCM_U8:    *native = MAV_FMT_U8;  return 1;
    case AV_CODEC_ID_PCM_S16LE: *native = MAV_FMT_S16; return 1;
    case AV_CODEC_ID_PCM_S24LE: *native = MAV_FMT_S24; return 1;
    case AV_CODEC_ID_PCM_S32LE: *native = MAV_FMT_S32; return 1;
    case AV_CODEC_ID_PCM_F32LE: *native = MAV_FMT_F32; return 1;
    case AV_CODEC_ID_PCM_F64LE: *native = MAV_FMT_F64; return 1;
    case AV_CODEC_ID_MP1: *layer = 1; break;
    case AV_CODEC_ID_MP2: *layer = 2; break;
    case AV_CODEC_ID_MP3: *layer = 3; break;
    case AV_CODEC_ID_AAC:
        /* decoded by the platform backend, to float */
        *kind = MAV_CODEC_AAC;
        *native = MAV_FMT_F32;
        return 1;
    case AV_CODEC_ID_WMAV1:
    case AV_CODEC_ID_WMAV2:
    case AV_CODEC_ID_WMAPRO:
    case AV_CODEC_ID_WMALOSSLESS:
        /* libavcodec, reported as S16 like MPEG audio (the WM reader's default) */
        *kind = MAV_CODEC_WMA;
        *native = MAV_FMT_S16;
        return 1;
    case AV_CODEC_ID_ADPCM_MS:
    case AV_CODEC_ID_ADPCM_IMA_WAV:
    case AV_CODEC_ID_PCM_ALAW:
    case AV_CODEC_ID_PCM_MULAW:
        *kind = MAV_CODEC_ADPCM;
        *native = MAV_FMT_S16;
        return 1;
    default: return 0;
    }
    *kind = MAV_CODEC_MPEG_AUDIO;
    *native = MAV_FMT_S16;
    return 1;
}

static uint32_t mav_layout_mask( const AVChannelLayout *layout )
{
    if (layout->order == AV_CHANNEL_ORDER_NATIVE && av_popcount64( layout->u.mask ) == layout->nb_channels
        && !(layout->u.mask & ~(uint64_t)0x3ffff))
        return (uint32_t)layout->u.mask;
    {
        AVChannelLayout def;
        uint32_t mask = 0;
        av_channel_layout_default( &def, layout->nb_channels );
        if (def.order == AV_CHANNEL_ORDER_NATIVE) mask = (uint32_t)(def.u.mask & 0x3ffff);
        av_channel_layout_uninit( &def );
        return mask;
    }
}

static int64_t mav_to_100ns( const struct mav_stream *s, int64_t ts )
{
    return av_rescale_q( ts - s->origin, s->time_base, (AVRational){ 1, 10000000 } );
}

/* The containers that carry video here: MP4 (platform decoders), ASF, MPEG
 * program streams (including unwrapped RIFF/CDXA VideoCD .dat), raw MPEG-1
 * video elementary streams and AVI (libavcodec). */
static int mav_video_container( const struct mav_parser *p )
{
    return p->is_mov || p->is_asf || p->is_mpeg || p->is_mpegvideo || p->is_avi;
}

/* A compressed-output parser hands out an ASF's Windows Media streams, and an
 * MPEG program or raw MPEG-1 video stream's MPEG-1 video and MPEG audio, as
 * they are: the formats wg_format can describe (WMA, WMV1/2/3, WMVA, WVC1;
 * MPEG-1 video, MPEG audio), for the WM reader's compressed samples and
 * quartz's MPEG-1 splitter (which a graph built by hand connects to the MPEG
 * video and audio decoders).  MS-MPEG4 and MPEG-2 video have no wg_format. */
static int mav_passes_compressed( const struct mav_parser *p, const struct mav_stream *s )
{
    if (!p->output_compressed) return 0;
    if (p->is_asf)
        return s->info.kind == MAV_CODEC_WMA || (s->info.kind == MAV_CODEC_WMV && s->info.wmv != MAV_WMV_NONE);
    if (p->is_mpeg || p->is_mpegvideo)
        return s->info.kind == MAV_CODEC_MPEG_AUDIO || (s->info.kind == MAV_CODEC_MPEG_VIDEO && s->info.version == 1);
    return 0;
}

/* ---- raw MPEG-1 video elementary streams (FFmpeg's mpegvideo demuxer) ----
 *
 * Raw .m1v / .mpv elementary streams carry no PES timestamps, and rawdec sets
 * avg_frame_rate to 25/1 before parsing.  We read the sequence header's
 * frame_rate_code (ISO/IEC 11172-2 Table 2-D4) for the real rate, and give
 * each picture its display-order timestamp (frame_number * frame_duration, via
 * time_base = 1 / frame_rate) from its GOP base and 10-bit temporal_reference. */
static int mav_mpeg1_seq_fps( const uint8_t *buf, size_t size, AVRational *fps )
{
    static const AVRational tab[16] =
    {
        { 0, 1 },
        { 24000, 1001 }, { 24, 1 }, { 25, 1 },       { 30000, 1001 },
        { 30, 1 },       { 50, 1 }, { 60000, 1001 }, { 60, 1 },
        { 15, 1 },       { 5, 1 },  { 10, 1 },       { 12, 1 },       { 15, 1 },
    };
    size_t i;

    if (!buf || size < 8) return 0;
    for (i = 0; i + 8 <= size; i++)
    {
        unsigned int code;

        if (buf[i] || buf[i + 1] || buf[i + 2] != 1 || buf[i + 3] != 0xb3) continue;
        code = buf[i + 7] & 0x0f;
        if (tab[code].num > 0)
        {
            *fps = tab[code];
            return 1;
        }
    }
    return 0;
}

static int64_t mav_count_m1v_pictures( struct mav_parser *p )
{
    uint8_t *buf = malloc( MAV_AVIO_BUFFER + 3 );
    uint64_t off = 0;
    int64_t count = 0;
    size_t carry = 0;

    if (!buf) return 0;
    while (!p->file_size || off < p->file_size)
    {
        int r = mav_raw_read_once( p, off, buf + carry, MAV_AVIO_BUFFER );
        size_t n, i;

        if (r <= 0) break;
        off += (uint32_t)r;
        n = carry + (size_t)r;
        for (i = 0; i + 4 <= n; i++)
            if (!buf[i] && !buf[i + 1] && buf[i + 2] == 1 && !buf[i + 3])
            {
                count++;
                i += 3;
            }
        carry = n >= 3 ? 3 : n;
        memmove( buf, buf + n - carry, carry );
    }
    free( buf );
    return count;
}

static void mav_stamp_m1v_packet( struct mav_stream *s, AVPacket *pkt )
{
    const uint8_t *d = pkt->data;
    size_t n = (size_t)pkt->size, i;
    int64_t disp = 0;
    int found_pic = 0;

    for (i = 0; i + 4 <= n; i++)
    {
        uint8_t code;

        if (d[i] || d[i + 1] || d[i + 2] != 1) continue;
        code = d[i + 3];
        if (code == 0xb8)   /* GOP_START_CODE: earliest picture in display order has temporal_reference 0 */
        {
            s->m1v_gop_base += s->m1v_gop_frames;
            s->m1v_gop_frames = 0;
            i += 3;
        }
        else if (code == 0x00 && i + 6 <= n)   /* PICTURE_START_CODE */
        {
            unsigned int tr = ((unsigned int)d[i + 4] << 2) | (d[i + 5] >> 6);
            unsigned int pct = (d[i + 5] >> 3) & 7;
            int64_t k = (s->m1v_gop_frames & ~(int64_t)1023) | tr;

            if (k + 512 < s->m1v_gop_frames) k += 1024;
            else if (k > s->m1v_gop_frames + 512) k -= 1024;
            if (k < 0) k = tr;
            disp = s->m1v_gop_base + k;
            s->m1v_gop_frames++;
            if (pct == 1) pkt->flags |= AV_PKT_FLAG_KEY;
            else pkt->flags &= ~AV_PKT_FLAG_KEY;
            found_pic = 1;
            break;
        }
        else if (code >= 0x01 && code <= 0xaf)
            break;
    }
    if (!found_pic) disp = s->m1v_gop_base + s->m1v_gop_frames++;
    pkt->pts = disp;
    pkt->dts = s->m1v_coded_frames++;
    pkt->duration = 1;
}

/***********************************************************************
 *           connect
 */
static int mav_refuse( struct mav_parser *p, int status, const char *why )
{
    mav_log( "connect refused (%s, compressed_out=%d): %s",
             p->fmt && p->fmt->iformat ? p->fmt->iformat->name : "no container",
             p->output_compressed, why );
    return status;
}

static int mav_refuse_codec( struct mav_parser *p, const char *what, const AVCodecParameters *par,
                             const char *why )
{
    char text[320];
    snprintf( text, sizeof(text), "%s codec %s (codec id %d, tag %#x): %s", what,
              avcodec_get_name( par->codec_id ), (int)par->codec_id, par->codec_tag, why );
    return mav_refuse( p, MAV_E_UNSUPPORTED, text );
}

static struct mav_stream *mav_stream_new( struct mav_parser *p, AVStream *st, enum mav_stream_type type )
{
    struct mav_stream *s = calloc( 1, sizeof(*s) );

    if (!s) return NULL;
    s->av_index = st->index;
    s->type = type;
    s->info.type = type;
    s->time_base = st->time_base;
    /* MP4 timestamps are already on the presentation timeline (edit lists
     * applied by the demuxer), and so are ASF's (its preroll taken off by the
     * demuxer), both on one clock for every stream.  An MPEG program stream's
     * clock starts anywhere, and its streams start a little apart on it: they
     * all count from the earliest start, so they stay in sync.  An MP3/WAV
     * stream starts at its own start. */
    if (p->is_mov || p->is_asf || p->is_mpegvideo || p->is_avi)
        s->origin = 0;
    else if (p->is_mpeg && p->fmt->start_time != AV_NOPTS_VALUE)
        s->origin = av_rescale_q( p->fmt->start_time, AV_TIME_BASE_Q, st->time_base );
    else
        s->origin = st->start_time != AV_NOPTS_VALUE ? st->start_time : 0;
    s->last_dts = s->last_vpts = INT64_MIN;
    s->seek_target = -1;
    s->parser = p;
    s->out_slot = -1;
    if (!(s->pkt = av_packet_alloc()))
    {
        free( s );
        return NULL;
    }
    snprintf( s->info.container, sizeof(s->info.container), "%s", p->is_mov ? "mp4" : p->fmt->iformat->name );   /* asf: "asf" */
    if (p->fmt->duration != AV_NOPTS_VALUE && p->fmt->duration > 0 && !p->is_mov)
        s->info.duration = (uint64_t)p->fmt->duration * 10;   /* AV_TIME_BASE is 1 us */
    else if (st->duration != AV_NOPTS_VALUE && st->duration > 0)
        s->info.duration = av_rescale_q( st->duration, st->time_base, (AVRational){ 1, 10000000 } );
    else if (p->fmt->duration != AV_NOPTS_VALUE && p->fmt->duration > 0)
        s->info.duration = (uint64_t)p->fmt->duration * 10;
    return s;
}

/* Returns MAV_OK, or MAV_E_UNSUPPORTED with *why set, or MAV_E_NOMEM. */
static int mav_open_audio( struct mav_parser *p, struct mav_stream *s, AVStream *st, char *why, size_t why_size )
{
    const AVCodecParameters *par = st->codecpar;
    const AVCodec *codec;

    if (!mav_classify_audio( par->codec_id, &s->info.kind, &s->info.layer, &s->info.native.fmt ))
    {
        snprintf( why, why_size, "no decoder for it in this port" );
        return MAV_E_UNSUPPORTED;
    }
    /* An ASF's streams are all exposed either way (the WM reader asks for
     * the same streams again with compressed output); see mav_passes_compressed. */
    if (p->output_compressed && !p->is_asf && !p->is_mpeg && s->info.kind != MAV_CODEC_PCM)
    {
        snprintf( why, why_size, "compressed output requested and no decoder filter exists; "
                  "the decoding splitter is tried next" );
        return MAV_E_UNSUPPORTED;
    }
    s->info.bitrate = par->bit_rate > 0 && par->bit_rate < UINT32_MAX ? (uint32_t)par->bit_rate : 0;
    snprintf( s->info.codec, sizeof(s->info.codec), "%s", avcodec_get_name( par->codec_id ) );

    if (s->info.kind == MAV_CODEC_AAC)
    {
        uint32_t rate = par->sample_rate, channels = par->ch_layout.nb_channels;

        if (!mav_video_allowed || !mav_abackend || !mav_abackend->supports( MAV_BACKEND_AAC ))
        {
            snprintf( why, why_size, "no AAC decoder backend" );
            return MAV_E_UNSUPPORTED;
        }
        if (!(s->adec = mav_abackend->open( MAV_BACKEND_AAC, par->extradata,
                                            par->extradata && par->extradata_size > 0 ? (uint32_t)par->extradata_size : 0,
                                            &rate, &channels, why, why_size )))
            return MAV_E_UNSUPPORTED;
        if (!rate || rate > 384000 || !channels || channels > MAV_MAX_CHANNELS)
        {
            snprintf( why, why_size, "the decoder reports rate %u channels %u", rate, channels );
            return MAV_E_UNSUPPORTED;
        }
        if (!(s->bframe = av_frame_alloc())) return MAV_E_NOMEM;
        s->bframe->format = AV_SAMPLE_FMT_FLT;
        s->bframe->sample_rate = rate;
        s->bframe->nb_samples = MAV_AUDIO_BACKEND_MAX_FRAMES;
        av_channel_layout_default( &s->bframe->ch_layout, channels );
        if (av_frame_get_buffer( s->bframe, 0 ) < 0) return MAV_E_NOMEM;
        snprintf( s->info.backend, sizeof(s->info.backend), "%s", mav_abackend->name );
        s->info.native.rate = rate;
        s->info.native.channels = channels;
        s->info.native.channel_mask = mav_layout_mask( &s->bframe->ch_layout );
        if (par->extradata && par->extradata_size > 0 && (size_t)par->extradata_size <= sizeof(s->info.codec_data))
        {
            memcpy( s->info.codec_data, par->extradata, par->extradata_size );
            s->info.codec_data_len = par->extradata_size;
        }
    }
    else
    {
        if (!(codec = avcodec_find_decoder( par->codec_id )))
        {
            snprintf( why, why_size, "no decoder in this build" );
            return MAV_E_UNSUPPORTED;
        }
        if (!(s->dec = avcodec_alloc_context3( codec ))) return MAV_E_NOMEM;
        s->dec->opaque = MAV_DECODER_MARKER;
        if (avcodec_parameters_to_context( s->dec, par ) < 0)
        {
            snprintf( why, why_size, "codec parameters rejected" );
            return MAV_E_UNSUPPORTED;
        }
        s->dec->pkt_timebase = st->time_base;
        if (avcodec_open2( s->dec, codec, NULL ) < 0)
        {
            snprintf( why, why_size, "decoder did not open" );
            return MAV_E_UNSUPPORTED;
        }
        if (s->dec->sample_rate <= 0 || s->dec->ch_layout.nb_channels <= 0
            || s->dec->ch_layout.nb_channels > MAV_MAX_CHANNELS)
        {
            snprintf( why, why_size, "no usable rate / channel count" );
            return MAV_E_UNSUPPORTED;
        }
        snprintf( s->info.codec, sizeof(s->info.codec), "%s", codec->name );
        snprintf( s->info.backend, sizeof(s->info.backend), "libavcodec" );
        if (s->info.kind == MAV_CODEC_WMA)
        {
            /* what wg_format describes a WMA stream by (the codec format) */
            s->info.version = par->codec_id == AV_CODEC_ID_WMAV1 ? 1 : par->codec_id == AV_CODEC_ID_WMAV2 ? 2
                              : par->codec_id == AV_CODEC_ID_WMAPRO ? 3 : 4;
            s->info.block_align = par->block_align > 0 ? (uint32_t)par->block_align : 0;
            s->info.depth = par->bits_per_coded_sample > 0 ? (uint32_t)par->bits_per_coded_sample : 16;
            if (par->extradata && par->extradata_size > 0 && (size_t)par->extradata_size <= sizeof(s->info.codec_data))
            {
                memcpy( s->info.codec_data, par->extradata, par->extradata_size );
                s->info.codec_data_len = par->extradata_size;
            }
        }
        s->info.native.rate = s->dec->sample_rate;
        s->info.native.channels = s->dec->ch_layout.nb_channels;
        s->info.native.channel_mask = mav_layout_mask( &s->dec->ch_layout );
    }
    if (!(s->frame = av_frame_alloc())) return MAV_E_NOMEM;
    s->out = s->info.native;
    return MAV_OK;
}

static int mav_open_video( struct mav_parser *p, struct mav_stream *s, AVStream *st, char *why, size_t why_size )
{
    const AVCodecParameters *par = st->codecpar;
    AVRational fps = st->avg_frame_rate;
    int codec;

    /* H.264 / HEVC from an MP4 go to the platform decoder (avcC / hvcC codec
     * data); Windows Media video from an ASF to libavcodec. */
    s->vbackend = mav_vbackend;
    switch (par->codec_id)
    {
    case AV_CODEC_ID_H264: codec = MAV_BACKEND_H264; s->info.kind = MAV_CODEC_H264; break;
    case AV_CODEC_ID_HEVC: codec = MAV_BACKEND_HEVC; s->info.kind = MAV_CODEC_HEVC; break;
    case AV_CODEC_ID_WMV1: codec = MAV_LAVC_WMV1; s->info.wmv = MAV_WMV_WMV1; break;
    case AV_CODEC_ID_WMV2: codec = MAV_LAVC_WMV2; s->info.wmv = MAV_WMV_WMV2; break;
    case AV_CODEC_ID_WMV3: codec = MAV_LAVC_WMV3; s->info.wmv = MAV_WMV_WMV3; break;
    case AV_CODEC_ID_VC1:
        codec = MAV_LAVC_VC1;
        s->info.wmv = par->codec_tag == MKTAG('W','M','V','A') ? MAV_WMV_WMVA : MAV_WMV_WVC1;
        break;
    case AV_CODEC_ID_MSMPEG4V1: codec = MAV_LAVC_MSMPEG4V1; break;
    case AV_CODEC_ID_MSMPEG4V2: codec = MAV_LAVC_MSMPEG4V2; break;
    case AV_CODEC_ID_MSMPEG4V3: codec = MAV_LAVC_MSMPEG4V3; break;
    case AV_CODEC_ID_MPEG1VIDEO: codec = MAV_LAVC_MPEG1; s->info.version = 1; break;
    case AV_CODEC_ID_MPEG2VIDEO: codec = MAV_LAVC_MPEG2; s->info.version = 2; break;
    case AV_CODEC_ID_MPEG4:      if (!p->is_avi) goto unsupported; codec = MAV_LAVC_MPEG4; break;
    case AV_CODEC_ID_MJPEG:      if (!p->is_avi) goto unsupported; codec = MAV_LAVC_MJPEG; break;
    case AV_CODEC_ID_CINEPAK:    if (!p->is_avi) goto unsupported; codec = MAV_LAVC_CINEPAK; break;
    case AV_CODEC_ID_MSVIDEO1:   if (!p->is_avi) goto unsupported; codec = MAV_LAVC_MSVIDEO1; break;
    case AV_CODEC_ID_MSRLE:      if (!p->is_avi) goto unsupported; codec = MAV_LAVC_MSRLE; break;
    case AV_CODEC_ID_INDEO3:     if (!p->is_avi) goto unsupported; codec = MAV_LAVC_INDEO3; break;
    case AV_CODEC_ID_INDEO4:     if (!p->is_avi) goto unsupported; codec = MAV_LAVC_INDEO4; break;
    case AV_CODEC_ID_INDEO5:     if (!p->is_avi) goto unsupported; codec = MAV_LAVC_INDEO5; break;
    case AV_CODEC_ID_RAWVIDEO:   if (!p->is_avi) goto unsupported; codec = MAV_LAVC_RAWVIDEO; break;
    default:
    unsupported:
        snprintf( why, why_size, "no decoder for it in this port" );
        return MAV_E_UNSUPPORTED;
    }
    if (codec >= MAV_LAVC_WMV1)
    {
        s->info.kind = codec >= MAV_LAVC_MPEG4 ? MAV_CODEC_AVI_VIDEO
                     : codec >= MAV_LAVC_MPEG1 ? MAV_CODEC_MPEG_VIDEO : MAV_CODEC_WMV;
        s->vbackend = &mav_lavc_video;
    }
    snprintf( s->info.codec, sizeof(s->info.codec), "%s", avcodec_get_name( par->codec_id ) );
    if (!(p->is_mov ? (s->info.kind == MAV_CODEC_H264 || s->info.kind == MAV_CODEC_HEVC)
        : p->is_asf ? (s->info.kind == MAV_CODEC_WMV)
        : (p->is_mpeg || p->is_mpegvideo) ? (s->info.kind == MAV_CODEC_MPEG_VIDEO)
        : p->is_avi ? (s->vbackend == &mav_lavc_video) : 0))
    {
        snprintf( why, why_size, "not in this container here (H.264 / HEVC in MP4, Windows Media video in ASF, "
                  "MPEG-1/2 video in MPEG, software-decoded video in AVI)" );
        return MAV_E_UNSUPPORTED;
    }
    if (p->is_mpegvideo && s->info.version != 1)
    {
        snprintf( why, why_size, "only MPEG-1 video is supported as a raw elementary stream" );
        return MAV_E_UNSUPPORTED;
    }
    if (!s->vbackend || !s->vbackend->supports( codec ))
    {
        snprintf( why, why_size, "no video decoder backend for it" );
        return MAV_E_UNSUPPORTED;
    }
    if (par->width <= 0 || par->height <= 0 || par->width > MAV_MAX_DIMENSION || par->height > MAV_MAX_DIMENSION)
    {
        snprintf( why, why_size, "unusable picture size %dx%d", par->width, par->height );
        return MAV_E_UNSUPPORTED;
    }
    s->decode_order = p->is_avi && s->vbackend == &mav_lavc_video;
    s->vdec = s->decode_order
              ? mav_lavc_open_stream( codec, st, why, why_size )
              : s->vbackend->open( codec, par->extradata,
                                   par->extradata && par->extradata_size > 0 ? (uint32_t)par->extradata_size : 0,
                                   par->width, par->height, why, why_size );
    if (!s->vdec) return MAV_E_UNSUPPORTED;
    snprintf( s->info.backend, sizeof(s->info.backend), "%s", s->vbackend->name );

    if (p->is_mpegvideo)
    {
        fps = (AVRational){ 0, 1 };
        if (par->extradata_size <= 0 || !mav_mpeg1_seq_fps( par->extradata, (size_t)par->extradata_size, &fps ))
        {
            uint8_t probe_hdr[4096];
            int n = mav_raw_read_full( p, 0, probe_hdr, sizeof(probe_hdr) );
            if (n > 0) mav_mpeg1_seq_fps( probe_hdr, (size_t)n, &fps );
        }
        if (fps.num <= 0 || fps.den <= 0) fps = par->framerate;
        if (fps.num <= 0 || fps.den <= 0) fps = st->r_frame_rate;
    }
    else if (fps.num <= 0 || fps.den <= 0)
        fps = st->r_frame_rate;
    if (fps.num <= 0 || fps.den <= 0 || av_q2d( fps ) > 1000)
    {
        mav_log( "stream %u: no frame rate in the container; assuming 30/1", s->number );
        fps = (AVRational){ 30, 1 };
    }
    if (p->is_mpegvideo)
    {
        s->time_base = (AVRational){ fps.den, fps.num };
        s->origin = 0;
        if (p->file_size > 0 && p->file_size <= (16u << 20))
        {
            int64_t pics = mav_count_m1v_pictures( p );
            if (pics > 0)
                s->info.duration = av_rescale_q( pics, s->time_base, (AVRational){ 1, 10000000 } );
        }
    }
    s->info.vnative.fmt = mav_native_pix;
    s->info.vnative.width = par->width;
    s->info.vnative.height = par->height;
    s->info.vnative.fps_n = fps.num;
    s->info.vnative.fps_d = fps.den;
    s->frame_duration = av_rescale( 10000000, fps.den, fps.num );
    s->info.bitrate = par->bit_rate > 0 && par->bit_rate < UINT32_MAX ? (uint32_t)par->bit_rate : 0;
    s->info.profile = par->profile > 0 ? par->profile : 0;
    s->info.level = par->level > 0 ? par->level : 0;
    if (par->extradata && par->extradata_size > 0 && (size_t)par->extradata_size <= sizeof(s->info.codec_data))
    {
        memcpy( s->info.codec_data, par->extradata, par->extradata_size );
        s->info.codec_data_len = par->extradata_size;
    }
    switch (par->color_space)
    {
    case AVCOL_SPC_BT709: s->bt709 = 1; break;
    case AVCOL_SPC_BT470BG:
    case AVCOL_SPC_SMPTE170M:
    case AVCOL_SPC_FCC: s->bt709 = 0; break;
    default: s->bt709 = par->height >= 720; break;   /* the usual assumption for untagged video */
    }
    s->vout = s->info.vnative;
    return MAV_OK;
}

static int mav_connect_locked( struct mav_parser *p )
{
    AVStream *vst = NULL, *ast = NULL;
    const char *name;
    uint8_t *avio_buf;
    char why[160];
    unsigned int i;
    int err, status, is_mp3;

    if ((err = mav_detect_cdxa( p )) < 0)
    {
        if (err == AVERROR(ENOMEM)) return MAV_E_NOMEM;
        if (err == AVERROR_PATCHWELCOME)
            return mav_refuse( p, MAV_E_UNSUPPORTED, !mav_video_allowed ? "container disabled by MADEIRA_WG_VIDEO=0"
                                                                        : "RIFF/CDXA disabled by MADEIRA_WG_MPEG_RAW=0" );
        return mav_refuse( p, MAV_E_IO, "read error during probe" );
    }

    if (!(avio_buf = av_malloc( (size_t)MAV_AVIO_BUFFER ))) return MAV_E_NOMEM;
    if (!(p->avio = avio_alloc_context( avio_buf, MAV_AVIO_BUFFER, 0, p, mav_avio_read, NULL, mav_avio_seek )))
    {
        av_free( avio_buf );
        return MAV_E_NOMEM;
    }
    if (!(p->fmt = avformat_alloc_context())) return MAV_E_NOMEM;
    p->fmt->pb = p->avio;
    p->fmt->flags |= AVFMT_FLAG_CUSTOM_IO;
    p->fmt->probesize = MAV_PROBESIZE;

    if ((err = avformat_open_input( &p->fmt, NULL, NULL, NULL )) < 0)
    {
        /* avformat_open_input freed the context (not our AVIO) */
        p->fmt = NULL;
        return mav_refuse( p, err == AVERROR_EXIT || err == AVERROR(EIO) ? MAV_E_IO : MAV_E_UNSUPPORTED,
                           "no enabled demuxer recognised the stream" );
    }
    name = p->fmt->iformat->name;
    is_mp3 = !strcmp( name, "mp3" );
    p->is_mov = !strcmp( name, MAV_MOV_NAME );
    p->is_asf = !strcmp( name, "asf" );
    p->is_mpeg = !strcmp( name, "mpeg" );
    /* Raw MPEG-1 video (.m1v / .mpv, FFmpeg's mpegvideo demuxer, which mpegps
     * also probes a program stream's video with): given display-order times
     * from its sequence header and temporal_reference when MADEIRA_WG_MPEG_RAW
     * is on. */
    p->is_mpegvideo = !strcmp( name, "mpegvideo" );
    if (p->is_mpegvideo && !mav_mpeg_raw)
        return mav_refuse( p, MAV_E_UNSUPPORTED, "container disabled by MADEIRA_WG_MPEG_RAW=0" );
    p->is_avi = !strcmp( name, "avi" );
    if (!is_mp3 && strcmp( name, "wav" ) != 0 && !(mav_video_container( p ) && mav_video_allowed))
        return mav_refuse( p, MAV_E_UNSUPPORTED, mav_video_container( p ) ? "container disabled by MADEIRA_WG_VIDEO=0"
                                                                          : "container not in the allowlist" );
    if (p->is_avi && !mav_avi_allowed)
        return mav_refuse( p, MAV_E_UNSUPPORTED, "container disabled by MADEIRA_WG_AVI=0" );
    /* An ASF header object scores like a recognised MP4 (its GUID matches);
     * an MPEG program or elementary stream has its own floor. */
    {
        int floor = (p->is_mpeg || p->is_mpegvideo) ? MAV_MIN_MPEG_PROBE_SCORE
                  : mav_video_container( p ) ? MAV_MIN_MOV_PROBE_SCORE : MAV_MIN_PROBE_SCORE;
        if (p->fmt->probe_score < floor)
        {
            snprintf( why, sizeof(why), "probe score %d below %d", p->fmt->probe_score, floor );
            return mav_refuse( p, MAV_E_UNSUPPORTED, why );
        }
    }
    /* The mp3 demuxer only ever carries MPEG audio and an MP4 only
     * compressed streams: a compressed-output parser is refused before the
     * stream analysis reads anything more.  An ASF is the WM reader's, which
     * asks for compressed samples of its Windows Media streams, and an MPEG
     * program or raw MPEG-1 video stream quartz's MPEG-1 splitter's.  An AVI's
     * codecs have no wg_format here: quartz's AVI splitter gives way, and the
     * decoding splitter takes it. */
    if (p->output_compressed && (is_mp3 || p->is_mov || p->is_avi
                                 || ((p->is_asf || p->is_mpeg || p->is_mpegvideo) && !mav_compressed_asf)))
        return mav_refuse( p, MAV_E_UNSUPPORTED,
                           "compressed output requested and no decoder filter exists; "
                           "the decoding splitter is tried next" );

    /* Only the stream types this port can expose are analysed; a cover-art
     * picture is not decodable here and would only keep the analysis reading. */
    for (i = 0; i < p->fmt->nb_streams; i++)
    {
        enum AVMediaType type = p->fmt->streams[i]->codecpar->codec_type;
        if (type != AVMEDIA_TYPE_AUDIO && !(mav_video_container( p ) && type == AVMEDIA_TYPE_VIDEO))
            p->fmt->streams[i]->discard = AVDISCARD_ALL;
    }

    if ((err = avformat_find_stream_info( p->fmt, NULL )) < 0)
        return mav_refuse( p, err == AVERROR_EXIT || err == AVERROR(EIO) ? MAV_E_IO : MAV_E_UNSUPPORTED,
                           "stream analysis failed" );

    for (i = 0; i < p->fmt->nb_streams; i++)
    {
        AVStream *s = p->fmt->streams[i];

        if (s->disposition & AV_DISPOSITION_ATTACHED_PIC) continue;
        if (s->codecpar->codec_type == AVMEDIA_TYPE_VIDEO)
        {
            if (!mav_video_container( p )) return mav_refuse( p, MAV_E_UNSUPPORTED, "the file has a video stream" );
            if (!vst) vst = s;
        }
        if (s->codecpar->codec_type == AVMEDIA_TYPE_AUDIO && !ast) ast = s;
    }
    if (!vst && !ast) return mav_refuse( p, MAV_E_UNSUPPORTED, mav_video_container( p ) ? "no audio or video stream"
                                                                                     : "no audio stream" );

    if (!(p->read_pkt = av_packet_alloc())) return MAV_E_NOMEM;

    /* Container order, so stream numbers follow the file's track order. */
    for (i = 0; i < p->fmt->nb_streams; i++)
    {
        AVStream *st = p->fmt->streams[i];
        struct mav_stream *s;

        if (st != vst && st != ast) continue;
        if (!(s = mav_stream_new( p, st, st == vst ? MAV_STREAM_VIDEO : MAV_STREAM_AUDIO ))) return MAV_E_NOMEM;
        s->number = p->stream_count;
        why[0] = 0;
        status = st == vst ? mav_open_video( p, s, st, why, sizeof(why) )
                           : mav_open_audio( p, s, st, why, sizeof(why) );
        if (status == MAV_E_NOMEM)
        {
            mav_stream_free( s );
            return status;
        }
        if (status)
        {
            /* An MP4's, ASF's or MPEG program stream's audio is optional; its video, or the only stream, is not. */
            if (st == ast && vst)
            {
                char text[320];
                snprintf( text, sizeof(text), "audio codec %s (codec id %d, tag %#x) not exposed: %s",
                          avcodec_get_name( st->codecpar->codec_id ), (int)st->codecpar->codec_id,
                          st->codecpar->codec_tag, why );
                mav_log( "%s", text );
                mav_stream_free( s );
                continue;
            }
            status = mav_refuse_codec( p, st == vst ? "video" : "audio", st->codecpar, why );
            mav_stream_free( s );
            return status;
        }
        p->streams[p->stream_count++] = s;
    }
    if (!p->stream_count) return mav_refuse( p, MAV_E_UNSUPPORTED, "no decodable stream" );

    for (i = 0; i < p->fmt->nb_streams; i++)
    {
        unsigned int j;
        p->fmt->streams[i]->discard = AVDISCARD_ALL;
        for (j = 0; j < p->stream_count; j++)
            if (p->streams[j]->av_index == (int)i) p->fmt->streams[i]->discard = AVDISCARD_DEFAULT;
    }

    for (i = 0; i < p->stream_count; i++)
    {
        struct mav_stream *s = p->streams[i];

        s->enabled = 1;
        s->compressed = mav_passes_compressed( p, s );
        s->discontinuity = 1;
        s->next_pts = 0;
        /* MP4 audio carries its encoder delay as packets before time 0
         * (the edit list); they are decoded and trimmed like a seek to 0. */
        s->seek_target = p->is_mov ? 0 : -1;
        if (s->type == MAV_STREAM_VIDEO)
            mav_log( "connect container=%s stream=%u video codec=%s backend=%s %dx%d fps=%u/%u out=%s "
                     "duration=%llums bitrate=%u profile=%u level=%u",
                     s->info.container, i, s->info.codec, s->info.backend, s->info.vnative.width,
                     s->info.vnative.height, s->info.vnative.fps_n, s->info.vnative.fps_d,
                     s->compressed ? "compressed" : mav_pix_name( s->vout.fmt ), (unsigned long long)(s->info.duration / 10000),
                     s->info.bitrate, s->info.profile, s->info.level );
        else
            mav_log( "connect container=%s codec=%s layer=%u rate=%u channels=%u mask=%#x out=%s "
                     "duration=%llums bitrate=%u compressed_out=%d stream=%u backend=%s",
                     s->info.container, s->info.codec, s->info.layer, s->info.native.rate,
                     s->info.native.channels, s->info.native.channel_mask,
                     s->compressed ? "compressed" : mav_format_name( s->out.fmt ),
                     (unsigned long long)(s->info.duration / 10000),
                     s->info.bitrate, p->output_compressed, i, s->info.backend );
    }
    p->stop = -1;
    p->demux_eof = 0;
    p->ready = 1;
    return MAV_OK;
}

static int mav_connect( struct mav_parser *p, uint64_t file_size )
{
    int status;

    pthread_mutex_lock( &p->lock );
    if (p->fmt || p->avio)
    {
        pthread_mutex_unlock( &p->lock );
        return MAV_E_STATE;
    }
    p->file_size = file_size;
    p->pos = 0;
    mav_set_connected( p, 1 );
    if ((status = mav_connect_locked( p )))
    {
        mav_teardown( p );
        /* like wg_parser.c: a failed connect ends the read protocol */
        mav_set_connected( p, 0 );
    }
    pthread_mutex_unlock( &p->lock );
    return status;
}

/***********************************************************************
 *           stream queries and format
 */
static struct mav_stream *mav_get_stream( struct mav_parser *p, unsigned int stream )
{
    return p->ready && stream < p->stream_count ? p->streams[stream] : NULL;
}

static unsigned int mav_stream_count( struct mav_parser *p )
{
    unsigned int count;

    pthread_mutex_lock( &p->lock );
    count = p->ready ? p->stream_count : 0;
    pthread_mutex_unlock( &p->lock );
    return count;
}

static int mav_stream_info( struct mav_parser *p, unsigned int stream, struct mav_stream_info *info )
{
    struct mav_stream *s;
    int status = MAV_E_STATE;

    pthread_mutex_lock( &p->lock );
    if ((s = mav_get_stream( p, stream )))
    {
        *info = s->info;
        status = MAV_OK;
    }
    pthread_mutex_unlock( &p->lock );
    return status;
}

static int mav_current_output( struct mav_parser *p, unsigned int stream, struct mav_output *out )
{
    struct mav_stream *s;
    int status = MAV_E_STATE;

    pthread_mutex_lock( &p->lock );
    if ((s = mav_get_stream( p, stream )) && s->type == MAV_STREAM_AUDIO)
    {
        *out = s->out;
        status = MAV_OK;
    }
    pthread_mutex_unlock( &p->lock );
    return status;
}

static int mav_current_video( struct mav_parser *p, unsigned int stream, struct mav_video_output *out )
{
    struct mav_stream *s;
    int status = MAV_E_STATE;

    pthread_mutex_lock( &p->lock );
    if ((s = mav_get_stream( p, stream )) && s->type == MAV_STREAM_VIDEO)
    {
        *out = s->vout;
        status = MAV_OK;
    }
    pthread_mutex_unlock( &p->lock );
    return status;
}

static int mav_enable( struct mav_parser *p, unsigned int stream, const struct mav_output *out )
{
    struct mav_stream *s;
    int status = MAV_OK;

    pthread_mutex_lock( &p->lock );
    if (!(s = mav_get_stream( p, stream )) || s->type != MAV_STREAM_AUDIO)
        status = MAV_E_STATE;
    else if (mav_av_format( out->fmt ) == AV_SAMPLE_FMT_NONE || !out->rate || out->rate > 768000
             || !out->channels || out->channels > MAV_MAX_CHANNELS)
    {
        /* Refused, and the stream stays disabled: its buffers would be in a
         * format nobody asked for. */
        s->enabled = 0;
        s->has_buffer = 0;
        s->cur_counted = 0;
        status = MAV_E_PARAM;
    }
    else
    {
        if (memcmp( out, &s->out, sizeof(*out) ) != 0 || s->compressed)
        {
            /* the held buffer is in the old format */
            s->has_buffer = 0;
            s->cur_counted = 0;
            swr_free( &s->swr );
            s->out = *out;
        }
        s->compressed = 0;
        s->enabled = 1;
    }
    pthread_mutex_unlock( &p->lock );
    return status;
}

static int mav_enable_video( struct mav_parser *p, unsigned int stream, const struct mav_video_output *out )
{
    struct mav_layout layout;
    struct mav_stream *s;
    int status = MAV_OK;

    pthread_mutex_lock( &p->lock );
    if (!(s = mav_get_stream( p, stream )) || s->type != MAV_STREAM_VIDEO)
        status = MAV_E_STATE;
    else if (!mav_video_layout( out->fmt, s->info.vnative.width, s->info.vnative.height, &layout )
             || out->width != s->info.vnative.width
             || (out->height != s->info.vnative.height && out->height != -s->info.vnative.height))
    {
        /* No scaler here: only the native size, in one of the layouts
         * mav_video_layout knows.  The stream stays disabled. */
        s->enabled = 0;
        s->has_buffer = 0;
        mav_ahead_reset( s );
        status = MAV_E_PARAM;
    }
    else
    {
        mav_ahead_quiesce( p );
        if (out->fmt != s->vout.fmt || out->height != s->vout.height || s->compressed)
        {
            s->has_buffer = 0;
            mav_ahead_reset( s );
        }
        s->vout = *out;
        s->compressed = 0;
        s->enabled = 1;
        mav_ahead_resume( p );
    }
    pthread_mutex_unlock( &p->lock );
    return status;
}

static int mav_can_pass_compressed( struct mav_parser *p, unsigned int stream )
{
    struct mav_stream *s;
    int ret;

    pthread_mutex_lock( &p->lock );
    ret = (s = mav_get_stream( p, stream )) && mav_passes_compressed( p, s );
    pthread_mutex_unlock( &p->lock );
    return ret;
}

static int mav_enable_compressed( struct mav_parser *p, unsigned int stream )
{
    struct mav_stream *s;
    int status = MAV_OK;

    pthread_mutex_lock( &p->lock );
    if (!(s = mav_get_stream( p, stream )))
        status = MAV_E_STATE;
    else if (!mav_passes_compressed( p, s ))
    {
        /* as a refused decoded format: the stream stays disabled */
        s->enabled = 0;
        s->has_buffer = 0;
        mav_ahead_reset( s );
        status = MAV_E_PARAM;
    }
    else
    {
        if (!s->compressed)
        {
            /* the held buffer, and what the decoder holds, were decoded output */
            mav_ahead_quiesce( p );
            s->has_buffer = 0;
            mav_ahead_reset( s );
            if (s->pkt_pending) av_packet_unref( s->pkt );
            s->pkt_pending = 0;
            s->priming_decode_ns = 0;
            s->cur_audio_ns = 0;
            mav_reorder_clear( s );
            mav_ahead_resume( p );
        }
        s->compressed = 1;
        s->enabled = 1;
    }
    pthread_mutex_unlock( &p->lock );
    return status;
}

static void mav_disable( struct mav_parser *p, unsigned int stream )
{
    struct mav_stream *s;

    pthread_mutex_lock( &p->lock );
    if ((s = mav_get_stream( p, stream )))
    {
        s->enabled = 0;
        s->has_buffer = 0;
        mav_ahead_reset( s );
        /* its queued packets will not be read */
        mav_queue_clear( s );
        if (p->bp_waiters) pthread_cond_broadcast( &p->drain_cond );
        pthread_cond_broadcast( &p->ahead_cond );
    }
    pthread_mutex_unlock( &p->lock );
}

/***********************************************************************
 *           packets
 */
static void mav_queue_push( struct mav_stream *s, AVPacket *pkt )
{
    if (s->queue_count >= MAV_QUEUE_MAX_PACKETS || s->queue_bytes + pkt->size > MAV_QUEUE_MAX_BYTES)
    {
        s->stat_bp_drops++;
        mav_log( "stream %u: %u packets (%zu bytes) queued and not read; dropping further packets",
                 s->number, s->queue_count, s->queue_bytes );
        s->discontinuity = 1;
        av_packet_free( &pkt );
        return;
    }
    if (s->queue_head + s->queue_count == s->queue_cap)
    {
        if (s->queue_head)
        {
            memmove( s->queue, s->queue + s->queue_head, s->queue_count * sizeof(*s->queue) );
            s->queue_head = 0;
        }
        if (s->queue_count == s->queue_cap)
        {
            unsigned int cap = s->queue_cap ? s->queue_cap * 2 : 64;
            AVPacket **grown = realloc( s->queue, cap * sizeof(*grown) );
            if (!grown)
            {
                av_packet_free( &pkt );
                s->discontinuity = 1;
                return;
            }
            s->queue = grown;
            s->queue_cap = cap;
        }
    }
    s->queue[s->queue_head + s->queue_count++] = pkt;
    s->queue_bytes += pkt->size;
}

static int mav_queue_over( const struct mav_stream *s, unsigned int num, unsigned int den )
{
    return s->queue_count > MAV_QUEUE_SOFT_PACKETS / den * num || s->queue_bytes > MAV_QUEUE_SOFT_BYTES / den * num;
}

/* Back-pressure, row 9 of the audit.  `waiter` just queued a packet for
 * `owner`, whose queue is past its soft limit while another thread reads it.
 * Dropping would break the owner's pictures (or audio) up to its next
 * keyframe, so the waiter sleeps -- WITHOUT the parser lock, which the owner's
 * reader needs to drain its queue -- until that queue is back under three
 * quarters of the limit.  The waiter holds no packet and no demuxer state
 * while it sleeps; it re-checks its own queue when it wakes.  It also wakes on
 * a seek (generation), a disable or end of the owner's stream, and disconnect
 * (closing).  An owner not read for MAV_BACKPRESSURE_WAIT_MS is marked unread:
 * its packets are queued again without waiting (and dropped past the hard
 * limit, as before) until it is read. */
static void mav_wait_drain( struct mav_parser *p, struct mav_stream *waiter, struct mav_stream *owner )
{
    unsigned int generation = p->generation;
    struct timespec deadline;

    clock_gettime( CLOCK_REALTIME, &deadline );
    deadline.tv_sec += MAV_BACKPRESSURE_WAIT_MS / 1000;
    deadline.tv_nsec += (long)(MAV_BACKPRESSURE_WAIT_MS % 1000) * 1000000;
    if (deadline.tv_nsec >= 1000000000) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000; }
    p->bp_waiters++;
    while (!p->closing && p->generation == generation && owner->enabled && !owner->eos && !owner->unread
           && mav_queue_over( owner, 3, 4 ))
    {
        if (pthread_cond_timedwait( &p->drain_cond, &p->lock, &deadline ) == ETIMEDOUT)
        {
            if (!p->closing && p->generation == generation && owner->enabled && !owner->eos
                && mav_queue_over( owner, 3, 4 ))
            {
                owner->unread = 1;
                mav_log( "stream %u: not read for %d ms while stream %u reads ahead (%u packets, %zu bytes "
                         "queued); queueing without waiting", owner->number, MAV_BACKPRESSURE_WAIT_MS,
                         waiter->number, owner->queue_count, owner->queue_bytes );
            }
            break;
        }
    }
    p->bp_waiters--;
    if (p->closing) pthread_cond_broadcast( &p->drain_cond );   /* mav_disconnect waits for bp_waiters == 0 */
}

/* Moves the next packet of stream `s` into `dst`, reading (and queueing for
 * the other streams) as needed.  Returns 0 at the end of the data. */
static int mav_next_packet( struct mav_parser *p, struct mav_stream *s, AVPacket *dst )
{
    unsigned int i;
    int err;

    for (;;)
    {
        struct mav_stream *owner = NULL;
        AVPacket *copy;

        if (s->queue_count)
        {
            AVPacket *q = s->queue[s->queue_head++];
            s->queue_count--;
            s->queue_bytes -= q->size;
            if (!s->queue_count) s->queue_head = 0;
            s->unread = 0;
            av_packet_move_ref( dst, q );
            av_packet_free( &q );
            if (p->bp_waiters) pthread_cond_broadcast( &p->drain_cond );
            return 1;
        }
        if (p->demux_eof || p->closing) return 0;
        if ((err = av_read_frame( p->fmt, p->read_pkt )) < 0)
        {
            if (err != AVERROR_EOF && err != AVERROR_EXIT && p->read_errors_logged < 3)
            {
                p->read_errors_logged++;
                mav_log( "read error %d at byte %llu; draining", err, (unsigned long long)p->pos );
            }
            p->demux_eof = 1;
            return 0;
        }
        for (i = 0; i < p->stream_count; i++)
            if (p->streams[i]->av_index == p->read_pkt->stream_index) owner = p->streams[i];
        if (p->is_mpegvideo && owner && owner->type == MAV_STREAM_VIDEO)
            mav_stamp_m1v_packet( owner, p->read_pkt );
        if (owner == s)
        {
            s->unread = 0;
            av_packet_move_ref( dst, p->read_pkt );
            return 1;
        }
        if (!owner || !owner->enabled || owner->eos)
        {
            av_packet_unref( p->read_pkt );
            continue;
        }
        if (!(copy = av_packet_alloc()))
        {
            av_packet_unref( p->read_pkt );
            owner->discontinuity = 1;
            continue;
        }
        av_packet_move_ref( copy, p->read_pkt );
        mav_queue_push( owner, copy );
        /* Only for an owner another thread reads: one thread serving both
         * streams (the earliest-buffer mode, or a caller that alternates)
         * would wait for itself.  A decode-ahead worker reads for its
         * stream's reader, so an owner that thread reads counts as its own:
         * that thread may be waiting for the worker's picture. */
        if (mav_queue_over( owner, 1, 1 ) && !owner->unread
            && !(owner->has_reader && (pthread_equal( owner->reader, pthread_self() )
                                       || (s->has_reader && pthread_equal( owner->reader, s->reader )))))
            mav_wait_drain( p, s, owner );
    }
}

/***********************************************************************
 *           audio
 */
static int mav_reserve( struct mav_stream *s, size_t need )
{
    size_t want;
    uint8_t *grown;

    if (s->buf_cap >= need) return 1;
    want = s->buf_cap ? s->buf_cap : 16384;
    while (want < need) want *= 2;
    if (!(grown = realloc( s->buf, want ))) return 0;
    s->buf = grown;
    s->buf_cap = want;
    return 1;
}

static int mav_setup_swr( struct mav_stream *s, const AVFrame *frame )
{
    AVChannelLayout out_layout;
    int err;

    if (s->swr && s->swr_in_fmt == frame->format && s->swr_in_rate == frame->sample_rate
        && !av_channel_layout_compare( &s->swr_in_layout, &frame->ch_layout ))
        return 0;

    swr_free( &s->swr );
    av_channel_layout_uninit( &s->swr_in_layout );
    if (!s->out.channel_mask || av_popcount( s->out.channel_mask ) != (int)s->out.channels
        || av_channel_layout_from_mask( &out_layout, s->out.channel_mask ) < 0)
        av_channel_layout_default( &out_layout, s->out.channels );
    err = swr_alloc_set_opts2( &s->swr, &out_layout, mav_av_format( s->out.fmt ), s->out.rate,
                               &frame->ch_layout, frame->format, frame->sample_rate, 0, NULL );
    av_channel_layout_uninit( &out_layout );
    if (err < 0 || (err = swr_init( s->swr )) < 0)
    {
        swr_free( &s->swr );
        return err < 0 ? err : AVERROR(EINVAL);
    }
    s->swr_in_fmt = frame->format;
    s->swr_in_rate = frame->sample_rate;
    av_channel_layout_copy( &s->swr_in_layout, &frame->ch_layout );
    return 0;
}

/* Converts `frame` (or, with NULL, the converter's tail) into s->buf, and
 * returns the number of output frames it produced, < 0 on error. */
static int mav_convert( struct mav_stream *s, const AVFrame *frame )
{
    uint32_t bps = mav_bytes_per_sample( s->out.fmt );
    uint32_t conv_bps = bps == 3 ? 4 : bps;
    int want, got;
    uint8_t *outp;

    if (frame && mav_setup_swr( s, frame ) < 0) return -1;
    if (!s->swr) return 0;
    want = swr_get_out_samples( s->swr, frame ? frame->nb_samples : 0 );
    if (want <= 0) return 0;
    if (!mav_reserve( s, (size_t)want * s->out.channels * conv_bps )) return -1;
    outp = s->buf;
    got = swr_convert( s->swr, &outp, want,
                       frame ? (const uint8_t *const *)frame->extended_data : NULL,
                       frame ? frame->nb_samples : 0 );
    if (got <= 0) return got;
    if (bps == 3)
    {
        /* S24: the top three bytes of each little-endian S32 sample, in place
         * (the write index never overtakes the read index) */
        size_t n = (size_t)got * s->out.channels, i;
        for (i = 0; i < n; i++)
        {
            s->buf[i * 3 + 0] = s->buf[i * 4 + 1];
            s->buf[i * 3 + 1] = s->buf[i * 4 + 2];
            s->buf[i * 3 + 2] = s->buf[i * 4 + 3];
        }
    }
    return got;
}

/* Sets s->cur for `frames` converted frames starting at `pts`, applying the
 * seek target and the stop position.  Returns 1 if a buffer is left. */
static int mav_finish_buffer( struct mav_parser *p, struct mav_stream *s, int64_t pts, int frames )
{
    uint32_t frame_bytes = mav_bytes_per_sample( s->out.fmt ) * s->out.channels;
    int64_t dur = av_rescale( frames, 10000000, s->out.rate );
    int64_t skip = 0, keep = frames;

    s->next_pts = pts + dur;
    if (s->seek_target >= 0)
    {
        if (pts + dur <= s->seek_target)
        {
            s->stat_seek_trim++;
            s->cur_audio_ns = 0;
            return 0;
        }
        if (pts < s->seek_target)
        {
            skip = av_rescale( s->seek_target - pts, s->out.rate, 10000000 );
            if (skip > frames) skip = frames;
            pts = s->seek_target;
        }
        s->seek_target = -1;
    }
    keep = frames - skip;
    if (p->stop >= 0)
    {
        if (pts >= p->stop)
        {
            s->cur_audio_ns = 0;
            s->eos = 1;
            return 0;
        }
        if (pts + av_rescale( keep, 10000000, s->out.rate ) > p->stop)
        {
            int64_t cut = av_rescale( p->stop - pts, s->out.rate, 10000000 );
            if (cut < keep) keep = cut;
            s->eos = 1;   /* nothing after this buffer is wanted */
        }
    }
    if (keep <= 0)
    {
        if (skip > 0) s->stat_seek_trim++;
        s->cur_audio_ns = 0;
        return 0;
    }
    if (skip) memmove( s->buf, s->buf + skip * frame_bytes, keep * frame_bytes );

    s->decode_count++;
    s->decode_ns_sum += s->cur_audio_ns;
    if (s->cur_audio_ns > s->decode_ns_max) s->decode_ns_max = s->cur_audio_ns;
    s->cur_audio_ns = 0;
    s->cur.pts = pts > 0 ? (uint64_t)pts : 0;
    s->cur.duration = av_rescale( keep, 10000000, s->out.rate );
    s->cur.size = (uint32_t)(keep * frame_bytes);
    s->cur.stream = s->number;
    s->cur.discontinuity = s->discontinuity;
    s->cur.delta = 0;
    s->discontinuity = 0;
    s->has_buffer = 1;
    return 1;
}

static int64_t mav_frame_pts( struct mav_stream *s, const AVFrame *frame )
{
    int64_t ts = frame->best_effort_timestamp;

    if (ts == AV_NOPTS_VALUE) return s->next_pts;
    return mav_to_100ns( s, ts );
}

static int mav_give_up( struct mav_stream *s )
{
    mav_log( "%s: %u consecutive undecodable packets; ending the stream", s->info.codec, s->decode_errors );
    s->eos = 1;
    return MAV_NO_BUFFER;
}

/* The platform backend: one packet in, float frames out. */
static int mav_audio_next_backend( struct mav_parser *p, struct mav_stream *s )
{
    for (;;)
    {
        uint64_t t0, dt;
        int64_t pts;
        int n, got;

        if (s->eos) return MAV_NO_BUFFER;
        if (!mav_next_packet( p, s, s->pkt ))
        {
            /* the converter's tail (only non-empty when resampling) */
            t0 = mav_now_ns();
            got = mav_convert( s, NULL );
            if (got >= 0) s->cur_audio_ns += t0 ? mav_now_ns() - t0 : 0;
            s->eos = 1;
            if (got > 0 && mav_finish_buffer( p, s, s->next_pts, got ))
            {
                s->eos = 1;
                return MAV_OK;
            }
            return MAV_NO_BUFFER;
        }
        /* The decoder may answer a packet late; timestamps follow the
         * packets in order, not the calls. */
        pts = s->pkt->pts != AV_NOPTS_VALUE ? mav_to_100ns( s, s->pkt->pts ) : INT64_MIN;
        if (s->apts_count == sizeof(s->apts) / sizeof(s->apts[0]))
        {
            memmove( s->apts, s->apts + 1, (s->apts_count - 1) * sizeof(s->apts[0]) );
            s->apts_count--;
        }
        s->apts[s->apts_count++] = pts;
        t0 = mav_now_ns();
        n = mav_abackend->decode( s->adec, s->pkt->data, s->pkt->size, (float *)s->bframe->data[0],
                                  MAV_AUDIO_BACKEND_MAX_FRAMES );
        dt = t0 ? mav_now_ns() - t0 : 0;
        av_packet_unref( s->pkt );
        if (n < 0)
        {
            s->stat_decode_errors++;
            if (s->errors_logged < 3)
            {
                s->errors_logged++;
                mav_log( "%s: packet rejected by %s (%d), skipped", s->info.codec, s->info.backend, n );
            }
            s->apts_count--;
            if (++s->decode_errors > MAV_MAX_DECODE_ERRORS) return mav_give_up( s );
            continue;
        }
        s->cur_audio_ns += dt;
        s->decode_errors = 0;
        if (!n) continue;
        pts = s->apts[0];
        memmove( s->apts, s->apts + 1, (s->apts_count - 1) * sizeof(s->apts[0]) );
        s->apts_count--;
        if (pts == INT64_MIN) pts = s->next_pts;
        s->bframe->nb_samples = n > MAV_AUDIO_BACKEND_MAX_FRAMES ? MAV_AUDIO_BACKEND_MAX_FRAMES : n;
        t0 = mav_now_ns();
        got = mav_convert( s, s->bframe );
        dt = t0 ? mav_now_ns() - t0 : 0;
        if (got < 0)
        {
            s->stat_decode_errors++;
            s->cur_audio_ns = 0;
            mav_log( "sample conversion failed; ending the stream" );
            s->eos = 1;
            return MAV_NO_BUFFER;
        }
        s->cur_audio_ns += dt;
        if (got && mav_finish_buffer( p, s, pts, got )) return MAV_OK;
    }
}

/* Produces the next buffer.  Returns MAV_OK with s->has_buffer set, or
 * MAV_NO_BUFFER at end of stream. */
static int mav_audio_next( struct mav_parser *p, struct mav_stream *s )
{
    uint64_t t0, dt;
    int err;

    if (s->adec) return mav_audio_next_backend( p, s );
    for (;;)
    {
        if (s->eos) return MAV_NO_BUFFER;

        t0 = mav_now_ns();
        err = avcodec_receive_frame( s->dec, s->frame );
        dt = t0 ? mav_now_ns() - t0 : 0;
        if (!err)
        {
            int64_t pts = mav_frame_pts( s, s->frame );
            int got;

            s->cur_audio_ns += dt;
            t0 = mav_now_ns();
            got = mav_convert( s, s->frame );
            dt = t0 ? mav_now_ns() - t0 : 0;
            av_frame_unref( s->frame );
            if (got < 0)
            {
                s->stat_decode_errors++;
                s->cur_audio_ns = 0;
                mav_log( "sample conversion failed; ending the stream" );
                s->eos = 1;
                return MAV_NO_BUFFER;
            }
            s->cur_audio_ns += dt;
            s->decode_errors = 0;
            if (got && mav_finish_buffer( p, s, pts, got )) return MAV_OK;
            continue;
        }
        if (err == AVERROR_EOF)
        {
            /* the converter's tail (only non-empty when resampling) */
            int got;
            int64_t pts = s->next_pts;

            t0 = mav_now_ns();
            got = mav_convert( s, NULL );
            if (got >= 0) s->cur_audio_ns += t0 ? mav_now_ns() - t0 : 0;
            s->eos = 1;
            if (got > 0 && mav_finish_buffer( p, s, pts, got ))
            {
                s->eos = 1;
                return MAV_OK;
            }
            return MAV_NO_BUFFER;
        }
        if (err != AVERROR(EAGAIN))
        {
            /* A decoding error on output; the next packet may be fine. */
            s->stat_decode_errors++;
            if (++s->decode_errors > MAV_MAX_DECODE_ERRORS) return mav_give_up( s );
        }

        if (s->draining)
        {
            /* receive_frame must reach EOF once drained; guard anyway */
            if (err == AVERROR(EAGAIN)) { s->eos = 1; return MAV_NO_BUFFER; }
            continue;
        }

        if (!s->pkt_pending)
        {
            if (!mav_next_packet( p, s, s->pkt ))
            {
                t0 = mav_now_ns();
                avcodec_send_packet( s->dec, NULL );
                s->cur_audio_ns += t0 ? mav_now_ns() - t0 : 0;
                s->draining = 1;
                continue;
            }
            s->pkt_pending = 1;
        }
        t0 = mav_now_ns();
        err = avcodec_send_packet( s->dec, s->pkt );
        dt = t0 ? mav_now_ns() - t0 : 0;
        if (err == AVERROR(EAGAIN)) continue;   /* output first, then this packet again */
        av_packet_unref( s->pkt );
        s->pkt_pending = 0;
        if (err < 0)
        {
            s->stat_decode_errors++;
            if (s->errors_logged < 3)
            {
                s->errors_logged++;
                mav_log( "%s: packet rejected (%d), skipped", s->info.codec, err );
            }
            if (++s->decode_errors > MAV_MAX_DECODE_ERRORS) return mav_give_up( s );
        }
        else s->cur_audio_ns += dt;
    }
}

/***********************************************************************
 *           video
 */
static void mav_vframe_emit_cb( void *ctx, void *handle, int64_t pts, int64_t duration )
{
    struct mav_stream *s = ctx;
    unsigned int i;

    if (s->reorder_count == s->reorder_cap)
    {
        unsigned int cap = s->reorder_cap ? s->reorder_cap * 2 : 8;
        struct mav_vframe *grown = realloc( s->reorder, cap * sizeof(*grown) );
        if (!grown)
        {
            s->vbackend->release( handle );
            return;
        }
        s->reorder = grown;
        s->reorder_cap = cap;
    }
    if (s->decode_order)
    {
        /* libavcodec already reorders B-frames (including DivX packed
         * bitstreams in AVI) into presentation order: keep that order even if
         * an AVI's packet timestamps swap across a packed P+B chunk or are
         * absent when the decoder drains. */
        int64_t last = s->reorder_count ? s->reorder[s->reorder_count - 1].pts : s->last_vpts;
        int64_t step = duration != INT64_MIN && duration > 0 ? duration
                       : av_rescale_q( s->frame_duration, (AVRational){ 1, 10000000 }, s->time_base );
        if (step <= 0) step = 1;
        if (pts == INT64_MIN)
            pts = last == INT64_MIN ? s->origin : last + step;
        else if (last != INT64_MIN && pts <= last)
            pts = last + step;
        i = s->reorder_count;
    }
    else
    {
        if (pts == INT64_MIN)
        {
            /* no timestamp: right after the latest picture known */
            int64_t last = s->reorder_count ? s->reorder[s->reorder_count - 1].pts : s->last_vpts;
            int64_t step = duration != INT64_MIN && duration > 0 ? duration
                           : av_rescale_q( s->frame_duration, (AVRational){ 1, 10000000 }, s->time_base );
            pts = last == INT64_MIN ? s->origin : last + (step > 0 ? step : 1);
        }
        for (i = s->reorder_count; i > 0 && s->reorder[i - 1].pts > pts; i--)
            s->reorder[i] = s->reorder[i - 1];
    }
    s->reorder[i].handle = handle;
    s->reorder[i].pts = pts;
    s->reorder[i].duration = duration;
    s->reorder[i].decode_ns = UINT64_MAX;
    s->reorder_count++;
}

static void mav_assign_decode_ns( struct mav_stream *s, uint64_t dt, int ok )
{
    unsigned int i, n = 0;

    for (i = 0; i < s->reorder_count; i++)
        if (s->reorder[i].decode_ns == UINT64_MAX) n++;
    if (n)
    {
        uint64_t share = (s->priming_decode_ns + dt) / n;
        s->priming_decode_ns = 0;
        for (i = 0; i < s->reorder_count; i++)
            if (s->reorder[i].decode_ns == UINT64_MAX) s->reorder[i].decode_ns = share;
    }
    else if (ok)
        s->priming_decode_ns += dt;
}

static inline uint8_t mav_clip8( int v )
{
    return v < 0 ? 0 : v > 255 ? 255 : (uint8_t)v;
}

struct mav_yuv_coefs
{
    int y, rv, gu, gv, bu, yoff;
};

static void mav_yuv_coefs( int bt709, int full, struct mav_yuv_coefs *c )
{
    double kr = bt709 ? 0.2126 : 0.299, kb = bt709 ? 0.0722 : 0.114, kg = 1.0 - kr - kb;
    double ys = full ? 1.0 : 255.0 / 219.0, cs = full ? 1.0 : 255.0 / 224.0;

    c->y = (int)lround( ys * 65536 );
    c->rv = (int)lround( 2 * (1 - kr) * cs * 65536 );
    c->bu = (int)lround( 2 * (1 - kb) * cs * 65536 );
    c->gu = (int)lround( 2 * (1 - kb) * kb / kg * cs * 65536 );
    c->gv = (int)lround( 2 * (1 - kr) * kr / kg * cs * 65536 );
    c->yoff = full ? 0 : 16;
}

/* Writes one decoded 4:2:0 bi-planar picture into `dst` in `vout`'s format
 * and layout, converting to RGB with the BT.709 matrix if `bt709`, else
 * BT.601.  A picture smaller than the output is padded with black; a larger
 * one is cropped (the codec's cropping is the decoder's business).  It takes
 * the output description rather than a stream so that the wg_transform's WMV
 * decoder (winegstreamer_unixlib_ios.c) writes its pictures with the same
 * code. */
static void mav_convert_picture( const struct mav_video_output *vout, int bt709, const struct mav_vplanes *src,
                                 uint8_t *dst, const struct mav_layout *l )
{
    uint32_t w = vout->width, h = vout->height < 0 ? -vout->height : vout->height;
    uint32_t cw = src->width < w ? src->width : w, ch = src->height < h ? src->height : h;
    uint32_t ccw = (cw + 1) / 2, cch = (ch + 1) / 2, x, y;
    int flip = vout->height < 0;
    int planar = vout->fmt == MAV_PIX_NV12 || vout->fmt == MAV_PIX_I420 || vout->fmt == MAV_PIX_YV12;
    int packed = vout->fmt == MAV_PIX_YUY2 || vout->fmt == MAV_PIX_UYVY || vout->fmt == MAV_PIX_YVYU;

    if (cw < w || ch < h)
    {
        static const uint8_t uyvy_black[4] = { 0x80, 0x10, 0x80, 0x10 };
        static const uint8_t yuy2_black[4] = { 0x10, 0x80, 0x10, 0x80 };
        static const uint8_t rgb_black[4] = { 0, 0, 0, 0xff };

        /* black: Y 16 / chroma 128, or RGB black (opaque where there is alpha) */
        if (packed)
            for (y = 0; y < h; y++)
                for (x = 0; x < l->stride[0] / 4; x++)
                    memcpy( dst + (size_t)y * l->stride[0] + (size_t)x * 4,
                            vout->fmt == MAV_PIX_UYVY ? uyvy_black : yuy2_black, 4 );
        else if (planar)
        {
            memset( dst, 16, l->offset[1] );
            memset( dst + l->offset[1], 128, l->size - l->offset[1] );
        }
        else if (vout->fmt == MAV_PIX_BGR || vout->fmt == MAV_PIX_RGB15 || vout->fmt == MAV_PIX_RGB16)
            memset( dst, 0, l->size );
        else
            for (y = 0; y < h; y++)
                for (x = 0; x < w; x++)
                    memcpy( dst + (size_t)y * l->stride[0] + (size_t)x * 4, rgb_black, 4 );
    }

#define DST_ROW(plane, row, rows) (dst + l->offset[plane] + (size_t)l->stride[plane] * (flip ? (rows) - 1 - (row) : (row)))
    switch (vout->fmt)
    {
    case MAV_PIX_NV12:
        for (y = 0; y < ch; y++) memcpy( DST_ROW( 0, y, h ), src->y + (size_t)y * src->y_stride, cw );
        for (y = 0; y < cch; y++) memcpy( DST_ROW( 1, y, l->chroma_height ), src->uv + (size_t)y * src->uv_stride, (size_t)ccw * 2 );
        break;
    case MAV_PIX_I420:
    case MAV_PIX_YV12:
    {
        int u_plane = vout->fmt == MAV_PIX_I420 ? 1 : 2, v_plane = 3 - u_plane;
        for (y = 0; y < ch; y++) memcpy( DST_ROW( 0, y, h ), src->y + (size_t)y * src->y_stride, cw );
        for (y = 0; y < cch; y++)
        {
            const uint8_t *uv = src->uv + (size_t)y * src->uv_stride;
            uint8_t *u = DST_ROW( u_plane, y, l->chroma_height ), *v = DST_ROW( v_plane, y, l->chroma_height );
            for (x = 0; x < ccw; x++)
            {
                u[x] = uv[(size_t)2 * x];
                v[x] = uv[(size_t)2 * x + 1];
            }
        }
        break;
    }
    case MAV_PIX_YUY2:
    case MAV_PIX_UYVY:
    case MAV_PIX_YVYU:
    {
        /* byte offsets of Y0, U, Y1, V in each 4-byte pair */
        int y0 = vout->fmt == MAV_PIX_UYVY ? 1 : 0, y1 = y0 + 2;
        int uo = vout->fmt == MAV_PIX_YUY2 ? 1 : vout->fmt == MAV_PIX_UYVY ? 0 : 3;
        int vo = vout->fmt == MAV_PIX_YUY2 ? 3 : vout->fmt == MAV_PIX_UYVY ? 2 : 1;
        for (y = 0; y < ch; y++)
        {
            const uint8_t *yr = src->y + (size_t)y * src->y_stride, *uv = src->uv + (size_t)(y / 2) * src->uv_stride;
            uint8_t *o = DST_ROW( 0, y, h );
            for (x = 0; x < cw; x += 2)
            {
                o[2 * x + y0] = yr[x];
                o[2 * x + uo] = uv[x];
                o[2 * x + y1] = x + 1 < cw ? yr[x + 1] : yr[x];
                o[2 * x + vo] = uv[x + 1];
            }
        }
        break;
    }
    case MAV_PIX_BGRA:
    case MAV_PIX_BGRx:
    case MAV_PIX_RGBA:
    {
        struct mav_yuv_coefs c;
        int ri = vout->fmt == MAV_PIX_RGBA ? 0 : 2, bi = 2 - ri;
        mav_yuv_coefs( bt709, src->full_range, &c );
        for (y = 0; y < ch; y++)
        {
            const uint8_t *yr = src->y + (size_t)y * src->y_stride, *uv = src->uv + (size_t)(y / 2) * src->uv_stride;
            uint8_t *o = DST_ROW( 0, y, h );
            for (x = 0; x < cw; x++)
            {
                int yy = (yr[x] - c.yoff) * c.y + 32768;
                int u = uv[(x & ~1u)] - 128, v = uv[(x & ~1u) + 1] - 128;
                o[4 * x + ri] = mav_clip8( (yy + c.rv * v) >> 16 );
                o[4 * x + 1] = mav_clip8( (yy - c.gu * u - c.gv * v) >> 16 );
                o[4 * x + bi] = mav_clip8( (yy + c.bu * u) >> 16 );
                o[4 * x + 3] = 0xff;
            }
        }
        break;
    }
    case MAV_PIX_BGR:
    case MAV_PIX_RGB15:
    case MAV_PIX_RGB16:
    {
        struct mav_yuv_coefs c;
        mav_yuv_coefs( bt709, src->full_range, &c );
        for (y = 0; y < ch; y++)
        {
            const uint8_t *yr = src->y + (size_t)y * src->y_stride, *uv = src->uv + (size_t)(y / 2) * src->uv_stride;
            uint8_t *o = DST_ROW( 0, y, h );
            for (x = 0; x < cw; x++)
            {
                int yy = (yr[x] - c.yoff) * c.y + 32768;
                int u = uv[(x & ~1u)] - 128, v = uv[(x & ~1u) + 1] - 128;
                uint8_t r = mav_clip8( (yy + c.rv * v) >> 16 );
                uint8_t g = mav_clip8( (yy - c.gu * u - c.gv * v) >> 16 );
                uint8_t b = mav_clip8( (yy + c.bu * u) >> 16 );
                if (vout->fmt == MAV_PIX_BGR)
                {
                    o[(size_t)3 * x] = b;
                    o[(size_t)3 * x + 1] = g;
                    o[(size_t)3 * x + 2] = r;
                }
                else
                {
                    uint16_t px = vout->fmt == MAV_PIX_RGB16
                                  ? (uint16_t)((r >> 3) << 11 | (g >> 2) << 5 | b >> 3)
                                  : (uint16_t)((r >> 3) << 10 | (g >> 3) << 5 | b >> 3);
                    o[(size_t)2 * x] = (uint8_t)px;
                    o[(size_t)2 * x + 1] = (uint8_t)(px >> 8);
                }
            }
        }
        break;
    }
    default:
        break;
    }
#undef DST_ROW
}

/* The worker decodes and converts without the parser lock, so a request for
 * another stream (audio, on the same Media Foundation work queue thread) is
 * not held up behind a picture; anyone else keeps the lock.  Nothing but the
 * worker touches this stream's decoder, reorder queue and s->buf meanwhile:
 * whoever would (seek, a new format, disable, disconnect) waits in
 * mav_ahead_quiesce. */
static int mav_heavy_begin( struct mav_parser *p, struct mav_stream *s )
{
    if (!s->ahead_on || !pthread_equal( s->ahead_thread, pthread_self() )) return 0;
    s->busy = 1;
    pthread_mutex_unlock( &p->lock );
    return 1;
}

static void mav_heavy_end( struct mav_parser *p, struct mav_stream *s, int unlocked )
{
    if (!unlocked) return;
    pthread_mutex_lock( &p->lock );
    s->busy = 0;
    pthread_cond_broadcast( &p->ahead_cond );
}

/* One picture out of the reorder queue, into s->buf.  Returns 1 if it is
 * the next buffer, 0 if it was dropped (before the seek target, past the
 * stop, or unmappable). */
static int mav_video_emit( struct mav_parser *p, struct mav_stream *s, struct mav_vframe *f )
{
    struct mav_vplanes planes;
    struct mav_layout l;
    int64_t pts = mav_to_100ns( s, f->pts ), dur;
    uint64_t t0, conv_ns, pic_ns;
    size_t size;
    int unlocked, mapped;

    dur = f->duration != INT64_MIN && f->duration > 0
          ? av_rescale_q( f->duration, s->time_base, (AVRational){ 1, 10000000 } ) : s->frame_duration;
    s->last_vpts = f->pts;
    if (s->seek_target >= 0)
    {
        if (pts + dur <= s->seek_target)
        {
            s->stat_seek_trim++;
            s->vbackend->release( f->handle );
            return 0;
        }
        s->seek_target = -1;
    }
    if (p->stop >= 0 && pts >= p->stop)
    {
        s->vbackend->release( f->handle );
        s->eos = 1;
        return 0;
    }
    size = mav_video_layout( s->vout.fmt, s->vout.width, s->vout.height < 0 ? -s->vout.height : s->vout.height, &l );
    if (!size || size > UINT32_MAX || !mav_reserve( s, size ))
    {
        s->vbackend->release( f->handle );
        s->eos = 1;
        mav_log( "stream %u: cannot hold a %zu-byte picture; ending the stream", s->number, size );
        return 0;
    }
    t0 = mav_now_ns();
    unlocked = mav_heavy_begin( p, s );
    if ((mapped = !s->vbackend->map( f->handle, &planes )))
    {
        mav_convert_picture( &s->vout, s->bt709, &planes, s->buf, &l );
        s->vbackend->unmap( f->handle );
    }
    s->vbackend->release( f->handle );
    conv_ns = t0 ? mav_now_ns() - t0 : 0;
    mav_heavy_end( p, s, unlocked );
    if (!mapped)
    {
        s->stat_decode_errors++;
        if (s->errors_logged < 3)
        {
            s->errors_logged++;
            mav_log( "stream %u: a decoded picture could not be mapped; dropped", s->number );
        }
        s->discontinuity = 1;
        return 0;
    }
    pic_ns = (f->decode_ns == UINT64_MAX ? 0 : f->decode_ns) + conv_ns;
    s->decode_count++;
    s->decode_ns_sum += pic_ns;
    if (pic_ns > s->decode_ns_max) s->decode_ns_max = pic_ns;

    s->next_pts = pts + dur;
    s->cur.pts = pts > 0 ? (uint64_t)pts : 0;
    s->cur.duration = dur;
    s->cur.size = (uint32_t)size;
    s->cur.stream = s->number;
    s->cur.discontinuity = s->discontinuity;
    s->cur.delta = 0;
    s->discontinuity = 0;
    s->has_buffer = 1;
    return 1;
}

static int mav_video_next( struct mav_parser *p, struct mav_stream *s )
{
    for (;;)
    {
        int err;

        if (s->eos) return MAV_NO_BUFFER;
        /* A picture is final once no later packet can present before it:
         * later packets decode at or after the last decode time, and a
         * picture never presents before it decodes. */
        if (s->reorder_count && (s->draining || s->reorder_count > MAV_REORDER_MAX
                                 || s->vbackend == &mav_lavc_video   /* already in presentation order */
                                 || (s->last_dts != INT64_MIN && s->reorder[0].pts <= s->last_dts)))
        {
            struct mav_vframe f = s->reorder[0];
            memmove( s->reorder, s->reorder + 1, (s->reorder_count - 1) * sizeof(*s->reorder) );
            s->reorder_count--;
            if (mav_video_emit( p, s, &f )) return MAV_OK;
            continue;
        }
        if (s->draining)
        {
            s->eos = 1;
            return MAV_NO_BUFFER;
        }
        if (!mav_next_packet( p, s, s->pkt ))
        {
            /* libavcodec holds its last pictures until it is drained */
            if (s->vbackend == &mav_lavc_video && !p->closing)
            {
                uint64_t t0 = mav_now_ns(), dt;
                int unlocked = mav_heavy_begin( p, s );
                mav_lavc_drain( s->vdec, mav_vframe_emit_cb, s );
                dt = t0 ? mav_now_ns() - t0 : 0;
                mav_heavy_end( p, s, unlocked );
                mav_assign_decode_ns( s, dt, 1 );
            }
            s->draining = 1;
            continue;
        }
        {
            uint64_t t0 = mav_now_ns(), dt;
            int unlocked = mav_heavy_begin( p, s );
            err = s->decode_order
                  ? mav_lavc_decode_packet( s->vdec, s->pkt, mav_vframe_emit_cb, s )
                  : s->vbackend->decode( s->vdec, s->pkt->data, s->pkt->size,
                                         s->pkt->pts != AV_NOPTS_VALUE ? s->pkt->pts : INT64_MIN,
                                         s->pkt->duration > 0 ? s->pkt->duration : INT64_MIN,
                                         !!(s->pkt->flags & AV_PKT_FLAG_KEY), mav_vframe_emit_cb, s );
            dt = t0 ? mav_now_ns() - t0 : 0;
            mav_heavy_end( p, s, unlocked );
            mav_assign_decode_ns( s, dt, err >= 0 );
        }
        s->last_dts = s->pkt->dts != AV_NOPTS_VALUE ? s->pkt->dts : INT64_MIN;
        av_packet_unref( s->pkt );
        if (err < 0)
        {
            s->stat_decode_errors++;
            if (s->errors_logged < 3)
            {
                s->errors_logged++;
                mav_log( "%s: packet rejected by %s (%d), skipped", s->info.codec, s->info.backend, err );
            }
            s->discontinuity = 1;
            if (++s->decode_errors > MAV_MAX_DECODE_ERRORS) return mav_give_up( s );
        }
        else s->decode_errors = 0;
    }
}

/***********************************************************************
 *           video decode-ahead
 *
 * Wine's media source asks for every stream's samples on one work-queue
 * thread (a standard work queue has one thread), and so does the WM reader
 * reading the earliest buffer.  Decoded on demand, each picture of a 1080p
 * WMV (software decode and RGB conversion, about 20 ms) held up the audio
 * request behind it, and the audio renderer ran short every few seconds
 * (Senren Banka's movie).  GStreamer decodes in streaming threads of its own;
 * here each decoded video stream gets a worker, started at its first request,
 * that keeps up to MAV_AHEAD_SLOTS - 1 pictures ready.  It demuxes under the
 * parser lock like any reader and decodes and converts without it
 * (mav_heavy_begin); a request pops a ready picture.  MADEIRA_WG_VIDEO_AHEAD=0
 * decodes on demand again.
 */
static int mav_ahead_free_slot( const struct mav_stream *s )
{
    unsigned int i, j;

    for (i = 0; i < MAV_AHEAD_SLOTS; i++)
    {
        int used = (int)i == s->out_slot;
        for (j = 0; j < s->ready_count && !used; j++) used = s->ready[j] == i;
        if (!used) return i;
    }
    return -1;
}

static void *mav_ahead_main( void *arg )
{
    struct mav_stream *s = arg;
    struct mav_parser *p = s->parser;

    pthread_mutex_lock( &p->lock );
    for (;;)
    {
        unsigned int generation;
        int status, slot;

        while (!p->closing && !s->ahead_stop
               && (p->ahead_hold || !s->enabled || s->compressed || s->ahead_eos || mav_ahead_free_slot( s ) < 0))
            pthread_cond_wait( &p->ahead_cond, &p->lock );
        if (p->closing || s->ahead_stop) break;

        generation = p->generation;
        s->has_buffer = 0;
        status = mav_video_next( p, s );
        if (p->closing || s->ahead_stop) break;
        if (generation != p->generation || !s->enabled || s->compressed)
        {
            /* a seek, a new format or a disable came while it waited for a
             * queue to drain: what it made is not wanted */
            s->has_buffer = 0;
            continue;
        }
        if (status == MAV_OK && s->has_buffer && (slot = mav_ahead_free_slot( s )) >= 0)
        {
            struct mav_ahead_slot *a = &s->ahead[slot];
            uint8_t *buf = a->buf;
            size_t cap = a->cap;

            /* the picture changes hands; its slot's old buffer is the next one made */
            a->buf = s->buf;
            a->cap = s->buf_cap;
            a->cur = s->cur;
            s->buf = buf;
            s->buf_cap = cap;
            s->ready[s->ready_count++] = slot;
        }
        else if (status != MAV_OK)
            s->ahead_eos = 1;
        s->has_buffer = 0;
        pthread_cond_broadcast( &p->ahead_cond );
    }
    pthread_mutex_unlock( &p->lock );
    return NULL;
}

/* Called by the first request, with the lock.  A worker that cannot be
 * started leaves the stream decoded on demand. */
static void mav_ahead_start( struct mav_parser *p, struct mav_stream *s )
{
    pthread_attr_t attr;
    int err;

    (void)p;
    pthread_attr_init( &attr );
    pthread_attr_setstacksize( &attr, (size_t)1024 * 1024 );
    s->ahead_stop = 0;
    s->ahead_eos = 0;
    s->ready_count = 0;
    s->out_slot = -1;
    /* the worker waits for this lock, so ahead_thread is set before it runs */
    if ((err = pthread_create( &s->ahead_thread, &attr, mav_ahead_main, s )))
    {
        s->ahead_failed = 1;
        mav_log( "stream %u: no decode-ahead thread (%d); decoding on demand", s->number, err );
    }
    else
    {
        s->ahead_on = 1;
        s->ahead_used = 1;
        mav_log( "stream %u: decoding ahead on a thread of its own (%u pictures)", s->number,
                 MAV_AHEAD_SLOTS - 1 );
    }
    pthread_attr_destroy( &attr );
}

static int mav_ahead_next( struct mav_parser *p, struct mav_stream *s )
{
    if (s->out_slot >= 0)
    {
        s->cur = s->ahead[s->out_slot].cur;
        return MAV_OK;
    }
    for (;;)
    {
        if (p->closing || !s->enabled || s->compressed) return MAV_NO_BUFFER;
        if (s->ready_count)
        {
            s->out_slot = s->ready[0];
            memmove( s->ready, s->ready + 1, (s->ready_count - 1) * sizeof(*s->ready) );
            s->ready_count--;
            s->cur = s->ahead[s->out_slot].cur;
            pthread_cond_broadcast( &p->ahead_cond );
            return MAV_OK;
        }
        if (s->ahead_eos || !s->ahead_on) return MAV_NO_BUFFER;
        p->ahead_waiters++;
        pthread_cond_wait( &p->ahead_cond, &p->lock );
        p->ahead_waiters--;
        if (p->closing) pthread_cond_broadcast( &p->drain_cond );   /* mav_ahead_stop_all waits for it */
    }
}

/***********************************************************************
 *           compressed
 */
/* After a seek, this many delta frames are dropped at most while waiting for
 * a keyframe (a file that flags none still plays). */
#define MAV_MAX_SEEK_SKIP 300

/* The next packet as it is, for the caller's decoder.  After a seek the
 * demuxer is at or before the target, and everything from the first keyframe
 * on is handed out, since a decoder needs it (the WM reader does not trim). */
static int mav_compressed_next( struct mav_parser *p, struct mav_stream *s )
{
    int64_t ts, pts, dur;

    for (;;)
    {
        if (s->eos) return MAV_NO_BUFFER;
        if (!mav_next_packet( p, s, s->pkt ))
        {
            s->eos = 1;
            return MAV_NO_BUFFER;
        }
        if (s->pkt->size <= 0)
        {
            av_packet_unref( s->pkt );
            continue;
        }
        if (s->seek_target >= 0 && s->type == MAV_STREAM_VIDEO && !(s->pkt->flags & AV_PKT_FLAG_KEY)
            && s->skipped < MAV_MAX_SEEK_SKIP)
        {
            s->skipped++;
            s->stat_seek_trim++;
            av_packet_unref( s->pkt );
            continue;
        }
        if (s->skipped >= MAV_MAX_SEEK_SKIP && s->errors_logged < 3)
        {
            s->errors_logged++;
            mav_log( "stream %u: no keyframe in %u packets after a seek; handing out delta frames", s->number,
                     s->skipped );
        }
        s->seek_target = -1;
        s->skipped = 0;
        ts = s->pkt->pts != AV_NOPTS_VALUE ? s->pkt->pts : s->pkt->dts;
        pts = ts != AV_NOPTS_VALUE ? mav_to_100ns( s, ts ) : s->next_pts;
        dur = s->pkt->duration > 0 ? av_rescale_q( s->pkt->duration, s->time_base, (AVRational){ 1, 10000000 } )
              : s->type == MAV_STREAM_VIDEO ? s->frame_duration : 0;
        if (p->stop >= 0 && pts >= p->stop)
        {
            av_packet_unref( s->pkt );
            s->eos = 1;
            return MAV_NO_BUFFER;
        }
        if (!mav_reserve( s, (size_t)s->pkt->size ))
        {
            av_packet_unref( s->pkt );
            s->eos = 1;
            mav_log( "stream %u: cannot hold a %d-byte packet; ending the stream", s->number, s->pkt->size );
            return MAV_NO_BUFFER;
        }
        memcpy( s->buf, s->pkt->data, s->pkt->size );
        s->next_pts = pts + dur;
        s->cur.pts = pts > 0 ? (uint64_t)pts : 0;
        s->cur.duration = dur;
        s->cur.size = (uint32_t)s->pkt->size;
        s->cur.stream = s->number;
        s->cur.discontinuity = s->discontinuity;
        s->cur.delta = !(s->pkt->flags & AV_PKT_FLAG_KEY);
        s->discontinuity = 0;
        s->has_buffer = 1;
        av_packet_unref( s->pkt );
        return MAV_OK;
    }
}

/***********************************************************************
 *           buffers
 */
static int mav_stream_next( struct mav_parser *p, struct mav_stream *s )
{
    if (!s->enabled) return MAV_NO_BUFFER;
    if (s->compressed) return s->has_buffer ? MAV_OK : mav_compressed_next( p, s );
    if (s->type == MAV_STREAM_VIDEO && mav_video_ahead && !s->ahead_on && !s->ahead_failed && !s->has_buffer)
        mav_ahead_start( p, s );
    if (mav_ahead_mode( s )) return mav_ahead_next( p, s );
    if (s->has_buffer) return MAV_OK;
    return s->type == MAV_STREAM_VIDEO ? mav_video_next( p, s ) : mav_audio_next( p, s );
}

/* The buffer get_buffer handed out is no longer the caller's. */
static void mav_drop_held( struct mav_parser *p, struct mav_stream *s )
{
    s->cur_counted = 0;
    if (mav_ahead_mode( s ))
    {
        if (s->out_slot >= 0)
        {
            s->out_slot = -1;
            pthread_cond_broadcast( &p->ahead_cond );
        }
    }
    else s->has_buffer = 0;
}

static int mav_get_buffer( struct mav_parser *p, int stream, struct mav_buffer *buffer )
{
    uint64_t wait_t0 = mav_now_ns();
    struct mav_stream *s = NULL;
    int status = MAV_NO_BUFFER;
    unsigned int i;

    pthread_mutex_lock( &p->lock );
    if (!p->ready)
        status = MAV_E_STATE;
    else if (stream >= 0)
    {
        if (!(s = mav_get_stream( p, stream ))) status = MAV_E_STATE;
        else
        {
            s->reader = pthread_self();
            s->has_reader = 1;
            status = mav_stream_next( p, s );
            /* disabled while this reader slept in mav_wait_drain */
            if (status == MAV_OK && !s->enabled)
            {
                mav_drop_held( p, s );
                status = MAV_NO_BUFFER;
            }
        }
    }
    else
    {
        /* wg_parser.c: the earliest buffer of all streams, by pts.  This
         * thread reads them all, so none waits for another (mav_wait_drain). */
        for (i = 0; i < p->stream_count; i++)
        {
            p->streams[i]->reader = pthread_self();
            p->streams[i]->has_reader = 1;
        }
        for (i = 0; i < p->stream_count; i++)
        {
            struct mav_stream *c = p->streams[i];
            if (mav_stream_next( p, c ) != MAV_OK || !c->enabled) continue;
            if (!s || c->cur.pts < s->cur.pts) s = c;
        }
        status = s ? MAV_OK : MAV_NO_BUFFER;
    }
    if (status == MAV_OK)
    {
        *buffer = s->cur;
        if (!s->cur_counted)
        {
            uint64_t wait_ns = wait_t0 ? mav_now_ns() - wait_t0 : 0;
            s->cur_counted = 1;
            s->stat_delivered++;
            s->wait_ns_sum += wait_ns;
            if (wait_ns > s->wait_ns_max) s->wait_ns_max = wait_ns;
        }
        /* One line per stream, so a device log tells a stream nobody asked
         * for (a renderer the media session dropped) from one that fails to
         * decode. */
        if (!s->delivered)
        {
            s->delivered = 1;
            if (s->compressed)
                mav_log( "stream %u: first compressed packet delivered (%s, %u bytes)", s->number, s->info.codec,
                         s->cur.size );
            else if (s->type == MAV_STREAM_VIDEO)
                mav_log( "stream %u: first picture delivered (%s %dx%d)", s->number, mav_pix_name( s->vout.fmt ),
                         s->vout.width, s->vout.height );
            else
                mav_log( "stream %u: first audio buffer delivered", s->number );
            if (mav_summary) mav_log_summary( p, s, "first" );
        }
    }
    /* a queue may have shrunk, or a stream ended: a waiter re-checks */
    if (p->bp_waiters) pthread_cond_broadcast( &p->drain_cond );
    pthread_mutex_unlock( &p->lock );
    return status;
}

static int mav_copy_buffer( struct mav_parser *p, unsigned int stream, void *dst, uint32_t offset, uint32_t size )
{
    struct mav_stream *s;
    int status = MAV_OK;

    pthread_mutex_lock( &p->lock );
    if (!(s = mav_get_stream( p, stream )) || (mav_ahead_mode( s ) ? s->out_slot < 0 : !s->has_buffer))
        status = MAV_E_STATE;
    else
    {
        const struct mav_buffer *cur = mav_ahead_mode( s ) ? &s->ahead[s->out_slot].cur : &s->cur;
        const uint8_t *buf = mav_ahead_mode( s ) ? s->ahead[s->out_slot].buf : s->buf;

        if (offset > cur->size || size > cur->size - offset || (size && !dst))
            status = MAV_E_PARAM;
        else
            memcpy( dst, buf + offset, size );
    }
    pthread_mutex_unlock( &p->lock );
    return status;
}

static void mav_release_buffer( struct mav_parser *p, unsigned int stream )
{
    struct mav_stream *s;

    pthread_mutex_lock( &p->lock );
    if ((s = mav_get_stream( p, stream ))) mav_drop_held( p, s );
    pthread_mutex_unlock( &p->lock );
}

/***********************************************************************
 *           seek
 */
/* Raw MPEG-1 video (ff_mpegvideo_demuxer) has no index or read_timestamp, so
 * FFmpeg's generic seek reads to EOF and fails.  Rewind the byte stream (which
 * flushes the demuxer's packet buffer and mpegvideo_parser), then -- when
 * seeking past 0 -- scan packets keeping only the last keyframe GOP at or
 * before `target` (plus the next keyframe, which open-GOP B-frames right after
 * it reference). */
static int mav_seek_m1v_rewind( struct mav_parser *p )
{
    av_seek_frame( p->fmt, -1, 0, AVSEEK_FLAG_BYTE );
    avio_seek( p->avio, 0, SEEK_SET );
    p->avio->error = 0;
    p->avio->eof_reached = 0;
    return 0;
}

static void mav_seek_m1v_advance( struct mav_parser *p, struct mav_stream *s, int64_t target )
{
    for (;;)
    {
        AVPacket *copy;
        int64_t pts_100ns;
        int is_key;

        if (av_read_frame( p->fmt, p->read_pkt ) < 0)
        {
            p->demux_eof = 1;
            break;
        }
        if (p->read_pkt->stream_index != s->av_index)
        {
            av_packet_unref( p->read_pkt );
            continue;
        }
        mav_stamp_m1v_packet( s, p->read_pkt );
        is_key = !!(p->read_pkt->flags & AV_PKT_FLAG_KEY);
        pts_100ns = mav_to_100ns( s, p->read_pkt->pts );
        if (is_key && pts_100ns <= target)
            mav_queue_clear( s );
        if (!(copy = av_packet_alloc()))
        {
            av_packet_unref( p->read_pkt );
            break;
        }
        av_packet_move_ref( copy, p->read_pkt );
        mav_queue_push( s, copy );
        if (is_key && pts_100ns > target)
            break;
    }
}

static int mav_seek( struct mav_parser *p, unsigned int stream, int set_start, uint64_t start,
                     int set_stop, uint64_t stop )
{
    struct mav_stream *s, *ref = NULL;
    int status = MAV_OK;
    unsigned int i;

    pthread_mutex_lock( &p->lock );
    if (!(s = mav_get_stream( p, stream )))
    {
        pthread_mutex_unlock( &p->lock );
        return MAV_E_STATE;
    }
    /* the decoders, the demuxer and the decode-ahead pictures are this thread's until the end */
    mav_ahead_quiesce( p );
    if (set_stop)
    {
        /* wg_parser.c: a stop at the duration means "no stop" */
        if (stop == s->info.duration || (s->info.duration && stop > s->info.duration))
            p->stop = -1;
        else
            p->stop = stop > INT64_MAX ? -1 : (int64_t)stop;
        /* pictures decoded ahead past a new stop are not handed out */
        for (i = 0; i < p->stream_count && i < MAV_MAX_STREAMS && p->stop >= 0; i++)
        {
            struct mav_stream *c = p->streams[i];
            unsigned int j, kept = 0;

            if (!c) continue;
            for (j = 0; j < c->ready_count; j++)
                if ((int64_t)c->ahead[c->ready[j]].cur.pts < p->stop) c->ready[kept++] = c->ready[j];
            if (kept < c->ready_count) c->ahead_eos = 1;
            c->ready_count = kept;
        }
    }
    if (set_start)
    {
        int64_t target = (int64_t)(start > INT64_MAX / 2 ? INT64_MAX / 2 : start), ts;
        int err;

        /* Seek on the video stream, so the demuxer lands on a keyframe.  An
         * MPEG program stream seeks to a pack by its timestamp, not to a
         * keyframe: a second earlier, the picture group that holds the target
         * starts after it, and the pictures up to the target are trimmed. */
        for (i = 0; i < p->stream_count && i < MAV_MAX_STREAMS; i++)
            if (p->streams[i] && (!ref || p->streams[i]->type == MAV_STREAM_VIDEO)) ref = p->streams[i];
        if (!ref) ref = s;
        ts = av_rescale_q( p->is_mpeg ? (target > MAV_MPEG_SEEK_LEAD ? target - MAV_MPEG_SEEK_LEAD : 0) : target,
                           (AVRational){ 1, 10000000 }, ref->time_base ) + ref->origin;

        /* A failed read (a NULL push) latches in the AVIOContext; a seek is
         * the PE side's way to start over, so it must not stay failed. */
        p->avio->error = 0;
        p->avio->eof_reached = 0;
        if (p->is_mpegvideo)
            err = mav_seek_m1v_rewind( p );
        else
        {
            err = avformat_seek_file( p->fmt, ref->av_index, INT64_MIN, ts, ts, 0 );
            if (err < 0) err = av_seek_frame( p->fmt, ref->av_index, ts, AVSEEK_FLAG_BACKWARD );
        }
        if (err < 0)
        {
            mav_log( "seek to %llums failed (%d)", (unsigned long long)(start / 10000), err );
            status = MAV_E_IO;
        }
        else
        {
            p->demux_eof = 0;
            for (i = 0; i < p->stream_count && i < MAV_MAX_STREAMS; i++)
            {
                struct mav_stream *c = p->streams[i];

                if (!c) continue;
                if (c->dec) avcodec_flush_buffers( c->dec );
                if (c->adec) mav_abackend->flush( c->adec );
                if (c->vdec)
                {
                    mav_reorder_clear( c );
                    c->vbackend->flush( c->vdec );
                }
                swr_free( &c->swr );
                if (c->pkt_pending) av_packet_unref( c->pkt );
                c->pkt_pending = 0;
                mav_queue_clear( c );
                c->apts_count = 0;
                c->has_buffer = 0;
                mav_ahead_reset( c );
                c->eos = c->draining = 0;
                c->decode_errors = 0;
                c->priming_decode_ns = 0;
                c->cur_audio_ns = 0;
                c->discontinuity = 1;
                c->seek_target = target;
                c->skipped = 0;
                c->next_pts = target;
                c->last_dts = c->last_vpts = INT64_MIN;
                c->m1v_gop_base = c->m1v_gop_frames = c->m1v_coded_frames = 0;
            }
            if (p->is_mpegvideo && target > 0)
                mav_seek_m1v_advance( p, ref, target );
            p->generation++;
            if (p->bp_waiters) pthread_cond_broadcast( &p->drain_cond );
        }
    }
    mav_ahead_resume( p );
    pthread_mutex_unlock( &p->lock );
    return status;
}
