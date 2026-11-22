#!/usr/bin/env python3
"""The raw video converter wg_transform in build/ntdll-unix/winegstreamer_unixlib_ios.c, on the host; no Wine runs.

Media Foundation's color converter (CLSID_CColorConvertDMO, dlls/winegstreamer/color_convert.c)
and video processor (CLSID_VideoProcessorMFT, dlls/winegstreamer/video_processor.c) are
wg_transforms whose input is RAW video. Previously every video wg_transform went to wmv_claims,
which refused raw input, so check_video_transform_support() failed at creation.

1. Source checks: both unix call tables route transform calls through the kind dispatcher;
   vconv_transform_ops ("video converter") sits in transform_kinds[] BEFORE wmv_transform_ops;
   MADEIRA_WG_VIDEO_CONVERT is read with getenv; vconv_read_data clears WG_SAMPLE_FLAG_INCOMPLETE
   and never sets it, and reuses mav_convert_picture; Wine's color_convert_create() and
   video_processor_create() probes (I420 1920x1080 -> NV12 1920x1080, attrs = {0}) still match;
   docs/MEDIA.md and ConfigCatalog.generated.swift list MADEIRA_WG_VIDEO_CONVERT.
2. Shared host FFmpeg 7.1.5 cache (same tag="asf" build as check-wmv-transform.py).
3. Compiles winegstreamer_unixlib_ios.c under ASan/UBSan and drives it through both call tables:
   - Wine's color_convert_create and video_processor_create probes (I420 1920x1080 -> NV12
     1920x1080, attrs = {0}), plus converting a 1920x1080 frame;
   - every input x output pair of all 14 formats (NV12, YV12, I420, IYUV, YUY2, UYVY, YVYU, AYUV,
     RGB32, ARGB32, ABGR32, RGB24, RGB565, RGB555 = 196 pairs) across all 4 orientation pairs
     (top-down/bottom-up in x top-down/bottom-up out = 784 runs) at 16x12 against an independent
     BT.601 limited-range reference, plus BT.709 checks, with guard bytes untouched;
   - 2D buffer sample->stride on both push_data and read_data, output_plane_align, too-short stride
     fallback, and input/output MinimumDisplayAperture cropping and offsets;
   - bilinear scaling (upscale, downscale, odd dimensions, 1x1 edge cases, aperture + scale)
     checked pixel-by-pixel against an independent floating-point bilinear reference;
   - timestamps (preserve_timestamps on/off, irregular, missing with/without frame rate),
     discontinuities, sync points, never INCOMPLETE; queue limits & get_status, drain, flush,
     mid-stream set_output_type with queued frames, two-phase get_output_type,
     STATUS_BUFFER_TOO_SMALL, short input drops, two threads, wow64 32-bit thunks (MAP_32BIT);
   - refusals, coexistence with WMV/WMA (and with MADEIRA_WG_WMV_TRANSFORM=0), and
     MADEIRA_WG_VIDEO_CONVERT=0.
"""
from pathlib import Path
import os, re, subprocess, sys, tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent))
from host_ffmpeg import host_ffmpeg, MEDIA_FLAGS

root = Path(__file__).resolve().parents[2]
ntdll_unix = root / "build/ntdll-unix"
wine = Path(os.environ.get("MADEIRA_WINE_SRC") or root / "wine")
wine_build = Path(os.environ.get("MADEIRA_WINE_BUILD") or wine / "build-macos")
glue = (ntdll_unix / "winegstreamer_unixlib_ios.c").read_text()
unixlib_h = (wine / "dlls/winegstreamer/unixlib.h").read_text()
failures = []


def check(cond, what):
    print(("PASS " if cond else "FAIL ") + what, flush=True)
    if not cond:
        failures.append(what)


def body(text, start, end="\n}\n"):
    if start not in text:
        return ""
    b = text[text.index(start):]
    return b[:b.index(end) + len(end)] if end in b else b


# ------------------------------------------------------------------ 1. source checks
enum_body = unixlib_h[unixlib_h.index("enum unix_funcs"):]
enum_body = enum_body[enum_body.index("{") + 1:enum_body.index("unix_wg_funcs_count")]
enum_names = re.findall(r"\b(unix_wg_\w+)\s*,", enum_body)


def table(name):
    b = body(glue, "const unixlib_entry_t %s[] =" % name, "};")
    rows = re.findall(r"^\s*(\w+),\s*/\*\s*(unix_wg_\w+)\s*\*/", b, re.M)
    return [r[1] for r in rows], dict((r[1], r[0]) for r in rows)


order64, native = table("__wine_unix_call_funcs")
order32, wow64 = table("__wine_unix_call_wow64_funcs")
check(order64 == enum_names and order32 == enum_names, "both call tables follow enum unix_funcs entry for entry")

vconv_row = body(glue, "static const struct wg_transform_ops vconv_transform_ops =", "};")
check('"video converter"' in vconv_row and all(
    fn in vconv_row for fn in ["vconv_claims", "vconv_create", "vconv_destroy", "vconv_get_output_type",
                               "vconv_set_output_type", "vconv_push_data", "vconv_read_data",
                               "vconv_get_status", "vconv_drain", "vconv_flush"]),
    'vconv_transform_ops ("video converter") defines all transform entry points')

kinds = body(glue, "static const struct wg_transform_ops *const transform_kinds[] =", "};")
check("&vconv_transform_ops," in kinds and "&wmv_transform_ops," in kinds
      and kinds.index("&vconv_transform_ops,") < kinds.index("&wmv_transform_ops,"),
      "vconv_transform_ops is in transform_kinds[] BEFORE wmv_transform_ops")

sw = body(glue, "static BOOL vconv_switch_on(void)")
check('getenv( "MADEIRA_WG_VIDEO_CONVERT" )' in sw and "vconv_switch_on()" in body(glue, "static NTSTATUS vconv_create("),
      "MADEIRA_WG_VIDEO_CONVERT is read with getenv in vconv_switch_on and checked in vconv_create")

vconv_read = body(glue, "static NTSTATUS vconv_read_data(")
check(vconv_read and "|= WG_SAMPLE_FLAG_INCOMPLETE" not in vconv_read and "WG_SAMPLE_FLAG_INCOMPLETE" in vconv_read,
      "vconv_read_data clears WG_SAMPLE_FLAG_INCOMPLETE and never sets it")
vconv_conv = body(glue, "static NTSTATUS vconv_convert_frame(")
check("mav_convert_picture(" in vconv_conv, "vconv_convert_frame reuses wg_parser_av_ios.c's mav_convert_picture")

# Wine pin checks: color_convert.c and video_processor.c probes
cc_src = (wine / "dlls/winegstreamer/color_convert.c").read_text()
vp_src = (wine / "dlls/winegstreamer/video_processor.c").read_text()
cc_create = body(cc_src, "HRESULT color_convert_create(")
vp_create = body(vp_src, "HRESULT video_processor_create(")
check(".dwWidth = 1920, .dwHeight = 1080" in cc_create
      and ".guidFormat = MFVideoFormat_I420" in cc_create
      and ".guidFormat = MFVideoFormat_NV12" in cc_create
      and "check_video_transform_support(&input_format, &output_format)" in cc_create,
      "pin: color_convert_create() probes I420 1920x1080 -> NV12 1920x1080 via check_video_transform_support")
check(".dwWidth = 1920, .dwHeight = 1080" in vp_create
      and ".guidFormat = MFVideoFormat_I420" in vp_create
      and ".guidFormat = MFVideoFormat_NV12" in vp_create
      and "check_video_transform_support(&input_format, &output_format)" in vp_create,
      "pin: video_processor_create() probes I420 1920x1080 -> NV12 1920x1080 via check_video_transform_support")
check("struct wg_transform_attrs attrs = {0};" in body(cc_src, "static HRESULT try_create_wg_transform(")
      and "struct wg_transform_attrs attrs = {0};" in body(vp_src, "static HRESULT try_create_wg_transform("),
      "pin: color_convert and video_processor create wg_transforms with default zeroed attrs")

doc = (root / "docs/MEDIA.md").read_text()
cat_gen = (root / "build/tools/gen-config-catalog.py").read_text()
cat = (root / "app/Madeira/ConfigCatalog.generated.swift").read_text()
check("MADEIRA_WG_VIDEO_CONVERT" in doc and "check-wg-video-convert.py" in doc,
      "docs/MEDIA.md documents MADEIRA_WG_VIDEO_CONVERT and check-wg-video-convert.py")
check('"env.MADEIRA_WG_VIDEO_CONVERT"' in cat_gen and '"env.MADEIRA_WG_VIDEO_CONVERT"' in cat,
      "gen-config-catalog.py OVERLAY and ConfigCatalog.generated.swift list env.MADEIRA_WG_VIDEO_CONVERT")

for need in [wine_build / "include/config.h", wine_build / "include/mfobjects.h",
             wine / "dlls/winegstreamer/unixlib.h"]:
    if not need.exists():
        print("SKIP-FAIL: %s missing; set MADEIRA_WINE_BUILD to a configured Wine tree" % need)
        sys.exit(1)

# ------------------------------------------------------------------ 2. shared host FFmpeg
tarball = os.environ.get("MADEIRA_FFMPEG_TARBALL") or str(root / "build/ffmpeg/src/ffmpeg-7.1.5.tar.xz")
FLAGS = MEDIA_FLAGS   # tests/host/host_ffmpeg.py: one cached build for the media checks
prefix = host_ffmpeg(FLAGS, tarball, tag="asf-", override=os.environ.get("MADEIRA_HOST_FFMPEG_ASF"))
inc, lib = prefix / "include", prefix / "lib"

# ------------------------------------------------------------------ 3. C harness (ASan + UBSan)
harness = r"""
#include <sys/mman.h>
#include <math.h>
#include "winegstreamer_unixlib_ios.c"

const struct mav_video_backend mav_apple_video_backend;
const struct mav_audio_backend mav_apple_audio_backend;

static int failures, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { printf( "FAIL %s:%d: ", __func__, __LINE__ ); printf( __VA_ARGS__ ); printf( "\n" ); failures++; return 1; } } while (0)
#define PASS(...) do { printf( "PASS " ); printf( __VA_ARGS__ ); printf( "\n" ); fflush( stdout ); } while (0)
#define FCC(a,b,c,d) ((UINT32)(uint8_t)(a) | ((UINT32)(uint8_t)(b) << 8) | ((UINT32)(uint8_t)(c) << 16) | ((UINT32)(uint8_t)(d) << 24))

static const GUID video_base = { 0, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71 } };

static NTSTATUS call64( enum unix_funcs fn, void *args ) { return __wine_unix_call_funcs[fn]( args ); }
static NTSTATUS call32( enum unix_funcs fn, void *args ) { return __wine_unix_call_wow64_funcs[fn]( args ); }

struct vfmt { MFVIDEOFORMAT f; BYTE extra[64]; };

static struct wg_media_type make_video( struct vfmt *v, UINT32 fourcc, UINT32 w, UINT32 h,
                                        UINT32 fps_n, UINT32 fps_d, BOOL bottom_up )
{
    struct wg_media_type type;

    memset( v, 0, sizeof(*v) );
    v->f.dwSize = sizeof(v->f);
    v->f.guidFormat = video_base;
    v->f.guidFormat.Data1 = fourcc;
    v->f.videoInfo.dwWidth = w;
    v->f.videoInfo.dwHeight = h;
    v->f.videoInfo.FramesPerSecond.Numerator = fps_n;
    v->f.videoInfo.FramesPerSecond.Denominator = fps_d;
    if (bottom_up) v->f.videoInfo.VideoFlags |= MFVideoFlag_BottomUpLinearRep;
    type.major = madeira_MFMediaType_Video;
    type.format_size = v->f.dwSize;
    type.u.video = &v->f;
    return type;
}

static NTSTATUS create_xform( wg_transform_t *out, const struct wg_media_type *in,
                              const struct wg_media_type *ot, const struct wg_transform_attrs *attrs )
{
    struct wg_transform_create_params p = { 0 };
    NTSTATUS st;

    p.input_type = *in;
    p.output_type = *ot;
    if (attrs) p.attrs = *attrs;
    st = call64( unix_wg_transform_create, &p );
    *out = p.transform;
    return st;
}

static void destroy_xform( wg_transform_t h )
{
    if (h && call64( unix_wg_transform_destroy, &h ))
    {
        printf( "FAIL: destroy failed\n" );
        failures++;
    }
}

static HRESULT push_frame( wg_transform_t h, const void *data, UINT32 size, UINT32 max_size,
                           UINT32 stride, INT64 pts, INT64 dur, UINT32 extra_flags )
{
    struct wg_sample s = { 0 };
    struct wg_transform_push_data_params p = { 0 };

    s.data = (UINT_PTR)data;
    s.size = size;
    s.max_size = max_size ? max_size : size;
    s.stride = stride;
    s.flags = WG_SAMPLE_FLAG_SYNC_POINT | extra_flags;
    if (pts != INT64_MIN) { s.flags |= WG_SAMPLE_FLAG_HAS_PTS; s.pts = pts; }
    if (dur != INT64_MIN) { s.flags |= WG_SAMPLE_FLAG_HAS_DURATION; s.duration = dur; }
    p.transform = h;
    p.sample = &s;
    if (call64( unix_wg_transform_push_data, &p )) { failures++; return E_FAIL; }
    return p.result;
}

static NTSTATUS read_frame( wg_transform_t h, struct wg_sample *s, void *buf, UINT32 max_size,
                            UINT32 stride, HRESULT *hr )
{
    struct wg_transform_read_data_params p = { 0 };

    memset( s, 0, sizeof(*s) );
    s->data = (UINT_PTR)buf;
    s->max_size = max_size;
    s->stride = stride;
    s->flags = WG_SAMPLE_FLAG_INCOMPLETE;   /* must be cleared on success */
    p.transform = h;
    p.sample = s;
    p.result = E_FAIL;
    NTSTATUS st = call64( unix_wg_transform_read_data, &p );
    *hr = p.result;
    return st;
}

/* ---- Independent reference oracle (floating-point BT.601 / BT.709 & bilinear) ---- */
enum
{
    F_NV12, F_YV12, F_I420, F_IYUV, F_YUY2, F_UYVY, F_YVYU, F_AYUV,
    F_BGRX, F_BGRA, F_RGBA, F_BGR, F_565, F_555, F_COUNT
};

static const struct { const char *name; UINT32 tag; int bpp; int yuv; int has_alpha; } fmts[F_COUNT] =
{
    { "NV12",   FCC('N','V','1','2'), 1, 1, 0 },
    { "YV12",   FCC('Y','V','1','2'), 1, 1, 0 },
    { "I420",   FCC('I','4','2','0'), 1, 1, 0 },
    { "IYUV",   FCC('I','Y','U','V'), 1, 1, 0 },
    { "YUY2",   FCC('Y','U','Y','2'), 2, 1, 0 },
    { "UYVY",   FCC('U','Y','V','Y'), 2, 1, 0 },
    { "YVYU",   FCC('Y','V','Y','U'), 2, 1, 0 },
    { "AYUV",   FCC('A','Y','U','V'), 4, 1, 1 },
    { "RGB32",  22,                   4, 0, 0 },
    { "ARGB32", 21,                   4, 0, 1 },
    { "ABGR32", 32,                   4, 0, 1 },
    { "RGB24",  20,                   3, 0, 0 },
    { "RGB565", 23,                   2, 0, 0 },
    { "RGB555", 24,                   2, 0, 0 },
};

static int is_420( int f ) { return f <= F_IYUV; }
static int is_422( int f ) { return f >= F_YUY2 && f <= F_YVYU; }
static int is_sub( int f ) { return f <= F_YVYU; }
static UINT32 align_up( UINT32 x, UINT32 mask ) { return (x + mask) & ~mask; }

struct ref_geom
{
    int f, flip;
    UINT32 w, h, aw, ah, ch;
    UINT32 s0, s1;
    size_t off1, off2, size;
    UINT32 rx, ry, rw, rh;
};

static void ref_geom_init( struct ref_geom *g, int f, UINT32 w, UINT32 h, int flip,
                           UINT32 plane_align, UINT32 stride )
{
    memset( g, 0, sizeof(*g) );
    g->f = f; g->flip = flip; g->w = w; g->h = h;
    g->aw = align_up( w, plane_align );
    g->ah = align_up( h, plane_align );
    g->ch = (g->ah + 1) / 2;
    if (f == F_NV12)
        g->s0 = g->s1 = plane_align ? align_up( align_up( g->aw, 3 ), plane_align ) : align_up( w, 1 );
    else if (is_420( f ))
    {
        g->s0 = align_up( align_up( g->aw, 3 ), plane_align );
        g->s1 = align_up( align_up( (g->aw + 1) / 2, 3 ), plane_align );
    }
    else if (f == F_BGR)
        g->s0 = align_up( align_up( g->aw * 3, 3 ), plane_align );
    else if (fmts[f].bpp == 4)
        g->s0 = align_up( g->aw * 4, plane_align );
    else
        g->s0 = align_up( align_up( g->aw * 2, 3 ), plane_align );

    if (stride)
    {
        g->s0 = stride;
        g->s1 = f == F_NV12 ? stride : (is_420( f ) ? stride / 2 : 0);
    }
    if (is_420( f ))
    {
        g->off1 = (size_t)g->s0 * g->ah;
        g->off2 = g->off1 + (size_t)g->s1 * g->ch;
        g->size = f == F_NV12 ? g->off2 : g->off2 + (size_t)g->s1 * g->ch;
    }
    else g->size = (size_t)g->s0 * g->ah;
    g->rw = w; g->rh = h;
}

static uint8_t ref_clip8( double v )
{
    int iv = (int)llround( v );
    return iv < 0 ? 0 : iv > 255 ? 255 : (uint8_t)iv;
}

static void ref_yuv_to_rgb( double Y, double U, double V, int bt709, uint8_t *R, uint8_t *G, uint8_t *B )
{
    double kr = bt709 ? 0.2126 : 0.299, kb = bt709 ? 0.0722 : 0.114, kg = 1.0 - kr - kb;
    double y = (Y - 16.0) * (255.0 / 219.0);
    double u = (U - 128.0) * (255.0 / 224.0);
    double v = (V - 128.0) * (255.0 / 224.0);

    *R = ref_clip8( y + 2.0 * (1.0 - kr) * v );
    *G = ref_clip8( y - 2.0 * (1.0 - kb) * kb / kg * u - 2.0 * (1.0 - kr) * kr / kg * v );
    *B = ref_clip8( y + 2.0 * (1.0 - kb) * u );
}

static void ref_rgb_to_yuv( double R, double G, double B, int bt709, uint8_t *Y, uint8_t *U, uint8_t *V )
{
    double kr = bt709 ? 0.2126 : 0.299, kb = bt709 ? 0.0722 : 0.114, kg = 1.0 - kr - kb;
    double ey = kr * R + kg * G + kb * B;
    double eu = 0.5 * (B - ey) / (1.0 - kb);
    double ev = 0.5 * (R - ey) / (1.0 - kr);

    *Y = ref_clip8( 16.0 + ey * (219.0 / 255.0) );
    *U = ref_clip8( 128.0 + eu * (224.0 / 255.0) );
    *V = ref_clip8( 128.0 + ev * (224.0 / 225.0 * (225.0 / 255.0)) );
}

/* Synthesises a deterministic test image in buffer `buf` (pre-filled with 0xCD)
 * in format `g->f`, with valid video-range YUV or full-range RGB values. */
static void fill_pattern( const struct ref_geom *g, int seed, uint8_t *buf )
{
    UINT32 x, y, cx, cy;

    for (y = 0; y < g->h; y++)
    {
        UINT32 brow = g->flip ? g->ah - 1 - y : y;
        uint8_t *row = buf + (size_t)g->s0 * brow;

        for (x = 0; x < g->w; x++)
        {
            uint8_t Y = (uint8_t)(16 + ((x * 13 + y * 19 + seed * 29) % 220));
            uint8_t R = (uint8_t)((x * 23 + y * 31 + seed * 17) % 256);
            uint8_t G = (uint8_t)((50 + x * 11 + y * 43 + seed * 13) % 256);
            uint8_t B = (uint8_t)((200 - (x * 7 + y * 17 + seed * 5) % 190));
            uint8_t A = (uint8_t)(37 + ((x * 41 + y * 29 + seed * 7) % 219));

            if (is_420( g->f )) row[x] = Y;
            else if (is_422( g->f ))
            {
                if (!(x & 1))
                {
                    uint8_t Y1 = x + 1 < g->w ? (uint8_t)(16 + (((x + 1) * 13 + y * 19 + seed * 29) % 220)) : Y;
                    uint8_t U = (uint8_t)(24 + (((x / 2) * 23 + y * 11 + seed * 19) % 208));
                    uint8_t V = (uint8_t)(232 - (((x / 2) * 17 + y * 13 + seed * 23) % 208));
                    uint8_t *p = row + (size_t)x * 2;
                    if (g->f == F_YUY2)      { p[0] = Y; p[1] = U; p[2] = Y1; p[3] = V; }
                    else if (g->f == F_UYVY) { p[0] = U; p[1] = Y; p[2] = V;  p[3] = Y1; }
                    else                     { p[0] = Y; p[1] = V; p[2] = Y1; p[3] = U; }
                }
            }
            else if (g->f == F_AYUV)
            {
                uint8_t U = (uint8_t)(24 + ((x * 17 + y * 11 + seed * 19) % 208));
                uint8_t V = (uint8_t)(232 - ((x * 13 + y * 23 + seed * 7) % 208));
                row[4 * x + 0] = V; row[4 * x + 1] = U; row[4 * x + 2] = Y; row[4 * x + 3] = A;
            }
            else if (g->f == F_BGRX)
                { row[4 * x + 0] = B; row[4 * x + 1] = G; row[4 * x + 2] = R; row[4 * x + 3] = (uint8_t)(x * 9 + y); /* junk X */ }
            else if (g->f == F_BGRA)
                { row[4 * x + 0] = B; row[4 * x + 1] = G; row[4 * x + 2] = R; row[4 * x + 3] = A; }
            else if (g->f == F_RGBA)
                { row[4 * x + 0] = R; row[4 * x + 1] = G; row[4 * x + 2] = B; row[4 * x + 3] = A; }
            else if (g->f == F_BGR)
                { row[3 * x + 0] = B; row[3 * x + 1] = G; row[3 * x + 2] = R; }
            else if (g->f == F_565)
            {
                uint16_t px = (uint16_t)(((R >> 3) << 11) | ((G >> 2) << 5) | (B >> 3));
                row[2 * x + 0] = (uint8_t)px; row[2 * x + 1] = (uint8_t)(px >> 8);
            }
            else if (g->f == F_555)
            {
                uint16_t px = (uint16_t)(((R >> 3) << 10) | ((G >> 3) << 5) | (B >> 3));
                row[2 * x + 0] = (uint8_t)px; row[2 * x + 1] = (uint8_t)(px >> 8);
            }
        }
    }
    if (is_420( g->f ))
    {
        for (cy = 0; cy < (g->h + 1) / 2; cy++)
        {
            UINT32 bcrow = g->flip ? g->ch - 1 - cy : cy;
            for (cx = 0; cx < (g->w + 1) / 2; cx++)
            {
                uint8_t U = (uint8_t)(24 + ((cx * 23 + cy * 19 + seed * 11) % 208));
                uint8_t V = (uint8_t)(232 - ((cx * 17 + cy * 29 + seed * 7) % 208));
                if (g->f == F_NV12)
                {
                    buf[g->off1 + (size_t)g->s1 * bcrow + 2 * cx + 0] = U;
                    buf[g->off1 + (size_t)g->s1 * bcrow + 2 * cx + 1] = V;
                }
                else
                {
                    size_t uoff = (g->f == F_YV12 ? g->off2 : g->off1) + (size_t)g->s1 * bcrow + cx;
                    size_t voff = (g->f == F_YV12 ? g->off1 : g->off2) + (size_t)g->s1 * bcrow + cx;
                    buf[uoff] = U;
                    buf[voff] = V;
                }
            }
        }
    }
}

/* Reads display pixel (fx, fy) from buffer `buf` into 4-channel [c0,c1,c2,A]:
 * [Y,U,V,A] for YUV formats, [R,G,B,A] for RGB formats. */
static void ref_read_pixel( const uint8_t *buf, const struct ref_geom *g, UINT32 fx, UINT32 fy, uint8_t out[4] )
{
    UINT32 brow = g->flip ? g->ah - 1 - fy : fy;
    const uint8_t *row = buf + (size_t)g->s0 * brow;

    if (is_420( g->f ))
    {
        UINT32 bcrow = g->flip ? g->ch - 1 - (fy / 2) : (fy / 2), cx = fx / 2;
        out[0] = row[fx];
        if (g->f == F_NV12)
        {
            out[1] = buf[g->off1 + (size_t)g->s1 * bcrow + 2 * cx + 0];
            out[2] = buf[g->off1 + (size_t)g->s1 * bcrow + 2 * cx + 1];
        }
        else
        {
            out[1] = buf[(g->f == F_YV12 ? g->off2 : g->off1) + (size_t)g->s1 * bcrow + cx];
            out[2] = buf[(g->f == F_YV12 ? g->off1 : g->off2) + (size_t)g->s1 * bcrow + cx];
        }
        out[3] = 255;
    }
    else if (is_422( g->f ))
    {
        const uint8_t *p = row + (size_t)(fx & ~1u) * 2;
        if (g->f == F_YUY2)      { out[0] = p[(fx & 1) ? 2 : 0]; out[1] = p[1]; out[2] = p[3]; }
        else if (g->f == F_UYVY) { out[0] = p[(fx & 1) ? 3 : 1]; out[1] = p[0]; out[2] = p[2]; }
        else                     { out[0] = p[(fx & 1) ? 2 : 0]; out[1] = p[3]; out[2] = p[1]; }
        out[3] = 255;
    }
    else if (g->f == F_AYUV)
        { out[0] = row[4 * fx + 2]; out[1] = row[4 * fx + 1]; out[2] = row[4 * fx + 0]; out[3] = row[4 * fx + 3]; }
    else if (g->f == F_BGRX)
        { out[0] = row[4 * fx + 2]; out[1] = row[4 * fx + 1]; out[2] = row[4 * fx + 0]; out[3] = 255; }
    else if (g->f == F_BGRA)
        { out[0] = row[4 * fx + 2]; out[1] = row[4 * fx + 1]; out[2] = row[4 * fx + 0]; out[3] = row[4 * fx + 3]; }
    else if (g->f == F_RGBA)
        { out[0] = row[4 * fx + 0]; out[1] = row[4 * fx + 1]; out[2] = row[4 * fx + 2]; out[3] = row[4 * fx + 3]; }
    else if (g->f == F_BGR)
        { out[0] = row[3 * fx + 2]; out[1] = row[3 * fx + 1]; out[2] = row[3 * fx + 0]; out[3] = 255; }
    else if (g->f == F_565)
    {
        UINT32 px = row[2 * fx + 0] | ((UINT32)row[2 * fx + 1] << 8);
        UINT32 r5 = (px >> 11) & 31u, g6 = (px >> 5) & 63u, b5 = px & 31u;
        out[0] = (uint8_t)((r5 << 3) | (r5 >> 2));
        out[1] = (uint8_t)((g6 << 2) | (g6 >> 4));
        out[2] = (uint8_t)((b5 << 3) | (b5 >> 2));
        out[3] = 255;
    }
    else if (g->f == F_555)
    {
        UINT32 px = row[2 * fx + 0] | ((UINT32)row[2 * fx + 1] << 8);
        UINT32 r5 = (px >> 10) & 31u, g5 = (px >> 5) & 31u, b5 = px & 31u;
        out[0] = (uint8_t)((r5 << 3) | (r5 >> 2));
        out[1] = (uint8_t)((g5 << 3) | (g5 >> 2));
        out[2] = (uint8_t)((b5 << 3) | (b5 >> 2));
        out[3] = 255;
    }
}

/* Independent floating-point bilinear + colour-space reference: computes the
 * expected output buffer bytes in `ref_out` (leaving bytes outside gout's
 * active region untouched as `sentinel`). */
static void ref_convert( const uint8_t *in_buf, const struct ref_geom *gin,
                         uint8_t *ref_out, const struct ref_geom *gout, int bt709 )
{
    uint8_t *inter = calloc( (size_t)gout->rw * gout->rh, 4 );
    UINT32 ox, oy, cx, cy;
    int c;

    for (oy = 0; oy < gout->rh; oy++)
    {
        double sy = gin->rh <= 1 ? 0.0 : ((oy + 0.5) * gin->rh / (double)gout->rh) - 0.5;
        if (sy < 0.0) sy = 0.0;
        if (sy > (double)(gin->rh - 1)) sy = (double)(gin->rh - 1);
        UINT32 y0 = (UINT32)floor( sy ), y1 = y0 + 1 < gin->rh ? y0 + 1 : y0;
        double wy = sy - y0;

        for (ox = 0; ox < gout->rw; ox++)
        {
            double sx = gin->rw <= 1 ? 0.0 : ((ox + 0.5) * gin->rw / (double)gout->rw) - 0.5;
            if (sx < 0.0) sx = 0.0;
            if (sx > (double)(gin->rw - 1)) sx = (double)(gin->rw - 1);
            UINT32 x0 = (UINT32)floor( sx ), x1 = x0 + 1 < gin->rw ? x0 + 1 : x0;
            double wx = sx - x0;

            uint8_t p00[4], p10[4], p01[4], p11[4], px[4];
            ref_read_pixel( in_buf, gin, gin->rx + x0, gin->ry + y0, p00 );
            ref_read_pixel( in_buf, gin, gin->rx + x1, gin->ry + y0, p10 );
            ref_read_pixel( in_buf, gin, gin->rx + x0, gin->ry + y1, p01 );
            ref_read_pixel( in_buf, gin, gin->rx + x1, gin->ry + y1, p11 );
            for (c = 0; c < 4; c++)
            {
                double v = (1.0 - wx) * (1.0 - wy) * p00[c] + wx * (1.0 - wy) * p10[c]
                         + (1.0 - wx) * wy * p01[c] + wx * wy * p11[c];
                px[c] = ref_clip8( v );
            }
            if (fmts[gin->f].yuv && !fmts[gout->f].yuv)
                ref_yuv_to_rgb( px[0], px[1], px[2], bt709, &px[0], &px[1], &px[2] );
            else if (!fmts[gin->f].yuv && fmts[gout->f].yuv)
                ref_rgb_to_yuv( px[0], px[1], px[2], bt709, &px[0], &px[1], &px[2] );

            memcpy( inter + ((size_t)oy * gout->rw + ox) * 4, px, 4 );
        }
    }

    if (is_420( gout->f ))
    {
        for (oy = 0; oy < gout->rh; oy++)
        {
            UINT32 brow = gout->flip ? gout->ah - 1 - (gout->ry + oy) : (gout->ry + oy);
            uint8_t *yrow = ref_out + (size_t)gout->s0 * brow + gout->rx;
            for (ox = 0; ox < gout->rw; ox++)
                yrow[ox] = inter[((size_t)oy * gout->rw + ox) * 4 + 0];
        }
        for (cy = 0; cy < (gout->rh + 1) / 2; cy++)
        {
            UINT32 y0 = 2 * cy, y1 = y0 + 1 < gout->rh ? y0 + 1 : y0;
            UINT32 bcrow = gout->flip ? gout->ch - 1 - (gout->ry / 2 + cy) : (gout->ry / 2 + cy);
            for (cx = 0; cx < (gout->rw + 1) / 2; cx++)
            {
                UINT32 x0 = 2 * cx, x1 = x0 + 1 < gout->rw ? x0 + 1 : x0;
                const uint8_t *q00 = inter + ((size_t)y0 * gout->rw + x0) * 4;
                const uint8_t *q10 = inter + ((size_t)y0 * gout->rw + x1) * 4;
                const uint8_t *q01 = inter + ((size_t)y1 * gout->rw + x0) * 4;
                const uint8_t *q11 = inter + ((size_t)y1 * gout->rw + x1) * 4;
                uint8_t U = (uint8_t)((q00[1] + q10[1] + q01[1] + q11[1] + 2) / 4);
                uint8_t V = (uint8_t)((q00[2] + q10[2] + q01[2] + q11[2] + 2) / 4);
                if (gout->f == F_NV12)
                {
                    ref_out[gout->off1 + (size_t)gout->s1 * bcrow + gout->rx + 2 * cx + 0] = U;
                    ref_out[gout->off1 + (size_t)gout->s1 * bcrow + gout->rx + 2 * cx + 1] = V;
                }
                else
                {
                    ref_out[(gout->f == F_YV12 ? gout->off2 : gout->off1) + (size_t)gout->s1 * bcrow + gout->rx / 2 + cx] = U;
                    ref_out[(gout->f == F_YV12 ? gout->off1 : gout->off2) + (size_t)gout->s1 * bcrow + gout->rx / 2 + cx] = V;
                }
            }
        }
    }
    else
    {
        for (oy = 0; oy < gout->rh; oy++)
        {
            UINT32 brow = gout->flip ? gout->ah - 1 - (gout->ry + oy) : (gout->ry + oy);
            uint8_t *o = ref_out + (size_t)gout->s0 * brow + (size_t)gout->rx * fmts[gout->f].bpp;
            const uint8_t *r = inter + (size_t)oy * gout->rw * 4;

            if (is_422( gout->f ))
            {
                for (ox = 0; ox < gout->rw; ox += 2)
                {
                    UINT32 x1 = ox + 1 < gout->rw ? ox + 1 : ox;
                    uint8_t Y0 = r[4 * ox + 0], Y1 = r[4 * x1 + 0];
                    uint8_t U = (uint8_t)((r[4 * ox + 1] + r[4 * x1 + 1] + 1) / 2);
                    uint8_t V = (uint8_t)((r[4 * ox + 2] + r[4 * x1 + 2] + 1) / 2);
                    if (gout->f == F_YUY2)      { o[2 * ox + 0] = Y0; o[2 * ox + 1] = U;  o[2 * ox + 2] = Y1; o[2 * ox + 3] = V; }
                    else if (gout->f == F_UYVY) { o[2 * ox + 0] = U;  o[2 * ox + 1] = Y0; o[2 * ox + 2] = V;  o[2 * ox + 3] = Y1; }
                    else                        { o[2 * ox + 0] = Y0; o[2 * ox + 1] = V;  o[2 * ox + 2] = Y1; o[2 * ox + 3] = U; }
                }
            }
            else if (gout->f == F_AYUV)
                for (ox = 0; ox < gout->rw; ox++)
                    { o[4 * ox + 0] = r[4 * ox + 2]; o[4 * ox + 1] = r[4 * ox + 1]; o[4 * ox + 2] = r[4 * ox + 0]; o[4 * ox + 3] = r[4 * ox + 3]; }
            else if (gout->f == F_BGRX || gout->f == F_BGRA)
                for (ox = 0; ox < gout->rw; ox++)
                    { o[4 * ox + 0] = r[4 * ox + 2]; o[4 * ox + 1] = r[4 * ox + 1]; o[4 * ox + 2] = r[4 * ox + 0]; o[4 * ox + 3] = gout->f == F_BGRA ? r[4 * ox + 3] : 255; }
            else if (gout->f == F_RGBA)
                memcpy( o, r, (size_t)gout->rw * 4 );
            else if (gout->f == F_BGR)
                for (ox = 0; ox < gout->rw; ox++)
                    { o[3 * ox + 0] = r[4 * ox + 2]; o[3 * ox + 1] = r[4 * ox + 1]; o[3 * ox + 2] = r[4 * ox + 0]; }
            else if (gout->f == F_565 || gout->f == F_555)
                for (ox = 0; ox < gout->rw; ox++)
                {
                    UINT32 R = r[4 * ox + 0], G = r[4 * ox + 1], B = r[4 * ox + 2];
                    UINT32 px = gout->f == F_565 ? (((R >> 3) << 11) | ((G >> 2) << 5) | (B >> 3))
                                                 : (((R >> 3) << 10) | ((G >> 3) << 5) | (B >> 3));
                    o[2 * ox + 0] = (uint8_t)px; o[2 * ox + 1] = (uint8_t)(px >> 8);
                }
        }
    }
    free( inter );
}

/* Compares `got` against `exp` across the whole buffer + `guard` bytes:
 * untouched bytes (where mask == 0) must be exact (0xCD); active pixels must
 * match within `tol` per channel (for RGB565/RGB555 packed 16-bit pixels,
 * compares unpacked 5/6-bit fields within `tol16`). */
static int compare_buffers( const char *ctx, const struct ref_geom *gout, const uint8_t *got,
                            const uint8_t *exp, const uint8_t *mask, size_t guard, int tol )
{
    size_t total = gout->size + guard, i;

    for (i = 0; i < total; i++)
    {
        if (!mask[i])
        {
            if (got[i] != exp[i])
            {
                printf( "FAIL %s: untouched byte at +%zu modified: got %#x, expected %#x\n",
                        ctx, i, got[i], exp[i] );
                failures++;
                return 1;
            }
        }
        else if (gout->f != F_565 && gout->f != F_555)
        {
            int d = abs( (int)got[i] - (int)exp[i] );
            if (d > tol)
            {
                printf( "FAIL %s: byte at +%zu differs by %d > %d (got %u, expected %u)\n",
                        ctx, i, d, tol, got[i], exp[i] );
                failures++;
                return 1;
            }
        }
    }
    if (gout->f == F_565 || gout->f == F_555)
    {
        UINT32 x, y;
        int tol_c = (tol + 7) / 8 + (tol > 0 ? 1 : 0);
        if (tol == 0) tol_c = 0;
        for (y = 0; y < gout->rh; y++)
        {
            UINT32 brow = gout->flip ? gout->ah - 1 - (gout->ry + y) : (gout->ry + y);
            const uint8_t *gr = got + (size_t)gout->s0 * brow + (size_t)gout->rx * 2;
            const uint8_t *er = exp + (size_t)gout->s0 * brow + (size_t)gout->rx * 2;
            for (x = 0; x < gout->rw; x++)
            {
                UINT32 gp = gr[2 * x] | ((UINT32)gr[2 * x + 1] << 8);
                UINT32 ep = er[2 * x] | ((UINT32)er[2 * x + 1] << 8);
                int gr5 = gout->f == F_565 ? (int)((gp >> 11) & 31) : (int)((gp >> 10) & 31);
                int er5 = gout->f == F_565 ? (int)((ep >> 11) & 31) : (int)((ep >> 10) & 31);
                int gg  = gout->f == F_565 ? (int)((gp >> 5) & 63)  : (int)((gp >> 5) & 31);
                int eg  = gout->f == F_565 ? (int)((ep >> 5) & 63)  : (int)((ep >> 5) & 31);
                int gb5 = (int)(gp & 31), eb5 = (int)(ep & 31);
                int top_bad = gout->f == F_555 && (gp & 0x8000u);
                if (top_bad || abs( gr5 - er5 ) > tol_c || abs( gg - eg ) > (gout->f == F_565 && tol ? tol_c + 1 : tol_c)
                    || abs( gb5 - eb5 ) > tol_c)
                {
                    printf( "FAIL %s: %s pixel (%u,%u) got %#06x, expected %#06x (tol_c=%d)\n",
                            ctx, fmts[gout->f].name, x, y, gp, ep, tol_c );
                    failures++;
                    return 1;
                }
            }
        }
    }
    checks++;
    return 0;
}

static void mark_active_mask( const struct ref_geom *g, uint8_t *mask )
{
    UINT32 oy, cy, bytes_w;

    if (is_420( g->f ))
    {
        for (oy = 0; oy < g->rh; oy++)
        {
            UINT32 brow = g->flip ? g->ah - 1 - (g->ry + oy) : (g->ry + oy);
            memset( mask + (size_t)g->s0 * brow + g->rx, 1, g->rw );
        }
        for (cy = 0; cy < (g->rh + 1) / 2; cy++)
        {
            UINT32 bcrow = g->flip ? g->ch - 1 - (g->ry / 2 + cy) : (g->ry / 2 + cy);
            UINT32 ccw = (g->rw + 1) / 2;
            if (g->f == F_NV12)
                memset( mask + g->off1 + (size_t)g->s1 * bcrow + g->rx, 1, ccw * 2 );
            else
            {
                memset( mask + g->off1 + (size_t)g->s1 * bcrow + g->rx / 2, 1, ccw );
                memset( mask + g->off2 + (size_t)g->s1 * bcrow + g->rx / 2, 1, ccw );
            }
        }
    }
    else
    {
        bytes_w = is_422( g->f ) ? ((g->rw + 1) / 2) * 4 : g->rw * fmts[g->f].bpp;
        for (oy = 0; oy < g->rh; oy++)
        {
            UINT32 brow = g->flip ? g->ah - 1 - (g->ry + oy) : (g->ry + oy);
            memset( mask + (size_t)g->s0 * brow + (size_t)g->rx * fmts[g->f].bpp, 1, bytes_w );
        }
    }
}

/* 1. Wine's color_convert_create() and video_processor_create() probes:
 *    I420 1920x1080 -> NV12 1920x1080 with zeroed attrs, plus a full 1080p frame. */
static int test_wine_probes(void)
{
    struct vfmt vi, vo;
    struct wg_media_type in = make_video( &vi, FCC('I','4','2','0'), 1920, 1080, 0, 0, FALSE );
    struct wg_media_type out = make_video( &vo, FCC('N','V','1','2'), 1920, 1080, 0, 0, FALSE );
    struct wg_transform_attrs zero_attrs = { 0 };
    struct ref_geom gin, gout;
    struct wg_sample smp;
    wg_transform_t h = 0;
    uint8_t *in_buf, *out_buf;
    HRESULT hr;
    UINT32 x, y;

    CHECK( !create_xform( &h, &in, &out, &zero_attrs ) && h, "probe I420 1920x1080 -> NV12 1920x1080" );
    CHECK( get_vconv_transform( h ) && !get_wmv_transform( h ), "probe claimed by vconv_transform_ops" );

    ref_geom_init( &gin, F_I420, 1920, 1080, 0, 0, 0 );
    ref_geom_init( &gout, F_NV12, 1920, 1080, 0, 0, 0 );
    in_buf = malloc( gin.size );
    out_buf = malloc( gout.size );
    for (y = 0; y < 1080; y++)
        for (x = 0; x < 1920; x++)
            in_buf[y * 1920 + x] = (uint8_t)(16 + (x + y) % 220);
    for (y = 0; y < 540; y++)
        for (x = 0; x < 960; x++)
        {
            in_buf[gin.off1 + y * 960 + x] = (uint8_t)(30 + (x + y) % 190);
            in_buf[gin.off2 + y * 960 + x] = (uint8_t)(210 - (x + y) % 180);
        }
    CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, 1234567, 333333, 0 ) == S_OK, "1080p push" );
    CHECK( !read_frame( h, &smp, out_buf, gout.size, 0, &hr ) && hr == S_OK && smp.size == gout.size, "1080p read" );
    CHECK( !memcmp( in_buf, out_buf, 1920 * 1080 ), "1080p luma exact" );
    for (x = 0; x < 960 * 540; x++)
        if (out_buf[gout.off1 + 2 * x] != in_buf[gin.off1 + x]
            || out_buf[gout.off1 + 2 * x + 1] != in_buf[gin.off2 + x])
            CHECK( 0, "1080p chroma mismatch at %u", x );

    free( in_buf );
    free( out_buf );
    destroy_xform( h );
    PASS( "Wine's color_convert_create & video_processor_create probe (I420 1920x1080 -> NV12 1920x1080, attrs={0}) "
          "succeeds and converts 1080p bit-exact" );
    return 0;
}

/* 2. Exhaustive 14 x 14 = 196 format pairs x 4 orientation combinations = 784 runs at 16x12,
 *    plus BT.709 matrix verification. */
static int test_all_pairs(void)
{
    const UINT32 W = 16, H = 12;
    const size_t GUARD = 64;
    uint8_t in_buf[4096], got_buf[4096], exp_buf[4096], mask[4096];
    int fi, fo, flip_in, flip_out, count = 0;

    for (fi = 0; fi < F_COUNT; fi++)
    {
        for (fo = 0; fo < F_COUNT; fo++)
        {
            for (flip_in = 0; flip_in <= 1; flip_in++)
            {
                for (flip_out = 0; flip_out <= 1; flip_out++)
                {
                    struct vfmt vi, vo;
                    struct wg_media_type in = make_video( &vi, fmts[fi].tag, W, H, 30, 1, flip_in );
                    struct wg_media_type out = make_video( &vo, fmts[fo].tag, W, H, 30, 1, flip_out );
                    struct wg_transform_attrs attrs = { 0 };
                    struct ref_geom gin, gout;
                    struct wg_sample smp;
                    wg_transform_t h = 0;
                    HRESULT hr;
                    char ctx[128];
                    int tol;

                    /* Exact (tol = 0) when no YUV<->RGB matrix or chroma averaging happens:
                     * e.g. NV12<->I420<->IYUV<->YV12, YUY2<->UYVY<->YVYU, AYUV->AYUV,
                     * RGB32<->ARGB32<->ABGR32<->RGB24, RGB565->RGB565, RGB555->RGB555.
                     * Fixed-point YUV<->RGB is within <= 2 LSB of double-precision BT.601. */
                    if (fmts[fi].yuv == fmts[fo].yuv)
                        tol = (is_420( fi ) && is_420( fo )) || (is_422( fi ) && is_422( fo )) || fi == fo
                              || (!fmts[fi].yuv && fi <= F_BGR && fo <= F_BGR) ? 0 : 1;
                    else
                        tol = 2;

                    snprintf( ctx, sizeof(ctx), "%s(%s)->%s(%s)", fmts[fi].name, flip_in ? "bu" : "td",
                              fmts[fo].name, flip_out ? "bu" : "td" );
                    ref_geom_init( &gin, fi, W, H, flip_in, 0, 0 );
                    ref_geom_init( &gout, fo, W, H, flip_out, 0, 0 );

                    memset( in_buf, 0xcd, gin.size + GUARD );
                    fill_pattern( &gin, fi * 17 + fo, in_buf );
                    memset( got_buf, 0xcd, gout.size + GUARD );
                    memset( exp_buf, 0xcd, gout.size + GUARD );
                    memset( mask, 0, gout.size + GUARD );
                    mark_active_mask( &gout, mask );
                    ref_convert( in_buf, &gin, exp_buf, &gout, 0 );

                    CHECK( !create_xform( &h, &in, &out, &attrs ) && h, "%s: create", ctx );
                    CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, 1000, 333333, 0 ) == S_OK, "%s: push", ctx );
                    CHECK( !read_frame( h, &smp, got_buf, gout.size, 0, &hr ) && hr == S_OK && smp.size == gout.size,
                           "%s: read", ctx );
                    CHECK( !(smp.flags & WG_SAMPLE_FLAG_INCOMPLETE), "%s: INCOMPLETE set", ctx );
                    destroy_xform( h );

                    if (compare_buffers( ctx, &gout, got_buf, exp_buf, mask, GUARD, tol )) return 1;
                    count++;
                }
            }
        }
    }

    /* Explicit BT.709 matrix check (YUV -> RGB and RGB -> YUV): matches BT.709 within 2 LSB
     * and differs noticeably from BT.601 on saturated colours. */
    for (int dir = 0; dir < 2; dir++)
    {
        struct vfmt vi, vo;
        int fi = dir == 0 ? F_NV12 : F_BGRX, fo = dir == 0 ? F_BGRX : F_NV12;
        struct wg_media_type in = make_video( &vi, fmts[fi].tag, W, H, 30, 1, FALSE );
        struct wg_media_type out = make_video( &vo, fmts[fo].tag, W, H, 30, 1, FALSE );
        struct ref_geom gin, gout;
        struct wg_sample smp;
        wg_transform_t h = 0;
        HRESULT hr;
        uint8_t exp601[4096];
        int max_diff_601 = 0;

        vi.f.videoInfo.TransferMatrix = MFVideoTransferMatrix_BT709;
        ref_geom_init( &gin, fi, W, H, 0, 0, 0 );
        ref_geom_init( &gout, fo, W, H, 0, 0, 0 );
        fill_pattern( &gin, 99, in_buf );
        memset( got_buf, 0xcd, gout.size + GUARD );
        memset( exp_buf, 0xcd, gout.size + GUARD );
        memset( exp601, 0xcd, gout.size + GUARD );
        memset( mask, 0, gout.size + GUARD );
        mark_active_mask( &gout, mask );
        ref_convert( in_buf, &gin, exp_buf, &gout, 1 );
        ref_convert( in_buf, &gin, exp601, &gout, 0 );

        CHECK( !create_xform( &h, &in, &out, NULL ) && h, "BT.709 create" );
        CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, 0, 0, 0 ) == S_OK, "BT.709 push" );
        CHECK( !read_frame( h, &smp, got_buf, gout.size, 0, &hr ) && hr == S_OK, "BT.709 read" );
        destroy_xform( h );

        if (compare_buffers( "BT.709", &gout, got_buf, exp_buf, mask, GUARD, 2 )) return 1;
        for (size_t i = 0; i < gout.size; i++)
            if (mask[i] && abs( (int)got_buf[i] - (int)exp601[i] ) > max_diff_601)
                max_diff_601 = abs( (int)got_buf[i] - (int)exp601[i] );
        CHECK( max_diff_601 >= 8, "BT.709 matrix took effect (max diff vs BT.601 = %d)", max_diff_601 );
    }

    PASS( "all %d input x output x orientation conversions (14 formats, 196 pairs x 4 orientations) + BT.709 match "
          "independent reference; lossless pairs and alpha are bit-exact; guard bytes untouched", count );
    return 0;
}

/* 3. 2D buffer sample->stride (on input and output, including IMF2DBuffer2's size < max_size),
 *    output_plane_align, too-short stride fallback, and input/output MinimumDisplayAperture. */
static int test_strides_and_apertures(void)
{
    const size_t GUARD = 64;
    static const int test_fmts[] = { F_NV12, F_YV12, F_I420, F_YUY2, F_UYVY, F_AYUV, F_BGRX, F_BGRA, F_BGR, F_565 };
    uint8_t *in_buf = malloc( 256 * 1024 ), *got_buf = malloc( 256 * 1024 );
    uint8_t *exp_buf = malloc( 256 * 1024 ), *mask = malloc( 256 * 1024 );
    unsigned int i, j;

    /* 2D pitched input AND 2D pitched output across formats and orientations */
    for (i = 0; i < ARRAY_SIZE(test_fmts); i++)
    {
        for (j = 0; j < ARRAY_SIZE(test_fmts); j++)
        {
            int fi = test_fmts[i], fo = test_fmts[j];
            int flip_in = (i & 1), flip_out = (j & 1);
            UINT32 W = 22, H = 14;   /* non-multiple of 4/8/16 width */
            UINT32 in_stride = align_up( W * fmts[fi].bpp + 36, 63 );
            UINT32 out_stride = align_up( W * fmts[fo].bpp + 52, 127 );
            struct vfmt vi, vo;
            struct wg_media_type in = make_video( &vi, fmts[fi].tag, W, H, 25, 1, flip_in );
            struct wg_media_type out = make_video( &vo, fmts[fo].tag, W, H, 25, 1, flip_out );
            struct ref_geom gin, gin_contig, gout;
            struct wg_sample smp;
            wg_transform_t h = 0;
            HRESULT hr;

            ref_geom_init( &gin, fi, W, H, flip_in, 0, in_stride );
            ref_geom_init( &gin_contig, fi, W, H, flip_in, 0, 0 );
            ref_geom_init( &gout, fo, W, H, flip_out, 0, out_stride );
            memset( in_buf, 0xcd, gin.size + GUARD );
            fill_pattern( &gin, (int)(i * 11 + j), in_buf );
            memset( got_buf, 0xcd, gout.size + GUARD );
            memset( exp_buf, 0xcd, gout.size + GUARD );
            memset( mask, 0, gout.size + GUARD );
            mark_active_mask( &gout, mask );
            ref_convert( in_buf, &gin, exp_buf, &gout, 0 );

            CHECK( !create_xform( &h, &in, &out, NULL ) && h, "2D create" );
            /* Pass sample->size = contiguous size (< gin.size) and sample->max_size = gin.size,
             * exactly as wg_sample_create_mf does for IMF2DBuffer2! */
            CHECK( push_frame( h, in_buf, gin_contig.size, gin.size, in_stride, 0, 400000, 0 ) == S_OK, "2D push" );
            CHECK( !read_frame( h, &smp, got_buf, gout.size, out_stride, &hr ) && hr == S_OK && smp.size == gout.size,
                   "2D read" );
            destroy_xform( h );
            if (compare_buffers( "2D stride", &gout, got_buf, exp_buf, mask, GUARD, 2 )) goto fail;
        }
    }

    /* output_plane_align = 15 (16-byte alignment) & too-short stride fallback */
    {
        struct vfmt vi, vo;
        struct wg_media_type in = make_video( &vi, FCC('I','4','2','0'), 18, 10, 30, 1, FALSE );
        struct wg_media_type out = make_video( &vo, 22, 18, 10, 30, 1, TRUE );
        struct wg_transform_attrs attrs = { 0 };
        struct ref_geom gin, gout;
        struct wg_sample smp;
        wg_transform_t h = 0;
        HRESULT hr;

        attrs.output_plane_align = 15;
        ref_geom_init( &gin, F_I420, 18, 10, 0, 0, 0 );
        ref_geom_init( &gout, F_BGRX, 18, 10, 1, 15, 0 );
        memset( in_buf, 0xcd, gin.size + GUARD );
        fill_pattern( &gin, 7, in_buf );
        memset( got_buf, 0xcd, gout.size + GUARD );
        memset( exp_buf, 0xcd, gout.size + GUARD );
        memset( mask, 0, gout.size + GUARD );
        mark_active_mask( &gout, mask );
        ref_convert( in_buf, &gin, exp_buf, &gout, 0 );

        CHECK( !create_xform( &h, &in, &out, &attrs ) && h, "plane_align create" );
        /* Stride 8 is too short for 18 pixels of RGB32 (72 bytes) -> falls back to aligned default */
        CHECK( push_frame( h, in_buf, gin.size, gin.size, 4, 0, 0, 0 ) == S_OK, "short stride push" );
        CHECK( !read_frame( h, &smp, got_buf, gout.size, 8, &hr ) && hr == S_OK && smp.size == gout.size,
               "plane_align read" );
        destroy_xform( h );
        if (compare_buffers( "plane_align", &gout, got_buf, exp_buf, mask, GUARD, 2 )) goto fail;
    }

    /* Apertures:
     * (a) Wine's video_processor Test 15: 96x96 NV12 with 82x84 aperture -> 82x84 RGB32 bottom-up
     * (b) Non-zero OffsetX/OffsetY on both input (64x48, aperture (8,6)-(40x28)) and output
     *     (72x56, aperture (12,10)-(40x28)), surrounding output bytes untouched (0xCD)! */
    for (int pass = 0; pass < 4; pass++)
    {
        int fi = pass == 0 ? F_NV12 : pass == 1 ? F_YUY2 : pass == 2 ? F_BGRX : F_AYUV;
        int fo = pass == 0 ? F_BGRX : pass == 1 ? F_YV12 : pass == 2 ? F_NV12 : F_BGRA;
        int flip_in = (pass >= 2), flip_out = (pass != 1);
        UINT32 iw = pass == 0 ? 96 : 64, ih = pass == 0 ? 96 : 48;
        UINT32 ow = pass == 0 ? 82 : 72, oh = pass == 0 ? 84 : 56;
        UINT32 irx = pass == 0 ? 0 : 8, iry = pass == 0 ? 0 : 6, irw = pass == 0 ? 82 : 40, irh = pass == 0 ? 84 : 28;
        UINT32 orx = pass == 0 ? 0 : 12, ory = pass == 0 ? 0 : 10, orw = irw, orh = irh;
        struct vfmt vi, vo;
        struct wg_media_type in = make_video( &vi, fmts[fi].tag, iw, ih, 30, 1, flip_in );
        struct wg_media_type out = make_video( &vo, fmts[fo].tag, ow, oh, 30, 1, flip_out );
        struct ref_geom gin, gout;
        struct wg_sample smp;
        wg_transform_t h = 0;
        HRESULT hr;

        vi.f.videoInfo.MinimumDisplayAperture.OffsetX.value = irx;
        vi.f.videoInfo.MinimumDisplayAperture.OffsetY.value = iry;
        vi.f.videoInfo.MinimumDisplayAperture.Area.cx = irw;
        vi.f.videoInfo.MinimumDisplayAperture.Area.cy = irh;
        vo.f.videoInfo.MinimumDisplayAperture.OffsetX.value = orx;
        vo.f.videoInfo.MinimumDisplayAperture.OffsetY.value = ory;
        vo.f.videoInfo.MinimumDisplayAperture.Area.cx = orw;
        vo.f.videoInfo.MinimumDisplayAperture.Area.cy = orh;

        ref_geom_init( &gin, fi, iw, ih, flip_in, 0, 0 );
        gin.rx = irx; gin.ry = iry; gin.rw = irw; gin.rh = irh;
        ref_geom_init( &gout, fo, ow, oh, flip_out, 0, 0 );
        gout.rx = orx; gout.ry = ory; gout.rw = orw; gout.rh = orh;

        memset( in_buf, 0xcd, gin.size + GUARD );
        fill_pattern( &gin, 40 + pass, in_buf );
        memset( got_buf, 0xcd, gout.size + GUARD );
        memset( exp_buf, 0xcd, gout.size + GUARD );
        memset( mask, 0, gout.size + GUARD );
        mark_active_mask( &gout, mask );
        ref_convert( in_buf, &gin, exp_buf, &gout, 0 );

        CHECK( !create_xform( &h, &in, &out, NULL ) && h, "aperture %d create", pass );
        CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, 0, 0, 0 ) == S_OK, "aperture %d push", pass );
        CHECK( !read_frame( h, &smp, got_buf, gout.size, 0, &hr ) && hr == S_OK && smp.size == gout.size,
               "aperture %d read", pass );
        destroy_xform( h );
        if (compare_buffers( "aperture", &gout, got_buf, exp_buf, mask, GUARD, 2 )) goto fail;
    }

    free( in_buf ); free( got_buf ); free( exp_buf ); free( mask );
    PASS( "2D buffer strides (input & output, IMF2DBuffer2 size < max_size), output_plane_align=15, short-stride "
          "fallback, and input/output MinimumDisplayAperture cropping & offsets (surrounding bytes stay 0xCD)" );
    return 0;
fail:
    free( in_buf ); free( got_buf ); free( exp_buf ); free( mask );
    return 1;
}

/* 4. Bilinear scaling: upscale, downscale, asymmetric, odd sizes, 1x1 edge cases, and
 *    aperture + scaling combined, checked against the floating-point bilinear reference. */
static int test_scaling(void)
{
    static const struct
    {
        int fi, fo, flip_in, flip_out;
        UINT32 iw, ih, ow, oh;
        UINT32 irx, iry, irw, irh;
        UINT32 orx, ory, orw, orh;
        const char *what;
    } cases[] =
    {
        { F_BGRX, F_BGRX, 0, 0, 16, 12, 40, 30, 0,0,0,0, 0,0,0,0, "RGB32 16x12 -> 40x30 upscale" },
        { F_BGRX, F_BGRX, 1, 1, 32, 24, 12, 10, 0,0,0,0, 0,0,0,0, "RGB32 bottom-up 32x24 -> 12x10 downscale" },
        { F_NV12, F_BGRX, 0, 1, 16, 12, 46, 34, 0,0,0,0, 0,0,0,0, "NV12 -> RGB32 bottom-up 16x12 -> 46x34 upscale" },
        { F_BGRX, F_NV12, 1, 0, 40, 30, 18, 14, 0,0,0,0, 0,0,0,0, "RGB32 bottom-up -> NV12 40x30 -> 18x14 downscale" },
        { F_I420, F_YUY2, 0, 0, 14, 10, 31, 23, 0,0,0,0, 0,0,0,0, "I420 -> YUY2 14x10 -> 31x23 odd upscale" },
        { F_UYVY, F_YV12, 0, 0, 30, 22, 11,  7, 0,0,0,0, 0,0,0,0, "UYVY -> YV12 30x22 -> 11x7 odd downscale" },
        { F_BGRA, F_AYUV, 0, 0, 13,  9, 29, 21, 0,0,0,0, 0,0,0,0, "ARGB32 -> AYUV 13x9 -> 29x21 (with alpha)" },
        { F_AYUV, F_RGBA, 1, 0, 25, 19,  9, 15, 0,0,0,0, 0,0,0,0, "AYUV -> ABGR32 25x19 -> 9x15 asymmetric" },
        { F_BGR,  F_565,  0, 1, 19, 13, 37, 25, 0,0,0,0, 0,0,0,0, "RGB24 -> RGB565 bottom-up 19x13 -> 37x25" },
        { F_BGRX, F_BGRX, 0, 0,  1,  1,  9,  7, 0,0,0,0, 0,0,0,0, "1x1 -> 9x7 edge clamp" },
        { F_BGRX, F_BGRX, 0, 0,  9,  7,  1,  1, 0,0,0,0, 0,0,0,0, "9x7 -> 1x1 edge clamp" },
        { F_BGRX, F_BGRX, 0, 0,  1, 11,  7,  5, 0,0,0,0, 0,0,0,0, "1x11 -> 7x5 1D column scale" },
        { F_NV12, F_BGRX, 0, 0, 48, 36, 64, 48, 4,4,24,18, 8,6,44,32, "aperture crop (24x18) scaled into output aperture (44x32)" },
    };
    const size_t GUARD = 64;
    uint8_t *in_buf = malloc( 128 * 1024 ), *got_buf = malloc( 128 * 1024 );
    uint8_t *exp_buf = malloc( 128 * 1024 ), *mask = malloc( 128 * 1024 );
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(cases); i++)
    {
        struct vfmt vi, vo;
        struct wg_media_type in = make_video( &vi, fmts[cases[i].fi].tag, cases[i].iw, cases[i].ih, 30, 1, cases[i].flip_in );
        struct wg_media_type out = make_video( &vo, fmts[cases[i].fo].tag, cases[i].ow, cases[i].oh, 30, 1, cases[i].flip_out );
        struct ref_geom gin, gout;
        struct wg_sample smp;
        wg_transform_t h = 0;
        HRESULT hr;
        /* 1/256 fixed-point coordinate rounding vs double bilinear is within <= 2 LSB (<= 3 with YUV<->RGB). */
        int tol = fmts[cases[i].fi].yuv == fmts[cases[i].fo].yuv ? 2 : 3;

        ref_geom_init( &gin, cases[i].fi, cases[i].iw, cases[i].ih, cases[i].flip_in, 0, 0 );
        ref_geom_init( &gout, cases[i].fo, cases[i].ow, cases[i].oh, cases[i].flip_out, 0, 0 );
        if (cases[i].irw)
        {
            vi.f.videoInfo.MinimumDisplayAperture.OffsetX.value = cases[i].irx;
            vi.f.videoInfo.MinimumDisplayAperture.OffsetY.value = cases[i].iry;
            vi.f.videoInfo.MinimumDisplayAperture.Area.cx = cases[i].irw;
            vi.f.videoInfo.MinimumDisplayAperture.Area.cy = cases[i].irh;
            gin.rx = cases[i].irx; gin.ry = cases[i].iry; gin.rw = cases[i].irw; gin.rh = cases[i].irh;
        }
        if (cases[i].orw)
        {
            vo.f.videoInfo.MinimumDisplayAperture.OffsetX.value = cases[i].orx;
            vo.f.videoInfo.MinimumDisplayAperture.OffsetY.value = cases[i].ory;
            vo.f.videoInfo.MinimumDisplayAperture.Area.cx = cases[i].orw;
            vo.f.videoInfo.MinimumDisplayAperture.Area.cy = cases[i].orh;
            gout.rx = cases[i].orx; gout.ry = cases[i].ory; gout.rw = cases[i].orw; gout.rh = cases[i].orh;
        }

        memset( in_buf, 0xcd, gin.size + GUARD );
        fill_pattern( &gin, 70 + (int)i, in_buf );
        memset( got_buf, 0xcd, gout.size + GUARD );
        memset( exp_buf, 0xcd, gout.size + GUARD );
        memset( mask, 0, gout.size + GUARD );
        mark_active_mask( &gout, mask );
        ref_convert( in_buf, &gin, exp_buf, &gout, 0 );

        CHECK( !create_xform( &h, &in, &out, NULL ) && h, "%s: create", cases[i].what );
        CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, 0, 0, 0 ) == S_OK, "%s: push", cases[i].what );
        CHECK( !read_frame( h, &smp, got_buf, gout.size, 0, &hr ) && hr == S_OK && smp.size == gout.size,
               "%s: read", cases[i].what );
        destroy_xform( h );
        if (compare_buffers( cases[i].what, &gout, got_buf, exp_buf, mask, GUARD, tol )) goto fail;
    }

    free( in_buf ); free( got_buf ); free( exp_buf ); free( mask );
    PASS( "bilinear scaling (%zu cases: upscale, downscale, odd sizes, 1x1 edge clamping, aperture + scale) matches "
          "floating-point bilinear reference at interior and edges", ARRAY_SIZE(cases) );
    return 0;
fail:
    free( in_buf ); free( got_buf ); free( exp_buf ); free( mask );
    return 1;
}

/* 5. Protocol: timestamps, queue limits, drain, flush, mid-stream set_output_type,
 *    two-phase get_output_type, STATUS_BUFFER_TOO_SMALL, short input drops. */
static int test_protocol(void)
{
    const UINT32 W = 16, H = 12;
    const INT64 TICK = 400000;   /* 25 fps */
    static const INT64 irreg[5][2] = { { 12000, 100000 }, { 555555, 222222 }, { 999999, 111111 }, { 1234567, 0 }, { 2500000, 400000 } };
    uint8_t in_buf[4096], out_buf[8192], exp_buf[8192], mask[8192];
    struct ref_geom gin, gout;

    ref_geom_init( &gin, F_NV12, W, H, 0, 0, 0 );
    ref_geom_init( &gout, F_BGRX, W, H, 0, 0, 0 );
    fill_pattern( &gin, 12, in_buf );

    /* Timestamps: pass 0 preserve_timestamps=1, pass 1 preserve_timestamps=0,
     * pass 2 no sample timestamps with 25 fps, pass 3 no sample timestamps & no fps */
    for (int pass = 0; pass < 4; pass++)
    {
        struct vfmt vi, vo;
        struct wg_media_type in = make_video( &vi, FCC('N','V','1','2'), W, H, pass == 3 ? 0 : 25, pass == 3 ? 0 : 1, FALSE );
        struct wg_media_type out = make_video( &vo, 22, W, H, 0, 0, FALSE );
        struct wg_transform_attrs attrs = { 0 };
        struct wg_sample smp;
        wg_transform_t h = 0;
        HRESULT hr;

        attrs.preserve_timestamps = (pass == 0);
        CHECK( !create_xform( &h, &in, &out, &attrs ) && h, "ts %d create", pass );
        for (int i = 0; i < 5; i++)
        {
            INT64 pts = pass < 2 ? irreg[i][0] : INT64_MIN;
            INT64 dur = pass < 2 ? irreg[i][1] : INT64_MIN;
            INT64 want_pts = pass < 2 ? irreg[i][0] : pass == 2 ? (INT64)i * TICK : 0;
            INT64 want_dur = pass < 2 ? irreg[i][1] : pass == 2 ? TICK : 0;
            UINT32 want_flags = WG_SAMPLE_FLAG_SYNC_POINT | WG_SAMPLE_FLAG_HAS_PTS | WG_SAMPLE_FLAG_HAS_DURATION;
            if (pass == 0) want_flags |= WG_SAMPLE_FLAG_PRESERVE_TIMESTAMPS;
            if (i == 2) want_flags |= WG_SAMPLE_FLAG_DISCONTINUITY;

            CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, pts, dur,
                               i == 2 ? WG_SAMPLE_FLAG_DISCONTINUITY : 0 ) == S_OK, "ts push" );
            CHECK( !read_frame( h, &smp, out_buf, gout.size, 0, &hr ) && hr == S_OK, "ts read" );
            CHECK( smp.flags == want_flags && smp.pts == want_pts && (INT64)smp.duration == want_dur,
                   "ts pass %d #%d: got flags=%#x pts=%lld dur=%lld", pass, i, smp.flags,
                   (long long)smp.pts, (long long)smp.duration );
        }
        destroy_xform( h );
    }

    /* Queue limit (0 and 7), get_status, drain, flush, mid-stream set_output_type,
     * two-phase get_output_type, STATUS_BUFFER_TOO_SMALL, short input sample */
    {
        struct vfmt vi, vo, vo2;
        struct wg_media_type in = make_video( &vi, FCC('N','V','1','2'), W, H, 25, 1, FALSE );
        struct wg_media_type out = make_video( &vo, 22, W, H, 0, 0, FALSE );
        struct wg_media_type out2 = make_video( &vo2, FCC('Y','U','Y','2'), W * 2, H * 2, 0, 0, FALSE );
        struct wg_transform_attrs attrs = { 0 };
        struct wg_transform_get_status_params st = { 0 };
        struct wg_transform_set_output_type_params so = { 0 };
        struct wg_transform_get_output_type_params go = { 0 };
        struct wg_sample smp;
        struct ref_geom gout2;
        wg_transform_t h = 0, hh;
        uint8_t fmt_buf[512];
        HRESULT hr;
        int i, n;

        /* input_queue_length = 0: accepts 1, refuses 2nd */
        CHECK( !create_xform( &h, &in, &out, &attrs ) && h, "q0 create" );
        st.transform = h;
        CHECK( !call64( unix_wg_transform_get_status, &st ) && st.accepts_input, "q0 accepts initially" );
        CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, 0, TICK, 0 ) == S_OK, "q0 push 1" );
        CHECK( !call64( unix_wg_transform_get_status, &st ) && !st.accepts_input, "q0 full" );
        CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, TICK, TICK, 0 ) == MF_E_NOTACCEPTING, "q0 push 2 refused" );
        /* Buffer too small keeps frame queued */
        CHECK( read_frame( h, &smp, out_buf, gout.size - 1, 0, &hr ) == STATUS_BUFFER_TOO_SMALL && !smp.size,
               "STATUS_BUFFER_TOO_SMALL" );
        CHECK( !read_frame( h, &smp, out_buf, gout.size, 0, &hr ) && hr == S_OK && smp.size == gout.size,
               "retry after STATUS_BUFFER_TOO_SMALL succeeds" );
        /* Short input buffer is safely dropped without reading out of bounds */
        {
            uint8_t tiny[16] = { 0 };
            CHECK( push_frame( h, tiny, sizeof(tiny), sizeof(tiny), 0, 2 * TICK, TICK, 0 ) == S_OK, "short input push" );
            CHECK( !read_frame( h, &smp, out_buf, gout.size, 0, &hr ) && hr == MF_E_TRANSFORM_NEED_MORE_INPUT,
                   "short input dropped cleanly" );
            /* Next valid frame carries DISCONTINUITY after dropped short sample */
            CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, 3 * TICK, TICK, 0 ) == S_OK, "push after short" );
            CHECK( !read_frame( h, &smp, out_buf, gout.size, 0, &hr ) && hr == S_OK
                   && (smp.flags & WG_SAMPLE_FLAG_DISCONTINUITY), "discontinuity after dropped short sample" );
        }
        destroy_xform( h );

        /* input_queue_length = 7 (8 frames), drain, flush, mid-stream set_output_type */
        attrs.input_queue_length = 7;
        CHECK( !create_xform( &h, &in, &out, &attrs ) && h, "q7 create" );
        for (i = 0; i < 8; i++)
            CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, (INT64)i * TICK, TICK, 0 ) == S_OK, "q7 push %d", i );
        CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, 8 * TICK, TICK, 0 ) == MF_E_NOTACCEPTING, "q7 9th refused" );

        /* Drain with 8 frames queued: input refused even after reading some, until queue is empty */
        hh = h;
        CHECK( !call64( unix_wg_transform_drain, &hh ), "drain" );
        st.transform = h;
        CHECK( !call64( unix_wg_transform_get_status, &st ) && !st.accepts_input, "get_status false while draining" );
        CHECK( !read_frame( h, &smp, out_buf, gout.size, 0, &hr ) && hr == S_OK, "drain read 0" );
        CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, 9 * TICK, TICK, 0 ) == MF_E_NOTACCEPTING,
               "still draining while 7 frames remain" );
        for (n = 1; ; n++)
        {
            CHECK( !read_frame( h, &smp, out_buf, gout.size, 0, &hr ), "drain read" );
            if (hr != S_OK) break;
        }
        CHECK( n == 8 && hr == MF_E_TRANSFORM_NEED_MORE_INPUT, "drained all 8 frames" );
        CHECK( !call64( unix_wg_transform_get_status, &st ) && st.accepts_input, "accepts again after drain" );

        /* Queue 3 frames, switch output type to scaled YUY2 32x24 mid-stream, read them in new format! */
        for (i = 0; i < 3; i++)
            CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, (INT64)i * TICK, TICK, 0 ) == S_OK, "pending push %d", i );
        so.transform = h; so.media_type = out2;
        CHECK( !call64( unix_wg_transform_set_output_type, &so ), "set_output_type to YUY2 32x24" );

        /* Invalid output type refused, YUY2 32x24 kept */
        {
            struct vfmt vbad;
            so.media_type = make_video( &vbad, FCC('N','V','1','1'), W, H, 0, 0, FALSE );
            CHECK( call64( unix_wg_transform_set_output_type, &so ) == STATUS_NOT_SUPPORTED, "bad set_output_type refused" );
        }

        go.transform = h;
        CHECK( call64( unix_wg_transform_get_output_type, &go ) == STATUS_BUFFER_TOO_SMALL
               && go.media_type.format_size == out2.format_size, "get_output_type phase 1" );
        go.media_type.u.format = fmt_buf;
        CHECK( !call64( unix_wg_transform_get_output_type, &go )
               && !memcmp( fmt_buf, &vo2.f, out2.format_size ), "get_output_type phase 2" );

        ref_geom_init( &gout2, F_YUY2, W * 2, H * 2, 0, 0, 0 );
        memset( exp_buf, 0xcd, gout2.size + 64 );
        memset( mask, 0, gout2.size + 64 );
        mark_active_mask( &gout2, mask );
        ref_convert( in_buf, &gin, exp_buf, &gout2, 0 );
        for (i = 0; i < 3; i++)
        {
            memset( out_buf, 0xcd, gout2.size + 64 );
            CHECK( !read_frame( h, &smp, out_buf, gout2.size, 0, &hr ) && hr == S_OK && smp.size == gout2.size,
                   "read pending %d in new format", i );
            if (compare_buffers( "mid-stream set_output_type", &gout2, out_buf, exp_buf, mask, 64, 2 )) return 1;
        }

        /* Flush drops queued frames and resets next_pts */
        for (i = 0; i < 4; i++)
            CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, INT64_MIN, INT64_MIN, 0 ) == S_OK, "flush push" );
        CHECK( !call64( unix_wg_transform_flush, &hh ), "flush" );
        CHECK( !read_frame( h, &smp, out_buf, gout2.size, 0, &hr ) && hr == MF_E_TRANSFORM_NEED_MORE_INPUT,
               "empty after flush" );
        CHECK( push_frame( h, in_buf, gin.size, gin.size, 0, INT64_MIN, INT64_MIN, 0 ) == S_OK, "push after flush" );
        CHECK( !read_frame( h, &smp, out_buf, gout2.size, 0, &hr ) && hr == S_OK && smp.pts == 0,
               "next_pts reset to 0 after flush" );

        destroy_xform( h );
    }

    PASS( "timestamps, queue limits (0 & 7), get_status, drain, flush, mid-stream set_output_type (format + scale), "
          "two-phase get_output_type, STATUS_BUFFER_TOO_SMALL, and short input drops" );
    return 0;
}

/* 6. Concurrent push on one thread and read on another. */
struct thread_ctx
{
    wg_transform_t h;
    struct ref_geom gin;
    uint8_t in_frames[24][2048];
};

static void *pusher_main( void *arg )
{
    struct thread_ctx *t = arg;
    int i = 0;

    while (i < 24)
    {
        HRESULT hr = push_frame( t->h, t->in_frames[i], t->gin.size, t->gin.size, 0, (INT64)i * 400000, 400000, 0 );
        if (hr == S_OK) i++;
        else sched_yield();
    }
    return NULL;
}

static int test_threads_and_wow64(void)
{
    /* Multi-threaded push + read */
    {
        struct thread_ctx *t = calloc( 1, sizeof(*t) );
        struct vfmt vi, vo;
        struct wg_media_type in = make_video( &vi, FCC('Y','U','Y','2'), 20, 14, 25, 1, FALSE );
        struct wg_media_type out = make_video( &vo, 22, 28, 20, 25, 1, TRUE );
        struct wg_transform_attrs attrs = { 0 };
        struct ref_geom gout;
        struct wg_sample smp;
        uint8_t got[4096], exp[4096], mask[4096];
        pthread_t th;
        HRESULT hr;
        int n = 0, spins = 0;

        attrs.input_queue_length = 3;
        ref_geom_init( &t->gin, F_YUY2, 20, 14, 0, 0, 0 );
        ref_geom_init( &gout, F_BGRX, 28, 20, 1, 0, 0 );
        for (int i = 0; i < 24; i++) fill_pattern( &t->gin, i + 1, t->in_frames[i] );
        CHECK( !create_xform( &t->h, &in, &out, &attrs ) && t->h, "threads create" );
        pthread_create( &th, NULL, pusher_main, t );
        while (n < 24 && spins < 2000000)
        {
            memset( got, 0xcd, gout.size + 64 );
            CHECK( !read_frame( t->h, &smp, got, gout.size, 0, &hr ), "threads read" );
            if (hr == S_OK)
            {
                memset( exp, 0xcd, gout.size + 64 );
                memset( mask, 0, gout.size + 64 );
                mark_active_mask( &gout, mask );
                ref_convert( t->in_frames[n], &t->gin, exp, &gout, 0 );
                if (compare_buffers( "threads", &gout, got, exp, mask, 64, 3 )) return 1;
                CHECK( smp.pts == (INT64)n * 400000, "threads pts %d", n );
                n++;
            }
            else spins++;
        }
        pthread_join( th, NULL );
        CHECK( n == 24, "threads delivered %d/24 frames", n );
        destroy_xform( t->h );
        free( t );
    }

#ifdef MAP_32BIT
    /* Wow64 32-bit thunks with pointers below 4 GB */
    {
        const size_t arena_size = 4 << 20;
        uint8_t *arena = mmap( NULL, arena_size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0 );
        size_t used = 0;
#define LOW(n) (used += ((n) + 15) & ~(size_t)15, (void *)(arena + used - (((n) + 15) & ~(size_t)15)))
#define G(p) ((ULONG)(UINT_PTR)(p))
        struct wg_transform_create_params32 *c32;
        struct wg_transform_sample_params32 *s32;
        struct wg_transform_output_type_params32 *o32;
        struct wg_transform_get_status_params *st;
        struct wg_sample *smp;
        struct vfmt *vi, *vo, *got_fmt;
        wg_transform_t *h;
        uint8_t *in_data, *out_data, exp[8192], mask[8192];
        struct ref_geom gin, gout;

        CHECK( arena != MAP_FAILED && (UINT_PTR)arena + arena_size < ((UINT64)1 << 32), "MAP_32BIT arena" );
        vi = LOW( sizeof(*vi) ); vo = LOW( sizeof(*vo) ); got_fmt = LOW( sizeof(*got_fmt) );
        c32 = LOW( sizeof(*c32) ); s32 = LOW( sizeof(*s32) ); o32 = LOW( sizeof(*o32) ); st = LOW( sizeof(*st) );
        smp = LOW( sizeof(*smp) ); h = LOW( sizeof(*h) );
        ref_geom_init( &gin, F_I420, 16, 12, 0, 0, 0 );
        ref_geom_init( &gout, F_BGRX, 24, 18, 1, 0, 0 );
        in_data = LOW( gin.size + 64 );
        out_data = LOW( gout.size + 64 );
        fill_pattern( &gin, 55, in_data );
        memset( out_data, 0xcd, gout.size + 64 );
        memset( exp, 0xcd, gout.size + 64 );
        memset( mask, 0, gout.size + 64 );
        mark_active_mask( &gout, mask );
        ref_convert( in_data, &gin, exp, &gout, 0 );

        make_video( vi, FCC('I','4','2','0'), 16, 12, 30, 1, FALSE );
        make_video( vo, 22, 24, 18, 30, 1, TRUE );
        memset( c32, 0, sizeof(*c32) );
        c32->input_type.major = madeira_MFMediaType_Video;
        c32->input_type.format_size = vi->f.dwSize;
        c32->input_type.format = G( &vi->f );
        c32->output_type.major = madeira_MFMediaType_Video;
        c32->output_type.format_size = vo->f.dwSize;
        c32->output_type.format = G( &vo->f );
        c32->attrs.preserve_timestamps = TRUE;
        CHECK( !call32( unix_wg_transform_create, c32 ) && c32->transform, "wow64 create" );
        *h = c32->transform;

        memset( smp, 0, sizeof(*smp) );
        smp->data = G( in_data ); smp->size = smp->max_size = gin.size;
        smp->flags = WG_SAMPLE_FLAG_HAS_PTS | WG_SAMPLE_FLAG_HAS_DURATION;
        smp->pts = 777777; smp->duration = 333333;
        memset( s32, 0, sizeof(*s32) );
        s32->transform = *h; s32->sample = G( smp );
        CHECK( !call32( unix_wg_transform_push_data, s32 ) && s32->result == S_OK, "wow64 push" );

        memset( smp, 0, sizeof(*smp) );
        smp->data = G( out_data ); smp->max_size = gout.size;
        s32->result = E_FAIL;
        CHECK( !call32( unix_wg_transform_read_data, s32 ) && s32->result == S_OK && smp->size == gout.size
               && smp->pts == 777777 && (smp->flags & WG_SAMPLE_FLAG_PRESERVE_TIMESTAMPS), "wow64 read" );
        if (compare_buffers( "wow64", &gout, out_data, exp, mask, 64, 3 )) return 1;

        memset( o32, 0, sizeof(*o32) );
        o32->transform = *h;
        CHECK( call32( unix_wg_transform_get_output_type, o32 ) == STATUS_BUFFER_TOO_SMALL
               && o32->media_type.format_size == vo->f.dwSize, "wow64 get_output_type size" );
        o32->media_type.format = G( got_fmt );
        CHECK( !call32( unix_wg_transform_get_output_type, o32 )
               && !memcmp( &got_fmt->f, &vo->f, vo->f.dwSize ), "wow64 get_output_type" );
        make_video( vo, FCC('N','V','1','2'), 16, 12, 0, 0, FALSE );
        o32->media_type.format_size = vo->f.dwSize; o32->media_type.format = G( &vo->f );
        CHECK( !call32( unix_wg_transform_set_output_type, o32 ), "wow64 set_output_type" );
        st->transform = *h;
        CHECK( !call32( unix_wg_transform_get_status, st ) && st->accepts_input, "wow64 get_status" );
        CHECK( !call32( unix_wg_transform_drain, h ) && !call32( unix_wg_transform_flush, h ), "wow64 drain/flush" );
        CHECK( !call32( unix_wg_transform_destroy, h ), "wow64 destroy" );
        munmap( arena, arena_size );
#undef LOW
#undef G
    }
#endif

    PASS( "two-thread push/read stress (24 scaled frames in order) and wow64 32-bit thunks below 4 GB" );
    return 0;
}

/* 7. Refusals, coexistence with WMV/WMA/resampler, and MADEIRA_WG_VIDEO_CONVERT=0. */
static int test_refusals_and_coexistence( int switched_off, int wmv_off )
{
    static const struct { UINT32 in, out, iw, ih, ow, oh; const char *what; } bad_cases[] =
    {
        { FCC('N','V','1','1'), FCC('N','V','1','2'), 32, 24, 32, 24, "NV11 in" },
        { 41 /* D3DFMT_P8 */,   FCC('N','V','1','2'), 32, 24, 32, 24, "RGB8 in" },
        { FCC('P','0','1','0'), FCC('N','V','1','2'), 32, 24, 32, 24, "P010 in" },
        { FCC('Y','V','U','9'), FCC('N','V','1','2'), 32, 24, 32, 24, "YVU9 in" },
        { FCC('N','V','1','2'), FCC('N','V','1','1'), 32, 24, 32, 24, "NV11 out" },
        { FCC('N','V','1','2'), 41 /* D3DFMT_P8 */,   32, 24, 32, 24, "RGB8 out" },
        { FCC('N','V','1','2'), FCC('P','0','1','0'), 32, 24, 32, 24, "P010 out" },
        { FCC('N','V','1','2'), FCC('H','2','6','4'), 32, 24, 32, 24, "H264 out" },
        { FCC('N','V','1','2'), 22,                    0, 24, 32, 24, "zero input width" },
        { FCC('N','V','1','2'), 22,                   32,  0, 32, 24, "zero input height" },
        { FCC('N','V','1','2'), 22,                 8193, 24, 32, 24, "oversize input width" },
        { FCC('N','V','1','2'), 22,                   32, 24, 32, 8193, "oversize output height" },
    };
    struct vfmt vi, vo;
    struct wg_media_type in, out;
    wg_transform_t h = 0;

    if (switched_off)
    {
        in = make_video( &vi, FCC('I','4','2','0'), 1920, 1080, 0, 0, FALSE );
        out = make_video( &vo, FCC('N','V','1','2'), 1920, 1080, 0, 0, FALSE );
        CHECK( create_xform( &h, &in, &out, NULL ) == STATUS_NOT_SUPPORTED && !h,
               "MADEIRA_WG_VIDEO_CONVERT=0 refuses probe" );
        in = make_video( &vi, FCC('N','V','1','2'), 32, 24, 30, 1, FALSE );
        out = make_video( &vo, 22, 32, 24, 30, 1, FALSE );
        CHECK( create_xform( &h, &in, &out, NULL ) == STATUS_NOT_SUPPORTED && !h,
               "MADEIRA_WG_VIDEO_CONVERT=0 refuses NV12->RGB32" );
        /* WMV decoder probe still works when MADEIRA_WG_VIDEO_CONVERT=0! */
        in = make_video( &vi, FCC('W','M','V','3'), 1920, 1080, 0, 0, FALSE );
        out = make_video( &vi == &vo ? &vi : &vo, FCC('I','4','2','0'), 1920, 1080, 0, 0, FALSE );
        CHECK( !create_xform( &h, &in, &out, NULL ) && h && get_wmv_transform( h ),
               "WMV decoder still works when MADEIRA_WG_VIDEO_CONVERT=0" );
        destroy_xform( h );
        PASS( "MADEIRA_WG_VIDEO_CONVERT=0 refuses raw video transforms while leaving WMV unaffected" );
        return 0;
    }

    if (wmv_off)
    {
        /* With MADEIRA_WG_WMV_TRANSFORM=0, raw video converter STILL works while WMV is refused! */
        in = make_video( &vi, FCC('I','4','2','0'), 1920, 1080, 0, 0, FALSE );
        out = make_video( &vo, FCC('N','V','1','2'), 1920, 1080, 0, 0, FALSE );
        CHECK( !create_xform( &h, &in, &out, NULL ) && h && get_vconv_transform( h ),
               "vconv still works when MADEIRA_WG_WMV_TRANSFORM=0" );
        destroy_xform( h );
        in = make_video( &vi, FCC('W','M','V','3'), 1920, 1080, 0, 0, FALSE );
        out = make_video( &vo, FCC('I','4','2','0'), 1920, 1080, 0, 0, FALSE );
        CHECK( create_xform( &h, &in, &out, NULL ) == STATUS_NOT_SUPPORTED && !h,
               "WMV refused when MADEIRA_WG_WMV_TRANSFORM=0" );
        PASS( "MADEIRA_WG_WMV_TRANSFORM=0 refuses WMV while leaving the raw video converter working" );
        return 0;
    }

    for (unsigned int i = 0; i < ARRAY_SIZE(bad_cases); i++)
    {
        in = make_video( &vi, bad_cases[i].in, bad_cases[i].iw, bad_cases[i].ih, 30, 1, FALSE );
        out = make_video( &vo, bad_cases[i].out, bad_cases[i].ow, bad_cases[i].oh, 30, 1, FALSE );
        h = 0xdeadbeef;
        CHECK( create_xform( &h, &in, &out, NULL ) == STATUS_NOT_SUPPORTED && !h,
               "%s not refused", bad_cases[i].what );
    }
    /* Raw video in, audio out -> refused */
    {
        WAVEFORMATEX pcm = { WAVE_FORMAT_PCM, 2, 48000, 192000, 4, 16, 0 };
        in = make_video( &vi, FCC('N','V','1','2'), 32, 24, 30, 1, FALSE );
        out.major = madeira_MFMediaType_Audio; out.format_size = sizeof(pcm); out.u.audio = &pcm;
        CHECK( create_xform( &h, &in, &out, NULL ) == STATUS_NOT_SUPPORTED && !h, "raw video to audio refused" );
    }
    /* Coexistence: WMV3 probe still goes to wmv_transform_ops, PCM goes to rs_transform_ops */
    in = make_video( &vi, FCC('W','M','V','3'), 1920, 1080, 0, 0, FALSE );
    out = make_video( &vo, FCC('I','4','2','0'), 1920, 1080, 0, 0, FALSE );
    CHECK( !create_xform( &h, &in, &out, NULL ) && h && get_wmv_transform( h ) && !get_vconv_transform( h ),
           "WMV3 still goes to wmv_transform_ops" );
    destroy_xform( h );

    PASS( "refusals (NV11, RGB8, P010, YVU9, H264 out, video->audio, 0x0 and >8192 sizes) and WMV coexistence" );
    return 0;
}

int main( int argc, char **argv )
{
    const char *mode = argc > 1 ? argv[1] : "";

    if (!strcmp( mode, "off" ))
        test_refusals_and_coexistence( 1, 0 );
    else if (!strcmp( mode, "wmv-off" ))
        test_refusals_and_coexistence( 0, 1 );
    else
    {
        test_wine_probes();
        test_refusals_and_coexistence( 0, 0 );
        test_all_pairs();
        test_strides_and_apertures();
        test_scaling();
        test_protocol();
        test_threads_and_wow64();
    }
    printf( "%s: %d failure(s), %d checks\n", failures ? "FAIL" : "PASS", failures, checks );
    return failures ? 1 : 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    h = Path(tmp) / "vconv_host.c"
    h.write_text(harness)
    exe = Path(tmp) / "vconv_host"
    cc = os.environ.get("CC", "cc")
    cmd = [cc, "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined",
           "-fno-strict-aliasing", "-Wno-int-conversion", "-Wno-implicit-function-declaration",
           "-include", str(wine_build / "include/config.h"),
           "-I" + str(ntdll_unix), "-I" + str(wine / "dlls/winegstreamer"),
           "-I" + str(wine_build / "include"), "-I" + str(wine / "include"), "-I" + str(inc),
           "-D__WINESRC__", "-D_NTSYSTEM_", "-D_ACRTIMP=", "-DWINBASEAPI=", "-DWINE_UNIX_LIB",
           str(h), "-o", str(exe),
           str(lib / "libavformat.a"), str(lib / "libavcodec.a"), str(lib / "libswresample.a"),
           str(lib / "libavutil.a"), "-lm", "-lpthread"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        print(r.stdout[-6000:], r.stderr[-6000:])
        print("FAIL: harness did not compile")
        sys.exit(1)

    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1")
    env.pop("MADEIRA_WG_VIDEO_CONVERT", None)
    env.pop("MADEIRA_WG_WMV_TRANSFORM", None)
    for label, extra_env, args, needles in [
        ("default", {}, [], [
            "[vconv] converter created i420 1920x1080 -> nv12 1920x1080",
            "is not a supported raw video format; refusing",
            "[vconv] further lines suppressed after 64",
        ]),
        ("MADEIRA_WG_VIDEO_CONVERT=0", {"MADEIRA_WG_VIDEO_CONVERT": "0"}, ["off"], [
            "[vconv] video converter refused: MADEIRA_WG_VIDEO_CONVERT=0",
        ]),
        ("MADEIRA_WG_WMV_TRANSFORM=0", {"MADEIRA_WG_WMV_TRANSFORM": "0"}, ["wmv-off"], [
            "[vconv] converter created i420 1920x1080 -> nv12 1920x1080",
            "[wmv] video transform refused: MADEIRA_WG_WMV_TRANSFORM=0",
        ]),
    ]:
        print("--- %s ---" % label, flush=True)
        r = subprocess.run([str(exe)] + args, env=dict(env, **extra_env), capture_output=True, text=True)
        sys.stdout.write(r.stdout)
        check(r.returncode == 0, "harness (%s) exits 0" % label)
        if r.returncode or "ERROR: AddressSanitizer" in r.stderr or "runtime error" in r.stderr:
            if r.returncode == 0:
                check(False, "sanitizer clean (%s)" % label)
            print("\n".join(r.stderr.splitlines()[-40:]))
        for needle in needles:
            check(needle in r.stderr, "log (%s): %s" % (label, needle))
        vconv_lines = [l for l in r.stderr.splitlines() if l.startswith("[vconv]")]
        print("first [vconv] lines (%d in all):\n  " % len(vconv_lines) + "\n  ".join(vconv_lines[:8]))

if failures:
    print("FAILED: %d" % len(failures))
    sys.exit(1)
print("PASS: the raw video converter wg_transform")
