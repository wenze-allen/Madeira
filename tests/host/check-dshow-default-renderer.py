#!/usr/bin/env python3
"""DirectShow's default video renderer on this port, from production source; nothing runs.

RenderFile() connects a video stream to the "Video Renderer" (CLSID_VideoRendererDefault),
which is the VMR-7 and, if that cannot be created, the GDI renderer. The VMR-7 draws through
DirectDraw, and DirectDraw through wined3d, which has no 3D backend here (no OpenGL, no
Vulkan): ddraw falls back to wined3d's no3d adapter, whose CPU blitter converts only YUY2 to
RGB. These are the checks that an MPEG-1 movie through RenderFile() is drawn:
1. The default renderer is the VMR-7 first.
2. The VMR-7 takes RGB, and any FOURCC that DirectDraw lists.
3. ddraw falls back to no3d, and then lists only YUY2 (the wine submodule's fix). Before it
   listed every format, the VMR-7 took YV12, and in no3d a YV12 surface holds the luma plane
   only: the copy overran it and every blit failed.
4. The CPU blitter converts YUY2 to the display's RGB, and only YUY2 among the YUV formats.
5. quartz's MPEG video decoder offers YV12 before YUY2 (why 3 matters), and our video
   transform, which it uses, writes YUY2.
6. Movies through winegstreamer's decoding splitter (AVI, MPEG-2) get the stream's native
   format first, which here is top-down RGB32 (`biHeight < 0`). The VMR-7's presenter, the
   VMR-7 itself, VMR-9 and shared `IBasicVideo` use `abs(biHeight)` for surface heights,
   window/source rects and reported sizes while `vmr_render` keeps the sign so only bottom-up
   RGB is flipped.
"""
from pathlib import Path
import re, sys

root = Path(__file__).resolve().parents[2]
wine = root / "wine"
need = [
    wine / "dlls/quartz/videorenderer.c",
    wine / "dlls/quartz/vmr7.c",
    wine / "dlls/quartz/vmr7_presenter.c",
    wine / "dlls/quartz/vmr9.c",
    wine / "dlls/quartz/window.c",
    wine / "dlls/winegstreamer/quartz_parser.c",
    wine / "dlls/ddraw/ddraw.c",
]
for n in need:
    if not n.exists():
        sys.exit("SKIP-FAIL: %s is missing (submodules not checked out)" % n)


def function(source, start):
    a = source.index(start)
    b = source.index("{", a)
    depth, c = 1, b + 1
    while depth:
        depth += (source[c] == "{") - (source[c] == "}")
        c += 1
    return source[a:c]


# ---- 1. the default renderer ----------------------------------------------------
vr = (wine / "dlls/quartz/videorenderer.c").read_text()
default = function(vr, "HRESULT video_renderer_default_create(")
assert default.index("vmr7_create(") < default.index("video_renderer_create("), default
print("PASS: the default video renderer is the VMR-7, then the GDI renderer")

# ---- 2. what the VMR-7 accepts ----------------------------------------------------
vmr7 = (wine / "dlls/quartz/vmr7.c").read_text()
accept = function(vmr7, "static HRESULT vmr_query_accept(")
assert "BI_RGB" in accept and "fourcc_is_supported(ddraw, bitmap_header->biCompression)" in accept
assert "IDirectDraw7_GetFourCCCodes" in function(vmr7, "static BOOL fourcc_is_supported(")
render = function(vmr7, "static HRESULT vmr_render(")
assert "mmioFOURCC('Y','V','1','2')" in render and "surface_desc.lPitch / 2" in render, \
    "the VMR-7 copies a YV12 frame's chroma planes after the luma plane"
print("PASS: the VMR-7 takes RGB and any FOURCC that DirectDraw lists, and copies YV12 as three planes")

# ---- 3. ddraw without 3D ----------------------------------------------------------------
ddraw = (wine / "dlls/ddraw/ddraw.c").read_text()
init = ddraw[ddraw.index("flags |= DDRAW_WINED3D_FLAGS;"):]
init = init[:init.index("wined3d_device_create(")]
assert "flags |= WINED3D_NO3D;" in init and "ddraw->flags |= DDRAW_NO3D;" in init, "ddraw falls back to no3d"
codes = function(ddraw, "static HRESULT WINAPI ddraw7_GetFourCCCodes(")
assert re.search(r"if \(\(ddraw->flags & DDRAW_NO3D\) && formats\[i\] != WINED3DFMT_YUY2\)\s*continue;", codes), \
    "without 3D, GetFourCCCodes lists only YUY2"
assert codes.index("DDRAW_NO3D") < codes.index("wined3d_check_device_format("), codes
build = (root / "build/wine-i386/build.sh").read_text()
assert "--without-vulkan" in build and "no OpenGL" in build, "wined3d has no 3D backend in this port"
print("PASS: ddraw runs on wined3d's no3d adapter here, and then lists only YUY2 among the FOURCCs")

# ---- 4. wined3d's CPU blitter ----------------------------------------------------------
surface = (wine / "dlls/wined3d/surface.c").read_text()
table = surface[surface.index("static const struct d3dfmt_converter_desc converters[] ="):]
table = table[:table.index("};")]
assert "{WINED3DFMT_YUY2,           WINED3DFMT_B8G8R8X8_UNORM,  convert_yuy2_x8r8g8b8}" in table, table
for fmt in ["YV12", "NV12", "UYVY"]:
    assert "WINED3DFMT_%s," % fmt not in table, "%s has a converter now: recheck the ddraw fix" % fmt
convert = function(surface, "static struct wined3d_texture *surface_convert_format(")
assert "WINED3D_NO3D" in convert and "Cannot find a conversion function" in convert
utils = (wine / "dlls/wined3d/utils.c").read_text()
no3d = function(utils, "BOOL wined3d_adapter_no3d_init_format_info(")
assert "height_scale" not in no3d, "no3d gives YV12/NV12 their 3/2 height now: recheck the ddraw fix"
print("PASS: without 3D the CPU blitter converts YUY2 to RGB, and no other YUV format")

# ---- 5. the MPEG video decoder ------------------------------------------------------
qt = (wine / "dlls/winegstreamer/quartz_transform.c").read_text()
offers = function(qt, "static HRESULT mpeg_video_codec_source_get_media_type(")
assert offers.index("WG_VIDEO_FORMAT_YV12") < offers.index("WG_VIDEO_FORMAT_YUY2"), offers
glue = (root / "build/ntdll-unix/winegstreamer_unixlib_ios.c").read_text()
assert "case MAKEFOURCC('Y','U','Y','2'): return MAV_PIX_YUY2;" in glue, "the video transform writes YUY2"
print("PASS: quartz's MPEG video decoder offers YV12 before YUY2, and our video transform writes YUY2")

# ---- 6. top-down RGB from the decoding splitter -------------------------------------
native_fmt = function(glue, "static enum mav_pixel_format wg_video_native_format(")
assert "if (!v || !*v) return MAV_PIX_BGRx;" in native_fmt, \
    "the parser's default native video format is BGRx (RGB32, top-down)"

qp = (wine / "dlls/winegstreamer/quartz_parser.c").read_text()
decodebin_mt = function(qp, "static HRESULT decodebin_parser_source_get_media_type(")
assert decodebin_mt.index("wg_parser_stream_get_current_format(") \
    < decodebin_mt.index("amt_from_wg_format(mt, &format, false)") \
    < decodebin_mt.index("video_formats[index]"), \
    "the decoding splitter offers the stream's current format before the bottom-up fallback table"
amt_video = function(qp, "static bool amt_from_wg_format_video(")
assert re.search(
    r"if \(wg_video_format_is_rgb\(format->u\.video\.format\)\)\s*"
    r"video_format->bmiHeader\.biHeight = -format->u\.video\.height;",
    amt_video,
), "amt_from_wg_format_video negates biHeight for top-down RGB"
print("PASS: the decoding splitter offers top-down RGB32 (biHeight < 0) first")

presenter = (wine / "dlls/quartz/vmr7_presenter.c").read_text()
alloc_surf = function(presenter, "static HRESULT WINAPI surface_allocator_AllocateSurface(")
assert "surface_desc.dwHeight = abs(info->lpHdr->biHeight);" in alloc_surf, alloc_surf
assert "surface_desc.dwHeight = info->lpHdr->biHeight;" not in alloc_surf, alloc_surf

alloc_vmr7 = function(vmr7, "static HRESULT allocate_surfaces(")
assert "info.szAspectRatio.cy = info.szNativeSize.cy = abs(bitmap_header.biHeight);" in alloc_vmr7, alloc_vmr7
assert "info.lpHdr = &bitmap_header;" in alloc_vmr7, "AllocateSurface still receives the connection's BITMAPINFOHEADER"
connect_vmr7 = function(vmr7, "static HRESULT vmr_connect(")
assert "SetRect(&rect, 0, 0, bitmap_header->biWidth, abs(bitmap_header->biHeight));" in connect_vmr7, connect_vmr7
defrect_vmr7 = function(vmr7, "static void vmr_get_default_rect(")
assert "SetRect(rect, 0, 0, bitmap_header->biWidth, abs(bitmap_header->biHeight));" in defrect_vmr7, defrect_vmr7
native_vmr7 = function(vmr7, "static HRESULT WINAPI windowless_control_GetNativeVideoSize(")
assert "*height = abs(bitmap_header->biHeight);" in native_vmr7, native_vmr7
assert "*aspect_height = abs(bitmap_header->biHeight);" in native_vmr7, native_vmr7
assert "info.szAspectRatio.cy = abs(height);" in render, render
assert "else if (height > 0 && (bitmap_header->biCompression == BI_RGB || bitmap_header->biCompression == BI_BITFIELDS))" in render, \
    "vmr_render flips RGB only when biHeight > 0"
assert "height = abs(height);" in render and "memcpy(surface_desc.lpSurface, data, data_size);" in render, \
    "top-down RGB copies forward (pitch-converting or memcpy)"

window_c = (wine / "dlls/quartz/window.c").read_text()
for fn in [
    "static HRESULT WINAPI basic_video_get_VideoHeight(",
    "static HRESULT WINAPI basic_video_put_SourceTop(",
    "static HRESULT WINAPI basic_video_put_SourceHeight(",
    "static HRESULT WINAPI basic_video_SetSourcePosition(",
    "static HRESULT WINAPI basic_video_SetDefaultSourcePosition(",
    "static HRESULT WINAPI basic_video_GetVideoSize(",
    "static HRESULT WINAPI basic_video_IsUsingDefaultSource(",
]:
    body = function(window_c, fn)
    assert "biHeight" in body, fn
    assert not re.search(r"(?<!abs\()(?<!abs\(get_bitmap_header\(window\)->)(?<!abs\(bitmap_header->)biHeight", body), body
assert len(re.findall(r"->biHeight", window_c)) == len(re.findall(r"abs\([^;\n]*?->biHeight\)", window_c)), \
    "unwrapped ->biHeight in window.c"

vmr9 = (wine / "dlls/quartz/vmr9.c").read_text()
assert "info.dwHeight = info.szAspectRatio.cy = info.szNativeSize.cy = abs(bmiheader->biHeight);" in function(
    vmr9, "static HRESULT allocate_surfaces("
)
assert "SetRect(&rect, 0, 0, bitmap_header->biWidth, abs(bitmap_header->biHeight));" in function(
    vmr9, "static HRESULT vmr_connect("
)
assert "SetRect(rect, 0, 0, bitmap_header->biWidth, abs(bitmap_header->biHeight));" in function(
    vmr9, "static void vmr_get_default_rect("
)
assert "bih.biHeight = abs(bih.biHeight);" in function(vmr9, "static HRESULT vmr_get_current_image(")
native_vmr9 = function(vmr9, "static HRESULT WINAPI VMR9WindowlessControl_GetNativeVideoSize(")
assert "*height = abs(bmiheader->biHeight);" in native_vmr9 and "*aspect_height = abs(bmiheader->biHeight);" in native_vmr9
assert "info.szAspectRatio.cy = abs(height);" in function(vmr9, "static HRESULT vmr_render(")
print("PASS: the VMR-7 presenter, VMR-7, VMR-9 and IBasicVideo use abs(biHeight) for surfaces, rects and sizes")
