# Media: winegstreamer on FFmpeg, VideoToolbox and AudioToolbox

Upstream Wine implements the unix side of `winegstreamer.dll` with GStreamer,
which does not exist on iOS. Without it `winegstreamer.dll` cannot load, and
three things that Windows programs use every day have no decoder:

- the Windows WMA decoder MFT/DMO (`CLSID_CWMADecMediaObject` in `wmadmod.dll`,
  which forwards to `CLSID_wg_wma_decoder` in winegstreamer). FAudio asks COM
  for it for every xWMA/XMA voice; without it the compressed bytes reached the
  mixer as PCM, which sounds like loud static;
- quartz's MPEG-I and "GStreamer" splitters (DirectShow MP3/WAV playback);
- Media Foundation's fallback media source (MP4/MOV video through the source
  resolver);
- the Windows Media Format reader (`wmvcore`: `WMCreateReader`,
  `WMCreateSyncReader`, and DirectShow's WM ASF Reader on top of it), which
  plays WMV/WMA (ASF) files. A visual novel's cutscenes went through it; the
  reader failed to connect (`no enabled demuxer recognised the stream`,
  `0x80040265`) and the game showed a white screen with no sound;
- the WMVideo Decoder DMO and MFT (`CLSID_CWMVDecMediaObject`, Wine's
  `wmv_decoder_create()` in `dlls/winegstreamer/video_decoder.c`), which a
  DirectShow graph or a Media Foundation pipeline uses to decode compressed
  Windows Media video. Sabbat of the Witch's `krmovie.dll` reads compressed
  WMV3 samples from `IWMSyncReader` and decodes them with it; without it the
  DMO could not even be created and the cutscenes were a white screen.

This port supplies that unix side in `libntdll_unix.a`, bound by name in
`load_builtin_unixlib()` (`build/ntdll-unix/virtual_ios.c`).

**By default only 32-bit (WoW64) processes get it.** A 64-bit (ARM64EC)
process gets the generic stub table, which is what every module without a
unix side gets and what `winegstreamer` got before this code existed, so the
64-bit engine behaves exactly as it did: a 64-bit game's Media Foundation or
DirectShow playback finds no media backend. `MADEIRA_WG_64BIT=1` (or
`env.MADEIRA_WG_64BIT = 1` in `madeira.cfg`) opts 64-bit processes in. The
arm64ec `winegstreamer.dll` they need ships in the app bundle
(`app/Madeira/arm64ec-windows/winegstreamer.dll`, built by
`build/wine-pe/build-modules.sh`); the opt-in stays off by default until it
has been tested game by game.

## Pieces

| File | What it is |
|---|---|
| `build/ntdll-unix/winegstreamer_unixlib_ios.c` | Both unix call tables (entry for entry with `dlls/winegstreamer/unixlib.h`), the wow64 thunks, and three kinds of `wg_transform` on libavcodec: the WMA decoder `wma_decoder.c` uses (WMA v1/v2/Pro/Lossless, XMA1/2), the video decoder `video_decoder.c`'s WMVideo Decoder DMO/MFT and `quartz_transform.c`'s MPEG video decoder use (WMV1, WMV2, WMV3, WMVA, WVC1; MPEG-1/2 video; see below), and the MPEG audio decoder `quartz_transform.c`'s MPEG audio and layer-3 decoders use (layers I-III). `transform_create` gives a create to the first kind that claims its input type; every other entry finds the kind by the magic its object starts with. Raw audio in is a third kind, the resampler `resampler.c` uses, on libswresample (see below). Other transforms (AAC, H.264, the colour converter) are refused at create, and `wg_muxer` returns `STATUS_NOT_IMPLEMENTED`. |
| `build/ntdll-unix/wg_parser_av_ios.c` | The `wg_parser` core, `#include`d by the file above: the PE read thread's pull protocol as an AVIOContext (with RIFF/CDXA 2352-byte sector unwrapping for VideoCD `.dat` files), libavformat demux (mp3, wav, mov, asf, mpegps, mpegvideo, avi), MPEG audio / PCM / ADPCM / A-law / mu-law / WMA decode through libavcodec + libswresample, Windows Media video (WMV7/8/9, VC-1, MS-MPEG4 v1-v3), MPEG-1/2 video and AVI video (MPEG-4/Xvid/DivX, MJPEG, Cinepak, MS Video 1, MS RLE, Indeo 3-5, raw video) decoded in software by libavcodec (`mav_lavc_video`), a packet queue with back-pressure, B-frame reordering, keyframe seek with exact trim, and conversion (`mav_convert_picture`, which the WMV transform uses too) to the formats `quartz_parser.c`, `media_source.c` and `wm_reader.c` ask for: NV12, I420, YV12, YUY2, UYVY, YVYU, BGRx, BGRA, RGBA, 24-bit BGR (the WM reader's default, bottom-up), RGB565 and RGB555. |
| `build/ntdll-unix/wg_parser_apple_ios.c` | H.264/HEVC on VideoToolbox (NV12 out) and AAC on an AudioToolbox AudioConverter (float PCM out). Its own translation unit with no Wine or FFmpeg header. |
| `build/ntdll-unix/wg_parser_backend_ios.h` | The contract between the core and a decoder backend; plain C types only, so the host test can supply stub backends. |
| `build/ffmpeg/build.sh` | FFmpeg 7.1.5, pinned by SHA-256, LGPL-only configuration. |

FFmpeg is built with no H.264, HEVC or AAC decoder or parser: those streams go
to the platform decoders. Windows Media video has no platform decoder on iOS,
so FFmpeg's LGPL `wmv1`, `wmv2`, `wmv3`, `vc1` and `msmpeg4v1-3` decoders are
built and decode it on the CPU (one thread, FFmpeg's C code: `--disable-asm`),
and so are `mpeg1video` and `mpeg2video` for MPEG program streams (with the
`mpegvideo` parser, and the `mpegvideo` demuxer, which `mpegps` probes a
program stream's video with), plus the AVI video (`mpeg4`, `mjpeg`, `cinepak`,
`msvideo1`, `msrle`, `indeo3`, `indeo4`, `indeo5`, `rawvideo`, with the
`mpeg4video` and `mjpeg` parsers) and ADPCM / A-law / mu-law audio
(`adpcm_ms`, `adpcm_ima_wav`, `pcm_alaw`, `pcm_mulaw`) decoders.
See `THIRD-PARTY-NOTICES.md` for the exact component list and its licence.

**Containers and codecs.** MP3/WAV: MPEG audio, PCM, ADPCM and A-law/mu-law.
MP4/MOV: H.264 or HEVC video (VideoToolbox) with AAC, MPEG audio or PCM. ASF
(WMV/WMA): Windows Media video (libavcodec) with WMA v1/v2/Pro/Lossless or
MPEG audio. MPEG program streams (`.mpg`, MPEG-1 and MPEG-2) and RIFF/CDXA
VideoCD sector files (`.dat`, unwrapped to 2324-byte packs): MPEG-1/2 video
(libavcodec) with MPEG audio. Raw MPEG-1 video elementary streams
(`.m1v`/`.mpv`): MPEG-1 video (libavcodec), timed in display order from the
sequence header's frame rate and each picture's `temporal_reference`. AVI
(`.avi`): MPEG-4 Part 2 (Xvid, DivX, DX50, FMP4, MP4V), MJPEG, Cinepak, MS
Video 1, MS RLE, Indeo 3/4/5, raw video, Windows Media / MS-MPEG4 and MPEG-1/2
video (all libavcodec; H.264 in AVI is refused under the platform-decoder-only
policy) with PCM, ADPCM (`adpcm_ms`, `adpcm_ima_wav`), A-law, mu-law, MPEG
audio or WMA. Raw MPEG-2 video (`.m2v`), transport streams, Bink and the like
are not handled here (Bink and most engines' own formats are decoded by the
game itself). The codec format of an
ASF stream (`wg_parser_stream_get_codec_format`) is the one Wine's GStreamer
backend reports: WMV1/WMV2/WMV3/WMVA/WVC1 video, WMA audio with its version,
block alignment and codec data, so a game that reads the file's profile
through `IWMProfile` sees the real stream types.

**The video format a stream reports: RGB32.** A video stream's native format
(the media type Media Foundation's source lists first) is RGB32 by default,
although VideoToolbox decodes to NV12 and the picture is converted on the CPU.
A media session connects a source straight to its renderer with that native
type only. The EVR accepts NV12, and the session then asks the EVR's sample
allocator for NV12 Direct3D 9 surfaces. DXMT, this port's d3d9, has no YUV
surface format, so the allocator fails. The session then drops the renderer's
output node and every node after it, and still reports that playback
started. No sample is ever requested, the audio renderer never starts, and the
title shows an empty video window. Senren Banka's CG movie did this (an MP4
through krkrz's MFPlayer; the workaround was `MADEIRA_WG_VIDEO=0`, which skips
the movie). RGB32 surfaces are ordinary DXMT surfaces. A source reader that
asks for NV12 still gets it from the YUV types listed after the native one.
`MADEIRA_WG_VIDEO_FORMAT=nv12` restores the old default. Each stream logs
`stream N: first picture delivered` (or `first audio buffer delivered`) once,
so a device log shows whether any sample was ever requested.

**Compressed samples from the WM reader.** An application can ask the WM
reader (`IWMSyncReader::SetReadStreamSamples`) for a stream's compressed
samples and decode them itself. KiriKiri's movie plugin (`krmovie.dll`) does
this for both streams of a WMV and feeds them to the WMV and WMA decoder DMOs
(Sabbat of the Witch's video CGs). The reader then opens a compressed-output
parser. This port's parser refused every compressed-output parser for an ASF,
and Wine's reader freed its streams when that reinit failed but kept their
count, so the next call wrote through a NULL array. Now:
- a compressed-output parser exposes an ASF's streams as the decoding one does
  (Wine's reader asserts the counts match);
- its WMA, WMV1/2/3, WMVA and WVC1 streams report their codec format as the
  current format and, enabled with it, hand out the demuxer's packets as they
  are: the file's bytes, keyframe flags (`delta`) and timestamps;
- after a seek the video starts at a keyframe;
- a stream enabled with a raw format in the same parser is decoded as usual
  (MS-MPEG4, which has no `wg_format`, always is);
- Wine's reader (in the wine submodule) chooses compressed or decoded per
  stream, keeps its streams when a reinit fails, goes back to the previous
  parser, and fails instead of asserting when the stream counts differ.

Each compressed stream logs `first compressed packet delivered` once.
`MADEIRA_WG_COMPRESSED=0` refuses compressed output for an ASF again.

**MPEG program streams (`.mpg`), raw MPEG-1 video (`.m1v`/`.mpv`) and VideoCD (`.dat`).**
Older visual novels play their movies as MPEG-1 program streams, raw MPEG-1
video elementary streams or RIFF/CDXA VideoCD `.dat` files through DirectShow,
two ways:
- `RenderFile`: quartz's MPEG-1 splitter takes nothing from a decoding parser,
  so for MPEG-2 program streams the graph falls through to winegstreamer's
  decoding splitter, which this parser serves with decoded pictures and PCM.
- A graph built by hand: KiriKiri's krmovie maps `.mpg`/`.mpeg` to
  `MEDIASUBTYPE_MPEG1System`, `.m1v`/`.mpv` to `MEDIASUBTYPE_MPEG1Video` and
  `.dat` to `MEDIASUBTYPE_MPEG1VideoCD`, connects its async reader to quartz's
  `CLSID_MPEG1Splitter` directly (which accepts all four MPEG-1 stream subtypes,
  and seeks the reader of a system stream to the end of the file on connect), and connects the
  splitter's output pins to `CLSID_CMpegVideoCodec` and `CLSID_CMpegAudioCodec`,
  and from them to its RGB32 buffer renderer (bottom-up) or VMR-9. BURIKO reads
  the picture size from the splitter's MPEG video format while connecting
  (krkrwine's notes). A compressed-output parser here hands out an MPEG program
  or raw MPEG-1 video stream's MPEG-1 video and MPEG audio as the demuxer's
  packets, and reports them as `WG_MAJOR_TYPE_VIDEO_MPEG1` (size, frame rate)
  and `WG_MAJOR_TYPE_AUDIO_MPEG1` (layer, rate, channels). MPEG-2 video has no
  `wg_format`: in a program stream it stays decoded, quartz's MPEG-1 splitter
  then gives way, and the decoding splitter plays it; a raw MPEG-2 `.m2v` is
  refused.

Raw MPEG-1 video elementary streams (FFmpeg's `mpegvideo` demuxer) carry no PES
timestamps, and `rawdec` defaults `avg_frame_rate` to 25 fps before parsing:
the parser reads the sequence header's `frame_rate_code` for the real rate and
stamps each picture with `frame_number * frame_duration` in display order from
its GOP base and 10-bit `temporal_reference` (handling both open and closed
GOPs and 1024-frame wraps), in both decoded and compressed modes, and rewinds
and scans to the target's keyframe GOP on seek. VideoCD `.dat` files wrap
2352-byte CD-ROM XA Mode 2 sectors in a `RIFF`/`CDXA` container, which FFmpeg's
demuxers do not unwrap (`psxstr` handles PlayStation STR only): the AVIO read
path unwraps each Mode 2 Form 2 sector's 2324-byte user payload (after the
24-byte sync/MSF/subheader, dropping the 4-byte EDC trailer, and zero-stuffing
empty or Form 1 ISO sectors so byte seeking stays exact) before `mpegps` sees
the stream. `MADEIRA_WG_MPEG_RAW=0` refuses raw `.m1v` and skips `RIFF`/`CDXA`
unwrapping again.

A program stream's clock starts anywhere, and its streams start a little
apart: they count from the earliest start, so audio and video stay in sync.
It seeks to a pack by timestamp, not to a keyframe: the parser seeks a second
early, drops pictures until the first keyframe, and trims to the target. The
decoders behind quartz's MPEG filters are two more `wg_transform` kinds:
- the video decoder (above and below) takes MPEG-1/2 too, through libavcodec's
  `mpegvideo` parser, since a sample holds whatever the splitter cut; quartz's
  probe (MPEG1Payload 1920x1080 to NV12) needs no sequence header;
- the MPEG audio decoder (layers I-III, `WAVE_FORMAT_MPEG` and
  `WAVE_FORMAT_MPEGLAYER3`) decodes through the `mpegaudio` parser into the PCM
  or float the output type asks for. Media Foundation's MP3 decoder (`mp3dmod`)
  is Wine's own.
Both parsers read past the end of their input, so a sample is copied with
FFmpeg's padding first.

**AVI files (`.avi`).** A visual novel's `.avi` movie reaches this parser on
its decoded path in both DirectShow and Media Foundation: a compressed-output
parser keeps refusing AVI (compressed AVI splitter output is not implemented),
so Wine's AVI splitter and Media Foundation's AVI handler fall back to
winegstreamer's decoding splitter (`CLSID_decodebin_parser`) and media source,
which open a decoding `wg_parser`. Video is decoded by `mav_lavc_video`
(`mpeg4` including DivX packed B-frame bitstreams, `mjpeg`, `cinepak`,
`msvideo1`, `msrle`, `indeo3`, `indeo4`, `indeo5`, `rawvideo`, plus the
existing MS-MPEG4 / WMV / MPEG-1/2 decoders; H.264 in AVI stays off), with the
`mpeg4video` and `mjpeg` parsers so libavformat derives B-frame presentation
times from the AVI index. Non-4:2:0 decoder outputs (MJPEG 4:2:2/4:4:4, Indeo
4:1:0, Cinepak `rgb24`, MS Video 1 `rgb555`/`pal8`, MS RLE `pal8`/monochrome,
bottom-up raw `bgr24`) are converted straight into the core's NV12 picture
layout without `libswscale`, and paletted streams keep their `BITMAPINFOHEADER`
palette across seeks. Audio uses the existing libavcodec + libswresample path
(`pcm_*`, `adpcm_ms`, `adpcm_ima_wav`, `pcm_alaw`, `pcm_mulaw`, `mp1-3`, WMA).
`MADEIRA_WG_AVI=0` refuses AVI at connect again, and `MADEIRA_WG_VIDEO=0`
disables it with the other video containers.

**The WMV decoder (`wg_transform`).** `video_decoder.c` probes a WMV3
1920x1080 to I420 transform without codec private data when the DMO is
created (`check_video_transform_support`), and libavcodec cannot open `wmv3`
or `vc1` without it. So a create whose input type has no codec private data
succeeds with the decoder closed and logs `[decoder not open: ...]`; frames
pushed into such a transform are dropped and logged. A sequence header that
libavcodec refuses refuses the create. As in upstream's GStreamer
`wg_transform.c`, `push_data` only queues the compressed frame (at most
`input_queue_length` + 1, then `MF_E_NOTACCEPTING`) and `read_data` decodes
until a picture comes out. Nothing ready is `MF_E_TRANSFORM_NEED_MORE_INPUT`,
which the DMO turns into `S_FALSE`. A picture is never split, so
`WG_SAMPLE_FLAG_INCOMPLETE` (the DMO's `DMO_OUTPUT_DATA_BUFFERF_INCOMPLETE`,
on which Wine's DMO wrapper calls `ProcessOutput` again) is never set. Output
formats: NV12, YV12, I420/IYUV, YUY2, UYVY, YVYU, RGB32, ARGB32, ABGR32,
RGB24, RGB565 and RGB555, top-down or bottom-up
(`MFVideoFlag_BottomUpLinearRep`). NV11 and RGB8 are refused, as GStreamer
refuses them. The frame is laid out as upstream's does it (4-byte aligned
rows, NV12 at 2), or at the stride of the caller's 2D buffer. An aperture
smaller than the frame is where the picture goes. A picture is not scaled: a
different size is cropped or padded with black, unless the caller allowed a
format change (`MF_E_TRANSFORM_STREAM_CHANGE`, then `get_output_type`; WMV
callers never allow it). Each picture is a sync point and keeps the time and
duration of the sample it was coded in, flagged
`WG_SAMPLE_FLAG_PRESERVE_TIMESTAMPS`, as `video_decoder.c` expects. A sample
without a time gets the previous picture's end (the first gets 0) and one
frame at the input type's frame rate. `set_output_type` keeps the decoder and
the pictures it holds, and writes them in the new format. Limits: WMV3 and
VC-1 are checked by codec-id plumbing only, because FFmpeg cannot encode
them. The DMO never drains, so a picture the decoder holds back (WMV3 with
B-frames) is lost at the end of a stream, as with GStreamer. When the DMO
wrapper meets a new output media type, `video_decoder.c` makes a new
transform, whose new decoder waits for a keyframe.

**The resampler.** Media Foundation's topology loader puts winegstreamer's
resampler (`CLSID_CResamplerMediaObject`, `wg_resampler`) between a source's
PCM and the audio renderer, which takes only the device mix format. Its
`wg_transform` was refused here ("input format tag 0x1 is not a WMA family
stream"), so `resampler_create` failed. For Senren Banka's WMV movie (48 kHz
S16 from the WMA stream) the topology then had no audio branch and no
presentation clock, and the video renderer never presented. The resampler is
now libswresample:
- integer PCM of 8, 16, 24 or 32 bits and float of 32 or 64, in and out;
- `WAVEFORMATEX` or `WAVEFORMATEXTENSIBLE`, any rate, 1 to 8 channels;
- timestamps run from the input's, less what the resampler holds back, and do
  not drift.

It logs one `[resampler] created ...` line per transform.
`MADEIRA_WG_RESAMPLER=0` refuses it again.

**The video converters (`wg_transform`).** Media Foundation's color converter
(`CLSID_CColorConvertDMO`, `color_convert.c`) and video processor
(`CLSID_VideoProcessorMFT`, `video_processor.c`) are `wg_transforms` whose
input is raw video (`IMFSourceReader` with video processing enabled in Unity
visual novels, or a topology needing a format or frame-size change; upstream
Wine's `vidreszr.dll` registers `CLSID_CResizerDMO` as a stub). Without a
raw-video kind ahead of the WMV/MPEG decoder in `transform_kinds`, both failed
their `check_video_transform_support` (`I420` 1920x1080 -> `NV12` 1920x1080)
probe at creation. The `"video converter"` kind claims raw video inputs before
the decoder kind:
- converts between any pair of NV12, YV12, I420, IYUV, YUY2, UYVY, YVYU, AYUV,
  RGB32, ARGB32, ABGR32, RGB24, RGB565 and RGB555, top-down or bottom-up
  (`MFVideoFlag_BottomUpLinearRep`), at default strides, `output_plane_align`,
  or a 2D buffer's `sample->stride` on input and output, and honours input and
  output `MinimumDisplayAperture`s;
- reuses `mav_convert_picture` for unscaled 4:2:0 inputs to non-AYUV outputs,
  keeps YUV-to-YUV and RGB-to-RGB conversions in their own colour space (so
  planar/packed reorderings and alpha channels stay exact), and converts
  YUV<->RGB in BT.601 or BT.709 limited range;
- scales in plain C with edge-clamped pixel-center bilinear interpolation when
  the input and output active sizes differ.

It logs under `[vconv]`. `MADEIRA_WG_VIDEO_CONVERT=0` refuses it again.

**One demuxer, several readers: back-pressure.** Quartz reads each stream on
its own thread (Media Foundation's source does not; see decode-ahead below); a
packet read for another stream is queued for it. A stream whose reader falls behind (a video decoded slower
than real time) used to lose packets once its queue passed 16,384 packets or
64 MB, which breaks every picture up to the next keyframe. Now, once a queue
passes 1,024 packets or 16 MB while another thread reads that stream, the
reader that demuxes for it waits (without the parser lock, which the other
reader needs) until the queue has drained to three quarters of that. A stream
that is not read for 5 s is marked unread and queued without waiting (dropped
past the old hard limits, as before) until it is read again; one thread
reading both streams (the WM reader's earliest-buffer mode) never waits for
itself; a seek, a disable or disconnect wakes a waiting reader.

**Decode-ahead.** Wine's media source asks for every stream's samples on one
work-queue thread (a standard work queue has one thread), and so does the WM
reader reading the earliest buffer. Decoded on demand, each picture held that
thread. Senren Banka's 1080p WMV needs about 20 ms a picture in software, so
the audio request behind it was late, and the audio renderer ran short for 6
to 17% of each 10 s (`[ios_audio] ... client wrote 8.33 s of audio in 10.01 s`).
GStreamer decodes in streaming threads of its own. Here each decoded video
stream gets a worker at its first request:
- it keeps up to three pictures ready, and a request pops one;
- it demuxes under the parser lock like any reader;
- it decodes and converts without that lock, so the audio request is
  answered meanwhile;
- a seek, a new format or a disconnect waits for the picture the worker is
  on, and it starts no new one until they are done.

Each such stream logs `decoding ahead on a thread of its own` once.
`MADEIRA_WG_VIDEO_AHEAD=0` decodes on the requesting thread again.

**The video renderer on DXMT.** A Media Foundation movie reaches the EVR
through Wine's sample copier and the EVR mixer, both on Direct3D 9 surfaces
that Wine's DXVA2 creates. Two of Wine's choices only worked on wined3d, which
is lenient where native d3d9 and DXMT are not. Both are fixed in the wine
submodule:
- **A black picture.** `CreateSurface` made every surface an offscreen plain
  surface. The mixer's targets are the size of the video window (Senren:
  1920x1080 into 2360x1328), and `StretchRect` does not stretch into a
  surface that is not a render target, so the mixer left only its black
  background. `DXVA2_VideoProcessorRenderTarget` surfaces are now lockable
  render targets, and a scaled blit is filtered (`D3DTEXF_LINEAR`).
- **A GPU wait per frame.** The copier's `ContiguousCopyFrom` locked its
  target without flags, so DXMT read the surface back first and waited for
  the GPU: 9 to 12 ms per frame (`[d9-drain] ... avg-us=9300`), on the
  session thread that also feeds the audio. It now locks with
  `D3DLOCK_DISCARD`, since it overwrites every byte.

**DirectShow's default video renderer.** `RenderFile` connects video to the
"Video Renderer", which is the VMR-7 (the GDI renderer only if the VMR-7
cannot be created). The VMR-7 draws through DirectDraw, and DirectDraw through
wined3d, which has no 3D backend in this port: ddraw falls back to wined3d's
no3d adapter, whose CPU blitter converts only YUY2 to RGB. The VMR-7 takes RGB
and any FOURCC that DirectDraw lists, and quartz's MPEG video decoder offers
YV12 first, so an MPEG-1 movie through `RenderFile` connected in YV12. In no3d a
YV12 surface holds only its luma plane, so each frame's copy overran it, and
each blit failed: a black window, if the game did not crash. Without 3D, ddraw
now lists only YUY2 (wine submodule), and the VMR-7 takes the decoder's YUY2.
Movies that reach the renderer through the decoding splitter (MPEG-2, AVI) get
RGB32 first and were not affected. `tests/host/check-dshow-default-renderer.py`
pins the chain.

The PE half of winegstreamer is upstream's but for `wm_reader.c` (above). Wine's configure
disables the module when GStreamer is missing, so a PE build tree has to be
configured with `--enable-winegstreamer` (`build/wine-pe/build-ntdll.sh` does
this for the arm64ec tree) and only the PE target is built. A 32-bit
(i386) build tree needs the same flag and must not skip `winegstreamer.dll`;
the 32-bit processes that use this unix side get their `winegstreamer.dll`
and `wmadmod.dll` from that tree.

## Switches

Environment variables (`env.NAME = value` in `madeira.cfg`):

| Variable | Default | Effect |
|---|---|---|
| `MADEIRA_WG_64BIT` | off | `1`: 64-bit processes get the real unix side too (see above). |
| `MADEIRA_WG_PARSER` | on | `0`: `wg_parser_create` returns `STATUS_NOT_IMPLEMENTED` again, as before this series; quartz and the MF source then fail the way they did. The WMA decoder is unaffected. |
| `MADEIRA_WG_VIDEO` | on | `0`: MP3/WAV only; an MP4/MOV, ASF, MPEG program stream or AVI is refused at connect. |
| `MADEIRA_WG_AVI` | on | `0`: an AVI file is refused at connect again, while the other video containers stay enabled. |
| `MADEIRA_WG_WMV_TRANSFORM` | on | `0`: the WMV/MPEG video decoder `wg_transform` is refused at create again, so the WMVideo Decoder DMO/MFT and quartz's MPEG video decoder cannot be created, as before. Read once per process. WMA and the video converter are unaffected. |
| `MADEIRA_WG_VIDEO_CONVERT` | on | `0`: the raw video converter `wg_transform` is refused at create again, so `CLSID_CColorConvertDMO` and `CLSID_VideoProcessorMFT` cannot be created, as before. |
| `MADEIRA_WG_MPEG_TRANSFORM` | on | `0`: the MPEG audio `wg_transform` is refused at create, so quartz's MPEG audio and layer-3 decoders cannot be created, as before. |
| `MADEIRA_WG_RESAMPLER` | on | `0`: the resampler transform is refused at create, as before. |
| `MADEIRA_WG_COMPRESSED` | on | `0`: a compressed-output parser refuses an ASF, an MPEG program stream and a raw MPEG-1 video stream, as before: the WM reader's compressed samples are not available, and quartz's MPEG-1 splitter gives way to the decoding splitter (see above). |
| `MADEIRA_WG_MPEG_RAW` | on | `0`: raw MPEG-1 video elementary streams (`.m1v`/`.mpv`) are refused at connect and `RIFF`/`CDXA` VideoCD `.dat` sectors are not unwrapped, as before. |
| `MADEIRA_WG_VIDEO_AHEAD` | on | `0`: video is decoded on the thread that asks for it, as before; a Media Foundation movie's audio then waits behind each picture (see above). |
| `MADEIRA_WG_VIDEO_FORMAT` | `rgb32` | Native format a video stream reports: `nv12`, `i420`, `yv12`, `yuy2`, `rgb32`, `argb32` or `abgr32` (see above for why the default is `rgb32`). |
| `MADEIRA_WG_SUMMARY` | on | `0`: omit the one-line playback summaries per parser stream (`stream N first:`, `stream N summary:`) and per `wg_transform` (`destroy:`), restoring the previous log output. |
| `MADEIRA_WMA_SEARCH` | on | `0`: keep the WMA v1/v2 decoder at the bit rate and flags it opened with; no search over other candidates when a bit-reservoir stream fails. A packet that fails is concealed with silence of its length and the next one is decoded as usual. (An xWMA stream still opens at the rate libavformat's xWMA table normalises to.) |
| `MADEIRA_WMA_DUMP` | off | Set: write each WMA decoder's input to `wma-dump-<n>.bin` in the Documents folder, for reproducing a decode failure on a host. |

## Reading playback logs

Log tags: `[wg-parser]` for the parser, `[wmv]` for the WMV and MPEG-1/2 video
decoder, `[vconv]` for the video converter, `[wma]` for the WMA decoder, and
`[resampler]` for the resampler and the MPEG audio decoder (plus `av:` lines
from libavformat/libavcodec routed under the owner's tag). All are rate-limited
per process (`[wg-parser]` deduplicates identical lines and caps at 63 distinct
lines; `MADEIRA_DIAG=1` lifts the `[wma]`, `[wmv]`, `[vconv]` and `[resampler]`
caps).

**Parser stream summaries (`[wg-parser]`).** Each exposed stream logs one line
on its first delivered buffer (`stream N first: ...`, in case the game hangs or
is closed mid-movie) and one line at disconnect (`stream N summary: ...`). The
summaries have a budget of their own, 48 lines per process, outside the 63
distinct lines: a game that plays many short clips does not crowd out the lines
of the movie that fails after them.

```text
[wg-parser] ml1990 stream 0 summary: container=mp4 codec=h264 backend=videotoolbox out=bgrx 1920x1080 mode=ahead delivered=300 dropped=0 (trim=0 errors=0 bp=0) wait=0.12/22.40ms decode=4.80/11.20ms
```

Fields:
- `container`, `codec`, `backend`: the demuxer (`mp4`, `asf`, `mpeg`, `mp3`,
  `wav`), libavcodec's codec name, and the decoder backend (`videotoolbox`,
  `audiotoolbox`, `libavcodec`).
- `out`: what the caller actually enabled — `compressed` when handing out
  demuxer packets, `<pixfmt> <w>x<h>` for decoded video (a negative height
  means bottom-up rows), or `<samplefmt> <rate>Hz <ch>ch` for decoded audio.
- `mode`: `compressed` (packets passed through), `ahead` (video decoded on its
  own worker thread), or `on-demand` (audio, or video with
  `MADEIRA_WG_VIDEO_AHEAD=0`). ` [disabled]` follows when the stream was
  disabled at disconnect.
- `delivered`: unique pictures, audio buffers or compressed packets handed out
  by `wg_parser_stream_get_buffer`.
- `dropped (trim=T errors=E bp=B)`: total items discarded and why:
  - `trim`: pictures, audio buffers or post-seek delta packets before the seek
    target (including MP4 audio edit-list lead-in at time 0). Non-zero after a
    keyframe seek is normal.
  - `errors`: packets rejected by the decoder, unmappable pictures, or failed
    sample conversions.
  - `bp`: packets dropped past the hard queue limit after a stream went unread
    for `MAV_BACKPRESSURE_WAIT_MS` (5 s).
- `wait=avg/maxms`: average and worst-case wall time `get_buffer` spent
  waiting for each delivered buffer (lock, demux/AVIO read, back-pressure wait,
  and either the decode-ahead worker or synchronous decode).
- `decode=avg/maxms` (decoded streams only): average and worst-case decoder +
  pixel/sample conversion time per picture or audio buffer, excluding demuxing
  and back-pressure waits.

**Transform summaries (`[wmv]`, `[vconv]`, `[wma]`, `[resampler]`).** Each `wg_transform`
that received a sample logs one `destroy:` line when torn down (with its
`created` line at open); the support probes, created and destroyed unused, log
none:
- `[wmv] destroy: transform 0x..., WMV3 1280x720 -> bgrx 1280x-720 bottom-up: S samples in, P pictures out, R rejected by the decoder, D dropped without a decoder, L lost to memory`
- `[vconv] destroy: transform 0x..., i420 -> nv12: F frames in, O out, S short dropped`
- `[wma] destroy: transform 0x..., wmav2 44100 Hz 2ch block=2973 (128000 bit/s) -> s16 44100 Hz 2ch: S samples (K packets) in, O samples (F frames) out, E packet errors (Z silence frames)` (plus `[muted]` if the parameter ladder exhausted without a valid decode)
- `[resampler] destroy: transform 0x..., s16 48000 Hz 2ch -> f32 48000 Hz 2ch: S samples (I frames) in, O samples (F frames) out, E errors`
- `[resampler] MPEG audio destroy: transform 0x..., MPEG-1 layer II 44100 Hz 2ch -> s16 44100 Hz 2ch: S samples (B bytes) in, O samples (F frames) out, E errors`

**How to read a failure from one or two lines:**
- **Refused at open:** `[wg-parser] ... connect refused (...)` or a transform
  refusal line names the container, codec or format and why; no summary line
  follows.
- **Downstream topology or renderer failure (empty/white/black window, silent):**
  `connect` succeeds, no `stream N first:` appears, and `stream N summary:`
  reports `delivered=0` (or a transform has a `created` line and no `destroy:`
  line, or one with `0 ... out`). Nobody downstream ever requested
  samples — e.g. an EVR surface-allocator or audio mix-format negotiation
  failure.
- **Hung or closed mid-movie:** `stream N first:` is present without a matching
  `stream N summary:`. It shows whether the first picture/buffer was delivered
  and what format, mode and initial `wait`/`decode` times it had before the
  session stalled.
- **Undecodable bitstream or missing sequence header:** `errors>0` in `stream N
  summary:` (past 512 consecutive errors the stream ends), `rejected by the
  decoder > 0` or `dropped without a decoder > 0` in `[wmv] destroy:`, or
  `packet errors > 0` / `[muted]` in `[wma] destroy:`.
- **Unread stream stalling the demuxer:** `stream N: not read for 5000 ms ...`,
  `delivered=0` with `bp>0` on that stream, and `wait` max ~5000 ms with tiny
  `decode` max on the sibling stream.
- **Decode slower than real time (stutter or audio underruns):** `decode` avg
  approaches or exceeds the frame period (e.g. >33 ms at 30 fps) and `wait` avg
  rises toward `decode` avg even with `mode=ahead` (the 3-picture lookahead is
  starved), or `mode=on-demand` shows `MADEIRA_WG_VIDEO_AHEAD=0` blocking the
  shared request thread on every picture.

## Tests

- `tests/host/check-wg-parser.py` (Linux): source checks on the call
  tables, wow64 thunks, kill switches, FFmpeg configuration and app link; then
  builds a host FFmpeg from the same tarball and runs the parser core under
  ASan/UBSan against MP3, MPEG layer II, WAV and synthetic MP4 (stub video and
  AAC backends), every picture format pixel by pixel. Decode-ahead: with a
  stub decoder that takes 20 ms a picture and one thread asking for both
  streams at 30 fps (the media source's way), a video request takes 0.0 ms
  instead of 21. Every picture still comes in order, the audio has no gaps, a
  seek lands exactly, and a disconnect mid-decode is clean. The threaded cases
  run again under ThreadSanitizer.
- `tests/host/check-wg-parser-asf.py` (Linux): builds a host FFmpeg from the
  same tarball with the port's demuxers and decoders and test-only WMV/WMA
  encoders and the asf muxer, synthesises WMV7, WMV8 and MS-MPEG4 v3 files
  with WMA2 audio, and checks under ASan/UBSan, against an independent
  libavcodec decode of the same file: every picture bit-exact, in order; the
  WM reader's way (bottom-up BGR, S16, earliest-buffer reads) to the end; every
  format it offers after a keyframe seek; a WMV3 stream of garbage; and, with
  small queue limits, the back-pressure cases (a slow video reader loses
  nothing, while the same build without back-pressure drops pictures; an
  unread stream; one thread reading both, and the worker decoding ahead for
  it; disconnect while a reader waits).
  Compressed output: every packet of WMV7, WMV8, the WMV3 garbage stream and
  WMA2 against an independent demux of the same file (bytes, keyframe flags,
  timestamps); compressed video with decoded audio; a seek starting at a
  keyframe; back to decoded pictures, bit-exact; MS-MPEG4 refused compressed;
  `MADEIRA_WG_COMPRESSED=0`. Also source checks on Wine's reader (per-stream
  compressed reading, no `free_streams` in a failed reinit). With video
  decoded ahead (the default), every case above runs again under
  ThreadSanitizer, the back-pressure ones included.
  WMV9/VC-1 streams themselves are not covered: FFmpeg cannot encode them.
- `tests/host/check-mf-video-render.py`: source checks on the path a Media
  Foundation movie takes to the screen:
  - DXMT's StretchRect rule the DXVA2 fix answers, and its discard lock;
  - Wine's DXVA2 render targets and filtered scaling;
  - mfplat's discard copy;
  - the allocators that ask for `DXVA2_VideoProcessorRenderTarget`;
  - the one-thread work queue that makes decode-ahead necessary.
- `tests/host/check-dshow-default-renderer.py`: source checks on the path from
  `RenderFile`'s default renderer to wined3d's CPU blitter, and that ddraw lists
  only YUY2 without 3D.
- `tests/host/check-wma-decoder.py` (Linux or macOS, needs a configured
  Wine tree for the generated headers): compiles the production
  `winegstreamer_unixlib_ios.c` under ASan/UBSan against a host FFmpeg built
  from the tracked tarball, encodes WMA v1 and v2 streams (a 440 Hz tone) with
  FFmpeg's own encoders at several rates and channel counts, drives them
  through the `wg_transform` entries the way `wma_decoder.c` does, to s16 and
  to float, with the parameter search on and off, and requires audio with the
  right level and fundamental back. Also checks that 64-bit callers keep the
  stub table by default. Bit-reservoir (superframe) streams are not covered:
  FFmpeg cannot encode them.
- `tests/host/check-wmv-transform.py` (Linux or macOS, needs a configured
  Wine tree): source checks on both call tables, the kind table, the switch,
  and the facts of the Wine pin the transform relies on. Then it compiles the
  production file under ASan/UBSan against the host FFmpeg build that
  `check-wg-parser-asf.py` uses, encodes WMV7 and WMV8 streams with FFmpeg's
  encoders, and drives them through both call tables. It checks: every
  picture bit-exact against libavcodec; every output format in both
  orientations at the default layout and at a 2D buffer's stride, pixel by
  pixel with the bytes around them untouched; apertures, cropping and
  padding; timestamps; the queue limit, drain, flush, mid-stream
  `set_output_type`, a format change, a buffer too small; Wine's DMO-wrapper
  loop; two threads; refusals; the wow64 thunks with 32-bit argument blocks
  below 4 GB; WMA through the same dispatcher; and
  `MADEIRA_WG_WMV_TRANSFORM=0`. WMV3/WVC1/WMVA are covered by codec-id
  plumbing only (the DMO's probe, hand-built sequence headers, garbage
  frames): FFmpeg cannot encode them.
- `tests/host/check-wg-mpeg.py` (the core on any host; the glue needs a
  configured Wine tree, like the WMA test): synthesises MPEG-1 and MPEG-2
  program streams (B-frames, MP2 audio) with FFmpeg's encoders. Checks:
  - every picture bit-exact against an independent decode, in order, decoded
    ahead; the tone; audio and video on one clock;
  - an exact seek, and a rewind to 0 after the end (KiriKiri's
    `put_CurrentPosition(0)`);
  - compressed output for quartz's MPEG-1 splitter, packet by packet against an
    independent demux; MPEG-2 video not passed; `MADEIRA_WG_COMPRESSED=0`;
  - raw MPEG-1 video elementary streams (`.m1v` at 25 and 30000/1001 fps with
    open-GOP B-frames) in decoded and compressed splitter modes: sequence-header
    frame rate, display-order `temporal_reference` timestamps, bit-exact NV12,
    rewind and seeks (including onto an open-GOP B-frame); raw MPEG-2 (`.m2v`)
    refused;
  - VideoCD `RIFF`/`CDXA` `.dat` sector files (2352-byte Mode 2 Form 2 sectors
    with 24-byte headers, 4-byte EDC trailers, empty pre-gap and Form 1 ISO
    sectors) unwrapped in the AVIO layer, in decoded and compressed splitter
    modes;
  - `MADEIRA_WG_MPEG_RAW=0` restoring `.m1v` and `.dat` refusal;
  - through the glue: the splitter's `WG_MAJOR_TYPE_VIDEO_MPEG1` size and frame
    rate (BURIKO's and KiriKiri's `.mpg`, `.m1v` and `.dat`) and MPEG audio
    formats; the MPEG video decoder's probe, the
    MPEG-1 and MPEG-2 elementary streams pushed in 997-byte pieces, bit-exact,
    and RGB32 bottom-up within 1 of BT.601; the MPEG audio decoder's probes and
    MP2 in 333-byte pieces to S16 and float; refusals,
    `MADEIRA_WG_MPEG_TRANSFORM=0` and `MADEIRA_WG_MPEG_RAW=0`;
  - the threaded cases again under ThreadSanitizer.
- `tests/host/check-wg-parser-avi.py` (Linux): source checks on the FFmpeg
  configuration (the `avi` demuxer, the AVI video and ADPCM/A-law/mu-law audio
  decoders, `mpeg4video` and `mjpeg` parsers, still no H.264/HEVC/AAC), the
  `MADEIRA_WG_AVI` switch, `docs/MEDIA.md` and the catalog; then compiles the
  parser core under ASan/UBSan against the shared host FFmpeg build and
  synthesises AVI files with FFmpeg's own encoders: `mpeg4` with B-frames +
  `adpcm_ima_wav`, a DivX packed-bitstream `mpeg4` (`[P+B]` chunks + N-VOPs),
  `mjpeg` (`yuvj422p`) + PCM, `msvideo1` (`rgb555`) + `adpcm_ms`, `cinepak`
  (`rgb24`) + `pcm_alaw`, bottom-up `rawvideo` (`bgr24`) + `pcm_mulaw`, and
  `msrle` (`pal8`). Checks every picture in order against an independent
  libavcodec decode (bit-exact for 4:2:0 sources, within format-conversion
  accuracy for 4:2:2, RGB and paletted sources) and the audio tone; keyframe
  seek with exact trim (including paletted `msrle` after a seek); compressed
  output refusal; `MADEIRA_WG_AVI=0`, `MADEIRA_WG_VIDEO=0` and H.264-in-AVI
  refusal; `indeo3`/`indeo4`/`indeo5` codec-id plumbing; back-pressure; and
  ThreadSanitizer on the threaded cases. Indeo 3/4/5 bitstreams are not
  decoded: FFmpeg has no Indeo encoder.
- `tests/host/check-wg-resampler.py` (needs a configured Wine tree, like
  the WMA test): drives the resampler through the `wg_transform` entries under
  ASan/UBSan. It covers:
  - 48 kHz S16 stereo to 48 and 44.1 kHz float (Senren's case): the tone's
    frequency and level, the frame count, timestamps without gaps or drift;
  - all 36 pairs of u8/s16/s24/s32/f32/f64, with identity bit-exact;
  - 5.1 to stereo, mono to stereo, stereo to mono;
  - `check_audio_transform_support()`'s probe, back-pressure, flush, a new
    output type mid-stream, drain;
  - refusals and `MADEIRA_WG_RESAMPLER=0`.
- `tests/host/check-wg-video-convert.py` (needs a configured Wine tree, like
  the WMV test): source checks on both call tables, `transform_kinds[]` order
  ahead of the decoder kind, the kill switch, Wine's `color_convert_create` and
  `video_processor_create` probes, `docs/MEDIA.md` and the settings catalog;
  then compiles `winegstreamer_unixlib_ios.c` under ASan/UBSan and drives the
  `"video converter"` kind through both call tables. It checks:
  - Wine's `color_convert.c` and `video_processor.c` `I420` 1920x1080 -> `NV12`
    1920x1080 probes and a 1080p conversion;
  - all 196 pairs of NV12, YV12, I420, IYUV, YUY2, UYVY, YVYU, AYUV, RGB32,
    ARGB32, ABGR32, RGB24, RGB565 and RGB555 in all four top-down/bottom-up
    combinations against an independent BT.601 limited-range oracle (plus
    BT.709), with guard bytes untouched;
  - 2D buffer `sample->stride` on input and output, `output_plane_align`, and
    input/output `MinimumDisplayAperture`s;
  - upscale, downscale and edge/1x1 cases against an independent floating-point
    bilinear reference;
  - timestamps, queue limits, drain, flush, mid-stream `set_output_type`,
    two-phase `get_output_type`, `STATUS_BUFFER_TOO_SMALL`, short input
    buffers, two threads, the wow64 32-bit thunks (`MAP_32BIT`), coexistence
    with WMV and WMA, refusals, and `MADEIRA_WG_VIDEO_CONVERT=0`.
- `tests/x86/wma-x86.c` (`build-wma-test.sh`): a 32-bit program that
  reaches the WMA decoder exactly as FAudio does and checks that the decoded
  PCM has the 440 Hz fundamental it was encoded from. Exit 62 pass, 63 decode
  failed, 64 class not registered, 65 watchdog.
- `tests/x86/video-selftest-x86.c` (`build-video-selftest.sh`,
  `make-video-clips.py`, host check `tests/host/check-video-selftest.py`):
  one 32-bit on-device self-test covering every video path visual novels use
  (see below).

### Running `video-selftest-x86.exe` on the iPad

Build and stage the 32-bit executable and its two 2-second test clips
(`video-selftest.wmv` and `video-selftest.mpg`, 320x240 25 fps with a 440 Hz
stereo tone, also embedded in the PE as a standalone fallback):

```sh
./tests/x86/build-video-selftest.sh
```

This copies `video-selftest-x86.exe`, `video-selftest.wmv` and
`video-selftest.mpg` into `app/Madeira/i386-windows/`, which `WineProcessBridge`
links into `C:\windows\syswow64\` at launch (requires the i386 farm from
`build/wine-i386/build.sh`). Package and install the app, then set in
`madeira.cfg`:

```ini
env.MADEIRA_EXE = video-selftest-x86.exe
```

The program writes its report both to `stderr`/`stdout` (captured in Madeira's
console log) and to `%USERPROFILE%\Documents\video-selftest.log` (override with
`env.MADEIRA_SELFTEST_LOG = C:\path\to\log.txt`).

**What each output line means:**

- Header (`log:`, `wmv:`, `mpg:`): the active log file path and where each test
  clip was loaded from (`beside-exe` when staged in `syswow64`, `cwd`, or
  `embedded-temp` / `embedded-docs` when extracted from the binary).
- `[1/6] PASS|FAIL kirikiri2-wmv-dmo`: Sabbat of the Witch's path —
  `LoadLibrary("wmvcore.dll")` + `GetProcAddress("WMCreateSyncReader")`,
  `SetReadStreamSamples(TRUE)` on both ASF streams, and direct DMO decode
  (`CLSID_CWMVDecMediaObject` to RGB32, `CLSID_CWMADecMediaObject` to 16-bit
  PCM). Prints compressed packet counts (`pkts=video+audio`), decoded RGB32
  `frames`, `size`, `rgb_crc`, `pcm_frames`, `peak`, Zero-crossing `freq` (~440
  Hz) and `pcm_crc`; on `FAIL`, prints the failing `step=` and `hr=`.
- `[2/6] PASS|FAIL kirikiri-mpeg1`: KiriKiri's hand-built DirectShow MPEG-1
  graph (`ConnectDirect` only, no `RenderFile`): `CLSID_AsyncReader` →
  `CLSID_MPEG1Splitter` → `CLSID_CMpegVideoCodec` → custom sink accepting only
  bottom-up RGB32 (`biHeight > 0`), and splitter → `CLSID_CMpegAudioCodec` →
  custom PCM sink. Checks `size=320x240` from `ConnectionMediaType`,
  `IAMStreamSelect` `Count`/`Info` (`streams=2`), plays to `EC_COMPLETE`
  (`pass1_frames`), rewinds with `IMediaPosition::put_CurrentPosition(0)`, and
  plays to `EC_COMPLETE` again (`pass2_frames`, `pcm_frames`, `rgb_crc`).
- `[3/6] PASS|FAIL dshow-renderfile-mpeg`: `IGraphBuilder::RenderFile` on the
  MPEG-1 clip with the default renderer attached to a hidden window, running to
  `EC_COMPLETE` (`elapsed` in ms).
- `[4/6] PASS|FAIL mf-session-evr-sar`: Senren Banka's path — the ASF clip
  through `MFCreateMediaSession` with `MFCreateVideoRendererActivate` (EVR on a
  window) and `MFCreateAudioRendererActivate` (SAR). Checks that
  `IMFVideoDisplayControl::GetCurrentImage` returns a non-black DIB mid-way
  (`image=320x240`, `nonblack_px`, `img_ts`), that
  `IMFPresentationClock::GetTime` advances (`clock=start->end`), and that the
  session reaches `MESessionEnded` (`ended=1`).
- `[5/6] PASS|FAIL mf-source-reader`: `MFCreateSourceReaderFromURL` on the ASF
  clip configured for `MFVideoFormat_RGB32`, counting non-black decoded frames
  (`frames`, `size`, `rgb_crc`).
- `[6/6] PASS|FAIL mci-mpeg`: `mciSendString` `open` / `play ... notify` /
  `close` on the MPEG-1 clip, waiting for playback completion (`notify=1`,
  `elapsed` in ms).
- `=== SUMMARY: P/6 passed, F failed (exit=F) ===`: final tally. Process exit
  code is `0` when all 6 paths pass, `1..6` for the exact number of paths that
  failed (or `6` if the 90 s watchdog fires, `99` if COM or clip staging fails
  before the paths start).
