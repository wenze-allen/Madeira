#!/usr/bin/env python3
"""Host source and syntax checks for the Media Foundation source buffer pool.

In a 32-bit process, allocating a fresh 8 MB MFCreateMemoryBuffer for every
1920x1080 RGB32 sample fragments the 4 GB window until large heap blocks fail,
and failing video allocations stall audio sample requests behind them on the
source's single-thread async_commands_queue.

Checks (production source, nothing runs on the host):
  1. mfplat's 1D memory buffer contract that media_source.c relies on: single
     refcount field manipulated with InterlockedIncrement/Decrement, exposing
     only IUnknown and IMFMediaBuffer;
  2. media_source.c's bounded per-stream buffer pool, sole-reference reuse
     check (AddRef == 2), too-small buffer drop & replace, fallback to fresh
     MFCreateMemoryBuffer when all slots are busy, one-time GetEnvironmentVariableW
     kill switch MADEIRA_MF_SOURCE_POOL=0, stream_id initialisation, pool
     teardown on both Shutdown and Release, and [mf-source] MESSAGE() summary;
  3. docs/MEDIA.md and ConfigCatalog registration of MADEIRA_MF_SOURCE_POOL;
  4. llvm-mingw -fsyntax-only compilation of media_source.c and mfplat/tests
     (i686 and x86_64; Wine's headers need its own flags for arm64ec) when llvm-mingw and Wine headers are present.
"""

import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

failures = []


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def fn_body(src, pattern):
    m = re.search(pattern, src, re.MULTILINE)
    if not m:
        return ""
    i = src.find("{", m.end() - 1)
    if i < 0:
        return ""
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    return ""


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print(f"FAIL: {msg}")
    else:
        print(f"  ok: {msg}")


def find_clang(triple):
    exe = f"{triple}-clang"
    found = shutil.which(exe)
    if found:
        return found
    candidates = [
        os.path.expanduser(f"~/.local/share/madeira-tools/llvm-mingw/bin/{exe}"),
        os.path.join(ROOT, "toolchains", "llvm-mingw", "bin", exe),
    ]
    for p in candidates:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def find_wine_build_inc():
    env_dir = os.environ.get("MADEIRA_WINE_BUILD", "")
    candidates = [
        os.path.join(env_dir, "include") if env_dir else "",
        os.path.expanduser("~/.local/share/madeira-tools/scratch/wine-hdr/include"),
        os.path.join(ROOT, "build", "wine-pe", "work", "wine-build", "include"),
        os.path.join(ROOT, "build", "wine-host", "include"),
    ]
    for p in candidates:
        if p and os.path.isfile(os.path.join(p, "mfidl.h")):
            return p
    return None


# ---------------------------------------------------------------------------
# 1. mfplat's 1D memory buffer contract
# ---------------------------------------------------------------------------
buf_src = read("wine/dlls/mfplat/buffer.c")

qi = fn_body(buf_src, r"memory_buffer_QueryInterface\s*\([^)]*\)\s*\{")
addref = fn_body(buf_src, r"memory_buffer_AddRef\s*\([^)]*\)\s*\{")
release = fn_body(buf_src, r"memory_buffer_Release\s*\([^)]*\)\s*\{")
create_mem = fn_body(buf_src, r"MFCreateMemoryBuffer\s*\([^)]*\)\s*\{")

check(
    bool(qi)
    and "IID_IMFMediaBuffer" in qi
    and "IID_IUnknown" in qi
    and "IID_IMF2DBuffer" not in qi,
    "mfplat 1D memory buffer QueryInterface exposes only IUnknown and IMFMediaBuffer",
)
check(
    "InterlockedIncrement(&buffer->refcount)" in addref
    and "return refcount;" in addref,
    "mfplat memory_buffer_AddRef returns InterlockedIncrement(&buffer->refcount)",
)
check(
    "InterlockedDecrement(&buffer->refcount)" in release
    and "_aligned_free(buffer->data)" in release,
    "mfplat memory_buffer_Release returns InterlockedDecrement and frees buffer->data at 0",
)
check(
    "create_1d_buffer" in create_mem,
    "MFCreateMemoryBuffer delegates to create_1d_buffer",
)


# ---------------------------------------------------------------------------
# 2. winegstreamer's media_source.c pool, safety invariant, fallback, switch
# ---------------------------------------------------------------------------
ms_src = read("wine/dlls/winegstreamer/media_source.c")

m_cap = re.search(r"#define\s+SOURCE_BUFFER_POOL_SIZE\s+(\d+)", ms_src)
cap = int(m_cap.group(1)) if m_cap else 0
check(
    2 <= cap <= 8,
    f"SOURCE_BUFFER_POOL_SIZE is a small bounded constant ({cap})",
)

stream_struct = fn_body(ms_src, r"struct\s+media_stream\s*\{")
check(
    "buffer_pool[SOURCE_BUFFER_POOL_SIZE]" in stream_struct
    and "IMFMediaBuffer *buffer;" in stream_struct
    and "DWORD max_length;" in stream_struct,
    "struct media_stream holds bounded buffer_pool[SOURCE_BUFFER_POOL_SIZE]",
)

init_pool = fn_body(ms_src, r"init_source_pool\s*\([^)]*\)\s*\{")
pool_enabled = fn_body(ms_src, r"media_source_pool_enabled\s*\([^)]*\)\s*\{")
check(
    'GetEnvironmentVariableW(L"MADEIRA_MF_SOURCE_POOL"' in init_pool
    and 'wcscmp(val, L"0")' in init_pool
    and "InitOnceExecuteOnce(&source_pool_once, init_source_pool" in pool_enabled,
    "MADEIRA_MF_SOURCE_POOL=0 is read once on the PE side via GetEnvironmentVariableW + InitOnceExecuteOnce",
)

acquire = fn_body(ms_src, r"media_stream_acquire_buffer\s*\([^)]*\)\s*\{")
check(
    "if (!media_source_pool_enabled())" in acquire
    and "return MFCreateMemoryBuffer(size, out);" in acquire,
    "kill switch restores direct per-sample MFCreateMemoryBuffer",
)
check(
    "IMFMediaBuffer_AddRef(stream->buffer_pool[i].buffer)" in acquire
    and "if (ref == 2)" in acquire
    and "stream->buffer_pool[i].max_length >= size" in acquire,
    "pooled buffer is reused only when AddRef returns 2 (sole reference) and max_length >= size",
)
check(
    "stream->buffer_pool[i].max_length < size" in acquire
    and "IMFMediaBuffer_Release(stream->buffer_pool[replace_idx].buffer)" in acquire,
    "free pooled buffer smaller than next sample is dropped from the pool and replaced",
)
check(
    acquire.count("MFCreateMemoryBuffer(size, &buffer)") == 2
    and "stream->pool_fresh_allocs++" in acquire
    and "stream->pool_alloc_failures++" in acquire,
    "pool allocates up to SOURCE_BUFFER_POOL_SIZE and falls back to fresh MFCreateMemoryBuffer when all slots are busy",
)

send_sample = fn_body(ms_src, r"media_stream_send_sample\s*\([^)]*\)\s*\{")
check(
    "media_stream_acquire_buffer(stream, wg_buffer->size, &buffer)" in send_sample
    and "IMFMediaBuffer_SetCurrentLength(buffer, wg_buffer->size)" in send_sample
    and "MFCreateSample(&sample)" in send_sample
    and "IMFSample_AddBuffer(sample, buffer)" in send_sample
    and "IMFSample_SetSampleTime(sample, wg_buffer->pts)" in send_sample
    and "IMFSample_SetSampleDuration(sample, wg_buffer->duration)" in send_sample
    and "MFSampleExtension_Token" in send_sample
    and "IMFMediaBuffer_Release(buffer)" in send_sample,
    "media_stream_send_sample acquires pooled buffer and preserves sample type, length, timestamps and token",
)

free_pool = fn_body(ms_src, r"media_stream_free_pool\s*\([^)]*\)\s*\{")
check(
    "if (stream->pool_has_pooled && !stream->pool_logged)" in free_pool
    and 'MESSAGE("[mf-source] stream %lu: %u buffers of %lu bytes, %I64u reuses, "' in free_pool
    and '"%I64u fresh allocations, %I64u failed, at most %u in use\\n"' in free_pool,
    "media_stream_free_pool logs one [mf-source] MESSAGE() summary only when the stream pooled buffers",
)

stream_create = fn_body(ms_src, r"media_stream_create\s*\([^)]*\)\s*\{")
stream_release = fn_body(ms_src, r"media_stream_Release\s*\([^)]*\)\s*\{")
source_shutdown = fn_body(ms_src, r"media_source_Shutdown\s*\([^)]*\)\s*\{")
check(
    "IMFStreamDescriptor_GetStreamIdentifier(descriptor, &object->stream_id)" in stream_create,
    "media_stream_create initialises stream->stream_id from the stream descriptor",
)
check(
    "media_stream_free_pool(stream)" in stream_release
    and stream_release.index("media_stream_free_pool(stream)")
    < stream_release.index("IMFMediaSource_Release(stream->media_source)"),
    "media_stream_Release frees the buffer pool before releasing media_source",
)
check(
    "media_stream_free_pool(source->streams[i])" in source_shutdown
    and source_shutdown.index("media_stream_free_pool(source->streams[i])")
    < source_shutdown.index("MFUnlockWorkQueue(source->async_commands_queue)"),
    "media_source_Shutdown frees stream buffer pools before unlocking the work queue",
)


# ---------------------------------------------------------------------------
# 3. Documentation and ConfigCatalog
# ---------------------------------------------------------------------------
media_doc = read("docs/MEDIA.md")
catalog_gen = read("build/tools/gen-config-catalog.py")
catalog_swift = read("app/Madeira/ConfigCatalog.generated.swift")

check(
    "**The Media Foundation source's frame buffers.**" in media_doc
    and "| `MADEIRA_MF_SOURCE_POOL` | on |" in media_doc
    and "`[mf-source]`" in media_doc
    and "`tests/host/check-mf-source-pool.py`" in media_doc,
    "docs/MEDIA.md documents the MF source buffer pool, MADEIRA_MF_SOURCE_POOL, [mf-source] log and host check",
)
check(
    '"env.MADEIRA_MF_SOURCE_POOL"' in catalog_gen
    and 'key: "env.MADEIRA_MF_SOURCE_POOL"' in catalog_swift
    and '"wine/dlls/winegstreamer/media_source.c"' in catalog_swift,
    "ConfigCatalog registers env.MADEIRA_MF_SOURCE_POOL pointing at wine/dlls/winegstreamer/media_source.c",
)


# ---------------------------------------------------------------------------
# 4. llvm-mingw -fsyntax-only checks (when toolchain + Wine headers exist)
# ---------------------------------------------------------------------------
wine_build_inc = find_wine_build_inc()
clang_i686 = find_clang("i686-w64-mingw32")
clang_64 = find_clang("x86_64-w64-mingw32")

if wine_build_inc and (clang_i686 or clang_64):
    for cc in [c for c in (clang_i686, clang_64) if c]:
        name = os.path.basename(cc)
        cmd_ms = [
            cc,
            "-fsyntax-only",
            "-Wall",
            "-Wextra",
            "-Wno-unused-parameter",
            "-D__WINESRC__",
            "-D_UCRT",
            f"-I{os.path.join(ROOT, 'wine', 'dlls', 'winegstreamer')}",
            f"-I{wine_build_inc}",
            f"-I{os.path.join(ROOT, 'wine', 'include')}",
            os.path.join(ROOT, "wine", "dlls", "winegstreamer", "media_source.c"),
        ]
        res = subprocess.run(cmd_ms, capture_output=True, text=True)
        check(
            res.returncode == 0,
            f"{name} -fsyntax-only compiles media_source.c cleanly"
            + (f":\n{res.stderr.strip()}" if res.returncode != 0 else ""),
        )

        cmd_test = [
            cc,
            "-fsyntax-only",
            "-Wall",
            "-Wno-unused-parameter",
            "-D__WINESRC__",
            "-DSTANDALONE",
            "-D_UCRT",
            f"-I{os.path.join(ROOT, 'wine', 'dlls', 'mfplat', 'tests')}",
            f"-I{wine_build_inc}",
            f"-I{os.path.join(ROOT, 'wine', 'include')}",
            os.path.join(ROOT, "wine", "dlls", "mfplat", "tests", "mfplat.c"),
        ]
        res_t = subprocess.run(cmd_test, capture_output=True, text=True)
        check(
            res_t.returncode == 0,
            f"{name} -fsyntax-only compiles mfplat/tests/mfplat.c cleanly"
            + (f":\n{res_t.stderr.strip()}" if res_t.returncode != 0 else ""),
        )
else:
    print("  (llvm-mingw or configured Wine headers not present; skipping -fsyntax-only step)")


if failures:
    print(f"\n{len(failures)} check(s) FAILED")
    sys.exit(1)
print("\nPASS")
