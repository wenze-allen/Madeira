#!/usr/bin/env python3
"""Playing a DirectShow movie again after it ended, from production source; nothing runs.

A program plays a movie to EC_COMPLETE, pauses, seeks back with put_CurrentPosition(0) and runs
the graph again: KiriKiri does this to loop or replay a movie, and the self-test's MPEG-1 paths
(tests/x86/video-selftest-x86.c: kirikiri-mpeg1, kirikiri-m1v, kirikiri-vcd-dat) do it to check
the second play. On the iPad all three got EC_COMPLETE at once in the second play, with no frame:
1. Wine's filter graph sets the event behind IMediaEvent::WaitForCompletion() at EC_COMPLETE and
   never reset it, so after one completion every later wait returned EC_COMPLETE at once. It is
   reset now when the graph starts running (graph_start), with the EC_COMPLETE count it already
   reset there.
2. quartz's MPEG video and audio decoders (quartz_transform.c) did not flush their transform when
   the stream is flushed for a seek: a video decoder would hand out its last delayed picture from
   before the seek first. They flush it at EndFlush now, and our transforms implement the flush.
3. Why the self-test saw it: the second play waits with WaitForCompletion().
"""
from pathlib import Path
import re, sys

root = Path(__file__).resolve().parents[2]
wine = root / "wine"
need = [wine / "dlls/quartz/filtergraph.c", wine / "dlls/winegstreamer/quartz_transform.c"]
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


# ---- 1. the filter graph's completion ----------------------------------------------------
fg = (wine / "dlls/quartz/filtergraph.c").read_text()
assert re.search(r"hEventCompletion = CreateEventW\(0, TRUE, FALSE, 0\);", fg), \
    "the completion event is manual-reset: something must reset it"
wait = function(fg, "static HRESULT WINAPI MediaEvent_WaitForCompletion(")
assert "WaitForSingleObject(This->hEventCompletion" in wait and "CompletionStatus" in wait, wait
notify = function(fg, "static HRESULT WINAPI MediaEventSink_Notify(")
assert "SetEvent(graph->hEventCompletion);" in notify, notify
start = function(fg, "static HRESULT graph_start(")
reset = start[:start.index("LeaveCriticalSection(&graph->event_cs);")]
assert "graph->EcCompleteCount = 0;" in reset and "ResetEvent(graph->hEventCompletion);" in reset \
    and "graph->CompletionStatus = 0;" in reset, "graph_start resets the completion with the EC_COMPLETE count"
resets = [m.start() for m in re.finditer(r"ResetEvent\((?:graph|This)->hEventCompletion\)", fg)]
assert len(resets) == 1, "the completion is reset in graph_start only (%d places)" % len(resets)
tests = (wine / "dlls/quartz/tests/filtergraph.c").read_text()
ec = function(tests, "static void test_ec_complete(")
assert "IMediaEvent_WaitForCompletion(eventsrc, 0, &code)" in ec, "Wine's test covers it"
print("PASS: WaitForCompletion() waits for the current run: graph_start resets the completion event")

# ---- 2. quartz's decoders flush their transform ------------------------------------------
qt = (wine / "dlls/winegstreamer/quartz_transform.c").read_text()
ops = qt[qt.index("static const struct strmbase_sink_ops sink_ops ="):]
ops = ops[:ops.index("};")]
assert ".sink_end_flush = transform_sink_end_flush," in ops, ops
flush = function(qt, "static HRESULT transform_sink_end_flush(")
assert "wg_transform_flush(filter->transform);" in flush and "IPin_EndFlush(filter->source.pin.peer)" in flush, flush
assert "filter->filter.state != State_Stopped" in flush, "no transform exists while stopped"
assert "EnterCriticalSection(&filter->filter.stream_cs);" in flush, "serialised with Receive"
glue = (root / "build/ntdll-unix/winegstreamer_unixlib_ios.c").read_text()
for kind in ["wmv_flush", "mpa_flush", "rs_flush"]:
    assert re.search(r"static NTSTATUS %s\( wg_transform_t handle \)" % kind, glue), kind
assert "wg_transform_flush,                 /* unix_wg_transform_flush */" in glue
print("PASS: quartz's MPEG decoders flush their transform at EndFlush (and forward it); our transforms flush")

# ---- 3. the self-test's second play ----------------------------------------------------
st = (root / "tests/x86/video-selftest-x86.c").read_text()
mpeg = function(st, "static BOOL run_kirikiri_mpeg_graph(")
assert mpeg.index("IMediaPosition_put_CurrentPosition( mp, 0.0 )") < mpeg.index('"WaitForCompletion(pass2)"'), \
    "the self-test's MPEG-1 paths rewind and wait for completion again"
assert "IMediaEvent_WaitForCompletion( me, 25, &ev_code )" in function(st, "static HRESULT wait_dshow_completion(")
print("PASS: the self-test's MPEG-1 paths play again after put_CurrentPosition(0) and wait with WaitForCompletion()")
