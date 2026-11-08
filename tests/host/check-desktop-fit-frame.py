#!/usr/bin/env python3
"""A window whose frame is pushed off the desktop is shown 1:1, not fitted (winios_fit_frame_offscreen
in app/Madeira/Winios/Winios.m); no app runs.

Sabbat of the Witch (KiriKiri) hides its menu bar in full screen by keeping the window at y=-19 and
dropping the menu, so its client rect is {0,-19 2360x1659} on a 2360x1640 desktop (iPad, log
2026-11-08 14:29). The desktop fit, meant for a window bigger than the desktop, scaled its Metal
layer by 0.989 and left 13.5 px of the window's white GDI surface on the left and right.

Compiles winios_fit_frame_offscreen with CoreGraphics' rect functions stubbed and checks:
  - Sabbat's rect at 2360x1640 and at 1152x800 (log 2026-11-05), and a frame and caption off all
    sides, are shown 1:1;
  - a window bigger than the desktop (1920x1080 on 1280x720), one that does not cover the desktop,
    and an overhang past 64 px on any side are fitted as before;
  - env.MADEIRA_DESKTOP_FIT_FRAME = 0 fits them all as before;
and that winios_desktop_fit leaves such a window alone.
Needs python3 and a C compiler.
"""
from pathlib import Path
import os, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
src = (root / "app/Madeira/Winios/Winios.m").read_text()
ok = True


def check(what, cond):
    global ok
    print(("PASS: " if cond else "FAIL: ") + what)
    ok &= bool(cond)


a = src.index("#define WINIOS_FIT_FRAME_PX 64")
b = src.index("\n}\n", src.index("static int winios_fit_frame_offscreen(CGRect desk, CGRect c) {")) + 3
helper = src[a:b]
fit = src[src.index("static BOOL winios_desktop_fit(NSNumber *key, CAMetalLayer *ml, CGRect c) {"):]
fit = fit[:fit.index("\n}\n")]
check("winios_desktop_fit does not fit a window whose frame is off the desktop",
      "&& !CGRectContainsRect(CGRectInset(desk, -8, -8), c)\n        && !winios_fit_frame_offscreen(desk, c);" in fit)

# (what, desk w, desk h, client x, y, w, h, shown 1:1)
CASES = [
    ("Sabbat of the Witch, menu hidden above a 2360x1640 desktop", 2360, 1640, 0, -19, 2360, 1659, 1),
    ("the same at 1152x800 (log 2026-11-05)", 1152, 800, 0, -19, 1152, 819, 1),
    ("border and caption off every side", 2360, 1640, -8, -31, 2376, 1679, 1),
    ("exactly the desktop", 2360, 1640, 0, 0, 2360, 1640, 1),
    ("64 px over on the top, the most a frame is given", 1280, 720, 0, -64, 1280, 784, 1),
    ("65 px over on the top: fitted", 1280, 720, 0, -65, 1280, 785, 0),
    ("65 px over on the right: fitted", 1280, 720, 0, 0, 1345, 720, 0),
    ("a 1920x1080 window on a 1280x720 desktop: fitted", 1280, 720, 0, 0, 1920, 1080, 0),
    ("a client below its menu, over the bottom (does not cover the desktop): fitted", 1920, 1080, 0, 19, 1920, 1080, 0),
    ("a window inside the desktop (the fit leaves it alone too)", 2360, 1640, 100, 100, 960, 540, 0),
]
rows = ",\n".join('        { %d, %d, %d, %d, %d, %d, %d, "%s" }' % (dw, dh, x, y, w, h, want, what)
                  for what, dw, dh, x, y, w, h, want in CASES)
harness = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef double CGFloat;
typedef struct { CGFloat x, y; } CGPoint;
typedef struct { CGFloat width, height; } CGSize;
typedef struct { CGPoint origin; CGSize size; } CGRect;
static CGRect CGRectMake( CGFloat x, CGFloat y, CGFloat w, CGFloat h ) { CGRect r = { { x, y }, { w, h } }; return r; }
static CGFloat CGRectGetMinX( CGRect r ) { return r.origin.x; }
static CGFloat CGRectGetMinY( CGRect r ) { return r.origin.y; }
static CGFloat CGRectGetMaxX( CGRect r ) { return r.origin.x + r.size.width; }
static CGFloat CGRectGetMaxY( CGRect r ) { return r.origin.y + r.size.height; }
static int CGRectContainsRect( CGRect a, CGRect b )
{
    return CGRectGetMinX( b ) >= CGRectGetMinX( a ) && CGRectGetMinY( b ) >= CGRectGetMinY( a )
        && CGRectGetMaxX( b ) <= CGRectGetMaxX( a ) && CGRectGetMaxY( b ) <= CGRectGetMaxY( a );
}
''' + helper + r'''
int main( int argc, char **argv )
{
    int off = argc > 1 && !strcmp( argv[1], "off" ), fails = 0;
    unsigned i;
    static const struct { int dw, dh, x, y, w, h, want; const char *what; } c[] = {
@ROWS@
    };
    for (i = 0; i < sizeof(c) / sizeof(c[0]); i++)
    {
        int got = winios_fit_frame_offscreen( CGRectMake( 0, 0, c[i].dw, c[i].dh ), CGRectMake( c[i].x, c[i].y, c[i].w, c[i].h ) );
        int want = off ? 0 : c[i].want;
        if (got != want) { printf( "FAIL: %s%s: %d, want %d\n", off ? "switch off: " : "", c[i].what, got, want ); fails++; }
        else printf( "PASS: %s%s: %s\n", off ? "switch off: " : "", c[i].what, got ? "shown 1:1" : "left to the fit" );
    }
    return fails != 0;
}
'''.replace("@ROWS@", rows)

with tempfile.TemporaryDirectory() as d:
    c = Path(d) / "t.c"
    c.write_text(harness)
    exe = Path(d) / "t"
    cc = subprocess.run(["cc", "-std=c11", "-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                         "-Wall", "-Wno-unused-function", "-o", str(exe), str(c)], capture_output=True, text=True)
    if cc.returncode:
        sys.exit("FAIL: the helper did not compile:\n" + cc.stderr[-3000:])
    for mode, env in (("on", {}), ("off", {"MADEIRA_DESKTOP_FIT_FRAME": "0"})):
        e = {k: v for k, v in os.environ.items() if k != "MADEIRA_DESKTOP_FIT_FRAME"}
        e.update(env)
        r = subprocess.run([str(exe), mode], capture_output=True, text=True, env=e)
        print(r.stdout, end="")
        if r.returncode:
            ok = False
            print("FAIL (%s): %s" % (mode, r.stderr[-2000:]))
if not ok:
    sys.exit(1)
print("check-desktop-fit-frame: OK")
