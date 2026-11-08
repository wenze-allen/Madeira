#!/usr/bin/env python3
"""The exclusive-pair store emulation understands logical operations between the load and the
store (ios_excl_decode_op / ios_excl_rmw in build/ntdll-unix/signal_arm64_ios_guards.c, upstream's
MADEIRA_EXCL_LOGICAL fix from 0a2e6ed); no Wine runs.

An RtlpInterlockedClearBit-shaped pair (LDAXR W11; AND W11, W11, W10; STLXR W12, W11) on a
critical-section word in a Mono runtime's RWX memory was refused, and the redelivery guard ended
the app. Only ADD/SUB immediate was understood. A pair with a logical operation cannot be replayed
as a compare-and-swap on the loaded value (AND loses it), so the operations are applied to the
memory's current value in a compare-and-swap loop.

Compiles the decoder and the read-modify-write out of the source and checks, with encodings from
the AArch64 assembler (llvm-mingw 20260421's clang, -target aarch64-linux-gnu):
  - AND/ORR/EOR/BIC/ORN/EON of another register and ADD/SUB immediate, Rd == Rn == the loaded
    register at its width, are understood, with the right operand;
  - ANDS, a shifted operand, Rm == the loaded register, Rd != Rn and a width mismatch are not;
  - the read-modify-write applies the operations in order to the memory's value, at every width;
  - env.MADEIRA_EXCL_LOGICAL = 0 understands ADD/SUB only.
Then checks that the Mach handler's [excl-store] case uses them.
Needs python3 and a C compiler.
"""
from pathlib import Path
import os, subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
guards = (root / "build/ntdll-unix/signal_arm64_ios_guards.c").read_text()
mach = (root / "build/ntdll-unix/signal_arm64_ios_mach.c").read_text()
ok = True


def check(what, cond):
    global ok
    print(("PASS: " if cond else "FAIL: ") + what)
    ok &= bool(cond)


a = guards.index("enum { IOS_EXCL_ADD, IOS_EXCL_AND, IOS_EXCL_ORR, IOS_EXCL_EOR };")
end_sig = "static void ios_excl_rmw( void *p, unsigned size, const ios_excl_op *ops, int n, uint64_t mask, uint64_t *result )\n{"
b = guards.index("\n}\n", guards.index(end_sig)) + 3
code = guards[a:b]

check("the [excl-store] case decodes the instructions between with ios_excl_decode_op",
      "if (nops < 8 && ios_excl_decode_op( prev, ld_rt, size, (const uint64_t *)state.__x, &ops[nops] ))" in mach)
check("a pair with a logical operation is a read-modify-write when the stored register is the loaded one",
      "ios_excl_rmw( rw_addr, size, ops, nops, mask, &written );" in mach and "if (rt == ld_rt)" in mach)
check("an earlier operation's Rm written later refuses the pair",
      "if (ops[j].rm >= 0 && (int)(prev & 0x1f) == ops[j].rm) clobbered = 1;" in mach)

# (word, assembly, loaded register, size log2, understood with the switch on, kind, arg with x10 = 0x0f0f00f0)
X10 = 0x0f0f00f0
CASES = [
    (0x0a0a016b, "and w11, w11, w10", 11, 2, 1, "IOS_EXCL_AND", X10),
    (0x2a0a016b, "orr w11, w11, w10", 11, 2, 1, "IOS_EXCL_ORR", X10),
    (0x4a0a016b, "eor w11, w11, w10", 11, 2, 1, "IOS_EXCL_EOR", X10),
    (0x0a2a016b, "bic w11, w11, w10", 11, 2, 1, "IOS_EXCL_AND", ~X10 & (2**64 - 1)),
    (0x2a2a016b, "orn w11, w11, w10", 11, 2, 1, "IOS_EXCL_ORR", ~X10 & (2**64 - 1)),
    (0x4a2a016b, "eon w11, w11, w10", 11, 2, 1, "IOS_EXCL_EOR", ~X10 & (2**64 - 1)),
    (0x8a0a016b, "and x11, x11, x10", 11, 3, 1, "IOS_EXCL_AND", X10),
    (0x2a1f016b, "orr w11, w11, wzr", 11, 2, 1, "IOS_EXCL_ORR", 0),
    (0x1100056b, "add w11, w11, #1", 11, 2, 1, "IOS_EXCL_ADD", 1),
    (0xd1000508, "sub x8, x8, #1", 8, 3, 1, "IOS_EXCL_ADD", 2**64 - 1),
    (0x1140056b, "add w11, w11, #1, lsl #12", 11, 2, 1, "IOS_EXCL_ADD", 0x1000),
    (0x6a0a016b, "ands w11, w11, w10", 11, 2, 0, None, 0),
    (0x0a0a096b, "and w11, w11, w10, lsl #2", 11, 2, 0, None, 0),
    (0x0a0b016b, "and w11, w11, w11", 11, 2, 0, None, 0),
    (0x0a0a018b, "and w11, w12, w10", 11, 2, 0, None, 0),
    (0x8a0a016b, "and x11, x11, x10 (a 32-bit pair)", 11, 2, 0, None, 0),
    (0x0a0a016b, "and w11, w11, w10 (a 64-bit pair)", 11, 3, 0, None, 0),
]
rows = ",\n".join('        { 0x%08xu, %d, %d, %d, %s, 0x%016xull, "%s" }' %
                  (w, r, s, u, k or "-1", arg, asm) for w, asm, r, s, u, k, arg in CASES)

harness = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
''' + code + r'''
int main( int argc, char **argv )
{
    int off = argc > 1 && !strcmp( argv[1], "off" );
    static const struct { uint32_t insn; int ld_rt, size, understood, kind; uint64_t arg; const char *what; } c[] = {
@ROWS@
    };
    uint64_t x[32];
    int fails = 0;
    unsigned i;
    for (i = 0; i < 32; i++) x[i] = 0xdead0000ull + i;
    x[10] = 0x0f0f00f0ull;
    for (i = 0; i < sizeof(c) / sizeof(c[0]); i++)
    {
        ios_excl_op op = { -2, 0, -2 };
        int want = c[i].understood && (!off || c[i].kind == IOS_EXCL_ADD);
        int got = ios_excl_decode_op( c[i].insn, c[i].ld_rt, c[i].size, x, &op );
        if (got != want) { printf( "FAIL: %s%s: understood=%d, want %d\n", off ? "switch off: " : "", c[i].what, got, want ); fails++; continue; }
        if (got && (op.kind != c[i].kind || op.arg != c[i].arg))
        { printf( "FAIL: %s: kind %d arg %016llx\n", c[i].what, op.kind, (unsigned long long)op.arg ); fails++; continue; }
        printf( "PASS: %s%s %s\n", off ? "switch off: " : "", c[i].what, got ? "understood" : "refused" );
    }
    if (off) return fails != 0;
    {
        /* LDAXR W11; AND W11, W11, W10; ADD W11, W11, #1; STLXR on a word another thread changed meanwhile */
        ios_excl_op ops[2];
        uint64_t written = 0;
        uint32_t w32 = 0xffffffffu;
        uint8_t w8 = 0xf3;
        uint16_t w16 = 0x8001;
        uint64_t w64 = 0x123456789abcdef0ull;
        ios_excl_decode_op( 0x0a0a016b, 11, 2, x, &ops[0] );
        ios_excl_decode_op( 0x1100056b, 11, 2, x, &ops[1] );
        ios_excl_rmw( &w32, 2, ops, 2, 0xffffffffull, &written );
        if (w32 != 0x0f0f00f1u || written != 0x0f0f00f1u) { printf( "FAIL: rmw 32: %08x %llx\n", w32, (unsigned long long)written ); fails++; }
        else printf( "PASS: AND then ADD on the current 32-bit value, in order\n" );
        ios_excl_rmw( &w8, 0, ops, 2, 0xffull, &written );
        if (w8 != 0xf1 || written != 0xf1) { printf( "FAIL: rmw 8: %02x\n", w8 ); fails++; }
        else printf( "PASS: the same on a byte (masked to its width)\n" );
        ios_excl_rmw( &w16, 1, ops, 2, 0xffffull, &written );
        if (w16 != 0x0001 || written != 0x0001) { printf( "FAIL: rmw 16: %04x\n", w16 ); fails++; }
        else printf( "PASS: the same on a halfword\n" );
        ios_excl_decode_op( 0x8a0a016b, 11, 3, x, &ops[0] );   /* and x11, x11, x10 */
        ios_excl_rmw( &w64, 3, ops, 1, ~0ull, &written );
        if (w64 != (0x123456789abcdef0ull & 0x0f0f00f0ull) || written != w64) { printf( "FAIL: rmw 64: %016llx\n", (unsigned long long)w64 ); fails++; }
        else printf( "PASS: AND on a doubleword\n" );
    }
    return fails != 0;
}
'''.replace("@ROWS@", rows)

with tempfile.TemporaryDirectory() as d:
    c = Path(d) / "t.c"
    c.write_text(harness)
    exe = Path(d) / "t"
    cc = subprocess.run(["cc", "-std=c11", "-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                         "-Wall", "-Wno-unused-variable", "-Wno-unused-function", "-o", str(exe), str(c)],
                        capture_output=True, text=True)
    if cc.returncode:
        sys.exit("FAIL: the decoder did not compile:\n" + cc.stderr[-3000:])
    for mode, env in (("on", {}), ("off", {"MADEIRA_EXCL_LOGICAL": "0"})):
        e = {k: v for k, v in os.environ.items() if k != "MADEIRA_EXCL_LOGICAL"}
        e.update(env)
        r = subprocess.run([str(exe), mode], capture_output=True, text=True, env=e)
        print(r.stdout, end="")
        if r.returncode:
            ok = False
            print("FAIL (%s): %s" % (mode, r.stderr[-2000:]))
if not ok:
    sys.exit(1)
print("check-excl-logical: OK")
