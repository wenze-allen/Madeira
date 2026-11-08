#!/usr/bin/env python3
"""Madeira's x18 emulator (the Mach exception path in build/ntdll-unix/signal_arm64_ios_mach.c) does
the sign-extending loads with an immediate offset from x18 (ios_x18_signed_load, upstream's fix from
0a2e6ed); no Wine runs.

A thread whose x18 the OS had cleared faulted on `ldrsw x28, [x18, #0x180c]` (b9980e5c). The
emulator had cases for LDR/STR of every width, but not LDRSW/LDRSB/LDRSH with an unsigned
immediate. The fault went down the "[x18-emul3] UNRECOGNIZED" path, the access violation was
unhandled, and Wine ended the game process. The app stayed up with the last frame on screen: the
"random freeze while playing" of 14 of 26 iPad sessions, 2026-11-05 to 11-08 (Senren Banka and
Sabbat of the Witch).

Compiles ios_x18_signed_load and the emulator's integer cases (from its `switch (insn & 0xffc00000)`
to the SIMD block) out of the source, with a buffer standing in for the TEB. Checks, with encodings from the AArch64
assembler (llvm-mingw 20260421's clang, -target aarch64-linux-gnu):
  - the crash's own word loads TEB+0x180c sign-extended into x28;
  - LDRSW, LDRSB and LDRSH into Xt sign-extend, and into Wt sign-extend to 32 bits and zero the
    upper half;
  - a load into XZR writes nothing;
  - env.MADEIRA_X18_SIGNED_LOAD = 0 declines the signed loads again (and only them);
  - the cases that were already there are unchanged: LDR X/W/B/H, register-offset LDRSW,
    unscaled LDURSW with a negative offset;
  - no other register is touched.
Needs python3 and a C compiler.
"""
from pathlib import Path
import subprocess, sys, tempfile

root = Path(__file__).resolve().parents[2]
src = (root / "build/ntdll-unix/signal_arm64_ios_mach.c").read_text()
start = src.index("if (rn == 18 || x18_derived)")
start = src.index("switch (insn & 0xffc00000)", start)
end = src.index("/* SIMD/FP register-offset + unsigned-offset loads/", start)
block = src[start:end]
f0 = src.index("static int ios_x18_signed_load( uint32_t insn, uintptr_t ea, uint64_t *val )\n{")
func = src[f0:src.index("\n}\n", f0) + 3]

# (word, assembly, offset from x18 the hardware reports as the fault address, Rt, expected Rt or None)
SENT = 0xdeadbeefcafef00d
CASES = [
    (0xb9980e5c, "ldrsw x28, [x18, #0x180c]", 0x180c, 28, 0xffffffff80000005),
    (0xb9801243, "ldrsw x3, [x18, #0x10]", 0x10, 3, 0x000000007ffffff0),
    (0x39808644, "ldrsb x4, [x18, #0x21]", 0x21, 4, 0xffffffffffffff9c),
    (0x39c08a45, "ldrsb w5, [x18, #0x22]", 0x22, 5, 0x00000000ffffff81),
    (0x79804a46, "ldrsh x6, [x18, #0x24]", 0x24, 6, 0xffffffffffff8001),
    (0x79c04e47, "ldrsh w7, [x18, #0x26]", 0x26, 7, 0x00000000fffffffe),
    (0xf9401a48, "ldr x8, [x18, #0x30]", 0x30, 8, 0x1122334455667788),
    (0xb9403649, "ldr w9, [x18, #0x34]", 0x34, 9, 0x0000000011223344),
    (0x3940864a, "ldrb w10, [x18, #0x21]", 0x21, 10, 0x9c),
    (0x79404a4b, "ldrh w11, [x18, #0x24]", 0x24, 11, 0x8001),
    (0xb8ad6a4c, "ldrsw x12, [x18, x13]", 0x180c, 12, 0xffffffff80000005),
    (0xb89fc24e, "ldursw x14, [x18, #-4]", (1 << 64) - 4, 14, 0xffffffffcafebabe),
    (0xb980125f, "ldrsw xzr, [x18, #0x10]", 0x10, 31, None),
]

harness = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
''' + func + r'''
static unsigned char mem[0x2000];
static int run(uint32_t insn, uint64_t fault_addr, uint64_t *x)
{
    struct { uint64_t __x[32]; } state;
    uintptr_t thread_teb = (uintptr_t)(mem + 0x100);
    uint64_t ios_teb_tls_slot_offset = 0;
    int rn = 18;
    uintptr_t ea = thread_teb + fault_addr;
    int rt = insn & 0x1f;
    int emulated = 0;
    memcpy(state.__x, x, sizeof(state.__x));
    (void)rn; (void)ios_teb_tls_slot_offset;
''' + block + r'''
    memcpy(x, state.__x, sizeof(state.__x));
    return emulated;
}
static void put32(int off, uint32_t v) { memcpy(mem + 0x100 + off, &v, 4); }
static void put16(int off, uint16_t v) { memcpy(mem + 0x100 + off, &v, 2); }
static void put64(int off, uint64_t v) { memcpy(mem + 0x100 + off, &v, 8); }
int main(int argc, char **argv)
{
    /* "off": run with env.MADEIRA_X18_SIGNED_LOAD = 0; the signed immediate loads are then declined */
    int off = argc > 1 && !strcmp(argv[1], "off");
    static const struct { uint32_t insn; uint64_t fa; int rt; int has; uint64_t want; const char *what; } c[] = {
@CASES@
    };
    int fails = 0;
    unsigned i;
    put32(0x180c, 0x80000005u);
    put32(0x10, 0x7ffffff0u);
    mem[0x100 + 0x21] = 0x9c;
    mem[0x100 + 0x22] = 0x81;
    put16(0x24, 0x8001);
    put16(0x26, 0xfffe);
    put64(0x30, 0x1122334455667788ull);
    put32(-4, 0xcafebabeu);
    for (i = 0; i < sizeof(c) / sizeof(c[0]); i++)
    {
        uint64_t x[32];
        unsigned r;
        for (r = 0; r < 32; r++) x[r] = 0xdeadbeefcafef00dull + r;
        int signed_imm = (c[i].insn & 0xff000000) == 0xb9000000 || (c[i].insn & 0xbf000000) == 0x39000000;
        signed_imm = signed_imm && ((c[i].insn >> 23) & 1);   /* opc<1>: LDRSB/LDRSH/LDRSW */
        int got = run(c[i].insn, c[i].fa, x);
        if (off && signed_imm)
        {
            if (got) { printf("FAIL: %s (%08x) emulated with the switch off\n", c[i].what, c[i].insn); fails++; }
            else printf("PASS: switch off: %s (%08x) declined\n", c[i].what, c[i].insn);
            continue;
        }
        if (!got) { printf("FAIL: %s (%08x) not emulated\n", c[i].what, c[i].insn); fails++; continue; }
        for (r = 0; r < 32; r++)
        {
            uint64_t want = (c[i].has && (int)r == c[i].rt) ? c[i].want : 0xdeadbeefcafef00dull + r;
            if (r == 18) continue;   /* the block does not set x18; the caller does */
            if (x[r] != want)
            {
                printf("FAIL: %s (%08x): x%u = %016llx, want %016llx\n", c[i].what, c[i].insn, r,
                       (unsigned long long)x[r], (unsigned long long)want);
                fails++;
            }
        }
        if (!fails) printf("PASS: %s (%08x)\n", c[i].what, c[i].insn);
    }
    return fails != 0;
}
'''
rows = ",\n".join('        { 0x%08xu, 0x%xull, %d, %d, 0x%016xull, "%s" }' %
                  (w, fa, rt, 0 if want is None else 1, want or 0, asm) for w, asm, fa, rt, want in CASES)
harness = harness.replace("@CASES@", rows)

with tempfile.TemporaryDirectory() as d:
    c = Path(d) / "t.c"
    c.write_text(harness)
    exe = Path(d) / "t"
    cc = subprocess.run(["cc", "-std=c11", "-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                         "-Wall", "-Wno-unused-variable", "-o", str(exe), str(c)], capture_output=True, text=True)
    if cc.returncode:
        sys.exit("FAIL: the emulator block did not compile:\n" + cc.stderr[-3000:])
    import os
    for mode, env in (("on", {}), ("off", {"MADEIRA_X18_SIGNED_LOAD": "0"})):
        e = {k: v for k, v in os.environ.items() if k != "MADEIRA_X18_SIGNED_LOAD"}
        e.update(env)
        r = subprocess.run([str(exe), mode], capture_output=True, text=True, env=e)
        print(r.stdout, end="")
        if r.returncode:
            sys.exit("FAIL (%s): %s" % (mode, r.stderr[-2000:]))
print("check-x18-signed-loads: OK")
