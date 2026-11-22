# C Standard (Madeira)

## DESCRIPTION

The C standard for Madeira's own C code, and the requirements a change to it
must satisfy. It is the general C standard (`c-standards`, commit `454f771`:
STANDARD.md and ACCEPTANCE_CRITERIA.md) with only the parts that hold for this
project kept. Each part left out, or changed, is listed with its reason under
DEVIATIONS. Like the general standard, it is guidance, and a justified
deviation is acceptable.

## SCOPE

Madeira's own C: the files this repository writes, not the submodules (`wine/`,
`dxmt/`, `FEX/`, `madeira-dock/`), which follow their projects' rules. Patches
to Wine follow Wine's.

A file is under the acceptance criteria once it is listed in
`tests/host/check-c-standard.py`. A file is added when it is cleaned, and every
file a change touches should be. The first to be cleaned are the media unix
side's two files (measured below, under DEVIATIONS).

## RATIONALE

As in the general standard: the compiler leaves memory errors, undefined
behaviour and integer overflow to the programmer, so compiler diagnostics,
static analysis, sanitizers and tests detect them instead. That holds here
with more force: this code parses files a game ships, on a device where a
crash is hard to diagnose.

## BASELINE

The language is C17 with GNU extensions (`-std=gnu17`), as Wine builds its
unix side: the code uses `__atomic` builtins, `__attribute__`, and `, ##
__VA_ARGS__` in its log macros. Every listed file compiles with both GCC and
Clang. The target is iOS (and macOS for the build), through Wine's build and
Xcode; the host checks run on Linux and macOS.

## STYLE

Match the surrounding code. Madeira's unix-side C is written in Wine's style
(four-space indents, `func( arg )` in ntdll's unix files), because it lives
beside Wine's code and goes upstream with it.

Names are lower case with underscores, use the abbreviations of libc and
POSIX (`buf`, `len`, `fd`), and are the precise term for the thing they
denote. New code also follows the existing prefixes (`mav_` in the core,
`wgp_`, `wmv_`, `rs_`, `mpa_`, `wma_`, `vconv_` in the glue).

## DEPENDENCIES

Every library beyond libc, POSIX and the Apple SDK is recorded in
`THIRD-PARTY-NOTICES.md` with its version, licence, how it is linked, and why
it is needed. Its source is pinned: an upstream release tarball tracked in the
repository with its SHA-256, or a submodule at a pinned commit.

## ACCEPTANCE CRITERIA

### M-AC-1 Clean compile on GCC and Clang

Every listed file compiles cleanly with both GCC and Clang with:

    -std=gnu17 -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion
    -Wdouble-promotion -Wformat=2 -Wundef -Wcast-qual -Wwrite-strings
    -Wvla -Wstrict-prototypes -Wmissing-prototypes -Wimplicit-fallthrough
    -Werror

Wine's and FFmpeg's headers are included as system headers (`-isystem`): their
warnings are not ours to fix.

Reason: the general standard's. `-Wconversion` stays for narrowing (a 64-bit
size or time truncated to 32 bits); `-Wimplicit-fallthrough` and
`-Wsign-compare` (in `-Wextra`) found real candidates in this code.

Check: `tests/host/check-c-standard.py`, in `tests/host/run-all.py`.

### M-AC-2 clang-tidy clean

clang-tidy with `tests/host/c-standard.clang-tidy` reports nothing for the
listed files. A suppression is placed inline, names the check and states the
reason: `// NOLINT(check-name): reason`.

Reason: static analysis finds null-dereference paths, leaks, unterminated
strings and overflowing size arithmetic that the compiler accepts.

Check: `tests/host/check-c-standard.py`.

### M-AC-3 Tests pass under the sanitizers

Code under test is exercised by host checks (`tests/host/check-*.py`) that
build it with `-fsanitize=address,undefined` and make a report fatal
(`-fno-sanitize-recover`), and with `-fsanitize=thread` where it runs on more
than one thread. A sanitizer report is a test failure.

Reason: memory errors and undefined behaviour often run silently.

Check: `tests/host/run-all.py`, on Linux (GCC) and macOS (Apple Clang) in CI
(`.github/workflows/host-checks.yml`).

### M-AC-4 Dependencies are recorded with a reason

As under DEPENDENCIES.

Check: code review.

## DEVIATIONS

From the general standard, and why:

- **FreeBSD style(9) and the shared `.clang-format` (its AC-2): not used.** The
  code is Wine's, or written to sit beside Wine's. The formatter would rewrite
  85% of `wg_parser_av_ios.c` (3,577 of 4,202 lines) and 79% of
  `winegstreamer_unixlib_ios.c` (5,269 of 6,654), and every merge from upstream
  Madeira or Wine would conflict.
- **`-std=c17` and `-Wpedantic`: gnu17 instead, without `-Wpedantic`.** The
  GNU extensions are deliberate, as in Wine. In the glue, `-Wpedantic` gave 129
  warnings for `, ## __VA_ARGS__` and 55 for `%p` with typed pointers, and no
  defect.
- **`-Wsign-conversion`: not used.** It gave about 170 warnings in the two
  files. In a sample, every one was ordinary traffic between FFmpeg's `int`
  fields and this code's `uint32_t` ones (a sample rate, a stride). The general
  standard adds a criterion only for an observed failure, and casts at 170
  sites would hide the next real one. Narrowing stays under `-Wconversion`.
- **clang-tidy checks also disabled here** (`tests/host/c-standard.clang-tidy`):
  - `bugprone-branch-clone`: 58 findings, parallel arms written so on purpose
    (format tables, per-container cases); each was checked before it was
    disabled.
  - `bugprone-multi-level-implicit-pointer-conversion`: `memmove` and `free`
    on pointer arrays, which C converts through `void *` by design.
  - `bugprone-assignment-in-selection-statement`: the general standard's
    `bugprone-assignment-in-if-condition` under another name in newer
    clang-tidy.
- **POSIX on Linux and the BSDs, GNU Make and the shared Makefile: not used.**
  The target is iOS, built through Wine's build system and Xcode; the host
  checks are run by `tests/host/run-all.py`.
- **Linking large or security-sensitive libraries from the system: not
  possible.** iOS has no system FFmpeg or GnuTLS, so they are built from pinned
  sources and linked statically (DEPENDENCIES).
- **Dependencies in a README: in `THIRD-PARTY-NOTICES.md` instead**, where the
  licences are.

## FILES

`docs/C-STANDARD.md`\
This file.

`tests/host/check-c-standard.py`\
M-AC-1 and M-AC-2 for the listed files.

`tests/host/c-standard.clang-tidy`\
The clang-tidy configuration.

## SEE ALSO

The general standard: `c-standards/STANDARD.md` and
`c-standards/ACCEPTANCE_CRITERIA.md` (commit `454f771`).

FreeBSD style(9): https://man.freebsd.org/style/9
