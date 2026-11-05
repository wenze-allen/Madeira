# Madeira's DXMT patches

Changes to DXMT (the `dxmt` submodule) that live in this repository until
they are in DXMT's own repository. `apply.sh` applies them, in file-name
order, to the `dxmt` working tree before `build/dxmt-ios/build.sh` (the unix
side and the native Direct3D 9 frontend in `libdxmt_combined.a`) and
`build/wine-i386/build.sh` (the 32-bit DLLs) build DXMT; it skips a patch
that is already applied, and `apply.sh --revert` takes them out. The `dxmt`
submodule pin does not change. (The mechanism is upstream's, from 9bb81d3.)

| Patch | What it fixes |
|---|---|
| `0001-airconv-tessellation-atomic.patch` | `get_next_index` in `src/airconv/shaders/air_tessellation.metal` called the compiler-internal `__metal_atomic_fetch_add_explicit` builtin, which the Metal compiler of the Xcode 27.3 beta (the 21e6697 Mac build) rejected, so `build/dxmt-ios/build.sh` could not make `air_tessellation.h`. It now uses the Metal standard library's `atomic_fetch_add_explicit` on a `threadgroup atomic_int`, relaxed order; a threadgroup atomic's scope is the threadgroup, as before. |

A patch must apply on the current `dxmt` pin. When the pin moves, rebase the
patches onto it (or drop a patch the new pin already covers).
