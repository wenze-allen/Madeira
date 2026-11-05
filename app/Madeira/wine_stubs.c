// wine_stubs.c - Provide missing symbols for Wine on iOS

#include <CoreFoundation/CoreFoundation.h>

// Wine build version string (normally generated at compile time)
const char wine_build[] = "wine-10.0-ios";

// IOPowerSources stubs - not available on iOS
CFTypeRef IOPSCopyPowerSourcesInfo(void) { return NULL; }
CFArrayRef IOPSCopyPowerSourcesList(CFTypeRef blob) { (void)blob; return NULL; }
CFDictionaryRef IOPSGetPowerSourceDescription(CFTypeRef blob, CFTypeRef ps) {
    (void)blob; (void)ps; return NULL;
}

// DXMT's winemetal (the 1f617cd pin) calls two app hooks that upstream defines with
// features this build does not carry: madeira_frame_mark (the performance overlay's
// frame times, Winios.m) and madeira_swap_overlay_stats (the swap tier's donor-RAM
// figures). winemetal declares them weak, but a weak reference still has to resolve
// when the app links, so they are defined here as weak no-ops: no frame marks, and no
// donated RAM counted (what winemetal does without them). A real definition wins.
__attribute__((weak)) void madeira_frame_mark(const void *layer) { (void)layer; }
__attribute__((weak)) void madeira_swap_overlay_stats(unsigned long long *file_mb, unsigned long long *donor_mb,
                                                      unsigned long long *pool_mb, unsigned long long *guarded) {
    if (file_mb) *file_mb = 0;
    if (donor_mb) *donor_mb = 0;
    if (pool_mb) *pool_mb = 0;
    if (guarded) *guarded = 0;
}
