/*
 * fuzz_sctp_parser.c
 *
 * libFuzzer harness for dpi_sctp_parser.c. Chunk walking (bounded
 * length, 4-byte padding alignment, multiple chunks per packet) is
 * exactly the kind of variable-length-field loop most likely to hide
 * a bounds bug — same reasoning as this project's other TLV/chunk-
 * walking harnesses.
 *
 * `sctp_dissect()` calls `dispatch_dissection()` internally for a
 * DATA chunk's PPID-keyed inner-protocol recursion (the same pattern
 * GRE/MPLS/L2TPv3/802.11's Data-frame recursion already use), so
 * M3UA is explicitly registered below — `fuzz_80211_parser.c` had
 * this exact situation (an internal `dispatch_dissection()` call
 * silently finding nothing because nothing was registered) turn into
 * a real, previously-undetected gap once its own inner dissectors
 * existed but were never wired into that harness. M2UA isn't
 * registered yet since `dpi_m2ua_parser.c` doesn't exist yet —
 * whoever adds it should register it here too, same reminder.
 *
 * Build: clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *            -o fuzz_sctp_parser fuzz_sctp_parser.c
 * Run:   ./fuzz_sctp_parser fuzz_seeds/sctp/ -max_len=512
 *
 * NOT RUN in this environment.
 */

#include <stdint.h>
#include <stddef.h>

#define DPI_SKIP_REGISTER_ALL
#include "dpi_dissector_registry.c"
#include "dpi_sctp_parser.c"
#include "dpi_m3ua_parser.c"

static int g_registered = 0;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1 || Size > 512) return 0;

    if (!g_registered) {
        register_m3ua_dissector();
        g_registered = 1;
    }

    double confidence = sctp_detect(Data, (uint16_t)Size, 0, "SCTP");
    if (confidence <= 0.15) return 0;

    struct dissect_result out;
    sctp_dissect(Data, (uint16_t)Size, 0, "SCTP", &out);

    return 0;
}
