/*
 * dpi_capwap_parser.c
 *
 * CAPWAP (RFC 5415, Control And Provisioning of Wireless Access
 * Points) dissector — UDP port 5246 (control channel) / 5247 (data
 * channel), both confirmed directly by the RFC Editor's own text.
 * Requested by name in a batch cross-check against a large protocol
 * list.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic — no CAPWAP capture was available. Built with a
 * DELIBERATELY NARROWER scope than most dissectors in this project,
 * stated honestly: RFC 5415's own header diagram packs HLEN(5 bits)
 * + RID(5 bits) + WBID(5 bits) + 6 individual flag bits + 3 reserved
 * bits into the 3 bytes following the 1-byte Preamble — the
 * arithmetic checks out exactly (5+5+5+6+3=24 bits), confirmed by
 * fetching the RFC's own text directly, but RID and WBID each cross
 * byte boundaries at awkward, non-byte-aligned bit offsets, and this
 * project could not obtain a definitive byte-level reference
 * (Wireshark's own real dissector source was checked but described
 * the header at a level that didn't fully resolve this) to verify
 * the exact bit-shift arithmetic against. Rather than guess at that
 * specific packing and risk silently wrong RID/WBID values, this
 * dissector decodes only the Preamble (Version/Type) and HLEN — HLEN
 * is cleanly byte-aligned (the top 5 bits of the byte immediately
 * following the Preamble) and confirmed directly by the real
 * Wireshark dissector source code's own comment ("HLEN: A 5-bit
 * field containing the length of the CAPWAP transport header in
 * 4-byte words").
 *
 * WIRE FORMAT: CAPWAP Preamble(1 byte: Version(4 bits) + Type(4
 * bits, 0=CAPWAP Header not present/DTLS, 1=CAPWAP transport header
 * present)) + CAPWAP Header (variable, HLEN*4 bytes total, starting
 * with HLEN(5 bits) as its own top 5 bits) + Payload.
 *
 * SCOPE: Preamble Version/Type, and HLEN (both the raw 5-bit value
 * and the resulting byte length). RID, WBID, the 6 flag bits
 * (T/F/L/W/M/K), Fragment ID, and Fragment Offset are deliberately
 * NOT decoded — this project won't guess at cross-byte-boundary bit
 * arithmetic it couldn't verify against a definitive source, the
 * same discipline applied elsewhere (DNP3's field layout, IEEE
 * 802.3br's mPacket SMD values). Extending this once a definitive
 * byte-level reference or real captured traffic becomes available is
 * well-scoped future work, not attempted here as a guess.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define CAPWAP_CONTROL_PORT 5246
#define CAPWAP_DATA_PORT    5247

static double capwap_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < 4) return 0.0;

    uint8_t version = (payload[0] >> 4) & 0x0F;
    uint8_t type = payload[0] & 0x0F;
    if (version > 1 || type > 1) return 0.0;   /* only versions/types
                                                    0-1 are currently
                                                    defined */

    uint8_t hlen = (payload[1] >> 3) & 0x1F;   /* top 5 bits of the
                                                   byte after the
                                                   Preamble — cleanly
                                                   byte-aligned, real-
                                                   confirmed per file
                                                   header */
    if (hlen == 0) return 0.0;   /* HLEN=0 would mean a header shorter
                                     than even the Preamble itself:
                                     invalid */

    double confidence = 0.3;   /* weak evidence alone — version/type/
                                   hlen all being individually
                                   plausible isn't strong without the
                                   port */
    if (dst_port == CAPWAP_CONTROL_PORT || dst_port == CAPWAP_DATA_PORT) confidence = 0.75;
    return confidence;
}

static void capwap_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < 4) return;

    uint8_t version = (payload[0] >> 4) & 0x0F;
    uint8_t type = payload[0] & 0x0F;
    uint8_t hlen = (payload[1] >> 3) & 0x1F;

    char buf[8];
    snprintf(buf, sizeof(buf), "%u", version);
    dissect_result_add(out, "capwap_preamble_version", buf);
    dissect_result_add(out, "capwap_preamble_type",
                        type == 0 ? "no transport header (DTLS)" : "transport header present");
    snprintf(buf, sizeof(buf), "%u", hlen);
    dissect_result_add(out, "capwap_hlen_words", buf);
    snprintf(buf, sizeof(buf), "%u", hlen * 4);
    dissect_result_add(out, "capwap_hlen_bytes", buf);
}

static const uint16_t capwap_hint_ports[] = { CAPWAP_CONTROL_PORT, CAPWAP_DATA_PORT };

void register_capwap_dissector(void) {
    register_dissector("CAPWAP", capwap_detect, capwap_dissect, capwap_hint_ports, 2);
}
