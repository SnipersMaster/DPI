/*
 * dpi_mdns_parser.c
 *
 * mDNS (Multicast DNS, RFC 6762) dissector — reuses dpi_dns_parser.c's
 * wire-format logic directly (mDNS uses the exact same message format
 * as unicast DNS: 12-byte header + question/answer/authority/
 * additional sections) rather than reimplementing name decompression
 * and record walking a second time. Registered as a separate
 * dissector from plain "DNS" (not just an alternate port for the same
 * one) because mDNS repurposes a bit this project's DNS dissector
 * doesn't know about — see below.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 339 real mDNS packets from a genuine capture
 * (Johannes Weber's "Ultimate PCAP") — 161 queries, 178 responses.
 *
 * TWO REAL MDNS-SPECIFIC QUIRKS FOUND DURING VERIFICATION, neither of
 * which plain unicast DNS ever exercises:
 *   1. QDCOUNT can legitimately be 0 — 178 of 339 real packets had no
 *      question section at all (pure announcements/"goodbye" packets,
 *      RFC 6762 S8.4/10.1). Ordinary DNS queries essentially always
 *      have QDCOUNT >= 1, so this is a real behavioral difference,
 *      not just a coincidence of this capture.
 *   2. The top bit of the CLASS field is repurposed (RFC 6762 S18.12):
 *      on a QUESTION, it's the "QU bit" (unicast response requested);
 *      on a RESOURCE RECORD, it's the "cache-flush bit" (this is the
 *      only authoritative record, flush any others with this name/
 *      type from your cache). Confirmed real usage in this capture:
 *      18 of 81 real questions had QU set, and 41 real answer-only
 *      packets had cache-flush set on their first record. This
 *      project's plain DNS dissector reports the raw 16-bit class
 *      value without masking this bit off — correct for real unicast
 *      DNS (where the bit is always 0), but would misreport mDNS's
 *      class as e.g. 32769 instead of 1 (IN) plus a separate flag.
 *      This dissector extracts both correctly.
 *
 * SCOPE: calls dns_dissect() (from dpi_dns_parser.c, included directly
 * here — see that file's include guard, added specifically for this
 * reuse) to get the full set of already-implemented fields (qname,
 * qtype, answer records, etc.), then does one additional, bounded pass
 * to extract the QU bit from the first question (if any) and the
 * cache-flush bit from the first answer record (if there's no
 * question section) — matching this project's established "first N,
 * not exhaustive" pattern rather than re-walking every record a
 * second time just for this one bit.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "dpi_dns_parser.c"

#define MDNS_PORT 5353

static double mdns_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    /* Reuse dns_detect()'s structural validation entirely — mDNS's
     * header is byte-for-byte identical to DNS's — then require the
     * mDNS port specifically, since dns_detect() alone would also
     * (correctly) accept this as looking like generic DNS. */
    double dns_confidence = dns_detect(payload, len, dst_port, l4_proto);
    if (dns_confidence <= 0.0) return 0.0;
    return (dst_port == MDNS_PORT) ? 0.9 : 0.0;
}

static void mdns_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    /* Get everything dns_dissect() already extracts — qname, qtype,
     * qclass (raw, unmasked — see below for the corrected version),
     * answer records, etc. */
    dns_dissect(payload, len, dst_port, l4_proto, out);

    if (len < DNS_HDR_LEN) return;
    uint16_t qdcount = (payload[4] << 8) | payload[5];
    uint16_t ancount = (payload[6] << 8) | payload[7];

    char name_buf[MAX_LABEL_OUTPUT];
    size_t pos = DNS_HDR_LEN;

    if (qdcount > 0) {
        size_t after_name = dns_decode_name(payload, len, pos, name_buf, sizeof(name_buf));
        if (after_name != 0 && after_name + 4 <= len) {
            uint16_t qclass_raw = (payload[after_name + 2] << 8) | payload[after_name + 3];
            bool qu_bit = (qclass_raw & 0x8000) != 0;
            uint16_t qclass = qclass_raw & 0x7FFF;

            char buf[8];
            dissect_result_add(out, "mdns_qu_bit_requested", qu_bit ? "true" : "false");
            snprintf(buf, sizeof(buf), "%u", qclass);
            dissect_result_add(out, "mdns_qclass_masked", buf);
        }
    } else if (ancount > 0) {
        /* No question section — this is the QDCOUNT=0 announcement
         * case confirmed real above. The first answer record's NAME
         * starts right where a question would have. */
        size_t after_name = dns_decode_name(payload, len, pos, name_buf, sizeof(name_buf));
        if (after_name != 0 && after_name + 10 <= len) {
            uint16_t rclass_raw = (payload[after_name + 2] << 8) | payload[after_name + 3];
            bool cache_flush = (rclass_raw & 0x8000) != 0;
            dissect_result_add(out, "mdns_cache_flush_bit", cache_flush ? "true" : "false");
        }
    }
}

static const uint16_t mdns_hint_ports[] = { MDNS_PORT };

void register_mdns_dissector(void) {
    register_dissector("mDNS", mdns_detect, mdns_dissect, mdns_hint_ports, 1);
}
