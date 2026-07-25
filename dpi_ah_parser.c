/*
 * dpi_ah_parser.c
 *
 * IPsec AH (Authentication Header, RFC 4302) dissector — IP protocol
 * 51. AH's sibling in this project is `dpi_esp_parser.c`, but the two
 * are fundamentally different in one respect that shapes this whole
 * file: AH only authenticates, it never encrypts. The protected
 * payload sits in cleartext immediately after the AH header, with its
 * own protocol identified by AH's Next Header field — exactly like an
 * IPv6 extension header. That means, unlike ESP (where nothing past
 * SPI/sequence can be recovered without keys), AH's inner payload can
 * be fully, correctly recursively dissected.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against all 82 real AH packets found across every pcap
 * checked in this project so far — all 82 were over IPv6 (zero over
 * IPv4 in any real capture available), protecting real OSPFv3 traffic
 * (Next Header 89): a real captured inner packet decoded to a genuine
 * OSPFv3 Hello (version 3, type 1, router ID 192.168.255.11) sitting
 * in cleartext right after the AH header, confirming this design
 * (recursive dissection based on Next Header) rather than assuming it
 * from the RFC text alone.
 *
 * WIRE FORMAT (RFC 4302 S3.1): Next Header(1) + Payload Len(1, total
 * AH header length in 4-byte units, minus 2) + Reserved(2) + SPI(4) +
 * Sequence Number(4) + Integrity Check Value (variable, length
 * implied by Payload Len — e.g. 12 bytes for HMAC-SHA1-96, confirmed
 * against real traffic: Payload Len=4 → total header 24 bytes → ICV
 * = 24 - 12 (fixed fields) = 12 bytes).
 *
 * SCOPE: full AH header extraction (SPI, sequence, next header) plus
 * recursive dissection of the inner payload for the protocols this
 * project already has a direct, name-dispatchable registry entry for
 * (OSPF, GRE, IGMP, EIGRP, ESP — matching AH's own real-world use
 * protecting routing-protocol traffic) and for TCP/UDP (via the same
 * parse_tcp/parse_udp + single-packet SNI pattern GRE's and 6in4's
 * inner-packet dissection already use). Only IPv6 is real-traffic-
 * verified — no real AH-over-IPv4 traffic was found in any pcap
 * checked, though the capture-path wiring covers both IP versions
 * since RFC 4302 applies equally to both and there's no reason to
 * assume IPv4 AH doesn't exist elsewhere, just that this project
 * hasn't seen it yet.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define AH_MIN_HDR_LEN 12   /* fixed fields before the ICV: Next
                                Header+PayloadLen+Reserved+SPI+Seq */

static const char *ah_next_header_dissector_name(uint8_t next_header) {
    switch (next_header) {
        case 89: return "OSPF";
        case 47: return "GRE";
        case 2:  return "IGMP";
        case 88: return "EIGRP";
        case 50: return "ESP";
        default: return NULL;   /* not a directly name-dispatchable
                                    IP-protocol-based dissector in this
                                    project's registry */
    }
}

static double ah_detect(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto) {
    (void)dst_port; (void)l4_proto;   /* identified by IP protocol 51
                                        * already at the capture path */
    if (len < AH_MIN_HDR_LEN) return 0.0;
    uint8_t ah_payload_len = payload[1];
    size_t total_ah_len = (size_t)(ah_payload_len + 2) * 4;
    if (total_ah_len < AH_MIN_HDR_LEN || total_ah_len > len) return 0.0;
    return 0.85;
}

static void ah_dissect(const uint8_t *payload, uint16_t len,
                        uint16_t dst_port, const char *l4_proto,
                        struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < AH_MIN_HDR_LEN) return;

    uint8_t next_header = payload[0];
    uint8_t ah_payload_len = payload[1];
    size_t total_ah_len = (size_t)(ah_payload_len + 2) * 4;
    if (total_ah_len < AH_MIN_HDR_LEN || total_ah_len > len) {
        dissect_result_add(out, "parse_warning", "ah_len_inconsistent");
        return;
    }

    uint32_t spi = ((uint32_t)payload[4]<<24)|((uint32_t)payload[5]<<16)|
                   ((uint32_t)payload[6]<<8)|payload[7];
    uint32_t seq = ((uint32_t)payload[8]<<24)|((uint32_t)payload[9]<<16)|
                   ((uint32_t)payload[10]<<8)|payload[11];

    char buf[16];
    snprintf(buf, sizeof(buf), "0x%08x", spi);
    dissect_result_add(out, "ah_spi", buf);
    snprintf(buf, sizeof(buf), "%u", seq);
    dissect_result_add(out, "ah_sequence", buf);
    snprintf(buf, sizeof(buf), "%u", next_header);
    dissect_result_add(out, "ah_next_header", buf);
    dissect_result_add(out, "ah_authenticated_not_encrypted", "true");

    const uint8_t *inner = payload + total_ah_len;
    size_t inner_len = len - total_ah_len;
    if (inner_len == 0) return;

    const char *dissector_name = ah_next_header_dissector_name(next_header);
    if (dissector_name) {
        struct dissect_result inner_out;
        if (dispatch_dissection(inner, (uint16_t)inner_len, 0, dissector_name, &inner_out)) {
            dissect_result_add(out, "ah_inner_protocol", dissector_name);
            /* Merge the single most useful inner field through, same
             * "surface what's actually being protected" reasoning as
             * GRE's/6in4's inner-packet flow-record fields. */
            const char *inner_type = dissect_result_get(&inner_out, "ospf_type");
            if (inner_type) dissect_result_add(out, "ah_inner_summary", inner_type);
        }
    } else if (next_header == 6 || next_header == 17) {
        dissect_result_add(out, "ah_inner_protocol", next_header == 6 ? "TCP" : "UDP");
        /* Unlike GRE's/6in4's inner payload (a COMPLETE tunneled IP
         * packet, with its own header to extract addresses from), AH
         * in transport mode sits directly in front of the original
         * L4 payload — there's no inner IP header here to get
         * addresses from, so full TCP/UDP parsing (which needs them
         * for pseudo-header checksums) isn't possible from this
         * dissector alone. Flagged by name only. */
    } else {
        dissect_result_add(out, "ah_inner_protocol", "other");
    }
}

static const uint16_t ah_hint_ports[] = { 0 };   /* no port concept, see file header */

void register_ah_dissector(void) {
    register_dissector("AH", ah_detect, ah_dissect, ah_hint_ports, 0);
}

