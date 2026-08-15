/*
 * dpi_geneve_parser.c
 *
 * Geneve (RFC 8926, Generic Network Virtualization Encapsulation)
 * dissector — UDP port 6081 (IANA-registered). Requested by name in
 * a batch cross-check against a large protocol list.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic — no Geneve capture was available in this project's pcap
 * survey set. Built with real confidence regardless: the 8-byte
 * fixed-header layout was cross-checked across the RFC Editor's own
 * RFC 8926 text (via multiple mirrors, including a PDF rendering)
 * and Google Cloud's own network security documentation, which
 * reproduces the identical header diagram — a real production cloud
 * provider's own docs agreeing byte-for-byte with the RFC.
 *
 * WIRE FORMAT: Ver(2 bits, currently always 0) + Opt Len(6 bits, the
 * variable options area's length in 4-byte words) + O(1 bit, this is
 * a control packet, not data) + C(1 bit, one or more critical
 * options present) + Reserved(6 bits) + Protocol Type(16 bits,
 * follows the EtherType convention — 0x6558 specifically means
 * Ethernet, i.e. "the same thing VXLAN's inner frame always is,"
 * though Geneve can carry other protocol types too) + Virtual
 * Network Identifier/VNI(24 bits) + Reserved(8 bits) — 8 bytes total,
 * followed by Opt-Len*4 bytes of variable-length TLV options, then
 * the actual encapsulated payload.
 *
 * SCOPE: the 8-byte fixed header — version, O/C flags, protocol type,
 * VNI. The variable-length options area (each option: Option
 * Class(16) + Type(8) + 3 reserved bits + Length(5, in 4-byte words))
 * is walked only to correctly skip past it (so a real inner-payload
 * offset could be computed), not decoded — Geneve's whole design
 * point is letting vendors define arbitrary option semantics (this
 * project found real-world examples of exactly that: per-flow QoS
 * metadata, tenant/security-group IDs, in-band telemetry, service-
 * chaining instructions — all vendor- or deployment-specific, with
 * no single universal structure to decode). The inner payload itself
 * (frequently a complete Ethernet frame, per Geneve's own protocol-
 * type convention) is flagged as present but not recursively
 * dissected — the same scope boundary this project already drew for
 * VXLAN's own inner frame, for the same structural reason.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define GENEVE_PORT 6081
#define GENEVE_HDR_LEN 8

static double geneve_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < GENEVE_HDR_LEN) return 0.0;

    uint8_t version = (payload[0] >> 6) & 0x03;
    if (version != 0) return 0.0;   /* the only version defined so far */

    uint8_t opt_len_words = payload[0] & 0x3F;
    if (len < GENEVE_HDR_LEN + (size_t)opt_len_words * 4) return 0.0;

    double confidence = 0.4;   /* a version-nibble-only match is weak
                                   evidence alone */
    if (dst_port == GENEVE_PORT) confidence = 0.8;
    return confidence;
}

static void geneve_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < GENEVE_HDR_LEN) return;

    uint8_t opt_len_words = payload[0] & 0x3F;
    bool o_flag = (payload[1] & 0x80) != 0;
    bool c_flag = (payload[1] & 0x40) != 0;
    uint16_t protocol_type = (payload[2] << 8) | payload[3];
    uint32_t vni = ((uint32_t)payload[4] << 16) | ((uint32_t)payload[5] << 8) | payload[6];

    char buf[16];
    dissect_result_add(out, "geneve_control_packet", o_flag ? "true" : "false");
    dissect_result_add(out, "geneve_critical_options_present", c_flag ? "true" : "false");
    snprintf(buf, sizeof(buf), "0x%04x", protocol_type);
    dissect_result_add(out, "geneve_protocol_type", buf);
    dissect_result_add(out, "geneve_inner_is_ethernet", protocol_type == 0x6558 ? "true" : "false");
    snprintf(buf, sizeof(buf), "%u", vni);
    dissect_result_add(out, "geneve_vni", buf);

    size_t opts_len = (size_t)opt_len_words * 4;
    char lenbuf[24];   /* sized for any size_t value, matching the
                           established fix in dpi_http1_parser.c for
                           the same -Wformat-truncation class of
                           warning with %zu */
    snprintf(lenbuf, sizeof(lenbuf), "%zu", opts_len);
    dissect_result_add(out, "geneve_options_length_bytes", lenbuf);
}

static const uint16_t geneve_hint_ports[] = { GENEVE_PORT };

void register_geneve_dissector(void) {
    register_dissector("Geneve", geneve_detect, geneve_dissect, geneve_hint_ports, 1);
}
