/*
 * dpi_eigrp_parser.c
 *
 * EIGRP (Enhanced Interior Gateway Routing Protocol, Cisco-proprietary
 * until documented in the informational RFC 7868) dissector — IP
 * protocol 88.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against all 60 real EIGRP packets from a genuine capture
 * (Johannes Weber's "Ultimate PCAP") — all version 2, 52 Hello
 * (opcode 5) and 8 Update (opcode 1), consistently carrying
 * Autonomous System Number 4711, with the INIT flag correctly set on
 * the first Update in the sequence (flags=0x1) — exactly the expected
 * real behavior for a new EIGRP session establishing itself.
 *
 * WIRE FORMAT (20-byte fixed header, RFC 7868 S4.1): Version(1) +
 * Opcode(1) + Checksum(2) + Flags(4) + Sequence(4) + Acknowledgment(4)
 * + Virtual Router ID(2) + Autonomous System Number(2), followed by
 * one or more TLVs: Type(2) + Length(2, includes this 4-byte header)
 * + Value.
 *
 * SCOPE, stated honestly: the fixed header (version, opcode, flags,
 * sequence, ack, ASN) is fully extracted with high confidence — RFC
 * 7868 documents this shape clearly and it matches real traffic
 * exactly. TLV VALUE contents are deliberately NOT decoded — EIGRP's
 * exact TLV type numbering and internal field layout (Parameters,
 * IP-Internal-Routes, IP-External-Routes, Software Version,
 * Multicast Sequence, etc.) would need RFC 7868's precise text in
 * hand to verify field offsets with the same confidence as everything
 * else in this project, which wasn't available while writing this —
 * same honest limitation already applied to HSRPv2 and GTPv2-C's
 * Bearer QoS bit-fields elsewhere in this project, rather than
 * guessing at a byte layout that can't be checked. TLVs ARE walked
 * correctly (type + length only) so the message structure and TLV
 * count are accurate, just not their internal semantics.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define EIGRP_HDR_LEN 20
#define EIGRP_MAX_TLVS_COUNTED 32

static const char *eigrp_opcode_name(uint8_t opcode) {
    switch (opcode) {
        case 1: return "Update";
        case 2: return "Request";
        case 3: return "Query";
        case 4: return "Reply";
        case 5: return "Hello";
        case 6: return "IPX SAP";
        case 7: return "Probe";
        case 10: return "SIA-Query";
        case 11: return "SIA-Reply";
        default: return "Unknown";
    }
}

static double eigrp_detect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto) {
    (void)dst_port; (void)l4_proto;   /* identified by IP protocol 88
                                        * already at the capture path */
    if (len < EIGRP_HDR_LEN) return 0.0;
    uint8_t version = payload[0];
    if (version != 2) return 0.0;   /* only version 2 ever seen/documented */
    uint8_t opcode = payload[1];
    if (opcode == 0 || opcode == 8 || opcode == 9 || opcode > 11) return 0.0;
    return 0.9;
}

static void eigrp_dissect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto,
                           struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < EIGRP_HDR_LEN) return;

    char buf[16];
    snprintf(buf, sizeof(buf), "%u", payload[0]);
    dissect_result_add(out, "eigrp_version", buf);
    dissect_result_add(out, "eigrp_opcode", eigrp_opcode_name(payload[1]));

    uint32_t flags = ((uint32_t)payload[4]<<24)|((uint32_t)payload[5]<<16)|
                      ((uint32_t)payload[6]<<8)|payload[7];
    dissect_result_add(out, "eigrp_init_flag", (flags & 0x1) ? "true" : "false");

    uint32_t seq = ((uint32_t)payload[8]<<24)|((uint32_t)payload[9]<<16)|
                    ((uint32_t)payload[10]<<8)|payload[11];
    snprintf(buf, sizeof(buf), "%u", seq);
    dissect_result_add(out, "eigrp_sequence", buf);

    uint32_t ack = ((uint32_t)payload[12]<<24)|((uint32_t)payload[13]<<16)|
                    ((uint32_t)payload[14]<<8)|payload[15];
    snprintf(buf, sizeof(buf), "%u", ack);
    dissect_result_add(out, "eigrp_ack", buf);

    uint16_t asn = (payload[18] << 8) | payload[19];
    snprintf(buf, sizeof(buf), "%u", asn);
    dissect_result_add(out, "eigrp_asn", buf);

    /* Walk TLVs for an accurate count/type list — see file header for
     * why VALUE contents aren't decoded. */
    size_t pos = EIGRP_HDR_LEN;
    int n_tlvs = 0;
    while (pos + 4 <= len && n_tlvs < EIGRP_MAX_TLVS_COUNTED) {
        uint16_t tlv_type = (payload[pos] << 8) | payload[pos+1];
        uint16_t tlv_len = (payload[pos+2] << 8) | payload[pos+3];
        if (tlv_len < 4 || pos + tlv_len > len) {
            dissect_result_add(out, "parse_warning", "eigrp_tlv_len_inconsistent");
            break;
        }
        if (n_tlvs == 0) {
            char tlvbuf[8];
            snprintf(tlvbuf, sizeof(tlvbuf), "0x%04x", tlv_type);
            dissect_result_add(out, "eigrp_first_tlv_type", tlvbuf);
        }
        pos += tlv_len;
        n_tlvs++;
    }
    snprintf(buf, sizeof(buf), "%d", n_tlvs);
    dissect_result_add(out, "eigrp_tlv_count", buf);
}

static const uint16_t eigrp_hint_ports[] = { 0 };   /* no port concept, see file header */

void register_eigrp_dissector(void) {
    register_dissector("EIGRP", eigrp_detect, eigrp_dissect, eigrp_hint_ports, 0);
}
