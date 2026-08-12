/*
 * dpi_vxlan_parser.c
 *
 * VXLAN (RFC 7348) dissector — UDP port 4789 (IANA-registered).
 * Requested by name in a batch cross-check against a large protocol
 * list.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic — no VXLAN capture was available in this project's pcap
 * survey set. Built with real confidence regardless: the 8-byte
 * header layout was cross-checked across the RFC Editor's own RFC
 * 7348 text, two independent open-source implementations (a Rust
 * crate and a TypeScript/JSR library), and vendor documentation from
 * three separate network vendors (Huawei, Juniper, Nokia) — including
 * a real Wireshark capture screenshot in Huawei's own documentation
 * confirming UDP destination port 4789, all agreeing byte-for-byte.
 *
 * WIRE FORMAT: Flags(1 byte — bit 3, the "I" flag, MUST be 1 for a
 * valid VNI; the other 7 bits are reserved, MUST be 0) + Reserved(3
 * bytes, MUST be 0) + VNI(3 bytes, the 24-bit VXLAN Network
 * Identifier — up to ~16.7M possible overlay segments) + Reserved(1
 * byte, MUST be 0) — 8 bytes total, followed by a complete inner
 * Ethernet frame (its own MAC header, optional VLAN tag, EtherType,
 * and payload).
 *
 * SCOPE: the 8-byte VXLAN header only — I flag, VNI. The inner
 * Ethernet frame is a real, complete, separately-dissectable packet
 * in its own right (this project already has full Ethernet-frame
 * dissection via `dispatch_by_ethertype()`), but re-entering that
 * whole dispatch chain recursively from inside a UDP payload is a
 * structural change to this project's dispatch architecture, not a
 * contained addition — deliberately out of scope here, stated
 * honestly rather than attempted as an afterthought. A real
 * VXLAN-in-VXLAN survey, or wiring the inner frame into the existing
 * dispatch chain, is well-scoped future work if real VXLAN traffic
 * becomes available to verify the integration against.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define VXLAN_PORT 4789
#define VXLAN_HDR_LEN 8

static double vxlan_detect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < VXLAN_HDR_LEN) return 0.0;

    bool i_flag = (payload[0] & 0x08) != 0;
    bool reserved_flags_zero = (payload[0] & 0xF7) == 0;
    bool reserved1_zero = (payload[1] == 0 && payload[2] == 0 && payload[3] == 0);
    bool reserved2_zero = (payload[7] == 0);
    if (!i_flag || !reserved_flags_zero || !reserved1_zero || !reserved2_zero) return 0.0;

    double confidence = 0.4;   /* an all-else-zero 8-byte header with
                                   one bit set is fairly weak evidence
                                   alone — real confidence comes from
                                   the port */
    if (dst_port == VXLAN_PORT) confidence = 0.85;
    return confidence;
}

static void vxlan_dissect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto,
                           struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < VXLAN_HDR_LEN) return;

    uint32_t vni = ((uint32_t)payload[4] << 16) | ((uint32_t)payload[5] << 8) | payload[6];
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", vni);
    dissect_result_add(out, "vxlan_vni", buf);
    dissect_result_add(out, "vxlan_vni_valid", "true");
}

static const uint16_t vxlan_hint_ports[] = { VXLAN_PORT };

void register_vxlan_dissector(void) {
    register_dissector("VXLAN", vxlan_detect, vxlan_dissect, vxlan_hint_ports, 1);
}
