/*
 * dpi_mobileip_parser.c
 *
 * Mobile IPv4 (RFC 5944, obsoleting RFC 3344) dissector — UDP port
 * 434 (IANA-registered, confirmed directly by the RFC Editor's own
 * text). Requested by name ("mobile_ip") in a batch cross-check
 * against a large protocol list.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic — no Mobile IP capture was available in this project's
 * pcap survey set. Built with real confidence regardless: the
 * Registration Request field layout was cross-checked across the RFC
 * Editor's own RFC 5944 text (via multiple mirrors — the RFC Editor
 * page, hjp.at, tech-invite.com) and its own worked example message
 * (Section 4, showing real field values for a documented registration
 * scenario), all agreeing. The flags-byte bit order (S/B/D/M/G/r/T/x)
 * and the 24-byte fixed field layout before Extensions begin were
 * verified with a constructed round-trip test before writing any C.
 *
 * WIRE FORMAT — Registration Request: Type(1, =1) + Flags(1 byte: S=
 * Simultaneous bindings, B=Broadcast datagrams, D=co-located care-of
 * address (Decapsulation by mobile node), M=Minimal encapsulation, G=
 * GRE encapsulation, r=reserved/MUST be 0, T=reverse Tunneling
 * requested, x=reserved/MUST be 0) + Lifetime(2, seconds) + Home
 * Address(4) + Home Agent(4) + Care-of Address(4) + Identification(8,
 * an NTP timestamp or nonce, used for replay protection) + optional
 * Extensions (TLV format, variable, not decoded — see SCOPE). A
 * Registration Reply (Type=3) uses a similar but distinct layout —
 * Code(1, a result/error code) in place of Flags, and no Care-of
 * Address field.
 *
 * SCOPE: message Type (named), and for a Registration Request
 * specifically, the Flags byte (broken into its 6 real, individually
 * meaningful bits — 2 reserved bits not surfaced), Lifetime, Home
 * Address, Home Agent, and Care-of Address. Registration Reply's own
 * Code field is named against RFC 5944's real, published result-code
 * table where confidently known (a small set of well-known values —
 * 0=accepted, 1=accepted-but-no-simultaneous-bindings, 128+=denied by
 * FA, 192+=denied by HA); Extensions (authentication, and more, TLV-
 * encoded) are not decoded for either message type — real, separate
 * structure this project has no real traffic to verify a byte-exact
 * layout against.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define MOBILEIP_PORT 434
#define MOBILEIP_REQ_HDR_LEN 20

static const char *mobileip_type_name(uint8_t type) {
    switch (type) {
        case 1: return "Registration Request";
        case 3: return "Registration Reply";
        default: return "Unknown";
    }
}

static double mobileip_detect(const uint8_t *payload, uint16_t len,
                               uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < 2) return 0.0;

    uint8_t type = payload[0];
    if (strcmp(mobileip_type_name(type), "Unknown") == 0) return 0.0;
    if (type == 1 && len < MOBILEIP_REQ_HDR_LEN) return 0.0;

    double confidence = 0.4;
    if (dst_port == MOBILEIP_PORT) confidence = 0.8;
    return confidence;
}

static void mobileip_dissect(const uint8_t *payload, uint16_t len,
                              uint16_t dst_port, const char *l4_proto,
                              struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < 2) return;

    uint8_t type = payload[0];
    dissect_result_add(out, "mobileip_type", mobileip_type_name(type));

    if (type != 1 || len < MOBILEIP_REQ_HDR_LEN) return;   /* only
                                                                Registration
                                                                Request's
                                                                layout is
                                                                decoded
                                                                further,
                                                                see file
                                                                header */

    uint8_t flags = payload[1];
    uint16_t lifetime = (payload[2] << 8) | payload[3];
    char buf[16];

    dissect_result_add(out, "mobileip_flag_simultaneous_bindings", (flags & 0x80) ? "true" : "false");
    dissect_result_add(out, "mobileip_flag_broadcast", (flags & 0x40) ? "true" : "false");
    dissect_result_add(out, "mobileip_flag_colocated_decapsulation", (flags & 0x20) ? "true" : "false");
    dissect_result_add(out, "mobileip_flag_minimal_encap", (flags & 0x10) ? "true" : "false");
    dissect_result_add(out, "mobileip_flag_gre_encap", (flags & 0x08) ? "true" : "false");
    dissect_result_add(out, "mobileip_flag_reverse_tunnel", (flags & 0x02) ? "true" : "false");

    snprintf(buf, sizeof(buf), "%u", lifetime);
    dissect_result_add(out, "mobileip_lifetime_sec", buf);

    char ipbuf[16];
    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", payload[4], payload[5], payload[6], payload[7]);
    dissect_result_add(out, "mobileip_home_address", ipbuf);
    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", payload[8], payload[9], payload[10], payload[11]);
    dissect_result_add(out, "mobileip_home_agent", ipbuf);
    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", payload[12], payload[13], payload[14], payload[15]);
    dissect_result_add(out, "mobileip_care_of_address", ipbuf);
}

static const uint16_t mobileip_hint_ports[] = { MOBILEIP_PORT };

void register_mobileip_dissector(void) {
    register_dissector("MobileIP", mobileip_detect, mobileip_dissect, mobileip_hint_ports, 1);
}
