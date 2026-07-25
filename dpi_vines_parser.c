/*
 * dpi_vines_parser.c
 *
 * Banyan VINES — Banyan Systems' proprietary network operating
 * system protocol suite, built on VIP (VINES Internetwork Protocol,
 * derived from Xerox XNS). Real EtherType 0x0BAD, reached via
 * `dispatch_by_ethertype()` the same way DECnet's is.
 *
 * NOT COMPILED/TESTED in this environment. HONEST, DELIBERATE SCOPE
 * LIMIT, stated directly: this dissector detects Banyan VINES traffic
 * (via its EtherType, confirmed across six independent, genuinely
 * authoritative sources — OpenBSD, FreeBSD/NetBSD, and Wireshark's
 * own ethertypes/etypes.h headers, a QNX source tree, and a
 * from-scratch Rust ethertype implementation, all agreeing on
 * 0x0BAD) but does NOT decode VIP's own header. What's available on
 * VIP's byte-level layout amounted to architectural background
 * (VINES uses a 32-bit network address + 16-bit subnet mapped to
 * Ethernet addresses, derived from XNS) rather than a byte-exact,
 * verified header format this project could check field offsets
 * against — the same situation DECnet's own dissector is in, and
 * handled the same way: report detection honestly, don't guess at
 * structure.
 *
 * SCOPE: EtherType-based detection only (this file also recognizes
 * VINES's two related EtherTypes, Loopback 0x0BAE and Echo 0x0BAF,
 * naming which of the three applies). If real VINES traffic or VIP's
 * actual protocol specification becomes available, decoding the VIP
 * header (source/destination network+subnet+port addressing) would
 * be the natural next layer — deliberately left as future work.
 */

#include <stdint.h>
#include <stdio.h>

#define VINES_ETHERTYPE_IP      0x0BAD
#define VINES_ETHERTYPE_LOOPBACK 0x0BAE
#define VINES_ETHERTYPE_ECHO     0x0BAF

static void vines_dissect_ethertype_payload(const uint8_t *payload, uint16_t len,
                                             uint16_t ethertype) {
    (void)payload;
    const char *subtype = ethertype == VINES_ETHERTYPE_IP ? "IP" :
                           ethertype == VINES_ETHERTYPE_LOOPBACK ? "Loopback" : "Echo";
    printf("{\"protocol\":\"BanyanVINES\",\"vines_subtype\":\"%s\",\"vines_length\":\"%u\","
           "\"note\":\"detected via EtherType only; VIP header not decoded "
           "(insufficient verified byte-layout confidence, see dpi_vines_parser.c)\"}\n",
           subtype, len);
}
