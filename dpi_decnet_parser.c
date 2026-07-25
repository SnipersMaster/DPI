/*
 * dpi_decnet_parser.c
 *
 * DECnet Phase IV — Digital Equipment Corporation's proprietary
 * network architecture, real EtherType 0x6003 ("DNA Routing"),
 * reached via `dispatch_by_ethertype()` the same way PPPoE/EAPOL/
 * LACP are.
 *
 * NOT COMPILED/TESTED in this environment. HONEST, DELIBERATE SCOPE
 * LIMIT, stated directly rather than glossed over: this dissector
 * detects DECnet Phase IV traffic (via its EtherType, confirmed
 * across four independent, genuinely authoritative sources — OpenBSD,
 * RTEMS, and INET Framework's own ethertypes.h headers, plus
 * Wikipedia's EtherType reference table, all agreeing on 0x6003) but
 * does NOT decode the DNA Routing layer header itself. What's
 * available on this protocol's byte-level layout (Short Data Packet
 * vs. Long Data Packet formats, flag-byte semantics, address field
 * widths) came only from fragmentary secondary sources — a patent
 * filing describing hardware-forwarding logic, not a clean primary
 * specification — and even those sources disagree on details like
 * total header length (23 to 29 bytes "depending on pad length," a
 * range, not a fixed offset this project could verify against real
 * bytes). Guessing at exact field offsets from that thin a foundation
 * would be the same mistake this project has consistently declined
 * to make elsewhere (DNP3's field layout, IEEE 802.3br's mPacket SMD
 * values) — better to report "DECnet Phase IV traffic, not decoded"
 * honestly than to publish a byte-offset guess dressed up as
 * verified.
 *
 * SCOPE: EtherType-based detection only. If real DECnet Phase IV
 * traffic or the actual DNA Phase IV Routing Layer Functional
 * Specification becomes available, the routing-layer header (packet
 * type/flags, destination/source node addresses, visit count) would
 * be the natural next layer to decode — deliberately left as future
 * work rather than guessed at now.
 */

#include <stdint.h>
#include <stdio.h>

#define DECNET_ETHERTYPE 0x6003

static void decnet_dissect_ethertype_payload(const uint8_t *payload, uint16_t len) {
    (void)payload;
    printf("{\"protocol\":\"DECnet\",\"decnet_phase\":\"IV\",\"decnet_length\":\"%u\","
           "\"note\":\"detected via EtherType 0x6003 only; routing-layer header not decoded "
           "(insufficient verified byte-layout confidence, see dpi_decnet_parser.c)\"}\n",
           len);
}
