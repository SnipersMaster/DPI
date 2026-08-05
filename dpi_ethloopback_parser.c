/*
 * dpi_ethloopback_parser.c
 *
 * Ethernet Loopback — real EtherType 0x9000, reached via
 * `dispatch_by_ethertype()`. Found via this project's own systematic
 * EtherType survey (127 real packets in a genuine capture,
 * `ultimate.pcapng`, real payload all zeros — consistent with a
 * keepalive/diagnostic ping carrying no meaningful content, not a
 * parsing gap).
 *
 * NOT COMPILED/TESTED in this environment. HONEST, DELIBERATE SCOPE
 * LIMIT, stated directly: this is detection-only, and unlike DECnet/
 * Banyan VINES (where the limit is "no verified spec was found yet"),
 * this one is different in kind — Wireshark's own wiki states plainly
 * that Loopback "doesn't appear in any IEEE 802 specification" at
 * all. It's a vendor-driven convention (most commonly associated with
 * Cisco's "loopback keepalive" / layer-2-ping mechanism for detecting
 * miswired or looped links) with no single, universally-defined
 * payload structure to decode in the first place — there is
 * genuinely nothing to verify a byte layout against, not just
 * something this project hasn't found yet.
 *
 * SCOPE: EtherType-based detection only, reporting the frame length.
 */

#include <stdint.h>
#include <stdio.h>

static void ethloopback_dissect_ethertype_payload(const uint8_t *payload, uint16_t len) {
    (void)payload;
    printf("{\"protocol\":\"EthernetLoopback\",\"loopback_length\":\"%u\","
           "\"note\":\"detected via EtherType 0x9000 only; no formal spec exists to decode "
           "a payload structure against, see dpi_ethloopback_parser.c\"}\n",
           len);
}
