/*
 * dpi_appletalk_parser.c
 *
 * AppleTalk (DDP — Datagram Delivery Protocol, EtherTalk Phase 2)
 * dissector — carried over 802.3 LLC/SNAP framing (not a real
 * EtherType at the Ethernet-II level), identified by SNAP's OUI field
 * being Apple's officially IANA/IEEE-registered OUI (08:00:07) and
 * SNAP's embedded EtherType being AppleTalk's officially registered
 * value (0x809B).
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 2 real, identical frames from a genuine capture
 * (`Paging_Request.pcap`) — hand-decoded byte-for-byte before writing
 * any C, and internally self-consistent in a way that confirms the
 * decode rather than just looking plausible: the DDP header's own
 * declared length field (77) matched the actual remaining bytes
 * exactly, and the decoded fields together describe a real, coherent
 * AppleTalk RTMP (Routing Table Maintenance Protocol) broadcast — hop
 * count 0 (a fresh, not-yet-forwarded packet), destination node 255
 * (the broadcast node address), and both source and destination
 * socket numbers set to 1 (RTMP's well-known socket), all consistent
 * with a router announcing its routing table to the local AppleTalk
 * network, not a guessed-at interpretation.
 *
 * Legacy, low-relevance protocol — included for completeness of this
 * project's real-traffic-driven roadmap, not because AppleTalk is
 * something a modern capture is likely to need.
 *
 * WIRE FORMAT: SNAP header (AA AA 03 + 3-byte OUI + 2-byte embedded
 * EtherType, 8 bytes total — the LLC DSAP/SSAP=0xAA pair identifying
 * SNAP encapsulation itself, reached via `dispatch_by_ethertype()`
 * the same way STP's LLC framing is, though AppleTalk needs the SNAP
 * sub-layer's own OUI+EtherType check rather than STP's direct
 * DSAP/SSAP=0x42 match), followed by the DDP header itself: a packed
 * Hop Count(4 bits)/Length(10 bits) field, Checksum(2 bytes),
 * Destination Network(2 bytes), Source Network(2 bytes), Destination
 * Node(1 byte), Source Node(1 byte), Destination Socket(1 byte),
 * Source Socket(1 byte), and DDP Type(1 byte) — 13 bytes total before
 * the actual upper-layer payload.
 *
 * SCOPE: SNAP/OUI detection, then the full DDP header (all 9 fields,
 * all real-traffic-verified). DDP Type is named only for the one
 * value real traffic confirmed (1 = RTMP Response/Data) — this
 * project has real, if general, confidence in several other standard
 * AppleTalk DDP type values (NBP, AEP, ZIP, ATP, and so on) from
 * general protocol knowledge, but names ONLY the real-traffic-
 * verified one rather than mix confirmed and unconfirmed values in
 * the same table without distinguishing them, matching this project's
 * discipline elsewhere of not asserting confidence in what wasn't
 * actually checked against real bytes. The upper-layer payload
 * itself (the actual RTMP routing-table entries, in this real case)
 * is not decoded further.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define APPLETALK_SNAP_HDR_LEN  8
#define APPLETALK_DDP_HDR_LEN   13
#define APPLETALK_ETHERTYPE     0x809B
#define APPLE_OUI_BYTE0         0x08
#define APPLE_OUI_BYTE1         0x00
#define APPLE_OUI_BYTE2         0x07

static const char *appletalk_ddp_type_name(uint8_t type) {
    if (type == 1) return "RTMP Response/Data";   /* the one real-traffic-verified value */
    return "Unknown";
}

/*
 * Called directly from `dispatch_by_ethertype()` when the SNAP OUI +
 * embedded EtherType signature matches — not autodetected via the
 * normal port/content-based registry, the same reasoning as STP's own
 * direct-call pattern (see dpi_stp_parser.c). `llc` points at the
 * start of the SNAP header (DSAP/SSAP already confirmed to be 0xAA by
 * the caller).
 */
static void appletalk_dissect_snap_payload(const uint8_t *llc, uint16_t llc_len) {
    if (llc_len < APPLETALK_SNAP_HDR_LEN + APPLETALK_DDP_HDR_LEN) return;
    if (llc[3] != APPLE_OUI_BYTE0 || llc[4] != APPLE_OUI_BYTE1 || llc[5] != APPLE_OUI_BYTE2) return;
    uint16_t ethertype = (llc[6] << 8) | llc[7];
    if (ethertype != APPLETALK_ETHERTYPE) return;

    const uint8_t *ddp = llc + APPLETALK_SNAP_HDR_LEN;

    uint16_t hop_and_len = (ddp[0] << 8) | ddp[1];
    uint8_t hop_count = (hop_and_len >> 10) & 0x0F;
    uint16_t ddp_length = hop_and_len & 0x3FF;
    uint16_t checksum = (ddp[2] << 8) | ddp[3];
    uint16_t dst_network = (ddp[4] << 8) | ddp[5];
    uint16_t src_network = (ddp[6] << 8) | ddp[7];
    uint8_t dst_node = ddp[8];
    uint8_t src_node = ddp[9];
    uint8_t dst_socket = ddp[10];
    uint8_t src_socket = ddp[11];
    uint8_t ddp_type = ddp[12];

    char buf[512];
    snprintf(buf, sizeof(buf),
             "{\"protocol\":\"AppleTalk\",\"ddp_hop_count\":\"%u\",\"ddp_length\":\"%u\","
             "\"ddp_checksum\":\"0x%04x\",\"ddp_dst_network\":\"%u\",\"ddp_src_network\":\"%u\","
             "\"ddp_dst_node\":\"%u\",\"ddp_src_node\":\"%u\",\"ddp_dst_socket\":\"%u\","
             "\"ddp_src_socket\":\"%u\",\"ddp_type\":\"%s\"}\n",
             hop_count, ddp_length, checksum, dst_network, src_network,
             dst_node, src_node, dst_socket, src_socket, appletalk_ddp_type_name(ddp_type));
    printf("%s", buf);
}
