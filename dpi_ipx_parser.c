/*
 * dpi_ipx_parser.c
 *
 * IPX (Novell's Internetwork Packet Exchange, derived from Xerox
 * XNS's IDP) dissector — reached via the "raw 802.3" length-field
 * framing case flagged earlier in this project (a real capture
 * showed a length-field frame — declared length 0x32/50 — matching
 * neither STP's nor AppleTalk/CDP's LLC DSAP/SSAP signature; IPX's
 * own classic "raw 802.3" framing, with no LLC header at all, is
 * exactly the historical reason that gap exists at all). Requested
 * by name in a batch cross-check against a large protocol list.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic in this project's own captures — no real IPX bytes have
 * been provided to check against yet (the original `0x32` frame's
 * actual content still hasn't been shared). Built with unusually high
 * confidence regardless: the fixed 30-byte header layout was cross-
 * checked across Novell's own original product documentation (the
 * protocol's actual vendor, not a third party), Microsoft's own IPX
 * reference documentation, RFC 1553 (a real IETF RFC, discussing IPX
 * header compression, giving its own independent ASCII field
 * diagram), and multiple further independent technical references —
 * all agreeing on the same field order and the same total (30 bytes),
 * a genuinely strong, multi-source consensus even without a real
 * captured packet of this project's own to check against.
 *
 * WIRE FORMAT: a fixed 30-byte header, no variable-length fields at
 * all — Checksum(2, historically always 0xFFFF — real IPX
 * deployments essentially never used this field, per Novell's own
 * documentation) + Packet Length(2, header + payload, i.e. the whole
 * IPX packet) + Transport Control(1, hop count — 0 at the source,
 * incremented by each router) + Packet Type(1) + Destination
 * Network(4) + Destination Node(6, a MAC-style address) + Destination
 * Socket(2) + Source Network(4) + Source Node(6) + Source Socket(2).
 *
 * SCOPE: the full 30-byte header — Packet Length, Transport Control,
 * Packet Type (named per the well-known, standard packet-type table:
 * RIP, Echo, Error, IPX/IDP, SPX, and the higher NetWare-specific
 * values NCP and NetBIOS Name Packet), and all four address/socket
 * fields. This IS this project's own raw-802.3 detection case,
 * so it's called directly from `dispatch_by_ethertype()`'s existing
 * length-field branch (matching neither STP's nor AppleTalk/CDP's LLC
 * signature) rather than the normal port-based registry — detection
 * here checks the IPX header's own internal plausibility (the
 * near-universal 0xFFFF checksum convention, a sane declared length,
 * and a recognized Packet Type) since there's no port or DSAP/SSAP
 * byte to key off of. The actual payload (an IDP/SPX/RIP/NCP message,
 * depending on Packet Type) is not decoded further.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define IPX_HDR_LEN 30

static const char *ipx_packet_type_name(uint8_t type) {
    switch (type) {
        case 0:  return "Unknown";
        case 1:  return "RIP";     /* Routing Information Packet */
        case 2:  return "Echo";
        case 3:  return "Error";
        case 4:  return "IPX";     /* IDP — the base IPX/IDP packet itself */
        case 5:  return "SPX";     /* Sequenced Packet Protocol */
        case 17: return "NCP";     /* NetWare Core Protocol */
        case 20: return "NetBIOS-Name-Packet";
        default:  return NULL;     /* not "Unknown" (that's a real,
                                       named type=0) — NULL signals
                                       "not a value this project has
                                       confidently named" */
    }
}

/*
 * Called directly from `dispatch_by_ethertype()`'s existing raw-802.3
 * length-field branch — not autodetected via the normal port-based
 * registry, since IPX has neither a port nor an LLC DSAP/SSAP
 * signature to key off of. `llc` points at the very start of the
 * 802.3 payload (right after the length field), matching the same
 * calling convention STP/AppleTalk/CDP's own direct-dispatch
 * functions use.
 */
static bool ipx_dissect_raw_8023_payload(const uint8_t *llc, uint16_t llc_len) {
    if (llc_len < IPX_HDR_LEN) return false;

    uint16_t checksum = (llc[0] << 8) | llc[1];
    uint16_t pkt_len = (llc[2] << 8) | llc[3];
    uint8_t transport_control = llc[4];
    uint8_t packet_type = llc[5];

    /* Internal-plausibility check, since there's no port/DSAP to key
     * off of: the checksum being 0xFFFF is the single strongest,
     * near-universal real-world signal (per every source checked —
     * genuine IPX deployments essentially never computed it), a
     * declared length that doesn't exceed what's actually captured,
     * and a Packet Type this project actually recognizes. */
    if (checksum != 0xFFFF) return false;
    if (pkt_len < IPX_HDR_LEN || pkt_len > llc_len) return false;
    const char *type_name = ipx_packet_type_name(packet_type);
    if (type_name == NULL) return false;

    char netbuf[16], macbuf[18];
    char buf[512];
    int written = snprintf(buf, sizeof(buf),
             "{\"protocol\":\"IPX\",\"ipx_length\":\"%u\",\"ipx_transport_control\":\"%u\","
             "\"ipx_packet_type\":\"%s\"",
             pkt_len, transport_control, type_name);

    snprintf(netbuf, sizeof(netbuf), "%02x%02x%02x%02x", llc[6], llc[7], llc[8], llc[9]);
    written += snprintf(buf + written, sizeof(buf) - written,
                         ",\"ipx_dst_network\":\"%s\"", netbuf);
    snprintf(macbuf, sizeof(macbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
             llc[10], llc[11], llc[12], llc[13], llc[14], llc[15]);
    written += snprintf(buf + written, sizeof(buf) - written,
                         ",\"ipx_dst_node\":\"%s\"", macbuf);
    written += snprintf(buf + written, sizeof(buf) - written,
                         ",\"ipx_dst_socket\":\"%u\"", (llc[16] << 8) | llc[17]);

    snprintf(netbuf, sizeof(netbuf), "%02x%02x%02x%02x", llc[18], llc[19], llc[20], llc[21]);
    written += snprintf(buf + written, sizeof(buf) - written,
                         ",\"ipx_src_network\":\"%s\"", netbuf);
    snprintf(macbuf, sizeof(macbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
             llc[22], llc[23], llc[24], llc[25], llc[26], llc[27]);
    written += snprintf(buf + written, sizeof(buf) - written,
                         ",\"ipx_src_node\":\"%s\"", macbuf);
    written += snprintf(buf + written, sizeof(buf) - written,
                         ",\"ipx_src_socket\":\"%u\"", (llc[28] << 8) | llc[29]);

    snprintf(buf + written, sizeof(buf) - written, "}\n");
    printf("%s", buf);

    uint16_t dst_socket = (llc[16] << 8) | llc[17];
    uint16_t src_socket = (llc[28] << 8) | llc[29];
    if ((dst_socket == 0x0452 || src_socket == 0x0452) && llc_len > IPX_HDR_LEN) {
        ipxsap_dissect(llc + IPX_HDR_LEN, llc_len - IPX_HDR_LEN);
    }

    return true;
}
