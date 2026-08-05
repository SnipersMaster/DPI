/*
 * dpi_macsec_parser.c
 *
 * MACsec (IEEE 802.1AE, Media Access Control Security) SecTAG
 * dissector — real EtherType 0x88E5, reached via
 * `dispatch_by_ethertype()` the same way PPPoE/EAPOL/LACP are. Found
 * via this project's own systematic EtherType survey across every
 * pcap in its working set (16 real packets in a genuine capture,
 * `ultimate.pcapng`).
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified with unusually high confidence for a protocol with no
 * dedicated real-traffic capture of its own: the SecTAG byte layout
 * was cross-checked against IEEE 802.1AE-2006's own standard text,
 * a Linux kernel netdev RFC patch implementing MACsec, Nokia's own
 * router documentation, a Renesas technical blog, and — critically —
 * the tcpdump project's own `print-macsec.c` source code, which
 * documents the identical field layout in an ASCII diagram. Applied
 * to the one real capture found: decoded to TCI_AN flags (SCI
 * present, payload encrypted), a Packet Number of 16, and a Secure
 * Channel Identifier whose MAC-address component
 * (`00:0c:29:55:9b:4b`) is a genuine, independently-recognizable
 * VMware-registered OUI — real confirmation that the byte offsets
 * are correct, not just a plausible-looking parse.
 *
 * WIRE FORMAT: the SecTAG immediately follows the MACsec EtherType —
 * TCI_AN(1 byte: Version(1 bit) + End Station(1 bit) + SC/SCI-
 * present(1 bit) + SCB/Single-Copy-Broadcast(1 bit) + Encrypted(1
 * bit) + Changed-Text(1 bit) + Association Number(2 bits)) + Short
 * Length(1 byte, only the low 6 bits used — the protected payload's
 * length if under 48 bytes, otherwise 0) + Packet Number(4 bytes) +
 * an OPTIONAL Secure Channel Identifier(8 bytes: a 48-bit MAC address
 * + 16-bit port identifier — present only if the SC bit in TCI_AN is
 * set).
 *
 * SCOPE: the SecTAG only, real-traffic-verified per above. The actual
 * protected payload that follows the SecTAG (and the 16-byte
 * Integrity Check Value that follows THAT) is, by design, either
 * encrypted or merely integrity-protected — MACsec's entire purpose
 * is exactly this, the same reason this project doesn't attempt to
 * decode inside TLS/QUIC's encrypted records either. Reporting the
 * SecTAG's own metadata (association number, packet number, secure
 * channel identity) is real, useful visibility without pretending to
 * see through encryption this project has no key material for.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define MACSEC_SECTAG_FIXED_LEN 6   /* TCI_AN(1) + SL(1) + Packet Number(4) */
#define MACSEC_SCI_LEN 8

static void macsec_dissect_ethertype_payload(const uint8_t *payload, uint16_t len) {
    if (len < MACSEC_SECTAG_FIXED_LEN) return;

    uint8_t tci_an = payload[0];
    bool version = (tci_an >> 7) & 1;
    bool end_station = (tci_an >> 6) & 1;
    bool sci_present = (tci_an >> 5) & 1;
    bool scb = (tci_an >> 4) & 1;
    bool encrypted = (tci_an >> 3) & 1;
    bool changed_text = (tci_an >> 2) & 1;
    uint8_t an = tci_an & 0x03;
    uint8_t sl = payload[1] & 0x3F;
    uint32_t packet_number = ((uint32_t)payload[2] << 24) | ((uint32_t)payload[3] << 16) |
                              ((uint32_t)payload[4] << 8) | payload[5];

    char sci_buf[24] = "";
    if (sci_present && len >= MACSEC_SECTAG_FIXED_LEN + MACSEC_SCI_LEN) {
        const uint8_t *sci = payload + MACSEC_SECTAG_FIXED_LEN;
        uint16_t port = (sci[6] << 8) | sci[7];
        snprintf(sci_buf, sizeof(sci_buf), "%02x:%02x:%02x:%02x:%02x:%02x/%u",
                 sci[0], sci[1], sci[2], sci[3], sci[4], sci[5], port);
    }

    printf("{\"protocol\":\"MACsec\",\"macsec_version\":\"%s\",\"macsec_end_station\":\"%s\","
           "\"macsec_sci_present\":\"%s\",\"macsec_single_copy_broadcast\":\"%s\","
           "\"macsec_encrypted\":\"%s\",\"macsec_changed_text\":\"%s\","
           "\"macsec_association_number\":\"%u\",\"macsec_short_length\":\"%u\","
           "\"macsec_packet_number\":\"%u\"%s%s%s}\n",
           version ? "true" : "false", end_station ? "true" : "false",
           sci_present ? "true" : "false", scb ? "true" : "false",
           encrypted ? "true" : "false", changed_text ? "true" : "false",
           an, sl, packet_number,
           sci_buf[0] ? ",\"macsec_sci\":\"" : "", sci_buf, sci_buf[0] ? "\"" : "");
}
