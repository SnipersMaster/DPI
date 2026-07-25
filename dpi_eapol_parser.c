/*
 * dpi_eapol_parser.c
 *
 * EAPOL (Extensible Authentication Protocol over LAN, IEEE 802.1X)
 * dissector — real EtherType 0x888E, reached via
 * `dispatch_by_ethertype()` the same way IPv6/ARP/MPLS/PPPoE already
 * are.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic — no EAPOL capture was available while building this,
 * stated honestly. Built with meaningfully higher confidence than
 * that alone would justify: IEEE 802.1X's EAPOL header format (a
 * fixed 4-byte Version/Type/Length header) and the 5 standard packet
 * types are consistently documented, byte-for-byte identical, across
 * multiple independent sources checked (a Wireshark-based real packet
 * walkthrough, HPE's own 802.1X documentation, and general IEEE
 * 802.1X references) — a stable standard, not a draft under revision.
 *
 * WIRE FORMAT: Version(1 byte — 1 for 802.1X-2001, 2 for -2004, 3 for
 * -2010) + Type(1 byte) + Length(2 bytes, the packet body length —
 * zero and no body follows for EAPOL-Start/Logoff) + Packet Body
 * (variable, format depends on Type).
 *
 * SCOPE: Version, Type (named, all 5 standard values), Length. For
 * an EAP-Packet type specifically, the inner EAP header (Code/
 * Identifier/Length, and Type for Request/Response) is decoded too —
 * RFC 3748's EAP header format, independently stable and well-known.
 * EAPOL-Key's own body (the actual WPA/WPA2 4-way-handshake key
 * material and MIC) is NOT decoded — a real, more involved,
 * security-sensitive structure this project doesn't have a confirmed
 * byte-exact layout for, and extracting raw key-exchange material
 * isn't something to guess at regardless.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define EAPOL_HDR_LEN  4

static const char *eapol_type_name(uint8_t type) {
    switch (type) {
        case 0: return "EAP-Packet";
        case 1: return "EAPOL-Start";
        case 2: return "EAPOL-Logoff";
        case 3: return "EAPOL-Key";
        case 4: return "EAPOL-Encapsulated-ASF-Alert";
        default: return "Unknown";
    }
}

static const char *eap_code_name(uint8_t code) {
    switch (code) {
        case 1: return "Request";
        case 2: return "Response";
        case 3: return "Success";
        case 4: return "Failure";
        default: return "Unknown";
    }
}

/* RFC 3748's well-known EAP Type values, for a Request/Response. */
static const char *eap_type_name(uint8_t type) {
    switch (type) {
        case 1:  return "Identity";
        case 2:  return "Notification";
        case 3:  return "Nak";
        case 4:  return "MD5-Challenge";
        case 13: return "EAP-TLS";
        case 25: return "PEAP";
        case 26: return "MS-EAP-Authentication";
        case 43: return "EAP-FAST";
        default:  return "Unknown";
    }
}

/*
 * Called directly from `dispatch_by_ethertype()` for a real
 * EtherType match (0x888E) — not autodetected via the normal
 * registry, the same reasoning as PPPoE's own real-EtherType
 * dissector.
 */
static void eapol_dissect_ethertype_payload(const uint8_t *payload, uint16_t len) {
    if (len < EAPOL_HDR_LEN) return;

    uint8_t version = payload[0];
    uint8_t type = payload[1];
    uint16_t length = (payload[2] << 8) | payload[3];

    if (version < 1 || version > 3) return;   /* only versions 1-3
                                                  (802.1X-2001/2004/2010)
                                                  are documented */
    const char *type_name = eapol_type_name(type);
    if (strcmp(type_name, "Unknown") == 0) return;

    char buf[512];
    int written = snprintf(buf, sizeof(buf),
             "{\"protocol\":\"EAPOL\",\"eapol_version\":\"%u\",\"eapol_type\":\"%s\","
             "\"eapol_length\":\"%u\"", version, type_name, length);

    if (type == 0 /* EAP-Packet */ && len >= EAPOL_HDR_LEN + 4) {
        const uint8_t *eap = payload + EAPOL_HDR_LEN;
        uint8_t eap_code = eap[0];
        uint8_t eap_id = eap[1];
        uint16_t eap_len = (eap[2] << 8) | eap[3];

        written += snprintf(buf + written, sizeof(buf) - written,
                             ",\"eap_code\":\"%s\",\"eap_identifier\":\"%u\",\"eap_length\":\"%u\"",
                             eap_code_name(eap_code), eap_id, eap_len);

        if ((eap_code == 1 || eap_code == 2) && len >= EAPOL_HDR_LEN + 5) {
            uint8_t eap_type = eap[4];
            written += snprintf(buf + written, sizeof(buf) - written,
                                 ",\"eap_type\":\"%s\"", eap_type_name(eap_type));
        }
    }
    /* EAPOL-Key's body (WPA/WPA2 4-way handshake material) is
     * deliberately not decoded — see file header. */

    snprintf(buf + written, sizeof(buf) - written, "}\n");
    printf("%s", buf);
}
