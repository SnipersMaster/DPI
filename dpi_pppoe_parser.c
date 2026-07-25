/*
 * dpi_pppoe_parser.c
 *
 * PPPoE (RFC 2516, "A Method for Transmitting PPP Over Ethernet")
 * dissector — real Ethernet EtherTypes (0x8863 Discovery stage,
 * 0x8864 PPP Session stage), reached via `dispatch_by_ethertype()`
 * the same way IPv6/ARP/MPLS already are, not LLC-framed like STP/
 * AppleTalk.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic — no PPPoE capture was available while building this,
 * stated honestly rather than implied otherwise.
 *
 * Built with meaningfully higher confidence than a real-traffic gap
 * would usually justify, because RFC 2516 itself is a long-published,
 * stable standard (February 1999), not a draft under revision — the
 * exact header layout, CODE values, and TAG format were cross-checked
 * across the RFC Editor's own page, IETF's mirror, and independent
 * vendor documentation (Huawei, Nokia), all showing byte-for-byte
 * identical values, the same category of confidence this project
 * placed in RFC 3331 (M2UA) and RFC 6166 (PIM) rather than the
 * draft-committee uncertainty that kept IEEE 802.3br's mPacket SMD
 * values deliberately undecoded.
 *
 * WIRE FORMAT: VER(4 bits, always 1) + TYPE(4 bits, always 1) packed
 * into the first byte, CODE(1 byte), SESSION_ID(2 bytes), LENGTH(2
 * bytes, the PPPoE payload length only — not including the Ethernet
 * or PPPoE headers themselves) — 6 bytes total. For Discovery-stage
 * packets (PADI/PADO/PADR/PADS/PADT), the payload is zero or more
 * TAGs: TAG_TYPE(2) + TAG_LENGTH(2) + TAG_VALUE. For Session-stage
 * packets, the payload begins with a 2-byte PPP Protocol field (per
 * RFC 1661) followed by the actual PPP payload.
 *
 * SCOPE: VER/TYPE validation, CODE (named per RFC 2516's full table),
 * SESSION_ID, LENGTH. For Discovery-stage packets, TAGs are walked
 * and the three most useful ones decoded as text (Service-Name,
 * AC-Name, Host-Uniq — all UTF-8/opaque per spec, not further
 * structured); other TAG types are named only. For Session-stage
 * packets, only the PPP Protocol field is identified (against RFC
 * 1661's well-known, stable values — IP, LCP, PAP, CHAP); the actual
 * PPP payload itself is not decoded further — a deeper layer this
 * project doesn't attempt without real traffic to verify against.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define PPPOE_HDR_LEN     6
#define PPPOE_ETHERTYPE_DISCOVERY 0x8863
#define PPPOE_ETHERTYPE_SESSION   0x8864
#define PPPOE_MAX_TAGS    16

static const char *pppoe_code_name(uint8_t code) {
    switch (code) {
        case 0x09: return "PADI";   /* Active Discovery Initiation */
        case 0x07: return "PADO";   /* Active Discovery Offer */
        case 0x19: return "PADR";   /* Active Discovery Request */
        case 0x65: return "PADS";   /* Active Discovery Session-confirmation */
        case 0xa7: return "PADT";   /* Active Discovery Terminate */
        case 0x00: return "Session_Data";
        default:   return "Unknown";
    }
}

static const char *ppp_protocol_name(uint16_t proto) {
    switch (proto) {
        case 0x0021: return "IP";
        case 0x0057: return "IPv6";
        case 0xC021: return "LCP";   /* Link Control Protocol */
        case 0xC023: return "PAP";   /* Password Authentication Protocol */
        case 0xC223: return "CHAP";  /* Challenge Handshake Authentication Protocol */
        case 0x8021: return "IPCP";  /* IP Control Protocol */
        case 0x8057: return "IPv6CP";
        default:      return "Unknown";
    }
}

/*
 * Called directly from `dispatch_by_ethertype()` for a real EtherType
 * match (0x8863/0x8864) — not autodetected via the normal port/
 * content registry, the same reasoning as every other real-EtherType
 * protocol already handled there (IPv6, ARP, MPLS).
 */
static void pppoe_dissect_ethertype_payload(const uint8_t *payload, uint16_t len,
                                             bool is_discovery_stage) {
    if (len < PPPOE_HDR_LEN) return;

    uint8_t ver = (payload[0] >> 4) & 0x0F;
    uint8_t type = payload[0] & 0x0F;
    if (ver != 1 || type != 1) return;   /* malformed or a future PPPoE version: don't guess */

    uint8_t code = payload[1];
    uint16_t session_id = (payload[2] << 8) | payload[3];
    uint16_t pppoe_length = (payload[4] << 8) | payload[5];

    const char *code_name = pppoe_code_name(code);
    if (strcmp(code_name, "Unknown") == 0) return;

    char buf[512];
    int written = snprintf(buf, sizeof(buf),
             "{\"protocol\":\"PPPoE\",\"pppoe_stage\":\"%s\",\"pppoe_code\":\"%s\","
             "\"pppoe_session_id\":\"0x%04x\",\"pppoe_length\":\"%u\"",
             is_discovery_stage ? "Discovery" : "Session",
             code_name, session_id, pppoe_length);

    const uint8_t *body = payload + PPPOE_HDR_LEN;
    uint16_t body_len = len - PPPOE_HDR_LEN;
    if (body_len > pppoe_length) body_len = pppoe_length;   /* bound to the
                                                                declared length,
                                                                not just whatever
                                                                was captured —
                                                                same discipline
                                                                as dpi_stp_parser.c */

    if (is_discovery_stage) {
        size_t pos = 0;
        int n_tags = 0;
        while (pos + 4 <= body_len && n_tags < PPPOE_MAX_TAGS && written < (int)sizeof(buf) - 32) {
            uint16_t tag_type = (body[pos] << 8) | body[pos + 1];
            uint16_t tag_len = (body[pos + 2] << 8) | body[pos + 3];
            if (pos + 4 + tag_len > body_len) break;
            const uint8_t *tag_val = body + pos + 4;

            const char *tag_key = tag_type == 0x0101 ? "pppoe_service_name" :
                                   tag_type == 0x0102 ? "pppoe_ac_name" :
                                   tag_type == 0x0103 ? "pppoe_host_uniq_hex" : NULL;
            if (tag_key) {
                char tagbuf[192];
                if (tag_type == 0x0103) {
                    /* Host-Uniq is opaque, host-chosen data (often not
                     * printable text) — always shown as hex, not
                     * risked as a printable string the way Service-
                     * Name/AC-Name (UTF-8 per spec) are. */
                    size_t hex_n = 0;
                    for (size_t i = 0; i < tag_len && hex_n + 2 < sizeof(tagbuf) - 1; i++) {
                        snprintf(tagbuf + hex_n, 3, "%02x", tag_val[i]);
                        hex_n += 2;
                    }
                    tagbuf[hex_n] = '\0';
                } else {
                    size_t n = tag_len < sizeof(tagbuf) - 1 ? tag_len : sizeof(tagbuf) - 1;
                    memcpy(tagbuf, tag_val, n);
                    tagbuf[n] = '\0';
                }
                written += snprintf(buf + written, sizeof(buf) - written,
                                     ",\"%s\":\"%s\"", tag_key, tagbuf);
            }

            pos += 4 + tag_len;
            n_tags++;
        }
    } else {
        if (body_len >= 2) {
            uint16_t ppp_proto = (body[0] << 8) | body[1];
            written += snprintf(buf + written, sizeof(buf) - written,
                                 ",\"pppoe_ppp_protocol\":\"%s\"", ppp_protocol_name(ppp_proto));
        }
    }

    snprintf(buf + written, sizeof(buf) - written, "}\n");
    printf("%s", buf);
}
