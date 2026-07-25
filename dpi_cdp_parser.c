/*
 * dpi_cdp_parser.c
 *
 * CDP (Cisco Discovery Protocol) dissector — LLC/SNAP-encapsulated
 * (Cisco's OUI 00:00:0c, embedded PID 0x2000), destined to the
 * well-known multicast MAC 01:00:0c:cc:cc:cc. Reached via the same
 * SNAP-detection path AppleTalk uses, distinguished by OUI+PID rather
 * than AppleTalk's own OUI 08:00:07 + EtherType 0x809B.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic in this project's own captures — no CDP packet was
 * available while building this. Built with meaningfully higher
 * confidence than that alone would justify: the Wireshark wiki
 * documents a complete, real, field-by-field decoded CDP packet
 * (Device ID, Addresses, Platform, Protocol Hello, VTP Management
 * Domain, Native VLAN, Duplex TLVs all shown with their real values
 * from an actual capture), and Cisco's own IOS configuration guides
 * independently confirm the same TLV-based structure and well-known
 * multicast destination — cross-checked across genuinely independent
 * sources, not a single uncertain reference.
 *
 * WIRE FORMAT: 4-byte header — Version(1) + TTL(1, seconds a
 * receiver should retain this information) + Checksum(2) — followed
 * by TLVs: Type(2) + Length(2, including the 4-byte TLV header
 * itself) + Value.
 *
 * SCOPE: header fields, and the TLV types the Wireshark wiki's real
 * worked example actually showed decoded — Device-ID (0x0001),
 * Addresses (0x0002, count only, not the encoded address entries
 * themselves — CDP's address TLV uses a nested, NLPID-tagged encoding
 * this project doesn't have a confirmed byte-exact layout for),
 * Platform (0x0006), Native VLAN (0x000a), and Duplex (0x000b, a
 * single byte: 0x00=half, 0x01=full). Every other TLV type Cisco
 * documents (Capabilities, Software-Version, IP-Prefix, and more) is
 * named where confidently known but not decoded further.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define CDP_HDR_LEN      4
#define CDP_MAX_TLVS     24
#define CISCO_OUI_BYTE0  0x00
#define CISCO_OUI_BYTE1  0x00
#define CISCO_OUI_BYTE2  0x0C
#define CDP_SNAP_PID     0x2000

static const char *cdp_tlv_name(uint16_t type) {
    switch (type) {
        case 0x0001: return "device_id";
        case 0x0002: return "addresses";
        case 0x0003: return "port_id";
        case 0x0004: return "capabilities";
        case 0x0005: return "software_version";
        case 0x0006: return "platform";
        case 0x0007: return "ip_prefix";
        case 0x0008: return "protocol_hello";
        case 0x0009: return "vtp_management_domain";
        case 0x000a: return "native_vlan";
        case 0x000b: return "duplex";
        default:      return NULL;
    }
}

/*
 * Called directly from `dispatch_by_ethertype()`'s SNAP-detection
 * path once the OUI/PID match Cisco's CDP signature — not
 * autodetected via the normal registry, the same reasoning as
 * AppleTalk's own SNAP-framed dissector.
 */
static void cdp_dissect_snap_payload(const uint8_t *llc, uint16_t llc_len) {
    if (llc_len < 8 + CDP_HDR_LEN) return;
    if (llc[3] != CISCO_OUI_BYTE0 || llc[4] != CISCO_OUI_BYTE1 || llc[5] != CISCO_OUI_BYTE2) return;
    uint16_t pid = (llc[6] << 8) | llc[7];
    if (pid != CDP_SNAP_PID) return;

    const uint8_t *cdp = llc + 8;
    uint16_t cdp_len = llc_len - 8;

    uint8_t version = cdp[0];
    uint8_t ttl = cdp[1];
    uint16_t checksum = (cdp[2] << 8) | cdp[3];

    char buf[1024];
    int written = snprintf(buf, sizeof(buf),
             "{\"protocol\":\"CDP\",\"cdp_version\":\"%u\",\"cdp_ttl_sec\":\"%u\","
             "\"cdp_checksum\":\"0x%04x\"", version, ttl, checksum);

    size_t pos = CDP_HDR_LEN;
    int n_tlvs = 0;
    while (pos + 4 <= cdp_len && n_tlvs < CDP_MAX_TLVS && written < (int)sizeof(buf) - 64) {
        uint16_t tlv_type = (cdp[pos] << 8) | cdp[pos + 1];
        uint16_t tlv_len = (cdp[pos + 2] << 8) | cdp[pos + 3];
        if (tlv_len < 4 || pos + tlv_len > cdp_len) break;
        const uint8_t *tlv_val = cdp + pos + 4;
        uint16_t val_len = tlv_len - 4;

        const char *name = cdp_tlv_name(tlv_type);
        if (name) {
            if (tlv_type == 0x0001 || tlv_type == 0x0005 || tlv_type == 0x0006 ||
                tlv_type == 0x0009) {
                /* Free-text fields (UTF-8/ASCII per Cisco's own docs
                 * and the Wireshark wiki's real example). */
                char textbuf[256];
                size_t n = val_len < sizeof(textbuf) - 1 ? val_len : sizeof(textbuf) - 1;
                memcpy(textbuf, tlv_val, n);
                textbuf[n] = '\0';
                written += snprintf(buf + written, sizeof(buf) - written,
                                     ",\"cdp_%s\":\"%s\"", name, textbuf);
            } else if (tlv_type == 0x0002 && val_len >= 4) {
                uint32_t addr_count = ((uint32_t)tlv_val[0]<<24)|((uint32_t)tlv_val[1]<<16)|
                                      ((uint32_t)tlv_val[2]<<8)|tlv_val[3];
                written += snprintf(buf + written, sizeof(buf) - written,
                                     ",\"cdp_address_count\":\"%u\"", addr_count);
            } else if (tlv_type == 0x000a && val_len >= 2) {
                uint16_t vlan = (tlv_val[0] << 8) | tlv_val[1];
                written += snprintf(buf + written, sizeof(buf) - written,
                                     ",\"cdp_native_vlan\":\"%u\"", vlan);
            } else if (tlv_type == 0x000b && val_len >= 1) {
                written += snprintf(buf + written, sizeof(buf) - written,
                                     ",\"cdp_duplex\":\"%s\"", tlv_val[0] ? "full" : "half");
            }
        }

        pos += tlv_len;
        n_tlvs++;
    }

    snprintf(buf + written, sizeof(buf) - written, "}\n");
    printf("%s", buf);
}
