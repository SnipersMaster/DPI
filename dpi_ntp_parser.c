/*
 * dpi_ntp_parser.c
 *
 * NTP (RFC 5905) dissector — fixed 48-byte header, no TLV/variable
 * parsing needed for the base fields. Extension fields and MAC (RFC
 * 5905 §7.5, used for NTP authentication) may follow the base header
 * but aren't parsed here — flagged as present, matching this
 * project's general pattern for scoping optional trailers out when
 * the base header already carries the valuable fields.
 *
 * NOT COMPILED/TESTED in this environment.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define NTP_PORT     123
#define NTP_HDR_LEN  48

static const char *ntp_mode_name(uint8_t mode) {
    switch (mode) {
        case 1: return "Symmetric Active";
        case 2: return "Symmetric Passive";
        case 3: return "Client";
        case 4: return "Server";
        case 5: return "Broadcast";
        case 6: return "NTP Control Message";
        case 7: return "Private";
        default: return "Reserved";
    }
}

static double ntp_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < NTP_HDR_LEN) return 0.0;

    uint8_t li_vn_mode = payload[0];
    uint8_t version = (li_vn_mode >> 3) & 0x07;
    uint8_t mode = li_vn_mode & 0x07;

    if (version < 1 || version > 4) return 0.0;   /* NTP versions 1-4 defined */
    if (mode == 0) return 0.0;                     /* mode 0 reserved/unspecified */

    double confidence = 0.6;
    if (dst_port == NTP_PORT) confidence = 0.9;
    return confidence;
}

static void ntp_dissect(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto,
                         struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint8_t li_vn_mode = payload[0];
    uint8_t leap = (li_vn_mode >> 6) & 0x03;
    uint8_t version = (li_vn_mode >> 3) & 0x07;
    uint8_t mode = li_vn_mode & 0x07;
    uint8_t stratum = payload[1];

    char buf[16];
    snprintf(buf, sizeof(buf), "%u", version);
    dissect_result_add(out, "ntp_version", buf);
    dissect_result_add(out, "ntp_mode", ntp_mode_name(mode));
    snprintf(buf, sizeof(buf), "%u", stratum);
    dissect_result_add(out, "ntp_stratum", buf);
    snprintf(buf, sizeof(buf), "%u", leap);
    dissect_result_add(out, "ntp_leap_indicator", buf);

    /* Reference ID, RFC 5905 S7.3: for stratum 0/1 this is a 4-char
     * ASCII "kiss code" or clock source identifier (e.g. "GPS ",
     * "PPS "); for stratum >=2 it's the IPv4 address of the reference
     * source. Surface both interpretations' raw bytes as hex; the
     * caller can decide which applies based on stratum. */
    char refid_hex[16];
    snprintf(refid_hex, sizeof(refid_hex), "%02x%02x%02x%02x",
             payload[12], payload[13], payload[14], payload[15]);
    dissect_result_add(out, "ntp_reference_id_hex", refid_hex);

    if (len > NTP_HDR_LEN) {
        dissect_result_add(out, "ntp_extension_or_mac_present", "true");
    }
}

static const uint16_t ntp_hint_ports[] = { NTP_PORT };

void register_ntp_dissector(void) {
    register_dissector("NTP", ntp_detect, ntp_dissect, ntp_hint_ports, 1);
}

