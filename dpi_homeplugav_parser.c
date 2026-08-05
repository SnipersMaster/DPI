/*
 * dpi_homeplugav_parser.c
 *
 * HomePlug AV — a powerline-networking protocol (Ethernet frames
 * carried over household electrical wiring, via dedicated adapter
 * hardware). Real EtherType 0x88E1, reached via
 * `dispatch_by_ethertype()`. Found via this project's own systematic
 * EtherType survey (28 real packets in a genuine capture,
 * `ultimate.pcapng`).
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against the real capture: the header format (Management
 * Message Version + Type + OUI) is confirmed identical across the
 * `faifa` open-source HomePlug configuration tool's own manpage,
 * Wireshark's own EtherType registry, and multiple independent
 * technical write-ups. Applied to the real bytes found, the decoded
 * OUI (`00:b0:52`) is a genuine, independently-recognizable
 * registered OUI belonging to Intellon Corporation — the original
 * developer of the HomePlug AV protocol — real confirmation the byte
 * offsets are correct, the same kind of independent cross-check
 * MACsec's own verification relied on (a real VMware OUI landing
 * exactly where the spec says a MAC address should be).
 *
 * WIRE FORMAT: Management Message Version(1 byte) + Management
 * Message Type(2 bytes) + OUI(3 bytes, identifying the vendor/
 * implementation) + Payload (variable — explicitly documented by
 * the protocol's own real-world tooling as "highly dependent on the
 * implementation," not a single fixed format even across vendors).
 *
 * SCOPE: the fixed 6-byte header only — Management Message Version,
 * Management Message Type (reported as a raw hex value, not named;
 * the real capture's own MM Type didn't match any of the small
 * number of specific values this project found named in public
 * references, and this project won't guess at an unconfirmed
 * mapping), and OUI. The variable-format, vendor-specific payload is
 * not decoded — by the protocol's own real-world documentation, this
 * isn't a fixed structure to decode in the first place.
 */

#include <stdint.h>
#include <stdio.h>

#define HOMEPLUGAV_HDR_LEN 6

static void homeplugav_dissect_ethertype_payload(const uint8_t *payload, uint16_t len) {
    if (len < HOMEPLUGAV_HDR_LEN) return;

    uint8_t mm_version = payload[0];
    uint16_t mm_type = (payload[1] << 8) | payload[2];

    printf("{\"protocol\":\"HomePlugAV\",\"homeplugav_mm_version\":\"%u\","
           "\"homeplugav_mm_type\":\"0x%04x\","
           "\"homeplugav_oui\":\"%02x:%02x:%02x\"}\n",
           mm_version, mm_type, payload[3], payload[4], payload[5]);
}
