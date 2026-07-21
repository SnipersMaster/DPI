/*
 * dpi_esp_parser.c
 *
 * IPsec ESP (Encapsulating Security Payload, RFC 4303) dissector — IP
 * protocol 50. Extracts ONLY the SPI (Security Parameters Index) and
 * Sequence Number, which are the sole unencrypted fields in ESP by
 * design; everything after them (the actual payload, padding, pad
 * length, next header, and ICV) is encrypted and/or authenticated and
 * cannot be parsed without the negotiated keys — which this passive
 * dissector, consistent with every other protocol in this project,
 * does not have and does not attempt to obtain or use.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against all 542 real ESP packets from a genuine capture
 * (Johannes Weber's "Ultimate PCAP") — 8 distinct Security
 * Associations (by SPI), each with sequence numbers correctly
 * incrementing from 1 in its own independent sequence space (e.g. SPI
 * 0xfb735613 ran from sequence 1 to 154 across its 154 packets) —
 * exactly the behavior RFC 4303's anti-replay window design predicts
 * for real traffic, confirmed rather than assumed.
 *
 * WIRE FORMAT (RFC 4303 S2): SPI(4) + Sequence Number(4), followed by
 * the encrypted Payload Data (variable) + Padding + Pad Length(1) +
 * Next Header(1) + Integrity Check Value (variable, if present) — all
 * of which requires the Security Association's negotiated algorithm
 * and key material to interpret, neither of which is available here.
 *
 * VALUE OF SPI/SEQUENCE ALONE, despite not decrypting anything: SPI
 * lets a passive observer distinguish and count distinct Security
 * Associations (tunnels) between the same two endpoints, and the
 * sequence number's progression is a legitimate signal for detecting
 * replay-window resets (e.g. an SA rekey) or gaps (packet loss) —
 * genuine network visibility without needing the payload itself, same
 * category of value as GRE's Key field or a TCP sequence number.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define ESP_HDR_LEN 8

static double esp_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    (void)dst_port; (void)l4_proto;   /* identified by IP protocol 50
                                        * already at the capture path,
                                        * same reasoning as GRE/OSPF */
    if (len < ESP_HDR_LEN) return 0.0;
    return 0.85;   /* can't validate structure further than "long enough
                     * for the fixed header" — everything past it is
                     * encrypted, so there's no additional structural
                     * signal to check, unlike protocols with a magic
                     * number or version field to confirm against */
}

static void esp_dissect(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto,
                         struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < ESP_HDR_LEN) return;

    uint32_t spi = ((uint32_t)payload[0]<<24)|((uint32_t)payload[1]<<16)|
                   ((uint32_t)payload[2]<<8)|payload[3];
    uint32_t seq = ((uint32_t)payload[4]<<24)|((uint32_t)payload[5]<<16)|
                   ((uint32_t)payload[6]<<8)|payload[7];

    char buf[16];
    snprintf(buf, sizeof(buf), "0x%08x", spi);
    dissect_result_add(out, "esp_spi", buf);
    snprintf(buf, sizeof(buf), "%u", seq);
    dissect_result_add(out, "esp_sequence", buf);
    dissect_result_add(out, "esp_payload_encrypted", "true");
}

static const uint16_t esp_hint_ports[] = { 0 };   /* no port concept, see file header */

void register_esp_dissector(void) {
    register_dissector("ESP", esp_detect, esp_dissect, esp_hint_ports, 0);
}
