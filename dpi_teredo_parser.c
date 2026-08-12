/*
 * dpi_teredo_parser.c
 *
 * Teredo (RFC 4380, IPv6 tunneling over UDP through NATs) dissector —
 * UDP port 3544 (IANA-registered, confirmed by the RFC itself).
 * Requested by name in a batch cross-check against a large protocol
 * list.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic in this project's own captures — no Teredo capture was
 * available in this project's pcap survey set. Built with unusually
 * high confidence regardless, cross-checked across three genuinely
 * independent, strong sources: the RFC Editor's own RFC 4380 text
 * (via multiple mirrors), the real Wireshark project's own
 * `packet-teredo.c` dissector source code, and — most valuably — a
 * SANS Internet Storm Center blog post analyzing an actual, real
 * captured Teredo exchange with tshark, showing real field values
 * (a real nonce, a real origin UDP port and IPv4 address) that match
 * this dissector's own field layout exactly. The Origin Indication
 * header's XOR-obfuscation scheme was verified against the RFC's own
 * worked numerical example (port 337 / IPv4 1.2.3.4 obfuscating to
 * the RFC's own stated byte sequence) before writing any C — not
 * assumed correct from the prose description alone.
 *
 * WIRE FORMAT: a Teredo UDP payload optionally begins with one or
 * both of two variable-length header extensions (Authentication MUST
 * come first if both are present), followed by a real, complete IPv6
 * packet:
 *   Authentication header: 0x00 0x01 (2-byte marker) + ID-len(1) +
 *     AU-len(1) + Client Identifier(ID-len bytes) + Authentication
 *     value(AU-len bytes) + Nonce(8 bytes) + Confirmation byte(1) —
 *     ID-len and AU-len are both 0 in the common case (no strong
 *     client authentication configured), confirmed by the real SANS
 *     ISC example.
 *   Origin Indication header: 0x00 0x00 (2-byte marker) + obfuscated
 *     UDP port(2, real value XOR 0xFFFF) + obfuscated IPv4 address(4,
 *     real value XOR 0xFFFFFFFF) — 8 bytes total, de-obfuscation
 *     verified against the RFC's own worked example.
 *   IPv6 packet: a genuine, complete IPv6 header (version nibble = 6)
 *     and payload — including the special case of a "Teredo bubble",
 *     a minimal IPv6 packet with Next Header = 59 (No Next Header)
 *     and no payload at all, used purely to create/refresh a NAT
 *     mapping.
 *
 * SCOPE: both optional header extensions are decoded (Authentication:
 * ID-len, AU-len, Nonce, Confirmation byte — not the variable-length
 * Client Identifier/Authentication value fields themselves, since the
 * one real example checked had both lengths at zero and this project
 * has nothing to verify a non-zero case's field boundaries against;
 * Origin Indication: de-obfuscated port and IPv4 address, real-
 * verified per above). The tunneled IPv6 packet itself is flagged as
 * present (and specifically flagged if it's a Teredo bubble) but not
 * recursively dissected — the same reasoning as VXLAN's own inner-
 * frame scope note in this project: re-entering this project's
 * existing IPv6 dispatch chain from inside a UDP payload is a
 * structural dispatch change, not a contained addition, and is left
 * as well-scoped future work rather than attempted here.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define TEREDO_PORT 3544

static double teredo_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < 2) return 0.0;

    bool looks_like_auth = (payload[0] == 0x00 && payload[1] == 0x01);
    bool looks_like_origin = (payload[0] == 0x00 && payload[1] == 0x00 && len >= 8);
    bool looks_like_ipv6 = ((payload[0] >> 4) == 6);
    if (!looks_like_auth && !looks_like_origin && !looks_like_ipv6) return 0.0;

    double confidence = 0.3;   /* a bare IPv6-version-nibble match on
                                   its own is weak — real evidence
                                   comes from the port */
    if (dst_port == TEREDO_PORT) confidence = 0.8;
    return confidence;
}

static void teredo_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < 2) return;

    size_t pos = 0;

    if (payload[0] == 0x00 && payload[1] == 0x01 && len >= pos + 4) {
        uint8_t id_len = payload[pos + 2];
        uint8_t au_len = payload[pos + 3];
        char buf[8];
        snprintf(buf, sizeof(buf), "%u", id_len);
        dissect_result_add(out, "teredo_auth_id_len", buf);
        snprintf(buf, sizeof(buf), "%u", au_len);
        dissect_result_add(out, "teredo_auth_au_len", buf);

        size_t nonce_pos = pos + 4 + id_len + au_len;
        if (len >= nonce_pos + 9) {
            char noncebuf[24];
            size_t hex_n = 0;
            for (int i = 0; i < 8; i++) {
                snprintf(noncebuf + hex_n, 3, "%02x", payload[nonce_pos + i]);
                hex_n += 2;
            }
            noncebuf[hex_n] = '\0';
            dissect_result_add(out, "teredo_auth_nonce_hex", noncebuf);
            snprintf(buf, sizeof(buf), "%u", payload[nonce_pos + 8]);
            dissect_result_add(out, "teredo_auth_confirmation_byte", buf);
            pos = nonce_pos + 9;
        } else {
            return;   /* incomplete: don't guess past what's captured */
        }
    }

    if (pos + 8 <= len && payload[pos] == 0x00 && payload[pos + 1] == 0x00) {
        uint16_t obf_port = (payload[pos + 2] << 8) | payload[pos + 3];
        uint32_t obf_ipv4 = ((uint32_t)payload[pos+4]<<24)|((uint32_t)payload[pos+5]<<16)|
                             ((uint32_t)payload[pos+6]<<8)|payload[pos+7];
        uint16_t real_port = obf_port ^ 0xFFFF;
        uint32_t real_ipv4 = obf_ipv4 ^ 0xFFFFFFFF;

        char buf[8];
        snprintf(buf, sizeof(buf), "%u", real_port);
        dissect_result_add(out, "teredo_origin_port", buf);
        char ipbuf[16];
        snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                 (real_ipv4>>24)&0xFF, (real_ipv4>>16)&0xFF, (real_ipv4>>8)&0xFF, real_ipv4&0xFF);
        dissect_result_add(out, "teredo_origin_ipv4", ipbuf);
        pos += 8;
    }

    if (pos < len && (payload[pos] >> 4) == 6) {
        dissect_result_add(out, "teredo_inner_ipv6_present", "true");
        if (pos + 6 < len && payload[pos + 6] == 59 && len == pos + 40) {
            /* Next Header = 59 (No Next Header) and no payload beyond
             * the 40-byte IPv6 header: a Teredo bubble, per the RFC's
             * own definition. */
            dissect_result_add(out, "teredo_is_bubble", "true");
        }
    }
}

static const uint16_t teredo_hint_ports[] = { TEREDO_PORT };

void register_teredo_dissector(void) {
    register_dissector("Teredo", teredo_detect, teredo_dissect, teredo_hint_ports, 1);
}
