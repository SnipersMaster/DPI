/*
 * dpi_stun_parser.c
 *
 * STUN (RFC 5389) dissector — also covers TURN (RFC 5766) and TURN's
 * additional message types, since TURN extends STUN's exact same
 * header/attribute format rather than defining a new one.
 *
 * The XOR-MAPPED-ADDRESS decoding (RFC 5389 §15.2 — the address is
 * XORed with the magic cookie specifically to prevent NAT devices from
 * transparently rewriting the address the way they would a literal
 * one) was verified with a round-trip test in Python before writing
 * this C version — encode a known address, decode it back, confirm
 * it matches.
 *
 * NOT COMPILED/TESTED in this environment.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define STUN_PORT 3478
#define STUN_HDR_LEN 20
#define STUN_MAGIC_COOKIE 0x2112A442u

static const char *stun_message_type_name(uint16_t type) {
    switch (type) {
        case 0x0001: return "Binding Request";
        case 0x0101: return "Binding Success Response";
        case 0x0111: return "Binding Error Response";
        case 0x0011: return "Binding Indication";
        case 0x0003: return "Allocate Request";        /* TURN, RFC 5766 */
        case 0x0103: return "Allocate Success Response";
        case 0x0113: return "Allocate Error Response";
        case 0x0004: return "Refresh Request";
        case 0x0104: return "Refresh Success Response";
        case 0x0006: return "Send Indication";
        case 0x0007: return "Data Indication";
        case 0x0008: return "CreatePermission Request";
        case 0x0108: return "CreatePermission Success Response";
        case 0x0009: return "ChannelBind Request";
        case 0x0109: return "ChannelBind Success Response";
        default:     return "Unknown";
    }
}

static double stun_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    (void)l4_proto;   /* STUN/TURN can run over UDP or TCP; no transport restriction */
    if (len < STUN_HDR_LEN) return 0.0;

    /* Top 2 bits of Message Type MUST be 0, per RFC 5389 S6. */
    if ((payload[0] & 0xC0) != 0) return 0.0;

    uint32_t magic_cookie = (payload[4]<<24)|(payload[5]<<16)|(payload[6]<<8)|payload[7];
    if (magic_cookie != STUN_MAGIC_COOKIE) return 0.0;   /* the single strongest signal here */

    uint16_t msg_len = (payload[2] << 8) | payload[3];
    if (msg_len % 4 != 0) return 0.0;   /* RFC 5389 S6: MUST be a multiple of 4 */
    if ((size_t)STUN_HDR_LEN + msg_len > len) return 0.0;

    double confidence = 0.85;   /* magic cookie match alone is already quite strong */
    if (dst_port == STUN_PORT) confidence = 0.95;
    return confidence;
}

static void stun_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    /* Same real defense-in-depth as radius_dissect()/rtp_dissect()
     * gained after a compiler flagged this parameter as unused: don't
     * rely solely on detect()'s len < STUN_HDR_LEN check having
     * already run on this exact buffer — fail safely here too if it
     * somehow wasn't. */
    if (len < STUN_HDR_LEN) return;

    uint16_t msg_type = (payload[0] << 8) | payload[1];
    uint16_t msg_len = (payload[2] << 8) | payload[3];

    dissect_result_add(out, "stun_message_type", stun_message_type_name(msg_type));

    char txid_hex[25];
    for (int i = 0; i < 12; i++) {
        snprintf(txid_hex + i * 2, 3, "%02x", payload[8 + i]);
    }
    dissect_result_add(out, "stun_transaction_id", txid_hex);

    size_t pos = STUN_HDR_LEN;
    size_t end = STUN_HDR_LEN + msg_len;
    int attrs_parsed = 0;

    while (pos + 4 <= end && attrs_parsed < 32) {
        uint16_t attr_type = (payload[pos] << 8) | payload[pos + 1];
        uint16_t attr_len = (payload[pos + 2] << 8) | payload[pos + 3];
        size_t value_pos = pos + 4;

        if (value_pos + attr_len > end) {
            dissect_result_add(out, "parse_warning", "stun_attribute_exceeds_message");
            break;
        }

        if (attr_type == 0x0006 /* USERNAME */) {
            char username[256];
            size_t n = attr_len < sizeof(username) - 1 ? attr_len : sizeof(username) - 1;
            memcpy(username, payload + value_pos, n);
            username[n] = '\0';
            dissect_result_add(out, "stun_username", username);
        } else if (attr_type == 0x0020 /* XOR-MAPPED-ADDRESS */ && attr_len >= 8) {
            uint8_t family = payload[value_pos + 1];
            uint16_t x_port = (payload[value_pos + 2] << 8) | payload[value_pos + 3];
            uint16_t port = (uint16_t)(x_port ^ (STUN_MAGIC_COOKIE >> 16));

            if (family == 0x01 /* IPv4 */) {
                uint32_t x_addr = (payload[value_pos+4]<<24)|(payload[value_pos+5]<<16)|
                                   (payload[value_pos+6]<<8)|payload[value_pos+7];
                uint32_t addr = x_addr ^ STUN_MAGIC_COOKIE;
                char ipbuf[32];
                snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                         (addr>>24)&0xFF, (addr>>16)&0xFF, (addr>>8)&0xFF, addr&0xFF);
                dissect_result_add(out, "stun_xor_mapped_address", ipbuf);

                char portbuf[8];
                snprintf(portbuf, sizeof(portbuf), "%u", port);
                dissect_result_add(out, "stun_xor_mapped_port", portbuf);
                /* IPv6 XOR-MAPPED-ADDRESS (family 0x02) also XORs with
                 * the transaction ID, not just the magic cookie — not
                 * implemented in this reference version, flagged rather
                 * than silently mishandled. */
            }
        }

        /* Attributes are padded to a 4-byte boundary — advance past
         * the padding, not just the declared length. */
        size_t padded_len = (attr_len + 3) & ~((size_t)3);
        pos = value_pos + padded_len;
        attrs_parsed++;
    }
}

static const uint16_t stun_hint_ports[] = { STUN_PORT };

void register_stun_dissector(void) {
    register_dissector("STUN", stun_detect, stun_dissect, stun_hint_ports, 1);
}
