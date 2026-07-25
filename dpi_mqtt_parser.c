/*
 * dpi_mqtt_parser.c
 *
 * MQTT (OASIS MQTT 3.1.1 / 5.0) dissector — compact binary protocol.
 * The "Remaining Length" variable-length encoding was verified in
 * Python against the spec's own worked example (0xC1 0x02 -> 321)
 * before writing this C version.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * SCOPE: extracts Protocol Name/Client ID for CONNECT, Topic Name for
 * PUBLISH — the two message types that actually carry
 * identifying/routing information useful for IoT traffic
 * visibility. Other message types (SUBSCRIBE/UNSUBSCRIBE topic
 * filters, etc.) are detected (message type surfaced) but their
 * payloads aren't parsed further in this pass.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define MQTT_PORT 1883
#define MQTT_TLS_PORT 8883

static const char *mqtt_type_name(uint8_t type) {
    switch (type) {
        case 1:  return "CONNECT";
        case 2:  return "CONNACK";
        case 3:  return "PUBLISH";
        case 4:  return "PUBACK";
        case 5:  return "PUBREC";
        case 6:  return "PUBREL";
        case 7:  return "PUBCOMP";
        case 8:  return "SUBSCRIBE";
        case 9:  return "SUBACK";
        case 10: return "UNSUBSCRIBE";
        case 11: return "UNSUBACK";
        case 12: return "PINGREQ";
        case 13: return "PINGRESP";
        case 14: return "DISCONNECT";
        case 15: return "AUTH";
        default: return "Reserved";
    }
}

/*
 * Decode the "Remaining Length" field, MQTT spec S2.2.3 — up to 4
 * bytes, each contributing 7 bits with a continuation bit in the top
 * bit. Verified against the spec's own example before use (see file
 * header).
 */
static bool mqtt_decode_remaining_length(const uint8_t *data, size_t len, size_t *pos,
                                          uint32_t *out_value) {
    uint32_t multiplier = 1;
    uint32_t value = 0;
    int bytes_used = 0;

    while (true) {
        if (*pos >= len) return false;
        uint8_t b = data[*pos];
        (*pos)++;
        value += (uint32_t)(b & 0x7F) * multiplier;

        if ((b & 0x80) == 0) break;

        multiplier *= 128;
        bytes_used++;
        if (bytes_used >= 4) return false;   /* malformed: spec caps at 4 bytes */
    }

    *out_value = value;
    return true;
}

static double mqtt_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;   /* MQTT is TCP-only (or TLS-over-TCP) */
    if (len < 2) return 0.0;

    uint8_t type = (payload[0] >> 4) & 0x0F;
    if (type == 0 || type > 15) return 0.0;

    size_t pos = 1;
    uint32_t remaining_length;
    if (!mqtt_decode_remaining_length(payload, len, &pos, &remaining_length)) return 0.0;
    if (pos + remaining_length > len) return 0.0;   /* declared length exceeds buffer */

    double confidence = 0.5;
    if (dst_port == MQTT_PORT || dst_port == MQTT_TLS_PORT) confidence = 0.85;
    return confidence;
}

/* Read a length-prefixed UTF-8 string (2-byte length + bytes), MQTT
 * spec S1.5.4. Bounds-checked the same way every other string-with-
 * length-prefix field is handled throughout this project. */
static bool mqtt_read_string(const uint8_t *data, size_t len, size_t *pos,
                              char *out, size_t out_cap) {
    if (*pos + 2 > len) return false;
    uint16_t str_len = (data[*pos] << 8) | data[*pos + 1];
    *pos += 2;
    if (*pos + str_len > len) return false;

    size_t copy_len = str_len < out_cap - 1 ? str_len : out_cap - 1;
    memcpy(out, data + *pos, copy_len);
    out[copy_len] = '\0';
    *pos += str_len;
    return true;
}

static void mqtt_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint8_t type = (payload[0] >> 4) & 0x0F;
    dissect_result_add(out, "mqtt_message_type", mqtt_type_name(type));

    size_t pos = 1;
    uint32_t remaining_length;
    if (!mqtt_decode_remaining_length(payload, len, &pos, &remaining_length)) {
        dissect_result_add(out, "parse_warning", "malformed_remaining_length");
        return;
    }
    size_t payload_end = pos + remaining_length;
    if (payload_end > len) {
        dissect_result_add(out, "parse_warning", "remaining_length_exceeds_buffer");
        return;
    }

    char strbuf[256];

    if (type == 1 /* CONNECT */) {
        if (mqtt_read_string(payload, payload_end, &pos, strbuf, sizeof(strbuf))) {
            dissect_result_add(out, "mqtt_protocol_name", strbuf);
        }
        if (pos + 2 > payload_end) return;   /* protocol level(1) + connect flags(1) */
        uint8_t protocol_level = payload[pos];
        pos += 2;   /* skip protocol level + connect flags */
        if (pos + 2 > payload_end) return;   /* keep alive(2) */
        pos += 2;

        char levelbuf[8];
        snprintf(levelbuf, sizeof(levelbuf), "%u", protocol_level);
        dissect_result_add(out, "mqtt_protocol_level", levelbuf);

        if (mqtt_read_string(payload, payload_end, &pos, strbuf, sizeof(strbuf))) {
            dissect_result_add(out, "mqtt_client_id", strbuf);
        }
    } else if (type == 3 /* PUBLISH */) {
        uint8_t qos = (payload[0] >> 1) & 0x03;
        char qosbuf[4];
        snprintf(qosbuf, sizeof(qosbuf), "%u", qos);
        dissect_result_add(out, "mqtt_qos", qosbuf);

        if (mqtt_read_string(payload, payload_end, &pos, strbuf, sizeof(strbuf))) {
            dissect_result_add(out, "mqtt_topic_name", strbuf);
        }
        /* Packet Identifier (if QoS > 0) and the actual publish
         * payload follow — not extracted here, matching this file's
         * stated scope (routing/identity fields, not message content). */
    }
}

static const uint16_t mqtt_hint_ports[] = { MQTT_PORT, MQTT_TLS_PORT };

void register_mqtt_dissector(void) {
    register_dissector("MQTT", mqtt_detect, mqtt_dissect, mqtt_hint_ports, 2);
}

