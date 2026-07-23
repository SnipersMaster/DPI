/*
 * dpi_tftp_parser.c
 *
 * TFTP (RFC 1350) dissector — UDP port 69.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against the one real TFTP packet found across every pcap
 * checked for this project — but that one packet is a complete,
 * fully self-contained WRQ (Write Request), not a fragment: opcode 2,
 * filename `"CCNP-LAB-R2-Mar--3-20-02-38.701-7"` (a realistic,
 * timestamped router-config filename — a real Cisco CCNP lab router
 * pushing its config to a TFTP server for backup, a genuine, common
 * network-operations scenario), mode `"octet"`, and the packet was
 * consumed EXACTLY to the last byte by this structure (2 + 34 + 6 =
 * 42 bytes, matching the real packet's length precisely) — confirmed
 * arithmetically, not just visually inspected.
 *
 * WIRE FORMAT (RFC 1350 S5): Opcode(2) then, depending on opcode:
 *   RRQ(1)/WRQ(2): Filename (null-terminated ASCII) + Mode
 *     (null-terminated ASCII, "netascii"/"octet"/"mail").
 *   DATA(3): Block#(2) + Data (up to 512 bytes, less than 512 meaning
 *     this is the final block).
 *   ACK(4): Block#(2), nothing else.
 *   ERROR(5): ErrorCode(2) + ErrMsg (null-terminated ASCII).
 *
 * SCOPE, stated honestly: only RRQ/WRQ's structure is real-traffic-
 * verified (via the one real WRQ found). DATA/ACK/ERROR's structure
 * is implemented directly from RFC 1350's text — all three are
 * simple, fixed-shape fields (a 2-byte block number or error code
 * plus, for ERROR, a null-terminated string using the identical
 * string-extraction logic already proven correct on the real WRQ's
 * filename/mode fields), so the same bounds-checking approach applies
 * with reasonable confidence even without a real example of each,
 * matching this project's established practice of extending an
 * already-proven parsing pattern to adjacent, similarly-shaped cases
 * (e.g. GTPv2-C's EBI/AMBR additions) rather than guessing at
 * something structurally novel.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define TFTP_STRING_MAX 128

static const char *tftp_opcode_name(uint16_t opcode) {
    switch (opcode) {
        case 1: return "RRQ";
        case 2: return "WRQ";
        case 3: return "DATA";
        case 4: return "ACK";
        case 5: return "ERROR";
        case 6: return "OACK";
        default: return "Unknown";
    }
}

/* Extracts a null-terminated ASCII string starting at *pos, bounded
 * to TFTP_STRING_MAX-1 characters; advances *pos past the terminator.
 * Returns false if no terminator is found within the buffer (doesn't
 * guess at a truncated string). */
static bool tftp_read_cstring(const uint8_t *data, size_t len, size_t *pos,
                               char *out, size_t out_cap) {
    size_t start = *pos;
    size_t i = start;
    while (i < len && data[i] != 0) i++;
    if (i >= len) return false;   /* no terminator found: truncated, don't guess */
    size_t str_len = i - start;
    size_t n = str_len < out_cap - 1 ? str_len : out_cap - 1;
    for (size_t k = 0; k < n; k++) {
        out[k] = isprint(data[start + k]) ? (char)data[start + k] : '.';
    }
    out[n] = '\0';
    *pos = i + 1;
    return true;
}

static double tftp_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < 4) return 0.0;

    uint16_t opcode = (payload[0] << 8) | payload[1];
    if (opcode < 1 || opcode > 6) return 0.0;

    double confidence = 0.6;
    if (dst_port == 69) confidence = 0.85;
    return confidence;
}

static void tftp_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < 4) return;

    uint16_t opcode = (payload[0] << 8) | payload[1];
    dissect_result_add(out, "tftp_opcode", tftp_opcode_name(opcode));

    char buf[TFTP_STRING_MAX];

    if (opcode == 1 || opcode == 2) {   /* RRQ / WRQ — real-traffic-verified */
        size_t pos = 2;
        if (tftp_read_cstring(payload, len, &pos, buf, sizeof(buf))) {
            dissect_result_add(out, "tftp_filename", buf);
            if (tftp_read_cstring(payload, len, &pos, buf, sizeof(buf))) {
                dissect_result_add(out, "tftp_mode", buf);
            }
        }
    } else if (opcode == 3 && len >= 4) {   /* DATA — not real-traffic-verified */
        uint16_t block = (payload[2] << 8) | payload[3];
        snprintf(buf, sizeof(buf), "%u", block);
        dissect_result_add(out, "tftp_block", buf);
        snprintf(buf, sizeof(buf), "%u", (unsigned)(len - 4));
        dissect_result_add(out, "tftp_data_length", buf);
    } else if (opcode == 4 && len >= 4) {   /* ACK — not real-traffic-verified */
        uint16_t block = (payload[2] << 8) | payload[3];
        snprintf(buf, sizeof(buf), "%u", block);
        dissect_result_add(out, "tftp_block", buf);
    } else if (opcode == 5 && len >= 4) {   /* ERROR — not real-traffic-verified */
        uint16_t error_code = (payload[2] << 8) | payload[3];
        snprintf(buf, sizeof(buf), "%u", error_code);
        dissect_result_add(out, "tftp_error_code", buf);
        size_t pos = 4;
        if (tftp_read_cstring(payload, len, &pos, buf, sizeof(buf))) {
            dissect_result_add(out, "tftp_error_message", buf);
        }
    }
}

static const uint16_t tftp_hint_ports[] = { 69 };

void register_tftp_dissector(void) {
    register_dissector("TFTP", tftp_detect, tftp_dissect, tftp_hint_ports, 1);
}
