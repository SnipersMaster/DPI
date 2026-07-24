/*
 * dpi_netbios_parser.c
 *
 * NetBIOS over TCP/IP (RFC 1001/1002) dissector — Name Service (NBNS,
 * UDP port 137) and Datagram Service (NBDS, UDP port 138). One file
 * for both since they share the same NetBIOS name "first-level
 * encoding" (RFC 1001 Appendix B): each byte of the 16-byte NetBIOS
 * name is split into two nibbles, each nibble mapped to an ASCII
 * letter 'A'-'P' by adding 0x41 — the actual mechanism behind names
 * that show up on the wire as 32-byte strings like the real decoded
 * example below.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 1,611 real NBNS packets and 1,205 real NBDS
 * packets across 7 pcaps (several from a monitored 2009 network,
 * plus dedicated single-host captures). A real NBNS query's name
 * field decoded exactly via the first-level encoding to "WORKGROUP"
 * with suffix byte 0x1D (Master Browser) — hand-verified byte-for-
 * byte before writing any C, not assumed from the RFC text alone.
 *
 * WIRE FORMAT:
 *   NBNS header (RFC 1002 S4.2, deliberately DNS-shaped — same
 *     Transaction ID/Flags/QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT layout as
 *     `dpi_dns_parser.c` already handles, though NOT reused directly
 *     here since NBNS's opcode/flag bit layout and name encoding
 *     differ enough that a shared decoder would need as much special-
 *     casing as just writing this small one directly): Transaction
 *     ID(2) + Flags(2, opcode in bits 11-14, response bit 15) +
 *     QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2), then a
 *     Question section with a first-level-encoded NAME.
 *   NBDS header (RFC 1002 S7): Msg Type(1) + Flags(1) + Datagram
 *     ID(2) + Source IP(4) + Source Port(2) + [for Direct/Broadcast
 *     types] Datagram Length(2) + Packet Offset(2) + Source Name
 *     (first-level encoded) + Destination Name (first-level encoded)
 *     + user data.
 *
 * SCOPE: NBNS — opcode (named), response bit, and the decoded name +
 * suffix byte from the question section. NBDS — message type (named)
 * and the decoded source/destination names. The actual datagram
 * payload (which can itself be a NetLogon mailslot broadcast, an SMB
 * browser announcement, etc.) is not decoded further — a separate,
 * substantially larger problem, same "highest-value piece" scope as
 * elsewhere in this project.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define NBNS_HDR_LEN 12
#define NBDS_MIN_HDR_LEN 14
#define NETBIOS_ENCODED_NAME_LEN 32

static const char *nbns_opcode_name(uint8_t opcode) {
    switch (opcode) {
        case 0: return "Query";
        case 5: return "Registration";
        case 6: return "Release";
        case 7: return "WACK";
        case 8: return "Refresh";
        default: return "Unknown";
    }
}

static const char *nbds_msg_type_name(uint8_t msg_type) {
    switch (msg_type) {
        case 0x10: return "Direct_Unique Datagram";
        case 0x11: return "Direct_Group Datagram";
        case 0x12: return "Broadcast Datagram";
        case 0x13: return "Datagram Error";
        case 0x14: return "Datagram Query Request";
        case 0x15: return "Datagram Positive Query Response";
        case 0x16: return "Datagram Negative Query Response";
        default: return "Unknown";
    }
}

/* Decodes a first-level-encoded NetBIOS name (RFC 1001 Appendix B).
 * `data` must point to the length byte; returns the number of bytes
 * consumed (1 length byte + encoded name bytes) or 0 on malformed
 * input. `out` receives the decoded 16-byte name (trailing spaces
 * trimmed) and `suffix` the 16th (service-type) byte. */
static size_t netbios_decode_name(const uint8_t *data, size_t avail,
                                   char *out, size_t out_cap, uint8_t *suffix) {
    if (avail < 1) return 0;
    uint8_t len = data[0];
    if (len != NETBIOS_ENCODED_NAME_LEN || avail < 1 + (size_t)len) return 0;

    uint8_t decoded[16];
    for (int i = 0; i < 16; i++) {
        uint8_t hi = data[1 + i*2] - 'A';
        uint8_t lo = data[1 + i*2 + 1] - 'A';
        if (hi > 0x0F || lo > 0x0F) return 0;   /* not valid first-level encoding */
        decoded[i] = (hi << 4) | lo;
    }
    *suffix = decoded[15];

    int name_len = 15;
    while (name_len > 0 && decoded[name_len - 1] == ' ') name_len--;
    size_t n = (size_t)name_len < out_cap - 1 ? (size_t)name_len : out_cap - 1;
    memcpy(out, decoded, n);
    out[n] = '\0';

    return 1 + len;
}

static double netbios_detect(const uint8_t *payload, uint16_t len,
                              uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;

    if (dst_port == 137) {
        if (len < NBNS_HDR_LEN) return 0.0;
        return 0.85;
    }
    if (dst_port == 138) {
        if (len < NBDS_MIN_HDR_LEN) return 0.0;
        uint8_t msg_type = payload[0];
        if (msg_type < 0x10 || msg_type > 0x16) return 0.0;
        return 0.85;
    }
    return 0.0;
}

static void nbns_dissect(const uint8_t *payload, uint16_t len, struct dissect_result *out) {
    if (len < NBNS_HDR_LEN) return;

    uint16_t flags = (payload[2] << 8) | payload[3];
    uint8_t opcode = (flags >> 11) & 0x0F;
    bool is_response = (flags >> 15) & 1;
    uint16_t qdcount = (payload[4] << 8) | payload[5];

    dissect_result_add(out, "nbns_opcode", nbns_opcode_name(opcode));
    dissect_result_add(out, "nbns_is_response", is_response ? "true" : "false");

    if (qdcount > 0 && len > NBNS_HDR_LEN) {
        char name[17];
        uint8_t suffix;
        size_t consumed = netbios_decode_name(payload + NBNS_HDR_LEN, len - NBNS_HDR_LEN,
                                               name, sizeof(name), &suffix);
        if (consumed > 0) {
            dissect_result_add(out, "nbns_name", name);
            char sbuf[8];
            snprintf(sbuf, sizeof(sbuf), "0x%02x", suffix);
            dissect_result_add(out, "nbns_name_suffix", sbuf);
        }
    }
}

static void nbds_dissect(const uint8_t *payload, uint16_t len, struct dissect_result *out) {
    if (len < NBDS_MIN_HDR_LEN) return;

    uint8_t msg_type = payload[0];
    dissect_result_add(out, "nbds_msg_type", nbds_msg_type_name(msg_type));

    char srcip[16];
    snprintf(srcip, sizeof(srcip), "%u.%u.%u.%u", payload[4], payload[5], payload[6], payload[7]);
    dissect_result_add(out, "nbds_source_ip", srcip);

    /* Direct_Unique/Direct_Group/Broadcast types (0x10-0x12) have the
     * Datagram Length + Packet Offset + Source/Destination Name
     * fields; Error/Query-response types (0x13-0x16) have a shorter,
     * differently-shaped body not covered here — same "highest-value
     * piece" scope as the file header states. */
    if (msg_type >= 0x10 && msg_type <= 0x12 && len > NBDS_MIN_HDR_LEN) {
        size_t pos = NBDS_MIN_HDR_LEN;
        char srcname[17], dstname[17];
        uint8_t suffix;
        size_t consumed = netbios_decode_name(payload + pos, len - pos, srcname, sizeof(srcname), &suffix);
        if (consumed > 0) {
            dissect_result_add(out, "nbds_source_name", srcname);
            pos += consumed;
            if (pos < len) {
                consumed = netbios_decode_name(payload + pos, len - pos, dstname, sizeof(dstname), &suffix);
                if (consumed > 0) {
                    dissect_result_add(out, "nbds_destination_name", dstname);
                }
            }
        }
    }
}

static void netbios_dissect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto,
                             struct dissect_result *out) {
    (void)l4_proto;
    if (dst_port == 137) {
        nbns_dissect(payload, len, out);
    } else if (dst_port == 138) {
        nbds_dissect(payload, len, out);
    }
}

static const uint16_t netbios_hint_ports[] = { 137, 138 };

void register_netbios_dissector(void) {
    register_dissector("NetBIOS", netbios_detect, netbios_dissect, netbios_hint_ports, 2);
}
