/*
 * dpi_mysql_parser.c
 *
 * MySQL client/server protocol dissector — TCP port 3306. Focuses on
 * the Initial Handshake packet (the server's very first message,
 * protocol version 10), the single highest-value packet for passive
 * identification: real server version, connection ID, and capability
 * flags, all without needing to track the full connection/command
 * phase state machine.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * captured traffic — no MySQL capture was available while building
 * this. Built with real confidence regardless: MySQL's own official
 * developer documentation (dev.mysql.com) documents this exact
 * packet layout, and a real, concrete example handshake packet
 * (`36 00 00 00 0a 35 2e 35 2e 32 2d 6d 32 00 52 00 ...`, from the
 * mysql-proxy project's own protocol documentation) was hand-decoded
 * byte-for-byte against this project's own field-offset assumptions
 * before writing any C — packet length (54), sequence ID (0),
 * protocol version (10), server version string ("5.5.2-m2"),
 * connection ID (82), and the lower 2 bytes of capability flags
 * (0xffff) all matched exactly.
 *
 * WIRE FORMAT: every MySQL packet is wrapped in a 4-byte header —
 * payload length (3 bytes, little-endian) + sequence ID (1 byte) —
 * confirmed identical across MySQL's own docs, MariaDB's docs, and
 * the mysql-proxy real example. The Initial Handshake packet payload
 * (protocol version 10): Protocol Version(1, always 0x0a for this
 * variant) + Server Version(NUL-terminated string) + Connection
 * ID(4) + Auth-Plugin-Data-Part-1(8) + Filler(1, always 0x00) +
 * Capability Flags lower 2 bytes(2) + optionally more fields this
 * project doesn't decode further (character set, status flags,
 * capability flags upper bytes, auth-plugin-data-part-2, auth-plugin
 * name).
 *
 * SCOPE: packet header (length, sequence ID), and for the Initial
 * Handshake packet specifically: protocol version, server version
 * string (a genuinely useful fingerprinting field — reveals the real
 * MySQL/MariaDB version and often distinguishes the two per
 * MariaDB's own documented convention of including "mariadb" in the
 * string), connection ID, and capability flags (lower 2 bytes only —
 * confirmed against the real example; the upper 2 bytes are
 * conditionally present depending on those same flags, a real,
 * genuinely more involved layout this project doesn't decode
 * further). Later connection-phase and command-phase packets
 * (HandshakeResponse, OK/ERR packets, queries, result sets) are not
 * decoded — a real, substantial state machine (which packet type
 * follows which depends on prior capability negotiation) this
 * project doesn't attempt without real traffic to verify the
 * decision points against.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define MYSQL_PORT           3306
#define MYSQL_HDR_LEN        4
#define MYSQL_PROTOCOL_V10   0x0a

static double mysql_detect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < MYSQL_HDR_LEN + 1) return 0.0;

    uint32_t pkt_len = payload[0] | ((uint32_t)payload[1] << 8) | ((uint32_t)payload[2] << 16);
    uint8_t seq_id = payload[3];
    /* The Initial Handshake is always sequence 0, always protocol
     * version 10 in modern MySQL/MariaDB, and its declared length
     * must fit within what's actually captured — a structural check,
     * the same discipline as every other length-prefixed protocol in
     * this project. */
    if (seq_id != 0) return 0.0;
    if (payload[MYSQL_HDR_LEN] != MYSQL_PROTOCOL_V10) return 0.0;
    if (MYSQL_HDR_LEN + pkt_len > (uint32_t)len + 32) return 0.0;   /* generous
                                                                        margin —
                                                                        a real
                                                                        capture
                                                                        might be
                                                                        snap-length
                                                                        truncated */

    double confidence = 0.6;
    if (dst_port == MYSQL_PORT) confidence = 0.9;
    return confidence;
}

static void mysql_dissect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto,
                           struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < MYSQL_HDR_LEN + 1) return;

    uint32_t pkt_len = payload[0] | ((uint32_t)payload[1] << 8) | ((uint32_t)payload[2] << 16);
    uint8_t seq_id = payload[3];

    char buf[16];
    snprintf(buf, sizeof(buf), "%u", pkt_len);
    dissect_result_add(out, "mysql_packet_length", buf);
    snprintf(buf, sizeof(buf), "%u", seq_id);
    dissect_result_add(out, "mysql_sequence_id", buf);

    const uint8_t *hs = payload + MYSQL_HDR_LEN;
    uint16_t hs_len = len - MYSQL_HDR_LEN;
    if (hs_len < 1 || hs[0] != MYSQL_PROTOCOL_V10) return;

    dissect_result_add(out, "mysql_protocol_version", "10");

    /* Server version: NUL-terminated string right after the protocol
     * version byte. */
    size_t pos = 1;
    size_t vstart = pos;
    while (pos < hs_len && hs[pos] != 0) pos++;
    if (pos >= hs_len) return;   /* no NUL found within what we have: incomplete */
    char server_version[128];
    size_t vlen = pos - vstart;
    size_t n = vlen < sizeof(server_version) - 1 ? vlen : sizeof(server_version) - 1;
    memcpy(server_version, hs + vstart, n);
    server_version[n] = '\0';
    dissect_result_add(out, "mysql_server_version", server_version);
    pos++;   /* skip the NUL */

    if (pos + 4 > hs_len) return;
    uint32_t connection_id = hs[pos] | ((uint32_t)hs[pos+1]<<8) |
                              ((uint32_t)hs[pos+2]<<16) | ((uint32_t)hs[pos+3]<<24);
    snprintf(buf, sizeof(buf), "%u", connection_id);
    dissect_result_add(out, "mysql_connection_id", buf);
    pos += 4;

    pos += 8;   /* auth-plugin-data-part-1, not extracted — opaque
                   challenge data, not a meaningful identifier */
    pos += 1;   /* filler byte, always 0x00 */

    if (pos + 2 > hs_len) return;
    uint16_t cap_lower = hs[pos] | ((uint16_t)hs[pos+1] << 8);
    snprintf(buf, sizeof(buf), "0x%04x", cap_lower);
    dissect_result_add(out, "mysql_capability_flags_lower", buf);
    /* Character set, status flags, capability flags upper bytes,
     * auth-plugin-data-part-2, and auth-plugin name are conditionally
     * present depending on those same capability flags — a real,
     * genuinely more involved layout this project doesn't decode
     * further, see file header. */
}

static const uint16_t mysql_hint_ports[] = { MYSQL_PORT };

void register_mysql_dissector(void) {
    register_dissector("MySQL", mysql_detect, mysql_dissect, mysql_hint_ports, 1);
}
