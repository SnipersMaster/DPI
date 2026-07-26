/*
 * dpi_postgresql_parser.c
 *
 * PostgreSQL wire protocol dissector — TCP port 5432. Focuses on the
 * StartupMessage, the client's very first message and the single
 * highest-value packet for passive identification (protocol version,
 * requested database, and connecting user, all in cleartext before
 * any authentication or encryption negotiation).
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * captured traffic — no PostgreSQL capture was available while
 * building this. Built with real confidence regardless: PostgreSQL's
 * own official documentation (postgresql.org) documents this exact
 * message format identically across every version checked (8.2
 * through 16, spanning nearly 15 years) — a genuinely stable format,
 * not something that's drifted release to release. A real, if
 * simple, worked example from PostgreSQL's own mailing list archives
 * ("user\0postgres\0database\0maach\0\0") was hand-decoded against
 * this project's own field-offset assumptions before writing any C
 * and confirmed to parse correctly into the two real parameters.
 *
 * WIRE FORMAT: unlike every other PostgreSQL message (which start
 * with a 1-byte type identifier), StartupMessage has none — it's
 * simply Int32(message length, including itself) + Int32(protocol
 * version — major in the upper 16 bits, 3 for the modern protocol;
 * minor in the lower 16 bits, 0) + one or more NUL-terminated
 * parameter-name/parameter-value string pairs + a final NUL
 * terminator byte. All integers are big-endian (network byte order)
 * per PostgreSQL's own documentation. Three special, non-version
 * codes can appear in the same position as the protocol version —
 * SSLRequest (1234 upper / 5679 lower), CancelRequest (1234 upper /
 * 5678 lower), and GSSAPIRequest (1234 upper / 5680 lower) — each a
 * distinct, shorter message with no parameters at all.
 *
 * SCOPE: message length, protocol version (major/minor), the three
 * special request codes (named, not further decoded — each is
 * followed by different fixed fields this project doesn't extract),
 * and for a genuine StartupMessage, the "user" and "database"
 * parameters specifically — real traffic could include other
 * parameter names (application_name, client_encoding, and more, all
 * officially documented), but "user" and "database" are the two most
 * operationally useful for identifying who's connecting to what, so
 * only those two are singled out; every other post-startup message
 * type (Query, Authentication, RowDescription, DataRow, and so on)
 * is not decoded — each has its own message-type byte and format,
 * real additional work this project doesn't attempt without traffic
 * to verify against.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define POSTGRESQL_PORT   5432
#define PG_STARTUP_HDR_LEN 8
#define PG_MAX_PARAMS      16

static double postgresql_detect(const uint8_t *payload, uint16_t len,
                                 uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < PG_STARTUP_HDR_LEN) return 0.0;

    uint32_t msg_len = ((uint32_t)payload[0]<<24)|((uint32_t)payload[1]<<16)|
                        ((uint32_t)payload[2]<<8)|payload[3];
    uint32_t proto = ((uint32_t)payload[4]<<24)|((uint32_t)payload[5]<<16)|
                      ((uint32_t)payload[6]<<8)|payload[7];
    uint16_t major = (uint16_t)(proto >> 16);
    uint16_t minor = (uint16_t)(proto & 0xFFFF);

    bool is_special = (major == 1234);   /* SSLRequest/CancelRequest/GSSAPIRequest */
    bool is_normal_startup = (major == 3 && minor == 0);
    if (!is_special && !is_normal_startup) return 0.0;
    if (msg_len < PG_STARTUP_HDR_LEN || msg_len > (uint32_t)len + 64) return 0.0;

    double confidence = 0.6;
    if (dst_port == POSTGRESQL_PORT) confidence = 0.9;
    return confidence;
}

static void postgresql_dissect(const uint8_t *payload, uint16_t len,
                                uint16_t dst_port, const char *l4_proto,
                                struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < PG_STARTUP_HDR_LEN) return;

    uint32_t msg_len = ((uint32_t)payload[0]<<24)|((uint32_t)payload[1]<<16)|
                        ((uint32_t)payload[2]<<8)|payload[3];
    uint32_t proto = ((uint32_t)payload[4]<<24)|((uint32_t)payload[5]<<16)|
                      ((uint32_t)payload[6]<<8)|payload[7];
    uint16_t major = (uint16_t)(proto >> 16);
    uint16_t minor = (uint16_t)(proto & 0xFFFF);

    char buf[16];
    snprintf(buf, sizeof(buf), "%u", msg_len);
    dissect_result_add(out, "postgresql_message_length", buf);

    if (major == 1234) {
        const char *req_name = minor == 5679 ? "SSLRequest" :
                                minor == 5678 ? "CancelRequest" :
                                minor == 5680 ? "GSSAPIRequest" : "UnknownSpecialRequest";
        dissect_result_add(out, "postgresql_message_type", req_name);
        return;
    }

    dissect_result_add(out, "postgresql_message_type", "StartupMessage");
    snprintf(buf, sizeof(buf), "%u.%u", major, minor);
    dissect_result_add(out, "postgresql_protocol_version", buf);

    size_t pos = PG_STARTUP_HDR_LEN;
    int n_params = 0;
    while (pos < len && n_params < PG_MAX_PARAMS) {
        if (payload[pos] == 0) break;   /* final terminator */

        size_t nstart = pos;
        while (pos < len && payload[pos] != 0) pos++;
        if (pos >= len) break;   /* no NUL found: incomplete */
        size_t nlen = pos - nstart;
        pos++;   /* skip NUL */

        size_t vstart = pos;
        while (pos < len && payload[pos] != 0) pos++;
        if (pos >= len) break;
        size_t vlen = pos - vstart;
        pos++;   /* skip NUL */

        char name[64], value[192];
        size_t nn = nlen < sizeof(name) - 1 ? nlen : sizeof(name) - 1;
        memcpy(name, payload + nstart, nn);
        name[nn] = '\0';
        size_t vn = vlen < sizeof(value) - 1 ? vlen : sizeof(value) - 1;
        memcpy(value, payload + vstart, vn);
        value[vn] = '\0';

        if (strcmp(name, "user") == 0) {
            dissect_result_add(out, "postgresql_user", value);
        } else if (strcmp(name, "database") == 0) {
            dissect_result_add(out, "postgresql_database", value);
        }

        n_params++;
    }
}

static const uint16_t postgresql_hint_ports[] = { POSTGRESQL_PORT };

void register_postgresql_dissector(void) {
    register_dissector("PostgreSQL", postgresql_detect, postgresql_dissect,
                        postgresql_hint_ports, 1);
}
