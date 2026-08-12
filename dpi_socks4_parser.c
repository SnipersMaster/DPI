/*
 * dpi_socks4_parser.c
 *
 * SOCKS4 (and SOCKS4a) protocol dissector — TCP port 1080
 * (conventional, not formally IANA-registered). Requested by name in
 * a batch cross-check against a large protocol list.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic — no SOCKS4 capture was available (checked this project's
 * full pcap survey set specifically for port 1080; found none). Built
 * with real confidence regardless: the wire format was cross-checked
 * across the openssh.org SOCKS4 protocol reference (the de facto
 * canonical spec — SOCKS4 itself was never formally published as an
 * IETF RFC, and this document is what every real SOCKS4
 * implementation is actually built against) and multiple independent
 * technical write-ups, all agreeing byte-for-byte.
 *
 * WIRE FORMAT — CONNECT/BIND request: VN(1, always 4) + CD(1,
 * command: 1=CONNECT, 2=BIND) + DSTPORT(2) + DSTIP(4) + USERID
 * (variable, NUL-terminated ASCII). SOCKS4a extends this: if DSTIP's
 * first three octets are 0 and the fourth is nonzero (an
 * unroutable "invalid" address used as a signal, not a real IP),
 * a second NUL-terminated field follows USERID: the actual
 * destination hostname as ASCII text — this is how SOCKS4a adds
 * domain-name support to a protocol that otherwise only carries a
 * raw IPv4 address.
 *
 * WIRE FORMAT — reply: VN(1, always 0) + CD(1, result code — 90
 * granted, 91 rejected/failed, 92 rejected because the SOCKS server
 * couldn't reach identd on the client, 93 rejected because the
 * client's userid didn't match identd's response) + DSTPORT(2) +
 * DSTIP(4) — DSTPORT/DSTIP are only meaningful for BIND's second
 * reply, ignored for CONNECT.
 *
 * SCOPE: request (command, destination IP/port, userid, and the
 * SOCKS4a hostname extension when the invalid-address signal is
 * present) and reply (result code) are both decoded. Nothing beyond
 * the initial negotiation — once a SOCKS4 CONNECT succeeds, the
 * connection becomes a raw relay of whatever the client is actually
 * talking to the real destination, indistinguishable at the SOCKS
 * layer from any other TCP payload.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define SOCKS4_PORT 1080
#define SOCKS4_MAX_FIELD 128

static const char *socks4_command_name(uint8_t cd) {
    switch (cd) {
        case 1: return "CONNECT";
        case 2: return "BIND";
        default: return "Unknown";
    }
}

static const char *socks4_reply_code_name(uint8_t cd) {
    switch (cd) {
        case 90: return "request granted";
        case 91: return "request rejected or failed";
        case 92: return "rejected: no identd response";
        case 93: return "rejected: userid mismatch";
        default: return "Unknown";
    }
}

static double socks4_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < 9) return 0.0;   /* VN+CD+DSTPORT+DSTIP+at least a NUL = 9 */

    bool is_request = (payload[0] == 4 &&
                        (payload[1] == 1 || payload[1] == 2));
    bool is_reply = (len >= 8 && payload[0] == 0 &&
                      (payload[1] >= 90 && payload[1] <= 93));
    if (!is_request && !is_reply) return 0.0;

    double confidence = 0.5;   /* genuinely ambiguous without the port —
                                   a handful of specific bytes matching
                                   isn't much evidence alone */
    if (dst_port == SOCKS4_PORT) confidence = 0.85;
    return confidence;
}

static void socks4_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < 8) return;

    if (payload[0] == 0) {
        /* Reply */
        uint8_t cd = payload[1];
        dissect_result_add(out, "socks4_message_type", "reply");
        dissect_result_add(out, "socks4_reply_code", socks4_reply_code_name(cd));
        return;
    }

    if (payload[0] != 4) return;

    uint8_t cd = payload[1];
    uint16_t dst_tcp_port = (payload[2] << 8) | payload[3];
    char ipbuf[16];
    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", payload[4], payload[5], payload[6], payload[7]);

    dissect_result_add(out, "socks4_message_type", "request");
    dissect_result_add(out, "socks4_command", socks4_command_name(cd));
    dissect_result_add(out, "socks4_dst_ip", ipbuf);
    char portbuf[8];
    snprintf(portbuf, sizeof(portbuf), "%u", dst_tcp_port);
    dissect_result_add(out, "socks4_dst_port", portbuf);

    /* USERID: NUL-terminated ASCII starting at offset 8. */
    size_t pos = 8;
    size_t userid_start = pos;
    while (pos < len && payload[pos] != 0) pos++;
    if (pos >= len) return;   /* incomplete: don't guess past what's captured */
    size_t userid_len = pos - userid_start;
    char useridbuf[SOCKS4_MAX_FIELD];
    size_t un = userid_len < sizeof(useridbuf) - 1 ? userid_len : sizeof(useridbuf) - 1;
    memcpy(useridbuf, payload + userid_start, un);
    useridbuf[un] = '\0';
    dissect_result_add(out, "socks4_userid", useridbuf);
    pos++;   /* skip the NUL */

    /* SOCKS4a extension: DSTIP of 0.0.0.x (x != 0) signals "domain
     * name follows userid, ignore this fake address" — a real,
     * specific protocol convention, not a guess. */
    bool is_socks4a = (payload[4] == 0 && payload[5] == 0 &&
                        payload[6] == 0 && payload[7] != 0);
    if (is_socks4a && pos < len) {
        size_t host_start = pos;
        while (pos < len && payload[pos] != 0) pos++;
        if (pos < len) {
            size_t host_len = pos - host_start;
            char hostbuf[SOCKS4_MAX_FIELD];
            size_t hn = host_len < sizeof(hostbuf) - 1 ? host_len : sizeof(hostbuf) - 1;
            memcpy(hostbuf, payload + host_start, hn);
            hostbuf[hn] = '\0';
            dissect_result_add(out, "socks4a_dst_hostname", hostbuf);
        }
    }
}

static const uint16_t socks4_hint_ports[] = { SOCKS4_PORT };

void register_socks4_dissector(void) {
    register_dissector("SOCKS4", socks4_detect, socks4_dissect, socks4_hint_ports, 1);
}
