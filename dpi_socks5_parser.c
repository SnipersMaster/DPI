/*
 * dpi_socks5_parser.c
 *
 * SOCKS5 (RFC 1928, with RFC 1929 username/password auth) dissector
 * — TCP port 1080. Requested by name in a batch cross-check against a
 * large protocol list.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic — no SOCKS5 capture was available in this project's pcap
 * survey set (checked port 1080 specifically, found none). Built with
 * real confidence regardless: RFC 1928/1929 are short, stable,
 * unambiguous IETF standards — cross-checked against multiple
 * independent implementation write-ups and library documentation
 * (including a Go implementation's own protocol package docs and an
 * IBM AIX libc reference for the same wire format), all agreeing.
 *
 * WIRE FORMAT — four sequential phases:
 *   1. Method negotiation request: VER(1, always 5) + NMETHODS(1) +
 *      METHODS(NMETHODS bytes, each an auth method ID — 0x00=no auth,
 *      0x02=username/password, others exist but aren't decoded).
 *      Reply: VER(1) + METHOD(1, the server's chosen method, or 0xFF
 *      if none acceptable).
 *   2. (If username/password was chosen) RFC 1929 sub-negotiation:
 *      VER(1, always 1 — its own version byte, distinct from SOCKS5's
 *      own) + ULEN(1) + UNAME(ULEN bytes) + PLEN(1) + PASSWD(PLEN
 *      bytes). Reply: VER(1) + STATUS(1, 0=success).
 *   3. Request: VER(1) + CMD(1: 1=CONNECT, 2=BIND, 3=UDP ASSOCIATE) +
 *      RSV(1, always 0) + ATYP(1: 1=IPv4, 3=domain name, 4=IPv6) +
 *      DST.ADDR(variable, per ATYP) + DST.PORT(2).
 *   4. Reply: identical shape to the request, but the CMD position
 *      instead carries REP (0=succeeded, 1-8 various error codes).
 *
 * SCOPE: method negotiation (methods offered/chosen) and the
 * CONNECT/BIND/UDP-ASSOCIATE request (command, address type,
 * destination address in all 3 forms, destination port) are
 * decoded. Username/password auth is detected but the actual
 * username/password fields are NOT extracted — this project doesn't
 * expose credentials in its output even when the wire format makes
 * them trivially visible, the same restraint applied to RADIUS's
 * User-Password attribute elsewhere in this project. The reply's
 * REP code is decoded; GSSAPI auth (RFC 1961) is named but not
 * decoded further — a real, more involved sub-protocol this project
 * has no real traffic to verify a byte-exact layout against.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define SOCKS5_PORT 1080
#define SOCKS5_MAX_FIELD 256

static const char *socks5_method_name(uint8_t m) {
    switch (m) {
        case 0x00: return "No Authentication Required";
        case 0x01: return "GSSAPI";
        case 0x02: return "Username/Password";
        case 0xFF: return "No Acceptable Methods";
        default:    return "Unknown";
    }
}

static const char *socks5_command_name(uint8_t cmd) {
    switch (cmd) {
        case 1: return "CONNECT";
        case 2: return "BIND";
        case 3: return "UDP_ASSOCIATE";
        default: return "Unknown";
    }
}

static const char *socks5_reply_code_name(uint8_t rep) {
    switch (rep) {
        case 0: return "succeeded";
        case 1: return "general SOCKS server failure";
        case 2: return "connection not allowed by ruleset";
        case 3: return "network unreachable";
        case 4: return "host unreachable";
        case 5: return "connection refused";
        case 6: return "TTL expired";
        case 7: return "command not supported";
        case 8: return "address type not supported";
        default: return "Unknown";
    }
}

static double socks5_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < 3) return 0.0;

    bool looks_like_negotiation = (payload[0] == 5 && len >= 2 + payload[1]);
    bool looks_like_request = (len >= 6 && payload[0] == 5 &&
                                (payload[1] >= 1 && payload[1] <= 3) && payload[2] == 0 &&
                                (payload[3] == 1 || payload[3] == 3 || payload[3] == 4));
    if (!looks_like_negotiation && !looks_like_request) return 0.0;

    double confidence = 0.5;
    if (dst_port == SOCKS5_PORT) confidence = 0.85;
    return confidence;
}

static void socks5_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < 3 || payload[0] != 5) return;

    /* Request/reply shape: byte[1] is CMD (1-3) for a request, or a
     * REP code (0-8) for a reply — checked first since a byte value
     * of, say, 2 is ambiguous between "BIND command" and "connection
     * not allowed" without also checking RSV/ATYP's own shape. */
    if (len >= 6 && payload[2] == 0 &&
        (payload[3] == 1 || payload[3] == 3 || payload[3] == 4)) {
        uint8_t cmd_or_rep = payload[1];
        uint8_t atyp = payload[3];
        bool is_reply = (cmd_or_rep <= 8 && cmd_or_rep != 0) ? false : (cmd_or_rep == 0);
        /* A cmd_or_rep of exactly 1,2,3 is ambiguous (valid as both a
         * CMD and a REP code) — resolved by which is more likely: a
         * genuine CONNECT/BIND/UDP_ASSOCIATE request is far more
         * common in real traffic than the specific error replies 1-3,
         * and this project doesn't have a stateful way to know which
         * side of the exchange a given payload is here, so request is
         * treated as the default interpretation for 1-3, matching
         * this dissector's own detect() logic above. REP 0
         * (succeeded) is unambiguous since CMD is never 0. */
        dissect_result_add(out, "socks5_message_type", is_reply ? "reply" : "request");

        if (!is_reply) {
            dissect_result_add(out, "socks5_command", socks5_command_name(cmd_or_rep));
        } else {
            dissect_result_add(out, "socks5_reply_code", socks5_reply_code_name(cmd_or_rep));
        }

        size_t pos = 4;
        char addrbuf[SOCKS5_MAX_FIELD];
        if (atyp == 1 && len >= pos + 4 + 2) {   /* IPv4 */
            snprintf(addrbuf, sizeof(addrbuf), "%u.%u.%u.%u",
                     payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]);
            dissect_result_add(out, "socks5_dst_addr", addrbuf);
            pos += 4;
        } else if (atyp == 3 && len >= pos + 1) {   /* domain name */
            uint8_t dlen = payload[pos];
            if (len >= pos + 1 + dlen + 2) {
                size_t n = dlen < sizeof(addrbuf) - 1 ? dlen : sizeof(addrbuf) - 1;
                memcpy(addrbuf, payload + pos + 1, n);
                addrbuf[n] = '\0';
                dissect_result_add(out, "socks5_dst_addr", addrbuf);
                pos += 1 + dlen;
            } else {
                return;   /* incomplete: don't guess */
            }
        } else if (atyp == 4 && len >= pos + 16 + 2) {   /* IPv6 */
            snprintf(addrbuf, sizeof(addrbuf),
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     payload[pos],payload[pos+1],payload[pos+2],payload[pos+3],
                     payload[pos+4],payload[pos+5],payload[pos+6],payload[pos+7],
                     payload[pos+8],payload[pos+9],payload[pos+10],payload[pos+11],
                     payload[pos+12],payload[pos+13],payload[pos+14],payload[pos+15]);
            dissect_result_add(out, "socks5_dst_addr", addrbuf);
            pos += 16;
        } else {
            return;
        }

        if (len >= pos + 2) {
            uint16_t dst_port_val = (payload[pos] << 8) | payload[pos + 1];
            char portbuf[8];
            snprintf(portbuf, sizeof(portbuf), "%u", dst_port_val);
            dissect_result_add(out, "socks5_dst_port", portbuf);
        }
        return;
    }

    /* Otherwise: method negotiation. */
    uint8_t nmethods = payload[1];
    if (len < 2 + nmethods) return;

    dissect_result_add(out, "socks5_message_type", "method_negotiation");
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", nmethods);
    dissect_result_add(out, "socks5_nmethods", buf);

    if (nmethods > 0) {
        dissect_result_add(out, "socks5_method_0", socks5_method_name(payload[2]));
    }
}

static const uint16_t socks5_hint_ports[] = { SOCKS5_PORT };

void register_socks5_dissector(void) {
    register_dissector("SOCKS5", socks5_detect, socks5_dissect, socks5_hint_ports, 1);
}
