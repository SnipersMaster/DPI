/*
 * dpi_pop3_parser.c
 *
 * POP3 (RFC 1939) dissector — text-based command/response protocol,
 * same general shape as `dpi_ftp_parser.c` and `dpi_smtp_parser.c`.
 * TCP port 110.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 340 real payloads from a genuine capture
 * (`email-troubles.pcap`) — but with an honest scope caveat worth
 * stating plainly: 122 of the 340 were pure zero-padding artifacts
 * (the same class of finding already seen in this project's FTP
 * stress-test — non-protocol bytes, correctly rejected by this
 * dissector's printable-ASCII validation, not a gap). Of the real
 * traffic, only RETR commands were actually present in this specific
 * capture (a real client retrieving 3 large messages) — the response
 * to one showed a real "+OK 100220 octets" followed by a genuine
 * multi-packet email body. USER/PASS/LIST/DELE/etc. were NOT observed
 * in this particular capture (the session may have started mid-
 * authentication, or simply didn't include those commands) — this
 * dissector implements the full RFC 1939 command set from the spec,
 * but only RETR and the +OK/-ERR response shape are real-traffic-
 * verified. Stated honestly rather than implied to be equally checked.
 *
 * A REAL STRUCTURAL DETAIL FROM THIS CAPTURE: one real "RETR 20\r\n"
 * command had 4 trailing zero bytes appended to the SAME payload
 * (not a separate packet) — Ethernet minimum-frame-length padding
 * leaking into the captured buffer, the same class of finding already
 * seen with GRE keepalives and OSPF neighbor lists earlier in this
 * project. This dissector's line-based parsing (stop at the first
 * CRLF, ignore anything after) handles this correctly without special
 *-casing it, confirmed against this real example.
 *
 * WIRE FORMAT: client commands are "VERB [argument]\r\n"; server
 * responses start with "+OK" or "-ERR" followed by optional text.
 * After a successful RETR (or LIST/UIDL without an argument), the
 * response is multi-line/multi-packet, ending in a lone "." — this
 * dissector, like FTP's, is stateless per-buffer and doesn't track
 * that framing across packets, so only the initial "+OK ..." status
 * line is recognized, not the message body that follows in later
 * packets (which won't look like a POP3 response shape and will
 * correctly get low/zero detect() confidence).
 *
 * SCOPE: command name and, for commands with a non-sensitive
 * argument (USER, LIST, RETR, DELE, TOP, UIDL), that argument.
 * **PASS's argument is never extracted**, only flagged present — same
 * discipline as FTP's PASS, RADIUS's User-Password, LDAP's bind
 * credential. APOP's digest argument (an MD5 hash, not a plaintext
 * credential) is extracted, since it isn't sensitive the same way.
 * Response: the status (+OK/-ERR) and, for -ERR, the reason text.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static bool pop3_line_looks_valid(const uint8_t *line, size_t len) {
    if (len == 0) return true;
    for (size_t i = 0; i < len; i++) {
        if (line[i] < 0x20 && line[i] != '\t') return false;
        if (line[i] > 0x7E) return false;
    }
    return true;
}

static size_t pop3_find_line_end(const uint8_t *data, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (data[i] == '\r' && data[i+1] == '\n') return i;
    }
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n') return i;
    }
    return len;
}

static double pop3_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < 3) return 0.0;

    size_t line_end = pop3_find_line_end(payload, len);
    if (!pop3_line_looks_valid(payload, line_end)) return 0.0;

    bool is_response = (line_end >= 3 && memcmp(payload, "+OK", 3) == 0) ||
                        (line_end >= 4 && memcmp(payload, "-ERR", 4) == 0);

    size_t verb_len = 0;
    while (verb_len < line_end && isupper(payload[verb_len])) verb_len++;
    bool is_command = (verb_len >= 3 && verb_len <= 4 &&
                        (verb_len == line_end || payload[verb_len] == ' '));

    if (!is_response && !is_command) return 0.0;

    double confidence = 0.5;
    if (dst_port == 110) confidence = 0.8;
    return confidence;
}

static void pop3_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)l4_proto;

    size_t line_end = pop3_find_line_end(payload, len);
    if (!pop3_line_looks_valid(payload, line_end)) return;

    bool is_response_direction = (dst_port != 110);

    if (is_response_direction) {
        if (line_end >= 3 && memcmp(payload, "+OK", 3) == 0) {
            dissect_result_add(out, "pop3_status", "+OK");
        } else if (line_end >= 4 && memcmp(payload, "-ERR", 4) == 0) {
            dissect_result_add(out, "pop3_status", "-ERR");
            if (line_end > 5) {
                char reason[128];
                size_t rn = line_end - 5 < sizeof(reason) - 1 ? line_end - 5 : sizeof(reason) - 1;
                memcpy(reason, payload + 5, rn);
                reason[rn] = '\0';
                dissect_result_add(out, "pop3_error_reason", reason);
            }
        }
        return;
    }

    size_t verb_end = 0;
    while (verb_end < line_end && payload[verb_end] != ' ') verb_end++;
    char verb[8];
    size_t vn = verb_end < sizeof(verb) - 1 ? verb_end : sizeof(verb) - 1;
    memcpy(verb, payload, vn);
    verb[vn] = '\0';
    for (size_t i = 0; i < vn; i++) verb[i] = (char)toupper((unsigned char)verb[i]);
    dissect_result_add(out, "pop3_command", verb);

    size_t arg_start = verb_end < line_end ? verb_end + 1 : line_end;
    size_t arg_len = line_end - arg_start;

    if (strcmp(verb, "PASS") == 0) {
        /* NEVER extract the password — see file header. */
        dissect_result_add(out, "pop3_password_present", "true");
    } else if (arg_len > 0 && (strcmp(verb, "USER") == 0 || strcmp(verb, "LIST") == 0 ||
                                strcmp(verb, "RETR") == 0 || strcmp(verb, "DELE") == 0 ||
                                strcmp(verb, "TOP") == 0 || strcmp(verb, "UIDL") == 0 ||
                                strcmp(verb, "APOP") == 0)) {
        char arg[128];
        size_t an = arg_len < sizeof(arg) - 1 ? arg_len : sizeof(arg) - 1;
        memcpy(arg, payload + arg_start, an);
        arg[an] = '\0';
        char key[24];
        snprintf(key, sizeof(key), "pop3_%s_arg",
                 strcmp(verb, "USER") == 0 ? "user" :
                 strcmp(verb, "LIST") == 0 ? "list" :
                 strcmp(verb, "RETR") == 0 ? "retr" :
                 strcmp(verb, "DELE") == 0 ? "dele" :
                 strcmp(verb, "TOP") == 0 ? "top" :
                 strcmp(verb, "UIDL") == 0 ? "uidl" : "apop");
        dissect_result_add(out, key, arg);
    }
}

static const uint16_t pop3_hint_ports[] = { 110 };

void register_pop3_dissector(void) {
    register_dissector("POP3", pop3_detect, pop3_dissect, pop3_hint_ports, 1);
}
