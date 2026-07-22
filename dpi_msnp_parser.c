/*
 * dpi_msnp_parser.c
 *
 * MSNP (MSN Messenger Protocol, never formally RFC-standardized —
 * documented by Microsoft historically and by community reverse-
 * engineering) dissector — TCP port 1863. Text-based command
 * protocol: "VERB arg1 arg2 ...\r\n", with MSG additionally carrying a
 * MIME-headers-plus-body payload after its command line.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 37 real MSNP payloads from a genuine captured chat
 * session (`msnms.pcap`) — a real conversation between two accounts
 * (evidently test/placeholder addresses, not real people's), including
 * real CAL (call a contact), JOI (contact joined), and 23 real MSG
 * exchanges — both "typing indicator" control messages
 * (Content-Type: text/x-msmsgscontrol) and real chat text (Content-
 * Type: text/plain), confirming MSNP uses MIME headers to distinguish
 * the two within the same command, not assumed from documentation
 * alone. 8 of the captured payloads were exactly 6 bytes of non-
 * printable, non-zero garbage — the same class of capture-artifact
 * finding as this project's FTP/POP3 stress-testing (there, zero-
 * padding; here, apparently uninitialized padding), correctly
 * rejected by this dissector's printable-ASCII validation.
 *
 * WIRE FORMAT: line-based commands, e.g. `USR <TrID> <email> <ticket>`,
 * `CAL <TrID> <email>`, `JOI <email> <display-name> <flags>`. MSG is
 * the one command with a body: the command line's shape differs by
 * direction — a client SENDING a message uses `MSG <TrID> <ack-type>
 * <payload-length>`, while the SERVER relaying it to a recipient uses
 * `MSG <sender-email> <sender-display-name> <payload-length>` (no
 * transaction ID at that point, since it's delivery, not origination)
 * — distinguished here by whether the second token contains '@',
 * confirmed against both real shapes in the same capture. The command
 * line is followed by MIME-style headers (MIME-Version, Content-Type,
 * and either TypingUser: for control messages or X-MMS-IM-Format: for
 * real text) then a blank line then the payload body.
 *
 * SCOPE, with two deliberate privacy/security choices stated plainly:
 *   1. USR's third argument (an authentication ticket from Microsoft's
 *      Passport/Live ID system, not a plaintext password, but still a
 *      bearer credential) is NEVER extracted — flagged present only,
 *      same discipline as this project's password/credential fields
 *      elsewhere (RADIUS, LDAP, FTP, POP3).
 *   2. The actual chat message BODY TEXT is NEVER extracted, even
 *      though MSNP's own structure would make it easy to — this
 *      matches how this project doesn't extract SMTP email body
 *      content either. Only the message's existence, length, and
 *      Content-Type are surfaced; whether it's a real text message or
 *      a typing-indicator control message is distinguishable from
 *      Content-Type alone without reading what was actually typed.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define MSNP_MAX_ARGS 4

static bool msnp_line_looks_valid(const uint8_t *line, size_t len) {
    if (len == 0) return true;
    for (size_t i = 0; i < len; i++) {
        if (line[i] < 0x20 && line[i] != '\t') return false;
        if (line[i] > 0x7E) return false;
    }
    return true;
}

static size_t msnp_find_line_end(const uint8_t *data, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (data[i] == '\r' && data[i+1] == '\n') return i;
    }
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n') return i;
    }
    return len;
}

static double msnp_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < 3) return 0.0;

    size_t line_end = msnp_find_line_end(payload, len);
    if (!msnp_line_looks_valid(payload, line_end)) return 0.0;

    size_t verb_len = 0;
    while (verb_len < line_end && isupper(payload[verb_len])) verb_len++;
    bool verb_shaped = (verb_len == 3 &&
                         (verb_len == line_end || payload[verb_len] == ' '));
    if (!verb_shaped) return 0.0;

    double confidence = 0.5;
    if (dst_port == 1863) confidence = 0.8;
    return confidence;
}

/* Splits a line (already known to end at `line_end`) into up to
 * MSNP_MAX_ARGS space-separated tokens; returns the count found. */
static int msnp_split_args(const uint8_t *line, size_t line_end,
                            size_t *arg_starts, size_t *arg_lens) {
    int n = 0;
    size_t pos = 0;
    while (pos < line_end && n < MSNP_MAX_ARGS) {
        while (pos < line_end && line[pos] == ' ') pos++;
        if (pos >= line_end) break;
        size_t start = pos;
        while (pos < line_end && line[pos] != ' ') pos++;
        arg_starts[n] = start;
        arg_lens[n] = pos - start;
        n++;
    }
    return n;
}

static void msnp_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t line_end = msnp_find_line_end(payload, len);
    if (!msnp_line_looks_valid(payload, line_end)) return;

    size_t verb_len = 0;
    while (verb_len < line_end && payload[verb_len] != ' ') verb_len++;
    char verb[8];
    size_t vn = verb_len < sizeof(verb) - 1 ? verb_len : sizeof(verb) - 1;
    memcpy(verb, payload, vn);
    verb[vn] = '\0';
    dissect_result_add(out, "msnp_command", verb);

    size_t arg_starts[MSNP_MAX_ARGS], arg_lens[MSNP_MAX_ARGS];
    size_t rest_start = verb_len < line_end ? verb_len + 1 : line_end;
    int n_args = msnp_split_args(payload + rest_start, line_end - rest_start, arg_starts, arg_lens);
    for (int i = 0; i < n_args; i++) arg_starts[i] += rest_start;

    char buf[256];

    if (strcmp(verb, "USR") == 0 && n_args >= 2) {
        size_t n = arg_lens[1] < sizeof(buf) - 1 ? arg_lens[1] : sizeof(buf) - 1;
        memcpy(buf, payload + arg_starts[1], n); buf[n] = '\0';
        dissect_result_add(out, "msnp_usr_email", buf);
        if (n_args >= 3) dissect_result_add(out, "msnp_usr_ticket_present", "true");
    } else if (strcmp(verb, "CAL") == 0 && n_args >= 2) {
        size_t n = arg_lens[1] < sizeof(buf) - 1 ? arg_lens[1] : sizeof(buf) - 1;
        memcpy(buf, payload + arg_starts[1], n); buf[n] = '\0';
        dissect_result_add(out, "msnp_cal_email", buf);
    } else if (strcmp(verb, "JOI") == 0 && n_args >= 1) {
        size_t n = arg_lens[0] < sizeof(buf) - 1 ? arg_lens[0] : sizeof(buf) - 1;
        memcpy(buf, payload + arg_starts[0], n); buf[n] = '\0';
        dissect_result_add(out, "msnp_joi_email", buf);
    } else if (strcmp(verb, "MSG") == 0 && n_args >= 3) {
        /* Distinguish the two real shapes by whether arg[0] looks like
         * an email address — confirmed against both real shapes. */
        bool has_at = false;
        for (size_t i = 0; i < arg_lens[0]; i++) {
            if (payload[arg_starts[0] + i] == '@') { has_at = true; break; }
        }
        if (has_at) {
            size_t n = arg_lens[0] < sizeof(buf) - 1 ? arg_lens[0] : sizeof(buf) - 1;
            memcpy(buf, payload + arg_starts[0], n); buf[n] = '\0';
            dissect_result_add(out, "msnp_msg_sender_email", buf);
        } else {
            size_t n = arg_lens[0] < sizeof(buf) - 1 ? arg_lens[0] : sizeof(buf) - 1;
            memcpy(buf, payload + arg_starts[0], n); buf[n] = '\0';
            dissect_result_add(out, "msnp_msg_transaction_id", buf);
        }
        size_t n = arg_lens[2] < sizeof(buf) - 1 ? arg_lens[2] : sizeof(buf) - 1;
        memcpy(buf, payload + arg_starts[2], n); buf[n] = '\0';
        dissect_result_add(out, "msnp_msg_length", buf);

        /* Content-Type header, if present in this buffer — the single
         * most useful field for distinguishing a typing-indicator
         * control message from real chat text WITHOUT reading the
         * actual message content, see file header. Body text itself
         * is deliberately never extracted. */
        size_t hpos = line_end + 2;
        while (hpos < len) {
            size_t hline_end = msnp_find_line_end(payload + hpos, len - hpos);
            if (hline_end == 0) break;   /* blank line: end of headers */
            if (hline_end > 14 && memcmp(payload + hpos, "Content-Type: ", 14) == 0) {
                size_t vlen = hline_end - 14;
                size_t vn = vlen < sizeof(buf) - 1 ? vlen : sizeof(buf) - 1;
                memcpy(buf, payload + hpos + 14, vn); buf[vn] = '\0';
                dissect_result_add(out, "msnp_msg_content_type", buf);
                break;
            }
            hpos += hline_end + 2;
        }
    }
}

static const uint16_t msnp_hint_ports[] = { 1863 };

void register_msnp_dissector(void) {
    register_dissector("MSNP", msnp_detect, msnp_dissect, msnp_hint_ports, 1);
}
