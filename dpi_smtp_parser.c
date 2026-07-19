/*
 * dpi_smtp_parser.c
 *
 * SMTP (RFC 5321) dissector — text-based command/response protocol,
 * same general shape as dpi_sip_rtp_parser.c's SIP half and
 * dpi_http1_parser.c. Extracts the commands/responses most useful for
 * mail relay abuse/spam detection: HELO/EHLO domain, MAIL FROM,
 * RCPT TO, response codes, and — when the DATA command's message
 * content lands in the same reassembled buffer — the RFC 5322 message
 * headers (Subject/From/To/Date) that precede the actual mail body.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * SCOPE, stated precisely: line-oriented command/response extraction,
 * PLUS plaintext RFC 5322 header parsing up to the blank line that
 * ends the header section. Does NOT parse the message BODY or any
 * MIME structure within it (multipart boundaries, base64/quoted-
 * printable encoded parts, attachments) — that's a substantially
 * different, MIME-aware parsing problem, matching this project's
 * pattern of scoping message bodies out of text-protocol dissectors
 * (SIP's dissector doesn't parse SDP bodies either). The distinction
 * that matters: RFC 5322 headers are structurally identical in
 * complexity to the SMTP command lines already parsed here (line-
 * oriented, colon-delimited); MIME body interpretation is not.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define SMTP_PORT      25
#define SMTP_SUBMISSION_PORT 587
#define SMTP_MAX_LINE  1024

static bool smtp_looks_like_command_or_response(const uint8_t *payload, uint16_t len) {
    if (len < 4) return false;

    /* Response: 3 digits + (space or hyphen for multi-line) */
    if (isdigit(payload[0]) && isdigit(payload[1]) && isdigit(payload[2]) &&
        (payload[3] == ' ' || payload[3] == '-')) {
        return true;
    }

    static const char *commands[] = {
        "HELO ", "EHLO ", "MAIL FROM:", "RCPT TO:", "DATA", "QUIT",
        "RSET", "VRFY ", "NOOP", "STARTTLS", "AUTH "
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        size_t clen = strlen(commands[i]);
        if (len >= clen && strncasecmp((const char *)payload, commands[i], clen) == 0) {
            return true;
        }
    }
    return false;
}

static double smtp_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;   /* SMTP is TCP-only */
    if (!smtp_looks_like_command_or_response(payload, len)) return 0.0;

    double confidence = 0.6;
    if (dst_port == SMTP_PORT || dst_port == SMTP_SUBMISSION_PORT) confidence = 0.9;
    return confidence;
}

static size_t smtp_find_line_end(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') return i;
    }
    return len;   /* SMTP requires CRLF, same as HTTP — no bare-LF fallback */
}

static void smtp_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t pos = 0;
    int lines_parsed = 0;

    while (pos < len && lines_parsed < 32) {
        size_t line_end = smtp_find_line_end(payload, len - pos);
        if (line_end >= len - pos) break;   /* incomplete final line: stop */

        char line[SMTP_MAX_LINE];
        size_t n = line_end < sizeof(line) - 1 ? line_end : sizeof(line) - 1;
        memcpy(line, payload + pos, n);
        line[n] = '\0';

        if (n >= 4 && isdigit((unsigned char)line[0]) && isdigit((unsigned char)line[1])
            && isdigit((unsigned char)line[2])) {
            /* Response line: "250 OK" or "250-CONTINUED" */
            char code[4] = { line[0], line[1], line[2], '\0' };
            dissect_result_add(out, "smtp_response_code", code);
        } else if (n >= 5 && strncasecmp(line, "HELO ", 5) == 0) {
            dissect_result_add(out, "smtp_helo_domain", line + 5);
        } else if (n >= 5 && strncasecmp(line, "EHLO ", 5) == 0) {
            dissect_result_add(out, "smtp_ehlo_domain", line + 5);
        } else if (n >= 10 && strncasecmp(line, "MAIL FROM:", 10) == 0) {
            dissect_result_add(out, "smtp_mail_from", line + 10);
        } else if (n >= 8 && strncasecmp(line, "RCPT TO:", 8) == 0) {
            dissect_result_add(out, "smtp_rcpt_to", line + 8);
        } else if (n >= 4 && strncasecmp(line, "DATA", 4) == 0) {
            dissect_result_add(out, "smtp_data_command_seen", "true");

            /* Extending scope slightly here: RFC 5322 message headers
             * (Subject/From/To/Date) that precede the actual mail
             * body are plaintext, line-oriented, and structurally
             * indistinguishable in complexity from the SMTP command
             * lines already parsed above — genuinely different from
             * MIME body/multipart decoding, which is the piece that
             * stays deliberately out of scope (see this file's header
             * comment). If the buffer we already have extends past
             * this DATA line (common when the client's message follows
             * closely enough to land in the same reassembled chunk),
             * walk RFC 5322 header lines until the blank line that
             * ends the header section, then stop — the body itself,
             * and any MIME structure within it, is NOT parsed. */
            pos += line_end + 2;
            int header_lines_parsed = 0;

            while (pos < len && header_lines_parsed < 16) {
                size_t hdr_line_end = smtp_find_line_end(payload, len - pos);
                if (hdr_line_end >= len - pos) break;   /* incomplete: stop, don't guess */

                char hdr_line[SMTP_MAX_LINE];
                size_t hn = hdr_line_end < sizeof(hdr_line) - 1
                            ? hdr_line_end : sizeof(hdr_line) - 1;
                memcpy(hdr_line, payload + pos, hn);
                hdr_line[hn] = '\0';

                if (hn == 0) {
                    /* Blank line: end of RFC 5322 headers, body begins
                     * right after — deliberately not parsed further. */
                    dissect_result_add(out, "smtp_message_body_begins", "true");
                    break;
                }

                char *colon = strchr(hdr_line, ':');
                if (colon) {
                    *colon = '\0';
                    char *val = colon + 1;
                    while (*val == ' ') val++;

                    if (strcasecmp(hdr_line, "Subject") == 0) {
                        dissect_result_add(out, "smtp_message_subject", val);
                    } else if (strcasecmp(hdr_line, "From") == 0) {
                        dissect_result_add(out, "smtp_message_from", val);
                    } else if (strcasecmp(hdr_line, "To") == 0) {
                        dissect_result_add(out, "smtp_message_to", val);
                    } else if (strcasecmp(hdr_line, "Date") == 0) {
                        dissect_result_add(out, "smtp_message_date", val);
                    }
                    /* Unrecognized headers (Content-Type, MIME-Version,
                     * etc.) are walked past but not extracted — this is
                     * genuinely still just RFC 5322 header parsing, not
                     * MIME interpretation, even when a Content-Type
                     * header is present; understanding what that
                     * Content-Type MEANS (multipart boundaries, nested
                     * body parts) is the part that stays out of scope. */
                } else {
                    /* A continuation/folded header line (starts with
                     * whitespace) or malformed line — not specifically
                     * handled, matching this addition's bounded scope. */
                }

                pos += hdr_line_end + 2;
                header_lines_parsed++;
            }

            break;   /* whether or not message headers were found, stop
                      * here — everything from this point on is message
                      * body/MIME content, not command/response or
                      * RFC 5322 header traffic */
        } else if (n >= 8 && strncasecmp(line, "STARTTLS", 8) == 0) {
            dissect_result_add(out, "smtp_starttls_seen", "true");
        }

        pos += line_end + 2;   /* +2 for CRLF */
        lines_parsed++;
    }
}

static const uint16_t smtp_hint_ports[] = { SMTP_PORT, SMTP_SUBMISSION_PORT };

void register_smtp_dissector(void) {
    register_dissector("SMTP", smtp_detect, smtp_dissect, smtp_hint_ports, 2);
}
