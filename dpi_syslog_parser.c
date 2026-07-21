/*
 * dpi_syslog_parser.c
 *
 * Syslog dissector — RFC 3164 (BSD syslog, the format essentially
 * all real network/security appliance traffic actually uses) with
 * the PRI-value parsing that RFC 5424 also shares. UDP port 514
 * (RFC 3164's original transport) and TCP port 601 (RFC 6587's
 * "syslog-conn", reliable delivery over TCP).
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 6 real UDP syslog packets (a Cisco device — link-
 * state change and IPv6 ACL log messages, using Cisco's own
 * "%FACILITY-SEVERITY-MNEMONIC" message-tag convention within the
 * free-form text) and 91 real TCP syslog payloads (a Palo Alto
 * firewall's TRAFFIC log stream, structured CSV-like fields after the
 * standard syslog header) from a genuine capture (Johannes Weber's
 * "Ultimate PCAP"). All real traffic in both transports was RFC 3164
 * format (`<PRI>TIMESTAMP ...`), not RFC 5424's more rigidly
 * structured format — confirmed the TCP framing is RFC 6587's
 * "non-transparent framing" (each message starts directly with its
 * own `<PRI>`, terminated by a trailing LF), not octet-counting.
 *
 * WIRE FORMAT: `<PRI>` where PRI is a decimal number (facility*8 +
 * severity) in angle brackets, immediately followed by the message
 * text — RFC 3164 doesn't mandate a strict machine-parseable
 * structure beyond the PRI value itself; everything after it is
 * conventionally "TIMESTAMP HOSTNAME TAG: MESSAGE" but real-world
 * variance in exactly how that's formatted (confirmed by this
 * capture's two genuinely different real formats) makes rigid parsing
 * of anything past PRI unreliable. RFC 5424 messages (`<PRI>1
 * TIMESTAMP...` — note the version digit `1` right after PRI) are
 * detected and the same PRI extraction applies, though this capture
 * had no real RFC 5424 traffic to verify that path against.
 *
 * SCOPE: extracts facility, severity (both decoded from PRI), and a
 * bounded prefix of the message text — full free-form message parsing
 * beyond that isn't attempted, matching real syslog's own design (it's
 * meant to be human-readable text, not a strict machine format, unlike
 * every binary/BER protocol elsewhere in this project). Walks multiple
 * LF-delimited messages per buffer, bounded, in case a TCP segment
 * ever carries more than one — this capture's real TCP traffic always
 * had exactly one message per segment, so that path is implemented per
 * RFC 6587 but not exercised by real multi-message traffic.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define SYSLOG_MAX_MESSAGES_PER_BUFFER 8
#define SYSLOG_MSG_PREVIEW_LEN 200

static const char *syslog_facility_name(uint8_t facility) {
    static const char *names[] = {
        "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
        "uucp", "cron", "authpriv", "ftp", "ntp", "logaudit", "logalert",
        "clock", "local0", "local1", "local2", "local3", "local4", "local5",
        "local6", "local7"
    };
    if (facility < 24) return names[facility];
    return "unknown";
}

static const char *syslog_severity_name(uint8_t severity) {
    static const char *names[] = {
        "Emergency", "Alert", "Critical", "Error", "Warning",
        "Notice", "Informational", "Debug"
    };
    if (severity < 8) return names[severity];
    return "unknown";
}

/* Parses "<NNN>" at the start of data. Returns the value and how many
 * bytes the "<NNN>" token itself occupied, or false if not present/
 * malformed. NNN must be 1-3 digits (RFC 3164/5424: PRI is 0-191). */
static bool syslog_parse_pri(const uint8_t *data, size_t len, uint32_t *pri_out, size_t *consumed) {
    if (len < 3 || data[0] != '<') return false;
    size_t pos = 1;
    uint32_t val = 0;
    int n_digits = 0;
    while (pos < len && isdigit(data[pos]) && n_digits < 3) {
        val = val * 10 + (data[pos] - '0');
        pos++;
        n_digits++;
    }
    if (n_digits == 0 || pos >= len || data[pos] != '>') return false;
    if (val > 191) return false;   /* max valid PRI: facility 23 * 8 + severity 7 */
    *pri_out = val;
    *consumed = pos + 1;
    return true;
}

static double syslog_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    (void)l4_proto;
    if (len < 4) return 0.0;

    uint32_t pri;
    size_t consumed;
    if (!syslog_parse_pri(payload, len, &pri, &consumed)) return 0.0;

    double confidence = 0.6;
    if (dst_port == 514 || dst_port == 601) confidence = 0.85;
    return confidence;
}

static void syslog_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t pos = 0;
    int n_messages = 0;

    while (pos < len && n_messages < SYSLOG_MAX_MESSAGES_PER_BUFFER) {
        uint32_t pri;
        size_t consumed;
        if (!syslog_parse_pri(payload + pos, len - pos, &pri, &consumed)) {
            if (n_messages == 0) dissect_result_add(out, "parse_warning", "syslog_pri_not_found");
            break;
        }

        if (n_messages == 0) {
            uint8_t facility = (uint8_t)(pri / 8);
            uint8_t severity = (uint8_t)(pri % 8);
            char buf[8];
            snprintf(buf, sizeof(buf), "%u", pri);
            dissect_result_add(out, "syslog_pri", buf);
            dissect_result_add(out, "syslog_facility", syslog_facility_name(facility));
            dissect_result_add(out, "syslog_severity", syslog_severity_name(severity));

            /* RFC 5424 detection: a version digit "1" immediately
             * follows PRI, followed by a space, e.g. "<14>1 2023-...".
             * This capture had no real RFC 5424 traffic to verify
             * against — see file header. */
            size_t msg_start = pos + consumed;
            if (msg_start + 2 <= len && payload[msg_start] == '1' && payload[msg_start+1] == ' ') {
                dissect_result_add(out, "syslog_rfc5424", "true");
            } else {
                dissect_result_add(out, "syslog_rfc5424", "false");
            }

            /* Bounded message preview — free-form text past this
             * point, see file header for why nothing further is
             * parsed rigidly. */
            size_t remaining = len - msg_start;
            /* Trim to the first LF if present (message boundary),
             * else the whole remainder up to the preview cap. */
            size_t msg_len = remaining;
            for (size_t i = 0; i < remaining; i++) {
                if (payload[msg_start + i] == '\n') { msg_len = i; break; }
            }
            char preview[SYSLOG_MSG_PREVIEW_LEN + 1];
            size_t pn = msg_len < SYSLOG_MSG_PREVIEW_LEN ? msg_len : SYSLOG_MSG_PREVIEW_LEN;
            memcpy(preview, payload + msg_start, pn);
            preview[pn] = '\0';
            dissect_result_add(out, "syslog_message_preview", preview);
        }

        /* Advance past this message: find the LF terminator (RFC 6587
         * non-transparent framing) or, if none, treat the rest of the
         * buffer as this one message and stop. */
        size_t search_start = pos + consumed;
        size_t next_pos = len;
        for (size_t i = search_start; i < len; i++) {
            if (payload[i] == '\n') { next_pos = i + 1; break; }
        }
        pos = next_pos;
        n_messages++;
        if (next_pos >= len) break;
    }

    char buf[8];
    snprintf(buf, sizeof(buf), "%d", n_messages);
    dissect_result_add(out, "syslog_message_count", buf);
}

static const uint16_t syslog_hint_ports[] = { 514, 601 };

void register_syslog_dissector(void) {
    register_dissector("Syslog", syslog_detect, syslog_dissect, syslog_hint_ports, 2);
}
