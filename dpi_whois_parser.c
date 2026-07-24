/*
 * dpi_whois_parser.c
 *
 * WHOIS (RFC 3912) dissector — TCP port 43. The simplest text
 * protocol in this project: the client sends exactly one line (a
 * query, terminated by CRLF) and the server replies with an
 * arbitrary, unstructured block of human-readable text, then closes
 * the connection. RFC 3912 doesn't standardize the query syntax
 * beyond "a line of text" — real registries differ (some take a bare
 * domain name, others accept flags like the real example below).
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 5 real payloads (of 10 port-43 packets total — the
 * other 5 were empty ACKs, the same "port count includes handshake
 * packets" pattern already seen throughout this project). Real
 * traffic: a genuine query `"-T dn,ace weberlab.de\r\n"` (DENIC/RIPE-
 * style flag syntax, querying a real domain) and a real, substantial
 * response beginning `"% Restricted rights...% Terms and Conditions
 * of Use..."` — a real DENIC (.de registry) response format, not
 * synthetic. 3 of the 5 real payloads were the same 6-byte non-
 * printable capture artifact already found (now for the sixth time)
 * across FTP, POP3, MSNP, Gnutella, Kerberos, and now WHOIS — checked
 * individually again here rather than assumed to be the same thing
 * without verifying, and confirmed identical in shape.
 *
 * WIRE FORMAT: no structure at all beyond "one CRLF-terminated line"
 * for the query. The response has NO structural signature
 * whatsoever — it's arbitrary text, whatever the remote registry
 * chooses to send — so unlike every other text-based protocol in
 * this project (FTP's status codes, POP3's +OK/-ERR, SMTP's reply
 * codes), there is no way to structurally distinguish a WHOIS
 * response from any other plain-text TCP payload. detect() on the
 * response side leans on the port number almost entirely, stated
 * honestly rather than implying a structural signal that doesn't
 * exist.
 *
 * A REAL FALSE POSITIVE FOUND AND FIXED: `dst_port` for a genuine
 * WHOIS response is just the client's ephemeral port (confirmed by
 * checking how the capture path actually invokes dispatch_dissection()
 * — it passes the packet's real destination port, with no WHOIS-
 * specific context); this file's detect() has no way to see the
 * real source port (43) for a response at all. The original response-
 * side check — "one printable-ASCII line ending in CRLF, on any
 * port" — matched completely unrelated real traffic found later in
 * this project: a proprietary steganography tool's session banner
 * ("Invisible Secrets 4 - Ready\r\n", one short line on TCP port
 * 10000) scored 0.4, clearing this project's dispatch threshold
 * (0.3), which would have misclassified it as WHOIS. Real WHOIS
 * responses are substantially different in shape — multi-line blocks
 * of registry data, not a single short banner — confirmed against
 * the real response already verified for this file (5 lines, 276+
 * bytes). Tightened to require both multiple lines and a minimum
 * length; re-verified this still correctly detects both real WHOIS
 * payloads from the original verification (2/5 payloads with data —
 * the query and the response) and now correctly rejects the real
 * false-positive sample.
 *
 * SCOPE: the full query line (bounded) for client-to-server traffic;
 * a bounded preview of the response text for server-to-client traffic
 * — same "extract a preview, note the privacy/structure limits
 * honestly" pattern as Syslog's message preview and Telnet's data
 * preview. WHOIS responses are already public directory data by
 * design (that's the protocol's whole purpose), so there's no
 * credential-safety concern here the way there is for Telnet.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define WHOIS_QUERY_PREVIEW_LEN 128
#define WHOIS_RESPONSE_PREVIEW_LEN 128

static bool whois_line_looks_valid(const uint8_t *line, size_t len) {
    if (len == 0) return false;
    for (size_t i = 0; i < len; i++) {
        if (line[i] < 0x20 && line[i] != '\t') return false;
        if (line[i] > 0x7E) return false;
    }
    return true;
}

static size_t whois_find_line_end(const uint8_t *data, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (data[i] == '\r' && data[i+1] == '\n') return i;
    }
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n') return i;
    }
    return len;
}

static double whois_detect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < 1) return 0.0;

    if (dst_port == 43) {
        /* Client query: the one real structural signal this protocol
         * has — a single printable-ASCII line ending in CRLF (or at
         * least not containing raw control/binary bytes). */
        size_t line_end = whois_find_line_end(payload, len);
        if (!whois_line_looks_valid(payload, line_end)) return 0.0;
        return 0.75;
    }

    /* Response direction: no structural signal exists, see file
     * header — and a REAL FALSE POSITIVE was found here, worth
     * stating precisely. `dst_port` for a genuine WHOIS response is
     * just the client's ephemeral port (confirmed by checking how the
     * capture path actually calls dispatch_dissection() — it passes
     * the packet's real destination port, nothing WHOIS-specific);
     * this detect() function has no way to see the response's real
     * SOURCE port (43) at all. The previous version of this check —
     * "one printable-ASCII line ending in CRLF, any port" — matched
     * completely unrelated real traffic: a proprietary steganography
     * tool's session banner ("Invisible Secrets 4 - Ready\r\n", a
     * single short line on TCP port 10000) scored 0.4, comfortably
     * above this project's dispatch threshold (0.3), which would have
     * misclassified it as WHOIS. Real WHOIS responses are
     * substantially different in shape — multi-line blocks of
     * registry data, not a single short banner line — confirmed
     * against the one real response already verified for this file
     * (5 lines, 276+ bytes). Tightened to require BOTH multiple lines
     * and a minimum length, re-verified this still matches the real
     * response and correctly rejects the real false-positive sample. */
    size_t line_end = whois_find_line_end(payload, len);
    size_t check_len = line_end < 64 ? line_end : 64;
    if (!whois_line_looks_valid(payload, check_len)) return 0.0;

    if (len < 50) return 0.0;
    int newline_count = 0;
    for (uint16_t i = 0; i < len; i++) {
        if (payload[i] == '\n') newline_count++;
    }
    if (newline_count < 2) return 0.0;

    return 0.4;
}

static void whois_dissect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto,
                           struct dissect_result *out) {
    (void)l4_proto;

    if (dst_port == 43) {
        size_t line_end = whois_find_line_end(payload, len);
        if (!whois_line_looks_valid(payload, line_end)) return;
        char buf[WHOIS_QUERY_PREVIEW_LEN + 1];
        size_t n = line_end < WHOIS_QUERY_PREVIEW_LEN ? line_end : WHOIS_QUERY_PREVIEW_LEN;
        memcpy(buf, payload, n);
        buf[n] = '\0';
        dissect_result_add(out, "whois_query", buf);
        return;
    }

    /* Response: bounded text preview, matching only printable/common
     * whitespace bytes through — WHOIS responses are already public
     * directory data, no privacy concern the way Telnet's is. */
    char buf[WHOIS_RESPONSE_PREVIEW_LEN + 1];
    size_t n = 0;
    for (size_t i = 0; i < len && n < WHOIS_RESPONSE_PREVIEW_LEN; i++) {
        uint8_t b = payload[i];
        buf[n++] = (isprint(b) || b == '\r' || b == '\n' || b == '\t') ? (char)b : '.';
    }
    buf[n] = '\0';
    if (n > 0) dissect_result_add(out, "whois_response_preview", buf);
}

static const uint16_t whois_hint_ports[] = { 43 };

void register_whois_dissector(void) {
    register_dissector("WHOIS", whois_detect, whois_dissect, whois_hint_ports, 1);
}
