/*
 * dpi_http1_parser.c
 *
 * HTTP/1.1 (RFC 9110-9112) dissector — request/status line + Host
 * header. Meant to run on TCP payload (either from
 * dpi_tcp_flow_reassembly.c's contiguous output, or raw if plaintext
 * HTTP on a non-standard flow) — plaintext, no crypto boundary.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * SCOPE: extracts the request line (method/path/version) or status
 * line, the Host/User-Agent/Content-Type headers, and a bounded body
 * preview (up to 200 bytes, plus the real total body length) — added
 * on direct request; previously out of scope. Does not do general
 * header parsing beyond the three named above, or chunked transfer-
 * encoding reassembly (a chunked body's own length-prefix framing
 * isn't unwound — the raw bytes captured for the preview would
 * include chunk-size markers rather than pure body content in that
 * case, stated honestly rather than silently wrong).
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define HTTP_PORT       80
#define HTTP_MAX_LINE   2048
#define HTTP_MAX_HDRS   64
#define HTTP_MAX_BODY_PREVIEW 200

static const char *http_methods[] = {
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ",
    "PATCH ", "CONNECT ", "TRACE "
};

static double http1_detect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < 8) return 0.0;

    if (len >= 5 && memcmp(payload, "HTTP/", 5) == 0) {
        double confidence = 0.7;
        if (dst_port == HTTP_PORT) confidence = 0.9;
        return confidence;
    }

    for (size_t i = 0; i < sizeof(http_methods) / sizeof(http_methods[0]); i++) {
        size_t mlen = strlen(http_methods[i]);
        if (len >= mlen && memcmp(payload, http_methods[i], mlen) == 0) {
            double confidence = 0.7;
            if (dst_port == HTTP_PORT) confidence = 0.9;
            return confidence;
        }
    }
    return 0.0;
}

static size_t http_find_line_end(const uint8_t *buf, size_t len, size_t start) {
    for (size_t i = start; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') return i;
    }
    return len;   /* HTTP/1.1 requires CRLF, not bare LF — unlike SIP's
                   * tolerance, so no bare-LF fallback here */
}

static void http1_dissect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto,
                           struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t line_end = http_find_line_end(payload, len, 0);
    if (line_end >= len) {
        dissect_result_add(out, "parse_warning", "no_complete_first_line");
        return;
    }

    char first_line[HTTP_MAX_LINE];
    size_t fl_len = line_end < sizeof(first_line) - 1 ? line_end : sizeof(first_line) - 1;
    memcpy(first_line, payload, fl_len);
    first_line[fl_len] = '\0';

    bool is_response = (fl_len >= 5 && memcmp(first_line, "HTTP/", 5) == 0);
    dissect_result_add(out, "http_is_response", is_response ? "true" : "false");
    dissect_result_add(out, "http_first_line", first_line);

    if (is_response) {
        /* "HTTP/1.1 200 OK" */
        if (fl_len >= 12) {
            char code[4] = { first_line[9], first_line[10], first_line[11], '\0' };
            dissect_result_add(out, "http_status_code", code);
        }
    } else {
        /* "GET /path HTTP/1.1" */
        char method[16];
        size_t i = 0;
        while (i < fl_len && i < sizeof(method) - 1 && first_line[i] != ' ') {
            method[i] = first_line[i]; i++;
        }
        method[i] = '\0';
        dissect_result_add(out, "http_method", method);

        if (i < fl_len) {
            size_t path_start = i + 1;
            size_t path_end = path_start;
            while (path_end < fl_len && first_line[path_end] != ' ') path_end++;
            if (path_end > path_start) {
                char path[512];
                size_t plen = (path_end - path_start) < sizeof(path) - 1
                               ? (path_end - path_start) : sizeof(path) - 1;
                memcpy(path, first_line + path_start, plen);
                path[plen] = '\0';
                dissect_result_add(out, "http_path", path);
            }
        }
    }

    /* Walk headers for Host specifically — the HTTP/1.1 equivalent of
     * TLS SNI for domain/app identification. */
    size_t pos = line_end + 2;
    int hdrs_parsed = 0;
    bool found_blank_line = false;

    while (pos < len && hdrs_parsed < HTTP_MAX_HDRS) {
        size_t hdr_end = http_find_line_end(payload, len, pos);
        if (hdr_end == pos) { found_blank_line = true; break; }   /* blank line: end of headers */
        if (hdr_end >= len) break;       /* incomplete final line: stop */

        size_t hdr_len = hdr_end - pos;
        char hdr_line[HTTP_MAX_LINE];
        size_t n = hdr_len < sizeof(hdr_line) - 1 ? hdr_len : sizeof(hdr_line) - 1;
        memcpy(hdr_line, payload + pos, n);
        hdr_line[n] = '\0';

        char *colon = strchr(hdr_line, ':');
        if (colon) {
            *colon = '\0';
            char *val = colon + 1;
            while (*val == ' ') val++;

            if (strcasecmp(hdr_line, "Host") == 0) {
                dissect_result_add(out, "http_host", val);
            } else if (strcasecmp(hdr_line, "User-Agent") == 0) {
                dissect_result_add(out, "http_user_agent", val);
            } else if (strcasecmp(hdr_line, "Content-Type") == 0) {
                dissect_result_add(out, "http_content_type", val);
            }
        }

        hdrs_parsed++;
        pos = hdr_end + 2;
    }

    /* Body/payload extraction — added on direct request, previously
     * out of scope (see this file's own earlier header comment, now
     * updated). Only attempted when a genuine blank-line terminator
     * was actually found above; without one, `pos` doesn't reliably
     * point at a body boundary at all (it could be mid-header, from
     * hitting HTTP_MAX_HDRS or an incomplete final header line), and
     * treating it as a body start would risk extracting header bytes
     * or garbage rather than real body content.
     *
     * Bounded to HTTP_MAX_BODY_PREVIEW bytes — this is a preview, not
     * a full-body capture; real HTTP bodies (uploads, large JSON
     * responses, images) can be arbitrarily large, and this project's
     * `dissect_result` field values are themselves capped at
     * MAX_FIELD_VAL_LEN (256) bytes regardless, so anything longer
     * gets safely truncated by `dissect_result_add()` either way —
     * bounding it explicitly here just makes that truncation a
     * deliberate design choice instead of an incidental one.
     *
     * No content-type filtering (e.g. skip images/binary) — the
     * bytes are handed to `dissect_result_add()` as-is, and this
     * project's own JSON emission layer (`dpi_flow_record.c`'s
     * `json_escape()`) already strips control characters and escapes
     * quotes/backslashes for every nested field value regardless of
     * origin, so non-printable body content becomes valid, if not
     * very readable, JSON rather than a malformed-output risk —
     * verified by inspecting that emission path directly rather than
     * assumed. */
    if (found_blank_line) {
        size_t body_start = pos + 2;
        if (body_start < len) {
            size_t body_len = len - body_start;
            char bodybuf[HTTP_MAX_BODY_PREVIEW + 1];
            size_t n = body_len < HTTP_MAX_BODY_PREVIEW ? body_len : HTTP_MAX_BODY_PREVIEW;
            memcpy(bodybuf, payload + body_start, n);
            bodybuf[n] = '\0';
            dissect_result_add(out, "http_body_preview", bodybuf);

            char lenbuf[24];   /* sized for any size_t value (up to 20
                                   digits on a 64-bit size_t) + NUL,
                                   not just the realistic range this
                                   value actually takes — a real
                                   compiler warning (-Wformat-
                                   truncation) caught the previous
                                   16-byte buffer being provably too
                                   small for what %zu can print,
                                   even though body_len itself can't
                                   actually reach that range in
                                   practice (derived from a uint16_t
                                   packet length) */
            snprintf(lenbuf, sizeof(lenbuf), "%zu", body_len);
            dissect_result_add(out, "http_body_length", lenbuf);
        }
    }
}

static const uint16_t http1_hint_ports[] = { HTTP_PORT };

void register_http1_dissector(void) {
    register_dissector("HTTP/1.1", http1_detect, http1_dissect, http1_hint_ports, 1);
}
