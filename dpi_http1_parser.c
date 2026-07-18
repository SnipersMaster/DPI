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
 * line, plus the Host header specifically — the HTTP/1.1 analog of
 * TLS's SNI for app/domain identification. Does not do general header
 * parsing, chunked transfer-encoding reassembly, or body inspection —
 * matching the "extract what's actually useful" pattern used by SIP.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define HTTP_PORT       80
#define HTTP_MAX_LINE   2048
#define HTTP_MAX_HDRS   64

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

    while (pos < len && hdrs_parsed < HTTP_MAX_HDRS) {
        size_t hdr_end = http_find_line_end(payload, len, pos);
        if (hdr_end == pos) break;       /* blank line: end of headers */
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
            }
        }

        hdrs_parsed++;
        pos = hdr_end + 2;
    }
}

static const uint16_t http1_hint_ports[] = { HTTP_PORT };

void register_http1_dissector(void) {
    register_dissector("HTTP/1.1", http1_detect, http1_dissect, http1_hint_ports, 1);
}
