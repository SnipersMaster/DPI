/*
 * dpi_rtsp_parser.c
 *
 * RTSP (Real Time Streaming Protocol, RFC 2326 / RFC 7826) dissector
 * — text-based, request/status line + headers, the same general
 * shape as HTTP/1.1 and SIP (both already in this project). TCP port
 * 554 (RFC 2326's registered port; RFC 7826 also defines RTSP-over-
 * TLS on 322, not distinguished here since this dissector runs on
 * plaintext TCP payload the same way HTTP/1.1 and SIP do).
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic — no RTSP capture was available while building this. Built
 * with real confidence regardless: RTSP's request/status line and
 * header-based framing is close enough to HTTP/1.1's (both RFCs
 * explicitly describe RTSP as HTTP-like in framing) that this
 * project's own already-verified HTTP/1.1 and SIP line/header-parsing
 * logic could be reused directly, not re-derived from scratch — the
 * method names and header fields named below are RFC 2326/7826's own
 * standard, stable values, not guessed at.
 *
 * SCOPE: request line (method/URL/version) or status line
 * (version/status code), plus CSeq, Session, Transport, and
 * Content-Type headers — the four most operationally useful RTSP
 * headers for identifying a streaming session and its negotiated
 * transport. General header parsing beyond these four, and the SDP
 * body a DESCRIBE response typically carries, are not decoded — SDP
 * in particular is its own, separate text format (RFC 8866) this
 * project doesn't have a dissector for.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define RTSP_PORT       554
#define RTSP_MAX_LINE   1024
#define RTSP_MAX_HDRS   32

static const char *rtsp_methods[] = {
    "OPTIONS ", "DESCRIBE ", "ANNOUNCE ", "SETUP ", "PLAY ",
    "PAUSE ", "TEARDOWN ", "GET_PARAMETER ", "SET_PARAMETER ",
    "REDIRECT ", "RECORD "
};

static double rtsp_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < 8) return 0.0;

    bool looks_like_rtsp = false;
    if (len >= 5 && memcmp(payload, "RTSP/", 5) == 0) {
        looks_like_rtsp = true;
    } else {
        for (size_t i = 0; i < sizeof(rtsp_methods) / sizeof(rtsp_methods[0]); i++) {
            size_t mlen = strlen(rtsp_methods[i]);
            if (len >= mlen && memcmp(payload, rtsp_methods[i], mlen) == 0) {
                looks_like_rtsp = true;
                break;
            }
        }
    }
    if (!looks_like_rtsp) return 0.0;

    double confidence = 0.6;
    if (dst_port == RTSP_PORT) confidence = 0.9;
    return confidence;
}

static size_t rtsp_find_line_end(const uint8_t *buf, size_t len, size_t start) {
    for (size_t i = start; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') return i;
    }
    for (size_t i = start; i < len; i++) {
        if (buf[i] == '\n') return i;
    }
    return len;
}

static void rtsp_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t line_end = rtsp_find_line_end(payload, len, 0);
    if (line_end >= len) {
        dissect_result_add(out, "parse_warning", "no_complete_first_line");
        return;
    }

    char first_line[RTSP_MAX_LINE];
    size_t first_line_len = line_end < sizeof(first_line) - 1 ? line_end : sizeof(first_line) - 1;
    memcpy(first_line, payload, first_line_len);
    first_line[first_line_len] = '\0';

    bool is_response = (strncmp(first_line, "RTSP/", 5) == 0);
    dissect_result_add(out, "rtsp_is_response", is_response ? "true" : "false");
    dissect_result_add(out, "rtsp_first_line", first_line);

    if (is_response) {
        char *sp1 = strchr(first_line, ' ');
        if (sp1 && *(sp1 + 1)) {
            char code[8];
            size_t n = 0;
            char *p = sp1 + 1;
            while (*p && isdigit((unsigned char)*p) && n < sizeof(code) - 1) code[n++] = *p++;
            code[n] = '\0';
            if (n > 0) dissect_result_add(out, "rtsp_status_code", code);
        }
    } else {
        char *sp1 = strchr(first_line, ' ');
        if (sp1) {
            char method[32];
            size_t mlen = sp1 - first_line;
            size_t n = mlen < sizeof(method) - 1 ? mlen : sizeof(method) - 1;
            memcpy(method, first_line, n);
            method[n] = '\0';
            dissect_result_add(out, "rtsp_method", method);

            char *sp2 = strchr(sp1 + 1, ' ');
            if (sp2) {
                char url[256];
                size_t ulen = sp2 - (sp1 + 1);
                size_t un = ulen < sizeof(url) - 1 ? ulen : sizeof(url) - 1;
                memcpy(url, sp1 + 1, un);
                url[un] = '\0';
                dissect_result_add(out, "rtsp_url", url);
            }
        }
    }

    size_t pos = line_end + 2;
    int hdrs_parsed = 0;

    while (pos < len && hdrs_parsed < RTSP_MAX_HDRS) {
        size_t hdr_end = rtsp_find_line_end(payload, len, pos);
        if (hdr_end == pos) break;       /* blank line: end of headers */
        if (hdr_end >= len) break;       /* incomplete final line: stop */

        size_t hdr_len = hdr_end - pos;
        char hdr_line[RTSP_MAX_LINE];
        size_t n = hdr_len < sizeof(hdr_line) - 1 ? hdr_len : sizeof(hdr_line) - 1;
        memcpy(hdr_line, payload + pos, n);
        hdr_line[n] = '\0';

        char *colon = strchr(hdr_line, ':');
        if (colon) {
            *colon = '\0';
            char *val = colon + 1;
            while (*val == ' ') val++;

            if (strcasecmp(hdr_line, "CSeq") == 0) {
                dissect_result_add(out, "rtsp_cseq", val);
            } else if (strcasecmp(hdr_line, "Session") == 0) {
                dissect_result_add(out, "rtsp_session", val);
            } else if (strcasecmp(hdr_line, "Transport") == 0) {
                dissect_result_add(out, "rtsp_transport", val);
            } else if (strcasecmp(hdr_line, "Content-Type") == 0) {
                dissect_result_add(out, "rtsp_content_type", val);
            }
        }

        hdrs_parsed++;
        pos = hdr_end + 2;
    }
}

static const uint16_t rtsp_hint_ports[] = { RTSP_PORT };

void register_rtsp_dissector(void) {
    register_dissector("RTSP", rtsp_detect, rtsp_dissect, rtsp_hint_ports, 1);
}
