/*
 * dpi_sip_rtp_parser.c
 *
 * SIP (RFC 3261) and RTP (RFC 3550) dissectors. Grouped in one file
 * since they're the two protocols of a VoIP call (SIP for signaling,
 * RTP for the actual media stream) and are typically discussed and
 * deployed together, though they're structurally very different —
 * SIP is text-based like HTTP, RTP is a compact binary header.
 *
 * NOT COMPILED/TESTED in this environment.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* ==================================================================
 * SIP (RFC 3261) — text-based, request/status line + headers, same
 * general shape as HTTP/1.1. Runs over UDP or TCP; this dissector
 * handles the UDP case (the common one for SIP signaling) — the
 * per-message parsing logic below is transport-agnostic and would
 * work identically fed from a TCP-reassembled buffer if wired there.
 * ================================================================== */
#define SIP_PORT       5060
#define SIP_MAX_HDRS   32
#define SIP_MAX_LINE   512

static bool sip_looks_like_request_or_response(const uint8_t *payload, uint16_t len) {
    /* SIP request lines start with a method ("INVITE", "REGISTER",
     * etc.) followed by a space; response lines start with "SIP/2.0".
     * Cheap, deliberately permissive check — dissect() re-validates
     * properly, this is just for detect()'s confidence signal. */
    if (len < 8) return false;
    if (memcmp(payload, "SIP/2.0", 7) == 0) return true;

    static const char *methods[] = {
        "INVITE ", "ACK ", "BYE ", "CANCEL ", "REGISTER ",
        "OPTIONS ", "PRACK ", "SUBSCRIBE ", "NOTIFY ", "MESSAGE "
    };
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        size_t mlen = strlen(methods[i]);
        if (len >= mlen && memcmp(payload, methods[i], mlen) == 0) return true;
    }
    return false;
}

static double sip_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    (void)l4_proto;   /* SIP runs over both UDP and TCP; no transport restriction here */
    if (!sip_looks_like_request_or_response(payload, len)) return 0.0;

    double confidence = 0.6;
    if (dst_port == SIP_PORT) confidence = 0.9;
    return confidence;
}

/* Find the end of the current line (CRLF or bare LF), bounded by
 * `len`. Returns the offset of the line terminator, or `len` if none
 * found (caller treats that as "no more complete lines available"). */
static size_t sip_find_line_end(const uint8_t *buf, size_t len, size_t start) {
    for (size_t i = start; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') return i;
    }
    for (size_t i = start; i < len; i++) {
        if (buf[i] == '\n') return i;
    }
    return len;
}

static void sip_dissect(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto,
                         struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t line_end = sip_find_line_end(payload, len, 0);
    if (line_end >= len) {
        dissect_result_add(out, "parse_warning", "no_complete_first_line");
        return;
    }

    char first_line[SIP_MAX_LINE];
    size_t first_line_len = line_end < sizeof(first_line) - 1 ? line_end : sizeof(first_line) - 1;
    memcpy(first_line, payload, first_line_len);
    first_line[first_line_len] = '\0';

    bool is_response = (strncmp(first_line, "SIP/2.0", 7) == 0);
    dissect_result_add(out, "sip_is_response", is_response ? "true" : "false");
    dissect_result_add(out, "sip_first_line", first_line);

    if (is_response) {
        /* "SIP/2.0 200 OK" — extract the 3-digit status code. */
        if (first_line_len >= 11 && first_line[8] && isdigit((unsigned char)first_line[8])) {
            char code[4] = { first_line[8], first_line[9], first_line[10], '\0' };
            dissect_result_add(out, "sip_status_code", code);
        }
    } else {
        /* "INVITE sip:bob@example.com SIP/2.0" — extract the method
         * (first space-delimited token). */
        char method[32];
        size_t i = 0;
        while (i < first_line_len && i < sizeof(method) - 1 && first_line[i] != ' ') {
            method[i] = first_line[i];
            i++;
        }
        method[i] = '\0';
        dissect_result_add(out, "sip_method", method);
    }

    /* Walk headers looking for a small set of the most useful ones
     * (From/To/Call-ID) — not a full generic header map, matching the
     * "extract what's actually useful" pattern used by the other
     * text-based dissectors in this project rather than parsing
     * everything generically. */
    size_t pos = line_end + (payload[line_end] == '\r' ? 2 : 1);
    int hdrs_parsed = 0;

    while (pos < len && hdrs_parsed < SIP_MAX_HDRS) {
        size_t hdr_end = sip_find_line_end(payload, len, pos);
        if (hdr_end <= pos) break;   /* blank line: end of headers */
        if (hdr_end >= len) break;   /* incomplete final line: stop, don't guess */

        size_t hdr_len = hdr_end - pos;
        char hdr_line[SIP_MAX_LINE];
        size_t n = hdr_len < sizeof(hdr_line) - 1 ? hdr_len : sizeof(hdr_line) - 1;
        memcpy(hdr_line, payload + pos, n);
        hdr_line[n] = '\0';

        char *colon = strchr(hdr_line, ':');
        if (colon) {
            *colon = '\0';
            char *val = colon + 1;
            while (*val == ' ') val++;

            if (strcasecmp(hdr_line, "Call-ID") == 0 || strcasecmp(hdr_line, "i") == 0) {
                dissect_result_add(out, "sip_call_id", val);
            } else if (strcasecmp(hdr_line, "From") == 0 || strcasecmp(hdr_line, "f") == 0) {
                dissect_result_add(out, "sip_from", val);
            } else if (strcasecmp(hdr_line, "To") == 0 || strcasecmp(hdr_line, "t") == 0) {
                dissect_result_add(out, "sip_to", val);
            }
        }

        hdrs_parsed++;
        pos = hdr_end + (payload[hdr_end] == '\r' ? 2 : 1);
    }
}

static const uint16_t sip_hint_ports[] = { SIP_PORT };

void register_sip_dissector(void) {
    register_dissector("SIP", sip_detect, sip_dissect, sip_hint_ports, 1);
}

/* ==================================================================
 * RTP (RFC 3550) — fixed 12-byte header, no crypto, minimal metadata
 * (payload type, sequence number, timestamp, SSRC). RTP itself
 * carries no application-identifying information (that's SIP's job,
 * in the SDP body negotiating the RTP session) — this dissector
 * extracts what RTP actually has: session/stream identity (SSRC) and
 * codec hint (payload type), useful for correlating with a SIP call
 * and for basic traffic characterization, not for identifying an app.
 * ================================================================== */
#define RTP_MIN_HDR_LEN 12

static double rtp_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    (void)dst_port;   /* RTP has no registered port — it's negotiated per-call
                        * via SDP, so port hints don't meaningfully apply here */
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < RTP_MIN_HDR_LEN) return 0.0;

    uint8_t version = payload[0] >> 6;
    if (version != 2) return 0.0;   /* RFC 3550 mandates version 2 */

    uint8_t payload_type = payload[1] & 0x7F;
    /* Payload types 72-76 are reserved for RTCP co-existing on the
     * same port range in some deployments — not RTP media, treat as a
     * weaker match rather than a hard reject, since real behavior
     * varies by deployment. */
    double confidence = (payload_type >= 72 && payload_type <= 76) ? 0.3 : 0.5;
    return confidence;
}

static void rtp_dissect(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto,
                         struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    /* Same real defense-in-depth as radius_dissect() gained after a
     * compiler flagged its unused `len` parameter: don't rely solely
     * on detect()'s len < RTP_MIN_HDR_LEN check having already run on
     * this exact buffer — fail safely here too if it somehow wasn't. */
    if (len < RTP_MIN_HDR_LEN) return;

    uint8_t byte0 = payload[0];
    uint8_t byte1 = payload[1];
    bool marker = (byte1 & 0x80) != 0;
    uint8_t payload_type = byte1 & 0x7F;
    uint16_t seq = (payload[2] << 8) | payload[3];
    uint32_t timestamp = (payload[4]<<24)|(payload[5]<<16)|(payload[6]<<8)|payload[7];
    uint32_t ssrc = (payload[8]<<24)|(payload[9]<<16)|(payload[10]<<8)|payload[11];
    uint8_t csrc_count = byte0 & 0x0F;

    char buf[16];
    snprintf(buf, sizeof(buf), "%u", payload_type);
    dissect_result_add(out, "rtp_payload_type", buf);
    snprintf(buf, sizeof(buf), "%u", seq);
    dissect_result_add(out, "rtp_sequence_number", buf);
    snprintf(buf, sizeof(buf), "%u", timestamp);
    dissect_result_add(out, "rtp_timestamp", buf);
    snprintf(buf, sizeof(buf), "0x%08x", ssrc);
    dissect_result_add(out, "rtp_ssrc", buf);
    dissect_result_add(out, "rtp_marker", marker ? "true" : "false");
    snprintf(buf, sizeof(buf), "%u", csrc_count);
    dissect_result_add(out, "rtp_csrc_count", buf);
}

static const uint16_t rtp_hint_ports[] = { 0 };   /* no meaningful hint port, see rtp_detect */

void register_rtp_dissector(void) {
    register_dissector("RTP", rtp_detect, rtp_dissect, rtp_hint_ports, 0);
}
