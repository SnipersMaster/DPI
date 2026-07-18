/*
 * dpi_http2_parser.c
 *
 * HTTP/2 (RFC 9113) dissector — connection preface detection and
 * frame-level parsing (type, flags, stream ID, length).
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * -------------------------------------------------------------------
 * EXPLICIT SCOPE LIMIT — read before assuming this gives you
 * :authority (HTTP/2's Host-header equivalent):
 * -------------------------------------------------------------------
 * HEADERS frames carry their field block HPACK-COMPRESSED (RFC 7541),
 * not plaintext. Decoding HPACK is NOT a small addition — unlike
 * DNS's name compression (a bounded, stateless pointer-following
 * scheme), HPACK requires:
 *   - A STATEFUL dynamic table per connection, updated by BOTH
 *     directions' HEADERS frames over the connection's lifetime —
 *     meaning you cannot correctly decode headers frame N without
 *     having correctly decoded frames 1..N-1 first, in order. This is
 *     a materially different problem than DNS decompression, which is
 *     self-contained per-message.
 *   - Huffman decoding (RFC 7541 Appendix B) for Huffman-coded string
 *     literals, which most real implementations use for smaller
 *     payloads.
 *   - The static table (RFC 7541 Appendix A, 61 predefined entries).
 * This is genuinely a separate subsystem — comparable in scope to,
 * say, the TCP flow reassembly layer was — not a follow-up tweak to
 * this file. It's flagged in the README as a real next step, not
 * silently glossed over here.
 *
 * WHAT THIS FILE DOES INSTEAD, AND WHY IT'S STILL USEFUL: frame-level
 * metadata (frame type distribution, stream count, frame sizes,
 * whether SETTINGS/PING/GOAWAY frames appear) is genuinely useful for
 * traffic characterization and anomaly detection even without header
 * content — e.g. an unusually large number of concurrent streams, or
 * repeated RST_STREAM frames, can indicate abuse (HTTP/2 Rapid Reset
 * style patterns) independent of what's actually in the headers.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define HTTP2_PORT 443   /* h2 is almost always over TLS/443 in practice;
                            h2c (cleartext) exists but is rare outside
                            internal/dev environments */

static const uint8_t HTTP2_PREFACE[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";   /* RFC 9113 §3.4, exactly 24 bytes */
#define HTTP2_PREFACE_LEN 24

#define HTTP2_FRAME_HDR_LEN 9

static const char *http2_frame_type_name(uint8_t t) {
    switch (t) {
        case 0x0: return "DATA";
        case 0x1: return "HEADERS";
        case 0x2: return "PRIORITY";
        case 0x3: return "RST_STREAM";
        case 0x4: return "SETTINGS";
        case 0x5: return "PUSH_PROMISE";
        case 0x6: return "PING";
        case 0x7: return "GOAWAY";
        case 0x8: return "WINDOW_UPDATE";
        case 0x9: return "CONTINUATION";
        default:  return "Unknown";
    }
}

static double http2_detect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto) {
    (void)dst_port;
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;

    /* Strongest signal: the connection preface, sent once at the very
     * start of an h2c (cleartext) connection, or immediately after
     * ALPN negotiation for h2-over-TLS (in which case this dissector
     * would see it post-decryption if wired downstream of TLS — not
     * done in this pass, see the README's protocol table). */
    if (len >= HTTP2_PREFACE_LEN &&
        memcmp(payload, HTTP2_PREFACE, HTTP2_PREFACE_LEN) == 0) {
        return 0.95;
    }

    /* Weaker signal: looks like a plausible frame header even without
     * the preface (e.g. mid-stream capture that missed the preface).
     * Structural validation only — length field within range, known
     * frame type, stream ID's reserved bit is 0 per RFC 9113 §4.1. */
    if (len >= HTTP2_FRAME_HDR_LEN) {
        uint8_t frame_type = payload[3];
        bool reserved_bit_zero = (payload[5] & 0x80) == 0;
        if (frame_type <= 0x9 && reserved_bit_zero) {
            return 0.3;   /* plausible but weak without the preface */
        }
    }

    return 0.0;
}

static void http2_dissect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto,
                           struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t pos = 0;
    bool has_preface = (len >= HTTP2_PREFACE_LEN &&
                         memcmp(payload, HTTP2_PREFACE, HTTP2_PREFACE_LEN) == 0);
    if (has_preface) {
        dissect_result_add(out, "http2_preface_present", "true");
        pos = HTTP2_PREFACE_LEN;
    } else {
        dissect_result_add(out, "http2_preface_present", "false");
    }

    /* Walk as many complete frame headers as are available. Frame
     * PAYLOADS are skipped over (using the frame's own length field)
     * rather than parsed — HEADERS frame contents specifically are
     * HPACK-compressed and out of scope, see this file's header
     * comment. */
    int frames_parsed = 0;
    int headers_frame_count = 0;
    int rst_stream_count = 0;
    int max_stream_id_seen = 0;

    while (pos + HTTP2_FRAME_HDR_LEN <= len && frames_parsed < 64) {
        uint32_t frame_len = (payload[pos]<<16)|(payload[pos+1]<<8)|payload[pos+2];
        uint8_t frame_type = payload[pos+3];
        uint32_t stream_id = ((payload[pos+5]<<24)|(payload[pos+6]<<16)|
                               (payload[pos+7]<<8)|payload[pos+8]) & 0x7FFFFFFF;

        if (pos + HTTP2_FRAME_HDR_LEN + frame_len > len) {
            /* Frame body not fully in this buffer — normal for a
             * large DATA frame split across TCP segments; stop here
             * rather than guess at partial content. */
            dissect_result_add(out, "http2_truncated_frame", "true");
            break;
        }

        if (frame_type == 0x1 /* HEADERS */) headers_frame_count++;
        if (frame_type == 0x3 /* RST_STREAM */) rst_stream_count++;
        if ((int)stream_id > max_stream_id_seen) max_stream_id_seen = (int)stream_id;

        pos += HTTP2_FRAME_HDR_LEN + frame_len;
        frames_parsed++;
    }

    char buf[16];
    snprintf(buf, sizeof(buf), "%d", frames_parsed);
    dissect_result_add(out, "http2_frames_parsed", buf);
    snprintf(buf, sizeof(buf), "%d", headers_frame_count);
    dissect_result_add(out, "http2_headers_frame_count", buf);
    snprintf(buf, sizeof(buf), "%d", rst_stream_count);
    dissect_result_add(out, "http2_rst_stream_count", buf);
    snprintf(buf, sizeof(buf), "%d", max_stream_id_seen);
    dissect_result_add(out, "http2_max_stream_id", buf);

    /* A high RST_STREAM count relative to frames parsed is the
     * signature of an HTTP/2 Rapid Reset-style abuse pattern (streams
     * opened and immediately reset to avoid server-side concurrent-
     * stream limits) — surfaced as a flag since it's detectable at
     * the frame-metadata level without needing HPACK at all. */
    if (frames_parsed > 0 && rst_stream_count * 2 > frames_parsed) {
        dissect_result_add(out, "http2_high_reset_ratio_flag", "true");
    }

    (void)http2_frame_type_name;   /* used for human-readable logging in a
                                     * fuller implementation; referenced here
                                     * to avoid an unused-function warning
                                     * in this reference version */
}

static const uint16_t http2_hint_ports[] = { HTTP2_PORT };

void register_http2_dissector(void) {
    register_dissector("HTTP/2", http2_detect, http2_dissect, http2_hint_ports, 1);
}
