/*
 * dpi_http2_parser.c
 *
 * HTTP/2 (RFC 9113) dissector — connection preface detection,
 * frame-level parsing (type, flags, stream ID, length), and now HPACK
 * decoding (RFC 7541, via dpi_hpack_decoder.c) for HEADERS frames,
 * including :authority extraction.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * -------------------------------------------------------------------
 * SCOPE LIMIT — narrower than "no HPACK at all" (an earlier version of
 * this file didn't have HPACK decoding; see dpi_hpack_decoder.c's own
 * header comment for the verification methodology behind it), but
 * still real:
 * -------------------------------------------------------------------
 *   - The HPACK dynamic table used per HEADERS frame is FRESH PER
 *     CALL, not persisted across a connection's multiple HEADERS
 *     frames. Static-table references and same-frame
 *     literal-with-indexing entries decode correctly; a reference to
 *     an entry created by an EARLIER frame on the same connection
 *     can't be resolved here and is flagged
 *     (http2_hpack_dynamic_table_miss) rather than guessed at. Real
 *     HTTP/2 traffic relies heavily on cross-frame dynamic table
 *     references, so this decodes a meaningful fraction of traffic
 *     correctly, not all of it.
 *   - CONTINUATION frames (a header block split across multiple
 *     HTTP/2 frames) are detected but not reassembled — flagged via
 *     http2_headers_continued_not_reassembled.
 *
 * Frame-level metadata (frame type distribution, stream count, frame
 * sizes, RST_STREAM ratio for Rapid-Reset-style abuse detection)
 * remains useful independent of header content, same as before.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

/* Provides: hpack_decode_header_block(), hpack_decode_header_block_fresh(),
 * hpack_header_callback typedef, struct hpack_dynamic_table. */
#include "dpi_hpack_decoder.c"

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

/*
 * Capture context for the handful of most valuable decoded headers —
 * the HTTP/2 pseudo-headers that carry request identity, mirroring
 * what http1_dissect() extracts for HTTP/1.1. Not a general header
 * map, matching the "extract what's actually useful" pattern used by
 * the other text-based dissectors in this project.
 */
struct http2_header_capture {
    char authority[256];
    char method[16];
    char path[512];
    char status[8];
    bool found_authority, found_method, found_path, found_status;
    int total_headers_seen;
};

static void http2_header_callback(const char *name, const char *value, void *user_ctx) {
    struct http2_header_capture *ctx = (struct http2_header_capture *)user_ctx;
    ctx->total_headers_seen++;

    if (strcmp(name, ":authority") == 0) {
        strncpy(ctx->authority, value, sizeof(ctx->authority) - 1);
        ctx->found_authority = true;
    } else if (strcmp(name, ":method") == 0) {
        strncpy(ctx->method, value, sizeof(ctx->method) - 1);
        ctx->found_method = true;
    } else if (strcmp(name, ":path") == 0) {
        strncpy(ctx->path, value, sizeof(ctx->path) - 1);
        ctx->found_path = true;
    } else if (strcmp(name, ":status") == 0) {
        strncpy(ctx->status, value, sizeof(ctx->status) - 1);
        ctx->found_status = true;
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

/*
 * Decode one (possibly CONTINUATION-reassembled) header block and
 * extract the captured pseudo-headers into `out`. Shared by both
 * entry points below — the only difference between them is whether
 * `dyn` is a fresh, call-scoped table or a persistent, connection-
 * scoped one.
 */
static void http2_process_header_block(const uint8_t *header_block, size_t header_block_len,
                                        struct hpack_dynamic_table *dyn,
                                        struct dissect_result *out) {
    struct http2_header_capture ctx;
    memset(&ctx, 0, sizeof(ctx));
    bool dyn_miss = false;

    bool decode_ok;
    if (dyn) {
        decode_ok = hpack_decode_header_block(header_block, header_block_len, dyn,
                                               http2_header_callback, &ctx, &dyn_miss);
    } else {
        /* 4096 is HTTP/2's default SETTINGS_HEADER_TABLE_SIZE (RFC 9113
         * S6.5.2) — used as the fresh table's max size since this path
         * has no persisted SETTINGS negotiation to draw from either. */
        decode_ok = hpack_decode_header_block_fresh(header_block, header_block_len, 4096,
                                                     http2_header_callback, &ctx, &dyn_miss);
    }

    if (ctx.found_authority) dissect_result_add(out, "http2_authority", ctx.authority);
    if (ctx.found_method) dissect_result_add(out, "http2_method", ctx.method);
    if (ctx.found_path) dissect_result_add(out, "http2_path", ctx.path);
    if (ctx.found_status) dissect_result_add(out, "http2_status", ctx.status);

    if (dyn_miss) {
        dissect_result_add(out, "http2_hpack_dynamic_table_miss", "true");
    } else if (!decode_ok) {
        dissect_result_add(out, "http2_hpack_decode_error", "true");
    }
}

/*
 * Shared core, parameterized by an OPTIONAL persistent dynamic table:
 *   - persistent_dyn == NULL: fresh per-HEADERS-frame table (the
 *     original, more limited behavior) — used by the registry-facing
 *     http2_dissect() below, which has no flow identity to key state
 *     on.
 *   - persistent_dyn != NULL: the SAME table is reused across calls
 *     for the same connection — used by http2_dissect_with_flow_state(),
 *     called directly from the TCP capture path where real flow
 *     identity (and therefore persistent per-flow state, the same way
 *     dpi_tcp_flow_reassembly.c persists TCP state) is available.
 */
static void http2_dissect_core(const uint8_t *payload, uint16_t len,
                                struct hpack_dynamic_table *persistent_dyn,
                                struct dissect_result *out) {
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
     * rather than parsed — except HEADERS/CONTINUATION field blocks,
     * which are now HPACK-decoded (see the shared helper below). */
    int frames_parsed = 0;
    int headers_frame_count = 0;
    int rst_stream_count = 0;
    int max_stream_id_seen = 0;

    while (pos + HTTP2_FRAME_HDR_LEN <= len && frames_parsed < 64) {
        uint32_t frame_len = (payload[pos]<<16)|(payload[pos+1]<<8)|payload[pos+2];
        uint8_t frame_type = payload[pos+3];
        uint8_t frame_flags = payload[pos+4];
        uint32_t stream_id = ((payload[pos+5]<<24)|(payload[pos+6]<<16)|
                               (payload[pos+7]<<8)|payload[pos+8]) & 0x7FFFFFFF;

        if (pos + HTTP2_FRAME_HDR_LEN + frame_len > len) {
            /* Frame body not fully in this buffer — normal for a
             * large DATA frame split across TCP segments; stop here
             * rather than guess at partial content. */
            dissect_result_add(out, "http2_truncated_frame", "true");
            break;
        }

        if (frame_type == 0x1 /* HEADERS */) {
            headers_frame_count++;

            /* HEADERS frame payload layout, RFC 9113 S6.2:
             *   [Pad Length (1)]     if PADDED flag (0x08) set
             *   [E(1)+Stream Dep(31)+Weight(8)]  if PRIORITY flag (0x20) set
             *   Field Block Fragment
             *   [Padding]            if PADDED flag set
             */
            bool padded = (frame_flags & 0x08) != 0;
            bool has_priority = (frame_flags & 0x20) != 0;
            bool end_headers = (frame_flags & 0x04) != 0;

            const uint8_t *frame_payload = payload + pos + HTTP2_FRAME_HDR_LEN;
            size_t fp = 0;
            uint8_t pad_length = 0;
            bool header_frame_malformed = false;

            if (padded) {
                if (fp >= frame_len) header_frame_malformed = true;
                else { pad_length = frame_payload[fp]; fp += 1; }
            }
            if (!header_frame_malformed && has_priority) {
                if (fp + 5 > frame_len) header_frame_malformed = true;
                else fp += 5;
            }

            if (!header_frame_malformed && fp + pad_length <= frame_len) {
                size_t header_block_len = frame_len - fp - pad_length;
                const uint8_t *header_block = frame_payload + fp;
                size_t consumed_through = pos + HTTP2_FRAME_HDR_LEN + frame_len;

                /* Accumulation buffer for HEADERS + CONTINUATION field
                 * blocks. Stack-allocated, NOT static — a static buffer
                 * here would be the exact same concurrency bug caught
                 * and fixed for dpi_quic_parser.c's decryption buffer
                 * earlier in this project: this function is called
                 * concurrently from multiple lcores in the DPDK worker.
                 * 16KB comfortably covers real-world header blocks
                 * without needing dynamic allocation. */
                uint8_t combined_block[16384];
                size_t combined_len = 0;

                if (header_block_len > sizeof(combined_block)) {
                    dissect_result_add(out, "parse_warning", "headers_frame_too_large_for_reassembly_buffer");
                } else {
                    memcpy(combined_block, header_block, header_block_len);
                    combined_len = header_block_len;

                    /* Reassemble CONTINUATION frames (RFC 9113 S6.10) that
                     * follow IMMEDIATELY in this same buffer, sharing the
                     * same stream_id, until one has END_HEADERS set. This
                     * covers the common case (HEADERS+CONTINUATION sent
                     * back-to-back in one write) — a CONTINUATION frame
                     * split across a TCP reassembly boundary into a
                     * SEPARATE dissect() call is NOT covered, since this
                     * dissector has no state persisting between calls
                     * for that (same category of limitation as the
                     * HPACK dynamic table needing connection state —
                     * see this file's header comment). */
                    size_t scan_pos = consumed_through;
                    bool reassembly_failed = false;

                    while (!end_headers && !reassembly_failed) {
                        if (scan_pos + HTTP2_FRAME_HDR_LEN > len) {
                            dissect_result_add(out, "http2_continuation_incomplete_in_buffer", "true");
                            reassembly_failed = true;
                            break;
                        }
                        uint32_t cont_len = (payload[scan_pos]<<16)|(payload[scan_pos+1]<<8)|payload[scan_pos+2];
                        uint8_t cont_type = payload[scan_pos+3];
                        uint8_t cont_flags = payload[scan_pos+4];
                        uint32_t cont_stream = ((payload[scan_pos+5]<<24)|(payload[scan_pos+6]<<16)|
                                                 (payload[scan_pos+7]<<8)|payload[scan_pos+8]) & 0x7FFFFFFF;

                        if (cont_type != 0x9 /* CONTINUATION */ || cont_stream != stream_id) {
                            /* RFC 9113 S6.10: a CONTINUATION frame MUST be
                             * preceded by a HEADERS/PUSH_PROMISE/CONTINUATION
                             * frame without END_HEADERS on the SAME stream.
                             * Anything else here is a protocol violation from
                             * this dissector's perspective — stop, don't guess. */
                            dissect_result_add(out, "parse_warning", "expected_continuation_frame_not_found");
                            reassembly_failed = true;
                            break;
                        }
                        if (scan_pos + HTTP2_FRAME_HDR_LEN + cont_len > len) {
                            dissect_result_add(out, "http2_continuation_incomplete_in_buffer", "true");
                            reassembly_failed = true;
                            break;
                        }
                        if (combined_len + cont_len > sizeof(combined_block)) {
                            dissect_result_add(out, "parse_warning", "continuation_reassembly_buffer_exceeded");
                            reassembly_failed = true;
                            break;
                        }

                        memcpy(combined_block + combined_len,
                               payload + scan_pos + HTTP2_FRAME_HDR_LEN, cont_len);
                        combined_len += cont_len;
                        scan_pos += HTTP2_FRAME_HDR_LEN + cont_len;
                        end_headers = (cont_flags & 0x04) != 0;
                    }

                    if (end_headers && !reassembly_failed) {
                        if (scan_pos != consumed_through) {
                            dissect_result_add(out, "http2_continuation_reassembled", "true");
                        }
                        http2_process_header_block(combined_block, combined_len,
                                                    persistent_dyn, out);
                        /* Advance the OUTER loop past every CONTINUATION
                         * frame we just consumed, so it doesn't re-walk
                         * them as if they were independent frames. */
                        consumed_through = scan_pos;
                    }
                }

                pos = consumed_through;
                frames_parsed++;
                if ((int)stream_id > max_stream_id_seen) max_stream_id_seen = (int)stream_id;
                continue;   /* pos already advanced past HEADERS+CONTINUATION(s) above */
            } else {
                dissect_result_add(out, "parse_warning", "malformed_headers_frame_padding");
            }
        }
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

/*
 * Registry-facing entry point — matches the dissector_dissect_fn
 * signature exactly, so this is what register_http2_dissector() below
 * wires in. Has no flow identity available (the registry interface
 * doesn't pass one), so it uses a fresh HPACK dynamic table per call —
 * the original, more limited behavior. Fine for the UDP dispatch path
 * and for standalone/fuzzing use; the TCP capture path should prefer
 * http2_dissect_with_flow_state() below when it has real flow context.
 */
static void http2_dissect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto,
                           struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    http2_dissect_core(payload, len, NULL, out);
}

/*
 * Capture-path-facing entry point — called DIRECTLY (not through
 * dispatch_dissection()/the registry) from the TCP path once it has a
 * real per-flow HPACK dynamic table to persist across calls for the
 * same connection. See dpi_hpack_connection_state.c for how that table
 * is looked up/created/evicted, keyed by the same tcp_flow_key
 * dpi_tcp_flow_reassembly.c uses.
 */
static void http2_dissect_with_flow_state(const uint8_t *payload, uint16_t len,
                                           struct hpack_dynamic_table *persistent_dyn,
                                           struct dissect_result *out) {
    http2_dissect_core(payload, len, persistent_dyn, out);
}

static const uint16_t http2_hint_ports[] = { HTTP2_PORT };

void register_http2_dissector(void) {
    register_dissector("HTTP/2", http2_detect, http2_dissect, http2_hint_ports, 1);
}
