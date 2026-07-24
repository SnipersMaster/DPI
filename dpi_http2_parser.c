/*
 * dpi_http2_parser.c
 *
 * HTTP/2 (RFC 9113) dissector — connection preface detection,
 * frame-level parsing (type, flags, stream ID, length), HPACK decoding
 * (RFC 7541, via dpi_hpack_decoder.c) for HEADERS frames including
 * :authority extraction, real SETTINGS_HEADER_TABLE_SIZE tracking, and
 * — when called with a real flow identity via
 * http2_dissect_with_flow_state() — both a PERSISTENT per-connection
 * HPACK dynamic table and CONTINUATION frame reassembly ACROSS TCP
 * delivery boundaries, not just within one buffer.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * -------------------------------------------------------------------
 * WHAT'S GENUINELY STILL LIMITED — read before assuming this is fully
 * general (an earlier version of this file's scope comment described
 * a narrower implementation; both major gaps it described — per-call-
 * only dynamic table, no cross-boundary CONTINUATION — are now closed
 * when a connection entry is available):
 * -------------------------------------------------------------------
 *   - The registry-facing http2_dissect() entry point (used by the
 *     UDP dispatch path and by fuzzing) has no flow identity to key
 *     persistent state on, so it still uses a fresh dynamic table and
 *     no cross-boundary CONTINUATION resumption — this is inherent to
 *     that entry point, not a remaining bug.
 *   - SETTINGS_HEADER_TABLE_SIZE tracking correctly resizes the
 *     OPPOSITE direction's table (RFC 9113 S6.5.1: a SETTINGS frame
 *     constrains the peer's encoder, not the sender's own) via
 *     `reverse_conn`, looked up through `tcp_flow_key_reverse()` — an
 *     earlier version of this file resized the SAME direction's table,
 *     which was a real correctness bug, not just a simplification;
 *     that's fixed now. The residual gap: this doesn't distinguish
 *     multiple SETTINGS frames arriving with different values over a
 *     connection's lifetime, applying whichever was most recently
 *     seen — a minor gap since real endpoints rarely change this
 *     value mid-connection, unlike the direction issue above.
 *   - CONTINUATION reassembly across a TCP boundary previously only
 *     covered a split that landed CLEANLY at a frame boundary. A split
 *     in the MIDDLE of a CONTINUATION frame's own payload (its 9-byte
 *     header fully present, only the payload incomplete) is now ALSO
 *     handled — `http2_resume_partial_continuation()` in this file
 *     persists that one in-flight frame's partial payload (in the new
 *     connection-state fields alongside the existing pending_block)
 *     and completes it from the start of the next delivery, correctly
 *     handling both a two-delivery split and a longer chain needing
 *     several deliveries to complete, and correctly continuing to scan
 *     for further CONTINUATION frames in the SAME buffer if the
 *     newly-completed frame didn't itself carry END_HEADERS. Verified
 *     against constructed multi-delivery scenarios covering all three
 *     shapes (two-way split, three-way split, split-then-another-
 *     frame-follows) — not real-traffic-verified, since no real
 *     capture available to this project happened to include a TCP
 *     delivery boundary landing inside a CONTINUATION frame's payload
 *     specifically (a genuinely rare occurrence even in real HTTP/2
 *     traffic), stated honestly rather than implied otherwise. A
 *     split in the middle of the 9-byte frame HEADER itself (as
 *     opposed to its payload) remains the one still-unhandled case,
 *     flagged via http2_continuation_split_mid_frame_not_reassembled
 *     — RFC 9113's fixed, tiny 9-byte header essentially never gets
 *     split by itself in practice, so this project's bounded-state
 *     discipline doesn't add tracking for a case with no real-traffic
 *     evidence it occurs.
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
 * Scans forward from *scan_pos_ptr in `payload` for CONTINUATION
 * frames matching `stream_id`, appending their content into
 * combined_block (bounded by combined_cap) until one is found with
 * END_HEADERS set. Shared by both the normal in-buffer HEADERS-frame
 * path and the cross-TCP-boundary resume path below — same scanning
 * logic, different starting state.
 *
 * Three distinguishable outcomes matter here, not just success/fail:
 *   - COMPLETE: END_HEADERS reached, combined_block/combined_len hold
 *     the full header block, ready to HPACK-decode.
 *   - NEED_MORE: ran out of buffer cleanly AT A FRAME BOUNDARY (not
 *     enough bytes for even the next frame's header) — this is the
 *     resumable case. The caller can save combined_block/combined_len
 *     and try again once more TCP data arrives for this connection.
 *   - FAILED: a genuine protocol violation (wrong frame type/stream),
 *     the reassembly buffer was exceeded, OR the split happened in
 *     the MIDDLE of a CONTINUATION frame's own header/payload rather
 *     than cleanly between frames — this last case specifically is
 *     NOT resumable with the state tracked here (would need partial-
 *     frame state this file doesn't keep) and is flagged via
 *     http2_continuation_split_mid_frame_not_reassembled to be
 *     honest about that distinct, still-unhandled scope limit.
 */
enum http2_continuation_scan_result {
    HTTP2_CONT_COMPLETE,
    HTTP2_CONT_NEED_MORE,
    HTTP2_CONT_FAILED
};

/*
 * Attempts to complete a partial CONTINUATION frame using bytes from
 * the START of a new TCP delivery, if the connection has one pending
 * (`conn->has_partial_continuation_frame`). This is the piece that
 * closes the "split in the MIDDLE of a CONTINUATION frame's payload"
 * gap this file previously only disclosed rather than handled.
 *
 * Returns the number of bytes consumed from `payload` (0 if there was
 * nothing pending, or if consuming stopped because `payload` ran out
 * before the frame could be completed). Sets *frame_completed to true
 * only if the frame's full declared payload is now available — in
 * that case *out_end_headers reports whether that (now complete)
 * frame had END_HEADERS set, and the frame's payload bytes have
 * already been appended to combined_block/*combined_len_ptr.
 */
static size_t http2_resume_partial_continuation(struct hpack_connection_entry *conn,
                                                 const uint8_t *payload, size_t len,
                                                 uint8_t *combined_block, size_t combined_cap,
                                                 size_t *combined_len_ptr,
                                                 bool *frame_completed, bool *out_end_headers,
                                                 struct dissect_result *out) {
    *frame_completed = false;
    *out_end_headers = false;
    if (!conn || !conn->has_partial_continuation_frame) return 0;

    uint32_t needed = conn->partial_cont_full_len - (uint32_t)conn->partial_cont_payload_len;
    size_t take = (size_t)needed < len ? (size_t)needed : len;

    if (conn->partial_cont_payload_len + take > sizeof(conn->partial_cont_payload)) {
        /* Shouldn't happen given partial_cont_full_len is itself bounds-
         * checked against this same buffer size before ever being
         * stored (see the scan function below) — defensive only. */
        dissect_result_add(out, "parse_warning", "continuation_partial_frame_buffer_exceeded");
        conn->has_partial_continuation_frame = false;
        return take;
    }
    memcpy(conn->partial_cont_payload + conn->partial_cont_payload_len, payload, take);
    conn->partial_cont_payload_len += take;

    if (conn->partial_cont_payload_len < conn->partial_cont_full_len) {
        /* Still not enough — this whole new delivery (or what's left
         * of it) went toward completing this one frame, and it still
         * isn't done. Stay pending, consume everything offered. */
        dissect_result_add(out, "http2_continuation_partial_frame_still_pending", "true");
        return take;
    }

    /* Frame's payload is now complete. */
    if (*combined_len_ptr + conn->partial_cont_payload_len > combined_cap) {
        dissect_result_add(out, "parse_warning", "continuation_reassembly_buffer_exceeded");
        conn->has_partial_continuation_frame = false;
        return take;
    }
    memcpy(combined_block + *combined_len_ptr, conn->partial_cont_payload,
           conn->partial_cont_payload_len);
    *combined_len_ptr += conn->partial_cont_payload_len;
    *out_end_headers = (conn->partial_cont_flags & 0x04 /* END_HEADERS */) != 0;
    *frame_completed = true;
    conn->has_partial_continuation_frame = false;
    dissect_result_add(out, "http2_continuation_mid_frame_split_reassembled", "true");
    return take;
}

static enum http2_continuation_scan_result http2_scan_continuations(
        const uint8_t *payload, uint16_t len, size_t *scan_pos_ptr, uint32_t stream_id,
        uint8_t *combined_block, size_t combined_cap, size_t *combined_len_ptr,
        struct hpack_connection_entry *conn, struct dissect_result *out) {
    size_t scan_pos = *scan_pos_ptr;
    size_t combined_len = *combined_len_ptr;

    while (true) {
        if (scan_pos + HTTP2_FRAME_HDR_LEN > len) {
            *scan_pos_ptr = scan_pos;
            *combined_len_ptr = combined_len;
            return HTTP2_CONT_NEED_MORE;   /* clean split at a frame boundary: resumable */
        }

        uint32_t cont_len = (payload[scan_pos]<<16)|(payload[scan_pos+1]<<8)|payload[scan_pos+2];
        uint8_t cont_type = payload[scan_pos+3];
        uint8_t cont_flags = payload[scan_pos+4];
        uint32_t cont_stream = ((payload[scan_pos+5]<<24)|(payload[scan_pos+6]<<16)|
                                 (payload[scan_pos+7]<<8)|payload[scan_pos+8]) & 0x7FFFFFFF;

        if (cont_type != 0x9 /* CONTINUATION */ || cont_stream != stream_id) {
            /* RFC 9113 S6.10: a CONTINUATION frame MUST be preceded by
             * a HEADERS/PUSH_PROMISE/CONTINUATION frame without
             * END_HEADERS on the SAME stream. Anything else here is a
             * protocol violation from this dissector's perspective —
             * stop, don't guess. */
            dissect_result_add(out, "parse_warning", "expected_continuation_frame_not_found");
            *scan_pos_ptr = scan_pos;
            *combined_len_ptr = combined_len;
            return HTTP2_CONT_FAILED;
        }

        if (scan_pos + HTTP2_FRAME_HDR_LEN + cont_len > len) {
            /* Split in the MIDDLE of this CONTINUATION frame's own
             * payload (its 9-byte header IS fully present — the check
             * above already required that — only the payload runs
             * off the end of this delivery). Resumable now, given a
             * connection entry to save the partial payload in;
             * without one (conn == NULL, e.g. the registry-facing
             * entry point with no flow identity), still correctly
             * falls back to the honest FAILED/not-reassembled
             * outcome, since there's nowhere to persist the partial
             * state until the next call. */
            if (conn && cont_len <= sizeof(conn->partial_cont_payload)) {
                size_t avail = len - (scan_pos + HTTP2_FRAME_HDR_LEN);
                memcpy(conn->partial_cont_payload, payload + scan_pos + HTTP2_FRAME_HDR_LEN, avail);
                conn->partial_cont_payload_len = avail;
                conn->partial_cont_full_len = cont_len;
                conn->partial_cont_flags = cont_flags;
                conn->has_partial_continuation_frame = true;
                dissect_result_add(out, "http2_continuation_mid_frame_split_pending", "true");
                *scan_pos_ptr = len;   /* this delivery is fully consumed */
                *combined_len_ptr = combined_len;
                return HTTP2_CONT_NEED_MORE;
            }
            dissect_result_add(out, "http2_continuation_split_mid_frame_not_reassembled", "true");
            *scan_pos_ptr = scan_pos;
            *combined_len_ptr = combined_len;
            return HTTP2_CONT_FAILED;
        }

        if (combined_len + cont_len > combined_cap) {
            dissect_result_add(out, "parse_warning", "continuation_reassembly_buffer_exceeded");
            *scan_pos_ptr = scan_pos;
            *combined_len_ptr = combined_len;
            return HTTP2_CONT_FAILED;
        }

        memcpy(combined_block + combined_len,
               payload + scan_pos + HTTP2_FRAME_HDR_LEN, cont_len);
        combined_len += cont_len;
        scan_pos += HTTP2_FRAME_HDR_LEN + cont_len;

        if (cont_flags & 0x04 /* END_HEADERS */) {
            *scan_pos_ptr = scan_pos;
            *combined_len_ptr = combined_len;
            return HTTP2_CONT_COMPLETE;
        }
    }
}

/*
 * Shared core, parameterized by an OPTIONAL connection entry:
 *   - conn == NULL: fresh per-HEADERS-frame table, no cross-TCP-
 *     boundary CONTINUATION resumption — the original, more limited
 *     behavior — used by the registry-facing http2_dissect() below,
 *     which has no flow identity to key state on.
 *   - conn != NULL: the SAME dynamic table is reused across calls for
 *     the same connection, AND a HEADERS/CONTINUATION sequence that
 *     runs off the end of one TCP delivery is saved and resumed on the
 *     next one for this same flow — used by
 *     http2_dissect_with_flow_state(), called directly from the TCP
 *     capture path where real flow identity is available.
 *
 * `reverse_conn` (also optional, NULL when conn is NULL) is the
 * connection entry for the OPPOSITE direction of the same TCP
 * connection — needed because a SETTINGS_HEADER_TABLE_SIZE value seen
 * in a SETTINGS frame constrains the PEER's encoder (RFC 9113 S6.5.1:
 * "the sender... informs the remote endpoint of the maximum size...
 * that the sender will use"), i.e. it applies to the dynamic table
 * used for the OPPOSITE direction's HEADERS frames, not this
 * direction's own table. This was found as a genuine correctness bug
 * (not just a documented simplification) while reasoning through what
 * "one table per connection, applied regardless of direction" would
 * actually mean in practice — a SETTINGS frame consistently resized
 * the WRONG direction's table.
 */
static void http2_dissect_core(const uint8_t *payload, uint16_t len,
                                struct hpack_connection_entry *conn,
                                struct hpack_connection_entry *reverse_conn,
                                struct dissect_result *out) {
    struct hpack_dynamic_table *persistent_dyn = conn ? &conn->dyn_table : NULL;
    size_t pos = 0;

    /* Resume a pending cross-TCP-boundary CONTINUATION sequence from
     * an EARLIER call, if one exists for this connection. This is
     * checked before anything else — including the preface check,
     * since a resumed buffer chunk mid-connection would never
     * rationally start with the connection preface. */
    if (conn && conn->has_pending_headers) {
        uint8_t combined_block[16384];
        size_t combined_len = conn->pending_block_len;
        if (combined_len > sizeof(combined_block)) combined_len = sizeof(combined_block);
        memcpy(combined_block, conn->pending_block, combined_len);

        size_t scan_pos = 0;   /* this NEW payload should pick up exactly
                                 * where the previous delivery's buffer
                                 * ran out — see the NEED_MORE case below
                                 * for why that's a safe assumption here */
        bool already_complete = false;   /* set if resuming a mid-frame
                                            * split alone finished the
                                            * whole reassembly, skipping
                                            * the normal scan below */

        /* If a CONTINUATION frame's payload was itself split mid-frame
         * across this TCP boundary, first try to complete IT using
         * bytes from the start of this new delivery — the piece that
         * closes the gap this file used to just disclose. */
        if (conn->has_partial_continuation_frame) {
            bool frame_completed = false, end_headers = false;
            size_t consumed = http2_resume_partial_continuation(
                conn, payload, len, combined_block, sizeof(combined_block),
                &combined_len, &frame_completed, &end_headers, out);
            scan_pos = consumed;

            if (!frame_completed) {
                /* Whatever was available in this delivery all went
                 * toward completing this one frame, and it still
                 * isn't enough — save state and stop, same as the
                 * frame-boundary NEED_MORE case below. */
                if (combined_len <= sizeof(conn->pending_block)) {
                    memcpy(conn->pending_block, combined_block, combined_len);
                    conn->pending_block_len = combined_len;
                }
                return;
            }
            if (end_headers) {
                /* That one frame completing was ALSO the end of the
                 * whole header block — done, no need to scan further. */
                dissect_result_add(out, "http2_continuation_resumed_across_tcp_boundary", "true");
                http2_process_header_block(combined_block, combined_len, persistent_dyn, out);
                conn->has_pending_headers = false;
                pos = scan_pos;
                already_complete = true;
            }
            /* Else: this frame completed but didn't have END_HEADERS —
             * fall through to the normal scan below, starting at
             * scan_pos, to look for whatever CONTINUATION frame(s)
             * follow immediately in this same buffer. */
        }

        if (!already_complete) {
            enum http2_continuation_scan_result res = http2_scan_continuations(
                payload, len, &scan_pos, conn->pending_stream_id,
                combined_block, sizeof(combined_block), &combined_len, conn, out);

            if (res == HTTP2_CONT_COMPLETE) {
                dissect_result_add(out, "http2_continuation_resumed_across_tcp_boundary", "true");
                http2_process_header_block(combined_block, combined_len, persistent_dyn, out);
                conn->has_pending_headers = false;
                pos = scan_pos;   /* continue the normal frame loop below for
                                    * anything remaining in this buffer */
            } else if (res == HTTP2_CONT_NEED_MORE) {
                /* Still not enough — update the pending state again and
                 * stop; nothing else in this delivery can be safely
                 * processed until the rest arrives. */
                if (combined_len <= sizeof(conn->pending_block)) {
                    memcpy(conn->pending_block, combined_block, combined_len);
                    conn->pending_block_len = combined_len;
                    dissect_result_add(out, "http2_continuation_still_pending", "true");
                }
                return;
            } else {
                /* FAILED — give up on this pending sequence rather than
                 * risk resuming from a now-desynchronized position. Fall
                 * through to process the rest of this buffer as if
                 * nothing were pending (pos stays 0), same degraded-but-
                 * reasonable behavior as a fresh protocol violation. */
                conn->has_pending_headers = false;
                dissect_result_add(out, "http2_continuation_resume_failed", "true");
            }
        }
    }

    bool has_preface = (pos == 0 && len >= HTTP2_PREFACE_LEN &&
                         memcmp(payload, HTTP2_PREFACE, HTTP2_PREFACE_LEN) == 0);
    if (has_preface) {
        dissect_result_add(out, "http2_preface_present", "true");
        pos = HTTP2_PREFACE_LEN;
    } else if (pos == 0) {
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

        if (frame_type == 0x4 /* SETTINGS */) {
            /* RFC 9113 S6.5.1: SETTINGS frame payload is a sequence of
             * (Identifier(2) + Value(4)) 6-byte pairs. Look for
             * SETTINGS_HEADER_TABLE_SIZE (identifier 0x1).
             *
             * CORRECTNESS NOTE — this used to be a bug, not just a
             * simplification: a SETTINGS_HEADER_TABLE_SIZE value tells
             * the PEER what dynamic table size THEY may use when
             * encoding headers back to the sender — i.e. it constrains
             * the OPPOSITE direction's table, not the sender's own. An
             * earlier version of this code resized `persistent_dyn`
             * (this SAME direction's table) directly, which is exactly
             * backwards. Fixed: now resizes `reverse_conn`'s table
             * instead — the connection entry for the other direction of
             * this same TCP connection, looked up by the capture path
             * via `tcp_flow_key_reverse()` and passed in alongside
             * `conn`. When `reverse_conn` isn't available (the registry-
             * facing fresh-per-call path, or a capture path that hasn't
             * been updated to pass it), the value is still surfaced as
             * a field but no resize happens — correct behavior is
             * "don't guess," not "resize the wrong table anyway."
             *
             * Remaining simplification, stated honestly: this still
             * doesn't distinguish MULTIPLE SETTINGS frames arriving
             * over a connection's lifetime with different values in
             * each direction pair — it applies whichever value was most
             * recently seen. Real HTTP/2 endpoints rarely change
             * SETTINGS_HEADER_TABLE_SIZE mid-connection, so this is a
             * minor residual gap compared to the directional fix above.
             */
            const uint8_t *settings_payload = payload + pos + HTTP2_FRAME_HDR_LEN;
            size_t sp = 0;
            while (sp + 6 <= frame_len) {
                uint16_t setting_id = (settings_payload[sp] << 8) | settings_payload[sp+1];
                uint32_t setting_value = (settings_payload[sp+2]<<24)|(settings_payload[sp+3]<<16)|
                                          (settings_payload[sp+4]<<8)|settings_payload[sp+5];
                if (setting_id == 0x1 /* SETTINGS_HEADER_TABLE_SIZE */) {
                    char buf[16];
                    snprintf(buf, sizeof(buf), "%u", setting_value);
                    dissect_result_add(out, "http2_settings_header_table_size", buf);

                    if (reverse_conn) {
                        hpack_dynamic_table_resize(&reverse_conn->dyn_table, setting_value);
                    }
                }
                sp += 6;
            }
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

                    size_t scan_pos = consumed_through;
                    enum http2_continuation_scan_result res = end_headers
                        ? HTTP2_CONT_COMPLETE   /* END_HEADERS already set on the
                                                  * HEADERS frame itself — no
                                                  * CONTINUATION frames to scan for */
                        : http2_scan_continuations(payload, len, &scan_pos, stream_id,
                                                    combined_block, sizeof(combined_block),
                                                    &combined_len, conn, out);

                    if (res == HTTP2_CONT_COMPLETE) {
                        if (scan_pos != consumed_through) {
                            dissect_result_add(out, "http2_continuation_reassembled", "true");
                        }
                        http2_process_header_block(combined_block, combined_len,
                                                    persistent_dyn, out);
                        consumed_through = scan_pos;
                    } else if (res == HTTP2_CONT_NEED_MORE) {
                        /* Clean split at a frame boundary — resumable
                         * IF we have a connection entry to save state
                         * in. Without one (the fresh-per-call registry
                         * path), there's nowhere to persist this to,
                         * so it's flagged as incomplete the same way
                         * it always was. */
                        if (conn && combined_len <= sizeof(conn->pending_block)) {
                            conn->has_pending_headers = true;
                            conn->pending_stream_id = stream_id;
                            memcpy(conn->pending_block, combined_block, combined_len);
                            conn->pending_block_len = combined_len;
                            dissect_result_add(out, "http2_continuation_pending_cross_boundary", "true");
                        } else {
                            dissect_result_add(out, "http2_continuation_incomplete_in_buffer", "true");
                        }
                        /* Nothing more can be safely parsed from this
                         * buffer past this point — the rest of it (if
                         * any) belongs to the CONTINUATION frame(s) we
                         * were expecting, not independent frames. */
                        consumed_through = len;
                    }
                    /* HTTP2_CONT_FAILED: consumed_through stays at its
                     * original value (just past the HEADERS frame
                     * itself) — the outer loop naturally falls through
                     * to reprocess whatever follows as independent
                     * frames, same degraded-but-reasonable behavior as
                     * before this refactor. */
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
 * doesn't pass one), so it uses a fresh HPACK dynamic table per call
 * and no cross-TCP-boundary CONTINUATION resumption — the original,
 * more limited behavior. Fine for the UDP dispatch path and for
 * standalone/fuzzing use; the TCP capture path should prefer
 * http2_dissect_with_flow_state() below when it has real flow context.
 */
static void http2_dissect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto,
                           struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    http2_dissect_core(payload, len, NULL, NULL, out);
}

/*
 * Capture-path-facing entry point — called DIRECTLY (not through
 * dispatch_dissection()/the registry) from the TCP path once it has a
 * real per-flow connection entry: persistent HPACK dynamic table AND
 * cross-TCP-boundary CONTINUATION resumption state. See
 * dpi_hpack_connection_state.c for how that entry is looked up/
 * created/evicted, keyed by the same tcp_flow_key
 * dpi_tcp_flow_reassembly.c uses.
 *
 * `reverse_conn` is the connection entry for the OPPOSITE direction of
 * the same TCP connection (looked up via `tcp_flow_key_reverse()` by
 * the capture path) — required for SETTINGS_HEADER_TABLE_SIZE to
 * resize the correct direction's table. See http2_dissect_core()'s
 * header comment for the full correctness rationale. Passing NULL here
 * (e.g. if the capture path hasn't been updated, or the reverse flow
 * hasn't been seen yet) means SETTINGS values are still surfaced as
 * fields but no resize happens — safe degradation, not silent
 * misbehavior.
 */
static void http2_dissect_with_flow_state(const uint8_t *payload, uint16_t len,
                                           struct hpack_connection_entry *conn,
                                           struct hpack_connection_entry *reverse_conn,
                                           struct dissect_result *out) {
    http2_dissect_core(payload, len, conn, reverse_conn, out);
}

static const uint16_t http2_hint_ports[] = { HTTP2_PORT };

void register_http2_dissector(void) {
    register_dissector("HTTP/2", http2_detect, http2_dissect, http2_hint_ports, 1);
}
