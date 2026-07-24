/*
 * dpi_hpack_connection_state.c
 *
 * Connection-level persistence for HPACK's dynamic table — the single
 * largest deliberately-deferred piece flagged when HPACK decoding was
 * first added. Without this, a cross-frame dynamic-table reference
 * (extremely common in real HTTP/2 traffic — that's the entire point
 * of HPACK's compression) couldn't be resolved. With it, the dynamic
 * table for a given TCP connection persists across every HEADERS
 * frame dissected on that connection, the same way
 * dpi_tcp_flow_reassembly.c persists TCP reassembly state per flow.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * -------------------------------------------------------------------
 * DESIGN — deliberately mirrors dpi_tcp_flow_reassembly.c's pattern
 * -------------------------------------------------------------------
 *   - Partitioned per-lcore (reusing TCP_REASSEMBLY_NUM_PARTITIONS),
 *     keyed by the SAME struct tcp_flow_key HTTP/2 already runs on top
 *     of (HTTP/2 is TCP-based) — RSS already guarantees a flow's
 *     packets land on one queue/core, so no locking is needed, same
 *     reasoning that made TCP flow reassembly's partitioning safe.
 *   - Timeout eviction, since HTTP/2 connections can be long-lived
 *     (much longer than typical TCP flows this engine otherwise
 *     tracks) — a longer timeout than TCP reassembly's is appropriate.
 *   - Bounded table size per partition, same "drop rather than grow
 *     unboundedly" discipline as everywhere else in this project.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

/* Provides: struct hpack_dynamic_table, hpack_dynamic_table_init().
 * Safe to include here regardless of what else has already included
 * it elsewhere in the same translation unit — dpi_hpack_decoder.c now
 * has an include guard specifically so this doesn't depend on a
 * fragile cross-file include ordering. */
#include "dpi_hpack_decoder.c"

#define HPACK_CONN_PER_PARTITION   32   /* fewer than TCP flows per partition —
                                           * HTTP/2 connections are typically
                                           * much longer-lived and more
                                           * numerous connections aren't
                                           * expected concurrently per core
                                           * at the same density as raw TCP
                                           * flows */
#define HPACK_CONN_TIMEOUT_SECONDS 300  /* HTTP/2 connections are often
                                           * long-lived (multiplexed,
                                           * kept alive) — much longer
                                           * than TCP_FLOW_TIMEOUT_SECONDS */
#define HPACK_PENDING_BLOCK_MAX    16384  /* matches dpi_http2_parser.c's
                                             * combined_block size — a
                                             * partial header block waiting
                                             * for its completing
                                             * CONTINUATION frame across a
                                             * TCP delivery boundary can't
                                             * exceed what a single
                                             * reassembly pass could ever
                                             * have accumulated anyway */

/* MEMORY FOOTPRINT of the pending-CONTINUATION addition specifically:
 * HPACK_PENDING_BLOCK_MAX (16384) + stream_id (4) + length (8) + flag (1)
 * ≈ 16.4 KB added per connection entry for the frame-boundary case,
 * PLUS another ~16.4 KB for the mid-frame-payload partial-CONTINUATION
 * state added alongside it (partial_cont_payload is the same
 * HPACK_PENDING_BLOCK_MAX size) — roughly 33 KB total per connection
 * entry for CONTINUATION reassembly state now. At
 * HPACK_CONN_PER_PARTITION=32 across TCP_REASSEMBLY_NUM_PARTITIONS=16
 * partitions, that's ~17 MB additional static memory for this feature
 * alone, on top of whatever the dynamic table itself already costs.
 * Worth knowing before treating this as a "small" addition — it isn't
 * free, even though it's bounded and predictable. */

struct hpack_connection_entry {
    bool     in_use;
    struct   tcp_flow_key key;
    struct   hpack_dynamic_table dyn_table;
    time_t   last_activity;

    /* Cross-TCP-boundary CONTINUATION reassembly state. When a HEADERS
     * (or CONTINUATION) frame's field block runs off the end of the
     * CURRENT TCP delivery without reaching one with END_HEADERS set,
     * the bytes accumulated so far are saved here instead of being
     * discarded — the NEXT delivery for this same flow resumes the
     * search rather than starting over or giving up. See
     * dpi_http2_parser.c's http2_dissect_core() for where this is
     * populated and consumed.
     *
     * SCOPE: this covers a split that lands cleanly AT a frame
     * boundary (not enough buffer for the next frame's header at
     * all) AND — now — a split in the MIDDLE of a CONTINUATION
     * frame's own payload (header fully present, payload isn't), via
     * the partial_cont_* fields below. A split in the middle of the
     * frame's own 9-byte HEADER (as opposed to its payload) is still
     * not tracked here — RFC 9113's fixed, tiny 9-byte frame header
     * essentially never gets split by itself in practice (a TCP
     * delivery boundary landing inside a 9-byte span while somehow
     * not also being able to include a few more bytes of payload
     * would require an almost pathologically small delivery), and
     * this project's existing bounded-state discipline doesn't add
     * tracking for a case with no real-traffic evidence it occurs —
     * still correctly falls through to
     * http2_continuation_split_mid_frame_not_reassembled in that
     * narrower remaining case, stated honestly rather than silently
     * assumed covered by the fix below. */
    bool     has_pending_headers;
    uint32_t pending_stream_id;
    uint8_t  pending_block[HPACK_PENDING_BLOCK_MAX];
    size_t   pending_block_len;

    /* Partial-CONTINUATION-frame state: the frame's 9-byte header has
     * been fully read (so its declared length and flags are known),
     * but the delivery ended before its payload was complete. Kept
     * separate from pending_block above, which only ever holds
     * COMPLETE frames' worth of already-extracted header-block bytes
     * — this holds the raw, still-incomplete payload of the ONE frame
     * currently in flight, if any. */
    bool     has_partial_continuation_frame;
    uint32_t partial_cont_full_len;      /* this frame's declared total payload length */
    uint8_t  partial_cont_flags;         /* this frame's flags (for END_HEADERS, once complete) */
    uint8_t  partial_cont_payload[HPACK_PENDING_BLOCK_MAX];
    size_t   partial_cont_payload_len;   /* how much of this frame's payload has arrived so far */
};

/* Reuses TCP_REASSEMBLY_NUM_PARTITIONS from dpi_tcp_flow_reassembly.c —
 * must be included before this file. Same partition count, same
 * reasoning: partition_id is the RX queue_id, and RSS guarantees a
 * given flow's packets land on one queue. */
static struct hpack_connection_entry
    g_hpack_conns[TCP_REASSEMBLY_NUM_PARTITIONS][HPACK_CONN_PER_PARTITION];

static bool tcp_flow_key_equal(const struct tcp_flow_key *a, const struct tcp_flow_key *b);
/* ^ Already defined in dpi_tcp_flow_reassembly.c, included before this
 * file — declared here only to make the dependency explicit at a
 * glance; the actual definition is used (same translation unit). */

/*
 * Full-entry accessor — used by http2_dissect_with_flow_state(), which
 * needs both the dynamic table AND the pending-CONTINUATION state, not
 * just the table alone. hpack_get_connection_table() below is now a
 * thin wrapper over this for callers that only need the table (kept
 * so existing call sites don't need to change).
 */
static struct hpack_connection_entry *hpack_get_connection_entry(uint16_t partition_id,
                                                                   const struct tcp_flow_key *key) {
    if (partition_id >= TCP_REASSEMBLY_NUM_PARTITIONS) return NULL;

    time_t now = time(NULL);
    struct hpack_connection_entry *free_slot = NULL;
    struct hpack_connection_entry *partition = g_hpack_conns[partition_id];

    for (int i = 0; i < HPACK_CONN_PER_PARTITION; i++) {
        struct hpack_connection_entry *e = &partition[i];

        if (e->in_use && (now - e->last_activity) > HPACK_CONN_TIMEOUT_SECONDS) {
            e->in_use = false;   /* idle past timeout: evict */
        }

        if (e->in_use && tcp_flow_key_equal(&e->key, key)) {
            e->last_activity = now;
            return e;
        }
        if (!e->in_use && !free_slot) free_slot = e;
    }

    if (!free_slot) return NULL;   /* table full even after evicting expired
                                     * entries: caller falls back to a fresh
                                     * per-call table rather than blocking */

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->in_use = true;
    free_slot->key = *key;
    free_slot->last_activity = now;
    /* 4096 = HTTP/2's default SETTINGS_HEADER_TABLE_SIZE (RFC 9113
     * S6.5.2) — now updated to the REAL negotiated value when a
     * SETTINGS frame carrying SETTINGS_HEADER_TABLE_SIZE is seen (see
     * dpi_http2_parser.c's SETTINGS handling), this is just the
     * starting default before any such frame has been observed. */
    hpack_dynamic_table_init(&free_slot->dyn_table, 4096);
    return free_slot;
}

/* Marked __attribute__((unused)): a convenience wrapper around
 * hpack_get_connection_entry() for callers that only need the
 * dynamic table, not the full connection entry — genuinely useful,
 * but no current caller in THIS project needs just the table alone
 * (dpi_http2_parser.c always wants the full entry, for the
 * CONTINUATION-reassembly fields too). Kept as public API surface
 * for a future caller rather than removed. */
static struct hpack_dynamic_table *hpack_get_connection_table(uint16_t partition_id,
                                                                const struct tcp_flow_key *key)
                                                                __attribute__((unused));
static struct hpack_dynamic_table *hpack_get_connection_table(uint16_t partition_id,
                                                                const struct tcp_flow_key *key) {
    struct hpack_connection_entry *e = hpack_get_connection_entry(partition_id, key);
    return e ? &e->dyn_table : NULL;
}

/*
 * Test/fuzzing-only helper, mirroring
 * tcp_reassembly_reset_partition_for_testing() — clears one
 * partition's HPACK connection state entirely. NOT for production use.
 * Marked __attribute__((unused)): called from fuzz harnesses, not
 * from every translation unit this file gets included into.
 */
static void hpack_conn_reset_partition_for_testing(uint16_t partition_id) __attribute__((unused));
static void hpack_conn_reset_partition_for_testing(uint16_t partition_id) {
    if (partition_id >= TCP_REASSEMBLY_NUM_PARTITIONS) return;
    memset(g_hpack_conns[partition_id], 0, sizeof(g_hpack_conns[partition_id]));
}
