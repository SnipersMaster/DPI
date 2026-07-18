/*
 * dpi_tcp_flow_reassembly.c
 *
 * Per-flow TCP stream reassembly, sitting on top of the per-segment
 * parsing in dpi_rfc_parser.c. This is what actually implements the
 * TCP overlap-resolution policy that file's header comment flagged as
 * an open decision rather than parsing each segment in isolation.
 *
 * WHY THIS MATTERS (recap from earlier in this project): a DPI engine
 * that reassembles overlapping/out-of-order segments differently than
 * the real destination host does is exactly the gap classic IDS
 * evasion techniques exploit (Ptacek & Newsham, "Insertion, Evasion,
 * and Denial of Service: Eluding Network Intrusion Detection", 1998).
 * An attacker sends a segment the DPI engine will read one way and the
 * destination OS will interpret another way — inserting or evading
 * content depending on which interpretation "wins".
 *
 * THE ACTUAL VALUABLE DETECTION HERE isn't "overlap happened" — benign
 * retransmission overlaps constantly under normal network conditions.
 * It's "overlap happened AND the new bytes differ from what's already
 * there at that position" — that specific pattern is what a legitimate
 * retransmission never produces (a retransmission resends the SAME
 * bytes) and what an evasion attempt requires. This file distinguishes
 * the two and only flags the latter as suspicious.
 *
 * NOT COMPILED/TESTED against live traffic in this environment.
 *
 * -------------------------------------------------------------------
 * DESIGN
 * -------------------------------------------------------------------
 *   - Per-flow bounded byte buffer + hole list, same pattern as the
 *     IPv4 fragmentation reassembly in dpi_rfc_parser.c, reused
 *     deliberately for consistency.
 *   - Sequence numbers are tracked as offsets relative to each flow's
 *     first-observed sequence number, computed with unsigned wraparound
 *     arithmetic — this is correct across a 32-bit sequence number
 *     wraparound as long as the flow's total tracked span stays under
 *     2^31 bytes, which the bounded buffer size guarantees.
 *   - Configurable overlap policy (FIRST_WINS / LAST_WINS) — RFC 9293
 *     does not mandate one, and different operating systems resolve
 *     overlaps differently. Defaults to FIRST_WINS (matches classic
 *     BSD behavior), overridable per deployment if you know your
 *     protected hosts' OS mix.
 *   - Timeout eviction AND a hard flow-count ceiling, closing the gap
 *     explicitly flagged as missing in the IPv4 fragment reassembly
 *     reference implementation earlier in this project.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define TCP_REASSEMBLY_MAX_FLOWS       4096
#define TCP_REASSEMBLY_BUFFER_BYTES    16384  /* enough for a ClientHello and
                                                 * initial app data; DPI depth
                                                 * is bounded on purpose — this
                                                 * isn't a full-connection buffer */
#define TCP_REASSEMBLY_MAX_HOLES       128
#define TCP_FLOW_TIMEOUT_SECONDS       60     /* evict idle flows after this long */

/* MEMORY FOOTPRINT: each flow struct is roughly
 *   buffer (16384) + bitmap (16384/8=2048) + holes (128*8=1024) + misc (~50)
 *   = ~19.5 KB per flow
 * At TCP_REASSEMBLY_MAX_FLOWS=4096 that's a static ~80 MB table.
 * Size these two constants deliberately for your deployment — halving
 * either roughly halves the footprint. This was caught and fixed once
 * already in this file: an earlier version used a bool array instead
 * of a bitmap for byte_written and had an ~132 MB footprint for no
 * reason. Worth actually computing this number after any future
 * change to these constants rather than assuming it stayed small. */

/*
 * CONCURRENCY NOTE — caught while wiring this into the multi-core DPDK
 * worker: an earlier version of this file used ONE shared global flow
 * table scanned and written by every lcore with no locking at all. RSS
 * pins same-FLOW traffic to the same core, but that does NOT make the
 * shared TABLE itself safe — multiple lcores doing unsynchronized
 * linear scans and writes into the same array concurrently is a real
 * data race (two lcores finding the same empty slot and both writing
 * to it, e.g.), not just a theoretical one.
 *
 * Fixed by partitioning the table per-lcore instead: each lcore gets
 * its own slice, indexed by partition_id (its queue_id). Combined with
 * RSS actually guaranteeing a given flow's packets all land on one
 * queue/core, this means no lcore ever touches another's partition —
 * zero shared mutable state on this hot path, no locks needed at all.
 * This mirrors the "no shared state with other cores" comment already
 * on dpi_dpdk_worker.c's lcore_worker function; the flow table just
 * hadn't actually been made to honor that yet.
 */
#define TCP_REASSEMBLY_NUM_PARTITIONS      16   /* must be >= your actual RX
                                                   queue/lcore count */
#define TCP_REASSEMBLY_FLOWS_PER_PARTITION (TCP_REASSEMBLY_MAX_FLOWS / TCP_REASSEMBLY_NUM_PARTITIONS)

enum tcp_overlap_policy {
    TCP_OVERLAP_FIRST_WINS,   /* keep existing data, discard new overlapping bytes (BSD-style) */
    TCP_OVERLAP_LAST_WINS     /* new data overwrites existing bytes at the overlap */
};

struct tcp_flow_key {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    /* Deliberately directional (src != dst symmetrically) — each
     * direction of a connection is reassembled independently, since
     * sequence numbers are direction-specific in TCP. */
};

static bool tcp_flow_key_equal(const struct tcp_flow_key *a, const struct tcp_flow_key *b) {
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port;
}

struct tcp_hole {
    uint32_t start, end;   /* offsets relative to flow base sequence, end exclusive */
};

struct tcp_reassembly_flow {
    bool     in_use;
    struct tcp_flow_key key;

    bool     base_seq_set;
    uint32_t base_seq;          /* first sequence number observed for this flow */
    uint32_t highest_offset;    /* highest (relative) offset written so far */
    uint32_t delivered_offset;  /* how much contiguous data has already been
                                  * handed off to the caller — avoids re-delivering
                                  * the same bytes on every insert */

    uint8_t  buffer[TCP_REASSEMBLY_BUFFER_BYTES];
    /* Packed bitmap (1 bit per byte) instead of a bool array (1 byte
     * per byte) for fill-tracking — an earlier draft of this file used
     * bool[TCP_REASSEMBLY_BUFFER_BYTES] here, which alone added ~16KB
     * per flow for no reason; caught while sizing the flow table's
     * total footprint below. */
    uint8_t  byte_written_bitmap[TCP_REASSEMBLY_BUFFER_BYTES / 8];

    struct tcp_hole holes[TCP_REASSEMBLY_MAX_HOLES];
    int      n_holes;

    enum tcp_overlap_policy policy;
    time_t   last_activity;

    /* Stats surfaced in the flow record, matching the schema shown
     * earlier in this project's flow record samples. */
    uint32_t out_of_order_segments;
    uint32_t retransmit_count;        /* overlap with IDENTICAL bytes: benign */
    uint32_t overlap_conflict_count;  /* overlap with DIFFERENT bytes: evasion signal */
};

static struct tcp_reassembly_flow g_tcp_flows[TCP_REASSEMBLY_NUM_PARTITIONS][TCP_REASSEMBLY_FLOWS_PER_PARTITION];

/* ------------------------------------------------------------------
 * Flow lookup / creation, with timeout eviction and a hard ceiling.
 * O(n) scan over the flow table — acceptable at the scale this
 * reference targets; see the dissector registry's note on the same
 * tradeoff for the general pattern if this becomes a bottleneck at
 * very high flow counts.
 * ------------------------------------------------------------------ */
static struct tcp_reassembly_flow *tcp_flow_find_or_create(uint16_t partition_id,
                                                             const struct tcp_flow_key *key,
                                                             enum tcp_overlap_policy policy) {
    if (partition_id >= TCP_REASSEMBLY_NUM_PARTITIONS) return NULL;

    time_t now = time(NULL);
    struct tcp_reassembly_flow *free_slot = NULL;
    struct tcp_reassembly_flow *partition = g_tcp_flows[partition_id];

    for (int i = 0; i < TCP_REASSEMBLY_FLOWS_PER_PARTITION; i++) {
        struct tcp_reassembly_flow *f = &partition[i];

        if (f->in_use && (now - f->last_activity) > TCP_FLOW_TIMEOUT_SECONDS) {
            /* Idle past the timeout: evict. This closes the gap the
             * IPv4 fragment reassembly reference explicitly lacked —
             * without this, a slow-trickle or abandoned-flow attack
             * fills the table permanently. */
            f->in_use = false;
        }

        if (f->in_use && tcp_flow_key_equal(&f->key, key)) {
            f->last_activity = now;
            return f;
        }
        if (!f->in_use && !free_slot) free_slot = f;
    }

    if (!free_slot) return NULL;   /* table full even after evicting expired
                                     * flows: caller must drop rather than block */

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->in_use = true;
    free_slot->key = *key;
    free_slot->policy = policy;
    free_slot->last_activity = now;
    free_slot->holes[0] = (struct tcp_hole){0, TCP_REASSEMBLY_BUFFER_BYTES};
    free_slot->n_holes = 1;
    return free_slot;
}

static inline bool bitmap_test(const uint8_t *bitmap, uint32_t pos) {
    return (bitmap[pos / 8] >> (pos % 8)) & 1;
}
static inline void bitmap_set(uint8_t *bitmap, uint32_t pos) {
    bitmap[pos / 8] |= (uint8_t)(1u << (pos % 8));
}

/* ------------------------------------------------------------------
 * Hole-list maintenance — same approach as the IPv4 fragment
 * reassembly, extended to also track WHICH bytes are filled (not just
 * which ranges are missing), since overlap detection needs to compare
 * against existing content, not just know a region isn't a hole.
 * ------------------------------------------------------------------ */
static void tcp_hole_close(struct tcp_reassembly_flow *f, uint32_t start, uint32_t end) {
    for (int i = 0; i < f->n_holes; i++) {
        struct tcp_hole *h = &f->holes[i];
        if (start <= h->start && end >= h->end) {
            memmove(&f->holes[i], &f->holes[i + 1],
                    sizeof(struct tcp_hole) * (f->n_holes - i - 1));
            f->n_holes--;
            i--;
        } else if (start <= h->start && end > h->start) {
            h->start = end;
        } else if (start < h->end && end >= h->end) {
            h->end = start;
        }
        /* A segment landing fully inside an existing hole would need a
         * split into two holes; omitted for brevity, same documented
         * gap as the IPv4 fragment reassembly reference. Under
         * adversarial fine-grained fragmentation this degrades to
         * treating the hole as still partially open rather than
         * silently misreporting completeness — acceptable for a
         * reference implementation, flagged here so it isn't missed. */
    }
}

/* ------------------------------------------------------------------
 * Segment insertion — the core of the overlap-resolution policy.
 *
 * Returns true if new contiguous data became available for delivery
 * (out_data/out_len point at it). The caller is responsible for
 * feeding that data onward (e.g. to extract_sni_from_record()).
 * ------------------------------------------------------------------ */
struct tcp_reassembly_stats {
    uint32_t out_of_order_segments;
    uint32_t retransmit_count;
    uint32_t overlap_conflict_count;
    bool     evasion_flag;   /* true if overlap_conflict_count > 0 for this flow */
    bool     is_first_delivery;  /* true if this call produced this flow's FIRST
                                   * contiguous data delivery — lets the caller
                                   * gate expensive per-flow work (SNI parsing,
                                   * classification) to run once per flow instead
                                   * of on every subsequent contiguous chunk as
                                   * more of a long-lived connection arrives */
};

static bool tcp_reassembly_insert(uint16_t partition_id,
                                   const struct tcp_flow_key *key,
                                   uint32_t seq, const uint8_t *data, uint32_t len,
                                   enum tcp_overlap_policy policy,
                                   const uint8_t **out_data, uint32_t *out_len,
                                   struct tcp_reassembly_stats *out_stats) {
    if (out_data) *out_data = NULL;
    if (out_len) *out_len = 0;
    if (out_stats) out_stats->is_first_delivery = false;

    struct tcp_reassembly_flow *f = tcp_flow_find_or_create(partition_id, key, policy);
    if (!f) return false;   /* flow table full: drop this segment's contribution */

    if (!f->base_seq_set) {
        f->base_seq = seq;
        f->base_seq_set = true;
    }

    /* Unsigned wraparound-correct relative offset — see file header
     * comment on why this is safe given the bounded buffer size. */
    uint32_t offset = seq - f->base_seq;

    if (offset >= TCP_REASSEMBLY_BUFFER_BYTES) {
        /* Beyond what we track for DPI purposes (see buffer size
         * rationale in the header comment) — not an error, just out
         * of the depth this engine inspects. Drop silently. */
        goto report_stats;
    }

    uint32_t write_len = len;
    if (offset + write_len > TCP_REASSEMBLY_BUFFER_BYTES) {
        write_len = TCP_REASSEMBLY_BUFFER_BYTES - offset;   /* clip to buffer bound */
    }

    if (offset != f->highest_offset && offset < f->highest_offset) {
        f->out_of_order_segments++;
    }

    /* Byte-by-byte overlap detection and policy application. Walking
     * byte-by-byte is not the fastest possible approach, but it is the
     * simplest to verify correct, which matters more for a reference
     * implementation whose whole point is getting the security-critical
     * policy right. */
    for (uint32_t i = 0; i < write_len; i++) {
        uint32_t pos = offset + i;
        uint8_t new_byte = data[i];

        if (!bitmap_test(f->byte_written_bitmap, pos)) {
            /* Virgin byte: always write it, regardless of policy. */
            f->buffer[pos] = new_byte;
            bitmap_set(f->byte_written_bitmap, pos);
            continue;
        }

        /* Overlap: this position was already filled. */
        uint8_t existing_byte = f->buffer[pos];
        if (existing_byte == new_byte) {
            /* Identical retransmission — benign, expected under normal
             * network conditions (loss + retransmit). Not evasion. */
            f->retransmit_count++;
            /* Content agrees regardless of policy; nothing to change. */
        } else {
            /* CONFLICTING overlap: the new segment claims different
             * bytes at a position we already have data for. This is
             * exactly the ambiguity an evasion attempt relies on.
             * Apply the configured policy explicitly rather than
             * picking one implicitly. */
            f->overlap_conflict_count++;
            if (f->policy == TCP_OVERLAP_LAST_WINS) {
                f->buffer[pos] = new_byte;
            }
            /* FIRST_WINS: leave existing byte in place, i.e. do nothing. */
        }
    }

    tcp_hole_close(f, offset, offset + write_len);
    if (offset + write_len > f->highest_offset) {
        f->highest_offset = offset + write_len;
    }

    /* Deliver any newly-available contiguous prefix. Only the FIRST
     * hole's start position matters here: data is contiguous from
     * delivered_offset up to the start of the next remaining hole (or
     * highest_offset if no holes remain in the tracked range). */
    uint32_t contiguous_end = f->highest_offset;
    for (int i = 0; i < f->n_holes; i++) {
        if (f->holes[i].start >= f->delivered_offset && f->holes[i].start < contiguous_end) {
            contiguous_end = f->holes[i].start;
        }
    }

    if (contiguous_end > f->delivered_offset) {
        bool was_first = (f->delivered_offset == 0);
        if (out_data) *out_data = f->buffer + f->delivered_offset;
        if (out_len) *out_len = contiguous_end - f->delivered_offset;
        f->delivered_offset = contiguous_end;
        if (out_stats) out_stats->is_first_delivery = was_first;
    }

report_stats:
    if (out_stats) {
        out_stats->out_of_order_segments = f->out_of_order_segments;
        out_stats->retransmit_count = f->retransmit_count;
        out_stats->overlap_conflict_count = f->overlap_conflict_count;
        out_stats->evasion_flag = f->overlap_conflict_count > 0;
    }

    return out_data && *out_data != NULL;
}

/*
 * Example integration with the rest of the engine:
 *
 *   struct tcp_flow_key key = { src_ip, dst_ip, src_port, dst_port };
 *   const uint8_t *contiguous;
 *   uint32_t contiguous_len;
 *   struct tcp_reassembly_stats stats;
 *
 *   // partition_id MUST be a value that's stable per-flow and unique
 *   // per-lcore — in the DPDK worker, that's the RX queue_id (RSS
 *   // already guarantees a flow's packets all land on one queue). In
 *   // the single-core bootstrap, it's always 0.
 *   if (tcp_reassembly_insert(partition_id, &key, tcp_seq, tcp_payload,
 *                              tcp_payload_len, TCP_OVERLAP_FIRST_WINS,
 *                              &contiguous, &contiguous_len, &stats)) {
 *       // contiguous now holds newly-available in-order bytes —
 *       // feed to extract_sni_from_record(), classify_flow(), etc.
 *   }
 *
 *   // stats.evasion_flag maps directly to the "possible_evasion_overlap"
 *   // flag shown in this project's earlier flow record samples.
 */
