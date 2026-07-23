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
 * VERIFIED AGAINST A REAL CAPTURED FLOW, AND A REAL GAP FOUND THERE
 * -------------------------------------------------------------------
 * This logic had been referenced many times elsewhere in this project
 * as "the real capture path's TCP reassembly handles this correctly"
 * (SMB1, Kerberos, and LDP's dissectors all found real TCP-
 * segmentation artifacts and deferred to this claim) — but that claim
 * itself had never actually been checked against real data until now.
 * Replayed the exact real flow LDP's verification first noticed
 * (10.200.200.101:646→10.200.200.102:46330 in `ultimate.pcapng`,
 * which has genuine duplicate packets and one real overlap conflict —
 * two different payloads claiming the same sequence number) through
 * this exact logic, in true packet arrival order.
 *
 * The overlap-conflict detection itself worked correctly: replaying
 * produced `overlap_conflict_count = 24`, correctly flagging this
 * flow as anomalous — confirming the evasion-detection design this
 * file exists for actually does its job on real, messy data, not just
 * synthetic test cases.
 *
 * But the replay also surfaced a real, previously only DISCLOSED (not
 * fixed) gap actually mattering in practice: `tcp_hole_close()`'s own
 * comment already flagged "a segment landing fully inside an existing
 * hole would need a split, omitted for brevity" — the same class of
 * gap found and fixed in IPv4/IPv6 fragmentation elsewhere in this
 * project. This real flow has a genuine 1-byte true gap (very likely
 * actual packet loss in this merged capture) immediately followed by
 * a later segment landing entirely inside the resulting hole,
 * touching neither edge. Confirmed the practical effect precisely:
 * without the split, even if the missing byte later arrived, only
 * that ONE byte would ever get delivered — the 6 real bytes already
 * buffered just after it would stay permanently invisible, because
 * the unsplit hole didn't distinguish "truly missing" from "present
 * but blocked behind something still missing". Fixed by implementing
 * the split (see `tcp_hole_close()`), then verified: with the fix, if
 * the missing byte arrives, all 7 bytes correctly deliver together.
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

/*
 * struct tcp_flow_key — extended to support IPv6.
 *
 * An earlier version of this struct used plain uint32_t src_ip/dst_ip,
 * which meant TCP-over-IPv6 flows had no way to be represented at all
 * — flagged repeatedly elsewhere in this project as the single largest
 * deliberately-deferred piece of IPv6 support. Fixed here: addresses
 * are now a fixed 16-byte array regardless of IP version, with an
 * explicit version tag rather than inferring version from address
 * content (inferring is fragile — e.g. an IPv4-mapped IPv6 address
 * would be ambiguous under a content-based scheme; an explicit tag
 * is not).
 *
 * IPv4 addresses are stored in the FIRST 4 bytes of the 16-byte field,
 * with the remaining 12 bytes zeroed (an arbitrary but consistent
 * choice — NOT the standard ::ffff:a.b.c.d IPv4-mapped-IPv6 encoding,
 * since that would make a real IPv6 flow using that literal mapped
 * address collide with an IPv4 flow to the same numeric address,
 * which the explicit ip_version tag already prevents without needing
 * a "safe" encoding trick). Always construct keys via
 * tcp_flow_key_make_v4()/_v6() below rather than hand-building them,
 * so this convention stays consistent everywhere.
 */
struct tcp_flow_key {
    uint8_t  ip_version;      /* 4 or 6 */
    uint8_t  src_addr[16];
    uint8_t  dst_addr[16];
    uint16_t src_port, dst_port;
    /* Deliberately directional (src != dst symmetrically) — each
     * direction of a connection is reassembled independently, since
     * sequence numbers are direction-specific in TCP. */
};

static struct tcp_flow_key tcp_flow_key_make_v4(uint32_t src_ip, uint32_t dst_ip,
                                                 uint16_t src_port, uint16_t dst_port) {
    struct tcp_flow_key k;
    memset(&k, 0, sizeof(k));
    k.ip_version = 4;
    k.src_addr[0] = (uint8_t)(src_ip >> 24); k.src_addr[1] = (uint8_t)(src_ip >> 16);
    k.src_addr[2] = (uint8_t)(src_ip >> 8);  k.src_addr[3] = (uint8_t)src_ip;
    k.dst_addr[0] = (uint8_t)(dst_ip >> 24); k.dst_addr[1] = (uint8_t)(dst_ip >> 16);
    k.dst_addr[2] = (uint8_t)(dst_ip >> 8);  k.dst_addr[3] = (uint8_t)dst_ip;
    k.src_port = src_port;
    k.dst_port = dst_port;
    return k;
}

static struct tcp_flow_key tcp_flow_key_make_v6(const uint8_t src_addr16[16],
                                                 const uint8_t dst_addr16[16],
                                                 uint16_t src_port, uint16_t dst_port) {
    struct tcp_flow_key k;
    memset(&k, 0, sizeof(k));
    k.ip_version = 6;
    memcpy(k.src_addr, src_addr16, 16);
    memcpy(k.dst_addr, dst_addr16, 16);
    k.src_port = src_port;
    k.dst_port = dst_port;
    return k;
}

/*
 * Swap src/dst to get the OPPOSITE direction's key for the same TCP
 * connection. Needed because this project's flow keys (and therefore
 * everything keyed by them, including dpi_hpack_connection_state.c's
 * per-connection HPACK state) are directional — each direction of a
 * connection gets its own independent entry. That's correct for TCP
 * reassembly (sequence numbers are direction-specific) but means any
 * protocol semantic that spans BOTH directions — like HTTP/2's
 * SETTINGS_HEADER_TABLE_SIZE, which a SETTINGS frame sent by endpoint A
 * uses to constrain endpoint B's encoder for the OPPOSITE direction,
 * not A's own — needs an explicit way to reach the other direction's
 * state. See dpi_http2_parser.c's SETTINGS handling for where this
 * matters: a real correctness bug (not just a documented
 * simplification) was found and fixed using this helper.
 */
static struct tcp_flow_key tcp_flow_key_reverse(const struct tcp_flow_key *key) {
    struct tcp_flow_key reversed;
    reversed.ip_version = key->ip_version;
    memcpy(reversed.src_addr, key->dst_addr, 16);
    memcpy(reversed.dst_addr, key->src_addr, 16);
    reversed.src_port = key->dst_port;
    reversed.dst_port = key->src_port;
    return reversed;
}

static bool tcp_flow_key_equal(const struct tcp_flow_key *a, const struct tcp_flow_key *b) {
    return a->ip_version == b->ip_version &&
           memcmp(a->src_addr, b->src_addr, 16) == 0 &&
           memcmp(a->dst_addr, b->dst_addr, 16) == 0 &&
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
 *
 * A REAL GAP FOUND AND FIXED HERE, same class as the IPv4/IPv6
 * fragmentation gap fixed elsewhere in this project: replaying a real
 * captured flow byte-for-byte through this exact function (the same
 * LDAP/LDP flow whose duplicate/overlapping segments were first
 * noticed during LDP's verification, replayed here precisely rather
 * than just assumed to be handled) showed a genuine, real 1-byte gap
 * in the sequence space (very likely actual packet loss in this
 * merged capture, not another artifact) followed immediately by a
 * later segment landing fully inside the resulting hole, touching
 * neither edge — exactly the "would need a split, omitted" case this
 * function's comment already disclosed. The practical effect: 6 real,
 * available bytes immediately after the 1-byte gap were silently
 * never delivered, because the undivided hole made them
 * indistinguishable from genuinely missing data. Fixed by
 * implementing the split, bounded by TCP_REASSEMBLY_MAX_HOLES the
 * same way IPv4/IPv6 fragmentation's version already is.
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
        } else if (h->start < start && end < h->end) {
            /* Segment fully inside this hole, touching neither edge:
             * split into two holes — the fix, see function header. */
            if (f->n_holes + 1 <= TCP_REASSEMBLY_MAX_HOLES) {
                memmove(&f->holes[i + 2], &f->holes[i + 1],
                        sizeof(struct tcp_hole) * (f->n_holes - i - 1));
                f->holes[i + 1] = (struct tcp_hole){end, h->end};
                h->end = start;   /* h is holes[i]; still valid after the memmove above */
                f->n_holes++;
                i++;   /* skip the newly-inserted second half, already correct */
            }
            /* else: hole table genuinely full — leave this hole
             * unsplit rather than overflow, same bounded-safety
             * intent as the rest of this function. */
        }
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
 * Test/fuzzing-only helper: clears one partition's flows entirely.
 * NOT for production use — real deployments rely on timeout eviction
 * and the bounded table filling naturally under real traffic patterns.
 * This exists because a long-running fuzz harness makes millions of
 * calls in-process without ever exiting, which would otherwise
 * eventually exhaust TCP_REASSEMBLY_FLOWS_PER_PARTITION and start
 * silently dropping every subsequent test case rather than exercising
 * fresh state each iteration.
 */
static void tcp_reassembly_reset_partition_for_testing(uint16_t partition_id) {
    if (partition_id >= TCP_REASSEMBLY_NUM_PARTITIONS) return;
    memset(g_tcp_flows[partition_id], 0, sizeof(g_tcp_flows[partition_id]));
}

/*
 * Example integration with the rest of the engine:
 *
 *   // IPv4:
 *   struct tcp_flow_key key = tcp_flow_key_make_v4(src_ip, dst_ip, src_port, dst_port);
 *   // IPv6:
 *   struct tcp_flow_key key = tcp_flow_key_make_v6(src_addr16, dst_addr16, src_port, dst_port);
 *
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
