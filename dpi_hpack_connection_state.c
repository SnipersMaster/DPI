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

struct hpack_connection_entry {
    bool     in_use;
    struct   tcp_flow_key key;
    struct   hpack_dynamic_table dyn_table;
    time_t   last_activity;
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

static struct hpack_dynamic_table *hpack_get_connection_table(uint16_t partition_id,
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
            return &e->dyn_table;
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
     * S6.5.2) — same default used by the fresh-per-call path in
     * dpi_http2_parser.c, since this reference implementation doesn't
     * track actual SETTINGS frame negotiation either way. A real
     * implementation would update this from the peer's actual
     * SETTINGS_HEADER_TABLE_SIZE value when negotiated. */
    hpack_dynamic_table_init(&free_slot->dyn_table, 4096);
    return &free_slot->dyn_table;
}

/*
 * Test/fuzzing-only helper, mirroring
 * tcp_reassembly_reset_partition_for_testing() — clears one
 * partition's HPACK connection state entirely. NOT for production use.
 */
static void hpack_conn_reset_partition_for_testing(uint16_t partition_id) {
    if (partition_id >= TCP_REASSEMBLY_NUM_PARTITIONS) return;
    memset(g_hpack_conns[partition_id], 0, sizeof(g_hpack_conns[partition_id]));
}
