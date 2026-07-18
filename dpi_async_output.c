/*
 * dpi_async_output.c
 *
 * Replaces dpi_dpdk_worker.c's hot-path printf() with a lock-free
 * per-lcore ring buffer, drained by a dedicated non-poll-mode thread
 * that does the actual (blocking) I/O. This is the standard pattern
 * for getting output off a DPDK poll-mode core: producers never block,
 * never do I/O, and never contend with each other or the consumer for
 * a lock.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * -------------------------------------------------------------------
 * DESIGN
 * -------------------------------------------------------------------
 *   - One ring PER LCORE, single-producer/single-consumer (SPSC). Each
 *     RX/dissection lcore is the sole producer for its own ring; one
 *     dedicated drain thread is the sole consumer across all rings.
 *     SPSC is the simplest lock-free ring buffer to get correct, and
 *     it fits this architecture exactly — there's no scenario here
 *     where two lcores write to the same ring.
 *   - Producers NEVER block. If a ring is full, the record is dropped
 *     and a counter is incremented — silently blocking or spinning on
 *     a full ring would reintroduce exactly the hot-path stall this
 *     exists to avoid. Drops are surfaced via the counter, not hidden.
 *   - Fixed-size POD records, not formatted strings — formatting
 *     (snprintf-family work) happens in the consumer, off the hot
 *     path, not in the producer. The producer's cost is a struct copy.
 *   - The drain thread is a plain pthread, NOT another DPDK lcore.
 *     DPDK's isolated poll-mode cores are a scarce, carefully-tuned
 *     resource (see the IOMMU/hugepage/core-isolation setup in
 *     dpi_dpdk_worker.c's header) — pairing them with a thread that
 *     does blocking I/O (stdout, file, network export) would waste
 *     that isolation. A regular thread on a non-isolated core is the
 *     right tool for this specific job.
 *
 * -------------------------------------------------------------------
 * SIZING
 * -------------------------------------------------------------------
 * LOG_RING_SIZE * sizeof(struct flow_log_record) * MAX_LCORE_RINGS is
 * the static memory cost. At the defaults below: ~400 bytes/record *
 * 8192 slots * 16 possible rings ≈ 52 MB. Tune LOG_RING_SIZE down if
 * that's not acceptable, but be aware a smaller ring drops more
 * records under a burst — there's a real tradeoff here, not a free
 * parameter.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>

/* Provides: struct output_sink, output_sink_create(), and the
 * file/syslog/unix-socket backend implementations. */
#include "dpi_output_sink.c"

#define LOG_RING_SIZE     8192   /* MUST be a power of 2 — see the mask-based
                                    indexing below, which relies on this */
#define MAX_LCORE_RINGS   16
#define MAX_SNI_LOG_LEN   256
#define MAX_STR_FIELD_LEN 64

struct flow_log_record {
    char     src_ip[46];   /* sized for the longest IPv6 text form;
                             * IPv4 addresses are shorter and fit fine */
    char     dst_ip[46];
    uint16_t src_port, dst_port;
    char     sni[MAX_SNI_LOG_LEN];
    char     category[MAX_STR_FIELD_LEN];
    char     app_name[MAX_STR_FIELD_LEN];
    char     confidence[16];
    double   dga_score;
    double   vpn_score;
    char     vpn_protocol[32];
    double   dot_score;
    double   doh_score;
    uint32_t out_of_order_segments;
    uint32_t retransmit_count;
    uint32_t overlap_conflict_count;
    bool     evasion_flag;
};

struct log_ring {
    _Atomic uint32_t head;   /* written only by the producer */
    _Atomic uint32_t tail;   /* written only by the consumer */
    _Atomic uint64_t dropped_count;
    struct flow_log_record records[LOG_RING_SIZE];
};

static struct log_ring g_log_rings[MAX_LCORE_RINGS];
static _Atomic bool g_output_thread_running = false;
static pthread_t g_output_thread;
static const struct output_sink *g_active_sink = NULL;

/* ------------------------------------------------------------------
 * Producer side — called from the hot path. Must never block.
 * ------------------------------------------------------------------ */
static bool log_ring_try_push(uint16_t ring_index, const struct flow_log_record *rec) {
    if (ring_index >= MAX_LCORE_RINGS) return false;
    struct log_ring *ring = &g_log_rings[ring_index];

    uint32_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
    uint32_t next_head = (head + 1) & (LOG_RING_SIZE - 1);

    if (next_head == tail) {
        /* Ring full: drop, count it, move on. This is the entire point —
         * a producer that blocks here defeats the purpose of this file. */
        atomic_fetch_add_explicit(&ring->dropped_count, 1, memory_order_relaxed);
        return false;
    }

    ring->records[head] = *rec;   /* struct copy — single producer, safe without a lock */
    atomic_store_explicit(&ring->head, next_head, memory_order_release);
    return true;
}

/* ------------------------------------------------------------------
 * Consumer side — runs only in the drain thread.
 * ------------------------------------------------------------------ */
static bool log_ring_try_pop(struct log_ring *ring, struct flow_log_record *out) {
    uint32_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    uint32_t head = atomic_load_explicit(&ring->head, memory_order_acquire);

    if (tail == head) return false;   /* empty */

    *out = ring->records[tail];
    uint32_t next_tail = (tail + 1) & (LOG_RING_SIZE - 1);
    atomic_store_explicit(&ring->tail, next_tail, memory_order_release);
    return true;
}

static void format_and_emit(const struct flow_log_record *rec) {
    /* All formatting cost (snprintf-family work) lives here, off the
     * hot path — this is deliberately the same JSON shape the earlier
     * inline printf produced, so downstream tooling doesn't need to
     * change now that this goes to a real sink instead. */
    char line[1200];
    int n = snprintf(line, sizeof(line),
           "{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,"
           "\"sni\":\"%s\",\"category\":\"%s\","
           "\"app_name\":\"%s\",\"confidence\":\"%s\",\"dga_score\":%.2f,"
           "\"vpn_score\":%.2f,\"vpn_protocol\":\"%s\",\"dot_score\":%.2f,"
           "\"doh_score\":%.2f,\"reassembly\":{\"out_of_order\":%u,"
           "\"retransmits\":%u,\"overlap_conflicts\":%u,\"evasion_flag\":%s}}\n",
           rec->src_ip, rec->dst_ip, rec->src_port, rec->dst_port,
           rec->sni, rec->category, rec->app_name,
           rec->confidence, rec->dga_score, rec->vpn_score, rec->vpn_protocol,
           rec->dot_score, rec->doh_score, rec->out_of_order_segments,
           rec->retransmit_count, rec->overlap_conflict_count,
           rec->evasion_flag ? "true" : "false");

    if (n < 0) return;   /* formatting failure: drop rather than write garbage */
    size_t len = (n >= (int)sizeof(line)) ? sizeof(line) - 1 : (size_t)n;

    if (g_active_sink) {
        g_active_sink->write_line(line, len);
    } else {
        /* No sink configured: this should not happen in normal
         * operation (async_output_start() requires a sink to be
         * chosen), but fail safe rather than silently discard if it
         * somehow does. */
        fwrite(line, 1, len, stdout);
    }
}

/*
 * Drain loop: round-robins across all rings so one busy lcore can't
 * starve another's output. Sleeps briefly when every ring was empty
 * on a pass, rather than busy-spinning — this thread isn't on the hot
 * path, there's no reason to burn a full core polling it.
 */
static void *output_drain_thread(void *arg) {
    (void)arg;
    time_t last_drop_report = time(NULL);
    time_t last_flush = time(NULL);
    /* How long a record can sit buffered (e.g. in the file sink's
     * stdio buffer) before it's guaranteed to actually hit disk. Not
     * every record needs to be flushed immediately — that would
     * reintroduce per-record I/O cost — but an unbounded delay risks
     * losing more on a crash than is acceptable. 1 second is a
     * reasonable default; tune against your durability requirements. */
    const time_t FLUSH_INTERVAL_SECONDS = 1;

    while (atomic_load_explicit(&g_output_thread_running, memory_order_relaxed)) {
        bool any_popped = false;

        for (int i = 0; i < MAX_LCORE_RINGS; i++) {
            struct flow_log_record rec;
            /* Drain a bounded number per ring per pass so one very
             * active ring can't starve the round-robin fairness across
             * rings — not just "pop everything from ring 0 first". */
            for (int n = 0; n < 256; n++) {
                if (!log_ring_try_pop(&g_log_rings[i], &rec)) break;
                format_and_emit(&rec);
                any_popped = true;
            }
        }

        time_t now = time(NULL);

        if (now - last_flush >= FLUSH_INTERVAL_SECONDS) {
            if (g_active_sink) g_active_sink->flush();
            last_flush = now;
        }

        if (now - last_drop_report >= 10) {
            uint64_t total_dropped = 0;
            for (int i = 0; i < MAX_LCORE_RINGS; i++) {
                total_dropped += atomic_load_explicit(&g_log_rings[i].dropped_count,
                                                        memory_order_relaxed);
            }
            if (total_dropped > 0) {
                fprintf(stderr, "dpi_async_output: %lu records dropped so far "
                        "(ring(s) full — consumer can't keep up, or a burst "
                        "exceeded LOG_RING_SIZE)\n", (unsigned long)total_dropped);
            }
            last_drop_report = now;
        }

        if (!any_popped) {
            usleep(1000);   /* 1ms: no work available, don't busy-spin */
        }
    }

    /* Drain whatever's left after shutdown is signaled, so a clean
     * exit doesn't silently lose the last burst of in-flight records. */
    for (int i = 0; i < MAX_LCORE_RINGS; i++) {
        struct flow_log_record rec;
        while (log_ring_try_pop(&g_log_rings[i], &rec)) {
            format_and_emit(&rec);
        }
    }
    if (g_active_sink) g_active_sink->flush();   /* final flush before exit */

    return NULL;
}

static bool async_output_start(const char *sink_config) {
    if (!output_sink_create(sink_config, &g_active_sink)) {
        fprintf(stderr, "dpi_async_output: failed to initialize output sink "
                "from config '%s'\n", sink_config);
        return false;
    }

    atomic_store_explicit(&g_output_thread_running, true, memory_order_relaxed);
    int ret = pthread_create(&g_output_thread, NULL, output_drain_thread, NULL);
    if (ret != 0) {
        fprintf(stderr, "dpi_async_output: failed to start drain thread: %d\n", ret);
        atomic_store_explicit(&g_output_thread_running, false, memory_order_relaxed);
        if (g_active_sink) g_active_sink->close_sink();
        return false;
    }
    return true;
}

static void async_output_stop(void) {
    atomic_store_explicit(&g_output_thread_running, false, memory_order_relaxed);
    pthread_join(g_output_thread, NULL);
    if (g_active_sink) g_active_sink->close_sink();
}
