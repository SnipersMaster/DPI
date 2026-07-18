/*
 * dpi_dpdk_worker.c
 *
 * Skeleton for a multi-core, DPDK-based DPI capture/dissection worker
 * intended for 100G line rate. This is an architecture reference, not a
 * finished engine — validate every constant and assumption on your own
 * lab hardware before touching production traffic.
 *
 * NOT COMPILED OR TESTED in this environment (no DPDK, no NIC, no IOMMU
 * available in the sandbox this was written in). Treat this as a design
 * document expressed in code.
 *
 * -------------------------------------------------------------------
 * REQUIRED LAB SETUP (do this before this code is relevant at all):
 * -------------------------------------------------------------------
 *   1. BIOS/kernel: enable IOMMU
 *        intel_iommu=on iommu=pt   (Intel)
 *        amd_iommu=on iommu=pt    (AMD)
 *   2. Bind the 100G NIC to vfio-pci, NOT igb_uio/uio_pci_generic:
 *        modprobe vfio-pci
 *        dpdk-devbind.py --bind=vfio-pci <PCI-ID>
 *   3. Reserve hugepages at boot (not at runtime):
 *        echo 4096 > /sys/kernel/mm/hugepages/hugepages-2048kB/.../nr_hugepages
 *        (size this to your mbuf pool needs; 1G hugepages are better at this scale)
 *   4. Create a dedicated service account and give it group access to the
 *      VFIO device node instead of running as root:
 *        useradd -r -s /usr/sbin/nologin dpi-svc
 *        chown root:dpi-svc /dev/vfio/<group>
 *        chmod 660 /dev/vfio/<group>
 *      This is the 100G equivalent of the setuid/setgid drop in the
 *      single-core version — the process never needs to be root because
 *      VFIO does privilege separation for you at the IOMMU/group level.
 *   5. Pin IRQs and isolate cores for your poll threads:
 *        isolcpus / nohz_full / irqaffinity kernel params, and confirm
 *        with `cat /proc/interrupts` that nothing else lands on your
 *        poll-thread cores.
 *
 * Build (once DPDK is installed and pkg-config sees it):
 *   gcc -O3 -march=native $(pkg-config --cflags libdpdk) \
 *       -o dpi_dpdk_worker dpi_dpdk_worker.c $(pkg-config --libs libdpdk)
 *
 * Run as the unprivileged service account, not root:
 *   sudo -u dpi-svc ./dpi_dpdk_worker -l 0-7 -n 4 -- -p 0x1
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ip.h>

/* Provides: parse_ipv4(), parse_tcp(), struct ipv4_result, struct tcp_result.
 * These operate on raw uint8_t* byte buffers, not DPDK-specific struct
 * types, so they plug in directly after the Ethernet header regardless
 * of capture backend (DPDK here, or the AF_PACKET path in
 * dpi_secure_bootstrap.c) — that portability was deliberate when this
 * file was written. */
#include "dpi_rfc_parser.c"

/* Provides: struct tcp_flow_key, tcp_reassembly_insert(), TCP_OVERLAP_FIRST_WINS. */
#include "dpi_tcp_flow_reassembly.c"

/* Provides: classify_flow(), struct app_classification, and (via its
 * own #includes) domain classification, DGA scoring, VPN scoring, and
 * DoH/DoT scoring. */
#include "dpi_app_classifier.c"

#define RX_RING_SIZE      4096
#define TX_RING_SIZE      1024
#define NUM_MBUFS         (1 << 18)   /* size per your flow count / lab testing, not a guess */
#define MBUF_CACHE_SIZE   512
#define BURST_SIZE        64          /* batch size per poll — amortizes per-call overhead */
#define MAX_QUEUES        16          /* one per core in the RSS group */

static volatile int force_quit = 0;

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nsignal %d received, shutting down\n", signum);
        force_quit = 1;
    }
}

/* -----------------------------------------------------------------
 * Port init: RSS across MAX_QUEUES so each core gets its own queue
 * and, critically, same-flow packets stay pinned to the same core
 * (needed so per-flow reassembly state never needs cross-core locks).
 * ----------------------------------------------------------------- */
static int port_init(uint16_t port_id, struct rte_mempool *mbuf_pool, uint16_t n_queues) {
    struct rte_eth_conf port_conf = {0};
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_hf =
        RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;

    int ret = rte_eth_dev_configure(port_id, n_queues, n_queues, &port_conf);
    if (ret < 0) {
        fprintf(stderr, "rte_eth_dev_configure failed: %s\n", rte_strerror(-ret));
        return -1;
    }

    for (uint16_t q = 0; q < n_queues; q++) {
        ret = rte_eth_rx_queue_setup(port_id, q, RX_RING_SIZE,
                                      rte_eth_dev_socket_id(port_id),
                                      NULL, mbuf_pool);
        if (ret < 0) {
            fprintf(stderr, "rx_queue_setup failed on queue %u: %s\n", q, rte_strerror(-ret));
            return -1;
        }
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        fprintf(stderr, "rte_eth_dev_start failed: %s\n", rte_strerror(-ret));
        return -1;
    }

    rte_eth_promiscuous_enable(port_id);
    return 0;
}

/* -----------------------------------------------------------------
 * Bounds-checked dissection — same discipline as the single-core
 * version, but now on the hot path at line rate. Do NOT relax this
 * for speed; a validated-length check costs nanoseconds, a heap
 * overflow at 100G costs you the whole engine.
 * ----------------------------------------------------------------- */
static inline void dissect_packet(struct rte_mbuf *m) {
    uint16_t len = rte_pktmbuf_pkt_len(m);
    if (len < sizeof(struct rte_ether_hdr)) {
        rte_pktmbuf_free(m);
        return;
    }

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ethertype = rte_be_to_cpu_16(eth->ether_type);

    if (ethertype != RTE_ETHER_TYPE_IPV4) {
        rte_pktmbuf_free(m);   /* IPv6 and everything else: not handled yet,
                                 * see the README's protocol coverage table */
        return;
    }

    const uint8_t *ip_start = (const uint8_t *)(eth + 1);
    uint16_t ip_len = len - sizeof(struct rte_ether_hdr);

    struct ipv4_result ip_result;
    if (!parse_ipv4(ip_start, ip_len, &ip_result)) {
        rte_pktmbuf_free(m);   /* malformed or not-yet-reassembled fragment: drop here */
        return;
    }

    if (ip_result.protocol != 6 /* TCP */) {
        rte_pktmbuf_free(m);   /* UDP-based protocols (QUIC, RADIUS, DoT/DoH,
                                 * VPN fingerprints) go through a separate path —
                                 * see the note below this function */
        return;
    }

    struct tcp_result tcp_result;
    if (!parse_tcp(ip_result.src_addr, ip_result.dst_addr,
                    ip_result.payload, ip_result.payload_len, &tcp_result)) {
        rte_pktmbuf_free(m);
        return;
    }

    if (tcp_result.payload_len == 0) {
        rte_pktmbuf_free(m);   /* pure ACK/control segment, no data to reassemble */
        return;
    }

    struct tcp_flow_key key = {
        .src_ip = ip_result.src_addr,
        .dst_ip = ip_result.dst_addr,
        .src_port = tcp_result.src_port,
        .dst_port = tcp_result.dst_port
    };

    const uint8_t *contiguous_data = NULL;
    uint32_t contiguous_len = 0;
    struct tcp_reassembly_stats stats;

    bool have_new_data = tcp_reassembly_insert(
        &key, tcp_result.seq, tcp_result.payload, tcp_result.payload_len,
        TCP_OVERLAP_FIRST_WINS, &contiguous_data, &contiguous_len, &stats);

    /* The mbuf itself can be freed now — tcp_reassembly_insert() already
     * copied whatever it needed into the flow's own reassembly buffer,
     * so nothing below this line depends on the mbuf staying alive.
     * Free it BEFORE the (potentially non-trivial) classification work
     * runs, not after, so the mbuf pool isn't held longer than needed
     * under load. */
    rte_pktmbuf_free(m);

    if (!have_new_data) return;

    /* Gate the classification pipeline (SNI parse, domain lookup, DGA
     * scoring, VPN scoring, DoH/DoT scoring) to run once per flow, on
     * its first contiguous delivery — not on every later chunk of a
     * long-lived connection. This matters at 100G: classify_flow()
     * does an O(rule-count) domain table scan and several string/byte
     * passes, which is fine once per flow but would be real waste if
     * re-run for every additional in-order byte a multi-second
     * connection delivers. The ClientHello (and therefore the SNI)
     * essentially always arrives in a flow's first contiguous chunk,
     * so this doesn't cost real detection coverage. */
    if (!stats.is_first_delivery) return;

    struct app_classification classification;
    classify_flow(contiguous_data, contiguous_len,
                  tcp_result.dst_port, "TCP", &classification);

    /* IMPORTANT: printf here is for reference/lab visibility ONLY.
     * Blocking, unbuffered stdout I/O on a poll-mode core at 100G is
     * itself a severe performance bug — the RX burst loop must never
     * block on I/O. A real deployment needs this to push onto a
     * lock-free SPSC ring buffer (one per lcore) that a SEPARATE
     * logging/export thread drains and writes/ships asynchronously.
     * Wiring that up is a reasonable next step, not included here
     * since it depends on your chosen output sink (file, Kafka,
     * syslog, etc.) — but do not leave this printf() in a build meant
     * for real traffic. */
    printf("{\"src_port\":%u,\"dst_port\":%u,\"sni\":\"%s\",\"category\":\"%s\","
           "\"app_name\":\"%s\",\"confidence\":\"%s\",\"dga_score\":%.2f,"
           "\"vpn_score\":%.2f,\"vpn_protocol\":\"%s\",\"dot_score\":%.2f,"
           "\"doh_score\":%.2f,\"reassembly\":{\"out_of_order\":%u,"
           "\"retransmits\":%u,\"overlap_conflicts\":%u,\"evasion_flag\":%s}}\n",
           tcp_result.src_port, tcp_result.dst_port,
           classification.sni, classification.category, classification.app_name,
           classification.confidence, classification.dga_score,
           classification.vpn_score, classification.vpn_protocol,
           classification.dot_score, classification.doh_score,
           stats.out_of_order_segments, stats.retransmit_count,
           stats.overlap_conflict_count, stats.evasion_flag ? "true" : "false");
}

/*
 * NOTE ON UDP-BASED PROTOCOLS: QUIC, RADIUS, DoT-on-853-is-TCP-so-that's
 * covered-above-but-DoH-fallback, and the WireGuard/IKE fingerprints in
 * dpi_vpn_detector.c all need a parallel UDP path — this function only
 * wires up the TCP branch since that's where TCP flow reassembly (the
 * thing this change set out to wire in) applies. A UDP equivalent would
 * skip reassembly entirely (UDP is datagram-oriented, no stream to
 * reassemble) and call dpi_dissector_registry.c's dispatch_dissection()
 * directly per-datagram — that's a separate wiring task from this one.
 */

/* -----------------------------------------------------------------
 * Per-core poll loop. Each lcore owns exactly one RX queue — no
 * shared state with other cores on this hot path.
 * ----------------------------------------------------------------- */
static int lcore_worker(void *arg) {
    uint16_t queue_id = *(uint16_t *)arg;
    uint16_t port_id = 0;
    struct rte_mbuf *bufs[BURST_SIZE];

    printf("lcore %u polling queue %u\n", rte_lcore_id(), queue_id);

    while (!force_quit) {
        uint16_t nb_rx = rte_eth_rx_burst(port_id, queue_id, bufs, BURST_SIZE);
        for (uint16_t i = 0; i < nb_rx; i++) {
            dissect_packet(bufs[i]);
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "rte_eal_init failed\n");
        return 1;
    }
    argc -= ret; argv += ret;

    uint16_t n_queues = rte_lcore_count();
    if (n_queues > MAX_QUEUES) n_queues = MAX_QUEUES;

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        fprintf(stderr, "mbuf pool creation failed\n");
        return 1;
    }

    if (port_init(0, mbuf_pool, n_queues) != 0) {
        fprintf(stderr, "port_init failed\n");
        return 1;
    }

    uint16_t queue_ids[MAX_QUEUES];
    uint16_t q = 0;
    unsigned lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (q >= n_queues) break;
        queue_ids[q] = q;
        rte_eal_remote_launch(lcore_worker, &queue_ids[q], lcore_id);
        q++;
    }

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_wait_lcore(lcore_id);
    }

    rte_eal_cleanup();
    return 0;
}
