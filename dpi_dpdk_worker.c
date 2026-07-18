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

    if (ethertype == RTE_ETHER_TYPE_IPV4) {
        if (len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)) {
            rte_pktmbuf_free(m);
            return;
        }
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
        uint16_t remaining = len - sizeof(struct rte_ether_hdr);
        if (ihl < sizeof(struct rte_ipv4_hdr) || ihl > remaining) {
            rte_pktmbuf_free(m);   /* malformed IHL: drop, don't clamp and continue */
            return;
        }
        /* Hand off to protocol-specific dissector here, applying the
         * same length-before-read discipline at every layer. */
    }

    rte_pktmbuf_free(m);
}

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
