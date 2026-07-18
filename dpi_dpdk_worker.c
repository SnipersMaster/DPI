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

/* Provides: parse_ipv6(), struct ipv6_result, parse_tcp_v6(),
 * parse_udp_v6(). Depends on checksum16()/struct tcp_result/
 * struct udp_result/parse_tcp_options()/TCP_MIN_HDR_BYTES/UDP_HDR_LEN
 * from dpi_rfc_parser.c above — must be included after it. */
#include "dpi_ipv6_parser.c"

/* Provides: struct tcp_flow_key, tcp_reassembly_insert(), TCP_OVERLAP_FIRST_WINS. */
#include "dpi_tcp_flow_reassembly.c"

/* Provides: classify_flow(), struct app_classification, and (via its
 * own #includes) domain classification, DGA scoring, VPN scoring, and
 * DoH/DoT scoring. */
#include "dpi_app_classifier.c"

/* Provides: struct dissect_result, dispatch_dissection(),
 * register_all_dissectors(), dissect_result_get(). register_all_dissectors()
 * calls register_radius_dissector() / register_quic_dissector() via
 * `extern` declarations — those resolve correctly as long as
 * dpi_radius_parser.c and dpi_quic_parser.c are included into this
 * same translation unit too (matching the single-TU #include pattern
 * used everywhere else in this project), which is why they're
 * included right below rather than compiled/linked separately. */
#include "dpi_dissector_registry.c"
#include "dpi_radius_parser.c"
#include "dpi_gtp_parser.c"
#include "dpi_dns_parser.c"
#include "dpi_http1_parser.c"
#include "dpi_http2_parser.c"

/* Provides: hpack_get_connection_table() — per-flow persistent HPACK
 * dynamic table, keyed by the same tcp_flow_key TCP reassembly uses.
 * Must come after both dpi_tcp_flow_reassembly.c (struct tcp_flow_key)
 * and dpi_http2_parser.c (struct hpack_dynamic_table, via
 * dpi_hpack_decoder.c). */
#include "dpi_hpack_connection_state.c"
#include "dpi_ssh_parser.c"
#include "dpi_dhcp_parser.c"
#include "dpi_sip_rtp_parser.c"
#include "dpi_icmp_parser.c"
#include "dpi_quic_parser.c"   /* needs OpenSSL — see this file's own header for
                                 * the -lssl -lcrypto build requirement */

/* Provides the lock-free per-lcore output ring buffer + drain thread
 * that replaces the hot-path printf() used before this change. */
#include "dpi_async_output.c"

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
/* Forward declaration: dissect_packet() calls this before its full
 * definition appears later in this file. */
static inline void dissect_udp_datagram(const struct ipv4_result *ip_result, uint16_t queue_id);
static inline void dissect_icmp_datagram(const struct ipv4_result *ip_result, uint16_t queue_id);
static inline void dissect_ipv6_packet(const uint8_t *ip_start, uint16_t ip_len, uint16_t queue_id);

static inline void dissect_packet(struct rte_mbuf *m, uint16_t queue_id) {
    uint16_t len = rte_pktmbuf_pkt_len(m);
    if (len < sizeof(struct rte_ether_hdr)) {
        rte_pktmbuf_free(m);
        return;
    }

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ethertype = rte_be_to_cpu_16(eth->ether_type);
    const uint8_t *ip_start = (const uint8_t *)(eth + 1);
    uint16_t ip_len = len - sizeof(struct rte_ether_hdr);

    if (ethertype == RTE_ETHER_TYPE_IPV6) {
        dissect_ipv6_packet(ip_start, ip_len, queue_id);
        rte_pktmbuf_free(m);
        return;
    }

    if (ethertype != RTE_ETHER_TYPE_IPV4) {
        rte_pktmbuf_free(m);   /* not IPv4 or IPv6: not handled */
        return;
    }

    struct ipv4_result ip_result;
    if (!parse_ipv4(ip_start, ip_len, &ip_result)) {
        rte_pktmbuf_free(m);   /* malformed or not-yet-reassembled fragment: drop here */
        return;
    }

    if (ip_result.protocol == 1 /* ICMP */) {
        dissect_icmp_datagram(&ip_result, queue_id);
        rte_pktmbuf_free(m);
        return;
    }

    if (ip_result.protocol == 17 /* UDP */) {
        dissect_udp_datagram(&ip_result, queue_id);
        rte_pktmbuf_free(m);
        return;
    }

    if (ip_result.protocol != 6 /* TCP */) {
        rte_pktmbuf_free(m);   /* neither TCP, UDP, nor ICMP: not handled */
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

    struct tcp_flow_key key = tcp_flow_key_make_v4(
        ip_result.src_addr, ip_result.dst_addr, tcp_result.src_port, tcp_result.dst_port);

    const uint8_t *contiguous_data = NULL;
    uint32_t contiguous_len = 0;
    struct tcp_reassembly_stats stats;

    /* queue_id doubles as the TCP reassembly partition_id — RSS
     * guarantees a flow's packets all land on this queue, so this
     * lcore never touches another lcore's partition of the flow
     * table. See the concurrency note in dpi_tcp_flow_reassembly.c
     * for why that matters (a real data race existed here before). */
    bool have_new_data = tcp_reassembly_insert(
        queue_id, &key, tcp_result.seq, tcp_result.payload, tcp_result.payload_len,
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

    /* Build the fixed-size record and push it onto THIS lcore's ring —
     * no I/O, no formatting, no blocking on this hot path. The drain
     * thread (dpi_async_output.c) does the actual printf-equivalent
     * work off-core. A full ring means this record is dropped and
     * counted, never blocks. */
    struct flow_log_record rec = {0};
    snprintf(rec.src_ip, sizeof(rec.src_ip), "%u.%u.%u.%u",
             (ip_result.src_addr >> 24) & 0xFF, (ip_result.src_addr >> 16) & 0xFF,
             (ip_result.src_addr >> 8) & 0xFF, ip_result.src_addr & 0xFF);
    snprintf(rec.dst_ip, sizeof(rec.dst_ip), "%u.%u.%u.%u",
             (ip_result.dst_addr >> 24) & 0xFF, (ip_result.dst_addr >> 16) & 0xFF,
             (ip_result.dst_addr >> 8) & 0xFF, ip_result.dst_addr & 0xFF);
    rec.src_port = tcp_result.src_port;
    rec.dst_port = tcp_result.dst_port;
    strncpy(rec.sni, classification.sni, sizeof(rec.sni) - 1);
    strncpy(rec.category, classification.category, sizeof(rec.category) - 1);
    strncpy(rec.app_name, classification.app_name, sizeof(rec.app_name) - 1);
    strncpy(rec.confidence, classification.confidence, sizeof(rec.confidence) - 1);
    rec.dga_score = classification.dga_score;
    rec.vpn_score = classification.vpn_score;
    strncpy(rec.vpn_protocol, classification.vpn_protocol, sizeof(rec.vpn_protocol) - 1);
    rec.dot_score = classification.dot_score;
    rec.doh_score = classification.doh_score;

    /* If no TLS ClientHello was found (category still "unknown"), this
     * might be plaintext HTTP/1.1, HTTP/2 (h2c), or SSH — try those
     * TCP-based dissectors now. THIS FIXES A REAL GAP found while
     * wiring HPACK connection persistence: dpi_http1_parser.c,
     * dpi_http2_parser.c, and dpi_ssh_parser.c were all registered
     * into the dissector registry, but nothing on this TCP path ever
     * actually called dispatch_dissection() against reassembled TCP
     * data — only classify_flow()'s TLS/SNI-specific path was called.
     * They were registered dead code. HTTP/2 gets special-cased (not
     * routed through the generic registry dispatch) specifically so it
     * can use the per-flow PERSISTENT HPACK table instead of a fresh
     * one — the same "handle outside the generic interface when the
     * generic interface doesn't fit" pattern used for TLS/SNI and for
     * ICMPv6's checksum. */
    if (strcmp(classification.category, "unknown") == 0) {
        double http2_confidence = http2_detect(contiguous_data, (uint16_t)contiguous_len,
                                                tcp_result.dst_port, "TCP");
        if (http2_confidence > 0.3) {
            struct hpack_dynamic_table *persistent_dyn =
                hpack_get_connection_table(queue_id, &key);
            struct dissect_result h2_out;
            memset(&h2_out, 0, sizeof(h2_out));
            http2_dissect_with_flow_state(contiguous_data, (uint16_t)contiguous_len,
                                           persistent_dyn, &h2_out);

            strncpy(rec.category, "HTTP/2", sizeof(rec.category) - 1);
            const char *authority = dissect_result_get(&h2_out, "http2_authority");
            if (authority) {
                strncpy(rec.app_name, authority, sizeof(rec.app_name) - 1);
                strncpy(rec.confidence, "high", sizeof(rec.confidence) - 1);
            } else {
                strncpy(rec.confidence, "low", sizeof(rec.confidence) - 1);
            }
        } else {
            struct dissect_result tcp_out;
            bool tcp_matched = dispatch_dissection(contiguous_data, contiguous_len,
                                                    tcp_result.dst_port, "TCP", &tcp_out);
            if (tcp_matched) {
                strncpy(rec.category, tcp_out.protocol_name, sizeof(rec.category) - 1);
                const char *identity = dissect_result_get(&tcp_out, "http_host");
                if (!identity) identity = dissect_result_get(&tcp_out, "ssh_software_version");
                if (identity) strncpy(rec.app_name, identity, sizeof(rec.app_name) - 1);
                strncpy(rec.confidence, "high", sizeof(rec.confidence) - 1);
            }
        }
    }

    rec.out_of_order_segments = stats.out_of_order_segments;
    rec.retransmit_count = stats.retransmit_count;
    rec.overlap_conflict_count = stats.overlap_conflict_count;
    rec.evasion_flag = stats.evasion_flag;

    log_ring_try_push(queue_id, &rec);
}

/* -----------------------------------------------------------------
 * UDP path: no reassembly (UDP is datagram-oriented — each datagram
 * is independent, nothing to reassemble across packets), so this goes
 * straight to the pluggable dissector registry, which tries RADIUS
 * and QUIC's detect() functions and dissects with whichever matches.
 * VPN protocol fingerprinting (WireGuard/IKE, also UDP) is layered in
 * alongside the registry's result rather than through it, since
 * dpi_vpn_detector.c is a scoring overlay, not a dissect_result-
 * producing dissector in the registry's sense.
 * ----------------------------------------------------------------- */
static inline void dissect_icmp_datagram(const struct ipv4_result *ip_result, uint16_t queue_id) {
    if (ip_result->payload_len == 0) return;

    struct dissect_result dissect_out;
    bool matched = dispatch_dissection(ip_result->payload, ip_result->payload_len,
                                        0, "ICMP", &dissect_out);
    if (!matched) return;

    char src_ip_str[16], dst_ip_str[16];
    snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
             (ip_result->src_addr >> 24) & 0xFF, (ip_result->src_addr >> 16) & 0xFF,
             (ip_result->src_addr >> 8) & 0xFF, ip_result->src_addr & 0xFF);
    snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
             (ip_result->dst_addr >> 24) & 0xFF, (ip_result->dst_addr >> 16) & 0xFF,
             (ip_result->dst_addr >> 8) & 0xFF, ip_result->dst_addr & 0xFF);

    struct flow_log_record rec = {0};
    strncpy(rec.src_ip, src_ip_str, sizeof(rec.src_ip) - 1);
    strncpy(rec.dst_ip, dst_ip_str, sizeof(rec.dst_ip) - 1);
    strncpy(rec.category, "ICMP", sizeof(rec.category) - 1);
    /* flow_log_record's fixed fields don't have a dedicated slot for
     * every ICMP-specific field (type/code/echo id-seq/etc) — same
     * limitation every dissector with more fields than the fixed
     * record has hits. app_name is repurposed here to carry the ICMP
     * type name specifically, since that's the single most useful
     * summary field for this protocol. */
    const char *icmp_type = dissect_result_get(&dissect_out, "icmp_type");
    if (icmp_type) strncpy(rec.app_name, icmp_type, sizeof(rec.app_name) - 1);
    strncpy(rec.confidence, "high", sizeof(rec.confidence) - 1);

    log_ring_try_push(queue_id, &rec);
}

static inline void dissect_udp_datagram(const struct ipv4_result *ip_result, uint16_t queue_id) {
    struct udp_result udp_result;
    if (!parse_udp(ip_result->src_addr, ip_result->dst_addr,
                    ip_result->payload, ip_result->payload_len, &udp_result)) {
        return;
    }
    if (udp_result.payload_len == 0) return;

    struct dissect_result dissect_out;
    bool matched = dispatch_dissection(udp_result.payload, udp_result.payload_len,
                                        udp_result.dst_port, "UDP", &dissect_out);

    struct vpn_result vpn;
    score_vpn_traffic(udp_result.payload, udp_result.payload_len,
                       udp_result.dst_port, "UDP", NULL, &vpn);

    /* If QUIC matched and extracted an SNI, run it through the same
     * domain classification and DGA scoring the TCP path uses — a
     * QUIC flow deserves the same treatment as a TLS-over-TCP flow,
     * not a lesser one just because it arrived via a different
     * capture branch. */
    struct flow_log_record rec = {0};
    snprintf(rec.src_ip, sizeof(rec.src_ip), "%u.%u.%u.%u",
             (ip_result->src_addr >> 24) & 0xFF, (ip_result->src_addr >> 16) & 0xFF,
             (ip_result->src_addr >> 8) & 0xFF, ip_result->src_addr & 0xFF);
    snprintf(rec.dst_ip, sizeof(rec.dst_ip), "%u.%u.%u.%u",
             (ip_result->dst_addr >> 24) & 0xFF, (ip_result->dst_addr >> 16) & 0xFF,
             (ip_result->dst_addr >> 8) & 0xFF, ip_result->dst_addr & 0xFF);
    rec.src_port = udp_result.src_port;
    rec.dst_port = udp_result.dst_port;
    rec.vpn_score = vpn.score;
    strncpy(rec.vpn_protocol, vpn.detected_protocol, sizeof(rec.vpn_protocol) - 1);

    if (matched) {
        strncpy(rec.category, dissect_out.protocol_name, sizeof(rec.category) - 1);

        const char *sni = dissect_result_get(&dissect_out, "sni");
        if (sni) {
            strncpy(rec.sni, sni, sizeof(rec.sni) - 1);

            struct classification_result cls;
            classify_hostname(sni, &cls);
            if (cls.matched) {
                strncpy(rec.app_name, cls.app_name, sizeof(rec.app_name) - 1);
                strncpy(rec.confidence, "high", sizeof(rec.confidence) - 1);
            } else {
                strncpy(rec.confidence, "low", sizeof(rec.confidence) - 1);
            }

            struct dga_result dga;
            score_dga(sni, &dga);
            rec.dga_score = dga.score;
        } else {
            strncpy(rec.confidence, "none", sizeof(rec.confidence) - 1);
        }
    } else {
        strncpy(rec.category, "unknown", sizeof(rec.category) - 1);
        strncpy(rec.confidence, "none", sizeof(rec.confidence) - 1);
    }

    log_ring_try_push(queue_id, &rec);
}

/* -----------------------------------------------------------------
 * IPv6 entry point. Both UDP and TCP get full treatment now.
 *
 * UDP-over-IPv6: dispatch_dissection() and score_vpn_traffic() are
 * IP-version-agnostic (they operate on the L4 payload + port +
 * protocol string, nothing IPv4-specific), so RADIUS/QUIC/GTP/DNS/
 * DHCP/SIP/RTP and VPN fingerprinting all work over IPv6 exactly as
 * they do over IPv4 with no extra code.
 *
 * TCP-over-IPv6: previously deferred (an earlier version of this
 * comment said so, at length) because dpi_tcp_flow_reassembly.c's
 * flow key used 32-bit fields sized for IPv4 addresses only.
 * struct tcp_flow_key was extended to hold 128-bit addresses with an
 * explicit ip_version tag (see that file), so TCP-over-IPv6 now goes
 * through the identical reassembly → classification pipeline as the
 * IPv4 path below, just constructing the key via
 * tcp_flow_key_make_v6() instead of _make_v4().
 * ----------------------------------------------------------------- */
static inline void dissect_ipv6_packet(const uint8_t *ip_start, uint16_t ip_len, uint16_t queue_id) {
    struct ipv6_result ip6_result;
    if (!parse_ipv6(ip_start, ip_len, &ip6_result)) return;

    char src_str[46], dst_str[46];
    ipv6_addr_to_string(ip6_result.src_addr, src_str, sizeof(src_str));
    ipv6_addr_to_string(ip6_result.dst_addr, dst_str, sizeof(dst_str));

    if (ip6_result.next_header == 58 /* ICMPv6 */) {
        if (ip6_result.payload_len == 0) return;

        struct dissect_result dissect_out;
        bool matched = dispatch_dissection(ip6_result.payload, ip6_result.payload_len,
                                            0, "ICMPv6", &dissect_out);
        if (!matched) return;

        /* ICMPv6 checksum verification happens HERE, not inside
         * icmpv6_dissect() — see dpi_icmp_parser.c's header comment
         * for why: it needs the IPv6 pseudo-header (RFC 8200 S8.1),
         * which requires the src/dst addresses this capture-path
         * function has but the generic dissector interface doesn't
         * pass through. Reuses the same pseudo-header helper already
         * built for UDP/TCP-over-IPv6 checksum verification. */
        bool icmpv6_checksum_valid = false;
        if (ip6_result.payload_len >= 4 && ip6_result.payload_len <= 1500) {
            uint8_t scratch[1500];
            memcpy(scratch, ip6_result.payload, ip6_result.payload_len);
            uint16_t orig_checksum = (scratch[2] << 8) | scratch[3];
            scratch[2] = 0; scratch[3] = 0;
            uint32_t partial = ipv6_pseudo_header_partial(
                ip6_result.src_addr, ip6_result.dst_addr, ip6_result.payload_len, 58);
            uint16_t computed = checksum16(scratch, ip6_result.payload_len, partial);
            icmpv6_checksum_valid = (computed == orig_checksum);
        }
        dissect_result_add(&dissect_out, "icmpv6_checksum_valid",
                            icmpv6_checksum_valid ? "true" : "false");

        struct flow_log_record rec = {0};
        strncpy(rec.src_ip, src_str, sizeof(rec.src_ip) - 1);
        strncpy(rec.dst_ip, dst_str, sizeof(rec.dst_ip) - 1);
        strncpy(rec.category, "ICMPv6", sizeof(rec.category) - 1);
        const char *icmpv6_type = dissect_result_get(&dissect_out, "icmpv6_type");
        if (icmpv6_type) strncpy(rec.app_name, icmpv6_type, sizeof(rec.app_name) - 1);
        strncpy(rec.confidence, icmpv6_checksum_valid ? "high" : "low", sizeof(rec.confidence) - 1);

        log_ring_try_push(queue_id, &rec);
        return;
    }

    if (ip6_result.next_header == 17 /* UDP */) {
        struct udp_result udp_result;
        if (!parse_udp_v6(ip6_result.src_addr, ip6_result.dst_addr,
                           ip6_result.payload, ip6_result.payload_len, &udp_result)) {
            return;
        }
        if (udp_result.payload_len == 0) return;

        struct dissect_result dissect_out;
        bool matched = dispatch_dissection(udp_result.payload, udp_result.payload_len,
                                            udp_result.dst_port, "UDP", &dissect_out);

        struct vpn_result vpn;
        score_vpn_traffic(udp_result.payload, udp_result.payload_len,
                           udp_result.dst_port, "UDP", NULL, &vpn);

        struct flow_log_record rec = {0};
        strncpy(rec.src_ip, src_str, sizeof(rec.src_ip) - 1);
        strncpy(rec.dst_ip, dst_str, sizeof(rec.dst_ip) - 1);
        rec.src_port = udp_result.src_port;
        rec.dst_port = udp_result.dst_port;
        rec.vpn_score = vpn.score;
        strncpy(rec.vpn_protocol, vpn.detected_protocol, sizeof(rec.vpn_protocol) - 1);

        if (matched) {
            strncpy(rec.category, dissect_out.protocol_name, sizeof(rec.category) - 1);
            const char *sni = dissect_result_get(&dissect_out, "sni");
            if (sni) {
                strncpy(rec.sni, sni, sizeof(rec.sni) - 1);
                struct classification_result cls;
                classify_hostname(sni, &cls);
                strncpy(rec.confidence, cls.matched ? "high" : "low", sizeof(rec.confidence) - 1);
                if (cls.matched) strncpy(rec.app_name, cls.app_name, sizeof(rec.app_name) - 1);
                struct dga_result dga;
                score_dga(sni, &dga);
                rec.dga_score = dga.score;
            } else {
                strncpy(rec.confidence, "none", sizeof(rec.confidence) - 1);
            }
        } else {
            strncpy(rec.category, "unknown", sizeof(rec.category) - 1);
            strncpy(rec.confidence, "none", sizeof(rec.confidence) - 1);
        }

        log_ring_try_push(queue_id, &rec);
        return;
    }

    if (ip6_result.next_header == 6 /* TCP */) {
        struct tcp_result tcp_result;
        if (!parse_tcp_v6(ip6_result.src_addr, ip6_result.dst_addr,
                           ip6_result.payload, ip6_result.payload_len, &tcp_result)) {
            return;
        }
        if (tcp_result.payload_len == 0) return;   /* pure ACK/control segment */

        /* This is the piece that was previously deferred — flagged
         * repeatedly as the single largest gap in IPv6 support. Now
         * wired identically to the IPv4 TCP path: same reassembly
         * partition scheme (queue_id doubles as partition_id, same
         * RSS-pinning argument as the v4 path), same is_first_delivery
         * gating, same classification pipeline. The only difference is
         * constructing the key via tcp_flow_key_make_v6() instead of
         * _make_v4(). */
        struct tcp_flow_key key = tcp_flow_key_make_v6(
            ip6_result.src_addr, ip6_result.dst_addr, tcp_result.src_port, tcp_result.dst_port);

        const uint8_t *contiguous_data = NULL;
        uint32_t contiguous_len = 0;
        struct tcp_reassembly_stats stats;

        bool have_new_data = tcp_reassembly_insert(
            queue_id, &key, tcp_result.seq, tcp_result.payload, tcp_result.payload_len,
            TCP_OVERLAP_FIRST_WINS, &contiguous_data, &contiguous_len, &stats);

        if (!have_new_data || !stats.is_first_delivery) return;

        struct app_classification classification;
        classify_flow(contiguous_data, contiguous_len,
                      tcp_result.dst_port, "TCP", &classification);

        struct flow_log_record rec = {0};
        strncpy(rec.src_ip, src_str, sizeof(rec.src_ip) - 1);
        strncpy(rec.dst_ip, dst_str, sizeof(rec.dst_ip) - 1);
        rec.src_port = tcp_result.src_port;
        rec.dst_port = tcp_result.dst_port;
        strncpy(rec.sni, classification.sni, sizeof(rec.sni) - 1);
        strncpy(rec.category, classification.category, sizeof(rec.category) - 1);
        strncpy(rec.app_name, classification.app_name, sizeof(rec.app_name) - 1);
        strncpy(rec.confidence, classification.confidence, sizeof(rec.confidence) - 1);
        rec.dga_score = classification.dga_score;
        rec.vpn_score = classification.vpn_score;
        strncpy(rec.vpn_protocol, classification.vpn_protocol, sizeof(rec.vpn_protocol) - 1);
        rec.dot_score = classification.dot_score;
        rec.doh_score = classification.doh_score;

        /* Same TCP-based dissector dispatch as the IPv4 TCP path above
         * (HTTP/1.1, HTTP/2 with persistent HPACK state, SSH) — see
         * that copy's comment for the full rationale on why HTTP/2 is
         * special-cased and why this matters at all (a real gap where
         * these dissectors were registered but never invoked). */
        if (strcmp(classification.category, "unknown") == 0) {
            double http2_confidence = http2_detect(contiguous_data, (uint16_t)contiguous_len,
                                                    tcp_result.dst_port, "TCP");
            if (http2_confidence > 0.3) {
                struct hpack_dynamic_table *persistent_dyn =
                    hpack_get_connection_table(queue_id, &key);
                struct dissect_result h2_out;
                memset(&h2_out, 0, sizeof(h2_out));
                http2_dissect_with_flow_state(contiguous_data, (uint16_t)contiguous_len,
                                               persistent_dyn, &h2_out);

                strncpy(rec.category, "HTTP/2", sizeof(rec.category) - 1);
                const char *authority = dissect_result_get(&h2_out, "http2_authority");
                if (authority) {
                    strncpy(rec.app_name, authority, sizeof(rec.app_name) - 1);
                    strncpy(rec.confidence, "high", sizeof(rec.confidence) - 1);
                } else {
                    strncpy(rec.confidence, "low", sizeof(rec.confidence) - 1);
                }
            } else {
                struct dissect_result tcp_out;
                bool tcp_matched = dispatch_dissection(contiguous_data, contiguous_len,
                                                        tcp_result.dst_port, "TCP", &tcp_out);
                if (tcp_matched) {
                    strncpy(rec.category, tcp_out.protocol_name, sizeof(rec.category) - 1);
                    const char *identity = dissect_result_get(&tcp_out, "http_host");
                    if (!identity) identity = dissect_result_get(&tcp_out, "ssh_software_version");
                    if (identity) strncpy(rec.app_name, identity, sizeof(rec.app_name) - 1);
                    strncpy(rec.confidence, "high", sizeof(rec.confidence) - 1);
                }
            }
        }

        rec.out_of_order_segments = stats.out_of_order_segments;
        rec.retransmit_count = stats.retransmit_count;
        rec.overlap_conflict_count = stats.overlap_conflict_count;
        rec.evasion_flag = stats.evasion_flag;

        log_ring_try_push(queue_id, &rec);
        return;
    }

    /* Other next_header values (ICMPv6, ESP, AH, etc.): not handled. */
}
static int lcore_worker(void *arg) {
    uint16_t queue_id = *(uint16_t *)arg;
    uint16_t port_id = 0;
    struct rte_mbuf *bufs[BURST_SIZE];

    printf("lcore %u polling queue %u\n", rte_lcore_id(), queue_id);

    while (!force_quit) {
        uint16_t nb_rx = rte_eth_rx_burst(port_id, queue_id, bufs, BURST_SIZE);
        for (uint16_t i = 0; i < nb_rx; i++) {
            dissect_packet(bufs[i], queue_id);
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

    /* App-specific argument (after EAL's own args, which rte_eal_init
     * already consumed above): the output sink config string, e.g.
     *   ./dpi_dpdk_worker -l 0-7 -n 4 -- file:/var/log/dpi/flows.log
     *   ./dpi_dpdk_worker -l 0-7 -n 4 -- syslog:daemon
     *   ./dpi_dpdk_worker -l 0-7 -n 4 -- unix:/var/run/dpi/output.sock
     * Defaults to a file sink in a conventional location if not given —
     * chosen over defaulting to stdout so a real deployment doesn't
     * accidentally end up writing flow records to whatever stdout
     * happens to be redirected to. */
    const char *sink_config = (argc > 1) ? argv[1] : "file:/var/log/dpi/flows.log";

    uint16_t n_queues = rte_lcore_count();
    if (n_queues > MAX_QUEUES) n_queues = MAX_QUEUES;
    if (n_queues > TCP_REASSEMBLY_NUM_PARTITIONS) {
        /* Each queue_id doubles as a flow-table partition index — see
         * the concurrency note in dpi_tcp_flow_reassembly.c. Running
         * with more queues than partitions would mean two lcores
         * sharing a partition, reintroducing the exact race that
         * partitioning was added to eliminate. Fail loudly rather
         * than silently degrade into unsafe behavior. */
        fprintf(stderr, "FATAL: %u queues exceeds TCP_REASSEMBLY_NUM_PARTITIONS (%d) — "
                "either reduce lcore count or increase that constant and its "
                "memory footprint accordingly (see dpi_tcp_flow_reassembly.c)\n",
                n_queues, TCP_REASSEMBLY_NUM_PARTITIONS);
        return 1;
    }

    /* Register RADIUS/QUIC/GTP/DNS dissectors ONCE, before any lcore
     * starts. dpi_dissector_registry.c's g_registry array is read-only
     * after this point — safe for concurrent lcore reads with no
     * locking, but only because nothing writes to it after this call
     * completes and before the RX loops begin. */
    register_all_dissectors();

    /* Start the async output drain thread BEFORE workers begin
     * producing records — see dpi_async_output.c for why this is a
     * plain pthread rather than another DPDK lcore (it does blocking
     * I/O, which has no place on an isolated poll-mode core). */
    if (!async_output_start(sink_config)) {
        fprintf(stderr, "failed to start async output thread\n");
        return 1;
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) {
        fprintf(stderr, "mbuf pool creation failed\n");
        async_output_stop();
        return 1;
    }

    if (port_init(0, mbuf_pool, n_queues) != 0) {
        fprintf(stderr, "port_init failed\n");
        async_output_stop();
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

    /* Stop the drain thread AFTER all producer lcores have exited, so
     * any records still in flight at shutdown get flushed rather than
     * silently dropped — see output_drain_thread()'s final drain pass
     * in dpi_async_output.c. */
    async_output_stop();

    rte_eal_cleanup();
    return 0;
}
