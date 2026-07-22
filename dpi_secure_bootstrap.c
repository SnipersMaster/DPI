/*
 * dpi_secure_bootstrap.c
 *
 * Reference skeleton for a Linux DPI engine's security-critical startup path.
 * This is NOT a full DPI engine — it demonstrates the four protocols from the
 * checklist that matter most before you write a single dissector:
 *
 *   1. Open the raw capture socket while still root
 *   2. Drop privileges immediately after (setgroups -> setgid -> setuid)
 *   3. Restrict syscalls with seccomp-bpf before touching any packet data
 *   4. Parse packets with strict, explicit bounds checks
 *
 * Build (requires dev packages, e.g. `apt install libseccomp-dev libcap-dev`):
 *   gcc -O2 -Wall -Wextra -o dpi_bootstrap dpi_secure_bootstrap.c -lseccomp -lcap
 *
 * Run (needs CAP_NET_RAW, not full root — see setcap note at bottom):
 *   sudo setcap cap_net_raw,cap_net_admin=eip ./dpi_bootstrap
 *   ./dpi_bootstrap eth0
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <seccomp.h>

#define UNPRIV_USER   "dpi-svc"     /* dedicated, shell-less service account */
#define SNAPLEN       65535
#define ETH_HDR_LEN   14

/* Provides: parse_ipv4(), parse_tcp(), parse_udp(), struct ipv4_result,
 * struct tcp_result, struct udp_result.
 * Provides: struct tcp_flow_key, tcp_reassembly_insert(), TCP_OVERLAP_FIRST_WINS.
 * Provides: classify_flow(), struct app_classification (+ domain/DGA/VPN/
 * DoH-DoT scoring via app_classifier's own #includes).
 * Provides: struct dissect_result, dispatch_dissection(),
 * register_all_dissectors(), dissect_result_get() (RADIUS + QUIC).
 * Same file set as dpi_dpdk_worker.c — see that file's comments for
 * the full rationale on each; not repeated here. This file doesn't
 * need dpi_async_output.c, since single-threaded printf() is fine at
 * this scale (see the note where it's used below). */
#include "dpi_vlan_parser.c"
#include "dpi_rfc_parser.c"

/* Provides: parse_ipv6(), struct ipv6_result, parse_tcp_v6(), parse_udp_v6(). */
#include "dpi_ipv6_parser.c"

#include "dpi_tcp_flow_reassembly.c"
#include "dpi_app_classifier.c"
#include "dpi_dissector_registry.c"
#include "dpi_radius_parser.c"
#include "dpi_gtp_parser.c"
#include "dpi_dns_parser.c"
#include "dpi_http1_parser.c"
#include "dpi_hpack_connection_state.c"
#include "dpi_http2_parser.c"
#include "dpi_ssh_parser.c"
#include "dpi_dhcp_parser.c"
#include "dpi_sip_rtp_parser.c"
#include "dpi_icmp_parser.c"
#include "dpi_gre_parser.c"
#include "dpi_mpls_parser.c"
#include "dpi_ospf_parser.c"
#include "dpi_igmp_parser.c"
#include "dpi_rip_parser.c"
#include "dpi_ssdp_parser.c"
#include "dpi_syslog_parser.c"
#include "dpi_mdns_parser.c"
#include "dpi_esp_parser.c"
#include "dpi_hsrp_parser.c"
#include "dpi_6in4_parser.c"
#include "dpi_isakmp_parser.c"
#include "dpi_ldp_parser.c"
#include "dpi_eigrp_parser.c"
#include "dpi_s7comm_parser.c"
#include "dpi_telnet_parser.c"
#include "dpi_ah_parser.c"
#include "dpi_netbios_parser.c"
#include "dpi_pop3_parser.c"
#include "dpi_msnp_parser.c"
#include "dpi_smb1_parser.c"
#include "dpi_bgp_parser.c"
#include "dpi_ldap_parser.c"
#include "dpi_ftp_parser.c"
#include "dpi_smtp_parser.c"
#include "dpi_arp_parser.c"
#include "dpi_mqtt_parser.c"
#include "dpi_ntp_parser.c"
#include "dpi_snmp_parser.c"
#include "dpi_stun_parser.c"
#include "dpi_modbus_parser.c"
#include "dpi_dnp3_parser.c"
#include "dpi_quic_parser.c"

/* ---------------------------------------------------------------------
 * 1. Open the raw capture socket while still root.
 *    Bind to a specific interface, not the whole machine, and keep this
 *    the ONLY privileged operation in the program.
 * --------------------------------------------------------------------- */
static int open_capture_socket(const char *ifname) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket(AF_PACKET) - do you have CAP_NET_RAW?");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(sock);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

/* ---------------------------------------------------------------------
 * 2. Drop privileges immediately after the socket is open.
 *    Order matters: setgroups -> setgid -> setuid. Reversing this order
 *    leaves the process able to reclaim root via a lingering group.
 * --------------------------------------------------------------------- */
static int drop_privileges(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "drop_privileges: user '%s' not found. "
                        "Create it: useradd -r -s /usr/sbin/nologin %s\n",
                username, username);
        return -1;
    }

    if (setgroups(0, NULL) != 0) { perror("setgroups"); return -1; }
    if (setgid(pw->pw_gid) != 0) { perror("setgid");     return -1; }
    if (setuid(pw->pw_uid) != 0) { perror("setuid");     return -1; }

    /* Verify the drop actually worked. Never assume; check. */
    if (setuid(0) == 0) {
        fprintf(stderr, "FATAL: privilege drop failed, still able to regain root\n");
        return -1;
    }

    fprintf(stderr, "privileges dropped: now running as uid=%d gid=%d\n",
            getuid(), getgid());
    return 0;
}

/* ---------------------------------------------------------------------
 * 3. Restrict syscalls with seccomp-bpf before any packet parsing runs.
 *    Allowlist only what the capture+parse loop actually needs. Extend
 *    this list deliberately, not by trial-and-error against denials.
 * --------------------------------------------------------------------- */
static int install_seccomp_filter(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        fprintf(stderr, "seccomp_init failed\n");
        return -1;
    }

    int allowed[] = {
        SCMP_SYS(read), SCMP_SYS(recvfrom), SCMP_SYS(recvmsg),
        SCMP_SYS(write), SCMP_SYS(sendto),
        SCMP_SYS(close), SCMP_SYS(exit), SCMP_SYS(exit_group),
        SCMP_SYS(brk), SCMP_SYS(mmap), SCMP_SYS(munmap),
        SCMP_SYS(rt_sigreturn), SCMP_SYS(nanosleep),
        SCMP_SYS(clock_gettime), SCMP_SYS(gettimeofday),
    };

    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed[i], 0) < 0) {
            fprintf(stderr, "seccomp_rule_add failed for syscall index %zu\n", i);
            seccomp_release(ctx);
            return -1;
        }
    }

    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "seccomp_load failed\n");
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    fprintf(stderr, "seccomp filter active: any other syscall now kills the process\n");
    return 0;
}

/* ---------------------------------------------------------------------
 * 4. Parse with strict, explicit bounds checks.
 *    This is the pattern to repeat for every protocol dissector: never
 *    trust a length field until it's validated against the buffer you
 *    actually have.
 * --------------------------------------------------------------------- */
static void dissect_udp_datagram(const struct ipv4_result *ip_result);
static void dissect_ipv6_packet(const uint8_t *ip_start, uint16_t ip_len);
static void dissect_icmp_datagram(const struct ipv4_result *ip_result);
static void dissect_gre_datagram(const struct ipv4_result *ip_result);
static void dissect_ospf_datagram(const struct ipv4_result *ip_result);
static void dissect_igmp_datagram(const struct ipv4_result *ip_result);
static void dissect_esp_datagram(const struct ipv4_result *ip_result);
static void dissect_sixin4_datagram(const struct ipv4_result *ip_result);
static void dissect_eigrp_datagram(const struct ipv4_result *ip_result);
static void dissect_ah_datagram(const struct ipv4_result *ip_result);

static void dissect_icmp_datagram(const struct ipv4_result *ip_result) {
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

    const char *icmp_type = dissect_result_get(&dissect_out, "icmp_type");
    const char *icmp_code = dissect_result_get(&dissect_out, "icmp_code");
    const char *checksum_valid = dissect_result_get(&dissect_out, "icmp_checksum_valid");

    printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"ICMP\","
           "\"icmp_type\":\"%s\",\"icmp_code\":\"%s\",\"icmp_checksum_valid\":\"%s\"}\n",
           src_ip_str, dst_ip_str,
           icmp_type ? icmp_type : "", icmp_code ? icmp_code : "",
           checksum_valid ? checksum_valid : "");
}

static void dissect_gre_datagram(const struct ipv4_result *ip_result) {
    if (ip_result->payload_len == 0) return;

    struct dissect_result dissect_out;
    bool matched = dispatch_dissection(ip_result->payload, ip_result->payload_len,
                                        0, "GRE", &dissect_out);
    if (!matched) return;

    char src_ip_str[16], dst_ip_str[16];
    snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
             (ip_result->src_addr >> 24) & 0xFF, (ip_result->src_addr >> 16) & 0xFF,
             (ip_result->src_addr >> 8) & 0xFF, ip_result->src_addr & 0xFF);
    snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
             (ip_result->dst_addr >> 24) & 0xFF, (ip_result->dst_addr >> 16) & 0xFF,
             (ip_result->dst_addr >> 8) & 0xFF, ip_result->dst_addr & 0xFF);

    const char *protocol_type = dissect_result_get(&dissect_out, "gre_protocol_type");
    const char *inner_src = dissect_result_get(&dissect_out, "gre_inner_src_ip");
    const char *inner_dst = dissect_result_get(&dissect_out, "gre_inner_dst_ip");
    const char *inner_sni = dissect_result_get(&dissect_out, "gre_inner_sni");
    const char *erspan = dissect_result_get(&dissect_out, "gre_erspan_detected");
    const char *keepalive = dissect_result_get(&dissect_out, "gre_keepalive_likely");

    printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"GRE\","
           "\"gre_protocol_type\":\"%s\",\"gre_inner_src_ip\":\"%s\","
           "\"gre_inner_dst_ip\":\"%s\",\"gre_inner_sni\":\"%s\","
           "\"gre_erspan_detected\":\"%s\",\"gre_keepalive_likely\":\"%s\"}\n",
           src_ip_str, dst_ip_str,
           protocol_type ? protocol_type : "", inner_src ? inner_src : "",
           inner_dst ? inner_dst : "", inner_sni ? inner_sni : "",
           erspan ? erspan : "false", keepalive ? keepalive : "false");
}

static void dissect_ospf_datagram(const struct ipv4_result *ip_result) {
    if (ip_result->payload_len == 0) return;

    struct dissect_result dissect_out;
    bool matched = dispatch_dissection(ip_result->payload, ip_result->payload_len,
                                        0, "OSPF", &dissect_out);
    if (!matched) return;

    char src_ip_str[16], dst_ip_str[16];
    snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
             (ip_result->src_addr >> 24) & 0xFF, (ip_result->src_addr >> 16) & 0xFF,
             (ip_result->src_addr >> 8) & 0xFF, ip_result->src_addr & 0xFF);
    snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
             (ip_result->dst_addr >> 24) & 0xFF, (ip_result->dst_addr >> 16) & 0xFF,
             (ip_result->dst_addr >> 8) & 0xFF, ip_result->dst_addr & 0xFF);

    const char *version = dissect_result_get(&dissect_out, "ospf_version");
    const char *type = dissect_result_get(&dissect_out, "ospf_type");
    const char *router_id = dissect_result_get(&dissect_out, "ospf_router_id");
    const char *area_id = dissect_result_get(&dissect_out, "ospf_area_id");

    printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"OSPF\","
           "\"ospf_version\":\"%s\",\"ospf_type\":\"%s\","
           "\"ospf_router_id\":\"%s\",\"ospf_area_id\":\"%s\"}\n",
           src_ip_str, dst_ip_str,
           version ? version : "", type ? type : "",
           router_id ? router_id : "", area_id ? area_id : "");
}

static void dissect_igmp_datagram(const struct ipv4_result *ip_result) {
    if (ip_result->payload_len == 0) return;

    struct dissect_result dissect_out;
    bool matched = dispatch_dissection(ip_result->payload, ip_result->payload_len,
                                        0, "IGMP", &dissect_out);
    if (!matched) return;

    char src_ip_str[16], dst_ip_str[16];
    snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
             (ip_result->src_addr >> 24) & 0xFF, (ip_result->src_addr >> 16) & 0xFF,
             (ip_result->src_addr >> 8) & 0xFF, ip_result->src_addr & 0xFF);
    snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
             (ip_result->dst_addr >> 24) & 0xFF, (ip_result->dst_addr >> 16) & 0xFF,
             (ip_result->dst_addr >> 8) & 0xFF, ip_result->dst_addr & 0xFF);

    const char *igmp_type = dissect_result_get(&dissect_out, "igmp_type");
    const char *group = dissect_result_get(&dissect_out, "igmp_group_address");

    printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"IGMP\","
           "\"igmp_type\":\"%s\",\"igmp_group_address\":\"%s\"}\n",
           src_ip_str, dst_ip_str,
           igmp_type ? igmp_type : "", group ? group : "");
}

static void dissect_esp_datagram(const struct ipv4_result *ip_result) {
    if (ip_result->payload_len == 0) return;

    struct dissect_result dissect_out;
    bool matched = dispatch_dissection(ip_result->payload, ip_result->payload_len,
                                        0, "ESP", &dissect_out);
    if (!matched) return;

    char src_ip_str[16], dst_ip_str[16];
    snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
             (ip_result->src_addr >> 24) & 0xFF, (ip_result->src_addr >> 16) & 0xFF,
             (ip_result->src_addr >> 8) & 0xFF, ip_result->src_addr & 0xFF);
    snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
             (ip_result->dst_addr >> 24) & 0xFF, (ip_result->dst_addr >> 16) & 0xFF,
             (ip_result->dst_addr >> 8) & 0xFF, ip_result->dst_addr & 0xFF);

    const char *spi = dissect_result_get(&dissect_out, "esp_spi");
    const char *seq = dissect_result_get(&dissect_out, "esp_sequence");

    printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"ESP\","
           "\"esp_spi\":\"%s\",\"esp_sequence\":\"%s\"}\n",
           src_ip_str, dst_ip_str,
           spi ? spi : "", seq ? seq : "");
}

static void dissect_sixin4_datagram(const struct ipv4_result *ip_result) {
    if (ip_result->payload_len == 0) return;

    struct dissect_result dissect_out;
    bool matched = dispatch_dissection(ip_result->payload, ip_result->payload_len,
                                        0, "6in4", &dissect_out);
    if (!matched) return;

    const char *inner_src = dissect_result_get(&dissect_out, "sixin4_inner_src_ip");
    const char *inner_dst = dissect_result_get(&dissect_out, "sixin4_inner_dst_ip");
    const char *inner_proto = dissect_result_get(&dissect_out, "sixin4_inner_protocol");
    const char *inner_sni = dissect_result_get(&dissect_out, "sixin4_inner_sni");

    printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"6in4\","
           "\"sixin4_inner_protocol\":\"%s\",\"sixin4_inner_sni\":\"%s\"}\n",
           inner_src ? inner_src : "", inner_dst ? inner_dst : "",
           inner_proto ? inner_proto : "", inner_sni ? inner_sni : "");
}

static void dissect_eigrp_datagram(const struct ipv4_result *ip_result) {
    if (ip_result->payload_len == 0) return;

    struct dissect_result dissect_out;
    bool matched = dispatch_dissection(ip_result->payload, ip_result->payload_len,
                                        0, "EIGRP", &dissect_out);
    if (!matched) return;

    char src_ip_str[16], dst_ip_str[16];
    snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
             (ip_result->src_addr >> 24) & 0xFF, (ip_result->src_addr >> 16) & 0xFF,
             (ip_result->src_addr >> 8) & 0xFF, ip_result->src_addr & 0xFF);
    snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
             (ip_result->dst_addr >> 24) & 0xFF, (ip_result->dst_addr >> 16) & 0xFF,
             (ip_result->dst_addr >> 8) & 0xFF, ip_result->dst_addr & 0xFF);

    const char *opcode = dissect_result_get(&dissect_out, "eigrp_opcode");
    const char *asn = dissect_result_get(&dissect_out, "eigrp_asn");

    printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"EIGRP\","
           "\"eigrp_opcode\":\"%s\",\"eigrp_asn\":\"%s\"}\n",
           src_ip_str, dst_ip_str, opcode ? opcode : "", asn ? asn : "");
}

static void dissect_ah_datagram(const struct ipv4_result *ip_result) {
    if (ip_result->payload_len == 0) return;

    struct dissect_result dissect_out;
    bool matched = dispatch_dissection(ip_result->payload, ip_result->payload_len,
                                        0, "AH", &dissect_out);
    if (!matched) return;

    char src_ip_str[16], dst_ip_str[16];
    snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
             (ip_result->src_addr >> 24) & 0xFF, (ip_result->src_addr >> 16) & 0xFF,
             (ip_result->src_addr >> 8) & 0xFF, ip_result->src_addr & 0xFF);
    snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
             (ip_result->dst_addr >> 24) & 0xFF, (ip_result->dst_addr >> 16) & 0xFF,
             (ip_result->dst_addr >> 8) & 0xFF, ip_result->dst_addr & 0xFF);

    const char *spi = dissect_result_get(&dissect_out, "ah_spi");
    const char *inner_proto = dissect_result_get(&dissect_out, "ah_inner_protocol");

    printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"AH\","
           "\"ah_spi\":\"%s\",\"ah_inner_protocol\":\"%s\"}\n",
           src_ip_str, dst_ip_str, spi ? spi : "", inner_proto ? inner_proto : "");
}

static void dissect_udp_datagram(const struct ipv4_result *ip_result) {
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

    char sni_out[256] = "";
    char confidence_out[16] = "none";
    double dga_score_out = 0.0;

    if (matched) {
        const char *sni = dissect_result_get(&dissect_out, "sni");
        if (sni) {
            strncpy(sni_out, sni, sizeof(sni_out) - 1);
            struct classification_result cls;
            classify_hostname(sni, &cls);
            strncpy(confidence_out, cls.matched ? "high" : "low", sizeof(confidence_out) - 1);

            struct dga_result dga;
            score_dga(sni, &dga);
            dga_score_out = dga.score;
        }
    }

    printf("{\"src_port\":%u,\"dst_port\":%u,\"protocol\":\"%s\",\"sni\":\"%s\","
           "\"confidence\":\"%s\",\"dga_score\":%.2f,\"vpn_score\":%.2f,"
           "\"vpn_protocol\":\"%s\"}\n",
           udp_result.src_port, udp_result.dst_port,
           matched ? dissect_out.protocol_name : "unknown",
           sni_out, confidence_out, dga_score_out, vpn.score, vpn.detected_protocol);
}

/* -----------------------------------------------------------------
 * IPv6 entry point. Both UDP and TCP get full treatment — see
 * dpi_dpdk_worker.c's matching function for the fuller explanation of
 * why TCP-over-IPv6 is no longer deferred (struct tcp_flow_key now
 * supports 128-bit addresses via tcp_flow_key_make_v6()). Single-
 * threaded here, so partition_id is always 0, same as the v4 TCP path
 * above.
 * ----------------------------------------------------------------- */
static void dissect_ipv6_packet(const uint8_t *ip_start, uint16_t ip_len) {
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

        /* Checksum computed here, not inside icmpv6_dissect() — same
         * reasoning as the DPDK worker's version: needs the IPv6
         * pseudo-header, which requires src/dst addresses the generic
         * dissector interface doesn't pass through. */
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

        const char *icmpv6_type = dissect_result_get(&dissect_out, "icmpv6_type");
        const char *icmpv6_code = dissect_result_get(&dissect_out, "icmpv6_code");
        printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"ICMPv6\","
               "\"icmpv6_type\":\"%s\",\"icmpv6_code\":\"%s\",\"icmpv6_checksum_valid\":\"%s\"}\n",
               src_str, dst_str, icmpv6_type ? icmpv6_type : "", icmpv6_code ? icmpv6_code : "",
               icmpv6_checksum_valid ? "true" : "false");
        return;
    }

    if (ip6_result.next_header == 47 /* GRE */) {
        if (ip6_result.payload_len == 0) return;

        struct dissect_result dissect_out;
        bool matched = dispatch_dissection(ip6_result.payload, ip6_result.payload_len,
                                            0, "GRE", &dissect_out);
        if (!matched) return;

        const char *protocol_type = dissect_result_get(&dissect_out, "gre_protocol_type");
        const char *inner_src = dissect_result_get(&dissect_out, "gre_inner_src_ip");
        const char *inner_dst = dissect_result_get(&dissect_out, "gre_inner_dst_ip");
        const char *inner_sni = dissect_result_get(&dissect_out, "gre_inner_sni");
        const char *erspan = dissect_result_get(&dissect_out, "gre_erspan_detected");
        const char *keepalive = dissect_result_get(&dissect_out, "gre_keepalive_likely");

        printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"GRE\","
               "\"gre_protocol_type\":\"%s\",\"gre_inner_src_ip\":\"%s\","
               "\"gre_inner_dst_ip\":\"%s\",\"gre_inner_sni\":\"%s\","
               "\"gre_erspan_detected\":\"%s\",\"gre_keepalive_likely\":\"%s\"}\n",
               src_str, dst_str,
               protocol_type ? protocol_type : "", inner_src ? inner_src : "",
               inner_dst ? inner_dst : "", inner_sni ? inner_sni : "",
               erspan ? erspan : "false", keepalive ? keepalive : "false");
        return;
    }

    if (ip6_result.next_header == 89 /* OSPF */) {
        if (ip6_result.payload_len == 0) return;

        struct dissect_result dissect_out;
        bool matched = dispatch_dissection(ip6_result.payload, ip6_result.payload_len,
                                            0, "OSPF", &dissect_out);
        if (!matched) return;

        const char *version = dissect_result_get(&dissect_out, "ospf_version");
        const char *type = dissect_result_get(&dissect_out, "ospf_type");
        const char *router_id = dissect_result_get(&dissect_out, "ospf_router_id");
        const char *area_id = dissect_result_get(&dissect_out, "ospf_area_id");

        printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"OSPF\","
               "\"ospf_version\":\"%s\",\"ospf_type\":\"%s\","
               "\"ospf_router_id\":\"%s\",\"ospf_area_id\":\"%s\"}\n",
               src_str, dst_str,
               version ? version : "", type ? type : "",
               router_id ? router_id : "", area_id ? area_id : "");
        return;
    }

    if (ip6_result.next_header == 50 /* ESP */) {
        if (ip6_result.payload_len == 0) return;

        struct dissect_result dissect_out;
        bool matched = dispatch_dissection(ip6_result.payload, ip6_result.payload_len,
                                            0, "ESP", &dissect_out);
        if (!matched) return;

        const char *spi = dissect_result_get(&dissect_out, "esp_spi");
        const char *seq = dissect_result_get(&dissect_out, "esp_sequence");

        printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"ESP\","
               "\"esp_spi\":\"%s\",\"esp_sequence\":\"%s\"}\n",
               src_str, dst_str, spi ? spi : "", seq ? seq : "");
        return;
    }

    if (ip6_result.next_header == 88 /* EIGRP */) {
        if (ip6_result.payload_len == 0) return;

        struct dissect_result dissect_out;
        bool matched = dispatch_dissection(ip6_result.payload, ip6_result.payload_len,
                                            0, "EIGRP", &dissect_out);
        if (!matched) return;

        const char *opcode = dissect_result_get(&dissect_out, "eigrp_opcode");
        const char *asn = dissect_result_get(&dissect_out, "eigrp_asn");

        printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"EIGRP\","
               "\"eigrp_opcode\":\"%s\",\"eigrp_asn\":\"%s\"}\n",
               src_str, dst_str, opcode ? opcode : "", asn ? asn : "");
        return;
    }

    if (ip6_result.next_header == 51 /* AH */) {
        if (ip6_result.payload_len == 0) return;

        struct dissect_result dissect_out;
        bool matched = dispatch_dissection(ip6_result.payload, ip6_result.payload_len,
                                            0, "AH", &dissect_out);
        if (!matched) return;

        const char *spi = dissect_result_get(&dissect_out, "ah_spi");
        const char *inner_proto = dissect_result_get(&dissect_out, "ah_inner_protocol");

        printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"AH\","
               "\"ah_spi\":\"%s\",\"ah_inner_protocol\":\"%s\"}\n",
               src_str, dst_str, spi ? spi : "", inner_proto ? inner_proto : "");
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

        char sni_out[256] = "";
        char confidence_out[16] = "none";
        double dga_score_out = 0.0;

        if (matched) {
            const char *sni = dissect_result_get(&dissect_out, "sni");
            if (sni) {
                strncpy(sni_out, sni, sizeof(sni_out) - 1);
                struct classification_result cls;
                classify_hostname(sni, &cls);
                strncpy(confidence_out, cls.matched ? "high" : "low", sizeof(confidence_out) - 1);
                struct dga_result dga;
                score_dga(sni, &dga);
                dga_score_out = dga.score;
            }
        }

        printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,"
               "\"protocol\":\"%s\",\"sni\":\"%s\",\"confidence\":\"%s\","
               "\"dga_score\":%.2f,\"vpn_score\":%.2f,\"vpn_protocol\":\"%s\"}\n",
               src_str, dst_str, udp_result.src_port, udp_result.dst_port,
               matched ? dissect_out.protocol_name : "unknown",
               sni_out, confidence_out, dga_score_out, vpn.score, vpn.detected_protocol);
        return;
    }

    if (ip6_result.next_header == 6 /* TCP */) {
        struct tcp_result tcp_result;
        if (!parse_tcp_v6(ip6_result.src_addr, ip6_result.dst_addr,
                           ip6_result.payload, ip6_result.payload_len, &tcp_result)) {
            return;
        }
        if (tcp_result.payload_len == 0) return;

        struct tcp_flow_key key = tcp_flow_key_make_v6(
            ip6_result.src_addr, ip6_result.dst_addr, tcp_result.src_port, tcp_result.dst_port);

        const uint8_t *contiguous_data = NULL;
        uint32_t contiguous_len = 0;
        struct tcp_reassembly_stats stats;

        bool have_new_data = tcp_reassembly_insert(
            0, &key, tcp_result.seq, tcp_result.payload, tcp_result.payload_len,
            TCP_OVERLAP_FIRST_WINS, &contiguous_data, &contiguous_len, &stats);

        if (!have_new_data) return;

        struct hpack_connection_entry *conn = hpack_get_connection_entry(0, &key);
        bool has_pending_http2_continuation = conn && conn->has_pending_headers;
        struct tcp_flow_key reverse_key = tcp_flow_key_reverse(&key);
        struct hpack_connection_entry *reverse_conn = hpack_get_connection_entry(0, &reverse_key);

        if (!stats.is_first_delivery && !has_pending_http2_continuation) return;

        if (!stats.is_first_delivery && has_pending_http2_continuation) {
            struct dissect_result h2_out;
            memset(&h2_out, 0, sizeof(h2_out));
            http2_dissect_with_flow_state(contiguous_data, (uint16_t)contiguous_len,
                                           conn, reverse_conn, &h2_out);

            if (!conn->has_pending_headers) {
                const char *authority = dissect_result_get(&h2_out, "http2_authority");
                printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,"
                       "\"category\":\"HTTP/2\",\"app_name\":\"%s\",\"confidence\":\"%s\","
                       "\"reassembly\":{\"out_of_order\":%u,\"retransmits\":%u,"
                       "\"overlap_conflicts\":%u,\"evasion_flag\":%s}}\n",
                       src_str, dst_str, tcp_result.src_port, tcp_result.dst_port,
                       authority ? authority : "", authority ? "high" : "low",
                       stats.out_of_order_segments, stats.retransmit_count,
                       stats.overlap_conflict_count, stats.evasion_flag ? "true" : "false");
            }
            return;
        }

        struct app_classification classification;
        classify_flow(contiguous_data, contiguous_len,
                      tcp_result.dst_port, "TCP", &classification);

        /* Effective category/app_name/confidence, possibly overridden
         * below by a TCP-based dissector match (HTTP/1.1, HTTP/2, SSH)
         * when classify_flow() found no TLS ClientHello. Same gap-fix
         * and HTTP/2-persistent-state reasoning as the DPDK worker's
         * matching code — see that file's comment for the full
         * rationale. partition_id is 0 here, same as everywhere else
         * in this single-threaded file.
         *
         * These are FIXED BUFFERS, not pointers into h2_out/tcp_out —
         * those structs are declared inside the nested blocks below and
         * go out of scope before the printf() call that uses these
         * values runs. Keeping raw pointers into them would be a
         * dangling-pointer bug (caught while writing this, not after
         * the fact). */
        char effective_category[MAX_PROTOCOL_NAME];
        char effective_app_name[MAX_FIELD_VAL_LEN];
        char effective_confidence[16];
        strncpy(effective_category, classification.category, sizeof(effective_category) - 1);
        strncpy(effective_app_name, classification.app_name, sizeof(effective_app_name) - 1);
        strncpy(effective_confidence, classification.confidence, sizeof(effective_confidence) - 1);

        if (strcmp(classification.category, "unknown") == 0) {
            double http2_confidence = http2_detect(contiguous_data, (uint16_t)contiguous_len,
                                                    tcp_result.dst_port, "TCP");
            if (http2_confidence > 0.3) {
                struct dissect_result h2_out;
                memset(&h2_out, 0, sizeof(h2_out));
                http2_dissect_with_flow_state(contiguous_data, (uint16_t)contiguous_len,
                                               conn, reverse_conn, &h2_out);

                strncpy(effective_category, "HTTP/2", sizeof(effective_category) - 1);
                const char *authority = dissect_result_get(&h2_out, "http2_authority");
                if (authority) {
                    strncpy(effective_app_name, authority, sizeof(effective_app_name) - 1);
                    strncpy(effective_confidence, "high", sizeof(effective_confidence) - 1);
                } else {
                    strncpy(effective_confidence, "low", sizeof(effective_confidence) - 1);
                }
            } else {
                struct dissect_result tcp_out;
                bool tcp_matched = dispatch_dissection(contiguous_data, contiguous_len,
                                                        tcp_result.dst_port, "TCP", &tcp_out);
                if (tcp_matched) {
                    strncpy(effective_category, tcp_out.protocol_name, sizeof(effective_category) - 1);
                    const char *identity = dissect_result_get(&tcp_out, "http_host");
                    if (!identity) identity = dissect_result_get(&tcp_out, "ssh_software_version");
                    if (!identity) identity = dissect_result_get(&tcp_out, "smtp_helo_domain");
                    if (!identity) identity = dissect_result_get(&tcp_out, "smtp_ehlo_domain");
                    if (identity) strncpy(effective_app_name, identity, sizeof(effective_app_name) - 1);
                    strncpy(effective_confidence, "high", sizeof(effective_confidence) - 1);
                }
            }
        }

        printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,"
               "\"sni\":\"%s\",\"category\":\"%s\","
               "\"app_name\":\"%s\",\"confidence\":\"%s\",\"dga_score\":%.2f,"
               "\"vpn_score\":%.2f,\"vpn_protocol\":\"%s\",\"dot_score\":%.2f,"
               "\"doh_score\":%.2f,\"reassembly\":{\"out_of_order\":%u,"
               "\"retransmits\":%u,\"overlap_conflicts\":%u,\"evasion_flag\":%s}}\n",
               src_str, dst_str, tcp_result.src_port, tcp_result.dst_port,
               classification.sni, effective_category, effective_app_name,
               effective_confidence, classification.dga_score,
               classification.vpn_score, classification.vpn_protocol,
               classification.dot_score, classification.doh_score,
               stats.out_of_order_segments, stats.retransmit_count,
               stats.overlap_conflict_count, stats.evasion_flag ? "true" : "false");
        return;
    }
    /* Other next_header values: not handled. */
}

static void parse_ethernet_frame(const unsigned char *buf, ssize_t len) {
    if (len < ETH_HDR_LEN) {
        /* Too short to even contain an Ethernet header. Drop, don't guess. */
        return;
    }

    uint16_t ethertype = ntohs(*(const uint16_t *)(buf + 12));
    const unsigned char *payload = buf + ETH_HDR_LEN;
    ssize_t payload_len = len - ETH_HDR_LEN;

    /* VLAN stripping (802.1Q / 802.1ad QinQ), bounded to 2 tags — same
     * gap and same fix as dpi_dpdk_worker.c's matching code, see that
     * comment (or dpi_vlan_parser.c's header) for the full rationale.
     * After this, ethertype/payload/payload_len refer to whatever's
     * INSIDE the VLAN tag(s), so the dispatch below needs no other
     * changes to handle tagged traffic transparently. */
    if (ethertype == ETHERTYPE_8021Q || ethertype == ETHERTYPE_8021AD) {
        struct vlan_strip_result vlan;
        if (!vlan_strip(ethertype, (const uint8_t *)payload, (uint16_t)payload_len, &vlan)) {
            return;   /* malformed tag or over-nested: drop, don't guess */
        }
        ethertype = vlan.real_ethertype;
        payload = (const unsigned char *)vlan.payload;
        payload_len = vlan.payload_len;
        (void)vlan.vlan_id_outer;   /* not yet threaded into the JSON output —
                                      * see dpi_dpdk_worker.c's matching note */
        (void)vlan.vlan_id_inner;
    }

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
    if (ethertype == ETH_P_IPV6) {
        dissect_ipv6_packet((const uint8_t *)payload, (uint16_t)payload_len);
        return;
    }

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif
    if (ethertype == ETH_P_ARP) {
        struct dissect_result arp_out;
        bool matched = dispatch_dissection((const uint8_t *)payload, (uint16_t)payload_len,
                                            0, "ARP", &arp_out);
        if (matched) {
            const char *opcode = dissect_result_get(&arp_out, "arp_opcode");
            const char *sender_ip = dissect_result_get(&arp_out, "arp_sender_ip");
            const char *target_ip = dissect_result_get(&arp_out, "arp_target_ip");
            const char *sender_mac = dissect_result_get(&arp_out, "arp_sender_mac");
            printf("{\"protocol\":\"ARP\",\"arp_opcode\":\"%s\",\"arp_sender_ip\":\"%s\","
                   "\"arp_sender_mac\":\"%s\",\"arp_target_ip\":\"%s\"}\n",
                   opcode ? opcode : "", sender_ip ? sender_ip : "",
                   sender_mac ? sender_mac : "", target_ip ? target_ip : "");
        }
        return;
    }

#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC 0x8847
#endif
    if (ethertype == ETH_P_MPLS_UC || ethertype == 0x8848 /* MPLS multicast */) {
        struct dissect_result mpls_out;
        bool matched = dispatch_dissection((const uint8_t *)payload, (uint16_t)payload_len,
                                            0, "MPLS", &mpls_out);
        if (matched) {
            const char *depth = dissect_result_get(&mpls_out, "mpls_stack_depth");
            const char *top_label = dissect_result_get(&mpls_out, "mpls_top_label");
            const char *inner_src = dissect_result_get(&mpls_out, "mpls_inner_src_ip");
            const char *inner_dst = dissect_result_get(&mpls_out, "mpls_inner_dst_ip");
            const char *inner_sni = dissect_result_get(&mpls_out, "mpls_inner_sni");
            printf("{\"protocol\":\"MPLS\",\"mpls_stack_depth\":\"%s\",\"mpls_top_label\":\"%s\","
                   "\"mpls_inner_src_ip\":\"%s\",\"mpls_inner_dst_ip\":\"%s\","
                   "\"mpls_inner_sni\":\"%s\"}\n",
                   depth ? depth : "", top_label ? top_label : "",
                   inner_src ? inner_src : "", inner_dst ? inner_dst : "",
                   inner_sni ? inner_sni : "");
        }
        return;
    }

    if (ethertype != ETH_P_IP) {
        return;   /* not IPv4, IPv6, ARP, or MPLS: not handled */
    }

    struct ipv4_result ip_result;
    if (!parse_ipv4((const uint8_t *)payload, (uint16_t)payload_len, &ip_result)) {
        return;   /* malformed, or a fragment still waiting on the rest */
    }

    if (ip_result.protocol == 1 /* ICMP */) {
        dissect_icmp_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol == 47 /* GRE */) {
        dissect_gre_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol == 89 /* OSPF */) {
        dissect_ospf_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol == 2 /* IGMP */) {
        dissect_igmp_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol == 50 /* ESP */) {
        dissect_esp_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol == 41 /* 6in4 */) {
        dissect_sixin4_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol == 88 /* EIGRP */) {
        dissect_eigrp_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol == 51 /* AH */) {
        dissect_ah_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol == 17 /* UDP */) {
        dissect_udp_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol != 6 /* TCP */) {
        return;   /* neither TCP, UDP, ICMP, GRE, OSPF, IGMP, ESP, 6in4, EIGRP, nor AH: not handled */
    }

    struct tcp_result tcp_result;
    if (!parse_tcp(ip_result.src_addr, ip_result.dst_addr,
                    ip_result.payload, ip_result.payload_len, &tcp_result)) {
        return;
    }

    if (tcp_result.payload_len == 0) {
        return;   /* pure ACK/control segment, nothing to reassemble */
    }

    struct tcp_flow_key key = tcp_flow_key_make_v4(
        ip_result.src_addr, ip_result.dst_addr, tcp_result.src_port, tcp_result.dst_port);

    const uint8_t *contiguous_data = NULL;
    uint32_t contiguous_len = 0;
    struct tcp_reassembly_stats stats;

    /* partition_id is always 0 here — single-threaded, so there's no
     * concurrent-access concern the way there is in the DPDK worker's
     * multi-lcore design (see dpi_tcp_flow_reassembly.c's concurrency
     * note for why that file's flow table is partitioned at all). */
    bool have_new_data = tcp_reassembly_insert(
        0, &key, tcp_result.seq, tcp_result.payload, tcp_result.payload_len,
        TCP_OVERLAP_FIRST_WINS, &contiguous_data, &contiguous_len, &stats);

    if (!have_new_data) return;

    /* Same pending-CONTINUATION check as dpi_dpdk_worker.c's matching
     * code, and the same fix for a real inconsistency found while
     * writing this: this v4 path never had the HTTP/1.1/HTTP/2/SSH/
     * SMTP dispatch fallback that the IPv6 path just below already
     * has — classify_flow() alone (TLS/SNI-only) was all that ran
     * here. Both gaps fixed together since they touch the same block. */
    struct hpack_connection_entry *conn = hpack_get_connection_entry(0, &key);
    bool has_pending_http2_continuation = conn && conn->has_pending_headers;
    struct tcp_flow_key reverse_key = tcp_flow_key_reverse(&key);
    struct hpack_connection_entry *reverse_conn = hpack_get_connection_entry(0, &reverse_key);

    if (!stats.is_first_delivery && !has_pending_http2_continuation) return;

    char src_ip_str[16], dst_ip_str[16];
    snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
             (ip_result.src_addr >> 24) & 0xFF, (ip_result.src_addr >> 16) & 0xFF,
             (ip_result.src_addr >> 8) & 0xFF, ip_result.src_addr & 0xFF);
    snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
             (ip_result.dst_addr >> 24) & 0xFF, (ip_result.dst_addr >> 16) & 0xFF,
             (ip_result.dst_addr >> 8) & 0xFF, ip_result.dst_addr & 0xFF);

    if (!stats.is_first_delivery && has_pending_http2_continuation) {
        struct dissect_result h2_out;
        memset(&h2_out, 0, sizeof(h2_out));
        http2_dissect_with_flow_state(contiguous_data, (uint16_t)contiguous_len,
                                       conn, reverse_conn, &h2_out);

        if (!conn->has_pending_headers) {
            const char *authority = dissect_result_get(&h2_out, "http2_authority");
            printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,"
                   "\"category\":\"HTTP/2\",\"app_name\":\"%s\",\"confidence\":\"%s\","
                   "\"reassembly\":{\"out_of_order\":%u,\"retransmits\":%u,"
                   "\"overlap_conflicts\":%u,\"evasion_flag\":%s}}\n",
                   src_ip_str, dst_ip_str, tcp_result.src_port, tcp_result.dst_port,
                   authority ? authority : "", authority ? "high" : "low",
                   stats.out_of_order_segments, stats.retransmit_count,
                   stats.overlap_conflict_count, stats.evasion_flag ? "true" : "false");
        }
        return;
    }

    struct app_classification classification;
    classify_flow(contiguous_data, contiguous_len,
                  tcp_result.dst_port, "TCP", &classification);

    /* Effective category/app_name/confidence, possibly overridden below
     * by a TCP-based dissector match (HTTP/1.1, HTTP/2, SSH, SMTP) when
     * classify_flow() found no TLS ClientHello — same pattern as the
     * IPv6 path just below and the DPDK worker's matching code. */
    char effective_category[MAX_PROTOCOL_NAME];
    char effective_app_name[MAX_FIELD_VAL_LEN];
    char effective_confidence[16];
    strncpy(effective_category, classification.category, sizeof(effective_category) - 1);
    strncpy(effective_app_name, classification.app_name, sizeof(effective_app_name) - 1);
    strncpy(effective_confidence, classification.confidence, sizeof(effective_confidence) - 1);

    if (strcmp(classification.category, "unknown") == 0) {
        double http2_confidence = http2_detect(contiguous_data, (uint16_t)contiguous_len,
                                                tcp_result.dst_port, "TCP");
        if (http2_confidence > 0.3) {
            struct dissect_result h2_out;
            memset(&h2_out, 0, sizeof(h2_out));
            http2_dissect_with_flow_state(contiguous_data, (uint16_t)contiguous_len,
                                           conn, reverse_conn, &h2_out);

            strncpy(effective_category, "HTTP/2", sizeof(effective_category) - 1);
            const char *authority = dissect_result_get(&h2_out, "http2_authority");
            if (authority) {
                strncpy(effective_app_name, authority, sizeof(effective_app_name) - 1);
                strncpy(effective_confidence, "high", sizeof(effective_confidence) - 1);
            } else {
                strncpy(effective_confidence, "low", sizeof(effective_confidence) - 1);
            }
        } else {
            struct dissect_result tcp_out;
            bool tcp_matched = dispatch_dissection(contiguous_data, contiguous_len,
                                                    tcp_result.dst_port, "TCP", &tcp_out);
            if (tcp_matched) {
                strncpy(effective_category, tcp_out.protocol_name, sizeof(effective_category) - 1);
                const char *identity = dissect_result_get(&tcp_out, "http_host");
                if (!identity) identity = dissect_result_get(&tcp_out, "ssh_software_version");
                if (!identity) identity = dissect_result_get(&tcp_out, "smtp_helo_domain");
                if (!identity) identity = dissect_result_get(&tcp_out, "smtp_ehlo_domain");
                if (identity) strncpy(effective_app_name, identity, sizeof(effective_app_name) - 1);
                strncpy(effective_confidence, "high", sizeof(effective_confidence) - 1);
            }
        }
    }

    /* Unlike dpi_dpdk_worker.c, printf here is fine — this is a
     * single-threaded, non-100G reference path meant for lab testing,
     * not a multi-core poll-mode hot loop. Still worth eventually
     * replacing with structured logging for anything beyond ad hoc
     * testing. */
    printf("{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,"
           "\"sni\":\"%s\",\"category\":\"%s\","
           "\"app_name\":\"%s\",\"confidence\":\"%s\",\"dga_score\":%.2f,"
           "\"vpn_score\":%.2f,\"vpn_protocol\":\"%s\",\"dot_score\":%.2f,"
           "\"doh_score\":%.2f,\"reassembly\":{\"out_of_order\":%u,"
           "\"retransmits\":%u,\"overlap_conflicts\":%u,\"evasion_flag\":%s}}\n",
           src_ip_str, dst_ip_str, tcp_result.src_port, tcp_result.dst_port,
           classification.sni, effective_category, effective_app_name,
           effective_confidence, classification.dga_score,
           classification.vpn_score, classification.vpn_protocol,
           classification.dot_score, classification.doh_score,
           stats.out_of_order_segments, stats.retransmit_count,
           stats.overlap_conflict_count, stats.evasion_flag ? "true" : "false");
}

/* SIGUSR1 reloads protocols.ini without a restart — see
 * reload_protocol_config() in dpi_dissector_registry.c. Usage:
 * kill -USR1 <pid> after editing protocols.ini. Single-threaded here,
 * so a plain sig_atomic_t (rather than the _Atomic bool the DPDK
 * worker's multi-lcore version needs for g_registry's `enabled` field)
 * is sufficient — only this one thread ever reads or writes it. Must
 * be file-scope (not local to main()) so the signal handler function
 * below can reach it — a signal handler has no way to access a
 * caller's local variables. */
static volatile sig_atomic_t reload_config_requested = 0;

static void bootstrap_signal_handler(int signum) {
    if (signum == SIGUSR1) reload_config_requested = 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <interface>\n", argv[0]);
        return 1;
    }

    int sock = open_capture_socket(argv[1]);
    if (sock < 0) return 1;

    if (drop_privileges(UNPRIV_USER) != 0) {
        close(sock);
        return 1;
    }

    if (install_seccomp_filter() != 0) {
        close(sock);
        return 1;
    }

    /* Register RADIUS/QUIC dissectors once, before the capture loop
     * starts. Single-threaded here, so there's no ordering hazard the
     * way there is in the DPDK worker — just needs to happen before
     * the first packet could possibly need it. */
    signal(SIGUSR1, bootstrap_signal_handler);

    register_all_dissectors();

    unsigned char buf[SNAPLEN];
    for (;;) {
        if (reload_config_requested) {
            reload_config_requested = 0;
            reload_protocol_config();
        }

        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            break;
        }
        parse_ethernet_frame(buf, n);
    }

    close(sock);
    return 0;
}
