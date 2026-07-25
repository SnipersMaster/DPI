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
 * Build (requires dev packages, e.g. `apt install libseccomp-dev libcap-dev
 * libssl-dev`):
 *   gcc -O2 -Wall -Wextra -o dpi_bootstrap dpi_secure_bootstrap.c -lseccomp -lcap -lm -lcrypto
 *
 * -lm is for log2() (dpi_dga_detector.c's Shannon entropy scoring).
 * -lcrypto is OpenSSL's libcrypto (not libssl — this project only uses
 * OpenSSL's crypto primitives directly for QUIC's own HKDF key
 * derivation and AES-GCM decryption, per RFC 9001; it never makes an
 * actual TLS connection, so the higher-level libssl isn't needed).
 *
 * Run against a LIVE interface (needs CAP_NET_RAW, not full root — see
 * setcap note at bottom):
 *   sudo setcap cap_net_raw,cap_net_admin=eip ./dpi_bootstrap
 *   ./dpi_bootstrap eth0
 *
 * Run OFFLINE against a saved capture instead — no root, no capabilities,
 * no live interface needed at all. Both classic pcap and pcapng are
 * supported natively, auto-detected from the file's own magic bytes —
 * no conversion step needed for either format:
 *   ./dpi_bootstrap --pcap-file=capture.pcap
 *   ./dpi_bootstrap --pcap-file=capture.pcapng
 *   ./dpi_bootstrap --pcap-file=capture.pcap > output.json   # JSON to a file
 *   ./dpi_bootstrap --pcap-file=capture.pcap --link-type=80211-radiotap
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/*
 * DPI_SAFE_STRNCPY — a real bug found via a real compiler warning, not
 * a cosmetic fix. `strncpy(dest, src, N-1)` does NOT null-terminate
 * `dest` if `src` is >= N-1 bytes long — `dest[N-1]` (the byte the
 * ordinary "reserve room for the null terminator" pattern assumes
 * gets set) is simply never touched by strncpy at all. Across this
 * project's ~240 strncpy call sites (found via a systematic project-
 * wide scan after a real compiler flagged a handful of them), most
 * happened to be safe only because the destination struct was zero-
 * initialized elsewhere (`= {0}`) — but not all of them were: at
 * least one local buffer (`effective_category` in this file) was
 * declared with no initializer at all, meaning a source string at or
 * past the buffer's capacity would leave whatever uninitialized stack
 * garbage was already there un-terminated — a real information-
 * disclosure risk the next time that buffer got read with `%s`, not
 * just a cosmetic truncation concern.
 *
 * IMPLEMENTED VIA snprintf(dest, dest_size, "%s", src) PLUS a scoped
 * pragma, not strncpy+explicit-null alone — the full story, since
 * this took two real compiler runs to get right and is worth stating
 * precisely rather than glossing over. First version used
 * strncpy+explicit-null (correct, always null-terminates) but
 * triggered `-Wstringop-truncation` at nearly every one of the ~240
 * call sites. Switched to `snprintf` on the assumption that GCC
 * treats its truncation as deliberate — WRONG: a second real compile
 * showed GCC has a *separate* warning, `-Wformat-truncation`, that
 * fires on `snprintf("%s", ...)` under the exact same circumstances
 * (destination smaller than the source theoretically could be).
 * Switching the copy mechanism a second time would just trade one
 * warning for a third; the actual fix is to stop chasing which
 * function GCC happens to flag and instead explicitly acknowledge
 * what's true: every call site's real intent has always been "cap
 * this field's length," never "the full value must be preserved or
 * the program is wrong" — silent truncation on an overlong source is
 * correct, intended behavior here, not a bug to keep working around.
 * `_Pragma` (the operator form, not `#pragma` — a `#pragma` directive
 * can't appear inside a macro's backslash-continued body) scopes the
 * suppression tightly to just this one `snprintf` call, not the
 * whole file, so it can't accidentally hide an unrelated truncation
 * bug somewhere else.
 *
 * Defined as a macro, not a function, specifically so it's available
 * to every `#include`d file regardless of order — `dpi_protocol_
 * config.c` (which has this exact same pattern) gets included from
 * within `dpi_dissector_registry.c` before any function defined
 * there would be visible to it; a macro defined here, before every
 * dissector file, has no such ordering constraint. Defined
 * identically in `dpi_dpdk_worker.c` since the two capture-path files
 * are separate translation units, never included into each other.
 */
#define DPI_SAFE_STRNCPY(dest, src, dest_size) do { \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wformat-truncation\"") \
    _Pragma("GCC diagnostic ignored \"-Wformat-truncation=\"") \
    _Pragma("GCC diagnostic ignored \"-Wstringop-truncation\"") \
    snprintf((dest), (dest_size), "%s", (src)); \
    _Pragma("GCC diagnostic pop") \
} while (0)

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
#include "dpi_flow_record.c"
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
#include "dpi_lldp_parser.c"
#include "dpi_kerberos_parser.c"
#include "dpi_l2tpv3_parser.c"
#include "dpi_whois_parser.c"
#include "dpi_tftp_parser.c"
#include "dpi_wol_parser.c"
#include "dpi_wow_parser.c"
#include "dpi_bt_dht_parser.c"
#include "dpi_sctp_parser.c"
#include "dpi_m3ua_parser.c"
#include "dpi_amqp_parser.c"
#include "dpi_stp_parser.c"
/* 802.11 is a genuinely different link layer from everything else
 * this file processes — see dpi_80211_parser.c's own header comment.
 * Included here specifically to support the optional --link-type=80211
 * mode added to main() below, for when this program is pointed at a
 * monitor-mode wireless interface (which delivers raw 802.11 frames
 * over the same AF_PACKET raw-socket mechanism used for Ethernet —
 * confirmed by how tools like tcpdump capture wireless traffic on
 * Linux) rather than a normal wired one. */
#include "dpi_80211_parser.c"
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
    DPI_SAFE_STRNCPY(ifr.ifr_name, ifname, IFNAMSIZ);
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
static void dispatch_by_ethertype(uint16_t ethertype, const unsigned char *payload, ssize_t payload_len);
static void dissect_icmp_datagram(const struct ipv4_result *ip_result);
static void dissect_gre_datagram(const struct ipv4_result *ip_result);
static void dissect_ospf_datagram(const struct ipv4_result *ip_result);
static void dissect_igmp_datagram(const struct ipv4_result *ip_result);
static void dissect_esp_datagram(const struct ipv4_result *ip_result);
static void dissect_sixin4_datagram(const struct ipv4_result *ip_result);
static void dissect_eigrp_datagram(const struct ipv4_result *ip_result);
static void dissect_ah_datagram(const struct ipv4_result *ip_result);
static void dissect_l2tpv3_datagram(const struct ipv4_result *ip_result);
static void dissect_sctp_datagram(const struct ipv4_result *ip_result);

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

static void dissect_l2tpv3_datagram(const struct ipv4_result *ip_result) {
    if (ip_result->payload_len == 0) return;

    struct dissect_result dissect_out;
    bool matched = dispatch_dissection(ip_result->payload, ip_result->payload_len,
                                        0, "L2TPv3", &dissect_out);
    if (!matched) return;

    const char *inner_src_ip = dissect_result_get(&dissect_out, "l2tpv3_inner_src_ip");
    const char *inner_dst_ip = dissect_result_get(&dissect_out, "l2tpv3_inner_dst_ip");
    const char *inner_src_mac = dissect_result_get(&dissect_out, "l2tpv3_inner_src_mac");
    const char *inner_dst_mac = dissect_result_get(&dissect_out, "l2tpv3_inner_dst_mac");
    const char *session_id = dissect_result_get(&dissect_out, "l2tpv3_session_id");
    const char *inner_proto = dissect_result_get(&dissect_out, "l2tpv3_inner_protocol");
    const char *inner_sni = dissect_result_get(&dissect_out, "l2tpv3_inner_sni");

    printf("{\"protocol\":\"L2TPv3\",\"l2tpv3_session_id\":\"%s\","
           "\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_mac\":\"%s\",\"dst_mac\":\"%s\","
           "\"inner_protocol\":\"%s\",\"inner_sni\":\"%s\"}\n",
           session_id ? session_id : "",
           inner_src_ip ? inner_src_ip : "", inner_dst_ip ? inner_dst_ip : "",
           inner_src_mac ? inner_src_mac : "", inner_dst_mac ? inner_dst_mac : "",
           inner_proto ? inner_proto : "", inner_sni ? inner_sni : "");
}

static void dissect_sctp_datagram(const struct ipv4_result *ip_result) {
    if (ip_result->payload_len == 0) return;

    struct dissect_result dissect_out;
    bool matched = dispatch_dissection(ip_result->payload, ip_result->payload_len,
                                        0, "SCTP", &dissect_out);
    if (!matched) return;

    char src_ip_str[16], dst_ip_str[16];
    snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
             (ip_result->src_addr>>24)&0xFF, (ip_result->src_addr>>16)&0xFF,
             (ip_result->src_addr>>8)&0xFF, ip_result->src_addr&0xFF);
    snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
             (ip_result->dst_addr>>24)&0xFF, (ip_result->dst_addr>>16)&0xFF,
             (ip_result->dst_addr>>8)&0xFF, ip_result->dst_addr&0xFF);

    const char *sport = dissect_result_get(&dissect_out, "sctp_src_port");
    const char *dport = dissect_result_get(&dissect_out, "sctp_dst_port");
    const char *verif_tag = dissect_result_get(&dissect_out, "sctp_verification_tag");
    const char *chunk0_type = dissect_result_get(&dissect_out, "sctp_chunk_0_type");
    const char *chunk0_ppid = dissect_result_get(&dissect_out, "sctp_chunk_0_ppid");
    const char *chunk0_inner = dissect_result_get(&dissect_out, "sctp_chunk_0_inner_protocol");

    printf("{\"protocol\":\"SCTP\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\","
           "\"sctp_src_port\":\"%s\",\"sctp_dst_port\":\"%s\","
           "\"sctp_verification_tag\":\"%s\",\"sctp_chunk_0_type\":\"%s\","
           "\"sctp_chunk_0_ppid\":\"%s\",\"sctp_chunk_0_inner_protocol\":\"%s\"}\n",
           src_ip_str, dst_ip_str,
           sport ? sport : "", dport ? dport : "",
           verif_tag ? verif_tag : "", chunk0_type ? chunk0_type : "",
           chunk0_ppid ? chunk0_ppid : "", chunk0_inner ? chunk0_inner : "");
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
            DPI_SAFE_STRNCPY(sni_out, sni, sizeof(sni_out));
            struct classification_result cls;
            classify_hostname(sni, &cls);
            DPI_SAFE_STRNCPY(confidence_out, cls.matched ? "high" : "low", sizeof(confidence_out));

            struct dga_result dga;
            score_dga(sni, &dga);
            dga_score_out = dga.score;
        }
    }

    /* Real gap found and fixed while extending flow-record coverage
     * to UDP: this function's own output previously never included
     * src_ip/dst_ip at all, even in the old flat format — only ports.
     * Not something the flow-record work introduced; found by
     * checking what this function actually emits while wiring it in. */
    uint8_t src_addr_bytes[4] = {
        (uint8_t)(ip_result->src_addr >> 24), (uint8_t)(ip_result->src_addr >> 16),
        (uint8_t)(ip_result->src_addr >> 8),  (uint8_t)(ip_result->src_addr)
    };
    uint8_t dst_addr_bytes[4] = {
        (uint8_t)(ip_result->dst_addr >> 24), (uint8_t)(ip_result->dst_addr >> 16),
        (uint8_t)(ip_result->dst_addr >> 8),  (uint8_t)(ip_result->dst_addr)
    };
    struct flow_record *fr = flow_record_find_or_create(
        4, src_addr_bytes, udp_result.src_port, dst_addr_bytes, udp_result.dst_port, 17);
    if (fr) {
        flow_record_touch(fr, udp_result.payload_len);
        /* confidence_out (from classify_hostname()'s domain-rules
         * match, when an SNI-bearing UDP protocol like QUIC/DTLS was
         * involved) is a more informative signal than a plain
         * matched-or-not boolean when it's actually available —
         * falls back to the simpler signal otherwise, rather than
         * leaving confidence_out computed and unused (a real
         * oversight caught while wiring this up, not shipped as-is). */
        const char *l7_confidence = sni_out[0] ? confidence_out : (matched ? "high" : "low");
        flow_record_set_l7(fr, matched ? dissect_out.protocol_name : "unknown",
                            l7_confidence, matched ? &dissect_out : NULL);
        /* UDP has no TCP-style reassembly — all four stats stay at
         * their zero-initialized default (set at flow creation),
         * kept in the emitted schema anyway for consistency across
         * every flow record regardless of L4 protocol. */
        flow_record_set_scores(fr, dga_score_out, vpn.score, vpn.detected_protocol, 0.0, 0.0);
    }
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
                DPI_SAFE_STRNCPY(sni_out, sni, sizeof(sni_out));
                struct classification_result cls;
                classify_hostname(sni, &cls);
                DPI_SAFE_STRNCPY(confidence_out, cls.matched ? "high" : "low", sizeof(confidence_out));
                struct dga_result dga;
                score_dga(sni, &dga);
                dga_score_out = dga.score;
            }
        }

        struct flow_record *fr = flow_record_find_or_create(
            6, ip6_result.src_addr, udp_result.src_port,
            ip6_result.dst_addr, udp_result.dst_port, 17);
        if (fr) {
            flow_record_touch(fr, udp_result.payload_len);
            const char *l7_confidence = sni_out[0] ? confidence_out : (matched ? "high" : "low");
            flow_record_set_l7(fr, matched ? dissect_out.protocol_name : "unknown",
                                l7_confidence, matched ? &dissect_out : NULL);
            flow_record_set_scores(fr, dga_score_out, vpn.score, vpn.detected_protocol, 0.0, 0.0);
        }
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
        DPI_SAFE_STRNCPY(effective_category, classification.category, sizeof(effective_category));
        DPI_SAFE_STRNCPY(effective_app_name, classification.app_name, sizeof(effective_app_name));
        DPI_SAFE_STRNCPY(effective_confidence, classification.confidence, sizeof(effective_confidence));

        if (strcmp(classification.category, "unknown") == 0) {
            double http2_confidence = http2_detect(contiguous_data, (uint16_t)contiguous_len,
                                                    tcp_result.dst_port, "TCP");
            if (http2_confidence > 0.3) {
                struct dissect_result h2_out;
                memset(&h2_out, 0, sizeof(h2_out));
                http2_dissect_with_flow_state(contiguous_data, (uint16_t)contiguous_len,
                                               conn, reverse_conn, &h2_out);

                DPI_SAFE_STRNCPY(effective_category, "HTTP/2", sizeof(effective_category));
                const char *authority = dissect_result_get(&h2_out, "http2_authority");
                if (authority) {
                    DPI_SAFE_STRNCPY(effective_app_name, authority, sizeof(effective_app_name));
                    DPI_SAFE_STRNCPY(effective_confidence, "high", sizeof(effective_confidence));
                } else {
                    DPI_SAFE_STRNCPY(effective_confidence, "low", sizeof(effective_confidence));
                }
            } else {
                struct dissect_result tcp_out;
                bool tcp_matched = dispatch_dissection(contiguous_data, contiguous_len,
                                                        tcp_result.dst_port, "TCP", &tcp_out);
                if (tcp_matched) {
                    DPI_SAFE_STRNCPY(effective_category, tcp_out.protocol_name, sizeof(effective_category));
                    const char *identity = dissect_result_get(&tcp_out, "http_host");
                    if (!identity) identity = dissect_result_get(&tcp_out, "ssh_software_version");
                    if (!identity) identity = dissect_result_get(&tcp_out, "smtp_helo_domain");
                    if (!identity) identity = dissect_result_get(&tcp_out, "smtp_ehlo_domain");
                    if (identity) DPI_SAFE_STRNCPY(effective_app_name, identity, sizeof(effective_app_name));
                    DPI_SAFE_STRNCPY(effective_confidence, "high", sizeof(effective_confidence));
                }

                struct flow_record *fr = flow_record_find_or_create(
                    6, ip6_result.src_addr, tcp_result.src_port,
                    ip6_result.dst_addr, tcp_result.dst_port, 6);
                if (fr) {
                    flow_record_touch(fr, contiguous_len);
                    flow_record_set_l7(fr, effective_category, effective_confidence,
                                        tcp_matched ? &tcp_out : NULL);
                    flow_record_set_evasion_stats(fr, stats.out_of_order_segments,
                        stats.retransmit_count, stats.overlap_conflict_count, stats.evasion_flag);
                    flow_record_set_scores(fr, classification.dga_score, classification.vpn_score,
                        classification.vpn_protocol, classification.dot_score, classification.doh_score);
                }
                return;
            }
        }

        struct flow_record *fr = flow_record_find_or_create(
            6, ip6_result.src_addr, tcp_result.src_port,
            ip6_result.dst_addr, tcp_result.dst_port, 6);
        if (fr) {
            flow_record_touch(fr, contiguous_len);
            flow_record_set_l7(fr, effective_category, effective_confidence, NULL);
            flow_record_set_evasion_stats(fr, stats.out_of_order_segments,
                stats.retransmit_count, stats.overlap_conflict_count, stats.evasion_flag);
            flow_record_set_scores(fr, classification.dga_score, classification.vpn_score,
                classification.vpn_protocol, classification.dot_score, classification.doh_score);
        }
        return;
    }
    /* Other next_header values: not handled. */
}

static void parse_80211_frame(const unsigned char *buf, ssize_t len) {
    if (len < 0) return;

    struct dissect_result dissect_out;
    dot11_dissect_frame((const uint8_t *)buf, (size_t)len, &dissect_out);

    const char *type = dissect_result_get(&dissect_out, "dot11_type");
    const char *subtype = dissect_result_get(&dissect_out, "dot11_subtype");
    const char *addr1 = dissect_result_get(&dissect_out, "dot11_addr1");
    const char *addr2 = dissect_result_get(&dissect_out, "dot11_addr2");
    const char *addr3 = dissect_result_get(&dissect_out, "dot11_addr3");
    const char *ssid = dissect_result_get(&dissect_out, "dot11_beacon_ssid");
    const char *auth_algo = dissect_result_get(&dissect_out, "dot11_auth_algorithm");
    const char *auth_status = dissect_result_get(&dissect_out, "dot11_auth_status");
    const char *auth_encrypted = dissect_result_get(&dissect_out, "dot11_auth_encrypted");

    if (!type) return;   /* header too short to even parse — see dot11_parse_header */

    printf("{\"link_type\":\"802.11\",\"dot11_type\":\"%s\",\"dot11_subtype\":\"%s\","
           "\"addr1\":\"%s\",\"addr2\":\"%s\",\"addr3\":\"%s\","
           "\"beacon_ssid\":\"%s\",\"auth_algorithm\":\"%s\","
           "\"auth_status\":\"%s\",\"auth_encrypted\":\"%s\"}\n",
           type, subtype ? subtype : "",
           addr1 ? addr1 : "", addr2 ? addr2 : "", addr3 ? addr3 : "",
           ssid ? ssid : "", auth_algo ? auth_algo : "",
           auth_status ? auth_status : "", auth_encrypted ? auth_encrypted : "");
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

    dispatch_by_ethertype(ethertype, payload, payload_len);
}

/*
 * Everything that used to be the back half of parse_ethernet_frame()
 * (every ethertype-based dispatch branch: IPv6, ARP/RARP, MPLS, LLDP,
 * WoL, and the whole IPv4 IP-protocol-number cascade below) — pulled
 * out into its own function specifically so it can be reused by link
 * types OTHER than Ethernet that still ultimately carry an ethertype-
 * equivalent value or a determinable IP version, without duplicating
 * this entire, substantial dispatch cascade for each one. Added when
 * two such link types turned up in a real, if deliberately
 * comprehensive, capture (`--pcap-file=`'s own real-world testing):
 * LINKTYPE_RAW (packet begins directly with an IP header, no link-
 * layer framing at all — the "ethertype" is synthesized from the IP
 * version nibble instead of read from a real field) and Linux SLL
 * "cooked capture" (a 16-byte pseudo-header whose own trailing
 * protocol field plays the exact same role a real EtherType does).
 * Both call this same function with whatever ethertype value applies
 * to their framing, exactly as if it had come from a real Ethernet
 * header — this function has no way to tell the difference, by
 * design.
 */
static void dispatch_by_ethertype(uint16_t ethertype, const unsigned char *payload,
                                   ssize_t payload_len) {
    /* IEEE 802.3's own length/EtherType ambiguity rule: values below
     * 0x0600 (1536) are a LENGTH field (802.3 LLC framing), values at
     * or above are a real EtherType (Ethernet II framing) — not
     * guessed at, this is how the wire format itself distinguishes
     * the two. Checked first, before any real EtherType comparison
     * below, since none of those are ever < 0x0600 anyway. See
     * dpi_stp_parser.c's own header comment for the full verification
     * story — this is currently the only LLC-framed protocol this
     * project recognizes, but the check is general (any DSAP/SSAP
     * pair could be added here later without restructuring this
     * function again). */
    if (ethertype < 0x0600 && payload_len >= 0) {
        stp_dissect_llc_payload((const uint8_t *)payload, (uint16_t)payload_len, ethertype);
        return;
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
    /* RARP (RFC 903, EtherType 0x8035) is byte-for-byte identical to
     * ARP's wire format — same fields, just opcodes 3/4 instead of
     * 1/2 — and dpi_arp_parser.c's opcode-name table already handles
     * both; this EtherType check was the only piece missing to
     * actually reach it. Verified against 4 real RARP Request frames
     * (opcode 3, sender/target IP both 0.0.0.0 — correct RARP
     * semantics for a host that doesn't know its own IP yet, not a
     * malformed packet). */
    if (ethertype == ETH_P_ARP || ethertype == 0x8035 /* RARP */) {
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

    if (ethertype == 0x88CC /* LLDP */) {
        struct dissect_result lldp_out;
        bool matched = dispatch_dissection((const uint8_t *)payload, (uint16_t)payload_len,
                                            0, "LLDP", &lldp_out);
        if (matched) {
            const char *mac = dissect_result_get(&lldp_out, "lldp_chassis_id_mac");
            const char *port_id = dissect_result_get(&lldp_out, "lldp_port_id");
            const char *sys_name = dissect_result_get(&lldp_out, "lldp_system_name");
            const char *mgmt_ip = dissect_result_get(&lldp_out, "lldp_management_address");
            printf("{\"protocol\":\"LLDP\",\"lldp_chassis_id_mac\":\"%s\","
                   "\"lldp_port_id\":\"%s\",\"lldp_system_name\":\"%s\","
                   "\"lldp_management_address\":\"%s\"}\n",
                   mac ? mac : "", port_id ? port_id : "",
                   sys_name ? sys_name : "", mgmt_ip ? mgmt_ip : "");
        }
        return;
    }

    if (ethertype == 0x0842 /* Wake-on-LAN Magic Packet */) {
        struct dissect_result wol_out;
        bool matched = dispatch_dissection((const uint8_t *)payload, (uint16_t)payload_len,
                                            0, "WoL", &wol_out);
        if (matched) {
            const char *target_mac = dissect_result_get(&wol_out, "wol_target_mac");
            const char *secureon = dissect_result_get(&wol_out, "wol_secureon_password_present");
            printf("{\"protocol\":\"WoL\",\"wol_target_mac\":\"%s\","
                   "\"wol_secureon_password_present\":\"%s\"}\n",
                   target_mac ? target_mac : "", secureon ? secureon : "false");
        }
        return;
    }

    if (ethertype != ETH_P_IP) {
        return;   /* not IPv4, IPv6, ARP, MPLS, LLDP, or WoL: not handled */
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

    if (ip_result.protocol == 115 /* L2TPv3 */) {
        dissect_l2tpv3_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol == 132 /* SCTP */) {
        dissect_sctp_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol == 17 /* UDP */) {
        dissect_udp_datagram(&ip_result);
        return;
    }

    if (ip_result.protocol != 6 /* TCP */) {
        return;   /* neither TCP, UDP, ICMP, GRE, OSPF, IGMP, ESP, 6in4, EIGRP, AH, L2TPv3, nor SCTP: not handled */
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
    DPI_SAFE_STRNCPY(effective_category, classification.category, sizeof(effective_category));
    DPI_SAFE_STRNCPY(effective_app_name, classification.app_name, sizeof(effective_app_name));
    DPI_SAFE_STRNCPY(effective_confidence, classification.confidence, sizeof(effective_confidence));

    bool tcp_matched = false;
    struct dissect_result tcp_out;
    memset(&tcp_out, 0, sizeof(tcp_out));

    if (strcmp(classification.category, "unknown") == 0) {
        double http2_confidence = http2_detect(contiguous_data, (uint16_t)contiguous_len,
                                                tcp_result.dst_port, "TCP");
        if (http2_confidence > 0.3) {
            struct dissect_result h2_out;
            memset(&h2_out, 0, sizeof(h2_out));
            http2_dissect_with_flow_state(contiguous_data, (uint16_t)contiguous_len,
                                           conn, reverse_conn, &h2_out);

            DPI_SAFE_STRNCPY(effective_category, "HTTP/2", sizeof(effective_category));
            const char *authority = dissect_result_get(&h2_out, "http2_authority");
            if (authority) {
                DPI_SAFE_STRNCPY(effective_app_name, authority, sizeof(effective_app_name));
                DPI_SAFE_STRNCPY(effective_confidence, "high", sizeof(effective_confidence));
            } else {
                DPI_SAFE_STRNCPY(effective_confidence, "low", sizeof(effective_confidence));
            }
            /* h2_out itself goes out of scope at the end of this
             * block — its fields were already copied into
             * effective_category/effective_app_name above, which is
             * all the flow record needs for the HTTP/2 case; the
             * full nested-field object (matching HTTP/1.1's) would
             * need h2_out plumbed out to function scope the same way
             * tcp_out just was, not done here to keep this specific
             * fix focused on the bug just found (tcp_out silently
             * never reaching the flow record at all) rather than
             * expanding scope further in the same edit. */
        } else {
            /* tcp_matched/tcp_out declared at function scope, above —
             * a REAL bug found while wiring this up: they were
             * previously scoped to just this `else` block, meaning
             * execution fell through to the flow-record code below
             * with tcp_out already out of scope, silently passing
             * NULL instead of the real dissection result — losing
             * every HTTP/SSH/SMTP field this branch exists to
             * extract, for exactly the traffic this branch matches
             * most: real TCP-based protocols classify_flow() alone
             * doesn't have SNI visibility into. */
            tcp_matched = dispatch_dissection(contiguous_data, contiguous_len,
                                               tcp_result.dst_port, "TCP", &tcp_out);
            if (tcp_matched) {
                DPI_SAFE_STRNCPY(effective_category, tcp_out.protocol_name, sizeof(effective_category));
                const char *identity = dissect_result_get(&tcp_out, "http_host");
                if (!identity) identity = dissect_result_get(&tcp_out, "ssh_software_version");
                if (!identity) identity = dissect_result_get(&tcp_out, "smtp_helo_domain");
                if (!identity) identity = dissect_result_get(&tcp_out, "smtp_ehlo_domain");
                if (identity) DPI_SAFE_STRNCPY(effective_app_name, identity, sizeof(effective_app_name));
                DPI_SAFE_STRNCPY(effective_confidence, "high", sizeof(effective_confidence));
            }
        }
    }

    /* Convert the uint32_t address representation used throughout
     * this IPv4 path into the 4-byte array dpi_flow_record.c expects
     * (uniformly sized for both IPv4 and IPv6 callers). */
    uint8_t src_addr_bytes[4] = {
        (uint8_t)(ip_result.src_addr >> 24), (uint8_t)(ip_result.src_addr >> 16),
        (uint8_t)(ip_result.src_addr >> 8),  (uint8_t)(ip_result.src_addr)
    };
    uint8_t dst_addr_bytes[4] = {
        (uint8_t)(ip_result.dst_addr >> 24), (uint8_t)(ip_result.dst_addr >> 16),
        (uint8_t)(ip_result.dst_addr >> 8),  (uint8_t)(ip_result.dst_addr)
    };
    struct flow_record *fr = flow_record_find_or_create(
        4, src_addr_bytes, tcp_result.src_port, dst_addr_bytes, tcp_result.dst_port, 6);
    if (fr) {
        flow_record_touch(fr, contiguous_len);
        flow_record_set_l7(fr, effective_category, effective_confidence,
                            tcp_matched ? &tcp_out : NULL);
        flow_record_set_evasion_stats(fr, stats.out_of_order_segments,
            stats.retransmit_count, stats.overlap_conflict_count, stats.evasion_flag);
        flow_record_set_scores(fr, classification.dga_score, classification.vpn_score,
            classification.vpn_protocol, classification.dot_score, classification.doh_score);
    }
}

/*
 * LINKTYPE_RAW (101) — the packet begins directly with an IP header,
 * no link-layer framing of any kind, not even a synthetic one like
 * Linux SLL's. Verified against real packets in a real capture
 * (`--pcap-file=`'s own testing surfaced this as a real, if
 * infrequent, link type — 37 real packets in one file) — both IPv4
 * and IPv6 share the same trick for determining which one a given
 * buffer holds: the very first 4 bits of the first byte are the IP
 * version field in both RFC 791 (IPv4) and RFC 8200 (IPv6), at the
 * identical bit position, before either header format diverges into
 * anything else. No ethertype exists to read here at all, so one is
 * synthesized (0x0800 or 0x86DD) purely to reuse the same, already-
 * verified dispatch_by_ethertype() rather than duplicate its entire
 * IP-protocol-number cascade for this one link type.
 */
static void parse_raw_ip_frame(const unsigned char *buf, ssize_t len) {
    if (len < 1) return;   /* not even enough for the version nibble */

    uint8_t version = (buf[0] >> 4) & 0x0F;
    if (version == 4) {
        dispatch_by_ethertype(0x0800, buf, len);
    } else if (version == 6) {
        dispatch_by_ethertype(0x86DD, buf, len);
    }
    /* Any other value: not a real IPv4/IPv6 header — drop, don't guess. */
}

/*
 * Linux SLL ("cooked capture", linktype 113) — the pseudo-header
 * Linux's packet-capture layer synthesizes when a real link-layer
 * header doesn't cleanly apply (most commonly the "any" pseudo-
 * interface, which can span multiple real interfaces of different
 * types at once). Verified against real packets in the same real
 * capture that surfaced LINKTYPE_RAW above (1,067 real packets — the
 * larger and more common of the two newly-added link types). Also
 * independently confirmed against a genuinely different real capture
 * earlier in this project (`bssmap_bsc_invoke_trace.pcap`, a real
 * SCTP/SIGTRAN trace) — this project's own SCTP dissector work relied
 * on this exact same 16-byte layout being correct, just without a
 * dedicated offline-file entry point for it until now.
 *
 * Fixed 16-byte header: packet type (2 bytes — unicast/broadcast/
 * multicast/etc., not used here), ARPHRD_ type (2 bytes — the kind of
 * underlying hardware, not used here), link-layer address length (2
 * bytes), a fixed 8-byte address field (only the first
 * address-length bytes are meaningful; the rest is padding — not
 * used here, since nothing this project dissects needs a raw L2
 * address from this specific pseudo-header), and finally a 2-byte
 * protocol field playing the exact same role a real EtherType does —
 * confirmed 0x0800 (IPv4) against the real SCTP capture's own real
 * bytes. After these 16 bytes, the payload is the L3 packet directly.
 */
static void parse_linux_sll_frame(const unsigned char *buf, ssize_t len) {
    if (len < 16) return;   /* too short for even the fixed SLL header */

    uint16_t protocol = ((uint16_t)buf[14] << 8) | buf[15];
    dispatch_by_ethertype(protocol, buf + 16, len - 16);
}

#define MPACKET_SFD_SMDE               0xD5
#define MPACKET_PREAMBLE_SEARCH_WINDOW 16

/*
 * LINKTYPE_ETHERNET_MPACKET (274) — mPackets per IEEE 802.3br Figure
 * 99-4, a real link type found in a real, publicly-available
 * reference capture ("The Ultimate PCAP") — 10,667 real packets in
 * that file, the single largest previously-unsupported category found
 * across this whole project's real-traffic testing.
 *
 * HONEST SCOPE, stated directly rather than glossed over after actual
 * research: this project does NOT have confident, verified knowledge
 * of this format's full byte-level structure, and says so rather than
 * guessing. IEEE 802.3br's frame-preemption feature (letting a high-
 * priority "express" frame interrupt a lower-priority one mid-
 * transmission) splits an interrupted frame into fragments called
 * mPackets. Each begins with the ordinary Ethernet preamble, but with
 * the Start Frame Delimiter replaced by one of several distinct
 * "Start mPacket Delimiter" (SMD) values: SMD-E for a complete
 * "express" frame that was never itself fragmented, several SMD-Sx
 * values for the FIRST fragment of a frame that DID get preempted,
 * and several SMD-Cx values for CONTINUATION fragments (each carrying
 * an extra "fragment count" byte the SMD-E/unfragmented case doesn't
 * have) — ending in a different trailing checksum (mCRC) for every
 * fragment except the last, which ends in the original frame's real
 * FCS instead. The authoritative source for the exact numeric SMD
 * values is the full IEEE 802.3-2018 text — a paid standard, not
 * freely available. What public 2015 IEEE 802.3br task-force working
 * documents DO show is several of those values being actively
 * corrected mid-draft (SMD-C3 changed from 0xAD to 0x2A; SMD-S3
 * changed from 0x83 to 0xB3 between revisions) — not a stable
 * foundation to build byte-exact fragment-type detection or
 * reassembly on. This project won't guess at values its own sources
 * visibly disagreed with during standardization, matching the same
 * discipline that kept it from guessing at DNP3's field layout or the
 * exact contents inside M3UA's Protocol Data parameter without a
 * trustworthy reference — real sample bytes from an actual capture
 * would resolve this properly; none were available to verify against
 * while building this.
 *
 * WHAT IS RELIABLY KNOWN, and what this function actually does with
 * it: every source consulted agrees, without contradiction, that (a)
 * a captured mPacket begins with the ordinary Ethernet preamble
 * (unlike a normal Ethernet capture, where the preamble is stripped
 * long before capture — preserving it is this link type's whole
 * reason for existing), and (b) SMD-E — a complete, never-fragmented
 * "express" frame — shares the exact same byte value as an ordinary
 * Ethernet SFD, 0xD5, confirmed identically across every source
 * checked, including general Ethernet PHY documentation entirely
 * independent of 802.3br. This function scans for that one,
 * confidently-known byte within a bounded window from the start of
 * the packet (covering the realistic preamble-length range with
 * margin, rather than assuming one fixed offset this project isn't
 * fully certain of); if found, everything after it is by definition a
 * complete, ordinary Ethernet frame and gets handed to the exact same
 * dispatch_by_ethertype() pipeline every other link type in this
 * project already uses — genuinely full dissection for that real
 * case, not a guess. If that byte isn't found in the search window,
 * the packet is a genuine preemption fragment (SMD-Sx or SMD-Cx) this
 * project cannot currently identify the sub-type of or reassemble —
 * reported as exactly that, honestly, rather than misidentified.
 */
static void parse_ethernet_mpacket_frame(const unsigned char *buf, ssize_t len) {
    if (len < 1) return;

    ssize_t search_limit = len < MPACKET_PREAMBLE_SEARCH_WINDOW ? len : MPACKET_PREAMBLE_SEARCH_WINDOW;
    for (ssize_t i = 0; i < search_limit; i++) {
        if (buf[i] != MPACKET_SFD_SMDE) continue;

        const unsigned char *frame = buf + i + 1;
        ssize_t frame_len = len - i - 1;
        if (frame_len < ETH_HDR_LEN) return;   /* found the marker but
                                                   not enough left for
                                                   even an Ethernet
                                                   header: malformed,
                                                   drop rather than guess */

        uint16_t ethertype = ntohs(*(const uint16_t *)(frame + 12));
        const unsigned char *payload = frame + ETH_HDR_LEN;
        ssize_t payload_len = frame_len - ETH_HDR_LEN;

        /* Same VLAN handling as parse_ethernet_frame() itself, for
         * consistency — a real express mPacket is an ordinary
         * Ethernet frame in every other respect, VLAN tags included. */
        if (ethertype == ETHERTYPE_8021Q || ethertype == ETHERTYPE_8021AD) {
            struct vlan_strip_result vlan;
            if (!vlan_strip(ethertype, (const uint8_t *)payload, (uint16_t)payload_len, &vlan)) {
                return;
            }
            ethertype = vlan.real_ethertype;
            payload = (const unsigned char *)vlan.payload;
            payload_len = vlan.payload_len;
        }

        dispatch_by_ethertype(ethertype, payload, payload_len);
        return;
    }

    /* No recognized SFD/SMD-E found in the search window: a genuine
     * preemption fragment this project can't currently identify the
     * sub-type of — reported honestly, not guessed at (see this
     * function's own header comment for the full reasoning). */
    printf("{\"protocol\":\"Ethernet-mPacket\",\"mpacket_fragment_type\":\"unidentified_preemption_fragment\","
           "\"note\":\"IEEE 802.3br frame-preemption fragment (SMD-Sx or SMD-Cx) — "
           "sub-type not decoded, real SMD byte values not confidently verified\"}\n");
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

/* ------------------------------------------------------------------
 * PCAP FILE READING — added so this engine can be tested offline
 * against a saved capture, not just a live interface. Classic pcap
 * format only (the older, simpler format: a 24-byte global header
 * followed by a sequence of 16-byte-header-prefixed packet records) —
 * pcapng (the newer, block-structured format several real captures in
 * this project actually use) is NOT handled here, stated honestly
 * rather than silently mishandled; converting pcapng to classic pcap
 * first (`tshark -F pcap -r in.pcapng -w out.pcap`, or Wireshark's own
 * "Save As") works as a practical workaround today.
 *
 * The pcap FILE format has its own endianness (declared by the magic
 * number, since either a little- or big-endian host could have
 * written it) — this affects ONLY the pcap-specific metadata fields
 * (the global header, and each packet record's header). The actual
 * captured PACKET BYTES are untouched by this and remain in real
 * network byte order exactly as every dissector in this project
 * already assumes — this file's own byte-order handling is entirely
 * separate from, and doesn't touch, the dissection pipeline itself.
 * ------------------------------------------------------------------ */

#define PCAP_MAGIC_MICROSEC        0xa1b2c3d4u
#define PCAP_MAGIC_MICROSEC_SWAP   0xd4c3b2a1u
#define PCAP_MAGIC_NANOSEC         0xa1b23c4du
#define PCAP_MAGIC_NANOSEC_SWAP    0x4d3cb2a1u

#define LINKTYPE_ETHERNET          1
#define LINKTYPE_IEEE802_11        105
#define LINKTYPE_IEEE802_11_RADIOTAP 127
#define LINKTYPE_RAW               101
#define LINKTYPE_LINUX_SLL         113
#define LINKTYPE_ETHERNET_MPACKET  274

static uint32_t pcap_read_u32(const uint8_t *p, bool swap) {
    uint32_t v;
    memcpy(&v, p, 4);
    if (!swap) return v;
    return ((v & 0x000000ffu) << 24) | ((v & 0x0000ff00u) << 8) |
           ((v & 0x00ff0000u) >> 8)  | ((v & 0xff000000u) >> 24);
}

static uint16_t pcap_read_u16(const uint8_t *p, bool swap) {
    uint16_t v;
    memcpy(&v, p, 2);
    if (!swap) return v;
    return (uint16_t)(((v & 0x00ff) << 8) | ((v & 0xff00) >> 8));
}

/* pcapng block type constants (Section 3 of the pcapng spec) — used
 * by process_pcapng_file() below, defined up here alongside the
 * classic-format constants since both readers share this section. */
#define PCAPNG_BLOCK_SHB            0x0A0D0D0Au   /* Section Header Block */
#define PCAPNG_BLOCK_IDB            0x00000001u   /* Interface Description Block */
#define PCAPNG_BLOCK_SPB            0x00000003u   /* Simple Packet Block */
#define PCAPNG_BLOCK_EPB            0x00000006u   /* Enhanced Packet Block */
#define PCAPNG_BYTE_ORDER_MAGIC     0x1A2B3C4Du
#define PCAPNG_MAX_INTERFACES       512  /* bounded, same discipline as
                                            every other array in this
                                            project — sized generously
                                            after a real file
                                            (`ultimate.pcapng`) turned
                                            up 313 genuine interfaces,
                                            not a hypothetical worst
                                            case */

/*
 * Shared by both file readers (classic pcap and pcapng below) — the
 * link-type-based dispatch was previously duplicated inline in
 * process_pcap_file() alone; factored out here once a second reader
 * needed the identical logic, so a future fix only has to happen in
 * one place. Radiotap handling matches the live-capture path's own
 * `--link-type=80211-radiotap` handling exactly (skip the self-
 * describing header length, then hand the rest to the same 802.11
 * dissector) — see that flag's own comment in main() for the real
 * capture this was verified against.
 *
 * Returns false (and dissects nothing) for a link type that's neither
 * Ethernet, raw 802.11, nor Radiotap+802.11, and isn't being forced
 * via a --link-type override — the classic pcap reader below rejects
 * a whole file upfront for exactly this reason (a single declared
 * link type covers every packet in that format), but pcapng allows
 * MULTIPLE interfaces with DIFFERENT link types in one file — a real,
 * not hypothetical, file (`ultimate.pcapng`) genuinely declares 4
 * distinct link types (1, 101, 113, 274) across its 313 interfaces.
 * Silently defaulting an unrecognized type to Ethernet, as an earlier
 * version of this function did, would have fed non-Ethernet bytes
 * (e.g. LINKTYPE_RAW, no link-layer header at all) into
 * parse_ethernet_frame() and produced garbage or misleading output
 * rather than either correctly dissecting them or honestly skipping
 * them — caught by checking this exact real file's link-type
 * diversity before shipping, not assumed.
 */
static bool dispatch_packet_by_linktype(uint32_t link_type, const unsigned char *buf,
                                         uint32_t len, bool force_80211, bool force_radiotap) {
    bool use_80211 = force_80211 || link_type == LINKTYPE_IEEE802_11;
    bool use_radiotap = force_radiotap || link_type == LINKTYPE_IEEE802_11_RADIOTAP;

    if (!use_80211 && !use_radiotap && link_type != LINKTYPE_ETHERNET &&
        link_type != LINKTYPE_RAW && link_type != LINKTYPE_LINUX_SLL &&
        link_type != LINKTYPE_ETHERNET_MPACKET) {
        return false;   /* unrecognized link type — caller decides how to report this */
    }

    if (use_radiotap) {
        if (len >= 4) {
            uint16_t radiotap_len = (uint16_t)buf[2] | ((uint16_t)buf[3] << 8);
            if (radiotap_len <= len) {
                parse_80211_frame(buf + radiotap_len, (ssize_t)(len - radiotap_len));
            }
        }
    } else if (use_80211) {
        parse_80211_frame(buf, (ssize_t)len);
    } else if (link_type == LINKTYPE_RAW) {
        parse_raw_ip_frame(buf, (ssize_t)len);
    } else if (link_type == LINKTYPE_LINUX_SLL) {
        parse_linux_sll_frame(buf, (ssize_t)len);
    } else if (link_type == LINKTYPE_ETHERNET_MPACKET) {
        parse_ethernet_mpacket_frame(buf, (ssize_t)len);
    } else {
        parse_ethernet_frame(buf, (ssize_t)len);
    }
    return true;
}

/*
 * Reads and dissects every packet in a classic-format pcap file.
 * Returns 0 on success (including "file had zero packets"), nonzero
 * on a file-level error (couldn't open, bad magic, truncated global
 * header). A single malformed PACKET record inside an otherwise-good
 * file is logged and skipped, not treated as fatal — matches this
 * project's "reject the bad packet, not the whole stream" discipline
 * everywhere else.
 */
static int process_pcap_file(const char *path, bool link_type_80211_arg,
                              bool link_type_80211_radiotap_arg) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        return 1;
    }

    uint8_t global_hdr[24];
    if (fread(global_hdr, 1, sizeof(global_hdr), f) != sizeof(global_hdr)) {
        fprintf(stderr, "%s: truncated pcap global header (need 24 bytes)\n", path);
        fclose(f);
        return 1;
    }

    uint32_t magic = pcap_read_u32(global_hdr, false);
    bool swap;
    bool nanosec;
    if (magic == PCAP_MAGIC_MICROSEC)          { swap = false; nanosec = false; }
    else if (magic == PCAP_MAGIC_MICROSEC_SWAP) { swap = true;  nanosec = false; }
    else if (magic == PCAP_MAGIC_NANOSEC)       { swap = false; nanosec = true;  }
    else if (magic == PCAP_MAGIC_NANOSEC_SWAP)  { swap = true;  nanosec = true;  }
    else {
        fprintf(stderr, "%s: unrecognized file format (magic 0x%08x is neither classic "
                        "pcap nor pcapng — this file's format auto-detection in main() "
                        "already ruled out pcapng before reaching this classic-pcap-"
                        "specific check, so this is genuinely neither)\n", path, magic);
        fclose(f);
        return 1;
    }
    /* nanosec now genuinely used below, to correctly scale each
     * record's sub-second timestamp field for flow_id ts_start/
     * ts_last — previously discarded entirely before flow-record
     * support existed. */

    uint32_t network = pcap_read_u32(global_hdr + 20, swap);

    const char *link_name =
        network == LINKTYPE_ETHERNET ? "Ethernet" :
        network == LINKTYPE_IEEE802_11 ? "raw 802.11" :
        network == LINKTYPE_IEEE802_11_RADIOTAP ? "Radiotap + 802.11" : "unsupported";
    fprintf(stderr, "%s: link type %u (%s)\n", path, network, link_name);

    if (network != LINKTYPE_ETHERNET && network != LINKTYPE_IEEE802_11 &&
        network != LINKTYPE_IEEE802_11_RADIOTAP) {
        fprintf(stderr, "%s: link type %u has no dissection path in this engine "
                        "yet (only Ethernet, raw 802.11, and Radiotap+802.11 are "
                        "wired up) — nothing to do\n", path, network);
        fclose(f);
        return 1;
    }

    /* The explicit --link-type flags remain available as an OVERRIDE
     * for a file whose own header claims Ethernet but actually needs
     * 802.11 handling (or vice versa) — genuinely rare, but cheaper to
     * allow than to assume the file header is always trustworthy. */
    bool use_80211 = link_type_80211_arg || network == LINKTYPE_IEEE802_11;
    bool use_radiotap = link_type_80211_radiotap_arg || network == LINKTYPE_IEEE802_11_RADIOTAP;

    unsigned char buf[SNAPLEN];
    uint32_t packet_count = 0, skipped_count = 0;

    for (;;) {
        uint8_t rec_hdr[16];
        size_t got = fread(rec_hdr, 1, sizeof(rec_hdr), f);
        if (got == 0) break;               /* clean EOF between records */
        if (got != sizeof(rec_hdr)) {
            fprintf(stderr, "%s: truncated packet record header near packet %u\n",
                    path, packet_count);
            break;
        }

        uint32_t ts_sec = pcap_read_u32(rec_hdr, swap);
        uint32_t ts_subsec = pcap_read_u32(rec_hdr + 4, swap);
        double ts = (double)ts_sec + (double)ts_subsec / (nanosec ? 1e9 : 1e6);
        flow_record_set_current_timestamp(ts);

        uint32_t incl_len = pcap_read_u32(rec_hdr + 8, swap);
        if (incl_len > sizeof(buf)) {
            fprintf(stderr, "%s: packet %u claims %u bytes, more than this engine's "
                            "%d-byte snaplen — skipping just this packet\n",
                    path, packet_count, incl_len, SNAPLEN);
            /* Still have to consume the bytes to stay synced with the
             * file, or every later record would be read from the
             * wrong offset. */
            if (fseek(f, (long)incl_len, SEEK_CUR) != 0) break;
            skipped_count++;
            packet_count++;
            continue;
        }

        size_t data_got = fread(buf, 1, incl_len, f);
        if (data_got != incl_len) {
            fprintf(stderr, "%s: truncated packet data at packet %u (wanted %u, got %zu)\n",
                    path, packet_count, incl_len, data_got);
            break;
        }

        /* Return value not checked here: `network` was already
         * validated upfront (only Ethernet/802.11/Radiotap+802.11
         * pass the check earlier in this function) — this can never
         * return false for a classic pcap file, unlike pcapng below
         * where different interfaces can have different link types. */
        (void)dispatch_packet_by_linktype(network, buf, incl_len, use_80211, use_radiotap);

        packet_count++;
    }

    /* Emit every flow accumulated during this file's read — see
     * dpi_flow_record.c's own header comment on scope (TCP flows
     * only, currently). */
    flow_record_emit_all_and_reset();

    fprintf(stderr, "%s: %u packets read, %u skipped (oversized)\n",
            path, packet_count, skipped_count);
    fclose(f);
    return 0;
}

/*
 * Reads and dissects every packet in a pcapng-format file — the
 * newer, block-structured capture format (Section Header Block,
 * Interface Description Blocks, Enhanced Packet Blocks) that many
 * modern tools default to, distinct from the older classic pcap
 * format `process_pcap_file()` above handles. Added because several
 * real captures used throughout this project's own development were
 * pcapng, and requiring a manual conversion step (`tshark -F pcap`)
 * before every run turned out to be real, avoidable friction —
 * confirmed the block layout precisely (byte-order-magic detection,
 * the exact fixed-field sizes and offsets in an Interface Description
 * Block and an Enhanced Packet Block) against this project's own
 * already-verified Python pcapng reader before writing any of this,
 * same discipline as every dissector in this project.
 *
 * Every block in pcapng ends with a repeated copy of its own total
 * length (for backward-reading tools) — this reader doesn't use that
 * for backward seeking, but does trust the block's OWN declared
 * total length to know how many bytes to skip past whatever it
 * didn't need from that block, the same "read what you need, skip
 * the rest by the block's own accounting" approach
 * `process_pcap_file()` uses for pcap record headers.
 *
 * Simple Packet Blocks (a rare, simplified alternative to Enhanced
 * Packet Blocks — RFC/spec allows them but real capture tools
 * overwhelmingly write Enhanced Packet Blocks) are recognized and
 * skipped explicitly rather than silently mis-parsed as an unknown
 * block type, but their packet data isn't dissected — no real
 * capture encountered during this project's development used them,
 * so there was nothing to verify the "which interface's link type
 * applies" assumption against (Simple Packet Blocks don't carry an
 * interface ID field at all, unlike Enhanced Packet Blocks).
 */
static int process_pcapng_file(const char *path, bool link_type_80211_arg,
                                bool link_type_80211_radiotap_arg) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        return 1;
    }

    /* The Section Header Block's own Block Total Length field is
     * itself in the file's byte order — which we don't know yet at
     * this point — so read just enough (type + length, still
     * uninterpreted, + the byte-order-magic field) to determine
     * endianness first, then come back and correctly reinterpret the
     * length. */
    uint8_t shb_start[12];
    if (fread(shb_start, 1, sizeof(shb_start), f) != sizeof(shb_start)) {
        fprintf(stderr, "%s: truncated pcapng file (need at least 12 bytes for a "
                        "Section Header Block)\n", path);
        fclose(f);
        return 1;
    }

    uint32_t block_type_unswapped = pcap_read_u32(shb_start, false);
    if (block_type_unswapped != PCAPNG_BLOCK_SHB) {
        fprintf(stderr, "%s: not a pcapng file (first block type 0x%08x, expected a "
                        "Section Header Block, 0x0a0d0d0a)\n", path, block_type_unswapped);
        fclose(f);
        return 1;
    }

    uint32_t magic_le = pcap_read_u32(shb_start + 8, false);
    uint32_t magic_be = pcap_read_u32(shb_start + 8, true);
    bool swap;
    if (magic_le == PCAPNG_BYTE_ORDER_MAGIC) swap = false;
    else if (magic_be == PCAPNG_BYTE_ORDER_MAGIC) swap = true;
    else {
        fprintf(stderr, "%s: Section Header Block has an unrecognized byte-order "
                        "magic (0x%08x) — corrupt or truncated file\n", path, magic_le);
        fclose(f);
        return 1;
    }

    uint32_t shb_total_len = pcap_read_u32(shb_start + 4, swap);
    if (shb_total_len < 12) {
        fprintf(stderr, "%s: Section Header Block declares an impossible length (%u)\n",
                path, shb_total_len);
        fclose(f);
        return 1;
    }
    if (fseek(f, (long)(shb_total_len - 12), SEEK_CUR) != 0) {
        fprintf(stderr, "%s: could not seek past the Section Header Block\n", path);
        fclose(f);
        return 1;
    }

    fprintf(stderr, "%s: pcapng file, %s-endian\n", path, swap ? "big" : "little");

    uint16_t interface_link_types[PCAPNG_MAX_INTERFACES];
    uint32_t n_interfaces = 0;

    unsigned char buf[SNAPLEN];
    uint32_t packet_count = 0, skipped_count = 0, idb_count = 0, unsupported_linktype_count = 0;

    for (;;) {
        uint8_t block_hdr[8];
        size_t got = fread(block_hdr, 1, sizeof(block_hdr), f);
        if (got == 0) break;   /* clean EOF between blocks */
        if (got != sizeof(block_hdr)) {
            fprintf(stderr, "%s: truncated block header near packet %u\n", path, packet_count);
            break;
        }

        uint32_t this_type = pcap_read_u32(block_hdr, swap);
        uint32_t this_total_len = pcap_read_u32(block_hdr + 4, swap);
        if (this_total_len < 12) {
            fprintf(stderr, "%s: block declares an impossible length (%u) near packet %u, "
                            "stopping\n", path, this_total_len, packet_count);
            break;
        }
        /* Everything after the 8-byte header we just read, for this
         * one block: body + the trailing repeated-length field. */
        long remaining_in_block = (long)(this_total_len - 8);

        if (this_type == PCAPNG_BLOCK_IDB) {
            uint8_t idb_fixed[4];   /* LinkType(2) + Reserved(2) */
            if (this_total_len - 12 < 4 ||
                fread(idb_fixed, 1, sizeof(idb_fixed), f) != sizeof(idb_fixed)) {
                fprintf(stderr, "%s: truncated or malformed Interface Description Block, "
                                "stopping\n", path);
                break;
            }
            uint16_t link_type = pcap_read_u16(idb_fixed, swap);
            if (n_interfaces < PCAPNG_MAX_INTERFACES) {
                interface_link_types[n_interfaces] = link_type;
            } else {
                fprintf(stderr, "%s: more than %d interfaces declared, ignoring link type "
                                "for interface %u\n", path, PCAPNG_MAX_INTERFACES, n_interfaces);
            }
            n_interfaces++;
            idb_count++;
            remaining_in_block -= (long)sizeof(idb_fixed);
            if (remaining_in_block > 0 && fseek(f, remaining_in_block, SEEK_CUR) != 0) break;

        } else if (this_type == PCAPNG_BLOCK_EPB) {
            uint8_t epb_fixed[20];   /* InterfaceID(4)+TsHigh(4)+TsLow(4)+CapLen(4)+OrigLen(4) */
            if (this_total_len - 12 < sizeof(epb_fixed) ||
                fread(epb_fixed, 1, sizeof(epb_fixed), f) != sizeof(epb_fixed)) {
                fprintf(stderr, "%s: truncated or malformed Enhanced Packet Block near "
                                "packet %u, stopping\n", path, packet_count);
                break;
            }
            uint32_t iface_id = pcap_read_u32(epb_fixed, swap);
            uint32_t ts_high = pcap_read_u32(epb_fixed + 4, swap);
            uint32_t ts_low = pcap_read_u32(epb_fixed + 8, swap);
            uint32_t captured_len = pcap_read_u32(epb_fixed + 12, swap);
            /* pcapng timestamps are a 64-bit value in units the
             * interface declares via an if_tsresol option on its own
             * Interface Description Block — this reader doesn't parse
             * IDB options (only the fixed LinkType field), so this
             * assumes the overwhelmingly common default (microsecond
             * resolution, i.e. if_tsresol absent) rather than reading
             * a per-interface resolution that isn't extracted here.
             * Stated honestly as a real, if narrow, limitation — a
             * capture using a non-default (e.g. nanosecond) interface
             * resolution would show timestamps off by a fixed
             * multiplicative factor, not garbage, but not correct
             * either. */
            uint64_t ts_raw = ((uint64_t)ts_high << 32) | ts_low;
            flow_record_set_current_timestamp((double)ts_raw / 1e6);
            remaining_in_block -= (long)sizeof(epb_fixed);

            if (captured_len > sizeof(buf) || (long)captured_len > remaining_in_block) {
                fprintf(stderr, "%s: packet %u claims %u bytes, more than this engine's "
                                "%d-byte snaplen or the block's own declared size — "
                                "skipping just this packet\n",
                        path, packet_count, captured_len, SNAPLEN);
                if (remaining_in_block > 0 && fseek(f, remaining_in_block, SEEK_CUR) != 0) break;
                skipped_count++;
                packet_count++;
                continue;
            }

            size_t data_got = fread(buf, 1, captured_len, f);
            if (data_got != captured_len) {
                fprintf(stderr, "%s: truncated packet data at packet %u (wanted %u, got %zu)\n",
                        path, packet_count, captured_len, data_got);
                break;
            }
            remaining_in_block -= (long)captured_len;

            /* Bounded by BOTH n_interfaces AND PCAPNG_MAX_INTERFACES —
             * n_interfaces keeps counting every real IDB seen even
             * past the array's capacity (so an over-limit file is
             * still reported accurately in the summary line), but
             * that means checking against n_interfaces ALONE would
             * read past the array's actual 64 slots for any file
             * declaring more interfaces than that — confirmed this
             * matters against a real file (`ultimate.pcapng`, which
             * genuinely declares 313 interfaces, not a malformed or
             * adversarial case). */
            uint16_t link_type = (iface_id < n_interfaces && iface_id < PCAPNG_MAX_INTERFACES)
                                  ? interface_link_types[iface_id]
                                                          : LINKTYPE_ETHERNET;
            bool dissected = dispatch_packet_by_linktype(link_type, buf, captured_len,
                                         link_type_80211_arg, link_type_80211_radiotap_arg);
            if (!dissected) unsupported_linktype_count++;
            packet_count++;

            if (remaining_in_block > 0 && fseek(f, remaining_in_block, SEEK_CUR) != 0) break;

        } else if (this_type == PCAPNG_BLOCK_SPB) {
            /* Recognized, not dissected — see file header comment for why. */
            if (remaining_in_block > 0 && fseek(f, remaining_in_block, SEEK_CUR) != 0) break;

        } else {
            /* Any other block type (Name Resolution, Interface
             * Statistics, custom/vendor blocks, etc.) — not relevant
             * to packet dissection, skip by the block's own declared
             * length without treating it as an error. */
            if (remaining_in_block > 0 && fseek(f, remaining_in_block, SEEK_CUR) != 0) break;
        }
    }

    flow_record_emit_all_and_reset();

    fprintf(stderr, "%s: %u interface(s) declared, %u packets read, %u skipped (oversized), "
                    "%u skipped (unsupported link type)\n",
            path, idb_count, packet_count, skipped_count, unsupported_linktype_count);
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    bool link_type_80211 = false;
    bool link_type_80211_radiotap = false;
    const char *ifname = NULL;
    const char *pcap_file_path = NULL;

    /* Argument parsing rewritten as a flexible flag scan (rather than
     * the previous rigid argc==2/argc==3 positional checks) so
     * --pcap-file=<path> can combine with either --link-type flag,
     * the same way <interface> already could. First non-flag
     * argument is the interface name (live-capture modes only —
     * ignored/unused in --pcap-file mode). */
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--pcap-file=", 12) == 0) {
            pcap_file_path = argv[i] + 12;
        } else if (strcmp(argv[i], "--link-type=80211") == 0) {
            link_type_80211 = true;
        } else if (strcmp(argv[i], "--link-type=80211-radiotap") == 0) {
            link_type_80211_radiotap = true;
        } else if (argv[i][0] != '-' && ifname == NULL) {
            ifname = argv[i];
        } else {
            fprintf(stderr, "unrecognized argument: %s\n", argv[i]);
            fprintf(stderr, "usage: %s <interface> [--link-type=80211|--link-type=80211-radiotap]\n", argv[0]);
            fprintf(stderr, "   or: %s --pcap-file=<path.pcap> [--link-type=80211|--link-type=80211-radiotap]\n", argv[0]);
            return 1;
        }
    }

    /* -------------------------------------------------------------
     * OFFLINE MODE: read a saved capture file instead of a live
     * interface — either classic pcap or pcapng, auto-detected from
     * the file's own first 4 bytes (no separate flag needed; both
     * formats declare their own type unambiguously in that first
     * word). Added specifically so this engine can be tested against
     * a capture without needing CAP_NET_RAW, a real interface, or
     * root at all — register_all_dissectors() is the only setup
     * needed; no socket, no privilege drop, no seccomp filter
     * (there's no live, attacker-reachable file descriptor to defend
     * here the way there is for a raw capture socket).
     * ------------------------------------------------------------- */
    if (pcap_file_path) {
        register_all_dissectors();

        FILE *probe = fopen(pcap_file_path, "rb");
        if (!probe) {
            fprintf(stderr, "cannot open %s: %s\n", pcap_file_path, strerror(errno));
            return 1;
        }
        uint8_t magic4[4];
        size_t magic_got = fread(magic4, 1, sizeof(magic4), probe);
        fclose(probe);
        if (magic_got != sizeof(magic4)) {
            fprintf(stderr, "%s: file too short to identify (need at least 4 bytes)\n",
                    pcap_file_path);
            return 1;
        }
        uint32_t magic_check = pcap_read_u32(magic4, false);

        if (magic_check == PCAPNG_BLOCK_SHB) {
            return process_pcapng_file(pcap_file_path, link_type_80211, link_type_80211_radiotap);
        }
        /* Anything else is handed to the classic-pcap reader, which
         * does its own, more specific magic-number check (covering
         * both byte orders and both microsecond/nanosecond variants)
         * and reports a precise error — including this same pcapng
         * hint — if it isn't actually a classic pcap file either. */
        return process_pcap_file(pcap_file_path, link_type_80211, link_type_80211_radiotap);
    }

    if (!ifname) {
        fprintf(stderr, "usage: %s <interface> [--link-type=80211|--link-type=80211-radiotap]\n", argv[0]);
        fprintf(stderr, "   or: %s --pcap-file=<path.pcap> [--link-type=80211|--link-type=80211-radiotap]\n", argv[0]);
        return 1;
    }

    int sock = open_capture_socket(ifname);
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
        if (link_type_80211_radiotap) {
            if (n < 4) continue;   /* not even enough for Radiotap's own length field */
            uint16_t radiotap_len = (uint16_t)buf[2] | ((uint16_t)buf[3] << 8);
            if (radiotap_len > n) continue;   /* claims more than we received: drop, don't guess */
            parse_80211_frame(buf + radiotap_len, n - radiotap_len);
        } else if (link_type_80211) {
            parse_80211_frame(buf, n);
        } else {
            parse_ethernet_frame(buf, n);
        }
    }

    close(sock);
    return 0;
}
