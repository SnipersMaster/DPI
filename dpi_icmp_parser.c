/*
 * dpi_icmp_parser.c
 *
 * ICMP (RFC 792) and ICMPv6 (RFC 4443) dissectors — basic but
 * genuinely missing network visibility (ping, traceroute, destination
 * unreachable, and for ICMPv6 specifically, Neighbor Discovery: router/
 * neighbor solicitation and advertisement).
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * -------------------------------------------------------------------
 * WHY THIS DOESN'T GO THROUGH THE NORMAL PORT-BASED DISPATCH
 * -------------------------------------------------------------------
 * ICMP/ICMPv6 are their own IP protocol numbers (1 and 58
 * respectively) — they run directly over IP, not over TCP/UDP, and
 * have no port concept at all. The registry's detect()/dissect()
 * function pointers still fit (this file registers into it exactly
 * like every other dissector), but the CAPTURE PATH needs its own
 * branch for IP protocol 1 / IPv6 next_header 58, alongside the
 * existing TCP/UDP branches — there's no "ICMP port" to dispatch on.
 * dst_port is passed as 0 to detect()/dissect() (unused) and
 * l4_proto is "ICMP" or "ICMPv6" — synthetic markers, not real
 * transport-layer protocol names, but they compose fine with the
 * existing generic dissector interface since it just treats l4_proto
 * as an opaque string.
 *
 * -------------------------------------------------------------------
 * ICMPv6 CHECKSUM — A REAL INTERFACE LIMITATION, STATED HONESTLY
 * -------------------------------------------------------------------
 * Unlike ICMPv4 (whose checksum is self-contained — computed over just
 * the ICMP message, no pseudo-header), ICMPv6's checksum REQUIRES the
 * IPv6 pseudo-header (RFC 8200 §8.1, same construction UDP/TCP-over-
 * IPv6 use) — meaning it needs the source/destination IPv6 addresses.
 * The generic dissector interface (detect/dissect) doesn't pass IP
 * addresses to any dissector — no existing dissector needed them
 * before this one. Rather than change that shared interface for one
 * protocol's checksum need, icmpv6_dissect() here does NOT verify the
 * checksum itself; the capture path (which DOES have the IPv6
 * addresses in scope) computes and appends checksum_valid as an extra
 * field after calling dispatch_dissection(), reusing
 * ipv6_pseudo_header_partial() from dpi_ipv6_parser.c. This is the
 * same "handle it at the call site, not inside the generic interface"
 * pattern used elsewhere when a protocol's needs don't fit the shared
 * signature.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

/* ==================================================================
 * ICMPv4 (RFC 792)
 * ================================================================== */
#define ICMP_HDR_LEN 8   /* type(1)+code(1)+checksum(2)+rest-of-header(4) */

static const char *icmpv4_type_name(uint8_t type) {
    switch (type) {
        case 0:  return "Echo Reply";
        case 3:  return "Destination Unreachable";
        case 4:  return "Source Quench";
        case 5:  return "Redirect";
        case 8:  return "Echo Request";
        case 11: return "Time Exceeded";
        case 12: return "Parameter Problem";
        case 13: return "Timestamp Request";
        case 14: return "Timestamp Reply";
        default: return "Unknown";
    }
}

static double icmpv4_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    (void)dst_port;
    if (strcmp(l4_proto, "ICMP") != 0) return 0.0;
    if (len < ICMP_HDR_LEN) return 0.0;
    return 0.9;   /* IP protocol number 1 already identified this as ICMP
                    * at the capture-path level before we're even called —
                    * confidence is inherently high, there's no port
                    * ambiguity the way TCP/UDP-based protocols have */
}

static void icmpv4_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint8_t type = payload[0];
    uint8_t code = payload[1];
    uint16_t checksum_field = (payload[2] << 8) | payload[3];

    /* ICMPv4 checksum has NO pseudo-header (unlike ICMPv6) — it's
     * computed over the whole ICMP message alone, so this can be
     * verified entirely within this function with no IP context. */
    uint8_t scratch[1500];
    bool checksum_valid = false;
    if (len <= sizeof(scratch)) {
        memcpy(scratch, payload, len);
        scratch[2] = 0; scratch[3] = 0;
        uint16_t computed = checksum16(scratch, len, 0);
        checksum_valid = (computed == checksum_field);
    }

    dissect_result_add(out, "icmp_type", icmpv4_type_name(type));
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", code);
    dissect_result_add(out, "icmp_code", buf);
    dissect_result_add(out, "icmp_checksum_valid", checksum_valid ? "true" : "false");

    if ((type == 0 || type == 8) && len >= ICMP_HDR_LEN) {
        /* Echo Reply/Request: rest-of-header is Identifier(2) + Sequence(2) */
        uint16_t identifier = (payload[4] << 8) | payload[5];
        uint16_t sequence = (payload[6] << 8) | payload[7];
        snprintf(buf, sizeof(buf), "%u", identifier);
        dissect_result_add(out, "icmp_echo_identifier", buf);
        snprintf(buf, sizeof(buf), "%u", sequence);
        dissect_result_add(out, "icmp_echo_sequence", buf);
    } else if (type == 5 && len >= ICMP_HDR_LEN) {
        /* Redirect: rest-of-header is the gateway IP address */
        char ipbuf[32];
        snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                 payload[4], payload[5], payload[6], payload[7]);
        dissect_result_add(out, "icmp_redirect_gateway", ipbuf);
    } else if ((type == 3 || type == 11) && len > ICMP_HDR_LEN) {
        /* Destination Unreachable / Time Exceeded: the original
         * (offending) packet's IP header + at least the first 8 bytes
         * of its L4 payload follow, per RFC 792. Same bounded (one
         * level, no further recursion) pattern as GTP-U inner-packet
         * dissection. IMPORTANT DIFFERENCE from GTP-U: RFC 792 only
         * guarantees 8 bytes of the ORIGINAL packet's data — enough
         * for a full UDP header (8 bytes) but NOT enough for a full
         * TCP header (20 bytes minimum). So this deliberately extracts
         * only what's always safe regardless of L4 protocol: the
         * embedded IP header (via parse_ipv4(), which validates its
         * own length independently) and, if there's room, just the
         * source/destination PORT NUMBERS directly — the first 4
         * bytes of ANY TCP or UDP header — rather than calling
         * parse_tcp()/parse_udp(), which would fail or misbehave
         * against a header that's likely truncated by design, not by
         * malice. Modern implementations (RFC 1812) often include
         * more than the original 8-byte minimum, but this dissector
         * doesn't assume that. */
        dissect_result_add(out, "icmp_original_packet_present", "true");

        const uint8_t *orig_pkt = payload + ICMP_HDR_LEN;
        uint16_t orig_len = len - ICMP_HDR_LEN;

        struct ipv4_result orig_ip;
        if (parse_ipv4(orig_pkt, orig_len, &orig_ip)) {
            char ipbuf[32];
            snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                     (orig_ip.src_addr >> 24) & 0xFF, (orig_ip.src_addr >> 16) & 0xFF,
                     (orig_ip.src_addr >> 8) & 0xFF, orig_ip.src_addr & 0xFF);
            dissect_result_add(out, "icmp_original_src_ip", ipbuf);
            snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                     (orig_ip.dst_addr >> 24) & 0xFF, (orig_ip.dst_addr >> 16) & 0xFF,
                     (orig_ip.dst_addr >> 8) & 0xFF, orig_ip.dst_addr & 0xFF);
            dissect_result_add(out, "icmp_original_dst_ip", ipbuf);

            if ((orig_ip.protocol == 6 || orig_ip.protocol == 17) && orig_ip.payload_len >= 4) {
                /* First 4 bytes of ANY TCP or UDP header are always
                 * src_port(2)+dst_port(2) — safe to read directly
                 * without calling the full parse_tcp()/parse_udp(),
                 * which require more bytes than RFC 792 guarantees. */
                uint16_t orig_src_port = (orig_ip.payload[0] << 8) | orig_ip.payload[1];
                uint16_t orig_dst_port = (orig_ip.payload[2] << 8) | orig_ip.payload[3];
                char portbuf[16];
                snprintf(portbuf, sizeof(portbuf), "%u", orig_src_port);
                dissect_result_add(out, "icmp_original_src_port", portbuf);
                snprintf(portbuf, sizeof(portbuf), "%u", orig_dst_port);
                dissect_result_add(out, "icmp_original_dst_port", portbuf);
                dissect_result_add(out, "icmp_original_protocol",
                                    orig_ip.protocol == 6 ? "TCP" : "UDP");
            }
        }
    }
}

static const uint16_t icmp_hint_ports[] = { 0 };   /* no port concept, see file header */

void register_icmp_dissector(void) {
    register_dissector("ICMP", icmpv4_detect, icmpv4_dissect, icmp_hint_ports, 0);
}

/* ==================================================================
 * ICMPv6 (RFC 4443), including Neighbor Discovery (RFC 4861) message
 * types since they're carried as ICMPv6 messages.
 * ================================================================== */
#define ICMPV6_HDR_LEN 8

static const char *icmpv6_type_name(uint8_t type) {
    switch (type) {
        case 1:   return "Destination Unreachable";
        case 2:   return "Packet Too Big";
        case 3:   return "Time Exceeded";
        case 4:   return "Parameter Problem";
        case 128: return "Echo Request";
        case 129: return "Echo Reply";
        case 133: return "Router Solicitation";
        case 134: return "Router Advertisement";
        case 135: return "Neighbor Solicitation";
        case 136: return "Neighbor Advertisement";
        case 137: return "Redirect";
        default:  return "Unknown";
    }
}

static double icmpv6_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    (void)dst_port;
    if (strcmp(l4_proto, "ICMPv6") != 0) return 0.0;
    if (len < ICMPV6_HDR_LEN) return 0.0;
    return 0.9;   /* same reasoning as icmpv4_detect — identified by IPv6
                    * next_header=58 at the capture path, not ambiguous */
}

static void icmpv6_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint8_t type = payload[0];
    uint8_t code = payload[1];
    /* Checksum NOT verified here — see this file's header comment on
     * why (needs the IPv6 pseudo-header, which this function doesn't
     * have access to). The capture path adds "icmpv6_checksum_valid"
     * to this same `out` after calling this function. */

    dissect_result_add(out, "icmpv6_type", icmpv6_type_name(type));
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", code);
    dissect_result_add(out, "icmpv6_code", buf);

    if ((type == 128 || type == 129) && len >= ICMPV6_HDR_LEN) {
        /* Echo Request/Reply: same rest-of-header shape as ICMPv4 */
        uint16_t identifier = (payload[4] << 8) | payload[5];
        uint16_t sequence = (payload[6] << 8) | payload[7];
        snprintf(buf, sizeof(buf), "%u", identifier);
        dissect_result_add(out, "icmpv6_echo_identifier", buf);
        snprintf(buf, sizeof(buf), "%u", sequence);
        dissect_result_add(out, "icmpv6_echo_sequence", buf);
    } else if ((type == 135 || type == 136) && len >= ICMPV6_HDR_LEN + 20) {
        /* Neighbor Solicitation/Advertisement, RFC 4861 §4.3/§4.4:
         * reserved(4) + Target Address(16). Extracting the target
         * address is genuinely useful for on-link host discovery /
         * spoofing detection — this is real, basic IPv6 network
         * visibility, same motivation as adding ICMP at all. */
        char target_buf[46];
        struct in6_addr target;
        memcpy(&target, payload + ICMPV6_HDR_LEN + 4, 16);
        if (inet_ntop(AF_INET6, &target, target_buf, sizeof(target_buf))) {
            dissect_result_add(out, "icmpv6_nd_target_address", target_buf);
        }
        if (type == 136 && len >= ICMPV6_HDR_LEN + 4) {
            /* NA flags byte: R(1)/S(1)/O(1) bits in the top 3 bits of
             * the reserved field's first byte. */
            uint8_t flags = payload[ICMPV6_HDR_LEN];
            bool router_flag = (flags & 0x80) != 0;
            bool solicited_flag = (flags & 0x40) != 0;
            bool override_flag = (flags & 0x20) != 0;
            dissect_result_add(out, "icmpv6_na_router_flag", router_flag ? "true" : "false");
            dissect_result_add(out, "icmpv6_na_solicited_flag", solicited_flag ? "true" : "false");
            dissect_result_add(out, "icmpv6_na_override_flag", override_flag ? "true" : "false");
        }
    } else if ((type == 1 || type == 3) && len > ICMPV6_HDR_LEN) {
        /* Destination Unreachable / Time Exceeded: original packet
         * follows. UNLIKE ICMPv4's RFC 792 (which guarantees only 8
         * bytes of the original packet's L4 data), RFC 4443 §2.4
         * requires including "as much of the invoking packet as
         * possible without the ICMPv6 packet exceeding the minimum
         * IPv6 MTU" (1280 bytes) — so a full embedded TCP/UDP header
         * is typically actually present, and parse_tcp_v6()/
         * parse_udp_v6() are safe to call directly here (they
         * validate their own length requirements internally and
         * simply return false if truncated, same as anywhere else in
         * this project — not assumed to succeed). */
        dissect_result_add(out, "icmpv6_original_packet_present", "true");

        const uint8_t *orig_pkt = payload + ICMPV6_HDR_LEN;
        uint16_t orig_len = len - ICMPV6_HDR_LEN;

        struct ipv6_result orig_ip6;
        if (parse_ipv6(orig_pkt, orig_len, &orig_ip6)) {
            char src_buf[46], dst_buf[46];
            ipv6_addr_to_string(orig_ip6.src_addr, src_buf, sizeof(src_buf));
            ipv6_addr_to_string(orig_ip6.dst_addr, dst_buf, sizeof(dst_buf));
            dissect_result_add(out, "icmpv6_original_src_ip", src_buf);
            dissect_result_add(out, "icmpv6_original_dst_ip", dst_buf);

            if (orig_ip6.next_header == 6 /* TCP */) {
                struct tcp_result orig_tcp;
                if (parse_tcp_v6(orig_ip6.src_addr, orig_ip6.dst_addr,
                                  orig_ip6.payload, orig_ip6.payload_len, &orig_tcp)) {
                    char portbuf[16];
                    snprintf(portbuf, sizeof(portbuf), "%u", orig_tcp.src_port);
                    dissect_result_add(out, "icmpv6_original_src_port", portbuf);
                    snprintf(portbuf, sizeof(portbuf), "%u", orig_tcp.dst_port);
                    dissect_result_add(out, "icmpv6_original_dst_port", portbuf);
                    dissect_result_add(out, "icmpv6_original_protocol", "TCP");
                } else if (orig_ip6.payload_len >= 4) {
                    /* Full header parse failed (truncated after all) —
                     * fall back to just the ports, same conservative
                     * approach as ICMPv4 above. */
                    uint16_t sp = (orig_ip6.payload[0] << 8) | orig_ip6.payload[1];
                    uint16_t dp = (orig_ip6.payload[2] << 8) | orig_ip6.payload[3];
                    char portbuf[16];
                    snprintf(portbuf, sizeof(portbuf), "%u", sp);
                    dissect_result_add(out, "icmpv6_original_src_port", portbuf);
                    snprintf(portbuf, sizeof(portbuf), "%u", dp);
                    dissect_result_add(out, "icmpv6_original_dst_port", portbuf);
                    dissect_result_add(out, "icmpv6_original_protocol", "TCP");
                }
            } else if (orig_ip6.next_header == 17 /* UDP */) {
                struct udp_result orig_udp;
                if (parse_udp_v6(orig_ip6.src_addr, orig_ip6.dst_addr,
                                  orig_ip6.payload, orig_ip6.payload_len, &orig_udp)) {
                    char portbuf[16];
                    snprintf(portbuf, sizeof(portbuf), "%u", orig_udp.src_port);
                    dissect_result_add(out, "icmpv6_original_src_port", portbuf);
                    snprintf(portbuf, sizeof(portbuf), "%u", orig_udp.dst_port);
                    dissect_result_add(out, "icmpv6_original_dst_port", portbuf);
                    dissect_result_add(out, "icmpv6_original_protocol", "UDP");
                }
            }
        }
    }
}

static const uint16_t icmpv6_hint_ports[] = { 0 };

void register_icmpv6_dissector(void) {
    register_dissector("ICMPv6", icmpv6_detect, icmpv6_dissect, icmpv6_hint_ports, 0);
}
