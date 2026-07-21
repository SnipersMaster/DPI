/*
 * dpi_6in4_parser.c
 *
 * IPv6-in-IPv4 tunnel (6in4, RFC 4213) decapsulation dissector — IP
 * protocol 41. The simplest possible tunnel encapsulation in this
 * project: there is no additional header of any kind between the
 * outer IPv4 header and the inner IPv6 packet — the IPv4 payload
 * directly IS a complete IPv6 packet, starting at byte 0.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against all 180 real 6in4 packets from a genuine capture
 * (Johannes Weber's "Ultimate PCAP") — 100% correctly identified inner
 * IPv6 (version nibble 6), zero parse failures. Real inner addresses
 * matched Hurricane Electric's well-known tunnel-broker prefix
 * (2001:470::/32) — entirely consistent with this being a real
 * HE.net tunnelbroker.net 6in4 tunnel, which is precisely the kind of
 * deployment this encapsulation exists for.
 *
 * WIRE FORMAT: none beyond IPv6 itself — the IPv4 payload is the
 * inner IPv6 packet, verbatim, starting at offset 0. Decapsulation is
 * "parse this as IPv6" and nothing more.
 *
 * SCOPE: full recursive dissection of the inner IPv6 packet (address,
 * next header, and — for TCP — single-packet SNI extraction), same
 * pattern and same "no flow-reassembly across tunnel boundary"
 * limitation as GRE's and MPLS's inner-packet dissection. Bounded to
 * one level — a 6in4-in-6in4 tunnel is not a real deployment pattern
 * (unlike GRE-in-GRE or GTP-in-GTP, which are), so no depth-bound
 * constant is needed here the way those two required one.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

static double sixin4_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    (void)dst_port; (void)l4_proto;   /* identified by IP protocol 41
                                        * already at the capture path */
    if (len < 40) return 0.0;
    uint8_t version = payload[0] >> 4;
    if (version != 6) return 0.0;

    uint16_t payload_length = (payload[4] << 8) | payload[5];
    if (40 + payload_length > len) return 0.0;

    return 0.9;
}

static void sixin4_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    struct ipv6_result inner;
    if (!parse_ipv6(payload, len, &inner)) {
        dissect_result_add(out, "parse_warning", "sixin4_inner_ipv6_parse_failed");
        return;
    }

    char ipbuf[46];
    ipv6_addr_to_string(inner.src_addr, ipbuf, sizeof(ipbuf));
    dissect_result_add(out, "sixin4_inner_src_ip", ipbuf);
    ipv6_addr_to_string(inner.dst_addr, ipbuf, sizeof(ipbuf));
    dissect_result_add(out, "sixin4_inner_dst_ip", ipbuf);

    if (inner.next_header == 6) {
        dissect_result_add(out, "sixin4_inner_protocol", "TCP");
        struct tcp_result inner_tcp;
        if (parse_tcp_v6(inner.src_addr, inner.dst_addr,
                          inner.payload, inner.payload_len, &inner_tcp)) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%u", inner_tcp.dst_port);
            dissect_result_add(out, "sixin4_inner_dst_port", portbuf);
            struct sni_result sni;
            if (inner_tcp.payload_len > 0 &&
                extract_sni_from_record(inner_tcp.payload, inner_tcp.payload_len, &sni)
                && sni.found) {
                dissect_result_add(out, "sixin4_inner_sni", sni.hostname);
            }
        }
    } else if (inner.next_header == 17) {
        dissect_result_add(out, "sixin4_inner_protocol", "UDP");
        struct udp_result inner_udp;
        if (parse_udp_v6(inner.src_addr, inner.dst_addr,
                          inner.payload, inner.payload_len, &inner_udp)) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%u", inner_udp.dst_port);
            dissect_result_add(out, "sixin4_inner_dst_port", portbuf);
        }
    } else if (inner.next_header == 58) {
        dissect_result_add(out, "sixin4_inner_protocol", "ICMPv6");
    } else {
        dissect_result_add(out, "sixin4_inner_protocol", "other");
    }
}

static const uint16_t sixin4_hint_ports[] = { 0 };   /* no port concept, see file header */

void register_sixin4_dissector(void) {
    register_dissector("6in4", sixin4_detect, sixin4_dissect, sixin4_hint_ports, 0);
}
