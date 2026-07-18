/*
 * dpi_ipv6_parser.c
 *
 * IPv6 (RFC 8200) fixed header + extension header chain parsing.
 *
 * SCOPE, stated upfront: this file parses IPv6 and hands off to
 * IPv6-specific TCP/UDP checksum verification (parse_tcp_v6/
 * parse_udp_v6 below), which are wired into the UDP-based dissector
 * path in both capture files (GTP, DNS, RADIUS, QUIC, VPN
 * fingerprinting all now work over IPv6). TCP-over-IPv6 is parsed and
 * checksum-verified here, but NOT yet wired into
 * dpi_tcp_flow_reassembly.c — that file's flow key
 * (struct tcp_flow_key) uses 32-bit fields sized for IPv4 addresses
 * only. Extending it to hold 128-bit addresses (and updating every
 * caller that constructs a key) is a real, separate integration task,
 * not done in this pass — flagged here rather than half-wired
 * silently. TCP-over-IPv6 flows currently get parsed at the IP/TCP
 * layer but won't reach classification/reassembly until that follow-up
 * lands.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * -------------------------------------------------------------------
 * WHY A SEPARATE CHECKSUM PATH FROM IPv4's
 * -------------------------------------------------------------------
 * RFC 8200 §8.1 defines a DIFFERENT pseudo-header for IPv6's TCP/UDP
 * checksum than IPv4 uses: 16-byte addresses instead of 4-byte, and an
 * explicit 32-bit upper-layer-packet-length field instead of relying
 * on the IP header's own length field the way IPv4's pseudo-header
 * does. Rather than risk destabilizing the already-relied-upon IPv4
 * parse_tcp()/parse_udp() in dpi_rfc_parser.c with a wider, riskier
 * refactor, this file adds parallel _v6 functions with the IPv6
 * pseudo-header construction, sharing the same checksum16() helper
 * and the same TCP/UDP header field parsing logic. Some duplication
 * versus a fully unified implementation — an intentional, lower-risk
 * tradeoff, not an oversight.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>

#define IPV6_HDR_LEN         40
#define IPV6_MAX_EXT_HEADERS 8   /* bound against a maliciously long or
                                    cyclic-looking extension chain —
                                    real IPv6 traffic essentially never
                                    has more than 2-3 */

/* Next Header values that are extension headers needing further
 * walking, vs. ones that terminate the chain (an actual upper-layer
 * protocol, or something we don't walk past). */
#define NH_HOP_BY_HOP   0
#define NH_ROUTING      43
#define NH_FRAGMENT     44
#define NH_DEST_OPTS    60
#define NH_TCP          6
#define NH_UDP          17
#define NH_ICMPV6       58
#define NH_ESP          50   /* encrypted from here on — nothing more to parse */
#define NH_AH           51

struct ipv6_result {
    uint8_t  src_addr[16];
    uint8_t  dst_addr[16];
    uint8_t  next_header;    /* final next_header after walking extensions —
                               * the actual upper-layer protocol, or an
                               * unwalked one (ESP/AH/unknown) */
    bool     is_fragment;    /* true if a Fragment extension header was seen */
    const uint8_t *payload;
    uint16_t payload_len;
};

static bool parse_ipv6(const uint8_t *pkt, uint16_t len, struct ipv6_result *out) {
    if (len < IPV6_HDR_LEN) return false;

    uint8_t version = pkt[0] >> 4;
    if (version != 6) return false;

    uint16_t payload_length = (pkt[4] << 8) | pkt[5];
    uint8_t next_header = pkt[6];
    /* octet 7 is Hop Limit — not needed for parsing */

    if ((size_t)IPV6_HDR_LEN + payload_length > len) return false;

    memcpy(out->src_addr, pkt + 8, 16);
    memcpy(out->dst_addr, pkt + 24, 16);
    out->is_fragment = false;

    size_t pos = IPV6_HDR_LEN;
    size_t end = IPV6_HDR_LEN + payload_length;
    int ext_count = 0;

    /* Walk the extension header chain. Each extension header (except
     * Fragment, which has a fixed 8-byte size) has the format:
     *   Next Header(1) + Header Extension Length(1, in 8-byte units,
     *   NOT counting the first 8 bytes) + header-specific data.
     * Bounded by IPV6_MAX_EXT_HEADERS regardless of what the chain
     * claims — an attacker-crafted chain that's technically
     * well-formed but absurdly long is still rejected past the cap. */
    while (next_header == NH_HOP_BY_HOP || next_header == NH_ROUTING ||
           next_header == NH_FRAGMENT || next_header == NH_DEST_OPTS) {
        if (++ext_count > IPV6_MAX_EXT_HEADERS) return false;
        if (pos + 8 > end) return false;   /* every extension header is at least 8 bytes */

        uint8_t this_next_header = pkt[pos];

        size_t ext_len;
        if (next_header == NH_FRAGMENT) {
            ext_len = 8;   /* Fragment header is always exactly 8 bytes, RFC 8200 §4.5 */
            out->is_fragment = true;
        } else {
            uint8_t hdr_ext_len_units = pkt[pos + 1];
            ext_len = (size_t)(hdr_ext_len_units + 1) * 8;
        }

        if (pos + ext_len > end) return false;   /* claims more than we have */

        pos += ext_len;
        next_header = this_next_header;
    }

    out->next_header = next_header;
    out->payload = pkt + pos;
    out->payload_len = (uint16_t)(end - pos);
    return true;
}

/* ------------------------------------------------------------------
 * IPv6 pseudo-header partial checksum, RFC 8200 §8.1. Same additive
 * accumulation approach as the IPv4/TCP pseudo-header in
 * dpi_rfc_parser.c's tcp_checksum_valid — kept as a partial sum here
 * so it composes with checksum16()'s `init` parameter the same way.
 * ------------------------------------------------------------------ */
static uint32_t ipv6_pseudo_header_partial(const uint8_t *src16, const uint8_t *dst16,
                                            uint32_t upper_layer_len, uint8_t next_header) {
    uint32_t sum = 0;
    for (int i = 0; i < 16; i += 2) sum += (src16[i] << 8) | src16[i + 1];
    for (int i = 0; i < 16; i += 2) sum += (dst16[i] << 8) | dst16[i + 1];
    sum += (upper_layer_len >> 16) & 0xFFFF;
    sum += upper_layer_len & 0xFFFF;
    sum += next_header;   /* the 3 zero bytes before Next Header contribute 0 */
    return sum;
}

/* ------------------------------------------------------------------
 * TCP-over-IPv6: same header/options parsing as parse_tcp() in
 * dpi_rfc_parser.c, but with the IPv6 pseudo-header for checksum
 * verification. See this file's header comment on why this is a
 * parallel function rather than a shared one.
 * ------------------------------------------------------------------ */
static bool parse_tcp_v6(const uint8_t *src16, const uint8_t *dst16,
                          const uint8_t *seg, uint16_t seg_len, struct tcp_result *out) {
    if (seg_len < TCP_MIN_HDR_BYTES) return false;

    const struct tcp_hdr *tcp = (const struct tcp_hdr *)seg;
    uint8_t data_off = (tcp->data_off_reserved >> 4) * 4;
    if (data_off < TCP_MIN_HDR_BYTES || data_off > seg_len) return false;

    out->src_port = ntohs(tcp->src_port);
    out->dst_port = ntohs(tcp->dst_port);
    out->seq = ntohl(tcp->seq);
    out->ack = ntohl(tcp->ack);
    out->flags = tcp->flags;
    out->window = ntohs(tcp->window);

    uint32_t partial = ipv6_pseudo_header_partial(src16, dst16, seg_len, NH_TCP);
    uint8_t scratch[1500];
    if (seg_len > sizeof(scratch)) {
        out->checksum_valid = false;
    } else {
        memcpy(scratch, seg, seg_len);
        scratch[16] = 0; scratch[17] = 0;
        uint16_t orig_checksum = ntohs(*(const uint16_t *)(seg + 16));
        uint16_t computed = checksum16(scratch, seg_len, partial);
        out->checksum_valid = (computed == orig_checksum);
    }

    if (data_off > TCP_MIN_HDR_BYTES) {
        if (!parse_tcp_options(seg + TCP_MIN_HDR_BYTES,
                                data_off - TCP_MIN_HDR_BYTES, &out->options)) {
            return false;
        }
    } else {
        memset(&out->options, 0, sizeof(out->options));
    }

    out->payload = seg + data_off;
    out->payload_len = seg_len - data_off;
    return true;
}

/* ------------------------------------------------------------------
 * UDP-over-IPv6: same structure as parse_udp() in dpi_rfc_parser.c,
 * IPv6 pseudo-header for checksum. Unlike IPv4, UDP checksum is
 * MANDATORY over IPv6 (RFC 8200 §8.1) — a zero checksum field is
 * invalid, not "not computed" the way it's optional over IPv4.
 * ------------------------------------------------------------------ */
static bool parse_udp_v6(const uint8_t *src16, const uint8_t *dst16,
                          const uint8_t *seg, uint16_t seg_len, struct udp_result *out) {
    if (seg_len < UDP_HDR_LEN) return false;

    uint16_t declared_len = (seg[4] << 8) | seg[5];
    if (declared_len < UDP_HDR_LEN || declared_len > seg_len) return false;

    out->src_port = (seg[0] << 8) | seg[1];
    out->dst_port = (seg[2] << 8) | seg[3];
    uint16_t checksum_field = (seg[6] << 8) | seg[7];

    out->checksum_present = true;   /* mandatory over IPv6 — a zero value here
                                       * is a protocol violation, not "absent" */
    if (checksum_field == 0) {
        out->checksum_valid = false;
    } else {
        uint32_t partial = ipv6_pseudo_header_partial(src16, dst16, declared_len, NH_UDP);
        uint8_t scratch[1500];
        if (declared_len > sizeof(scratch)) {
            out->checksum_valid = false;
        } else {
            memcpy(scratch, seg, declared_len);
            scratch[6] = 0; scratch[7] = 0;
            uint16_t computed = checksum16(scratch, declared_len, partial);
            out->checksum_valid = (computed == checksum_field);
        }
    }

    out->payload = seg + UDP_HDR_LEN;
    out->payload_len = declared_len - UDP_HDR_LEN;
    return true;
}

/* Helper for dissectors/logging that want a human-readable address —
 * not used on any hot path, just for the JSON flow record fields. */
static void ipv6_addr_to_string(const uint8_t *addr16, char *out, size_t out_cap) {
    inet_ntop(AF_INET6, addr16, out, (socklen_t)out_cap);
}
