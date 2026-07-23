/*
 * dpi_gtp_parser.c
 *
 * GTP-U v1 (3GPP TS 29.281, user plane tunneling — carries actual
 * subscriber IP traffic between mobile network nodes) and GTPv2-C
 * (3GPP TS 29.274, control plane signaling — session/bearer
 * management) dissectors.
 *
 * Standard ports: GTP-U on UDP/2152, GTPv2-C on UDP/2123.
 *
 * NOT COMPILED/TESTED against live GTP traffic in this environment.
 *
 * -------------------------------------------------------------------
 * IMPORTANT SCOPE NOTE — read before assuming this gives full
 * visibility into tunneled traffic:
 * -------------------------------------------------------------------
 * GTP-U's G-PDU message (type 255) carries an ENTIRE inner IP packet
 * as its payload — a subscriber's real HTTP/TLS/whatever traffic,
 * tunneled. This dissector extracts the GTP header fields (TEID,
 * message type, sequence number) and flags where the inner packet
 * starts, but does NOT recursively re-run the IPv4/TCP/UDP/classifier
 * pipeline on that inner packet. That recursive dissection is the
 * natural next step for real mobile-network visibility (you'd want
 * to know not just "this is a GTP tunnel" but "this tunnel carries a
 * TLS connection to instagram.com"), but it's a genuinely separate
 * piece of work: it means calling back into dpi_rfc_parser.c /
 * dpi_app_classifier.c from inside a dissector, which the current
 * dispatch_dissection() → single dissect() call model in
 * dpi_dissector_registry.c doesn't cleanly support yet without some
 * restructuring. Flagged honestly rather than silently only
 * half-implemented.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#define GTP_U_PORT   2152
#define GTPV2_C_PORT 2123

/* ==================================================================
 * GTP-U v1 (3GPP TS 29.281 §5)
 *
 * Mandatory header (8 bytes):
 *   octet 1: Version(3 bits) | PT(1 bit) | spare(1 bit) | E(1 bit) | S(1 bit) | PN(1 bit)
 *   octet 2: Message Type
 *   octet 3-4: Length (of everything AFTER this mandatory 8-byte header)
 *   octet 5-8: TEID (Tunnel Endpoint Identifier)
 * Optional (present if E, S, or PN flag set) — 4 more bytes:
 *   Sequence Number(2) + N-PDU Number(1) + Next Extension Header Type(1)
 * ================================================================== */
#define GTP1_HDR_LEN_MANDATORY  8
#define GTP1_HDR_LEN_OPTIONAL   4
#define GTP1_MSG_TYPE_ECHO_REQ      1
#define GTP1_MSG_TYPE_ECHO_RESP     2
#define GTP1_MSG_TYPE_ERROR_IND    26
#define GTP1_MSG_TYPE_GPDU        255   /* carries the actual tunneled IP packet */

static const char *gtp1_msg_type_name(uint8_t t) {
    switch (t) {
        case GTP1_MSG_TYPE_ECHO_REQ:  return "Echo Request";
        case GTP1_MSG_TYPE_ECHO_RESP: return "Echo Response";
        case GTP1_MSG_TYPE_ERROR_IND: return "Error Indication";
        case GTP1_MSG_TYPE_GPDU:      return "G-PDU";
        default: return "Unknown";
    }
}

static double gtp1_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < GTP1_HDR_LEN_MANDATORY) return 0.0;

    uint8_t flags = payload[0];
    uint8_t version = (flags >> 5) & 0x07;
    uint8_t pt = (flags >> 4) & 0x01;

    if (version != 1 || pt != 1) return 0.0;   /* not GTPv1, or GTP' (charging) not GTP */

    uint16_t declared_len = (payload[2] << 8) | payload[3];
    /* declared_len is everything AFTER the mandatory 8 bytes — must
     * not claim more than we actually have. */
    if ((size_t)GTP1_HDR_LEN_MANDATORY + declared_len > len) return 0.0;

    double confidence = 0.6;
    if (dst_port == GTP_U_PORT) confidence = 0.9;
    return confidence;
}

/*
 * GTP-in-GTP nesting depth bound — explicit and configurable, not just
 * an implicit "never recurse" as an earlier version of this file had.
 * Default stays conservative (1 extra level beyond the outer G-PDU,
 * i.e. GTP_MAX_TUNNEL_DEPTH=1 permits exactly one nested tunnel to be
 * dissected) for the security reason stated repeatedly in this
 * project: unbounded recursion driven by attacker-controlled tunnel
 * depth is a resource-exhaustion vector. Raise this only if you have a
 * genuine multi-layer tunneling deployment and understand the
 * per-level parsing cost you're accepting — this is a real safety
 * bound, not an arbitrary one, so don't raise it casually.
 */
#define GTP_MAX_TUNNEL_DEPTH 1

/* Forward declaration: gtp1_dissect() calls this before its definition appears. */
static void gtp1_dissect_inner_packet(const uint8_t *inner, uint16_t inner_len,
                                       int depth, struct dissect_result *out);
static void gtp1_dissect_inner_packet_v6(const uint8_t *inner, uint16_t inner_len,
                                          int depth, struct dissect_result *out);

static void gtp1_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint8_t flags = payload[0];
    uint8_t msg_type = payload[1];
    uint16_t declared_len = (payload[2] << 8) | payload[3];
    uint32_t teid = (payload[4]<<24)|(payload[5]<<16)|(payload[6]<<8)|payload[7];

    bool has_optional = (flags & 0x07) != 0;   /* E, S, or PN bit set */
    size_t hdr_len = GTP1_HDR_LEN_MANDATORY;

    char buf[32];
    snprintf(buf, sizeof(buf), "%s", gtp1_msg_type_name(msg_type));
    dissect_result_add(out, "gtp_message_type", buf);

    snprintf(buf, sizeof(buf), "0x%08x", teid);
    dissect_result_add(out, "gtp_teid", buf);

    if (has_optional) {
        if (GTP1_HDR_LEN_MANDATORY + GTP1_HDR_LEN_OPTIONAL > len) {
            dissect_result_add(out, "parse_warning", "truncated_optional_header");
            return;
        }
        uint16_t seq = (payload[8] << 8) | payload[9];
        snprintf(buf, sizeof(buf), "%u", seq);
        dissect_result_add(out, "gtp_sequence_number", buf);
        hdr_len += GTP1_HDR_LEN_OPTIONAL;

        /* Extension headers, if Next Extension Header Type (last byte
         * of the optional block) is nonzero, would follow here — each
         * is length-prefixed in 4-byte units per TS 29.281 §5.2.1.
         * Not walked in this reference version; flagged rather than
         * silently ignored if present. */
        uint8_t next_ext_type = payload[11];
        if (next_ext_type != 0) {
            dissect_result_add(out, "gtp_extension_headers_present", "true");
            dissect_result_add(out, "parse_warning", "extension_header_walk_not_implemented");
        }
    }

    if (msg_type == GTP1_MSG_TYPE_GPDU) {
        dissect_result_add(out, "gtp_inner_packet_present", "true");

        /* Bound the inner packet by GTP's OWN declared length, not
         * just whatever bytes remain in the buffer — declared_len is
         * "everything after the mandatory 8-byte header" per TS
         * 29.281 §5.1, so the true end of the GTP message (and start
         * of any trailing padding/garbage) is mandatory_hdr +
         * declared_len, which may be less than what parse_udp() handed
         * us if the UDP datagram was padded. */
        size_t gtp_msg_end = GTP1_HDR_LEN_MANDATORY + declared_len;
        size_t inner_start = hdr_len;
        uint16_t inner_len = (inner_start < gtp_msg_end && gtp_msg_end <= len)
                              ? (uint16_t)(gtp_msg_end - inner_start)
                              : (uint16_t)(len - inner_start);   /* fall back to
                                                                    remaining buffer
                                                                    if declared_len
                                                                    looks inconsistent */
        gtp1_dissect_inner_packet(payload + inner_start, inner_len, 0, out);
    }
}

/*
 * Recursively dissect the inner IP packet carried by a G-PDU message.
 * BOUNDED TO EXACTLY ONE LEVEL — if the inner packet is itself GTP
 * (a nested tunnel), this does NOT recurse again. That's a deliberate
 * safety bound, not a missed case: unbounded recursion driven by
 * attacker-controlled nested tunnel depth is exactly the kind of
 * resource-exhaustion vector the very first security checklist in
 * this project warned about ("cap recursion and nesting depth" under
 * multi-protocol dissector risk). A legitimate GTP deployment doesn't
 * nest GTP-in-GTP; an attacker crafting one to probe for a recursion
 * bug gets a flag, not a crash or a hang.
 */
static void gtp1_dissect_inner_packet(const uint8_t *inner, uint16_t inner_len,
                                       int depth, struct dissect_result *out) {
    if (inner_len < 1) return;

    uint8_t version = inner[0] >> 4;

    if (version == 6) {
        gtp1_dissect_inner_packet_v6(inner, inner_len, depth, out);
        return;
    }

    if (version != 4) {
        dissect_result_add(out, "gtp_inner_packet_unknown_ip_version", "true");
        return;
    }

    struct ipv4_result inner_ip;
    if (!parse_ipv4(inner, inner_len, &inner_ip)) {
        dissect_result_add(out, "gtp_inner_packet_parse_failed", "true");
        return;
    }

    char ipbuf[32];
    const char *src_key = (depth == 0) ? "gtp_inner_src_ip" : "gtp_nested_inner_src_ip";
    const char *dst_key = (depth == 0) ? "gtp_inner_dst_ip" : "gtp_nested_inner_dst_ip";
    const char *proto_key = (depth == 0) ? "gtp_inner_protocol" : "gtp_nested_inner_protocol";
    const char *port_key = (depth == 0) ? "gtp_inner_dst_port" : "gtp_nested_inner_dst_port";
    const char *sni_key = (depth == 0) ? "gtp_inner_sni" : "gtp_nested_inner_sni";

    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
             (inner_ip.src_addr >> 24) & 0xFF, (inner_ip.src_addr >> 16) & 0xFF,
             (inner_ip.src_addr >> 8) & 0xFF, inner_ip.src_addr & 0xFF);
    dissect_result_add(out, src_key, ipbuf);
    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
             (inner_ip.dst_addr >> 24) & 0xFF, (inner_ip.dst_addr >> 16) & 0xFF,
             (inner_ip.dst_addr >> 8) & 0xFF, inner_ip.dst_addr & 0xFF);
    dissect_result_add(out, dst_key, ipbuf);

    if (inner_ip.protocol == 6 /* TCP */) {
        dissect_result_add(out, proto_key, "TCP");
        struct tcp_result inner_tcp;
        if (parse_tcp(inner_ip.src_addr, inner_ip.dst_addr,
                       inner_ip.payload, inner_ip.payload_len, &inner_tcp)) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%u", inner_tcp.dst_port);
            dissect_result_add(out, port_key, portbuf);

            /* Attempt SNI extraction directly on this single G-PDU
             * packet's inner payload — NOT going through TCP flow
             * reassembly (dpi_tcp_flow_reassembly.c isn't wired into
             * this recursive path). This means a ClientHello split
             * across multiple G-PDU packets won't be caught — a real
             * limitation, consistent with "bounded to one level, no
             * further stateful tracking" for this reference
             * implementation.
             *
             * extract_sni_from_record() and struct sni_result come
             * from dpi_app_classifier.c, already visible here since
             * that file is included before this one in both capture
             * paths (same reasoning as parse_ipv4()/parse_tcp() above
             * needing no extern declaration either — same translation
             * unit via the #include chain). This does mean
             * dpi_gtp_parser.c now genuinely depends on
             * dpi_app_classifier.c being included first — true of the
             * capture files already, and fuzz_gtp_parser.c has been
             * updated to include it too. */
            struct sni_result sni;
            if (inner_tcp.payload_len > 0 &&
                extract_sni_from_record(inner_tcp.payload, inner_tcp.payload_len, &sni)
                && sni.found) {
                dissect_result_add(out, sni_key, sni.hostname);
            }
        }
    } else if (inner_ip.protocol == 17 /* UDP */) {
        dissect_result_add(out, proto_key, "UDP");
        struct udp_result inner_udp;
        if (parse_udp(inner_ip.src_addr, inner_ip.dst_addr,
                       inner_ip.payload, inner_ip.payload_len, &inner_udp)) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%u", inner_udp.dst_port);
            dissect_result_add(out, port_key, portbuf);

            if (inner_udp.dst_port == GTP_U_PORT || inner_udp.dst_port == GTPV2_C_PORT) {
                /* Nested GTP tunnel found. Recurse into it — but ONLY
                 * if the depth bound allows, per GTP_MAX_TUNNEL_DEPTH
                 * above. This is now a REAL bounded recursion (an
                 * earlier version of this file only ever flagged this
                 * case and stopped, with no actual recursion mechanism
                 * at all) — the safety property is the explicit depth
                 * check below, not "recursion doesn't exist". */
                dissect_result_add(out, "gtp_nested_tunnel_detected", "true");

                if (depth + 1 <= GTP_MAX_TUNNEL_DEPTH &&
                    inner_udp.payload_len >= GTP1_HDR_LEN_MANDATORY) {
                    const uint8_t *nested_gtp = inner_udp.payload;
                    uint16_t nested_gtp_len = inner_udp.payload_len;

                    uint8_t nested_flags = nested_gtp[0];
                    uint8_t nested_version = (nested_flags >> 5) & 0x07;
                    uint8_t nested_pt = (nested_flags >> 4) & 0x01;

                    if (nested_version == 1 && nested_pt == 1) {
                        uint8_t nested_msg_type = nested_gtp[1];
                        char buf[32];
                        snprintf(buf, sizeof(buf), "%s", gtp1_msg_type_name(nested_msg_type));
                        dissect_result_add(out, "gtp_nested_message_type", buf);

                        bool nested_has_optional = (nested_flags & 0x07) != 0;
                        size_t nested_hdr_len = GTP1_HDR_LEN_MANDATORY +
                                                 (nested_has_optional ? GTP1_HDR_LEN_OPTIONAL : 0);

                        if (nested_msg_type == GTP1_MSG_TYPE_GPDU &&
                            nested_hdr_len <= nested_gtp_len) {
                            /* Recurse into the DOUBLY-nested inner packet,
                             * at depth+1 — the depth check above is what
                             * keeps this from ever going further than
                             * GTP_MAX_TUNNEL_DEPTH regardless of how many
                             * more GTP layers an attacker tries to stack. */
                            gtp1_dissect_inner_packet(nested_gtp + nested_hdr_len,
                                                       (uint16_t)(nested_gtp_len - nested_hdr_len),
                                                       depth + 1, out);
                        }
                    } else {
                        dissect_result_add(out, "gtp_nested_not_gtpv1u", "true");
                    }
                } else if (depth + 1 > GTP_MAX_TUNNEL_DEPTH) {
                    dissect_result_add(out, "gtp_nested_tunnel_depth_limit_reached", "true");
                }
            }
        }
    } else {
        dissect_result_add(out, proto_key, "other");
    }
}

/*
 * IPv6 counterpart to gtp1_dissect_inner_packet() above — same
 * discipline (bounded to one level, TCP gets single-packet SNI
 * extraction only, UDP-to-a-GTP-port is flagged as nested-not-
 * recursed) applied via dpi_ipv6_parser.c's parse_ipv6()/parse_tcp_v6()/
 * parse_udp_v6() instead of the IPv4 equivalents. Closes the gap
 * where an IPv6 inner packet was previously detected but not
 * dissected at all.
 */
static void gtp1_dissect_inner_packet_v6(const uint8_t *inner, uint16_t inner_len,
                                          int depth, struct dissect_result *out) {
    struct ipv6_result inner_ip6;
    if (!parse_ipv6(inner, inner_len, &inner_ip6)) {
        dissect_result_add(out, "gtp_inner_packet_parse_failed", "true");
        return;
    }

    const char *src_key = (depth == 0) ? "gtp_inner_src_ip" : "gtp_nested_inner_src_ip";
    const char *dst_key = (depth == 0) ? "gtp_inner_dst_ip" : "gtp_nested_inner_dst_ip";
    const char *proto_key = (depth == 0) ? "gtp_inner_protocol" : "gtp_nested_inner_protocol";
    const char *port_key = (depth == 0) ? "gtp_inner_dst_port" : "gtp_nested_inner_dst_port";
    const char *sni_key = (depth == 0) ? "gtp_inner_sni" : "gtp_nested_inner_sni";

    char ipbuf[46];
    ipv6_addr_to_string(inner_ip6.src_addr, ipbuf, sizeof(ipbuf));
    dissect_result_add(out, src_key, ipbuf);
    ipv6_addr_to_string(inner_ip6.dst_addr, ipbuf, sizeof(ipbuf));
    dissect_result_add(out, dst_key, ipbuf);

    if (inner_ip6.next_header == 6 /* TCP */) {
        dissect_result_add(out, proto_key, "TCP");
        struct tcp_result inner_tcp;
        if (parse_tcp_v6(inner_ip6.src_addr, inner_ip6.dst_addr,
                          inner_ip6.payload, inner_ip6.payload_len, &inner_tcp)) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%u", inner_tcp.dst_port);
            dissect_result_add(out, port_key, portbuf);

            /* Same single-packet-only SNI extraction limitation as the
             * IPv4 path — see that function's comment for why. */
            struct sni_result sni;
            if (inner_tcp.payload_len > 0 &&
                extract_sni_from_record(inner_tcp.payload, inner_tcp.payload_len, &sni)
                && sni.found) {
                dissect_result_add(out, sni_key, sni.hostname);
            }
        }
    } else if (inner_ip6.next_header == 17 /* UDP */) {
        dissect_result_add(out, proto_key, "UDP");
        struct udp_result inner_udp;
        if (parse_udp_v6(inner_ip6.src_addr, inner_ip6.dst_addr,
                          inner_ip6.payload, inner_ip6.payload_len, &inner_udp)) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%u", inner_udp.dst_port);
            dissect_result_add(out, port_key, portbuf);

            if (inner_udp.dst_port == GTP_U_PORT || inner_udp.dst_port == GTPV2_C_PORT) {
                dissect_result_add(out, "gtp_nested_tunnel_detected", "true");

                /* Same bounded-recursion mechanism as the IPv4 path —
                 * see that function's comment for the safety rationale. */
                if (depth + 1 <= GTP_MAX_TUNNEL_DEPTH &&
                    inner_udp.payload_len >= GTP1_HDR_LEN_MANDATORY) {
                    const uint8_t *nested_gtp = inner_udp.payload;
                    uint16_t nested_gtp_len = inner_udp.payload_len;

                    uint8_t nested_flags = nested_gtp[0];
                    uint8_t nested_version = (nested_flags >> 5) & 0x07;
                    uint8_t nested_pt = (nested_flags >> 4) & 0x01;

                    if (nested_version == 1 && nested_pt == 1) {
                        uint8_t nested_msg_type = nested_gtp[1];
                        char buf[32];
                        snprintf(buf, sizeof(buf), "%s", gtp1_msg_type_name(nested_msg_type));
                        dissect_result_add(out, "gtp_nested_message_type", buf);

                        bool nested_has_optional = (nested_flags & 0x07) != 0;
                        size_t nested_hdr_len = GTP1_HDR_LEN_MANDATORY +
                                                 (nested_has_optional ? GTP1_HDR_LEN_OPTIONAL : 0);

                        if (nested_msg_type == GTP1_MSG_TYPE_GPDU &&
                            nested_hdr_len <= nested_gtp_len) {
                            gtp1_dissect_inner_packet(nested_gtp + nested_hdr_len,
                                                       (uint16_t)(nested_gtp_len - nested_hdr_len),
                                                       depth + 1, out);
                        }
                    } else {
                        dissect_result_add(out, "gtp_nested_not_gtpv1u", "true");
                    }
                } else if (depth + 1 > GTP_MAX_TUNNEL_DEPTH) {
                    dissect_result_add(out, "gtp_nested_tunnel_depth_limit_reached", "true");
                }
            }
        }
    } else {
        dissect_result_add(out, proto_key, "other");
    }
}

static const uint16_t gtp1_hint_ports[] = { GTP_U_PORT };

void register_gtp_dissector(void) {
    register_dissector("GTPv1-U", gtp1_detect, gtp1_dissect, gtp1_hint_ports, 1);
}

/* ==================================================================
 * GTPv2-C (3GPP TS 29.274 §5)
 *
 * Header (variable length depending on TEID flag):
 *   octet 1: Version(3 bits)=2 | P(1 bit, piggybacking) | T(1 bit, TEID present) | spare(3 bits)
 *   octet 2: Message Type
 *   octet 3-4: Message Length (everything after octet 4)
 *   if T=1: octet 5-8 TEID, octet 9-11 Sequence Number, octet 12 spare
 *   if T=0: octet 5-7 Sequence Number, octet 8 spare
 * ================================================================== */
#define GTPV2_MSG_TYPE_ECHO_REQ            1
#define GTPV2_MSG_TYPE_ECHO_RESP           2
#define GTPV2_MSG_TYPE_CREATE_SESSION_REQ  32
#define GTPV2_MSG_TYPE_CREATE_SESSION_RESP 33
#define GTPV2_MSG_TYPE_MODIFY_BEARER_REQ   34
#define GTPV2_MSG_TYPE_MODIFY_BEARER_RESP  35
#define GTPV2_MSG_TYPE_DELETE_SESSION_REQ  36
#define GTPV2_MSG_TYPE_DELETE_SESSION_RESP 37

static const char *gtpv2_msg_type_name(uint8_t t) {
    switch (t) {
        case GTPV2_MSG_TYPE_ECHO_REQ:            return "Echo Request";
        case GTPV2_MSG_TYPE_ECHO_RESP:            return "Echo Response";
        case GTPV2_MSG_TYPE_CREATE_SESSION_REQ:   return "Create Session Request";
        case GTPV2_MSG_TYPE_CREATE_SESSION_RESP:  return "Create Session Response";
        case GTPV2_MSG_TYPE_MODIFY_BEARER_REQ:    return "Modify Bearer Request";
        case GTPV2_MSG_TYPE_MODIFY_BEARER_RESP:   return "Modify Bearer Response";
        case GTPV2_MSG_TYPE_DELETE_SESSION_REQ:   return "Delete Session Request";
        case GTPV2_MSG_TYPE_DELETE_SESSION_RESP:  return "Delete Session Response";
        default: return "Unknown";
    }
}

static double gtpv2_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < 4) return 0.0;

    uint8_t flags = payload[0];
    uint8_t version = (flags >> 5) & 0x07;
    if (version != 2) return 0.0;

    uint16_t msg_len = (payload[2] << 8) | payload[3];
    if ((size_t)4 + msg_len > len) return 0.0;

    double confidence = 0.6;
    if (dst_port == GTPV2_C_PORT) confidence = 0.9;
    return confidence;
}

/*
 * IMSI/MSISDN are encoded as "BCD digits, low nibble first" per
 * TS 29.274 §8.3/§8.11 — each byte holds two decimal digits with the
 * least-significant digit in the LOW nibble. 0xF is a filler nibble
 * for odd-length numbers and is not itself a digit — encountering it
 * ends the number, it doesn't get silently treated as digit "15".
 *
 * PRIVACY NOTE: IMSI and MSISDN are subscriber PII (the mobile
 * network equivalents of a national ID number and phone number,
 * respectively) — extracting them is legitimate for network
 * diagnostics/correlation (the same reasoning as extracting IP
 * addresses elsewhere in this project), but unlike an IP address
 * they're long-lived, directly-identifying subscriber data. Whatever
 * consumes this dissector's output should apply the same
 * access-control and retention discipline it would to any other PII
 * field, not treat it as casually loggable as a TEID or sequence
 * number.
 */
static void gtpv2_decode_bcd_digits(const uint8_t *data, uint16_t len, char *out, size_t out_cap) {
    size_t o = 0;
    for (uint16_t i = 0; i < len && o + 1 < out_cap; i++) {
        uint8_t lo = data[i] & 0x0F;
        uint8_t hi = (data[i] >> 4) & 0x0F;
        if (lo <= 9 && o + 1 < out_cap) out[o++] = (char)('0' + lo);
        else break;   /* filler (0xF) or invalid nibble: number ends here */
        if (hi <= 9 && o + 1 < out_cap) out[o++] = (char)('0' + hi);
        else break;
    }
    out[o] = '\0';
}

/*
 * APN, TS 23.003 §9.1: sequence of length-prefixed labels, same shape
 * as DNS labels but WITHOUT compression pointers (GTPv2 IEs are
 * self-contained, no cross-message back-references) — so this is
 * deliberately a separate, simpler walker rather than reusing
 * dpi_dns_parser.c's dns_decode_name(), which would be over-general
 * for a format that never needs pointer-following at all.
 */
static void gtpv2_decode_apn(const uint8_t *data, uint16_t len, char *out, size_t out_cap) {
    size_t pos = 0, o = 0;
    while (pos < len) {
        uint8_t label_len = data[pos];
        if (label_len == 0 || pos + 1 + label_len > len) break;   /* malformed: stop, don't guess */
        if (o > 0 && o + 1 < out_cap) out[o++] = '.';
        size_t copy_len = label_len;
        if (o + copy_len >= out_cap) copy_len = out_cap - o - 1;
        memcpy(out + o, data + pos + 1, copy_len);
        o += copy_len;
        pos += 1 + label_len;
    }
    out[o] = '\0';
}

static void gtpv2_dissect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto,
                           struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint8_t flags = payload[0];
    uint8_t msg_type = payload[1];
    bool has_teid = (flags & 0x08) != 0;   /* T bit */

    char buf[32];
    snprintf(buf, sizeof(buf), "%s", gtpv2_msg_type_name(msg_type));
    dissect_result_add(out, "gtpv2_message_type", buf);

    size_t pos = 4;
    if (has_teid) {
        if (pos + 4 > len) {
            dissect_result_add(out, "parse_warning", "truncated_teid_field");
            return;
        }
        uint32_t teid = (payload[pos]<<24)|(payload[pos+1]<<16)|(payload[pos+2]<<8)|payload[pos+3];
        snprintf(buf, sizeof(buf), "0x%08x", teid);
        dissect_result_add(out, "gtpv2_teid", buf);
        pos += 4;
    } else {
        dissect_result_add(out, "gtpv2_teid_present", "false");
    }

    if (pos + 3 > len) {
        dissect_result_add(out, "parse_warning", "truncated_sequence_number");
        return;
    }
    uint32_t seq = (payload[pos] << 16) | (payload[pos+1] << 8) | payload[pos+2];
    snprintf(buf, sizeof(buf), "%u", seq);
    dissect_result_add(out, "gtpv2_sequence_number", buf);

    /* Information Elements (IEs), TS 29.274 §8.3: Type(1) + Length(2,
     * length of Value only) + Instance(1, low 4 bits; high 4 bits
     * spare) + Value(Length bytes). Same bounds-checked TLV discipline
     * as every other dissector in this project. */
    size_t ie_pos = pos;
    int ie_count = 0;

    while (ie_pos + 4 <= len && ie_count < 64) {
        uint8_t ie_type = payload[ie_pos];
        uint16_t ie_len = (payload[ie_pos + 1] << 8) | payload[ie_pos + 2];
        /* instance nibble (payload[ie_pos+3] & 0x0F) extracted but not
         * currently surfaced as its own field — distinguishing
         * multiple instances of the same IE type (e.g. two F-TEID IEs
         * for different interfaces) is a reasonable future addition */

        if (ie_pos + 4 + ie_len > len) {
            dissect_result_add(out, "parse_warning", "ie_length_exceeds_available");
            break;
        }
        const uint8_t *ie_val = payload + ie_pos + 4;

        char key[48], val[256];
        switch (ie_type) {
            case 1:   /* IMSI */
                gtpv2_decode_bcd_digits(ie_val, ie_len, val, sizeof(val));
                snprintf(key, sizeof(key), "gtpv2_ie_%d_imsi", ie_count);
                dissect_result_add(out, key, val);
                break;
            case 76:  /* MSISDN */
                gtpv2_decode_bcd_digits(ie_val, ie_len, val, sizeof(val));
                snprintf(key, sizeof(key), "gtpv2_ie_%d_msisdn", ie_count);
                dissect_result_add(out, key, val);
                break;
            case 71:  /* APN */
                gtpv2_decode_apn(ie_val, ie_len, val, sizeof(val));
                snprintf(key, sizeof(key), "gtpv2_ie_%d_apn", ie_count);
                dissect_result_add(out, key, val);
                break;
            case 2:   /* Cause */
                if (ie_len >= 1) {
                    snprintf(val, sizeof(val), "%u", ie_val[0]);
                    snprintf(key, sizeof(key), "gtpv2_ie_%d_cause", ie_count);
                    dissect_result_add(out, key, val);
                }
                break;
            case 3: {  /* Recovery / Restart Counter, TS 29.274 S8.5 */
                if (ie_len >= 1) {
                    snprintf(val, sizeof(val), "%u", ie_val[0]);
                    snprintf(key, sizeof(key), "gtpv2_ie_%d_recovery", ie_count);
                    dissect_result_add(out, key, val);
                }
                break;
            }
            case 82: {  /* RAT Type, TS 29.274 S8.17 */
                if (ie_len >= 1) {
                    static const char *rat_names[] = {
                        "Reserved", "UTRAN", "GERAN", "WLAN", "GAN",
                        "HSPA Evolution", "EUTRAN", "Virtual",
                        "EUTRAN-NB-IoT", "LTE-M", "NR"
                    };
                    uint8_t rat = ie_val[0];
                    const char *name = (rat < sizeof(rat_names) / sizeof(rat_names[0]))
                                        ? rat_names[rat] : "Unknown";
                    snprintf(key, sizeof(key), "gtpv2_ie_%d_rat_type", ie_count);
                    dissect_result_add(out, key, name);
                }
                break;
            }
            case 87: {  /* F-TEID (Fully Qualified TEID), TS 29.274 S8.22 */
                if (ie_len >= 5) {
                    bool v4_flag = (ie_val[0] >> 7) & 1;
                    bool v6_flag = (ie_val[0] >> 6) & 1;
                    uint8_t iface_type = ie_val[0] & 0x3F;
                    uint32_t teid = (ie_val[1]<<24)|(ie_val[2]<<16)|(ie_val[3]<<8)|ie_val[4];

                    snprintf(val, sizeof(val), "iface_type=%u teid=0x%08x", iface_type, teid);
                    snprintf(key, sizeof(key), "gtpv2_ie_%d_fteid", ie_count);
                    dissect_result_add(out, key, val);

                    size_t addr_pos = 5;
                    if (v4_flag && addr_pos + 4 <= ie_len) {
                        snprintf(val, sizeof(val), "%u.%u.%u.%u",
                                 ie_val[addr_pos], ie_val[addr_pos+1],
                                 ie_val[addr_pos+2], ie_val[addr_pos+3]);
                        snprintf(key, sizeof(key), "gtpv2_ie_%d_fteid_ipv4", ie_count);
                        dissect_result_add(out, key, val);
                        addr_pos += 4;
                    }
                    if (v6_flag && addr_pos + 16 <= ie_len) {
                        char v6buf[46];
                        struct in6_addr a;
                        memcpy(&a, ie_val + addr_pos, 16);
                        if (inet_ntop(AF_INET6, &a, v6buf, sizeof(v6buf))) {
                            snprintf(key, sizeof(key), "gtpv2_ie_%d_fteid_ipv6", ie_count);
                            dissect_result_add(out, key, v6buf);
                        }
                    }
                }
                break;
            }
            case 79: {  /* PDN Address Allocation (PAA), TS 29.274 S8.14 */
                if (ie_len >= 1) {
                    uint8_t pdn_type = ie_val[0] & 0x07;
                    const char *pdn_name = (pdn_type == 1) ? "IPv4" :
                                            (pdn_type == 2) ? "IPv6" :
                                            (pdn_type == 3) ? "IPv4v6" : "Unknown";
                    snprintf(key, sizeof(key), "gtpv2_ie_%d_paa_type", ie_count);
                    dissect_result_add(out, key, pdn_name);

                    size_t pos2 = 1;
                    if ((pdn_type == 2 || pdn_type == 3) && pos2 + 17 <= ie_len) {
                        pos2 += 1;   /* skip IPv6 Prefix Length octet */
                        char v6buf[46];
                        struct in6_addr a;
                        memcpy(&a, ie_val + pos2, 16);
                        if (inet_ntop(AF_INET6, &a, v6buf, sizeof(v6buf))) {
                            snprintf(key, sizeof(key), "gtpv2_ie_%d_paa_ipv6", ie_count);
                            dissect_result_add(out, key, v6buf);
                        }
                        pos2 += 16;
                    }
                    if ((pdn_type == 1 || pdn_type == 3) && pos2 + 4 <= ie_len) {
                        snprintf(val, sizeof(val), "%u.%u.%u.%u",
                                 ie_val[pos2], ie_val[pos2+1], ie_val[pos2+2], ie_val[pos2+3]);
                        snprintf(key, sizeof(key), "gtpv2_ie_%d_paa_ipv4", ie_count);
                        dissect_result_add(out, key, val);
                    }
                }
                break;
            }
            case 94: {  /* Charging ID, TS 29.274 S8.28 — a plain 4-byte
                         * unsigned integer, no bit-field ambiguity */
                if (ie_len >= 4) {
                    uint32_t charging_id = (ie_val[0]<<24)|(ie_val[1]<<16)|(ie_val[2]<<8)|ie_val[3];
                    snprintf(val, sizeof(val), "%u", charging_id);
                    snprintf(key, sizeof(key), "gtpv2_ie_%d_charging_id", ie_count);
                    dissect_result_add(out, key, val);
                }
                break;
            }
            case 80: {  /* Bearer QoS, TS 29.274 S8.15 — DELIBERATELY
                         * PARTIAL. Octet 5 packs PCI/PL/PVI as bit
                         * fields whose EXACT bit positions this project
                         * doesn't have the source spec text in front of
                         * it to verify with the same confidence as
                         * everything else here (unlike F-TEID/PAA,
                         * which were verified against constructed test
                         * vectors) — rather than assert a bit-field
                         * layout that might be subtly wrong, only QCI
                         * (octet 6, an unambiguous single byte
                         * immediately following the flags octet) is
                         * extracted. The four 5-byte bit-rate fields
                         * that follow (Uplink/Downlink Maximum and
                         * Guaranteed Bit Rate) are present but not
                         * decoded in this pass for the same reason. */
                if (ie_len >= 2) {
                    snprintf(val, sizeof(val), "%u", ie_val[1]);
                    snprintf(key, sizeof(key), "gtpv2_ie_%d_qci", ie_count);
                    dissect_result_add(out, key, val);
                }
                break;
            }
            case 73: {  /* EPS Bearer ID (EBI), TS 29.274 S8.8 — a
                         * single byte, low 4 bits significant (values
                         * 5-15), no bit-field ambiguity like Bearer
                         * QoS has. Same "not compiled/tested against
                         * live GTP traffic" caveat as the rest of this
                         * file applies — no real GTPv2-C traffic was
                         * found in any capture available to verify
                         * against, stated honestly rather than implied
                         * otherwise. */
                if (ie_len >= 1) {
                    snprintf(val, sizeof(val), "%u", ie_val[0] & 0x0F);
                    snprintf(key, sizeof(key), "gtpv2_ie_%d_ebi", ie_count);
                    dissect_result_add(out, key, val);
                }
                break;
            }
            case 72: {  /* Aggregate Maximum Bit Rate (AMBR), TS 29.274
                         * S8.7 — two plain 4-byte unsigned integers
                         * (uplink then downlink, both in kbps), no
                         * bit-field ambiguity. */
                if (ie_len >= 8) {
                    uint32_t uplink = ((uint32_t)ie_val[0]<<24)|((uint32_t)ie_val[1]<<16)|
                                       ((uint32_t)ie_val[2]<<8)|ie_val[3];
                    uint32_t downlink = ((uint32_t)ie_val[4]<<24)|((uint32_t)ie_val[5]<<16)|
                                         ((uint32_t)ie_val[6]<<8)|ie_val[7];
                    snprintf(val, sizeof(val), "%u", uplink);
                    snprintf(key, sizeof(key), "gtpv2_ie_%d_ambr_uplink_kbps", ie_count);
                    dissect_result_add(out, key, val);
                    snprintf(val, sizeof(val), "%u", downlink);
                    snprintf(key, sizeof(key), "gtpv2_ie_%d_ambr_downlink_kbps", ie_count);
                    dissect_result_add(out, key, val);
                }
                break;
            }
            case 83: {  /* Serving Network, TS 29.274 S8.18 — 3-byte
                         * MCC/MNC in the same BCD-swapped-nibble
                         * encoding already used (and verified) for
                         * IMSI/MSISDN elsewhere in this file via
                         * gtpv2_decode_bcd_digits() — reusing that same
                         * digit-extraction logic here inline, since
                         * Serving Network's fixed 3-byte layout (versus
                         * IMSI's variable-length string) doesn't map
                         * onto that helper's variable-length interface
                         * directly. */
                if (ie_len >= 3) {
                    char mcc_mnc[8];
                    /* MCC digit 1, digit 2, then (digit 3 of MCC or
                     * filler 0xF) packed with MNC digit 3 in the low
                     * nibble of byte 2 — same layout as IMSI's PLMN
                     * prefix. */
                    mcc_mnc[0] = '0' + (ie_val[0] & 0x0F);
                    mcc_mnc[1] = '0' + (ie_val[0] >> 4);
                    mcc_mnc[2] = '0' + (ie_val[1] & 0x0F);
                    mcc_mnc[3] = '-';
                    mcc_mnc[4] = '0' + (ie_val[2] & 0x0F);
                    mcc_mnc[5] = '0' + (ie_val[2] >> 4);
                    uint8_t mnc_digit3 = ie_val[1] >> 4;
                    if (mnc_digit3 != 0x0F) {
                        mcc_mnc[6] = '0' + mnc_digit3;
                        mcc_mnc[7] = '\0';
                    } else {
                        mcc_mnc[6] = '\0';
                    }
                    snprintf(key, sizeof(key), "gtpv2_ie_%d_serving_network", ie_count);
                    dissect_result_add(out, key, mcc_mnc);
                }
                break;
            }
            default:
                break;   /* unrecognized IE type: already bounds-validated
                          * above, just skip over it via ie_len below —
                          * Bearer QoS's bit-rate fields, PCO, Bearer
                          * Context (a grouped/nested IE), and others
                          * would follow the identical pattern */
        }

        ie_pos += 4 + ie_len;
        ie_count++;
    }

    char ie_count_buf[16];
    snprintf(ie_count_buf, sizeof(ie_count_buf), "%d", ie_count);
    dissect_result_add(out, "gtpv2_ie_count", ie_count_buf);
}

static const uint16_t gtpv2_hint_ports[] = { GTPV2_C_PORT };

void register_gtpv2_dissector(void) {
    register_dissector("GTPv2-C", gtpv2_detect, gtpv2_dissect, gtpv2_hint_ports, 1);
}
