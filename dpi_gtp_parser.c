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

/* Forward declaration: gtp1_dissect() calls this before its definition appears. */
static void gtp1_dissect_inner_packet(const uint8_t *inner, uint16_t inner_len,
                                       struct dissect_result *out);

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
        gtp1_dissect_inner_packet(payload + inner_start, inner_len, out);
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
                                       struct dissect_result *out) {
    if (inner_len < 1) return;

    uint8_t version = inner[0] >> 4;
    if (version != 4) {
        /* Only IPv4 inner packets are recursed into in this pass — an
         * IPv6 inner packet would need dpi_ipv6_parser.c wired here
         * too, not done yet, flagged rather than silently skipped. */
        dissect_result_add(out, "gtp_inner_packet_ipv6_not_dissected",
                            version == 6 ? "true" : "false");
        return;
    }

    struct ipv4_result inner_ip;
    if (!parse_ipv4(inner, inner_len, &inner_ip)) {
        dissect_result_add(out, "gtp_inner_packet_parse_failed", "true");
        return;
    }

    char ipbuf[32];
    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
             (inner_ip.src_addr >> 24) & 0xFF, (inner_ip.src_addr >> 16) & 0xFF,
             (inner_ip.src_addr >> 8) & 0xFF, inner_ip.src_addr & 0xFF);
    dissect_result_add(out, "gtp_inner_src_ip", ipbuf);
    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
             (inner_ip.dst_addr >> 24) & 0xFF, (inner_ip.dst_addr >> 16) & 0xFF,
             (inner_ip.dst_addr >> 8) & 0xFF, inner_ip.dst_addr & 0xFF);
    dissect_result_add(out, "gtp_inner_dst_ip", ipbuf);

    if (inner_ip.protocol == 6 /* TCP */) {
        dissect_result_add(out, "gtp_inner_protocol", "TCP");
        struct tcp_result inner_tcp;
        if (parse_tcp(inner_ip.src_addr, inner_ip.dst_addr,
                       inner_ip.payload, inner_ip.payload_len, &inner_tcp)) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%u", inner_tcp.dst_port);
            dissect_result_add(out, "gtp_inner_dst_port", portbuf);

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
                dissect_result_add(out, "gtp_inner_sni", sni.hostname);
            }
        }
    } else if (inner_ip.protocol == 17 /* UDP */) {
        dissect_result_add(out, "gtp_inner_protocol", "UDP");
        struct udp_result inner_udp;
        if (parse_udp(inner_ip.src_addr, inner_ip.dst_addr,
                       inner_ip.payload, inner_ip.payload_len, &inner_udp)) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%u", inner_udp.dst_port);
            dissect_result_add(out, "gtp_inner_dst_port", portbuf);

            if (inner_udp.dst_port == GTP_U_PORT || inner_udp.dst_port == GTPV2_C_PORT) {
                /* Nested GTP tunnel detected — deliberately NOT
                 * recursing further, see this function's header
                 * comment. Flagged for visibility, not dissected. */
                dissect_result_add(out, "gtp_nested_tunnel_detected", "true");
            }
        }
    } else {
        dissect_result_add(out, "gtp_inner_protocol", "other");
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

    /* Information Elements (IEs) — the actual session parameters
     * (APN, IMSI, bearer QoS, etc.) — follow as TLV-encoded fields per
     * TS 29.274 §8. Not walked in this reference version; the message
     * type and TEID alone are already useful signals (e.g. correlating
     * session establishment/teardown with the G-PDU tunnels it
     * creates), and IE walking is a reasonable next addition following
     * the same TLV-bounds-checking discipline used everywhere else in
     * this project. */
    dissect_result_add(out, "gtpv2_ie_walk_not_implemented", "true");
}

static const uint16_t gtpv2_hint_ports[] = { GTPV2_C_PORT };

void register_gtpv2_dissector(void) {
    register_dissector("GTPv2-C", gtpv2_detect, gtpv2_dissect, gtpv2_hint_ports, 1);
}
