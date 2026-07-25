/*
 * dpi_m3ua_parser.c
 *
 * M3UA (MTP3 User Adaptation Layer, RFC 4666) dissector — carried
 * inside SCTP DATA chunks with Payload Protocol Identifier 3 (IANA-
 * registered), not its own transport-layer port. Reached via
 * `dpi_sctp_parser.c`'s PPID-keyed recursion, the same "recurse into
 * what's actually there" pattern GRE/MPLS/L2TPv3/802.11's Data-frame
 * SNAP recursion already use — this file registers with a PPID value
 * in its "hint ports" array rather than a TCP/UDP port, since that's
 * genuinely what identifies it at this layer.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against all 7 real M3UA messages found in a genuine SS7-
 * over-IP call-signaling capture (`raaw-call.pcap`, reached via
 * `dpi_sctp_parser.c`'s real DATA-chunk verification) — every single
 * one hand-decoded byte-for-byte before writing any C, and every one
 * shares the exact same shape: Message Class 1 (Transfer), Message
 * Type 1 (DATA), and precisely 3 parameters in the same order:
 * Network Appearance (tag 0x0200, two distinct real values seen —
 * 0x00000008 and 0x00000001, likely two logical SS7 networks/routing
 * relationships in this real call trace), Routing Context (tag
 * 0x0006, identically 0x00000015 across all 7 real messages — the
 * same signaling relationship throughout this one real call), and
 * Protocol Data (tag 0x0210, variable length, 23-95 bytes across the
 * 7 real messages) — the actual carried MTP3-User payload.
 *
 * WIRE FORMAT: an 8-byte common header shared with every other
 * SIGTRAN adaptation-layer protocol in this family (M2UA included) —
 * Version(1) + Reserved(1) + Message Class(1) + Message Type(1) +
 * Message Length(4, confirmed via all 7 real messages to exactly
 * equal the message's own total byte length) — followed by a
 * sequence of TLV parameters (Tag(2) + Length(2, NOT including
 * padding) + Value, each padded to a 4-byte boundary), the same
 * "chunk"-like framing SCTP itself uses one layer down.
 *
 * SCOPE: Message Class and Type (named, all RFC 4666-defined values),
 * and — for a DATA message specifically — Network Appearance and
 * Routing Context (both real-traffic-verified, both simple 4-byte
 * integers) plus Protocol Data as a raw hex blob. Protocol Data is
 * NOT decoded further — its own internal structure (an MTP3 routing
 * label followed by the actual SCCP or ISUP message this SS7-over-IP
 * call trace is really carrying) is a further, deeper layer this
 * project doesn't have confirmed, verified knowledge of the exact
 * national/international MTP3 label format or SCCP/ISUP message
 * layout to decode with the same confidence as everything else here
 * — stated honestly as a real, deliberate scope boundary rather than
 * guessed at. Message classes/types other than DATA (Management, SS7
 * Signalling Network Management, ASP State/Traffic Maintenance,
 * Routing Key Management) are named only — none appeared in the real
 * traffic checked, which showed only steady-state call signaling, not
 * association setup/teardown at the M3UA layer.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define M3UA_HDR_LEN     8
#define M3UA_MAX_PARAMS  16   /* bounded walk, same discipline as every
                                 other TLV-walking dissector here */

/* M3UA's message TYPE values are only unique WITHIN a given class
 * (RFC 4666 S1.3.1) — so naming needs the (class, type) pair
 * together, not two independent lookups. */
static const char *m3ua_message_name(uint8_t msg_class, uint8_t msg_type) {
    if (msg_class == 0) {   /* Management (MGMT) */
        if (msg_type == 0) return "MGMT/ERR";
        if (msg_type == 1) return "MGMT/NTFY";
    } else if (msg_class == 1) {   /* Transfer (verified: msg_type 1 is real) */
        if (msg_type == 1) return "Transfer/DATA";
    } else if (msg_class == 2) {   /* SS7 Signalling Network Management (SSNM) */
        if (msg_type == 1) return "SSNM/DUNA";
        if (msg_type == 2) return "SSNM/DAVA";
        if (msg_type == 3) return "SSNM/DAUD";
        if (msg_type == 4) return "SSNM/SCON";
        if (msg_type == 5) return "SSNM/DUPU";
        if (msg_type == 6) return "SSNM/DRST";
    } else if (msg_class == 3) {   /* ASP State Maintenance (ASPSM) */
        if (msg_type == 1) return "ASPSM/ASPUP";
        if (msg_type == 2) return "ASPSM/ASPDN";
        if (msg_type == 3) return "ASPSM/BEAT";
        if (msg_type == 4) return "ASPSM/ASPUP_ACK";
        if (msg_type == 5) return "ASPSM/ASPDN_ACK";
        if (msg_type == 6) return "ASPSM/BEAT_ACK";
    } else if (msg_class == 4) {   /* ASP Traffic Maintenance (ASPTM) */
        if (msg_type == 1) return "ASPTM/ASPAC";
        if (msg_type == 2) return "ASPTM/ASPIA";
        if (msg_type == 3) return "ASPTM/ASPAC_ACK";
        if (msg_type == 4) return "ASPTM/ASPIA_ACK";
    } else if (msg_class == 9) {   /* Routing Key Management (RKM) */
        if (msg_type == 1) return "RKM/REG_REQ";
        if (msg_type == 2) return "RKM/REG_RSP";
        if (msg_type == 3) return "RKM/DEREG_REQ";
        if (msg_type == 4) return "RKM/DEREG_RSP";
    }
    return "Unknown";
}

static double m3ua_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    (void)dst_port;   /* PPID-based dispatch, not port-based — see file header */
    if (strcmp(l4_proto, "SCTP-DATA") != 0) return 0.0;
    if (len < M3UA_HDR_LEN) return 0.0;

    uint8_t version = payload[0];
    if (version != 1) return 0.0;   /* every real message checked was version 1 */

    uint8_t msg_class = payload[2];
    uint8_t msg_type = payload[3];
    if (strcmp(m3ua_message_name(msg_class, msg_type), "Unknown") == 0) return 0.0;

    uint32_t msg_len = ((uint32_t)payload[4]<<24)|((uint32_t)payload[5]<<16)|
                        ((uint32_t)payload[6]<<8)|payload[7];
    if (msg_len != len) return 0.0;   /* confirmed exact-match against
                                        * all 7 real messages, not an
                                        * approximation */

    return 0.9;
}

static void m3ua_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < M3UA_HDR_LEN) return;

    uint8_t msg_class = payload[2];
    uint8_t msg_type = payload[3];
    dissect_result_add(out, "m3ua_message", m3ua_message_name(msg_class, msg_type));

    size_t pos = M3UA_HDR_LEN;
    int n_params = 0;
    char buf[192];

    while (pos + 4 <= len && n_params < M3UA_MAX_PARAMS) {
        uint16_t tag = (payload[pos] << 8) | payload[pos + 1];
        uint16_t param_len = (payload[pos + 2] << 8) | payload[pos + 3];
        if (param_len < 4) break;
        if (pos + param_len > len) break;

        const uint8_t *value = payload + pos + 4;
        uint16_t value_len = param_len - 4;

        if (tag == 0x0200 /* Network Appearance */ && value_len >= 4) {
            uint32_t na = ((uint32_t)value[0]<<24)|((uint32_t)value[1]<<16)|
                          ((uint32_t)value[2]<<8)|value[3];
            snprintf(buf, sizeof(buf), "0x%08x", na);
            dissect_result_add(out, "m3ua_network_appearance", buf);
        } else if (tag == 0x0006 /* Routing Context */ && value_len >= 4) {
            uint32_t rc = ((uint32_t)value[0]<<24)|((uint32_t)value[1]<<16)|
                          ((uint32_t)value[2]<<8)|value[3];
            snprintf(buf, sizeof(buf), "0x%08x", rc);
            dissect_result_add(out, "m3ua_routing_context", buf);
        } else if (tag == 0x0210 /* Protocol Data */) {
            /* Raw hex — the nested MTP3-User payload (SCCP/ISUP) is
             * deliberately not decoded further, see file header. */
            size_t hex_n = value_len < (sizeof(buf) - 1) / 2 ? value_len : (sizeof(buf) - 1) / 2;
            for (size_t i = 0; i < hex_n; i++) {
                snprintf(buf + i * 2, 3, "%02x", value[i]);
            }
            buf[hex_n * 2] = '\0';
            dissect_result_add(out, "m3ua_protocol_data_hex", buf);
        }

        uint16_t padded_len = param_len + ((4 - param_len % 4) % 4);
        pos += padded_len;
        n_params++;
    }
}

/* SCTP dispatches DATA-chunk payloads by PPID via dispatch_dissection()'s
 * dst_port argument (repurposed for this recursion, see
 * dpi_sctp_parser.c) — 3 is IANA's assigned PPID for M3UA. */
static const uint16_t m3ua_hint_ports[] = { 3 };

void register_m3ua_dissector(void) {
    register_dissector("M3UA", m3ua_detect, m3ua_dissect, m3ua_hint_ports, 1);
}
