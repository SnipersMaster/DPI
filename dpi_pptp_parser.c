/*
 * dpi_pptp_parser.c
 *
 * PPTP (RFC 2637, Point-to-Point Tunneling Protocol) control-
 * connection dissector — TCP port 1723 (IANA-registered). Requested
 * by name in a batch cross-check against a large protocol list.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic — no PPTP capture was available in this project's pcap
 * survey set. Built with real confidence regardless: the control
 * message header format was cross-checked across the RFC Editor's
 * own RFC 2637 text (via three independent mirrors), a security-
 * fuzzing company's technical write-up describing the identical
 * field layout, and general, well-established PPTP documentation —
 * all agreeing on the same fields, the same Magic Cookie constant,
 * and the same port.
 *
 * WIRE FORMAT: every PPTP control message shares a 12-byte common
 * prefix — Length(2, total message length including this header) +
 * PPTP Message Type(2, always 1 for a Control Message in the current
 * spec — value 2, "Management Message", is explicitly reserved for
 * future use and MUST NOT appear) + Magic Cookie(4, always the fixed
 * constant 0x1A2B3C4D — the RFC's own stated purpose is purely a
 * synchronization sanity check, not a version or capability field) +
 * Control Message Type(2) + Reserved0(2, always 0) — followed by
 * message-specific fields whose layout depends entirely on the
 * Control Message Type. PPTP's actual tunneled PPP data travels
 * separately, inside GRE (IP protocol 47, already covered by this
 * project's `dpi_gre_parser.c`) — not over this TCP control
 * connection at all.
 *
 * SCOPE: the 12-byte common header only — Magic Cookie validation
 * and Control Message Type, named per RFC 2637's full, standard
 * 15-value table (Start/Stop-Control-Connection-Request/Reply, Echo-
 * Request/Reply, Outgoing/Incoming-Call-Request/Reply, Incoming-
 * Call-Connected, Call-Clear-Request, Call-Disconnect-Notify, WAN-
 * Error-Notify, Set-Link-Info). The message-specific fields that
 * follow (framing/bearer capabilities, call IDs, connect speed, and
 * so on — a different layout for each of the 15 message types) are
 * not decoded — real, substantial additional work this project has
 * no real traffic to verify field offsets against, for any of the 15
 * separately-shaped messages.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define PPTP_PORT 1723
#define PPTP_HDR_LEN 12
#define PPTP_MAGIC_COOKIE 0x1A2B3C4D

static const char *pptp_control_message_name(uint16_t type) {
    switch (type) {
        case 1:  return "Start-Control-Connection-Request";
        case 2:  return "Start-Control-Connection-Reply";
        case 3:  return "Stop-Control-Connection-Request";
        case 4:  return "Stop-Control-Connection-Reply";
        case 5:  return "Echo-Request";
        case 6:  return "Echo-Reply";
        case 7:  return "Outgoing-Call-Request";
        case 8:  return "Outgoing-Call-Reply";
        case 9:  return "Incoming-Call-Request";
        case 10: return "Incoming-Call-Reply";
        case 11: return "Incoming-Call-Connected";
        case 12: return "Call-Clear-Request";
        case 13: return "Call-Disconnect-Notify";
        case 14: return "WAN-Error-Notify";
        case 15: return "Set-Link-Info";
        default: return "Unknown";
    }
}

static double pptp_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < PPTP_HDR_LEN) return 0.0;

    uint16_t msg_type = (payload[2] << 8) | payload[3];
    uint32_t magic_cookie = ((uint32_t)payload[4] << 24) | ((uint32_t)payload[5] << 16) |
                             ((uint32_t)payload[6] << 8) | payload[7];
    if (msg_type != 1) return 0.0;   /* only "Control Message" is
                                         real/current; type 2 is
                                         reserved and MUST NOT appear */
    if (magic_cookie != PPTP_MAGIC_COOKIE) return 0.0;

    uint16_t ctrl_msg_type = (payload[8] << 8) | payload[9];
    if (strcmp(pptp_control_message_name(ctrl_msg_type), "Unknown") == 0) return 0.0;

    double confidence = 0.85;   /* the magic cookie alone is a strong,
                                    fairly specific signal even before
                                    considering the port */
    if (dst_port == PPTP_PORT) confidence = 0.95;
    return confidence;
}

static void pptp_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < PPTP_HDR_LEN) return;

    uint16_t msg_len = (payload[0] << 8) | payload[1];
    uint16_t ctrl_msg_type = (payload[8] << 8) | payload[9];

    char buf[16];
    snprintf(buf, sizeof(buf), "%u", msg_len);
    dissect_result_add(out, "pptp_length", buf);
    dissect_result_add(out, "pptp_control_message_type", pptp_control_message_name(ctrl_msg_type));
}

static const uint16_t pptp_hint_ports[] = { PPTP_PORT };

void register_pptp_dissector(void) {
    register_dissector("PPTP", pptp_detect, pptp_dissect, pptp_hint_ports, 1);
}
