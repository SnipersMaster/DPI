/*
 * dpi_dhcp6_parser.c
 *
 * DHCPv6 (RFC 8415, obsoleting RFC 3315/3633/3736/4242/7083/7283)
 * dissector — UDP ports 546 (client) / 547 (server), both IANA-
 * registered. Requested by name in a batch cross-check against a
 * large protocol list; complements this project's existing DHCPv4
 * dissector (`dpi_dhcp_parser.c`).
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic — no DHCPv6 capture was available in this project's pcap
 * survey set. Built with real confidence regardless: the message
 * header format and message-type table were cross-checked across the
 * RFC Editor's own RFC 8415 text (via multiple mirrors) and an
 * independent technical blog that quotes RFC 8415 Section 7.3's
 * message-type table directly, both agreeing on the same values.
 *
 * WIRE FORMAT: Message Type(1 byte) + Transaction-ID(3 bytes — not
 * 4; a real, specific detail confirmed independently by a patent
 * filing's own technical background section describing the same
 * field as "24 bits (3 bytes)") + Options (TLV format: Option-Code(2)
 * + Option-Length(2) + Option-Data(variable), repeated to fill the
 * message) — this is the format for direct client/server messages;
 * Relay-Forward and Relay-Reply messages (types 12 and 13) use a
 * different, longer header (including a hop count and relay/peer
 * addresses) not decoded here, see SCOPE below.
 *
 * SCOPE: Message Type (named, RFC 8415's full 13-value table) and
 * Transaction ID are decoded for all message types. The Options TLV
 * area is walked and each option's raw Code/Length is reported (a
 * count and the first option's code specifically) but individual
 * option contents are not decoded — DHCPv6 defines dozens of option
 * types (IA_NA, IA_TA, IA_PD, DNS servers, DUID variants, and more),
 * each with its own internal structure, and this project has no real
 * traffic to verify any of their byte-exact layouts against. Relay-
 * Forward/Relay-Reply's different header shape is recognized (named)
 * but not parsed — it carries a nested, potentially multiply-relayed
 * DHCPv6 message inside its own options area, real additional
 * complexity this project doesn't attempt without traffic to verify
 * against.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define DHCP6_CLIENT_PORT 546
#define DHCP6_SERVER_PORT 547
#define DHCP6_HDR_LEN 4
#define DHCP6_MAX_OPTIONS 16

static const char *dhcp6_message_type_name(uint8_t type) {
    switch (type) {
        case 1:  return "SOLICIT";
        case 2:  return "ADVERTISE";
        case 3:  return "REQUEST";
        case 4:  return "CONFIRM";
        case 5:  return "RENEW";
        case 6:  return "REBIND";
        case 7:  return "REPLY";
        case 8:  return "RELEASE";
        case 9:  return "DECLINE";
        case 10: return "RECONFIGURE";
        case 11: return "INFORMATION-REQUEST";
        case 12: return "RELAY-FORW";
        case 13: return "RELAY-REPL";
        default: return "Unknown";
    }
}

static double dhcp6_detect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < DHCP6_HDR_LEN) return 0.0;

    uint8_t msg_type = payload[0];
    if (strcmp(dhcp6_message_type_name(msg_type), "Unknown") == 0) return 0.0;
    if (msg_type == 12 || msg_type == 13) return 0.0;   /* Relay
                                                            messages use
                                                            a different
                                                            header shape
                                                            this project
                                                            doesn't
                                                            decode, see
                                                            file header
                                                            — don't
                                                            misparse
                                                            their
                                                            transaction
                                                            ID field */

    double confidence = 0.5;
    if (dst_port == DHCP6_CLIENT_PORT || dst_port == DHCP6_SERVER_PORT) confidence = 0.85;
    return confidence;
}

static void dhcp6_dissect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto,
                           struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < DHCP6_HDR_LEN) return;

    uint8_t msg_type = payload[0];
    dissect_result_add(out, "dhcp6_message_type", dhcp6_message_type_name(msg_type));

    if (msg_type == 12 || msg_type == 13) return;   /* Relay messages:
                                                         named only,
                                                         see file
                                                         header */

    uint32_t xid = ((uint32_t)payload[1] << 16) | ((uint32_t)payload[2] << 8) | payload[3];
    char buf[16];
    snprintf(buf, sizeof(buf), "0x%06x", xid);
    dissect_result_add(out, "dhcp6_transaction_id", buf);

    size_t pos = DHCP6_HDR_LEN;
    int n_options = 0;
    uint16_t first_option_code = 0;
    bool have_first = false;

    while (pos + 4 <= len && n_options < DHCP6_MAX_OPTIONS) {
        uint16_t opt_code = (payload[pos] << 8) | payload[pos + 1];
        uint16_t opt_len = (payload[pos + 2] << 8) | payload[pos + 3];
        if (pos + 4 + opt_len > len) break;

        if (!have_first) {
            first_option_code = opt_code;
            have_first = true;
        }

        pos += 4 + opt_len;
        n_options++;
    }

    if (n_options > 0) {
        snprintf(buf, sizeof(buf), "%d", n_options);
        dissect_result_add(out, "dhcp6_options_count", buf);
        snprintf(buf, sizeof(buf), "%u", first_option_code);
        dissect_result_add(out, "dhcp6_first_option_code", buf);
    }
}

static const uint16_t dhcp6_hint_ports[] = { DHCP6_CLIENT_PORT, DHCP6_SERVER_PORT };

void register_dhcp6_dissector(void) {
    register_dissector("DHCPv6", dhcp6_detect, dhcp6_dissect, dhcp6_hint_ports, 2);
}
