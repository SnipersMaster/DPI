/*
 * dpi_arp_parser.c
 *
 * ARP (RFC 826) dissector. ARCHITECTURALLY DIFFERENT from every other
 * dissector in this project: ARP is its own EtherType (0x0806), sent
 * directly over Ethernet — it never has an IP header, let alone a
 * TCP/UDP one. Every other dissector here is reached via IP (directly,
 * for ICMP, or via TCP/UDP for everything else); ARP needs its own
 * branch in the capture path's ethertype check, parallel to the IPv4/
 * IPv6 branches, not routed through dispatch_dissection() the way
 * UDP/TCP payloads are (there's no L4 payload to dispatch on — the
 * ARP message IS the whole thing after the Ethernet header).
 *
 * It's still registered into the registry (with l4_proto="ARP",
 * dst_port=0, same pattern as ICMP's port-less registration) purely
 * for consistency/discoverability — but the capture path calls it
 * directly, the same way it currently calls dissect_icmp_datagram()
 * directly rather than going through the generic UDP/TCP dispatch.
 *
 * NOT COMPILED/TESTED in this environment.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define ARP_MIN_LEN 28   /* HTYPE(2)+PTYPE(2)+HLEN(1)+PLEN(1)+OPER(2)+
                            SHA(6)+SPA(4)+THA(6)+TPA(4) for the common
                            Ethernet+IPv4 case (HLEN=6, PLEN=4) */

static const char *arp_opcode_name(uint16_t oper) {
    switch (oper) {
        case 1: return "Request";
        case 2: return "Reply";
        case 3: return "RARP Request";
        case 4: return "RARP Reply";
        default: return "Unknown";
    }
}

static double arp_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    (void)dst_port;
    if (strcmp(l4_proto, "ARP") != 0) return 0.0;
    if (len < 8) return 0.0;   /* need at least HTYPE/PTYPE/HLEN/PLEN/OPER to validate */

    uint16_t htype = (payload[0] << 8) | payload[1];
    uint16_t ptype = (payload[2] << 8) | payload[3];
    uint8_t hlen = payload[4];
    uint8_t plen = payload[5];
    uint16_t oper = (payload[6] << 8) | payload[7];

    if (htype != 1 /* Ethernet */) return 0.2;   /* unusual but not impossible */
    if (ptype != 0x0800 /* IPv4 */) return 0.2;
    if (hlen != 6 || plen != 4) return 0.2;
    if (oper < 1 || oper > 4) return 0.0;

    return 0.95;   /* identified by EtherType at the capture path already,
                     * same reasoning as ICMP's high base confidence */
}

static void arp_dissect(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto,
                         struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint16_t htype = (payload[0] << 8) | payload[1];
    uint8_t hlen = payload[4];
    uint8_t plen = payload[5];
    uint16_t oper = (payload[6] << 8) | payload[7];

    dissect_result_add(out, "arp_opcode", arp_opcode_name(oper));

    /* Only decode addresses for the overwhelmingly common case
     * (Ethernet/IPv4, HLEN=6/PLEN=4) — other hardware/protocol type
     * combinations exist (RFC 826 is generic) but are rare enough in
     * practice that this reference version doesn't generalize the
     * address field offsets for them, matching this project's pattern
     * of scoping to what's actually common rather than fully generic. */
    if (htype == 1 && hlen == 6 && plen == 4 && len >= ARP_MIN_LEN) {
        char mac[18];
        const uint8_t *sha = payload + 8;
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
        dissect_result_add(out, "arp_sender_mac", mac);

        char ip[16];
        const uint8_t *spa = payload + 14;
        snprintf(ip, sizeof(ip), "%u.%u.%u.%u", spa[0], spa[1], spa[2], spa[3]);
        dissect_result_add(out, "arp_sender_ip", ip);

        const uint8_t *tha = payload + 18;
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 tha[0], tha[1], tha[2], tha[3], tha[4], tha[5]);
        dissect_result_add(out, "arp_target_mac", mac);

        const uint8_t *tpa = payload + 24;
        snprintf(ip, sizeof(ip), "%u.%u.%u.%u", tpa[0], tpa[1], tpa[2], tpa[3]);
        dissect_result_add(out, "arp_target_ip", ip);

        /* A Reply where target MAC is all-zero, or a gratuitous ARP
         * (sender IP == target IP), are both signals worth surfacing
         * for ARP spoofing detection — flagged, not judged, since
         * gratuitous ARP is also completely legitimate (used for
         * duplicate address detection, failover). */
        bool target_mac_zero = (tha[0]|tha[1]|tha[2]|tha[3]|tha[4]|tha[5]) == 0;
        bool gratuitous = memcmp(spa, tpa, 4) == 0;
        if (target_mac_zero && oper == 2) {
            dissect_result_add(out, "arp_reply_with_zero_target_mac", "true");
        }
        if (gratuitous) {
            dissect_result_add(out, "arp_gratuitous", "true");
        }
    }
}

static const uint16_t arp_hint_ports[] = { 0 };

void register_arp_dissector(void) {
    register_dissector("ARP", arp_detect, arp_dissect, arp_hint_ports, 0);
}
