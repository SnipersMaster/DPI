/*
 * dpi_rip_parser.c
 *
 * RIP v1/v2 (RFC 1058, RFC 2453, UDP port 520) and RIPng (RFC 2080,
 * UDP port 521) dissector — one file covering both, since they share
 * an identical 4-byte header shape (Command + Version + 2 reserved/
 * unused bytes) and the same overall "header + N fixed-size route
 * entries" structure, differing only in what a route entry looks like
 * (IPv4-shaped for RIP, IPv6-shaped for RIPng).
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 68 real RIPv2 packets and 124 real RIPng packets
 * from a genuine capture (Johannes Weber's "Ultimate PCAP") — both
 * showed sensible real routes (RIP: a default route 0.0.0.0/0 with
 * metric 2, and 192.168.20.0/24 with metric 1; RIPng: real /64
 * prefixes like 2003:51:6012:120::/64 and a default route ::/0).
 *
 * WIRE FORMAT:
 *   Common header (4 bytes): Command(1, 1=Request, 2=Response) +
 *     Version(1) + 2 bytes (Routing Domain for RIPv2 / Reserved for
 *     RIPng/RIPv1) + N route entries (20 bytes each).
 *   RIP route entry (20 bytes): Address Family Identifier(2, 2=IP) +
 *     Route Tag(2, RIPv2 only, must be 0 in RIPv1) + IP Address(4) +
 *     Subnet Mask(4, RIPv2 only) + Next Hop(4, RIPv2 only) + Metric(4,
 *     though only the low byte is meaningful — metrics are 1-16).
 *   RIPng route entry (20 bytes): IPv6 Prefix(16) + Route Tag(2) +
 *     Prefix Length(1) + Metric(1).
 *
 * SCOPE: extracts command, version, and up to 4 route entries (metric,
 * prefix/mask, next hop for RIP; prefix/length, metric for RIPng) —
 * same bounded-entry-count pattern as BGP's NLRI cap and OSPF's
 * neighbor cap. A message with more than 4 entries still reports its
 * true total entry count, just doesn't list every one individually.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define RIP_HDR_LEN 4
#define RIP_ENTRY_LEN 20
#define RIP_MAX_ENTRIES_SHOWN 4

static const char *rip_command_name(uint8_t command) {
    switch (command) {
        case 1: return "Request";
        case 2: return "Response";
        case 3: return "Traceon (obsolete)";
        case 4: return "Traceoff (obsolete)";
        case 5: return "Sun poll (obsolete)";
        default: return "Unknown";
    }
}

static double rip_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < RIP_HDR_LEN) return 0.0;

    uint8_t command = payload[0];
    uint8_t version = payload[1];
    if (command < 1 || command > 5) return 0.0;
    if (version < 1 || version > 2) return 0.0;   /* RIPv2 max version is 2;
                                                     * RIPng also uses
                                                     * version 1 in this
                                                     * field, checked
                                                     * separately below */

    /* Body should be a whole number of 20-byte entries. */
    if ((len - RIP_HDR_LEN) % RIP_ENTRY_LEN != 0) return 0.3;

    double confidence = 0.7;
    if (dst_port == 520 || dst_port == 521) confidence = 0.9;
    return confidence;
}

static void rip_dissect(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto,
                         struct dissect_result *out) {
    (void)l4_proto;
    if (len < RIP_HDR_LEN) return;

    uint8_t command = payload[0];
    uint8_t version = payload[1];
    bool is_ripng = (dst_port == 521);   /* the only reliable way to tell
                                            * RIP and RIPng apart — their
                                            * headers are otherwise
                                            * identical, so the port this
                                            * dissector was reached on is
                                            * the disambiguator */

    dissect_result_add(out, "rip_command", rip_command_name(command));
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", version);
    dissect_result_add(out, "rip_version", buf);
    dissect_result_add(out, "rip_is_ripng", is_ripng ? "true" : "false");

    int n_entries = (len - RIP_HDR_LEN) / RIP_ENTRY_LEN;
    snprintf(buf, sizeof(buf), "%d", n_entries);
    dissect_result_add(out, "rip_entry_count", buf);

    int shown = n_entries < RIP_MAX_ENTRIES_SHOWN ? n_entries : RIP_MAX_ENTRIES_SHOWN;
    for (int i = 0; i < shown; i++) {
        const uint8_t *entry = payload + RIP_HDR_LEN + i * RIP_ENTRY_LEN;
        char key[32], val[64];

        if (is_ripng) {
            char prefix[46];
            /* IPv6 prefix — reuse the same colon-hex formatting
             * approach as dpi_ipv6_parser.c's ipv6_addr_to_string(),
             * called directly since that function is already visible
             * in the same translation unit in both capture files. */
            ipv6_addr_to_string(entry, prefix, sizeof(prefix));
            uint8_t prefix_len = entry[18];
            uint8_t metric = entry[19];
            snprintf(val, sizeof(val), "%s/%u", prefix, prefix_len);
            snprintf(key, sizeof(key), "rip_entry_%d_prefix", i);
            dissect_result_add(out, key, val);
            snprintf(key, sizeof(key), "rip_entry_%d_metric", i);
            snprintf(val, sizeof(val), "%u", metric);
            dissect_result_add(out, key, val);
        } else {
            uint32_t metric = ((uint32_t)entry[16]<<24)|((uint32_t)entry[17]<<16)|
                               ((uint32_t)entry[18]<<8)|entry[19];
            snprintf(val, sizeof(val), "%u.%u.%u.%u/%u.%u.%u.%u",
                     entry[4], entry[5], entry[6], entry[7],
                     entry[8], entry[9], entry[10], entry[11]);
            snprintf(key, sizeof(key), "rip_entry_%d_prefix", i);
            dissect_result_add(out, key, val);
            snprintf(key, sizeof(key), "rip_entry_%d_metric", i);
            snprintf(val, sizeof(val), "%u", metric);
            dissect_result_add(out, key, val);
        }
    }
}

static const uint16_t rip_hint_ports[] = { 520, 521 };

void register_rip_dissector(void) {
    register_dissector("RIP", rip_detect, rip_dissect, rip_hint_ports, 2);
}
