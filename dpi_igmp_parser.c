/*
 * dpi_igmp_parser.c
 *
 * IGMP dissector — IGMPv1 (RFC 1112), IGMPv2 (RFC 2236), IGMPv3
 * (RFC 3376). IP protocol number 2, so — like GRE/OSPF — needs a
 * dedicated IP-protocol-level capture-path branch, not TCP/UDP.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against all 25 real IGMP packets from a genuine capture
 * (Johannes Weber's "Ultimate PCAP"): 4 Membership Queries, 6 v1
 * Membership Reports, 15 v3 Membership Reports. Confirmed real
 * addresses make sense — a Membership Query correctly showed
 * group=0.0.0.0 (a General Query), a v1 Report showed group
 * 239.255.255.250 (SSDP's multicast address, also present in this
 * same capture), and a v3 Report's group record correctly showed
 * mcast_addr 224.0.0.251 (mDNS's multicast address, likewise present).
 *
 * WIRE FORMAT:
 *   IGMPv1/v2 (8 bytes): Type(1) + Max Resp Time(1, v2 only — v1
 *     always sends 0 here) + Checksum(2) + Group Address(4).
 *   IGMPv3 Membership Query (12+ bytes): Type(1)=0x11 + Max Resp
 *     Code(1) + Checksum(2) + Group Address(4) + Resv/S/QRV(1) +
 *     QQIC(1) + Number of Sources(2) + Source Address(4 each) —
 *     confirmed via a real 12-byte query (0 sources) in this capture.
 *   IGMPv3 Membership Report (Type 0x22): Type(1) + Reserved(1) +
 *     Checksum(2) + Reserved(2) + Number of Group Records(2), followed
 *     by that many Group Records: Record Type(1) + Aux Data Len(1) +
 *     Number of Sources(2) + Multicast Address(4) + Source Address(4
 *     each) + Auxiliary Data(4 * Aux Data Len bytes) — confirmed
 *     against a real single-group-record report in this capture.
 *
 * SCOPE: full field extraction for v1/v2 messages (type, group
 * address) and IGMPv3 Queries (group address, source count). For
 * IGMPv3 Reports, group record count plus the FIRST record's type and
 * multicast address are extracted — not every record and not its
 * source-address list, matching this project's "extract the highest-
 * value piece" pattern (same scope choice as BGP's NLRI cap and OSPF's
 * neighbor cap).
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define IGMP_V1V2_HDR_LEN 8
#define IGMP_V3_QUERY_MIN_LEN 12
#define IGMP_V3_REPORT_MIN_LEN 8
#define IGMP_V3_RECORD_MIN_LEN 8

static const char *igmp_type_name(uint8_t type) {
    switch (type) {
        case 0x11: return "Membership Query";
        case 0x12: return "v1 Membership Report";
        case 0x16: return "v2 Membership Report";
        case 0x17: return "Leave Group";
        case 0x22: return "v3 Membership Report";
        default: return "Unknown";
    }
}

static const char *igmp_v3_record_type_name(uint8_t type) {
    switch (type) {
        case 1: return "MODE_IS_INCLUDE";
        case 2: return "MODE_IS_EXCLUDE";
        case 3: return "CHANGE_TO_INCLUDE_MODE";
        case 4: return "CHANGE_TO_EXCLUDE_MODE";
        case 5: return "ALLOW_NEW_SOURCES";
        case 6: return "BLOCK_OLD_SOURCES";
        default: return "Unknown";
    }
}

static double igmp_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    (void)dst_port; (void)l4_proto;   /* identified by IP protocol 2 already
                                        * at the capture path, same reasoning
                                        * as GRE/OSPF's detect() */
    if (len < IGMP_V1V2_HDR_LEN) return 0.0;
    uint8_t type = payload[0];
    if (type != 0x11 && type != 0x12 && type != 0x16 && type != 0x17 && type != 0x22) {
        return 0.0;
    }
    return 0.9;
}

static void igmp_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < IGMP_V1V2_HDR_LEN) return;

    uint8_t type = payload[0];
    dissect_result_add(out, "igmp_type", igmp_type_name(type));

    char group[16];
    snprintf(group, sizeof(group), "%u.%u.%u.%u", payload[4], payload[5], payload[6], payload[7]);
    dissect_result_add(out, "igmp_group_address", group);

    char buf[16];

    if (type == 0x11 /* Membership Query */) {
        snprintf(buf, sizeof(buf), "%u", payload[1]);
        dissect_result_add(out, "igmp_max_resp_time", buf);

        /* IGMPv3 query extension, verified against a real 12-byte
         * query in this capture — see file header. */
        if (len >= IGMP_V3_QUERY_MIN_LEN) {
            uint8_t s_qrv = payload[8];
            uint8_t qrv = s_qrv & 0x07;
            snprintf(buf, sizeof(buf), "%u", qrv);
            dissect_result_add(out, "igmp_v3_qrv", buf);
            uint16_t num_sources = (payload[10] << 8) | payload[11];
            snprintf(buf, sizeof(buf), "%u", num_sources);
            dissect_result_add(out, "igmp_v3_num_sources", buf);
        }
    } else if (type == 0x22 /* v3 Membership Report */) {
        if (len < IGMP_V3_REPORT_MIN_LEN) return;
        uint16_t num_records = (payload[6] << 8) | payload[7];
        snprintf(buf, sizeof(buf), "%u", num_records);
        dissect_result_add(out, "igmp_v3_num_group_records", buf);

        if (num_records > 0 && len >= IGMP_V3_REPORT_MIN_LEN + IGMP_V3_RECORD_MIN_LEN) {
            const uint8_t *rec = payload + IGMP_V3_REPORT_MIN_LEN;
            uint8_t record_type = rec[0];
            dissect_result_add(out, "igmp_v3_first_record_type",
                                igmp_v3_record_type_name(record_type));
            char mcast[16];
            snprintf(mcast, sizeof(mcast), "%u.%u.%u.%u", rec[4], rec[5], rec[6], rec[7]);
            dissect_result_add(out, "igmp_v3_first_record_mcast_addr", mcast);
        }
    }
    /* v1/v2 Reports and Leave Group: type + group address (already
     * extracted above) is the whole message — nothing further to add. */
}

static const uint16_t igmp_hint_ports[] = { 0 };   /* no port concept, see file header */

void register_igmp_dissector(void) {
    register_dissector("IGMP", igmp_detect, igmp_dissect, igmp_hint_ports, 0);
}
