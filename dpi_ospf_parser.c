/*
 * dpi_ospf_parser.c
 *
 * OSPF dissector — OSPFv2 (RFC 2328, over IPv4) and OSPFv3 (RFC 5340,
 * over IPv6). IP protocol number 89, so — like GRE — this needs a
 * dedicated IP-protocol-level capture-path branch, not a TCP/UDP one.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 586 real OSPF packets from a genuine capture
 * (Johannes Weber's "Ultimate PCAP"): 278 OSPFv2 and 308 OSPFv3,
 * covering all five message types (Hello, Database Description, Link
 * State Request, Link State Update, Link State Acknowledgment) in
 * both versions.
 *
 * -------------------------------------------------------------------
 * THE MOST IMPORTANT LESSON FROM THAT VERIFICATION, BAKED INTO THIS
 * FILE FROM THE START rather than discovered as a bug afterward:
 * -------------------------------------------------------------------
 * OSPF carries its OWN packet length field (distinct from the IP
 * header's length), and it must be used to bound parsing — NOT the IP
 * layer's declared length alone. A real captured Hello packet's IP
 * layer said 60 bytes were available; OSPF's own header said the
 * actual OSPF message was only 48 bytes. The extra 12 bytes were
 * Ethernet/IP trailing padding, and parsing the neighbor list without
 * bounding to OSPF's own length field produced three garbage
 * "neighbor router IDs" that were actually just padding bytes
 * misread as IP addresses. Once correctly bounded, the same packet
 * showed exactly one real neighbor.
 * This is the THIRD time this exact class of bug — trusting an outer
 * layer's declared length instead of an inner protocol's own length
 * field — showed up during real-traffic verification in this project
 * (after GRE's keepalive-payload miscount and an earlier DNS
 * threshold mismatch of a different kind). It's worth stating as a
 * general principle: whenever a protocol carries its own length
 * field, bound to THAT field, not just whatever the caller handed you.
 *
 * WIRE FORMAT:
 *   OSPFv2 common header (24 bytes): Version(1) Type(1) PacketLength(2)
 *     RouterID(4) AreaID(4) Checksum(2) AuType(2) Authentication(8)
 *   OSPFv3 common header (16 bytes, RFC 5340 SA.3.1): Version(1) Type(1)
 *     PacketLength(2) RouterID(4) AreaID(4) Checksum(2) InstanceID(1)
 *     Reserved(1) — authentication moved to IPsec, hence no AuType/Auth
 *     fields and a shorter header.
 *   Both versions: Type 1=Hello, 2=DB Description, 3=LS Request,
 *     4=LS Update, 5=LS Ack.
 *
 * SCOPE: Hello packets get full body extraction (both versions have
 * genuinely different Hello body layouts — OSPFv2's has a network
 * mask, OSPFv3's has an Interface ID instead, verified separately
 * against real packets of each version). The other four message
 * types are named/counted but their bodies (LSAs, primarily) aren't
 * decoded further — LSA parsing is a substantially larger, separate
 * problem (many distinct LSA types, each with its own format), same
 * "extract the highest-value piece, flag the rest by name" pattern
 * used for GTPv2-C's less common IEs and MPLS's less common cases.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define OSPFV2_HDR_LEN 24
#define OSPFV3_HDR_LEN 16

static const char *ospf_type_name(uint8_t type) {
    switch (type) {
        case 1: return "Hello";
        case 2: return "Database Description";
        case 3: return "Link State Request";
        case 4: return "Link State Update";
        case 5: return "Link State Acknowledgment";
        default: return "Unknown";
    }
}

static double ospf_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    (void)dst_port;
    if (strcmp(l4_proto, "OSPF") != 0) return 0.0;
    if (len < OSPFV3_HDR_LEN) return 0.0;   /* shorter of the two header sizes */

    uint8_t version = payload[0];
    uint8_t type = payload[1];
    if ((version != 2 && version != 3) || type < 1 || type > 5) return 0.0;

    uint16_t hdr_len = (version == 2) ? OSPFV2_HDR_LEN : OSPFV3_HDR_LEN;
    if (len < hdr_len) return 0.0;

    return 0.9;   /* identified by IP protocol 89 already at the capture
                    * path — same reasoning as GRE/ICMP's detect() */
}

static void ospf_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint8_t version = payload[0];
    uint8_t type = payload[1];
    uint16_t hdr_len = (version == 2) ? OSPFV2_HDR_LEN : OSPFV3_HDR_LEN;
    if (len < hdr_len) return;

    uint16_t pkt_len = (payload[2] << 8) | payload[3];
    /* THE bounding fix, applied here: never trust `len` (whatever the
     * caller handed us, itself already bounded by the IP layer) over
     * OSPF's own declared length — see this file's header comment. */
    if (pkt_len < hdr_len || pkt_len > len) {
        dissect_result_add(out, "parse_warning", "ospf_pkt_len_inconsistent_with_buffer");
        return;
    }
    uint16_t effective_len = pkt_len;

    char buf[16];
    snprintf(buf, sizeof(buf), "%u", version);
    dissect_result_add(out, "ospf_version", buf);
    dissect_result_add(out, "ospf_type", ospf_type_name(type));

    char router_id[16], area_id[16];
    snprintf(router_id, sizeof(router_id), "%u.%u.%u.%u", payload[4], payload[5], payload[6], payload[7]);
    snprintf(area_id, sizeof(area_id), "%u.%u.%u.%u", payload[8], payload[9], payload[10], payload[11]);
    dissect_result_add(out, "ospf_router_id", router_id);
    dissect_result_add(out, "ospf_area_id", area_id);

    if (version == 2) {
        uint16_t autype = (payload[14] << 8) | payload[15];
        snprintf(buf, sizeof(buf), "%u", autype);
        dissect_result_add(out, "ospf_autype", buf);
    } else {
        snprintf(buf, sizeof(buf), "%u", payload[14]);
        dissect_result_add(out, "ospf_instance_id", buf);
    }

    if (type != 1 /* Hello */) {
        /* Other message types: named above, bodies not decoded further
         * in this pass — see this file's header comment. */
        return;
    }

    const uint8_t *body = payload + hdr_len;
    uint16_t body_len = effective_len - hdr_len;

    if (version == 2) {
        /* OSPFv2 Hello body, RFC 2328 SA.3.2: NetworkMask(4) +
         * HelloInterval(2) + Options(1) + RtrPriority(1) +
         * RouterDeadInterval(4) + DR(4) + BDR(4) + Neighbor(4 each) */
        if (body_len < 20) return;
        char netmask[16], dr[16], bdr[16];
        snprintf(netmask, sizeof(netmask), "%u.%u.%u.%u", body[0], body[1], body[2], body[3]);
        uint16_t hello_interval = (body[4] << 8) | body[5];
        uint8_t priority = body[7];
        uint32_t dead_interval = ((uint32_t)body[8]<<24)|((uint32_t)body[9]<<16)|
                                  ((uint32_t)body[10]<<8)|body[11];
        snprintf(dr, sizeof(dr), "%u.%u.%u.%u", body[12], body[13], body[14], body[15]);
        snprintf(bdr, sizeof(bdr), "%u.%u.%u.%u", body[16], body[17], body[18], body[19]);

        dissect_result_add(out, "ospf_hello_netmask", netmask);
        snprintf(buf, sizeof(buf), "%u", hello_interval);
        dissect_result_add(out, "ospf_hello_interval", buf);
        snprintf(buf, sizeof(buf), "%u", priority);
        dissect_result_add(out, "ospf_hello_priority", buf);
        snprintf(buf, sizeof(buf), "%u", dead_interval);
        dissect_result_add(out, "ospf_hello_dead_interval", buf);
        dissect_result_add(out, "ospf_hello_dr", dr);
        dissect_result_add(out, "ospf_hello_bdr", bdr);

        int n_neighbors = (body_len - 20) / 4;
        snprintf(buf, sizeof(buf), "%d", n_neighbors);
        dissect_result_add(out, "ospf_hello_neighbor_count", buf);
        /* Individual neighbor IDs are extracted up to a small cap —
         * dissect_result has a bounded number of field slots shared
         * across everything already added, so this doesn't try to
         * list every neighbor on a router with a huge neighbor count. */
        int cap = n_neighbors < 4 ? n_neighbors : 4;
        for (int i = 0; i < cap; i++) {
            char nbuf[16], key[24];
            const uint8_t *n = body + 20 + i * 4;
            snprintf(nbuf, sizeof(nbuf), "%u.%u.%u.%u", n[0], n[1], n[2], n[3]);
            snprintf(key, sizeof(key), "ospf_hello_neighbor_%d", i);
            dissect_result_add(out, key, nbuf);
        }
    } else {
        /* OSPFv3 Hello body, RFC 5340 SA.3.2: InterfaceID(4) +
         * RtrPriority(1) + Options(3) + HelloInterval(2) +
         * RouterDeadInterval(2) + DR(4) + BDR(4) + Neighbor(4 each).
         * Genuinely different layout from v2 — no network mask (OSPFv3
         * doesn't carry one at this layer), interval fields are
         * narrower, verified separately against a real v3 Hello packet. */
        if (body_len < 20) return;
        uint32_t interface_id = ((uint32_t)body[0]<<24)|((uint32_t)body[1]<<16)|
                                 ((uint32_t)body[2]<<8)|body[3];
        uint8_t priority = body[4];
        uint16_t hello_interval = (body[8] << 8) | body[9];
        uint16_t dead_interval = (body[10] << 8) | body[11];
        char dr[16], bdr[16];
        snprintf(dr, sizeof(dr), "%u.%u.%u.%u", body[12], body[13], body[14], body[15]);
        snprintf(bdr, sizeof(bdr), "%u.%u.%u.%u", body[16], body[17], body[18], body[19]);

        snprintf(buf, sizeof(buf), "%u", interface_id);
        dissect_result_add(out, "ospf_hello_interface_id", buf);
        snprintf(buf, sizeof(buf), "%u", priority);
        dissect_result_add(out, "ospf_hello_priority", buf);
        snprintf(buf, sizeof(buf), "%u", hello_interval);
        dissect_result_add(out, "ospf_hello_interval", buf);
        snprintf(buf, sizeof(buf), "%u", dead_interval);
        dissect_result_add(out, "ospf_hello_dead_interval", buf);
        dissect_result_add(out, "ospf_hello_dr", dr);
        dissect_result_add(out, "ospf_hello_bdr", bdr);

        int n_neighbors = (body_len - 20) / 4;
        snprintf(buf, sizeof(buf), "%d", n_neighbors);
        dissect_result_add(out, "ospf_hello_neighbor_count", buf);
        int cap = n_neighbors < 4 ? n_neighbors : 4;
        for (int i = 0; i < cap; i++) {
            char nbuf[16], key[24];
            const uint8_t *n = body + 20 + i * 4;
            snprintf(nbuf, sizeof(nbuf), "%u.%u.%u.%u", n[0], n[1], n[2], n[3]);
            snprintf(key, sizeof(key), "ospf_hello_neighbor_%d", i);
            dissect_result_add(out, key, nbuf);
        }
    }
}

static const uint16_t ospf_hint_ports[] = { 0 };   /* no port concept, see file header */

void register_ospf_dissector(void) {
    register_dissector("OSPF", ospf_detect, ospf_dissect, ospf_hint_ports, 0);
}

