/*
 * dpi_garp_parser.c
 *
 * GARP (Generic Attribute Registration Protocol, IEEE 802.1D) — LLC-
 * framed (DSAP=SSAP=0x42), the SAME LLC signature this project's own
 * STP dissector uses. Requested by name in a batch cross-check
 * against a large protocol list.
 *
 * NOT COMPILED/TESTED in this environment. NOT verified against real
 * traffic in this project's own captures — no GARP/GVRP capture was
 * available in this project's pcap survey set. Built with unusually
 * high confidence regardless: verified against a real, complete,
 * byte-exact GVRP LeaveAll packet posted to the Ethereal (now
 * Wireshark) mailing list — the actual hex dump ("01 80 c2 00 00 21
 * ... 42 42 03 00 01 01 02 00 00 00") was hand-decoded field-by-
 * field before writing any C, and every field decoded to exactly
 * what the same email's own tool output independently stated
 * (Protocol Identifier 0x0001, Message Type VID, Attribute Length 2,
 * Event LeaveAll).
 *
 * A REAL, IMPORTANT AMBIGUITY FOUND AND ALREADY SAFELY HANDLED: GVRP
 * (GARP's VLAN-registration application) uses the identical LLC
 * DSAP/SSAP (0x42/0x42) as STP — confirmed both by the real captured
 * packet above and independently by a Cisco Community discussion
 * explaining the same overlap. Checking this project's own existing
 * `dpi_stp_parser.c` before adding this file showed it already
 * validates the BPDU's Protocol Identifier field is exactly 0x0000
 * and rejects anything else — meaning STP was never at risk of
 * misreading GARP/GVRP traffic as malformed BPDU content, a defensive
 * check that happened to already be correct rather than something
 * that needed fixing. This dissector distinguishes itself from STP
 * the same way, checking for Protocol Identifier 0x0001 specifically.
 *
 * WIRE FORMAT: Protocol Identifier(2 bytes, identifies which GARP
 * application — 0x0001 for GVRP, the one real-traffic-verified value;
 * GMRP's own value was not found with equal confidence and is not
 * asserted here) + one or more Messages, each: Attribute Type(1 byte
 * — GVRP's own single defined value is 0x01, "VID") + a list of
 * Attributes, each Length(1, includes itself + Event + Value) +
 * Event(1, named per GARP's own stable 6-value table: LeaveAll,
 * JoinEmpty, JoinIn, LeaveEmpty, LeaveIn, Empty) + Value(Length-2
 * bytes, present only when Length > 2 — LeaveAll has no value, real-
 * traffic-verified) + a terminating End-of-Attributes mark (0x00) —
 * followed by a final End-of-PDU mark (0x00) after the last Message.
 *
 * SCOPE: Protocol Identifier, and the first Message's Attribute Type
 * and first Attribute's Event/Value — all real-traffic-verified
 * above. Additional Messages/Attributes beyond the first are walked
 * (to advance and terminate correctly) but not themselves reported in
 * full, matching this project's general pattern for repeated-entry
 * structures backed by only one real example.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define GARP_PROTOCOL_ID_GVRP 0x0001
#define GARP_MAX_ATTRS 16

static const char *garp_event_name(uint8_t event) {
    switch (event) {
        case 0: return "LeaveAll";
        case 1: return "JoinEmpty";
        case 2: return "JoinIn";
        case 3: return "LeaveEmpty";
        case 4: return "LeaveIn";
        case 5: return "Empty";
        default:  return NULL;
    }
}

/*
 * Called directly from `dispatch_by_ethertype()`'s LLC-framing check
 * — DSAP=SSAP=0x42, the same byte pattern that first routes to STP's
 * own check; this function only proceeds if the Protocol Identifier
 * doesn't match STP's fixed 0x0000, avoiding the overlap described
 * in the file header. `llc` points at the start of the LLC header
 * (DSAP byte), matching STP's own calling convention.
 */
static bool garp_dissect_llc_payload(const uint8_t *llc, uint16_t llc_len) {
    if (llc_len < 3 + 2) return false;
    if (llc[0] != 0x42 || llc[1] != 0x42) return false;

    const uint8_t *garp = llc + 3;   /* skip DSAP+SSAP+Control */
    uint16_t garp_len = llc_len - 3;
    if (garp_len < 2) return false;

    uint16_t protocol_id = (garp[0] << 8) | garp[1];
    if (protocol_id != GARP_PROTOCOL_ID_GVRP) return false;   /* not
                                                                  STP
                                                                  (that's
                                                                  0x0000,
                                                                  handled
                                                                  elsewhere)
                                                                  and not
                                                                  a value
                                                                  this
                                                                  project
                                                                  has
                                                                  confirmed */

    size_t pos = 2;
    char buf[512];
    int written = snprintf(buf, sizeof(buf), "{\"protocol\":\"GVRP\",\"garp_protocol_id\":\"0x%04x\"",
                            protocol_id);

    bool reported_first = false;
    while (pos < garp_len && written < (int)sizeof(buf) - 128) {
        uint8_t msg_type = garp[pos];
        if (msg_type == 0x00) break;   /* End-of-PDU mark */
        pos++;
        if (!reported_first) {
            written += snprintf(buf + written, sizeof(buf) - written,
                                 ",\"garp_attribute_type\":\"%u\"", msg_type);
        }

        int n_attrs = 0;
        while (pos < garp_len && n_attrs < GARP_MAX_ATTRS && written < (int)sizeof(buf) - 128) {
            uint8_t attr_len = garp[pos];
            if (attr_len == 0x00) { pos++; break; }   /* End-of-Attributes mark */
            if (attr_len < 2 || pos + attr_len > garp_len) break;
            uint8_t event = garp[pos + 1];
            const char *event_name = garp_event_name(event);

            if (!reported_first && event_name != NULL) {
                written += snprintf(buf + written, sizeof(buf) - written,
                                     ",\"garp_event\":\"%s\"", event_name);
                if (attr_len > 2) {
                    char valbuf[64];
                    size_t vlen = attr_len - 2;
                    size_t hex_n = 0;
                    for (size_t i = 0; i < vlen && hex_n + 2 < sizeof(valbuf) - 1; i++) {
                        snprintf(valbuf + hex_n, 3, "%02x", garp[pos + 2 + i]);
                        hex_n += 2;
                    }
                    valbuf[hex_n] = '\0';
                    written += snprintf(buf + written, sizeof(buf) - written,
                                         ",\"garp_value_hex\":\"%s\"", valbuf);
                }
                reported_first = true;
            }

            pos += attr_len;
            n_attrs++;
        }
    }

    snprintf(buf + written, sizeof(buf) - written, "}\n");
    printf("%s", buf);
    return true;
}
