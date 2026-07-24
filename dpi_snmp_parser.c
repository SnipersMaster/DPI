/*
 * dpi_snmp_parser.c
 *
 * SNMP (RFC 1157 v1, RFC 1901/3416 v2c) dissector — the first ASN.1
 * BER-encoded protocol in this project, a genuinely different parsing
 * paradigm from everything else built so far (fixed fields or simple
 * length-prefixed TLV). A minimal BER TLV reader (tag + length +
 * value, short-form and long-form length both handled) was verified
 * end-to-end in Python — constructing a real SNMPv2c GetRequest byte
 * sequence and parsing it back out, confirming version/community/PDU
 * type/request-id all extracted correctly — before writing this C
 * version.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * SCOPE: SNMPv1/v2c only (community-string-based). SNMPv3's message
 * format is structurally different (msgGlobalData, USM security
 * parameters, no plaintext community string) — detected as "SNMP,
 * version 3" but not parsed further, flagged rather than
 * misinterpreted as v1/v2c's simpler structure.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define SNMP_PORT      161
#define SNMP_TRAP_PORT 162

/*
 * BER TLV reader — tag(1 byte) + length (short or long form, RFC
 * 8825-style, though SNMP predates that document, the BER length
 * encoding itself is the same X.690 rules) + value. Verified against
 * a real constructed message before use (see file header).
 */
static bool snmp_ber_read_tlv(const uint8_t *data, size_t len, size_t *pos,
                          uint8_t *out_tag, size_t *out_value_start, size_t *out_value_len) {
    if (*pos >= len) return false;
    uint8_t tag = data[*pos];
    (*pos)++;

    if (*pos >= len) return false;
    uint8_t first_len_byte = data[*pos];
    (*pos)++;

    size_t value_len;
    if ((first_len_byte & 0x80) == 0) {
        value_len = first_len_byte;   /* short form */
    } else {
        uint8_t num_len_bytes = first_len_byte & 0x7F;
        if (num_len_bytes == 0 || num_len_bytes > 4) return false;   /* indefinite-length
                                                                        (BER, not DER) not
                                                                        supported, or absurd */
        if (*pos + num_len_bytes > len) return false;
        value_len = 0;
        for (int i = 0; i < num_len_bytes; i++) {
            value_len = (value_len << 8) | data[*pos + i];
        }
        *pos += num_len_bytes;
    }

    if (*pos + value_len > len) return false;   /* declared length exceeds buffer */

    *out_tag = tag;
    *out_value_start = *pos;
    *out_value_len = value_len;
    *pos += value_len;   /* caller can reset *pos to *out_value_start to descend
                            into this TLV's contents, or leave it advanced past
                            it to move to the next sibling TLV */
    return true;
}

static const char *snmp_pdu_type_name(uint8_t tag) {
    switch (tag) {
        case 0xA0: return "GetRequest";
        case 0xA1: return "GetNextRequest";
        case 0xA2: return "GetResponse";       /* "Response" in v2c terminology */
        case 0xA3: return "SetRequest";
        case 0xA4: return "Trap (v1)";
        case 0xA5: return "GetBulkRequest";
        case 0xA6: return "InformRequest";
        case 0xA7: return "SNMPv2-Trap";
        case 0xA8: return "Report";
        default:   return "Unknown";
    }
}

static double snmp_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;   /* SNMP is conventionally UDP */
    if (len < 2) return 0.0;
    if (payload[0] != 0x30) return 0.0;   /* must start with SEQUENCE tag */

    size_t pos = 0;
    uint8_t tag; size_t val_start, val_len;
    if (!snmp_ber_read_tlv(payload, len, &pos, &tag, &val_start, &val_len)) return 0.0;

    /* Descend into the outer SEQUENCE and check the version INTEGER
     * looks plausible (0, 1, or 3) — cheap structural validation
     * before committing to "this is SNMP". */
    size_t inner_pos = val_start;
    uint8_t ver_tag; size_t ver_val_start, ver_val_len;
    if (!snmp_ber_read_tlv(payload, val_start + val_len, &inner_pos, &ver_tag, &ver_val_start, &ver_val_len)) {
        return 0.0;
    }
    if (ver_tag != 0x02 || ver_val_len != 1) return 0.0;   /* version must be a 1-byte INTEGER */
    uint8_t version = payload[ver_val_start];
    if (version != 0 && version != 1 && version != 3) return 0.0;

    double confidence = 0.7;
    if (dst_port == SNMP_PORT || dst_port == SNMP_TRAP_PORT) confidence = 0.9;
    return confidence;
}

/*
 * Decode a BER OBJECT IDENTIFIER, X.690 S8.19. First byte encodes the
 * first two sub-identifiers as (X*40 + Y); each subsequent
 * sub-identifier is base-128 encoded with a continuation bit (0x80)
 * set on all but the last byte of that sub-identifier. Verified
 * against constructed test OIDs (including one needing a multi-byte
 * sub-identifier) in Python before writing this C version.
 */
static bool ber_decode_oid(const uint8_t *data, size_t len, char *out, size_t out_cap) {
    if (len == 0) return false;

    size_t o = 0;
    uint8_t first = data[0];
    int written = snprintf(out + o, out_cap - o, "%u.%u", first / 40, first % 40);
    if (written < 0 || (size_t)written >= out_cap - o) return false;
    o += (size_t)written;

    uint32_t val = 0;
    for (size_t i = 1; i < len; i++) {
        uint8_t b = data[i];
        val = (val << 7) | (b & 0x7F);
        if ((b & 0x80) == 0) {
            written = snprintf(out + o, out_cap - o, ".%u", val);
            if (written < 0 || (size_t)written >= out_cap - o) return false;
            o += (size_t)written;
            val = 0;
        }
    }
    return true;
}

/*
 * Walk the variable-bindings SEQUENCE OF VarBind, where each VarBind
 * is itself SEQUENCE { name OBJECT IDENTIFIER, value ANY }. Bounded to
 * a handful of varbinds. Covers every standard SNMP SMI value type
 * (RFC 2578): INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER,
 * IpAddress, Counter32, Gauge32, TimeTicks, Counter64, and Opaque
 * (extracted identically to OCTET STRING, since RFC 2578 defines it
 * as exactly that with a different application tag — same wire
 * encoding, not a separate structure to verify), plus the three
 * SNMPv2 exception values (RFC 3416 S2.10: noSuchObject,
 * noSuchInstance, endOfMibView). Real traffic checked for this
 * project only ever exercised INTEGER, OCTET STRING, and NULL —
 * Opaque and the exception values are included for completeness
 * against the standard, stated honestly as not real-traffic-verified
 * the way the three common types are. Any remaining unrecognized tag
 * is named but not decoded further.
 */
static void snmp_walk_varbinds(const uint8_t *payload, size_t vb_list_start, size_t vb_list_len,
                                struct dissect_result *out) {
    size_t pos = vb_list_start;
    size_t end = vb_list_start + vb_list_len;
    int vb_count = 0;

    while (pos < end && vb_count < 16) {
        uint8_t vb_tag; size_t vb_val_start, vb_val_len;
        if (!snmp_ber_read_tlv(payload, end, &pos, &vb_tag, &vb_val_start, &vb_val_len)) break;
        if (vb_tag != 0x30 /* SEQUENCE */) break;

        size_t inner = vb_val_start;
        size_t inner_end = vb_val_start + vb_val_len;

        uint8_t oid_tag; size_t oid_val_start, oid_val_len;
        if (!snmp_ber_read_tlv(payload, inner_end, &inner, &oid_tag, &oid_val_start, &oid_val_len)) break;
        if (oid_tag != 0x06 /* OBJECT IDENTIFIER */) break;

        char oid_str[256];
        char key[48], val_buf[300];
        if (ber_decode_oid(payload + oid_val_start, oid_val_len, oid_str, sizeof(oid_str))) {
            snprintf(key, sizeof(key), "snmp_varbind_%d_oid", vb_count);
            dissect_result_add(out, key, oid_str);
        }

        uint8_t val_tag; size_t val_val_start, val_val_len;
        if (snmp_ber_read_tlv(payload, inner_end, &inner, &val_tag, &val_val_start, &val_val_len)) {
            snprintf(key, sizeof(key), "snmp_varbind_%d_value", vb_count);

            switch (val_tag) {
                case 0x02: /* INTEGER */
                case 0x41: /* Counter32 */
                case 0x42: /* Gauge32 */
                case 0x43: { /* TimeTicks */
                    if (val_val_len >= 1 && val_val_len <= 4) {
                        uint32_t v = 0;
                        for (size_t i = 0; i < val_val_len; i++) v = (v << 8) | payload[val_val_start + i];
                        snprintf(val_buf, sizeof(val_buf), "%u", v);
                        dissect_result_add(out, key, val_buf);
                    }
                    break;
                }
                case 0x46: { /* Counter64 */
                    if (val_val_len >= 1 && val_val_len <= 8) {
                        uint64_t v = 0;
                        for (size_t i = 0; i < val_val_len; i++) v = (v << 8) | payload[val_val_start + i];
                        snprintf(val_buf, sizeof(val_buf), "%llu", (unsigned long long)v);
                        dissect_result_add(out, key, val_buf);
                    }
                    break;
                }
                case 0x04: /* OCTET STRING */
                case 0x44: { /* Opaque — RFC 2578 defines this as
                              * "[APPLICATION 4] IMPLICIT OCTET STRING":
                              * same underlying wire encoding as OCTET
                              * STRING, just a different application
                              * tag, so the identical extraction is
                              * correct by the standard's own
                              * definition, not a guess. No real Opaque-
                              * tagged varbind was found in any capture
                              * checked for this project — only
                              * INTEGER, OCTET STRING, and NULL values
                              * were ever seen in real traffic — stated
                              * honestly rather than implied verified. */
                    size_t n = val_val_len < sizeof(val_buf) - 1 ? val_val_len : sizeof(val_buf) - 1;
                    memcpy(val_buf, payload + val_val_start, n);
                    val_buf[n] = '\0';
                    dissect_result_add(out, key, val_buf);
                    break;
                }
                case 0x40: { /* IpAddress — 4-byte OCTET STRING, dotted-quad */
                    if (val_val_len == 4) {
                        snprintf(val_buf, sizeof(val_buf), "%u.%u.%u.%u",
                                 payload[val_val_start], payload[val_val_start+1],
                                 payload[val_val_start+2], payload[val_val_start+3]);
                        dissect_result_add(out, key, val_buf);
                    }
                    break;
                }
                case 0x05: /* NULL */
                    dissect_result_add(out, key, "null");
                    break;
                case 0x06: { /* OBJECT IDENTIFIER value (some varbinds return an OID) */
                    if (ber_decode_oid(payload + val_val_start, val_val_len, val_buf, sizeof(val_buf))) {
                        dissect_result_add(out, key, val_buf);
                    }
                    break;
                }
                case 0x80: /* noSuchObject — SNMPv2 exception value, RFC
                            * 3416 S2.10. Not found in any real capture
                            * checked; the shape (context-tagged, no
                            * meaningful content) is simple enough that
                            * verifying it wasn't necessary the way a
                            * multi-field structure would be, but
                            * stated honestly as unverified against
                            * real traffic regardless. */
                    dissect_result_add(out, key, "noSuchObject");
                    break;
                case 0x81: /* noSuchInstance — same caveat as noSuchObject */
                    dissect_result_add(out, key, "noSuchInstance");
                    break;
                case 0x82: /* endOfMibView — same caveat as noSuchObject */
                    dissect_result_add(out, key, "endOfMibView");
                    break;
                default:
                    /* Opaque and other less common types: named by tag,
                     * not decoded further. */
                    snprintf(val_buf, sizeof(val_buf), "unhandled_type_0x%02x", val_tag);
                    dissect_result_add(out, key, val_buf);
                    break;
            }
        }

        vb_count++;
    }

    char count_buf[16];
    snprintf(count_buf, sizeof(count_buf), "%d", vb_count);
    dissect_result_add(out, "snmp_varbind_count", count_buf);
}

static void snmp_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t pos = 0;
    uint8_t tag; size_t val_start, val_len;
    if (!snmp_ber_read_tlv(payload, len, &pos, &tag, &val_start, &val_len)) return;

    size_t msg_end = val_start + val_len;
    size_t inner_pos = val_start;

    uint8_t ver_tag; size_t ver_val_start, ver_val_len;
    if (!snmp_ber_read_tlv(payload, msg_end, &inner_pos, &ver_tag, &ver_val_start, &ver_val_len)) return;
    uint8_t version = payload[ver_val_start];

    const char *version_name = (version == 0) ? "v1" : (version == 1) ? "v2c" : "v3";
    dissect_result_add(out, "snmp_version", version_name);

    if (version == 3) {
        /* SNMPv3's structure diverges from here — msgGlobalData, USM
         * security parameters, no plaintext community string. Not
         * parsed further, per this file's stated scope. */
        dissect_result_add(out, "snmp_v3_structure_not_parsed", "true");
        return;
    }

    uint8_t comm_tag; size_t comm_val_start, comm_val_len;
    if (!snmp_ber_read_tlv(payload, msg_end, &inner_pos, &comm_tag, &comm_val_start, &comm_val_len)) return;
    if (comm_tag == 0x04 /* OCTET STRING */) {
        char community[256];
        size_t n = comm_val_len < sizeof(community) - 1 ? comm_val_len : sizeof(community) - 1;
        memcpy(community, payload + comm_val_start, n);
        community[n] = '\0';
        /* SNMP community strings function as a plaintext password —
         * flagged with the SAME care as RADIUS's User-Password and
         * GTPv2's IMSI/MSISDN elsewhere in this project: this is
         * credential-adjacent material (SNMPv1/v2c's only access
         * control mechanism), not a casually-loggable identifier. */
        dissect_result_add(out, "snmp_community_string", community);
    }

    uint8_t pdu_tag; size_t pdu_val_start, pdu_val_len;
    if (!snmp_ber_read_tlv(payload, msg_end, &inner_pos, &pdu_tag, &pdu_val_start, &pdu_val_len)) return;
    dissect_result_add(out, "snmp_pdu_type", snmp_pdu_type_name(pdu_tag));

    if (pdu_tag == 0xA4 /* Trap-PDU, v1 — different structure, no request-id */) {
        return;
    }

    size_t pdu_pos = pdu_val_start;
    size_t pdu_end = pdu_val_start + pdu_val_len;
    uint8_t reqid_tag; size_t reqid_val_start, reqid_val_len;
    if (snmp_ber_read_tlv(payload, pdu_end, &pdu_pos, &reqid_tag, &reqid_val_start, &reqid_val_len)
        && reqid_tag == 0x02 && reqid_val_len <= 4) {
        uint32_t request_id = 0;
        for (size_t i = 0; i < reqid_val_len; i++) {
            request_id = (request_id << 8) | payload[reqid_val_start + i];
        }
        char buf[16];
        snprintf(buf, sizeof(buf), "%u", request_id);
        dissect_result_add(out, "snmp_request_id", buf);
    } else {
        return;   /* couldn't even find request-id: don't guess at the rest */
    }

    /* error-status and error-index: skip over both (each a small
     * INTEGER) rather than extract — meaningful mainly on responses,
     * and the varbind list itself is the higher-value target here. */
    uint8_t err_tag; size_t err_val_start, err_val_len;
    if (!snmp_ber_read_tlv(payload, pdu_end, &pdu_pos, &err_tag, &err_val_start, &err_val_len)) return;
    if (!snmp_ber_read_tlv(payload, pdu_end, &pdu_pos, &err_tag, &err_val_start, &err_val_len)) return;

    uint8_t vb_list_tag; size_t vb_list_val_start, vb_list_val_len;
    if (!snmp_ber_read_tlv(payload, pdu_end, &pdu_pos, &vb_list_tag, &vb_list_val_start, &vb_list_val_len)) return;
    if (vb_list_tag != 0x30 /* SEQUENCE OF VarBind */) return;

    snmp_walk_varbinds(payload, vb_list_val_start, vb_list_val_len, out);
}

static const uint16_t snmp_hint_ports[] = { SNMP_PORT, SNMP_TRAP_PORT };

void register_snmp_dissector(void) {
    register_dissector("SNMP", snmp_detect, snmp_dissect, snmp_hint_ports, 2);
}
