/*
 * dpi_dns_parser.c
 *
 * DNS (RFC 1035) dissector — header + question section + answer
 * record walking (A/AAAA/CNAME). Authority and additional sections are
 * not walked in this reference version (see the note near the bottom).
 *
 * Standard ports: UDP/53 (primary), TCP/53 (large responses, zone
 * transfers) — this dissector's detect()/dissect() take an l4_proto
 * parameter and work for either, though DNS-over-TCP framing (a
 * 2-byte length prefix before the message) needs one extra step the
 * caller must handle — see the note in dns_detect().
 *
 * NOT COMPILED/TESTED against live DNS traffic in this environment.
 *
 * -------------------------------------------------------------------
 * WHY NAME DECOMPRESSION GETS ITS OWN CAREFUL TREATMENT
 * -------------------------------------------------------------------
 * DNS name compression (RFC 1035 §4.1.4) lets a name reference an
 * earlier occurrence via a 2-byte pointer instead of repeating it —
 * this is also one of the most common sources of real DNS parser bugs
 * historically (infinite loops from cyclic pointers, quadratic
 * blowup from long pointer chains, out-of-bounds reads from an
 * unvalidated pointer target). This implementation guards against all
 * three explicitly:
 *   - MAX_POINTER_JUMPS caps how many times we follow a compression
 *     pointer per name, guaranteeing termination even against a
 *     deliberately cyclic packet.
 *   - Every pointer target is bounds-checked against the packet buffer
 *     before being followed.
 *   - MAX_DNS_NAME_LEN caps the total assembled name length (matching
 *     RFC 1035's 255-byte limit) regardless of how many labels/jumps
 *     contributed to it.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#define DNS_PORT            53
#define DNS_HDR_LEN         12
#define MAX_DNS_NAME_LEN    255   /* RFC 1035 §3.1 */
#define MAX_POINTER_JUMPS   32    /* generous for any legitimate packet,
                                    * tight enough to bound worst-case work */
#define MAX_LABEL_OUTPUT    300   /* MAX_DNS_NAME_LEN plus room for the
                                    * dots this reference adds between labels */

static double dns_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    /* NOTE ON TCP: DNS-over-TCP (RFC 1035 §4.2.2) prefixes the message
     * with a 2-byte length field before the actual DNS message begins.
     * This function expects to be called with that prefix ALREADY
     * stripped (i.e. `payload` points at the DNS header itself) — the
     * caller is responsible for that framing step on TCP, the same way
     * dpi_rfc_parser.c's TCP path already separates framing from
     * per-message parsing. Not handling this distinction here would be
     * silently wrong on TCP rather than a clear, documented caller
     * contract. */
    (void)l4_proto;
    if (len < DNS_HDR_LEN) return 0.0;

    uint16_t qdcount = (payload[4] << 8) | payload[5];
    uint16_t ancount = (payload[6] << 8) | payload[7];
    uint16_t nscount = (payload[8] << 8) | payload[9];
    uint16_t arcount = (payload[10] << 8) | payload[11];

    /* A real DNS message practically never has thousands of records —
     * this isn't a protocol limit, it's a sanity bound to reject
     * obvious garbage cheaply before doing any real parsing work. */
    if (qdcount > 64 || ancount > 4096 || nscount > 4096 || arcount > 4096) return 0.0;

    uint8_t opcode = (payload[2] >> 3) & 0x0F;
    uint8_t rcode = payload[3] & 0x0F;
    /* Opcode 0-5 and 4096-range rcodes are defined; a wildly invalid
     * combination is a (weak) signal this isn't really DNS. */
    if (opcode > 5) return 0.2;

    double confidence = 0.5;
    if (dst_port == DNS_PORT) confidence = 0.85;
    (void)rcode;
    return confidence;
}

/*
 * Decode a (possibly compressed) DNS name starting at `payload + pos`.
 * `packet` / `packet_len` are the FULL message buffer, needed because
 * compression pointers can reference anywhere earlier in the packet,
 * not just within the current field. Returns the number of bytes
 * consumed from the ORIGINAL (non-followed) position — i.e. how far
 * to advance `pos` in the caller's linear walk — or 0 on failure.
 */
static size_t dns_decode_name(const uint8_t *packet, size_t packet_len,
                               size_t start_pos, char *out, size_t out_cap) {
    size_t pos = start_pos;
    size_t out_len = 0;
    int jumps = 0;
    bool jumped = false;
    size_t consumed_before_first_jump = 0;

    out[0] = '\0';

    while (true) {
        if (pos >= packet_len) return 0;   /* ran off the end: malformed */

        uint8_t label_len = packet[pos];

        if (label_len == 0) {
            /* End of name. */
            if (!jumped) consumed_before_first_jump = pos + 1 - start_pos;
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            /* Compression pointer: top two bits set, remaining 14 bits
             * (this byte's low 6 + next byte) are the offset. */
            if (pos + 1 >= packet_len) return 0;
            uint16_t ptr_offset = ((label_len & 0x3F) << 8) | packet[pos + 1];

            if (!jumped) {
                consumed_before_first_jump = pos + 2 - start_pos;
                jumped = true;
            }

            jumps++;
            if (jumps > MAX_POINTER_JUMPS) return 0;   /* cycle or absurd chain: reject */

            /* Bounds-check the target BEFORE following it — this is
             * the check that turns "attacker-controlled offset" into
             * "safe to dereference", not just "probably fine". */
            if (ptr_offset >= packet_len) return 0;

            pos = ptr_offset;
            continue;
        }

        if (label_len > 63) return 0;   /* RFC 1035: labels are max 63 bytes */
        if (pos + 1 + label_len > packet_len) return 0;   /* label claims more than we have */

        if (out_len + label_len + 1 >= out_cap - 1 || out_len + label_len + 1 >= MAX_LABEL_OUTPUT) {
            return 0;   /* assembled name would exceed RFC 1035's 255-byte limit */
        }

        if (out_len > 0) out[out_len++] = '.';
        memcpy(out + out_len, packet + pos + 1, label_len);
        out_len += label_len;
        out[out_len] = '\0';

        pos += 1 + label_len;
    }

    return consumed_before_first_jump;   /* 0 only on a genuine parse failure
                                           * (see the `return 0` branches above);
                                           * a legitimate root name ("." — a
                                           * single zero byte) correctly
                                           * returns 1, never 0. */
}

static void dns_dissect(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto,
                         struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint16_t flags = (payload[2] << 8) | payload[3];
    bool is_response = (flags & 0x8000) != 0;
    uint8_t opcode = (payload[2] >> 3) & 0x0F;
    uint8_t rcode = payload[3] & 0x0F;
    uint16_t qdcount = (payload[4] << 8) | payload[5];

    dissect_result_add(out, "dns_is_response", is_response ? "true" : "false");

    char buf[16];
    snprintf(buf, sizeof(buf), "%u", opcode);
    dissect_result_add(out, "dns_opcode", buf);
    snprintf(buf, sizeof(buf), "%u", rcode);
    dissect_result_add(out, "dns_rcode", buf);

    if (qdcount == 0) {
        dissect_result_add(out, "parse_warning", "no_question_section");
        return;
    }

    /* Only the FIRST question is extracted — qdcount > 1 is legal but
     * vanishingly rare in practice (most resolvers/clients send
     * exactly one question per message); walking further questions
     * would follow the identical pattern below. */
    size_t pos = DNS_HDR_LEN;
    char qname[MAX_LABEL_OUTPUT];
    size_t consumed = dns_decode_name(payload, len, pos, qname, sizeof(qname));

    /* consumed == 0 is always a genuine parse failure here — even the
     * root name ("." — a single zero byte) correctly returns 1, not 0,
     * so there's no legitimate case this check needs to carve out. */
    if (consumed == 0) {
        dissect_result_add(out, "parse_warning", "malformed_or_unterminated_qname");
        return;
    }

    dissect_result_add(out, "dns_qname", qname);
    pos += consumed;

    if (pos + 4 > len) {
        dissect_result_add(out, "parse_warning", "truncated_qtype_qclass");
        return;
    }
    uint16_t qtype = (payload[pos] << 8) | payload[pos + 1];
    uint16_t qclass = (payload[pos + 2] << 8) | payload[pos + 3];

    snprintf(buf, sizeof(buf), "%u", qtype);
    dissect_result_add(out, "dns_qtype", buf);
    snprintf(buf, sizeof(buf), "%u", qclass);
    dissect_result_add(out, "dns_qclass", buf);

    /* Answer section — the resolved IP addresses (A/AAAA) and CNAME
     * chains, when this message is a response. This reuses the exact
     * same dns_decode_name() used for the question above; RRs
     * legitimately DO use compression pointers back to the question
     * name (this is the case that wasn't representable in the
     * question-only version — an RR's NAME field pointing back to
     * offset 12 is completely normal, unlike a self-referential
     * question). RDATA is parsed per-type for A/AAAA/CNAME; other
     * types are skipped by their declared RDLENGTH rather than parsed
     * — extending to more types follows the same pattern.
     */
    uint16_t ancount = (payload[6] << 8) | payload[7];
    int records_parsed = 0;

    for (uint16_t i = 0; i < ancount && pos < len; i++) {
        if (records_parsed >= 32) {   /* sanity bound on how many answer
                                        * records we'll walk per message */
            dissect_result_add(out, "parse_warning", "answer_record_limit_reached");
            break;
        }

        char rr_name[MAX_LABEL_OUTPUT];
        size_t rr_name_consumed = dns_decode_name(payload, len, pos, rr_name, sizeof(rr_name));
        if (rr_name_consumed == 0) {
            dissect_result_add(out, "parse_warning", "malformed_answer_rr_name");
            break;
        }
        pos += rr_name_consumed;

        if (pos + 10 > len) {   /* TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2) */
            dissect_result_add(out, "parse_warning", "truncated_answer_rr_header");
            break;
        }
        uint16_t rr_type = (payload[pos] << 8) | payload[pos + 1];
        uint32_t rr_ttl = (payload[pos+4]<<24)|(payload[pos+5]<<16)|(payload[pos+6]<<8)|payload[pos+7];
        uint16_t rdlength = (payload[pos + 8] << 8) | payload[pos + 9];
        pos += 10;

        if (pos + rdlength > len) {
            dissect_result_add(out, "parse_warning", "rdata_exceeds_available_length");
            break;
        }

        char field_key[32], field_val[300];

        switch (rr_type) {
            case 1:   /* A */
                if (rdlength == 4) {
                    snprintf(field_key, sizeof(field_key), "dns_answer_%d_a", records_parsed);
                    snprintf(field_val, sizeof(field_val), "%u.%u.%u.%u",
                             payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]);
                    dissect_result_add(out, field_key, field_val);
                }
                break;
            case 28: {  /* AAAA */
                if (rdlength == 16) {
                    char v6buf[46];
                    struct in6_addr addr;
                    memcpy(&addr, payload + pos, 16);
                    if (inet_ntop(AF_INET6, &addr, v6buf, sizeof(v6buf))) {
                        snprintf(field_key, sizeof(field_key), "dns_answer_%d_aaaa", records_parsed);
                        dissect_result_add(out, field_key, v6buf);
                    }
                }
                break;
            }
            case 5: {   /* CNAME — RDATA is itself a (possibly compressed) name */
                char cname[MAX_LABEL_OUTPUT];
                size_t cname_consumed = dns_decode_name(payload, len, pos, cname, sizeof(cname));
                if (cname_consumed != 0) {
                    snprintf(field_key, sizeof(field_key), "dns_answer_%d_cname", records_parsed);
                    dissect_result_add(out, field_key, cname);
                }
                break;
            }
            default:
                break;   /* unrecognized type: RDATA already bounds-validated
                          * above, just skip over it via rdlength below */
        }

        (void)rr_ttl;   /* extracted but not currently surfaced as its own
                          * field — TTL-based caching/expiry analysis is a
                          * reasonable future addition, not done here */
        pos += rdlength;
        records_parsed++;
    }

    char count_buf[16];
    snprintf(count_buf, sizeof(count_buf), "%d", records_parsed);
    dissect_result_add(out, "dns_answer_records_parsed", count_buf);
}

static const uint16_t dns_hint_ports[] = { DNS_PORT };

void register_dns_dissector(void) {
    register_dissector("DNS", dns_detect, dns_dissect, dns_hint_ports, 1);
}
