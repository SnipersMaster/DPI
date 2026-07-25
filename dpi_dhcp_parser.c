/*
 * dpi_dhcp_parser.c
 *
 * DHCP (RFC 2131, options per RFC 2132) dissector — UDP/67 (server)
 * and UDP/68 (client). Plaintext fixed header + TLV options, same
 * discipline as RADIUS.
 *
 * NOT COMPILED/TESTED in this environment.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_MIN_LEN     240   /* fixed header (236) + magic cookie (4) */
#define DHCP_MAGIC_COOKIE 0x63825363

#define DHCP_OPT_MESSAGE_TYPE   53
#define DHCP_OPT_REQUESTED_IP   50
#define DHCP_OPT_HOSTNAME       12
#define DHCP_OPT_VENDOR_CLASS   60
#define DHCP_OPT_RELAY_AGENT_INFO 82
#define DHCP_OPT_AUTHENTICATION 90
#define DHCP_OPT_END           255
#define DHCP_OPT_PAD             0

static const char *dhcp_msg_type_name(uint8_t t) {
    switch (t) {
        case 1: return "DHCPDISCOVER";
        case 2: return "DHCPOFFER";
        case 3: return "DHCPREQUEST";
        case 4: return "DHCPDECLINE";
        case 5: return "DHCPACK";
        case 6: return "DHCPNAK";
        case 7: return "DHCPRELEASE";
        case 8: return "DHCPINFORM";
        default: return "Unknown";
    }
}

static double dhcp_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < DHCP_MIN_LEN) return 0.0;

    uint8_t op = payload[0];
    if (op != 1 && op != 2) return 0.0;   /* 1=BOOTREQUEST, 2=BOOTREPLY */

    uint32_t cookie = (payload[236]<<24)|(payload[237]<<16)|(payload[238]<<8)|payload[239];
    if (cookie != DHCP_MAGIC_COOKIE) return 0.0;

    double confidence = 0.7;
    if (dst_port == DHCP_SERVER_PORT || dst_port == DHCP_CLIENT_PORT) confidence = 0.9;
    return confidence;
}

static void dhcp_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint8_t op = payload[0];
    dissect_result_add(out, "dhcp_op", op == 1 ? "BOOTREQUEST" : "BOOTREPLY");

    /* Options begin right after the 4-byte magic cookie at offset 236. */
    size_t pos = 240;
    int iterations = 0;

    while (pos < len) {
        if (++iterations > 200) {   /* sanity bound, real DHCP options never
                                       come close to this many */
            dissect_result_add(out, "parse_warning", "too_many_options");
            break;
        }

        uint8_t opt_type = payload[pos];
        if (opt_type == DHCP_OPT_PAD) { pos += 1; continue; }
        if (opt_type == DHCP_OPT_END) break;

        if (pos + 1 >= len) {
            dissect_result_add(out, "parse_warning", "truncated_option_length");
            break;
        }
        uint8_t opt_len = payload[pos + 1];
        if (pos + 2 + opt_len > len) {
            dissect_result_add(out, "parse_warning", "option_claims_more_than_available");
            break;
        }
        const uint8_t *opt_val = payload + pos + 2;

        switch (opt_type) {
            case DHCP_OPT_MESSAGE_TYPE:
                if (opt_len == 1) {
                    dissect_result_add(out, "dhcp_message_type", dhcp_msg_type_name(opt_val[0]));
                }
                break;
            case DHCP_OPT_REQUESTED_IP:
                if (opt_len == 4) {
                    char ipbuf[32];
                    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                             opt_val[0], opt_val[1], opt_val[2], opt_val[3]);
                    dissect_result_add(out, "dhcp_requested_ip", ipbuf);
                }
                break;
            case DHCP_OPT_HOSTNAME: {
                char hostbuf[256];
                size_t n = opt_len < sizeof(hostbuf) - 1 ? opt_len : sizeof(hostbuf) - 1;
                memcpy(hostbuf, opt_val, n);
                hostbuf[n] = '\0';
                dissect_result_add(out, "dhcp_hostname", hostbuf);
                break;
            }
            case DHCP_OPT_VENDOR_CLASS: {
                char vcbuf[256];
                size_t n = opt_len < sizeof(vcbuf) - 1 ? opt_len : sizeof(vcbuf) - 1;
                memcpy(vcbuf, opt_val, n);
                vcbuf[n] = '\0';
                dissect_result_add(out, "dhcp_vendor_class", vcbuf);
                break;
            }
            case DHCP_OPT_AUTHENTICATION: {
                /* RFC 3118. Verified against a real option (31 bytes)
                 * found in a real capture: Protocol(1)+Algorithm(1)+
                 * RDM(1)+Replay Detection(8)+Authentication
                 * Information(remaining) — for the real Algorithm=1
                 * (HMAC-MD5) case found, Authentication Information
                 * splits exactly into a 4-byte Secret ID + 16-byte
                 * HMAC-MD5 digest per RFC 3118 S4's "delayed
                 * authentication" format for that algorithm, 20 bytes
                 * total, matching this real option's length exactly.
                 * Only a digest is extracted here, never anything
                 * that could reconstruct the shared secret — same
                 * "extract identity, never credentials" discipline as
                 * every other dissector in this project; an HMAC
                 * digest doesn't reveal the key it was computed with. */
                if (opt_len < 11) break;   /* too short for even the fixed fields */
                uint8_t protocol = opt_val[0];
                uint8_t algorithm = opt_val[1];
                uint8_t rdm = opt_val[2];

                char buf[8];
                snprintf(buf, sizeof(buf), "%u", protocol);
                dissect_result_add(out, "dhcp_auth_protocol", buf);
                dissect_result_add(out, "dhcp_auth_algorithm",
                                    algorithm == 1 ? "HMAC-MD5" : "Unknown");
                dissect_result_add(out, "dhcp_auth_rdm",
                                    rdm == 0 ? "Monotonically Increasing Counter" : "Unknown");

                char hexbuf[80];
                size_t hex_n = 0;
                for (int i = 3; i < 11 && hex_n + 2 < sizeof(hexbuf); i++) {
                    snprintf(hexbuf + hex_n, 3, "%02x", opt_val[i]);
                    hex_n += 2;
                }
                hexbuf[hex_n] = '\0';
                dissect_result_add(out, "dhcp_auth_replay_detection_hex", hexbuf);

                if (opt_len > 11) {
                    hex_n = 0;
                    for (int i = 11; i < opt_len && hex_n + 2 < sizeof(hexbuf); i++) {
                        snprintf(hexbuf + hex_n, 3, "%02x", opt_val[i]);
                        hex_n += 2;
                    }
                    hexbuf[hex_n] = '\0';
                    dissect_result_add(out, "dhcp_auth_info_hex", hexbuf);
                }
                break;
            }
            case DHCP_OPT_RELAY_AGENT_INFO: {
                /* RFC 3046. Sub-options are TLV-encoded: SubOpt(1) +
                 * SubOptLen(1) + SubOptValue. Verified against a real
                 * option (22 bytes, one sub-option) in the same real
                 * capture as the Authentication option above:
                 * sub-option 1 (Agent Circuit ID) containing a real,
                 * printable ASCII circuit identifier from real access
                 * equipment (" PON 1/1/07/01:1.0.1" — a passive-
                 * optical-network port identifier). Sub-option 2
                 * (Agent Remote ID) is named the same way per RFC
                 * 3046 but wasn't present in the real capture checked
                 * — extracted with the identical printable-ASCII-or-
                 * hex-fallback approach as sub-option 1, not
                 * separately real-traffic-verified. */
                size_t sp = 0;
                int n_suboptions = 0;
                while (sp + 2 <= (size_t)opt_len && n_suboptions < 8) {
                    uint8_t subopt = opt_val[sp];
                    uint8_t sublen = opt_val[sp + 1];
                    if (sp + 2 + sublen > (size_t)opt_len) break;
                    const uint8_t *subval = opt_val + sp + 2;

                    bool printable = sublen > 0;
                    for (int i = 0; i < sublen; i++) {
                        if (subval[i] < 0x20 || subval[i] > 0x7E) { printable = false; break; }
                    }

                    const char *key = subopt == 1 ? "dhcp_relay_agent_circuit_id" :
                                       subopt == 2 ? "dhcp_relay_agent_remote_id" : NULL;
                    if (key) {
                        char subbuf[128];
                        if (printable) {
                            size_t n = sublen < sizeof(subbuf) - 1 ? sublen : sizeof(subbuf) - 1;
                            memcpy(subbuf, subval, n);
                            subbuf[n] = '\0';
                        } else {
                            size_t hex_n = 0;
                            for (int i = 0; i < sublen && hex_n + 2 < sizeof(subbuf); i++) {
                                snprintf(subbuf + hex_n, 3, "%02x", subval[i]);
                                hex_n += 2;
                            }
                            subbuf[hex_n] = '\0';
                        }
                        dissect_result_add(out, key, subbuf);
                    }
                    sp += 2 + sublen;
                    n_suboptions++;
                }
                break;
            }
            default:
                break;   /* unrecognized option: skip by declared length */
        }

        pos += 2 + opt_len;
    }
}

static const uint16_t dhcp_hint_ports[] = { DHCP_SERVER_PORT, DHCP_CLIENT_PORT };

void register_dhcp_dissector(void) {
    register_dissector("DHCP", dhcp_detect, dhcp_dissect, dhcp_hint_ports, 2);
}
