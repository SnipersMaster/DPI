/*
 * dpi_radius_parser.c
 *
 * RADIUS (RFC 2865 authentication, RFC 2866 accounting) dissector.
 * No cryptography needed to parse the structure — the header and
 * attribute-value pairs are plaintext (the User-Password attribute is
 * individually obfuscated per RFC 2865 S5.2, but that's one attribute,
 * not the whole packet). This is why RADIUS was worth doing before
 * QUIC: same TLV-walking discipline already used for TCP/IP options,
 * just applied to a new protocol.
 *
 * Wire format (RFC 2865 S3):
 *   code(1) + identifier(1) + length(2) + authenticator(16) + attributes
 *
 * Attributes (RFC 2865 S5): type(1) + length(1) + value(length-2)
 *
 * NOT COMPILED/TESTED against live RADIUS traffic in this environment.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define RADIUS_HDR_LEN        20   /* code+id+length+authenticator */
#define RADIUS_PORT_AUTH     1812
#define RADIUS_PORT_AUTH_OLD 1645  /* legacy port, still seen */
#define RADIUS_PORT_ACCT     1813
#define RADIUS_PORT_ACCT_OLD 1646

/* RFC 2865 S3 code values */
#define RADIUS_CODE_ACCESS_REQUEST    1
#define RADIUS_CODE_ACCESS_ACCEPT     2
#define RADIUS_CODE_ACCESS_REJECT     3
#define RADIUS_CODE_ACCOUNTING_REQ    4
#define RADIUS_CODE_ACCOUNTING_RESP   5
#define RADIUS_CODE_ACCESS_CHALLENGE 11

/* A handful of well-known attribute types, RFC 2865 S5 */
#define RADIUS_ATTR_USER_NAME          1
#define RADIUS_ATTR_USER_PASSWORD      2   /* obfuscated, never log/expose raw */
#define RADIUS_ATTR_NAS_IP_ADDRESS     4
#define RADIUS_ATTR_NAS_PORT           5
#define RADIUS_ATTR_CALLING_STATION_ID 31
#define RADIUS_ATTR_ACCT_STATUS_TYPE   40  /* accounting: start/stop/interim */

static const char *radius_code_name(uint8_t code) {
    switch (code) {
        case RADIUS_CODE_ACCESS_REQUEST:  return "Access-Request";
        case RADIUS_CODE_ACCESS_ACCEPT:   return "Access-Accept";
        case RADIUS_CODE_ACCESS_REJECT:   return "Access-Reject";
        case RADIUS_CODE_ACCOUNTING_REQ:  return "Accounting-Request";
        case RADIUS_CODE_ACCOUNTING_RESP: return "Accounting-Response";
        case RADIUS_CODE_ACCESS_CHALLENGE:return "Access-Challenge";
        default: return "Unknown";
    }
}

/*
 * detect() — structural validation first, port as a secondary signal
 * only (same discipline as the VPN detector). A packet that doesn't
 * satisfy the header shape doesn't get called RADIUS just because it
 * showed up on port 1812.
 */
static double radius_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;   /* RADIUS is UDP */
    if (len < RADIUS_HDR_LEN) return 0.0;

    uint8_t code = payload[0];
    uint16_t declared_len = (payload[2] << 8) | payload[3];

    bool known_code = (code >= 1 && code <= 5) || code == 11 ||
                       code == 40 || code == 41 || code == 42 || code == 43;
    if (!known_code) return 0.0;

    /* RADIUS length field must be internally consistent: between the
     * minimum header size and 4096 (RFC 2865 S3 hard cap), and not
     * exceeding what we actually received. */
    if (declared_len < RADIUS_HDR_LEN || declared_len > 4096 || declared_len > len) {
        return 0.0;
    }

    double confidence = 0.6;   /* structurally plausible on its own */
    bool known_port = (dst_port == RADIUS_PORT_AUTH || dst_port == RADIUS_PORT_AUTH_OLD ||
                        dst_port == RADIUS_PORT_ACCT || dst_port == RADIUS_PORT_ACCT_OLD);
    if (known_port) confidence = 0.9;   /* structure + expected port: strong match */

    return confidence;
}

/*
 * dissect() — walk the attribute TLVs. Same bounds-checked-at-every-
 * step discipline as every other dissector in this project. Sensitive
 * attributes (User-Password) are flagged as present but their value is
 * NEVER copied into the output — this ties directly to the
 * logging/privacy protocol from the very first checklist in this
 * conversation ("never log payload/credential content by default").
 */
static void radius_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    /* Real defense-in-depth, not just relying on a comment that
     * detect() already checked this: a compiler warning (this
     * parameter was otherwise unused) was the prompt to actually
     * check `len` here rather than just silence the warning.
     * detect() and dissect() are always called on the SAME buffer by
     * this project's registry design, so this should never actually
     * fire in practice — but dissect() no longer silently trusts that
     * invariant. If something ever calls dissect() directly (a fuzz
     * harness bypassing detect(), a future refactor), this now fails
     * safely instead of reading past the real buffer. */
    if (len < RADIUS_HDR_LEN) return;

    uint8_t code = payload[0];
    uint8_t identifier = payload[1];
    uint16_t declared_len = (payload[2] << 8) | payload[3];

    char buf[64];
    snprintf(buf, sizeof(buf), "%s", radius_code_name(code));
    dissect_result_add(out, "radius_code", buf);

    snprintf(buf, sizeof(buf), "%u", identifier);
    dissect_result_add(out, "radius_identifier", buf);

    size_t pos = RADIUS_HDR_LEN;
    size_t end = declared_len;
    if (end > len) end = len;   /* clamp: declared_len is attacker-influenced */

    while (pos + 2 <= end) {
        uint8_t attr_type = payload[pos];
        uint8_t attr_len = payload[pos + 1];

        if (attr_len < 2 || pos + attr_len > end) {
            /* Malformed attribute length: stop parsing this packet's
             * attributes, but keep what we already extracted — don't
             * discard a partially-valid result over one bad TLV. */
            dissect_result_add(out, "parse_warning", "malformed_attribute_truncated");
            break;
        }

        uint8_t val_len = attr_len - 2;
        const uint8_t *val = payload + pos + 2;

        switch (attr_type) {
            case RADIUS_ATTR_USER_NAME: {
                char uname[MAX_FIELD_VAL_LEN];
                size_t n = val_len < sizeof(uname) - 1 ? val_len : sizeof(uname) - 1;
                memcpy(uname, val, n);
                uname[n] = '\0';
                dissect_result_add(out, "user_name", uname);
                break;
            }
            case RADIUS_ATTR_USER_PASSWORD:
                /* Present but deliberately NOT extracted — this is
                 * credential material (obfuscated, not encrypted, per
                 * RFC 2865 S5.2 — recoverable if you know the shared
                 * secret). Logging it, even obfuscated, is a
                 * credential-handling mistake regardless of whether an
                 * attacker could feasibly reverse it in your setup. */
                dissect_result_add(out, "user_password_present", "true");
                break;
            case RADIUS_ATTR_NAS_IP_ADDRESS: {
                if (val_len == 4) {
                    char ipbuf[32];
                    snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                             val[0], val[1], val[2], val[3]);
                    dissect_result_add(out, "nas_ip_address", ipbuf);
                }
                break;
            }
            case RADIUS_ATTR_CALLING_STATION_ID: {
                char csid[MAX_FIELD_VAL_LEN];
                size_t n = val_len < sizeof(csid) - 1 ? val_len : sizeof(csid) - 1;
                memcpy(csid, val, n);
                csid[n] = '\0';
                dissect_result_add(out, "calling_station_id", csid);
                break;
            }
            case RADIUS_ATTR_ACCT_STATUS_TYPE: {
                if (val_len == 4) {
                    uint32_t status = (val[0]<<24)|(val[1]<<16)|(val[2]<<8)|val[3];
                    snprintf(buf, sizeof(buf), "%u", status);
                    dissect_result_add(out, "acct_status_type", buf);
                }
                break;
            }
            default:
                break;   /* unrecognized attribute type: skip by length, don't guess */
        }

        pos += attr_len;
    }
}

static const uint16_t radius_hint_ports[] = {
    RADIUS_PORT_AUTH, RADIUS_PORT_AUTH_OLD, RADIUS_PORT_ACCT, RADIUS_PORT_ACCT_OLD
};

void register_radius_dissector(void) {
    register_dissector("RADIUS", radius_detect, radius_dissect,
                        radius_hint_ports, 4);
}
