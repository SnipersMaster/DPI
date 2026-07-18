/*
 * dpi_ssh_parser.c
 *
 * SSH (RFC 4253) dissector — version banner and KEXINIT (key exchange
 * initialization) algorithm negotiation. Both are sent in PLAINTEXT
 * before encryption begins (RFC 4253 §4.2, §7.1) — the same
 * "protocol negotiates in the clear first" pattern as TLS's
 * ClientHello, which is why this is fuzzable/parseable without any
 * crypto boundary at all, unlike the actual encrypted session that
 * follows.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * SCOPE: this parses the identification string and the KEXINIT
 * algorithm lists — genuinely useful for fingerprinting client/server
 * implementations and spotting anomalous algorithm negotiation (e.g. a
 * client offering only deprecated/weak algorithms), similar in spirit
 * to JA3 for TLS. It does NOT parse anything past KEXINIT — the
 * Diffie-Hellman exchange and everything after is either genuinely
 * encrypted or not worth this project's effort to parse further.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define SSH_PORT 22

static double ssh_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;   /* SSH is TCP-only */
    if (len < 4) return 0.0;
    if (memcmp(payload, "SSH-", 4) != 0) return 0.0;

    double confidence = 0.6;
    if (dst_port == SSH_PORT) confidence = 0.9;
    return confidence;
}

static size_t ssh_find_line_end(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') return i;
    }
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\n') return i;
    }
    return len;
}

/*
 * KEXINIT packet, RFC 4253 §7.1, inside the SSH binary packet
 * protocol (§6): packet_length(4) + padding_length(1) + payload
 * (starts with message code 20 = SSH_MSG_KEXINIT) + padding + MAC.
 * The payload itself: cookie(16 random bytes) + 10 name-lists, each
 * name-list being length(4) + comma-separated ASCII names.
 */
#define SSH_MSG_KEXINIT 20
#define SSH_MAX_NAMELIST_OUT 256

static bool ssh_read_namelist(const uint8_t *buf, size_t len, size_t pos,
                               char *out, size_t out_cap, size_t *consumed) {
    if (pos + 4 > len) return false;
    uint32_t namelist_len = (buf[pos]<<24)|(buf[pos+1]<<16)|(buf[pos+2]<<8)|buf[pos+3];
    if (pos + 4 + namelist_len > len) return false;

    size_t copy_len = namelist_len;
    if (copy_len >= out_cap) copy_len = out_cap - 1;   /* truncate for output only */

    memcpy(out, buf + pos + 4, copy_len);
    out[copy_len] = '\0';
    *consumed = 4 + namelist_len;   /* actual wire-format length, NOT the
                                      * possibly-truncated output length */
    return true;
}

static void ssh_dissect(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto,
                         struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t line_end = ssh_find_line_end(payload, len);
    size_t banner_len = line_end < 255 ? line_end : 255;
    if (banner_len > len) banner_len = len;

    char banner[256];
    memcpy(banner, payload, banner_len);
    banner[banner_len] = '\0';
    dissect_result_add(out, "ssh_identification_string", banner);

    /* Parse "SSH-2.0-OpenSSH_8.9p1" style string for protocol version
     * and software identifier — bounds-checked token extraction, no
     * assumption the format is exactly as expected. */
    if (banner_len >= 4 && memcmp(banner, "SSH-", 4) == 0) {
        char *p = banner + 4;
        char *dash = strchr(p, '-');
        if (dash) {
            *dash = '\0';
            dissect_result_add(out, "ssh_protocol_version", p);
            char *software = dash + 1;
            char *space = strchr(software, ' ');
            if (space) *space = '\0';
            dissect_result_add(out, "ssh_software_version", software);
        }
    }

    /* KEXINIT may or may not be in the SAME packet as the banner
     * (implementations vary). If there's nothing after the banner's
     * line terminator in this buffer, that's normal, not an error. */
    size_t after_banner = line_end + 2;   /* assumes CRLF; if bare LF this
                                            * over-advances by one byte,
                                            * tolerated by the length
                                            * checks immediately below
                                            * rather than assumed exact */
    if (after_banner >= len) {
        dissect_result_add(out, "ssh_kexinit_present", "false");
        return;
    }

    const uint8_t *pkt = payload + after_banner;
    size_t pkt_len = len - after_banner;
    if (pkt_len < 6) {
        dissect_result_add(out, "ssh_kexinit_present", "false");
        return;
    }

    uint32_t packet_length = (pkt[0]<<24)|(pkt[1]<<16)|(pkt[2]<<8)|pkt[3];
    uint8_t padding_length = pkt[4];
    if (packet_length < (uint32_t)(1 + padding_length) || (size_t)4 + packet_length > pkt_len) {
        dissect_result_add(out, "parse_warning", "invalid_kexinit_packet_length");
        return;
    }

    uint8_t msg_code = pkt[5];
    if (msg_code != SSH_MSG_KEXINIT) {
        dissect_result_add(out, "ssh_kexinit_present", "false");
        return;
    }

    dissect_result_add(out, "ssh_kexinit_present", "true");

    size_t pos = 6 + 16;   /* past packet header + message code + 16-byte cookie */
    const char *namelist_fields[] = {
        "ssh_kex_algorithms", "ssh_server_host_key_algorithms",
        "ssh_encryption_algorithms_client_to_server",
        "ssh_encryption_algorithms_server_to_client",
        "ssh_mac_algorithms_client_to_server", "ssh_mac_algorithms_server_to_client",
        "ssh_compression_algorithms_client_to_server", "ssh_compression_algorithms_server_to_client"
    };
    /* RFC 4253 §7.1 defines 10 name-lists total; extracting the first
     * 8 (the ones most useful for fingerprinting) rather than all 10 —
     * the languages_client_to_server/server_to_client lists are almost
     * always empty in practice and add little value. */
    char namelist_buf[SSH_MAX_NAMELIST_OUT];
    for (size_t i = 0; i < sizeof(namelist_fields) / sizeof(namelist_fields[0]); i++) {
        size_t consumed;
        if (!ssh_read_namelist(pkt, pkt_len, pos, namelist_buf, sizeof(namelist_buf), &consumed)) {
            dissect_result_add(out, "parse_warning", "truncated_kexinit_namelist");
            return;
        }
        dissect_result_add(out, namelist_fields[i], namelist_buf);
        pos += consumed;
    }
}

static const uint16_t ssh_hint_ports[] = { SSH_PORT };

void register_ssh_dissector(void) {
    register_dissector("SSH", ssh_detect, ssh_dissect, ssh_hint_ports, 1);
}
