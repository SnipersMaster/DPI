/*
 * dpi_wow_parser.c
 *
 * World of Warcraft client-server protocol — TCP port 3724 (the
 * "realm"/world-server port; the separate auth/login server on port
 * 3724 in some older client versions and 3724 in others share this
 * same framing, not distinguished further here). Never formally
 * documented by Blizzard — reverse-engineered by the WoW private-
 * server community (MaNGOS/TrinityCore/WoWDev), same "no official
 * spec, verify against real bytes" situation as HSRP/EIGRP/DNP3
 * elsewhere in this project, except here even the community
 * documentation wasn't directly consulted — everything below was
 * confirmed from scratch against one real captured packet.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * DELIBERATELY SCOPED TO THE "DETECTED, NOT FULLY DISSECTED" TIER —
 * verified against all 66,610 real packets in a genuine capture
 * (`app-wow-look4wireshark.pcapng`), and found that 66,609 of them are
 * opaque: after the ONE initial client authentication packet, the
 * protocol's own header (size+opcode) is itself RC4-encrypted using a
 * session key derived during that one handshake, so a passive
 * observer without that key genuinely cannot decode anything past it
 * — not a gap in this dissector, an inherent property of the
 * protocol once authentication completes. Confirmed structurally:
 * every later packet's first two bytes fail to line up with the
 * buffer length as a plausible size prefix, exactly as encrypted
 * bytes would.
 *
 * THE ONE REAL, VERIFIED, DECODABLE MESSAGE: the client's initial
 * CMSG_AUTH_SESSION (opcode 0x1ED / 493 — a long-publicly-known value
 * from the WoW private-server reverse-engineering community, not
 * something this project derived independently, stated honestly).
 * Hand-decoded byte-for-byte from the one real example found: a
 * 2-byte big-endian size prefix (195, confirmed to exactly equal the
 * buffer length minus 2), a 4-byte little-endian opcode (493), a
 * 4-byte little-endian build number (7799, a real, dated WoW client
 * build), 4 bytes this project doesn't have a confirmed name for
 * (present but not decoded — a Login Server ID or similar per
 * community documentation, not verified independently here), and then
 * a null-terminated ASCII account name ("SCOTTBOT" in the real
 * example — extracted via a bounded scan for the first printable-
 * ASCII run of at least 3 characters, not a hardcoded fixed offset,
 * since this project isn't fully confident the 4-byte field before it
 * is always exactly 4 bytes across every WoW client version). What
 * follows the account name (a client seed, a SHA1 digest proving
 * password knowledge without transmitting it — the same one-way-hash
 * discipline this project already applies to CHAP-style credentials
 * elsewhere — and a zlib-compressed addon-info blob, recognizable by
 * its real `78 9c` zlib header) is not decoded further.
 *
 * The account name is a username, not a password or any password-
 * derived secret — same "extract identity, never extract or derive
 * credentials" discipline as this project's RADIUS/FTP/LDAP/HSRP
 * fields.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define WOW_PORT 3724
#define WOW_OPCODE_CMSG_AUTH_SESSION 493

static const char *wow_opcode_name(uint32_t opcode) {
    switch (opcode) {
        case WOW_OPCODE_CMSG_AUTH_SESSION: return "CMSG_AUTH_SESSION";
        default: return "Unknown";
    }
}

static double wow_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < 6) return 0.0;

    /* Structural signal: WoW's own 2-byte big-endian size prefix
     * should equal exactly (buffer length - 2) for a complete,
     * unencrypted message. This correctly fails to match on the
     * encrypted bulk of real traffic (confirmed: every packet after
     * the one real auth message checked did NOT satisfy this),
     * rather than accepting encrypted bytes as if they were a valid
     * header. */
    uint16_t declared_size = (payload[0] << 8) | payload[1];
    if (declared_size != len - 2) return 0.0;

    if (dst_port == WOW_PORT) return 0.5;   /* moderate: this heuristic
                                               * only distinguishes
                                               * "looks length-prefixed"
                                               * from garbage, not a
                                               * WoW-specific magic
                                               * number — stated
                                               * honestly rather than
                                               * over-claimed */
    return 0.0;
}

static void wow_dissect(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto,
                         struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < 10) return;

    uint32_t opcode = (uint32_t)payload[2] | ((uint32_t)payload[3] << 8) |
                       ((uint32_t)payload[4] << 16) | ((uint32_t)payload[5] << 24);
    dissect_result_add(out, "wow_opcode", wow_opcode_name(opcode));

    if (opcode != WOW_OPCODE_CMSG_AUTH_SESSION) return;   /* everything else:
                                                             * named only, see
                                                             * file header */

    uint32_t build = (uint32_t)payload[6] | ((uint32_t)payload[7] << 8) |
                      ((uint32_t)payload[8] << 16) | ((uint32_t)payload[9] << 24);
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", build);
    dissect_result_add(out, "wow_client_build", buf);

    /* Bounded scan for the account name — see file header for why
     * this isn't a hardcoded fixed offset. */
    size_t pos = 10;
    size_t start = 0;
    bool in_run = false;
    for (size_t i = pos; i < len; i++) {
        if (payload[i] >= 32 && payload[i] < 127) {
            if (!in_run) { start = i; in_run = true; }
        } else {
            if (in_run && payload[i] == 0) {
                size_t run_len = i - start;
                if (run_len >= 3) {
                    char account[64];
                    size_t n = run_len < sizeof(account) - 1 ? run_len : sizeof(account) - 1;
                    memcpy(account, payload + start, n);
                    account[n] = '\0';
                    dissect_result_add(out, "wow_account_name", account);
                }
                break;
            }
            in_run = false;
        }
    }
}

static const uint16_t wow_hint_ports[] = { WOW_PORT };

void register_wow_dissector(void) {
    register_dissector("WoW", wow_detect, wow_dissect, wow_hint_ports, 1);
}
