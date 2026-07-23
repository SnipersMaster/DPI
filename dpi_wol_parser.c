/*
 * dpi_wol_parser.c
 *
 * Wake-on-LAN "Magic Packet" dissector — EtherType 0x0842 (the raw-
 * Ethernet form; WoL can also be sent as a UDP broadcast to port 0, 7,
 * or 9 with the identical payload, but only the raw-Ethernet form was
 * found in real traffic for this project). Never formally RFC-
 * standardized — originally an AMD specification, now a de facto
 * industry standard.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against the one real Magic Packet found across every pcap
 * checked for this project — but rigorously: the 6-byte sync stream
 * was confirmed to be exactly 0xFF repeated, and the 96 bytes that
 * follow were confirmed PROGRAMMATICALLY (not just visually) to be
 * one target MAC address (`b8:27:eb:bc:cd:b4` — a real Raspberry Pi
 * Foundation OUI) repeated exactly 16 times with every repeat
 * matching, for a total of exactly 102 bytes — precisely RFC-
 * consistent with the Magic Packet spec's minimum size, not
 * approximately matching it.
 *
 * WIRE FORMAT: Synchronization Stream(6 bytes, all 0xFF) + Target MAC
 * Address repeated 16 times (96 bytes) [+ optional 4 or 6-byte
 * SecureOn password, not present in the real example checked]. This
 * dissector's whole "protocol" IS this one fixed-shape packet — there
 * is no session, no other message type, no request/response —
 * unlike every other protocol in this project, one real, fully
 * verified example genuinely does confirm the complete wire format,
 * not just a sample of a larger, more varied protocol.
 *
 * SCOPE: verifies the sync stream and all 16 MAC repeats match before
 * extracting the target MAC — this dissector will NOT report a MAC
 * from a malformed or truncated packet that merely happens to start
 * with 6 bytes of 0xFF, matching this project's general "verify the
 * whole structure, don't assume partial matches" discipline. The
 * optional SecureOn password suffix (if present) is flagged but not
 * extracted — it functions as a weak shared secret, same credential-
 * adjacent caution as this project's other password/credential
 * fields, even though it wasn't present in the real example checked.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define WOL_SYNC_LEN 6
#define WOL_MAC_LEN 6
#define WOL_MAC_REPEATS 16
#define WOL_MIN_LEN (WOL_SYNC_LEN + WOL_MAC_LEN * WOL_MAC_REPEATS)   /* 102 */

static double wol_detect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto) {
    (void)dst_port; (void)l4_proto;   /* identified by EtherType 0x0842
                                        * already at the capture path */
    if (len < WOL_MIN_LEN) return 0.0;

    for (int i = 0; i < WOL_SYNC_LEN; i++) {
        if (payload[i] != 0xFF) return 0.0;
    }
    const uint8_t *target_mac = payload + WOL_SYNC_LEN;
    for (int r = 0; r < WOL_MAC_REPEATS; r++) {
        const uint8_t *repeat = payload + WOL_SYNC_LEN + r * WOL_MAC_LEN;
        if (memcmp(repeat, target_mac, WOL_MAC_LEN) != 0) return 0.0;
    }
    return 0.95;   /* sync stream + all 16 MAC repeats verified — about
                     * as unambiguous a structural match as any
                     * dissector in this project gets */
}

static void wol_dissect(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto,
                         struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (wol_detect(payload, len, 0, "") <= 0.0) return;

    const uint8_t *mac = payload + WOL_SYNC_LEN;
    char macbuf[18];
    snprintf(macbuf, sizeof(macbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    dissect_result_add(out, "wol_target_mac", macbuf);

    size_t consumed = WOL_MIN_LEN;
    size_t trailing = len - consumed;
    if (trailing == 4 || trailing == 6) {
        dissect_result_add(out, "wol_secureon_password_present", "true");
        /* Never extracted — see file header. */
    }
}

static const uint16_t wol_hint_ports[] = { 0 };   /* no port concept, see file header */

void register_wol_dissector(void) {
    register_dissector("WoL", wol_detect, wol_dissect, wol_hint_ports, 0);
}
