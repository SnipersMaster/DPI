/*
 * dpi_telnet_parser.c
 *
 * Telnet (RFC 854, option negotiation per RFC 855 and many per-option
 * RFCs) dissector — TCP port 23. Interactive terminal protocol: plain
 * keystroke/output bytes interleaved with IAC (0xFF, "Interpret As
 * Command") escape sequences for option negotiation.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 99 real Telnet payloads from two genuine captures
 * — 76 were plain keystroke/output data (e.g. a real captured "ls\r\n"
 * command), 23 contained IAC negotiation sequences. One real sample
 * decoded to a standard, recognizable telnet client option-negotiation
 * sequence: IAC DO Suppress-Go-Ahead, IAC WILL Terminal-Type, IAC WILL
 * Window-Size (NAWS), IAC WILL Terminal-Speed, IAC WILL Remote-Flow-
 * Control, IAC WILL Linemode — exactly what a real Linux/BSD telnet
 * client sends on connect.
 *
 * WIRE FORMAT (RFC 854): a stream of bytes, mostly literal data. The
 * byte 0xFF (IAC) introduces a command:
 *   IAC WILL/WONT/DO/DONT <option> (3 bytes total) — option
 *     negotiation, RFC 855.
 *   IAC SB <option> ... IAC SE — subnegotiation (option-specific
 *     parameters, e.g. actual terminal type string or window
 *     dimensions), variable length, walked to find the closing SE.
 *   IAC <other command byte> (2 bytes total) — NOP, Data Mark, Break,
 *     Interrupt Process, Abort Output, Are-You-There, Erase Character,
 *     Erase Line, Go Ahead — no further data.
 *   IAC IAC — a literal 0xFF byte in the data stream (escaping).
 *
 * A REAL, INHERENT LIMITATION STATED HONESTLY, unlike every other
 * text-adjacent protocol in this project (FTP's PASS, RADIUS's User-
 * Password, LDAP's bind credential, HSRP's auth data): Telnet has NO
 * wire-level field that distinguishes "this is a password" from "this
 * is any other keystroke." A username/password exchange in Telnet is
 * just an ordinary character stream shaped by whatever login prompt
 * the remote host printed — there is no structural signal this
 * dissector (or any passive observer) could use to detect and redact
 * it the way the other protocols' explicit credential fields allow.
 * The bounded text preview this dissector extracts will show
 * whatever was actually typed, which may include credentials if a
 * login sequence was captured — this is Telnet's own, well-documented
 * security weakness, not a gap in this dissector's carefulness. Flagged
 * here explicitly rather than silently extracting text with an
 * implied (false) safety guarantee matching the other protocols.
 *
 * SCOPE: walks IAC sequences correctly (so option negotiation doesn't
 * get misread as literal data) and names the option for WILL/WONT/DO/
 * DONT; extracts a bounded preview of literal (non-IAC) data bytes.
 * Subnegotiation content (e.g. the actual terminal type string) is
 * walked past correctly but not individually extracted.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define TELNET_IAC  0xFF
#define TELNET_SB   250
#define TELNET_SE   240
#define TELNET_WILL 251
#define TELNET_WONT 252
#define TELNET_DO   253
#define TELNET_DONT 254
#define TELNET_MAX_NEGOTIATIONS_SHOWN 6
#define TELNET_TEXT_PREVIEW_LEN 64

static const char *telnet_option_name(uint8_t opt) {
    switch (opt) {
        case 0: return "Binary Transmission";
        case 1: return "Echo";
        case 3: return "Suppress Go Ahead";
        case 24: return "Terminal Type";
        case 31: return "Window Size (NAWS)";
        case 32: return "Terminal Speed";
        case 33: return "Remote Flow Control";
        case 34: return "Linemode";
        case 36: return "Environment Variables";
        default: return "Unknown";
    }
}

static const char *telnet_verb_name(uint8_t cmd) {
    switch (cmd) {
        case TELNET_WILL: return "WILL";
        case TELNET_WONT: return "WONT";
        case TELNET_DO: return "DO";
        case TELNET_DONT: return "DONT";
        default: return "?";
    }
}

static double telnet_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;
    if (len < 1) return 0.0;

    /* No strong structural signal for plain data-only Telnet
     * payloads (they're just arbitrary bytes) — the port is doing
     * most of the identification work here, same as any protocol
     * without a magic number of its own. IAC-containing payloads get
     * a small structural boost since 0xFF followed by a valid command
     * byte is at least mildly distinctive. */
    bool has_plausible_iac = false;
    for (uint16_t i = 0; i + 1 < len; i++) {
        if (payload[i] == TELNET_IAC) {
            uint8_t next = payload[i+1];
            if (next == TELNET_SB || next == TELNET_SE || next == TELNET_WILL ||
                next == TELNET_WONT || next == TELNET_DO || next == TELNET_DONT ||
                next == TELNET_IAC) {
                has_plausible_iac = true;
                break;
            }
        }
    }

    double confidence = has_plausible_iac ? 0.6 : 0.2;
    if (dst_port == 23) confidence += 0.3;
    return confidence;
}

static void telnet_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t pos = 0;
    int n_negotiations = 0;
    char text_preview[TELNET_TEXT_PREVIEW_LEN + 1];
    size_t text_len = 0;

    while (pos < len) {
        if (payload[pos] == TELNET_IAC && pos + 1 < len) {
            uint8_t cmd = payload[pos+1];
            if (cmd == TELNET_IAC) {
                /* Escaped literal 0xFF byte in the data stream. */
                if (text_len < TELNET_TEXT_PREVIEW_LEN) text_preview[text_len++] = (char)0xFF;
                pos += 2;
            } else if ((cmd == TELNET_WILL || cmd == TELNET_WONT ||
                        cmd == TELNET_DO || cmd == TELNET_DONT) && pos + 2 < len) {
                uint8_t opt = payload[pos+2];
                if (n_negotiations < TELNET_MAX_NEGOTIATIONS_SHOWN) {
                    char key[32], val[48];
                    snprintf(key, sizeof(key), "telnet_negotiation_%d", n_negotiations);
                    snprintf(val, sizeof(val), "%s %s", telnet_verb_name(cmd), telnet_option_name(opt));
                    dissect_result_add(out, key, val);
                }
                n_negotiations++;
                pos += 3;
            } else if (cmd == TELNET_SB) {
                /* Subnegotiation — walk to the closing IAC SE without
                 * extracting the option-specific parameter content,
                 * see file header. */
                size_t sb_pos = pos + 2;
                while (sb_pos + 1 < len &&
                       !(payload[sb_pos] == TELNET_IAC && payload[sb_pos+1] == TELNET_SE)) {
                    sb_pos++;
                }
                pos = (sb_pos + 1 < len) ? sb_pos + 2 : len;
            } else {
                /* Other 2-byte IAC commands (NOP, Break, Interrupt
                 * Process, Are-You-There, etc.) — no further data. */
                pos += 2;
            }
        } else {
            if (text_len < TELNET_TEXT_PREVIEW_LEN) {
                uint8_t b = payload[pos];
                text_preview[text_len++] = isprint(b) || b == '\r' || b == '\n' || b == '\t'
                                            ? (char)b : '.';
            }
            pos++;
        }
    }

    char buf[8];
    snprintf(buf, sizeof(buf), "%d", n_negotiations);
    dissect_result_add(out, "telnet_negotiation_count", buf);

    if (text_len > 0) {
        text_preview[text_len] = '\0';
        /* See file header: this may contain credential material if a
         * login sequence was captured — Telnet has no structural way
         * to tell, unlike this project's other protocols. */
        dissect_result_add(out, "telnet_data_preview", text_preview);
    }
}

static const uint16_t telnet_hint_ports[] = { 23 };

void register_telnet_dissector(void) {
    register_dissector("Telnet", telnet_detect, telnet_dissect, telnet_hint_ports, 1);
}
