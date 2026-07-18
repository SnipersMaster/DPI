/*
 * dpi_vpn_detector.c
 *
 * VPN / tunnel traffic scoring. Unlike DGA detection (purely lexical),
 * this is mostly STRUCTURAL — several VPN protocols have a recognizable
 * packet shape on the wire even though the actual payload is encrypted
 * and unreadable. Combines protocol fingerprints, known ports, and the
 * SNI-based vpn_proxy category from domain_rules.ini into one score.
 *
 * NOT COMPILED/TESTED against live VPN traffic in this environment.
 * Validate the WireGuard/OpenVPN/IKE byte offsets below against real
 * captures (Wireshark on actual VPN sessions) before trusting them —
 * protocol version differences can shift field positions.
 *
 * -------------------------------------------------------------------
 * SIGNALS, IN ROUGH ORDER OF RELIABILITY
 * -------------------------------------------------------------------
 *   1. SNI match against a known VPN provider domain (from
 *      domain_rules.ini's [vpn_proxy] category) — highest confidence,
 *      but only works for commercial VPN apps that still leak SNI
 *      (many use obfuscation specifically to avoid this).
 *   2. WireGuard handshake message fingerprint — WireGuard's handshake
 *      messages have FIXED sizes and a type byte, defined precisely in
 *      the protocol (Donenfeld, "WireGuard: Next Generation Kernel
 *      Network Tunnel", 2017). This is a strong, low-false-positive
 *      signal — it's a specific wire format, not a byte-value guess.
 *   3. OpenVPN opcode detection — OpenVPN's packet header format (see
 *      the OpenVPN protocol documentation) encodes an opcode in the
 *      first byte's top 5 bits. Recognizable but a weaker signal than
 *      WireGuard since a stray byte can coincidentally match.
 *   4. IKE/ISAKMP header (IPsec key exchange, RFC 7296) — standard
 *      ports 500/4500, recognizable header structure.
 *   5. Known VPN port numbers alone (weakest signal — these ports can
 *      carry other traffic, and VPN traffic increasingly runs over 443
 *      specifically to blend in, which defeats this signal entirely).
 *   6. High-entropy payload on an atypical port with no recognizable
 *      protocol structure at all — the weakest, most speculative
 *      signal, included mainly to flag "something opaque is happening
 *      here" for human review, not as a confident VPN identification.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

/* ------------------------------------------------------------------
 * Signal 2: WireGuard handshake fingerprint.
 * Message types and EXACT fixed lengths per the WireGuard protocol:
 *   type 1 (initiation): 148 bytes
 *   type 2 (response):    92 bytes
 *   type 3 (cookie reply): 64 bytes
 *   type 4 (transport data): 16-byte header + variable encrypted payload,
 *     always a multiple of 16 bytes total (padded).
 * The fixed sizes for types 1-3 are what make this a strong signal —
 * a random UDP packet landing on exactly 148 bytes with byte[0]==1 and
 * three reserved zero bytes is very unlikely by chance.
 * ------------------------------------------------------------------ */
static double score_wireguard(const uint8_t *udp_payload, uint16_t len) {
    if (len < 4) return 0.0;

    uint8_t msg_type = udp_payload[0];
    bool reserved_zero = (udp_payload[1] == 0 && udp_payload[2] == 0 && udp_payload[3] == 0);

    if (!reserved_zero) return 0.0;   /* WireGuard always zeroes these 3 bytes */

    if (msg_type == 1 && len == 148) return 0.95;   /* handshake initiation */
    if (msg_type == 2 && len == 92)  return 0.95;   /* handshake response */
    if (msg_type == 3 && len == 64)  return 0.85;   /* cookie reply */
    if (msg_type == 4 && len >= 32 && (len % 16) == 0) return 0.4;
        /* transport data: type+reserved+16-byte header pattern is
         * plausible but far weaker alone — could coincide by chance
         * more easily than the fixed-size handshake messages */

    return 0.0;
}

/* ------------------------------------------------------------------
 * Signal 3: OpenVPN opcode detection.
 * First byte: top 5 bits = opcode, bottom 3 bits = key ID.
 * Opcodes 1-9 are defined control/data message types in the OpenVPN
 * wire protocol. This alone is a WEAK signal (1 byte, 5 meaningful
 * bits — real collision risk), so it's scored lower and really should
 * be corroborated by seeing a consistent opcode sequence across
 * several packets in the same flow (a proper implementation would
 * track this per-flow; this function scores a single packet only).
 * ------------------------------------------------------------------ */
static double score_openvpn(const uint8_t *payload, uint16_t len) {
    if (len < 1) return 0.0;

    uint8_t opcode = payload[0] >> 3;
    if (opcode >= 1 && opcode <= 9) {
        return 0.3;   /* weak single-packet signal, see note above */
    }
    return 0.0;
}

/* ------------------------------------------------------------------
 * Signal 4: IKE/ISAKMP header (IPsec key exchange, RFC 7296 S3.1).
 * Initiator SPI (8 bytes) + Responder SPI (8 bytes) + next payload (1)
 * + version (1) + exchange type (1) + flags (1) + message ID (4) +
 * length (4) = 28-byte fixed header. On port 4500 (NAT-T) there's a
 * 4-byte zero "non-ESP marker" before this header.
 * ------------------------------------------------------------------ */
static double score_ike(const uint8_t *payload, uint16_t len, uint16_t dst_port) {
    const uint8_t *hdr = payload;
    uint16_t remaining = len;

    if (dst_port == 4500) {
        if (len < 4) return 0.0;
        bool non_esp_marker = (payload[0]==0 && payload[1]==0 && payload[2]==0 && payload[3]==0);
        if (!non_esp_marker) return 0.0;   /* on 4500, real ESP traffic has no marker */
        hdr = payload + 4;
        remaining = len - 4;
    }

    if (remaining < 28) return 0.0;

    uint8_t version = hdr[17];
    uint8_t major = version >> 4, minor = version & 0x0F;
    /* IKEv1 is 1.0, IKEv2 is 2.0 — reject implausible values outright */
    if (!((major == 1 || major == 2) && minor == 0)) return 0.0;

    return (dst_port == 500 || dst_port == 4500) ? 0.7 : 0.3;
}

/* ------------------------------------------------------------------
 * Signal 5: known VPN port numbers. Weak alone — listed for
 * completeness and as a fallback contributor, not a standalone trigger.
 * ------------------------------------------------------------------ */
static double score_known_port(uint16_t dst_port, const char *l4_proto) {
    bool is_udp = (strcmp(l4_proto, "UDP") == 0);

    if (is_udp && dst_port == 51820) return 0.5;   /* WireGuard default */
    if (is_udp && dst_port == 1194)  return 0.4;   /* OpenVPN default (UDP mode) */
    if (!is_udp && dst_port == 1194) return 0.4;   /* OpenVPN default (TCP mode) */
    if (is_udp && (dst_port == 500 || dst_port == 4500)) return 0.3;  /* IKE — see score_ike for the real signal */
    if (!is_udp && dst_port == 1723) return 0.5;   /* PPTP */
    if (is_udp && dst_port == 1701)  return 0.3;   /* L2TP */
    return 0.0;
}

/* ------------------------------------------------------------------
 * Signal 6: entropy fallback for unrecognized-but-opaque traffic on
 * an atypical port. Deliberately capped low — this catches "something
 * encrypted and non-standard is happening" far more often than it
 * catches an actual VPN, since plenty of legitimate traffic (QUIC,
 * proprietary app protocols, already-compressed data) looks the same
 * way. Reuses the same entropy math as the DGA detector's Signal 1.
 * ------------------------------------------------------------------ */
static double shannon_entropy_bytes(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    int counts[256] = {0};
    for (size_t i = 0; i < len; i++) counts[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / (double)len;
        entropy -= p * log2(p);
    }
    return entropy / 8.0;   /* normalize against 8 bits/byte ceiling */
}

static double score_entropy_fallback(const uint8_t *payload, uint16_t len, uint16_t dst_port) {
    /* Skip well-known ports where high entropy is expected and normal
     * (443 = TLS application data is supposed to look random). This
     * signal is only meaningful on UNUSUAL ports. */
    if (dst_port == 443 || dst_port == 80 || dst_port == 53) return 0.0;
    if (len < 64) return 0.0;   /* too little data to estimate entropy meaningfully */

    double e = shannon_entropy_bytes(payload, len);
    if (e > 0.97) return 0.25;   /* capped low deliberately, see note above */
    return 0.0;
}

/* ------------------------------------------------------------------
 * Combined result.
 * ------------------------------------------------------------------ */
struct vpn_result {
    double      score;          /* 0.0 (not VPN-like) to 1.0 (very VPN-like) */
    const char *verdict;        /* "low" | "medium" | "high" */
    const char *detected_protocol;  /* "wireguard" | "openvpn" | "ike" | "unknown" | "none" */
    bool        sni_matched_known_vpn_provider;
};

/*
 * score_vpn_traffic — call this per-flow, on the first payload-bearing
 * packet(s). `l4_payload` is the UDP/TCP payload (post IP/TCP-UDP
 * header, i.e. what dpi_rfc_parser.c hands off).
 *
 * `sni_category` should be the category string already resolved by
 * dpi_app_classifier.c / dpi_domain_rules_loader.c for this flow (pass
 * NULL if no SNI was seen) — this function does not re-do SNI
 * extraction, it just folds in the classification you already have.
 */
static void score_vpn_traffic(const uint8_t *l4_payload, uint16_t payload_len,
                               uint16_t dst_port, const char *l4_proto,
                               const char *sni_category,
                               struct vpn_result *out) {
    memset(out, 0, sizeof(*out));

    double best = 0.0;
    const char *best_proto = "none";

    double wg = score_wireguard(l4_payload, payload_len);
    if (wg > best) { best = wg; best_proto = "wireguard"; }

    double ovpn = score_openvpn(l4_payload, payload_len);
    if (ovpn > best) { best = ovpn; best_proto = "openvpn"; }

    double ike = score_ike(l4_payload, payload_len, dst_port);
    if (ike > best) { best = ike; best_proto = "ike"; }

    double port_signal = score_known_port(dst_port, l4_proto);
    /* Port signal contributes additively but capped, rather than
     * replacing a stronger structural match — a WireGuard-shaped
     * packet on the WireGuard port is more confident than either
     * signal alone, but we don't want the port alone to dominate. */
    double combined_structural = best + (port_signal * 0.3);
    if (combined_structural > best) best = combined_structural;

    double entropy_fallback = score_entropy_fallback(l4_payload, payload_len, dst_port);
    if (best == 0.0 && entropy_fallback > 0.0) {
        best = entropy_fallback;
        best_proto = "unknown";
    }

    if (sni_category && strcmp(sni_category, "vpn_proxy") == 0) {
        out->sni_matched_known_vpn_provider = true;
        best = best > 0.9 ? best : 0.9;   /* known commercial VPN provider domain: high confidence */
        if (strcmp(best_proto, "none") == 0) best_proto = "commercial_vpn_app";
    }

    if (best > 1.0) best = 1.0;
    out->score = best;
    out->detected_protocol = best_proto;

    if (best >= 0.7)      out->verdict = "high";
    else if (best >= 0.35) out->verdict = "medium";
    else                    out->verdict = "low";
}
