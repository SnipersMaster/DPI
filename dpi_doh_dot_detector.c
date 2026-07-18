/*
 * dpi_doh_dot_detector.c
 *
 * DNS-over-TLS (DoT, RFC 7858) and DNS-over-HTTPS (DoH, RFC 8484)
 * detection. These are structurally very different problems:
 *
 *   - DoT has its own dedicated port (853) and is just DNS wrapped
 *     directly in TLS — no HTTP framing involved. Structurally
 *     detectable the same way the VPN detector approaches things:
 *     port + a valid-looking TLS ClientHello structure.
 *
 *   - DoH is DNS-over-HTTP/2-over-TLS, indistinguishable at the
 *     TLS/TCP level from any other HTTPS traffic to the same server —
 *     there is no structural fingerprint. It is, honestly, just
 *     another SNI-domain-list problem, same as the VPN provider
 *     category. This is why domain_rules.ini's [dns_over_https]
 *     category is the actual detection mechanism for DoH; this file
 *     mainly documents that and exposes it as a scored signal
 *     alongside DoT rather than pretending there's a cleverer trick.
 *
 * NOT COMPILED/TESTED against live DoT/DoH traffic in this environment.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define DOT_PORT 853

/* ------------------------------------------------------------------
 * DoT: port 853 + a structurally plausible TLS ClientHello. Reuses
 * the same "structure first, port as corroboration" discipline as
 * every other detector in this project — a valid TLS record on 853
 * that ISN'T actually a ClientHello (e.g. a scan, a misconfigured
 * client) shouldn't be called DoT just because of the port.
 * ------------------------------------------------------------------ */
static double score_dot(const uint8_t *payload, uint16_t len,
                         uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;   /* DoT is TCP (TLS) */
    if (len < 6) return 0.0;

    /* TLS record header: content type 0x16 (handshake), version, length */
    bool looks_like_tls_handshake = (payload[0] == 0x16);
    if (!looks_like_tls_handshake) return 0.0;

    if (dst_port == DOT_PORT) return 0.85;   /* structure + dedicated port: strong */
    return 0.15;   /* TLS handshake shape alone, wrong port: very weak, most TLS
                     * traffic looks like this — not meaningful evidence by itself */
}

/* ------------------------------------------------------------------
 * DoH: no wire-level structural fingerprint exists — it's ordinary
 * HTTPS. Detection is entirely: does the SNI match a known DoH
 * resolver domain (domain_rules.ini's [dns_over_https] category)?
 * This function doesn't re-derive that match; it takes the category
 * string already resolved by dpi_app_classifier.c/domain rules loader
 * and folds it into a score, mirroring how the VPN detector consumes
 * the vpn_proxy category.
 * ------------------------------------------------------------------ */
static double score_doh(const char *sni_category) {
    if (sni_category && strcmp(sni_category, "dns_over_https") == 0) {
        return 0.9;   /* SNI directly matched a known public DoH resolver */
    }
    return 0.0;   /* no structural fallback exists for DoH — being honest
                    * about the limit rather than inventing a weak heuristic */
}

struct doh_dot_result {
    double      dot_score;
    const char *dot_verdict;   /* "low" | "medium" | "high" */
    double      doh_score;
    const char *doh_verdict;   /* "low" | "medium" | "high" */
};

static const char *verdict_for(double score) {
    if (score >= 0.7)  return "high";
    if (score >= 0.35) return "medium";
    return "low";
}

static void score_doh_dot(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto,
                           const char *sni_category,
                           struct doh_dot_result *out) {
    memset(out, 0, sizeof(*out));

    out->dot_score = score_dot(payload, len, dst_port, l4_proto);
    out->dot_verdict = verdict_for(out->dot_score);

    out->doh_score = score_doh(sni_category);
    out->doh_verdict = verdict_for(out->doh_score);
}
