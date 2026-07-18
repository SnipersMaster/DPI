/*
 * dpi_app_classifier.c
 *
 * Application-category classification layer. Sits on top of the TCP
 * payload produced by dpi_rfc_parser.c — takes the first segment(s) of
 * a new TCP flow on port 443 (or wherever your policy says to look),
 * looks for a TLS ClientHello, extracts the SNI, and classifies it
 * against a domain->category table. Falls back to JA3 when SNI is
 * unavailable (e.g. Encrypted Client Hello).
 *
 * NOT COMPILED/TESTED against live traffic in this environment — same
 * caveat as the earlier files. Validate against real ClientHello
 * captures from your lab before trusting classification output.
 *
 * -------------------------------------------------------------------
 * SPEC REFERENCES
 * -------------------------------------------------------------------
 *   RFC 8446 S4.1.2  — Handshake message structure, ClientHello layout
 *   RFC 6066 S3       — server_name extension (SNI) format
 *   JA3 is NOT an RFC. It's a de facto community convention (Salesforce
 *   engineering, 2017): MD5 of a specific ordered tuple of
 *   (TLSVersion, CipherSuites, Extensions, EllipticCurves, ECPointFormats).
 *   Treat JA3 matches as a heuristic signal, not a standards-guaranteed one.
 *
 * -------------------------------------------------------------------
 * IMPORTANT LIMITS OF THIS APPROACH — state these to whoever consumes
 * the classification output, don't let confidence get overstated:
 * -------------------------------------------------------------------
 *   1. Encrypted Client Hello (ECH) hides the SNI entirely. Where ECH
 *      is in use, this falls back to JA3-only, which identifies the
 *      TLS client library, NOT the destination service. Classification
 *      confidence must drop accordingly (see l7_confidence in the flow
 *      record) — don't silently guess.
 *   2. A single domain can host multiple app categories (e.g. a CDN
 *      domain shared across services) and a single app can span many
 *      domains (e.g. Instagram uses api.instagram.com, cdninstagram.com,
 *      scontent*.cdninstagram.com, etc.) — the category table needs
 *      wildcard/suffix matching and maintenance, not just exact strings.
 *   3. This is inherently a per-user traffic classification capability.
 *      Revisit the legal/privacy note from earlier before deploying
 *      this against traffic you don't have clear authority to monitor.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

/* Provides: struct classification_result, classify_hostname(),
 * reload_domain_rules_if_changed(). In a real build these would be
 * declared in a shared dpi_domain_rules.h and linked as a separate
 * .o rather than #included directly — kept as a single #include here
 * for simplicity since these are reference files, not a build system. */
#include "dpi_domain_rules_loader.c"

/* Provides: struct dga_result, score_dga(). */
#include "dpi_dga_detector.c"

/* Provides: struct vpn_result, score_vpn_traffic(). */
#include "dpi_vpn_detector.c"

#define MAX_SNI_LEN        256
#define MAX_CATEGORY_LEN   32
#define MAX_DOMAIN_RULES   1024

/* ------------------------------------------------------------------
 * Category table — no longer hardcoded here. Domain rules are loaded
 * from an external file (domain_rules.ini) at startup and reloaded
 * automatically whenever the file changes on disk, via
 * dpi_domain_rules_loader.c. #include that file (or link it as a
 * separate translation unit with a shared header) to get:
 *
 *   bool reload_domain_rules_if_changed(const char *path);
 *   void classify_hostname(const char *hostname,
 *                           struct classification_result *out);
 *
 * classify_hostname() below is now just a thin wrapper that calls
 * through to the loader's version, which reads from the live,
 * dynamically-sized rule table instead of a fixed array. Adding a new
 * app/category is now a config file edit, not a rebuild:
 *
 *   [social_media]
 *   newapp.com = New App
 *
 * See domain_rules.ini for the full sample and format documentation.
 * ------------------------------------------------------------------ */
#define DEFAULT_DOMAIN_RULES_PATH "/etc/dpi/domain_rules.ini"

/* ------------------------------------------------------------------
 * Minimal TLS record + handshake header structures (not the whole
 * ClientHello body, which is variable-length and walked manually).
 * ------------------------------------------------------------------ */
#define TLS_CONTENT_TYPE_HANDSHAKE  0x16
#define TLS_HANDSHAKE_CLIENT_HELLO  0x01
#define TLS_EXT_SERVER_NAME         0x0000
#define SNI_NAME_TYPE_HOSTNAME      0x00

struct sni_result {
    bool     found;
    char     hostname[MAX_SNI_LEN];
    uint16_t hostname_len;
};

/*
 * Walk a TLS ClientHello and extract the SNI, per RFC 8446 S4.1.2 for
 * the ClientHello structure and RFC 6066 S3 for the server_name
 * extension format. Every read is length-checked against `remaining`
 * before it happens — same discipline as the IPv4/TCP parser.
 */
static bool extract_sni(const uint8_t *data, size_t len, struct sni_result *out) {
    memset(out, 0, sizeof(*out));
    size_t pos = 0;

    /* TLS record header: type(1) + version(2) + length(2) */
    if (len < 5) return false;
    if (data[0] != TLS_CONTENT_TYPE_HANDSHAKE) return false;
    uint16_t record_len = (data[3] << 8) | data[4];
    pos = 5;
    if (pos + record_len > len) return false;  /* record claims more than we have */

    /* Handshake header: msg_type(1) + length(3) */
    if (pos + 4 > len) return false;
    if (data[pos] != TLS_HANDSHAKE_CLIENT_HELLO) return false;
    uint32_t hs_len = (data[pos+1] << 16) | (data[pos+2] << 8) | data[pos+3];
    pos += 4;
    size_t hs_end = pos + hs_len;
    if (hs_end > len) return false;

    /* ClientHello body: legacy_version(2) + random(32) +
     * session_id length(1) + session_id + cipher_suites length(2) +
     * cipher_suites + compression_methods length(1) + compression_methods +
     * extensions length(2) + extensions */
    if (pos + 2 + 32 + 1 > hs_end) return false;
    pos += 2 + 32;

    uint8_t session_id_len = data[pos];
    pos += 1;
    if (pos + session_id_len > hs_end) return false;
    pos += session_id_len;

    if (pos + 2 > hs_end) return false;
    uint16_t cipher_suites_len = (data[pos] << 8) | data[pos+1];
    pos += 2;
    if (pos + cipher_suites_len > hs_end) return false;
    pos += cipher_suites_len;

    if (pos + 1 > hs_end) return false;
    uint8_t compression_len = data[pos];
    pos += 1;
    if (pos + compression_len > hs_end) return false;
    pos += compression_len;

    if (pos + 2 > hs_end) return false;
    uint16_t extensions_len = (data[pos] << 8) | data[pos+1];
    pos += 2;
    size_t ext_end = pos + extensions_len;
    if (ext_end > hs_end) return false;

    /* Walk the extension list looking for server_name (type 0x0000). */
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos+1];
        uint16_t ext_len  = (data[pos+2] << 8) | data[pos+3];
        pos += 4;
        if (pos + ext_len > ext_end) return false;  /* malformed extension length */

        if (ext_type == TLS_EXT_SERVER_NAME) {
            /* server_name_list: length(2) + entries */
            size_t sp = pos;
            if (sp + 2 > pos + ext_len) return false;
            uint16_t list_len = (data[sp] << 8) | data[sp+1];
            sp += 2;
            if (sp + list_len > pos + ext_len) return false;

            if (sp + 3 <= pos + ext_len) {
                uint8_t name_type = data[sp];
                uint16_t name_len = (data[sp+1] << 8) | data[sp+2];
                sp += 3;
                if (name_type == SNI_NAME_TYPE_HOSTNAME &&
                    sp + name_len <= pos + ext_len &&
                    name_len < MAX_SNI_LEN) {
                    memcpy(out->hostname, data + sp, name_len);
                    out->hostname[name_len] = '\0';
                    out->hostname_len = name_len;
                    out->found = true;
                    return true;
                }
            }
        }
        pos += ext_len;
    }

    return false;  /* well-formed ClientHello, but no SNI present (e.g. ECH) */
}

/* Domain -> category classification now lives in
 * dpi_domain_rules_loader.c (classify_hostname + classification_result),
 * reading from the dynamically loaded, reloadable rule table. */

/* ------------------------------------------------------------------
 * Entry point: call this on the first payload-bearing segment(s) of a
 * new TCP flow on a TLS port. Returns classification with an explicit
 * confidence/method field so downstream consumers know how the result
 * was derived — never present a JA3-only guess with the same
 * confidence as a direct SNI match.
 * ------------------------------------------------------------------ */
enum classification_method {
    CLASSIFY_NONE,
    CLASSIFY_SNI,
    CLASSIFY_JA3_HEURISTIC,   /* stub — see note below */
};

struct app_classification {
    enum classification_method method;
    char sni[MAX_SNI_LEN];
    char category[MAX_SECTION_LEN];
    char app_name[MAX_APPNAME_LEN];
    const char *confidence;   /* "high" | "low" | "none" — fixed literals, fine as pointers */
    double dga_score;         /* 0.0 (human-like) to 1.0 (algorithmic-like) */
    const char *dga_verdict;  /* "low" | "medium" | "high" */
    double vpn_score;         /* 0.0 (not VPN-like) to 1.0 (very VPN-like) */
    const char *vpn_verdict;  /* "low" | "medium" | "high" */
    const char *vpn_protocol; /* "wireguard" | "openvpn" | "ike" | "commercial_vpn_app" | "unknown" | "none" */
};

/*
 * classify_flow — now takes dst_port and l4_proto ("TCP"/"UDP") in
 * addition to the payload, since VPN detection needs to look at UDP
 * flows (WireGuard, IKE) and non-443 ports, not just TLS ClientHellos
 * on TCP/443 the way SNI/DGA scoring does. `l4_payload` is whatever
 * dpi_rfc_parser.c handed off for this flow — a TCP segment's payload
 * or (for a UDP-aware build) a UDP datagram's payload.
 */
static void classify_flow(const uint8_t *l4_payload, size_t payload_len,
                           uint16_t dst_port, const char *l4_proto,
                           struct app_classification *result) {
    memset(result, 0, sizeof(*result));

    struct sni_result sni;
    bool have_sni = extract_sni(l4_payload, payload_len, &sni) && sni.found;

    if (have_sni) {
        strncpy(result->sni, sni.hostname, MAX_SNI_LEN - 1);

        /* DGA scoring runs on every extracted SNI regardless of whether
         * it matches a known app — a malware C2 domain won't be in the
         * category table, that's exactly the case this is meant to
         * catch. Scoring a known-good domain like "instagram.com" is
         * cheap and just confirms a low score, which is fine. */
        struct dga_result dga;
        score_dga(sni.hostname, &dga);
        result->dga_score = dga.score;
        result->dga_verdict = dga.verdict;

        struct classification_result cls;
        classify_hostname(sni.hostname, &cls);   /* reads the live, reloadable table */
        if (cls.matched) {
            result->method = CLASSIFY_SNI;
            strncpy(result->category, cls.category, MAX_SECTION_LEN - 1);
            strncpy(result->app_name, cls.app_name, MAX_APPNAME_LEN - 1);
            result->confidence = "high";
        } else {
            result->method = CLASSIFY_SNI;
            strncpy(result->category, "unclassified", MAX_SECTION_LEN - 1);
            result->confidence = "low";  /* SNI seen, but not in our table yet */
        }
    } else {
        /* No SNI found — likely ECH, UDP traffic (WireGuard/IKE never
         * present a TLS ClientHello at all), or not a ClientHello. A
         * real implementation would compute JA3 here as a fallback for
         * the TCP/TLS case. */
        result->method = CLASSIFY_NONE;
        strncpy(result->category, "unknown", MAX_SECTION_LEN - 1);
        result->confidence = "none";
        result->dga_score = 0.0;
        result->dga_verdict = "low";   /* no SNI to score — not itself suspicious, just opaque */
    }

    /* VPN scoring runs regardless of SNI outcome — this is the whole
     * point: WireGuard/IKE traffic never has a TLS ClientHello to find
     * an SNI in, so it would otherwise fall through as "unknown" with
     * no further signal. Feed in the resolved category so a commercial
     * VPN provider's domain (matched via domain_rules.ini's
     * [vpn_proxy] section) folds into the same score. */
    struct vpn_result vpn;
    score_vpn_traffic(l4_payload, (uint16_t)payload_len, dst_port, l4_proto,
                       have_sni ? result->category : NULL, &vpn);
    result->vpn_score = vpn.score;
    result->vpn_verdict = vpn.verdict;
    result->vpn_protocol = vpn.detected_protocol;
}

/*
 * Call once at startup and periodically thereafter (e.g. every 1-5s
 * from a management thread) so config edits to domain_rules.ini take
 * effect without a rebuild or restart:
 *
 *   reload_domain_rules_if_changed(DEFAULT_DOMAIN_RULES_PATH);
 */
