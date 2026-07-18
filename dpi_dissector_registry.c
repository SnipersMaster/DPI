/*
 * dpi_dissector_registry.c
 *
 * The actual answer to "support all protocols": a pluggable registry,
 * not one growing function. Every protocol dissector added to this
 * engine is a self-contained module implementing this interface:
 *
 *   1. detect()  — does this payload look like protocol X? Port hints
 *                  are a starting point, not the ground truth (VPN
 *                  traffic on 443, RADIUS on a nonstandard port, etc.
 *                  are exactly why signature-based detection matters
 *                  more than port lookup alone).
 *   2. dissect()  — given a payload that detect() said matched, extract
 *                  the protocol-specific fields into a generic result.
 *
 * WHY THIS MATTERS FOR SECURITY (ties back to the very first checklist
 * in this conversation, "multi-protocol dissector risk"): every
 * dissector in this registry is independently fuzzable, independently
 * sandboxable, and a bug in one cannot corrupt another's state, because
 * each only ever touches its own local buffers and returns a
 * plain-old-data result struct — never a pointer into another
 * dissector's internals. Adding dissector #50 should not increase the
 * blast radius of a bug in dissector #12.
 *
 * NOT COMPILED/TESTED in this environment — this is an architecture
 * skeleton to build the real dissectors (dpi_radius_parser.c,
 * dpi_quic_parser.c, and future ones) against.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

/* Provides: load_protocol_config(), protocol_enabled() — the protocol
 * "arsenal" config. Included unconditionally (not gated by
 * DPI_SKIP_REGISTER_ALL) since it's small, self-contained, and doesn't
 * add meaningful build cost even for single-dissector fuzz harnesses
 * that don't call register_all_dissectors(). */
#include "dpi_protocol_config.c"

#define MAX_DISSECTORS      64
#define MAX_PROTOCOL_NAME   32
#define MAX_FIELD_KEY_LEN   32
#define MAX_FIELD_VAL_LEN   256
#define MAX_FIELDS_PER_RESULT 32

/* ------------------------------------------------------------------
 * Generic dissection result — deliberately protocol-agnostic so the
 * registry/dispatch layer doesn't need to know about every protocol's
 * specific struct shape. Each dissector fills in key/value fields;
 * the flow-record serializer (JSON output) just walks this generically.
 * ------------------------------------------------------------------ */
struct dissect_field {
    char key[MAX_FIELD_KEY_LEN];
    char value[MAX_FIELD_VAL_LEN];
};

struct dissect_result {
    bool     matched;
    char     protocol_name[MAX_PROTOCOL_NAME];
    int      n_fields;
    struct dissect_field fields[MAX_FIELDS_PER_RESULT];
};

static void dissect_result_add(struct dissect_result *r, const char *key, const char *val) {
    if (r->n_fields >= MAX_FIELDS_PER_RESULT) return;   /* silently cap, don't overflow */
    struct dissect_field *f = &r->fields[r->n_fields++];
    strncpy(f->key, key, MAX_FIELD_KEY_LEN - 1);
    strncpy(f->value, val, MAX_FIELD_VAL_LEN - 1);
}

/* Look up a field by key. Returns NULL if not present — e.g. QUIC's
 * dissector adds an "sni" field only when it actually found one (not
 * ECH, not a non-ClientHello handshake message); callers must handle
 * the NULL case rather than assume the field exists just because the
 * protocol matched. */
static const char *dissect_result_get(const struct dissect_result *r, const char *key) {
    for (int i = 0; i < r->n_fields; i++) {
        if (strcmp(r->fields[i].key, key) == 0) return r->fields[i].value;
    }
    return NULL;
}

/* ------------------------------------------------------------------
 * Dissector interface. Function pointers, not inheritance — this is C.
 *   detect():  payload, len, dst_port, l4_proto ("TCP"/"UDP") -> confidence 0.0-1.0
 *   dissect(): same inputs -> fills result. Only called if detect()
 *              returned above a threshold, but MUST still validate
 *              everything itself — never trust detect()'s confidence
 *              as a substitute for dissect()'s own bounds checking.
 *              This mirrors the "every dissector validates its own
 *              input" rule from the original security checklist.
 * ------------------------------------------------------------------ */
typedef double (*dissector_detect_fn)(const uint8_t *payload, uint16_t len,
                                       uint16_t dst_port, const char *l4_proto);
typedef void   (*dissector_dissect_fn)(const uint8_t *payload, uint16_t len,
                                        uint16_t dst_port, const char *l4_proto,
                                        struct dissect_result *out);

struct dissector {
    char                  name[MAX_PROTOCOL_NAME];
    dissector_detect_fn   detect;
    dissector_dissect_fn  dissect;
    /* Optional hint ports — used only to break ties between multiple
     * dissectors with similar detect() confidence, never as the sole
     * criterion. A dissector that ONLY checks dst_port in detect() is
     * doing it wrong — see dpi_radius_parser.c / dpi_quic_parser.c for
     * the pattern: structural validation first, port as a tiebreaker. */
    uint16_t              hint_ports[4];
    int                   n_hint_ports;
};

static struct dissector g_registry[MAX_DISSECTORS];
static int g_n_dissectors = 0;

static bool register_dissector(const char *name,
                                dissector_detect_fn detect,
                                dissector_dissect_fn dissect,
                                const uint16_t *hint_ports, int n_hint_ports) {
    if (g_n_dissectors >= MAX_DISSECTORS) {
        fprintf(stderr, "dissector_registry: full, cannot register '%s'\n", name);
        return false;
    }
    struct dissector *d = &g_registry[g_n_dissectors++];
    strncpy(d->name, name, MAX_PROTOCOL_NAME - 1);
    d->detect = detect;
    d->dissect = dissect;
    d->n_hint_ports = n_hint_ports > 4 ? 4 : n_hint_ports;
    for (int i = 0; i < d->n_hint_ports; i++) d->hint_ports[i] = hint_ports[i];
    return true;
}

/*
 * Dispatch: try every registered dissector's detect(), take the
 * highest-confidence match above a minimum threshold, run its
 * dissect(). O(n) over registered dissectors per flow — fine for
 * tens to low hundreds of protocols; if this ever becomes a hot-path
 * bottleneck at 100G with many dissectors registered, the port hints
 * can be used to build a port->candidate-dissector index and only
 * fall back to the full O(n) scan when no port hint matches (common
 * case: most traffic is on a small set of well-known ports).
 */
#define MIN_DETECT_CONFIDENCE 0.3

static bool dispatch_dissection(const uint8_t *payload, uint16_t len,
                                 uint16_t dst_port, const char *l4_proto,
                                 struct dissect_result *out) {
    memset(out, 0, sizeof(*out));

    struct dissector *best = NULL;
    double best_confidence = MIN_DETECT_CONFIDENCE;

    for (int i = 0; i < g_n_dissectors; i++) {
        struct dissector *d = &g_registry[i];
        double conf = d->detect(payload, len, dst_port, l4_proto);
        if (conf > best_confidence) {
            best_confidence = conf;
            best = d;
        }
    }

    if (!best) return false;   /* nothing matched confidently: leave as unclassified */

    best->dissect(payload, len, dst_port, l4_proto, out);
    out->matched = true;
    strncpy(out->protocol_name, best->name, MAX_PROTOCOL_NAME - 1);
    return true;
}

/*
 * Registration point — call once at startup, before the capture loop
 * begins. Each new protocol module (dpi_radius_parser.c,
 * dpi_quic_parser.c, and whatever comes after) exposes a
 * `register_<protocol>_dissector()` function that this calls.
 *
 * THIS is what "supporting all protocols" actually looks like in
 * practice: not one function that knows about everything, but a list
 * that grows by one line per protocol, each protocol's logic fully
 * contained in its own file, independently fuzzable and testable.
 */
/*
 * register_all_dissectors() is guarded behind this macro so that a
 * fuzz harness targeting ONE dissector in isolation (e.g.
 * fuzz_radius_parser.c) can include this registry file for
 * struct dissect_result / dissect_result_add() / register_dissector()
 * WITHOUT being forced to also link every other protocol module (and
 * their dependencies — QUIC alone pulls in OpenSSL) just to satisfy
 * this function's extern references to registration functions the
 * harness never calls. Define DPI_SKIP_REGISTER_ALL before including
 * this file to get that isolation; the real capture paths
 * (dpi_dpdk_worker.c, dpi_secure_bootstrap.c) do NOT define it, since
 * they genuinely need every dissector registered.
 *
 * This preserves the "each dissector is independently fuzzable"
 * design goal stated earlier in this file's own header comment —
 * without this guard, that goal was quietly broken by every fuzz
 * harness needing the full multi-protocol dependency graph just to
 * link, which defeats the point of testing one dissector in isolation.
 */
#ifndef DPI_SKIP_REGISTER_ALL
static void register_all_dissectors(void) {
    /* Load the protocol "arsenal" config once, before registering
     * anything — see dpi_protocol_config.c for why this is a
     * startup-time-only config, not hot-reloaded like domain_rules.ini. */
    load_protocol_config("protocols.ini");

    /* extern declarations for each protocol module's registration fn: */
    extern void register_radius_dissector(void);
    extern void register_quic_dissector(void);
    extern void register_gtp_dissector(void);
    extern void register_gtpv2_dissector(void);
    extern void register_dns_dissector(void);
    extern void register_http1_dissector(void);
    extern void register_http2_dissector(void);
    extern void register_ssh_dissector(void);
    extern void register_dhcp_dissector(void);
    extern void register_sip_dissector(void);
    extern void register_rtp_dissector(void);
    extern void register_icmp_dissector(void);
    extern void register_icmpv6_dissector(void);

    /* Each registration is now gated by the arsenal config — a
     * protocol disabled in protocols.ini is simply never registered,
     * rather than registered-and-ignored. This is the actual "modular,
     * one place to configure" behavior requested: register_all_
     * dissectors() itself doesn't need editing to turn a protocol on
     * or off anymore, protocols.ini does. */
    if (protocol_enabled("radius")) register_radius_dissector();
    if (protocol_enabled("quic"))   register_quic_dissector();
    if (protocol_enabled("gtp"))    register_gtp_dissector();
    if (protocol_enabled("gtpv2"))  register_gtpv2_dissector();
    if (protocol_enabled("dns"))    register_dns_dissector();
    if (protocol_enabled("http1"))  register_http1_dissector();
    if (protocol_enabled("http2"))  register_http2_dissector();
    if (protocol_enabled("ssh"))    register_ssh_dissector();
    if (protocol_enabled("dhcp"))   register_dhcp_dissector();
    if (protocol_enabled("sip"))    register_sip_dissector();
    if (protocol_enabled("rtp"))    register_rtp_dissector();
    if (protocol_enabled("icmp"))   register_icmp_dissector();
    if (protocol_enabled("icmpv6")) register_icmpv6_dissector();

    fprintf(stderr, "dissector_registry: %d protocol dissector(s) registered "
            "(per protocols.ini)\n", g_n_dissectors);
}
#endif /* DPI_SKIP_REGISTER_ALL */
