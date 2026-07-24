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
#include <stdatomic.h>

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
    /* Runtime-mutable — see dissector_set_enabled() and
     * reload_protocol_config() below. Separate from "is this dissector
     * registered at all": every dissector is now registered
     * unconditionally at startup (see register_all_dissectors()), and
     * `enabled` is what protocols.ini actually controls. This is the
     * change that makes runtime toggling possible at all — a
     * dissector that was never added to g_registry in the first place
     * (the old behavior, when protocols.ini gated the registration
     * call itself) can't later be turned on without a restart, no
     * matter what flag you invent; only something already present in
     * the registry can be flipped on or off.
     *
     * _Atomic because dispatch_dissection() reads this from every
     * DPDK lcore concurrently on the hot path, while a config reload
     * (triggered by SIGUSR1, potentially from a different thread/
     * signal context — see reload_protocol_config() below) writes it.
     * A plain bool here would be the same class of data race already
     * found and fixed twice elsewhere in this project (the TCP flow
     * table, the IPv6 TCP deferred-packet counter) — not repeating
     * that mistake a third time. */
    _Atomic bool          enabled;
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
    d->enabled = true;   /* actual initial state is set by
                           * apply_protocol_config_to_registry() right
                           * after all registration calls complete —
                           * this default just means "on until told
                           * otherwise," consistent with
                           * dpi_protocol_config.c's own "a protocol not
                           * listed defaults to enabled" rule. */
    return true;
}

/*
 * Look up a registered dissector by its display name (e.g. "GTPv1-U",
 * not the protocols.ini config key "gtp" — those are deliberately
 * different strings, see the mapping table in
 * apply_protocol_config_to_registry() below) and set its enabled flag.
 * Returns false if no dissector with that name is registered — which,
 * since every dissector is now registered unconditionally at startup,
 * should only happen for a genuine typo, not a "disabled at startup"
 * dissector.
 */
static bool dissector_set_enabled(const char *name, bool enabled) {
    for (int i = 0; i < g_n_dissectors; i++) {
        if (strcmp(g_registry[i].name, name) == 0) {
            g_registry[i].enabled = enabled;
            return true;
        }
    }
    return false;
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
        if (!d->enabled) continue;   /* toggled off via protocols.ini + a
                                        reload — see reload_protocol_config() */
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
 * Maps each protocols.ini config key to the exact display name its
 * dissector registers under (these are deliberately different strings
 * — e.g. config key "gtp" vs. display name "GTPv1-U" — since the
 * config key is a short, stable identifier while the display name is
 * whatever's most readable in output). This table is the ONE place
 * that mapping lives; both the initial startup configuration and any
 * later reload use it, so they can never drift apart from each other.
 */
struct protocol_key_name_pair {
    const char *config_key;
    const char *display_name;
};

static const struct protocol_key_name_pair g_protocol_key_names[] = {
    { "radius", "RADIUS" },
    { "quic",   "QUIC" },
    { "gtp",    "GTPv1-U" },
    { "gtpv2",  "GTPv2-C" },
    { "dns",    "DNS" },
    { "http1",  "HTTP/1.1" },
    { "http2",  "HTTP/2" },
    { "ssh",    "SSH" },
    { "dhcp",   "DHCP" },
    { "sip",    "SIP" },
    { "rtp",    "RTP" },
    { "icmp",   "ICMP" },
    { "icmpv6", "ICMPv6" },
    { "smtp",   "SMTP" },
    { "arp",    "ARP" },
    { "mqtt",   "MQTT" },
    { "ntp",    "NTP" },
    { "snmp",   "SNMP" },
    { "stun",   "STUN" },
    { "modbus", "Modbus" },
    { "dnp3",   "DNP3" },
    { "gre",    "GRE" },
    { "mpls",   "MPLS" },
    { "ospf",   "OSPF" },
    { "bgp",    "BGP" },
    { "ldap",   "LDAP" },
    { "ftp",    "FTP" },
    { "igmp",   "IGMP" },
    { "rip",    "RIP" },
    { "ssdp",   "SSDP" },
    { "syslog", "Syslog" },
    { "mdns",   "mDNS" },
    { "esp",    "ESP" },
    { "hsrp",   "HSRP" },
    { "sixin4", "6in4" },
    { "isakmp", "ISAKMP" },
    { "ldp",    "LDP" },
    { "eigrp",  "EIGRP" },
    { "s7comm", "S7comm" },
    { "telnet", "Telnet" },
    { "ah",     "AH" },
    { "netbios", "NetBIOS" },
    { "pop3",   "POP3" },
    { "msnp",   "MSNP" },
    { "smb1",   "SMB1" },
    { "lldp",   "LLDP" },
    { "kerberos", "Kerberos" },
    { "l2tpv3", "L2TPv3" },
    { "whois",  "WHOIS" },
    { "tftp",   "TFTP" },
    { "wol",    "WoL" },
    { "wow",    "WoW" },
    { "bt_dht", "BitTorrent-DHT" },
};
#define N_PROTOCOL_KEY_NAMES (sizeof(g_protocol_key_names) / sizeof(g_protocol_key_names[0]))

/*
 * Apply the CURRENT protocols.ini state (already loaded via
 * load_protocol_config()) to every already-registered dissector's
 * `enabled` flag. Called once right after registration at startup,
 * and again by reload_protocol_config() any time later — same
 * function, so "startup config" and "reloaded config" can't behave
 * differently by accident.
 */
static void apply_protocol_config_to_registry(void) {
    for (size_t i = 0; i < N_PROTOCOL_KEY_NAMES; i++) {
        bool want_enabled = protocol_enabled(g_protocol_key_names[i].config_key);
        bool found = dissector_set_enabled(g_protocol_key_names[i].display_name, want_enabled);
        if (!found) {
            /* Every dissector is registered unconditionally now (see
             * register_all_dissectors()), so this should only fire on
             * a genuine typo in this table or a dissector that forgot
             * to add itself here — worth knowing about loudly, not
             * silently ignoring. */
            fprintf(stderr, "dissector_registry: config key '%s' has no matching "
                    "registered dissector named '%s' — check g_protocol_key_names\n",
                    g_protocol_key_names[i].config_key, g_protocol_key_names[i].display_name);
        }
    }
}

/*
 * Re-read protocols.ini and apply any changes to already-registered
 * dissectors' enabled/disabled state — THE actual fix for "no
 * unregister operation, restart to pick up a change." Toggling a
 * protocol off or back on no longer requires restarting the engine;
 * it requires editing protocols.ini and calling this function.
 *
 * What this does NOT do, stated plainly: it doesn't add or remove
 * dissectors from g_registry itself — every dissector this engine
 * knows how to parse is registered once, unconditionally, at startup
 * (see register_all_dissectors()), and stays registered for the
 * process's whole lifetime. "Disabled" means dispatch_dissection()
 * skips it, not that its code is unloaded or its memory freed — this
 * is a toggle, not a plugin unload mechanism. That's a deliberate,
 * much simpler design than dynamic loading/unloading of dissector code
 * would be, and it's sufficient for the actual use case (an operator
 * wanting to turn a protocol off without a restart), so there was no
 * reason to build the heavier mechanism instead.
 *
 * HOW TO TRIGGER THIS IN PRODUCTION: this function itself doesn't
 * install any trigger — wiring it to something (a SIGHUP handler, a
 * periodic timer thread, an admin API endpoint) is left to the
 * integration, the same way dpi_output_sink.c's file sink already
 * reopens its file on SIGHUP without this file needing to know
 * anything about signals itself. A SIGHUP handler is probably the
 * most natural fit given that precedent already exists in this
 * project.
 */
static void reload_protocol_config(void) {
    load_protocol_config("protocols.ini");
    apply_protocol_config_to_registry();
    fprintf(stderr, "dissector_registry: protocols.ini reloaded, "
            "dissector enabled/disabled state updated\n");
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
     * anything. Note what changed here: this file is still only READ
     * at this specific point in time — making the ENGINE'S reaction to
     * later changes dynamic (rather than the file-reading itself) is
     * exactly what reload_protocol_config() above adds. */
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
    extern void register_smtp_dissector(void);
    extern void register_arp_dissector(void);
    extern void register_mqtt_dissector(void);
    extern void register_ntp_dissector(void);
    extern void register_snmp_dissector(void);
    extern void register_stun_dissector(void);
    extern void register_modbus_dissector(void);
    extern void register_dnp3_dissector(void);
    extern void register_gre_dissector(void);
    extern void register_mpls_dissector(void);
    extern void register_ospf_dissector(void);
    extern void register_bgp_dissector(void);
    extern void register_ldap_dissector(void);
    extern void register_ftp_dissector(void);
    extern void register_igmp_dissector(void);
    extern void register_rip_dissector(void);
    extern void register_ssdp_dissector(void);
    extern void register_syslog_dissector(void);
    extern void register_mdns_dissector(void);
    extern void register_esp_dissector(void);
    extern void register_hsrp_dissector(void);
    extern void register_sixin4_dissector(void);
    extern void register_isakmp_dissector(void);
    extern void register_ldp_protocol_dissector(void);
    extern void register_eigrp_dissector(void);
    extern void register_s7comm_dissector(void);
    extern void register_telnet_dissector(void);
    extern void register_ah_dissector(void);
    extern void register_netbios_dissector(void);
    extern void register_pop3_dissector(void);
    extern void register_msnp_dissector(void);
    extern void register_smb1_dissector(void);
    extern void register_lldp_dissector(void);
    extern void register_kerberos_dissector(void);
    extern void register_l2tpv3_dissector(void);
    extern void register_whois_dissector(void);
    extern void register_tftp_dissector(void);
    extern void register_wol_dissector(void);
    extern void register_wow_dissector(void);
    extern void register_bt_dht_dissector(void);

    /* Every dissector is now registered UNCONDITIONALLY — this is the
     * change that makes runtime toggling possible at all. An earlier
     * version of this function gated each registration CALL behind
     * `if (protocol_enabled(...))`, which meant a disabled protocol was
     * never added to g_registry and therefore could never be turned
     * back on without restarting — exactly the limitation this change
     * closes. Initial enabled/disabled state is applied afterward,
     * uniformly, via apply_protocol_config_to_registry(). */
    register_radius_dissector();
    register_quic_dissector();
    register_gtp_dissector();
    register_gtpv2_dissector();
    register_dns_dissector();
    register_http1_dissector();
    register_http2_dissector();
    register_ssh_dissector();
    register_dhcp_dissector();
    register_sip_dissector();
    register_rtp_dissector();
    register_icmp_dissector();
    register_icmpv6_dissector();
    register_smtp_dissector();
    register_arp_dissector();
    register_mqtt_dissector();
    register_ntp_dissector();
    register_snmp_dissector();
    register_stun_dissector();
    register_modbus_dissector();
    register_dnp3_dissector();
    register_gre_dissector();
    register_mpls_dissector();
    register_ospf_dissector();
    register_bgp_dissector();
    register_ldap_dissector();
    register_ftp_dissector();
    register_igmp_dissector();
    register_rip_dissector();
    register_ssdp_dissector();
    register_syslog_dissector();
    register_mdns_dissector();
    register_esp_dissector();
    register_hsrp_dissector();
    register_sixin4_dissector();
    register_isakmp_dissector();
    register_ldp_protocol_dissector();
    register_eigrp_dissector();
    register_s7comm_dissector();
    register_telnet_dissector();
    register_ah_dissector();
    register_netbios_dissector();
    register_pop3_dissector();
    register_msnp_dissector();
    register_smb1_dissector();
    register_lldp_dissector();
    register_kerberos_dissector();
    register_l2tpv3_dissector();
    register_whois_dissector();
    register_tftp_dissector();
    register_wol_dissector();
    register_wow_dissector();
    register_bt_dht_dissector();

    apply_protocol_config_to_registry();

    fprintf(stderr, "dissector_registry: %d protocol dissector(s) registered, "
            "initial enabled/disabled state applied from protocols.ini\n",
            g_n_dissectors);
}
#endif /* DPI_SKIP_REGISTER_ALL */
