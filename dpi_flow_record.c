/*
 * dpi_flow_record.c
 *
 * Flow-record aggregation and rich, nested JSON emission for the
 * offline pcap-file analysis path (`--pcap-file=`). Built in response
 * to a direct request for output matching a specific richer schema —
 * flow_id, ts_start/ts_last, bytes_total/packets_total/duration_ms,
 * and a nested per-protocol object — rather than this project's
 * previous flat, immediate-per-packet JSON line.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * SCOPE, stated precisely rather than implied: wired into the TCP
 * dispatch path specifically (both IPv4 and IPv6), in
 * `dpi_secure_bootstrap.c` — the offline file-reading capture path.
 * UDP-based protocols (DNS, DHCP, SNMP, etc.), ICMP, ARP, and 802.11
 * still use this project's existing flat, immediate emission and are
 * NOT yet flow-aggregated into this richer schema — extending them is
 * real, additional, well-scoped future work, not done here to avoid
 * rushing a much larger change across many more call sites within one
 * pass. The live-capture paths (DPDK worker, AF_PACKET bootstrap
 * without `--pcap-file`) are similarly unaffected — this is
 * specifically for offline analysis, where "wait until EOF, then
 * emit one summarized record per flow" is the natural model, unlike
 * live capture where near-real-time per-packet output usually matters
 * more than waiting for a flow to end.
 *
 * THREADING MODEL: this file's flow table is NOT thread-safe (no
 * locking, no partitioning) — safe here because the offline pcap-file
 * reading path is single-threaded by design (see
 * `process_pcap_file()`/`process_pcapng_file()`'s own comments). Do
 * NOT call any function in this file from the multi-threaded DPDK
 * worker without adding real synchronization first.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

#define FLOW_RECORD_MAX_FLOWS      4096   /* bounded, same discipline
                                              as every other table in
                                              this project — a single
                                              pcap file with more
                                              concurrent flows than
                                              this will evict the
                                              oldest (see below), not
                                              crash or grow unbounded */
#define FLOW_RECORD_MAX_L7_FIELDS  32     /* mirrors MAX_FIELDS_PER_RESULT
                                              in dpi_dissector_registry.c */

/*
 * A single stashed dissect_result field, copied out of the
 * short-lived `struct dissect_result` a dissector fills in (which
 * goes out of scope well before this flow gets emitted, possibly
 * many packets later) — this file owns its own copies, not pointers
 * into something that no longer exists by emission time.
 */
struct flow_l7_field {
    char key[MAX_FIELD_KEY_LEN];
    char value[MAX_FIELD_VAL_LEN];
};

struct flow_record {
    bool     in_use;
    uint64_t flow_id;

    uint8_t  ip_version;         /* 4 or 6 */
    uint8_t  addr_lo[16];        /* normalized: addr_lo/port_lo is
                                     whichever endpoint sorts first,
                                     so both directions of one real
                                     connection map to the SAME flow
                                     entry, matching how a flow record
                                     is conventionally understood
                                     (one record per connection, not
                                     one per direction) */
    uint8_t  addr_hi[16];
    uint16_t port_lo, port_hi;
    uint8_t  l4_protocol;        /* 6 = TCP; only TCP flows are
                                     tracked here currently, see file
                                     header SCOPE note */

    /* The actual first-observed direction — kept separately from the
     * normalized lo/hi key above specifically so src_ip/dst_ip in the
     * emitted record reflect who really initiated the connection,
     * not an arbitrary sort order. */
    uint8_t  orig_addr[16];
    uint16_t orig_port;
    uint8_t  resp_addr[16];
    uint16_t resp_port;

    double   ts_start;           /* seconds since epoch, fractional */
    double   ts_last;
    uint64_t bytes_total;
    uint32_t packets_total;

    char     l7_protocol[MAX_PROTOCOL_NAME];
    char     l7_confidence[16];
    struct flow_l7_field l7_fields[FLOW_RECORD_MAX_L7_FIELDS];
    int      n_l7_fields;

    uint32_t out_of_order_segments;
    uint32_t retransmit_count;
    uint32_t overlap_conflict_count;
    bool     evasion_flag;

    double   dga_score;
    double   vpn_score;
    char     vpn_protocol[32];
    double   dot_score;
    double   doh_score;
};

static struct flow_record g_flow_records[FLOW_RECORD_MAX_FLOWS];
static uint64_t g_flow_id_counter = 0;

/* Set once per packet by the file readers before dispatching it —
 * see this file's header comment on why a simple global is the right
 * call here rather than threading a timestamp parameter through
 * every function in the existing dissection call chain. */
static double g_current_packet_ts = 0.0;

static void flow_record_set_current_timestamp(double ts) {
    g_current_packet_ts = ts;
}

/* ISO 8601 with microsecond precision and a literal "Z" (UTC) suffix,
 * matching the requested schema exactly (e.g.
 * "2026-07-18T14:22:04.003112Z"). `epoch_seconds` is a double —
 * fractional part is the sub-second component. */
static void format_iso8601_micros(double epoch_seconds, char *out, size_t out_cap) {
    time_t whole_secs = (time_t)epoch_seconds;
    double frac = epoch_seconds - (double)whole_secs;
    /* int, not long — always clamped to [0, 999999] by the check
     * below, but `long`'s full 64-bit range was enough to trigger a
     * real compiler warning here (same class as the telnet/HSRP/
     * Kerberos/etc. cases fixed earlier this project), since GCC
     * can't see through the clamp to the actual bounded range. */
    int micros = (int)(frac * 1000000.0 + 0.5);
    if (micros >= 1000000) { micros -= 1000000; whole_secs += 1; }

    struct tm tm_utc;
    gmtime_r(&whole_secs, &tm_utc);

    char base[32];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm_utc);
    snprintf(out, out_cap, "%s.%06dZ", base, micros);
}

static bool addr_equal(const uint8_t *a, const uint8_t *b, uint8_t ip_version) {
    return memcmp(a, b, ip_version == 4 ? 4 : 16) == 0;
}

static int addr_compare(const uint8_t *a, const uint8_t *b, uint8_t ip_version) {
    return memcmp(a, b, ip_version == 4 ? 4 : 16);
}

/*
 * Finds an existing flow matching this 5-tuple in EITHER direction,
 * or creates a new one. Returns NULL only if the table is full AND
 * eviction of the least-recently-active flow still didn't free a
 * slot (shouldn't happen in practice — eviction always frees exactly
 * one slot — kept as a defensive NULL check anyway rather than
 * assumed impossible).
 */
static struct flow_record *flow_record_find_or_create(uint8_t ip_version,
                                                        const uint8_t *src_addr, uint16_t src_port,
                                                        const uint8_t *dst_addr, uint16_t dst_port,
                                                        uint8_t l4_protocol) {
    uint8_t addr_lo[16], addr_hi[16];
    uint16_t port_lo, port_hi;
    bool src_is_lo;

    int cmp = addr_compare(src_addr, dst_addr, ip_version);
    if (cmp < 0 || (cmp == 0 && src_port <= dst_port)) {
        memcpy(addr_lo, src_addr, 16); memcpy(addr_hi, dst_addr, 16);
        port_lo = src_port; port_hi = dst_port;
        src_is_lo = true;
    } else {
        memcpy(addr_lo, dst_addr, 16); memcpy(addr_hi, src_addr, 16);
        port_lo = dst_port; port_hi = src_port;
        src_is_lo = false;
    }
    (void)src_is_lo;   /* the ORIGINATOR fields are only set at
                          creation time, below — an existing flow's
                          originator doesn't change just because a
                          later packet happens to flow the other way */

    for (int i = 0; i < FLOW_RECORD_MAX_FLOWS; i++) {
        struct flow_record *f = &g_flow_records[i];
        if (!f->in_use) continue;
        if (f->ip_version == ip_version && f->l4_protocol == l4_protocol &&
            addr_equal(f->addr_lo, addr_lo, ip_version) && f->port_lo == port_lo &&
            addr_equal(f->addr_hi, addr_hi, ip_version) && f->port_hi == port_hi) {
            return f;
        }
    }

    /* Not found: create in a free slot, or evict the flow with the
     * oldest ts_last (least-recently-active) if the table is full —
     * bounded, not unbounded growth, same discipline as every other
     * table in this project. */
    struct flow_record *slot = NULL;
    for (int i = 0; i < FLOW_RECORD_MAX_FLOWS; i++) {
        if (!g_flow_records[i].in_use) { slot = &g_flow_records[i]; break; }
    }
    if (!slot) {
        int oldest_idx = 0;
        double oldest_ts = g_flow_records[0].ts_last;
        for (int i = 1; i < FLOW_RECORD_MAX_FLOWS; i++) {
            if (g_flow_records[i].ts_last < oldest_ts) {
                oldest_ts = g_flow_records[i].ts_last;
                oldest_idx = i;
            }
        }
        /* Emit the evicted flow before overwriting it, so it isn't
         * silently lost from the output — forward-declared below,
         * defined further down in this same file. */
        extern void flow_record_emit_one(const struct flow_record *f);
        flow_record_emit_one(&g_flow_records[oldest_idx]);
        slot = &g_flow_records[oldest_idx];
    }
    if (!slot) return NULL;   /* defensive only, see function comment */

    memset(slot, 0, sizeof(*slot));
    slot->in_use = true;
    slot->flow_id = ++g_flow_id_counter;
    slot->ip_version = ip_version;
    memcpy(slot->addr_lo, addr_lo, 16);
    memcpy(slot->addr_hi, addr_hi, 16);
    slot->port_lo = port_lo;
    slot->port_hi = port_hi;
    slot->l4_protocol = l4_protocol;
    memcpy(slot->orig_addr, src_addr, 16);
    slot->orig_port = src_port;
    memcpy(slot->resp_addr, dst_addr, 16);
    slot->resp_port = dst_port;
    slot->ts_start = g_current_packet_ts;
    slot->ts_last = g_current_packet_ts;
    strncpy(slot->l7_confidence, "low", sizeof(slot->l7_confidence) - 1);

    return slot;
}

/* Called once per packet belonging to a flow — updates counters and
 * activity timestamp. Byte count is the CAPTURED length of this one
 * packet (the same `incl_len`/`captured_len` the file readers already
 * validated against the engine's snaplen), not the original on-wire
 * length if those ever differ (a truncated/snapped capture) — stated
 * explicitly since "bytes_total" could otherwise be read as claiming
 * more precision than this actually has. */
static void flow_record_touch(struct flow_record *f, uint32_t packet_bytes) {
    f->packets_total++;
    f->bytes_total += packet_bytes;
    if (g_current_packet_ts > f->ts_last) f->ts_last = g_current_packet_ts;
}

/*
 * Stashes the most recently observed L7 dissection result into the
 * flow, overwriting whatever was there before — a flow's emitted
 * record reflects its MOST RECENT/MOST COMPLETE dissection (e.g. the
 * last HTTP request seen on a keep-alive connection), not every
 * individual request merged together, since merging would risk
 * mixing fields from genuinely different requests into one
 * misleading nested object.
 */
static void flow_record_set_l7(struct flow_record *f, const char *protocol_name,
                                const char *confidence, const struct dissect_result *result) {
    strncpy(f->l7_protocol, protocol_name, sizeof(f->l7_protocol) - 1);
    f->l7_protocol[sizeof(f->l7_protocol) - 1] = '\0';
    strncpy(f->l7_confidence, confidence, sizeof(f->l7_confidence) - 1);
    f->l7_confidence[sizeof(f->l7_confidence) - 1] = '\0';

    f->n_l7_fields = 0;
    if (!result) return;
    for (int i = 0; i < result->n_fields && f->n_l7_fields < FLOW_RECORD_MAX_L7_FIELDS; i++) {
        strncpy(f->l7_fields[f->n_l7_fields].key, result->fields[i].key,
                sizeof(f->l7_fields[f->n_l7_fields].key) - 1);
        strncpy(f->l7_fields[f->n_l7_fields].value, result->fields[i].value,
                sizeof(f->l7_fields[f->n_l7_fields].value) - 1);
        f->n_l7_fields++;
    }
}

static void flow_record_set_evasion_stats(struct flow_record *f, uint32_t out_of_order,
                                           uint32_t retransmits, uint32_t overlap_conflicts,
                                           bool evasion_flag) {
    f->out_of_order_segments = out_of_order;
    f->retransmit_count = retransmits;
    f->overlap_conflict_count = overlap_conflicts;
    f->evasion_flag = evasion_flag;
}

static void flow_record_set_scores(struct flow_record *f, double dga_score, double vpn_score,
                                    const char *vpn_protocol, double dot_score, double doh_score) {
    f->dga_score = dga_score;
    f->vpn_score = vpn_score;
    strncpy(f->vpn_protocol, vpn_protocol, sizeof(f->vpn_protocol) - 1);
    f->dot_score = dot_score;
    f->doh_score = doh_score;
}

/*
 * Finds the longest prefix (ending in '_') shared by every stashed
 * L7 field's key — e.g. "http_method"/"http_host"/"http_user_agent"
 * all share the prefix "http_". Used to both name the nested
 * protocol object and strip the redundant prefix from each field
 * name inside it (so "http_method" becomes "method" nested under
 * "http", matching the requested schema) — done GENERICALLY, for
 * every protocol this project has, rather than hand-building a
 * separate nested-object schema for each of the 55 registered
 * dissectors individually. Falls back to using each field's full,
 * unstripped key if no common prefix is found (e.g. mixed-prefix
 * results, or a single-field result) — never crashes, never silently
 * drops a field, just less tidy in that fallback case.
 */
static void find_common_field_prefix(const struct flow_record *f, char *prefix_out, size_t cap) {
    prefix_out[0] = '\0';
    if (f->n_l7_fields == 0) return;

    const char *first_key = f->l7_fields[0].key;
    const char *underscore = strchr(first_key, '_');
    if (!underscore) return;
    size_t prefix_len = (size_t)(underscore - first_key) + 1;   /* include the '_' */
    if (prefix_len >= cap) return;

    for (int i = 0; i < f->n_l7_fields; i++) {
        if (strncmp(f->l7_fields[i].key, first_key, prefix_len) != 0) {
            return;   /* not a universal prefix: leave prefix_out empty (fallback) */
        }
    }
    memcpy(prefix_out, first_key, prefix_len);
    prefix_out[prefix_len] = '\0';
}

/* Minimal JSON string escaping — the same fields this project has
 * always printed with a bare %s in every existing printf() call site
 * (this isn't a new gap this file introduces); covers the characters
 * genuinely likely to appear in real header/hostname/URI values. */
static void json_escape(const char *in, char *out, size_t out_cap) {
    size_t oi = 0;
    for (size_t ii = 0; in[ii] != '\0' && oi + 2 < out_cap; ii++) {
        unsigned char c = (unsigned char)in[ii];
        if (c == '"' || c == '\\') {
            if (oi + 2 >= out_cap) break;
            out[oi++] = '\\'; out[oi++] = (char)c;
        } else if (c == '\n') {
            if (oi + 2 >= out_cap) break;
            out[oi++] = '\\'; out[oi++] = 'n';
        } else if (c < 0x20) {
            /* skip other control characters rather than emit invalid JSON */
            continue;
        } else {
            out[oi++] = (char)c;
        }
    }
    out[oi] = '\0';
}

static void ip_to_string(const uint8_t *addr, uint8_t ip_version, char *out, size_t out_cap) {
    if (ip_version == 4) {
        snprintf(out, out_cap, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    } else {
        snprintf(out, out_cap, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                               "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 addr[0],addr[1],addr[2],addr[3],addr[4],addr[5],addr[6],addr[7],
                 addr[8],addr[9],addr[10],addr[11],addr[12],addr[13],addr[14],addr[15]);
    }
}

/* Emits exactly one flow as one JSON line, matching the requested
 * schema. Does NOT mark the flow as no-longer-in-use — callers that
 * want the slot freed (eviction) or the whole table cleared (EOF)
 * handle that themselves, since "emit" and "retire" are genuinely
 * different operations (an evicted-and-reused flow is emitted once
 * per eviction, not just once ever). */
void flow_record_emit_one(const struct flow_record *f) {
    if (!f->in_use) return;

    char ts_start_str[48], ts_last_str[48];
    format_iso8601_micros(f->ts_start, ts_start_str, sizeof(ts_start_str));
    format_iso8601_micros(f->ts_last, ts_last_str, sizeof(ts_last_str));

    char src_str[64], dst_str[64];
    ip_to_string(f->orig_addr, f->ip_version, src_str, sizeof(src_str));
    ip_to_string(f->resp_addr, f->ip_version, dst_str, sizeof(dst_str));

    long duration_ms = (long)((f->ts_last - f->ts_start) * 1000.0 + 0.5);

    char flow_id_str[24];
    snprintf(flow_id_str, sizeof(flow_id_str), "%08x-%04x",
             (unsigned)(f->flow_id & 0xFFFFFFFFu), (unsigned)((f->flow_id >> 32) & 0xFFFFu));

    const char *l4_name = f->l4_protocol == 6 ? "TCP" : f->l4_protocol == 17 ? "UDP" : "IP";

    char prefix[MAX_FIELD_KEY_LEN];
    find_common_field_prefix(f, prefix, sizeof(prefix));
    size_t prefix_len = strlen(prefix);

    char l7_object_name[MAX_PROTOCOL_NAME];
    if (prefix_len > 1) {
        strncpy(l7_object_name, prefix, sizeof(l7_object_name) - 1);
        l7_object_name[sizeof(l7_object_name) - 1] = '\0';
        /* drop the trailing '_' for the object name itself, e.g. "http_" -> "http" */
        size_t nlen = strlen(l7_object_name);
        if (nlen > 0 && l7_object_name[nlen - 1] == '_') l7_object_name[nlen - 1] = '\0';
    } else {
        /* No common prefix found: fall back to a sanitized l7_protocol
         * name (lowercased, non-alnum stripped) as the object key. */
        size_t oi = 0;
        for (size_t ii = 0; f->l7_protocol[ii] != '\0' && oi < sizeof(l7_object_name) - 1; ii++) {
            char c = f->l7_protocol[ii];
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) l7_object_name[oi++] = c;
            else if (c >= 'A' && c <= 'Z') l7_object_name[oi++] = (char)(c - 'A' + 'a');
        }
        l7_object_name[oi] = '\0';
        if (oi == 0) strncpy(l7_object_name, "l7", sizeof(l7_object_name) - 1);
    }

    char escaped_val[MAX_FIELD_VAL_LEN * 2];

    printf("{\"flow_id\":\"%s\",\"ts_start\":\"%s\",\"ts_last\":\"%s\","
           "\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,"
           "\"protocol\":\"%s\",\"l7_protocol\":\"%s\",\"l7_confidence\":\"%s\","
           "\"bytes_total\":%llu,\"packets_total\":%u,\"duration_ms\":%ld",
           flow_id_str, ts_start_str, ts_last_str,
           src_str, dst_str, f->orig_port, f->resp_port,
           l4_name, f->l7_protocol[0] ? f->l7_protocol : "unknown", f->l7_confidence,
           (unsigned long long)f->bytes_total, f->packets_total, duration_ms);

    if (f->n_l7_fields > 0) {
        printf(",\"%s\":{", l7_object_name);
        for (int i = 0; i < f->n_l7_fields; i++) {
            const char *key = f->l7_fields[i].key;
            const char *nested_key = key;
            if (prefix_len > 1 && strncmp(key, prefix, prefix_len) == 0) {
                nested_key = key + prefix_len;
            }
            json_escape(f->l7_fields[i].value, escaped_val, sizeof(escaped_val));
            printf("%s\"%s\":\"%s\"", i > 0 ? "," : "", nested_key, escaped_val);
        }
        printf("}");
    }

    printf(",\"reassembly\":{\"out_of_order_segments\":%u,\"overlap_detected\":%s,"
           "\"retransmits\":%u}",
           f->out_of_order_segments, f->overlap_conflict_count > 0 ? "true" : "false",
           f->retransmit_count);

    printf(",\"flags\":[");
    bool first_flag = true;
    if (f->evasion_flag) { printf("%s\"tcp_evasion\"", first_flag ? "" : ","); first_flag = false; }
    if (f->dga_score > 0.5) { printf("%s\"dga_suspected\"", first_flag ? "" : ","); first_flag = false; }
    if (f->vpn_score > 0.5) { printf("%s\"vpn_detected\"", first_flag ? "" : ","); first_flag = false; }
    if (f->dot_score > 0.5) { printf("%s\"dns_over_tls\"", first_flag ? "" : ","); first_flag = false; }
    if (f->doh_score > 0.5) { printf("%s\"dns_over_https\"", first_flag ? "" : ","); first_flag = false; }
    printf("]}\n");
}

/* Called once, at end-of-file, by both file readers — walks every
 * still-in-use flow and emits it. Flows evicted earlier (table was
 * full) were already emitted at eviction time, by
 * flow_record_find_or_create() above, so this only covers flows that
 * survived to EOF without being evicted. */
void flow_record_emit_all_and_reset(void) {
    for (int i = 0; i < FLOW_RECORD_MAX_FLOWS; i++) {
        if (g_flow_records[i].in_use) {
            flow_record_emit_one(&g_flow_records[i]);
        }
    }
    memset(g_flow_records, 0, sizeof(g_flow_records));
    g_flow_id_counter = 0;
}
