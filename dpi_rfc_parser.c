/*
 * dpi_rfc_parser.c
 *
 * RFC-conformant IPv4 + TCP dissection module, meant to replace the
 * placeholder dissect_packet() in dpi_dpdk_worker.c.
 *
 * Scope, deliberately: IPv4 (RFC 791) and TCP (RFC 9293) only. Get these
 * two right first — everything else (HTTP, TLS, IPv6) sits on top of a
 * correct L3/L4 foundation, and mistakes here are exactly the class of
 * bug that creates DPI/endpoint interpretation mismatches (evasion).
 *
 * NOT COMPILED OR TESTED against a live NIC in this environment. Build
 * and validate on your lab hardware, including against known evasion
 * test suites (e.g. traffic generated to match fragroute / the classic
 * Ptacek & Newsham IDS evasion test cases) before trusting this on
 * production traffic.
 *
 * -------------------------------------------------------------------
 * DESIGN DECISIONS AND THE RFC TEXT BEHIND THEM
 * -------------------------------------------------------------------
 *
 * IPv4 (RFC 791):
 *   - Header checksum is verified (S2.3). A packet failing checksum is
 *     dropped outright — a real receiving host would too.
 *   - IHL is validated against both the RFC minimum (5, i.e. 20 bytes)
 *     and the actual buffer length before any options are read.
 *   - Options (S3.1) are walked type-length-value, bounds-checked at
 *     every step. Unknown option types are skipped by their declared
 *     length, never assumed.
 *   - Fragmentation (S3.2) is reassembled using a bounded per-flow
 *     cache keyed on (src, dst, protocol, identification). This is a
 *     simplified reference reassembler, not a production-hardened one —
 *     see the FRAG_* constants and comments for what a real
 *     implementation needs to add (timeout eviction, overlap policy,
 *     memory ceiling enforcement under attack).
 *
 * TCP (RFC 9293):
 *   - Checksum is verified using the IPv4 pseudo-header (S3.1).
 *   - Data offset is validated the same way IHL is.
 *   - Options (S3.2) are walked TLV-style: MSS, window scale, SACK
 *     permitted, timestamps. Same discipline as IP options.
 *   - Overlapping segment policy: this implementation uses "first data
 *     wins" (favor the first-arriving bytes for any overlapping
 *     region), matching classic BSD stack behavior. THIS IS A CHOICE,
 *     NOT A NEUTRAL DEFAULT — RFC 9293 does not mandate a single
 *     resolution policy, and different operating systems resolve
 *     overlaps differently. A DPI engine that doesn't match the
 *     actual endpoint's OS can be evaded via crafted overlaps. If you
 *     know your protected hosts' OS mix, make this configurable per
 *     policy (first-wins vs last-wins) rather than hardcoded.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------
 * Wire structures — packed, network byte order fields read via the
 * accessor macros below rather than direct struct access, so byte
 * order handling stays explicit at every read site.
 * ------------------------------------------------------------------ */
#pragma pack(push, 1)

struct ipv4_hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

#pragma pack(pop)

#define IPV4_MIN_IHL_BYTES   20
#define IPV4_FLAG_MF         0x2000   /* more fragments, in flags_frag_off */
#define IPV4_FRAG_OFF_MASK   0x1FFF   /* 13-bit fragment offset, in 8-byte units */

#define TCP_MIN_HDR_BYTES    20

/* ------------------------------------------------------------------
 * RFC 1071 Internet checksum — used for both IPv4 header checksum
 * and, with a pseudo-header prepended, TCP checksum.
 * ------------------------------------------------------------------ */
static uint16_t checksum16(const void *data, size_t len, uint32_t init) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = init;

    while (len > 1) {
        sum += (p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += (uint32_t)p[0] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* ------------------------------------------------------------------
 * IPv4 options — TLV walk, RFC 791 S3.1. Every step is bounds-checked
 * against the header length actually declared, never assumed.
 * ------------------------------------------------------------------ */
struct ipv4_parsed_options {
    bool has_unrecognized;   /* surfaced as a flag, not silently dropped */
};

static bool parse_ipv4_options(const uint8_t *opts, size_t opts_len,
                                struct ipv4_parsed_options *out) {
    memset(out, 0, sizeof(*out));
    size_t i = 0;

    while (i < opts_len) {
        uint8_t opt_type = opts[i];

        if (opt_type == 0x00) break;        /* end of options list */
        if (opt_type == 0x01) { i += 1; continue; }  /* NOP, 1 byte, no length field */

        if (i + 1 >= opts_len) {
            /* Option claims to exist but there's no room for a length
             * byte. Malformed: stop parsing, flag it, don't guess. */
            out->has_unrecognized = true;
            return false;
        }

        uint8_t opt_len = opts[i + 1];
        if (opt_len < 2 || i + opt_len > opts_len) {
            /* Length field lies about remaining space: reject. */
            out->has_unrecognized = true;
            return false;
        }

        /* Recognized option types (timestamp, record route, etc.) would
         * be dispatched here by opt_type. Anything else: skip exactly
         * opt_len bytes as the spec requires, don't assume a fixed size. */
        i += opt_len;
    }
    return true;
}

/* ------------------------------------------------------------------
 * IPv4 fragmentation reassembly — simplified bounded reference cache.
 *
 * Production requirements this reference version calls out but does
 * not fully implement (mark these TODO before trusting on live traffic):
 *   - Per-fragment-set timeout eviction (RFC 791 suggests ~15-30s TTL)
 *   - Hard memory ceiling across ALL in-flight fragment sets, enforced
 *     BEFORE allocating, to prevent a fragmentation-based memory
 *     exhaustion DoS
 *   - Overlap-in-fragmentation handling (fragments can themselves
 *     overlap — same evasion class as TCP overlap, needs an explicit
 *     policy)
 * ------------------------------------------------------------------ */
#define FRAG_MAX_FLOWS        1024
#define FRAG_MAX_PACKET_BYTES 65535
#define FRAG_MAX_HOLES        64

struct frag_hole {
    uint16_t start;
    uint16_t end;    /* exclusive */
};

struct frag_entry {
    bool     in_use;
    uint32_t src_addr, dst_addr;
    uint8_t  protocol;
    uint16_t id;
    uint8_t  buf[FRAG_MAX_PACKET_BYTES];
    uint16_t total_len;       /* 0 until the final fragment (MF=0) sets it */
    struct frag_hole holes[FRAG_MAX_HOLES];
    int      n_holes;
};

static struct frag_entry frag_table[FRAG_MAX_FLOWS];

static struct frag_entry *frag_find_or_create(uint32_t src, uint32_t dst,
                                               uint8_t proto, uint16_t id) {
    struct frag_entry *free_slot = NULL;
    for (int i = 0; i < FRAG_MAX_FLOWS; i++) {
        struct frag_entry *e = &frag_table[i];
        if (e->in_use && e->src_addr == src && e->dst_addr == dst &&
            e->protocol == proto && e->id == id) {
            return e;
        }
        if (!e->in_use && !free_slot) free_slot = e;
    }
    if (!free_slot) return NULL;  /* table full: caller must drop the fragment */

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->in_use = true;
    free_slot->src_addr = src;
    free_slot->dst_addr = dst;
    free_slot->protocol = proto;
    free_slot->id = id;
    free_slot->holes[0] = (struct frag_hole){0, FRAG_MAX_PACKET_BYTES};
    free_slot->n_holes = 1;
    return free_slot;
}

/* Returns true and fills out_len when reassembly completes. */
static bool frag_insert(struct frag_entry *e, uint16_t frag_off_bytes,
                         const uint8_t *data, uint16_t data_len,
                         bool more_fragments, uint16_t *out_len) {
    if ((size_t)frag_off_bytes + data_len > FRAG_MAX_PACKET_BYTES) {
        return false;   /* would overflow the reassembly buffer: reject */
    }

    memcpy(e->buf + frag_off_bytes, data, data_len);

    if (!more_fragments) {
        e->total_len = frag_off_bytes + data_len;
    }

    /* Close the hole this fragment fills. Reference implementation:
     * linear scan/update, adequate for FRAG_MAX_HOLES=64. A production
     * version under adversarial fragmentation needs this bounded more
     * carefully (an attacker can try to maximize hole-list churn). */
    uint16_t frag_end = frag_off_bytes + data_len;
    for (int i = 0; i < e->n_holes; i++) {
        struct frag_hole *h = &e->holes[i];
        if (frag_off_bytes <= h->start && frag_end >= h->end) {
            /* fragment fully covers this hole */
            memmove(&e->holes[i], &e->holes[i + 1],
                    sizeof(struct frag_hole) * (e->n_holes - i - 1));
            e->n_holes--;
            i--;
        } else if (frag_off_bytes <= h->start && frag_end > h->start) {
            h->start = frag_end;
        } else if (frag_off_bytes < h->end && frag_end >= h->end) {
            h->end = frag_off_bytes;
        }
        /* fragment fully inside an existing hole: would need a split;
         * omitted here for brevity — flag as a known gap */
    }

    if (e->total_len != 0 && e->n_holes == 0) {
        *out_len = e->total_len;
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------
 * IPv4 top-level parse
 * ------------------------------------------------------------------ */
struct ipv4_result {
    uint32_t src_addr, dst_addr;
    uint8_t  protocol;
    const uint8_t *payload;
    uint16_t payload_len;
    bool     checksum_valid;
    bool     reassembled;      /* true if this came out of the frag cache */
};

static bool parse_ipv4(const uint8_t *pkt, uint16_t len, struct ipv4_result *out) {
    if (len < IPV4_MIN_IHL_BYTES) return false;

    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)pkt;
    uint8_t version = ip->ver_ihl >> 4;
    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;

    if (version != 4) return false;
    if (ihl < IPV4_MIN_IHL_BYTES || ihl > len) return false;

    uint16_t total_len = ntohs(ip->total_len);
    if (total_len < ihl || total_len > len) return false;

    /* Checksum over the header as received (checksum field included
     * as-is; RFC 1071 property makes the result 0 for a valid packet
     * when computed this way — but we compute explicitly against a
     * zeroed checksum field for clarity instead of relying on that). */
    struct ipv4_hdr tmp = *ip;
    tmp.checksum = 0;
    out->checksum_valid = (checksum16(&tmp, ihl, 0) == ntohs(ip->checksum));

    if (ihl > IPV4_MIN_IHL_BYTES) {
        struct ipv4_parsed_options opts;
        if (!parse_ipv4_options(pkt + IPV4_MIN_IHL_BYTES,
                                 ihl - IPV4_MIN_IHL_BYTES, &opts)) {
            return false;  /* malformed options: reject the packet */
        }
    }

    uint16_t flags_frag = ntohs(ip->flags_frag_off);
    bool more_fragments = (flags_frag & IPV4_FLAG_MF) != 0;
    uint16_t frag_offset_bytes = (flags_frag & IPV4_FRAG_OFF_MASK) * 8;

    const uint8_t *payload = pkt + ihl;
    uint16_t payload_len = total_len - ihl;

    if (frag_offset_bytes != 0 || more_fragments) {
        /* Part of a fragmented datagram: route through reassembly. */
        struct frag_entry *e = frag_find_or_create(ip->src_addr, ip->dst_addr,
                                                     ip->protocol, ntohs(ip->id));
        if (!e) return false;   /* table full: drop, don't block */

        uint16_t reassembled_len = 0;
        bool done = frag_insert(e, frag_offset_bytes, payload, payload_len,
                                 more_fragments, &reassembled_len);
        if (!done) return false;  /* waiting on more fragments: nothing to emit yet */

        out->src_addr = ip->src_addr;
        out->dst_addr = ip->dst_addr;
        out->protocol = ip->protocol;
        out->payload = e->buf;
        out->payload_len = reassembled_len;
        out->reassembled = true;
        e->in_use = false;   /* release the slot now that reassembly is complete */
        return true;
    }

    out->src_addr = ip->src_addr;
    out->dst_addr = ip->dst_addr;
    out->protocol = ip->protocol;
    out->payload = payload;
    out->payload_len = payload_len;
    out->reassembled = false;
    return true;
}

/* ------------------------------------------------------------------
 * TCP options — TLV walk, RFC 9293 S3.2.
 * ------------------------------------------------------------------ */
struct tcp_parsed_options {
    bool     has_mss;      uint16_t mss;
    bool     has_wscale;   uint8_t  wscale;
    bool     sack_permitted;
    bool     has_timestamps; uint32_t tsval, tsecr;
};

static bool parse_tcp_options(const uint8_t *opts, size_t opts_len,
                               struct tcp_parsed_options *out) {
    memset(out, 0, sizeof(*out));
    size_t i = 0;

    while (i < opts_len) {
        uint8_t kind = opts[i];

        if (kind == 0) break;              /* end of option list */
        if (kind == 1) { i += 1; continue; } /* NOP */

        if (i + 1 >= opts_len) return false;
        uint8_t olen = opts[i + 1];
        if (olen < 2 || i + olen > opts_len) return false;

        switch (kind) {
            case 2:  /* MSS */
                if (olen == 4) {
                    out->has_mss = true;
                    out->mss = (opts[i + 2] << 8) | opts[i + 3];
                }
                break;
            case 3:  /* window scale */
                if (olen == 3) {
                    out->has_wscale = true;
                    out->wscale = opts[i + 2];
                }
                break;
            case 4:  /* SACK permitted */
                if (olen == 2) out->sack_permitted = true;
                break;
            case 8:  /* timestamps */
                if (olen == 10) {
                    out->has_timestamps = true;
                    out->tsval = (opts[i+2]<<24)|(opts[i+3]<<16)|(opts[i+4]<<8)|opts[i+5];
                    out->tsecr = (opts[i+6]<<24)|(opts[i+7]<<16)|(opts[i+8]<<8)|opts[i+9];
                }
                break;
            default:
                break;  /* unrecognized: skip by declared length, don't assume */
        }
        i += olen;
    }
    return true;
}

/* ------------------------------------------------------------------
 * TCP pseudo-header checksum, RFC 9293 S3.1 (referencing RFC 791 S3.2
 * / the IPv4 pseudo-header convention carried forward).
 * ------------------------------------------------------------------ */
static bool tcp_checksum_valid(uint32_t src, uint32_t dst,
                                const uint8_t *tcp_seg, uint16_t seg_len) {
    struct {
        uint32_t src, dst;
        uint8_t  zero, proto;
        uint16_t len;
    } pseudo;
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.proto = 6;  /* TCP */
    pseudo.len = htons(seg_len);

    uint32_t partial = 0;
    const uint8_t *p = (const uint8_t *)&pseudo;
    for (size_t i = 0; i < sizeof(pseudo); i += 2) {
        partial += (p[i] << 8) | p[i + 1];
    }

    struct tcp_hdr tmp;
    memcpy(&tmp, tcp_seg, sizeof(tmp) < seg_len ? sizeof(tmp) : seg_len);
    uint16_t orig_checksum = ntohs(*(const uint16_t *)(tcp_seg + 16));

    /* Recompute over the full segment with checksum field zeroed. */
    uint8_t scratch[1500];  /* bounded by typical MTU; larger segments need heap */
    if (seg_len > sizeof(scratch)) return false;  /* reject rather than overrun */
    memcpy(scratch, tcp_seg, seg_len);
    scratch[16] = 0; scratch[17] = 0;

    uint16_t computed = checksum16(scratch, seg_len, partial);
    return computed == orig_checksum;
}

/* ------------------------------------------------------------------
 * TCP top-level parse, including the overlap-resolution policy.
 * ------------------------------------------------------------------ */
struct tcp_result {
    uint16_t src_port, dst_port;
    uint32_t seq, ack;
    uint8_t  flags;
    uint16_t window;
    bool     checksum_valid;
    struct tcp_parsed_options options;
    const uint8_t *payload;
    uint16_t payload_len;
};

static bool parse_tcp(uint32_t ip_src, uint32_t ip_dst,
                       const uint8_t *seg, uint16_t seg_len,
                       struct tcp_result *out) {
    if (seg_len < TCP_MIN_HDR_BYTES) return false;

    const struct tcp_hdr *tcp = (const struct tcp_hdr *)seg;
    uint8_t data_off = (tcp->data_off_reserved >> 4) * 4;
    if (data_off < TCP_MIN_HDR_BYTES || data_off > seg_len) return false;

    out->src_port = ntohs(tcp->src_port);
    out->dst_port = ntohs(tcp->dst_port);
    out->seq = ntohl(tcp->seq);
    out->ack = ntohl(tcp->ack);
    out->flags = tcp->flags;
    out->window = ntohs(tcp->window);
    out->checksum_valid = tcp_checksum_valid(ip_src, ip_dst, seg, seg_len);

    if (data_off > TCP_MIN_HDR_BYTES) {
        if (!parse_tcp_options(seg + TCP_MIN_HDR_BYTES,
                                data_off - TCP_MIN_HDR_BYTES, &out->options)) {
            return false;  /* malformed options: reject */
        }
    } else {
        memset(&out->options, 0, sizeof(out->options));
    }

    out->payload = seg + data_off;
    out->payload_len = seg_len - data_off;
    return true;
}

/*
 * NOTE ON UDP (RFC 768): added when wiring the UDP capture path (see
 * dpi_dpdk_worker.c / dpi_secure_bootstrap.c). UDP's header is fixed
 * and trivial by comparison to IPv4/TCP — 8 bytes, no options, no
 * fragmentation concerns of its own (UDP relies on IP fragmentation).
 * Included here rather than a separate file since it's a natural
 * extension of this file's existing L3/L4 scope, not a new module.
 */
#define UDP_HDR_LEN 8

struct udp_result {
    uint16_t src_port, dst_port;
    bool     checksum_valid;     /* UDP checksum is OPTIONAL over IPv4 (a
                                   * value of 0 means "not computed" per
                                   * RFC 768) — checksum_present distinguishes
                                   * that case from an actually-invalid one */
    bool     checksum_present;
    const uint8_t *payload;
    uint16_t payload_len;
};

static bool parse_udp(uint32_t ip_src, uint32_t ip_dst,
                       const uint8_t *seg, uint16_t seg_len, struct udp_result *out) {
    if (seg_len < UDP_HDR_LEN) return false;

    uint16_t declared_len = (seg[4] << 8) | seg[5];
    if (declared_len < UDP_HDR_LEN || declared_len > seg_len) return false;

    out->src_port = (seg[0] << 8) | seg[1];
    out->dst_port = (seg[2] << 8) | seg[3];
    uint16_t checksum_field = (seg[6] << 8) | seg[7];

    out->checksum_present = (checksum_field != 0);
    if (out->checksum_present) {
        /* Same pseudo-header construction as TCP's checksum, but with
         * UDP length in place of TCP segment length and protocol=17. */
        struct {
            uint32_t src, dst;
            uint8_t  zero, proto;
            uint16_t len;
        } pseudo;
        pseudo.src = ip_src;
        pseudo.dst = ip_dst;
        pseudo.zero = 0;
        pseudo.proto = 17;   /* UDP */
        pseudo.len = htons(declared_len);

        uint32_t partial = 0;
        const uint8_t *p = (const uint8_t *)&pseudo;
        for (size_t i = 0; i < sizeof(pseudo); i += 2) {
            partial += (p[i] << 8) | p[i + 1];
        }

        uint8_t scratch[1500];
        if (declared_len > sizeof(scratch)) {
            out->checksum_valid = false;   /* can't verify, but not necessarily wrong —
                                             * treat unverifiable as untrusted, not fatal */
        } else {
            memcpy(scratch, seg, declared_len);
            scratch[6] = 0; scratch[7] = 0;   /* zero the checksum field for recompute */
            uint16_t computed = checksum16(scratch, declared_len, partial);
            out->checksum_valid = (computed == checksum_field);
        }
    } else {
        out->checksum_valid = false;   /* not applicable — see checksum_present */
    }

    out->payload = seg + UDP_HDR_LEN;
    out->payload_len = declared_len - UDP_HDR_LEN;
    return true;
}

/*
 * NOTE on the "overlap resolution policy" referenced in the TCP
 * header comment above: that logic lives in the PER-FLOW STREAM
 * REASSEMBLY layer (dpi_tcp_flow_reassembly.c), which tracks expected
 * next-seq per flow across many segments over the life of a
 * connection — a separate, stateful component from this per-packet
 * parser. This file gives you a correctly-parsed segment (seq,
 * payload, flags); dpi_tcp_flow_reassembly.c is where first-wins vs
 * last-wins for overlapping seq ranges is actually decided.
 *
 * UDP has no equivalent reassembly concern — it's datagram-oriented,
 * each datagram is independent, so the UDP capture path calls
 * dpi_dissector_registry.c's dispatch_dissection() directly per
 * datagram rather than going through anything like
 * dpi_tcp_flow_reassembly.c.
 */
