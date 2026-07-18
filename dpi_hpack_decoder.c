/*
 * dpi_hpack_decoder.c
 *
 * HPACK (RFC 7541) decoder — decodes the header field block carried in
 * HTTP/2 HEADERS frames, extending dpi_http2_parser.c's frame-level-only
 * parsing to actually recover header names/values, specifically
 * :authority (the HTTP/2 analog of the Host header, and the field this
 * project's HTTP/2 dissector was originally missing).
 *
 * NOT COMPILED/TESTED against a live HTTP/2 connection in this
 * environment. HOWEVER, unlike most crypto-adjacent code in this
 * project, the single highest-risk component here — the 257-entry
 * Huffman table (RFC 7541 Appendix B) — WAS verified before writing
 * any C code: transcribed into a Python list, checked for structural
 * correctness (all 257 symbols present exactly once, Kraft's
 * inequality equals exactly 1.0 confirming a complete prefix code, no
 * duplicate bit patterns), and then used to decode three independent
 * real byte sequences from RFC 7541 Appendix C and confirmed to
 * produce the exact expected output:
 *   - Appendix C.4.1: f1e3c2e5f23a6ba0ab90f4ff -> "www.example.com"
 *   - Appendix C.6.1: aec3771a4b               -> "private"
 *   - Appendix C.4.2: a8eb10649cbf              -> "no-cache"
 * The C table below was then generated programmatically FROM that
 * verified Python list (not retyped by hand), specifically to
 * eliminate transcription risk between the two representations.
 *
 * -------------------------------------------------------------------
 * SCOPE LIMIT, stated as plainly as the QUIC/GTP/IPv6 ones earlier in
 * this project:
 * -------------------------------------------------------------------
 * The dynamic table implemented here is FRESH PER CALL — it does not
 * persist across multiple HEADERS frames for the same connection.
 * This means:
 *   - Static-table references (:authority, :method, etc.) decode
 *     correctly regardless.
 *   - Literal-with-incremental-indexing entries created and then
 *     referenced WITHIN THE SAME header block decode correctly.
 *   - A reference to a dynamic table entry created by an EARLIER
 *     HEADERS frame on the same connection CANNOT be resolved here —
 *     that requires connection-level state persisted the same way
 *     dpi_tcp_flow_reassembly.c persists TCP reassembly state per
 *     flow, which this pass does not wire up. Flagged explicitly
 *     rather than silently producing wrong output — see
 *     hpack_decode_result.dynamic_table_miss below.
 * Real-world HTTP/2 traffic frequently relies on cross-frame dynamic
 * table references (that's the entire point of HPACK's compression),
 * so this decoder will correctly handle a meaningful fraction of
 * traffic (anything using only static-table refs and same-block
 * literals) but not all of it. This is genuinely the next integration
 * step, not a small gap.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

/* ==================================================================
 * Static table, RFC 7541 Appendix A — 61 predefined entries.
 * ================================================================== */
struct hpack_static_entry {
    const char *name;
    const char *value;   /* NULL means "no predefined value, literal follows" */
};

static const struct hpack_static_entry HPACK_STATIC_TABLE[61] = {
    {":authority", NULL}, {":method", "GET"}, {":method", "POST"},
    {":path", "/"}, {":path", "/index.html"}, {":scheme", "http"},
    {":scheme", "https"}, {":status", "200"}, {":status", "204"},
    {":status", "206"}, {":status", "304"}, {":status", "400"},
    {":status", "404"}, {":status", "500"}, {"accept-charset", NULL},
    {"accept-encoding", "gzip, deflate"}, {"accept-language", NULL},
    {"accept-ranges", NULL}, {"accept", NULL},
    {"access-control-allow-origin", NULL}, {"age", NULL}, {"allow", NULL},
    {"authorization", NULL}, {"cache-control", NULL},
    {"content-disposition", NULL}, {"content-encoding", NULL},
    {"content-language", NULL}, {"content-length", NULL},
    {"content-location", NULL}, {"content-range", NULL},
    {"content-type", NULL}, {"cookie", NULL}, {"date", NULL},
    {"etag", NULL}, {"expect", NULL}, {"expires", NULL}, {"from", NULL},
    {"host", NULL}, {"if-match", NULL}, {"if-modified-since", NULL},
    {"if-none-match", NULL}, {"if-range", NULL},
    {"if-unmodified-since", NULL}, {"last-modified", NULL}, {"link", NULL},
    {"location", NULL}, {"max-forwards", NULL},
    {"proxy-authenticate", NULL}, {"proxy-authorization", NULL},
    {"range", NULL}, {"referer", NULL}, {"refresh", NULL},
    {"retry-after", NULL}, {"server", NULL}, {"set-cookie", NULL},
    {"strict-transport-security", NULL}, {"transfer-encoding", NULL},
    {"user-agent", NULL}, {"vary", NULL}, {"via", NULL},
    {"www-authenticate", NULL},
};

/* ==================================================================
 * Huffman table, RFC 7541 Appendix B — {bit_length, code} per symbol
 * 0-255 plus EOS (symbol 256). See this file's header comment for how
 * this was verified before being generated into this exact form.
 * ================================================================== */
struct hpack_huffman_entry { uint8_t length; uint32_t code; };

static const struct hpack_huffman_entry HPACK_HUFFMAN_TABLE[257] = {
    {13, 0x00001ff8}, {23, 0x007fffd8}, {28, 0x0fffffe2}, {28, 0x0fffffe3},
    {28, 0x0fffffe4}, {28, 0x0fffffe5}, {28, 0x0fffffe6}, {28, 0x0fffffe7},
    {28, 0x0fffffe8}, {24, 0x00ffffea}, {30, 0x3ffffffc}, {28, 0x0fffffe9},
    {28, 0x0fffffea}, {30, 0x3ffffffd}, {28, 0x0fffffeb}, {28, 0x0fffffec},
    {28, 0x0fffffed}, {28, 0x0fffffee}, {28, 0x0fffffef}, {28, 0x0ffffff0},
    {28, 0x0ffffff1}, {28, 0x0ffffff2}, {30, 0x3ffffffe}, {28, 0x0ffffff3},
    {28, 0x0ffffff4}, {28, 0x0ffffff5}, {28, 0x0ffffff6}, {28, 0x0ffffff7},
    {28, 0x0ffffff8}, {28, 0x0ffffff9}, {28, 0x0ffffffa}, {28, 0x0ffffffb},
    {6, 0x00000014}, {10, 0x000003f8}, {10, 0x000003f9}, {12, 0x00000ffa},
    {13, 0x00001ff9}, {6, 0x00000015}, {8, 0x000000f8}, {11, 0x000007fa},
    {10, 0x000003fa}, {10, 0x000003fb}, {8, 0x000000f9}, {11, 0x000007fb},
    {8, 0x000000fa}, {6, 0x00000016}, {6, 0x00000017}, {6, 0x00000018},
    {5, 0x00000000}, {5, 0x00000001}, {5, 0x00000002}, {6, 0x00000019},
    {6, 0x0000001a}, {6, 0x0000001b}, {6, 0x0000001c}, {6, 0x0000001d},
    {6, 0x0000001e}, {6, 0x0000001f}, {7, 0x0000005c}, {8, 0x000000fb},
    {15, 0x00007ffc}, {6, 0x00000020}, {12, 0x00000ffb}, {10, 0x000003fc},
    {13, 0x00001ffa}, {6, 0x00000021}, {7, 0x0000005d}, {7, 0x0000005e},
    {7, 0x0000005f}, {7, 0x00000060}, {7, 0x00000061}, {7, 0x00000062},
    {7, 0x00000063}, {7, 0x00000064}, {7, 0x00000065}, {7, 0x00000066},
    {7, 0x00000067}, {7, 0x00000068}, {7, 0x00000069}, {7, 0x0000006a},
    {7, 0x0000006b}, {7, 0x0000006c}, {7, 0x0000006d}, {7, 0x0000006e},
    {7, 0x0000006f}, {7, 0x00000070}, {7, 0x00000071}, {7, 0x00000072},
    {8, 0x000000fc}, {7, 0x00000073}, {8, 0x000000fd}, {13, 0x00001ffb},
    {19, 0x0007fff0}, {13, 0x00001ffc}, {14, 0x00003ffc}, {6, 0x00000022},
    {15, 0x00007ffd}, {5, 0x00000003}, {6, 0x00000023}, {5, 0x00000004},
    {6, 0x00000024}, {5, 0x00000005}, {6, 0x00000025}, {6, 0x00000026},
    {6, 0x00000027}, {5, 0x00000006}, {7, 0x00000074}, {7, 0x00000075},
    {6, 0x00000028}, {6, 0x00000029}, {6, 0x0000002a}, {5, 0x00000007},
    {6, 0x0000002b}, {7, 0x00000076}, {6, 0x0000002c}, {5, 0x00000008},
    {5, 0x00000009}, {6, 0x0000002d}, {7, 0x00000077}, {7, 0x00000078},
    {7, 0x00000079}, {7, 0x0000007a}, {7, 0x0000007b}, {15, 0x00007ffe},
    {11, 0x000007fc}, {14, 0x00003ffd}, {13, 0x00001ffd}, {28, 0x0ffffffc},
    {20, 0x000fffe6}, {22, 0x003fffd2}, {20, 0x000fffe7}, {20, 0x000fffe8},
    {22, 0x003fffd3}, {22, 0x003fffd4}, {22, 0x003fffd5}, {23, 0x007fffd9},
    {22, 0x003fffd6}, {23, 0x007fffda}, {23, 0x007fffdb}, {23, 0x007fffdc},
    {23, 0x007fffdd}, {23, 0x007fffde}, {24, 0x00ffffeb}, {23, 0x007fffdf},
    {24, 0x00ffffec}, {24, 0x00ffffed}, {22, 0x003fffd7}, {23, 0x007fffe0},
    {24, 0x00ffffee}, {23, 0x007fffe1}, {23, 0x007fffe2}, {23, 0x007fffe3},
    {23, 0x007fffe4}, {21, 0x001fffdc}, {22, 0x003fffd8}, {23, 0x007fffe5},
    {22, 0x003fffd9}, {23, 0x007fffe6}, {23, 0x007fffe7}, {24, 0x00ffffef},
    {22, 0x003fffda}, {21, 0x001fffdd}, {20, 0x000fffe9}, {22, 0x003fffdb},
    {22, 0x003fffdc}, {23, 0x007fffe8}, {23, 0x007fffe9}, {21, 0x001fffde},
    {23, 0x007fffea}, {22, 0x003fffdd}, {22, 0x003fffde}, {24, 0x00fffff0},
    {21, 0x001fffdf}, {22, 0x003fffdf}, {23, 0x007fffeb}, {23, 0x007fffec},
    {21, 0x001fffe0}, {21, 0x001fffe1}, {22, 0x003fffe0}, {21, 0x001fffe2},
    {23, 0x007fffed}, {22, 0x003fffe1}, {23, 0x007fffee}, {23, 0x007fffef},
    {20, 0x000fffea}, {22, 0x003fffe2}, {22, 0x003fffe3}, {22, 0x003fffe4},
    {23, 0x007ffff0}, {22, 0x003fffe5}, {22, 0x003fffe6}, {23, 0x007ffff1},
    {26, 0x03ffffe0}, {26, 0x03ffffe1}, {20, 0x000fffeb}, {19, 0x0007fff1},
    {22, 0x003fffe7}, {23, 0x007ffff2}, {22, 0x003fffe8}, {25, 0x01ffffec},
    {26, 0x03ffffe2}, {26, 0x03ffffe3}, {26, 0x03ffffe4}, {27, 0x07ffffde},
    {27, 0x07ffffdf}, {26, 0x03ffffe5}, {24, 0x00fffff1}, {25, 0x01ffffed},
    {19, 0x0007fff2}, {21, 0x001fffe3}, {26, 0x03ffffe6}, {27, 0x07ffffe0},
    {27, 0x07ffffe1}, {26, 0x03ffffe7}, {27, 0x07ffffe2}, {24, 0x00fffff2},
    {21, 0x001fffe4}, {21, 0x001fffe5}, {26, 0x03ffffe8}, {26, 0x03ffffe9},
    {28, 0x0ffffffd}, {27, 0x07ffffe3}, {27, 0x07ffffe4}, {27, 0x07ffffe5},
    {20, 0x000fffec}, {24, 0x00fffff3}, {20, 0x000fffed}, {21, 0x001fffe6},
    {22, 0x003fffe9}, {21, 0x001fffe7}, {21, 0x001fffe8}, {23, 0x007ffff3},
    {22, 0x003fffea}, {22, 0x003fffeb}, {25, 0x01ffffee}, {25, 0x01ffffef},
    {24, 0x00fffff4}, {24, 0x00fffff5}, {26, 0x03ffffea}, {23, 0x007ffff4},
    {26, 0x03ffffeb}, {27, 0x07ffffe6}, {26, 0x03ffffec}, {26, 0x03ffffed},
    {27, 0x07ffffe7}, {27, 0x07ffffe8}, {27, 0x07ffffe9}, {27, 0x07ffffea},
    {27, 0x07ffffeb}, {28, 0x0ffffffe}, {27, 0x07ffffec}, {27, 0x07ffffed},
    {27, 0x07ffffee}, {27, 0x07ffffef}, {27, 0x07fffff0}, {26, 0x03ffffee},
    {30, 0x3fffffff},
};
#define HPACK_EOS_SYMBOL 256

/*
 * Huffman decode: linear scan over candidate lengths 5..30 at each bit
 * position, checking against the table for a match. O(entries) per
 * symbol decoded — not the fastest possible (a bit-trie would be
 * faster) but simplest to verify correct, matching this project's
 * general preference for verifiable-over-clever in reference code.
 * Bounded total output via out_cap; bounded work via MAX_SYMBOLS.
 */
#define MAX_HUFFMAN_SYMBOLS 2048

static bool hpack_huffman_decode(const uint8_t *data, size_t len,
                                  char *out, size_t out_cap, size_t *out_len) {
    size_t total_bits = len * 8;
    size_t bitpos = 0;
    size_t o = 0;
    int symbols_decoded = 0;

    while (bitpos < total_bits) {
        bool matched = false;

        for (int length = 5; length <= 30 && bitpos + (size_t)length <= total_bits; length++) {
            uint32_t code = 0;
            for (int i = 0; i < length; i++) {
                size_t bit_idx = bitpos + i;
                uint8_t byte = data[bit_idx / 8];
                uint8_t bit = (byte >> (7 - (bit_idx % 8))) & 1;
                code = (code << 1) | bit;
            }

            for (int sym = 0; sym < 257; sym++) {
                if (HPACK_HUFFMAN_TABLE[sym].length == length && HPACK_HUFFMAN_TABLE[sym].code == code) {
                    if (sym == HPACK_EOS_SYMBOL) {
                        /* RFC 7541 S5.2: a Huffman-encoded string literal
                         * containing the EOS symbol MUST be treated as a
                         * decoding error — this is not valid padding. */
                        return false;
                    }
                    if (o >= out_cap - 1) return false;   /* output would overflow: reject */
                    out[o++] = (char)sym;
                    bitpos += length;
                    matched = true;
                    break;
                }
            }
            if (matched) break;
        }

        if (!matched) {
            /* Remaining bits must be valid EOS-prefix padding: RFC 7541
             * S5.2 requires padding to be the most-significant bits of
             * the EOS code, strictly less than 8 bits. */
            size_t remaining = total_bits - bitpos;
            if (remaining >= 8) return false;   /* too long to be padding: reject */
            uint32_t pad_bits = 0;
            for (size_t i = 0; i < remaining; i++) {
                size_t bit_idx = bitpos + i;
                uint8_t byte = data[bit_idx / 8];
                uint8_t bit = (byte >> (7 - (bit_idx % 8))) & 1;
                pad_bits = (pad_bits << 1) | bit;
            }
            uint32_t expected = (HPACK_HUFFMAN_TABLE[HPACK_EOS_SYMBOL].code) >>
                                 (HPACK_HUFFMAN_TABLE[HPACK_EOS_SYMBOL].length - remaining);
            if (pad_bits != expected) return false;   /* wrong padding: reject per spec */
            break;
        }

        if (++symbols_decoded > MAX_HUFFMAN_SYMBOLS) return false;   /* sanity bound */
    }

    out[o] = '\0';
    *out_len = o;
    return true;
}

/* ==================================================================
 * Integer decoding, RFC 7541 S5.1.
 * ================================================================== */
static bool hpack_decode_integer(const uint8_t *data, size_t len, size_t *pos,
                                  int prefix_bits, uint64_t *out_value) {
    if (*pos >= len) return false;

    uint8_t prefix_mask = (uint8_t)((1 << prefix_bits) - 1);
    uint64_t value = data[*pos] & prefix_mask;
    (*pos)++;

    if (value < prefix_mask) {
        *out_value = value;
        return true;
    }

    uint64_t m = 0;
    uint8_t b;
    do {
        if (*pos >= len) return false;
        b = data[*pos];
        (*pos)++;
        value += (uint64_t)(b & 0x7F) << m;
        m += 7;
        if (m > 63) return false;   /* implementation limit: reject absurd encodings */
    } while (b & 0x80);

    *out_value = value;
    return true;
}

/* ==================================================================
 * String literal decoding, RFC 7541 S5.2.
 * ================================================================== */
static bool hpack_decode_string(const uint8_t *data, size_t len, size_t *pos,
                                 char *out, size_t out_cap) {
    if (*pos >= len) return false;

    bool huffman = (data[*pos] & 0x80) != 0;
    uint64_t str_len;
    if (!hpack_decode_integer(data, len, pos, 7, &str_len)) return false;

    if (*pos + str_len > len) return false;

    if (huffman) {
        size_t decoded_len;
        if (!hpack_huffman_decode(data + *pos, str_len, out, out_cap, &decoded_len)) {
            return false;
        }
    } else {
        if (str_len >= out_cap) return false;
        memcpy(out, data + *pos, str_len);
        out[str_len] = '\0';
    }

    *pos += str_len;
    return true;
}

/* ==================================================================
 * Dynamic table — FRESH PER CALL, see this file's header comment for
 * why that's a real, stated scope limit rather than a full
 * connection-persistent implementation.
 * ================================================================== */
#define HPACK_MAX_DYNAMIC_ENTRIES 64
#define HPACK_MAX_NAME_LEN 128
#define HPACK_MAX_VALUE_LEN 512

struct hpack_dynamic_entry {
    char name[HPACK_MAX_NAME_LEN];
    char value[HPACK_MAX_VALUE_LEN];
};

struct hpack_dynamic_table {
    struct hpack_dynamic_entry entries[HPACK_MAX_DYNAMIC_ENTRIES];
    int count;
    size_t total_size;   /* per RFC 7541 S4.1: sum of (name_len+value_len+32) */
    size_t max_size;
};

static void hpack_dynamic_table_init(struct hpack_dynamic_table *t, size_t max_size) {
    memset(t, 0, sizeof(*t));
    t->max_size = max_size;
}

static void hpack_dynamic_table_insert(struct hpack_dynamic_table *t,
                                        const char *name, const char *value) {
    size_t entry_size = strlen(name) + strlen(value) + 32;   /* RFC 7541 S4.1 */

    /* Evict from the end until there's room, per RFC 7541 S4.4. */
    while (t->count > 0 && t->total_size + entry_size > t->max_size) {
        struct hpack_dynamic_entry *last = &t->entries[t->count - 1];
        t->total_size -= strlen(last->name) + strlen(last->value) + 32;
        t->count--;
    }

    if (entry_size > t->max_size) return;   /* too big for the table even empty: not added */
    if (t->count >= HPACK_MAX_DYNAMIC_ENTRIES) return;   /* reference-implementation bound */

    /* Insert at the front (index 0 = newest, per RFC 7541 S2.3.2). */
    memmove(&t->entries[1], &t->entries[0], sizeof(struct hpack_dynamic_entry) * t->count);
    strncpy(t->entries[0].name, name, HPACK_MAX_NAME_LEN - 1);
    strncpy(t->entries[0].value, value, HPACK_MAX_VALUE_LEN - 1);
    t->count++;
    t->total_size += entry_size;
}

/*
 * Resolve an index into the combined static+dynamic address space,
 * RFC 7541 S2.3.3. Returns false (with dynamic_table_miss set) if the
 * index falls in the dynamic table's valid RANGE but this per-call
 * table doesn't actually have that entry (i.e. it would have come
 * from an earlier HEADERS frame we don't have — the scope limit
 * stated in this file's header comment made concrete).
 */
static bool hpack_resolve_index(uint64_t index, const struct hpack_dynamic_table *dyn,
                                 const char **out_name, const char **out_value,
                                 bool *dynamic_table_miss) {
    *dynamic_table_miss = false;
    if (index == 0) return false;   /* index 0 is invalid, RFC 7541 S6.1 */

    if (index <= 61) {
        *out_name = HPACK_STATIC_TABLE[index - 1].name;
        *out_value = HPACK_STATIC_TABLE[index - 1].value;
        return true;
    }

    uint64_t dyn_index = index - 61;
    if (dyn_index <= (uint64_t)dyn->count) {
        *out_name = dyn->entries[dyn_index - 1].name;
        *out_value = dyn->entries[dyn_index - 1].value;
        return true;
    }

    /* Index is in a plausible dynamic-table range but we don't have
     * that entry — almost certainly because it was created by an
     * earlier HEADERS frame this per-call decoder never saw. */
    *dynamic_table_miss = true;
    return false;
}

/* ==================================================================
 * Top-level header block decoder, RFC 7541 S6.
 *
 * Calls `on_header(name, value, user_ctx)` for each decoded header
 * field, in order. Returns false if the block couldn't be fully
 * decoded (malformed input, or a dynamic-table-miss on a reference
 * this per-call table can't resolve — see this file's header comment).
 * ================================================================== */
typedef void (*hpack_header_callback)(const char *name, const char *value, void *user_ctx);

static bool hpack_decode_header_block(const uint8_t *data, size_t len,
                                       size_t dynamic_table_max_size,
                                       hpack_header_callback on_header, void *user_ctx,
                                       bool *saw_dynamic_table_miss) {
    struct hpack_dynamic_table dyn;
    hpack_dynamic_table_init(&dyn, dynamic_table_max_size);
    *saw_dynamic_table_miss = false;

    size_t pos = 0;
    int fields_decoded = 0;

    while (pos < len && fields_decoded < 256) {   /* sanity bound per header block */
        uint8_t first_byte = data[pos];
        char name_buf[HPACK_MAX_NAME_LEN];
        char value_buf[HPACK_MAX_VALUE_LEN];

        if (first_byte & 0x80) {
            /* Indexed Header Field, RFC 7541 S6.1 */
            uint64_t index;
            if (!hpack_decode_integer(data, len, &pos, 7, &index)) return false;

            const char *name, *value;
            bool miss;
            if (!hpack_resolve_index(index, &dyn, &name, &value, &miss)) {
                if (miss) *saw_dynamic_table_miss = true;
                return false;
            }
            on_header(name, value ? value : "", user_ctx);

        } else if (first_byte & 0x40) {
            /* Literal Header Field with Incremental Indexing, RFC 7541 S6.2.1 */
            uint64_t index;
            if (!hpack_decode_integer(data, len, &pos, 6, &index)) return false;

            const char *name;
            if (index == 0) {
                if (!hpack_decode_string(data, len, &pos, name_buf, sizeof(name_buf))) return false;
                name = name_buf;
            } else {
                const char *dummy_val; bool miss;
                if (!hpack_resolve_index(index, &dyn, &name, &dummy_val, &miss)) {
                    if (miss) *saw_dynamic_table_miss = true;
                    return false;
                }
            }

            if (!hpack_decode_string(data, len, &pos, value_buf, sizeof(value_buf))) return false;
            on_header(name, value_buf, user_ctx);
            hpack_dynamic_table_insert(&dyn, name, value_buf);

        } else if ((first_byte & 0xE0) == 0x20) {
            /* Dynamic Table Size Update, RFC 7541 S6.3 */
            uint64_t new_size;
            if (!hpack_decode_integer(data, len, &pos, 5, &new_size)) return false;
            if (new_size > dyn.max_size) return false;   /* MUST NOT exceed protocol limit */
            dyn.max_size = new_size;
            while (dyn.count > 0 && dyn.total_size > dyn.max_size) {
                struct hpack_dynamic_entry *last = &dyn.entries[dyn.count - 1];
                dyn.total_size -= strlen(last->name) + strlen(last->value) + 32;
                dyn.count--;
            }
            continue;   /* no header field produced by this instruction */

        } else {
            /* Literal Header Field without Indexing (S6.2.2, '0000' prefix)
             * or Never Indexed (S6.2.3, '0001' prefix) — identical wire
             * format, differing only in re-encoding policy, which this
             * read-only decoder has no reason to distinguish. */
            uint64_t index;
            if (!hpack_decode_integer(data, len, &pos, 4, &index)) return false;

            const char *name;
            if (index == 0) {
                if (!hpack_decode_string(data, len, &pos, name_buf, sizeof(name_buf))) return false;
                name = name_buf;
            } else {
                const char *dummy_val; bool miss;
                if (!hpack_resolve_index(index, &dyn, &name, &dummy_val, &miss)) {
                    if (miss) *saw_dynamic_table_miss = true;
                    return false;
                }
            }

            if (!hpack_decode_string(data, len, &pos, value_buf, sizeof(value_buf))) return false;
            on_header(name, value_buf, user_ctx);
            /* NOT inserted into the dynamic table — that's the entire
             * point of "without indexing" / "never indexed". */
        }

        fields_decoded++;
    }

    return true;
}
