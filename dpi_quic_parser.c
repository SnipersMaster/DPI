/*
 * dpi_quic_parser.c
 *
 * QUIC (RFC 9000) Initial packet dissector — extracts the SNI from the
 * TLS ClientHello carried inside QUIC's Initial packet, per the
 * RFC 9001 key derivation that makes Initial packets deliberately
 * inspectable by network observers (this is a documented, intentional
 * property of the protocol, not a weakness being exploited — RFC 9001
 * S5.2 exists specifically so middleboxes/DPI CAN see the handshake).
 *
 * Everything past the Initial handshake (1-RTT application data) is
 * genuinely encrypted with keys never observable from the wire — this
 * module cannot and does not attempt anything beyond the Initial
 * packet's SNI.
 *
 * REQUIRES OpenSSL (libssl-dev). Build:
 *   gcc -O2 -Wall -o dpi_quic_test dpi_quic_parser.c -lssl -lcrypto
 *
 * VALIDATION STATUS: the logic in this file has been cross-checked
 * line-by-line against RFC 9001's own pseudocode (S5.2 initial secrets,
 * S5.3 AEAD/nonce/AAD construction, S5.4.1-5.4.3 header protection) —
 * salt value, label lengths, AAD boundaries, and the sample-offset
 * formula all match the spec text. This is NOT the same as validation
 * against byte-exact test vectors — RFC 9001 Appendix A.2 publishes a
 * full worked example (DCID 0x8394c8f03e515708) specifically for this
 * purpose, and this code has not yet been run against those exact
 * bytes. Do that before trusting this on real traffic.
 *
 * KNOWN SIMPLIFICATION: packet number reconstruction here just uses
 * the truncated bytes directly as the value, not the full RFC 9000
 * S17.1 algorithm (which reconstructs relative to the largest
 * previously-acknowledged packet number in that space). This is
 * correct for a connection's first Initial packet — the case that
 * matters for SNI extraction — but would need the real algorithm for
 * general-purpose QUIC packet handling beyond the first packet.
 *
 * -------------------------------------------------------------------
 * WHY OPENSSL AND NOT HAND-ROLLED AES/HKDF
 * -------------------------------------------------------------------
 * "Never roll your own crypto" applies here even though the QUIC
 * Initial keys aren't protecting a secret from us (that's the whole
 * point). A hand-rolled AES-GCM or HKDF implementation is still a new
 * place to introduce a timing side channel, a buffer overrun, or a
 * subtly wrong AEAD construction — none of which buys anything, since
 * a well-audited library does the same job correctly. This is the
 * "secure coding & build" protocol from the very first checklist in
 * this conversation applied literally.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define QUIC_INITIAL_SALT_LEN 20
static const uint8_t QUIC_V1_INITIAL_SALT[QUIC_INITIAL_SALT_LEN] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};
/* RFC 9001 S5.2. Verify this constant against the RFC text yourself
 * before relying on it — see the file header comment. */

#define QUIC_VERSION_1   0x00000001u
#define MAX_QUIC_PACKET  1500
#define MAX_CID_LEN      20
#define SHA256_LEN       32
#define AES128_KEY_LEN   16
#define AES_GCM_IV_LEN   12
#define AES_GCM_TAG_LEN  16

/* ------------------------------------------------------------------
 * QUIC variable-length integer decoding, RFC 9000 S16. The two
 * high bits of the first byte encode the length (1/2/4/8 bytes).
 * ------------------------------------------------------------------ */
static bool quic_varint_decode(const uint8_t *p, size_t remaining,
                                uint64_t *out_val, size_t *out_len) {
    if (remaining < 1) return false;
    uint8_t first = p[0];
    uint8_t len_bits = first >> 6;
    size_t len = 1u << len_bits;   /* 1, 2, 4, or 8 */
    if (remaining < len) return false;

    uint64_t val = first & 0x3F;
    for (size_t i = 1; i < len; i++) {
        val = (val << 8) | p[i];
    }
    *out_val = val;
    *out_len = len;
    return true;
}

/* ------------------------------------------------------------------
 * HKDF-Extract / HKDF-Expand-Label, RFC 5869 + RFC 8446 S7.1 (TLS 1.3
 * key schedule, reused directly by QUIC per RFC 9001 S5.1). Implemented
 * directly over OpenSSL's HMAC() rather than EVP_PKEY_CTX's HKDF API,
 * since the manual HMAC construction is simpler to get right and
 * easier to verify line-by-line against the RFC pseudocode.
 * ------------------------------------------------------------------ */
static bool hkdf_extract(const uint8_t *salt, size_t salt_len,
                          const uint8_t *ikm, size_t ikm_len,
                          uint8_t *out_prk /* SHA256_LEN bytes */) {
    unsigned int out_len = 0;
    uint8_t *res = HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len,
                         out_prk, &out_len);
    return res != NULL && out_len == SHA256_LEN;
}

/* HKDF-Expand-Label per RFC 8446 S7.1:
 *   HkdfLabel = length(2) || "tls13 " + label (1-byte length prefixed)
 *               || context (1-byte length prefixed, empty for QUIC)
 * QUIC uses the TLS 1.3 labels directly (RFC 9001 S5.1), e.g. "client in",
 * "quic key", "quic iv", "quic hp" — NOT prefixed with "tls13 " again;
 * the "tls13 " prefix is added by HKDF-Expand-Label itself per the
 * TLS 1.3 spec, applied uniformly to every label QUIC passes in.
 */
static bool hkdf_expand_label(const uint8_t *secret, size_t secret_len,
                               const char *label, uint16_t out_len,
                               uint8_t *out) {
    uint8_t info[256];
    size_t pos = 0;

    info[pos++] = (uint8_t)(out_len >> 8);
    info[pos++] = (uint8_t)(out_len & 0xFF);

    char full_label[64];
    int label_len = snprintf(full_label, sizeof(full_label), "tls13 %s", label);
    if (label_len < 0 || (size_t)label_len > sizeof(full_label)) return false;

    info[pos++] = (uint8_t)label_len;
    memcpy(info + pos, full_label, (size_t)label_len);
    pos += (size_t)label_len;

    info[pos++] = 0;   /* empty context, per RFC 9001's use of this function */

    /* HKDF-Expand (RFC 5869 S2.3), single-block case is enough since
     * every QUIC-derived value here is <= 32 bytes = 1 SHA-256 block. */
    if (out_len > SHA256_LEN) return false;  /* would need multi-block expand; not needed here */

    uint8_t t[SHA256_LEN];
    uint8_t hmac_input[300];
    memcpy(hmac_input, info, pos);
    hmac_input[pos] = 0x01;   /* counter byte, first (only) block */

    unsigned int t_len = 0;
    uint8_t *res = HMAC(EVP_sha256(), secret, (int)secret_len,
                         hmac_input, pos + 1, t, &t_len);
    if (!res || t_len != SHA256_LEN) return false;

    memcpy(out, t, out_len);
    return true;
}

struct quic_keys {
    uint8_t key[AES128_KEY_LEN];
    uint8_t iv[AES_GCM_IV_LEN];
    uint8_t hp[AES128_KEY_LEN];
};

static bool derive_quic_initial_keys(const uint8_t *dcid, size_t dcid_len,
                                      struct quic_keys *client_keys) {
    uint8_t initial_secret[SHA256_LEN];
    if (!hkdf_extract(QUIC_V1_INITIAL_SALT, QUIC_INITIAL_SALT_LEN,
                       dcid, dcid_len, initial_secret)) {
        return false;
    }

    uint8_t client_initial_secret[SHA256_LEN];
    if (!hkdf_expand_label(initial_secret, SHA256_LEN, "client in",
                            SHA256_LEN, client_initial_secret)) {
        return false;
    }

    if (!hkdf_expand_label(client_initial_secret, SHA256_LEN, "quic key",
                            AES128_KEY_LEN, client_keys->key)) return false;
    if (!hkdf_expand_label(client_initial_secret, SHA256_LEN, "quic iv",
                            AES_GCM_IV_LEN, client_keys->iv)) return false;
    if (!hkdf_expand_label(client_initial_secret, SHA256_LEN, "quic hp",
                            AES128_KEY_LEN, client_keys->hp)) return false;

    return true;
}

/* ------------------------------------------------------------------
 * Header protection removal, RFC 9001 S5.4. AES-128-ECB(hp_key, sample)
 * produces a 5-byte mask used to unmask the first byte's low bits and
 * the (now-revealed-length) packet number field.
 * ------------------------------------------------------------------ */
static bool aes_ecb_encrypt_block(const uint8_t *key, const uint8_t *in16, uint8_t *out16) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    int len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) == 1) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (EVP_EncryptUpdate(ctx, out16, &len, in16, 16) == 1 && len == 16) {
            ok = true;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* ------------------------------------------------------------------
 * AEAD_AES_128_GCM decrypt, RFC 9001 S5.3 / RFC 5116. `nonce` is the
 * client IV XORed with the packet number, per RFC 9001 S5.3.
 * ------------------------------------------------------------------ */
static bool aes_gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *ciphertext, size_t ct_len,
                             const uint8_t *tag,
                             uint8_t *plaintext_out, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    int len = 0, total = 0;

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1) break;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) break;
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) break;
        if (EVP_DecryptUpdate(ctx, plaintext_out, &len, ciphertext, (int)ct_len) != 1) break;
        total = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN,
                                 (void *)tag) != 1) break;
        if (EVP_DecryptFinal_ex(ctx, plaintext_out + total, &len) != 1) break;
        total += len;
        *plaintext_len = total;
        ok = true;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* ------------------------------------------------------------------
 * detect() — QUIC Initial packet structural check. Long-header form
 * bit set, fixed bit set, Initial packet type, and (for QUIC v1) the
 * known version number. Deliberately does NOT depend on port at all —
 * QUIC is commonly used on 443 alongside/instead of TCP+TLS, and
 * increasingly on nonstandard ports too.
 * ------------------------------------------------------------------ */
static double quic_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    (void)dst_port;
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < 7) return 0.0;   /* header form + version at minimum */

    uint8_t first_byte = payload[0];
    bool long_header = (first_byte & 0x80) != 0;
    bool fixed_bit    = (first_byte & 0x40) != 0;
    if (!long_header || !fixed_bit) return 0.0;

    uint8_t packet_type = (first_byte >> 4) & 0x03;
    if (packet_type != 0x00) return 0.0;   /* 0x00 = Initial */

    uint32_t version = (payload[1]<<24)|(payload[2]<<16)|(payload[3]<<8)|payload[4];
    if (version == QUIC_VERSION_1) return 0.85;
    if (version == 0x00000000) return 0.0;   /* version negotiation packet, not Initial */

    return 0.4;   /* long-header Initial-shaped but unrecognized version:
                    * plausible QUIC, lower confidence since we can't
                    * derive keys for a version we don't have a salt for */
}

/* ------------------------------------------------------------------
 * dissect() — full path: parse header, derive keys, remove header
 * protection, AEAD-decrypt, find the CRYPTO frame, hand its contents
 * to the existing TLS ClientHello / SNI parser from dpi_app_classifier.c.
 * ------------------------------------------------------------------ */
static void quic_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t pos = 5;   /* past first byte + 4-byte version */
    if (pos >= len) { dissect_result_add(out, "parse_error", "truncated_header"); return; }

    uint8_t dcid_len = payload[pos++];
    if (dcid_len > MAX_CID_LEN || pos + dcid_len > len) {
        dissect_result_add(out, "parse_error", "invalid_dcid_length");
        return;
    }
    const uint8_t *dcid = payload + pos;
    pos += dcid_len;

    if (pos >= len) { dissect_result_add(out, "parse_error", "truncated_after_dcid"); return; }
    uint8_t scid_len = payload[pos++];
    if (scid_len > MAX_CID_LEN || pos + scid_len > len) {
        dissect_result_add(out, "parse_error", "invalid_scid_length");
        return;
    }
    pos += scid_len;

    uint64_t token_len = 0; size_t vlen = 0;
    if (!quic_varint_decode(payload + pos, len - pos, &token_len, &vlen)) {
        dissect_result_add(out, "parse_error", "truncated_token_length"); return;
    }
    pos += vlen;
    if (pos + token_len > len) { dissect_result_add(out, "parse_error", "invalid_token_length"); return; }
    pos += token_len;

    uint64_t payload_field_len = 0;
    if (!quic_varint_decode(payload + pos, len - pos, &payload_field_len, &vlen)) {
        dissect_result_add(out, "parse_error", "truncated_length_field"); return;
    }
    size_t length_field_start = pos;
    pos += vlen;
    size_t pn_offset = pos;   /* protected packet number starts here */

    if (pos + payload_field_len > len || payload_field_len < AES_GCM_TAG_LEN) {
        dissect_result_add(out, "parse_error", "invalid_payload_length");
        return;
    }

    struct quic_keys keys;
    if (!derive_quic_initial_keys(dcid, dcid_len, &keys)) {
        dissect_result_add(out, "parse_error", "key_derivation_failed");
        return;
    }

    /* Header protection removal, RFC 9001 S5.4.2. Sample starts 4
     * bytes into the (as-yet-unknown-length) packet number field. */
    if (pn_offset + 4 + 16 > len) {
        dissect_result_add(out, "parse_error", "truncated_for_hp_sample");
        return;
    }
    const uint8_t *sample = payload + pn_offset + 4;
    uint8_t mask[16];
    if (!aes_ecb_encrypt_block(keys.hp, sample, mask)) {
        dissect_result_add(out, "parse_error", "header_protection_removal_failed");
        return;
    }

    uint8_t unprotected_first_byte = payload[0] ^ (mask[0] & 0x0F);   /* long header: low 4 bits */
    uint8_t pn_len = (unprotected_first_byte & 0x03) + 1;

    uint8_t pn_bytes[4] = {0};
    for (int i = 0; i < pn_len; i++) {
        pn_bytes[i] = payload[pn_offset + i] ^ mask[1 + i];
    }
    uint32_t packet_number = 0;
    for (int i = 0; i < pn_len; i++) packet_number = (packet_number << 8) | pn_bytes[i];

    /* AAD = the entire header exactly as transmitted, but with the
     * first byte and packet number bytes UNPROTECTED (RFC 9001 S5.3). */
    uint8_t aad[256];
    if (pn_offset + pn_len > sizeof(aad)) {
        dissect_result_add(out, "parse_error", "header_too_large_for_aad_buffer");
        return;
    }
    memcpy(aad, payload, pn_offset + pn_len);
    aad[0] = unprotected_first_byte;
    memcpy(aad + pn_offset, pn_bytes, pn_len);

    /* Nonce = client IV XOR packet number (left-padded to 12 bytes). */
    uint8_t nonce[AES_GCM_IV_LEN];
    memcpy(nonce, keys.iv, AES_GCM_IV_LEN);
    for (int i = 0; i < 4; i++) {
        nonce[AES_GCM_IV_LEN - 1 - i] ^= (uint8_t)((packet_number >> (8 * i)) & 0xFF);
    }

    size_t ct_offset = pn_offset + pn_len;
    size_t ct_len = (length_field_start + vlen + payload_field_len) - ct_offset - AES_GCM_TAG_LEN;
    const uint8_t *ciphertext = payload + ct_offset;
    const uint8_t *tag = payload + ct_offset + ct_len;

    /* Stack-allocated, NOT static — this function is called concurrently
     * from multiple lcores in dpi_dpdk_worker.c's multi-core design. A
     * `static` buffer here would be shared across all callers and
     * corrupt each other's decrypted output under concurrent access.
     * This was a real bug in an earlier version of this file, caught
     * when wiring QUIC into the multi-core capture path — the
     * single-core bootstrap would never have exposed it, since it only
     * ever has one caller at a time. 1500 bytes is small enough that
     * the stack is the right place for this regardless. */
    uint8_t plaintext[MAX_QUIC_PACKET];
    int plaintext_len = 0;
    if (!aes_gcm_decrypt(keys.key, nonce, aad, pn_offset + pn_len,
                          ciphertext, ct_len, tag, plaintext, &plaintext_len)) {
        dissect_result_add(out, "parse_error", "aead_decrypt_failed_or_auth_tag_mismatch");
        return;
    }

    /* Walk decrypted QUIC frames looking for a CRYPTO frame (type
     * 0x06). RFC 9000 S19.6: type(varint) + offset(varint) +
     * length(varint) + data. A production implementation needs to
     * handle CRYPTO frame reassembly (offset != 0, split across
     * multiple Initial packets) — this reference version only handles
     * the common case of the whole ClientHello fitting in one frame
     * starting at offset 0, and flags anything else rather than
     * guessing. */
    size_t fp = 0;
    while (fp < (size_t)plaintext_len) {
        uint64_t frame_type = 0; size_t flen = 0;
        if (!quic_varint_decode(plaintext + fp, plaintext_len - fp, &frame_type, &flen)) break;
        fp += flen;

        if (frame_type == 0x00) continue;          /* PADDING, single byte, no length field */
        if (frame_type == 0x02 || frame_type == 0x03) break; /* ACK: skip parsing rest, out of scope here */

        if (frame_type == 0x06) {   /* CRYPTO frame */
            uint64_t crypto_offset = 0, crypto_len = 0;
            size_t l1, l2;
            if (!quic_varint_decode(plaintext + fp, plaintext_len - fp, &crypto_offset, &l1)) break;
            fp += l1;
            if (!quic_varint_decode(plaintext + fp, plaintext_len - fp, &crypto_len, &l2)) break;
            fp += l2;
            if (fp + crypto_len > (size_t)plaintext_len) break;

            if (crypto_offset != 0) {
                dissect_result_add(out, "parse_warning", "crypto_frame_reassembly_needed_not_implemented");
                return;
            }

            /* Hand off to the existing TLS ClientHello/SNI parser.
             * extract_sni_from_clienthello_body() (dpi_app_classifier.c)
             * expects a bare ClientHello body with no TLS record-layer
             * wrapper — which is exactly what a QUIC CRYPTO frame
             * contains (RFC 9001 S4.1.3: "QUIC takes the unprotected
             * content of TLS handshake records as the content of
             * CRYPTO frames. TLS record protection is not used by
             * QUIC."). Note this is the ClientHello BODY, not
             * including the handshake message header (msg_type+length)
             * that would normally precede it — skip those 4 bytes too. */
            extern bool extract_sni_from_clienthello_body(const uint8_t *data, size_t len,
                                                            struct sni_result *out);
            /* struct sni_result mirrors the definition in
             * dpi_app_classifier.c — kept in sync manually here since
             * these files aren't yet split into proper shared headers
             * (see the README's build-system note). A real build
             * should replace this with #include "dpi_tls_sni.h". */
            struct sni_result {
                bool     found;
                char     hostname[256];
                uint16_t hostname_len;
            };

            if (crypto_len < 4) {
                dissect_result_add(out, "parse_warning", "crypto_frame_too_short_for_handshake_header");
                return;
            }
            /* Handshake message header inside the CRYPTO frame: msg_type(1) + length(3) */
            const uint8_t *hs = plaintext + fp;
            if (hs[0] != 0x01 /* ClientHello */) {
                dissect_result_add(out, "quic_handshake_msg_type_not_clienthello", "true");
                return;
            }
            uint32_t inner_hs_len = (hs[1]<<16)|(hs[2]<<8)|hs[3];
            if (4 + inner_hs_len > crypto_len) {
                dissect_result_add(out, "parse_warning", "clienthello_length_exceeds_crypto_frame");
                return;
            }

            struct sni_result sni;
            if (extract_sni_from_clienthello_body(hs + 4, inner_hs_len, &sni) && sni.found) {
                dissect_result_add(out, "sni", sni.hostname);
                dissect_result_add(out, "quic_version", "1");
            } else {
                dissect_result_add(out, "quic_version", "1");
                dissect_result_add(out, "sni_absent", "true");   /* ECH, or no SNI sent */
            }
            return;
        }

        /* Unrecognized/unhandled frame type in this reference parser:
         * we don't know its length encoding, so we can't safely skip
         * past it and keep scanning. Stop here rather than guess. */
        break;
    }

    dissect_result_add(out, "parse_warning", "no_crypto_frame_found_in_first_packet");
}

static const uint16_t quic_hint_ports[] = { 443 };

void register_quic_dissector(void) {
    register_dissector("QUIC", quic_detect, quic_dissect, quic_hint_ports, 1);
}
