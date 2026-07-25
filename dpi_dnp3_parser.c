/*
 * dpi_dnp3_parser.c
 *
 * DNP3 (IEEE 1815, "Distributed Network Protocol") dissector — a
 * second ICS/SCADA protocol alongside Modbus, requested explicitly as
 * a "cheaper, rounds out ICS/SCADA coverage" option in this project's
 * protocol recommendation table.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * -------------------------------------------------------------------
 * VERIFICATION METHODOLOGY — read before trusting the field layout
 * -------------------------------------------------------------------
 * Unlike most of this project's plaintext dissectors (which follow
 * RFCs this project's author could cross-check directly), DNP3's
 * governing spec is IEEE 1815, a paid standard not available to
 * search/fetch here. Instead, the frame layout below was verified
 * against real, independently-captured, CRC-confirmed-good DNP3
 * frames from two separate sources (a GitHub DNP3 implementation's
 * README and a protocol-analysis notes site), cross-checked against
 * each other and against an official-looking DNP3 quick-reference
 * PDF's function-code table — all three agree exactly on the Control
 * byte's bit layout (DIR/PRM/FCB-or-DFC/FCV/function-code) and the
 * Transport/Application Control bytes' FIR/FIN/sequence-number
 * layout. One additional source (a tutorial blog post) had an
 * internally-inconsistent example that was DISCARDED in favor of the
 * two mutually-consistent real captures — a genuine discrepancy was
 * found and resolved by trusting the sources that agreed with each
 * other and with the official function-code table, not just picking
 * one source at random.
 *
 * This is a real, if secondhand, verification — stronger than "looked
 * plausible" — but it is NOT the same confidence level as the
 * from-scratch, byte-exact test-vector verification this project did
 * for HPACK's Huffman table or QUIC's key derivation, where the
 * primary source document itself was directly checked. Treat this
 * dissector as verified-by-corroboration, not verified-by-primary-source.
 *
 * -------------------------------------------------------------------
 * SCOPE
 * -------------------------------------------------------------------
 * Data Link Layer (10-byte header): start-byte validation, length,
 * Control byte (DIR/PRM/FCB-or-DFC/FCV bits + data-link function
 * code), Destination/Source addresses (little-endian — confirmed via
 * explicit "Low Byte Ahead" source text, not inferred from an
 * ambiguous small test value). The header CRC is NOT verified (DNP3's
 * CRC-16 uses polynomial 0x3D65, a specific enough algorithm that
 * getting it subtly wrong is a real risk without a way to test it
 * here — skipped rather than risk asserting a checksum result that
 * might be wrong).
 *
 * Transport + Application Layer parsing (FIR/FIN/sequence + Application
 * function code) is attempted ONLY when the frame's declared user data
 * fits within a SINGLE 16-byte data-link block — DNP3 requires a 2-byte
 * CRC after every 16 bytes of user data, and reassembling user data
 * that spans multiple such CRC-delimited blocks is a real piece of
 * work this pass doesn't attempt (flagged via
 * dnp3_multi_block_user_data_not_reassembled rather than silently
 * misparsed). Many real DNP3 requests (simple reads, single-object
 * writes) fit in one block, so this covers a meaningful fraction of
 * traffic, not a token case.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define DNP3_PORT 20000
#define DNP3_START_BYTE_1 0x05
#define DNP3_START_BYTE_2 0x64
#define DNP3_HDR_LEN 10   /* Start(2)+Length(1)+Control(1)+Dest(2)+Src(2)+CRC(2) */
#define DNP3_MAX_BLOCK_USER_DATA 16

static const char *dnp3_link_function_name(uint8_t prm, uint8_t func) {
    if (prm) {
        /* Primary (master-originated) station function codes */
        switch (func) {
            case 0:  return "RESET_LINK_STATES";
            case 2:  return "TEST_LINK_STATES";
            case 3:  return "CONFIRMED_USER_DATA";
            case 4:  return "UNCONFIRMED_USER_DATA";
            case 9:  return "REQUEST_LINK_STATUS";
            default: return "Unknown";
        }
    } else {
        /* Secondary (outstation-originated) station function codes */
        switch (func) {
            case 0:  return "ACK";
            case 1:  return "NACK";
            case 0xB: return "LINK_STATUS";
            case 0xF: return "NOT_SUPPORTED";
            default: return "Unknown";
        }
    }
}

static const char *dnp3_app_function_name(uint8_t fc) {
    /* A small, well-known subset — DNP3 defines many more application
     * function codes (file transfer, authentication, etc.) than are
     * confidently included here; anything else is named "Unknown"
     * rather than guessed at. */
    switch (fc) {
        case 0x01: return "READ";
        case 0x02: return "WRITE";
        case 0x03: return "SELECT";
        case 0x04: return "OPERATE";
        case 0x05: return "DIRECT_OPERATE";
        case 0x06: return "DIRECT_OPERATE_NO_ACK";
        case 0x0D: return "COLD_RESTART";
        case 0x0E: return "WARM_RESTART";
        case 0x81: return "RESPONSE";
        case 0x82: return "UNSOLICITED_RESPONSE";
        default:   return "Unknown";
    }
}

static double dnp3_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;   /* DNP3 also runs over
                                                       * serial lines, not
                                                       * applicable here */
    if (len < DNP3_HDR_LEN) return 0.0;
    if (payload[0] != DNP3_START_BYTE_1 || payload[1] != DNP3_START_BYTE_2) return 0.0;

    uint8_t declared_len = payload[2];
    if (declared_len < 5) return 0.0;   /* must cover at least Control+Dest+Src */

    double confidence = 0.7;   /* the 0x0564 start-byte match is a fairly
                                 * strong structural signal on its own */
    if (dst_port == DNP3_PORT) confidence = 0.9;
    return confidence;
}

static void dnp3_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint8_t declared_len = payload[2];
    uint8_t control = payload[3];
    uint16_t destination = payload[4] | (payload[5] << 8);   /* little-endian */
    uint16_t source = payload[6] | (payload[7] << 8);        /* little-endian */
    /* payload[8..9] = header CRC, not verified — see file header comment */

    uint8_t dir_bit = (control >> 7) & 1;
    uint8_t prm_bit = (control >> 6) & 1;
    uint8_t link_func = control & 0x0F;

    dissect_result_add(out, "dnp3_direction", dir_bit ? "master_to_outstation" : "outstation_to_master");
    dissect_result_add(out, "dnp3_link_function", dnp3_link_function_name(prm_bit, link_func));

    char buf[16];
    snprintf(buf, sizeof(buf), "%u", destination);
    dissect_result_add(out, "dnp3_destination", buf);
    snprintf(buf, sizeof(buf), "%u", source);
    dissect_result_add(out, "dnp3_source", buf);

    if (prm_bit) {
        uint8_t fcv_bit = (control >> 4) & 1;
        uint8_t fcb_bit = (control >> 5) & 1;
        dissect_result_add(out, "dnp3_fcv", fcv_bit ? "true" : "false");
        if (fcv_bit) dissect_result_add(out, "dnp3_fcb", fcb_bit ? "true" : "false");
    } else {
        uint8_t dfc_bit = (control >> 4) & 1;
        dissect_result_add(out, "dnp3_dfc", dfc_bit ? "true" : "false");
    }

    /* User data length = declared_len - 5 (Control+Dest+Src already
     * counted in declared_len per the format: Length covers Control
     * through end of user data, i.e. 5 fixed bytes + user data). */
    if (declared_len < 5) return;   /* already checked in detect(), defensive here too */
    size_t user_data_len = declared_len - 5;

    if (user_data_len == 0) return;   /* link-layer-only frame (e.g. ACK/NACK/RESET) */

    if (user_data_len > DNP3_MAX_BLOCK_USER_DATA) {
        dissect_result_add(out, "dnp3_multi_block_user_data_not_reassembled", "true");
        return;
    }

    /* Single-block case: user data immediately follows the 10-byte
     * header (no intervening CRC yet, since this block hasn't hit the
     * 16-byte boundary). Bounds-check against what's actually in the
     * buffer, not just what the frame claims. */
    if ((size_t)DNP3_HDR_LEN + user_data_len > len) {
        dissect_result_add(out, "parse_warning", "user_data_exceeds_available_length");
        return;
    }
    const uint8_t *user_data = payload + DNP3_HDR_LEN;

    if (user_data_len < 1) return;
    uint8_t transport_control = user_data[0];
    bool t_fir = (transport_control >> 7) & 1;
    bool t_fin = (transport_control >> 6) & 1;
    uint8_t t_seq = transport_control & 0x3F;

    dissect_result_add(out, "dnp3_transport_fir", t_fir ? "true" : "false");
    dissect_result_add(out, "dnp3_transport_fin", t_fin ? "true" : "false");
    snprintf(buf, sizeof(buf), "%u", t_seq);
    dissect_result_add(out, "dnp3_transport_sequence", buf);

    if (user_data_len < 3) return;   /* need at least transport(1) + app control(1) + function(1) */
    uint8_t app_control = user_data[1];
    uint8_t app_function = user_data[2];

    bool a_fir = (app_control >> 7) & 1;
    bool a_fin = (app_control >> 6) & 1;
    uint8_t a_seq = app_control & 0x3F;

    dissect_result_add(out, "dnp3_app_fir", a_fir ? "true" : "false");
    dissect_result_add(out, "dnp3_app_fin", a_fin ? "true" : "false");
    snprintf(buf, sizeof(buf), "%u", a_seq);
    dissect_result_add(out, "dnp3_app_sequence", buf);
    dissect_result_add(out, "dnp3_app_function", dnp3_app_function_name(app_function));

    /* Object headers / data objects (Group+Variation+Qualifier+Range)
     * that follow are not parsed in this pass — genuinely a separate,
     * substantial piece of work (DNP3 has a large, extensible object
     * library), matching the "extract the envelope, not everything
     * inside it" scope limit already used for GTPv2-C's less common
     * IEs and Modbus's less common function codes. */
}

static const uint16_t dnp3_hint_ports[] = { DNP3_PORT };

void register_dnp3_dissector(void) {
    register_dissector("DNP3", dnp3_detect, dnp3_dissect, dnp3_hint_ports, 1);
}

