/*
 * dpi_modbus_parser.c
 *
 * Modbus/TCP dissector (Modbus Application Protocol Specification
 * V1.1b3) — an industrial/SCADA protocol, genuinely distinct from
 * everything else built in this project so far (nothing else here
 * targets ICS/OT network visibility). Chosen over SMB (higher effort,
 * more complex binary structure) and POP3/IMAP (lower distinct value
 * given SMTP already covers similar mail-protocol ground) as the next
 * protocol addition — see the README's protocol recommendation table.
 * (Since updated: SMB1 and POP3 were both later built —
 * `dpi_smb1_parser.c`, `dpi_pop3_parser.c` — once they became the
 * clear next candidates; SMB2/3 and IMAP remain the genuinely open
 * items from this original comparison.)
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Wire format: MBAP header (7 bytes) + PDU (function code + data).
 *   MBAP: Transaction Identifier(2) + Protocol Identifier(2, always 0
 *         for Modbus) + Length(2, byte count of everything from Unit
 *         Identifier onward) + Unit Identifier(1)
 *   PDU:  Function Code(1) + Data(variable, function-code-specific)
 *
 * SCOPE: extracts transaction ID, unit ID, function code (+ name), and
 * for the most common function codes (Read Coils/Discrete Inputs/
 * Holding Registers/Input Registers, Write Single Coil/Register) the
 * starting address and quantity/value. Exception responses (function
 * code with the high bit set) are flagged with their exception code.
 * Less common function codes (Read/Write Multiple Registers with full
 * data payload decoding, diagnostics, file record access) are
 * recognized by name but their data payloads aren't decoded further —
 * same "extract what's most useful, not everything" pattern as every
 * other dissector in this project.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define MODBUS_PORT 502
#define MBAP_HDR_LEN 7

static const char *modbus_function_name(uint8_t fc) {
    switch (fc & 0x7F) {   /* mask off the exception-response high bit for lookup */
        case 1:  return "Read Coils";
        case 2:  return "Read Discrete Inputs";
        case 3:  return "Read Holding Registers";
        case 4:  return "Read Input Registers";
        case 5:  return "Write Single Coil";
        case 6:  return "Write Single Register";
        case 7:  return "Read Exception Status";
        case 8:  return "Diagnostics";
        case 15: return "Write Multiple Coils";
        case 16: return "Write Multiple Registers";
        case 17: return "Report Server ID";
        case 20: return "Read File Record";
        case 21: return "Write File Record";
        case 22: return "Mask Write Register";
        case 23: return "Read/Write Multiple Registers";
        case 24: return "Read FIFO Queue";
        case 43: return "Encapsulated Interface Transport";
        default: return "Unknown";
    }
}

static const char *modbus_exception_name(uint8_t code) {
    switch (code) {
        case 1: return "Illegal Function";
        case 2: return "Illegal Data Address";
        case 3: return "Illegal Data Value";
        case 4: return "Server Device Failure";
        case 5: return "Acknowledge";
        case 6: return "Server Device Busy";
        case 8: return "Memory Parity Error";
        case 10: return "Gateway Path Unavailable";
        case 11: return "Gateway Target Device Failed to Respond";
        default: return "Unknown";
    }
}

static double modbus_detect(const uint8_t *payload, uint16_t len,
                             uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "TCP") != 0) return 0.0;   /* Modbus/TCP is TCP-only
                                                       * (Modbus/RTU/ASCII are
                                                       * serial-line variants,
                                                       * not applicable here) */
    if (len < MBAP_HDR_LEN + 1) return 0.0;

    uint16_t protocol_id = (payload[2] << 8) | payload[3];
    if (protocol_id != 0) return 0.0;   /* Modbus's Protocol Identifier is
                                          * always 0 — a strong structural
                                          * signal, not just a port guess */

    uint16_t declared_len = (payload[4] << 8) | payload[5];
    if (declared_len < 2 || (size_t)MBAP_HDR_LEN - 1 + declared_len > len) return 0.0;

    double confidence = 0.6;
    if (dst_port == MODBUS_PORT) confidence = 0.9;
    return confidence;
}

static void modbus_dissect(const uint8_t *payload, uint16_t len,
                            uint16_t dst_port, const char *l4_proto,
                            struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    uint16_t transaction_id = (payload[0] << 8) | payload[1];
    uint16_t declared_len = (payload[4] << 8) | payload[5];
    uint8_t unit_id = payload[6];
    uint8_t function_code = payload[7];

    char buf[16];
    snprintf(buf, sizeof(buf), "%u", transaction_id);
    dissect_result_add(out, "modbus_transaction_id", buf);
    snprintf(buf, sizeof(buf), "%u", unit_id);
    dissect_result_add(out, "modbus_unit_id", buf);
    dissect_result_add(out, "modbus_function", modbus_function_name(function_code));

    const uint8_t *data = payload + MBAP_HDR_LEN + 1;
    /* declared_len counts Unit Identifier(1) + function code(1) + data;
     * the data portion alone is declared_len - 2, bounds-checked
     * against what's actually available in this buffer. */
    size_t data_len = (declared_len >= 2) ? (size_t)(declared_len - 2) : 0;
    size_t available = (len > (size_t)(MBAP_HDR_LEN + 1)) ? len - MBAP_HDR_LEN - 1 : 0;
    if (data_len > available) data_len = available;

    if (function_code & 0x80) {
        /* Exception response: data is exactly one byte, the exception code */
        dissect_result_add(out, "modbus_exception_response", "true");
        if (data_len >= 1) {
            dissect_result_add(out, "modbus_exception_code", modbus_exception_name(data[0]));
        }
        return;
    }

    uint8_t base_fc = function_code;
    if ((base_fc >= 1 && base_fc <= 4) && data_len >= 4) {
        /* Read Coils/Discrete Inputs/Holding Registers/Input
         * Registers REQUEST shape: Starting Address(2) + Quantity(2).
         * (A RESPONSE to these has a different shape — byte count +
         * raw data — which this dissector doesn't have enough context
         * to distinguish from a request without tracking transaction
         * state across the request/response pair, so this
         * interpretation is only reliable for requests; flagged via
         * the field name itself rather than asserted unconditionally.) */
        uint16_t addr = (data[0] << 8) | data[1];
        uint16_t qty = (data[2] << 8) | data[3];
        snprintf(buf, sizeof(buf), "%u", addr);
        dissect_result_add(out, "modbus_request_start_address", buf);
        snprintf(buf, sizeof(buf), "%u", qty);
        dissect_result_add(out, "modbus_request_quantity", buf);
    } else if ((base_fc == 5 || base_fc == 6) && data_len >= 4) {
        /* Write Single Coil/Register: Address(2) + Value(2) */
        uint16_t addr = (data[0] << 8) | data[1];
        uint16_t value = (data[2] << 8) | data[3];
        snprintf(buf, sizeof(buf), "%u", addr);
        dissect_result_add(out, "modbus_write_address", buf);
        snprintf(buf, sizeof(buf), "%u", value);
        dissect_result_add(out, "modbus_write_value", buf);
    }
    /* Other function codes: name already extracted above; data payload
     * not decoded further — same bounds-checked-but-not-exhaustive
     * pattern as GTPv2-C's less common IE types. */
}

static const uint16_t modbus_hint_ports[] = { MODBUS_PORT };

void register_modbus_dissector(void) {
    register_dissector("Modbus", modbus_detect, modbus_dissect, modbus_hint_ports, 1);
}
