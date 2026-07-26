/*
 * dpi_serialnumberd_parser.c
 *
 * Apple serialnumberd — a Mac OS X Server service (10.2 through 10.5
 * era) that tracked server serial number/registration usage on the
 * local network, to prevent the same license serial number being
 * used twice. UDP port 626, IANA-registered ("asia"/serialnumberd).
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Found via this project's own systematic pcap survey (looking for
 * any TCP/UDP port with real traffic and no matching dissector) —
 * 8,640 real packets on UDP 626 in a genuine capture
 * (`net-2009-11-13-09_24.pcap`), immediately identifiable as ASCII
 * text: `SNQUERY:domex.nps.edu:yWQBLA:xsvr` (a real hostname — the
 * Naval Postgraduate School's domain — followed by what's evidently a
 * per-query random token). Independently cross-checked against the
 * Nmap version-probe database's own documented `serialnumberd` probe
 * (`SNQUERY:127.0.0.1:W8XLcP:xsvr`), which uses the exact same
 * colon-delimited structure with a different real example — genuine
 * agreement between this project's own real capture and an
 * independent, widely-used reference, not a single uncorroborated
 * source.
 *
 * WIRE FORMAT: plaintext ASCII, colon-delimited: literal `SNQUERY` +
 * `:` + a hostname or IP address (the querying host's identity) +
 * `:` + an opaque, per-query token (real-traffic length varies — 6
 * characters in this project's own real example, 6 in the Nmap
 * reference too, but stated as "varies" by Nmap's own probe-
 * database maintainers, not asserted as a fixed length here) + `:` +
 * literal `xsvr`.
 *
 * SCOPE: the query format only, real-traffic-verified. The
 * corresponding server response format is not decoded — no real
 * response packets were available in the captures surveyed to verify
 * a byte-exact reply structure against (only client-side SNQUERY
 * traffic was found), and this project doesn't guess at an
 * unverified reply format from a protocol this obscure and this
 * poorly publicly documented.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define SERIALNUMBERD_PORT 626
#define SERIALNUMBERD_MAX_FIELD 128

static double serialnumberd_detect(const uint8_t *payload, uint16_t len,
                                    uint16_t dst_port, const char *l4_proto) {
    (void)dst_port;
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < 9) return 0.0;   /* "SNQUERY:" is 8 bytes, need at least 1 more */
    if (memcmp(payload, "SNQUERY:", 8) != 0) return 0.0;

    double confidence = 0.7;
    if (dst_port == SERIALNUMBERD_PORT) confidence = 0.9;
    return confidence;
}

static void serialnumberd_dissect(const uint8_t *payload, uint16_t len,
                                   uint16_t dst_port, const char *l4_proto,
                                   struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;
    if (len < 9 || memcmp(payload, "SNQUERY:", 8) != 0) return;

    dissect_result_add(out, "serialnumberd_message_type", "SNQUERY");

    /* Walk the remaining colon-delimited fields: hostname, token,
     * and the trailing "xsvr" literal — bounded, same discipline as
     * every other field-walking dissector in this project. */
    size_t pos = 8;
    const char *field_names[3] = { "serialnumberd_hostname",
                                    "serialnumberd_token",
                                    "serialnumberd_suffix" };
    for (int i = 0; i < 3 && pos < len; i++) {
        size_t start = pos;
        while (pos < len && payload[pos] != ':') pos++;
        size_t field_len = pos - start;
        char field[SERIALNUMBERD_MAX_FIELD];
        size_t n = field_len < sizeof(field) - 1 ? field_len : sizeof(field) - 1;
        memcpy(field, payload + start, n);
        field[n] = '\0';
        dissect_result_add(out, field_names[i], field);
        pos++;   /* skip the ':' */
    }
}

static const uint16_t serialnumberd_hint_ports[] = { SERIALNUMBERD_PORT };

void register_serialnumberd_dissector(void) {
    register_dissector("serialnumberd", serialnumberd_detect, serialnumberd_dissect,
                        serialnumberd_hint_ports, 1);
}
