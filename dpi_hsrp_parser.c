/*
 * dpi_hsrp_parser.c
 *
 * HSRP (Hot Standby Router Protocol, Cisco-proprietary, informational
 * RFC 2281 for v1) dissector — UDP port 1985, multicast to
 * 224.0.0.2. Router redundancy: a set of routers elect an Active and
 * Standby to share a Virtual IP, exchanged via periodic Hello
 * messages.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 338 real HSRP packets from a genuine capture
 * (Johannes Weber's "Ultimate PCAP") — hand-decoded a real 20-byte
 * packet byte-for-byte before writing any C: hellotime=3s, holdtime=
 * 10s, priority=100 (a common real default), the well-known plaintext
 * authentication string "cisco" (HSRPv1's own documented default, not
 * a coincidence), and a sensible virtual IP (192.168.20.1).
 *
 * WIRE FORMAT (HSRPv1, RFC 2281, fixed 20 bytes): Version(1) + Op
 * Code(1, 0=Hello/1=Coup/2=Resign) + State(1, 0=Initial/1=Learn/
 * 2=Listen/4=Speak/8=Standby/16=Active) + Hellotime(1, seconds) +
 * Holdtime(1, seconds) + Priority(1) + Group(1) + Reserved(1) +
 * Authentication Data(8, a plaintext password padded with nulls —
 * "cisco" is HSRPv1's own documented default) + Virtual IP Address(4).
 *
 * A REAL FINDING FROM VERIFICATION, stated honestly: this capture's
 * real HSRP traffic is a MIX of two different versions — 167 packets
 * matched HSRPv1's 20-byte shape exactly (confirmed above), but 156
 * packets were 72 bytes with a completely different field layout
 * (byte 0 = 1, byte 1 = 40 — neither matches any valid HSRPv1 Version/
 * OpCode value), almost certainly HSRPv2 with MD5 authentication
 * (which adds a TLV-based authentication extension HSRPv1 doesn't
 * have). Rather than guess at HSRPv2's exact byte offsets without
 * being confident in them — HSRPv2 was never formally standardized in
 * an RFC the way v1 was, and this project doesn't have authoritative
 * documentation for it in hand to verify against the way every other
 * dissector here was verified — this dissector only fully decodes
 * HSRPv1 and flags anything else (wrong length, or fields outside
 * HSRPv1's valid ranges) as "unrecognized, possibly HSRPv2" rather
 * than asserting field values it can't confirm are correct. Two
 * smaller fragment shapes (6 and 16 bytes, 5 and 10 real packets
 * respectively) were also seen and are likewise left unrecognized
 * rather than guessed at.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define HSRP_V1_LEN 20

static const char *hsrp_opcode_name(uint8_t opcode) {
    switch (opcode) {
        case 0: return "Hello";
        case 1: return "Coup";
        case 2: return "Resign";
        default: return "Unknown";
    }
}

static const char *hsrp_state_name(uint8_t state) {
    switch (state) {
        case 0: return "Initial";
        case 1: return "Learn";
        case 2: return "Listen";
        case 4: return "Speak";
        case 8: return "Standby";
        case 16: return "Active";
        default: return "Unknown";
    }
}

static double hsrp_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < 6) return 0.0;   /* shortest real fragment shape seen was 6 bytes */

    double confidence = 0.5;
    if (dst_port == 1985) confidence = 0.8;

    if (len == HSRP_V1_LEN) {
        uint8_t opcode = payload[1];
        if (opcode <= 2) confidence = (dst_port == 1985) ? 0.9 : 0.6;
    }
    return confidence;
}

static void hsrp_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    if (len != HSRP_V1_LEN) {
        dissect_result_add(out, "hsrp_recognized_version", "unrecognized_possibly_v2");
        char lenbuf[8];
        snprintf(lenbuf, sizeof(lenbuf), "%u", len);
        dissect_result_add(out, "hsrp_unrecognized_length", lenbuf);
        return;
    }

    uint8_t version = payload[0];
    uint8_t opcode = payload[1];
    uint8_t state = payload[2];

    if (opcode > 2) {
        /* Right length, but OpCode isn't a valid HSRPv1 value —
         * matches the real 72-byte-vs-20-byte confusion risk this
         * file's header warns about; better to flag than assert. */
        dissect_result_add(out, "hsrp_recognized_version", "unrecognized_possibly_v2");
        return;
    }

    dissect_result_add(out, "hsrp_recognized_version", "v1");
    char buf[16];
    snprintf(buf, sizeof(buf), "%u", version);
    dissect_result_add(out, "hsrp_version", buf);
    dissect_result_add(out, "hsrp_opcode", hsrp_opcode_name(opcode));
    dissect_result_add(out, "hsrp_state", hsrp_state_name(state));
    snprintf(buf, sizeof(buf), "%u", payload[3]);
    dissect_result_add(out, "hsrp_hellotime", buf);
    snprintf(buf, sizeof(buf), "%u", payload[4]);
    dissect_result_add(out, "hsrp_holdtime", buf);
    snprintf(buf, sizeof(buf), "%u", payload[5]);
    dissect_result_add(out, "hsrp_priority", buf);
    snprintf(buf, sizeof(buf), "%u", payload[6]);
    dissect_result_add(out, "hsrp_group", buf);
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", payload[16], payload[17], payload[18], payload[19]);
    dissect_result_add(out, "hsrp_virtual_ip", buf);
    /* Authentication data (bytes 8-15) is a plaintext password in
     * HSRPv1 — deliberately NOT extracted, same credential-handling
     * discipline as RADIUS/LDAP/SNMP/FTP throughout this project, even
     * though HSRPv1's own documented default value is publicly known
     * ("cisco") — a real deployment may have changed it to something
     * that shouldn't be surfaced. */
    dissect_result_add(out, "hsrp_auth_data_present", "true");
}

static const uint16_t hsrp_hint_ports[] = { 1985 };

void register_hsrp_dissector(void) {
    register_dissector("HSRP", hsrp_detect, hsrp_dissect, hsrp_hint_ports, 1);
}
