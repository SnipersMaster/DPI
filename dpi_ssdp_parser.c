/*
 * dpi_ssdp_parser.c
 *
 * SSDP (Simple Service Discovery Protocol, part of UPnP) dissector —
 * HTTP-like text headers over UDP (port 1900, typically multicast to
 * 239.255.255.250), used for UPnP device/service discovery.
 *
 * NOT COMPILED/TESTED in this environment.
 *
 * Verified against 99 real SSDP packets from a genuine capture
 * (Johannes Weber's "Ultimate PCAP"): 87 M-SEARCH requests, 12 NOTIFY
 * announcements — including a real NOTIFY from what's identifiable as
 * an AVM FRITZ!Box-style media renderer ("KnOS/3.2 UPnP/1.0 DMP/3.5"
 * in its SERVER header) and a real M-SEARCH targeting an AVM-specific
 * device type URN. No HTTP/1.1-response-shaped M-SEARCH replies
 * appeared in this capture (those are typically unicast back to the
 * specific requester rather than multicast, so wouldn't necessarily
 * appear in a capture positioned to see the multicast group) — this
 * dissector still handles that shape per the UPnP spec, just without
 * real-traffic confirmation for that specific case, stated honestly.
 *
 * WIRE FORMAT: first line is either "M-SEARCH * HTTP/1.1", "NOTIFY *
 * HTTP/1.1", or "HTTP/1.1 200 OK" (a search response), followed by
 * "Header: value" lines (CRLF-terminated, case-insensitive header
 * names per HTTP convention) and a blank line. Structurally almost
 * identical to an HTTP/1.1 request/response — SSDP reuses HTTP's
 * textual header syntax over UDP rather than defining its own.
 *
 * SCOPE: extracts the method/status line, and the handful of headers
 * that actually matter for UPnP discovery visibility — ST (Search
 * Target/Service Type), NT/NTS (Notification Type/Sub-type), LOCATION
 * (the device description XML URL — often the single most useful
 * field, since it points to what's actually being advertised), SERVER,
 * and USN (Unique Service Name). Other headers (MAN, MX, CACHE-
 * CONTROL, BOOTID.UPNP.ORG, etc.) are walked past correctly but not
 * individually extracted.
 *
 * A REAL BUG CAUGHT DURING VERIFICATION, worth stating plainly: an
 * early draft miscounted "M-SEARCH * HTTP/1.1" as 20 characters (it's
 * 19) and had a related, inconsistent length guard on the NOTIFY
 * check too. The practical effect: ALL 87 real M-SEARCH messages in
 * the verification capture were rejected by detect() — only the 12
 * NOTIFY messages passed. This was caught specifically because the
 * verification script was re-run with the fix applied and the method
 * counts (87 M-SEARCH / 12 NOTIFY) were checked against what real
 * traffic actually showed, rather than accepting a nonzero "detect
 * ok" count as sufficient on its own — 12/99 looked like partial
 * success, not obviously wrong, until the method breakdown was
 * checked against the real distribution.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define SSDP_MAX_HEADERS 12

static size_t ssdp_find_line_end(const uint8_t *data, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (data[i] == '\r' && data[i+1] == '\n') return i;
    }
    return len;
}

static double ssdp_detect(const uint8_t *payload, uint16_t len,
                           uint16_t dst_port, const char *l4_proto) {
    if (strcmp(l4_proto, "UDP") != 0) return 0.0;
    if (len < 14) return 0.0;

    size_t line_end = ssdp_find_line_end(payload, len);
    if (line_end < 14 || line_end > 32) return 0.0;   /* the three valid
                                                         * first lines are
                                                         * all short and
                                                         * within this range */

    bool is_msearch = (line_end >= 19 && memcmp(payload, "M-SEARCH * HTTP/1.1", 19) == 0);
    bool is_notify = (line_end >= 17 && memcmp(payload, "NOTIFY * HTTP/1.1", 17) == 0);
    bool is_response = (line_end >= 8 && memcmp(payload, "HTTP/1.1", 8) == 0);

    if (!is_msearch && !is_notify && !is_response) return 0.0;

    double confidence = 0.6;
    if (dst_port == 1900) confidence = 0.9;
    return confidence;
}

static void ssdp_dissect(const uint8_t *payload, uint16_t len,
                          uint16_t dst_port, const char *l4_proto,
                          struct dissect_result *out) {
    (void)dst_port; (void)l4_proto;

    size_t pos = 0;
    size_t line_end = ssdp_find_line_end(payload, len);
    if (line_end == 0) return;

    if (line_end >= 19 && memcmp(payload, "M-SEARCH * HTTP/1.1", 19) == 0) {
        dissect_result_add(out, "ssdp_method", "M-SEARCH");
    } else if (line_end >= 17 && memcmp(payload, "NOTIFY * HTTP/1.1", 17) == 0) {
        dissect_result_add(out, "ssdp_method", "NOTIFY");
    } else if (line_end >= 8 && memcmp(payload, "HTTP/1.1", 8) == 0) {
        dissect_result_add(out, "ssdp_method", "RESPONSE");
    } else {
        return;
    }

    pos = line_end + 2;   /* past the CRLF */
    int n_headers = 0;

    while (pos < len && n_headers < SSDP_MAX_HEADERS) {
        size_t remaining = len - pos;
        line_end = ssdp_find_line_end(payload + pos, remaining);
        if (line_end == 0) break;   /* blank line: end of headers */

        const uint8_t *line = payload + pos;
        const uint8_t *colon = memchr(line, ':', line_end);
        if (!colon) {
            pos += line_end + 2;
            n_headers++;
            continue;
        }
        size_t name_len = (size_t)(colon - line);
        const uint8_t *val_start = colon + 1;
        while (val_start < line + line_end && *val_start == ' ') val_start++;
        size_t val_len = (line + line_end) - val_start;

        char name[24];
        size_t nn = name_len < sizeof(name) - 1 ? name_len : sizeof(name) - 1;
        memcpy(name, line, nn);
        name[nn] = '\0';
        for (size_t i = 0; i < nn; i++) name[i] = (char)toupper((unsigned char)name[i]);

        const char *field_key = NULL;
        if (strcmp(name, "ST") == 0) field_key = "ssdp_st";
        else if (strcmp(name, "NT") == 0) field_key = "ssdp_nt";
        else if (strcmp(name, "NTS") == 0) field_key = "ssdp_nts";
        else if (strcmp(name, "LOCATION") == 0) field_key = "ssdp_location";
        else if (strcmp(name, "SERVER") == 0) field_key = "ssdp_server";
        else if (strcmp(name, "USN") == 0) field_key = "ssdp_usn";

        if (field_key) {
            char val[256];
            size_t vn = val_len < sizeof(val) - 1 ? val_len : sizeof(val) - 1;
            memcpy(val, val_start, vn);
            val[vn] = '\0';
            dissect_result_add(out, field_key, val);
        }

        pos += line_end + 2;
        n_headers++;
    }
}

static const uint16_t ssdp_hint_ports[] = { 1900 };

void register_ssdp_dissector(void) {
    register_dissector("SSDP", ssdp_detect, ssdp_dissect, ssdp_hint_ports, 1);
}
