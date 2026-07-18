/*
 * dpi_protocol_config.c
 *
 * Central protocol configuration — the "arsenal": one file
 * (protocols.ini) that controls which dissectors are active, instead
 * of that decision being hardcoded across register_all_dissectors().
 *
 * SCOPE NOTE, stated upfront: this controls ENABLE/DISABLE only, read
 * once at startup before the RX loop begins — it does NOT hot-reload
 * the way domain_rules.ini does. That's a deliberate difference, not
 * an oversight: domain rules are looked up on every classified flow,
 * so re-reading them live makes sense. Dissector REGISTRATION happens
 * once, before any packet is processed — the registry
 * (dpi_dissector_registry.c) has no "unregister" operation, so
 * toggling a protocol off mid-run isn't something the current
 * architecture supports. Restart to pick up a protocols.ini change.
 * Making registration itself dynamic is a reasonable future addition,
 * not attempted here.
 *
 * NOT COMPILED/TESTED in this environment.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>

#define MAX_PROTOCOL_ENTRIES 64
#define MAX_PROTOCOL_NAME_LEN 32

struct protocol_config_entry {
    char name[MAX_PROTOCOL_NAME_LEN];
    bool enabled;
};

static struct protocol_config_entry g_protocol_config[MAX_PROTOCOL_ENTRIES];
static int g_n_protocol_config = 0;
static bool g_protocol_config_loaded = false;

static char *pc_trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/*
 * Load protocols.ini. Format (flat, no sections needed — this is a
 * simple enable/disable list, not domain_rules.ini's categorized
 * structure):
 *   ; comment
 *   radius = true
 *   quic = true
 *   gtp = false
 *
 * Unknown/missing entries default to ENABLED — a protocol not
 * mentioned in the file is on by default, matching the principle that
 * this config exists to let you turn things OFF you don't want, not
 * as a strict allowlist that silently disables anything unlisted
 * (which would be a confusing default for anyone extending this with
 * a new protocol and forgetting to add a line for it).
 */
static bool load_protocol_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "protocol_config: cannot open '%s' (%s) — "
                "all protocols default to ENABLED\n", path, strerror(errno));
        g_protocol_config_loaded = true;   /* "loaded" with zero overrides is valid */
        return true;
    }

    char line[256];
    int line_no = 0;
    while (fgets(line, sizeof(line), f)) {
        line_no++;
        char *l = pc_trim(line);
        if (*l == '\0' || *l == ';' || *l == '#') continue;

        char *eq = strchr(l, '=');
        if (!eq) {
            fprintf(stderr, "protocol_config: %s:%d: no '=', skipping\n", path, line_no);
            continue;
        }
        *eq = '\0';
        char *key = pc_trim(l);
        char *val = pc_trim(eq + 1);

        bool enabled;
        if (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0) enabled = true;
        else if (strcasecmp(val, "false") == 0 || strcmp(val, "0") == 0) enabled = false;
        else {
            fprintf(stderr, "protocol_config: %s:%d: value must be true/false, "
                    "got '%s', skipping\n", path, line_no, val);
            continue;
        }

        if (g_n_protocol_config >= MAX_PROTOCOL_ENTRIES) {
            fprintf(stderr, "protocol_config: too many entries, ignoring rest\n");
            break;
        }
        struct protocol_config_entry *e = &g_protocol_config[g_n_protocol_config++];
        strncpy(e->name, key, MAX_PROTOCOL_NAME_LEN - 1);
        e->enabled = enabled;
    }

    fclose(f);
    g_protocol_config_loaded = true;
    fprintf(stderr, "protocol_config: loaded %d override(s) from %s\n",
            g_n_protocol_config, path);
    return true;
}

/* Default-enabled if never loaded or not explicitly listed — see the
 * rationale in this file's header comment. */
static bool protocol_enabled(const char *name) {
    if (!g_protocol_config_loaded) return true;
    for (int i = 0; i < g_n_protocol_config; i++) {
        if (strcasecmp(g_protocol_config[i].name, name) == 0) {
            return g_protocol_config[i].enabled;
        }
    }
    return true;
}
