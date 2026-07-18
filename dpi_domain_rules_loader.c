/*
 * dpi_domain_rules_loader.c
 *
 * Loads domain classification rules from an external INI file instead
 * of a hardcoded table, so categories/apps/domains can be updated by
 * editing domain_rules.ini and reloading — no rebuild, no redeploy.
 *
 * File format (see domain_rules.ini for a full sample):
 *   [category_name]
 *   domain.suffix = App Display Name
 *
 * Design choices:
 *   - Rules live in a heap-allocated, realloc-grown array. No fixed
 *     cap baked into the code — the file controls the size.
 *   - reload_domain_rules_if_changed() stats the file's mtime and only
 *     re-parses when it's changed, so this is cheap to call on a timer
 *     or before each classification burst without adding real overhead.
 *   - The swap from old rules to new rules is atomic from the caller's
 *     perspective: a fresh array is built, then a single pointer swap
 *     replaces the live table. A reader mid-lookup during a reload
 *     will finish against a consistent view. (For a multi-threaded
 *     classifier, wrap the swap itself in a lock or use an RCU-style
 *     pattern — noted at the bottom, not implemented here.)
 *   - Malformed lines are skipped with a logged warning, not treated
 *     as fatal — a typo in the config shouldn't take the engine down.
 *
 * NOT COMPILED/TESTED against a live filesystem in this environment.
 * Validate path handling and file permissions in your lab deployment.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <stdatomic.h>

#define MAX_LINE_LEN      512
#define MAX_SECTION_LEN   64
#define MAX_SUFFIX_LEN    128
#define MAX_APPNAME_LEN   64

struct domain_rule {
    char suffix[MAX_SUFFIX_LEN];
    char category[MAX_SECTION_LEN];
    char app_name[MAX_APPNAME_LEN];
};

struct domain_rule_table {
    struct domain_rule *rules;
    size_t count;
    size_t capacity;
    time_t loaded_mtime;
    char   path[512];
};

/* The live, in-use table. Swapped atomically on reload — see the
 * thread-safety note above table_add and the swap logic in
 * reload_domain_rules_if_changed() below. */
static _Atomic(struct domain_rule_table *) g_active_table = NULL;

/*
 * RETIRED-TABLE GRACE PERIOD
 * --------------------------
 * A reader on another core may have just loaded g_active_table right
 * before a reload swaps it out. Freeing the old table immediately
 * would let that reader dereference freed memory. Rather than a full
 * RCU implementation (hazard pointers, epoch reclamation), this uses
 * a simple bounded retirement list: the last N retired tables are kept
 * alive and only actually freed once N more reloads have happened.
 * Since domain_rules.ini reloads are infrequent (config edits, not a
 * per-packet event) and each in-flight classify_hostname() call is
 * short (a single loop over a few hundred rules), a handful of reload
 * cycles is a generous grace period in practice.
 *
 * This is NOT a substitute for proper RCU/hazard-pointer reclamation
 * in a design that reloads frequently or has long-running readers —
 * it's a pragmatic bound appropriate for "config file edited a few
 * times a day," which is domain_rules.ini's actual use pattern.
 */
#define RETIRED_TABLE_GRACE_SLOTS 4
static struct domain_rule_table *g_retired[RETIRED_TABLE_GRACE_SLOTS] = {0};
static int g_retired_next = 0;

static void retire_table(struct domain_rule_table *old) {
    if (!old) return;
    struct domain_rule_table *to_free = g_retired[g_retired_next];
    g_retired[g_retired_next] = old;
    g_retired_next = (g_retired_next + 1) % RETIRED_TABLE_GRACE_SLOTS;
    if (to_free) {
        free(to_free->rules);
        free(to_free);
    }
}

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static struct domain_rule_table *table_create(void) {
    struct domain_rule_table *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->capacity = 64;
    t->rules = malloc(t->capacity * sizeof(struct domain_rule));
    if (!t->rules) { free(t); return NULL; }
    return t;
}

static bool table_add(struct domain_rule_table *t, const char *suffix,
                       const char *category, const char *app_name) {
    if (t->count == t->capacity) {
        size_t new_cap = t->capacity * 2;
        struct domain_rule *grown = realloc(t->rules, new_cap * sizeof(struct domain_rule));
        if (!grown) return false;
        t->rules = grown;
        t->capacity = new_cap;
    }
    struct domain_rule *r = &t->rules[t->count];
    strncpy(r->suffix, suffix, MAX_SUFFIX_LEN - 1);
    r->suffix[MAX_SUFFIX_LEN - 1] = '\0';
    strncpy(r->category, category, MAX_SECTION_LEN - 1);
    r->category[MAX_SECTION_LEN - 1] = '\0';
    strncpy(r->app_name, app_name, MAX_APPNAME_LEN - 1);
    r->app_name[MAX_APPNAME_LEN - 1] = '\0';
    t->count++;
    return true;
}

/*
 * Validate that `suffix` looks like a plausible domain suffix, not a
 * malformed entry that would silently never match anything (like the
 * `microsoft.com/security` mistake from an earlier revision of this
 * file — that entry parsed fine as a string but could never match a
 * real SNI, since hostnames never contain a path).
 *
 * This is deliberately a conservative, low-false-positive check: it
 * rejects things that are DEFINITELY wrong (paths, whitespace, illegal
 * characters, no dot at all), not things that are merely unusual (a
 * single-label suffix like "t.co" is fine and used in this file).
 * Returns NULL if valid, or a short reason string if not.
 */
static const char *validate_suffix(const char *suffix) {
    size_t len = strlen(suffix);

    if (len < 3) return "too short to be a real domain suffix";
    if (len >= MAX_SUFFIX_LEN) return "exceeds max suffix length";

    if (strchr(suffix, '/') || strchr(suffix, '\\')) {
        return "contains a path separator — SNI values are hostnames, never paths";
    }
    if (strchr(suffix, ' ') || strchr(suffix, '\t')) {
        return "contains whitespace";
    }
    if (strchr(suffix, '@') || strchr(suffix, ':')) {
        return "contains a character not valid in a hostname";
    }
    if (suffix[0] == '.' || suffix[len - 1] == '.') {
        return "starts or ends with a dot";
    }
    if (strstr(suffix, "..")) {
        return "contains a double dot";
    }
    if (!strchr(suffix, '.')) {
        return "no dot found — not a valid domain suffix (bare TLD or typo?)";
    }

    for (size_t i = 0; i < len; i++) {
        char c = suffix[i];
        bool ok = isalnum((unsigned char)c) || c == '.' || c == '-' || c == '_';
        if (!ok) return "contains a character not valid in a hostname";
    }

    return NULL;   /* valid */
}

/*
 * Detect a suffix that's already present in the table being built.
 * Not fatal — a duplicate with a DIFFERENT category/app-name is a
 * config authoring mistake worth flagging (which one wins is decided
 * by table_add order, which is easy to get wrong by accident), but
 * shouldn't block the load.
 */
static bool table_has_suffix(struct domain_rule_table *t, const char *suffix) {
    for (size_t i = 0; i < t->count; i++) {
        if (strcasecmp(t->rules[i].suffix, suffix) == 0) return true;
    }
    return false;
}


static struct domain_rule_table *parse_domain_rules_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "domain_rules: cannot open '%s': %s\n", path, strerror(errno));
        return NULL;
    }

    struct domain_rule_table *t = table_create();
    if (!t) { fclose(f); return NULL; }
    strncpy(t->path, path, sizeof(t->path) - 1);

    char line[MAX_LINE_LEN];
    char current_section[MAX_SECTION_LEN] = "uncategorized";
    int line_no = 0;
    int skipped_count = 0;

    while (fgets(line, sizeof(line), f)) {
        line_no++;
        char *l = trim(line);

        if (*l == '\0' || *l == ';' || *l == '#') continue;   /* blank/comment */

        if (*l == '[') {
            char *close = strchr(l, ']');
            if (!close) {
                fprintf(stderr, "domain_rules: %s:%d: unterminated section header, skipping\n",
                        path, line_no);
                skipped_count++;
                continue;
            }
            size_t sect_len = (size_t)(close - l - 1);
            if (sect_len >= MAX_SECTION_LEN) sect_len = MAX_SECTION_LEN - 1;
            strncpy(current_section, l + 1, sect_len);
            current_section[sect_len] = '\0';
            continue;
        }

        char *eq = strchr(l, '=');
        if (!eq) {
            fprintf(stderr, "domain_rules: %s:%d: no '=' found, skipping line: %s\n",
                    path, line_no, l);
            skipped_count++;
            continue;
        }

        *eq = '\0';
        char *key = trim(l);
        char *val = trim(eq + 1);

        if (*key == '\0' || *val == '\0') {
            fprintf(stderr, "domain_rules: %s:%d: empty key or value, skipping\n", path, line_no);
            skipped_count++;
            continue;
        }
        if (strlen(key) >= MAX_SUFFIX_LEN || strlen(val) >= MAX_APPNAME_LEN) {
            fprintf(stderr, "domain_rules: %s:%d: key/value too long, skipping\n", path, line_no);
            skipped_count++;
            continue;
        }

        const char *invalid_reason = validate_suffix(key);
        if (invalid_reason) {
            fprintf(stderr, "domain_rules: %s:%d: invalid suffix '%s' (%s), skipping\n",
                    path, line_no, key, invalid_reason);
            skipped_count++;
            continue;
        }

        if (table_has_suffix(t, key)) {
            fprintf(stderr, "domain_rules: %s:%d: WARNING duplicate suffix '%s' "
                    "(already defined earlier in this file) — first definition wins, "
                    "this line is ignored. Check for a copy-paste or category mistake.\n",
                    path, line_no, key);
            skipped_count++;
            continue;
        }

        if (!table_add(t, key, current_section, val)) {
            fprintf(stderr, "domain_rules: %s:%d: allocation failure, stopping load\n",
                    path, line_no);
            break;
        }
    }

    fclose(f);
    fprintf(stderr, "domain_rules: loaded %zu rules from %s (%d line(s) skipped due to "
            "validation errors — see warnings above)\n", t->count, path, skipped_count);
    return t;
}

static time_t file_mtime(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return st.st_mtime;
}

/*
 * Call this at startup, and periodically (e.g. once/sec from a
 * management thread, or before each classification burst — it's cheap
 * when the file hasn't changed since it's just a stat() call).
 *
 * Returns true if a reload happened (new table swapped in).
 */
static void table_free(struct domain_rule_table *t) {
    if (!t) return;
    free(t->rules);
    free(t);
}

static bool reload_domain_rules_if_changed(const char *path) {
    time_t mtime = file_mtime(path);
    if (mtime == 0) return false;   /* file missing/unreadable: keep serving old table */

    struct domain_rule_table *current = atomic_load(&g_active_table);
    if (current && current->loaded_mtime == mtime) {
        return false;   /* unchanged since last load */
    }

    struct domain_rule_table *new_table = parse_domain_rules_file(path);
    if (!new_table) {
        fprintf(stderr, "domain_rules: reload failed, keeping previous table in place\n");
        return false;
    }
    new_table->loaded_mtime = mtime;

    /* Atomic swap: any reader calling classify_hostname() concurrently
     * either sees the fully-old table or the fully-new table, never a
     * half-updated one. The old table is retired (see retire_table's
     * grace-period comment above), not freed immediately — a reader
     * that loaded the pointer just before this store is still safe to
     * finish its lookup against it. */
    struct domain_rule_table *old = atomic_exchange(&g_active_table, new_table);
    retire_table(old);

    return true;
}

/*
 * Longest-suffix-match classification against the currently active
 * table — same matching semantics as before, just reading from the
 * dynamically loaded table instead of a hardcoded array.
 */
struct classification_result {
    bool        matched;
    char        category[MAX_SECTION_LEN];
    char        app_name[MAX_APPNAME_LEN];
};

static bool hostname_has_suffix(const char *hostname, const char *suffix) {
    size_t hlen = strlen(hostname), slen = strlen(suffix);
    if (slen > hlen) return false;
    const char *tail = hostname + (hlen - slen);
    if (strcasecmp(tail, suffix) != 0) return false;
    if (hlen == slen) return true;
    return hostname[hlen - slen - 1] == '.';
}

static void classify_hostname(const char *hostname, struct classification_result *out) {
    memset(out, 0, sizeof(*out));

    /* Atomic load once, use this local copy for the whole lookup — if
     * a reload swaps g_active_table concurrently, this call still
     * completes safely against the table it started with (which the
     * grace-period retirement in reload_domain_rules_if_changed keeps
     * alive long enough for exactly this reason). */
    struct domain_rule_table *table = atomic_load(&g_active_table);
    if (!table) return;

    size_t best_len = 0;
    for (size_t i = 0; i < table->count; i++) {
        struct domain_rule *r = &table->rules[i];
        if (hostname_has_suffix(hostname, r->suffix)) {
            size_t rule_len = strlen(r->suffix);
            if (rule_len > best_len) {
                best_len = rule_len;
                out->matched = true;
                strncpy(out->category, r->category, MAX_SECTION_LEN - 1);
                strncpy(out->app_name, r->app_name, MAX_APPNAME_LEN - 1);
            }
        }
    }
}

/*
 * Example integration:
 *
 *   int main(void) {
 *       reload_domain_rules_if_changed("/etc/dpi/domain_rules.ini");
 *       ...
 *       // in your periodic management/reload loop:
 *       while (running) {
 *           reload_domain_rules_if_changed("/etc/dpi/domain_rules.ini");
 *           sleep(1);
 *       }
 *   }
 *
 * Then dpi_app_classifier.c's classify_flow() calls this same
 * classify_hostname() (replacing its old hardcoded-array version) to
 * pick up rule changes live, without a rebuild or restart.
 */
