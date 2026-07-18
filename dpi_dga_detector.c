/*
 * dpi_dga_detector.c
 *
 * Lexical/statistical DGA (Domain Generation Algorithm) scoring for a
 * hostname/SNI. DGA domains are how a lot of malware finds its C2
 * server without hardcoding a domain that gets taken down — the
 * malware and the attacker both run the same algorithm to generate a
 * rotating list of candidate domains from a seed (often date-based).
 * They tend to look statistically different from human-chosen domains:
 * high character-level entropy, few real dictionary substrings,
 * unusual consonant clusters, some are purely random-looking hex/base32.
 *
 * This module gives a 0.0 (looks human-chosen) to 1.0 (looks
 * algorithmically generated) score using four independent signals,
 * combined with a weighted average. This is a HEURISTIC, not a
 * definitive detector — treat it the same way as the JA3 fallback
 * earlier: a supporting signal for triage/alerting, not a standalone
 * block decision. Real-world DGA classifiers (see Bilge et al.
 * "EXPOSURE", 2011; Antonakakis et al. "Pleiades", 2012) combine
 * lexical scoring like this with contextual signals (NXDOMAIN rate,
 * domain age, request volume patterns) that this module doesn't have
 * access to at the packet-parsing layer — those live in a slower,
 * stateful analytics path, not per-packet DPI.
 *
 * NOT COMPILED/TESTED against a labeled DGA dataset in this
 * environment. Before trusting the score thresholds in production,
 * validate against a labeled corpus (e.g. a mix of Alexa/Tranco top
 * domains as negatives and a public DGA domain list as positives) and
 * tune the weights/thresholds to your actual false-positive tolerance.
 *
 * -------------------------------------------------------------------
 * THE FOUR SIGNALS
 * -------------------------------------------------------------------
 *   1. Shannon entropy of characters — random strings have higher
 *      entropy than pronounceable words. ("instagram" ~2.9 bits/char,
 *      "xk4jq9zpfl" ~3.3+ bits/char)
 *   2. Bigram likelihood against common English bigram frequencies —
 *      real words are built from common letter pairs ("th", "in",
 *      "er"); DGA output usually isn't.
 *   3. Consonant run length — human words rarely stack more than 3-4
 *      consonants in a row; algorithmic strings often do.
 *   4. Digit ratio and digit/letter interleaving — many DGA families
 *      mix digits throughout rather than only at natural positions
 *      (e.g. a trailing version number).
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#define MAX_LABEL_LEN 64

/* ------------------------------------------------------------------
 * Signal 1: Shannon entropy over the label's characters, normalized
 * to a 0-1ish range for combination with the other signals.
 * ------------------------------------------------------------------ */
static double shannon_entropy(const char *s, size_t len) {
    if (len == 0) return 0.0;

    int counts[256] = {0};
    for (size_t i = 0; i < len; i++) {
        counts[(unsigned char)tolower((unsigned char)s[i])]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / (double)len;
        entropy -= p * log2(p);
    }

    /* Max entropy for lowercase alpha+digit alphabet (~36 symbols) is
     * log2(36) ~= 5.17. Normalize against that as a practical ceiling. */
    double normalized = entropy / 5.17;
    return normalized > 1.0 ? 1.0 : normalized;
}

/* ------------------------------------------------------------------
 * Signal 2: bigram likelihood. Small hardcoded table of the most
 * common English bigrams — a real deployment should use a proper
 * frequency table (e.g. derived from a large corpus) loaded from
 * config, same modularity principle as the domain rules. This is a
 * representative subset for illustration.
 * ------------------------------------------------------------------ */
static const char *common_bigrams[] = {
    "th","he","in","er","an","re","on","at","en","nd",
    "ti","es","or","te","of","ed","is","it","al","ar",
    "st","to","nt","ng","se","ha","as","ou","io","le",
    "ve","co","me","de","hi","ri","ro","ic","ne","ea",
    "ra","ce","li","ch","ll","be","ma","si","om","ur"
};
#define N_COMMON_BIGRAMS (sizeof(common_bigrams) / sizeof(common_bigrams[0]))

static bool is_common_bigram(const char *pair) {
    for (size_t i = 0; i < N_COMMON_BIGRAMS; i++) {
        if (common_bigrams[i][0] == pair[0] && common_bigrams[i][1] == pair[1]) {
            return true;
        }
    }
    return false;
}

/* Returns the FRACTION of bigrams in the label that are common
 * English bigrams. Low fraction = less word-like = more DGA-like.
 * We return (1 - fraction) so higher = more suspicious, consistent
 * with the other signals. */
static double bigram_suspicion(const char *s, size_t len) {
    if (len < 2) return 0.5;   /* too short to judge meaningfully */

    char lower[MAX_LABEL_LEN];
    size_t n = len < MAX_LABEL_LEN - 1 ? len : MAX_LABEL_LEN - 1;
    for (size_t i = 0; i < n; i++) lower[i] = tolower((unsigned char)s[i]);
    lower[n] = '\0';

    int total = 0, common = 0;
    for (size_t i = 0; i + 1 < n; i++) {
        if (isalpha((unsigned char)lower[i]) && isalpha((unsigned char)lower[i+1])) {
            total++;
            if (is_common_bigram(lower + i)) common++;
        }
    }
    if (total == 0) return 0.5;

    double fraction_common = (double)common / (double)total;
    return 1.0 - fraction_common;
}

/* ------------------------------------------------------------------
 * Signal 3: longest consonant run. Normalized against a practical
 * ceiling (runs of 5+ are rare in real words, common in DGA output).
 * ------------------------------------------------------------------ */
static double consonant_run_suspicion(const char *s, size_t len) {
    const char *vowels = "aeiou";
    int max_run = 0, cur_run = 0;

    for (size_t i = 0; i < len; i++) {
        char c = tolower((unsigned char)s[i]);
        if (isalpha((unsigned char)c) && !strchr(vowels, c)) {
            cur_run++;
            if (cur_run > max_run) max_run = cur_run;
        } else {
            cur_run = 0;
        }
    }

    double normalized = (double)max_run / 6.0;   /* 6+ consonants in a row: max suspicion */
    return normalized > 1.0 ? 1.0 : normalized;
}

/* ------------------------------------------------------------------
 * Signal 4: digit ratio and interleaving. High digit density, or
 * digits scattered throughout rather than clustered (e.g. a trailing
 * version number), both push the score up.
 * ------------------------------------------------------------------ */
static double digit_pattern_suspicion(const char *s, size_t len) {
    if (len == 0) return 0.0;

    int digit_count = 0, transitions = 0;
    bool prev_was_digit = false;

    for (size_t i = 0; i < len; i++) {
        bool is_digit = isdigit((unsigned char)s[i]);
        if (is_digit) digit_count++;
        if (i > 0 && is_digit != prev_was_digit) transitions++;
        prev_was_digit = is_digit;
    }

    double digit_ratio = (double)digit_count / (double)len;
    double transition_ratio = (double)transitions / (double)len;

    /* Weighted blend: raw digit density matters, but frequent
     * alpha<->digit transitions (interleaving) is the stronger signal. */
    double score = (digit_ratio * 0.4) + (transition_ratio * 0.6);
    return score > 1.0 ? 1.0 : score;
}

/* ------------------------------------------------------------------
 * Combined DGA score. Extracts just the registrable label being
 * scored (the part before the first '.', i.e. not the TLD/eTLD+1
 * suffix) since DGA algorithms generate the subdomain/domain label,
 * not the TLD.
 * ------------------------------------------------------------------ */
struct dga_result {
    double score;        /* 0.0 (human-like) to 1.0 (algorithmic-like) */
    const char *verdict; /* "low" | "medium" | "high" — thresholds are a starting
                           * point, tune against your own labeled data */
    double entropy_component;
    double bigram_component;
    double consonant_component;
    double digit_component;
};

static void score_dga(const char *hostname, struct dga_result *out) {
    memset(out, 0, sizeof(*out));

    /* Extract the first label only, e.g. "xk4jq9zpfl" from
     * "xk4jq9zpfl.ddns-c2-example.net" — this is a simplification;
     * production code should use a proper public-suffix-list-aware
     * eTLD+1 extraction so multi-part TLDs (co.uk, com.au) don't
     * throw off which label is actually the generated one. */
    char label[MAX_LABEL_LEN];
    const char *dot = strchr(hostname, '.');
    size_t label_len = dot ? (size_t)(dot - hostname) : strlen(hostname);
    if (label_len >= MAX_LABEL_LEN) label_len = MAX_LABEL_LEN - 1;
    memcpy(label, hostname, label_len);
    label[label_len] = '\0';

    if (label_len < 4) {
        /* Too short to score meaningfully either way. */
        out->score = 0.0;
        out->verdict = "low";
        return;
    }

    out->entropy_component   = shannon_entropy(label, label_len);
    out->bigram_component    = bigram_suspicion(label, label_len);
    out->consonant_component = consonant_run_suspicion(label, label_len);
    out->digit_component     = digit_pattern_suspicion(label, label_len);

    /* Weighted combination. Entropy and bigram-likelihood are the
     * strongest standalone predictors in the DGA-detection literature;
     * consonant runs and digit patterns are supporting signals. */
    out->score = (out->entropy_component   * 0.35) +
                 (out->bigram_component    * 0.35) +
                 (out->consonant_component * 0.15) +
                 (out->digit_component     * 0.15);

    if (out->score >= 0.7)      out->verdict = "high";
    else if (out->score >= 0.4) out->verdict = "medium";
    else                        out->verdict = "low";
}
