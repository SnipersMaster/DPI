/*
 * dpi_output_sink.c
 *
 * Real output backends for dpi_async_output.c's drain thread, replacing
 * the printf() placeholder. Three sinks, chosen at startup via a
 * config string — no single choice is right for every deployment:
 *
 *   file:/path/to/flows.log
 *       Appends JSON lines to a file. Reopens the file on SIGHUP so
 *       standard `logrotate` (rename + signal) works without dropping
 *       records — this is the conventional Unix log-rotation pattern,
 *       not a custom rotation scheme, so it composes with tooling ops
 *       teams already have.
 *
 *   syslog:daemon   (or syslog:local0, etc. — any standard facility)
 *       Sends each record via syslog(3). Good for integrating with
 *       existing alerting/SIEM pipelines that already consume syslog.
 *       NOT recommended as the primary sink at high flow rates — each
 *       syslog() call has real per-call overhead (syscall + whatever
 *       your syslog daemon does with it), and this project's whole
 *       point with dpi_async_output.c was getting I/O cost off the hot
 *       path, not just moving it to a different, still-expensive sink.
 *       Fine for a secondary/alerting-only stream; not fine as the
 *       sole sink for a busy 100G deployment's full flow log.
 *
 *   unix:/var/run/dpi/output.sock
 *       Writes JSON lines to a Unix domain socket. This is the
 *       recommended path for feeding a real message queue (Kafka,
 *       etc.) WITHOUT embedding a message-queue client library in the
 *       DPI engine itself: point a dedicated, separately-maintained
 *       shipper (Fluentd, Vector, Filebeat, or a small custom relay)
 *       at the other end of the socket, and let IT own the Kafka
 *       client, retry logic, and schema concerns. Keeping that
 *       complexity out of this process is deliberate — the DPI engine
 *       has enough responsibility already (see the very first security
 *       checklist in this project on minimizing attack surface).
 *       Reconnects with backoff if the shipper isn't there yet or
 *       restarts; never blocks the drain thread indefinitely.
 *
 * NOT COMPILED/TESTED in this environment.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

/* ------------------------------------------------------------------
 * Sink interface — every backend implements this. init()/write()/
 * close() are only ever called from the single drain thread in
 * dpi_async_output.c, so none of this needs its own locking.
 * ------------------------------------------------------------------ */
struct output_sink {
    bool (*init)(const char *config_arg);
    void (*write_line)(const char *json_line, size_t len);
    void (*flush)(void);
    void (*close_sink)(void);
};

/* ==================================================================
 * FILE SINK
 * ================================================================== */
static FILE *g_file_sink_fp = NULL;
static char  g_file_sink_path[512];
static volatile sig_atomic_t g_file_sink_reopen_requested = 0;

static void file_sink_sighup_handler(int signum) {
    (void)signum;
    g_file_sink_reopen_requested = 1;   /* signal-safe: just set a flag,
                                          * do the actual reopen from the
                                          * drain thread's normal flow */
}

static bool file_sink_open(void) {
    g_file_sink_fp = fopen(g_file_sink_path, "a");
    if (!g_file_sink_fp) {
        fprintf(stderr, "output_sink(file): failed to open '%s': %s\n",
                g_file_sink_path, strerror(errno));
        return false;
    }
    /* Line-buffered would flush every record (defeats the purpose of
     * batching I/O off the hot path); fully unbuffered is worse.
     * Block-buffer at a reasonable size and flush explicitly on our
     * own schedule instead — see flush() below, called periodically
     * by the drain loop, not on every write. */
    setvbuf(g_file_sink_fp, NULL, _IOFBF, 64 * 1024);
    return true;
}

static bool file_sink_init(const char *config_arg) {
    if (!config_arg || strlen(config_arg) == 0) {
        fprintf(stderr, "output_sink(file): missing path, expected file:/path/to/log\n");
        return false;
    }
    strncpy(g_file_sink_path, config_arg, sizeof(g_file_sink_path) - 1);

    if (!file_sink_open()) return false;

    /* SIGHUP-triggered reopen is what makes this compose with
     * logrotate: rotate the file (rename flows.log -> flows.log.1),
     * signal this process, we reopen "flows.log" fresh — records in
     * flight during the brief reopen window queue in the ring buffer
     * (dpi_async_output.c) as normal, nothing is lost, just briefly
     * delayed. */
    struct sigaction sa = {0};
    sa.sa_handler = file_sink_sighup_handler;
    sigaction(SIGHUP, &sa, NULL);

    fprintf(stderr, "output_sink(file): writing to '%s' (SIGHUP to rotate)\n",
            g_file_sink_path);
    return true;
}

static void file_sink_write(const char *json_line, size_t len) {
    if (g_file_sink_reopen_requested) {
        g_file_sink_reopen_requested = 0;
        if (g_file_sink_fp) fclose(g_file_sink_fp);
        if (!file_sink_open()) {
            fprintf(stderr, "output_sink(file): reopen after SIGHUP failed, "
                    "records will be dropped until this is fixed\n");
            g_file_sink_fp = NULL;
        }
    }
    if (!g_file_sink_fp) return;   /* reopen failed: drop rather than crash */

    fwrite(json_line, 1, len, g_file_sink_fp);
}

static void file_sink_flush(void) {
    if (g_file_sink_fp) fflush(g_file_sink_fp);
}

static void file_sink_close(void) {
    if (g_file_sink_fp) {
        fflush(g_file_sink_fp);
        fclose(g_file_sink_fp);
        g_file_sink_fp = NULL;
    }
}

static const struct output_sink FILE_SINK = {
    .init = file_sink_init,
    .write_line = file_sink_write,
    .flush = file_sink_flush,
    .close_sink = file_sink_close,
};

/* ==================================================================
 * SYSLOG SINK
 * ================================================================== */
static int syslog_facility_from_name(const char *name) {
    if (!name || strcmp(name, "daemon") == 0) return LOG_DAEMON;
    if (strcmp(name, "local0") == 0) return LOG_LOCAL0;
    if (strcmp(name, "local1") == 0) return LOG_LOCAL1;
    if (strcmp(name, "local2") == 0) return LOG_LOCAL2;
    if (strcmp(name, "local3") == 0) return LOG_LOCAL3;
    if (strcmp(name, "local4") == 0) return LOG_LOCAL4;
    if (strcmp(name, "local5") == 0) return LOG_LOCAL5;
    if (strcmp(name, "local6") == 0) return LOG_LOCAL6;
    if (strcmp(name, "local7") == 0) return LOG_LOCAL7;
    if (strcmp(name, "user") == 0) return LOG_USER;
    fprintf(stderr, "output_sink(syslog): unrecognized facility '%s', "
            "defaulting to daemon\n", name);
    return LOG_DAEMON;
}

static bool syslog_sink_init(const char *config_arg) {
    int facility = syslog_facility_from_name(config_arg);
    openlog("dpi-engine", LOG_PID | LOG_NDELAY, facility);
    fprintf(stderr, "output_sink(syslog): facility=%s "
            "(NOTE: not recommended as sole sink at high flow rates — "
            "see this file's header comment)\n", config_arg ? config_arg : "daemon");
    return true;
}

static void syslog_sink_write(const char *json_line, size_t len) {
    (void)len;   /* syslog() takes a NUL-terminated string, not a length —
                   * json_line is guaranteed NUL-terminated by the caller */
    syslog(LOG_INFO, "%s", json_line);
}

static void syslog_sink_flush(void) {
    /* syslog(3) has no user-space buffering to flush — each call is
     * already a syscall (or a write to /dev/log). Nothing to do here. */
}

static void syslog_sink_close(void) {
    closelog();
}

static const struct output_sink SYSLOG_SINK = {
    .init = syslog_sink_init,
    .write_line = syslog_sink_write,
    .flush = syslog_sink_flush,
    .close_sink = syslog_sink_close,
};

/* ==================================================================
 * UNIX DOMAIN SOCKET SINK
 * ================================================================== */
static int g_unix_sink_fd = -1;
static char g_unix_sink_path[108];   /* sizeof(sockaddr_un.sun_path) */
static time_t g_unix_sink_last_connect_attempt = 0;
#define UNIX_SINK_RECONNECT_INTERVAL_SECONDS 5

static bool unix_sink_try_connect(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return false;

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_unix_sink_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return false;
    }

    g_unix_sink_fd = fd;
    fprintf(stderr, "output_sink(unix): connected to '%s'\n", g_unix_sink_path);
    return true;
}

static bool unix_sink_init(const char *config_arg) {
    if (!config_arg || strlen(config_arg) == 0) {
        fprintf(stderr, "output_sink(unix): missing path, expected unix:/path/to.sock\n");
        return false;
    }
    if (strlen(config_arg) >= sizeof(g_unix_sink_path)) {
        fprintf(stderr, "output_sink(unix): path too long for sockaddr_un.sun_path\n");
        return false;
    }
    strncpy(g_unix_sink_path, config_arg, sizeof(g_unix_sink_path) - 1);

    /* Don't fail startup if the shipper isn't listening yet — this
     * sink retries in the background from write_line(). A DPI engine
     * that refuses to start because a log shipper hasn't come up yet
     * (or is being redeployed) is a worse failure mode than briefly
     * dropping records while it reconnects. */
    if (!unix_sink_try_connect()) {
        fprintf(stderr, "output_sink(unix): initial connect to '%s' failed, "
                "will retry in the background — records drop until connected\n",
                g_unix_sink_path);
    }
    return true;
}

static void unix_sink_write(const char *json_line, size_t len) {
    if (g_unix_sink_fd < 0) {
        time_t now = time(NULL);
        if (now - g_unix_sink_last_connect_attempt < UNIX_SINK_RECONNECT_INTERVAL_SECONDS) {
            return;   /* recently failed, don't hammer connect() every record */
        }
        g_unix_sink_last_connect_attempt = now;
        if (!unix_sink_try_connect()) return;   /* still down: drop this record */
    }

    ssize_t written = write(g_unix_sink_fd, json_line, len);
    if (written < 0 || (size_t)written != len) {
        /* Shipper likely restarted or the socket died. Close and let
         * the next write_line() call attempt reconnection — never
         * block or retry synchronously here, that would stall the
         * drain thread on a dead peer. */
        close(g_unix_sink_fd);
        g_unix_sink_fd = -1;
    }
}

static void unix_sink_flush(void) {
    /* Nothing buffered at this layer — each write_line() is a direct
     * write() syscall. Kept as a no-op for interface symmetry with
     * the other sinks rather than omitted. */
}

static void unix_sink_close(void) {
    if (g_unix_sink_fd >= 0) {
        close(g_unix_sink_fd);
        g_unix_sink_fd = -1;
    }
}

static const struct output_sink UNIX_SOCKET_SINK = {
    .init = unix_sink_init,
    .write_line = unix_sink_write,
    .flush = unix_sink_flush,
    .close_sink = unix_sink_close,
};

/* ==================================================================
 * Factory: parse a "scheme:argument" config string, e.g.
 *   "file:/var/log/dpi/flows.log"
 *   "syslog:daemon"
 *   "unix:/var/run/dpi/output.sock"
 * ================================================================== */
static bool output_sink_create(const char *config, const struct output_sink **out_sink) {
    const char *colon = strchr(config, ':');
    if (!colon) {
        fprintf(stderr, "output_sink: config '%s' missing scheme, expected "
                "file:PATH, syslog:FACILITY, or unix:PATH\n", config);
        return false;
    }

    size_t scheme_len = (size_t)(colon - config);
    const char *arg = colon + 1;

    if (strncmp(config, "file", scheme_len) == 0 && scheme_len == 4) {
        *out_sink = &FILE_SINK;
    } else if (strncmp(config, "syslog", scheme_len) == 0 && scheme_len == 6) {
        *out_sink = &SYSLOG_SINK;
    } else if (strncmp(config, "unix", scheme_len) == 0 && scheme_len == 4) {
        *out_sink = &UNIX_SOCKET_SINK;
    } else {
        fprintf(stderr, "output_sink: unrecognized scheme in '%s'\n", config);
        return false;
    }

    return (*out_sink)->init(arg);
}
