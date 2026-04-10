/*
 * mei-guard: Main Daemon (Revised – typed JSON IPC stream)
 *
 * All output goes to stdout as newline-delimited JSON with a "type" field:
 *
 *   {"timestamp":1234567890.123, "type":"alert",   "source":"heci",  ...}
 *   {"timestamp":1234567890.456, "type":"latency",  "ticks":312}
 *   {"timestamp":1234567890.789, "type":"stats",    ...}
 *
 * Pipe to the Python analyser:
 *   sudo mei-guard | python3 analyser.py --db /var/lib/mei-guard/db.sqlite
 *
 * Options:
 *   --enroll-microcode          Record current microcode as trusted baseline
 *   --check-once                Run all checks once and exit (for cron)
 *   --no-heci / --no-microcode / --no-mei-status / --no-dmi-latency
 *   --amt                       Declare AMT is provisioned
 *   --verbose                   Enable debug logging
 *   --notify CMD                Pipe alert detail to command
 *   --pid-file PATH             Write PID file
 *   --telemetry-interval N      Latency snapshot interval in seconds (default 2)
 *
 * Signals:
 *   SIGUSR1 – emit a "stats" JSON line
 *   SIGTERM/SIGINT – graceful shutdown
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>

#ifdef PLAT_LINUX
  #include <sys/stat.h>
#endif

#include "platform/platform.h"
#include "checks/heci_monitor.h"
#include "checks/microcode_verifier.h"
#include "checks/mei_status.h"
#include "checks/dmi_latency.h"

/* ------------------------------------------------------------------ */
/*  Global state                                                        */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t g_running    = 1;
static volatile sig_atomic_t g_dump_stats = 0;

static heci_monitor_t *g_heci = NULL;
static dmi_monitor_t  *g_dmi  = NULL;

/* Protect stdout across threads */
static pthread_mutex_t g_stdout_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ */
/*  Config                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    bool enable_heci;
    bool enable_microcode;
    bool enable_mei_status;
    bool enable_dmi_latency;
    bool amt_provisioned;
    bool check_once;
    bool verbose;
    char notify_cmd[256];
    char pid_file[256];
    int  microcode_check_interval_s;
    int  mei_status_check_interval_s;
    int  telemetry_interval_s;
} config_t;

static config_t g_cfg = {
    .enable_heci                  = true,
    .enable_microcode             = true,
    .enable_mei_status            = true,
    .enable_dmi_latency           = true,
    .amt_provisioned              = false,
    .check_once                   = false,
    .verbose                      = false,
    .microcode_check_interval_s   = 3600,
    .mei_status_check_interval_s  = 300,
    .telemetry_interval_s         = 2,
};

/* ------------------------------------------------------------------ */
/*  JSON IPC                                                            */
/* ------------------------------------------------------------------ */

static void json_escape(const char *in, char *out, size_t outsz)
{
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 4 < outsz; i++) {
        unsigned char c = (unsigned char)in[i];
        if      (c == '"')  { out[j++] = '\\'; out[j++] = '"'; }
        else if (c == '\\') { out[j++] = '\\'; out[j++] = '\\'; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (c < 0x20)  { /* skip control chars */ }
        else                { out[j++] = (char)c; }
    }
    out[j] = '\0';
}

static void emit_json_line(const char *type, const char *extra_fields)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    pthread_mutex_lock(&g_stdout_mutex);
    printf("{\"timestamp\":%ld.%09ld,\"type\":\"%s\"%s}\n",
           (long)ts.tv_sec, ts.tv_nsec,
           type,
           extra_fields ? extra_fields : "");
    fflush(stdout);
    pthread_mutex_unlock(&g_stdout_mutex);
}

static void emit_alert(const char *source, int severity, const char *detail)
{
    char escaped[2048];
    json_escape(detail, escaped, sizeof(escaped));

    char fields[2560];
    snprintf(fields, sizeof(fields),
             ",\"source\":\"%s\",\"severity\":%d,\"detail\":\"%s\"",
             source, severity, escaped);
    emit_json_line("alert", fields);

    if (g_cfg.notify_cmd[0]) {
        FILE *p = popen(g_cfg.notify_cmd, "w");
        if (p) { fprintf(p, "%s\n", detail); pclose(p); }
    }
}

/* ------------------------------------------------------------------ */
/*  Alert callbacks                                                     */
/* ------------------------------------------------------------------ */

static void on_heci_alert(const heci_alert_t *a, void *ctx)
{
    (void)ctx;
    emit_alert("heci", (int)a->severity, a->detail);
}

static void on_dmi_alert(const dmi_alert_t *a, void *ctx)
{
    (void)ctx;
    emit_alert("dmi_latency", ALERT_HIGH, a->detail);
}

/* ------------------------------------------------------------------ */
/*  Telemetry thread – streams latency samples to Python analyser      */
/* ------------------------------------------------------------------ */

static void *telemetry_thread(void *arg)
{
    (void)arg;
    while (g_running) {
        if (g_cfg.enable_dmi_latency && g_dmi) {
            uint64_t samples[100];
            int n = dmi_monitor_snapshot(g_dmi, samples, 100);

            pthread_mutex_lock(&g_stdout_mutex);
            for (int i = 0; i < n; i++) {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                printf("{\"timestamp\":%ld.%09ld,"
                       "\"type\":\"latency\","
                       "\"ticks\":%llu}\n",
                       (long)ts.tv_sec, ts.tv_nsec,
                       (unsigned long long)samples[i]);
            }
            if (n > 0) fflush(stdout);
            pthread_mutex_unlock(&g_stdout_mutex);
        }
        sleep((unsigned)g_cfg.telemetry_interval_s);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Periodic checks thread                                              */
/* ------------------------------------------------------------------ */

static void *periodic_checks_thread(void *arg)
{
    (void)arg;
    time_t last_mc = 0, last_status = 0;

    while (g_running) {
        time_t now = time(NULL);

        if (g_cfg.enable_microcode &&
            now - last_mc >= g_cfg.microcode_check_interval_s) {
            mc_check_result_t mc = microcode_check();
            last_mc = now;
            if (mc.status != MC_OK      &&
                mc.status != MC_NO_DB   &&
                mc.status != MC_UNKNOWN_CPU)
                emit_alert("microcode", ALERT_CRITICAL, mc.detail);
        }

        if (g_cfg.enable_mei_status &&
            now - last_status >= g_cfg.mei_status_check_interval_s) {
            mei_status_result_t ms = mei_status_check();
            last_status = now;
            if (ms.status != MEI_STATUS_OK &&
                ms.status != MEI_STATUS_UNAVAILABLE)
                emit_alert("mei_status", ALERT_CRITICAL, ms.detail);
        }

        sleep(10);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Stats dump (SIGUSR1)                                               */
/* ------------------------------------------------------------------ */

static void dump_stats(void)
{
    char fields[512] = "";
    if (g_heci) {
        heci_stats_t s;
        heci_monitor_stats(g_heci, &s);
        snprintf(fields, sizeof(fields),
                 ",\"heci_messages\":%llu"
                 ",\"heci_alerts\":%llu"
                 ",\"heci_unknown_guids\":%llu",
                 (unsigned long long)s.msg_count,
                 (unsigned long long)s.alert_count,
                 (unsigned long long)s.unknown_guid_count);
    }
    emit_json_line("stats", fields);
}

/* ------------------------------------------------------------------ */
/*  Signal handlers                                                     */
/* ------------------------------------------------------------------ */

static void sig_term(int s) { (void)s; g_running = 0; }
static void sig_usr1(int s) { (void)s; g_dump_stats = 1; }

/* ------------------------------------------------------------------ */
/*  Argument parsing                                                    */
/* ------------------------------------------------------------------ */

static void parse_args(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--enroll-microcode")) {
            plat_init();
            microcode_enroll();
            exit(0);
        }
        else if (!strcmp(argv[i], "--check-once"))       g_cfg.check_once = true;
        else if (!strcmp(argv[i], "--no-heci"))          g_cfg.enable_heci = false;
        else if (!strcmp(argv[i], "--no-microcode"))     g_cfg.enable_microcode = false;
        else if (!strcmp(argv[i], "--no-mei-status"))    g_cfg.enable_mei_status = false;
        else if (!strcmp(argv[i], "--no-dmi-latency"))   g_cfg.enable_dmi_latency = false;
        else if (!strcmp(argv[i], "--amt"))              g_cfg.amt_provisioned = true;
        else if (!strcmp(argv[i], "--verbose"))          g_cfg.verbose = true;
        else if (!strcmp(argv[i], "--notify") && i+1 < argc)
            strncpy(g_cfg.notify_cmd, argv[++i], sizeof(g_cfg.notify_cmd)-1);
        else if (!strcmp(argv[i], "--pid-file") && i+1 < argc)
            strncpy(g_cfg.pid_file, argv[++i], sizeof(g_cfg.pid_file)-1);
        else if (!strcmp(argv[i], "--telemetry-interval") && i+1 < argc) {
            g_cfg.telemetry_interval_s = atoi(argv[++i]);
            if (g_cfg.telemetry_interval_s < 1)
                g_cfg.telemetry_interval_s = 1;
        }
        else if (!strcmp(argv[i], "--help")) {
            puts("mei-guard: Ring -3 Heuristic Anomaly Detection System\n"
                 "\n"
                 "Output: newline-delimited JSON on stdout\n"
                 "Usage:  sudo mei-guard [OPTIONS] | python3 analyser.py ...\n"
                 "\n"
                 "  --enroll-microcode          Trust current microcode\n"
                 "  --check-once               Run checks once, exit\n"
                 "  --no-heci                  Disable HECI monitor\n"
                 "  --no-microcode             Disable microcode verifier\n"
                 "  --no-mei-status            Disable MEI status check\n"
                 "  --no-dmi-latency           Disable DMI latency profiler\n"
                 "  --amt                      Suppress AMT alerts\n"
                 "  --verbose                  Debug logging\n"
                 "  --notify CMD               Pipe alerts to command\n"
                 "  --pid-file PATH            Write PID file\n"
                 "  --telemetry-interval N     Latency emit interval (default 2s)\n");
            exit(0);
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            exit(1);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  PID file                                                            */
/* ------------------------------------------------------------------ */

static void write_pid_file(const char *path)
{
    if (!path[0]) return;
    FILE *f = fopen(path, "w");
    if (f) { fprintf(f, "%d\n", getpid()); fclose(f); }
}

static void remove_pid_file(const char *path)
{
    if (path[0]) unlink(path);
}

/* ------------------------------------------------------------------ */
/*  Main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    parse_args(argc, argv);

    plat_err_t err = plat_init();
    if (err != PLAT_OK) {
        fprintf(stderr, "mei-guard: platform init failed: %s\n",
                plat_strerr(err));
        return 1;
    }

    LOG_I("main", "mei-guard starting. PID=%d  "
          "heci=%d ucode=%d mei_status=%d dmi=%d  AMT=%d",
          getpid(),
          g_cfg.enable_heci, g_cfg.enable_microcode,
          g_cfg.enable_mei_status, g_cfg.enable_dmi_latency,
          g_cfg.amt_provisioned);

    write_pid_file(g_cfg.pid_file);

    /* Initial synchronous checks */
    if (g_cfg.enable_microcode) {
        mc_check_result_t mc = microcode_check();
        if (mc.status == MC_REVISION_CHANGED || mc.status == MC_HASH_MISMATCH)
            emit_alert("microcode", ALERT_CRITICAL, mc.detail);
    }
    if (g_cfg.enable_mei_status) {
        mei_status_result_t ms = mei_status_check();
        if (ms.status != MEI_STATUS_OK && ms.status != MEI_STATUS_UNAVAILABLE)
            emit_alert("mei_status", ALERT_CRITICAL, ms.detail);
    }

    if (g_cfg.check_once) {
        LOG_I("main", "--check-once complete.");
        plat_teardown();
        return 0;
    }

    /* Start monitors */
    if (g_cfg.enable_heci) {
        g_heci = heci_monitor_create(g_cfg.amt_provisioned, on_heci_alert, NULL);
        if (g_heci && heci_monitor_start(g_heci) != 0)
            LOG_W("main", "HECI monitor thread failed to start");
    }
    if (g_cfg.enable_dmi_latency) {
        g_dmi = dmi_monitor_create(on_dmi_alert, NULL);
        if (g_dmi && dmi_monitor_start(g_dmi) != 0)
            LOG_W("main", "DMI latency monitor thread failed to start");
    }

    pthread_t periodic_tid, telemetry_tid;
    pthread_create(&periodic_tid, NULL, periodic_checks_thread, NULL);
    pthread_create(&telemetry_tid, NULL, telemetry_thread, NULL);

    signal(SIGTERM, sig_term);
    signal(SIGINT,  sig_term);
    signal(SIGUSR1, sig_usr1);

    LOG_I("main", "All monitors running. SIGUSR1=stats, SIGTERM=stop.");

    while (g_running) {
        sleep(1);
        if (g_dump_stats) { dump_stats(); g_dump_stats = 0; }
    }

    LOG_I("main", "Shutting down...");
    g_running = 0;
    pthread_join(periodic_tid, NULL);
    pthread_join(telemetry_tid, NULL);
    if (g_heci) { heci_monitor_stop(g_heci); g_heci = NULL; }
    if (g_dmi)  { dmi_monitor_stop(g_dmi);   g_dmi  = NULL; }

    dump_stats();
    remove_pid_file(g_cfg.pid_file);
    plat_teardown();
    LOG_I("main", "Stopped cleanly.");
    return 0;
}