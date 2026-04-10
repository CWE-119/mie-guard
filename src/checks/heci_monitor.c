/*
 * mei-guard: HECI Bus Monitor
 *
 * Monitors the Host Embedded Controller Interface (HECI/MEI) bus
 * for unexpected ME commands.
 *
 * Architecture:
 *   The Intel ME communicates with the OS via a circular buffer in
 *   shared memory, exposed through /dev/mei0 (Linux) or the Intel MEI
 *   driver (Windows).  Each message has a 16-byte GUID identifying the
 *   ME client, followed by a command byte and payload.
 *
 *   Normal traffic (when AMT is not provisioned):
 *     - MKHI  heartbeats (every ~30 s)
 *     - Watchdog keepalives (HECI_WDT)
 *     - Thermal/FIVR (power management)
 *
 *   Suspicious traffic:
 *     - Unknown GUIDs
 *     - KVM/SOL (Serial-Over-LAN) commands outside provisioned AMT
 *     - High-frequency bursts (> N messages in M ms)
 *     - Messages during system idle (no user input, no scheduled tasks)
 */

#ifndef HECI_MONITOR_H_IMPL
#define HECI_MONITOR_H_IMPL
#endif

#include "heci_monitor.h"
#include "../platform/platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>

/* ------------------------------------------------------------------ */
/*  HECI protocol types                                                 */
/* ------------------------------------------------------------------ */

/* MKHI (ME Kernel Host Interface) header */
typedef struct __attribute__((packed)) {
    uint32_t group_id   : 8;
    uint32_t command    : 7;
    uint32_t is_resp    : 1;
    uint32_t reserved   : 8;
    uint32_t result     : 8;
} mkhi_header_t;

/* Generic MEI message header */
typedef struct __attribute__((packed)) {
    uint32_t me_addr    : 8;   /* ME client address    */
    uint32_t host_addr  : 8;   /* Host client address  */
    uint32_t length     : 9;   /* Payload length       */
    uint32_t reserved   : 6;
    uint32_t msg_complete : 1; /* Last fragment        */
} mei_msg_hdr_t;

/* MEI client GUID (128-bit) */
typedef struct {
    uint8_t bytes[16];
} mei_guid_t;

/* ------------------------------------------------------------------ */
/*  Known-good GUID whitelist                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    mei_guid_t  guid;
    const char *name;
    bool        requires_amt;   /* Only valid when AMT provisioned */
} known_client_t;

/* GUIDs from Intel ME specification and public research */
static const known_client_t KNOWN_CLIENTS[] = {
    {
        .guid = {{0x8E,0x6A,0x63,0x01, 0x73,0x1F, 0x45,0x43,
                  0xAD,0xEA,0x3D,0x2B,0xDB,0xD2,0xDA,0x3A}},
        .name = "MKHI",
        .requires_amt = false
    },
    {
        .guid = {{0x12,0xF8,0x02,0x28, 0x9A,0x45, 0x45,0x40,
                  0xA7,0x9E,0x23,0x4F,0x96,0x5B,0xC3,0x66}},
        .name = "AMT_HOST",
        .requires_amt = true
    },
    {
        .guid = {{0x05,0xB7,0x9A,0x6C, 0xF8,0xF1, 0x11,0xE0,
                  0x97,0xA1,0x00,0x00,0x00,0x00,0x00,0x00}},
        .name = "HECI_WDT",
        .requires_amt = false
    },
    {
        .guid = {{0xE2,0xD1,0xFF,0x34, 0x34,0x58, 0x49,0xA9,
                  0x88,0xDA,0x8E,0x69,0x15,0xCE,0x9B,0xE5}},
        .name = "MEI_CLDEV",
        .requires_amt = false
    },
    {
        .guid = {{0xFC,0x9C,0x99,0x03, 0xF6,0xA1, 0x45,0x00,
                  0x96,0xFE,0x0A,0x7A,0xA7,0xF8,0xAC,0x9B}},
        .name = "THERMAL_MGMT",
        .requires_amt = false
    },
    /* Sentinel */
    { .name = NULL }
};

/* ------------------------------------------------------------------ */
/*  Rate limiting: sliding window counter                               */
/* ------------------------------------------------------------------ */

#define WINDOW_SIZE_MS   1000   /* 1 second window                   */
#define BURST_THRESHOLD  20     /* > 20 msgs/sec = suspicious         */
#define RING_DEPTH       256

typedef struct {
    uint64_t timestamps[RING_DEPTH];  /* TSC ticks of each message   */
    int      head;
    int      count;
    uint64_t tsc_freq;
} rate_counter_t;

static void rc_init(rate_counter_t *rc, uint64_t tsc_freq)
{
    memset(rc, 0, sizeof(*rc));
    rc->tsc_freq = tsc_freq;
}

static int rc_push(rate_counter_t *rc, uint64_t now_tsc)
{
    rc->timestamps[rc->head] = now_tsc;
    rc->head = (rc->head + 1) % RING_DEPTH;
    if (rc->count < RING_DEPTH) rc->count++;

    /* Count messages within the window */
    uint64_t window_ticks = rc->tsc_freq * WINDOW_SIZE_MS / 1000;
    int in_window = 0;
    for (int i = 0; i < rc->count; i++) {
        int idx = (rc->head - 1 - i + RING_DEPTH) % RING_DEPTH;
        if (now_tsc - rc->timestamps[idx] <= window_ticks)
            in_window++;
        else
            break;
    }
    return in_window;
}

/* ------------------------------------------------------------------ */
/*  Monitor state                                                       */
/* ------------------------------------------------------------------ */

struct heci_monitor {
    plat_fd_t        fd;
    bool             amt_provisioned;
    rate_counter_t   rate;
    uint64_t         msg_count;
    uint64_t         alert_count;
    uint64_t         unknown_guid_count;
    pthread_t        thread;
    volatile bool    running;

    /* Callback when alert fires */
    heci_alert_fn    alert_fn;
    void            *alert_ctx;
};

/* ------------------------------------------------------------------ */
/*  GUID helpers                                                        */
/* ------------------------------------------------------------------ */

static bool guid_equal(const mei_guid_t *a, const mei_guid_t *b)
{
    return memcmp(a->bytes, b->bytes, 16) == 0;
}

/* ------------------------------------------------------------------ */
/*  Runtime GUID whitelist (file override)                             */
/*                                                                      */
/*  /etc/mei-guard/guid_whitelist.txt format (one entry per line):     */
/*    8E6A6301-731F-4543-ADEA-3D2BDBD2DA3A MKHI                       */
/*    # lines starting with # are comments                             */
/*    <GUID-no-braces> <name> [requires_amt]                           */
/* ------------------------------------------------------------------ */

#define MAX_RUNTIME_GUIDS 64
#define WHITELIST_PATH    "/etc/mei-guard/guid_whitelist.txt"

static known_client_t g_runtime_list[MAX_RUNTIME_GUIDS];
static int            g_runtime_count = 0;
static bool           g_whitelist_loaded = false;

static uint8_t hex2(const char *s)
{
    uint8_t hi = (s[0] >= 'a') ? (s[0]-'a'+10)
               : (s[0] >= 'A') ? (s[0]-'A'+10)
               : (s[0]-'0');
    uint8_t lo = (s[1] >= 'a') ? (s[1]-'a'+10)
               : (s[1] >= 'A') ? (s[1]-'A'+10)
               : (s[1]-'0');
    return (hi << 4) | lo;
}

/**
 * parse_guid_str() - Parse a GUID string (with or without dashes) into
 * a 16-byte array in RFC-4122 mixed-endian byte order.
 * Returns true on success.
 */
static bool parse_guid_str(const char *s, mei_guid_t *out)
{
    /* Remove dashes, collect exactly 32 hex digits */
    char hex[33] = {0};
    int  n = 0;
    for (; *s && n < 32; s++) {
        if (*s == '-') continue;
        if (!isxdigit((unsigned char)*s)) return false;
        hex[n++] = *s;
    }
    if (n != 32) return false;

    /* RFC-4122: first three fields are little-endian on disk but
       stored big-endian in the string.  Mirror the byte order used
       in KNOWN_CLIENTS above. */
    uint8_t raw[16];
    for (int i = 0; i < 16; i++) raw[i] = hex2(&hex[i*2]);

    /* Swap bytes for Data1 (4B), Data2 (2B), Data3 (2B) */
    out->bytes[0] = raw[3]; out->bytes[1] = raw[2];
    out->bytes[2] = raw[1]; out->bytes[3] = raw[0];
    out->bytes[4] = raw[5]; out->bytes[5] = raw[4];
    out->bytes[6] = raw[7]; out->bytes[7] = raw[6];
    /* Data4 (8B) verbatim */
    for (int i = 0; i < 8; i++) out->bytes[8+i] = raw[8+i];
    return true;
}

static void load_whitelist_file(void)
{
    g_whitelist_loaded = true;

    FILE *f = fopen(WHITELIST_PATH, "r");
    if (!f) {
        LOG_D("heci", "No runtime whitelist at %s; using built-in list.",
              WHITELIST_PATH);
        return;
    }

    char line[256];
    int loaded = 0;

    while (fgets(line, sizeof(line), f) && loaded < MAX_RUNTIME_GUIDS) {
        /* Strip trailing newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* Skip blank lines and comments */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;

        /* Parse: <GUID> <name> [requires_amt] */
        char guid_str[40] = {0};
        char name[32]     = {0};
        char amt_str[8]   = {0};
        int fields = sscanf(p, "%39s %31s %7s", guid_str, name, amt_str);
        if (fields < 2) continue;

        mei_guid_t guid;
        if (!parse_guid_str(guid_str, &guid)) {
            LOG_W("heci", "Cannot parse GUID on whitelist line: %s", line);
            continue;
        }

        known_client_t *e = &g_runtime_list[loaded++];
        e->guid         = guid;
        e->name         = strdup(name);   /* leaked intentionally (daemon lifetime) */
        e->requires_amt = (strcmp(amt_str, "requires_amt") == 0);
    }

    fclose(f);
    g_runtime_count = loaded;
    LOG_I("heci", "Loaded %d GUID entries from %s", loaded, WHITELIST_PATH);
}

static const known_client_t *guid_lookup(const mei_guid_t *guid)
{
    /* Prefer runtime list if it was loaded and non-empty */
    if (g_whitelist_loaded && g_runtime_count > 0) {
        for (int i = 0; i < g_runtime_count; i++) {
            if (guid_equal(guid, &g_runtime_list[i].guid))
                return &g_runtime_list[i];
        }
        return NULL;
    }

    /* Fall back to compiled-in list */
    for (int i = 0; KNOWN_CLIENTS[i].name; i++) {
        if (guid_equal(guid, &KNOWN_CLIENTS[i].guid))
            return &KNOWN_CLIENTS[i];
    }
    return NULL;
}

static void guid_to_str(const mei_guid_t *g, char *buf, size_t n)
{
    snprintf(buf, n,
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-"
        "%02X%02X-%02X%02X%02X%02X%02X%02X",
        g->bytes[3],  g->bytes[2],  g->bytes[1],  g->bytes[0],
        g->bytes[5],  g->bytes[4],
        g->bytes[7],  g->bytes[6],
        g->bytes[8],  g->bytes[9],
        g->bytes[10], g->bytes[11], g->bytes[12],
        g->bytes[13], g->bytes[14], g->bytes[15]);
}

/* ------------------------------------------------------------------ */
/*  Message analysis                                                    */
/* ------------------------------------------------------------------ */

static void analyse_message(struct heci_monitor *m,
                             const uint8_t *buf, size_t len)
{
    if (len < sizeof(mei_msg_hdr_t) + 16) return;

    /* Skip the MEI transport header */
    const uint8_t *payload = buf + sizeof(mei_msg_hdr_t);
    const mei_guid_t *guid = (const mei_guid_t *)payload;

    char guid_str[40];
    guid_to_str(guid, guid_str, sizeof(guid_str));

    m->msg_count++;

    /* --- 1. Rate check --- */
    uint64_t now = plat_rdtsc();
    int rate = rc_push(&m->rate, now);
    if (rate > BURST_THRESHOLD) {
        heci_alert_t alert = {
            .type      = HECI_ALERT_BURST,
            .severity  = ALERT_HIGH,
            .msg_count = m->msg_count,
        };
        snprintf(alert.detail, sizeof(alert.detail),
                 "MEI burst: %d messages in %d ms (threshold %d). "
                 "Last GUID: %s",
                 rate, WINDOW_SIZE_MS, BURST_THRESHOLD, guid_str);
        LOG_A("heci", "%s", alert.detail);
        m->alert_count++;
        if (m->alert_fn) m->alert_fn(&alert, m->alert_ctx);
    }

    /* --- 2. GUID whitelist check --- */
    const known_client_t *known = guid_lookup(guid);
    if (!known) {
        m->unknown_guid_count++;
        heci_alert_t alert = {
            .type      = HECI_ALERT_UNKNOWN_GUID,
            .severity  = ALERT_CRITICAL,
            .msg_count = m->msg_count,
        };
        snprintf(alert.detail, sizeof(alert.detail),
                 "Unknown MEI client GUID: {%s}  "
                 "(payload length: %zu bytes). "
                 "This GUID is not in the Intel public specification. "
                 "Possible covert ME channel.",
                 guid_str, len - sizeof(mei_msg_hdr_t) - 16);
        LOG_C("heci", "%s", alert.detail);
        m->alert_count++;
        if (m->alert_fn) m->alert_fn(&alert, m->alert_ctx);
        return;
    }

    /* --- 3. AMT-gated client outside provisioned AMT --- */
    if (known->requires_amt && !m->amt_provisioned) {
        heci_alert_t alert = {
            .type      = HECI_ALERT_AMT_UNGATED,
            .severity  = ALERT_HIGH,
            .msg_count = m->msg_count,
        };
        snprintf(alert.detail, sizeof(alert.detail),
                 "AMT client '%s' active but AMT not provisioned. "
                 "Remote management commands without BIOS provisioning "
                 "is a strong indicator of compromise.",
                 known->name);
        LOG_A("heci", "%s", alert.detail);
        m->alert_count++;
        if (m->alert_fn) m->alert_fn(&alert, m->alert_ctx);
        return;
    }

    LOG_D("heci", "MSG #%lu guid=%-12s len=%zu rate=%d/s",
          m->msg_count, known->name, len, rate);
}

/* ------------------------------------------------------------------ */
/*  Monitor thread                                                      */
/* ------------------------------------------------------------------ */

static void *monitor_thread(void *arg)
{
    struct heci_monitor *m = arg;
    uint8_t buf[4096];

    LOG_I("heci", "Monitor thread started. Watching /dev/mei0...");

    while (m->running) {
        ssize_t n = plat_mei_read(m->fd, buf, sizeof(buf), 500);
        if (n > 0) {
            analyse_message(m, buf, (size_t)n);
        } else if (n < 0) {
            LOG_W("heci", "MEI read error; pausing 1s");
#ifdef PLAT_LINUX
            sleep(1);
#else
            Sleep(1000);
#endif
        }
    }

    LOG_I("heci", "Monitor thread stopped. "
          "Total messages: %lu  Alerts: %lu  Unknown GUIDs: %lu",
          m->msg_count, m->alert_count, m->unknown_guid_count);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                          */
/* ------------------------------------------------------------------ */

heci_monitor_t *heci_monitor_create(bool amt_provisioned,
                                     heci_alert_fn fn, void *ctx)
{
    struct heci_monitor *m = calloc(1, sizeof(*m));
    if (!m) return NULL;

    m->amt_provisioned = amt_provisioned;
    m->alert_fn        = fn;
    m->alert_ctx       = ctx;
    rc_init(&m->rate, plat_tsc_freq_hz());

    /* Load GUID whitelist (file overrides built-in list if present) */
    load_whitelist_file();

    plat_err_t err = plat_mei_open(&m->fd);
    if (err != PLAT_OK) {
        LOG_W("heci", "Cannot open MEI device: %s. "
              "HECI monitor disabled.", plat_strerr(err));
        m->fd = PLAT_INVALID_FD;
    }

    return m;
}

int heci_monitor_start(heci_monitor_t *m)
{
    if (m->fd == PLAT_INVALID_FD) {
        LOG_W("heci", "No MEI device; skipping monitor thread.");
        return -1;
    }
    m->running = true;
    return pthread_create(&m->thread, NULL, monitor_thread, m);
}

void heci_monitor_stop(heci_monitor_t *m)
{
    if (!m) return;
    m->running = false;
    if (m->fd != PLAT_INVALID_FD) {
        pthread_join(m->thread, NULL);
        plat_mei_close(m->fd);
        m->fd = PLAT_INVALID_FD;
    }
    free(m);
}

void heci_monitor_stats(const heci_monitor_t *m, heci_stats_t *out)
{
    if (!m || !out) return;
    out->msg_count          = m->msg_count;
    out->alert_count        = m->alert_count;
    out->unknown_guid_count = m->unknown_guid_count;
}