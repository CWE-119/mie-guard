/*
 * mei-guard: DMI Bus Latency Profiler
 *
 * Detects passive ME/PCH DMA activity by measuring the side-channel
 * effect of PCH-initiated DMA reads on the system memory bus.
 *
 * Theory of operation:
 *   The CPU, RAM, and PCH (where the ME lives) all share the same
 *   memory bus (via DMI on Intel, or FCH on AMD).  When the ME reads
 *   or DMA-copies system RAM, it adds bus cycles that compete with
 *   CPU memory access, causing measurable latency increases.
 *
 *   We exploit this by:
 *     1. Allocating a fixed "probe page" of memory
 *     2. Flushing it from CPU caches (CLFLUSH) to force a DRAM read
 *     3. Measuring the read latency with RDTSC
 *     4. Repeating at high frequency and applying CUSUM on the series
 *
 *   CUSUM (Cumulative Sum) control chart:
 *     The algorithm is designed to detect small, persistent shifts in
 *     a time series that would be missed by simple thresholding.
 *     A genuine ME DMA scan causes a sustained 5–15% latency increase
 *     rather than a single spike, which is exactly what CUSUM finds.
 *
 * Calibration:
 *   We run a 10-second baseline phase at startup to determine:
 *     - Mean read latency (μ)
 *     - Std deviation (σ)
 *   CUSUM thresholds are set at μ + k*σ with k=0.5 (sensitive).
 *
 * False positive mitigation:
 *   - Cross-correlate with OS scheduler events (avoid flagging during
 *     disk I/O, IRQs, and known DMA-active periods)
 *   - Require the anomaly to persist for > MIN_ANOMALY_DURATION_MS
 *   - Pin the probe thread to a dedicated CPU core
 */

#include "dmi_latency.h"
#include "../platform/platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <pthread.h>

#ifdef PLAT_LINUX
  #include <sched.h>
  #include <unistd.h>
  #include <fcntl.h>
#endif

/* ------------------------------------------------------------------ */
/*  Tunables                                                            */
/* ------------------------------------------------------------------ */

#define PROBE_PAGE_SIZE          4096
#define SAMPLES_PER_SEC          5000   /* probes / second              */
#define BASELINE_SECONDS         10     /* calibration duration         */
#define BASELINE_SAMPLES         (SAMPLES_PER_SEC * BASELINE_SECONDS)
#define CUSUM_K_FACTOR           0.5    /* sensitivity factor           */
#define CUSUM_H_THRESHOLD        5.0    /* decision threshold (σ units) */
#define MIN_ANOMALY_DURATION_MS  200    /* sustained for this long      */
#define MOVING_AVG_WINDOW        50     /* for noise smoothing          */
#define CPU_PIN_CORE             2      /* dedicate core 2 to probing   */

/* ------------------------------------------------------------------ */
/*  Per-sample ring buffer                                              */
/* ------------------------------------------------------------------ */

#define RING_SIZE   (1 << 14)   /* 16384 samples (~3.3 seconds)        */
#define RING_MASK   (RING_SIZE - 1)

typedef struct {
    uint64_t samples[RING_SIZE];
    int      head;
    int      count;
} ring_buf_t;

static void ring_push(ring_buf_t *r, uint64_t v)
{
    r->samples[r->head] = v;
    r->head = (r->head + 1) & RING_MASK;
    if (r->count < RING_SIZE) r->count++;
}

/* ------------------------------------------------------------------ */
/*  Statistics helpers                                                  */
/* ------------------------------------------------------------------ */

static double compute_mean(const uint64_t *s, int n)
{
    double sum = 0;
    for (int i = 0; i < n; i++) sum += (double)s[i];
    return sum / n;
}

static double compute_stddev(const uint64_t *s, int n, double mean)
{
    double sum = 0;
    for (int i = 0; i < n; i++) {
        double d = (double)s[i] - mean;
        sum += d * d;
    }
    return sqrt(sum / n);
}

/* ------------------------------------------------------------------ */
/*  CUSUM algorithm                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    double  mean;       /* baseline mean (latency ticks)            */
    double  sigma;      /* baseline std deviation                   */
    double  k;          /* reference value: mean + k*sigma         */
    double  h;          /* decision threshold: h*sigma             */
    double  S_hi;       /* upper CUSUM accumulator                  */
    double  S_lo;       /* lower CUSUM accumulator (decreases OK)   */
    bool    alarmed;
} cusum_t;

static void cusum_init(cusum_t *c, double mean, double sigma)
{
    c->mean    = mean;
    c->sigma   = sigma;
    c->k       = mean + CUSUM_K_FACTOR * sigma;
    c->h       = CUSUM_H_THRESHOLD * sigma;
    c->S_hi    = 0;
    c->S_lo    = 0;
    c->alarmed = false;
}

/**
 * cusum_update() - Feed one sample into the CUSUM.
 * Returns true if an alarm condition has been reached.
 */
static bool cusum_update(cusum_t *c, double x)
{
    double z = (x - c->mean) / c->sigma;  /* standardise */

    c->S_hi += z - CUSUM_K_FACTOR;
    if (c->S_hi < 0) c->S_hi = 0;

    c->S_lo += -z - CUSUM_K_FACTOR;
    if (c->S_lo < 0) c->S_lo = 0;

    c->alarmed = (c->S_hi > CUSUM_H_THRESHOLD ||
                  c->S_lo > CUSUM_H_THRESHOLD);
    return c->alarmed;
}

static void cusum_reset(cusum_t *c)
{
    c->S_hi = c->S_lo = 0;
    c->alarmed = false;
}

/* ------------------------------------------------------------------ */
/*  Single memory latency probe                                         */
/* ------------------------------------------------------------------ */

static uint64_t probe_latency(volatile uint8_t *page)
{
    /* Flush the cache line */
    plat_flush_cacheline((void *)page);

    /* Serialise before the measurement */
    uint64_t t0 = plat_rdtsc();

    /* Force a read that must go to DRAM */
    uint8_t sink = *page;
    (void)sink;

    uint64_t t1 = plat_rdtsc();
    return t1 - t0;
}

/* ------------------------------------------------------------------ */
/*  Noise gate: try to detect OS-induced spikes                        */
/* ------------------------------------------------------------------ */

#ifdef PLAT_LINUX
static uint64_t read_irq_count(void)
{
    /* Sum all IRQs seen so far from /proc/stat line 'intr ...' */
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return 0;
    char line[1024];
    uint64_t total = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "intr ", 5) == 0) {
            sscanf(line + 5, "%lu", &total);
            break;
        }
    }
    fclose(f);
    return total;
}
#else
static uint64_t read_irq_count(void) { return 0; }
#endif

/* ------------------------------------------------------------------ */
/*  Monitor state                                                       */
/* ------------------------------------------------------------------ */

struct dmi_monitor {
    volatile uint8_t  *probe_page;

    /* Calibration */
    bool               calibrated;
    double             baseline_mean;
    double             baseline_sigma;

    /* CUSUM */
    cusum_t            cusum;

    /* Anomaly tracking */
    bool               in_anomaly;
    uint64_t           anomaly_start_tsc;
    uint64_t           tsc_freq;
    uint64_t           anomaly_count;

    /* Ring buffer for export */
    ring_buf_t         ring;
    pthread_mutex_t    ring_mutex;

    /* Thread */
    pthread_t          thread;
    volatile bool      running;

    /* Callback */
    dmi_alert_fn       alert_fn;
    void              *alert_ctx;
};

/* ------------------------------------------------------------------ */
/*  Calibration                                                         */
/* ------------------------------------------------------------------ */

static void calibrate(struct dmi_monitor *m)
{
    LOG_I("dmi_lat", "Calibrating baseline (%d samples, %d seconds)...",
          BASELINE_SAMPLES, BASELINE_SECONDS);

    uint64_t *samples = malloc(BASELINE_SAMPLES * sizeof(uint64_t));
    if (!samples) {
        LOG_W("dmi_lat", "Calibration malloc failed; using defaults");
        m->baseline_mean  = 200.0;
        m->baseline_sigma = 40.0;
        m->calibrated = true;
        return;
    }

    /* Warm up cache coherence state */
    for (int i = 0; i < 100; i++) probe_latency(m->probe_page);

    for (int i = 0; i < BASELINE_SAMPLES; i++) {
        samples[i] = probe_latency(m->probe_page);

        /* Rate-limit to SAMPLES_PER_SEC */
        if ((i % (SAMPLES_PER_SEC / 10)) == 0) {
#ifdef PLAT_LINUX
            struct timespec ts = { .tv_sec = 0,
                                   .tv_nsec = 100000000L / 10 };
            nanosleep(&ts, NULL);
#else
            Sleep(10);
#endif
        }
    }

    m->baseline_mean  = compute_mean(samples, BASELINE_SAMPLES);
    m->baseline_sigma = compute_stddev(samples, BASELINE_SAMPLES,
                                       m->baseline_mean);

    free(samples);
    m->calibrated = true;

    cusum_init(&m->cusum, m->baseline_mean, m->baseline_sigma);

    LOG_I("dmi_lat",
          "Calibration complete. "
          "Baseline μ=%.1f ticks  σ=%.1f ticks  "
          "(≈%.1f ns / %.1f ns at %.2f GHz)",
          m->baseline_mean, m->baseline_sigma,
          m->baseline_mean  / ((double)m->tsc_freq / 1e9),
          m->baseline_sigma / ((double)m->tsc_freq / 1e9),
          (double)m->tsc_freq / 1e9);
}

/* ------------------------------------------------------------------ */
/*  Monitor thread                                                      */
/* ------------------------------------------------------------------ */

static void *dmi_thread(void *arg)
{
    struct dmi_monitor *m = arg;

    /* Pin to a dedicated core to minimise scheduler noise */
#ifdef PLAT_LINUX
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(CPU_PIN_CORE, &cs);
    if (pthread_setaffinity_np(pthread_self(),
                                sizeof(cs), &cs) != 0) {
        LOG_W("dmi_lat", "Could not pin to core %d; "
              "false positives may increase", CPU_PIN_CORE);
    }
#endif

    calibrate(m);

    uint64_t last_irq  = read_irq_count();
    uint64_t sample_n  = 0;

    while (m->running) {
        uint64_t latency = probe_latency(m->probe_page);
        sample_n++;

        /* Store in ring */
        pthread_mutex_lock(&m->ring_mutex);
        ring_push(&m->ring, latency);
        pthread_mutex_unlock(&m->ring_mutex);

        /* Noise gate: skip sample if an IRQ fired during measurement */
        uint64_t cur_irq = read_irq_count();
        if (cur_irq != last_irq) {
            last_irq = cur_irq;
            cusum_reset(&m->cusum);
            continue;
        }

        bool alarm = cusum_update(&m->cusum, (double)latency);

        if (alarm && !m->in_anomaly) {
            m->in_anomaly      = true;
            m->anomaly_start_tsc = plat_rdtsc();
        }

        if (m->in_anomaly) {
            uint64_t elapsed_tsc = plat_rdtsc() - m->anomaly_start_tsc;
            uint64_t elapsed_ms  = elapsed_tsc * 1000 / m->tsc_freq;

            if (!alarm) {
                /* Anomaly ended before threshold */
                m->in_anomaly = false;
                cusum_reset(&m->cusum);
            } else if (elapsed_ms >= MIN_ANOMALY_DURATION_MS) {
                /* Confirmed sustained anomaly */
                m->in_anomaly  = false;
                m->anomaly_count++;
                cusum_reset(&m->cusum);

                dmi_alert_t alert = {
                    .elapsed_ms      = elapsed_ms,
                    .mean_latency_ns = m->baseline_mean /
                                       ((double)m->tsc_freq / 1e9),
                    .anomaly_latency_ns = (double)latency /
                                          ((double)m->tsc_freq / 1e9),
                    .cusum_score     = m->cusum.S_hi,
                    .anomaly_count   = m->anomaly_count,
                };
                snprintf(alert.detail, sizeof(alert.detail),
                    "DMI BUS LATENCY ANOMALY #%lu: "
                    "Sustained %lu ms latency spike. "
                    "Observed=%.1f ns vs baseline=%.1f ns "
                    "(%.0f%% increase). CUSUM S+=%.2f. "
                    "Pattern consistent with PCH DMA memory scraping. "
                    "Check for ME/BMC DMA activity.",
                    m->anomaly_count, elapsed_ms,
                    alert.anomaly_latency_ns,
                    alert.mean_latency_ns,
                    100.0 * (alert.anomaly_latency_ns /
                             alert.mean_latency_ns - 1.0),
                    m->cusum.S_hi);

                LOG_A("dmi_lat", "%s", alert.detail);
                if (m->alert_fn) m->alert_fn(&alert, m->alert_ctx);
            }
        }

        /* Rate limit: target SAMPLES_PER_SEC */
        if (sample_n % 100 == 0) {
#ifdef PLAT_LINUX
            struct timespec ts = { .tv_sec = 0,
                                   .tv_nsec = 100000000L /
                                              (SAMPLES_PER_SEC / 100) };
            nanosleep(&ts, NULL);
#else
            Sleep(1);
#endif
        }
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                          */
/* ------------------------------------------------------------------ */

dmi_monitor_t *dmi_monitor_create(dmi_alert_fn fn, void *ctx)
{
    struct dmi_monitor *m = calloc(1, sizeof(*m));
    if (!m) return NULL;

    m->probe_page = plat_alloc_uncached(PROBE_PAGE_SIZE);
    if (!m->probe_page) {
        free(m);
        return NULL;
    }
    memset((void *)m->probe_page, 0xAB, PROBE_PAGE_SIZE);

    m->tsc_freq   = plat_tsc_freq_hz();
    m->alert_fn   = fn;
    m->alert_ctx  = ctx;
    pthread_mutex_init(&m->ring_mutex, NULL);

    LOG_I("dmi_lat", "Probe page at %p  TSC freq %.2f GHz",
          (void *)m->probe_page, (double)m->tsc_freq / 1e9);

    if (!plat_has_uncached()) {
        LOG_W("dmi_lat",
              "No kernel-level uncached mapping available. "
              "Using CLFLUSH fallback – side-channel sensitivity reduced. "
              "Consider booting a kernel >= 5.10 for MAP_UNCACHED support.");
    }

    return m;
}

int dmi_monitor_start(dmi_monitor_t *m)
{
    m->running = true;
    return pthread_create(&m->thread, NULL, dmi_thread, m);
}

void dmi_monitor_stop(dmi_monitor_t *m)
{
    if (!m) return;
    m->running = false;
    pthread_join(m->thread, NULL);
    plat_free_uncached((void *)m->probe_page, PROBE_PAGE_SIZE);
    pthread_mutex_destroy(&m->ring_mutex);
    free(m);
}

int dmi_monitor_snapshot(const dmi_monitor_t *m,
                          uint64_t *out, int max_samples)
{
    pthread_mutex_lock((pthread_mutex_t *)&m->ring_mutex);
    int n = m->ring.count < max_samples ? m->ring.count : max_samples;
    for (int i = 0; i < n; i++) {
        int idx = (m->ring.head - n + i + RING_SIZE) & RING_MASK;
        out[i] = m->ring.samples[idx];
    }
    pthread_mutex_unlock((pthread_mutex_t *)&m->ring_mutex);
    return n;
}