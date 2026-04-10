#ifndef DMI_LATENCY_H
#define DMI_LATENCY_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint64_t elapsed_ms;
    double   mean_latency_ns;
    double   anomaly_latency_ns;
    double   cusum_score;
    uint64_t anomaly_count;
    char     detail[512];
} dmi_alert_t;

typedef struct dmi_monitor dmi_monitor_t;
typedef void (*dmi_alert_fn)(const dmi_alert_t *alert, void *ctx);

dmi_monitor_t *dmi_monitor_create(dmi_alert_fn fn, void *ctx);
int            dmi_monitor_start(dmi_monitor_t *m);
void           dmi_monitor_stop(dmi_monitor_t *m);

/** dmi_monitor_snapshot(): copy last N latency samples (in TSC ticks) */
int            dmi_monitor_snapshot(const dmi_monitor_t *m,
                                    uint64_t *out, int max_samples);

#endif /* DMI_LATENCY_H */