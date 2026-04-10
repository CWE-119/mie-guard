#ifndef HECI_MONITOR_H
#define HECI_MONITOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/*  Alert types and severities                                          */
/* ------------------------------------------------------------------ */

typedef enum {
    ALERT_LOW      = 1,
    ALERT_MEDIUM   = 2,
    ALERT_HIGH     = 3,
    ALERT_CRITICAL = 4,
} alert_severity_t;

typedef enum {
    HECI_ALERT_UNKNOWN_GUID  = 0x01, /* GUID not in Intel public spec      */
    HECI_ALERT_BURST         = 0x02, /* > N messages per second            */
    HECI_ALERT_AMT_UNGATED   = 0x03, /* AMT client active without AMT BIOS */
    HECI_ALERT_MKHI_UNUSUAL  = 0x04, /* Unusual MKHI group/command         */
} heci_alert_type_t;

typedef struct {
    heci_alert_type_t type;
    alert_severity_t  severity;
    uint64_t          msg_count;
    char              detail[512];
} heci_alert_t;

typedef struct {
    uint64_t msg_count;
    uint64_t alert_count;
    uint64_t unknown_guid_count;
} heci_stats_t;

/* ------------------------------------------------------------------ */
/*  API                                                                 */
/* ------------------------------------------------------------------ */

typedef struct heci_monitor heci_monitor_t;
typedef void (*heci_alert_fn)(const heci_alert_t *alert, void *ctx);

heci_monitor_t *heci_monitor_create(bool amt_provisioned,
                                     heci_alert_fn fn, void *ctx);
int             heci_monitor_start(heci_monitor_t *m);
void            heci_monitor_stop(heci_monitor_t *m);
void            heci_monitor_stats(const heci_monitor_t *m,
                                   heci_stats_t *out);

#endif /* HECI_MONITOR_H */