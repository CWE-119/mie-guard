#ifndef MICROCODE_VERIFIER_H
#define MICROCODE_VERIFIER_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    MC_OK               = 0,
    MC_REVISION_CHANGED = 1,   /* Revision differs from DB: ALERT         */
    MC_HASH_MISMATCH    = 2,   /* Firmware blob hash differs: CRITICAL     */
    MC_NO_DB            = 3,   /* No trusted DB enrolled yet               */
    MC_UNKNOWN_CPU      = 4,   /* This CPUID not in DB                     */
    MC_UNAVAILABLE      = 5,   /* MSR read failed (permissions/no module)  */
} mc_status_t;

typedef struct {
    mc_status_t status;
    uint32_t    cpuid;
    uint32_t    revision;
    char        detail[512];
} mc_check_result_t;

/**
 * microcode_check() - Run the full microcode integrity check.
 * Call once at boot and then periodically (every 30–60 minutes).
 */
mc_check_result_t microcode_check(void);

/**
 * microcode_enroll() - Write the current microcode state to the
 * trusted database.  Run this once on a known-clean system.
 */
void microcode_enroll(void);

#endif /* MICROCODE_VERIFIER_H */