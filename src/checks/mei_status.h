#ifndef MEI_STATUS_H
#define MEI_STATUS_H

#include <stdint.h>

typedef enum {
    MEI_STATUS_OK               = 0,
    MEI_STATUS_SECURITY_OVERRIDE = 1,  /* SECOVER_JMPR / SECOVER_MFGJMPR */
    MEI_STATUS_MFG_MODE         = 2,   /* Manufacturing mode flag set      */
    MEI_STATUS_DEBUG_MODE       = 3,   /* Enhanced debug mode active       */
    MEI_STATUS_CPU_REPLACED     = 4,   /* CPU swap detected by ME          */
    MEI_STATUS_ERROR            = 5,   /* ME error code non-zero           */
    MEI_STATUS_UNAVAILABLE      = 6,   /* Cannot read PCI regs             */
} mei_status_t;

typedef struct {
    mei_status_t status;
    uint32_t     fwsts1;
    uint32_t     fwsts2;
    char         detail[512];
} mei_status_result_t;

mei_status_result_t mei_status_check(void);

#endif /* MEI_STATUS_H */