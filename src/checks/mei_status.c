/*
 * mei-guard: MEI Firmware Status Register Monitor
 *
 * Reads and decodes the ME Firmware Status Registers (FWSTS1–FWSTS6)
 * via PCI configuration space (offset 0x40).
 *
 * The most critical register is FWSTS1 (HFS - Host Firmware Status):
 *
 *  [3:0]   ME operation mode:
 *            0x0 = Normal
 *            0x2 = Normal (power-saving)
 *            0x3 = Temp disabled
 *            0x4 = Temp disabled
 *            0x5 = SECOVER_JMPR (Security Override Jumper) ← RED FLAG
 *            0x6 = SECOVER_MFGJMPR (Manufacturing Jumper)  ← RED FLAG
 *            0x7 = Enhanced Debug Mode                     ← RED FLAG
 *  [8:4]   ME firmware state machine state
 *  [9]     ME init complete
 *  [10]    ME Boot Options Present
 *  [12]    ME Reset Count
 *  [14]    Manufacturing mode                              ← RED FLAG
 *
 * References:
 *   Intel ME BIOS Writer Guide (public, search "826828")
 *   Intel ME 11 Architecture specification
 *   Trammell Hudson's "me_cleaner" project documentation
 */

#include "mei_status.h"
#include "../platform/platform.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  FWSTS register offsets in PCI config space                          */
/* ------------------------------------------------------------------ */

#define MEI_PCI_FWSTS1   0x40
#define MEI_PCI_FWSTS2   0x48
#define MEI_PCI_FWSTS3   0x60
#define MEI_PCI_FWSTS4   0x64
#define MEI_PCI_FWSTS5   0x68
#define MEI_PCI_FWSTS6   0x6C

/* ------------------------------------------------------------------ */
/*  FWSTS1 field extraction                                             */
/* ------------------------------------------------------------------ */

#define FWSTS1_OP_MODE(x)        ((x) & 0x0F)
#define FWSTS1_STATE(x)          (((x) >> 4) & 0x1F)
#define FWSTS1_INIT_COMPLETE(x)  (((x) >> 9) & 0x1)
#define FWSTS1_MFG_MODE(x)       (((x) >> 14) & 0x1)
#define FWSTS1_ERROR_CODE(x)     (((x) >> 15) & 0xF)
#define FWSTS1_OPERATION_STATE(x)(((x) >> 5) & 0x7)

typedef enum {
    ME_OP_NORMAL       = 0x0,
    ME_OP_NORMAL_PS    = 0x2,
    ME_OP_TEMP_DIS_1   = 0x3,
    ME_OP_TEMP_DIS_2   = 0x4,
    ME_OP_SECOVER_JMPR = 0x5,   /* ← CRITICAL: Security Override       */
    ME_OP_SECOVER_MFG  = 0x6,   /* ← CRITICAL: Manufacturing Override  */
    ME_OP_ENHANCED_DBG = 0x7,   /* ← HIGH: Enhanced Debug Mode         */
} me_op_mode_t;

static const char *op_mode_str(me_op_mode_t m)
{
    switch (m) {
        case ME_OP_NORMAL:       return "Normal";
        case ME_OP_NORMAL_PS:    return "Normal (Power Saving)";
        case ME_OP_TEMP_DIS_1:   return "Temporarily Disabled";
        case ME_OP_TEMP_DIS_2:   return "Temporarily Disabled (Alt)";
        case ME_OP_SECOVER_JMPR: return "SECOVER_JMPR [SECURITY OVERRIDE JUMPER]";
        case ME_OP_SECOVER_MFG:  return "SECOVER_MFGJMPR [MANUFACTURING OVERRIDE]";
        case ME_OP_ENHANCED_DBG: return "Enhanced Debug Mode";
        default:                 return "Unknown";
    }
}

/* ------------------------------------------------------------------ */
/*  FWSTS2: extended state (ME 11+)                                     */
/* ------------------------------------------------------------------ */

#define FWSTS2_BIST_IN_PROGRESS(x)  ((x) & 0x1)
#define FWSTS2_BIST_ERR_CODE(x)     (((x) >> 1) & 0xF)
#define FWSTS2_MPHY_READY(x)        (((x) >> 8) & 0x1)
#define FWSTS2_ICC_PROG_STATUS(x)   (((x) >> 16) & 0x3)
#define FWSTS2_CPU_REPLACED(x)      (((x) >> 18) & 0x1)
#define FWSTS2_EXTSTAT(x)           (((x) >> 20) & 0xFF)

/* ------------------------------------------------------------------ */
/*  SYSFS fallback (Linux without PCI access)                           */
/* ------------------------------------------------------------------ */

#ifdef PLAT_LINUX
#include <fcntl.h>
#include <unistd.h>

static bool read_fwsts_sysfs(int reg_num, uint32_t *val)
{
    char path[128];
    snprintf(path, sizeof(path),
             "/sys/class/mei/mei0/fw_status");

    /* mei driver exposes all FWSTS registers as a space-separated string */
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    char buf[256] = {0};
    read(fd, buf, sizeof(buf) - 1);
    close(fd);

    /* Parse: "FWSTS1 FWSTS2 FWSTS3 FWSTS4 FWSTS5 FWSTS6" */
    uint32_t regs[6] = {0};
    int n = sscanf(buf, "%x %x %x %x %x %x",
                   &regs[0], &regs[1], &regs[2],
                   &regs[3], &regs[4], &regs[5]);
    if (n < reg_num) return false;
    *val = regs[reg_num - 1];
    return true;
}
#endif /* PLAT_LINUX */

/* ------------------------------------------------------------------ */
/*  Public API                                                          */
/* ------------------------------------------------------------------ */

mei_status_result_t mei_status_check(void)
{
    mei_status_result_t result = { .status = MEI_STATUS_OK };
    uint32_t fwsts1 = 0, fwsts2 = 0;

    /* Try sysfs first (doesn't need PCI root access) */
    bool got_fwsts = false;

#ifdef PLAT_LINUX
    if (read_fwsts_sysfs(1, &fwsts1)) {
        read_fwsts_sysfs(2, &fwsts2);
        got_fwsts = true;
    }
#endif

    /* Fall back to direct PCI config space read */
    if (!got_fwsts) {
        plat_pci_addr_t pci;
        plat_err_t err = plat_pci_find_mei(&pci);
        if (err != PLAT_OK) {
            result.status = MEI_STATUS_UNAVAILABLE;
            snprintf(result.detail, sizeof(result.detail),
                     "MEI PCI device not found: %s", plat_strerr(err));
            return result;
        }

        if (plat_pci_read32(&pci, MEI_PCI_FWSTS1, &fwsts1) != PLAT_OK ||
            plat_pci_read32(&pci, MEI_PCI_FWSTS2, &fwsts2) != PLAT_OK) {
            result.status = MEI_STATUS_UNAVAILABLE;
            snprintf(result.detail, sizeof(result.detail),
                     "Cannot read PCI config space registers");
            return result;
        }
    }

    result.fwsts1 = fwsts1;
    result.fwsts2 = fwsts2;

    me_op_mode_t op_mode = (me_op_mode_t)FWSTS1_OP_MODE(fwsts1);
    bool mfg_mode        = FWSTS1_MFG_MODE(fwsts1);
    uint8_t err_code     = FWSTS1_ERROR_CODE(fwsts1);
    bool cpu_replaced    = FWSTS2_CPU_REPLACED(fwsts2);

    LOG_I("mei_status",
          "FWSTS1=0x%08X  FWSTS2=0x%08X  "
          "OP_MODE=%s  MFG=%d  ERR=0x%X  CPU_REPLACED=%d",
          fwsts1, fwsts2,
          op_mode_str(op_mode), mfg_mode, err_code, cpu_replaced);

    /* --- Evaluate conditions --- */

    if (op_mode == ME_OP_SECOVER_JMPR || op_mode == ME_OP_SECOVER_MFG) {
        result.status = MEI_STATUS_SECURITY_OVERRIDE;
        snprintf(result.detail, sizeof(result.detail),
                 "CRITICAL: ME operation mode = %s (0x%X). "
                 "The Management Engine is in Security Override mode. "
                 "This is used to flash unsigned ME firmware. "
                 "Unless you physically moved the SECOVER jumper yourself, "
                 "this is a strong indicator of hardware-level compromise.",
                 op_mode_str(op_mode), op_mode);
        LOG_C("mei_status", "%s", result.detail);
        return result;
    }

    if (op_mode == ME_OP_ENHANCED_DBG) {
        result.status = MEI_STATUS_DEBUG_MODE;
        snprintf(result.detail, sizeof(result.detail),
                 "HIGH: ME Enhanced Debug Mode active (0x%X). "
                 "Debug mode exposes JTAG and serial console. "
                 "Verify this was set intentionally for legitimate development.",
                 op_mode);
        LOG_A("mei_status", "%s", result.detail);
        return result;
    }

    if (mfg_mode) {
        result.status = MEI_STATUS_MFG_MODE;
        snprintf(result.detail, sizeof(result.detail),
                 "HIGH: ME Manufacturing Mode flag is set in FWSTS1. "
                 "Manufacturing mode allows unsigned firmware operations. "
                 "This flag should NOT be set on a production system.");
        LOG_A("mei_status", "%s", result.detail);
        return result;
    }

    if (cpu_replaced) {
        result.status = MEI_STATUS_CPU_REPLACED;
        snprintf(result.detail, sizeof(result.detail),
                 "MEDIUM: ME CPU_REPLACED flag set (FWSTS2 bit 18). "
                 "The ME detected the CPU was swapped since the last boot. "
                 "If you did not replace the CPU, this may indicate a "
                 "supply-chain interdiction event.");
        LOG_W("mei_status", "%s", result.detail);
        return result;
    }

    if (err_code != 0) {
        result.status = MEI_STATUS_ERROR;
        snprintf(result.detail, sizeof(result.detail),
                 "ME reports error code 0x%X in FWSTS1. "
                 "This may indicate a failed firmware operation or "
                 "detected tampering.", err_code);
        LOG_W("mei_status", "%s", result.detail);
        return result;
    }

    result.status = MEI_STATUS_OK;
    snprintf(result.detail, sizeof(result.detail),
             "ME status nominal. Operation mode: %s. "
             "FWSTS1=0x%08X FWSTS2=0x%08X",
             op_mode_str(op_mode), fwsts1, fwsts2);
    LOG_I("mei_status", "%s", result.detail);
    return result;
}