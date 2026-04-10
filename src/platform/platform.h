#ifndef MEI_GUARD_PLATFORM_H
#define MEI_GUARD_PLATFORM_H

/*
 * mei-guard: Ring -3 Heuristic Anomaly Detection System
 * Platform Abstraction Layer
 *
 * Provides a unified API across Linux and Windows for:
 *   - HECI/MEI device access
 *   - MSR (Model-Specific Register) reading
 *   - PCI configuration space access
 *   - High-resolution timing (RDTSC)
 *   - Uncached memory allocation for latency probing
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef _WIN32
  #include <windows.h>
  typedef HANDLE   plat_fd_t;
  #define PLAT_INVALID_FD  INVALID_HANDLE_VALUE
  #define PLAT_WINDOWS     1
#else
  #include <sys/types.h>
  typedef int      plat_fd_t;
  #define PLAT_INVALID_FD  (-1)
  #define PLAT_LINUX       1
#endif

/* ------------------------------------------------------------------ */
/*  Return codes                                                        */
/* ------------------------------------------------------------------ */
typedef enum {
    PLAT_OK            =  0,
    PLAT_ERR_PERM      = -1,   /* Insufficient privileges              */
    PLAT_ERR_NODEV     = -2,   /* Device not found                     */
    PLAT_ERR_IO        = -3,   /* I/O error                            */
    PLAT_ERR_NOMEM     = -4,   /* Memory allocation failure            */
    PLAT_ERR_TIMEOUT   = -5,   /* Operation timed out                  */
    PLAT_ERR_UNSUP     = -6,   /* Unsupported on this platform/CPU     */
} plat_err_t;

/* ------------------------------------------------------------------ */
/*  Timing                                                              */
/* ------------------------------------------------------------------ */

/**
 * plat_rdtsc() - Read the hardware Time Stamp Counter.
 * Serialized with CPUID to prevent out-of-order execution skewing
 * measurements.  Returns raw TSC ticks; caller converts with
 * plat_tsc_freq_hz() if wall-clock time is needed.
 */
static inline uint64_t plat_rdtsc(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    uint32_t lo, hi;
    __asm__ volatile (
        "cpuid\n\t"          /* serialize */
        "rdtsc\n\t"
        : "=a"(lo), "=d"(hi)
        : "a"(0)
        : "rbx", "rcx"
    );
    return ((uint64_t)hi << 32) | lo;
#elif defined(__i386__) || defined(_M_IX86)
    uint64_t tsc;
    __asm__ volatile ("rdtsc" : "=A"(tsc));
    return tsc;
#else
    #error "RDTSC only available on x86/x86_64"
#endif
}

/**
 * plat_tsc_freq_hz() - Estimate TSC frequency in Hz.
 * Uses CPUID leaf 0x15 when available, otherwise falls back to a
 * 50 ms busy-wait calibration.
 */
uint64_t plat_tsc_freq_hz(void);

/* ------------------------------------------------------------------ */
/*  MSR access (requires ring-0 / Administrator)                       */
/* ------------------------------------------------------------------ */

/* Well-known MSR addresses relevant to ME/microcode detection */
#define MSR_IA32_BIOS_UPDT_TRIG   0x79ULL   /* Microcode update trigger     */
#define MSR_IA32_BIOS_SIGN_ID     0x8BULL   /* Current microcode revision   */
#define MSR_IA32_PLATFORM_ID      0x17ULL   /* Platform ID fuses            */
#define MSR_IA32_MCG_STATUS       0x17AULL  /* Machine Check Global Status  */
#define MSR_PERF_GLOBAL_STATUS    0x38EULL  /* PMU overflow status          */

/**
 * plat_rdmsr() - Read a Model-Specific Register.
 *
 * @msr:   MSR address
 * @value: Output; populated on PLAT_OK
 *
 * Linux: opens /dev/cpu/0/msr or uses the kernel module's
 *        /proc/mei_guard_msr interface.
 * Windows: uses NtQuerySystemInformation (SystemProcessorInformation
 *          extended) via a thin ring-0 driver shim.
 */
plat_err_t plat_rdmsr(uint64_t msr, uint64_t *value);

/* ------------------------------------------------------------------ */
/*  PCI configuration space                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t  bus;
    uint8_t  slot;
    uint8_t  func;
} plat_pci_addr_t;

/**
 * plat_pci_find_mei() - Locate the MEI/HECI PCI device.
 * Searches by Intel vendor ID (0x8086) and known MEI device IDs.
 * Populates @addr on success.
 */
plat_err_t plat_pci_find_mei(plat_pci_addr_t *addr);

/**
 * plat_pci_read32() - Read a 32-bit DWORD from PCI config space.
 */
plat_err_t plat_pci_read32(const plat_pci_addr_t *addr,
                            uint16_t offset, uint32_t *value);

/* ------------------------------------------------------------------ */
/*  HECI/MEI device I/O                                                 */
/* ------------------------------------------------------------------ */

/**
 * plat_mei_open() - Open the MEI host interface.
 * Linux: /dev/mei0
 * Windows: \\.\INTC_MEI0  (Intel MEI driver)
 */
plat_err_t plat_mei_open(plat_fd_t *fd);

/**
 * plat_mei_read() - Non-blocking read from the MEI FIFO.
 * Returns bytes read, 0 on no data, negative on error.
 */
ssize_t plat_mei_read(plat_fd_t fd, void *buf, size_t len, int timeout_ms);

/**
 * plat_mei_close() - Release the MEI handle.
 */
void plat_mei_close(plat_fd_t fd);

/* ------------------------------------------------------------------ */
/*  Memory: uncached allocation for latency probing                     */
/* ------------------------------------------------------------------ */

/**
 * plat_alloc_uncached() - Allocate a page of write-combining/uncached
 * memory suitable for DMI latency probing.  The returned pointer is
 * page-aligned and its physical address is guaranteed not to be in any
 * CPU cache when plat_flush_cache() is called.
 *
 * Linux: MAP_UNCACHED (kernel >= 5.10) → true uncached mapping.
 *        Fallback: MAP_LOCKED + CLFLUSH per probe (still effective).
 * Windows: VirtualAlloc + _mm_clflush
 */
void *plat_alloc_uncached(size_t size);
void  plat_free_uncached(void *ptr, size_t size);

/**
 * plat_has_uncached() - Returns true if the last plat_alloc_uncached()
 * call obtained a kernel-level uncached mapping (MAP_UNCACHED).
 * Returns false when using the CLFLUSH-on-locked-page fallback.
 * The DMI latency profiler uses this to calibrate its sensitivity warning.
 */
bool plat_has_uncached(void);

/**
 * plat_flush_cacheline() - Flush a single cache line containing @ptr.
 */
static inline void plat_flush_cacheline(const void *ptr)
{
#if defined(__x86_64__) || defined(__i386__) || \
    defined(_M_X64)    || defined(_M_IX86)
    __asm__ volatile ("clflush (%0)" : : "r"(ptr) : "memory");
#endif
}

/* ------------------------------------------------------------------ */
/*  Logging                                                             */
/* ------------------------------------------------------------------ */

typedef enum {
    LOG_DEBUG   = 0,
    LOG_INFO    = 1,
    LOG_WARN    = 2,
    LOG_ALERT   = 3,   /* Anomaly detected; write to alert log         */
    LOG_CRIT    = 4,   /* Possible compromise; page the operator       */
} log_level_t;

void plat_log(log_level_t level, const char *module,
              const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#define LOG_D(mod, ...) plat_log(LOG_DEBUG, mod, __VA_ARGS__)
#define LOG_I(mod, ...) plat_log(LOG_INFO,  mod, __VA_ARGS__)
#define LOG_W(mod, ...) plat_log(LOG_WARN,  mod, __VA_ARGS__)
#define LOG_A(mod, ...) plat_log(LOG_ALERT, mod, __VA_ARGS__)
#define LOG_C(mod, ...) plat_log(LOG_CRIT,  mod, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/*  Init / teardown                                                     */
/* ------------------------------------------------------------------ */

/**
 * plat_init() - One-time platform initialisation.
 * Must be called before any other plat_*() function.
 */
plat_err_t plat_init(void);
void       plat_teardown(void);

/** plat_strerr() - Human-readable string for a plat_err_t. */
const char *plat_strerr(plat_err_t err);

#endif /* MEI_GUARD_PLATFORM_H */