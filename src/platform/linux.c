/*
 * mei-guard: Linux platform backend (Revised)
 *
 * Implements the platform abstraction for Linux using:
 *   /dev/mei0          – HECI host interface
 *   /dev/cpu/N/msr     – MSR access (requires msr kernel module)
 *   /sys/bus/pci       – PCI config space via sysfs
 *   mmap + clflush     – Uncached/locked memory for latency probing
 *
 * Uncached memory strategy (three methods, best-first):
 *   1. MAP_UNCACHED flag (Linux >= 5.10)
 *   2. Locked cacheable memory + CLFLUSH on every probe (fallback)
 */

#ifndef _WIN32  /* Entire file excluded on Windows */

#define _GNU_SOURCE

#ifndef MAP_UNCACHED
#define MAP_UNCACHED 0   /* not defined on older kernels; disable path */
#endif
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <poll.h>
#include <pthread.h>
#include <dirent.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/*  Logging                                                             */
/* ------------------------------------------------------------------ */

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE           *g_alert_log  = NULL;
static log_level_t     g_min_level  = LOG_DEBUG;

static const char *level_str[] = {
    [LOG_DEBUG] = "DEBUG",
    [LOG_INFO]  = "INFO ",
    [LOG_WARN]  = "WARN ",
    [LOG_ALERT] = "ALERT",
    [LOG_CRIT]  = "CRIT ",
};

static const char *level_color[] = {
    [LOG_DEBUG] = "\033[37m",    /* white  */
    [LOG_INFO]  = "\033[36m",    /* cyan   */
    [LOG_WARN]  = "\033[33m",    /* yellow */
    [LOG_ALERT] = "\033[31m",    /* red    */
    [LOG_CRIT]  = "\033[1;31m",  /* bold red */
};

void plat_log(log_level_t level, const char *module,
              const char *fmt, ...)
{
    if (level < g_min_level) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&g_log_mutex);

    /* Console */
    fprintf(stderr, "%s[%ld.%06ld] [%s] [%-16s] %s\033[0m\n",
            level_color[level],
            (long)ts.tv_sec, ts.tv_nsec / 1000,
            level_str[level], module, msg);

    /* Persistent alert log */
    if (g_alert_log && level >= LOG_ALERT) {
        fprintf(g_alert_log,
                "[%ld.%06ld] [%s] [%s] %s\n",
                (long)ts.tv_sec, ts.tv_nsec / 1000,
                level_str[level], module, msg);
        fflush(g_alert_log);
    }

    pthread_mutex_unlock(&g_log_mutex);
}

/* ------------------------------------------------------------------ */
/*  Init / teardown                                                     */
/* ------------------------------------------------------------------ */

plat_err_t plat_init(void)
{
    /* Try to open persistent alert log */
    g_alert_log = fopen("/var/log/mei-guard/alerts.log", "a");
    if (!g_alert_log) {
        /* Fall back to cwd */
        g_alert_log = fopen("mei-guard-alerts.log", "a");
    }

    /* Ensure /dev/mei0 exists */
    struct stat st;
    if (stat("/dev/mei0", &st) != 0) {
        plat_log(LOG_WARN, "platform",
                 "/dev/mei0 not found – HECI monitor disabled. "
                 "Is intel_mei loaded? Try: modprobe mei_me");
    }

    /* Ensure msr module is loaded */
    if (stat("/dev/cpu/0/msr", &st) != 0) {
        plat_log(LOG_WARN, "platform",
                 "/dev/cpu/0/msr not found – "
                 "Microcode verifier disabled. "
                 "Try: modprobe msr");
    }

    return PLAT_OK;
}

void plat_teardown(void)
{
    if (g_alert_log) {
        fclose(g_alert_log);
        g_alert_log = NULL;
    }
}

const char *plat_strerr(plat_err_t err)
{
    switch (err) {
        case PLAT_OK:           return "success";
        case PLAT_ERR_PERM:     return "permission denied (run as root)";
        case PLAT_ERR_NODEV:    return "device not found";
        case PLAT_ERR_IO:       return "I/O error";
        case PLAT_ERR_NOMEM:    return "out of memory";
        case PLAT_ERR_TIMEOUT:  return "timeout";
        case PLAT_ERR_UNSUP:    return "unsupported";
        default:                return "unknown error";
    }
}

/* ------------------------------------------------------------------ */
/*  TSC frequency calibration                                           */
/* ------------------------------------------------------------------ */

uint64_t plat_tsc_freq_hz(void)
{
    /* 1. Try CPUID leaf 0x15 (TSC / Core Crystal Clock Ratio) */
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ volatile (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0x15), "c"(0)
    );
    if (eax && ebx && ecx) {
        return (uint64_t)ecx * ebx / eax;
    }

    /* 2. Fall back: read /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq */
    FILE *f = fopen(
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", "r");
    if (f) {
        unsigned long khz = 0;
        if (fscanf(f, "%lu", &khz) == 1) {
            fclose(f);
            return (uint64_t)khz * 1000ULL;
        }
        fclose(f);
    }

    /* 3. Busy-wait calibration: 50 ms */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    uint64_t tsc0 = plat_rdtsc();
    /* spin 50 ms */
    do { clock_gettime(CLOCK_MONOTONIC, &t1); }
    while ((t1.tv_sec  - t0.tv_sec) * 1000000000LL +
           (t1.tv_nsec - t0.tv_nsec) < 50000000LL);
    uint64_t tsc1 = plat_rdtsc();
    long ns = (t1.tv_sec  - t0.tv_sec) * 1000000000LL +
              (t1.tv_nsec - t0.tv_nsec);
    return (tsc1 - tsc0) * 1000000000ULL / (uint64_t)ns;
}

/* ------------------------------------------------------------------ */
/*  MSR access                                                          */
/* ------------------------------------------------------------------ */

plat_err_t plat_rdmsr(uint64_t msr, uint64_t *value)
{
    char path[64];
    snprintf(path, sizeof(path), "/dev/cpu/0/msr");

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT)  return PLAT_ERR_NODEV;
        if (errno == EACCES)  return PLAT_ERR_PERM;
        return PLAT_ERR_IO;
    }

    uint64_t v;
    ssize_t r = pread(fd, &v, sizeof(v), (off_t)msr);
    close(fd);

    if (r != sizeof(v)) {
        /* SIGBUS / EIO usually means the MSR doesn't exist on this CPU */
        return PLAT_ERR_UNSUP;
    }

    *value = v;
    return PLAT_OK;
}

/* ------------------------------------------------------------------ */
/*  PCI config space                                                    */
/* ------------------------------------------------------------------ */

/* Known Intel MEI PCI device IDs (non-exhaustive; extend as needed) */
static const uint16_t MEI_DEVICE_IDS[] = {
    0x1C3A, /* Cougar Point   */
    0x1D3A, /* Patsburg       */
    0x1E3A, /* Panther Point  */
    0x8C3A, /* Lynx Point     */
    0x8CBA, /* Lynx Point-LP  */
    0x9C3A, /* Wildcat Point  */
    0xA13A, /* Sunrise Point  */
    0xA2BA, /* Union Point    */
    0x9DE0, /* Cannon Point   */
    0x02E0, /* Ice Point      */
    0x43E0, /* Tiger Point    */
    0x7AE8, /* Raptor Point   */
    0xA848, /* Meteor Lake    */
    0,      /* sentinel       */
};

plat_err_t plat_pci_find_mei(plat_pci_addr_t *addr)
{
    DIR *dir = opendir("/sys/bus/pci/devices");
    if (!dir) return PLAT_ERR_NODEV;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char path[512];
        /* Read vendor */
        snprintf(path, sizeof(path),
                 "/sys/bus/pci/devices/%s/vendor", ent->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        unsigned vendor = 0;
        int ok = fscanf(f, "%x", &vendor);
        fclose(f);
        if (ok != 1 || vendor != 0x8086) continue;

        /* Read device ID */
        snprintf(path, sizeof(path),
                 "/sys/bus/pci/devices/%s/device", ent->d_name);
        f = fopen(path, "r");
        if (!f) continue;
        unsigned device = 0;
        ok = fscanf(f, "%x", &device);
        fclose(f);
        if (ok != 1) continue;

        for (int i = 0; MEI_DEVICE_IDS[i]; i++) {
            if ((uint16_t)device != MEI_DEVICE_IDS[i]) continue;

            addr->vendor_id = (uint16_t)vendor;
            addr->device_id = (uint16_t)device;

            /* Parse "domain:bus:slot.func" from directory name */
            unsigned dom = 0, bus = 0, dev = 0, func = 0;
            if (sscanf(ent->d_name, "%04x:%02x:%02x.%x",
                       &dom, &bus, &dev, &func) == 4) {
                addr->bus  = (uint8_t)bus;
                addr->slot = (uint8_t)dev;
                addr->func = (uint8_t)func;
            }
            closedir(dir);
            return PLAT_OK;
        }
    }

    closedir(dir);
    return PLAT_ERR_NODEV;
}

plat_err_t plat_pci_read32(const plat_pci_addr_t *addr,
                            uint16_t offset, uint32_t *value)
{
    char path[256];
    snprintf(path, sizeof(path),
             "/sys/bus/pci/devices/%04x:%02x:%02x.%x/config",
             0, addr->bus, addr->slot, addr->func);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return PLAT_ERR_NODEV;

    uint32_t v;
    ssize_t r = pread(fd, &v, sizeof(v), offset);
    close(fd);

    if (r != (ssize_t)sizeof(v)) return PLAT_ERR_IO;
    *value = v;
    return PLAT_OK;
}

/* ------------------------------------------------------------------ */
/*  HECI device I/O                                                     */
/* ------------------------------------------------------------------ */

plat_err_t plat_mei_open(plat_fd_t *fd)
{
    int f = open("/dev/mei0", O_RDWR | O_NONBLOCK);
    if (f < 0) {
        if (errno == ENOENT)  return PLAT_ERR_NODEV;
        if (errno == EACCES)  return PLAT_ERR_PERM;
        return PLAT_ERR_IO;
    }
    *fd = f;
    return PLAT_OK;
}

ssize_t plat_mei_read(plat_fd_t fd, void *buf, size_t len, int timeout_ms)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int r = poll(&pfd, 1, timeout_ms);
    if (r == 0) return 0;          /* timeout – no data */
    if (r < 0)  return -1;
    return read(fd, buf, len);
}

void plat_mei_close(plat_fd_t fd)
{
    if (fd >= 0) close(fd);
}

/* ------------------------------------------------------------------ */
/*  Uncached memory allocation                                          */
/*                                                                      */
/*  Method 1: MAP_UNCACHED (Linux >= 5.10, bypasses page cache)        */
/*  Method 2: Locked cacheable page + CLFLUSH on every probe access    */
/*            (still effective: forces DRAM round-trip per measurement) */
/* ------------------------------------------------------------------ */

static bool g_have_real_uncached = false;

void *plat_alloc_uncached(size_t size)
{
    void *ptr = MAP_FAILED;

#if defined(MAP_UNCACHED) && (MAP_UNCACHED != 0)
    /* Method 1: kernel-level uncached mapping */
    ptr = mmap(NULL, size,
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_UNCACHED | MAP_LOCKED,
               -1, 0);
    if (ptr != MAP_FAILED) {
        g_have_real_uncached = true;
        LOG_I("platform",
              "Uncached memory via MAP_UNCACHED (%zu bytes)", size);
        /* Touch every page */
        volatile uint8_t *b = ptr;
        for (size_t i = 0; i < size; i += 4096) b[i] = 0;
        return ptr;
    }
    LOG_D("platform", "MAP_UNCACHED failed (%s); using fallback",
          strerror(errno));
#endif

    /* Method 2: locked cacheable page — CLFLUSH at probe time is sufficient */
    ptr = mmap(NULL, size,
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
               -1, 0);
    if (ptr == MAP_FAILED) return NULL;

    g_have_real_uncached = false;

    /* Fault all pages in */
    volatile uint8_t *b = ptr;
    for (size_t i = 0; i < size; i += 4096) b[i] = 0;

    LOG_I("platform",
          "Uncached fallback: cacheable locked page (%zu bytes). "
          "CLFLUSH will be applied per-probe.", size);
    return ptr;
}

void plat_free_uncached(void *ptr, size_t size)
{
    if (ptr) munmap(ptr, size);
}

/**
 * plat_has_uncached() - Returns true if plat_alloc_uncached() succeeded
 * with a kernel-level uncached mapping (MAP_UNCACHED).  Returns false
 * when using the CLFLUSH fallback; callers can log reduced sensitivity.
 */
bool plat_has_uncached(void)
{
    return g_have_real_uncached;
}

#endif /* !_WIN32 */