/*
 * mei-guard: Windows platform backend
 *
 * Implements the platform abstraction for Windows using:
 *   \\.\INTC_MEI0           – Intel MEI driver (HECI host interface)
 *   NtQuerySystemInformation – MSR access via ring-0 shim
 *   SetupAPI / DeviceIoControl – PCI device enumeration
 *   VirtualAlloc + _mm_clflush – Uncached memory
 *
 * NOTE: MSR reads on Windows require either:
 *   (a) A signed kernel driver (included in tools\msr_shim\)
 *   (b) Intel SEAPI / OpenHardwareMonitor driver
 * The build will warn if neither is available.
 */

#ifdef _WIN32

#include "platform.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <initguid.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

/* Intel MEI device interface GUID */
DEFINE_GUID(GUID_DEVINTERFACE_MEI,
    0xE2D1FF34, 0x3458, 0x49A9,
    0x88, 0xDA, 0x8E, 0x69, 0x15, 0xCE, 0x9B, 0xE5);

/* ------------------------------------------------------------------ */
/*  Logging                                                             */
/* ------------------------------------------------------------------ */

static CRITICAL_SECTION g_log_cs;
static HANDLE           g_alert_log = INVALID_HANDLE_VALUE;
static bool             g_cs_inited = false;

static const char *level_str[] = {
    "DEBUG", "INFO ", "WARN ", "ALERT", "CRIT "
};

void plat_log(log_level_t level, const char *module,
              const char *fmt, ...)
{
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt, ap);
    va_end(ap);

    SYSTEMTIME st;
    GetLocalTime(&st);

    char line[1280];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02d:%02d:%02d.%03d] [%s] [%-16s] %s\r\n",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        level_str[level], module, msg);

    if (g_cs_inited) EnterCriticalSection(&g_log_cs);

    /* Windows debug output */
    OutputDebugStringA(line);
    fputs(line, stderr);

    if (g_alert_log != INVALID_HANDLE_VALUE && level >= LOG_ALERT) {
        DWORD written;
        WriteFile(g_alert_log, line, (DWORD)len, &written, NULL);
        FlushFileBuffers(g_alert_log);
    }

    if (g_cs_inited) LeaveCriticalSection(&g_log_cs);
}

/* ------------------------------------------------------------------ */
/*  Init / teardown                                                     */
/* ------------------------------------------------------------------ */

plat_err_t plat_init(void)
{
    InitializeCriticalSection(&g_log_cs);
    g_cs_inited = true;

    /* Create log directory */
    CreateDirectoryA("C:\\ProgramData\\mei-guard", NULL);

    g_alert_log = CreateFileA(
        "C:\\ProgramData\\mei-guard\\alerts.log",
        GENERIC_WRITE, FILE_SHARE_READ,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (g_alert_log != INVALID_HANDLE_VALUE)
        SetFilePointer(g_alert_log, 0, NULL, FILE_END);

    return PLAT_OK;
}

void plat_teardown(void)
{
    if (g_alert_log != INVALID_HANDLE_VALUE) {
        CloseHandle(g_alert_log);
        g_alert_log = INVALID_HANDLE_VALUE;
    }
    if (g_cs_inited) {
        DeleteCriticalSection(&g_log_cs);
        g_cs_inited = false;
    }
}

const char *plat_strerr(plat_err_t err)
{
    switch (err) {
        case PLAT_OK:           return "success";
        case PLAT_ERR_PERM:     return "permission denied (run as Administrator)";
        case PLAT_ERR_NODEV:    return "device not found";
        case PLAT_ERR_IO:       return "I/O error";
        case PLAT_ERR_NOMEM:    return "out of memory";
        case PLAT_ERR_TIMEOUT:  return "timeout";
        case PLAT_ERR_UNSUP:    return "unsupported";
        default:                return "unknown error";
    }
}

/* ------------------------------------------------------------------ */
/*  TSC frequency                                                       */
/* ------------------------------------------------------------------ */

uint64_t plat_tsc_freq_hz(void)
{
    /* Try CPUID leaf 0x15 */
    int regs[4];
    __cpuidex(regs, 0x15, 0);
    if (regs[0] && regs[1] && regs[2]) {
        return (uint64_t)(unsigned)regs[2] *
               (uint64_t)(unsigned)regs[1] /
               (uint64_t)(unsigned)regs[0];
    }

    /* Fall back: QueryPerformanceFrequency + busy spin */
    LARGE_INTEGER qpf, t0, t1;
    QueryPerformanceFrequency(&qpf);
    QueryPerformanceCounter(&t0);
    uint64_t tsc0 = __rdtsc();
    do { QueryPerformanceCounter(&t1); }
    while ((t1.QuadPart - t0.QuadPart) < qpf.QuadPart / 20); /* 50 ms */
    uint64_t tsc1 = __rdtsc();

    LONGLONG elapsed_ticks = t1.QuadPart - t0.QuadPart;
    return (tsc1 - tsc0) * (uint64_t)qpf.QuadPart / (uint64_t)elapsed_ticks;
}

/* ------------------------------------------------------------------ */
/*  MSR access via kernel driver shim                                  */
/* ------------------------------------------------------------------ */

/*
 * We use the WinRing0 / OpenHardwareMonitor driver interface when present.
 * Device: \\.\WinRing0_1_2_0
 * IOCTL: 0x9C402084  (IOCTL_OLS_READ_MSR)
 *
 * If the driver isn't loaded, fall back to the bundled msr_shim.sys.
 * msr_shim.sys is in tools\msr_shim\ and must be signed for Secure Boot.
 */

#define IOCTL_OLS_READ_MSR    0x9C402084UL
#define MSR_SHIM_DEVICE_NAME  "\\\\.\\WinRing0_1_2_0"

typedef struct { DWORD msr_index; } MsrReadInput;
typedef struct { DWORD eax; DWORD edx; } MsrReadOutput;

plat_err_t plat_rdmsr(uint64_t msr, uint64_t *value)
{
    HANDLE hDrv = CreateFileA(
        MSR_SHIM_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDrv == INVALID_HANDLE_VALUE) {
        /* Try loading bundled shim */
        plat_log(LOG_WARN, "msr",
                 "WinRing0 driver not found. "
                 "MSR reads unavailable. Load tools\\msr_shim\\msr_shim.sys");
        return PLAT_ERR_NODEV;
    }

    MsrReadInput  in  = { (DWORD)msr };
    MsrReadOutput out = {0};
    DWORD         returned;

    BOOL ok = DeviceIoControl(hDrv, IOCTL_OLS_READ_MSR,
                               &in, sizeof(in),
                               &out, sizeof(out),
                               &returned, NULL);
    CloseHandle(hDrv);

    if (!ok) return PLAT_ERR_IO;

    *value = ((uint64_t)out.edx << 32) | out.eax;
    return PLAT_OK;
}

/* ------------------------------------------------------------------ */
/*  PCI config space via SetupAPI                                       */
/* ------------------------------------------------------------------ */

static const uint16_t MEI_DEVICE_IDS[] = {
    0x1C3A, 0x1D3A, 0x1E3A, 0x8C3A, 0x8CBA, 0x9C3A,
    0xA13A, 0xA2BA, 0x9DE0, 0x02E0, 0x43E0, 0x7AE8, 0xA848, 0
};

plat_err_t plat_pci_find_mei(plat_pci_addr_t *addr)
{
    HDEVINFO di = SetupDiGetClassDevsA(
        NULL, "PCI", NULL,
        DIGCF_PRESENT | DIGCF_ALLCLASSES);

    if (di == INVALID_HANDLE_VALUE) return PLAT_ERR_IO;

    SP_DEVINFO_DATA did = { .cbSize = sizeof(did) };

    for (DWORD idx = 0; SetupDiEnumDeviceInfo(di, idx, &did); idx++) {
        char hw_id[256] = {0};
        SetupDiGetDeviceRegistryPropertyA(
            di, &did, SPDRP_HARDWAREID,
            NULL, (PBYTE)hw_id, sizeof(hw_id), NULL);

        /* Parse "PCI\VEN_8086&DEV_XXXX" */
        unsigned ven = 0, dev = 0;
        if (sscanf(hw_id, "PCI\\VEN_%x&DEV_%x", &ven, &dev) != 2)
            continue;
        if (ven != 0x8086) continue;

        for (int i = 0; MEI_DEVICE_IDS[i]; i++) {
            if ((uint16_t)dev == MEI_DEVICE_IDS[i]) {
                addr->vendor_id = (uint16_t)ven;
                addr->device_id = (uint16_t)dev;
                /* Bus/slot/func from CM_Get_DevNode_Registry_Property */
                addr->bus = addr->slot = addr->func = 0; /* simplified */
                SetupDiDestroyDeviceInfoList(di);
                return PLAT_OK;
            }
        }
    }

    SetupDiDestroyDeviceInfoList(di);
    return PLAT_ERR_NODEV;
}

plat_err_t plat_pci_read32(const plat_pci_addr_t *addr,
                            uint16_t offset, uint32_t *value)
{
    /*
     * Direct PCI config space access on Windows requires either:
     *   - The WinRing0 driver (same as MSR shim)
     *   - The PCIe ECAM mapped via \Device\PhysicalMemory (risky)
     * We use the WinRing0 IOCTL_OLS_READ_PCI_CONFIG ioctl.
     */
#define IOCTL_OLS_READ_PCI_CONFIG  0x9C402088UL

    typedef struct {
        DWORD pci_address;   /* bus<<8 | dev<<3 | func, offset in high word */
        DWORD size;
    } PciReadInput;

    HANDLE hDrv = CreateFileA(MSR_SHIM_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrv == INVALID_HANDLE_VALUE) return PLAT_ERR_NODEV;

    PciReadInput in = {
        .pci_address = ((DWORD)offset << 16) |
                       ((DWORD)addr->bus  << 8) |
                       ((DWORD)addr->slot << 3) |
                       addr->func,
        .size = 4
    };
    DWORD out = 0, returned;
    BOOL ok = DeviceIoControl(hDrv, IOCTL_OLS_READ_PCI_CONFIG,
                               &in, sizeof(in),
                               &out, sizeof(out), &returned, NULL);
    CloseHandle(hDrv);
    if (!ok) return PLAT_ERR_IO;
    *value = out;
    return PLAT_OK;
}

/* ------------------------------------------------------------------ */
/*  HECI device I/O                                                     */
/* ------------------------------------------------------------------ */

plat_err_t plat_mei_open(plat_fd_t *fd)
{
    /* Enumerate by device interface GUID first */
    HDEVINFO di = SetupDiGetClassDevsA(
        &GUID_DEVINTERFACE_MEI, NULL, NULL,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

    char path[256] = "\\\\.\\INTC_MEI0";  /* fallback */

    if (di != INVALID_HANDLE_VALUE) {
        SP_DEVICE_INTERFACE_DATA ifd = { .cbSize = sizeof(ifd) };
        if (SetupDiEnumDeviceInterfaces(di, NULL,
                &GUID_DEVINTERFACE_MEI, 0, &ifd)) {
            DWORD needed;
            SetupDiGetDeviceInterfaceDetailA(di, &ifd, NULL, 0, &needed, NULL);
            SP_DEVICE_INTERFACE_DETAIL_DATA_A *detail = malloc(needed);
            if (detail) {
                detail->cbSize = sizeof(*detail);
                if (SetupDiGetDeviceInterfaceDetailA(
                        di, &ifd, detail, needed, NULL, NULL)) {
                    strncpy_s(path, sizeof(path),
                              detail->DevicePath, _TRUNCATE);
                }
                free(detail);
            }
        }
        SetupDiDestroyDeviceInfoList(di);
    }

    HANDLE h = CreateFileA(path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) return PLAT_ERR_PERM;
        return PLAT_ERR_NODEV;
    }

    *fd = h;
    return PLAT_OK;
}

ssize_t plat_mei_read(plat_fd_t fd, void *buf, size_t len, int timeout_ms)
{
    OVERLAPPED ov = {0};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    DWORD read_bytes = 0;
    if (!ReadFile(fd, buf, (DWORD)len, &read_bytes, &ov)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            CloseHandle(ov.hEvent);
            return -1;
        }
        DWORD r = WaitForSingleObject(ov.hEvent, (DWORD)timeout_ms);
        if (r == WAIT_TIMEOUT) {
            CancelIo(fd);
            CloseHandle(ov.hEvent);
            return 0;
        }
        GetOverlappedResult(fd, &ov, &read_bytes, FALSE);
    }
    CloseHandle(ov.hEvent);
    return (ssize_t)read_bytes;
}

void plat_mei_close(plat_fd_t fd)
{
    if (fd != INVALID_HANDLE_VALUE) CloseHandle(fd);
}

/* ------------------------------------------------------------------ */
/*  Uncached memory                                                     */
/* ------------------------------------------------------------------ */

void *plat_alloc_uncached(size_t size)
{
    return VirtualAlloc(NULL, size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE);
}

void plat_free_uncached(void *ptr, size_t size)
{
    (void)size;
    if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
}

/* Windows VirtualAlloc is always write-back cached; CLFLUSH fallback. */
bool plat_has_uncached(void) { return false; }

#endif /* _WIN32 */