/*
 * mei-guard: Microcode Integrity Verifier
 *
 * Reads MSR 0x8B (IA32_BIOS_SIGN_ID) to get the current CPU microcode
 * revision, hashes it alongside the CPU family/model/stepping, and
 * compares against a locally-maintained Trusted Repository.
 *
 * Threat model:
 *   A Ring -3 (ME/PSP) or Ring -2 (SMM) attacker can inject a rogue
 *   microcode blob by triggering IA32_BIOS_UPDT_TRIG (MSR 0x79).
 *   Rogue microcode can:
 *     - Suppress RDRAND entropy
 *     - Silently leak memory to the PCH
 *     - Disable hardware security features (CET, SMEP)
 *
 * Detection approach:
 *   We cannot verify the microcode contents directly (it's encrypted
 *   and authenticated by Intel).  We can detect UNEXPECTED CHANGES
 *   between reboots and between policy updates.
 *
 *   Trusted repository format (JSON):
 *   {
 *     "entries": [
 *       {
 *         "cpuid": "0x906EA",          // family/model/stepping
 *         "revision": "0xDE",
 *         "source": "intel-microcode 20231114",
 *         "sha256": "..."               // SHA-256 of /lib/firmware/intel-ucode/<cpuid>
 *       }
 *     ]
 *   }
 */

#include "microcode_verifier.h"
#include "../platform/platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef PLAT_LINUX
  #include <sys/stat.h>
  #include <dirent.h>
  #include <fcntl.h>
  #include <unistd.h>
#endif

/* SHA-256 implementation (single-file, no external dependency) */
#include "../crypto/sha256.h"

#define UCODE_DB_PATH_LINUX   "/etc/mei-guard/trusted_microcode.json"
#define UCODE_DB_PATH_WIN     "C:\\ProgramData\\mei-guard\\trusted_microcode.json"
#define UCODE_FW_PATH_LINUX   "/lib/firmware/intel-ucode"

/* ------------------------------------------------------------------ */
/*  CPU identification                                                  */
/* ------------------------------------------------------------------ */

static uint32_t read_cpuid_signature(void)
{
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1), "c"(0)
    );
    /* Mask to family/model/stepping only */
    return eax & 0x0FFF3FFF;
}

static uint32_t read_microcode_revision(void)
{
    uint64_t val;
    plat_err_t err = plat_rdmsr(MSR_IA32_BIOS_SIGN_ID, &val);
    if (err != PLAT_OK) return 0xFFFFFFFF;  /* sentinel: unavailable */
    return (uint32_t)(val >> 32);   /* revision is in the high DWORD */
}

static uint32_t read_platform_id(void)
{
    uint64_t val;
    plat_err_t err = plat_rdmsr(MSR_IA32_PLATFORM_ID, &val);
    if (err != PLAT_OK) return 0;
    return (uint32_t)((val >> 50) & 0x7);   /* bits [52:50] */
}

/* ------------------------------------------------------------------ */
/*  Firmware blob hashing (Linux only)                                  */
/* ------------------------------------------------------------------ */

#ifdef PLAT_LINUX
static bool hash_firmware_blob(uint32_t cpuid_sig,
                                uint8_t out_hash[32])
{
    char path[256];
    snprintf(path, sizeof(path), "%s/%02x-%02x-%02x",
             UCODE_FW_PATH_LINUX,
             (cpuid_sig >> 8) & 0xF,   /* family */
             (cpuid_sig >> 4) & 0xF,   /* model  */
             cpuid_sig & 0xF);         /* stepping */

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        /* Try alternate naming */
        snprintf(path, sizeof(path), "%s/%08x",
                 UCODE_FW_PATH_LINUX, cpuid_sig);
        fd = open(path, O_RDONLY);
    }
    if (fd < 0) return false;

    sha256_ctx_t ctx;
    sha256_init(&ctx);

    uint8_t buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        sha256_update(&ctx, buf, (size_t)n);
    }
    sha256_final(&ctx, out_hash);
    close(fd);
    return true;
}
#endif /* PLAT_LINUX */

/* ------------------------------------------------------------------ */
/*  Trusted database: minimal JSON reader (no external deps)           */
/* ------------------------------------------------------------------ */

/*
 * We implement a minimal parser for our specific JSON schema rather
 * than pulling in a JSON library.  The format is fixed and simple.
 */

typedef struct {
    uint32_t cpuid;
    uint32_t revision;
    uint8_t  sha256[32];
    bool     has_hash;
    char     source[128];
} db_entry_t;

#define MAX_DB_ENTRIES 256

typedef struct {
    db_entry_t entries[MAX_DB_ENTRIES];
    int        count;
} trusted_db_t;

static uint8_t hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    return 0;
}

static void parse_hex_bytes(const char *s, uint8_t *out, int n)
{
    for (int i = 0; i < n && s[i*2] && s[i*2+1]; i++) {
        out[i] = (hex_nibble(s[i*2]) << 4) | hex_nibble(s[i*2+1]);
    }
}

static bool load_trusted_db(trusted_db_t *db)
{
    const char *path;
#ifdef PLAT_LINUX
    path = UCODE_DB_PATH_LINUX;
#else
    path = UCODE_DB_PATH_WIN;
#endif

    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_W("ucode", "Trusted microcode DB not found at %s. "
              "Run 'mei-guard --enroll-microcode' on a known-clean system.",
              path);
        return false;
    }

    memset(db, 0, sizeof(*db));

    char line[512];
    db_entry_t cur = {0};
    bool in_entry = false;

    while (fgets(line, sizeof(line), f)) {
        /* Trim leading whitespace */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        if (strstr(p, "\"cpuid\"")) {
            unsigned long v;
            if (sscanf(p, " \"cpuid\" : \"%lx\"", &v) == 1) {
                cur.cpuid = (uint32_t)v;
                in_entry = true;
            }
        } else if (strstr(p, "\"revision\"")) {
            unsigned long v;
            if (sscanf(p, " \"revision\" : \"%lx\"", &v) == 1)
                cur.revision = (uint32_t)v;
        } else if (strstr(p, "\"sha256\"")) {
            char hexbuf[65] = {0};
            if (sscanf(p, " \"sha256\" : \"%64s\"", hexbuf) == 1) {
                /* strip trailing quote if present */
                for (int i = 0; i < 65; i++) {
                    if (hexbuf[i] == '"') { hexbuf[i] = 0; break; }
                }
                parse_hex_bytes(hexbuf, cur.sha256, 32);
                cur.has_hash = true;
            }
        } else if (strstr(p, "\"source\"")) {
            sscanf(p, " \"source\" : \"%127[^\"]\"", cur.source);
        } else if (p[0] == '}' && in_entry) {
            if (db->count < MAX_DB_ENTRIES) {
                db->entries[db->count++] = cur;
            }
            memset(&cur, 0, sizeof(cur));
            in_entry = false;
        }
    }

    fclose(f);
    LOG_I("ucode", "Loaded %d trusted microcode entries from %s",
          db->count, path);
    return db->count > 0;
}

/* ------------------------------------------------------------------ */
/*  Enrollment: write current state to DB                              */
/* ------------------------------------------------------------------ */

static void bytes_to_hex(const uint8_t *b, int n, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i*2]   = hex[b[i] >> 4];
        out[i*2+1] = hex[b[i] & 0xF];
    }
    out[n*2] = '\0';
}

void microcode_enroll(void)
{
    uint32_t cpuid_sig = read_cpuid_signature();
    uint32_t revision  = read_microcode_revision();

    if (revision == 0xFFFFFFFF) {
        LOG_W("ucode", "Cannot read microcode revision (MSR unavailable). "
              "Are you running as root with the msr module loaded?");
        return;
    }

    char hash_hex[65] = "N/A";
    uint8_t fw_hash[32];
    bool has_hash = false;

#ifdef PLAT_LINUX
    has_hash = hash_firmware_blob(cpuid_sig, fw_hash);
    if (has_hash) bytes_to_hex(fw_hash, 32, hash_hex);
#endif

    const char *path;
#ifdef PLAT_LINUX
    path = UCODE_DB_PATH_LINUX;
    /* Ensure directory exists */
    mkdir("/etc/mei-guard", 0700);
#else
    path = UCODE_DB_PATH_WIN;
#endif

    FILE *f = fopen(path, "w");
    if (!f) {
        LOG_W("ucode", "Cannot write trusted DB to %s: check permissions",
              path);
        return;
    }

    fprintf(f,
        "{\n"
        "  \"_comment\": \"mei-guard trusted microcode database. "
            "Do not edit manually.\",\n"
        "  \"entries\": [\n"
        "    {\n"
        "      \"cpuid\":    \"0x%08X\",\n"
        "      \"revision\": \"0x%08X\",\n"
        "      \"sha256\":   \"%s\",\n"
        "      \"source\":   \"enrolled-at-boot\",\n"
        "      \"enrolled\":  true\n"
        "    }\n"
        "  ]\n"
        "}\n",
        cpuid_sig, revision, hash_hex);

    fclose(f);
    LOG_I("ucode",
          "Enrolled: CPUID=0x%08X  Revision=0x%08X  Hash=%s",
          cpuid_sig, revision, hash_hex);
}

/* ------------------------------------------------------------------ */
/*  Check                                                               */
/* ------------------------------------------------------------------ */

mc_check_result_t microcode_check(void)
{
    mc_check_result_t result = {
        .status   = MC_OK,
        .cpuid    = read_cpuid_signature(),
        .revision = read_microcode_revision(),
    };

    if (result.revision == 0xFFFFFFFF) {
        result.status = MC_UNAVAILABLE;
        snprintf(result.detail, sizeof(result.detail),
                 "Cannot read MSR 0x8B. msr module loaded?");
        return result;
    }

    LOG_I("ucode", "CPU CPUID=0x%08X  Microcode revision=0x%08X  "
          "Platform ID=%u",
          result.cpuid, result.revision, read_platform_id());

    trusted_db_t db;
    if (!load_trusted_db(&db)) {
        result.status = MC_NO_DB;
        snprintf(result.detail, sizeof(result.detail),
                 "No trusted DB. Run: mei-guard --enroll-microcode "
                 "on a known-clean system.");
        return result;
    }

    /* Find matching CPUID in DB */
    for (int i = 0; i < db.count; i++) {
        if (db.entries[i].cpuid != result.cpuid) continue;

        if (db.entries[i].revision != result.revision) {
            result.status = MC_REVISION_CHANGED;
            snprintf(result.detail, sizeof(result.detail),
                     "MICROCODE REVISION MISMATCH! "
                     "Expected 0x%08X, got 0x%08X. "
                     "Verify a legitimate intel-microcode package update "
                     "is responsible for this change.",
                     db.entries[i].revision, result.revision);
            LOG_A("ucode", "%s", result.detail);
            return result;
        }

        /* Revision matches; optionally check firmware blob hash */
#ifdef PLAT_LINUX
        if (db.entries[i].has_hash) {
            uint8_t cur_hash[32];
            if (hash_firmware_blob(result.cpuid, cur_hash)) {
                if (memcmp(cur_hash, db.entries[i].sha256, 32) != 0) {
                    char got_hex[65], exp_hex[65];
                    bytes_to_hex(cur_hash, 32, got_hex);
                    bytes_to_hex(db.entries[i].sha256, 32, exp_hex);
                    result.status = MC_HASH_MISMATCH;
                    snprintf(result.detail, sizeof(result.detail),
                             "FIRMWARE BLOB HASH MISMATCH! "
                             "Expected: %s  Got: %s",
                             exp_hex, got_hex);
                    LOG_C("ucode", "%s", result.detail);
                    return result;
                }
            }
        }
#endif

        result.status = MC_OK;
        snprintf(result.detail, sizeof(result.detail),
                 "Microcode revision 0x%08X matches trusted DB (%s). OK.",
                 result.revision, db.entries[i].source);
        LOG_I("ucode", "%s", result.detail);
        return result;
    }

    /* CPUID not in DB at all */
    result.status = MC_UNKNOWN_CPU;
    snprintf(result.detail, sizeof(result.detail),
             "CPU CPUID 0x%08X not in trusted DB. "
             "Run --enroll-microcode to add this CPU.",
             result.cpuid);
    LOG_W("ucode", "%s", result.detail);
    return result;
}