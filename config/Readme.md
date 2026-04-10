Let's break down the exact contents and purpose of these two configuration files. They are both **plain text** and are meant to be copied and edited by the user before running the system.

---

## 1. `config/notify.json.example`

**Purpose:** Controls how the Python analyser sends alerts when an anomaly is detected (e.g., unknown GUID on the HECI bus, DMI latency spike, microcode mismatch).

**Format:** JSON (strict syntax – commas, quotes, braces).

**Location after installation:**  
- Linux: `/etc/mei-guard/notify.json`  
- Windows: `C:\ProgramData\mei-guard\notify.json`

### Example Content with Explanations

```json
{
    "_comment": "mei-guard notification configuration. Remove this field in your actual file.",

    "syslog": true,

    "webhook_url": "https://your-server.com/api/alerts",

    "email": {
        "from": "mei-guard@localhost",
        "to": "admin@example.com",
        "host": "localhost",
        "port": 25
    },

    "exec": "/usr/local/bin/my-alert-script.sh"
}
```

### Field Descriptions

| Field | Type | Required? | Description |
|-------|------|-----------|-------------|
| `syslog` | boolean | No (default `false`) | If `true`, alerts are logged to the system logger (`syslog` on Linux, Event Log on Windows). |
| `webhook_url` | string | No | A full HTTPS URL. When an alert fires, the analyser sends a JSON payload (the alert object) via an HTTP POST request. Use this to integrate with Slack, Discord, PagerDuty, or a custom SIEM. |
| `email` | object | No | Configuration for SMTP email notifications. |
| `email.from` | string | Yes if `email` present | The "From:" address. |
| `email.to` | string | Yes if `email` present | The recipient address. |
| `email.host` | string | No (default `localhost`) | SMTP server hostname or IP. |
| `email.port` | integer | No (default `25`) | SMTP server port. |
| `exec` | string | No | A shell command to execute when an alert occurs. The alert JSON is piped to the command's standard input. Use this for custom scripts (e.g., send an SNMP trap, flash a USB LED). |

**How to use it:**
1. Copy `notify.json.example` to `notify.json`.
2. Edit the file with your actual email server or webhook URL.
3. Remove the `_comment` line (JSON does not officially support comments, though our parser tolerates them).

---

## 2. `config/guid_whitelist.txt.example`

**Purpose:** Defines a list of **known‑good** GUIDs (Globally Unique Identifiers) that the Intel Management Engine is allowed to use when communicating with the OS via the HECI bus. Any GUID not on this list triggers a **CRITICAL** alert.

**Format:** Plain text, one entry per line. Lines starting with `#` are ignored.

**Location after installation:**  
- Linux: `/etc/mei-guard/guid_whitelist.txt`  
- Windows: `C:\ProgramData\mei-guard\guid_whitelist.txt`

### Example Content with Explanations

```text
# mei-guard GUID whitelist
# Format: <GUID without braces> <name> [requires_amt]
# Lines starting with # are comments and ignored.

# MKHI (ME Kernel Host Interface) – heartbeats and power management
8E6A6301-731F-4543-ADEA-3D2BDBD2DA3A MKHI

# Watchdog timer keep‑alive
05B79A6C-F8F1-11E0-97A1-000000000000 HECI_WDT

# MEI Client Device (generic)
E2D1FF34-3458-49A9-88DA-8E6915CE9BE5 MEI_CLDEV

# Thermal / FIVR management
FC9C9903-F6A1-4500-96FE-0A7AA7F8AC9B THERMAL_MGMT

# AMT Host Interface – ONLY active when AMT is provisioned in BIOS
# The "requires_amt" flag tells mei-guard to suppress alerts for this
# GUID if AMT is NOT provisioned. Without this flag, the GUID appearing
# on a non‑AMT system would trigger a HIGH alert.
12F80228-9A45-4540-A79E-234F965BC366 AMT_HOST requires_amt

# You can add additional GUIDs from Intel public specs or your own
# research. Example format:
# 12345678-1234-1234-1234-123456789ABC MY_CUSTOM_CLIENT
```

### Line Format Explained

Each non‑comment line has the form:

```
<GUID> <NAME> [requires_amt]
```

- **`<GUID>`** – The 128‑bit GUID in standard RFC 4122 format **without** the curly braces `{}`. The parser expects exactly 36 characters including hyphens.  
  Example: `8E6A6301-731F-4543-ADEA-3D2BDBD2DA3A`

- **`<NAME>`** – A human‑readable label (no spaces). Used in log messages.  
  Example: `MKHI`

- **`[requires_amt]`** – *Optional* keyword. If present, the monitor will **not** alert when this GUID is seen on a system where AMT (Active Management Technology) has not been provisioned in the BIOS. This is useful for GUIDs that are only legitimate when AMT is enabled, but may appear spuriously in some firmware versions.

### What Happens If an Unknown GUID Appears?

The `heci_monitor.c` module will generate an alert with `severity = ALERT_CRITICAL` and a detail message like:

```
Unknown MEI client GUID: {DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF} (payload length: 32 bytes). Possible covert ME channel.
```

This is the primary way `mei-guard` detects **backdoor or spyware activity** on the HECI bus.

### How to Extend the Whitelist

If you find a legitimate GUID that triggers false positives (for example, a new GUID added by a firmware update), simply add it to your local `guid_whitelist.txt` file. The daemon re‑reads this file at startup, so a restart is required to pick up changes.

---

## Summary of File Placement

After building and installing `mei-guard`, you should have:

```
/etc/mei-guard/
├── notify.json
├── guid_whitelist.txt
└── trusted_microcode.json   (created by --enroll-microcode)
```

On Windows, the equivalent is `C:\ProgramData\mei-guard\`.

These files give you full control over **who gets notified** and **what ME traffic is considered normal**.