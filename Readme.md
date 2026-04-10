# mei-guard

**Ring -3 Heuristic Anomaly Detection System**

Monitors for side-effects of Intel ME / AMD PSP backdoor activity from Ring 0 / userspace. Cannot guarantee detection — the ME operates below the OS and can lie to it — but provides high-confidence heuristics across four independent channels.

---

## Threat model

| Layer | Who runs there | Can lie to Ring 0? |
|-------|---------------|--------------------|
| Ring 3 | Userspace apps | No |
| Ring 0 | OS kernel | — |
| Ring -1 | Hypervisor | Yes (VMX) |
| Ring -2 | SMM (BIOS/UEFI) | Yes |
| **Ring -3** | **Intel ME / AMD PSP** | **Yes, unconditionally** |

This tool cannot say *"the NSA is reading Word.docx."*  
It **can** say:

```
ALERT: HECI Bus Anomaly.
  Type: Unsolicited MKHI command, unknown UUID {DEADBEEF-...}.
  Likelihood of ME Activity: 97%.

ALERT: DMI Bus Latency Spike.
  Pattern: Consistent 4KB DMA read every 200ms during system idle.
  Analysis: Consistent with Memory Scraping via VT-d bypass.
```

---

## Detection channels

### 1. HECI Bus Monitor (`src/checks/heci_monitor.c`)
- Watches `/dev/mei0` for messages with unknown client GUIDs
- Detects burst traffic (> 20 messages/second)
- Detects AMT-gated clients active without AMT provisioning
- GUID whitelist is file-configurable: `/etc/mei-guard/guid_whitelist.txt`

### 2. Microcode Integrity Verifier (`src/checks/microcode_verifier.c`)
- Reads `MSR 0x8B` (IA32_BIOS_SIGN_ID) at boot and every hour
- Compares revision against locally-enrolled trusted database
- On Linux: also hashes the firmware blob at `/lib/firmware/intel-ucode/`
- Alert if revision or blob hash changes without a corresponding OS package update

### 3. MEI Firmware Status Register (`src/checks/mei_status.c`)
- Reads FWSTS1/FWSTS2 from PCI config space (sysfs or direct)
- **Critical alert** on `SECOVER_JMPR` (0x5) — Security Override Jumper mode
- **Critical alert** on Manufacturing Mode flag
- **High alert** on Enhanced Debug Mode (JTAG exposed)

### 4. DMI Bus Latency Profiler (`src/checks/dmi_latency.c`)
- RDTSC-based probe loop; CLFLUSH forces DRAM round-trips
- CUSUM (Cumulative Sum) algorithm detects sustained latency shifts
- Detects passive ME DMA memory reads (the hardest attack to catch)
- False-positive mitigation: IRQ noise gate + 200ms minimum anomaly duration

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   C Daemon (ring 0)                  │
│                                                      │
│  ┌──────────────┐  ┌────────────┐  ┌─────────────┐  │
│  │ HECI Monitor │  │ MEI Status │  │ Microcode   │  │
│  │ (thread)     │  │ (periodic) │  │ (periodic)  │  │
│  └──────┬───────┘  └─────┬──────┘  └──────┬──────┘  │
│         │                │                │         │
│  ┌──────┴───────┐        │                │         │
│  │ DMI Latency  │        │                │         │
│  │ (thread)     │        │                │         │
│  └──────┬───────┘        │                │         │
│         └────────────────┴────────────────┘         │
│                     ↓ stdout                        │
│         newline-delimited JSON (typed stream)        │
└─────────────────────────────────────────────────────┘
                         │
                         │ pipe
                         ↓
┌─────────────────────────────────────────────────────┐
│            Python Analyser (userspace)               │
│                                                      │
│  ┌──────────────────┐   ┌─────────────────────────┐ │
│  │  Alert router    │   │  Latency trend analyser │ │
│  │  + dedup         │   │  (CUSUM / Mann-Kendall) │ │
│  └────────┬─────────┘   └────────────┬────────────┘ │
│           │                          │              │
│  ┌────────┴──────────────────────────┴────────────┐ │
│  │              SQLite store                       │ │
│  └────────────────────────────────────────────────┘ │
│           │                          │              │
│  ┌────────┴──────┐         ┌─────────┴───────────┐  │
│  │  Notifier     │         │  Web dashboard      │  │
│  │  syslog/email │         │  http://localhost   │  │
│  │  /webhook     │         │  :7473              │  │
│  └───────────────┘         └─────────────────────┘  │
│                                                      │
│  ┌──────────────────────────────────────────────┐    │
│  │  ARP watcher (optional, requires scapy)      │    │
│  │  Detects ME MAC active on LAN                │    │
│  └──────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘

Optional: Kernel module (/kernel/mei_guard_kmod.c)
  /proc/mei_guard/heci_log  – raw HECI message tap
  /dev/mei_guard_msr        – gated MSR proxy
```

---

## Build

### Prerequisites (Linux)
```bash
sudo apt install build-essential cmake libpthread-stubs0-dev
# For kernel module:
sudo apt install linux-headers-$(uname -r)
# Python analyser:
pip install numpy scapy  # optional but recommended
```

### Compile
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install
```

### Kernel module (optional, deeper HECI hooks)
```bash
cd kernel
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
sudo insmod mei_guard_kmod.ko
```

---

## First run: enrol microcode baseline

**Do this on a known-clean system before any potential compromise.**

```bash
sudo mkdir -p /etc/mei-guard
sudo mei-guard --enroll-microcode
# Writes to /etc/mei-guard/trusted_microcode.json
```

---

## Running

```bash
# Standard run (all checks, JSON → Python analyser → dashboard)
sudo mei-guard | python3 /usr/share/mei-guard/analyser.py \
    --db /var/lib/mei-guard/db.sqlite

# Dashboard available at http://127.0.0.1:7473

# One-shot check (good for cron):
sudo mei-guard --check-once 2>&1 | logger -t mei-guard

# Disable a check you can't run (e.g., no MEI device):
sudo mei-guard --no-heci --no-mei-status | python3 analyser.py ...

# With AMT provisioned (suppresses AMT alerts):
sudo mei-guard --amt | python3 analyser.py ...

# With external alerting (POST to webhook):
# Edit /etc/mei-guard/notify.json, set webhook_url

# With ARP-based ME MAC watcher (requires scapy, promiscuous NIC):
sudo mei-guard | python3 analyser.py \
    --watch-arp --os-mac 00:11:22:33:44:55 --arp-iface eth0
```

---

## Systemd service

```ini
# /etc/systemd/system/mei-guard.service
[Unit]
Description=mei-guard Ring -3 Anomaly Detection
After=network.target

[Service]
Type=simple
ExecStart=/bin/sh -c 'mei-guard | python3 /usr/share/mei-guard/analyser.py --db /var/lib/mei-guard/db.sqlite'
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now mei-guard
sudo journalctl -fu mei-guard
```

---

## Signals

| Signal | Effect |
|--------|--------|
| `SIGUSR1` | Emit a `stats` JSON line to stdout |
| `SIGTERM` / `SIGINT` | Graceful shutdown |

---

## Output format

All C daemon output is newline-delimited JSON:

```json
{"timestamp":1700000000.000000000,"type":"alert","source":"heci","severity":4,"detail":"Unknown MEI client GUID: {DEADBEEF-...}"}
{"timestamp":1700000000.002000000,"type":"latency","ticks":512}
{"timestamp":1700000000.100000000,"type":"stats","heci_messages":42,"heci_alerts":1,"heci_unknown_guids":1}
```

`severity`: 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL

---

## Limitations (important)

1. **The ME can censor its own logs.** This tool runs on a potentially compromised host. Detection is probabilistic, not definitive.
2. **False positives on DMI latency.** Heavy I/O, NUMA effects, and thermal throttling can trigger latency anomalies. The CUSUM algorithm and 200ms minimum duration suppress most of these, but tune `CUSUM_H_THRESHOLD` if needed.
3. **HECI whitelist completeness.** Unknown legitimate clients (OEM extensions) may generate false alerts. Add them to `/etc/mei-guard/guid_whitelist.txt`.
4. **The only fully-reliable monitor is off-host.** A [ChipWhisperer](https://rtfm.newae.com/) or Bus Pirate on the LPC debug header is the ground truth.

---

## Files

```
mei-guard/
├── CMakeLists.txt
├── README.md
├── config/
│   ├── notify.json.example
│   └── guid_whitelist.txt.example
├── src/
│   ├── main.c                        ← daemon entry, IPC stream
│   ├── platform/
│   │   ├── platform.h                ← cross-platform API
│   │   ├── linux.c                   ← Linux backend
│   │   └── windows.c                 ← Windows backend
│   ├── checks/
│   │   ├── heci_monitor.{c,h}        ← HECI bus anomaly detection
│   │   ├── microcode_verifier.{c,h}  ← MSR 0x8B / firmware blob check
│   │   ├── mei_status.{c,h}          ← FWSTS1/2 PCI register check
│   │   └── dmi_latency.{c,h}         ← CUSUM bus latency profiler
│   └── crypto/
│       └── sha256.h                  ← single-header SHA-256 (no deps)
├── kernel/
│   ├── mei_guard_kmod.c              ← optional deep-hook kernel module
│   └── Makefile
├── python/
│   └── analyser.py                   ← typed-stream router, dashboard, ARP
└── tests/
    ├── test_core.c                   ← CUSUM, GUID, FWSTS unit tests
    └── CMakeLists.txt
```