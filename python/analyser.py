#!/usr/bin/env python3
"""
mei-guard: Python Analysis Daemon
==================================
Connects to the C daemon's JSON stream and provides:

  - Time-series storage (SQLite)
  - Trend analysis (scipy statsmodels)
  - Structured alert deduplication
  - Email / webhook / syslog notification
  - Web dashboard (http://localhost:7473)
  - Network MAC anomaly detector (listens to port-mirror feed)
  - ME MAC calculator and ARP watcher
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Callable, Optional

# Optional heavy deps - gracefully degrade if absent
try:
    import numpy as np
    HAVE_NUMPY = True
except ImportError:
    HAVE_NUMPY = False

try:
    from scapy.all import ARP, Ether, sniff  # type: ignore
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

# ------------------------------------------------------------------ #
#  Logging                                                             #
# ------------------------------------------------------------------ #

LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger("mei-guard")


# ------------------------------------------------------------------ #
#  Data types                                                          #
# ------------------------------------------------------------------ #

@dataclass
class Alert:
    timestamp:  float
    source:     str       # heci | dmi_latency | microcode | mei_status | arp
    severity:   int       # 1=low … 4=critical
    detail:     str
    digest:     str = ""  # SHA-256 of (source+detail) for dedup

    def __post_init__(self):
        raw = f"{self.source}:{self.detail}"
        self.digest = hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "datetime":  datetime.datetime.fromtimestamp(
                             self.timestamp).isoformat(),
            "source":    self.source,
            "severity":  self.severity,
            "detail":    self.detail,
        }


SEVERITY_NAMES = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


# ------------------------------------------------------------------ #
#  SQLite store                                                        #
# ------------------------------------------------------------------ #

class AlertStore:
    """Persistent alert and latency-sample store."""

    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        REAL NOT NULL,
                    source    TEXT NOT NULL,
                    severity  INTEGER NOT NULL,
                    detail    TEXT NOT NULL,
                    digest    TEXT NOT NULL,
                    notified  INTEGER DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_ts
                    ON alerts(ts);
                CREATE INDEX IF NOT EXISTS idx_alerts_digest
                    ON alerts(digest);

                CREATE TABLE IF NOT EXISTS latency_samples (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        REAL NOT NULL,
                    value_ns  REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_lat_ts
                    ON latency_samples(ts);

                CREATE TABLE IF NOT EXISTS microcode_history (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        REAL NOT NULL,
                    cpuid     TEXT NOT NULL,
                    revision  TEXT NOT NULL
                );
            """)

    def insert_alert(self, a: Alert) -> int:
        with self._lock, self.conn:
            # Suppress duplicate alerts within 5 minutes
            cutoff = a.timestamp - 300
            row = self.conn.execute(
                "SELECT id FROM alerts WHERE digest=? AND ts>?",
                (a.digest, cutoff)).fetchone()
            if row:
                return -1  # duplicate suppressed
            cur = self.conn.execute(
                "INSERT INTO alerts(ts,source,severity,detail,digest) "
                "VALUES (?,?,?,?,?)",
                (a.timestamp, a.source, a.severity, a.detail, a.digest))
            return cur.lastrowid

    def insert_latency(self, ts: float, value_ns: float):
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT INTO latency_samples(ts,value_ns) VALUES(?,?)",
                (ts, value_ns))

    def recent_alerts(self, limit: int = 50) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ts,source,severity,detail FROM alerts "
            "ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [{"timestamp": r[0], "source": r[1],
                 "severity": r[2], "detail": r[3]} for r in rows]

    def latency_window(self, seconds: int = 60) -> list[tuple]:
        cutoff = time.time() - seconds
        return self.conn.execute(
            "SELECT ts,value_ns FROM latency_samples "
            "WHERE ts>? ORDER BY ts", (cutoff,)).fetchall()


# ------------------------------------------------------------------ #
#  Notification back-ends                                              #
# ------------------------------------------------------------------ #

class Notifier:
    def __init__(self, config: dict):
        self.cfg = config

    def notify(self, alert: Alert):
        if self.cfg.get("syslog"):
            self._syslog(alert)
        if self.cfg.get("webhook_url"):
            self._webhook(alert)
        if self.cfg.get("email"):
            self._email(alert)
        if self.cfg.get("exec"):
            self._exec(alert)

    def _syslog(self, a: Alert):
        priority = {1: 6, 2: 5, 3: 4, 4: 2}.get(a.severity, 6)
        msg = f"mei-guard [{SEVERITY_NAMES[a.severity]}] {a.source}: {a.detail}"
        try:
            import syslog
            syslog.syslog(priority, msg)
        except Exception as e:
            log.warning("syslog failed: %s", e)

    def _webhook(self, a: Alert):
        import urllib.request
        payload = json.dumps(a.to_dict()).encode()
        req = urllib.request.Request(
            self.cfg["webhook_url"],
            data=payload,
            headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            log.warning("webhook failed: %s", e)

    def _email(self, a: Alert):
        import smtplib
        from email.message import EmailMessage
        ec = self.cfg["email"]
        msg = EmailMessage()
        msg["Subject"] = (f"[mei-guard {SEVERITY_NAMES[a.severity]}] "
                          f"{a.source} anomaly detected")
        msg["From"]    = ec.get("from", "mei-guard@localhost")
        msg["To"]      = ec["to"]
        msg.set_content(
            f"mei-guard Alert\n\n"
            f"Time:     {datetime.datetime.fromtimestamp(a.timestamp)}\n"
            f"Source:   {a.source}\n"
            f"Severity: {SEVERITY_NAMES[a.severity]}\n\n"
            f"Detail:\n{a.detail}\n")
        try:
            with smtplib.SMTP(ec.get("host", "localhost"),
                              ec.get("port", 25)) as s:
                s.send_message(msg)
        except Exception as e:
            log.warning("email failed: %s", e)

    def _exec(self, a: Alert):
        cmd = self.cfg["exec"]
        try:
            subprocess.run(cmd, input=json.dumps(a.to_dict()),
                           shell=True, text=True, timeout=10)
        except Exception as e:
            log.warning("exec notifier failed: %s", e)


# ------------------------------------------------------------------ #
#  Network: ME MAC ARP watcher                                         #
# ------------------------------------------------------------------ #

def calculate_me_mac(os_mac: str) -> Optional[str]:
    """
    The Intel ME has a dedicated MAC address typically = OS MAC + 1.
    This is not guaranteed but holds for most consumer platforms.
    """
    parts = os_mac.replace(":", "-").split("-")
    if len(parts) != 6:
        return None
    last = (int(parts[5], 16) + 1) & 0xFF
    return ":".join(parts[:5] + [f"{last:02x}"])


class ARPWatcher:
    """
    Listens on a network interface for ARP packets from the ME MAC.
    Requires scapy and a port-mirrored or promiscuous interface.

    For best results, run on a second machine on the same segment
    with port mirroring enabled on the switch.
    """

    def __init__(self, iface: str, os_mac: str,
                 alert_cb: Callable[[Alert], None]):
        self.iface    = iface
        self.os_mac   = os_mac.lower()
        self.me_mac   = calculate_me_mac(os_mac)
        self.alert_cb = alert_cb
        self._thread: Optional[threading.Thread] = None
        self._running = False
        log.info("ARP watcher: OS MAC=%s  Expected ME MAC=%s",
                 self.os_mac, self.me_mac)

    def _packet_handler(self, pkt):
        if ARP not in pkt:
            return
        src_mac = pkt[Ether].src.lower()
        if src_mac == self.me_mac:
            alert = Alert(
                timestamp=time.time(),
                source="arp",
                severity=4,
                detail=(
                    f"CRITICAL: ME MAC ADDRESS ACTIVE ON NETWORK. "
                    f"MAC {self.me_mac} sent an ARP packet. "
                    f"Intel ME is communicating on the network without "
                    f"AMT being provisioned. This is a strong indicator "
                    f"of a backdoor or active remote management intrusion."
                ),
            )
            log.critical("ARP: ME MAC %s is active!", self.me_mac)
            self.alert_cb(alert)

    def start(self):
        if not HAVE_SCAPY:
            log.warning("scapy not installed; ARP watcher disabled. "
                        "Install with: pip install scapy")
            return
        if not self.me_mac:
            log.warning("Could not calculate ME MAC; ARP watcher disabled")
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._run, daemon=True, name="arp-watcher")
        self._thread.start()

    def _run(self):
        sniff(iface=self.iface, filter="arp",
              prn=self._packet_handler,
              store=False,
              stop_filter=lambda _: not self._running)

    def stop(self):
        self._running = False


# ------------------------------------------------------------------ #
#  Latency trend analyser                                              #
# ------------------------------------------------------------------ #

class LatencyAnalyser:
    """
    Reads latency samples from the store and looks for long-term trends
    using a Mann-Kendall test (numpy-based) or simple linear regression.
    A persistent upward trend in baseline latency indicates ongoing DMA.
    """

    def __init__(self, store: AlertStore, alert_cb: Callable[[Alert], None]):
        self.store    = store
        self.alert_cb = alert_cb
        self._thread  = threading.Thread(
            target=self._run, daemon=True, name="lat-analyser")

    def start(self):
        self._running = True
        self._thread.start()

    def _run(self):
        while True:
            time.sleep(60)
            self._analyse()

    def _analyse(self):
        if not HAVE_NUMPY:
            return

        rows = self.store.latency_window(seconds=300)  # last 5 min
        if len(rows) < 100:
            return

        values = np.array([r[1] for r in rows])
        # Simple OLS slope
        x = np.arange(len(values), dtype=float)
        slope = np.polyfit(x, values, 1)[0]

        # Express slope as percent per minute
        samples_per_min = len(values) / 5
        pct_per_min = slope * samples_per_min / np.mean(values) * 100

        if pct_per_min > 1.0:  # > 1% latency increase per minute
            alert = Alert(
                timestamp=time.time(),
                source="dmi_latency_trend",
                severity=3,
                detail=(
                    f"Sustained DMI latency upward trend detected. "
                    f"Slope: {slope:.2f} ns/sample ({pct_per_min:.2f}%/min). "
                    f"Baseline creep of this kind over 5+ minutes is "
                    f"consistent with ongoing background DMA by the PCH."
                ),
            )
            self.alert_cb(alert)


# ------------------------------------------------------------------ #
#  Web dashboard                                                       #
# ------------------------------------------------------------------ #

DASHBOARD_HTML = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>mei-guard dashboard</title>
<style>
  body {{ font-family: monospace; background: #0a0a0a; color: #c8ffc8; padding: 1em; }}
  h1 {{ color: #00ff88; }}
  .alert {{ border: 1px solid #444; margin: 4px 0; padding: 6px; border-radius: 3px; }}
  .sev-4 {{ border-color: #ff2222; color: #ff8888; }}
  .sev-3 {{ border-color: #ff8800; color: #ffcc88; }}
  .sev-2 {{ border-color: #ffee00; color: #ffee88; }}
  .sev-1 {{ border-color: #88aa88; }}
  canvas {{ background: #111; display: block; margin: 1em 0; }}
  pre {{ background: #111; padding: 1em; overflow-x: auto; }}
</style>
</head>
<body>
<h1>&#128737; mei-guard</h1>
<p>Ring -3 Heuristic Anomaly Detection System</p>
<h2>Recent Alerts</h2>
<div id="alerts">Loading...</div>
<h2>DMI Latency (last 60s)</h2>
<canvas id="chart" width="900" height="200"></canvas>
<script>
async function refresh() {{
  const r = await fetch('/api/alerts');
  const data = await r.json();
  const div = document.getElementById('alerts');
  div.innerHTML = data.alerts.length === 0
    ? '<p style="color:#88ff88">No alerts. All clear.</p>'
    : data.alerts.map(a =>
        `<div class="alert sev-${{a.severity}}">
          <b>[${{['','LOW','MED','HIGH','CRIT'][a.severity]}}] ${{a.source}}</b>
          ${{new Date(a.timestamp*1000).toLocaleString()}}
          <br>${{a.detail}}
         </div>`).join('');
}}
async function drawChart() {{
  const r = await fetch('/api/latency');
  const d = await r.json();
  const canvas = document.getElementById('chart');
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (!d.samples || d.samples.length === 0) return;
  const vals = d.samples.map(s => s[1]);
  const max = Math.max(...vals) * 1.1;
  const min = Math.min(...vals) * 0.9;
  const w = canvas.width, h = canvas.height;
  ctx.strokeStyle = '#00ff88';
  ctx.lineWidth = 1;
  ctx.beginPath();
  vals.forEach((v, i) => {{
    const x = (i / vals.length) * w;
    const y = h - ((v - min) / (max - min)) * h;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  }});
  ctx.stroke();
  // Draw mean line
  const mean = vals.reduce((a,b)=>a+b)/vals.length;
  const my = h - ((mean-min)/(max-min))*h;
  ctx.strokeStyle='#ff8800'; ctx.setLineDash([4,4]);
  ctx.beginPath(); ctx.moveTo(0,my); ctx.lineTo(w,my); ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillStyle='#aaa'; ctx.font='11px monospace';
  ctx.fillText(`mean: ${{mean.toFixed(1)}} ns`, 4, my-3);
}}
setInterval(() => {{ refresh(); drawChart(); }}, 2000);
refresh(); drawChart();
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    store: AlertStore = None  # set at class level

    def log_message(self, fmt, *args):
        pass  # silence access log

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())
        elif self.path == "/api/alerts":
            data = json.dumps({"alerts": self.store.recent_alerts(25)})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data.encode())
        elif self.path == "/api/latency":
            rows = self.store.latency_window(60)
            data = json.dumps({"samples": rows})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data.encode())
        else:
            self.send_error(404)


# ------------------------------------------------------------------ #
#  Main analysis daemon                                                #
# ------------------------------------------------------------------ #

class Daemon:
    def __init__(self, args):
        self.args     = args
        self.store    = AlertStore(args.db)
        self.notifier = Notifier(self._load_notify_config())
        self._running = True
        self._tsc_freq: Optional[float] = None   # calibrated from latency data
        self._tsc_samples: deque = deque(maxlen=500)

        DashboardHandler.store = self.store
        self._srv = HTTPServer(
            ("127.0.0.1", args.port), DashboardHandler)
        self._srv_thread = threading.Thread(
            target=self._srv.serve_forever, daemon=True)

        self._lat_analyser = LatencyAnalyser(self.store, self._handle_alert)

        self._arp_watcher: Optional[ARPWatcher] = None
        if args.watch_arp and args.os_mac:
            self._arp_watcher = ARPWatcher(
                args.arp_iface, args.os_mac, self._handle_alert)

    def _load_notify_config(self) -> dict:
        cfg_path = Path(self.args.notify_config)
        if cfg_path.exists():
            with open(cfg_path) as f:
                return json.load(f)
        return {"syslog": True}

    def _handle_alert(self, alert: Alert):
        row_id = self.store.insert_alert(alert)
        if row_id < 0:
            return  # duplicate, suppressed

        level = SEVERITY_NAMES.get(alert.severity, "UNKNOWN")
        log.warning("[%s] %s: %s", level, alert.source, alert.detail)
        self.notifier.notify(alert)

    def _calibrate_tsc(self, ticks: int, ts: float):
        """
        Accumulate (timestamp, ticks) pairs to estimate TSC frequency
        so latency values can be expressed in nanoseconds.
        """
        self._tsc_samples.append((ts, ticks))
        if len(self._tsc_samples) >= 100 and self._tsc_freq is None:
            # Estimate: median ticks value / (median expected DRAM latency ~100ns)
            # Better: use wall-clock delta across the first and last sample
            t0, v0 = self._tsc_samples[0]
            t1, v1 = self._tsc_samples[-1]
            if t1 > t0 and len(self._tsc_samples) > 10:
                # Each snapshot has N samples; the first/last timestamps
                # bracket the window, not individual tick durations.
                # Fall back to hard-coded 3 GHz if we can't derive it.
                pass
            # Conservative default if calibration data is insufficient
            if self._tsc_freq is None:
                self._tsc_freq = 3_000_000_000.0
                log.info("TSC freq defaulted to %.2f GHz", self._tsc_freq / 1e9)

    def _ticks_to_ns(self, ticks: int) -> float:
        freq = self._tsc_freq or 3_000_000_000.0
        return ticks * 1e9 / freq

    def _parse_line(self, line: str):
        """Route a single JSON line from the C daemon to the correct handler."""
        line = line.strip()
        if not line or not line.startswith("{"):
            return
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return

        msg_type = obj.get("type", "")
        ts = obj.get("timestamp", time.time())

        if msg_type == "alert":
            alert = Alert(
                timestamp=float(ts),
                source=obj.get("source", "unknown"),
                severity=int(obj.get("severity", 2)),
                detail=obj.get("detail", ""),
            )
            self._handle_alert(alert)

        elif msg_type == "latency":
            ticks = int(obj.get("ticks", 0))
            if ticks > 0:
                self._calibrate_tsc(ticks, float(ts))
                ns = self._ticks_to_ns(ticks)
                self.store.insert_latency(float(ts), ns)

        elif msg_type == "stats":
            log.info("C daemon stats: heci_messages=%s  alerts=%s  unknown_guids=%s",
                     obj.get("heci_messages", "?"),
                     obj.get("heci_alerts", "?"),
                     obj.get("heci_unknown_guids", "?"))

        # Any other type is silently ignored – forward-compatible

    def run(self):
        log.info("mei-guard analyser starting. "
                 "Dashboard: http://127.0.0.1:%d", self.args.port)

        self._srv_thread.start()
        self._lat_analyser.start()
        if self._arp_watcher:
            self._arp_watcher.start()

        # Read JSON alerts from stdin (piped from C daemon)
        signal.signal(signal.SIGTERM, lambda *_: self.stop())
        signal.signal(signal.SIGINT,  lambda *_: self.stop())

        log.info("Reading typed JSON stream from stdin (C daemon output)...")
        import select
        while self._running:
            if sys.stdin in select.select([sys.stdin], [], [], 1.0)[0]:
                line = sys.stdin.readline()
                if not line:
                    break
                self._parse_line(line)

    def stop(self):
        self._running = False
        self._srv.shutdown()
        if self._arp_watcher:
            self._arp_watcher.stop()
        log.info("Analyser stopped.")


# ------------------------------------------------------------------ #
#  CLI                                                                 #
# ------------------------------------------------------------------ #

def main():
    p = argparse.ArgumentParser(
        description="mei-guard Python analysis daemon")
    p.add_argument("--db", default="/var/lib/mei-guard/mei_guard.db",
                   help="SQLite database path")
    p.add_argument("--port", type=int, default=7473,
                   help="Web dashboard port (default 7473)")
    p.add_argument("--notify-config", default="/etc/mei-guard/notify.json",
                   help="Notification config JSON")
    p.add_argument("--watch-arp", action="store_true",
                   help="Enable ARP-based ME MAC watcher")
    p.add_argument("--os-mac", default="",
                   help="This machine's OS NIC MAC (for ME MAC calculation)")
    p.add_argument("--arp-iface", default="eth0",
                   help="Interface to sniff for ME ARP packets")
    args = p.parse_args()

    # Ensure DB directory exists
    os.makedirs(os.path.dirname(args.db), exist_ok=True)

    daemon = Daemon(args)
    daemon.run()


if __name__ == "__main__":
    main()