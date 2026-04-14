#!/usr/bin/env python3
"""
md5_server.py — MD5 integrity-alert receiver and web UI.

No third-party dependencies — uses only the Python standard library.
Runs on Linux (systemd) or Windows (run directly / as a Windows service).

Endpoints:
  POST /alert              Receive a JSON alert from an md5_monitor.sh client.
  GET  /                   Web UI: all alerts, newest first, live-polls every 5 s.
  GET  /api/alerts         Raw JSON dump of all stored alerts.
  GET  /api/alerts/count   JSON object with the total number of stored alerts.
"""

import configparser
import json
import logging
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────────────────
_SCRIPT_DIR  = Path(__file__).parent
_CONFIG_FILE = _SCRIPT_DIR / "md5monitor_server.conf"
_SECTION     = "md5monitor"

def _load_config():
    cfg = configparser.ConfigParser()
    if _CONFIG_FILE.exists():
        cfg.read(_CONFIG_FILE, encoding="utf-8")
    else:
        # No config file — all defaults apply. Log after logger is set up.
        pass
    host     = cfg.get(_SECTION, "host",     fallback="0.0.0.0")
    port     = int(cfg.get(_SECTION, "port", fallback="8080"))
    data_raw = cfg.get(_SECTION, "data_dir", fallback="").strip()
    # data_dir defaults to the script's own directory if not set, so the server
    # works wherever it lives (a Desktop folder, /opt/md5monitor/, etc.)
    data_dir = Path(data_raw) if data_raw else _SCRIPT_DIR
    return host, port, data_dir

HOST, PORT, DATA_DIR = _load_config()
ALERTS_FILE = DATA_DIR / "alerts.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("md5monitor")

# ── Alert storage (thread-safe) ────────────────────────────────────────────────
_alerts_lock = threading.Lock()

def _load_alerts_unsafe() -> list:
    """Load alerts from disk. Caller must hold _alerts_lock."""
    if ALERTS_FILE.exists():
        try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            log.error("Failed to read alerts file: %s", exc)
    return []

def load_alerts() -> list:
    with _alerts_lock:
        return _load_alerts_unsafe()

def append_alert(alert: dict) -> None:
    with _alerts_lock:
        alerts = _load_alerts_unsafe()
        alerts.insert(0, alert)          # newest first
        with open(ALERTS_FILE, "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=2, ensure_ascii=False)

# ── HTML helpers ───────────────────────────────────────────────────────────────
def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )

def _fmt_ts(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return iso

# ── HTML page ──────────────────────────────────────────────────────────────────
# The initial render is server-side; JavaScript then polls /api/alerts every
# 5 seconds and updates the table body in-place (no full page reload).

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MD5 Integrity Monitor</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0f1117;
    color: #e2e8f0;
  }
  header {
    background: #1a1d27;
    border-bottom: 1px solid #2d3148;
    padding: 1rem 2rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  header h1 { margin: 0; font-size: 1.4rem; color: #a78bfa; }
  #badge {
    background: #312e81;
    color: #c4b5fd;
    border-radius: 9999px;
    padding: 0.2rem 0.75rem;
    font-size: 0.8rem;
    font-weight: 600;
  }
  #poll-status {
    margin-left: auto;
    font-size: 0.75rem;
    color: #64748b;
  }
  #poll-status.error { color: #f87171; }
  main { padding: 1.5rem 2rem; }
  #empty {
    display: none;
    text-align: center;
    color: #475569;
    margin-top: 4rem;
    font-size: 1.1rem;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }
  thead th {
    background: #1e2235;
    color: #94a3b8;
    text-align: left;
    padding: 0.65rem 0.9rem;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.72rem;
    letter-spacing: 0.05em;
    white-space: nowrap;
  }
  tbody tr {
    border-bottom: 1px solid #1e2235;
    transition: background 0.1s;
  }
  tbody tr:hover { background: #171b2b; }
  tbody td {
    padding: 0.65rem 0.9rem;
    vertical-align: top;
    word-break: break-all;
  }
  .ts   { color: #64748b; white-space: nowrap; font-size: 0.8rem; }
  .host { color: #38bdf8; font-weight: 600; white-space: nowrap; }
  .ip   { color: #94a3b8; font-size: 0.8rem; }
  .file { color: #f1f5f9; font-family: 'Cascadia Code', 'Consolas', monospace; }
  .hash { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.78rem; }
  .hash-old      { color: #f87171; }
  .hash-new      { color: #4ade80; }
  .hash-deleted  { color: #fb923c; }
  .hash-restored { color: #38bdf8; }
  .pill {
    display: inline-block;
    border-radius: 4px;
    padding: 0.1rem 0.45rem;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .pill-changed  { background: #1e1b4b; color: #a78bfa; }
  .pill-deleted  { background: #431407; color: #fb923c; }
  .pill-restored { background: #0c2340; color: #38bdf8; }
  .pill-new      { background: #052e16; color: #4ade80; }
</style>
</head>
<body>
<header>
  <h1>&#128274; MD5 Integrity Monitor</h1>
  <span id="badge">__BADGE__</span>
  <span id="poll-status">Polling every 5 s&hellip;</span>
</header>
<main>
  <p id="empty">No alerts received yet.</p>
  <table id="alert-table" style="__TABLE_DISPLAY__">
    <thead>
      <tr>
        <th>Time (UTC)</th>
        <th>Host</th>
        <th>IP(s)</th>
        <th>Status</th>
        <th>File</th>
        <th>Old Hash</th>
        <th>New Hash</th>
      </tr>
    </thead>
    <tbody id="alert-tbody">
__ROWS__
    </tbody>
  </table>
</main>

<script>
function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtTs(iso) {
  try {
    const d = new Date(iso);
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  } catch (_) { return esc(iso); }
}

function buildRow(a) {
  const ts      = fmtTs(a.timestamp || '');
  const host    = esc(a.hostname || 'unknown');
  const ips     = esc(Array.isArray(a.ips) ? a.ips.join(', ') : String(a.ips || ''));
  const file    = esc(a.file || '');
  const oldH    = esc(a.old_hash || '');
  const newH    = String(a.new_hash || '');
  const newHEsc = esc(newH);

  let pill, newHtml;
  if (newH.toUpperCase() === 'DELETED') {
    pill    = '<span class="pill pill-deleted">Deleted</span>';
    newHtml = `<span class="hash hash-deleted">${newHEsc}</span>`;
  } else if (oldH.toUpperCase() === 'DELETED') {
    pill    = '<span class="pill pill-restored">Restored</span>';
    newHtml = `<span class="hash hash-restored">${newHEsc}</span>`;
  } else if (oldH.toUpperCase() === 'NEW') {
    pill    = '<span class="pill pill-new">New File</span>';
    newHtml = `<span class="hash hash-new">${newHEsc}</span>`;
  } else {
    pill    = '<span class="pill pill-changed">Changed</span>';
    newHtml = `<span class="hash hash-new">${newHEsc}</span>`;
  }

  return `<tr>
    <td class="ts">${ts}</td>
    <td class="host">${host}</td>
    <td class="ip">${ips}</td>
    <td>${pill}</td>
    <td class="file">${file}</td>
    <td class="hash hash-old">${oldH}</td>
    <td>${newHtml}</td>
  </tr>`;
}

function updateUI(alerts) {
  const count  = alerts.length;
  const badge  = document.getElementById('badge');
  const tbody  = document.getElementById('alert-tbody');
  const empty  = document.getElementById('empty');
  const table  = document.getElementById('alert-table');

  badge.textContent = count + ' alert' + (count !== 1 ? 's' : '');
  if (count === 0) {
    empty.style.display = 'block';
    table.style.display = 'none';
  } else {
    empty.style.display = 'none';
    table.style.display = '';
    tbody.innerHTML = alerts.map(buildRow).join('\n');
  }
}

async function poll() {
  const status = document.getElementById('poll-status');
  try {
    const resp = await fetch('/api/alerts');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const alerts = await resp.json();
    updateUI(alerts);
    const now = new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
    status.textContent = 'Last updated ' + now;
    status.className = '';
  } catch (err) {
    status.textContent = 'Poll error: ' + err.message;
    status.className = 'error';
  }
}

setInterval(poll, 5000);
</script>
</body>
</html>
"""

def _build_row(alert: dict) -> str:
    ts       = _esc(_fmt_ts(alert.get("timestamp", "")))
    host     = _esc(str(alert.get("hostname", "unknown")))
    ips_raw  = alert.get("ips", [])
    ips      = _esc(", ".join(ips_raw) if isinstance(ips_raw, list) else str(ips_raw))
    filepath = _esc(str(alert.get("file", "")))
    old_h    = _esc(str(alert.get("old_hash", "")))
    new_h    = str(alert.get("new_hash", ""))
    new_h_esc = _esc(new_h)

    new_h_upper = new_h.upper()
    old_h_upper = alert.get("old_hash", "").upper()

    if new_h_upper == "DELETED":
        pill      = '<span class="pill pill-deleted">Deleted</span>'
        new_h_html = f'<span class="hash hash-deleted">{new_h_esc}</span>'
    elif old_h_upper == "DELETED":
        pill      = '<span class="pill pill-restored">Restored</span>'
        new_h_html = f'<span class="hash hash-restored">{new_h_esc}</span>'
    elif old_h_upper == "NEW":
        pill      = '<span class="pill pill-new">New File</span>'
        new_h_html = f'<span class="hash hash-new">{new_h_esc}</span>'
    else:
        pill      = '<span class="pill pill-changed">Changed</span>'
        new_h_html = f'<span class="hash hash-new">{new_h_esc}</span>'

    return (
        f'      <tr>'
        f'<td class="ts">{ts}</td>'
        f'<td class="host">{host}</td>'
        f'<td class="ip">{ips}</td>'
        f'<td>{pill}</td>'
        f'<td class="file">{filepath}</td>'
        f'<td class="hash hash-old">{old_h}</td>'
        f'<td>{new_h_html}</td>'
        f'</tr>'
    )

def generate_html(alerts: list) -> str:
    count = len(alerts)
    badge = f'{count} alert{"s" if count != 1 else ""}'
    rows  = "\n".join(_build_row(a) for a in alerts)
    table_display = "" if count else "display:none"
    return (
        _HTML_TEMPLATE
        .replace("__BADGE__", badge)
        .replace("__TABLE_DISPLAY__", table_display)
        .replace("__ROWS__", rows)
    )


# ── Request handler ────────────────────────────────────────────────────────────
class AlertHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path != "/alert":
            self._respond(404, "text/plain", b"Not Found")
            return

        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            self._respond(400, "text/plain", b"Empty body")
            return

        body = self.rfile.read(length)
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            log.warning("Malformed JSON from %s: %s", self.client_address, exc)
            self._respond(400, "text/plain", b"Invalid JSON")
            return

        required = ("hostname", "ips", "file", "old_hash", "new_hash")
        missing  = [k for k in required if k not in data]
        if missing:
            self._respond(400, "text/plain", f"Missing fields: {missing}".encode())
            return

        data["timestamp"] = datetime.now(timezone.utc).isoformat()
        append_alert(data)

        log.info(
            "Alert  host=%-20s  file=%s  old=%s  new=%s",
            data["hostname"], data["file"], data["old_hash"], data["new_hash"],
        )
        self._respond(200, "text/plain", b"OK")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            alerts = load_alerts()
            html   = generate_html(alerts)
            self._respond(200, "text/html; charset=utf-8", html.encode("utf-8"))

        elif self.path == "/api/alerts":
            alerts = load_alerts()
            body   = json.dumps(alerts, indent=2, ensure_ascii=False).encode("utf-8")
            self._respond(200, "application/json", body)

        elif self.path == "/api/alerts/count":
            count = len(load_alerts())
            body  = json.dumps({"count": count}).encode("utf-8")
            self._respond(200, "application/json", body)

        else:
            self._respond(404, "text/plain", b"Not Found")

    def _respond(self, code: int, content_type: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        log.debug("%s - %s", self.address_string(), fmt % args)


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not _CONFIG_FILE.exists():
        log.warning("Config file not found: %s — using defaults", _CONFIG_FILE)

    server = HTTPServer((HOST, PORT), AlertHandler)
    log.info("Config file    : %s", _CONFIG_FILE)
    log.info("Data directory : %s", DATA_DIR)
    log.info("Alerts file    : %s", ALERTS_FILE)
    log.info("MD5 Monitor Server listening on %s:%d", HOST, PORT)
    log.info("Web UI         : http://0.0.0.0:%d/", PORT)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
        server.server_close()
