# MD5 Integrity Monitor

A lightweight file integrity monitoring system. Client machines (Linux) hash
watched files on a schedule and send an alert to a central server whenever a
file is created, modified, deleted, or restored. The server provides a web UI
and a small JSON API for reviewing alerts.

```
┌─────────────────────┐        HTTP POST /alert         ┌──────────────────────┐
│  Client machine(s)  │  ─────────────────────────────> │  Server machine      │
│  md5_monitor.sh     │  (direct, or via SSH jump box)  │  md5_server.py       │
│  systemd service    │                                 │  Web UI :8080        │
└─────────────────────┘                                 └──────────────────────┘
```

---

## Repository layout

```
client/
  md5_monitor.sh              Bash client script (POSIX sh)
  md5monitor.conf.example     Client config template

server/
  md5_server.py               Python 3 server (stdlib only)
  md5monitor_server.conf.example  Server config template

services/
  md5monitor-client.service   systemd unit for the client
  md5monitor-server.service   systemd unit for the server
```

---

## Server setup

### Requirements
- Python 3.6 or newer
- Any Linux distro (or Windows — see below)

### 1. Copy files

```bash
mkdir -p /opt/md5monitor
cp server/md5_server.py /opt/md5monitor/
cp server/md5monitor_server.conf.example /opt/md5monitor/md5monitor_server.conf
```

### 2. Edit the config

```bash
nano /opt/md5monitor/md5monitor_server.conf
```

```ini
[md5monitor]
host = 0.0.0.0   # listen on all interfaces
port = 8080      # change if needed
# data_dir =     # leave blank to store alerts.json next to the script
```

All settings are optional. If the config file is absent the server starts with
the defaults shown above.

### 3. Install and start the systemd service

```bash
cp services/md5monitor-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now md5monitor-server
```

### 4. Verify

```bash
systemctl status md5monitor-server
journalctl -u md5monitor-server -f
```

The web UI is now available at `http://<server-ip>:8080/`.

### Running on Windows (no systemd)

```powershell
python md5_server.py
```

`alerts.json` is stored in the same folder as the script. To use a different
location set the `data_dir` key in `md5monitor_server.conf`.

---

## Client setup

Repeat these steps on every machine you want to monitor.

### Requirements
- Any POSIX-compatible shell (`/bin/sh`) — no bash required
- `md5sum` (GNU coreutils — standard on all Linux distros)
- `find` (POSIX.1-2008 — standard on all Linux distros)
- `awk` (POSIX — standard on all Linux distros)
- `curl` (very common; `apt install curl` / `dnf install curl` if missing)
- `ip` (iproute2 — standard on all modern Linux distros)
- `flock` (util-linux — standard on all Linux distros)
- `sshpass` — **only** needed when using password auth for the jump box

### 1. Copy files

```bash
mkdir -p /root/md5monitor
cp client/md5_monitor.sh /root/md5monitor/
chmod +x /root/md5monitor/md5_monitor.sh
cp client/md5monitor.conf.example /root/md5monitor/md5monitor.conf
```

### 2. Edit the config

```bash
nano /root/md5monitor/md5monitor.conf
```

#### Required settings

**`SERVER_URL`** — full HTTP address of the server (no trailing slash):
```sh
SERVER_URL="http://192.168.1.100:8080"
```

**`monitor_paths()`** — a shell function that prints one path per line.
Files are hashed directly; directories are scanned recursively.
```sh
monitor_paths() {
    printf '%s\n' \
        "/etc/passwd"   \
        "/etc/shadow"   \
        "/etc/ssh"      \
        "/root/.ssh"
}
```

#### Optional settings

**`SCAN_INTERVAL`** — seconds between scans (default `300`):
```sh
SCAN_INTERVAL=300
```

### 3. Install and start the systemd service

The client runs as a self-looping process — systemd starts it once at boot and
restarts it automatically if it ever crashes.

```bash
cp services/md5monitor-client.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now md5monitor-client
```

### 4. Verify

```bash
systemctl status md5monitor-client
journalctl -u md5monitor-client -f
```

The **first run** creates the hash baseline and does not send any alerts.
Alerts fire from the second scan onward.

---

## Jump box (optional)

If client machines cannot reach the server directly, alerts can be routed
through an SSH jump box. The client SSHes into the jump box and runs `curl`
from there.

Add the following to `/root/md5monitor/md5monitor.conf`:

```sh
JUMPBOX_SSH_IP=192.168.1.50
JUMPBOX_SSH_PORT=22          # optional, defaults to 22
JUMPBOX_SSH_USER=monitor
```

### Key-based auth (recommended)

Root's SSH key on the client must be authorised for `JUMPBOX_SSH_USER` on the
jump box. No extra config is needed.

```bash
# One-time setup — run on the client machine
ssh-copy-id -i /root/.ssh/id_rsa.pub monitor@192.168.1.50
```

### Password auth

Requires `sshpass` installed on the **client** machine:
```bash
apt install sshpass   # Debian/Ubuntu
dnf install sshpass   # RHEL/Fedora
```

Create a password file readable only by root:
```bash
echo 'your-password-here' > /root/md5monitor/jumpbox.pass
chmod 600 /root/md5monitor/jumpbox.pass
```

Then add to the config:
```sh
JUMPBOX_SSH_PASSWORD_FILE=/root/md5monitor/jumpbox.pass
```

---

## Alert types

| Status | Meaning |
|---|---|
| **New File** | A file appeared that was not in the baseline |
| **Changed** | A monitored file's MD5 hash changed |
| **Deleted** | A monitored file was removed |
| **Restored** | A previously deleted file reappeared |

Each alert records the hostname, IP address(es), affected file path, old hash,
and new hash. Deleted files are marked with a sentinel in the baseline so the
alert fires only once — not on every subsequent scan.

---

## API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Web UI — all alerts, newest first, auto-updates every 5 s |
| `GET` | `/api/alerts` | Full alert list as JSON |
| `GET` | `/api/alerts/count` | `{"count": N}` — total number of stored alerts |
| `POST` | `/alert` | Ingest a new alert (used by the client script) |

### Alert JSON schema (POST /alert)

```json
{
  "hostname": "webserver-01",
  "ips": ["192.168.1.10", "10.0.0.5"],
  "file": "/etc/passwd",
  "old_hash": "abc123...",
  "new_hash": "def456..."
}
```

Special values for `old_hash`: `"NEW"` (file just appeared), `"DELETED"` (file
was previously deleted and has now been restored).

Special value for `new_hash`: `"DELETED"` (file was removed).

---

## Log files & troubleshooting

### Client log
```bash
# Via systemd journal (recommended)
journalctl -u md5monitor-client -f

# Or directly
tail -f /root/md5monitor/md5monitor.log
```

### Server log
```bash
journalctl -u md5monitor-server -f
```

### Manually trigger a scan
```bash
# Run once in the foreground to see output immediately
/root/md5monitor/md5_monitor.sh
```

Note: if the systemd service is already running, the lock file will prevent a
second instance. Stop the service first:
```bash
systemctl stop md5monitor-client
/root/md5monitor/md5_monitor.sh
systemctl start md5monitor-client
```

### Reset the baseline
Delete the baseline file. The next scan will rebuild it from scratch without
sending any alerts.
```bash
systemctl stop md5monitor-client
rm /root/md5monitor/baseline.md5
systemctl start md5monitor-client
```

### Reset all stored alerts
```bash
# On the server machine
systemctl stop md5monitor-server
rm /opt/md5monitor/alerts.json
systemctl start md5monitor-server
```
