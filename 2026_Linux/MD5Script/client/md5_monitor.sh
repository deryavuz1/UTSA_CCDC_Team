#!/bin/sh
# md5_monitor.sh — File integrity monitor client (POSIX sh)
# Runs as root. Systemd starts it once at boot; the script loops internally.
# Dependencies: sh, md5sum, find, awk, curl, flock, ip
set -eu

SCRIPT_DIR="/root/md5monitor"
CONFIG_FILE="${SCRIPT_DIR}/md5monitor.conf"
BASELINE_FILE="${SCRIPT_DIR}/baseline.md5"
LOCK_FILE="${SCRIPT_DIR}/md5monitor.lock"
LOG_FILE="${SCRIPT_DIR}/md5monitor.log"

# Sentinel stored in the baseline for a known-deleted file.
# 32 zeros is not a valid MD5 digest, so it's unambiguous.
DELETED_SENTINEL="00000000000000000000000000000000"

# ── Logging ────────────────────────────────────────────────────────────────────
# Writes to the log file AND stderr (captured by journalctl).
# Deliberately does NOT write to stdout so hash output is never contaminated.
log() {
    _ts="$(date '+%Y-%m-%d %H:%M:%S')"
    printf '[%s] %s\n' "$_ts" "$*" >> "$LOG_FILE"
    printf '[%s] %s\n' "$_ts" "$*" >&2
}
log_warn() { log "WARNING: $*"; }
log_err()  { log "ERROR: $*"; }

# ── Temp file tracking & cleanup ───────────────────────────────────────────────
CURRENT_TMP=""
EVENTS_TMP=""
NEW_BASELINE_TMP=""

cleanup() {
    rm -f "$CURRENT_TMP" "$EVENTS_TMP" "$NEW_BASELINE_TMP" 2>/dev/null
    true   # ensure cleanup itself never triggers set -e
}
trap cleanup EXIT
trap 'log "Received shutdown signal, exiting."; exit 0' TERM INT

# ── Lock: only one instance at a time ──────────────────────────────────────────
# fd 9 is used — single digit, universally supported by POSIX shells.
exec 9>"$LOCK_FILE"
flock -n 9 || { log_err "Another instance is already running. Exiting."; exit 1; }

# ── Config ─────────────────────────────────────────────────────────────────────
if [ ! -f "$CONFIG_FILE" ]; then
    log_err "Config file not found: $CONFIG_FILE"
    exit 1
fi
# shellcheck source=/dev/null
. "$CONFIG_FILE"
# Config must define:
#   SERVER_URL                 — e.g. "http://192.168.1.100:8080"
#   monitor_paths()            — shell function that prints one path per line
# Config may define:
#   SCAN_INTERVAL              — seconds between scans (default: 300)
#   JUMPBOX_SSH_IP             — IP/hostname of the SSH jump box
#   JUMPBOX_SSH_PORT           — SSH port on the jump box (default: 22)
#   JUMPBOX_SSH_USER           — SSH user on the jump box
#   JUMPBOX_SSH_PASSWORD_FILE  — file containing the password (requires sshpass);
#                                omit to use root's SSH key instead

SCAN_INTERVAL="${SCAN_INTERVAL:-300}"

if [ -z "${SERVER_URL:-}" ]; then
    log_err "SERVER_URL is not set in $CONFIG_FILE"
    exit 1
fi
if ! type monitor_paths > /dev/null 2>&1; then
    log_err "monitor_paths() function is not defined in $CONFIG_FILE"
    exit 1
fi

# ── Jump box validation ────────────────────────────────────────────────────────
if [ -n "${JUMPBOX_SSH_IP:-}" ] && [ -z "${JUMPBOX_SSH_USER:-}" ]; then
    log_err "JUMPBOX_SSH_IP is set but JUMPBOX_SSH_USER is missing in $CONFIG_FILE"
    exit 1
fi
if [ -n "${JUMPBOX_SSH_USER:-}" ] && [ -z "${JUMPBOX_SSH_IP:-}" ]; then
    log_err "JUMPBOX_SSH_USER is set but JUMPBOX_SSH_IP is missing in $CONFIG_FILE"
    exit 1
fi
if [ -n "${JUMPBOX_SSH_PASSWORD_FILE:-}" ]; then
    if [ ! -r "${JUMPBOX_SSH_PASSWORD_FILE}" ]; then
        log_err "JUMPBOX_SSH_PASSWORD_FILE is not readable: ${JUMPBOX_SSH_PASSWORD_FILE}"
        exit 1
    fi
    if ! type sshpass > /dev/null 2>&1; then
        log_err "JUMPBOX_SSH_PASSWORD_FILE is set but 'sshpass' is not installed"
        exit 1
    fi
fi

# ── Host identity (resolved once at startup) ───────────────────────────────────
HOSTNAME_VAL=$(hostname)

# One awk call collects IPs, strips CIDR, excludes virtual interfaces.
get_real_ips() {
    ip -4 addr show 2>/dev/null | awk '
        /^[0-9]+:/ { iface = $2; sub(/:$/, "", iface) }
        /inet / {
            if (iface !~ /^(lo|docker[0-9]|br-|veth|virbr|tun|tap)/) {
                addr = $2; sub(/\/.*/, "", addr)
                result = result (result ? "," : "") addr
            }
        }
        END { print result }
    '
}

IPS=$(get_real_ips)

# ── JSON helpers ───────────────────────────────────────────────────────────────

# Escape a value for use inside a JSON double-quoted string.
# Handles: backslash, double-quote, tab, carriage return, newline.
json_escape() {
    printf '%s' "$1" | awk 'BEGIN { ORS = "" }
    {
        gsub(/\\/, "\\\\")
        gsub(/"/, "\\\"")
        gsub(/\t/, "\\t")
        gsub(/\r/, "\\r")
        gsub(/\n/, "\\n")
        print
    }'
}

# Convert a comma-separated IP string to a JSON array: ["a","b"]
ips_to_json() {
    if [ -z "$1" ]; then
        printf '[]'
        return
    fi
    printf '%s' "$1" | awk 'BEGIN { ORS = "" } {
        n = split($0, arr, ",")
        printf "["
        sep = ""
        for (i = 1; i <= n; i++) {
            if (arr[i] != "") { printf "%s\"%s\"", sep, arr[i]; sep = "," }
        }
        printf "]"
    }'
}

# ── Alert transport ────────────────────────────────────────────────────────────
# POST a JSON string to ${SERVER_URL}/alert.
# If jump box vars are configured, the curl runs on the remote machine;
# the payload is piped through stdin so no shell quoting issues arise.
_post_json() {
    _json="$1"
    _url="${SERVER_URL}/alert"
    _jport="${JUMPBOX_SSH_PORT:-22}"

    if [ -n "${JUMPBOX_SSH_IP:-}" ] && [ -n "${JUMPBOX_SSH_USER:-}" ]; then
        # -sS: silent progress but still emit error messages; -f: fail on HTTP errors
        _remote_cmd="curl -sSf -m 10 -X POST '${_url}' -H 'Content-Type: application/json' -d @-"

        if [ -n "${JUMPBOX_SSH_PASSWORD_FILE:-}" ]; then
            # Password auth via sshpass — password is read from the file, not echoed
            printf '%s' "$_json" | \
                sshpass -f "$JUMPBOX_SSH_PASSWORD_FILE" \
                ssh -p "$_jport" \
                    -o StrictHostKeyChecking=accept-new \
                    -o ConnectTimeout=10 \
                    -o PasswordAuthentication=yes \
                    "${JUMPBOX_SSH_USER}@${JUMPBOX_SSH_IP}" \
                    "$_remote_cmd"
        else
            # Key-based auth — root's SSH key must be authorised on the jump box
            printf '%s' "$_json" | \
                ssh -p "$_jport" \
                    -o BatchMode=yes \
                    -o PasswordAuthentication=no \
                    -o StrictHostKeyChecking=accept-new \
                    -o ConnectTimeout=10 \
                    "${JUMPBOX_SSH_USER}@${JUMPBOX_SSH_IP}" \
                    "$_remote_cmd"
        fi
    else
        # Direct delivery — no jump box; -sS: silent but show errors
        printf '%s' "$_json" | \
            curl -sSf -m 10 -X POST "$_url" \
                 -H "Content-Type: application/json" \
                 -d @-
    fi
}

# ── Alert sender ───────────────────────────────────────────────────────────────
send_alert() {
    _file="$1"
    _old_hash="$2"
    _new_hash="$3"

    _host_esc=$(json_escape "$HOSTNAME_VAL")
    _file_esc=$(json_escape "$_file")
    _ips_json=$(ips_to_json "$IPS")

    _payload="{\"hostname\":\"${_host_esc}\",\"ips\":${_ips_json},\"file\":\"${_file_esc}\",\"old_hash\":\"${_old_hash}\",\"new_hash\":\"${_new_hash}\"}"

    # Capture combined stdout+stderr. On success stdout is the server's "OK"
    # response (not logged). On failure the captured output contains the error
    # from sshpass, ssh, or curl — whichever step failed.
    if _output=$( _post_json "$_payload" 2>&1 ); then
        log "Alert sent  file='$_file'  old=$_old_hash  new=$_new_hash"
    else
        log_warn "Failed to deliver alert for file: $_file (exit code: $?)"
        [ -n "$_output" ] && log_warn "Delivery error: ${_output}"
    fi
}

# ── Hash generation ────────────────────────────────────────────────────────────
# Writes "hash  /path" lines to stdout only.
# Logging goes to stderr/file so stdout stays clean for capture.
generate_current_hashes() {
    monitor_paths | while IFS= read -r _path; do
        if [ -f "$_path" ]; then
            md5sum "$_path"
        elif [ -d "$_path" ]; then
            # -exec {} + batches args per invocation (POSIX.1-2008, faster than \;)
            find "$_path" -type f -exec md5sum {} +
        else
            log_warn "Path not found, skipping: $_path" >&2
        fi
    done
}

# ── Single scan ────────────────────────────────────────────────────────────────
run_scan() {
    CURRENT_TMP=$(mktemp "${SCRIPT_DIR}/current.XXXXXX")
    EVENTS_TMP=$(mktemp "${SCRIPT_DIR}/events.XXXXXX")
    NEW_BASELINE_TMP=$(mktemp "${SCRIPT_DIR}/baseline_new.XXXXXX")

    generate_current_hashes > "$CURRENT_TMP" 2>/dev/null || true
    current_count=$(wc -l < "$CURRENT_TMP" | tr -d ' ')

    # First run — write baseline, no comparison
    if [ ! -f "$BASELINE_FILE" ]; then
        cp "$CURRENT_TMP" "$BASELINE_FILE"
        log "Baseline created with ${current_count} entries. Alerts fire from the next scan onward."
        rm -f "$CURRENT_TMP" "$EVENTS_TMP" "$NEW_BASELINE_TMP"
        CURRENT_TMP=""; EVENTS_TMP=""; NEW_BASELINE_TMP=""
        return
    fi

    # ── Compare baseline vs current with awk ──────────────────────────────────
    # md5sum format: "<32-char-hash>  <path>"  — path starts at position 35 (1-indexed)
    #
    # Event output — always exactly 4 tab-separated fields, NO empty fields:
    #   CHANGED        <old_hash>    <new_hash>    <filepath>
    #   NEW            NEW           <new_hash>    <filepath>
    #   RESTORED       DELETED       <new_hash>    <filepath>
    #   NEWLY_DELETED  <old_hash>    DELETED       <filepath>
    #   STILL_DELETED  <sentinel>    <sentinel>    <filepath>
    #
    # No empty/consecutive-tab fields: POSIX sh treats a lone tab in IFS as
    # "IFS whitespace", which collapses consecutive tabs — empty placeholder
    # fields would silently shift the filepath into the wrong variable.
    awk -v sentinel="$DELETED_SENTINEL" '
        NR == FNR {
            fp = substr($0, 35)
            baseline[fp] = $1
            next
        }
        {
            fp = substr($0, 35)
            ch = $1
            if (fp in baseline) {
                bh = baseline[fp]
                if (bh == sentinel)
                    print "RESTORED\tDELETED\t"    ch          "\t" fp
                else if (bh != ch)
                    print "CHANGED\t"              bh "\t" ch  "\t" fp
                delete baseline[fp]
            } else {
                print "NEW\tNEW\t"                 ch          "\t" fp
            }
        }
        END {
            for (fp in baseline) {
                bh = baseline[fp]
                if (bh != sentinel)
                    print "NEWLY_DELETED\t" bh     "\tDELETED\t"    fp
                else
                    print "STILL_DELETED\t" sentinel "\t" sentinel "\t" fp
            }
        }
    ' "$BASELINE_FILE" "$CURRENT_TMP" > "$EVENTS_TMP"

    # New baseline starts from the current snapshot
    cp "$CURRENT_TMP" "$NEW_BASELINE_TMP"

    # ── Process events ─────────────────────────────────────────────────────────
    alert_count=0
    TAB=$(printf '\t')

    # Reading from a file (not a pipe) keeps alert_count in the current shell.
    # _ha = old_hash (or "NEW"/"DELETED"/sentinel), _hb = new_hash, _fp = filepath.
    # Because _fp is the last variable, read assigns it everything remaining on
    # the line — including any tab characters that may appear in the filepath.
    while IFS="$TAB" read -r _event _ha _hb _fp; do
        [ -z "$_event" ] && continue
        case "$_event" in
            CHANGED|NEW|RESTORED|NEWLY_DELETED)
                send_alert "$_fp" "$_ha" "$_hb"
                alert_count=$((alert_count + 1))
                ;;
        esac
        # Re-append sentinel for absent files (newly deleted or still deleted)
        case "$_event" in
            NEWLY_DELETED|STILL_DELETED)
                printf '%s  %s\n' "$DELETED_SENTINEL" "$_fp" >> "$NEW_BASELINE_TMP"
                ;;
        esac
    done < "$EVENTS_TMP"

    # Atomically install the new baseline
    mv "$NEW_BASELINE_TMP" "$BASELINE_FILE"
    rm -f "$CURRENT_TMP" "$EVENTS_TMP"
    CURRENT_TMP=""; EVENTS_TMP=""; NEW_BASELINE_TMP=""

    log "Scan complete: ${current_count} file(s) present, ${alert_count} alert(s) sent."
}

# ── Main loop ──────────────────────────────────────────────────────────────────
if [ -n "${JUMPBOX_SSH_IP:-}" ]; then
    _via=" via jumpbox=${JUMPBOX_SSH_USER}@${JUMPBOX_SSH_IP}:${JUMPBOX_SSH_PORT:-22}"
else
    _via=""
fi
log "MD5 monitor starting (host=${HOSTNAME_VAL}, server=${SERVER_URL}${_via}, interval=${SCAN_INTERVAL}s)"

while true; do
    run_scan
    log "Sleeping ${SCAN_INTERVAL}s until next scan..."
    sleep "$SCAN_INTERVAL"
done
