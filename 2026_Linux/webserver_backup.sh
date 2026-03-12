#!/usr/bin/env bash
# =============================================================================
# webserver_backup.sh
# Locates any Nginx and/or Apache installation on the host, collects all
# associated files into a single .tar.gz archive under /root/webserver_backups/
#
# All original file permissions, ownership, and timestamps are preserved
# inside the archive so that files can be fully restored with:
#   tar -xpzf <archive> -C /

# Individual files can be restored as so:
#   tar -xpzf <archive> -C / etc/nginx/nginx.conf
#
# The archive itself is set to mode 400 (root read-only).
#
# Must be run as root.
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

# ── Root check ────────────────────────────────────────────────────────────────
if [[ "$EUID" -ne 0 ]]; then
    error "This script must be run as root (sudo $0)."
    exit 1
fi

# ── Timestamp & paths ─────────────────────────────────────────────────────────
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
HOSTNAME="$(hostname -s 2>/dev/null || echo "localhost")"
BACKUP_DIR="/root/webserver_backups"
ARCHIVE_NAME="webserver_backup_${HOSTNAME}_${TIMESTAMP}.tar.gz"
ARCHIVE_PATH="${BACKUP_DIR}/${ARCHIVE_NAME}"

# Manifest log written alongside the archive
MANIFEST_PATH="${BACKUP_DIR}/webserver_backup_${HOSTNAME}_${TIMESTAMP}.manifest"

echo -e "\n${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}         Web Server Configuration Backup Tool           ${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo -e "  Hostname  : ${HOSTNAME}"
echo -e "  Timestamp : ${TIMESTAMP}"
echo -e "  Archive   : ${ARCHIVE_PATH}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${RESET}\n"

# ── Collected source paths (with deduplication) ───────────────────────────────
declare -A SEEN_PATHS   # used as a set to prevent duplicates
SOURCE_PATHS=()

register_path() {
    local src="$1"

    # Resolve symlinks to the real path for dedup purposes
    local real
    real="$(realpath -m "$src" 2>/dev/null || echo "$src")"

    if [[ ! -e "$real" ]]; then
        warn "  Not found, skipping: ${src}"
        return
    fi

    # Skip if already queued, or if a parent directory is already queued
    # (tar will include children when a directory is given)
    for queued in "${SOURCE_PATHS[@]+"${SOURCE_PATHS[@]}"}"; do
        if [[ "$real" == "$queued" || "$real" == "$queued/"* ]]; then
            return
        fi
    done

    if [[ -n "${SEEN_PATHS[$real]+_}" ]]; then
        return
    fi

    SEEN_PATHS["$real"]=1
    SOURCE_PATHS+=("$real")
    info "  Queued: ${real}"
}

# =============================================================================
# NGINX — detection & path registration
# =============================================================================
detect_nginx() {
    echo -e "\n${BOLD}── Nginx ────────────────────────────────────────────────${RESET}"

    local found=0
    local nginx_bin=""

    for candidate in nginx /usr/sbin/nginx /usr/local/sbin/nginx /opt/nginx/sbin/nginx; do
        if command -v "$candidate" &>/dev/null || [[ -x "$candidate" ]]; then
            nginx_bin="$(command -v "$candidate" 2>/dev/null || echo "$candidate")"
            found=1
            break
        fi
    done

    # Also detect via package database even if the binary isn't in PATH
    if dpkg -l nginx &>/dev/null 2>&1 || rpm -q nginx &>/dev/null 2>&1; then
        found=1
    fi

    if [[ $found -eq 0 ]]; then
        warn "Nginx not detected on this host – skipping."
        return
    fi

    success "Nginx installation detected."
    [[ -n "$nginx_bin" ]] && info "  Binary: ${nginx_bin}"

    # Derive compile-time prefix from the binary's -V output
    local prefix=""
    if [[ -n "$nginx_bin" ]]; then
        prefix="$("$nginx_bin" -V 2>&1 | grep -oP '(?<=--prefix=)[^ ]+' || true)"
    fi

    local -a PATHS=(
        # Configuration
        /etc/nginx
        /usr/local/nginx/conf
        /opt/nginx/conf
        # Logs
        /var/log/nginx
        /usr/local/nginx/logs
        # Web roots
        /usr/share/nginx/html
        /var/www/html
        /srv/www
        # Systemd unit files
        /lib/systemd/system/nginx.service
        /etc/systemd/system/nginx.service
    )

    if [[ -n "$prefix" ]]; then
        PATHS+=("${prefix}/conf" "${prefix}/logs" "${prefix}/html")
    fi

    for p in "${PATHS[@]}"; do register_path "$p"; done
}

# =============================================================================
# APACHE — detection & path registration
# =============================================================================
detect_apache() {
    echo -e "\n${BOLD}── Apache ───────────────────────────────────────────────${RESET}"

    local found=0

    for candidate in apache2 httpd /usr/sbin/apache2 /usr/sbin/httpd /usr/local/sbin/httpd; do
        if command -v "$candidate" &>/dev/null || [[ -x "$candidate" ]]; then
            found=1; break
        fi
    done

    if dpkg -l apache2 &>/dev/null 2>&1 || \
       rpm -q httpd   &>/dev/null 2>&1 || \
       rpm -q apache2 &>/dev/null 2>&1; then
        found=1
    fi

    if [[ $found -eq 0 ]]; then
        warn "Apache not detected on this host – skipping."
        return
    fi

    success "Apache installation detected."

    local -a PATHS=(
        # Configuration — Debian/Ubuntu
        /etc/apache2
        # Configuration — RHEL/CentOS/Fedora
        /etc/httpd
        /etc/httpd/conf
        /etc/httpd/conf.d
        /etc/httpd/conf.modules.d
        # Configuration — custom builds
        /usr/local/apache2/conf
        /opt/apache2/conf
        # Logs
        /var/log/apache2
        /var/log/httpd
        /usr/local/apache2/logs
        # Web roots
        /var/www/html
        /var/www
        /srv/www
        /usr/local/apache2/htdocs
        # Systemd unit files
        /lib/systemd/system/apache2.service
        /lib/systemd/system/httpd.service
        /etc/systemd/system/apache2.service
        /etc/systemd/system/httpd.service
    )

    for p in "${PATHS[@]}"; do register_path "$p"; done
}

# =============================================================================
# MAIN
# =============================================================================

detect_nginx
detect_apache

if [[ ${#SOURCE_PATHS[@]} -eq 0 ]]; then
    error "No Nginx or Apache files were found on this host. Nothing to back up."
    exit 1
fi

# ── Prepare the backup directory (root-only access) ───────────────────────────
mkdir -p "$BACKUP_DIR"
chown root:root "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

# ── Build the .tar.gz archive ─────────────────────────────────────────────────
echo -e "\n${BOLD}── Creating archive ─────────────────────────────────────${RESET}"
info "  ${#SOURCE_PATHS[@]} path(s) queued for archiving …"

# tar flags explained:
#   --create              create a new archive
#   --gzip                compress with gzip
#   --preserve-permissions  store exact file mode bits (ugo+rwxst)
#   --same-owner          store owner/group; restores them on extract as root
#   --numeric-owner       store UID/GID numbers (portable across systems)
#   --ignore-failed-read  skip unreadable files instead of aborting
#   --file                output archive path
#   --files-from=-        read paths from stdin (one per line)
#
# Paths are absolute, so restoring with  tar -xpzf archive.tar.gz -C /
# puts every file back exactly where it came from.
#
# The stderr filter suppresses the cosmetic "Removing leading /" notice
# while still surfacing real warnings.

printf '%s\n' "${SOURCE_PATHS[@]}" \
    | tar \
        --create \
        --gzip \
        --preserve-permissions \
        --same-owner \
        --numeric-owner \
        --ignore-failed-read \
        --file="$ARCHIVE_PATH" \
        --files-from=- \
        2> >(grep -v "^tar: Removing leading" >&2) \
    || warn "tar exited non-zero – some files may have been skipped (see above)."

# ── Set archive to root read-only (400) ───────────────────────────────────────
chown root:root "$ARCHIVE_PATH"
chmod 400 "$ARCHIVE_PATH"

success "Archive created and locked to root read-only."

# ── Write a human-readable manifest (also root read-only) ────────────────────
{
    echo "Webserver Backup Manifest"
    echo "Generated : $(date)"
    echo "Hostname  : ${HOSTNAME}"
    echo "Archive   : ${ARCHIVE_PATH}"
    echo ""
    echo "Contents:"
    tar -tzf "$ARCHIVE_PATH"
} > "$MANIFEST_PATH"

chown root:root "$MANIFEST_PATH"
chmod 400 "$MANIFEST_PATH"

# ── Summary ───────────────────────────────────────────────────────────────────
ARCHIVE_SIZE="$(du -sh "$ARCHIVE_PATH" 2>/dev/null | cut -f1)"
FILE_COUNT="$(tar -tzf "$ARCHIVE_PATH" | wc -l)"

echo -e "\n${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}                     Summary                           ${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${RESET}"
echo -e "  Archive   : ${ARCHIVE_PATH}"
echo -e "  Manifest  : ${MANIFEST_PATH}"
echo -e "  Size      : ${ARCHIVE_SIZE}  (${FILE_COUNT} entries)"
echo -e "  Perms     : 400  (root read-only)"
echo ""
echo -e "  ${CYAN}List all archived files:${RESET}"
echo -e "    ${BOLD}tar -tzf ${ARCHIVE_PATH} | less${RESET}"
echo ""
echo -e "  ${CYAN}Restore everything to original paths:${RESET}"
echo -e "    ${BOLD}tar -xpzf ${ARCHIVE_PATH} -C /${RESET}"
echo ""
echo -e "  ${CYAN}Restore a single file:${RESET}"
echo -e "    ${BOLD}tar -xpzf ${ARCHIVE_PATH} -C / etc/nginx/nginx.conf${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${RESET}\n"
