#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HARDEN_LOG_FILE="${HARDEN_LOG_FILE:-/root/bsd_hardening.log}"

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_INFO=$'\033[1;34m'
  C_WARN=$'\033[1;33m'
  C_ERR=$'\033[1;31m'
  C_OK=$'\033[1;32m'
else
  C_RESET=""
  C_INFO=""
  C_WARN=""
  C_ERR=""
  C_OK=""
fi

BASE="https://raw.githubusercontent.com/SouthwestCCDC/2026-Regionals-Shared/main/The%20University%20of%20Texas%20at%20San%20Antonio/2026_BSD"

BSD_SECTION1_URL="${BSD_SECTION1_URL:-$BASE/bsd_section1_enumeration.sh}"
BSD_SECTION2_URL="${BSD_SECTION2_URL:-$BASE/bsd_section2_initial_hardening.sh}"
export BSD_SECTION1_URL BSD_SECTION2_URL

log_line() {
  local level="$1"
  shift
  printf '%s [%s] %s\n' "$(date '+%F %T')" "$level" "$*" >>"$HARDEN_LOG_FILE"
}

info() {
  printf '%s[*]%s %s\n' "$C_INFO" "$C_RESET" "$*"
  log_line "INFO" "$*"
}

ok() {
  printf '%s[+]%s %s\n' "$C_OK" "$C_RESET" "$*"
  log_line "OK" "$*"
}

warn() {
  printf '%s[!]%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2
  log_line "WARN" "$*"
}

error() {
  printf '%s[x]%s %s\n' "$C_ERR" "$C_RESET" "$*" >&2
  log_line "ERROR" "$*"
}

section_header() {
  printf '\n%s==== %s ====%s\n' "$C_INFO" "$*" "$C_RESET"
  log_line "SECTION" "$*"
}

pause_step() {
  read -r -p "Press Enter to continue..." _unused
}

show_output_source_header() {
  local source_label="$1"
  printf '\n%s############################################%s\n' "$C_WARN" "$C_RESET"
  printf '%s# OUTPUT SOURCE: %s%s\n' "$C_WARN" "$source_label" "$C_RESET"
  printf '%s############################################%s\n' "$C_WARN" "$C_RESET"
}

show_file_with_pause() {
  local file_path="$1"
  show_output_source_header "FILE: $file_path"
  if [[ -r "$file_path" ]]; then
    cat "$file_path"
  elif [[ -e "$file_path" ]]; then
    warn "File exists but is not readable: $file_path"
  else
    warn "File not found: $file_path"
  fi
  pause_step
}

show_command_with_pause() {
  local label="$1"
  shift
  show_output_source_header "COMMAND: $label"
  "$@" || warn "Command failed: $label"
  pause_step
}

show_shell_with_pause() {
  local label="$1"
  local shell_cmd="$2"
  show_output_source_header "COMMAND: $label"
  bash -c "$shell_cmd" || warn "Command failed: $label"
  pause_step
}

ask_yes_no() {
  local prompt="$1"
  local default="${2:-N}"
  local answer

  while true; do
    if [[ "$default" =~ ^[Yy]$ ]]; then
      read -r -p "$prompt [Y/n]: " answer
      answer="${answer:-Y}"
    else
      read -r -p "$prompt [y/N]: " answer
      answer="${answer:-N}"
    fi

    case "$answer" in
      [Yy]|[Yy][Ee][Ss]) return 0 ;;
      [Nn]|[Nn][Oo]) return 1 ;;
      *) warn "Please answer y or n." ;;
    esac
  done
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    info "Root privileges are required. Re-running with sudo/doas."
    if command_exists sudo; then
      exec sudo -E bash "$0" "$@"
    elif command_exists doas; then
      exec doas bash "$0" "$@"
    else
      error "Neither sudo nor doas found. Run as root."
      exit 1
    fi
  fi
}

# Detect BSD variant: prints "freebsd" or "openbsd"
detect_bsd() {
  local os
  os="$(uname -s)"
  case "$os" in
    FreeBSD) echo "freebsd" ;;
    OpenBSD) echo "openbsd" ;;
    *) echo "unknown" ;;
  esac
}

BSD_TYPE="$(detect_bsd)"

is_freebsd() { [[ "$BSD_TYPE" == "freebsd" ]]; }
is_openbsd() { [[ "$BSD_TYPE" == "openbsd" ]]; }

# getent wrapper - OpenBSD lacks getent, fall back to grep
getent_compat() {
  local db="$1"
  shift
  if command_exists getent; then
    getent "$db" "$@"
  else
    case "$db" in
      passwd)
        if [[ $# -gt 0 ]]; then
          grep -E "^[^:]*:[^:]*:${1}:" /etc/passwd 2>/dev/null || \
          grep -E "^${1}:" /etc/passwd 2>/dev/null
        else
          cat /etc/passwd
        fi
        ;;
      group)
        if [[ $# -gt 0 ]]; then
          grep -E "^${1}:" /etc/group 2>/dev/null
        else
          cat /etc/group
        fi
        ;;
      *)
        warn "getent_compat: unsupported db '$db'"
        return 1
        ;;
    esac
  fi
}

install_packages() {
  if is_freebsd; then
    pkg install -y "$@"
  elif is_openbsd; then
    pkg_add "$@"
  else
    warn "Unknown BSD variant; cannot auto-install packages."
    return 1
  fi
}

save_installed_packages() {
  local output_file="$1"
  if is_freebsd; then
    pkg info >"$output_file" 2>&1
  elif is_openbsd; then
    if command_exists pkg_info; then
      pkg_info >"$output_file" 2>&1
    else
      warn "pkg_info not available"
      return 1
    fi
  else
    warn "Unknown BSD variant; cannot save package list."
    return 1
  fi
  ok "Installed package list saved to $output_file"
}

list_listening_sockets() {
  if command_exists sockstat; then
    sockstat -l
  elif command_exists netstat; then
    netstat -an -p tcp
    netstat -an -p udp
  else
    warn "Neither sockstat nor netstat is available."
    return 1
  fi
}

print_groups_highlighted() {
  local hi reset
  if [[ -t 1 ]]; then
    hi=$'\033[1;33m'
    reset=$'\033[0m'
  else
    hi=""
    reset=""
  fi

  # FreeBSD/OpenBSD privileged groups: wheel, operator, docker (if installed)
  cat /etc/group | awk -F: -v hi="$hi" -v reset="$reset" '{
    if ($1=="wheel" || $1=="operator" || $1=="docker" || $1=="staff") {
      print hi $0 reset
    } else {
      print $0
    }
  }'
}

# Disable a service using the appropriate BSD mechanism
disable_service_if_present() {
  local svc="$1"
  if is_freebsd; then
    if service "$svc" status >/dev/null 2>&1 || grep -qE "^${svc}_enable" /etc/rc.conf 2>/dev/null; then
      sysrc "${svc}_enable=NO" 2>/dev/null || warn "Could not disable $svc in rc.conf"
      service "$svc" stop 2>/dev/null || true
      ok "Disabled service: $svc"
    else
      warn "Service not found or not enabled: $svc"
    fi
  elif is_openbsd; then
    if command_exists rcctl; then
      rcctl disable "$svc" 2>/dev/null && ok "Disabled service: $svc" || warn "Failed to disable $svc"
      rcctl stop "$svc" 2>/dev/null || true
    else
      warn "rcctl not available"
    fi
  fi
}

backup_file() {
  local src="$1"
  local backup_dir="${2:-/root/backup}"
  local stamp dest

  if [[ ! -e "$src" ]]; then
    warn "Cannot backup missing file: $src"
    return 1
  fi

  mkdir -p "$backup_dir"
  stamp="$(date '+%F_%H%M%S')"
  dest="$backup_dir/$(basename "$src").$stamp.bak"
  cp -a "$src" "$dest"
  ok "Backup saved: $dest"
}

regex_escape() {
  printf '%s' "$1" | sed -e 's/[.[\\*^$()+?{}|]/\\&/g'
}

open_in_editor() {
  local target="$1"
  local editor="vi"
  if command_exists nano; then
    editor="nano"
  elif command_exists vim; then
    editor="vim"
  fi
  "$editor" "$target"
}

download_file() {
  local url="$1"
  local out="$2"
  if command_exists curl; then
    curl -fsSL "$url" -o "$out"
  elif command_exists fetch; then
    fetch -q -o "$out" "$url"
  elif command_exists wget; then
    wget -qO "$out" "$url"
  else
    warn "No download tool available (curl/fetch/wget) for: $url"
    return 1
  fi
}

sync_scripts_from_github() {
  section_header "Script Sync"
  info "Attempting to pull latest section scripts from GitHub placeholders."

  local fetched=0
  local pair
  for pair in \
    "bsd_section1_enumeration.sh|$BSD_SECTION1_URL" \
    "bsd_section2_initial_hardening.sh|$BSD_SECTION2_URL"; do
    local file url
    file="${pair%%|*}"
    url="${pair#*|}"

    if [[ "$url" == *"INSERT_ORG"* || "$url" == *"INSERT_REPO"* ]]; then
      warn "URL placeholder still set for $file. Skipping remote fetch."
      continue
    fi

    if download_file "$url" "$SCRIPT_DIR/$file"; then
      chmod +x "$SCRIPT_DIR/$file" 2>/dev/null || true
      ok "Synced $file from $url"
      fetched=1
    else
      warn "Failed to sync $file from $url"
    fi
  done

  if [[ "$fetched" -eq 0 ]]; then
    warn "No scripts fetched from GitHub. Using local copies."
  fi
}

run_section_script() {
  local script_name="$1"
  local script_path="$SCRIPT_DIR/$script_name"

  if [[ ! -f "$script_path" ]]; then
    error "Missing script: $script_path"
    return 1
  fi

  chmod +x "$script_path"
  "$script_path"
}

menu() {
  while true; do
    section_header "BSD Checklist Launcher (${BSD_TYPE})"
    printf '%s\n' "1) Section 1 - Enumeration"
    printf '%s\n' "2) Section 2 - Initial Hardening"
    printf '%s\n' "0) Exit"

    read -r -p "Choose an option: " choice

    case "$choice" in
      1) run_section_script "bsd_section1_enumeration.sh" ;;
      2) run_section_script "bsd_section2_initial_hardening.sh" ;;
      0)
        ok "Exiting launcher."
        exit 0
        ;;
      *)
        warn "Invalid option: $choice"
        ;;
    esac

    pause_step
  done
}

main() {
  require_root "$@"
  section_header "BSD Multi-Script Toolkit (${BSD_TYPE})"
  info "Detected BSD variant: $BSD_TYPE"
  sync_scripts_from_github
  pause_step
  menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
