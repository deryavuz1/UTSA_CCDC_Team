#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HARDEN_LOG_FILE="${HARDEN_LOG_FILE:-/root/linux_hardening.log}"

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

# Placeholder links. Override with environment variables before running.
BASE="https://raw.githubusercontent.com/SouthwestCCDC/2026-Regionals-Shared/main/The%20University%20of%20Texas%20at%20San%20Antonio/2026_Linux"

SECTION1_URL="${SECTION1_URL:-$BASE/section1_enumeration.sh}"
SECTION2_URL="${SECTION2_URL:-$BASE/section2_initial_hardening.sh}"
SECTION3_URL="${SECTION3_URL:-$BASE/section3_password_changes.sh}"
SECTION4_URL="${SECTION4_URL:-$BASE/section4_setup_logging.sh}"
SECTION5_URL="${SECTION5_URL:-$BASE/section5_setup_rsyslog.sh}"
AUDIT_RULES_URL="${AUDIT_RULES_URL:-$BASE/audit.rules}"
export SECTION1_URL SECTION2_URL SECTION3_URL SECTION4_URL SECTION5_URL AUDIT_RULES_URL

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
    info "Root privileges are required. Re-running with sudo."
    exec sudo -E bash "$0" "$@"
  fi
}

detect_pkg_manager() {
  local pm
  for pm in apt-get dnf yum zypper pacman apk; do
    if command_exists "$pm"; then
      printf '%s\n' "$pm"
      return 0
    fi
  done
  return 1
}

install_packages() {
  local pm
  pm="$(detect_pkg_manager || true)"

  if [[ -z "$pm" ]]; then
    warn "No supported package manager found. Install manually: $*"
    return 1
  fi

  case "$pm" in
    apt-get)
      DEBIAN_FRONTEND=noninteractive apt-get update -y || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
      ;;
    dnf) dnf install -y "$@" ;;
    yum) yum install -y "$@" ;;
    zypper) zypper --non-interactive install "$@" ;;
    pacman) pacman --noconfirm -Sy "$@" ;;
    apk) apk add "$@" ;;
    *)
      warn "Unsupported package manager: $pm"
      return 1
      ;;
  esac
}

remove_packages() {
  local pm
  pm="$(detect_pkg_manager || true)"

  if [[ -z "$pm" ]]; then
    warn "No supported package manager found. Remove manually: $*"
    return 1
  fi

  case "$pm" in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get purge -y "$@" ;;
    dnf) dnf remove -y "$@" ;;
    yum) yum remove -y "$@" ;;
    zypper) zypper --non-interactive remove "$@" ;;
    pacman) pacman --noconfirm -Rns "$@" ;;
    apk) apk del "$@" ;;
    *)
      warn "Unsupported package manager: $pm"
      return 1
      ;;
  esac
}

backup_file() {
  local src="$1"
  local backup_dir="${2:-/root/backup}"
  local stamp
  local dest

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

set_kv_conf() {
  local file="$1"
  local key="$2"
  local value="$3"
  local escaped_key

  escaped_key="$(regex_escape "$key")"

  if grep -Eq "^[[:space:]]*${escaped_key}[[:space:]]*=" "$file"; then
    sed -ri "s|^[[:space:]]*${escaped_key}[[:space:]]*=.*|${key} = ${value}|" "$file"
  else
    printf '%s = %s\n' "$key" "$value" >>"$file"
  fi
}

save_installed_packages() {
  local output_file="$1"
  local pm

  pm="$(detect_pkg_manager || true)"
  if [[ -z "$pm" ]]; then
    warn "Unable to determine package manager; cannot auto-export installed packages."
    return 1
  fi

  case "$pm" in
    apt-get)
      dpkg -l >"$output_file"
      ;;
    dnf|yum|zypper)
      if command_exists rpm; then
        rpm -qa >"$output_file"
      else
        warn "rpm not found; cannot export package list for $pm"
        return 1
      fi
      ;;
    pacman)
      pacman -Q >"$output_file"
      ;;
    apk)
      apk info -vv >"$output_file"
      ;;
    *)
      warn "Unsupported package manager: $pm"
      return 1
      ;;
  esac

  ok "Installed package list saved to $output_file"
}

list_listening_sockets() {
  if command_exists ss; then
    ss -tulnap
  elif command_exists netstat; then
    netstat -tulnap
  else
    warn "Neither ss nor netstat is available."
    return 1
  fi
}

open_in_editor() {
  local target="$1"
  local editor

  editor="vi"
  if command_exists nano; then
    editor="nano"
  elif command_exists vim; then
    editor="vim"
  fi

  "$editor" "$target"
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

  getent group | awk -F: -v hi="$hi" -v reset="$reset" '{
    if ($1=="root" || $1=="sudo" || $1=="wheel" || $1=="docker") {
      print hi $0 reset
    } else {
      print $0
    }
  }'
}

disable_service_if_present() {
  local svc="$1"
  if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "${svc}.service"; then
    systemctl disable --now "$svc" || warn "Failed to disable $svc"
    ok "Disabled service: $svc"
  else
    warn "Service not found: $svc"
  fi
}

download_file() {
  local url="$1"
  local out="$2"

  if command_exists curl; then
    curl -fsSL "$url" -o "$out"
  elif command_exists wget; then
    wget -qO "$out" "$url"
  else
    warn "Neither curl nor wget is available for download: $url"
    return 1
  fi
}

sync_scripts_from_github() {
  section_header "Script Sync"
  info "Attempting to pull latest section scripts from GitHub placeholders."

  local fetched=0
  local pair
  for pair in \
    "section1_enumeration.sh|$SECTION1_URL" \
    "section2_initial_hardening.sh|$SECTION2_URL" \
    "section3_password_changes.sh|$SECTION3_URL" \
    "section4_setup_logging.sh|$SECTION4_URL" \
    "section5_setup_rsyslog.sh|$SECTION5_URL" \
    "audit.rules|$AUDIT_RULES_URL"; do
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
    warn "No scripts or audit rules were fetched from GitHub. Using local copies."
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
    section_header "Linux Checklist Launcher"
    printf '%s\n' "1) Section 1 - Enumeration"
    printf '%s\n' "2) Section 2 - Initial Hardening"
    printf '%s\n' "3) Section 3 - Password Changes"
    printf '%s\n' "4) Section 4 - Setup Logging"
    printf '%s\n' "5) Section 5 - Setup Rsyslog"
    printf '%s\n' "6) Run All Sections"
    printf '%s\n' "0) Exit"

    read -r -p "Choose an option: " choice

    case "$choice" in
      1) run_section_script "section1_enumeration.sh" ;;
      2) run_section_script "section2_initial_hardening.sh" ;;
      3) run_section_script "section3_password_changes.sh" ;;
      4) run_section_script "section4_setup_logging.sh" ;;
      5) run_section_script "section5_setup_rsyslog.sh" ;;
      6)
        run_section_script "section1_enumeration.sh"
        run_section_script "section2_initial_hardening.sh"
        run_section_script "section3_password_changes.sh"
        run_section_script "section4_setup_logging.sh"
        run_section_script "section5_setup_rsyslog.sh"
        ;;
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
  section_header "Linux Multi-Script Toolkit"
  info "This launcher enforces sudo and can optionally sync sections from GitHub URLs."
  sync_scripts_from_github
  pause_step
  menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
