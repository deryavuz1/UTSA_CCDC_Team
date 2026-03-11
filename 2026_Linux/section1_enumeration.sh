#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/main_launcher.sh"

require_root "$@"

TARGET_USER="${SUDO_USER:-root}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | awk -F: '{print $6}')"
TARGET_HOME="${TARGET_HOME:-/root}"
MOVE_KEY_BIN_FLAG="/root/.key_binary_move_prompt_done"
SUID_FILE="/root/suid_files.txt"
SGID_FILE="/root/sgid_files.txt"
SUID_UNEXPECTED_FILE="/root/suid_unexpected.txt"
SGID_UNEXPECTED_FILE="/root/sgid_unexpected.txt"
SUID_ALLOW_FILE="/root/suid_allowlist.txt"
SGID_ALLOW_FILE="/root/sgid_allowlist.txt"
SUID_SCAN_PID=""

find_integrity_runner() {
  if command_exists dpkg; then
    echo "debian"
  elif command_exists rpm; then
    echo "rpm"
  elif command_exists pacman; then
    echo "arch"
  elif command_exists apk; then
    echo "alpine"
  else
    echo "unknown"
  fi
}

start_integrity_check() {
  local mode
  mode="$(find_integrity_runner)"
  local output_file="/root/modified_files.txt"

  case "$mode" in
    debian)
      if ! command_exists debsums; then
        warn "debsums not found. Attempting install."
        install_packages debsums || {
          warn "debsums install failed. Skipping integrity check."
          return 1
        }
      fi
      nohup bash -c "debsums -ac > '$output_file' 2>&1" >/dev/null 2>&1 &
      ;;
    rpm)
      nohup bash -c "rpm -Va | grep -E '^[^ ]*[5MUG]' > '$output_file' 2>&1" >/dev/null 2>&1 &
      ;;
    arch)
      nohup bash -c "pacman -Qkk > '$output_file' 2>&1" >/dev/null 2>&1 &
      ;;
    alpine)
      nohup bash -c "apk verify > '$output_file' 2>&1" >/dev/null 2>&1 &
      ;;
    *)
      warn "No known package integrity check command for this distro."
      return 1
      ;;
  esac

  ok "File integrity check started in background. Output: $output_file (PID: $!)"
}

ensure_locate_tool() {
  if command_exists locate && command_exists updatedb; then
    return 0
  fi

  install_packages plocate || install_packages mlocate || {
    warn "Could not install plocate/mlocate."
    return 1
  }

  return 0
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

start_suid_guid_scan_bg() {
  cat >"$SUID_ALLOW_FILE" <<'ALLOWEOF'
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/fusermount3
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/su
/usr/bin/sudo
/usr/bin/umount
/usr/lib/openssh/ssh-keysign
ALLOWEOF

  cat >"$SGID_ALLOW_FILE" <<'ALLOWSGIDEOF'
/usr/bin/chage
/usr/bin/crontab
/usr/bin/expiry
/usr/bin/ssh-agent
/usr/bin/wall
/usr/bin/write.ul
/usr/lib/utempter/utempter
/usr/sbin/postdrop
/usr/sbin/postqueue
ALLOWSGIDEOF

  (
    find / -perm -4000 -type f 2>/dev/null | sort -u >"$SUID_FILE"
    find / -perm -2000 -type f 2>/dev/null | sort -u >"$SGID_FILE"
    grep -Fxv -f "$SUID_ALLOW_FILE" "$SUID_FILE" >"$SUID_UNEXPECTED_FILE" || true
    grep -Fxv -f "$SGID_ALLOW_FILE" "$SGID_FILE" >"$SGID_UNEXPECTED_FILE" || true
  ) &
  SUID_SCAN_PID="$!"

  ok "SUID/SGID scan started in background (PID: $SUID_SCAN_PID)"
}

show_suid_guid_results() {
  if [[ -n "$SUID_SCAN_PID" ]]; then
    if kill -0 "$SUID_SCAN_PID" 2>/dev/null; then
      info "Waiting for background SUID/SGID scan (PID: $SUID_SCAN_PID) to complete..."
    fi
    wait "$SUID_SCAN_PID" || warn "Background SUID/SGID scan reported an error."
  else
    warn "No background SUID/SGID scan PID recorded; showing any existing result files."
  fi

  show_output_source_header "FILE: $SUID_UNEXPECTED_FILE (unexpected SUID)"
  if [[ -s "$SUID_UNEXPECTED_FILE" ]]; then
    cat "$SUID_UNEXPECTED_FILE"
  else
    ok "No unexpected SUID entries based on current allowlist."
  fi
  pause_step

  show_output_source_header "FILE: $SGID_UNEXPECTED_FILE (unexpected SGID)"
  if [[ -s "$SGID_UNEXPECTED_FILE" ]]; then
    cat "$SGID_UNEXPECTED_FILE"
  else
    ok "No unexpected SGID entries based on current allowlist."
  fi
  pause_step

  info "If needed, remove dangerous SUID bits with: chmod u-x /path/to/exe"
}

section_header "Section 1 - Enumeration"

section_header "1) OS Version, Hostname, IP, Distribution"
show_command_with_pause "hostnamectl" hostnamectl
show_command_with_pause "uname -a" uname -a
show_file_with_pause "/etc/os-release"
if command_exists ip; then
  show_command_with_pause "ip addr" ip addr
elif command_exists ifconfig; then
  show_command_with_pause "ifconfig -a" ifconfig -a
else
  show_output_source_header "COMMAND: ip addr / ifconfig -a"
  warn "Neither ip nor ifconfig is available."
  pause_step
fi

section_header "2) Services and Ports"
show_command_with_pause "ss -tulnap / netstat -tulnap" list_listening_sockets
if command_exists lsof; then
  show_command_with_pause "lsof -i -n -P" lsof -i -n -P
else
  show_output_source_header "COMMAND: lsof -i -n -P"
  warn "lsof not installed"
  pause_step
fi
warn "TAKE A SCREENSHOT! Open ports and network services."
pause_step

section_header "3) DNS, LDAP, SSSD, Kerberos Checks"
show_file_with_pause "/etc/nsswitch.conf"
info "Check if ldap/sss entries exist in nsswitch sources."
if grep -Eq '(^|[[:space:]])sss([[:space:]]|$)' /etc/nsswitch.conf 2>/dev/null; then
  info "sss detected in nsswitch. Printing /etc/sssd/sssd.conf (if present)."
  if [[ -f /etc/sssd/sssd.conf ]]; then
    show_file_with_pause "/etc/sssd/sssd.conf"
  else
    show_output_source_header "FILE: /etc/sssd/sssd.conf"
    warn "/etc/sssd/sssd.conf not found"
    pause_step
  fi
fi
if command_exists realm; then
  show_command_with_pause "realm list" realm list
else
  show_output_source_header "COMMAND: realm list"
  warn "realm command not available"
  pause_step
fi
show_command_with_pause "systemctl status sssd winbind" systemctl --no-pager --full status sssd winbind
show_file_with_pause "/etc/hosts"
show_file_with_pause "/etc/resolv.conf"

section_header "4) Environment Variables and Bash Config"
show_command_with_pause "alias" alias
show_output_source_header "ENVIRONMENT: PATH"
echo "PATH=$PATH"
pause_step
if [[ -f "$TARGET_HOME/.bashrc" ]]; then
  show_file_with_pause "$TARGET_HOME/.bashrc"
else
  show_output_source_header "FILE: $TARGET_HOME/.bashrc"
  warn "No .bashrc found for $TARGET_USER at $TARGET_HOME"
  pause_step
fi
if [[ -f "$TARGET_HOME/.bash_history" ]]; then
  show_file_with_pause "$TARGET_HOME/.bash_history"
else
  show_output_source_header "FILE: $TARGET_HOME/.bash_history"
  warn "No .bash_history found for $TARGET_USER at $TARGET_HOME"
  pause_step
fi

section_header "5) Enumerate Users and Shell Access"
show_command_with_pause "getent passwd 0" getent passwd 0
show_output_source_header "FILE: /etc/passwd (false/nologin highlighted)"
if [[ -r /etc/passwd ]]; then
  awk '{
    line=$0
    gsub(/false/,"\033[1;31mfalse\033[0m",line)
    gsub(/nologin/,"\033[1;31mnologin\033[0m",line)
    print line
  }' /etc/passwd
else
  warn "Cannot read /etc/passwd"
fi
pause_step
show_output_source_header "COMMAND: getent group (root/sudo/wheel/docker highlighted)"
print_groups_highlighted || warn "Could not enumerate groups with getent"
if ! getent group | awk -F: '{print $1}' | grep -Eq '^(root|sudo|wheel|docker)$'; then
  warn "No root/sudo/wheel/docker groups found in getent output."
fi
pause_step
show_file_with_pause "/etc/shells"
info "Generally acceptable shells: dash, rbash, sh, bash."
pause_step

section_header "6) Check Sudo Permissions"
if [[ -d /etc/sudoers.d ]]; then
  show_output_source_header "DIRECTORY: /etc/sudoers.d"
  ls -la /etc/sudoers.d
  pause_step
  find /etc/sudoers.d -maxdepth 1 -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
    show_file_with_pause "$f"
  done
else
  show_output_source_header "DIRECTORY: /etc/sudoers.d"
  warn "/etc/sudoers.d is missing"
  pause_step
fi
if ask_yes_no "Open visudo now to inspect for unsafe directives (example: !authenticate)?" "N"; then
  if command_exists nano; then
    EDITOR=nano visudo
  else
    visudo
  fi
fi
if [[ -n "${SUDO_USER:-}" ]]; then
  show_command_with_pause "sudo -l -U $SUDO_USER" sudo -l -U "$SUDO_USER"
else
  show_command_with_pause "sudo -l" sudo -l
fi

section_header "7) Session/Authentication Context"
show_command_with_pause "w (who is logged in and active sessions)" w
show_shell_with_pause "lastb | head -n 40 (failed login attempts)" "lastb 2>/dev/null | head -n 40"
show_shell_with_pause "last -i | head -n 40 (recent successful logins with source IPs)" "last -i 2>/dev/null | head -n 40"
warn "TAKE A SCREENSHOT! w, lastb, and last -i output."
pause_step

section_header "8) Enabled Startup Services"
show_shell_with_pause "systemctl list-unit-files --type=service | grep enabled" "systemctl list-unit-files --type=service | grep enabled"

section_header "9) Running Processes"
show_command_with_pause "ps -efH" ps -efH

section_header "10) Cron Jobs"
show_output_source_header "COMMAND: crontab -l for all users in /etc/passwd"
while IFS=: read -r user _; do
  printf '\n=== crontab for %s ===\n' "$user"
  crontab -u "$user" -l 2>/dev/null || true
done </etc/passwd
pause_step

read -r -p "Enter a username to edit crontab now with 'crontab -eu <user>' (blank to skip): " cron_user
if [[ -n "$cron_user" ]]; then
  crontab -u "$cron_user" -e
fi
if compgen -G "/etc/cron.d/*" >/dev/null; then
  for cron_file in /etc/cron.d/*; do
    show_file_with_pause "$cron_file"
  done
else
  show_output_source_header "FILE GLOB: /etc/cron.d/*"
  warn "No files in /etc/cron.d/"
  pause_step
fi

section_header "11) Save Installed Programs"
if save_installed_packages /root/installed_apps.txt; then
  ok "Installed applications saved to /root/installed_apps.txt"
fi
pause_step

section_header "12) Start SUID/SGID Scan in Background"
start_suid_guid_scan_bg
info "Results will be shown near the end of Section 1."
pause_step

section_header "13) Validate File Integrity in Background"
start_integrity_check || true
pause_step

section_header "14) Install mlocate/plocate and Search for Password Artifacts"
section_header "14a) Install locate tooling and update database"
if ensure_locate_tool; then
  updatedb || warn "updatedb failed"
fi
pause_step

section_header "14b) Run locate search for 'password'"
if command_exists locate; then
  show_shell_with_pause "locate password | head -n 200" "locate password | head -n 200"
else
  show_output_source_header "COMMAND: locate password"
  warn "locate not available"
  pause_step
fi

section_header "14c) Run keyword grep search in sensitive paths"
read -r -p "Enter first password keyword to search for (blank to skip grep scan): " pw1
read -r -p "Enter second password keyword to search for (blank to skip grep scan): " pw2

if [[ -n "$pw1" && -n "$pw2" ]]; then
  pattern="$(regex_escape "$pw1")|$(regex_escape "$pw2")"
  show_output_source_header "COMMAND: find ... | grep password keywords"
  find /etc /opt /tmp /home /usr /var -type f -print0 2>/dev/null \
    | xargs -0 grep -IinH -E "$pattern" 2>/dev/null \
    | tee /root/password_pattern_hits.txt || true
  info "Password pattern hits saved to /root/password_pattern_hits.txt"
else
  warn "Skipping pattern grep because both keywords were not provided."
fi
pause_step

section_header "15) Find World-Writable Files and Directories"
show_output_source_header "COMMAND: find world-writable files"
find / -xdev -type f -perm -0002 -print 2>/dev/null | tee /root/world_writable_files.txt
pause_step
show_output_source_header "COMMAND: find world-writable directories without sticky bit"
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null | tee /root/world_writable_dirs_no_sticky.txt
pause_step

section_header "16) Check File Mounts"
show_file_with_pause "/etc/fstab"

section_header "17) Review /tmp and /opt Contents"
show_shell_with_pause "find /tmp /opt -mindepth 1 -maxdepth 2 -ls | head 300" "find /tmp /opt -mindepth 1 -maxdepth 2 -ls 2>/dev/null | sed -n '1,300p'"

section_header "18) Locate SSH Keys"
if command_exists locate; then
  show_shell_with_pause "locate authorized_keys" "locate authorized_keys"
  show_shell_with_pause "locate id_rsa" "locate id_rsa"
else
  show_output_source_header "COMMAND: locate authorized_keys / locate id_rsa"
  warn "locate not available"
  pause_step
fi

section_header "19) Review Background SUID/SGID Results"
show_suid_guid_results

section_header "20) Change Root Password"
if ask_yes_no "Run 'passwd root' now?" "Y"; then
  passwd root
else
  warn "Skipped root password change."
fi
pause_step

section_header "21) Add Root SSH Public Key"
read -r -p "Paste the public key to append to /root/.ssh/authorized_keys (blank to skip): " root_pubkey
if [[ -n "$root_pubkey" ]]; then
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh

  touch /root/.ssh/authorized_keys
  if command_exists lsattr && command_exists chattr; then
    if lsattr /root/.ssh/authorized_keys 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
      chattr -i /root/.ssh/authorized_keys || true
    fi
  fi

  if grep -Fxq "$root_pubkey" /root/.ssh/authorized_keys; then
    info "Key already exists in authorized_keys"
  else
    printf '%s\n' "$root_pubkey" >>/root/.ssh/authorized_keys
    ok "Key appended"
  fi

  chmod 600 /root/.ssh/authorized_keys
  if command_exists chattr; then
    chattr +i /root/.ssh/authorized_keys || warn "Could not set immutable bit on authorized_keys"
  fi
else
  warn "No key supplied. Skipping authorized_keys update."
fi
pause_step

section_header "22) Manual Validation Prompt"
info "Test SSH connectivity in a separate terminal now before continuing."
pause_step

section_header "23) Move Key Binaries (High-Risk)"
warn "Moving sudo/chattr can lock out normal administration paths."
if [[ -f "$MOVE_KEY_BIN_FLAG" ]]; then
  info "Move prompt has already been answered once on this host. Skipping."
elif ask_yes_no "Proceed with moving chattr and sudo binaries to /root/.wow_bin_*?" "N"; then
  chattr_path="$(command -v chattr || true)"
  sudo_path="$(command -v sudo || true)"

  if [[ -n "$chattr_path" && -x "$chattr_path" ]]; then
    mv "$chattr_path" /root/.wow_bin_c
    ok "Moved $chattr_path -> /root/.wow_bin_c"
  else
    warn "chattr binary not found"
  fi

  if [[ -n "$sudo_path" && -x "$sudo_path" ]]; then
    mv "$sudo_path" /root/.wow_bin_s
    ok "Moved $sudo_path -> /root/.wow_bin_s"
  else
    warn "sudo binary not found"
  fi
else
  info "Skipped moving sudo/chattr binaries."
fi
touch "$MOVE_KEY_BIN_FLAG"
pause_step

section_header "24) Cleanup Enumeration Artifacts from /root"
rm -f /root/suid_files.txt /root/sgid_files.txt /root/suid_unexpected.txt /root/sgid_unexpected.txt
rm -f /root/suid_allowlist.txt /root/sgid_allowlist.txt
rm -f /root/world_writable_files.txt /root/world_writable_dirs_no_sticky.txt
ok "Removed temporary SUID/SGID/world-writable output files from /root."
pause_step

ok "Section 1 complete."
