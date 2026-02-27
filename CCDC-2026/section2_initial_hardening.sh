#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/main_launcher.sh"

require_root "$@"

append_block_once() {
  local file="$1"
  local marker="$2"
  local content="$3"

  if grep -Fq "$marker" "$file" 2>/dev/null; then
    info "Block already present in $file: $marker"
    return 0
  fi

  printf '\n%s\n' "$content" >>"$file"
  ok "Appended hardening block to $file"
}

add_fstab_entry_if_missing() {
  local mount_point="$1"
  local entry="$2"

  if awk '{print $2}' /etc/fstab | grep -qx "$mount_point"; then
    info "fstab already contains mount point: $mount_point"
  else
    printf '%s\n' "$entry" >>/etc/fstab
    ok "Added fstab entry for $mount_point"
  fi
}

disable_service_prompted() {
  local service="$1"
  if ask_yes_no "Disable service '$service' now?" "Y"; then
    disable_service_if_present "$service"
  fi
}

ensure_sshd_include_dir() {
  local cfg="/etc/ssh/sshd_config"
  if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$cfg"; then
    printf '\nInclude /etc/ssh/sshd_config.d/*.conf\n' >>"$cfg"
    ok "Added sshd Include directive for sshd_config.d"
  fi
}

write_sshd_hardening_file() {
  local password_auth="$1"
  local auth_methods="$2"
  local out="/etc/ssh/sshd_config.d/99-security-hardening.conf"

  mkdir -p /etc/ssh/sshd_config.d
  cat >"$out" <<EOF_CONF
# Managed by section2_initial_hardening.sh
Port 22
ListenAddress 0.0.0.0
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication ${password_auth}
KbdInteractiveAuthentication no
AuthenticationMethods ${auth_methods}
PermitEmptyPasswords no
MaxAuthTries 3
ChallengeResponseAuthentication no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
DisableForwarding yes
GatewayPorts no
PermitTunnel no
X11Forwarding no
IgnoreRhosts yes
MaxSessions 2
TCPKeepAlive no
EOF_CONF
  chmod 600 "$out"
  ok "Wrote SSH hardening drop-in: $out"
}

restart_ssh_service() {
  local svc
  local found=""
  for svc in sshd ssh; do
    if systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "${svc}.service"; then
      found="$svc"
      break
    fi
  done

  if [[ -z "$found" ]]; then
    warn "Could not detect ssh/sshd service name automatically."
    return 1
  fi

  if command_exists sshd && ! sshd -t; then
    warn "sshd -t failed. SSH config has syntax errors; service not restarted."
    return 1
  fi

  systemctl restart "$found" && ok "Restarted SSH service: $found" || warn "Failed to restart $found"
}

apply_sysctl_hardening() {
  local cfg="/etc/sysctl.conf"

  backup_file "$cfg" /root/backup || true

  while read -r key value; do
    [[ -z "$key" ]] && continue
    set_kv_conf "$cfg" "$key" "$value"
  done <<'EOF_SYSCTL'
kernel.exec-shield 2
kernel.randomize_va_space 2
kernel.sysrq 0
kernel.core_uses_pid 1
kernel.kptr_restrict 2
kernel.yama.ptrace_scope 3
kernel.dmesg_restrict 1
kernel.unprivileged_bpf_disabled 1
kernel.kexec_load_disabled 1
kernel.perf_event_paranoid 3
kernel.perf_cpu_time_max_percent 1
kernel.perf_event_max_sample_rate 1
dev.tty.ldisc_autoload 0
dev.tty.legacy_tiocsti 0
vm.swappiness 1
fs.suid_dumpable 0
fs.protected_hardlinks 1
fs.protected_symlinks 1
fs.protected_fifos 2
fs.protected_regular 2
net.core.bpf_jit_harden 2
net.ipv4.tcp_congestion_control bbr
net.core.default_qdisc fq_codel
net.ipv4.ip_forward 0
net.ipv4.tcp_syncookies 1
net.ipv4.tcp_synack_retries 5
net.ipv4.conf.default.send_redirects 0
net.ipv4.conf.all.send_redirects 0
net.ipv4.conf.default.accept_source_route 0
net.ipv4.conf.all.accept_source_route 0
net.ipv4.conf.default.rp_filter 1
net.ipv4.conf.all.rp_filter 1
net.ipv4.conf.default.log_martians 1
net.ipv4.conf.all.log_martians 1
net.ipv4.conf.default.accept_redirects 0
net.ipv4.conf.default.secure_redirects 0
net.ipv4.conf.all.accept_redirects 0
net.ipv4.conf.all.secure_redirects 0
net.ipv4.icmp_ignore_bogus_error_responses 1
net.ipv4.tcp_rfc1337 1
EOF_SYSCTL

  if sysctl -p "$cfg"; then
    ok "Applied sysctl settings."
  else
    warn "Some sysctl keys failed to apply (expected on some kernels). Review output above."
  fi
}

section_header "Section 2 - Initial Hardening"

section_header "1) Move High-Risk Binaries to /root/binaries"
mkdir -p /root/binaries
warn "This can break tooling and remote operations. Use only when strategy supports it."
if ask_yes_no "Move listed binaries into /root/binaries now?" "N"; then
  for b in \
    /usr/bin/wget /usr/bin/curl /usr/bin/scp /usr/bin/rsync /usr/bin/nc /usr/bin/socat \
    /usr/bin/ftp /usr/bin/tftp /usr/bin/telnet /usr/bin/nmap \
    /usr/bin/gcc /usr/bin/make /usr/bin/perl \
    /usr/bin/crontab /usr/bin/at; do
    if [[ -e "$b" ]]; then
      mv "$b" /root/binaries/ && ok "Moved $b"
    fi
  done
  if [[ ":$PATH:" != *":/root/binaries:"* ]]; then
    export PATH="$PATH:/root/binaries"
  fi
  ok "Updated current PATH to include /root/binaries"
else
  info "Skipped binary move step."
fi
pause_step

section_header "2) Manage Groups and /etc/group"
show_output_source_header "COMMAND: getent group (root/sudo/wheel/docker highlighted)"
print_groups_highlighted || warn "Could not enumerate groups with getent"
if ! getent group | awk -F: '{print $1}' | grep -Eq '^(root|sudo|wheel|docker)$'; then
  warn "No root/sudo/wheel/docker groups found in getent output."
fi
pause_step
if ask_yes_no "Open /etc/group in an editor now?" "N"; then
  open_in_editor /etc/group
fi
pause_step

section_header "3) Review /etc/passwd and Optional User Deletion"
show_file_with_pause "/etc/passwd"
if ask_yes_no "Delete any users now?" "N"; then
  while true; do
    read -r -p "Enter username to delete (blank to stop): " del_user
    [[ -z "$del_user" ]] && break

    if [[ "$del_user" == "root" ]]; then
      warn "Refusing to delete root"
      continue
    fi

    if ! id "$del_user" >/dev/null 2>&1; then
      warn "User not found: $del_user"
      continue
    fi

    if command_exists deluser; then
      deluser --remove-home "$del_user" && ok "Deleted user $del_user" || warn "Failed to delete $del_user"
    else
      userdel -r "$del_user" && ok "Deleted user $del_user" || warn "Failed to delete $del_user"
    fi
  done
fi
pause_step

section_header "4) Remove Unwanted Installed Programs"
if [[ -f /root/installed_apps.txt ]]; then
  section_header "4a) Review Full Installed Application List"
  show_output_source_header "FILE: /root/installed_apps.txt"
  if command_exists less; then
    less /root/installed_apps.txt
  else
    cat /root/installed_apps.txt
  fi
  pause_step
else
  warn "/root/installed_apps.txt not found. Run Section 1 first for package inventory."
fi

section_header "4b) Remove Selected Packages"
read -r -p "Enter package names to uninstall (space-separated, blank to skip): " remove_line
if [[ -n "$remove_line" ]]; then
  # shellcheck disable=SC2206
  pkgs=($remove_line)
  remove_packages "${pkgs[@]}" || warn "Package removal command reported errors"
fi
pause_step

section_header "5) Limit Process/File Descriptor Creation"
show_file_with_pause "/etc/security/limits.conf"
if ask_yes_no "Append recommended secure limits block to /etc/security/limits.conf?" "Y"; then
  append_block_once /etc/security/limits.conf "# BEGIN SECURITY LIMITS" "# BEGIN SECURITY LIMITS
*       soft    nproc   512
*       hard    nproc   1024
*       soft    nofile  8192
*       hard    nofile  16384
root    soft    nproc   512
root    hard    nproc   1024
root    soft    nofile  8192
root    hard    nofile  16384
# END SECURITY LIMITS"
fi
pause_step

section_header "6) Review Integrity Output"
if [[ -f /root/modified_files.txt ]]; then
  show_output_source_header "FILE: /root/modified_files.txt (first 250 lines)"
  sed -n '1,250p' /root/modified_files.txt
  info "Review flagged files in another terminal and remediate as needed."
  pause_step
else
  show_output_source_header "FILE: /root/modified_files.txt"
  warn "/root/modified_files.txt not found yet (integrity scan may still be running)."
  pause_step
fi

section_header "7) Review Ports and Disable Unneeded Services"
show_command_with_pause "ss -tulnap / netstat -tulnap" list_listening_sockets
disable_service_if_present avahi-daemon
disable_service_if_present cups

if ask_yes_no "Disable rpcbind? (Answer NO if NFS/port 2049 is required)" "N"; then
  disable_service_if_present rpcbind
fi

read -r -p "Enter extra services to disable (space-separated, blank to skip): " extra_svcs
if [[ -n "$extra_svcs" ]]; then
  # shellcheck disable=SC2206
  services=($extra_svcs)
  for svc in "${services[@]}"; do
    disable_service_if_present "$svc"
  done
fi
pause_step

section_header "8) Kernel Security (sysctl)"
apply_sysctl_hardening
pause_step

section_header "9) Harden /tmp, /var/tmp, /dev/shm in fstab"
show_file_with_pause "/etc/fstab"
if ask_yes_no "Add tmpfs noexec/nodev/nosuid entries if missing?" "Y"; then
  add_fstab_entry_if_missing "/tmp" "tmpfs  /tmp      tmpfs  defaults,nodev,nosuid,noexec  0  0"
  add_fstab_entry_if_missing "/var/tmp" "tmpfs  /var/tmp  tmpfs  defaults,nodev,nosuid,noexec  0  0"
  add_fstab_entry_if_missing "/dev/shm" "tmpfs  /dev/shm  tmpfs  defaults,nodev,nosuid,noexec  0  0"
  mount -a || warn "mount -a reported errors"
  systemctl daemon-reload || true
fi
pause_step

section_header "10) Backup Users and Password Files"
mkdir -p /root/backup
cp -a /etc/passwd /root/backup/passwd.bak
cp -a /etc/shadow /root/backup/shadow.bak
cp -a /etc/group /root/backup/group.bak
ok "Backups saved in /root/backup"
pause_step

section_header "11) Update SSH Configuration"
if [[ ! -f /etc/ssh/sshd_config ]]; then
  warn "/etc/ssh/sshd_config not found; skipping SSH hardening step."
else
  backup_file /etc/ssh/sshd_config /root/backup || true

  if ask_yes_no "Is SSH a scored service? (recommended default: yes)" "Y"; then
    ssh_scored="yes"
  else
    ssh_scored="no"
  fi

  show_shell_with_pause "grep non-comment lines from /etc/ssh/sshd_config" "grep -Ev '^[[:space:]]*#|^[[:space:]]*$' /etc/ssh/sshd_config || true"

  if ask_yes_no "Apply SSH hardening configuration now?" "Y"; then
    password_auth="no"
    auth_methods="publickey"

    if [[ "$ssh_scored" == "yes" ]]; then
      password_auth="yes"
      auth_methods="any"
    fi

    ensure_sshd_include_dir
    write_sshd_hardening_file "$password_auth" "$auth_methods"

    if restart_ssh_service; then
      ok "SSH hardening applied."
    else
      warn "SSH service restart failed. Validate settings before disconnecting."
    fi

    info "If SSH is scored, review checklist-specific policy before disabling password auth globally."
  fi
fi
pause_step

ok "Section 2 complete."
