#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/bsd_main_launcher.sh"

require_root "$@"

MOVE_BIN_DIR="/root/.wow_bins"
PRIV_BIN_FLAG="/root/.priv_bin_move_done"
TOOL_BIN_FLAG="/root/.tool_bin_move_done"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

append_block_once() {
  local file="$1"
  local marker="$2"
  local content="$3"

  if grep -Fq "$marker" "$file" 2>/dev/null; then
    info "Block already present in $file: $marker"
    return 0
  fi
  printf '\n%s\n' "$content" >>"$file"
  ok "Appended block to $file"
}

# BSD-safe in-place sed: FreeBSD requires -i '' whereas OpenBSD accepts -i alone
sed_inplace() {
  if is_freebsd; then
    sed -i '' "$@"
  else
    sed -i "$@"
  fi
}

# Comment out all existing uncommented instances of an sshd_config keyword,
# then append the canonical setting. Works for 'Key Value' sshd format.
set_sshd_option() {
  local key="$1"
  local value="$2"
  local cfg="/etc/ssh/sshd_config"

  # Escape key for use in regex
  local ekey
  ekey="$(printf '%s' "$key" | sed 's/[.[\\*^$()+?{}|]/\\&/g')"

  # Comment out existing uncommented lines for this key
  sed_inplace -E "/^[[:space:]]*${ekey}[[:space:]]/s/^/#HARDEN: /" "$cfg"

  # Append canonical value
  printf '%s %s\n' "$key" "$value" >>"$cfg"
  info "Set sshd: $key $value"
}

# Write BSD sysctl.conf entry (key=value format, no spaces)
set_bsd_sysctl() {
  local cfg="$1"
  local key="$2"
  local value="$3"
  local ekey
  ekey="$(printf '%s' "$key" | sed 's/\./\\./g')"

  if grep -Eq "^[[:space:]]*${ekey}=" "$cfg" 2>/dev/null; then
    sed_inplace -E "s|^[[:space:]]*${ekey}=.*|${key}=${value}|" "$cfg"
  else
    printf '%s=%s\n' "$key" "$value" >>"$cfg"
  fi
}

apply_sysctl_hardening() {
  local cfg="/etc/sysctl.conf"
  [[ -f "$cfg" ]] || touch "$cfg"
  backup_file "$cfg" /root/backup || true

  info "Writing BSD sysctl hardening settings to $cfg and applying live..."

  # Settings common to both FreeBSD and OpenBSD
  local -a common_settings=(
    "net.inet.ip.forwarding=0"
    "net.inet.ip.redirect=0"
    "net.inet.ip.sourceroute=0"
    "net.inet.ip.accept_sourceroute=0"
    "net.inet.tcp.blackhole=2"
    "net.inet.udp.blackhole=1"
    "net.inet6.ip6.forwarding=0"
    "net.inet6.ip6.redirect=0"
  )

  local -a freebsd_settings=(
    "net.inet.icmp.drop_redirect=1"
    "net.inet.icmp.bmcastecho=0"
    "net.inet.tcp.log_in_vain=1"
    "net.inet.udp.log_in_vain=1"
    "security.bsd.see_other_uids=0"
    "security.bsd.see_other_gids=0"
    "security.bsd.unprivileged_proc_debug=0"
    "security.bsd.allow_ptrace=0"
    "security.bsd.unprivileged_read_msgbuf=0"
    "security.bsd.hardlink_check_uid=1"
    "security.bsd.hardlink_check_gid=1"
    "kern.coredump=0"
    "kern.sugid_coredump=0"
  )

  local -a openbsd_settings=(
    "net.inet.icmp.rediraccept=0"
    "ddb.panic=0"
  )

  local settings=()
  settings+=("${common_settings[@]}")
  if is_freebsd; then
    settings+=("${freebsd_settings[@]}")
  elif is_openbsd; then
    settings+=("${openbsd_settings[@]}")
  fi

  local key value cur
  for entry in "${settings[@]}"; do
    key="${entry%%=*}"
    value="${entry#*=}"
    set_bsd_sysctl "$cfg" "$key" "$value"
    cur="$(sysctl -n "${key}" 2>/dev/null || true)"
    if [[ "$cur" == "$value" ]]; then
      ok "Applied: ${key}=${value} (already set)"
    else
      sysctl "${key}=${value}" 2>/dev/null && ok "Applied: ${key}=${value}" \
        || warn "Live apply failed (may need reboot): ${key}=${value}"
    fi
  done

  # kern.securelevel: can only be raised, not lowered.
  # We write it to sysctl.conf for next boot ONLY — not applied live.
  if is_freebsd; then
    set_bsd_sysctl "$cfg" "kern.securelevel" "1"
    cur_sl="$(sysctl -n kern.securelevel 2>/dev/null || echo -1)"
    info "kern.securelevel=1 written to $cfg (current: $cur_sl — takes effect on next boot)"
    info "Skipping live apply to avoid blocking kernel module loads later in this session."
  elif is_openbsd; then
    cur_sl="$(sysctl -n kern.securelevel 2>/dev/null || echo 1)"
    info "OpenBSD kern.securelevel is currently $cur_sl (managed by kernel at boot)"
  fi

  ok "sysctl hardening complete. Settings persisted in $cfg."
}

restart_sshd() {
  if ! sshd -t 2>/dev/null; then
    warn "sshd -t config test FAILED. Not restarting to avoid lockout."
    warn "Fix /etc/ssh/sshd_config then restart manually."
    return 1
  fi

  if is_freebsd; then
    service sshd restart && ok "sshd restarted" || warn "sshd restart failed"
  elif is_openbsd; then
    rcctl restart sshd && ok "sshd restarted" || warn "sshd restart failed"
  fi
}

disable_service_prompted() {
  local svc="$1"
  if ask_yes_no "Disable service '$svc' now?" "Y"; then
    disable_service_if_present "$svc"
  fi
}

# FreeBSD: harden running jails and write/update jail.conf defaults
harden_jails() {
  local jail_conf="/etc/jail.conf"
  local ran=0

  # Write secure defaults block to jail.conf
  if [[ ! -f "$jail_conf" ]] || ! grep -q "# HARDEN_DEFAULTS" "$jail_conf" 2>/dev/null; then
    info "Writing hardened jail defaults to $jail_conf"
    backup_file "$jail_conf" /root/backup 2>/dev/null || true

    cat >>"$jail_conf" <<'JAILEOF'

# HARDEN_DEFAULTS - written by bsd_section2_initial_hardening.sh
# Applied to all jails unless overridden per-jail
defaults {
  # No raw sockets inside jail (no ping, no arp spoofing)
  allow.raw_sockets   = 0;
  # Prevent jail from modifying schg/sappnd immutable flags
  allow.chflags       = 0;
  # No mounting filesystems inside jail
  allow.mount         = 0;
  allow.mount.devfs   = 0;
  allow.mount.nullfs  = 0;
  allow.mount.procfs  = 0;
  allow.mount.fdescfs = 0;
  allow.mount.zfs     = 0;
  # No SysV IPC (prevents certain shared-memory escape paths)
  allow.sysvipc       = 0;
  # No mlock inside jail
  allow.mlock         = 0;
  # No nested jails (prevents escape via child jail creation)
  children.max        = 0;
  # Strictest statfs visibility (jail only sees its own mounts)
  enforce_statfs      = 2;
  # Raise securelevel inside jail
  securelevel         = 2;
  # Use the standard jail devfs ruleset (hides most devices)
  devfs_ruleset       = 4;
  # Standard rc lifecycle
  exec.start          = "/bin/sh /etc/rc";
  exec.stop           = "/bin/sh /etc/rc.shutdown jail";
  exec.clean;
  mount.devfs;
}
JAILEOF
    ok "Written hardened jail defaults to $jail_conf"
    warn "Defaults apply on next jail restart: jail -rc <jailname>"
  else
    info "Hardened jail defaults already present in $jail_conf"
  fi

  # Harden each running jail
  while IFS= read -r jid; do
    [[ "$jid" =~ ^[0-9]+$ ]] || continue
    ran=$((ran + 1))

    local jname jpath
    jname=$(jls -j "$jid" 2>/dev/null | awk 'NR==2{print $3}')
    jpath=$(jls -j "$jid" 2>/dev/null | awk 'NR==2{print $NF}')
    jname="${jname:-jail-$jid}"
    jpath="${jpath:-unknown}"

    section_header "  Hardening Jail: $jname (JID=$jid)"

    # Apply sysctl hardening inside jail (limited by what's permitted)
    local sysctl_inside=(
      "security.bsd.see_other_uids=0"
      "security.bsd.see_other_gids=0"
      "security.bsd.unprivileged_proc_debug=0"
      "security.bsd.allow_ptrace=0"
      "security.bsd.unprivileged_read_msgbuf=0"
      "net.inet.tcp.blackhole=2"
      "net.inet.udp.blackhole=1"
    )
    for kv in "${sysctl_inside[@]}"; do
      jexec "$jid" sysctl "$kv" >/dev/null 2>&1 && ok "[$jname] $kv" || \
        info "[$jname] $kv not settable (may be restricted by jail policy)"
    done

    # Write sysctl.conf inside jail for persistence
    if [[ -d "$jpath/etc" ]]; then
      local jcfg="$jpath/etc/sysctl.conf"
      [[ -f "$jcfg" ]] || touch "$jcfg"
      for kv in "${sysctl_inside[@]}"; do
        local k="${kv%%=*}" v="${kv#*=}"
        local ek
        ek="$(printf '%s' "$k" | sed 's/\./\\./g')"
        if grep -Eq "^[[:space:]]*${ek}=" "$jcfg" 2>/dev/null; then
          sed_inplace -E "s|^[[:space:]]*${ek}=.*|${k}=${v}|" "$jcfg"
        else
          printf '%s=%s\n' "$k" "$v" >>"$jcfg"
        fi
      done
      ok "[$jname] sysctl.conf updated in jail"
    fi

    # Harden SSH inside jail if present
    local jail_sshd_cfg="$jpath/etc/ssh/sshd_config"
    if [[ -f "$jail_sshd_cfg" ]] && ask_yes_no "Harden SSH config inside jail $jname?" "Y"; then
      backup_file "$jail_sshd_cfg" /root/backup || true
      sed_inplace -E "/^[[:space:]]*PermitRootLogin[[:space:]]/s/^/#HARDEN: /" "$jail_sshd_cfg"
      printf 'PermitRootLogin prohibit-password\n' >>"$jail_sshd_cfg"
      sed_inplace -E "/^[[:space:]]*PasswordAuthentication[[:space:]]/s/^/#HARDEN: /" "$jail_sshd_cfg"
      printf 'PasswordAuthentication no\n' >>"$jail_sshd_cfg"
      sed_inplace -E "/^[[:space:]]*X11Forwarding[[:space:]]/s/^/#HARDEN: /" "$jail_sshd_cfg"
      printf 'X11Forwarding no\n' >>"$jail_sshd_cfg"
      sed_inplace -E "/^[[:space:]]*AllowTcpForwarding[[:space:]]/s/^/#HARDEN: /" "$jail_sshd_cfg"
      printf 'AllowTcpForwarding no\n' >>"$jail_sshd_cfg"
      sed_inplace -E "/^[[:space:]]*PermitEmptyPasswords[[:space:]]/s/^/#HARDEN: /" "$jail_sshd_cfg"
      printf 'PermitEmptyPasswords no\n' >>"$jail_sshd_cfg"

      if jexec "$jid" sshd -t 2>/dev/null; then
        jexec "$jid" service sshd restart 2>/dev/null && ok "[$jname] sshd restarted" \
          || warn "[$jname] sshd restart failed"
      else
        warn "[$jname] sshd -t failed — fix manually inside jail $jid"
      fi
    fi

    warn "TAKE A SCREENSHOT! Jail $jname hardening applied."
  done < <(jls 2>/dev/null | awk 'NR>1 {print $1}')

  if [[ "$ran" -eq 0 ]]; then
    info "No running jails to harden (defaults written to $jail_conf for future jails)."
  fi
}

# ---------------------------------------------------------------------------
section_header "Section 2 - Initial Hardening (BSD: $BSD_TYPE)"
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
section_header "1) Move Privilege Escalation Binaries (sudo / doas)"
# ---------------------------------------------------------------------------

mkdir -p "$MOVE_BIN_DIR"
warn "Ensure SSH key login as root works before moving privilege escalation binaries."
warn "Once moved, only root with a direct session or SSH key can administer this system."

if [[ -f "$PRIV_BIN_FLAG" ]]; then
  info "Privilege escalation binary move already completed on this host. Skipping."
  info "Binaries are in: $MOVE_BIN_DIR"
else
  # sudo
  sudo_path="$(command -v sudo 2>/dev/null || true)"
  if [[ -n "$sudo_path" && -x "$sudo_path" ]]; then
    info "sudo found at: $sudo_path"
    if ask_yes_no "Move sudo to $MOVE_BIN_DIR/.wow_bin_s now?" "Y"; then
      mv "$sudo_path" "$MOVE_BIN_DIR/.wow_bin_s" && ok "Moved sudo -> $MOVE_BIN_DIR/.wow_bin_s" \
        || warn "Failed to move sudo"
    fi
  else
    info "sudo not found or already moved."
  fi

  # doas (native BSD privilege escalator)
  doas_path="$(command -v doas 2>/dev/null || true)"
  if [[ -n "$doas_path" && -x "$doas_path" ]]; then
    info "doas found at: $doas_path"
    if ask_yes_no "Move doas to $MOVE_BIN_DIR/.wow_bin_d now?" "Y"; then
      mv "$doas_path" "$MOVE_BIN_DIR/.wow_bin_d" && ok "Moved doas -> $MOVE_BIN_DIR/.wow_bin_d" \
        || warn "Failed to move doas"
    fi
  else
    info "doas not found or already moved."
  fi

  # FreeBSD: chflags is equivalent to chattr
  if is_freebsd; then
    chflags_path="$(command -v chflags 2>/dev/null || true)"
    if [[ -n "$chflags_path" && -x "$chflags_path" ]]; then
      info "chflags found at: $chflags_path"
      if ask_yes_no "Move chflags to $MOVE_BIN_DIR/.wow_bin_cf now?" "Y"; then
        mv "$chflags_path" "$MOVE_BIN_DIR/.wow_bin_cf" && ok "Moved chflags -> $MOVE_BIN_DIR/.wow_bin_cf" \
          || warn "Failed to move chflags"
      fi
    fi
  fi

  touch "$PRIV_BIN_FLAG"
fi
info "To restore: cp $MOVE_BIN_DIR/.wow_bin_s /usr/local/bin/sudo (etc.)"
pause_step

# ---------------------------------------------------------------------------
section_header "2) Move High-Risk Network and Compiler Binaries"
# ---------------------------------------------------------------------------

mkdir -p "$MOVE_BIN_DIR"

if [[ -f "$TOOL_BIN_FLAG" ]]; then
  info "Tool binary move already completed on this host. Skipping."
else
  warn "Moving these prevents attackers from using them as download/pivot tools."
  if ask_yes_no "Move high-risk tool binaries to $MOVE_BIN_DIR now?" "N"; then
    # BSD tools + common ports-installed tools
    risky_bins=(
      /usr/bin/nc /usr/bin/netcat
      /usr/bin/ftp /usr/bin/tftp
      /usr/bin/telnet
      /usr/bin/fetch
      /usr/local/bin/wget /usr/local/bin/curl
      /usr/local/bin/socat
      /usr/local/bin/nmap /usr/local/bin/ncat
      /usr/local/bin/gcc /usr/local/bin/cc /usr/bin/cc
      /usr/local/bin/make /usr/bin/make
      /usr/local/bin/perl /usr/bin/perl
      /usr/local/bin/python3 /usr/local/bin/python
      /usr/bin/crontab
      /usr/bin/at
    )

    for b in "${risky_bins[@]}"; do
      if [[ -f "$b" && -x "$b" ]]; then
        bname="$(basename "$b")"
        mv "$b" "$MOVE_BIN_DIR/${bname}" && ok "Moved $b -> $MOVE_BIN_DIR/${bname}"
      fi
    done

    # Keep curl available for root via PATH update
    if [[ ":$PATH:" != *":${MOVE_BIN_DIR}:"* ]]; then
      export PATH="$PATH:$MOVE_BIN_DIR"
      info "Added $MOVE_BIN_DIR to current PATH so moved tools remain available to root"
    fi

    touch "$TOOL_BIN_FLAG"
    ok "Tool binary move complete."
  else
    info "Skipped tool binary move."
  fi
fi
pause_step

# ---------------------------------------------------------------------------
section_header "3) Manage Groups and /etc/group"
# ---------------------------------------------------------------------------

show_output_source_header "COMMAND: /etc/group (wheel/operator highlighted)"
print_groups_highlighted
pause_step

if ask_yes_no "Open /etc/group in an editor now?" "N"; then
  open_in_editor /etc/group
fi
pause_step

# ---------------------------------------------------------------------------
section_header "4) Review /etc/passwd and Optional User Deletion"
# ---------------------------------------------------------------------------

show_file_with_pause "/etc/passwd"
if ask_yes_no "Delete any users now?" "N"; then
  while true; do
    read -r -p "Enter username to delete (blank to stop): " del_user
    [[ -z "$del_user" ]] && break

    if [[ "$del_user" == "root" || "$del_user" == "toor" ]]; then
      warn "Refusing to delete $del_user"
      continue
    fi

    if ! id "$del_user" >/dev/null 2>&1; then
      warn "User not found: $del_user"
      continue
    fi

    if is_freebsd && command_exists pw; then
      pw userdel -n "$del_user" -r && ok "Deleted user $del_user (home removed)" \
        || warn "pw userdel failed for $del_user"
    else
      # OpenBSD / fallback
      userdel -r "$del_user" 2>/dev/null && ok "Deleted user $del_user" \
        || warn "userdel failed for $del_user"
    fi
  done
fi
pause_step

# ---------------------------------------------------------------------------
section_header "5) Remove Unwanted Packages / Ports Review"
# ---------------------------------------------------------------------------

if [[ -f /root/installed_apps.txt ]]; then
  show_file_with_pause "/root/installed_apps.txt"
else
  warn "/root/installed_apps.txt not found. Run Section 1 first."
  pause_step
fi

# Highlight risky port/package categories that may be installed
section_header "5a) Risky Installed Packages (compilers, debuggers, sniffers)"
risky_pkgs=()
if is_freebsd && command_exists pkg; then
  # Check for specific risky packages by pattern
  while IFS= read -r line; do
    risky_pkgs+=("$line")
  done < <(pkg info 2>/dev/null | grep -Ei \
    'gcc|clang|llvm|nmap|wireshark|tcpdump|netcat|ncat|socat|metasploit|hydra|john|hashcat|aircrack|sqlmap|nikto|openvas|ettercap|bettercap|dsniff|masscan|zmap|theharvester|recon-ng|exploitdb|msfconsole|cobaltstrike|mimikatz|impacket|responder|burpsuite|beef-|set-|enum4linux|nbtscan|onesixtyone|snmpwalk|medusa|crowbar' \
    || true)
  if [[ ${#risky_pkgs[@]} -gt 0 ]]; then
    warn "Potentially risky packages detected:"
    printf '  %s\n' "${risky_pkgs[@]}"
  else
    ok "No obvious attacker-tool packages found."
  fi
  pause_step

  # Check for port work dirs (indicates ports were compiled recently)
  if [[ -d /usr/ports ]]; then
    work_dirs="$(find /usr/ports -maxdepth 3 -name work -type d 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$work_dirs" -gt 0 ]]; then
      warn "Found $work_dirs port build work/ dirs in /usr/ports — software may have been compiled from source:"
      find /usr/ports -maxdepth 3 -name work -type d 2>/dev/null | head -20
    else
      ok "No port work/ dirs found (no recent source builds)."
    fi
    pause_step
  fi

  # pkg audit
  show_output_source_header "COMMAND: pkg audit (known vulnerabilities)"
  pkg audit 2>/dev/null || warn "pkg audit found issues or vuln DB not fetched"
  pause_step

elif is_openbsd && command_exists pkg_info; then
  while IFS= read -r line; do
    risky_pkgs+=("$line")
  done < <(pkg_info 2>/dev/null | grep -Ei \
    'gcc|clang|nmap|wireshark|tcpdump|netcat|ncat|socat|hydra|john|hashcat|aircrack|sqlmap|nikto|ettercap|dsniff|masscan|metasploit' \
    || true)
  if [[ ${#risky_pkgs[@]} -gt 0 ]]; then
    warn "Potentially risky packages detected:"
    printf '  %s\n' "${risky_pkgs[@]}"
  else
    ok "No obvious attacker-tool packages found."
  fi
  pause_step

  if [[ -d /usr/ports ]]; then
    work_dirs="$(find /usr/ports -maxdepth 3 -name work -type d 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$work_dirs" -gt 0 ]]; then
      warn "Found $work_dirs port build work/ dirs in /usr/ports"
      find /usr/ports -maxdepth 3 -name work -type d 2>/dev/null | head -20
    else
      ok "No port work/ dirs found."
    fi
    pause_step
  fi
fi

read -r -p "Enter package names to remove (space-separated, blank to skip): " remove_line
if [[ -n "$remove_line" ]]; then
  # shellcheck disable=SC2206
  pkgs=($remove_line)
  if is_freebsd; then
    pkg delete -y "${pkgs[@]}" || warn "pkg delete reported errors"
  elif is_openbsd; then
    pkg_delete "${pkgs[@]}" || warn "pkg_delete reported errors"
  fi
fi
pause_step

# ---------------------------------------------------------------------------
section_header "6) Resource Limits (login.conf)"
# ---------------------------------------------------------------------------

show_file_with_pause "/etc/login.conf"

if ask_yes_no "Apply resource limits to /etc/login.conf (nproc/nofile/coredump)?" "Y"; then
  backup_file /etc/login.conf /root/backup || true

  append_block_once /etc/login.conf "# BEGIN CCDC SECURITY LIMITS" \
"# BEGIN CCDC SECURITY LIMITS
# Applied by bsd_section2_initial_hardening.sh
limited:\\
	:coredumpsize=0:\\
	:maxproc=256:\\
	:openfiles=512:\\
	:tc=default:
# END CCDC SECURITY LIMITS"

  # Set coredumpsize=0 in the default class if not already restricted
  if grep -q '^default:' /etc/login.conf 2>/dev/null; then
    if ! grep -A50 '^default:' /etc/login.conf | grep -q 'coredumpsize=0'; then
      info "Consider setting coredumpsize=0 in the default class manually."
    fi
  fi

  # Rebuild login.conf database (required after any change)
  if command_exists cap_mkdb; then
    cap_mkdb /etc/login.conf && ok "Rebuilt login.conf database (cap_mkdb)" \
      || warn "cap_mkdb failed — run manually: cap_mkdb /etc/login.conf"
  fi
fi
pause_step

# ---------------------------------------------------------------------------
section_header "7) Review File Integrity Output"
# ---------------------------------------------------------------------------

if [[ -f /root/modified_files.txt ]]; then
  show_output_source_header "FILE: /root/modified_files.txt (first 250 lines)"
  sed -n '1,250p' /root/modified_files.txt
  info "Review flagged files and remediate as needed."
  pause_step
else
  show_output_source_header "FILE: /root/modified_files.txt"
  warn "Not found yet (integrity scan from Section 1 may still be running)."
  pause_step
fi

# ---------------------------------------------------------------------------
section_header "8) Review Ports and Disable Unneeded Services"
# ---------------------------------------------------------------------------

show_command_with_pause "listening sockets" list_listening_sockets

if is_freebsd; then
  # Common services that may not be needed
  for svc in avahi-daemon cups rpcbind inetd sendmail; do
    # Check if enabled before prompting
    if sysrc -n "${svc}_enable" 2>/dev/null | grep -qi '^yes'; then
      disable_service_prompted "$svc"
    elif service "$svc" status >/dev/null 2>&1; then
      disable_service_prompted "$svc"
    fi
  done

  # smtpd check (mail may or may not be scored)
  if sysrc -n sendmail_enable 2>/dev/null | grep -qi 'YES\|yes'; then
    if ask_yes_no "sendmail appears enabled. Disable it? (NO if mail is scored)" "Y"; then
      sysrc sendmail_enable="NONE"
      service sendmail stop 2>/dev/null || true
      ok "sendmail disabled"
    fi
  fi

elif is_openbsd; then
  # OpenBSD smtpd check
  if rcctl check smtpd >/dev/null 2>&1; then
    if ask_yes_no "smtpd is running. Disable it? (NO if mail is scored)" "N"; then
      rcctl disable smtpd && rcctl stop smtpd && ok "smtpd disabled"
    fi
  fi
fi

read -r -p "Enter any additional service names to disable (space-separated, blank to skip): " extra_svcs
if [[ -n "$extra_svcs" ]]; then
  # shellcheck disable=SC2206
  svcs=($extra_svcs)
  for svc in "${svcs[@]}"; do
    disable_service_if_present "$svc"
  done
fi
pause_step

# ---------------------------------------------------------------------------
section_header "9) Kernel Security (sysctl Hardening)"
# ---------------------------------------------------------------------------

info "Applying BSD kernel security sysctl settings..."
apply_sysctl_hardening
pause_step

# ---------------------------------------------------------------------------
section_header "10) ZFS Dataset Hardening (FreeBSD only)"
# ---------------------------------------------------------------------------

if is_freebsd && command_exists zfs; then
  info "Reviewing ZFS dataset security properties (exec, setuid)..."

  show_output_source_header "COMMAND: zfs get exec,setuid,atime (current)"
  zfs get exec,setuid 2>/dev/null
  pause_step

  if ask_yes_no "Set exec=off on /tmp and /var/tmp ZFS datasets (recommended)?" "Y"; then
    # Find datasets mounted at /tmp and /var/tmp
    tmp_ds="$(zfs list -H -o name,mountpoint 2>/dev/null | awk '$2=="/tmp"{print $1}')"
    vartmp_ds="$(zfs list -H -o name,mountpoint 2>/dev/null | awk '$2=="/var/tmp"{print $1}')"

    if [[ -n "$tmp_ds" ]]; then
      zfs set exec=off "$tmp_ds" && ok "Set exec=off on $tmp_ds (/tmp)"
      zfs set setuid=off "$tmp_ds" && ok "Set setuid=off on $tmp_ds (/tmp)"
    else
      warn "No ZFS dataset found at /tmp"
    fi

    if [[ -n "$vartmp_ds" ]]; then
      zfs set exec=off "$vartmp_ds" && ok "Set exec=off on $vartmp_ds (/var/tmp)"
      zfs set setuid=off "$vartmp_ds" && ok "Set setuid=off on $vartmp_ds (/var/tmp)"
    else
      warn "No ZFS dataset found at /var/tmp"
    fi
  fi

  if ask_yes_no "Set setuid=off on /usr/ports (prevents SUID in ports tree)?" "Y"; then
    ports_ds="$(zfs list -H -o name,mountpoint 2>/dev/null | awk '$2=="/usr/ports"{print $1}')"
    if [[ -n "$ports_ds" ]]; then
      zfs set setuid=off "$ports_ds" && ok "Set setuid=off on $ports_ds (/usr/ports)"
    else
      warn "No ZFS dataset found at /usr/ports"
    fi
  fi

  show_output_source_header "COMMAND: zfs get exec,setuid (after hardening)"
  zfs get exec,setuid 2>/dev/null
  pause_step

else
  show_output_source_header "BSD ZFS HARDENING"
  if is_openbsd; then
    info "OpenBSD does not support ZFS. Skipping."
  else
    info "zfs command not found. Skipping ZFS hardening."
  fi
  pause_step
fi

# ---------------------------------------------------------------------------
section_header "11) Harden Temporary Mount Points"
# ---------------------------------------------------------------------------

show_command_with_pause "mount" mount

if is_freebsd; then
  info "On ZFS systems, mount options are set via 'zfs set' (Section 10)."
  info "Checking /etc/fstab for any non-ZFS /tmp or /var/tmp entries..."
  if grep -E '^[^#].*/tmp' /etc/fstab 2>/dev/null; then
    info "fstab /tmp entries found above. Review and add noexec,nosuid if needed."
  else
    info "No /tmp in fstab (likely ZFS-managed). Handled in Section 10."
  fi
  pause_step

elif is_openbsd; then
  # OpenBSD uses mount options via /etc/fstab
  show_file_with_pause "/etc/fstab"
  info "On OpenBSD, ensure /tmp is mounted with nosuid,nodev."
  info "Example: swap /tmp mfs rw,nodev,nosuid,-s=256m 0 0"
  pause_step
fi

# ---------------------------------------------------------------------------
section_header "12) FreeBSD Jail Hardening"
# ---------------------------------------------------------------------------

if is_freebsd; then
  if command_exists jls && jls 2>/dev/null | awk 'NR>1' | grep -q .; then
    info "Running jails detected. Applying hardening..."
  else
    info "No running jails detected. Writing secure defaults to jail.conf for future jails."
  fi

  if ask_yes_no "Apply jail hardening (jail.conf defaults + per-jail sysctl/SSH)?" "Y"; then
    harden_jails
  else
    info "Skipped jail hardening."
  fi
  pause_step
else
  show_output_source_header "BSD JAIL HARDENING"
  info "Jails are FreeBSD-specific. Skipping on $BSD_TYPE."
  pause_step
fi

# ---------------------------------------------------------------------------
section_header "13) Backup Password and Auth Files"
# ---------------------------------------------------------------------------

mkdir -p /root/backup
stamp="$(date '+%F_%H%M%S')"

if is_freebsd; then
  for f in /etc/passwd /etc/master.passwd /etc/group /etc/login.conf; do
    [[ -f "$f" ]] && cp -a "$f" "/root/backup/$(basename "$f").${stamp}.bak" \
      && ok "Backed up $f"
  done
elif is_openbsd; then
  for f in /etc/passwd /etc/master.passwd /etc/group /etc/login.conf; do
    [[ -f "$f" ]] && cp -a "$f" "/root/backup/$(basename "$f").${stamp}.bak" \
      && ok "Backed up $f"
  done
fi
ok "Auth file backups saved in /root/backup/"
pause_step

# ---------------------------------------------------------------------------
section_header "14) SSH Hardening"
# ---------------------------------------------------------------------------

sshd_cfg="/etc/ssh/sshd_config"

if [[ ! -f "$sshd_cfg" ]]; then
  warn "$sshd_cfg not found. Skipping SSH hardening."
  pause_step
else
  backup_file "$sshd_cfg" /root/backup || true

  show_output_source_header "COMMAND: current sshd_config (non-comment lines)"
  grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$sshd_cfg" || true
  pause_step

  ssh_scored="yes"
  if ask_yes_no "Is SSH a scored service? (YES = keep password auth; NO = key-only)" "Y"; then
    ssh_scored="yes"
  else
    ssh_scored="no"
  fi

  if ask_yes_no "Apply SSH hardening configuration now?" "Y"; then
    if [[ "$ssh_scored" == "yes" ]]; then
      pw_auth="yes"
      authmethod="any"
      info "Scored SSH: password authentication will remain enabled."
    else
      pw_auth="no"
      authmethod="publickey"
      info "Non-scored SSH: key-only authentication enforced."
    fi

    # Apply settings directly to sshd_config
    set_sshd_option "PermitRootLogin"              "prohibit-password"
    set_sshd_option "PubkeyAuthentication"         "yes"
    set_sshd_option "PasswordAuthentication"       "$pw_auth"
    set_sshd_option "KbdInteractiveAuthentication" "no"
    set_sshd_option "AuthenticationMethods"        "$authmethod"
    set_sshd_option "PermitEmptyPasswords"         "no"
    set_sshd_option "MaxAuthTries"                 "3"
    set_sshd_option "PermitUserEnvironment"        "no"
    set_sshd_option "AllowAgentForwarding"         "no"
    set_sshd_option "AllowTcpForwarding"           "no"
    set_sshd_option "GatewayPorts"                 "no"
    set_sshd_option "PermitTunnel"                 "no"
    set_sshd_option "X11Forwarding"                "no"
    set_sshd_option "IgnoreRhosts"                 "yes"
    set_sshd_option "MaxSessions"                  "2"
    set_sshd_option "TCPKeepAlive"                 "no"
    set_sshd_option "LoginGraceTime"               "30"

    # Validate and restart
    if sshd -t 2>/dev/null; then
      ok "sshd -t config test passed."
      warn "TAKE A SCREENSHOT! Test SSH login in another terminal BEFORE confirming."
      info "Test SSH connectivity in a separate terminal NOW before continuing."
      pause_step

      if ask_yes_no "Restart sshd to apply new config?" "Y"; then
        restart_sshd
      fi
    else
      warn "sshd -t FAILED. Showing errors:"
      sshd -t 2>&1 || true
      warn "NOT restarting sshd. Fix /etc/ssh/sshd_config manually."
    fi

    if [[ "$ssh_scored" == "yes" ]]; then
      info "SSH is scored: password auth kept enabled. Review checklist policy."
    fi
  fi
fi
pause_step

ok "Section 2 complete. (BSD: $BSD_TYPE)"
