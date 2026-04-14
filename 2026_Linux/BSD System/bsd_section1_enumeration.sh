#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/bsd_main_launcher.sh"

require_root "$@"

TARGET_USER="${SUDO_USER:-root}"
TARGET_HOME="$(getent_compat passwd "$TARGET_USER" 2>/dev/null | awk -F: '{print $6}' | head -1)"
TARGET_HOME="${TARGET_HOME:-/root}"
MOVE_KEY_BIN_FLAG="/root/.key_binary_move_prompt_done"
SUID_FILE="/root/suid_files.txt"
SGID_FILE="/root/sgid_files.txt"
SUID_UNEXPECTED_FILE="/root/suid_unexpected.txt"
SGID_UNEXPECTED_FILE="/root/sgid_unexpected.txt"
SUID_ALLOW_FILE="/root/suid_allowlist.txt"
SGID_ALLOW_FILE="/root/sgid_allowlist.txt"
SUID_SCAN_PID=""

# ---------------------------------------------------------------------------
# Background SUID/SGID scan
# ---------------------------------------------------------------------------

start_suid_guid_scan_bg() {
  if is_freebsd; then
    cat >"$SUID_ALLOW_FILE" <<'ALLOWEOF'
/sbin/mksnap_ffs
/sbin/ping
/sbin/ping6
/sbin/poweroff
/sbin/shutdown
/usr/bin/at
/usr/bin/atq
/usr/bin/atrm
/usr/bin/batch
/usr/bin/chpass
/usr/bin/crontab
/usr/bin/lock
/usr/bin/login
/usr/bin/lpq
/usr/bin/lpr
/usr/bin/lprm
/usr/bin/newgrp
/usr/bin/opiepasswd
/usr/bin/passwd
/usr/bin/quota
/usr/bin/rlogin
/usr/bin/rsh
/usr/bin/su
/usr/libexec/dma-mbox-create
/usr/libexec/ssh-keysign
/usr/libexec/ulog-helper
/usr/sbin/authpf
/usr/sbin/authpf-noip
/usr/sbin/ppp
/usr/sbin/traceroute
/usr/sbin/traceroute6
ALLOWEOF

    cat >"$SGID_ALLOW_FILE" <<'ALLOWSGIDEOF'
/usr/bin/btsockstat
/usr/bin/lpq
/usr/bin/lpr
/usr/bin/lprm
/usr/bin/wall
/usr/bin/write
/usr/libexec/dma
/usr/libexec/sendmail/sendmail
/usr/sbin/authpf
/usr/sbin/authpf-noip
/usr/sbin/lpc
ALLOWSGIDEOF

  else
    # OpenBSD standard SUID allowlist
    cat >"$SUID_ALLOW_FILE" <<'ALLOWEOF'
/sbin/ping
/sbin/ping6
/sbin/shutdown
/usr/bin/chfn
/usr/bin/chpass
/usr/bin/chsh
/usr/bin/doas
/usr/bin/lpr
/usr/bin/lprm
/usr/bin/passwd
/usr/bin/su
/usr/libexec/auth/login_chpass
/usr/libexec/auth/login_lchpass
/usr/libexec/auth/login_passwd
/usr/libexec/lockspool
/usr/libexec/ssh-keysign
/usr/sbin/authpf
/usr/sbin/authpf-noip
/usr/sbin/pppd
/usr/sbin/traceroute
/usr/sbin/traceroute6
ALLOWEOF

    # OpenBSD standard SGID allowlist
    cat >"$SGID_ALLOW_FILE" <<'ALLOWSGIDEOF'
/usr/bin/at
/usr/bin/atq
/usr/bin/atrm
/usr/bin/batch
/usr/bin/crontab
/usr/bin/lock
/usr/bin/lpq
/usr/bin/lpr
/usr/bin/lprm
/usr/bin/skeyaudit
/usr/bin/skeyinfo
/usr/bin/skeyinit
/usr/bin/ssh-agent
/usr/bin/wall
/usr/bin/write
/usr/libexec/auth/login_activ
/usr/libexec/auth/login_crypto
/usr/libexec/auth/login_radius
/usr/libexec/auth/login_skey
/usr/libexec/auth/login_snk
/usr/libexec/auth/login_token
/usr/libexec/auth/login_yubikey
/usr/sbin/authpf
/usr/sbin/authpf-noip
/usr/sbin/lpc
/usr/sbin/lpd
/usr/sbin/smtpctl
ALLOWSGIDEOF
  fi

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

  info "Remove dangerous SUID bits with: chmod u-s /path/to/exe"
  info "Remove immutable BSD flags with: chflags noschg /path/to/exe"
}

# ---------------------------------------------------------------------------
# File integrity check
# ---------------------------------------------------------------------------

start_integrity_check() {
  local output_file="/root/modified_files.txt"

  if is_freebsd && command_exists pkg; then
    nohup bash -c "pkg check -s 2>&1 | grep -v 'Checking' > '$output_file'" >/dev/null 2>&1 &
    ok "File integrity check (pkg check -s) started in background. Output: $output_file (PID: $!)"
  elif is_openbsd && command_exists pkg_check; then
    nohup bash -c "pkg_check 2>&1 > '$output_file'" >/dev/null 2>&1 &
    ok "File integrity check (pkg_check) started in background. Output: $output_file (PID: $!)"
  else
    warn "No known pkg integrity check command for this BSD variant."
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Locate tooling
# ---------------------------------------------------------------------------

ensure_locate_tool() {
  if command_exists locate && command_exists locate.updatedb 2>/dev/null; then
    return 0
  elif command_exists locate; then
    return 0
  fi

  warn "locate not found. Attempting install."
  if is_freebsd; then
    install_packages findutils 2>/dev/null || true
  fi

  command_exists locate || { warn "Could not install locate."; return 1; }
}

# ---------------------------------------------------------------------------
# Section 1 - Enumeration
# ---------------------------------------------------------------------------

section_header "Section 1 - Enumeration (BSD: $BSD_TYPE)"

# ---------------------------------------------------------------------------
section_header "1) OS Version, Hostname, IP, Distribution"
# ---------------------------------------------------------------------------

show_command_with_pause "hostname" hostname
show_command_with_pause "uname -a" uname -a

if is_freebsd && command_exists freebsd-version; then
  show_command_with_pause "freebsd-version -ku" freebsd-version -ku
fi

if [[ -f /etc/os-release ]]; then
  show_file_with_pause "/etc/os-release"
else
  show_output_source_header "COMMAND: sysctl kern version"
  sysctl kern.ostype kern.osrelease kern.version 2>/dev/null || warn "sysctl kern version failed"
  pause_step
fi

show_command_with_pause "ifconfig -a" ifconfig -a

show_output_source_header "COMMAND: netstat -rn (routing table)"
netstat -rn || warn "netstat -rn failed"
pause_step

# ---------------------------------------------------------------------------
section_header "2) Services and Ports"
# ---------------------------------------------------------------------------

show_command_with_pause "sockstat -l / netstat listening" list_listening_sockets
warn "TAKE A SCREENSHOT! Open ports and network services."
pause_step

if is_freebsd; then
  show_output_source_header "COMMAND: sockstat -4 -6 (all connections)"
  sockstat 2>/dev/null || warn "sockstat failed"
  pause_step
fi

if command_exists lsof; then
  show_command_with_pause "lsof -i -n -P" lsof -i -n -P
else
  show_output_source_header "COMMAND: lsof -i -n -P"
  warn "lsof not installed"
  pause_step
fi

# ---------------------------------------------------------------------------
section_header "3) DNS, NIS, Kerberos Checks"
# ---------------------------------------------------------------------------

if is_freebsd && [[ -f /etc/nsswitch.conf ]]; then
  show_file_with_pause "/etc/nsswitch.conf"
  info "Check if nis/compat/ldap entries exist in nsswitch sources."

  if grep -Eq '(^|[[:space:]])(nis|compat)([[:space:]]|$)' /etc/nsswitch.conf 2>/dev/null; then
    warn "NIS/compat detected in nsswitch.conf. Checking NIS status."
    show_output_source_header "COMMAND: ypwhich (NIS master)"
    timeout 5 ypwhich 2>/dev/null || warn "ypwhich failed, timed out, or NIS not running"
    pause_step

    show_output_source_header "COMMAND: ypcat passwd (NIS users)"
    timeout 5 ypcat passwd 2>/dev/null | head -30 || warn "ypcat passwd failed, timed out, or NIS not active"
    pause_step
  fi
elif is_openbsd; then
  info "OpenBSD does not use nsswitch.conf; name resolution via resolv.conf and /etc/hosts."
  # Check if YP (NIS) is actively configured on OpenBSD
  # /var/yp exists in base but only has Makefiles; active YP has a domain subdir or /etc/yp.conf
  YP_ACTIVE=0
  [[ -f /etc/yp.conf ]] && YP_ACTIVE=1
  # Active YP server has a domainname directory under /var/yp (not just Makefiles)
  [[ -d /var/yp ]] && find /var/yp -mindepth 1 -maxdepth 1 -type d 2>/dev/null | grep -q . && YP_ACTIVE=1
  if [[ "$YP_ACTIVE" -eq 1 ]]; then
    warn "YP/NIS config detected. Checking ypbind."
    show_output_source_header "COMMAND: rcctl check ypbind (NIS client)"
    rcctl check ypbind 2>/dev/null || warn "ypbind not running"
    pause_step
    show_output_source_header "COMMAND: ypwhich"
    timeout 5 ypwhich 2>/dev/null || warn "ypwhich failed, timed out, or YP not active"
    pause_step
  else
    info "No YP/NIS configuration found (/etc/yp.conf, /var/yp)."
    pause_step
  fi
fi

if [[ -f /etc/krb5.conf ]]; then
  show_file_with_pause "/etc/krb5.conf"
fi

show_file_with_pause "/etc/hosts"
show_file_with_pause "/etc/resolv.conf"

# ---------------------------------------------------------------------------
section_header "4) Environment Variables and Shell Config"
# ---------------------------------------------------------------------------

show_command_with_pause "alias" alias
show_output_source_header "ENVIRONMENT: PATH"
echo "PATH=$PATH"
pause_step

# Check shell config files for the target user
for rcfile in "$TARGET_HOME/.bashrc" "$TARGET_HOME/.profile" "$TARGET_HOME/.cshrc" "$TARGET_HOME/.tcshrc"; do
  if [[ -f "$rcfile" ]]; then
    show_file_with_pause "$rcfile"
  fi
done

# Shell history
for histfile in "$TARGET_HOME/.bash_history" "$TARGET_HOME/.sh_history" "$TARGET_HOME/.history"; do
  if [[ -f "$histfile" ]]; then
    show_file_with_pause "$histfile"
  fi
done

# ---------------------------------------------------------------------------
section_header "5) Enumerate Users and Shell Access"
# ---------------------------------------------------------------------------

show_output_source_header "COMMAND: id 0 / root UID check"
id 0 2>/dev/null || getent_compat passwd 0 2>/dev/null || grep -E ':0:' /etc/passwd
pause_step

show_output_source_header "FILE: /etc/passwd (nologin highlighted)"
if [[ -r /etc/passwd ]]; then
  awk '{
    line=$0
    gsub(/nologin/,"\033[1;31mnologin\033[0m",line)
    gsub(/\/bin\/false/,"\033[1;31m\/bin\/false\033[0m",line)
    print line
  }' /etc/passwd
else
  warn "Cannot read /etc/passwd"
fi
pause_step

# Show UID 0 accounts specifically
show_output_source_header "COMMAND: UID 0 accounts"
awk -F: '$3 == 0 { print }' /etc/passwd
pause_step

show_output_source_header "COMMAND: /etc/group (wheel/operator highlighted)"
print_groups_highlighted
pause_step

# Show wheel members explicitly
show_output_source_header "COMMAND: wheel group members"
grep -E "^wheel:" /etc/group || warn "wheel group not found"
pause_step

if is_freebsd && command_exists pw; then
  show_output_source_header "COMMAND: pw usershow -a (all users)"
  pw usershow -a 2>/dev/null || warn "pw usershow failed"
  pause_step
fi

show_file_with_pause "/etc/shells"
info "Generally acceptable shells: sh, csh, tcsh, bash. Review git-shell if present."
pause_step

# ---------------------------------------------------------------------------
section_header "6) Check Sudo and Doas Permissions"
# ---------------------------------------------------------------------------

# Check sudo
SUDO_CONF=""
for p in /usr/local/etc/sudoers /etc/sudoers; do
  if [[ -f "$p" ]]; then
    SUDO_CONF="$p"
    break
  fi
done

if [[ -n "$SUDO_CONF" ]]; then
  show_output_source_header "FILE: $SUDO_CONF"
  cat "$SUDO_CONF" || warn "Cannot read $SUDO_CONF"
  pause_step
else
  show_output_source_header "FILE: sudoers"
  warn "No sudoers file found at /usr/local/etc/sudoers or /etc/sudoers"
  pause_step
fi

for sudoers_d in /usr/local/etc/sudoers.d /etc/sudoers.d; do
  if [[ -d "$sudoers_d" ]]; then
    show_output_source_header "DIRECTORY: $sudoers_d"
    ls -la "$sudoers_d"
    pause_step
    find "$sudoers_d" -maxdepth 1 -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
      show_file_with_pause "$f"
    done
  fi
done

if command_exists visudo; then
  if ask_yes_no "Open visudo now to inspect for unsafe directives?" "N"; then
    if command_exists nano; then
      EDITOR=nano visudo
    else
      visudo
    fi
  fi
fi

if command_exists sudo; then
  if [[ -n "${SUDO_USER:-}" ]]; then
    show_command_with_pause "sudo -l -U $SUDO_USER" sudo -l -U "$SUDO_USER"
  else
    show_command_with_pause "sudo -l" sudo -l
  fi
fi

# Check doas (OpenBSD native, also available on FreeBSD as port)
for doas_conf in /etc/doas.conf /usr/local/etc/doas.conf; do
  if [[ -f "$doas_conf" ]]; then
    show_file_with_pause "$doas_conf"
  fi
done

if ! [[ -f /etc/doas.conf || -f /usr/local/etc/doas.conf ]]; then
  show_output_source_header "FILE: doas.conf"
  info "No doas.conf found (doas not configured)."
  pause_step
fi

# ---------------------------------------------------------------------------
section_header "7) Session/Authentication Context"
# ---------------------------------------------------------------------------

show_command_with_pause "w (who is logged in)" w
show_command_with_pause "last | head -40 (recent logins)" bash -c "last | head -40"

# Failed logins: FreeBSD uses /var/log/failedlogin
show_output_source_header "COMMAND: last -f /var/log/failedlogin (failed logins)"
if [[ -f /var/log/failedlogin ]]; then
  last -f /var/log/failedlogin 2>/dev/null | head -40 || warn "Could not read failedlogin"
else
  info "/var/log/failedlogin not present (created on first failed login attempt)"
fi
pause_step

warn "TAKE A SCREENSHOT! w, last, and failed login output."
pause_step

# ---------------------------------------------------------------------------
section_header "8) Enabled Startup Services"
# ---------------------------------------------------------------------------

if is_freebsd; then
  show_output_source_header "COMMAND: service -e (enabled services)"
  service -e 2>/dev/null || warn "service -e failed"
  pause_step

  show_output_source_header "COMMAND: sysrc -a (rc.conf settings)"
  sysrc -a 2>/dev/null || warn "sysrc -a failed"
  pause_step

  show_file_with_pause "/etc/rc.conf"

  if [[ -d /etc/rc.conf.d ]]; then
    show_output_source_header "DIRECTORY: /etc/rc.conf.d"
    ls -la /etc/rc.conf.d
    pause_step
    for f in /etc/rc.conf.d/*; do
      [[ -f "$f" ]] && show_file_with_pause "$f"
    done
  fi

  if [[ -f /usr/local/etc/rc.conf ]]; then
    show_file_with_pause "/usr/local/etc/rc.conf"
  fi

  if [[ -d /usr/local/etc/rc.d ]]; then
    show_output_source_header "DIRECTORY: /usr/local/etc/rc.d (third-party services)"
    ls -la /usr/local/etc/rc.d
    pause_step
  fi

elif is_openbsd; then
  if command_exists rcctl; then
    show_command_with_pause "rcctl ls started" rcctl ls started
    show_command_with_pause "rcctl ls on" rcctl ls on
  fi
  show_file_with_pause "/etc/rc.conf.local"
fi

# Boot loader config
if is_freebsd; then
  show_file_with_pause "/boot/loader.conf"
elif is_openbsd; then
  show_file_with_pause "/etc/boot.conf"
fi

# ---------------------------------------------------------------------------
section_header "9) Running Processes"
# ---------------------------------------------------------------------------

if is_freebsd; then
  show_command_with_pause "ps -auxwwH" ps -auxwwH
else
  show_command_with_pause "ps -aux" ps -aux
fi

# ---------------------------------------------------------------------------
section_header "10) Cron Jobs and Periodic Tasks"
# ---------------------------------------------------------------------------

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

# FreeBSD crontab spool location
if [[ -d /var/cron/tabs ]]; then
  show_output_source_header "DIRECTORY: /var/cron/tabs"
  ls -la /var/cron/tabs
  pause_step
  for cron_tab in /var/cron/tabs/*; do
    [[ -f "$cron_tab" ]] && show_file_with_pause "$cron_tab"
  done
fi

if [[ -f /etc/crontab ]]; then
  show_file_with_pause "/etc/crontab"
fi

# Third-party cron.d
for cron_d in /usr/local/etc/cron.d /etc/cron.d; do
  if [[ -d "$cron_d" ]]; then
    show_output_source_header "DIRECTORY: $cron_d"
    ls -la "$cron_d"
    pause_step
    for cron_file in "$cron_d"/*; do
      [[ -f "$cron_file" ]] && show_file_with_pause "$cron_file"
    done
  fi
done

# FreeBSD periodic tasks (run by cron via /etc/crontab)
if [[ -d /etc/periodic ]]; then
  show_output_source_header "DIRECTORY: /etc/periodic (scheduled maintenance scripts)"
  find /etc/periodic -type f | sort
  pause_step
fi

if [[ -f /etc/periodic.conf ]]; then
  show_file_with_pause "/etc/periodic.conf"
fi

# ---------------------------------------------------------------------------
section_header "11) Save Installed Programs"
# ---------------------------------------------------------------------------

if save_installed_packages /root/installed_apps.txt; then
  ok "Installed applications saved to /root/installed_apps.txt"
fi
pause_step

# ---------------------------------------------------------------------------
section_header "11b) Ports Tree and Third-Party Software Enumeration"
# ---------------------------------------------------------------------------

if is_freebsd; then
  # Ports tree presence
  if [[ -d /usr/ports ]]; then
    show_output_source_header "DIRECTORY: /usr/ports (top-level)"
    ls /usr/ports 2>/dev/null | head -20
    pause_step

    # Recently touched port work dirs (built in last 30 days)
    show_output_source_header "COMMAND: recently built port work dirs (find /usr/ports -name work -newer ...)"
    find /usr/ports -maxdepth 3 -name work -type d -newer /usr/ports/Makefile 2>/dev/null | head -30 \
      || info "No recently-built port work dirs found."
    pause_step
  else
    info "Ports tree not installed at /usr/ports."
    pause_step
  fi

  # Security audit of installed packages
  if command_exists pkg; then
    show_output_source_header "COMMAND: pkg audit -F (vulnerability check)"
    pkg audit -F 2>/dev/null || warn "pkg audit failed or found vulnerabilities — see above"
    pause_step

    show_output_source_header "COMMAND: pkg version -v (outdated packages)"
    pkg version -v 2>/dev/null | grep -v "^=\|up-to-date" | head -50 \
      || info "All packages up to date (or index not fetched yet)."
    pause_step

    show_output_source_header "COMMAND: pkg query (manually installed packages)"
    pkg query -e '%a = 0' '%n-%v (%o)' 2>/dev/null | head -80 \
      || info "Could not query manually installed packages."
    pause_step
  fi

  # Third-party service scripts from ports
  if [[ -d /usr/local/etc/rc.d ]]; then
    show_output_source_header "DIRECTORY: /usr/local/etc/rc.d (ports-installed services)"
    ls -la /usr/local/etc/rc.d 2>/dev/null
    pause_step
  fi

  # Check /usr/local/sbin and /usr/local/bin for notable binaries
  show_output_source_header "COMMAND: ls /usr/local/bin /usr/local/sbin (installed port binaries)"
  ls /usr/local/bin /usr/local/sbin 2>/dev/null
  pause_step

elif is_openbsd; then
  # OpenBSD ports build into packages; pkg_info covers all
  show_output_source_header "COMMAND: pkg_info (all installed packages)"
  pkg_info 2>/dev/null || warn "pkg_info failed"
  pause_step

  # Manually installed (not auto-installed as dependency)
  show_output_source_header "COMMAND: pkg_info -m (manually installed)"
  pkg_info -m 2>/dev/null || warn "pkg_info -m failed"
  pause_step

  if [[ -d /usr/ports ]]; then
    show_output_source_header "DIRECTORY: /usr/ports (ports tree present)"
    ls /usr/ports 2>/dev/null | head -20
    pause_step
  else
    info "No ports tree at /usr/ports (normal for installed-only systems)."
    pause_step
  fi

  # Third-party service scripts
  if [[ -d /usr/local/etc/rc.d ]]; then
    show_output_source_header "DIRECTORY: /usr/local/etc/rc.d (ports-installed services)"
    ls -la /usr/local/etc/rc.d 2>/dev/null
    pause_step
  fi

  show_output_source_header "COMMAND: ls /usr/local/bin /usr/local/sbin"
  ls /usr/local/bin /usr/local/sbin 2>/dev/null
  pause_step
fi

# ---------------------------------------------------------------------------
section_header "12) Start SUID/SGID Scan in Background"
# ---------------------------------------------------------------------------

start_suid_guid_scan_bg
info "Results will be shown near the end of Section 1."
pause_step

# ---------------------------------------------------------------------------
section_header "13) Validate File Integrity in Background"
# ---------------------------------------------------------------------------

start_integrity_check || true
pause_step

# ---------------------------------------------------------------------------
section_header "14) Install locate and Search for Password Artifacts"
# ---------------------------------------------------------------------------

section_header "14a) locate database update"
if command_exists locate; then
  if [[ -x /usr/libexec/locate.updatedb ]]; then
    /usr/libexec/locate.updatedb 2>/dev/null && ok "locate database updated" || warn "locate.updatedb failed"
  elif command_exists updatedb; then
    updatedb || warn "updatedb failed"
  else
    warn "No updatedb found; locate database may be stale"
  fi
else
  warn "locate not installed"
fi
pause_step

section_header "14b) Run locate search for 'password'"
if command_exists locate; then
  show_shell_with_pause "locate password | head -n 200" "locate password 2>/dev/null | head -n 200"
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
  find /etc /usr/local/etc /opt /tmp /home /usr /var -type f -print0 2>/dev/null \
    | xargs -0 grep -IilH -E "$pattern" 2>/dev/null \
    | tee /root/password_pattern_hits.txt || true
  info "Password pattern file hits saved to /root/password_pattern_hits.txt"
else
  warn "Skipping pattern grep because both keywords were not provided."
fi
pause_step

# ---------------------------------------------------------------------------
section_header "15) Find World-Writable Files and Directories"
# ---------------------------------------------------------------------------

show_output_source_header "COMMAND: find world-writable files"
find / -xdev -type f -perm -0002 -print 2>/dev/null | tee /root/world_writable_files.txt
pause_step

show_output_source_header "COMMAND: find world-writable directories without sticky bit"
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null | tee /root/world_writable_dirs_no_sticky.txt
pause_step

# ---------------------------------------------------------------------------
section_header "16) Check File Mounts and ZFS"
# ---------------------------------------------------------------------------

show_file_with_pause "/etc/fstab"
show_command_with_pause "mount" mount
show_command_with_pause "df -h" df -h

if command_exists zfs; then
  show_output_source_header "COMMAND: zpool list"
  zpool list 2>/dev/null || warn "zpool list failed (no ZFS pools?)"
  pause_step

  show_output_source_header "COMMAND: zpool status"
  zpool status 2>/dev/null || warn "zpool status failed"
  pause_step

  show_output_source_header "COMMAND: zfs list"
  zfs list 2>/dev/null || warn "zfs list failed"
  pause_step

  show_output_source_header "COMMAND: zfs list -t snapshot"
  zfs list -t snapshot 2>/dev/null || info "No ZFS snapshots found"
  pause_step

  show_output_source_header "COMMAND: zfs get all (security-relevant properties)"
  zfs get exec,setuid,encryption 2>/dev/null || warn "zfs get properties failed"
  pause_step
fi

# ---------------------------------------------------------------------------
section_header "17) Review /tmp and /opt Contents"
# ---------------------------------------------------------------------------

show_shell_with_pause "find /tmp /opt -mindepth 1 -maxdepth 2 -ls | head 300" \
  "find /tmp /opt -mindepth 1 -maxdepth 2 -ls 2>/dev/null | head -300"

# ---------------------------------------------------------------------------
section_header "18) Locate SSH Keys"
# ---------------------------------------------------------------------------

if command_exists locate; then
  show_shell_with_pause "locate authorized_keys" "locate authorized_keys 2>/dev/null"
  show_shell_with_pause "locate id_rsa / id_ecdsa / id_ed25519" \
    "locate id_rsa 2>/dev/null; locate id_ecdsa 2>/dev/null; locate id_ed25519 2>/dev/null"
else
  show_output_source_header "COMMAND: find SSH keys"
  find /root /home /etc/ssh -name "authorized_keys" -o -name "id_rsa" \
    -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
  pause_step
fi

show_file_with_pause "/etc/ssh/sshd_config"

show_output_source_header "COMMAND: find SSH host keys"
ls -la /etc/ssh/ssh_host_* 2>/dev/null || warn "No SSH host keys found"
pause_step

# ---------------------------------------------------------------------------
section_header "19) FreeBSD Jails Enumeration"
# ---------------------------------------------------------------------------

if is_freebsd; then
  show_output_source_header "COMMAND: jls -v (running jails)"
  if command_exists jls; then
    jls -v 2>/dev/null || warn "jls failed"
  else
    warn "jls not found"
  fi
  pause_step

  # Jail configuration files
  if [[ -f /etc/jail.conf ]]; then
    show_file_with_pause "/etc/jail.conf"
  else
    show_output_source_header "FILE: /etc/jail.conf"
    info "No /etc/jail.conf found (jails may use jail.conf.d or rc.conf)"
    pause_step
  fi

  if [[ -d /etc/jail.conf.d ]]; then
    show_output_source_header "DIRECTORY: /etc/jail.conf.d"
    ls -la /etc/jail.conf.d
    pause_step
    for jconf in /etc/jail.conf.d/*; do
      [[ -f "$jconf" ]] && show_file_with_pause "$jconf"
    done
  fi

  # rc.conf jail settings
  show_output_source_header "COMMAND: sysrc -a | grep jail"
  sysrc -a 2>/dev/null | grep -i jail || info "No jail entries in rc.conf"
  pause_step

  # Enumerate each running jail
  # jls basic output: JID  IP Address  Hostname  Path
  JAIL_COUNT=0
  if command_exists jls; then
    while IFS= read -r jid; do
      [[ "$jid" =~ ^[0-9]+$ ]] || continue
      JAIL_COUNT=$((JAIL_COUNT + 1))
      jname=$(jls -j "$jid" 2>/dev/null | awk 'NR==2{print $3}')
      jpath=$(jls -j "$jid" 2>/dev/null | awk 'NR==2{print $NF}')
      jname="${jname:-jail-$jid}"
      jpath="${jpath:-unknown}"

      section_header "  Jail: $jname (JID=$jid) at $jpath"

      show_output_source_header "JAIL $jname: hostname"
      jexec "$jid" hostname 2>/dev/null || warn "jexec $jid hostname failed"
      pause_step

      show_output_source_header "JAIL $jname: ifconfig -a"
      jexec "$jid" ifconfig -a 2>/dev/null || warn "jexec $jid ifconfig failed"
      pause_step

      show_output_source_header "JAIL $jname: /etc/passwd"
      if [[ -r "$jpath/etc/passwd" ]]; then
        awk '{
          line=$0
          gsub(/nologin/,"\033[1;31mnologin\033[0m",line)
          print line
        }' "$jpath/etc/passwd"
      else
        warn "Cannot read $jpath/etc/passwd"
      fi
      pause_step

      show_output_source_header "JAIL $jname: listening sockets (sockstat -l)"
      jexec "$jid" sockstat -l 2>/dev/null || warn "sockstat in jail $jid failed"
      pause_step

      show_output_source_header "JAIL $jname: ps aux"
      jexec "$jid" ps aux 2>/dev/null || warn "ps aux in jail $jid failed"
      pause_step

      show_output_source_header "JAIL $jname: enabled services (service -e)"
      jexec "$jid" service -e 2>/dev/null || warn "service -e in jail $jid failed"
      pause_step

      show_output_source_header "JAIL $jname: /etc/rc.conf"
      if [[ -r "$jpath/etc/rc.conf" ]]; then
        cat "$jpath/etc/rc.conf"
      else
        warn "No rc.conf in jail at $jpath/etc/rc.conf"
      fi
      pause_step

      show_output_source_header "JAIL $jname: installed packages"
      jexec "$jid" pkg info 2>/dev/null | head -40 || warn "pkg info in jail $jid failed"
      pause_step

      show_output_source_header "JAIL $jname: crontabs"
      if [[ -d "$jpath/var/cron/tabs" ]]; then
        ls -la "$jpath/var/cron/tabs" && cat "$jpath/var/cron/tabs"/* 2>/dev/null
      else
        info "No cron tabs directory in jail $jpath"
      fi
      pause_step

      warn "TAKE A SCREENSHOT! Jail $jname ($jid) enumeration complete."

    done < <(jls 2>/dev/null | awk 'NR>1 {print $1}')
  fi

  if [[ "$JAIL_COUNT" -eq 0 ]]; then
    info "No running jails found."
    pause_step
  else
    ok "$JAIL_COUNT jail(s) enumerated."
    pause_step
  fi

  warn "TAKE A SCREENSHOT! Jails enumeration complete."
  pause_step

else
  show_output_source_header "BSD JAILS"
  info "Jails are a FreeBSD-specific feature. Skipping on $BSD_TYPE."
  pause_step
fi

# ---------------------------------------------------------------------------
section_header "20) PF Firewall Status"
# ---------------------------------------------------------------------------

show_output_source_header "COMMAND: pfctl -s info"
if command_exists pfctl; then
  pfctl -s info 2>/dev/null || info "PF not enabled or not running"
  pause_step

  if pfctl -s info 2>/dev/null | grep -q "^Status: Enabled"; then
    show_output_source_header "COMMAND: pfctl -s rules"
    pfctl -s rules 2>/dev/null || warn "pfctl -s rules failed"
    pause_step

    # pfctl -s nat is FreeBSD-specific; OpenBSD does NAT via pass/binat/rdr rules
    if is_freebsd; then
      show_output_source_header "COMMAND: pfctl -s nat"
      pfctl -s nat 2>/dev/null || warn "pfctl -s nat failed"
      pause_step
    fi

    # OpenBSD uses capital 'Tables', FreeBSD accepts lowercase
    show_output_source_header "COMMAND: pfctl -s Tables"
    pfctl -s Tables 2>/dev/null || info "No PF tables defined"
    pause_step
  fi

  if [[ -f /etc/pf.conf ]]; then
    show_file_with_pause "/etc/pf.conf"
  else
    info "No /etc/pf.conf found"
    pause_step
  fi
else
  warn "pfctl not available"
  pause_step
fi

# ---------------------------------------------------------------------------
section_header "21) Kernel Security Sysctl"
# ---------------------------------------------------------------------------

if is_freebsd; then
  show_output_source_header "COMMAND: sysctl security.bsd"
  sysctl security.bsd 2>/dev/null || warn "sysctl security.bsd failed"
  pause_step

  show_output_source_header "COMMAND: sysctl net.inet (key network settings)"
  sysctl net.inet.ip.forwarding net.inet.ip.redirect \
         net.inet.ip.accept_sourceroute net.inet.ip.sourceroute \
         net.inet.tcp.blackhole net.inet.udp.blackhole 2>/dev/null || true
  pause_step

  show_output_source_header "COMMAND: sysctl kern.securelevel"
  sysctl kern.securelevel 2>/dev/null || warn "kern.securelevel unavailable"
  pause_step

  show_output_source_header "COMMAND: sysctl kern.randompid"
  sysctl kern.randompid 2>/dev/null || true
  pause_step

elif is_openbsd; then
  show_output_source_header "COMMAND: sysctl kern.securelevel"
  sysctl kern.securelevel 2>/dev/null || warn "kern.securelevel unavailable"
  pause_step

  show_output_source_header "COMMAND: sysctl net.inet (key network settings)"
  sysctl net.inet.ip.forwarding net.inet.ip.redirect \
         net.inet.ip.sourceroute net.inet.ip.accept_sourceroute 2>/dev/null || true
  pause_step

  show_output_source_header "COMMAND: sysctl ddb.panic (kernel debugger on panic)"
  sysctl ddb.panic 2>/dev/null || true
  pause_step
fi

# ---------------------------------------------------------------------------
section_header "22) Review Background SUID/SGID Results"
# ---------------------------------------------------------------------------

show_suid_guid_results

# ---------------------------------------------------------------------------
section_header "23) Change Root Password"
# ---------------------------------------------------------------------------

if ask_yes_no "Run 'passwd root' now?" "Y"; then
  passwd root
else
  warn "Skipped root password change."
fi
pause_step

# ---------------------------------------------------------------------------
section_header "24) Add Root SSH Public Key"
# ---------------------------------------------------------------------------

read -r -p "Paste the public key to append to /root/.ssh/authorized_keys (blank to skip): " root_pubkey
if [[ -n "$root_pubkey" ]]; then
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh

  touch /root/.ssh/authorized_keys

  # Clear immutable BSD flag if set
  if command_exists chflags; then
    chflags noschg /root/.ssh/authorized_keys 2>/dev/null || true
  fi

  if grep -Fxq "$root_pubkey" /root/.ssh/authorized_keys; then
    info "Key already exists in authorized_keys"
  else
    printf '%s\n' "$root_pubkey" >>/root/.ssh/authorized_keys
    ok "Key appended"
  fi

  chmod 600 /root/.ssh/authorized_keys

  # Set immutable flag (BSD equivalent of chattr +i)
  if command_exists chflags; then
    chflags schg /root/.ssh/authorized_keys && ok "Set schg (immutable) flag on authorized_keys" \
      || warn "Could not set immutable flag on authorized_keys"
  fi
else
  warn "No key supplied. Skipping authorized_keys update."
fi
pause_step

# ---------------------------------------------------------------------------
section_header "25) Manual Validation Prompt"
# ---------------------------------------------------------------------------

info "Test SSH connectivity in a separate terminal now before continuing."
pause_step

# ---------------------------------------------------------------------------
section_header "26) Move Key Binaries (High-Risk)"
# ---------------------------------------------------------------------------

warn "Moving sudo can lock out normal administration paths."
if [[ -f "$MOVE_KEY_BIN_FLAG" ]]; then
  info "Move prompt has already been answered once on this host. Skipping."
elif ask_yes_no "Proceed with moving sudo binary to /root/.wow_bin_s?" "N"; then
  sudo_path="$(command -v sudo || true)"

  if [[ -n "$sudo_path" && -x "$sudo_path" ]]; then
    mv "$sudo_path" /root/.wow_bin_s
    ok "Moved $sudo_path -> /root/.wow_bin_s"
  else
    warn "sudo binary not found"
  fi
else
  info "Skipped moving sudo binary."
fi
touch "$MOVE_KEY_BIN_FLAG"
pause_step

# ---------------------------------------------------------------------------
section_header "27) Cleanup Enumeration Artifacts from /root"
# ---------------------------------------------------------------------------

rm -f /root/suid_files.txt /root/sgid_files.txt /root/suid_unexpected.txt /root/sgid_unexpected.txt
rm -f /root/suid_allowlist.txt /root/sgid_allowlist.txt
rm -f /root/world_writable_files.txt /root/world_writable_dirs_no_sticky.txt
ok "Removed temporary SUID/SGID/world-writable output files from /root."
pause_step

ok "Section 1 complete. (BSD: $BSD_TYPE)"
