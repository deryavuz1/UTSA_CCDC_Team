#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/main_launcher.sh"

require_root "$@"

# Override these URLs with environment variables as needed.
PSPY_URL="${PSPY_URL:-https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64}"

install_audit_packages() {
  local pm
  pm="$(detect_pkg_manager || true)"

  case "$pm" in
    apt-get)
      install_packages auditd audispd-plugins
      ;;
    dnf|yum)
      install_packages audit audispd-plugins
      ;;
    zypper)
      install_packages audit audit-audispd-plugins || install_packages audit
      ;;
    pacman)
      install_packages audit
      ;;
    apk)
      install_packages audit
      ;;
    *)
      warn "Unsupported package manager for automatic auditd install."
      return 1
      ;;
  esac
}

write_pspy_exclude() {
  cat >/root/pspy.exclude <<'EOF_EXCLUDE'
/usr/lib/
/usr/share/
/usr/src/
/usr/local/lib/
/usr/lib/x86_64-linux-gnu
/etc/ssl/
/etc/gai.conf
/etc/gss/
/etc/nsswitch.conf
/etc/locale.alias
/etc/pam.d/
/etc/ssh/ssh_host
/etc/security/
/etc/ld.so.cache
/etc/bash_completion.d/
/etc/protocols
/etc/update-motd.d/
/etc/lsb-release
/usr/bin/lsb_release
/etc/machine-id
/var/log/
/var/lib/
/root/pspy.log
/root/.lesshst
EOF_EXCLUDE
  chmod 600 /root/pspy.exclude
  ok "Created /root/pspy.exclude"
}

write_pspy_service() {
  cat >/etc/systemd/system/pspy.service <<'EOF_SERVICE'
[Unit]
Description=pspy process monitor
After=network.target

[Service]
Type=simple
WorkingDirectory=/root
ExecStart=/bin/bash -lc 'exec /root/pspy64 -f -c -r /etc -r /home -r /media -r /mnt -r /opt -r /root -r /tmp -r /usr -r /var -r /srv | grep -vF -f /root/pspy.exclude'
StandardOutput=append:/root/pspy.log
StandardError=append:/root/pspy.log
Restart=always
RestartSec=2
ProtectHome=false

[Install]
WantedBy=multi-user.target
EOF_SERVICE
  ok "Created /etc/systemd/system/pspy.service"
}

setup_pspy_logrotate() {
  cat >/etc/logrotate.d/pspy <<'EOF_ROTATE'
/root/pspy.log {
  size 50M
  rotate 5
  compress
  missingok
  notifempty
  copytruncate
}
EOF_ROTATE
  chmod 644 /etc/logrotate.d/pspy
  ok "Created /etc/logrotate.d/pspy"
}

setup_auditd_override_if_needed() {
  mkdir -p /etc/systemd/system/auditd.service.d
  cat >/etc/systemd/system/auditd.service.d/override.conf <<'EOF_OVR'
[Service]
RefuseManualStop=no
EOF_OVR
  systemctl daemon-reload
  ok "Added auditd override: RefuseManualStop=no"
}

section_header "Section 4 - Setup Logging"

section_header "1) Configure pspy"
section_header "1a) Download pspy binary"
if download_file "$PSPY_URL" /root/pspy64; then
  chmod +x /root/pspy64
  ok "Downloaded pspy to /root/pspy64"
else
  warn "Failed to download pspy from: $PSPY_URL"
fi
pause_step

section_header "1b) Create pspy exclude list and service file"
write_pspy_exclude
write_pspy_service
show_file_with_pause "/root/pspy.exclude"
show_file_with_pause "/etc/systemd/system/pspy.service"

section_header "1c) Enable pspy and set log rotation"
systemctl daemon-reload
systemctl enable --now pspy || warn "Failed to enable/start pspy"
show_shell_with_pause "systemctl status pspy | head -n 40" "systemctl --no-pager --full status pspy | sed -n '1,40p' || true"

setup_pspy_logrotate
show_file_with_pause "/etc/logrotate.d/pspy"
info "Use: less -R +G /root/pspy.log"
pause_step

section_header "2) Auditd Setup"
section_header "2a) Install auditd packages"
install_audit_packages || warn "Audit package installation had issues"
pause_step

section_header "2b) Download and install audit rules"
if [[ "$AUDIT_RULES_URL" == *"INSERT_ORG"* || "$AUDIT_RULES_URL" == *"INSERT_REPO"* ]]; then
  show_output_source_header "FILE: /etc/audit/rules.d/security.rules"
  warn "AUDIT_RULES_URL is still a placeholder. Set it before running this step in production."
  pause_step
else
  if download_file "$AUDIT_RULES_URL" /root/audit.rules; then
    echo "-a never,exit -F arch=b64 -S all -F exe=/root/pspy64 -k pspy" >>/root/audit.rules
    cp /root/audit.rules /etc/audit/rules.d/security.rules
    chmod 640 /etc/audit/rules.d/security.rules
    ok "Installed audit rules at /etc/audit/rules.d/security.rules"
    show_file_with_pause "/etc/audit/rules.d/security.rules"
  else
    show_output_source_header "FILE: /etc/audit/rules.d/security.rules"
    warn "Failed to download audit rules from $AUDIT_RULES_URL"
    pause_step
  fi
fi
pause_step

section_header "2c) Load rules and restart auditd"
if command_exists augenrules; then
  show_command_with_pause "augenrules --load" augenrules --load
fi

systemctl enable auditd || warn "Failed to enable auditd"
if ! systemctl restart auditd; then
  warn "auditd restart failed. Applying RefuseManualStop override and retrying."
  setup_auditd_override_if_needed
  systemctl restart auditd || warn "auditd restart still failing after override"
fi
show_shell_with_pause "systemctl status auditd | head -n 40" "systemctl --no-pager --full status auditd | sed -n '1,40p' || true"
pause_step

ok "Section 4 complete."
