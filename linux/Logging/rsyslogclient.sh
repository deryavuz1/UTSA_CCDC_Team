#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root."
   exit 1
fi

# Ask for the Rsyslog Server IP
read -p "[?] Enter Rsyslog server IP: " RSYSLOG_SERVER_IP

AUDIT_RULES_PATH="/mnt/data/audit.rules"
DEST_AUDIT_RULES="/etc/audit/rules.d/audit.rules"

echo "[+] Detecting package manager..."
if command -v apt &> /dev/null; then
    PKG_MGR="apt"
elif command -v yum &> /dev/null; then
    PKG_MGR="yum"
elif command -v dnf &> /dev/null; then
    PKG_MGR="dnf"
elif command -v zypper &> /dev/null; then
    PKG_MGR="zypper"
else
    echo "[-] No supported package manager found (APT, YUM, DNF, Zypper). Exiting."
    exit 1
fi

if [[ $PKG_MGR == "apt" ]]; then
    apt update && apt install -y rsyslog auditd audispd-plugins
elif [[ $PKG_MGR == "yum" || $PKG_MGR == "dnf" ]]; then
    $PKG_MGR install -y rsyslog audit audit-libs audispd-plugins
elif [[ $PKG_MGR == "zypper" ]]; then
    zypper install -y rsyslog audit audit-audisp
fi

# Ensure Rsyslog Client Configuration
echo "[+] Configuring rsyslog to send logs to server ($RSYSLOG_SERVER_IP)..."

cat <<EOF > /etc/rsyslog.d/50-remote.conf
# Send logs to central Rsyslog server
*.* @${RSYSLOG_SERVER_IP}:514
EOF

# Restart Rsyslog Service
systemctl restart rsyslog
systemctl enable rsyslog

# Apply Auditd Rules
if [[ -f "$AUDIT_RULES_PATH" ]]; then
    echo "[+] Applying custom audit rules from $AUDIT_RULES_PATH..."
    cp "$AUDIT_RULES_PATH" "$DEST_AUDIT_RULES"
    chmod 600 "$DEST_AUDIT_RULES"
    auditctl -R "$DEST_AUDIT_RULES"
else
    echo "[-] Custom audit rules file not found. Skipping audit rule application."
fi

# Restart auditd service
systemctl restart auditd
systemctl enable auditd

echo "[+] Rsyslog Client & Auditd setup complete!"
