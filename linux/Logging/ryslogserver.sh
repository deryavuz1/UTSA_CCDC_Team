#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root."
   exit 1
fi

AUDIT_RULES_PATH="/mnt/data/audit.rules"
DEST_AUDIT_RULES="/etc/audit/rules.d/audit.rules"
HOSTNAME=$(hostname)  # Dynamically get the machine's hostname

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

# Ensure remote logging directory exists and has correct permissions
LOG_DIR="/var/log/remote/$HOSTNAME"
echo "[+] Creating remote log directory: $LOG_DIR"
mkdir -p "$LOG_DIR"
chmod -R 755 /var/log/remote
chown -R syslog:adm /var/log/remote

# Backup original rsyslog config
cp /etc/rsyslog.conf /etc/rsyslog.conf.bak

# Enable UDP logging in rsyslog.conf
cat <<EOF >> /etc/rsyslog.conf

# Enable UDP syslog reception
module(load="imudp")
input(type="imudp" port="514")

# Store logs by host
template(name="RemoteLogs" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
*.* ?RemoteLogs
& stop
EOF

cat <<EOF > /etc/logrotate.d/rsyslog-remote
/var/log/remote/*/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        systemctl restart rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

AUDIT_CONF="/etc/audit/auditd.conf"
AUDISP_CONF="/etc/audit/plugins.d/syslog.conf"

cp $AUDIT_CONF ${AUDIT_CONF}.bak

sed -i 's/^log_format = .*/log_format = RAW/' $AUDIT_CONF
sed -i 's/^priority_boost = .*/priority_boost = 4/' $AUDIT_CONF

echo "active = yes" > $AUDISP_CONF
echo "direction = out" >> $AUDISP_CONF
echo "path = builtin_syslog" >> $AUDISP_CONF
echo "type = builtin" >> $AUDISP_CONF
echo "args = LOG_INFO" >> $AUDISP_CONF
echo "format = string" >> $AUDISP_CONF

if [[ -f "$AUDIT_RULES_PATH" ]]; then
    echo "[+] Applying custom audit rules from $AUDIT_RULES_PATH..."
    cp "$AUDIT_RULES_PATH" "$DEST_AUDIT_RULES"
    chmod 600 "$DEST_AUDIT_RULES"
    auditctl -R "$DEST_AUDIT_RULES"
else
    echo "[-] Custom audit rules file not found. Skipping audit rule application."
fi

systemctl restart rsyslog
systemctl enable rsyslog
systemctl restart auditd
systemctl enable auditd

echo "[+] rsyslog and auditd setup complete!"
