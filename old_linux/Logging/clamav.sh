#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root."
   exit 1
fi

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
    echo "[-] No supported package manager found (APT, YUM, DNF, Zypper). what is u doin."
    exit 1
fi

echo "[+] Installing ClamAV..."
if [[ $PKG_MGR == "apt" ]]; then
    apt update && apt install -y clamav clamav-daemon
elif [[ $PKG_MGR == "yum" || $PKG_MGR == "dnf" ]]; then
    $PKG_MGR install -y clamav clamav-update
elif [[ $PKG_MGR == "zypper" ]]; then
    zypper install -y clamav clamav-daemon
fi

echo "[+] Stopping ClamAV daemon for updates..."
systemctl stop clamav-freshclam || systemctl stop freshclam

echo "[+] Updating ClamAV virus definitions..."
freshclam

echo "[+] Starting ClamAV services..."
systemctl start clamav-freshclam || systemctl start freshclam
systemctl enable clamav-freshclam || systemctl enable freshclam

echo "[+] Enabling ClamAV on boot..."
systemctl enable clamav-daemon
systemctl start clamav-daemon

SCAN_SCRIPT="/usr/local/bin/clamav_scan.sh"

cat <<EOF > $SCAN_SCRIPT
#!/bin/bash
LOG_FILE="/var/log/clamav_scan.log"
SCAN_DIRS="/home /root /etc /var /usr"

echo "[\$(date)] Starting ClamAV scan..." | tee -a "\$LOG_FILE"
clamscan -r --bell --log="\$LOG_FILE" \$SCAN_DIRS
echo "[\$(date)] Scan completed." | tee -a "\$LOG_FILE"
EOF

chmod 700 $SCAN_SCRIPT
chown root:root $SCAN_SCRIPT
chattr +i $SCAN_SCRIPT  # **Make the script immutable**

LOG_FILE="/var/log/clamav_scan.log"
touch $LOG_FILE
chmod 600 $LOG_FILE
chown root:root $LOG_FILE
chattr +a $LOG_FILE  # **Append-only mode for security**

SYSTEMD_SERVICE="/etc/systemd/system/clamav-scan.service"

cat <<EOF > $SYSTEMD_SERVICE
[Unit]
Description=ClamAV Automated Virus Scanner
After=network.target

[Service]
ExecStart=/usr/local/bin/clamav_scan.sh
User=root
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
ProtectSystem=full
ProtectHome=yes
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelModules=true

[Install]
WantedBy=multi-user.target
EOF

chmod 644 $SYSTEMD_SERVICE
chown root:root $SYSTEMD_SERVICE

SYSTEMD_TIMER="/etc/systemd/system/clamav-scan.timer"

cat <<EOF > $SYSTEMD_TIMER
[Unit]
Description=Run ClamAV scan every 10 minutes

[Timer]
OnBootSec=2m
OnUnitActiveSec=10m
Persistent=true

[Install]
WantedBy=timers.target
EOF

chmod 644 $SYSTEMD_TIMER
chown root:root $SYSTEMD_TIMER

systemctl daemon-reload

systemctl enable clamav-scan.timer
systemctl start clamav-scan.timer

echo "[+] ClamAV setup complete! Scans will run every 10 minutes using systemd."
