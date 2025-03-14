#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root."
   exit 1
fi

SPLUNK_HOME="/opt/splunkforwarder"
SPLUNK_DEB="splunkforwarder-9.4.1-e3bdab203ac8-linux-amd64.deb"
SPLUNK_URL="https://download.splunk.com/products/universalforwarder/releases/9.4.1/linux/$SPLUNK_DEB"
SPLUNK_USER="splunk"

read -p "[?] Enter Splunk Server IP: " SPLUNK_SERVER_IP

echo "[+] Updating package lists..."
apt update

echo "[+] Installing dependencies..."
apt install -y wget

if [ -d "$SPLUNK_HOME" ]; then
    echo "[!] Removing existing Splunk Universal Forwarder..."
    rm -rf "$SPLUNK_HOME"
fi

echo "[+] Downloading Splunk Universal Forwarder..."
wget -O /tmp/$SPLUNK_DEB $SPLUNK_URL

echo "[+] Installing Splunk Universal Forwarder..."
dpkg -i /tmp/$SPLUNK_DEB

if ! id "$SPLUNK_USER" &>/dev/null; then
    echo "[+] Creating Splunk user..."
    useradd -m -d $SPLUNK_HOME -s /bin/bash splunk
fi

echo "[+] Setting ownership..."
chown -R splunk:splunk $SPLUNK_HOME

$SPLUNK_HOME/bin/splunk enable boot-start -user splunk --accept-license --no-prompt

echo "[+] Configuring Splunk Forwarder to send logs to $SPLUNK_SERVER_IP..."
$SPLUNK_HOME/bin/splunk add forward-server "$SPLUNK_SERVER_IP:9997" --accept-license --no-prompt

echo "[+] Enabling system log monitoring..."
mkdir -p $SPLUNK_HOME/etc/system/local
cat <<EOF > $SPLUNK_HOME/etc/system/local/inputs.conf
[default]
host = $(hostname)

[monitor:///var/log]
disabled = false
index = main
sourcetype = syslog

[monitor:///var/log/auth.log]
disabled = false
index = security
sourcetype = auth

[monitor:///var/log/syslog]
disabled = false
index = os
sourcetype = syslog
EOF

chown splunk:splunk $SPLUNK_HOME/etc/system/local/inputs.conf
chmod 600 $SPLUNK_HOME/etc/system/local/inputs.conf

echo "[+] Starting Splunk Forwarder..."
su - splunk -c "$SPLUNK_HOME/bin/splunk restart"

echo "[+] Splunk Universal Forwarder setup complete!"
echo "[!] Logs are now being sent to Splunk Server at $SPLUNK_SERVER_IP."
