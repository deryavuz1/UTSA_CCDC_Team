#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root."
   exit 1
fi

SPLUNK_HOME="/opt/splunk"
SPLUNK_DEB="splunk-9.4.1-e3bdab203ac8-linux-amd64.deb"
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/9.4.1/linux/$SPLUNK_DEB"
SPLUNK_USER="splunk"
RANDOM_STATE="/root/.rnd" 

read -sp "[?] Enter Splunk admin password: " admin_password
echo

echo "[+] Fixing OpenSSL random state issue..."
touch $RANDOM_STATE
chmod 600 $RANDOM_STATE
export RANDFILE=$RANDOM_STATE

echo "[+] Updating package lists..."
apt update

echo "[+] Installing dependencies..."
apt install -y wget openssl

if [ -d "$SPLUNK_HOME" ]; then
    echo "[!] Removing existing Splunk installation..."
    rm -rf "$SPLUNK_HOME"
fi

echo "[+] Downloading Splunk..."
wget -O /tmp/$SPLUNK_DEB $SPLUNK_URL

echo "[+] Installing Splunk..."
dpkg -i /tmp/$SPLUNK_DEB

if ! id "$SPLUNK_USER" &>/dev/null; then
    echo "[+] Creating Splunk user..."
    useradd -m -d $SPLUNK_HOME -s /bin/bash splunk
fi

echo "[+] Setting ownership..."
chown -R splunk:splunk $SPLUNK_HOME

echo "[+] Setting up Splunk admin account..."
mkdir -p $SPLUNK_HOME/etc/system/local
cat <<EOF > $SPLUNK_HOME/etc/system/local/user-seed.conf
[user_info]
USERNAME = admin
PASSWORD = $admin_password
EOF
chown splunk:splunk $SPLUNK_HOME/etc/system/local/user-seed.conf
chmod 600 $SPLUNK_HOME/etc/system/local/user-seed.conf
chattr +i $SPLUNK_HOME/etc/system/local/user-seed.conf  # Prevent modification by Red Team

echo "[+] Enabling Splunk Web UI..."
cat <<EOF > $SPLUNK_HOME/etc/system/local/web.conf
[settings]
startwebserver = true
EOF

$SPLUNK_HOME/bin/splunk enable boot-start -user splunk --accept-license --no-prompt

echo "[+] Restarting Splunk to apply changes..."
su - splunk -c "$SPLUNK_HOME/bin/splunk start"

echo "[+] Splunk setup complete!"
echo "[!] Access Splunk Web UI at: http://$(hostname -I | awk '{print $1}'):8000"
echo "[!] Login with: Username: admin | Password: $admin_password"
