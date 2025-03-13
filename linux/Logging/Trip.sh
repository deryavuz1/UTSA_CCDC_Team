#!/bin/bash

# Ensure script runs as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root!" 
    exit 1
fi

# we DONT WANT POSTFIX
echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections
echo "postfix hold" | dpkg --set-selections

# Install Tripwire WITHOUT recommended packages
apt update && apt install -y --no-install-recommends tripwire

# Backup policy file
cp /etc/tripwire/twpol.txt /etc/tripwire/twpol.txt.bak

cat << 'EOL' | tee /etc/tripwire/twpol.txt > /dev/null
(
  rulename = "Critical System Files",
  severity = $(SIG_HI)
)
{
  /etc/passwd        -> $(SEC_CRIT);
  /etc/shadow        -> $(SEC_CRIT);
  /etc/group         -> $(SEC_CRIT);
  /etc/sudoers       -> $(SEC_CRIT);
  /etc/ssh           -> $(SEC_CONFIG);
  /root              -> $(SEC_CONFIG);
  /home              -> $(SEC_CONFIG);
  /usr/bin           -> $(SEC_BIN);
  /usr/local/bin     -> $(SEC_BIN);
  /bin               -> $(SEC_BIN);
}

(
  rulename = "Tripwire Self-Monitoring",
  severity = $(SIG_HI)
)
{
  /usr/sbin/tripwire -> $(SEC_BIN);
  /etc/tripwire      -> $(SEC_CONFIG);
}

# Monitor /tmp explicitly (Red Team defense)
(
  rulename = "Monitor Temporary Files",
  severity = $(SIG_MED)
)
{
  /tmp       -> $(SEC_CONFIG);
}
EOL

twadmin --create-polfile /etc/tripwire/twpol.txt

rm -f /var/lib/tripwire/*.twd

tripwire --init

chattr +i /usr/sbin/tripwire
find /etc/tripwire -type f -exec chattr +i {} \;

echo "*/5 * * * * root /usr/sbin/tripwire --check | grep -q 'Total violations found: [^0]' && logger 'Tripwire Alert: Files Modified!'" >> /etc/crontab

# Done
echo "Tripwire successfully installed and configured without monitoring /proc."
