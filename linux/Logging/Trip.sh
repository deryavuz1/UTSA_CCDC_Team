#!/bin/bash

# Run as root

apt update && apt install -y tripwire

tripwire --init


cp /etc/tripwire/twpol.txt /etc/tripwire/twpol.txt.bak

cat <<EOL > /etc/tripwire/twpol.txt
(
  rulename = "Critical System Files",
  severity = \$(SIG_HI)
)
{
  /etc/passwd            -> \$(SEC_CRIT);
  /etc/shadow            -> \$(SEC_CRIT);
  /etc/group             -> \$(SEC_CRIT);
  /etc/sudoers           -> \$(SEC_CRIT);
  /etc/ssh               -> \$(SEC_CONFIG);
  /root                  -> \$(SEC_CONFIG);
  /home                  -> \$(SEC_CONFIG);
  /usr/bin               -> \$(SEC_BIN);
  /usr/local/bin         -> \$(SEC_BIN);
  /bin                   -> \$(SEC_BIN);
}

(
  rulename = "Tripwire Self-Monitoring",
  severity = \$(SIG_HI)
)
{
  /usr/sbin/tripwire     -> \$(SEC_BIN);
  /etc/tripwire          -> \$(SEC_CONFIG);
}
EOL

sudo twadmin -m P /etc/tripwire/twpol.txt

tripwire --init

chattr +i /usr/sbin/tripwire
chattr -R +i /etc/tripwire

#  cron automation (checks every 5 min)
echo "*/5 * * * * root /usr/sbin/tripwire --check | grep 'Total violations found:' && logger 'Tripwire Alert: Files Modified!'" >> /etc/crontab

# Done
echo "Tripwire successfully installed"
