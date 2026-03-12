#!/bin/bash
# LDAP + Kerberos + SSSD Backup Script
# Usage: ./backup.sh

BACKUP_DIR="/root/bkp/ldap"
DATE=$(date +%Y%m%d_%H%M%S)
DATA_BACKUP="$BACKUP_DIR/ldap_data_$DATE.ldif"
CONFIG_BACKUP="$BACKUP_DIR/ldap_config_$DATE.ldif"
KRB5_BACKUP="$BACKUP_DIR/krb5_$DATE"
SSSD_BACKUP="$BACKUP_DIR/sssd_$DATE"

# Auto-detect distro
if [ -f /etc/debian_version ]; then
    LDAP_USER="openldap"
    LDAP_CONF_DIR="/etc/ldap/slapd.d"
    KRB5_KDC_DIR="/var/lib/krb5kdc"
    KRB5_CONF_DIR="/etc/krb5kdc"
else
    LDAP_USER="ldap"
    LDAP_CONF_DIR="/etc/openldap/slapd.d"
    KRB5_KDC_DIR="/var/kerberos/krb5kdc"
    KRB5_CONF_DIR="/var/kerberos/krb5kdc"
fi

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root. Try: sudo $0 $@"
    exit 1
fi

# Auto-detect the data database index and directory
DB_INDEX=$(slapcat -n 0 | awk '
    /^dn: olcDatabase=\{([0-9]+)\}/ { match($0, /\{([0-9]+)\}/, arr); idx=arr[1] }
    /^olcDbDirectory:/ { print idx; exit }
')

DB_DIR=$(slapcat -n 0 | awk '
    /^olcDbDirectory:/ { print $2; exit }
')

if [ -z "$DB_INDEX" ]; then
    echo "ERROR: Could not auto-detect LDAP database index."
    exit 1
fi

if [ -z "$DB_DIR" ]; then
    echo "ERROR: Could not auto-detect LDAP data directory."
    exit 1
fi

echo "Detected data database index: $DB_INDEX"
echo "Detected data directory:      $DB_DIR"

mkdir -p "$BACKUP_DIR"

# --- LDAP Backup ---

echo ""
echo "=== LDAP Backup ==="

echo "Backing up LDAP config (cn=config)..."
slapcat -n 0 -l "$CONFIG_BACKUP"
if [ $? -eq 0 ]; then
    echo "Config backup saved to: $CONFIG_BACKUP"
else
    echo "ERROR: Config backup failed!"
    exit 1
fi

echo "Backing up LDAP data..."
slapcat -n "$DB_INDEX" -l "$DATA_BACKUP"
if [ $? -eq 0 ]; then
    echo "Data backup saved to: $DATA_BACKUP"
else
    echo "ERROR: Data backup failed!"
    exit 1
fi

# --- Kerberos Backup ---

echo ""
echo "=== Kerberos Backup ==="

if [ ! -d "$KRB5_KDC_DIR" ]; then
    echo "Kerberos KDC directory not found at $KRB5_KDC_DIR, skipping."
else
    mkdir -p "$KRB5_BACKUP"

    echo "Backing up KDC directory ($KRB5_KDC_DIR)..."
    cp -a "$KRB5_KDC_DIR/." "$KRB5_BACKUP/kdc"
    if [ $? -eq 0 ]; then
        echo "KDC backup saved to: $KRB5_BACKUP/kdc"
    else
        echo "ERROR: KDC backup failed!"
        exit 1
    fi

    echo "Backing up /etc/krb5.conf..."
    if [ -f /etc/krb5.conf ]; then
        cp -a /etc/krb5.conf "$KRB5_BACKUP/krb5.conf"
        echo "krb5.conf saved to: $KRB5_BACKUP/krb5.conf"
    else
        echo "WARNING: No /etc/krb5.conf found, skipping."
    fi

    echo "Backing up host keytab..."
    if [ -f /etc/krb5.keytab ]; then
        cp -a /etc/krb5.keytab "$KRB5_BACKUP/krb5.keytab"
        echo "Keytab saved to: $KRB5_BACKUP/krb5.keytab"
    else
        echo "WARNING: No keytab found at /etc/krb5.keytab, skipping."
    fi
fi

# --- SSSD Backup ---

echo ""
echo "=== SSSD Backup ==="

if [ ! -f /etc/sssd/sssd.conf ] && [ ! -d /etc/sssd/conf.d ]; then
    echo "No SSSD config found, skipping."
else
    mkdir -p "$SSSD_BACKUP"

    if [ -f /etc/sssd/sssd.conf ]; then
        echo "Backing up /etc/sssd/sssd.conf..."
        cp -a /etc/sssd/sssd.conf "$SSSD_BACKUP/sssd.conf"
        echo "sssd.conf saved to: $SSSD_BACKUP/sssd.conf"
    fi

    if [ -d /etc/sssd/conf.d ] && [ "$(ls -A /etc/sssd/conf.d)" ]; then
        echo "Backing up /etc/sssd/conf.d/..."
        cp -a /etc/sssd/conf.d "$SSSD_BACKUP/conf.d"
        echo "conf.d saved to: $SSSD_BACKUP/conf.d"
    fi
fi

# --- Cleanup old backups ---

echo ""
echo "=== Cleanup ==="

find "$BACKUP_DIR" -name "ldap_data_*.ldif" -mtime +7 -delete
find "$BACKUP_DIR" -name "ldap_config_*.ldif" -mtime +7 -delete
find "$BACKUP_DIR" -maxdepth 1 -name "krb5_*" -type d -mtime +7 -exec rm -rf {} +
find "$BACKUP_DIR" -maxdepth 1 -name "sssd_*" -type d -mtime +7 -exec rm -rf {} +

echo "Old backups cleaned up."
echo ""
echo "Done."
