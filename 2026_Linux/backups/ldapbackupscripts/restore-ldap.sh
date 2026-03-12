#!/bin/bash
# LDAP + Kerberos + SSSD Restore Script
# Usage: ./restore.sh <all|krb5|ldap> <backup_date>
# Example: ./restore.sh all 20240101_120000
# Example: ./restore.sh ldap 20240101_120000
# Example: ./restore.sh krb5 20240101_120000

MODE="$1"
DATE="$2"
BACKUP_DIR="/root/bkp/ldap"

# Auto-detect distro
if [ -f /etc/debian_version ]; then
    LDAP_USER="openldap"
    LDAP_CONF_DIR="/etc/ldap/slapd.d"
    KRB5_KDC_DIR="/var/lib/krb5kdc"
else
    LDAP_USER="ldap"
    LDAP_CONF_DIR="/etc/openldap/slapd.d"
    KRB5_KDC_DIR="/var/kerberos/krb5kdc"
fi

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root. Try: sudo $0 $*"
    exit 1
fi

# Validate mode and date
if [ -z "$MODE" ] || [ -z "$DATE" ]; then
    echo "Usage: $0 <all|krb5|ldap> <backup_date>"
    echo ""
    echo "  all   - Restore LDAP + Kerberos + SSSD"
    echo "  ldap  - Restore LDAP + SSSD only"
    echo "  krb5  - Restore Kerberos only"
    echo ""
    echo "Available backups:"
    DATES=($(ls "$BACKUP_DIR"/ldap_data_*.ldif 2>/dev/null | sed 's/.*ldap_data_//;s/\.ldif//' | sort))
    TOTAL=${#DATES[@]}
    if [ "$TOTAL" -eq 0 ]; then
        echo "  No backups found in $BACKUP_DIR"
    else
        for i in "${!DATES[@]}"; do
            d="${DATES[$i]}"
            label=""
            if [ "$TOTAL" -gt 1 ]; then
                if [ "$i" -eq 0 ]; then
                    label=" (* oldest)"
                elif [ "$i" -eq $((TOTAL - 1)) ]; then
                    label=" (* latest)"
                fi
            fi
            echo "  $d$label"
        done
    fi
    exit 1
fi

if [ "$MODE" != "all" ] && [ "$MODE" != "krb5" ] && [ "$MODE" != "ldap" ]; then
    echo "ERROR: Mode must be one of: all, krb5, ldap"
    exit 1
fi

# Resolve backup file paths
DATA_BACKUP="$BACKUP_DIR/ldap_data_$DATE.ldif"
CONFIG_BACKUP="$BACKUP_DIR/ldap_config_$DATE.ldif"
KRB5_BACKUP="$BACKUP_DIR/krb5_$DATE"
SSSD_BACKUP="$BACKUP_DIR/sssd_$DATE"

# Validate required files exist for chosen mode
if [ "$MODE" = "all" ] || [ "$MODE" = "ldap" ]; then
    if [ ! -f "$DATA_BACKUP" ]; then
        echo "ERROR: Data backup not found: $DATA_BACKUP"
        exit 1
    fi
    if [ ! -f "$CONFIG_BACKUP" ]; then
        echo "ERROR: Config backup not found: $CONFIG_BACKUP"
        exit 1
    fi
fi

if [ "$MODE" = "all" ] || [ "$MODE" = "krb5" ]; then
    if [ ! -d "$KRB5_BACKUP" ]; then
        echo "ERROR: Kerberos backup not found: $KRB5_BACKUP"
        exit 1
    fi
fi

# Auto-detect the data database index and directory (only needed for ldap/all)
if [ "$MODE" = "all" ] || [ "$MODE" = "ldap" ]; then
    SLAPCAT_OUT=$(slapcat -n 0 2>/dev/null)

    DB_DIR=$(echo "$SLAPCAT_OUT" | grep "^olcDbDirectory:" | awk '{print $2}')

    DB_INDEX=$(echo "$SLAPCAT_OUT" | grep -B20 "^olcDbDirectory:" | grep "^dn: olcDatabase=" | tail -1 | sed 's/[^0-9]*\([0-9]*\).*/\1/')

    if [ -z "$DB_INDEX" ]; then
        echo "ERROR: Could not auto-detect LDAP database index."
        exit 1
    fi

    if [ -z "$DB_DIR" ]; then
        echo "ERROR: Could not auto-detect LDAP data directory."
        exit 1
    fi
fi

# Summary
echo "Restore mode:             $MODE"
echo "Backup date:              $DATE"

if [ "$MODE" = "all" ] || [ "$MODE" = "ldap" ]; then
    echo "LDAP data backup:         $DATA_BACKUP"
    echo "LDAP config backup:       $CONFIG_BACKUP"
    echo "Detected LDAP user:       $LDAP_USER"
    echo "Detected config dir:      $LDAP_CONF_DIR"
    echo "Detected database index:  $DB_INDEX"
    echo "Detected data directory:  $DB_DIR"
    if [ -d "$SSSD_BACKUP" ]; then
        echo "SSSD backup:              $SSSD_BACKUP"
    else
        echo "SSSD backup:              not found, will skip"
    fi
fi

if [ "$MODE" = "all" ] || [ "$MODE" = "krb5" ]; then
    echo "Kerberos backup:          $KRB5_BACKUP"
fi

echo ""
echo "WARNING: This will WIPE and restore the selected components."
read -p "Are you sure? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

# --- LDAP Restore ---

if [ "$MODE" = "all" ] || [ "$MODE" = "ldap" ]; then
    echo ""
    echo "=== LDAP Restore ==="

    echo "Stopping slapd..."
    systemctl stop slapd

    echo "Clearing existing config..."
    rm -rf "$LDAP_CONF_DIR"/*

    echo "Restoring config (cn=config)..."
    slapadd -n 0 -l "$CONFIG_BACKUP" -F "$LDAP_CONF_DIR"
    if [ $? -ne 0 ]; then
        echo "ERROR: Config restore failed!"
        exit 1
    fi
    chown -R "$LDAP_USER":"$LDAP_USER" "$LDAP_CONF_DIR"

    echo "Clearing existing data..."
    rm -rf "$DB_DIR"/*

    echo "Restoring data..."
    slapadd -n "$DB_INDEX" -l "$DATA_BACKUP"
    if [ $? -ne 0 ]; then
        echo "ERROR: Data restore failed!"
        exit 1
    fi
    chown -R "$LDAP_USER":"$LDAP_USER" "$DB_DIR"

    echo "Starting slapd..."
    systemctl start slapd

    if systemctl is-active --quiet slapd; then
        echo "slapd is running."
    else
        echo "WARNING: slapd failed to start. Check: journalctl -xe -u slapd"
        exit 1
    fi
fi

# --- Kerberos Restore ---

if [ "$MODE" = "all" ] || [ "$MODE" = "krb5" ]; then
    echo ""
    echo "=== Kerberos Restore ==="

    echo "Stopping krb5kdc and kadmin..."
    systemctl stop krb5kdc kadmin 2>/dev/null

    if [ -d "$KRB5_BACKUP/kdc" ]; then
        echo "Restoring KDC directory to $KRB5_KDC_DIR..."
        rm -rf "$KRB5_KDC_DIR"/*
        cp -a "$KRB5_BACKUP/kdc/." "$KRB5_KDC_DIR/"
        if [ $? -ne 0 ]; then
            echo "ERROR: KDC restore failed!"
            exit 1
        fi
    else
        echo "WARNING: No kdc directory found in backup, skipping KDC restore."
    fi

    if [ -f "$KRB5_BACKUP/krb5.conf" ]; then
        echo "Restoring /etc/krb5.conf..."
        cp -a "$KRB5_BACKUP/krb5.conf" /etc/krb5.conf
    else
        echo "WARNING: No krb5.conf found in backup, skipping."
    fi

    if [ -f "$KRB5_BACKUP/krb5.keytab" ]; then
        echo "Restoring /etc/krb5.keytab..."
        cp -a "$KRB5_BACKUP/krb5.keytab" /etc/krb5.keytab
        chmod 600 /etc/krb5.keytab
    else
        echo "WARNING: No keytab found in backup, skipping."
    fi

    echo "Starting krb5kdc and kadmin..."
    systemctl start krb5kdc kadmin 2>/dev/null

    if systemctl is-active --quiet krb5kdc; then
        echo "krb5kdc is running."
    else
        echo "WARNING: krb5kdc failed to start. Check: journalctl -xe -u krb5kdc"
    fi
fi

# --- SSSD Restore ---

if [ "$MODE" = "all" ] || [ "$MODE" = "ldap" ]; then
    if [ -d "$SSSD_BACKUP" ]; then
        echo ""
        echo "=== SSSD Restore ==="

        echo "Stopping sssd..."
        systemctl stop sssd

        if [ -f "$SSSD_BACKUP/sssd.conf" ]; then
            echo "Restoring /etc/sssd/sssd.conf..."
            mkdir -p /etc/sssd
            cp -a "$SSSD_BACKUP/sssd.conf" /etc/sssd/sssd.conf
            chmod 600 /etc/sssd/sssd.conf
            echo "sssd.conf restored."
        fi

        if [ -d "$SSSD_BACKUP/conf.d" ]; then
            echo "Restoring /etc/sssd/conf.d/..."
            mkdir -p /etc/sssd/conf.d
            cp -a "$SSSD_BACKUP/conf.d/." /etc/sssd/conf.d/
            echo "conf.d restored."
        fi

        echo "Clearing SSSD cache..."
        rm -rf /var/lib/sss/db/*
        mkdir -p /var/lib/sss/db
        chown -R sssd:sssd /var/lib/sss/db
        chmod 700 /var/lib/sss/db

        echo "Starting sssd..."
        systemctl start sssd

        if systemctl is-active --quiet sssd; then
            echo "sssd is running."
        else
            echo "WARNING: sssd failed to start. Check: journalctl -xe -u sssd"
        fi
    fi
fi

echo ""
echo "Restore complete."
