#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "[-] This script must be run as root."
   exit 1
fi

AUDIT_RULES_DEST="/mnt/data/audit.rules"

echo "[+] Searching for audit.rules file in the system..."

# Create /mnt/data if it doesn't exist
mkdir -p /mnt/data

# Automatically find audit.rules file anywhere in the system
AUDIT_RULES_SOURCE=$(find / -name "audit.rules" -type f 2>/dev/null | head -n 1)

if [[ -f "$AUDIT_RULES_SOURCE" ]]; then
    echo "[+] Found audit.rules at: $AUDIT_RULES_SOURCE"
    echo "[+] Moving it to $AUDIT_RULES_DEST..."
    mv "$AUDIT_RULES_SOURCE" "$AUDIT_RULES_DEST"
    chmod 600 "$AUDIT_RULES_DEST"
else
    echo "[-] audit.rules not found anywhere on the system. Ensure it exists before running the main script."
    exit 1
fi

echo "[+] audit.rules successfully staged. You can now run the rsyslogserver.sh script."
