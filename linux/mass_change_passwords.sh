#!/usr/bin/env bash
set -euo pipefail

# Mass-change local user passwords and store them encrypted in /root.
# Requires: bash, awk, grep, openssl, chpasswd, passwd

# Add usernames here to skip (space-separated). Example: EXCLUDE_USERS=("alice" "svc_backup")
# Note: If you exclude "root", its password will not be rotated/locked.
EXCLUDE_USERS=()

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "ERROR: This script must be run as root." >&2
  exit 1
fi

for cmd in awk grep openssl chpasswd passwd; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: Missing required command: $cmd" >&2
    exit 1
  fi
done

# Determine UID_MIN from /etc/login.defs if present; default to 1000.
UID_MIN=1000
if [[ -r /etc/login.defs ]]; then
  UID_MIN=$(awk '($1=="UID_MIN"){print $2; exit}' /etc/login.defs || echo 1000)
  if [[ -z "$UID_MIN" ]]; then UID_MIN=1000; fi
fi

ENC_OUT="/root/user_passwords.txt.enc"
PASS_PROTECT="J0hnC3na@987!"

umask 077

cleanup() {
  if [[ -n "${TMP_OUT:-}" && -f "$TMP_OUT" ]]; then
    shred -u "$TMP_OUT" 2>/dev/null || rm -f "$TMP_OUT"
  fi
}
trap cleanup EXIT

TMP_OUT=$(mktemp /root/user_passwords.XXXXXX)

# Generate a complex password: 20 chars with at least 1 lower, upper, digit, special.
# Uses /dev/urandom and a conservative special set for portability.
SPECIAL_SET='!@#$%^&*()_+=.,?'
make_password() {
  local pw tries=0
  while true; do
    tries=$((tries + 1))
    pw=$(LC_ALL=C tr -dc "A-Za-z0-9${SPECIAL_SET}" </dev/urandom | head -c 20 || true)
    if [[ ${#pw} -ge 20 ]] && \
       echo "$pw" | grep -q '[a-z]' && \
       echo "$pw" | grep -q '[A-Z]' && \
       echo "$pw" | grep -q '[0-9]' && \
       echo "$pw" | grep -q '[!@#$%^&*()_+=.,?]'; then
      echo "$pw"
      return 0
    fi
    if [[ $tries -ge 200 ]]; then
      echo "ERROR: Failed to generate a compliant password after $tries attempts." >&2
      return 1
    fi
  done
}

# Build list of users: root plus interactive users (UID >= UID_MIN and valid shell).
# This avoids service accounts with nologin/false shells.
mapfile -t USERS < <(
  awk -F: -v min_uid="$UID_MIN" '$3==0 || ($3>=min_uid && $7 !~ /(nologin|false)$/) {print $1}' /etc/passwd
)

if [[ ${#EXCLUDE_USERS[@]} -gt 0 ]]; then
  FILTERED_USERS=()
  for user in "${USERS[@]}"; do
    skip=false
    for ex in "${EXCLUDE_USERS[@]}"; do
      if [[ "$user" == "$ex" ]]; then
        skip=true
        break
      fi
    done
    if ! $skip; then
      FILTERED_USERS+=("$user")
    fi
  done
  USERS=("${FILTERED_USERS[@]}")
fi

if [[ ${#USERS[@]} -eq 0 ]]; then
  echo "ERROR: No users found to update." >&2
  exit 1
fi

# Change passwords and record them.
{
  printf "# Generated on %s\n" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  for user in "${USERS[@]}"; do
    pw=$(make_password)
    echo "${user}:${pw}" | chpasswd
    printf "%s:%s\n" "$user" "$pw"
  done
} > "$TMP_OUT"

# Encrypt and save to /root; remove plaintext.
# Decrypt on Linux:   openssl enc -d -aes-256-cbc -pbkdf2 -in /root/user_passwords.txt.enc -out /root/user_passwords.txt -pass pass:"J0hnC3na@987!"
# Decrypt on Windows: openssl enc -d -aes-256-cbc -pbkdf2 -in C:\path\user_passwords.txt.enc -out C:\path\user_passwords.txt -pass pass:"J0hnC3na@987!"
openssl enc -aes-256-cbc -pbkdf2 -salt -in "$TMP_OUT" -out "$ENC_OUT" -pass pass:"$PASS_PROTECT"
shred -u "$TMP_OUT" 2>/dev/null || rm -f "$TMP_OUT"

# Lock root account at the end (password changed above).
passwd -l root >/dev/null

# Keep a secure copy name for admin reference if desired (encrypted only).
# The plaintext file is not retained.

echo "OK: Passwords updated for ${#USERS[@]} users."
echo "Encrypted file: $ENC_OUT"
