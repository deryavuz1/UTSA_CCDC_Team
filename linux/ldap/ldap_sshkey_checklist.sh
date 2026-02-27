#!/bin/bash
# LDAP Bulk SSH Key Changer - minimal
# Outputs: oldkeys.txt revertkeys.ldif privatekeys/ newkeys.ldif userkeys.txt
#
# ── ONELINERS TO BUILD USER LIST FOR sshkeys_to_change.txt ────────────
# Paste output into sshkeys_to_change.txt starting at line 4.
#
# All users with SSH keys (DN + pubkey):
#   ldapsearch -x -LLL -H ldapi:// -D "BINDDN" -w "PW" -b "BASEDN" "(&(uid=*)(sshPublicKey=*))" dn sshPublicKey | perl -p0e 's/\n //g' | awk '/^dn: /{dn=substr($0,5)} /^sshPublicKey: /{print dn" "substr($0,15)}'
#
# Single OU (DN + pubkey):
#   ldapsearch -x -LLL -H ldapi:// -D "BINDDN" -w "PW" -b "ou=people,BASEDN" -s one "(&(uid=*)(sshPublicKey=*))" dn sshPublicKey | perl -p0e 's/\n //g' | awk '/^dn: /{dn=substr($0,5)} /^sshPublicKey: /{print dn" "substr($0,15)}'
#
# Exclude admin/manager — append to any of the above:
#   | grep -v -E "(cn=admin|cn=Manager)"
#
# ── sshkeys_to_change.txt FORMAT ──────────────────────────────────────
# Line 1: LDAP URI          Line 2: Bind DN
# Line 3: Bind Password
# Line 4+: FULL_DN OLD_PUBKEY  (# to skip a user)
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail
F="${1:-sshkeys_to_change.txt}"
[[ -f "$F" ]] || { echo "No file: $F"; exit 1; }

mapfile -t CFG < <(grep -v '^#' "$F" | head -3)
URI="${CFG[0]}"; BD="${CFG[1]}"; BP="${CFG[2]}"

: > oldkeys.txt; : > revertkeys.ldif; : > newkeys.ldif; : > userkeys.txt
mkdir -p privatekeys
N=0

while IFS= read -r L; do
  L=$(echo "$L" | xargs)
  [[ -z "$L" || "$L" == \#* ]] && continue
  DN="${L%% *}"
  UID_VAL="${DN#uid=}"; UID_VAL="${UID_VAL%%,*}"

  # Only build revert entry if an old pubkey was provided after the DN
  if [[ "$L" == *" "* ]]; then
    OLD_KEY="${L#* }"
    echo "$UID_VAL $OLD_KEY" >> oldkeys.txt
    printf "dn: %s\nchangetype: modify\nreplace: sshPublicKey\nsshPublicKey: %s\n\n" "$DN" "$OLD_KEY" >> revertkeys.ldif
  else
    echo "NOTICE: $UID_VAL has no old key — skipping revert entry"
  fi

  # Generate new ed25519 keypair
  KEYFILE="privatekeys/${UID_VAL}_id_ed25519"
  ssh-keygen -t ed25519 -f "$KEYFILE" -N "" -C "$UID_VAL" -q
  PUBKEY=$(cat "${KEYFILE}.pub")

  printf "dn: %s\nchangetype: modify\nreplace: sshPublicKey\nsshPublicKey: %s\n\n" "$DN" "$PUBKEY" >> newkeys.ldif
  PRIVKEY=$(grep -v '^-----' "$KEYFILE" | tr -d '\n')
  echo "$UID_VAL,$PRIVKEY" >> userkeys.txt
  ((++N))
done < <(grep -v '^#' "$F" | tail -n +4)

echo "Done: $N prepared"
echo "Private keys saved to: privatekeys/"
echo "APPLY:  ldapmodify -x -H $URI -D '$BD' -w '$BP' -f newkeys.ldif"
echo "REVERT: ldapmodify -x -H $URI -D '$BD' -w '$BP' -f revertkeys.ldif"
