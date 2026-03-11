#!/bin/bash
# LDAP Bulk Password Changer - minimal
# Outputs: oldusers.txt revert.ldif user.txt newpwd.ldif
#
# ── ONELINERS TO BUILD USER LIST FOR to_change.txt ──────────────────
# Paste output into to_change.txt starting at line 5.
#
# All users, all OUs (DN + decoded hash):
#   ldapsearch -x -LLL -H ldapi:// -D "BINDDN" -w "PW" -b "BASEDN" "(&(uid=*)(userPassword=*))" dn userPassword | awk '/^dn: /{dn=substr($0,5)} /^userPassword:: /{cmd="echo "$2" | base64 -d"; cmd | getline h; close(cmd); print dn" "h}'
#
# Single OU (DN + decoded hash):
#   ldapsearch -x -LLL -H ldapi:// -D "BINDDN" -w "PW" -b "ou=people,BASEDN" -s one "(&(uid=*)(userPassword=*))" dn userPassword | awk '/^dn: /{dn=substr($0,5)} /^userPassword:: /{cmd="echo "$2" | base64 -d"; cmd | getline h; close(cmd); print dn" "h}'
#
# Exclude admin/manager — append to any of the above:
#   | grep -v -E "(cn=admin|cn=Manager)"
#
# ── to_change.txt FORMAT ────────────────────────────────────────────
# Line 1: LDAP URI          Line 2: Bind DN
# Line 3: Bind Password     Line 4: Password hash ({SSHA})
# Line 5+: FULL_DN OLDHASH  (# to skip a user)
# ────────────────────────────────────────────────────────────────────
set -euo pipefail
F="${1:-to_change.txt}"
[[ -f "$F" ]] || { echo "No file: $F"; exit 1; }

mapfile -t CFG < <(grep -v '^#' "$F" | head -4)
URI="${CFG[0]}"; BD="${CFG[1]}"; BP="${CFG[2]}"; HASH="${CFG[3]}"

: > oldusers.txt; : > revert.ldif; : > user.txt; : > newpwd.ldif
N=0

while IFS= read -r L; do
  L=$(echo "$L" | xargs)
  [[ -z "$L" || "$L" == \#* ]] && continue
  DN="${L%% *}"
  UID_VAL="${DN#uid=}"; UID_VAL="${UID_VAL%%,*}"

  # Only build revert entry if an old hash was provided after the DN
  if [[ "$L" == *" "* ]]; then
    OH="${L#* }"
    echo "$UID_VAL $OH" >> oldusers.txt
    printf "dn: %s\nchangetype: modify\nreplace: userPassword\nuserPassword: %s\n\n" "$DN" "$OH" >> revert.ldif
  else
    echo "NOTICE: $UID_VAL has no old hash — skipping revert entry"
  fi

  PW=$(openssl rand -base64 18)
  printf "dn: %s\nchangetype: modify\nreplace: userPassword\nuserPassword: %s\n\n" "$DN" "$(slappasswd -h "$HASH" -s "$PW")" >> newpwd.ldif
  echo "$UID_VAL,$PW" >> user.txt
  ((++N))
done < <(grep -v '^#' "$F" | tail -n +5)

echo "Done: $N prepared"
echo "APPLY:  ldapmodify -x -H $URI -D '$BD' -w '$BP' -f newpwd.ldif"
echo "REVERT: ldapmodify -x -H $URI -D '$BD' -w '$BP' -f revert.ldif"
