#!/bin/bash

LDAP_SERVER="ldap://<ldap host>" #CHANGE ME
BASE_DN="dc=<DC>,dc=<DC>" #CHANGE ME
ORG_UNIT="ou=people" #CHANGE ME
ADMIN_DN="cn=<ADMIN DN>,dc=<DC>,dc=<DC>"
ADMIN_PASS="<admin dn password>"
CSV_FILE="users.csv"

tail -n +2 "$CSV_FILE" | while IFS="," read -r username name title department password; do
        if [[ -z "$username" || -z "$name" || -z "$password" ]]; then
                echo "Skipping invalid line: $username,$name,$title,$department,$password"
                continue
        fi

        HASHED_PASS=$(slappasswd -s "$password")

        LDIF_FILE="/tmp/$username.ldif"
        cat <<EOF > "$LDIF_FILE"
dn: uid=$username,$ORG_UNIT,$BASE_DN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: $username
cn: $name
sn: ${name##* }
title: $title
ou: $department
userPassword: $HASHED_PASS
loginShell: /bin/bash
uidNumber: $(shuf -i 1000-9999 -n 1)
gidNumber: 1000
homeDirectory: /home/$username
EOF

        ldapadd -x -D "$ADMIN_DN" -w "$ADMIN_PASS" -H "$LDAP_SERVER" -f "$LDIF_FILE"

        rm -f "$LDIF_FILE"

done

