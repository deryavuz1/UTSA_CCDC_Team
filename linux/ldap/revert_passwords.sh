# First do - sudo slapcat | grep -e "dn: " -e "userPassword:: "  > old-pass.txt

#!/bin/bash

FILENAME="old-pass.txt"
LDAP_SERVER="ldap://pokedap.oak.org" # CHANGE ME
ADMIN_DN="cn=admin,dc=oak,dc=org" # CHANGE ME
ADMIN_PASS="P@ssw0rd"

while IFS= read -r orig_user_dn; do
        IFS= read -r orig_pass_hash

        USER_DN=$(echo "$orig_user_dn" | cut -c5-)
        PASS_HASH_STR=$(echo "$orig_pass_hash" | cut -c15-)
        PASS_HASH=$(echo $PASS_HASH_STR | base64 -d)

        LDIF_FILE="/tmp/$PASS_HASH.ldif"
        cat <<EOF > "$LDIF_FILE"
dn: $USER_DN
changetype: modify
replace: userPassword
userPassword: $PASS_HASH
EOF

        ldapmodify -H $LDAP_SERVER -x -D $ADMIN_DN -w $ADMIN_PASS -f $LDIF_FILE
        rm $LDIF_FILE


done < "$FILENAME"

