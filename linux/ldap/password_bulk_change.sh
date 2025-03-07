
#csv is dn: uid=ddiaz,ou=people,dc=oak,dc=org

#!/bin/bash

LDAP_SERVER="ldap://pokedap.oak.org"
ADMIN_DN="cn=admin,dc=oak,dc=org"
ADMIN_PASS="P@ssw0rd"
CSV_FILE="reset.txt"
NEW_PASSWORD="test123"

while IFS= read -r line; do
        STRIPPED_LINE=$(echo "$line" | cut -c5-)
        LDIF_FILE="/tmp/$STRIPPED_LINE.ldif"

        HASHED_PASS=$(slappasswd -s "$NEW_PASSWORD")

        cat <<EOF > "$LDIF_FILE"
dn: $STRIPPED_LINE
changetype: modify
replace: userPassword
userPassword: $HASHED_PASS
EOF

        ldapmodify -H $LDAP_SERVER -x -D $ADMIN_DN -w $ADMIN_PASS -f /tmp/$STRIPPED_LINE.ldif
        rm /tmp/$STRIPPED_LINE.ldif

done < $CSV_FILE
