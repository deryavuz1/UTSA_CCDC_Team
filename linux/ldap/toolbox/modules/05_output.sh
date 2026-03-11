#!/usr/bin/env bash
# modules/05_output.sh — Generate all output files
# Outputs: new_passwords.txt, old_hashes.txt, changes.ldif, revert.ldif,
#          krb5_changes.sh (if Kerberos detected), and copies SSH keys.
# Entry point: output_main

OUT="${SESSION_DIR}/output"
GEN="${SESSION_DIR}/gen"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# ── PCR password files ────────────────────────────────────────────────────────
_gen_pcr_files() {
    local new_file="${OUT}/new_passwords.txt"
    local old_file="${OUT}/old_hashes.txt"

    {
        echo "# PCR — New Passwords"
        echo "# Generated: ${TIMESTAMP}"
        echo "# Session:   ${SESSION_NAME}"
        echo "# Format:    username,plaintext_password"
        echo "#"
        echo "# !! SENSITIVE — handle with care !!"
        echo "username,password"
    } > "$new_file"

    {
        echo "# PCR — Old SSHA Hashes (pre-change)"
        echo "# Generated: ${TIMESTAMP}"
        echo "# Session:   ${SESSION_NAME}"
        echo "# Format:    username,{SSHA}hash"
        echo "# Use these values in revert.ldif to restore original passwords."
        echo "username,ssha_hash"
    } > "$old_file"

    while IFS= read -r uid; do
        local pass_file="${GEN}/${uid}.pass"
        [[ -f "$pass_file" ]] || continue   # skip if no password generated (skipped user)

        local newpass; newpass=$(cat "$pass_file")
        echo "${uid},${newpass}" >> "$new_file"

        local old_ssha=""
        [[ -f "${SESSION_DIR}/user_data/${uid}.ssha" ]] && \
            old_ssha=$(cat "${SESSION_DIR}/user_data/${uid}.ssha")
        echo "${uid},${old_ssha:-NO_HASH_CAPTURED}" >> "$old_file"

    done < "${SESSION_DIR}/users.list"

    success "  new_passwords.txt"
    success "  old_hashes.txt"
}

# ── LDAP changes LDIF ─────────────────────────────────────────────────────────
_gen_changes_ldif() {
    local ldif_file="${OUT}/changes.ldif"

    {
        echo "# LDAP Changes LDIF"
        echo "# Generated: ${TIMESTAMP}"
        echo "# Session:   ${SESSION_NAME}"
        echo "#"
        echo "# !! WARNING: Review carefully before applying !!"
        echo "# !! This file changes LDAP passwords and SSH keys !!"
        echo "#"
        echo "# Apply with:"
        echo "#   ldapmodify -x -H '${LDAP_URI}' -D '${BIND_DN}' -W -f changes.ldif"
        echo "# Or use option 4 (Apply Changes) in the toolbox."
        echo ""
    } > "$ldif_file"

    local count=0
    while IFS= read -r uid; do
        local pass_file="${GEN}/${uid}.pass"
        local pub_file="${GEN}/${uid}.pub"
        [[ -f "$pass_file" ]] || continue

        local newpass; newpass=$(cat "$pass_file")
        local new_ssha; new_ssha=$(gen_ssha_hash "$newpass")

        # Load user DN
        local DN=""
        # shellcheck source=/dev/null
        source "${SESSION_DIR}/user_data/${uid}.info" 2>/dev/null
        [[ -z "$DN" ]] && { warn "No DN for ${uid} — skipping"; continue; }

        {
            echo "dn: ${DN}"
            echo "changetype: modify"
            echo "replace: userPassword"
            echo "userPassword: ${new_ssha}"
        } >> "$ldif_file"

        if [[ -f "$pub_file" ]]; then
            local pubkey; pubkey=$(cat "$pub_file")
            {
                echo "-"
                echo "replace: ${SSH_ATTR}"
                echo "${SSH_ATTR}: ${pubkey}"
            } >> "$ldif_file"
        fi

        echo "" >> "$ldif_file"
        ((count++)) || true

    done < "${SESSION_DIR}/users.list"

    success "  changes.ldif  (${count} user modification(s))"
}

# ── Revert LDIF ────────────────────────────────────────────────────────────────
_gen_revert_ldif() {
    local ldif_file="${OUT}/revert.ldif"

    {
        echo "# REVERT LDIF — Restores passwords and SSH keys to pre-change state"
        echo "# Generated: ${TIMESTAMP}"
        echo "# Session:   ${SESSION_NAME}"
        echo "#"
        echo "# !! DANGER: Applying this file UNDOES all password changes !!"
        echo "# !! Only run this if you need to rollback !!"
        echo "#"
        echo "# Apply with:"
        echo "#   ldapmodify -x -H '${LDAP_URI}' -D '${BIND_DN}' -W -f revert.ldif"
        echo ""
    } > "$ldif_file"

    local count=0
    while IFS= read -r uid; do
        local pass_file="${GEN}/${uid}.pass"
        [[ -f "$pass_file" ]] || continue

        local DN=""
        # shellcheck source=/dev/null
        source "${SESSION_DIR}/user_data/${uid}.info" 2>/dev/null
        [[ -z "$DN" ]] && continue

        local old_ssha=""
        [[ -f "${SESSION_DIR}/user_data/${uid}.ssha" ]] && \
            old_ssha=$(cat "${SESSION_DIR}/user_data/${uid}.ssha")

        {
            echo "dn: ${DN}"
            echo "changetype: modify"
        } >> "$ldif_file"

        if [[ -n "$old_ssha" ]]; then
            {
                echo "replace: userPassword"
                echo "userPassword: ${old_ssha}"
            } >> "$ldif_file"
        else
            {
                echo "# WARNING: No old password hash captured for ${uid}"
                echo "# Cannot revert userPassword for this user"
            } >> "$ldif_file"
        fi

        # Old SSH key
        local old_sshkey=""
        [[ -f "${SESSION_DIR}/user_data/${uid}.sshkey" ]] && \
            old_sshkey=$(cat "${SESSION_DIR}/user_data/${uid}.sshkey")

        if [[ -n "$old_sshkey" ]]; then
            {
                echo "-"
                echo "replace: ${SSH_ATTR}"
                echo "${SSH_ATTR}: ${old_sshkey}"
            } >> "$ldif_file"
        elif [[ "${HAS_SSH:-0}" == "0" ]]; then
            {
                echo "-"
                echo "delete: ${SSH_ATTR}"
            } >> "$ldif_file"
        fi

        echo "" >> "$ldif_file"
        ((count++)) || true

    done < "${SESSION_DIR}/users.list"

    success "  revert.ldif   (${count} user restoration(s))"
}

# ── Kerberos change script ─────────────────────────────────────────────────────
_gen_krb5_script() {
    [[ "$KRB5_ENABLED" == "true" ]] || return 0

    local krb_file="${OUT}/krb5_changes.sh"

    {
        cat <<SCRIPT_HEADER
#!/usr/bin/env bash
# Kerberos Password Changes
# Generated: ${TIMESTAMP}
# Session:   ${SESSION_NAME}
# Realm:     ${KRB5_REALM}
#
# !! WARNING: This script changes Kerberos passwords !!
# !! Review before running — it cannot be auto-applied by the toolbox !!
# !! Run manually after applying changes.ldif !!
#
# Usage: bash krb5_changes.sh
set -uo pipefail

REALM='${KRB5_REALM}'
KADMIN_PRINCIPAL='${KADMIN_PRINCIPAL}'

echo ""
echo "  Kerberos Password Change Script"
echo "  Realm: \${REALM}"
echo "  Admin: \${KADMIN_PRINCIPAL}"
echo ""
read -rsp "  Enter kadmin/admin Kerberos password: " KADMIN_PASS
echo ""
echo ""

_kadmin() {
    kadmin -p "\${KADMIN_PRINCIPAL}" -w "\${KADMIN_PASS}" -q "\$1" 2>&1
}

_change() {
    local user="\$1" pass="\$2"
    local cmd
    # Use printf to build the command string — avoids shell re-interpretation of \$
    cmd=\$(printf 'cpw -pw %s %s@%s' "\${pass}" "\${user}" "\${REALM}")
    if _kadmin "\${cmd}" | grep -qi "changed\\."; then
        echo -e "  \\033[0;32m[✓]\\033[0m \${user}@\${REALM}"
    else
        echo -e "  \\033[0;31m[✗]\\033[0m \${user}@\${REALM} — FAILED (check kadmin output above)"
    fi
}

echo "  Changing passwords..."
echo ""
SCRIPT_HEADER
    } > "$krb_file"

    local count=0
    while IFS= read -r uid; do
        local pass_file="${GEN}/${uid}.pass"
        [[ -f "$pass_file" ]] || continue

        local newpass; newpass=$(cat "$pass_file")
        # Single-quote the password in the script to prevent any shell interpretation
        # Our charset (A-HJ-NP-Za-km-z2-9@#!) never contains single quotes.
        printf "PASS_%s='%s'\n" "$uid" "$newpass" >> "$krb_file"
        printf '_change "%s" "${PASS_%s}"\n' "$uid" "$uid" >> "$krb_file"
        printf '\n' >> "$krb_file"
        ((count++)) || true
    done < "${SESSION_DIR}/users.list"

    cat >> "$krb_file" <<'SCRIPT_FOOTER'
echo ""
echo "  Done. Verify with: kinit <user> && klist"
echo ""
SCRIPT_FOOTER

    chmod +x "$krb_file"
    success "  krb5_changes.sh  (${count} principal(s))"
}

# ── Copy SSH keys to output ────────────────────────────────────────────────────
_copy_ssh_keys() {
    local key_out="${OUT}/sshkeys"
    mkdir -p "$key_out"
    local count=0
    while IFS= read -r uid; do
        local priv="${SESSION_DIR}/sshkeys/${uid}"
        local pub="${SESSION_DIR}/sshkeys/${uid}.pub"
        if [[ -f "$priv" ]]; then
            cp "$priv" "${key_out}/${uid}"
            cp "$pub"  "${key_out}/${uid}.pub"
            chmod 600  "${key_out}/${uid}"
            ((count++)) || true
        fi
    done < "${SESSION_DIR}/users.list"
    [[ $count -gt 0 ]] && success "  sshkeys/  (${count} keypair(s))"
}

# ── Main entry point ───────────────────────────────────────────────────────────
output_main() {
    header "Generating Output Files"
    echo
    mkdir -p "$OUT"

    _gen_pcr_files
    _gen_changes_ldif
    _gen_revert_ldif
    _gen_krb5_script
    _copy_ssh_keys

    echo
    success "All output files written to:"
    echo -e "  ${CYAN}${OUT}/${RESET}"
    echo
    echo "  Files:"
    for f in new_passwords.txt old_hashes.txt changes.ldif revert.ldif krb5_changes.sh; do
        local fp="${OUT}/${f}"
        if [[ -f "$fp" ]]; then
            printf "    %-22s  %s\n" "$f" "$(wc -l < "$fp") lines"
        fi
    done
    local keys
    keys=$(ls "${OUT}/sshkeys/"*.pub 2>/dev/null | wc -l)
    [[ "$keys" -gt 0 ]] && printf "    %-22s  %s keypairs\n" "sshkeys/" "$keys"
    echo
    warn "changes.ldif and krb5_changes.sh will NOT be applied automatically."
    warn "Use option 4 (Apply Changes) to apply changes.ldif with explicit confirmation."
    warn "Run krb5_changes.sh manually after reviewing it."
    echo
}
