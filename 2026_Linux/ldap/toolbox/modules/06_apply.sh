#!/usr/bin/env bash
# modules/06_apply.sh — Apply changes with explicit confirmation
# Applies changes.ldif via ldapmodify using admin credentials.
# The Kerberos script is NEVER auto-run — must be run manually.
# Entry point: apply_main

_print_apply_warning() {
    echo
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}${BOLD}║               !! DESTRUCTIVE OPERATION !!                ║${RESET}"
    echo -e "${RED}${BOLD}║                                                          ║${RESET}"
    echo -e "${RED}${BOLD}║  This will IMMEDIATELY apply changes.ldif to LDAP.      ║${RESET}"
    echo -e "${RED}${BOLD}║  All selected users' passwords and SSH keys will change. ║${RESET}"
    echo -e "${RED}${BOLD}║                                                          ║${RESET}"
    echo -e "${RED}${BOLD}║  • Make sure you have saved new_passwords.txt first      ║${RESET}"
    echo -e "${RED}${BOLD}║  • revert.ldif can undo this if needed                  ║${RESET}"
    echo -e "${RED}${BOLD}║  • Kerberos (krb5_changes.sh) is NOT run automatically  ║${RESET}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
    echo
}

_apply_ldif() {
    local ldif_file="$1"
    local apply_dn apply_pw

    echo "  The bind DN used for writes needs write access (admin or equivalent)."
    echo -e "  Current read bind DN: ${DIM}${BIND_DN}${RESET}"
    echo
    read -rp "  Use a different DN for writes? [y/N]: " use_other
    if [[ "${use_other,,}" == "y" ]]; then
        read -rp "  Write DN: " apply_dn
        read -rsp "  Write password: " apply_pw; echo
    else
        apply_dn="$BIND_DN"
        read -rsp "  Password for ${apply_dn}: " apply_pw; echo
    fi

    echo
    info "Applying ${ldif_file}..."
    echo

    LDAPTLS_CACERT="${LDAP_CACERT}" \
    ldapmodify -x -H "${LDAP_URI}" -D "${apply_dn}" -w "${apply_pw}" \
        -f "$ldif_file" 2>&1 | while IFS= read -r line; do
            echo "  $line"
        done
    local rc="${PIPESTATUS[0]}"

    echo
    if [[ "$rc" -eq 0 ]]; then
        success "ldapmodify completed successfully (exit code 0)"
    else
        error "ldapmodify exited with code ${rc} — check output above for errors"
        warn "If some entries failed, revert.ldif may partially revert changes."
    fi
    return "$rc"
}

_show_apply_summary() {
    local out="${SESSION_DIR}/output"
    echo
    echo -e "  ${BOLD}Session:${RESET}  ${SESSION_NAME}"
    echo -e "  ${BOLD}LDAP URI:${RESET} ${LDAP_URI}"
    echo
    echo "  Files to apply:"

    if [[ -f "${out}/changes.ldif" ]]; then
        local changes
        changes=$(grep -c "^changetype:" "${out}/changes.ldif" 2>/dev/null || echo "?")
        echo -e "    ${GREEN}✓${RESET}  changes.ldif   (${changes} modification(s))"
    else
        echo -e "    ${RED}✗${RESET}  changes.ldif   NOT FOUND — run workflow first"
    fi

    if [[ "$KRB5_ENABLED" == "true" ]] && [[ -f "${out}/krb5_changes.sh" ]]; then
        local krb_count
        krb_count=$(grep -c "^_change " "${out}/krb5_changes.sh" 2>/dev/null || echo "?")
        echo -e "    ${YELLOW}!${RESET}  krb5_changes.sh (${krb_count} principal(s)) — MANUAL RUN REQUIRED"
    fi

    echo
    echo -e "  Revert available: ${out}/revert.ldif"
    echo
}

apply_main() {
    header "Apply Changes"
    _print_apply_warning

    local out="${SESSION_DIR}/output"
    [[ -f "${out}/changes.ldif" ]] || {
        error "changes.ldif not found. Run the full workflow first."
        press_enter
        return
    }

    _show_apply_summary

    # First confirmation
    echo -e "  ${BOLD}${RED}Type 'APPLY' (all caps) to confirm you want to modify LDAP:${RESET}"
    read -rp "  > " confirm_str
    if [[ "$confirm_str" != "APPLY" ]]; then
        warn "Cancelled — LDAP was not modified."
        press_enter
        return
    fi

    # Second confirmation: show the changes.ldif summary
    echo
    echo -e "  ${BOLD}Preview of changes.ldif (first 40 lines):${RESET}"
    head -40 "${out}/changes.ldif" | while IFS= read -r line; do
        echo "    $line"
    done
    echo
    echo -e "  ${BOLD}${RED}Final confirmation — type 'YES' to proceed:${RESET}"
    read -rp "  > " final_str
    if [[ "$final_str" != "YES" ]]; then
        warn "Cancelled."
        press_enter
        return
    fi

    _apply_ldif "${out}/changes.ldif"
    local rc=$?

    echo
    if [[ "$KRB5_ENABLED" == "true" ]]; then
        echo
        warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        warn "Kerberos passwords were NOT changed automatically."
        warn "Run the script manually:"
        warn "  bash ${out}/krb5_changes.sh"
        warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    fi

    press_enter
    return "$rc"
}
