#!/usr/bin/env bash
# modules/07_admin_passwd.sh — Change admin passwords (LDAP + Kerberos)
# Handles: LDAP admin, Kerberos admin principal, cn=krbadmin LDAP service account + keyfile
# Entry point: admin_passwd_main

# ── Environment detection ──────────────────────────────────────────────────────

# Returns "local" (kadmin.local available), "remote" (only kadmin), or "none"
_detect_kadmin_mode() {
    if command -v kadmin.local &>/dev/null && kadmin.local -q "listprincs" &>/dev/null 2>&1; then
        echo "local"
    elif command -v kadmin &>/dev/null; then
        echo "remote"
    else
        echo "none"
    fi
}

# Returns 0 if KDC is using LDAP backend (kldap)
_kdc_uses_ldap() {
    grep -qsP 'db_library\s*=\s*kldap' /etc/krb5.conf /etc/krb5.conf.d/*.conf 2>/dev/null
}

_get_krbadmin_dn() {
    grep -hPo '(?<=ldap_kdc_dn = )\S+' /etc/krb5.conf /etc/krb5.conf.d/*.conf 2>/dev/null | head -1
}

_get_keyfile_path() {
    grep -hPo '(?<=ldap_service_password_file = )\S+' /etc/krb5.conf /etc/krb5.conf.d/*.conf 2>/dev/null | head -1
}

_restart_kdc() {
    local svc
    for svc in krb5kdc krb5-kdc; do
        if systemctl is-active --quiet "$svc" 2>/dev/null || \
           systemctl list-units --type=service 2>/dev/null | grep -q "${svc}.service"; then
            info "Restarting ${svc}..."
            systemctl restart "$svc" 2>&1 | while IFS= read -r line; do echo "  $line"; done
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                success "KDC restarted successfully."
            else
                error "KDC restart failed — check: systemctl status ${svc}"
            fi
            return
        fi
    done
    warn "Could not detect KDC service name. Restart krb5kdc/krb5-kdc manually."
}

# ── Password prompt helper ─────────────────────────────────────────────────────
# _prompt_new_password <varname_result> [<prompt_label>]
# Stores confirmed new password in varname_result.
_prompt_new_password() {
    local _var="$1"
    local _label="${2:-target}"
    local _pw _pw2
    while true; do
        read -rsp "  New password for ${_label}: " _pw; echo
        read -rsp "  Confirm new password: " _pw2; echo
        if [[ "$_pw" == "$_pw2" ]]; then
            printf -v "$_var" '%s' "$_pw"
            return 0
        fi
        warn "Passwords do not match — try again."
        echo
    done
}

# ── LDAP admin password ────────────────────────────────────────────────────────
# Optional arg $1: preset new password (skips prompt, used by change-both flow)
_change_ldap_admin_password() {
    header "Change LDAP Admin Password"
    echo

    local target_dn auth_dn auth_pw new_pw
    local preset_pw="${1:-}"

    echo -e "  ${BOLD}Target DN (whose password to change):${RESET}"
    read -rp "  DN [${BIND_DN}]: " target_dn
    [[ -z "$target_dn" ]] && target_dn="$BIND_DN"

    echo
    echo -e "  ${BOLD}Authenticating as (bind DN with write access):${RESET}"
    read -rp "  Auth DN [${BIND_DN}]: " auth_dn
    [[ -z "$auth_dn" ]] && auth_dn="$BIND_DN"
    read -rsp "  Auth password: " auth_pw; echo

    echo
    if [[ -n "$preset_pw" ]]; then
        new_pw="$preset_pw"
        info "Using shared password for LDAP admin."
    else
        _prompt_new_password new_pw "${target_dn}"
    fi

    echo
    info "Applying LDAP password change for ${target_dn}..."
    echo

    LDAPTLS_CACERT="${LDAP_CACERT}" \
    ldappasswd -x -H "${LDAP_URI}" \
        -D "${auth_dn}" -w "${auth_pw}" \
        -s "${new_pw}" \
        "${target_dn}" 2>&1 | while IFS= read -r line; do echo "  $line"; done
    local rc="${PIPESTATUS[0]}"

    echo
    if [[ "$rc" -eq 0 ]]; then
        success "LDAP admin password changed successfully."
        if [[ "$target_dn" == "$BIND_DN" ]] && [[ -f "${SESSION_DIR}/env.conf" ]]; then
            echo
            read -rp "  Update saved session bind password? [y/N]: " upd
            if [[ "${upd,,}" == "y" ]]; then
                BIND_PW="$new_pw"
                save_env_conf
                success "Session env.conf updated."
            fi
        fi
    else
        error "ldappasswd exited with code ${rc} — check output above."
    fi
    return "$rc"
}

# ── Kerberos admin principal password ─────────────────────────────────────────
# Optional arg $1: preset new password (skips prompt, used by change-both flow)
_change_krb5_admin_password() {
    header "Change Kerberos Admin Password"
    echo

    local kadmin_mode; kadmin_mode=$(_detect_kadmin_mode)

    if [[ "$kadmin_mode" == "none" ]]; then
        error "Neither kadmin.local nor kadmin found — install krb5-user / krb5-workstation."
        return 1
    fi

    local preset_pw="${1:-}"
    local principal new_pw old_pw

    echo -e "  ${BOLD}Admin principal to change:${RESET}"
    read -rp "  Principal [${KADMIN_PRINCIPAL}]: " principal
    [[ -z "$principal" ]] && principal="$KADMIN_PRINCIPAL"

    if [[ -n "$preset_pw" ]]; then
        new_pw="$preset_pw"
        info "Using shared password for Kerberos admin."
    else
        echo
        _prompt_new_password new_pw "${principal}"
    fi

    echo
    info "Changing Kerberos password for ${principal} (using kadmin.${kadmin_mode})..."
    echo

    if [[ "$kadmin_mode" == "local" ]]; then
        # kadmin.local: runs directly against KDC database, no auth needed
        kadmin.local -q "cpw -pw ${new_pw} ${principal}" 2>&1 | \
            while IFS= read -r line; do echo "  $line"; done
    else
        # Remote kadmin: need current credentials
        echo
        read -rsp "  Current password for ${principal}: " old_pw; echo
        echo
        kadmin -p "${principal}" -w "${old_pw}" \
            -q "cpw -pw ${new_pw} ${principal}" 2>&1 | \
            while IFS= read -r line; do echo "  $line"; done
    fi
    local rc="${PIPESTATUS[0]}"

    echo
    if [[ "$rc" -eq 0 ]]; then
        success "Kerberos admin password changed successfully."
    else
        error "kadmin exited with code ${rc} — check output above."
    fi
    return "$rc"
}

# ── cn=krbadmin LDAP service account + keyfile ─────────────────────────────────
# This is the account the KDC uses to bind to LDAP. Changing it requires:
#   1. ldappasswd to update the LDAP entry
#   2. kdb5_ldap_util stashsrvpw to update the keyfile
#   3. KDC restart to pick up the new keyfile
_change_krbadmin_password() {
    header "Change KDC LDAP Service Account (cn=krbadmin)"
    echo

    if ! _kdc_uses_ldap; then
        warn "KDC does not appear to use LDAP backend (db_library != kldap)."
        warn "This operation is not needed for file-based KDC databases."
        press_enter
        return 0
    fi

    if ! command -v kdb5_ldap_util &>/dev/null; then
        error "kdb5_ldap_util not found — install krb5-kdc-ldap / krb5-server-ldap."
        return 1
    fi

    local krbadmin_dn; krbadmin_dn=$(_get_krbadmin_dn)
    local keyfile; keyfile=$(_get_keyfile_path)

    if [[ -z "$krbadmin_dn" ]]; then
        error "Could not detect ldap_kdc_dn from krb5.conf."
        return 1
    fi
    if [[ -z "$keyfile" ]]; then
        error "Could not detect ldap_service_password_file from krb5.conf."
        return 1
    fi

    echo -e "  ${YELLOW}${BOLD}WARNING:${RESET} This changes the KDC's LDAP bind credentials."
    echo -e "  ${DIM}If the keyfile update fails, the KDC will lose LDAP access on restart.${RESET}"
    echo
    echo -e "  ${BOLD}Service DN:${RESET} ${krbadmin_dn}"
    echo -e "  ${BOLD}Keyfile:${RESET}    ${keyfile}"
    echo
    confirm "Proceed?" || { warn "Cancelled."; return 0; }
    echo

    local auth_dn auth_pw new_pw

    echo -e "  ${BOLD}Authenticate to LDAP (needs write access to ${krbadmin_dn}):${RESET}"
    read -rp "  Auth DN [${BIND_DN}]: " auth_dn
    [[ -z "$auth_dn" ]] && auth_dn="$BIND_DN"
    read -rsp "  Auth password: " auth_pw; echo

    echo
    _prompt_new_password new_pw "${krbadmin_dn}"
    echo

    # Step 1: Change password in LDAP
    info "Step 1/3 — Updating LDAP entry for ${krbadmin_dn}..."
    echo
    LDAPTLS_CACERT="${LDAP_CACERT}" \
    ldappasswd -x -H "${LDAP_URI}" \
        -D "${auth_dn}" -w "${auth_pw}" \
        -s "${new_pw}" \
        "${krbadmin_dn}" 2>&1 | while IFS= read -r line; do echo "  $line"; done
    local rc="${PIPESTATUS[0]}"

    if [[ "$rc" -ne 0 ]]; then
        error "ldappasswd failed (code ${rc}) — keyfile NOT updated. KDC unchanged."
        return "$rc"
    fi
    success "LDAP entry updated."
    echo

    # Step 2: Re-stash password into keyfile
    info "Step 2/3 — Stashing new password into keyfile..."
    echo
    # kdb5_ldap_util stashsrvpw prompts twice: password + confirm
    printf '%s\n%s\n' "${new_pw}" "${new_pw}" | \
        kdb5_ldap_util stashsrvpw -f "${keyfile}" "${krbadmin_dn}" 2>&1 | \
        while IFS= read -r line; do echo "  $line"; done
    rc="${PIPESTATUS[1]}"  # exit code of kdb5_ldap_util (after the pipe from printf)

    if [[ "$rc" -ne 0 ]]; then
        error "kdb5_ldap_util stashsrvpw failed (code ${rc})."
        error "LDAP password was changed but keyfile is stale — KDC will fail on restart!"
        warn "Manually run: kdb5_ldap_util stashsrvpw -f ${keyfile} ${krbadmin_dn}"
        return "$rc"
    fi
    success "Keyfile updated: ${keyfile}"
    echo

    # Step 3: Restart KDC
    info "Step 3/3 — Restarting KDC to load new keyfile..."
    echo
    _restart_kdc
    echo

    return 0
}

# ── Change both LDAP admin + Kerberos admin ────────────────────────────────────
_change_both() {
    echo
    echo -e "  ${BOLD}Use the same new password for both LDAP and Kerberos?${RESET}"
    echo -e "  ${DIM}(Recommended if services use LDAP PLAIN auth fallback)${RESET}"
    echo
    read -rp "  Same password for both? [Y/n]: " same_ans

    if [[ "${same_ans,,}" != "n" ]]; then
        local shared_pw
        _prompt_new_password shared_pw "LDAP admin + Kerberos admin"
        echo
        _change_ldap_admin_password "$shared_pw"
        echo
        if [[ "$KRB5_ENABLED" != "true" ]]; then
            warn "Kerberos not enabled in session — skipping krb5 change."
        else
            _change_krb5_admin_password "$shared_pw"
        fi
    else
        _change_ldap_admin_password
        echo
        if [[ "$KRB5_ENABLED" != "true" ]]; then
            warn "Kerberos not enabled in session — skipping krb5 change."
        else
            _change_krb5_admin_password
        fi
    fi
}

# ── Main entry point ───────────────────────────────────────────────────────────
admin_passwd_main() {
    local kadmin_mode; kadmin_mode=$(_detect_kadmin_mode)
    local has_kldap=false
    _kdc_uses_ldap && has_kldap=true

    while true; do
        clear
        header "Change Admin Passwords"
        echo
        echo -e "  ${CYAN}1)${RESET}  Change LDAP admin password        (ldappasswd)"
        echo -e "  ${CYAN}2)${RESET}  Change Kerberos admin password     (kadmin.${kadmin_mode})"
        echo -e "  ${CYAN}3)${RESET}  Change both                        (optionally same password)"
        if [[ "$has_kldap" == "true" ]]; then
            echo -e "  ${CYAN}4)${RESET}  ${YELLOW}Change KDC LDAP service account${RESET}   (krbadmin + keyfile + KDC restart)"
            echo -e "  ${CYAN}5)${RESET}  Back"
        else
            echo -e "  ${CYAN}4)${RESET}  Back"
        fi
        echo
        if [[ "$kadmin_mode" == "local" ]]; then
            echo -e "  ${DIM}kadmin mode: local (no admin password required)${RESET}"
        elif [[ "$kadmin_mode" == "remote" ]]; then
            echo -e "  ${DIM}kadmin mode: remote (admin password required)${RESET}"
        else
            echo -e "  ${YELLOW}kadmin not found — Kerberos options unavailable${RESET}"
        fi
        echo
        read -rp "  Choice: " c
        echo
        case "$c" in
            1)
                _change_ldap_admin_password
                press_enter
                ;;
            2)
                if [[ "$KRB5_ENABLED" != "true" ]]; then
                    warn "Kerberos is not enabled in the current session."
                elif [[ "$kadmin_mode" == "none" ]]; then
                    error "kadmin not found."
                else
                    _change_krb5_admin_password
                fi
                press_enter
                ;;
            3)
                _change_both
                press_enter
                ;;
            4)
                if [[ "$has_kldap" == "true" ]]; then
                    _change_krbadmin_password
                    press_enter
                else
                    return
                fi
                ;;
            5)
                [[ "$has_kldap" == "true" ]] && return
                warn "Invalid choice." ; sleep 0.3
                ;;
            *) warn "Invalid choice." ; sleep 0.3 ;;
        esac
    done
}
