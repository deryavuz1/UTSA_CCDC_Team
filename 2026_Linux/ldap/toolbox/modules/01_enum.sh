#!/usr/bin/env bash
# modules/01_enum.sh — Environment enumeration
# Discovers: LDAP connection, users, groups, SSH attr, Kerberos config.
# Entry point: enum_main

# ── Auto-detection ─────────────────────────────────────────────────────────────
_enum_try_sssd_conf() {
    local conf="/etc/sssd/sssd.conf"
    [[ -f "$conf" ]] || return 1
    LDAP_URI=$(grep -Po '(?<=ldap_uri\s=\s).*' "$conf" 2>/dev/null | head -1 | tr -d ' ')
    BIND_DN=$(grep -Po '(?<=ldap_default_bind_dn\s=\s).*' "$conf" 2>/dev/null | head -1 | tr -d ' ')
    BIND_PW=$(grep -Po '(?<=ldap_default_authtok\s=\s).*' "$conf" 2>/dev/null | head -1 | tr -d ' ')
    BASE_DN=$(grep -Po '(?<=ldap_search_base\s=\s).*' "$conf" 2>/dev/null | head -1 | tr -d ' ')
    LDAP_CACERT=$(grep -Po '(?<=ldap_tls_cacert\s=\s).*' "$conf" 2>/dev/null | head -1 | tr -d ' ')
    local ssh_attr
    ssh_attr=$(grep -Po '(?<=ldap_user_ssh_public_key\s=\s).*' "$conf" 2>/dev/null | head -1 | tr -d ' ')
    [[ -n "$ssh_attr" ]] && SSH_ATTR="$ssh_attr"
    [[ -n "$LDAP_URI" && -n "$BIND_DN" && -n "$BIND_PW" && -n "$BASE_DN" ]]
}

_enum_try_ldap_conf() {
    local conf="/etc/ldap/ldap.conf"
    [[ -f "$conf" ]] || return 1
    local uri base
    uri=$(grep -i "^URI " "$conf" 2>/dev/null | awk '{print $2}')
    base=$(grep -i "^BASE " "$conf" 2>/dev/null | awk '{print $2}')
    [[ -n "$uri" ]] && LDAP_URI="$uri"
    [[ -n "$base" ]] && BASE_DN="$base"
    [[ -n "$LDAP_URI" && -n "$BASE_DN" ]]
}

_enum_try_krb5_conf() {
    local conf="/etc/krb5.conf"
    [[ -f "$conf" ]] || return 1
    KRB5_REALM=$(grep -Po '(?<=default_realm\s=\s)\S+' "$conf" 2>/dev/null | head -1)
    KRB5_KDC=$(grep -A5 '\[realms\]' "$conf" 2>/dev/null \
        | grep -Po '(?<=kdc\s=\s)\S+' | head -1)
    [[ -n "$KRB5_REALM" ]]
}

# ── LDAP discovery helpers ──────────────────────────────────────────────────────
_gid_to_group() {
    local gid="$1"
    ldap_search -b "$BASE_DN" "(&(objectClass=posixGroup)(gidNumber=${gid}))" cn \
        | grep "^cn: " | head -1 | sed 's/^cn: //'
}

_get_user_groups() {
    local uid="$1"
    ldap_search -b "$BASE_DN" "(&(objectClass=posixGroup)(memberUid=${uid}))" cn \
        | grep "^cn: " | awk '{print $2}' | sort | paste -sd ','
}

_check_kerberos_in_ldap() {
    # Check if any entries have krbPrincipalName or krbPrincipalReferences
    local count
    count=$(ldap_search -b "$BASE_DN" \
        "(|(objectClass=krbPrincipal)(objectClass=krbPrincRefAux)(krbPrincipalName=*))" dn \
        | grep -c "^dn:" 2>/dev/null || true)
    [[ "${count:-0}" -gt 0 ]]
}

_find_user_ous() {
    # Return all OUs that contain at least one posixAccount
    ldap_search -b "$BASE_DN" "(objectClass=organizationalUnit)" dn \
        | grep "^dn: " | sed 's/^dn: //' | while read -r ou_dn; do
            local cnt
            cnt=$(ldap_search -b "$ou_dn" -s one \
                "(objectClass=${USER_OBJECT_CLASS})" dn 2>/dev/null \
                | grep -c "^dn:" 2>/dev/null || true)
            [[ "${cnt:-0}" -gt 0 ]] && echo "$ou_dn"
        done
}

# ── Credential prompting ───────────────────────────────────────────────────────
_prompt_ldap_creds() {
    header "LDAP Connection Setup"
    echo "  Auto-detection failed or is incomplete. Please provide:"
    echo
    [[ -z "$LDAP_URI" ]] && read -rp "  LDAP URI (e.g. ldaps://dc.example.com): " LDAP_URI
    [[ -z "$BASE_DN" ]]  && read -rp "  Base DN  (e.g. dc=example,dc=com): " BASE_DN
    [[ -z "$BIND_DN" ]]  && read -rp "  Bind DN  (e.g. cn=admin,dc=example,dc=com): " BIND_DN
    [[ -z "$BIND_PW" ]]  && read -rsp "  Bind password: " BIND_PW && echo
    if [[ "$LDAP_URI" == ldaps://* ]]; then
        if [[ -z "$LDAP_CACERT" ]]; then
            read -rp "  CA cert path (blank to use system trust store): " LDAP_CACERT
        fi
    fi
}

# ── Per-user data collection ───────────────────────────────────────────────────
_process_user() {
    local uid="$1"
    local search_base="${USER_OU:-$BASE_DN}"

    local entry
    entry=$(ldap_search -b "$search_base" "(uid=${uid})" \
        dn gidNumber loginShell homeDirectory \
        "${SSH_ATTR}" krbPrincipalName krbPrincipalReferences userPassword 2>/dev/null)

    [[ -z "$entry" ]] && return 1

    local dn gid login_shell home_dir
    dn=$(ldif_attr "dn" "$entry")
    gid=$(ldif_attr "gidNumber" "$entry")
    login_shell=$(ldif_attr "loginShell" "$entry")
    home_dir=$(ldif_attr "homeDirectory" "$entry")

    # SSH key
    local has_ssh=0 ssh_key=""
    if printf '%s\n' "$entry" | grep -qP "^${SSH_ATTR}[: ]"; then
        has_ssh=1
        ssh_key=$(ldif_attr "${SSH_ATTR}" "$entry")
    fi

    # Kerberos principal reference
    local has_krb=0
    if printf '%s\n' "$entry" | grep -qP "^(krbPrincipalName|krbPrincipalReferences)[: ]"; then
        has_krb=1
    fi

    # Old SSHA hash
    local ssha_hash
    ssha_hash=$(ldif_attr "userPassword" "$entry")

    # Group lookups
    local primary_group all_groups
    primary_group=$(_gid_to_group "$gid")
    all_groups=$(_get_user_groups "$uid")
    [[ -z "$all_groups" ]] && all_groups="${primary_group}"

    # Write .info file (KEY=VALUE, safe strings only)
    cat > "${SESSION_DIR}/user_data/${uid}.info" <<EOF
DN=${dn}
PRIMARY_GID=${gid}
PRIMARY_GROUP=${primary_group}
GROUPS=${all_groups}
HAS_SSH=${has_ssh}
HAS_KRB=${has_krb}
LOGIN_SHELL=${login_shell}
HOME_DIR=${home_dir}
EOF

    # Store SSH key and SSHA separately to avoid quoting issues
    [[ -n "$ssh_key" ]]   && printf '%s\n' "$ssh_key"    > "${SESSION_DIR}/user_data/${uid}.sshkey"
    [[ -n "$ssha_hash" ]] && printf '%s'   "$ssha_hash"  > "${SESSION_DIR}/user_data/${uid}.ssha"

    info "  Discovered: ${uid}  [${all_groups}]  SSH=${has_ssh}  KRB=${has_krb}"
}

# ── Service OU management ──────────────────────────────────────────────────────
_handle_service_ous() {
    header "User OUs Discovery"
    echo
    info "Scanning for OUs containing ${USER_OBJECT_CLASS} entries..."
    local found_ous
    mapfile -t found_ous < <(_find_user_ous)

    if [[ ${#found_ous[@]} -eq 0 ]]; then
        warn "No OUs found — will search from base DN directly."
        USER_OU="$BASE_DN"
        return
    fi

    echo "  Found OUs with user entries:"
    for i in "${!found_ous[@]}"; do
        echo "    $((i+1))) ${found_ous[$i]}"
    done
    echo

    # Identify likely login user OU vs service OUs
    local login_ou=""
    for ou in "${found_ous[@]}"; do
        if [[ "$ou" =~ [Pp]eople|[Uu]sers|[Aa]ccounts|[Uu]ser ]]; then
            login_ou="$ou"
        fi
    done

    if [[ -n "$login_ou" ]]; then
        USER_OU="$login_ou"
        info "Auto-selected login OU: ${USER_OU}"
    else
        echo "  Which OU contains login users? (number or paste DN)"
        read -rp "  > " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -le "${#found_ous[@]}" ]]; then
            USER_OU="${found_ous[$((choice-1))]}"
        else
            USER_OU="$choice"
        fi
    fi

    # Mark remaining OUs as service OUs
    SERVICE_OUS=""
    for ou in "${found_ous[@]}"; do
        [[ "$ou" == "$USER_OU" ]] && continue
        warn "  Marking as service OU (excluded): ${ou}"
        SERVICE_OUS="${SERVICE_OUS} ${ou}"
    done
    SERVICE_OUS="${SERVICE_OUS# }"

    # Allow user to add more service/exclusion OUs
    echo
    echo "  Add additional OUs to exclude? (one per line, blank to finish)"
    while true; do
        read -rp "  Exclude OU (or Enter to skip): " extra_ou
        [[ -z "$extra_ou" ]] && break
        SERVICE_OUS="${SERVICE_OUS} ${extra_ou}"
        warn "  Added to exclusions: ${extra_ou}"
    done
    SERVICE_OUS="${SERVICE_OUS# }"
}

# ── Main entry point ───────────────────────────────────────────────────────────
enum_main() {
    header "Environment Enumeration"
    echo

    # ── Step 1: Connection credentials ──
    info "Trying auto-detection from /etc/sssd/sssd.conf..."
    if _enum_try_sssd_conf; then
        success "Auto-detected LDAP credentials from sssd.conf"
    else
        _enum_try_ldap_conf && info "Partial info from /etc/ldap/ldap.conf"
        _prompt_ldap_creds
    fi

    # ── Step 2: Test connection ──
    info "Testing LDAP connection to ${LDAP_URI}..."
    if ! test_ldap_conn; then
        warn "Connection test failed with auto-detected creds. Please verify:"
        _prompt_ldap_creds
        test_ldap_conn || die "LDAP connection failed. Check URI, bind DN, password, and CA cert."
    fi
    success "LDAP connection OK"
    echo

    # ── Step 3: Kerberos detection ──
    info "Checking for Kerberos..."
    if _enum_try_krb5_conf; then
        info "krb5.conf found — realm: ${KRB5_REALM}"
        if _check_kerberos_in_ldap; then
            KRB5_ENABLED="true"
            success "Kerberos principals detected in LDAP — will generate krb5_changes.sh"
        else
            warn "krb5.conf present but no KRB principals found in LDAP"
            KRB5_ENABLED="false"
        fi
    else
        KRB5_ENABLED="false"
        info "No Kerberos configuration detected"
    fi

    # ── Step 4: Discover user OUs ──
    echo
    _handle_service_ous

    # ── Step 5: Discover users ──
    header "Discovering Users"
    echo

    local search_base="${USER_OU:-$BASE_DN}"
    info "Searching ${search_base} for (${USER_OBJECT_CLASS}=*)..."
    echo

    mapfile -t uids < <(ldap_search -b "$search_base" \
        "(objectClass=${USER_OBJECT_CLASS})" uid \
        | grep "^uid: " | awk '{print $2}' | sort -u)

    if [[ ${#uids[@]} -eq 0 ]]; then
        warn "No ${USER_OBJECT_CLASS} entries found in ${search_base}"
        echo "  Try a different object class? (e.g. inetOrgPerson, person — blank to keep ${USER_OBJECT_CLASS})"
        read -rp "  Object class: " alt_class
        if [[ -n "$alt_class" ]]; then
            USER_OBJECT_CLASS="$alt_class"
            mapfile -t uids < <(ldap_search -b "$search_base" \
                "(objectClass=${USER_OBJECT_CLASS})" uid \
                | grep "^uid: " | awk '{print $2}' | sort -u)
        fi
    fi

    [[ ${#uids[@]} -eq 0 ]] && die "No users found. Check USER_OU and USER_OBJECT_CLASS."

    # Clear existing user data for fresh run
    rm -f "${SESSION_DIR}/users.list"
    rm -f "${SESSION_DIR}/user_data/"*.info \
          "${SESSION_DIR}/user_data/"*.sshkey \
          "${SESSION_DIR}/user_data/"*.ssha 2>/dev/null

    local count=0
    for uid in "${uids[@]}"; do
        if _process_user "$uid"; then
            echo "$uid" >> "${SESSION_DIR}/users.list"
            ((count++)) || true
        fi
    done

    echo
    success "Discovered ${count} user(s)"

    # ── Step 6: Summary ──
    echo
    header "Enumeration Summary"
    echo
    echo -e "  LDAP URI:        ${CYAN}${LDAP_URI}${RESET}"
    echo -e "  Base DN:         ${CYAN}${BASE_DN}${RESET}"
    echo -e "  Bind DN:         ${CYAN}${BIND_DN}${RESET}"
    echo -e "  User OU:         ${CYAN}${USER_OU}${RESET}"
    echo -e "  Users found:     ${GREEN}${count}${RESET}"
    echo -e "  Kerberos:        $([[ "$KRB5_ENABLED" == "true" ]] && echo "${GREEN}YES — ${KRB5_REALM}${RESET}" || echo "${DIM}No${RESET}")"
    echo -e "  SSH attr:        ${CYAN}${SSH_ATTR}${RESET}"
    [[ -n "$SERVICE_OUS" ]] && echo -e "  Service OUs:     ${YELLOW}${SERVICE_OUS}${RESET}"
    echo

    save_env_conf
    success "Environment saved to session: ${SESSION_NAME}"
    echo
}
