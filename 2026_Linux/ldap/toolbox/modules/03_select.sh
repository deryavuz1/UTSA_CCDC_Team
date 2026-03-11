#!/usr/bin/env bash
# modules/03_select.sh — Interactive per-user selection menu
# Commands: r <user|all>  n <user|all>  s <user> <password>  done
# Entry point: select_main

SEL_DIR="${SESSION_DIR}/selections"

# ── Selection state helpers ───────────────────────────────────────────────────
_set_sel() {
    local uid="$1" val="$2"
    mkdir -p "$SEL_DIR"
    printf '%s' "$val" > "${SEL_DIR}/${uid}.sel"
}

_get_sel() {
    local uid="$1"
    [[ -f "${SEL_DIR}/${uid}.sel" ]] && cat "${SEL_DIR}/${uid}.sel" || echo "pending"
}

_active_users() {
    # Users in users.list who are NOT filtered
    while IFS= read -r uid; do
        is_filtered "$uid" && continue
        echo "$uid"
    done < "${SESSION_DIR}/users.list"
}

_pending_count() {
    local count=0
    while IFS= read -r uid; do
        local sel; sel=$(_get_sel "$uid")
        [[ "$sel" == "pending" ]] && ((count++)) || true
    done < <(_active_users)
    echo "$count"
}

# ── Display ───────────────────────────────────────────────────────────────────
_draw_table() {
    clear
    print_banner

    # Filtered users summary
    if [[ -s "${SESSION_DIR}/filtered.list" ]]; then
        echo -e "  ${YELLOW}FILTERED (excluded):${RESET}"
        while IFS=: read -r fuid _ fpattern; do
            echo -e "    ${DIM}${fuid}${RESET}  (matched: ${fpattern})"
        done < "${SESSION_DIR}/filtered.list"
        echo -e "  ${DIM}Type 'enable <user>' to include a filtered user.${RESET}"
        echo
    fi

    # Main table header
    printf "  ${BOLD}%-16s %-14s %-5s %-5s %s${RESET}\n" \
        "USER" "GROUP" "SSH" "KRB" "ACTION"
    hr

    while IFS= read -r uid; do
        # Load user info
        local DN="" PRIMARY_GROUP="" HAS_SSH="" HAS_KRB=""
        # shellcheck source=/dev/null
        source "${SESSION_DIR}/user_data/${uid}.info" 2>/dev/null

        local sel; sel=$(_get_sel "$uid")
        local action_str action_color
        case "$sel" in
            pending)    action_str="PENDING";          action_color="$DIM" ;;
            skip)       action_str="SKIP";             action_color="$YELLOW" ;;
            random)     action_str="RANDOM";           action_color="$CYAN" ;;
            set:*)      action_str="SET: ${sel#set:}"; action_color="$GREEN" ;;
            *)          action_str="$sel";             action_color="$DIM" ;;
        esac

        local ssh_icon krb_icon
        [[ "${HAS_SSH:-0}" == "1" ]] && ssh_icon="${GREEN}✓${RESET}" || ssh_icon="${DIM}✗${RESET}"
        [[ "${HAS_KRB:-0}" == "1" ]] && krb_icon="${GREEN}✓${RESET}" || krb_icon="${DIM}✗${RESET}"

        # Print row (non-colored cols via printf, colored inline)
        printf "  %-16s %-14s " "$uid" "${PRIMARY_GROUP:-unknown}"
        echo -ne "${ssh_icon}    ${krb_icon}    "
        echo -e "${action_color}${action_str}${RESET}"
    done < "${SESSION_DIR}/users.list"

    echo
    local pending; pending=$(_pending_count)
    if [[ "$pending" -gt 0 ]]; then
        echo -e "  ${YELLOW}${pending} user(s) still PENDING — set before typing 'done'${RESET}"
    else
        echo -e "  ${GREEN}All active users have actions assigned.${RESET}"
    fi
    echo
    hr
    echo -e "  ${BOLD}Commands:${RESET}"
    echo -e "    ${CYAN}r <user>${RESET}          random password"
    echo -e "    ${CYAN}r all${RESET}             random password for all pending"
    echo -e "    ${CYAN}n <user>${RESET}          skip (no change)"
    echo -e "    ${CYAN}n all${RESET}             skip all pending"
    echo -e "    ${CYAN}s <user> <pass>${RESET}   set specific password"
    echo -e "    ${CYAN}enable <user>${RESET}     re-enable a filtered user"
    echo -e "    ${CYAN}reset <user>${RESET}      clear selection (back to pending)"
    echo -e "    ${CYAN}done${RESET}              proceed to generate output"
    hr
}

# ── Command processing ────────────────────────────────────────────────────────
_process_cmd() {
    local line="$1"
    local cmd arg1 arg2
    read -r cmd arg1 arg2 <<< "$line"

    case "${cmd,,}" in
        r|random)
            if [[ "${arg1,,}" == "all" || -z "$arg1" ]]; then
                while IFS= read -r uid; do
                    [[ "$(_get_sel "$uid")" == "pending" ]] && _set_sel "$uid" "random"
                done < <(_active_users)
                info "Set all pending users to RANDOM"
            else
                if grep -q "^${arg1}$" "${SESSION_DIR}/users.list" 2>/dev/null; then
                    if is_filtered "$arg1"; then
                        warn "${arg1} is filtered. Use 'enable ${arg1}' first."
                    else
                        _set_sel "$arg1" "random"
                        info "${arg1} → RANDOM"
                    fi
                else
                    warn "User not found: ${arg1}"
                fi
            fi
            ;;
        n|skip)
            if [[ "${arg1,,}" == "all" || -z "$arg1" ]]; then
                while IFS= read -r uid; do
                    [[ "$(_get_sel "$uid")" == "pending" ]] && _set_sel "$uid" "skip"
                done < <(_active_users)
                info "Skipped all pending users"
            else
                if grep -q "^${arg1}$" "${SESSION_DIR}/users.list" 2>/dev/null; then
                    _set_sel "$arg1" "skip"
                    info "${arg1} → SKIP"
                else
                    warn "User not found: ${arg1}"
                fi
            fi
            ;;
        s|set)
            if [[ -z "$arg1" ]]; then
                warn "Usage: s <user> <password>"
            elif [[ -z "$arg2" ]]; then
                warn "Usage: s <user> <password>  (password cannot be empty)"
            elif grep -q "^${arg1}$" "${SESSION_DIR}/users.list" 2>/dev/null; then
                if is_filtered "$arg1"; then
                    warn "${arg1} is filtered. Use 'enable ${arg1}' first."
                else
                    _set_sel "$arg1" "set:${arg2}"
                    info "${arg1} → SET: ${arg2}"
                fi
            else
                warn "User not found: ${arg1}"
            fi
            ;;
        enable)
            [[ -z "$arg1" ]] && warn "Usage: enable <user>" && return
            filter_remove_user "$arg1"
            ;;
        reset)
            [[ -z "$arg1" ]] && warn "Usage: reset <user>" && return
            rm -f "${SEL_DIR}/${arg1}.sel"
            info "${arg1} → PENDING"
            ;;
        "")
            ;;  # ignore blank lines
        *)
            warn "Unknown command: ${cmd}. Type 'done' to proceed."
            sleep 0.5
            ;;
    esac
    sleep 0.3
}

# ── Main entry point ───────────────────────────────────────────────────────────
select_main() {
    [[ -f "${SESSION_DIR}/users.list" ]] || die "No user list. Run enumeration first."
    mkdir -p "$SEL_DIR"

    # Pre-mark filtered users as 'skip' so they show in the table
    if [[ -f "${SESSION_DIR}/filtered.list" ]]; then
        while IFS=: read -r fuid _; do
            _set_sel "$fuid" "skip"
        done < "${SESSION_DIR}/filtered.list"
    fi

    while true; do
        _draw_table
        read -rp "  > " input

        [[ "${input,,}" == "done" ]] && break

        _process_cmd "$input"
    done

    # Warn if any active users still pending
    local pending; pending=$(_pending_count)
    if [[ "$pending" -gt 0 ]]; then
        echo
        warn "${pending} user(s) are still PENDING (no action set)."
        echo "  Options:"
        echo "    1) Set all remaining to RANDOM (recommended)"
        echo "    2) Set all remaining to SKIP"
        echo "    3) Go back and set them manually"
        echo
        read -rp "  Choice [1/2/3]: " c
        case "$c" in
            1)
                while IFS= read -r uid; do
                    [[ "$(_get_sel "$uid")" == "pending" ]] && _set_sel "$uid" "random"
                done < <(_active_users)
                success "Set all pending to RANDOM"
                ;;
            2)
                while IFS= read -r uid; do
                    [[ "$(_get_sel "$uid")" == "pending" ]] && _set_sel "$uid" "skip"
                done < <(_active_users)
                info "Skipped all pending"
                ;;
            3)
                select_main  # recurse
                return
                ;;
        esac
    fi

    echo
    success "Selections complete."
    echo
}
