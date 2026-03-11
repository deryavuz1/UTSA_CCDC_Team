#!/usr/bin/env bash
# modules/02_filter.sh — Whiteteam/blackteam user filtering
# Auto-detects users that match competition service account patterns.
# Filtered users are EXCLUDED from password changes by default.
# Entry point: filter_main

FILTER_FILE="${SESSION_DIR}/filtered.list"

# ── Pattern matching ───────────────────────────────────────────────────────────
# Returns 0 (filtered) if uid matches any pattern (exact or starts-with)
_uid_matches_filter() {
    local uid_lower="${1,,}"
    for pattern in ${FILTER_PATTERNS}; do
        local p_lower="${pattern,,}"
        # Exact match OR starts-with
        if [[ "$uid_lower" == "$p_lower" ]] || [[ "$uid_lower" == "${p_lower}"* ]]; then
            echo "$pattern"
            return 0
        fi
    done
    return 1
}

# ── Build initial filter list ──────────────────────────────────────────────────
_apply_auto_filter() {
    > "$FILTER_FILE"  # reset
    local filtered_count=0
    while IFS= read -r uid; do
        local matched_pattern
        if matched_pattern=$(_uid_matches_filter "$uid"); then
            echo "${uid}:pattern:${matched_pattern}" >> "$FILTER_FILE"
            ((filtered_count++)) || true
        fi
    done < "${SESSION_DIR}/users.list"
    echo "$filtered_count"
}

# ── Display ────────────────────────────────────────────────────────────────────
_show_filter_status() {
    header "Filter Status"
    echo

    if [[ ! -s "$FILTER_FILE" ]]; then
        info "No users currently filtered."
        return
    fi

    echo -e "  ${YELLOW}${BOLD}FILTERED USERS${RESET}  (excluded from password changes by default)"
    echo
    printf "  ${BOLD}%-20s %-12s %-20s${RESET}\n" "USERNAME" "REASON" "MATCHED PATTERN"
    hr
    while IFS=: read -r fuid freason fpattern; do
        printf "  ${YELLOW}%-20s${RESET} %-12s %-20s\n" "$fuid" "$freason" "$fpattern"
    done < "$FILTER_FILE"
    echo
    echo -e "  ${DIM}These users will NOT have passwords/keys changed.${RESET}"
    echo -e "  ${DIM}Type 'enable <user>' in the selection menu to include them.${RESET}"
}

# ── Add/remove from filter ──────────────────────────────────────────────────────
filter_add_user() {
    local uid="$1" reason="${2:-manual}"
    # Don't double-add
    grep -q "^${uid}:" "$FILTER_FILE" 2>/dev/null && return
    echo "${uid}:${reason}:manual" >> "$FILTER_FILE"
    warn "Filtered: ${uid}"
}

filter_remove_user() {
    local uid="$1"
    if grep -q "^${uid}:" "$FILTER_FILE" 2>/dev/null; then
        sed -i "/^${uid}:/d" "$FILTER_FILE"
        success "Re-enabled: ${uid} (will be included in password changes)"
        # Remove any existing 'skip' selection for this user
        rm -f "${SESSION_DIR}/selections/${uid}.sel"
    else
        warn "${uid} is not currently filtered."
    fi
}

is_filtered() {
    grep -q "^${1}:" "$FILTER_FILE" 2>/dev/null
}

# ── Interactive filter management ──────────────────────────────────────────────
_filter_menu() {
    while true; do
        clear
        print_banner
        _show_filter_status
        hr
        echo -e "  ${DIM}Commands:${RESET}"
        echo "    add <user>     — add a user to the filter"
        echo "    remove <user>  — remove (re-enable) a filtered user"
        echo "    pattern <word> — add a filter pattern for this session"
        echo "    list           — show all filter patterns"
        echo "    done           — proceed to user selection"
        hr
        echo
        read -rp "  > " cmd args

        case "$cmd" in
            add)
                [[ -z "$args" ]] && warn "Usage: add <user>" && continue
                if grep -q "^${args}$" "${SESSION_DIR}/users.list" 2>/dev/null; then
                    filter_add_user "$args" "manual"
                else
                    warn "User '${args}' not in user list."
                fi
                ;;
            remove|enable)
                [[ -z "$args" ]] && warn "Usage: remove <user>" && continue
                filter_remove_user "$args"
                sleep 0.8
                ;;
            pattern)
                [[ -z "$args" ]] && warn "Usage: pattern <word>" && continue
                FILTER_PATTERNS="${FILTER_PATTERNS} ${args}"
                info "Added pattern: ${args}"
                # Re-apply filters with new pattern
                local n; n=$(_apply_auto_filter)
                info "Re-applied: ${n} user(s) filtered total"
                save_env_conf
                sleep 0.8
                ;;
            list)
                echo
                echo -e "  ${BOLD}Active filter patterns:${RESET}"
                for p in ${FILTER_PATTERNS}; do echo "    • ${p}"; done
                press_enter
                ;;
            done|"")
                break
                ;;
            *)
                warn "Unknown command. Type 'done' to proceed."
                sleep 0.5
                ;;
        esac
    done
}

# ── Main entry point ───────────────────────────────────────────────────────────
filter_main() {
    [[ -f "${SESSION_DIR}/users.list" ]] || die "No user list found. Run enumeration first."

    info "Applying whiteteam/blackteam auto-filter..."
    local n; n=$(_apply_auto_filter)

    if [[ "$n" -gt 0 ]]; then
        echo
        warn "${n} user(s) auto-filtered. Review and adjust if needed."
        echo
        _filter_menu
    else
        info "No users matched filter patterns (${FILTER_PATTERNS})."
        echo
        info "Opening filter manager — add users manually if needed."
        echo
        read -rp "  Open filter manager? [y/N]: " ans
        if [[ "${ans,,}" == "y" ]]; then
            _filter_menu
        fi
    fi

    local total filtered active
    total=$(wc -l < "${SESSION_DIR}/users.list" 2>/dev/null || echo 0)
    filtered=$(wc -l < "$FILTER_FILE" 2>/dev/null || echo 0)
    active=$((total - filtered))

    echo
    success "Filter complete: ${active} active user(s), ${filtered} filtered"
    echo
}
