#!/usr/bin/env bash
# toolbox.sh — LDAP/Kerberos Credential Management Toolbox
# Usage: ./toolbox.sh
# Requires: ldap-utils (ldapsearch, ldapmodify), openssl, ssh-keygen
# Optional: krb5-user (kadmin) for Kerberos password changes

set -uo pipefail

# ── Root check ─────────────────────────────────────────────────────────────────
if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: toolbox.sh must be run as root." >&2
    exit 1
fi

TOOLBOX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${TOOLBOX_DIR}/lib"
MODULES_DIR="${TOOLBOX_DIR}/modules"
SESSIONS_DIR="${TOOLBOX_DIR}/sessions"
mkdir -p "${SESSIONS_DIR}"

# Load shared library
# shellcheck source=lib/common.sh
source "${LIB_DIR}/common.sh"

# ── Module loader ──────────────────────────────────────────────────────────────
load_module() {
    local mod="${MODULES_DIR}/${1}"
    [[ -f "$mod" ]] || die "Module not found: ${mod}"
    # shellcheck source=/dev/null
    source "$mod"
}

# ── Workflow functions ─────────────────────────────────────────────────────────
run_full_workflow() {
    new_session
    echo

    load_module "01_enum.sh";   enum_main
    load_module "02_filter.sh"; filter_main
    load_module "03_select.sh"; select_main
    load_module "04_generate.sh"; generate_main
    load_module "05_output.sh"; output_main

    echo
    success "Full workflow complete."
    echo -e "  Output: ${CYAN}${SESSION_DIR}/output/${RESET}"
    press_enter
}

run_enum_only() {
    new_session
    load_module "01_enum.sh"; enum_main
    success "Enumeration saved. Session: ${SESSION_NAME}"
    press_enter
}

run_load_modify() {
    if ! load_session "latest" 2>/dev/null; then
        warn "No session found. Run the full workflow first."
        press_enter
        return
    fi
    echo
    echo -e "  ${BOLD}Session loaded:${RESET} ${SESSION_NAME}"
    echo
    echo "  What do you want to do?"
    echo "    1) Re-run user selection & regenerate output"
    echo "    2) Re-run filter management, then selection & output"
    echo "    3) Regenerate output files only (with existing selections)"
    echo "    4) Back"
    echo
    read -rp "  Choice: " c
    case "$c" in
        1)
            load_module "02_filter.sh"  # needed for is_filtered()
            load_module "03_select.sh"; select_main
            load_module "04_generate.sh"; generate_main
            load_module "05_output.sh"; output_main
            ;;
        2)
            load_module "02_filter.sh"; filter_main
            load_module "03_select.sh"; select_main
            load_module "04_generate.sh"; generate_main
            load_module "05_output.sh"; output_main
            ;;
        3)
            load_module "04_generate.sh"; generate_main
            load_module "05_output.sh"; output_main
            ;;
        4) return ;;
        *) warn "Invalid choice" ;;
    esac
    press_enter
}

run_apply() {
    if ! load_session "latest" 2>/dev/null; then
        warn "No session found. Run the full workflow first."
        press_enter
        return
    fi
    load_module "02_filter.sh"  # needed for is_filtered()
    load_module "06_apply.sh"; apply_main
}

run_admin_passwd() {
    if ! load_session "latest" 2>/dev/null; then
        warn "No session found. Run the full workflow first to configure LDAP/Kerberos settings."
        press_enter
        return
    fi
    load_module "07_admin_passwd.sh"; admin_passwd_main
}

view_outputs() {
    if [[ ! -L "${SESSIONS_DIR}/latest" ]]; then
        warn "No session found."
        press_enter
        return
    fi
    local sdir; sdir=$(readlink -f "${SESSIONS_DIR}/latest")
    local sname; sname=$(basename "$sdir")
    local out="${sdir}/output"

    header "Output Files — ${sname}"
    echo
    if [[ -d "$out" ]]; then
        for f in new_passwords.txt old_hashes.txt changes.ldif revert.ldif krb5_changes.sh; do
            if [[ -f "${out}/${f}" ]]; then
                local lines; lines=$(wc -l < "${out}/${f}")
                echo -e "  ${GREEN}✓${RESET}  ${out}/${f}  ${DIM}(${lines} lines)${RESET}"
            else
                echo -e "  ${DIM}✗  ${out}/${f} (not generated)${RESET}"
            fi
        done
        local keys; keys=$(ls "${out}/sshkeys/"*.pub 2>/dev/null | wc -l)
        [[ "$keys" -gt 0 ]] && echo -e "  ${GREEN}✓${RESET}  ${out}/sshkeys/  ${DIM}(${keys} keypairs)${RESET}"
    else
        warn "No output directory. Run the full workflow first."
    fi
    press_enter
}

list_sessions() {
    header "Sessions"
    echo
    local count=0
    for d in "${SESSIONS_DIR}"/*/; do
        local name; name=$(basename "$d")
        [[ "$name" == "latest" ]] && continue
        [[ -d "$d" ]] || continue
        local users=0
        [[ -f "${d}users.list" ]] && users=$(wc -l < "${d}users.list")
        local marker=""
        [[ "$(readlink -f "${SESSIONS_DIR}/latest" 2>/dev/null)" == "$(readlink -f "$d")" ]] && \
            marker=" ${GREEN}← latest${RESET}"
        echo -e "  ${name}  ${DIM}(${users} users)${RESET}${marker}"
        ((count++)) || true
    done
    [[ $count -eq 0 ]] && warn "No sessions found."
    press_enter
}

# ── Main menu ──────────────────────────────────────────────────────────────────
main_menu() {
    while true; do
        clear
        print_banner
        hr
        echo -e "  ${BOLD}MAIN MENU${RESET}"
        hr
        echo
        echo -e "  ${CYAN}1)${RESET}  Run Full Workflow  — Enum → Filter → Select → Generate → Output"
        echo -e "  ${CYAN}2)${RESET}  Enumerate Environment Only"
        echo -e "  ${CYAN}3)${RESET}  Load Latest Session & Modify"
        echo -e "  ${CYAN}4)${RESET}  ${RED}${BOLD}Apply Changes${RESET}           ← MODIFIES LDAP (requires confirmation)"
        echo -e "  ${CYAN}5)${RESET}  ${YELLOW}${BOLD}Change Admin Passwords${RESET}  ← LDAP admin + Kerberos admin"
        echo -e "  ${CYAN}6)${RESET}  View Output File Paths"
        echo -e "  ${CYAN}7)${RESET}  List All Sessions"
        echo -e "  ${CYAN}8)${RESET}  Exit"
        echo
        hr
        read -rp "  Choice: " choice
        echo
        case "$choice" in
            1) run_full_workflow ;;
            2) run_enum_only ;;
            3) run_load_modify ;;
            4) run_apply ;;
            5) run_admin_passwd ;;
            6) view_outputs ;;
            7) list_sessions ;;
            8) echo -e "  ${DIM}Exiting.${RESET}"; echo; exit 0 ;;
            *) warn "Invalid choice."; sleep 0.5 ;;
        esac
    done
}

main_menu
