#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/main_launcher.sh"

require_root "$@"

generate_password() {
  if command_exists openssl; then
    openssl rand -base64 9
  else
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12
    printf '\n'
  fi
}

section_header "Section 3 - Local Password Changes"

section_header "1) Generate Random Passwords for Local Interactive Users"
PASS_FILE="/root/passwords_$(hostname).txt"
mapfile -t target_users < <(awk -F: '($3>=1000)&&($7!~/nologin|false/){print $1}' /etc/passwd)

: >"$PASS_FILE"
for u in "${target_users[@]}"; do
  printf '%s:%s\n' "$u" "$(generate_password)" >>"$PASS_FILE"
done

if [[ -s "$PASS_FILE" ]]; then
  show_file_with_pause "$PASS_FILE"
  ok "Password file created: $PASS_FILE"
else
  show_output_source_header "FILE: $PASS_FILE"
  warn "No qualifying users found. Password file is empty: $PASS_FILE"
  pause_step
fi

section_header "2) Apply Password Changes (Only After Approval/Portal Submission)"
if ask_yes_no "Apply these password changes now with chpasswd?" "N"; then
  if [[ -s "$PASS_FILE" ]]; then
    chpasswd <"$PASS_FILE" && ok "Passwords updated successfully" || warn "chpasswd returned an error"
  else
    warn "Password file is empty. Nothing to apply."
  fi
else
  info "Skipped applying password changes."
fi
pause_step

section_header "3) Move Password File Off-Host and Delete"
info "Move $PASS_FILE to secure storage, then delete it from this host."
if ask_yes_no "Delete $PASS_FILE now?" "N"; then
  shred -u "$PASS_FILE" 2>/dev/null || rm -f "$PASS_FILE"
  ok "Removed $PASS_FILE"
fi
pause_step

ok "Section 3 complete."
