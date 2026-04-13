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

user_is_excluded() {
  local target="$1"
  [[ -n "${excluded_lookup[$target]:-}" ]]
}

section_header "Section 3 - Local Password Changes"

section_header "1) Choose Users to Exclude"
read -r -p "Enter users to exclude from password changes (comma-separated, blank for none): " excluded_csv
mapfile -t excluded_users < <(printf '%s\n' "$excluded_csv" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | sed '/^$/d')
declare -A excluded_lookup=()
if ((${#excluded_users[@]} > 0)); then
  for excluded_user in "${excluded_users[@]}"; do
    excluded_lookup["$excluded_user"]=1
    if ! getent passwd "$excluded_user" >/dev/null 2>&1; then
      warn "Excluded user not found in passwd database: $excluded_user"
    fi
  done
  info "Excluded users: ${excluded_users[*]}"
else
  info "No users excluded."
fi
pause_step

section_header "2) Generate Random Passwords for Local Interactive Users"
PASS_FILE="/root/passwords_$(hostname).txt"
mapfile -t candidate_users < <(awk -F: '($3>=1000)&&($7!~/nologin|false/){print $1}' /etc/passwd)
target_users=()

for u in "${candidate_users[@]}"; do
  if user_is_excluded "$u"; then
    info "Skipping excluded user: $u"
    continue
  fi
  target_users+=("$u")
done

: >"$PASS_FILE"
for u in "${target_users[@]}"; do
  printf '%s:%s\n' "$u" "$(generate_password)" >>"$PASS_FILE"
done

if ((${#excluded_users[@]} > 0)) && [[ -s "$PASS_FILE" ]]; then
  temp_pass_file="$(mktemp)"
  awk -F: -v exclude_csv="$(IFS=,; printf '%s' "${excluded_users[*]}")" '
    BEGIN {
      count = split(exclude_csv, names, ",")
      for (i = 1; i <= count; i++) {
        if (length(names[i]) > 0) {
          excluded[names[i]] = 1
        }
      }
    }
    !($1 in excluded) { print }
  ' "$PASS_FILE" >"$temp_pass_file"
  mv "$temp_pass_file" "$PASS_FILE"
fi

if [[ -s "$PASS_FILE" ]]; then
  show_file_with_pause "$PASS_FILE"
  ok "Password file created: $PASS_FILE"
else
  show_output_source_header "FILE: $PASS_FILE"
  warn "No qualifying users found. Password file is empty: $PASS_FILE"
  pause_step
fi

section_header "3) Apply Password Changes (Only After Approval/Portal Submission)"
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

section_header "4) Move Password File Off-Host and Delete"
info "Move $PASS_FILE to secure storage, then delete it from this host."
if ask_yes_no "Delete $PASS_FILE now?" "N"; then
  shred -u "$PASS_FILE" 2>/dev/null || rm -f "$PASS_FILE"
  ok "Removed $PASS_FILE"
fi
pause_step

ok "Section 3 complete."
