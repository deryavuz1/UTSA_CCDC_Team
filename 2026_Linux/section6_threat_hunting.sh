#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/main_launcher.sh"

require_root "$@"

TH_DIR="/root/threatHunting_files"
BASELINE_DIR="$TH_DIR/baseline"
PSPY_HUNT_EXCLUDE_FILE="$TH_DIR/pspy_hunt_exclude.txt"
BASELINE_EPOCH_FILE="$TH_DIR/baseline_epoch"
BASELINE_PSPY_TS_FILE="$TH_DIR/baseline_pspy_ts"
LAST_LOG_REVIEW_EPOCH_FILE="$TH_DIR/last_log_review_epoch"
LAST_LOG_REVIEW_PSPY_TS_FILE="$TH_DIR/last_log_review_pspy_ts"
RUNS_DIR="$TH_DIR/runs"
STATE_FILE="$TH_DIR/latest_run_path.txt"
CURRENT_RUN_ID="$(date '+%F_%H%M%S')_$$"
CURRENT_RUN_DIR="$RUNS_DIR/$CURRENT_RUN_ID"
REPORT_DIR="$CURRENT_RUN_DIR/reports"
LOG_SNAPSHOT_DIR="$CURRENT_RUN_DIR/logs"
PSPY_LOG_SNAPSHOT="$LOG_SNAPSHOT_DIR/pspy.log"
AUDIT_LOG_SNAPSHOT="$LOG_SNAPSHOT_DIR/audit.log"
CURRENT_EPOCH="$(date +%s)"
CURRENT_PSPY_TS="$(date '+%Y/%m/%d %H:%M:%S')"
SUSPICIOUS_CMD_NAMES="cat,bash,sh,dash,rbash,python,python3,perl,php,ruby,lua,nc,ncat,netcat,socat,curl,wget,ftp,tftp,scp,rsync,chmod,chown,chattr,setcap,getcap,systemctl,service,update-rc.d,chkconfig,crontab,at,atd,useradd,usermod,userdel,adduser,deluser,passwd,chpasswd,vipw,chage,groupadd,groupmod,gpasswd,sudo,visudo,ssh-keygen"
AUDIT_ALWAYS_ALERT_CMD_NAMES="cat,nc,ncat,netcat,socat,curl,wget,ftp,tftp,scp,rsync,chmod,chown,chattr,setcap,getcap,systemctl,service,update-rc.d,chkconfig,crontab,at,atd,useradd,usermod,userdel,adduser,deluser,passwd,chpasswd,vipw,chage,groupadd,groupmod,gpasswd,sudo,visudo,ssh-keygen"
AUDIT_ROOT_ONLY_CMD_NAMES="bash,sh,dash,rbash,python,python3,perl,php,ruby,lua"
AUDIT_SELF_NOISE_REGEX='section6_threat_hunting\.sh|main_launcher\.sh|/root/threatHunting_files/|pspy_hunt_exclude\.txt|audit_rootcmd_ausearch|audit_credential_ausearch|cmd_list=|prefixes=/tmp/|egrep -i \(|grep -E -i \(|grep --color=auto|/tmp/section6_run'
PSPY_CREATE_PREFIXES="/tmp/,/var/tmp/,/dev/shm/,/opt/,/home/,/root/,/usr/bin/,/usr/sbin/,/bin/,/sbin/"
AUDIT_CREDENTIAL_TYPES="USER_ACCT,USER_AUTH,USER_CMD,USER_CHAUTHTOK,USER_START,USER_END,CRED_ACQ,CRED_DISP,ADD_USER,DEL_USER,ADD_GROUP,DEL_GROUP,CHUSER_ID,CHGRP_ID"
PREVIOUS_RUN_DIR=""
COMPARISON_DIR=""
COMPARISON_LABEL=""
BASELINE_CREATED=0
LOG_WINDOW_START_EPOCH=""
LOG_WINDOW_START_PSPY_TS=""
AUDIT_WINDOW_START_DATE=""
AUDIT_WINDOW_START_TIME=""
AUDIT_WINDOW_END_DATE=""
AUDIT_WINDOW_END_TIME=""

ensure_threat_hunting_dirs() {
  mkdir -p "$BASELINE_DIR" "$RUNS_DIR" "$CURRENT_RUN_DIR" "$REPORT_DIR" "$LOG_SNAPSHOT_DIR"
  if [[ ! -e "$PSPY_HUNT_EXCLUDE_FILE" ]]; then
    cat >"$PSPY_HUNT_EXCLUDE_FILE" <<'EOF'
# One substring per line. Matching pspy report lines will be suppressed.
# Examples:
# /apt/
# unattended-upgrades
EOF
  fi
  ok "Threat hunting data will be stored under $TH_DIR"
}

trim_whitespace() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

manage_pspy_hunt_exclusions() {
  local raw_input=""
  local entry=""
  local added_count=0

  section_header "5a) Review pspy Report Exclusions"
  info "Raw pspy logs remain saved. This exclusion list only suppresses matching lines from the threat hunting pspy reports."
  show_file_with_pause "$PSPY_HUNT_EXCLUDE_FILE"

  if ask_yes_no "Add substring exclusions for pspy report output?" "N"; then
    read -r -p "Enter substrings to exclude (comma-separated): " raw_input
    IFS=',' read -r -a exclusion_items <<< "$raw_input"
    for entry in "${exclusion_items[@]}"; do
      entry="$(trim_whitespace "$entry")"
      [[ -n "$entry" ]] || continue
      if ! grep -Fqx -- "$entry" "$PSPY_HUNT_EXCLUDE_FILE"; then
        printf '%s\n' "$entry" >>"$PSPY_HUNT_EXCLUDE_FILE"
        added_count=$((added_count + 1))
      fi
    done
    ok "Added $added_count new pspy exclusion entr$( [[ "$added_count" -eq 1 ]] && printf 'y' || printf 'ies' )."
    show_file_with_pause "$PSPY_HUNT_EXCLUDE_FILE"
  fi
}

normalize_snapshot() {
  local snapshot_name="$1"
  local raw_file="$2"

  case "$snapshot_name" in
    sockets)
      awk 'NR > 1 && NF {
        gsub(/[[:space:]]+/, " ")
        sub(/^ /, "")
        print
      }' "$raw_file" | sort -u
      ;;
    lsof)
      awk 'NR > 1 && NF {
        $2 = ""
        gsub(/[[:space:]]+/, " ")
        sub(/^ /, "")
        print
      }' "$raw_file" | sort -u
      ;;
    w)
      awk 'NR > 2 && NF {
        gsub(/[[:space:]]+/, " ")
        sub(/^ /, "")
        print
      }' "$raw_file" | sort -u
      ;;
    lastb)
      awk 'NF && $0 !~ /^btmp begins/ {
        gsub(/[[:space:]]+/, " ")
        sub(/^ /, "")
        print
      }' "$raw_file"
      ;;
    last_i)
      awk 'NF && $0 !~ /^wtmp begins/ {
        gsub(/[[:space:]]+/, " ")
        sub(/^ /, "")
        print
      }' "$raw_file"
      ;;
    *)
      cat "$raw_file"
      ;;
  esac
}

capture_snapshot() {
  local snapshot_name="$1"
  local raw_file="$CURRENT_RUN_DIR/${snapshot_name}.raw"
  local norm_file="$CURRENT_RUN_DIR/${snapshot_name}.norm"

  case "$snapshot_name" in
    sockets)
      list_listening_sockets >"$raw_file" 2>&1 || true
      ;;
    lsof)
      if command_exists lsof; then
        lsof -i -n -P >"$raw_file" 2>&1 || true
      else
        printf '%s\n' "lsof command not available" >"$raw_file"
      fi
      ;;
    w)
      w >"$raw_file" 2>&1 || true
      ;;
    lastb)
      lastb 2>/dev/null | head -n 40 >"$raw_file"
      ;;
    last_i)
      last -i 2>/dev/null | head -n 40 >"$raw_file"
      ;;
    *)
      warn "Unknown snapshot type: $snapshot_name"
      return 1
      ;;
  esac

  normalize_snapshot "$snapshot_name" "$raw_file" >"$norm_file"
}

load_previous_run_dir() {
  if [[ -r "$STATE_FILE" ]]; then
    PREVIOUS_RUN_DIR="$(<"$STATE_FILE")"
    if [[ ! -d "$PREVIOUS_RUN_DIR" ]]; then
      warn "Previous run path is stale: $PREVIOUS_RUN_DIR"
      PREVIOUS_RUN_DIR=""
    fi
  fi
}

initialize_baseline_if_missing() {
  local snapshot_name="$1"
  local baseline_raw="$BASELINE_DIR/${snapshot_name}.raw"
  local baseline_norm="$BASELINE_DIR/${snapshot_name}.norm"

  if [[ ! -f "$baseline_raw" || ! -f "$baseline_norm" ]]; then
    cp -a "$CURRENT_RUN_DIR/${snapshot_name}.raw" "$baseline_raw"
    cp -a "$CURRENT_RUN_DIR/${snapshot_name}.norm" "$baseline_norm"
    BASELINE_CREATED=1
  fi
}

ensure_baseline_time_files() {
  if [[ "$BASELINE_CREATED" -eq 1 || ! -s "$BASELINE_EPOCH_FILE" || ! -s "$BASELINE_PSPY_TS_FILE" ]]; then
    printf '%s\n' "$CURRENT_EPOCH" >"$BASELINE_EPOCH_FILE"
    printf '%s\n' "$CURRENT_PSPY_TS" >"$BASELINE_PSPY_TS_FILE"
  fi
}

load_log_review_window() {
  local source_label="current run"

  if [[ -s "$LAST_LOG_REVIEW_EPOCH_FILE" && -s "$LAST_LOG_REVIEW_PSPY_TS_FILE" ]]; then
    LOG_WINDOW_START_EPOCH="$(<"$LAST_LOG_REVIEW_EPOCH_FILE")"
    LOG_WINDOW_START_PSPY_TS="$(<"$LAST_LOG_REVIEW_PSPY_TS_FILE")"
    source_label="last threat hunting log review"
  elif [[ -s "$BASELINE_EPOCH_FILE" && -s "$BASELINE_PSPY_TS_FILE" ]]; then
    LOG_WINDOW_START_EPOCH="$(<"$BASELINE_EPOCH_FILE")"
    LOG_WINDOW_START_PSPY_TS="$(<"$BASELINE_PSPY_TS_FILE")"
    source_label="baseline seed"
  else
    LOG_WINDOW_START_EPOCH="$CURRENT_EPOCH"
    LOG_WINDOW_START_PSPY_TS="$CURRENT_PSPY_TS"
  fi

  if [[ "$LOG_WINDOW_START_EPOCH" -gt "$CURRENT_EPOCH" ]]; then
    warn "Stored log review window start is newer than current time. Resetting to current run."
    LOG_WINDOW_START_EPOCH="$CURRENT_EPOCH"
    LOG_WINDOW_START_PSPY_TS="$CURRENT_PSPY_TS"
    source_label="current run"
  fi

  info "Log review window start source: $source_label"
  info "Log review window: $LOG_WINDOW_START_PSPY_TS -> $CURRENT_PSPY_TS"

  AUDIT_WINDOW_START_DATE="$(date -d "@$LOG_WINDOW_START_EPOCH" '+%m/%d/%y')"
  AUDIT_WINDOW_START_TIME="$(date -d "@$LOG_WINDOW_START_EPOCH" '+%H:%M:%S')"
  AUDIT_WINDOW_END_DATE="$(date -d "@$CURRENT_EPOCH" '+%m/%d/%y')"
  AUDIT_WINDOW_END_TIME="$(date -d "@$CURRENT_EPOCH" '+%H:%M:%S')"
}

set_comparison_target() {
  if [[ -n "$PREVIOUS_RUN_DIR" ]]; then
    COMPARISON_DIR="$PREVIOUS_RUN_DIR"
    COMPARISON_LABEL="Last Run"
  else
    COMPARISON_DIR="$BASELINE_DIR"
    COMPARISON_LABEL="Baseline"
  fi

  info "Comparison target: $COMPARISON_LABEL"
}

print_colorized_diff() {
  local report_file="$1"
  awk -v add="$C_OK" -v del="$C_ERR" -v reset="$C_RESET" '
    /^(---|\+\+\+|@@)/ { print; next }
    /^\+/ { print add $0 reset; next }
    /^-/ { print del $0 reset; next }
    { print }
  ' "$report_file"
}

show_additions_report() {
  local title="$1"
  local old_file="$2"
  local new_file="$3"
  local report_file="$4"

  section_header "$title"
  show_output_source_header "REPORT: $report_file"

  if [[ ! -f "$old_file" ]]; then
    printf '%s\n' "none"
    pause_step
    return 0
  fi

  comm -13 "$old_file" "$new_file" >"$report_file" || true
  if [[ -s "$report_file" ]]; then
    awk -v hi="$C_OK" -v reset="$C_RESET" '{ print hi $0 reset }' "$report_file"
  else
    printf '%s\n' "none"
  fi
  pause_step
}

show_diff_report() {
  local title="$1"
  local old_file="$2"
  local new_file="$3"
  local report_file="$4"
  local exit_code=0

  section_header "$title"
  show_output_source_header "REPORT: $report_file"

  if [[ ! -f "$old_file" ]]; then
    printf '%s\n' "none"
    pause_step
    return 0
  fi

  if diff -u "$old_file" "$new_file" >"$report_file"; then
    :
  else
    exit_code=$?
  fi

  if [[ "$exit_code" -gt 1 ]]; then
    warn "diff failed while building $report_file"
    printf '%s\n' "none"
  elif [[ -s "$report_file" ]]; then
    print_colorized_diff "$report_file"
  else
    printf '%s\n' "none"
  fi
  pause_step
}

show_text_report() {
  local title="$1"
  local report_file="$2"

  section_header "$title"
  show_output_source_header "REPORT: $report_file"
  if [[ -s "$report_file" ]]; then
    cat "$report_file"
  else
    printf '%s\n' "none"
  fi
  pause_step
}

print_highlighted_audit_report() {
  local report_file="$1"

  awk -v type_hi="$C_WARN" -v proc_hi="$C_OK" -v reset="$C_RESET" '
    {
      line = $0
      gsub(/type=[A-Z_]+/, type_hi "&" reset, line)
      if ($0 ~ /^[[:space:]]*type=PROCTITLE/) {
        print proc_hi line reset
      } else {
        print line
      }
    }
  ' "$report_file"
}

show_audit_report() {
  local title="$1"
  local report_file="$2"

  section_header "$title"
  show_output_source_header "REPORT: $report_file"
  if [[ -s "$report_file" ]]; then
    print_highlighted_audit_report "$report_file"
  else
    printf '%s\n' "none"
  fi
  pause_step
}

run_ausearch_interpreted() {
  local out_file="$1"
  local err_file="$2"
  shift 2
  local -a query_args=("$@")

  : >"$out_file"
  : >"$err_file"

  if ! command_exists ausearch; then
    warn "ausearch not available; skipping interpreted audit review."
    return 1
  fi

  # Prefer the host's live audit logs. They are more reliable than replaying a copied
  # snapshot through older ausearch builds. Fall back to the snapshot only if needed.
  LC_ALL=C ausearch --input-logs -i "${query_args[@]}" >"$out_file" 2>"$err_file" || true

  if [[ ! -s "$out_file" && -r "$AUDIT_LOG_SNAPSHOT" ]]; then
    LC_ALL=C ausearch --input-logs -if "$AUDIT_LOG_SNAPSHOT" -i "${query_args[@]}" >"$out_file" 2>>"$err_file" || true
  fi

  if [[ ! -s "$out_file" && -s "$err_file" ]]; then
    warn "ausearch returned no readable output. See $err_file for details."
  fi

  return 0
}

snapshot_logs_for_review() {
  if [[ -r /root/pspy.log ]]; then
    cp -a /root/pspy.log "$PSPY_LOG_SNAPSHOT"
    ok "Saved /root/pspy.log snapshot for this threat hunting run"
  else
    warn "/root/pspy.log not found"
    rm -f "$PSPY_LOG_SNAPSHOT"
  fi

  if [[ -r /var/log/audit/audit.log ]]; then
    cp -a /var/log/audit/audit.log "$AUDIT_LOG_SNAPSHOT"
    ok "Saved /var/log/audit/audit.log snapshot for this threat hunting run"
  else
    warn "/var/log/audit/audit.log not found"
    rm -f "$AUDIT_LOG_SNAPSHOT"
  fi
}

generate_pspy_command_hits() {
  local out="$REPORT_DIR/pspy_suspicious_commands.txt"
  local self_noise='(pspy64|pspy\.exclude|main_launcher\.sh|section[0-9]_[A-Za-z0-9_]+\.sh)'

  : >"$out"
  [[ -r "$PSPY_LOG_SNAPSHOT" ]] || return 0

  awk -v start="$LOG_WINDOW_START_PSPY_TS" \
      -v end="$CURRENT_PSPY_TS" \
      -v cmd_list="$SUSPICIOUS_CMD_NAMES" \
      -v exclude_file="$PSPY_HUNT_EXCLUDE_FILE" \
      -v self_noise="$self_noise" '
    function strip_ansi(s) {
      gsub(/\033\[[0-9;]*[[:alpha:]]/, "", s)
      return s
    }
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function token_is_suspicious(cmd,   count, i, tok) {
      count = split(cmd, parts, /[[:space:]]+/)
      for (i = 1; i <= count; i++) {
        tok = parts[i]
        if (tok == "" || tok ~ /^-/) {
          continue
        }
        gsub(/^[\"`]+|[\"`]+$/, "", tok)
        gsub(/^[()]+|[()]+$/, "", tok)
        sub(/^.*\//, "", tok)
        sub(/[,:;|]+$/, "", tok)
        if (tok in allow) {
          return 1
        }
      }
      return 0
    }
    function line_is_excluded(line,   i) {
      for (i = 1; i <= exclude_count; i++) {
        if (exclude_list[i] != "" && index(line, exclude_list[i]) > 0) {
          return 1
        }
      }
      return 0
    }
    BEGIN {
      count = split(cmd_list, names, ",")
      for (i = 1; i <= count; i++) {
        allow[names[i]] = 1
      }
      while ((getline exclude_line < exclude_file) > 0) {
        sub(/^[[:space:]]+/, "", exclude_line)
        sub(/[[:space:]]+$/, "", exclude_line)
        if (exclude_line == "" || exclude_line ~ /^#/) {
          continue
        }
        exclude_list[++exclude_count] = exclude_line
      }
      close(exclude_file)
    }
    {
      line = strip_ansi($0)
      ts = substr(line, 1, 19)
      if (ts <= start || ts > end) {
        next
      }
      if (line !~ /CMD:[[:space:]]+UID=/ || index(line, "|") == 0) {
        next
      }
      cmd = line
      sub(/^.*\|[[:space:]]*/, "", cmd)
      cmd = trim(cmd)
      if (cmd == "" || cmd ~ self_noise) {
        next
      }
      if (line_is_excluded(line) || line_is_excluded(cmd)) {
        next
      }
      if (token_is_suspicious(cmd)) {
        print line
      }
    }
  ' "$PSPY_LOG_SNAPSHOT" >"$out"
}

generate_pspy_create_hits() {
  local out="$REPORT_DIR/pspy_suspicious_creates.txt"

  : >"$out"
  [[ -r "$PSPY_LOG_SNAPSHOT" ]] || return 0

  awk -v start="$LOG_WINDOW_START_PSPY_TS" \
      -v end="$CURRENT_PSPY_TS" \
      -v prefixes="$PSPY_CREATE_PREFIXES" \
      -v exclude_file="$PSPY_HUNT_EXCLUDE_FILE" '
    function strip_ansi(s) {
      gsub(/\033\[[0-9;]*[[:alpha:]]/, "", s)
      return s
    }
    function line_is_excluded(line,   i) {
      for (i = 1; i <= exclude_count; i++) {
        if (exclude_list[i] != "" && index(line, exclude_list[i]) > 0) {
          return 1
        }
      }
      return 0
    }
    BEGIN {
      prefix_count = split(prefixes, prefix_list, ",")
      while ((getline exclude_line < exclude_file) > 0) {
        sub(/^[[:space:]]+/, "", exclude_line)
        sub(/[[:space:]]+$/, "", exclude_line)
        if (exclude_line == "" || exclude_line ~ /^#/) {
          continue
        }
        exclude_list[++exclude_count] = exclude_line
      }
      close(exclude_file)
    }
    {
      line = strip_ansi($0)
      ts = substr(line, 1, 19)
      if (ts <= start || ts > end) {
        next
      }
      if (line !~ /CREATE/) {
        next
      }
      if (line_is_excluded(line)) {
        next
      }
      for (i = 1; i <= prefix_count; i++) {
        if (prefix_list[i] != "" && index(line, prefix_list[i]) > 0) {
          print line
          break
        }
      }
    }
  ' "$PSPY_LOG_SNAPSHOT" >"$out"
}

generate_audit_rootcmd_hits() {
  local out="$REPORT_DIR/audit_rootcmd_suspicious_commands.txt"
  local ausearch_out="$REPORT_DIR/audit_rootcmd_ausearch_full.txt"
  local ausearch_err="$REPORT_DIR/audit_rootcmd_ausearch.err"

  : >"$out"
  : >"$ausearch_out"

  run_ausearch_interpreted "$ausearch_out" "$ausearch_err" \
    -ts "$AUDIT_WINDOW_START_DATE" "$AUDIT_WINDOW_START_TIME" \
    -te "$AUDIT_WINDOW_END_DATE" "$AUDIT_WINDOW_END_TIME" || return 0

  awk -v always_list="$AUDIT_ALWAYS_ALERT_CMD_NAMES" \
      -v root_only_list="$AUDIT_ROOT_ONLY_CMD_NAMES" \
      -v noise_re="$AUDIT_SELF_NOISE_REGEX" '
    function token_in_set(line, set_name,   count, i, tok, pieces) {
      count = split(line, pieces, /[^[:alnum:]_\/.+-]+/)
      for (i = 1; i <= count; i++) {
        tok = pieces[i]
        if (tok == "") {
          continue
        }
        sub(/^.*\//, "", tok)
        if (tok in set_name) {
          return 1
        }
      }
      return 0
    }
    function block_is_rootish(block) {
      return block ~ /key="?rootcmd"?|[[:space:]]uid=root|[[:space:]]euid=root|UID="root"|EUID="root"/
    }
    function block_is_noise(block) {
      return block ~ noise_re
    }
    function block_is_interesting(block,   line_count, idx, line, rootish) {
      rootish = block_is_rootish(block)
      line_count = split(block, lines, /\n/)
      for (idx = 1; idx <= line_count; idx++) {
        line = lines[idx]
        if (line !~ /^type=(SYSCALL|EXECVE|PROCTITLE|USER_CMD)/) {
          continue
        }
        if (token_in_set(line, always_allow)) {
          return 1
        }
        if (rootish && token_in_set(line, root_only_allow)) {
          return 1
        }
      }
      return 0
    }
    function flush_event() {
      if (event_seen && !block_is_noise(block) && block_is_interesting(block)) {
        printf "%s", block
        if (block !~ /\n$/) {
          printf "\n"
        }
        printf "\n"
      }
      block = ""
      event_seen = 0
      event_match = 0
    }
    BEGIN {
      count = split(always_list, names, ",")
      for (i = 1; i <= count; i++) {
        always_allow[names[i]] = 1
      }
      count = split(root_only_list, names, ",")
      for (i = 1; i <= count; i++) {
        root_only_allow[names[i]] = 1
      }
    }
    /^----/ {
      flush_event()
      block = $0 ORS
      event_seen = 1
      next
    }
    /^$/ {
      flush_event()
      next
    }
    {
      block = block $0 ORS
      event_seen = 1
    }
    END {
      flush_event()
    }
  ' "$ausearch_out" >"$out"
}

generate_audit_credential_hits() {
  local out="$REPORT_DIR/audit_credential_account_hits.txt"
  local ausearch_out="$REPORT_DIR/audit_credential_ausearch_full.txt"
  local ausearch_err="$REPORT_DIR/audit_credential_ausearch.err"

  : >"$out"
  : >"$ausearch_out"

  run_ausearch_interpreted "$ausearch_out" "$ausearch_err" -m "$AUDIT_CREDENTIAL_TYPES" \
    -ts "$AUDIT_WINDOW_START_DATE" "$AUDIT_WINDOW_START_TIME" \
    -te "$AUDIT_WINDOW_END_DATE" "$AUDIT_WINDOW_END_TIME" || return 0

  cp -a "$ausearch_out" "$out"
}

save_latest_run_state() {
  printf '%s\n' "$CURRENT_RUN_DIR" >"$STATE_FILE"
  ok "Latest threat hunting run recorded: $CURRENT_RUN_DIR"
}

save_log_review_state() {
  printf '%s\n' "$CURRENT_EPOCH" >"$LAST_LOG_REVIEW_EPOCH_FILE"
  printf '%s\n' "$CURRENT_PSPY_TS" >"$LAST_LOG_REVIEW_PSPY_TS_FILE"
  ok "Updated rolling log review marker to $CURRENT_PSPY_TS"
}

section_header "Section 6 - Threat Hunting"

section_header "1) Prepare Threat Hunting Workspace"
ensure_threat_hunting_dirs
load_previous_run_dir
if [[ -n "$PREVIOUS_RUN_DIR" ]]; then
  info "Previous run loaded: $PREVIOUS_RUN_DIR"
else
  info "No previous run found. This run will establish the first comparison point."
fi
pause_step

section_header "2) Capture Current Snapshots"
capture_snapshot sockets
capture_snapshot lsof
capture_snapshot w
capture_snapshot lastb
capture_snapshot last_i
initialize_baseline_if_missing sockets
initialize_baseline_if_missing lsof
initialize_baseline_if_missing w
initialize_baseline_if_missing lastb
initialize_baseline_if_missing last_i
ensure_baseline_time_files
load_log_review_window
set_comparison_target
if [[ "$BASELINE_CREATED" -eq 1 ]]; then
  info "No baseline was found for one or more snapshots. Current data was saved as the fallback baseline."
fi
ok "Current run snapshots saved to $CURRENT_RUN_DIR"
pause_step

section_header "3) Compare Current Network State to $COMPARISON_LABEL"
show_additions_report \
  "3a) Listening Sockets Added vs $COMPARISON_LABEL" \
  "$COMPARISON_DIR/sockets.norm" \
  "$CURRENT_RUN_DIR/sockets.norm" \
  "$REPORT_DIR/comparison_sockets_additions.txt"
show_additions_report \
  "3b) LSOF Network Entries Added vs $COMPARISON_LABEL" \
  "$COMPARISON_DIR/lsof.norm" \
  "$CURRENT_RUN_DIR/lsof.norm" \
  "$REPORT_DIR/comparison_lsof_additions.txt"

section_header "4) Compare Current Session/Auth State to $COMPARISON_LABEL"
show_diff_report \
  "4a) w Changes vs $COMPARISON_LABEL" \
  "$COMPARISON_DIR/w.norm" \
  "$CURRENT_RUN_DIR/w.norm" \
  "$REPORT_DIR/comparison_w_diff.txt"
show_diff_report \
  "4b) lastb Changes vs $COMPARISON_LABEL" \
  "$COMPARISON_DIR/lastb.norm" \
  "$CURRENT_RUN_DIR/lastb.norm" \
  "$REPORT_DIR/comparison_lastb_diff.txt"
show_diff_report \
  "4c) last -i Changes vs $COMPARISON_LABEL" \
  "$COMPARISON_DIR/last_i.norm" \
  "$CURRENT_RUN_DIR/last_i.norm" \
  "$REPORT_DIR/comparison_last_i_diff.txt"

section_header "5) Review pspy/auditd Logs in Rolling Window"
info "Reviewing only log entries between $LOG_WINDOW_START_PSPY_TS and $CURRENT_PSPY_TS."
manage_pspy_hunt_exclusions
snapshot_logs_for_review
generate_pspy_command_hits
generate_pspy_create_hits
generate_audit_rootcmd_hits
generate_audit_credential_hits
show_text_report "5b) pspy Suspicious Command Hits" "$REPORT_DIR/pspy_suspicious_commands.txt"
show_text_report "5c) pspy Suspicious CREATE Hits" "$REPORT_DIR/pspy_suspicious_creates.txt"
show_audit_report "5d) auditd Suspicious Command Hits" "$REPORT_DIR/audit_rootcmd_suspicious_commands.txt"
show_audit_report "5e) auditd Credential/Account Event Hits" "$REPORT_DIR/audit_credential_account_hits.txt"

section_header "6) Finalize Threat Hunting Run"
save_latest_run_state
save_log_review_state
info "Baseline files: $BASELINE_DIR"
info "Current run files: $CURRENT_RUN_DIR"
pause_step

ok "Section 6 complete."
