#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/main_launcher.sh"

require_root "$@"

ROLE=""
SERVER_IP=""
GRAYLOG_IP=""

prompt_role() {
  while true; do
    read -r -p "Is this host an rsyslog server or client? [server/client]: " ROLE
    case "${ROLE,,}" in
      server|client)
        ROLE="${ROLE,,}"
        return 0
        ;;
      *) warn "Please enter 'server' or 'client'." ;;
    esac
  done
}

install_rsyslog() {
  if command_exists rsyslogd; then
    ok "rsyslog already installed"
    return 0
  fi

  install_packages rsyslog || {
    warn "Unable to install rsyslog automatically"
    return 1
  }
}

write_common_conf() {
  cat >/etc/rsyslog.d/00-rsyslog-common.conf <<'EOF_COMMON'
# Managed by section5_setup_rsyslog.sh
global(workDirectory="/var/spool/rsyslog")
$RepeatedMsgReduction off
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
EOF_COMMON
  ok "Wrote /etc/rsyslog.d/00-rsyslog-common.conf"
}

write_server_conf() {
  mkdir -p /var/log/remote
  chmod 750 /var/log/remote

  cat >/etc/rsyslog.d/10-rsyslog-server.conf <<'EOF_SERVER'
# Managed by section5_setup_rsyslog.sh
module(load="imudp")
input(type="imudp" port="514")

module(load="imtcp")
input(type="imtcp" port="514")

template(name="RemoteByHostProgram" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
*.* action(type="omfile" dynaFile="RemoteByHostProgram" createDirs="on")
EOF_SERVER

  rm -f /etc/rsyslog.d/10-rsyslog-client.conf
  ok "Configured host as rsyslog server"
}

write_client_conf() {
  local client_cfg="/etc/rsyslog.d/10-rsyslog-client.conf"
  local summary=""

  cat >"$client_cfg" <<'EOF_CLIENT'
# Managed by section5_setup_rsyslog.sh
EOF_CLIENT

  if [[ -n "$SERVER_IP" ]]; then
    cat >>"$client_cfg" <<EOF_RSYSLOG
# Forward all logs to centralized rsyslog server
*.* action(
  type="omfwd"
  target="$SERVER_IP"
  port="514"
  protocol="tcp"
  action.resumeRetryCount="-1"
  queue.type="linkedList"
  queue.filename="fwd_rsyslog_server"
  queue.maxDiskSpace="1g"
  queue.saveOnShutdown="on"
)
EOF_RSYSLOG
    summary="rsyslog:$SERVER_IP"
  fi

  if [[ -n "$GRAYLOG_IP" ]]; then
    cat >>"$client_cfg" <<EOF_GRAYLOG
# Forward all logs to Graylog server
*.* action(
  type="omfwd"
  target="$GRAYLOG_IP"
  port="5140"
  protocol="tcp"
  template="RSYSLOG_SyslogProtocol23Format"
  action.resumeRetryCount="-1"
  queue.type="linkedList"
  queue.filename="fwd_graylog_server"
  queue.maxDiskSpace="1g"
  queue.saveOnShutdown="on"
)
EOF_GRAYLOG
    if [[ -n "$summary" ]]; then
      summary="${summary}, graylog:$GRAYLOG_IP"
    else
      summary="graylog:$GRAYLOG_IP"
    fi
  fi

  rm -f /etc/rsyslog.d/10-rsyslog-server.conf
  ok "Configured host as log forwarder -> $summary"
}

validate_and_restart() {
  if command_exists rsyslogd; then
    show_output_source_header "COMMAND: rsyslogd -N1"
    rsyslogd -N1 || {
      warn "rsyslog config validation failed. Not restarting service."
      pause_step
      return 1
    }
    pause_step
  fi

  systemctl daemon-reload || true
  systemctl enable --now rsyslog || {
    warn "Failed to enable/start rsyslog"
    return 1
  }

  systemctl restart rsyslog || warn "Failed to restart rsyslog"
  show_output_source_header "COMMAND: systemctl status rsyslog | head -n 40"
  systemctl --no-pager --full status rsyslog | sed -n '1,40p' || true
  pause_step
}

section_header "Section 5 - Setup Rsyslog"

section_header "1) Choose Server or Client"
prompt_role
if [[ "$ROLE" == "client" ]]; then
  read -r -p "Enter the rsyslog server IP/FQDN (blank to skip rsyslog target): " SERVER_IP
  read -r -p "Enter the Graylog server IP/FQDN (blank to skip Graylog target): " GRAYLOG_IP

  if [[ -z "$SERVER_IP" && -z "$GRAYLOG_IP" ]]; then
    error "At least one destination must be set in client mode (rsyslog or Graylog)."
    exit 1
  fi
fi
pause_step

section_header "2) Install and Configure Rsyslog"
install_rsyslog || true
write_common_conf
show_file_with_pause "/etc/rsyslog.d/00-rsyslog-common.conf"

if [[ "$ROLE" == "server" ]]; then
  write_server_conf
  show_file_with_pause "/etc/rsyslog.d/10-rsyslog-server.conf"
else
  write_client_conf
  show_file_with_pause "/etc/rsyslog.d/10-rsyslog-client.conf"
fi

validate_and_restart || true
pause_step

ok "Section 5 complete."
