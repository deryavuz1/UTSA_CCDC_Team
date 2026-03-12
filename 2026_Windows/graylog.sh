#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup-graylog.sh — Automated Graylog + OpenSearch + MongoDB deployment
# Usage:  chmod +x setup-graylog.sh && sudo ./setup-graylog.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colour helpers ───────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Must run as root ─────────────────────────────────────────────────────────
[[ "$EUID" -eq 0 ]] || error "Please run this script as root (sudo)."

# ── Configurable variables ───────────────────────────────────────────────────
INSTALL_DIR="/opt/graylog"
GRAYLOG_ADMIN_PASSWORD="${GRAYLOG_ADMIN_PASSWORD:-}"

# ── Prompt for the admin password if not set via env var ─────────────────────
if [[ -z "$GRAYLOG_ADMIN_PASSWORD" ]]; then
    echo ""
    read -rsp "Enter the Graylog admin password: " GRAYLOG_ADMIN_PASSWORD
    echo ""
    [[ -n "$GRAYLOG_ADMIN_PASSWORD" ]] || error "Password cannot be empty."
fi

# ── 1. Kernel tuning (required by OpenSearch) ───────────────────────────────
info "Setting vm.max_map_count=262144 ..."
sysctl -w vm.max_map_count=262144 >/dev/null
if ! grep -q '^vm.max_map_count=262144' /etc/sysctl.conf 2>/dev/null; then
    echo "vm.max_map_count=262144" >> /etc/sysctl.conf
    info "Persisted in /etc/sysctl.conf"
fi

# ── 2. Install Docker (if missing) ──────────────────────────────────────────
if command -v docker &>/dev/null; then
    info "Docker already installed: $(docker --version)"
else
    info "Installing Docker via official convenience script ..."
    apt-get update -qq
    apt-get install -y -qq curl ca-certificates gnupg >/dev/null
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
    info "Docker installed: $(docker --version)"
fi

# Ensure the docker compose plugin is available
if ! docker compose version &>/dev/null; then
    info "Installing docker-compose-plugin ..."
    apt-get install -y -qq docker-compose-plugin >/dev/null
fi

# ── 3. Install pwgen (if missing) ───────────────────────────────────────────
if ! command -v pwgen &>/dev/null; then
    info "Installing pwgen ..."
    apt-get install -y -qq pwgen >/dev/null
fi

# ── 4. Create project directory ─────────────────────────────────────────────
info "Setting up project in ${INSTALL_DIR} ..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# ── 5. Generate .env secrets ────────────────────────────────────────────────
info "Generating secrets ..."
GRAYLOG_PASSWORD_SECRET="$(pwgen -N 1 -s 96)"
GRAYLOG_ROOT_PASSWORD_SHA2="$(echo -n "${GRAYLOG_ADMIN_PASSWORD}" | sha256sum | cut -d' ' -f1)"

cat > .env <<EOF
GRAYLOG_PASSWORD_SECRET=${GRAYLOG_PASSWORD_SECRET}
GRAYLOG_ROOT_PASSWORD_SHA2=${GRAYLOG_ROOT_PASSWORD_SHA2}
EOF

chmod 600 .env
info ".env written (permissions 600)"

# ── 6. Write docker-compose.yml ─────────────────────────────────────────────
info "Writing docker-compose.yml ..."
cat > docker-compose.yml <<'COMPOSE'
services:
  # ── MongoDB ────────────────────────────────────────────────────────────────
  mongodb:
    image: mongo:8.0
    container_name: mongodb
    restart: unless-stopped
    volumes:
      - mongodb_data:/data/db
    networks:
      - graylog

  # ── OpenSearch ─────────────────────────────────────────────────────────────
  # WARNING: Do NOT upgrade to OpenSearch 3.0+ — it is not supported by Graylog.
  opensearch:
    image: opensearchproject/opensearch:2.19.0
    container_name: opensearch
    restart: unless-stopped
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
      - "bootstrap.memory_lock=true"
      - "discovery.type=single-node"
      - "action.auto_create_index=false"
      - "plugins.security.ssl.http.enabled=false"
      - "plugins.security.disabled=true"
      - "OPENSEARCH_INITIAL_ADMIN_PASSWORD=+_8r#wliY3Kj"
    ulimits:
      memlock:
        hard: -1
        soft: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - opensearch_data:/usr/share/opensearch/data
    networks:
      - graylog

  # ── Graylog ────────────────────────────────────────────────────────────────
  graylog:
    image: graylog/graylog:7.0
    container_name: graylog
    restart: unless-stopped
    depends_on:
      - mongodb
      - opensearch
    environment:
      - GRAYLOG_PASSWORD_SECRET=${GRAYLOG_PASSWORD_SECRET:-replacethiswithatleast64characterslongsecretstring0000000000000000}
      - GRAYLOG_ROOT_PASSWORD_SHA2=${GRAYLOG_ROOT_PASSWORD_SHA2:-8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918}
      - GRAYLOG_HTTP_EXTERNAL_URI=http://0.0.0.0:9000/
      - GRAYLOG_HTTP_BIND_ADDRESS=0.0.0.0:9000
      - GRAYLOG_ELASTICSEARCH_HOSTS=http://opensearch:9200
      - GRAYLOG_MONGODB_URI=mongodb://mongodb:27017/graylog
      - GRAYLOG_MESSAGE_JOURNAL_MAX_SIZE=1gb
      - TZ=UTC
    ports:
      - "9000:9000"       # Graylog web UI & REST API
      - "5044:5044"       # Beats input
      - "5140:5140/udp"   # Syslog UDP
      - "5140:5140/tcp"   # Syslog TCP
      - "12201:12201"     # GELF TCP
      - "12201:12201/udp" # GELF UDP
    volumes:
      - graylog_data:/usr/share/graylog/data
    networks:
      - graylog

volumes:
  mongodb_data:
  opensearch_data:
  graylog_data:

networks:
  graylog:
    driver: bridge
COMPOSE

# ── 7. Pull images & start the stack ────────────────────────────────────────
info "Pulling container images (this may take a few minutes) ..."
docker compose pull

info "Starting Graylog stack ..."
docker compose up -d

# ── 8. Summary ───────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
info "Graylog is starting up!"
echo ""
echo "  Web UI:   http://<YOUR-SERVER-IP>:9000"
echo "  User:     admin"
echo "  Password: (the one you just entered)"
echo ""
echo "  Project:  ${INSTALL_DIR}"
echo "  Logs:     docker compose -f ${INSTALL_DIR}/docker-compose.yml logs -f"
echo ""
warn "Give it 1-2 minutes for all services to become healthy."
warn "Make sure your CPU supports AVX (in Proxmox, set CPU type to 'host')."
echo "═══════════════════════════════════════════════════════════════"