#!/usr/bin/env bash
# lib/common.sh — Shared library for ldap-toolbox
# Sourced by toolbox.sh and all modules. Never executed directly.

# ── Colors ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m';  YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';   MAGENTA='\033[0;35m'
BOLD='\033[1m';    DIM='\033[2m';        RESET='\033[0m'

# ── Print helpers ──────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══ $* ══${RESET}"; }
die()     { error "$*"; exit 1; }
hr()      { echo -e "${DIM}  ──────────────────────────────────────────────────────${RESET}"; }
press_enter() { echo; read -rp "  Press Enter to continue..." _ ; echo; }
confirm()     { local a; read -rp "  ${1:-Are you sure?} [y/N]: " a; [[ "${a,,}" == "y" ]]; }

print_banner() {
    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║       LDAP TOOLBOX — Credential Manager v1.0        ║"
    echo "  ║     CCDC / Lab Use Only — Authorized Access Only     ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ── Session management ─────────────────────────────────────────────────────────
# SESSIONS_DIR, SESSION_DIR, SESSION_NAME are set by toolbox.sh

new_session() {
    SESSION_NAME=$(date +%Y%m%d_%H%M%S)
    SESSION_DIR="${SESSIONS_DIR}/${SESSION_NAME}"
    mkdir -p "${SESSION_DIR}/user_data" \
             "${SESSION_DIR}/selections" \
             "${SESSION_DIR}/sshkeys" \
             "${SESSION_DIR}/output/sshkeys"
    ln -sfn "${SESSION_DIR}" "${SESSIONS_DIR}/latest"
    # Init all env vars to safe defaults
    LDAP_URI=""
    BIND_DN=""
    BIND_PW=""
    BASE_DN=""
    LDAP_CACERT=""
    KRB5_ENABLED="false"
    KRB5_REALM=""
    KRB5_KDC=""
    KADMIN_PRINCIPAL="kadmin/admin"
    SSH_ATTR="sshPublicKey"
    USER_OBJECT_CLASS="posixAccount"
    USER_OU=""
    SERVICE_OUS=""
    FILTER_PATTERNS="whiteteam white wt scorebot scoring inject blackteam black redteam"
    info "New session: ${SESSION_NAME}"
}

load_session() {
    local target="${1:-latest}"
    if [[ "$target" == "latest" ]]; then
        [[ -L "${SESSIONS_DIR}/latest" ]] || die "No previous session found. Run Full Workflow first."
        SESSION_DIR=$(readlink -f "${SESSIONS_DIR}/latest")
    else
        SESSION_DIR="${SESSIONS_DIR}/${target}"
    fi
    [[ -d "$SESSION_DIR" ]] || die "Session directory not found: $SESSION_DIR"
    SESSION_NAME=$(basename "$SESSION_DIR")
    [[ -f "${SESSION_DIR}/env.conf" ]] || die "Session env.conf missing — re-run enumeration."
    # shellcheck source=/dev/null
    source "${SESSION_DIR}/env.conf"
    info "Loaded session: ${SESSION_NAME}"
}

save_env_conf() {
    cat > "${SESSION_DIR}/env.conf" <<EOF
LDAP_URI='${LDAP_URI}'
BIND_DN='${BIND_DN}'
BIND_PW='${BIND_PW}'
BASE_DN='${BASE_DN}'
LDAP_CACERT='${LDAP_CACERT}'
KRB5_ENABLED='${KRB5_ENABLED}'
KRB5_REALM='${KRB5_REALM}'
KRB5_KDC='${KRB5_KDC}'
KADMIN_PRINCIPAL='${KADMIN_PRINCIPAL}'
SSH_ATTR='${SSH_ATTR}'
USER_OBJECT_CLASS='${USER_OBJECT_CLASS}'
USER_OU='${USER_OU}'
SERVICE_OUS='${SERVICE_OUS}'
FILTER_PATTERNS='${FILTER_PATTERNS}'
EOF
}

# ── LDAP helpers ───────────────────────────────────────────────────────────────
ldap_search() {
    LDAPTLS_CACERT="${LDAP_CACERT}" \
    ldapsearch -x -LLL -o ldif-wrap=no \
        -H "${LDAP_URI}" -D "${BIND_DN}" -w "${BIND_PW}" "$@" 2>/dev/null
}

test_ldap_conn() {
    LDAPTLS_CACERT="${LDAP_CACERT}" \
    ldapsearch -x -LLL -o ldif-wrap=no \
        -H "${LDAP_URI}" -D "${BIND_DN}" -w "${BIND_PW}" \
        -b "${BASE_DN}" -s base "(objectClass=*)" dn &>/dev/null
}

# Extract a single-value attribute from an LDIF block.
# Handles both "attr: value" (plain) and "attr:: value" (base64-encoded).
ldif_attr() {
    local attr="$1"
    local ldif="$2"
    local val

    # Try base64-encoded first
    val=$(printf '%s\n' "$ldif" | grep -P "^${attr}:: " | head -1 | sed "s/^${attr}:: //")
    if [[ -n "$val" ]]; then
        printf '%s' "$val" | base64 -d 2>/dev/null
        return
    fi
    # Plain value
    printf '%s\n' "$ldif" | grep -P "^${attr}: " | head -1 | sed "s/^${attr}: //"
}

# ── Password & key generation ──────────────────────────────────────────────────
gen_random_password() {
    # 16 chars: mixed case, digits, symbols. Excludes 0/O/l/1/I to avoid confusion.
    tr -dc 'A-HJ-NP-Za-km-z2-9@#!' < /dev/urandom 2>/dev/null | head -c 16
    echo
}

# Generate SSHA hash compatible with OpenLDAP userPassword.
# Uses openssl so slappasswd is not required (works on any client host).
gen_ssha_hash() {
    local password="$1"
    local tmp; tmp=$(mktemp -d)
    openssl rand 4 > "${tmp}/salt" 2>/dev/null
    # hash = SHA1(password || salt)
    printf '%s' "$password" | cat - "${tmp}/salt" \
        | openssl dgst -sha1 -binary 2>/dev/null > "${tmp}/hash"
    cat "${tmp}/hash" "${tmp}/salt" > "${tmp}/combined"
    printf '{SSHA}%s' "$(base64 -w 0 < "${tmp}/combined")"
    rm -rf "$tmp"
}

# Generate an ED25519 keypair into SESSION_DIR/sshkeys/
# Returns the public key on stdout.
gen_ed25519_keypair() {
    local uid="$1"
    local keydir="${SESSION_DIR}/sshkeys"
    rm -f "${keydir}/${uid}" "${keydir}/${uid}.pub"
    ssh-keygen -t ed25519 -C "${uid}@ldap-toolbox" \
        -f "${keydir}/${uid}" -N "" -q 2>/dev/null
    cat "${keydir}/${uid}.pub"
}
