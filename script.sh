#!/usr/bin/env bash
set -euo pipefail

# ===[ 0G RPC Manager ]=========================================================
# Features:
# - install: 0G Galileo (consensus: 0gchaind) + geth (execution), systemd services
# - reverse-proxy: Nginx + TLS (Let's Encrypt or self-signed), rate limit, CORS
# - access control: IP allowlist (Nginx) + optional HTTP Basic Auth users
# - lifecycle: start/stop/restart/status, logs (follow), validate, health checks
# - update/upgrade binaries, backup/restore data snapshots, firewall helper
# ==============================================================================

# ------------------------- USER CONFIG (edit as needed) -----------------------
NODE_NAME="${NODE_NAME:-my-0g-node}"
INSTALL_DIR="${INSTALL_DIR:-/opt/0g}"
DATA_DIR="${DATA_DIR:-/var/lib/0g}"
LOG_DIR="${LOG_DIR:-/var/log/0g}"
USER_NAME="${USER_NAME:-0g}"
GROUP_NAME="${GROUP_NAME:-0g}"

# 0G Galileo build (adjust to latest known good release if you like)
OG_RELEASE="${OG_RELEASE:-v1.2.0}"
OG_TARBALL="${OG_TARBALL:-galileo-${OG_RELEASE}.tar.gz}"
OG_RELEASE_URL="${OG_RELEASE_URL:-https://github.com/0glabs/0gchain-NG/releases/download/${OG_RELEASE}/galileo-${OG_RELEASE}.tar.gz}"

# Network/chain
CHAIN_ID="${CHAIN_ID:-16601}"         # Galileo
EXT_IP="${EXT_IP:-}"                  # set to your public IP or leave blank (auto)
DOMAIN="${DOMAIN:-rpc.example.com}"   # your DNS pointing to this box

# Ports
HTTP_PORT="${HTTP_PORT:-8545}"
WS_PORT="${WS_PORT:-8546}"
AUTH_PORT="${AUTH_PORT:-8551}"
P2P_PORT_TM="${P2P_PORT_TM:-26656}"
RPC_PORT_TM="${RPC_PORT_TM:-26657}"
NODE_API_PORT="${NODE_API_PORT:-3500}"

# Nginx / TLS
ENABLE_NGINX="${ENABLE_NGINX:-true}"
USE_LETSENCRYPT="${USE_LETSENCRYPT:-true}"  # if false -> self-signed
CORS_ORIGIN="${CORS_ORIGIN:-https://${DOMAIN}}"
RATE_LIMIT_RPS="${RATE_LIMIT_RPS:-20}"      # per IP
ALLOWED_IPS_FILE="/etc/nginx/0g-allowlist.conf" # managed by this script
BASIC_AUTH_FILE="/etc/nginx/.htpasswd-0g"

# Geth config (exposed modules kept safe)
HTTP_MODULES='["eth","net","web3","engine"]'
WS_MODULES='["eth","net","web3","engine"]'

# Bootnodes (example—replace if 0G publishes updated ones)
GETH_BOOTNODE="${GETH_BOOTNODE:-enode://de7b86d8ac45@8.218.88.60:30303}"
TM_SEEDS="${TM_SEEDS:-85a9b9a1b7fa0969704db2bc37f7c100855a75d9@8.218.88.60:${P2P_PORT_TM}}"

# -----------------------------------------------------------------------------

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run as root (sudo)." >&2
    exit 1
  fi
}

ensure_user() {
  id -u "${USER_NAME}" &>/dev/null || useradd -r -m -d "${INSTALL_DIR}" -s /usr/sbin/nologin "${USER_NAME}"
  getent group "${GROUP_NAME}" &>/dev/null || groupadd -r "${GROUP_NAME}"
  usermod -a -G "${GROUP_NAME}" "${USER_NAME}" || true
}

ensure_dirs() {
  mkdir -p "${INSTALL_DIR}/bin" "${DATA_DIR}"/{geth-home,0gchaind-home} "${LOG_DIR}"
  chown -R "${USER_NAME}:${GROUP_NAME}" "${INSTALL_DIR}" "${DATA_DIR}" "${LOG_DIR}"
}

detect_ip() {
  if [[ -z "${EXT_IP}" ]]; then
    EXT_IP=$(curl -s ifconfig.me || true)
    [[ -z "${EXT_IP}" ]] && EXT_IP="0.0.0.0"
  fi
}

install_deps() {
  apt-get update
  apt-get install -y curl wget jq tar unzip ca-certificates gnupg \
    nginx apache2-utils ufw python3
}

fetch_0g() {
  echo "Downloading 0G package: ${OG_RELEASE_URL}"
  tmp="$(mktemp -d)"
  wget -qO "${tmp}/${OG_TARBALL}" "${OG_RELEASE_URL}"
  tar -xzf "${tmp}/${OG_TARBALL}" -C "${tmp}"
  # Expecting ./bin/geth and ./bin/0gchaind plus genesis/kzg/jwt files in bundle
  install -m 0755 "${tmp}"/bin/geth "${INSTALL_DIR}/bin/geth"
  install -m 0755 "${tmp}"/bin/0gchaind "${INSTALL_DIR}/bin/0gchaind"
  # copy config assets if present
  for f in genesis.json kzg-trusted-setup.json jwt-secret.hex; do
    if [[ -f "${tmp}/${f}" ]]; then
      install -m 0644 "${tmp}/${f}" "${INSTALL_DIR}/${f}"
    fi
  done
  chown -R "${USER_NAME}:${GROUP_NAME}" "${INSTALL_DIR}"
  rm -rf "${tmp}"
}

write_geth_config() {
  cat >/etc/0g-geth.toml <<EOF
[Eth]
NetworkId = ${CHAIN_ID}

[Node]
DataDir = "${DATA_DIR}/geth-home"

HTTPHost = "0.0.0.0"
HTTPPort = ${HTTP_PORT}
HTTPModules = ${HTTP_MODULES}
HTTPVirtualHosts = ["*"]

WSHost = "0.0.0.0"
WSPort = ${WS_PORT}
WSModules = ${WS_MODULES}

AuthAddr = "0.0.0.0"
AuthPort = ${AUTH_PORT}
AuthVirtualHosts = ["*"]
EOF
  chown "${USER_NAME}:${GROUP_NAME}" /etc/0g-geth.toml
}

init_stores() {
  # geth init
  if [[ ! -f "${DATA_DIR}/geth-home/geth/chaindata/CURRENT" ]]; then
    sudo -u "${USER_NAME}" "${INSTALL_DIR}/bin/geth" init \
      --datadir "${DATA_DIR}/geth-home" "${INSTALL_DIR}/genesis.json"
  fi

  # 0gchaind keys/state (only if not present)
  mkdir -p "${DATA_DIR}/0gchaind-home"/{config,data}
  if [[ ! -f "${DATA_DIR}/0gchaind-home/config/priv_validator_key.json" ]]; then
    tmpd="$(mktemp -d)"
    sudo -u "${USER_NAME}" "${INSTALL_DIR}/bin/0gchaind" init "${NODE_NAME}" --home "${tmpd}"
    cp -n "${tmpd}/config/node_key.json"           "${DATA_DIR}/0gchaind-home/config/" || true
    cp -n "${tmpd}/config/priv_validator_key.json" "${DATA_DIR}/0gchaind-home/config/" || true
    cp -n "${tmpd}/data/priv_validator_state.json" "${DATA_DIR}/0gchaind-home/data/"   || true
    rm -rf "${tmpd}"
  fi
  chown -R "${USER_NAME}:${GROUP_NAME}" "${DATA_DIR}"
}

write_systemd_units() {
  cat >/etc/systemd/system/0gchaind.service <<EOF
[Unit]
Description=0G Consensus (0gchaind)
After=network-online.target
Wants=network-online.target

[Service]
User=${USER_NAME}
Group=${GROUP_NAME}
LimitNOFILE=1000000
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/0gchaind start \
  --rpc.laddr tcp://0.0.0.0:${RPC_PORT_TM} \
  --chaincfg.chain-spec devnet \
  --chaincfg.kzg.trusted-setup-path=${INSTALL_DIR}/kzg-trusted-setup.json \
  --chaincfg.engine.jwt-secret-path=${INSTALL_DIR}/jwt-secret.hex \
  --chaincfg.kzg.implementation=crate-crypto/go-kzg-4844 \
  --chaincfg.block-store-service.enabled \
  --chaincfg.node-api.enabled \
  --chaincfg.node-api.logging \
  --chaincfg.node-api.address 0.0.0.0:${NODE_API_PORT} \
  --pruning=nothing \
  --home ${DATA_DIR}/0gchaind-home \
  --p2p.seeds ${TM_SEEDS} \
  --p2p.external_address ${EXT_IP}:${P2P_PORT_TM}
StandardOutput=append:${LOG_DIR}/0gchaind.log
StandardError=append:${LOG_DIR}/0gchaind.err
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/0g-geth.service <<EOF
[Unit]
Description=0G Execution (geth)
After=0gchaind.service
Requires=0gchaind.service

[Service]
User=${USER_NAME}
Group=${GROUP_NAME}
LimitNOFILE=1000000
ExecStart=${INSTALL_DIR}/bin/geth --config /etc/0g-geth.toml \
  --nat extip:${EXT_IP} \
  --bootnodes ${GETH_BOOTNODE} \
  --datadir ${DATA_DIR}/geth-home \
  --networkid ${CHAIN_ID}
StandardOutput=append:${LOG_DIR}/geth.log
StandardError=append:${LOG_DIR}/geth.err
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
}

configure_nginx() {
  [[ "${ENABLE_NGINX}" != "true" ]] && return 0

  # Allowlist include file (managed by this script)
  if [[ ! -f "${ALLOWED_IPS_FILE}" ]]; then
    echo "allow 127.0.0.1;" > "${ALLOWED_IPS_FILE}"
    echo "deny all;"       >> "${ALLOWED_IPS_FILE}"
  fi

  # Nginx site
  cat >/etc/nginx/sites-available/0g-rpc.conf <<EOF
map \$http_authorization \$auth_basic_user {
    default "";
}

limit_req_zone \$binary_remote_addr zone=api:${RATE_LIMIT_RPS}m rate=${RATE_LIMIT_RPS}r/s;

server {
    listen 80;
    server_name ${DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};

    # TLS (will be replaced by certbot if USE_LETSENCRYPT=true)
    ssl_certificate /etc/ssl/0g/self.crt;
    ssl_certificate_key /etc/ssl/0g/self.key;

    # Rate limit + CORS
    limit_req zone=api burst=50 nodelay;

    add_header Access-Control-Allow-Origin "${CORS_ORIGIN}" always;
    add_header Access-Control-Allow-Methods "GET,POST,OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type,Authorization" always;

    # Optional Basic Auth (create users via: add-user <name>)
    auth_basic "Restricted";
    auth_basic_user_file ${BASIC_AUTH_FILE};

    # IP allowlist
    include ${ALLOWED_IPS_FILE};

    # HTTP JSON-RPC
    location / {
        proxy_pass http://127.0.0.1:${HTTP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_read_timeout 300s;
    }

    # WebSocket
    location /ws {
        proxy_pass http://127.0.0.1:${WS_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
    }
}
EOF

  ln -sf /etc/nginx/sites-available/0g-rpc.conf /etc/nginx/sites-enabled/0g-rpc.conf
  mkdir -p /etc/ssl/0g

  if [[ "${USE_LETSENCRYPT}" == "true" ]]; then
    apt-get install -y certbot python3-certbot-nginx
    systemctl reload nginx || true
    certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos -m "admin@${DOMAIN}" || true
  else
    if [[ ! -f /etc/ssl/0g/self.crt ]]; then
      openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/0g/self.key -out /etc/ssl/0g/self.crt \
        -subj "/CN=${DOMAIN}"
    fi
  fi

  systemctl enable --now nginx
  nginx -t && systemctl reload nginx
}

open_firewall() {
  ufw allow 22/tcp || true
  ufw allow "${P2P_PORT_TM}"/tcp || true
  ufw allow "${RPC_PORT_TM}"/tcp || true
  ufw allow "${HTTP_PORT}"/tcp || true
  ufw allow "${WS_PORT}"/tcp || true
  ufw allow "${AUTH_PORT}"/tcp || true
  ufw allow 80,443/tcp || true
  yes | ufw enable || true
  ufw status || true
}

install_all() {
  require_root
  detect_ip
  install_deps
  ensure_user
  ensure_dirs
  fetch_0g
  write_geth_config
  init_stores
  write_systemd_units
  systemctl enable --now 0gchaind.service
  sleep 2
  systemctl enable --now 0g-geth.service
  if [[ "${ENABLE_NGINX}" == "true" ]]; then
    configure_nginx
  fi
  open_firewall
  echo "Install completed. Public endpoint: https://${DOMAIN}"
}

# ------------------------------- Access Control -------------------------------
add_ip() {
  require_root
  [[ ! -f "${ALLOWED_IPS_FILE}" ]] && echo "allow 127.0.0.1;" > "${ALLOWED_IPS_FILE}"
  local ip="${1:-}"
  [[ -z "${ip}" ]] && { echo "Usage: $0 access add-ip <IP/CIDR>"; exit 1; }
  grep -q "allow ${ip};" "${ALLOWED_IPS_FILE}" || sed -i "1i allow ${ip};" "${ALLOWED_IPS_FILE}"
  nginx -t && systemctl reload nginx
  echo "Added IP ${ip} to allowlist."
}

remove_ip() {
  require_root
  local ip="${1:-}"
  [[ -z "${ip}" ]] && { echo "Usage: $0 access remove-ip <IP/CIDR>"; exit 1; }
  sed -i "\#allow ${ip};#d" "${ALLOWED_IPS_FILE}" || true
  nginx -t && systemctl reload nginx
  echo "Removed IP ${ip}."
}

list_ips() {
  [[ -f "${ALLOWED_IPS_FILE}" ]] && cat "${ALLOWED_IPS_FILE}" || echo "No allowlist file."
}

add_user() {
  require_root
  local user="${1:-}"
  [[ -z "${user}" ]] && { echo "Usage: $0 access add-user <username>"; exit 1; }
  htpasswd "${BASIC_AUTH_FILE}" "${user}"
  nginx -t && systemctl reload nginx
}

remove_user() {
  require_root
  local user="${1:-}"
  [[ -z "${user}" ]] && { echo "Usage: $0 access remove-user <username>"; exit 1; }
  [[ -f "${BASIC_AUTH_FILE}" ]] && htpasswd -D "${BASIC_AUTH_FILE}" "${user}" || true
  nginx -t && systemctl reload nginx
}

list_users() {
  [[ -f "${BASIC_AUTH_FILE}" ]] && cut -d: -f1 "${BASIC_AUTH_FILE}" || echo "No users."
}

# --------------------------------- Lifecycle ---------------------------------
start_services()  { systemctl start 0gchaind 0g-geth; systemctl status --no-pager 0gchaind 0g-geth || true; }
stop_services()   { systemctl stop 0g-geth 0gchaind; }
restart_services(){ systemctl restart 0gchaind 0g-geth; }
status_services() { systemctl status --no-pager 0gchaind 0g-geth || true; }

logs_follow() {
  journalctl -u 0gchaind -u 0g-geth -f -n 200
}

logs_tail() {
  tail -n 200 "${LOG_DIR}/0gchaind.log" || true
  tail -n 200 "${LOG_DIR}/geth.log" || true
}

# -------------------------------- Health/Utils --------------------------------
rpc_block() {
  curl -s "http://127.0.0.1:${HTTP_PORT}" \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | jq -r '.result'
}

tm_status() {
  curl -s "http://127.0.0.1:${RPC_PORT_TM}/status" | jq '.result.sync_info'
}

health() {
  echo "Execution block: $(rpc_block)"
  echo "Consensus sync:  "; tm_status
}

validate() {
  echo "Nginx: "; nginx -t || true
  echo "Services:"
  systemctl is-active 0gchaind && echo "0gchaind: active" || echo "0gchaind: inactive"
  systemctl is-active 0g-geth && echo "0g-geth: active" || echo "0g-geth: inactive"
}

upgrade() {
  echo "Stopping services..."
  stop_services || true
  echo "Fetching new release: ${OG_RELEASE}"
  fetch_0g
  echo "Starting services..."
  start_services
}

backup() {
  local dst="${1:-/root/0g-backup-$(date +%Y%m%d-%H%M)}"
  mkdir -p "${dst}"
  systemctl stop 0g-geth 0gchaind
  rsync -a "${DATA_DIR}/" "${dst}/data/"
  rsync -a /etc/0g-geth.toml "${dst}/"
  rsync -a "${INSTALL_DIR}/" "${dst}/install/"
  systemctl start 0gchaind 0g-geth
  echo "Backup at ${dst}"
}

restore() {
  local src="${1:-}"
  [[ -z "${src}" ]] && { echo "Usage: $0 restore </path/to/backup>"; exit 1; }
  systemctl stop 0g-geth 0gchaind
  rsync -a "${src}/data/" "${DATA_DIR}/"
  rsync -a "${src}/0g-geth.toml" /etc/0g-geth.toml || true
  rsync -a "${src}/install/" "${INSTALL_DIR}/"
  chown -R "${USER_NAME}:${GROUP_NAME}" "${DATA_DIR}" "${INSTALL_DIR}"
  systemctl start 0gchaind 0g-geth
  echo "Restored from ${src}"
}

firewall_lockdown() {
  ufw deny "${HTTP_PORT}"/tcp || true
  ufw deny "${WS_PORT}"/tcp || true
  ufw status || true
  echo "HTTP/WS closed at host firewall. (Still available behind Nginx if enabled.)"
}

rpc_test_public() {
  echo "Testing public endpoint https://${DOMAIN}"
  curl -s "https://${DOMAIN}" -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | jq .
}

usage() {
cat <<USAGE
0G RPC Manager

Usage: $0 <command> [args]

Install & config:
  install                      Install binaries, create data dirs, systemd, nginx, firewall
  upgrade                      Download and replace binaries, restart services

Lifecycle:
  start|stop|restart|status    Control services
  logs follow                  Live logs via journalctl
  logs tail                    Last 200 lines of file logs

Access control:
  access add-ip <IP/CIDR>      Allow an IP in Nginx
  access remove-ip <IP/CIDR>   Remove an IP from Nginx
  access list-ips              Show current allowlist
  access add-user <name>       Add Basic Auth user (prompt for password)
  access remove-user <name>    Remove Basic Auth user
  access list-users            List Basic Auth users

Health & utils:
  validate                     Check services + nginx config
  health                       Show block height + consensus sync state
  rpc test-public              Call eth_blockNumber via https://${DOMAIN}
  backup [dst_dir]             Stop, snapshot data/config, start
  restore <src_dir>            Stop, restore snapshot, start
  firewall lockdown            Close raw HTTP/WS ports at host firewall

Tip: Set env vars before running, e.g.
  DOMAIN=rpc.myorg.com ENABLE_NGINX=true USE_LETSENCRYPT=true $0 install
USAGE
}

# --------------------------------- Router ------------------------------------
cmd="${1:-}"; shift || true
case "${cmd}" in
  install) install_all ;;
  upgrade) upgrade ;;
  start) start_services ;;
  stop) stop_services ;;
  restart) restart_services ;;
  status) status_services ;;
  logs)
    sub="${1:-}"; shift || true
    case "${sub}" in
      follow) logs_follow ;;
      tail) logs_tail ;;
      *) echo "Usage: $0 logs [follow|tail]"; exit 1 ;;
    esac
    ;;
  access)
    sub="${1:-}"; shift || true
    case "${sub}" in
      add-ip) add_ip "${1:-}";;
      remove-ip) remove_ip "${1:-}";;
      list-ips) list_ips ;;
      add-user) add_user "${1:-}";;
      remove-user) remove_user "${1:-}";;
      list-users) list_users ;;
      *) echo "Usage: $0 access [add-ip|remove-ip|list-ips|add-user|remove-user|list-users]"; exit 1 ;;
    esac
    ;;
  validate) validate ;;
  health) health ;;
  rpc)
    sub="${1:-}"; shift || true
    case "${sub}" in
      test-public) rpc_test_public ;;
      *) echo "Usage: $0 rpc test-public"; exit 1 ;;
    esac
    ;;
  backup) backup "${1:-}";;
  restore) restore "${1:-}";;
  firewall)
    sub="${1:-}"; shift || true
    case "${sub}" in
      lockdown) firewall_lockdown ;;
      *) echo "Usage: $0 firewall lockdown"; exit 1 ;;
    esac
    ;;
  ""|-h|--help|help) usage ;;
  *) echo "Unknown command: ${cmd}"; usage; exit 1 ;;
esac
