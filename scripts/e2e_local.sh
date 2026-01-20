#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Local E2E smoke test:
#   - start PostgreSQL in Docker
#   - build app image
#   - run app in Docker
#   - call /actuator/health and print status + body
#   - (optional) POST /api/auth/register
#   - (optional) OAuth2 client_credentials token + introspection + revocation
#
# Usage:
#   ./scripts/e2e_local.sh
#   ./scripts/e2e_local.sh clean
# -----------------------------------------------------------------------------

ACTION="${1:-run}"

# Tunables (override via env)
APP_PORT="${APP_PORT:-9000}"
DB_PORT="${DB_PORT:-5432}"

DB_NAME="${DB_NAME:-gera_auth}"
DB_USER="${DB_USER:-postgres}"
DB_PASS="${DB_PASS:-postgres}"

# If your app expects different vars, change them here (or export before running).
# DB host will be "postgres" inside the docker network.
SPRING_DATASOURCE_URL="${SPRING_DATASOURCE_URL:-jdbc:postgresql://postgres:5432/${DB_NAME}}"
SPRING_DATASOURCE_USERNAME="${SPRING_DATASOURCE_USERNAME:-${DB_USER}}"
SPRING_DATASOURCE_PASSWORD="${SPRING_DATASOURCE_PASSWORD:-${DB_PASS}}"

# Issuer for local auth server (adjust if your app needs https or another host)
APP_ISSUER="${APP_ISSUER:-http://localhost:${APP_PORT}}"

# Docker resources (namespaced to avoid collisions)
NET_NAME="${NET_NAME:-e2e_local_net}"
PG_CONTAINER="${PG_CONTAINER:-e2e_local_postgres}"
APP_CONTAINER="${APP_CONTAINER:-e2e_local_app}"
PG_VOLUME="${PG_VOLUME:-e2e_local_pgdata}"
APP_IMAGE="${APP_IMAGE:-e2e-local-app:dev}"

HEALTH_URL="${HEALTH_URL:-http://localhost:${APP_PORT}/actuator/health}"
WAIT_SECONDS="${WAIT_SECONDS:-60}"

# E2E HTTP checks (override via env)
RUN_REGISTRATION="${RUN_REGISTRATION:-1}"
RUN_OAUTH_CLIENT_CREDENTIALS="${RUN_OAUTH_CLIENT_CREDENTIALS:-1}"
RUN_OAUTH_INTROSPECT="${RUN_OAUTH_INTROSPECT:-1}"
RUN_OAUTH_REVOKE="${RUN_OAUTH_REVOKE:-1}"

# Registration payload (auto-generated when empty)
REG_USERNAME="${REG_USERNAME:-}"
REG_PASSWORD="${REG_PASSWORD:-Password1!}"
REG_EMAIL="${REG_EMAIL:-}"

# E2E client (created by the app only when APP_E2E_ENABLED=true)
E2E_CLIENT_ID="${E2E_CLIENT_ID:-e2e-client}"
E2E_CLIENT_SECRET="${E2E_CLIENT_SECRET:-e2e-secret}"
E2E_SCOPE="${E2E_SCOPE:-api.read}"

BASE_URL="${BASE_URL:-http://localhost:${APP_PORT}}"
REGISTER_URL="${REGISTER_URL:-${BASE_URL}/api/auth/register}"
TOKEN_URL="${TOKEN_URL:-${BASE_URL}/oauth2/token}"
INTROSPECT_URL="${INTROSPECT_URL:-${BASE_URL}/oauth2/introspect}"
REVOKE_URL="${REVOKE_URL:-${BASE_URL}/oauth2/revoke}"

log() { printf "\n[%s] %s\n" "$(date +'%H:%M:%S')" "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1"; exit 1; }
}

json_get() {
  local key="$1"
  local file="$2"
  python3 - "$key" "$file" <<'PY'
import json, sys
key = sys.argv[1]
path = sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
val = data
for part in key.split("."):
    if isinstance(val, dict) and part in val:
        val = val[part]
    else:
        val = None
        break
if isinstance(val, (dict, list)):
    print(json.dumps(val))
elif val is None:
    print("")
else:
    print(str(val))
PY
}

docker_rm_if_exists() {
  local name="$1"
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
}

docker_network_create_if_needed() {
  if ! docker network ls --format '{{.Name}}' | grep -qx "$NET_NAME"; then
    docker network create "$NET_NAME" >/dev/null
  fi
}

cleanup() {
  log "Cleaning up containers/network (and volume if REMOVE_VOLUME=1)..."
  docker_rm_if_exists "$APP_CONTAINER"
  docker_rm_if_exists "$PG_CONTAINER"

  if docker network ls --format '{{.Name}}' | grep -qx "$NET_NAME"; then
    docker network rm "$NET_NAME" >/dev/null 2>&1 || true
  fi

  if [[ "${REMOVE_VOLUME:-0}" == "1" ]]; then
    if docker volume ls --format '{{.Name}}' | grep -qx "$PG_VOLUME"; then
      docker volume rm "$PG_VOLUME" >/dev/null 2>&1 || true
    fi
  fi

  log "Done. (REMOVE_VOLUME=${REMOVE_VOLUME:-0})"
}

if [[ "$ACTION" == "clean" ]]; then
  cleanup
  exit 0
fi

require_cmd docker
require_cmd curl
require_cmd python3

# Optional but useful
if command -v ./gradlew >/dev/null 2>&1; then
  :
else
  echo "Expected ./gradlew in repo root. If your project differs, adjust the script."
  exit 1
fi

if [[ ! -f Dockerfile ]]; then
  echo "Expected Dockerfile in repo root. If you use another path, set DOCKERFILE=... and adjust build command."
  exit 1
fi

log "Preparing docker network..."
docker_network_create_if_needed

log "Ensuring clean state (containers only)..."
docker_rm_if_exists "$APP_CONTAINER"
docker_rm_if_exists "$PG_CONTAINER"

log "Starting PostgreSQL container..."
docker run -d \
  --name "$PG_CONTAINER" \
  --network "$NET_NAME" \
  --network-alias postgres \
  -p "${DB_PORT}:5432" \
  -e POSTGRES_DB="$DB_NAME" \
  -e POSTGRES_USER="$DB_USER" \
  -e POSTGRES_PASSWORD="$DB_PASS" \
  -v "${PG_VOLUME}:/var/lib/postgresql/data" \
  --health-cmd="pg_isready -U ${DB_USER} -d ${DB_NAME}" \
  --health-interval=2s \
  --health-timeout=3s \
  --health-retries=30 \
  postgres:16 >/dev/null

log "Waiting for PostgreSQL to become healthy..."
pg_deadline=$((SECONDS + WAIT_SECONDS))
while true; do
  status="$(docker inspect -f '{{.State.Health.Status}}' "$PG_CONTAINER" 2>/dev/null || echo "unknown")"
  if [[ "$status" == "healthy" ]]; then
    break
  fi
  if (( SECONDS >= pg_deadline )); then
    echo "PostgreSQL did not become healthy within ${WAIT_SECONDS}s."
    echo "----- postgres logs (last 200 lines) -----"
    docker logs --tail 200 "$PG_CONTAINER" || true
    exit 1
  fi
  sleep 2
done

log "Building application JAR (Gradle)..."
./gradlew -q clean bootJar

log "Building Docker image for app: ${APP_IMAGE} ..."
docker build -t "$APP_IMAGE" .

log "Starting application container..."
docker run -d \
  --name "$APP_CONTAINER" \
  --network "$NET_NAME" \
  -p "${APP_PORT}:${APP_PORT}" \
  -e "SERVER_PORT=${APP_PORT}" \
  -e "SPRING_DATASOURCE_URL=${SPRING_DATASOURCE_URL}" \
  -e "SPRING_DATASOURCE_USERNAME=${SPRING_DATASOURCE_USERNAME}" \
  -e "SPRING_DATASOURCE_PASSWORD=${SPRING_DATASOURCE_PASSWORD}" \
  -e "APP_ISSUER=${APP_ISSUER}" \
  -e "APP_E2E_ENABLED=true" \
  -e "APP_E2E_CLIENT_ID=${E2E_CLIENT_ID}" \
  -e "APP_E2E_CLIENT_SECRET=${E2E_CLIENT_SECRET}" \
  -e "APP_E2E_SCOPE=${E2E_SCOPE}" \
  "${APP_IMAGE}" >/dev/null

log "Waiting for app health endpoint: ${HEALTH_URL}"
app_deadline=$((SECONDS + WAIT_SECONDS))
while true; do
  # We do not want curl to fail the script until the final attempt; just poll.
  if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
    break
  fi
  if (( SECONDS >= app_deadline )); then
    echo "App did not become ready within ${WAIT_SECONDS}s."
    echo "----- app logs (last 200 lines) -----"
    docker logs --tail 200 "$APP_CONTAINER" || true
    echo "----- postgres logs (last 200 lines) -----"
    docker logs --tail 200 "$PG_CONTAINER" || true
    exit 1
  fi
  sleep 2
done

log "Smoke request: GET /actuator/health"
# Print HTTP status + body
tmp_body="$(mktemp)"
http_code="$(curl -sS -o "$tmp_body" -w '%{http_code}' "$HEALTH_URL" || true)"

echo "HTTP ${http_code}"
cat "$tmp_body"
echo
rm -f "$tmp_body"

if [[ "$RUN_REGISTRATION" == "1" ]]; then
  if [[ -z "$REG_USERNAME" ]]; then
    REG_USERNAME="e2e_${RANDOM}_$(python3 -c 'import uuid; print(uuid.uuid4().hex[:8])')"
  fi
  if [[ -z "$REG_EMAIL" ]]; then
    REG_EMAIL="${REG_USERNAME}@example.com"
  fi

  log "Request: POST /api/auth/register"
  reg_body="$(mktemp)"
  cat >"$reg_body" <<JSON
{"username":"${REG_USERNAME}","password":"${REG_PASSWORD}","email":"${REG_EMAIL}"}
JSON

  reg_tmp="$(mktemp)"
  reg_code="$(curl -sS -o "$reg_tmp" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    --data-binary @"$reg_body" \
    "$REGISTER_URL" || true)"
  echo "HTTP ${reg_code}"
  cat "$reg_tmp"
  echo
  rm -f "$reg_body"
  rm -f "$reg_tmp"

  if [[ "$reg_code" != "201" ]]; then
    echo "Registration request failed (HTTP ${reg_code})."
    exit 1
  fi
fi

ACCESS_TOKEN=""
if [[ "$RUN_OAUTH_CLIENT_CREDENTIALS" == "1" ]]; then
  log "Request: OAuth2 client_credentials token"
  token_tmp="$(mktemp)"
  token_code="$(curl -sS -o "$token_tmp" -w '%{http_code}' \
    -u "${E2E_CLIENT_ID}:${E2E_CLIENT_SECRET}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "scope=${E2E_SCOPE}" \
    "$TOKEN_URL" || true)"

  echo "HTTP ${token_code}"
  cat "$token_tmp"
  echo

  if [[ "$token_code" != "200" ]]; then
    echo "Token request failed (HTTP ${token_code})."
    rm -f "$token_tmp"
    exit 1
  fi

  ACCESS_TOKEN="$(json_get access_token "$token_tmp")"
  if [[ -z "$ACCESS_TOKEN" ]]; then
    echo "Token response did not contain access_token."
    rm -f "$token_tmp"
    exit 1
  fi
  rm -f "$token_tmp"
fi

if [[ "$RUN_OAUTH_INTROSPECT" == "1" && -n "$ACCESS_TOKEN" ]]; then
  log "Request: OAuth2 introspect access_token"
  introspect_tmp="$(mktemp)"
  introspect_code="$(curl -sS -o "$introspect_tmp" -w '%{http_code}' \
    -u "${E2E_CLIENT_ID}:${E2E_CLIENT_SECRET}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "token=${ACCESS_TOKEN}" \
    "$INTROSPECT_URL" || true)"

  echo "HTTP ${introspect_code}"
  cat "$introspect_tmp"
  echo

  if [[ "$introspect_code" != "200" ]]; then
    echo "Introspection request failed (HTTP ${introspect_code})."
    rm -f "$introspect_tmp"
    exit 1
  fi

  active="$(json_get active "$introspect_tmp")"
  client_id="$(json_get client_id "$introspect_tmp")"
  if [[ "$active" != "True" && "$active" != "true" ]]; then
    echo "Expected introspection active=true but got: ${active}"
    rm -f "$introspect_tmp"
    exit 1
  fi
  if [[ -n "$client_id" && "$client_id" != "$E2E_CLIENT_ID" ]]; then
    echo "Expected introspection client_id=${E2E_CLIENT_ID} but got: ${client_id}"
    rm -f "$introspect_tmp"
    exit 1
  fi

  rm -f "$introspect_tmp"
fi

if [[ "$RUN_OAUTH_REVOKE" == "1" && -n "$ACCESS_TOKEN" ]]; then
  log "Request: OAuth2 revoke access_token"
  revoke_tmp="$(mktemp)"
  revoke_code="$(curl -sS -o "$revoke_tmp" -w '%{http_code}' \
    -u "${E2E_CLIENT_ID}:${E2E_CLIENT_SECRET}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "token_type_hint=access_token" \
    --data-urlencode "token=${ACCESS_TOKEN}" \
    "$REVOKE_URL" || true)"

  echo "HTTP ${revoke_code}"
  cat "$revoke_tmp"
  echo
  rm -f "$revoke_tmp"

  if [[ "$revoke_code" != "200" ]]; then
    echo "Revocation request failed (HTTP ${revoke_code})."
    exit 1
  fi

  if [[ "$RUN_OAUTH_INTROSPECT" == "1" ]]; then
    log "Request: OAuth2 introspect access_token after revocation (expect inactive)"
    post_tmp="$(mktemp)"
    post_code="$(curl -sS -o "$post_tmp" -w '%{http_code}' \
      -u "${E2E_CLIENT_ID}:${E2E_CLIENT_SECRET}" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "token=${ACCESS_TOKEN}" \
      "$INTROSPECT_URL" || true)"

    echo "HTTP ${post_code}"
    cat "$post_tmp"
    echo

    if [[ "$post_code" != "200" ]]; then
      echo "Post-revoke introspection failed (HTTP ${post_code})."
      rm -f "$post_tmp"
      exit 1
    fi

    post_active="$(json_get active "$post_tmp")"
    rm -f "$post_tmp"
    if [[ "$post_active" != "False" && "$post_active" != "false" ]]; then
      echo "Expected introspection active=false after revoke but got: ${post_active}"
      exit 1
    fi
  fi
fi

log "Running containers:"
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' | sed 's/[[:space:]]\+$//'

log "How to cleanup:"
echo "  make test-local-clean"
echo "  # or: ./scripts/e2e_local.sh clean"
echo "  # add REMOVE_VOLUME=1 to delete Postgres data volume"

log "Done."
