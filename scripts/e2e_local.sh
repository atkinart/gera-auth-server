#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Local E2E smoke test:
#   - start PostgreSQL in Docker
#   - build app image
#   - run app in Docker
#   - call /actuator/health and print status + body
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

log() { printf "\n[%s] %s\n" "$(date +'%H:%M:%S')" "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1"; exit 1; }
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

log "Running containers:"
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' | sed 's/[[:space:]]\+$//'

log "How to cleanup:"
echo "  make test-local-clean"
echo "  # or: ./scripts/e2e_local.sh clean"
echo "  # add REMOVE_VOLUME=1 to delete Postgres data volume"

log "Done."
