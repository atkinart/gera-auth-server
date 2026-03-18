#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-run}"

APP_PORT="${APP_PORT:-9000}"
MONGO_PORT="${MONGO_PORT:-27017}"
MONGO_DB="${MONGO_DB:-gera}"

APP_ISSUER="${APP_ISSUER:-http://localhost:${APP_PORT}}"
APP_CORS_ORIGINS="${APP_CORS_ORIGINS:-http://localhost:8081}"
MONGO_URI="${MONGO_URI:-mongodb://mongo:27017/${MONGO_DB}}"
SPRING_DATA_MONGODB_URI="${SPRING_DATA_MONGODB_URI:-${MONGO_URI}}"

NET_NAME="${NET_NAME:-e2e_local_net}"
MONGO_CONTAINER="${MONGO_CONTAINER:-e2e_local_mongo}"
APP_CONTAINER="${APP_CONTAINER:-e2e_local_app}"
MONGO_VOLUME="${MONGO_VOLUME:-e2e_local_mongo_data}"
APP_IMAGE="${APP_IMAGE:-e2e-local-app:dev}"

HEALTH_URL="${HEALTH_URL:-http://localhost:${APP_PORT}/actuator/health}"
WAIT_SECONDS="${WAIT_SECONDS:-90}"

RUN_REGISTRATION="${RUN_REGISTRATION:-1}"
REG_USERNAME="${REG_USERNAME:-smoke_user}"
REG_PASSWORD="${REG_PASSWORD:-Password1!}"
REG_EMAIL="${REG_EMAIL:-smoke_user@example.com}"
REGISTER_URL="${REGISTER_URL:-http://localhost:${APP_PORT}/api/auth/register}"

log() { printf "\n[%s] %s\n" "$(date +'%H:%M:%S')" "$*"; }

docker_rm_if_exists() {
  local name="$1"
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
}

ensure_network() {
  if ! docker network ls --format '{{.Name}}' | grep -qx "$NET_NAME"; then
    docker network create "$NET_NAME" >/dev/null
  fi
}

cleanup() {
  log "Cleaning up local e2e containers..."
  docker_rm_if_exists "$APP_CONTAINER"
  docker_rm_if_exists "$MONGO_CONTAINER"

  if docker network ls --format '{{.Name}}' | grep -qx "$NET_NAME"; then
    docker network rm "$NET_NAME" >/dev/null 2>&1 || true
  fi

  if [[ "${REMOVE_VOLUME:-0}" == "1" ]]; then
    if docker volume ls --format '{{.Name}}' | grep -qx "$MONGO_VOLUME"; then
      docker volume rm "$MONGO_VOLUME" >/dev/null 2>&1 || true
    fi
  fi

  log "Done. REMOVE_VOLUME=${REMOVE_VOLUME:-0}"
}

if [[ "$ACTION" == "clean" ]]; then
  cleanup
  exit 0
fi

command -v docker >/dev/null 2>&1 || { echo "Missing docker"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "Missing curl"; exit 1; }
command -v ./gradlew >/dev/null 2>&1 || { echo "Missing ./gradlew"; exit 1; }

log "Preparing docker network and clean state"
ensure_network
docker_rm_if_exists "$APP_CONTAINER"
docker_rm_if_exists "$MONGO_CONTAINER"

log "Starting MongoDB container"
docker run -d \
  --name "$MONGO_CONTAINER" \
  --network "$NET_NAME" \
  --network-alias mongo \
  -p "${MONGO_PORT}:27017" \
  -v "${MONGO_VOLUME}:/data/db" \
  mongo:7 >/dev/null

log "Waiting for MongoDB ping"
mongo_deadline=$((SECONDS + WAIT_SECONDS))
while true; do
  if docker exec "$MONGO_CONTAINER" mongosh --quiet --eval 'db.adminCommand({ ping: 1 }).ok' >/dev/null 2>&1; then
    break
  fi
  if (( SECONDS >= mongo_deadline )); then
    echo "MongoDB did not become ready within ${WAIT_SECONDS}s"
    docker logs --tail 200 "$MONGO_CONTAINER" || true
    exit 1
  fi
  sleep 2
done

log "Building app jar"
./gradlew -q clean bootJar

log "Building app docker image"
docker build -t "$APP_IMAGE" .

log "Starting auth app container"
docker run -d \
  --name "$APP_CONTAINER" \
  --network "$NET_NAME" \
  -p "${APP_PORT}:${APP_PORT}" \
  -e "SERVER_PORT=${APP_PORT}" \
  -e "APP_ISSUER=${APP_ISSUER}" \
  -e "APP_CORS_ORIGINS=${APP_CORS_ORIGINS}" \
  -e "MONGO_URI=${MONGO_URI}" \
  -e "SPRING_DATA_MONGODB_URI=${SPRING_DATA_MONGODB_URI}" \
  "$APP_IMAGE" >/dev/null

log "Waiting for auth health endpoint"
app_deadline=$((SECONDS + WAIT_SECONDS))
while true; do
  if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
    break
  fi
  if (( SECONDS >= app_deadline )); then
    echo "Auth app did not become ready within ${WAIT_SECONDS}s"
    echo "----- auth logs (last 200) -----"
    docker logs --tail 200 "$APP_CONTAINER" || true
    echo "----- mongo logs (last 200) -----"
    docker logs --tail 200 "$MONGO_CONTAINER" || true
    exit 1
  fi
  sleep 2
done

log "Smoke: GET /actuator/health"
health_body="$(mktemp)"
health_code="$(curl -sS -o "$health_body" -w '%{http_code}' "$HEALTH_URL" || true)"
echo "HTTP ${health_code}"
cat "$health_body"
echo
rm -f "$health_body"

if [[ "$RUN_REGISTRATION" == "1" ]]; then
  log "Smoke: POST /api/auth/register"
  reg_body="$(mktemp)"
  reg_resp="$(mktemp)"
  cat >"$reg_body" <<JSON
{"username":"${REG_USERNAME}","password":"${REG_PASSWORD}","email":"${REG_EMAIL}"}
JSON
  reg_code="$(curl -sS -o "$reg_resp" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    --data-binary @"$reg_body" \
    "$REGISTER_URL" || true)"
  echo "HTTP ${reg_code}"
  cat "$reg_resp"
  echo
  rm -f "$reg_body" "$reg_resp"
fi

log "Running containers"
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'

log "Cleanup command"
echo "  make test-local-clean"
echo "  # or: ./scripts/e2e_local.sh clean"
echo "  # add REMOVE_VOLUME=1 to remove Mongo volume"
