#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Local E2E smoke test:
#   - start PostgreSQL in Docker
#   - build app image
#   - run app in Docker
#   - call /actuator/health and print status + body
#   - (optional) POST /api/auth/register
#   - (optional) OAuth2 Authorization Code + PKCE (as SPA client)
#   - (optional) call /userinfo with the issued access_token
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
RUN_OAUTH_PKCE="${RUN_OAUTH_PKCE:-1}"
RUN_USERINFO="${RUN_USERINFO:-1}"

# Registration payload (auto-generated when empty)
REG_USERNAME="${REG_USERNAME:-}"
REG_PASSWORD="${REG_PASSWORD:-Password1!}"
REG_EMAIL="${REG_EMAIL:-}"

# SPA client (exists in production via ClientInitializer)
SPA_CLIENT_ID="${SPA_CLIENT_ID:-spa}"
SPA_REDIRECT_URI="${SPA_REDIRECT_URI:-http://localhost:5173/callback}"
SPA_SCOPE="${SPA_SCOPE:-openid profile api.read}"

BASE_URL="${BASE_URL:-http://localhost:${APP_PORT}}"
REGISTER_URL="${REGISTER_URL:-${BASE_URL}/api/auth/register}"
TOKEN_URL="${TOKEN_URL:-${BASE_URL}/oauth2/token}"
AUTHORIZE_URL="${AUTHORIZE_URL:-${BASE_URL}/oauth2/authorize}"
LOGIN_URL="${LOGIN_URL:-${BASE_URL}/login}"
USERINFO_URL="${USERINFO_URL:-${BASE_URL}/userinfo}"

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

urlencode() {
  python3 - "$1" <<'PY'
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
}

pkce_verifier() {
  python3 - <<'PY'
import os, base64
print(base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("="))
PY
}

pkce_challenge_s256() {
  python3 - "$1" <<'PY'
import sys, hashlib, base64
v = sys.argv[1].encode("ascii")
d = hashlib.sha256(v).digest()
print(base64.urlsafe_b64encode(d).decode("ascii").rstrip("="))
PY
}

extract_csrf() {
  local html_file="$1"
  python3 - "$html_file" <<'PY'
import pathlib, re, sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="ignore")
patterns = [
    r'name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']',
    r'value=["\']([^"\']+)["\'][^>]*name=["\']_csrf["\']',
]

for pattern in patterns:
    m = re.search(pattern, text)
    if m:
        print(m.group(1))
        break
else:
    print("")
PY
}

extract_location_header() {
  local headers_file="$1"
  awk 'BEGIN{IGNORECASE=1} /^Location:/ {sub(/\r$/,""); print substr($0, 10)}' "$headers_file" | tail -n1
}

extract_query_param() {
  python3 - "$1" "$2" <<'PY'
import sys, urllib.parse
url = sys.argv[1]
key = sys.argv[2]
q = urllib.parse.urlparse(url).query
params = urllib.parse.parse_qs(q)
print((params.get(key) or [""])[0])
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
if [[ "$RUN_OAUTH_PKCE" == "1" ]]; then
  if [[ -z "${REG_USERNAME}" ]]; then
    echo "RUN_OAUTH_PKCE=1 requires a user. Either RUN_REGISTRATION=1 or set REG_USERNAME/REG_PASSWORD."
    exit 1
  fi

  log "OAuth2 PKCE: login as user (${REG_USERNAME})"
  cookies="$(mktemp)"
  login_html="$(mktemp)"

  curl -sS -c "$cookies" -b "$cookies" -o "$login_html" "$LOGIN_URL"
  login_csrf="$(extract_csrf "$login_html")"
  if [[ -z "$login_csrf" ]]; then
    echo "Could not extract CSRF token from login page."
    sed -n '1,120p' "$login_html" || true
    rm -f "$login_html" "$cookies"
    exit 1
  fi
  rm -f "$login_html"

  login_code="$(curl -sS -o /dev/null -w '%{http_code}' \
    -c "$cookies" -b "$cookies" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${REG_USERNAME}" \
    --data-urlencode "password=${REG_PASSWORD}" \
    --data-urlencode "_csrf=${login_csrf}" \
    "$LOGIN_URL" || true)"

  if [[ "$login_code" != "302" ]]; then
    echo "Login failed (HTTP ${login_code})."
    rm -f "$cookies"
    exit 1
  fi

  log "OAuth2 PKCE: authorize (client_id=${SPA_CLIENT_ID})"
  verifier="$(pkce_verifier)"
  challenge="$(pkce_challenge_s256 "$verifier")"
  state="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  nonce="$(python3 -c 'import uuid; print(uuid.uuid4())')"

  auth_headers="$(mktemp)"
  auth_body="$(mktemp)"
  auth_query="response_type=code"
  auth_query="${auth_query}&client_id=$(urlencode "$SPA_CLIENT_ID")"
  auth_query="${auth_query}&redirect_uri=$(urlencode "$SPA_REDIRECT_URI")"
  auth_query="${auth_query}&scope=$(urlencode "$SPA_SCOPE")"
  auth_query="${auth_query}&code_challenge=$(urlencode "$challenge")"
  auth_query="${auth_query}&code_challenge_method=S256"
  auth_query="${auth_query}&state=$(urlencode "$state")"
  auth_query="${auth_query}&nonce=$(urlencode "$nonce")"

  auth_code="$(curl -sS -D "$auth_headers" -o "$auth_body" -w '%{http_code}' \
    -c "$cookies" -b "$cookies" \
    "${AUTHORIZE_URL}?${auth_query}" || true)"

  if [[ "$auth_code" == "200" ]]; then
    # Consent page expected when spa requires consent
    consent_csrf="$(extract_csrf "$auth_body")"
    consent_action_url="$(grep -Eo '<form[^>]+action="[^"]+"' "$auth_body" | head -n1 | sed -E 's/.*action="([^"]+)".*/\1/')"
    consent_action_url="${consent_action_url:-/oauth2/authorize}"
    if [[ "$consent_action_url" != http* ]]; then
      consent_action_url="${BASE_URL}${consent_action_url}"
    fi

    state_in_form="$(grep -Eo 'name="state" value="[^"]+"' "$auth_body" | head -n1 | sed -E 's/.*value="([^"]+)".*/\1/')"
    client_in_form="$(grep -Eo 'name="client_id" value="[^"]+"' "$auth_body" | head -n1 | sed -E 's/.*value="([^"]+)".*/\1/')"
    state_in_form="${state_in_form:-$state}"
    client_in_form="${client_in_form:-$SPA_CLIENT_ID}"

    scopes=()
    while IFS= read -r s; do
      [[ -n "$s" ]] && scopes+=("$s")
    done < <(grep -Eo 'name="scope" value="[^"]+"' "$auth_body" | sed -E 's/.*value="([^"]+)".*/\1/' | sort -u)
    if [[ "${#scopes[@]}" -eq 0 ]]; then
      for s in $SPA_SCOPE; do
        scopes+=("$s")
      done
    fi

    rm -f "$auth_headers" "$auth_body"

    consent_headers="$(mktemp)"
    consent_body="$(mktemp)"
    curl_args=( -sS -D "$consent_headers" -o "$consent_body" -w '%{http_code}' )
    curl_args+=( -c "$cookies" -b "$cookies" )
    curl_args+=( -H 'Content-Type: application/x-www-form-urlencoded' )
    if [[ -n "$consent_csrf" ]]; then
      curl_args+=( --data-urlencode "_csrf=${consent_csrf}" )
    fi
    curl_args+=( --data-urlencode "client_id=${client_in_form}" )
    curl_args+=( --data-urlencode "state=${state_in_form}" )
    curl_args+=( --data-urlencode "consent_action=approve" )
    for s in "${scopes[@]}"; do
      curl_args+=( --data-urlencode "scope=${s}" )
    done

    consent_code="$(curl "${curl_args[@]}" "$consent_action_url" || true)"
    auth_location="$(extract_location_header "$consent_headers")"
    rm -f "$consent_headers" "$consent_body"
    if [[ "$consent_code" != "302" || -z "$auth_location" ]]; then
      echo "Consent submit did not redirect to client (HTTP ${consent_code})."
      rm -f "$cookies"
      exit 1
    fi
  elif [[ "$auth_code" == "302" ]]; then
    auth_location="$(extract_location_header "$auth_headers")"
    rm -f "$auth_headers" "$auth_body"
    if [[ -z "$auth_location" ]]; then
      echo "Authorize did not include Location header."
      rm -f "$cookies"
      exit 1
    fi
  else
    echo "Authorize request failed (HTTP ${auth_code})."
    echo "----- headers -----"
    cat "$auth_headers" || true
    echo "----- body (first 200 lines) -----"
    sed -n '1,200p' "$auth_body" || true
    rm -f "$auth_headers" "$auth_body" "$cookies"
    exit 1
  fi

  code="$(extract_query_param "$auth_location" code)"
  if [[ -z "$code" ]]; then
    echo "Authorize redirect did not include code."
    echo "Location: ${auth_location}"
    rm -f "$cookies"
    exit 1
  fi

  log "OAuth2 PKCE: exchange code for token"
  token_tmp="$(mktemp)"
  token_code="$(curl -sS -o "$token_tmp" -w '%{http_code}' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "client_id=${SPA_CLIENT_ID}" \
    --data-urlencode "redirect_uri=${SPA_REDIRECT_URI}" \
    --data-urlencode "code=${code}" \
    --data-urlencode "code_verifier=${verifier}" \
    "$TOKEN_URL" || true)"

  echo "HTTP ${token_code}"
  cat "$token_tmp"
  echo

  if [[ "$token_code" != "200" ]]; then
    echo "Token exchange failed (HTTP ${token_code})."
    rm -f "$token_tmp" "$cookies"
    exit 1
  fi

  ACCESS_TOKEN="$(json_get access_token "$token_tmp")"
  rm -f "$token_tmp"
  if [[ -z "$ACCESS_TOKEN" ]]; then
    echo "Token response did not contain access_token."
    rm -f "$cookies"
    exit 1
  fi

  rm -f "$cookies"
fi

if [[ "$RUN_USERINFO" == "1" && -n "$ACCESS_TOKEN" ]]; then
  log "Request: GET /userinfo (verify token is accepted)"
  userinfo_tmp="$(mktemp)"
  userinfo_code="$(curl -sS -o "$userinfo_tmp" -w '%{http_code}' \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H 'Accept: application/json' \
    "$USERINFO_URL" || true)"

  echo "HTTP ${userinfo_code}"
  cat "$userinfo_tmp"
  echo

  if [[ "$userinfo_code" != "200" ]]; then
    echo "Userinfo request failed (HTTP ${userinfo_code})."
    rm -f "$userinfo_tmp"
    exit 1
  fi

  sub="$(json_get sub "$userinfo_tmp")"
  rm -f "$userinfo_tmp"
  if [[ -z "$sub" ]]; then
    echo "Userinfo response did not contain sub."
    exit 1
  fi
fi

log "Running containers:"
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' | sed 's/[[:space:]]\+$//'

log "How to cleanup:"
echo "  make test-local-clean"
echo "  # or: ./scripts/e2e_local.sh clean"
echo "  # add REMOVE_VOLUME=1 to delete Postgres data volume"

log "Done."
