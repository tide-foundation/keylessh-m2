#!/bin/bash

# +-----------------------------------------------------------------------------------------------+
# | init-tidecloak.sh - Initialize TideCloak realm after deployment                               |
# | ===============================================================                               |
# | This script initializes a TideCloak instance with:                                            |
# |   1. Create a new realm from a JSON template                                                  |
# |   2. Initialize Tide + IGA                                                                    |
# |   3. Approve and commit change-sets                                                           |
# |   4. Create admin user with tide-realm-admin role                                             |
# |   5. Generate adapter config                                                                  |
# |   6. Upload branding (optional)                                                               |
# |   7. Generate invite link and wait for account linking                                        |
# |   8. Update CustomAdminUIDomain                                                               |
# |                                                                                               |
# | Reads configuration from the same .env file as setup-azure-env.sh.                           |
# | Usage:                                                                                        |
# |   ./init-tidecloak.sh [.env file]                                                            |
# |                                                                                               |
# +-----------------------------------------------------------------------------------------------+

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# =============================================
#  Load .env file
# =============================================

ENV_FILE="${1:-.env}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$ENV_FILE" ]; then
  log_error "Configuration file '$ENV_FILE' not found."
  echo "Use the same .env file as setup-azure-env.sh"
  exit 1
fi

log_info "Loading configuration from ${ENV_FILE}..."
source "$ENV_FILE"

# =============================================
#  Configuration
# =============================================

# TideCloak connection - auto-detect FQDN from Azure if not set
TC_APP_NAME="${TC_APP_NAME:-tidecloak}"
RESOURCE_GROUP="${RESOURCE_GROUP:-tidecloak-rg}"

if [ -n "${TIDECLOAK_URL:-}" ]; then
  # Use explicit URL if provided
  TIDECLOAK_URL="$TIDECLOAK_URL"
elif [ -n "${TC_HOSTNAME:-}" ]; then
  # Use custom hostname if configured
  TIDECLOAK_URL="https://${TC_HOSTNAME}"
else
  # Auto-detect from Azure container app
  log_info "Detecting TideCloak URL from Azure..."
  APP_FQDN=$(az containerapp show \
    -n "$TC_APP_NAME" -g "$RESOURCE_GROUP" \
    --query 'properties.configuration.ingress.fqdn' -o tsv 2>/dev/null || true)
  if [ -n "$APP_FQDN" ]; then
    TIDECLOAK_URL="https://${APP_FQDN}"
  else
    log_error "Could not detect TideCloak URL. Set TIDECLOAK_URL in .env"
    exit 1
  fi
fi

# Realm settings
REALM_NAME="${REALM_NAME:-myrealm}"
REALM_JSON_PATH="${REALM_JSON_PATH:-${SCRIPT_DIR}/realm.json}"
CLIENT_NAME="${CLIENT_NAME:-myclient}"
CLIENT_APP_URL="${CLIENT_APP_URL:-http://localhost:3000}"
ADAPTER_OUTPUT_PATH="${ADAPTER_OUTPUT_PATH:-${SCRIPT_DIR}/tidecloak.json}"

# Admin credentials (from setup-azure-env.sh .env)
KC_USER="${TC_ADMIN:-admin}"
KC_PASSWORD="${TC_ADMIN_PASSWORD:-password}"

# Internal
REALM_MGMT_CLIENT_ID="realm-management"
ADMIN_ROLE_NAME="tide-realm-admin"

# Curl options
CURL_OPTS=""
if [[ "$TIDECLOAK_URL" == https://* ]]; then
  CURL_OPTS="-k"
fi

# =============================================
#  Checks
# =============================================

echo ""
echo "=================================="
echo "  TideCloak Realm Initialization  "
echo "=================================="
echo ""

# Check dependencies
log_info "Checking dependencies..."
for cmd in curl jq; do
  if ! command -v $cmd &> /dev/null; then
    log_error "$cmd is not installed"
    exit 1
  fi
done
log_info "All dependencies installed"
echo ""

log_info "Configuration:"
log_info "  TideCloak URL:   $TIDECLOAK_URL"
log_info "  Realm Name:      $REALM_NAME"
log_info "  Client Name:     $CLIENT_NAME"
log_info "  Client App URL:  $CLIENT_APP_URL"
log_info "  Realm Template:  $REALM_JSON_PATH"
log_info "  Adapter Output:  $ADAPTER_OUTPUT_PATH"
echo ""

# Check realm.json exists
if [ ! -f "$REALM_JSON_PATH" ]; then
  log_error "Realm template not found at: $REALM_JSON_PATH"
  exit 1
fi

# Wait for TideCloak to be ready
log_info "Checking TideCloak connectivity..."
for i in $(seq 1 30); do
  if curl -s $CURL_OPTS --connect-timeout 5 "$TIDECLOAK_URL" > /dev/null 2>&1; then
    log_info "TideCloak is accessible"
    break
  fi
  if [ $i -eq 30 ]; then
    log_error "Cannot connect to TideCloak at $TIDECLOAK_URL after 30 attempts"
    exit 1
  fi
  log_warn "Waiting for TideCloak (attempt $i/30)..."
  sleep 10
done
echo ""

# =============================================
#  Helper functions
# =============================================

get_admin_token() {
  curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${KC_USER}" \
    -d "password=${KC_PASSWORD}" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" | jq -r '.access_token'
}

# Sign ALL pending change-requests, regardless of entity type. The new iga-core
# model has no per-CLIENT change-set step; you simply authorize+commit every
# pending change request after realm/IGA init.
#
# This mirrors the ecosystem-canonical drain used by the iga-engine tests
# (tidecloak-iga-engine-tests/lib/iga.ts `drainPending`): list PENDING, then for
# each CR POST .../{id}/authorize {} followed by POST .../{id}/commit {}; loop up
# to a max number of passes, re-listing each pass (committing some CRs can
# generate/unblock others), and stop early when the pass makes no forward
# progress so it can never hang.
sign_all_change_requests() {
  local max_passes=8
  local pass=0
  while [ "$pass" -lt "$max_passes" ]; do
    pass=$((pass + 1))
    TOKEN="$(get_admin_token)"
    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
      log_error "Failed to get admin token for signing change-requests"
      return 1
    fi

    # Flat list of ALL pending change requests (every entity type).
    local pending id_count
    pending=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/iga/change-requests?status=PENDING" \
      -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo "[]")
    if ! echo "$pending" | jq -e 'type == "array"' > /dev/null 2>&1; then
      log_error "Unexpected response from change-request API: $pending"
      return 1
    fi

    id_count=$(echo "$pending" | jq 'length' 2>/dev/null || echo "0")
    if [ "$id_count" = "0" ] || [ "$id_count" = "" ]; then
      log_info "No pending change-requests remain."
      return 0
    fi

    log_info "Signing $id_count pending change-request(s) (pass $pass)..."
    local progressed=0
    # Iterate CR ids (subshell-free so `progressed` survives the loop).
    while read -r cr_id; do
      [ -z "$cr_id" ] && continue

      # authorize then commit (canonical drainPending flow, both empty-body).
      curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/iga/change-requests/${cr_id}/authorize" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{}" > /dev/null 2>&1 || true

      local commit_status
      commit_status=$(curl -s $CURL_OPTS -o /dev/null -w "%{http_code}" -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/iga/change-requests/${cr_id}/commit" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{}" 2>/dev/null || echo "000")
      if [[ "$commit_status" =~ ^2 ]]; then
        progressed=$((progressed + 1))
      else
        log_warn "CR ${cr_id} not committed (HTTP $commit_status); will retry next pass"
      fi
    done < <(echo "$pending" | jq -r '.[].id')

    # No forward progress this pass -> stop rather than spin (a CR that stays
    # PENDING needs a role/quorum this bootstrap admin cannot satisfy).
    if [ "$progressed" -eq 0 ]; then
      log_warn "No change-requests committed this pass; stopping ($id_count still pending)."
      return 0
    fi

    sleep 2
  done

  log_warn "Reached max sign-all passes ($max_passes); some change-requests may remain pending."
  return 0
}

# =============================================
#  1. Create Realm
# =============================================

log_info "Creating realm '${REALM_NAME}'..."
TMP_REALM_JSON="$(mktemp)"
cp "$REALM_JSON_PATH" "$TMP_REALM_JSON"
sed -i "s|KEYLESSH|$REALM_NAME|g" "$TMP_REALM_JSON"

TOKEN="$(get_admin_token)"
status=$(curl -s $CURL_OPTS -o /dev/null -w "%{http_code}" \
  -X POST "${TIDECLOAK_URL}/admin/realms" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @"$TMP_REALM_JSON")

if [[ $status == 2* ]]; then
  log_info "Realm '${REALM_NAME}' created."
elif [[ $status == 409 ]]; then
  log_warn "Realm '${REALM_NAME}' already exists. Continuing..."
else
  log_error "Realm creation failed (HTTP $status)"
  rm -f "$TMP_REALM_JSON"
  exit 1
fi

# =============================================
#  2. Initialize Tide + IGA
# =============================================

log_info "Initializing Tide realm + IGA..."

# Prompt for email
echo ""
while true; do
  echo -ne "${YELLOW}Enter an email to manage your license: ${NC}"
  read LICENSE_EMAIL
  if [[ -n "$LICENSE_EMAIL" && "$LICENSE_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    break
  else
    log_error "Please enter a valid email address"
  fi
done

# Prompt for terms acceptance
echo ""
echo "Please review the Terms & Conditions at: https://tide.org/legal"
while true; do
  echo -ne "${YELLOW}I agree to the Terms & Conditions (enter 'y' or 'yes' to continue): ${NC}"
  read TERMS_ACCEPTANCE
  if [[ "$TERMS_ACCEPTANCE" == "y" || "$TERMS_ACCEPTANCE" == "yes" ]]; then
    break
  else
    log_error "You must explicitly agree to the Terms & Conditions by entering 'y' or 'yes'"
  fi
done

echo ""
TOKEN="$(get_admin_token)"
curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/vendorResources/setUpTideRealm" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "email=${LICENSE_EMAIL}" \
  --data-urlencode "isRagnarokEnabled=true" > /dev/null 2>&1

curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/tide-admin/toggle-iga" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "isIGAEnabled=true" > /dev/null 2>&1

log_info "Tide realm + IGA initialized."

# =============================================
#  3. Sign all pending change-requests
# =============================================

# Wait for ANY pending change-request to appear (not client-specific: the new
# iga-core model has no per-CLIENT change-set step).
log_info "Waiting for pending change-requests to be generated..."
for i in $(seq 1 12); do
  TOKEN="$(get_admin_token)"
  cs_count=$(curl -s $CURL_OPTS "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/iga/change-requests?status=PENDING" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
  if [ "$cs_count" -gt 0 ] 2>/dev/null; then
    log_info "Found $cs_count pending change-request(s)."
    break
  fi
  if [ $i -eq 12 ]; then
    log_warn "No pending change-requests found after 60s. They may have been committed already."
    break
  fi
  sleep 5
done

sign_all_change_requests

# =============================================
#  4. Create admin user
# =============================================

TOKEN="$(get_admin_token)"
log_info "Creating admin user..."

curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@yourorg.com","firstName":"admin","lastName":"user","enabled":true,"emailVerified":false,"requiredActions":[],"attributes":{"locale":""},"groups":[]}' > /dev/null 2>&1

USER_ID=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/users?username=admin" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

CLIENT_UUID=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/clients?clientId=${REALM_MGMT_CLIENT_ID}" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

ROLE_JSON=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/clients/$CLIENT_UUID/roles/${ADMIN_ROLE_NAME}" \
  -H "Authorization: Bearer $TOKEN")

curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/users/$USER_ID/role-mappings/clients/$CLIENT_UUID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "[$ROLE_JSON]" > /dev/null 2>&1

log_info "Admin user created with ${ADMIN_ROLE_NAME} role."

# =============================================
#  5. Fetch adapter config
# =============================================

TOKEN="$(get_admin_token)"
log_info "Fetching adapter config..."

CLIENT_UUID=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/clients?clientId=${CLIENT_NAME}" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/vendorResources/get-installations-provider?clientId=${CLIENT_UUID}&providerId=keycloak-oidc-keycloak-json" \
  -H "Authorization: Bearer $TOKEN" > "$ADAPTER_OUTPUT_PATH"

log_info "Adapter config saved to $ADAPTER_OUTPUT_PATH"

rm -f "$TMP_REALM_JSON"

# =============================================
#  6. Upload branding (optional)
# =============================================

BRANDING_DIR="${BRANDING_DIR:-${SCRIPT_DIR}/branding}"

if [ -d "$BRANDING_DIR" ]; then
  log_info "Uploading branding images from ${BRANDING_DIR}..."
  TOKEN="$(get_admin_token)"

  # Upload logo
  LOGO_FILE=$(find "$BRANDING_DIR" -name "*logo*" -type f 2>/dev/null | head -1)
  if [ -n "$LOGO_FILE" ]; then
    logo_status=$(curl -s -k -o /dev/null -w "%{http_code}" \
      -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/tide-idp-admin-resources/images/upload" \
      -H "Authorization: Bearer ${TOKEN}" \
      -F "fileData=@${LOGO_FILE}" \
      -F "fileName=$(basename "$LOGO_FILE")" \
      -F "fileType=LOGO" 2>/dev/null || echo "000")
    if [[ "$logo_status" =~ ^2 ]]; then
      log_info "Logo uploaded: $(basename "$LOGO_FILE")"
    else
      log_warn "Logo upload failed (HTTP $logo_status)"
    fi
  fi

  # Upload background
  BG_FILE=$(find "$BRANDING_DIR" -name "*bg*" -o -name "*background*" -type f 2>/dev/null | head -1)
  if [ -n "$BG_FILE" ]; then
    bg_status=$(curl -s -k -o /dev/null -w "%{http_code}" \
      -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/tide-idp-admin-resources/images/upload" \
      -H "Authorization: Bearer ${TOKEN}" \
      -F "fileData=@${BG_FILE}" \
      -F "fileName=$(basename "$BG_FILE")" \
      -F "fileType=BACKGROUND_IMAGE" 2>/dev/null || echo "000")
    if [[ "$bg_status" =~ ^2 ]]; then
      log_info "Background uploaded: $(basename "$BG_FILE")"
    else
      log_warn "Background upload failed (HTTP $bg_status)"
    fi
  fi

  log_info "Branding upload complete."
else
  log_warn "No branding directory found at ${BRANDING_DIR}. Skipping."
fi

# =============================================
#  7. Generate invite link and wait for linking
# =============================================

TOKEN="$(get_admin_token)"
log_info "Generating invite link..."

RAW_INVITE_LINK=$(curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/tideAdminResources/get-required-action-link?userId=${USER_ID}&lifespan=43200" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '["link-tide-account-action"]')

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  INVITE LINK (open in browser):${NC}"
echo ""
echo "  $RAW_INVITE_LINK"
echo ""
echo -e "${GREEN}================================================${NC}"
echo ""
echo "Open this link in your browser to link the admin account."
echo -ne "Waiting for account to be linked"

while true; do
  TOKEN="$(get_admin_token)"
  ATTRS=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/users?username=admin" \
    -H "Authorization: Bearer $TOKEN")
  KEY=$(echo "$ATTRS" | jq -r '.[0].attributes.tideUserKey[0] // empty')
  VUID=$(echo "$ATTRS" | jq -r '.[0].attributes.vuid[0] // empty')
  if [[ -n "$KEY" && -n "$VUID" ]]; then
    echo ""
    log_info "Account linked!"
    break
  fi
  echo -n "."
  sleep 5
done

# =============================================
#  8. Sign all pending change-requests (post user creation)
# =============================================

# User creation above may have generated new pending change-requests; drain them
# all (same sign-all pass; no per-type change-set step in the new iga-core).
sign_all_change_requests

# =============================================
#  9. Update CustomAdminUIDomain
# =============================================

TOKEN="$(get_admin_token)"
log_info "Updating CustomAdminUIDomain to ${CLIENT_APP_URL}..."

INST=$(curl -s $CURL_OPTS -X GET "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/identity-provider/instances/tide" \
  -H "Authorization: Bearer $TOKEN")

UPDATED=$(echo "$INST" | jq --arg d "$CLIENT_APP_URL" '.config.CustomAdminUIDomain=$d')

curl -s $CURL_OPTS -X PUT "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/identity-provider/instances/tide" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$UPDATED" > /dev/null 2>&1

curl -s $CURL_OPTS -X POST "${TIDECLOAK_URL}/admin/realms/${REALM_NAME}/vendorResources/sign-idp-settings" \
  -H "Authorization: Bearer $TOKEN" > /dev/null 2>&1

log_info "CustomAdminUIDomain updated and signed."

# =============================================
#  Summary
# =============================================

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  TideCloak Initialization Complete!    ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "TideCloak URL:     ${GREEN}${TIDECLOAK_URL}${NC}"
echo -e "Realm:             ${GREEN}${REALM_NAME}${NC}"
echo -e "Admin Console:     ${GREEN}${TIDECLOAK_URL}/admin/${REALM_NAME}/console${NC}"
echo -e "Adapter Config:    ${GREEN}${ADAPTER_OUTPUT_PATH}${NC}"
echo ""