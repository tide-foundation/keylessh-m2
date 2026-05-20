#!/bin/bash
set -e

# =============================================================================
# KeyleSSH DevOps Full Deployment Script
# Deploys: Web App + Punchd Gateway (Azure Container Instance)
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load .env overrides (template first, then local secrets override)
load_env() {
    while IFS= read -r line || [ -n "$line" ]; do
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        line="${line%%#*}"
        line="${line%"${line##*[![:space:]]}"}"
        key="${line%%=*}"
        val="${line#*=}"
        val="${val#\'}" ; val="${val%\'}"
        val="${val#\"}" ; val="${val%\"}"
        export "$key=$val"
    done < "$1"
}
[ -f "$SCRIPT_DIR/.env.devops" ] && load_env "$SCRIPT_DIR/.env.devops"
[ -f "$SCRIPT_DIR/.env.devops.local" ] && load_env "$SCRIPT_DIR/.env.devops.local"

# ─── Configuration ───────────────────────────────────────────────────────────
RESOURCE_GROUP="${RESOURCE_GROUP:-KeyleSSH}"
LOCATION="${LOCATION:-australiaeast}"

# Web App
WEBAPP_NAME="${WEBAPP_NAME:-keylessh-devops}"
APP_SERVICE_PLAN="${APP_SERVICE_PLAN:-keylessh-plan}"
STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-keylesshstorage}"
FILE_SHARE="${FILE_SHARE:-keylessh-devops}"

# Punchd Gateway (ACI)
ACI_NAME="${ACI_NAME:-punchd-gateway-devops}"
DNS_LABEL="${DNS_LABEL:-punchd-gateway-devops}"
GATEWAY_IMAGE="${GATEWAY_IMAGE:-tideorg/punchd-gateway:latest}"
GATEWAY_ID="${GATEWAY_ID:-Devops-GW}"
GATEWAY_DISPLAY_NAME="${GATEWAY_DISPLAY_NAME:-Devops Gateway}"

# Signal server (must be set in .env.devops or environment)
STUN_SERVER_URL="${STUN_SERVER_URL:?Set STUN_SERVER_URL in .env.devops}"
API_SECRET="${API_SECRET:?Set API_SECRET in .env.devops}"
TURN_SECRET="${TURN_SECRET:?Set TURN_SECRET in .env.devops}"

# TideCloak
AUTH_SERVER_PUBLIC_URL="${AUTH_SERVER_PUBLIC_URL:-https://login.dauth.me}"
SERVER_URL="${SERVER_URL:-https://devops.keylessh.com}"
TIDECLOAK_CONFIG="${TIDECLOAK_CONFIG:-$PROJECT_ROOT/data/tidecloak.json}"

# Backends for gateway (SSH targets)
BACKENDS="${BACKENDS:-}"

# ICE/TURN derived from signal server
EXTERNAL_IP="${EXTERNAL_IP:-}"
ICE_SERVERS="${ICE_SERVERS:-stun:${EXTERNAL_IP}:3478}"
TURN_SERVER="${TURN_SERVER:-turn:${EXTERNAL_IP}:3478}"

# ─── Helpers ─────────────────────────────────────────────────────────────────
print_header() {
    echo ""
    echo "==========================================="
    echo "  $1"
    echo "==========================================="
}

check_az_login() {
    if ! az account show &> /dev/null; then
        echo "Error: Please login to Azure first: az login"
        exit 1
    fi
}

# ─── Parse arguments ─────────────────────────────────────────────────────────
DEPLOY_WEBAPP=false
DEPLOY_GATEWAY=false
SETUP_ONLY=false

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all          Deploy both Web App and Gateway"
    echo "  --webapp       Deploy Web App only"
    echo "  --gateway      Deploy Punchd Gateway only"
    echo "  --setup        Create Azure resources only (no code deploy)"
    echo "  --help         Show this help"
    echo ""
    echo "Environment: configure via azure/.env.devops"
}

if [ $# -eq 0 ]; then
    usage
    exit 0
fi

for arg in "$@"; do
    case $arg in
        --all)      DEPLOY_WEBAPP=true; DEPLOY_GATEWAY=true ;;
        --webapp)   DEPLOY_WEBAPP=true ;;
        --gateway)  DEPLOY_GATEWAY=true ;;
        --setup)    SETUP_ONLY=true ;;
        --help)     usage; exit 0 ;;
        *)          echo "Unknown option: $arg"; usage; exit 1 ;;
    esac
done

# ─── Resolve TideCloak config ───────────────────────────────────────────────
if [ -f "$TIDECLOAK_CONFIG" ]; then
    TIDECLOAK_CONFIG="$(cd "$(dirname "$TIDECLOAK_CONFIG")" && pwd)/$(basename "$TIDECLOAK_CONFIG")"
    TIDECLOAK_CONFIG_B64=$(base64 -w0 "$TIDECLOAK_CONFIG" 2>/dev/null || base64 "$TIDECLOAK_CONFIG" | tr -d '\n')
else
    echo "Error: tidecloak.json not found at $TIDECLOAK_CONFIG"
    exit 1
fi

check_az_login

print_header "KeyleSSH DevOps Deployment"
echo "  Resource Group:   $RESOURCE_GROUP"
echo "  Location:         $LOCATION"
echo "  Web App:          $WEBAPP_NAME"
echo "  Gateway ACI:      $ACI_NAME"
echo "  Gateway Image:    $GATEWAY_IMAGE"
echo "  Server URL:       $SERVER_URL"
echo "  Signal Server:    $STUN_SERVER_URL"
echo ""

# =============================================================================
# SETUP — Create Azure resources
# =============================================================================
if [ "$SETUP_ONLY" = true ] || [ "$DEPLOY_WEBAPP" = true ]; then

    print_header "Setting Up Web App: $WEBAPP_NAME"

    # Get storage key
    STORAGE_KEY=$(az storage account keys list \
        --account-name $STORAGE_ACCOUNT \
        --resource-group $RESOURCE_GROUP \
        --query "[0].value" -o tsv)

    # Create file share
    az storage share create \
        --name $FILE_SHARE \
        --account-name $STORAGE_ACCOUNT \
        --account-key "$STORAGE_KEY" \
        --quota 5 \
        --output none 2>/dev/null || echo "  File share already exists"

    # Create App Service Plan (shared across web apps)
    az appservice plan create \
        --name $APP_SERVICE_PLAN \
        --resource-group $RESOURCE_GROUP \
        --location $LOCATION \
        --sku B1 \
        --is-linux \
        --output none 2>/dev/null || echo "  App Service Plan already exists"

    # Create Web App
    az webapp create \
        --name $WEBAPP_NAME \
        --resource-group $RESOURCE_GROUP \
        --plan $APP_SERVICE_PLAN \
        --runtime "NODE:20-lts" \
        --output none 2>/dev/null || echo "  Web App already exists"

    # Configure Web App
    echo "  Configuring Web App..."
    az webapp config set \
        --name $WEBAPP_NAME \
        --resource-group $RESOURCE_GROUP \
        --web-sockets-enabled true \
        --startup-file "node dist/index.cjs" \
        --always-on true \
        --output none

    # Mount storage
    az webapp config storage-account add \
        --name $WEBAPP_NAME \
        --resource-group $RESOURCE_GROUP \
        --custom-id $FILE_SHARE \
        --storage-type AzureFiles \
        --share-name $FILE_SHARE \
        --account-name $STORAGE_ACCOUNT \
        --access-key "$STORAGE_KEY" \
        --mount-path /home/site/data \
        --output none 2>/dev/null || echo "  Storage mount already exists"

    # Set environment variables
    az webapp config appsettings set \
        --name $WEBAPP_NAME \
        --resource-group $RESOURCE_GROUP \
        --settings \
            NODE_ENV=production \
            DATABASE_URL=/home/site/data/keylessh.db \
            SCM_DO_BUILD_DURING_DEPLOYMENT=false \
            ENABLE_ORYX_BUILD=false \
        --output none

    echo "  Web App configured"

    # Upload tidecloak.json to file share
    echo "  Uploading tidecloak.json to Azure Files..."
    if command -v wslpath &>/dev/null; then
        # Running in WSL — az.exe needs a native Windows path
        mkdir -p /mnt/c/Temp 2>/dev/null || true
        cp "$TIDECLOAK_CONFIG" /mnt/c/Temp/tidecloak-upload.json
        TC_SOURCE=$(wslpath -w /mnt/c/Temp/tidecloak-upload.json)
    else
        cp "$TIDECLOAK_CONFIG" /tmp/tidecloak-upload.json
        TC_SOURCE="/tmp/tidecloak-upload.json"
    fi
    az storage file upload \
        --account-name $STORAGE_ACCOUNT \
        --account-key "$STORAGE_KEY" \
        --share-name $FILE_SHARE \
        --source "$TC_SOURCE" \
        --path tidecloak.json \
        --output none
    rm -f /mnt/c/Temp/tidecloak-upload.json /tmp/tidecloak-upload.json 2>/dev/null
    echo "  tidecloak.json uploaded"
fi

if [ "$SETUP_ONLY" = true ]; then
    print_header "Setup Complete"
    WEBAPP_URL=$(az webapp show --name $WEBAPP_NAME --resource-group $RESOURCE_GROUP --query "defaultHostName" -o tsv 2>/dev/null || echo "$WEBAPP_NAME.azurewebsites.net")
    echo ""
    echo "  Web App:  https://$WEBAPP_URL"
    echo ""
    echo "Next: deploy with --all or --webapp / --gateway"
    exit 0
fi

# =============================================================================
# DEPLOY WEB APP
# =============================================================================
if [ "$DEPLOY_WEBAPP" = true ]; then

    print_header "Building Web App"
    cd "$PROJECT_ROOT"

    # Copy TideCloak config for client build
    cp "$TIDECLOAK_CONFIG" client/src/tidecloakAdapter.json
    echo "  Copied tidecloak.json to client adapter"

    npm ci
    npm run build

    # Create deployment package
    print_header "Packaging"
    rm -rf deploy deploy.zip
    mkdir -p deploy

    cp -r dist deploy/
    cp package.json deploy/
    cp package-lock.json deploy/

    mkdir -p deploy/data
    cp "$TIDECLOAK_CONFIG" deploy/data/tidecloak.json

    # Install production node_modules inside deploy dir
    # (WSL is Linux so native modules match Azure's Linux runtime)
    echo "  Installing production dependencies..."
    mkdir -p deploy/script
    cp script/patch-tideorg.js deploy/script/
    cd deploy
    npm ci --omit=dev
    cd ..

    echo "  Creating zip..."
    cd deploy
    if command -v zip &> /dev/null; then
        zip -qr ../deploy.zip .
    elif command -v powershell &> /dev/null; then
        powershell -Command "Compress-Archive -Path * -DestinationPath ../deploy.zip -Force"
    else
        echo "Error: Neither 'zip' nor 'powershell' available"
        exit 1
    fi
    cd ..

    # Deploy via az webapp deploy (more reliable than curl to Kudu from WSL)
    print_header "Deploying to Azure Web App"
    if command -v wslpath &>/dev/null; then
        DEPLOY_ZIP=$(wslpath -w "$(pwd)/deploy.zip")
    else
        DEPLOY_ZIP="$(pwd)/deploy.zip"
    fi
    az webapp deploy \
        --name $WEBAPP_NAME \
        --resource-group $RESOURCE_GROUP \
        --src-path "$DEPLOY_ZIP" \
        --type zip \
        --clean true

    rm -rf deploy deploy.zip
    echo ""
    echo "  Web App deployed"
fi

# =============================================================================
# DEPLOY PUNCHD GATEWAY (ACI)
# =============================================================================
if [ "$DEPLOY_GATEWAY" = true ]; then

    print_header "Deploying Punchd Gateway: $ACI_NAME"

    if [ -z "$BACKENDS" ]; then
        echo "Warning: BACKENDS not set. Gateway will start with no backends."
        echo "Set BACKENDS in .env.devops, e.g.: BACKENDS='SSH Server=ssh://10.0.0.4'"
        BACKENDS="${BACKENDS:-}"
    fi

    # Delete existing container
    echo "  Removing old ACI (if any)..."
    az container delete --resource-group "$RESOURCE_GROUP" --name "$ACI_NAME" --yes 2>/dev/null || true

    # Generate ACI YAML (use Windows-accessible path for WSL compatibility)
    if command -v wslpath &>/dev/null; then
        mkdir -p /mnt/c/Temp 2>/dev/null || true
        TMPFILE="/mnt/c/Temp/aci-devops.yaml"
        TMPFILE_AZ=$(wslpath -w "$TMPFILE")
    else
        TMPFILE=$(mktemp /tmp/aci-devops-XXXXXX.yaml)
        TMPFILE_AZ="$TMPFILE"
    fi
    cat > "$TMPFILE" <<YAML
apiVersion: 2021-09-01
location: ${LOCATION}
name: ${ACI_NAME}
type: Microsoft.ContainerInstance/containerGroups
properties:
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    dnsNameLabel: ${DNS_LABEL}
    ports:
      - port: 7891
        protocol: TCP
      - port: 7892
        protocol: TCP
      - port: 7893
        protocol: UDP
  containers:
    - name: ${ACI_NAME}
      properties:
        image: ${GATEWAY_IMAGE}
        resources:
          requests:
            cpu: 1
            memoryInGb: 1
        ports:
          - port: 7891
            protocol: TCP
          - port: 7892
            protocol: TCP
          - port: 7893
            protocol: UDP
        environmentVariables:
          - name: GATEWAY_ID
            value: "${GATEWAY_ID}"
          - name: GATEWAY_DISPLAY_NAME
            value: "${GATEWAY_DISPLAY_NAME}"
          - name: STUN_SERVER_URL
            value: "${STUN_SERVER_URL}"
          - name: API_SECRET
            secureValue: "${API_SECRET}"
          - name: ICE_SERVERS
            value: "${ICE_SERVERS}"
          - name: TURN_SERVER
            value: "${TURN_SERVER}"
          - name: TURN_SECRET
            secureValue: "${TURN_SECRET}"
          - name: BACKENDS
            value: "${BACKENDS}"
          - name: TIDECLOAK_CONFIG_B64
            secureValue: "${TIDECLOAK_CONFIG_B64}"
          - name: AUTH_SERVER_PUBLIC_URL
            value: "${AUTH_SERVER_PUBLIC_URL}"
          - name: SERVER_URL
            value: "${SERVER_URL}"
          - name: LISTEN_PORT
            value: "7891"
          - name: HEALTH_PORT
            value: "7892"
          - name: QUIC_PORT
            value: "7893"
          - name: HTTPS
            value: "false"
          - name: PUBLIC_URL
            value: "${DNS_LABEL}.${LOCATION}.azurecontainer.io"
YAML

    echo "  Creating ACI..."
    az container create --resource-group "$RESOURCE_GROUP" --file "$TMPFILE_AZ"
    rm -f "$TMPFILE"

    # Show result
    IP=$(az container show --resource-group "$RESOURCE_GROUP" --name "$ACI_NAME" --query "ipAddress.ip" -o tsv)
    FQDN=$(az container show --resource-group "$RESOURCE_GROUP" --name "$ACI_NAME" --query "ipAddress.fqdn" -o tsv)

    echo ""
    echo "  Gateway deployed!"
    echo "  IP:   ${IP}"
    echo "  FQDN: ${FQDN}"
    echo "  HTTP: http://${FQDN}:7891"
    echo "  QUIC: ${FQDN}:7893 (UDP)"
fi

# =============================================================================
# Summary
# =============================================================================
print_header "Deployment Complete"
echo ""

if [ "$DEPLOY_WEBAPP" = true ]; then
    WEBAPP_URL=$(az webapp show --name $WEBAPP_NAME --resource-group $RESOURCE_GROUP --query "defaultHostName" -o tsv 2>/dev/null || echo "$WEBAPP_NAME.azurewebsites.net")
    echo "  Web App:  https://$WEBAPP_URL"
fi

if [ "$DEPLOY_GATEWAY" = true ]; then
    FQDN=$(az container show --resource-group "$RESOURCE_GROUP" --name "$ACI_NAME" --query "ipAddress.fqdn" -o tsv 2>/dev/null || echo "${DNS_LABEL}.${LOCATION}.azurecontainer.io")
    echo "  Gateway:  http://${FQDN}:7891"
    echo "  QUIC:     ${FQDN}:7893"
fi

echo ""
echo "  Logs:"
if [ "$DEPLOY_WEBAPP" = true ]; then
    echo "    az webapp log tail --name $WEBAPP_NAME --resource-group $RESOURCE_GROUP"
fi
if [ "$DEPLOY_GATEWAY" = true ]; then
    echo "    az container logs --name $ACI_NAME --resource-group $RESOURCE_GROUP --follow"
fi
echo ""
