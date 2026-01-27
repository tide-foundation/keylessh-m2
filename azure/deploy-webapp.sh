#!/bin/bash
set -e

# Load .env file if it exists
SCRIPT_DIR="$(dirname "$0")"
if [ -f "$SCRIPT_DIR/.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
fi

# =============================================================================
# KeyleSSH Web App Deployment Script
# Builds and deploys the application to Azure Web App
# =============================================================================

# Configuration (from .env or defaults)
ENV_NAME="${ENV_NAME:-myenv}"
RESOURCE_GROUP="${RESOURCE_GROUP:-keylessh-${ENV_NAME}}"
WEBAPP_NAME="${WEBAPP_NAME:-keylessh-${ENV_NAME}}"

# =============================================================================
print_header() {
    echo ""
    echo "==========================================="
    echo "$1"
    echo "==========================================="
}

print_header "KeyleSSH Web App Deployment"
echo "Environment:    $ENV_NAME"
echo "Resource Group: $RESOURCE_GROUP"
echo "Web App:        $WEBAPP_NAME"
echo ""

# Check if logged in
if ! az account show &> /dev/null; then
    echo "Error: Please login to Azure first: az login"
    exit 1
fi

# Navigate to project root
cd "$SCRIPT_DIR/.."

# =============================================================================
print_header "Installing Dependencies"
npm ci

# =============================================================================
print_header "Building Application"
npm run build

# =============================================================================
print_header "Creating Deployment Package"
rm -rf deploy deploy.zip
mkdir -p deploy

# Copy build output
cp -r dist deploy/

# Copy package files
cp package.json deploy/
cp package-lock.json deploy/

# Install production dependencies only
cd deploy
npm ci --omit=dev
cd ..

# Create zip
cd deploy
zip -r ../deploy.zip .
cd ..

# =============================================================================
print_header "Deploying to Azure Web App"
az webapp deploy \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --src-path deploy.zip \
    --type zip \
    --clean true

# =============================================================================
print_header "Cleaning Up"
rm -rf deploy deploy.zip

# =============================================================================
print_header "Deployment Complete!"

WEBAPP_URL=$(az webapp show \
    --name $WEBAPP_NAME \
    --resource-group $RESOURCE_GROUP \
    --query "defaultHostName" -o tsv)

echo ""
echo "Web App URL: https://$WEBAPP_URL"
echo ""
echo "View logs with:"
echo "  az webapp log tail --name $WEBAPP_NAME --resource-group $RESOURCE_GROUP"
echo ""
