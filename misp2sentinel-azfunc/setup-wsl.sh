#!/usr/bin/env bash
# Run this inside WSL to install Azure Functions Core Tools natively.
# Usage: bash setup-wsl.sh

sed -i 's/\r//' "$0"

echo "==> Checking for WSL-native npm..."
NPM=$(command -v npm || true)
if [ -z "$NPM" ] || echo "$NPM" | grep -q "/mnt/c/"; then
    echo "    WSL-native npm not found. Installing nodejs and npm via apt..."
    sudo apt-get update -q
    sudo apt-get install -y nodejs npm
    NPM=$(command -v npm)
fi
echo "    Found: $NPM ($(npm --version))"

echo ""
echo "==> Installing Azure Functions Core Tools v4..."
sudo "$NPM" install -g azure-functions-core-tools@4 --unsafe-perm true

FUNC=$(command -v func 2>/dev/null || echo /usr/local/bin/func)
echo ""
echo "==> func installed: $($FUNC --version)"

echo ""
echo "==> Installing Azurite..."
sudo "$NPM" install -g azurite

echo ""
echo "==> Done! Next steps:"
echo "    1. cp local.settings.json.example local.settings.json"
echo "    2. Edit local.settings.json with your credentials"
echo "    3. Terminal 1:  azurite --silent"
echo "    4. Terminal 2:  func start"
echo "    5. Trigger:     curl -X POST http://localhost:7071/admin/functions/sync-timer -H 'Content-Type: application/json' -d '{}'"