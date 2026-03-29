#!/usr/bin/env bash
# Run this inside WSL to install Azure Functions Core Tools natively.
# Usage: bash setup-wsl.sh

# Strip any Windows carriage returns from this script itself, then re-exec if needed
if grep -qP '\r' "$0" 2>/dev/null; then
    sed -i 's/\r//' "$0"
    exec bash "$0" "$@"
fi

set -e

# Use WSL-native tools, not Windows ones from /mnt/c
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

NPM=$(which npm)
echo "==> Using npm at: $NPM ($(npm --version))"
echo ""

echo "==> Installing Azure Functions Core Tools v4 via npm..."
sudo "$NPM" install -g azure-functions-core-tools@4 --unsafe-perm true

echo ""
echo "==> func installed: $(/usr/local/bin/func --version)"
echo ""
echo "==> Installing Azurite (local storage emulator)..."
sudo "$NPM" install -g azurite

echo ""
echo "==> Done! Next steps:"
echo "    1. cp local.settings.json.example local.settings.json"
echo "    2. Edit local.settings.json with your credentials"
echo "    3. In one terminal:  azurite --silent"
echo "    4. In another:       func start"
echo "    5. To trigger:       curl -X POST http://localhost:7071/admin/functions/sync-timer -H 'Content-Type: application/json' -d '{}'"