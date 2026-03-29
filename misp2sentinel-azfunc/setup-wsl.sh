#!/usr/bin/env bash
# Run this inside WSL to install Azure Functions Core Tools natively.
# Usage: bash setup-wsl.sh

set -e

# Use WSL-native tools, not Windows ones from /mnt/c
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echo "==> Installing Azure Functions Core Tools v4 (Linux native)..."

curl -s https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /tmp/microsoft.gpg
sudo install -o root -g root -m 644 /tmp/microsoft.gpg /etc/apt/trusted.gpg.d/

. /etc/os-release
sudo sh -c "echo 'deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ ${VERSION_CODENAME} main' > /etc/apt/sources.list.d/azure-cli.list"

sudo apt-get update -q
sudo apt-get install -y azure-functions-core-tools-4

echo ""
echo "==> func installed: $(func --version)"
echo ""
echo "==> Installing Azurite (local storage emulator)..."
sudo npm install -g azurite

echo ""
echo "==> Done! Next steps:"
echo "    1. Copy local.settings.json.example to local.settings.json and fill in your values"
echo "    2. In one terminal:  azurite --silent"
echo "    3. In another:       func start"
echo "    4. To trigger:       curl -X POST http://localhost:7071/admin/functions/sync-timer -H 'Content-Type: application/json' -d '{}'"