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

echo ""
echo "==> Installing Azurite..."
sudo "$NPM" install -g azurite

echo ""
echo "==> Ensuring /usr/local/bin is first in PATH..."
if ! grep -q 'export PATH="/usr/local/bin' ~/.bashrc; then
    echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
    echo "    Added to ~/.bashrc"
fi

FUNC=/usr/local/bin/func
echo ""
echo "==> func version: $($FUNC --version)"
echo ""
echo "==> Done! To start, run these commands:"
echo ""
echo "    source ~/.bashrc"
echo "    $FUNC start"
echo ""
echo "    (In a separate terminal to trigger the function manually:)"
echo "    curl -X POST http://localhost:7071/admin/functions/sync-timer -H 'Content-Type: application/json' -d '{}'"