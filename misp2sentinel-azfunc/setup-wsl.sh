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

echo "==> Cleaning up any leftover apt source files from previous runs..."
sudo find /etc/apt/sources.list.d/ -name "azure-cli*" -delete 2>/dev/null || true

echo "==> Adding Microsoft apt repository..."
curl -s https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /tmp/microsoft.gpg
sudo install -o root -g root -m 644 /tmp/microsoft.gpg /etc/apt/trusted.gpg.d/microsoft.gpg

CODENAME=$(. /etc/os-release && printf '%s' "$VERSION_CODENAME")
echo "    Detected Ubuntu codename: $CODENAME"
printf 'deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ %s main\n' "$CODENAME" \
    | sudo tee /etc/apt/sources.list.d/azure-cli.list > /dev/null

echo "==> Installing Azure Functions Core Tools v4..."
sudo apt-get update -q
sudo apt-get install -y azure-functions-core-tools-4

echo ""
echo "==> func installed: $(/usr/bin/func --version)"
echo ""
echo "==> Installing Azurite (local storage emulator)..."
sudo /usr/bin/npm install -g azurite

echo ""
echo "==> Done! Next steps:"
echo "    1. cp local.settings.json.example local.settings.json"
echo "    2. Edit local.settings.json with your credentials"
echo "    3. In one terminal:  azurite --silent"
echo "    4. In another:       func start"
echo "    5. To trigger:       curl -X POST http://localhost:7071/admin/functions/sync-timer -H 'Content-Type: application/json' -d '{}'"