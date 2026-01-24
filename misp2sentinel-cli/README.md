# MISP2Sentinel CLI

Command-line tool for syncing MISP indicators to Microsoft Sentinel.

## Install

```bash
cargo build --release -p misp2sentinel-cli
# Binary at: target/release/misp2sentinel-cli
```

## Usage

```bash
# Basic usage with config file
misp2sentinel-cli --config config.toml

# Dry run (no uploads)
misp2sentinel-cli --dry-run

# Validate configuration
misp2sentinel-cli --check-config

# With environment variables (no config file)
export MISP_URL=https://misp.example.com
export MISP_API_KEY=your-key
export SENTINEL_WORKSPACE_ID=workspace-id
export SENTINEL_TENANT_ID=tenant-id
export SENTINEL_CLIENT_ID=client-id
export SENTINEL_CLIENT_SECRET=client-secret
misp2sentinel-cli
```

## Options

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Path to TOML config file |
| `-d, --dry-run` | Validate and log without uploading |
| `--check-config` | Validate configuration and exit |
| `-v, --verbose` | Enable verbose logging |

## Config File

```toml
[misp]
url = "https://misp.example.com"
api_key = "your-api-key"
verify_ssl = true

[sentinel]
workspace_id = "00000000-0000-0000-0000-000000000000"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "00000000-0000-0000-0000-000000000000"
client_secret = "your-client-secret"

[sync]
days_to_sync = 30
dry_run = false
```

## Key Vault Integration

Store secrets in Azure Key Vault instead of config files:

```bash
export AZURE_KEYVAULT_NAME=kv-misp2sentinel
misp2sentinel-cli --config config.toml
```

The CLI will fetch these secrets from Key Vault:
- `MISP-API-KEY` → MISP API key
- `SENTINEL-CLIENT-SECRET` → Service principal secret

Authentication uses `DefaultAzureCredential` (Azure CLI, managed identity, etc.).

## Scheduled Sync (cron)

```bash
# Every 6 hours
0 */6 * * * /path/to/misp2sentinel-cli --config /path/to/config.toml >> /var/log/misp2sentinel.log 2>&1
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Configuration error |
| 2 | MISP connection error |
| 3 | Sentinel API error |
