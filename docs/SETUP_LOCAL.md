# Local Setup

Run MISP2Sentinel directly on your MISP server or any host with network access to both MISP and Azure.

## Prerequisites

- Rust 1.70+ (or use pre-built binary from releases)
- MISP API access
- Azure AD app registration with Microsoft Sentinel Contributor role

## Installation

### Option A: Pre-built Binary (Recommended)

Download the appropriate binary for your platform from [GitHub Releases](https://github.com/lnfernux/rustymisp2sentinel/releases/latest):

- **Linux (static)**: `misp2sentinel-cli-linux-x64-static` - Statically linked, works on any Linux distribution
- **Linux (dynamic)**: `misp2sentinel-cli-linux-x64` - Dynamically linked, smaller size, requires glibc
- **Windows**: `misp2sentinel-cli-windows-x64.exe`

```bash
# Linux example
curl -LO https://github.com/lnfernux/rustymisp2sentinel/releases/latest/download/misp2sentinel-cli-linux-x64-static
chmod +x misp2sentinel-cli-linux-x64-static
sudo mv misp2sentinel-cli-linux-x64-static /usr/local/bin/misp2sentinel-cli

# Verify installation
misp2sentinel-cli --version
```

### Option B: Build from Source

For development or if you need to customize the code:

```bash
git clone https://github.com/lnfernux/rustymisp2sentinel.git
cd rustymisp2sentinel
cargo build --release
```

Binary at `target/release/misp2sentinel-cli`.

## Configuration

The CLI supports three configuration methods (in order of priority):

1. **CLI arguments** (highest priority)
2. **Environment variables**
3. **TOML config file** (lowest priority)

### Option 1: Config File (Recommended)

```bash
cp config.toml.example config.toml
# Edit config.toml with your values
```

```toml
[misp]
url = "https://misp.example.com"
api_key = "your-api-key"
verify_tls = true

[misp.filters]
published = true
to_ids = true
publish_timestamp = "14d"
tags = ["tlp:white", "type:malware"]
not_tags = ["tlp:red", "false-positive"]
# See docs/FILTERS.md for all filter options

[sentinel]
workspace_id = "00000000-0000-0000-0000-000000000000"
tenant_id = "00000000-0000-0000-0000-000000000000"
client_id = "00000000-0000-0000-0000-000000000000"
client_secret = "your-secret"

[sync]
days_to_expire = 50
dry_run = false
verbose = false
```

### Option 2: Environment Variables

```bash
# Required
export MISP_URL=https://misp.example.com
export MISP_API_KEY=your-misp-api-key
export SENTINEL_WORKSPACE_ID=00000000-0000-0000-0000-000000000000
export AZURE_TENANT_ID=00000000-0000-0000-0000-000000000000
export AZURE_CLIENT_ID=00000000-0000-0000-0000-000000000000
export AZURE_CLIENT_SECRET=your-client-secret

# Filters (optional)
export MISP_FILTER_PUBLISH_TIMESTAMP=14d
export MISP_FILTER_TAGS=tlp:white,type:malware
export MISP_FILTER_NOT_TAGS=tlp:red,false-positive
```

### Option 3: Mixed (Config + Env Overrides)

Use a config file for base settings, override specific values with environment variables:

```bash
# Base config from file
./misp2sentinel-cli --config config.toml

# With env override for API key (e.g., from secret manager)
MISP_API_KEY=$(vault read -field=key secret/misp) ./misp2sentinel-cli --config config.toml
```

## Usage

```bash
# With config file
./misp2sentinel-cli --config config.toml

# With environment variables only
./misp2sentinel-cli

# Dry run (parse events, don't upload)
./misp2sentinel-cli --config config.toml --dry-run

# Verbose logging
./misp2sentinel-cli --config config.toml --verbose

# Check config validity without running
./misp2sentinel-cli --config config.toml --check-config

# Debug level logging via RUST_LOG
RUST_LOG=debug ./misp2sentinel-cli --config config.toml
```

## CLI Options

| Flag | Env Variable | Description |
|------|--------------|-------------|
| `--config PATH` | `CONFIG_PATH` | Path to TOML config file |
| `--dry-run` | `SYNC_DRY_RUN` | Parse without uploading |
| `--verbose` | `VERBOSE` | Enable verbose logging |
| `--json-logs` | `LOG_JSON` | Output logs as JSON |
| `--check-config` | — | Validate config and exit |
| `--misp-url URL` | `MISP_URL` | MISP server URL |
| `--tenant-id ID` | `AZURE_TENANT_ID` | Azure AD tenant ID |
| `--client-id ID` | `AZURE_CLIENT_ID` | Azure AD client ID |
| `--workspace-id ID` | `SENTINEL_WORKSPACE_ID` | Sentinel workspace ID |
| `--keyvault-url URL` | `AZURE_KEYVAULT_URL` | Key Vault URL for secrets |

## Filtering Events

Filters control which MISP events are synchronized. Configure via config file or environment variables.

**Config file example:**
```toml
[misp.filters]
publish_timestamp = "7d"           # Events from last 7 days
tags = ["tlp:green", "tlp:amber"]  # Include if has these tags
not_tags = ["tlp:red", "test"]     # Exclude if has these tags
threat_level_id = [1, 2]           # High and Medium only
to_ids = true                      # Only IDS-flagged attributes
```

**Environment variable example:**
```bash
export MISP_FILTER_PUBLISH_TIMESTAMP=7d
export MISP_FILTER_TAGS=tlp:green,tlp:amber
export MISP_FILTER_NOT_TAGS=tlp:red,test
export MISP_FILTER_THREAT_LEVEL=1,2
```

See [FILTERS.md](./FILTERS.md) for the complete filter reference.

## Scheduled Sync

### Systemd Timer (Linux)

Create `/etc/systemd/system/misp2sentinel.service`:

```ini
[Unit]
Description=MISP2Sentinel Sync
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/misp2sentinel-cli --config /etc/misp2sentinel/config.toml
User=misp2sentinel

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/misp2sentinel.timer`:

```ini
[Unit]
Description=Run MISP2Sentinel every 6 hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable:

```bash
sudo systemctl enable --now misp2sentinel.timer
systemctl status misp2sentinel.timer
```

### Cron (Linux/macOS)

```bash
# Every 6 hours
0 */6 * * * /usr/local/bin/misp2sentinel-cli --config /etc/misp2sentinel/config.toml >> /var/log/misp2sentinel.log 2>&1
```

### Task Scheduler (Windows)

```powershell
# Create scheduled task to run every 6 hours
$action = New-ScheduledTaskAction -Execute "C:\misp2sentinel\misp2sentinel-cli.exe" -Argument "--config C:\misp2sentinel\config.toml"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 6)
Register-ScheduledTask -TaskName "MISP2Sentinel" -Action $action -Trigger $trigger -User "SYSTEM"
```

## Troubleshooting

### Check Configuration

```bash
./misp2sentinel-cli --config config.toml --check-config
```

### Verbose Logging

```bash
./misp2sentinel-cli --config config.toml --verbose 2>&1 | tee sync.log
```

### Test MISP Connectivity

```bash
curl -k -H "Authorization: YOUR_API_KEY" https://misp.example.com/servers/getVersion
```

### Test Azure Auth

```bash
curl -X POST "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=$AZURE_CLIENT_ID&client_secret=$AZURE_CLIENT_SECRET&scope=https://management.azure.com/.default"
```

### Common Issues

| Issue | Solution |
|-------|----------|
| "MISP_URL not set" | Set via config file, env var, or `--misp-url` |
| "SSL certificate error" | Set `verify_tls = false` for self-signed certs |
| "401 Unauthorized" (MISP) | Check API key has read permissions |
| "403 Forbidden" (Azure) | Check app has Sentinel Contributor role |

## Related Documentation

- [Filter Configuration](./FILTERS.md) - All filter options
- [Azure Setup](./SETUP_AZURE.md) - Azure Function deployment
- [Architecture](./ARCHITECTURE.md) - System design
