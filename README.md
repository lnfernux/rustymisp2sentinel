# MISP2Sentinel

High-performance Rust implementation for syncing threat intelligence from MISP to Microsoft Sentinel.

> [!CAUTION]
> **Disclaimer**
>
> **This tool is created mainly by using AI.** Please exercise caution when using this solution and always understand what are you running before you run it in production. This tool was created as an experiment to learn more about Rust - the developer assumes no liability for any vulnerabilities or issues.
> 
> By downloading, installing, or using this tool, you acknowledge that you have read, understood, and agree to these terms.

## Prerequisites

This project supports the [STIX Objects version of the Microsoft Sentinel Upload Indicators API](https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api/?wt.mc_id=SEC-MVP-5005030) and requires the following to be setup:

1. **Application registration in Entra ID with Microsoft Sentinel Contributor on the resource group where Microsoft Sentinel is deployed**
    * You should have the following values from this step:
        * **client_id** - the application id of the application registration
        * **client_secret** - the secret (value) of the application registration, must be created
        * **tenant_id** - the azure tenant id
        * **workspace_id** - the id of sentinels underlying log analytics workspace
2. **MISP server configured**
    * You should have the following values from this step:
        * **MISP URI** - the url of the MISP server
        * **api key** - misp auth key

*For more guidance the Entra ID aspects:*
- **[Setting up app registrations](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app/?wt.mc_id=SEC-MVP-5005030)**
- **[Add credentials to an app registration](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials?tabs=client-secret/?wt.mc_id=SEC-MVP-5005030)**

## Quick Start

1. Download the appropriate binary for your platform from [GitHub Releases](https://github.com/lnfernux/rustymisp2sentinel/releases/latest)
2. Copy the `config.toml.example` file and place it in the same directory as the binary (or you can use environment variables)

```bash
cp config.toml.example config.toml
```

3. Fill out the config file with values from the prereqs and then check the config file 

```bash
./misp2sentinel-cli --config config.toml --check-config
```

4. Run the binary

```bash
# Base config from file
./misp2sentinel-cli --config config.toml

# With env override for API key (e.g., from secret manager)
MISP_API_KEY=$(vault read -field=key secret/misp) ./misp2sentinel-cli --config config.toml
```

## Documentation

- **[Filter Configuration Guide](docs/FILTERS.md)** - How to configure MISP event filters
- **[Local/CLI Setup](docs/SETUP_LOCAL.md)** - Running locally on the MISP server
- **[Architecture](docs/ARCHITECTURE.md)** - System architecture and design

## Components

| Crate | Description |
|-------|-------------|
| `misp2sentinel-core` | Core library |
| `misp2sentinel-cli` | CLI tool |

## Configuration

### Core Settings

| Variable | Required | Description |
|----------|----------|-------------|
| `MISP_URL` | Yes | MISP instance URL |
| `MISP_API_KEY` | Yes | MISP API key |
| `MISP_VERIFY_TLS` | No | Verify SSL certificates (default: true, set to false for self-signed) |
| `SENTINEL_WORKSPACE_ID` | Yes | Sentinel workspace ID |
| `AZURE_TENANT_ID` | No | Required without managed identity |
| `AZURE_CLIENT_ID` | No | Required without managed identity |
| `AZURE_CLIENT_SECRET` | No | Required without managed identity |

### MISP Filters

Control which events are synced using environment variables.

**Built-in defaults** (no configuration required, but can be changed in config.toml or via env):
- `published: true` - Only syncs published events
- `publish_timestamp: 14d` - Only events published in last 14 days  
- `to_ids: true` - Only IDS-flagged attributes

**Optional overrides:**

| Variable | Example | Description |
|----------|---------|-------------|
| `MISP_FILTER_TAGS` | `tlp:white,type:malware` | Include events with these tags (OR logic) |
| `MISP_FILTER_NOT_TAGS` | `tlp:red,false-positive` | Exclude events with these tags |
| `MISP_FILTER_ORGS` | `CIRCL,MISP Project` | Include events from these organizations |
| `MISP_FILTER_NOT_ORGS` | `Test Org` | Exclude events from these organizations |
| `MISP_FILTER_PUBLISH_TIMESTAMP` | `7d` or `2024-01-01` | Events published after this time (default: 14d) |
| `MISP_FILTER_LAST` | `24h` or `7d` | Events from the last N time period |
| `MISP_FILTER_PUBLISHED` | `true` | Only published events (default: true) |
| `MISP_FILTER_TO_IDS` | `true` | Only IDS-flagged attributes (default: true) |
| `MISP_FILTER_THREAT_LEVEL` | `1,2` | Filter by threat level (1=High, 2=Medium, 3=Low) |
| `MISP_FILTER_EVENT_INFO` | `phishing` | Search in event description |

See [docs/FILTERS.md](docs/FILTERS.md) for full configuration options.

## Performance & Benchmarks

The Rust implementation is significantly faster than the Python version, primarily due to concurrent uploads and highly optimized STIX conversion.

### Benchmark Results (10 Events)

| Metric | Python | Rust | Notes |
|--------|--------|------|-------|
| **Events fetched** | 10 | 10 | Same source |
| **Indicators created** | 1507 | 1496 | ~0.7% variance (see below) |
| **Upload success** | 1507 | 1496 | Both 100% |
| **Upload errors** | 0 | 0 | N/A |

### Timing Breakdown

| Phase | Python | Rust | Speedup |
|-------|--------|------|---------|
| MISP Fetch | 0.73s | 0.53s | 1.4x |
| STIX Conversion | 1.21s | 0.003s | **~400x** |
| Azure Auth | 0.44s | 0.15s | 2.9x |
| Sentinel Upload | 120.23s | 23.31s | **5.2x** |
| **TOTAL** | **122.61s** | **23.85s** | **5.14x faster** |

### Why Rust is Faster

1. **Concurrent uploads**: Rust uploads 4 batches in parallel vs Python's sequential approach
2. **Native STIX conversion**: Rust converts attributes directly to STIX patterns without external libraries (449,074 indicators/sec)
3. **Zero-copy parsing**: Efficient JSON handling with serde

### Indicator Count Difference Explained

The slight variance (1507 vs 1496 = 11 indicators, ~0.7%) is due to implementation differences:

| Difference | Python | Rust |
|------------|--------|------|
| **STIX converter** | Uses `misp-stix` library (Python) | Native Rust implementation |
| **Deduplication** | Per-event dedup, then global | Pattern-based global dedup |
| **Attribute handling** | Library-determined type mapping | Direct attribute type → STIX pattern |
| **Edge cases** | Library handles composite attributes | Some composite types may be handled differently |

Both implementations produce valid STIX indicators that Sentinel accepts (100% upload success rate). The difference is negligible for production use.

## License

MIT
