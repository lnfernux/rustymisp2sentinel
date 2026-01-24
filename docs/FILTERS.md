# MISP Filter Configuration Guide

This guide explains how to configure MISP event filters to control which threat intelligence is synced to Microsoft Sentinel.

## Overview

Filters can be configured via:
1. **TOML config file** (`config.toml`) - Recommended for local development
2. **Environment variables** - Recommended for Azure deployments

Filters are applied server-side during the MISP API request, ensuring efficient data transfer.

## Default Behavior

Without any custom filters, MISP2Sentinel:
- Fetches **published events only**
- From the **last 14 days** (`publish_timestamp = "14d"`)
- With **IDS-flagged attributes only** (`to_ids = true`)
- Processes **all organizations and tags**

## Configuration Methods

### Method 1: TOML Config File (Local/CLI)

```toml
[misp.filters]
published = true
to_ids = true
publish_timestamp = "14d"
tags = ["tlp:white", "type:malware"]
not_tags = ["tlp:red", "false-positive"]
threat_level_id = [1, 2]
```

### Method 2: Environment Variables (Azure Function)

```bash
MISP_FILTER_PUBLISHED=true
MISP_FILTER_TO_IDS=true
MISP_FILTER_PUBLISH_TIMESTAMP=14d
MISP_FILTER_TAGS=tlp:white,type:malware
MISP_FILTER_NOT_TAGS=tlp:red,false-positive
MISP_FILTER_THREAT_LEVEL=1,2
```

### Method 3: Azure Portal (GUI)

1. Navigate to your Function App in Azure Portal
2. Go to **Settings** → **Environment variables**
3. Click **+ Add** for each application setting
4. Add your filter variables (see table below)
5. Click **Apply** then **Confirm**

### Method 4: Azure CLI

```bash
az functionapp config appsettings set \
    --name <function-app-name> \
    --resource-group <resource-group> \
    --settings \
        "MISP_FILTER_TAGS=tlp:white,type:malware" \
        "MISP_FILTER_NOT_TAGS=tlp:red,false-positive" \
        "MISP_FILTER_PUBLISH_TIMESTAMP=7d"
```

## Available Filters

### Time-Based Filters

| TOML Key | Env Variable | Format | Example | Description |
|----------|--------------|--------|---------|-------------|
| `publish_timestamp` | `MISP_FILTER_PUBLISH_TIMESTAMP` | `Nd` or `YYYY-MM-DD` | `7d`, `2024-01-01` | Events published after this time (default: `14d`) |
| `timestamp` | `MISP_FILTER_TIMESTAMP` | `Nd` or `YYYY-MM-DD` | `30d` | Events modified after this time |
| `last` | `MISP_FILTER_LAST` | `Nh` or `Nd` | `24h`, `7d` | Events from the last N hours/days |
| `from` | `MISP_FILTER_FROM` | `YYYY-MM-DD` | `2024-01-01` | Events with date >= from |
| `to` | `MISP_FILTER_TO` | `YYYY-MM-DD` | `2024-12-31` | Events with date <= to |

### Tag Filters

| TOML Key | Env Variable | Format | Description |
|----------|--------------|--------|-------------|
| `tags` | `MISP_FILTER_TAGS` | Array / comma-separated | Include events with ANY of these tags (OR logic) |
| `not_tags` | `MISP_FILTER_NOT_TAGS` | Array / comma-separated | Exclude events with ANY of these tags |

**TOML format**: `tags = ["tlp:white", "type:malware"]`
**Env format**: `MISP_FILTER_TAGS=tlp:white,type:malware`

### Organization Filters

| TOML Key | Env Variable | Format | Description |
|----------|--------------|--------|-------------|
| `orgs` | `MISP_FILTER_ORGS` | Array / comma-separated | Include events from these organizations |
| `not_orgs` | `MISP_FILTER_NOT_ORGS` | Array / comma-separated | Exclude events from these organizations |

### Content Filters

| TOML Key | Env Variable | Format | Description |
|----------|--------------|--------|-------------|
| `event_info` | `MISP_FILTER_EVENT_INFO` | String | Search term in event info/description |
| `threat_level_id` | `MISP_FILTER_THREAT_LEVEL` | Array / comma-separated | Filter by threat level (1=High, 2=Medium, 3=Low, 4=Undefined) |

### Boolean Filters

| TOML Key | Env Variable | Default | Description |
|----------|--------------|---------|-------------|
| `published` | `MISP_FILTER_PUBLISHED` | `true` | Only include published events |
| `to_ids` | `MISP_FILTER_TO_IDS` | `true` | Only include IDS-flagged attributes |
| `enforce_warninglist` | `MISP_FILTER_ENFORCE_WARNINGLIST` | `false` | Apply MISP warninglist filtering |
| `include_event_tags` | `MISP_FILTER_INCLUDE_EVENT_TAGS` | `true` | Include event-level tags in response |

## Common Filter Scenarios

### Scenario 1: High-Confidence Indicators Only

Get TLP:WHITE, high/medium threat level indicators from the last 7 days:

**TOML:**
```toml
[misp.filters]
tags = ["tlp:white"]
threat_level_id = [1, 2]
publish_timestamp = "7d"
to_ids = true
```

**Environment:**
```bash
MISP_FILTER_TAGS=tlp:white
MISP_FILTER_THREAT_LEVEL=1,2
MISP_FILTER_PUBLISH_TIMESTAMP=7d
MISP_FILTER_TO_IDS=true
```

### Scenario 2: Specific Threat Campaign

Track a specific campaign:

**TOML:**
```toml
[misp.filters]
tags = ["campaign:operation-xyz"]
not_tags = ["false-positive"]
publish_timestamp = "30d"
```

### Scenario 3: Trusted Organizations Only

Only sync events from trusted threat intel providers:

**TOML:**
```toml
[misp.filters]
orgs = ["CIRCL", "CERT-EU"]
publish_timestamp = "14d"
```

### Scenario 4: Exclude Test/Low-Quality Data

**TOML:**
```toml
[misp.filters]
not_tags = ["false-positive", "test", "tlp:red"]
not_orgs = ["TestOrg", "Sandbox"]
published = true
```

### Scenario 5: Recent Malware Indicators

Get malware indicators from the last 24 hours:

**TOML:**
```toml
[misp.filters]
tags = ["type:malware"]
last = "24h"
to_ids = true
```

## Testing Filter Changes

### CLI Dry Run

Test filters locally without uploading:

```bash
# Edit config.toml with your filters, then:
cargo run --release -- --dry-run
```

### Azure Function HTTP Trigger

Trigger a manual sync via HTTP:

```bash
# Get function key
FUNC_KEY=$(az functionapp keys list \
    --name <function-app-name> \
    --resource-group <resource-group> \
    --query "functionKeys.default" -o tsv)

# Trigger sync
curl -X POST "https://<function-app-name>.azurewebsites.net/api/misp2sentinelhttp?code=$FUNC_KEY"
```

Expected response:
```json
{
  "status": "success",
  "message": "Processed 42 events, created 1337 indicators. Upload: 1337 successful, 0 failed",
  "details": {
    "events_processed": 42,
    "indicators_created": 1337,
    "successful": 1337,
    "failed": 0
  }
}
```

## Filter Logic

- **Tag filters** use OR logic: Event must have at least one tag from `tags`
- **NOT filters** use OR logic: Event is excluded if it has any tag from `not_tags`
- **Multiple filter types** use AND logic: Event must match ALL filter criteria
- **Empty/unset filters** are ignored: Not setting a filter means "match all"

Example combining filters:
```toml
[misp.filters]
tags = ["tlp:white", "type:malware"]   # Must have tlp:white OR type:malware
not_tags = ["false-positive"]           # AND must NOT have false-positive
threat_level_id = [1, 2]                # AND threat level must be 1 OR 2
```

## Performance Considerations

- **Server-side filtering**: Filters are applied by MISP during the query, reducing network transfer
- **Pagination**: Large result sets are fetched in pages (default: 100 events per page, 4 concurrent)
- **Time-based filters**: Use shorter time ranges (e.g., `7d` instead of `365d`) for faster syncs
- **Concurrent fetches**: Configurable via `concurrent_page_fetches` (default: 4)

## Troubleshooting

### No Events Returned

If `events_processed: 0`, check:

1. **MISP has matching events**: Verify events exist in MISP matching your filters
2. **Time range**: Try broadening `publish_timestamp` (e.g., `30d` or `365d`)
3. **Tag requirements**: Try removing `tags` filter to see all events
4. **IDS flag**: Set `to_ids = false` to include non-IDS attributes
5. **Published status**: Ensure events are published in MISP

### Too Many Events

If processing takes too long:

1. **Narrow time range**: Use `7d` or `14d` instead of `365d`
2. **Add tag filters**: Only sync specific threat types
3. **Organization filters**: Limit to trusted sources
4. **Use max_events**: Set `max_events = 1000` to cap the number

### Filter Not Applied

If changes don't take effect:

1. **Azure Function**: Restart after changing environment variables
2. **CLI**: Ensure you're editing the correct `config.toml`
3. **Env override**: Environment variables override TOML values
4. **Spelling**: Variable names are case-sensitive

## Complete Reference

### TOML Config Structure

```toml
[misp.filters]
# Boolean filters
published = true                    # Default: true
to_ids = true                       # Default: true
enforce_warninglist = false         # Default: false
include_event_tags = true           # Default: true

# Time filters (pick one approach)
publish_timestamp = "14d"           # Default: "14d"
# timestamp = "7d"                  # Alternative: modification time
# last = "24h"                      # Alternative: relative time
# from = "2024-01-01"               # Alternative: date range
# to = "2024-12-31"

# Tag filters
tags = ["tlp:white"]                # Include if has any
not_tags = ["false-positive"]       # Exclude if has any

# Organization filters
orgs = ["CIRCL"]                    # Include if from any
not_orgs = ["TestOrg"]              # Exclude if from any

# Content filters
event_info = "ransomware"           # Text search
threat_level_id = [1, 2]            # 1=High, 2=Med, 3=Low, 4=Undef
```

### Environment Variable Reference

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MISP_FILTER_PUBLISHED` | bool | `true` | Only published events |
| `MISP_FILTER_TO_IDS` | bool | `true` | Only IDS-flagged attributes |
| `MISP_FILTER_PUBLISH_TIMESTAMP` | string | `14d` | Events published after |
| `MISP_FILTER_TIMESTAMP` | string | — | Events modified after |
| `MISP_FILTER_LAST` | string | — | Events from last N time |
| `MISP_FILTER_FROM` | string | — | Events from date (YYYY-MM-DD) |
| `MISP_FILTER_TO` | string | — | Events until date (YYYY-MM-DD) |
| `MISP_FILTER_TAGS` | csv | — | Tags to include (OR) |
| `MISP_FILTER_NOT_TAGS` | csv | — | Tags to exclude (OR) |
| `MISP_FILTER_ORGS` | csv | — | Orgs to include (OR) |
| `MISP_FILTER_NOT_ORGS` | csv | — | Orgs to exclude (OR) |
| `MISP_FILTER_EVENT_INFO` | string | — | Text search in event info |
| `MISP_FILTER_THREAT_LEVEL` | csv | — | Threat levels (1,2,3,4) |
| `MISP_FILTER_ENFORCE_WARNINGLIST` | bool | `false` | Apply warninglist |
| `MISP_FILTER_INCLUDE_EVENT_TAGS` | bool | `true` | Include event tags |

## Related Documentation

- [Local Setup Guide](./SETUP_LOCAL.md) - CLI configuration
- [Azure Setup Guide](./SETUP_AZURE.md) - Azure Function configuration
- [Deployment Guide](../deploy/README.md) - Bicep deployment with filters
- [MISP restSearch API](https://www.misp-project.org/openapi/#tag/Events/operation/restSearchEvents) - Full API reference
