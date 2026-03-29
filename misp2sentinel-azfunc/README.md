# misp2sentinel-azfunc

Azure Functions Custom Handler for [rustymisp2sentinel](https://github.com/lnfernux/rustymisp2sentinel) — syncs threat indicators from MISP to Microsoft Sentinel on a timer.

## Deploy to Azure

Click below to deploy the full infrastructure (Function App, Key Vault, Storage, Application Insights) into your Azure subscription:

[![Deploy to Azure](https://aka.ms/deploytoazure)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Flnfernux%2Frustymisp2sentinel%2Frocky-grove%2Fmisp2sentinel-azfunc%2Fazuredeploy.json)

> **Note:** After deploying the infrastructure, you must publish the function code separately — see [Post-deployment](#post-deployment) below.

### Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `functionAppName` | ✅ | — | Globally unique name for the Function App |
| `mispUrl` | ✅ | — | MISP server URL (e.g. `https://misp.example.com`) |
| `mispApiKey` | ✅ | — | MISP API key — stored in Key Vault |
| `clientId` | ✅ | — | Azure AD app registration Client ID with Sentinel Contributor role |
| `clientSecret` | ✅ | — | Azure AD Client Secret — stored in Key Vault |
| `sentinelWorkspaceId` | ✅ | — | Microsoft Sentinel Workspace ID |
| `tenantId` | | subscription tenant | Azure AD Tenant ID |
| `mispVerifyTls` | | `true` | Verify TLS certificate when connecting to MISP |
| `mispPublishTimestamp` | | `14d` | MISP publish_timestamp filter (e.g. `7d`, `1d`, `2024-01-01`) |
| `daysToExpire` | | `90` | Days until uploaded indicators expire in Sentinel |
| `defaultConfidence` | | `50` | Default confidence score for indicators (0–100) |
| `syncSchedule` | | `0 0 * * * *` | Timer schedule as [NCRONTAB](https://learn.microsoft.com/azure/azure-functions/functions-bindings-timer#ncrontab-expressions) — default is hourly |
| `dryRun` | | `false` | Fetch and convert but skip upload to Sentinel |

### What gets deployed

- **Function App** (Linux Consumption plan) with system-assigned managed identity
- **Key Vault** — stores `MISP_API_KEY` and `AZURE_CLIENT_SECRET`; Function App is granted *Key Vault Secrets User* via RBAC
- **Storage Account** — required by the Functions runtime
- **Application Insights** + **Log Analytics Workspace** — for logs and monitoring

### Post-deployment

The ARM template provisions infrastructure only. Deploy the function code with the Azure Functions Core Tools:

```bash
# From the misp2sentinel-azfunc directory
func azure functionapp publish <functionAppName> --no-build
```

> The pre-built Linux `handler` binary is included in the repo and deployed automatically by the above command.

---

## Local development (WSL)

### First-time setup

```bash
# Install Azure Functions Core Tools and Azurite
bash setup-wsl.sh

# Copy and fill in your credentials
cp local.settings.json.example local.settings.json
# Edit local.settings.json with your values
```

### Running locally

**Terminal 1** — local storage emulator:
```bash
azurite --silent
```

**Terminal 2** — function host:
```bash
/usr/local/bin/func start
```

**Terminal 3** — trigger manually:
```bash
bash trigger.sh
```

### Updating local settings

If new settings were added to `local.settings.json.example`, merge them into your existing file without overwriting credentials:

```bash
bash patch-settings.sh
```

---

## Monitoring

Logs are structured JSON and forwarded to Application Insights automatically. Key log events at `INFO` level:

| Event | What it means |
|---|---|
| `Starting MISP to Sentinel synchronization` | Run started |
| `Fetched N events from MISP in Xs` | Phase 1 complete |
| `Converted to N STIX indicators in Xs` | Phase 2 complete |
| `Starting upload: N indicators in M batches` | Phase 3 starting |
| `Upload progress: M/T batches (X%)` | Progress every 10% |
| `Batch N: rate limit hit, waiting X seconds` | Automatic retry on 429 |
| `Sync completed` | Run finished with counts |

To enable verbose per-batch logging, set `RUST_LOG=misp2sentinel_core=debug` in application settings.
