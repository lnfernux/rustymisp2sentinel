@description('Name of the Function App. Must be globally unique.')
param functionAppName string

@description('Location for all resources. Defaults to the resource group location.')
param location string = resourceGroup().location

@description('MISP server URL (e.g. https://misp.example.com).')
param mispUrl string

@description('MISP API key. Stored in Key Vault.')
@secure()
param mispApiKey string

@description('Whether to verify TLS certificates when connecting to MISP.')
param mispVerifyTls bool = true

@description('MISP publish_timestamp filter window (e.g. 14d, 7d, 1d).')
param mispPublishTimestamp string = '14d'

@description('Azure AD Tenant ID used to authenticate against Sentinel.')
param tenantId string = subscription().tenantId

@description('Azure AD Client ID (app registration) with Sentinel Contributor role.')
param clientId string

@description('Azure AD Client Secret for the app registration. Stored in Key Vault.')
@secure()
param clientSecret string

@description('Microsoft Sentinel Workspace ID.')
param sentinelWorkspaceId string

@description('Number of days until uploaded indicators expire in Sentinel.')
param daysToExpire int = 90

@description('Default confidence score for indicators (0-100).')
param defaultConfidence int = 50

@description('Sync schedule as a 6-part NCRONTAB expression.')
param syncSchedule string = '0 0 * * * *'

@description('Run in dry-run mode — fetches and converts indicators but does not upload to Sentinel.')
param dryRun bool = false

// ── Names ──────────────────────────────────────────────────────────────────
var uniqueSuffix = uniqueString(resourceGroup().id)
var storageAccountName = 'stmisp${take(uniqueSuffix, 11)}'
var keyVaultName = 'kv-misp-${take(uniqueSuffix, 10)}'
var appServicePlanName = '${functionAppName}-plan'
var logAnalyticsName = '${functionAppName}-logs'
var appInsightsName = '${functionAppName}-ai'
var keyVaultSecretsUserRole = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User
)

// ── Storage Account ────────────────────────────────────────────────────────
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

// ── Log Analytics Workspace ────────────────────────────────────────────────
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// ── Application Insights ───────────────────────────────────────────────────
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

// ── Consumption Plan (Linux) ───────────────────────────────────────────────
resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  kind: 'linux'
  properties: {
    reserved: true
  }
}

// ── Key Vault ──────────────────────────────────────────────────────────────
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    softDeleteRetentionInDays: 7
    enabledForTemplateDeployment: false
  }
}

resource mispApiKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'misp-api-key'
  properties: { value: mispApiKey }
}

resource clientSecretSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'sentinel-client-secret'
  properties: { value: clientSecret }
}

// ── Function App ───────────────────────────────────────────────────────────
resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    reserved: true
    siteConfig: {
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccountName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
        }
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'custom' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
        { name: 'SYNC_SCHEDULE', value: syncSchedule }
        { name: 'MISP_URL', value: mispUrl }
        { name: 'MISP_VERIFY_TLS', value: string(mispVerifyTls) }
        { name: 'MISP_FILTER_PUBLISHED', value: 'true' }
        { name: 'MISP_FILTER_PUBLISH_TIMESTAMP', value: mispPublishTimestamp }
        {
          name: 'MISP_API_KEY'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=misp-api-key)'
        }
        { name: 'AZURE_TENANT_ID', value: tenantId }
        { name: 'AZURE_CLIENT_ID', value: clientId }
        {
          name: 'AZURE_CLIENT_SECRET'
          value: '@Microsoft.KeyVault(VaultName=${keyVaultName};SecretName=sentinel-client-secret)'
        }
        { name: 'SENTINEL_WORKSPACE_ID', value: sentinelWorkspaceId }
        { name: 'SENTINEL_SOURCE_SYSTEM', value: 'MISP' }
        { name: 'SYNC_DAYS_TO_EXPIRE', value: string(daysToExpire) }
        { name: 'SYNC_DEFAULT_CONFIDENCE', value: string(defaultConfidence) }
        { name: 'SYNC_DRY_RUN', value: string(dryRun) }
      ]
      linuxFxVersion: ''
    }
    httpsOnly: true
  }
  dependsOn: [mispApiKeySecret, clientSecretSecret]
}

// ── RBAC: grant Function App managed identity access to Key Vault secrets ──
resource kvRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, functionApp.id, keyVaultSecretsUserRole)
  scope: keyVault
  properties: {
    roleDefinitionId: keyVaultSecretsUserRole
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ── Outputs ────────────────────────────────────────────────────────────────
output functionAppName string = functionApp.name
output functionAppUrl string = 'https://${functionApp.properties.defaultHostName}'
output keyVaultName string = keyVault.name
