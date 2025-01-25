@description('Location for all resources.')
param location string = resourceGroup().location

@description('The language worker runtime to load in the function app.')
param linuxFxVersion string = 'PYTHON|3.11'

@description('Subscription ID containing the existing storage account')
param storageAccountSubscriptionId string

var functionAppName = 'wafw00fkscsc'
var hostingPlanName = functionAppName
var functionWorkerRuntime = 'python'
var existingStorageAccountName = 'kscscwebrootstorage'
var existingStorageAccountResourceGroup = 'Websites'

resource existingStorageAccount 'Microsoft.Storage/storageAccounts@2022-09-01' existing = {
  name: existingStorageAccountName
  scope: resourceGroup(storageAccountSubscriptionId, existingStorageAccountResourceGroup)
}

resource hostingPlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: hostingPlanName
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2022-03-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  properties: {
    serverFarmId: hostingPlan.id
    siteConfig: {
      linuxFxVersion: linuxFxVersion
      numberOfWorkers: 1
      minimumElasticInstanceCount: 1
      ftpsState: 'FtpsOnly'
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${existingStorageAccountName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${existingStorageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${existingStorageAccountName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${existingStorageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(functionAppName)
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: functionWorkerRuntime
        }
        {
          name: 'WEBSITE_NODE_DEFAULT_VERSION'
          value: '~18'
        }
        {
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'true'
        }
        {
          name: 'ENABLE_ORYX_BUILD'
          value: 'true'
        }
      ]
    }
    httpsOnly: true
  }
} 
