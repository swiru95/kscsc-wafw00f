@description('Location for all resources.')
param location string = resourceGroup().location

@description('The language worker runtime to load in the function app.')
param linuxFxVersion string = 'PYTHON|3.11'

param storageAccountName string

var functionAppName = 'wafw00fkscsc'
var hostingPlanName = functionAppName
var functionWorkerRuntime = 'python'
var storageAccountType = 'Standard_LRS'

resource storageAccount 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: storageAccountType
  }
  kind: 'Storage'
  properties: {
    supportsHttpsTrafficOnly: true
    defaultToOAuthAuthentication: true
  }
}
resource storageAccountContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2022-09-01' = {
  name: '${storageAccountName}/default/functionapp'
  properties: {
    publicAccess: 'None'
  }
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
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: hostingPlan.id
    siteConfig: {
      linuxFxVersion: linuxFxVersion
      numberOfWorkers: 1
      minimumElasticInstanceCount: 1
      ftpsState: 'FtpsOnly'
      appSettings: [
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: functionWorkerRuntime
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: 'https://${storageAccountName}.blob.core.windows.net/functionapp/functionapp.zip'
        }
      ]
    }
    httpsOnly: true
  }
} 
