/* This Bicep file creates a function app running in a Flex Consumption plan 
that connects to Azure Storage by using managed identities with Microsoft Entra ID. */

//********************************************
// Parameters
//********************************************

@description('Primary region for all Azure resources.')
@minLength(1)
param location string = resourceGroup().location

@description('Language runtime used by the function app.')
@allowed(['dotnet-isolated', 'python', 'java', 'node', 'powerShell'])
param functionAppRuntime string = 'python'

@description('Target language version used by the function app.')
@allowed(['3.10', '3.11', '3.12', '7.4', '8.0', '9.0', '10', '11', '17', '20'])
param functionAppRuntimeVersion string = '3.12'

@description('The maximum scale-out instance count limit for the app.')
@minValue(40)
@maxValue(1000)
param maximumInstanceCount int = 40

@description('The memory size of instances used by the app.')
@allowed([512, 2048, 4096])
param instanceMemoryMB int = 512

@description('A unique token used for resource name generation.')
@minLength(3)
param resourceToken string = toLower(uniqueString(subscription().id, location))

@description('A globally unigue name for your deployed function app.')
@secure()
param functionName string

@description('The ID of the Log Analytics workspace to which Application Insights will send telemetry data.')
@secure()
param logAnalyticsWorkspaceId string

//********************************************
// Variables
//********************************************

// Generates a unique container name for deployments.
var deploymentStorageContainerName = 'app-package-${take(functionName, 32)}-${take(resourceToken, 7)}'

// Key access to the storage account is disabled by default 
var storageAccountAllowSharedKeyAccess = false

// Define the IDs of the roles we need to assign to our managed identities.
var storageBlobDataOwnerRoleId = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
var storageBlobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var storageQueueDataContributorId = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
var storageTableDataContributorId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var monitoringMetricsPublisherId = '3913510d-42f4-4e42-8a64-420c390055eb'

//********************************************
// Azure resources required by your function app.
//********************************************

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-${resourceToken}'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspaceId
    DisableLocalAuth: true
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'st${resourceToken}'
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: storageAccountAllowSharedKeyAccess
    dnsEndpointType: 'Standard'
    minimumTlsVersion: 'TLS1_2'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
    publicNetworkAccess: 'Enabled'
  }
  resource blobServices 'blobServices' = {
    name: 'default'
    properties: {
      deleteRetentionPolicy: {}
    }
    resource deploymentContainer 'containers' = {
      name: deploymentStorageContainerName
      properties: {
        publicAccess: 'None'
      }
    }
  }
}

resource roleAssignmentBlobDataOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, storage.id, functionApp.id, 'Storage Blob Data Owner')
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource roleAssignmentBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, storage.id, functionApp.id, 'Storage Blob Data Contributor')
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageBlobDataContributorRoleId
    )
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource roleAssignmentQueueStorage 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, storage.id, functionApp.id, 'Storage Queue Data Contributor')
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageQueueDataContributorId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource roleAssignmentTableStorage 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, storage.id, functionApp.id, 'Storage Table Data Contributor')
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageTableDataContributorId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource roleAssignmentAppInsights 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, applicationInsights.id, functionApp.id, 'Monitoring Metrics Publisher')
  scope: applicationInsights
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

//********************************************
// Function app and Flex Consumption plan definitions
//********************************************

resource appServicePlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: 'plan-${resourceToken}'
  location: location
  kind: 'functionapp'
  sku: {
    tier: 'FlexConsumption'
    name: 'FC1'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: functionName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      alwaysOn: false
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${deploymentStorageContainerName}'
          authentication: {
            type: 'SystemAssignedIdentity'
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: maximumInstanceCount
        instanceMemoryMB: instanceMemoryMB
      }
      runtime: {
        name: functionAppRuntime
        version: functionAppRuntimeVersion
      }
    }
  }
  resource configAppSettings 'config' = {
    name: 'appsettings'
    properties: {
      AzureWebJobsStorage__accountName: storage.name
      AzureWebJobsStorage__credential: 'managedidentity'
      APPINSIGHTS_INSTRUMENTATIONKEY: applicationInsights.properties.InstrumentationKey
      APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'Authorization=AAD'
    }
  }
}
