<#
.SYNOPSIS
    Connects to Azure using the security context of an Azure AD application. Regenrates keys 
    of all storage accounts in the subscription. Writes the new primary keys to a Key Vault.

.DESCRIPTION
    Connects to Azure using the security context of an Azure AD application. Regenrates keys 
    of all storage accounts in the subscription. Writes the new primary keys to a Key Vault.
    http://www.dushyantgill.com
    
.NOTES
	Author: Dushyant Gill
	Last Updated: 4/27
#>

workflow AzureKeysRollerDaemon
{   
	# By default, errors in PowerShell do not cause workflows to suspend, like exceptions do.
	# This means a runbook can still reach 'completed' state, even if it encounters errors
	# during execution. The below command will cause all errors in the runbook to be thrown as
	# exceptions, therefore causing the runbook to suspend when an error is hit.
	$ErrorActionPreference = "Stop"
  $clientId = Get-AutomationVariable -Name "AzureKeysRollerDaemon-ClientId"
  $clientSecret = Get-AutomationVariable -Name "AzureKeysRollerDaemon-ClientSecret"
  $directory = Get-AutomationVariable -Name "DirectoryDomainName"
  $subscriptionId = Get-AutomationVariable -Name "SubscriptionId"
  $keyVaultName = Get-AutomationVariable -Name "AzureKeysRollerDaemon-KeyVaultName"
  InlineScript {
    #######################################################
    #acquire token from Azure AD for Azure Resource Manager
    #######################################################
    $armAccessToken = $null
    $uri = "https://login.windows.net/" + $using:directory + "/oauth2/token"
    $body = "grant_type=client_credentials"
    $body += "&client_id=" + $using:clientId
    $body += "&client_secret=" + [Uri]::EscapeDataString($using:clientSecret)
    $body += "&resource=" + [Uri]::EscapeDataString("https://management.core.windows.net/")
    $headers = @{"Accept"="application/json"}
    $enc = New-Object "System.Text.ASCIIEncoding"
    $byteArray = $enc.GetBytes($body)
    $contentLength = $byteArray.Length
    $headers.Add("Content-Type","application/x-www-form-urlencoded")
    $headers.Add("Content-Length",$contentLength)
    $result = try { Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -Body $body } catch { $_.Exception.Response } 
    $armAccessToken = $result.access_token

    ################################################
    #acquire token from Azure AD for Azure Key Vault
    ################################################
    $kvAccessToken = $null
    $uri = "https://login.windows.net/" + $using:directory + "/oauth2/token"
    $body = "grant_type=client_credentials"
    $body += "&client_id=" + $using:clientId
    $body += "&client_secret=" + [Uri]::EscapeDataString($using:clientSecret)
    $body += "&resource=" + [Uri]::EscapeDataString("https://vault.azure.net")
    $headers = @{"Accept"="application/json"}
    $enc = New-Object "System.Text.ASCIIEncoding"
    $byteArray = $enc.GetBytes($body)
    $contentLength = $byteArray.Length
    $headers.Add("Content-Type","application/x-www-form-urlencoded")
    $headers.Add("Content-Length",$contentLength)
    $result = try { Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -Body $body } catch { $_.Exception.Response }
    $kvAccessToken = $result.access_token

    ###########################
    #Enumerate Storage Accounts
    ###########################
    $storageAccounts = $null
    $header = "Bearer " + $armAccessToken
    $headers = @{"Authorization"=$header;"Content-Type"="application/json"}
    $uri = [string]::Format("https://management.azure.com/subscriptions/{0}/providers/Microsoft.ClassicStorage/storageAccounts?api-version=2014-04-01", $using:subscriptionId)
    $result = try { Invoke-RestMethod -Method GET -Uri $uri -Headers $headers } catch { $_.Exception.Response }
    $storageAccounts = $result.value

    if($storageAccounts -ne $null){
      $storageAccounts | % {
        $newPrimaryKey = $null
        
        #######################
        #regenerate primary Key
        #######################
        $uri = [string]::Format("https://management.azure.com{0}/regenerateKey?api-version=2014-06-01",$_.id)
        $postData = "" | select KeyType
        $postData.KeyType = "Primary"
        $header = "Bearer " + $armAccessToken
        $headers = @{"Authorization"=$header;"Content-Type"="application/json"}
        $enc = New-Object "System.Text.ASCIIEncoding"
        $body = ConvertTo-Json $postData
        $byteArray = $enc.GetBytes($body)
        $contentLength = $byteArray.Length
        $headers.Add("Content-Length",$contentLength)
        $result = try { Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -Body $body } catch { $_.Exception.Response }
        
        if($result.primaryKey -ne $null){
          #######################
          #regenerate secondary Key
          #######################
          $uri = [string]::Format("https://management.azure.com{0}/regenerateKey?api-version=2014-06-01",$_.id)
          $postData = "" | select KeyType
          $postData.KeyType = "Secondary"
          $header = "Bearer " + $armAccessToken
          $headers = @{"Authorization"=$header;"Content-Type"="application/json"}
          $enc = New-Object "System.Text.ASCIIEncoding"
          $body = ConvertTo-Json $postData
          $byteArray = $enc.GetBytes($body)
          $contentLength = $byteArray.Length
          $headers.Add("Content-Length",$contentLength)
          $result = try { Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -Body $body } catch { $_.Exception.Response }
          $newPrimaryKey = $result.primaryKey
        }
        
        ####################################
        # Write new primary key to Key Vault
        ####################################
        if($newPrimaryKey -ne $null){
          $secretName = "StorageAccount-" + $_.name
          $uri = [string]::Format("https://{0}.vault.azure.net/secrets/{1}?api-version=2014-12-08-preview",$using:keyVaultName, $secretName)
          $postData = "" | select value
          $postData.value = $newPrimaryKey
          $header = "Bearer " + $kvAccessToken
          $headers = @{"Authorization"=$header;"Content-Type"="application/json"}
          $enc = New-Object "System.Text.ASCIIEncoding"
          $body = ConvertTo-Json $postData
          $byteArray = $enc.GetBytes($body)
          $contentLength = $byteArray.Length
          $headers.Add("Content-Length",$contentLength)
          $result = try { Invoke-RestMethod -Method PUT -Uri $uri -Headers $headers -Body $body } catch { $_.Exception.Response }
          if($result.value -ne $null) {
            [string]::Format("Regenerated key for Storage Account {0} and saved it in Key Vault {1} as Secret {2}", $_.name, $using:keyVaultName, $result.id)
          }
          else {
            [string]::Format("Error while regenerating key for Storage Account {0} and saving it in Key Vault {1}", $_.name, $using:keyVaultName)
          }
        }
      }
    }
  }
}