$tenantId = Get-AutomationVariable -Name 'tenantId'
$clientId = Get-AutomationVariable -Name 'GraphAPI-LAPS-client-id'
$clientSecret = Get-AutomationVariable -Name 'GraphAPI-LAPS-secret'
$vaultName = "lapssecret"

# Function to get an access token
function Get-AccessToken {
    param (
        [string]$tenantId,
        [string]$clientId,
        [string]$clientSecret
    )
    
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $clientId
        client_secret = $clientSecret
        scope         = "https://vault.azure.net/.default"
    }
    
    $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $body
    return $response.access_token
}

# Get the access token
$accessToken = Get-AccessToken -tenantId $tenantId -clientId $clientId -clientSecret $clientSecret

# Function to get all deleted secrets with paging
function Get-DeletedSecrets {
    param (
        [string]$vaultName,
        [string]$accessToken
    )

    $deletedSecrets = @()
    $deletedSecretsUri = "https://$vaultName.vault.azure.net/deletedsecrets?api-version=7.4"

    do {
        $response = Invoke-RestMethod -Method Get -Uri $deletedSecretsUri -Headers @{ Authorization = "Bearer $accessToken" }
        $deletedSecrets += $response.value
        $deletedSecretsUri = $response.nextLink
    } while ($deletedSecretsUri)

    return $deletedSecrets
}

# Function to purge a deleted secret
function Purge-DeletedSecret {
    param (
        [string]$vaultName,
        [string]$secretName,
        [string]$accessToken
    )
    
    $purgeUri = "https://$vaultName.vault.azure.net/deletedsecrets/$($secretName)?api-version=7.4"
    $response = Invoke-RestMethod -Method Delete -Uri $purgeUri -Headers @{ Authorization = "Bearer $accessToken" }
    return $response

}

# Get all deleted secrets
$deletedSecrets = Get-DeletedSecrets -vaultName $vaultName -accessToken $accessToken

if ($deletedSecrets.Count -eq 0) {
    Write-Output "No deleted secrets found in Key Vault '$vaultName'."
}
else {
    $deletedCount = 0
    foreach ($secret in $deletedSecrets) {
        $secretName = $secret.id.Split("/")[-1]
        $purgeUri = "https://$vaultName.vault.azure.net/deletedsecrets/$($secretName)?api-version=7.4"
        Write-Output "Purging deleted secret '$secretName' using URL: $purgeUri"
        $purgeResponse = Purge-DeletedSecret -vaultName $vaultName -secretName $secretName -accessToken $accessToken
        Write-Output "Deleted secret '$secretName' purged successfully."
        $deletedCount++
    }    
    Write-Output "$deletedCount deleted secrets have been purged from Key Vault '$vaultName'."
}
