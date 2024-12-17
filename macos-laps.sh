#!/usr/bin/env bash
# Exit script as soon as a command fails
set -e

# Function to log messages
log_message() {
    echo "$(date) | $1" >> "$log_file"
    echo $1
}

# Get Mac name
mac_name=$(scutil --get ComputerName)

# Variables definition
adminaccountname="adminuser"
log_folder="/var/log/intune_scripts"
log_file="$log_folder/laps.log"
key_vault_name="your_keyvault_name"
# GraphAPI-LAPS
tenant_id="your-tenant-id"
client_id="your-client-id"
azure_api_secret="your-client-secret"

# Generate a random password
randomstring=$(openssl rand -base64 12)
upper=$(LC_ALL=C tr -dc 'A-Z' </dev/urandom | head -c 1)
digit=$(LC_ALL=C tr -dc '0-9' </dev/urandom | head -c 1)
lower=$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c 1)
specchar=$(LC_ALL=C tr -dc '%&$=+#!?' </dev/urandom | head -c 1)
p="$randomstring$upper$digit$lower$specchar"

# Function to get Azure access token
get_access_token() {
    local response=$(curl -s -X POST "https://login.microsoftonline.com/$tenant_id/oauth2/v2.0/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=$client_id&client_secret=$azure_api_secret&scope=https://vault.azure.net/.default")
    echo $(echo $response | grep -o '"access_token":"[^"]*' | grep -o '[^"]*$')
}

# Get access token
log_message "Requesting access token..."
access_token=$(get_access_token)
if [ -z "$access_token" ]; then
    log_message "Failed to retrieve access token."
    exit 1
fi
log_message "Access token retrieved successfully"

# Function to check if the secret exists
secret_exists() {
    local result=$(curl -s -o /dev/null -w "%{http_code}" -X GET "https://$key_vault_name.vault.azure.net/secrets/$mac_name?api-version=7.4" \
        -H "Authorization: Bearer $access_token")
    if [ "$result" -eq 200 ]; then
        return 0
    else
        return 1
    fi
}

# Function to update or create the secret
update_or_create_secret() {
    local result=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "https://$key_vault_name.vault.azure.net/secrets/$mac_name?api-version=7.4" \
        -H "Authorization: Bearer $access_token" \
        -H "Content-Type: application/json" \
        -d "{\"value\":\"$p\"}")

    echo $result
}

# Create log folder
mkdir -m 755 -p $log_folder

log_message "===== starting script laps ======"

if id "$adminaccountname" >/dev/null 2>&1; then
    log_message "$adminaccountname already exists. deleting..."
    sysadminctl -deleteUser "$adminaccountname" >> $log_file 2>&1
else
    log_message "$adminaccountname does not exist"
fi

log_message "creating user $adminaccountname ..."
sysadminctl -adminUser "$adminaccountname" -adminPassword "$p" -addUser "$adminaccountname" -fullName "$adminaccountname" -password "$p" -admin >> $log_file 2>&1
log_message "user $adminaccountname created"

log_message "hiding created user $adminaccountname"
defaults write /Library/Preferences/com.apple.loginwindow HiddenUsersList -array-add "$adminaccountname" >> $log_file 2>&1
log_message "user $adminaccountname hidden"

log_message "Checking if secret '$mac_name' exists in Azure Key Vault"
if secret_exists; then
    log_message "Secret '$mac_name' already exists. Deleting..."
    delete_result=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "https://$key_vault_name.vault.azure.net/secrets/$mac_name?api-version=7.4" \
        -H "Authorization: Bearer $access_token")

    if [ "$delete_result" -eq 200 ] || [ "$delete_result" -eq 204 ]; then
        log_message "Secret '$mac_name' deleted successfully. Waiting for 30 seconds..."
        sleep 30
        log_message "Purging secret '$mac_name'..."
        purge_result=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "https://$key_vault_name.vault.azure.net/deletedsecrets/$mac_name?api-version=7.4" \
            -H "Authorization: Bearer $access_token")

        if [ "$purge_result" -eq 204 ]; then
            log_message "Secret '$mac_name' purged successfully. Waiting for 30 seconds..."
            sleep 30
            log_message "Recreating the secret '$mac_name'..."
            create_result=$(update_or_create_secret)
            if [ "$create_result" -eq 200 ] || [ "$create_result" -eq 201 ]; then
                log_message "Secret '$mac_name' created successfully."
            else
                log_message "Failed to create secret. Response code: $create_result."
                exit 1
            fi
        else
            log_message "Failed to purge secret. Response code: $purge_result."
            exit 1
        fi
    else
        log_message "Failed to delete secret. Response code: $delete_result."
        exit 1
    fi
else
    log_message "Secret '$mac_name' does not exist. Creating..."
    create_result=$(update_or_create_secret)
    if [ "$create_result" -eq 200 ] || [ "$create_result" -eq 201 ]; then
        log_message "Secret '$mac_name' created successfully."
    else
        log_message "Failed to create secret. Response code: $create_result."
        exit 1
    fi
fi
