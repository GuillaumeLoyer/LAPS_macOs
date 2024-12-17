#!/usr/bin/env bash
set -eu -o pipefail

# Optional: trap function to log and exit gracefully on an error
trap 'log_message "An unexpected error occurred. Exiting..."' ERR

#######################################
# Configuration Variables
#######################################
adminaccountname="<admin_user_name>"
log_folder="/var/log/intune_scripts"
log_file="$log_folder/laps.log"
max_log_size=51200  # 50 KB

key_vault_name="<vault_name>"
tenant_id="<your_tenant_id>"
client_id="<your_client_id>"
azure_api_secret="<your_client_secret>"

#######################################
# Helper Functions
#######################################

log_message() {
    local msg="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $msg" >> "$log_file"
    echo "$msg"
}

rotate_logs_if_needed() {
    if [ -f "$log_file" ]; then
        local size
        size=$(stat -f%z "$log_file" 2>/dev/null || echo 0)
        if [ "$size" -gt "$max_log_size" ]; then
            log_message "Log file exceeds $max_log_size bytes. Truncating..."
            : > "$log_file"
        fi
    fi
}

get_machine_name() {
    scutil --get ComputerName
}

generate_random_password() {
    local randomstring
    randomstring=$(openssl rand -base64 12)
    local upper digit lower specchar
    upper=$(LC_ALL=C tr -dc 'A-Z' < /dev/urandom | head -c 1)
    digit=$(LC_ALL=C tr -dc '0-9' < /dev/urandom | head -c 1)
    lower=$(LC_ALL=C tr -dc 'a-z' < /dev/urandom | head -c 1)
    specchar=$(LC_ALL=C tr -dc '%&$=+#!?' < /dev/urandom | head -c 1)
    echo "${randomstring}${upper}${digit}${lower}${specchar}"
}

get_access_token() {
    local response
    response=$(curl -s -X POST "https://login.microsoftonline.com/$tenant_id/oauth2/v2.0/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=$client_id&client_secret=$azure_api_secret&scope=https://vault.azure.net/.default")

    echo "$response" | grep -o '"access_token":"[^"]*' | grep -o '[^"]*$'
}

check_key_vault_connectivity() {
    # Check if we can list secrets. If this fails, the vault is not reachable or unauthorized.
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://$key_vault_name.vault.azure.net/secrets?api-version=7.4" \
        -H "Authorization: Bearer $access_token")
    [ "$status" -eq 200 ]
}

secret_exists() {
    local secret_name="$1"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X GET \
        "https://$key_vault_name.vault.azure.net/secrets/$secret_name?api-version=7.4" \
        -H "Authorization: Bearer $access_token")
    [[ "$status" == "200" ]]
}

delete_secret() {
    local secret_name="$1"
    curl -s -o /dev/null -w "%{http_code}" -X DELETE \
        "https://$key_vault_name.vault.azure.net/secrets/$secret_name?api-version=7.4" \
        -H "Authorization: Bearer $access_token"
}

purge_deleted_secret() {
    local secret_name="$1"
    curl -s -o /dev/null -w "%{http_code}" -X DELETE \
        "https://$key_vault_name.vault.azure.net/deletedsecrets/$secret_name?api-version=7.4" \
        -H "Authorization: Bearer $access_token"
}

update_or_create_secret() {
    local secret_name="$1"
    local secret_value="$2"
    curl -s -o /dev/null -w "%{http_code}" -X PUT \
        "https://$key_vault_name.vault.azure.net/secrets/$secret_name?api-version=7.4" \
        -H "Authorization: Bearer $access_token" \
        -H "Content-Type: application/json" \
        -d "{\"value\":\"$secret_value\"}"
}

create_admin_user() {
    local username="$1"
    local password="$2"

    if id "$username" &>/dev/null; then
        log_message "User $username already exists. Deleting..."
        sysadminctl -deleteUser "$username" >> "$log_file" 2>&1
    else
        log_message "User $username does not exist."
    fi

    log_message "Creating user $username..."
    sysadminctl -adminUser "$username" -adminPassword "$password" \
        -addUser "$username" -fullName "$username" -password "$password" -admin >> "$log_file" 2>&1
    log_message "User $username created."

    log_message "Hiding user $username..."
    defaults write /Library/Preferences/com.apple.loginwindow HiddenUsersList -array-add "$username" >> "$log_file" 2>&1
    log_message "User $username hidden."
}

#######################################
# Main Script
#######################################

mkdir -p "$log_folder" && chmod 755 "$log_folder"
rotate_logs_if_needed
log_message "===== Starting script LAPS ====="

machine_name=$(get_machine_name)
log_message "Machine name: $machine_name"

log_message "Requesting Azure access token..."
access_token=$(get_access_token)
if [ -z "$access_token" ]; then
    log_message "Failed to retrieve access token."
    exit 1
fi
log_message "Access token retrieved successfully."

log_message "Checking Key Vault connectivity..."
if ! check_key_vault_connectivity; then
    log_message "Key Vault connectivity check failed. Exiting without modifying local admin account."
    exit 1
fi
log_message "Key Vault connectivity OK."

password=$(generate_random_password)
create_admin_user "$adminaccountname" "$password"

log_message "Checking if secret '$machine_name' exists in Azure Key Vault..."
if secret_exists "$machine_name"; then
    log_message "Secret '$machine_name' exists. Deleting..."
    delete_result=$(delete_secret "$machine_name")
    if [[ "$delete_result" == "200" || "$delete_result" == "204" ]]; then
        log_message "Secret '$machine_name' deleted successfully. Waiting for 30 seconds..."
        sleep 30
        log_message "Purging secret '$machine_name'..."
        purge_result=$(purge_deleted_secret "$machine_name")
        if [ "$purge_result" == "204" ]; then
            log_message "Secret '$machine_name' purged successfully. Waiting for 30 seconds..."
            sleep 30
            log_message "Recreating the secret '$machine_name'..."
            create_result=$(update_or_create_secret "$machine_name" "$password")
            if [[ "$create_result" == "200" || "$create_result" == "201" ]]; then
                log_message "Secret '$machine_name' created successfully."
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
    log_message "Secret '$machine_name' does not exist. Creating..."
    create_result=$(update_or_create_secret "$machine_name" "$password")
    if [[ "$create_result" == "200" || "$create_result" == "201" ]]; then
        log_message "Secret '$machine_name' created successfully."
    else
        log_message "Failed to create secret. Response code: $create_result."
        exit 1
    fi
fi

log_message "Script completed successfully."
