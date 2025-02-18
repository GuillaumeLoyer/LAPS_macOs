#!/usr/bin/env bash
set -eu -o pipefail

#######################################
# Configuration Variables
#######################################
adminaccountname="<admin_user_name>"
log_folder="/var/log/intune_scripts"
log_file="$log_folder/laps.log"
max_log_size=51200  # 50 KB

# Azure AD App (Client Credentials)
tenant_id="<your_tenant_id>"
client_id="<your_client_id>"
client_secret="<your_client_secret>"

# Azure Storage
storage_account_name="<storageaccount>"
table_name="<table>"

#######################################
# Helper Functions
#######################################

log_message() {
    local msg="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $msg" | tee -a "$log_file" >&2
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

get_storage_token() {
    log_message "Requesting Azure Storage access token using client credentials..."
    local response
    response=$(curl -s -X POST \
        "https://login.microsoftonline.com/$tenant_id/oauth2/v2.0/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=$client_id" \
        -d "client_secret=$client_secret" \
        -d "grant_type=client_credentials" \
        -d "scope=https://storage.azure.com/.default")

    local access_token
    access_token=$(echo "$response" | jq -r '.access_token')

    if [ -z "$access_token" ]; then
        log_message "Failed to retrieve access token from AAD. Full response: $response"
        exit 1
    fi
    log_message "Access token retrieved successfully."
    echo "$access_token"
}

create_or_update_admin_user() {
    local username="$1"
    local password="$2"

    if id "$username" &>/dev/null; then
        log_message "User $username already exists. Rotating password..."
        dscl . -passwd "/Users/$username" "$password" >> "$log_file" 2>&1
        log_message "Password for user $username updated successfully."
    else
        log_message "User $username does not exist. Creating..."
        sysadminctl \
            -addUser "$username" \
            -fullName "$username" \
            -password "$password" \
            -admin >> "$log_file" 2>&1
        log_message "User $username created successfully."

        log_message "Hiding user $username..."
        defaults write /Library/Preferences/com.apple.loginwindow HiddenUsersList -array-add "$username" >> "$log_file" 2>&1
        log_message "User $username hidden."
    fi
}

############################################
# Table Storage REST Calls
############################################

store_password_in_table() {
    local machine_name="$1"
    local password="$2"
    local access_token="$3"

    local partition="macOS"
    local rowkey="$machine_name"

    log_message "Storing password in Azure Table: $table_name (Storage Account: $storage_account_name)"

    # Sanitize PartitionKey and RowKey by removing newline and control characters
    partition=$(echo -n "$partition" | tr -d '\n\r')
    rowkey=$(echo -n "$rowkey" | tr -d '\n\r')

    # URL-encode PartitionKey and RowKey
    local encoded_partition
    local encoded_rowkey
    encoded_partition=$(echo -n "$partition" | jq -sRr @uri)
    encoded_rowkey=$(echo -n "$rowkey" | jq -sRr @uri)

    local entity_url="https://${storage_account_name}.table.core.windows.net/$table_name(PartitionKey='$encoded_partition',RowKey='$encoded_rowkey')"

    local body
    body=$(cat <<EOF
{
  "PartitionKey": "$partition",
  "RowKey": "$rowkey",
  "Password": "$password"
}
EOF
)

    local response
    response=$(curl -s -w "\nHTTP_CODE=%{http_code}" -X MERGE \
        -H "Authorization: Bearer $access_token" \
        -H "Accept: application/json;odata=nometadata" \
        -H "Content-Type: application/json" \
        -H "If-Match: *" \
        -H "x-ms-version: 2025-01-05" \
        -H "x-ms-date: $(date -u +"%a, %d %b %Y %H:%M:%S GMT")" \
        -d "$body" \
        "$entity_url")

    local http_code
    http_code=$(echo "$response" | sed -n 's/^HTTP_CODE=//p')
    local response_body
    response_body=$(echo "$response" | sed '/^HTTP_CODE=/d')

    if [[ "$http_code" == "204" ]]; then
        log_message "Entity merged successfully (HTTP 204)."
    elif [[ "$http_code" == "404" ]]; then
        log_message "Entity not found. Performing an INSERT..."
        insert_entity "$access_token" "$partition" "$rowkey" "$password"
    else
        log_message "ERROR: MERGE failed with code $http_code. Response: $response_body"
        exit 1
    fi
}

insert_entity() {
    local access_token="$1"
    local partition="$2"
    local rowkey="$3"
    local password="$4"

    local table_url="https://${storage_account_name}.table.core.windows.net/$table_name"

    local body
    body=$(cat <<EOF
{
  "PartitionKey": "$partition",
  "RowKey": "$rowkey",
  "Password": "$password"
}
EOF
)

    local response
    response=$(curl -s -w "\nHTTP_CODE=%{http_code}" -X POST \
        -H "Authorization: Bearer $access_token" \
        -H "Accept: application/json;odata=nometadata" \
        -H "Content-Type: application/json" \
        -H "x-ms-version: 2025-01-05" \
        -d "$body" \
        "$table_url")

    local http_code
    http_code=$(echo "$response" | sed -n 's/^HTTP_CODE=//p')
    local response_body
    response_body=$(echo "$response" | sed '/^HTTP_CODE=/d')

    if [[ "$http_code" == "201" ]]; then
        log_message "Entity inserted successfully (HTTP 201)."
    else
        log_message "ERROR: INSERT failed with code $http_code. Response: $response_body"
        exit 1
    fi
}

#######################################
# Main Script
#######################################

mkdir -p "$log_folder" && chmod 755 "$log_folder"
rotate_logs_if_needed
log_message "===== Starting script LAPS (Azure Table version) ====="
storage_token=$(get_storage_token)
machine_name=$(get_machine_name)
log_message "Machine name: $machine_name"
password=$(generate_random_password)
create_or_update_admin_user "$adminaccountname" "$password"
store_password_in_table "$machine_name" "$password" "$storage_token"
log_message "===== Script completed successfully. ====="