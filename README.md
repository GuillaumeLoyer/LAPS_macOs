# LAPS_macOs
# macOS Local Admin Account Creation and Azure Key Vault Integration

## Description

This repository contains a script that automates the process of creating a local administrator account on macOS devices. The script generates a random password for the account and securely stores it in **Azure Key Vault**. The script is designed to be deployed via **Microsoft Intune** for enterprise environments.

## Features

- **Random Password Generation**: Creates a strong, randomized password for the new local administrator account.
- **macOS Local Admin Account**: Creates a local administrator account with the generated password.
- **Azure Key Vault Integration**: The password is securely stored in **Azure Key Vault** for safe retrieval.
- **Secret Management**: The script checks if the secret already exists in Azure, deletes it if necessary, and recreates it with the new password.
- **Logging**: Logs all actions performed during the script execution in a log file on the macOS device.

## Prerequisites

Before running the script, ensure the following:

- You have an **Azure Key Vault** instance set up with the correct permissions to create and manage secrets.
- You have the **Tenant ID**, **Client ID**, and **Client Secret** for Azure authentication.
- The following tools must be available on the macOS machine:
  - `openssl`
  - `curl`
  - `sysadminctl`
- The script is designed to be deployed via **Microsoft Intune**.

## Deployment via Microsoft Intune

To deploy the script to macOS devices using **Microsoft Intune**:

1. Create a **Shell Script** deployment in **Microsoft Intune**.
2. Upload the script to Intune.
3. Configure any necessary parameters (if needed).
4. Assign the deployment to the target macOS devices or device groups.

Once deployed, the script will automatically create a local administrator account on the macOS device and store its password in **Azure Key Vault**.

## Configuration

Before running or deploying the script, modify the following variables in the script:

- `adminaccountname`: The name of the administrator account to create (e.g., `adminuser`).
- `key_vault_name`: The name of your **Azure Key Vault** instance.
- `tenant_id`: Your **Azure Tenant ID**.
- `client_id`: Your **Azure Client ID**.
- `azure_api_secret`: Your **Azure Client Secret**.

## Logs

The script generates a log file located at `/var/log/intune_scripts/laps.log` on the macOS device. This file contains detailed information about the actions performed during the script execution, including:

- The creation of the administrator account.
- Interactions with **Azure Key Vault** (checking, deleting, and creating the secret).
