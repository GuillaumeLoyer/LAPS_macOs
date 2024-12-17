
# macOS Local Admin Account Creation and Azure Key Vault Integration

## Description

This repository contains two scripts:

1. **Bash Script**: Runs on macOS devices (deployed via **Microsoft Intune**) to automate the creation of a local administrator account. The generated password is securely stored in **Azure Key Vault**.
2. **PowerShell Script**: Runs on Azure via an **Automation Runbook** to manage and purge deleted secrets from the **Azure Key Vault**.

## Features

### Bash Script (macOS)
- **Random Password Generation**: Automatically generates a secure password for the new local administrator account.
- **Local Admin Account Creation**: Creates a local administrator account on the macOS device.
- **Azure Key Vault Integration**: Securely stores the generated password in **Azure Key Vault**.
- **Secret Management**: Deletes existing secrets in the Key Vault (if necessary) before creating new ones.
- **Logging**: Logs script actions for troubleshooting and auditing.

### PowerShell Script (Azure Runbook)
- **Azure Key Vault Purging**: Purges deleted secrets to maintain a clean and secure **Azure Key Vault** instance.
- **Automation Ready**: Designed to be run periodically as an **Azure Automation Runbook**.

## Prerequisites

### For the Bash Script (macOS):
Ensure the following tools and configurations are in place:
- An **Azure Key Vault** instance with permissions to manage secrets.
- **Tenant ID**, **Client ID**, and **Client Secret** for Azure authentication.
- **Microsoft Intune** setup for deploying scripts to target devices.

### For the PowerShell Script (Azure):
- An **Azure Key Vault** instance configured with appropriate permissions.
- An **Azure Automation Account** to host and schedule the script as a Runbook.

## Deployment Instructions

### Bash Script Deployment via Microsoft Intune

1. Log in to **Microsoft Endpoint Manager Admin Center**.
2. Navigate to **Devices > macOS > Shell Scripts**.
3. Create a new Shell Script deployment.
4. Upload the provided Bash script.
5. Configure any necessary parameters (e.g., script execution frequency, logging settings).
6. Assign the deployment to targeted macOS devices.

Once deployed, the script will:
- Create a local administrator account.
- Generate and securely store the account password in **Azure Key Vault**.

### PowerShell Script Deployment in Azure

1. Log in to the **Azure Portal**.
2. Navigate to your **Automation Account**.
3. Import the provided PowerShell script as a Runbook.
4. Schedule the Runbook to run periodically (e.g., daily or weekly).

The script will automatically purge deleted secrets in **Azure Key Vault** to maintain security.

## Configuration

Before deployment, update the following variables in the scripts:

### Bash Script (macOS):
- `adminaccountname`: Name of the admin account to be created (e.g., `adminuser`).
- `key_vault_name`: Name of the Azure Key Vault instance.
- `tenant_id`: Azure Tenant ID.
- `client_id`: Azure Client ID.
- `azure_api_secret`: Azure Client Secret.

### PowerShell Script (Azure):
- `keyVaultName`: Name of the Azure Key Vault instance.

## Logs

### Bash Script Logs (macOS):
Logs are generated on the macOS device at:

```
/var/log/intune_scripts/laps.log
```

These logs include:
- Account creation details.
- Azure Key Vault operations (e.g., secret creation and management).

### PowerShell Script Logs (Azure):
Azure Automation Runbook execution logs can be viewed in the **Runbook Output** section of the Automation Account.

## Security Best Practices

- Rotate passwords periodically to enhance security.
- Use least-privilege access for Azure accounts interacting with Key Vault.
- Securely store **Client ID** and **Client Secret** using Azure Key Vault or secure environment variables.
- Regularly audit and monitor Azure Key Vault usage.

## Support

For any issues, contributions, or suggestions, open an issue or pull request in this repository.

---

### Files Included

- `macos_admin_creation.sh`: Bash script for macOS local admin creation and Key Vault integration.
- `purge_keyvault_secrets.ps1`: PowerShell script to purge deleted secrets in Azure Key Vault.

---

### License

This project is licensed under the MIT License. See `LICENSE` for details.
