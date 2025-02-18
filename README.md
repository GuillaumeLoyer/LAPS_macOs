# Azure LAPS Management with macOS & Windows Integration  

This repository contains two scripts to manage Local Administrator Password Solution (LAPS) using **Azure Storage Tables** for macOS and Windows devices.  

## **Overview**  

- **Bash Script** (`laps_mac.sh`):  
  - Manages local administrator accounts on **macOS devices**.  
  - Generates **random passwords** for the admin account.  
  - Stores credentials securely in an **Azure Storage Table**.  

- **Python Script** (`laps_windows.py`):  
  - Provides a **GUI application** for securely retrieving stored credentials.  
  - Authenticates via **Azure AD**.  
  - Supports **macOS and Windows** for password retrieval.  
  - Retrieves secrets from **Azure Key Vault** or **Intune Graph API**.  

## **License**  

This project is licensed under the MIT License.
