#!/bin/bash
# VUL702 | Data Exfiltration | Azure Serverless | Severity: HIGH | CVSS: 7.1
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Function with misconfigured CORS policy allowing cross-origin data leakage.

# Step 1: Enable a system-assigned managed identity
az functionapp identity assign --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL702}}

# Step 2: Grant the identity access to the Key Vault secret
az keyvault set-policy --name {{KEYVAULT_NAME}} --object-id {{IDENTITY_OBJECT_ID}} --secret-permissions get

# Step 3: Replace the plaintext app setting with a Key Vault reference
az functionapp config appsettings set --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL702}} \
  --settings "{{SETTING_NAME}}=@Microsoft.KeyVault(SecretUri={{SECRET_URI}})"