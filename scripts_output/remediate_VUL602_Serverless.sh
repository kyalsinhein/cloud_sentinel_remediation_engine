#!/bin/bash
# VUL602 | Privilege Escalation | Azure Serverless | Severity: CRITICAL | CVSS: 9.4
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Function with misconfigured managed identity allowing privilege escalation.

# Step 1: Enable a system-assigned managed identity
az functionapp identity assign --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL602}}

# Step 2: Grant the identity access to the Key Vault secret
az keyvault set-policy --name {{KEYVAULT_NAME}} --object-id {{IDENTITY_OBJECT_ID}} --secret-permissions get

# Step 3: Replace the plaintext app setting with a Key Vault reference
az functionapp config appsettings set --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL602}} \
  --settings "{{SETTING_NAME}}=@Microsoft.KeyVault(SecretUri={{SECRET_URI}})"