#!/bin/bash
# VUL1198 | Data Exposure | Azure Secrets | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure App Service with misconfigured environment variables exposing secrets.

# Step 1: Set a new secret value
az keyvault secret set --vault-name {{KEYVAULT_NAME}} --name {{RESOURCE_NAME_VUL1198}} --value {{NEW_SECRET_VALUE}}

# Step 2: Set an expiry so it can't silently live forever
az keyvault secret set-attributes --vault-name {{KEYVAULT_NAME}} --name {{RESOURCE_NAME_VUL1198}} \
  --expires {{EXPIRY_DATE}}

# Step 3: Restrict the access policy to only the identities that need it
az keyvault delete-policy --name {{KEYVAULT_NAME}} --object-id {{OVERBROAD_OBJECT_ID}}