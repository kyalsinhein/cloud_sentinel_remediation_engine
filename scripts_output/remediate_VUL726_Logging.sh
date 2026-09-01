#!/bin/bash
# VUL726 | Data Exposure | Azure Logging | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure API Management with misconfigured logging exposing sensitive data.

# Step 1: Disable public blob access
az storage account update \
  --name {{STORAGE_ACCOUNT}} \
  --resource-group {{RG_NAME}} \
  --allow-blob-public-access false

# Step 2: Enable storage encryption
az storage account update \
  --name {{STORAGE_ACCOUNT}} \
  --resource-group {{RG_NAME}} \
  --encryption-services blob file

# Step 3: Enable Defender for Storage
az security pricing create \
  --name StorageAccounts --tier Standard

# Step 4: Set up diagnostic logging
az monitor diagnostic-settings create \
  --name storage-audit \
  --resource {{STORAGE_ACCOUNT_ID}} \
  --logs '[{"category":"StorageRead","enabled":true},{"category":"StorageWrite","enabled":true}]'