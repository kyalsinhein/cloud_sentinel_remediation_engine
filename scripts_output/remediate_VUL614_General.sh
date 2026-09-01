#!/bin/bash
# VUL614 | Data Exposure | Azure General | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Cosmos DB with misconfigured partition key allowing data leakage.

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