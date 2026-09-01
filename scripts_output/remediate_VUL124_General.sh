#!/bin/bash
# VUL124 | Data Protection | Azure General | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Key Vault with no purge protection.

# Step 1: Enable soft delete and blob versioning on the storage account
az storage account blob-service-properties update \
  --account-name {{STORAGE_ACCOUNT}} --resource-group {{RG_NAME}} \
  --enable-delete-retention true --delete-retention-days 30 \
  --enable-versioning true

# Step 2: Add the resource to an Azure Backup vault policy
az backup protection enable-for-azurewl \
  --resource-group {{RG_NAME}} --vault-name {{VAULT_NAME}} \
  --policy-name {{POLICY_NAME}} --protectable-item-name {{RESOURCE_NAME_VUL124}}

# Step 3: Register the subscription with Microsoft Purview for data classification
az purview account create --resource-group {{RG_NAME}} --name {{PURVIEW_ACCOUNT}}