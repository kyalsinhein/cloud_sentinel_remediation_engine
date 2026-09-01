#!/bin/bash
# VUL088 | Access Control | Azure IAM | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Databricks with public cluster access.

# Step 1: List current ACL entries on the container/filesystem path
az storage fs access show \
  --account-name {{STORAGE_ACCOUNT}} \
  -f {{FILESYSTEM_NAME}} -p {{PATH}}

# Step 2: Remove the wildcard/AnyUser ACL entry and grant the specific
# principal(s) that legitimately need access
az storage fs access set \
  --account-name {{STORAGE_ACCOUNT}} \
  -f {{FILESYSTEM_NAME}} -p {{PATH}} \
  --acl "user:{{PRINCIPAL_ID}}:r-x"

# Step 3: Disable anonymous/public blob access at the storage account level
az storage account update \
  --name {{STORAGE_ACCOUNT}} \
  --resource-group {{RG_NAME}} \
  --allow-blob-public-access false