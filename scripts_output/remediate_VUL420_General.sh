#!/bin/bash
# VUL420 | Data Exposure | Azure General | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Virtual Machine with misconfigured diagnostics exposing sensitive data.

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