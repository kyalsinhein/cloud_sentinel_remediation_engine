#!/bin/bash
# VUL502 | Data Exposure | Azure Storage | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Function with misconfigured blob trigger allowing data tampering.

# ── Step 1: Disable public blob access on storage account ────────────────
az storage account update \
  --name {{STORAGE_ACCOUNT}} \
  --resource-group {{RESOURCE_GROUP}} \
  --allow-blob-public-access false

# ── Step 2: Set container access level to private ────────────────────────
az storage container set-permission \
  --name {{RESOURCE_NAME_VUL502}} \
  --public-access off \
  --account-name {{STORAGE_ACCOUNT}}

# ── Step 3: Enable storage encryption services ───────────────────────────
az storage account update \
  --name {{STORAGE_ACCOUNT}} \
  --resource-group {{RESOURCE_GROUP}} \
  --encryption-services blob file

# ── Step 4: Enable diagnostic logging to Log Analytics ───────────────────
az monitor diagnostic-settings create \
  --name storage-diagnostics \
  --resource {{STORAGE_ACCOUNT_ID}} \
  --logs '[{"category":"StorageRead","enabled":true},{"category":"StorageWrite","enabled":true}]' \
  --workspace {{LOG_ANALYTICS_WORKSPACE_ID}}