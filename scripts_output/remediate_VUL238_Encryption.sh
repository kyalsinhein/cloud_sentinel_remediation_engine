#!/bin/bash
# VUL238 | Encryption | Azure Encryption | Severity: MEDIUM | CVSS: 6.0
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Synapse Analytics with no encryption.

# ── Step 1: Enable soft delete ───────────────────────────────────────────
az keyvault update \
  --name {{RESOURCE_NAME_VUL238}} \
  --resource-group {{RESOURCE_GROUP}} \
  --enable-soft-delete true

# ── Step 2: Enable purge protection ──────────────────────────────────────
az keyvault update \
  --name {{RESOURCE_NAME_VUL238}} \
  --resource-group {{RESOURCE_GROUP}} \
  --enable-purge-protection true

# ── Step 3: Enable audit logging ─────────────────────────────────────────
az monitor diagnostic-settings create \
  --name keyvault-audit \
  --resource $(az keyvault show --name {{RESOURCE_NAME_VUL238}} --query id -o tsv) \
  --logs '[{"category":"AuditEvent","enabled":true}]' \
  --workspace {{LOG_ANALYTICS_WORKSPACE_ID}}