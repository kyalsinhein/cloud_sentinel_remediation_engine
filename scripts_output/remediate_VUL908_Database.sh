#!/bin/bash
# VUL908 | Encryption | Azure Database | Severity: MEDIUM | CVSS: 6.0
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure SQL Database with misconfigured TDE exposing data.

# Step 1: Disable public network access
az sql server update --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL908}} \
  --enable-public-network false

# Step 2: Enforce Azure AD-only authentication (retire the SQL admin password)
az sql server ad-only-auth enable --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL908}}

# Step 3: Enable Transparent Data Encryption (on by default, verify)
az sql db tde show --resource-group {{RG_NAME}} --server {{RESOURCE_NAME_VUL908}} --database {{DB_NAME}}

# Step 4: Enable auditing to Log Analytics
az sql server audit-policy update --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL908}} \
  --state Enabled --log-analytics-target-state Enabled --log-analytics-workspace-resource-id {{LOG_ANALYTICS_WORKSPACE_ID}}