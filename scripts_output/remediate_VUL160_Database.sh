#!/bin/bash
# VUL160 | Monitoring | Azure Database | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure SQL Database with no auditing.

# Step 1: Disable public network access
az sql server update --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL160}} \
  --enable-public-network false

# Step 2: Enforce Azure AD-only authentication (retire the SQL admin password)
az sql server ad-only-auth enable --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL160}}

# Step 3: Enable Transparent Data Encryption (on by default, verify)
az sql db tde show --resource-group {{RG_NAME}} --server {{RESOURCE_NAME_VUL160}} --database {{DB_NAME}}

# Step 4: Enable auditing to Log Analytics
az sql server audit-policy update --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL160}} \
  --state Enabled --log-analytics-target-state Enabled --log-analytics-workspace-resource-id {{LOG_ANALYTICS_WORKSPACE_ID}}