#!/bin/bash
# VUL268 | Monitoring | Azure Logging | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Cognitive Services with no logging.

# Step 1: Create a Log Analytics workspace (if one is not already in place)
az monitor log-analytics workspace create \
  --resource-group {{RG_NAME}} --workspace-name {{WORKSPACE_NAME}}

# Step 2: Route diagnostic logs from the resource to the workspace
az monitor diagnostic-settings create --name {{DIAG_SETTING_NAME}} \
  --resource {{RESOURCE_NAME_VUL268}} \
  --workspace {{WORKSPACE_NAME}} \
  --logs '[{"category": "Administrative", "enabled": true}]'

# Step 3: Create an activity-log alert for high-severity administrative changes
az monitor activity-log alert create --name {{ALERT_NAME}} \
  --resource-group {{RG_NAME}} \
  --condition category=Administrative and level=Critical