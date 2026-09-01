#!/bin/bash
# VUL892 | Access Control | Azure Network | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Kubernetes with misconfigured network policy allowing unauthorized access.

# Step 1: List all role assignments at subscription scope
az role assignment list --all --output table

# Step 2: Remove Owner/Contributor at subscription scope
az role assignment delete \
  --assignee {{SERVICE_PRINCIPAL_ID}} \
  --role Owner \
  --scope /subscriptions/{{SUBSCRIPTION_ID}}

# Step 3: Re-assign least-privilege role at resource group scope
az role assignment create \
  --assignee {{SERVICE_PRINCIPAL_ID}} \
  --role Reader \
  --scope /subscriptions/{{SUBSCRIPTION_ID}}/resourceGroups/{{RG_NAME}}

# Step 4: Enable Privileged Identity Management (PIM)
az rest --method POST \
  --url https://management.azure.com/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/{{REQUEST_ID}}?api-version=2020-10-01