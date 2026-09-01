#!/bin/bash
# VUL302 | IAM Misconfiguration | Azure IAM | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Managed Identity with excessive permissions leading to resource hijacking.

# Step 1: List current role assignments for the identity
az role assignment list --assignee {{PRINCIPAL_ID}} --all --output table

# Step 2: Remove the overly broad role assignment
az role assignment delete --assignee {{PRINCIPAL_ID}} \
  --role {{CURRENT_ROLE}} --scope {{SCOPE}}

# Step 3: Assign a least-privilege role scoped to the resource group
az role assignment create --assignee {{PRINCIPAL_ID}} \
  --role {{SCOPED_ROLE}} --scope /subscriptions/{{SUBSCRIPTION_ID}}/resourceGroups/{{RG_NAME}}