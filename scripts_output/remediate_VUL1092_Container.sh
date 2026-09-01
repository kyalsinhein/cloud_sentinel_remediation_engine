#!/bin/bash
# VUL1092 | Privilege Escalation | Azure Container | Severity: CRITICAL | CVSS: 9.4
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Kubernetes with misconfigured RBAC policy allowing privilege escalation.

# Step 1: Enable Entra ID integration and Azure RBAC on the cluster
az aks update --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL1092}} \
  --enable-aad --aad-admin-group-object-ids {{AAD_ADMIN_GROUP_ID}} \
  --enable-azure-rbac

# Step 2: Disable local accounts (removes the --admin backdoor entirely)
az aks update --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL1092}} \
  --disable-local-accounts

# Step 3: Rotate cluster certificates to revoke anything issued under the old local accounts
az aks rotate-certs --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL1092}} --yes

# Step 4: Verify
az aks show --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL1092}} --query "disableLocalAccounts"