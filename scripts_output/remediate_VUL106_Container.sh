#!/bin/bash
# VUL106 | Access Control | Azure Container | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Kubernetes with no RBAC enabled.

# Step 1: Enable Entra ID integration and Azure RBAC on the cluster
az aks update --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL106}} \
  --enable-aad --aad-admin-group-object-ids {{AAD_ADMIN_GROUP_ID}} \
  --enable-azure-rbac

# Step 2: Disable local accounts (removes the --admin backdoor entirely)
az aks update --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL106}} \
  --disable-local-accounts

# Step 3: Rotate cluster certificates to revoke anything issued under the old local accounts
az aks rotate-certs --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL106}} --yes

# Step 4: Verify
az aks show --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL106}} --query "disableLocalAccounts"