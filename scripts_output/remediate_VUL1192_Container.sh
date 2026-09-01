#!/bin/bash
# VUL1192 | Privilege Escalation | Azure Container | Severity: CRITICAL | CVSS: 9.4
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure Kubernetes with misconfigured pod security policy allowing privilege escalation.

# Step 1: Enable the Azure Policy Add-on for AKS (if not already enabled)
az aks enable-addons --resource-group {{RG_NAME}} --name {{RESOURCE_NAME_VUL1192}} \
  --addons azure-policy

# Step 2: Look up the built-in initiative ID by name (never hardcode a policy
# GUID - verify it resolves before assigning) and assign it to the cluster.
# Use the 'restricted' initiative for the strictest baseline, or swap in
# 'Kubernetes cluster pod security baseline standards for Linux-based workloads'
# for a lighter starting point.
POLICY_SET_ID=$(az policy set-definition list \
  --query "[?displayName=='Kubernetes cluster pod security restricted standards for Linux-based workloads'].id" \
  -o tsv)
az policy assignment create \
  --name "aks-pod-security-restricted" \
  --policy-set-definition "$POLICY_SET_ID" \
  --scope /subscriptions/{{SUBSCRIPTION_ID}}/resourceGroups/{{RG_NAME}}/providers/Microsoft.ContainerService/managedClusters/{{RESOURCE_NAME_VUL1192}}

# Step 3 (alternative/complementary): enforce Pod Security Admission at the
# namespace level - built into Kubernetes, no add-on required
kubectl label namespace {{NAMESPACE}} \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest --overwrite

# Step 4: Audit and patch any existing privileged workload
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] | select(.spec.containers[]?.securityContext?.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"'
kubectl patch deployment {{WORKLOAD_NAME}} -n {{NAMESPACE}} --type=json -p \
  '[{"op":"replace","path":"/spec/template/spec/containers/0/securityContext/privileged","value":false}]'

# Step 5: Verify the policy assignment is compliant
az policy state list --resource {{RESOURCE_NAME_VUL1192}} --filter "policyAssignmentName eq 'aks-pod-security-restricted'"