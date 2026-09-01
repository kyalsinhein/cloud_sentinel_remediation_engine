#!/bin/bash
# VUL925 | Privilege Escalation | AWS IAM | Severity: CRITICAL | CVSS: 9.4
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS EKS with misconfigured pod security policy allowing privilege escalation.

# Step 1: Enforce Pod Security Standards at the namespace level (built into
# Kubernetes 1.23+, no add-on required) - blocks new privileged pods
kubectl label namespace {{NAMESPACE}} \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest --overwrite

# Step 2: Audit existing workloads for privileged containers
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] | select(.spec.containers[]?.securityContext?.privileged==true or .spec.hostPID==true or .spec.hostNetwork==true) | "\(.metadata.namespace)/\(.metadata.name)"'

# Step 3: Patch a flagged workload's securityContext to remove privileged mode
kubectl patch deployment {{WORKLOAD_NAME}} -n {{NAMESPACE}} --type=json -p \
  '[{"op":"replace","path":"/spec/template/spec/containers/0/securityContext/privileged","value":false}]'

# Step 4: Verify no privileged pods remain
kubectl get pods --all-namespaces -o json | \
  jq '[.items[] | select(.spec.containers[]?.securityContext?.privileged==true)] | length'