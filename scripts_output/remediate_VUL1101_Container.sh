#!/bin/bash
# VUL1101 | Data Exposure | AWS Container | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS ECS with misconfigured container port exposing internal services.

# Step 1: Restrict (or disable) the public API server endpoint
aws eks update-cluster-config --name {{RESOURCE_NAME_VUL1101}} \
  --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs={{TRUSTED_CIDR}}

# Step 2: Enable IAM Roles for Service Accounts (replace broad node-role perms)
eksctl utils associate-iam-oidc-provider --cluster {{RESOURCE_NAME_VUL1101}} --approve

# Step 3: Enable control-plane audit logging to CloudWatch
aws eks update-cluster-config --name {{RESOURCE_NAME_VUL1101}} \
  --logging '{"clusterLogging":[{"types":["audit","authenticator"],"enabled":true}]}'

# Step 4: Rotate the cluster's service account tokens
kubectl delete secret -n kube-system -l kubernetes.io/service-account.name