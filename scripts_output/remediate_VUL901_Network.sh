#!/bin/bash
# VUL901 | Network Security | AWS Network | Severity: MEDIUM | CVSS: 6.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS ECS with misconfigured network mode allowing container-to-host communication.

# Step 1: List all security groups with 0.0.0.0/0 ingress
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query SecurityGroups[*].[GroupId,GroupName] --output table

# Step 2: Revoke unrestricted inbound rules
aws ec2 revoke-security-group-ingress \
  --group-id {{SG_ID}} \
  --protocol tcp --port {{PORT}} --cidr 0.0.0.0/0

# Step 3: Add restricted ingress from trusted CIDR only
aws ec2 authorize-security-group-ingress \
  --group-id {{SG_ID}} \
  --protocol tcp --port {{PORT}} \
  --cidr {{TRUSTED_CIDR}}/32

# Step 4: Enable VPC Flow Logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids {{VPC_ID}} \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name VPCFlowLogs