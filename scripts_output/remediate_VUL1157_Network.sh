#!/bin/bash
# VUL1157 | Network Security | GCP Network | Severity: MEDIUM | CVSS: 6.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud VPN with misconfigured routing policy allowing traffic interception.

# Step 1: List firewall rules allowing 0.0.0.0/0 ingress
gcloud compute firewall-rules list \
  --filter="sourceRanges:('0.0.0.0/0')" --format table

# Step 2: Update the rule to a trusted CIDR only
gcloud compute firewall-rules update {{RULE_NAME}} \
  --source-ranges={{TRUSTED_CIDR}}/32

# Step 3: Enable VPC Flow Logs on the subnet
gcloud compute networks subnets update {{SUBNET_NAME}} \
  --region={{REGION}} --enable-flow-logs

# Step 4: Verify final firewall ruleset
gcloud compute firewall-rules describe {{RULE_NAME}}