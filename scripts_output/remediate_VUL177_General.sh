#!/bin/bash
# VUL177 | Resource Control | AWS General | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS Fargate with no resource limits.

# Step 1: Tag the resource so it falls under governance/automation scope
aws resourcegroupstaggingapi tag-resources \
  --resource-arn-list {{RESOURCE_ARN}} \
  --tags Environment={{ENV}},Owner={{OWNER}}

# Step 2: Enforce a tagging policy via SCP so untagged resources cannot be created
aws organizations create-policy --name {{TAG_POLICY_NAME}} \
  --type TAG_POLICY --content file://{{TAG_POLICY_FILE}}

# Step 3: Review current service quota headroom for the resource type
aws service-quotas list-service-quotas --service-code {{SERVICE_CODE}}