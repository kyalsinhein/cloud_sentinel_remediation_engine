#!/bin/bash
# VUL153 | Data Protection | AWS General | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS DynamoDB with no point-in-time recovery.

# Step 1: Enable versioning so data can be recovered after accidental change/delete
aws s3api put-bucket-versioning --bucket {{RESOURCE_NAME_VUL153}} \
  --versioning-configuration Status=Enabled

# Step 2: Add the resource to an AWS Backup plan
aws backup create-backup-plan --backup-plan file://backup-plan.json
aws backup create-backup-selection \
  --backup-plan-id {{BACKUP_PLAN_ID}} \
  --backup-selection file://backup-selection.json

# Step 3: Enable Macie to discover and classify sensitive data
aws macie2 enable-macie --status ENABLED --finding-publishing-frequency FIFTEEN_MINUTES