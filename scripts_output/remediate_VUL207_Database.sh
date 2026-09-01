#!/bin/bash
# VUL207 | Data Protection | AWS Database | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS RDS with no deletion protection.

# Step 1: Disable public accessibility
aws rds modify-db-instance --db-instance-identifier {{RESOURCE_NAME_VUL207}} \
  --no-publicly-accessible --apply-immediately

# Step 2: Rotate the master credential via Secrets Manager
aws secretsmanager rotate-secret --secret-id rds/{{RESOURCE_NAME_VUL207}}/credentials

# Step 3: Enable deletion protection
aws rds modify-db-instance --db-instance-identifier {{RESOURCE_NAME_VUL207}} \
  --deletion-protection --apply-immediately

# Step 4: Verify encryption at rest is on
aws rds describe-db-instances --db-instance-identifier {{RESOURCE_NAME_VUL207}} \
  --query 'DBInstances[0].StorageEncrypted'