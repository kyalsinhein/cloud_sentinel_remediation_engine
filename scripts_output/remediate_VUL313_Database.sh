#!/bin/bash
# VUL313 | Injection | AWS Database | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS API Gateway with misconfigured request validation allowing SQL injection.

# Step 1: Disable public accessibility
aws rds modify-db-instance --db-instance-identifier {{RESOURCE_NAME_VUL313}} \
  --no-publicly-accessible --apply-immediately

# Step 2: Rotate the master credential via Secrets Manager
aws secretsmanager rotate-secret --secret-id rds/{{RESOURCE_NAME_VUL313}}/credentials

# Step 3: Enable deletion protection
aws rds modify-db-instance --db-instance-identifier {{RESOURCE_NAME_VUL313}} \
  --deletion-protection --apply-immediately

# Step 4: Verify encryption at rest is on
aws rds describe-db-instances --db-instance-identifier {{RESOURCE_NAME_VUL313}} \
  --query 'DBInstances[0].StorageEncrypted'