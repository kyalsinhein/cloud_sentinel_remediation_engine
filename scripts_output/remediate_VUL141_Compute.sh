#!/bin/bash
# VUL141 | Security Policy | AWS Compute | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS EC2 instance with no IMDSv2 enforcement.

# Step 1: Force IMDSv2 (blocks SSRF-based credential theft)
aws ec2 modify-instance-metadata-options --instance-id {{RESOURCE_NAME_VUL141}} \
  --http-tokens required --http-endpoint enabled

# Step 2: Rotate the instance's SSH key pair
aws ec2 create-key-pair --key-name {{NEW_KEY_NAME}} --query 'KeyMaterial' --output text

# Step 3: Reset OS-level password via SSM (no SSH key required)
aws ssm send-command --instance-ids {{RESOURCE_NAME_VUL141}} \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["passwd -e $(whoami)"]'

# Step 4: Detach the instance profile if it grants excess IAM permissions
aws ec2 describe-iam-instance-profile-associations --filters Name=instance-id,Values={{RESOURCE_NAME_VUL141}}

# Step 5: Restrict the attached security group to essential ports only
aws ec2 revoke-security-group-ingress --group-id {{SG_ID}} \
  --protocol tcp --port 22 --cidr 0.0.0.0/0