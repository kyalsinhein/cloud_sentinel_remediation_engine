#!/bin/bash
# VUL038 | Patch Management | AWS General | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS Elastic Beanstalk with outdated runtime.

# Step 1: Associate the instance with a patch baseline via State Manager
aws ssm create-association --name AWS-RunPatchBaseline \
  --targets Key=instanceids,Values={{INSTANCE_ID}} \
  --schedule-expression 'rate(7 days)'

# Step 2: Run an on-demand patch scan
aws ssm send-command --document-name AWS-RunPatchBaseline \
  --targets Key=instanceids,Values={{INSTANCE_ID}} \
  --parameters Operation=Scan

# Step 3: Install missing patches
aws ssm send-command --document-name AWS-RunPatchBaseline \
  --targets Key=instanceids,Values={{INSTANCE_ID}} \
  --parameters Operation=Install