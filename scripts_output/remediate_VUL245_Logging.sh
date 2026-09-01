#!/bin/bash
# VUL245 | Monitoring | GCP Logging | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud DNS with no logging enabled.

# Step 1: Create a logging sink that exports audit logs for retention
gcloud logging sinks create {{SINK_NAME}} \
  storage.googleapis.com/{{LOG_BUCKET}} \
  --project={{PROJECT_ID}} \
  --log-filter='logName:"cloudaudit.googleapis.com"'

# Step 2: Enable Data Access audit logs for the project
gcloud projects get-iam-policy {{PROJECT_ID}} --format=json > /tmp/policy.json
# Edit /tmp/policy.json to add an auditConfigs block enabling DATA_READ/DATA_WRITE, then:
gcloud projects set-iam-policy {{PROJECT_ID}} /tmp/policy.json

# Step 3: Create a baseline alerting policy for IAM policy changes
gcloud alpha monitoring policies create \
  --notification-channels={{CHANNEL_ID}} \
  --display-name='IAM Policy Change Alert' \
  --condition-display-name='IAM change detected'