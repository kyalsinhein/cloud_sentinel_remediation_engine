#!/bin/bash
# VUL213 | Monitoring | AWS Logging | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS API Gateway with no logging enabled.

# Step 1: Enable multi-region CloudTrail with log file validation
aws cloudtrail create-trail --name {{TRAIL_NAME}} \
  --s3-bucket-name {{LOG_BUCKET}} --is-multi-region-trail \
  --enable-log-file-validation
aws cloudtrail start-logging --name {{TRAIL_NAME}}

# Step 2: Enable AWS Config to record configuration changes
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN={{CONFIG_ROLE_ARN}} \
  --recording-group allSupported=true,includeGlobalResourceTypes=true
aws configservice start-configuration-recorder --configuration-recorder-name default

# Step 3: Create a baseline CloudWatch alarm on unauthorized API calls
aws cloudwatch put-metric-alarm --alarm-name {{ALARM_NAME}} \
  --metric-name UnauthorizedAPICalls --namespace CloudTrailMetrics \
  --statistic Sum --period 300 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1