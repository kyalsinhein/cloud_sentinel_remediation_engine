#!/bin/bash
# VUL761 | Denial of Service | AWS General | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS CodeBuild with misconfigured build timeout allowing resource exhaustion.

# Step 1: Enable AWS Shield Standard (free, automatic)
aws shield describe-subscription

# Step 2: Create WAF rate-based rule
aws wafv2 create-web-acl \
  --name RateLimitACL \
  --scope REGIONAL \
  --default-action Allow={} \
  --rules file://rate-limit-rules.json \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=RateLimitACL

# Step 3: Configure Auto Scaling with scale-in protection
aws autoscaling put-scaling-policy \
  --auto-scaling-group-name {{ASG_NAME}} \
  --policy-name ScaleOutPolicy \
  --policy-type TargetTrackingScaling \
  --target-tracking-configuration file://target-tracking.json

# Step 4: Enable CloudFront with DDoS protection
aws cloudfront create-distribution \
  --distribution-config file://cloudfront-config.json