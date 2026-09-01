#!/bin/bash
# VUL581 | Denial of Service | GCP General | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Run with misconfigured memory allocation allowing resource exhaustion.

# Step 1: Add a rate-based ban rule to Cloud Armor policy
gcloud compute security-policies rules create 2000 \
  --security-policy {{POLICY_NAME}} \
  --action=rate-based-ban --rate-limit-threshold-count=100 \
  --rate-limit-threshold-interval-sec=60 --ban-duration-sec=600

# Step 2: Enable autoscaling on the Managed Instance Group
gcloud compute instance-groups managed set-autoscaling {{MIG_NAME}} \
  --zone={{ZONE}} --min-num-replicas=2 --max-num-replicas=10 \
  --target-cpu-utilization=0.7