#!/bin/bash
# VUL451 | Injection | GCP AppSec | Severity: LOW | CVSS: 2.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Armor with misconfigured XSS protection allowing script injection.

# Step 1: Create a Cloud Armor security policy
gcloud compute security-policies create {{POLICY_NAME}} \
  --description='Blocks SQLi/XSS/command injection patterns'

# Step 2: Add the preconfigured SQLi and XSS rules
gcloud compute security-policies rules create 1000 \
  --security-policy={{POLICY_NAME}} \
  --expression="evaluatePreconfiguredExpr('sqli-stable')" --action=deny-403
gcloud compute security-policies rules create 1001 \
  --security-policy={{POLICY_NAME}} \
  --expression="evaluatePreconfiguredExpr('xss-stable')" --action=deny-403

# Step 3: Attach the policy to the backend service
gcloud compute backend-services update {{BACKEND_SERVICE}} \
  --security-policy={{POLICY_NAME}}