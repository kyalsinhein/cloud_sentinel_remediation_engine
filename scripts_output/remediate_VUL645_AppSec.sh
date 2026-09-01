#!/bin/bash
# VUL645 | Code Injection | GCP AppSec | Severity: CRITICAL | CVSS: 9.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# GCP Cloud Composer with misconfigured environment allowing code injection.

# Step 1: Create Cloud Armor security policy with OWASP rules
gcloud compute security-policies create {{POLICY_NAME}} \
  --description 'Blocks SQLi/XSS'
gcloud compute security-policies rules create 1000 \
  --security-policy {{POLICY_NAME}} \
  --expression "evaluatePreconfiguredExpr('sqli-stable')" --action deny-403

# Step 2: Restrict Cloud Function invoker to authenticated only
gcloud functions remove-iam-policy-binding {{FUNCTION_NAME}} \
  --member=allUsers --role=roles/cloudfunctions.invoker