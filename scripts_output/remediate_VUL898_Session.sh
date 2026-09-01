#!/bin/bash
# VUL898 | Session Management | Azure Session | Severity: MEDIUM | CVSS: 5.3
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# Azure App Service with misconfigured authentication allowing session hijacking.

# Step 1: Set a sign-in frequency conditional access control
az ad conditional-access policy create \
  --name EnforceSignInFrequency \
  --session-controls '{"signInFrequency":{"value":1,"type":"hours","isEnabled":true}}'

# Step 2: Revoke all active refresh tokens for the affected user
az ad user revoke-sign-in-sessions --id {{USER_ID}}