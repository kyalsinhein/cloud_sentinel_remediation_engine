#!/bin/bash
# VUL007 | Access Control | AWS Compute | Severity: HIGH | CVSS: 8.8
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS EC2 instance with exposed SSH port and weak key.

# ── Step 1: Revoke unrestricted IPv4 SSH ─────────────────────────────────
aws ec2 revoke-security-group-ingress \
  --group-id {{RESOURCE_NAME_VUL007}} \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

# ── Step 2: Revoke unrestricted IPv6 SSH ─────────────────────────────────
aws ec2 revoke-security-group-ingress \
  --group-id {{RESOURCE_NAME_VUL007}} \
  --protocol tcp --port 22 --ipv6-cidr ::/0

# ── Step 3: Authorise access from trusted CIDR only ──────────────────────
aws ec2 authorize-security-group-ingress \
  --group-id {{RESOURCE_NAME_VUL007}} \
  --protocol tcp --port 22 \
  --cidr {{TRUSTED_IP}}/32

# ── Step 4: Verify final ruleset ─────────────────────────────────────────
aws ec2 describe-security-groups \
  --group-ids {{RESOURCE_NAME_VUL007}} \
  --query 'SecurityGroups[*].IpPermissions'