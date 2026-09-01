#!/bin/bash
# VUL1097 | Denial of Service | AWS API | Severity: HIGH | CVSS: 8.7
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS API Gateway with misconfigured throttling policy allowing DoS attacks.

# Step 1: Require an authorizer (IAM or Cognito) on the API
aws apigateway update-method --rest-api-id {{RESOURCE_NAME_VUL1097}} --resource-id {{RESOURCE_ID}} \
  --http-method ANY --patch-operations op=replace,path=/authorizationType,value=CUSTOM

# Step 2: Associate a WAF web ACL
aws wafv2 associate-web-acl --web-acl-arn {{WEB_ACL_ARN}} --resource-arn {{RESOURCE_NAME_VUL1097}}

# Step 3: Enable access logging
aws apigateway update-stage --rest-api-id {{RESOURCE_NAME_VUL1097}} --stage-name {{STAGE}} \
  --patch-operations op=replace,path=/accessLogSettings/destinationArn,value={{LOG_GROUP_ARN}}