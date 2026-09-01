#!/bin/bash
# VUL401 | Privilege Escalation | AWS Container | Severity: CRITICAL | CVSS: 9.4
# Review only: replace {{PLACEHOLDER}} values and test in non-production before running.
#
# AWS ECS with misconfigured task definition allowing container breakout.

# Step 1: Fetch the current (vulnerable) task definition
aws ecs describe-task-definition --task-definition {{RESOURCE_NAME_VUL401}} \
  --query 'taskDefinition' > current-task-def.json

# Step 2: Edit current-task-def.json - set containerDefinitions[].privileged
# to false and remove any host-path mountPoints/volumes that allow host
# filesystem access. This edit must be authored by the reviewer.

# Step 3: Register the corrected definition as a new revision
aws ecs register-task-definition --cli-input-json file://current-task-def.json

# Step 4: Update the service to use the new (non-privileged) revision
aws ecs update-service --cluster {{ECS_CLUSTER_NAME}} \
  --service {{ECS_SERVICE_NAME}} \
  --task-definition {{RESOURCE_NAME_VUL401}}:{{NEW_REVISION_NUMBER}}

# Step 5: Verify no running task uses the old privileged revision
aws ecs list-tasks --cluster {{ECS_CLUSTER_NAME}} --service-name {{ECS_SERVICE_NAME}} \
  --query 'taskArns' --output text | \
  xargs -I{} aws ecs describe-tasks --cluster {{ECS_CLUSTER_NAME}} --tasks {} \
  --query 'tasks[].taskDefinitionArn'