# SPDX-License-Identifier: Apache-2.0

output "region" {
  description = "Region every resource lives in."
  value       = var.region
}

output "admin_role_arn" {
  description = "MFA-gated human administration role. Assume this; do not use the user's own permissions."
  value       = aws_iam_role.admin.arn
}

output "assume_admin_policy_arn" {
  description = "Attach to the day-to-day IAM user, then remove that user from the admin group."
  value       = aws_iam_policy.assume_admin_only.arn
}

output "github_ci_role_arn" {
  description = "Set as the role-to-assume in the GitHub Actions AWS credentials step."
  value       = aws_iam_role.github_ci.arn
}

output "drift_database_uri" {
  description = "Where the drift history lives between ephemeral runners."
  value       = "s3://${var.state_bucket}/drift/history.db"
}

output "ecr_registry" {
  description = "Registry host for the evaluation fleet."
  value       = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.region}.amazonaws.com"
}

output "pull_through_prefix" {
  description = "Pull an upstream image via e.g. <registry>/docker-hub/library/python:3.11-slim"
  value       = try(aws_ecr_pull_through_cache_rule.dockerhub[0].ecr_repository_prefix, null)
}

output "inspector_enabled" {
  description = "Whether the paid referee is currently switched on."
  value       = var.enable_inspector
}
