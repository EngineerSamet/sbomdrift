# SPDX-License-Identifier: Apache-2.0

variable "region" {
  description = <<-EOT
    AWS region for every resource.

    eu-central-1 (Frankfurt). The architecture document originally locked
    us-east-1 on the grounds that "the account already defaults there" — which
    turned out to be false: the account's configured region is eu-central-1 and
    its only existing bucket is in eu-north-1. Since the stated reason did not
    hold, the choice was re-made rather than inherited. Frankfurt is also the
    nearest region to the operator, and ECR, Inspector and OIDC federation are
    all available there.
  EOT
  type        = string
  default     = "eu-central-1"
}

variable "project" {
  description = "Name prefix and cost-allocation tag applied to every resource."
  type        = string
  default     = "sbomdrift"
}

variable "state_bucket" {
  description = <<-EOT
    Bucket holding both Terraform state and the drift database.

    One bucket, two prefixes, deliberately: the CI role is scoped to `drift/*`
    and must not be able to touch `tfstate/*`. Sharing the bucket keeps the
    footprint small; scoping the prefix keeps the blast radius small.
  EOT
  type        = string
  default     = "sbomdrift-tfstate-848122498488"
}

variable "github_repository" {
  description = "owner/repo allowed to assume the CI role via OIDC."
  type        = string
  default     = "EngineerSamet/sbomdrift"
}

variable "github_branch" {
  description = "Branch the CI role is restricted to. A role assumable from any branch is assumable from any fork's pull request."
  type        = string
  default     = "main"
}

variable "upstream_images" {
  description = <<-EOT
    Images pulled through the ECR cache to form the evaluation fleet.

    Kept small on purpose: ECR bills per unique compressed layer, and images
    sharing a base cost almost nothing extra, but there is no reason to pay for
    breadth the evaluation does not use.
  EOT
  type        = list(string)
  default = [
    "python:3.11-slim",
    "python:3.12-slim",
    "node:22-slim",
    "nginx:stable",
    "postgres:17-alpine",
    "redis:8-alpine",
    "alpine:3.22",
    "debian:13-slim",
  ]
}

variable "enable_pull_through_cache" {
  description = <<-EOT
    Mirror upstream images into ECR automatically.

    Off by default because ECR's Docker Hub cache requires a stored Docker Hub
    access token — the one long-lived credential this project cannot replace
    with OIDC, since Docker Hub offers no federation. Seeding the fleet by
    pushing images directly needs no stored credential, so the default path is
    the one with no secret in it.
  EOT
  type        = bool
  default     = false
}

variable "dockerhub_username" {
  description = "Docker Hub user, used only when the pull-through cache is enabled."
  type        = string
  default     = ""
}

variable "dockerhub_token" {
  description = "Docker Hub read-only access token, used only when the pull-through cache is enabled."
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_inspector" {
  description = <<-EOT
    Turn on Inspector enhanced scanning for ECR.

    Defaults to false because this is the only line item in the stack that costs
    real money (~$0.09 per initial scan, ~$0.01 per re-scan). It is switched on
    for the oracle-agreement measurement and switched off again afterwards, so
    the cost is bounded by the length of the experiment rather than by how long
    the infrastructure happens to exist.
  EOT
  type        = bool
  default     = false
}

variable "monthly_budget_usd" {
  description = "Budget alarm threshold. Small on purpose: the alarm should fire long before the credits do."
  type        = number
  default     = 20
}

variable "budget_notification_email" {
  description = "Where budget alarms go."
  type        = string
  default     = "sezersanlikan@gmail.com"
}
