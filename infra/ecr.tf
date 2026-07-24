# SPDX-License-Identifier: Apache-2.0
#
# The evaluation fleet. Images are not built here — they are pulled through a
# cache from Docker Hub, so the fleet is real upstream software with real
# vulnerability histories rather than a set of toy images whose contents were
# chosen to make the tool look good.

# Docker Hub requires authentication for pull-through caching, and ECR insists
# the credential live in Secrets Manager under this exact name prefix. That
# token is the one long-lived credential this project cannot design away: it
# belongs to Docker Hub, where no OIDC path exists. Rather than leave it to be
# discovered, it is named here — and the whole cache is opt-in, so a default
# `terraform apply` does not create a secret with nothing in it.
#
# Without the cache, the fleet is seeded by pushing images directly, which needs
# no stored credential at all.
resource "aws_secretsmanager_secret" "dockerhub" {
  count = var.enable_pull_through_cache ? 1 : 0
  name  = "ecr-pullthroughcache/${var.project}-dockerhub"
}

resource "aws_secretsmanager_secret_version" "dockerhub" {
  count     = var.enable_pull_through_cache ? 1 : 0
  secret_id = aws_secretsmanager_secret.dockerhub[0].id
  secret_string = jsonencode({
    username    = var.dockerhub_username
    accessToken = var.dockerhub_token
  })
}

resource "aws_ecr_pull_through_cache_rule" "dockerhub" {
  count                 = var.enable_pull_through_cache ? 1 : 0
  ecr_repository_prefix = "docker-hub"
  upstream_registry_url = "registry-1.docker.io"
  credential_arn        = aws_secretsmanager_secret.dockerhub[0].arn
}

resource "aws_ecr_repository" "fleet" {
  for_each = toset([for image in var.upstream_images : replace(split(":", image)[0], "/", "-")])

  name                 = "${var.project}/${each.value}"
  image_tag_mutability = "IMMUTABLE"

  # Immutable tags matter more here than anywhere else in this project: the
  # whole point of version drift is that "the same tag" pointed at different
  # content on two different days. If our own registry allowed that, the
  # evaluation could not distinguish a rebuild from a re-tag.

  image_scanning_configuration {
    scan_on_push = false # Inspector handles scanning when enabled; see inspector.tf
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "expire_untagged" {
  for_each   = aws_ecr_repository.fleet
  repository = each.value.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 7 days — layers left by an interrupted push are pure cost."
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep at most 10 images per repository."
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = { type = "expire" }
      }
    ]
  })
}
