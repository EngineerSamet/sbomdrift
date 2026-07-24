# SPDX-License-Identifier: Apache-2.0
#
# GitHub Actions reaches AWS with no stored credential at all. The runner
# presents a signed OIDC token describing which repository, branch and workflow
# it is, AWS verifies that against this trust policy, and hands back STS
# credentials that expire in an hour.
#
# The alternative — an access key pair in repository secrets — is a permanent
# credential that exists whether or not a build is running, can be exfiltrated
# by any workflow or any compromised Action in the chain, and is exactly what
# the March 2026 supply-chain attack was harvesting.

data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]
}

data "aws_iam_policy_document" "github_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Scoped to one branch of one repository. `repo:owner/*` would be assumable
    # from any branch, and a branch can be created by anyone who can open a pull
    # request — which turns a federation role into a public one.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/${var.github_branch}"]
    }
  }
}

resource "aws_iam_role" "github_ci" {
  name                 = "${var.project}-github-ci"
  description          = "Assumed by GitHub Actions via OIDC. Holds no credentials of its own."
  assume_role_policy   = data.aws_iam_policy_document.github_assume_role.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "ci_permissions" {
  # The drift database, and only the drift database. The same bucket holds
  # Terraform state under tfstate/, and CI has no business reading — let alone
  # rewriting — the description of the infrastructure it runs on.
  statement {
    sid       = "DriftDatabaseObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["arn:${data.aws_partition.current.partition}:s3:::${var.state_bucket}/drift/*"]
  }

  statement {
    sid       = "ListOnlyTheDriftPrefix"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["arn:${data.aws_partition.current.partition}:s3:::${var.state_bucket}"]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["drift/*"]
    }
  }

  statement {
    sid    = "PullAndPushFleetImages"
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchCheckLayerAvailability",
      "ecr:DescribeImages",
      "ecr:ListImages",
      "ecr:PutImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
    ]
    resources = ["*"] # GetAuthorizationToken is account-wide by definition
  }
}

resource "aws_iam_role_policy" "github_ci" {
  name   = "${var.project}-ci"
  role   = aws_iam_role.github_ci.id
  policy = data.aws_iam_policy_document.ci_permissions.json
}
