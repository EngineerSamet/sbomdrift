# SPDX-License-Identifier: Apache-2.0
#
# Human identity, and the one place this project accepts a long-lived artefact.
#
# The anti-pattern (AWS SEC02-BP02) is an IAM user carrying an administrator
# access key: a static secret that, on its own, can do everything. The textbook
# answer is IAM Identity Center — and it is what I would use in a real
# organisation. It is not usable here: on a new Free-plan account, enabling it
# forces the creation of an AWS Organization, and AWS's own Free Tier terms
# expire the $200 credits immediately when an account joins one. Burning a
# twelve-month learning runway to avoid a $15 experiment is not a trade worth
# making, and an "account instance" of Identity Center cannot issue permission
# sets, so it solves nothing.
#
# What is left is to make the long-lived thing harmless. The access key is
# allowed to do exactly one thing — ask to become this role — and the role will
# not open without a second factor. So the key bears *identity*, not
# *authority*: leaked on its own it opens nothing, and every credential that
# actually grants access is short-lived.

data "aws_iam_policy_document" "admin_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }

    # Belt and braces: MultiFactorAuthPresent is absent (not false) for
    # federated principals, and an absent key makes a Bool condition fail open
    # in some policy shapes. Requiring the age of the MFA event to be bounded
    # forces the key to be genuinely present.
    condition {
      test     = "NumericLessThan"
      variable = "aws:MultiFactorAuthAge"
      values   = ["43200"] # 12 hours
    }
  }
}

resource "aws_iam_role" "admin" {
  name                 = "${var.project}-admin"
  description          = "Human administration role. Requires MFA; holds no credentials."
  assume_role_policy   = data.aws_iam_policy_document.admin_assume_role.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.admin.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
}

# The only permission the day-to-day user needs. Attaching this does *not* by
# itself reduce the user's power — the account's `admin` group still grants
# AdministratorAccess directly. Removing that group membership is the last step
# of the bootstrap, and deliberately manual: doing it before an MFA device is
# registered would lock the account out of itself.
resource "aws_iam_policy" "assume_admin_only" {
  name        = "${var.project}-assume-admin"
  description = "Permits assuming the MFA-gated admin role, and nothing else."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.admin.arn
    }]
  })
}
