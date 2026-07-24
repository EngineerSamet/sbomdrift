# SPDX-License-Identifier: Apache-2.0

provider "aws" {
  region = var.region

  # Every resource carries these. Cost allocation on an account this small is
  # not the point; being able to find and destroy everything this project
  # created, with certainty, is.
  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Repo      = var.github_repository
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}
