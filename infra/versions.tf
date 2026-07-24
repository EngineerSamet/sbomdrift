# SPDX-License-Identifier: Apache-2.0

terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # State lives in S3 with native locking. The DynamoDB lock table that every
  # older tutorial reaches for has been deprecated since Terraform 1.11 and is
  # slated for removal: it would be one extra resource, one extra IAM surface
  # and one future breakage, in exchange for nothing that `use_lockfile` does
  # not already do.
  #
  # Chicken-and-egg: the bucket must exist before `terraform init` can use it as
  # a backend, so it is created once by bootstrap/create-state-bucket.sh rather
  # than by Terraform. Local state is not an option because CI also runs apply.
  backend "s3" {
    bucket       = "sbomdrift-tfstate-848122498488"
    key          = "tfstate/infra.tfstate"
    region       = "eu-central-1"
    encrypt      = true
    use_lockfile = true
  }
}
