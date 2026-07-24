#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The chicken-and-egg step: Terraform's S3 backend needs the bucket to exist
# before `terraform init` can use it, so this one resource is created outside
# Terraform. It is run once, by a human, and never again.
#
# Keeping state local instead would break the moment CI also runs apply, which
# is the whole reason a remote backend exists.

set -euo pipefail

REGION="${AWS_REGION:-eu-central-1}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="${BUCKET:-sbomdrift-tfstate-${ACCOUNT_ID}}"

echo "Creating s3://${BUCKET} in ${REGION}"

if aws s3api head-bucket --bucket "${BUCKET}" 2>/dev/null; then
  echo "Bucket already exists — nothing to do."
else
  # Every region except us-east-1 requires an explicit LocationConstraint, and
  # omitting it fails with an error that does not mention the region at all.
  aws s3api create-bucket \
    --bucket "${BUCKET}" \
    --region "${REGION}" \
    --create-bucket-configuration "LocationConstraint=${REGION}"
fi

# Versioning is not optional for a state bucket: it is the only thing standing
# between a bad apply and an unrecoverable state file.
aws s3api put-bucket-versioning \
  --bucket "${BUCKET}" \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption \
  --bucket "${BUCKET}" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'

aws s3api put-public-access-block \
  --bucket "${BUCKET}" \
  --public-access-block-configuration \
  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'

echo
echo "Done. Set this in infra/versions.tf if it differs:"
echo "    bucket = \"${BUCKET}\""
