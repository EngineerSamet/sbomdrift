# SPDX-License-Identifier: Apache-2.0
#
# AWS Inspector is not a supporting service here — it is the referee.
#
# Inspector already does continuous re-scanning of ECR images as new CVEs are
# published, which makes it the nearest competitor to sbomdrift, not a
# complement to it. Rather than avoid the comparison, the evaluation measures it:
# both oracles are pointed at the same fleet and their findings are compared.
#
# The honest scope of that comparison is *oracle agreement* — do OSV.dev and
# Inspector flag the same components? — and not a live drift comparison, which
# would require two evaluation points with real CVE movement in between.
#
# Off by default; see the reasoning on var.enable_inspector.

resource "aws_inspector2_enabler" "ecr" {
  count = var.enable_inspector ? 1 : 0

  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECR"]
}
