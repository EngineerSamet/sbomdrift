# SPDX-License-Identifier: Apache-2.0
# The "gate blocks" half of the demo.
#
# python:3.11.0-slim was published in October 2022 on Debian bullseye. Nothing
# is wrong with it as a Dockerfile — it is simply old, which is the entire point:
# the vulnerabilities are real, published, and were introduced by the passage of
# time rather than by anything the author did. sbomdrift measures 160 findings
# against this image, six of them CRITICAL.
FROM python:3.11.0-slim

ENTRYPOINT ["python", "-c", "print('sealed-build demo: should never ship')"]
