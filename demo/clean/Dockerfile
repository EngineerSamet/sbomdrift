# SPDX-License-Identifier: Apache-2.0
# The "gate passes" half of the demo: a current, minimal base image.
FROM alpine:3.22

RUN adduser -D -u 10001 app
USER app
ENTRYPOINT ["/bin/sh", "-c", "echo sealed-build demo: clean"]
