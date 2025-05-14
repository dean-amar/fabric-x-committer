# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
FROM registry.access.redhat.com/ubi9/ubi-micro:9.4 AS prod
ARG SERVICE_NAME
ARG PORTS
ARG TARGETOS
ARG TARGETARCH

WORKDIR /
COPY ./archbin/${TARGETOS}-${TARGETARCH}/${SERVICE_NAME} /app
EXPOSE ${PORTS}
CMD ["./app"]
