# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

FROM registry.access.redhat.com/ubi9/ubi-micro:9.4 AS prod
ARG BIN
ARG ARCHBIN_PATH
ARG PORTS
ARG TARGETOS
ARG TARGETARCH


COPY ${ARCHBIN_PATH}/${TARGETOS}-${TARGETARCH}/${BIN} /bin/${BIN}
EXPOSE ${PORTS}

COPY ./bin/sc-genesis-block.proto.bin /root/config/