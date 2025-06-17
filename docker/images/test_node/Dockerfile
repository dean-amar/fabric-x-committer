# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
FROM postgres:16.9-alpine3.21 AS node

ARG ARCHBIN_PATH
ARG TARGETOS
ARG TARGETARCH

ENV CONFIGS_PATH=/root/config
ENV BINS_PATH=/root/bin

# Set endpoints to be local.
ENV SC_COORDINATOR_VERIFIER_ENDPOINTS=localhost:5001
ENV SC_COORDINATOR_VALIDATOR_COMMITTER_ENDPOINTS=localhost:6001
ENV SC_SIDECAR_ORDERER_CONNECTION_ENDPOINTS=localhost:7050
ENV SC_SIDECAR_COMMITTER_ENDPOINT=localhost:9001
ENV SC_QUERY_DATABASE_ENDPOINTS=localhost:5433
ENV SC_VC_DATABASE_ENDPOINTS=localhost:5433

COPY ${ARCHBIN_PATH}/${TARGETOS}-${TARGETARCH}/committer ${BINS_PATH}/
COPY ${ARCHBIN_PATH}/${TARGETOS}-${TARGETARCH}/loadgen ${BINS_PATH}/
COPY ./cmd/config/samples $CONFIGS_PATH
COPY ./docker/images/test_node/scripts/. /root/
RUN chmod a+x /root/*.sh

EXPOSE 4001

CMD ["/root/run-services.sh"]
