#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

###########################################
# Stage 1: Production runtime image
###########################################
FROM postgres:18.3-alpine3.23 AS node

ARG SRC_BIN_PATH
ARG TARGETOS
ARG TARGETARCH
ARG VERSION

ENV CONFIGS_PATH=/root/config
ENV ARTIFACTS_PATH=/root/artifacts
ENV BINS_PATH=/root/bin
ENV PATH="$BINS_PATH:$PATH"

# Set endpoints to be local.
ENV SC_COORDINATOR_VERIFIER_ENDPOINTS=localhost:5001
ENV SC_COORDINATOR_VALIDATOR_COMMITTER_ENDPOINTS=localhost:6001
ENV SC_QUERY_DATABASE_ENDPOINTS=localhost:5433
ENV SC_VC_DATABASE_ENDPOINTS=localhost:5433
ENV SC_SIDECAR_COMMITTER_ENDPOINT=localhost:9001
ENV SC_SIDECAR_ORDERER_ORGANIZATIONS_ORG0_ENDPOINTS="id=0,broadcast,deliver,localhost:7050"
ENV SC_LOADGEN_ORDERER_CLIENT_ORDERER_ORGANIZATIONS_ORG0_ENDPOINTS="id=0,broadcast,deliver,localhost:7050"
# This variable defines the Orderer endpoints in the generated genesis block.
ENV SC_LOADGEN_LOAD_PROFILE_POLICY_ORDERER_ENDPOINTS="id=0,msp-id=org,broadcast,deliver,localhost:7050"
ENV SC_LOADGEN_ORDERER_CLIENT_SIDECAR_CLIENT_ENDPOINT=localhost:4001
ENV SC_QUERY_AUTH_CLIENT_ENDPOINT=localhost:10001
ENV SC_SIDECAR_AUTH_CLIENT_ENDPOINT=localhost:10001
ENV SC_LOADGEN_ORDERER_CLIENT_AUTH_ENDPOINT=localhost:10001
ENV SC_AUTH_DATABASE_ENDPOINTS=localhost:5433
# The sample's one-minute refresh is far too slow here: the node commits its config block seconds
# after start, and until the auth service observes it every Authenticate answers Unavailable - long
# enough for a waiting client's nonce to expire.
ENV SC_AUTH_CONFIG_REFRESH_INTERVAL=1s
# Tokens are minted once and never renewed, so they must outlast the whole test run.
ENV SC_AUTH_TOKEN_TTL=1h
ENV SC_AUTH_NONCE_TTL=1h

# Override default database credentials (YAML samples default to "yugabyte"
# which is correct for YugabyteDB but not for the PostgreSQL base image).
ENV SC_VC_DATABASE_USERNAME="postgres"
ENV SC_VC_DATABASE_PASSWORD="postgres"
ENV SC_VC_DATABASE_DATABASE="postgres"
ENV SC_QUERY_DATABASE_USERNAME="postgres"
ENV SC_QUERY_DATABASE_PASSWORD="postgres"
ENV SC_QUERY_DATABASE_DATABASE="postgres"
ENV SC_AUTH_DATABASE_USERNAME="postgres"
ENV SC_AUTH_DATABASE_PASSWORD="postgres"
ENV SC_AUTH_DATABASE_DATABASE="postgres"

# Disable TLS usage for db.
ENV SC_VC_DATABASE_TLS_MODE="none"
ENV SC_QUERY_DATABASE_TLS_MODE="none"
ENV SC_AUTH_DATABASE_TLS_MODE="none"

COPY ${SRC_BIN_PATH}/${TARGETOS}-${TARGETARCH}/* ${BINS_PATH}/
COPY ./docker/images/test_node/run ./docker/images/test_node/healthcheck ${BINS_PATH}/
COPY ./cmd/config/samples $CONFIGS_PATH
RUN chmod a+x ${BINS_PATH}/*

# Generate the genesis block and the crypto artifacts for the test-container.
# This includes private keys, public keys, TLS keys, etc.
RUN ${BINS_PATH}/loadgen make-artifacts -c "${CONFIGS_PATH}/loadgen.yaml"

# Expose ports
EXPOSE 7050 4001 2114 7001 2117 2110 10001 2121

# OCI metadata labels
LABEL org.opencontainers.image.created="${CREATED}" \
    org.opencontainers.image.description="Hyperledger Fabric-X Committer Test Node." \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.ref.name="postgres" \
    org.opencontainers.image.revision="${REVISION}" \
    org.opencontainers.image.source="https://github.com/hyperledger/fabric-x-committer" \
    org.opencontainers.image.title="fabric-x-committer-test-node" \
    org.opencontainers.image.url="https://github.com/hyperledger/fabric-x-committer" \
    org.opencontainers.image.version="${VERSION}"

# Default CMD
CMD ["run"]
