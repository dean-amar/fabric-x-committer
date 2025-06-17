#!/usr/bin/env bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

export POSTGRES_PASSWORD=yugabyte
export POSTGRES_USER=yugabyte
docker-entrypoint.sh postgres -p 5433 &

"$BINS_PATH/committer" start-verifier    --config "$CONFIGS_PATH/sigservice.yaml" &
"$BINS_PATH/committer" start-query       --config "$CONFIGS_PATH/queryservice.yaml" &
"$BINS_PATH/committer" start-vc          --config "$CONFIGS_PATH/vcservice.yaml" &
"$BINS_PATH/committer" start-coordinator --config "$CONFIGS_PATH/coordinator.yaml" &
"$BINS_PATH/committer" start-sidecar     --config "$CONFIGS_PATH/sidecar.yaml"
