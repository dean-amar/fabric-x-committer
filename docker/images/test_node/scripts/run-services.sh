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

"$BINS_PATH/signatureverifier" start --config "$CONFIGS_PATH/sigservice.yaml" &
"$BINS_PATH/queryexecutor" start --config "$CONFIGS_PATH/queryservice.yaml" &
"$BINS_PATH/validatorpersister" start --config "$CONFIGS_PATH/vcservice.yaml" &
"$BINS_PATH/coordinator" start --config "$CONFIGS_PATH/coordinator.yaml" &
"$BINS_PATH/sidecar" start --config "$CONFIGS_PATH/sidecar.yaml"
