#!/usr/bin/env bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

/home/yugabyte/bin/yugabyted start \
  --advertise_address 0.0.0.0 \
  --callhome false \
  --fault_tolerance none \
  --background true \
  --ui false \
  --insecure \
  --tserver_flags "ysql_max_connections=500,tablet_replicas_per_gib_limit=4000,yb_num_shards_per_tserver=1,minloglevel=3"

"$BINS_PATH/signatureverifier" start --config "$CONFIGS_PATH/sigservice.yaml" &
"$BINS_PATH/queryexecutor" start --config "$CONFIGS_PATH/queryservice.yaml" &
"$BINS_PATH/validatorpersister" start --config "$CONFIGS_PATH/vcservice.yaml" &
"$BINS_PATH/coordinator" start --config "$CONFIGS_PATH/coordinator.yaml" &
"$BINS_PATH/sidecar" start --config "$CONFIGS_PATH/sidecar.yaml"
