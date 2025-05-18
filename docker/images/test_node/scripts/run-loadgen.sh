#!/usr/bin/env bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

"$BINS_PATH/loadgen" start --config "$CONFIGS_PATH/loadgen.yaml"
