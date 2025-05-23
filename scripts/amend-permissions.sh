#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# Workaround for issue when binding folders from host

if [ "$(uname -s)" == "Linux" ]; then
  sudo chown -R "$(id -u):$(id -g)" "$@"
fi

chmod -R +w "$@"
