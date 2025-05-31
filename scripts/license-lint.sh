#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
REQUIRED_HEADER="SPDX-License-Identifier: Apache-2.0"

# - JSON does not support comments.
# - `goheader` linter already covers the `.go` files.
# - `go.sum` is automatically generated from the `go.mod` file.
IGNORE_REGEXP="(.*\.(json|go)|go.sum|LICENSE)$"

missing=$(git ls-files | sort -u | grep -vE "${IGNORE_REGEXP}"| xargs grep -L "${REQUIRED_HEADER}")

if [[ -z "$missing" ]]; then
  exit 0
fi

echo "Files without license headers:"
echo "------------------------------"
echo "$missing"
echo "--- FAIL"
exit 1
