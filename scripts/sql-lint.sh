#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
CHANGED_FILES=$(git diff --name-only main -- '*.sql')

if [ -n "$CHANGED_FILES" ]; then
  echo "Linting changed SQL files:"
  echo "$CHANGED_FILES"
  sqlfluff lint --dialect postgres $CHANGED_FILES
else
  echo "No SQL files has been changed."
fi
