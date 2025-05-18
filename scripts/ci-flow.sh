#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

export GO111MODULE=on
export GOPRIVATE=github.ibm.com
export DB_DEPLOYMENT=local

echo "Unit Test (non DB)" | tee /tmp/sc-tests.txt
make test-non-db-packages "$@" &>>/tmp/sc-tests.txt

echo >>/tmp/sc-tests.txt
echo "Unit Tests" | tee -a /tmp/sc-tests.txt
make test-db-packages "$@" &>>/tmp/sc-tests.txt

echo >>/tmp/sc-tests.txt
echo "Integration Tests" | tee -a /tmp/sc-tests.txt
make test-db-packages "$@" &>>/tmp/sc-tests.txt

echo >>/tmp/sc-tests.txt
echo "Build and test container images" | tee -a /tmp/sc-tests.txt
make container-test "$@" &>>/tmp/sc-tests.txt

echo >>/tmp/sc-tests.txt
echo "Searching fails" | tee -a /tmp/sc-tests.txt
grep FAIL <tmp/sc-tests.txt | tee -a /tmp/sc-tests.txt
