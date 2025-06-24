#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

# This script adds a TX/sec column to the benchmark output.
{
	if ($NF ~ /ns\/op/) {
		ops=1e9/$(NF-1);
		printf "%s\t%'.0f TX/sec\n", $0, ops
	} else print $0
}
