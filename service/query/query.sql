/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0

Template for the querying rows for each namespace.
*/
SELECT
    key,
    value,
    version
FROM ns_%[1]s
WHERE key = any($1);
