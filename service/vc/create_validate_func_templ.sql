/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

CREATE OR REPLACE FUNCTION validate_reads_%[1]s(
    keys BYTEA [],
    versions BYTEA []
)
RETURNS TABLE (key_mismatched BYTEA, version_mismatched BYTEA)
AS $$
BEGIN
	RETURN QUERY
	SELECT
		reads.keys AS key_mismatched,
		reads.versions AS version_mismatched
	FROM
		unnest(keys, versions) WITH ORDINALITY AS reads(keys, versions, ord_keys)
	LEFT JOIN
		%[1]s ON reads.keys = %[1]s.key
	WHERE
		/* if the key does not exist in the committed state but read version is not null,
		we found a mismatch */
		(%[1]s.key IS NULL AND reads.versions IS NOT NULL)
		OR
		/* if the key exists in the committed state but read version is null, we found a mismatch */
		(reads.versions IS NULL AND %[1]s.key is NOT NULL)
		OR
		/* if the committed version of a key is different from the read version, we found a mismatch */
		reads.versions <> %[1]s.version;
END;
$$ LANGUAGE plpgsql;
