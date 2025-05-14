/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

CREATE OR REPLACE FUNCTION update_%[1]s(
    IN _keys BYTEA [],
    IN _values BYTEA [],
    IN _versions BYTEA []
)
RETURNS VOID
AS $$
BEGIN
    UPDATE %[1]s
    SET
        value = t.value,
        version = t.version
    FROM (
        SELECT *
        FROM unnest(_keys, _values, _versions) AS t(key, value, version)
    ) AS t
    WHERE
        %[1]s.key = t.key;
END;
$$ LANGUAGE plpgsql;
