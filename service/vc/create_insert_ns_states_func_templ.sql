/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

CREATE OR REPLACE FUNCTION insert_%[1]s(
    IN _keys BYTEA [],
    IN _values BYTEA [],
    OUT result TEXT,
    OUT violating BYTEA []
)
AS $$
BEGIN
    result := 'success';
    violating := NULL;

    INSERT INTO %[1]s (key, value)
    SELECT k, v
    FROM unnest(_keys, _values) AS t(k, v);

EXCEPTION
    WHEN unique_violation THEN
        SELECT array_agg(t_existing.key)
        INTO violating
        FROM %[1]s t_existing
        WHERE t_existing.key = ANY (_keys);

        IF cardinality(violating) < cardinality(_keys) THEN
            result := cardinality(violating)::text || '-unique-violation';
        ELSE
            violating := NULL;
            result := 'all-unique-violation';
        END IF;
END;
$$ LANGUAGE plpgsql;
