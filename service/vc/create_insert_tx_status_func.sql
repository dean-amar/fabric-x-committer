/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

CREATE OR REPLACE FUNCTION insert_tx_status(
    IN _tx_ids BYTEA [],
    IN _statuses INTEGER [],
    IN _heights BYTEA [],
    OUT result TEXT,
    OUT violating BYTEA []
)
AS $$
BEGIN
    result := 'success';
    violating := NULL;

    INSERT INTO tx_status (tx_id, status, height)
    VALUES (
        unnest(_tx_ids),
        unnest(_statuses),
        unnest(_heights)
    );

EXCEPTION
    WHEN unique_violation THEN
        SELECT array_agg(t.tx_id)
        INTO violating
        FROM tx_status t
        WHERE t.tx_id = ANY(_tx_ids);

        IF cardinality(violating) < cardinality(_tx_ids) THEN
            result := cardinality(violating)::text || '-unique-violation';
        ELSE
            violating := NULL;
            result := 'all-unique-violation';
        END IF;
END;
$$ LANGUAGE plpgsql;
