\echo Execute "CREATE EXTENSION pg_bech32;" to use this extension. \quit


--
-- Encoding/decoding functions
--

CREATE FUNCTION bech32_encode(hrp text, bit varying) RETURNS text
  LANGUAGE c IMMUTABLE STRICT PARALLEL SAFE COST 10
  AS 'MODULE_PATHNAME', 'pg_bech32_encode';

CREATE FUNCTION bech32_decode(text) RETURNS bit varying
  LANGUAGE c IMMUTABLE STRICT PARALLEL SAFE COST 10
  AS 'MODULE_PATHNAME', 'pg_bech32_decode';

CREATE FUNCTION bech32_hrp(text) RETURNS text
  LANGUAGE c IMMUTABLE STRICT PARALLEL SAFE COST 10
  AS 'MODULE_PATHNAME', 'pg_bech32_hrp';

CREATE OR REPLACE FUNCTION b32_decode(encodedstr text) RETURNS text
  LANGUAGE plpgsql STABLE AS $$
  DECLARE
    bit_string bit varying;
  BEGIN
    SELECT INTO bit_string bech32_decode(encodedstr);
    RETURN (
      SELECT
        CASE
          WHEN LENGTH(bit_string) % 8 = 0 THEN ENCODE(SUBSTR(varbit_send(bit_string), 5)::bytea, 'hex')
          ELSE LEFT(ENCODE(SUBSTR(varbit_send(bit_string), 5)::bytea, 'hex'), -2)
        END
    );
  END;
  $$;

CREATE OR REPLACE FUNCTION b32_encode(pre text, bytea text) RETURNS text
  LANGUAGE SQL STABLE AS $$
    SELECT bech32_encode(pre, RIGHT(bytea::text, -1)::varbit);
  $$;
