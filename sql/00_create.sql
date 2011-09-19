DROP VIEW IF EXISTS observations_view;
DROP TABLE IF EXISTS observations;
DROP TYPE IF EXISTS service_type_enum;
DROP TABLE IF EXISTS services;

CREATE TYPE service_type_enum AS ENUM ('ssl', 'ssh');

CREATE TABLE services (
    id serial PRIMARY KEY,
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    service_type service_type_enum NOT NULL DEFAULT 'ssl'
);

CREATE TABLE observations (
    id serial PRIMARY KEY,
    start_time timestamp with time zone NOT NULL,
    end_time timestamp with time zone NOT NULL,
    certificate bytea NOT NULL,
    md5 bytea NOT NULL,
    sha1 bytea NOT NULL,
    service_id INTEGER NOT NULL REFERENCES services(id)
);

CREATE UNIQUE INDEX service_idx ON services (host, port, service_type);

CREATE INDEX observations_fkey_service_idx ON observations (service_id);
CREATE INDEX end_time_idx ON observations (end_time);

-- CREATE VIEW observations_view AS
--     SELECT id, host, port, service_type,
--         date_part('epoch', start_time)::int AS start_ts,
--         date_part('epoch', end_time)::int AS end_ts,
--         md5,
--         encode(md5, 'hex') AS md5_hex, 
--         sha1,
--         encode(sha1, 'hex') AS sha1_hex
--         FROM observations;

