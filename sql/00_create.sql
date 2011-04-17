DROP VIEW IF EXISTS observations_view;
DROP TABLE IF EXISTS observations;
DROP TABLE IF EXISTS service;

-- This would be better as enum, but then we'd have to rewrite a lot of
-- original code.
CREATE TABLE service (
    id SMALLINT UNIQUE NOT NULL,
    name VARCHAR(16) NOT NULL
);

INSERT INTO service (id, name) VALUES 
    (1, 'ssh'),
    (2, 'ssl');

CREATE TABLE observations (
    id serial PRIMARY KEY,
    fqdn VARCHAR(255) NOT NULL,
    port integer NOT NULL,
    service_type SMALLINT REFERENCES service(id),
    start_time timestamp with time zone NOT NULL,
    end_time timestamp with time zone NOT NULL,
    md5 bytea NOT NULL,
    sha1 bytea -- allowed null to allow old DB migration
);

-- (fqdn, port, service_type) is not unique since fingerprints may change
CREATE INDEX service_idx ON observations (fqdn, port, service_type);

CREATE VIEW observations_view AS
    SELECT id, fqdn, port, service_type,
        date_part('epoch', start_time)::int AS start_ts,
        date_part('epoch', end_time)::int AS end_ts,
        md5,
        encode(md5, 'hex') AS md5hex, 
        sha1,
        encode(sha1, 'hex') AS sha1hex
        FROM observations;
