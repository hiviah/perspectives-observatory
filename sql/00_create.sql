DROP VIEW IF EXISTS observations_view;
DROP TABLE IF EXISTS ee_cert_x_ca_certs;
DROP TABLE IF EXISTS ca_certs;
DROP TABLE IF EXISTS ee_certs;
DROP TABLE IF EXISTS services;


-- All observed hosts
CREATE TABLE services (
    id serial PRIMARY KEY,
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL DEFAULT 443
);

-- Table with CA/intermediate certificates
CREATE TABLE ca_certs (
    id serial PRIMARY KEY,
    certificate bytea NOT NULL
);

-- Table with end-entity, or server-certificates
CREATE TABLE ee_certs (
    id serial PRIMARY KEY,
    start_time timestamp with time zone NOT NULL DEFAULT NOW(),
    end_time timestamp with time zone NOT NULL DEFAULT NOW(),
    certificate bytea NOT NULL,
    service_id INTEGER NOT NULL REFERENCES services(id)
);

-- Defines certificate chains; order of chains is given by seq_num (starting
-- from 0). Higher seq_num means closer to chain root.
CREATE TABLE ee_cert_x_ca_certs (
    seq_num smallint NOT NULL,
    ee_cert_id INTEGER NOT NULL REFERENCES ee_certs(id),
    ca_cert_id INTEGER NOT NULL REFERENCES ca_certs(id)
);

CREATE UNIQUE INDEX services_idx ON services (host, port);

CREATE INDEX ee_certs_fkey_service_idx ON ee_certs (service_id);
CREATE INDEX ee_certs_x_ca_certs_service_id_idx ON ee_cert_x_ca_certs (ee_cert_id);

-- Creating index on md5() is for index speedup, collision (non)-resistance is
-- not an issue.
CREATE INDEX ca_certs_cert_idx ON ca_certs(md5(certificate));

-- View for querying results for Perspectives HTTP API.
CREATE VIEW observations_view AS
    SELECT ee.id AS id, 
        s.host AS host, 
        s.port AS port, 
        date_part('epoch', ee.start_time)::int AS start_ts,
        date_part('epoch', ee.end_time)::int AS end_ts,
        ee.certificate AS certificate
    FROM services AS s INNER JOIN ee_certs AS ee ON (ee.service_id = s.id);

