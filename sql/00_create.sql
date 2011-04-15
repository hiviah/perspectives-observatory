DROP VIEW IF EXISTS observations_hex;
DROP TABLE IF EXISTS observations;
DROP TYPE IF EXISTS service_type;

CREATE TYPE service_type AS ENUM ('ssh', 'ssl');

-- id not needed yet, later may be used for foreign keys
CREATE TABLE observations (
    id serial UNIQUE NOT NULL,
    fqdn VARCHAR(255) NOT NULL,
    port integer NOT NULL,
    service service_type NOT NULL,
    md5 bytea NOT NULL,
    sha1 bytea,

    PRIMARY KEY (fqdn, port, service)
);

CREATE VIEW observations_hex AS
    SELECT id, fqdn, port, service, 
        encode(md5, 'hex') AS md5hex, 
        encode(sha1, 'hex') AS sha1hex 
        FROM observations;
