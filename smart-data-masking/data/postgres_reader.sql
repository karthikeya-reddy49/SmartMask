-- Run as a PostgreSQL administrator. Replace the password outside source control.
-- The application role is intentionally not a superuser and must only read source data.
CREATE ROLE smartmask_reader LOGIN PASSWORD 'REPLACE_WITH_SECRET'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
ALTER ROLE smartmask_reader SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE REPLACE_DATABASE TO smartmask_reader;

-- Connect to REPLACE_DATABASE as the database owner, then grant schema/table access.
GRANT USAGE ON SCHEMA public TO smartmask_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO smartmask_reader;
-- Execute as the role that creates future source tables:
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO smartmask_reader;
