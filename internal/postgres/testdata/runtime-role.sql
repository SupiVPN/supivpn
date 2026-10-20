-- Disposable PostgreSQL test fixture. Production roles/grants live in db/roles.tf.
CREATE ROLE supivpn_runtime LOGIN
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 20;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE supivpn_test TO supivpn_runtime;
GRANT USAGE ON SCHEMA supivpn TO supivpn_runtime;
GRANT SELECT ON public.supivpn_schema_migrations TO supivpn_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA supivpn TO supivpn_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA supivpn TO supivpn_runtime;
