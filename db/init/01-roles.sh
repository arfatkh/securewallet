#!/bin/sh
# Runs once, as the Postgres superuser, when the data volume is first created.
# wallet_owner owns the schema (migrations, SECURITY DEFINER functions).
# wallet_app is what the API uses: not the owner and NOBYPASSRLS, so RLS binds it.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<EOSQL
CREATE ROLE wallet_owner LOGIN PASSWORD '${OWNER_DB_PASSWORD}';
CREATE ROLE wallet_app LOGIN PASSWORD '${APP_DB_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE securewallet OWNER wallet_owner;
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname securewallet <<EOSQL
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO wallet_owner;
GRANT USAGE ON SCHEMA public TO wallet_app;
REVOKE CONNECT ON DATABASE securewallet FROM PUBLIC;
GRANT CONNECT ON DATABASE securewallet TO wallet_owner, wallet_app;
EOSQL
