#!/bin/bash
# Runs once, on first initialisation of the pg-data volume.
# One database + owner role per service (SPEC §6.6).
set -euo pipefail

for db in keycloak identity portal; do
  pass_var="PG_${db^^}_PASSWORD"
  pass="${!pass_var:?missing $pass_var}"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<SQL
CREATE ROLE ${db} LOGIN PASSWORD '${pass}';
CREATE DATABASE ${db} OWNER ${db};
SQL
done
