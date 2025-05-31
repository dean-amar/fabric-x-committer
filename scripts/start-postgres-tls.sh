##!/bin/bash
#set -euo pipefail
#
#CONTAINER_NAME="sc_postgres_unit_tests_tls"
#CERTS_DIR="/Users/deanamar/Work/ssh-scalable-committer/scalable-committer/test-certs"
#PGDATA_DIR="/tmp/pgdata_tls_$CONTAINER_NAME"
#IMAGE="postgres:16.9-alpine3.21"
#
#echo "📥 Pulling Postgres image..."
#docker pull $IMAGE
#
#echo "🧼 Cleaning up old data and container (if any)..."
#docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
#rm -rf "$PGDATA_DIR"
#mkdir -p "$PGDATA_DIR"
#
#echo "🧱 Initializing database manually as 'postgres' user..."
#docker run --rm \
#  -e PGDATA="/var/lib/postgresql/data" \
#  -v "$PGDATA_DIR":/var/lib/postgresql/data \
#  $IMAGE \
#  su postgres -c "initdb -U yugabyte -A trust --nosync"
#
#echo "🛠 Adding hostssl rule to pg_hba.conf"
#echo "hostssl all all all trust" >> "$PGDATA_DIR/pg_hba.conf"
#
#echo "🔐 Fixing permissions for TLS key"
#chmod 600 "$CERTS_DIR/server.key"
#
#echo "🚀 Starting PostgreSQL with TLS..."
#docker run \
#  --name "$CONTAINER_NAME" \
#  -e POSTGRES_USER=yugabyte \
#  -e POSTGRES_PASSWORD=yugabyte \
#  -v "$PGDATA_DIR":/var/lib/postgresql/data \
#  -v "$CERTS_DIR":/certs \
#  -p 5433:5432 \
#  $IMAGE \
#  -c ssl=on \
#  -c ssl_cert_file=/certs/server.crt \
#  -c ssl_key_file=/certs/server.key \
#  -c ssl_ca_file=/certs/ca.crt
#
#echo "✅ PostgreSQL with TLS is running on port 5433"
#

#!/bin/bash
set -euo pipefail

CONTAINER_NAME="sc_postgres_unit_tests_tls"
CERTS_DIR="/Users/deanamar/Work/ssh-scalable-committer/scalable-committer/test-certs"
PGDATA_DIR="/tmp/pgdata_tls_$CONTAINER_NAME"
IMAGE="postgres:16.9-alpine3.21"

echo "📥 Pulling Postgres image..."
docker pull $IMAGE

echo "🧼 Cleaning up old data and container (if any)..."
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
rm -rf "$PGDATA_DIR"
mkdir -p "$PGDATA_DIR"

echo "🧱 Initializing database manually as 'postgres' user..."
docker run --rm \
  -e PGDATA="/var/lib/postgresql/data" \
  -v "$PGDATA_DIR":/var/lib/postgresql/data \
  $IMAGE \
  su postgres -c "initdb -U yugabyte -A trust --nosync"

echo "🛠 Adding hostssl rule to pg_hba.conf"
echo "hostssl all all all trust" >> "$PGDATA_DIR/pg_hba.conf"

echo "🔐 Fixing permissions for TLS key"
chmod 600 "$CERTS_DIR/server.key"

echo "🚀 Starting PostgreSQL with TLS..."
docker run -d \
  --name "$CONTAINER_NAME" \
  -e POSTGRES_USER=yugabyte \
  -e POSTGRES_PASSWORD=yugabyte \
  -v "$PGDATA_DIR":/var/lib/postgresql/data \
  -v "$CERTS_DIR":/certs \
  -p 5433:5432 \
  $IMAGE \
  -c ssl=on \
  -c ssl_cert_file=/certs/server.crt \
  -c ssl_key_file=/certs/server.key \
  -c ssl_ca_file=/certs/ca.crt

echo "⏳ Waiting a few seconds for Postgres to come up..."
sleep 2

echo "📦 Creating 'yugabyte' database manually..."
docker exec "$CONTAINER_NAME" createdb -U yugabyte yugabyte

echo "✅ PostgreSQL with TLS is running on port 5433"

