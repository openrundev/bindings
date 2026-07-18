#!/bin/bash
# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Integration tests for the binding providers, run through the full RPC layer:
# an OpenRun server is started, each provider is installed with
# `openrun provider install` (registering it in the metadata database and
# launching the provider executable over go-plugin/gRPC), and the commander
# yaml suites drive the CLI against a real service container.
#
# Usage: ./run_int_tests.sh [redis|mongodb|sqlserver|oracle|all]
#
# Requirements: docker (or OPENRUN_TEST_CONTAINER_COMMAND=podman), jq, and the
# commander CLI (go install github.com/commander-cli/commander/v2/cmd/commander@v2.5.0).
#
# OPENRUN_SRC points at a checkout of the openrundev/openrun repo (used to
# build the server and resolve the pkg/binding SDK module); it defaults to a
# sibling checkout.

set -e

PROVIDER="${1:-all}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
OPENRUN_SRC="${OPENRUN_SRC:-$ROOT/../openrun7}"
CONTAINER_COMMAND="${OPENRUN_TEST_CONTAINER_COMMAND:-docker}"
CL_TEST_VERBOSE="${CL_TEST_VERBOSE:-}"

case "$PROVIDER" in
  redis|mongodb|sqlserver|oracle|all) ;;
  *)
    echo "usage: $0 [redis|mongodb|sqlserver|oracle|all]" >&2
    exit 1
    ;;
esac
if [[ ! -d "$OPENRUN_SRC/cmd/openrun" ]]; then
  echo "OpenRun source not found at $OPENRUN_SRC; set OPENRUN_SRC" >&2
  exit 1
fi

WORK="$SCRIPT_DIR/run"
rm -rf "$WORK"
mkdir -p "$WORK/bin"
export OPENRUN_HOME="$WORK"
export OPENRUN_BIN="$WORK/bin/openrun"
export CL_CONFIG_FILE="$WORK/openrun.toml"

echo "Building openrun server from $OPENRUN_SRC"
(cd "$OPENRUN_SRC" && go build -o "$OPENRUN_BIN" ./cmd/openrun)

build_provider() {
  local name="$1"
  echo "Building openrun-binding-$name"
  (cd "$ROOT/$name" && go build -o "$WORK/bin/openrun-binding-$name" .)
}

cleanup() {
  "$OPENRUN_BIN" server stop >/dev/null 2>&1 || true
  local id
  for id in "$REDIS_TEST_CONTAINER_ID" "$MONGODB_TEST_CONTAINER_ID" "$SQLSERVER_TEST_CONTAINER_ID" "$ORACLE_TEST_CONTAINER_ID"; do
    if [[ -n "$id" ]]; then
      $CONTAINER_COMMAND stop -t 1 "$id" >/dev/null 2>&1 || true
    fi
  done
}
trap cleanup EXIT

container_port() {
  local container_id="$1" container_port="$2" port=""
  for _ in {1..75}; do
    port=$($CONTAINER_COMMAND inspect \
      --format "{{with index .NetworkSettings.Ports \"${container_port}/tcp\"}}{{(index . 0).HostPort}}{{end}}" \
      "$container_id" 2>/dev/null || true)
    if [[ -n "$port" ]]; then
      echo "$port"
      return 0
    fi
    sleep 0.2
  done
  echo "Container port ${container_port} was not published for ${container_id}" >&2
  return 1
}

start_redis_container() {
  # Set OPENRUN_TEST_REDIS_IMAGE=valkey/valkey:8-alpine to run against Valkey.
  local image="${OPENRUN_TEST_REDIS_IMAGE:-redis:8-alpine}"
  echo "Starting redis test container $image"
  REDIS_TEST_CONTAINER_ID=$($CONTAINER_COMMAND run --detach --rm --publish "127.0.0.1::6379" "$image")
  export REDIS_TEST_CONTAINER_ID
  export REDIS_TEST_CONTAINER_COMMAND="$CONTAINER_COMMAND"
  local port
  port=$(container_port "$REDIS_TEST_CONTAINER_ID" 6379)
  export TEST_REDIS_URL="redis://localhost:${port}"
}

start_mongodb_container() {
  local image="${OPENRUN_TEST_MONGODB_IMAGE:-mongo:8}"
  echo "Starting mongodb test container $image"
  # The root env vars make the official image start mongod with --auth
  MONGODB_TEST_CONTAINER_ID=$($CONTAINER_COMMAND run --detach --rm \
    --env MONGO_INITDB_ROOT_USERNAME=root \
    --env MONGO_INITDB_ROOT_PASSWORD=mongo \
    --publish "127.0.0.1::27017" "$image")
  export MONGODB_TEST_CONTAINER_ID
  export MONGODB_TEST_CONTAINER_COMMAND="$CONTAINER_COMMAND"
  local port
  port=$(container_port "$MONGODB_TEST_CONTAINER_ID" 27017)
  export TEST_MONGODB_URL="mongodb://root:mongo@localhost:${port}/?authSource=admin"
}

# sqlserver_exec_sqlcmd runs sqlcmd inside the SQL Server test container. The
# tools path moved between image versions (mssql-tools before 2022, and
# mssql-tools18, which needs -C to trust the self-signed cert, after), so both
# are tried.
sqlserver_exec_sqlcmd() {
  $CONTAINER_COMMAND exec "$SQLSERVER_TEST_CONTAINER_ID" /opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P "$TEST_SQLSERVER_PASSWORD" "$@" >/dev/null 2>&1 || \
    $CONTAINER_COMMAND exec "$SQLSERVER_TEST_CONTAINER_ID" /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P "$TEST_SQLSERVER_PASSWORD" "$@" >/dev/null 2>&1
}

start_sqlserver_container() {
  # SQL Server Express edition; the mssql image is amd64-only, arm64 hosts need
  # Rosetta/qemu emulation enabled in the container runtime.
  local image="${SQLSERVER_TESTCONTAINER_IMAGE:-mcr.microsoft.com/mssql/server:2022-latest}"
  export TEST_SQLSERVER_PASSWORD="OpenRun1Test!"
  echo "Starting sqlserver test container $image"
  SQLSERVER_TEST_CONTAINER_ID=$($CONTAINER_COMMAND run --detach --rm \
    --publish "127.0.0.1::1433" \
    --env ACCEPT_EULA=Y \
    --env MSSQL_SA_PASSWORD="$TEST_SQLSERVER_PASSWORD" \
    --env MSSQL_PID=Express \
    "$image")
  export SQLSERVER_TEST_CONTAINER_ID
  export SQLSERVER_TEST_CONTAINER_COMMAND="$CONTAINER_COMMAND"
  local port
  port=$(container_port "$SQLSERVER_TEST_CONTAINER_ID" 1433)

  local ready=""
  for _ in {1..300}; do
    if sqlserver_exec_sqlcmd -Q "SELECT 1"; then
      ready="true"
      break
    fi
    sleep 1
  done
  if [[ -z "$ready" ]]; then
    echo "SQL Server test container did not become ready" >&2
    $CONTAINER_COMMAND logs "$SQLSERVER_TEST_CONTAINER_ID" || true
    return 1
  fi
  if ! sqlserver_exec_sqlcmd -Q "IF DB_ID('openrun_cli') IS NULL CREATE DATABASE openrun_cli"; then
    echo "Could not create the SQL Server test database" >&2
    return 1
  fi
  export TEST_SQLSERVER_URL="sqlserver://sa:${TEST_SQLSERVER_PASSWORD}@localhost:${port}?database=openrun_cli"
}

start_oracle_container() {
  # Oracle Database XE 21c by default; the image is amd64-only, so arm64 hosts
  # default to gvenzl/oracle-free:23-slim (same envs and healthcheck; the
  # binding avoids 23ai-only features either way).
  local default_image="gvenzl/oracle-xe:21-slim"
  if [[ "$(uname -m)" == "arm64" || "$(uname -m)" == "aarch64" ]]; then
    default_image="gvenzl/oracle-free:23-slim"
  fi
  local image="${ORACLE_TESTCONTAINER_IMAGE:-$default_image}"
  local service="XEPDB1"
  if [[ "$image" == *free* ]]; then
    service="FREEPDB1"
  fi
  echo "Starting oracle test container $image"
  ORACLE_TEST_CONTAINER_ID=$($CONTAINER_COMMAND run --detach --rm \
    --publish "127.0.0.1::1521" \
    --env ORACLE_PASSWORD=oracle \
    "$image")
  export ORACLE_TEST_CONTAINER_ID
  export ORACLE_TEST_CONTAINER_COMMAND="$CONTAINER_COMMAND"
  local port
  port=$(container_port "$ORACLE_TEST_CONTAINER_ID" 1521)

  # Oracle takes a few minutes to initialize on first start; the gvenzl images
  # ship a healthcheck.sh that reports database readiness.
  local ready=""
  for _ in {1..360}; do
    if $CONTAINER_COMMAND exec "$ORACLE_TEST_CONTAINER_ID" healthcheck.sh >/dev/null 2>&1; then
      ready="true"
      break
    fi
    sleep 1
  done
  if [[ -z "$ready" ]]; then
    echo "Oracle test container did not become ready" >&2
    $CONTAINER_COMMAND logs "$ORACLE_TEST_CONTAINER_ID" || true
    return 1
  fi
  export TEST_ORACLE_URL="oracle://system:oracle@localhost:${port}/${service}"
}

wait_for_socket() {
  local attempt=0
  while [[ $attempt -lt 100 ]]; do
    if curl -sS --connect-timeout 0.1 --max-time 0.5 --unix-socket "$WORK/run/openrun.sock" -o /dev/null "http://openrun/" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
    attempt=$((attempt + 1))
  done
  echo "Timed out waiting for the openrun server socket" >&2
  return 1
}

wait_for_service() {
  # Retry until the service container accepts connections through the binding
  # path: create and delete a probe service (InitializeService pings the
  # service). Providers are already installed at this point.
  local service_type="$1" url="$2" attempt=0
  while [[ $attempt -lt 60 ]]; do
    if "$OPENRUN_BIN" service create --config url="$url" "$service_type/readyprobe" >/dev/null 2>&1; then
      "$OPENRUN_BIN" service delete "$service_type/readyprobe" >/dev/null 2>&1 || true
      return 0
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  echo "Timed out waiting for $service_type test container to become ready" >&2
  return 1
}

# Non-default ports so the tests never clash with a locally running server;
# the CLI talks over the workdir-scoped unix socket in any case.
cat <<EOF > "$CL_CONFIG_FILE"
[http]
port = 25322

[https]
port = -1

[client]
default_format = "table"
EOF

if [[ "$PROVIDER" == "redis" || "$PROVIDER" == "all" ]]; then
  build_provider redis
  export REDIS_PROVIDER_BIN="$WORK/bin/openrun-binding-redis"
  start_redis_container
fi
if [[ "$PROVIDER" == "mongodb" || "$PROVIDER" == "all" ]]; then
  build_provider mongodb
  export MONGODB_PROVIDER_BIN="$WORK/bin/openrun-binding-mongodb"
  start_mongodb_container
fi
if [[ "$PROVIDER" == "sqlserver" || "$PROVIDER" == "all" ]]; then
  build_provider sqlserver
  export SQLSERVER_PROVIDER_BIN="$WORK/bin/openrun-binding-sqlserver"
  start_sqlserver_container
fi
if [[ "$PROVIDER" == "oracle" || "$PROVIDER" == "all" ]]; then
  build_provider oracle
  export ORACLE_PROVIDER_BIN="$WORK/bin/openrun-binding-oracle"
  start_oracle_container
fi

echo "Starting openrun server"
cd "$WORK"
"$OPENRUN_BIN" server start &
wait_for_socket

FAILED=0
if [[ "$PROVIDER" == "redis" || "$PROVIDER" == "all" ]]; then
  "$OPENRUN_BIN" provider install redis --source-url "$REDIS_PROVIDER_BIN"
  wait_for_service redis "$TEST_REDIS_URL"
  commander test $CL_TEST_VERBOSE "$SCRIPT_DIR/test_redis.yaml" || FAILED=1
fi
if [[ "$PROVIDER" == "mongodb" || "$PROVIDER" == "all" ]]; then
  "$OPENRUN_BIN" provider install mongodb --source-url "$MONGODB_PROVIDER_BIN"
  wait_for_service mongodb "$TEST_MONGODB_URL"
  commander test $CL_TEST_VERBOSE "$SCRIPT_DIR/test_mongodb.yaml" || FAILED=1
fi
if [[ "$PROVIDER" == "sqlserver" || "$PROVIDER" == "all" ]]; then
  "$OPENRUN_BIN" provider install sqlserver --source-url "$SQLSERVER_PROVIDER_BIN"
  wait_for_service sqlserver "$TEST_SQLSERVER_URL"
  commander test $CL_TEST_VERBOSE "$SCRIPT_DIR/test_sqlserver.yaml" || FAILED=1
fi
if [[ "$PROVIDER" == "oracle" || "$PROVIDER" == "all" ]]; then
  "$OPENRUN_BIN" provider install oracle --source-url "$ORACLE_PROVIDER_BIN"
  wait_for_service oracle "$TEST_ORACLE_URL"
  commander test $CL_TEST_VERBOSE "$SCRIPT_DIR/test_oracle.yaml" || FAILED=1
fi

exit $FAILED
