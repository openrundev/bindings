#!/bin/bash
# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0
#
# Integration tests for the binding providers, run through the full RPC layer:
# an OpenRun server is started, each provider is installed with
# `openrun provider install` (registering it in the metadata database and
# launching the provider executable over go-plugin/gRPC), and the commander
# yaml suites drive the CLI against a real service container.
#
# Usage: ./run_int_tests.sh [mongodb|sqlserver|oracle|snowflake|clickhouse|databricks|all]
#
# The clickhouse suite runs against a docker container by default
# (clickhouse/clickhouse-server, image overridable with
# OPENRUN_TEST_CLICKHOUSE_IMAGE). Set TEST_CLICKHOUSE_URL to an admin
# connection URL to run against a live endpoint instead, e.g.
# https://default:password@abc123.us-west-2.aws.clickhouse.cloud:8443/default?secure=true
# (ClickHouse Cloud) or clickhouse://default:password@host:9000 (self-hosted).
# Binding deletion drops the cl_-prefixed users/roles/databases the suite
# created on the endpoint (container or live); the delete-verification tests
# assert this through the container's clickhouse-client, so they need the
# container mode.
#
# The snowflake suite runs against a real Snowflake account instead of a
# container: set TEST_SNOWFLAKE_ACCOUNT (org-account identifier),
# TEST_SNOWFLAKE_USER, and TEST_SNOWFLAKE_PRIVATE_KEY (unencrypted PKCS#8
# PEM, preferred) or TEST_SNOWFLAKE_PASSWORD as the admin credential (e.g. an
# ACCOUNTADMIN user; the private key wins when both are set). Optional:
# TEST_SNOWFLAKE_DATABASE (default OPENRUN_CLI; must already exist) and
# TEST_SNOWFLAKE_WAREHOUSE (default COMPUTE_WH). With `all`, the snowflake
# suite is skipped unless TEST_SNOWFLAKE_ACCOUNT is set. Binding deletion
# drops the CL_-prefixed users/roles/schemas the suite created on the
# account; only artifacts left by pre-artifact-recording OpenRun versions
# need external cleanup.
#
# Requirements: docker (or OPENRUN_TEST_CONTAINER_COMMAND=podman), jq, and the
# commander CLI (go install github.com/commander-cli/commander/v2/cmd/commander@v2.5.0).
#
# OPENRUN_SRC points at a checkout of the openrundev/openrun repo (used to
# build the server and resolve the pkg/binding SDK module); it defaults to a
# sibling checkout. OPENRUN_TEST_SERVER_BIN can point at a prebuilt server
# binary, which CI uses to avoid rebuilding an unchanged OpenRun checkout.

set -e

PROVIDER="${1:-all}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
OPENRUN_SRC="${OPENRUN_SRC:-$ROOT/../openrun}"
CONTAINER_COMMAND="${OPENRUN_TEST_CONTAINER_COMMAND:-docker}"
CL_TEST_VERBOSE="${CL_TEST_VERBOSE:-}"

case "$PROVIDER" in
  mongodb|sqlserver|oracle|snowflake|clickhouse|databricks|all) ;;
  *)
    echo "usage: $0 [mongodb|sqlserver|oracle|snowflake|clickhouse|databricks|all]" >&2
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

if [[ -n "${OPENRUN_TEST_SERVER_BIN:-}" ]]; then
  if [[ ! -x "$OPENRUN_TEST_SERVER_BIN" ]]; then
    echo "Prebuilt OpenRun server is not executable: $OPENRUN_TEST_SERVER_BIN" >&2
    exit 1
  fi
  echo "Using prebuilt openrun server from $OPENRUN_TEST_SERVER_BIN"
  cp "$OPENRUN_TEST_SERVER_BIN" "$OPENRUN_BIN"
else
  echo "Building openrun server from $OPENRUN_SRC"
  (cd "$OPENRUN_SRC" && go build -o "$OPENRUN_BIN" ./cmd/openrun)
fi

build_provider() {
  local name="$1"
  echo "Building openrun-binding-$name"
  (cd "$ROOT/$name" && go build -o "$WORK/bin/openrun-binding-$name" .)
}

cleanup() {
  "$OPENRUN_BIN" server stop >/dev/null 2>&1 || true
  local id
  for id in "$MONGODB_TEST_CONTAINER_ID" "$SQLSERVER_TEST_CONTAINER_ID" "$ORACLE_TEST_CONTAINER_ID" "$CLICKHOUSE_TEST_CONTAINER_ID"; do
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

start_clickhouse_container() {
  local image="${OPENRUN_TEST_CLICKHOUSE_IMAGE:-clickhouse/clickhouse-server:25.8}"
  echo "Starting clickhouse test container $image"
  # CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT lets the default user run the
  # access control DDL the binding needs (CREATE USER/ROLE, GRANT).
  CLICKHOUSE_TEST_CONTAINER_ID=$($CONTAINER_COMMAND run --detach --rm \
    --env CLICKHOUSE_PASSWORD=clickhouse \
    --env CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
    --ulimit nofile=262144:262144 \
    --publish "127.0.0.1::8123" "$image")
  export CLICKHOUSE_TEST_CONTAINER_ID
  export CLICKHOUSE_TEST_CONTAINER_COMMAND="$CONTAINER_COMMAND"
  local port
  port=$(container_port "$CLICKHOUSE_TEST_CONTAINER_ID" 8123)

  local ready=""
  for _ in {1..120}; do
    if curl -sS --max-time 2 "http://127.0.0.1:${port}/ping" 2>/dev/null | grep -q "Ok"; then
      ready="true"
      break
    fi
    sleep 1
  done
  if [[ -z "$ready" ]]; then
    echo "ClickHouse test container did not become ready" >&2
    $CONTAINER_COMMAND logs "$CLICKHOUSE_TEST_CONTAINER_ID" || true
    return 1
  fi
  export TEST_CLICKHOUSE_URL="http://default:clickhouse@localhost:${port}/default"
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
# the CLI talks over the workdir-scoped unix socket in any case. The env
# secret provider backs {{secret_from "env" ...}} references in service
# configs (used by the snowflake suite for the admin password).
cat <<EOF > "$CL_CONFIG_FILE"
[http]
port = 25322

[https]
port = -1

[client]
default_format = "table"

[secret.env]
EOF

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
RUN_SNOWFLAKE=""
if [[ "$PROVIDER" == "snowflake" ]]; then
  RUN_SNOWFLAKE=true
elif [[ "$PROVIDER" == "all" ]]; then
  if [[ -n "${TEST_SNOWFLAKE_ACCOUNT:-}" ]]; then
    RUN_SNOWFLAKE=true
  else
    echo "Skipping snowflake suite (TEST_SNOWFLAKE_ACCOUNT not set)"
  fi
fi
if [[ -n "$RUN_SNOWFLAKE" ]]; then
  : "${TEST_SNOWFLAKE_ACCOUNT:?set TEST_SNOWFLAKE_ACCOUNT (org-account identifier)}"
  : "${TEST_SNOWFLAKE_USER:?set TEST_SNOWFLAKE_USER (admin user)}"
  if [[ -z "${TEST_SNOWFLAKE_PRIVATE_KEY:-}" && -z "${TEST_SNOWFLAKE_PASSWORD:-}" ]]; then
    echo "set TEST_SNOWFLAKE_PRIVATE_KEY (unencrypted PKCS#8 PEM, preferred) or TEST_SNOWFLAKE_PASSWORD" >&2
    exit 1
  fi
  # Both are exported (possibly empty): the suite passes both as secret
  # references and the provider uses the private key when it is non-empty.
  export TEST_SNOWFLAKE_PRIVATE_KEY="${TEST_SNOWFLAKE_PRIVATE_KEY:-}"
  export TEST_SNOWFLAKE_PASSWORD="${TEST_SNOWFLAKE_PASSWORD:-}"
  export TEST_SNOWFLAKE_DATABASE="${TEST_SNOWFLAKE_DATABASE:-OPENRUN_CLI}"
  export TEST_SNOWFLAKE_WAREHOUSE="${TEST_SNOWFLAKE_WAREHOUSE:-COMPUTE_WH}"
  build_provider snowflake
  export SNOWFLAKE_PROVIDER_BIN="$WORK/bin/openrun-binding-snowflake"
fi
RUN_DATABRICKS=""
if [[ "$PROVIDER" == "databricks" ]]; then
  RUN_DATABRICKS=true
elif [[ "$PROVIDER" == "all" ]]; then
  if [[ -n "${TEST_DATABRICKS_HOST:-}" ]]; then
    RUN_DATABRICKS=true
  else
    echo "Skipping databricks suite (TEST_DATABRICKS_HOST not set)"
  fi
fi
if [[ -n "$RUN_DATABRICKS" ]]; then
  # The databricks suite runs against a live workspace: set
  # TEST_DATABRICKS_HOST, TEST_DATABRICKS_HTTP_PATH (SQL warehouse) and
  # TEST_DATABRICKS_TOKEN (workspace admin PAT). TEST_DATABRICKS_CATALOG
  # defaults to main; the catalog must already exist.
  : "${TEST_DATABRICKS_HOST:?set TEST_DATABRICKS_HOST (workspace hostname)}"
  : "${TEST_DATABRICKS_HTTP_PATH:?set TEST_DATABRICKS_HTTP_PATH (SQL warehouse http path)}"
  : "${TEST_DATABRICKS_TOKEN:?set TEST_DATABRICKS_TOKEN (workspace admin PAT)}"
  export TEST_DATABRICKS_CATALOG="${TEST_DATABRICKS_CATALOG:-main}"
  build_provider databricks
  export DATABRICKS_PROVIDER_BIN="$WORK/bin/openrun-binding-databricks"
fi
if [[ "$PROVIDER" == "clickhouse" || "$PROVIDER" == "all" ]]; then
  build_provider clickhouse
  export CLICKHOUSE_PROVIDER_BIN="$WORK/bin/openrun-binding-clickhouse"
  # A preset TEST_CLICKHOUSE_URL targets a live endpoint (e.g. ClickHouse
  # Cloud); otherwise a local container is started.
  if [[ -z "${TEST_CLICKHOUSE_URL:-}" ]]; then
    start_clickhouse_container
  fi
fi

echo "Starting openrun server"
cd "$WORK"
"$OPENRUN_BIN" server start &
wait_for_socket

FAILED=0
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
if [[ -n "$RUN_SNOWFLAKE" ]]; then
  # No wait_for_service: the service is a cloud endpoint (the suite installs
  # the provider itself so uninstall/reinstall is covered in one file).
  commander test $CL_TEST_VERBOSE "$SCRIPT_DIR/test_snowflake.yaml" || FAILED=1
fi
if [[ -n "$RUN_DATABRICKS" ]]; then
  # No wait_for_service: the workspace is a live endpoint; the suite installs
  # the provider itself so uninstall/reinstall is covered in one file.
  commander test $CL_TEST_VERBOSE "$SCRIPT_DIR/test_databricks.yaml" || FAILED=1
fi
if [[ "$PROVIDER" == "clickhouse" || "$PROVIDER" == "all" ]]; then
  # No wait_for_service: the container start already waits for /ping (and a
  # live endpoint is always up); the suite installs the provider itself so
  # uninstall/reinstall is covered in one file.
  commander test $CL_TEST_VERBOSE "$SCRIPT_DIR/test_clickhouse.yaml" || FAILED=1
fi

exit $FAILED
