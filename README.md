# OpenRun Binding Providers

Out-of-process [service binding](https://github.com/openrundev/openrun) providers
for OpenRun. Each provider is an independent Go module built into a standalone
executable (`openrun-binding-<name>`) that the OpenRun server launches on demand
and talks to over gRPC (hashicorp/go-plugin). Keeping providers out of the main
server binary keeps the server small and lets providers release independently.

## Providers

| Provider    | Service types       | Notes                                            |
|-------------|---------------------|--------------------------------------------------|
| `mongodb`   | `mongodb`, `atlas`  | Self-hosted MongoDB and MongoDB Atlas            |
| `sqlserver` | `sqlserver`         | Schema-based isolation, SQL Server 2019+         |
| `oracle`    | `oracle`            | Pure-Go go-ora driver, no Oracle client needed   |
| `snowflake` | `snowflake`         | Role/schema isolation, key-pair auth accounts    |
| `clickhouse`| `clickhouse`        | Self-hosted and ClickHouse Cloud, role/database isolation |
| `databricks`| `databricks`        | Databricks SQL warehouse, Unity Catalog schema isolation |

## Building

Each provider is its own module:

```sh
cd mongodb && go build -o openrun-binding-mongodb .
cd sqlserver && go build -o openrun-binding-sqlserver .
```

## Installing

Install into a running OpenRun server (registers the provider in the metadata
database and makes its service types available):

```sh
openrun provider install mongodb --source-url /path/to/openrun-binding-mongodb
openrun provider list
openrun service create mongodb/m1 --config url=mongodb://localhost:27017
```

For development, a provider can instead be registered directly from a local
path in `openrun.toml` (no database registration, no checksum verification):

```toml
[bindings.dev_providers.mongodb]
path = "/path/to/openrun-binding-mongodb"
```

## Testing

Unit tests are self-contained per module:

```sh
cd mongodb && go test ./...
```

Integration tests run through the full RPC layer: `tests/run_int_tests.sh`
builds the provider and an OpenRun server (from a sibling `openrun` checkout,
override with `OPENRUN_SRC`), starts a service container with docker, starts
the server, installs the provider with `openrun provider install`, and drives
the commander yaml suite (`tests/test_<provider>.yaml`) through the CLI:

```sh
go install github.com/commander-cli/commander/v2/cmd/commander@v2.5.0
./tests/run_int_tests.sh mongodb    # or sqlserver, oracle, snowflake, clickhouse, databricks, all
```

Notes: the SQL Server image is amd64-only (arm64 hosts need Rosetta/qemu
emulation in the container runtime); the oracle tests default to
`gvenzl/oracle-xe:21-slim` on amd64 and `gvenzl/oracle-free:23-slim` on arm64,
and the container takes a few minutes to initialize on first start.

The snowflake suite has no container: it runs against a live Snowflake
account. Set `TEST_SNOWFLAKE_ACCOUNT` (org-account identifier),
`TEST_SNOWFLAKE_USER`, and either `TEST_SNOWFLAKE_PRIVATE_KEY` (unencrypted
PKCS#8 PEM, preferred — Snowflake is phasing out password sign-in) or
`TEST_SNOWFLAKE_PASSWORD` as the admin credential; the suite uses the private
key when both are set. Optionally set `TEST_SNOWFLAKE_DATABASE` (default
`OPENRUN_CLI`, must already exist) and `TEST_SNOWFLAKE_WAREHOUSE` (default
`COMPUTE_WH`). With `all`, the snowflake suite is skipped unless
`TEST_SNOWFLAKE_ACCOUNT` is set. In CI the credentials come from the
`TEST_SNOWFLAKE_*` repository secrets. Binding deletion in OpenRun removes
only metadata, so the `CL_`-prefixed users, roles and schemas the suite
creates on the account are not dropped by the suite and must be cleaned up
externally.

The clickhouse suite runs against a docker container by default
(`clickhouse/clickhouse-server`, overridable with
`OPENRUN_TEST_CLICKHOUSE_IMAGE`). Set `TEST_CLICKHOUSE_URL` to an admin
connection URL to target a live endpoint instead, e.g.
`https://default:password@abc123.region.aws.clickhouse.cloud:8443/default?secure=true`
(ClickHouse Cloud) or `clickhouse://default:password@host:9000` (self-hosted).
On a live endpoint, the `cl_`-prefixed users, roles and databases the suite
creates are cleaned up externally (with the container they vanish with it).

## CI

Each provider has its own workflow (`.github/workflows/test-<provider>.yml`),
path-filtered so a change to one provider only builds and tests that provider.
Each workflow runs the module's unit tests and the RPC-layer integration suite

## Releasing

Push a `<provider>/vX.Y.Z` tag to trigger the release workflow:

```sh
git tag mongodb/v0.1.0 && git push origin mongodb/v0.1.0
```

It builds `openrun-binding-<provider>-<os>-<arch>` binaries for
linux/darwin/windows plus a `SHA256SUMS` file and publishes a GitHub release.
Install a released provider with:

```sh
openrun provider install mongodb --version v0.1.0 \
  --source-url "https://github.com/openrundev/bindings/releases/download/mongodb%2F{version}/openrun-binding-mongodb-{os}-{arch}"
```

## Writing a new provider

Implement `binding.ServiceBinding` from
`github.com/openrundev/openrun/pkg/binding` and call `binding.Serve` in `main`.
See `mongodb/main.go` for a minimal example. Add a `tests/test_<name>.yaml`
commander suite, a `test-<name>.yml` workflow, and the provider's tag pattern
to `release.yml`.
