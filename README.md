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
| `redis`     | `redis`, `valkey`   | ACL-based isolation, Redis 6+/Valkey             |
| `sqlserver` | `sqlserver`         | Schema-based isolation, SQL Server 2019+         |
| `oracle`    | `oracle`            | Pure-Go go-ora driver, no Oracle client needed   |

## Building

Each provider is its own module:

```sh
cd mongodb && go build -o openrun-binding-mongodb .
cd redis && go build -o openrun-binding-redis .
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
cd redis && go test ./...
```

Integration tests run through the full RPC layer: `tests/run_int_tests.sh`
builds the provider and an OpenRun server (from a sibling `openrun` checkout,
override with `OPENRUN_SRC`), starts a service container with docker, starts
the server, installs the provider with `openrun provider install`, and drives
the commander yaml suite (`tests/test_<provider>.yaml`) through the CLI:

```sh
go install github.com/commander-cli/commander/v2/cmd/commander@v2.5.0
./tests/run_int_tests.sh redis      # or mongodb, sqlserver, oracle, all
OPENRUN_TEST_REDIS_IMAGE=valkey/valkey:8-alpine ./tests/run_int_tests.sh redis
```

Notes: the SQL Server image is amd64-only (arm64 hosts need Rosetta/qemu
emulation in the container runtime); the oracle tests default to
`gvenzl/oracle-xe:21-slim` on amd64 and `gvenzl/oracle-free:23-slim` on arm64,
and the container takes a few minutes to initialize on first start.

## CI

Each provider has its own workflow (`.github/workflows/test-<provider>.yml`),
path-filtered so a change to one provider only builds and tests that provider.
Each workflow runs the module's unit tests and the RPC-layer integration suite
(the redis workflow runs it against both Redis and Valkey images).

## Releasing

Push a `<provider>/vX.Y.Z` tag to trigger the release workflow:

```sh
git tag redis/v0.1.0 && git push origin redis/v0.1.0
```

It builds `openrun-binding-<provider>-<os>-<arch>` binaries for
linux/darwin/windows plus a `SHA256SUMS` file and publishes a GitHub release.
Install a released provider with:

```sh
openrun provider install redis --version v0.1.0 \
  --source-url "https://github.com/openrundev/bindings/releases/download/redis%2F{version}/openrun-binding-redis-{os}-{arch}"
```

## Writing a new provider

Implement `binding.ServiceBinding` from
`github.com/openrundev/openrun/pkg/binding` and call `binding.Serve` in `main`.
See `redis/main.go` for a minimal example. Add a `tests/test_<name>.yaml`
commander suite, a `test-<name>.yml` workflow, and the provider's tag pattern
to `release.yml`.
