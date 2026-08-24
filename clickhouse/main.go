// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

// openrun-binding-clickhouse is the OpenRun binding provider for ClickHouse
// (self-hosted and ClickHouse Cloud). It uses the pure-Go clickhouse-go
// driver. It is launched by the OpenRun server; it is not meant to be run
// directly.
package main

import (
	"github.com/openrundev/openrun/pkg/binding"
)

// version is the provider release version, set at build time with
// -ldflags "-X main.version=v0.x.y".
var version = "dev"

func main() {
	binding.Serve(&binding.ServeConfig{
		ProviderVersion: version,
		Bindings: map[string]binding.Builder{
			"clickhouse": NewClickHouseServiceBinding,
		},
		TypeInfo: map[string]binding.ServiceTypeInfo{
			"clickhouse": {
				SupportedGrantTypes: []binding.GrantType{binding.GrantTypeRead, binding.GrantTypeCreate, binding.GrantTypeFull},
				RequiredConfigKeys:  []string{"url"},
				OptionalConfigKeys:  []string{"binding_hostname", "cluster"},
			},
		},
	})
}
