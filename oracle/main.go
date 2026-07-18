// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// openrun-binding-oracle is the OpenRun binding provider for Oracle Database.
// It uses the pure-Go go-ora driver, so no Oracle client libraries are needed.
// It is launched by the OpenRun server; it is not meant to be run directly.
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
			"oracle": NewOracleServiceBinding,
		},
		TypeInfo: map[string]binding.ServiceTypeInfo{
			"oracle": {
				SupportedGrantTypes: []binding.GrantType{binding.GrantTypeRead, binding.GrantTypeFull},
				RequiredConfigKeys:  []string{"url"},
				OptionalConfigKeys:  []string{"binding_hostname"},
			},
		},
	})
}
