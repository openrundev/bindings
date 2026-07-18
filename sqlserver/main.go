// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// openrun-binding-sqlserver is the OpenRun binding provider for Microsoft SQL
// Server. It is launched by the OpenRun server; it is not meant to be run
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
			"sqlserver": NewSqlServerServiceBinding,
		},
		TypeInfo: map[string]binding.ServiceTypeInfo{
			"sqlserver": {
				SupportedGrantTypes: []binding.GrantType{binding.GrantTypeRead, binding.GrantTypeCreate, binding.GrantTypeFull},
				RequiredConfigKeys:  []string{"url"},
				OptionalConfigKeys:  []string{"binding_hostname"},
			},
		},
	})
}
