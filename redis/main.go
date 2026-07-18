// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// openrun-binding-redis is the OpenRun binding provider for Redis and Valkey
// (one ACL-compatible implementation serves both service types). It is
// launched by the OpenRun server; it is not meant to be run directly.
package main

import (
	"github.com/openrundev/openrun/pkg/binding"
)

// version is the provider release version, set at build time with
// -ldflags "-X main.version=v0.x.y".
var version = "dev"

func main() {
	typeInfo := binding.ServiceTypeInfo{
		SupportedGrantTypes: []binding.GrantType{binding.GrantTypeRead, binding.GrantTypeFull},
		RequiredConfigKeys:  []string{"url"},
		OptionalConfigKeys:  []string{"binding_hostname"},
	}

	binding.Serve(&binding.ServeConfig{
		ProviderVersion: version,
		Bindings: map[string]binding.Builder{
			"redis":  NewRedisServiceBinding,
			"valkey": NewRedisServiceBinding,
		},
		TypeInfo: map[string]binding.ServiceTypeInfo{
			"redis":  typeInfo,
			"valkey": typeInfo,
		},
	})
}
