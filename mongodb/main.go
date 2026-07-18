// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// openrun-binding-mongodb is the OpenRun binding provider for MongoDB. It
// serves two service types: "mongodb" (self-hosted servers) and "atlas"
// (MongoDB Atlas, managed through the Atlas Admin API). It is launched by the
// OpenRun server; it is not meant to be run directly.
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
			"mongodb": func() binding.ServiceBinding { return &MongoServiceBinding{} },
			"atlas":   func() binding.ServiceBinding { return &MongoServiceBinding{isAtlas: true} },
		},
		TypeInfo: map[string]binding.ServiceTypeInfo{
			"mongodb": {
				SupportedGrantTypes: []binding.GrantType{binding.GrantTypeRead, binding.GrantTypeFull},
				RequiredConfigKeys:  []string{"url"},
				OptionalConfigKeys:  []string{"binding_hostname"},
			},
			"atlas": {
				SupportedGrantTypes: []binding.GrantType{binding.GrantTypeRead, binding.GrantTypeFull},
				RequiredConfigKeys:  []string{"url", "project_id"},
				OptionalConfigKeys:  []string{"public_key", "private_key", "client_id", "client_secret", "cluster_name", "api_base_url", "user_wait_secs"},
			},
		},
	})
}
