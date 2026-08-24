// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

// openrun-binding-databricks is the OpenRun binding provider for Databricks
// SQL warehouses with Unity Catalog. It is launched by the OpenRun server; it
// is not meant to be run directly.
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
			"databricks": NewDatabricksServiceBinding,
		},
		TypeInfo: map[string]binding.ServiceTypeInfo{
			"databricks": {
				SupportedGrantTypes: []binding.GrantType{binding.GrantTypeRead, binding.GrantTypeCreate, binding.GrantTypeFull},
				RequiredConfigKeys:  databricksServiceConfigKeys.required,
				OptionalConfigKeys:  databricksServiceConfigKeys.optional,
			},
		},
	})
}
