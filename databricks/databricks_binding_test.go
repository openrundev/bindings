// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestDatabricksAuthConfigInference(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]string
		wantType string
		wantErr  string
	}{
		{
			name:     "pat",
			config:   map[string]string{"host": "dbc-1.cloud.databricks.com", "token": "dapi123"},
			wantType: "pat",
		},
		{
			name:     "oauth m2m",
			config:   map[string]string{"host": "dbc-1.cloud.databricks.com", "client_id": "abc", "client_secret": "xyz"},
			wantType: "oauth-m2m",
		},
		{
			name: "azure client secret",
			config: map[string]string{"host": "adb-1.azuredatabricks.net", "azure_client_id": "app-id",
				"azure_client_secret": "s", "azure_tenant_id": "t"},
			wantType: "azure-client-secret",
		},
		{
			name:     "azure msi",
			config:   map[string]string{"host": "adb-1.azuredatabricks.net", "azure_use_msi": "true"},
			wantType: "azure-msi",
		},
		{
			name:     "google id",
			config:   map[string]string{"host": "1.gcp.databricks.com", "google_service_account": "sa@proj.iam.gserviceaccount.com"},
			wantType: "google-id",
		},
		{
			name:     "google credentials",
			config:   map[string]string{"host": "1.gcp.databricks.com", "google_credentials": "{}"},
			wantType: "google-credentials",
		},
		{
			name:     "explicit auth_type wins",
			config:   map[string]string{"host": "dbc-1.cloud.databricks.com", "auth_type": "oauth-m2m", "client_id": "abc", "client_secret": "xyz", "token": "dapi123"},
			wantType: "oauth-m2m",
		},
		{
			name:    "no auth config",
			config:  map[string]string{"host": "dbc-1.cloud.databricks.com"},
			wantErr: "auth config is required",
		},
		{
			name:    "oauth missing secret",
			config:  map[string]string{"host": "dbc-1.cloud.databricks.com", "auth_type": "oauth-m2m", "client_id": "abc"},
			wantErr: "client_id and client_secret are required",
		},
		{
			name:    "azure missing tenant",
			config:  map[string]string{"host": "adb-1.azuredatabricks.net", "auth_type": "azure-client-secret", "azure_client_id": "a", "azure_client_secret": "s"},
			wantErr: "azure_tenant_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := databricksAuthConfig(tt.config)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("databricksAuthConfig() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("databricksAuthConfig() error = %v", err)
			}
			if cfg.AuthType != tt.wantType {
				t.Fatalf("AuthType = %q, want %q", cfg.AuthType, tt.wantType)
			}
			if !strings.HasPrefix(cfg.Host, "https://") {
				t.Fatalf("Host = %q, want https:// prefix", cfg.Host)
			}
		})
	}
}

func TestDatabricksHostHelpers(t *testing.T) {
	if got := databricksHostURL("dbc-1.cloud.databricks.com"); got != "https://dbc-1.cloud.databricks.com" {
		t.Fatalf("databricksHostURL() = %q", got)
	}
	if got := databricksHostURL("https://dbc-1.cloud.databricks.com/"); got != "https://dbc-1.cloud.databricks.com" {
		t.Fatalf("databricksHostURL() with scheme = %q", got)
	}
	if got := databricksHostname("https://dbc-1.cloud.databricks.com"); got != "dbc-1.cloud.databricks.com" {
		t.Fatalf("databricksHostname() = %q", got)
	}
	if got := databricksHostname("dbc-1.cloud.databricks.com"); got != "dbc-1.cloud.databricks.com" {
		t.Fatalf("databricksHostname() bare = %q", got)
	}
}

func TestDatabricksWarehouseID(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
		want   string
	}{
		{"explicit", map[string]string{"warehouse_id": "abc123", "http_path": "/sql/1.0/warehouses/def"}, "abc123"},
		{"from path", map[string]string{"http_path": "/sql/1.0/warehouses/c7703dc7e9d84c5d"}, "c7703dc7e9d84c5d"},
		{"trailing slash", map[string]string{"http_path": "/sql/1.0/warehouses/c7703dc7e9d84c5d/"}, "c7703dc7e9d84c5d"},
		{"legacy path", map[string]string{"http_path": "/sql/protocolv1/o/123/456-789-abc"}, ""},
		{"empty", map[string]string{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := databricksWarehouseID(tt.config); got != tt.want {
				t.Fatalf("databricksWarehouseID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDatabricksAccountURL(t *testing.T) {
	patURL := databricksAccountURL("dbc-1.cloud.databricks.com", "/sql/1.0/warehouses/w1",
		"main", "cl_sch_prd_1", dbxAccountAuthPat, "app-id-1", "dapi-secret")
	if !strings.HasPrefix(patURL, "token:dapi-secret@dbc-1.cloud.databricks.com:443/sql/1.0/warehouses/w1?") {
		t.Fatalf("pat url = %q", patURL)
	}
	params, err := url.ParseQuery(strings.SplitN(patURL, "?", 2)[1])
	if err != nil {
		t.Fatalf("pat url params: %v", err)
	}
	if params.Get("catalog") != "main" || params.Get("schema") != "cl_sch_prd_1" {
		t.Fatalf("pat url catalog/schema = %v", params)
	}
	if params.Get("authType") != "" {
		t.Fatalf("pat url must not set authType: %q", patURL)
	}

	oauthURL := databricksAccountURL("dbc-1.cloud.databricks.com", "/sql/1.0/warehouses/w1",
		"main", "cl_sch_prd_1", dbxAccountAuthOauth, "app-id-1", "oauth-secret")
	if strings.HasPrefix(oauthURL, "token:") {
		t.Fatalf("oauth url must not embed a token: %q", oauthURL)
	}
	params, err = url.ParseQuery(strings.SplitN(oauthURL, "?", 2)[1])
	if err != nil {
		t.Fatalf("oauth url params: %v", err)
	}
	if params.Get("authType") != "OauthM2M" || params.Get("clientID") != "app-id-1" || params.Get("clientSecret") != "oauth-secret" {
		t.Fatalf("oauth url params = %v", params)
	}
}

func TestQuoteDatabricksIdent(t *testing.T) {
	if got := quoteDatabricksIdent("cl_sch_prd_1"); got != "`cl_sch_prd_1`" {
		t.Fatalf("quoteDatabricksIdent() = %q", got)
	}
	// Embedded backticks are doubled so they cannot break out of the quoting
	if got := quoteDatabricksIdent("a`b"); got != "`a``b`" {
		t.Fatalf("quoteDatabricksIdent() escape = %q", got)
	}
	// Grant principals are application id UUIDs, quoted verbatim
	if got := quoteDatabricksIdent("7d3a9c1e-1111-2222-3333-444455556666"); got != "`7d3a9c1e-1111-2222-3333-444455556666`" {
		t.Fatalf("quoteDatabricksIdent() uuid = %q", got)
	}
}
