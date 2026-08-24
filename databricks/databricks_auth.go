// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/databricks/databricks-sdk-go/config"
)

// Admin authentication: every non-interactive method of the Databricks SDK
// unified auth is supported. The service config keys populate a
// databricks-sdk-go config.Config, which authenticates both the REST plane
// (workspace client) and the SQL plane: *config.Config implements the
// databricks-sql-go auth.Authenticator interface directly. The method is
// inferred from which config keys are set, or forced with the auth_type key
// (values match the SDK's auth types):
//
//   - token                                       -> pat (personal access token)
//   - client_id/client_secret                     -> oauth-m2m (Databricks-managed
//     service principal OAuth secret)
//   - azure_client_id/azure_client_secret/
//     azure_tenant_id                             -> azure-client-secret (Entra ID
//     service principal)
//   - azure_use_msi                               -> azure-msi (Azure managed identity;
//     azure_client_id selects a user-assigned identity)
//   - google_service_account                      -> google-id (service account
//     impersonation)
//   - google_credentials                          -> google-credentials (service
//     account key JSON or path)
//
// OAuth U2M is browser-interactive and is not supported in a server-side
// provider.
const (
	dbxAuthTypePat               = "pat"
	dbxAuthTypeOauthM2M          = "oauth-m2m"
	dbxAuthTypeAzureClientSecret = "azure-client-secret"
	dbxAuthTypeAzureMsi          = "azure-msi"
	dbxAuthTypeGoogleID          = "google-id"
	dbxAuthTypeGoogleCredentials = "google-credentials"
)

var databricksServiceConfigKeys = struct {
	required []string
	optional []string
}{
	required: []string{"host", "http_path", "catalog"},
	optional: []string{"warehouse_id", "auth_type", "token", "client_id", "client_secret",
		"azure_client_id", "azure_client_secret", "azure_tenant_id", "azure_use_msi",
		"google_service_account", "google_credentials",
		"account_credential_type", "token_lifetime_seconds"},
}

// databricksAuthConfig builds the SDK auth config for the admin connection
// from the service config.
func databricksAuthConfig(serviceConfig map[string]string) (*config.Config, error) {
	cfg := &config.Config{
		Host:                 databricksHostURL(serviceConfig["host"]),
		Token:                serviceConfig["token"],
		ClientID:             serviceConfig["client_id"],
		ClientSecret:         serviceConfig["client_secret"],
		AzureClientID:        serviceConfig["azure_client_id"],
		AzureClientSecret:    serviceConfig["azure_client_secret"],
		AzureTenantID:        serviceConfig["azure_tenant_id"],
		AzureUseMSI:          serviceConfig["azure_use_msi"] == "true",
		GoogleServiceAccount: serviceConfig["google_service_account"],
		GoogleCredentials:    serviceConfig["google_credentials"],
	}

	authType := strings.ToLower(strings.TrimSpace(serviceConfig["auth_type"]))
	if authType == "" {
		switch {
		case cfg.Token != "":
			authType = dbxAuthTypePat
		case cfg.ClientID != "" || cfg.ClientSecret != "":
			authType = dbxAuthTypeOauthM2M
		case cfg.AzureClientID != "" || cfg.AzureClientSecret != "":
			authType = dbxAuthTypeAzureClientSecret
		case cfg.AzureUseMSI:
			authType = dbxAuthTypeAzureMsi
		case cfg.GoogleServiceAccount != "":
			authType = dbxAuthTypeGoogleID
		case cfg.GoogleCredentials != "":
			authType = dbxAuthTypeGoogleCredentials
		default:
			return nil, fmt.Errorf("databricks auth config is required: set token (PAT), " +
				"client_id/client_secret (service principal OAuth), azure_client_id/azure_client_secret/azure_tenant_id " +
				"(Entra ID), azure_use_msi (managed identity), google_service_account or google_credentials")
		}
	}

	switch authType {
	case dbxAuthTypePat:
		if cfg.Token == "" {
			return nil, fmt.Errorf("token is required for pat auth")
		}
	case dbxAuthTypeOauthM2M:
		if cfg.ClientID == "" || cfg.ClientSecret == "" {
			return nil, fmt.Errorf("client_id and client_secret are required for oauth-m2m auth")
		}
	case dbxAuthTypeAzureClientSecret:
		if cfg.AzureClientID == "" || cfg.AzureClientSecret == "" || cfg.AzureTenantID == "" {
			return nil, fmt.Errorf("azure_client_id, azure_client_secret and azure_tenant_id are required for azure-client-secret auth")
		}
	case dbxAuthTypeAzureMsi:
		cfg.AzureUseMSI = true
	case dbxAuthTypeGoogleID:
		if cfg.GoogleServiceAccount == "" {
			return nil, fmt.Errorf("google_service_account is required for google-id auth")
		}
	case dbxAuthTypeGoogleCredentials:
		if cfg.GoogleCredentials == "" {
			return nil, fmt.Errorf("google_credentials is required for google-credentials auth")
		}
	default:
		// Pass through unknown values (e.g. github-oidc, env, azure-cli for dev
		// setups): the SDK validates them and its auth surface keeps growing.
	}
	cfg.AuthType = authType
	return cfg, nil
}

// databricksHostURL normalizes the host config value to the https URL form
// the SDK expects.
func databricksHostURL(host string) string {
	host = strings.TrimSuffix(strings.TrimSpace(host), "/")
	if host == "" || strings.Contains(host, "://") {
		return host
	}
	return "https://" + host
}

// databricksHostname returns the bare hostname for the SQL driver.
func databricksHostname(host string) string {
	host = databricksHostURL(host)
	if parsed, err := url.Parse(host); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return strings.TrimPrefix(host, "https://")
}

// databricksWarehouseID resolves the warehouse id for the permissions API:
// the explicit warehouse_id config, or parsed from an http_path of the form
// /sql/1.0/warehouses/<id>.
func databricksWarehouseID(serviceConfig map[string]string) string {
	if id := serviceConfig["warehouse_id"]; id != "" {
		return id
	}
	httpPath := strings.TrimSuffix(serviceConfig["http_path"], "/")
	const marker = "/warehouses/"
	idx := strings.LastIndex(httpPath, marker)
	if idx == -1 {
		return ""
	}
	id := httpPath[idx+len(marker):]
	if id == "" || strings.Contains(id, "/") {
		return ""
	}
	return id
}
