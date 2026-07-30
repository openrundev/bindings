// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	sf "github.com/snowflakedb/gosnowflake"
)

// Admin authentication: Snowflake retired single-factor password sign-in, so
// the service config supports every non-interactive authentication method the
// gosnowflake driver offers. The method is inferred from which config keys are
// set, or forced with the authenticator key:
//
//   - private_key (PEM)                          -> key-pair JWT (snowflake_jwt)
//   - oauth_client_id/oauth_client_secret/
//     oauth_token_url                            -> OAuth2 client credentials
//   - token                                      -> OAuth access token, or a
//     programmatic access token with authenticator=programmatic_access_token
//   - workload_identity_provider (AWS/GCP/
//     AZURE/OIDC)                                -> workload identity federation
//   - password                                   -> username/password (only
//     usable where the account still allows it, e.g. legacy service users)
const (
	authenticatorSnowflake  = "snowflake"
	authenticatorJwt        = "snowflake_jwt"
	authenticatorOAuth      = "oauth"
	authenticatorPat        = "programmatic_access_token"
	authenticatorClientCred = "oauth_client_credentials"
	authenticatorWorkload   = "workload_identity"
)

// snowflakeAuthConfig builds the gosnowflake connection config for the admin
// connection from the service config. Auth-unrelated fields (database,
// warehouse, role) are also applied.
func snowflakeAuthConfig(serviceConfig map[string]string) (*sf.Config, error) {
	cfg := &sf.Config{
		Account:   serviceConfig["account"],
		User:      serviceConfig["user"],
		Database:  serviceConfig["database"],
		Warehouse: serviceConfig["warehouse"],
		Role:      serviceConfig["role"],
	}

	authenticator := strings.ToLower(strings.TrimSpace(serviceConfig["authenticator"]))
	if authenticator == "" {
		switch {
		case serviceConfig["private_key"] != "":
			authenticator = authenticatorJwt
		case serviceConfig["oauth_client_id"] != "" || serviceConfig["oauth_client_secret"] != "" || serviceConfig["oauth_token_url"] != "":
			authenticator = authenticatorClientCred
		case serviceConfig["token"] != "":
			authenticator = authenticatorOAuth
		case serviceConfig["workload_identity_provider"] != "":
			authenticator = authenticatorWorkload
		case serviceConfig["password"] != "":
			authenticator = authenticatorSnowflake
		default:
			return nil, fmt.Errorf("snowflake auth config is required: set private_key (key-pair), " +
				"oauth_client_id/oauth_client_secret/oauth_token_url (client credentials), token (OAuth/PAT), " +
				"workload_identity_provider (WIF) or password")
		}
	}

	switch authenticator {
	case authenticatorSnowflake:
		if serviceConfig["password"] == "" {
			return nil, fmt.Errorf("password is required for password auth")
		}
		cfg.Authenticator = sf.AuthTypeSnowflake
		cfg.Password = serviceConfig["password"]

	case authenticatorJwt:
		key, err := parseSnowflakePrivateKey(serviceConfig["private_key"])
		if err != nil {
			return nil, err
		}
		cfg.Authenticator = sf.AuthTypeJwt
		cfg.PrivateKey = key

	case authenticatorOAuth:
		if serviceConfig["token"] == "" {
			return nil, fmt.Errorf("token is required for oauth auth")
		}
		cfg.Authenticator = sf.AuthTypeOAuth
		cfg.Token = serviceConfig["token"]

	case authenticatorPat, "pat":
		if serviceConfig["token"] == "" {
			return nil, fmt.Errorf("token is required for programmatic access token auth")
		}
		cfg.Authenticator = sf.AuthTypePat
		cfg.Token = serviceConfig["token"]

	case authenticatorClientCred:
		for _, key := range []string{"oauth_client_id", "oauth_client_secret", "oauth_token_url"} {
			if serviceConfig[key] == "" {
				return nil, fmt.Errorf("%s is required for oauth client credentials auth", key)
			}
		}
		cfg.Authenticator = sf.AuthTypeOAuthClientCredentials
		cfg.OauthClientID = serviceConfig["oauth_client_id"]
		cfg.OauthClientSecret = serviceConfig["oauth_client_secret"]
		cfg.OauthTokenRequestURL = serviceConfig["oauth_token_url"]
		cfg.OauthScope = serviceConfig["oauth_scope"]

	case authenticatorWorkload:
		if serviceConfig["workload_identity_provider"] == "" {
			return nil, fmt.Errorf("workload_identity_provider (AWS, GCP, AZURE or OIDC) is required for workload identity auth")
		}
		cfg.Authenticator = sf.AuthTypeWorkloadIdentityFederation
		cfg.WorkloadIdentityProvider = strings.ToUpper(serviceConfig["workload_identity_provider"])
		cfg.WorkloadIdentityEntraResource = serviceConfig["workload_identity_entra_resource"]

	default:
		// The configured value is intentionally not echoed: service config
		// values may resolve from secret references, and provider errors are
		// returned to callers who may not be allowed to read secret values.
		return nil, fmt.Errorf("unsupported authenticator value: supported values are %s",
			strings.Join([]string{authenticatorSnowflake, authenticatorJwt, authenticatorOAuth,
				authenticatorPat, authenticatorClientCred, authenticatorWorkload}, ", "))
	}

	return cfg, nil
}

// parseSnowflakePrivateKey parses an RSA private key in PEM form (PKCS#8, or
// legacy PKCS#1). Encrypted keys are rejected: store the decrypted key through
// a secret provider ({{secret ...}} in the service config) instead.
func parseSnowflakePrivateKey(pemValue string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemValue)))
	if block == nil {
		return nil, fmt.Errorf("private_key is not valid PEM data")
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("private_key is passphrase protected; store the unencrypted PKCS#8 key " +
			"(openssl pkcs8 -topk8 -nocrypt) in a secret provider instead")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private_key is not an RSA key")
		}
		return rsaKey, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("private_key could not be parsed as a PKCS#8 or PKCS#1 RSA private key")
}
