// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	sf "github.com/snowflakedb/gosnowflake"
)

func testKeyPEM(t *testing.T, pkcs1 bool) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if pkcs1 {
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func baseConfig(extra map[string]string) map[string]string {
	config := map[string]string{
		"account":   "myorg-myaccount",
		"user":      "admin",
		"database":  "appdb",
		"warehouse": "compute_wh",
	}
	for key, value := range extra {
		config[key] = value
	}
	return config
}

func TestAuthConfigPassword(t *testing.T) {
	cfg, err := snowflakeAuthConfig(baseConfig(map[string]string{"password": "pw"}))
	if err != nil {
		t.Fatalf("snowflakeAuthConfig returned error: %v", err)
	}
	if cfg.Authenticator != sf.AuthTypeSnowflake || cfg.Password != "pw" {
		t.Fatalf("authenticator = %v password = %q, want snowflake password auth", cfg.Authenticator, cfg.Password)
	}
	if cfg.Account != "myorg-myaccount" || cfg.Database != "appdb" || cfg.Warehouse != "compute_wh" {
		t.Fatalf("connection fields not applied: %+v", cfg)
	}
}

func TestAuthConfigKeyPair(t *testing.T) {
	for _, pkcs1 := range []bool{false, true} {
		cfg, err := snowflakeAuthConfig(baseConfig(map[string]string{"private_key": testKeyPEM(t, pkcs1)}))
		if err != nil {
			t.Fatalf("snowflakeAuthConfig (pkcs1=%v) returned error: %v", pkcs1, err)
		}
		if cfg.Authenticator != sf.AuthTypeJwt || cfg.PrivateKey == nil {
			t.Fatalf("authenticator = %v, want jwt with private key", cfg.Authenticator)
		}
	}
}

func TestAuthConfigOAuthToken(t *testing.T) {
	cfg, err := snowflakeAuthConfig(baseConfig(map[string]string{"token": "tok"}))
	if err != nil {
		t.Fatalf("snowflakeAuthConfig returned error: %v", err)
	}
	if cfg.Authenticator != sf.AuthTypeOAuth || cfg.Token != "tok" {
		t.Fatalf("authenticator = %v, want oauth token auth", cfg.Authenticator)
	}
}

func TestAuthConfigPat(t *testing.T) {
	for _, name := range []string{"programmatic_access_token", "pat"} {
		cfg, err := snowflakeAuthConfig(baseConfig(map[string]string{"token": "tok", "authenticator": name}))
		if err != nil {
			t.Fatalf("snowflakeAuthConfig (%s) returned error: %v", name, err)
		}
		if cfg.Authenticator != sf.AuthTypePat || cfg.Token != "tok" {
			t.Fatalf("authenticator = %v, want pat auth", cfg.Authenticator)
		}
	}
}

func TestAuthConfigClientCredentials(t *testing.T) {
	cfg, err := snowflakeAuthConfig(baseConfig(map[string]string{
		"oauth_client_id":     "cid",
		"oauth_client_secret": "csecret",
		"oauth_token_url":     "https://idp.example.com/token",
		"oauth_scope":         "session:role:sysadmin",
	}))
	if err != nil {
		t.Fatalf("snowflakeAuthConfig returned error: %v", err)
	}
	if cfg.Authenticator != sf.AuthTypeOAuthClientCredentials || cfg.OauthClientID != "cid" ||
		cfg.OauthClientSecret != "csecret" || cfg.OauthTokenRequestURL != "https://idp.example.com/token" ||
		cfg.OauthScope != "session:role:sysadmin" {
		t.Fatalf("client credentials config not applied: %+v", cfg)
	}
}

func TestAuthConfigClientCredentialsMissingKey(t *testing.T) {
	_, err := snowflakeAuthConfig(baseConfig(map[string]string{"oauth_client_id": "cid"}))
	if err == nil || !strings.Contains(err.Error(), "oauth_client_secret is required") {
		t.Fatalf("error = %v, want missing oauth_client_secret", err)
	}
}

func TestAuthConfigWorkloadIdentity(t *testing.T) {
	cfg, err := snowflakeAuthConfig(baseConfig(map[string]string{"workload_identity_provider": "aws"}))
	if err != nil {
		t.Fatalf("snowflakeAuthConfig returned error: %v", err)
	}
	if cfg.Authenticator != sf.AuthTypeWorkloadIdentityFederation || cfg.WorkloadIdentityProvider != "AWS" {
		t.Fatalf("authenticator = %v provider = %q, want workload identity AWS", cfg.Authenticator, cfg.WorkloadIdentityProvider)
	}
}

func TestAuthConfigNoAuth(t *testing.T) {
	_, err := snowflakeAuthConfig(baseConfig(nil))
	if err == nil || !strings.Contains(err.Error(), "auth config is required") {
		t.Fatalf("error = %v, want auth required error", err)
	}
}

func TestAuthConfigUnknownAuthenticator(t *testing.T) {
	_, err := snowflakeAuthConfig(baseConfig(map[string]string{"authenticator": "externalbrowser"}))
	if err == nil || !strings.Contains(err.Error(), "unsupported authenticator") {
		t.Fatalf("error = %v, want unsupported authenticator error", err)
	}
}

func TestAuthConfigExplicitAuthenticatorWins(t *testing.T) {
	// Both password and private_key set: explicit authenticator selects password
	cfg, err := snowflakeAuthConfig(baseConfig(map[string]string{
		"password": "pw", "private_key": testKeyPEM(t, false), "authenticator": "snowflake"}))
	if err != nil {
		t.Fatalf("snowflakeAuthConfig returned error: %v", err)
	}
	if cfg.Authenticator != sf.AuthTypeSnowflake {
		t.Fatalf("authenticator = %v, want snowflake", cfg.Authenticator)
	}
}

func TestParsePrivateKeyRejectsEncrypted(t *testing.T) {
	encrypted := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
	_, err := parseSnowflakePrivateKey(encrypted)
	if err == nil || !strings.Contains(err.Error(), "passphrase protected") {
		t.Fatalf("error = %v, want passphrase protected error", err)
	}
}

func TestParsePrivateKeyRejectsGarbage(t *testing.T) {
	_, err := parseSnowflakePrivateKey("not a key")
	if err == nil || !strings.Contains(err.Error(), "not valid PEM") {
		t.Fatalf("error = %v, want invalid PEM error", err)
	}
}

func TestQuoteSnowflakeIdent(t *testing.T) {
	tests := []struct{ in, want string }{
		{"compute_wh", `"COMPUTE_WH"`},   // plain identifiers are uppercased
		{"APPDB", `"APPDB"`},             // already uppercase
		{"my$db", `"MY$DB"`},             // $ is valid in unquoted identifiers
		{"my-db", `"my-db"`},             // needs quoting, kept verbatim
		{"weird\"name", `"weird""name"`}, // embedded quote doubled
		{"1leading", `"1leading"`},       // cannot be unquoted, kept verbatim
	}
	for _, tc := range tests {
		if got := quoteSnowflakeIdent(tc.in); got != tc.want {
			t.Fatalf("quoteSnowflakeIdent(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestGeneratedAccountDSNRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dsn, err := sf.DSN(&sf.Config{
		Account:       "myorg-myaccount",
		User:          "CL_USR_PRD_X",
		Database:      "APPDB",
		Schema:        "CL_SCH_PRD_X",
		Warehouse:     "COMPUTE_WH",
		Role:          "CL_ROL_PRD_X",
		Authenticator: sf.AuthTypeJwt,
		PrivateKey:    key,
	})
	if err != nil {
		t.Fatalf("DSN returned error: %v", err)
	}
	parsed, err := sf.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("ParseDSN returned error: %v", err)
	}
	if parsed.Authenticator != sf.AuthTypeJwt || parsed.PrivateKey == nil ||
		parsed.User != "CL_USR_PRD_X" || parsed.Schema != "CL_SCH_PRD_X" || parsed.Warehouse != "COMPUTE_WH" {
		t.Fatalf("DSN round trip lost fields: %+v", parsed)
	}
	if !parsed.PrivateKey.Equal(key) {
		t.Fatalf("DSN round trip lost the private key")
	}
}
