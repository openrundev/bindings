// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

package main

import (
	"strings"
	"testing"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
)

func TestGeneratePasswordComplexity(t *testing.T) {
	for range 20 {
		password, err := generateClickhousePassword()
		if err != nil {
			t.Fatalf("generateClickhousePassword returned error: %v", err)
		}
		if len(password) < 12 {
			t.Fatalf("password %q shorter than 12 chars", password)
		}
		var hasLower, hasUpper, hasDigit, hasSpecial bool
		for _, c := range password {
			switch {
			case c >= 'a' && c <= 'z':
				hasLower = true
			case c >= 'A' && c <= 'Z':
				hasUpper = true
			case c >= '0' && c <= '9':
				hasDigit = true
			case strings.ContainsRune("~-._", c):
				hasSpecial = true
			default:
				t.Fatalf("password %q contains unexpected char %q", password, c)
			}
		}
		if !hasLower || !hasUpper || !hasDigit || !hasSpecial {
			t.Fatalf("password %q missing a required character class", password)
		}
	}
}

func TestAccountURLs(t *testing.T) {
	accountURL, directURL, err := clickhouseAccountURLs(
		"https://admin:secret@host.clickhouse.cloud:8443/default?secure=true",
		"cl_usr_prd_x", "Pass~word.123", "cl_db_prd_x", "")
	if err != nil {
		t.Fatalf("clickhouseAccountURLs returned error: %v", err)
	}
	if accountURL != directURL {
		t.Fatalf("url %q != url_direct %q without binding hostname", accountURL, directURL)
	}
	want := "https://cl_usr_prd_x:Pass~word.123@host.clickhouse.cloud:8443/cl_db_prd_x?secure=true"
	if accountURL != want {
		t.Fatalf("account url = %q, want %q", accountURL, want)
	}

	// The account URL must parse back with the same credentials and database
	opts, err := clickhouse.ParseDSN(accountURL)
	if err != nil {
		t.Fatalf("driver rejected account url: %v", err)
	}
	if opts.Auth.Username != "cl_usr_prd_x" || opts.Auth.Password != "Pass~word.123" || opts.Auth.Database != "cl_db_prd_x" {
		t.Fatalf("account url round trip lost fields: %+v", opts.Auth)
	}
}

func TestAccountURLsBindingHostname(t *testing.T) {
	accountURL, directURL, err := clickhouseAccountURLs(
		"clickhouse://admin:secret@localhost:9000/default",
		"user1", "pw", "db1", "host.docker.internal")
	if err != nil {
		t.Fatalf("clickhouseAccountURLs returned error: %v", err)
	}
	if !strings.Contains(accountURL, "@host.docker.internal:9000/db1") {
		t.Fatalf("account url did not apply binding hostname: %q", accountURL)
	}
	if !strings.Contains(directURL, "@localhost:9000/db1") {
		t.Fatalf("direct url should keep the service hostname: %q", directURL)
	}
}

func TestOnClusterClause(t *testing.T) {
	b := &ClickHouseServiceBinding{serviceConfig: map[string]string{}}
	if clause := b.onCluster(); clause != "" {
		t.Fatalf("onCluster without config = %q, want empty", clause)
	}
	b.serviceConfig["cluster"] = "main_cluster"
	if clause := b.onCluster(); clause != ` ON CLUSTER "main_cluster"` {
		t.Fatalf("onCluster = %q, want ON CLUSTER clause", clause)
	}
}

func TestQuoteClickhouseIdent(t *testing.T) {
	if got := quoteClickhouseIdent(`we"ird`); got != `"we""ird"` {
		t.Fatalf("quoteClickhouseIdent = %q, want doubled quote", got)
	}
}
