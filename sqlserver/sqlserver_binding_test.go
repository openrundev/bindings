// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

package main

import (
	"strings"
	"testing"

	"github.com/microsoft/go-mssqldb/msdsn"
)

func TestQuoteSqlserverIdent(t *testing.T) {
	tests := []struct{ in, want string }{
		{"users", "[users]"},
		{"cl_sch_prd_bnd_abc", "[cl_sch_prd_bnd_abc]"},
		{"we]ird", "[we]]ird]"},
		{"a]]b", "[a]]]]b]"},
		{"", "[]"},
	}
	for _, tt := range tests {
		if got := quoteSqlserverIdent(tt.in); got != tt.want {
			t.Errorf("quoteSqlserverIdent(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestQuoteSqlserverString(t *testing.T) {
	tests := []struct{ in, want string }{
		{"secret", "N'secret'"},
		{"it's", "N'it''s'"},
		{"a''b", "N'a''''b'"},
		{"", "N''"},
	}
	for _, tt := range tests {
		if got := quoteSqlserverString(tt.in); got != tt.want {
			t.Errorf("quoteSqlserverString(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSqlserverDatabaseFromURL(t *testing.T) {
	db, err := sqlserverDatabaseFromURL("sqlserver://sa:pw@localhost:1433?database=appdb")
	if err != nil || db != "appdb" {
		t.Fatalf("db = %q, err = %v", db, err)
	}

	// The database query parameter is required
	if _, err := sqlserverDatabaseFromURL("sqlserver://sa:pw@localhost:1433"); err == nil ||
		!strings.Contains(err.Error(), "database query parameter") {
		t.Fatalf("expected missing database error, got %v", err)
	}

	// Non-sqlserver schemes are rejected
	if _, err := sqlserverDatabaseFromURL("postgres://localhost/db"); err == nil ||
		!strings.Contains(err.Error(), "unsupported sqlserver url scheme") {
		t.Fatalf("expected scheme error, got %v", err)
	}

	// Unparsable URL
	if _, err := sqlserverDatabaseFromURL("sqlserver://sa:pw@local host"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestSQLServerAccountURLsRemoveAdminCredentials(t *testing.T) {
	for _, query := range []string{"user+id=sa&password=admin-secret", "UID=sa&PWD=admin-secret", "User=sa&Password=admin-secret&Change+Password=next-secret"} {
		appURL, directURL, err := sqlserverAccountURLs("sqlserver://localhost:1433?database=appdb&encrypt=true&"+query, "binding_login", "binding-password", "app-host")
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []string{appURL, directURL} {
			cfg, err := msdsn.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.User != "binding_login" || cfg.Password != "binding-password" || cfg.Database != "appdb" || cfg.ChangePassword != "" {
				t.Fatalf("unexpected config: %+v", cfg)
			}
			if strings.Contains(raw, "admin-secret") || strings.Contains(raw, "next-secret") {
				t.Fatal("admin secret leaked")
			}
		}
	}
}
