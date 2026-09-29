// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

package main

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	binding "github.com/openrundev/openrun/pkg/binding"
)

// Runs only against an explicitly supplied test endpoint. All generated
// accounts and databases are removed, including after a failed assertion.
func TestClickHouseSecurityIntegration(t *testing.T) {
	endpoint := os.Getenv("BINDINGS_TEST_CLICKHOUSE_URL")
	if endpoint == "" {
		t.Skip("BINDINGS_TEST_CLICKHOUSE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	b := &ClickHouseServiceBinding{}
	if err := b.InitializeService(ctx, binding.NewLogger("error"), map[string]string{"url": endpoint}, binding.ServiceBindingRuntime{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.CloseService(context.Background()) })
	create := func(id string, base *binding.BindingMetadata) map[string]string {
		account, artifacts, err := b.GenerateAccount(ctx, id, "", binding.BindingMetadata{}, base, false)
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			for i := len(artifacts) - 1; i >= 0; i-- {
				if err := b.DeleteArtifact(cleanupCtx, artifacts[i]); err != nil {
					t.Error(err)
				}
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		return account
	}
	suffix, err := binding.RandomHex(8)
	if err != nil {
		t.Fatal(err)
	}
	base := create("bnd_review"+suffix, nil)
	derived := create("bnd_reviewderived"+suffix, &binding.BindingMetadata{Account: base})
	baseDB, err := sql.Open("clickhouse", base["url_direct"])
	if err != nil {
		t.Fatal(err)
	}
	defer baseDB.Close() //nolint:errcheck
	derivedDB, err := sql.Open("clickhouse", derived["url_direct"])
	if err != nil {
		t.Fatal(err)
	}
	defer derivedDB.Close() //nolint:errcheck
	run := func(query string) {
		t.Helper()
		if _, err := baseDB.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	read := binding.BindingGrant{GrantType: binding.GrantTypeRead, GrantTarget: "revoked_table"}
	run("CREATE TABLE revoked_table (n UInt64) ENGINE=Memory")
	metadata := binding.BindingMetadata{Grants: []string{"read:revoked_table"}}
	result, err := b.ApplyGrants(ctx, derived, metadata, binding.BindingMetadata{}, false)
	if err != nil || len(result.Granted) != 1 {
		t.Fatalf("grant: %+v %v", result, err)
	}
	var n uint64
	if err := derivedDB.QueryRowContext(ctx, "SELECT count() FROM revoked_table").Scan(&n); err != nil {
		t.Fatal(err)
	}
	run("DROP TABLE revoked_table")
	if err := b.RevokeGrants(ctx, derived, binding.BindingMetadata{}, []binding.BindingGrant{read}, nil); err != nil {
		t.Fatal(err)
	}
	run("CREATE TABLE revoked_table (n UInt64) ENGINE=Memory")
	if err := derivedDB.QueryRowContext(ctx, "SELECT count() FROM revoked_table").Scan(&n); err == nil {
		t.Fatal("revoked permission returned after table recreation")
	}

	// A backslash must remain part of the exact table name and cannot escape
	// the identifier delimiter in an admin GRANT statement.
	target := `literal\" TO review_attacker --`
	safeIdent := `"` + strings.ReplaceAll(strings.ReplaceAll(target, `\`, `\\`), `"`, `""`) + `"`
	run("CREATE TABLE " + safeIdent + " (n UInt64) ENGINE=Memory")
	_, err = b.ApplyGrants(ctx, derived, binding.BindingMetadata{Grants: []string{"read:" + target}}, binding.BindingMetadata{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := derivedDB.QueryRowContext(ctx, "SELECT count() FROM "+safeIdent).Scan(&n); err != nil {
		t.Fatal(err)
	}

	// An invalid later grant must not leave a preceding full:* in effect.
	_, err = b.ApplyGrants(ctx, derived, binding.BindingMetadata{Grants: []string{"full:*", "create:unsupported"}}, binding.BindingMetadata{}, false)
	if err == nil {
		t.Fatal("invalid update succeeded")
	}
	if _, err := derivedDB.ExecContext(ctx, "INSERT INTO revoked_table VALUES (1)"); err == nil {
		t.Fatal("failed update leaked write access")
	}
}
