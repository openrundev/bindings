// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	binding "github.com/openrundev/openrun/pkg/binding"
)

// TestIntegrationDatabricksLifecycle exercises the full binding lifecycle
// against a live workspace: service init, base and derived account
// provisioning, grant enforcement, revoke and artifact cleanup. Gated on the
// TEST_DATABRICKS_* environment variables; skipped otherwise.
func TestIntegrationDatabricksLifecycle(t *testing.T) {
	host := os.Getenv("TEST_DATABRICKS_HOST")
	httpPath := os.Getenv("TEST_DATABRICKS_HTTP_PATH")
	token := os.Getenv("TEST_DATABRICKS_TOKEN")
	if host == "" || httpPath == "" || token == "" {
		t.Skip("TEST_DATABRICKS_HOST, TEST_DATABRICKS_HTTP_PATH and TEST_DATABRICKS_TOKEN are not set")
	}
	catalog := os.Getenv("TEST_DATABRICKS_CATALOG")
	if catalog == "" {
		catalog = "main"
	}

	// Generous deadline: a stopped serverless warehouse can take a while on
	// the first query.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	b := NewDatabricksServiceBinding()
	serviceConfig := map[string]string{
		"host":      host,
		"http_path": httpPath,
		"catalog":   catalog,
		"token":     token,
	}
	if credType := os.Getenv("TEST_DATABRICKS_CREDENTIAL_TYPE"); credType != "" {
		serviceConfig["account_credential_type"] = credType
	}
	if err := b.InitializeService(ctx, binding.NewLogger("DEBUG"), serviceConfig, binding.ServiceBindingRuntime{}); err != nil {
		t.Fatalf("InitializeService() error = %v", err)
	}
	defer b.CloseService(ctx) //nolint:errcheck

	suffix, err := binding.RandomHex(6)
	if err != nil {
		t.Fatal(err)
	}
	baseId := "bnd_it" + suffix
	derivedId := "bnd_id" + suffix

	deleteArtifacts := func(artifacts []binding.Artifact) {
		for i := len(artifacts) - 1; i >= 0; i-- {
			if err := b.DeleteArtifact(ctx, artifacts[i]); err != nil {
				t.Errorf("DeleteArtifact(%s %s) error = %v", artifacts[i].Type, artifacts[i].Name, err)
			}
		}
	}

	// Base account: schema + service principal with full schema access
	baseAccount, baseArtifacts, err := b.GenerateAccount(ctx, baseId, "/apps/it", binding.BindingMetadata{}, nil, false)
	defer deleteArtifacts(baseArtifacts)
	if err != nil {
		t.Fatalf("GenerateAccount(base) error = %v", err)
	}
	t.Logf("base account: schema=%s auth_type=%s client_id=%s", baseAccount["schema"], baseAccount["auth_type"], baseAccount["client_id"])
	for _, key := range []string{"url", "url_direct", "host", "http_path", "catalog", "schema", "auth_type", "client_id"} {
		if baseAccount[key] == "" {
			t.Fatalf("base account is missing %s: %v", key, baseAccount)
		}
	}
	if !strings.HasPrefix(baseAccount["schema"], "cl_sch_prd_") {
		t.Fatalf("base schema = %q, want cl_sch_prd_ prefix", baseAccount["schema"])
	}

	baseMeta := binding.BindingMetadata{Account: baseAccount}

	// The base account can create and use tables in its schema
	runBase := func(cmd string) (map[string]any, error) {
		return b.RunCommand(ctx, baseMeta, cmd)
	}
	if _, err := runBase("CREATE TABLE t1 (id INT, note STRING)"); err != nil {
		t.Fatalf("base create table error = %v", err)
	}
	if _, err := runBase("INSERT INTO t1 VALUES (1, 'base')"); err != nil {
		t.Fatalf("base insert error = %v", err)
	}
	result, err := runBase("SELECT count(*) AS n FROM t1")
	if err != nil {
		t.Fatalf("base select error = %v", err)
	}
	rows, _ := result["rows"].([]map[string]any)
	if len(rows) != 1 || fmt.Sprint(rows[0]["n"]) != "1" {
		t.Fatalf("base select rows = %#v", result["rows"])
	}

	// Derived account: no data access before grants
	derivedAccount, derivedArtifacts, err := b.GenerateAccount(ctx, derivedId, "/apps/itd", binding.BindingMetadata{},
		&baseMeta, false)
	defer deleteArtifacts(derivedArtifacts)
	if err != nil {
		t.Fatalf("GenerateAccount(derived) error = %v", err)
	}
	if derivedAccount["schema"] != baseAccount["schema"] {
		t.Fatalf("derived schema = %q, want base schema %q", derivedAccount["schema"], baseAccount["schema"])
	}
	derivedMeta := binding.BindingMetadata{Account: derivedAccount}
	if _, err := b.RunCommand(ctx, derivedMeta, "SELECT count(*) FROM t1"); err == nil {
		t.Fatal("derived select before grants should fail")
	}

	// read:* grants server-enforced read-only access, current and future tables
	grantMeta := binding.BindingMetadata{Account: derivedAccount, Grants: []string{"read:*"}}
	applyResult, err := b.ApplyGrants(ctx, derivedAccount, grantMeta, baseMeta, false)
	if err != nil {
		t.Fatalf("ApplyGrants(read:*) error = %v", err)
	}
	if len(applyResult.GrantsApplied) != 1 || len(applyResult.PendingRevokes) != 0 {
		t.Fatalf("ApplyGrants result = %#v", applyResult)
	}
	if _, err := b.RunCommand(ctx, derivedMeta, "SELECT count(*) FROM t1"); err != nil {
		t.Fatalf("derived select after read grant error = %v", err)
	}
	if _, err := b.RunCommand(ctx, derivedMeta, "INSERT INTO t1 VALUES (2, 'derived')"); err == nil {
		t.Fatal("derived insert with read grant should fail")
	}
	// Inheritance: a table created after the grant is readable without reapply
	if _, err := runBase("CREATE TABLE t2 (id INT)"); err != nil {
		t.Fatalf("base create t2 error = %v", err)
	}
	if _, err := b.RunCommand(ctx, derivedMeta, "SELECT count(*) FROM t2"); err != nil {
		t.Fatalf("derived select on future table error = %v", err)
	}

	// Revoking the read grant removes access
	if err := b.RevokeGrants(ctx, derivedAccount, baseMeta, applyResult.GrantsApplied, nil); err != nil {
		t.Fatalf("RevokeGrants error = %v", err)
	}
	if _, err := b.RunCommand(ctx, derivedMeta, "SELECT count(*) FROM t1"); err == nil {
		t.Fatal("derived select after revoke should fail")
	}
}
