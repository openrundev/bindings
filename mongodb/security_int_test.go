// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

package main

import (
	"context"
	"os"
	"testing"
	"time"

	binding "github.com/openrundev/openrun/pkg/binding"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Requires an isolated MongoDB test endpoint with enableTestCommands=1.
func TestMongoRestoreFailureRollsBackRole(t *testing.T) {
	endpoint := os.Getenv("BINDINGS_TEST_MONGODB_URL")
	if endpoint == "" {
		t.Skip("BINDINGS_TEST_MONGODB_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	b := &MongoServiceBinding{}
	if err := b.InitializeService(ctx, binding.NewLogger("error"), map[string]string{"url": endpoint}, binding.ServiceBindingRuntime{}); err != nil {
		t.Fatal(err)
	}
	defer b.CloseService(context.Background()) //nolint:errcheck
	suffix, err := binding.RandomHex(8)
	if err != nil {
		t.Fatal(err)
	}
	account, artifacts, err := b.GenerateAccount(ctx, "bnd_review"+suffix, "", binding.BindingMetadata{}, &binding.BindingMetadata{Account: map[string]string{"database": "review_" + suffix}}, false)
	defer func() {
		for i := len(artifacts) - 1; i >= 0; i-- {
			if err := b.DeleteArtifact(context.Background(), artifacts[i]); err != nil {
				t.Error(err)
			}
		}
	}()
	if err != nil {
		t.Fatal(err)
	}
	// Fail only the post-update usersInfo command; updateRole itself succeeds.
	failpoint := bson.D{
		{Key: "configureFailPoint", Value: "failCommand"},
		{Key: "mode", Value: bson.D{{Key: "times", Value: 1}}},
		{Key: "data", Value: bson.D{{Key: "failCommands", Value: bson.A{"usersInfo"}}, {Key: "errorCode", Value: 11600}}},
	}
	if err := b.adminClient.Database("admin").RunCommand(ctx, failpoint).Err(); err != nil {
		t.Fatal(err)
	}
	defer b.adminClient.Database("admin").RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}})
	_, err = b.ApplyGrants(ctx, account, binding.BindingMetadata{Grants: []string{"full:*"}}, binding.BindingMetadata{}, true)
	if err == nil {
		t.Fatal("expected user restoration to fail")
	}
	var result struct {
		Roles []struct {
			Privileges bson.A `bson:"privileges"`
		} `bson:"roles"`
	}
	err = b.adminClient.Database("admin").RunCommand(ctx, bson.D{
		{Key: "rolesInfo", Value: bson.D{{Key: "role", Value: account["username"]}, {Key: "db", Value: "admin"}}},
		{Key: "showPrivileges", Value: true},
	}).Decode(&result)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Roles) != 1 || len(result.Roles[0].Privileges) != 0 {
		t.Fatalf("failed reapply left privileges: %+v", result)
	}
}
