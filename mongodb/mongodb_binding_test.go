// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	binding "github.com/openrundev/openrun/pkg/binding"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/openrundev/openrun/pkg/binding/bindingtest"
)

func TestMongoAccountNames(t *testing.T) {
	bindingId := "bnd_2b7Ho4WrbGF3RTqxCFHRWmjfPqM" // bnd_ + 27-char ksuid
	user, db := mongoAccountNames(bindingId, false)
	if user != "cl_usr_prd_"+bindingId {
		t.Fatalf("prod user = %q", user)
	}
	if db != "cl_prd_"+bindingId {
		t.Fatalf("prod db = %q", db)
	}
	if len(db) >= 64 {
		t.Fatalf("db name %q exceeds the 64-byte limit", db)
	}

	user, db = mongoAccountNames(bindingId, true)
	if user != "cl_usr_stg_"+bindingId {
		t.Fatalf("staging user = %q", user)
	}
	if db != "cl_stg_"+bindingId {
		t.Fatalf("staging db = %q", db)
	}
}

func TestBuildMongoAccountURL(t *testing.T) {
	accountURL, err := buildMongoAccountURL("mongodb://admin:secret@localhost:27017/?directConnection=true", "cl_user", "p@ss", "cl_db", "")
	if err != nil {
		t.Fatalf("buildMongoAccountURL() error = %v", err)
	}
	bindingtest.AssertURL(t, accountURL, "mongodb", "localhost:27017", "cl_user", "p@ss", "/cl_db", map[string]string{
		"directConnection": "true",
		"authSource":       "admin",
	})

	bindingURL, err := buildMongoAccountURL("mongodb://admin:secret@localhost:27017/", "cl_user", "p@ss", "cl_db", "host.docker.internal")
	if err != nil {
		t.Fatalf("buildMongoAccountURL() with binding hostname error = %v", err)
	}
	bindingtest.AssertURL(t, bindingURL, "mongodb", "host.docker.internal:27017", "cl_user", "p@ss", "/cl_db", map[string]string{
		"authSource": "admin",
	})

	disabledURL, err := buildMongoAccountURL("mongodb://admin:secret@localhost:27017/", "cl_user", "p@ss", "cl_db", "disable")
	if err != nil {
		t.Fatalf("buildMongoAccountURL() with disabled binding hostname error = %v", err)
	}
	bindingtest.AssertURL(t, disabledURL, "mongodb", "localhost:27017", "cl_user", "p@ss", "/cl_db", map[string]string{
		"authSource": "admin",
	})

	// A mongodb+srv host is never rewritten, even with a binding hostname
	srvURL, err := buildMongoAccountURL("mongodb+srv://cluster0.example.mongodb.net/?retryWrites=true", "cl_user", "p@ss", "cl_db", "host.docker.internal")
	if err != nil {
		t.Fatalf("buildMongoAccountURL() with srv url error = %v", err)
	}
	bindingtest.AssertURL(t, srvURL, "mongodb+srv", "cluster0.example.mongodb.net", "cl_user", "p@ss", "/cl_db", map[string]string{
		"retryWrites": "true",
		"authSource":  "admin",
	})

	if _, err := buildMongoAccountURL("mongodb://h1:27017,h2:27018/", "u", "p", "db", ""); err == nil {
		t.Fatal("expected error for multi-host url")
	}
	if _, err := buildMongoAccountURL("postgres://localhost/db", "u", "p", "db", ""); err == nil {
		t.Fatal("expected error for non-mongodb scheme")
	}
}

func TestValidateMongoServiceURL(t *testing.T) {
	if err := validateMongoServiceURL("mongodb://localhost:27017/"); err != nil {
		t.Fatalf("single host url error = %v", err)
	}
	if err := validateMongoServiceURL("mongodb+srv://cluster0.example.mongodb.net/"); err != nil {
		t.Fatalf("srv url error = %v", err)
	}
	if err := validateMongoServiceURL("mongodb://h1,h2/"); err == nil {
		t.Fatal("expected error for multi-host url")
	}
	if err := validateMongoServiceURL("redis://localhost/"); err == nil {
		t.Fatal("expected error for non-mongodb scheme")
	}
}

func TestBuildMongoRolePrivileges(t *testing.T) {
	grants := []binding.BindingGrant{
		{GrantType: binding.GrantTypeRead, GrantTarget: binding.GrantTargetAll},
		{GrantType: binding.GrantTypeFull, GrantTarget: "orders"},
		{GrantType: binding.GrantTypeRead, GrantTarget: "orders"}, // merged into the full privilege
	}
	privileges, err := buildMongoRolePrivileges("cl_db", grants)
	if err != nil {
		t.Fatalf("buildMongoRolePrivileges() error = %v", err)
	}
	if len(privileges) != 2 {
		t.Fatalf("privileges length = %d, want 2; %v", len(privileges), privileges)
	}

	dbPriv := privileges[0].(bson.D)
	resource := dbPriv[0].Value.(bson.D)
	if resource[0].Value != "cl_db" || resource[1].Value != "" {
		t.Fatalf("db privilege resource = %v", resource)
	}
	dbActions := dbPriv[1].Value.([]string)
	for _, action := range []string{"find", "listCollections", "dbStats"} {
		if !slices.Contains(dbActions, action) {
			t.Fatalf("db actions %v missing %s", dbActions, action)
		}
	}
	if slices.Contains(dbActions, "insert") {
		t.Fatalf("read:* actions %v must not include insert", dbActions)
	}

	collPriv := privileges[1].(bson.D)
	resource = collPriv[0].Value.(bson.D)
	if resource[0].Value != "cl_db" || resource[1].Value != "orders" {
		t.Fatalf("collection privilege resource = %v", resource)
	}
	collActions := collPriv[1].Value.([]string)
	for _, action := range []string{"find", "insert", "update", "remove"} {
		if !slices.Contains(collActions, action) {
			t.Fatalf("collection actions %v missing %s", collActions, action)
		}
	}
	for _, action := range []string{"listCollections", "renameCollectionSameDB"} {
		if slices.Contains(collActions, action) {
			t.Fatalf("collection actions %v must not include database-level action %s", collActions, action)
		}
	}

	if _, err := buildMongoRolePrivileges("cl_db", []binding.BindingGrant{{GrantType: binding.GrantTypeRead, GrantTarget: "bad$name"}}); err == nil {
		t.Fatal("expected error for invalid grant target")
	}
	if _, err := buildMongoRolePrivileges("cl_db", []binding.BindingGrant{{GrantType: binding.GrantTypeRead, GrantTarget: "system.users"}}); err == nil {
		t.Fatal("expected error for system collection target")
	}
	if _, err := buildMongoRolePrivileges("cl_db", []binding.BindingGrant{{GrantType: binding.GrantTypeRead, GrantTarget: ""}}); err == nil {
		t.Fatal("expected error for empty grant target")
	}
	if _, err := buildMongoRolePrivileges("cl_db", []binding.BindingGrant{{GrantType: binding.GrantTypeCreate, GrantTarget: binding.GrantTargetAll}}); err == nil {
		t.Fatal("expected error for create grant type")
	}

	privileges, err = buildMongoRolePrivileges("cl_db", nil)
	if err != nil {
		t.Fatalf("buildMongoRolePrivileges() with no grants error = %v", err)
	}
	if len(privileges) != 0 {
		t.Fatalf("privileges length = %d, want 0", len(privileges))
	}
}

func TestBuildAtlasRoles(t *testing.T) {
	baseline := atlasRole{RoleName: "read", DatabaseName: atlasBaselineDatabase, CollectionName: atlasBaselineCollection}

	roles, err := buildAtlasRoles("cl_db", nil)
	if err != nil {
		t.Fatalf("buildAtlasRoles() with no grants error = %v", err)
	}
	if !reflect.DeepEqual(roles, []atlasRole{baseline}) {
		t.Fatalf("no-grant roles = %v", roles)
	}

	grants := []binding.BindingGrant{
		{GrantType: binding.GrantTypeRead, GrantTarget: binding.GrantTargetAll},
		{GrantType: binding.GrantTypeFull, GrantTarget: "orders"},
		{GrantType: binding.GrantTypeRead, GrantTarget: binding.GrantTargetAll}, // duplicate
	}
	roles, err = buildAtlasRoles("cl_db", grants)
	if err != nil {
		t.Fatalf("buildAtlasRoles() error = %v", err)
	}
	want := []atlasRole{
		baseline,
		{RoleName: "read", DatabaseName: "cl_db"},
		{RoleName: "readWrite", DatabaseName: "cl_db", CollectionName: "orders"},
	}
	if !reflect.DeepEqual(roles, want) {
		t.Fatalf("roles = %v, want %v", roles, want)
	}

	if _, err := buildAtlasRoles("cl_db", []binding.BindingGrant{{GrantType: binding.GrantTypeCreate, GrantTarget: binding.GrantTargetAll}}); err == nil {
		t.Fatal("expected error for create grant type")
	}
	if _, err := buildAtlasRoles("cl_db", []binding.BindingGrant{{GrantType: binding.GrantTypeRead, GrantTarget: "a b"}}); err == nil {
		t.Fatal("expected error for invalid grant target")
	}
}

func TestParseMongoCommand(t *testing.T) {
	doc, err := parseMongoCommand(`{"insert": "t1", "documents": [{"k": "v"}]}`)
	if err != nil {
		t.Fatalf("parseMongoCommand() error = %v", err)
	}
	if doc[0].Key != "insert" || doc[0].Value != "t1" {
		t.Fatalf("first element = %v, command name must stay first", doc[0])
	}

	// Canonical extended JSON is accepted too
	doc, err = parseMongoCommand(`{"find": "t1", "limit": {"$numberLong": "5"}}`)
	if err != nil {
		t.Fatalf("parseMongoCommand() extended json error = %v", err)
	}
	if doc[1].Value != int64(5) {
		t.Fatalf("limit = %v (%T), want int64 5", doc[1].Value, doc[1].Value)
	}

	if _, err := parseMongoCommand("not json"); err == nil {
		t.Fatal("expected error for invalid json")
	}
	if _, err := parseMongoCommand("{}"); err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestMongoResultToJSONMap(t *testing.T) {
	rawBytes, err := bson.Marshal(bson.D{{Key: "ok", Value: 1.0}, {Key: "n", Value: int32(2)}})
	if err != nil {
		t.Fatalf("bson.Marshal() error = %v", err)
	}
	result, err := mongoResultToJSONMap(bson.Raw(rawBytes))
	if err != nil {
		t.Fatalf("mongoResultToJSONMap() error = %v", err)
	}
	if result["ok"] != 1.0 || result["n"] != 2.0 {
		t.Fatalf("result = %v", result)
	}
}

// atlasStubRequest is one request captured by the Atlas API stub server.
type atlasStubRequest struct {
	Method string
	Path   string
	Body   []byte
	Auth   string
}

// newAtlasStub starts an httptest server that answers Atlas Admin API calls
// with the given status per "METHOD path" key (default 200) and records the
// requests. The stub answers requests without digest challenges; digest
// challenge handling is covered by TestAtlasDigestAuth.
func newAtlasStub(t *testing.T, statuses map[string]int) (*httptest.Server, *[]atlasStubRequest) {
	t.Helper()
	requests := &[]atlasStubRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*requests = append(*requests, atlasStubRequest{Method: r.Method, Path: r.URL.Path, Body: body, Auth: r.Header.Get("Authorization")})
		status := statuses[r.Method+" "+r.URL.Path]
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(`{"errorCode": "STUB", "detail": "stub response"}`)) //nolint:errcheck
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func newAtlasTestBinding(serverURL string, config map[string]string) *MongoServiceBinding {
	serviceConfig := map[string]string{
		"url":        "mongodb+srv://cluster0.example.mongodb.net/",
		"project_id": "proj1",
	}
	maps.Copy(serviceConfig, config)
	return &MongoServiceBinding{
		Logger:        binding.NewLogger("WARN"),
		isAtlas:       true,
		serviceConfig: serviceConfig,
		atlasClient:   newAtlasDigestClient(serverURL, "proj1", "pk", "sk"),
		userWaitSecs:  0,
	}
}

func TestAtlasGenerateAccount(t *testing.T) {
	server, requests := newAtlasStub(t, map[string]int{"POST /api/atlas/v2/groups/proj1/databaseUsers": http.StatusCreated})
	b := newAtlasTestBinding(server.URL, map[string]string{"cluster_name": "Cluster0"})

	account, artifacts, err := b.GenerateAccount(context.Background(), "bnd_base1", "/app1", binding.BindingMetadata{}, nil, false)
	if err != nil {
		t.Fatalf("GenerateAccount() error = %v", err)
	}
	if len(artifacts) != 1 || artifacts[0].Type != binding.ArtifactUser || artifacts[0].Name != "cl_usr_prd_bnd_base1" {
		t.Fatalf("artifacts = %v", artifacts)
	}
	if account["username"] != "cl_usr_prd_bnd_base1" || account["database"] != "cl_prd_bnd_base1" {
		t.Fatalf("account = %v", account)
	}
	if account["url"] != account["url_direct"] {
		t.Fatalf("atlas url %q and url_direct %q must match", account["url"], account["url_direct"])
	}
	bindingtest.AssertURL(t, account["url"], "mongodb+srv", "cluster0.example.mongodb.net", "cl_usr_prd_bnd_base1", account["password"], "/cl_prd_bnd_base1", map[string]string{
		"authSource": "admin",
	})

	if len(*requests) != 1 {
		t.Fatalf("requests = %v", *requests)
	}
	var user atlasDatabaseUser
	if err := json.Unmarshal((*requests)[0].Body, &user); err != nil {
		t.Fatalf("error decoding request body: %v", err)
	}
	if user.DatabaseName != "admin" || user.Username != "cl_usr_prd_bnd_base1" || user.Password != account["password"] {
		t.Fatalf("posted user = %+v", user)
	}
	wantRoles := []atlasRole{
		{RoleName: "readWrite", DatabaseName: "cl_prd_bnd_base1"},
		{RoleName: "dbAdmin", DatabaseName: "cl_prd_bnd_base1"},
	}
	if !reflect.DeepEqual(user.Roles, wantRoles) {
		t.Fatalf("posted roles = %v, want %v", user.Roles, wantRoles)
	}
	if !reflect.DeepEqual(user.Scopes, []atlasScope{{Name: "Cluster0", Type: "CLUSTER"}}) {
		t.Fatalf("posted scopes = %v", user.Scopes)
	}
}

func TestAtlasGenerateAccountDerived(t *testing.T) {
	server, requests := newAtlasStub(t, map[string]int{"POST /api/atlas/v2/groups/proj1/databaseUsers": http.StatusCreated})
	b := newAtlasTestBinding(server.URL, nil)

	derivedFrom := binding.BindingMetadata{Account: map[string]string{"database": "cl_prd_bnd_base1"}}
	account, artifacts, err := b.GenerateAccount(context.Background(), "bnd_drv1", "/app2", binding.BindingMetadata{}, &derivedFrom, true)
	if err != nil {
		t.Fatalf("GenerateAccount() error = %v", err)
	}
	if account["username"] != "cl_usr_stg_bnd_drv1" || account["database"] != "cl_prd_bnd_base1" {
		t.Fatalf("account = %v", account)
	}
	if len(artifacts) != 1 || artifacts[0].Name != "cl_usr_stg_bnd_drv1" {
		t.Fatalf("artifacts = %v", artifacts)
	}

	var user atlasDatabaseUser
	if err := json.Unmarshal((*requests)[0].Body, &user); err != nil {
		t.Fatalf("error decoding request body: %v", err)
	}
	// A fresh derived user holds only the placeholder role
	wantRoles := []atlasRole{{RoleName: "read", DatabaseName: atlasBaselineDatabase, CollectionName: atlasBaselineCollection}}
	if !reflect.DeepEqual(user.Roles, wantRoles) {
		t.Fatalf("posted roles = %v, want %v", user.Roles, wantRoles)
	}
	if user.Scopes != nil {
		t.Fatalf("posted scopes = %v, want none", user.Scopes)
	}

	// Duplicate user: POST returns 409, no artifacts to clean up
	server409, _ := newAtlasStub(t, map[string]int{"POST /api/atlas/v2/groups/proj1/databaseUsers": http.StatusConflict})
	b409 := newAtlasTestBinding(server409.URL, nil)
	_, artifacts, err = b409.GenerateAccount(context.Background(), "bnd_drv1", "/app2", binding.BindingMetadata{}, &derivedFrom, true)
	if err == nil {
		t.Fatal("expected error for duplicate user")
	}
	if len(artifacts) != 0 {
		t.Fatalf("artifacts = %v, want none", artifacts)
	}
}

func TestAtlasApplyGrants(t *testing.T) {
	userPath := "/api/atlas/v2/groups/proj1/databaseUsers/admin/cl_usr_prd_bnd_drv1"
	server, requests := newAtlasStub(t, nil)
	b := newAtlasTestBinding(server.URL, nil)

	account := map[string]string{"username": "cl_usr_prd_bnd_drv1", "database": "cl_prd_bnd_base1", "password": "pw"}
	bindingMetadata := binding.BindingMetadata{
		Grants:        []string{"read:*", "full:orders"},
		GrantsApplied: []binding.BindingGrant{{GrantType: binding.GrantTypeRead, GrantTarget: "sess"}},
	}
	result, err := b.ApplyGrants(context.Background(), account, bindingMetadata, binding.BindingMetadata{}, false)
	if err != nil {
		t.Fatalf("ApplyGrants() error = %v", err)
	}

	wantApplied := []binding.BindingGrant{
		{GrantType: binding.GrantTypeRead, GrantTarget: "sess"},
		{GrantType: binding.GrantTypeRead, GrantTarget: binding.GrantTargetAll},
		{GrantType: binding.GrantTypeFull, GrantTarget: "orders"},
	}
	if !reflect.DeepEqual(result.GrantsApplied, wantApplied) {
		t.Fatalf("GrantsApplied = %v, want %v", result.GrantsApplied, wantApplied)
	}
	if !reflect.DeepEqual(result.PendingRevokes, []binding.BindingGrant{{GrantType: binding.GrantTypeRead, GrantTarget: "sess"}}) {
		t.Fatalf("PendingRevokes = %v", result.PendingRevokes)
	}
	if !reflect.DeepEqual(result.Granted, wantApplied[1:]) {
		t.Fatalf("Granted = %v", result.Granted)
	}

	if len(*requests) != 1 || (*requests)[0].Method != http.MethodPatch || (*requests)[0].Path != userPath {
		t.Fatalf("requests = %v", *requests)
	}
	var patch struct {
		Roles []atlasRole `json:"roles"`
	}
	if err := json.Unmarshal((*requests)[0].Body, &patch); err != nil {
		t.Fatalf("error decoding request body: %v", err)
	}
	// The union of applied and desired grants: pending revokes stay in effect
	wantRoles := []atlasRole{
		{RoleName: "read", DatabaseName: atlasBaselineDatabase, CollectionName: atlasBaselineCollection},
		{RoleName: "read", DatabaseName: "cl_prd_bnd_base1", CollectionName: "sess"},
		{RoleName: "read", DatabaseName: "cl_prd_bnd_base1"},
		{RoleName: "readWrite", DatabaseName: "cl_prd_bnd_base1", CollectionName: "orders"},
	}
	if !reflect.DeepEqual(patch.Roles, wantRoles) {
		t.Fatalf("patched roles = %v, want %v", patch.Roles, wantRoles)
	}
}

func TestAtlasApplyGrantsRecreatesDeletedUser(t *testing.T) {
	userPath := "/api/atlas/v2/groups/proj1/databaseUsers/admin/cl_usr_prd_bnd_drv1"
	server, requests := newAtlasStub(t, map[string]int{
		"PATCH " + userPath:                             http.StatusNotFound,
		"POST /api/atlas/v2/groups/proj1/databaseUsers": http.StatusCreated,
	})
	b := newAtlasTestBinding(server.URL, nil)

	account := map[string]string{"username": "cl_usr_prd_bnd_drv1", "database": "cl_prd_bnd_base1", "password": "pw"}
	bindingMetadata := binding.BindingMetadata{Grants: []string{"read:*"}}
	if _, err := b.ApplyGrants(context.Background(), account, bindingMetadata, binding.BindingMetadata{}, true); err != nil {
		t.Fatalf("ApplyGrants() error = %v", err)
	}

	if len(*requests) != 2 || (*requests)[1].Method != http.MethodPost {
		t.Fatalf("requests = %v", *requests)
	}
	var user atlasDatabaseUser
	if err := json.Unmarshal((*requests)[1].Body, &user); err != nil {
		t.Fatalf("error decoding request body: %v", err)
	}
	if user.Username != "cl_usr_prd_bnd_drv1" || user.Password != "pw" || len(user.Roles) != 2 {
		t.Fatalf("recreated user = %+v", user)
	}
}

// A recreated user must preserve the cluster_name scope: dropping it would
// silently widen the user's access to every cluster in the Atlas project.
func TestAtlasRecreatedUserPreservesClusterScope(t *testing.T) {
	userPath := "/api/atlas/v2/groups/proj1/databaseUsers/admin/cl_usr_prd_bnd_drv1"
	server, requests := newAtlasStub(t, map[string]int{
		"PATCH " + userPath:                             http.StatusNotFound,
		"POST /api/atlas/v2/groups/proj1/databaseUsers": http.StatusCreated,
	})
	b := newAtlasTestBinding(server.URL, map[string]string{"cluster_name": "Cluster0"})

	account := map[string]string{"username": "cl_usr_prd_bnd_drv1", "database": "cl_prd_bnd_base1", "password": "pw"}
	bindingMetadata := binding.BindingMetadata{Grants: []string{"read:*"}}
	if _, err := b.ApplyGrants(context.Background(), account, bindingMetadata, binding.BindingMetadata{}, true); err != nil {
		t.Fatalf("ApplyGrants() error = %v", err)
	}

	var user atlasDatabaseUser
	if err := json.Unmarshal((*requests)[1].Body, &user); err != nil {
		t.Fatalf("error decoding request body: %v", err)
	}
	if len(user.Scopes) != 1 || user.Scopes[0].Name != "Cluster0" || user.Scopes[0].Type != "CLUSTER" {
		t.Fatalf("recreated user scopes = %+v, cluster scope was dropped", user.Scopes)
	}
}

func TestAtlasRevokeGrants(t *testing.T) {
	userPath := "/api/atlas/v2/groups/proj1/databaseUsers/admin/cl_usr_prd_bnd_drv1"
	server, requests := newAtlasStub(t, nil)
	b := newAtlasTestBinding(server.URL, nil)

	account := map[string]string{"username": "cl_usr_prd_bnd_drv1", "database": "cl_prd_bnd_base1"}
	revokes := []binding.BindingGrant{{GrantType: binding.GrantTypeRead, GrantTarget: "sess"}}
	regrants := []binding.BindingGrant{{GrantType: binding.GrantTypeRead, GrantTarget: binding.GrantTargetAll}}
	if err := b.RevokeGrants(context.Background(), account, binding.BindingMetadata{}, revokes, regrants); err != nil {
		t.Fatalf("RevokeGrants() error = %v", err)
	}

	if len(*requests) != 1 || (*requests)[0].Method != http.MethodPatch || (*requests)[0].Path != userPath {
		t.Fatalf("requests = %v", *requests)
	}
	var patch struct {
		Roles []atlasRole `json:"roles"`
	}
	if err := json.Unmarshal((*requests)[0].Body, &patch); err != nil {
		t.Fatalf("error decoding request body: %v", err)
	}
	wantRoles := []atlasRole{
		{RoleName: "read", DatabaseName: atlasBaselineDatabase, CollectionName: atlasBaselineCollection},
		{RoleName: "read", DatabaseName: "cl_prd_bnd_base1"},
	}
	if !reflect.DeepEqual(patch.Roles, wantRoles) {
		t.Fatalf("patched roles = %v, want %v", patch.Roles, wantRoles)
	}

	// Empty revokes list is a no-op
	if err := b.RevokeGrants(context.Background(), account, binding.BindingMetadata{}, nil, regrants); err != nil {
		t.Fatalf("RevokeGrants() with no revokes error = %v", err)
	}
	if len(*requests) != 1 {
		t.Fatalf("no-op revoke made a request: %v", *requests)
	}
}

func TestAtlasDeleteArtifact(t *testing.T) {
	userPath := "/api/atlas/v2/groups/proj1/databaseUsers/admin/cl_usr_prd_bnd_drv1"
	server, requests := newAtlasStub(t, map[string]int{"DELETE " + userPath: http.StatusNotFound})
	b := newAtlasTestBinding(server.URL, nil)

	// An already-deleted user (404) is tolerated
	if err := b.DeleteArtifact(context.Background(), binding.Artifact{Type: binding.ArtifactUser, Name: "cl_usr_prd_bnd_drv1"}); err != nil {
		t.Fatalf("DeleteArtifact() 404 error = %v", err)
	}
	if len(*requests) != 1 || (*requests)[0].Method != http.MethodDelete {
		t.Fatalf("requests = %v", *requests)
	}

	if err := b.DeleteArtifact(context.Background(), binding.Artifact{Type: binding.ArtifactRole, Name: "r1"}); err == nil {
		t.Fatal("expected error for role artifact on atlas")
	}

	serverErr, _ := newAtlasStub(t, map[string]int{"DELETE " + userPath: http.StatusInternalServerError})
	bErr := newAtlasTestBinding(serverErr.URL, nil)
	if err := bErr.DeleteArtifact(context.Background(), binding.Artifact{Type: binding.ArtifactUser, Name: "cl_usr_prd_bnd_drv1"}); err == nil {
		t.Fatal("expected error for server failure")
	}
}

func TestAtlasDigestAuth(t *testing.T) {
	authed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="MMS Public API", domain="", nonce="abc123", algorithm=MD5, qop="auth", stale=false`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.Contains(auth, `username="pk"`) {
			t.Errorf("digest authorization %q missing username", auth)
		}
		authed = true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}")) //nolint:errcheck
	}))
	defer server.Close()

	client := newAtlasDigestClient(server.URL, "proj1", "pk", "sk")
	if err := client.verifyAccess(context.Background()); err != nil {
		t.Fatalf("verifyAccess() error = %v", err)
	}
	if !authed {
		t.Fatal("digest authorization was never sent")
	}
}

func TestAtlasOAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "tok1", "token_type": "Bearer", "expires_in": 3600}`)) //nolint:errcheck
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok1" {
			t.Errorf("authorization = %q, want Bearer tok1", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}")) //nolint:errcheck
	}))
	defer server.Close()

	client := newAtlasOAuthClient(server.URL, "proj1", "client1", "secret1")
	if err := client.verifyAccess(context.Background()); err != nil {
		t.Fatalf("verifyAccess() error = %v", err)
	}
}
