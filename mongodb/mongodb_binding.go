// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	binding "github.com/openrundev/openrun/pkg/binding"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoDB service binding, registered as two service types backed by one
// implementation:
//   - "mongodb": self-hosted servers. Users and custom roles are managed with
//     in-database commands (createUser/createRole/updateRole) over an admin
//     connection.
//   - "atlas": MongoDB Atlas, where those commands are blocked on the cluster
//     for every tier. Database users are project-level resources managed
//     through the Atlas Admin API instead (see mongodb_atlas_api.go).
//
// Isolation follows the mysql model: each base binding owns a dedicated
// database (created lazily by MongoDB on first write, so no database artifact
// is ever reported and data outlives the account). Derived bindings share the
// base binding's database with their own user.
//
// The permission model is where the two modes diverge:
//   - Self-hosted built-in roles are database-scoped only, so collection-level
//     grants need a custom role. Each derived binding gets one custom role
//     (same name as its user, created in the admin database so it can hold
//     privileges on the binding database) whose privileges array is atomically
//     rebuilt from the grants on every change.
//   - Atlas built-in read/readWrite roles accept a collection scope directly
//     in the user's roles array, which is atomically replaced via PATCH.
//     Atlas custom roles are avoided deliberately: an Atlas user holding a
//     custom role cannot hold any other role.
//
// Grant targets are exact collection names, not prefixes (unlike redis).
const (
	mongoUserPrefixProd = "cl_usr_prd_"
	mongoUserPrefixStg  = "cl_usr_stg_"
	mongoDBPrefixProd   = "cl_prd_"
	mongoDBPrefixStg    = "cl_stg_"

	// Database and collection used for the placeholder role that keeps a
	// derived Atlas user's roles array non-empty when it has no grants (the
	// API rejects users without roles). The placeholder is scoped to a
	// dedicated dummy database, never the binding database: a collection in
	// the real database could be created and would then be readable by every
	// derived user without a grant.
	atlasBaselineDatabase   = "cl_baseline_none_db"
	atlasBaselineCollection = "cl_baseline_none"

	// MongoDB error codes used for tolerated failures.
	mongoErrUnauthorized = 13
	mongoErrUserNotFound = 11
	mongoErrRoleNotFound = 31

	// How long GenerateAccount waits for a new Atlas user to propagate to the
	// cluster (changes take up to a couple of minutes to deploy); overridden
	// with the user_wait_secs service config key, 0 disables the wait.
	atlasDefaultUserWaitSecs = 120
	atlasUserPollInterval    = 5 * time.Second
)

// Privilege actions for the self-hosted custom roles. The collection lists
// apply to a specific collection resource; the DB lists are the extra actions
// only meaningful on the whole-database resource ({db, collection: ""}) used
// for `*` targets. Atlas Search index actions are omitted: search indexes are
// not available on plain self-hosted servers and the actions are unknown to
// older versions, which would reject the createRole.
var (
	mongoReadActionsColl = []string{"find", "changeStream", "collStats", "listIndexes"}
	mongoReadActionsDB   = []string{"listCollections", "dbStats"}

	mongoWriteActionsColl = []string{
		"insert", "update", "remove", "createCollection", "createIndex",
		"dropCollection", "dropIndex", "collMod", "convertToCapped",
	}
	mongoWriteActionsDB = []string{"renameCollectionSameDB"}
)

// mongoGrantTargetRegex limits grant targets to safe collection name
// characters. system.* collections are additionally rejected in
// validateMongoGrantTarget.
var mongoGrantTargetRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type MongoServiceBinding struct {
	*binding.Logger
	isAtlas       bool
	serviceConfig map[string]string
	adminClient   *mongo.Client // Self-hosted admin connection, available after InitializeService
	atlasClient   *atlasClient  // Atlas Admin API client, available after InitializeService
	userWaitSecs  int
}

var _ binding.ServiceBinding = (*MongoServiceBinding)(nil)

func (b *MongoServiceBinding) GetAccountEnv(ctx context.Context) ([]string, []string, error) {
	return []string{"url", "url_direct", "username", "password", "database"}, []string{}, nil
}

func (b *MongoServiceBinding) InitializeService(ctx context.Context, logger *binding.Logger, serviceConfig map[string]string, runtime binding.ServiceBindingRuntime) error {
	b.Logger = logger
	if b.isAtlas {
		return b.initAtlas(ctx, serviceConfig)
	}
	return b.initSelfHosted(ctx, serviceConfig, runtime)
}

func (b *MongoServiceBinding) initSelfHosted(ctx context.Context, serviceConfig map[string]string, runtime binding.ServiceBindingRuntime) error {
	if err := binding.VerifyKeys(slices.Collect(maps.Keys(serviceConfig)), []string{"url"}, []string{"binding_hostname"}); err != nil {
		return err
	}

	connURL := serviceConfig["url"]
	if err := validateMongoServiceURL(connURL); err != nil {
		return err
	}

	adminClient, err := mongo.Connect(options.Client().ApplyURI(connURL))
	if err != nil {
		return fmt.Errorf("error connecting to mongodb: %w", err)
	}
	if err := adminClient.Ping(ctx, nil); err != nil {
		adminClient.Disconnect(ctx) //nolint:errcheck
		return fmt.Errorf("error verifying mongodb connection: %w", err)
	}

	if err := checkMongoAuthorizationEnabled(ctx, connURL); err != nil {
		adminClient.Disconnect(ctx) //nolint:errcheck
		return err
	}

	b.serviceConfig = binding.ServiceConfigWithLocalhostBindingHostname(serviceConfig, connURL, runtime)
	b.adminClient = adminClient
	return nil
}

func (b *MongoServiceBinding) initAtlas(ctx context.Context, serviceConfig map[string]string) error {
	if err := binding.VerifyKeys(slices.Collect(maps.Keys(serviceConfig)), []string{"url", "project_id"},
		[]string{"public_key", "private_key", "client_id", "client_secret", "cluster_name", "api_base_url", "user_wait_secs"}); err != nil {
		return err
	}

	connURL := serviceConfig["url"]
	if err := validateMongoServiceURL(connURL); err != nil {
		return err
	}

	userWaitSecs := atlasDefaultUserWaitSecs
	if waitStr := serviceConfig["user_wait_secs"]; waitStr != "" {
		parsed, err := strconv.Atoi(waitStr)
		if err != nil || parsed < 0 {
			return fmt.Errorf("invalid user_wait_secs value %q: must be a non-negative integer", waitStr)
		}
		userWaitSecs = parsed
	}

	baseURL := strings.TrimSuffix(serviceConfig["api_base_url"], "/")
	if baseURL == "" {
		baseURL = atlasDefaultBaseURL
	}

	hasAPIKey := serviceConfig["public_key"] != "" || serviceConfig["private_key"] != ""
	hasServiceAccount := serviceConfig["client_id"] != "" || serviceConfig["client_secret"] != ""
	var client *atlasClient
	switch {
	case hasAPIKey && hasServiceAccount:
		return fmt.Errorf("configure either public_key/private_key or client_id/client_secret, not both")
	case hasAPIKey:
		if serviceConfig["public_key"] == "" || serviceConfig["private_key"] == "" {
			return fmt.Errorf("both public_key and private_key are required for api key auth")
		}
		client = newAtlasDigestClient(baseURL, serviceConfig["project_id"], serviceConfig["public_key"], serviceConfig["private_key"])
	case hasServiceAccount:
		if serviceConfig["client_id"] == "" || serviceConfig["client_secret"] == "" {
			return fmt.Errorf("both client_id and client_secret are required for service account auth")
		}
		client = newAtlasOAuthClient(baseURL, serviceConfig["project_id"], serviceConfig["client_id"], serviceConfig["client_secret"])
	default:
		return fmt.Errorf("atlas api credentials are required: public_key/private_key (api key) or client_id/client_secret (service account)")
	}

	if err := client.verifyAccess(ctx); err != nil {
		return fmt.Errorf("error verifying atlas api access: %w", err)
	}
	if err := checkMongoReachable(ctx, connURL); err != nil {
		return fmt.Errorf("error verifying atlas cluster connection: %w", err)
	}

	b.serviceConfig = serviceConfig
	b.atlasClient = client
	b.userWaitSecs = userWaitSecs
	return nil
}

func (b *MongoServiceBinding) CloseService(ctx context.Context) error {
	if b.adminClient == nil {
		return nil
	}
	return b.adminClient.Disconnect(ctx)
}

func (b *MongoServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata binding.BindingMetadata,
	derivedFromMetadata *binding.BindingMetadata, isStaging bool) (map[string]string, []binding.Artifact, error) {
	if err := binding.VerifyKeys(slices.Collect(maps.Keys(bindingMetadata.Config)), []string{}, []string{}); err != nil {
		return nil, nil, err
	}

	password, err := binding.RandomHex(32)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating random password: %w", err)
	}

	userName, databaseName := mongoAccountNames(bindingId, isStaging)
	if derivedFromMetadata != nil {
		// Derived binding, share the base binding's database
		databaseName = derivedFromMetadata.Account["database"]
		if databaseName == "" {
			return nil, nil, fmt.Errorf("derived binding base account is missing the database field")
		}
	}

	var artifacts []binding.Artifact
	if b.isAtlas {
		artifacts, err = b.generateAtlasAccount(ctx, userName, password, databaseName, derivedFromMetadata != nil)
	} else {
		artifacts, err = b.generateSelfHostedAccount(ctx, userName, password, databaseName, derivedFromMetadata != nil)
	}
	if err != nil {
		return nil, artifacts, err
	}

	accountDirectURL, err := buildMongoAccountURL(b.serviceConfig["url"], userName, password, databaseName, "")
	if err != nil {
		return nil, artifacts, fmt.Errorf("error building account url: %w", err)
	}
	accountURL, err := buildMongoAccountURL(b.serviceConfig["url"], userName, password, databaseName, b.serviceConfig["binding_hostname"])
	if err != nil {
		return nil, artifacts, fmt.Errorf("error building binding account url: %w", err)
	}

	return map[string]string{
		"url":        accountURL,
		"url_direct": accountDirectURL,
		"username":   userName,
		"password":   password,
		"database":   databaseName,
	}, artifacts, nil
}

// generateSelfHostedAccount creates the binding user (and for derived
// bindings its custom role) in the admin database, so account URLs uniformly
// use authSource=admin and a role can hold privileges on the binding
// database. User management commands are not transactional, so on partial
// failure the artifacts created so far are returned with the error for the
// caller to clean up. Duplicate users/roles fail naturally in createUser/
// createRole; no pre-check is needed.
func (b *MongoServiceBinding) generateSelfHostedAccount(ctx context.Context, userName, password, databaseName string, isDerived bool) ([]binding.Artifact, error) {
	artifacts := []binding.Artifact{}
	var userRoles bson.A
	if isDerived {
		// The derived binding user's only role is its own custom role, which
		// starts with no privileges: the user can authenticate but every data
		// command fails until ApplyGrants (called right after account
		// creation) populates the role.
		createRoleCmd := bson.D{
			{Key: "createRole", Value: userName},
			{Key: "privileges", Value: bson.A{}},
			{Key: "roles", Value: bson.A{}},
		}
		if err := b.adminClient.Database("admin").RunCommand(ctx, createRoleCmd).Err(); err != nil {
			return artifacts, fmt.Errorf("error creating role %s: %w", userName, err)
		}
		artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactRole, Name: userName})
		userRoles = bson.A{bson.D{{Key: "role", Value: userName}, {Key: "db", Value: "admin"}}}
	} else {
		// The base binding user gets full access to its own database.
		userRoles = bson.A{
			bson.D{{Key: "role", Value: "readWrite"}, {Key: "db", Value: databaseName}},
			bson.D{{Key: "role", Value: "dbAdmin"}, {Key: "db", Value: databaseName}},
		}
	}

	createUserCmd := bson.D{
		{Key: "createUser", Value: userName},
		{Key: "pwd", Value: password},
		{Key: "roles", Value: userRoles},
	}
	if err := b.adminClient.Database("admin").RunCommand(ctx, createUserCmd).Err(); err != nil {
		return artifacts, fmt.Errorf("error creating user %s: %w", userName, err)
	}
	artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactUser, Name: userName})
	return artifacts, nil
}

// generateAtlasAccount creates the project-level database user through the
// Atlas Admin API, then waits for the user to propagate to the cluster
// (changes deploy asynchronously). A duplicate user fails the POST with 409.
// newAtlasDatabaseUser builds the Atlas user payload, including the
// cluster_name scope when configured. All user-creation paths (initial
// creation and out-of-band 404 recreation) must go through this so a
// recreated user never silently loses its cluster scoping and widens to the
// whole project.
func (b *MongoServiceBinding) newAtlasDatabaseUser(userName, password string, roles []atlasRole) atlasDatabaseUser {
	user := atlasDatabaseUser{
		DatabaseName: atlasAuthDatabase,
		Username:     userName,
		Password:     password,
		Description:  "openrun service binding account",
		Roles:        roles,
	}
	if clusterName := b.serviceConfig["cluster_name"]; clusterName != "" {
		user.Scopes = []atlasScope{{Name: clusterName, Type: "CLUSTER"}}
	}
	return user
}

func (b *MongoServiceBinding) generateAtlasAccount(ctx context.Context, userName, password, databaseName string, isDerived bool) ([]binding.Artifact, error) {
	var roles []atlasRole
	var err error
	if isDerived {
		// Grants are applied right after account creation; until then the
		// user holds only the placeholder role (the API rejects an empty
		// roles array).
		roles, err = buildAtlasRoles(databaseName, nil)
		if err != nil {
			return nil, err
		}
	} else {
		roles = atlasBaseRoles(databaseName)
	}

	user := b.newAtlasDatabaseUser(userName, password, roles)

	if err := b.atlasClient.createDatabaseUser(ctx, user); err != nil {
		return nil, fmt.Errorf("error creating atlas user %s: %w", userName, err)
	}
	artifacts := []binding.Artifact{{Type: binding.ArtifactUser, Name: userName}}

	if err := b.waitForAtlasUser(ctx, userName, password); err != nil {
		// The user exists in the project but never became usable on the
		// cluster; return the artifact so the caller's rollback removes it.
		return artifacts, err
	}
	return artifacts, nil
}

// waitForAtlasUser polls the cluster authenticating as the new user until the
// change has propagated (or the configured wait is exhausted).
func (b *MongoServiceBinding) waitForAtlasUser(ctx context.Context, userName, password string) error {
	if b.userWaitSecs == 0 {
		return nil
	}

	userURL, err := buildMongoAccountURL(b.serviceConfig["url"], userName, password, atlasAuthDatabase, "")
	if err != nil {
		return fmt.Errorf("error building atlas user url: %w", err)
	}

	deadline := time.Now().Add(time.Duration(b.userWaitSecs) * time.Second)
	var lastErr error
	for {
		lastErr = pingMongoURL(ctx, userURL)
		if lastErr == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for atlas user %s to become usable: %w", userName, lastErr)
		}
		b.Debug().Err(lastErr).Msgf("waiting for atlas user %s to propagate", userName)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(atlasUserPollInterval):
		}
	}
}

// DeleteArtifact deletes one user or custom role previously reported as
// created by GenerateAccount. Data in the binding's database is not touched;
// like the other bindings, data outlives the account. Already-deleted
// artifacts are tolerated so a rollback retry is harmless.
func (b *MongoServiceBinding) DeleteArtifact(ctx context.Context, artifact binding.Artifact) error {
	if artifact.Name == "" {
		return fmt.Errorf("artifact name is required")
	}

	if b.isAtlas {
		if artifact.Type != binding.ArtifactUser {
			return fmt.Errorf("unsupported atlas artifact type %s", artifact.Type)
		}
		if err := b.atlasClient.deleteDatabaseUser(ctx, artifact.Name); err != nil && atlasErrorStatus(err) != 404 {
			return fmt.Errorf("error deleting atlas user %s: %w", artifact.Name, err)
		}
		return nil
	}

	switch artifact.Type {
	case binding.ArtifactUser:
		err := b.adminClient.Database("admin").RunCommand(ctx, bson.D{{Key: "dropUser", Value: artifact.Name}}).Err()
		if err != nil && !isMongoErrCode(err, mongoErrUserNotFound) {
			return fmt.Errorf("error dropping user %s: %w", artifact.Name, err)
		}
	case binding.ArtifactRole:
		err := b.adminClient.Database("admin").RunCommand(ctx, bson.D{{Key: "dropRole", Value: artifact.Name}}).Err()
		if err != nil && !isMongoErrCode(err, mongoErrRoleNotFound) {
			return fmt.Errorf("error dropping role %s: %w", artifact.Name, err)
		}
	default:
		return fmt.Errorf("unsupported mongodb artifact type %s", artifact.Type)
	}
	return nil
}

// ApplyGrants rebuilds the derived account's complete permission set (the
// custom role's privileges for self-hosted, the user's roles array for Atlas)
// in one atomic operation, from the union of the currently applied and the
// desired grants. The union keeps this additive, per the interface contract:
// grants no longer desired are reported in PendingRevokes but stay in effect
// until the caller runs RevokeGrants after its metadata transaction commits.
// The full set is applied every time, so reapplyAll needs no special grant
// handling and nothing is ever deferred (a grant target is just a collection
// name, it does not need to exist); reapplyAll additionally restores a
// self-hosted user that was dropped out-of-band (the role is restored by the
// updateRole upsert in setUserGrants, and an externally deleted Atlas user is
// recreated by the 404 fallback there).
func (b *MongoServiceBinding) ApplyGrants(ctx context.Context, account map[string]string, bindingMetadata binding.BindingMetadata,
	derivedFromMetadata binding.BindingMetadata, reapplyAll bool) (binding.GrantApplyResult, error) {
	return binding.ApplyGrantsRebuild(bindingMetadata,
		[]binding.GrantType{binding.GrantTypeRead, binding.GrantTypeFull},
		func(grantsApplied []binding.BindingGrant) error {
			if err := b.setUserGrants(ctx, account, grantsApplied); err != nil {
				return err
			}
			if !b.isAtlas && reapplyAll {
				// After the role upsert, so the recreated user's role reference resolves
				if err := b.restoreSelfHostedUser(ctx, account); err != nil {
					return err
				}
			}
			return nil
		})
}

// RevokeGrants removes grants that are no longer desired. Every caller path
// maintains the invariant that the account's remaining grants after the
// revoke equal exactly the regrants list, so the permission set is rebuilt
// from regrants in one atomic operation. Kept grants are never transiently
// revoked, and revoking a grant that was never applied is naturally harmless.
func (b *MongoServiceBinding) RevokeGrants(ctx context.Context, account map[string]string,
	derivedFromMetadata binding.BindingMetadata, revokes, regrants []binding.BindingGrant) error {
	if len(revokes) == 0 {
		return nil
	}
	return b.setUserGrants(ctx, account, regrants)
}

// setUserGrants applies the account's complete permission set, built from the
// given grants, in one atomic operation per mode.
func (b *MongoServiceBinding) setUserGrants(ctx context.Context, account map[string]string, grants []binding.BindingGrant) error {
	userName := account["username"]
	databaseName := account["database"]
	if userName == "" || databaseName == "" {
		return fmt.Errorf("binding account is missing the username or database field")
	}

	if b.isAtlas {
		roles, err := buildAtlasRoles(databaseName, grants)
		if err != nil {
			return err
		}
		err = b.atlasClient.updateDatabaseUserRoles(ctx, userName, roles)
		if err != nil && atlasErrorStatus(err) == 404 && account["password"] != "" {
			// The user was deleted out-of-band; recreate it with the desired
			// roles (`binding update --reapply-all` uses this to recover).
			b.Warn().Msgf("atlas user %s not found, recreating", userName)
			err = b.atlasClient.createDatabaseUser(ctx, b.newAtlasDatabaseUser(userName, account["password"], roles))
		}
		if err != nil {
			return fmt.Errorf("error applying grants to atlas user %s: %w", userName, err)
		}
		return nil
	}

	privileges, err := buildMongoRolePrivileges(databaseName, grants)
	if err != nil {
		return err
	}
	updateRoleCmd := bson.D{
		{Key: "updateRole", Value: userName},
		{Key: "privileges", Value: privileges},
		{Key: "roles", Value: bson.A{}},
	}
	err = b.adminClient.Database("admin").RunCommand(ctx, updateRoleCmd).Err()
	if isMongoErrCode(err, mongoErrRoleNotFound) {
		// The role was dropped out-of-band; recreate it with the desired
		// privileges (`binding update --reapply-all` uses this to recover).
		b.Warn().Msgf("role %s not found, recreating", userName)
		createRoleCmd := bson.D{
			{Key: "createRole", Value: userName},
			{Key: "privileges", Value: privileges},
			{Key: "roles", Value: bson.A{}},
		}
		err = b.adminClient.Database("admin").RunCommand(ctx, createRoleCmd).Err()
	}
	if err != nil {
		return fmt.Errorf("error applying grants to role %s: %w", userName, err)
	}
	return nil
}

// restoreSelfHostedUser recreates the derived binding user if it was dropped
// out-of-band, using the stored account password. Called only on reapplyAll.
func (b *MongoServiceBinding) restoreSelfHostedUser(ctx context.Context, account map[string]string) error {
	userName := account["username"]
	password := account["password"]
	if userName == "" || password == "" {
		return fmt.Errorf("binding account is missing the username or password field")
	}

	var usersResult struct {
		Users []bson.M `bson:"users"`
	}
	usersInfoCmd := bson.D{{Key: "usersInfo", Value: bson.D{{Key: "user", Value: userName}, {Key: "db", Value: "admin"}}}}
	if err := b.adminClient.Database("admin").RunCommand(ctx, usersInfoCmd).Decode(&usersResult); err != nil {
		return fmt.Errorf("error checking user %s: %w", userName, err)
	}
	if len(usersResult.Users) > 0 {
		return nil
	}

	b.Warn().Msgf("user %s not found, recreating", userName)
	createUserCmd := bson.D{
		{Key: "createUser", Value: userName},
		{Key: "pwd", Value: password},
		{Key: "roles", Value: bson.A{bson.D{{Key: "role", Value: userName}, {Key: "db", Value: "admin"}}}},
	}
	if err := b.adminClient.Database("admin").RunCommand(ctx, createUserCmd).Err(); err != nil {
		return fmt.Errorf("error recreating user %s: %w", userName, err)
	}
	return nil
}

func (b *MongoServiceBinding) RunCommand(ctx context.Context, bindingMetadata binding.BindingMetadata, command string) (map[string]any, error) {
	cmdDoc, err := parseMongoCommand(command)
	if err != nil {
		return nil, err
	}

	databaseName := bindingMetadata.Account["database"]
	if databaseName == "" {
		return nil, fmt.Errorf("binding account is missing the database field")
	}

	client, err := mongo.Connect(options.Client().ApplyURI(bindingMetadata.Account["url_direct"]))
	if err != nil {
		return nil, fmt.Errorf("error connecting with account url: %w", err)
	}
	defer client.Disconnect(ctx) //nolint:errcheck

	raw, err := client.Database(databaseName).RunCommand(ctx, cmdDoc).Raw()
	if err != nil {
		return nil, fmt.Errorf("error executing command: %w", err)
	}
	result, err := mongoResultToJSONMap(raw)
	if err != nil {
		return nil, err
	}
	return map[string]any{"result": result}, nil
}

// mongoAccountNames computes the user and database names for a base binding.
// bindingId is `bnd_` + 27-char ksuid, so the longest name (user, 42 chars)
// is comfortably inside MongoDB's limits (database names must stay under 64
// bytes and both names use a safe charset).
func mongoAccountNames(bindingId string, isStaging bool) (string, string) {
	userPrefix := mongoUserPrefixProd
	dbPrefix := mongoDBPrefixProd
	if isStaging {
		userPrefix = mongoUserPrefixStg
		dbPrefix = mongoDBPrefixStg
	}
	return userPrefix + bindingId, dbPrefix + bindingId
}

// validateMongoServiceURL enforces the URL forms the binding supports:
// mongodb:// with a single host, or mongodb+srv://. Multi-host seed lists are
// rejected because account URLs are rebuilt with net/url, which cannot
// represent them.
func validateMongoServiceURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("error parsing mongodb url: %w", err)
	}
	if u.Scheme != "mongodb" && u.Scheme != "mongodb+srv" {
		return fmt.Errorf("unsupported mongodb url scheme %q (expected mongodb:// or mongodb+srv://)", u.Scheme)
	}
	if strings.Contains(u.Host, ",") {
		return fmt.Errorf("multi-host mongodb urls are not supported for service bindings, use a single host or a mongodb+srv url")
	}
	return nil
}

// buildMongoAccountURL constructs an account URL from the service URL with
// the supplied user and password, the binding database as the default
// database, and authSource forced to admin (where binding users are created).
// The host is only rewritten for the mongodb:// scheme: rewriting a
// mongodb+srv:// host would break the SRV lookup.
func buildMongoAccountURL(serviceURL, user, password, database, bindingHostname string) (string, error) {
	if err := validateMongoServiceURL(serviceURL); err != nil {
		return "", err
	}
	u, err := url.Parse(serviceURL)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword(user, password)
	if u.Scheme == "mongodb" {
		binding.SetURLHostname(u, bindingHostname)
	}
	u.Path = "/" + database
	query := u.Query()
	query.Set("authSource", "admin")
	u.RawQuery = query.Encode()
	return u.String(), nil
}

// validateMongoGrantTarget restricts grant targets to safe collection names,
// so a target cannot name a system collection or clash with MongoDB name
// rules.
func validateMongoGrantTarget(grant binding.BindingGrant) (string, error) {
	target := grant.GrantTarget
	if target == binding.GrantTargetAll {
		return "", nil
	}
	if target == "" {
		return "", fmt.Errorf("grant target is required, use %s:* for all collections", strings.ToLower(string(grant.GrantType)))
	}
	if !mongoGrantTargetRegex.MatchString(target) {
		return "", fmt.Errorf("invalid grant target %q: only letters, digits and _ . - are allowed", target)
	}
	if strings.HasPrefix(target, "system.") {
		return "", fmt.Errorf("invalid grant target %q: system collections cannot be granted", target)
	}
	return target, nil
}

// buildMongoRolePrivileges builds the complete privileges array for a derived
// binding's custom role from the grants. Grants on the same target are merged
// into one privilege with the union of their actions ({db, collection: ""}
// for `*` targets applies to every collection in the binding database and
// additionally carries the database-level actions).
func buildMongoRolePrivileges(database string, grants []binding.BindingGrant) (bson.A, error) {
	targets := []string{}
	actionsByTarget := map[string][]string{}
	addActions := func(target string, actions []string) {
		if _, ok := actionsByTarget[target]; !ok {
			targets = append(targets, target)
		}
		for _, action := range actions {
			if !slices.Contains(actionsByTarget[target], action) {
				actionsByTarget[target] = append(actionsByTarget[target], action)
			}
		}
	}

	for _, grant := range grants {
		target, err := validateMongoGrantTarget(grant)
		if err != nil {
			return nil, err
		}

		switch grant.GrantType {
		case binding.GrantTypeRead:
			addActions(target, mongoReadActionsColl)
			if target == "" {
				addActions(target, mongoReadActionsDB)
			}
		case binding.GrantTypeFull:
			addActions(target, mongoReadActionsColl)
			addActions(target, mongoWriteActionsColl)
			if target == "" {
				addActions(target, mongoReadActionsDB)
				addActions(target, mongoWriteActionsDB)
			}
		default:
			return nil, fmt.Errorf("unsupported grant type %s for mongodb", grant.GrantType)
		}
	}

	privileges := bson.A{}
	for _, target := range targets {
		privileges = append(privileges, bson.D{
			{Key: "resource", Value: bson.D{{Key: "db", Value: database}, {Key: "collection", Value: target}}},
			{Key: "actions", Value: actionsByTarget[target]},
		})
	}
	return privileges, nil
}

// atlasBaseRoles is the Atlas roles array for a base binding user: full
// access to its own database.
func atlasBaseRoles(database string) []atlasRole {
	return []atlasRole{
		{RoleName: "readWrite", DatabaseName: database},
		{RoleName: "dbAdmin", DatabaseName: database},
	}
}

// buildAtlasRoles builds the complete roles array for a derived binding's
// Atlas user from the grants, using built-in read/readWrite roles with the
// optional collection scope. The placeholder baseline role is always included
// so the roles array is never empty (the Atlas API rejects users without
// roles), including for a fresh derived user with no grants yet.
func buildAtlasRoles(database string, grants []binding.BindingGrant) ([]atlasRole, error) {
	roles := []atlasRole{{RoleName: "read", DatabaseName: atlasBaselineDatabase, CollectionName: atlasBaselineCollection}}
	addRole := func(role atlasRole) {
		if !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}

	for _, grant := range grants {
		target, err := validateMongoGrantTarget(grant)
		if err != nil {
			return nil, err
		}

		switch grant.GrantType {
		case binding.GrantTypeRead:
			addRole(atlasRole{RoleName: "read", DatabaseName: database, CollectionName: target})
		case binding.GrantTypeFull:
			addRole(atlasRole{RoleName: "readWrite", DatabaseName: database, CollectionName: target})
		default:
			return nil, fmt.Errorf("unsupported grant type %s for atlas", grant.GrantType)
		}
	}
	return roles, nil
}

// parseMongoCommand parses a runCommand document from (relaxed or canonical)
// extended JSON. bson.D preserves the key order, keeping the command name as
// the first element as MongoDB requires.
func parseMongoCommand(command string) (bson.D, error) {
	var doc bson.D
	if err := bson.UnmarshalExtJSON([]byte(command), false, &doc); err != nil {
		return nil, fmt.Errorf("error parsing command as a JSON document: %w", err)
	}
	if len(doc) == 0 {
		return nil, fmt.Errorf("command is required, e.g. {\"find\": \"collection\"}")
	}
	return doc, nil
}

// mongoResultToJSONMap converts a raw command reply into JSON-marshalable
// types via relaxed extended JSON (so BSON types like ObjectId and dates get
// their standard JSON representation).
func mongoResultToJSONMap(raw bson.Raw) (map[string]any, error) {
	jsonBytes, err := bson.MarshalExtJSON(raw, false, false)
	if err != nil {
		return nil, fmt.Errorf("error encoding command result: %w", err)
	}
	var result map[string]any
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, fmt.Errorf("error decoding command result: %w", err)
	}
	return result, nil
}

// isMongoErrCode reports whether err is a MongoDB command error with the
// given numeric code.
func isMongoErrCode(err error, code int) bool {
	var cmdErr mongo.CommandError
	return errors.As(err, &cmdErr) && cmdErr.Code == int32(code)
}

// pingMongoURL connects with the given URL and runs ping, verifying both
// reachability and (when the URL carries credentials) authentication, since
// the driver authenticates the connection before running the command.
func pingMongoURL(ctx context.Context, rawURL string) error {
	client, err := mongo.Connect(options.Client().ApplyURI(rawURL))
	if err != nil {
		return err
	}
	defer client.Disconnect(context.WithoutCancel(ctx)) //nolint:errcheck
	return client.Ping(ctx, nil)
}

// checkMongoAuthorizationEnabled verifies the server actually enforces
// authorization by attempting a privileged command without credentials. If it
// succeeds, the server is running without --auth and the per-binding users
// would provide no isolation, so the service is rejected.
func checkMongoAuthorizationEnabled(ctx context.Context, adminURL string) error {
	u, err := url.Parse(adminURL)
	if err != nil {
		return fmt.Errorf("error parsing mongodb url: %w", err)
	}
	u.User = nil

	client, err := mongo.Connect(options.Client().ApplyURI(u.String()))
	if err != nil {
		return fmt.Errorf("error connecting to mongodb: %w", err)
	}
	defer client.Disconnect(context.WithoutCancel(ctx)) //nolint:errcheck

	err = client.Database("admin").RunCommand(ctx, bson.D{{Key: "usersInfo", Value: 1}}).Err()
	if err == nil {
		return fmt.Errorf("mongodb server does not have authorization enabled (run with --auth); binding isolation would not be enforced")
	}
	if isMongoErrCode(err, mongoErrUnauthorized) {
		return nil
	}
	return fmt.Errorf("error checking mongodb authorization status: %w", err)
}

// checkMongoReachable verifies the cluster URL is reachable. The Atlas
// service URL carries no credentials (users are managed via the API), so an
// unauthorized command error still proves the server was reached.
func checkMongoReachable(ctx context.Context, rawURL string) error {
	err := pingMongoURL(ctx, rawURL)
	if err == nil || isMongoErrCode(err, mongoErrUnauthorized) {
		return nil
	}
	return err
}
