// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/databricks/databricks-sdk-go"
	"github.com/databricks/databricks-sdk-go/apierr"
	"github.com/databricks/databricks-sdk-go/config"
	"github.com/databricks/databricks-sdk-go/service/iam"
	"github.com/databricks/databricks-sdk-go/service/oauth2"
	"github.com/databricks/databricks-sdk-go/service/settings"
	dbsqlservice "github.com/databricks/databricks-sdk-go/service/sql"
	dbsql "github.com/databricks/databricks-sql-go"
	binding "github.com/openrundev/openrun/pkg/binding"
	"github.com/openrundev/openrun/pkg/binding/sqlbinding"
)

// Databricks binding model: apps get access to a Databricks SQL warehouse,
// scoped to a Unity Catalog schema, through a per-binding Databricks-managed
// service principal. A base binding gets a schema in the service's configured
// catalog, created (and therefore owned) by the admin identity, with USE
// CATALOG plus ALL PRIVILEGES on the schema granted to its service principal.
// Derived bindings get a service principal that shares the base schema with
// only the USE CATALOG / USE SCHEMA connect-baseline; data access is assigned
// through grants.
//
//   - Unity Catalog privileges granted on a schema apply to current AND future
//     child objects, so `*`-target grants need no reapply when tables are
//     added; only table-specific grants are deferred when the target does not
//     exist yet.
//   - ALL PRIVILEGES excludes MANAGE, so binding principals can never re-grant.
//   - Unity Catalog grants do not cover compute: each service principal also
//     gets a CAN_USE entry on the SQL warehouse (additive permissions update).
//   - The admin identity must be able to manage service principals and
//     warehouse permissions (workspace admin), create schemas in the catalog,
//     and issue account credentials (service principal OAuth secrets or
//     on-behalf-of tokens). A workspace admin covers all of these.
//
// Account credentials are an OAuth secret of the service principal
// (account_credential_type=oauth) or an on-behalf-of PAT
// (account_credential_type=token). The default (auto) tries the OAuth secret
// first and falls back to an OBO token where the secrets API is unavailable.
const (
	dbxUserPrefixProd   = "cl_usr_prd_"
	dbxUserPrefixStg    = "cl_usr_stg_"
	dbxSchemaPrefixProd = "cl_sch_prd_"
	dbxSchemaPrefixStg  = "cl_sch_stg_"

	dbxCredentialAuto  = "auto"
	dbxCredentialOauth = "oauth"
	dbxCredentialToken = "token"

	// Account auth_type values, matching what app-side Databricks connectors
	// call the methods.
	dbxAccountAuthOauth = "oauth-m2m"
	dbxAccountAuthPat   = "pat"

	// Privileges applied on the schema for `full:*` grants. Deliberately not
	// ALL PRIVILEGES: revoking that would also remove the USE SCHEMA
	// connect-baseline granted at account generation.
	dbxFullSchemaPrivileges = "SELECT, MODIFY, CREATE TABLE"
)

type DatabricksServiceBinding struct {
	*binding.Logger
	serviceConfig map[string]string
	cfg           *config.Config              // SDK auth config, shared by both planes
	workspace     *databricks.WorkspaceClient // REST plane, available after InitializeService
	adminDB       *sql.DB                     // SQL plane admin connection, available after InitializeService
	warehouseID   string
}

var _ binding.ServiceBinding = (*DatabricksServiceBinding)(nil)

func NewDatabricksServiceBinding() binding.ServiceBinding {
	return &DatabricksServiceBinding{}
}

func (b *DatabricksServiceBinding) GetAccountEnv(ctx context.Context) ([]string, []string, error) {
	return []string{"url", "url_direct", "host", "http_path", "catalog", "schema", "auth_type", "client_id"},
		[]string{"token", "client_secret"}, nil
}

func (b *DatabricksServiceBinding) InitializeService(ctx context.Context, logger *binding.Logger, serviceConfig map[string]string, runtime binding.ServiceBindingRuntime) error {
	b.Logger = logger
	if err := binding.VerifyKeys(configKeys(serviceConfig),
		databricksServiceConfigKeys.required, databricksServiceConfigKeys.optional); err != nil {
		return err
	}
	switch credType := serviceConfig["account_credential_type"]; credType {
	case "", dbxCredentialAuto, dbxCredentialOauth, dbxCredentialToken:
	default:
		return fmt.Errorf("invalid account_credential_type %q: use %s, %s or %s",
			credType, dbxCredentialAuto, dbxCredentialOauth, dbxCredentialToken)
	}
	if lifetime := serviceConfig["token_lifetime_seconds"]; lifetime != "" {
		if _, err := strconv.ParseInt(lifetime, 10, 64); err != nil {
			return fmt.Errorf("invalid token_lifetime_seconds %q: %w", lifetime, err)
		}
	}

	cfg, err := databricksAuthConfig(serviceConfig)
	if err != nil {
		return err
	}

	workspace, err := databricks.NewWorkspaceClient((*databricks.Config)(cfg))
	if err != nil {
		return fmt.Errorf("error creating databricks workspace client: %w", err)
	}

	// *config.Config implements the driver's auth.Authenticator, so the SQL
	// plane uses the same resolved credential as the REST plane.
	connector, err := dbsql.NewConnector(
		dbsql.WithServerHostname(databricksHostname(serviceConfig["host"])),
		dbsql.WithPort(443),
		dbsql.WithHTTPPath(serviceConfig["http_path"]),
		dbsql.WithAuthenticator(cfg),
		dbsql.WithInitialNamespace(serviceConfig["catalog"], ""),
		dbsql.WithUserAgentEntry("openrun-binding-databricks"),
	)
	if err != nil {
		return fmt.Errorf("error building databricks connection config: %w", err)
	}
	adminDB := sql.OpenDB(connector)

	// Verifies auth and warehouse reachability; wakes a stopped warehouse.
	if err := adminDB.PingContext(ctx); err != nil {
		adminDB.Close() //nolint:errcheck
		return fmt.Errorf("error verifying databricks connection: %w", err)
	}
	catalogQuery := "SELECT 1 FROM system.information_schema.catalogs WHERE catalog_name = " +
		sqlbinding.QuoteStringSingle(serviceConfig["catalog"])
	row := adminDB.QueryRowContext(ctx, catalogQuery)
	var one int
	if err := row.Scan(&one); err != nil {
		adminDB.Close() //nolint:errcheck
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("unity catalog %q was not found (or the admin identity cannot see it)", serviceConfig["catalog"])
		}
		return fmt.Errorf("error checking catalog %s: %w", serviceConfig["catalog"], err)
	}

	b.serviceConfig = serviceConfig
	b.cfg = cfg
	b.workspace = workspace
	b.adminDB = adminDB
	b.warehouseID = databricksWarehouseID(serviceConfig)
	return nil
}

func (b *DatabricksServiceBinding) CloseService(ctx context.Context) error {
	if b.adminDB == nil {
		return nil
	}
	return b.adminDB.Close()
}

func (b *DatabricksServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata binding.BindingMetadata,
	derivedFromMetadata *binding.BindingMetadata, isStaging bool) (map[string]string, []binding.Artifact, error) {
	if err := binding.VerifyKeys(configKeys(bindingMetadata.Config), []string{}, []string{}); err != nil {
		return nil, nil, err
	}
	if b.warehouseID == "" {
		return nil, nil, fmt.Errorf("could not determine the warehouse id from http_path; set the warehouse_id service config")
	}

	// Unity Catalog stores object names lowercased; lowercase the generated
	// names so the account values match the catalog's view of them.
	spName, err := binding.AccountName(dbxUserPrefixProd, dbxUserPrefixStg, bindingId, isStaging, binding.NameOptions{})
	if err != nil {
		return nil, nil, err
	}
	spName = strings.ToLower(spName)
	schemaName, err := binding.AccountName(dbxSchemaPrefixProd, dbxSchemaPrefixStg, bindingId, isStaging, binding.NameOptions{})
	if err != nil {
		return nil, nil, err
	}
	schemaName = strings.ToLower(schemaName)
	if derivedFromMetadata != nil {
		// Derived binding, use the base binding's schema
		schemaName = derivedFromMetadata.Account["schema"]
		if schemaName == "" {
			return nil, nil, fmt.Errorf("derived binding base account is missing the schema field")
		}
	}

	// SCIM create does not enforce display name uniqueness, so check first to
	// avoid stacking a second principal on a leftover from a partial operation.
	if existing, err := b.findServicePrincipal(ctx, spName); err != nil {
		return nil, nil, fmt.Errorf("error checking service principal %s: %w", spName, err)
	} else if existing != nil {
		return nil, nil, fmt.Errorf("databricks service principal %s already exists", spName)
	}

	sp, err := b.workspace.ServicePrincipalsV2.Create(ctx, iam.CreateServicePrincipalRequest{
		DisplayName: spName,
		Active:      true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error creating service principal %s: %w", spName, err)
	}
	artifacts := []binding.Artifact{{Type: binding.ArtifactUser, Name: spName}}

	authType, credential, err := b.createAccountCredential(ctx, sp)
	if err != nil {
		return nil, artifacts, fmt.Errorf("error creating credential for service principal %s: %w", spName, err)
	}

	// Unity Catalog grants do not cover compute: the principal needs CAN_USE
	// on the warehouse. UpdatePermissions is additive (PATCH), existing ACL
	// entries are untouched; the entry is removed with the principal.
	if _, err := b.workspace.Warehouses.UpdatePermissions(ctx, dbsqlservice.WarehousePermissionsRequest{
		WarehouseId: b.warehouseID,
		AccessControlList: []dbsqlservice.WarehouseAccessControlRequest{{
			ServicePrincipalName: sp.ApplicationId,
			PermissionLevel:      dbsqlservice.WarehousePermissionLevelCanUse,
		}},
	}); err != nil {
		return nil, artifacts, fmt.Errorf("error granting warehouse access to service principal %s: %w", spName, err)
	}

	catalog := b.serviceConfig["catalog"]
	quotedCatalog := quoteDatabricksIdent(catalog)
	quotedSchema := quotedCatalog + "." + quoteDatabricksIdent(schemaName)
	quotedPrincipal := quoteDatabricksIdent(sp.ApplicationId)

	if derivedFromMetadata == nil {
		// Base binding: schema owned by the admin identity, full schema access
		// for the principal. Schema-level privileges inherit to current and
		// future objects; ALL PRIVILEGES excludes MANAGE.
		if _, err := b.adminDB.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
			return nil, artifacts, fmt.Errorf("error creating schema %s: %w", schemaName, err)
		}
		artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactSchema, Name: schemaName})

		for _, stmt := range []string{
			"GRANT USE CATALOG ON CATALOG " + quotedCatalog + " TO " + quotedPrincipal,
			"GRANT ALL PRIVILEGES ON SCHEMA " + quotedSchema + " TO " + quotedPrincipal,
		} {
			if _, err := b.adminDB.ExecContext(ctx, stmt); err != nil {
				return nil, artifacts, fmt.Errorf("error granting schema privileges to %s: %w", spName, err)
			}
		}
	} else {
		// Derived binding: connect-baseline only, so negative permission checks
		// fail on the table privilege instead of namespace resolution.
		// Application privileges are assigned only by ApplyGrants.
		for _, stmt := range []string{
			"GRANT USE CATALOG ON CATALOG " + quotedCatalog + " TO " + quotedPrincipal,
			"GRANT USE SCHEMA ON SCHEMA " + quotedSchema + " TO " + quotedPrincipal,
		} {
			if _, err := b.adminDB.ExecContext(ctx, stmt); err != nil {
				return nil, artifacts, fmt.Errorf("error granting baseline privileges to %s: %w", spName, err)
			}
		}
	}

	hostname := databricksHostname(b.serviceConfig["host"])
	httpPath := b.serviceConfig["http_path"]
	accountURL := databricksAccountURL(hostname, httpPath, catalog, schemaName, authType, sp.ApplicationId, credential)

	// Databricks is always a remote service, so there is no localhost binding
	// hostname mapping and url equals url_direct.
	account := map[string]string{
		"url":        accountURL,
		"url_direct": accountURL,
		"host":       hostname,
		"http_path":  httpPath,
		"catalog":    catalog,
		"schema":     schemaName,
		"auth_type":  authType,
		"client_id":  sp.ApplicationId,
	}
	if authType == dbxAccountAuthOauth {
		account["client_secret"] = credential
	} else {
		account["token"] = credential
	}
	return account, artifacts, nil
}

// createAccountCredential issues the credential for a generated service
// principal: an OAuth secret (auth_type oauth-m2m) or an on-behalf-of PAT
// (auth_type pat), per the account_credential_type service config. The default
// auto mode tries the OAuth secret first and falls back to an OBO token when
// the secrets API is unavailable or denied on the workspace.
func (b *DatabricksServiceBinding) createAccountCredential(ctx context.Context, sp *iam.ServicePrincipal) (string, string, error) {
	credType := b.serviceConfig["account_credential_type"]
	if credType == "" {
		credType = dbxCredentialAuto
	}

	if credType == dbxCredentialOauth || credType == dbxCredentialAuto {
		secret, err := b.workspace.ServicePrincipalSecretsProxy.Create(ctx, oauth2.CreateServicePrincipalSecretRequest{
			ServicePrincipalId: sp.Id,
		})
		if err == nil {
			return dbxAccountAuthOauth, secret.Secret, nil
		}
		if credType == dbxCredentialOauth {
			return "", "", fmt.Errorf("error creating service principal OAuth secret: %w", err)
		}
		b.Debug().Err(err).Msg("service principal OAuth secret unavailable, falling back to an on-behalf-of token")
	}

	request := settings.CreateOboTokenRequest{
		ApplicationId: sp.ApplicationId,
		Comment:       "OpenRun binding account token",
	}
	if lifetime := b.serviceConfig["token_lifetime_seconds"]; lifetime != "" {
		seconds, err := strconv.ParseInt(lifetime, 10, 64)
		if err != nil {
			return "", "", fmt.Errorf("invalid token_lifetime_seconds %q: %w", lifetime, err)
		}
		request.LifetimeSeconds = seconds
	}
	token, err := b.workspace.TokenManagement.CreateOboToken(ctx, request)
	if err != nil {
		return "", "", fmt.Errorf("error creating on-behalf-of token: %w", err)
	}
	return dbxAccountAuthPat, token.TokenValue, nil
}

// findServicePrincipal looks up a workspace service principal by display name.
// Returns nil when there is no match.
func (b *DatabricksServiceBinding) findServicePrincipal(ctx context.Context, displayName string) (*iam.ServicePrincipal, error) {
	principals, err := b.workspace.ServicePrincipalsV2.ListAll(ctx, iam.ListServicePrincipalsRequest{
		Filter: fmt.Sprintf("displayName eq %s", sqlbinding.QuoteStringSingle(displayName)),
	})
	if err != nil {
		return nil, err
	}
	for _, sp := range principals {
		if sp.DisplayName == displayName {
			return &sp, nil
		}
	}
	return nil, nil
}

// DeleteArtifact deletes one service principal or schema previously reported
// as created by GenerateAccount, either to undo a rolled-back operation or
// when the binding is deleted. Deleting the principal removes its credentials,
// Unity Catalog grants and warehouse ACL entry; DROP SCHEMA CASCADE removes
// the schema's objects regardless of which principal created them.
func (b *DatabricksServiceBinding) DeleteArtifact(ctx context.Context, artifact binding.Artifact) error {
	if artifact.Name == "" {
		return fmt.Errorf("artifact name is required")
	}

	switch artifact.Type {
	case binding.ArtifactUser:
		sp, err := b.findServicePrincipal(ctx, artifact.Name)
		if err != nil {
			return fmt.Errorf("error looking up service principal %s: %w", artifact.Name, err)
		}
		if sp == nil {
			return nil // already gone
		}
		if err := b.workspace.ServicePrincipalsV2.Delete(ctx, iam.DeleteServicePrincipalRequest{Id: sp.Id}); err != nil && !apierr.IsMissing(err) {
			return fmt.Errorf("error deleting service principal %s: %w", artifact.Name, err)
		}
	case binding.ArtifactSchema:
		stmt := "DROP SCHEMA IF EXISTS " + quoteDatabricksIdent(b.serviceConfig["catalog"]) + "." + quoteDatabricksIdent(artifact.Name) + " CASCADE"
		if _, err := b.adminDB.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("error dropping schema %s: %w", artifact.Name, err)
		}
	default:
		return fmt.Errorf("unsupported databricks artifact type %s", artifact.Type)
	}
	return nil
}

func (b *DatabricksServiceBinding) ApplyGrants(ctx context.Context, account map[string]string, bindingMetadata binding.BindingMetadata,
	derivedFromMetadata binding.BindingMetadata, reapplyAll bool) (binding.GrantApplyResult, error) {
	return binding.ApplyGrantsIncremental(bindingMetadata,
		[]binding.GrantType{binding.GrantTypeRead, binding.GrantTypeCreate, binding.GrantTypeFull}, reapplyAll,
		func(grants []binding.BindingGrant) ([]binding.BindingGrant, error) {
			return b.applyPerms(ctx, "grant", grants, account["schema"], account["client_id"])
		})
}

func (b *DatabricksServiceBinding) RevokeGrants(ctx context.Context, account map[string]string,
	_ binding.BindingMetadata, revokes, regrants []binding.BindingGrant) error {
	return binding.RevokeThenRegrant(revokes, regrants, func(op string, grants []binding.BindingGrant) error {
		_, err := b.applyPerms(ctx, op, grants, account["schema"], account["client_id"])
		return err
	})
}

// applyPerms runs Unity Catalog GRANT or REVOKE statements for binding grants
// on the admin connection. operation must be "grant" or "revoke". Grants
// target the binding's service principal by application id.
//
// Schema-scoped privileges inherit to current and future objects, so `*`
// grants need no reapply when tables are added. Only table-specific grants are
// deferred when the target does not exist yet. Revoking a privilege that is
// not held is a no-op in Unity Catalog, so revokes need no special-casing
// beyond the table precheck.
func (b *DatabricksServiceBinding) applyPerms(ctx context.Context, operation string,
	grants []binding.BindingGrant, schema, principal string) ([]binding.BindingGrant, error) {
	var isGrant bool
	switch operation {
	case "grant":
		isGrant = true
	case "revoke":
		isGrant = false
	default:
		return nil, fmt.Errorf("invalid grant operation %q: want %q or %q", operation, "grant", "revoke")
	}
	verb := "revoking"
	if isGrant {
		verb = "granting"
	}

	quotedSchema := quoteDatabricksIdent(b.serviceConfig["catalog"]) + "." + quoteDatabricksIdent(schema)
	quotedPrincipal := quoteDatabricksIdent(principal)

	// applyStmt formats one GRANT/REVOKE of privs at the given scope
	// ("SCHEMA <name>", "TABLE <name>").
	applyStmt := func(privs, scope string) error {
		var stmt string
		if isGrant {
			stmt = fmt.Sprintf("GRANT %s ON %s TO %s", privs, scope, quotedPrincipal)
		} else {
			stmt = fmt.Sprintf("REVOKE %s ON %s FROM %s", privs, scope, quotedPrincipal)
		}
		_, err := b.adminDB.ExecContext(ctx, stmt)
		return err
	}

	// tableSpecific grants/revokes privs on one table or view, deferring the
	// grant when the target does not exist yet (returns false, nil).
	tableSpecific := func(target, privs string) (bool, error) {
		tableName, exists, err := b.resolveTable(ctx, schema, target)
		if err != nil {
			return false, err
		}
		if !exists {
			return false, nil
		}
		if err := applyStmt(privs, "TABLE "+quotedSchema+"."+quoteDatabricksIdent(tableName)); err != nil {
			return false, err
		}
		return true, nil
	}

	logDeferred := func(grant binding.BindingGrant) {
		if isGrant {
			b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
				Msg("table does not exist yet; grant deferred until reconcile")
		} else {
			b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
				Msg("table does not exist; revoke skipped")
		}
	}

	grantsDone := []binding.BindingGrant{}
	for _, grant := range grants {
		switch grant.GrantType {
		case binding.GrantTypeRead:
			if grant.GrantTarget == binding.GrantTargetAll {
				// Inherits to current and future tables and views
				if err := applyStmt("SELECT", "SCHEMA "+quotedSchema); err != nil {
					return nil, fmt.Errorf("error %s select privileges on schema %s: %w", verb, schema, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				applied, err := tableSpecific(grant.GrantTarget, "SELECT")
				if err != nil {
					return nil, fmt.Errorf("error %s select privileges on table %s.%s: %w", verb, schema, grant.GrantTarget, err)
				}
				if applied {
					grantsDone = append(grantsDone, grant)
				} else {
					logDeferred(grant)
				}
			}

		case binding.GrantTypeCreate:
			if isGrant && grant.GrantTarget != "" && grant.GrantTarget != binding.GrantTargetAll {
				return nil, fmt.Errorf("create grant on specific table is not supported")
			}
			// CREATE TABLE also covers view creation in Unity Catalog. The
			// principal owns (and so fully controls) the objects it creates;
			// the base principal keeps access through schema inheritance.
			if err := applyStmt("CREATE TABLE", "SCHEMA "+quotedSchema); err != nil {
				return nil, fmt.Errorf("error %s create privileges on schema %s: %w", verb, schema, err)
			}
			grantsDone = append(grantsDone, grant)

		case binding.GrantTypeFull:
			if grant.GrantTarget == binding.GrantTargetAll {
				// Explicit privileges rather than ALL PRIVILEGES: REVOKE ALL
				// PRIVILEGES would also remove the USE SCHEMA connect-baseline
				// granted in GenerateAccount, breaking the account's namespace
				// resolution after a full:* revoke (same rationale as the MySQL
				// binding's SHOW VIEW baseline). Schema-level SELECT/MODIFY
				// inherit to current and future tables and views.
				if err := applyStmt(dbxFullSchemaPrivileges, "SCHEMA "+quotedSchema); err != nil {
					return nil, fmt.Errorf("error %s full privileges on schema %s: %w", verb, schema, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				applied, err := tableSpecific(grant.GrantTarget, "ALL PRIVILEGES")
				if err != nil {
					return nil, fmt.Errorf("error %s full privileges on table %s.%s: %w", verb, schema, grant.GrantTarget, err)
				}
				if applied {
					grantsDone = append(grantsDone, grant)
				} else {
					logDeferred(grant)
				}
			}
		}
	}
	return grantsDone, nil
}

// resolveTable looks up a table or view by name in the schema via
// information_schema. Unity Catalog stores object names lowercased, so the
// lookup matches case-insensitively and returns the stored name.
func (b *DatabricksServiceBinding) resolveTable(ctx context.Context, schema, target string) (string, bool, error) {
	query := "SELECT table_name FROM " + quoteDatabricksIdent(b.serviceConfig["catalog"]) +
		".information_schema.tables WHERE table_schema = " + sqlbinding.QuoteStringSingle(schema) +
		" AND table_name = lower(" + sqlbinding.QuoteStringSingle(target) + ") LIMIT 1"
	row := b.adminDB.QueryRowContext(ctx, query)
	var name string
	if err := row.Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("error checking if table %s.%s exists: %w", schema, target, err)
	}
	return name, true, nil
}

func (b *DatabricksServiceBinding) RunCommand(ctx context.Context, bindingMetadata binding.BindingMetadata, command string) (map[string]any, error) {
	return sqlbinding.RunCommand(ctx, "databricks", bindingMetadata.Account[binding.AccountKeyURLDirect], command,
		sqlbinding.RunCommandOptions{RowReturningKeywords: []string{"SHOW", "DESC", "DESCRIBE", "EXPLAIN", "VALUES", "LIST"}})
}

// databricksAccountURL composes the Go driver DSN for a generated account:
// token:<pat>@host:443<http_path>?... for pat accounts, or
// host:443<http_path>?authType=OauthM2M&clientID=..&clientSecret=.. for OAuth
// accounts. The catalog and schema ride along as session defaults.
func databricksAccountURL(hostname, httpPath, catalog, schema, authType, clientID, credential string) string {
	params := url.Values{}
	params.Set("catalog", catalog)
	params.Set("schema", schema)

	prefix := ""
	if authType == dbxAccountAuthOauth {
		params.Set("authType", "OauthM2M")
		params.Set("clientID", clientID)
		params.Set("clientSecret", credential)
	} else {
		prefix = "token:" + url.QueryEscape(credential) + "@"
	}
	return prefix + hostname + ":443" + httpPath + "?" + params.Encode()
}

// quoteDatabricksIdent quotes an identifier (catalog, schema, table, grant
// principal) using backticks. Embedded backticks are doubled, per Databricks
// SQL identifier rules.
func quoteDatabricksIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// configKeys returns the keys of a config map.
func configKeys(configMap map[string]string) []string {
	keys := make([]string, 0, len(configMap))
	for key := range configMap {
		keys = append(keys, key)
	}
	return keys
}
