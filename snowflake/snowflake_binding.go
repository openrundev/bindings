// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"

	binding "github.com/openrundev/openrun/pkg/binding"
	"github.com/openrundev/openrun/pkg/binding/sqlbinding"
	sf "github.com/snowflakedb/gosnowflake"
)

// Snowflake binding model: each binding gets a ROLE plus a USER whose default
// role is that role (Snowflake privileges are always granted to roles, never
// to users). A base binding also gets a SCHEMA in the service's configured
// database, with usage/create privileges granted to its role; derived bindings
// get a user whose default namespace is the base binding's schema, with access
// assigned only through grants on the role.
//
// Snowflake retired single-factor password sign-in, so generated users are
// TYPE=SERVICE with a per-account RSA key pair: the provider generates the
// key pair, registers the public key on the user and returns the private key
// in the account (as a ready-to-use DSN in url/url_direct, and as PEM in
// private_key for non-Go drivers).
//
//   - Schema-scoped grants use ON ALL ... IN SCHEMA for existing objects plus
//     ON FUTURE ... IN SCHEMA, so `*` grants cover later objects with no
//     reapply step.
//   - The schema stays owned by the admin role (objects the binding user
//     creates are owned by the binding role), so DeleteArtifact can DROP
//     SCHEMA ... CASCADE without ownership juggling.
//   - The admin needs CREATE ROLE and CREATE USER on the account, CREATE
//     SCHEMA on the database, and MANAGE GRANTS (to grant on objects owned by
//     binding roles). ACCOUNTADMIN covers all of these.
const (
	snowflakeRolePrefixProd   = "CL_ROL_PRD_"
	snowflakeRolePrefixStg    = "CL_ROL_STG_"
	snowflakeUserPrefixProd   = "CL_USR_PRD_"
	snowflakeUserPrefixStg    = "CL_USR_STG_"
	snowflakeSchemaPrefixProd = "CL_SCH_PRD_"
	snowflakeSchemaPrefixStg  = "CL_SCH_STG_"

	// Privileges applied on tables for `full` grants. Views and sequences get
	// SELECT/USAGE respectively.
	snowflakeFullTablePrivileges = "SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES"

	// Key size for generated account key pairs (Snowflake requires >= 2048).
	snowflakeAccountKeyBits = 2048
)

var snowflakeServiceConfigKeys = struct {
	required []string
	optional []string
}{
	required: []string{"account", "user", "database", "warehouse"},
	optional: []string{"role", "authenticator", "password", "private_key", "token",
		"oauth_client_id", "oauth_client_secret", "oauth_token_url", "oauth_scope",
		"workload_identity_provider", "workload_identity_entra_resource"},
}

type SnowflakeServiceBinding struct {
	*binding.Logger
	serviceConfig map[string]string
	adminConn     *sql.DB // Admin connection to the service, available after InitService
}

var _ binding.ServiceBinding = (*SnowflakeServiceBinding)(nil)

func NewSnowflakeServiceBinding() binding.ServiceBinding {
	return &SnowflakeServiceBinding{}
}

func (b *SnowflakeServiceBinding) GetAccountEnv(ctx context.Context) ([]string, []string, error) {
	return []string{"url", "url_direct", "user", "role", "schema", "database", "warehouse", "account", "private_key"}, []string{}, nil
}

func (b *SnowflakeServiceBinding) InitializeService(ctx context.Context, logger *binding.Logger, serviceConfig map[string]string, runtime binding.ServiceBindingRuntime) error {
	b.Logger = logger
	if err := binding.VerifyKeys(configKeys(serviceConfig),
		snowflakeServiceConfigKeys.required, snowflakeServiceConfigKeys.optional); err != nil {
		return err
	}

	cfg, err := snowflakeAuthConfig(serviceConfig)
	if err != nil {
		return err
	}
	dsn, err := sf.DSN(cfg)
	if err != nil {
		return fmt.Errorf("error building snowflake connection config: %w", err)
	}

	adminConn, err := sql.Open("snowflake", dsn)
	if err != nil {
		return fmt.Errorf("error opening admin connection: %w", err)
	}
	if err := adminConn.PingContext(ctx); err != nil {
		adminConn.Close() //nolint:errcheck
		return fmt.Errorf("error verifying snowflake connection: %w", err)
	}

	b.serviceConfig = serviceConfig
	b.adminConn = adminConn
	return nil
}

func (b *SnowflakeServiceBinding) CloseService(ctx context.Context) error {
	if b.adminConn == nil {
		return nil
	}
	return b.adminConn.Close()
}

func (b *SnowflakeServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata binding.BindingMetadata, derivedFromMetadata *binding.BindingMetadata, isStaging bool) (map[string]string, []binding.Artifact, error) {
	// Uppercase names so the quoted identifiers match Snowflake's unquoted
	// identifier resolution (same approach as the Oracle binding).
	nameOpts := binding.NameOptions{Uppercase: true}
	roleName, err := binding.AccountName(snowflakeRolePrefixProd, snowflakeRolePrefixStg, bindingId, isStaging, nameOpts)
	if err != nil {
		return nil, nil, err
	}
	userName, err := binding.AccountName(snowflakeUserPrefixProd, snowflakeUserPrefixStg, bindingId, isStaging, nameOpts)
	if err != nil {
		return nil, nil, err
	}
	schemaName, err := binding.AccountName(snowflakeSchemaPrefixProd, snowflakeSchemaPrefixStg, bindingId, isStaging, nameOpts)
	if err != nil {
		return nil, nil, err
	}
	if derivedFromMetadata != nil {
		// Derived binding, use the base binding's schema
		schemaName = derivedFromMetadata.Account["schema"]
		if schemaName == "" {
			return nil, nil, fmt.Errorf("derived binding base account is missing the schema field")
		}
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, snowflakeAccountKeyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating account key pair: %w", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding account public key: %w", err)
	}
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKeyDER)

	database := b.serviceConfig["database"]
	warehouse := b.serviceConfig["warehouse"]
	quotedRole := quoteSnowflakeIdent(roleName)
	quotedUser := quoteSnowflakeIdent(userName)
	quotedDB := quoteSnowflakeIdent(database)
	quotedSchema := quotedDB + "." + quoteSnowflakeIdent(schemaName)
	quotedWarehouse := quoteSnowflakeIdent(warehouse)

	// Snowflake DDL auto-commits per statement, so a partial failure cannot be
	// rolled back here; the artifacts created so far are returned with the
	// error so the caller can delete them.
	artifacts := []binding.Artifact{}

	if _, err := b.adminConn.ExecContext(ctx, "CREATE ROLE "+quotedRole); err != nil {
		return nil, artifacts, fmt.Errorf("error creating role %s: %w", roleName, err)
	}
	artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactRole, Name: roleName})

	// Both base and derived roles can connect to the database and run queries
	// on the configured warehouse; object access comes from ownership (base)
	// or ApplyGrants (derived).
	for _, stmt := range []string{
		"GRANT USAGE ON DATABASE " + quotedDB + " TO ROLE " + quotedRole,
		"GRANT USAGE ON WAREHOUSE " + quotedWarehouse + " TO ROLE " + quotedRole,
	} {
		if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
			return nil, artifacts, fmt.Errorf("error granting usage to role %s: %w", roleName, err)
		}
	}

	if derivedFromMetadata == nil {
		// Base binding: schema owned by the admin role, with usage and create
		// privileges for the binding role. Objects the binding user creates are
		// owned by the binding role, giving it full control over them.
		if _, err := b.adminConn.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
			return nil, artifacts, fmt.Errorf("error creating schema %s: %w", schemaName, err)
		}
		artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactSchema, Name: schemaName})

		grantSQL := "GRANT USAGE, CREATE TABLE, CREATE VIEW, CREATE SEQUENCE ON SCHEMA " + quotedSchema + " TO ROLE " + quotedRole
		if _, err := b.adminConn.ExecContext(ctx, grantSQL); err != nil {
			return nil, artifacts, fmt.Errorf("error granting create privileges on schema %s: %w", schemaName, err)
		}
	}
	// Derived bindings: application privileges are assigned only by ApplyGrants.

	// TYPE=SERVICE forbids password sign-in and exempts the user from MFA
	// enforcement; the key pair is the only credential.
	createUserSQL := fmt.Sprintf("CREATE USER %s RSA_PUBLIC_KEY='%s' TYPE=SERVICE DEFAULT_ROLE=%s DEFAULT_NAMESPACE=%s DEFAULT_WAREHOUSE=%s",
		quotedUser, publicKeyB64, quotedRole, quotedSchema, quotedWarehouse)
	if _, err := b.adminConn.ExecContext(ctx, createUserSQL); err != nil {
		return nil, artifacts, fmt.Errorf("error creating user %s: %w", userName, err)
	}
	artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactUser, Name: userName})

	if _, err := b.adminConn.ExecContext(ctx, "GRANT ROLE "+quotedRole+" TO USER "+quotedUser); err != nil {
		return nil, artifacts, fmt.Errorf("error granting role %s to user %s: %w", roleName, userName, err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(privateKey)})
	accountDSN, err := sf.DSN(&sf.Config{
		Account:       b.serviceConfig["account"],
		User:          userName,
		Database:      database,
		Schema:        schemaName,
		Warehouse:     warehouse,
		Role:          roleName,
		Authenticator: sf.AuthTypeJwt,
		PrivateKey:    privateKey,
	})
	if err != nil {
		return nil, artifacts, fmt.Errorf("error building account url: %w", err)
	}

	// Snowflake is always a remote service, so there is no localhost binding
	// hostname mapping and url equals url_direct.
	return map[string]string{
		"url":         accountDSN,
		"url_direct":  accountDSN,
		"user":        userName,
		"role":        roleName,
		"schema":      schemaName,
		"database":    database,
		"warehouse":   warehouse,
		"account":     b.serviceConfig["account"],
		"private_key": string(privateKeyPEM),
	}, artifacts, nil
}

// mustMarshalPKCS8 encodes an in-memory generated RSA key; marshalling a key
// produced by rsa.GenerateKey cannot fail.
func mustMarshalPKCS8(key *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return der
}

// DeleteArtifact drops one role, user or schema previously reported as created
// by GenerateAccount, either to undo a rolled-back operation or when the
// binding is deleted. The caller passes artifacts back in reverse creation
// order. DROP SCHEMA CASCADE removes the schema's objects regardless of which
// binding role owns them.
func (b *SnowflakeServiceBinding) DeleteArtifact(ctx context.Context, artifact binding.Artifact) error {
	if artifact.Name == "" {
		return fmt.Errorf("artifact name is required")
	}

	var stmt string
	switch artifact.Type {
	case binding.ArtifactRole:
		stmt = "DROP ROLE IF EXISTS " + quoteSnowflakeIdent(artifact.Name)
	case binding.ArtifactUser:
		stmt = "DROP USER IF EXISTS " + quoteSnowflakeIdent(artifact.Name)
	case binding.ArtifactSchema:
		stmt = "DROP SCHEMA IF EXISTS " + quoteSnowflakeIdent(b.serviceConfig["database"]) + "." + quoteSnowflakeIdent(artifact.Name) + " CASCADE"
	default:
		return fmt.Errorf("unsupported snowflake artifact type %s", artifact.Type)
	}
	if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("error dropping %s %s: %w", artifact.Type, artifact.Name, err)
	}
	return nil
}

func (b *SnowflakeServiceBinding) ApplyGrants(ctx context.Context, account map[string]string, bindingMetadata binding.BindingMetadata,
	derivedFromMetadata binding.BindingMetadata, reapplyAll bool) (binding.GrantApplyResult, error) {
	return binding.ApplyGrantsIncremental(bindingMetadata,
		[]binding.GrantType{binding.GrantTypeRead, binding.GrantTypeCreate, binding.GrantTypeFull}, reapplyAll,
		func(grants []binding.BindingGrant) ([]binding.BindingGrant, error) {
			return b.applyPerms(ctx, "grant", grants, account["schema"], account["role"])
		})
}

func (b *SnowflakeServiceBinding) RevokeGrants(ctx context.Context, account map[string]string,
	_ binding.BindingMetadata, revokes, regrants []binding.BindingGrant) error {
	return binding.RevokeThenRegrant(revokes, regrants, func(op string, grants []binding.BindingGrant) error {
		_, err := b.applyPerms(ctx, op, grants, account["schema"], account["role"])
		return err
	})
}

// applyPerms runs GRANT or REVOKE statements for binding grants on the admin
// connection. operation must be "grant" or "revoke". Grants always target the
// binding's role, per the Snowflake privilege model.
//
// `*`-target grants pair ON ALL (current objects) with ON FUTURE (later
// objects), so they need no reapply when tables are added. Only table-specific
// grants are deferred when the target does not exist yet. Revoking a privilege
// that is not held is a no-op in Snowflake, so revokes need no special-casing
// beyond the table precheck.
func (b *SnowflakeServiceBinding) applyPerms(ctx context.Context, operation string,
	grants []binding.BindingGrant, schema, role string) ([]binding.BindingGrant, error) {
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

	quotedSchema := quoteSnowflakeIdent(b.serviceConfig["database"]) + "." + quoteSnowflakeIdent(schema)
	quotedRole := quoteSnowflakeIdent(role)

	// applyStmt formats one GRANT/REVOKE of privs at the given scope ("SCHEMA
	// <name>", "ALL TABLES IN SCHEMA <name>", "TABLE <name>", ...).
	applyStmt := func(privs, scope string) error {
		var stmt string
		if isGrant {
			stmt = fmt.Sprintf("GRANT %s ON %s TO ROLE %s", privs, scope, quotedRole)
		} else {
			stmt = fmt.Sprintf("REVOKE %s ON %s FROM ROLE %s", privs, scope, quotedRole)
		}
		_, err := b.adminConn.ExecContext(ctx, stmt)
		return err
	}

	schemaWide := func(tablePrivs, viewPrivs, sequencePrivs string) error {
		if err := applyStmt("USAGE", "SCHEMA "+quotedSchema); err != nil {
			return err
		}
		for _, objectClass := range []struct{ privs, class string }{
			{tablePrivs, "TABLES"}, {viewPrivs, "VIEWS"}, {sequencePrivs, "SEQUENCES"},
		} {
			if objectClass.privs == "" {
				continue
			}
			if err := applyStmt(objectClass.privs, "ALL "+objectClass.class+" IN SCHEMA "+quotedSchema); err != nil {
				return err
			}
			if err := applyStmt(objectClass.privs, "FUTURE "+objectClass.class+" IN SCHEMA "+quotedSchema); err != nil {
				return err
			}
		}
		return nil
	}

	// tableSpecific grants/revokes privs on one table or view, deferring the
	// grant when the target does not exist yet (returns false, nil).
	tableSpecific := func(target, privs string) (bool, error) {
		objectName, isView, exists, err := b.resolveTableOrView(ctx, schema, target)
		if err != nil {
			return false, err
		}
		if !exists {
			return false, nil
		}
		if isView {
			privs = "SELECT"
		}
		if err := applyStmt("USAGE", "SCHEMA "+quotedSchema); err != nil {
			return false, err
		}
		objectKeyword := "TABLE"
		if isView {
			objectKeyword = "VIEW"
		}
		if err := applyStmt(privs, objectKeyword+" "+quotedSchema+"."+quoteSnowflakeIdent(objectName)); err != nil {
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
				if err := schemaWide("SELECT", "SELECT", ""); err != nil {
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
			if err := applyStmt("USAGE, CREATE TABLE, CREATE VIEW, CREATE SEQUENCE", "SCHEMA "+quotedSchema); err != nil {
				return nil, fmt.Errorf("error %s create privileges on schema %s: %w", verb, schema, err)
			}
			grantsDone = append(grantsDone, grant)

		case binding.GrantTypeFull:
			if grant.GrantTarget == binding.GrantTargetAll {
				if err := schemaWide(snowflakeFullTablePrivileges, "SELECT", "USAGE"); err != nil {
					return nil, fmt.Errorf("error %s full privileges on schema %s: %w", verb, schema, err)
				}
				// full:* includes the create privileges, matching the Postgres
				// and SQL Server bindings' full semantics.
				if err := applyStmt("CREATE TABLE, CREATE VIEW, CREATE SEQUENCE", "SCHEMA "+quotedSchema); err != nil {
					return nil, fmt.Errorf("error %s create privileges on schema %s: %w", verb, schema, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				applied, err := tableSpecific(grant.GrantTarget, snowflakeFullTablePrivileges)
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

// resolveTableOrView looks up a table or view by name in the schema, matching
// the target exactly first (covering quoted mixed-case names) and then via
// Snowflake's uppercase normalization for unquoted identifiers. SHOW commands
// are used because they need no running warehouse.
func (b *SnowflakeServiceBinding) resolveTableOrView(ctx context.Context, schema, target string) (name string, isView, exists bool, err error) {
	quotedSchema := quoteSnowflakeIdent(b.serviceConfig["database"]) + "." + quoteSnowflakeIdent(schema)
	for _, objectClass := range []struct {
		keyword string
		view    bool
	}{{"TABLES", false}, {"VIEWS", true}} {
		// LIKE patterns are case-insensitive; matching the returned names
		// exactly (or via uppercase normalization) avoids LIKE wildcard
		// surprises from _ in table names.
		query := "SHOW " + objectClass.keyword + " LIKE " + sqlbinding.QuoteStringSingle(target) + " IN SCHEMA " + quotedSchema
		rows, err := b.adminConn.QueryContext(ctx, query)
		if err != nil {
			return "", false, false, fmt.Errorf("error listing objects in schema %s: %w", schema, err)
		}
		names, err := scanShowNames(rows)
		if err != nil {
			return "", false, false, fmt.Errorf("error reading objects in schema %s: %w", schema, err)
		}
		for _, candidate := range []string{target, strings.ToUpper(target)} {
			for _, n := range names {
				if n == candidate {
					return n, objectClass.view, true, nil
				}
			}
		}
	}
	return "", false, false, nil
}

// scanShowNames extracts the "name" column values from a SHOW command result.
func scanShowNames(rows *sql.Rows) ([]string, error) {
	defer rows.Close() //nolint:errcheck
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	nameIdx := -1
	for i, column := range columns {
		if column == "name" {
			nameIdx = i
			break
		}
	}
	if nameIdx == -1 {
		return nil, fmt.Errorf("SHOW result has no name column")
	}

	names := []string{}
	for rows.Next() {
		values := make([]any, len(columns))
		valuePtrs := make([]any, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}
		switch v := values[nameIdx].(type) {
		case string:
			names = append(names, v)
		case []byte:
			names = append(names, string(v))
		}
	}
	return names, rows.Err()
}

func (b *SnowflakeServiceBinding) RunCommand(ctx context.Context, bindingMetadata binding.BindingMetadata, command string) (map[string]any, error) {
	return sqlbinding.RunCommand(ctx, "snowflake", bindingMetadata.Account[binding.AccountKeyURLDirect], command,
		sqlbinding.RunCommandOptions{RowReturningKeywords: []string{"SHOW", "DESC", "DESCRIBE", "LIST", "CALL"}})
}

// CheckHealth verifies the admin connection with a no-op query.
func (b *SnowflakeServiceBinding) CheckHealth(ctx context.Context) error {
	return sqlbinding.CheckHealth(ctx, b.adminConn, "select 1")
}

// CheckBindingHealth connects as the binding account and runs a no-op query,
// verifying the generated user and role still exist and the key-pair works.
func (b *SnowflakeServiceBinding) CheckBindingHealth(ctx context.Context, bindingMetadata binding.BindingMetadata) error {
	return sqlbinding.CheckBindingHealth(ctx, "snowflake", bindingMetadata.Account[binding.AccountKeyURLDirect], "select 1")
}

// unquotedIdentRegex matches identifiers Snowflake resolves case-insensitively
// when unquoted.
var unquotedIdentRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]*$`)

// quoteSnowflakeIdent quotes an identifier with double quotes. Plain
// identifiers are uppercased first, matching how Snowflake resolves them when
// written unquoted (so a service config value like warehouse=compute_wh finds
// the warehouse COMPUTE_WH); anything else is quoted verbatim.
func quoteSnowflakeIdent(name string) string {
	if unquotedIdentRegex.MatchString(name) {
		name = strings.ToUpper(name)
	}
	return sqlbinding.QuoteIdentDouble(name)
}

// configKeys returns the keys of a service config map.
func configKeys(serviceConfig map[string]string) []string {
	keys := make([]string, 0, len(serviceConfig))
	for key := range serviceConfig {
		keys = append(keys, key)
	}
	return keys
}
