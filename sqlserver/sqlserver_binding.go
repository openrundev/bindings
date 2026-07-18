// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"

	_ "github.com/microsoft/go-mssqldb"
	binding "github.com/openrundev/openrun/pkg/binding"
	"github.com/openrundev/openrun/pkg/binding/sqlbinding"
)

// SQL Server binding model: each binding gets a server-level LOGIN plus a
// database USER in the service's configured database. A base binding also gets
// a SCHEMA owned by its user (the SQL Server analogue of the Postgres binding's
// schema+role pair); derived bindings get a user whose default schema is the
// base binding's schema, with access assigned only through grants.
//
// Everything used here (CREATE LOGIN/USER/SCHEMA, schema-scoped GRANT ... ON
// SCHEMA::, OBJECT:: grants) works on SQL Server Express and has been available
// since SQL Server 2012, so older Express instances work too.
//
//   - Schema-scoped grants (GRANT SELECT ON SCHEMA::s) cover current AND future
//     objects in the schema, so `*` grants need no default-privileges follow-up
//     like Postgres requires.
//   - There is no schema-scoped CREATE permission: creating a table needs the
//     database-level CREATE TABLE permission plus ALTER on the schema. ALTER on
//     a schema also allows dropping/altering other principals' objects in that
//     schema (broader than the Postgres CREATE-on-schema semantic); it does not
//     include any data access.
const (
	sqlserverLoginPrefixProd  = "cl_lgn_prd_"
	sqlserverLoginPrefixStg   = "cl_lgn_stg_"
	sqlserverUserPrefixProd   = "cl_usr_prd_"
	sqlserverUserPrefixStg    = "cl_usr_stg_"
	sqlserverSchemaPrefixProd = "cl_sch_prd_"
	sqlserverSchemaPrefixStg  = "cl_sch_stg_"

	// Privileges applied for `full:*` (schema-scoped) and `full:tbl`
	// (object-scoped). Mirrors the Postgres binding's `full` semantics: full
	// data access plus, for `full:*`, the create/alter rights on the schema.
	// TRIGGER is intentionally omitted (no object-level TRIGGER permission in
	// SQL Server; ALTER on the object covers it and is part of schema ALTER).
	sqlserverFullPrivileges = "SELECT, INSERT, UPDATE, DELETE, REFERENCES"
)

type SqlServerServiceBinding struct {
	*binding.Logger
	serviceConfig map[string]string
	database      string  // database from the service URL, where users/schemas are created
	adminConn     *sql.DB // Admin connection to the configured database, available after InitService
}

var _ binding.ServiceBinding = (*SqlServerServiceBinding)(nil)

func (b *SqlServerServiceBinding) GetAccountEnv(ctx context.Context) ([]string, []string, error) {
	return []string{"url", "url_direct", "login", "user", "schema", "database"}, []string{}, nil
}

func NewSqlServerServiceBinding() binding.ServiceBinding {
	return &SqlServerServiceBinding{}
}

func (b *SqlServerServiceBinding) InitializeService(ctx context.Context, logger *binding.Logger, serviceConfig map[string]string, runtime binding.ServiceBindingRuntime) error {
	b.Logger = logger
	database, err := sqlserverDatabaseFromURL(serviceConfig["url"])
	if err != nil {
		return err
	}

	adminConn, effectiveConfig, err := sqlbinding.InitService(ctx, "sqlserver", serviceConfig["url"], serviceConfig, runtime)
	if err != nil {
		return err
	}

	b.serviceConfig = effectiveConfig
	b.database = database
	b.adminConn = adminConn
	return nil
}

func (b *SqlServerServiceBinding) CloseService(ctx context.Context) error {
	if b.adminConn == nil {
		return nil
	}
	return b.adminConn.Close()
}

func (b *SqlServerServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata binding.BindingMetadata, derivedFromMetadata *binding.BindingMetadata, isStaging bool) (map[string]string, []binding.Artifact, error) {
	password, err := binding.RandomHex(32)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating random password: %w", err)
	}

	loginPrefix, userPrefix, schemaPrefix := sqlserverLoginPrefixProd, sqlserverUserPrefixProd, sqlserverSchemaPrefixProd
	if isStaging {
		loginPrefix, userPrefix, schemaPrefix = sqlserverLoginPrefixStg, sqlserverUserPrefixStg, sqlserverSchemaPrefixStg
	}

	loginName := loginPrefix + bindingId
	userName := userPrefix + bindingId
	schemaName := schemaPrefix + bindingId
	if derivedFromMetadata != nil {
		// Derived binding, use the base binding's schema
		schemaName = derivedFromMetadata.Account["schema"]
		if schemaName == "" {
			return nil, nil, fmt.Errorf("derived binding base account is missing the schema field")
		}
	}

	quotedLogin := quoteSqlserverIdent(loginName)
	quotedUser := quoteSqlserverIdent(userName)
	quotedSchema := quoteSqlserverIdent(schemaName)
	quotedDB := quoteSqlserverIdent(b.database)

	// SQL Server DDL here spans server-level (CREATE LOGIN) and database-level
	// statements, and CREATE SCHEMA must be alone in its batch, so the
	// statements run individually. On a partial failure the artifacts created
	// so far are returned with the error so the caller can delete them.
	artifacts := []binding.Artifact{}

	// CHECK_POLICY = OFF: the generated password is random hex, which does not
	// meet the Windows complexity classes the default policy may enforce; the
	// 64-char random password does not need policy checks.
	createLoginSQL := fmt.Sprintf("CREATE LOGIN %s WITH PASSWORD = %s, CHECK_POLICY = OFF, DEFAULT_DATABASE = %s",
		quotedLogin, quoteSqlserverString(password), quotedDB)
	if _, err := b.adminConn.ExecContext(ctx, createLoginSQL); err != nil {
		return nil, artifacts, fmt.Errorf("error creating login %s: %w", loginName, err)
	}
	artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactLogin, Name: loginName})

	// DEFAULT_SCHEMA may name a schema that does not exist yet (created below
	// for base bindings); SQL Server allows that.
	createUserSQL := fmt.Sprintf("CREATE USER %s FOR LOGIN %s WITH DEFAULT_SCHEMA = %s", quotedUser, quotedLogin, quotedSchema)
	if _, err := b.adminConn.ExecContext(ctx, createUserSQL); err != nil {
		return nil, artifacts, fmt.Errorf("error creating user %s: %w", userName, err)
	}
	artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactUser, Name: userName})

	if derivedFromMetadata == nil {
		// Base binding: schema owned by the binding user, plus the database
		// level create permissions. Ownership gives full control within the
		// schema; the db-level permissions are what actually allow creating
		// objects (they only take effect inside schemas the user owns or has
		// ALTER on, so other schemas stay off limits).
		createSchemaSQL := fmt.Sprintf("CREATE SCHEMA %s AUTHORIZATION %s", quotedSchema, quotedUser)
		if _, err := b.adminConn.ExecContext(ctx, createSchemaSQL); err != nil {
			return nil, artifacts, fmt.Errorf("error creating schema %s: %w", schemaName, err)
		}
		artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactSchema, Name: schemaName})

		// CREATE SEQUENCE is not a database-level permission in SQL Server; it
		// is schema-scoped and already covered by schema ownership (base) or
		// the schema ALTER granted for create/full grants (derived).
		grantSQL := fmt.Sprintf("GRANT CREATE TABLE, CREATE VIEW TO %s", quotedUser)
		if _, err := b.adminConn.ExecContext(ctx, grantSQL); err != nil {
			return nil, artifacts, fmt.Errorf("error granting create privileges to user %s: %w", userName, err)
		}
	}
	// Derived bindings get CONNECT implicitly from CREATE USER; application
	// privileges are assigned only by ApplyGrants.

	accountURL, accountDirectURL, err := binding.AccountURLs(b.serviceConfig["url"], loginName, password, b.serviceConfig["binding_hostname"])
	if err != nil {
		return nil, artifacts, fmt.Errorf("error building account url: %w", err)
	}

	return map[string]string{
		"url":        accountURL,
		"url_direct": accountDirectURL,
		"login":      loginName,
		"user":       userName,
		"schema":     schemaName,
		"database":   b.database,
	}, artifacts, nil
}

// DeleteArtifact drops one login, user or schema previously reported as created
// by GenerateAccount. The caller passes artifacts back in reverse creation
// order, so a base binding's schema is dropped before its owning user. A schema
// created during the current operation can only contain objects created since,
// so its contents are dropped before the schema itself (SQL Server has no DROP
// SCHEMA CASCADE).
func (b *SqlServerServiceBinding) DeleteArtifact(ctx context.Context, artifact binding.Artifact) error {
	if artifact.Name == "" {
		return fmt.Errorf("artifact name is required")
	}

	switch artifact.Type {
	case binding.ArtifactSchema:
		return b.dropSchemaCascade(ctx, artifact.Name)
	case binding.ArtifactUser:
		if _, err := b.adminConn.ExecContext(ctx, "DROP USER IF EXISTS "+quoteSqlserverIdent(artifact.Name)); err != nil {
			return fmt.Errorf("error dropping user %s: %w", artifact.Name, err)
		}
	case binding.ArtifactLogin:
		// DROP LOGIN has no IF EXISTS form on older versions; check first so
		// repeated deletes are harmless.
		var exists int
		err := b.adminConn.QueryRowContext(ctx,
			"SELECT 1 FROM sys.server_principals WHERE name = @p1", artifact.Name).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("error checking login %s: %w", artifact.Name, err)
		}
		if _, err := b.adminConn.ExecContext(ctx, "DROP LOGIN "+quoteSqlserverIdent(artifact.Name)); err != nil {
			return fmt.Errorf("error dropping login %s: %w", artifact.Name, err)
		}
	default:
		return fmt.Errorf("unsupported sqlserver artifact type %s", artifact.Type)
	}
	return nil
}

// dropSchemaCascade drops every object in the schema (foreign keys first, then
// tables/views/sequences), then the schema itself. Missing schema is a no-op.
func (b *SqlServerServiceBinding) dropSchemaCascade(ctx context.Context, schemaName string) error {
	var exists int
	err := b.adminConn.QueryRowContext(ctx, "SELECT 1 FROM sys.schemas WHERE name = @p1", schemaName).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("error checking schema %s: %w", schemaName, err)
	}

	quotedSchema := quoteSqlserverIdent(schemaName)

	// Drop foreign key constraints on the schema's tables so table drop order
	// does not matter.
	fkRows, err := b.adminConn.QueryContext(ctx, `
		SELECT fk.name, o.name FROM sys.foreign_keys fk
		JOIN sys.objects o ON fk.parent_object_id = o.object_id
		WHERE o.schema_id = SCHEMA_ID(@p1)`, schemaName)
	if err != nil {
		return fmt.Errorf("error listing foreign keys in schema %s: %w", schemaName, err)
	}
	type fkInfo struct{ fkName, tableName string }
	fks := []fkInfo{}
	for fkRows.Next() {
		var fk fkInfo
		if err := fkRows.Scan(&fk.fkName, &fk.tableName); err != nil {
			fkRows.Close() //nolint:errcheck
			return fmt.Errorf("error reading foreign keys in schema %s: %w", schemaName, err)
		}
		fks = append(fks, fk)
	}
	fkRows.Close() //nolint:errcheck
	if err := fkRows.Err(); err != nil {
		return fmt.Errorf("error reading foreign keys in schema %s: %w", schemaName, err)
	}
	for _, fk := range fks {
		stmt := fmt.Sprintf("ALTER TABLE %s.%s DROP CONSTRAINT %s",
			quotedSchema, quoteSqlserverIdent(fk.tableName), quoteSqlserverIdent(fk.fkName))
		if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("error dropping foreign key %s in schema %s: %w", fk.fkName, schemaName, err)
		}
	}

	// Views first (they may reference tables), then tables, then sequences.
	for _, objectClass := range []struct{ objectType, dropKeyword string }{
		{"V", "VIEW"}, {"U", "TABLE"}, {"SO", "SEQUENCE"},
	} {
		rows, err := b.adminConn.QueryContext(ctx,
			"SELECT name FROM sys.objects WHERE schema_id = SCHEMA_ID(@p1) AND type = @p2",
			schemaName, objectClass.objectType)
		if err != nil {
			return fmt.Errorf("error listing objects in schema %s: %w", schemaName, err)
		}
		names := []string{}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close() //nolint:errcheck
				return fmt.Errorf("error reading objects in schema %s: %w", schemaName, err)
			}
			names = append(names, name)
		}
		rows.Close() //nolint:errcheck
		if err := rows.Err(); err != nil {
			return fmt.Errorf("error reading objects in schema %s: %w", schemaName, err)
		}
		for _, name := range names {
			stmt := fmt.Sprintf("DROP %s %s.%s", objectClass.dropKeyword, quotedSchema, quoteSqlserverIdent(name))
			if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("error dropping %s %s in schema %s: %w", objectClass.dropKeyword, name, schemaName, err)
			}
		}
	}

	if _, err := b.adminConn.ExecContext(ctx, "DROP SCHEMA "+quotedSchema); err != nil {
		return fmt.Errorf("error dropping schema %s: %w", schemaName, err)
	}
	return nil
}

func (b *SqlServerServiceBinding) ApplyGrants(ctx context.Context, account map[string]string, bindingMetadata binding.BindingMetadata,
	derivedFromMetadata binding.BindingMetadata, reapplyAll bool) (binding.GrantApplyResult, error) {
	return binding.ApplyGrantsIncremental(bindingMetadata,
		[]binding.GrantType{binding.GrantTypeRead, binding.GrantTypeCreate, binding.GrantTypeFull}, reapplyAll,
		func(grants []binding.BindingGrant) ([]binding.BindingGrant, error) {
			return b.applyPerms(ctx, "grant", grants, account["schema"], account["user"])
		})
}

func (b *SqlServerServiceBinding) RevokeGrants(ctx context.Context, account map[string]string,
	_ binding.BindingMetadata, revokes, regrants []binding.BindingGrant) error {
	return binding.RevokeThenRegrant(revokes, regrants, func(op string, grants []binding.BindingGrant) error {
		_, err := b.applyPerms(ctx, op, grants, account["schema"], account["user"])
		return err
	})
}

// applyPerms runs GRANT or REVOKE statements for binding grants on the admin
// connection. operation must be "grant" or "revoke".
//
// Future-table behavior: schema-scoped permissions (ON SCHEMA::s) cover every
// current and future object in the schema, so `*`-target grants need no
// default-privileges follow-up. Only table-specific grants are deferred when
// the target table does not yet exist. Revoking a permission that was never
// granted is a no-op in SQL Server, so revokes need no existence special-casing
// beyond the table precheck.
func (b *SqlServerServiceBinding) applyPerms(ctx context.Context, operation string,
	grants []binding.BindingGrant, schema, user string) ([]binding.BindingGrant, error) {
	var isGrant bool
	switch operation {
	case "grant":
		isGrant = true
	case "revoke":
		isGrant = false
	default:
		return nil, fmt.Errorf("invalid grant operation %q: want %q or %q", operation, "grant", "revoke")
	}
	grantOrRevoke := "REVOKE"
	toOrFrom := "FROM"
	verb := "revoking"
	if isGrant {
		grantOrRevoke = "GRANT"
		toOrFrom = "TO"
		verb = "granting"
	}

	quotedSchema := quoteSqlserverIdent(schema)
	quotedUser := quoteSqlserverIdent(user)

	grantsDone := []binding.BindingGrant{}
	for _, grant := range grants {
		switch grant.GrantType {
		case binding.GrantTypeRead:
			if grant.GrantTarget == binding.GrantTargetAll {
				stmt := fmt.Sprintf("%s SELECT ON SCHEMA::%s %s %s", grantOrRevoke, quotedSchema, toOrFrom, quotedUser)
				if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s select privileges on schema %s: %w", verb, schema, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				stmt := fmt.Sprintf("%s SELECT ON OBJECT::%s.%s %s %s", grantOrRevoke, quotedSchema, quoteSqlserverIdent(grant.GrantTarget), toOrFrom, quotedUser)
				applied, err := b.trySoftGrant(ctx, schema, grant.GrantTarget, stmt)
				if err != nil {
					return nil, fmt.Errorf("error %s select privileges on table %s.%s: %w", verb, schema, grant.GrantTarget, err)
				}
				if applied {
					grantsDone = append(grantsDone, grant)
				} else if isGrant {
					b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
						Msg("table does not exist yet; grant deferred until reconcile")
				} else {
					b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
						Msg("table does not exist; revoke skipped")
				}
			}

		case binding.GrantTypeCreate:
			if isGrant && grant.GrantTarget != "" && grant.GrantTarget != binding.GrantTargetAll {
				return nil, fmt.Errorf("create grant on specific table is not supported")
			}
			// Creating a table needs the database-level CREATE TABLE permission
			// plus ALTER on the target schema. The db-level permission only has
			// effect in schemas the user owns or holds ALTER on, so it does not
			// open up other schemas.
			stmt := fmt.Sprintf("%s CREATE TABLE, CREATE VIEW %s %s", grantOrRevoke, toOrFrom, quotedUser)
			if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
				return nil, fmt.Errorf("error %s create privileges for user %s: %w", verb, user, err)
			}
			stmt = fmt.Sprintf("%s ALTER ON SCHEMA::%s %s %s", grantOrRevoke, quotedSchema, toOrFrom, quotedUser)
			if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
				return nil, fmt.Errorf("error %s alter privileges on schema %s: %w", verb, schema, err)
			}
			grantsDone = append(grantsDone, grant)

		case binding.GrantTypeFull:
			if grant.GrantTarget == binding.GrantTargetAll {
				stmt := fmt.Sprintf("%s %s ON SCHEMA::%s %s %s", grantOrRevoke, sqlserverFullPrivileges, quotedSchema, toOrFrom, quotedUser)
				if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s full privileges on schema %s: %w", verb, schema, err)
				}

				stmt = fmt.Sprintf("%s CREATE TABLE, CREATE VIEW %s %s", grantOrRevoke, toOrFrom, quotedUser)
				if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s create privileges for user %s: %w", verb, user, err)
				}

				stmt = fmt.Sprintf("%s ALTER ON SCHEMA::%s %s %s", grantOrRevoke, quotedSchema, toOrFrom, quotedUser)
				if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
					return nil, fmt.Errorf("error %s alter privileges on schema %s: %w", verb, schema, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				stmt := fmt.Sprintf("%s %s ON OBJECT::%s.%s %s %s", grantOrRevoke, sqlserverFullPrivileges, quotedSchema, quoteSqlserverIdent(grant.GrantTarget), toOrFrom, quotedUser)
				applied, err := b.trySoftGrant(ctx, schema, grant.GrantTarget, stmt)
				if err != nil {
					return nil, fmt.Errorf("error %s full privileges on table %s.%s: %w", verb, schema, grant.GrantTarget, err)
				}
				if applied {
					grantsDone = append(grantsDone, grant)
				} else if isGrant {
					b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
						Msg("table does not exist yet; grant deferred until reconcile")
				} else {
					b.Warn().Str("grant", grant.String()).Str("schema", schema).Str("table", grant.GrantTarget).
						Msg("table does not exist; revoke skipped")
				}
			}
		}
	}
	return grantsDone, nil
}

// trySoftGrant runs a single GRANT or REVOKE on a specific table. The table's
// existence is prechecked so a grant on a not-yet-created table is reported as
// deferred (returns false, nil) instead of failing the operation.
func (b *SqlServerServiceBinding) trySoftGrant(ctx context.Context, schema, table, stmt string) (bool, error) {
	exists, err := b.tableExists(ctx, schema, table)
	if err != nil {
		return false, fmt.Errorf("error checking if table %s.%s exists: %w", schema, table, err)
	}
	if !exists {
		return false, nil
	}
	if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
		return false, err
	}
	return true, nil
}

// tableExists reports whether the schema contains a table or view with the
// given name. Used to precheck table-level GRANT/REVOKE.
func (b *SqlServerServiceBinding) tableExists(ctx context.Context, schema, table string) (bool, error) {
	const q = "SELECT 1 FROM sys.objects WHERE schema_id = SCHEMA_ID(@p1) AND name = @p2 AND type IN ('U', 'V')"
	var present int
	if err := b.adminConn.QueryRowContext(ctx, q, schema, table).Scan(&present); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// quoteSqlserverIdent quotes an identifier using brackets.
func quoteSqlserverIdent(name string) string {
	return sqlbinding.QuoteIdentBracket(name)
}

// quoteSqlserverString quotes a value as an N-prefixed SQL string literal.
func quoteSqlserverString(s string) string {
	return "N" + sqlbinding.QuoteStringSingle(s)
}

// sqlserverDatabaseFromURL extracts the database from a sqlserver:// URL. The
// database is required: it is where the binding users and schemas are created.
// Both the `?database=` query form and the /instance path form are accepted,
// with the query form taking precedence (the go-mssqldb URL format).
func sqlserverDatabaseFromURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("error parsing sqlserver url: %w", err)
	}
	if u.Scheme != "sqlserver" {
		return "", fmt.Errorf("unsupported sqlserver url scheme %q (expected sqlserver://)", u.Scheme)
	}
	database := u.Query().Get("database")
	if database == "" {
		return "", fmt.Errorf("sqlserver url must include the database query parameter, like sqlserver://user:password@host:1433?database=dbname")
	}
	return database, nil
}

func (b *SqlServerServiceBinding) RunCommand(ctx context.Context, bindingMetadata binding.BindingMetadata, command string) (map[string]any, error) {
	return sqlbinding.RunCommand(ctx, "sqlserver", bindingMetadata.Account[binding.AccountKeyURLDirect], command,
		sqlbinding.RunCommandOptions{RowReturningKeywords: []string{"EXEC", "EXECUTE"}})
}
