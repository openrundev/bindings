// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	binding "github.com/openrundev/openrun/pkg/binding"
	"github.com/openrundev/openrun/pkg/binding/sqlbinding"
	_ "github.com/sijms/go-ora/v2"
	"github.com/sijms/go-ora/v2/network"
)

// Oracle binding model: in Oracle a schema is inseparable from a user, so each
// binding gets its own database user. A base binding's user owns its schema and
// holds the CREATE TABLE/VIEW/SEQUENCE system privileges (which only apply to
// the user's own schema). A derived binding's user gets CREATE SESSION plus a
// logon trigger that sets CURRENT_SCHEMA to the base binding's schema (the
// Oracle analogue of the Postgres binding's search_path), with data access
// assigned only through grants.
//
// Everything used here works on Oracle Database XE (11g and later) and needs
// only long-standing features: CREATE USER, per-object GRANT/REVOKE, logon
// triggers. The admin account in the service url must be able to create users
// and grant across schemas (e.g. SYSTEM, or any DBA-role account).
//
// Oracle has no schema-scoped object privileges before 23ai, so `*` grants are
// expanded to per-object grants over the base schema's current tables, views
// and sequences. Objects created later are not covered until the binding is
// reprocessed (`binding update --reapply-all`). The `create` grant type is not
// supported: pre-23ai Oracle can only allow creating objects in another user's
// schema via the CREATE ANY TABLE system privilege, which is database-wide and
// far too broad for a scoped binding. `full` therefore covers data access
// (SELECT/INSERT/UPDATE/DELETE on tables, SELECT on views and sequences) but
// not DDL in the base schema.
const (
	// Identifier prefixes. Oracle limits identifiers to 30 bytes before 12.2;
	// the 27-char ksuid core of the binding id (the `bnd_` prefix is stripped)
	// leaves only 3 chars for the prefix.
	oracleUserPrefixProd = "CP_"
	oracleUserPrefixStg  = "CS_"
	oracleBindingIDTrim  = "bnd_"
	oracleMaxIdentLen    = 30

	// Name of the logon trigger created in a derived user's schema to set
	// CURRENT_SCHEMA to the base schema. Owned by the derived user, so DROP
	// USER CASCADE removes it with the user.
	oracleLogonTriggerName = "CL_LOGON_SCHEMA_TRG"
)

// Oracle error codes handled specially.
const (
	oraTableNotFound   = 942  // ORA-00942: table or view does not exist
	oraCannotRevoke    = 1927 // ORA-01927: cannot REVOKE privileges you did not grant
	oraSequenceMissing = 2289 // ORA-02289: sequence does not exist
)

// isOracleErr reports whether err is an Oracle error with the given code.
func isOracleErr(err error, code int) bool {
	var oraErr *network.OracleError
	return errors.As(err, &oraErr) && oraErr.ErrCode == code
}

type OracleServiceBinding struct {
	*binding.Logger
	serviceConfig map[string]string
	adminConn     *sql.DB // Admin connection to the service, available after InitService
}

var _ binding.ServiceBinding = (*OracleServiceBinding)(nil)

func (b *OracleServiceBinding) GetAccountEnv(ctx context.Context) ([]string, []string, error) {
	return []string{"url", "url_direct", "user", "schema"}, []string{}, nil
}

func NewOracleServiceBinding() binding.ServiceBinding {
	return &OracleServiceBinding{}
}

func (b *OracleServiceBinding) InitializeService(ctx context.Context, logger *binding.Logger, serviceConfig map[string]string, runtime binding.ServiceBindingRuntime) error {
	b.Logger = logger
	connURL := serviceConfig["url"]
	u, err := url.Parse(connURL)
	if err != nil {
		return fmt.Errorf("error parsing oracle url: %w", err)
	}
	if u.Scheme != "oracle" {
		return fmt.Errorf("unsupported oracle url scheme %q (expected oracle://user:password@host:1521/service)", u.Scheme)
	}

	adminConn, effectiveConfig, err := sqlbinding.InitService(ctx, "oracle", connURL, serviceConfig, runtime)
	if err != nil {
		return err
	}

	b.serviceConfig = effectiveConfig
	b.adminConn = adminConn
	return nil
}

func (b *OracleServiceBinding) CloseService(ctx context.Context) error {
	if b.adminConn == nil {
		return nil
	}
	return b.adminConn.Close()
}

func (b *OracleServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata binding.BindingMetadata, derivedFromMetadata *binding.BindingMetadata, isStaging bool) (map[string]string, []binding.Artifact, error) {
	// 30 chars: the traditional Oracle password length limit (and go-ora's
	// logon fails with longer passwords even where the server accepts them)
	password, err := binding.RandomHex(15)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating random password: %w", err)
	}

	userName, err := binding.AccountName(oracleUserPrefixProd, oracleUserPrefixStg, bindingId, isStaging,
		binding.NameOptions{MaxLen: oracleMaxIdentLen, Uppercase: true})
	if err != nil {
		return nil, nil, err
	}

	schemaName := userName // Base binding: the user is the schema
	if derivedFromMetadata != nil {
		schemaName = derivedFromMetadata.Account["schema"]
		if schemaName == "" {
			return nil, nil, fmt.Errorf("derived binding base account is missing the schema field")
		}
	}

	quotedUser := quoteOracleIdent(userName)
	quotedSchema := quoteOracleIdent(schemaName)
	// Oracle passwords are quoted as identifiers, not string literals
	quotedPassword := quoteOracleIdent(password)

	// Oracle DDL auto-commits each statement, so a partial failure cannot be
	// rolled back here. The user artifact is returned with the error once
	// created so the caller can delete it (DROP USER CASCADE removes any
	// dependent objects like the logon trigger).
	artifacts := []binding.Artifact{}

	createUserSQL := fmt.Sprintf("CREATE USER %s IDENTIFIED BY %s", quotedUser, quotedPassword)
	if _, err := b.adminConn.ExecContext(ctx, createUserSQL); err != nil {
		return nil, artifacts, fmt.Errorf("error creating user %s: %w", userName, err)
	}
	artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactUser, Name: userName})

	if derivedFromMetadata == nil {
		// Base binding: creation privileges (these system privileges only apply
		// within the user's own schema) and quota on the default tablespace so
		// the user can store data.
		tablespace, err := b.defaultTablespace(ctx)
		if err != nil {
			return nil, artifacts, err
		}
		quotaSQL := fmt.Sprintf("ALTER USER %s QUOTA UNLIMITED ON %s", quotedUser, quoteOracleIdent(tablespace))
		if _, err := b.adminConn.ExecContext(ctx, quotaSQL); err != nil {
			return nil, artifacts, fmt.Errorf("error setting tablespace quota for user %s: %w", userName, err)
		}

		grantSQL := fmt.Sprintf("GRANT CREATE SESSION, CREATE TABLE, CREATE VIEW, CREATE SEQUENCE TO %s", quotedUser)
		if _, err := b.adminConn.ExecContext(ctx, grantSQL); err != nil {
			return nil, artifacts, fmt.Errorf("error granting create privileges to user %s: %w", userName, err)
		}
	} else {
		// Derived binding: connect only; application privileges are assigned by
		// ApplyGrants.
		grantSQL := fmt.Sprintf("GRANT CREATE SESSION TO %s", quotedUser)
		if _, err := b.adminConn.ExecContext(ctx, grantSQL); err != nil {
			return nil, artifacts, fmt.Errorf("error granting session privilege to user %s: %w", userName, err)
		}

		// Logon trigger owned by the derived user sets CURRENT_SCHEMA to the
		// base schema, so the account resolves unqualified table names in the
		// base binding's schema (like the Postgres binding's search_path).
		// Setting CURRENT_SCHEMA does not require the ALTER SESSION privilege.
		triggerSQL := fmt.Sprintf(`CREATE OR REPLACE TRIGGER %s.%s AFTER LOGON ON %s.SCHEMA
BEGIN
  EXECUTE IMMEDIATE 'ALTER SESSION SET CURRENT_SCHEMA=%s';
END;`, quotedUser, quoteOracleIdent(oracleLogonTriggerName), quotedUser, quotedSchema)
		if _, err := b.adminConn.ExecContext(ctx, triggerSQL); err != nil {
			return nil, artifacts, fmt.Errorf("error creating logon trigger for user %s: %w", userName, err)
		}
	}

	accountURL, accountDirectURL, err := binding.AccountURLs(b.serviceConfig["url"], userName, password, b.serviceConfig["binding_hostname"])
	if err != nil {
		return nil, artifacts, fmt.Errorf("error building account url: %w", err)
	}

	return map[string]string{
		"url":        accountURL,
		"url_direct": accountDirectURL,
		"user":       userName,
		"schema":     schemaName,
	}, artifacts, nil
}

// defaultTablespace returns the database's default permanent tablespace, used
// for the base binding user's quota.
func (b *OracleServiceBinding) defaultTablespace(ctx context.Context) (string, error) {
	var tablespace string
	err := b.adminConn.QueryRowContext(ctx,
		"SELECT property_value FROM database_properties WHERE property_name = 'DEFAULT_PERMANENT_TABLESPACE'").Scan(&tablespace)
	if err != nil {
		return "", fmt.Errorf("error querying default tablespace: %w", err)
	}
	return tablespace, nil
}

// DeleteArtifact drops one user previously reported as created by
// GenerateAccount. DROP USER CASCADE removes everything the user owns (tables,
// the logon trigger for derived users), which is safe because the user was
// created during the current operation.
func (b *OracleServiceBinding) DeleteArtifact(ctx context.Context, artifact binding.Artifact) error {
	if artifact.Name == "" {
		return fmt.Errorf("artifact name is required")
	}
	if artifact.Type != binding.ArtifactUser {
		return fmt.Errorf("unsupported oracle artifact type %s", artifact.Type)
	}

	var exists int
	err := b.adminConn.QueryRowContext(ctx, "SELECT 1 FROM all_users WHERE username = :1", artifact.Name).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("error checking user %s: %w", artifact.Name, err)
	}

	if _, err := b.adminConn.ExecContext(ctx, "DROP USER "+quoteOracleIdent(artifact.Name)+" CASCADE"); err != nil {
		return fmt.Errorf("error dropping user %s: %w", artifact.Name, err)
	}
	return nil
}

func (b *OracleServiceBinding) ApplyGrants(ctx context.Context, account map[string]string, bindingMetadata binding.BindingMetadata,
	derivedFromMetadata binding.BindingMetadata, reapplyAll bool) (binding.GrantApplyResult, error) {
	// The create grant type is excluded: Oracle has no schema-scoped create
	// privilege before 23ai (only the database-wide CREATE ANY TABLE), so it
	// cannot be supported safely.
	return binding.ApplyGrantsIncremental(bindingMetadata,
		[]binding.GrantType{binding.GrantTypeRead, binding.GrantTypeFull}, reapplyAll,
		func(grants []binding.BindingGrant) ([]binding.BindingGrant, error) {
			return b.applyPerms(ctx, "grant", grants, account["schema"], account["user"])
		})
}

func (b *OracleServiceBinding) RevokeGrants(ctx context.Context, account map[string]string,
	_ binding.BindingMetadata, revokes, regrants []binding.BindingGrant) error {
	return binding.RevokeThenRegrant(revokes, regrants, func(op string, grants []binding.BindingGrant) error {
		_, err := b.applyPerms(ctx, op, grants, account["schema"], account["user"])
		return err
	})
}

// applyPerms runs GRANT or REVOKE statements for binding grants on the admin
// connection. operation must be "grant" or "revoke".
//
// The admin grants on other users' objects via the GRANT ANY OBJECT PRIVILEGE
// system privilege; Oracle records such grants as if made by the object owner.
// `*`-target grants are expanded over the schema's current tables, views and
// sequences; objects created later need a reapply (`--reapply-all`) since
// pre-23ai Oracle has no schema-scoped privileges or default-privilege
// mechanism. Revoking a privilege that is not held (ORA-01927) is treated as a
// no-op so revokes of deferred/partially applied grants are harmless.
func (b *OracleServiceBinding) applyPerms(ctx context.Context, operation string,
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
	verb := "revoking"
	if isGrant {
		verb = "granting"
	}

	grantsDone := []binding.BindingGrant{}
	for _, grant := range grants {
		switch grant.GrantType {
		case binding.GrantTypeRead:
			if grant.GrantTarget == binding.GrantTargetAll {
				if err := b.applySchemaWide(ctx, isGrant, schema, user, "SELECT", "SELECT", ""); err != nil {
					return nil, fmt.Errorf("error %s select privileges on schema %s: %w", verb, schema, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				applied, err := b.applyObjectPerm(ctx, isGrant, schema, grant.GrantTarget, user, "SELECT")
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

		case binding.GrantTypeFull:
			if grant.GrantTarget == binding.GrantTargetAll {
				if err := b.applySchemaWide(ctx, isGrant, schema, user, "SELECT, INSERT, UPDATE, DELETE", "SELECT", "SELECT"); err != nil {
					return nil, fmt.Errorf("error %s full privileges on schema %s: %w", verb, schema, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				applied, err := b.applyObjectPerm(ctx, isGrant, schema, grant.GrantTarget, user, "SELECT, INSERT, UPDATE, DELETE")
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
		default:
			return nil, fmt.Errorf("unsupported grant type %s for oracle bindings", grant.GrantType)
		}
	}
	return grantsDone, nil
}

// applySchemaWide grants/revokes tablePrivs on every table, viewPrivs on every
// view and sequencePrivs on every sequence currently in the schema (empty priv
// strings skip that object class). A concurrent DROP between listing and
// grant/revoke is tolerated (ORA-00942/ORA-02289), as is revoking a privilege
// that was never granted (ORA-01927).
func (b *OracleServiceBinding) applySchemaWide(ctx context.Context, isGrant bool, schema, user, tablePrivs, viewPrivs, sequencePrivs string) error {
	quotedSchema := quoteOracleIdent(schema)
	quotedUser := quoteOracleIdent(user)

	apply := func(privs, objectName string, missingCode int) error {
		if privs == "" {
			return nil
		}
		var stmt string
		if isGrant {
			stmt = fmt.Sprintf("GRANT %s ON %s.%s TO %s", privs, quotedSchema, quoteOracleIdent(objectName), quotedUser)
		} else {
			stmt = fmt.Sprintf("REVOKE %s ON %s.%s FROM %s", privs, quotedSchema, quoteOracleIdent(objectName), quotedUser)
		}
		if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
			if isOracleErr(err, missingCode) || (!isGrant && isOracleErr(err, oraCannotRevoke)) {
				return nil
			}
			return fmt.Errorf("object %s.%s: %w", schema, objectName, err)
		}
		return nil
	}

	tables, views, sequences, err := b.listSchemaObjects(ctx, schema)
	if err != nil {
		return err
	}
	for _, table := range tables {
		if err := apply(tablePrivs, table, oraTableNotFound); err != nil {
			return err
		}
	}
	for _, view := range views {
		if err := apply(viewPrivs, view, oraTableNotFound); err != nil {
			return err
		}
	}
	for _, sequence := range sequences {
		if err := apply(sequencePrivs, sequence, oraSequenceMissing); err != nil {
			return err
		}
	}
	return nil
}

// applyObjectPerm grants/revokes privs on one table or view. The object's
// existence is prechecked so a grant on a not-yet-created table is reported as
// deferred (returns false, nil) instead of failing the operation. The target is
// matched exactly first (covering objects created with quoted mixed-case
// names), then falling back to Oracle's uppercase normalization for unquoted
// identifiers.
func (b *OracleServiceBinding) applyObjectPerm(ctx context.Context, isGrant bool, schema, target, user, privs string) (bool, error) {
	objectName := target
	exists, err := b.objectExists(ctx, schema, objectName)
	if err != nil {
		return false, fmt.Errorf("error checking if object %s.%s exists: %w", schema, objectName, err)
	}
	if !exists && target != strings.ToUpper(target) {
		objectName = strings.ToUpper(target)
		exists, err = b.objectExists(ctx, schema, objectName)
		if err != nil {
			return false, fmt.Errorf("error checking if object %s.%s exists: %w", schema, objectName, err)
		}
	}
	if !exists {
		return false, nil
	}

	var stmt string
	if isGrant {
		stmt = fmt.Sprintf("GRANT %s ON %s.%s TO %s", privs, quoteOracleIdent(schema), quoteOracleIdent(objectName), quoteOracleIdent(user))
	} else {
		stmt = fmt.Sprintf("REVOKE %s ON %s.%s FROM %s", privs, quoteOracleIdent(schema), quoteOracleIdent(objectName), quoteOracleIdent(user))
	}
	if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
		if isOracleErr(err, oraTableNotFound) {
			// Lost a race with a DROP between precheck and grant; treat as
			// deferred so the caller logs and moves on instead of aborting.
			return false, nil
		}
		if !isGrant && isOracleErr(err, oraCannotRevoke) {
			// Revoking something that was never granted is harmless.
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// listSchemaObjects returns the tables, views and sequences currently owned by
// the schema, for expanding `*`-target grants.
func (b *OracleServiceBinding) listSchemaObjects(ctx context.Context, schema string) (tables, views, sequences []string, err error) {
	collect := func(query string) ([]string, error) {
		rows, err := b.adminConn.QueryContext(ctx, query, schema)
		if err != nil {
			return nil, fmt.Errorf("error listing objects in schema %s: %w", schema, err)
		}
		defer rows.Close() //nolint:errcheck
		names := []string{}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return nil, fmt.Errorf("error reading objects in schema %s: %w", schema, err)
			}
			names = append(names, name)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("error reading objects in schema %s: %w", schema, err)
		}
		return names, nil
	}

	if tables, err = collect("SELECT table_name FROM all_tables WHERE owner = :1"); err != nil {
		return nil, nil, nil, err
	}
	if views, err = collect("SELECT view_name FROM all_views WHERE owner = :1"); err != nil {
		return nil, nil, nil, err
	}
	if sequences, err = collect("SELECT sequence_name FROM all_sequences WHERE sequence_owner = :1"); err != nil {
		return nil, nil, nil, err
	}
	return tables, views, sequences, nil
}

// objectExists reports whether the schema contains a table or view with the
// given (already uppercased) name. Used to precheck object-level GRANT/REVOKE.
func (b *OracleServiceBinding) objectExists(ctx context.Context, schema, objectName string) (bool, error) {
	const q = `SELECT 1 FROM (
		SELECT table_name AS name FROM all_tables WHERE owner = :1
		UNION ALL
		SELECT view_name AS name FROM all_views WHERE owner = :2
	) WHERE name = :3`
	var present int
	if err := b.adminConn.QueryRowContext(ctx, q, schema, schema, objectName).Scan(&present); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// quoteOracleIdent quotes an identifier using double quotes.
func quoteOracleIdent(name string) string {
	return sqlbinding.QuoteIdentDouble(name)
}

func (b *OracleServiceBinding) RunCommand(ctx context.Context, bindingMetadata binding.BindingMetadata, command string) (map[string]any, error) {
	// Oracle rejects trailing semicolons on single SQL statements; PL/SQL
	// blocks (BEGIN/DECLARE) keep theirs.
	return sqlbinding.RunCommand(ctx, "oracle", bindingMetadata.Account[binding.AccountKeyURLDirect], command,
		sqlbinding.RunCommandOptions{})
}
