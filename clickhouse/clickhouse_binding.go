// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	binding "github.com/openrundev/openrun/pkg/binding"
	"github.com/openrundev/openrun/pkg/binding/sqlbinding"
)

// ClickHouse binding model: each binding gets a ROLE plus a USER whose default
// role is that role. A base binding also gets a DATABASE (ClickHouse's
// namespace unit; there are no schemas), which is the user's default database;
// derived bindings get a user whose default database is the base binding's
// database, with access assigned only through grants on the role.
//
// One service type covers self-hosted ClickHouse and ClickHouse Cloud: both
// support SQL-driven access control over the same connection. Differences are
// config-level only — Cloud requires TLS (an https:// or secure=true url) and
// enforces password complexity (generated passwords always comply), while
// multi-node self-hosted clusters without replicated access storage set the
// `cluster` config key so access DDL runs ON CLUSTER.
//
//   - db.* grants cover current AND future tables (newly created objects
//     inherit parent grants), so `*` grants need no reapply step.
//   - ClickHouse has no UPDATE/DELETE privileges: mutations and lightweight
//     deletes fall under ALTER, so `full` includes ALTER.
//   - Generated users are created with IDENTIFIED WITH sha256_hash (the hash
//     is computed provider-side, so the password never appears in DDL).
//   - The admin user needs CREATE USER/ROLE/DATABASE and the privileges it
//     grants WITH GRANT OPTION (the Cloud default admin user qualifies).
const (
	clickhouseUserPrefixProd = "cl_usr_prd_"
	clickhouseUserPrefixStg  = "cl_usr_stg_"
	clickhouseRolePrefixProd = "cl_rol_prd_"
	clickhouseRolePrefixStg  = "cl_rol_stg_"
	clickhouseDBPrefixProd   = "cl_db_prd_"
	clickhouseDBPrefixStg    = "cl_db_stg_"

	// Privileges applied for full:* (database-scoped). Data access plus
	// mutations (ALTER) and object create/drop, mirroring the other SQL
	// bindings' `full` semantics.
	clickhouseFullDBPrivileges = "SELECT, INSERT, ALTER, CREATE TABLE, CREATE VIEW, DROP TABLE, DROP VIEW, TRUNCATE, OPTIMIZE"
	// Privileges applied for full:<table> (table-scoped): data access and
	// mutations only, no create/drop.
	clickhouseFullTablePrivileges = "SELECT, INSERT, ALTER, TRUNCATE, OPTIMIZE"
)

type ClickHouseServiceBinding struct {
	*binding.Logger
	serviceConfig map[string]string
	adminConn     *sql.DB // Admin connection to the service, available after InitService
}

var _ binding.ServiceBinding = (*ClickHouseServiceBinding)(nil)

func NewClickHouseServiceBinding() binding.ServiceBinding {
	return &ClickHouseServiceBinding{}
}

func (b *ClickHouseServiceBinding) GetAccountEnv(ctx context.Context) ([]string, []string, error) {
	return []string{"url", "url_direct", "user", "role", "database"}, []string{}, nil
}

func (b *ClickHouseServiceBinding) InitializeService(ctx context.Context, logger *binding.Logger, serviceConfig map[string]string, runtime binding.ServiceBindingRuntime) error {
	b.Logger = logger
	if err := binding.VerifyKeys(configKeys(serviceConfig), []string{"url"}, []string{"binding_hostname", "cluster"}); err != nil {
		return err
	}
	u, err := url.Parse(serviceConfig["url"])
	if err != nil {
		return fmt.Errorf("error parsing clickhouse url: %w", err)
	}
	switch u.Scheme {
	case "clickhouse", "http", "https":
	default:
		return fmt.Errorf("unsupported clickhouse url scheme %q (expected clickhouse://host:9000, https://host:8443?secure=true or http://host:8123)", u.Scheme)
	}

	// sqlbinding.InitService is not used here: it re-validates the config
	// keys against a fixed url/binding_hostname list, which would reject the
	// cluster key. Same steps inline: open, ping, apply the localhost
	// binding hostname.
	adminConn, err := sql.Open("clickhouse", serviceConfig["url"])
	if err != nil {
		return fmt.Errorf("error opening admin connection: %w", err)
	}
	if err := adminConn.PingContext(ctx); err != nil {
		adminConn.Close() //nolint:errcheck
		return fmt.Errorf("error verifying clickhouse connection: %w", err)
	}

	b.serviceConfig = binding.ServiceConfigWithLocalhostBindingHostname(serviceConfig, serviceConfig["url"], runtime)
	b.adminConn = adminConn
	return nil
}

func (b *ClickHouseServiceBinding) CloseService(ctx context.Context) error {
	if b.adminConn == nil {
		return nil
	}
	return b.adminConn.Close()
}

// onCluster returns the ON CLUSTER clause for access DDL when the cluster
// service config key is set (multi-node self-hosted clusters without
// replicated access storage), empty otherwise.
func (b *ClickHouseServiceBinding) onCluster() string {
	if cluster := b.serviceConfig["cluster"]; cluster != "" {
		return " ON CLUSTER " + quoteClickhouseIdent(cluster)
	}
	return ""
}

func (b *ClickHouseServiceBinding) GenerateAccount(ctx context.Context, bindingId, bindingPath string, bindingMetadata binding.BindingMetadata, derivedFromMetadata *binding.BindingMetadata, isStaging bool) (map[string]string, []binding.Artifact, error) {
	password, err := generateClickhousePassword()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating random password: %w", err)
	}
	passwordHash := sha256.Sum256([]byte(password))

	nameOpts := binding.NameOptions{}
	userName, err := binding.AccountName(clickhouseUserPrefixProd, clickhouseUserPrefixStg, bindingId, isStaging, nameOpts)
	if err != nil {
		return nil, nil, err
	}
	roleName, err := binding.AccountName(clickhouseRolePrefixProd, clickhouseRolePrefixStg, bindingId, isStaging, nameOpts)
	if err != nil {
		return nil, nil, err
	}
	databaseName, err := binding.AccountName(clickhouseDBPrefixProd, clickhouseDBPrefixStg, bindingId, isStaging, nameOpts)
	if err != nil {
		return nil, nil, err
	}
	if derivedFromMetadata != nil {
		// Derived binding, use the base binding's database
		databaseName = derivedFromMetadata.Account["database"]
		if databaseName == "" {
			return nil, nil, fmt.Errorf("derived binding base account is missing the database field")
		}
	}

	quotedUser := quoteClickhouseIdent(userName)
	quotedRole := quoteClickhouseIdent(roleName)
	quotedDB := quoteClickhouseIdent(databaseName)
	onCluster := b.onCluster()

	// ClickHouse access DDL auto-commits per statement, so a partial failure
	// cannot be rolled back here; the artifacts created so far are returned
	// with the error so the caller can delete them.
	artifacts := []binding.Artifact{}

	if _, err := b.adminConn.ExecContext(ctx, "CREATE ROLE "+quotedRole+onCluster); err != nil {
		return nil, artifacts, fmt.Errorf("error creating role %s: %w", roleName, err)
	}
	artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactRole, Name: roleName})

	if derivedFromMetadata == nil {
		// Base binding: the database plus full privileges on it for the role.
		// Objects the account creates live in this database; db.* grants cover
		// tables created later automatically.
		if _, err := b.adminConn.ExecContext(ctx, "CREATE DATABASE "+quotedDB+onCluster); err != nil {
			return nil, artifacts, fmt.Errorf("error creating database %s: %w", databaseName, err)
		}
		artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactDatabase, Name: databaseName})

		grantSQL := fmt.Sprintf("GRANT%s %s ON %s.* TO %s", onCluster, clickhouseFullDBPrivileges, quotedDB, quotedRole)
		if _, err := b.adminConn.ExecContext(ctx, grantSQL); err != nil {
			return nil, artifacts, fmt.Errorf("error granting privileges on database %s: %w", databaseName, err)
		}
	}
	// Derived bindings: application privileges are assigned only by ApplyGrants.

	// The password hash is computed provider-side so the password itself never
	// appears in DDL. The generated password meets ClickHouse Cloud's
	// complexity policy (the hash form is not policy-checked, but a compliant
	// password keeps behavior uniform if the identification type changes).
	createUserSQL := fmt.Sprintf("CREATE USER %s%s IDENTIFIED WITH sha256_hash BY '%s' DEFAULT ROLE %s DEFAULT DATABASE %s",
		quotedUser, onCluster, strings.ToUpper(hex.EncodeToString(passwordHash[:])), quotedRole, quotedDB)
	if _, err := b.adminConn.ExecContext(ctx, createUserSQL); err != nil {
		return nil, artifacts, fmt.Errorf("error creating user %s: %w", userName, err)
	}
	artifacts = append(artifacts, binding.Artifact{Type: binding.ArtifactUser, Name: userName})

	if _, err := b.adminConn.ExecContext(ctx, "GRANT"+onCluster+" "+quotedRole+" TO "+quotedUser); err != nil {
		return nil, artifacts, fmt.Errorf("error granting role %s to user %s: %w", roleName, userName, err)
	}

	accountURL, accountDirectURL, err := clickhouseAccountURLs(b.serviceConfig["url"], userName, password, databaseName, b.serviceConfig["binding_hostname"])
	if err != nil {
		return nil, artifacts, fmt.Errorf("error building account url: %w", err)
	}

	return map[string]string{
		"url":        accountURL,
		"url_direct": accountDirectURL,
		"user":       userName,
		"role":       roleName,
		"database":   databaseName,
	}, artifacts, nil
}

// clickhouseAccountURLs builds the account connection URL pair from the admin
// URL: the generated credentials replace the admin ones and the path is set to
// the binding database (the admin URL's database would be inaccessible to the
// account). Query parameters like secure=true carry over. url applies the
// binding hostname; url_direct keeps the service hostname.
func clickhouseAccountURLs(adminURL, user, password, database, bindingHostname string) (accountURL, accountDirectURL string, err error) {
	u, err := url.Parse(adminURL)
	if err != nil {
		return "", "", err
	}
	u.User = url.UserPassword(user, password)
	u.Path = "/" + database
	accountDirectURL = u.String()
	binding.SetURLHostname(u, bindingHostname)
	return u.String(), accountDirectURL, nil
}

// DeleteArtifact drops one role, user or database previously reported as
// created by GenerateAccount, either to undo a rolled-back operation or when
// the binding is deleted. The caller passes artifacts back in reverse creation
// order. DROP DATABASE drops the database's tables with it.
func (b *ClickHouseServiceBinding) DeleteArtifact(ctx context.Context, artifact binding.Artifact) error {
	if artifact.Name == "" {
		return fmt.Errorf("artifact name is required")
	}

	var stmt string
	switch artifact.Type {
	case binding.ArtifactRole:
		stmt = "DROP ROLE IF EXISTS " + quoteClickhouseIdent(artifact.Name) + b.onCluster()
	case binding.ArtifactUser:
		stmt = "DROP USER IF EXISTS " + quoteClickhouseIdent(artifact.Name) + b.onCluster()
	case binding.ArtifactDatabase:
		stmt = "DROP DATABASE IF EXISTS " + quoteClickhouseIdent(artifact.Name) + b.onCluster()
	default:
		return fmt.Errorf("unsupported clickhouse artifact type %s", artifact.Type)
	}
	if _, err := b.adminConn.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("error dropping %s %s: %w", artifact.Type, artifact.Name, err)
	}
	return nil
}

func (b *ClickHouseServiceBinding) ApplyGrants(ctx context.Context, account map[string]string, bindingMetadata binding.BindingMetadata,
	derivedFromMetadata binding.BindingMetadata, reapplyAll bool) (binding.GrantApplyResult, error) {
	return binding.ApplyGrantsIncremental(bindingMetadata,
		[]binding.GrantType{binding.GrantTypeRead, binding.GrantTypeCreate, binding.GrantTypeFull}, reapplyAll,
		func(grants []binding.BindingGrant) ([]binding.BindingGrant, error) {
			return b.applyPerms(ctx, "grant", grants, account["database"], account["role"])
		})
}

func (b *ClickHouseServiceBinding) RevokeGrants(ctx context.Context, account map[string]string,
	_ binding.BindingMetadata, revokes, regrants []binding.BindingGrant) error {
	return binding.RevokeThenRegrant(revokes, regrants, func(op string, grants []binding.BindingGrant) error {
		_, err := b.applyPerms(ctx, op, grants, account["database"], account["role"])
		return err
	})
}

// applyPerms runs GRANT or REVOKE statements for binding grants on the admin
// connection. operation must be "grant" or "revoke". Grants always target the
// binding's role.
//
// db.* privileges cover every current and future table in the database, so
// `*`-target grants need no reapply when tables are added. Only
// table-specific grants are deferred when the target does not exist yet.
// Revoking a privilege that is not held is a no-op in ClickHouse.
func (b *ClickHouseServiceBinding) applyPerms(ctx context.Context, operation string,
	grants []binding.BindingGrant, database, role string) ([]binding.BindingGrant, error) {
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

	quotedDB := quoteClickhouseIdent(database)
	quotedRole := quoteClickhouseIdent(role)
	onCluster := b.onCluster()

	// applyStmt formats one GRANT/REVOKE of privs at the given scope
	// ("db.*" or "db.table").
	applyStmt := func(privs, scope string) error {
		var stmt string
		if isGrant {
			stmt = fmt.Sprintf("GRANT%s %s ON %s TO %s", onCluster, privs, scope, quotedRole)
		} else {
			stmt = fmt.Sprintf("REVOKE%s %s ON %s FROM %s", onCluster, privs, scope, quotedRole)
		}
		_, err := b.adminConn.ExecContext(ctx, stmt)
		return err
	}

	// tableSpecific grants/revokes privs on one table or view, deferring the
	// grant when the target does not exist yet (returns false, nil).
	tableSpecific := func(target, privs string) (bool, error) {
		exists, err := b.tableExists(ctx, database, target)
		if err != nil {
			return false, err
		}
		if !exists {
			return false, nil
		}
		if err := applyStmt(privs, quotedDB+"."+quoteClickhouseIdent(target)); err != nil {
			return false, err
		}
		return true, nil
	}

	logDeferred := func(grant binding.BindingGrant) {
		if isGrant {
			b.Warn().Str("grant", grant.String()).Str("database", database).Str("table", grant.GrantTarget).
				Msg("table does not exist yet; grant deferred until reconcile")
		} else {
			b.Warn().Str("grant", grant.String()).Str("database", database).Str("table", grant.GrantTarget).
				Msg("table does not exist; revoke skipped")
		}
	}

	grantsDone := []binding.BindingGrant{}
	for _, grant := range grants {
		switch grant.GrantType {
		case binding.GrantTypeRead:
			if grant.GrantTarget == binding.GrantTargetAll {
				if err := applyStmt("SELECT", quotedDB+".*"); err != nil {
					return nil, fmt.Errorf("error %s select privileges on database %s: %w", verb, database, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				applied, err := tableSpecific(grant.GrantTarget, "SELECT")
				if err != nil {
					return nil, fmt.Errorf("error %s select privileges on table %s.%s: %w", verb, database, grant.GrantTarget, err)
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
			if err := applyStmt("CREATE TABLE, CREATE VIEW", quotedDB+".*"); err != nil {
				return nil, fmt.Errorf("error %s create privileges on database %s: %w", verb, database, err)
			}
			grantsDone = append(grantsDone, grant)

		case binding.GrantTypeFull:
			if grant.GrantTarget == binding.GrantTargetAll {
				if err := applyStmt(clickhouseFullDBPrivileges, quotedDB+".*"); err != nil {
					return nil, fmt.Errorf("error %s full privileges on database %s: %w", verb, database, err)
				}
				grantsDone = append(grantsDone, grant)
			} else {
				applied, err := tableSpecific(grant.GrantTarget, clickhouseFullTablePrivileges)
				if err != nil {
					return nil, fmt.Errorf("error %s full privileges on table %s.%s: %w", verb, database, grant.GrantTarget, err)
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

// tableExists reports whether the database contains a table or view with the
// given name. Used to precheck table-level GRANT/REVOKE.
func (b *ClickHouseServiceBinding) tableExists(ctx context.Context, database, table string) (bool, error) {
	const q = "SELECT 1 FROM system.tables WHERE database = ? AND name = ?"
	var present int
	if err := b.adminConn.QueryRowContext(ctx, q, database, table).Scan(&present); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("error checking if table %s.%s exists: %w", database, table, err)
	}
	return true, nil
}

func (b *ClickHouseServiceBinding) RunCommand(ctx context.Context, bindingMetadata binding.BindingMetadata, command string) (map[string]any, error) {
	return sqlbinding.RunCommand(ctx, "clickhouse", bindingMetadata.Account[binding.AccountKeyURLDirect], command,
		sqlbinding.RunCommandOptions{RowReturningKeywords: []string{"SHOW", "DESC", "DESCRIBE", "EXISTS", "EXPLAIN"}})
}

// CheckHealth verifies the admin connection with a no-op query.
func (b *ClickHouseServiceBinding) CheckHealth(ctx context.Context) error {
	return sqlbinding.CheckHealth(ctx, b.adminConn, "select 1")
}

// CheckBindingHealth connects as the binding account and runs a no-op query,
// verifying the generated user still exists and its credentials work.
func (b *ClickHouseServiceBinding) CheckBindingHealth(ctx context.Context, bindingMetadata binding.BindingMetadata) error {
	return sqlbinding.CheckBindingHealth(ctx, "clickhouse", bindingMetadata.Account[binding.AccountKeyURLDirect], "select 1")
}

// generateClickhousePassword returns a random password satisfying ClickHouse
// Cloud's complexity policy (12+ chars with lower, upper, digit and special).
// The special characters are URL-unreserved so the password embeds in account
// URLs without escaping.
func generateClickhousePassword() (string, error) {
	const (
		lower   = "abcdefghijkmnopqrstuvwxyz"
		upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		digits  = "23456789"
		special = "~-._"
	)
	classes := []string{lower, upper, digits, special}

	// Six characters from each class, then shuffled: 24 chars with every
	// class guaranteed.
	password := make([]byte, 0, 24)
	for _, class := range classes {
		for range 6 {
			idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(class))))
			if err != nil {
				return "", err
			}
			password = append(password, class[idx.Int64()])
		}
	}
	for i := len(password) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}
	return string(password), nil
}

// quoteClickhouseIdent quotes an identifier with double quotes (ClickHouse
// supports SQL-standard double-quoted identifiers alongside backticks).
func quoteClickhouseIdent(name string) string {
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
