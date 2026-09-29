// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: LicenseRef-scancode-polyform-free-trial-1.0.0

package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"
)

type lookupConnector struct{ conn *lookupConn }

func (c lookupConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (c lookupConnector) Driver() driver.Driver                        { return lookupDriver{} }

type lookupDriver struct{}

func (lookupDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type lookupConn struct {
	query string
	args  []driver.NamedValue
}

func (*lookupConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*lookupConn) Close() error                        { return nil }
func (*lookupConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (c *lookupConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.query, c.args = query, args
	return emptyLookupRows{}, nil
}

type emptyLookupRows struct{}

func (emptyLookupRows) Columns() []string         { return []string{"table_name"} }
func (emptyLookupRows) Close() error              { return nil }
func (emptyLookupRows) Next([]driver.Value) error { return io.EOF }

func TestResolveTableBindsUntrustedNames(t *testing.T) {
	conn := &lookupConn{}
	db := sql.OpenDB(lookupConnector{conn})
	defer db.Close() //nolint:errcheck
	b := &DatabricksServiceBinding{adminDB: db, serviceConfig: map[string]string{"catalog": "catalog"}}
	schema, target := `schema\'`, `\') UNION ALL SELECT 'private_table' --`
	_, exists, err := b.resolveTable(context.Background(), schema, target)
	if err != nil || exists {
		t.Fatalf("lookup: %v %v", exists, err)
	}
	want := "SELECT table_name FROM `catalog`.information_schema.tables WHERE table_schema = ? AND table_name = lower(?) LIMIT 1"
	if conn.query != want {
		t.Fatalf("lookup interpolated untrusted input: %s", conn.query)
	}
	if len(conn.args) != 2 || conn.args[0].Value != schema || conn.args[1].Value != target {
		t.Fatalf("lookup parameters: %v", conn.args)
	}
}
