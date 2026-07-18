// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sijms/go-ora/v2/network"
)

func TestQuoteOracleIdent(t *testing.T) {
	tests := []struct{ in, want string }{
		{"CP_ABC", `"CP_ABC"`},
		{"lower", `"lower"`},
		{`we"ird`, `"we""ird"`},
		{"", `""`},
	}
	for _, tt := range tests {
		if got := quoteOracleIdent(tt.in); got != tt.want {
			t.Errorf("quoteOracleIdent(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsOracleErr(t *testing.T) {
	notFound := &network.OracleError{ErrCode: oraTableNotFound}
	if !isOracleErr(notFound, oraTableNotFound) {
		t.Fatal("expected match for ORA-00942")
	}
	if isOracleErr(notFound, oraCannotRevoke) {
		t.Fatal("unexpected match for a different code")
	}
	// Wrapped errors are unwrapped
	if !isOracleErr(fmt.Errorf("query failed: %w", notFound), oraTableNotFound) {
		t.Fatal("expected match through wrapping")
	}
	if isOracleErr(errors.New("plain error"), oraTableNotFound) {
		t.Fatal("unexpected match for non-oracle error")
	}
	if isOracleErr(nil, oraTableNotFound) {
		t.Fatal("unexpected match for nil error")
	}
}
