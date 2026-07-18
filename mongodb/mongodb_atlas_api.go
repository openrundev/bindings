// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/icholy/digest"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Minimal Atlas Admin API client for database user management. Atlas clusters
// block the in-database user management commands (createUser/dropUser/
// createRole), so the atlas service type manages users through this project
// level REST API instead. Only the databaseUsers endpoints the binding needs
// are implemented; the generated Atlas SDK is avoided to keep the dependency
// footprint small.
const (
	// Pinned resource version per the Atlas versioned-API scheme; sent as the
	// Accept/Content-Type media type on every request.
	atlasAPIMediaType = "application/vnd.atlas.2023-01-01+json"

	atlasDefaultBaseURL = "https://cloud.mongodb.com"

	// SCRAM database users always authenticate against the admin database.
	atlasAuthDatabase = "admin"
)

// atlasRole is one entry in a database user's roles array. RoleName can be a
// built-in role; read and readWrite additionally accept an exact collection
// scope via CollectionName (this is the Atlas replacement for the custom
// roles the self-hosted mode has to create).
type atlasRole struct {
	RoleName       string `json:"roleName"`
	DatabaseName   string `json:"databaseName"`
	CollectionName string `json:"collectionName,omitempty"`
}

// atlasScope restricts a database user to named deployments in the project
// (type CLUSTER); without scopes a user can access every cluster.
type atlasScope struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type atlasDatabaseUser struct {
	DatabaseName string       `json:"databaseName"`
	Username     string       `json:"username"`
	Password     string       `json:"password,omitempty"`
	Description  string       `json:"description,omitempty"`
	Roles        []atlasRole  `json:"roles"`
	Scopes       []atlasScope `json:"scopes,omitempty"`
}

// atlasAPIError is a non-2xx Atlas API response. StatusCode is kept so
// callers can special-case 404 (delete after rollback) and 409 (duplicate
// user).
type atlasAPIError struct {
	StatusCode int    `json:"-"`
	ErrorCode  string `json:"errorCode"`
	Detail     string `json:"detail"`
	Reason     string `json:"reason"`
}

func (e *atlasAPIError) Error() string {
	msg := e.Detail
	if msg == "" {
		msg = e.Reason
	}
	return fmt.Sprintf("atlas api error (status %d, code %s): %s", e.StatusCode, e.ErrorCode, msg)
}

// atlasErrorStatus returns the HTTP status of an atlasAPIError, or 0 when the
// error is not an Atlas API response error.
func atlasErrorStatus(err error) int {
	var apiErr *atlasAPIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

type atlasClient struct {
	baseURL   string
	projectID string
	client    *http.Client
}

// newAtlasDigestClient authenticates with a programmatic API key pair using
// HTTP digest, the legacy Atlas Admin API auth method.
func newAtlasDigestClient(baseURL, projectID, publicKey, privateKey string) *atlasClient {
	return &atlasClient{
		baseURL:   baseURL,
		projectID: projectID,
		client: &http.Client{
			Transport: &digest.Transport{Username: publicKey, Password: privateKey},
		},
	}
}

// newAtlasOAuthClient authenticates with a service account using the OAuth2
// client credentials flow, the auth method Atlas currently recommends. Token
// refresh is handled by the oauth2 transport. The background context keeps
// the token source alive past InitializeService.
func newAtlasOAuthClient(baseURL, projectID, clientID, clientSecret string) *atlasClient {
	conf := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     baseURL + "/api/oauth/token",
		AuthStyle:    oauth2.AuthStyleInHeader,
	}
	return &atlasClient{
		baseURL:   baseURL,
		projectID: projectID,
		client:    conf.Client(context.Background()),
	}
}

func (c *atlasClient) usersPath() string {
	return "/api/atlas/v2/groups/" + url.PathEscape(c.projectID) + "/databaseUsers"
}

func (c *atlasClient) userPath(username string) string {
	return c.usersPath() + "/" + atlasAuthDatabase + "/" + url.PathEscape(username)
}

// verifyAccess checks that the configured credentials and project id are
// valid by listing one database user.
func (c *atlasClient) verifyAccess(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, c.usersPath()+"?itemsPerPage=1", nil, nil)
}

func (c *atlasClient) createDatabaseUser(ctx context.Context, user atlasDatabaseUser) error {
	return c.do(ctx, http.MethodPost, c.usersPath(), user, nil)
}

// updateDatabaseUserRoles replaces the user's complete roles array in one
// PATCH; fields not included (password, scopes) are left unchanged.
func (c *atlasClient) updateDatabaseUserRoles(ctx context.Context, username string, roles []atlasRole) error {
	body := struct {
		Roles []atlasRole `json:"roles"`
	}{Roles: roles}
	return c.do(ctx, http.MethodPatch, c.userPath(username), body, nil)
}

func (c *atlasClient) deleteDatabaseUser(ctx context.Context, username string) error {
	return c.do(ctx, http.MethodDelete, c.userPath(username), nil, nil)
}

func (c *atlasClient) do(ctx context.Context, method, path string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("error encoding atlas api request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("error creating atlas api request: %w", err)
	}
	req.Header.Set("Accept", atlasAPIMediaType)
	if body != nil {
		req.Header.Set("Content-Type", atlasAPIMediaType)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("error calling atlas api: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("error reading atlas api response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &atlasAPIError{StatusCode: resp.StatusCode}
		_ = json.Unmarshal(respBody, apiErr) // best effort, the status code alone is meaningful
		return apiErr
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("error decoding atlas api response: %w", err)
		}
	}
	return nil
}
