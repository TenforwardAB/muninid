/**
 * This file is licensed under the European Union Public License (EUPL) v1.2.
 * You may only use this work in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed "as is",
 * without any warranty or conditions of any kind.
 *
 * Copyright (c) 2024- Tenforward AB. All rights reserved.
 *
 * This file :: internal/authz/solutrix.go is part of the MuninID project.
 */

package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SolutrixConfig configures the solutrix PDP backend. See docs/authz-contract.md.
type SolutrixConfig struct {
	BaseURL      string        // solutrix-api base, e.g. https://solutrix-api.internal
	TokenURL     string        // client_credentials token endpoint (muninID's own)
	ClientID     string        // service client id
	ClientSecret string        // service client secret
	Scope        string        // optional client_credentials scope
	CacheTTL     time.Duration // decision cache TTL (0 disables caching)
	HTTPClient   *http.Client  // optional; defaults to a 5s-timeout client
}

// solutrixAuthorizer asks solutrix-api's ABAC engine for decisions over HTTP. It
// authenticates as a service via client_credentials and caches both the service
// token and (briefly) decisions.
type solutrixAuthorizer struct {
	cfg    SolutrixConfig
	http   *http.Client
	tokens *tokenSource

	mu    sync.Mutex
	cache map[string]cachedDecision
}

type cachedDecision struct {
	decision  Decision
	scope     Scope
	expiresAt time.Time
}

// NewSolutrixAuthorizer builds the solutrix backend. It validates that the
// required endpoints/credentials are present.
func NewSolutrixAuthorizer(cfg SolutrixConfig) (Authorizer, error) {
	if cfg.BaseURL == "" || cfg.TokenURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("authz: solutrix backend requires BaseURL, TokenURL, ClientID and ClientSecret")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	return &solutrixAuthorizer{
		cfg:    cfg,
		http:   hc,
		tokens: &tokenSource{cfg: cfg, http: hc},
		cache:  make(map[string]cachedDecision),
	}, nil
}

// checkRequest is the POST /authz/check body.
type checkRequest struct {
	Subject  checkSubject   `json:"subject"`
	Action   string         `json:"action"`
	Resource string         `json:"resource"`
	Scope    *string        `json:"scope,omitempty"`
	Instance map[string]any `json:"instance,omitempty"`
}

type checkSubject struct {
	UserID     string  `json:"user_id"`
	CustomerID *string `json:"customer_id"`
}

// checkResponse is the PDP reply.
type checkResponse struct {
	Allow         bool       `json:"allow"`
	Reason        string     `json:"reason"`
	PolicyVersion string     `json:"policy_version"`
	Visibility    visibility `json:"visibility"`
}

type visibility struct {
	Kind        string   `json:"kind"` // all | customerIds | none
	CustomerIDs []string `json:"customer_ids"`
	Fields      []string `json:"fields"`
}

func (a *solutrixAuthorizer) Authorize(ctx context.Context, req Request) (Decision, error) {
	key := cacheKey("dec", req.Subject.ID, req.Subject.CustomerID, req.Action, req.Resource.Type, req.Resource.ID, req.Resource.Owner)
	if d, ok := a.getCachedDecision(key); ok {
		return d, nil
	}

	body := checkRequest{
		Subject:  checkSubject{UserID: req.Subject.ID, CustomerID: ptrOrNil(req.Subject.CustomerID)},
		Action:   req.Action,
		Resource: req.Resource.Type,
	}
	// Send the instance whenever an owner is known — for a specific client
	// (ID set) or for a create targeting a customer (owner set, ID empty) — so
	// the PDP can scope-check the target tenant.
	if req.Resource.Owner != "" {
		body.Instance = map[string]any{"customerid": req.Resource.Owner}
	}

	resp, err := a.check(ctx, body)
	if err != nil {
		return Decision{}, err
	}
	d := Decision{Allow: resp.Allow, Reason: resp.Reason}
	a.putCachedDecision(key, cachedDecision{decision: d})
	return d, nil
}

func (a *solutrixAuthorizer) Scope(ctx context.Context, sub Subject, action, resourceType string) (Scope, error) {
	key := cacheKey("scope", sub.ID, sub.CustomerID, action, resourceType, "", "")
	if c, ok := a.getCachedScope(key); ok {
		return c, nil
	}

	resp, err := a.check(ctx, checkRequest{
		Subject:  checkSubject{UserID: sub.ID, CustomerID: ptrOrNil(sub.CustomerID)},
		Action:   action,
		Resource: resourceType,
	})
	if err != nil {
		return Scope{}, err
	}
	scope := visibilityToScope(resp.Visibility)
	a.putCachedDecision(key, cachedDecision{scope: scope})
	return scope, nil
}

// check performs the authenticated POST /authz/check call.
func (a *solutrixAuthorizer) check(ctx context.Context, body checkRequest) (checkResponse, error) {
	token, err := a.tokens.get(ctx)
	if err != nil {
		return checkResponse{}, fmt.Errorf("authz: service token: %w", err)
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return checkResponse{}, err
	}
	endpoint := strings.TrimRight(a.cfg.BaseURL, "/") + "/authz/check"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return checkResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	res, err := a.http.Do(httpReq)
	if err != nil {
		return checkResponse{}, fmt.Errorf("authz: solutrix request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return checkResponse{}, fmt.Errorf("authz: solutrix returned %d", res.StatusCode)
	}
	var out checkResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return checkResponse{}, fmt.Errorf("authz: decode solutrix response: %w", err)
	}
	return out, nil
}

func visibilityToScope(v visibility) Scope {
	switch v.Kind {
	case "all":
		return Scope{All: true}
	case "customerIds":
		return Scope{CustomerIDs: v.CustomerIDs}
	default: // "none" or unknown
		return Scope{CustomerIDs: nil}
	}
}

// ---- decision cache ----

func (a *solutrixAuthorizer) getCachedDecision(key string) (Decision, bool) {
	if a.cfg.CacheTTL <= 0 {
		return Decision{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.cache[key]
	if !ok || time.Now().After(c.expiresAt) {
		return Decision{}, false
	}
	return c.decision, true
}

func (a *solutrixAuthorizer) getCachedScope(key string) (Scope, bool) {
	if a.cfg.CacheTTL <= 0 {
		return Scope{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.cache[key]
	if !ok || time.Now().After(c.expiresAt) {
		return Scope{}, false
	}
	return c.scope, true
}

func (a *solutrixAuthorizer) putCachedDecision(key string, entry cachedDecision) {
	if a.cfg.CacheTTL <= 0 {
		return
	}
	entry.expiresAt = time.Now().Add(a.cfg.CacheTTL)
	a.mu.Lock()
	a.cache[key] = entry
	a.mu.Unlock()
}

func cacheKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}

func ptrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ---- service token source (client_credentials) ----

type tokenSource struct {
	cfg  SolutrixConfig
	http *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// get returns a valid service token, fetching/refreshing as needed.
func (t *tokenSource) get(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Refresh a little early to avoid using a token that expires mid-flight.
	if t.token != "" && time.Now().Before(t.expiresAt.Add(-30*time.Second)) {
		return t.token, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if t.cfg.Scope != "" {
		form.Set("scope", t.cfg.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(t.cfg.ClientID, t.cfg.ClientSecret)

	res, err := t.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", res.StatusCode)
	}
	var tr tokenResponse
	if err := json.NewDecoder(res.Body).Decode(&tr); err != nil {
		return "", err
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned empty access_token")
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	t.token = tr.AccessToken
	t.expiresAt = time.Now().Add(ttl)
	return t.token, nil
}
