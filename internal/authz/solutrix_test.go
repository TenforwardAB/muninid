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
 * This file :: internal/authz/solutrix_test.go is part of the MuninID project.
 */

package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSolutrix stands in for muninID's token endpoint and solutrix-api's PDP.
type fakeSolutrix struct {
	server      *httptest.Server
	tokenHits   int32
	lastCheck   checkRequest
	lastBearer  string
	checkResult checkResponse
}

func newFakeSolutrix(t *testing.T, result checkResponse) *fakeSolutrix {
	t.Helper()
	f := &fakeSolutrix{checkResult: result}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.tokenHits, 1)
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "client_credentials" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		if user, _, ok := r.BasicAuth(); !ok || user == "" {
			http.Error(w, "no basic auth", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "svc-token", TokenType: "Bearer", ExpiresIn: 300})
	})
	mux.HandleFunc("/authz/check", func(w http.ResponseWriter, r *http.Request) {
		f.lastBearer = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&f.lastCheck)
		_ = json.NewEncoder(w).Encode(f.checkResult)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeSolutrix) authorizer(t *testing.T, cacheTTL time.Duration) Authorizer {
	t.Helper()
	az, err := NewSolutrixAuthorizer(SolutrixConfig{
		BaseURL:      f.server.URL,
		TokenURL:     f.server.URL + "/oauth/token",
		ClientID:     "svc-client",
		ClientSecret: "svc-secret",
		Scope:        "authz:check",
		CacheTTL:     cacheTTL,
	})
	if err != nil {
		t.Fatalf("NewSolutrixAuthorizer: %v", err)
	}
	return az
}

func TestSolutrixAuthorize(t *testing.T) {
	f := newFakeSolutrix(t, checkResponse{Allow: true, Reason: "ok"})
	az := f.authorizer(t, 0)

	dec, err := az.Authorize(context.Background(), Request{
		Subject:  Subject{ID: "u1", CustomerID: "cust-a"},
		Action:   ActionUpdate,
		Resource: Resource{Type: ResourceClient, ID: "c1", Owner: "cust-a"},
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("Allow = false, want true")
	}
	if f.lastBearer != "Bearer svc-token" {
		t.Fatalf("bearer = %q, want Bearer svc-token", f.lastBearer)
	}
	if f.lastCheck.Subject.UserID != "u1" || f.lastCheck.Action != ActionUpdate || f.lastCheck.Resource != ResourceClient {
		t.Fatalf("unexpected check body: %+v", f.lastCheck)
	}
	if f.lastCheck.Instance["customerid"] != "cust-a" {
		t.Fatalf("instance = %+v, want customerid=cust-a", f.lastCheck.Instance)
	}
}

func TestSolutrixAuthorizeNoInstanceForCollection(t *testing.T) {
	f := newFakeSolutrix(t, checkResponse{Allow: true})
	az := f.authorizer(t, 0)

	_, err := az.Authorize(context.Background(), Request{
		Subject:  Subject{ID: "u1", CustomerID: "cust-a"},
		Action:   ActionCreate,
		Resource: Resource{Type: ResourceClient}, // no ID/Owner
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if f.lastCheck.Instance != nil {
		t.Fatalf("instance = %+v, want nil for collection action", f.lastCheck.Instance)
	}
}

func TestSolutrixScopeMapping(t *testing.T) {
	cases := []struct {
		vis  visibility
		want Scope
	}{
		{visibility{Kind: "all"}, Scope{All: true}},
		{visibility{Kind: "customerIds", CustomerIDs: []string{"a", "b"}}, Scope{CustomerIDs: []string{"a", "b"}}},
		{visibility{Kind: "none"}, Scope{CustomerIDs: nil}},
	}
	for _, tc := range cases {
		f := newFakeSolutrix(t, checkResponse{Visibility: tc.vis})
		az := f.authorizer(t, 0)
		got, err := az.Scope(context.Background(), Subject{ID: "u1", CustomerID: "cust-a"}, ActionRead, ResourceClient)
		if err != nil {
			t.Fatalf("Scope: %v", err)
		}
		if got.All != tc.want.All || len(got.CustomerIDs) != len(tc.want.CustomerIDs) {
			t.Fatalf("kind %q: got %+v, want %+v", tc.vis.Kind, got, tc.want)
		}
	}
}

func TestSolutrixCachesToken(t *testing.T) {
	f := newFakeSolutrix(t, checkResponse{Allow: true})
	az := f.authorizer(t, 0) // decision cache off; token cache still on

	for i := 0; i < 3; i++ {
		if _, err := az.Authorize(context.Background(), Request{
			Subject:  Subject{ID: "u1"},
			Action:   ActionRead,
			Resource: Resource{Type: ResourceClient, ID: "c1", Owner: "x"},
		}); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
	}
	if hits := atomic.LoadInt32(&f.tokenHits); hits != 1 {
		t.Fatalf("token endpoint hit %d times, want 1 (cached)", hits)
	}
}

func TestSolutrixDecisionCache(t *testing.T) {
	f := newFakeSolutrix(t, checkResponse{Allow: true})
	az := f.authorizer(t, time.Minute)

	req := Request{Subject: Subject{ID: "u1"}, Action: ActionRead, Resource: Resource{Type: ResourceClient, ID: "c1", Owner: "x"}}
	if _, err := az.Authorize(context.Background(), req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	// Flip the server's answer; cache should still return the first decision.
	f.checkResult = checkResponse{Allow: false}
	dec, err := az.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("Allow = false, want cached true")
	}
}

func TestSolutrixNon200IsError(t *testing.T) {
	f := &fakeSolutrix{}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "t", ExpiresIn: 300})
	})
	mux.HandleFunc("/authz/check", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	az, _ := NewSolutrixAuthorizer(SolutrixConfig{
		BaseURL: f.server.URL, TokenURL: f.server.URL + "/oauth/token",
		ClientID: "c", ClientSecret: "s",
	})
	if _, err := az.Authorize(context.Background(), Request{Subject: Subject{ID: "u1"}, Action: ActionRead, Resource: Resource{Type: ResourceClient}}); err == nil {
		t.Fatalf("expected error on 500 response")
	}
}
