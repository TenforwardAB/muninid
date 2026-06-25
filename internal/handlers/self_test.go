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
 * This file :: internal/handlers/self_test.go is part of the MuninID project.
 */

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/tenforwardab/muninid/internal/authz"
	"github.com/tenforwardab/muninid/internal/store"
)

// ---- fakes ----

type fakeAuthorizer struct {
	allow    bool
	scope    authz.Scope
	err      error
	scopeErr error

	gotReqs    []authz.Request
	scopeCalls int
}

func (f *fakeAuthorizer) Authorize(_ context.Context, req authz.Request) (authz.Decision, error) {
	f.gotReqs = append(f.gotReqs, req)
	if f.err != nil {
		return authz.Decision{}, f.err
	}
	return authz.Decision{Allow: f.allow}, nil
}

func (f *fakeAuthorizer) Scope(_ context.Context, _ authz.Subject, _, _ string) (authz.Scope, error) {
	f.scopeCalls++
	if f.scopeErr != nil {
		return authz.Scope{}, f.scopeErr
	}
	return f.scope, nil
}

// fakeStore implements clientStore; only client methods are exercised here.
type fakeStore struct {
	clients   map[string]store.Client
	listByCID map[string][]store.Client
	listAll   []store.Client

	created *store.Client
	updated *store.Client
	deleted string
	getErr  error
}

func newFakeStore() *fakeStore {
	return &fakeStore{clients: map[string]store.Client{}, listByCID: map[string][]store.Client{}}
}

func (s *fakeStore) GetClientByID(_ context.Context, id string) (store.Client, error) {
	if s.getErr != nil {
		return store.Client{}, s.getErr
	}
	c, ok := s.clients[id]
	if !ok {
		return store.Client{}, store.ErrNotFound
	}
	return c, nil
}

func (s *fakeStore) ListClients(_ context.Context, customerID *string) ([]store.Client, error) {
	if customerID == nil {
		return s.listAll, nil
	}
	return s.listByCID[*customerID], nil
}

func (s *fakeStore) CreateClient(_ context.Context, c store.Client) (store.Client, error) {
	s.created = &c
	return c, nil
}

func (s *fakeStore) UpdateClient(_ context.Context, c store.Client) error {
	s.updated = &c
	return nil
}

func (s *fakeStore) DeleteClient(_ context.Context, id string) error {
	s.deleted = id
	return nil
}

// Unused-by-self-tests methods, present to satisfy clientStore.
func (s *fakeStore) ListServiceProviders(context.Context) ([]store.SAMLServiceProvider, error) {
	return nil, nil
}
func (s *fakeStore) GetServiceProvider(context.Context, string) (store.SAMLServiceProvider, error) {
	return store.SAMLServiceProvider{}, nil
}
func (s *fakeStore) CreateServiceProvider(context.Context, store.SAMLServiceProvider) (store.SAMLServiceProvider, error) {
	return store.SAMLServiceProvider{}, nil
}
func (s *fakeStore) UpdateServiceProvider(context.Context, store.SAMLServiceProvider) error {
	return nil
}
func (s *fakeStore) DeleteServiceProvider(context.Context, string) error          { return nil }
func (s *fakeStore) ListPolicies(context.Context) ([]store.IdentityPolicy, error) { return nil, nil }
func (s *fakeStore) GetPolicy(context.Context, string) (store.IdentityPolicy, error) {
	return store.IdentityPolicy{}, nil
}
func (s *fakeStore) CreatePolicy(context.Context, store.IdentityPolicy) (store.IdentityPolicy, error) {
	return store.IdentityPolicy{}, nil
}
func (s *fakeStore) UpdatePolicy(context.Context, store.IdentityPolicy) error { return nil }
func (s *fakeStore) DeletePolicy(context.Context, string) error               { return nil }

type fakeEncryptor struct{}

func (fakeEncryptor) EncryptSecret(value string) (string, error) { return "enc:" + value, nil }

// ---- helpers ----

func ptr(s string) *string { return &s }

func newSelfRouter(h *Admin, sub *authz.Subject) http.Handler {
	r := chi.NewRouter()
	if sub != nil {
		s := *sub
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(WithSubject(r.Context(), s)))
			})
		})
	}
	h.SelfClientRoutes(r)
	return r
}

func do(t *testing.T, router http.Handler, method, target string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body == "" {
		rdr = bytes.NewReader(nil)
	} else {
		rdr = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, target, rdr)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// ---- tests ----

func TestSelfRoutesRequireSubject(t *testing.T) {
	h := NewAdmin(fakeEncryptor{}, newFakeStore(), &fakeAuthorizer{allow: true})
	router := newSelfRouter(h, nil) // no subject in context

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/clients"},
		{http.MethodPost, "/clients"},
		{http.MethodGet, "/clients/x"},
	} {
		rec := do(t, router, tc.method, tc.path, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: code = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

func TestSelfGetClient(t *testing.T) {
	sub := authz.Subject{ID: "u1", CustomerID: "cust-a"}
	st := newFakeStore()
	st.clients["c1"] = store.Client{ID: "c1", ClientID: "cid1", CustomerID: ptr("cust-a")}

	t.Run("denied", func(t *testing.T) {
		az := &fakeAuthorizer{allow: false}
		h := NewAdmin(fakeEncryptor{}, st, az)
		rec := do(t, newSelfRouter(h, &sub), http.MethodGet, "/clients/c1", "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
		if len(az.gotReqs) != 1 || az.gotReqs[0].Resource.Owner != "cust-a" || az.gotReqs[0].Action != authz.ActionRead {
			t.Fatalf("authorizer received wrong request: %+v", az.gotReqs)
		}
	})

	t.Run("allowed", func(t *testing.T) {
		h := NewAdmin(fakeEncryptor{}, st, &fakeAuthorizer{allow: true})
		rec := do(t, newSelfRouter(h, &sub), http.MethodGet, "/clients/c1", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", rec.Code)
		}
	})

	t.Run("not found", func(t *testing.T) {
		h := NewAdmin(fakeEncryptor{}, st, &fakeAuthorizer{allow: true})
		rec := do(t, newSelfRouter(h, &sub), http.MethodGet, "/clients/missing", "")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("code = %d, want 404", rec.Code)
		}
	})
}

func TestSelfDeleteClient(t *testing.T) {
	sub := authz.Subject{ID: "u1", CustomerID: "cust-a"}
	st := newFakeStore()
	st.clients["c1"] = store.Client{ID: "c1", CustomerID: ptr("cust-a")}

	az := &fakeAuthorizer{allow: true}
	h := NewAdmin(fakeEncryptor{}, st, az)
	rec := do(t, newSelfRouter(h, &sub), http.MethodDelete, "/clients/c1", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d, want 204", rec.Code)
	}
	if st.deleted != "c1" {
		t.Fatalf("deleted = %q, want c1", st.deleted)
	}
	if az.gotReqs[0].Action != authz.ActionDelete {
		t.Fatalf("action = %q, want delete", az.gotReqs[0].Action)
	}
}

func TestSelfCreateClient(t *testing.T) {
	sub := authz.Subject{ID: "u1", CustomerID: "cust-a"}
	body := `{"name":"app","grant_types":["client_credentials"]}`

	t.Run("forbidden before store", func(t *testing.T) {
		st := newFakeStore()
		h := NewAdmin(fakeEncryptor{}, st, &fakeAuthorizer{allow: false})
		rec := do(t, newSelfRouter(h, &sub), http.MethodPost, "/clients", body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
		if st.created != nil {
			t.Fatalf("client was created despite forbidden")
		}
	})

	t.Run("allowed sets owner from subject", func(t *testing.T) {
		st := newFakeStore()
		h := NewAdmin(fakeEncryptor{}, st, &fakeAuthorizer{allow: true})
		rec := do(t, newSelfRouter(h, &sub), http.MethodPost, "/clients", body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("code = %d, want 201", rec.Code)
		}
		if st.created == nil || st.created.CustomerID == nil || *st.created.CustomerID != "cust-a" {
			t.Fatalf("created client customer = %+v, want cust-a", st.created)
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["client_secret"] == nil {
			t.Fatalf("response missing client_secret")
		}
	})

	t.Run("authorizer error -> 500", func(t *testing.T) {
		st := newFakeStore()
		h := NewAdmin(fakeEncryptor{}, st, &fakeAuthorizer{err: errors.New("pdp down")})
		rec := do(t, newSelfRouter(h, &sub), http.MethodPost, "/clients", body)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("code = %d, want 500", rec.Code)
		}
	})
}

func TestSelfListClients(t *testing.T) {
	sub := authz.Subject{ID: "u1", CustomerID: "cust-a"}

	t.Run("scope none returns empty", func(t *testing.T) {
		st := newFakeStore()
		st.listAll = []store.Client{{ID: "x"}} // must not be returned
		h := NewAdmin(fakeEncryptor{}, st, &fakeAuthorizer{scope: authz.Scope{CustomerIDs: nil}})
		rec := do(t, newSelfRouter(h, &sub), http.MethodGet, "/clients", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", rec.Code)
		}
		var out []store.Client
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 0 {
			t.Fatalf("len = %d, want 0", len(out))
		}
	})

	t.Run("scope customerIds filters", func(t *testing.T) {
		st := newFakeStore()
		st.listByCID["cust-a"] = []store.Client{{ID: "c1"}, {ID: "c2"}}
		st.listAll = []store.Client{{ID: "other"}}
		h := NewAdmin(fakeEncryptor{}, st, &fakeAuthorizer{scope: authz.Scope{CustomerIDs: []string{"cust-a"}}})
		rec := do(t, newSelfRouter(h, &sub), http.MethodGet, "/clients", "")
		var out []store.Client
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 2 {
			t.Fatalf("len = %d, want 2", len(out))
		}
	})

	t.Run("scope all returns all", func(t *testing.T) {
		st := newFakeStore()
		st.listAll = []store.Client{{ID: "c1"}, {ID: "c2"}, {ID: "c3"}}
		h := NewAdmin(fakeEncryptor{}, st, &fakeAuthorizer{scope: authz.Scope{All: true}})
		rec := do(t, newSelfRouter(h, &sub), http.MethodGet, "/clients", "")
		var out []store.Client
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 3 {
			t.Fatalf("len = %d, want 3", len(out))
		}
	})

	t.Run("scope error -> 500", func(t *testing.T) {
		st := newFakeStore()
		h := NewAdmin(fakeEncryptor{}, st, &fakeAuthorizer{scopeErr: errors.New("pdp down")})
		rec := do(t, newSelfRouter(h, &sub), http.MethodGet, "/clients", "")
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("code = %d, want 500", rec.Code)
		}
	})
}
