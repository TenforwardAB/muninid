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
 * This file :: internal/authz/claims_test.go is part of the MuninID project.
 */

package authz

import (
	"context"
	"reflect"
	"testing"
)

func TestClaimsAuthorize(t *testing.T) {
	az := NewClaimsAuthorizer(nil)
	ctx := context.Background()

	admin := Subject{ID: "u1", Roles: []string{"admin"}}
	tenant := Subject{ID: "u2", CustomerID: "cust-a"}
	anon := Subject{ID: "u3"}

	cases := []struct {
		name string
		req  Request
		want bool
	}{
		{"admin any instance", Request{admin, ActionDelete, Resource{ResourceClient, "c1", "cust-x"}}, true},
		{"tenant owns instance", Request{tenant, ActionUpdate, Resource{ResourceClient, "c1", "cust-a"}}, true},
		{"tenant other instance", Request{tenant, ActionUpdate, Resource{ResourceClient, "c1", "cust-b"}}, false},
		{"tenant collection", Request{tenant, ActionCreate, Resource{Type: ResourceClient}}, true},
		{"no customer collection", Request{anon, ActionCreate, Resource{Type: ResourceClient}}, false},
		{"no customer instance", Request{anon, ActionRead, Resource{ResourceClient, "c1", "cust-a"}}, false},
		{"tenant create for own", Request{tenant, ActionCreate, Resource{Type: ResourceClient, Owner: "cust-a"}}, true},
		{"tenant create for other", Request{tenant, ActionCreate, Resource{Type: ResourceClient, Owner: "cust-b"}}, false},
		{"admin create for other", Request{admin, ActionCreate, Resource{Type: ResourceClient, Owner: "cust-x"}}, true},
		{"tenant instance null owner", Request{tenant, ActionRead, Resource{Type: ResourceClient, ID: "c1"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := az.Authorize(ctx, tc.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Allow != tc.want {
				t.Fatalf("Allow = %v (reason %q), want %v", d.Allow, d.Reason, tc.want)
			}
		})
	}
}

func TestClaimsScope(t *testing.T) {
	az := NewClaimsAuthorizer([]string{"superadmin"})
	ctx := context.Background()

	got, _ := az.Scope(ctx, Subject{ID: "u1", Roles: []string{"superadmin"}}, ActionRead, ResourceClient)
	if !got.All {
		t.Fatalf("admin scope = %+v, want All", got)
	}

	got, _ = az.Scope(ctx, Subject{ID: "u2", CustomerID: "cust-a"}, ActionRead, ResourceClient)
	if got.All || !reflect.DeepEqual(got.CustomerIDs, []string{"cust-a"}) {
		t.Fatalf("tenant scope = %+v, want CustomerIDs=[cust-a]", got)
	}

	got, _ = az.Scope(ctx, Subject{ID: "u3"}, ActionRead, ResourceClient)
	if got.All || len(got.CustomerIDs) != 0 {
		t.Fatalf("anon scope = %+v, want nothing visible", got)
	}
}

func TestSubjectFromClaims(t *testing.T) {
	sub := SubjectFromClaims(map[string]any{
		"sub":         "user-1",
		"customer_id": "cust-a",
		"roles":       []any{"admin", "", "captain"},
	})
	if sub.ID != "user-1" || sub.CustomerID != "cust-a" {
		t.Fatalf("unexpected subject: %+v", sub)
	}
	if !reflect.DeepEqual(sub.Roles, []string{"admin", "captain"}) {
		t.Fatalf("roles = %v", sub.Roles)
	}
}
