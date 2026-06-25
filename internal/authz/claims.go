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
 * This file :: internal/authz/claims.go is part of the MuninID project.
 */

package authz

import "context"

// DefaultAdminRoles are the roles that grant unrestricted (all-tenant) access in
// the claims backend. Mirrors the hardcoded set in app.requireBearerAdmin.
var DefaultAdminRoles = []string{"idp_admin", "admin", "superadmin"}

// claimsAuthorizer is the in-process PDP: decisions come purely from the token's
// roles and customer_id, with no external dependency. It encodes muninID's
// existing rule set:
//
//   - an admin role => allowed on everything, all tenants;
//   - otherwise => allowed only on resources owned by the subject's customer_id
//     (and only if the subject has a customer_id at all).
type claimsAuthorizer struct {
	adminRoles []string
}

// NewClaimsAuthorizer returns the claims backend. Passing nil adminRoles uses
// DefaultAdminRoles.
func NewClaimsAuthorizer(adminRoles []string) Authorizer {
	if len(adminRoles) == 0 {
		adminRoles = DefaultAdminRoles
	}
	return &claimsAuthorizer{adminRoles: adminRoles}
}

func (a *claimsAuthorizer) Authorize(_ context.Context, req Request) (Decision, error) {
	if req.Subject.hasAnyRole(a.adminRoles) {
		return Decision{Allow: true, Reason: "admin_role"}, nil
	}
	// Non-admins must have a tenant identity.
	if req.Subject.CustomerID == "" {
		return Decision{Allow: false, Reason: "no_customer_id"}, nil
	}
	// Collection actions (no specific instance, ID == ""): a tenant user may
	// list/create within their own tenant. A targeted owner (e.g. creating a
	// client for another customer) must still be their own tenant.
	if req.Resource.ID == "" {
		if req.Resource.Owner == "" || req.Resource.Owner == req.Subject.CustomerID {
			return Decision{Allow: true, Reason: "own_tenant"}, nil
		}
		return Decision{Allow: false, Reason: "not_owner"}, nil
	}
	// Instance actions require an exact ownership match. A null-owner (system)
	// client is never "owned" by a tenant user.
	if req.Resource.Owner != "" && req.Resource.Owner == req.Subject.CustomerID {
		return Decision{Allow: true, Reason: "owner"}, nil
	}
	return Decision{Allow: false, Reason: "not_owner"}, nil
}

func (a *claimsAuthorizer) Scope(_ context.Context, sub Subject, _, _ string) (Scope, error) {
	if sub.hasAnyRole(a.adminRoles) {
		return Scope{All: true}, nil
	}
	if sub.CustomerID == "" {
		return Scope{CustomerIDs: nil}, nil // nothing visible
	}
	return Scope{CustomerIDs: []string{sub.CustomerID}}, nil
}
