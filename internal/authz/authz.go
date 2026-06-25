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
 * This file :: internal/authz/authz.go is part of the MuninID project.
 */

// Package authz is muninID's policy enforcement layer. It turns "who is calling"
// (a verified token's claims) plus "what are they trying to do" (an action on a
// resource) into an allow/deny Decision, delegating the actual decision to a
// pluggable Authorizer backend.
//
// Two backends ship today:
//   - claims:   in-process role + customer_id ownership (no external dependency)
//   - solutrix: HTTP call to solutrix-api's ABAC engine (see docs/authz-contract.md)
package authz

import (
	"context"
	"strings"
)

// Resource types and actions. Kept as constants so callers don't drift on
// spelling; the strings match the solutrix `idp:` vocabulary.
const (
	ResourceClient = "idp:clients"
	ResourceSAMLSP = "idp:saml_sps"
	ResourcePolicy = "idp:policies"

	ActionCreate       = "create"
	ActionRead         = "read"
	ActionUpdate       = "update"
	ActionDelete       = "delete"
	ActionRotateSecret = "rotate_secret"
)

// Subject is the authenticated caller, derived from a verified access token.
type Subject struct {
	ID         string         // token "sub"
	CustomerID string         // customer_id claim ("" when absent)
	Roles      []string       // roles claim
	Claims     map[string]any // full claim bag, for attribute checks
}

// Resource is the thing being acted on. ID == "" means the collection
// (list/create); Owner is the resource's customer_id when known.
type Resource struct {
	Type  string
	ID    string
	Owner string
}

// Request is a single authorization question.
type Request struct {
	Subject  Subject
	Action   string
	Resource Resource
}

// Decision is the answer. Reason is optional, for logging/diagnostics.
type Decision struct {
	Allow  bool
	Reason string
}

// Scope is the tenant filter for list endpoints. All == true means no
// restriction; otherwise CustomerIDs holds the allowed owners (possibly empty,
// meaning "nothing visible").
type Scope struct {
	All         bool
	CustomerIDs []string
}

// Authorizer is the policy decision point. Implementations must be safe for
// concurrent use.
type Authorizer interface {
	// Authorize answers a single allow/deny question.
	Authorize(ctx context.Context, req Request) (Decision, error)
	// Scope returns the tenant filter to apply when listing resources of a
	// type for a subject+action.
	Scope(ctx context.Context, sub Subject, action, resourceType string) (Scope, error)
}

// SubjectFromClaims builds a Subject from a verified token's claim map.
func SubjectFromClaims(claims map[string]any) Subject {
	sub := Subject{Claims: claims}
	if claims == nil {
		return sub
	}
	if v, ok := claims["sub"].(string); ok {
		sub.ID = v
	}
	if v, ok := claims["customer_id"].(string); ok {
		sub.CustomerID = v
	}
	sub.Roles = stringSlice(claims["roles"])
	return sub
}

// hasAnyRole reports whether the subject holds at least one of want.
func (s Subject) hasAnyRole(want []string) bool {
	for _, r := range s.Roles {
		for _, w := range want {
			if strings.EqualFold(r, w) {
				return true
			}
		}
	}
	return false
}

// stringSlice coerces a claim value (which decodes as []any from JSON) into a
// []string, tolerating a single string too.
func stringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
