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
 * This file :: internal/authn/ports.go is part of the MuninID project.
 */

// Package authn defines the backend-neutral ports the IdP core depends on for
// credential operations. WildDuck is one implementation (internal/backend/
// wildduck); a DB or LDAP backend can implement the same interfaces later
// without touching core. Keep this package free of any concrete backend types
// so nothing leaks across the boundary.
package authn

import "context"

// Account is the backend-neutral view of an identity. Deliberately carries no
// raw backend payload (e.g. WildDuck metaData/internalData maps) — anything the
// core needs must be surfaced through a typed field or a port method.
type Account struct {
	ID        string
	Email     string
	Username  string
	Name      string
	Activated bool
	Suspended bool
	Disabled  bool
}

// Usable reports whether the account may authenticate / receive a reset.
func (a Account) Usable() bool {
	return a.Activated && !a.Suspended && !a.Disabled
}

// Destination is a recovery channel for an account. Exactly one of Address or
// Hash is meaningful: Address is plaintext and safe to send to; Hash is the
// sha256 (lower-hex) of the address and can only be verified by matching a
// user-supplied value (used for signup contact emails, which are stored hashed).
type Destination struct {
	Kind    string // "email" (later: "phone")
	Address string
	Hash    string
}

// IdentityBackend is the port the IdP core needs from a credential backend for
// the self-service password-reset flow. It intentionally stays minimal: the
// existing forced-password-change path still talks to WildDuck directly and
// will migrate its Authenticate/GetAccount calls behind this port later.
type IdentityBackend interface {
	// FindByLogin resolves a login (email address) to an account. The bool is
	// false when no such account exists; err is reserved for backend failures.
	FindByLogin(ctx context.Context, login string) (Account, bool, error)

	// RecoveryDestinations returns the recovery channels known for an account.
	RecoveryDestinations(ctx context.Context, acc Account) ([]Destination, error)

	// SetPassword replaces the account's password.
	SetPassword(ctx context.Context, id, newPassword string) error
}

// Mailer sends transactional mail. Kept separate from IdentityBackend so the
// transport (WildDuck submission today, a plain SMTP relay later) is swappable
// on its own.
type Mailer interface {
	SendPasswordReset(ctx context.Context, to, displayName, link string) error
}
