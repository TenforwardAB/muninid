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
 * This file :: internal/backend/wildduck/adapter.go is part of the MuninID project.
 */

// Package wildduck adapts the WildDuck HTTP API to the authn ports. All
// WildDuck-specific shapes (the metaData/internalData maps, field names) are
// confined to this package so the IdP core stays backend-neutral.
package wildduck

import (
	"context"
	"errors"
	"strings"

	wd "github.com/tenforwardab/wildduck-gosdk"

	"github.com/tenforwardab/muninid/internal/authn"
)

// Backend implements authn.IdentityBackend on top of the WildDuck SDK.
type Backend struct {
	c *wd.Client
}

func NewBackend(c *wd.Client) *Backend { return &Backend{c: c} }

// FindByLogin resolves an address to an account. A missing user is reported as
// (zero, false, nil) rather than an error so callers can respond generically.
func (b *Backend) FindByLogin(ctx context.Context, login string) (authn.Account, bool, error) {
	res, err := b.c.Users.Resolve(ctx, login, nil)
	if err != nil {
		// Resolve returns an HTTP error for unknown addresses; treat as not found.
		return authn.Account{}, false, nil
	}
	id := str(res["id"])
	if id == "" {
		return authn.Account{}, false, nil
	}
	user, err := b.c.Users.Get(ctx, id, nil)
	if err != nil || user["success"] != true {
		return authn.Account{}, false, nil
	}
	return toAccount(user), true, nil
}

// RecoveryDestinations derives the reset channels from the WildDuck user. Two
// sources are recognised:
//   - internalData.contact_email_hash — the sha256 of the signup contact email
//     (one-way; can only be verified by matching, then mailed to what the user
//     typed).
//   - metaData.profile.recoveryEmail — a plaintext recovery address the user set
//     in their profile.
func (b *Backend) RecoveryDestinations(ctx context.Context, acc authn.Account) ([]authn.Destination, error) {
	user, err := b.c.Users.Get(ctx, acc.ID, nil)
	if err != nil || user["success"] != true {
		return nil, errors.New("wildduck user not found")
	}
	var dests []authn.Destination
	if internal := mapv(user["internalData"]); internal != nil {
		if h := strings.ToLower(strings.TrimSpace(str(internal["contact_email_hash"]))); h != "" {
			dests = append(dests, authn.Destination{Kind: "email", Hash: h})
		}
	}
	if meta := mapv(user["metaData"]); meta != nil {
		if profile := mapv(meta["profile"]); profile != nil {
			if e := strings.ToLower(strings.TrimSpace(str(profile["recoveryEmail"]))); e != "" {
				dests = append(dests, authn.Destination{Kind: "email", Address: e})
			}
		}
	}
	return dests, nil
}

// SetPassword writes a new permanent password via PUT /users/:id.
func (b *Backend) SetPassword(ctx context.Context, id, newPassword string) error {
	res, err := b.c.Users.Update(ctx, id, wd.M{"password": newPassword})
	if err != nil {
		return err
	}
	if res["success"] != true {
		return errors.New("wildduck password update failed")
	}
	return nil
}

func toAccount(u wd.M) authn.Account {
	return authn.Account{
		ID:        str(u["id"]),
		Email:     str(u["address"]),
		Username:  str(u["username"]),
		Name:      str(u["name"]),
		Activated: boolv(u["activated"]),
		Suspended: boolv(u["suspended"]),
		Disabled:  boolv(u["disabled"]),
	}
}

func str(v any) string { s, _ := v.(string); return s }
func boolv(v any) bool { b, _ := v.(bool); return b }
func mapv(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
