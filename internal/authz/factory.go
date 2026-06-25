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
 * This file :: internal/authz/factory.go is part of the MuninID project.
 */

package authz

import (
	"fmt"
	"strings"
)

// Backend selects the authorization decision point.
const (
	BackendClaims   = "claims"
	BackendSolutrix = "solutrix"
)

// Config selects and configures an Authorizer. Backend defaults to "claims".
type Config struct {
	Backend    string         // "claims" (default) | "solutrix"
	AdminRoles []string       // claims backend: roles granted all-tenant access
	Solutrix   SolutrixConfig // solutrix backend settings
}

// New builds the Authorizer described by cfg.
func New(cfg Config) (Authorizer, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Backend)) {
	case "", BackendClaims:
		return NewClaimsAuthorizer(cfg.AdminRoles), nil
	case BackendSolutrix:
		return NewSolutrixAuthorizer(cfg.Solutrix)
	default:
		return nil, fmt.Errorf("authz: unknown backend %q", cfg.Backend)
	}
}
