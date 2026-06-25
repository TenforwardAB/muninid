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
 * Created on 4/23/25 :: 1:22PM BY joyider <andre(-at-)sess.se>
 *
 * This file :: internal/handlers/context.go is part of the MuninID project.
 */

package handlers

import (
	"context"

	"github.com/tenforwardab/muninid/internal/authz"
)

type adminClaimsKey struct{}

func WithAdminClaims(ctx context.Context, claims map[string]any) context.Context {
	return context.WithValue(ctx, adminClaimsKey{}, claims)
}

func AdminClaims(ctx context.Context) map[string]any {
	claims, _ := ctx.Value(adminClaimsKey{}).(map[string]any)
	return claims
}

type subjectKey struct{}

// WithSubject stores the authenticated authz.Subject for self-service routes.
func WithSubject(ctx context.Context, sub authz.Subject) context.Context {
	return context.WithValue(ctx, subjectKey{}, sub)
}

// SubjectFromContext returns the authenticated subject and whether one was set.
func SubjectFromContext(ctx context.Context) (authz.Subject, bool) {
	sub, ok := ctx.Value(subjectKey{}).(authz.Subject)
	return sub, ok
}
