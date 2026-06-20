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
 * This file :: internal/handlers/openapi.go is part of the MuninID project.
 */

package handlers

func OpenAPI(issuer string) map[string]any {
	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":   "MuninID",
			"version": "0.1.0",
		},
		"servers": []map[string]string{{"url": issuer}},
		"paths": map[string]any{
			"/oauth/authorize":           map[string]any{"get": map[string]any{"summary": "OIDC authorization endpoint"}},
			"/oauth/token":               map[string]any{"post": map[string]any{"summary": "OAuth token endpoint including authorization_code, refresh_token, client_credentials, and token exchange"}},
			"/userinfo":                  map[string]any{"get": map[string]any{"summary": "OIDC userinfo endpoint"}},
			"/api/global/admin/clients":  adminCRUDPath("OIDC/OAuth clients"),
			"/api/global/admin/policies": adminCRUDPath("identity policy records"),
			"/api/global/admin/sps":      adminCRUDPath("SAML service provider records"),
		},
	}
}

func adminCRUDPath(resource string) map[string]any {
	return map[string]any{
		"get":  map[string]any{"summary": "List " + resource},
		"post": map[string]any{"summary": "Create " + resource},
	}
}
