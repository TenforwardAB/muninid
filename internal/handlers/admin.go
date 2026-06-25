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
 * This file :: internal/handlers/admin.go is part of the MuninID project.
 */

package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/tenforwardab/muninid/internal/authz"
	"github.com/tenforwardab/muninid/internal/store"
)

// clientStore is the persistence surface the Admin handlers depend on. It is
// satisfied by *store.Store; defining it as an interface keeps handlers testable
// without a database.
type clientStore interface {
	ListClients(ctx context.Context, customerID *string) ([]store.Client, error)
	GetClientByID(ctx context.Context, id string) (store.Client, error)
	CreateClient(ctx context.Context, c store.Client) (store.Client, error)
	UpdateClient(ctx context.Context, c store.Client) error
	DeleteClient(ctx context.Context, id string) error
	ListServiceProviders(ctx context.Context) ([]store.SAMLServiceProvider, error)
	GetServiceProvider(ctx context.Context, id string) (store.SAMLServiceProvider, error)
	CreateServiceProvider(ctx context.Context, provider store.SAMLServiceProvider) (store.SAMLServiceProvider, error)
	UpdateServiceProvider(ctx context.Context, provider store.SAMLServiceProvider) error
	DeleteServiceProvider(ctx context.Context, id string) error
	ListPolicies(ctx context.Context) ([]store.IdentityPolicy, error)
	GetPolicy(ctx context.Context, id string) (store.IdentityPolicy, error)
	CreatePolicy(ctx context.Context, policy store.IdentityPolicy) (store.IdentityPolicy, error)
	UpdatePolicy(ctx context.Context, policy store.IdentityPolicy) error
	DeletePolicy(ctx context.Context, id string) error
}

// secretEncryptor encrypts client secrets. Satisfied by *idp.Provider.
type secretEncryptor interface {
	EncryptSecret(value string) (string, error)
}

type Admin struct {
	idp   secretEncryptor
	store clientStore
	authz authz.Authorizer
}

func NewAdmin(provider secretEncryptor, st clientStore, authorizer authz.Authorizer) *Admin {
	return &Admin{idp: provider, store: st, authz: authorizer}
}

func (h *Admin) GlobalRoutes(r chi.Router) {
	r.Get("/clients", h.listClients(nil))
	r.Post("/clients", h.createClient(nil))
	r.Get("/clients/{id}", h.getClient(nil))
	r.Put("/clients/{id}", h.updateClient(nil))
	r.Delete("/clients/{id}", h.deleteClient(nil))
	r.Post("/clients/{id}/rotate-secret", h.rotateSecret(nil))
	r.Post("/keys/rotate", h.rotateKey)
	r.Get("/sps", h.listServiceProviders)
	r.Post("/sps", h.createServiceProvider)
	r.Get("/sps/{id}", h.getServiceProvider)
	r.Put("/sps/{id}", h.updateServiceProvider)
	r.Delete("/sps/{id}", h.deleteServiceProvider)
	r.Get("/policies", h.listPolicies)
	r.Post("/policies", h.createPolicy)
	r.Get("/policies/{id}", h.getPolicy)
	r.Put("/policies/{id}", h.updatePolicy)
	r.Delete("/policies/{id}", h.deletePolicy)
}

func (h *Admin) TenantRoutes(r chi.Router) {
	r.Get("/clients", h.listClients(customerFromClaims))
	r.Post("/clients", h.createClient(customerFromClaims))
	r.Get("/clients/{id}", h.getClient(customerFromClaims))
	r.Put("/clients/{id}", h.updateClient(customerFromClaims))
	r.Post("/clients/{id}/rotate-secret", h.rotateSecret(customerFromClaims))
	r.Delete("/clients/{id}", h.deleteClient(customerFromClaims))
}

func (h *Admin) listClients(customer func(*http.Request) *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clients, err := h.store.ListClients(r.Context(), customerValue(customer, r))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "client_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, clients)
	}
}

func (h *Admin) getClient(customer func(*http.Request) *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := h.store.GetClientByID(r.Context(), chi.URLParam(r, "id"))
		if errors.Is(err, store.ErrNotFound) || !owned(client, customerValue(customer, r)) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
			return
		}
		writeJSON(w, http.StatusOK, client)
	}
}

func (h *Admin) createClient(customer func(*http.Request) *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req clientRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
			return
		}
		clientSecret := randomHex(32)
		encrypted, err := h.idp.EncryptSecret(clientSecret)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "secret_encrypt_failed"})
			return
		}
		client := store.Client{
			ID:                     uuid.NewString(),
			ClientID:               uuid.NewString(),
			ClientSecret:           encrypted,
			Name:                   strings.TrimSpace(req.Name),
			RedirectURIs:           normalize(req.RedirectURIs, req.RedirectUris),
			GrantTypes:             normalize(req.GrantTypes, req.GrantTypesCamel),
			Scopes:                 normalize(req.Scopes, nil),
			PostLogoutRedirectURIs: normalize(req.PostLogoutRedirectURIs, req.PostLogoutRedirectUris),
			CustomerID:             customerValue(customer, r),
		}
		if client.Name == "" || len(client.GrantTypes) == 0 || (!onlyClientCredentials(client.GrantTypes) && len(client.RedirectURIs) == 0) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_payload"})
			return
		}
		created, err := h.store.CreateClient(r.Context(), client)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "client_create_failed"})
			return
		}
		resp := clientResponse(created)
		resp["client_secret"] = clientSecret
		writeJSON(w, http.StatusCreated, resp)
	}
}

func (h *Admin) updateClient(customer func(*http.Request) *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := h.store.GetClientByID(r.Context(), chi.URLParam(r, "id"))
		if errors.Is(err, store.ErrNotFound) || !owned(client, customerValue(customer, r)) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
			return
		}
		var req clientRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
			return
		}
		if req.Name != "" {
			client.Name = strings.TrimSpace(req.Name)
		}
		if values := normalize(req.RedirectURIs, req.RedirectUris); values != nil {
			client.RedirectURIs = values
		}
		if values := normalize(req.GrantTypes, req.GrantTypesCamel); values != nil {
			client.GrantTypes = values
		}
		if values := normalize(req.Scopes, nil); values != nil {
			client.Scopes = values
		}
		if values := normalize(req.PostLogoutRedirectURIs, req.PostLogoutRedirectUris); values != nil {
			client.PostLogoutRedirectURIs = values
		}
		resp := clientResponse(client)
		if req.RotateSecret {
			plain := randomHex(32)
			client.ClientSecret, _ = h.idp.EncryptSecret(plain)
			resp["client_secret"] = plain
		}
		if err := h.store.UpdateClient(r.Context(), client); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "client_update_failed"})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func (h *Admin) rotateSecret(customer func(*http.Request) *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := h.store.GetClientByID(r.Context(), chi.URLParam(r, "id"))
		if errors.Is(err, store.ErrNotFound) || !owned(client, customerValue(customer, r)) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
			return
		}
		plain := randomHex(32)
		client.ClientSecret, _ = h.idp.EncryptSecret(plain)
		if err := h.store.UpdateClient(r.Context(), client); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "client_update_failed"})
			return
		}
		resp := clientResponse(client)
		resp["client_secret"] = plain
		writeJSON(w, http.StatusOK, resp)
	}
}

func (h *Admin) deleteClient(customer func(*http.Request) *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client, err := h.store.GetClientByID(r.Context(), chi.URLParam(r, "id"))
		if errors.Is(err, store.ErrNotFound) || !owned(client, customerValue(customer, r)) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
			return
		}
		if err := h.store.DeleteClient(r.Context(), client.ID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "client_delete_failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *Admin) rotateKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "restart_with_new_key_or_extend_rotate_endpoint"})
}

func (h *Admin) listServiceProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := h.store.ListServiceProviders(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "service_provider_list_failed"})
		return
	}
	writeJSON(w, http.StatusOK, providers)
}

func (h *Admin) getServiceProvider(w http.ResponseWriter, r *http.Request) {
	provider, err := h.store.GetServiceProvider(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "service_provider_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "service_provider_get_failed"})
		return
	}
	writeJSON(w, http.StatusOK, provider)
}

func (h *Admin) createServiceProvider(w http.ResponseWriter, r *http.Request) {
	var req serviceProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	provider := store.SAMLServiceProvider{
		ID:               uuid.NewString(),
		EntityID:         strings.TrimSpace(firstString(req.EntityID, req.EntityIDCamel)),
		MetadataXML:      optionalString(req.MetadataXML, req.MetadataXMLCamel),
		ACSEndpoints:     normalize(req.ACS, normalize(req.ACSEndpoints, req.ACSEndpointsCamel)),
		Binding:          strings.TrimSpace(req.Binding),
		AttributeMapping: firstMap(req.AttributeMapping, req.AttributeMappingSnake, req.AttributeMappingCamel),
	}
	if provider.EntityID == "" || len(provider.ACSEndpoints) == 0 || provider.Binding == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_service_provider_payload"})
		return
	}
	if provider.AttributeMapping == nil {
		provider.AttributeMapping = map[string]any{}
	}
	created, err := h.store.CreateServiceProvider(r.Context(), provider)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "service_provider_create_failed"})
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *Admin) updateServiceProvider(w http.ResponseWriter, r *http.Request) {
	provider, err := h.store.GetServiceProvider(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "service_provider_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "service_provider_get_failed"})
		return
	}
	var req serviceProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if value := firstString(req.EntityID, req.EntityIDCamel); value != "" {
		provider.EntityID = strings.TrimSpace(value)
	}
	if req.MetadataXML != nil || req.MetadataXMLCamel != nil {
		provider.MetadataXML = optionalString(req.MetadataXML, req.MetadataXMLCamel)
	}
	if values := normalize(req.ACS, normalize(req.ACSEndpoints, req.ACSEndpointsCamel)); values != nil {
		if len(values) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "acs_endpoints_required"})
			return
		}
		provider.ACSEndpoints = values
	}
	if req.Binding != "" {
		provider.Binding = strings.TrimSpace(req.Binding)
	}
	if mapping := firstMap(req.AttributeMapping, req.AttributeMappingSnake, req.AttributeMappingCamel); mapping != nil {
		provider.AttributeMapping = mapping
	}
	if err := h.store.UpdateServiceProvider(r.Context(), provider); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "service_provider_update_failed"})
		return
	}
	writeJSON(w, http.StatusOK, provider)
}

func (h *Admin) deleteServiceProvider(w http.ResponseWriter, r *http.Request) {
	if err := h.store.DeleteServiceProvider(r.Context(), chi.URLParam(r, "id")); errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "service_provider_not_found"})
		return
	} else if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "service_provider_delete_failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Admin) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.store.ListPolicies(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy_list_failed"})
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (h *Admin) getPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := h.store.GetPolicy(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy_get_failed"})
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *Admin) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req policyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	policy := store.IdentityPolicy{
		ID:         uuid.NewString(),
		Name:       strings.TrimSpace(req.Name),
		TargetType: strings.TrimSpace(firstString(req.TargetType, req.TargetTypeCamel)),
		TargetID:   optionalString(req.TargetID, req.TargetIDCamel),
		Policy:     req.Policy,
	}
	if policy.Name == "" || policy.TargetType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_policy_payload"})
		return
	}
	if policy.Policy == nil {
		policy.Policy = map[string]any{}
	}
	created, err := h.store.CreatePolicy(r.Context(), policy)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy_create_failed"})
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *Admin) updatePolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := h.store.GetPolicy(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy_get_failed"})
		return
	}
	var req policyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if req.Name != "" {
		policy.Name = strings.TrimSpace(req.Name)
	}
	if value := firstString(req.TargetType, req.TargetTypeCamel); value != "" {
		policy.TargetType = strings.TrimSpace(value)
	}
	if req.TargetID != nil || req.TargetIDCamel != nil {
		policy.TargetID = optionalString(req.TargetID, req.TargetIDCamel)
	}
	if req.Policy != nil {
		policy.Policy = req.Policy
	}
	if err := h.store.UpdatePolicy(r.Context(), policy); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy_update_failed"})
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *Admin) deletePolicy(w http.ResponseWriter, r *http.Request) {
	if err := h.store.DeletePolicy(r.Context(), chi.URLParam(r, "id")); errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy_not_found"})
		return
	} else if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy_delete_failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type clientRequest struct {
	Name                   string   `json:"name"`
	RedirectURIs           []string `json:"redirect_uris"`
	RedirectUris           []string `json:"redirectUris"`
	GrantTypes             []string `json:"grant_types"`
	GrantTypesCamel        []string `json:"grantTypes"`
	Scopes                 []string `json:"scopes"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	PostLogoutRedirectUris []string `json:"postLogoutRedirectUris"`
	RotateSecret           bool     `json:"rotate_secret"`
	CustomerID             *string  `json:"customer_id"`
	CustomerIDCamel        *string  `json:"customerId"`
}

type serviceProviderRequest struct {
	EntityID              *string        `json:"entity_id"`
	EntityIDCamel         *string        `json:"entityId"`
	MetadataXML           *string        `json:"metadata_xml"`
	MetadataXMLCamel      *string        `json:"metadataXml"`
	ACS                   []string       `json:"acs"`
	ACSEndpoints          []string       `json:"acs_endpoints"`
	ACSEndpointsCamel     []string       `json:"acsEndpoints"`
	Binding               string         `json:"binding"`
	AttributeMapping      map[string]any `json:"attr_mapping"`
	AttributeMappingSnake map[string]any `json:"attribute_mapping"`
	AttributeMappingCamel map[string]any `json:"attributeMapping"`
}

type policyRequest struct {
	Name            string         `json:"name"`
	TargetType      *string        `json:"target_type"`
	TargetTypeCamel *string        `json:"targetType"`
	TargetID        *string        `json:"target_id"`
	TargetIDCamel   *string        `json:"targetId"`
	Policy          map[string]any `json:"policy"`
}

func customerFromClaims(r *http.Request) *string {
	claims := AdminClaims(r.Context())
	if cid, ok := claims["customer_id"].(string); ok && cid != "" {
		return &cid
	}
	return nil
}

func customerValue(fn func(*http.Request) *string, r *http.Request) *string {
	if fn == nil {
		return nil
	}
	return fn(r)
}

func owned(client store.Client, customerID *string) bool {
	return customerID == nil || (client.CustomerID != nil && *client.CustomerID == *customerID)
}

func normalize(a, b []string) []string {
	if len(a) == 0 {
		a = b
	}
	if len(a) == 0 {
		return nil
	}
	out := make([]string, 0, len(a))
	for _, item := range a {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func firstString(values ...*string) string {
	for _, value := range values {
		if value != nil {
			return *value
		}
	}
	return ""
}

func optionalString(values ...*string) *string {
	for _, value := range values {
		if value == nil {
			continue
		}
		trimmed := strings.TrimSpace(*value)
		if trimmed == "" {
			return nil
		}
		return &trimmed
	}
	return nil
}

func firstMap(values ...map[string]any) map[string]any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func onlyClientCredentials(grants []string) bool {
	return len(grants) == 1 && grants[0] == "client_credentials"
}

func clientResponse(c store.Client) map[string]any {
	return map[string]any{
		"id":                        c.ID,
		"client_id":                 c.ClientID,
		"name":                      c.Name,
		"redirect_uris":             c.RedirectURIs,
		"grant_types":               c.GrantTypes,
		"scopes":                    c.Scopes,
		"post_logout_redirect_uris": c.PostLogoutRedirectURIs,
		"customer_id":               c.CustomerID,
		"created_by_subject":        c.CreatedBySubject,
		"created_by_email":          c.CreatedByEmail,
		"created_at":                c.CreatedAt,
		"updated_at":                c.UpdatedAt,
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func notImplemented(code string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": code})
	}
}
