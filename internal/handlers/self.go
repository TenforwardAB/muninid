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
 * This file :: internal/handlers/self.go is part of the MuninID project.
 */

package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/tenforwardab/muninid/internal/authz"
	"github.com/tenforwardab/muninid/internal/store"
)

// SelfClientRoutes mounts the self-service client API. Every decision is
// delegated to the configured Authorizer (claims or solutrix ABAC); the caller's
// identity must already be in context (see app.requireIdentity).
func (h *Admin) SelfClientRoutes(r chi.Router) {
	r.Get("/clients", h.selfListClients)
	r.Post("/clients", h.selfCreateClient)
	r.Get("/clients/{id}", h.selfGetClient)
	r.Put("/clients/{id}", h.selfUpdateClient)
	r.Delete("/clients/{id}", h.selfDeleteClient)
	r.Post("/clients/{id}/rotate-secret", h.selfRotateSecret)
}

// authorizeClient runs an instance-level decision for a loaded client.
func (h *Admin) authorizeClient(r *http.Request, sub authz.Subject, action string, client store.Client) (bool, error) {
	dec, err := h.authz.Authorize(r.Context(), authz.Request{
		Subject: sub,
		Action:  action,
		Resource: authz.Resource{
			Type:  authz.ResourceClient,
			ID:    client.ID,
			Owner: derefString(client.CustomerID),
		},
	})
	if err != nil {
		return false, err
	}
	return dec.Allow, nil
}

// loadOwnedClient fetches a client and authorizes the action against it,
// writing the appropriate error response when it can't proceed.
func (h *Admin) loadOwnedClient(w http.ResponseWriter, r *http.Request, sub authz.Subject, action string) (store.Client, bool) {
	client, err := h.store.GetClientByID(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client_not_found"})
		return store.Client{}, false
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "client_get_failed"})
		return store.Client{}, false
	}
	allowed, err := h.authorizeClient(r, sub, action, client)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authorization_failed"})
		return store.Client{}, false
	}
	if !allowed {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return store.Client{}, false
	}
	return client, true
}

func (h *Admin) selfListClients(w http.ResponseWriter, r *http.Request) {
	sub, ok := SubjectFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	scope, err := h.authz.Scope(r.Context(), sub, authz.ActionRead, authz.ResourceClient)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authorization_failed"})
		return
	}

	clients := []store.Client{}
	switch {
	case scope.All:
		clients, err = h.store.ListClients(r.Context(), nil)
	case len(scope.CustomerIDs) == 0:
		// nothing visible
	default:
		for _, cid := range scope.CustomerIDs {
			id := cid
			part, listErr := h.store.ListClients(r.Context(), &id)
			if listErr != nil {
				err = listErr
				break
			}
			clients = append(clients, part...)
		}
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "client_list_failed"})
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (h *Admin) selfCreateClient(w http.ResponseWriter, r *http.Request) {
	sub, ok := SubjectFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req clientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	// Target customer: an explicit customer_id (e.g. a superadmin/reseller picking
	// a tenant) falls back to the caller's own tenant. The PDP decides whether the
	// subject may create a client for that owner.
	owner := optionalString(req.CustomerID, req.CustomerIDCamel)
	if owner == nil {
		owner = subjectCustomer(sub)
	}
	dec, err := h.authz.Authorize(r.Context(), authz.Request{
		Subject:  sub,
		Action:   authz.ActionCreate,
		Resource: authz.Resource{Type: authz.ResourceClient, Owner: derefString(owner)},
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authorization_failed"})
		return
	}
	if !dec.Allow {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
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
		CustomerID:             owner,
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

func (h *Admin) selfGetClient(w http.ResponseWriter, r *http.Request) {
	sub, ok := SubjectFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	client, ok := h.loadOwnedClient(w, r, sub, authz.ActionRead)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, clientResponse(client))
}

func (h *Admin) selfUpdateClient(w http.ResponseWriter, r *http.Request) {
	sub, ok := SubjectFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	client, ok := h.loadOwnedClient(w, r, sub, authz.ActionUpdate)
	if !ok {
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

func (h *Admin) selfRotateSecret(w http.ResponseWriter, r *http.Request) {
	sub, ok := SubjectFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	client, ok := h.loadOwnedClient(w, r, sub, authz.ActionRotateSecret)
	if !ok {
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

func (h *Admin) selfDeleteClient(w http.ResponseWriter, r *http.Request) {
	sub, ok := SubjectFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	client, ok := h.loadOwnedClient(w, r, sub, authz.ActionDelete)
	if !ok {
		return
	}
	if err := h.store.DeleteClient(r.Context(), client.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "client_delete_failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// subjectCustomer returns the subject's customer id as a *string for the
// CustomerID column (nil when the subject has no tenant, e.g. a pure admin).
func subjectCustomer(sub authz.Subject) *string {
	if sub.CustomerID == "" {
		return nil
	}
	cid := sub.CustomerID
	return &cid
}
