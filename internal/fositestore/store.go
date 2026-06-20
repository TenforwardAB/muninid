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
 * This file :: internal/fositestore/store.go is part of the MuninID project.
 */

package fositestore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"

	"github.com/tenforwardab/muninid/internal/kv"
	"github.com/tenforwardab/muninid/internal/secret"
)

const (
	nameAuthorizeCode  = "fosite_authorize_code"
	nameAccessToken    = "fosite_access_token"
	nameRefreshToken   = "fosite_refresh_token"
	namePKCE           = "fosite_pkce"
	nameOpenID         = "fosite_openid"
	nameClientJWTJTI   = "fosite_client_jwt_jti"
	defaultResponseTyp = "code"
)

// Token sessions live in valkey (TTL-native, hot path). OAuth clients are still
// read from postgres via GetClient.
type Store struct {
	db         *pgxpool.Pool
	kv         *kv.Client
	secrets    *secret.Store
	defaultTTL time.Duration
}

func New(db *pgxpool.Pool, cache *kv.Client, secrets *secret.Store, defaultTTL time.Duration) *Store {
	if defaultTTL <= 0 {
		defaultTTL = 30 * 24 * time.Hour
	}
	return &Store{db: db, kv: cache, secrets: secrets, defaultTTL: defaultTTL}
}

func (s *Store) SecretHasher() EncryptedSecretHasher {
	return EncryptedSecretHasher{Secrets: s.secrets}
}

func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var clientID, clientSecret string
	var redirectJSON, grantJSON, scopeJSON []byte
	err := s.db.QueryRow(ctx, `select "clientId", "clientSecret", "redirectUris", "grantTypes", scopes
		from oidc_clients where "clientId"=$1`, id).Scan(&clientID, &clientSecret, &redirectJSON, &grantJSON, &scopeJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var redirectURIs, grantTypes, scopes []string
	if err := json.Unmarshal(redirectJSON, &redirectURIs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(grantJSON, &grantTypes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopeJSON, &scopes); err != nil {
		return nil, err
	}

	return &fosite.DefaultClient{
		ID:            clientID,
		Secret:        []byte(clientSecret),
		RedirectURIs:  redirectURIs,
		GrantTypes:    grantTypes,
		ResponseTypes: []string{defaultResponseTyp},
		Scopes:        scopes,
		Audience:      []string{clientID},
		Public:        clientSecret == "",
	}, nil
}

func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	exists, err := s.kv.Exists(ctx, jtiKey(jti))
	if err != nil {
		return err
	}
	if exists {
		return fosite.ErrJTIKnown
	}
	return nil
}

func (s *Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	body, _ := json.Marshal(map[string]any{"jti": jti})
	return s.kv.Set(ctx, jtiKey(jti), body, ttlUntil(exp, s.defaultTTL))
}

func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	return s.put(ctx, nameAuthorizeCode, code, request, "", false)
}

func (s *Store) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	request, persisted, err := s.get(ctx, nameAuthorizeCode, code, session)
	if err != nil {
		return nil, err
	}
	if persisted.Invalidated {
		return request, fosite.ErrInvalidatedAuthorizeCode
	}
	return request, nil
}

func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	persisted, err := s.getPersisted(ctx, nameAuthorizeCode, code)
	if err != nil {
		return err
	}
	persisted.Invalidated = true
	return s.putPersisted(ctx, nameAuthorizeCode, code, persisted)
}

func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.put(ctx, nameAccessToken, signature, request, "", false)
}

func (s *Store) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	request, _, err := s.get(ctx, nameAccessToken, signature, session)
	return request, err
}

func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.delete(ctx, nameAccessToken, signature)
}

func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	return s.put(ctx, nameRefreshToken, signature, request, accessSignature, false)
}

func (s *Store) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	request, _, err := s.get(ctx, nameRefreshToken, signature, session)
	return request, err
}

func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.delete(ctx, nameRefreshToken, signature)
}

func (s *Store) RotateRefreshToken(ctx context.Context, _ string, refreshTokenSignature string) error {
	return s.DeleteRefreshTokenSession(ctx, refreshTokenSignature)
}

func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.revokeByRequestID(ctx, nameRefreshToken, requestID)
}

func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.revokeByRequestID(ctx, nameAccessToken, requestID)
}

func (s *Store) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.put(ctx, namePKCE, signature, requester, "", false)
}

func (s *Store) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	request, _, err := s.get(ctx, namePKCE, signature, session)
	return request, err
}

func (s *Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.delete(ctx, namePKCE, signature)
}

func (s *Store) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	return s.put(ctx, nameOpenID, authorizeCode, requester, "", false)
}

func (s *Store) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	var session fosite.Session
	if requester != nil {
		session = requester.GetSession()
	}
	request, _, err := s.get(ctx, nameOpenID, authorizeCode, session)
	return request, err
}

func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return s.delete(ctx, nameOpenID, authorizeCode)
}

type persistedRequest struct {
	ID                string     `json:"id"`
	RequestedAt       time.Time  `json:"requested_at"`
	ClientID          string     `json:"client_id"`
	RequestedScope    []string   `json:"requested_scope,omitempty"`
	GrantedScope      []string   `json:"granted_scope,omitempty"`
	RequestedAudience []string   `json:"requested_audience,omitempty"`
	GrantedAudience   []string   `json:"granted_audience,omitempty"`
	Form              url.Values `json:"form,omitempty"`
	Session           *Session   `json:"session,omitempty"`
	AccessSignature   string     `json:"access_signature,omitempty"`
	Invalidated       bool       `json:"invalidated,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
}

func (s *Store) put(ctx context.Context, name, key string, request fosite.Requester, accessSignature string, invalidated bool) error {
	persisted, err := requestToPersisted(request)
	if err != nil {
		return err
	}
	persisted.AccessSignature = accessSignature
	persisted.Invalidated = invalidated
	// TTL must match THIS token's own lifespan, not the earliest across the
	// shared session: a refresh token (30d) and its access token (10m) live in
	// the same session, so using the earliest would expire the refresh token
	// session after the access token and break refresh.
	persisted.ExpiresAt = expiryFor(request.GetSession(), name)
	if err := s.putPersisted(ctx, name, key, persisted); err != nil {
		return err
	}
	// Access and refresh tokens can be revoked by request id; keep a reverse
	// index (request id -> store keys) so RevokeAccess/RefreshToken can find them.
	if (name == nameAccessToken || name == nameRefreshToken) && persisted.ID != "" {
		if err := s.kv.SAdd(ctx, indexKey(name, persisted.ID), s.ttlFor(persisted.ExpiresAt), storeID(name, key)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) putPersisted(ctx context.Context, name, key string, persisted persistedRequest) error {
	body, err := json.Marshal(persisted)
	if err != nil {
		return err
	}
	return s.kv.Set(ctx, storeID(name, key), body, s.ttlFor(persisted.ExpiresAt))
}

func (s *Store) get(ctx context.Context, name, key string, session fosite.Session) (fosite.Requester, persistedRequest, error) {
	persisted, err := s.getPersisted(ctx, name, key)
	if err != nil {
		return nil, persistedRequest{}, err
	}
	request, err := s.persistedToRequest(ctx, persisted, session)
	return request, persisted, err
}

func (s *Store) getPersisted(ctx context.Context, name, key string) (persistedRequest, error) {
	body, err := s.kv.Get(ctx, storeID(name, key))
	if errors.Is(err, kv.ErrNil) {
		return persistedRequest{}, fosite.ErrNotFound
	}
	if err != nil {
		return persistedRequest{}, err
	}
	var persisted persistedRequest
	if err := json.Unmarshal(body, &persisted); err != nil {
		return persistedRequest{}, err
	}
	// Redis TTL handles expiry, but honour the embedded deadline defensively.
	if persisted.ExpiresAt != nil && time.Now().UTC().After(*persisted.ExpiresAt) {
		_ = s.delete(ctx, name, key)
		return persistedRequest{}, fosite.ErrNotFound
	}
	return persisted, nil
}

func (s *Store) persistedToRequest(ctx context.Context, persisted persistedRequest, session fosite.Session) (fosite.Requester, error) {
	client, err := s.GetClient(ctx, persisted.ClientID)
	if err != nil {
		return nil, err
	}
	storedSession := session
	if persisted.Session != nil {
		storedSession = persisted.Session
	}
	if storedSession == nil {
		storedSession = &Session{}
	}
	return &fosite.Request{
		ID:                persisted.ID,
		RequestedAt:       persisted.RequestedAt,
		Client:            client,
		RequestedScope:    fosite.Arguments(persisted.RequestedScope),
		GrantedScope:      fosite.Arguments(persisted.GrantedScope),
		Form:              persisted.Form,
		Session:           storedSession,
		RequestedAudience: fosite.Arguments(persisted.RequestedAudience),
		GrantedAudience:   fosite.Arguments(persisted.GrantedAudience),
	}, nil
}

func (s *Store) delete(ctx context.Context, name, key string) error {
	return s.kv.Del(ctx, storeID(name, key))
}

func (s *Store) revokeByRequestID(ctx context.Context, name, requestID string) error {
	idx := indexKey(name, requestID)
	members, err := s.kv.SMembers(ctx, idx)
	if err != nil {
		return err
	}
	return s.kv.Del(ctx, append(members, idx)...)
}

// ttlFor converts an absolute expiry into a redis TTL, falling back to the
// configured default when the request carries no deadline.
func (s *Store) ttlFor(exp *time.Time) time.Duration {
	if exp == nil {
		return s.defaultTTL
	}
	if d := time.Until(*exp); d > 0 {
		return d
	}
	return time.Second
}

func ttlUntil(exp time.Time, fallback time.Duration) time.Duration {
	if exp.IsZero() {
		return fallback
	}
	if d := time.Until(exp); d > 0 {
		return d
	}
	return time.Second
}

func requestToPersisted(request fosite.Requester) (persistedRequest, error) {
	if request == nil {
		return persistedRequest{}, errors.New("nil fosite requester")
	}
	persisted := persistedRequest{
		ID:                request.GetID(),
		RequestedAt:       request.GetRequestedAt(),
		ClientID:          request.GetClient().GetID(),
		RequestedScope:    append([]string(nil), request.GetRequestedScopes()...),
		GrantedScope:      append([]string(nil), request.GetGrantedScopes()...),
		RequestedAudience: append([]string(nil), request.GetRequestedAudience()...),
		GrantedAudience:   append([]string(nil), request.GetGrantedAudience()...),
		Form:              cloneValues(request.GetRequestForm()),
	}
	if session, ok := request.GetSession().(*Session); ok {
		persisted.Session = session.Clone().(*Session)
	}
	return persisted, nil
}

// expiryFor returns the deadline for the token type being stored, so each
// session key gets a TTL matching its own lifespan (access ≈ minutes, refresh ≈
// days, codes ≈ short). nil means "no embedded deadline" -> fall back to defaultTTL.
func expiryFor(rawSession fosite.Session, name string) *time.Time {
	session, ok := rawSession.(*Session)
	if !ok {
		return nil
	}
	var tokenType fosite.TokenType
	switch name {
	case nameAccessToken:
		tokenType = fosite.AccessToken
	case nameRefreshToken:
		tokenType = fosite.RefreshToken
	case nameAuthorizeCode, namePKCE, nameOpenID:
		tokenType = fosite.AuthorizeCode
	default:
		return nil
	}
	if exp := session.GetExpiresAt(tokenType); !exp.IsZero() {
		value := exp
		return &value
	}
	return nil
}

func cloneValues(values url.Values) url.Values {
	clone := make(url.Values, len(values))
	for key, value := range values {
		clone[key] = append([]string(nil), value...)
	}
	return clone
}

func storeID(name, key string) string {
	sum := sha256.Sum256([]byte(name + "\x00" + key))
	return "fs:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func indexKey(name, requestID string) string {
	sum := sha256.Sum256([]byte("idx\x00" + name + "\x00" + requestID))
	return "fsidx:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func jtiKey(jti string) string {
	sum := sha256.Sum256([]byte("jti\x00" + jti))
	return "fsjti:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

var _ fosite.Storage = (*Store)(nil)
var _ oauth2.CoreStorage = (*Store)(nil)
var _ oauth2.TokenRevocationStorage = (*Store)(nil)
var _ pkce.PKCERequestStorage = (*Store)(nil)
var _ openid.OpenIDConnectRequestStorage = (*Store)(nil)
