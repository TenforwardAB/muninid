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
 * This file :: internal/store/store.go is part of the MuninID project.
 */

package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tenforwardab/muninid/internal/kv"
)

var ErrNotFound = errors.New("not found")

// Store keeps durable records (clients, keys, policies, audit, consent) in
// postgres and ephemeral, TTL-native state (login interactions, IdP sessions,
// login rate-limit counters) in valkey.
type Store struct {
	db *pgxpool.Pool
	kv *kv.Client
}

func New(db *pgxpool.Pool, cache *kv.Client) *Store {
	return &Store{db: db, kv: cache}
}

type Client struct {
	ID                     string    `json:"id"`
	ClientID               string    `json:"client_id"`
	ClientSecret           string    `json:"-"`
	Name                   string    `json:"name"`
	RedirectURIs           []string  `json:"redirect_uris"`
	GrantTypes             []string  `json:"grant_types"`
	Scopes                 []string  `json:"scopes"`
	PostLogoutRedirectURIs []string  `json:"post_logout_redirect_uris,omitempty"`
	CustomerID             *string   `json:"customer_id,omitempty"`
	CreatedBySubject       *string   `json:"created_by_subject,omitempty"`
	CreatedByEmail         *string   `json:"created_by_email,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type Key struct {
	ID         int
	PublicPEM  string
	PrivatePEM string
	KeyID      string
	Invalid    bool
}

type SAMLServiceProvider struct {
	ID               string         `json:"id"`
	EntityID         string         `json:"entityId"`
	MetadataXML      *string        `json:"metadataXml,omitempty"`
	ACSEndpoints     []string       `json:"acsEndpoints"`
	Binding          string         `json:"binding"`
	AttributeMapping map[string]any `json:"attributeMapping"`
	CreatedAt        time.Time      `json:"createdAt"`
	UpdatedAt        time.Time      `json:"updatedAt"`
}

type IdentityPolicy struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	TargetType string         `json:"targetType"`
	TargetID   *string        `json:"targetId,omitempty"`
	Policy     map[string]any `json:"policy"`
	CreatedAt  time.Time      `json:"createdAt"`
	UpdatedAt  time.Time      `json:"updatedAt"`
}

type TokenExchangePolicy struct {
	ID                 string    `json:"id"`
	ClientID           string    `json:"clientId"`
	Priority           int       `json:"priority"`
	Subject            *string   `json:"subject,omitempty"`
	SubjectTokenTypes  []string  `json:"subjectTokenTypes"`
	Audiences          []string  `json:"audiences"`
	Scopes             []string  `json:"scopes,omitempty"`
	ActorTokenRequired bool      `json:"actorTokenRequired"`
	Enabled            bool      `json:"enabled"`
	Description        *string   `json:"description,omitempty"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

type TokenExchangeEvent struct {
	ClientID          string
	PolicyID          *string
	Subject           *string
	SubjectTokenType  string
	SubjectTokenID    *string
	RequestedAudience *string
	GrantedAudience   *string
	RequestedScopes   []string
	GrantedScopes     []string
	ActorSubject      *string
	Success           bool
	Error             *string
	IssuedTokenID     *string
}

type ConsentGrant struct {
	Subject   string    `json:"subject"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	Audiences []string  `json:"audiences,omitempty"`
	GrantedAt time.Time `json:"granted_at"`
}

func (s *Store) ListClients(ctx context.Context, customerID *string) ([]Client, error) {
	query := `select id::text, "clientId", "clientSecret", name, "redirectUris", "grantTypes", scopes,
		coalesce("postLogoutRedirectUris", '[]'::jsonb), "customerId", "createdBySubject", "createdByEmail", "createdAt", "updatedAt"
		from oidc_clients`
	args := []any{}
	if customerID != nil {
		query += ` where "customerId" = $1`
		args = append(args, *customerID)
	}
	query += ` order by "createdAt" desc`
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanClients(rows)
}

func (s *Store) GetClientByID(ctx context.Context, id string) (Client, error) {
	return s.scanClient(ctx, `where id = $1`, id)
}

func (s *Store) GetClientByClientID(ctx context.Context, clientID string) (Client, error) {
	return s.scanClient(ctx, `where "clientId" = $1`, clientID)
}

func (s *Store) scanClient(ctx context.Context, where string, arg any) (Client, error) {
	rows, err := s.db.Query(ctx, `select id::text, "clientId", "clientSecret", name, "redirectUris", "grantTypes", scopes,
		coalesce("postLogoutRedirectUris", '[]'::jsonb), "customerId", "createdBySubject", "createdByEmail", "createdAt", "updatedAt"
		from oidc_clients `+where, arg)
	if err != nil {
		return Client{}, err
	}
	defer rows.Close()
	clients, err := scanClients(rows)
	if err != nil {
		return Client{}, err
	}
	if len(clients) == 0 {
		return Client{}, ErrNotFound
	}
	return clients[0], nil
}

func scanClients(rows pgx.Rows) ([]Client, error) {
	var clients []Client
	for rows.Next() {
		var c Client
		var redirectJSON, grantJSON, scopeJSON, logoutJSON []byte
		if err := rows.Scan(&c.ID, &c.ClientID, &c.ClientSecret, &c.Name, &redirectJSON, &grantJSON, &scopeJSON, &logoutJSON, &c.CustomerID, &c.CreatedBySubject, &c.CreatedByEmail, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(redirectJSON, &c.RedirectURIs)
		_ = json.Unmarshal(grantJSON, &c.GrantTypes)
		_ = json.Unmarshal(scopeJSON, &c.Scopes)
		_ = json.Unmarshal(logoutJSON, &c.PostLogoutRedirectURIs)
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (s *Store) CreateClient(ctx context.Context, c Client) (Client, error) {
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	redirectJSON, _ := json.Marshal(c.RedirectURIs)
	grantJSON, _ := json.Marshal(c.GrantTypes)
	scopeJSON, _ := json.Marshal(c.Scopes)
	logoutJSON, _ := json.Marshal(c.PostLogoutRedirectURIs)
	now := time.Now().UTC()
	err := s.db.QueryRow(ctx, `insert into oidc_clients
		(id, "clientId", "clientSecret", name, "redirectUris", "grantTypes", scopes, "postLogoutRedirectUris",
		 "customerId", "createdBySubject", "createdByEmail", "createdAt", "updatedAt")
		values ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10,$11,$12,$12)
		returning "createdAt", "updatedAt"`,
		c.ID, c.ClientID, c.ClientSecret, c.Name, redirectJSON, grantJSON, scopeJSON, logoutJSON,
		c.CustomerID, c.CreatedBySubject, c.CreatedByEmail, now,
	).Scan(&c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func (s *Store) UpdateClient(ctx context.Context, c Client) error {
	redirectJSON, _ := json.Marshal(c.RedirectURIs)
	grantJSON, _ := json.Marshal(c.GrantTypes)
	scopeJSON, _ := json.Marshal(c.Scopes)
	logoutJSON, _ := json.Marshal(c.PostLogoutRedirectURIs)
	tag, err := s.db.Exec(ctx, `update oidc_clients set
		name=$2, "clientSecret"=$3, "redirectUris"=$4::jsonb, "grantTypes"=$5::jsonb,
		scopes=$6::jsonb, "postLogoutRedirectUris"=$7::jsonb, "updatedAt"=now()
		where id=$1`,
		c.ID, c.Name, c.ClientSecret, redirectJSON, grantJSON, scopeJSON, logoutJSON)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteClient(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `delete from oidc_clients where id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListServiceProviders(ctx context.Context) ([]SAMLServiceProvider, error) {
	rows, err := s.db.Query(ctx, `select id::text, "entityId", "metadataXml", "acsEndpoints", binding, "attributeMapping", "createdAt", "updatedAt"
		from saml_service_providers order by "createdAt" desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanServiceProviders(rows)
}

func (s *Store) GetServiceProvider(ctx context.Context, id string) (SAMLServiceProvider, error) {
	rows, err := s.db.Query(ctx, `select id::text, "entityId", "metadataXml", "acsEndpoints", binding, "attributeMapping", "createdAt", "updatedAt"
		from saml_service_providers where id=$1`, id)
	if err != nil {
		return SAMLServiceProvider{}, err
	}
	defer rows.Close()
	providers, err := scanServiceProviders(rows)
	if err != nil {
		return SAMLServiceProvider{}, err
	}
	if len(providers) == 0 {
		return SAMLServiceProvider{}, ErrNotFound
	}
	return providers[0], nil
}

func (s *Store) CreateServiceProvider(ctx context.Context, provider SAMLServiceProvider) (SAMLServiceProvider, error) {
	if provider.ID == "" {
		provider.ID = uuid.NewString()
	}
	acsJSON, _ := json.Marshal(provider.ACSEndpoints)
	mappingJSON, _ := json.Marshal(provider.AttributeMapping)
	err := s.db.QueryRow(ctx, `insert into saml_service_providers
		(id, "entityId", "metadataXml", "acsEndpoints", binding, "attributeMapping", "createdAt", "updatedAt")
		values ($1,$2,$3,$4::jsonb,$5,$6::jsonb,now(),now())
		returning "createdAt", "updatedAt"`,
		provider.ID, provider.EntityID, provider.MetadataXML, acsJSON, provider.Binding, mappingJSON,
	).Scan(&provider.CreatedAt, &provider.UpdatedAt)
	return provider, err
}

func (s *Store) UpdateServiceProvider(ctx context.Context, provider SAMLServiceProvider) error {
	acsJSON, _ := json.Marshal(provider.ACSEndpoints)
	mappingJSON, _ := json.Marshal(provider.AttributeMapping)
	tag, err := s.db.Exec(ctx, `update saml_service_providers set
		"entityId"=$2, "metadataXml"=$3, "acsEndpoints"=$4::jsonb, binding=$5, "attributeMapping"=$6::jsonb, "updatedAt"=now()
		where id=$1`,
		provider.ID, provider.EntityID, provider.MetadataXML, acsJSON, provider.Binding, mappingJSON)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteServiceProvider(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `delete from saml_service_providers where id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanServiceProviders(rows pgx.Rows) ([]SAMLServiceProvider, error) {
	var providers []SAMLServiceProvider
	for rows.Next() {
		var provider SAMLServiceProvider
		var acsJSON, mappingJSON []byte
		if err := rows.Scan(&provider.ID, &provider.EntityID, &provider.MetadataXML, &acsJSON, &provider.Binding, &mappingJSON, &provider.CreatedAt, &provider.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(acsJSON, &provider.ACSEndpoints)
		_ = json.Unmarshal(mappingJSON, &provider.AttributeMapping)
		providers = append(providers, provider)
	}
	return providers, rows.Err()
}

func (s *Store) ListPolicies(ctx context.Context) ([]IdentityPolicy, error) {
	rows, err := s.db.Query(ctx, `select id::text, name, "targetType", "targetId"::text, policy, "createdAt", "updatedAt"
		from identity_policies order by "createdAt" desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPolicies(rows)
}

func (s *Store) GetPolicy(ctx context.Context, id string) (IdentityPolicy, error) {
	rows, err := s.db.Query(ctx, `select id::text, name, "targetType", "targetId"::text, policy, "createdAt", "updatedAt"
		from identity_policies where id=$1`, id)
	if err != nil {
		return IdentityPolicy{}, err
	}
	defer rows.Close()
	policies, err := scanPolicies(rows)
	if err != nil {
		return IdentityPolicy{}, err
	}
	if len(policies) == 0 {
		return IdentityPolicy{}, ErrNotFound
	}
	return policies[0], nil
}

func (s *Store) CreatePolicy(ctx context.Context, policy IdentityPolicy) (IdentityPolicy, error) {
	if policy.ID == "" {
		policy.ID = uuid.NewString()
	}
	policyJSON, _ := json.Marshal(policy.Policy)
	err := s.db.QueryRow(ctx, `insert into identity_policies
		(id, name, "targetType", "targetId", policy, "createdAt", "updatedAt")
		values ($1,$2,$3,$4,$5::jsonb,now(),now())
		returning "createdAt", "updatedAt"`,
		policy.ID, policy.Name, policy.TargetType, policy.TargetID, policyJSON,
	).Scan(&policy.CreatedAt, &policy.UpdatedAt)
	return policy, err
}

func (s *Store) UpdatePolicy(ctx context.Context, policy IdentityPolicy) error {
	policyJSON, _ := json.Marshal(policy.Policy)
	tag, err := s.db.Exec(ctx, `update identity_policies set
		name=$2, "targetType"=$3, "targetId"=$4, policy=$5::jsonb, "updatedAt"=now()
		where id=$1`,
		policy.ID, policy.Name, policy.TargetType, policy.TargetID, policyJSON)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeletePolicy(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `delete from identity_policies where id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanPolicies(rows pgx.Rows) ([]IdentityPolicy, error) {
	var policies []IdentityPolicy
	for rows.Next() {
		var policy IdentityPolicy
		var policyJSON []byte
		if err := rows.Scan(&policy.ID, &policy.Name, &policy.TargetType, &policy.TargetID, &policyJSON, &policy.CreatedAt, &policy.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(policyJSON, &policy.Policy)
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}

func (s *Store) FindTokenExchangePolicy(ctx context.Context, clientID, subject, subjectTokenType, audience string, actorPresent bool) (*TokenExchangePolicy, error) {
	rows, err := s.db.Query(ctx, `select id::text, "clientId", priority, subject, "subjectTokenTypes", audiences,
		coalesce(scopes, 'null'::jsonb), "actorTokenRequired", enabled, description, "createdAt", "updatedAt"
		from token_exchange_policies
		where "clientId"=$1 and enabled=true
		order by priority desc, "createdAt" asc`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		policy, err := scanTokenExchangePolicy(rows)
		if err != nil {
			return nil, err
		}
		if tokenExchangePolicyMatches(policy, subject, subjectTokenType, audience, actorPresent) {
			return &policy, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nil, ErrNotFound
}

func scanTokenExchangePolicy(rows pgx.Rows) (TokenExchangePolicy, error) {
	var policy TokenExchangePolicy
	var typesJSON, audiencesJSON []byte
	var scopesJSON []byte
	if err := rows.Scan(&policy.ID, &policy.ClientID, &policy.Priority, &policy.Subject, &typesJSON, &audiencesJSON, &scopesJSON, &policy.ActorTokenRequired, &policy.Enabled, &policy.Description, &policy.CreatedAt, &policy.UpdatedAt); err != nil {
		return TokenExchangePolicy{}, err
	}
	_ = json.Unmarshal(typesJSON, &policy.SubjectTokenTypes)
	_ = json.Unmarshal(audiencesJSON, &policy.Audiences)
	if len(scopesJSON) > 0 {
		_ = json.Unmarshal(scopesJSON, &policy.Scopes)
	}
	return policy, nil
}

func tokenExchangePolicyMatches(policy TokenExchangePolicy, subject, subjectTokenType, audience string, actorPresent bool) bool {
	if policy.Subject != nil && *policy.Subject != "" && *policy.Subject != "*" && *policy.Subject != subject {
		return false
	}
	if !matchesList(policy.SubjectTokenTypes, subjectTokenType) {
		return false
	}
	if !matchesList(policy.Audiences, audience) {
		return false
	}
	return !policy.ActorTokenRequired || actorPresent
}

func matchesList(values []string, candidate string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == "*" || value == candidate {
			return true
		}
	}
	return false
}

func (s *Store) LogTokenExchangeEvent(ctx context.Context, event TokenExchangeEvent) error {
	requestedScopesJSON, _ := json.Marshal(event.RequestedScopes)
	grantedScopesJSON, _ := json.Marshal(event.GrantedScopes)
	_, err := s.db.Exec(ctx, `insert into token_exchange_events
		(id, "clientId", "policyId", subject, "subjectTokenType", "subjectTokenId", "requestedAudience", "grantedAudience",
		 "requestedScopes", "grantedScopes", "actorSubject", success, error, "issuedTokenId", "createdAt", "updatedAt")
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12,$13,$14,now(),now())`,
		uuid.NewString(), event.ClientID, event.PolicyID, event.Subject, event.SubjectTokenType, event.SubjectTokenID,
		event.RequestedAudience, event.GrantedAudience, requestedScopesJSON, grantedScopesJSON, event.ActorSubject,
		event.Success, event.Error, event.IssuedTokenID)
	return err
}

func (s *Store) ActiveKeys(ctx context.Context) ([]Key, error) {
	rows, err := s.db.Query(ctx, `select id, "publicKey", "privateKey", "keyId", "isInvalid" from jwt_rsa256_keys where "isInvalid" = false order by "createdAt" desc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []Key
	for rows.Next() {
		var key Key
		if err := rows.Scan(&key.ID, &key.PublicPEM, &key.PrivatePEM, &key.KeyID, &key.Invalid); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) InsertKey(ctx context.Context, publicPEM, privatePEM, keyID string) error {
	_, err := s.db.Exec(ctx, `insert into jwt_rsa256_keys ("publicKey", "privateKey", "keyId", "isInvalid", "createdAt", "updatedAt") values ($1,$2,$3,false,now(),now())`,
		publicPEM, privatePEM, keyID)
	return err
}

// PutArtifact/GetArtifact/DeleteArtifact back the ephemeral OAuth interaction
// state (login interactions, IdP SSO sessions). They live in valkey so a muninid
// restart keeps them and redis TTL handles expiry. A ttl <= 0 means no expiry.
func (s *Store) PutArtifact(ctx context.Context, name, id string, payload map[string]any, ttl time.Duration) error {
	body, _ := json.Marshal(payload)
	return s.kv.Set(ctx, artifactKey(name, id), body, ttl)
}

func (s *Store) GetArtifact(ctx context.Context, name, id string) (map[string]any, error) {
	body, err := s.kv.Get(ctx, artifactKey(name, id))
	if errors.Is(err, kv.ErrNil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (s *Store) DeleteArtifact(ctx context.Context, name, id string) error {
	return s.kv.Del(ctx, artifactKey(name, id))
}

func artifactKey(name, id string) string {
	return "art:" + name + ":" + id
}

// Consent grants are durable user decisions, so they stay in postgres
// (oidc_adapter_store) rather than valkey.
func (s *Store) PutConsentGrant(ctx context.Context, subject, clientID string, scopes, audiences []string) error {
	body, _ := json.Marshal(map[string]any{
		"subject":    subject,
		"client_id":  clientID,
		"scopes":     scopes,
		"audiences":  audiences,
		"granted_at": time.Now().UTC(),
	})
	_, err := s.db.Exec(ctx, `insert into oidc_adapter_store (id,name,payload,"expiresAt","createdAt","updatedAt")
		values ($1,$2,$3::jsonb,null,now(),now())
		on conflict (id) do update set payload=excluded.payload, "updatedAt"=now()`,
		consentGrantID(subject, clientID), "ConsentGrant", body)
	return err
}

func (s *Store) GetConsentGrant(ctx context.Context, subject, clientID string) (ConsentGrant, error) {
	var body []byte
	err := s.db.QueryRow(ctx, `select payload from oidc_adapter_store where id=$1 and name=$2`,
		consentGrantID(subject, clientID), "ConsentGrant").Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConsentGrant{}, ErrNotFound
	}
	if err != nil {
		return ConsentGrant{}, err
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return ConsentGrant{}, err
	}
	grant := ConsentGrant{
		Subject:   strFromAny(payload["subject"]),
		ClientID:  strFromAny(payload["client_id"]),
		Scopes:    stringsFromAny(payload["scopes"]),
		Audiences: stringsFromAny(payload["audiences"]),
	}
	if raw, ok := payload["granted_at"].(string); ok {
		grant.GrantedAt, _ = time.Parse(time.RFC3339Nano, raw)
	}
	return grant, nil
}

func consentGrantID(subject, clientID string) string {
	sum := sha256.Sum256([]byte(subject + "\x00" + clientID))
	return "consent:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func strFromAny(value any) string {
	s, _ := value.(string)
	return s
}

func stringsFromAny(value any) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// Login failure / lockout counters live in valkey (high churn, TTL-native). The
// failure counter expires after lockFor; once lockAfter failures accumulate a
// lock key is set with the same TTL.
func (s *Store) RecordLoginFailure(ctx context.Context, key, keyType string, lockAfter int, lockFor time.Duration) error {
	_ = keyType
	count, err := s.kv.IncrTTL(ctx, loginFailKey(key), lockFor)
	if err != nil {
		return err
	}
	if lockAfter > 0 && int(count) >= lockAfter {
		return s.kv.Set(ctx, loginLockKey(key), []byte("1"), lockFor)
	}
	return nil
}

func (s *Store) LoginLocked(ctx context.Context, key string) (bool, *time.Time, error) {
	pttl, err := s.kv.PTTL(ctx, loginLockKey(key))
	if err != nil {
		return false, nil, err
	}
	if pttl <= 0 {
		return false, nil, nil
	}
	until := time.Now().Add(pttl)
	return true, &until, nil
}

func (s *Store) ResetLoginFailures(ctx context.Context, key string) error {
	return s.kv.Del(ctx, loginFailKey(key), loginLockKey(key))
}

func loginFailKey(key string) string { return "login:fail:" + key }
func loginLockKey(key string) string { return "login:lock:" + key }
