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
 * This file :: internal/idp/provider.go is part of the MuninID project.
 */

package idp

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"
	wildduck "github.com/tenforwardab/wildduck-gosdk"

	"github.com/tenforwardab/muninid/internal/config"
	"github.com/tenforwardab/muninid/internal/fositestore"
	"github.com/tenforwardab/muninid/internal/secret"
	"github.com/tenforwardab/muninid/internal/store"
)

const (
	sessionCookie           = "idp.sid"
	codeName                = "AuthorizationCode"
	sessionName             = "Session"
	interactionName         = "Interaction"
	refreshName             = "RefreshToken"
	revokedName             = "RevokedToken"
	tokenExchangeGrant      = "urn:ietf:params:oauth:grant-type:token-exchange"
	accessTokenType         = "urn:ietf:params:oauth:token-type:access_token"
	tokenExchangeIssuedType = "urn:ietf:params:oauth:token-type:access_token"
)

type InteractionView struct {
	UID       string
	Mode      string
	ClientID  string
	Client    string
	Scopes    []string
	Audiences []string
	Error     string
}

type Provider struct {
	cfg     config.Config
	store   *store.Store
	secrets *secret.Store
	wd      *wildduck.Client
	key     *rsa.PrivateKey
	keyID   string
	fstore  *fositestore.Store
	oauth   fosite.OAuth2Provider
}

type Interaction struct {
	UID           string         `json:"uid"`
	ClientID      string         `json:"client_id"`
	RedirectURI   string         `json:"redirect_uri"`
	Scope         string         `json:"scope"`
	State         string         `json:"state,omitempty"`
	Nonce         string         `json:"nonce,omitempty"`
	CodeChallenge string         `json:"code_challenge,omitempty"`
	CodeMethod    string         `json:"code_challenge_method,omitempty"`
	Params        map[string]any `json:"params,omitempty"`
}

type Account struct {
	ID           string         `json:"id"`
	Email        string         `json:"email"`
	Username     string         `json:"username"`
	Name         string         `json:"name"`
	Activated    bool           `json:"activated"`
	Suspended    bool           `json:"suspended"`
	Disabled     bool           `json:"disabled"`
	MetaData     map[string]any `json:"metaData"`
	InternalData map[string]any `json:"internalData"`
}

func New(ctx context.Context, cfg config.Config, st *store.Store, fst *fositestore.Store, wd *wildduck.Client) (*Provider, error) {
	p := &Provider{cfg: cfg, store: st, secrets: secret.New(cfg.SecretKey), wd: wd}
	if err := p.loadSigningKey(ctx); err != nil {
		return nil, err
	}
	if fst != nil {
		p.fstore = fst
		p.oauth = p.newFositeProvider(fst)
	}
	return p, nil
}

func (p *Provider) newFositeProvider(fst *fositestore.Store) fosite.OAuth2Provider {
	keyGetter := func(context.Context) (interface{}, error) {
		return p.key, nil
	}
	secretHash := sha256.Sum256([]byte(p.cfg.SecretKey))
	cfg := &fosite.Config{
		AccessTokenLifespan:            p.cfg.AccessTokenTTL,
		RefreshTokenLifespan:           p.cfg.RefreshTokenTTL,
		AuthorizeCodeLifespan:          p.cfg.CodeTTL,
		IDTokenLifespan:                p.cfg.IDTokenTTL,
		IDTokenIssuer:                  p.cfg.Issuer,
		AccessTokenIssuer:              p.cfg.Issuer,
		TokenURL:                       p.cfg.Issuer + "/oauth/token",
		GlobalSecret:                   secretHash[:],
		ClientSecretsHasher:            fst.SecretHasher(),
		RefreshTokenScopes:             []string{"offline_access"},
		EnforcePKCE:                    true,
		EnablePKCEPlainChallengeMethod: false,
		JWTScopeClaimKey:               jwt.JWTScopeFieldString,
		MinParameterEntropy:            16,
	}
	hmacStrategy := compose.NewOAuth2HMACStrategy(cfg)
	jwtStrategy := compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, cfg)
	return compose.Compose(
		cfg,
		fst,
		&compose.CommonStrategy{
			CoreStrategy:               jwtStrategy,
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, cfg),
			Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
	)
}

func (p *Provider) loadSigningKey(ctx context.Context) error {
	keys, err := p.store.ActiveKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return err
		}
		publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
		keyID := keyIDForPublicPEM(publicPEM)
		encrypted, err := p.secrets.Encrypt(string(privatePEM))
		if err != nil {
			return err
		}
		if err := p.store.InsertKey(ctx, string(publicPEM), encrypted, keyID); err != nil {
			return err
		}
		p.key, p.keyID = key, keyID
		return nil
	}
	privatePEM, err := p.secrets.Decrypt(keys[0].PrivatePEM)
	if err != nil {
		return err
	}
	key, err := parseRSAPrivateKey(privatePEM)
	if err != nil {
		return err
	}
	p.key, p.keyID = key, keys[0].KeyID
	return nil
}

func parseRSAPrivateKey(value string) (*rsa.PrivateKey, error) {
	normalized := strings.ReplaceAll(value, `\n`, "\n")
	normalized = strings.ReplaceAll(normalized, `\r`, "\r")
	normalized = strings.ReplaceAll(normalized, "------BEGIN ", "-----BEGIN ")
	normalized = strings.ReplaceAll(normalized, "------END ", "-----END ")
	block, _ := pem.Decode([]byte(normalized))
	if block == nil {
		key, err := parseRSAJWKPrivateKey([]byte(value))
		if err != nil {
			return nil, errors.New("invalid private key pem or jwk")
		}
		return key, nil
	}
	return parseRSAPrivateKeyDER(block.Bytes)
}

func parseRSAPrivateKeyDER(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

func parseRSAJWKPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	var jwk struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
		D   string `json:"d"`
		P   string `json:"p"`
		Q   string `json:"q"`
		DP  string `json:"dp"`
		DQ  string `json:"dq"`
		QI  string `json:"qi"`
	}
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, err
	}
	if jwk.Kty != "RSA" {
		return nil, errors.New("private key is not RSA")
	}
	n, err := jwkBigInt(jwk.N)
	if err != nil {
		return nil, err
	}
	e, err := jwkInt(jwk.E)
	if err != nil {
		return nil, err
	}
	d, err := jwkBigInt(jwk.D)
	if err != nil {
		return nil, err
	}
	p, err := jwkBigInt(jwk.P)
	if err != nil {
		return nil, err
	}
	q, err := jwkBigInt(jwk.Q)
	if err != nil {
		return nil, err
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: e},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	if jwk.DP != "" && jwk.DQ != "" && jwk.QI != "" {
		dp, err := jwkBigInt(jwk.DP)
		if err != nil {
			return nil, err
		}
		dq, err := jwkBigInt(jwk.DQ)
		if err != nil {
			return nil, err
		}
		qi, err := jwkBigInt(jwk.QI)
		if err != nil {
			return nil, err
		}
		key.Precomputed.Dp = dp
		key.Precomputed.Dq = dq
		key.Precomputed.Qinv = qi
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	key.Precompute()
	return key, nil
}

func jwkBigInt(value string) (*big.Int, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(decoded), nil
}

func jwkInt(value string) (int, error) {
	decoded, err := jwkBigInt(value)
	if err != nil {
		return 0, err
	}
	return int(decoded.Int64()), nil
}

func (p *Provider) Discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.cfg.Issuer,
		"authorization_endpoint":                p.cfg.Issuer + "/oauth/authorize",
		"token_endpoint":                        p.cfg.Issuer + "/oauth/token",
		"jwks_uri":                              p.cfg.Issuer + "/oauth/jwks.json",
		"userinfo_endpoint":                     p.cfg.Issuer + "/userinfo",
		"introspection_endpoint":                p.cfg.Issuer + "/oauth/introspect",
		"revocation_endpoint":                   p.cfg.Issuer + "/oauth/revoke",
		"end_session_endpoint":                  p.cfg.Issuer + "/oauth/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials", tokenExchangeGrant},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "account", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "preferred_username", "name", "given_name", "family_name", "customer_id", "roles", "permissions", "branding"},
	})
}

func (p *Provider) JWKS(w http.ResponseWriter, r *http.Request) {
	pub := p.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]any{{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": p.keyID,
		"n":   b64(pub.N.Bytes()),
		"e":   b64(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (p *Provider) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	client, err := p.store.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client", "unknown client")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !contains(client.RedirectURIs, redirectURI) {
		oauthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is not registered")
		return
	}
	if q.Get("response_type") != "code" {
		redirectError(w, redirectURI, q.Get("state"), "unsupported_response_type", "only code is supported")
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		redirectError(w, redirectURI, q.Get("state"), "invalid_request", "PKCE S256 is required")
		return
	}
	scope, err := allowedScopes(client, q.Get("scope"), false)
	if err != nil {
		redirectError(w, redirectURI, q.Get("state"), "invalid_scope", "requested scope is not allowed for this client")
		return
	}
	q.Set("scope", scope)
	if sid, ok := p.readSession(r); ok {
		if session, err := p.store.GetArtifact(r.Context(), sessionName, sid); err == nil {
			sub, _ := session["sub"].(string)
			if !p.canAutoGrantAuthorization(r.Context(), client, sub, q) {
				p.redirectToConsent(w, r, client, sub, q)
				return
			}
			p.finishAuthorization(w, r, client, sub, q)
			return
		}
	}
	uid := randomID(16)
	interaction := map[string]any{
		"uid":                   uid,
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"scope":                 q.Get("scope"),
		"state":                 q.Get("state"),
		"nonce":                 q.Get("nonce"),
		"prompt":                q.Get("prompt"),
		"code_challenge":        q.Get("code_challenge"),
		"code_challenge_method": q.Get("code_challenge_method"),
	}
	if err := p.store.PutArtifact(r.Context(), interactionName, uid, interaction, 10*time.Minute); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to store interaction")
		return
	}
	http.Redirect(w, r, "/interaction/"+url.PathEscape(uid), http.StatusFound)
}

func (p *Provider) FinishLogin(ctx context.Context, uid, username, password, ip, userAgent string) (string, error) {
	// Brute-force lockout thresholds. The per-IP+username counter stops targeted
	// guessing from a single source; the per-username counter adds protection
	// against distributed / credential-stuffing attempts spread across many IPs.
	const (
		ipLockAfter   = 5
		ipLockFor     = 15 * time.Minute
		userLockAfter = 20
		userLockFor   = 15 * time.Minute
	)

	artifact, err := p.store.GetArtifact(ctx, interactionName, uid)
	if err != nil {
		return "", err
	}
	_ = artifact

	uname := strings.ToLower(username)
	ipKey := uname + "|" + ip  // targeted brute force from a single source
	userKey := "user|" + uname // distributed brute force across many IPs

	// Check both lockouts before talking to the auth backend.
	for _, lk := range []string{ipKey, userKey} {
		if locked, _, err := p.store.LoginLocked(ctx, lk); err != nil {
			return "", err
		} else if locked {
			return "", errors.New("locked")
		}
	}

	recordFailure := func() {
		_ = p.store.RecordLoginFailure(ctx, ipKey, "user_ip", ipLockAfter, ipLockFor)
		_ = p.store.RecordLoginFailure(ctx, userKey, "user", userLockAfter, userLockFor)
	}

	auth, err := p.wd.Authentication.Authenticate(ctx, username, password, wildduck.M{"scope": "master"})
	if err != nil || auth["success"] != true {
		recordFailure()
		return "", errors.New("invalid credentials")
	}
	userID, _ := auth["id"].(string)
	if userID == "" {
		recordFailure()
		return "", errors.New("invalid credentials")
	}
	account, err := p.FetchAccount(ctx, userID)
	if err != nil {
		return "", err
	}
	if !account.Activated || account.Suspended || account.Disabled {
		recordFailure()
		return "", errors.New("invalid credentials")
	}
	_ = p.store.ResetLoginFailures(ctx, ipKey)
	_ = p.store.ResetLoginFailures(ctx, userKey)
	sessionID := randomID(32)
	_ = p.store.PutArtifact(ctx, sessionName, sessionID, map[string]any{"sub": account.ID, "email": account.Email}, 24*time.Hour)
	return sessionID, nil
}

func (p *Provider) RedirectAfterLogin(w http.ResponseWriter, r *http.Request, uid, sessionID string) {
	http.SetCookie(w, p.signedCookie(sessionCookie, sessionID, 24*time.Hour))
	artifact, err := p.store.GetArtifact(r.Context(), interactionName, uid)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "interaction not found")
		return
	}
	q := url.Values{}
	for k, v := range artifact {
		if s, ok := v.(string); ok && s != "" && k != "uid" {
			q.Set(k, s)
		}
	}
	q.Set("response_type", "code")
	http.Redirect(w, r, "/oauth/authorize?"+q.Encode(), http.StatusSeeOther)
}

func (p *Provider) InteractionView(r *http.Request, uid string, errorText string) (InteractionView, error) {
	artifact, err := p.store.GetArtifact(r.Context(), interactionName, uid)
	if err != nil {
		return InteractionView{}, err
	}
	view := InteractionView{UID: uid, Mode: "login", Error: errorText}
	clientID, _ := artifact["client_id"].(string)
	view.ClientID = clientID
	if client, err := p.store.GetClientByClientID(r.Context(), clientID); err == nil {
		view.Client = firstNonEmpty(client.Name, client.ClientID)
	} else {
		view.Client = clientID
	}
	if sid, ok := p.readSession(r); ok {
		if session, err := p.store.GetArtifact(r.Context(), sessionName, sid); err == nil && session["sub"] != "" {
			view.Mode = "consent"
			view.Scopes = parseScopes(str(artifact["scope"]))
			view.Audiences = parseScopes(str(artifact["audience"]))
		}
	}
	return view, nil
}

func (p *Provider) ConfirmConsent(w http.ResponseWriter, r *http.Request, uid string) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	if r.Form.Get("allow") != "yes" {
		p.abortInteraction(w, r, uid)
		return
	}
	sid, ok := p.readSession(r)
	if !ok {
		http.Redirect(w, r, "/interaction/"+url.PathEscape(uid), http.StatusSeeOther)
		return
	}
	session, err := p.store.GetArtifact(r.Context(), sessionName, sid)
	if err != nil {
		http.Redirect(w, r, "/interaction/"+url.PathEscape(uid), http.StatusSeeOther)
		return
	}
	sub, _ := session["sub"].(string)
	artifact, err := p.store.GetArtifact(r.Context(), interactionName, uid)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "interaction not found")
		return
	}
	clientID, _ := artifact["client_id"].(string)
	client, err := p.store.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client", "unknown client")
		return
	}
	q := valuesFromInteraction(artifact)
	scopes := parseScopes(q.Get("scope"))
	audiences := append(parseScopes(q.Get("audience")), client.ClientID)
	if err := p.store.PutConsentGrant(r.Context(), sub, client.ClientID, scopes, uniqueStrings(audiences)); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to store consent")
		return
	}
	p.finishAuthorization(w, r, client, sub, q)
}

func (p *Provider) AbortInteraction(w http.ResponseWriter, r *http.Request, uid string) {
	p.abortInteraction(w, r, uid)
}

func (p *Provider) abortInteraction(w http.ResponseWriter, r *http.Request, uid string) {
	artifact, err := p.store.GetArtifact(r.Context(), interactionName, uid)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "interaction not found")
		return
	}
	redirectError(w, str(artifact["redirect_uri"]), str(artifact["state"]), "access_denied", "consent denied")
}

func (p *Provider) canAutoGrantAuthorization(ctx context.Context, client store.Client, sub string, q url.Values) bool {
	if p.trustedFirstPartyClient(client) {
		return true
	}
	if q.Get("prompt") == "consent" {
		return false
	}
	grant, err := p.store.GetConsentGrant(ctx, sub, client.ClientID)
	if err != nil {
		return false
	}
	return scopeSubset(parseScopes(q.Get("scope")), grant.Scopes) && scopeSubset([]string{client.ClientID}, grant.Audiences)
}

func (p *Provider) redirectToConsent(w http.ResponseWriter, r *http.Request, client store.Client, sub string, q url.Values) {
	uid := randomID(16)
	interaction := map[string]any{
		"uid":                   uid,
		"client_id":             client.ClientID,
		"redirect_uri":          q.Get("redirect_uri"),
		"scope":                 q.Get("scope"),
		"audience":              strings.Join(q["audience"], " "),
		"state":                 q.Get("state"),
		"nonce":                 q.Get("nonce"),
		"prompt":                q.Get("prompt"),
		"code_challenge":        q.Get("code_challenge"),
		"code_challenge_method": q.Get("code_challenge_method"),
		"sub":                   sub,
	}
	if err := p.store.PutArtifact(r.Context(), interactionName, uid, interaction, 10*time.Minute); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to store interaction")
		return
	}
	http.Redirect(w, r, "/interaction/"+url.PathEscape(uid), http.StatusFound)
}

func (p *Provider) finishAuthorization(w http.ResponseWriter, r *http.Request, client store.Client, sub string, q url.Values) {
	if p.oauth != nil {
		p.finishAuthorizationFosite(w, r, client, sub, q)
		return
	}
	code := randomID(32)
	payload := map[string]any{
		"client_id":      client.ClientID,
		"redirect_uri":   q.Get("redirect_uri"),
		"scope":          q.Get("scope"),
		"sub":            sub,
		"nonce":          q.Get("nonce"),
		"code_challenge": q.Get("code_challenge"),
	}
	if err := p.store.PutArtifact(r.Context(), codeName, code, payload, p.cfg.CodeTTL); err != nil {
		redirectError(w, q.Get("redirect_uri"), q.Get("state"), "server_error", "failed to store authorization code")
		return
	}
	redirect, _ := url.Parse(q.Get("redirect_uri"))
	values := redirect.Query()
	values.Set("code", code)
	if state := q.Get("state"); state != "" {
		values.Set("state", state)
	}
	redirect.RawQuery = values.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *Provider) finishAuthorizationFosite(w http.ResponseWriter, r *http.Request, client store.Client, sub string, q url.Values) {
	ctx := r.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.Issuer+"/oauth/authorize?"+q.Encode(), nil)
	if err != nil {
		redirectError(w, q.Get("redirect_uri"), q.Get("state"), "server_error", "failed to build authorization request")
		return
	}
	req.RemoteAddr = r.RemoteAddr
	req.Header.Set("User-Agent", r.UserAgent())
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}
	if forwardedProto := r.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
		req.Header.Set("X-Forwarded-Proto", forwardedProto)
	}

	ar, err := p.oauth.NewAuthorizeRequest(ctx, req)
	if err != nil {
		p.oauth.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	for _, audience := range ar.GetRequestedAudience() {
		ar.GrantAudience(audience)
	}
	ar.GrantAudience(client.ClientID)
	session := p.newFositeSession(ctx, sub, client.ClientID, q.Get("nonce"))
	response, err := p.oauth.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		p.oauth.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	p.oauth.WriteAuthorizeResponse(ctx, w, ar, response)
}

func (p *Provider) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	if r.Form.Get("grant_type") != tokenExchangeGrant && p.oauth != nil {
		p.tokenFosite(w, r)
		return
	}
	client, err := p.authenticateClient(r)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		p.tokenAuthorizationCode(w, r, client)
	case "refresh_token":
		p.tokenRefresh(w, r, client)
	case "client_credentials":
		p.tokenClientCredentials(w, r, client)
	case tokenExchangeGrant:
		p.tokenExchange(w, r, client)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (p *Provider) tokenFosite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p.normalizeClientCredentialsScope(r)
	session := &fositestore.Session{
		JWTClaims: &jwt.JWTClaims{Extra: map[string]interface{}{}},
		JWTHeader: jwt.NewHeaders(),
		IDClaims:  &jwt.IDTokenClaims{RequestedAt: time.Now().UTC(), Extra: map[string]interface{}{}},
		IDHeader:  jwt.NewHeaders(),
	}
	session.JWTHeader.Add("kid", p.keyID)
	session.IDHeader.Add("kid", p.keyID)

	accessRequest, err := p.oauth.NewAccessRequest(ctx, r, session)
	if err != nil {
		logFositeError("fosite token access request error", r.Form.Get("grant_type"), err)
		p.oauth.WriteAccessError(ctx, w, accessRequest, err)
		return
	}
	if accessRequest.GetGrantTypes().ExactOne("client_credentials") {
		for _, scope := range accessRequest.GetRequestedScopes() {
			accessRequest.GrantScope(scope)
		}
		accessRequest.GrantAudience(accessRequest.GetClient().GetID())
	}
	if accessRequest.GetSession() == session {
		p.populateClientTokenSession(session, accessRequest.GetClient().GetID())
	}
	response, err := p.oauth.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		logFositeError("fosite token access response error", r.Form.Get("grant_type"), err)
		p.oauth.WriteAccessError(ctx, w, accessRequest, err)
		return
	}
	p.writeCompatibleAccessResponse(w, response)
}

func logFositeError(prefix, grantType string, err error) {
	var oauthErr *fosite.RFC6749Error
	if errors.As(err, &oauthErr) {
		log.Printf("%s: grant_type=%s err=%v reason=%q debug=%q cause=%v", prefix, grantType, oauthErr, oauthErr.Reason(), oauthErr.Debug(), oauthErr.Cause())
		return
	}
	log.Printf("%s: grant_type=%s err=%v", prefix, grantType, err)
}

func (p *Provider) tokenAuthorizationCode(w http.ResponseWriter, r *http.Request, client store.Client) {
	if !contains(client.GrantTypes, "authorization_code") {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "client is not allowed to use authorization_code")
		return
	}
	code := r.Form.Get("code")
	payload, err := p.store.GetArtifact(r.Context(), codeName, code)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	if payload["client_id"] != client.ClientID || payload["redirect_uri"] != r.Form.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code client or redirect mismatch")
		return
	}
	challenge, _ := payload["code_challenge"].(string)
	if challenge != "" && !verifyPKCE(challenge, r.Form.Get("code_verifier")) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier is invalid")
		return
	}
	_ = p.store.DeleteArtifact(r.Context(), codeName, code)
	sub, _ := payload["sub"].(string)
	scope, _ := payload["scope"].(string)
	scope, err = allowedScopes(client, scope, false)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "requested scope is not allowed for this client")
		return
	}
	nonce, _ := payload["nonce"].(string)
	p.issueTokenResponse(w, r, client, sub, scope, nonce)
}

func (p *Provider) tokenClientCredentials(w http.ResponseWriter, r *http.Request, client store.Client) {
	if !contains(client.GrantTypes, "client_credentials") {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "client is not allowed to use client_credentials")
		return
	}
	scope, err := allowedScopes(client, r.Form.Get("scope"), true)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "requested scope is not allowed for this client")
		return
	}
	p.issueTokenResponse(w, r, client, "", scope, "")
}

func (p *Provider) tokenRefresh(w http.ResponseWriter, r *http.Request, client store.Client) {
	if !contains(client.GrantTypes, "refresh_token") {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "client is not allowed to use refresh_token")
		return
	}
	payload, err := p.store.GetArtifact(r.Context(), refreshName, r.Form.Get("refresh_token"))
	if err != nil || payload["client_id"] != client.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh_token is invalid")
		return
	}
	sub, _ := payload["sub"].(string)
	scope, _ := payload["scope"].(string)
	scope, err = allowedScopes(client, scope, false)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "refresh token scope is no longer allowed for this client")
		return
	}
	_ = p.store.DeleteArtifact(r.Context(), refreshName, r.Form.Get("refresh_token"))
	p.issueTokenResponse(w, r, client, sub, scope, "")
}

func (p *Provider) tokenExchange(w http.ResponseWriter, r *http.Request, client store.Client) {
	event := store.TokenExchangeEvent{
		ClientID:         client.ClientID,
		SubjectTokenType: firstNonEmpty(r.Form.Get("subject_token_type"), "unknown"),
		RequestedScopes:  parseScopes(r.Form.Get("scope")),
		Success:          false,
	}
	status := http.StatusBadRequest
	errCode := "invalid_request"
	errDesc := "invalid token exchange request"

	defer func() {
		if logErr := p.store.LogTokenExchangeEvent(r.Context(), event); logErr != nil {
			// Audit logging must not change the OAuth response.
			_ = logErr
		}
	}()

	fail := func(code, desc string) {
		errCode = code
		errDesc = desc
		msg := desc
		event.Error = &msg
	}

	if !contains(client.GrantTypes, tokenExchangeGrant) {
		fail("unauthorized_client", "client is not allowed to use token exchange")
		oauthError(w, status, errCode, errDesc)
		return
	}
	if requested := r.Form.Get("requested_token_type"); requested != "" && requested != tokenExchangeIssuedType {
		fail("invalid_request", "requested_token_type is not supported")
		oauthError(w, status, errCode, errDesc)
		return
	}
	if r.Form.Get("subject_token_type") != accessTokenType {
		fail("invalid_request", "subject_token_type must be access_token")
		oauthError(w, status, errCode, errDesc)
		return
	}
	subjectTokenValue := r.Form.Get("subject_token")
	if subjectTokenValue == "" {
		fail("invalid_request", "subject_token is required")
		oauthError(w, status, errCode, errDesc)
		return
	}
	subjectClaims, err := p.VerifyAccessToken(r.Context(), subjectTokenValue)
	if err != nil {
		fail("invalid_grant", "subject_token is invalid")
		oauthError(w, status, "invalid_grant", errDesc)
		return
	}
	if claimString(subjectClaims, "client_id") != client.ClientID {
		fail("invalid_grant", "subject_token was not issued to the authenticated client")
		oauthError(w, status, "invalid_grant", errDesc)
		return
	}

	subject := claimString(subjectClaims, "sub")
	event.Subject = optionalClaim(subject)
	event.SubjectTokenID = optionalClaim(claimString(subjectClaims, "jti"))

	audience, err := resolveTokenExchangeAudience(r.Form)
	if err != nil {
		fail("invalid_request", err.Error())
		oauthError(w, status, errCode, errDesc)
		return
	}
	event.RequestedAudience = &audience

	actorPresent := r.Form.Get("actor_token") != ""
	var actorSubject string
	if r.Form.Get("actor_token") != "" || r.Form.Get("actor_token_type") != "" {
		if r.Form.Get("actor_token") == "" || r.Form.Get("actor_token_type") == "" {
			fail("invalid_request", "actor_token and actor_token_type must be provided together")
			oauthError(w, status, errCode, errDesc)
			return
		}
		if r.Form.Get("actor_token_type") != accessTokenType {
			fail("invalid_request", "actor_token_type must be access_token")
			oauthError(w, status, errCode, errDesc)
			return
		}
		actorClaims, err := p.VerifyAccessToken(r.Context(), r.Form.Get("actor_token"))
		if err != nil {
			fail("invalid_grant", "actor_token is invalid")
			oauthError(w, status, "invalid_grant", errDesc)
			return
		}
		if claimString(actorClaims, "client_id") != client.ClientID {
			fail("invalid_grant", "actor_token was not issued to the authenticated client")
			oauthError(w, status, "invalid_grant", errDesc)
			return
		}
		actorSubject = claimString(actorClaims, "sub")
		event.ActorSubject = optionalClaim(actorSubject)
	}

	policy, err := p.store.FindTokenExchangePolicy(r.Context(), client.ClientID, subject, accessTokenType, audience, actorPresent)
	if err != nil {
		fail("invalid_grant", "token exchange is not permitted for this subject or audience")
		oauthError(w, status, "invalid_grant", errDesc)
		return
	}
	event.PolicyID = &policy.ID

	subjectScopes := parseScopes(claimString(subjectClaims, "scope"))
	requestedScopes := parseScopes(r.Form.Get("scope"))
	if len(requestedScopes) == 0 {
		requestedScopes = subjectScopes
	}
	event.RequestedScopes = requestedScopes
	if !scopeSubset(requestedScopes, subjectScopes) {
		fail("invalid_scope", "requested scope exceeds the rights of the subject_token")
		oauthError(w, status, "invalid_scope", errDesc)
		return
	}
	if !policyAllowsScopes(policy.Scopes, requestedScopes) {
		fail("invalid_scope", "requested scope is not permitted by policy")
		oauthError(w, status, "invalid_scope", errDesc)
		return
	}

	claims := cloneMap(subjectClaims)
	jti := randomID(16)
	now := time.Now()
	claims["iss"] = p.cfg.Issuer
	claims["aud"] = audience
	claims["client_id"] = client.ClientID
	claims["scope"] = strings.Join(requestedScopes, " ")
	claims["jti"] = jti
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(p.cfg.AccessTokenTTL).Unix()
	claims["gty"] = tokenExchangeGrant
	claims["token_exchange"] = map[string]any{
		"subject_token_jti":  claimString(subjectClaims, "jti"),
		"subject_token_type": accessTokenType,
	}
	if actorSubject != "" {
		claims["act"] = map[string]any{"sub": actorSubject}
		if subject != "" && subject != actorSubject {
			claims["may_act"] = map[string]any{"sub": subject}
		}
	}
	accessToken, err := p.signJWT(claims)
	if err != nil {
		status = http.StatusInternalServerError
		fail("server_error", "failed to sign token")
		oauthError(w, status, errCode, errDesc)
		return
	}

	event.Success = true
	event.Error = nil
	event.GrantedAudience = &audience
	event.GrantedScopes = requestedScopes
	event.IssuedTokenID = &jti

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      accessToken,
		"issued_token_type": tokenExchangeIssuedType,
		"token_type":        "Bearer",
		"expires_in":        int(p.cfg.AccessTokenTTL.Seconds()),
		"scope":             strings.Join(requestedScopes, " "),
	})
}

func (p *Provider) issueTokenResponse(w http.ResponseWriter, r *http.Request, client store.Client, sub, scope, nonce string) {
	claims := map[string]any{}
	if sub != "" {
		account, err := p.FetchAccount(r.Context(), sub)
		if err == nil {
			claims = p.BuildClaims(account)
		}
	}
	jti := randomID(16)
	claims["iss"] = p.cfg.Issuer
	claims["aud"] = client.ClientID
	claims["client_id"] = client.ClientID
	claims["scope"] = scope
	claims["jti"] = jti
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(p.cfg.AccessTokenTTL).Unix()
	if sub != "" {
		claims["sub"] = sub
	}
	accessToken, err := p.signJWT(claims)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}
	response := map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": int(p.cfg.AccessTokenTTL.Seconds()), "scope": scope}
	if sub != "" {
		if contains(client.GrantTypes, "refresh_token") && hasScope(scope, "offline_access") {
			refresh := randomID(32)
			_ = p.store.PutArtifact(r.Context(), refreshName, refresh, map[string]any{"client_id": client.ClientID, "sub": sub, "scope": scope}, p.cfg.RefreshTokenTTL)
			response["refresh_token"] = refresh
		}
		if strings.Contains(" "+scope+" ", " openid ") {
			idClaims := cloneMap(claims)
			idClaims["nonce"] = nonce
			idClaims["exp"] = time.Now().Add(p.cfg.IDTokenTTL).Unix()
			idToken, _ := p.signJWT(idClaims)
			response["id_token"] = idToken
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (p *Provider) UserInfo(w http.ResponseWriter, r *http.Request) {
	claims, err := p.VerifyAccessToken(r.Context(), bearer(r))
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_token", "token invalid")
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

func (p *Provider) Introspect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if p.oauth != nil {
		p.ensureBasicAuthFromForm(r)
		session := &fositestore.Session{}
		response, err := p.oauth.NewIntrospectionRequest(r.Context(), r, session)
		if err != nil {
			if p.legacyIntrospect(w, r) {
				return
			}
			p.oauth.WriteIntrospectionError(r.Context(), w, err)
			return
		}
		p.writeCompatibleIntrospectionResponse(w, r, response)
		return
	}
	_ = p.legacyIntrospect(w, r)
}

func (p *Provider) legacyIntrospect(w http.ResponseWriter, r *http.Request) bool {
	client, err := p.authenticateClient(r)
	if err != nil {
		return false
	}
	token := r.Form.Get("token")
	claims, err := p.verifyLegacyAccessToken(r.Context(), token)
	if err != nil {
		if payload, refreshErr := p.store.GetArtifact(r.Context(), refreshName, token); refreshErr == nil && payload["client_id"] == client.ClientID {
			writeJSON(w, http.StatusOK, map[string]any{
				"active":     true,
				"token_type": "refresh_token",
				"client_id":  client.ClientID,
				"sub":        payload["sub"],
				"scope":      payload["scope"],
			})
			return true
		}
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return true
	}
	if claimString(claims, "client_id") != "" && claimString(claims, "client_id") != client.ClientID {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return true
	}
	claims["active"] = true
	writeJSON(w, http.StatusOK, claims)
	return true
}

func (p *Provider) Revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if p.oauth != nil {
		client, _ := p.authenticateClient(r)
		err := p.oauth.NewRevocationRequest(r.Context(), r)
		if err == nil {
			p.revokeLegacyJWTIfOwned(r.Context(), r.Form.Get("token"), client)
		}
		p.oauth.WriteRevocationResponse(r.Context(), w, err)
		return
	}
	client, err := p.authenticateClient(r)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	token := r.Form.Get("token")
	if claims, err := p.VerifyAccessToken(r.Context(), token); err == nil {
		if jti, _ := claims["jti"].(string); jti != "" {
			_ = p.store.PutArtifact(r.Context(), revokedName, jti, map[string]any{"revoked": true}, p.cfg.RefreshTokenTTL)
		}
	} else if payload, refreshErr := p.store.GetArtifact(r.Context(), refreshName, token); refreshErr == nil && payload["client_id"] == client.ClientID {
		_ = p.store.DeleteArtifact(r.Context(), refreshName, token)
	}
	w.WriteHeader(http.StatusOK)
}

func (p *Provider) Logout(w http.ResponseWriter, r *http.Request) {
	if sid, ok := p.readSession(r); ok {
		_ = p.store.DeleteArtifact(r.Context(), sessionName, sid)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	redirect := r.FormValue("post_logout_redirect_uri")
	if redirect == "" {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (p *Provider) VerifyAccessToken(ctx context.Context, token string) (map[string]any, error) {
	claims, err := p.verifyJWT(token)
	if err != nil {
		return nil, err
	}
	if exp, ok := claims["exp"].(float64); ok && int64(exp) < time.Now().Unix() {
		return nil, errors.New("expired")
	}
	if jti, _ := claims["jti"].(string); jti != "" {
		if _, err := p.store.GetArtifact(ctx, revokedName, jti); err == nil {
			return nil, errors.New("revoked")
		}
	}
	if p.oauth != nil && claimString(claims, "gty") != tokenExchangeGrant && hasArrayAudience(claims) {
		if _, _, err := p.oauth.IntrospectToken(ctx, token, fosite.AccessToken, &fositestore.Session{}); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

func (p *Provider) verifyLegacyAccessToken(ctx context.Context, token string) (map[string]any, error) {
	claims, err := p.verifyJWT(token)
	if err != nil {
		return nil, err
	}
	if exp, ok := claims["exp"].(float64); ok && int64(exp) < time.Now().Unix() {
		return nil, errors.New("expired")
	}
	if jti, _ := claims["jti"].(string); jti != "" {
		if _, err := p.store.GetArtifact(ctx, revokedName, jti); err == nil {
			return nil, errors.New("revoked")
		}
	}
	return claims, nil
}

func (p *Provider) revokeLegacyJWTIfOwned(ctx context.Context, token string, client store.Client) {
	if client.ClientID == "" {
		return
	}
	claims, err := p.verifyJWT(token)
	if err != nil {
		return
	}
	if claimString(claims, "client_id") != "" && claimString(claims, "client_id") != client.ClientID {
		return
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return
	}
	_ = p.store.PutArtifact(ctx, revokedName, jti, map[string]any{"revoked": true}, p.cfg.RefreshTokenTTL)
}

func (p *Provider) FetchAccount(ctx context.Context, userID string) (Account, error) {
	user, err := p.wd.Users.Get(ctx, userID, nil)
	if err != nil || user["success"] != true {
		return Account{}, errors.New("wildduck user not found")
	}
	return Account{
		ID:           str(user["id"]),
		Email:        str(user["address"]),
		Username:     str(user["username"]),
		Name:         str(user["name"]),
		Activated:    boolv(user["activated"]),
		Suspended:    boolv(user["suspended"]),
		Disabled:     boolv(user["disabled"]),
		MetaData:     mapv(user["metaData"]),
		InternalData: mapv(user["internalData"]),
	}, nil
}

func (p *Provider) BuildClaims(account Account) map[string]any {
	claims := map[string]any{
		"sub":                account.ID,
		"email":              account.Email,
		"email_verified":     account.Activated && !account.Suspended && !account.Disabled,
		"preferred_username": firstNonEmpty(account.Username, account.Email),
	}
	if account.Name != "" {
		claims["name"] = account.Name
	}
	if cid, _ := account.InternalData["cid"].(string); cid != "" {
		claims["customer_id"] = cid
	}
	if roles, ok := account.InternalData["roles"]; ok {
		claims["roles"] = roles
	}
	if role, ok := account.InternalData["role"]; ok {
		claims["roles"] = []any{role}
	}
	if permissions, ok := account.InternalData["permissions"]; ok {
		claims["permissions"] = permissions
	}
	if idpMeta := mapv(account.MetaData["idp"]); len(idpMeta) > 0 {
		if branding, ok := idpMeta["branding"]; ok {
			claims["branding"] = branding
		}
	}
	return claims
}

func (p *Provider) newFositeSession(ctx context.Context, sub, clientID, nonce string) *fositestore.Session {
	now := time.Now().UTC()
	claims := map[string]any{}
	if sub != "" {
		if account, err := p.FetchAccount(ctx, sub); err == nil {
			claims = p.BuildClaims(account)
		} else {
			claims["sub"] = sub
		}
	}
	claims["client_id"] = clientID

	session := fositestore.NewSession(sub, fositestore.MuninClaims{
		Email:         claimString(claims, "email"),
		EmailVerified: boolClaim(claims, "email_verified"),
		CustomerID:    claimString(claims, "customer_id"),
		Roles:         stringsFromClaim(claims["roles"]),
		Raw:           cloneMap(claims),
	})
	session.JWTHeader = jwt.NewHeaders()
	session.JWTHeader.Add("kid", p.keyID)
	session.IDHeader = jwt.NewHeaders()
	session.IDHeader.Add("kid", p.keyID)
	session.JWTClaims = &jwt.JWTClaims{
		Subject: sub,
		Extra:   cloneMap(claims),
	}
	session.IDClaims = &jwt.IDTokenClaims{
		Subject:     sub,
		Nonce:       nonce,
		RequestedAt: now,
		AuthTime:    now,
		Extra:       cloneMap(claims),
	}
	session.Extra = cloneMap(claims)
	return session
}

func (p *Provider) populateClientTokenSession(session *fositestore.Session, clientID string) {
	claims := map[string]any{"client_id": clientID}
	session.Subject = ""
	session.Username = clientID
	session.Munin.Raw = claims
	session.Extra = cloneMap(claims)
	session.JWTClaims = &jwt.JWTClaims{Extra: cloneMap(claims)}
	if session.JWTHeader == nil {
		session.JWTHeader = jwt.NewHeaders()
	}
	session.JWTHeader.Add("kid", p.keyID)
}

func (p *Provider) normalizeClientCredentialsScope(r *http.Request) {
	if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != "" {
		return
	}
	client, err := p.authenticateClient(r)
	if err != nil || len(client.Scopes) == 0 {
		return
	}
	r.Form.Set("scope", strings.Join(client.Scopes, " "))
	r.PostForm.Set("scope", strings.Join(client.Scopes, " "))
}

func (p *Provider) ensureBasicAuthFromForm(r *http.Request) {
	if _, _, ok := r.BasicAuth(); ok {
		return
	}
	if r.Form.Get("client_id") == "" || r.Form.Get("client_secret") == "" {
		return
	}
	r.SetBasicAuth(r.Form.Get("client_id"), r.Form.Get("client_secret"))
}

func (p *Provider) writeCompatibleAccessResponse(w http.ResponseWriter, response fosite.AccessResponder) {
	payload := response.ToMap()
	if tokenType, _ := payload["token_type"].(string); strings.EqualFold(tokenType, "bearer") {
		payload["token_type"] = "Bearer"
	}
	writeJSON(w, http.StatusOK, payload)
}

func (p *Provider) writeCompatibleIntrospectionResponse(w http.ResponseWriter, r *http.Request, response fosite.IntrospectionResponder) {
	if !response.IsActive() {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	payload := map[string]any{"active": true}
	if claims, err := p.verifyJWT(r.Form.Get("token")); err == nil {
		for key, value := range claims {
			payload[key] = value
		}
	}

	requester := response.GetAccessRequester()
	if requester == nil {
		writeJSON(w, http.StatusOK, payload)
		return
	}
	if clientID := requester.GetClient().GetID(); clientID != "" {
		payload["client_id"] = clientID
	}
	if scopes := requester.GetGrantedScopes(); len(scopes) > 0 {
		payload["scope"] = strings.Join(scopes, " ")
	}
	if requestedAt := requester.GetRequestedAt(); !requestedAt.IsZero() {
		payload["iat"] = requestedAt.Unix()
	}
	if sub := requester.GetSession().GetSubject(); sub != "" {
		payload["sub"] = sub
	}
	if aud := requester.GetGrantedAudience(); len(aud) > 0 {
		payload["aud"] = []string(aud)
	}
	if username := requester.GetSession().GetUsername(); username != "" {
		payload["username"] = username
	}
	if response.GetTokenUse() == fosite.RefreshToken {
		payload["token_type"] = "refresh_token"
		if exp := requester.GetSession().GetExpiresAt(fosite.RefreshToken); !exp.IsZero() {
			payload["exp"] = exp.Unix()
		}
	} else {
		payload["token_type"] = "Bearer"
		if exp := requester.GetSession().GetExpiresAt(fosite.AccessToken); !exp.IsZero() {
			payload["exp"] = exp.Unix()
		}
	}
	if extraSession, ok := requester.GetSession().(fosite.ExtraClaimsSession); ok {
		for key, value := range extraSession.GetExtraClaims() {
			if _, exists := payload[key]; !exists {
				payload[key] = value
			}
		}
	}
	writeJSON(w, http.StatusOK, payload)
}

func (p *Provider) EncryptSecret(value string) (string, error) {
	return p.secrets.Encrypt(value)
}

func (p *Provider) authenticateClient(r *http.Request) (store.Client, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}
	client, err := p.store.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		return store.Client{}, err
	}
	plain, err := p.secrets.Decrypt(client.ClientSecret)
	if err != nil {
		return store.Client{}, err
	}
	if !hmac.Equal([]byte(plain), []byte(clientSecret)) {
		return store.Client{}, errors.New("bad secret")
	}
	return client, nil
}

func (p *Provider) signedCookie(name, value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{Name: name, Value: value + "." + p.sign(value), Path: "/", MaxAge: int(ttl.Seconds()), HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

func (p *Provider) readSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(p.sign(parts[0]))) {
		return "", false
	}
	return parts[0], true
}

func (p *Provider) sign(value string) string {
	mac := hmac.New(sha256.New, []byte(p.cfg.CookieKeys[0]))
	mac.Write([]byte(value))
	return b64(mac.Sum(nil))
}

func (p *Provider) signJWT(claims map[string]any) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": p.keyID}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := b64(hb) + "." + b64(cb)
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
}

func (p *Provider) verifyJWT(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if err := rsa.VerifyPKCS1v15(&p.key.PublicKey, crypto.SHA256, hash[:], sig); err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	return claims, json.Unmarshal(payload, &claims)
}

func verifyPKCE(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return hmac.Equal([]byte(challenge), []byte(b64(sum[:])))
}

func randomID(size int) string {
	b := make([]byte, size)
	_, _ = rand.Read(b)
	return b64(b)
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func keyIDForPublicPEM(publicPEM []byte) string {
	sum := sha256.Sum256(publicPEM)
	encoded := hex.EncodeToString(sum[:])
	return encoded[len(encoded)-8:]
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]any{"error": code, "error_description": desc})
}

func redirectError(w http.ResponseWriter, redirectURI, state, code, desc string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}

func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func resolveTokenExchangeAudience(values url.Values) (string, error) {
	candidates := values["audience"]
	if len(candidates) == 0 {
		candidates = values["resource"]
	}
	normalized := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" {
			normalized = append(normalized, candidate)
		}
	}
	if len(normalized) == 0 {
		return "", errors.New("audience parameter is required for token exchange")
	}
	if len(normalized) > 1 {
		return "", errors.New("multiple audience/resource values are not supported")
	}
	return normalized[0], nil
}

func parseScopes(value string) []string {
	fields := strings.Fields(value)
	seen := map[string]struct{}{}
	scopes := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if _, ok := seen[field]; ok {
			continue
		}
		seen[field] = struct{}{}
		scopes = append(scopes, field)
	}
	return scopes
}

func allowedScopes(client store.Client, requested string, defaultAll bool) (string, error) {
	requestedScopes := parseScopes(requested)
	if len(requestedScopes) == 0 {
		if defaultAll {
			return strings.Join(client.Scopes, " "), nil
		}
		return "", nil
	}
	if !scopeSubset(requestedScopes, client.Scopes) {
		return "", errors.New("scope not allowed")
	}
	return strings.Join(requestedScopes, " "), nil
}

func hasScope(value, scope string) bool {
	for _, item := range parseScopes(value) {
		if item == scope {
			return true
		}
	}
	return false
}

func scopeSubset(requested, available []string) bool {
	if len(requested) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(available))
	for _, scope := range available {
		set[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := set[scope]; !ok {
			return false
		}
	}
	return true
}

func (p *Provider) trustedFirstPartyClient(client store.Client) bool {
	for _, raw := range append(append([]string{}, client.RedirectURIs...), client.PostLogoutRedirectURIs...) {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if p.trustedFirstPartyHost(u.Hostname()) {
			return true
		}
	}
	return false
}

func (p *Provider) trustedFirstPartyHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, domain := range p.cfg.TrustedConsentDomains {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		if domain == "" {
			continue
		}
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func valuesFromInteraction(artifact map[string]any) url.Values {
	q := url.Values{}
	for _, key := range []string{"client_id", "redirect_uri", "scope", "state", "nonce", "prompt", "code_challenge", "code_challenge_method", "audience"} {
		if value := str(artifact[key]); value != "" {
			q.Set(key, value)
		}
	}
	q.Set("response_type", "code")
	return q
}

func uniqueStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func policyAllowsScopes(policyScopes, requested []string) bool {
	if len(policyScopes) == 0 {
		return true
	}
	for _, scope := range policyScopes {
		if scope == "*" {
			return true
		}
	}
	return scopeSubset(requested, policyScopes)
}

func claimString(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

func boolClaim(claims map[string]any, name string) bool {
	value, _ := claims[name].(bool)
	return value
}

func stringsFromClaim(value any) []string {
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
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

func hasArrayAudience(claims map[string]any) bool {
	switch claims["aud"].(type) {
	case []any, []string:
		return true
	default:
		return false
	}
}

func optionalClaim(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
func cloneMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}
func str(v any) string { s, _ := v.(string); return s }
func boolv(v any) bool { b, _ := v.(bool); return b }
func mapv(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
