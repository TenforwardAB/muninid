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
 * This file :: internal/app/app.go is part of the MuninID project.
 */

package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	wildduck "github.com/tenforwardab/wildduck-gosdk"

	"github.com/tenforwardab/muninid/internal/authz"
	"github.com/tenforwardab/muninid/internal/config"
	"github.com/tenforwardab/muninid/internal/fositestore"
	"github.com/tenforwardab/muninid/internal/handlers"
	"github.com/tenforwardab/muninid/internal/idp"
	"github.com/tenforwardab/muninid/internal/kv"
	"github.com/tenforwardab/muninid/internal/secret"
	"github.com/tenforwardab/muninid/internal/store"
)

type App struct {
	cfg   config.Config
	db    *pgxpool.Pool
	kv    *kv.Client
	idp   *idp.Provider
	store *store.Store
	authz authz.Authorizer
}

func New(ctx context.Context, cfg config.Config) (*App, error) {
	db, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, err
	}

	cache, err := kv.New(cfg.ValkeyURL)
	if err != nil {
		db.Close()
		return nil, err
	}
	if err := cache.Ping(ctx); err != nil {
		_ = cache.Close()
		db.Close()
		return nil, err
	}

	st := store.New(db, cache)
	fst := fositestore.New(db, cache, secret.New(cfg.SecretKey), cfg.RefreshTokenTTL)
	wd := wildduck.New(cfg.WildDuckToken, cfg.WildDuckURL)
	provider, err := idp.New(ctx, cfg, st, fst, wd)
	if err != nil {
		_ = cache.Close()
		db.Close()
		return nil, err
	}

	authorizer, err := authz.New(authz.Config{
		Backend:    cfg.AuthzBackend,
		AdminRoles: cfg.AuthzAdminRoles,
		Solutrix: authz.SolutrixConfig{
			BaseURL:      cfg.SolutrixAPIBaseURL,
			TokenURL:     cfg.SolutrixTokenURL,
			ClientID:     cfg.SolutrixClientID,
			ClientSecret: cfg.SolutrixClientSecret,
			Scope:        cfg.SolutrixScope,
			CacheTTL:     cfg.AuthzCacheTTL,
		},
	})
	if err != nil {
		_ = cache.Close()
		db.Close()
		return nil, err
	}

	return &App{cfg: cfg, db: db, kv: cache, idp: provider, store: st, authz: authorizer}, nil
}

func (a *App) Close() {
	if a.kv != nil {
		_ = a.kv.Close()
	}
	if a.db != nil {
		a.db.Close()
	}
}

func (a *App) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   a.cfg.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Admin-Api-Key"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	auth := handlers.NewAuth(a.idp)
	admin := handlers.NewAdmin(a.idp, a.store, a.authz)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	r.Get("/docs.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, handlers.OpenAPI(a.cfg.Issuer))
	})

	r.Get("/.well-known/openid-configuration", a.idp.Discovery)
	r.Get("/oauth/jwks.json", a.idp.JWKS)
	r.Get("/oauth/authorize", a.idp.Authorize)
	r.Post("/oauth/token", a.idp.Token)
	r.Post("/oauth/introspect", a.idp.Introspect)
	r.Post("/oauth/revoke", a.idp.Revoke)
	r.Get("/oauth/logout", a.idp.Logout)
	r.Post("/oauth/logout", a.idp.Logout)
	r.Get("/userinfo", a.idp.UserInfo)

	r.Route("/interaction", func(r chi.Router) {
		r.Get("/{uid}", auth.ShowInteraction)
		r.Post("/{uid}/login", auth.Login)
		r.Post("/{uid}/password", auth.ChangePassword)
		r.Get("/{uid}/abort", auth.Abort)
		r.Post("/{uid}/abort", auth.Abort)
		r.Post("/{uid}/confirm", auth.Confirm)
	})

	r.Route("/api/global/admin", func(r chi.Router) {
		r.Use(a.requireAdminAPIKey)
		admin.GlobalRoutes(r)
	})
	r.Route("/api/admin", func(r chi.Router) {
		r.Use(a.requireBearerAdmin)
		admin.TenantRoutes(r)
	})
	r.Route("/api/self", func(r chi.Router) {
		r.Use(a.requireIdentity)
		admin.SelfClientRoutes(r)
	})

	if a.cfg.EnableGUI {
		r.Route("/gui/api", func(r chi.Router) {
			r.Use(a.requireMasterPassword)
			admin.GlobalRoutes(r)
		})
		r.With(a.requireMasterPassword).Get("/gui", handlers.AdminGUI(a.cfg.MasterUser))
	}

	return r
}

func (a *App) requireAdminAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.AdminAPIKey == "" || r.Header.Get("X-Admin-Api-Key") != a.cfg.AdminAPIKey {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin_api_key_required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) requireBearerAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer_token_required"})
			return
		}
		claims, err := a.idp.VerifyAccessToken(r.Context(), token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		roles, _ := claims["roles"].([]any)
		ok := false
		for _, role := range roles {
			if role == "idp_admin" || role == "admin" || role == "superadmin" {
				ok = true
				break
			}
		}
		if !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_role"})
			return
		}
		next.ServeHTTP(w, r.WithContext(handlers.WithAdminClaims(r.Context(), claims)))
	})
}

// requireIdentity verifies the bearer token and stores the resolved subject in
// context for self-service routes. Unlike requireBearerAdmin it does not require
// a privileged role; authorization is delegated to the Authorizer per request.
func (a *App) requireIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer_token_required"})
			return
		}
		claims, err := a.idp.VerifyAccessToken(r.Context(), token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		next.ServeHTTP(w, r.WithContext(handlers.WithSubject(r.Context(), authz.SubjectFromClaims(claims))))
	})
}

func (a *App) requireMasterPassword(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.MasterUser == "" || a.cfg.MasterPass == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "master_credentials_not_configured"})
			return
		}
		user, pass, ok := basicAuthSecret(r.Header.Get("Authorization"))
		if !ok || !secureEqual(user, a.cfg.MasterUser) || !secureEqual(pass, a.cfg.MasterPass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="idp-gui"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func secureEqual(left, right string) bool {
	leftSum := sha256.Sum256([]byte(left))
	rightSum := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftSum[:], rightSum[:]) == 1
}

func basicAuthSecret(header string) (string, string, bool) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
