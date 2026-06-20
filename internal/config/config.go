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
 * This file :: internal/config/config.go is part of the MuninID project.
 */

package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	Host string
	Port string

	Issuer        string
	CORSOrigins   []string
	CookieKeys    []string
	AdminAPIKey   string
	SecretKey     string
	EnableGUI     bool
	MasterUser    string
	MasterPass    string
	DatabaseURL   string
	ValkeyURL     string
	WildDuckURL   string
	WildDuckToken string

	TrustedConsentDomains []string
	AccessTokenTTL        time.Duration
	IDTokenTTL            time.Duration
	CodeTTL               time.Duration
	RefreshTokenTTL       time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Host:                  env("HOST", "0.0.0.0"),
		Port:                  env("PORT", "8080"),
		Issuer:                os.Getenv("OIDC_ISSUER"),
		AdminAPIKey:           os.Getenv("ADMIN_API_KEY"),
		SecretKey:             os.Getenv("IDP_SECRET_ENCRYPTION_KEY"),
		EnableGUI:             strings.EqualFold(env("ENABLE_GUI", "false"), "true"),
		MasterUser:            env("MASTER_USER", "idp_admin"),
		MasterPass:            os.Getenv("MASTER_PASSWORD"),
		DatabaseURL:           firstEnv("DATABASE_URL", "DB_URL", "POSTGRES_URL"),
		ValkeyURL:             firstEnv("VALKEY_URL", "REDIS_URL"),
		WildDuckURL:           firstEnv("WILDDUCK_API_URL", "WILDDUCK_URL"),
		WildDuckToken:         firstEnv("WILDDUCK_API_TOKEN", "WILDDUCK_API_KEY"),
		TrustedConsentDomains: splitCSV(env("OIDC_TRUSTED_CONSENT_DOMAINS", "muninid.local,mailtrix.eu")),
		AccessTokenTTL:        10 * time.Minute,
		IDTokenTTL:            10 * time.Minute,
		CodeTTL:               5 * time.Minute,
		RefreshTokenTTL:       30 * 24 * time.Hour,
	}
	cfg.CORSOrigins = splitCSV(os.Getenv("CORS_ORIGINS"))
	cfg.CookieKeys = splitCSV(os.Getenv("OIDC_COOKIE_KEYS"))
	if cfg.Issuer == "" {
		cfg.Issuer = fmt.Sprintf("http://localhost:%s", cfg.Port)
	}
	if len(cfg.CookieKeys) < 1 {
		return cfg, errors.New("OIDC_COOKIE_KEYS must contain at least one secret")
	}
	if len(cfg.CookieKeys[0]) < 32 {
		return cfg, errors.New("first OIDC_COOKIE_KEYS secret must be 32+ chars")
	}
	if cfg.DatabaseURL == "" {
		return cfg, errors.New("DATABASE_URL is required")
	}
	if cfg.ValkeyURL == "" {
		return cfg, errors.New("VALKEY_URL is required")
	}
	if len(cfg.SecretKey) < 32 {
		return cfg, errors.New("IDP_SECRET_ENCRYPTION_KEY must be 32+ characters")
	}
	if cfg.WildDuckURL == "" || cfg.WildDuckToken == "" {
		return cfg, errors.New("WILDDUCK_API_URL and WILDDUCK_API_TOKEN are required")
	}
	return cfg, nil
}

func (c Config) HTTPAddr() string {
	return c.Host + ":" + c.Port
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
