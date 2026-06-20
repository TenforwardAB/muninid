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
 * This file :: internal/fositestore/session.go is part of the MuninID project.
 */

package fositestore

import (
	"time"

	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

type MuninClaims struct {
	Email         string         `json:"email,omitempty"`
	EmailVerified bool           `json:"email_verified,omitempty"`
	CustomerID    string         `json:"customer_id,omitempty"`
	Roles         []string       `json:"roles,omitempty"`
	Groups        []string       `json:"groups,omitempty"`
	Raw           map[string]any `json:"raw,omitempty"`
}

type Session struct {
	JWTClaims *jwt.JWTClaims `json:"jwt_claims,omitempty"`
	JWTHeader *jwt.Headers   `json:"jwt_header,omitempty"`

	IDClaims *jwt.IDTokenClaims `json:"id_token_claims,omitempty"`
	IDHeader *jwt.Headers       `json:"id_token_header,omitempty"`

	ExpiresAt map[fosite.TokenType]time.Time `json:"expires_at,omitempty"`
	Username  string                         `json:"username,omitempty"`
	Subject   string                         `json:"subject,omitempty"`

	Munin MuninClaims    `json:"muninid,omitempty"`
	Extra map[string]any `json:"extra,omitempty"`
}

func NewSession(subject string, claims MuninClaims) *Session {
	now := time.Now().UTC()
	return &Session{
		JWTClaims: &jwt.JWTClaims{},
		JWTHeader: &jwt.Headers{},
		IDClaims:  &jwt.IDTokenClaims{Subject: subject, RequestedAt: now, AuthTime: now},
		IDHeader:  &jwt.Headers{},
		Subject:   subject,
		Username:  claims.Email,
		Munin:     claims,
	}
}

func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTClaims == nil {
		s.JWTClaims = &jwt.JWTClaims{}
	}
	return s.JWTClaims
}

func (s *Session) GetJWTHeader() *jwt.Headers {
	if s.JWTHeader == nil {
		s.JWTHeader = &jwt.Headers{}
	}
	return s.JWTHeader
}

func (s *Session) IDTokenClaims() *jwt.IDTokenClaims {
	if s.IDClaims == nil {
		now := time.Now().UTC()
		s.IDClaims = &jwt.IDTokenClaims{RequestedAt: now, AuthTime: now}
	}
	if s.IDClaims.Subject == "" {
		s.IDClaims.Subject = s.Subject
	}
	if s.IDClaims.AuthTime.IsZero() {
		s.IDClaims.AuthTime = s.IDClaims.RequestedAt
	}
	return s.IDClaims
}

func (s *Session) IDTokenHeaders() *jwt.Headers {
	if s.IDHeader == nil {
		s.IDHeader = &jwt.Headers{}
	}
	return s.IDHeader
}

func (s *Session) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}
	s.ExpiresAt[key] = exp
}

func (s *Session) GetExpiresAt(key fosite.TokenType) time.Time {
	if s == nil || s.ExpiresAt == nil {
		return time.Time{}
	}
	return s.ExpiresAt[key]
}

func (s *Session) GetUsername() string {
	if s == nil {
		return ""
	}
	return s.Username
}

func (s *Session) GetSubject() string {
	if s == nil {
		return ""
	}
	return s.Subject
}

func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	return deepcopy.Copy(s).(fosite.Session)
}

func (s *Session) GetExtraClaims() map[string]any {
	if s == nil {
		return nil
	}
	if s.Extra == nil {
		s.Extra = make(map[string]any)
	}
	if s.Munin.Email != "" {
		s.Extra["email"] = s.Munin.Email
	}
	if s.Munin.EmailVerified {
		s.Extra["email_verified"] = true
	}
	if s.Munin.CustomerID != "" {
		s.Extra["customer_id"] = s.Munin.CustomerID
	}
	if len(s.Munin.Roles) > 0 {
		s.Extra["roles"] = append([]string(nil), s.Munin.Roles...)
	}
	if len(s.Munin.Groups) > 0 {
		s.Extra["groups"] = append([]string(nil), s.Munin.Groups...)
	}
	for k, v := range s.Munin.Raw {
		if _, exists := s.Extra[k]; !exists {
			s.Extra[k] = v
		}
	}
	return s.Extra
}

var _ fosite.Session = (*Session)(nil)
var _ fosite.ExtraClaimsSession = (*Session)(nil)
