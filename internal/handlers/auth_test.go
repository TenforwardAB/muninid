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
 * This file :: internal/handlers/auth_test.go is part of the MuninID project.
 */

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/tenforwardab/muninid/internal/idp"
)

// fakeAuthProvider records the interaction calls made by the handlers so the
// HTTP-level behaviour can be asserted without a real provider/store/WildDuck.
type fakeAuthProvider struct {
	finishSession   string
	finishErr       error
	completeSession string
	completeErr     error

	completeArgs []string // uid, current, new (nil until CompletePasswordChange is called)
	redirected   string   // sessionID handed to RedirectAfterLogin (empty until called)
}

func (f *fakeAuthProvider) InteractionView(_ *http.Request, uid, errorText string) (idp.InteractionView, error) {
	return idp.InteractionView{UID: uid, Mode: "login", Error: errorText}, nil
}

func (f *fakeAuthProvider) PasswordChangeView(_ *http.Request, uid, errorText string) (idp.InteractionView, error) {
	return idp.InteractionView{UID: uid, Mode: "password", Error: errorText}, nil
}

func (f *fakeAuthProvider) FinishLogin(context.Context, string, string, string, string, string) (string, error) {
	return f.finishSession, f.finishErr
}

func (f *fakeAuthProvider) CompletePasswordChange(_ context.Context, uid, next string) (string, error) {
	f.completeArgs = []string{uid, next}
	return f.completeSession, f.completeErr
}

func (f *fakeAuthProvider) RedirectAfterLogin(w http.ResponseWriter, _ *http.Request, _, sessionID string) {
	f.redirected = sessionID
	w.WriteHeader(http.StatusSeeOther)
}

func (f *fakeAuthProvider) AbortInteraction(http.ResponseWriter, *http.Request, string) {}
func (f *fakeAuthProvider) ConfirmConsent(http.ResponseWriter, *http.Request, string)  {}

func newAuthRouter(p authProvider) http.Handler {
	h := NewAuth(p)
	r := chi.NewRouter()
	r.Post("/interaction/{uid}/login", h.Login)
	r.Post("/interaction/{uid}/password", h.ChangePassword)
	return r
}

func postForm(t *testing.T, router http.Handler, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestLoginRequiresPasswordChange(t *testing.T) {
	p := &fakeAuthProvider{finishErr: idp.ErrPasswordChangeRequired}
	rec := postForm(t, newAuthRouter(p), "/interaction/u1/login", url.Values{
		"username": {"user@example.com"},
		"password": {"current-secret"},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Update your password") {
		t.Fatalf("body did not render the password-change form:\n%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `id="pw-meter"`) {
		t.Fatalf("body is missing the password strength meter:\n%s", rec.Body.String())
	}
	if p.redirected != "" {
		t.Fatalf("must not redirect before the password is changed (got %q)", p.redirected)
	}
}

func TestChangePassword(t *testing.T) {
	const good = "New-Strong-Pass1"

	t.Run("mismatch is rejected without calling the provider", func(t *testing.T) {
		p := &fakeAuthProvider{}
		rec := postForm(t, newAuthRouter(p), "/interaction/u1/password", url.Values{
			"new_password":     {good},
			"confirm_password": {"different"},
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", rec.Code)
		}
		if p.completeArgs != nil {
			t.Fatalf("provider was called despite mismatch: %v", p.completeArgs)
		}
		if !strings.Contains(rec.Body.String(), "Passwords do not match.") {
			t.Fatalf("error message not shown:\n%s", rec.Body.String())
		}
	})

	t.Run("policy violation is rejected without calling the provider", func(t *testing.T) {
		p := &fakeAuthProvider{}
		rec := postForm(t, newAuthRouter(p), "/interaction/u1/password", url.Values{
			"new_password":     {"short"},
			"confirm_password": {"short"},
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", rec.Code)
		}
		if p.completeArgs != nil {
			t.Fatalf("provider was called despite weak password: %v", p.completeArgs)
		}
	})

	t.Run("success changes password and resumes the flow", func(t *testing.T) {
		p := &fakeAuthProvider{completeSession: "sess-123"}
		rec := postForm(t, newAuthRouter(p), "/interaction/u1/password", url.Values{
			"new_password":     {good},
			"confirm_password": {good},
		})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("code = %d, want 303", rec.Code)
		}
		if want := []string{"u1", good}; !equalStrings(p.completeArgs, want) {
			t.Fatalf("CompletePasswordChange args = %v, want %v", p.completeArgs, want)
		}
		if p.redirected != "sess-123" {
			t.Fatalf("redirected session = %q, want sess-123", p.redirected)
		}
	})

	t.Run("provider failure re-renders the form", func(t *testing.T) {
		p := &fakeAuthProvider{completeErr: errors.New("weak password")}
		rec := postForm(t, newAuthRouter(p), "/interaction/u1/password", url.Values{
			"new_password":     {good},
			"confirm_password": {good},
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", rec.Code)
		}
		if p.redirected != "" {
			t.Fatalf("must not redirect when the change failed (got %q)", p.redirected)
		}
		if !strings.Contains(rec.Body.String(), "Could not change password") {
			t.Fatalf("error message not shown:\n%s", rec.Body.String())
		}
	})
}

func TestPasswordPolicyError(t *testing.T) {
	for _, tc := range []struct {
		name string
		pw   string
		ok   bool
	}{
		{"valid", "New-Strong-Pass1", true},
		{"too short", "Ab1!xyz", false},
		{"no uppercase", "lower-case1!", false},
		{"no digit", "NoDigitsHere!", false},
		{"no special", "NoSpecial1Abc", false},
		{"exactly ten valid", "Abcdefg1!x", true},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := passwordPolicyError(tc.pw)
			if tc.ok && msg != "" {
				t.Fatalf("passwordPolicyError(%q) = %q, want accepted", tc.pw, msg)
			}
			if !tc.ok && msg == "" {
				t.Fatalf("passwordPolicyError(%q) = accepted, want rejected", tc.pw)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
