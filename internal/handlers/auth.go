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
 * This file :: internal/handlers/auth.go is part of the MuninID project.
 */

package handlers

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/tenforwardab/muninid/internal/idp"
)

type authProvider interface {
	InteractionView(r *http.Request, uid, errorText string) (idp.InteractionView, error)
	PasswordChangeView(r *http.Request, uid, errorText string) (idp.InteractionView, error)
	FinishLogin(ctx context.Context, uid, username, password, ip, userAgent string) (string, error)
	CompletePasswordChange(ctx context.Context, uid, newPassword string) (string, error)
	RedirectAfterLogin(w http.ResponseWriter, r *http.Request, uid, sessionID string)
	AbortInteraction(w http.ResponseWriter, r *http.Request, uid string)
	ConfirmConsent(w http.ResponseWriter, r *http.Request, uid string)
}

type Auth struct {
	idp authProvider
}

func NewAuth(provider authProvider) *Auth {
	return &Auth{idp: provider}
}

func (h *Auth) ShowInteraction(w http.ResponseWriter, r *http.Request) {
	uid := chi.URLParam(r, "uid")
	view, err := h.idp.InteractionView(r, uid, r.URL.Query().Get("error"))
	if err != nil {
		http.Error(w, "interaction not found", http.StatusBadRequest)
		return
	}
	page.Execute(w, view)
}

func (h *Auth) Login(w http.ResponseWriter, r *http.Request) {
	uid := chi.URLParam(r, "uid")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	sessionID, err := h.idp.FinishLogin(r.Context(), uid, r.Form.Get("username"), r.Form.Get("password"), r.RemoteAddr, r.UserAgent())
	if errors.Is(err, idp.ErrPasswordChangeRequired) {
		view, viewErr := h.idp.PasswordChangeView(r, uid, "")
		if viewErr != nil {
			http.Error(w, "interaction not found", http.StatusBadRequest)
			return
		}
		page.Execute(w, view)
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		view, viewErr := h.idp.InteractionView(r, uid, "Invalid username or password.")
		if viewErr != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		page.Execute(w, view)
		return
	}
	h.idp.RedirectAfterLogin(w, r, uid, sessionID)
}

// ChangePassword completes a forced password change started during login
func (h *Auth) ChangePassword(w http.ResponseWriter, r *http.Request) {
	uid := chi.URLParam(r, "uid")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	render := func(msg string) {
		view, err := h.idp.PasswordChangeView(r, uid, msg)
		if err != nil {
			http.Error(w, "interaction not found", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		page.Execute(w, view)
	}

	next := r.Form.Get("new_password")
	if next != r.Form.Get("confirm_password") {
		render("Passwords do not match.")
		return
	}
	if msg := passwordPolicyError(next); msg != "" {
		render(msg)
		return
	}

	sessionID, err := h.idp.CompletePasswordChange(r.Context(), uid, next)
	if err != nil {
		render("Could not change password. Choose a different password and try again.")
		return
	}
	h.idp.RedirectAfterLogin(w, r, uid, sessionID)
}

// passwordPolicyError checks a new password against the minimum policy (at least
// 10 characters with an upper-case letter, a digit, and a special character)
func passwordPolicyError(pw string) string {
	var hasUpper, hasDigit, hasSpecial bool
	for _, c := range pw {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsDigit(c):
			hasDigit = true
		case unicode.IsLetter(c), unicode.IsSpace(c):
			// lower-case letters and whitespace satisfy no specific requirement
		default:
			hasSpecial = true
		}
	}
	if utf8.RuneCountInString(pw) < 10 || !hasUpper || !hasDigit || !hasSpecial {
		return "Password must be at least 10 characters and include an uppercase letter, a digit, and a special character."
	}
	return ""
}

func (h *Auth) Abort(w http.ResponseWriter, r *http.Request) {
	h.idp.AbortInteraction(w, r, chi.URLParam(r, "uid"))
}

func (h *Auth) Confirm(w http.ResponseWriter, r *http.Request) {
	h.idp.ConfirmConsent(w, r, chi.URLParam(r, "uid"))
}

// Self-contained, mobile-first interaction page (login + consent + forced
// password change).
var page = template.Must(template.New("interaction").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<meta name="color-scheme" content="light" />
<meta name="theme-color" content="#f1f5f9" />
<title>{{if eq .Mode "consent"}}Consent{{else}}Sign in{{end}} · MuninID</title>
<style>
*{box-sizing:border-box}
/* Force a single light theme so Chrome's "Darken websites" (force-dark) can't
   half-invert the page or flicker against a prefers-color-scheme block. */
:root{color-scheme:light}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:24px;background:#f1f5f9;color:#0f172a;-webkit-text-size-adjust:100%;
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.45}
.card{width:100%;max-width:400px;background:#fff;border:1px solid #e2e8f0;border-radius:16px;
  padding:28px 24px;box-shadow:0 10px 30px rgba(15,23,42,.06)}
.logo{width:48px;height:48px;border-radius:12px;background:#1d4ed8;color:#fff;display:flex;
  align-items:center;justify-content:center;font-weight:800;font-size:22px;margin-bottom:18px}
h1{margin:0 0 4px;font-size:1.4rem;font-weight:700}
.sub{margin:0 0 22px;color:#64748b;font-size:.95rem}
label{display:block;font-size:.85rem;font-weight:600;color:#334155;margin-bottom:6px}
input{width:100%;padding:12px 14px;font-size:16px;border:1px solid #cbd5e1;border-radius:10px;
  background:#fff;color:#0f172a;margin-bottom:16px}
input:focus{outline:none;border-color:#1d4ed8;box-shadow:0 0 0 3px rgba(29,78,216,.15)}
button{width:100%;padding:13px 16px;font-size:1rem;font-weight:700;border:none;border-radius:10px;cursor:pointer}
.btn-primary{background:#1d4ed8;color:#fff}
.btn-primary:active{background:#1e40af}
.btn-secondary{background:#f1f5f9;color:#334155;margin-top:10px}
.error{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;padding:10px 12px;border-radius:10px;
  font-size:.9rem;margin-bottom:18px}
.scopes{list-style:none;padding:0;margin:0 0 20px}
.scopes li{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid #f1f5f9;
  color:#334155;font-size:.95rem}
.scopes li:last-child{border-bottom:none}
.dot{width:7px;height:7px;border-radius:50%;background:#1d4ed8;flex:none}
.muted{color:#94a3b8;font-size:.8rem;margin-top:20px;text-align:center}
.meter{display:flex;gap:6px;margin:-8px 0 8px}
.meter span{height:6px;flex:1;border-radius:999px;background:#e2e8f0;transition:background .2s ease}
.strength{font-size:.8rem;font-weight:600;color:#64748b;margin:0 0 14px;min-height:1.1em}
</style>
</head>
<body>
<main class="card">
<div class="logo" aria-hidden="true">M</div>
{{if eq .Mode "consent"}}
<h1>Review access</h1>
<p class="sub">Allow {{.Client}} to use your MuninID account.</p>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<ul class="scopes">{{if .Scopes}}{{range .Scopes}}<li><span class="dot"></span>{{.}}</li>{{end}}{{else}}<li>No scopes requested</li>{{end}}</ul>
<form method="post" action="/interaction/{{.UID}}/confirm"><input type="hidden" name="allow" value="yes" /><button class="btn-primary" type="submit">Allow access</button></form>
<form method="post" action="/interaction/{{.UID}}/abort"><button class="btn-secondary" type="submit">Deny</button></form>
{{else if eq .Mode "password"}}
<h1>Update your password</h1>
<p class="sub">Your password must be changed before continuing.</p>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<form method="post" action="/interaction/{{.UID}}/password">
<input type="hidden" name="uid" value="{{.UID}}" />
<label for="new_password">New password</label>
<input id="new_password" type="password" name="new_password" autocomplete="new-password" required placeholder="New password" autofocus />
<div class="meter" id="pw-meter" aria-hidden="true"><span></span><span></span><span></span><span></span></div>
<p class="strength" id="pw-strength" aria-live="polite"></p>
<label for="confirm_password">Confirm new password</label>
<input id="confirm_password" type="password" name="confirm_password" autocomplete="new-password" required placeholder="Confirm new password" />
<button class="btn-primary" type="submit">Update password</button>
</form>
{{else}}
<h1>Sign in</h1>
<p class="sub">Continue to {{.Client}}</p>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<form method="post" action="/interaction/{{.UID}}/login">
<input type="hidden" name="uid" value="{{.UID}}" />
<label for="username">Email</label>
<input id="username" type="email" name="username" autocomplete="username" inputmode="email" required placeholder="you@company.com" autofocus />
<label for="password">Password</label>
<input id="password" type="password" name="password" autocomplete="current-password" required placeholder="Your password" />
<button class="btn-primary" type="submit">Continue</button>
</form>
{{end}}
<p class="muted">Secured by MuninID</p>
</main>
<script>
// Progressive-enhancement password strength meter. The form works without JS;
// this only adds a live visual cue. Scoring follows the common rubric of
// length-first (NIST SP 800-63B) plus character-class variety. The authoritative
// breach/strength check is still performed server-side by WildDuck.
(function () {
  var pw = document.getElementById('new_password');
  if (!pw) return;
  var meter = document.getElementById('pw-meter');
  var label = document.getElementById('pw-strength');
  var segs = meter ? meter.children : [];
  var levels = [
    { text: '', color: '#e2e8f0' },
    { text: 'Weak', color: '#dc2626' },
    { text: 'Fair', color: '#f59e0b' },
    { text: 'Good', color: '#84cc16' },
    { text: 'Strong', color: '#16a34a' }
  ];
  function score(v) {
    if (!v) return 0;
    var variety = 0;
    if (/[a-z]/.test(v)) variety++;
    if (/[A-Z]/.test(v)) variety++;
    if (/[0-9]/.test(v)) variety++;
    if (/[^A-Za-z0-9]/.test(v)) variety++;
    var s = 0;
    if (v.length >= 10) s++;
    if (v.length >= 14) s++;
    if (variety >= 3) s++;
    if (variety === 4 && v.length >= 12) s++;
    return Math.min(Math.max(s, 1), 4);
  }
  function update() {
    var s = score(pw.value);
    var lv = levels[s];
    for (var i = 0; i < segs.length; i++) {
      segs[i].style.background = i < s ? lv.color : '#e2e8f0';
    }
    if (label) {
      label.textContent = pw.value ? lv.text : '';
      label.style.color = lv.color;
    }
  }
  pw.addEventListener('input', update);
  update();
})();
</script>
</body>
</html>`))
