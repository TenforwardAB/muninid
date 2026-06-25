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
	"html/template"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/tenforwardab/muninid/internal/idp"
)

type Auth struct {
	idp *idp.Provider
}

func NewAuth(provider *idp.Provider) *Auth {
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

func (h *Auth) Abort(w http.ResponseWriter, r *http.Request) {
	h.idp.AbortInteraction(w, r, chi.URLParam(r, "uid"))
}

func (h *Auth) Confirm(w http.ResponseWriter, r *http.Request) {
	h.idp.ConfirmConsent(w, r, chi.URLParam(r, "uid"))
}

// Self-contained, mobile-first interaction page (login + consent). No external
// CSS/CDN and no JS, so it renders correctly inside in-app browsers and on
// slow/offline networks. Dark mode follows the device via prefers-color-scheme.
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
</body>
</html>`))
