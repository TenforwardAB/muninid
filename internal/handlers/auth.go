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

var page = template.Must(template.New("interaction").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{{if eq .Mode "consent"}}Consent{{else}}Sign in{{end}} · MuninID</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css" />
<style>
:root{--pico-font-family:"Inter","Segoe UI","Helvetica Neue",system-ui,-apple-system,sans-serif;--pico-primary:#0f6fff;--pico-primary-background:#0f6fff;--pico-primary-underline:rgba(15,111,255,.25);--pico-border-radius:16px;--bg-gradient:radial-gradient(circle at 16% 20%,#dbeafe 0%,#eff6ff 22%,transparent 22%),radial-gradient(circle at 80% 10%,#e0f2fe 0%,#e5ecff 24%,transparent 24%),linear-gradient(180deg,#f8fafc 0%,#eef2ff 100%);--panel-bg:#fff;--panel-border:#e2e8f0;--panel-shadow:0 24px 60px rgba(15,23,42,.08);--text-strong:#0f172a;--text-muted:#475569;--chip-bg:rgba(15,111,255,.08);--chip-text:#0f3e9c;--accent-gradient:radial-gradient(circle at 25% 20%,rgba(15,111,255,.12),transparent 40%),radial-gradient(circle at 90% 30%,rgba(14,165,233,.14),transparent 36%),linear-gradient(160deg,#0ea5e9 0%,#0f6fff 55%,#312e81 100%);color-scheme:light dark}
[data-theme="dark"]{--bg-gradient:radial-gradient(circle at 20% 20%,rgba(15,23,42,.75) 0%,rgba(15,23,42,.55) 24%,transparent 26%),radial-gradient(circle at 80% 10%,rgba(30,41,59,.7) 0%,rgba(17,24,39,.55) 28%,transparent 30%),linear-gradient(180deg,#0f172a 0%,#111827 100%);--panel-bg:#0f172a;--panel-border:#1f2937;--panel-shadow:0 24px 60px rgba(0,0,0,.45);--text-strong:#e2e8f0;--text-muted:#cbd5e1;--chip-bg:rgba(80,130,255,.18);--chip-text:#bfdbfe;--accent-gradient:radial-gradient(circle at 25% 20%,rgba(59,130,246,.22),transparent 40%),radial-gradient(circle at 90% 30%,rgba(56,189,248,.24),transparent 36%),linear-gradient(160deg,#0ea5e9 0%,#1d4ed8 55%,#312e81 100%)}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:32px;background:var(--bg-gradient);color:var(--text-strong)}
main{width:min(1080px,100%);display:grid;gap:22px;grid-template-columns:repeat(1,minmax(0,1fr))}
@media (min-width:720px){main{grid-template-columns:{{if eq .Mode "consent"}}6fr 5fr{{else}}7fr 5fr{{end}}}}
.panel{background:var(--panel-bg);border:1px solid var(--panel-border);border-radius:18px;padding:26px 28px;box-shadow:var(--panel-shadow)}
.brand{display:flex;align-items:center;gap:16px;margin-bottom:12px}.brand img{width:64px;height:64px;border-radius:14px;border:1px solid var(--panel-border);padding:12px;background:linear-gradient(145deg,#f8fafc,#e2e8f0);object-fit:contain}.logo-fallback{width:64px;height:64px;border-radius:14px;background:linear-gradient(145deg,#0ea5e9,#0f6fff 60%,#312e81);display:grid;place-items:center;color:#fff;font-weight:800;font-size:26px;border:1px solid var(--panel-border)}
.eyebrow{margin:0;font-size:13px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted)}h1{margin:4px 0 6px;font-size:1.75rem;color:var(--text-strong)}.subtitle{margin:0;color:var(--text-muted);font-size:1rem}
form{margin-top:16px;display:flex;flex-direction:column;gap:14px}label{font-weight:600;color:var(--text-strong)}input{margin-top:8px}.chip{display:inline-flex;align-items:center;gap:8px;padding:10px 12px;border-radius:999px;background:var(--chip-bg);color:var(--chip-text);font-weight:600;font-size:.95rem}
.notice{padding:12px 14px;border-radius:14px;border:1px solid var(--panel-border);background:rgba(148,163,184,.08);font-weight:600;color:var(--text-strong)}.notice.error{border-color:rgba(239,68,68,.35);background:rgba(239,68,68,.12);color:#f87171}
.form-footer{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:4px;color:var(--text-muted);font-size:.95rem}.actions{margin-top:16px;display:flex;flex-wrap:wrap;gap:12px}.actions form{margin:0}.actions button{margin:0}.secondary{background:#e5e7eb;color:#1f2937}
.scopes{margin:16px 0 8px;padding:0;list-style:none;display:grid;gap:10px}.scopes li{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:12px;border:1px solid var(--panel-border);background:rgba(148,163,184,.06);font-weight:600;color:var(--text-strong)}.scopes li.empty{color:var(--text-muted);font-weight:500}.scope-name{color:var(--text-strong)}
.accent{background:var(--accent-gradient);color:#e2e8f0;border:none;position:relative;overflow:hidden}.accent::after{content:"";position:absolute;inset:14px;border:1px solid rgba(255,255,255,.12);border-radius:14px;pointer-events:none}.accent h2{margin:4px 0 8px;font-size:1.5rem}.accent p{color:rgba(226,232,240,.9)}.accent .badge{display:inline-flex;align-items:center;gap:6px;padding:8px 12px;border-radius:999px;background:rgba(255,255,255,.14);font-weight:700;letter-spacing:.04em}
.accent .logo-mark{width:56px;height:56px;border-radius:12px;background:rgba(255,255,255,.14);display:grid;place-items:center;border:1px solid rgba(255,255,255,.18);margin-top:10px}.accent .logo-mark span{font-weight:900;font-size:24px;color:#fff}.highlights{list-style:none;padding:0;margin:14px 0 0;display:grid;gap:8px}.highlights li{display:flex;gap:10px;align-items:center;padding:10px 12px;border-radius:12px;background:rgba(255,255,255,.08);color:#e2e8f0;font-weight:600}
.pill-icon{width:9px;height:9px;border-radius:999px;background:#a5f3fc;display:inline-block}.fineprint{margin-top:20px;color:{{if eq .Mode "consent"}}#dbeafe{{else}}var(--text-muted){{end}};font-size:.9rem}.theme-toggle{display:flex;justify-content:flex-end;align-items:center;margin-bottom:10px;grid-column:1/-1}.theme-toggle button{margin:0;padding:10px 12px;display:inline-flex;align-items:center;gap:6px}.icon{font-size:18px;line-height:1}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}
</style>
</head>
<body>
<main>
<div class="theme-toggle"><button type="button" class="secondary" data-theme-toggle onclick="window.muninidToggleTheme?.()"><span class="icon" aria-hidden="true">☀️</span><span class="sr-only">Toggle theme</span></button></div>
<article class="panel">
<div class="brand"><div class="logo-fallback" aria-hidden="true">S</div><div><p class="eyebrow">MuninID</p>{{if eq .Mode "consent"}}<h1>Review access request</h1><p class="subtitle">Allow {{.Client}} to use your MuninID identity.</p>{{else}}<h1>Sign in</h1><p class="subtitle">Continue to {{.Client}}</p>{{end}}</div></div>
{{if .Error}}<div class="notice error" role="alert">{{.Error}}</div>{{end}}
{{if eq .Mode "consent"}}
<div class="chip">Requested scopes</div>
<ul class="scopes" role="list">{{if .Scopes}}{{range .Scopes}}<li><span class="pill-icon"></span><span class="scope-name">{{.}}</span></li>{{end}}{{else}}<li class="empty">No scopes requested</li>{{end}}</ul>
{{if .Audiences}}<div class="chip">Requested audience</div><ul class="scopes" role="list">{{range .Audiences}}<li><span class="pill-icon"></span><span class="scope-name">{{.}}</span></li>{{end}}</ul>{{end}}
<div class="actions"><form method="post" action="/interaction/{{.UID}}/confirm"><input type="hidden" name="allow" value="yes" /><button type="submit">Allow access</button></form><form method="post" action="/interaction/{{.UID}}/abort"><button class="secondary" type="submit">Deny</button></form></div>
{{else}}
{{if .Scopes}}<div class="chip">Requesting access: {{range $index, $scope := .Scopes}}{{if $index}} {{end}}{{$scope}}{{end}}</div>{{end}}
<form method="post" action="/interaction/{{.UID}}/login"><input type="hidden" name="uid" value="{{.UID}}" /><label>Work or personal email<input type="email" name="username" autocomplete="username" required placeholder="you@company.com" autofocus /></label><label>Password<input type="password" name="password" autocomplete="current-password" required placeholder="Enter your password" /></label><button type="submit">Continue</button></form>
<div class="form-footer"><span>MuninID protects your session with modern security.</span><small class="eyebrow" style="letter-spacing:.02em">Help</small></div>
{{end}}
</article>
<article class="panel accent">
<div class="badge"><span class="pill-icon"></span>MuninID</div>
{{if eq .Mode "consent"}}<h2>Transparent consent, enterprise clarity.</h2><p>We align with familiar identity dialogs so your users instantly know what is being shared and why.</p>{{else}}<h2>Trusted access, Google-simple with Entra polish.</h2><p>One clean sign-in for every MuninID-powered app. Strong MFA, clear scopes, and a frictionless experience your teams already know.</p>{{end}}
<div class="logo-mark" aria-hidden="true"><span>S</span></div>
<ul class="highlights">
{{if eq .Mode "consent"}}<li><span class="pill-icon"></span>Human-friendly scopes and plain language</li><li><span class="pill-icon"></span>Granular controls with crisp primary and secondary actions</li><li><span class="pill-icon"></span>Approvals are stored per app and user</li>{{else}}<li><span class="pill-icon"></span>Fast identity hand-offs with clear consent</li><li><span class="pill-icon"></span>Adaptive security tuned for modern workloads</li><li><span class="pill-icon"></span>Designed to mirror the clarity of Google and Entra</li>{{end}}
</ul>
{{if eq .Mode "consent"}}<p class="fineprint">You are approving a connection between {{.Client}} and MuninID.</p>{{else}}<p class="fineprint">MuninID keeps access predictable across your apps.</p>{{end}}
</article>
</main>
<script>
(() => {
    const storageKey = "muninid-theme";
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)");
    const applyTheme = (value) => {
        const mode = value === "light" || value === "dark" ? value : "auto";
        const effective = mode === "auto" ? (prefersDark.matches ? "dark" : "light") : mode;
        document.documentElement.setAttribute("data-theme", effective);
        document.documentElement.setAttribute("data-theme-mode", mode);
        const button = document.querySelector("[data-theme-toggle]");
        if (button) {
            const icon = mode === "auto" ? (prefersDark.matches ? "🌙" : "☀️") : mode === "dark" ? "🌙" : "☀️";
            button.querySelector(".icon")?.replaceChildren(document.createTextNode(icon));
        }
    };
    const stored = localStorage.getItem(storageKey);
    applyTheme(stored || "auto");
    window.muninidToggleTheme = () => {
        const currentMode = document.documentElement.getAttribute("data-theme-mode") || "auto";
        const next = currentMode === "auto" ? "light" : currentMode === "light" ? "dark" : "auto";
        localStorage.setItem(storageKey, next);
        applyTheme(next);
    };
    prefersDark.addEventListener("change", () => {
        if ((localStorage.getItem(storageKey) || "auto") === "auto") {
            applyTheme("auto");
        }
    });
})();
</script>
</body>
</html>`))
