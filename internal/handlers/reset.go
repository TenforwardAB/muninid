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
 * This file :: internal/handlers/reset.go is part of the MuninID project.
 */

package handlers

import (
	"html/template"
	"net/http"
)

// resetView drives the self-service password-reset pages (request link, choose
// new password, and the generic notice/success screens).
type resetView struct {
	Mode   string // "forgot" | "reset" | "notice" | "done"
	Token  string
	Error  string // inline form error (reset mode)
	Notice string // message body (notice/done modes)
}

// ForgotForm shows the "request a reset link" form.
func (h *Auth) ForgotForm(w http.ResponseWriter, r *http.Request) {
	renderReset(w, http.StatusOK, resetView{Mode: "forgot"})
}

// ForgotSubmit verifies the recovery destination and (on a match) mails a link.
// The response is always the same generic notice to avoid account enumeration.
func (h *Auth) ForgotSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	h.idp.BeginPasswordReset(r.Context(), r.Form.Get("username"), r.Form.Get("recovery_email"), r.RemoteAddr)
	renderReset(w, http.StatusOK, resetView{
		Mode:   "notice",
		Notice: "If an account with that address exists, we've sent password reset instructions to its recovery email. The link expires shortly.",
	})
}

// ResetForm validates the token from the emailed link and shows the new-password
// form, or a friendly notice if the link is invalid/expired.
func (h *Auth) ResetForm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if !h.idp.ResetTokenValid(r.Context(), token) {
		renderReset(w, http.StatusOK, resetView{Mode: "notice", Error: expiredLinkMsg})
		return
	}
	renderReset(w, http.StatusOK, resetView{Mode: "reset", Token: token})
}

// ResetSubmit applies the new password and signs the user in on success.
func (h *Auth) ResetSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	token := r.Form.Get("token")
	next := r.Form.Get("new_password")

	render := func(msg string) {
		renderReset(w, http.StatusBadRequest, resetView{Mode: "reset", Token: token, Error: msg})
	}
	if next != r.Form.Get("confirm_password") {
		render("Passwords do not match.")
		return
	}
	if msg := passwordPolicyError(next); msg != "" {
		render(msg)
		return
	}

	sessionID, err := h.idp.CompletePasswordReset(r.Context(), token, next)
	if err != nil {
		renderReset(w, http.StatusBadRequest, resetView{Mode: "notice", Error: expiredLinkMsg})
		return
	}
	h.idp.SetSessionCookie(w, sessionID)
	renderReset(w, http.StatusOK, resetView{
		Mode:   "done",
		Notice: "Your password has been updated and you're signed in. You can close this tab and continue where you left off.",
	})
}

const expiredLinkMsg = "This reset link is invalid or has expired. Please request a new one."

func renderReset(w http.ResponseWriter, status int, v resetView) {
	w.WriteHeader(status)
	_ = resetPage.Execute(w, v)
}

// resetPage is self-contained (its own CSS) so the login/consent interaction
// template stays untouched. Same visual language as that page.
var resetPage = template.Must(template.New("reset").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<meta name="color-scheme" content="light" />
<meta name="theme-color" content="#f1f5f9" />
<title>Reset password · MuninID</title>
<style>
*{box-sizing:border-box}
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
.error{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;padding:10px 12px;border-radius:10px;
  font-size:.9rem;margin-bottom:18px}
.notice{background:#f0f9ff;border:1px solid #bae6fd;color:#075985;padding:12px 14px;border-radius:10px;
  font-size:.92rem;margin-bottom:18px}
.muted{color:#94a3b8;font-size:.8rem;margin-top:20px;text-align:center}
.muted a{color:#64748b}
.meter{display:flex;gap:6px;margin:-8px 0 8px}
.meter span{height:6px;flex:1;border-radius:999px;background:#e2e8f0;transition:background .2s ease}
.strength{font-size:.8rem;font-weight:600;color:#64748b;margin:0 0 14px;min-height:1.1em}
</style>
</head>
<body>
<main class="card">
<div class="logo" aria-hidden="true">M</div>
{{if eq .Mode "forgot"}}
<h1>Reset your password</h1>
<p class="sub">Enter your account address and a recovery email you've registered. We'll email a reset link.</p>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<form method="post" action="/forgot">
<label for="username">Account address</label>
<input id="username" type="email" name="username" autocomplete="username" inputmode="email" required placeholder="you@mailtrix.eu" autofocus />
<label for="recovery_email">Recovery email</label>
<input id="recovery_email" type="email" name="recovery_email" inputmode="email" required placeholder="you@personal.com" />
<button class="btn-primary" type="submit">Send reset link</button>
</form>
{{else if eq .Mode "reset"}}
<h1>Choose a new password</h1>
<p class="sub">Pick a strong password you don't use anywhere else.</p>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
<form method="post" action="/reset">
<input type="hidden" name="token" value="{{.Token}}" />
<label for="new_password">New password</label>
<input id="new_password" type="password" name="new_password" autocomplete="new-password" required placeholder="New password" autofocus />
<div class="meter" id="pw-meter" aria-hidden="true"><span></span><span></span><span></span><span></span></div>
<p class="strength" id="pw-strength" aria-live="polite"></p>
<label for="confirm_password">Confirm new password</label>
<input id="confirm_password" type="password" name="confirm_password" autocomplete="new-password" required placeholder="Confirm new password" />
<button class="btn-primary" type="submit">Update password</button>
</form>
{{else if eq .Mode "done"}}
<h1>Password updated</h1>
<div class="notice" role="status">{{.Notice}}</div>
{{else}}
<h1>Check your email</h1>
{{if .Error}}<div class="error" role="alert">{{.Error}}</div><p class="muted"><a href="/forgot">Request a new reset link</a></p>{{else}}<div class="notice" role="status">{{.Notice}}</div>{{end}}
{{end}}
<p class="muted">Secured by MuninID</p>
</main>
<script>
// Progressive-enhancement strength meter (mirrors the login page). The
// authoritative check is server-side.
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
