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
 * This file :: internal/handlers/admin_gui.go is part of the MuninID project.
 */

package handlers

import (
	"html"
	"net/http"
)

func AdminGUI(masterUser string) http.HandlerFunc {
	page := adminGUIPage(html.EscapeString(masterUser))
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	}
}

func adminGUIPage(masterUser string) string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MuninID Admin GUI</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css" />
  <style>
    :root {
      --pico-font-family: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
      --pico-primary: #0f6fff;
      --pico-primary-background: #0f6fff;
      --panel-bg: #ffffff;
      --panel-border: #d8dee8;
      --panel-shadow: 0 18px 48px rgba(15, 23, 42, 0.08);
      --text-muted: #475569;
    }
    [data-theme="dark"] {
      --panel-bg: #101827;
      --panel-border: #243145;
      --panel-shadow: 0 18px 48px rgba(0, 0, 0, 0.35);
      --text-muted: #cbd5e1;
    }
    body {
      min-height: 100vh;
      margin: 0;
      padding: 28px 16px 44px;
      background: linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%);
    }
    [data-theme="dark"] body {
      background: linear-gradient(180deg, #0f172a 0%, #111827 100%);
    }
    .shell {
      width: min(1280px, 100%);
      margin: 0 auto;
      display: grid;
      gap: 18px;
    }
    .hero {
      color: #f8fafc;
      background: linear-gradient(135deg, #0ea5e9 0%, #0f6fff 56%, #312e81 100%);
      border-radius: 14px;
      padding: 22px 24px;
      box-shadow: var(--panel-shadow);
    }
    .brand-line {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .brand-mark {
      width: 52px;
      height: 52px;
      border-radius: 10px;
      display: grid;
      place-items: center;
      background: rgba(255,255,255,0.14);
      border: 1px solid rgba(255,255,255,0.22);
      font-weight: 800;
    }
    .grid {
      display: grid;
      gap: 18px;
      grid-template-columns: 1fr;
    }
    @media (min-width: 1080px) {
      .grid { grid-template-columns: 6fr 5fr; }
    }
    .panel {
      background: var(--panel-bg);
      border: 1px solid var(--panel-border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: var(--panel-shadow);
    }
    .topbar, .actions {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }
    .resource-actions {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }
    .muted {
      color: var(--text-muted);
      font-size: 0.94rem;
    }
    .hidden { display: none; }
    textarea {
      min-height: 112px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    }
    table { width: 100%; border-collapse: collapse; }
    table tr { cursor: pointer; }
    table tr.selected { background: rgba(15, 111, 255, 0.1); }
    table th, table td {
      border-bottom: 1px solid var(--panel-border);
      padding: 10px 8px;
      vertical-align: top;
    }
    .table-wrapper { overflow-x: auto; }
    .pill {
      display: inline-flex;
      align-items: center;
      padding: 5px 9px;
      border-radius: 999px;
      background: rgba(15, 111, 255, 0.1);
      font-weight: 700;
      font-size: 0.86rem;
    }
    pre {
      max-height: 380px;
      overflow: auto;
      white-space: pre-wrap;
    }
    dialog article { min-width: min(620px, 92vw); }
  </style>
</head>
<body>
  <dialog id="secretModal">
    <article>
      <header><h3>Copy client credentials</h3></header>
      <p class="muted">Store this client_id and client_secret now. The secret cannot be retrieved later.</p>
      <pre id="secretContent"></pre>
      <footer><button id="closeSecret" class="secondary">Close</button></footer>
    </article>
  </dialog>
  <div class="shell">
    <header class="hero">
      <div class="brand-line">
        <div class="brand-mark">ID</div>
        <div>
          <p style="margin:0;font-weight:700;letter-spacing:0.08em;font-size:13px;">MuninID</p>
          <h1 style="margin:4px 0 4px;font-size:1.7rem;">Admin Console</h1>
          <p style="margin:0;color:rgba(248,250,252,0.88);">Manage OIDC clients now, with policies and SAML SPs using the same API paths as the Node admin UI.</p>
        </div>
      </div>
    </header>

    <div class="grid">
      <article class="panel">
        <div class="topbar">
          <div class="resource-actions">
            <label for="resource" style="margin:0;">Resource</label>
            <select id="resource">
              <option value="clients">Clients</option>
              <option value="policies">Policies</option>
              <option value="sps">Service Providers</option>
            </select>
            <button type="button" id="listBtn" class="secondary">List</button>
            <button type="button" id="createBtn">Create new</button>
          </div>
          <button type="button" class="secondary" id="themeBtn">Theme</button>
        </div>

        <div class="row" style="margin-bottom:8px;">
          <div>
            <label for="username">MASTER_USER</label>
            <input id="username" value="` + masterUser + `" autocomplete="username" />
          </div>
          <div>
            <label for="password">MASTER_PASSWORD</label>
            <input id="password" type="password" placeholder="Enter master password" autocomplete="current-password" />
          </div>
          <div>
            <label for="status">Status</label>
            <input id="status" readonly value="Ready" />
          </div>
        </div>

        <div id="form-clients">
          <p class="muted" id="mode-clients">Mode: Create</p>
          <div class="row">
            <div><label for="client_name">Name</label><input id="client_name" placeholder="example-app" /></div>
            <div><label for="client_rotate">Rotate Secret on Update</label><input id="client_rotate" type="checkbox" role="switch" /></div>
          </div>
          <label for="client_redirects">Redirect URIs (one per line)</label>
          <textarea id="client_redirects" placeholder="http://localhost:3000/callback"></textarea>
          <label for="client_post_logout">Post-logout Redirect URIs (one per line)</label>
          <textarea id="client_post_logout" placeholder="http://localhost:5173/"></textarea>
          <label for="client_grants">Grant Types (one per line)</label>
          <textarea id="client_grants" placeholder="authorization_code&#10;refresh_token"></textarea>
          <label for="client_scopes">Scopes (one per line)</label>
          <textarea id="client_scopes" placeholder="openid&#10;profile&#10;email"></textarea>
        </div>

        <div id="form-policies" class="hidden">
          <p class="muted" id="mode-policies">Mode: Create</p>
          <div class="row">
            <div><label for="policy_name">Name</label><input id="policy_name" placeholder="require-2fa" /></div>
            <div><label for="policy_target_type">Target Type</label><input id="policy_target_type" placeholder="client|user|service" /></div>
            <div><label for="policy_target_id">Target ID</label><input id="policy_target_id" placeholder="client-id or user-id" /></div>
          </div>
          <label for="policy_body">Policy JSON</label>
          <textarea id="policy_body" placeholder='{"rule":"allow"}'></textarea>
        </div>

        <div id="form-sps" class="hidden">
          <p class="muted" id="mode-sps">Mode: Create</p>
          <div class="row">
            <div><label for="sp_entity">Entity ID</label><input id="sp_entity" placeholder="urn:example:sp" /></div>
            <div><label for="sp_binding">Binding</label><input id="sp_binding" placeholder="post|redirect" /></div>
          </div>
          <label for="sp_acs">ACS Endpoints (one per line)</label>
          <textarea id="sp_acs" placeholder="https://app.example.com/saml/acs"></textarea>
          <label for="sp_metadata">Metadata XML</label>
          <textarea id="sp_metadata" placeholder="<EntityDescriptor>...</EntityDescriptor>"></textarea>
          <label for="sp_attrs">Attribute Mapping JSON</label>
          <textarea id="sp_attrs" placeholder='{"email":"mail","name":"displayName"}'></textarea>
        </div>

        <div class="actions" style="margin-top:12px;">
          <button id="saveBtn">Save</button>
          <button class="secondary" id="deleteBtn">Delete selected</button>
        </div>
      </article>

      <article class="panel">
        <div class="topbar" style="margin-bottom:8px;">
          <div>
            <p style="margin:0;font-weight:700;letter-spacing:0.08em;font-size:12px;" class="muted">Listing</p>
            <h3 style="margin:2px 0;">Records</h3>
          </div>
          <span class="muted">Requests use /gui/api with master Basic Auth.</span>
        </div>
        <div class="table-wrapper">
          <table id="listTable">
            <thead id="listHead"></thead>
            <tbody id="listBody"><tr><td>No records.</td></tr></tbody>
          </table>
        </div>
        <div style="margin-top:12px;">
          <pre id="output">Awaiting action...</pre>
        </div>
        <div id="secretInline" class="hidden" style="margin-top:12px;">
          <strong>Copy these credentials now:</strong>
          <pre id="secretInlineContent"></pre>
        </div>
      </article>
    </div>
  </div>

  <script>
    const resource = document.getElementById('resource');
    const username = document.getElementById('username');
    const password = document.getElementById('password');
    const statusEl = document.getElementById('status');
    const output = document.getElementById('output');
    const listHead = document.getElementById('listHead');
    const listBody = document.getElementById('listBody');
    const listBtn = document.getElementById('listBtn');
    const createBtn = document.getElementById('createBtn');
    const saveBtn = document.getElementById('saveBtn');
    const deleteBtn = document.getElementById('deleteBtn');
    const themeBtn = document.getElementById('themeBtn');
    const forms = {
      clients: document.getElementById('form-clients'),
      policies: document.getElementById('form-policies'),
      sps: document.getElementById('form-sps')
    };
    const modes = {
      clients: document.getElementById('mode-clients'),
      policies: document.getElementById('mode-policies'),
      sps: document.getElementById('mode-sps')
    };
    const state = { resource: resource.value, selection: null, data: [] };

    const setOutput = (value) => {
      output.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
    };
    const setStatus = (text) => { statusEl.value = text; };
    const splitLines = (value) => value.split(/\r?\n/).map((v) => v.trim()).filter(Boolean);
    const joinLines = (arr) => Array.isArray(arr) ? arr.join('\n') : '';
    const itemID = (item) => item.id || item.client_id || item.clientId || '';
    const buildAuthHeader = () => 'Basic ' + btoa((username.value || '') + ':' + (password.value || ''));

    const applyTheme = (mode) => {
      const effective = mode === 'dark' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', effective);
      localStorage.setItem('muninid-theme', effective);
    };
    applyTheme(localStorage.getItem('muninid-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
    themeBtn.addEventListener('click', () => {
      applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    });

    const showForm = () => {
      Object.entries(forms).forEach(([key, el]) => el && el.classList.toggle('hidden', key !== state.resource));
      Object.entries(modes).forEach(([key, el]) => {
        if (el) el.textContent = 'Mode: ' + (state.selection && state.resource === key ? 'Edit' : 'Create');
      });
    };

    const clearForm = () => {
      document.querySelectorAll('input[id^="client_"], textarea[id^="client_"], input[id^="policy_"], textarea[id^="policy_"], input[id^="sp_"], textarea[id^="sp_"]').forEach((el) => {
        if (el.type === 'checkbox') el.checked = false;
        else el.value = '';
      });
      state.selection = null;
      showForm();
      highlightSelection();
    };

    const fillForm = (item) => {
      if (state.resource === 'clients') {
        document.getElementById('client_name').value = item.name || '';
        document.getElementById('client_rotate').checked = false;
        document.getElementById('client_redirects').value = joinLines(item.redirectUris || item.redirect_uris || []);
        document.getElementById('client_post_logout').value = joinLines(item.postLogoutRedirectUris || item.post_logout_redirect_uris || []);
        document.getElementById('client_grants').value = joinLines(item.grantTypes || item.grant_types || []);
        document.getElementById('client_scopes').value = joinLines(item.scopes || []);
      }
      if (state.resource === 'policies') {
        document.getElementById('policy_name').value = item.name || '';
        document.getElementById('policy_target_type').value = item.targetType || item.target_type || '';
        document.getElementById('policy_target_id').value = item.targetId || item.target_id || '';
        document.getElementById('policy_body').value = item.policy ? JSON.stringify(item.policy, null, 2) : '';
      }
      if (state.resource === 'sps') {
        document.getElementById('sp_entity').value = item.entityId || item.entity_id || '';
        document.getElementById('sp_binding').value = item.binding || '';
        document.getElementById('sp_acs').value = joinLines(item.acsEndpoints || item.acs || item.acs_endpoints || []);
        document.getElementById('sp_metadata').value = item.metadataXml || item.metadata_xml || '';
        document.getElementById('sp_attrs').value = item.attributeMapping ? JSON.stringify(item.attributeMapping, null, 2) : '';
      }
      state.selection = item;
      showForm();
    };

    const buildPayload = () => {
      if (state.resource === 'clients') {
        const payload = {
          name: document.getElementById('client_name').value.trim() || undefined,
          redirect_uris: splitLines(document.getElementById('client_redirects').value),
          post_logout_redirect_uris: splitLines(document.getElementById('client_post_logout').value),
          grant_types: splitLines(document.getElementById('client_grants').value),
          scopes: splitLines(document.getElementById('client_scopes').value),
          rotate_secret: document.getElementById('client_rotate').checked
        };
        if (!state.selection) delete payload.rotate_secret;
        return payload;
      }
      if (state.resource === 'policies') {
        const raw = document.getElementById('policy_body').value.trim();
        return {
          name: document.getElementById('policy_name').value.trim() || undefined,
          target_type: document.getElementById('policy_target_type').value.trim() || undefined,
          target_id: document.getElementById('policy_target_id').value.trim() || undefined,
          policy: raw ? JSON.parse(raw) : {}
        };
      }
      if (state.resource === 'sps') {
        const attrsRaw = document.getElementById('sp_attrs').value.trim();
        return {
          entity_id: document.getElementById('sp_entity').value.trim() || undefined,
          binding: document.getElementById('sp_binding').value.trim() || undefined,
          acs: splitLines(document.getElementById('sp_acs').value),
          metadata_xml: document.getElementById('sp_metadata').value.trim() || undefined,
          attr_mapping: attrsRaw ? JSON.parse(attrsRaw) : {}
        };
      }
      return {};
    };

    const apiFetch = async (path, options = {}) => {
      const resp = await fetch(path, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': buildAuthHeader(),
          ...(options.headers || {})
        }
      });
      const text = await resp.text();
      let parsed;
      try { parsed = JSON.parse(text); } catch { parsed = text; }
      return { resp, parsed };
    };

    const loadList = async () => {
      setStatus('Loading...');
      const { resp, parsed } = await apiFetch('/gui/api/' + state.resource);
      if (!resp.ok) {
        setStatus('List failed');
        setOutput(parsed);
        state.data = [];
        renderTable();
        return;
      }
      state.data = Array.isArray(parsed) ? parsed : [];
      setStatus('Loaded ' + state.data.length);
      renderTable();
      setOutput({ status: resp.status, count: state.data.length });
    };

    const renderTable = () => {
      listHead.innerHTML = '';
      listBody.innerHTML = '';
      const data = state.data || [];
      if (data.length === 0) {
        listBody.innerHTML = '<tr><td colspan="6">No records.</td></tr>';
        return;
      }
      const keys = Object.keys(data[0]).filter((k) => !['client_secret', 'clientSecret'].includes(k)).slice(0, 6);
      const headRow = document.createElement('tr');
      headRow.innerHTML = '<th>id</th>' + keys.map((k) => '<th>' + escapeHTML(k) + '</th>').join('');
      listHead.appendChild(headRow);
      data.forEach((item) => {
        const id = itemID(item);
        const tr = document.createElement('tr');
        tr.dataset.id = id;
        tr.innerHTML = '<td><span class="pill">' + escapeHTML(String(id).slice(0, 8)) + '</span></td>' +
          keys.map((k) => '<td>' + formatCell(item[k]) + '</td>').join('');
        if (state.selection && itemID(state.selection) === id) tr.classList.add('selected');
        tr.addEventListener('click', () => {
          state.selection = item;
          fillForm(item);
          highlightSelection();
        });
        listBody.appendChild(tr);
      });
    };

    const escapeHTML = (value) => String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[char]));
    const formatCell = (value) => {
      if (Array.isArray(value)) return escapeHTML(value.join(', '));
      if (typeof value === 'object' && value !== null) return escapeHTML(JSON.stringify(value));
      return value === undefined || value === null ? '' : escapeHTML(value);
    };
    const highlightSelection = () => {
      [...listBody.querySelectorAll('tr')].forEach((tr) => {
        tr.classList.toggle('selected', state.selection && tr.dataset.id === itemID(state.selection));
      });
    };

    listBtn.addEventListener('click', () => {
      state.selection = null;
      clearForm();
      loadList().catch((err) => {
        setStatus('List failed');
        setOutput(String(err));
      });
    });
    createBtn.addEventListener('click', () => {
      clearForm();
      setStatus('Create mode');
      setOutput('Ready to create');
    });
    saveBtn.addEventListener('click', async () => {
      try {
        const payload = buildPayload();
        const id = state.selection ? itemID(state.selection) : '';
        const isEdit = Boolean(id);
        const path = '/gui/api/' + state.resource + (isEdit ? '/' + encodeURIComponent(id) : '');
        const method = isEdit ? 'PUT' : 'POST';
        setStatus(isEdit ? 'Updating...' : 'Creating...');
        const { resp, parsed } = await apiFetch(path, { method, body: JSON.stringify(payload) });
        setOutput(parsed);
        if (!resp.ok) {
          setStatus(isEdit ? 'Update failed' : 'Create failed');
          return;
        }
        setStatus(isEdit ? 'Updated' : 'Created');
        if (parsed && parsed.client_id && parsed.client_secret) showSecretModal(parsed.client_id, parsed.client_secret);
        state.selection = null;
        clearForm();
        await loadList();
      } catch (err) {
        setStatus('Save error');
        setOutput(String(err));
      }
    });
    deleteBtn.addEventListener('click', async () => {
      if (!state.selection) {
        setOutput('Select a record first');
        return;
      }
      const id = itemID(state.selection);
      setStatus('Deleting...');
      const { resp, parsed } = await apiFetch('/gui/api/' + state.resource + '/' + encodeURIComponent(id), { method: 'DELETE' });
      setOutput(parsed || { status: resp.status });
      if (!resp.ok && resp.status !== 204) {
        setStatus('Delete failed');
        return;
      }
      setStatus('Deleted');
      state.selection = null;
      clearForm();
      await loadList();
    });
    resource.addEventListener('change', () => {
      state.resource = resource.value;
      state.selection = null;
      state.data = [];
      clearForm();
      renderTable();
      setStatus('Ready');
    });

    const secretModal = document.getElementById('secretModal');
    const secretContent = document.getElementById('secretContent');
    const closeSecret = document.getElementById('closeSecret');
    const secretInline = document.getElementById('secretInline');
    const secretInlineContent = document.getElementById('secretInlineContent');
    const showSecretModal = (clientId, clientSecret) => {
      const payload = { client_id: clientId, client_secret: clientSecret };
      secretContent.textContent = JSON.stringify(payload, null, 2);
      secretInlineContent.textContent = JSON.stringify(payload, null, 2);
      secretInline.classList.remove('hidden');
      if (typeof secretModal.showModal === 'function') secretModal.showModal();
      else secretModal.setAttribute('open', 'true');
    };
    closeSecret.addEventListener('click', () => {
      if (typeof secretModal.close === 'function') secretModal.close();
      else secretModal.removeAttribute('open');
      secretInline.classList.add('hidden');
    });
    showForm();
  </script>
</body>
</html>`
}
