# Authorization contract (muninID → external PDP)

Status: **Draft** · Last updated: 2026-06-24

muninID acts as a **Policy Enforcement Point (PEP)**: it authenticates the
caller (verifies the muninID-issued OIDC access token locally) and then asks a
pluggable **Policy Decision Point (PDP)** whether the subject may perform an
action on a resource. The PDP is selected via `AUTHZ_BACKEND`:

| Backend | Decision source | External dependency |
|---------|-----------------|---------------------|
| `claims` (default) | Token roles + `customer_id` ownership, in-process | none |
| `solutrix` | `POST /authz/check` against solutrix-api (ABAC) | solutrix-api |

This document specifies the `solutrix` HTTP contract. It mirrors solutrix-api's
existing in-process engine (`abacService.can` / `getVisibility`), so the PDP can
delegate straight to it.

---

## 1. Service-to-service authentication

muninID is the IdP, so it mints a **service access token** for itself via the
`client_credentials` grant at its own token endpoint, then calls solutrix with
`Authorization: Bearer <service-token>`. solutrix already verifies muninID
tokens (`idpTokenVerifier.ts`), so no new trust anchor is needed.

solutrix restricts the endpoint to trusted service callers: `requireServiceCaller`
checks the token's `client_id` against the `AUTHZ_SERVICE_CLIENTS` allow-list
(comma-separated; empty = reject everyone), and optionally a required scope via
`AUTHZ_SERVICE_SCOPE`. The endpoint evaluates an **arbitrary** subject, so an
untrusted caller could otherwise probe other users' permissions.

The subject being evaluated is asserted by muninID (it already verified that
user's token). solutrix re-derives roles, `org_type` and policy from its own DB
using `user_id` + `customer_id` — the asserted subject is only an identity
pointer, not a grant.

---

## 2. Resource & action vocabulary

muninID resources use the `idp:` namespace (reserved-prefix pattern from
`abac-design.md` §4):

| Resource | Covers |
|----------|--------|
| `idp:clients` | OAuth clients (CRUD + `rotate_secret`) |
| `idp:saml_sps` | SAML service providers (future) |
| `idp:policies` | muninID policies (future) |

Actions: `create`, `read`, `update`, `delete`, plus `rotate_secret`.

solutrix needs grants for these resources in `policy_template` /
`role_permissions` for any non-superadmin to be allowed (superadmin `*:*`
already covers them).

---

## 3. `POST /api/v1/authz/check`

Single decision, optionally with list visibility. muninID builds the URL as
`SOLUTRIX_API_BASE_URL + "/authz/check"`, so set
`SOLUTRIX_API_BASE_URL=https://solutrix-api/api/v1`.

### Request

```jsonc
{
  "subject": {
    "user_id":     "f1e2...",        // required; token "sub"
    "customer_id": "ac3d...|null"    // tenant context; token customer_id claim
  },
  "action":   "create",             // required
  "resource": "idp:clients",        // required
  "scope":    null,                 // optional effective customer-scope override
  "instance": { "customerid": "ac3d..." }  // optional; enables exact where/deny check
}
```

- Omit `instance` for collection endpoints (list/create-into-scope); the PDP
  returns `visibility` for filtering.
- Provide `instance` for a specific object; the PDP runs the full `can()` check
  including `where`/deny-precedence. `instance.customerid` is the object's owner.

### Response `200`

```jsonc
{
  "allow": true,
  "reason": "",                                  // optional, human-readable
  "policy_version": "customer:ac3d...:Captain:1718000000000",
  "visibility": {                                // present for list filtering
    "kind": "all",                               // "all" | "customerIds" | "none"
    "customer_ids": ["ac3d..."],                 // present when kind == customerIds
    "fields": ["name", "redirect_uris"]          // optional field allow-list
  }
}
```

`visibility` maps to muninID's `Scope` result:

| `visibility.kind` | muninID `Scope` |
|-------------------|-----------------|
| `all` | `nil` (no tenant filter — all) |
| `customerIds` | `customer_ids` (filter `ListClients` to these) |
| `none` | empty slice (return nothing / 403) |

### Errors

| Status | Body `{ "error": ... }` | Meaning |
|--------|-------------------------|---------|
| `401` | `unauthorized` | Service token missing/invalid |
| `403` | `forbidden` | Service caller not allowed to use `/authz/check` |
| `400` | `invalid_request` | Missing `action`/`resource`/`subject.user_id` |
| `500` | `server_error` | PDP failure |

muninID treats any non-`200` (or transport error) as **deny** and logs it.

---

## 4. Mapping to solutrix-api internals

Implemented in `src/controllers/authzController.ts`, mounted at
`/api/v1/authz/check` (`src/routes/authzRoutes.ts`):

```
/api/v1/authz/check
  -> authMiddleware + requireServiceCaller        // S2S guard
  -> getEffectivePolicy(subject.user_id, subject.customer_id, scope)
  -> allow      = can(subject, action, resource, instance)
  -> visibility = getVisibility(subject, action, resource)   // for list calls
```

For non-superadmins to be allowed, solutrix needs grants for the `idp:*`
resources in `policy_template` / `role_permissions` (superadmin `*:*` already
covers them).
