### Tenancy and IAM

```text
Organization   (tenant boundary; SSO/audit scope)
 └─ Project    (hierarchical, arbitrary depth — teams, environments)
     └─ Registry   (one git surface + one cache surface, backed by a
                    StorageBinding + prefix — see "Storage")
```

- **Principals**: users (humans), service accounts, and tokens.
  **Service accounts** are token-only principals — no sessions, no
  email, created by org admins with explicit role grants (CI publishers
  being the canonical case). The token-ownership rule applies to them
  unchanged: their tokens clamp to the service account's current
  grants, and deleting the account deadens every token it owns. They
  appear in audit as `sa:<org>/<name>`.
- **Roles**, grantable at org, project, or registry scope and inherited
  downward, expanding to permission verbs (`read`, `publish`,
  `channel.advance`, `keys.manage`, `tokens.self`, `tokens.manage`,
  `members.manage`, `registry.configure`, `storage.manage`,
  `validation.repair`, `audit.read`, `iam.admin`):

  | Role | Grants |
  | --- | --- |
  | `owner` | everything incl. delete, ownership transfer, IAM |
  | `admin` | members, tokens, registries, frontends, signing keys |
  | `maintainer` | publish, tag, advance channels, manage rosters |
  | `developer` | read private registries, self-service tokens |
  | `viewer` | read-only |

- **Visibility** per registry: `public` (anonymous read — the Debian
  case), `internal` (any org member), `private` (explicit grants).
- Every mutating action lands in an append-only `audit_log` carrying
  the actor, scope, a `change_id` (see "Configuration management"),
  and — where applicable — the resulting git commit/tag hash, so the
  audit log cross-references the cryptographic history rather than
  replacing it.

The registry's own trust model is unchanged and remains beneath the
hub: signatures verify against the roster regardless of what the hub's
IAM says. Hub IAM controls *who may use the hub's write paths*; the
roster controls *what consumers accept*.

### Authentication: sessions, tokens, SSO

Two principal planes that never cross:

- **Humans** get cookie sessions (`__Host-aos_session`, opaque 256-bit
  random, `Secure; HttpOnly; SameSite=Lax`; only the SHA-256 of the
  session id is stored — the same high-entropy-secret rationale as
  `aos-server`'s token store). Native: a `sessions` table. Workers: KV
  with native TTL plus a D1 row for enumeration and "revoke all
  sessions"; KV is eventually consistent, so revocation tombstones D1
  and destructive operations re-check it. Defaults: 7-day idle
  timeout, 30-day absolute lifetime (the KV TTL). Sessions carry an
  `auth_level` enabling **sudo mode**: destructive operations require
  re-authentication within the last 10 minutes. Human authorization is
  computed from `memberships` per request — role changes take effect
  immediately, no static scopes.
- **Machines** keep the existing `aos-server` pattern
  (`crates/aos-server/src/auth.rs`, `tokens.rs`): `aos_`-prefixed
  provisioning tokens, hashed at rest, exchanged at `/oauth2/token` for
  short-TTL JWTs — with scope generalized from `views` to
  `{path_prefix, permissions[]}` (e.g. `acme/infra/prod` +
  `["read","publish"]`). One strengthening: **tokens are owned by a
  principal, and effective permissions = token grants ∩ the owner's
  *current* grants** — removing a member instantly deadens every token
  they minted; no revocation sweep needed. Cookies are never accepted
  on machine paths; bearer tokens never establish a human session. The
  rotation-grace bug noted in `tokens.rs`'s own docs (grace window
  recorded but not honored) is fixed in the hub's implementation.

**Human auth methods** (assessed against both runtimes; build-level
verification of the wasm claims is part of the phase-1/2 spikes):

- **Email magic links** — v1 baseline and the recovery path. SMTP via
  `lettre` natively; an HTTP mail API behind a `Mailer` trait on
  Workers (no raw TCP).
- **Passkeys/WebAuthn** — v1. `webauthn-rs` cannot ship on the Workers
  target today (OpenSSL backend; server-side WASM is an open upstream
  issue), so the plan is a small in-house RP verifier with a hard
  `attestation: "none"` policy — which deletes the hard 80% of WebAuthn
  (the attestation-format zoo) and leaves clientDataJSON checks,
  authenticatorData parsing, COSE key decode, and ES256/Ed25519/RS256
  signature verification on already-wasm-proven RustCrypto crates.
  `webauthn-rs` remains the native-only fallback if the spike fails.
- **Passwords — never.** No credential-stuffing surface, no
  memory-hard-KDF-vs-Workers-CPU-budget problem, no reset flows beyond
  the magic link that must exist anyway.
- **Per-org OIDC SSO** — phase 3. The `openidconnect` crate is
  wasm-clean by construction (pure-RustCrypto JWS verification,
  pluggable `AsyncHttpClient` — implemented over `worker::Fetch` on
  Workers and `aos-net`/hyper natively). Authorization-code + PKCE
  always; per-org IdP config with encrypted client secrets;
  **domain capture** (email-first login: `user@acme.com` routes to
  acme's IdP when `acme.com` is DNS-TXT-verified, forced if the org
  sets `enforce_sso`); JIT provisioning keyed on `(iss, sub)` — never
  bare email — with auto-linking only for IdP-verified emails on
  captured domains; `groups_claim` → role mapping re-evaluated on every
  SSO login. SCIM deprovisioning is explicitly later; `enforce_sso`
  orgs mitigate with short absolute session lifetimes.
- **SAML — permanently out of scope.** No credible Rust/wasm story;
  orgs bridge through an OIDC-capable IdP or proxy (Dex, Okta/Entra
  OIDC apps).

**CLI login** is the OAuth device-code flow (RFC 8628):
`apr login https://hub.example.com` → anonymous, rate-limited
`POST /oauth2/device_authorization` → the user approves at
`/activate` in any authenticated session → the approval mints a
provisioning token **owned by the approving user**, scope clamped to
≤ that user's grants, delivered through the standard polling exchange
and written to `[registry.upload_auth]`.

**CSRF** for Connect-JSON endpoints, layered: cookie-authenticated
Connect calls require the `Connect-Protocol-Version` header (forms
can't send it; cross-origin XHR with it triggers a preflight rejected
by strict same-origin CORS), plus `Origin`/`Sec-Fetch-Site` validation;
the no-JS SSR form pages carry a per-session synchronizer token; bearer
requests need no CSRF defense (no ambient credential).

### Access matrix

Anonymous vs authenticated follows **registry visibility, not page
type** — on a `public` registry every read-only surface is anonymous,
including machine paths:

| Surface | `public` | `internal` | `private` |
| --- | --- | --- | --- |
| Browse pages (home, packages, channels, releases, git log/diff), raw autoindex | anonymous | org member (viewer+) | explicit grant |
| Machine paths: nix-cache + dumb-HTTP git | anonymous | bearer token with `read` at scope | same |

Search is not a per-registry surface: results are filtered
registry-by-registry to what the caller could read — anonymous callers
see public registries only. Global package search across orgs is
public-only by definition.

Always authenticated: org/project dashboards and member lists
(viewer+), audit feed (admin+), publish console and upload-credential
minting (maintainer+), channel advance (maintainer+ with reviewed signing-key
custody resolution; external-custody users prepare advances for CLI signing, see
"Configuration management"), validation repair jobs (maintainer+,
`validation.repair`), roster mutations (maintainer+; the roster itself
is *readable* per visibility — it is public data on a public registry),
signing-key enrollment/rotation/usage/retirement (admin+), own-token management (developer+),
others' tokens (admin+), registry/frontend/storage/cache-store
configuration (admin+ at parent, `storage.manage`), org
delete/ownership transfer (owner; last-owner removal is hard-blocked).
ConnectRPC services map method-by-method onto the same matrix.
