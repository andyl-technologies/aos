# Hub tenancy, authorization, and authentication

This page describes who can act in a Hub and how: the tenancy hierarchy, the
pure authorization kernel, the credentials each principal holds, and the audit
trail. Operator procedures are in
[Trust an internal AOS Hub deployment](../../users/aos-hub/trust.md) and
[Operate AOS Hub in production](../../users/aos-hub/production.md).

## Tenancy

```text
Instance
 └─ Organization        tenant boundary; SSO, audit, and quota scope
     └─ Project         hierarchical, arbitrary depth (teams, environments)
         ├─ Registry    signed catalog surface
         └─ Binary cache
```

A project locates itself inside its organization by a materialized path of
ancestor project names. Registries and caches may also sit directly under an
organization or, for an instance-level unowned public registry, outside any
organization. Membership is open by invitation: a user may create their own
organization subject to the instance signup policy and a per-owner cap, and
joins others by accepting an invitation.

## Principals

There are two grantable principal kinds (`crates/hub/aos-hub-model/src/domain/mod.rs`):

- **users** — humans with sessions, email, and optional SSO identities; and
- **service accounts** — token-only principals created by organization
  administrators with explicit role grants, for example for publishing
  automation.

Tokens and sessions are owned by a principal; they are not principals
themselves.

## Authorization kernel

Authorization is a pure, IO-free function shared by both runtimes
(`crates/hub/aos-hub-model/src/domain/iam.rs`). A grant is a `(scope, role)`
pair, and `allow` returns true when some grant's scope is in the target's
ancestor closure and the grant's role confers the requested permission.

Scopes are stable identities, never slugs or paths, so renames and reparenting
do not change authorization:

```text
scope         := "instance"
               | "org:" lower_hex_32
               | "project:" lower_hex_32
               | "registry:" lower_hex_32
               | "cache:" lower_hex_32
lower_hex_32  := 32 lowercase hexadecimal digits
```

Scope keys carry no hierarchy; the validated ancestor closure is loaded from
`authorization_scope_ancestors`, which makes every inheritance decision explicit
and auditable.

Roles form a five-rung ladder, each expanding to a fixed permission set
(`role_grants`):

| Role | Permissions |
|---|---|
| `owner` | Every permission, including IAM administration. |
| `admin` | Members, token management, registry, delivery, and storage configuration, audit read, plus the read and self-token baseline. |
| `maintainer` | Publish, channel advance, and roster (key) management, plus read and self-tokens. |
| `developer` | Registry read, specialized topology reads, and self-service tokens. |
| `viewer` | Registry and specialized topology reads only. |

Topology resources have read, manage, and grant permissions of their own
(bindings, placements, placement policies, domains, network policies,
endpoints, gateways), so access to a credential-bearing binding can be granted
without granting registry administration.

## Credentials

All high-entropy secrets are stored only as SHA-256 hashes
(`crates/hub/aos-hub-model/src/auth/`).

| Credential | Holder | Shape and lifetime |
|---|---|---|
| Provisioning token | User or service account | `aos_` plus 40 hex characters; shown once at creation or rotation. A rotated token's old secret remains valid for a one-hour grace period. |
| Access token | Client | Short-lived HS256 JWT minted at `POST /oauth2/token` from a provisioning token. It carries the owner, stable scope, and explicit permission verbs, so request gates decide without a database read. |
| Session cookie | Browser user | 256-bit opaque secret in `__Host-aos_session` (`Secure; HttpOnly; SameSite=Lax; Path=/`); 7-day idle and 30-day absolute lifetime. A session is sudo-capable for 15 minutes after re-authentication, which destructive operations require. |
| Device grant | CLI login | OAuth device authorization at `/oauth2/device_authorization`: the CLI polls with a 64-hex device code while the user approves a short user code at `/activate`; approval mints a provisioning token clamped to the approver's grants. |

Browser sessions sign in with any of these methods, all served by the shared
router on both runtimes (`crates/hub/aos-hub-service/src/auth/`):

- **Magic links** — single-use, emailed links that prove mailbox control; also
  the account recovery path.
- **Passwords** — Argon2id PHC hashes with constant-time verification.
- **Passkeys** — a first-party WebAuthn relying party that accepts only
  `attestation: "none"` and verifies Ed25519, ES256, and RS256 COSE keys.
- **Per-organization OIDC SSO** — one identity provider per organization,
  authorization code with PKCE and JWKS-backed RS256 ID-token verification.
  Email-first login routes an address in a captured domain to that
  organization's provider.

The console's browser application exchanges its session and CSRF token for an
in-memory bearer at `POST /-/auth/session-token` and then calls the same API as
the CLI.

## Audit and offboarding

Every mutation records an append-only audit entry: who did what, at which
scope, with cross-references to the configuration change-set and any git
history it produced (`AuditService`). Organization deletion is a soft delete
with a grace window; a purge job hard-deletes expired organizations, and an
organization export contains token metadata but never usable credentials. A
user cannot be deleted while they are the sole owner of an organization.
