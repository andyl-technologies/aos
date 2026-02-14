# Authentication & Authorization

### 5.1 Two-Layer Token Model

**Provisioning secrets** (long-lived) are exchanged for **access tokens**
(short-lived JWTs) via an OAuth2 Client Credentials endpoint. This gives us:
- Immediate revocation (delete the provisioning secret → all derived access
  tokens become unissuable; existing ones expire within 1 hour)
- Stateless API auth (JWTs verified by signature, no DB lookup per request)
- Audit trail (provisioning token usage is logged)

```
Provisioning secret (long-lived, stored in SQLite)
    │
    │  POST /oauth2/token (Client Credentials grant)
    ▼
Access token (JWT, 1-hour expiry, HMAC-SHA256 signed)
    │
    │  Authorization: Bearer {access-token}
    ▼
API endpoints (narinfo, NAR, build, etc.)
```

### 5.2 Local Unix Bootstrap

Provisioning secrets are created **locally** via a Unix socket — no network
round-trip, no admin API. Only root or members of an `aos-admins` group can
create tokens:

```sh
# On the server machine (requires root or aos-admins group membership):
$ aos token create --view ci --permissions read,build --expires 90d

Token:    aos_ci_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p
Expires:  2024-04-01

Store this token securely. It will NOT be shown again.
```

**Mechanism**: `aos token create` connects to `/run/aos/bootstrap.sock`
(Unix domain socket created by `aos serve`). The server validates `SO_PEERCRED`
to get the caller's uid/gid. Authorization:

- `uid == 0` → always allowed (root)
- `gid ∈ aos-admins` → allowed
- Otherwise → rejected (permission denied)

Per-view scoping: `--view ci` can be further restricted by configuring which
local users/groups may create tokens for which views.

### 5.3 OAuth2 Token Endpoint

```
POST /oauth2/token
Authorization: Bearer {provisioning-secret}
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials

Response 200:
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read build"
}
```

The access token is a JWT signed with the server's HMAC-SHA256 secret:
```json
{
  "sub": "token-id-uuid",
  "views": ["ci"],
  "permissions": ["read", "build"],
  "iat": 1706000000,
  "exp": 1706003600
}
```

API middleware validates the JWT signature and checks `views` + `permissions`
claims against the requested endpoint. No database lookup needed.

### 5.4 Token Storage (SQLite)

Provisioning secrets are stored in a separate SQLite database at
`/var/lib/aos/meta/tokens.db` (NOT the store DB):

```sql
CREATE TABLE provisioning_tokens (
  id TEXT PRIMARY KEY,
  hash TEXT UNIQUE NOT NULL,       -- SHA-256 of plaintext token
  views TEXT NOT NULL,              -- JSON: ["ci"] or ["*"]
  permissions TEXT NOT NULL,        -- JSON: ["read", "build"]
  created_at INTEGER NOT NULL,
  created_by_uid INTEGER,           -- uid from SO_PEERCRED
  expires_at INTEGER,               -- nullable = no expiry
  revoked_at INTEGER,               -- nullable = active
  comment TEXT
);
```

> **Security note — file permissions**: All files in `/etc/aos/` must be owned
> by `aos-serve` or root with mode `0600`. The JWT secret and signing key are
> sensitive cryptographic material and must not be readable by unprivileged
> users. The bootstrap socket `/run/aos/bootstrap.sock` should be created with
> mode `0660` owned by `aos-serve:aos-admins` to restrict token provisioning to
> authorized administrators.

### 5.5 Token Lifecycle

```sh
# Create a new provisioning secret:
aos token create --view ci --permissions read,build --expires 90d

# List active tokens:
aos token list
# ID                    View  Permissions  Created     Expires     Last Used
# abc123-uuid           ci    read,build   2024-01-03  2024-04-01  2024-01-15

# Revoke immediately:
aos token revoke --token-id abc123-uuid --reason "suspected compromise"

# Rotate (new token, old one expires in 1 hour grace period):
aos token rotate --token-id abc123-uuid
```

### 5.6 Anonymous Access

Views can optionally allow anonymous reads (no token needed for GET):

```toml
[[views]]
name = "public"
anonymous_read = true
```
