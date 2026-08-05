# Second-Round Security Audit — aos-hub

> Round 2 (deep surfaces + regression-review of the round-1 fixes): 8 finders →
> 2 skeptics per finding → synthesis. 27 findings; 23 confirmed, 2 contested,
> 2 dropped. 64 agents. **Run AFTER the 10 round-1 fixes landed** — examines the
> current post-fix code.

## 1. Overall assessment

Round 1 closed 26 issues, but **residual risk is not yet acceptable**: the
highest-value invariants — the C1/M1 mirror-and-pull-through verification
guarantee, RPC read authorization, and SSO enforcement — each still have a live
bypass in the post-fix code. **Two round-1 fixes are incomplete/bypassable** and
are the top priority.

### (a) Round-1 fixes found INCOMPLETE / BYPASSABLE — fix first
- **C1 NAR verification is void for compressed NARs** (Critical, CR-1). The
  Ed25519 narinfo signature covers only the *uncompressed* `NarHash`; the crate
  has no zstd/xz decompression, so a compressed NAR is verified only against the
  *unsigned* `FileHash`, or — when `FileHash` is omitted — against nothing
  (`if file_hash.is_none() && nar_hash.is_none() { return DeepCheck::Ok; }`,
  validation.rs:896-898). A hostile/MITM'd upstream serves a backdoored
  `Compression: zstd` NAR under a genuinely-valid signature.
- **C1 verify-before-write is a verify-then-refetch TOCTOU** (High, H-1).
  `collect_nix_cache` verifies bytes, discards them, returns path strings; the
  copy phase re-fetches each path (independent GET) and writes it with no
  re-verification (mirror.rs:553-563). The narinfo/NAR class is not re-indexed,
  so the bytes that passed verification are never the bytes persisted.
- **Sudo gate omits the highest-value ops** (Medium, M-1). `require_sudo` covers
  only password-change / org-delete / registry-delete; token mint, SSO/IdP
  config, signing keys, and membership mutation are ungated.

### (b) New issues on the deep surfaces
- RPC read path skips the visibility gate the HTML path enforces; `ListBindings`/
  `ListProjects` have no auth at all (anonymous cross-tenant disclosure, leaks
  host filesystem paths). (H-2, H-3)
- `enforce_sso` is bypassable via password/passkey login. (H-4)
- Uncapped `.json()`/`.text()`/`.bytes()` reads of attacker-controlled bodies
  (OIDC, deep validation, frontend probe) → OOM DoS. (H-5, H-6, L-1)
- Non-atomic check-then-act races (last-owner, device approval, domain claim,
  OIDC identity collation). (M-2, M-3, M-4, M-6)

---

## 2. Findings by final severity

### CRITICAL

**CR-1 — Compressed NAR accepted against the unsigned `FileHash` (or against nothing).**
`validation.rs:882-911` (`verify_nar_bytes`), via `verify_nar_against_narinfo` at
`mirror.rs:513` (persisted) and `:754` (served). The signed fingerprint
`1;<StorePath>;<NarHash>;<NarSize>;<refs>` does **not** cover `FileHash`,
`FileSize`, `URL`, `Compression`. An attacker keeps the signed fields, sets
`Compression: zstd` + attacker `URL`/`FileHash` for a backdoored NAR; verified as
authentic on both pull-through and full-mirror. `verify=true` is the default.
**Fix:** for `Compression != none`, decompress per declared compression and
verify against the **signed `NarHash`**; `FileHash` may pre-screen but is never
authoritative; fail closed when no signed `NarHash` can be checked.

**CR-2 — RPC `create_org` skips slug-charset validation → instance-root / victim-org Owner.**
`rpc.rs:559-593`; scope normalization `domain/iam.rs:237`. The console rejects
slugs outside `[A-Za-z0-9_-]`; the RPC checks only `is_empty()` and passes the
slug verbatim into `orgs.slug` and `grant_membership(.., slug, Role::Owner)`.
`Scope::parse` trims `/`, so slug `"/"` → empty **root** scope → Owner over
*everything*; `"/victimorg"` → Owner over `victimorg` (no UNIQUE collision on the
distinct string). Reachable by any authenticated principal (open signup) or any
member/service-account (invite_only). No DB-layer backstop.
**Fix:** apply `main.rs:validate_slug` in RPC `create_org` before create/grant;
better, centralize in `Database::create_org`/`grant_membership`.

### HIGH

**H-1 — Full-mirror verify-then-copy TOCTOU (narinfo/NAR class).** `mirror.rs:172-177,
470-524, 552-565`. Verify discards bytes; copy re-fetches + writes unverified;
the re-index covers only the git surface (no narinfo/NAR refs), so poison
persists. **Fix:** retain verified bytes and write exactly those, or re-verify
narinfo/NAR (and loose-object oid) inside `copy_path`. Compounds with CR-1.

**H-2 — Package/Channel/Registry read RPCs skip `require_read`.** `rpc.rs:1105,
1141, 1199, 1229, 375`. Unauthenticated `ListPackages {"slug":"victim/internal"}`
returns the full private inventory (store_path, nar_hash, sizes); `GetChannel`/
`ListChannels` leak signed-release maps; `ListRegistries` enumerates every
record (incl. soft-deleted) with source_url/trust_keys/roster. **Fix:** add
`require_read` after `registry_or_not_found`; filter+drop in `list_registries`.

**H-3 — `ListBindings`/`ListProjects` have no auth, leaking host filesystem paths.**
`rpc.rs:800-826, 709-734`. Only `org_or_not_found`, no claims/permission;
`list_bindings` returns `root` (on-disk `local_fs` path). `ListOrgs` is also
unauthenticated → enumerate orgs, then harvest storage roots + project trees
across all tenants. **Fix:** gate with `require_claims` + `require_permission`;
never return `root` to non-admins.

**H-4 — `enforce_sso` bypassable via password / passkey login.** `console.rs:454,
965, 678`; the only `enforce_sso` gate is `login_submit` (:328-340). Password/
passkey login never consult the policy, and `account_set_password` lets a member
of an SSO-enforced org create a durable local credential → survives IdP
deprovisioning. **Fix:** at password/passkey login resolve the user's capturing
orgs; if any has `enforce_sso`, refuse the local credential and redirect to OIDC;
refuse local-credential enrollment for SSO-enforced orgs.

**H-5 — OIDC token + JWKS responses deserialized with unbounded `.json()` (OOM).**
`auth/oidc.rs:462, 530`. `token_endpoint`/`jwks_uri` are tenant-admin-controlled,
not passed through `is_safe_remote_url`, and read with bare `.json()`. A
malicious/MITM IdP streams multi-GB → OOM. **Fix:** `read_body_capped` +
`serde_json::from_slice`; cap `jwks.keys`; `is_safe_remote_url` at config write.

**H-6 — Deep/integrity validation reads attacker-chosen narinfo/NAR uncapped.**
`validation.rs:1312, 1332, 1350`. Cache endpoints come from the
producer-controlled `[cache_stack]`; the deep/integrity probe reads use bare
`.text()`/`.bytes()`. `validate run --depth integrity|deep` → OOM. **Fix:**
`read_text_capped`/`read_body_capped`. (The auto-scheduled path is Presence/
HEAD-only and does NOT reach these — operator-triggered only.)

### MEDIUM

- **M-1 — sudo gate omits credential/trust ops.** `console.rs:2962 (tokens_create),
  3804 (org_sso_action), 3425 (org_keys_action), 1441/1831 (member ops)`. Extend
  `require_sudo` to "mints a credential or changes who/what is trusted."
- **M-2 — last-owner guard is non-transactional check-then-act.** `console.rs:1463,
  1866`; `db/mod.rs:5630`. Concurrent demotes can zero out owners. Wrap in
  `with_tx`, re-assert `>=1 owner`.
- **M-3 — `approve_device` select-then-mint non-atomic (double-minted token).**
  `db/mod.rs:5812-5853`. Claim with a single guarded `UPDATE ... WHERE
  approved_by_user IS NULL`, mint in the same tx.
- **M-4 — `add_org_domain` check-then-upsert race (cross-tenant SSO login-DoS).**
  `db/mod.rs:6099-6122`. Wrap read+write in `with_tx` (the H7 guard is correct
  serially but racy). (Takeover arm is gated by instance-operator verification;
  impact is resetting a victim's verified domain.)
- **M-5 — Pull-through narinfo not bound to the requested `<hash>.narinfo`.**
  `mirror.rs:727-756`. Assert `store_hash(StorePath) == requested hash` (and NAR
  `URL` == served path) → blocks signed-but-wrong-package downgrade/substitution.
- **M-6 — OIDC `(issuer, subject)` over case-insensitive VARCHAR on MySQL.**
  `db/dialect.rs:252-254`; `db/mod.rs:6609`. Case-variant `sub` collides →
  identity takeover on the mysql backend. **Fix:** `COLLATE utf8mb4_bin`.
- **M-7 (→ Low) — security TEXT columns get case-folding collation on MySQL.**
  Consistency defect; takeover arm neutralized by the verified-domain gate. Same
  fix as M-6 + a dialect contract test.

### LOW

- **L-1 — Frontend probe reads `info/refs`/`nix-cache-info` uncapped** (`probe.rs:317,
  340, 180`). Route through capped helpers.
- **L-2 — Mirror full-closure object walk uncapped** (`mirror.rs:281, 384-406`).
  `collect_tree_objects` has no object-count / inflated-byte cap (unlike
  `load_registry_tree`). Add caps.
- **L-3 — `CreateOrg` has no rate limit / per-user cap** (`rpc.rs:559`). (Default
  is InviteOnly, not open.) Add a per-principal limit/cap.
- **L-4 — `/activate` device endpoints have no rate limit (user_code enumeration)**
  (`console.rs:1019-1095`). Add a rate-limit class keyed on session+IP.

### DROPPED — not exploitable (informational)
- **Publish-pointer flip vs inline re-index not atomic** — crosses no trust
  boundary; objects land immutable-first, served bytes are signature-verified,
  `apply_snapshot` writes the index atomically, no authz gates on indexed-yet. A
  benign self-healing eventual-consistency artifact.
- **Committed-roster revocation doesn't prune a pinned key** — finding as written
  is wrong (`[[revoked]]` has no key blob; revocation = absence from active
  roster). Real residual: the trusted set is additive, not replaced; if acted on,
  fix = *replace* the trusted set with the active roster on the hub path.

---

## 3. Confirm before shipping (must-fix)

1. **CR-1** — decompress compressed NARs, verify against the signed `NarHash`;
   never accept compressed-NAR against `FileHash`-only or nothing.
2. **CR-2** — slug-charset validation in RPC `create_org` (+ `Database::create_org`/
   `grant_membership`) before granting Owner.
3. **H-1** — full-mirror copy writes the verified bytes (or re-verifies in
   `copy_path`); fix together with CR-1.
4. **H-2 + H-3** — `require_read` on the read RPCs + filter `list_registries`;
   `require_claims`+`require_permission` on `list_bindings`/`list_projects` and
   stop returning `root`.
5. **H-4** — enforce `enforce_sso` on password/passkey login; refuse local-cred
   enrollment for SSO-enforced orgs.
6. **H-5 + H-6** — capped body reads for OIDC token/JWKS and deep/integrity
   validation; cap JWKS key count.

Strongly recommended same release: **M-1** (sudo on credential/trust ops),
**M-2/M-3/M-4** (wrap the check-then-act races in `with_tx`), **M-5** (bind
narinfo to requested hash), **M-6** (`COLLATE utf8mb4_bin`).

---

## 4. Completeness critique — residual gaps beyond the application layer

**New issues found in the targeted sweep:**
- **A — Postgres backend is hardcoded cleartext (`NoTls`); DB URLs (with passwords)
  leak into error logs.** `src/db/backend/postgres.rs:16,35` — `Client::connect(url,
  NoTls)`, no TLS path at all; `with_context(|| format!("connecting to postgres
  {url}"))` embeds `postgresql://user:pass@host/db` into error chains. mysql.rs:42-44
  same leak, TLS unenforced. **High for the DB-transport posture.**
- **B — OIDC token/JWKS fetch: no SSRF revalidation at config-write, no body cap**
  (`auth/oidc.rs:454-462, 523-530`) — same as H-5; the only SSRF defense is the
  ValidatingResolver. `redirect(Policy::none())` also breaks IdPs that legitimately
  redirect their token endpoint (correctness).
- **C — DB backends have no reconnect/pool/health-check** (`db/backend/postgres.rs:22`,
  `mysql.rs`) — one `Mutex<Client>`; a dropped connection is a permanent outage
  until restart, and the global lock serializes all DB access.

**Named gaps for a next round / sign-off:**
- KMS / key lifecycle for `seal.rs` (no rotation, no versioned blob, no perms check
  on read; one AES-GCM key unseals everything).
- The on-CDN SPA + **Cloudflare Worker data-plane** — the single largest entirely
  unreviewed surface (worker authz, CSP, token storage, signed-URL/cache-key).
- `cargo audit` on the pinned tree; vet the `rsa` crate vs the Marvin timing
  advisory (RS256 OIDC verification).
- systemd/deployment hardening + config-file permission/precedence (DB URL with
  password in config).
- Constant-time token compares across `auth/token.rs`, `magic.rs`, `device.rs`.
