# Security Audit Report: aos-hub

> Adversarial review (2026-06-14): 10 attack-surface finders → 2 diverse skeptics
> per finding (refute on reachability + on mitigation) → synthesis. 31 distinct
> findings; 26 confirmed, 5 contested, 0 refuted. 74 agents.

## Overall assessment

The implementation is **not airtight**. The core authorization kernel (the RPC
token-vs-live-grant intersection, the per-key-variant WebAuthn dispatch, the
read-side symlink containment, the SSRF allowlist) is genuinely well-built, and
several "findings" against it are sound-by-design. But residual risk is
concentrated in three places, two flatly exploitable today:

1. **Trust boundaries the data plane is supposed to enforce are missing.** Both
   full-mirror sync and pull-through copy/serve attacker-controlled narinfos and
   NARs with **zero** signature or hash verification — contradicting the module's
   own "a mirror is a byte courier, not a trust party" invariant. Worst class of
   bug in the codebase.
2. **The IAM ladder has a vertical-escalation hole and OIDC trusts asserted
   email.** A plain org Admin can self-promote to Owner; a hostile org's IdP can
   JIT-link to any existing user by email. Both are full-takeover primitives
   reachable by a low-trust org admin.
3. **Producer-controlled content executes same-origin on the authenticated hub,
   and one unauthenticated input crashes the whole process.** The CSP relaxation
   keys on filename, not provenance, and the `?filter=` parser has unbounded
   recursion.

Session/CSRF machinery is mostly sound (the CSRF synchronizer token correctly
defeats cross-site forgery), but there is **no step-up (sudo) gate** and **no
real idle/absolute session timeout**, so a stolen cookie has a long, unconstrained,
fully-privileged life — defense-in-depth gaps, calibrated down accordingly.

---

## Critical

### C1. Full-mirror sync copies narinfos and NARs with no signature/hash verification, then serves them immutable for a year
- **Location:** `src/mirror.rs:335-348, 417-450, 472-479`
- **Attack:** A hostile/MITM'd upstream serves a validly-signed git surface plus a
  tampered `foo.narinfo` pointing at a backdoored `nar/evil.nar.zst`.
  `collect_nix_cache` runs **unconditionally** (not inside the `if verify` blocks
  that gate the commit/tag checks), pushes the narinfo and its `URL:`-named NAR
  into `VerifiedSurface.immutable` with no `Sig:`/`NarHash`/`FileHash` check, and
  `copy_path → write_atomic` writes them byte-for-byte into the local binding. The
  re-index only walks the git surface, so it never re-checks. `compat.rs` then
  serves the NAR with `max-age=31536000, immutable`. The scheduler drives this with
  no operator action and records `last_sync_status = ok`. Result: durable
  distribution of an attacker-chosen package binary to every mirror consumer.
- **Fix:** Before copying any narinfo, verify its Ed25519 `Sig:` against the
  registry trust roster. Before copying any NAR, verify its bytes against the
  narinfo's `FileHash`/`NarHash` via the existing `verify_nar_bytes()`
  (`validation.rs:870`). Gate `collect_nix_cache` on `verify` like the git checks,
  and **fail the whole sync writing nothing** on any mismatch.

---

## High

### H1. members.manage holder can grant any role, including Owner — vertical privilege escalation
- **Location:** `src/console.rs:1696-1744` (`org_member_role`), `1244-1291`
  (`org_invite_member`); `src/config/mod.rs:673-732` (`change_membership`)
- **Attack:** `role_grants(Admin)` includes `MembersManage` but **not** `IamAdmin`.
  Both handlers gate solely on `MembersManage`, then pass the caller-supplied `role`
  (which `Role::parse` resolves to `owner`) into `grant_membership` (a raw
  `INSERT ... ON CONFLICT DO UPDATE SET role = excluded.role`) with **no
  `actor_role >= granted_role` ceiling**. The last-owner block is conditioned on
  `role != Owner`, so *raising* to Owner bypasses it. A malicious org Admin POSTs
  `/-/org/{org}/members/role` with `principal_id=self, role=owner` and becomes Owner.
- **Fix:** Load the actor's effective role at the target scope; reject any grant
  whose `role.rank()` exceeds the actor's (and forbid raising one's own membership).
  Enforce centrally in `change_membership`. Only `IamAdmin`/Owner may create/modify
  an Owner grant.

### H2. OIDC JIT provisioning links a hostile IdP's asserted email to an existing victim account (cross-org takeover)
- **Location:** `src/db/mod.rs:6406-6419` (`link_or_create_identity` step 3), from
  `src/auth/oidc.rs:473-485`
- **Attack:** Step 2's anti-takeover guard only auto-links a verified email whose
  domain is captured-and-verified by the org. Step 3 (JIT, `allow_jit` + new
  `(iss,sub)`) defeats it: it calls `find_or_create_user(asserted_email)`, which
  **returns any pre-existing user with that exact email** — no `email_verified`, no
  domain-capture check. An org Admin controls issuer/jwks/`allow_jit`/`role_map` via
  set-idp, stands up an IdP asserting `email=ceo@othercorp.com`, and the new
  `(iss,sub)` links to the victim's existing row and mints an `auth_level=1` session
  **as the victim**, inheriting all their grants across all orgs.
- **Fix:** In JIT, never reuse an existing user by email. Create-new-only, or require
  the same verified-email + captured-domain gate as step 2 before linking.

### H3. Hostile-registry web surface executes producer JS same-origin on the authenticated hub
- **Location:** `src/compat.rs:122-130` (`web_surface_csp`), `138-207`
  (`serve_machine_path`); `src/auth/session.rs:45-48` (cookie `Path=/`)
- **Attack:** Registry machine surfaces are served same-origin at `/{slug}/<path>`.
  A producer (only `Permission::Publish`) PUTs arbitrary bytes to `index.html`,
  `browse/*.html`, `web/*.js` (the upload facade checks only `is_machine_path` +
  size), then makes the registry `public`. `web_surface_csp` stamps those paths with
  `script-src 'self' 'wasm-unsafe-eval'`, so producer `web/evil.js` executes in the
  hub origin. A lured logged-in admin loading `/{slug}/index.html` runs producer
  script that fetches `/account`, scrapes the per-session CSRF token, and POSTs
  authenticated mutations as the victim. No cookieless origin, no `sandbox` CSP, no
  `Origin`/`Sec-Fetch-Site` check.
- **Fix:** Don't serve producer-controlled HTML/JS on the authenticated cookie
  origin: serve from a separate cookieless sandbox origin, **or** `CSP: sandbox` +
  `Content-Disposition: attachment` for producer `.html` and never apply
  `script-src 'self'` to producer paths. **Subsumes M5 and L2's framing fix.**

### H4. Webhook delivery URLs bypass the SSRF guard entirely
- **Location:** `src/webhook.rs:310-324`; `src/rpc.rs:1278-1289`;
  `src/console.rs:3490-3510`; `src/db/mod.rs:6882-6900`
- **Attack:** Mirror/frontend URLs go through `is_safe_remote_url`; webhook URLs
  never do. Both `create_webhook` paths reject only an empty URL and store it
  verbatim; `deliver_one` POSTs straight to it. An org admin registers a webhook at
  `http://169.254.169.254/...` or `http://127.0.0.1:8500/...`, triggers an event,
  and the worker POSTs from inside the hub network — blind SSRF against metadata /
  Consul / etcd / internal ports.
- **Fix:** `is_safe_remote_url` on the webhook URL at create (both paths) and again
  in `deliver_one` before the POST. Use a no-redirect, address-validating connector.

### H5. Outbound HTTP client follows redirects without re-validating the target
- **Location:** `src/fetch.rs:129-138` (`hardened_client`); sinks at `230-252`,
  `mirror.rs:141`, `server.rs:1320` (pull-through), `probe.rs:293`
- **Attack:** `hardened_client()` sets only timeouts — no redirect policy — so
  reqwest follows up to 10 redirects. `is_safe_remote_url` validates only the
  configured base; the redirect target is never checked. An upstream answers with
  `302 Location: http://169.254.169.254/...` and the hub follows it. The pull-through
  sink is reachable **unauthenticated**.
- **Fix:** `.redirect(reqwest::redirect::Policy::none())` on `hardened_client()`, or
  a custom policy that runs each hop's resolved address through `is_global_ip`.

### H6. Unbounded recursion in the `?filter=` parser/evaluator crashes the whole process
- **Location:** `src/filter.rs:379-400` (`parse_unary`/`parse_primary`), `434-455`
  (`eval`); from `src/server.rs:827/834`
- **Attack:** No depth counter, no input-length cap. An **unauthenticated** visitor
  GETs `/{slug}/-/packages?filter=` + ~50k–100k `(` (within hyper's ~64 KiB head
  limit, overflows the 2 MiB worker stack). Stack overflow is SIGSEGV/abort, which
  `CatchPanicLayer` cannot intercept — the entire multi-tenant process dies. A
  one-line curl loop keeps the hub down. (This is the same parser whose lone-operator
  infinite loop was fixed earlier; the recursion limit was missed.)
- **Fix:** Reject `?filter=` over a few KiB before tokenizing **and** thread a depth
  counter through the parser (`FilterError` past ~64). The length cap alone is the
  cheapest robust mitigation.

### H7. Any org admin can steal another org's verified email domain via add-domain ON CONFLICT
- **Location:** `src/db/mod.rs:5949-5958` (`add_org_domain`), from
  `src/console.rs:3768-3798`
- **Attack:** `add_org_domain` upserts `ON CONFLICT(domain) DO UPDATE SET org_id =
  excluded.org_id, ..., verified_at = NULL` with **no guard** that the row belongs to
  the same org. An admin of Org B submits `domain=acme.com` (verified by Org A); the
  row's `org_id` is silently rewritten to B and `verified_at` reset. **Immediate:**
  `org_for_domain` stops resolving acme.com, breaking Org A's SSO login routing
  (cross-tenant DoS / claim theft). The sibling `delete_org_domain` is correctly
  scoped `WHERE org_id = ?2`; this path is not.
- **Fix:** Pre-check `org_domain(domain)` and reject when `existing.org_id != org.id`
  (especially when verified), or scope the `ON CONFLICT` update to the same org.

---

## Medium

- **M1. Pull-through serves unverified narinfos/NARs** — `src/mirror.rs:541-554,
  584-623`. `fetch_through` returns both verbatim (only loose git objects get a hash
  check). Verify the `Sig:` and `FileHash`/`NarHash` before serving (same primitive
  as C1).
- **M2. Mirror takes the NAR path from the attacker-controlled narinfo `URL:` field**
  — `src/mirror.rs:454-467`. `narinfo_url()` accepts any relative path, letting a
  pointer file be written in the immutable phase. Constrain to `nar/` paths.
- **M3. `is_safe_remote_url` DNS-rebinding TOCTOU** — `src/fetch.rs:337-371`. Resolve
  → check → discard, then reqwest re-resolves at connect. Pin the validated IP to the
  socket (closes H5 too).
- **M4. Sudo / `auth_level` step-up is never enforced** — `src/db/mod.rs:5599-5604`;
  destructive handlers throughout `src/console.rs`. `auth_level`/`last_authenticated_at`
  are read nowhere; every login mints `auth_level=1`. No re-auth speed bump on
  destructive actions.
- **M4b. Password change requires neither re-auth nor sibling-session revocation
  (HIGH)** — `src/console.rs:636-677`. A stolen session can set a password (durable
  second login path), and a victim changing their password does **not** evict the
  attacker. Require re-auth/current password and call `revoke_all_user_sessions`.
- **M5. SPA CSP relaxation keys on filename, not provenance** — `src/compat.rs:122-130`.
  The enabler for H3; fix with H3.
- **M6. Browse/search is anonymous and unthrottled; `RateClass::BrowseSearch` is
  defined but never wired** — `src/server.rs:909-928`; `src/ratelimit.rs:84`. Wire it
  into `package_index`/`instance_home`/the nested packages branch.
- **M7. Whole-registry package list loaded fully into memory, no DB LIMIT, plus N+1**
  — `src/db/mod.rs:3129-3168`. Push filter/sort/paginate into SQL.
- **M8. Indexer parses an attacker-controlled tree with no package/closure cap** —
  `src/surface/load.rs:117-161`. Add `MAX_PACKAGES`/`MAX_CLOSURE_ENTRIES` like the
  tag/branch caps; a hostile producer can OOM-kill the hub via re-index.
- **M9. Session idle timeout and absolute lifetime are not enforced** —
  `src/db/mod.rs:5387-5418`. `last_seen_at` is written but read nowhere;
  `ABSOLUTE_LIFETIME_SECS` is dead. Sessions are a flat 7-day deadline.
- **M10. Password-login timing oracle: Argon2 verify runs only for existing accounts**
  — `src/console.rs:464-472`. Always verify against a fixed dummy PHC string so every
  path spends comparable time.

---

## Low

- **L1. Surface write paths don't enforce symlink containment (reads do)** —
  `src/facade.rs:344-413`; `src/mirror.rs:472-497`. Contested: needs a pre-existing
  out-of-root symlink (operator misconfig). Apply the read path's canonicalize check
  to writes.
- **L2. CSP `style-src 'unsafe-inline'` + no `frame-ancestors`/`X-Frame-Options`** —
  `src/compat.rs:127-128`. Clickjacking on the console/`/activate`. Add
  `frame-ancestors 'self'` and `X-Frame-Options: DENY`. (CSS-exfil vector is **not**
  real — `default-src 'self'` confines it.)
- **L3. CSRF token is a non-rotating SHA-256 of the session secret, compared
  non-constant-time** — `src/auth/extract.rs:280-288`. Contested/hardening: the token
  is bound to the requester's own session secret, so it's not a CSRF break. Use
  `subtle::ConstantTimeEq`; prefer HMAC with rotation.
- **L4. Full-mirror in-band roster rotation expands the trusted set with no
  audit/alert** — `src/mirror.rs:243-250`. Contested: runs only after a HEAD commit
  signed by a pinned anchor. Surface roster changes in audit; offer roster-pinning.
- **L5. Health deep-validation never checks the narinfo `Sig:`, samples only 16 NARs**
  — `src/validation.rs:870-899`. Operator-CLI-only. Add `Sig:` verification; document
  hash-only limits.
- **L6. Publish lease is process-local — breaks single-writer in multi-replica HA** —
  `src/facade.rs:140-183`. Back the lease with the shared DB.
- **L7. `AOS_HUB_ALLOW_LOCAL_REMOTES` disables the SSRF guard process-wide** —
  `src/fetch.rs:333-336`. Contested (test-only var). Gate behind
  `#[cfg(test)]`/`debug_assertions`; even `=0`/empty currently enables it.
- **L8. Rate-limiter does O(n) sweep + O(n) min-scan per new key under a distinct-key
  flood** — `src/ratelimit.rs:201-247`. Track insertion order for O(log n) eviction;
  prune lazily.

## Informational

- **N1. RPC `require_permission` is sound** — intersects JWT-claimed perms with live
  `effective_scopes`. No membership-mutation RPC exists, so H1 is console-only; fix at
  `change_membership` so any future RPC inherits the ceiling.
- **N2. WebAuthn dispatches on the stored key variant, not an attacker-supplied alg** —
  no `alg:none`/confusion path. Optional: reject keys whose `alg` is inconsistent with
  `kty`/`crv` at registration.

---

## Confirm before shipping (must-fix)

1. **C1** — Verify narinfo `Sig:` and NAR hashes in full-mirror sync; gate
   `collect_nix_cache` on `verify`; fail the sync on mismatch. (Also fixes M1, M2.)
2. **M1** — Verify narinfos/NARs in the pull-through serving path.
3. **H1** — Add an `actor_role >= granted_role` ceiling in `change_membership`.
4. **H2** — Stop JIT linking an asserted email to an existing user.
5. **H3 / M5 / L2** — Stop executing producer HTML/JS on the authenticated origin;
   add `frame-ancestors`/`X-Frame-Options`.
6. **H4** — Validate webhook URLs with `is_safe_remote_url` at create and before send.
7. **H5 / M3** — Disable redirect-following and pin the validated DNS address.
8. **H6** — Cap `?filter=` length and parser depth.
9. **H7** — Block cross-org overwrite in `add_org_domain`.
10. **M4b** — Make password change require re-auth and revoke sibling sessions.

---

## Completeness critique — under-examined surfaces (next round)

**New issues found in the targeted sweep:**
- **Redirect-following SSRF** (HIGH) — same as H5; `hardened_client` leaves the
  default redirect policy.
- **Unbounded list queries defeat API pagination** (MEDIUM) — `list_audit`
  (`db/mod.rs:6531`), `list_releases` (`:3460`), `list_packages` (`:3129`),
  `list_registries` (`:2148`) all `SELECT … ORDER BY` with no LIMIT; `rpc.rs:80`
  `paginate` skip/takes a fully-materialized Vec; `page_token` is a stringified
  offset that re-scans from the top each page.

**Named gaps not yet deep-dived:**
- **Dialect SQL rewriting on postgres/mysql** (`src/db/dialect.rs:120-265`) — textual
  `quote_reserved`/`rewrite_ddl_types`/`rewrite_upsert` rewriters run only on the
  least-tested (non-sqlite) path; check for `TEXT`→`VARCHAR(255)` truncation of
  security columns (tokens, OIDs, signer DNs) and any rewrite over attacker literals.
- **`HttpFetch` raw path interpolation** (`src/fetch.rs:231`) — `format!("{}/{path}")`
  with no `safe_join`/encoding; mirror sync derives segments from remote data.
- **Error-path information disclosure** — `{err:#}` chains surfaced to
  unauthenticated/cross-tenant callers (internal hostnames, store paths, DB text).
- **Untrusted deserialization** — `serde_json::from_*` on narinfo/`info/refs`/channel
  partitions/OIDC discovery/JWKS/JWT; recursion/size limits, ReDoS on config/remote
  regex.
- **ConnectRPC framing & limits** — no visible inbound body-size cap; decompression
  bombs; `OwnedView` allocation from attacker-sized messages.
- **Concurrency / TOCTOU** — lease handling, mirror "mutable pointers last", check-then-act
  in create_* RPCs.
- **Header / log injection** — actor labels/scopes/URLs into `audit_log.detail` and
  logs (CRLF/control chars), rendered back in the WebUI.
- **IPv4 range completeness** (`src/fetch.rs:396-403`) — `is_global_ipv4` misses
  100.64.0.0/10 (CGNAT), 192.0.0.0/24, 198.18.0.0/15, and the documentation ranges.
