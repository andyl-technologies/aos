# Third-Round Security Audit — aos-hub

> Round 3 (per-item review of the 7 formerly-deferred RFC-0004 surfaces):
> 7 attack-surface finders (one per deferred item) → 2 diverse skeptics per
> finding (reachability + existing-mitigation, drop only if BOTH refute) →
> completeness critic. 22 agents. **Run AFTER the round-1 and round-2 fixes
> landed** — examines the current post-fix code, scoped to the seven items the
> RFC originally deferred and that were implemented later.

## 1. Overall assessment

The seven deferred surfaces are in good shape: the two highest-assurance
invariants — *no forged/unsigned bytes are ever served as authentic*, and *no
hub-originated request reaches an internal host* — held across the WebAuthn,
change-request, and worker surfaces, and the per-item finders returned **zero**
findings for change-requests, WebAuthn, and the worker. Eight real issues were
confirmed (2 High, 5 Medium, 1 Low), clustered in the **validation/repair** and
**mirroring** paths plus two operations gaps and one SPA trust-UX divergence.
All eight are fixed in this change; every fix ships with a regression test (or,
where a live network/signing fixture is required, a precise `regression:`
comment pinning the invariant).

The two High findings share a root cause with the round-2 mirror work: a
*propagation* path (HTTP-cache repair) and a *probe* path (consistency
validation) each trusted bytes/targets that the canonical mirror path already
guards. The pattern — "a second code path that produces the same trusted state
as the audited one, minus a guard" — recurred (console create-org vs. RPC
create-org; repair-http vs. repair-file; pull-through NAR branch vs. narinfo
branch), and is the throughline of this round.

## 2. Findings

### HIGH

- **H1 — HTTP-cache repair propagated source narinfo/NAR onto the hub's trusted
  facade without verifying the narinfo signature** (`validation.rs`,
  `execute_repair_http`). The repair-into-an-authorized-facade path is the one
  place the hub *writes* cache bytes onto a surface consumers trust as
  authentic, yet it checked only `verify_nar_bytes` (NAR-vs-its-own-declared-
  hash), never `verify_narinfo_signature` against the trust roster — the exact
  laundering the mirror path forbids. A registry whose cache stack includes a
  MITM-able `http://` upstream and the hub's own writable facade could have a
  backdoored, self-consistent narinfo+NAR (for a store hash outside the
  predictable deep-sample) fetched and PUT onto the hub facade, then served to
  every consumer as authentic. The attacker-controlled `URL:` field was also
  unconstrained, allowing a repair PUT to be steered onto a channel/pointer
  path. **Fix:** verify the source narinfo `Sig:` against the registry roster
  and the NAR against the *signed* `NarHash` (fail-closed) before any PUT;
  constrain the propagated `URL:` to the conventional `nar/` location.

- **H2 — Consistency-validation and repair reads omitted `is_safe_remote_url`;
  literal-IP hosts bypass the validating resolver** (`validation.rs` probe/deep/
  integrity/repair-read helpers; `fetch.rs`). The hardened client's
  `ValidatingResolver` only vets DNS *names*, so a committed cache URL with a
  literal internal IP (e.g. `http://169.254.169.254/…`) was never checked — and
  this validation runs automatically on every reindex tick. A publisher (or a
  mirrored upstream's `caches.toml`) could drive blind SSRF to cloud-metadata or
  internal services. **Fix:** gate every http(s) cache read in `validation.rs`
  on `is_safe_remote_url` (fail-closed), matching the frontend probe path, and
  document/test the literal-IP call-site predicate in `fetch.rs`.

### MEDIUM

- **M1 — Console `POST /new` create-org bypassed the per-owner org cap and the
  `CreateOrg` rate limit** (`console.rs`). The RPC `create_org` enforces both
  `MAX_ORGS_PER_OWNER` and a per-principal rate limit; the parallel console
  handler enforced neither, so a session user could script unlimited org
  creation (each self-granting Owner). **Fix:** replicate both guards inline in
  `new_org_submit` with the RPC's exact rate-limit key derivation.

- **M2 — Org purge race: `hard_purge_org` deleted unconditionally** (`db/mod.rs`).
  The purge job lists purgeable orgs then deletes each with no transaction
  spanning list+delete; a concurrent `restore_org` landing in that window would
  be silently destroyed (cascading away the now-active org). **Fix:**
  re-assert the `deleted_at IS NOT NULL AND purge_after <= now` predicate in the
  `DELETE`, threading the *same* `now` the list used so one timestamp spans the
  tick.

- **M3 — Pull-through NAR branch omitted the StorePath-hash binding**
  (`mirror.rs`, `fetch_through` `PullClass::Nar` + `collect_nix_cache`). The
  signed narinfo fingerprint does **not** cover `URL:`, so a hostile upstream
  could serve a genuinely-signed narinfo for store hash `HASHY` (with only its
  `URL:` rewritten) under `HASHX`'s slot — passing the signature, URL, and
  NarHash checks while substituting content. The sibling narinfo branch already
  bound the store hash; the NAR branch did not. **Fix:** assert
  `store_hash(narinfo.store_path) == requested_store_hash` in both the
  pull-through NAR branch and the full-mirror `collect_nix_cache`.

- **M4 — In-browser verifier read `[[active]]` but the real `keys.toml` uses
  `[[keys]]`** (`aos-registry-spa/verify.rs`). The "Verify in your browser"
  badge — the security-UX centerpiece, claiming to run the *same* roster the
  server runs — parsed a table name no real registry emits, so it extracted zero
  keys and failed closed on every valid registry, training users to ignore the
  badge. **Fix:** match the `serde(rename = "keys")` table name the server
  format uses; update fixtures to the real spelling and add a cross-format
  regression test feeding the exact bytes the hub seed writer produces.

- **M5 — `execute_repair` (file://→file://) copied narinfo/NAR with no
  signature, no content-hash, and no path-containment on `URL:`** (`validation.rs`).
  A distinct, weaker repair path: raw `fs::copy` of a source-chosen narinfo and
  the NAR named by its attacker-influenced `URL:` field, with no `safe_join`/
  `ensure_within_root` — a `URL: ../../../…` escaped the cache root
  (arbitrary read/write). **Fix:** same trust gate as H1 plus `safe_join` +
  `ensure_within_root` against both source and target roots.

### LOW

- **L1 — Cache probe lacked the `is_safe_remote_url` pre-check** (`probe.rs`).
  The sibling of H2 in the lightweight freshness prober: `probe_one`/`probe_http`
  relied solely on the resolver, so a literal-IP cache URL slipped through as a
  blind-reachability SSRF. **Fix:** gate `probe_one` on `is_safe_remote_url`
  (record unsafe as `Unreachable`), matching `probe_one_frontend`.

## 3. What held (no findings)

- **Change requests** (`gitwrite.rs`, `signing.rs`): the per-instance draft key
  is structurally distinct from any roster key and is never presented as a
  producer signature; change-merge verifies signed commits; AOS-Change-Id audit
  synthesis is registry-scoped.
- **WebAuthn** (`auth/webauthn.rs`): attestation-none verification is sound
  across Ed25519/ES256/RS256; no algorithm confusion; credentials are bound to
  their stored public key; challenges are fresh; the CSP nonce is per-request.
- **Worker** (`aos-hub-worker`): D1 access uses bound parameters (no
  string-built SQL); the R2 facade key-maps within the registry and does not
  serve private registries unauthenticated; the Cron indexer fails closed and
  preserves the anti-rollback floor; `render.rs` escapes its fields.

## 4. Method

Per-item finders (operations, validation+repair, change-requests, mirroring,
WebAuthn, SPA, worker) each read the actual code and reported only reachable
defects with `file:line` evidence. Each finding was then judged by two diverse
skeptics — one testing reachability, one searching for an existing mitigation —
and dropped only when **both** refuted (conservative: kept on any doubt). A
final completeness critic looked for cross-cutting gaps the per-item split could
miss; it surfaced H2 and M5 (the validation/repair siblings of the probe and
repair-http findings). 6 item findings + 2 critic findings = 8 confirmed.
