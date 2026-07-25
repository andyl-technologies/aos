# Implementation plan — `apr release` review fixes + test coverage

Companion to `README.md` (the spec). Addresses the review findings against the
current working-tree implementation, closes the §13 test gaps, and adds one
end-to-end fleet test. All `path:line` anchors are the current tree.

## Findings being addressed

1. **Pointer committed before upload** — `registry_ops.rs:7770-7779` commits the
   `[[caches]]` pointer right after generation, *before* tag/packs/channel and
   *before* the upload at `7825-7850`. Spec §9/§12.1 require it *after* a
   successful upload and only when ≥1 narinfo is present. (critical)
2. **Membership HEAD checks are fully sequential** — serial `for … .await?` in
   `membership.rs:65-69` (across destinations), `nixcache.rs:~178-186` (roots),
   `nixcache.rs:~200-205` (members). Spec §7.3 wants them concurrent. (critical/perf)
3. **Staging path deviates** — `types.rs:1088-1093` returns
   `…/registry-caches/<reg>` instead of `nar_cache_path()/registry-static/<reg>`
   (spec §6.1).
4. **Membership uses raw `exists("<hash>.narinfo")`** rather than the AOS-aware
   `has_narinfo`, leaving the AOS-synthesized-narinfo case ambiguous.
5. **Test gaps** — §13(b) skip counts unasserted; §13(c)/(d)/(e) and §12.1/§12.4
   missing; no E2E fleet test.

---

## A. Code fixes

### A1. Pointer-after-upload + ≥1-narinfo gate (critical)

Reorder the publishing tail of `release_registry_tree` (`registry_ops.rs:7736-7850`)
so the cache **bytes** upload before the pointer is committed, and the **origin
git** uploads after — reusing the two upload helpers that already exist instead
of the bundled path:

1. `should_publish_cache()` block: keep `generate_static_cache` (→ staging),
   **delete** the `upsert_registry_cache` + `commit_registry` block at
   `7770-7779`.
2. tag → packs → channel (unchanged, `7784-7823`).
3. **Cache upload:** call `nixcache::upload_static_cache_to_all(cache_dir, urls,
   auth, &root_hashes, no_skip, …)` (already root-last ordered + per-dest
   `exists`-skip, `nixcache.rs:484-540,700-720`).
4. **Advertise:** iff `should_publish_cache()` && resolved `cache_url` is set &&
   `cache.narinfos + cache.remote_skipped > 0` → `upsert_registry_cache` +
   `commit_registry`; set `report.cache_pointer_updated`.
   - Gate comment is load-bearing: `narinfos` counts written entries (incl.
     local-reused) but **not** remote-skipped (those `continue` before the
     handle is pushed, `nixcache.rs:206`), so the sum is the true
     "≥1 narinfo present on dest." Do **not** shrink to `narinfos > 0` — that
     breaks the GC'd-root re-ship case (§12.4).
5. **Origin upload:** call `upload_static_origin_to_all(dir, /*cache_dir*/ None,
   …)` so the just-committed pointer commit is in the uploaded git objects and
   the advertising refs upload last (immutable-before-mutable, already enforced).
   The empty-origin `bail!` (`static_upload.rs:173`) stays safe — the git
   surface always has `HEAD`/`info/refs`.

Consequence: on any failure through step 3, no pointer exists anywhere
(all-or-nothing). Reviewer-verified: with `cache_dir = None`,
`collect_static_origin_files` skips the cache block entirely, so the two upload
calls never double-PUT and each enforces §8 independently.

**Done (follow-up commit):** the `StaticOriginPhase` variants
(`CacheNar`/`CacheMemberNarinfo`/`CacheRootNarinfo`) and the cache-bundling
machinery have been removed — `static_upload.rs` is now git-origin-only, and
`upload_static_cache_to_all` is the single owner of §8 cache ordering. The
second bundled-cache caller, `apr origin upload --cache-dir` (`run_origin`),
was rerouted to call `upload_static_cache_to_all` then the git-only
`upload_static_origin_to_all`, preserving behavior (it derives no roots, so
all narinfos remain members — narinfos-after-NARs, still producer-safe). A new
`apr origin upload --cache-dir` integration test (`apr_cache_cli.rs`) locks in
that both surfaces land. Noted deltas for `http://` destinations: cache uploads
against an AOS endpoint now no-op rather than error, NAR `Content-Type` becomes
`application/x-nix-nar`, and the JSON `files`/`bytes` count the git surface only.

**Plan/JSON helpers:** update `release_plan_steps_json` (`registry_ops.rs:~7978`)
to list *advertise* after *upload-cache* and before *upload-origin*, but
**collapse** the two near-identical publishing/non-publishing branches into one
`Vec` with conditional `insert`s (as the non-publishing branch already does for
`publish_store_path`) rather than forking a third branch. Switch
`print_release_plan` (`:8021`) to an unnumbered list / running counter — it
already has duplicate hardcoded "6."s (`:8043`, `:8054`).

### A2 + A4. Parallel membership, via `has_narinfo` (critical)

`membership.rs` — fan out across destinations, use the AOS-aware method (resolves
finding #4), and **return `bool`** — drop the `Membership` enum (it's a boolean
with ceremony, already collapsed via `matches!` at every use site). Keep the
`CacheMembership` *trait* (spec §14 swaps it for the HLSSI index without touching
callers — a concrete, documented future, not speculative generality):

```rust
async fn narinfo(&self, store_hash: &str) -> Result<bool> {
    if self.backends.is_empty() { return Ok(false); }
    let present = try_join_all(self.backends.iter().map(|b| b.has_narinfo(store_hash))).await?;
    Ok(present.iter().all(|&p| p))
}
```

`try_join_all` doesn't short-circuit on the first `false` (only on `Err`), which
is fine — destination counts are 1–3. Deleting `Membership` also removes the
`remote_narinfo_present` `matches!` wrapper (`nixcache.rs:306-317`).
(`backend.exists` stays for NAR/object PUT-skip.) Replace the 11-method
`MemoryBackend` test mock with a tempdir `FsBackend` (touch `<hash>.narinfo` or
not) — `backend_matrix.rs` already proves `FsBackend::exists`; saves ~50 lines.

`nixcache.rs` — replace the two serial skip loops by probing all hashes
concurrently up front, reusing the **existing** `buffer_unordered` pattern from
`upload_concurrency` (`nixcache.rs:553`) — pure I/O, so no `Semaphore`/
`spawn_blocking` (that pattern is for the CPU-bound `gather_all_path_info`). Two
call sites; if a shared helper is warranted it returns **owned partitions**, not
indices+count:

```rust
async fn partition_absent<T>(items: Vec<T>, hash_of: impl Fn(&T) -> &str,
    membership: Option<&dyn CacheMembership>, workers: usize) -> Result<(Vec<T>, usize)>
```

Root pass: probe root hashes → expand closures for the absent `Vec<String>`.
Member pass: gather infos → probe → compress the absent `Vec<CachePathInfo>`
(compression already parallel). The member-pass present-count must still land in
`cache.remote_skipped` (the §13(b) assertion). Lean alt: inline the
`stream::iter(...).map(...).buffer_unordered(workers).try_collect()` +
`partition` at both sites — it's ~4 lines each. Final call is the implementer's;
the rule is **no per-path `.await` chain and no hand-rolled concurrency**.

### A3. Staging path (spec §6.1)

`types.rs:1088-1093` →
`self.nar_cache_path().join("registry-static").join(registry)`. Update the unit
assertion (`types.rs:~1933`) to the `nar_cache_path`-rooted value, and fix the
two VM tests that hard-code the old default (`tests/vm/apm/registry.nix`,
`tests/vm/apm/trust_anchor.nix`) to `registry-static`.

---

## B. Test additions

### B1. Rust unit tests
- `validate_release_options`: one assertion per §5.3 rejection (some exist; add
  missing no-derivable-URL case). The explicit-`--cache-priority` check uses the
  **existing** `cache_priority_explicit` field (`registry_ops.rs:7428`, set at
  `:7631`) — assert against it; do **not** reintroduce a sentinel.
- URL derivation §5.4: add multi-destination and `s3://`/`sftp://` → reject
  cases beside the existing single-HTTP test (`registry_ops.rs` test module).
- `membership.rs`: all-present / any-absent / empty-backends → `false`, against a
  tempdir `FsBackend` (not a hand mock). Concurrency is structural — no timing
  asserts.

### B2. `crates/aos/tests/apr_cache_cli.rs` integration (the §13 matrix)
Drive with `--json` and assert on report fields, not log scraping.
- **(b) skip counts** — extend the v1→v2 overlapping-closure test: second
  release's `cache.remote_skipped > 0`, `cache.nars == <only-new>`.
- **(c) reject** — `apr release --cache-url … ` (no `--upload-url`) exits non-zero
  with the actionable message; same for `--cache-key` / explicit `--cache-priority`.
- **(d)/§12.4 recovery** — publish v1 to a `file://` dest; delete the dest's
  `nar/` but keep the root narinfo; v2 release of an overlapping closure asserts
  `cache.remote_skipped > 0` and `cache.nars == 0` for the skipped subtree (field
  assertions, not "no dump" log-scraping); rerun with `--no-skip` → `nars > 0`.
- **(e) non-publishing** — `apr release` with no `--upload-url`: tag + packs
  only, `registry.toml` has no `[[caches]]`, cache flags rejected.
- **§12.1 conditionality** — force the upload to fail (unwritable `file://`
  dest): release errors **and** no `[[caches]]` entry **and** no `vX` tag.
- **Backend matrix** — `backend_matrix.rs` already covers `exists` present/absent
  across fs/http/s3/sftp; add nothing.

---

## C. One E2E fleet test

Create `tests/fleet/apr-release-e2e.nix` (keeps the heavy
`apm-registry-upgrade.nix` sysroot test focused), modeled on its roles:
`registry` = `aos-registry-server` + `test-http-server` (serves the uploaded
static origin on :8000 over the fleet L2); `client` = roleless consumer.

Flow:
1. **Producer:** `apr create`, real store path, `apr release <semver>
   --store-path <pkg> --upload-url file:///var/lib/<served>/origin
   --cache-url http://registry:8000/<served>/origin` (file:// upload because the
   Python `http.server` role is read-only; explicit `--cache-url` is the HTTP
   read path — also exercises §5.4's "non-derivable → explicit URL" branch);
   `apr push` to the bare git origin.
2. **Assert producer:** `[[caches]]` committed; narinfos + `nar/` present under
   the served dir.
3. **Skip:** second `apr release` of an overlapping closure → assert remote-skip
   in `--json` output.
4. **Consumer:** `apm registry add` + `apm update` + `apm install <pkg>`,
   substituting NARs from `http://registry:8000/...`; assert the binary is
   installed and runs.

Register via auto-discovery (`default.nix:194-226`); run with
`aos test fleet apr-release-e2e`. (Failure-injection/all-or-nothing stays in the
fast Rust integration test B2-§12.1; the fleet test proves the happy +
skip + real-substitution path.)

---

## D. Sequencing & verification

1. A2+A4 (membership) → 2. A1 (orchestration reorder) + dead-phase cleanup →
3. A3 (path) → 4. B1/B2 → 5. C.

Verify: `cargo test -p aos-package -p aos-cache` (unit + `apr_cache_cli`);
`aos test eval`; `aos test fleet apr-release-e2e`. Per repo principles, all test
tooling is AOS-built (no host/nixpkgs tools).
