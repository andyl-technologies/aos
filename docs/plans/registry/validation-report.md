# AOS Registry Redesign — Plan Validation Report

> **Archival note:** this report audited the original plan against the target
> reference docs before the registry implementation landed. It is useful for
> historical coverage context, but its "uncovered", "partial", and stale
> `path:line` findings are not live TODOs by themselves. Current remaining work is
> tracked in [`TODO.md`](./TODO.md) and the as-built reference status is in
> [`../../registry/current-state.md`](../../registry/current-state.md).

This report validates the registry-redesign implementation plan (`gap-analysis.md` +
`workstream-01..05`) against the six reference design docs (`architecture.md`,
`repo-layout.md`, `http-layout.md`, `versioning-and-channels.md`,
`packs-and-deltas.md`, `signing-and-trust.md`, `publishing.md`,
`nix-cache-compatibility.md`).

Two questions are answered:

1. **Coverage** — does the plan cover every TARGET feature from the reference docs?
2. **Detail/accuracy** — does every plan item describe concrete code changes
   (files / functions / types / tests) with accurate file references?

---

## 1. Executive summary

### 1a. Feature coverage (397 features)

| Status | Count | % |
|---|---|---|
| **Covered** | 340 | 85.6% |
| **Partial** | 23 | 5.8% |
| **Uncovered** | 34 | 8.6% |

The plan covers the entire **git-object / channels / packs / signing / consumer**
surface essentially completely. **All 34 uncovered features and most of the partials
cluster in two areas**:

- **Nix-cache / narinfo emitter** (`nix-cache-compatibility.md`): 27 of the 34
  uncovered features (F362–F395) — the entire producer-side narinfo / nix-cache-info
  emitter is treated as an optional "origin MAY serve" aside and is never planned as
  a build item in any workstream.
- **Package-TOML / closures tree content** (`repo-layout.md`): F90–F95 — the on-disk
  package metadata shape is delegated to the reference doc as an unchanged "surviving
  primitive" and is not re-planned.

One genuine **functional gap outside those two clusters**: **F351** (serialize
concurrent publishers on the same channel via ref-CAS / If-Match) is unplanned by any
workstream — a correctness concern, not just a doc gap.

### 1b. Plan-item detail / accuracy (87 audited plan items)

| Actionability | Count | % |
|---|---|---|
| **Full** (names files, functions, types, AND tests) | 9 | 10.3% |
| **Partial** (names anchors but missing some of fn/type/test) | 61 | 70.1% |
| **Vague** (prose / policy only, no code locus) | 17 | 19.5% |
| **Under-specified (partial + vague)** | **78** | **89.7%** |

| Code-reference accuracy | Items | Notes |
|---|---|---|
| **Accurate** | 40 | symbol + behavior + line all correct |
| **No refs (n/a)** | 34 | target-only / greenfield, no CURRENT cite |
| **Inaccurate** | 13 | wrong line range, wrong fn name, or wrong struct |

**Bottom line:** the plan is *directionally* sound and code-aware — it correctly
identifies that nearly all target machinery is greenfield and names the right CURRENT
anchor points to delete/retarget. But it is a **design-grade** plan, not a
**code-grade** one: ~90% of items lack a complete (function + type + test) spec, the
**workstream task checklists name essentially zero test functions**, and a recurring
**~12–27 line citation drift** plus a few **wrong symbol/struct names** will trip an
implementer at the first edit.

---

## 2. Coverage matrix — every Partial / Uncovered feature

### 2a. Uncovered (34)

| ID | Title | Doc | Why uncovered | Owner WS |
|---|---|---|---|---|
| F90 | `[package]` section fields | repo-layout | Package-TOML content delegated to ref doc as surviving primitive (`build_package_toml`); no item enumerates name/desc/homepage/license/maintainer/sysroot | WS-01 / new |
| F91 | `[[versions]]` version chain | repo-layout | per-version `version`/`previous` shape never planned | WS-01 / new |
| F92 | Per-platform version metadata | repo-layout | store_path/nar_hash/.../references never re-planned | WS-01 / new |
| F93 | Pre-built sysroot images | repo-layout | `[[versions.platforms.*.images]]` not mentioned anywhere | WS-01 / new |
| F94 | Package metadata = narinfo source | repo-layout | narinfo emitter not planned (see cluster below) | WS-05 / new |
| F163 | Build metadata ignored for precedence | versioning | semver crate ignores `+build`, but plan never states it; conflicts w/ F150 keeping `+build` in path | WS-05 |
| **F351** | **Serialize concurrent pointer flips on a channel** | publishing | **No item plans ref-CAS / If-Match serialization; only single-publisher atomicity is covered** | **WS-01 / WS-03** |
| F362 | Distinct AOS-priority vs nix-cache-info Priority | nix-cache | nix-cache-info Priority knob not modeled | WS-05 |
| F363–F366 | nix-cache-info emitter (StoreDir/WantMassQuery/Priority) | nix-cache | No emitter build item; "origin MAY serve" only | new WS-06 |
| F367–F376, F378–F383 | narinfo generator + every narinfo field | nix-cache | Full narinfo field mapping unplanned | new WS-06 |
| F386 | Two published pubkey encodings (aos + Nix form) | nix-cache | keys.toml carries only `parse_signing_key` form; Nix projection unplanned | WS-04 |
| F388 / F389 | NAR blob URL key (colon retained / colon-free fallback) | nix-cache | wire-key scheme + CDN-colon edge case unplanned | new WS-06 |
| F392 | Nix-form trusted-public-keys value | nix-cache | `<name>:<base64>` projection unplanned | WS-04 / WS-05 |
| F393 | Do not disable `require-sigs` | nix-cache | stock-nix consumer guidance unplanned | new WS-06 (docs) |
| F394 | Flake `nixConfig` acceptance caveat | nix-cache | unplanned | new WS-06 (docs) |

### 2b. Partial (23)

| ID | Title | Doc | What's missing | Owner WS |
|---|---|---|---|---|
| F75 | Cache priority semantics + default | repo-layout | `default_cache_priority()=100` and resolve_mirror-takes-first not stated | WS-05 §8 |
| F89 | Package TOML nested→flattened | repo-layout | nested `PackageToml` vs `PackageMeta` distinction not explicitly planned | WS-01 |
| F95 | `closures/<hash>` adjacency format | repo-layout | root-hash-then-dep-hashes-per-line format unspecified | WS-01 |
| F126 | info/refs peeled tags | http-layout | `refs/tags/<semver>^{}` peeled entries not called out | WS-01 §4 Step 4 |
| F128 | "only mutable root-tree parts" invariant | http-layout | low-TTL set listed but not asserted as a strict closed invariant | WS-01 §3.2 |
| F151 | root `objects/info/packs` typically empty | http-layout | implied by per-release packs, not stated as designed behavior | WS-01 |
| F160–F162 | semver precedence / pre-release identifier rules | versioning | delegated to `semver` crate; never restated as a spec item | WS-05 §7.1 |
| F263 | allowed-signers principal = literal `registry` | signing | rides implicitly on reused `verify_commit_signature`; not called out | WS-04 §2.1 |
| F265 | Pre-installed keys in `/etc/apm/trusted-keys.d/` | signing | dir mechanism covered; exact path not pinned | WS-04 §2.1 |
| F267 | Canonical stored TOFU key line | signing | stored-line format implied by reuse, not stated | WS-04 §8 |
| F308 | Release-publish 4 inputs (commit/channel/plan/key) | publishing | no single section defines the `apr release` command signature; unifying cmd is an open question | WS open-q §16.4 |
| F344 | Upload honoring per-path CDN TTL | publishing | TTL *policy* planned; upload-honoring step deferred ("deployment concern"); backend is open question | WS-01 §3.2 |
| F346 | Invalidate low-TTL paths on publish | publishing | one-line mention; CDN-invalidation backend an open question | WS-01 §4 Step 6 |
| F352 | No coordination for immutable objects | publishing | premise implied by content-before-pointer ordering; "no-lock / stale-but-consistent" not stated | WS-01 §4 Step 6 |
| F354 | Strict-superset cache origin (3 reqs) | nix-cache | consumer side planned; producer emitter only "MAY serve" | WS-05 / new WS-06 |
| F361 | Standard relative endpoint paths | nix-cache | planned from consumer view; producer serve-commitment not a build item | WS-05 §8.2 |
| F377 | narinfo `Sig` generated | nix-cache | reuse-key noted as aside; per-narinfo Sig not a planned emitter task | new WS-06 |
| F385 | Nix fingerprint signed message | nix-cache | "separate signature object" stated; fingerprint composition (StorePath/NarHash/NarSize/References) not planned | new WS-06 |
| F387 | per-narinfo Sig satisfies `require-sigs` | nix-cache | broad orthogonality planned; specific rationale not stated | new WS-06 |
| F390 | Stock-nix host substituter wiring | nix-cache | `extra-substituters`/`extra-trusted-public-keys` path not a deliverable | new WS-06 (docs) |
| F395 | Substitution request/verify flow | nix-cache | 3 endpoints listed; full verify-Sig→verify-NarHash sequence not laid out | new WS-06 (docs) |

---

## 3. Under-specified plan items (partial / vague)

78 of 87 audited items are under-specified. Highlighted below are the items where the
missing detail most blocks implementation. The dominant systemic gap: **no workstream
task checklist names a single test function** even though `update.rs` / `state.rs` ship
extensive `#[cfg(test)]` modules that the changes will break.

### 3a. gap-analysis.md (1 full, 19 partial, 6 vague)

| Item | Rating | Missing concrete detail |
|---|---|---|
| G21c — drop `RegistrySigningConfig`/`signing.public_key` | **full** | The one fully-actionable item: names the exact struct+field; only missing enumeration of callers/tests of `signing.public_key` |
| G6 — CDN TTL policy | vague | Pure policy, no code locus / config schema / test |
| G15 — deterministic bucket | partial | Algorithm precise, but no struct/field for persistence, no fn name, no test |
| G19 — name-binding | vague | No fn (belongs in `verify_tag_signature`), no tag-name parser, no test |
| G21 — freshness policy | vague | No config field for max-staleness, no fn, no test |
| G21b — keys.toml roster | partial | No new Rust type (`KeysToml`/roster), no parser fn, no rotation logic, no test |

> gap-analysis is explicitly a *design* doc; its job is to name removal targets (which
> it does accurately, see §4) and hand concrete tasks to WS-01..05.

### 3b. workstream-01-object-store.md (6 full, 4 partial, 1 vague) — strongest doc

| Item | Rating | Missing detail |
|---|---|---|
| Step 1 sha256 init | full | — |
| Step 4 update-server-info | full | — |
| Step 5 write_alternates | full | net-new; fn + format + 3 unit tests named |
| §6.1/§6.2/§6.3 tests | full | concrete test names + assertions |
| Step 2 loose-to-root | partial | No Rust fn body; `GIT_OBJECT_DIRECTORY` redirect-vs-move left undecided (Risk 1, deferred to WS-02); no test for the move |
| Step 3 ensure_loose_completeness | partial | shows `git unpack-objects` shell; Rust impl (pack enumeration, error handling) not pinned |
| Step 6 atomic ordering | partial | prose only; no orchestrator fn; no ordering-invariant test |
| §7.2 command surface | vague | doctor verb not located in `crates/aos/src/commands`; no subcommand struct |

### 3c. workstream-02-pack-delta-pipeline.md (0 full, 8 partial, 3 vague)

| Item | Rating | Missing detail |
|---|---|---|
| Task 1 delete bundle path | partial | **Does not mention `update.rs` is a direct consumer** of every deleted symbol (`BundleManifest::fetch`, `download_bundle`, `verify_bundle`, `unbundle`, `resolve_tag`, plus a `SAMPLE_MANIFEST` test suite); deletion won't compile until the whole `apm update` sync path is rewritten — not a named task |
| Task 2/3/5/6 full_pack/thin_delta/zstd/index-pack | partial | git commands exact, but no return types, no error types, no module location confirmed, no isolated unit test |
| Task 4 `scheme_deltas` | partial | **`Semver` / `FromSemver` types do not exist** — repo uses the external `semver` crate's `Version`; plan invents types without defining them |
| Task 5 zstd | partial | hermetic-build constraint (must use `pkgs.zstd`, no nixpkgs) not addressed; `opts` type undefined |
| Test plan items | vague | no fixtures/harness; round-trip + stock-clone tests need a sha256 repo + dumb-HTTP server + git+zstd binaries with no provisioning stated |

### 3d. workstream-03-channels-rollouts.md (1 full, 10 partial, 2 vague)

| Item | Rating | Missing detail |
|---|---|---|
| D1 delete creation_token path | **full** | most actionable; but does not mention the breaking `state.rs` token tests |
| A1 channel config | partial | "decide" the shape rather than declaring `channel: Option<String>` field + `TrackingMode::Channel` variant + `tracking_mode()` count update |
| A2 floor field | partial | new field type undecided; `save_state`/`load_state` serializer + ~10 unit tests not addressed |
| A3 host rollout state | partial | new struct/module/file path/format unnamed |
| B1–B4 consumer bucket/probe/floor | partial | no fn names, no module, machine_id source open; B4 cites wrong call-site line |
| C1–C5 `apr channel` subcommands | partial | **all depend on a non-existent Ed25519 signed-tag write primitive (deferred to WS-04)**; no `RegistryCommand` variant decl, no handler fn; C3 frontier has zero existing helper (no `git update-ref`/`update-server-info` wrapper exists) |
| D2 strip rollout-% framing | vague | no config-parsing location cited; may be a no-op |

### 3e. workstream-04-signing-trust.md (0 full, 9 partial, 2 vague)

| Item | Rating | Missing detail |
|---|---|---|
| Task 4 verify-tag retarget | partial | no new fn name (`verify_tag_signature`), no tag-object header parse mechanism (`git cat-file`?), no return type carrying name+type+target, no test |
| Task 5 name-binding | partial | no fn/type/module; **no negative test** for the stable-served-as-testing attack |
| Task 6 chain walk | partial | detailed pseudocode but `verify_and_select` has no module/file/signature; no `fetch_tag` helper; no test |
| Task 8 semver floor | partial | persistence undefined (no struct/field/file); does not reference existing token `check_monotonic` as related/distinct |
| Task 10 keys.toml | partial | full schema given but **central removal target mis-cited** (see §4); no roster Rust type/parser/test |
| Task 2 pure tags | vague | design constraint, not a code change |
| Task 7 freshness | vague | no config field, no `ptag_age` fn, no pointer-timestamp source, no test |

### 3f. workstream-05-consumer.md (1 full, 11 partial, 3 vague) — best CURRENT-state grounding

| Item | Rating | Missing detail |
|---|---|---|
| `extract_packages_from_git` reuse | **full** | — |
| State schema (floor/bucket/retained) | partial | exact types named; but no serde migration for old `last_creation_token` configs; **no test updates** though existing tests reference the removed field |
| Replace token fns w/ semver comparator | partial | comparator has no name/signature/location; ~10 tests covering deleted fns not addressed |
| resolve_objects delta-walk | partial | detailed 4-step pseudocode + target fn named; but no signature/module, no `deltas_at`/`releases_between`/alternates-parse helpers, no HTTP object-fetch layer, no test |
| Gating-bug fix (`update.rs:263`) | partial | **bug is REAL and verified** (see §4); concrete before/after rust given; but comparator fn unnamed, no downgrade-refused test |
| keys.toml roster read / TOFU | vague | no keys.toml type/parser/file-path/`apr trust` wiring, no test — large greenfield in prose |
| Nix cache wiring §8 | partial | reuses `CacheEntry`/`resolve_mirrors` well; but **substituter-registration mechanism unspecified** (how a cache is wired into nix's substituter set), no merge fn, no relative-URL resolver fn, no test |

---

## 4. Inaccurate / missing code references

13 of 87 audited items carry an inaccurate reference. Two patterns dominate:
**(a) systematic line-number drift** (the plans were written against an earlier
revision; symbols/behaviors are correct, line anchors are stale by ~12–27 lines), and
**(b) a handful of wrong symbol/struct names** that an implementer hits immediately.

### 4a. Wrong symbol / struct (load-bearing — fix first)

| Plan loc | Claim | Reality (verified) | Impact |
|---|---|---|---|
| WS-01 §7.1 | reuse helper `git_allow_fail` @ `registry_ops.rs:94` | line is right; fn is named **`git_try`** (`registry_ops.rs:96`); `git_allow_fail` does not exist | implementer references a non-existent fn |
| WS-04 §7.5 / Task 10 | remove `signing.public_key` from `RegistryRootConfig` @ `types.rs:566-573` | `RegistryRootConfig` is `types.rs:564-570`; it holds only `signing: Option<RegistrySigningConfig>` (line 569). **`public_key` lives in `RegistrySigningConfig` @ `types.rs:594-595`** — never named in the plan | the actual removal target struct is unnamed and the cited range doesn't contain the field |
| WS-02 Task 4 | `scheme_deltas(release: &Semver) -> Vec<FromSemver>` | **No `Semver`/`FromSemver` types exist**; repo uses `semver::Version` | the function signature depends on undefined types |
| WS-04 §8.3 / WS-05 | "NARs SHA-256-verified" @ `download.rs:102-115` | `102-115` is `fetch_narinfos` signature; actual hash check `with_hash(Sha256, …)` is `download.rs:177-204` | cite points at narinfo fetch, not the verification |

### 4b. Systematic line drift (symbols correct, anchors stale)

| Plan loc | Cited | Actual | Δ |
|---|---|---|---|
| gap-analysis G7 / WS-04 Task 9 — `apr bundle` `git bundle create` | `registry_ops.rs:1739-1751` / `1716-1756` | fn `bundle` body ~`1704-1744` | ~+12 |
| gap-analysis G17 / WS-04 Task 3 — `apr sign` `commit --amend -S` | `:1770` / `1759-1774` | fn `1746-1762`, `-S` at `1758` | ~+12 |
| gap-analysis G17 / WS-04 Task 3 — `apr tag` + `_key` arg | `:1696-1714`, `_key` @ `1700` | fn `1683-1702`, `_key` @ `1750`/`1688` | ~+12 |
| gap-analysis G16 / WS-03 B4 / WS-05 — `check_monotonic` call site | `update.rs:262-267` / `:263` | `update.rs:291-292` | ~+27 |
| gap-analysis G14 / WS-03 D1 — `pick_bundles` | `update.rs:292-391` | `update.rs:319-418` | ~+25 |
| WS-03 D1 — `extract_minor_base` | `update.rs:456-464` | `update.rs:479-491` | ~+23 |
| WS-05 — `sync_bundle` | `update.rs:193` | `update.rs:209` | ~+16 |
| WS-01 — `git init --bare` (git.rs) | `git.rs:150` | `git.rs:157` | ~+7 |
| WS-01 — `last_creation_token` | `types.rs:259` | `types.rs:256` | ~+3 |

### 4c. Confirmed-accurate, high-value cites (independently verified)

- The **gating bug** described in WS-05 §7.2 / gap-analysis G16 is **REAL**:
  `update.rs:291` guards `if latest_token > old_token { check_monotonic(...) }`, so the
  monotonic check is skipped exactly when a downgrade would occur. ✔
- `security.rs` primitives (KeyStore, `tofu_check`, `parse_signing_key`,
  `key_fingerprint`, `verify_commit_signature`, `check_downgrade`) — all accurate. ✔
- `state.rs` token machinery (`check_monotonic:104`, `version_to_token:131`,
  `token_to_version:173`) — accurate. ✔
- `git_try` at `registry_ops.rs:96`, `RegistrySigningConfig.public_key` at
  `types.rs:594-595`, `pick_bundles` at `update.rs:319` — verified in this review. ✔

### 4d. Missing references (consumers of deleted code not cited)

- **WS-02 Task 1** omits that `update.rs` imports and uses *every* bundle symbol slated
  for deletion (incl. a `SAMPLE_MANIFEST` test suite). The `apm update` sync path
  rewrite is implied but not a named task.
- **WS-03 / WS-05** state/field changes omit the **~10+ breaking `#[cfg(test)]` tests**
  in `state.rs` (`version_to_token_*`, `token_to_version_*`, `check_monotonic_*`,
  `tracking_mode_*`) that reference removed symbols.

---

## 5. Prioritized recommendations

| # | Priority | Recommendation | Targets |
|---|---|---|---|
| 1 | **P0** | **Add a Nix-cache / narinfo emitter workstream (WS-06).** This is the single largest gap: 27 uncovered + ~7 partial features. Plan the `nix-cache-info` emitter (StoreDir/WantMassQuery/Priority), the narinfo generator (full field mapping F368–F383), the NAR blob URL key scheme (colon-retained + colon-free fallback), the Nix-fingerprint Sig, the two pubkey encodings, and stock-nix consumer docs. | F354, F361–F395, F94 |
| 2 | **P0** | **Plan concurrent-publisher serialization (F351).** Add a task (WS-01 or WS-03) for ref-CAS on `refs/heads/<channel>`/`refs/tags/*` or conditional-PUT/If-Match on `/channels/**`, with the loser re-deriving the frontier. This is a correctness gap, not a doc gap. | F351 |
| 3 | **P0** | **Fix the load-bearing wrong references** before any coding starts: rename `git_allow_fail`→`git_try` (WS-01 §7.1); point the pubkey-removal at `RegistrySigningConfig` @ `types.rs:594-595` (WS-04 Task 10); define `Semver`/`FromSemver` or switch `scheme_deltas` to `semver::Version` (WS-02 Task 4); re-point the NAR-hash cite to `download.rs:177-204`. | §4a |
| 4 | **P1** | **Re-anchor all `registry_ops.rs`/`update.rs` citations** against HEAD (drift ~+12 and ~+25 lines). Prefer symbol names over line numbers, or add a "verified against commit `<sha>`" header so reviewers know the anchors are point-in-time. | §4b |
| 5 | **P1** | **Name the breaking-test surface in every removal task.** WS-02 Task 1 must list `update.rs` consumers + `SAMPLE_MANIFEST`; WS-03/WS-05 must list the `state.rs` token tests. Add an "apm update sync-path rewrite" task to WS-02. | §4d |
| 6 | **P1** | **Promote the consumer-resolution greenfield items from pseudocode to signatures.** Give `verify_tag_signature`, `verify_and_select`, `resolve_objects`, the semver comparator, and the bucket selector concrete module paths, Rust signatures, and at least one named test each — especially the **name-binding negative test** (stable-served-as-testing). | WS-04 Tasks 4–8, WS-05 |
| 7 | **P1** | **Specify the keys.toml Rust surface.** Define the roster type (`KeysToml`/`KeyEntry`/`RevokedEntry`), parser fn, the tree-file path it's read from, the `apr trust` wiring, and rotation/revocation-vouching tests. Currently prose-only across WS-04 §7.5 and WS-05 §6.3. | F71, F79–F86 |
| 8 | **P2** | **Resolve the unifying `apr release/publish` command (F308) and the upload backend (F344/F346).** These are flagged open questions (§16.4); pin at least a command signature (commit/channel/partition-plan/key) and a pluggable upload-backend trait, even if a concrete backend is deferred. | F308, F344, F346 |
| 9 | **P2** | **Close the small spec gaps that ride on reused crates/code:** state the build-metadata-ignored rule and reconcile it with `+build` in the path (F163/F150); restate or explicitly delegate semver precedence (F160–F162); pin `/etc/apm/trusted-keys.d/` (F265), the literal `registry` principal (F263), and the canonical TOFU stored-line (F267). | F160–F163, F263, F265, F267 |
| 10 | **P2** | **Re-plan or formally delegate the package-TOML/closures tree content** (F89–F95). If truly unchanged, add a one-line "surviving primitive: shape per repo-layout §4–§5, no code change" note per feature so coverage is explicit rather than implied. | F89–F95 |
| 11 | **P3** | **Add the hermetic-build + test-harness notes WS-02 omits:** zstd via `pkgs.zstd` (no nixpkgs), and how round-trip/stock-clone tests provision a sha256 git repo + dumb-HTTP server. | WS-02 tests |

---

### Appendix — methodology

Counts derived from the 397-feature coverage set and 87 audited plan items supplied as
input. Code references spot-verified against `crates/aos-package/src/{registry_ops.rs,
types.rs,update.rs,registry/state.rs}` at the current `docs/registry-design` branch
HEAD; confirmations and corrections are recorded inline in §4.
