# Acceptance criteria — definition-of-done per checklist item

Every implementation-plan item paired with the concrete check/assertion that proves it done, so a goal-mode agent self-verifies without judgment.


---

## T0 + P0 + P1 packaging

Grounded. Here is the drop-in RFC markdown.

---

## Definition-of-Done — T0 + P0 + P1-Packaging

Each checklist item is paired with a **concrete acceptance test**: the exact build target, assertion, or golden comparison that proves it done. "Green" means the named `nix-build -A <target>` (or `cargo test <name>`) exits 0 in CI. All goldens follow the barrier pattern — an unexpected diff is a failure, an intentional diff requires a reviewed commit that updates the fixture.

### T0 — Characterization suite

| Checklist item | Definition of Done (acceptance test) |
|---|---|
| **Pure-eval toplevel golden** — `lib/testing/system-characterization.nix` + `tests/fixtures/system-characterization-goldens/<system>/` (etcDump, unit bodies, substituted `activate.sh.in`, os-release), added to `checks.eval`. Comparator normalizes job scripts to text. | New file wired as `checks.system-characterization` in the `default.nix` `checks` rec (sibling of `systemd-generate`). `nix-build -A checks.system-characterization` is **green on master**: for every variant in `discoverSystems`, the builder diffs `system.build.toplevel`'s `etcDump.txt`, `systemd-units/*`, substituted `activate-script.sh`, and `os-release` against the committed fixture and the derivation fails on any byte diff. The comparator is proven to normalize by a self-test: a fixture whose `ExecStart=` points at a `/nix/store/…-unit-script` path and one carrying the same snippet as inline text compare **equal** (normalization unit assertion inside the check). Determinism: building the check twice yields identical out-paths (`nix-build … && p1=$(...); nix-build … --check` succeeds). |
| **Flat-merge Rust golden** — `crates/aos-package/tests/golden_config_artifact.rs` + fixtures; snapshot `render_package_config()`, re-render shuffled ⇒ stable ⇒ matches golden. Becomes `checks.config-parity` oracle. | `cargo test -p aos-package --test golden_config_artifact` passes. Test asserts three properties on the fixture corpus (≥1 multi-artifact package × multiple config fields): (1) `render_package_config(pkg, artifacts, desired)` equals the committed `tests/fixtures/…/<case>.golden`; (2) re-invoking with the artifact/field input order **shuffled** produces byte-identical output to (1); (3) the render is idempotent across two calls. `render_package_config` is made test-visible (e.g. `pub(crate)` + `#[cfg(test)]` re-export) without changing its behavior. The build-side gate `nix-build -A pkgs.aos` (which runs the crate test suite hermetically) stays green. |
| **Activate + substrate fleet assertions** — extend `apm-system-upgrade`/`install-from-image`/`measured-boot` from "boots" to pin observable outcomes (repart/cryptsetup status, partition sizes, `/var` mount, `/var/etc` allowlist survival, post-swap `systemctl --failed` empty). | The three existing fleet tests gain explicit guest assertions and stay green: `nix-build -A checks.fleet.apm-system-upgrade`, `-A checks.fleet.install-from-image`, `-A checks.fleet.measured-boot`. Each new assertion uses harness primitives only (`vm.succeed`/`vm.fail`/`vm.wait_for_unit`; `/proc`,`/sys`,`systemctl`,`journalctl` — no grep/sed/ip in guest). Concretely: `apm-system-upgrade` asserts `systemctl --failed` lists zero units post-swap and `/var/etc` allowlisted files survive while a non-allowlisted file triggers the dirty-upper warning in the journal; `install-from-image` and `measured-boot` assert partition labels (root-a/root-b/var/swap), `/var` present in `/proc/mounts` rw, and (measured-boot) `cryptsetup status` reports the LUKS2 var device active. Each assertion is shown to **fail** if the outcome is inverted (negative-control demonstrated in the commit). |
| **Commit goldens at branch base** (barrier pattern). | The characterization commit is the **first commit** on the branch and CI is green at that commit with no P0 code present (`git log` shows goldens precede any `lib/modules/systemd/lib.nix` change). Any later golden modification appears as a standalone reviewed diff in the PR; an un-reviewed golden change blocks merge. |

### P0 — render/assemble split (no behavior change)

Global gate for the whole section: `checks.system-characterization` (T0 toplevel golden) stays **green**, with the *only* permitted fixture change being the documented job-script-text normalization; and `nix-build -A checks.vm.boot` plus the per-system image hashes are unchanged.

| Checklist item | Definition of Done (acceptance test) |
|---|---|
| Make `lib/modules/systemd/lib.nix` `generateUnits` a **pure function** returning `{ unitName → { text; mode; … } }` instead of a derivation. | `nix-build -A checks.systemd-generate` and `-A checks.systemd-lib` green. `generateUnits` provably returns a plain attrset (not a derivation): a new assertion in `systemd-lib.nix` checks `!(lib.isDerivation (generateUnits …))` and that each value has `text`/`mode` string attrs. The T0 toplevel golden's `systemd-units/*` bodies stay byte-identical (modulo job-script text). |
| **Shell-snippet options → manifest text (F2-A, C2):** reroute `script`/`preStart`/`postStart`/`reload`/`preStop`/`postStop` (`unit-options.nix:644` `makeJobScript`) to `manifest.jobScripts`; materializer writes gen-local paths and rewrites `Exec*=`; publish lint rejects derivation refs in `config` outputs. | T0 toplevel golden green under the **job-script normalization only**: the comparator shows the `ExecStart=` snippet body identical while the embedded path moved from a `writeShellScriptBin` store path to a gen-local path (this is the single documented golden diff). A new assertion (extend `checks.lint` or `package-expose`) fails the build when a `config` output's manifest carries a `/nix/store/…` derivation ref in a `jobScripts` entry. `nix-build -A checks.lint` green. The end-to-end materialize is exercised by `checks.vm.boot` staying green (units with `script=` still start). |
| Make `modules/base/build.nix` `/etc` assembly emit the **manifest** (`aos.config-manifest/v1`) as a pure value. | A new pure-eval check (e.g. `checks.config-manifest`) asserts the emitted manifest is a non-derivation Nix value validating against the v1 schema (has `etc`, `units`, `jobScripts`, `inputs` keys) and that re-evaluating it twice is `==`. `nix-build -A checks.config-manifest` green; T0 golden unchanged (manifest is internal, render output identical). |
| Builder-side `system.build.toplevel` consumes the manifest via a thin materialize step → byte-identical toplevel (gate: `checks.vm.boot` + image hashes unchanged; job scripts compared semantically). | `nix-build -A checks.vm.boot` green and the materialized `system.build.toplevel` out-path hash equals the pre-refactor hash for each system **after** applying the documented job-script text normalization (T0 golden green). Image hash parity demonstrated: `nix-build -A systems.server.build.image` produces the same store path (or the same content hash if job-script paths are normalized out) as master. |
| Define the manifest JSON schema as a shared Rust + Nix data contract (incl. `jobScripts`; `inputs` = base_lib + evaluator + config_modules + host_nix + instance_facts). | A single schema artifact is consumed by both sides: the Nix check `checks.config-manifest` validates an emitted manifest against it, **and** `cargo test -p aos-package` deserializes the same fixture manifest into the Rust `ConfigManifest` type with `serde(deny_unknown_fields)` (round-trip serialize ⇒ byte-identical). A cross-language conformance test (one fixture `manifest.json` under `crates/aos-package/tests/fixtures/`) parses on both sides; `inputs` carries exactly the five named keys (asserted). Both `cargo test -p aos-package` and `nix-build -A checks.config-manifest` green. |

### P1 — Packaging & module outputs

| Checklist item | Definition of Done (acceptance test) |
|---|---|
| Add a second **`config` output** to `mkDerivation` (config-only module + private helpers), references-as-strings discipline. | A package built with the new output exposes a `config` output path containing the module file with no `/nix/store` derivation refs (only strings). New eval check (extend `checks.package-expose`) asserts `pkg.config` exists, is a separate output, and an AST/text scan of its module finds zero store-path literals. `nix-build -A checks.package-expose` green; `nix-build -A pkgs.<sample-pkg>.config` produces the output. The publish-time references-as-strings rule is enforced by the same lint that P0 added (derivation-ref-in-config-output fails). |
| Promote `expose` (`pkgs/build-support/_expose-renderer.nix`) into a config module: `firewall.*`, `kernel.*`, units, `config.artifacts`, `permissions.*`, `credentials` become evaluated module options. | `nix-build -A checks.package-expose` green with the expose surface now evaluated through `lib.evalModules` (each of `firewall`, `kernel`, units, `config.artifacts`, `permissions`, `credentials` is a typed `mkOption` — a bad type now throws an eval error, asserted via `tryEval` in the check). **Parity gate:** the module-eval render of a fixture package equals the legacy `_expose-renderer.nix` flat render byte-for-byte — proven by `cargo test -p aos-package --test golden_config_artifact` (the T0 oracle) comparing module-eval output to the committed flat-merge golden (this is `checks.config-parity`). |
| Registry: add `Option<ConfigOutputMeta>` to `PackageMeta` (`types.rs`) + `FEATURE_MULTI_OUTPUT_V1` gate; `store/` realization entries for the config output. | `cargo test -p aos-package` green, including: a serde round-trip test proving a `PackageMeta` **without** `config_output` deserializes from an old-format JSON fixture (back-compat, `Option` defaults `None`) and one **with** it round-trips byte-identically; a test asserting the `FEATURE_MULTI_OUTPUT_V1` capability flag gates acceptance (a `ConfigOutputMeta`-bearing publish is rejected when the feature bit is absent and accepted when present). A registry e2e (`cargo test -p aos-package --test registry_e2e`) shows the config output realized as a `store/` entry retrievable by hash. |
| Remove the hand-authored `expose.requires` edge list; derive per-package `provides` metadata (options-only eval at publish) + AST-scan requires. | The static `expose.requires` list is deleted from the tree (`grep -rn "expose.requires" pkgs/` returns nothing) and `nix-build -A checks.package-expose` stays green with the derived per-package `provides`. A test asserts the auto-derived `provides` set (from an options-only eval, kept as per-package `ConfigModuleMeta.declares` and never aggregated registry-wide) and the AST-scanned `requires` set for a fixture package **equal** the previously hand-authored edges for that package (no regression in the dependency graph): `cargo test -p aos-package` provenance/resolve test green, and `nix-build -A checks.eval` green. The options-only publish eval is shown to not force any build (`--allow-import-from-derivation=false`, no derivation realized). |

**Section P1-packaging gate:** `cargo test -p aos-package` (golden_config_artifact, types serde, registry_e2e, provenance) all green; `nix-build -A checks.package-expose -A checks.eval -A checks.lint` green; the `checks.config-parity` oracle (module-eval == flat-merge golden) green — this is the load-bearing proof that promoting `expose` to a module changed no rendered bytes.

---

Relevant paths (all absolute):
- Plan: `/Users/dplecki/src/andyl/andyl-os/.claude/worktrees/rfc-0011-on-host-config-eval/docs/rfcs/0011-on-host-config-eval/implementation-plan.md`
- Test plan: `/Users/dplecki/src/andyl/andyl-os/.claude/worktrees/rfc-0011-on-host-config-eval/docs/rfcs/0011-on-host-config-eval/test-plan.md`
- Checks rec: `/Users/dplecki/src/andyl/andyl-os/default.nix` (the `checks = rec { … }` block; new pure-eval checks wire in beside `systemd-generate`)
- Eval/test harness: `lib/testing/` (new `system-characterization.nix`; existing `eval.nix`, `package-expose.nix`, `systemd-lib.nix`, `systemd-generate.nix`, `fleet.nix`)
- Rust oracle: `/Users/dplecki/src/andyl/andyl-os/crates/aos-package/src/config_artifact.rs` (`render_package_config` at line 212, currently private — make test-visible), `/Users/dplecki/src/andyl/andyl-os/crates/aos-package/src/types.rs` (`PackageMeta` at line 513), new `/Users/dplecki/src/andyl/andyl-os/crates/aos-package/tests/golden_config_artifact.rs`
- Expose renderer to promote: `/Users/dplecki/src/andyl/andyl-os/pkgs/build-support/_expose-renderer.nix`

Load-bearing note for an implementing agent: `render_package_config` is **private** today (`fn`, not `pub`) at `config_artifact.rs:212`; the T0 Rust golden requires exposing it (e.g. `pub(crate)`) without altering behavior — this is a doc-noted, reviewed change, not a refactor.


---

## P1 module-system, resolver/eval, generations

Below is drop-in RFC markdown. Each checklist item is reproduced verbatim with a nested **Done when** definition-of-done naming the concrete acceptance test (the `checks.<name>`/`tests/fleet/<name>.nix`/`crates/aos-package/tests/<name>.rs` mechanism from `test-plan.md` §"How a check is added") and the exact assertion that proves it.

---

### Namespacing & module system

- [ ] Per-package root mounting: each `config` module as a submodule at `{pkg}.*`.
  - **Done when** `checks.eval` (`lib/testing/rfc-0011-namespacing.nix`) evaluates two packages whose private options collide on a bare segment (`redis.maxmemory`, `valkey.maxmemory`) and asserts: each resolves under its own root with no cross-talk; an options-only eval of pkg A in isolation declares only `A.*` paths (matches `lib/modules.nix:924-930` non-forcing introspection); and writing `B.x` from package A's `config` throws the `:917` "not declared" string. Structural-ownership claim is proven by the by-name convention: `A.maxmemory` resolves to `A@ver` and `B.maxmemory` to `B@ver` purely from the root segment equalling the package name (each package's per-package `declares` names only its own `A.*` / `B.*` paths), with no manual edge and no registry-published index.

- [ ] `SystemRoots` for shared roots (`root → installed owner`), per-system exclusivity + install-time trust (key policy / operator allowlist) enforced at resolve (optionally early at install).
  - **Done when** a Rust test `crates/aos-package/tests/system_roots.rs` asserts: (a) building `SystemRoots` from an installed set with **two** owners of `firewall.*` is a **hard error** citing both sources; (b) a successor version of the same owner (only one installed) is **accepted**; (c) installing a shared-root owner that fails the operator's install-time key policy / allowlist is **rejected at install** (the registry itself never gates the claim — two registry packages may both claim `firewall`); (d) a `checks.eval` companion confirms the resolver refuses to compose an installed set with two owners of one shared root (single-owner-per-system).

- [ ] Variants/alternatives: `Provides`/`Conflicts` on a virtual shared root (single-declarer-per-resolved-set).
  - **Done when** `crates/aos-package/tests/variants.rs` resolves a set requesting `nginx.*` with `nginx-full` and `nginx-minimal` both in the registry and asserts: exactly one provider lands in the resolved set; selecting both yields a `Conflicts` resolve error; and the resolved set passes the single-declarer check in `checks.eval` (the surviving variant is the sole declarer of `nginx.*`).

- [ ] Merge precedence: file-provenance priority tagging at `lib/modules.nix:695` → `host.nix` bare defs at priority 75 (do **not** subtree-wrap).
  - **Done when** `checks.eval` (`lib/testing/rfc-0011-precedence.nix`) asserts the priority band table holds: a `host.nix` bare def of `redis.maxmemory` deterministically beats a package contribution **regardless of module order** (shuffle the `modules` list, same winner); a package def at priority 100 loses to the host.nix value resolved at 75; and the **subtree-wrap trap** is regression-pinned — a `redis = mkOverride 75 { maxmemory = …; }` form is shown to drop the nested leaf (asserts `collectDefsAtPath` finds no leaf under the marker), so the leaf/provenance approach is the only passing form.

- [ ] `host.facts.*` privileged root (`attrsOf`-by-MAC); reject ambient facts.
  - **Done when** `checks.eval` (`lib/testing/rfc-0011-host-facts.nix`) asserts: `host.facts.hostname` typed `nonEmptyStr` (empty throws), `host.facts.interfaces` keyed by MAC injects the key as `name` (`lib/default.nix:81-88`), `host.facts.disks` keyed by disk-id; and a module attempting to read a host fact via `specialArgs`/`getEnv` under `--pure-eval` throws rather than reading an ambient channel (the only declared input is `host.nix`). A fleet assertion in the on-host-eval test confirms `facts.json → host.facts.*` is the sole facts path (no imperative `/etc/hostname` write).

- [ ] Shared scalars typed `uniq`/`mergeEqualOption`; reject multiple declarers.
  - **Done when** `checks.eval` (`lib/testing/rfc-0011-shared-scalars.nix`) asserts: `firewall.forwardPolicy = uniq (enum [...])` with two **conflicting** definitions at equal priority throws "conflicting definitions" listing every def with its `file` (not last-wins); two **equal** definitions via `mergeEqualOption` pass; and an explicit operator priority bump at tier 75 resolves the conflict. List-typed shared options (`firewall.allowedTCP`) are shown to merge by concatenation with no conflict.

- [ ] Enablement policy: forbid foreign `enable` writes (per-def authenticated provenance + the installed owner's contributable surface in `SystemRoots`); provider sub-feature enable allowed; dependencies as resolve-time assertions.
  - **Done when** `checks.eval` (`lib/testing/rfc-0011-conscription.nix`) asserts the four enablement rules: (a) `redis-exporter` setting `redis.enable` is **rejected at resolve time** (foreign top-level enable — `redis.enable` is not in the installed `redis` owner's contributable surface); (b) `nginx-full` setting `nginx.modules.http3.enable` **within the root it provides** is allowed; (c) `redis-exporter`'s dependency surfaces as a **resolve-time assertion** ("requires `redis.enable = true`; set it in host.nix"), collected at `lib/modules.nix:935` and failing the manifest force when unmet; (d) operator `host.nix` at tier 75 overrides any provider-set sub-flag. Rejection is keyed on **resolver-assigned provenance**, verified by the forged-`_file` case below.

---

### Resolver & evaluator

- [ ] Error-driven resolve↔eval fixpoint (parse the strict throw → root-based dispatch → fetch provider → re-eval), with causal-chain diagnostics + iteration cap.
  - **Done when** a fleet test `tests/fleet/rfc-0011-fixpoint.nix` asserts: a `host.nix` enabling a package whose config module is absent pulls the **config output first**, re-evals, and **converges** to a manifest; a `checks.eval` companion proves **both** missing-option detectors — a write to an undeclared option caught via the `:917` throw string, **and** a read of an absent root caught via the raw missing-attr message and dispatched on its root segment (`SystemRoots` for a shared root, else structural by-name lookup; not `:744`); a missing provider fails with a legible causal chain; and a deliberately non-converging cycle hits the **iteration cap** and dumps the trace rather than hanging.

- [ ] `module_abi`: bake the monotonic integer into `os-release`/toplevel; config modules declare `module_abi_compat`; resolver fail-closed refuses incompatible modules pre-eval (mirror `trust_ctx.enforce_totality()`).
  - **Done when** `checks.eval` (`lib/testing/rfc-0011-module-abi.nix`) asserts: the running image's `module_abi = K` is readable from `os-release`/toplevel (next to `aos.system.version`, `system.nix:124-141`) without network; a config module with `module_abi_compat = { min; max }` **excluding K** is **refused before any manifest is produced** (fail-closed, same shape as `trust_ctx.enforce_totality()`, `sysroot.rs:192-204`); and the produced config-gen records `module_abi_pinned = K`. A fleet assertion confirms the incompatible module leaves the **old config-gen live**.

- [ ] `aos-eval.service` (stage-2, `After=network-online.target`, `Before=aos-install-packages.service`, `Type=oneshot`, best-effort) running sandboxed stock Nix (`nix-instantiate --store dummy:// --eval --strict --json`, `restrict-eval`, `allow-import-from-derivation=false`) → manifest.
  - **Done when** `tests/fleet/rfc-0011-on-host-eval.nix` asserts: the agent receives literal-Nix user-data, `aos-eval.service` runs at stage-2 with the correct ordering (`systemctl show` confirms `After=network-online.target`, `Before=aos-install-packages.service`, `Type=oneshot`), emits a manifest of the expected `etc`/`units`/`jobScripts`/`inputs` shape, and **eval-twice is byte-identical** (determinism gate). The off-host preflight `checks.config-eval` independently asserts succeeds + schema-valid + eval-twice-deterministic with the same sandbox flags.

- [ ] Hardened transient eval scope: `MemoryMax=2G`/`MemoryHigh=1536M`/`TimeoutStartSec=120s`/`TasksMax`, `ProtectSystem=strict`, read-only input binds, `SystemCallFilter`; fail-closed on kill.
  - **Done when** `tests/fleet/rfc-0011-eval-sandbox.nix` asserts: `systemctl show aos-eval.service` reports the exact directives (`MemoryMax=2G`, `MemoryHigh=1536M`, `TimeoutStartUSec=2min`, `TasksMax=`, `ProtectSystem=strict`); an eval forced to allocate past `MemoryMax` (or exceed `TimeoutStartSec`) is **killed and the unit fails-closed** (no partial manifest committed, old config-gen stays live, `systemctl --failed` shows the eval unit and `is-system-running` does not transition to a switched state); and a write attempt to a read-only input bind from inside eval is denied.

---

### Generations

- [ ] Split `SystemGeneration` into **image-gen** + **config-gen**; the existing `current → gen-N` pointer becomes the config-gen pointer.
  - **Done when** `crates/aos-package/tests/generations_split.rs` asserts: the persisted shape splits into image-gen `{ kernel_path, uki/toplevel ref, version, module_abi, evaluator_ref }` and config-gen `{ number, image_gen_parent, module_abi_pinned, manifest_hash, config_module_closure, host_nix_ref }`; the `current → gen-N` pointer now refers to a **config-gen**; and `Profile::switch_to` operates on config-gens (`profile/mod.rs:282`). A fleet assertion confirms a boot enumerates one image-gen parent owning a lineage of config-gens.

- [ ] Config-gen records `{ image_gen_parent, module_abi_pinned, manifest_hash, config_module_closure, host_nix_ref }`; content-address by `manifest_hash`.
  - **Done when** `crates/aos-package/tests/config_gen_record.rs` asserts: all five fields are persisted and round-trip; two evals of the same `(base_lib, config_module_closure, host.nix)` produce the **same `manifest_hash`** and resolve to the **same gen dir** (content-addressed); and the recorded `module_abi_pinned` equals the running image's K. This reuses the flat-merge determinism oracle (`golden_config_artifact.rs`, shuffled-order ⇒ stable) as the upstream guarantee.

- [ ] APM materialize step: manifest → composefs `/etc` overlay (on-host `mkfs.erofs` + symlink trees) → generation dir; invoke `activate <N>`.
  - **Done when** `tests/fleet/rfc-0011-materialize.nix` asserts: APM renders a manifest into a content-addressed gen dir using on-host `mkfs.erofs` + symlink trees, invokes `activate <N>`, and the resulting 3-layer `/etc` overlay + `mount --move --beneath` swap matches the `apm-system-upgrade` preserve contract (post-swap `systemctl --failed` empty, expected units reloaded/restarted); `checks.config-parity` asserts the materialized `/etc` is **byte-equal** to the flat-merge golden for the same inputs (job scripts compared as text per the C2 normalization).

- [ ] Upgrade ordering (image-first → reboot → re-eval → switch); config-only change skips reboot. Rollback verbs: config (pointer switch, same-ABI) + image (A/B UKI). Cross-ABI rollback re-evals retained inputs.
  - **Done when** `tests/fleet/rfc-0011-two-axis-gen.nix` asserts: an image+config upgrade stages the UKI offline, reboots into it, re-evals against the **new** base lib, then switches (never evals on the source substrate); a **config-only** change short-circuits to re-eval+`activate` with **no reboot**; config rollback is a **pointer switch only** (no eval, no reboot — `Profile::switch_to`); and cross-ABI rollback is **refused for direct activation** and instead **re-evals** `(old_base_lib, config_module_closure, host.nix)` to a fresh config-gen pinned to the rolled-back image-gen. An ABI-gate failure in the re-eval step aborts with the **old config-gen live** (`EX_PREPARE`/`EX_COMPOSE` contract).

- [ ] `gen-N/cfg/<hash>` GC roots; retention/prune unchanged.
  - **Done when** `tests/fleet/rfc-0011-gc-roots.nix` asserts: `gen-N/cfg/<hash>` GC-roots the manifest **outputs** (package runtime closures survive `apm gc`); retention/prune depth is unchanged from the existing `Profile`/`Generation` behavior; and a config rollback to a retained gen still finds its materialized `/etc`. (The complementary `cfgsrc/` source-closure root that keeps cross-ABI re-eval working is gated by the Review-driven item below — this item covers only the outputs root.)

---

### Review-driven hardening

- [ ] ⟂ **F1 — anchor the evaluator/base-lib root to measured boot**: dm-verity on the erofs root with the roothash on the measured kernel cmdline (`verity.nix` exists but is unused in production), or embed evaluator+base-lib in the UKI initrd. Without it the producer is unmeasured.
  - **Done when** (post-fork-decision) `measured-boot` is extended to assert the evaluator/base-lib root is in the measured chain: either the erofs dm-verity roothash appears on the **measured kernel cmdline** and a tampered root fails verity at boot, or the evaluator+base-lib digest is a **PCR-11-measured UKI section** (generations.md OQ2) such that `expected_pcr11` from the registry catalog covers it. The fleet test boots, reads the achieved PCR-11, and asserts it equals the catalog value with the producer included.

- [ ] ⟂ **F3 — capability-scoped contribution surface**: shared-root owners declare contributable sub-paths; resolver enforces writes against them + authenticated provenance (not module `_file`).
  - **Done when** (post-fork-decision) `checks.eval` (`lib/testing/rfc-0011-contribution-surface.nix`) asserts: an owner declares contributable sub-paths (`nginx` opens `virtualHosts.*`/`upstreams.*`, keeps `enable`/global owner-only); `nextcloud` writing `nginx.virtualHosts.*` is **allowed** (legitimate composition); the same package writing `nginx.enable` or a non-contributable sub-path is **rejected at resolve time** (its `RootContribution.paths` are not a subset of the installed `nginx` owner's `contributable` surface in `SystemRoots`); and the enforcement keys on **resolver-assigned authenticated provenance**, not module `_file`.

- [ ] **Provenance from authenticated fetch source**, not module-supplied `_file`, for both priority-75 lift and conscription detection.
  - **Done when** `checks.eval` (`lib/testing/rfc-0011-forgeable-file.nix`, review M-forgeable-file) asserts: a package injecting `imports = [ { _file = "<registered host.nix path>"; … } ]` does **not** earn operator priority 75 and does **not** evade conscription detection — the engine reads the resolver-supplied, non-module provenance attribute at `lib/modules.nix:695`/`:669` and ignores the module-supplied `_file`. The legitimate `host.nix` (loaded from the policy-accepted store path) **does** get tier 75. Both the precedence outcome and the conscription rejection are asserted under the forged-`_file` input.

- [ ] **Instance facts as a recorded input**: `facts_hash` (+ retained `facts.json`) in the manifest `inputs` + `gen-attestation`; remove any pre-verification `authorized_keys` seeding from the facts channel.
  - **Done when** `crates/aos-package/tests/facts_input.rs` asserts `facts_hash` is part of the manifest `inputs` set and `gen-attestation/v1`; a fleet assertion confirms `facts.json` is retained per config-gen and that **no `authorized_keys` is seeded from the facts channel before signature verification** (only the gen-0 SSH-key bootstrap carve-out remains). Changing a fact changes `facts_hash` and therefore `manifest_hash` (content-addressed).

- [ ] **Static-networking seed** from platform metadata in the initrd agent for DHCP-less clouds (DO/OpenStack) so stage-2 can reach the registry.
  - **Done when** `tests/fleet/rfc-0011-metadata-agent.nix` (DO/OpenStack recorded fixtures) asserts: the initrd `aos metadata` agent seeds static networking from platform metadata, and on a **DHCP-less** profile stage-2 reaches the registry (a fetch over the configured interface succeeds) where it would otherwise time out. The accepted provisioning input and its hashes survive switch-root unchanged.

- [ ] **Authenticated first-boot `host.nix` provisioning projection** with the
      base module default as the no-input fallback.
  - **Done when** `tests/fleet/provisioning-boot.nix` asserts: literal
    `host.nix` setting `aos.provisioning.storage` changes the first-boot
    layout; no JSON provisioning/storage document is accepted; absent
    `host.nix` evaluates the same default Nix module; present invalid input
    reaches emergency before GPT mutation and does not fall back; a pending
    marker fails closed for explicit partial-commit recovery; only a committed
    operator/fallback marker freezes mutation; reboot reacquires and fully
    evaluates runtime `host.nix`, dry-runs storage for
    coherent/divergent/unavailable reporting, and preserves partition sizes;
    missing metadata restores only a hash-checked input that previously
    produced a manifest; root-first multi-device output makes partial commits
    observable; durable audit evidence and reusable definitions land under
    `/var/lib/aos-provisioning`; measured `/var` remains raw; baked/out-of-band
    disks carry a committed marker; and the mutating repart exit status
    propagates.

- [ ] **Degraded commit = re-projected manifest** (full minus un-fetched), re-hashed, drop-set recorded — keeps the generation content-addressed.
  - **Done when** `tests/fleet/rfc-0011-degraded-boot.nix` (from `apm-system-activation-fail`) asserts: a single failing package fetch yields `is-system-running = degraded` with `multi-user.target` reached and the box SSH-reachable; healthy packages are live; and the **committed config-gen is the re-projected (full-minus-unfetched) manifest** — re-hashed to a new `manifest_hash`, with the drop-set recorded — so the degraded generation is still content-addressed (not the full manifest, not an uncommitted state).

- [ ] **`gen-N/cfgsrc/<hash>` GC root** pinning the config-module source closure + host.nix per config-gen (cross-ABI re-eval survives `apm gc`).
  - **Done when** `tests/fleet/rfc-0011-cfgsrc-gc.nix` (review M-gc-inputs) asserts: after `apm gc`, the config-module **source NARs** + the `host.nix` store path remain alive via the `gen-N/cfgsrc/<hash>` root; a cross-ABI rollback then **successfully re-evals** the retained inputs (proving `cfg/` outputs-root alone is insufficient — removing `cfgsrc/` makes the same re-eval fail with a missing-source error).

- [ ] **Durable image rollback** via `bootctl set-default` + sd-boot boot-counting (`+tries`), not the lexically-highest `default aos-*.efi`.
  - **Done when** `tests/fleet/rfc-0011-image-rollback.nix` (review M-rollback-glob) asserts: an image rollback `bootctl set-default`s the older UKI and the next reboot lands on it (**not** re-selected by the lexically-highest `default aos-*.efi` glob); and a freshly rolled-out UKI tagged `aos-<ver>+N.efi` that **fails to boot** is auto-demoted by sd-boot boot-counting without operator action (boot the bad slot N times, assert the system falls back to the prior good UKI).

- [ ] **Read-of-absent-root discovery** via root-based dispatch on the missing root segment (distinct from the strict write-throw); flag throw-string parsing as the P1 stopgap retired by aos-nix structured errors.
  - **Done when** `checks.eval` (`lib/testing/rfc-0011-read-absent.nix`, review M-read-absent) asserts: a `config.firewall.forwardPolicy` read with firewall absent surfaces as `attribute 'firewall' missing` (**not** the `:744` declared-but-unset throw) and is resolved by dispatching on the missing root segment (`firewall` in `SystemRoots` → its installed owner, else a structural by-name lookup), which fetches the provider and re-evals to convergence — proving the two-detector design. A code-comment/test marker flags throw-string parsing as the P1 stopgap retired by aos-nix structured errors in P2.

- [ ] **Retarget `activate.sh.in` `prepare`** off the hard-coded Ignition binary to the `aos metadata` agent; enable `-Dfirstboot` only if firstboot is adopted (else keep manifest-rendered hostname).
  - **Done when** the `apm-system-upgrade`/activate fleet assertions confirm the `prepare` stage invokes the `aos metadata` agent (no reference to the Ignition binary remains in the substituted `activate-script.sh` golden); and the hostname path is asserted in whichever mode is adopted — manifest-rendered hostname when `-Dfirstboot` is **not** enabled, or systemd-firstboot when it is. The substituted `activate.sh.in` golden in `tests/fixtures/system-characterization-goldens/<system>/` pins the chosen wiring.


---

## Provisioning/orchestration, trust/secrets, operability, P2

Below is drop-in RFC markdown. Each checklist item is reproduced verbatim and annotated with a **DoD** (definition of done) naming the concrete, self-verifiable acceptance test that proves it. File path of the source plan: `/Users/dplecki/src/andyl/andyl-os/.claude/worktrees/rfc-0011-on-host-config-eval/docs/rfcs/0011-on-host-config-eval/implementation-plan.md`.

---

### Provisioning, substrate & orchestration (Ignition removal)

- [ ] **systemd-repart substrate.** Flip `-Drepart=enabled`/`-Dfdisk=enabled` in `pkgs/system/systemd.nix`; un-strip `systemd-repart` from the initrd (`modules/base/_initrd-builder.nix:651`); ship convention `repart.d` drop-ins (adopt ESP+root-a, fixed swap, `var` `Weight=1000` grow-to-fill); add `systemd-repart.service`; **delete** `aos-growfs` + `aos-gpt-relocate`.
  - **DoD — fleet (`tests/fleet/install-from-image.nix`, repart-extended, gate "Provisioning"):** on a fresh VM whose image is `dd`'d onto an over-sized disk, `systemctl status systemd-repart.service` is `active (exited)` `result=success`; `/proc/partitions` + `blkid` show ESP+root-a+swap+`var`; the `var` partition size ≈ full disk (grow-to-fill, within one extent); `/var` is mounted rw (`/proc/mounts`). T0 char-assertion that the old behavior held (partition labels/sizes, `/var` grown+mounted) stays green across the swap. Build proves `nix-build -A pkgs.systemd` links `systemd-repart` and `nix-build -A checks.vm.boot` no longer contains `aos-growfs`/`aos-gpt-relocate` units (grep the rendered toplevel unit set = empty).

- [ ] Retarget `aos-var-crypt`/`cryptswap` ordering from `ignition-disks` to `systemd-repart.service` (LUKS path otherwise unchanged — RFC-0006).
  - **DoD — fleet (`measured-boot.nix`):** still green unchanged (LUKS2 `/var` seal + unattended TPM unlock + SB-enforcing all pass); additionally assert `systemctl show aos-var-crypt -p After` contains `systemd-repart.service` and **not** `ignition-disks.service`. The unchanged `measured-boot` pass is the byte-for-byte-behavior proof; the ordering assertion proves the retarget.

- [ ] **Lifecycle guards.** Render destructive ops as `Type=oneshot` + state-probe (`cryptsetup isLuks`/`blkid || mkfs`) / `ConditionFirstBoot=`; never guard convergent ops (repart/tmpfiles/sysusers).
  - **DoD — fleet (`tests/fleet/apm-substrate-idempotency.nix`):** boot, reboot, boot again; assert each destructive unit (mkfs `/var`, LUKS format/enroll) ran exactly **once** (`journalctl -u <unit> --boot=<n>`: ExecStart present on first boot, `Condition...was not met`/skipped on second), while `systemd-repart.service` and `systemd-tmpfiles-setup.service` ran on **both** boots (convergent, no guard). A grep of the rendered manifest units asserts no `ConditionFirstBoot=`/marker on any repart/tmpfiles/sysusers unit (anti-pattern lint, `checks.eval`).

- [ ] **`aos metadata` agent.** `detect` + `fetch` + `authorize` exact
      `host.nix`; reuse `aos-net` + `security.rs` SSHSIG + `KeyStore`. Stash
      raw user-data, accepted `host.nix`, facts, and trust evidence.
  - **DoD — Rust + fleet:** fixture tests cover each transport and byte-exact
    pointer hashes. `platform` accepts control-plane delivery. `signed`
    accepts a signature over the exact Nix bytes and rejects unsigned,
    modified, or wrong-key input before evaluation. Stage 2 sees the same
    hash. A JSON object containing `storage` is treated as Nix source and fails
    Nix parsing; it is never interpreted as provisioning configuration.

- [ ] Net-new pieces (config-drive mount helper; vendor a YAML crate; request-timeout shim; per-platform fetchers behind `PlatformFetcher`, recorded-fixture tested).
  - **DoD — Rust (`cargo test` in `crates/aos`):** config-drive helper mounts each of `cidata`/`config-2`/`aos-metadata` labelled ISO9660/vfat fixtures and reads `user-data` (one test per label). The vendored YAML crate is in `Cargo.lock` and parses a `meta-data` fixture (build proves no `serde_yaml`). Each `PlatformFetcher` impl (AWS IMDSv2 token-dance / GCP `Metadata-Flavor` / Azure / OpenStack / DO) passes a recorded-fixture round-trip test asserting the exact request shape (headers, PUT-token→GET order) and the parsed payload. The timeout shim test asserts an IMDS call wrapped in `tokio::time::timeout` returns a timeout `Err` against a non-responding fixture endpoint within the bound.

- [ ] Render `facts.json` → `/run/aos-eval/host-facts.nix` as `host.facts.*` (D9); no imperative `/etc/hostname`/`authorized_keys` writes (manifest outputs), except the gen-0 SSH-key bootstrap carve-out.
  - **DoD — fleet (`apm-metadata-agent.nix`) + `checks.eval`:** assert `/run/aos-eval/host-facts.nix` exists and `eval` reads it as `host.facts.*` (the resolved hostname/MAC-map/disk-IDs appear in the manifest `etc`/`units`). Negative assertion: the initrd/stage-2 agent writes **no** `/etc/hostname` and **no** `authorized_keys` directly — both appear only as manifest-rendered `/etc` entries in the committed generation (`gen-N/manifest.json` lists them; no journal line shows an imperative write). Carve-out proved separately by the gen-0-key test below.

- [ ] **Unit graph (D19).** Bake template units `aos-pkg-fetch@.service` / `aos-pkg-install@.service` + `aos-fetch`/`aos-config-render`/`aos-config` targets into gen-0. New `apm fetch <pkg>` / `render-one <pkg>` subverbs.
  - **DoD — `checks.eval` + fleet (`apm-desired-sequencing.nix`):** the rendered gen-0 toplevel contains the two template units + three targets (assert by name in the systemd-unit set, pure-eval). `apm fetch <pkg>` downloads+verifies one NAR closure (exit 0, store path present) and `apm render-one <pkg>` writes that package's config artifact only (no `/etc` swap) — both asserted in-VM with a single-package fixture. T0 toplevel golden absorbs the new static units as a documented, reviewed golden diff.

- [ ] **Graph compiler** → write `/run/systemd/system/` instance dropins + `.wants` → `daemon-reload` → start `aos-config.target`; replace monolithic `aos-install-packages.service` with `aos-eval` + `aos-graph-compile` + `aos-activate`.
  - **DoD — fleet (`apm-desired-sequencing.nix`):** with a two-package fixture where `nginx → firewall`, assert (a) `/run/systemd/system/aos-pkg-install@nginx.service.d/10-edges.conf` exists with `After=aos-pkg-install@firewall.service`; (b) `journalctl` ordering shows `aos-pkg-install@firewall` start-time precedes `aos-pkg-install@nginx`; (c) two **independent** packages start concurrently (overlapping active windows in the journal); (d) `aos-install-packages.service` no longer exists and `aos-eval`/`aos-graph-compile`/`aos-activate` all reach `active (exited)`. Reconfig: `apm switch` removes a package → its `/run` unit is deleted and `reset_failed` called (unit absent from `systemctl list-units` after).

- [ ] `Wants=` for package pulls (degraded, not failed boot); `Requires=`/`BindsTo=` reserved for substrate edges; `Restart=on-failure` on fetch; `aos-activate` is the single atomic commit.
  - **DoD — fleet (`tests/fleet/apm-system-activation-fail.nix`, gate "Provisioning"):** inject one package whose fetch always fails; assert `systemctl is-system-running` = `degraded`, `multi-user.target` reached, the box is SSH-reachable, the healthy packages are `active`, and the failing `aos-pkg-fetch@<p>` shows `Restart=on-failure` budget exhausted without failing `aos-fetch.target`. Substrate-edge proof: a forced initrd substrate failure (repart/mount-var) reaches `emergency.target` (hard `Requires=` propagation), a stage-2 `/etc`-swap failure reaches `rescue.target`.

- [ ] Remove Ignition and support every advertised platform through native `aos metadata` fetchers.
  - **DoD — fleet + build:** recorded fixtures exercise every supported offline and cloud channel; every system variant builds with `pkgs.ignition`, `pkgs.butane`, and `lib/formats/ignition.nix` absent from the flake and closure; no runtime fallback or Ignition-format parser remains.

---

### Trust & secrets

- [ ] Configurable provisioning trust: `platform` by default; `signed` with public configuration anchors in the measured image and initrd.
  - **DoD — fleet (`apm-metadata-agent.nix`):** platform mode boots and
    evaluates unsigned control-plane `host.nix`; signed mode accepts a
    correctly signed file and rejects missing/wrong signatures before disk
    mutation. A vendor/fleet root plus signed operator delegation lets one
    golden image serve all instances. Stage 2 refuses bytes that do not match
    the initrd authorization record.

- [ ] `secretRef` opaque type + activation resolution contract; credentials-by-handle only, no plaintext constructor in the option type.
  - **DoD — `checks.eval` + Rust (`cargo test`):** a config module attempting a literal `value=`/`text=` on a credential **fails evaluation** with the allowed-keys error (type-level enforcement test). A `{pkg}.credentials.*` declaration renders to `LoadCredentialEncrypted=<name>:<source>` on the unit (golden-asserted) and the manifest JSON contains only `{name,source,encrypted,units,ref}` — a grep of the canonicalized manifest for any secret plaintext is empty (invariant test). Fleet: the credential bytes are placed at `source` (mode 0600) before the consuming unit starts and the unit is restarted on change (reuses `reconcile_desired_credentials`), asserted via `systemd-creds`/unit state in-VM.

- [ ] `gen-attestation/v1` record (generation_id, manifest_hash, authenticated input set) quoted alongside PCR 7/11; reuse `expected_pcr11` from the registry catalog.
  - **DoD — fleet (`measured-boot.nix`, attestation-extended) +
    attestation-verify oracle:** after activation, the quote binds PCR 7/11,
    release provenance, `trust_mode`, exact `host.nix` hash, platform identity,
    optional signer/delegation, and `facts_hash`; re-running pure eval on the
    recorded tuple reproduces `manifest_hash`.

---

### Operability & migration

- [ ] `apm switch --dry-run [--diff-against] [--json]`; persist `gen-N/manifest.json`.
  - **DoD — fleet (`apm-system-upgrade.nix`, dry-run-matches-realized gate) + Rust:** `apm switch --dry-run --json` emits an envelope with `etc_diff`/`unit_actions`/`fetch_plan`/`resolution_trace`; the fleet test runs dry-run, then activates, then asserts the **realized `/etc` and the reloaded/restarted unit set byte-equal the dry-run prediction** (the dry-run doubles as oracle). `--diff-against gen-N` loads the persisted `gen-N/manifest.json` and prints the structural diff; assert `gen-N/manifest.json` exists in the gen dir after activation. This is the "dry-run-matches-realized" P1 gate.

- [ ] Eval-failure classification + legible apm/journal surfacing.
  - **DoD — fleet (`apm-system-activation-fail.nix`) + `checks.eval`:** four injected failures each produce the exact tagged one-liner and a clean no-op on the live system (no gen created, `/etc` untouched): Assertion → `config eval failed: assertion '…' (file:line)`; Undefined option → `option '…' read but no provider`; Scalar conflict → `conflict on '…': 'x' (fileA) vs 'y' (fileB)`; OOM/timeout → `config eval killed: exceeded MemoryMax/RuntimeMaxSec`. Assert the summary is the last throw line (file:option) and the full trace is present only at `--verbose`. `checks.eval` covers the three eval-time classes; fleet covers the cgroup-kill class and the no-op property.

- [ ] Flat-merge fallback for non-migrated packages; `checks.config-parity` byte-parity gate.
  - **DoD — `checks.config-parity` (pure, every PR):** for each fixture package that has **both** a flat `expose.config` and an equivalent config module, render both ways with identical `desired.toml` inputs, canonicalize, and **byte-diff** the materialized artifacts **and** the reload/restart sets; **any** divergence fails CI. Mixed-generation fleet case asserts a generation containing one migrated + one flat package activates and both land in `/etc/aos/packages/<pkg>/…` identically. This is the P1 `checks.config-parity` gate; the flat path's determinism (`BTreeMap`) makes the diff well-defined.

- [ ] `checks.config-eval` (off-host preflight: succeeds + schema-valid + eval-twice-deterministic).
  - **DoD — `checks.config-eval` (pure, every PR):** per host fixture, evaluate with `--eval-system x86_64-linux` + checked-out `host.nix` + pinned registry lock and assert (1) `evalModules` succeeds (else fail printing the module-system error verbatim); (2) the manifest validates against the `aos.config-manifest/v1` schema; (3) **eval twice ⇒ byte-identical manifest JSON** (same discipline as the aos-nix `.drv` parity gate). Shares one Rust codepath with on-host `--dry-run`, so green CI predicts on-box behavior. This is the P1 `checks.config-eval` gate.

- [ ] VM/fleet tests: conflict no-op, successful switch matches dry-run, rollback pointer-only.
  - **DoD — fleet (three cases, P1 gate):** (a) a `host.nix` triggering a cross-package conflict → `apm` exits non-zero with the conflict message and the live generation is **untouched** (manifest hash unchanged, `/etc` identical pre/post); (b) a successful module-eval switch → realized `/etc` equals the dry-run-predicted manifest and exactly the expected units reloaded/restarted (`systemctl --failed` empty); (c) rollback to a pre-migration generation is **pointer-only** (no eval, no reboot) — assert its `cfg/`/`cfgsrc/` GC roots kept the old config closure alive so the switch needs no fetch and no re-eval.

---

### P2 — aos-nix behind the same seam

The governing P2 gate for this whole section: **byte-identical manifest vs P1 stock-Nix on the full fixture corpus** (the aos-nix `.drv`-parity discipline), with all P1 gates (`checks.config-eval`, `checks.config-parity`, the three fleet cases) still green. Each item below adds a narrower DoD on top of that umbrella gate.

- [ ] Pull `aos-nix` (RFC-0007) into the main tree; wire the `NixEval` seam.
  - **DoD — build + the umbrella parity gate:** `aos-nix` builds in-tree (`cargo check`/`nix-build -A pkgs.aos-nix` green) and is reachable behind the `NixEval` seam without any change to the manifest schema, registry format, module contract, or generation layout (assert by diffing those interfaces against P1 = empty). The seam is proven inert here; behavior parity is the next item.

- [ ] Swap the evaluator behind `eval → manifest` (no registry/module/gen changes).
  - **DoD — `checks.config-parity-p2` (new, the byte-identical-vs-P1 gate):** for every fixture in the corpus, the manifest produced by aos-nix is **byte-identical** to the P1 stock-Nix manifest (canonicalized JSON diff = empty). Fail CI on any divergence; each divergence must be root-caused (per the established aos-nix parity discipline) — no allowlist of "expected" diffs. All P1 fleet cases re-run on the aos-nix path and stay green.

- [ ] One-shot read-tracing (exact `requires` discovery; retire the fixpoint loop for the common case, keep it as backstop).
  - **DoD — `checks.eval` + perf assertion:** for a fixture needing K external providers, the aos-nix path discovers all `requires` in **one** eval (assert the resolver performed exactly 1 eval iteration via the iteration counter, vs. ≈K under P1) and the resolved provider set is **identical** to the P1 fixpoint result. The fixpoint backstop still triggers and converges when read-tracing is disabled (assert via a feature-flag test). Manifest output remains byte-identical to P1 (umbrella gate).

- [ ] In-engine bounding/timeouts (replace the OOM-kill with a clean error; path to totality analysis rejecting divergent configs pre-run).
  - **DoD — `checks.eval`:** a fixture with unbounded recursion / memory blow-up returns a **clean structured error** from aos-nix (not an external cgroup OOM-kill) with a legible message, classified the same as the P1 "timeout/OOM" class, and leaves the live system a no-op. Assert the engine returns `Err` before exhausting `MemoryMax` (i.e., no systemd kill line in the journal for that eval). Totality-analysis path: a known-divergent fixture is rejected **pre-run** with a divergence diagnostic.

- [ ] Incremental early-cutoff cache (cheap re-eval on small `host.nix` changes).
  - **DoD — perf micro-benchmark (`cargo bench`/timed `checks`):** after a full eval, a re-eval following a small `host.nix` edit recomputes only the affected subgraph — assert wall-time is a small fraction of the cold eval (e.g. ≤ ~20%) **and** the resulting manifest is byte-identical to a cold eval of the edited input (correctness of the cache: incremental == from-scratch). Both the speedup and the identity are asserted.

- [ ] Expose the option read/write graph as a first-class intrinsic to the resolver (replace AST-scan + error-parse reconstruction).
  - **DoD — `checks.eval` (graph-equivalence):** for the fixture corpus, the `graph.json` produced from the aos-nix intrinsic is **identical** (same node/edge set) to the P1 graph reconstructed from publish-time AST-scan + error-driven fixpoint. Assert the resolver no longer parses throw-strings (the P1 stopgap codepath is unreached — covered by a "no throw-string parsing" assertion), and the orchestration `After=`/`.wants` dropins generated from the intrinsic graph match the P1-generated ones byte-for-byte.
