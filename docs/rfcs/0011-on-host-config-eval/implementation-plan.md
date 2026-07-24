# Implementation plan

Phased checklist. **P1** stands the whole model up end-to-end on the existing
stock C++ Nix evaluator; **P2** swaps in `aos-nix` behind the unchanged
`eval → manifest` seam and adds the richer graph intrinsics. The seam means P1
exercises every load-bearing decision; P2 changes only discovery efficiency,
the bounding mechanism, and eval speed — not the registry format, the module
contract, or the generations.

Each item below is realized by a field-level contract in
[`build-spec.md`](build-spec.md) and verified by a definition-of-done in
[`acceptance-criteria.md`](acceptance-criteria.md); the forks/open-questions it
once depended on are locked in [`decisions.md`](decisions.md). The combination is
intended to be **goal-mode-executable** — no consequential design choice is left
to the implementer.

## T0 — Characterization suite (the FIRST code in the PR; green on master before any refactor)

Pin current behavior so every later phase runs under a regression net. Written
and verified green on master *before* P0 touches rendering. Full strategy in
[`test-plan.md`](test-plan.md).

- [ ] **Pure-eval toplevel golden** — `lib/testing/system-characterization.nix`
      + `tests/fixtures/system-characterization-goldens/<system>/` (etcDump, unit bodies,
      substituted `activate.sh.in`, os-release). Added to `checks.eval`.
      **Comparator normalizes job scripts to text** (the only intentional P0
      byte change, review C2).
- [ ] **Flat-merge Rust golden** — `crates/aos-package/tests/golden_config_artifact.rs`
      + fixtures: snapshot `render_package_config()`, re-render shuffled ⇒ stable
      ⇒ matches golden. Becomes the `checks.config-parity` oracle.
- [ ] **Activate + substrate fleet assertions** — extend
      `apm-system-upgrade`/`install-from-image`/`measured-boot` from "boots" to
      pin observable outcomes (repart/cryptsetup status, partition sizes, `/var`
      mount, `/var/etc` allowlist survival, post-swap `systemctl --failed` empty).
- [ ] Commit the goldens at the branch base; an unexpected golden diff in CI is a
      caught regression (barrier pattern).

## P0 — render/assemble split (no behavior change)

The enabling refactor; ships independently and de-risks everything after it.
**Runs under the T0 toplevel golden** — the only allowed golden change is the
job-script normalization, documented in the commit.

- [ ] Make `lib/modules/systemd/lib.nix` `generateUnits` a **pure function**
      returning `{ unitName → { text; mode; … } }` instead of a derivation.
- [ ] **Shell-snippet options → manifest text (F2-A, review C2).** Reroute
      `script`/`preStart`/`postStart`/`reload`/`preStop`/`postStop`
      (`unit-options.nix:644` `makeJobScript`) to emit job-script **text** into
      `manifest.jobScripts`; the materializer writes gen-local paths and rewrites
      `Exec*=`. Add a publish lint that rejects derivation refs in `config` outputs.
- [ ] Make the `modules/base/build.nix` `/etc` assembly emit the **manifest**
      data structure (`aos.config-manifest/v1`) as a pure value.
- [ ] Have the builder-side `system.build.toplevel` consume the manifest via a
      thin materialize step → byte-identical toplevel output (gate: existing
      `checks.vm.boot` + image hashes unchanged, **job scripts compared
      semantically (text), not by embedded store path**).
- [ ] Define the manifest JSON schema as a shared Rust + Nix data contract
      (incl. `jobScripts`; `inputs` = base_lib + evaluator + config_modules +
      host_nix + instance_facts).

## P1 — on-host eval with stock Nix

### Packaging & module outputs

- [ ] Add a second **`config` output** to `mkDerivation` (the package's
      config-only module + private helpers), references-as-strings discipline.
- [ ] Promote `expose` (`pkgs/build-support/_expose-renderer.nix`) into a config
      module: `firewall.*`, `kernel.*`, units, `config.artifacts`,
      `permissions.*`, `credentials` become evaluated module options.
- [ ] Registry: add `Option<ConfigOutputMeta>` to `PackageMeta`
      (`crates/aos-package/src/types.rs`) + `FEATURE_MULTI_OUTPUT_V1` gate;
      `store/` realization entries for the config output.
- [ ] Remove the hand-authored `expose.requires` edge list; derive per-package
      `provides` metadata (options-only eval at publish) + AST-scan requires.

### Namespacing & module system

- [ ] Per-package root mounting: each `config` module as a submodule at `{pkg}.*`.
- [ ] `SystemRoots` for shared roots (`root → installed owner`), per-system
      exclusivity + install-time trust (key policy / operator allowlist)
      enforced at resolve (optionally early at install).
- [ ] Variants/alternatives: `Provides`/`Conflicts` on a virtual shared root
      (single-declarer-per-resolved-set).
- [ ] Merge precedence: file-provenance priority tagging at `lib/modules.nix:695`
      → `host.nix` bare defs at priority 75 (do **not** subtree-wrap).
- [ ] `host.facts.*` privileged root (`attrsOf`-by-MAC); reject ambient facts.
- [ ] Shared scalars typed `uniq`/`mergeEqualOption`; reject multiple declarers.
- [ ] Enablement policy: forbid foreign `enable` writes (per-def authenticated
      provenance + the installed owner's contributable surface in `SystemRoots`);
      provider sub-feature enable allowed; dependencies as resolve-time
      assertions.

### Resolver & evaluator

- [ ] Error-driven resolve↔eval fixpoint (parse the strict throw → root-based
      dispatch → fetch provider → re-eval), with causal-chain diagnostics +
      iteration cap.
- [ ] `module_abi`: bake the monotonic integer into `os-release`/toplevel;
      config modules declare `module_abi_compat`; resolver fail-closed refuses
      incompatible modules pre-eval (mirror `trust_ctx.enforce_totality()`).
- [ ] `aos-eval.service` (stage-2, `After=network-online.target`,
      `Before=aos-install-packages.service`, `Type=oneshot`, best-effort) running
      sandboxed stock Nix (`--pure-eval --restrict-eval
      --allow-import-from-derivation=false`) → manifest.
- [ ] Hardened transient eval scope: `MemoryMax=2G`/`MemoryHigh=1536M`/
      `RuntimeMaxSec=120`/`TasksMax`, `ProtectSystem=strict`, read-only input
      binds, `SystemCallFilter`; fail-closed on kill.

### Generations

- [ ] Split `SystemGeneration` into **image-gen** + **config-gen**; the existing
      `current → gen-N` pointer becomes the config-gen pointer.
- [ ] Config-gen records `{ image_gen_parent, module_abi_pinned, manifest_hash,
      config_module_closure, host_nix_ref }`; content-address by `manifest_hash`.
- [ ] APM materialize step: manifest → composefs `/etc` overlay (on-host
      `mkfs.erofs` + symlink trees) → generation dir; invoke `activate <N>`.
- [ ] Upgrade ordering (image-first → reboot → re-eval → switch); config-only
      change skips reboot. Rollback verbs: config (pointer switch, same-ABI) +
      image (A/B UKI). Cross-ABI rollback re-evals retained inputs.
- [ ] `gen-N/cfg/<hash>` GC roots; retention/prune unchanged.

### Provisioning, substrate & orchestration (Ignition removal)

systemd-native substrate + the `aos metadata` agent + the unit graph.

- [ ] **systemd-repart substrate.** Flip `-Drepart=enabled`/`-Dfdisk=enabled`
      in `pkgs/system/systemd.nix`; un-strip `systemd-repart` from the initrd
      (`modules/base/_initrd-builder.nix:651`); ship convention `repart.d`
      drop-ins (adopt ESP+root-a, fixed swap, `var` `Weight=1000` grow-to-fill);
      add `systemd-repart.service`; **delete** `aos-growfs` + `aos-gpt-relocate`.
- [ ] Retarget `aos-var-crypt`/`cryptswap` ordering from `ignition-disks` to
      `systemd-repart.service` (LUKS path otherwise unchanged — RFC-0006).
- [ ] **Lifecycle guards.** Render destructive ops as `Type=oneshot` +
      state-probe (`cryptsetup isLuks`/`blkid || mkfs`) / `ConditionFirstBoot=`;
      never guard convergent ops (repart/tmpfiles/sysusers).
- [x] **`aos metadata` agent.** `aos metadata detect` + `fetch`; reuse
      `aos-net` + `security.rs` SSHSIG + `KeyStore`; add `authorize` for the
      exact literal `host.nix` bytes. Stash raw user-data, accepted `host.nix`,
      facts, and trust evidence. Support a hash-pinned URL/signature pointer
      only as transport metadata; remove `aos.provisioning/v1` and every
      storage field outside `host.nix`.
- [x] **Restricted provisioning eval.** Add
      `baseLib.evalProvisioningConfig`, which declares only
      `aos.provisioning`, runs in initrd under restrict-eval/no-IFD, and emits
      `aos.provisioning-plan/v1` pure JSON. Add the undeclared-throw regression
      that locks the non-strict/no-global-freeform invariant.
- [x] **Typed storage renderer.** Deserialize the evaluated plan into a strict
      Rust contract, reject unsafe devices/types/labels/formats/sizes, group by
      device, and render generated per-device repart definitions. The
      no-host.nix fallback evaluates the same default Nix module and uses the
      same validator/renderer.
- [x] **One-time provisioning commit.** Reserve a GPT marker as
      `aos-provisioning-pending-v1`; dry-run all devices, apply all devices,
      verify, then relabel it to `aos-provenance-operator-v1` or
      `aos-provenance-fallback-v1`. Only committed labels suppress future
      mutation. Committed boots do not depend on metadata; any later stage-2
      comparison may report drift but can never reopen disk mutation.
- [ ] Net-new pieces (the rest is reuse): a **config-drive mount helper**
      (`blkid -L cidata|config-2|aos-metadata` + ISO9660/vfat mount — the one
      capability with no aos primitive); **vendor a YAML crate** (no
      `serde_yaml` in the lock); a `tokio::time::timeout` **request-timeout
      shim**; the thin **per-platform fetchers** behind a `PlatformFetcher`
      trait (AWS IMDSv2 / GCP / Azure / OpenStack / DO), recorded-fixture tested.
- [ ] Render `facts.json` → `/run/aos-eval/host-facts.nix` as `host.facts.*`
      (D9); no imperative `/etc/hostname`/`authorized_keys` writes (manifest
      outputs), except the gen-0 SSH-key bootstrap carve-out.
- [ ] **Unit graph (D19).** Bake template units `aos-pkg-fetch@.service` /
      `aos-pkg-install@.service` + `aos-fetch`/`aos-config-render`/`aos-config`
      targets into gen-0. New `apm fetch <pkg>` / `render-one <pkg>` subverbs.
- [ ] **Graph compiler** (new `crates/aos-package` module): consume
      `manifest.json` + `graph.json` → write `/run/systemd/system/` instance
      dropins + `.wants` (edges mirror the config DAG) → `daemon-reload` → start
      `aos-config.target`, via the `aos-systemd` client. Replace the monolithic
      `aos-install-packages.service` with `aos-eval` + `aos-graph-compile` +
      `aos-activate`.
- [ ] `Wants=` for package pulls (degraded, not failed boot); `Requires=`/
      `BindsTo=` reserved for substrate edges; `Restart=on-failure` on fetch;
      `aos-activate` is the single atomic commit.
- [ ] Remove Ignition, Butane, and `lib/formats/ignition.nix`; every supported
      offline and cloud transport is implemented natively by `aos metadata` and
      covered by recorded fixtures.

### Golden-image / host-policy boundary

- [ ] Split mixed server/edge/debug profiles into immutable image-capability
      modules and runtime role modules bundled in the base library. Production
      systems select no workload/debug role; `host.nix` selects
      `aos.roles.server`/`edge` as needed.
- [x] Remove production passwordless root autologin. Keep any initrd recovery
      shell as an explicit image capability; make runtime diagnostics ordinary
      desired packages selected by authenticated `host.nix`.
- [ ] Replace image package declarations/presets with
      `aos.apm.desiredPackages = [ <registry-name> ... ]`. Only
      boot/eval/fetch/verify/activate/recovery packages are bundled by default.
      Workload users, D-Bus policy, units, and files come from each resolved
      package's config module.
- [ ] Move hostname, locale, timezone, host state version, networking, users,
      SSH, chrony, runtime security, firewall, audit, journald, monitoring,
      PAM, runtime PKI, and registry routing to the host manifest. Keep image
      version/module ABI, UKI/kernel/initrd settings, verity, measured boot,
      and initial trust roots image-owned.
- [ ] Replace config-dependent frozen artifacts with manifest/runtime
      materialization: PAM limits as `/etc` text, extra CA roots as runtime
      bundle inputs, package-derived D-Bus policy from the resolved package
      set, and desired package profiles/presets from `host.nix`.

### Trust & secrets

- [ ] Provisioning trust policy: default `platform`; opt-in `signed` with a
      vendor/fleet root included in the measured image and initrd plus optional
      signed operator-key delegation. Authorize the exact `host.nix` bytes
      before restricted evaluation and bind stage-2 to their accepted hash.
- [ ] `secretRef` opaque type + activation resolution contract (reuse
      `credential_artifact.rs::reconcile_desired_credentials`); credentials-by-
      handle only, no plaintext constructor in the option type.
- [ ] `gen-attestation/v1` record (generation_id, manifest_hash, authenticated
      input set including trust mode and optional signer) quoted alongside PCR
      7/11; reuse `expected_pcr11` from the registry
      catalog.

### Operability & migration

- [ ] `apm switch --dry-run [--diff-against] [--json]`; persist
      `gen-N/manifest.json`.
- [ ] Eval-failure classification + legible apm/journal surfacing.
- [ ] Flat-merge fallback for non-migrated packages; `checks.config-parity`
      byte-parity gate.
- [ ] `checks.config-eval` (off-host preflight: succeeds + schema-valid +
      eval-twice-deterministic).
- [ ] VM/fleet tests: conflict no-op, successful switch matches dry-run, rollback
      pointer-only.

## P2 — aos-nix behind the same seam

- [ ] Pull `aos-nix` (RFC-0007) into the main tree; wire the `NixEval` seam.
- [ ] Swap the evaluator behind `eval → manifest` (no registry/module/gen
      changes).
- [ ] One-shot read-tracing (exact `requires` discovery; retire the fixpoint
      loop for the common case, keep it as backstop).
- [ ] In-engine bounding/timeouts (replace the OOM-kill with a clean error;
      path to totality analysis rejecting divergent configs pre-run).
- [ ] Incremental early-cutoff cache (cheap re-eval on small `host.nix` changes).
- [ ] Expose the option read/write graph as a first-class intrinsic to the
      resolver (replace AST-scan + error-parse reconstruction).

### Review-driven hardening

Findings folded in from the adversarial review (full log:
[`known-issues.md`](known-issues.md)). The forks (F1/F2/F3) are **resolved** in
[`decisions.md`](decisions.md); the items marked ⟂ are now unblocked and their
mechanisms are specified in [`build-spec.md`](build-spec.md).

- [ ] ⟂ **F1 — anchor the evaluator/base-lib root to measured boot**: dm-verity
      on the erofs root with the roothash on the measured kernel cmdline
      (`verity.nix` exists but is unused in production), or embed evaluator+base-lib
      in the UKI initrd. Without it the producer is unmeasured.
- [ ] ⟂ **F3 — capability-scoped contribution surface**: shared-root owners
      declare contributable sub-paths; resolver enforces writes against them +
      authenticated provenance (not module `_file`).
- [ ] **Provenance from authenticated fetch source**, not module-supplied
      `_file`, for both priority-75 lift and conscription detection.
- [ ] **Instance facts as a recorded input**: `facts_hash` (+ retained
      `facts.json`) in the manifest `inputs` + `gen-attestation`; remove any
      pre-verification `authorized_keys` seeding from the facts channel.
- [ ] **Static-networking seed** from platform metadata in the initrd agent for
      DHCP-less clouds (DO/OpenStack) so stage-2 can reach the registry.
- [ ] **Authenticated first-boot `host.nix` projection**: absent `host.nix`
      evaluates the base default `aos.provisioning.storage`; a present file is
      authenticated then partially evaluated in initrd, validated in Rust,
      rendered to transient `repart.d`, and committed once. Reject raw
      fragments and invalid plans before GPT mutation with no fallback.
- [ ] **Degraded commit = re-projected manifest** (full minus un-fetched),
      re-hashed, drop-set recorded — keeps the generation content-addressed.
- [ ] **`gen-N/cfgsrc/<hash>` GC root** pinning the config-module source closure
      + host.nix per config-gen (cross-ABI re-eval survives `apm gc`).
- [ ] **Durable image rollback** via `bootctl set-default` + sd-boot
      boot-counting (`+tries`), not the lexically-highest `default aos-*.efi`.
- [ ] **Read-of-absent-root discovery** via root-based dispatch on the missing
      root segment (`SystemRoots` for shared roots, else structural by-name
      lookup; distinct from the strict write-throw); flag throw-string parsing as
      the P1 stopgap retired by aos-nix structured errors.
- [ ] **Retarget `activate.sh.in` `prepare`** off the hard-coded Ignition binary
      to the `aos metadata` agent; enable `-Dfirstboot` only if firstboot is
      adopted (else keep manifest-rendered hostname).

## Gates

- **T0:** the characterization goldens (toplevel snapshot, flat-merge Rust
  goldens) are **green on master** and committed at the branch base before P0.
- **P0:** image hash + `checks.vm.boot` unchanged, and the **T0 toplevel golden
  stays green** after the render/assemble refactor (job scripts compared as text).
- **P1:** `checks.config-eval` + `checks.config-parity` green; fleet
  conflict-no-op + dry-run-matches-realized + pointer-only-rollback green;
  on-host eval within the perf budget.
- **Provisioning:** `systemd-repart` applies the baked default or an
  authenticated `host.nix` storage projection on first boot and is a no-op on reboot; invalid
  declared plans stop before GPT mutation; `aos metadata` covers every
  advertised offline and cloud channel natively; a single failing package yields
  `is-system-running = degraded` with `multi-user.target` reached and the box
  SSH-reachable (`tests/fleet/apm-system-activation-fail.nix`).
- **P2:** byte-identical manifest vs P1 stock-Nix on the full fixture corpus
  (the aos-nix parity discipline), plus the P1 gates still green.
