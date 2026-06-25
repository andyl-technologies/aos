# Implementation plan

Phased checklist. **P1** stands the whole model up end-to-end on the existing
stock C++ Nix evaluator; **P2** swaps in `aos-nix` behind the unchanged
`eval → manifest` seam and adds the richer graph intrinsics. The seam means P1
exercises every load-bearing decision; P2 changes only discovery efficiency,
the bounding mechanism, and eval speed — not the registry format, the module
contract, or the generations.

## P0 — render/assemble split (no behavior change)

The enabling refactor; ships independently and de-risks everything after it.

- [ ] Make `lib/modules/systemd/lib.nix` `generateUnits` a **pure function**
      returning `{ unitName → { text; mode; … } }` instead of a derivation.
- [ ] Make the `modules/base/build.nix` `/etc` assembly emit the **manifest**
      data structure (`aos.config-manifest/v1`) as a pure value.
- [ ] Have the builder-side `system.build.toplevel` consume the manifest via a
      thin materialize step → byte-identical toplevel output (gate: existing
      `checks.vm.boot` + image hashes unchanged).
- [ ] Define the manifest JSON schema as a shared Rust + Nix data contract.

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
- [ ] Remove the hand-authored `expose.requires` edge list; derive the
      provides index (options-only eval at publish) + AST-scan requires.

### Namespacing & module system

- [ ] Per-package root mounting: each `config` module as a submodule at `{pkg}.*`.
- [ ] Owner registry for shared roots (`root → owner@version`), exclusivity +
      trust-gate (system-extension key / operator allowlist) enforced at
      publish/resolve.
- [ ] Variants/alternatives: `Provides`/`Conflicts` on a virtual shared root
      (single-declarer-per-resolved-set).
- [ ] Merge precedence: file-provenance priority tagging at `lib/modules.nix:695`
      → `host.nix` bare defs at priority 75 (do **not** subtree-wrap).
- [ ] `host.facts.*` privileged root (`attrsOf`-by-MAC); reject ambient facts.
- [ ] Shared scalars typed `uniq`/`mergeEqualOption`; reject multiple declarers.
- [ ] Enablement policy: forbid foreign `enable` writes (per-def file provenance
      + owner/provider registry); provider sub-feature enable allowed;
      dependencies as resolve-time assertions.

### Resolver & evaluator

- [ ] Error-driven resolve↔eval fixpoint (parse the strict throw → index lookup
      → fetch provider → re-eval), with causal-chain diagnostics + iteration cap.
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

systemd-native substrate + the `aos metadata` agent + the unit graph. Phased to
keep an Ignition-compat fallback (see [`provisioning.md`](provisioning.md) §Phasing).

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
- [ ] **`aos metadata` agent.** `aos metadata detect` (port
      `pkgs/boot/aos-platform-detect.nix`) + `fetch`; reuse `aos-net` +
      `security.rs` SSHSIG + `TrustStore`. Transport-only in initrd; stash
      `/run/aos-metadata/{host.nix,host.nix.sig,facts.json}`. Literal-Nix payload
      + URL-pointer (`sha256` content-pin). Reuse surface in
      [`provisioning.md`](provisioning.md) §Implementation.
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
- [ ] Phase out Ignition: keep `ignition-fetch` (payload-only) → `aos metadata`
      for offline channels (ISO/NoCloud/config-drive/fw_cfg) → cloud IMDS
      (AWS/GCP/DO/OpenStack); drop `pkgs.ignition`/`pkgs.butane`/
      `lib/formats/ignition.nix` when the fallback is unused.

### Trust & secrets

- [ ] `trusted-config-keys.d/<op>.pub` baked into the image
      (`modules/base/apm-registries.nix`); evaluator verifies the `host.nix`
      operator signature **before** eval.
- [ ] `secretRef` opaque type + activation resolution contract (reuse
      `credential_artifact.rs::reconcile_desired_credentials`); credentials-by-
      handle only, no plaintext constructor in the option type.
- [ ] `gen-attestation/v1` record (generation_id, manifest_hash, signed input
      set) quoted alongside PCR 7/11; reuse `expected_pcr11` from the registry
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

## Gates

- **P0:** image hash + `checks.vm.boot` unchanged after the render/assemble
  refactor.
- **P1:** `checks.config-eval` + `checks.config-parity` green; fleet
  conflict-no-op + dry-run-matches-realized + pointer-only-rollback green;
  on-host eval within the perf budget.
- **Provisioning:** `systemd-repart` carves/grows `/var` on a fresh VM and is a
  no-op on reboot (idempotent); `aos metadata` fetches+stashes literal-Nix
  user-data across the offline channels; a single failing package yields
  `is-system-running = degraded` with `multi-user.target` reached and the box
  SSH-reachable (`tests/fleet/apm-system-activation-fail.nix`); Ignition fallback
  path still green until each native fetcher lands.
- **P2:** byte-identical manifest vs P1 stock-Nix on the full fixture corpus
  (the aos-nix parity discipline), plus the P1 gates still green.
