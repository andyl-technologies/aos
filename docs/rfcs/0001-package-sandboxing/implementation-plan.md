# RFC-0001 — Implementation plan (all phases)

This is the single tickable master plan for AOS Package Sandboxing. It spans
every phase from the schema foundation through the module-tree dissolve and the
explicitly-deferred tail. Each topic doc in this set carries its own
`## Implementation checklist`; **this document is the roll-up**, and it adds the
phase ordering, the gate dependencies, and the falsifiable exit criteria.

Per RFC discipline the maturity claim lives only in the set's
[`README.md`](README.md); this document makes no status claim. It is bound to
two documents and must not contradict them:

- [`open-questions.md`](open-questions.md) — the **decision register**
  (Decisions 1–25, each with disposition and owner). Every box below cites the
  decisions it closes by number (`D1`–`D25`).
- [`migration.md`](migration.md) — the cutover plan (the module tree is
  dissolved into `pkgs/` `expose` blocks).

## Budget mandate

This plan is governed by an **unlimited-engineering-budget, no-corners-cut**
mandate: the goal is the **state-of-the-art** package-sandboxing OS
([`state-of-the-art.md`](state-of-the-art.md)), not a cost-bounded MVP. That
reframes how the phases below are read:

- **The full stack is committed.** The state-of-the-art additions —
  hardware-rooted runtime attestation ([`attestation.md`](attestation.md)),
  dm-verity package roots, the layered Landlock + MAC + eBPF-LSM enforcement
  stack ([`enforcement.md`](enforcement.md)), and the in-toto/SLSA + transparency
  supply chain — are **in scope, built, not "ship if we have time."**
- **Cost is never a reason to defer.** Items the earlier draft deferred on
  engineering-cost grounds (notably dm-verity / `CONFIG_DM_VERITY` and the
  verity-signed `RootImage=` path) are **un-deferred** and now have phases.
- **Correctness-driven deferrals still hold.** The one deferral the budget does
  *not* lift is the **nspawn substrate** (Decision 17): it stays deferred because
  it would regress k3s's `KillMode=process` and no multi-unit-init package
  exists — a *merit* reason, not a *cost* reason.
- **The correctness gates remain absolute.** The Decision 17 spike (Phase 3), the
  `systemd-analyze security` per-package CI gate (Phase 8), the byte-stable schema
  (Phase 0), and the fail-closed capability gate (D19) gate every feature,
  always. Budget does not waive them.

## How to use this plan

- **The plan is a build *order* with explicit gates, not a strict serial
  schedule.** A phase begins when its true predecessor's exit criterion holds
  (the gate edges in the master table). Independent deliverables inside a phase,
  and independent phases, may proceed in parallel.
- **Tick a box only when its evidence exists** — a green `checks.eval` run, a
  VM/fleet test, a serde round-trip test, a recorded spike result. Falsifiable,
  not aspirational. A box names the **concrete file(s)** it lands in so the
  implementer does not have to choose placement.
- **The schema is pinned in Phase 0, before any permission-bearing package
  ships.** D12/D18/D19 and the policy format are wire/disk contracts on a
  content-addressed, signed registry; getting them wrong is expensive to
  migrate. They land first and are then held invariant.
- **Phase 3 is the single implementation gate.** The Decision 17 validation
  spike (materialize the default `expose-minimal` proving package, the
  side-effect `expose-smoke` package, and `k3s` as per-unit services) must pass
  before Phases 4–7 build on the per-unit substrate. It is
  *validation* of a resolved direction, not an open decision.
- **Every verification-tracked item in the set is collected in the
  [verification register](#needs-verification-register) below** and tagged to
  the phase that must resolve it. The implementer should clear each one rather
  than guessing.

## The invariants (do not violate)

- **Hermetic from source.** Container roots and any new build helper use only
  AOS packages (`mkfs.ext4 -d`, `fakeroot`, `exportReferencesGraph`); no host
  tools, no OCI imports (CLAUDE.md).
- **No evaluator on the host.** `apm install` runs with no `lib.evalModules`.
  All integration is build artifacts in the package's store output / registry
  metadata (the [`authoring.md`](authoring.md) forcing function). A box that
  would need host-side eval is wrong.
- **Manifest is the single source of truth for privilege**, signed, static per
  package version, substrate-independent ([`permissions.md`](permissions.md)).
- **Honest labeling.** k3s is *not* a sandbox; the computed confinement label
  must say so on operator surfaces, not only in docs (D1, D10).
- **Default Off / declarative.** Image ships `disable *`; install-at-boot
  reconciles the desired package set, including removals.
- **Fail closed.** Old clients refuse permission-bearing packages they cannot
  fully parse (D19), before any such package is published.

---

## Master progress table

| Phase | Goal | Gate (begins when) | Closes | Status |
|-------|------|--------------------|--------|--------|
| **P0** | Schema & policy foundation: registry metadata, policy file, `requires`, the fail-closed capability gate, the permission surface | — (do first) | D2, D12, D18, D19; D1(a) | ☑ |
| **P1** | `expose` authoring + build-time renderer (eval-free artifacts via `passthru`) | P0 schema pinned | authoring.md mechanics | ☑ |
| **P2** | Target sandbox + gated side-effect services + nftables reload coherence + eval assertion | P1 | D15; activation.md | ☑ |
| **P3** | Per-unit sandboxing materialization + confinement label + **the Decision 17 validation spike** (the gate) | P1, P2 | D2, D4, D10, D17; D1(b) | ☑ |
| **P4** | Preset enablement (image `disable *`; Ignition per-host preset; every-boot `aos-preset.service`) | P2 | D8 (enable half) | ☑ |
| **P5** | `apm install` + install-at-boot + **declarative reconciliation (install + prune)** + upgrade/rollback + **layered config** (TPM2 creds / schema'd artifact / EnvironmentFile) + **hot-reload plumbing** | P3, P4 | D8 (install half), D9, D11, D16, D24, D25 | ☑ |
| **P6** | Container roots (volatile per-service overlay `RootDirectory=` with authenticated store lower) + the three network modes | P3 | D3, D5, D6 | ☑ |
| **P7** | Dissolve `modules/roles/` into `pkgs/` `expose`; `modules/` shrinks to policy | P1–P6 green per package | D14; migration.md | ☑ |
| **P8** | Layered enforcement: Landlock + generated MAC + eBPF-LSM, full systemd hardening baseline, per-package `systemd-analyze security` CI gate, per-package UID identity | P3 | D2, D10, D20 | ☑ |
| **P9** | Runtime integrity & attestation: dm-verity package roots (`RootImage=`+`RootHashSignature=` vs the `.platform` keyring), measure package+manifest into PCR 15, TPM quote + registry golden-measurements catalog | P6, P8 (+ RFC-0006) | D5, D6, D21, D22 | ☑ |
| **P10** | Supply-chain provenance: in-toto/SLSA attestation (NAR + manifest), transparency log, TUF roles/thresholds | P0 | D23 | ☑ |
| **P11** | Out of scope **on merit** (not cost): nspawn (dominated), microVM tier (planned future effort — untrusted workloads), machined/portabled/importd (attack surface), L2 zones, perf measurement | — (merit / scheduled later) | D7, D13, D17 | ☑ |

Legend: ☐ not started · ◐ in progress · ☑ exit criterion met. Phases 8–10 are
the state-of-the-art additions under the [budget mandate](#budget-mandate);
they gate on the per-unit substrate (P3) / package roots (P6) but are
otherwise independent workstreams that proceed in parallel.

---

## Phase 0 — Schema & policy foundation

**GOAL.** Pin every wire/disk contract before any permission-bearing package
exists, and make old clients fail closed. Nothing downstream should have to
invent a field.

**Deliverables.**

- [x] **Capability gate (D19) — first.** Add a `min-format` / `requires-features`
      field to `PackageMeta` (`crates/aos-package/src/types.rs`) and the registry
      parser (`crates/aos-package/src/registry/parse.rs`); permission-bearing
      entries carry the gate inside a structured `references` table so an apm
      predating the schema **fails closed** instead of silently dropping the
      privilege metadata. Land this *before* any `[permissions]`/`expose` package
      is published. The platform parser rejects unknown fields; the structural
      gate covers older clients that only understood `references = [...]`.
- [x] **Hybrid package metadata (D12).** Add `expose: Option<ExposeMeta>` and the
      signed `permissions` manifest to `PackageMeta`; registry TOML gains
      `[…expose]` + `[…permissions]` sections, all `#[serde(default)]`. Shape:
      `ExposeMeta { target, units, images, requires, config, provides, uses }`,
      plus `ExposeArtifactMeta` and the signed `PermissionsMeta` surface.
      The TOML (tag-signed, visible pre-fetch) carries `target`/`requires`/the
      `[permissions]` manifest so `apm info --permissions` and the host policy
      check work **without** fetching the closure; the rendered unit files ride
      the closure as `pkg.expose` (P1).
- [x] **`requires` field + resolver semantics (D18).** `requires: Vec<String>`
      (package names, not store-path hashes). Semantics: **install-time pull-in**
      (deb-style `Depends:`) materialized atomically in the shared profile
      generation; **no version-constraint solver** (the registry channel model
      already pins versions). Resolve names in `crates/aos-package/src/resolve.rs`
      (today hash-only); emit target ordering edges in the expose phase (P5).
- [x] **The permission surface (`permissions.md`).** Document the manifest
      fields and their per-unit-directive mapping as the canonical table:
      `capabilities`→`CapabilityBoundingSet=`/`AmbientCapabilities=`,
      `network`→`PrivateNetwork=`, `devices`→`DeviceAllow=`,
      `host-paths`→`BindPaths=`/`BindReadOnlyPaths=`,
      `cgroup-delegate`→`Delegate=`, `privileged-users`→`PrivateUsers=`,
      `kernel-modules`→host-fulfilled service (not a unit directive),
      `syscalls`→`SystemCallFilter=` (named profiles only),
      `security-label`→SELinux/AppArmor context.
- [x] **Named policy tiers + syscall profiles.** Tiers `restricted` / `baseline`
      / `privileged` (K8s Pod Security Standards lesson); syscall values are
      **named profiles** pinned to systemd syscall groups (`@system-service`,
      `@privileged`), never free-form.
- [x] **Policy file format (D1(a), D2) — confirm the proposal.** `/etc/aos/policy.toml`:
      a named `tier` + optional per-permission overrides + the `kernel-modules`
      allowlist; image-baked EROFS default, overridable per host by an
      Ignition-written copy in a higher overlay layer (same precedence as
      presets); evaluated by `apm` at install/enable. Nix-evaluated policy is
      rejected (no evaluator at runtime install). Parser in `crates/aos-package/`.

**Phase 0 implementation scope.** `apm` can parse, validate, display, resolve,
persist, and policy-admit generator-authored registry metadata carrying these
fields. Teaching `apr publish` and the package build renderer to emit that
metadata is Phase 1, where the `expose` authoring artifact is introduced.

**Closes.** D19, D12, D18, D2; D1(a) (pending confirmation of the proposed file
format). Produces the schema every later phase keys off.

**EXIT CRITERIA.** The schema serde-round-trips in a unit test; an old-format
apm binary refuses a `min-format`-bearing fixture (fail-closed test); the
permission table and policy format are documented; `aos fmt --check` +
`checks.eval` green. **No permission-bearing package is published before this
exit holds.**

---

## Phase 1 — `expose` authoring + build-time renderer

**GOAL.** Any `pkgs/` derivation can carry an optional `expose` attribute,
rendered at build time into eval-free, signable artifacts — no new package type,
no central module tree. (migration.md increment 1.)

**Deliverables.**

- [x] **Route `expose` through `mkDerivation`.** Add `expose` to the
      `removeAttrs` filter list in `lib/derivations.nix` (~`:478–656`) — unknown
      attrs flow into `builtins.derivation` where a nested attrset fails — and
      hand it to the renderer instead. One filter-list entry, not N top-level args.
- [x] **Build-time renderer as a cheap sibling derivation.** Render
      `expose.units` to unit text + a manifest copy via a trivial builder
      (`pkgs/build-support/trivial-builders.nix`), surfaced as `pkg.expose` via
      `passthru`. Editing a unit re-renders text and never rebuilds the payload;
      the payload closure never references its own integration.
- [x] **Reuse the pure renderers.** Call `serviceToUnit`/`targetToUnit`/… from
      `lib/modules/systemd/lib.nix` + `render-role.nix` (verified pure, callable
      outside `evalModules`); typed validation by evaluating `unit-options.nix`
      types over the attrset at render time.
- [x] **Enumeration helpers.** `lib.filterAttrs (_: p: p ? expose) pkgs` for
      fleet-spec and eval checks — the second instance of the existing optional-
      attr pattern (`checks`, `default.nix:137–151`).
- [x] **Validation placement.** Validate `expose.permissions` at **package build**
      (authoring feedback) **and** at `apr publish` (the gate). (See
      [Needs-verification register](#needs-verification-register).)

**Closes.** The [`authoring.md`](authoring.md) mechanics.

**EXIT CRITERIA.** A trivial `pkgs/` derivation with an `expose` block builds;
`pkg.expose` is a store path containing valid, `unit-options`-typed unit text +
a manifest copy; editing a unit re-renders without rebuilding the payload; the
payload closure does not reference its integration. `checks.eval` green.

---

## Phase 2 — Target sandbox + gated side-effect services

**GOAL.** Synthesize the per-package target and its gated side-effect services
with the three sandbox invariants. This is [`activation.md`](activation.md)'s
design, now produced by the P1 renderer (not a `modules/roles` synthesis).

**Deliverables.**

- [x] **Synthesize `aos-pkg-<name>.target`** (D15 naming, resolved). Members are
      `PartOf=` + `WantedBy=` the target; no member is `WantedBy=` a system target
      directly. The generated package service carries `PartOf=aos-pkg-<name>.target`.
- [x] **Gated side-effect oneshots** replacing the three global scan-dir drop-ins:
      `aos-pkg-<name>-modules.service` (`modprobe -a`),
      `aos-pkg-<name>-sysctl.service` (`sysctl -w`),
      `aos-pkg-<name>-firewall.service` (`nft add/delete element` against the base
      `allowed_tcp`/`allowed_udp` sets) — each `WantedBy`/`PartOf` the target.
- [x] **nftables reload coherence.** Each firewall service declares
      `ReloadPropagatedFrom=nftables.service` and an `ExecReload=` identical to
      its `ExecStart` (re-adding an element is idempotent), so a base-ruleset
      reload (`nft -f` begins with `flush ruleset`) re-applies every *active*
      package's ports. Drop the `include "/etc/nftables.d/*.nft"` line from
      `modules/security/firewall.nix`.
- [x] **Eval-time sandbox assertion.** Single activation root + **zero** storage
      entries under `/etc/modules-load.d`, `/etc/sysctl.d`, `/etc/nftables.d`.
- [x] **Teardown semantics.** Disabled = strict (nothing applied); stopped =
      `PartOf` propagates stop, firewall `ExecStop` removes ports, workload stops;
      loaded modules + applied sysctls stay (documented one-way).

**Closes.** D15; the [`activation.md`](activation.md) shape.

**EXIT CRITERIA.** Rendered units show the target + the three gated services with
the correct edges; the assertion fires on an injected global-scan-dir violation;
a live `nftables.service` reload re-applies an active package's ports (test).

---

## Phase 3 — Per-unit sandboxing + the Decision 17 validation spike (THE GATE)

**GOAL.** Materialize the manifest as per-unit isolation directives (the resolved
default substrate), compute the confinement label, and **validate** the whole
approach against the two proving packages before anything builds on it.

**Deliverables.**

- [x] **Manifest → directive materialization** (the P0 table), with the package
      payload delivered as the immutable lower layer of a **per-service
      volatile overlay `RootDirectory=`** (D5; no image, no loop device, no
      udev ordering). A host-side preparation unit creates distinct `upper`,
      `work`, and `merged` directories under `/run` before the workload.
      `ProtectSystem=strict` + `MountAPIVFS=` +
      `TemporaryFileSystem=` for scratch; persistent state in `StateDirectory=`.
- [x] **`kernel-modules` as an allowlisted, host-fulfilled permission (D2).**
      `aos-pkg-<name>-modules.service` loads **only** modules in the host
      allowlist (D1(a)); admission fails clearly otherwise; kernel module-signing
      is the backstop. Non-reversibility (modules persist after stop) documented.
- [x] **Computed confinement label (D10).** `sandboxed` / `sandboxed-with-holes
      (<grants>)` / `unconfined`, derived by fixed rules, never authored.
      Root-equivalent grants force `unconfined` (`CAP_SYS_ADMIN`,
      `privileged-users`, rw `host-paths` into system locations). Surface in
      `apm info <pkg> --permissions` for registry/install metadata published
      with `apr publish --expose-manifest`, and in `aos describe <pkg>` from
      local expose passthru metadata.
- [x] **★ The Decision 17 validation spike (the gate).** Materialize
      `expose-minimal`'s default manifest (the test-http-server-equivalent
      proving package before the P7 role migration), `expose-smoke`'s
      side-effect manifest, and k3s's manifest as per-unit services and confirm
      all three:
      1. **teardown semantics** behave (start / inspect / stop) under the per-unit
         substrate;
      2. **the generated k3s unit matches today's working unit** — `KillMode=process`
         preserved, host network/cgroups intact (this absorbs D1(b), the k3s
         permission-set validation; desk-check the strawman against kind/k3d/Incus
         requirement sets — likely add `/lib/modules` (ro) and `/dev/fuse`);
      3. **the one flagged plumbing cost:** `network = "private"` *with outbound*
         needs a gated `aos-pkg-<n>-netns.service` oneshot (named netns + veth,
         `NetworkNamespacePath=`) — validate it works (D3).
- [x] **Per-unit lifecycle VM test (D4).** `RootDirectory=` + `PrivateUsers=` +
      `PrivateNetwork=` inside the VM harness; introspection via `systemctl` /
      `systemd-run` / `nsenter`, **not** `machinectl` (machined stays disabled,
      D7). The lifecycle check exercises those paths directly.

**Closes.** D17, D10, D2, D4; D1(b). **Unblocks Phases 4–7.**

**EXIT CRITERIA.** The spike passes its three confirmations; the confinement
label is correct for the proving packages (`sandboxed` for the default
`expose-minimal` package, `sandboxed` for `expose-smoke`'s host-fulfilled module
load, and `unconfined` for k3s); the per-unit lifecycle VM test is green.
Recorded in [`container-model.md`](container-model.md) §"Substrate decision".

---

## Phase 4 — Preset enablement

**GOAL.** Deterministic enable/disable that survives AOS's stage-1 machine-id
commit and the tmpfs `/etc` upper. ([`boot-activation.md`](boot-activation.md) §3.2.)

**Deliverables.**

- [x] **Image-baked default-deny.** Ship
      `/usr/lib/systemd/system-preset/99-aos-default.preset` containing `disable *`.
- [x] **Ignition per-host preset.** Write `/etc/systemd/system-preset/20-aos-host.preset`
      (one `enable aos-pkg-<name>.target` line per desired package) via plain
      `storage.files` (`20-` beats `99-` first-match-wins).
- [x] **Every-boot `aos-preset.service`.** `ExecStart=systemctl preset-all
      --preset-mode=enable-only` (enable-only is **mandatory** — full mode would
      whiteout EROFS-baked `.wants` of base services), `Before=multi-user.target`,
      then `systemctl start --no-block` for newly-enabled targets (the boot
      transaction is computed before the symlinks exist, so an explicit start is
      required).
- [x] **Runtime install enable.** `systemctl preset aos-pkg-<name>.target` +
      record the enable line in `/var/etc/systemd/system-preset/30-aos-apm.preset`.

**Phase 4 implementation scope.** The image now stages the default-deny preset,
the VM harness verifies an Ignition-written host preset, and the every-boot
`aos-preset.service` applies enable-only policy and starts enabled package
targets. Runtime `apm` records enablement durably in `/var/etc` and mirrors it
into live `/etc` for immediate preset evaluation; it applies `systemctl preset`
only once the target unit is visible to systemd. The Phase 5 attach phase remains
responsible for materializing runtime-installed unit files and starting the
target after install.

**Closes.** D8 (the enable half). Verified facts that force this shape (do not
re-derive): systemd's native first-boot preset pass can never fire (machine-id
committed in stage-1 by `aos-machine-id.service`); the `/etc` upper is tmpfs so
enablement must be recomputed each boot from preset *files*, not symlinks.

**EXIT CRITERIA.** VM: an enabled package's target is reached at boot; a disabled
package's units exist but nothing is active; enablement survives a reboot via the
preset files (not runtime symlinks).

---

## Phase 5 — apm install + install-at-boot + upgrade/rollback

**GOAL.** Install a package on a booted host with no evaluator; bridge Ignition →
apm at first boot; define upgrade/rollback.

**Deliverables.**

- [x] **`apm install` expose phase.** Read `expose` + the `[permissions]`
      manifest; verify `request ∩ host policy` (refuse if the manifest exceeds
      policy); materialize the per-unit + gated units; run the preset; start the
      target. In `crates/aos-package/src/install.rs` (reuse the existing async
      zbus client `crates/aos-systemd` for start/stop/reload).
- [x] **Attach dir (D16).** Materialize runtime-installed units as **gc-rooted
      store-path symlinks** under `/var/etc/systemd/system.attached/` (apm-owned,
      portablectl-attach shape) + the enable line in `30-aos-apm.preset`. Both
      surface through the overlay each boot. Verified by the
      `package-expose-lifecycle` VM check, including `system.attached` lookup
      with portabled disabled.
- [x] **Install-at-boot oneshot.** `aos-install-packages.service`:
      `After=nix-overlay-setup.service aos-seed-profiles.service ignition-files.service`,
      `Before=aos-preset.service multi-user.target`,
      `ConditionPathExists=/etc/aos/packages.d/desired.toml`. The service does
      not `Require=` the early-boot overlay producers in the stage-2 graph, and
      registry refresh is best-effort so cached metadata can keep air-gapped
      boots from hard-failing.
- [x] **Ignition writes** `/etc/aos/packages.d/desired.toml` (desired packages)
      plus registry config/trust anchors under `/etc/apm/registries.d` and
      sibling trust directories via `storage.files`. Implemented as the reusable
      `aos.apm.installAtBoot.ignitionConfig` fragment, verified by
      `checks.vm.apm-install-at-boot`.
- [x] **Declarative reconciliation (D24).** The install-at-boot step converges to
      the desired set: install additions **and uninstall packages removed from
      `desired.toml`** (disable target, remove attach units + preset lines, gc the
      generation). Replaces additive-only — the Nix/Talos/K8s declarative idiom.
- [x] **Layered config (D9, signed off).** Structured/env apm config artifacts
      are declared in signed `expose.config` metadata, validated against the
      manifest-declared required/optional field set, materialized under
      `/var/etc` + `/etc`, and bound into sandboxed units before start for
      desired-file installs. Desired-file credential entries now validate
      against signed `expose.config.credentials`, provision `/etc` and `/run`
      credstore source paths, and encrypt encrypted credentials with
      `systemd-creds encrypt --with-key=tpm2 --tpm2-public-key-pcrs=11` using
      the measured-boot PCR public key. Package-time `encryptedFile`
      declarations now vendor already encrypted
      `credstore.encrypted/aos/<package>/<name>` expose-artifact blobs, keep
      build-only inputs out of `manifest.json`, and project those blobs under
      `/run/credstore.encrypted/aos/...` before package targets start. Inline
      encrypted payload production is owned by `apm credential encrypt`, which
      emits either the inline ciphertext or a Nix metadata snippet. External
      system-credential ingress now works through desired values of
      `{ system-credential = "<name>" }`, read from
      `/run/credentials/@system/<name>` ([`config.md`](config.md)).
- [x] **Hot-reload plumbing (D25).** The manifest declares whether the service
      supports reload; a config change runs `systemctl reload-or-restart`
      (`Type=notify-reload`/`RELOADING=1` where supported, restart otherwise).
- [x] **Typed capability routing (D18).** `requires` resolves typed capabilities a
      provider's `expose` declares. Directory and namespace routes now emit
      runtime drop-ins (`BindReadOnlyPaths=` / `JoinsNamespaceOf=`), while
      socket routes emit named-fd activation drop-ins and consumer-target edges,
      with same-generation validation.
- [x] **Upgrade / rollback (D11).** Upgrade = generation switch + `daemon-reload`
      + restart with the unit's own semantics (k3s keeps `KillMode=process`, no pod
      kill). Rollback = switch back (both store paths gc-rooted) → rewrite the
      attach symlinks + preset lines → `daemon-reload` + restart.

**Phase 5 implementation scope.** This increment implements the runtime attach
path, first-boot desired-set reconciliation, package-profile install/prune,
generation upgrade/rollback mechanics, signed structured/env config artifact
metadata + desired materialization, config-triggered reload/restart, and
directory/namespace/socket capability-route drop-ins. Signed credential metadata
now renders `LoadCredentialEncrypted=` / `LoadCredential=` into the consuming
service units; when a credential declares a credstore `source`, the renderer
emits `name:/path` plus `ConditionPathExists=` so missing credential blobs fail
closed. Inline encrypted payload metadata renders `SetCredentialEncrypted=`.
Bare-name imports remain an explicit appetite/import declaration. Desired files
can now provision signed package-declared `/etc` and `/run` credstore sources;
encrypted desired credentials are sealed with signed-PCR-11 policy, and measured
boot publishes the PCR public key at `/etc/aos/pcr-sign.pem` for that path.
Offline/package-time vendor blobs now build through `encryptedFile` metadata
for already sealed ciphertext and are projected by `apm` under the AOS-owned
runtime credstore namespace at `/run/credstore.encrypted/aos/...`. Inline
ciphertext production is handled by `apm credential encrypt`, so the P5
implementation surface is complete. Desired reconciliation defers intermediate
install/remove exposed-unit reconciliation until after package-scoped config and
credentials are materialized, so an add+prune converge cannot start a newly
added config-gated package before its desired artifacts exist.

**Closes.** D8 (install half), D9, D11, D16, D18, D24, D25.

**EXIT CRITERIA.** End-to-end on a booted host: a package's manifest is verified
against policy, units land under `/var/etc`, the preset is applied, the target
starts — all with **no Nix evaluator present**; a generation rollback restores
the prior generation's units.

---

## Phase 6 — Container roots & networking

**GOAL.** The package root and the three network modes, hermetic and signed.

**Deliverables.**

- [x] **Root = volatile per-service overlay via `RootDirectory=`** (D5/D6): the
      authenticated payload is an ordinary immutable closure member, inheriting
      NAR hashing + the registry tag-signature chain + gc-rooting. A generated
      host-side `aos-pkg-<package>-roots.service` unit mounts that payload as the
      lower layer with `aos-service-root prepare` and creates distinct `upper`,
      `work`, and `merged` directories below
      `/run/aos/service-roots/<package>/<unit>` before each workload. This needs
      no image build, loop device, or udev ordering, and systemd-created mount
      targets never mutate the store. Bake k3s and other infrastructure; fetch
      workloads (the standing default). Install and upgrade root the payload
      and `expose.images`; the lifecycle VM asserts the active payload identity
      and volatile-root ordering.
- [x] **Networking modes (D3).** *inbound-only private* (default): host-owned
      socket units pass **named** fds into the sandboxed `PrivateNetwork=`
      service; the socket unit intentionally stays in the host namespace.
      `PrivateNetwork=` + `JoinsNamespaceOf=` on the socket is only for the
      different shape where the listen socket must bind inside a shared private
      namespace. *private with outbound*: the gated
      `aos-pkg-<n>-netns.service` from P3 (named netns + veth, host side
      systemd-networkd) + `NetworkNamespacePath=`, **plus Landlock TCP
      bind/connect rules on the allowed ports** ([`enforcement.md`](enforcement.md)).
      *host*: k3s and peers. Partial coverage exists: the runtime route
      generator emits named-fd socket drop-ins, the lifecycle VM now exercises
      package-manager reconciliation plus cross-package named-fd inbound
      activation, the route validator rejects socket namespace directives that
      would move routed provider sockets out of the host namespace, the
      attached-unit writer drops stale provider-socket drop-ins before writing
      AOS route drop-ins, and the VM performs a real private-outbound netns HTTP
      request. The default socket namespace shape is now verified and covered;
      the renderer now signs explicit `tcp-bind` / `tcp-connect` grants and
      emits `network-policy.json` for Landlock/eBPF consumers. TCP Landlock
      enforcement for those grants is applied by generated `aos-landlock`
      prefixes on package-authored service exec directives and revalidated by
      `apm` against the Nix-built trusted helper path before unit attach. The
      generated cgroup eBPF policy service now attaches before package
      workloads and enforces the same TCP bind/connect grants against the
      package slice cgroup.
- [x] **Per-package network policy via eBPF** for static TCP bind/connect grants,
      not only host-global nftables base-set mutation.
      The signed `network-policy.json` contract is loaded by the Nix-built
      `aos-ebpf-net-policy` helper, validated by APM against the trusted helper
      and BPF object paths, attached to the package slice cgroup with
      `socket_bind` / `socket_connect` programs, and covered by renderer,
      eval, Rust, kernel-config, and lifecycle checks
      ([`container-model.md`](container-model.md) networking). UDP and fuller
      L3 policy remain outside this P6 slice.
- [x] **Naming without `nss-mymachines`** (not shipped): default NSS host
      lookup uses explicit `/etc/hosts`, `nss-myhostname`, systemd-resolved, and
      DNS only; fleet metadata already writes `/etc/hosts` entries for host
      reachability.

> The verity-signed `RootImage=` package root is **no longer deferred** — it is
> built in **Phase 9** ([`attestation.md`](attestation.md)) under the budget
> mandate. Phase 6 ships the volatile overlay `RootDirectory=` root backed by
> the authenticated payload store path; Phase 9 adds the signed-verity image on
> top of the same closure. `RootImage=` services do not use the overlay path.

**Closes.** D3, D5, D6.

**EXIT CRITERIA.** `test-http-server` is reachable on its network mode; k3s host
networking is intact; the veth/netns outbound path works (carried from the P3
spike).

---

## Phase 7 — Dissolve the module tree into `pkgs/` `expose`

**GOAL.** Remove `modules/roles/`; `modules/` shrinks to ~50 lines of host
policy. (migration.md increments 2–4; D14.)

**Deliverables.**

- [x] **`test-http-server` via `expose` end-to-end** (build → image bake → preset
      enable → VM check) while the role tree still exists.
- [x] **Dissolve `modules/roles/*` one package at a time** into `pkgs/` `expose`
      blocks; `k3s-worker` / `k3s-control-plane` become **meta-packages**
      (`runtimeDeps = [ k3s ]` + `expose`), `_k3s-common.nix` survives as a shared
      let-binding. Delete the `roleType` machinery (~400 lines) **last**.
- [x] **Thin policy modules.** `modules/packages.nix` owns the bake list and
      image preset policy; `modules/security/firewall.nix` remains the base
      nftables table without role drop-in includes; package permission policy is
      enforced by the signed expose/permissions renderer and apm path. The legacy
      role loader is removed from `modules/default.nix`, and role rendering now
      lives in the P1 package expose renderer.
- [x] **Fleet-spec rename.** `lib/testing/fleet-spec.nix` + `fleet.nix`:
      `roles` → `packages`, `availableRoles` → `availablePackages`, and every
      `roles = ["…"]` → `packages = ["…"]` in `tests/fleet/*.nix`. The fleet
      harness now writes a package-profile seed at `/etc/aos/packages.d/fleet-seed`
      instead of merging per-role Ignition fragments from
      `/etc/aos/ignition-roles`.

**Phase 7 implementation scope.** `test-http-server` exists as a `pkgs/`
derivation with an `expose` block, is baked into an image through
`modules/packages.nix`, seeds the system package profile at boot, attaches its
rendered unit artifact, and is enabled through image/APM preset policy in the
`package-test-http-server` VM. The same VM also proves `bundle = true; preset =
false` packages stay baked but inert: they are present in the image without
being seeded into the package profile, attached, or enabled. Fleet tests have a
`packages = [...]` selector that seeds selected bundled package profiles per
machine via `/etc/aos/packages.d/fleet-seed`, rather than by merging per-role
Ignition fragments.

The final dissolve converts `aos-registry-server` into an exposed package with
git-daemon and `aos serve` units, an explicit static `aos-gitd` identity, host
TCP exposure for ports 9418 and 15000, and package-owned state directories. The
expose renderer now supports static non-root service users without falling back
to `DynamicUser=`. `modules/roles/` and the `ignitionRolesBundle` plumbing are
gone from the module loader, initrd builder, stage-2 toplevel, activation script,
fleet spec, and fleet tests. Registry fleet tests use the package target
`aos-pkg-aos-registry-server.target` plus the generated firewall service, and
continue to use `test-static-cache-server` when they need to serve generated
cache files from `/var/lib/sysreg-cache`.

**Closes.** D14; the [`migration.md`](migration.md) increments.

**EXIT CRITERIA.** `modules/roles/` is gone; `checks.eval` +
`systems.server.checks.system-boot` + the package/fleet checks are green; the
k3s fleet test asserts `aos-pkg-k3s-worker.target` /
`aos-pkg-k3s-control-plane.target` are reached.

---

## Phase 8 — Layered enforcement (defense in depth)

**GOAL.** Add the kernel-enforcement layers under the per-unit sandbox so a
breach of any one layer still meets another — all generated from the manifest.
Full spec: [`enforcement.md`](enforcement.md).

**Deliverables.**

- [x] **Landlock layer (D20).** The `expose` renderer emits Landlock policy from
      the manifest. Current coverage: `tcp-bind` /
      `tcp-connect` are rendered into `network-policy.json`, workload
      service exec commands are prefixed with the AOS-built `aos-landlock`
      wrapper, the helper requires ABI 4 and probes
      `LANDLOCK_CREATE_RULESET_VERSION`, and `apm` validates the exact trusted
      wrapper path and arguments before attaching a unit artifact. Current
      coverage records the built kernel's max Landlock ABI in the
      `security-aos-landlock-fs` VM check with `aos-landlock --print-abi` and
      fails closed below ABI 4. `checks.fleet.apm-landlock-argv` verifies that
      generated Landlock/MAC wrapper prefixes preserve package-authored `Exec*`
      argv tokenization. Current coverage also maps declared `host-paths` to
      `LANDLOCK_ACCESS_FS_*` rules for `sandboxed-with-holes` packages and
      applies default filesystem confinement (`/` read-only plus writable
      package temp/state roots) for non-root-equivalent empty manifests. Holds
      even when a namespace is shared — the layer for `sandboxed-with-holes`
      packages. Host-owned TCP socket listeners are validated against the
      socket-capability /
      `tcp-bind` contract before units can be attached.
- [x] **Generated MAC profile (D20).** Render a default-deny per-package
      SELinux profile named from the manifest security label and load it before
      package workload units start. The profile name is part of the measured
      manifest digest (P9). Current coverage renders deterministic
      `mac-profile.json` plus SELinux `.te`, `.mod`, and `.pp` artifacts for
      confined packages with collision-resistant escaped SELinux identifiers;
      records the MAC metadata and generated `aos-pkg-*-mac.service` in
      `manifest.json`; makes APM rebuild and byte-compare compiled policy
      payloads from the validated source, then validate the trusted AOS-built
      `semodule` helper, target membership, workload `After=`/`Requires=`
      ordering, and absence of extra loader exec hooks before attaching units;
      and builds the loader unit under `ConditionSecurity=selinux`. The
      base SELinux policy is now enabled in booted systems:
      `modules/security/selinux.nix` installs the AOS-built refpolicy store,
      seeds the matching `/etc/selinux/refpolicy` contexts and libsemanage
      config, includes the `.pp` HLL loader helper, boots permissive until
      policy load, rebuilds the linked policy if volatile `/etc` policy files
      are missing, and then applies the requested mode. `checks.selinux-base`
      opts out of the generic disabled-SELinux VM seed, boots an enforcing
      SELinux system, verifies the base policy is loaded, reboots through the
      marker/cache path, installs a smoke SELinux module, bakes a generated
      `pkg.expose` package, reconciles the generated target/unit/MAC loader
      path, proves the workload service enters
      `system_u:system_r:aos_x2eselinux_x2dgenerated_t`, and proves the same
      generated domain cannot perform an out-of-policy `/tmp` write. Generated
      MAC workload units temporarily disable `PrivateUsers=` because the current
      base policy denies systemd user-namespace setup before the
      `aos-selinux-run` transition.
- [x] **eBPF-LSM channel (D20).** Kernel config
      (`CONFIG_BPF_LSM`, `bpf` in `lsm=`, BTF) + a signed-policy channel through
      the registry trust chain for fleet-managed dynamic policy (CVE live-patch).
      Current coverage enables `CONFIG_BPF_EVENTS`, `CONFIG_BPF_LSM`,
      `CONFIG_FUNCTION_TRACER`, `CONFIG_DYNAMIC_FTRACE`, `bpf` in `CONFIG_LSM`,
      AOS-built `pahole`/dwarves, and `CONFIG_DEBUG_INFO_BTF` /
      `CONFIG_DEBUG_INFO_BTF_MODULES`; adds the `bpf-lsm-policy-v1` signed
      package metadata gate, registry parser support, and host policy
      `[[ebpf-lsm.policies]]` selector; ships the AOS-built
      `aos-ebpf-lsm-policy` helper and seed BPF-LSM policy package; and loads
      selected installed policy artifacts through
      `apm _load-ebpf-lsm-policies --system`, resolving the JSON policy and
      `.bpf.o` object from installed, signed package metadata rooted in the
      current system package generation before pinning BPF links under
      `/sys/fs/bpf/aos/lsm`. The `aos-ebpf-lsm-policies.service` prepares bpffs
      and runs after package seed and install services, while the helper also
      verifies or mounts bpffs for direct and live-reconcile invocations. Live
      package target reconciliation loads the selected fleet BPF-LSM policies
      before exposing package targets; complete existing pin sets are treated as
      already loaded, and partial pin sets fail closed.
- [x] **Full systemd hardening baseline** on every generated workload service (the
      `systemd-analyze security` consensus set — see [`enforcement.md`](enforcement.md));
      relaxations computed from the manifest, never hand-written. The renderer
      emits the namespace, credential, device, proc, clock, hostname,
      capability, syscall, control-group, realtime, SUID/SGID, personality,
      W^X, and address-family directives, with `PrivateDevices=` relaxed only
      for explicit device grants, `ProtectControlGroups=` relaxed only for
      `cgroup-delegate`, and proc isolation skipped for root-equivalent package
      manifests. Generated host-side side-effect units remain outside the
      workload sandbox and use narrow generated commands for their privileged
      setup/teardown work.
- [x] **Per-package UID identity.** `DynamicUser=yes` + `PrivateUsers=identity`
      default so two sandboxed packages can't touch each other's state via a
      shared host path. Current coverage asserts generated defaults and
      privileged-user relaxation at render time, then proves in the
      package-expose lifecycle VM that two live dynamic-user package units with
      the same writable host-path grant receive distinct UIDs and cannot
      overwrite each other's `0600` file.
- [x] **CI gate.** `checks.eval` runs the AOS-built `systemd-analyze security`
      offline against rendered package workload services with the default
      threshold equivalent to 5.5; a unit worse than the gate fails the build.
      Generated host-side side-effect units stay outside the workload-service
      gate, and `unconfined` packages such as k3s are counted as documented
      skips rather than silent passes.

**Closes.** D20; strengthens D2, D10.

**EXIT CRITERIA.** A default-manifest package's workload service scores within
the default `systemd-analyze` threshold; its Landlock ruleset denies an
out-of-manifest path in a VM test *with a host-path hole present* (proves
namespace-independence); its MAC profile loads and denies a default-denied
operation; a signed fleet BPF-LSM package selected by `/etc/aos/policy.toml` is
rooted in the current package generation, loads in a VM with `bpf` active in
`/sys/kernel/security/lsm`, emits the trusted helper's success record, survives
an idempotent second load, and pins the expected BPF link before package targets
are exposed.

---

## Phase 9 — Runtime integrity & attestation

**GOAL.** Bind each package's content digest **and its signed manifest** into a
hardware-rooted, attestable chain, extending [RFC-0006](../0006-secure-boot/README.md).
Full spec: [`attestation.md`](attestation.md).

**Deliverables.**

- [x] **dm-verity package roots (D21).** Build each exposed package root as its
      own signed ext4 dm-verity image, hermetically (`veritysetup format`, no
      host tools). Consume via
      `RootImage=`+`RootHash=`+`RootVerity=`+`RootHashSignature=`; the PKCS#7
      `.roothash.p7s` is validated by the kernel against the **`.platform`
      keyring** populated from the UEFI db (RFC-0006). Kernel config:
      `CONFIG_DM_VERITY`, `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`,
      `..._PLATFORM_KEYRING` (via `pkgs.linuxWith`). Reconcile the `RootImage=`
      caveats (loop-backed, `After=systemd-udevd.service`, no `PrivateDevices=yes`).
- [x] **Measure into the TPM (D22).** At package-set activation, extend **PCR 15**
      with `H(name ‖ version ‖ root-digest ‖ manifest-digest)` per enabled package
      and record a TCG-compatible event log (`/run/log/aos-packages.cel`). The
      AOS JSONL CEL profile records monotonic sequence numbers, PCR 15, SHA-256
      digests, event sizes, and measured event content, and the verifier accepts
      the same payloads as binary `TCG_PCR_EVENT2` records. The **manifest
      digest is measured** — privilege becomes attested state.
- [x] **Quote + verify (D22).** `aos-attest` unit produces a `TPM2_Quote` over
      {PCR 7,11,12,15} with a verifier nonce, AK←EK. A fleet verifier (Keylime-
      shaped) replays the event log and checks each tuple against the **registry
      golden-measurements catalog**; `apm attest enroll` separates identity-only
      quote pins from enrolled AK/EK trust anchors.
- [x] **Registry golden catalog (D22).** The registry records the expected
      measurement tuple per package/version and serves the `.roothash.p7s` +
      provenance — the catalog/oracle role, **never a runtime signer**
      ([`apm-integration.md`](apm-integration.md), [`attestation.md`](attestation.md)).
      Key custody: registry key ≠ UEFI-db/verity key ≠ TPM AK/EK.

**Implemented so far.** Verity packages use per-package signed ext4 dm-verity
`RootImage=` roots; a consolidated composefs/EROFS digest per package generation
is left as a future size/dedup optimization, not the MVP integrity boundary.
Package activation measures every explicitly exposed package, including
non-verity overlay-backed `RootDirectory=` packages, by using `root_digest` as
the measurement input. The volatile upper/work/merged directories are not a
new package identity. For verity packages `root_digest` equals `root_hash`;
otherwise the registry derives it from the immutable payload NAR hash and
seeded bundled metadata derives a stable package-root digest before writing the
golden catalog. The
package event log is an AOS JSONL CEL profile with monotonic `sequence_number`,
PCR index, SHA-256 digest list, event size, and measured event content; the
verifier rejects malformed sequence numbers while retaining legacy JSONL log
compatibility and accepts a binary `TCG_PCR_EVENT2` projection of the same AOS
event payloads for external CEL/TPM log tooling. Quote verification can also
require an explicit quote-identity pin catalog; without one, quote mode remains
explicitly marked as
self-consistent but untrusted. `apm attest enroll` now records a quote bundle's
AK/EK identity plus the SHA-256 digest of credential-activation, privacy-CA, or
equivalent out-of-band enrollment evidence into that catalog, and quote
verification reports `ak_ek_trusted=true` only for enrolled anchors. The
verifier-hosting decision is implemented as the standalone
`aos.services.attestationVerifier` role, which consumes delivered
quote/event-log/catalog evidence and writes the verifier result without sharing
registry signing custody. P9 is closed by the fleet Secure Boot/root-image
attestation check plus unit coverage for binary CEL decoding and replay.

**Tracks.** D5 (verity variant), D6, D21, D22. The current slice closes the
remaining D22 event-log compatibility gap; the Secure Boot/root-image fleet
test exercises measurement, TPM quote verification, enrolled AK/EK trust, and
standalone verifier hosting.

**EXIT CRITERIA.** A node mounts a tampered package root → kernel refuses
(verity); an untampered node produces a quote a verifier accepts and whose event
log matches the registry catalog; flipping one package's manifest changes the
measured PCR 15 and the quote reflects it.

---

## Phase 10 — Supply-chain provenance & transparency

**GOAL.** Make the publication chain externally auditable and provenance-bound,
beyond the single registry signing key. ([`apm-integration.md`](apm-integration.md) §7.)

**Deliverables.**

- [x] **in-toto/SLSA provenance (D23).** Emit a DSSE-wrapped SLSA v1.2
      provenance attestation per build binding the NAR hash **and the manifest
      hash** to the build inputs (`.drv`/source); serve from the registry
      alongside the narinfo; `apm install` verifies the DSSE signature against
      an active or sequence-valid retired `keys.toml` roster key, checks the
      builder id, and then verifies the SLSA subjects. RFC-0001 expose,
      permission, and BPF-LSM policy packages fail closed when provenance is
      absent.
- [x] **Transparency log (D23).** Append every published binding to the
      in-registry `transparency/package-provenance.jsonl` hash chain. Publish
      and install both verify that the logged statement digest matches the DSSE
      artifact bytes; this gives append-chain consistency for clients following
      the same registry history, while independent witness/Rekor-style
      compromise resistance remains future work.
- [x] **TUF hardening (D23).** Roles + thresholds + timestamping over the catalog
      via committed `tuf/root.json`, `targets.json`, `snapshot.json`, and
      `timestamp.json`; verify expiry, version floors, catalog hashes, and
      key-rotation continuity against freeze / mix-and-match / fast-forward /
      rollback attempts.

**Closes.** D23.

**EXIT CRITERIA.** A package fetched via `apm install` carries a DSSE-verifiable
SLSA provenance binding its NAR + manifest to its build; the publication appears
in the transparency log; a rollback/mix-and-match attempt is refused.

---

## Phase 11 — Out of scope, on merit (not cost)

Under the budget mandate the **only** reason to not build something is that
building it would make the OS *worse*. Everything cost-deferred moved into Phases
8–10; what remains is justified on merit, and the items below are **maintainer
decisions**, not engineering deferrals.

- [x] **nspawn substrate (D17) — *dominated*, skipped.** Lighter than per-unit
      for every package we have, weaker than a microVM tier for untrusted code; a
      second service manager with zero consumer. Not built. The deferred template
      in [`container-model.md`](container-model.md) is the spec *if* a multi-unit-
      init package ever appears.
- [x] **microVM isolation tier (Firecracker/Kata) — *planned future effort*.** The
      genuinely-stronger-than-namespace boundary. **Decided (2026-06): not yet** —
      the current threat model is first-party confinement, for which the per-unit +
      Landlock + MAC + attestation stack is sufficient. Built when untrusted /
      multi-tenant workloads enter scope, from AOS's existing from-source QEMU +
      `lib/testing/firecracker.nix` infra (a manifest-selectable
      `substrate = "microvm"`), **not** nspawn. The substrate gradient (per-unit
      now → microVM later) is the recorded direction; only the timing is deferred,
      on a real future need.
- [x] **machined / portabled / importd stay disabled (D7) — *attack surface*.**
      Enabling unused daemons enlarges the TCB for no capability; introspection via
      `systemctl`.
- [x] **Zone-style multi-container L2 (D3); performance/init measurement (D13) —
      *no consumer / mooted*.** The netns/veth capability exists (P6); a zone is a
      topology to add on a concrete need. Per-unit removes per-package PID-1
      overhead, so there is nothing to measure.

The following moved **out of "deferred" into committed phases** under this pass:

- **Declarative reconciliation / prune-on-removal (D24)** → **Phase 5**: the
  install-at-boot step now converges to the desired set (install additions **and
  uninstall removals**) — the Nix/Talos/K8s declarative idiom; additive-only was
  a wart.
- **Hot-reload plumbing (D25)** → **Phase 5**: the manifest declares reload
  support; a config change runs `systemctl reload-or-restart` (`Type=notify-reload`
  where the service supports it).
- **Typed capability routing (D18)** → **Phases 0 + 5 + 8**: `expose` declares
  **provided capabilities** and `requires` references them by typed name; the
  renderer wires each as a least-privilege fd-pass / `BindReadOnlyPaths=` /
  `JoinsNamespaceOf=` (flat ordering ships first as the subset). See
  [`open-questions.md`](open-questions.md) §18.
- **Config layering (D9, signed off)** → **Phase 5 / [`config.md`](config.md)**:
  secrets via TPM2-sealed systemd-creds, structured config via apm artifact +
  manifest schema, simple via `EnvironmentFile=`.

---

## Decision → phase map

Every tracked decision and where it is discharged. Statuses are from
[`open-questions.md`](open-questions.md).

| Decision | Disposition | Phase |
|---|---|---|
| D1(a) policy enforcement model / file format | RESOLVED (`/etc/aos/policy.toml`) | P0 |
| D1(b) validated k3s permission set | RESOLVED | P3 (in the spike) |
| D2 kernel-modules as allowlisted permission | RESOLVED | P0 (schema) + P3 (load) |
| D3 networking modes | RESOLVED | P0 (schema) + P3 (validate) + P6 (build) |
| D4 nspawn-in-VM / lifecycle test | RESOLVED (mooted; per-unit test remains) | P3 |
| D5 package roots / volatile overlay `RootDirectory=` default / signed `RootImage=` path | RESOLVED | P6 |
| D6 bake vs fetch | RESOLVED by D5 | P6 |
| D7 machined/portabled/importd disabled | RESOLVED (stay) | P11 |
| D8 install-at-boot + enable | RESOLVED (presets + install/reconcile) | P4 (enable) + P5 (install) |
| D9 config & credential delivery | RESOLVED (direction): layered — TPM2 creds (sign-off) / schema'd artifact / EnvironmentFile | P5 |
| D10 boundary labeling | RESOLVED (computed label); now also attestable | P3 + P8 + P9 |
| D11 upgrade/rollback | RESOLVED (direction) | P5 |
| D12 package metadata (hybrid) | RESOLVED | P0 |
| D13 performance / init strategy | RESOLVED (mooted by per-unit substrate) | P11 |
| D14 module-tree dissolve | RESOLVED | P7 |
| D15 unit naming `aos-pkg-<name>` | RESOLVED | P2 |
| D16 runtime unit placement (`/var/etc` attach) | RESOLVED | P5 |
| D17 execution substrate (per-unit default); nspawn skipped (dominated); microVM tier threat-model-gated | RESOLVED; spike = validation | P3 (gate); P11 (microVM/nspawn) |
| D18 cross-package deps | RESOLVED (direction): flat ordering → typed capability routing | P0 + P5 + P8 |
| D19 registry capability gate (fail-closed) | RESOLVED | P0 (first) |
| D20 layered enforcement (Landlock + MAC + eBPF-LSM) | committed (budget mandate) | P8 |
| D21 dm-verity package roots | committed (budget mandate; un-deferred) | P9 |
| D22 runtime attestation (PCR measure + quote + registry golden catalog) | committed (budget mandate); extends RFC-0006 | P9 |
| D23 supply-chain provenance + transparency (in-toto/SLSA, TUF) | committed (budget mandate) | P10 |
| D24 declarative reconciliation (install + prune) | committed (budget mandate) | P5 |
| D25 hot-reload plumbing | committed (budget mandate) | P5 |
| — microVM isolation tier (stronger-than-namespace) | RESOLVED (not yet; threat-model-gated) | P11 |

---

## Needs-verification register

Every small verification gap that was tracked for the set, collected so the
implementer cleared it rather than guessing. Each item below is closed before
the cited phase's exit is ticked.

- [x] **`system.attached` search path (P5).** Whether the AOS systemd build
      includes `/etc/systemd/system.attached/` in the unit search path with
      portabled disabled; if not, use `/var/etc/systemd/system/` directly — same
      mechanism, less tidy. Verified by the `package-expose-lifecycle` VM check.
      ([`apm-integration.md`](apm-integration.md) §4.1, D16.)
- [x] **systemd credential substrate (P5).** Whether the AOS systemd build
      exposes `systemd-creds`, signed-PCR TPM2 encryption flags, credstore
      tmpfiles entries, `systemd-measure`, TPM2 setup units and generator, and the
      cryptsetup TPM2 token plugin. Verified by `checks.systemd-credentials`.
- [x] **Exact `expose` schema (P0/P1).** Verified in
      `crates/aos-package/src/types.rs`: `PackageMeta` carries
      `min-format`, `requires-features`, `expose: Option<ExposeMeta>`,
      `expose_artifact: Option<ExposeArtifactMeta>`, and the signed
      `PermissionsMeta`; `ExposeMeta` covers target, units, images, package
      `requires`, config artifacts/credentials, and typed capability
      `provides`/`uses`. The registry writer emits the matching TOML and
      required feature gates from the rendered manifest, so the P0 schema and
      P1 renderer/publish artifact are one contract.
- [x] **`expose.permissions` validation point (P1).** Verified as both:
      `pkgs/build-support/_expose-renderer.nix` validates
      `expose.permissions` while rendering package-authored `expose` metadata,
      and `apr publish --expose-manifest` parses the renderer manifest through
      `read_publish_expose_manifest()`, revalidates `expose` and
      `permissions`, computes confinement when absent, and rejects malformed
      MAC/profile artifacts before writing registry TOML.
- [x] **Runtime package scope (P5).** Whether runtime apm-installed packages share
      the `system` scope or get their own (`crates/aos-package/src/profile/mod.rs`);
      the apm package generation must stay independent of the toplevel generation.
- [x] **Desired-packages file layout (P5).** Reuse `registries.d/` + a separate
      `packages.d/desired.toml`, or fold both into one document.
- [x] **Expose-artifact carry-across-generations (P5).** Whether expose-phase
      units are carried by `copy_roots` or regenerated each generation
      (`install.rs`); whether a *package*-profile generation swap re-materializes
      them.
- [x] **`expose.images` resolution (P6).** Install and upgrade now explicitly
      download and generation-root `expose.images[].store_path` on ordinary
      packages, verify the image NAR against signed registry metadata, and
      reject image NARs that declare unsigned runtime references
      (`crates/aos-package/src/install.rs`, `upgrade.rs`).
- [x] **nspawn feature checks (P8, only if nspawn lands).** Not applicable to
      the MVP because the nspawn substrate did not land (D17/P11). If a future
      multi-unit-init package reopens nspawn, that implementation must check
      cgroup-v2 delegation depth, `--private-users` mapping, and custom seccomp
      support on the built `systemd-nspawn`.
- [x] **`CAP_SYS_MODULE` policy (P0/P3).** Confirm module loading is *always*
      host-side via `kernel-modules` and `CAP_SYS_MODULE` is never granted into a
      container (lean: always host-side).
- [x] **k3s strawman completeness (P3).** Desk-check against kind / k3d / Incus
      requirement sets; the package spike includes `/lib/modules` (ro),
      `/dev/fuse`, `/dev/kmsg`, host networking, cgroup delegation, and the
      host-fulfilled `br_netfilter` / `vxlan` / `ip_set` module loads.
- [x] **Re-confirm investigation-reported facts (all phases).** Re-confirmed
      against the current tree: `pkgs/system/systemd.nix` still sets
      `-Dmachined=false`, `-Dportabled=false`, and `-Dimportd=disabled`;
      `pkgs/kernel/config/base.config` enables `CONFIG_NAMESPACES`,
      `CONFIG_UTS_NS`, `CONFIG_IPC_NS`, `CONFIG_USER_NS`, `CONFIG_PID_NS`,
      and `CONFIG_NET_NS`, now asserted by `tests/build/kernel-config.nix`;
      and `aos-seed-profiles.service` still runs in initrd after
      `nix-overlay-setup.service`, before
      `ignition-files.service`, with baked package seeding and desired-package
      install ordered after it.
- [x] **Landlock apply mechanism (P8).** The TCP policy apply point uses the
      AOS-built `aos-landlock` service exec wrapper rather than waiting for an
      upstream systemd directive. The wrapper now exposes `--print-abi`; the
      `security-aos-landlock-fs` VM check records the built kernel's max
      Landlock ABI, asserts it is at least ABI 4, and proves filesystem rules
      deny writes outside the declared `--fs-rw` path. The renderer and APM
      validation derive matching wrapper `--fs-ro` / `--fs-rw` arguments from
      signed `host-paths`, package temp, and state-directory policy.
      ([`enforcement.md`](enforcement.md))
- [x] **MAC backend choice (P8).** The generated per-package profile uses
      SELinux because the AOS kernel, systemd, dbus, and SELinux policy tools are
      already built for that backend; base-policy enablement and enforcing VM
      denial coverage remain under the generated MAC deliverable.
      ([`enforcement.md`](enforcement.md))
- [x] **PCR index / event-log convention for the package set (P9).** The
      implementation extends PCR 15 during package activation; RFC-0006 uses
      PCR 11/12 for measured boot, leaving PCR 15 for AOS package-set
      measurement. The AOS JSONL CEL profile records monotonic
      `sequence_number`, PCR index, SHA-256 digest list, event size, and
      measured event content; the verifier also accepts the same AOS payloads
      wrapped as binary `TCG_PCR_EVENT2` records for external CEL/TPM log
      tooling compatibility.
      ([`attestation.md`](attestation.md))
- [x] **Consolidated vs per-package verity root (P9).** AOS uses per-package
      signed ext4 dm-verity `RootImage=` images for the MVP; each exposed image
      is downloaded, gc-rooted, rolled back, revoked, measured, and verified by
      the kernel with the package that references it. A consolidated
      composefs/EROFS digest per package generation remains a future size/dedup
      optimization rather than the MVP integrity boundary.
      ([`attestation.md`](attestation.md))
- [x] **Quote identity pinning (P9).** Quote verification can require an
      explicit catalog of quote-bundle identity fingerprints; matching quotes
      report `quote_identity_pinned=true`, with `ak_ek_trusted=false` for
      legacy identity-only pins that lack enrollment evidence.
- [x] **TPM AK/EK enrollment workflow (P9).** `apm attest enroll` populates the
      quote identity catalog from a quote bundle after credential activation, a
      privacy-CA certificate, or equivalent out-of-band TPM enrollment proof has
      been completed. The catalog records the AK/EK identity fingerprints plus
      the SHA-256 digest of the enrollment evidence; `attest verify` reports
      `ak_ek_trusted=true` only for matching enrolled anchors.
- [x] **Verifier hosting (P9).** The fleet attestation verifier is a standalone
      AOS service role (`aos.services.attestationVerifier`) that runs
      `apm attest verify` over delivered evidence. It is separate from the
      registry catalog/provenance plane and does not hold the registry signing
      key.
- [x] **Transparency-log substrate (P10).** Build the first substrate in-registry as
      `transparency/package-provenance.jsonl`: an append-only JSONL hash chain
      committed alongside package provenance, with staged validation rejecting
      rewrites or unlogged provenance-bearing packages. ([`apm-integration.md`](apm-integration.md))
