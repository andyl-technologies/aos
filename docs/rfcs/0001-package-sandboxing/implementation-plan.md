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
  (Decisions 1–19, each with disposition and owner). Every box below cites the
  decisions it closes by number (`D1`–`D19`).
- [`migration.md`](migration.md) — the cutover plan (the module tree is
  dissolved into `pkgs/` `expose` blocks).

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
  spike (materialize `test-http-server` and `k3s` as per-unit sandboxed
  services) must pass before Phases 4–7 build on the per-unit substrate. It is
  *validation* of a resolved direction, not an open decision.
- **Every "needs verification" item in the set is collected in the
  [Needs-verification register](#needs-verification-register) below** and tagged
  to the phase that must resolve it. The implementer should clear each one
  rather than guessing.

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
- **Default Off / additive.** Image ships `disable *`; install-at-boot is
  additive-only; removal is an explicit operation.
- **Fail closed.** Old clients refuse permission-bearing packages they cannot
  fully parse (D19), before any such package is published.

---

## Master progress table

| Phase | Goal | Gate (begins when) | Closes | Status |
|-------|------|--------------------|--------|--------|
| **P0** | Schema & policy foundation: registry metadata, policy file, `requires`, the fail-closed capability gate, the permission surface | — (do first) | D2, D12, D18, D19; D1(a) | ☐ |
| **P1** | `expose` authoring + build-time renderer (eval-free artifacts via `passthru`) | P0 schema pinned | authoring.md mechanics | ☐ |
| **P2** | Target sandbox + gated side-effect services + nftables reload coherence + eval assertion | P1 | D15; activation.md | ☐ |
| **P3** | Per-unit sandboxing materialization + confinement label + **the Decision 17 validation spike** (the gate) | P1, P2 | D2, D4, D10, D17; D1(b) | ☐ |
| **P4** | Preset enablement (image `disable *`; Ignition per-host preset; every-boot `aos-preset.service`) | P2 | D8 (enable half) | ☐ |
| **P5** | `apm install` + install-at-boot + upgrade/rollback (attach dir, idempotency) | P3, P4 | D8 (install half), D11, D16 | ☐ |
| **P6** | Container roots (`RootDirectory=` store path) + the three network modes | P3 | D3, D5, D6 | ☐ |
| **P7** | Dissolve `modules/roles/` into `pkgs/` `expose`; `modules/` shrinks to policy | P1–P6 green per package | D14; migration.md | ☐ |
| **P8** | Deferred / out of scope: config delivery, nspawn substrate, verity `RootImage=`, L2 zones, hot-reload | — (tracked, not built for MVP) | D9 (open), D7 (stays disabled), D13 | ☐ |

Legend: ☐ not started · ◐ in progress · ☑ exit criterion met.

---

## Phase 0 — Schema & policy foundation

**GOAL.** Pin every wire/disk contract before any permission-bearing package
exists, and make old clients fail closed. Nothing downstream should have to
invent a field.

**Deliverables.**

- [ ] **Capability gate (D19) — first.** Add a `min-format` / `requires-features`
      field to `PackageMeta` (`crates/aos-package/src/types.rs`) and the registry
      parser (`crates/aos-package/src/registry/parse.rs`); an apm predating the
      schema **parses and refuses** a package carrying it. Land this *before* any
      `[permissions]`/`expose` package is published. (The parser is serde-tolerant
      today — no `deny_unknown_fields` — so without this, old clients install
      permission-bearing packages with privilege silently dropped.)
- [ ] **Hybrid package metadata (D12).** Add `expose: Option<ExposeMeta>` and the
      signed `permissions` manifest to `PackageMeta`; registry TOML gains
      `[…expose]` + `[…permissions]` sections, all `#[serde(default)]`. Shape:
      `ExposeMeta { target: String, units: Vec<String>, images: Vec<…>, requires: Vec<String> }`.
      The TOML (tag-signed, visible pre-fetch) carries `target`/`requires`/the
      `[permissions]` manifest so `apm info --permissions` and the host policy
      check work **without** fetching the closure; the rendered unit files ride
      the closure as `pkg.expose` (P1).
- [ ] **`requires` field + resolver semantics (D18).** `requires: Vec<String>`
      (package names, not store-path hashes). Semantics: **install-time pull-in**
      (deb-style `Depends:`) materialized atomically in the shared profile
      generation; **no version-constraint solver** (the registry channel model
      already pins versions). Resolve names in `crates/aos-package/src/resolve.rs`
      (today hash-only); emit target ordering edges in the expose phase (P5).
- [ ] **The permission surface (`permissions.md`).** Document the manifest
      fields and their per-unit-directive mapping as the canonical table:
      `capabilities`→`CapabilityBoundingSet=`/`AmbientCapabilities=`,
      `network`→`PrivateNetwork=`, `devices`→`DeviceAllow=`,
      `host-paths`→`BindPaths=`/`BindReadOnlyPaths=`,
      `cgroup-delegate`→`Delegate=`, `privileged-users`→`PrivateUsers=`,
      `kernel-modules`→host-fulfilled service (not a unit directive),
      `syscalls`→`SystemCallFilter=` (named profiles only),
      `security-label`→SELinux/AppArmor context.
- [ ] **Named policy tiers + syscall profiles.** Tiers `restricted` / `baseline`
      / `privileged` (K8s Pod Security Standards lesson); syscall values are
      **named profiles** pinned to systemd syscall groups (`@system-service`,
      `@privileged`), never free-form.
- [ ] **Policy file format (D1(a), D2) — confirm the proposal.** `/etc/aos/policy.toml`:
      a named `tier` + optional per-permission overrides + the `kernel-modules`
      allowlist; image-baked EROFS default, overridable per host by an
      Ignition-written copy in a higher overlay layer (same precedence as
      presets); evaluated by `apm` at install/enable. Nix-evaluated policy is
      rejected (no evaluator at runtime install). Parser in `crates/aos-package/`.

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

- [ ] **Route `expose` through `mkDerivation`.** Add `expose` to the
      `removeAttrs` filter list in `lib/derivations.nix` (~`:478–656`) — unknown
      attrs flow into `builtins.derivation` where a nested attrset fails — and
      hand it to the renderer instead. One filter-list entry, not N top-level args.
- [ ] **Build-time renderer as a cheap sibling derivation.** Render
      `expose.units` to unit text + a manifest copy via a trivial builder
      (`pkgs/build-support/trivial-builders.nix`), surfaced as `pkg.expose` via
      `passthru`. Editing a unit re-renders text and never rebuilds the payload;
      the payload closure never references its own integration.
- [ ] **Reuse the pure renderers.** Call `serviceToUnit`/`targetToUnit`/… from
      `lib/modules/systemd/lib.nix` + `render-role.nix` (verified pure, callable
      outside `evalModules`); typed validation by evaluating `unit-options.nix`
      types over the attrset at render time.
- [ ] **Enumeration helpers.** `lib.filterAttrs (_: p: p ? expose) pkgs` for
      fleet-spec and eval checks — the second instance of the existing optional-
      attr pattern (`checks`, `default.nix:137–151`).
- [ ] **Validation placement.** Validate `expose.permissions` at **package build**
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

- [ ] **Synthesize `aos-pkg-<name>.target`** (D15 naming, resolved). Members are
      `PartOf=` + `WantedBy=` the target; no member is `WantedBy=` a system target
      directly. Template stays `aos-package@.service` with `PartOf=aos-pkg-%i.target`.
- [ ] **Gated side-effect oneshots** replacing the three global scan-dir drop-ins:
      `aos-pkg-<name>-modules.service` (`modprobe -a`),
      `aos-pkg-<name>-sysctl.service` (`sysctl -w`),
      `aos-pkg-<name>-firewall.service` (`nft add/delete element` against the base
      `allowed_tcp`/`allowed_udp` sets) — each `WantedBy`/`PartOf` the target.
- [ ] **nftables reload coherence.** Each firewall service declares
      `ReloadPropagatedFrom=nftables.service` and an `ExecReload=` identical to
      its `ExecStart` (re-adding an element is idempotent), so a base-ruleset
      reload (`nft -f` begins with `flush ruleset`) re-applies every *active*
      package's ports. Drop the `include "/etc/nftables.d/*.nft"` line from
      `modules/security/firewall.nix`.
- [ ] **Eval-time sandbox assertion.** Single activation root + **zero** storage
      entries under `/etc/modules-load.d`, `/etc/sysctl.d`, `/etc/nftables.d`.
- [ ] **Teardown semantics.** Disabled = strict (nothing applied); stopped =
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

- [ ] **Manifest → directive materialization** (the P0 table), with the package
      root delivered as a **store path via `RootDirectory=`** (D5; no image, no
      loop device, no udev ordering). `ProtectSystem=strict` + `MountAPIVFS=` +
      `TemporaryFileSystem=` for scratch; persistent state in `StateDirectory=`.
- [ ] **`kernel-modules` as an allowlisted, host-fulfilled permission (D2).**
      `aos-pkg-<name>-modules.service` loads **only** modules in the host
      allowlist (D1(a)); admission fails clearly otherwise; kernel module-signing
      is the backstop. Non-reversibility (modules persist after stop) documented.
- [ ] **Computed confinement label (D10).** `sandboxed` / `sandboxed-with-holes
      (<grants>)` / `unconfined`, derived by fixed rules, never authored.
      Root-equivalent grants force `unconfined` (`CAP_SYS_ADMIN`,
      `privileged-users`, rw `host-paths` into system locations). Surface in
      `apm info <pkg> --permissions` and `aos describe <pkg>`.
- [ ] **★ The Decision 17 validation spike (the gate).** Materialize
      `test-http-server`'s empty manifest and k3s's manifest as per-unit services
      and confirm all three:
      1. **teardown semantics** behave (start / inspect / stop) under the per-unit
         substrate;
      2. **the generated k3s unit matches today's working unit** — `KillMode=process`
         preserved, host network/cgroups intact (this absorbs D1(b), the k3s
         permission-set validation; desk-check the strawman against kind/k3d/Incus
         requirement sets — likely add `/lib/modules` (ro) and `/dev/fuse`);
      3. **the one flagged plumbing cost:** `network = "private"` *with outbound*
         needs a gated `aos-pkg-<n>-netns.service` oneshot (named netns + veth,
         `NetworkNamespacePath=`) — validate it works (D3).
- [ ] **Per-unit lifecycle VM test (D4).** `RootDirectory=` + `PrivateUsers=` +
      `PrivateNetwork=` inside the VM harness; introspection via `systemctl` /
      `systemd-run` / `nsenter`, **not** `machinectl` (machined stays disabled,
      D7). Helpers `vm.exec_in_container` / `vm.container_status` built on those.

**Closes.** D17, D10, D2, D4; D1(b). **Unblocks Phases 4–7.**

**EXIT CRITERIA.** The spike passes its three confirmations; the confinement
label is correct for both packages (`sandboxed` for test-http-server,
`unconfined` for k3s); the per-unit lifecycle VM test is green. Recorded in
[`container-model.md`](container-model.md) §"Substrate decision".

---

## Phase 4 — Preset enablement

**GOAL.** Deterministic enable/disable that survives AOS's stage-1 machine-id
commit and the tmpfs `/etc` upper. ([`boot-activation.md`](boot-activation.md) §3.2.)

**Deliverables.**

- [ ] **Image-baked default-deny.** Ship
      `/usr/lib/systemd/system-preset/99-aos-default.preset` containing `disable *`.
- [ ] **Ignition per-host preset.** Write `/etc/systemd/system-preset/20-aos-host.preset`
      (one `enable aos-pkg-<name>.target` line per desired package) via plain
      `storage.files` (`20-` beats `99-` first-match-wins).
- [ ] **Every-boot `aos-preset.service`.** `ExecStart=systemctl preset-all
      --preset-mode=enable-only` (enable-only is **mandatory** — full mode would
      whiteout EROFS-baked `.wants` of base services), `Before=multi-user.target`,
      then `systemctl start --no-block` for newly-enabled targets (the boot
      transaction is computed before the symlinks exist, so an explicit start is
      required).
- [ ] **Runtime install enable.** `systemctl preset aos-pkg-<name>.target` +
      record the enable line in `/var/etc/systemd/system-preset/30-aos-apm.preset`.

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

- [ ] **`apm install` expose phase.** Read `expose` + the `[permissions]`
      manifest; verify `request ∩ host policy` (refuse if the manifest exceeds
      policy); materialize the per-unit + gated units; run the preset; start the
      target. In `crates/aos-package/src/install.rs` (reuse the existing async
      zbus client `crates/aos-systemd` for start/stop/reload).
- [ ] **Attach dir (D16).** Materialize runtime-installed units as **gc-rooted
      store-path symlinks** under `/var/etc/systemd/system.attached/` (apm-owned,
      portablectl-attach shape) + the enable line in `30-aos-apm.preset`. Both
      surface through the overlay each boot. (Verify `system.attached` is in the
      unit search path with portabled disabled; else use
      `/var/etc/systemd/system/` — same mechanism. See register.)
- [ ] **Install-at-boot oneshot.** `aos-install-packages.service`:
      `After=nix-overlay-setup.service aos-seed-profiles.service ignition-files.service`,
      `Requires=nix-overlay-setup.service`, `Before=multi-user.target`,
      `ConditionPathExists=/etc/aos/packages.d/desired.toml`. Idempotent via the
      existing early-exit (`install.rs:67–73` mints no generation when nothing
      changed); **additive-only** (removal is explicit); registry-unreachable must
      **not** hard-fail boot (air-gapped); pull `network-online.target` on demand.
- [ ] **Ignition writes** `/etc/aos/packages.d/desired.toml` (registries +
      desired packages) + registry config under `registries.d/` via `storage.files`.
- [ ] **Upgrade / rollback (D11).** Upgrade = generation switch + `daemon-reload`
      + restart with the unit's own semantics (k3s keeps `KillMode=process`, no pod
      kill). Rollback = switch back (both store paths gc-rooted) → rewrite the
      attach symlinks + preset lines → `daemon-reload` + restart.

**Closes.** D8 (install half), D16, D11.

**EXIT CRITERIA.** End-to-end on a booted host: a package's manifest is verified
against policy, units land under `/var/etc`, the preset is applied, the target
starts — all with **no Nix evaluator present**; a generation rollback restores
the prior generation's units.

---

## Phase 6 — Container roots & networking

**GOAL.** The package root and the three network modes, hermetic and signed.

**Deliverables.**

- [ ] **Root = store path via `RootDirectory=`** (D5/D6): an ordinary closure
      member, inheriting NAR hashing + the registry tag-signature chain +
      gc-rooting; no image build, no loop device, no udev ordering. Bake k3s and
      other infrastructure; fetch workloads (the standing default).
- [ ] **Networking modes (D3).** *inbound-only private* (default): host-owned
      socket units pass **named** fds into the sandboxed unit (`PrivateNetwork=`
      on both + socket `JoinsNamespaceOf=`). *private with outbound*: the gated
      `aos-pkg-<n>-netns.service` from P3 (named netns + veth, host side
      systemd-networkd) + `NetworkNamespacePath=`. *host*: k3s and peers.
- [ ] **Naming without `nss-mymachines`** (not shipped): explicit `/etc/hosts`
      or DNS for container reachability.
- [ ] **Future (behind a kernel-config change, not MVP):** add `CONFIG_DM_VERITY`
      (absent today) and offer a verity-signed `RootImage=` variant
      (`RootHash=`/`RootVerity=`/`RootHashSignature=`).

**Closes.** D3, D5, D6.

**EXIT CRITERIA.** `test-http-server` is reachable on its network mode; k3s host
networking is intact; the veth/netns outbound path works (carried from the P3
spike).

---

## Phase 7 — Dissolve the module tree into `pkgs/` `expose`

**GOAL.** Remove `modules/roles/`; `modules/` shrinks to ~50 lines of host
policy. (migration.md increments 2–4; D14.)

**Deliverables.**

- [ ] **`test-http-server` via `expose` end-to-end** (build → image bake → preset
      enable → VM check) while the role tree still exists.
- [ ] **Dissolve `modules/roles/*` one package at a time** into `pkgs/` `expose`
      blocks; `k3s-worker` / `k3s-control-plane` become **meta-packages**
      (`runtimeDeps = [ k3s ]` + `expose`), `_k3s-common.nix` survives as a shared
      let-binding. Delete the `roleType` machinery (~400 lines) **last**.
- [ ] **Thin policy modules.** `modules/packages.nix` (bake list + image preset
      policy), `modules/security/policy.nix` (tiers + kernel-module allowlist),
      `modules/security/firewall.nix` (base table, unchanged minus the dropped
      include). `render-role.nix` logic relocates into the P1 renderer.
- [ ] **Fleet-spec rename.** `lib/testing/fleet-spec.nix` + `fleet.nix`:
      `roles` → `packages`, `availableRoles` → `availablePackages`,
      `file:///etc/aos/ignition-roles/<n>` → `/etc/aos/packages/<n>`; every
      `roles = ["…"]` → `packages = ["…"]` in `tests/fleet/*.nix`.

**Closes.** D14; the [`migration.md`](migration.md) increments.

**EXIT CRITERIA.** `modules/roles/` is gone; `checks.eval` + `checks.vm.boot` +
the fleet suite are green; the k3s fleet test asserts `aos-pkg-k3s-worker.target`
/ `aos-pkg-k3s-control-plane.target` are reached.

---

## Phase 8 — Deferred / out of scope (tracked, not built for MVP)

These are **explicitly not built for the MVP** but are tracked so they are not
silently dropped.

- [ ] **Config & secret delivery (D9) — OPEN, deliberately.** Do **not** settle
      on credstore. The 7-option matrix + decision criteria are ready in
      [`config.md`](config.md); the MVP placeholder is the per-package
      `/etc/aos/<pkg>/` overlay extending today's k3s `EnvironmentFile=` pattern.
      Resolve the three independent sub-questions first (hot-reload in v1?;
      secrets-at-rest layer?; boundary-crossing mechanism?) then choose.
- [ ] **nspawn substrate (D17 deferral).** Built only if a package genuinely
      needs its own multi-unit init tree (currently none). The deferred template
      in [`container-model.md`](container-model.md) (`--keep-unit --register=no`,
      `Slice=aos-pkg-%i.slice`, the DevicePolicy block) is the spec if it lands.
- [ ] **Verity-signed `RootImage=`** — behind the `CONFIG_DM_VERITY` kernel
      change (P6).
- [ ] **machined / portabled / importd stay disabled (D7).** No `machinectl`,
      no `nss-mymachines`; all introspection via `systemctl`.
- [ ] **Zone-style multi-container L2 (D3 defer); hot config reload; secrets-at-
      rest encryption; prune-on-removal reconciliation** (install-at-boot is
      additive-only today). Performance/init-strategy measurement (D13) only if
      the nspawn path materializes.

---

## Decision → phase map

Every tracked decision and where it is discharged. Statuses are from
[`open-questions.md`](open-questions.md).

| Decision | Disposition | Phase |
|---|---|---|
| D1(a) policy enforcement model / file format | answered; format proposed | P0 (confirm) |
| D1(b) validated k3s permission set | BEFORE-MVP | P3 (in the spike) |
| D2 kernel-modules as allowlisted permission | DECIDE-EARLY | P0 (schema) + P3 (load) |
| D3 networking modes | resolved (direction) | P0 (schema) + P3 (validate) + P6 (build) |
| D4 nspawn-in-VM / lifecycle test | mooted; per-unit test remains | P3 |
| D5 container roots = `RootDirectory=` store path | RESOLVED | P6 |
| D6 bake vs fetch | RESOLVED by D5 | P6 |
| D7 machined/portabled/importd disabled | RESOLVED (stay) | P8 |
| D8 install-at-boot + enable | enable resolved (presets) | P4 (enable) + P5 (install) |
| D9 config & credential delivery | OPEN (deliberately) | P8 |
| D10 boundary labeling | RESOLVED (computed label) | P3 |
| D11 upgrade/rollback | RESOLVED (direction) | P5 |
| D12 package metadata (hybrid) | RESOLVED | P0 |
| D13 performance / init strategy | DEFER | P8 |
| D14 module-tree dissolve | RESOLVED | P7 |
| D15 unit naming `aos-pkg-<name>` | RESOLVED | P2 |
| D16 runtime unit placement (`/var/etc` attach) | RESOLVED | P5 |
| D17 execution substrate (per-unit default) | RESOLVED (direction); spike = validation | P3 (gate) |
| D18 `requires` resolver semantics | DECIDE-EARLY | P0 |
| D19 registry capability gate (fail-closed) | DECIDE-BEFORE-MVP | P0 (first) |

---

## Needs-verification register

Every small open gap in the set, collected so the implementer clears it rather
than guessing. Resolve each in the cited phase before ticking that phase's exit.

- [ ] **`system.attached` search path (P5).** Whether the AOS systemd build
      includes `/etc/systemd/system.attached/` in the unit search path with
      portabled disabled; if not, use `/var/etc/systemd/system/` directly — same
      mechanism, less tidy. ([`apm-integration.md`](apm-integration.md) §4.1, D16.)
- [ ] **Exact `expose` schema (P0/P1).** The precise units / permissions /
      `requires` / container-root-reference shape, co-designed with the registry
      metadata ([`apm-integration.md`](apm-integration.md) §2) and gated on D19.
- [ ] **`expose.permissions` validation point (P1).** Build-time, `apr publish`,
      or both (lean: both — build for authoring feedback, publish as the gate).
- [ ] **Runtime package scope (P5).** Whether runtime apm-installed packages share
      the `system` scope or get their own (`crates/aos-package/src/profile/mod.rs`);
      the apm package generation must stay independent of the toplevel generation.
- [ ] **Desired-packages file layout (P5).** Reuse `registries.d/` + a separate
      `packages.d/desired.toml`, or fold both into one document.
- [ ] **Expose-artifact carry-across-generations (P5).** Whether expose-phase
      units are carried by `copy_roots` or regenerated each generation
      (`install.rs`); whether a *package*-profile generation swap re-materializes
      them.
- [ ] **`expose.images` resolution (P6).** `images:` is "sysroot only" today; the
      installer must explicitly resolve `expose.images[].store_path` for ordinary
      packages (`crates/aos-package/src/resolve.rs`, `install.rs`).
- [ ] **nspawn feature checks (P8, only if nspawn lands).** cgroup-v2 delegation
      depth, `--private-users` mapping, custom seccomp support on the built
      `systemd-nspawn`.
- [ ] **`CAP_SYS_MODULE` policy (P0/P3).** Confirm module loading is *always*
      host-side via `kernel-modules` and `CAP_SYS_MODULE` is never granted into a
      container (lean: always host-side).
- [ ] **k3s strawman completeness (P3).** Desk-check against kind / k3d / Incus
      requirement sets; the current strawman likely misses `/lib/modules` (ro) and
      `/dev/fuse`.
- [ ] **Re-confirm investigation-reported facts (all phases).** The
      machined/portabled/importd disable flags, the kernel namespace configs, and
      the exact `aos-seed-profiles` ordering were read once and should be
      re-confirmed against the tree before the MVP lands.
