# Cutover: dissolving the legacy role tree into packages

Status: implemented through the module-tree dissolve

This doc is the concrete cutover plan for the package-sandboxing design: how the
legacy `aos.roles.<name>` module tree became the **packages** concept in the
running source tree. It inventories every touched surface (the **option tree**,
the **build/bundle surface**, the **fleet-test surface**, and the **synthesized
systemd unit names**), classifies which packages get which privilege manifest,
states the backward-compatibility stance, and records the ordered,
individually-reviewable increment plan that was used.

Package definitions do **not** live in a central `modules/packages/` tree.
Service integration is an optional **`expose` attribute on package derivations
in `pkgs/`**, rendered at build time to eval-free artifacts, with `modules/`
shrinking to host policy (bake list, presets, permission policy) — see
[`authoring.md`](authoring.md). The legacy `modules/roles/` machinery was
therefore *dissolved* into `pkgs/` `expose` blocks, not relocated wholesale. The
touchpoint tables below remain the accurate inventory of every identifier and
path that moved; the increment plan records the order used:

1. Extend `mkDerivation` with the filtered `expose` attribute + the
   build-time unit/manifest renderer (reusing the pure
   `systemdLib`/`render-role.nix` functions — verified pure, see
   [`authoring.md`](authoring.md)).
2. Define `test-http-server` via `expose` end-to-end (build → image bake →
   preset enable → VM check) while the role tree still exists.
3. Dissolve `modules/roles/*` one package at a time into `pkgs/` `expose`
   blocks (k3s via meta-packages), then delete the `roleType` machinery and
   role loader.
4. Land the thin `modules/packages.nix` policy module + preset wiring
   ([`boot-activation.md`](boot-activation.md) §3.2).

Validation gates per increment are constant (`aos fmt --check`, `checks.eval`,
`systems.server.checks.system-boot`, package checks, and fleet suite).

This is one of the package docs. Siblings:
[README.md](README.md), [permissions.md](permissions.md),
[container-model.md](container-model.md),
[apm-integration.md](apm-integration.md), [boot-activation.md](boot-activation.md),
[config.md](config.md), [open-questions.md](open-questions.md),
[authoring.md](authoring.md).

Audience: anyone working on package exposure in `pkgs/`,
`lib/testing/fleet-spec.nix`, `lib/testing/fleet.nix`,
`lib/modules/systemd/render-role.nix`, `tests/fleet/`, and the former
`aos.roles` consumers across the tree.

## Scope

This doc covers the mechanical cutover: dissolving the existing typed-role
machinery into the `packages` surface, sequenced so each step kept `master`
green. Semantic features such as registry installability, install-at-boot,
config/credential delivery, and the per-unit sandbox substrate are tracked in
their own topic docs and in [`implementation-plan.md`](implementation-plan.md).

The naming we adopt here (`aos.packages.<name>`,
`aos-pkg-<name>.target`, package config under `/etc/aos/packages/<name>/`, and
fleet package seeding under `/etc/aos/packages.d/`) is the surface those later
docs already assume.

## Legacy touchpoints that changed

The former typed-role machinery lived under `modules/roles/`. The cutover had
four moving parts: the **option tree**, the **build/bundle surface**, the
**fleet-test surface**, and the **synthesized systemd unit names**. The tables
below are the authoritative inventory of every identifier, directory, and path
that moved.

### 1. Option tree (`modules/roles/default.nix`)

| Legacy | Final state |
|---|---|
| `aos.roles.<name>` | `pkgs.<name>.expose` plus optional `aos.packages.<name>` host policy |
| `aos.roles.<name>.bundle` | `aos.packages.<name>.bundle` |
| `aos.roles.<name>.systemd.*` | `pkgs.<name>.expose.units` |
| `aos.roles.<name>.kernel.*` | `pkgs.<name>.expose.kernel` plus signed `permissions.kernel-modules` |
| `aos.roles.<name>.firewall.*` | `pkgs.<name>.expose.firewall` plus signed TCP/UDP permission grants |
| `aos.roles.<name>.ignitionExtras` | package expose/config artifacts or test machine `instanceMetadata` |
| `roleType` (submodule binding) | removed; package policy lives in `modules/packages.nix` |

The old submodule did not move wholesale. Runtime integration now comes from
each package derivation's `expose` attribute, while `modules/packages.nix`
contains only host policy for bundling and image preset emission. The old
`modules/roles/default.nix` assertion messages and `roleType` binding are gone.

### 2. Build / bundle surface

| Legacy | Final state |
|---|---|
| `system.build.ignitionRolesBundle` | removed |
| `/etc/aos/ignition-roles/<name>` (fragment path) | removed; fleet package selection writes `/etc/aos/packages.d/fleet-seed` |
| `environment.etc."aos/ignition-roles"` | removed |
| `lib/modules/systemd/render-role.nix` | kept as a pure systemd renderer consumed by `pkgs/build-support/_expose-renderer.nix` |

The old role bundle was referenced from the initrd builder, stage-2 toplevel,
activation, and fleet spec. Those references are deleted rather than renamed:
selected bundled packages are seeded into the package profile, and exposed unit
artifacts are attached by the package path.

### 3. Fleet-test surface (`lib/testing/fleet-spec.nix`, `lib/testing/fleet.nix`)

`fleet-spec.nix` derives a per-machine `packages` enum from the chosen system's
bundled packages. The relevant shape today:

```nix
packages = mkOption {
  type = let
    availablePackages = builtins.attrNames (
      lib.filterAttrs (_: r: r.bundle or false)
        (config.system.config.aos.packages or {}));
  in types.listOf (types.enum availablePackages);
  # … writes selected package names into /etc/aos/packages.d/fleet-seed …
};
```

| Legacy | Final state |
|---|---|
| `fleetMachineType.options.roles` | `fleetMachineType.options.packages` |
| `availableRoles` (internal binding) | `availablePackages` |
| `config.system.config.aos.roles` (filter source) | `config.system.config.aos.packages` |
| merge target `file:///etc/aos/ignition-roles/<name>` | package-profile seed file `/etc/aos/packages.d/fleet-seed` |
| per-machine `roles = ["…"]` (in `tests/fleet/*.nix`) | `packages = ["…"]` |

The `bundle = true` filter semantics are unchanged: only bundled packages are
listable in a machine's `packages = […]`, because only bundled packages have the
payload and rendered expose artifact in the image. The fleet harness writes the
selected names into `/etc/aos/packages.d/fleet-seed`; APM reconciliation seeds
the package profile, attaches the artifacts, presets the selected target, and
starts it.

### 4. Synthesized systemd unit names

The synthesis emits a per-package target and gated services. The names carry an
`aos-pkg-` prefix because targets share a flat namespace with
`multi-user.target`. The resolved names are:

| Unit | Name |
|---|---|
| package target | `aos-pkg-<name>.target` |
| modules service | `aos-pkg-<name>-modules.service` |
| sysctl service | `aos-pkg-<name>-sysctl.service` |
| firewall service | `aos-pkg-<name>-firewall.service` |

**Unit naming is resolved: `aos-pkg-<name>`** (Decision 15 in
[`open-questions.md`](open-questions.md)). The `aos-pkg-` prefix makes "this
unit belongs to a package" explicit in the flat global unit namespace, and it is
the form every sibling doc ([`README.md`](README.md),
[`permissions.md`](permissions.md), [`container-model.md`](container-model.md),
[`boot-activation.md`](boot-activation.md),
[`open-questions.md`](open-questions.md)) already uses.

The nspawn container path (deferred — see [`container-model.md`](container-model.md))
adds a second unit family, the `aos-package@.service` template with instance
`%i` = package name, whose internal references are `PartOf=aos-pkg-%i.target` /
`WantedBy=aos-pkg-%i.target`. That family is *new*, not part of this cutover.

## What does NOT change

- **Per-package integration semantics.** Package units, module loads, sysctls,
  firewall openings, and target-gated activation keep the same behavioral
  contract, but they are authored in `pkgs/` `expose` blocks rather than
  `modules/roles`.
- **The sandbox model.** The target + gated-service synthesis, the eval-time
  sandbox assertion, and the drift check are carried over unchanged (just
  renamed). The teardown semantics (strict-when-disabled, cheap-revert firewall,
  sticky modules/sysctls) are unchanged.
- **`render-role.nix` logic.** The pure systemd rendering helper is reused by
  the expose renderer rather than rewritten.

## Which packages get which privilege manifest

This is a *classification* that drives the later container increment, recorded
here. Under the unified model every package's service integration is declared
through `expose`, and privilege is declared in a signed `[permissions]` manifest
(see [`permissions.md`](permissions.md)). There is no "container vs host-gated"
split — only an empty manifest (full sandbox) vs. a long one (k3s).

| Package | Likely manifest | Disposition |
|---|---|---|
| `test-http-server` | empty (`network = "private"`) | **Tightly-sandboxed.** Single Python `http.server` unit, no host privilege, no kernel modules — the canonical first `expose` package. |
| `aos-registry-server` | host network, TCP bind 9418/15000, static `aos-gitd` user, `CAP_CHOWN`, selected runtime host paths | **Sandboxed with declared holes.** git-daemon + `aos serve` cache; no kernel/sysctl needs, but the stable service UID and cache/bootstrap paths are explicit. |
| `apm-systemd-client-test` | empty | Sandboxed; it exists to exercise apm/systemd D-Bus, not to need privilege. |
| `k3s-worker` | high-privilege (host net + caps + cgroup-delegate + host-paths + kernel-modules) | **High-privilege host unit** (see below). |
| `k3s-control-plane` | high-privilege | **High-privilege host unit.** |
| `k3s-combined` | high-privilege | **High-privilege host unit.** |

### The k3s case (honest about the limit)

k3s is the package where a *sandbox* benefit disappears, and the design must not
pretend otherwise. `pkgs/kubernetes/_k3s-expose-package.nix` already declares
`kernel.modules = [ "br_netfilter" "vxlan" "ip_set" ]`, `net.ipv4.ip_forward`
and bridge sysctls, ports 10250/8472, and a service with `Delegate = "yes"` /
`TasksMax = "infinity"`. Those become entries in k3s's `[permissions]` manifest,
and they are **host-global** by nature:

- kernel modules load into the **host** kernel — there is no per-container
  module namespace, so the `kernel-modules` permission is host-fulfilled and
  allowlisted (granted only if the requested modules are in the host allowlist);
- k3s/kubelet must drive host nftables, host routes, and the host cgroup tree
  to schedule pods, so k3s declares `network = "host"` and `cgroup-delegate`.

Per the resolved per-unit substrate (Decision 17), k3s **materializes as a host
unit** — today's working unit shape, with `KillMode=process` preserved — gated
by its `aos-pkg-k3s-worker.target` over `aos-pkg-k3s-worker-modules.service` etc.
Its manifest *documents* the privilege it holds rather than building an nspawn
wrapper around it; nspawn is deferred ([`container-model.md`](container-model.md)).
k3s must be labeled a *nominal* boundary, not a sandbox: its declared privilege
is broad enough that an isolation claim would be dishonest.

This is the practical meaning of the unified model: most packages reach a real
sandbox, but at least one (k3s) declares enough privilege that its boundary is
honestly nominal — and that is recorded in the manifest, on a host unit, not in
a separate package class.

## Backward compatibility

There is **no external stability contract** to preserve: `aos.roles.<name>` is an
internal module option and `roles = […]` is internal fleet-test syntax. Neither
is a published API. The stance is therefore a **hard rename, no compatibility
shim**, because:

- a `aos.roles` → `aos.packages` `mkRenamedOptionModule`-style alias would keep
  two names alive indefinitely and invite half-migrated trees;
- the blast radius is fully in-repo and mechanically greppable (`rg
  '\baos\.roles\b'`, `rg 'ignition-roles'`, `rg 'ignitionRolesBundle'`, `rg
  '\broles\s*=\s*\['` in `tests/fleet/`), so a single sweep is tractable;
- the fleet `roles` enum is type-checked at eval, so a missed call site fails
  the eval check loudly rather than silently mis-activating.

If a transition window is wanted anyway (e.g. to land the move across two PRs
without breaking `master` mid-flight), the cheapest shim is a **read-only
alias**: define `aos.packages` as the real tree and `aos.roles = config.aos.packages`
as a deprecated mirror with a warning, plus a symlink
`/etc/aos/ignition-roles → packages` for one release. This is **optional** and
should be deleted in the increment that follows. The default plan is no shim.

## Ordered, reviewable increment plan

Each increment was kept reviewable and green with the matching gate set
(`aos fmt --check`, `nix-build -A checks.eval`,
`nix-build -A systems.server.checks.system-boot`, package checks, and the
affected fleet tests).

### Increment 1 — `expose` attribute + build-time renderer

- Completed: extended `mkDerivation` with the filtered `expose` attribute and
  the build-time unit/manifest renderer, reusing the pure `systemdLib` /
  `render-role.nix` functions (verified pure —
  [`authoring.md`](authoring.md)).
- At this historical increment, no package was migrated yet; the role tree
  still drove every system.
- **Reviewable as:** "does `expose` render the same units/manifest the role tree
  would, at build time?"
- **Gate:** `checks.eval` + `systems.server.checks.system-boot` pass; the
  renderer output matches the role tree's `ignitionConfig` byte-for-byte for an
  equivalent input.

### Increment 2 — `test-http-server` via `expose`, end-to-end

- Completed: defined `test-http-server`'s service integration through `expose`
  on its `pkgs/` derivation, and wired it through build → image bake → preset
  enable → VM check, while `modules/roles/*` still existed for everything else.
- The package is seeded into the package profile and attached from its rendered
  expose artifact; no role fragment is involved.
- **Gate:** the `test-http-server` fleet check passes against the `expose`-driven
  package, with no behavior change.

### Increment 3 — dissolve `modules/roles/*` into `pkgs/` `expose`

- Completed: converted each `modules/roles/*.nix` and
  `modules/roles/kubernetes/*.nix` package one at a time into a `pkgs/`
  `expose` block:
  - `aos.roles.<name>` consumers → `aos.packages.<name>`;
  - `system.build.ignitionRolesBundle` and
    `environment.etc."aos/ignition-roles"` were deleted;
  - k3s via meta-packages (the `kubernetes/k3s-*` set), materialized as host
    units per Decision 17;
  - fleet-test surface: `lib/testing/fleet-spec.nix` `roles` option →
    `packages`, `availableRoles` → `availablePackages`, filter source
    `aos.roles` → `aos.packages`, and the explanatory comment block;
    `lib/testing/fleet.nix` reads the renamed key and emits
    `/etc/aos/packages.d/fleet-seed`; `tests/fleet/*.nix` `roles = ["…"]` →
    `packages = ["…"]`.
  - Deleted the `roleType` machinery last, once no role-tree consumer remained.
- **Gate:** the full fleet suite (`test-http-server`, `k3s-control-plane-worker`,
  `apm-e2e`, …) passes unchanged in behavior after each package is dissolved;
  emitted units are `aos-pkg-<name>.target` /
  `aos-pkg-<name>-{modules,sysctl,firewall}.service`.

### Increment 4 — policy module + preset wiring

- Completed: landed the thin `modules/packages.nix` policy module (bake list,
  presets, permission policy) and preset wiring
  ([`boot-activation.md`](boot-activation.md) §3.2).
- **Gate:** `aos fmt --check`, `checks.eval`,
  `systems.server.checks.system-boot`, package checks, and the eval guard
  (target + gated services present, no global scan-dir storage entry) pass.

### Later semantic phases

The mechanical cutover deliberately stayed separate from the higher-risk
semantic phases. Registry installability, permission metadata, per-unit
sandboxing, install-at-boot, and config/credential delivery are tracked in the
topic docs and summarized in [`implementation-plan.md`](implementation-plan.md).

## Honest limits of this cutover

- **k3s is a high-privilege host unit, not a sandbox** (see the k3s case above):
  its manifest declares host network, broad caps, and global kernel modules, so
  its boundary is nominal. The cutover must not be read as implying it is
  isolated.
- **Config mechanics live elsewhere.** k3s continues to read
  `/etc/rancher/k3s/k3s.env` via `EnvironmentFile=`, while the general
  config/credential design is owned by [`config.md`](config.md) and Phase 5.
- **`render-role.nix` was not renamed.** It remains a pure systemd rendering
  helper and is consumed by the package expose renderer.
