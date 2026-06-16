# Cutover: dissolving the current tree into packages

Status: planning

This doc is the concrete cutover plan for the package-sandboxing design: how the
current `aos.roles.<name>` module tree becomes the **packages** concept in the
running source tree. It inventories every current-tree touchpoint that changes
(the **option tree**, the **build/bundle surface**, the **fleet-test surface**,
and the **synthesized systemd unit names**) with real `file:line` facts,
classifies which packages get which privilege manifest, states the
backward-compatibility stance, and lays out an ordered, individually-reviewable
increment plan.

Package definitions do **not** live in a central `modules/packages/` tree.
Service integration is an optional **`expose` attribute on package derivations
in `pkgs/`**, rendered at build time to eval-free artifacts, with `modules/`
shrinking to host policy (bake list, presets, permission policy) — see
[`authoring.md`](authoring.md). The current `modules/roles/` machinery is
therefore *dissolved* into `pkgs/` `expose` blocks, not relocated wholesale. The
touchpoint tables below remain the accurate inventory of every identifier and
path that moves; the increment plan dissolves them in order:

1. Extend `mkDerivation` with the filtered `expose` attribute + the
   build-time unit/manifest renderer (reusing the pure
   `systemdLib`/`render-role.nix` functions — verified pure, see
   [`authoring.md`](authoring.md)).
2. Define `test-http-server` via `expose` end-to-end (build → image bake →
   preset enable → VM check) while the role tree still exists.
3. Dissolve `modules/roles/*` one package at a time into `pkgs/` `expose`
   blocks (k3s via meta-packages), deleting the `roleType` machinery last.
4. Land the thin `modules/packages.nix` policy module + preset wiring
   ([`boot-activation.md`](boot-activation.md) §3.2).

Validation gates per increment are constant (`aos fmt --check`, `checks.eval`,
`checks.vm.boot`, fleet suite).

This is one of the package docs. Siblings:
[README.md](README.md), [permissions.md](permissions.md),
[container-model.md](container-model.md),
[apm-integration.md](apm-integration.md), [boot-activation.md](boot-activation.md),
[config.md](config.md), [open-questions.md](open-questions.md),
[authoring.md](authoring.md).

Audience: anyone working on `modules/roles/`, `lib/testing/fleet-spec.nix`,
`lib/testing/fleet.nix`, `lib/modules/systemd/render-role.nix`, `tests/fleet/`,
and the `aos.roles` consumers across the tree.

## Scope

This doc covers the mechanical cutover: dissolving the existing typed-role
machinery into the `packages` surface, sequenced so each step keeps `master`
green. The semantic features each have their own doc and land in later
increments:

- Registry installability of packages (`apm install`) — [`apm-integration.md`](apm-integration.md).
- `systemd-nspawn` containers for packages, with privilege declared in a
  signed `[permissions]` manifest — [`container-model.md`](container-model.md),
  [`permissions.md`](permissions.md).
- Install-at-boot via Ignition + apm — [`boot-activation.md`](boot-activation.md).
- Config/credential delivery — [`config.md`](config.md) (decision **TBD**).

The naming we adopt here (`aos.packages.<name>`, `aos-pkg-<name>.target`,
`/etc/aos/packages/<name>`) is the surface those later docs already assume.

## Current-tree touchpoints that change

The current typed-role machinery lives under `modules/roles/`. The cutover has
four moving parts: the **option tree**, the **build/bundle surface**, the
**fleet-test surface**, and the **synthesized systemd unit names**. The tables
below are the authoritative inventory of every identifier, directory, and path
that moves.

### 1. Option tree (`modules/roles/default.nix`)

| Current | Becomes |
|---|---|
| `aos.roles.<name>` | `aos.packages.<name>` |
| `aos.roles.<name>.bundle` | `aos.packages.<name>.bundle` |
| `aos.roles.<name>.systemd.*` | `aos.packages.<name>.systemd.*` |
| `aos.roles.<name>.kernel.*` | `aos.packages.<name>.kernel.*` |
| `aos.roles.<name>.firewall.*` | `aos.packages.<name>.firewall.*` |
| `aos.roles.<name>.ignitionExtras` | `aos.packages.<name>.ignitionExtras` |
| `roleType` (submodule binding) | `packageType` |

The submodule's internal structure (`systemd`, `kernel`, `firewall`,
`ignitionExtras`, the computed `ignitionConfig` / `ignitionConfigDrv` /
`driftCheck`) is unchanged — only the option path and the binding name move.

`modules/roles/default.nix`'s header comment documents the tree it owns
("Declares the `aos.roles.<name>` option tree…"); that comment and the
assertion messages (e.g. `aos.roles."${name}": role names must match …` near
line 400) move with it.

### 2. Build / bundle surface

| Current | Becomes |
|---|---|
| `system.build.ignitionRolesBundle` | `system.build.packagesBundle` |
| `/etc/aos/ignition-roles/<name>` (fragment path) | `/etc/aos/packages/<name>` |
| `environment.etc."aos/ignition-roles"` | `environment.etc."aos/packages"` |
| `lib/modules/systemd/render-role.nix` | `lib/modules/systemd/render-package.nix` |

`ignitionRolesBundle` is defined once in `modules/roles/default.nix` and is
referenced from the initrd builder (`modules/base/_initrd-builder.nix`), the
stage-2 `environment.etc` mirror, and the fleet spec (which resolves
`file:///etc/aos/ignition-roles/<name>` merge entries). All three move together.

`render-role.nix`'s rename to `render-package.nix` is not load-bearing — the
helper's logic is identical. Its import in `default.nix` updates either way.

### 3. Fleet-test surface (`lib/testing/fleet-spec.nix`, `lib/testing/fleet.nix`)

`fleet-spec.nix` derives a per-machine `roles` enum from the chosen system's
bundled roles. The relevant lines today:

```nix
roles = mkOption {
  type = let
    availableRoles = builtins.attrNames (
      lib.filterAttrs (_: r: r.bundle or false)
        (config.system.config.aos.roles or {}));
  in types.listOf (types.enum availableRoles);
  # … "file:///etc/aos/ignition-roles/<name>" for the synthesised merge entry …
};
```

| Current | Becomes |
|---|---|
| `fleetMachineType.options.roles` | `fleetMachineType.options.packages` |
| `availableRoles` (internal binding) | `availablePackages` |
| `config.system.config.aos.roles` (filter source) | `config.system.config.aos.packages` |
| merge target `file:///etc/aos/ignition-roles/<name>` | `file:///etc/aos/packages/<name>` |
| per-machine `roles = ["…"]` (in `tests/fleet/*.nix`) | `packages = ["…"]` |

The `bundle = true` filter semantics are unchanged: only bundled packages are
listable in a machine's `packages = […]`, because only bundled packages have a
fragment at `/etc/aos/packages/<name>` for the synthesized
`ignition.config.merge` entry to resolve. The comment block at the top of
`fleet-spec.nix` (lines ~10–15) that explains this contract moves verbatim.

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

- **Per-package authoring.** Each package keeps declaring `systemd.services`,
  `kernel.*`, and `firewall.*` exactly as today. The only edit is the
  `cfg = config.aos.roles.<name>` → `config.aos.packages.<name>` binding and the
  `aos.roles.<name> = { … }` → `aos.packages.<name> = { … }` block header.
- **Ignition fragment format.** `ignition.generate` output is byte-identical;
  only the on-disk path of the fragment changes.
- **The sandbox model.** The target + gated-service synthesis, the eval-time
  sandbox assertion, and the drift check are carried over unchanged (just
  renamed). The teardown semantics (strict-when-disabled, cheap-revert firewall,
  sticky modules/sysctls) are unchanged.
- **`render-role.nix` logic.** Renamed at most; not rewritten.

## Which packages get which privilege manifest

This is a *classification* that drives the later container increment, recorded
here. Under the unified model every package's service integration is declared
through `expose`, and privilege is declared in a signed `[permissions]` manifest
(see [`permissions.md`](permissions.md)). There is no "container vs host-gated"
split — only an empty manifest (full sandbox) vs. a long one (k3s).

| Current role | Likely manifest | Disposition |
|---|---|---|
| `test-http-server` | empty (`network = "private"`) | **Tightly-sandboxed.** Single Python `http.server` unit, no host privilege, no kernel modules — the canonical first `expose` package. |
| `aos-registry-server` | minimal (host port exposure only) | **Tightly-sandboxed.** git-daemon + `aos serve` cache; host net exposure but no kernel/sysctl needs. Good second target. |
| `apm-systemd-client-test` | empty | Sandboxed; it exists to exercise apm/systemd D-Bus, not to need privilege. |
| `kubernetes/k3s-worker` | high-privilege (host net + caps + cgroup-delegate + host-paths + kernel-modules) | **High-privilege host unit** (see below). |
| `kubernetes/k3s-control-plane` | high-privilege | **High-privilege host unit.** |
| `kubernetes/k3s-combined` | high-privilege | **High-privilege host unit.** |

### The k3s case (honest about the limit)

k3s is the package where a *sandbox* benefit disappears, and the design must not
pretend otherwise. `modules/roles/kubernetes/k3s-worker.nix` already declares
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

Each increment is a single PR that keeps `master` green
(`aos fmt --check`, `nix-build -A checks.eval`, `nix-build -A checks.vm.boot`,
and the fleet suite).

### Increment 1 — `expose` attribute + build-time renderer

- Extend `mkDerivation` with the filtered `expose` attribute and the build-time
  unit/manifest renderer, reusing the pure `systemdLib` / `render-role.nix`
  functions (verified pure — [`authoring.md`](authoring.md)).
- No package is migrated yet; the role tree still drives every system.
- **Reviewable as:** "does `expose` render the same units/manifest the role tree
  would, at build time?"
- **Gate:** `checks.eval` + `checks.vm.boot` pass; the renderer output matches
  the role tree's `ignitionConfig` byte-for-byte for an equivalent input.

### Increment 2 — `test-http-server` via `expose`, end-to-end

- Define `test-http-server`'s service integration through `expose` on its
  `pkgs/` derivation, and wire it through build → image bake → preset enable →
  VM check, while `modules/roles/*` still exists for everything else.
- The fragment path moves to `/etc/aos/packages/test-http-server`; the boot/VM
  test must still find it.
- **Gate:** the `test-http-server` fleet check passes against the `expose`-driven
  package, with no behavior change.

### Increment 3 — dissolve `modules/roles/*` into `pkgs/` `expose`

- Convert each `modules/roles/*.nix` and `modules/roles/kubernetes/*.nix`
  package one at a time into a `pkgs/` `expose` block:
  - `aos.roles.<name>` consumers → `aos.packages.<name>`;
  - `system.build.ignitionRolesBundle` → `packagesBundle`,
    `environment.etc."aos/ignition-roles"` → `"aos/packages"`;
  - k3s via meta-packages (the `kubernetes/k3s-*` set), materialized as host
    units per Decision 17;
  - fleet-test surface: `lib/testing/fleet-spec.nix` `roles` option →
    `packages`, `availableRoles` → `availablePackages`, filter source
    `aos.roles` → `aos.packages`, merge target
    `file:///etc/aos/ignition-roles/<n>` → `file:///etc/aos/packages/<n>`, and
    the explanatory comment block; `lib/testing/fleet.nix` reads the renamed key
    and emits the new path; `tests/fleet/*.nix` `roles = ["…"]` → `packages =
    ["…"]`.
  - Delete the `roleType` machinery and `git mv lib/modules/systemd/render-role.nix
    render-package.nix` **last**, once no role-tree consumer remains.
- **Gate:** the full fleet suite (`test-http-server`, `k3s-control-plane-worker`,
  `apm-e2e`, …) passes unchanged in behavior after each package is dissolved;
  emitted units are `aos-pkg-<name>.target` /
  `aos-pkg-<name>-{modules,sysctl,firewall}.service`.

### Increment 4 — policy module + preset wiring

- Land the thin `modules/packages.nix` policy module (bake list, presets,
  permission policy) and preset wiring
  ([`boot-activation.md`](boot-activation.md) §3.2).
- **Gate:** `aos fmt --check`, `checks.eval`, `checks.vm.boot`, and the eval
  guard (target + gated services present, no global scan-dir storage entry)
  pass.

### Increment 5+ — the actual feature (separate docs)

- Registry installability → [`apm-integration.md`](apm-integration.md).
- The `[permissions]` manifest and its nspawn-flag generation →
  [`permissions.md`](permissions.md).
- nspawn containers, starting with the empty-manifest `test-http-server` then
  `aos-registry-server` → [`container-model.md`](container-model.md).
- Install-at-boot via Ignition + apm → [`boot-activation.md`](boot-activation.md).
- Config delivery (**TBD**) → [`config.md`](config.md).

These are intentionally left as separate increments because they carry real
design risk, unlike 1–4.

## Honest limits of this cutover

- **k3s is a high-privilege host unit, not a sandbox** (see the k3s case above):
  its manifest declares host network, broad caps, and global kernel modules, so
  its boundary is nominal. The cutover must not be read as implying it is
  isolated.
- **Config is untouched and still open.** k3s continues to read
  `/etc/rancher/k3s/k3s.env` via `EnvironmentFile=` exactly as today; this doc
  picks **no** new config mechanism — that is [`config.md`](config.md)'s open
  decision.
- **The `render-role.nix` → `render-package.nix` rename is mechanical** and
  happens last in Increment 3, once the role tree has no remaining consumer.
