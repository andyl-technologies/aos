# Migration: roles → packages

Status: planning

This doc is the concrete rename + cutover plan for folding the current
`aos.roles.<name>` module tree into the **packages** concept. It enumerates
the identifier/directory/option renames (`modules/roles/` → `modules/packages/`,
`ignitionRolesBundle`, the fleet-spec `roles` enum, the per-machine `roles = […]`
key, and the affected tests), proposes an ordered and individually-reviewable
increment plan, states the backward-compatibility stance, and is honest that the
rename is a **prerequisite**, not the feature: it ships **no** behavior change.
The interesting parts — registry installability, real nspawn containers, boot
activation, config — live in the sibling docs and land in later increments. It
also settles the relationship to PR #28 / [`../roles/targets-and-sandbox.md`](../roles/targets-and-sandbox.md):
that precursor doc stays where it is as history, and its content is superseded
by this doc set.

This is one of the package docs. Siblings:
[README.md](README.md), [permissions.md](permissions.md),
[container-model.md](container-model.md),
[apm-integration.md](apm-integration.md), [boot-activation.md](boot-activation.md),
[config.md](config.md), [open-questions.md](open-questions.md).

Audience: anyone working on `modules/roles/`, `lib/testing/fleet-spec.nix`,
`lib/testing/fleet.nix`, `lib/modules/systemd/render-role.nix`, `tests/fleet/`,
and the `aos.roles` consumers across the tree.

## Scope and non-goals

This doc covers **the rename only**: moving the existing typed-role machinery to
a `packages` namespace with no functional change. It is deliberately small and
mechanical so it can be the first merged increment, de-risking everything after.

Explicitly **out of scope here** (each has its own doc + later increment):

- Registry installability of packages (`apm install`) — [`apm-integration.md`](apm-integration.md).
- `systemd-nspawn` containers for every package, with privilege declared in a
  signed `[permissions]` manifest — [`container-model.md`](container-model.md),
  [`permissions.md`](permissions.md).
- Install-at-boot via Ignition + apm — [`boot-activation.md`](boot-activation.md).
- Config/credential delivery — [`config.md`](config.md) (decision **TBD**).

The naming we adopt here (`aos.packages.<name>`, `aos-<pkg>.target`,
`/etc/aos/packages/<name>`) is the surface those later docs already assume, so
doing the rename first removes churn from them.

## Why rename first, separately

The rename touches a lot of files but changes **zero** behavior. Bundling it
with semantic work (registry, nspawn) would make the diff impossible to review
honestly — a reviewer could not tell a pure rename from a real change. Landing
the rename as its own reviewable increment means:

- every subsequent PR diffs against the new names, so it stays small;
- a regression in the rename is bisectable independently of feature work;
- the `git mv`-heavy commit can be reviewed as "did the names move correctly"
  rather than "is the new container model correct".

## What is being renamed

The current design is described in
[`../roles/targets-and-sandbox.md`](../roles/targets-and-sandbox.md) and lives
under `modules/roles/`. The rename has four moving parts: the **option tree**,
the **build/bundle surface**, the **fleet-test surface**, and the **synthesized
systemd unit names**.

### 1. Option tree (`modules/roles/default.nix` → `modules/packages/default.nix`)

| Old | New |
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

`modules/roles/default.nix`'s header comment already documents the tree it owns
("Declares the `aos.roles.<name>` option tree…"); that comment and the
assertion messages (e.g. `aos.roles."${name}": role names must match …` near
line 400) move with it.

### 2. Build / bundle surface

| Old | New |
|---|---|
| `system.build.ignitionRolesBundle` | `system.build.packagesBundle` |
| `/etc/aos/ignition-roles/<name>` (fragment path) | `/etc/aos/packages/<name>` |
| `environment.etc."aos/ignition-roles"` | `environment.etc."aos/packages"` |
| `lib/modules/systemd/render-role.nix` | `lib/modules/systemd/render-package.nix` |

`ignitionRolesBundle` is defined once in `modules/roles/default.nix` and is
referenced from the initrd builder (`modules/base/_initrd-builder.nix`), the
stage-2 `environment.etc` mirror, and the fleet spec (which resolves
`file:///etc/aos/ignition-roles/<name>` merge entries). All three move together.

`render-role.nix`'s rename to `render-package.nix` is the one rename that is
**not** load-bearing — the helper's logic is identical. We rename it for
consistency, but it could be deferred to keep the first increment smaller (see
the increment plan). Its import in `default.nix` updates either way.

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

| Old | New |
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
`fleet-spec.nix` (lines ~10–15) that explains this contract moves verbatim with
the rename.

### 4. Synthesized systemd unit names (PR #28 surface)

PR #28 ([`../roles/targets-and-sandbox.md`](../roles/targets-and-sandbox.md))
synthesizes a per-role target and gated services. Those names carry an `aos-`
prefix because targets share a flat namespace with `multi-user.target`:

| PR #28 (role) | Packages |
|---|---|
| `aos-<role>.target` | `aos-<pkg>.target` |
| `aos-<role>-modules.service` | `aos-<pkg>-modules.service` |
| `aos-<role>-sysctl.service` | `aos-<pkg>-sysctl.service` |
| `aos-<role>-firewall.service` | `aos-<pkg>-firewall.service` |

**Naming decision (resolve before increment 4).** The investigation notes
floated a longer `aos-pkg-<name>-…` prefix to avoid collision in the global
systemd namespace. The rest of this doc set has already standardized on
`aos-<pkg>.target` and `aos-package@.service` (see
[`README.md`](README.md), [`container-model.md`](container-model.md)). We keep
`aos-<pkg>` here for consistency with those docs. This is the *minimal* mechanical
substitution of `<role>`→`<pkg>` in PR #28's synthesis and reads cleanly when
`<pkg>` is e.g. `k3s-worker` (`aos-k3s-worker.target`). If a future package name
ever collides with a stock systemd unit, the `aos-` prefix already disambiguates;
the longer `aos-pkg-` is held in reserve and **needs verification** only if a
real collision appears.

Note the container path adds a second unit family — the `aos-package@.service`
nspawn template from [`container-model.md`](container-model.md) — which is
*new*, not a rename, and is out of scope for this migration doc.

## What does NOT change

- **Per-package authoring.** Individual modules (`test-http-server.nix`,
  `aos-registry-server.nix`, the `kubernetes/k3s-*.nix` set) keep declaring
  `systemd.services`, `kernel.*`, and `firewall.*` exactly as today. The only
  edit inside each is the `cfg = config.aos.roles.<name>` →
  `config.aos.packages.<name>` line and the `aos.roles.<name> = { … }` →
  `aos.packages.<name> = { … }` block header.
- **Ignition fragment format.** `ignition.generate` output is byte-identical;
  only the on-disk path of the fragment changes.
- **The sandbox model.** PR #28's target + gated-service synthesis, the
  eval-time sandbox assertion, and the drift check are carried over unchanged
  (just renamed). The teardown semantics (strict-when-disabled, cheap-revert
  firewall, sticky modules/sysctls) are unchanged.
- **`render-role.nix` logic.** Renamed at most; not rewritten.

## Which roles get which privilege manifest

This is a *classification*, not part of the rename increment — but it drives the
later container increment, so it is recorded here. Under the unified model
**every** package is an nspawn container; what differs is *privilege*, declared
in a signed `[permissions]` manifest (see [`permissions.md`](permissions.md)).
There is no "container vs host-gated" split — only an empty manifest (full
sandbox) vs. a long one (k3s).

| Current role | Likely manifest | Disposition |
|---|---|---|
| `test-http-server` | empty (`network = "private"`) | **Tightly-sandboxed container.** Single Python `http.server` unit, no host privilege, no kernel modules — the canonical first nspawn package. |
| `aos-registry-server` | minimal (host port exposure only) | **Tightly-sandboxed container.** git-daemon + `aos serve` cache; host net exposure but no kernel/sysctl needs. Good second target. |
| `apm-systemd-client-test` | empty | Sandboxed container; it exists to exercise apm/systemd D-Bus, not to need privilege. |
| `kubernetes/k3s-worker` | high-privilege (host net + caps + cgroup-delegate + host-paths + kernel-modules) | **High-privilege container** (see below). |
| `kubernetes/k3s-control-plane` | high-privilege | **High-privilege container.** |
| `kubernetes/k3s-combined` | high-privilege | **High-privilege container.** |

### The k3s case (honest about the limit)

k3s is the package where the *sandbox* benefit disappears, and the rename must
not pretend otherwise. `modules/roles/kubernetes/k3s-worker.nix` already declares
`kernel.modules = [ "br_netfilter" "vxlan" "ip_set" ]`, `net.ipv4.ip_forward`
and bridge sysctls, ports 10250/8472, and a service with `Delegate = "yes"` /
`TasksMax = "infinity"`. Those become entries in k3s's `[permissions]` manifest,
and they are **host-global** by nature:

- kernel modules load into the **host** kernel — there is no per-container
  module namespace, so the `kernel-modules` permission is honored host-side and
  is the one irreducibly host-level grant;
- k3s/kubelet must drive host nftables, host routes, and the host cgroup tree
  to schedule pods, so k3s declares `network = "host"` and `cgroup-delegate`.

So after the rename, k3s is **still a container** with PR #28's target +
gated-service shape (`aos-k3s-worker.target` gating
`aos-k3s-worker-modules.service` etc.), but its manifest declares away most of
the boundary: the nspawn instance is a packaging/lifecycle wrapper, not a
security boundary. It must be labeled a *nominal* boundary, not a sandbox
([`container-model.md`](container-model.md) discusses the `--network=host` +
`--keep-unit` flags its manifest generates). The rename does not change this; it
only renames the units.

This is the practical meaning of the unified model: **every** package is a
container, but at least one (k3s) declares enough privilege that its container
is honestly nominal — and that is now recorded in the manifest, not in a
separate package class.

## Backward compatibility

There is **no external stability contract** to preserve: `aos.roles.<name>` is an
internal module option and `roles = […]` is internal fleet-test syntax. Neither
is a published API. The recommended stance is therefore a **hard rename, no
compatibility shim**, because:

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
and the fleet suite). Increments 1–3 are the rename; 4+ are the feature and are
detailed in the sibling docs.

### Increment 1 — move the module tree (pure `git mv` + option rename)

- `git mv modules/roles modules/packages` (preserves history per file).
- In `modules/packages/default.nix`: `aos.roles` → `aos.packages`, `roleType` →
  `packageType`, `system.build.ignitionRolesBundle` → `packagesBundle`,
  `environment.etc."aos/ignition-roles"` → `"aos/packages"`, header comment and
  assertion strings updated.
- In each `modules/packages/*.nix` and `modules/packages/kubernetes/*.nix`:
  rename the `cfg = config.aos.roles.<n>` binding and the `aos.roles.<n> = {…}`
  block header. **No logic edits.**
- Update the module-dir registration (the `./roles` entry in the module loader)
  to `./packages`.
- Update consumers of `ignitionRolesBundle` in `modules/base/_initrd-builder.nix`.
- **Reviewable as:** "did the names move, and only the names?" — diff should be
  rename + identifier substitution with no semantic hunks.
- **Gate:** `checks.eval` + `checks.vm.boot` pass. The fragment path moves from
  `/etc/aos/ignition-roles/<n>` to `/etc/aos/packages/<n>`; the boot test must
  still find it.

### Increment 2 — fleet-test surface

- `lib/testing/fleet-spec.nix`: `roles` option → `packages`, `availableRoles` →
  `availablePackages`, filter source `aos.roles` → `aos.packages`, merge target
  `file:///etc/aos/ignition-roles/<n>` → `file:///etc/aos/packages/<n>`, and the
  explanatory comment block.
- `lib/testing/fleet.nix`: the `roles = […]` → merge-entry synthesis updates to
  read the renamed key and emit the new path.
- `tests/fleet/*.nix`: every `roles = ["…"]` → `packages = ["…"]`
  (test-http-server, k3s-*, apm-* harnesses), and any assertion that greps for
  `ignition-roles/` → `packages/`.
- **Gate:** the full fleet suite (`test-http-server`, `k3s-control-plane-worker`,
  `apm-e2e`, …) passes unchanged in behavior.

### Increment 3 — helper rename + docs (optional, low-risk)

- `git mv lib/modules/systemd/render-role.nix render-package.nix`; update its
  import in `modules/packages/default.nix`. Logic untouched.
- Update in-tree comments that still say "role"/"roles" where they now mean a
  package.
- Move/curate docs: leave `docs/roles/targets-and-sandbox.md` in place as
  history (see next section), ensure this doc set cross-links it.
- **Gate:** `aos fmt --check` + `checks.eval`.

> Increments 1–3 complete the rename. At this point the tree is functionally
> identical to PR #28's roles-as-targets, under the `packages` name. Everything
> below is **new behavior**, gated by its own doc.

### Increment 4 — synthesized target naming reconciliation

- Land the `<role>`→`<pkg>` substitution in PR #28's synthesis so emitted units
  are `aos-<pkg>.target` / `aos-<pkg>-{modules,sysctl,firewall}.service`.
- If PR #28 has not yet merged, this folds into the rebase of #28 onto the
  `packages` names rather than being a separate PR. **Needs verification** of
  #28's merge state at the time this increment is scheduled.
- **Gate:** the eval guard from #28 (target + gated services present, no global
  scan-dir storage entry) passes under the new names.

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

## Relationship to PR #28 / `docs/roles/targets-and-sandbox.md`

PR #28 introduced the roles-as-targets sandbox under `modules/roles/` and
documented it at `docs/roles/targets-and-sandbox.md`. The packages direction
**builds on** #28; it does not discard it.

- **Does the doc move under `docs/packages/`?** No — leave
  `docs/roles/targets-and-sandbox.md` where it is, as the historical record of
  the targets/sandbox design and the PR that introduced it. This doc set
  ([`README.md`](README.md) and siblings) is the current source of truth and
  already links back to it. Moving the file would break the PR-#28 paper trail
  for little gain; a one-line "superseded by `docs/packages/`" banner at its top
  is the lighter touch (**optional**, do in increment 3).
- **Merge ordering.** Cleanest is: **#28 merges first** (roles-as-targets under
  the `roles` name), then increments 1–3 rename the merged result, then
  increment 4 reconciles the synthesized unit names. If #28 is still open when
  the rename starts, increments 1–4 collapse into a rebase of #28 onto the
  `packages` names. The **current merge state of #28 needs verification** before
  scheduling; this doc assumes it lands first.
- **What #28's "What changes" table becomes.** #28's table (its lines ~134–139)
  targeting `modules/roles/default.nix`, `lib/modules/systemd/render-role.nix`,
  and `modules/security/firewall.nix` maps file-for-file onto their renamed
  counterparts; the *content* of those changes is unchanged.

## Honest limits of this migration

- **It is a rename, full stop.** It delivers no installability, no container, no
  boot install. Reviewers should expect a large but boring diff. The value is
  de-risking the later increments, not user-visible change.
- **k3s is a high-privilege container, not a sandbox** (see the k3s case above):
  its manifest declares host network, broad caps, and global kernel modules, so
  its container is nominal. The rename must not be read as implying it is
  isolated.
- **Config is untouched and still open.** k3s continues to read
  `/etc/rancher/k3s/k3s.env` via `EnvironmentFile=` exactly as today; this doc
  picks **no** new config mechanism — that is [`config.md`](config.md)'s open
  decision.
- **The `render-role.nix` → `render-package.nix` rename and the
  `docs/roles/` banner are optional** and can be dropped from the first pass to
  keep increment 1 minimal.
- **Increment 4's exact landing shape depends on PR #28's merge state**, which
  needs verification when scheduling.
