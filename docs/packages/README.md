# Packages (formerly roles): overview & index

Status: planning

This doc set plans a new direction: **fold the "roles" concept into AOS's
existing apm/registry package system**. A "package" becomes the single
registry-installable unit (`apm install <pkg>`). Most packages are just store
paths with deps; **some packages additionally expose a systemd-nspawn
container plus an `aos-pkg-<name>.target` handle**. Packages are listed in a host's
Ignition config, **installed at first boot by apm**, then **enabled** (the
package target — and, for container packages, its nspawn instance). This
generalizes the precursor design in
[`../roles/targets-and-sandbox.md`](../roles/targets-and-sandbox.md) (PR #28),
which made each role a single `aos-<role>.target` with side-effects sandboxed
under it. Config delivery is **explicitly open / TBD** — see
[`config.md`](config.md).

Audience: anyone working on `modules/roles/` (to become `modules/packages/`),
`crates/aos-package/`, `lib/testing/`, `modules/services/ignition.nix`,
`modules/security/firewall.nix`, and `lib/build/`.

## Why rename roles → packages

Today a "role" (e.g. `k3s-worker`) is a typed bundle declared in the module
system — systemd units + kernel modules + sysctls + firewall openings —
shipped as a per-role Ignition fragment and activated by merging that fragment
at boot. The role machinery lives in:

- `modules/roles/default.nix` — the `roleType` submodule (`aos.roles.<name>`)
  and the `system.build.ignitionRolesBundle` collection.
- `lib/modules/systemd/render-role.nix` — renders typed units to unit files
  and predicts `storage.links` for the fragment.
- `lib/testing/fleet-spec.nix` — the fleet `roles` option (`roles = ["..."]`).

Separately, AOS already has a **registry/apm** system: a package is a
registry-installable unit fetched and imported into `/nix/store`, then merged
into a profile generation under `/var/lib/profiles/`. This lives in
`crates/aos-package/` (`PackageMeta`, `install.rs`, the profile/generation
model) and is shipped on every image by `modules/base/apm.nix`.

These are two unrelated notions of "a deployable thing." The rename makes them
one: **a package is the unit you install, and roles are simply packages that
also happen to carry units/targets and (optionally) a container.** This is a
prerequisite for installing role-like bundles *at runtime* from a registry,
rather than only baking them into the image as Ignition fragments.

> Honesty note: today there is **no mechanism to install additional apm
> packages at first boot** — `aos-seed-profiles` in
> `modules/services/ignition.nix` only seeds the *system* profile. Bridging
> Ignition → apm install is new work this plan introduces; see
> [`boot-activation.md`](boot-activation.md).

## Core terminology

| Term | Meaning |
|---|---|
| **package** | The registry-installable unit. Resolvable by `apm install <name>`; described by `PackageMeta` in `crates/aos-package/src/types.rs`. Supersedes "role." |
| **package target** | `aos-pkg-<name>.target` — the single systemd handle for the package's effects (the "sandbox" of [`../roles/targets-and-sandbox.md`](../roles/targets-and-sandbox.md)). Present whether or not the package ships a container. |
| **container package** | A package that *also* exposes a systemd-nspawn container (own PID1, namespaces). The container is gated by the package target. |
| **plain package** | A package with no container — just a store path / closure (the existing apm case). |
| **workload package** | A container package whose container is a real isolation boundary (own netns, user-ns optional). |
| **infrastructure package** | A package like k3s that needs host privilege (host net/cgroups, global kernel modules). Gets at most a *nominal* container; see the honesty note below. |
| **install-at-boot** | Ignition lists desired packages; an apm first-boot service installs them before enable. |
| **enable** | Start the package target (and, for container packages, its nspawn instance). |

## The model in one paragraph

A host's Ignition config lists packages (and the registries to fetch them
from). At first boot, an apm-driven oneshot installs each package into the
store and a profile generation, then **the package target is the handle** that
gets enabled: enabling `aos-pkg-<name>.target` pulls in the package's gated
side-effect services (modules/sysctl/firewall, exactly as in the precursor
design) and — for container packages — an `aos-pkg-<name>` systemd-nspawn service.
**The target is the uniform handle whether or not a container exists.** Plain
packages have a target with no container; container packages have a target that
additionally `Wants=` the nspawn service.

```
Ignition (lists packages + registries)
        │
        ▼
apm install-at-boot  ──►  /nix/store + /var/lib/profiles/<scope>/gen-N
        │
        ▼
enable aos-pkg-<name>.target ──┬─► aos-pkg-<name>-modules.service   (modprobe)
                          ├─► aos-pkg-<name>-sysctl.service    (sysctl -w)
                          ├─► aos-pkg-<name>-firewall.service  (nft add/del element)
                          └─► aos-pkg-<name>.service           (systemd-nspawn)   ← only if container package
```

## Honesty: where the model does NOT fit (k3s)

k3s is the motivating *infrastructure* package, and it is the clearest place
the container story breaks down:

- **Kernel modules are global.** `br_netfilter`, `vxlan`, `ip_set` load into
  the host kernel; there is no per-container module namespace. The
  `aos-pkg-<name>-modules.service` runs on the host regardless of any container.
- **k3s wants host network and cgroups.** CNI configures host routes/bridges;
  kubelet manages host cgroups. A real netns/cgroup boundary breaks pod
  networking. So k3s gets `--network=host`, host cgroup delegation
  (`Delegate=yes`, already set in `modules/roles/kubernetes/k3s-worker.nix`),
  and effectively a **nominal** container (mount/UTS isolation only).
- Conclusion: for k3s the nspawn wrapper is **transparent, not a security
  boundary**, and this must be stated plainly in the package's own docs. The
  real isolation boundary for k3s workloads is the kubelet's pod sandboxes,
  not nspawn.

Workload packages (a database, a web service) *can* be genuinely sandboxed
(`--network-veth`, optional `--private-users`). See
[`container-model.md`](container-model.md) for the split and the feasibility
findings (systemd-nspawn is shipped; `machined`/`portabled`/`importd` are
disabled in `pkgs/system/systemd.nix`).

## Scope

In scope for this plan:

- Rename `aos.roles.*` → `aos.packages.*` and the surrounding machinery
  (module dir, fleet-spec option, ignition bundle path). Pure naming/path
  change with no logic impact — see [`migration.md`](migration.md).
- A per-package systemd target as the uniform handle (generalizing PR #28).
- An optional systemd-nspawn container per package, built hermetically from
  source as a minimal rootfs (`lib/build/container-root.nix`, modeled on
  `lib/build/rootfs.nix`) — [`container-model.md`](container-model.md).
- Install-at-boot: Ignition lists packages; apm installs them; the target is
  enabled — [`boot-activation.md`](boot-activation.md) and
  [`apm-integration.md`](apm-integration.md).
- Surveying config-delivery options without choosing one —
  [`config.md`](config.md).

## Non-goals

- **Choosing a config/secret mechanism.** Explicitly deferred; do not settle
  on credstore. [`config.md`](config.md) surveys options and criteria only.
- **An OCI runtime / containerd / cri-o.** The container substrate is
  systemd-nspawn only. OCI image format is not integrated (native packages are
  Nix store paths, not OCI tarballs). Needs verification before any OCI claim.
- **Enabling `machined`/`portabled`/`importd`.** They stay disabled; lifecycle
  is via `systemctl` + explicit units, not `machinectl`.
- **Hot config reload.** Out of scope; current systemd model requires
  `systemctl restart` for config changes (see [`config.md`](config.md)).
- **Re-litigating the target/sandbox design** of PR #28. This plan *builds on*
  it; the three sandbox invariants are assumed.

## Relationship to the target/sandbox design (PR #28)

[`../roles/targets-and-sandbox.md`](../roles/targets-and-sandbox.md) is the
direct precursor. It establishes:

1. **One switch per role** — `aos-<role>.target` is the sole activation root.
2. **No global side-channels** — the three `renderRoleLinks` drop-ins
   (`/etc/modules-load.d`, `/etc/sysctl.d`, `/etc/nftables.d`) become
   target-gated oneshot services.
3. **Containment edges** — every member is `PartOf=` the target.

This plan **generalizes** that target into the uniform package handle and adds
two things PR #28 does not: (a) the package is now a *registry-installable*
unit, installable at runtime, not only an image-baked Ignition fragment; and
(b) a package may attach a *real* systemd-nspawn container under its target,
turning the "sandbox" from a gated set of host services into an actual
namespace boundary for workload packages. PR #28's naming (`aos-<role>-*`)
shifts to `aos-pkg-<name>-*` (prefix TBD — `aos-pkg-` was floated for clarity;
needs verification against unit-name collision rules).

## Document index

- [`README.md`](README.md) — **this doc.** Vision, terminology, scope, index.
- [`container-model.md`](container-model.md) — the systemd-nspawn container
  model: which packages get a container, workload vs. infrastructure
  (nominal) containers, how container roots are built hermetically from source
  (mirroring `lib/build/rootfs.nix` with `mkfs.ext4 -d`), networking modes,
  cgroup delegation, and the honest k3s carve-out.
- [`apm-integration.md`](apm-integration.md) — how a package declares its
  target/container in the registry: extend `PackageMeta`
  (`crates/aos-package/src/types.rs`) or ship an in-closure manifest; how
  `apm install` resolves the container rootfs and registers/enables the
  package target; trust and NAR-delivery implications.
- [`boot-activation.md`](boot-activation.md) — install-at-boot: Ignition lists
  packages + registries, a new apm first-boot oneshot installs them (the gap
  beyond today's system-profile-only `aos-seed-profiles`), then enables the
  target; idempotency via profile/state.json; ordering after
  `nix-overlay-setup` / `network-online.target`.
- [`config.md`](config.md) — the **open** config-delivery design space:
  Ignition `storage.files` + `EnvironmentFile` (today's k3s pattern), systemd
  credentials/credstore, per-package `/etc/aos/<pkg>/` overlays, apm config
  artifacts with registry schema, kernel cmdline, registry-hosted config — with
  a tradeoffs matrix and decision criteria. **No decision made.**
- [`migration.md`](migration.md) — the concrete rename plan and blast radius:
  `modules/roles/` → `modules/packages/`, `aos.roles` → `aos.packages`,
  `ignitionRolesBundle` → `packagesBundle`, `/etc/aos/ignition-roles/` →
  `/etc/aos/packages/`, fleet-spec `roles` → `packages`, and the validation
  gates (`aos fmt --check`, `checks.eval`, `checks.vm.boot`, fleet tests).
- [`open-questions.md`](open-questions.md) — unresolved decisions: unit-name
  prefix, where container roots live (`/var/lib/machines`), image
  provisioning/signing, whether to enable `machined`, the config decision, and
  the k3s "nominal container" labeling — with what each blocks.

## Status of evidence

The findings behind these docs were gathered by read-only investigation of the
current tree (apm/registry, the role system, ignition/boot, nspawn
feasibility, container-image build, config space, and testing). Where a claim
rests on a design choice not yet in the tree (install-at-boot bridge, container
manifest schema, unit-name prefix, container-root builder), the sibling docs
say so explicitly rather than implying it already exists.
