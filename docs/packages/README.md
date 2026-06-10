# Packages (formerly roles): overview & index

Status: planning

This doc set plans a new direction: **fold the "roles" concept into AOS's
existing apm/registry package system**. A "package" becomes the single
registry-installable unit (`apm install <pkg>`). Under the unified model
**every package is a systemd-nspawn container** plus an `aos-pkg-<name>.target`
handle; what differs between packages is *privilege*, declared in a **signed
`[permissions]` manifest** (Android/iOS app-permission analogy — see
[`permissions.md`](permissions.md)). The default (empty manifest) is a tightly
sandboxed container; a package gets only what it declares. k3s is not special —
it is a **high-privilege container** that declares a long permission list.
Packages are listed in a host's Ignition config, **installed at first boot by
apm**, then **enabled** (the package target and its nspawn instance). This
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
also carry units/targets and an nspawn container.** This is a prerequisite for
installing role-like bundles *at runtime* from a registry, rather than only
baking them into the image as Ignition fragments.

> Honesty note: today there is **no mechanism to install additional apm
> packages at first boot** — `aos-seed-profiles` in
> `modules/services/ignition.nix` only seeds the *system* profile. Bridging
> Ignition → apm install is new work this plan introduces; see
> [`boot-activation.md`](boot-activation.md).

## Core terminology

| Term | Meaning |
|---|---|
| **package** | The registry-installable unit. Resolvable by `apm install <name>`; described by `PackageMeta` in `crates/aos-package/src/types.rs`. Supersedes "role." Every package is an nspawn container. |
| **package target** | `aos-pkg-<name>.target` — the single systemd handle for the package's effects (the "sandbox" of [`../roles/targets-and-sandbox.md`](../roles/targets-and-sandbox.md)). |
| **`[permissions]` manifest** | The declared, signed privilege list on a package (see [`permissions.md`](permissions.md)). Empty = a tightly-sandboxed container; entries grant host network, capabilities, devices, host-paths, cgroup-delegate, kernel-modules, etc. The single source of truth for a container's privilege. |
| **default (sandboxed) package** | A package with an empty `[permissions]` manifest — a real isolation boundary (own PID1, netns, user-ns on, ephemeral overlay root). |
| **high-privilege package** | A package like k3s whose manifest declares host privilege (host net/cgroups, global kernel modules, broad caps). Its container is *nominal* — a packaging/lifecycle wrapper, not a security boundary; see the honesty note below. |
| **privilege gradient** | Boundary strength runs from "full sandbox" (empty manifest) to "packaging wrapper" (k3s), set entirely by the manifest — not a categorical shape split. |
| **install-at-boot** | Ignition lists desired packages; an apm first-boot service installs them before enable. |
| **enable** | The package target becomes wanted via **systemd preset policy** (image default `disable *`; per-host Ignition-written preset file; PID 1's native first-boot preset pass; `systemctl preset` at runtime installs — see [`boot-activation.md`](boot-activation.md) §3.2) and is started. |
| **`expose` attribute** | The optional attrset on a package derivation carrying its units, `[permissions]` manifest, and service `requires` — rendered at build time to eval-free artifacts. See [`authoring.md`](authoring.md). |

## The model in one paragraph

A host's Ignition config lists packages (and the registries to fetch them
from). At first boot, an apm-driven oneshot installs each package into the
store and a profile generation, then **the package target is the handle** that
gets enabled: enabling `aos-pkg-<name>.target` pulls in the package's gated
side-effect services (modules/sysctl/firewall, exactly as in the precursor
design) and an `aos-pkg-<name>` systemd-nspawn service. **Every package is a
container; the target is the uniform handle.** What differs is the container's
*privilege*, generated from the package's signed `[permissions]` manifest (see
[`permissions.md`](permissions.md)): an empty manifest yields a tightly
sandboxed container, while a manifest with grants (host network, capabilities,
host-paths, kernel-modules, …) trades the boundary away point by point.

```
Ignition (lists packages + registries)
        │
        ▼
apm install-at-boot  ──►  /nix/store + /var/lib/profiles/<scope>/gen-N
        │
        ▼
enable aos-pkg-<name>.target ──┬─► aos-pkg-<name>-modules.service   (modprobe — the host-level kernel-modules permission)
                          ├─► aos-pkg-<name>-sysctl.service    (sysctl -w)
                          ├─► aos-pkg-<name>-firewall.service  (nft add/del element)
                          └─► aos-pkg-<name>.service           (systemd-nspawn — privilege per the [permissions] manifest)
```

## Honesty: the high-privilege end of the gradient (k3s)

k3s is the motivating high-privilege package, and it is the clearest place the
*sandbox* benefit disappears. It is still a container like every package — but
its `[permissions]` manifest declares away most of the boundary, and that
declaration is now **visible** rather than hidden:

- **Kernel modules are global.** k3s declares `kernel-modules = ["br_netfilter",
  "vxlan", "ip_set"]`; these load into the host kernel via
  `aos-pkg-<name>-modules.service` regardless of any container — a host-fulfilled,
  allowlisted permission (granted only if the modules are allowlisted; see
  [`permissions.md`](permissions.md)).
- **k3s declares host network and cgroups.** CNI configures host routes/bridges;
  kubelet manages host cgroups. A real netns/cgroup boundary breaks pod
  networking. So k3s's manifest declares `network = "host"` and `cgroup-delegate`
  (`Delegate=yes`, already set in `modules/roles/kubernetes/k3s-worker.nix`),
  yielding effectively a **nominal** container (mount/UTS isolation only).
- Conclusion: for k3s the nspawn wrapper is a **packaging/lifecycle wrapper, not
  a security boundary**, and the signed manifest says so plainly. The real
  isolation boundary for k3s workloads is the kubelet's pod sandboxes, not
  nspawn.
- **Restart semantics regress under nspawn.** Today's `KillMode=process` lets
  k3s restart/upgrade without killing pods; a private PID namespace cannot
  preserve that — every container restart kills all pods. See
  [`container-model.md`](container-model.md) §"The `KillMode=process`
  regression" and the substrate decision (Decision 17) in
  [`open-questions.md`](open-questions.md).

Default (empty-manifest) packages — a database, a web service — *are* genuinely
sandboxed (`--network-veth`, `--private-users` on). The difference is a
**privilege gradient set by the manifest**, not a separate package shape. See
[`permissions.md`](permissions.md) for the full permission surface and
[`container-model.md`](container-model.md) for the nspawn mechanics and
feasibility findings (systemd-nspawn is shipped; `machined`/`portabled`/`importd`
are disabled in `pkgs/system/systemd.nix`).

## Scope

In scope for this plan:

- Rename `aos.roles.*` → `aos.packages.*` and the surrounding machinery
  (module dir, fleet-spec option, ignition bundle path). Pure naming/path
  change with no logic impact — see [`migration.md`](migration.md).
- A per-package systemd target as the uniform handle (generalizing PR #28).
- A systemd-nspawn container per package, built hermetically from source as a
  minimal rootfs (`lib/build/container-root.nix`, modeled on
  `lib/build/rootfs.nix`) — [`container-model.md`](container-model.md).
- A declared, signed `[permissions]` privilege manifest per package, generating
  the container's nspawn flags — [`permissions.md`](permissions.md).
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
three things PR #28 does not: (a) the package is now a *registry-installable*
unit, installable at runtime, not only an image-baked Ignition fragment; (b)
every package attaches a systemd-nspawn container under its target, turning the
"sandbox" from a gated set of host services into an actual namespace boundary by
default; and (c) the container's privilege is a declared, signed `[permissions]`
manifest ([`permissions.md`](permissions.md)), so a default package is a real
boundary and k3s is an honestly-labelled high-privilege wrapper. PR #28's naming
(`aos-<role>-*`) shifts to `aos-pkg-<name>-*` (prefix TBD — `aos-pkg-` was floated
for clarity; needs verification against unit-name collision rules).

## Document index

- [`README.md`](README.md) — **this doc.** Vision, terminology, scope, index.
- [`permissions.md`](permissions.md) — **the privilege manifest** (canonical
  model). Every package is a container; what differs is privilege, declared in a
  signed, auditable `[permissions]` manifest (Android/iOS app-permission
  analogy). Defines the permission surface and its mapping to nspawn flags,
  default-deny least privilege, manifest examples (including k3s), introspection
  (`apm info --permissions`)/policy/signing, and the honest host-level limits
  (`kernel-modules`, `network: host`).
- [`authoring.md`](authoring.md) — **where package definitions live**: service
  integration as an optional `expose` attribute on package derivations in
  `pkgs/` (rendered at build time to eval-free, signable artifacts; nixpkgs
  Modular Services is the merged prior art), with `modules/` reduced to host
  policy (bake list, presets, permission policy). Supersedes the central
  `modules/packages/` tree as the destination of the rename.
- [`container-model.md`](container-model.md) — the systemd-nspawn container
  model: every package is a container with a privilege gradient set by its
  manifest, how container roots are built hermetically from source (mirroring
  `lib/build/rootfs.nix` with `mkfs.ext4 -d`), networking modes, cgroup
  delegation, cross-package **composition rules** (flat siblings, no permission
  inheritance, no nesting, `aos.slice` hierarchy), and the honest
  k3s-as-high-privilege-container case. Also carries the **open substrate
  decision** (Decision 17): whether the manifest materializes as nspawn or as
  per-unit `RootImage=` sandboxing directives.
- [`apm-integration.md`](apm-integration.md) — how a package declares its
  target/container in the registry: extend `PackageMeta`
  (`crates/aos-package/src/types.rs`) or ship an in-closure manifest; the
  signed `[permissions]` block (no `expose.kind`); how `apm install` resolves
  the container rootfs and registers/enables the package target; trust and
  NAR-delivery implications.
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
- [`open-questions.md`](open-questions.md) — unresolved decisions: the policy
  enforcement point/format and the validated k3s permission set (Decision 1, now
  resolved into the unified `[permissions]` model), unit-name prefix, where
  container roots live (`/var/lib/machines`), image provisioning/signing, whether
  to enable `machined`, and the config decision — with what each blocks.

## Status of evidence

The findings behind these docs were gathered by read-only investigation of the
current tree (apm/registry, the role system, ignition/boot, nspawn
feasibility, container-image build, config space, and testing). Where a claim
rests on a design choice not yet in the tree (install-at-boot bridge, container
manifest schema, unit-name prefix, container-root builder), the sibling docs
say so explicitly rather than implying it already exists.
