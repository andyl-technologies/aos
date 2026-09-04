# RFC-0001: AOS Package Sandboxing

- **Status:** Implemented for exposed APM service packages — Phases 0–10 in
  [`implementation-plan.md`](implementation-plan.md) have met their exit
  criteria, including the Decision 17 validation spike. The stronger microVM
  tier remains a planned future effort; the current threat model is first-party
  workload confinement. AOS remains an early preview; see the canonical
  [`support-status.md`](../../users/aos/support-status.md) for operational
  limitations. Current operator behavior is documented in
  [`package-sandbox.md`](../../users/aos/package-sandbox.md); maintainer review
  responsibilities are in
  [`package-security.md`](../../maintainers/package-security.md).
- **Mandate:** unlimited engineering budget, no corners cut — the target is the
  state of the art ([`state-of-the-art.md`](state-of-the-art.md)). Cost-based
  deferrals are lifted; what stays out is out **on merit** (dominated, no
  consumer, or pure attack surface), never cost — see
  [`open-questions.md`](open-questions.md) §"Why anything is still out of scope".
- **Date:** 2026-06-08
- **PR:** [#28](https://github.com/andyl-technologies/aos/pull/28)
- **Audience:** anyone working on `pkgs/`, `crates/aos-package/`,
  `lib/testing/`, `lib/modules/systemd/`, `modules/services/ignition.nix`,
  `modules/security/firewall.nix`, or `modules/`.

Every unit of software AOS runs is a **package**: a registry-installable unit
(`apm install <name>`) that is **sandboxed by default**. A package declares how
it integrates with the system — its systemd units, a signed `[permissions]`
manifest, and its service dependencies — in an optional **`expose`** attribute
that renders at build time into eval-free, signable artifacts. A host grants
only the permissions its policy allows, and every package's effects hang off a
single systemd handle, `aos-pkg-<name>.target`, which is the one switch for
turning the package on or off.

The default materialization is **per-unit sandboxing**: a confined non-verity
service runs from its own volatile overlay root (`RootDirectory=`) under
`/run`, with the authenticated package store path as its immutable lower layer.
`PrivateNetwork=`, `PrivateUsers=`, a `CapabilityBoundingSet=`,
`SystemCallFilter=`, and `DeviceAllow=` are all generated from its manifest. An
empty manifest is a tightly-confined sandbox; a package gets only what it
declares. High-privilege
software (k3s) is the same mechanism with a long, explicit manifest — its
privilege is visible and signed, not a special case. Config delivery is
layered: TPM2-sealed systemd credentials for secrets, schema-validated apm
config artifacts for structured config, and `EnvironmentFile=` for simple
settings — see [`config.md`](config.md).

## Where this sits in the tree

AOS already has a **registry/apm** system: a package is fetched and imported
into `/nix/store`, then merged into a profile generation under
`/var/lib/profiles/`. This lives in `crates/aos-package/` (`PackageMeta`,
`install.rs`, the profile/generation model) and ships on every image via
`modules/base/apm.nix`. The legacy path for software that needed systemd units
+ kernel modules + sysctls + firewall openings was the module system under
`modules/roles/` (the `roleType` submodule, `render-role.nix`,
`system.build.ignitionRolesBundle`), shipped as a per-host Ignition fragment.

This RFC makes the package the single deployable unit: software's units,
targets, privilege manifest, and dependencies travel **with the package** as
build artifacts, so a package can be installed *at runtime* from a registry —
not only baked into the image. The `modules/roles/` machinery has dissolved into
`pkgs/` `expose` blocks plus a thin host-policy layer
([`authoring.md`](authoring.md), [`migration.md`](migration.md)).

> The forcing function: `apm install` runs on a deployed host with **no Nix
> evaluator**. Whatever a package needs at install time (units, target,
> manifest, root reference) must exist as build artifacts in its store output /
> registry metadata — which is why integration is built *with* the package
> rather than evaluated host-side. Bridging Ignition → apm install at first boot
> is new work; see [`boot-activation.md`](boot-activation.md).

## Core terminology

| Term | Meaning |
|---|---|
| **package** | The registry-installable unit. Resolvable by `apm install <name>`; described by `PackageMeta` in `crates/aos-package/src/types.rs`. |
| **package target** | `aos-pkg-<name>.target` — the single systemd handle for the package's effects (the sandbox of [`activation.md`](activation.md)). |
| **`[permissions]` manifest** | The declared, signed privilege list on a package (see [`permissions.md`](permissions.md)). Empty = a tight sandbox; entries grant host network, capabilities, devices, host-paths, cgroup-delegate, kernel-modules, etc. The single source of truth for a package's privilege. |
| **per-unit sandboxing** | The default materialization: a confined non-verity service runs from a per-service volatile overlay `RootDirectory=` whose immutable lower layer is the authenticated payload store path, with `PrivateNetwork=`, `PrivateUsers=`, `CapabilityBoundingSet=`, `SystemCallFilter=`, and `DeviceAllow=` generated from the manifest (Decision 17, [`container-model.md`](container-model.md)). |
| **default (sandboxed) package** | A package with an empty `[permissions]` manifest — a real isolation boundary. |
| **high-privilege package** | A package like k3s whose manifest declares host privilege (host net/cgroups, global kernel modules, broad caps). Its boundary is *nominal* — a packaging/lifecycle wrapper, not a security boundary; see the honesty note below. |
| **privilege gradient** | Boundary strength runs from "full sandbox" (empty manifest) to "packaging wrapper" (k3s), set entirely by the manifest — not a categorical shape split. |
| **install-at-boot** | Ignition lists desired packages; an apm first-boot service installs them before enable. |
| **enable** | The package target becomes wanted via **systemd preset policy** (image default `disable *`; per-host Ignition-written preset file; an every-boot `aos-preset.service` pass; `systemctl preset` at runtime installs — see [`boot-activation.md`](boot-activation.md) §3.2) and is started. |
| **`expose` attribute** | The optional attrset on a package derivation carrying its units, `[permissions]` manifest, and service `requires` — rendered at build time to eval-free artifacts. See [`authoring.md`](authoring.md). |

## The model in one paragraph

A host's Ignition config lists packages (and the registries to fetch them from).
At first boot, an apm-driven oneshot installs each package into the store and a
profile generation, then **the package target is the handle** that gets enabled:
enabling `aos-pkg-<name>.target` pulls in the package's gated side-effect
services (modules/sysctl/firewall — [`activation.md`](activation.md)) and the
package's sandboxed service. What differs between packages is *privilege*,
generated from the signed `[permissions]` manifest: an empty manifest yields a
tightly sandboxed unit, while a manifest with grants (host network, capabilities,
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
                          └─► aos-pkg-<name>.service           (sandboxed per the [permissions] manifest)
```

## Honesty: the high-privilege end of the gradient (k3s)

k3s is the motivating high-privilege package, and it is the clearest place the
*sandbox* benefit disappears. It is still a package like every other — but its
`[permissions]` manifest declares away most of the boundary, **visibly**:

- **Kernel modules are global.** k3s declares `kernel-modules = ["br_netfilter",
  "vxlan", "ip_set"]`; these load into the host kernel via
  `aos-pkg-<name>-modules.service` regardless — a host-fulfilled, allowlisted
  permission (granted only if the modules are allowlisted; see
  [`permissions.md`](permissions.md)).
- **k3s declares host network and cgroups.** CNI configures host routes/bridges;
  kubelet manages host cgroups. A real netns/cgroup boundary breaks pod
  networking. So k3s's manifest declares `network = "host"` and `cgroup-delegate`
  (`Delegate=yes`, set by `pkgs/kubernetes/_k3s-expose-package.nix`),
  yielding effectively a **nominal** boundary (mount isolation only).
- Conclusion: for k3s the wrapper is a **packaging/lifecycle wrapper, not a
  security boundary**, and the signed manifest says so plainly. The real
  isolation boundary for k3s workloads is the kubelet's pod sandboxes.
- **Restart semantics are preserved.** k3s runs as a host unit under the
  per-unit substrate, so today's `KillMode=process` survives — restart/upgrade
  does not kill pods. (A private PID namespace could not preserve that, which is
  one driver of the per-unit substrate decision — see
  [`container-model.md`](container-model.md) §"The `KillMode=process`
  regression" and Decision 17 in [`open-questions.md`](open-questions.md).)

Default (empty-manifest) packages — a database, a web service — *are* genuinely
sandboxed. The difference is a **privilege gradient set by the manifest**, not a
separate package shape. See [`permissions.md`](permissions.md) for the full
permission surface and [`container-model.md`](container-model.md) for the
substrate mechanics and the resolved per-unit decision (`machined`/`portabled`/
`importd` are disabled in `pkgs/system/systemd.nix`).

## Scope

In scope:

- The optional `expose` attribute on `pkgs/` derivations, rendered at build time
  to eval-free artifacts; `modules/` shrinks to host policy —
  [`authoring.md`](authoring.md).
- A per-package systemd target as the uniform handle, with sandboxed
  side-effects — [`activation.md`](activation.md).
- A declared, signed `[permissions]` privilege manifest per package, generating
  the package's sandbox directives — [`permissions.md`](permissions.md).
- Per-unit sandboxing as the default substrate (nspawn skipped for MVP) —
  [`container-model.md`](container-model.md).
- Install-at-boot: Ignition lists packages; apm installs them; the target is
  enabled — [`boot-activation.md`](boot-activation.md),
  [`apm-integration.md`](apm-integration.md).
- Dissolved `modules/roles/` machinery into `pkgs/` `expose` blocks +
  policy — [`migration.md`](migration.md).
- Layered config delivery: TPM2-sealed credentials, schema-validated apm
  config artifacts, and `EnvironmentFile=` for simple settings —
  [`config.md`](config.md).

## Non-goals

- **An OCI runtime / containerd / cri-o.** Native packages are Nix store paths,
  not OCI tarballs.
- **Enabling `machined`/`portabled`/`importd`.** They stay disabled; lifecycle is
  via `systemctl` + explicit units, not `machinectl`.
- **Building full `systemd-nspawn` containers for MVP.** Per-unit sandboxing is
  the default substrate; nspawn is skipped until a future package genuinely
  needs its own multi-unit init tree (Decision 17).

## Document index

- [`implementation-plan.md`](implementation-plan.md) — **the phased, tickable
  build plan for the whole RFC.** A master progress table plus per-phase sections
  (goal, `- [ ]` deliverables naming concrete files, the decisions each phase
  closes, falsifiable exit criteria). Every topic doc below carries its own
  `## Implementation checklist`; this doc is the roll-up. Start here to build;
  read the topic docs for the *why*.
- [`README.md`](README.md) — **this doc.** Vision, terminology, scope, index.
- [`activation.md`](activation.md) — **the target sandbox.** The per-package
  `aos-pkg-<name>.target` as the one activation switch, the three global scan-dir
  drop-ins recast as target-gated oneshot services, teardown semantics, and the
  nftables reload-coherence requirement. The *shape*; enablement is
  [`boot-activation.md`](boot-activation.md).
- [`authoring.md`](authoring.md) — **where package definitions live.** Service
  integration as an optional `expose` attribute on `pkgs/` derivations (rendered
  at build time to eval-free, signable artifacts; nixpkgs Modular Services is the
  prior art), with `modules/` reduced to host policy.
- [`permissions.md`](permissions.md) — **the privilege manifest** (canonical
  model). The permission surface and its mapping to per-unit directives,
  default-deny least privilege, manifest examples (including k3s), introspection
  (`apm info --permissions`) / policy / signing, the computed confinement label,
  and the honest host-level limits (`kernel-modules`, `network: host`).
- [`container-model.md`](container-model.md) — the substrate. The resolved
  per-unit sandboxing default (`RootDirectory=` + isolation directives), how
  package payloads back per-service volatile overlay roots, networking modes,
  cgroup delegation, cross-package **composition rules** (flat siblings, no
  permission inheritance, no nesting, `aos.slice` hierarchy), the honest
  k3s-as-high-privilege case, and the future nspawn path.
- [`apm-integration.md`](apm-integration.md) — how a package declares its
  target/manifest in the registry: the `PackageMeta`/`ExposeMeta` schema, the
  signed `[permissions]` block, how `apm install` materializes and enables the
  package, and the trust / NAR-delivery implications.
- [`boot-activation.md`](boot-activation.md) — install-at-boot: Ignition lists
  packages + registries, an apm first-boot oneshot installs them (the gap beyond
  today's system-profile-only `aos-seed-profiles`), then enables the target via
  presets; idempotency via profile/state.json; ordering after `nix-overlay-setup`
  / `network-online.target`.
- [`config.md`](config.md) — layered package config and credential delivery:
  TPM2-sealed systemd credentials for secrets, schema-validated apm artifacts
  for structured config, `EnvironmentFile=` for simple config, and the
  hot-reload/restart contract.
- [`migration.md`](migration.md) — the cutover: dissolved `modules/roles/`
  machinery into `pkgs/` `expose` blocks + a thin policy module, the legacy
  touchpoints, and the validation gates (`aos fmt --check`, `checks.eval`,
  `systems.server.checks.system-boot`, package/fleet tests).
- [`open-questions.md`](open-questions.md) — the decision register: all 25
  tracked decisions with disposition, evidence, and owner.
- [`state-of-the-art.md`](state-of-the-art.md) — the comparison against other
  operating systems (Fuchsia/Genode/seL4, Android/iOS, Flatpak/Snap, Talos/
  Flatcar/ChromeOS, systemd/Landlock/eBPF-LSM): where AOS leads, where it was
  lagging, and what each improvement closes.
- [`enforcement.md`](enforcement.md) — **the layered defense-in-depth stack**:
  Landlock + a generated per-package MAC profile + fleet-managed eBPF-LSM, the
  full `systemd-analyze security` hardening baseline, per-package UID identity,
  and the per-package CI score gate — all generated from the manifest.
- [`attestation.md`](attestation.md) — **runtime integrity & hardware-rooted
  attestation**: dm-verity package roots validated against the `.platform`
  keyring, measuring the package set **and its privilege manifests** into the
  TPM (extending RFC-0006), the TPM quote + fleet verifier, and **how the
  registry fits in** as the golden-measurements catalog / provenance plane —
  never a runtime signer.

## Status of evidence

The findings behind these docs were gathered by read-only investigation of the
current tree (apm/registry, the role machinery, ignition/boot, substrate
feasibility, package-root build, config space, and testing). Where a claim rests
on planned future work or partially implemented machinery, the sibling docs say
so explicitly rather than implying it is already complete; verified facts are
collected in the implementation plan's evidence register.
