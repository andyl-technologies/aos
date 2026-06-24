# Activation & the target sandbox

Every effect a package has on the running system is reachable through a
**single per-package systemd target**, `aos-pkg-<name>.target` — the package's
one on/off switch and the root of its sandbox. This doc defines that target, the
gated side-effect services that hang off it, the teardown semantics, and the
nftables reload-coherence requirement. *How* the target is enabled (systemd
presets) is [`boot-activation.md`](boot-activation.md) §3.2; this doc is the
**shape**.

Audience: anyone working on the `expose` renderer
([authoring.md](authoring.md)), `lib/modules/systemd/`,
`modules/services/ignition.nix`, or `modules/security/firewall.nix`.

## Problem

A package (e.g. `k3s-worker`) is a bundle of systemd units plus kernel modules,
sysctls, and firewall openings. Those effects could reach the running system
through **two** channels:

1. **systemd units** — services/targets/timers rendered from the package's
   `expose` block ([authoring.md](authoring.md)).
2. **global scan-dir drop-ins** — files under `/etc/modules-load.d`,
   `/etc/sysctl.d`, and `/etc/nftables.d` consumed by the **host-global**
   `systemd-modules-load.service`, `systemd-sysctl.service`, and
   `nftables.service` (firewall.nix: `include "/etc/nftables.d/*.nft"`)
   **independently of any package unit**.

Channel 2 is a leak: there would be no single switch that turns a package on or
off. Disable a package and its kernel modules would still load, its sysctls
still apply, and its firewall ports still open, because three unrelated global
services pick the drop-ins up by directory scan. This design closes channel 2:
**every effect is reachable only through the package's target.**

## Goals

- **One switch per package.** `aos-pkg-<name>.target` is the sole activation
  root. Enabling/disabling it enables/disables the entire package.
- **Sandbox containment.** When the target is *not* enabled, *nothing* from the
  package is active: no modules, no sysctls, no firewall ports, no services.
  This is a build-time-checkable property, not a convention.
- **Introspection via systemd.** `systemctl list-dependencies
  aos-pkg-<name>.target` shows the whole package tree;
  `systemctl status aos-pkg-<name>.target` is its health.

## The target sandbox

A package is **sandboxed** iff all three invariants hold. Invariants 1–2 are
enforced by an eval-time assertion in the `expose` renderer; invariant 3 is
guaranteed by the synthesis.

1. **Single activation root.** Exactly one unit — `aos-pkg-<name>.target` —
   carries `WantedBy=multi-user.target`. No member unit may be `WantedBy=` a
   system target directly.
2. **No global side-channels.** The package emits **zero** storage entries under
   `/etc/modules-load.d`, `/etc/sysctl.d`, or `/etc/nftables.d`. Each side-effect
   becomes a target-gated oneshot (below).
3. **Containment edges.** Every member unit is `PartOf=aos-pkg-<name>.target`
   (stop/restart of the target propagates to it) and is pulled in by the target's
   `Wants=` (start of the target starts it).

### Side-effects become gated services

The three global drop-ins become three oneshot services, each
`WantedBy=aos-pkg-<name>.target`, `PartOf=aos-pkg-<name>.target`:

| Effect | Gated unit | Start | Stop |
|---|---|---|---|
| kernel modules | `aos-pkg-<name>-modules.service` | `modprobe -a <mods>` | — (one-way) |
| sysctls | `aos-pkg-<name>-sysctl.service` | `sysctl -w <k=v>…` | — (one-way) |
| firewall ports | `aos-pkg-<name>-firewall.service` | `nft add element …` | `nft delete element …` |

The firewall service keeps the package's ports in the **base table's**
`allowed_tcp` / `allowed_udp` sets (declared empty by firewall.nix) via
`add element` / `delete element`, rather than a separate table. A separate table
cannot make traffic flow: the base `input` chain has `policy drop` and an
explicit terminal `drop`, so an `accept` verdict from a lower-priority chain in
another table is overridden. Mutating the base sets is the only correct *and*
reversible option. `forwardPolicy=accept` is applied as a named rule the service
adds on start and deletes on stop.

**Reload coherence (required).** `nftables.service` reloads via
`ExecReload=nft -f /etc/nftables.conf`, which begins with `flush ruleset`
(`modules/security/firewall.nix`) — re-creating the base sets **empty**. Without
a countermeasure, a live reload (`reloadIfChanged` firing on a generation
upgrade) silently closes every active package's ports while the gated services
sit `active (exited)` believing their elements are applied. The gated services
prevent this: each `aos-pkg-<name>-firewall.service` declares
`ReloadPropagatedFrom=nftables.service` and an `ExecReload=` identical to its
`ExecStart` (re-adding an existing element to an nft set is idempotent), so a
base-ruleset reload re-applies every *active* package's elements. The edge lives
on the package side because only the package units know the package list;
`nftables.service` stays package-agnostic. One component must own reload-time
reconciliation — this puts it on the gated services.

### Teardown semantics (gate + cheap revert)

- **Disabled (image default):** none of the gated services run, so no modules,
  sysctls, ports, or workloads are applied. **Strict guarantee.**
- **Stopped at runtime** (`systemctl stop aos-pkg-<name>.target`): `PartOf`
  propagates stop to all members; the firewall service's `ExecStop` removes the
  package's ports; workload services stop. **Kernel modules stay loaded and
  sysctls keep their values** — these are not safely reversible (a module may be
  in use; no prior sysctl value is saved). This is documented and accepted: the
  load-bearing guarantee is the *disabled* case, which is strict.

## Activation: inert in image, enabled by preset

Under the composefs `/etc` model, "the image" is the EROFS lower and `/etc` is
an overlay. A package is shipped **inert** by baking its member units + gated
services into the EROFS `/etc/systemd/system` **without** any
`multi-user.target.wants/` symlink. They are present and introspectable but
inactive, because nothing wants them until the target is enabled.

The target is enabled by **systemd preset policy**, not by a per-package
`multi-user.target.wants` symlink baked at build time: the image ships
`disable *`, a per-host preset file names the targets to enable, and an
every-boot `aos-preset.service` applies the merged policy
([`boot-activation.md`](boot-activation.md) §3.2 is canonical for the preset
mechanism, including why systemd's native first-boot pass cannot fire on AOS and
why the tmpfs `/etc` upper forces every-boot reconciliation). Runtime installs
enable with `systemctl preset aos-pkg-<name>.target`. Members are never enabled
directly; the target's `Wants=` pulls them.

This is the "ship the package inert, flip one enable" model: enabling a package
flips exactly one target's preset, and the target pulls in everything else.

## Where the synthesis lives

The target + gated services are produced at **build time** by the package's
`expose` renderer ([authoring.md](authoring.md)), not by a central module:

| Area | Responsibility |
|---|---|
| `expose` renderer (`lib/modules/systemd/`) | Synthesize `aos-pkg-<name>.target`; rewire members (`PartOf`, no direct `multi-user` wants); render the three gated side-effect services in place of any global drop-in; emit the eval-time sandbox assertion. |
| `modules/security/firewall.nix` | The base `allowed_tcp`/`allowed_udp` sets stay; the `include "/etc/nftables.d/*.nft"` line is removed (no package drop-ins). Gated firewall services carry `ExecReload=` + `ReloadPropagatedFrom=nftables.service` for reload coherence (above). |
| `modules/packages.nix` (policy) | The bake list (which packages' inert units ship in the EROFS) and the image preset policy. |

Individual packages declare their `systemd` units, `kernel.*`, and `firewall.*`
in their `expose` block; the target/gated-service synthesis is automatic.

## Tests

- **Single-VM** on `test-http-server`: the target file is present;
  `aos-pkg-test-http-server.target` is active; `list-dependencies` shows the
  member; `systemctl stop` tears the package down (service stops, port 8000
  closes); with the package disabled the unit files exist but nothing is active
  and 8000 is closed.
- **Eval guard:** the synthesized target + gated services appear in the
  package's rendered units; no storage path under a global scan dir is emitted
  (the sandbox assertion).
- **Fleet (`tests/fleet/k3s-*`):** assert `aos-pkg-k3s-worker.target` /
  `aos-pkg-k3s-control-plane.target` are reached, in addition to the existing
  `k3s.service` checks.

## Naming

Targets share a flat namespace with `multi-user.target` etc., so the `aos-pkg-`
prefix is mandatory. Package name `<name>` is the existing `[a-z][a-z0-9-]*`
pattern; the target is `aos-pkg-<name>.target` and the gated services are
`aos-pkg-<name>-{modules,sysctl,firewall}.service`.
