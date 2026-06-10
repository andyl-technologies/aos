# Roles as systemd targets, with sandboxed side-effects

Status: design + phased implementation
Audience: anyone working on `modules/roles/`, `lib/modules/systemd/`,
`modules/services/ignition.nix`, or `modules/security/firewall.nix`.

## Problem

A "role" (e.g. `k3s-worker`) is a typed bundle of systemd units plus
kernel modules, sysctls, and firewall openings. Today a role's effects
reach the running system through **two** channels:

1. **systemd units** — services/targets/timers projected into the role's
   ignition fragment as `storage.links` (`render-role.nix`, spec §5.6).
2. **global scan-dir drop-ins** — `renderRoleLinks`
   (`modules/roles/default.nix`) writes
   `/etc/modules-load.d/role-<name>.conf`,
   `/etc/sysctl.d/70-role-<name>.conf`, and
   `/etc/nftables.d/50-role-<name>.nft`. These are consumed by the
   **host-global** `systemd-modules-load.service`, `systemd-sysctl.service`,
   and `nftables.service` (firewall.nix: `include "/etc/nftables.d/*.nft"`)
   **independently of any role unit**.

Channel 2 is a leak: there is no single switch that turns a role on or
off. Disable a role and its kernel modules still load, its sysctls still
apply, and its firewall ports still open, because three unrelated global
services pick the drop-ins up by directory scan.

This document defines a model where **every effect a role has is reachable
only through a single per-role systemd target** — a "role sandbox" — and
where that target is what Ignition enables at first boot.

## Goals

- **One switch per role.** `aos-<role>.target` is the sole activation
  root. Enabling/disabling it enables/disables the entire role.
- **Sandbox containment.** When the target is *not* enabled, *nothing*
  from the role is active: no modules, no sysctls, no firewall ports, no
  services. This is a build-time-checkable property, not a convention.
- **Introspection via systemd.** `systemctl list-dependencies
  aos-<role>.target` shows the whole role tree;
  `systemctl status aos-<role>.target` is the role's health.
- **Ignition-native activation.** First boot enables the role by enabling
  one unit, the target.

## The role sandbox

A role is **sandboxed** iff all three invariants hold. Invariants 1–2 are
enforced by an eval-time assertion in `modules/roles/default.nix`;
invariant 3 is guaranteed by the synthesis.

1. **Single activation root.** Exactly one unit — `aos-<role>.target` —
   carries `WantedBy=multi-user.target`. No member unit may be
   `WantedBy=` a system target directly.
2. **No global side-channels.** The role emits **zero** storage entries
   under `/etc/modules-load.d`, `/etc/sysctl.d`, or `/etc/nftables.d`.
   Each former drop-in becomes a target-gated oneshot (below).
3. **Containment edges.** Every member unit is `PartOf=aos-<role>.target`
   (stop/restart of the target propagates to it) and is pulled in by the
   target's `Wants=` (start of the target starts it).

### Side-effects become gated services

`renderRoleLinks`'s three global drop-ins are replaced by three oneshot
services, each `WantedBy=aos-<role>.target`, `PartOf=aos-<role>.target`:

| Former drop-in | Gated unit | Start | Stop |
|---|---|---|---|
| `/etc/modules-load.d/role-<n>.conf` | `aos-<role>-modules.service` | `modprobe -a <mods>` | — (one-way) |
| `/etc/sysctl.d/70-role-<n>.conf` | `aos-<role>-sysctl.service` | `sysctl -w <k=v>…` | — (one-way) |
| `/etc/nftables.d/50-role-<n>.nft` | `aos-<role>-firewall.service` | `nft add element …` | `nft delete element …` |

The firewall service keeps the role's ports in the **base table's**
`allowed_tcp` / `allowed_udp` sets (declared empty by firewall.nix) via
`add element` / `delete element`, rather than a separate table. A separate
table cannot make traffic flow: the base `input` chain has `policy drop`
and an explicit terminal `drop`, so an `accept` verdict from a
lower-priority chain in another table is overridden. Mutating the base
sets is the only correct *and* reversible option. `forwardPolicy=accept`
is applied as a named rule the service adds on start and deletes on stop.

**Reload coherence (required).** `nftables.service` reloads via
`ExecReload=nft -f /etc/nftables.conf`, which begins with `flush ruleset`
(`modules/security/firewall.nix`) — re-creating the base sets **empty**.
Without a countermeasure, a live reload (`reloadIfChanged` firing on a
generation upgrade) silently closes every active role's ports while the
gated services sit `active (exited)` believing their elements are applied.
Under the old model this could not happen: drop-ins were `include`d into
the same `nft -f` transaction, so base rules and role elements were always
re-created together. The gated services must restore that behavior: each
`aos-<role>-firewall.service` declares
`ReloadPropagatedFrom=nftables.service` and an `ExecReload=` identical to
its `ExecStart` (re-adding an existing element to an nft set is
idempotent), so a base-ruleset reload re-applies every *active* role's
elements. The edge lives on the role side because only the role units know
the role list; `nftables.service` stays role-agnostic. One component must
own reload-time reconciliation — this puts it on the gated services.

### Teardown semantics (decision: gate + cheap revert)

- **Disabled (image default):** none of the gated services run, so no
  modules, sysctls, ports, or workloads are applied. **Strict guarantee.**
- **Stopped at runtime** (`systemctl stop aos-<role>.target`): `PartOf`
  propagates stop to all members; the firewall service's `ExecStop`
  removes the role's ports; workload services stop. **Kernel modules stay
  loaded and sysctls keep their values** — these are not safely reversible
  (a module may be in use; no prior sysctl value is saved). This is
  documented and accepted: the load-bearing guarantee is the *disabled*
  case, which is strict.

## Activation: inert in image, Ignition enables the target

Under the composefs `/etc` model, "the image" is the EROFS lower and
`/etc` is an overlay. A role is shipped **inert** by baking its member
units + gated services into the EROFS `/etc/systemd/system` **without** any
`multi-user.target.wants/` symlink. They are present and introspectable but
inactive, because nothing wants them until the target exists and is
enabled.

The **target** is delivered and enabled by Ignition. The role's ignition
fragment carries a single `systemd.units[]` entry:

```json
{ "name": "aos-<role>.target",
  "contents": "[Unit]\nDescription=…\nWants=<members>\n…\n[Install]\nWantedBy=multi-user.target\n",
  "enabled": true }
```

Stock Ignition (coreos/ignition 2.25.1) processes this in its `files`
stage — already invoked by AOS at `ignition-files.service` with
`--root=/run/etc/ignition-<gen>`. Ignition **writes the target's contents
into `<root>`, then reads the `[Install]` section from the copy it just
wrote** to create `multi-user.target.wants/aos-<role>.target`. Because it
reads its own just-written file, it does not need the EROFS members to be
visible at files-stage time. At stage 2 the `/etc` overlay merges the
EROFS members with the per-gen target, systemd reaches the target, and the
target's `Wants=` pulls the members.

This is the "ship the role inert, flip one enable" model: the only thing
Ignition adds per activated role is one target unit and its one wants
symlink. Members are never re-shipped through Ignition.

Note this re-opens the systemd surface that spec §5.6.4 closed for roles —
deliberately and narrowly: roles may carry **exactly one** ignition
`systemd.units[]` entry, the synthesized `aos-<role>.target`, with
`enabled=true`. The old `ignitionExtras.systemd` free-for-all stays
forbidden.

> **Packages-direction note.** The packages doc set
> (`../packages/boot-activation.md` §3.2) supersedes this enable mechanism:
> there, enable is expressed via **systemd presets** (image ships `disable *`;
> Ignition writes a per-host preset file via `storage.files`; an every-boot
> `aos-preset.service` applies the merged policy — systemd's native first-boot
> pass cannot fire on AOS because the machine-id is committed in stage-1 by
> design; `systemctl preset` for runtime installs) — not by an Ignition
> `systemd.units[]` entry. The single-entry path above remains the documented
> roles-era mechanism for this PR only. Where the two descriptions disagree,
> `boot-activation.md` §3.2 is canonical for packages.

## What changes

| Area | Change |
|---|---|
| `modules/roles/default.nix` | Synthesize `aos-<role>.target`; rewire members (`PartOf`, drop direct `multi-user` wants); replace `renderRoleLinks` drop-ins with gated services; bake members into EROFS under `bundle`; emit the target-enable ignition fragment; add the sandbox assertion. |
| `lib/modules/systemd/render-role.nix` | Reduced role: produce the target's unit text for the fragment. Member `storage.links` prediction retired once members move to EROFS. |
| `modules/security/firewall.nix` | Base `allowed_tcp`/`allowed_udp` sets stay; the `include "/etc/nftables.d/*.nft"` line is removed (no role drop-ins anymore). Gated firewall services gain `ExecReload=` + `ReloadPropagatedFrom=nftables.service` for reload coherence (see above). |
| `modules/roles/*.nix` | No per-role authoring change required — synthesis is automatic. `k3s-*`, `test-http-server`, `aos-registry-server` keep declaring `systemd.services`, `kernel.*`, `firewall.*` as before. |

## Tests

- **Single-VM (`system.checks`)** on `test-http-server`: target file
  present; `aos-test-http-server.target` is active; `list-dependencies`
  shows the member; `systemctl stop` tears the role down (service stops,
  port 8000 closes); with the role disabled the unit files exist but
  nothing is active and 8000 is closed.
- **Eval guard:** the synthesized target + gated services appear in the
  role's rendered units; no storage path under a global scan dir is
  emitted (the sandbox assertion); the single ignition `systemd.units[]`
  target-enable entry is present.
- **Fleet (`tests/fleet/k3s-*`):** assert `aos-k3s-worker.target` /
  `aos-k3s-control-plane.target` are reached, in addition to the existing
  `k3s.service` checks.

## Naming

Targets share a flat namespace with `multi-user.target` etc., so the
`aos-` prefix is mandatory. Role name `<role>` is the existing
`[a-z][a-z0-9-]*` pattern; the target is `aos-<role>.target` and gated
services are `aos-<role>-{modules,sysctl,firewall}.service`.
