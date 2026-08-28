# Package execution substrate

Status: planning
Audience: anyone working on `modules/roles/`,
`lib/build/`, `pkgs/system/systemd.nix`, `modules/services/ignition.nix`, and the
`apm`/registry surface in `crates/aos-package/`.

This doc records how a **package** is materialized as a systemd-managed unit
with sandbox directives generated from a signed `[permissions]` manifest — see
[permissions.md](permissions.md) for that manifest and the full permission
surface. The MVP substrate is per-unit sandboxing; the retained nspawn sections
are a future template for a package that genuinely needs its own init tree. It
is deliberately honest that **k3s is a high-privilege package** whose isolation
is *nominal* — it declares host network, broad capabilities, cgroup delegation,
and host paths, and that privilege is visible in its manifest, not behind a "not
really a container" carve-out. Config delivery across the boundary is layered —
see [config.md](config.md). Sibling docs: [README.md](README.md),
[permissions.md](permissions.md),
[apm-integration.md](apm-integration.md), [boot-activation.md](boot-activation.md),
[migration.md](migration.md), [open-questions.md](open-questions.md). The
target-sandbox invariants are in
[activation.md](activation.md). Runtime-integrity siblings:
[attestation.md](attestation.md) (dm-verity + hardware attestation),
[enforcement.md](enforcement.md) (Landlock/MAC/eBPF-LSM layering),
[state-of-the-art.md](state-of-the-art.md). Under the
**unlimited-engineering-budget mandate, nothing here is deferred for cost** —
only correctness-driven deferrals (nspawn) remain.

## Where this sits in the model

The model (see [README.md](README.md)) builds on AOS's
registry/`apm` package system. A **package** is the registry-installable
unit (`apm install`). Under the unified model every service package exposes an
`aos-pkg-<name>.target` handle plus generated systemd units. There is **one
shape** — a package target — with a *privilege gradient* set by the package's
declared `[permissions]` manifest
(see [permissions.md](permissions.md)):

| Privilege | Manifest | Boundary | Example |
|---|---|---|---|
| Default (sandboxed) | empty `[permissions]` | real per-unit sandbox (private root, namespaces, caps/seccomp) | `test-http-server` |
| Some grants | a few declared permissions | real, but with declared holes | a web app needing a host path |
| High-privilege | host network + caps + cgroup-delegate + host-paths + kernel-modules | packaging/lifecycle wrapper, not a security boundary | `k3s-*` |

The boundary strength is a *gradient set by the manifest*, from "full sandbox"
(empty manifest) to "packaging wrapper only" (k3s) — not a categorical
workload/infra split. See [permissions.md](permissions.md) for the full
permission surface and how each grant maps onto systemd unit directives and
defense-in-depth policy artifacts.

The target sandbox ([activation.md](activation.md))
is the *activation* mechanism: `aos-pkg-<name>.target` is the one
switch, gated `*-modules`/`*-sysctl`/`*-firewall` oneshots are members,
and the disabled case is the strict guarantee. What this doc adds is the
execution substrate for the generated member units behind that target.

## Permissions

The privilege a package holds is **not** baked into the unit by hand — it is
**generated from a declared, signed `[permissions]` manifest** on the package,
exactly like an Android/iOS app permission list. The default (empty manifest) is
a tightly-sandboxed service; a package gets only what it declares. Each grant
(`capabilities`, `network`, `devices`, `host-paths`, `cgroup-delegate`,
`privileged-users`, `kernel-modules`, `syscalls`, `security-label`) maps onto a
specific systemd unit directive, host-side gated service, and generated policy
artifact. The full surface, the manifest examples
(including k3s's long list), and the honest host-level limits live in
[permissions.md](permissions.md). The manifest is the *what*; generated units
and artifacts are the *how*.

## Substrate decision (RESOLVED): per-unit default, nspawn skipped

The substrate decision is **resolved** (Decision 17 in
[open-questions.md](open-questions.md)): **per-unit sandboxing is the default
materialization, and nspawn is skipped for MVP** — reserved for a future package
that genuinely needs its own init tree. systemd offers this
substrate purpose-built for the niche: **per-unit sandboxing**
— `RootImage=`/`RootDirectory=` plus the unit-level isolation directives
(`PrivateNetwork=`, `PrivateUsers=`, `CapabilityBoundingSet=`, `DeviceAllow=`,
`BindPaths=`/`BindReadOnlyPaths=`, `SystemCallFilter=`, `ProtectSystem=strict`,
`MountAPIVFS=`). This is the portable-services model — which systemd's own docs
describe as "not a container, but lightweight application sandboxing using the
same directives," with host-selected `strict`/`default`/`trusted` profiles, the
same host-authoritative grant shape as [permissions.md](permissions.md).
`portabled` being disabled is irrelevant: the directives are core
service-manager features, and the attach logic is reimplemented by `apm`'s
expose phase either way.

Why this wins for the MVP:

- **The `[permissions]` manifest is substrate-independent.** Every manifest
  field maps onto a per-unit directive at least as cleanly as onto an nspawn
  flag (`capabilities`→`CapabilityBoundingSet=`/`AmbientCapabilities=`,
  `network`→`PrivateNetwork=`, `devices`→`DeviceAllow=`,
  `host-paths`→`BindPaths=`, `privileged-users`→`PrivateUsers=`,
  `syscalls`→`SystemCallFilter=`). The manifest is the architecture; nspawn is
  one possible materialization. Each field **also** derives a Landlock rule and
  a MAC profile (defense in depth, applied on top of the unit directives) — see
  [enforcement.md](enforcement.md).
- **It dissolves the k3s `KillMode=process` regression** (see the k3s section
  below): a high-privilege package becomes a host unit with few restrictions,
  and non-disruptive restart keeps working.
- **It removes the second service manager** for single-unit packages: no
  in-container PID1, no `--notify=ready` proxying, no nspawn-in-VM nesting risk
  (Decision 4), no extra nspawn package-root image for single-binary packages. The
  "single-service root" strategy below is `RootImage=` with extra steps.
- **nspawn's remaining honest use case** is a package that needs its own
  multi-unit init tree — currently a set of approximately zero (k3s is one
  binary plus a preflight, both expressible as host units under the target).
- **Socket activation and verity favor it too** (verified, systemd 259):
  host-namespace socket units pass **named** fds natively into a
  `PrivateNetwork=` sandboxed unit, while nspawn forwards `$LISTEN_FDS` only
  to a `--boot` init and drops fd names (`LISTEN_FDNAMES` forwarding is an
  open RFE, systemd#17764), needing `systemd-socket-proxyd` as a bridge.
  `PrivateNetwork=` + `JoinsNamespaceOf=` on socket units is reserved for the
  different shape where the listen socket itself must bind inside a shared
  private namespace. The same substrate also lets
  `RootImage=` carry dm-verity natively (`RootHash=`, `RootVerity=`,
  `RootHashSignature=`, v246+) — signed package roots extending the registry
  trust chain to runtime integrity (now in scope and built — see
  [attestation.md](attestation.md)). The `RootImage=` + `DynamicUser=` +
  `PrivateUsers=` + `MountAPIVFS=` stack is upstream's own portable-services
  **default profile** — the flagship-supported composition, not an experiment.
  (Caveats: loop-device based, auto-adds `After=systemd-udevd.service` so not
  early-boot, and must not be combined with `PrivateDevices=yes`.)
- **Per-package UID identity by default.** The per-unit substrate defaults to
  `DynamicUser=yes` + `PrivateUsers=identity` (systemd v257), giving every
  sandboxed package its own host UID identity. Two sandboxed packages then
  cannot reach each other's state **even via a shared host path** — the kernel
  ownership check fails across distinct UIDs. This matches Android's
  per-app-UID foundation. See [enforcement.md](enforcement.md).

Prior-art note: NixOS's declarative nspawn `containers.*` is the closest
precedent for "module system generates nspawn units," and it is widely
considered one of NixOS's weaker subsystems (machined coupling,
restart-on-switch semantics, networking friction); much of that ecosystem moved
to podman-systemd (quadlet) or per-unit hardening. The landing (Decision 17):
**per-unit sandboxing as the default materialization, nspawn skipped** until
a package genuinely needs an init tree. The default confined non-verity root is
a **per-service volatile overlay under `/run`**, with the authenticated package
store path as its immutable lower layer. The host-side
`aos-pkg-<package>-service-roots.service` preparation unit invokes
`aos-service-root prepare` to create
`/run/aos/service-roots/<package>/<unit>/{upper,work,merged}` and completes
before the workload; `RootDirectory=` names the merged path. The trusted helper
is bounded to `CAP_DAC_OVERRIDE`, `CAP_MKNOD`, and `CAP_SYS_ADMIN`, the minimal
set required for OverlayFS's private work directory, whiteouts, and mount. This needs no
image build, loop device, or udev ordering and prevents systemd mount-point
preparation from writing into the store. The signed-verity **`RootImage=` path
is now IN SCOPE**: the
cost-based deferral is **lifted by the unlimited-engineering-budget mandate**,
and verity-signed package roots are a **built deliverable**, not future work.
A `RootImage=` carries `RootHash=`/`RootVerity=`/`RootHashSignature=` validated
against the `.platform` keyring (populated from the UEFI db at boot), extending
the registry trust chain to runtime integrity. The kernel-config additions this
needs — `CONFIG_DM_VERITY`, `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`,
`CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG_PLATFORM_KEYRING` — and the full design
(image build, signature chain, attestation) live in
[attestation.md](attestation.md). Caveat: `RootImage=` is loop-device backed,
auto-adds `After=systemd-udevd.service` (so not early-boot), and must **not** be
combined with `PrivateDevices=yes`. The P3 spike validated the decision by
materializing `expose-minimal`'s default manifest (the
test-http-server-equivalent proving package before the P7 role migration),
`expose-smoke`'s side-effect manifest, and k3s's manifest as per-unit services,
including teardown semantics and the private-outbound netns plumbing cost.
The nspawn-specific sections below are retained as the spec for if/when a
package needs an init tree; the *boundary semantics* (what an empty manifest
isolates, what a grant opens) stand either way.

## Feasibility baseline (from investigation)

`systemd-nspawn` **is built and shipped**. It is built unconditionally by
systemd, independent of the management daemons. The current systemd build,
however, disables the surrounding ecosystem — in `pkgs/system/systemd.nix`:

```nix
-Dmachined=false
-Dportabled=false
-Dimportd=disabled
```

Consequences, verified against the current flags in
`pkgs/system/systemd.nix`:

- **No `machined` / `machinectl`.** No machine registry, no
  `systemd-nspawn@.service` multiplexing via `machinectl`, no
  `nss-mymachines` `.host`/`.local` name resolution. We define **explicit
  units** instead of relying on `machinectl start`.
- **No `portabled`.** No portable services / sysext-confext install path. Not
  needed; package roots carry their own contents.
- **No `importd`.** No `systemd-pull` image fetch. Images come from the AOS
  store via `apm`, not from upstream OCI registries.

This shapes any future nspawn design: AOS would drive containers through
**first-class systemd units**, not `machinectl`. systemd is 259.1, so the full
`--private-users`, `LoadCredential=`, `--volatile`, cgroup-delegation feature
set is present. The kernel config pins `CONFIG_NAMESPACES`, `CONFIG_USER_NS`,
`CONFIG_PID_NS`, `CONFIG_NET_NS`, `CONFIG_IPC_NS`, `CONFIG_UTS_NS`, and
`CONFIG_CGROUPS` in `pkgs/kernel/config/base.config`; the production resolved
config is asserted by `tests/build/kernel-config.nix`.

## Per-package root image

A package root is just a **smaller, single-purpose rootfs** built with the exact
same hermetic style AOS already uses for the host image and VM test disks. The
implemented builder is
[`lib/build/package-root-image.nix`](../../../lib/build/package-root-image.nix):

- `exportReferencesGraph` over the package's `rootPackages` discovers the
  closure (no host tools, sandbox-safe).
- The FHS skeleton (`/usr/{bin,lib,sbin}` real, `/bin`/`/sbin`/`/lib`
  symlinks, empty `/etc`, `/proc`, `/sys`, `/dev`, `/run`) is staged.
- Store closures are copied in; `/aos-registration` carries the closure-info
  stream so the embedded store is coherent.
- `fakeroot -- mkfs.ext4 -d rootfs … root.img` produces the image — **no
  losetup, no mount**, every file owned by uid/gid 0. This is the same
  sandbox-compatible path the host image uses.
- `veritysetup` and `openssl cms` produce `root.verity`, `root.roothash`, and
  `root.roothash.p7s` for `RootImage=` services that enforce dm-verity against
  the platform keyring.

Two PID1 strategies, chosen per package:

- **Single-service root** — `/init` is `exec`d straight to the one binary.
  Closure is minimal (binary + deps), startup is milliseconds. Good for
  sidecars and simple workloads.
- **systemd PID1 root** — `/init -> ${systemd}/lib/systemd/systemd`, with a
  minimal `/etc/systemd/system` carrying only the package's units and the
  targets to auto-start. Needed only if a future package genuinely needs several
  interdependent units inside its own init tree; k3s does not use this path for
  the MVP because its preflight and daemon are generated host units under the
  package target.

Image **format is ext4**, not EROFS, for package roots. The generated service
consumes it directly from the image store path with `RootImage=`,
`RootVerity=`, `RootHash=`, `RootHashSignature=`, and
`RootImagePolicy=root=signed`. Confined services without a verity image instead
use the per-service volatile overlay described above. The immutable store
payload remains its lower layer and its authenticated identity; systemd never
receives the store path itself as `RootDirectory=`.

Where the image lives: in a signed package image store path referenced by
`expose.images[]`. `apm install` and upgrade carry those image roots into the
package generation alongside the package closure and rendered expose artifact.

## Deferred nspawn template

The following sketch is retained only for the future case where a package needs
its own multi-unit init tree. It is **not** the MVP materialization. If nspawn
returns, machined stays off and the implementation must use explicit generated
units or a template with generated drop-ins rather than relying on
`systemd-nspawn@.service` + `machinectl`:

```ini
# aos-package@.service  (template; %i = package name)
[Unit]
Description=AOS package container %i
After=network-online.target
PartOf=aos-pkg-%i.target

[Service]
Type=notify
Delegate=yes
Slice=aos-pkg-%i.slice
DevicePolicy=closed
DeviceAllow=/dev/loop-control rw
DeviceAllow=block-loop rwm
DeviceAllow=block-blkext rwm
DeviceAllow=/dev/mapper/control rw
DeviceAllow=block-device-mapper rwm
ExecStart=/usr/lib/systemd/systemd-nspawn \
  --quiet \
  --keep-unit \
  --register=no \
  --machine=%i \
  --image=/var/lib/machines/%i.img \
  --volatile=overlay \
  --private-users=pick \
  --network-veth \
  --notify=ready \
  --load-credential=… \
  --setenv=… 
Restart=on-failure

[Install]
WantedBy=aos-pkg-%i.target
```

Three of those lines are load-bearing on a machined-less host (verified
against systemd 259): **`--register=no`**, because a privileged nspawn treats
failed machined registration as **fatal**; **`--keep-unit`**, because without
it nspawn asks PID 1 for its own transient scope under `machine.slice` *even
with* `--register=no` — escaping the unit's cgroup and making
`Slice=`/`Delegate=` dead letters; and the `DevicePolicy=closed` +
`DeviceAllow=` loop/device-mapper block, which mirrors upstream's own
`systemd-nspawn@.service` and is what lets `--image=` attach its loop device
under a closed device policy. With `--keep-unit`, `Slice=aos-pkg-%i.slice` is
fully honored — the package's nspawn instance, like its gated oneshots, lives under
`aos.slice/aos-pkg-<name>.slice` (see §Composition below).

Per-package divergence (network mode, binds, capabilities, user-ns policy) would
be supplied by generated unit text. The existing per-unit implementation already
uses fully rendered per-package services; that is the preferred shape if this
future nspawn path is reopened.

## Namespaces

`systemd-nspawn` gives a default (empty-manifest) package its own:

| Namespace | Default (empty manifest) | Notes |
|---|---|---|
| PID | private | container has its own PID1 (`systemd` or the binary) |
| Mount | private | own `/`, `/etc`, `/tmp`; host store bind-mounted RO |
| Net | private (`--network-veth`) | veth pair to host; see networking below |
| IPC | private | no host SysV/POSIX IPC leakage |
| UTS | private | own hostname (`--machine=%i`) |
| User | `--private-users=pick` | maps package root → unprivileged host uid range |
| cgroup | delegated subtree | `Delegate=yes`, container manages its own children |

`--private-users` is the contentious one. For the **default** (no
`privileged-users` permission) it is the right choice: package-root maps to
`nobody`-class host uids, so a container escape lands as an unprivileged host
user. The cost is the usual user-ns friction — file ownership in the image must
be shifted (`-U`/`--private-users=pick` handle this via UID shifting), and some
`/dev` access patterns break. A package that declares `privileged-users` in its
manifest turns user-ns off (`--private-users=no`); k3s does (see below).

## Networking

Beyond the host-global nftables base-set mutation described below (which is
**L3/L4 and host-global** — it mutates a shared host table), per-package network
policy SHOULD additionally use **per-package eBPF policy** (Cilium-style
per-identity attachment — the SOTA, vs. mutating a host-global set) and
**Landlock TCP bind/connect rules** (ABI 4+) to restrict egress from *inside*
the sandbox. These are identity-aware (keyed to the package's UID identity, see
above) and stack on top of the L3/L4 base table as defense in depth — see
[enforcement.md](enforcement.md) (layer 4). The signed manifest exposes those
grants as explicit `tcp-bind` and `tcp-connect` port lists, and the renderer
copies them into `network-policy.json`; they are not inferred from host firewall
ports.

Three modes, selected by the manifest's `network` permission:

- **`--network-veth` (default, `network = "private"`).** nspawn creates a veth pair; the
  host side (`ve-<pkg>*`) is managed by a `systemd-networkd` `.network` file
  the package ships into the host `/etc/systemd/network/`. `systemd-networkd`
  and `systemd-resolved` are already enabled on the host. The container side
  runs DHCP or static. nftables on the host gates container↔host and
  container↔world traffic — and this is exactly the `aos-pkg-<name>-firewall.service`
  gated oneshot from the target-sandbox design, now opening the container's
  ports on the host base table. Reachability from off-host additionally needs
  host-side forwarding — nspawn `--port=` (DNAT) or an equivalent nftables DNAT
  rule installed by the same gated service; both revert on stop. Verified for
  systemd 259: `--port=` works only with private networking and is
  **nftables-only** (the iptables backend was removed in v259); its rules live
  in systemd's own `io.systemd.nat` table, so AOS's base table — whose forward
  chain defaults to `policy drop` — can still eat the DNATed traffic. The
  gated firewall service must add the matching forward accept, or install the
  DNAT in the base table itself instead of using `--port=`. This
  `network = "private"`-with-outbound path additionally gains **Landlock TCP
  bind/connect rules** (ABI 4+) scoped to `tcp-bind` / `tcp-connect`, restricting
  egress from inside the sandbox even where the host base table would permit it
  — see [enforcement.md](enforcement.md).
- **`--network-zone=<zone>` (multi-container L2).** nspawn maintains a virtual
  zone hub so several containers share an isolated L2 without an external
  bridge. Available, less-documented; veth+managed-network is the more
  portable default.
- **`--network=host` (`network = "host"`).** No net isolation. This is what k3s
  declares and is a deliberate, manifest-visible downgrade — see below and
  [permissions.md](permissions.md).

## cgroup delegation

`Delegate=yes` on the generated service hands the package a delegated cgroup
subtree it can subdivide. This is the same mechanism the k3s exposed packages
already rely on today: `pkgs/kubernetes/_k3s-expose-package.nix` sets

```nix
serviceConfig = {
  Delegate = "yes";
  TasksMax = "infinity";
  LimitNOFILE = "1048576";
  TimeoutStartSec = "infinity";
};
```

For a package that declares `cgroup-delegate` the same keys go on the
`aos-pkg-<name>.service` unit, and the package manages workload cgroups beneath
the delegated root. Because the service lives under `aos-pkg-<name>.slice`,
accounting and cgroup policy stay inside the package target hierarchy without a
second service manager.

## Immutable root and writable state

`RootImage=` makes the image root immutable. For a non-verity service,
`RootDirectory=` selects a volatile per-service overlay whose lower layer is
the immutable authenticated payload; systemd-created mount points land only in
the overlay upper. The generated package roots preparation unit is ordered
before every affected workload and uses distinct `upper`, `work`, and `merged`
directories below `/run/aos/service-roots/<package>/<unit>`. Runtime writes by
the workload must still be explicit: tmpfs scratch paths through
`TemporaryFileSystem=`/`RuntimeDirectory=`, persistent state through
`StateDirectory=` or declared host-path grants. A package upgrade is therefore
"new package root + restart", not in-place mutation. k3s binds most real state
out to host paths, so the immutable-root property is mostly lifecycle hygiene
for it rather than meaningful isolation.

## Composition: packages that depend on each other

Cross-package structure follows one distinction and four rules, each grounded
in verified prior art.

**"Depends on" means two different things.**

1. **Closure dependencies** (the overwhelming majority): `runtimeDeps` on
   libraries and tools — zlib, iptables, even `pkgs.k3s`-the-payload. These
   are inert bytes that ride the Nix closure into the dependent's root
   image/`RootImage=`. Nix already composes these flatly and perfectly, and a
   payload being *also* installable as a service does not infect its
   dependents: B's binaries inside A's package root run **as A**, under **A's**
   manifest.
2. **Service dependencies** (rare, explicit): A needs B *running* — a web app
   needs the database package up. These are **not** closure edges; they are
   orchestration edges between flat siblings.

**Rule 1 — permissions never flow along closure edges.** Grants attach to the
runtime context: the unit that executes code declares for all code
it executes, like a statically-linked Android app. The cautionary precedent is
exact: Android deprecated `sharedUserId` (API 29) because merged security
identities made permission grants non-deterministic and impossible to unwind.
No inheritance, no transitive union, ever.

**Rule 2 — service dependencies are flat sibling edges, declared by name.**
A package's `expose` block may declare `requires = ["b"]`
([authoring.md](authoring.md)); apm resolves it like any dependency and the
expose phase materializes `After=`/`Wants=` edges between the **targets**
(`aos-pkg-a.target` → `aos-pkg-b.target`). Current resolution
(`crates/aos-package/src/resolve.rs`) pulls both `expose.requires` package
names and provider packages referenced by typed `expose.uses` routes; the
profile switch still lands the resulting set atomically. Keeping ordering edges
is deliberate: snapd offers *no* cross-snap ordering and its users hand-roll
retry loops as a recurring, documented pain point.

**Rule 3 — communication channels are declared on both sides.** B exposes a
socket/port; A declares the matching `host-paths` (unix socket dir) or network
reachability. Precedent: snapd's content interface (producer slot + consumer
plug + store-gated auto-connect) — coupling is capability-shaped and visible
in both manifests ([permissions.md](permissions.md)).

**Rule 4 — no nested package substrates.** A default-deny package cannot create
another privileged sandbox inside itself; doing so would require the very
capabilities the default profile removes. k3s spawning runc/containerd workloads
is the high-privilege proving case, not a pattern for ordinary packages: its
manifest makes those host grants explicit. Kubernetes reached the same
conclusion at the model level: pods are a flat container list, and ordered
helpers became sidecars-as-init-containers rather than nested pods.

**Resource hierarchy lives in slices.** Every package's generated service and
gated oneshots run under `aos.slice/aos-pkg-<name>.slice`. Slices carry resource
control only (no config, no privilege) and give `systemd-cgtop` per-package
accounting.

**The pod case (co-location) is one package, not two nested ones.** Two
processes that must share fate and a network namespace are a single
(meta-)package: under nspawn, two units inside one container; under the
per-unit substrate, two host units sharing a netns via `JoinsNamespaceOf=` —
verified semantics: shares **network + IPC + /tmp only** (no UTS, no PID),
requires `PrivateNetwork=`/`PrivateIPC=`/`PrivateTmp=` on **both** units,
implies no ordering (add `After=`/`Requires=` yourself), and works on socket
units — giving named-fd socket activation into the shared namespace, which
nspawn cannot do (systemd#17764).

## Lifecycle

Install and enable are split (see [boot-activation.md](boot-activation.md) and
[apm-integration.md](apm-integration.md) for the boot path):

1. **Install** — `apm install <pkg>` resolves the closure, fetches NARs,
   imports to the store, and writes a profile generation. If the package
   declares `expose.images[]`, those signed image store paths are fetched,
   verified, rooted, and linked into the generation's expose image roots.
2. **Enable** — `systemctl preset aos-pkg-<name>.target` against the merged
   preset policy; at boot the every-boot `aos-preset.service` pass re-derives
   enablement for every unit (see [boot-activation.md](boot-activation.md)
   §3.2). The target `Wants=` the generated per-package service and gated
   side-effect services.
3. **Run** — the generated `aos-pkg-<name>.service` starts the package workload;
   `Type=notify` / `Type=notify-reload` is used where the service supports it.
4. **Stop** — `systemctl stop aos-pkg-<name>.target` → `PartOf` propagates to the
   generated service → systemd applies the package's stop/kill policy.

## Teardown semantics: what reverts, what does not

This refines the target-sandbox teardown table for the package-service case.

| Effect | On `stop aos-pkg-<name>.target` | Notes |
|---|---|---|
| Package-root writes | **reverted or rejected** | root is immutable; tmpfs scratch evaporates |
| Package processes | **reverted** | `PartOf=` stops the generated service |
| Private network namespace | **reverted** | generated netns/veth helper is stopped with the package target |
| Firewall ports | **reverted** | `aos-pkg-<name>-firewall.service` `ExecStop` `nft delete element` |
| Explicitly-bound `/var/lib/<pkg>` state | **persists** | by design — that is what binds are for |
| Kernel modules (`aos-pkg-<name>-modules`) | **persists** | global, one-way; same caveat as today |
| sysctls (`aos-pkg-<name>-sysctl`) | **persists** | global, no saved prior value; same caveat |

So the package boundary improves revert for the workload's own root and
processes (vs. an ad hoc host service) but **does not change** the two
fundamentally-global caveats: **kernel modules and sysctls stay**.
`kernel-modules` is a host-fulfilled (allowlisted) permission — the host loads
them and they persist one-way after stop (see
[permissions.md](permissions.md) for the allowlist + signing model). The strict
guarantee remains the
*disabled* (never-enabled) case, identical to
[activation.md](activation.md).

## Security / isolation

For a default (empty-manifest) package the boundary is real: a private package
root, `PrivateNetwork=`, `PrivateUsers=`, `CapabilityBoundingSet=`,
`SystemCallFilter=`, `DeviceAllow=`, Landlock TCP/path rules, generated MAC
policy, eBPF network policy, and `nftables`-gated ports. The details live in
[enforcement.md](enforcement.md).

Boundary strength is a *gradient set by the manifest* (see
[permissions.md](permissions.md)). It is **not** a security boundary for a
high-privilege package like k3s — once a package declares host network, broad
caps, and host paths, its generated service is a packaging/lifecycle wrapper,
not a sandbox — and we must not pretend otherwise. The value is that the privilege is
least-by-default, declared, signed, and visible in the manifest, not that
everything is isolated.

## The host→package credential boundary

Crossing config/secrets into the package's service boundary is resolved by the
layered model in [config.md](config.md): TPM2-sealed systemd credentials for
secrets, schema-validated apm config artifacts for structured config, and
`EnvironmentFile=` for simple config. This section only states the substrate
boundary mechanics.

systemd's native path is `LoadCredential=`/`ImportCredential=`: the host unit
loads a credential and exposes it to the service under
`$CREDENTIALS_DIRECTORY` (tmpfs, `noexec`). AOS's resolved secret path layers
that runtime mechanism over TPM2-sealed credential sources, so the package does
not need a separate host-to-container credential handoff for the MVP.

## Honest caveat: k3s is a high-privilege package

k3s is a **high-privilege** package whose manifest declares away most of the
boundary. Its generated unit is a packaging/lifecycle wrapper, not a security
boundary. k3s must manage *host* state, and every one of these grants is an
explicit entry in its
`[permissions]` manifest (see [permissions.md](permissions.md)):

- **Kernel modules are global.** k3s declares `kernel-modules = ["br_netfilter",
  "vxlan", "ip_set"]` (via `pkgs/kubernetes/_k3s-expose-package.nix`). There is no
  per-package module namespace — these load into the host kernel via
  `aos-pkg-k3s-worker-modules.service`. The package cannot own them; this is a
  host-fulfilled, allowlisted permission (the host grants it only if the
  requested modules are allowlisted — see
  [permissions.md](permissions.md)).
- **Host network.** CNI/flannel program host routes, the host bridge, and host
  iptables/nftables. `PrivateNetwork=true` would cut k3s off from the L2 it is
  supposed to manage, so it declares `network = "host"`.
- **Host cgroups.** kubelet manages host cgroups; it declares
  `cgroup-delegate` (`Delegate=yes`) and runs in the package slice.
- **Broad capabilities** (declared `capabilities`) and host `/sys`, `/proc`,
  `/var/lib/kubelet`, `/var/lib/rancher` (declared `host-paths`).

The generated unit runs a process with effectively full host privilege. The
privilege is **visible in the manifest** rather than buried in the
implementation. The unit its manifest generates makes the privilege explicit and
ugly:

```ini
[Service]
Type=notify
Delegate=yes
PrivateNetwork=false
PrivateUsers=false
CapabilityBoundingSet=CAP_AUDIT_WRITE CAP_CHOWN CAP_DAC_OVERRIDE ...
AmbientCapabilities=CAP_AUDIT_WRITE CAP_CHOWN CAP_DAC_OVERRIDE ...
BindPaths=/sys /proc /var/lib/rancher /var/lib/kubelet /etc/rancher
KillMode=process
```

Host network, broad capabilities, delegated cgroups, and those host binds mean
the isolation benefit is intentionally low. The honest recommendation:

> **k3s is a high-privilege package** — like every package it gets an
> `aos-pkg-k3s-*.target` and generated units, but its `[permissions]` manifest
> declares host network, broad caps, cgroup-delegate, host-paths, and
> kernel-modules, so the generated service is a packaging/lifecycle wrapper, not
> a sandbox. It must be labelled as high privilege, not as a security boundary,
> and that labelling lives in the signed manifest, not in tribal knowledge.

### The `KillMode=process` regression (restart kills every pod)

The single biggest cost of wrapping k3s in nspawn, and it must not be glossed:
today's host unit (`pkgs/kubernetes/_k3s-expose-package.nix`) sets
`KillMode=process` — deliberately, inherited from upstream k3s packaging — so
stopping or upgrading `k3s.service` kills only the k3s supervisor process.
containerd, the shims, and **all pod processes survive the restart**. That is
the property that makes in-place k3s upgrades routine in production.

A systemd-nspawn container **always has a private PID namespace** (there is no
nspawn option to share the host's), and PID-namespace teardown kills everything
in it. Under the nspawn materialization, every
`systemctl restart aos-pkg-k3s-worker.target` — including every package upgrade
per [apm-integration.md](apm-integration.md) §5 — kills containerd, every shim,
and every pod outright. "Upgrades drain the node" understates it: it is an
ungraceful mass pod kill unless an explicit cordon+drain step is orchestrated
first.

For calibration: k3d and kind accept restart-kills-everything because they are
dev tools; the one production system running kubelet containerized (Talos, under
containerd with host namespaces) treats kubelet restart semantics as a
first-class engineering problem. The options are (a) accept it and loudly
document "k3s upgrade = pod kill; mitigate with drain orchestration," or (b)
materialize k3s as a host unit under its target (the per-unit substrate above),
which keeps `KillMode=process` intact. There is no nspawn flag that recovers
it. Tracked in [open-questions.md](open-questions.md) Decisions 11 and 17.

This is the **privilege gradient**, not a shape split: the same one-shape
package target model spans "full sandbox" (empty manifest) to "packaging
wrapper" (k3s), and the manifest is what places a package on it. See
[permissions.md](permissions.md) for the gradient and k3s's full (still
high-privilege) permission set.

## Relation to the target-sandbox invariants

Nothing here weakens the target sandbox ([activation.md](activation.md)):

- **Single activation root** — still `aos-pkg-<name>.target`. Generated member
  units are `WantedBy=`/`PartOf=` the target, never `WantedBy=multi-user.target`
  directly. Invariant 1 holds.
- **No global side-channels** — modules/sysctl/firewall remain gated oneshots
  under the target. The package service does not reintroduce drop-in scan dirs.
  Invariant 2 holds.
- **Containment edges** — the generated service carries
  `PartOf=aos-pkg-<name>.target` like every other member. Invariant 3 holds.
- **One enable switch** — still exactly the target. How that switch is flipped
  is owned by [boot-activation.md](boot-activation.md) §3.2 (canonical:
  systemd presets — image `disable *`, Ignition-written host preset file, an
  every-boot `aos-preset.service` pass, `systemctl preset` for runtime
  installs). Generated package units ship inert either way.

## Conditional future nspawn work

Decision 17 resolves the current substrate: per-unit `RootImage=` or volatile
overlay-backed `RootDirectory=` sandboxing is the default and nspawn is
skipped. If a future
multi-unit-init package reopens nspawn, the work is conditional and should start
from these items:

- Fully rendered per-package nspawn units, not a host-side evaluator and not
  `machinectl`.
- A separate nspawn metadata extension if `expose.images[]` plus unit text is
  insufficient.
- Materialization outside `/var/lib/machines` unless there is a concrete reason
  to use nspawn's machine-image conventions.
- A fresh `--private-users` and namespace/cgroup verification pass against the
  exact AOS systemd/kernel build.
- A stateful (`--directory=`) snapshot/rollback story.
- Continued refusal to enable `machined` unless a concrete need outweighs the
  attack-surface cost.
