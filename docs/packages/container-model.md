# The systemd-nspawn container model

Status: planning
Audience: anyone working on `modules/packages/` (the renamed `modules/roles/`),
`lib/build/`, `pkgs/system/systemd.nix`, `modules/services/ignition.nix`, and the
`apm`/registry surface in `crates/aos-package/`.

This doc plans how a **package** runs inside a real `systemd-nspawn(1)`
container. Under the unified model **every** package is an nspawn container; what
differs is *privilege*, declared in a signed `[permissions]` manifest — see
[permissions.md](permissions.md) for that manifest and the full permission
surface. This doc covers the per-package root image, the `aos-package@.service`
template, the namespace/networking/cgroup choices, the ephemeral overlay that
gives us a cheap fs-revert, teardown semantics, and the host→container PID1
credential boundary. It is deliberately honest that **k3s is a high-privilege
container** whose isolation is *nominal* — it declares host network, broad
capabilities, cgroup delegation, and host paths, and that privilege is now
visible in its manifest rather than hidden behind a "not really a container"
carve-out. Config delivery across the boundary is **left open** — see
[config.md](config.md). Sibling docs: [README.md](README.md),
[permissions.md](permissions.md),
[apm-integration.md](apm-integration.md), [boot-activation.md](boot-activation.md),
[migration.md](migration.md), [open-questions.md](open-questions.md). The
target-sandbox invariants this builds on are in
[../roles/targets-and-sandbox.md](../roles/targets-and-sandbox.md).

## Where this sits in the new model

The new direction (see [README.md](README.md)) folds "roles" into AOS's
existing registry/`apm` package system. A **package** is the registry-installable
unit (`apm install`). Under the unified model **every** package exposes a
`systemd-nspawn` container plus an `aos-pkg-<name>.target` handle. This doc is
about that container. There is **one shape** — a container — with a *privilege
gradient* set by the package's declared `[permissions]` manifest
(see [permissions.md](permissions.md)):

| Privilege | Manifest | Boundary | Example |
|---|---|---|---|
| Default (sandboxed) | empty `[permissions]` | real (PID/mount/net/IPC/user ns) | `test-http-server` |
| Some grants | a few declared permissions | real, but with declared holes | a web app needing a host path |
| High-privilege | host network + caps + cgroup-delegate + host-paths + kernel-modules | nominal — packaging/lifecycle wrapper, not a security boundary | `k3s-*` |

The boundary strength is a *gradient set by the manifest*, from "full sandbox"
(empty manifest) to "packaging wrapper only" (k3s) — not a categorical
workload/infra split. See [permissions.md](permissions.md) for the full
permission surface and how each grant maps onto an nspawn flag.

The target sandbox from [../roles/targets-and-sandbox.md](../roles/targets-and-sandbox.md)
is unchanged as the *activation* mechanism: `aos-pkg-<name>.target` is still the one
switch, gated `*-modules`/`*-sysctl`/`*-firewall` oneshots are still members,
and the disabled case is still the strict guarantee. What this doc adds is one
more kind of member unit — the nspawn instance — that every package now carries.

## Permissions

The privilege a container holds is **not** baked into the unit by hand — it is
**generated from a declared, signed `[permissions]` manifest** on the package,
exactly like an Android/iOS app permission list. The default (empty manifest) is
a tightly-sandboxed container; a package gets only what it declares. Each grant
(`capabilities`, `network`, `devices`, `host-paths`, `cgroup-delegate`,
`privileged-users`, `kernel-modules`, `syscalls`, `security-label`) maps onto a
specific `systemd-nspawn` / unit knob. The full surface, the manifest examples
(including k3s's long list), and the honest host-level limits live in
[permissions.md](permissions.md). The nspawn-flag mechanics below are the *how*;
the manifest is the *what*.

## Substrate decision (RESOLVED — direction): per-unit default, nspawn deferred

The substrate decision is **resolved in direction** (Decision 17 in
[open-questions.md](open-questions.md)): **per-unit sandboxing is the default
materialization, and nspawn is deferred** — not built for MVP, reserved for a
future package that genuinely needs its own init tree. systemd offers this
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

Why this must be evaluated head-to-head before implementation:

- **The `[permissions]` manifest is substrate-independent.** Every manifest
  field maps onto a per-unit directive at least as cleanly as onto an nspawn
  flag (`capabilities`→`CapabilityBoundingSet=`/`AmbientCapabilities=`,
  `network`→`PrivateNetwork=`, `devices`→`DeviceAllow=`,
  `host-paths`→`BindPaths=`, `privileged-users`→`PrivateUsers=`,
  `syscalls`→`SystemCallFilter=`). The manifest is the architecture; nspawn is
  one possible materialization.
- **It dissolves the k3s `KillMode=process` regression** (see the k3s section
  below): a high-privilege package becomes a host unit with few restrictions,
  and non-disruptive restart keeps working.
- **It removes the second service manager** for single-unit packages: no
  in-container PID1, no `--notify=ready` proxying, no nspawn-in-VM nesting risk
  (Decision 4), no container-root image for single-binary packages. The
  "single-service root" strategy below is `RootImage=` with extra steps.
- **nspawn's remaining honest use case** is a package that needs its own
  multi-unit init tree — currently a set of approximately zero (k3s is one
  binary plus a preflight, both expressible as host units under the target).
- **Socket activation and verity favor it too** (verified, systemd 259):
  socket units with `PrivateNetwork=` + `JoinsNamespaceOf=` pass **named** fds
  natively into a sandboxed unit, while nspawn forwards `$LISTEN_FDS` only to
  a `--boot` init and drops fd names (`LISTEN_FDNAMES` forwarding is an open
  RFE, systemd#17764), needing `systemd-socket-proxyd` as a bridge. And
  `RootImage=` carries dm-verity natively (`RootHash=`, `RootVerity=`,
  `RootHashSignature=`, v246+) — signed container roots extending the registry
  trust chain to runtime integrity. The `RootImage=` + `DynamicUser=` +
  `PrivateUsers=` + `MountAPIVFS=` stack is upstream's own portable-services
  **default profile** — the flagship-supported composition, not an experiment.
  (Caveats: loop-device based, auto-adds `After=systemd-udevd.service` so not
  early-boot, and must not be combined with `PrivateDevices=yes`.)

Prior-art note: NixOS's declarative nspawn `containers.*` is the closest
precedent for "module system generates nspawn units," and it is widely
considered one of NixOS's weaker subsystems (machined coupling,
restart-on-switch semantics, networking friction); much of that ecosystem moved
to podman-systemd (quadlet) or per-unit hardening. The landing (Decision 17):
**per-unit sandboxing as the default materialization, nspawn deferred** until
a package genuinely needs an init tree. The MVP "container root" is simply a
**store path consumed via `RootDirectory=`** — no image build, no loop
device, no udev ordering (`CONFIG_DM_VERITY` is also absent from the AOS
kernel config today, so the verity-signed `RootImage=` upgrade is future work
behind a kernel-config change). The remaining spike is **validation, not
decision input**: materialize `test-http-server`'s empty manifest and k3s's
manifest as per-unit services and confirm teardown semantics and harness
cost. Everything below specifies the **deferred nspawn materialization** —
retained as the spec for if/when a package needs an init tree; the *boundary
semantics* (what an empty manifest isolates, what a grant opens) stand either
way.

## Feasibility baseline (from investigation)

`systemd-nspawn` **is built and shipped**. It is built unconditionally by
systemd, independent of the management daemons. The current systemd build,
however, disables the surrounding ecosystem — in `pkgs/system/systemd.nix`:

```nix
-Dmachined=false
-Dportabled=false
-Dimportd=disabled
```

Consequences (needs verification against the exact current flags in
`pkgs/system/systemd.nix`):

- **No `machined` / `machinectl`.** No machine registry, no
  `systemd-nspawn@.service` multiplexing via `machinectl`, no
  `nss-mymachines` `.host`/`.local` name resolution. We define **explicit
  units** instead of relying on `machinectl start`.
- **No `portabled`.** No portable services / sysext-confext install path. Not
  needed; container roots carry their own contents.
- **No `importd`.** No `systemd-pull` image fetch. Images come from the AOS
  store via `apm`, not from upstream OCI registries.

This shapes the design: we drive containers through **first-class systemd
template units**, not `machinectl`. systemd is 259.1, so the full
`--private-users`, `LoadCredential=`, `--volatile`, cgroup-delegation feature
set is present. The kernel ships `CONFIG_USER_NS`, `CONFIG_PID_NS`,
`CONFIG_NET_NS`, `CONFIG_IPC_NS`, `CONFIG_UTS_NS`, and mount namespaces, and
cgroup v2 — confirmed present for the VM test kernels; needs verification that
the production image kernel config matches.

## Per-package root image

A container root is just a **smaller, single-purpose rootfs** built with the
exact same machinery AOS already uses for the host image and VM test disks
(`lib/build/rootfs.nix`, `lib/build/closure-info.nix`). The investigation
proposes a sibling builder `lib/build/container-root.nix` (new, ~200 lines)
that mirrors `rootfs.nix`:

- `exportReferencesGraph` over the package's `rootPackages` discovers the
  closure (no host tools, sandbox-safe).
- The FHS skeleton (`/usr/{bin,lib,sbin}` real, `/bin`/`/sbin`/`/lib`
  symlinks, empty `/etc`, `/proc`, `/sys`, `/dev`, `/run`) is staged.
- Store closures are copied in; `/aos-registration` carries the closure-info
  stream so the in-container store is coherent.
- `fakeroot -- mkfs.ext4 -d rootfs … root.img` produces the image — **no
  losetup, no mount**, every file owned by uid/gid 0. This is the same
  sandbox-compatible path the host image uses.

Two PID1 strategies, chosen per package:

- **Single-service root** — `/init` is `exec`d straight to the one binary.
  Closure is minimal (binary + deps), startup is milliseconds. Good for
  sidecars and simple workloads.
- **systemd PID1 root** — `/init -> ${systemd}/lib/systemd/systemd`, with a
  minimal `/etc/systemd/system` carrying only the package's units and the
  targets to auto-start. Needed when the workload is several interdependent
  units. This is what a high-privilege package like k3s would use *inside* the
  container.

Image **format is ext4, not EROFS**, for container roots. ext4 mounts
read-write (we make it RO at runtime via nspawn instead), needs no
`mkcomposefs`/dump step, and is what `systemd-nspawn --image=` consumes
transparently. EROFS is reserved for the host `/etc` composefs path. (Needs
verification: whether we want EROFS roots later for compression on large
images.)

Where the image lives: `/var/lib/machines/<pkg>.img` (or
`/var/lib/aos-containers/`). `/var` is the writable persistent partition that
Ignition already creates, alongside `/var/log`, `/var/lib`, `/var/tmp`. The
store path itself (`/nix/store/…`) is **read-only composefs/EROFS** and cannot
hold a writable image, so the image is either copied to `/var` at install time
or the package's image-output store path is bind-mounted RO and overlaid (see
ephemeral overlay below).

## The `aos-package@.service` template

Because `machined` is off, we ship an explicit **template unit**,
`aos-package@.service` (instance `%i` = package name), rather than relying on
`systemd-nspawn@.service` + `machinectl`. A package's `aos-pkg-<name>.target`
`Wants=`/`PartOf=` its `aos-package@<pkg>.service` instance, exactly the way it
`Wants=` the `*-modules`/`*-sysctl` gated services today. Sketch (illustrative;
exact flags per package, **needs verification** of each against systemd 259.1):

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
fully honored — the package's container, like its gated oneshots, lives under
`aos.slice/aos-pkg-<name>.slice` (see §Composition below).

Per-package divergence (network mode, binds, capabilities, user-ns policy) is
supplied by a drop-in the package synthesizes —
`aos-package@<pkg>.service.d/10-<pkg>.conf` — so the template stays generic.
This mirrors how `render-role.nix` already synthesizes per-role units; the
container instance is one more synthesized member. Whether we prefer a template
with drop-ins or a fully-rendered concrete `aos-pkg-<name>-container.service` per
package is an open call — see [open-questions.md](open-questions.md).

## Namespaces

`systemd-nspawn` gives a default (empty-manifest) package its own:

| Namespace | Default (empty manifest) | Notes |
|---|---|---|
| PID | private | container has its own PID1 (`systemd` or the binary) |
| Mount | private | own `/`, `/etc`, `/tmp`; host store bind-mounted RO |
| Net | private (`--network-veth`) | veth pair to host; see networking below |
| IPC | private | no host SysV/POSIX IPC leakage |
| UTS | private | own hostname (`--machine=%i`) |
| User | `--private-users=pick` | maps container root → unprivileged host uid range |
| cgroup | delegated subtree | `Delegate=yes`, container manages its own children |

`--private-users` is the contentious one. For the **default** (no
`privileged-users` permission) it is the right choice: container-root maps to
`nobody`-class host uids, so a container escape lands as an unprivileged host
user. The cost is the usual user-ns friction — file ownership in the image must
be shifted (`-U`/`--private-users=pick` handle this via UID shifting), and some
`/dev` access patterns break. A package that declares `privileged-users` in its
manifest turns user-ns off (`--private-users=no`); k3s does (see below).

## Networking

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
  DNAT in the base table itself instead of using `--port=`.
- **`--network-zone=<zone>` (multi-container L2).** nspawn maintains a virtual
  zone hub so several containers share an isolated L2 without an external
  bridge. Available, less-documented; veth+managed-network is the more
  portable default.
- **`--network=host` (`network = "host"`).** No net isolation. This is what k3s
  declares and is a deliberate, manifest-visible downgrade — see below and
  [permissions.md](permissions.md).

## cgroup delegation

`Delegate=yes` on the nspawn service hands the container a delegated cgroup
subtree it can subdivide. This is the same mechanism k3s already relies on
today: `modules/roles/kubernetes/k3s-worker.nix` sets

```nix
serviceConfig = {
  Delegate = "yes";
  TasksMax = "infinity";
  LimitNOFILE = "1048576";
  TimeoutStartSec = "infinity";
};
```

For a package that declares `cgroup-delegate` the same keys go on
`aos-package@<pkg>.service`, and the container's PID1 manages workload cgroups
beneath the delegated root. Note `--keep-unit` is not an alternative but the
**default for every package** on this machined-less host (see the template
above): the container lives in the nspawn service's own cgroup under the
package slice, and nspawn creates a payload subcgroup beneath it (upstream
pairs this with `DelegateSubgroup=supervisor`, v254+ — adopt the same).

## Ephemeral overlay root (fs-revert)

`--volatile=overlay` mounts the package root image **read-only as the lower**
and a **tmpfs upper**, so all runtime writes land in tmpfs and **evaporate on
stop**. This gives us a cheap fs-revert for free: a workload container is born
from the pristine image every start, and tearing it down discards all
filesystem mutations. Persistent state is exactly and only what the package
**explicitly binds** from `/var` (e.g. `--bind=/var/lib/<pkg>:/data`). This is
the recommended default for stateless workloads.

Stateful packages that genuinely need an accumulating root use
`--directory=<extracted-root>` (writable) and own their snapshot/rollback story
— out of scope here, flagged in [open-questions.md](open-questions.md).

## Composition: packages that depend on each other

Cross-package structure follows one distinction and four rules, each grounded
in verified prior art.

**"Depends on" means two different things.**

1. **Closure dependencies** (the overwhelming majority): `runtimeDeps` on
   libraries and tools — zlib, iptables, even `pkgs.k3s`-the-payload. These
   are inert bytes that ride the Nix closure into the dependent's root
   image/`RootImage=`. Nix already composes these flatly and perfectly, and a
   payload being *also* installable as a service does not infect its
   dependents: B's binaries inside A's container run **as A**, under **A's**
   manifest.
2. **Service dependencies** (rare, explicit): A needs B *running* — a web app
   needs the database package up. These are **not** closure edges; they are
   orchestration edges between flat siblings.

**Rule 1 — permissions never flow along closure edges.** Grants attach to the
runtime context: the unit/container that executes code declares for all code
it executes, like a statically-linked Android app. The cautionary precedent is
exact: Android deprecated `sharedUserId` (API 29) because merged security
identities made permission grants non-deterministic and impossible to unwind.
No inheritance, no transitive union, ever.

**Rule 2 — service dependencies are flat sibling edges, declared by name.**
A package's `expose` block may declare `requires = ["b"]`
([authoring.md](authoring.md)); apm resolves it like any dependency and the
expose phase materializes `After=`/`Wants=` edges between the **targets**
(`aos-pkg-a.target` → `aos-pkg-b.target`). Honest gap: this is genuinely
**new resolver surface** — today's resolver
(`crates/aos-package/src/resolve.rs`) finds the root by name but walks
dependencies by store-path hash only; `PackageMeta` has no named dependencies
(Decision 18 in [open-questions.md](open-questions.md)). The supporting fact
is favorable: `apm install a b` already lands both in **one profile
generation**, so cross-package edges materialize atomically before the
generation switch. Keeping ordering edges is deliberate: snapd offers *no*
cross-snap ordering and its users hand-roll retry loops as a recurring,
documented pain point.

**Rule 3 — communication channels are declared on both sides.** B exposes a
socket/port; A declares the matching `host-paths` (unix socket dir) or network
reachability. Precedent: snapd's content interface (producer slot + consumer
plug + store-gated auto-connect) — coupling is capability-shaped and visible
in both manifests ([permissions.md](permissions.md)).

**Rule 4 — no nested containers.** Verified mechanism (v259):
nspawn-in-nspawn *works under nspawn's defaults* — the default capability set
includes `CAP_SYS_ADMIN`, and the seccomp allowlist includes `@mount`,
`clone`, `setns` — and **breaks precisely when capabilities are dropped**
(systemd#12798). So a default-deny (least-privilege) package can never host a
nested container; only a near-fully-privileged one can, which inverts the
sandbox. Upstream considers nesting expected-to-work but it is undocumented
and untested (doc+test PR systemd#34811, still draft). The one sanctioned
"nesting" — k3s spawning runc containers inside its nominal wrapper — is
possible only because k3s is effectively unconfined; it is the degenerate
case, not a pattern. Kubernetes reached the same conclusion: pods are a flat
container list, and ordered helpers became sidecars-as-init-containers rather
than nesting.

**Resource hierarchy lives in slices, not containers.** Every package's units
— the nspawn instance (or sandboxed host units) *and* its gated oneshots — run
under `aos.slice/aos-pkg-<name>.slice`. Slices carry resource control only (no
config, no privilege), give `systemd-cgtop` per-package accounting, and
replace what `machine.slice` would have provided with machined off. With
`--keep-unit` the unit's `Slice=` is fully honored (see the template above).

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
   imports to the store, and writes a profile generation. For a container
   package the package's image-output store path comes along in the closure;
   `apm` materializes/links `/var/lib/machines/<pkg>.img`. (This post-install
   image step is **not yet implemented** — `PackageMeta` in
   `crates/aos-package/src/types.rs` has no container/image field today; see
   [apm-integration.md](apm-integration.md).)
2. **Enable** — `systemctl preset aos-pkg-<name>.target` against the merged
   preset policy; at boot the every-boot `aos-preset.service` pass re-derives
   enablement for every unit (see [boot-activation.md](boot-activation.md)
   §3.2). The target `Wants=` the `aos-package@<pkg>` instance.
3. **Run** — `aos-package@<pkg>.service` `ExecStart`s nspawn; `Type=notify` +
   `--notify=ready` lets the container PID1 signal readiness.
4. **Stop** — `systemctl stop aos-pkg-<name>.target` → `PartOf` propagates to the
   nspawn instance → container PID1 gets `SIGRTMIN+3` (clean shutdown) → tmpfs
   upper discarded.

## Teardown semantics: what reverts, what does not

This refines the target-sandbox teardown table for the container case.

| Effect | On `stop aos-pkg-<name>.target` | Notes |
|---|---|---|
| Container filesystem writes | **reverted** | tmpfs upper of `--volatile=overlay` is discarded |
| Container processes | **reverted** | PID ns torn down with the leader |
| veth / host-side `.network` | **reverted** | nspawn removes the veth; host iface disappears |
| Firewall ports | **reverted** | `aos-pkg-<name>-firewall.service` `ExecStop` `nft delete element` |
| Explicitly-bound `/var/lib/<pkg>` state | **persists** | by design — that is what binds are for |
| Kernel modules (`aos-pkg-<name>-modules`) | **persists** | global, one-way; same caveat as today |
| sysctls (`aos-pkg-<name>-sysctl`) | **persists** | global, no saved prior value; same caveat |

So the container boundary *improves* revert for the workload's own fs and
processes (vs. a bare host service) but **does not change** the two
fundamentally-global caveats: **kernel modules and sysctls stay**. `kernel-modules`
is a host-fulfilled (allowlisted) permission — the host loads them and a
container cannot, so they persist one-way after stop (see
[permissions.md](permissions.md) for the allowlist + signing model). The strict
guarantee remains the
*disabled* (never-enabled) case, identical to
[../roles/targets-and-sandbox.md](../roles/targets-and-sandbox.md).

## Security / isolation

For a default (empty-manifest) package the boundary is real: separate
PID/mount/net/IPC/UTS namespaces, user-ns mapping container-root to an
unprivileged host range, a RO root with an ephemeral upper, a delegated (capped)
cgroup, and `nftables`-gated ports. Further hardening available but not yet
specified: `--system-call-filter` (seccomp), capability dropping
(`--drop-capability=`), `--read-only`, `ProtectKernelModules=` on the service.
These are honest TODOs, not claims.

Boundary strength is a *gradient set by the manifest* (see
[permissions.md](permissions.md)). It is **not** a security boundary for a
high-privilege package like k3s — once a package declares host network, broad
caps, and host paths, its container is a packaging/lifecycle wrapper, not a
sandbox — and we must not pretend otherwise. The value is that the privilege is
least-by-default, declared, signed, and visible in the manifest, not that
everything is isolated.

## The host→container PID1 credential boundary

Crossing config/secrets into the container's PID1 is **explicitly open** —
fully treated in [config.md](config.md); this section only states the boundary
mechanics, not a decision.

systemd's native path is `LoadCredential=`/`ImportCredential=`: the host unit
loads a credential, nspawn exposes it to the container PID1 under
`/run/credentials/<unit>/<name>` (tmpfs, `noexec`), and the container's units
re-import it. The mechanism exists in systemd 259.1. The blocker is that AOS has
**no credential backend** today — without a TPM/sealed/encrypted store,
`LoadCredential=/path` just reads plaintext from `/var`, which is no better than
a bind-mount. The known-working interim is the current k3s pattern: Ignition
writes an env file, the unit reads it via `EnvironmentFile=`, and for a
container we bind that path RO into the instance. **Do not settle this here** —
the decision, the option matrix, and the criteria live in [config.md](config.md).

## Honest caveat: k3s is a high-privilege container

k3s is still an nspawn container — but a **high-privilege** one whose manifest
declares away most of the boundary. Its container is *nominal*: a
packaging/lifecycle wrapper, not a security boundary. k3s must manage *host*
state, and every one of these grants is an explicit entry in its
`[permissions]` manifest (see [permissions.md](permissions.md)):

- **Kernel modules are global.** k3s declares `kernel-modules = ["br_netfilter",
  "vxlan", "ip_set"]` (in `modules/roles/kubernetes/k3s-worker.nix`). There is no
  per-container module namespace — these load into the host kernel via
  `aos-pkg-k3s-worker-modules.service` regardless of any container. The container
  cannot own them; this is a host-fulfilled, allowlisted permission (the host
  grants it only if the requested modules are allowlisted — see
  [permissions.md](permissions.md)).
- **Host network.** CNI/flannel program host routes, the host bridge, and
  host iptables/nftables. `--network-veth` would cut k3s off from the L2 it is
  supposed to manage, so it declares `network = "host"`.
- **Host cgroups.** kubelet manages host cgroups; it declares `cgroup-delegate`
  (`Delegate=yes`) plus, realistically, a near-flat `--keep-unit` placement.
- **Broad capabilities** (declared `capabilities`) and host `/sys`, `/proc`,
  `/var/lib/kubelet`, `/var/lib/rancher` (declared `host-paths`).

Wrapped in nspawn it is a **nominal** container — mount + UTS isolation only —
around a process with effectively full host privilege. The difference from the
old "k3s isn't really a container" framing is that the privilege is now
**visible in the manifest** rather than buried in the implementation. The unit
its manifest generates makes the privilege explicit and ugly (illustrative,
**needs verification** of the exact flag set):

```ini
[Service]
Type=notify
Delegate=yes
ExecStart=/usr/lib/systemd/systemd-nspawn \
  --machine=k3s \
  --image=/var/lib/machines/k3s.img \
  --network=host \
  --keep-unit \
  --register=no \
  --capability=all \
  --bind=/sys \
  --bind=/var/lib/rancher:/var/lib/rancher \
  --bind=/var/lib/kubelet:/var/lib/kubelet \
  --bind=/etc/rancher:/etc/rancher \
  --volatile=overlay \
  --notify=ready
```

`--network=host --capability=all --keep-unit` plus those host binds is "a
process running on the host wearing a container costume". The fs-revert benefit
shrinks to the parts of k3s's tree that are *not* host-bound (most of its real
state is bound out to `/var/lib/rancher` and `/var/lib/kubelet`, which persist).
The isolation benefit is near zero. The honest recommendation:

> **k3s is a high-privilege container** — like every package it gets an
> `aos-pkg-k3s-*.target` and an nspawn instance, but its `[permissions]`
> manifest declares host network, broad caps, cgroup-delegate, host-paths, and
> kernel-modules, so the container is a packaging/lifecycle wrapper, not a
> sandbox. It must be labelled as cosmetic isolation, not a security boundary —
> and now that labelling lives in the signed manifest, not in tribal knowledge.

### The `KillMode=process` regression (restart kills every pod)

The single biggest cost of wrapping k3s in nspawn, and it must not be glossed:
today's bare unit (`modules/roles/kubernetes/k3s-worker.nix`) sets
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
container model spans "full sandbox" (empty manifest) to "packaging wrapper"
(k3s), and the manifest is what places a package on it. See
[permissions.md](permissions.md) for the gradient and k3s's full (still
`needs verification`) permission set.

## Relation to the target-sandbox invariants

Nothing here weakens [../roles/targets-and-sandbox.md](../roles/targets-and-sandbox.md):

- **Single activation root** — still `aos-pkg-<name>.target`. The nspawn instance is
  `WantedBy=`/`PartOf=` the target, never `WantedBy=multi-user.target`
  directly. Invariant 1 holds.
- **No global side-channels** — modules/sysctl/firewall remain gated oneshots
  under the target. The container does not reintroduce drop-in scan dirs.
  Invariant 2 holds.
- **Containment edges** — the nspawn instance carries `PartOf=aos-pkg-<name>.target`
  like every other member. Invariant 3 holds.
- **One enable switch** — still exactly the target. How that switch is flipped
  is owned by [boot-activation.md](boot-activation.md) §3.2 (canonical:
  systemd presets — image `disable *`, Ignition-written host preset file, an
  every-boot `aos-preset.service` pass, `systemctl preset` for runtime
  installs) — the roles-era single Ignition `systemd.units[]` entry described
  in the precursor doc is superseded for packages. The container template and
  its drop-in ship inert in EROFS either way.

## Open items (carried to [open-questions.md](open-questions.md))

- **Decision 17: the substrate itself** — per-unit `RootImage=` sandboxing as
  the default materialization vs. nspawn everywhere (see "Substrate decision"
  above). Upstream of most items below.
- Template-with-drop-ins vs. fully-rendered per-package container unit.
  Prior art: quadlet (podman's systemd generator, the canonical
  container-under-systemd path) chose fully-rendered per-container units over
  template+drop-ins after per-instance divergence overwhelmed the template; our
  per-package divergence is the entire manifest, so the evidence points to
  fully-rendered.
- `PackageMeta`/registry schema extension for image + nspawn metadata (today:
  none; `crates/aos-package/src/types.rs`).
- Where the image is materialized and how `apm` links it into `/var/lib/machines`
  (post-install hook does not exist yet).
- `--private-users` policy (the `privileged-users` permission); UID-shift cost
  on first start.
- Production-kernel namespace/cgroup config verification.
- Stateful (`--directory=`) snapshot/rollback story.
- Whether to enable `machined` for `machinectl` introspection (current lean:
  no — explicit units, no magic).
- The whole config/credential delivery decision — [config.md](config.md).
