# Package permissions — the declarative privilege manifest

Status: planning
Sibling docs: [README.md](README.md) · [container-model.md](container-model.md) ·
[apm-integration.md](apm-integration.md) · [boot-activation.md](boot-activation.md) ·
[config.md](config.md) · [migration.md](migration.md) ·
[open-questions.md](open-questions.md)

Summary: **every package is a systemd-nspawn container** — there is no
"workload vs. infrastructure" shape split. What differs between packages is
*privilege*, and privilege is a **declared, signed, auditable manifest** on the
package, exactly like an Android/iOS app's permission list. The default is a
tightly-sandboxed container; a package receives only the permissions it
declares. k3s is not a special case — it is a container that requests a long
permission list. This doc defines the permission surface, how it maps onto
systemd-nspawn, how it is generated/enforced, and the honest limits.

This supersedes the earlier two-shape model (see
[migration.md](migration.md)) and resolves Decision 1 in
[open-questions.md](open-questions.md) (the `workload` vs `infrastructure`
*class* split) and the `expose.kind = "container" | "host"` strawman in
[apm-integration.md](apm-integration.md): there is one shape (container) with a
permission gradient.

## Why a manifest

Two things fall out of making privilege declarative:

1. **Uniformity.** One shape, one lifecycle, one mental model. Every package is
   an nspawn container fronted by an `aos-pkg-<name>.target`
   (see [container-model.md](container-model.md)). k3s stops being a carve-out.
2. **Legibility.** You can ask a package *what it needs to run* before you
   install or enable it — `apm info <pkg> --permissions` — the way an app store
   shows permissions before install. A fleet policy can refuse a package that
   asks for more than allowed. The permission set is part of the package's
   **signed** metadata, so it cannot escalate after publish.

The reframe this forces (and it is a feature, not a fudge): the value is no
longer "everything is isolated." A maximally-privileged container is **not** a
security boundary. The value is that privilege is **least-by-default, declared,
signed, and enforceable** — a privileged package is still a container with a
manifest, just as a privileged Android app is still an app with a manifest.

## The permission surface

These map directly onto knobs systemd-nspawn / the generated scope already
expose. The manifest field is the package-facing name; the mechanism is what
the package module emits.

| Manifest field | systemd-nspawn / unit mechanism | Default | App-store analog |
|---|---|---|---|
| `capabilities` | `--capability=CAP_…` (`=all` for full) | none added | dangerous permissions |
| `network` | `private` = `--network-veth`/`--network-zone`; `host` = no `--private-network` | `private` | INTERNET / local network |
| `devices` | `--bind=/dev/…` + `--property=DeviceAllow=…` | none | camera / USB / sensors |
| `host-paths` | `--bind=` (rw) / `--bind-ro=` | none | scoped storage |
| `cgroup-delegate` | `--property=Delegate=yes` (+ controllers) | off | — (no analog) |
| `privileged-users` | `--private-users=no` (UID 0 == host UID 0) | userns on | "runs unsandboxed" |
| `kernel-modules` | host loads them — container cannot (see Limits) | none | system/OEM-level |
| `syscalls` | `--system-call-filter=` / named profile | default seccomp | — |
| `security-label` | SELinux/AppArmor context (`--selinux-context=`) | inherit | — |

`needs verification`: which of these the AOS systemd build's `systemd-nspawn`
actually supports end-to-end (the investigation found nspawn is shipped but
`machined`/`portabled`/`importd` are disabled — see
[open-questions.md](open-questions.md) Decision 7). cgroup-v2 delegation,
`--private-users` mapping, and custom seccomp profiles each need a feature
check on the built `systemd-nspawn`.

## Default-deny, least privilege

The baseline container, with an **empty** `[permissions]` block:

- private network namespace (veth into a host zone; only the ports the package
  declares are reachable, and they are container-local — firewall rules live in
  the container's own netns and revert on teardown);
- no added capabilities, default seccomp, user namespacing on;
- no host devices, no host bind mounts beyond the package's own state dir;
- ephemeral overlay root (filesystem writes revert on stop — see
  [container-model.md](container-model.md)).

A package gets *only* what it lists on top of that. So a plain workload package
is a genuine security boundary; k3s, having declared a long list, is not — and
that difference is visible in the manifest, not buried in the implementation.

## Manifest examples

A workload package — strong sandbox, declares almost nothing:

```toml
[permissions]
network = "private"          # veth; firewall is container-local, auto-reverts
# everything else defaulted: no caps, userns on, no host paths/devices
```

k3s — high privilege, every grant explicit:

```toml
[permissions]
network          = "host"     # k3s manages host networking + pod netns
privileged-users = true       # --private-users=no
cgroup-delegate  = true       # k3s manages pod cgroups
capabilities     = [
  "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_NET_RAW",
  "CAP_SYS_RESOURCE", "CAP_SYS_PTRACE", "CAP_SYS_MODULE?"  # see Limits
]
devices          = ["/dev/net/tun", "/dev/kmsg"]
host-paths       = [
  { path = "/var/lib/rancher", mode = "rw" },
]
kernel-modules   = ["br_netfilter", "vxlan", "ip_set"]   # host loads these
syscalls         = "relaxed"
```

`needs verification`: the exact capability/device/mount set k3s requires under
nspawn — the list above is a strawman derived from the known k3s-in-privileged-
container patterns (k3d, k3s-in-docker), not yet validated against a running
AOS nspawn k3s. k3s is the **proving case** for this whole model: if it runs,
the manifest schema is complete enough.

## From manifest to running container

The manifest is the single source of truth. The package module **generates**,
from it:

1. the nspawn launch unit `aos-pkg-<name>@.service` (or a concrete
   `aos-pkg-<name>.service`) with the corresponding `--capability=`,
   `--bind=`/`--bind-ro=`, `--network-*`, `--private-users=`,
   `--property=Delegate=`/`DeviceAllow=`, `--system-call-filter=` flags;
2. the host-side gated services for permissions that cannot live inside the
   container — today that is `aos-pkg-<name>-modules.service` (host `modprobe`
   of the declared `kernel-modules`), wired `WantedBy`/`PartOf` the package
   target like the other sandbox services in
   [container-model.md](container-model.md).

So `aos-pkg-<name>.target` `Wants=` both the nspawn instance and any host-side
permission services. Enabling the target grants exactly the declared
permission set; disabling it removes the container and the host-side grants
(modulo the one-way limits below).

## The two genuinely host-level permissions (honest limits)

1. **`kernel-modules`.** No container can load a kernel module — the kernel is
   shared. This permission is satisfied by the **host** loading the module
   (`aos-pkg-<name>-modules.service`), declared by the package but honored
   host-side. It is the one permission that is irreducibly host-level, and
   loaded modules persist after the package stops (global, one-way — same
   caveat as the gated-target sandbox).
2. **`network: host`.** Choosing host networking trades the network boundary
   away: the package's ports and firewall rules are host-level, and any netns it
   creates (k3s pods) lives in the host. The manifest makes that trade explicit
   rather than implicit. A `network: private` package keeps a real, auto-
   reverting network boundary.

Everything else (mounts, devices, caps, fs writes) is scoped to the container
and reverts on teardown — so the boundary strength is a *gradient set by the
manifest*, from "full sandbox" (empty manifest) to "packaging wrapper only"
(k3s).

## Introspection, policy, and signing (the app-store story)

- **Introspect before install/enable:** `apm info <pkg> --permissions` (and
  `aos describe <pkg>`) render the manifest — the permission prompt. This is
  the answer to "what does this package need to run?"
- **Policy gate:** a host/fleet policy can allow-list or cap permissions
  ("this fleet refuses `CAP_SYS_ADMIN`/`privileged-users` packages"), enforced
  at install or enable time. `needs verification`: where the policy lives and
  who enforces it (apm at install vs a boot-time admission check) — track as an
  open decision in [open-questions.md](open-questions.md).
- **Signed & immutable:** the permission manifest is part of the package's
  signed registry metadata (see [apm-integration.md](apm-integration.md) and
  the registry signing docs), so a package cannot widen its own privileges
  after publish; a privilege change is a new signed version.

## What this changes elsewhere

- [container-model.md](container-model.md): the "three shapes" table collapses
  to one shape (container) plus this permission gradient; k3s moves from "stays
  host-gated" to "high-privilege container."
- [apm-integration.md](apm-integration.md): `expose` no longer carries a
  `kind = container|host` field; instead every exposing package is a container
  and carries a `[permissions]` block.
- [open-questions.md](open-questions.md): Decision 1 (workload vs
  infrastructure class) is resolved by this manifest; the remaining open item is
  the *policy enforcement point* and the validated k3s permission set.

## Open questions

- The validated k3s permission set under AOS nspawn (the proving case).
- nspawn feature coverage in the AOS systemd build (cgroup-v2 delegation,
  `--private-users` mapping, custom seccomp) — Decision 7 in
  [open-questions.md](open-questions.md).
- Policy enforcement point and format (install-time vs boot admission).
- Whether `CAP_SYS_MODULE` is ever granted to a container or module loading is
  *always* host-side via `kernel-modules` (lean: always host-side).
- Config delivery into the container is a separate, still-open question — see
  [config.md](config.md) (do not assume credstore).
