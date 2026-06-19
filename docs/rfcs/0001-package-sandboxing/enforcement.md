# Layered enforcement: the defense-in-depth stack

[permissions.md](permissions.md) defines *what* a package may do (the signed
manifest) and maps each field to a systemd unit directive. That mapping is one
enforcement layer — namespace/credential isolation. The state of the art
(Android, Fedora/RHEL) is **defense in depth**: namespaces *and* capabilities
*and* seccomp *and* a MAC layer *and* Landlock *and* (fleet-managed) eBPF-LSM,
so that defeating one layer still hits another. Under the
[budget mandate](implementation-plan.md#budget-mandate) AOS builds the full
stack, **all derived from the same manifest**. This doc is the implementer spec
for those layers.

Siblings: [permissions.md](permissions.md) · [container-model.md](container-model.md) ·
[attestation.md](attestation.md) · [implementation-plan.md](implementation-plan.md).

## The stack (every package, generated from its manifest)

| Layer | Mechanism | Scope | Derived from manifest field |
|---|---|---|---|
| 1. Namespaces + credentials | systemd `Private*`/`Protect*`/`RootImage=` | per-unit | `network`, `host-paths`, `privileged-users`, `devices` |
| 2. Capabilities | `CapabilityBoundingSet=`/`AmbientCapabilities=` | per-unit | `capabilities` |
| 3. Syscall surface | `SystemCallFilter=` (named `@`-groups) | per-thread | `syscalls` |
| 4. Object/path + TCP sandbox | **Landlock** ruleset | per-unit, **namespace-independent** | `host-paths`, `network` |
| 5. MAC | generated **SELinux/AppArmor** profile | system-wide, per-package domain | `security-label` (+ all of the above) |
| 6. Dynamic fleet policy | **eBPF-LSM** signed policy | system-wide, runtime-loadable | host/fleet policy ([permissions.md] tiers) |

Layers 1–3 exist in the current RFC. **Layers 4–6 are the additions.** Each is
*generated*, not hand-authored, so a package author still writes only the
manifest.

## Layer 4 — Landlock (the highest-value addition)

Landlock is an unprivileged, **stackable**, **irreversible**, `execve`-inherited
LSM that enforces object-level access (filesystem paths, TCP bind/connect ports)
**even when a namespace is shared**. That last property is why it matters here:
it is the layer that still holds for a **`sandboxed-with-holes`** package whose
namespace is intentionally porous (a granted `host-path`, a shared net ns). It is
default-on in Debian/Fedora/Ubuntu/Arch/RHEL 9.6+, and it is the exact defense
the XZ backdoor disabled — evidence it is worth enforcing.

**Mechanism (implementer detail).**

- The `expose` renderer emits `network-policy.json` alongside the unit artifact
  from the signed manifest: `tcp-bind` maps to
  `LANDLOCK_ACCESS_NET_BIND_TCP`, `tcp-connect` maps to
  `LANDLOCK_ACCESS_NET_CONNECT_TCP`, and the same port lists are copied into the
  eBPF policy contract. The host policy admits those grants explicitly via
  `[allow].tcp-bind` and `[allow].tcp-connect`; `host-paths` map to
  `LANDLOCK_ACCESS_FS_*` path rules. Non-root-equivalent services also get the
  default filesystem rules `--fs-ro / --fs-rw /tmp --fs-rw /var/tmp` plus
  writable `StateDirectory=` paths, evaluated after `RootDirectory=` and its
  package-private temp/state directories are in place.
  `apm` validates any artifact-carried `network-policy.json` against the
  admitted package metadata before attaching exposed units, so the JSON is not a
  second policy source. An **empty manifest yields no service-process TCP
  grants** and the default filesystem confinement. Host-owned socket activation
  units remain outside the wrapper, so `expose` and `apm` validate TCP
  `ListenStream=` ports against the socket capability / `tcp-bind` contract.
- **Apply point.** Landlock self-restriction runs in each service command's own
  process before `execve`. For TCP policy, the renderer prefixes every
  package-authored workload service exec directive (`ExecStart=`,
  `ExecStartPre=`, `ExecStartPost=`, `ExecReload=`, `ExecStop=`,
  `ExecStopPost=`, `ExecCondition=`) with the AOS-built `aos-landlock` wrapper,
  passing `--require-abi 4` plus the admitted `tcp-bind` / `tcp-connect` ports
  and filesystem path grants.
  The wrapper probes the kernel ABI, loads the Landlock ruleset, sets
  `no_new_privs`, and then `execve`s the real command. The Nix-built `aos`/`apm`
  wrapper exports the trusted helper path as `AOS_LANDLOCK_WRAPPER`; `apm`
  validates every workload service's wrapper identity and arguments against that
  exact path before attaching the unit artifact, while generated host-side
  side-effect units stay outside the wrapper. A future
  `LandlockPaths=`-style systemd directive can replace the wrapper only after it
  preserves the same fail-closed validation point.
- **ABI feature-detect, never hardcode.** Query
  `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`;
  generated package wrappers currently fail closed below ABI 4. ABI→kernel:
  v1/5.13 (fs), v2/5.19 (`FS_REFER`), v3/6.2 (`FS_TRUNCATE`), v4/6.7
  (`NET_BIND/CONNECT_TCP`), v5/6.10 (`FS_IOCTL_DEV`), v6/6.12 (`SCOPE_*`). AOS
  targets at least ABI 4 (network rules); `aos-landlock --print-abi` records
  the built kernel's max ABI in the `security-aos-landlock-fs` VM check.
- **Known limits (document, don't fight):** TCP-port granularity only (no
  UDP/raw/per-IP — those stay on the nftables/eBPF layer); does not restrict
  identity (combine with DAC/MAC); 16-layer stack cap; `IOCTL_DEV` covers only
  newly-opened device fds.

## Layer 5 — generated MAC (SELinux or AppArmor)

`security-label` is currently a manifest field with no enforced policy behind it.
The SOTA (Android per-app SELinux domains since API 28 + MLS categories for
per-UID isolation; RHEL/Fedora shipping comprehensive policy) is a MAC profile
*under* the namespace sandbox, so a namespace escape still hits a mandatory wall.

**Mechanism.** The renderer generates a **per-package MAC profile** from the
manifest: an AppArmor profile (simpler to generate; path-based, matches
`host-paths`) or an SELinux type+domain with MLS categories (stronger, matches
Android's per-app domain model). Default-deny; the granted permissions widen it.
The package's confinement label ([permissions.md](permissions.md)) and the MAC
profile are derived from the *same* manifest, so they cannot drift. Pick
AppArmor for MVP unless the kernel already ships an SELinux base policy; record
the choice in the Phase-9 spike. The profile name is `aos-pkg-<name>`; it is part
of the measured manifest digest ([attestation.md](attestation.md)). AOS currently
selects SELinux for generated package profiles because the kernel, systemd, dbus,
and SELinux policy toolchain already target that backend.

## Layer 6 — eBPF-LSM (fleet-managed dynamic policy)

A privileged, system-wide, **runtime-loadable** enforcement layer stacked on the
major MAC — the mechanism Cloudflare used to live-patch a namespace CVE and that
KubeArmor/Tetragon use for in-kernel enforcement at LSM hooks. For a fleet OS
with a signing registry this is a natural distinctive capability: **ship signed
BPF-LSM policies through the existing registry trust chain.**

**Mechanism.** A host policy artifact (the same `/etc/aos/policy.toml` plane,
[permissions.md](permissions.md) tiers) references signed BPF-LSM programs the
fleet loads to (a) live-patch a CVE-class behavior ahead of a kernel update, or
(b) add fleet-wide hardening (e.g. block unprivileged `unshare`) without
rebuilding the kernel or the major MAC. Requirements: `CONFIG_BPF_LSM=y`,
`CONFIG_BPF_EVENTS=y`, `CONFIG_FUNCTION_TRACER=y`,
`CONFIG_DYNAMIC_FTRACE=y`, `bpf` in the `lsm=` order, BTF
(`CONFIG_DEBUG_INFO_BTF` plus the AOS-built `pahole`/dwarves toolchain),
and privileged load. The function-tracing options are required because BPF-LSM
links attach through BPF trampolines.

The policy channel is part of signed package metadata, not an ad-hoc host file:
registry entries carrying BPF-LSM artifacts require `bpf-lsm-policy-v1`,
installed package metadata records the selected JSON policy, BPF object, and
program names, and `/etc/aos/policy.toml` selects exact
`[[ebpf-lsm.policies]]` by registry/package/version/artifact path. At boot,
`aos-ebpf-lsm-policies.service` prepares bpffs and runs
`apm _load-ebpf-lsm-policies --system`; during live package activation, APM loads
the same selected fleet policies before starting package targets. The loader
resolves artifacts only from installed, signed package metadata rooted in the
current system package generation, validates that the policy JSON matches the
host selector, invokes the AOS-built `aos-ebpf-lsm-policy` helper, and pins links
under `/sys/fs/bpf/aos/lsm`. The helper also verifies or mounts bpffs for direct
and live-reconcile invocations, treats an already complete pin set as
idempotently loaded, and never unlinks an existing durable pin during load.

This is **host/fleet policy, not per-package manifest** — it is the dynamic
counterpart to the static MAC of layer 5. The current seed policy proves the
channel and attach path; enforcement content remains fleet-authored.

## The systemd hardening baseline (apply to every generated workload service)

Beyond the manifest-derived directives, every workload service the renderer
emits carries the full consensus hardening set (what `systemd-analyze security`
rewards), unless a granted permission specifically requires relaxing one:

```
NoNewPrivileges=yes
ProtectSystem=strict            ProtectHome=yes
PrivateTmp=disconnected         PrivateDevices=yes
ProtectKernelTunables=yes       ProtectKernelModules=yes      ProtectKernelLogs=yes
ProtectControlGroups=private    ProtectClock=yes
ProtectProc=invisible           ProcSubset=pid
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6   # widened only if declared
RestrictNamespaces=yes          RestrictRealtime=yes          RestrictSUIDSGID=yes
LockPersonality=yes             MemoryDenyWriteExecute=yes    # relaxed for JIT runtimes
SystemCallFilter=@system-service   SystemCallErrorNumber=EPERM   SystemCallArchitectures=native
CapabilityBoundingSet=          # empty unless caps declared
DynamicUser=yes                 PrivateUsers=identity         # per-package UID identity (see below)
```

`PrivateDevices=` is relaxed only for declared device grants,
`ProtectProc=` / `ProcSubset=` are omitted for root-equivalent manifests,
`MemoryDenyWriteExecute=` is relaxed only for declared JIT runtimes (Java/Node);
`RestrictAddressFamilies=`/`PrivateNetwork=`/`CapabilityBoundingSet=` widen only
where the manifest grants it. The renderer computes the relaxations from the
manifest — the author never writes a directive by hand.

**Per-package UID identity.** Make `DynamicUser=yes` + `PrivateUsers=identity`
(systemd v257) the default so two sandboxed packages cannot touch each other's
state even via a shared host path — matching Android's foundational per-app-UID
isolation under the MAC domain.

## The CI gate (objective, per-package)

Gate every generated **workload service** on a
`systemd-analyze security --threshold=<N>` score in `checks.eval` using
`--offline`/`--root` review. A package whose workload manifest forces a worse
score than the gate allows **fails the build**. Generated host-side side-effect
services (`host-paths`, `modules`, `sysctl`, `firewall`, `netns`) are not
workload services; they stay outside the workload sandbox and are covered by
their explicit render checks and narrow generated commands. This is a concrete,
measurable SOTA bar enforced *per package*. The default gate uses the policy
threshold from [permissions.md](permissions.md), currently 5.5; k3s
(`unconfined`) is an explicit allowlisted exception, not a silent pass.

## Where each layer is enforced (summary)

- **Build time:** the renderer generates the unit directives, the Landlock
  ruleset, and the MAC profile from the manifest; `systemd-analyze` gates the
  score; the manifest digest (including the MAC profile name) is fixed for
  measurement ([attestation.md](attestation.md)).
- **Install time:** `apm` checks `manifest ∩ host policy`, materializes all
  layers, loads the MAC profile and any fleet BPF-LSM policy.
- **Runtime:** the kernel enforces namespaces + caps + seccomp + **Landlock** +
  **MAC** + **eBPF-LSM** simultaneously; a breach of any one still meets the
  others.
