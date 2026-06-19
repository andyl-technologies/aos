# Package permissions — the declarative privilege manifest

Status: planning
Sibling docs: [README.md](README.md) · [container-model.md](container-model.md) ·
[apm-integration.md](apm-integration.md) · [boot-activation.md](boot-activation.md) ·
[config.md](config.md) · [migration.md](migration.md) ·
[open-questions.md](open-questions.md)

Summary: **every package exposes a target plus generated systemd units** — there
is no "workload vs. infrastructure" shape split. What differs between packages
is *privilege*, and privilege is a **declared, signed, auditable manifest** on
the package, exactly like an Android/iOS app's permission list. The default is a
tightly-sandboxed per-unit service; a package receives only the permissions it
declares. k3s is not a special case — it is a high-privilege package that
requests a long permission list. This doc defines the permission surface, how it
maps onto systemd unit directives, how it is generated/enforced, and the honest
limits.

There is one package target shape with a permission gradient — not a
`workload` vs `infrastructure` *class* split, and not an
`expose.kind = "container" | "host"` distinction (see
[apm-integration.md](apm-integration.md) and Decision 1 in
[open-questions.md](open-questions.md)).

## Why a manifest

Two things fall out of making privilege declarative:

1. **Uniformity.** One target shape, one lifecycle, one mental model. Every
   service package is fronted by an `aos-pkg-<name>.target`
   (see [container-model.md](container-model.md)). k3s stops being a carve-out.
2. **Legibility.** You can ask a package *what it needs to run* before you
   install or enable it — `apm info <pkg> --permissions` — the way an app store
   shows permissions before install. A fleet policy can refuse a package that
   asks for more than allowed. The permission set is part of the package's
   **signed** metadata, so it cannot escalate after publish.

The reframe this forces (and it is a feature, not a fudge): the value is no
longer "everything is isolated." A maximally-privileged package is **not** a
security boundary. The value is that privilege is **least-by-default, declared,
signed, and enforceable** — a privileged package is still a package target with
a manifest, just as a privileged Android app is still an app with a manifest.

## The permission surface

One unifying rule governs every entry below:

> Every permission is **`requested by the package ∩ granted by host policy`**.
> Permissions differ only in *how* a grant is fulfilled — on the generated
> service sandbox (caps, seccomp, devices, mounts, netns) or by a **host-side
> action** (`modprobe` for `kernel-modules`; the host firewall for
> `network: host`).

So `kernel-modules` is not an exception to the model — it is a normal permission
whose grant happens to be fulfilled host-side. The package *declares* a request;
the host *grants* it only if policy allows; the difference is just the mechanism
that materializes the grant.

These map directly onto generated systemd unit directives. nspawn remains
documented as a future/alternate materialization, but the Phase 0 schema is
pinned against the per-unit substrate:

| Manifest field | Per-unit materialization | Default | App-store analog |
|---|---|---|---|
| `capabilities` | `CapabilityBoundingSet=` and `AmbientCapabilities=` | none added | dangerous permissions |
| `network` | `PrivateNetwork=` for `private`; `NetworkNamespacePath=` for `private-outbound`; neither for `host` | `private` | INTERNET / local network |
| `tcp-bind` / `tcp-connect` | Signed TCP port grants consumed by generated Landlock/eBPF policy | none | scoped network access |
| `devices` | `DevicePolicy=closed` plus `DeviceAllow=` entries | none | camera / USB / sensors |
| `host-paths` | `BindReadOnlyPaths=` for `mode = "read-only"`; `BindPaths=` for `mode = "rw"` | none | scoped storage |
| `cgroup-delegate` | `Delegate=` | off | — (no analog) |
| `privileged-users` | `PrivateUsers=` disabled when true; enabled otherwise | userns on | "runs unsandboxed" |
| `kernel-modules` | host-fulfilled: `aos-pkg-<name>-modules.service` `modprobe`s allowlisted modules (see Limits); never `CAP_SYS_MODULE` in the workload | none | system/OEM-level |
| `syscalls` | `SystemCallFilter=` using the named profiles `restricted`, `system-service`, or `privileged`, pinned to systemd syscall groups (`@system-service`, `@privileged`, …); never free-form filters | default seccomp | — |
| `security-label` | Generated SELinux/AppArmor profile name, `aos-pkg-<name>` by default, applied through the selected MAC backend | generated default-deny | — |

The per-unit MVP maps these permissions to systemd service directives and
host-side gated services. If the future nspawn substrate is reopened, it must
re-check cgroup-v2 delegation, `--private-users` mapping, and custom seccomp
support against the exact `systemd-nspawn` binary AOS ships.

## Layered enforcement (defense in depth)

The single-directive view above is the *floor*, not the ceiling. Under the
unlimited-engineering-budget mandate, each manifest field now maps onto
**multiple, independent enforcement layers** rather than one systemd directive.
The layers are stacked so that **defeating one still hits the next** — a
namespace escape lands inside a Landlock confinement; a Landlock bypass lands
inside the generated MAC profile; a MAC mislabel is still caught by the
eBPF-LSM observer. Every layer is derived from the *same* signed manifest, so
they cannot drift apart.

| Manifest field | Layer 1: namespaces + caps + seccomp | Layer 2: Landlock (namespace-independent) | Layer 3: generated MAC profile | Layer 4: eBPF-LSM |
|---|---|---|---|---|
| `host-paths` | `BindPaths=` / `--bind=`/`--bind-ro=` | Landlock filesystem rule (path + access bits) | path rule in `aos-pkg-<name>` profile | LSM hook observes/denies off-policy opens |
| `network` | `PrivateNetwork=` / `--private-network` | Landlock TCP bind/connect rules | network rules in `aos-pkg-<name>` profile | socket-hook coverage |
| `syscalls` | `SystemCallFilter=` (named profiles) | — | — | LSM backstop on filtered classes |
| `capabilities` | `CapabilityBoundingSet=` / `--capability=` | — | capability rules in `aos-pkg-<name>` profile | LSM cap-hook coverage |
| `devices` | `DeviceAllow=` / `--bind=/dev/…` | Landlock filesystem rule on the device node | device rules in `aos-pkg-<name>` profile | LSM hook coverage |
| `security-label` | (was inert — see below) | — | **the** generated `aos-pkg-<name>` SELinux/AppArmor profile | label-aware hooks |

The point is not that any single layer is perfect — it is that they are
**independent and overlapping**. Namespaces and capabilities are kernel
isolation; Landlock is a namespace-independent, unprivileged-sandbox
confinement that holds even when a package runs with `privileged-users` or
breaks out of its userns; the generated MAC profile is a default-deny policy
the kernel enforces regardless of namespace topology; the eBPF-LSM layer is the
last-resort observer/enforcer that catches anything the static layers missed.

> **Authoritative spec:** [enforcement.md](enforcement.md) is the normative
> definition of the layered stack — namespaces+caps+seccomp + Landlock +
> generated MAC profile + eBPF-LSM, all derived from the manifest. It also owns
> the **full systemd hardening baseline** every generated workload service
> inherits and the **per-package `systemd-analyze security --threshold` CI
> gate** that fails the build if a workload service's exposure score regresses.
> This doc defines the manifest and the field→layer mapping; `enforcement.md`
> defines how each layer is rendered.

### `security-label` is no longer an inert field

Previously `security-label` was just a field that set an nspawn SELinux/AppArmor
*context* with **no enforced policy behind it** — a label pointing at nothing.
That is gone. The renderer now **generates a default-deny SELinux/AppArmor
profile from the whole manifest**, named `aos-pkg-<name>`, following the Android
**per-app-domain** model: each package gets its own confinement domain, derived
from exactly the privileges it declared, denying everything else by default.
`host-paths`, `network`, `devices`, and `capabilities` each emit the
corresponding allow rules into that profile; everything not declared is denied.
So `security-label` stops being an unenforced annotation and becomes the name of
a real, generated, kernel-enforced MAC policy — the third layer of the stack
above. (Profile rendering details live in [enforcement.md](enforcement.md).)

## Default-deny, least privilege

The baseline generated service, with an **empty** `[permissions]` block:

- private network namespace; only the ports the package declares are reachable.
  Rules in the package netns revert on teardown by construction; reachability
  from off-host is materialized **host-side** by the gated
  `aos-pkg-<name>-firewall.service` — base-table set elements plus any needed
  DNAT/forwarding — and reverts via its `ExecStop`. See
  [container-model.md](container-model.md) §Networking.
- no added capabilities, default seccomp, user namespacing on;
- no host devices, no host bind mounts beyond the package's own state dir;
- immutable package root plus explicit writable state/scratch paths (filesystem
  writes outside those paths revert on stop — see
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
kernel-modules   = ["br_netfilter", "vxlan", "ip_set"]   # request; host loads iff allowlisted
syscalls         = "privileged"  # a named profile (pinned set of systemd syscall groups), not an adjective
```

The exact k3s permission set is validated under the per-unit package spike and
desk-checked against kind/k3d/Incus patterns. k3s remains the high-privilege
proving case for the manifest: if the generated unit matches the current k3s
unit shape while making its host grants explicit, the schema is complete enough.

## From manifest to running unit

The manifest is the single source of truth. The package module **generates**,
from it:

1. the launch unit `aos-pkg-<name>.service` with the corresponding
   `CapabilityBoundingSet=`, `BindPaths=`/`BindReadOnlyPaths=`,
   `PrivateNetwork=`, `PrivateUsers=`, `Delegate=`, `DeviceAllow=`, and
   `SystemCallFilter=` directives;
2. the host-side gated services for permissions that cannot be expressed solely
   on the workload unit — today that is `aos-pkg-<name>-modules.service` (host
   `modprobe` of the declared `kernel-modules`), wired `WantedBy`/`PartOf` the
   package target like the other sandbox services in
   [container-model.md](container-model.md).

So `aos-pkg-<name>.target` `Wants=` the generated workload service and any
host-side permission services. Enabling the target grants exactly the declared
permission set; disabling it stops the generated units and host-side grants
(modulo the one-way limits below).

> **Substrate-independent.** The manifest does not presuppose nspawn: under the
> per-unit substrate (Decision 17 in [open-questions.md](open-questions.md);
> "Substrate decision" in [container-model.md](container-model.md)) the same
> manifest generates `CapabilityBoundingSet=` / `PrivateNetwork=` /
> `DeviceAllow=` / `BindPaths=` / `PrivateUsers=` / `SystemCallFilter=`
> directives on a host unit instead of nspawn flags. The manifest is the
> architecture; the substrate is a materialization choice.

## The two host-fulfilled permissions (honest limits)

These two are **fulfilled host-side** rather than solely on the workload unit — but
they are *not* exceptions to the `request ∩ grant` model above. The package
still only *requests*; the host still decides whether to *grant*. The difference
is the mechanism, plus an honest one-way teardown caveat for modules.

1. **`kernel-modules`.** No sandboxed package can load a kernel module — the
   kernel is shared. The package **declares** `kernel-modules = [...]` as a *request*; the
   host **grants** it only if every requested module is in a host **allowlist**.
   A non-allowlisted module **fails admission with a clear message — exactly
   like a forbidden capability**. Granted modules are loaded host-side by
   `aos-pkg-<name>-modules.service` (gated by the package target). Two
   AOS-specific backstops make this the safest place such a grant could live:
   - **The module universe is bounded automatically.** A package *cannot ship* a
     module — that would be unsigned kernel code on an immutable, hermetic host —
     so the only modules that exist are the ones the host kernel was built with.
     The allowlist is therefore *at minimum* "modules this kernel has," and can
     be narrowed to a policy subset.
   - **The kernel is the ultimate backstop.** With module signing /
     `module.sig_enforce`, even a policy bug cannot load an arbitrary module. The
     chain is **package request → host allowlist → kernel signature enforcement**
     (defense in depth).

   Module loading is the **most dangerous** permission — it is kernel-level code
   execution — which is *why* it gets an explicit allowlisted, signature-backed
   grant rather than a quiet host action. The honest caveat remains: loaded
   modules **persist one-way** after the package stops (global — same caveat as
   the gated-target sandbox).
2. **`network: host`.** Choosing host networking trades the network boundary
   away: the package's ports and firewall rules are host-level, and any netns it
   creates (k3s pods) lives in the host. The grant is still host-fulfilled (the
   host firewall, not a container-local netns), and the manifest makes that trade
   explicit rather than implicit. A `network: private` package keeps a real,
   auto-reverting network boundary.

Everything else (mounts, devices, caps, fs writes) is scoped to the container
and reverts on teardown — so the boundary strength is a *gradient set by the
manifest*, from "full sandbox" (empty manifest) to "packaging wrapper only"
(k3s).

## Permissions and composition

Permissions **never flow along dependency edges**. A package's closure
dependencies (libraries, tools, even another service package's payload) run
inside *its* runtime context under *its* manifest — the unit/container that
executes code declares for all code it executes. There is no inheritance and
no transitive union: Android deprecated `sharedUserId` (API 29) precisely
because merged security identities made grants non-deterministic and
impossible to unwind. Cross-package coupling is instead an explicit,
two-sided channel — B exposes a socket/port, A declares the matching
`host-paths`/network grant — visible in both manifests (snapd's content
interface is the precedent). Full composition rules:
[container-model.md](container-model.md) §Composition.

## Introspection, policy, and signing (the app-store story)

- **Introspect before install/enable:** `apm info <pkg> --permissions` (and
  `aos describe <pkg>`) render the manifest — the permission prompt. This is
  the answer to "what does this package need to run?"
- **Computed confinement label:** above the itemized list, `apm info` renders a
  label **derived by fixed rules from the manifest** — `sandboxed` /
  `sandboxed-with-holes (<grants>)` / `unconfined` — never authored by the
  package. Root-equivalent grants force `unconfined`: `CAP_SYS_ADMIN` alone is
  root-equivalent (Kerrisk, "CAP_SYS_ADMIN: the new root", LWN 2012), as are
  `privileged-users` and rw `host-paths` into system locations. This is snap's
  `classic` confinement ("runs unsandboxed") and Android's protection levels:
  operators reason in tiers, and itemized lists alone over-communicate and
  under-inform — both developers over-request and reviewers cannot evaluate raw
  lists (Felt et al., "Android Permissions Demystified", CCS 2011). The label
  guarantees a k3s-shaped manifest can never present as sandboxed.
- **Attestable, not just introspectable:** the **signed manifest digest is
  measured into the TPM** (see [attestation.md](attestation.md)). A node's
  *declared + granted* privilege is hashed into a PCR at activation, so the
  confinement label is not merely something `apm info` can show — it becomes
  part of the node's **attested state**. A remote verifier can confirm that the
  privilege a node *actually* runs under matches the signed manifest it
  *claims*, closing the gap between "introspectable on the box" and "provable to
  a third party." Any post-publish privilege change is a new signed version with
  a new digest, which changes the measurement.
- **Policy gate:** a host/fleet policy can allow-list or cap permissions
  ("this fleet refuses `CAP_SYS_ADMIN`/`privileged-users` packages"). The
  enforcement model — who decides, when, and how it is mechanically guaranteed —
  is the next section. The primary policy surface is a small set of
  **named tiers** (`restricted`/`baseline`/`privileged`), with per-permission
  allowlists as the escape hatch: Kubernetes removed knob-level
  PodSecurityPolicy in favor of exactly three named Pod Security Standards
  because per-knob policy proved unwritable and unauditable, and systemd
  portable services ship four named profiles for the same reason. The host file
  is `/etc/aos/policy.toml`, parsed by `crates/aos-package/src/policy.rs`:

  ```toml
  tier = "baseline"
  kernel-modules = ["br_netfilter"]
  systemd-security-threshold = 5.5

  [allow]
  networks = ["private-outbound"]
  capabilities = ["CAP_NET_BIND_SERVICE"]
  devices = ["/dev/net/tun"]
  host-paths = [{ path = "/var/lib/rancher", mode = "rw" }]
  cgroup-delegate = false
  privileged-users = false
  syscall-profiles = ["system-service"]
  security-labels = ["aos-pkg-k3s"]
  ```
- **Signed & immutable:** the permission manifest is part of the package's
  signed registry metadata (see [apm-integration.md](apm-integration.md) and
  the registry signing docs), so a package cannot widen its own privileges
  after publish; a privilege change is a new signed version.

## Enforcement: package / registry / system

The manifest is enforced by **defense in depth across three layers, each making
a different decision**. The phone analogy is exact: an app *declares* permissions
in its manifest, the app store *reviews and signs* it, and your *device + its
policy* actually grant or deny at install/run.

| Layer | Decision it makes | What it can / cannot know | Phone analog |
|---|---|---|---|
| **Package** | **Declares** what it needs — a signed claim, immutable post-publish. **Not a grant.** | Knows its own needs; knows nothing about any host's policy. | the manifest in the APK |
| **Registry** | **Publication policy + trust anchor.** Gates what may be distributed; **binds the manifest to the artifact and signs it** so a host can trust the declaration is authentic. | Cannot know any host's local policy. | app-store review + app signing |
| **System / host** | **The authoritative grant.** Checks the signed manifest against *this* host's/fleet's local policy (allowlists, caps, the module allowlist) and grants or denies. | The only layer that can actually constrain what runs — because only it knows its own policy. | the OS + device policy/MDM + user consent |

Two properties make this robust:

1. **Enforcement is mechanical, not trust-based.** The host **materializes
   exactly the granted set**: the generated unit contains *only* the directives
   for granted permissions, and `aos-pkg-<name>-modules.service` loads *only*
   allowlisted modules. A package that declared more than was granted simply runs
   with less — the surplus is never put in the unit. Even a policy-check bug
   cannot over-grant beyond what the host materializes, and the
   kernel/signature layer backstops modules.
2. **The registry signature is the trust anchor that makes host enforcement
   meaningful.** Without it, a package could lie about its permissions to slip
   past host policy. Registry signing is **not** policy enforcement — it is what
   lets host enforcement *be trusted*.

**Timing.** Host policy is checked at **install/enable** (apm refuses to install
or enable a package whose manifest exceeds host policy). The **materialization**
— unit generation plus the gated modules service — is the *actual* enforcement,
and it is re-derived from the granted set on every generation. This resolves the
earlier "install-time vs boot-time admission" question: **policy-checked at
install, mechanically enforced by what gets generated, kernel-backstopped for
modules** (see [open-questions.md](open-questions.md) Decision 1).

## What this changes elsewhere

- [container-model.md](container-model.md): the "three shapes" table collapses
  to one package target shape plus this permission gradient; k3s moves from
  "stays host-gated" to "high-privilege package."
- [apm-integration.md](apm-integration.md): `expose` no longer carries a
  `kind = container|host` field; instead every exposing package is a target plus
  generated units and carries a `[permissions]` block.
- [open-questions.md](open-questions.md): Decision 1 (workload vs
  infrastructure class) is resolved by this manifest; the *policy enforcement
  point* is now answered by the Enforcement section above (three-layer,
  system/host authoritative, mechanical materialization, registry-signed trust
  anchor, checked at install/enable). The remaining proving-case item is the
  validated k3s permission set.

## Open questions

- The validated k3s permission set under AOS nspawn (the proving case) —
  desk-check it first against the documented k8s-in-container requirement sets
  (kind: private cgroupns, `/dev/fuse`, `/lib/modules` ro-bind; k3d:
  `--privileged`; Incus "k8s in LXD": `/dev/kmsg`, pre-loaded `br_netfilter`).
  The current strawman is likely missing `/lib/modules` (ro) and `/dev/fuse`.
- The substrate (Decision 17 in [open-questions.md](open-questions.md)): the
  manifest is substrate-independent, and several nspawn-specific rows above
  become per-unit directives if the per-unit substrate wins.
- nspawn feature coverage in the AOS systemd build (cgroup-v2 delegation,
  `--private-users` mapping, custom seccomp) — Decision 7 in
  [open-questions.md](open-questions.md).
- The k3s `kernel-modules` allowlist is still a concrete host-policy value to
  validate in Phase 3, but the file format and allowlist location are resolved:
  `/etc/aos/policy.toml`.
- Config delivery is layered — see [config.md](config.md): TPM2-sealed
  credentials for secrets, schema-validated apm artifacts for structured config,
  and `EnvironmentFile=` for simple config.
