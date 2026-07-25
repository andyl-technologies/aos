# Packages: open questions, risks & decisions

Status: planning
Audience: anyone planning the package model, the package execution substrate,
apm/registry integration, or the boot-time activation path
(`modules/roles/`, `crates/aos-package/`, `modules/services/ignition.nix`,
`lib/testing/`, `pkgs/system/systemd.nix`).

This is the "what we must decide" doc for the packages direction: every unit of
software AOS runs is a registry-installable **package** (`apm install`), and
**every** package exposes an `aos-pkg-<pkg>.target` handle plus generated
systemd units, with its privilege declared in a signed `[permissions]` manifest
(see [permissions.md](permissions.md)). Per-unit sandboxing is the default
substrate; nspawn is skipped for the MVP. It collects the open risks,
unknowns, and pending decisions surfaced across the investigation. Each entry has
a statement, why it matters, the options, and a disposition. Sibling docs:
[README.md](README.md), [permissions.md](permissions.md),
[container-model.md](container-model.md),
[apm-integration.md](apm-integration.md), [boot-activation.md](boot-activation.md),
[config.md](config.md), [migration.md](migration.md), [activation.md](activation.md).

A quick note on honesty up front: k3s does **not** fit a low-privilege workload
shape. It declares host network, host cgroups, host paths, and globally-loaded
kernel modules in its manifest, so its privilege is now *visible in the
manifest* instead of hidden in bespoke role code. Config delivery is also
intentionally layered rather than universal: secrets use TPM2-sealed systemd
credentials, structured config uses apm artifacts, and simple/non-secret config
uses `EnvironmentFile=` plus Ignition files.

---

## How to read this

Each decision is tagged with a rough disposition:

- **DECIDE-BEFORE-MVP** — blocks a first working service package.
- **DECIDE-EARLY** — shapes the schema/API; expensive to change later.
- **DEFER** — can ship a placeholder and revisit; must be explicitly tracked.

Owners are roles, not people: *packages-core* (the module synthesis),
*apm* (`crates/aos-package/`), *boot* (`modules/services/ignition.nix`),
*test-infra* (`lib/testing/`), *pkgs* (`pkgs/system/systemd.nix`,
package-root builders).

---

## 1. Package privilege model — RESOLVED (unified target + `[permissions]` manifest)

> **Resolved.** The earlier proposal here — introduce a package **class**
> distinction (`workload` vs. `infrastructure`) — is **superseded** by the
> unified model in [permissions.md](permissions.md): every service package has a
> target plus generated systemd units, and privilege is a declared, signed
> `[permissions]` manifest (Android/iOS app-permission analogy), not a
> two-valued class. The default (empty manifest) is a tightly-sandboxed per-unit
> service; a package gets only what it declares. k3s is not a special case — it
> is a high-privilege **package** that declares a long permission list (host
> network, privileged-users,
> cgroup-delegate, broad capabilities, devices, host-paths, kernel-modules). Its
> container is honestly "a packaging/lifecycle wrapper, not a security boundary,"
> but that privilege is now *visible in the manifest*. This also retires the
> `expose.kind = "container" | "host"` strawman in
> [apm-integration.md](apm-integration.md).

The honesty question that motivated the old framing still stands and is answered
the same way — k3s needs the host network namespace (CNI configures host
routes/bridge, flannel VXLAN on port 8472), the host cgroup hierarchy (kubelet
already declares `Delegate=yes`/`TasksMax=infinity`), full iptables/nftables
control, and globally-loaded kernel modules (`br_netfilter`, `vxlan`, `ip_set`).
Describing that as "isolated" would mislead operators. The difference is that the
manifest *records* the trade rather than burying it in a class label.

Both sub-questions that shaped the old split are resolved under the current
model:

**(a) Policy enforcement point — ANSWERED (see
[permissions.md](permissions.md) §"Enforcement: package / registry / system").**
Enforcement is **defense in depth across three layers**: the **package**
*declares* (a signed, immutable claim — not a grant); the **registry** is the
*publication policy + trust anchor* (binds and signs the manifest so a host can
trust it, but cannot know any host's local policy); the **system/host** is the
**authoritative grant** (checks the signed manifest against this host's/fleet's
local policy — allowlists, caps, the module allowlist — and grants or denies). It
is the only layer that can constrain what runs, because only it knows its own
policy. The "install-time vs boot-time admission" tension is resolved:
**policy-checked at install/enable** (apm refuses a package whose manifest
exceeds host policy), but the **actual enforcement is mechanical
materialization** — the generated unit contains only the directives for granted
permissions and `aos-pkg-<pkg>-modules.service` loads only allowlisted modules,
re-derived from the granted set each generation, with the kernel/signature layer
backstopping modules. A package that declared more than granted simply runs with
less. The policy file format and host allowlist location are pinned:
`/etc/aos/policy.toml` carries a named tier plus optional per-permission
overrides, the `kernel-modules` allowlist, and per-tier
`systemd-analyze security` thresholds. Prior-art constraint for that decision:
the primary policy surface should be a small set of **named tiers**
(`restricted`/`baseline`/`privileged`), with per-permission allowlists as the
escape hatch — Kubernetes removed knob-level PodSecurityPolicy in favor of
exactly three named Pod Security Standards because per-knob policy proved
unwritable and unauditable, and systemd portable services ship four named
profiles for the same reason. The policy file is shipped in the image EROFS as
the fleet default and overridable per host by an Ignition-written copy in a
higher overlay layer (the same precedence model as presets); `apm` evaluates it
at install/enable. Nix-evaluated policy is rejected (not available at runtime
install — the [authoring.md](authoring.md) forcing function); a signed
fleet-policy document can layer on later without changing the format.
**RESOLVED.** *packages-core* + *apm* + *boot*.

**(b) The validated k3s permission set under AOS per-unit sandboxing.** The
manifest in [permissions.md](permissions.md) is derived from the existing k3s
unit shape and the kind/k3d/Incus requirement sets, then validated by the P3
per-unit spike. k3s materializes as a host unit — today's working unit shape,
`KillMode=process` preserved — whose manifest *documents* its privilege rather
than constructing an nspawn wrapper. The package spike includes `/lib/modules`
(read-only), `/dev/fuse`, `/dev/kmsg`, host networking, cgroup delegation, and
the host-fulfilled `br_netfilter` / `vxlan` / `ip_set` module loads.
**RESOLVED.** *pkgs* + *test-infra*.

---

## 2. Kernel modules are global — there is no per-package module namespace

**Statement.** k3s needs `br_netfilter`, `vxlan`, `ip_set`. Kernel modules load
into the single host kernel; package services inherit them and cannot scope them. These
load via a synthesized `aos-pkg-<pkg>-modules.service` (`modprobe -a …`) gated by
the package target ([activation.md](activation.md)).

**Why it matters.** It undercuts the "package is self-contained" story: enabling
a package mutates global kernel state that does not cleanly reverse (the teardown
trade-off — modules stay loaded after `systemctl stop`). For a containerized
workload this is a leak out of the sandbox.

**Options.**
- Keep module loading host-side, gated by the package target (current design).
  Honest, simple, one-way on stop.
- Treat `kernel-modules` as a normal **allowlisted** permission (see
  [permissions.md](permissions.md)): a package *requests* it, and the host
  *grants* it only if every requested module is in a host **allowlist** —
  otherwise admission fails with a clear message, exactly like a forbidden
  capability. It is *host-fulfilled* (loaded via `aos-pkg-<pkg>-modules.service`),
  but no longer an "exception" to the `request ∩ grant` model.

**Why this is safe in AOS (defense in depth).** Two backstops bound the risk:
(1) the module **universe is bounded automatically** — a package cannot *ship* a
module (unsigned kernel code on an immutable, hermetic host), so the only modules
that exist are those the host kernel was built with; the allowlist is at minimum
"modules this kernel has," narrowable to a policy subset. (2) The **kernel is the
ultimate backstop** — with module signing / `module.sig_enforce`, even a policy
bug cannot load an arbitrary module. The chain is **package request → host
allowlist → kernel signature enforcement**. Module loading is the *most
dangerous* permission (kernel-level code execution), which is *why* it gets an
explicit allowlisted, signature-backed grant.

**Resolution.** `kernel.modules` is modeled as the allowlisted
`kernel-modules` permission in the `[permissions]` manifest: host-fulfilled,
gated by the package target, admission-checked against the host allowlist in
`/etc/aos/policy.toml`, and kernel-signature backstopped. Loaded modules remain
non-reversible after package stop.

---

## 3. Package networking model — RESOLVED (direction, under Decision 17)

> **Resolved (direction).** The `network` permission materializes as:
> **inbound-only private** (default) — host-owned socket units pass named fds
> into the sandboxed `PrivateNetwork=` unit while the socket stays in the host
> namespace, with no ambient host-network access beyond passed activation fds;
> **private with
> outbound** — a gated `aos-pkg-<n>-netns.service` oneshot creates a named
> netns + veth pair (host side managed by systemd-networkd; `CONFIG_VETH=y`
> confirmed in the kernel config) and the workload unit joins via
> `NetworkNamespacePath=/run/netns/aos-pkg-<n>` — the one place per-unit is
> more plumbing than nspawn's `--network-veth`, validated by the Decision 17
> spike; **host** — k3s and peers, per their manifest. Zone-style multi-package
> L2 is deferred until a real need appears.

**Statement.** AOS already runs systemd-networkd + systemd-resolved. Sandboxed
package services want a private network namespace with explicit inbound/outbound
grants; k3s wants host networking (Decision 1). The skipped nspawn substrate
would have offered `--network-veth`, `--network-zone`,
`--network-namespace-path`, and `--network=host`; the per-unit substrate
materializes the same manifest semantics through systemd service directives and
host-side gated helper units.

**Why it matters.** Private outbound networking requires host-side `.network`
files or equivalent setup, firewall coordination with the base nftables sets,
and possibly DHCP/static addressing inside the package netns. Cross-package and
package-host reachability in test L2 is fiddly (the k3s fleet test already pins
`node-ip`/`flannel-iface` to work around a missing default route).
`nss-mymachines` is **not** shipped, so there is no machine-name DNS substrate to
lean on if nspawn returns.

**Options.**
- Workload default `--network-veth` + a generated host `.network`; firewall
  ports flow through the existing `aos-pkg-<pkg>-firewall.service` against the
  base `allowed_tcp`/`allowed_udp` sets (plus the `--port=`/DNAT forward for
  off-host reachability — see [container-model.md](container-model.md)
  §Networking).
- `--network-zone` for multi-container L2 (less documented; revisit if needed).
- `--network=host` only for infrastructure packages.

**Resolution.** The schema names socket activation / private netns+veth /
host-network modes; the host `.network` and nftables pieces are generated from
the package definition. Host-net is reserved for infrastructure packages such as
k3s. Multi-container L2 zones stay out of the MVP until a real consumer appears.

---

## 4. nspawn inside test VMs — feasibility (mostly mooted by Decision 17)

> **Mostly mooted.** With nspawn skipped (Decision 17), no nesting runs in
> MVP test VMs. What remains for *test-infra*: a per-unit-sandbox lifecycle
> test (`RootDirectory=` + `PrivateUsers=` + `PrivateNetwork=` inside the VM
> harness) — strictly simpler, no nested service manager. Loop devices are
> available in guests if `RootImage=` is ever exercised
> (`CONFIG_BLK_DEV_LOOP=y`, udevd shipped and running).

**Statement.** Future nspawn tests, if that path is reopened, must run inside
the existing harnesses (`lib/testing/vm.nix`, `firecracker.nix`, `fleet.nix`).
The guest kernel has the needed namespace configs and ships systemd-nspawn;
nesting (systemd → nspawn → systemd) is expected to work.

**Why it matters.** If the future nspawn path is reopened, nspawn-in-VM
flake would make that substrate's tests flaky. Known risk areas: cgroup-v2
delegation depth, writable `/proc/sys` for container init, `/dev` population,
and the fact that **machined is disabled** (see Decision 7) so
`machinectl`-based introspection (`vm.exec_in_container`, `vm.container_status`)
needs an alternative. Verified for v259: every future generated nspawn unit must
use `--keep-unit --register=no` — privileged registration failure is **fatal**
without machined, and without `--keep-unit` nspawn allocates its own scope under
`machine.slice` via PID 1 *even with* `--register=no`, escaping the package's
slice (see the corrected template in
[container-model.md](container-model.md)).

**Options.**
- Drive containers purely via `systemctl` + explicit nspawn units, parse
  `systemctl show --json`; avoid `machinectl` entirely.
- Re-enable machined in the test image only (divergence from production — risky).

**Resolution.** The nspawn-in-VM test is mooted for the MVP. The remaining
lifecycle coverage is the per-unit VM test path, with introspection through
`systemctl` / `systemd-run` / `nsenter` rather than `machinectl`.

---

## 5. Package roots and RootImage — RESOLVED

> **Resolved.** Store-path-in-closure, consumed via `RootDirectory=`, remains the
> default package root shape: it inherits NAR hashing, the registry
> tag-signature chain, and gc-rooting with zero new machinery, and needs no
> image build, loop device, or udev ordering. The stronger verity-signed
> `RootImage=` path also landed for packages that declare signed
> `expose.images[]` metadata: the builder emits `root.img`, `root.verity`,
> `root.roothash`, and `root.roothash.p7s`, while the kernel config enables the
> dm-verity platform-keyring checks.

**Statement.** AOS now builds per-package roots as store paths. The implemented
builder, [`lib/build/package-root-image.nix`](../../../lib/build/package-root-image.nix),
reuses the rootfs pattern (`mkfs.ext4 -d`, `fakeroot`, closure discovery via
`exportReferencesGraph`) to emit a minimal ext4 image plus its verity tuple.
There is still **no OCI format** in the pipeline.

**Why it matters.** This is build surface and a registry artifact. The registry
ships package closures as NARs (`crates/aos-package/`); a package root is an
additional artifact that must be fetched, verified, rooted in the package
generation, and consumed by `RootImage=`/`RootDirectory=`. The resolved
`RootImage=` path signs the dm-verity root hash and validates it against the
platform keyring, closing the unsigned-root trust gap.

**Options.**
- Ship the package root as a normal store path inside the package closure →
  it inherits NAR hashing + the registry signing chain for free; the generated
  service consumes the store-path rootfs with `RootDirectory=`. (Most hermetic;
  aligns with "verify it exists in the closure".)
- Ship a separate verity-signed package-root image through `expose.images[]`
  with the existing narinfo/signature chain plus `RootImage=` runtime
  verification.
- Bake the package root into the host image for infrastructure packages
  (no runtime fetch; bloats image — see Decision 6).

**Baked-vs-fetched trust split-brain.** Per
[apm-integration.md](apm-integration.md) §7, the two delivery models have *two
different roots of trust*: a **fetched** package root is covered by the
registry tag signature + NAR hash, while a **host-image-baked** root never
transits the registry and is covered only by the host image's own integrity
(UKI / system closure). Mixing baked and fetched roots for the *same* package
across a fleet yields a split trust story (image-signed vs. tag-signed). The
recommendation is **fetch-at-boot via apm as the default**; if a deployment
bakes a root, the per-package choice must be documented explicitly (ties to
Decision 6's bake-vs-fetch).

**Resolution.** The default package root is a store path consumed via
`RootDirectory=`, so ordinary package roots inherit existing NAR signing and
registry metadata. The stronger signed `RootImage=` path is in P9 with
dm-verity, PCR measurement, and attestation-binding of the package manifest to
the package root.

---

## 6. Image size & closure growth — RESOLVED by Decision 5

> **Resolved.** With package roots as ordinary closure members, bake-vs-fetch
> is just "is the package in the system closure or apm-fetched" — the
> standing default holds: fetch-at-boot for workloads, bake k3s and other
> infrastructure. No separate sizing model; quantify the closure delta once a
> real workload package exists.

**Statement.** Per the investigation, the host rootfs closure is ~800 MiB–1.2 GiB
uncompressed (~400–600 MiB shrunk). A k3s package root is ~200–300 MiB
(k3s + containerd + runc + cni-plugins), with coreutils/bash deduped against the
host closure.

**Why it matters.** If package roots are **baked into the host image**
(Decision 5 Option 3), every host carries them whether or not the package is
enabled — directly contradicting "installed at boot via apm." If fetched at
boot, we trade image size for a network/registry dependency and first-boot
latency.

**Options.**
- Fetch package roots at boot via apm (keeps host image lean; needs network +
  registry reachability — conflicts with air-gapped).
- Bake only a small set of "always-on" infrastructure roots; fetch the rest.
- Store-path-in-closure (Decision 5 Option 1) makes "fetch" just a normal apm
  install — no separate sizing model.

**Resolution.** The default is ordinary apm delivery; baked packages are an
explicit image input and are seeded into the package profile before install-time
reconciliation. The package manifest records the delivery and enablement shape.

---

## 7. machined / portabled / importd are disabled by design — RESOLVED (stay disabled)

> **Resolved.** Keep all three disabled. The per-unit substrate (Decision 17)
> needs none of them; the future nspawn path, if it ever materializes, uses
> explicit units with `--keep-unit --register=no` (Decision 4 note,
> [container-model.md](container-model.md) template).

**Statement.** `pkgs/system/systemd.nix` sets `-Dmachined=false`,
`-Dportabled=false`, `-Dimportd=disabled`. systemd-nspawn itself **is** shipped.

**Why it matters.** No `machinectl` (no machine registry, no enumeration, no
`machinectl shell`), no portable services / sysext-confext, no `systemd-pull`
image import, no `nss-mymachines`. Every container must be an **explicit**
`systemd-nspawn` unit, lifecycle is `systemctl`-only, and test introspection
(Decision 4) and name resolution (Decision 3) need non-machinectl paths.

**Options.**
- Keep all three disabled; manage containers via explicit units + `systemctl`
  (aligns with AOS "explicit > magic"). Accept the extra unit boilerplate.
- Enable machined to regain `machinectl`/`nss-mymachines`. Adds a daemon and
  diverges from the current minimal build; weigh against the package model not
  actually needing it.

**Resolution.** Keep all three disabled. Lifecycle and introspection use
`systemctl` and explicit units; no MVP feature depends on `machinectl`.

---

## 8. Install-at-boot: apm packages via Ignition

**Statement.** Ignition's `aos-seed-profiles` service
(`modules/services/ignition.nix`) seeds the **system** profile
(`/var/lib/profiles/system/`) for the baked toplevel. Runtime package
generations live separately under `/var/lib/profiles/system-packages/`. Ignition
lists desired packages + registry config, then `aos-install-packages.service`
runs after profile seeding and reconciles the desired package set.

**Why it matters.** This is the load-bearing new boot step. It must order after
the writable nix overlay (`nix-overlay-setup`), after `aos-seed-profiles`
(state.json exists), optionally after `network-online.target`, and run
**once** (idempotency tracked in state.json so upgrades don't re-install). It
introduces first-boot network dependence and apm-lock contention, and the
installed unit closures must be validated so a bad fetch doesn't wedge boot.

**Options.**
- New `aos-install-packages.service` reading a desired-packages list +
  registry/key config laid down by Ignition `storage.files`
  (e.g. `/etc/apm/registries.d/<name>.toml`, a desired-packages JSON).
- Extend the ignition module to synthesize the unit + file list from a
  `aos.packages.<name>` declaration directly.

**Who runs expose vs. enable — RESOLVED (systemd presets, verified).** The
**expose phase** (materialize unit files + drop the
`aos-pkg-<package>.target`) is performed by `apm install`; **enablement is
systemd presets** ([boot-activation.md](boot-activation.md) §3.2, canonical):
the image ships `99-aos-default.preset` (`disable *`), Ignition writes one
per-host preset file via `storage.files` into the per-gen `/etc` lower, and an
**every-boot `aos-preset.service`** runs
`systemctl preset-all --preset-mode=enable-only` (+ `start --no-block` for
newly-enabled targets). Runtime installs run
`systemctl preset aos-pkg-<name>.target` — the Fedora `systemd-update-helper`
pattern — and record the enable line in `/var/etc/systemd/system-preset/`
(Decision 16). Repo verification closed the open items: systemd's *native*
first-boot pass can never fire on AOS (the machine-id is deliberately
committed in stage-1 — `aos-machine-id.service` — so PID 1 always sees "not
first boot"); the `/etc` overlay **upper is tmpfs**, so enablement must be
derived state recomputed each boot (which the every-boot pass provides); and
`apm install` is already generation-stable when nothing changed
(`install.rs:67-73`). Enable-only mode is mandatory — full mode would
whiteout the EROFS-baked `.wants` symlinks of base services. The old Option A
(`storage.links`) / Option B (`systemctl enable`) strawmen are superseded.

**Resolution.** Desired packages live in `/etc/aos/packages.d/desired.toml`.
`aos-install-packages.service` runs after `nix-overlay-setup.service`,
`aos-seed-profiles.service`, and `ignition-files.service`, before
`aos-preset.service`, and reconciles install additions plus removals. Enablement
is a preset concern.

---

## 9. Config & credential delivery — RESOLVED: layered, secrets path signed off

> **Resolved (direction).** The "pick one option" framing was the mistake —
> config has three distinct needs, and the budget mandate says build all three
> rather than force them through one channel:
> - **Secrets → TPM2-sealed systemd credentials** (signed-PCR-11/UKI policy,
>   [config.md](config.md)). This is the SOTA *and* satisfies the original "do
>   not settle on credstore" caution: it is **TPM-sealed**, not the bare host-key
>   credstore that caution was about, and it rides RFC-0006's measured-boot
>   substrate. `SetCredentialEncrypted=` in signed units; surfaces under
>   `$CREDENTIALS_DIRECTORY` (per-service, non-swappable, not inherited).
> - **Structured config → an apm config artifact with a manifest-declared
>   schema** (the package's `expose` declares its config schema; apm validates
>   before start) — closes the "no schema enforcement" gap.
> - **Simple/non-secret → `EnvironmentFile=` + Ignition `storage.files`** (k3s's
>   pattern) stays as the zero-ceremony tier.
>
> **Hot reload is built (D25), not skipped:** the manifest declares whether the
> service supports reload; a config change triggers `systemctl reload-or-restart`
> (`Type=notify-reload`/`RELOADING=1` where supported). **Secrets path signed off
> (2026-06) — fully RESOLVED.** *packages-core* / *apm*.

**Statement.** How per-instance config and secrets reach a package is answered by
the layered model above. The working baseline is k3s today: Ignition writes
`/etc/rancher/k3s/k3s.env`, consumed via systemd `EnvironmentFile=` — which
survives as the simple tier.

**Why it matters.** It touches secret safety, reloadability, offline operation,
per-instance override, schema validation, and the host↔container boundary all at
once — and no option wins on every axis. Committing early (especially to a
credstore) would foreclose options we have not evaluated.

**Options (surveyed, none chosen).**

| Option | Reload w/o restart | Secret isolation | Offline | Schema | Container crossing | Maturity |
|---|---|---|---|---|---|---|
| systemd credentials + credstore | no | good | yes | no | fair | recent |
| EnvironmentFile + Ignition files (status quo) | no | fair | yes | no | good | classic |
| apm config artifact + registry schema | no | fair | yes | yes | good | custom |
| kernel cmdline / SMBIOS / fw_cfg | no | bad | yes | no | good | classic |
| registry-hosted config + apm fetch | maybe | good | **no** | yes | fair | custom |
| per-package `/etc/aos/<pkg>/` overlay + bind-mount | no | fair | yes | maybe | good | classic |
| systemd-confext config image (signed/verity) | no | good (integrity, not secrecy) | yes | no | good | recent |

**Decision criteria to apply:** reloadability, secret-at-rest isolation,
air-gapped suitability, per-instance override ease, schema enforcement, clean
host↔container crossing, introspectability, systemd/ecosystem maturity.

**Resolution.** Config delivery is layered: TPM2-sealed systemd credentials for
secrets, schema-validated apm artifacts for structured config, and
`EnvironmentFile=` for simple config. The manifest records reload support, and a
config change runs `systemctl reload-or-restart` where supported.

---

## 10. Security boundary strength & honest labeling — RESOLVED

> **Resolved.** The signed `[permissions]` manifest is the introspectable
> source of truth, rendered with the **computed confinement label**
> (`sandboxed` / `sandboxed-with-holes` / `unconfined`, derived by fixed
> rules — [permissions.md](permissions.md) §Introspection). The
> `--private-users` question folds into the manifest's `privileged-users`
> permission (`PrivateUsers=` under the per-unit substrate).

**Statement.** A default (empty-manifest) package gets a generated systemd unit
with the per-unit sandboxing boundary: private package root, namespace
directives, capability bounding, syscall/device filtering, Landlock/MAC/eBPF
policy, and a computed confinement label. A high-privilege package (k3s)
declares away parts of that boundary. `PrivateUsers=` is available but has
file-ownership/`/dev` trade-offs; packages that need host identity request the
`privileged-users` permission and keep the rest of the manifest restrictions
explicit.

**Why it matters.** Operators must know exactly which packages are isolated and
which are not. Misrepresenting a high-privilege package as sandboxed is a
security-communication failure, not just a doc nit.

**Options.**
- Surface the boundary directly from the signed `[permissions]` manifest
  (Decision 1, [permissions.md](permissions.md)) in `apm info <pkg>
  --permissions` / `apm show`, so isolation level is queryable before
  install/enable.
- Default to `--private-users=no` + seccomp only where the manifest declares it;
  revisit user-namespacing later.

**Resolution.** The permission manifest is the first-class, introspectable
source of truth for isolation level. `apm info --permissions` exposes the
declared grants and computed confinement label before install/enable.

---

## 11. Upgrade & rollback — RESOLVED (direction, under Decision 17)

> **Resolved (direction).** Per-unit materialization: an upgrade is a
> generation switch + unit restart **with the unit's own declared
> semantics** — k3s keeps `KillMode=process`, so no pod kill (the regression
> this decision flagged disappears with the nspawn deferral). Filesystem
> revert for sandboxed packages comes from a read-only root +
> `TemporaryFileSystem=` for scratch paths; persistent state lives in
> explicit `StateDirectory=`/`BindPaths=`. Rollback = generation switch back
> (both store paths gc-rooted) + `daemon-reload` + restart. The orphaned
> `/var/lib/machines` concern disappears with the image format.

**Statement.** apm already has a generation/profile model
(`/var/lib/profiles/{scope}/gen-N/`, atomic `current` symlink switch, anti-
rollback floor in the registry). The resolved model maps exposed package roots
and rendered units into the package generation rather than into
`/var/lib/machines`.

**Why it matters.** Upgrading a workload means swapping the package root and
restarting the unit; rollback means switching back a generation. Stateful
packages (databases) complicate this (persistent volumes, snapshots). The
resolved per-unit path keeps k3s's `KillMode=process` semantics; the skipped
nspawn materialization would have killed all pods because private PID-ns
teardown loses that survival property (see
[container-model.md](container-model.md) §"The `KillMode=process` regression"
and Decision 17). Without a defined story, upgrades risk state loss or wedged
units.

**Options.**
- Immutable package roots (read-only store path or signed `RootImage=`, state in
  explicit host bind-mounts/state directories) so upgrade = swap root + restart;
  rollback = apm generation switch + restart. Recommended default.
- Persistent roots only for packages that require it, with explicit
  snapshot/rollback (out of MVP scope).

**Resolution.** Package upgrades switch the package profile generation, rewrite
the attached symlinks/preset lines, reload systemd, and restart or reload the
target according to the manifest. Host-mounted state is explicit in the
permissions/config surface.

---

## 12. Package metadata: how a package declares generated services — RESOLVED (hybrid)

> **Resolved (hybrid).** The registry TOML (tag-signed, visible pre-fetch)
> carries what introspection and policy need **before download**:
> `expose.target`, `expose.requires`, `expose.config`,
> `expose.provides`/`expose.uses`, and the full `[permissions]` manifest — so
> `apm info --permissions` and the host policy check work without fetching the
> closure. The rendered unit files (+ a manifest copy) ride the closure as the
> `pkg.expose` store path ([authoring.md](authoring.md)), covered by the NAR
> hash. Gated on Decision 19's capability-gate field landing first.

**Current implementation.** Phase 0 extends `PackageMeta`
(`crates/aos-package/src/types.rs`) and the per-platform registry TOML parser
(`crates/aos-package/src/registry/parse.rs`) with `expose`, the signed
`permissions` manifest, `expose_artifact`, `min-format`, and
`requires-features`. Phase 1 renders the package-owned `pkg.expose` artifact
and copies the manifest into that eval-free output.

**Why it matters.** This is the schema that everything else keys off (install
hook, activation, package service launch, config). Getting it wrong is expensive
to migrate (the registry is content-addressed and signed). It must also carry
the signed `[permissions]` manifest (Decision 1, [permissions.md](permissions.md))
— which subsumes network mode (Decision 3) and isolation level (Decision 10) —
and any package-root image metadata (Decision 5).

**Options.**
- Extend registry `packages/<letter>/<name>.toml` with optional
  `[…container]` / `[…services]` sections (registry-versioned, signed by the
  tag).
- Ship `.aos-manifest.toml` in the store path (discovered at install; travels
  with the closure).
- Hybrid: minimal class/target hints in registry TOML, detailed unit/container
  spec in the closure manifest.

**Implemented artifact.** The package-owned `pkg.expose` output contains the
rendered unit files plus `manifest.json`; `apr publish --expose-manifest`
revalidates that manifest and records the matching `expose_artifact` metadata.

---

## 13. Performance & footprint (largely mooted for MVP by Decision 17)

> Note: with no per-package PID 1 under the per-unit substrate, the
> overhead concern shrinks to ordinary unit sandboxing cost (negligible).
> Measure only if a future package reopens the skipped nspawn path or another
> multi-process init substrate.

**Statement.** nspawn nesting adds marginal startup overhead (~2 s per
container per the investigation); cgroup-v2 delegation and per-container systemd
PID1 add memory. Test timeouts already budget 360–600 s for k3s/registry fleet
tests.

**Why it matters.** Many small workload containers each running a full systemd
PID1 is heavier than the single-process alternative. Test timeout creep is a
real cost as the matrix grows.

**Options.**
- Single-service containers (custom `/init`, no systemd) for one-process
  workloads; full-systemd PID1 only when multiple interdependent services exist
  (k3s).
- Budget test timeouts generously and parallelize where the harness allows.

**Resolution.** No MVP work remains. Per-unit sandboxing removes the
per-package PID-1 cost from the shipped substrate; performance/init measurement
is only reopened with a concrete multi-process init consumer.

---

## 14. Dissolving the module tree into `pkgs/` — RESOLVED (dissolve)

> **Resolved.** Per the direction in [migration.md](migration.md): the
> `modules/roles/` module tree is **dissolved** into `pkgs/` `expose` blocks +
> a thin policy module. The touchpoint tables survive as the inventory;
> sequencing is the increment plan (mkDerivation `expose` → test-http-server
> end-to-end → dissolve per-package → policy module + preset wiring).

**Statement.** The legacy option tree (`aos.roles.*`), module dir
(`modules/roles/`), the bundle (`system.build.ignitionRolesBundle`), the
Ignition path (`/etc/aos/ignition-roles/<name>`), `lib/testing/fleet-spec.nix`,
`lib/modules/systemd/render-role.nix`, and ~6 fleet test files moved to the
package model. The mechanical surface is well-understood (~15 files moved, ~10
edited, ~200–300 lines).

**Why it matters.** This is the prerequisite for everything else. Folding the
dissolve and the container model into one change would be hard to review; doing
them out of order risks churn — synthesized unit names must not be reworked
twice (`aos-<pkg>` → `aos-pkg-<package>`).

**Options.**
- Land target synthesis on `pkgs/` `expose` blocks first, then the per-package
  dissolve, then the container/apm work. Smaller reviewable steps.
- Dissolve first, then targets, then containers. Risks reworking the target
  naming twice.

**Resolution.** The migration sequence is targets → dissolve →
container-model, with synthesized unit naming stabilized before package
exposure moves out of `modules/roles/`.

---

## 15. Systemd unit naming under the package model

**Statement.** Each package synthesizes `aos-pkg-<package>.target` plus
`aos-pkg-<package>-{modules,sysctl,firewall}.service`, plus a container unit
(e.g. `aos-pkg-<package>` nspawn service).

**Why it matters.** Unit names land in the global systemd namespace and are
referenced by Ignition fragments, fleet-test assertions, and operator muscle
memory. Changing them later is a breaking change.

**Options.**
- `aos-pkg-<package>-…` (explicit; recommended in the investigation for
  namespace clarity).
- Shorter prefixes (`pkg-`, `sys-`) — risk collision / less clarity.

**Resolution.** The naming convention is **`aos-pkg-<name>`**. The majority
usage across the doc set now matches it, and [migration.md](migration.md) §4 has
been updated to match (its earlier claim that the set had standardized on the
shorter `aos-<pkg>` was wrong). The future nspawn template stays
`aos-package@.service`; its internal references are `PartOf=aos-pkg-%i.target`
(a `%i`-expansion mismatch here was a real bug in an earlier draft of
[container-model.md](container-model.md)).

---

## 16. Writable /etc overlay path for runtime-installed package units — RESOLVED

> **Resolved (forced by repo verification).** The `/etc` overlay's **upperdir
> is tmpfs** (`etc-overlay-setup.service`,
> `upperdir=/run/etc/upper-<gen>/upper`), so anything written into
> `/etc/systemd/system/` at runtime is **gone on reboot** — rendered-text-in-
> upper was never viable. The persistent, overlay-surfaced location that
> already exists is **`/var/etc`** — the highest-priority *lower* of the
> 3-layer overlay (today carrying machine-id and ssh host keys). Resolution,
> following the `portablectl attach` shape:
>
> - `apm` materializes runtime-installed package units as **gc-rooted
>   store-path symlinks** under `/var/etc/systemd/system.attached/` (an
>   apm-owned attach dir, kept out of admin space), plus the package's
>   enable line in `/var/etc/systemd/system-preset/30-aos-apm.preset`.
> - Both surface through the overlay on every subsequent boot; the every-boot
>   `aos-preset.service` re-derives enablement
>   ([boot-activation.md](boot-activation.md) §3.2).
> - **Rollback** = the generation switch rewrites the symlinks + preset
>   lines (old and new store paths both stay gc-rooted in their
>   generations), then `systemctl daemon-reload` + restart.
> - Verified by the `package-expose-lifecycle` VM check: the AOS systemd build
>   includes `/etc/systemd/system.attached/` in the unit search path with
>   portabled disabled.

**Statement.** [apm-integration.md](apm-integration.md) §4.1 records this
resolved mechanism. Package units are baked into the
EROFS `/etc` lower as inert regular files, but an `apm install` that happens
*after* first boot **cannot rewrite the EROFS lower**. So a runtime-installed
package's systemd units (its `aos-pkg-<package>.target` and member units) must
land in the **writable `/etc` overlay** — the `/var/etc` upper of the 3-layer
overlay — not in EROFS.

**Why it matters.** The expose phase (Decision 8) has nowhere to write units
unless this path is pinned. It also determines rollback behavior: if a package
generation is rolled back, its units must roll back with it, which depends on
*how* they are materialized.

**Options.**
- **gc-rooted store-path symlinks** from the package generation into
  `/var/etc/systemd/system/...` — clean rollback (switch the generation, the
  symlinks follow), but requires the unit text to be a build artifact in the
  store.
- **Rendered text** written directly into `/var/etc/systemd/system/...` —
  simpler to generate at install time, but rollback must **re-render** the prior
  generation's units rather than just flipping a symlink.

**Verified resolution.**
- Runtime units land as gc-rooted store-path symlinks in the apm-owned
  `/var/etc/systemd/system.attached/` directory.
- Enablement lands in `/var/etc/systemd/system-preset/30-aos-apm.preset`.
- Package rollback rewrites the attached symlinks and preset lines from the
  selected package-profile generation, then reloads systemd and restarts the
  target.

**Next step.** Keep [apm-integration.md](apm-integration.md) §4.1 as the
implementation reference for this resolved mechanism.

---

## 17. Execution substrate — RESOLVED (per-unit default, nspawn skipped)

> **Resolved.** **Per-unit sandboxing is the default materialization; nspawn is
> skipped entirely** (not built for MVP, reserved
> for a future package that genuinely needs its own init tree). Every line of
> gathered evidence pointed one way: it dissolves the k3s `KillMode=process`
> regression (Decision 11), eliminates the nesting/test risk (Decision 4) and
> the per-package image format (Decision 5 — the MVP "root" is a store path
> via `RootDirectory=`: no loop device, no udev ordering, no image build),
> gives named-fd host-socket activation and the `JoinsNamespaceOf=` pod primitive,
> and is upstream's flagship-supported composition (the portable-services
> default profile). The Decision 17 spike served as **validation**: materialize
> `test-http-server`'s empty manifest and k3s's manifest as per-unit services;
> confirm teardown semantics and harness cost.
> The honest cost to validate: `network = "private"` *with outbound* needs a
> gated netns+veth oneshot + `NetworkNamespacePath=` (Decision 3) — more
> plumbing than nspawn's `--network-veth`.

**Statement.** The doc set materializes the `[permissions]` manifest as
systemd-nspawn flags. systemd offers a second substrate: **per-unit
sandboxing** — `RootImage=`/`RootDirectory=` plus the unit isolation directives
(`PrivateNetwork=`, `PrivateUsers=`, `CapabilityBoundingSet=`, `DeviceAllow=`,
`BindPaths=`, `SystemCallFilter=`, `ProtectSystem=strict`) — the
portable-services model, usable without `portabled` since the directives are
core service-manager features and `apm` reimplements the attach logic anyway.
See "Substrate decision" in [container-model.md](container-model.md).

**Why it matters.** The manifest is substrate-independent — every field maps
onto a directive as cleanly as onto an nspawn flag. The per-unit substrate
dissolves the k3s `KillMode=process` regression (Decision 11), removes the
second service manager for single-unit packages (no in-container PID1, no
nesting risk — Decision 4; no extra nspawn package-root image for single-binary packages —
Decision 5), and shrinks nspawn's honest use case to "package needs its own
multi-unit init tree" — currently approximately none. Choosing the substrate
late invalidates the package-root builder, image format, and template
decisions, so it is upstream of Decisions 4, 5, 11, and 13. Further verified
evidence for the per-unit side: host-namespace socket units give named-fd
socket activation into a `PrivateNetwork=` service, while `JoinsNamespaceOf=`
remains the two-unit pod primitive when units intentionally share a private
namespace (nspawn forwards `$LISTEN_FDS` only to a `--boot` init, unnamed —
systemd#17764); `RootImage=` carries dm-verity (`RootHashSignature=`) for
signed package roots; and `RootImage=` + `DynamicUser=` + `PrivateUsers=` is
upstream's own portable-services default profile.

**Options.**
- Per-unit sandboxing as the default materialization; nspawn opt-in for
  packages that need an init tree. (Lean.)
- Universal nspawn materialization (the superseded proposal), accepting the k3s regression and
  the nesting/test costs.

**Resolution.** The head-to-head spike chose per-unit sandboxing. nspawn is
skipped for the MVP and retained only as a future template for a package that
genuinely needs its own init tree.

---

## 18. Cross-package dependencies — RESOLVED (direction): typed capability routing, flat ordering first

> **Resolved (direction).** Two increments, both built (budget mandate):
> 1. **Flat ordering (MVP).** `requires: Vec<String>` by package name →
>    install-time pull-in (deb-style `Depends:`, materialized atomically in the
>    shared generation) + `After=`/`Wants=` target edges. No version solver (the
>    channel model pins versions). This is the immediate, low-risk subset.
> 2. **Typed capability routing (target).** Generalize `requires` from "needs B
>    *running*" to "needs *capability X* from B": a package's `expose` declares
>    **provided capabilities** (a named socket, directory, or service), and a
>    consumer requires them by typed name. The renderer wires each edge as the
>    *least-privilege* primitive — a passed **fd** (socket activation +
>    `JoinsNamespaceOf=`), a `BindReadOnlyPaths=` of just that directory — so the
>    consumer gets exactly that capability and **no ambient access**. This
>    unifies cross-package composition with the brokered-capability model
>    ([permissions.md](permissions.md), [state-of-the-art.md](state-of-the-art.md)):
>    it is Fuchsia's `offer`/`use` in AOS's *flat* idiom (siblings under
>    `aos.slice`, no realm tree — simpler than Fuchsia, same least-privilege
>    guarantee), and it is the answer to the "ambient path authority" gap the SOTA
>    review flagged. Why this is right, not gold-plating: AOS already passes named
>    fds (inbound-private net, the pod primitive), so typed routing *completes* an
>    existing half-built capability story rather than adding a new paradigm.
> **DECIDE-EARLY → done (direction).** Flat first, typed routing as the committed
> target. *apm* / *packages-core*.

## 18. Package-name service dependencies (`requires`)

**Statement.** Cross-package service dependencies ("A needs B *running*") are
declared by package **name** in the `expose` block
([authoring.md](authoring.md)) and materialize as `After=`/`Wants=` edges
between package targets ([container-model.md](container-model.md)
§Composition). Phase 0 adds the name-level resolver surface in
`crates/aos-package/src/resolve.rs`; the Phase 5 expose phase emits the
corresponding target edges.

**Why it matters.** This was new resolver surface (name-level resolution +
closure merge), and the implementation pins it as install-time pull-in
(deb-style `Depends:`) plus generated target edges. Favorable ground truth:
`apm install a b` already shares one profile generation, so cross-package edges
materialize atomically before the generation switch.
Counter-precedent against over-building: snapd ships *no* cross-snap ordering
and pushes retry loops onto users — a documented pain point — so flat ordering
edges are worth having, but nothing more (no version-constraint solver; the
registry channel model already pins versions).

**Current implementation.** `resolve.rs` pulls `expose.requires` packages and
provider packages named by `expose.uses`; the expose-unit materializer emits the
target ordering and typed capability route drop-ins from the signed metadata.

---

## 19. Registry schema capability gate (fail-open on old clients)

**Statement.** The registry TOML parser is serde-tolerant (no
`deny_unknown_fields` — `registry/parse.rs`). New `expose`/`[permissions]`
blocks parse as no-ops on old clients: an apm predating the schema would
install and expose a permission-bearing package **without knowing or
enforcing its privilege** — fail-open.

**Why it matters.** The enforcement story in
[permissions.md](permissions.md) assumes the host reads the manifest. A fleet
with stale apm binaries silently bypasses it.

**Options.** A `min-format`/`requires-features` field added to the schema
**before** the first permission-bearing package is published, plus a structural
wire-format break for permission-bearing entries so old resolvers fail closed
instead of ignoring unknown fields.

**Current implementation.** Phase 0 adds `min-format` and `requires-features`
to `PackageMeta` + the registry parser. Permission-bearing TOML carries the
gate inside a structured `references` table; pre-Phase-0 clients expected
`references = [...]` and reject the entry. Current clients also refuse
unsupported formats/features, and RFC-0001 fields must declare their feature
gate.
**RESOLVED** (fail-closed property).

---

## Decision summary

| # | Decision | Disposition | Owner |
|---|---|---|---|
| 1 | Privilege model **RESOLVED**; (a) enforcement model + policy file format **RESOLVED** (`/etc/aos/policy.toml`: named tier + per-permission overrides + module allowlist + per-tier `systemd-analyze` threshold; image default, Ignition per-host override); (b) k3s set — validated in the D17 spike against kind/k3d/Incus (adds `/lib/modules` ro + `/dev/fuse`) | RESOLVED | packages-core / apm / boot / pkgs |
| 2 | Kernel modules as the allowlisted, signature-backed host-fulfilled permission (allowlist in 1(a)) | RESOLVED | packages-core |
| 3 | Networking — **RESOLVED**: socket-activation default, netns+veth oneshot for outbound, host for k3s | RESOLVED | packages-core / pkgs |
| 4 | nspawn-in-VM feasibility — **mooted for MVP** by D17; per-unit lifecycle test remains | RESOLVED | test-infra |
| 5 | Container roots — **RESOLVED**: store path via `RootDirectory=`; **verity-signed `RootImage=` un-deferred** (budget mandate) — built in D21/P9, `CONFIG_DM_VERITY` added | RESOLVED | pkgs / apm |
| 6 | Bake vs. fetch — **RESOLVED by 5**: ordinary closure delivery; bake k3s, fetch workloads | RESOLVED | pkgs / boot |
| 7 | machined/portabled/importd — **RESOLVED: stay disabled** | RESOLVED | pkgs |
| 8 | Install-at-boot — enable **RESOLVED: presets via every-boot `aos-preset.service`** (machine-id + tmpfs-upper + apm idempotency all verified); install unit runs after profile seeding and reconciles desired packages | RESOLVED | boot / apm |
| 9 | Config & credential delivery — **RESOLVED (signed off 2026-06): layered** — secrets via TPM2-sealed systemd-creds (RFC-0006 substrate; satisfies the credstore caution), structured config via apm artifact + manifest schema, simple via `EnvironmentFile=`; hot reload built (D25) | RESOLVED | packages-core / apm |
| 10 | Boundary labeling — **RESOLVED**: computed confinement label | RESOLVED | packages-core |
| 11 | Upgrade/rollback — **RESOLVED (direction)** under D17: unit-semantics restarts, `KillMode=process` preserved for k3s | RESOLVED (direction) | apm / packages-core |
| 12 | Package metadata — **RESOLVED (hybrid)**: TOML carries target/requires/permissions; units ride the closure | RESOLVED | apm / packages-core |
| 13 | Performance & init strategy — **RESOLVED**: mooted for MVP by per-unit substrate; reopen only for a concrete multi-process init consumer | RESOLVED | pkgs / test-infra |
| 14 | Module-tree dissolve sequencing — **RESOLVED**: dissolve into `pkgs/` `expose` blocks ([migration.md](migration.md)) | RESOLVED | packages-core |
| 15 | Unit naming — **RESOLVED: `aos-pkg-<name>`** | RESOLVED | packages-core |
| 16 | Runtime unit placement — **RESOLVED**: `/var/etc` attach dir + preset lines (tmpfs upper forced it) | RESOLVED | boot / apm |
| 17 | Execution substrate — **RESOLVED**: per-unit default, nspawn skipped; spike = validation | RESOLVED | packages-core / pkgs |
| 18 | Cross-package dependencies — **RESOLVED (direction)**: flat `requires` ordering first, then **typed capability routing** (provided/required typed caps → fd-pass/`BindReadOnlyPaths=`/`JoinsNamespaceOf=`, least-privilege; Fuchsia `offer`/`use` in AOS's flat idiom) | RESOLVED (direction) | apm / packages-core |
| 19 | Registry schema capability gate (fail-open on old clients) | RESOLVED | apm |
| 20 | **Layered enforcement** — Landlock + generated MAC + eBPF-LSM + full systemd hardening baseline + per-package `systemd-analyze` CI gate ([enforcement.md](enforcement.md)) | COMMITTED (budget mandate) | packages-core / pkgs |
| 21 | **dm-verity package roots** — signed `RootImage=` vs the `.platform` keyring ([attestation.md](attestation.md)); un-deferred | COMMITTED (budget mandate) | pkgs |
| 22 | **Runtime attestation** — measure package + manifest into PCR 15, TPM quote, **registry golden-measurements catalog** (catalog/oracle, never a runtime signer); extends RFC-0006 ([attestation.md](attestation.md)) | COMMITTED (budget mandate) | apm / boot |
| 23 | **Supply-chain provenance & transparency** — in-toto/SLSA, transparency log, TUF roles/thresholds ([apm-integration.md](apm-integration.md) §7) | COMMITTED (budget mandate) | apm |
| 24 | **Declarative reconciliation** — desired-package set converges by install *and prune*; removing a package from `desired.toml` uninstalls it (the Nix/Talos/K8s declarative idiom; additive-only was a wart) | COMMITTED (budget mandate) | apm / boot |
| 25 | **Hot-reload plumbing** — manifest declares reload support; config change → `systemctl reload-or-restart` (`Type=notify-reload` where the service supports it) | COMMITTED (budget mandate) | apm / packages-core |

## Why anything is still out of scope (merit, not cost)

Under the unlimited-budget mandate the **only** reason to not build something is
that building it would make the OS *worse* — never that it costs effort. Three
classes remain genuinely out, each justified on merit:

- **Dominated mechanisms.** **nspawn** (D17) is squeezed from both sides: the
  per-unit substrate is lighter for every package we have, and a **microVM tier**
  (below) is strictly stronger for untrusted code. Building nspawn would add a
  second service manager (machined coupling, nesting/test flakiness) with **zero
  consumer** — speculative complexity the budget should not fund.
- **Pure attack surface.** **machined / portabled / importd** (D7) stay disabled:
  enabling daemons we don't use enlarges the TCB for no capability — anti-SOTA
  for a minimal immutable OS.
- **No consumer yet.** **L2 multi-container zones** (the netns/veth *capability*
  is built in P6; a zone is a topology to add when a concrete multi-package-L2
  need appears) and **performance/init measurement** (D13, mooted by the per-unit
  substrate — no per-package PID 1).

**The one genuine capability gap — stronger-than-namespace isolation — is a
threat-model question, and it is now ANSWERED: not yet.** The current threat
model is **first-party package confinement**, for which the per-unit + Landlock +
MAC + attestation stack is sufficient; a microVM tier would be gold-plating
today. **Decided (2026-06): the microVM tier is a planned future effort, built
when untrusted / multi-tenant workloads enter scope** — and when it is, the SOTA
answer is a **microVM tier (Firecracker/Kata)** built from AOS's existing
from-source QEMU + `lib/testing/firecracker.nix` infrastructure as a
manifest-selectable `substrate = "microvm"`, **not nspawn**. The substrate
*gradient* — per-unit (default, now) → microVM (untrusted, later), nspawn skipped
entirely — is the recorded direction; only the timing is deferred, on a real
future need rather than on cost.

## State-of-the-art additions (Decisions 20–25)

Decisions 1–19 were the original design questions. Decisions 20–25 are the
state-of-the-art improvements added under the unlimited-engineering-budget
mandate ([state-of-the-art.md](state-of-the-art.md)) — they are **committed
deliverables, not open questions**, with full implementer detail in
[enforcement.md](enforcement.md), [attestation.md](attestation.md), and
[apm-integration.md](apm-integration.md). They are listed here so the register
is the single index of everything to build. Both maintainer decisions are now
answered: D9 (config) — secrets path signed off (TPM2-sealed creds); and the
microVM tier — **not yet** (first-party threat model; a planned future effort).
D17 (nspawn) stays skipped on merit, not cost.

---

## Cross-cutting non-negotiables

- **Hermetic from source.** Container roots and any new build helpers must use
  only AOS packages (`mkfs.ext4 -d`, `fakeroot`, `exportReferencesGraph`), no
  host tools, no OCI imports pulled from upstream — consistent with CLAUDE.md.
- **Honest labeling.** k3s is *not* a sandbox (Decisions 1, 10). Say so in
  operator-facing surfaces, not just in design docs.
- **Layered config commitment.** Config delivery (Decision 9) is layered:
  TPM2-sealed systemd credentials for secrets, schema-validated apm artifacts
  for structured config, and `EnvironmentFile=` for simple config.
- **Verified against the tree.** The "machined disabled" flags remain in
  `pkgs/system/systemd.nix`, the namespace and LSM kernel configs are pinned in
  `pkgs/kernel/config/base.config` / `security.config` and checked by
  `tests/build/kernel-config.nix`, and `aos-seed-profiles.service` still runs
  after `nix-overlay-setup.service` in initrd before the stage-2 package seed
  and desired-package install services.
