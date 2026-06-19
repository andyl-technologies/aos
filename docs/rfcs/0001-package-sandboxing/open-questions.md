# Packages: open questions, risks & decisions

Status: planning
Audience: anyone planning the package model, the systemd-nspawn
container model, apm/registry integration, or the boot-time activation path
(`modules/roles/`, `crates/aos-package/`, `modules/services/ignition.nix`,
`lib/testing/`, `pkgs/system/systemd.nix`).

This is the "what we must decide" doc for the packages direction: every unit of
software AOS runs is a registry-installable **package** (`apm install`), and
**every** package exposes a systemd-nspawn container plus an `aos-pkg-<pkg>.target`
handle, with its privilege declared in a signed `[permissions]` manifest
(see [permissions.md](permissions.md)). It collects the open risks,
unknowns, and pending decisions surfaced across the investigation. Each entry has
a statement, why it matters, the options, and a proposed owner / next step. It
deliberately leaves the **config delivery** decision open. Sibling docs:
[README.md](README.md), [permissions.md](permissions.md),
[container-model.md](container-model.md),
[apm-integration.md](apm-integration.md), [boot-activation.md](boot-activation.md),
[config.md](config.md), [migration.md](migration.md), [activation.md](activation.md).

A quick note on honesty up front: two things in this plan do **not** fit the
clean model and are called out throughout. (1) **k3s is a high-privilege
container** — it declares host network, host cgroups, and globally-loaded kernel
modules in its manifest, so its container is a nominal mount/UTS wrapper, not a
security boundary; the privilege is now *visible in the manifest*. (2) **config
delivery is genuinely undecided** — no option is a clear winner, and we must not
let "settle on credstore" sneak in by default.

---

## How to read this

Each decision is tagged with a rough disposition:

- **DECIDE-BEFORE-MVP** — blocks a first working containerized package.
- **DECIDE-EARLY** — shapes the schema/API; expensive to change later.
- **DEFER** — can ship a placeholder and revisit; must be explicitly tracked.

Owners are roles, not people: *packages-core* (the module synthesis),
*apm* (`crates/aos-package/`), *boot* (`modules/services/ignition.nix`),
*test-infra* (`lib/testing/`), *pkgs* (`pkgs/system/systemd.nix`,
container-root builders).

---

## 1. Package privilege model — RESOLVED (unified container + `[permissions]` manifest)

> **Resolved.** The earlier proposal here — introduce a package **class**
> distinction (`workload` vs. `infrastructure`) — is **superseded** by the
> unified model in [permissions.md](permissions.md): **every** package is an
> nspawn container, and privilege is a declared, signed `[permissions]` manifest
> (Android/iOS app-permission analogy), not a two-valued class. The default
> (empty manifest) is a tightly-sandboxed container; a package gets only what it
> declares. k3s is not a special case — it is a high-privilege **container** that
> declares a long permission list (host network, privileged-users,
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

One sub-question is now **answered** and one remains **genuinely open** under the
resolved model:

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
materialization** — the generated nspawn unit contains only the flags for granted
permissions and `aos-pkg-<pkg>-modules.service` loads only allowlisted modules,
re-derived from the granted set each generation, with the kernel/signature layer
backstopping modules. A package that declared more than granted simply runs with
less. **What is still open** is the policy **file format** and **where the host
allowlist is declared** (TOML allow/deny lists, a signed fleet policy doc,
Nix-evaluated) — that remains TBD. Prior-art constraint for that decision: the
primary policy surface should be a small set of **named tiers**
(`restricted`/`baseline`/`privileged`), with per-permission allowlists as the
escape hatch — Kubernetes removed knob-level PodSecurityPolicy in favor of
exactly three named Pod Security Standards because per-knob policy proved
unwritable and unauditable, and systemd portable services ship four named
profiles for the same reason. **Proposed format:** a TOML policy file at
`/etc/aos/policy.toml` — a named tier (`tier = "baseline"`) plus optional
per-permission overrides and the `kernel-modules` allowlist; shipped in the
image EROFS as the fleet default and overridable per host by an
Ignition-written copy in a higher overlay layer (the same precedence model as
presets); evaluated by `apm` at install/enable. Nix-evaluated policy is
rejected (not available at runtime install — the [authoring.md](authoring.md)
forcing function); a signed fleet-policy document can layer on later without
changing the format. **DECIDE-EARLY** (confirm the proposed format; the
enforcement model is settled). *packages-core* + *apm* + *boot*.

**(b) The validated k3s permission set under AOS nspawn.** The manifest in
[permissions.md](permissions.md) is a *strawman* derived from known
k3s-in-privileged-container patterns (k3d, k3s-in-docker), **not yet validated**
against a running AOS nspawn k3s. k3s is the **proving case**: if it runs under
the generated unit, the permission schema is complete enough. The exact
capability / device / mount / module set is `needs verification`. Under
Decision 17's per-unit direction the proving case **shrinks dramatically**:
k3s materializes as a host unit — today's working unit shape,
`KillMode=process` preserved — whose manifest *documents* its privilege
rather than constructing a wrapper. Validation reduces to "does the generated
unit match today's working unit," plus the gated modules/sysctl/firewall
services. **DECIDE-BEFORE-MVP** (gates the first high-privilege package).
*pkgs* + *test-infra*.

---

## 2. Kernel modules are global — there is no per-container module namespace

**Statement.** k3s needs `br_netfilter`, `vxlan`, `ip_set`. Kernel modules load
into the single host kernel; containers inherit them and cannot scope them. These
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

**Proposed next step.** *packages-core*: model `kernel.modules` as the
allowlisted `kernel-modules` permission in the `[permissions]` manifest —
host-fulfilled, gated by the package target, admission-checked against the host
allowlist (Decision 1(a)), kernel-signature backstopped. Document the
non-reversibility (loaded modules persist after stop). **DECIDE-EARLY** (where
the allowlist is declared rides on the still-open policy file format of 1(a)).

---

## 3. Container networking model — RESOLVED (direction, under Decision 17)

> **Resolved (direction).** The `network` permission materializes as:
> **inbound-only private** (default) — host-owned socket units pass named fds
> into the sandboxed `PrivateNetwork=` unit while the socket stays in the host
> namespace, with no ambient host-network access beyond passed activation fds;
> **private with
> outbound** — a gated `aos-pkg-<n>-netns.service` oneshot creates a named
> netns + veth pair (host side managed by systemd-networkd; `CONFIG_VETH=y`
> confirmed in the kernel config) and the workload unit joins via
> `NetworkNamespacePath=/run/netns/aos-pkg-<n>` — the one place per-unit is
> more plumbing than nspawn's `--network-veth`, to be validated in the
> Decision 17 spike; **host** — k3s and peers, per their manifest. Zone-style
> multi-container L2 is deferred until a real need appears.

**Statement.** systemd-nspawn offers `--network-veth` (paired veth, host side
managed by systemd-networkd), `--network-zone`, `--network-namespace-path`, and
`--network=host`. AOS already runs systemd-networkd + systemd-resolved. Workload
containers want veth; k3s wants host (Decision 1).

**Why it matters.** Veth requires host-side `.network` files (e.g.
`/etc/systemd/network/30-container-<pkg>.network` matching `ve-<pkg>-*`),
firewall coordination with the base nftables sets, and possibly DHCP/static
inside the container. Cross-container and container↔host reachability in test L2
is fiddly (the k3s fleet test already pins `node-ip`/`flannel-iface` to work
around a missing default route). `nss-mymachines` is **not** shipped, so
`getent hosts <container>` does not resolve container names.

**Options.**
- Workload default `--network-veth` + a generated host `.network`; firewall
  ports flow through the existing `aos-pkg-<pkg>-firewall.service` against the
  base `allowed_tcp`/`allowed_udp` sets (plus the `--port=`/DNAT forward for
  off-host reachability — see [container-model.md](container-model.md)
  §Networking).
- `--network-zone` for multi-container L2 (less documented; revisit if needed).
- `--network=host` only for infrastructure packages.

**Proposed next step.** *packages-core* + *pkgs*: spec veth as the workload
default and generate the host `.network` from the package definition; document
host-net for infrastructure. Resolve naming without `nss-mymachines` (explicit
`/etc/hosts` or DNS). **DECIDE-EARLY** for the schema (how a package declares
its network mode), **DEFER** zone support.

---

## 4. nspawn inside test VMs — feasibility (mostly mooted by Decision 17)

> **Mostly mooted.** With nspawn deferred (Decision 17), no nesting runs in
> MVP test VMs. What remains for *test-infra*: a per-unit-sandbox lifecycle
> test (`RootDirectory=` + `PrivateUsers=` + `PrivateNetwork=` inside the VM
> harness) — strictly simpler, no nested service manager. Loop devices are
> available in guests if `RootImage=` is ever exercised
> (`CONFIG_BLK_DEV_LOOP=y`, udevd shipped and running).

**Statement.** Tests must run containerized packages inside the existing
harnesses (`lib/testing/vm.nix`, `firecracker.nix`, `fleet.nix`). The guest
kernel has the needed namespace configs and ships systemd-nspawn; nesting
(systemd → nspawn → systemd) is expected to work.

**Why it matters.** If nspawn-in-VM is flaky, every containerized-package test is
flaky. Known risk areas: cgroup-v2 delegation depth, writable `/proc/sys` for
container init, `/dev` population, and the fact that **machined is disabled**
(see Decision 7) so `machinectl`-based introspection (`vm.exec_in_container`,
`vm.container_status`) needs an alternative. Verified for v259: every
generated nspawn unit must use `--keep-unit --register=no` — privileged
registration failure is **fatal** without machined, and without `--keep-unit`
nspawn allocates its own scope under `machine.slice` via PID 1 *even with*
`--register=no`, escaping the package's slice (see the corrected template in
[container-model.md](container-model.md)).

**Options.**
- Drive containers purely via `systemctl` + explicit nspawn units, parse
  `systemctl show --json`; avoid `machinectl` entirely.
- Re-enable machined in the test image only (divergence from production — risky).

**Proposed next step.** *test-infra*: prototype a single-VM lifecycle test
(start/inspect/exec/stop) against a trivial workload package **before** building
out the matrix, to de-risk nesting and the no-machined introspection path. Add
`vm.exec_in_container` / `vm.container_status` helpers built on `systemctl` +
`systemd-run`/`nsenter`, not `machinectl`. **DECIDE-BEFORE-MVP** (gates the test
plan in [boot-activation.md](boot-activation.md) /
[container-model.md](container-model.md)).

---

## 5. Container root images — RESOLVED (store path via `RootDirectory=`)

> **Resolved.** Store-path-in-closure, consumed via `RootDirectory=` (per
> Decision 17): the package's root tree is an ordinary store path inside the
> package closure — it inherits NAR hashing, the registry tag-signature
> chain, and gc-rooting with zero new machinery, and needs no image build, no
> loop device, no udev ordering. The `expose.images` registry field is
> therefore **not needed for MVP**; it returns if/when a verity-signed
> `RootImage=` variant lands (blocked on adding `CONFIG_DM_VERITY` to the
> kernel config — verified absent today). The baked-vs-fetched trust
> split-brain dissolves with it: a store path rides whichever closure
> delivers it (system toplevel or apm fetch), covered by that channel's
> existing trust.

**Statement.** systemd-nspawn needs a real root filesystem; AOS today builds
store closures + a host rootfs (`lib/build/rootfs.nix` via `mkfs.ext4 -d` +
`fakeroot`, closure discovery via `lib/build/closure-info.nix`'s
`exportReferencesGraph`) but **does not** build per-package container roots, and
there is **no OCI format** in the pipeline. A proposed `lib/build/container-root.nix`
would reuse the rootfs pattern to emit a minimal ext4 image per package.

**Why it matters.** This is net-new build surface and a new **registry
artifact**. Today the registry ships package closures as NARs
(`crates/aos-package/`); a container root is an additional artifact that must be
fetched, verified, and stored (`/var/lib/machines` on the writable `/var`
partition). Container roots are currently **unsigned** in the proposal, whereas
the registry already has an Ed25519 signing/TOFU/anti-rollback trust model
(`docs/registry/signing-and-trust.md`). An unsigned container root run as PID1
is a trust gap.

**Options.**
- Ship the container root as a normal store path inside the package closure →
  it inherits NAR hashing + the registry signing chain for free; nspawn mounts
  the store-path rootfs read-only. (Most hermetic; aligns with "verify it exists
  in the closure".)
- Ship a separate `*-container-root.img` artifact with its own narinfo/signature.
  More like OCI; more schema and a second verification path.
- Bake the container root into the host image for infrastructure packages
  (no runtime fetch; bloats image — see Decision 6).

**Baked-vs-fetched trust split-brain.** Per
[apm-integration.md](apm-integration.md) §7, the two delivery models have *two
different roots of trust*: a **fetched** container root is covered by the
registry tag signature + NAR hash, while a **host-image-baked** root never
transits the registry and is covered only by the host image's own integrity
(UKI / system closure). Mixing baked and fetched roots for the *same* package
across a fleet yields a split trust story (image-signed vs. tag-signed). The
recommendation is **fetch-at-boot via apm as the default**; if a deployment
bakes a root, the per-package choice must be documented explicitly (ties to
Decision 6's bake-vs-fetch).

**Proposed next step.** *pkgs* + *apm*: prefer the **store-path-in-closure**
approach so container roots inherit existing signing; spec it in
[container-model.md](container-model.md) and the registry schema in
[apm-integration.md](apm-integration.md). Decide ext4-image vs. bare store-path
mount, and pin one delivery model per package (default fetch-at-boot) to avoid
the trust split-brain. **DECIDE-EARLY** (schema-shaping). Image signing of any
separate artifact is **DECIDE-BEFORE-MVP** if Option 2 is chosen. Audit the
whole chain against TUF's attack catalog (freeze, mix-and-match, fast-forward,
key rotation) and consider attestation-binding the `[permissions]` manifest to
the NAR hash — see [apm-integration.md](apm-integration.md) §7.

---

## 6. Image size & closure growth — RESOLVED by Decision 5

> **Resolved.** With package roots as ordinary closure members, bake-vs-fetch
> is just "is the package in the system closure or apm-fetched" — the
> standing default holds: fetch-at-boot for workloads, bake k3s and other
> infrastructure. No separate sizing model; quantify the closure delta once a
> real workload package exists.

**Statement.** Per the investigation, the host rootfs closure is ~800 MiB–1.2 GiB
uncompressed (~400–600 MiB shrunk). A k3s container root is ~200–300 MiB
(k3s + containerd + runc + cni-plugins), with coreutils/bash deduped against the
host closure.

**Why it matters.** If container roots are **baked into the host image**
(Decision 5 Option 3), every host carries them whether or not the package is
enabled — directly contradicting "installed at boot via apm." If fetched at
boot, we trade image size for a network/registry dependency and first-boot
latency.

**Options.**
- Fetch container roots at boot via apm (keeps host image lean; needs network +
  registry reachability — conflicts with air-gapped).
- Bake only a small set of "always-on" infrastructure roots; fetch the rest.
- Store-path-in-closure (Decision 5 Option 1) makes "fetch" just a normal apm
  install — no separate sizing model.

**Proposed next step.** *pkgs* + *boot*: default to fetch-at-boot via apm; gate
any baking behind an explicit per-deployment opt-in. Quantify the closure delta
once a real workload package exists. **DECIDE-EARLY**.

---

## 7. machined / portabled / importd are disabled by design — RESOLVED (stay disabled)

> **Resolved.** Keep all three disabled. The per-unit substrate (Decision 17)
> needs none of them; the deferred nspawn path, if it ever materializes, uses
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

**Proposed next step.** *pkgs*: keep disabled unless a concrete blocker appears;
record the decision and the `machinectl`-free equivalents in
[container-model.md](container-model.md). **DECIDE-EARLY** (affects every unit
template and the test harness).

---

## 8. Install-at-boot: apm packages via Ignition

**Statement.** Today Ignition's `aos-seed-profiles` service
(`modules/services/ignition.nix`) seeds only the **system** profile
(`/var/lib/profiles/system/`); there is **no** mechanism to install additional
apm packages at first boot, and registries are configured post-boot via
`apm registry add`. The plan: Ignition lists packages + registry config, then
an `apm-install-at-boot` oneshot installs and enables them.

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

**Proposed next step.** *boot* + *apm*: design the desired-packages handoff and
the oneshot ordering in [boot-activation.md](boot-activation.md); fix the
expose-vs-enable ownership split; define idempotency via state.json and behavior
when the registry is unreachable (air-gapped / on-prem must not hard-fail boot).
**DECIDE-BEFORE-MVP**.

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

**Proposed next step.** *packages-core* + *apm*: keep the decision open in
[config.md](config.md); document the k3s `EnvironmentFile` pattern as the known-
working baseline; do **not** bake any config system into the package type (keep
`ignitionExtras` as the escape hatch). Likely MVP placeholder is the
per-package `/etc/aos/<pkg>/` overlay (extends the status quo, no new infra),
with schema-validated apm config and credstore explicitly deferred and tracked.
**DEFER** (but track the open questions in [config.md](config.md): hot-reload
mechanism, secrets-at-rest encryption, credential audit, container config
isolation, schema format, Ignition `storage.files` enrichment, registry
responsibility, k3s `/etc/rancher/k3s/k3s.env` backward-compat).

---

## 10. Security boundary strength & honest labeling — RESOLVED

> **Resolved.** The signed `[permissions]` manifest is the introspectable
> source of truth, rendered with the **computed confinement label**
> (`sandboxed` / `sandboxed-with-holes` / `unconfined`, derived by fixed
> rules — [permissions.md](permissions.md) §Introspection). The
> `--private-users` question folds into the manifest's `privileged-users`
> permission (`PrivateUsers=` under the per-unit substrate).

**Statement.** A default (empty-manifest) package gets a real nspawn sandbox
(own PID1, namespaces); a high-privilege package (k3s) declares away the
boundary. `--private-users` is available but has file-ownership/`/dev`
trade-offs; the investigation recommends `--private-users=no` (the
`privileged-users` permission) with seccomp/mount restrictions instead for the
packages that need it.

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

**Proposed next step.** *packages-core*: make the permission manifest the
first-class, introspectable source of truth for isolation level; document
seccomp/mount defaults in [container-model.md](container-model.md). **DECIDE-EARLY**.

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
rollback floor in the registry). It is unclear how this maps onto a running
nspawn container and its `/var/lib/machines` rootfs and persistent state.

**Why it matters.** Upgrading a workload means swapping the container root and
restarting the unit; rollback means switching back a generation. Stateful
packages (databases) complicate this (persistent volumes, snapshots). For k3s
under the nspawn materialization, restart **kills all pods** — private PID-ns
teardown loses today's `KillMode=process` survival property (see
[container-model.md](container-model.md) §"The `KillMode=process` regression"
and Decision 17) — so upgrade is disruptive well beyond a drain. Without a
defined story, upgrades risk orphaned roots in `/var/lib/machines`, state loss,
or wedged units.

**Options.**
- Ephemeral container roots (read-only image + `--volatile=overlay`, state in
  explicit host bind-mounts) so upgrade = swap image + restart; rollback = apm
  generation switch + restart. Recommended default.
- Persistent roots only for packages that require it, with explicit
  snapshot/rollback (out of MVP scope).

**Proposed next step.** *apm* + *packages-core*: define the
generation↔container-root↔unit-restart mapping; default to ephemeral roots with
host-mounted state; document k3s upgrade as disruptive (drains). Spec in
[container-model.md](container-model.md) and [migration.md](migration.md).
**DECIDE-EARLY**.

---

## 12. Package metadata: how a package declares a container/service — RESOLVED (hybrid)

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
hook, activation, container launch, config). Getting it wrong is expensive to
migrate (the registry is content-addressed and signed). It must also carry the
signed `[permissions]` manifest (Decision 1, [permissions.md](permissions.md))
— which subsumes network mode (Decision 3) and isolation level (Decision 10) —
and the container-root reference (Decision 5).

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
> Measure only if/when the deferred nspawn path materializes.

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

**Proposed next step.** *pkgs* + *test-infra*: support both init strategies in
the container-root builder; pick per-package. Measure real overhead once a
workload package exists rather than guessing. **DEFER** (measure first).

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

**Proposed next step.** *packages-core*: sequence as targets → dissolve →
container-model to avoid renaming synthesized unit names twice; capture the
touchpoint inventory and validation gates (`aos fmt --check`,
`checks.eval`, `systems.server.checks.system-boot`, fleet) in
[migration.md](migration.md).
**DECIDE-BEFORE-MVP** (sequencing).

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

**Proposed next step.** *packages-core*: fix the naming convention **once**,
before Decision 14's dissolve, and assert it. **RESOLVED: `aos-pkg-<name>`** —
the majority usage across the doc set; [migration.md](migration.md) §4 has been
updated to match (its earlier claim that the set had standardized on the
shorter `aos-<pkg>` was wrong). The nspawn template stays
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
> - *Small needs-verification:* whether the AOS systemd build includes
>   `/etc/systemd/system.attached/` in the unit search path with portabled
>   disabled; if not, use `/var/etc/systemd/system/` directly — same
>   mechanism, less tidy separation.

**Statement.** [apm-integration.md](apm-integration.md) §4.1 calls this **the
single biggest unresolved mechanism**. Package units are baked into the
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

**Needs verification.**
- The exact writable path (`/var/etc/systemd/system/` vs. another overlay upper
  location).
- Whether `apm` is permitted to write systemd units into the `/etc` overlay at
  runtime at all.
- Rollback semantics: gc-rooted store-path symlinks vs. rendered text when a
  package generation is rolled back.

**Proposed next step.** *boot* + *apm*: pin the writable path and the
materialization strategy (symlink vs. rendered text), and tie unit rollback to
the package generation. Spec in [apm-integration.md](apm-integration.md) §4.1.
**DECIDE-BEFORE-MVP**.

---

## 17. Execution substrate — RESOLVED (direction: per-unit default, nspawn deferred)

> **Resolved (direction).** **Per-unit sandboxing is the default
> materialization; nspawn is deferred entirely** (not built for MVP, reserved
> for a future package that genuinely needs its own init tree). Every line of
> gathered evidence pointed one way: it dissolves the k3s `KillMode=process`
> regression (Decision 11), eliminates the nesting/test risk (Decision 4) and
> the per-package image format (Decision 5 — the MVP "root" is a store path
> via `RootDirectory=`: no loop device, no udev ordering, no image build),
> gives named-fd host-socket activation and the `JoinsNamespaceOf=` pod primitive,
> and is upstream's flagship-supported composition (the portable-services
> default profile). Kernel note: `CONFIG_DM_VERITY` is absent today, so the
> verity-signed `RootImage=` upgrade path is future work behind a
> kernel-config change. The planned spike downgrades from decision input to
> **validation**: materialize `test-http-server`'s empty manifest and k3s's
> manifest as per-unit services; confirm teardown semantics and harness cost.
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
nesting risk — Decision 4; no container-root image for single-binary packages —
Decision 5), and shrinks nspawn's honest use case to "package needs its own
multi-unit init tree" — currently approximately none. Choosing the substrate
late invalidates the container-root builder, image format, and template
decisions, so it is upstream of Decisions 4, 5, 11, and 13. Further verified
evidence for the per-unit side: host-namespace socket units give named-fd
socket activation into a `PrivateNetwork=` service, while `JoinsNamespaceOf=`
remains the two-unit pod primitive when units intentionally share a private
namespace (nspawn forwards `$LISTEN_FDS` only to a `--boot` init, unnamed —
systemd#17764); `RootImage=` carries dm-verity (`RootHashSignature=`) for
signed container roots; and `RootImage=` + `DynamicUser=` + `PrivateUsers=` is
upstream's own portable-services default profile.

**Options.**
- Per-unit sandboxing as the default materialization; nspawn opt-in for
  packages that need an init tree. (Lean.)
- nspawn everywhere (the current doc set), accepting the k3s regression and
  the nesting/test costs.

**Proposed next step.** *packages-core* + *pkgs*: a head-to-head spike —
materialize `test-http-server`'s empty manifest both ways, and k3s's manifest
as a per-unit host service; compare unit text, teardown semantics, and test
harness cost. Record the outcome in
[container-model.md](container-model.md) §"Substrate decision".
**DECIDE-BEFORE-MVP** (upstream of 4, 5, 11, 13).

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
**DECIDE-BEFORE-MVP** (fail-closed property).

---

## Decision summary

| # | Decision | Disposition | Owner |
|---|---|---|---|
| 1 | Privilege model **RESOLVED**; (a) enforcement model + policy file format **RESOLVED** (`/etc/aos/policy.toml`: named tier + per-permission overrides + module allowlist + per-tier `systemd-analyze` threshold; image default, Ignition per-host override); (b) k3s set — validated in the D17 spike against kind/k3d/Incus (likely adds `/lib/modules` ro + `/dev/fuse`) | (a) RESOLVED · (b) BEFORE-MVP validation | packages-core / apm / boot / pkgs |
| 2 | Kernel modules as the allowlisted, signature-backed host-fulfilled permission (allowlist location rides 1(a)) | DECIDE-EARLY | packages-core |
| 3 | Networking — **RESOLVED (direction)**: socket-activation default, netns+veth oneshot for outbound, host for k3s | validate in D17 spike | packages-core / pkgs |
| 4 | nspawn-in-VM feasibility — **mooted for MVP** by D17; per-unit lifecycle test remains | test plan | test-infra |
| 5 | Container roots — **RESOLVED**: store path via `RootDirectory=`; **verity-signed `RootImage=` un-deferred** (budget mandate) — built in D21/P9, `CONFIG_DM_VERITY` added | RESOLVED | pkgs / apm |
| 6 | Bake vs. fetch — **RESOLVED by 5**: ordinary closure delivery; bake k3s, fetch workloads | RESOLVED | pkgs / boot |
| 7 | machined/portabled/importd — **RESOLVED: stay disabled** | RESOLVED | pkgs |
| 8 | Install-at-boot — enable **RESOLVED: presets via every-boot `aos-preset.service`** (machine-id + tmpfs-upper + apm idempotency all verified) | install unit remains BEFORE-MVP | boot / apm |
| 9 | Config & credential delivery — **RESOLVED (signed off 2026-06): layered** — secrets via TPM2-sealed systemd-creds (RFC-0006 substrate; satisfies the credstore caution), structured config via apm artifact + manifest schema, simple via `EnvironmentFile=`; hot reload built (D25) | RESOLVED | packages-core / apm |
| 10 | Boundary labeling — **RESOLVED**: computed confinement label | RESOLVED | packages-core |
| 11 | Upgrade/rollback — **RESOLVED (direction)** under D17: unit-semantics restarts, `KillMode=process` preserved for k3s | RESOLVED (direction) | apm / packages-core |
| 12 | Package metadata — **RESOLVED (hybrid)**: TOML carries target/requires/permissions; units ride the closure | RESOLVED | apm / packages-core |
| 13 | Performance & init strategy — largely mooted for MVP by D17 | DEFER | pkgs / test-infra |
| 14 | Module-tree dissolve sequencing — **RESOLVED**: dissolve into `pkgs/` `expose` blocks ([migration.md](migration.md)) | RESOLVED | packages-core |
| 15 | Unit naming — **RESOLVED: `aos-pkg-<name>`** | RESOLVED | packages-core |
| 16 | Runtime unit placement — **RESOLVED**: `/var/etc` attach dir + preset lines (tmpfs upper forced it) | RESOLVED | boot / apm |
| 17 | Execution substrate — **RESOLVED (direction)**: per-unit default, nspawn deferred; spike = validation | validate | packages-core / pkgs |
| 18 | Cross-package dependencies — **RESOLVED (direction)**: flat `requires` ordering first, then **typed capability routing** (provided/required typed caps → fd-pass/`BindReadOnlyPaths=`/`JoinsNamespaceOf=`, least-privilege; Fuchsia `offer`/`use` in AOS's flat idiom) | RESOLVED (direction) | apm / packages-core |
| 19 | Registry schema capability gate (fail-open on old clients) | DECIDE-BEFORE-MVP | apm |
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
- **No premature config commitment.** Config delivery (Decision 9) stays open;
  credstore is one option among several, not the default.
- **Needs verification.** The "machined disabled" flags, the kernel namespace
  configs for nesting, and the exact `aos-seed-profiles` ordering are reported
  from investigation and should be re-confirmed against the tree before the MVP
  lands.
