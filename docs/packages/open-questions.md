# Packages: open questions, risks & decisions

Status: planning
Audience: anyone planning the roles→packages rename, the systemd-nspawn
container model, apm/registry integration, or the boot-time activation path
(`modules/roles/`, `crates/aos-package/`, `modules/services/ignition.nix`,
`lib/testing/`, `pkgs/system/systemd.nix`).

This is the "what we must decide" doc for the packages direction: fold the
existing "roles" concept (`modules/roles/`) into AOS's apm/registry **package**
system, where a package is the registry-installable unit (`apm install`) and
**some** packages additionally expose a systemd-nspawn container plus an
`aos-<pkg>.target` handle. It consolidates the open risks, unknowns, and
pending decisions surfaced across the investigation. Each entry has a
statement, why it matters, the options, and a proposed owner / next step. It
deliberately leaves the **config delivery** decision open. Sibling docs:
[README.md](README.md), [container-model.md](container-model.md),
[apm-integration.md](apm-integration.md), [boot-activation.md](boot-activation.md),
[config.md](config.md), [migration.md](migration.md). The prior design this
builds on is `docs/roles/targets-and-sandbox.md`.

A quick note on honesty up front: two things in this plan do **not** fit the
clean model and are called out throughout. (1) **k3s is not a real container** —
it needs host network, host cgroups, and globally-loaded kernel modules, so its
"container" is a nominal mount/UTS wrapper, not a security boundary. (2)
**config delivery is genuinely undecided** — no option is a clear winner, and we
must not let "settle on credstore" sneak in by default.

---

## How to read this

Each decision is tagged with a rough disposition:

- **DECIDE-BEFORE-MVP** — blocks a first working containerized package.
- **DECIDE-EARLY** — shapes the schema/API; expensive to change later.
- **DEFER** — can ship a placeholder and revisit; must be explicitly tracked.

Owners are roles, not people: *packages-core* (the rename + module synthesis),
*apm* (`crates/aos-package/`), *boot* (`modules/services/ignition.nix`),
*test-infra* (`lib/testing/`), *pkgs* (`pkgs/system/systemd.nix`,
container-root builders).

---

## 1. Is k3s ever a real container? (the honesty question)

**Statement.** k3s (`modules/roles/kubernetes/k3s-worker.nix`,
`k3s-control-plane.nix`, `k3s-combined.nix`) is being folded into the package
model, but it cannot be a sandboxed workload. It needs the host network
namespace (CNI configures host routes/bridge, flannel VXLAN on port 8472),
the host cgroup hierarchy (kubelet manages host cgroups — it already declares
`Delegate=yes` and `TasksMax=infinity`), full iptables/nftables control, and
globally-loaded kernel modules (`br_netfilter`, `vxlan`, `ip_set`).

**Why it matters.** If we describe k3s as "containerized" we mislead operators
about the security boundary. A `systemd-nspawn --network=host --ipc=host` wrapper
isolates only the mount and UTS namespaces — a crash or compromise inside it
still affects the host. Full isolation (`--network=private`) is a hard NO: it
breaks pod networking.

**Options.**

| Option | What it is | Verdict |
|---|---|---|
| A. Nominal nspawn (`--network=host`, `--keep-unit`) | Mount/UTS isolation only; host net/cgroups inherited | Works; must be labeled "not a security boundary" |
| B. No container at all — k3s is a "host-privileged" / "infrastructure" package class | k3s runs as plain target-gated units (the `targets-and-sandbox.md` model) | Most honest; simplest |
| C. Full isolation | `--network=private` etc. | Not viable — breaks k3s |

**Proposed next step.** *packages-core* + *pkgs*: introduce an explicit package
**class** distinction — `workload` (real nspawn sandbox) vs. `infrastructure`
(host-privileged, container is nominal or absent). Default k3s to
*infrastructure*. Document the boundary honestly in
[container-model.md](container-model.md). Decide whether infrastructure packages
get a nominal nspawn (Option A) or stay as bare target-gated units (Option B) —
**DECIDE-EARLY**, leaning B for k3s unless a concrete isolation win appears.

---

## 2. Kernel modules are global — there is no per-container module namespace

**Statement.** k3s needs `br_netfilter`, `vxlan`, `ip_set`. Kernel modules load
into the single host kernel; containers inherit them and cannot scope them. In
the `targets-and-sandbox.md` model these load via a synthesized
`aos-<pkg>-modules.service` (`modprobe -a …`) gated by the package target.

**Why it matters.** It undercuts the "package is self-contained" story: enabling
a package mutates global kernel state that does not cleanly reverse (the
`targets-and-sandbox.md` teardown trade-off — modules stay loaded after
`systemctl stop`). For a containerized workload this is a leak out of the
sandbox.

**Options.**
- Keep module loading host-side, gated by the package target (current design).
  Honest, simple, one-way on stop.
- Forbid `kernel.modules` on *workload* (real-container) packages entirely;
  allow it only on *infrastructure* packages. Pushes the leak to the class that
  already admits host privilege.

**Proposed next step.** *packages-core*: tie `kernel.modules` to the package
**class** from Decision 1 — permitted (and host-global) for *infrastructure*,
disallowed-by-assertion for *workload*. Document the non-reversibility.
**DECIDE-EARLY**.

---

## 3. Container networking model

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
  ports flow through the existing `aos-<pkg>-firewall.service` against the base
  `allowed_tcp`/`allowed_udp` sets.
- `--network-zone` for multi-container L2 (less documented; revisit if needed).
- `--network=host` only for infrastructure packages.

**Proposed next step.** *packages-core* + *pkgs*: spec veth as the workload
default and generate the host `.network` from the package definition; document
host-net for infrastructure. Resolve naming without `nss-mymachines` (explicit
`/etc/hosts` or DNS). **DECIDE-EARLY** for the schema (how a package declares
its network mode), **DEFER** zone support.

---

## 4. nspawn inside test VMs — feasibility

**Statement.** Tests must run containerized packages inside the existing
harnesses (`lib/testing/vm.nix`, `firecracker.nix`, `fleet.nix`). The guest
kernel has the needed namespace configs and ships systemd-nspawn; nesting
(systemd → nspawn → systemd) is expected to work.

**Why it matters.** If nspawn-in-VM is flaky, every containerized-package test is
flaky. Known risk areas: cgroup-v2 delegation depth, writable `/proc/sys` for
container init, `/dev` population, and the fact that **machined is disabled**
(see Decision 7) so `machinectl`-based introspection (`vm.exec_in_container`,
`vm.container_status`) needs an alternative.

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

## 5. Container root images — build, registry delivery, and signing

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
separate artifact is **DECIDE-BEFORE-MVP** if Option 2 is chosen.

---

## 6. Image size & closure growth

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

## 7. machined / portabled / importd are disabled by design

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

**Who runs expose vs. enable.** A sub-question that both
[apm-integration.md](apm-integration.md) §4 and [boot-activation.md](boot-activation.md)
§4.2 defer to here: the **expose phase** (materialize the package's unit files
into the writable `/etc` overlay + drop the `aos-pkg-<package>.target`) is
distinct from **enabling** that target (wiring the `multi-user.target.wants`
symlink and starting it). The working assumption across the doc set is that
**`apm install` performs expose**, and **enable is a separate, tightly-ordered
step** (a follow-on `aos-enable-packages.service`, or `apm` itself per §3.2
Option B). Firming up the ownership split — and whether enable is ever expressed
via Ignition `storage.links` (Option A) instead — is part of this decision.

**Proposed next step.** *boot* + *apm*: design the desired-packages handoff and
the oneshot ordering in [boot-activation.md](boot-activation.md); fix the
expose-vs-enable ownership split; define idempotency via state.json and behavior
when the registry is unreachable (air-gapped / on-prem must not hard-fail boot).
**DECIDE-BEFORE-MVP**.

---

## 9. Config & credential delivery (EXPLICITLY OPEN — do NOT settle on credstore)

**Statement.** How per-instance config and secrets reach a package (and cross the
nspawn boundary) is **undecided**. The working baseline is k3s today: Ignition
writes `/etc/rancher/k3s/k3s.env`, consumed via systemd `EnvironmentFile=`.

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

## 10. Security boundary strength & honest labeling

**Statement.** Workload packages get a real nspawn sandbox (own PID1,
namespaces); infrastructure packages (k3s) get host privilege. `--private-users`
is available but has file-ownership/`/dev` trade-offs; the investigation
recommends `--private-users=no` for workloads with seccomp/mount restrictions
instead.

**Why it matters.** Operators must know exactly which packages are isolated and
which are not. Misrepresenting an infrastructure package as sandboxed is a
security-communication failure, not just a doc nit.

**Options.**
- Encode the boundary in the package **class** (Decision 1) and surface it in
  `apm show` / the package metadata, so isolation level is queryable.
- Default workloads to `--private-users=no` + seccomp; revisit user-namespacing
  later.

**Proposed next step.** *packages-core*: make isolation level a first-class,
introspectable property of every package; document seccomp/mount defaults in
[container-model.md](container-model.md). **DECIDE-EARLY**.

---

## 11. Upgrade & rollback of containerized packages

**Statement.** apm already has a generation/profile model
(`/var/lib/profiles/{scope}/gen-N/`, atomic `current` symlink switch, anti-
rollback floor in the registry). It is unclear how this maps onto a running
nspawn container and its `/var/lib/machines` rootfs and persistent state.

**Why it matters.** Upgrading a workload means swapping the container root and
restarting the unit; rollback means switching back a generation. Stateful
packages (databases) complicate this (persistent volumes, snapshots). For k3s,
restart **drains workloads** — upgrade is disruptive. Without a defined story,
upgrades risk orphaned roots in `/var/lib/machines`, state loss, or wedged
units.

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

## 12. Package metadata: how a package declares a container/service

**Statement.** `PackageMeta` (`crates/aos-package/src/types.rs`) and the registry
TOML have **no** field for systemd units, a container rootfs, env/config refs, or
an `aos-<pkg>.target`. Three placement options exist: extend the registry TOML,
ship a `.aos-manifest` in the closure, or add a per-registry manifest section.

**Why it matters.** This is the schema that everything else keys off (install
hook, activation, container launch, config). Getting it wrong is expensive to
migrate (the registry is content-addressed and signed). It must also express the
package **class** (Decision 1), network mode (Decision 3), isolation level
(Decision 10), and container-root reference (Decision 5).

**Options.**
- Extend registry `packages/<letter>/<name>.toml` with optional
  `[…container]` / `[…services]` sections (registry-versioned, signed by the
  tag).
- Ship `.aos-manifest.toml` in the store path (discovered at install; travels
  with the closure).
- Hybrid: minimal class/target hints in registry TOML, detailed unit/container
  spec in the closure manifest.

**Proposed next step.** *apm* + *packages-core*: pick the manifest location and
draft the schema (must carry class, target name, container ref, network mode,
isolation level, config hooks). Spec in [apm-integration.md](apm-integration.md).
**DECIDE-EARLY**.

---

## 13. Performance & footprint

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

## 14. The rename itself — blast radius & sequencing

**Statement.** Renaming `roles` → `packages` touches the option tree
(`aos.roles.*` → `aos.packages.*`), the module dir (`modules/roles/` →
`modules/packages/`), the bundle (`system.build.ignitionRolesBundle` →
`packagesBundle`), the Ignition path (`/etc/aos/ignition-roles/<name>` →
`/etc/aos/packages/<name>`), `lib/testing/fleet-spec.nix` (`roles` →
`packages`), `lib/modules/systemd/render-role.nix`, and ~6 fleet test files.
Per the investigation it is a **pure rename** with **zero logic change** (~15
files renamed, ~10 edited, ~200–300 lines).

**Why it matters.** It is the prerequisite for everything else, but it collides
with the in-flight `targets-and-sandbox.md` work on the `roles-as-targets`
branch (PR #28). Doing the rename and the container model in one change would be
hard to review; doing them out of order risks churn.

**Options.**
- Land `targets-and-sandbox.md` first (target synthesis on the `roles` name),
  then a mechanical rename, then the container/apm work. Smaller reviewable
  steps.
- Rename first, then targets, then containers. Risks reworking the target naming
  twice (`aos-<role>` → `aos-pkg-<package>`).

**Proposed next step.** *packages-core*: sequence as targets → rename →
container-model to avoid renaming synthesized unit names twice; capture the
mechanical rename table and validation gates (`aos fmt --check`,
`checks.eval`, `checks.vm.boot`, fleet) in [migration.md](migration.md).
**DECIDE-BEFORE-MVP** (sequencing).

---

## 15. Systemd unit naming under the package model

**Statement.** The `targets-and-sandbox.md` model synthesizes `aos-<role>.target`
plus `aos-<role>-{modules,sysctl,firewall}.service`. Under packages these become
`aos-pkg-<package>.target` and `aos-pkg-<package>-{modules,sysctl,firewall}.service`,
plus a container unit (e.g. `aos-pkg-<package>` nspawn service).

**Why it matters.** Unit names land in the global systemd namespace and are
referenced by Ignition fragments, fleet-test assertions, and operator muscle
memory. Changing them later is a breaking change.

**Options.**
- `aos-pkg-<package>-…` (explicit; recommended in the investigation for
  namespace clarity).
- Shorter prefixes (`pkg-`, `sys-`) — risk collision / less clarity.

**Proposed next step.** *packages-core*: fix the naming convention **once**,
before Decision 14's rename, and assert it. **DECIDE-EARLY**. The doc set's
examples now use `aos-pkg-<name>` consistently; this entry records that the
naming is a decision, not a fait accompli.

---

## 16. Writable /etc overlay path for runtime-installed package units

**Statement.** [apm-integration.md](apm-integration.md) §4.1 calls this **the
single biggest unresolved mechanism**. Role/package units are baked into the
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

## Decision summary

| # | Decision | Disposition | Owner |
|---|---|---|---|
| 1 | k3s container class (real vs. nominal vs. none) | DECIDE-EARLY | packages-core / pkgs |
| 2 | Kernel modules tied to package class | DECIDE-EARLY | packages-core |
| 3 | Container networking model (veth/host/zone) | DECIDE-EARLY | packages-core / pkgs |
| 4 | nspawn-in-VM test feasibility prototype | DECIDE-BEFORE-MVP | test-infra |
| 5 | Container root build + delivery + signing | DECIDE-EARLY / -BEFORE-MVP | pkgs / apm |
| 6 | Image size: bake vs. fetch-at-boot | DECIDE-EARLY | pkgs / boot |
| 7 | machined/portabled/importd stay disabled | DECIDE-EARLY | pkgs |
| 8 | Install-at-boot via Ignition + apm | DECIDE-BEFORE-MVP | boot / apm |
| 9 | Config & credential delivery | DEFER (open) | packages-core / apm |
| 10 | Security boundary strength & labeling | DECIDE-EARLY | packages-core |
| 11 | Upgrade/rollback of containers | DECIDE-EARLY | apm / packages-core |
| 12 | Package metadata schema (container/service) | DECIDE-EARLY | apm / packages-core |
| 13 | Performance & init strategy | DEFER (measure) | pkgs / test-infra |
| 14 | Rename blast radius & sequencing | DECIDE-BEFORE-MVP | packages-core |
| 15 | Systemd unit naming convention | DECIDE-EARLY | packages-core |
| 16 | Writable /etc overlay path for runtime-installed package units | DECIDE-BEFORE-MVP | boot / apm |

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
