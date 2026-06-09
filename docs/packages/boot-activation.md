# Boot activation: install at boot via Ignition + apm, then enable

Status: planning

This doc specifies the boot-time flow for the new **packages** model (the
rename and refold of today's `roles` into AOS's `apm`/registry system — see
[README.md](README.md) and [migration.md](migration.md)). The shape is:
Ignition **declares** the package set, a boot-stage step runs **apm** to
**install** those packages into the system profile, and then each package is
**enabled** — for plain packages that means reaching `aos-pkg-<name>.target`,
and for container packages it means starting the `systemd-nspawn` instance
behind that target (see [container-model.md](container-model.md)). The
package files ship **inert in the image**; install makes their store closure
present and their units reachable; enable activates them. Config delivery that
those enabled units consume is **explicitly open** — see [config.md](config.md)
and [open-questions.md](open-questions.md) — and is deliberately not settled
here.

This is a planning doc. Where the current code already does part of this, the
real file/line is cited. Where the mechanism does not yet exist, it is marked
**(new)** or **needs verification** rather than presented as built.

---

## 1. The three states: inert → installed → enabled

The model has three distinct states, and the boot flow walks a package through
all three. Keeping them separate is the whole point — it is what lets a package
be present in the image without running, and lets `apm`/Ignition decide per host
which packages actually come up.

| State | What it means | Who establishes it |
|-------|---------------|--------------------|
| **Inert (in image)** | The package's *system-level* units (the synthesized `aos-pkg-<name>.target` and its member units / gated side-effect services) exist as regular files in the EROFS `/etc/systemd/system/`, but nothing `Wants=` them. The package's store closure may or may not be in the local store yet. | Image build (the package module, evaluated into `system.build.toplevel`) |
| **Installed** | The package's store closure is present in the local `/nix/store`, recorded in the system profile generation, and (for container packages) its container root image is available under `/var/lib/machines`. | `apm install` at boot |
| **Enabled** | The package is *running*: `aos-pkg-<name>.target` is reached, pulling member units; for container packages the `systemd-nspawn` service behind the target is started. | systemd activation, triggered by the Ignition-written enable hook |

The in-flight roles-as-targets design (`docs/roles/targets-and-sandbox.md`,
PR #28 — **not yet on this branch**, cite as in-flight) already establishes the
"inert in EROFS, one activation root per role" half: member units are baked into
EROFS as plain files with no `multi-user.target.wants` symlink, and a single
synthesized target is the sole activation root. The packages work inherits that
directly; the new part here is the **installed** state in the middle, supplied
by `apm`.

> **Honest gap.** Today these two halves are not connected. The targets/sandbox
> design assumes the units are baked into the image and merely *enabled* via
> Ignition; it does **not** run `apm install` at boot. There is currently **no**
> boot-stage step that installs *additional* apm packages — `aos-seed-profiles`
> (below) seeds only the system profile. Bridging that is the core new work this
> doc plans.

---

## 2. What exists today: Ignition stages and the seed step

The boot path is driven by Ignition (coreos/ignition 2.25.1) run as a sequence
of staged systemd services in the initrd, defined in
`modules/services/ignition.nix`. The relevant ordering (from that file):

```
fetch  →  disks  →  mount  →  ignition-files  →  (switch-root)  →  stage 2
```

Key services and their wiring (real, from `modules/services/ignition.nix`):

- **`ignition-fetch` / `ignition-disks` / `ignition-mount`** — standard Ignition
  stages; each is a oneshot running
  `ignition --platform=$PLATFORM_ID --root=... --stage=<stage>`
  (`stageServiceConfig`, ~line 65–72). `ignition-disks` is strictly declarative
  against an existing partition table (comments ~line 155–167).
- **`nix-overlay-setup.service`** (~line 548) — mounts the writable `/nix`
  overlay (immutable lower + persistent `/var/nix` upper) and seeds the Nix DB.
  This is the service that makes the store **writable**, which is a hard
  prerequisite for `apm install` importing NARs.
- **`aos-seed-profiles.service`** (~line 595) — ordered `After=nix-overlay-setup`
  (~line 607/612). On first boot it reads the toplevel from the
  `/sysroot/aos-toplevel` seed pointer (~line 588/624) and writes
  `/var/lib/profiles/system/state.json` with generation 1 marked
  `registry: "seed"` (~line 642–661), a sentinel for "this gen was baked into the
  image, not fetched from a registry."
- **`ignition-files.service`** (~line 316) — the Ignition **files** stage
  (`stage = "files"`, ~line 354). It writes to the per-generation `/etc` tmpfs
  lower (`/run/etc/ignition-<gen>/...`), which persists through switch-root into
  stage 2 (comment ~line 377). This is where role/package Ignition fragments are
  materialized — units, and (under the *old* roles model) the global drop-ins.

Network: `network-online.target` is **not** a static dependency of the Ignition
stages — the module notes (~line 112–135) that on cloud platforms networking is
itself configured by an Ignition transaction, so a static
`Wants=network-online.target` can't be used; instead a stage explicitly runs
`systemctl start network-online.target` when network is required. This matters
for the install step (§4): fetching NARs needs network, but baked/offline
installs do not.

The `apm`/`apr`/`aos` binary and `tar` (needed to extract registry git
archives) are shipped in every image via `modules/base/apm.nix` (`pkgs.aos`,
`pkgs.tar` in `environment.systemPackages`, ~line 20), and
`/root/.config/apm/registries.d/` is pre-created via tmpfiles.d (~line 26–32).
So the install *tooling* is already present in the image; what is missing is the
boot step that invokes it from the Ignition-declared list.

---

## 3. Ignition declares the package list

Ignition is the per-host instance metadata. Under the packages model it carries
two things: a **declared package set** (what to install) and, separately, an
**enable hook** per package (what to bring up). These are distinct because
install and enable are distinct states (§1).

### 3.1 Declaring the set

The declared set is delivered as an Ignition-written file that the boot install
step (§4) reads. Strawman path and shape **(new)**:

```
/etc/aos/packages.d/desired.toml      # written by ignition-files
```

```toml
# Written via Ignition storage.files (data: URL or inline), per host.
[[registries]]
name    = "public"
url     = "https://registry.example.com"
channel = "stable"           # or tag = "1.4.0", or commit = "..."

[[packages]]
name = "k3s-worker"
# version pin optional; omit to take the channel's resolved version

[[packages]]
name = "web-frontend"
```

This mirrors how registries are already configured post-boot
(`apm registry add` writes `registries.d/<name>.toml`), just laid down by
Ignition instead of by hand. Writing it through `storage.files` keeps it inside
Ignition's existing idempotent files stage rather than inventing a new Ignition
section. **Needs verification:** whether to reuse `registries.d/` verbatim plus a
separate `packages.d/desired.toml`, or fold both into one document.

### 3.2 The systemd.units[].enabled removal — how "enabled" is expressed now

The original roles design enabled a role by emitting **one**
`systemd.units[]` entry per role in the Ignition config with `enabled: true`,
relying on Ignition to read the unit's `[Install]` section and synthesize the
`multi-user.target.wants/<unit>` symlink. **That field was removed** for the
packages direction: per Ignition spec **v12 §5.6.4**, `systemd.units[].enabled`
(and the implicit enable-by-`[Install]` behavior it drove) is no longer
available to us for roles/packages. So "enable" can no longer be a single
`enabled: true` toggle in the fetched/merged Ignition fragment.

How enable is expressed instead **(new — needs verification against the exact
v12 surface we target)**:

- **Option A — explicit wants link via `storage.links`.** The enable hook becomes
  a `storage.links[]` entry that creates
  `/etc/systemd/system/multi-user.target.wants/aos-pkg-<name>.target` →
  `…/aos-pkg-<name>.target`. This is what the old design already does for member
  units' side-effects (storage.links are how role drop-ins were shipped), so it
  is a known-working primitive — we just point it at the target's wants symlink
  instead of relying on `enabled`. Honest cost: we re-implement, in our own
  fragment generator, the `[Install]`→symlink logic Ignition used to do for us.
- **Option B — enable performed by `apm` at install time.** Since the package is
  being installed by `apm` at boot anyway (§4), `apm` can run
  `systemctl enable aos-pkg-<name>.target` (or write the wants symlink into the
  per-gen `/etc` lower) as part of `install`/an `apm enable` step. This keeps
  Ignition out of the enable business entirely and puts install+enable in one
  tool. Honest cost: enable now depends on the install step succeeding and on
  `apm` knowing the target name a package exposes (requires the container/target
  metadata from [apm-integration.md](apm-integration.md)).

Recommendation for planning: **lean Option B** (enable via `apm`), with Option A
as the fallback for packages with no `apm`-visible target. Either way the enable
*decision* still originates in the Ignition-declared set — the host that lists
`k3s-worker` in `desired.toml` is the host that enables it.

---

## 4. The install step: which unit, which stage, ordering

Insert a **(new)** boot-stage oneshot, `aos-install-packages.service`, that
reads the declared set (§3.1) and runs `apm` to install it.

### 4.1 Placement and ordering

It must run after three things are true: the store is writable, the system
profile exists, and (only if fetching) the network is up.

```ini
# aos-install-packages.service  (new)
[Unit]
Description=Install Ignition-declared apm packages at boot
After=nix-overlay-setup.service aos-seed-profiles.service
Requires=nix-overlay-setup.service
After=ignition-files.service          # desired.toml has been written
ConditionPathExists=/etc/aos/packages.d/desired.toml
# Network only when the install needs to fetch (see 4.4); the unit itself
# starts network-online.target on demand rather than hard-depending on it.

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/apm install --from /etc/aos/packages.d/desired.toml
StandardOutput=journal+console
```

Two viable placements:

1. **Late initrd, before switch-root** — alongside the other Ignition stage
   units, after `aos-seed-profiles`. Pro: the system is "complete" before stage
   2 starts, matching the seed-then-switch shape. Con: networking in the initrd
   is more constrained, and `apm`'s registry/git machinery is heavier than the
   minimal initrd contract.
2. **Stage 2, before `multi-user.target`** — as a normal systemd service.
   Pro: full userspace (network stack, `tar`, `apm` all in their normal form);
   matches where `apm` runs post-boot today. Con: packages are installed
   slightly later in boot.

Recommendation: **stage 2**, ordered `Before=multi-user.target` and after the
overlay/seed/network preconditions. This is also what the
[testing](#7-testing) and fleet harnesses are set up to observe. **Needs
verification:** that `nix-overlay-setup`/`aos-seed-profiles` state is visible
from stage 2 (they run in the initrd and the overlays persist across
switch-root, so it should be — confirm the profile dir is on the persistent
`/var`).

### 4.2 Enable follows install

Working assumption: `apm install` performs the **expose phase** (materialize
unit files into the writable `/etc` overlay + drop the target); **enabling** the
target is a separate, tightly-ordered step — see Decision 8 in
[open-questions.md](open-questions.md), which covers who runs expose vs. enable.
Under Option B (§3.2) that enable step (e.g. `aos-enable-packages.service`,
ordered after install) runs the enable after install completes:

```
install (apm install ...)  →  enable (systemctl enable/start aos-pkg-<name>.target)
```

For plain packages, "enable" reaches the target and its member units (the
gated `aos-pkg-<name>-modules/sysctl/firewall.service` from the targets-and-
sandbox design) come up under it. For **container** packages, the target's
`Wants=` pulls the `systemd-nspawn` instance — see
[container-model.md](container-model.md) for the unit shape. The boot flow does
not need to know which kind it is; it enables the target and the package's own
unit graph decides what runs.

### 4.3 Idempotency across generations and upgrades

The install step must be safe to run on **every** boot, not just first boot,
because a host's declared set may change and image upgrades produce new
generations.

- **First boot:** `desired.toml` packages are not yet installed → `apm install`
  resolves, downloads/imports, and creates a new profile generation. This is the
  full path.
- **Subsequent boots, unchanged set:** `apm install` of already-present packages
  must be a no-op (closure already in store, already in current generation).
  `apm`'s profile model already supports this — installs create a new generation
  by copying the previous gen's roots (`copy_roots`) and adding deltas
  (`crates/aos-package/src/install.rs`), and importing an already-present NAR is
  idempotent. The boot step should detect "no change" and **not** churn a new
  generation every boot. **Needs verification:** that `apm install` is
  generation-stable when the input set is unchanged (i.e., it does not always
  mint a new generation). If it does, the boot step must guard with a marker
  (e.g. a hash of `desired.toml` recorded in `/var/lib/aos/packages.installed`)
  and skip when unchanged — analogous to Ignition's own `resultFilePath`
  first-boot marker.
  > **Profile vs. scope (needs verification).** Two distinct things are at play
  > and must not be conflated: the **system profile** holds the toplevel plus
  > the packages **baked** into the image (seeded `registry: "seed"`), while
  > **runtime apm-installed** packages live in an apm package profile/scope
  > (`/var/lib/profiles/{scope}/`, the `{scope}` parameter referenced in §1 and
  > §4.3 and in [apm-integration.md](apm-integration.md) §5). The intended
  > relationship — whether runtime packages share the `system` scope or get
  > their own — is **needs verification** against
  > `crates/aos-package/src/profile/mod.rs`. The key property either way: an
  > apm package generation is independent of the *toplevel* (system-image)
  > generation, so a host-image upgrade does not by itself churn the
  > apm-installed package set.

- **Image upgrade (new generation of the *system*):** the baked-in packages
  belong to the new toplevel (gen seeded `registry: "seed"`). apm-installed
  packages live in their apm package profile/scope (see the note above)
  independently of the toplevel generation. The boot step re-runs against
  `desired.toml`; packages already
  present remain, newly-added ones install, removed ones are **not** auto-removed
  (removal is a separate, explicit `apm` operation — see
  [apm-integration.md](apm-integration.md)). **Open:** whether a package dropped
  from `desired.toml` should be disabled on next boot. Reconciling "declared set
  vs installed set" (prune) is a policy decision; default to **additive only**
  for safety and call removal out as future work.

The enable step is naturally idempotent: `systemctl enable`/the wants symlink is
a fixed-point operation, and starting an already-active target is a no-op.

### 4.4 Offline / baked vs fetched

Two install sources, chosen per package / per host:

| Mode | Where the closure comes from | Network at boot | Use |
|------|------------------------------|-----------------|-----|
| **Baked / offline** | Package closure is already in the image's store (built into `system.build.toplevel`'s closure or shipped alongside in the rootfs). `apm install` only needs to register it in the profile and enable — no download. | **Not** required | Air-gapped fleets; infrastructure packages like k3s that should never depend on a registry being reachable at boot |
| **Fetched** | `apm install` downloads NARs from the registry's `[[caches]]` pointer over dumb-HTTP, verifying hashes and trust (TOFU-pinned Ed25519 key) before import. | Required (`apm install` triggers `network-online.target`) | Hosts that pull optional/workload packages not present in the base image |

Baked mode is the honest default for **k3s**: it is an infrastructure package
that wants host privilege (global kernel modules, host net/cgroups), is large,
and should come up deterministically without a registry round-trip. Its closure
(and, if containerized, its container root under `/var/lib/machines`) should be
present in the image, and the boot step's job for k3s is install-as-register +
enable, not fetch. See [container-model.md](container-model.md) for why k3s's
container is *nominal* (host net/cgroups, not a security boundary) and
[migration.md](migration.md) for how the existing k3s role maps onto this.

For fetched packages, the install step needs network, so it explicitly pulls
`network-online.target` (the same on-demand pattern Ignition stages use, per
`modules/services/ignition.nix` ~line 112–135) rather than hard-ordering all
boots behind network — keeping baked/offline boots from blocking on a network
that may not exist.

---

## 5. End-to-end boot sequence

Putting it together (stage-2 placement, Option B enable):

```
initrd:
  ignition-fetch → ignition-disks → ignition-mount
  ignition-files            # writes /etc/aos/packages.d/desired.toml into per-gen /etc lower
  nix-overlay-setup         # /nix writable, Nix DB seeded
  aos-seed-profiles         # /var/lib/profiles/system/state.json (gen 1, registry:"seed")
  switch-root → systemd PID 1

stage 2:
  (network-online.target reached on demand if any package is "fetched")
  aos-install-packages.service          # apm install --from desired.toml  [INSTALLED]
    └─ (Option B) apm enable / systemctl enable aos-pkg-<name>.target
  aos-enable... → systemd reaches aos-pkg-<name>.target       [ENABLED]
       ├─ plain package: member units + gated modules/sysctl/firewall services
       └─ container package: systemd-nspawn@<name> instance (see container-model.md)
  multi-user.target
```

The package's system units were **inert in EROFS** the whole time (built in);
`aos-install-packages` moved them to **installed**; the enable hook moved them to
**enabled**. Disabled hosts (package not in `desired.toml`) never install or
enable it — its units sit inert in EROFS, wanted by nothing, exactly as the
targets-and-sandbox "strict disabled = inert" guarantee requires.

---

## 6. Honest gaps and limits

- **The bridge does not exist yet.** `aos-seed-profiles` seeds only the system
  profile; there is no boot step today that runs `apm install` for additional
  packages. `aos-install-packages.service` is entirely new.
- **`systemd.units[].enabled` is gone (v12 §5.6.4).** Enable must be expressed
  via `storage.links` (Option A) or by `apm` (Option B). We must re-implement the
  `[Install]`→wants-symlink logic ourselves; Ignition no longer does it for
  roles/packages. The exact v12 surface we target **needs verification**.
- **Idempotency depends on `apm` generation behavior.** If `apm install` mints a
  generation on every invocation regardless of input, the boot step will churn
  generations each boot and needs an explicit "unchanged set" guard. **Needs
  verification.**
- **k3s does not fit the sandbox cleanly.** It must be a **baked/offline**
  infrastructure package with a **nominal** container (host net/cgroups, global
  kernel modules) — call this out rather than pretend it is a sandboxed workload.
  Details in [container-model.md](container-model.md).
- **Config is not solved here.** The enabled units consume configuration whose
  delivery is **explicitly open** (do not assume credstore). The boot flow only
  guarantees *units come up*; whether they have valid config to consume is the
  subject of [config.md](config.md). For k3s today, config arrives via Ignition
  `storage.files` (`/etc/rancher/k3s/k3s.env`) consumed by `EnvironmentFile=` —
  documented as the current working pattern, not a decision.
- **Prune semantics undecided.** Removing a package from `desired.toml` does not
  currently disable/uninstall it on next boot (additive-only). Reconciliation is
  future work; tracked in [open-questions.md](open-questions.md).

---

## 7. Testing

The flow is observable end-to-end with the existing harnesses (see the testing
findings; harness files under `lib/testing/`):

- **Eval:** assert the package module emits exactly one `aos-pkg-<name>.target`
  and that no `multi-user.target.wants` symlink is baked into EROFS for it
  (inert-in-image invariant).
- **Single-VM check:** boot with `desired.toml` declaring one package; assert
  `aos-install-packages.service` succeeded, the closure is in `/nix/store`, the
  target is enabled, and (container case) the `systemd-nspawn` instance is
  active. Re-trigger the service and assert no new generation is minted
  (idempotency).
- **Fleet:** the existing `apm-e2e` pattern (registry server + client running
  `apm update` / `apm install`) extended so the client's install is driven by an
  Ignition-declared `desired.toml` rather than a manual `apm install`, proving
  the Ignition→apm bridge. k3s fleet tests stay baked/offline.

---

## See also

- [README.md](README.md) — overview of the packages model and doc set
- [container-model.md](container-model.md) — nspawn containers, the nominal-vs-real boundary, k3s
- [apm-integration.md](apm-integration.md) — registry metadata, target/container declaration, install/enable/remove
- [config.md](config.md) — config-delivery design space (open)
- [migration.md](migration.md) — roles → packages rename and the k3s mapping
- [open-questions.md](open-questions.md) — unresolved decisions (prune, enable mechanism, config backend)
