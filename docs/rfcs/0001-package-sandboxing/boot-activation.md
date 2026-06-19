# Boot activation: install at boot via Ignition + apm, then enable

Status: planning

This doc specifies the boot-time flow for the **packages** model, which folds
into AOS's `apm`/registry system — see [README.md](README.md) and
[migration.md](migration.md). The shape is:
Ignition **declares** the package set, a boot-stage step runs **apm** to
**install/reconcile** those packages into the system package profile, and then each package is
**enabled** — reaching `aos-pkg-<name>.target`, which starts the generated
per-unit service behind that target (see [container-model.md](container-model.md)). The
package files ship **inert in the image**; install makes their store closure
present and their units reachable; enable activates them. Config delivery that
those enabled units consume is layered — see [config.md](config.md) and
[open-questions.md](open-questions.md).

This is an implementation-tracking doc. Where a mechanism is now built, this doc
states the resolved shape; where future work is conditional, it is called out as
future rather than as part of the boot path.

---

## 1. The three states: inert → installed → enabled

The model has three distinct states, and the boot flow walks a package through
all three. Keeping them separate is the whole point — it is what lets a package
be present in the image without running, and lets `apm`/Ignition decide per host
which packages actually come up.

| State | What it means | Who establishes it |
|-------|---------------|--------------------|
| **Inert (in image)** | The package's *system-level* units (the synthesized `aos-pkg-<name>.target` and its member units / gated side-effect services) exist as regular files in the EROFS `/etc/systemd/system/`, but nothing `Wants=` them. The package's store closure may or may not be in the local store yet. | Image build (the package module, evaluated into `system.build.toplevel`) |
| **Installed** | The package's store closure is present in the local `/nix/store`, recorded in the system package profile generation, and its expose artifacts are materialized. | `apm install` at boot |
| **Enabled** | The package is *running*: `aos-pkg-<name>.target` is reached, pulling member units and gated side-effect services. | systemd activation, triggered by preset policy |

The target/activation design ([activation.md](activation.md)) establishes the
"inert in EROFS, one activation root per package" half: member units are baked
into EROFS as plain files with no `multi-user.target.wants` symlink, and a single
synthesized target is the sole activation root. The boot flow builds on that
directly; the **installed** state in the middle is supplied by `apm`.

> **Honest gap.** Today these two halves are not connected. The activation
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
  materialized — units, and the global drop-ins.

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
step (§4) reads. The resolved path and shape:

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
section. **Resolved:** registries stay in `registries.d/`, while desired
packages live in the separate `/etc/aos/packages.d/desired.toml`.

### 3.2 How "enabled" is expressed

> **Canonical statement.** This section is the doc set's single source of truth
> for how enable is expressed. For packages, enable is expressed through the
> **preset mechanism** below — see [activation.md](activation.md) §"Activation"
> and [container-model.md](container-model.md)'s invariant list. Where the docs
> disagree, this section wins.

A single `systemd.units[]` entry per package with `enabled: true` — relying on
Ignition to read the unit's `[Install]` section and synthesize the
`multi-user.target.wants/<unit>` symlink — is **not** available to us: per
Ignition spec **v12 §5.6.4**, `systemd.units[].enabled` (and the implicit
enable-by-`[Install]` behavior it drove) is no longer present for packages. So
"enable" can no longer be a single `enabled: true` toggle in the fetched/merged
Ignition fragment.

**Enable is expressed through systemd presets** — the mechanism every major
distro converged on. Repo verification (below) ruled out relying on systemd's
*native* first-boot preset pass on AOS, so the same policy is applied by one
tiny every-boot oneshot instead:

1. **The image ships default-deny policy:**
   `/usr/lib/systemd/system-preset/99-aos-default.preset` containing
   `disable *` (Arch ships exactly this file). Every `aos-pkg-*.target` is
   inert unless something more specific enables it. (Verified: the image
   ships **zero** preset files today — `-Dinstall-sysconfdir=false`
   suppresses even upstream defaults — so this layer starts clean.)
2. **Ignition writes one per-host preset file** via plain `storage.files`:
   `/etc/systemd/system-preset/20-aos-host.preset`, one
   `enable aos-pkg-<name>.target` line per desired package. No
   `systemd.units[]` surface, no `[Install]`-symlink reimplementation. Preset
   files sort lexicographically with first-match-wins, so `20-…` beats `99-…`.
3. **An every-boot oneshot applies the policy:** `aos-preset.service` runs
   `systemctl preset-all --preset-mode=enable-only`, ordered
   `Before=multi-user.target`. Enablement is **derived state, recomputed from
   the preset files on every boot** — which is also what makes the tmpfs
   `/etc` upper a non-issue (see verification below). Two sharp edges, both
   handled: `--preset-mode=enable-only` is **mandatory** (full mode would try
   to *disable* base services whose `.wants` symlinks are baked into the
   EROFS lower — sshd, nftables — by writing overlay whiteouts over them);
   and because the boot transaction was computed before the symlinks existed,
   the oneshot must follow up with `systemctl start --no-block` for the
   targets it newly enabled, or they would only come up on the *next* boot.
4. **Runtime installs: `apm` runs `systemctl preset aos-pkg-<name>.target`**
   after the expose phase — the exact pattern Fedora's `%systemd_post` /
   `systemd-update-helper` uses — and records the `enable` line in the
   persistent host layer (`/var/etc/systemd/system-preset/`, Decision 16) so
   the next boot's `aos-preset.service` re-derives it. `preset` is idempotent
   and policy-respecting: it enables only what the merged preset files allow,
   so a fleet that ships a stricter preset automatically refuses enablement.

Distro precedent (verified): Debian's auto-enable is itself implemented as
`systemctl preset --preset-mode=enable-only` (deb-systemd-helper, after Debian
bug #772555); Fedora enables only units allowlisted in `90-default.preset` and
replaced scriptlets with `systemd-update-helper` + RPM file triggers; Arch
ships `disable *` and never auto-enables. AOS composes the Arch default with a
Fedora-style per-host allowlist written by Ignition.

**Verified against the tree (previously unresolved — now resolved):**

- **systemd's native first-boot preset pass will never fire on AOS — by
  design, and that is correct.** PID 1 keys "first boot" on
  `/etc/machine-id` being absent or `uninitialized`, but AOS deliberately
  creates the machine-id in the stage-1 initrd (`aos-machine-id.service`,
  `modules/services/ignition.nix:721` — generated from
  `/proc/sys/kernel/random/uuid` into `/sysroot/var/etc/machine-id`) and
  surfaces it through the persistent `/var/etc` overlay layer *before*
  stage-2 PID 1 starts — precisely so the ID persists per host instead of
  being committed by systemd into the throwaway tmpfs upper. Keeping that
  property means PID 1 always sees "not first boot"; hence the explicit
  `aos-preset.service` in step 3, which is equivalent and runs every boot.
- **The `/etc` overlay upper is tmpfs** (`etc-overlay-setup.service`,
  `upperdir=/run/etc/upper-<gen>/upper`): runtime
  `systemctl preset`/`enable` symlinks do **not** survive a reboot. The
  every-boot preset pass makes that irrelevant — the durable truth is the
  preset *files* (EROFS default + per-gen Ignition lower + persistent
  `/var/etc` host layer), not the symlinks.
- **The preset file is in place before PID 1.** The Ignition files stage
  writes into `/run/etc/ignition-<gen>/etc/…` in the initrd, and
  `etc-overlay-setup.service` mounts the 3-layer overlay **before
  switch-root** — stage-2 systemd boots with the merged `/etc` (including
  the preset file) already assembled.
- **Baked enablement is safe.** Base services are enabled by `.wants`
  symlinks generated at build time into the EROFS lower
  (`lib/modules/systemd/lib.nix` `generateUnits`,
  `modules/base/build.nix:291`); enable-only preset application never
  touches them.
- **`-Dfirst-boot-full-preset` is irrelevant** under the explicit-oneshot
  mechanism; the AOS systemd build sets no preset-related flags and need not.

Two alternatives — **Option A** (re-implement `[Install]`→symlink via
`storage.links`) and **Option B** (`apm` runs `systemctl enable`) — are both
**ruled out** in favor of presets: presets subsume both with one oneshot plus
one Ignition-written file, and the policy lives in declarative files rather than
in symlink state. Either way the enable *decision* still originates in the
Ignition-declared set — the host that lists `k3s-worker` in `desired.toml` is
the host whose preset file enables it.

---

## 4. The install step: which unit, which stage, ordering

Use the boot-stage oneshot `aos-install-packages.service` to read the declared
set (§3.1) and run `apm` to install or prune it.

### 4.1 Placement and ordering

It must run after three things are true: the store is writable, the system
profile exists, and (only if fetching) the network is up.

```ini
# aos-install-packages.service
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
[testing](#7-testing) and fleet harnesses are set up to observe. **Verified:**
`aos-seed-profiles` writes `/sysroot/var/lib/profiles/system` — the
persistent `/var` partition — so the sysroot state is visible from stage 2.
Runtime/boot-time `apm install --system` uses `ProfileScope::System`'s package
profile path, `/var/lib/profiles/system-packages/`
(`crates/aos-package/src/types.rs`), keeping package generations independent
from the sysroot generation pointer the seed step initializes.

### 4.2 Enable follows install

`apm install` performs the **expose phase** (materialize unit files into the
writable `/etc` overlay + drop the target); **enabling** is `systemctl preset`
against the merged preset policy (§3.2), run by `apm` immediately after expose
(Decision 8 in [open-questions.md](open-questions.md), resolved to this split):

```
install (apm install ...) → expose (units + target) → systemctl preset aos-pkg-<name>.target → start
```

For service packages, "enable" reaches the target and its member units (the
generated launch service plus the gated
`aos-pkg-<name>-modules/sysctl/firewall.service` units from the
[activation.md](activation.md) design) come up under it. The boot flow does not
need to know a substrate kind; it enables the target and the package's own unit
graph decides what runs.

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
  idempotent. **Verified:** `apm install` is generation-stable —
  `install.rs:67-73` exits early ("All requested packages are already
  installed. No changes made.") **without** minting a generation when nothing
  changed and `--reinstall` is not set. No extra marker file is needed.
  > **Profile vs. scope (verified).** Two distinct things are at play and must
  > not be conflated: the **system profile** holds the toplevel plus the packages
  > **baked** into the image (seeded `registry: "seed"`), while **runtime
  > apm-installed** system packages live in the separate apm package profile at
  > `/var/lib/profiles/system-packages/`
  > (`crates/aos-package/src/types.rs`:
  > `ProfileScope::System.package_profile_path()`). An apm package generation is
  > independent of the *toplevel* (system-image) generation, so a host-image
  > upgrade does not by itself churn the apm-installed package set.

- **Image upgrade (new generation of the *system*):** the baked-in packages
  belong to the new toplevel (gen seeded `registry: "seed"`). apm-installed
  packages live in their apm package profile/scope (see the note above)
  independently of the toplevel generation. The boot step re-runs against
  `desired.toml`; packages already present remain, newly-added ones install, and
  removed ones are pruned by declarative reconciliation. The boot step converges
  the package profile to the declared set rather than staying additive-only.

The enable step is naturally idempotent: the preset policy is a fixed-point
operation, `aos-preset.service` re-derives wants links from that policy, and
starting an already-active target is a no-op.

### 4.4 Offline / baked vs fetched

Two install sources, chosen per package / per host:

| Mode | Where the closure comes from | Network at boot | Use |
|------|------------------------------|-----------------|-----|
| **Baked / offline** | Package closure is already in the image's store (built into `system.build.toplevel`'s closure or shipped alongside in the rootfs). `apm install` only needs to register it in the profile and enable — no download. | **Not** required | Air-gapped fleets; infrastructure packages like k3s that should never depend on a registry being reachable at boot |
| **Fetched** | `apm install` downloads NARs from the registry's `[[caches]]` pointer over dumb-HTTP, verifying hashes and trust (TOFU-pinned Ed25519 key) before import. | Required (`apm install` triggers `network-online.target`) | Hosts that pull optional/workload packages not present in the base image |

Baked mode is the honest default for **k3s**: it is an infrastructure package
that wants host privilege (global kernel modules, host net/cgroups), is large,
and should come up deterministically without a registry round-trip. Its closure
(and any package-root artifact) should be present in the image, and the boot
step's job for k3s is install-as-register + enable, not fetch. See
[container-model.md](container-model.md) for why k3s is high-privilege (host
net/cgroups, not a security boundary) and
[migration.md](migration.md) for how the existing k3s role maps onto this.

For fetched packages, the install step needs network, so it explicitly pulls
`network-online.target` (the same on-demand pattern Ignition stages use, per
`modules/services/ignition.nix` ~line 112–135) rather than hard-ordering all
boots behind network — keeping baked/offline boots from blocking on a network
that may not exist.

---

## 5. End-to-end boot sequence

Putting it together (stage-2 placement, preset-based enable):

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
    └─ apm runs: systemctl preset aos-pkg-<name>.target    (per §3.2 policy)
  aos-preset.service                    # systemctl preset-all --preset-mode=enable-only
                                        # + start --no-block newly-enabled targets (§3.2)
  systemd reaches aos-pkg-<name>.target                        [ENABLED]
       └─ service package: generated per-unit service + gated modules/sysctl/firewall services
  multi-user.target
```

The package's system units were **inert in EROFS** the whole time (built in);
`aos-install-packages` moved them to **installed**; the enable hook moved them to
**enabled**. Disabled hosts (package not in `desired.toml`) never install or
enable it — its units sit inert in EROFS, wanted by nothing, exactly as the
[activation.md](activation.md) "strict disabled = inert" guarantee requires.

---

## 6. Honest gaps and limits

- **The bridge exists as `aos-install-packages.service`.** `aos-seed-profiles`
  seeds the sysroot system profile; the stage-2 install service reconciles
  additional desired packages in the system package profile.
- **`systemd.units[].enabled` is gone (v12 §5.6.4).** Enable is expressed via
  systemd presets (§3.2): the image ships `disable *`, Ignition writes a
  per-host preset file, PID 1 applies presets on first boot, and `apm` runs
  `systemctl preset` for runtime installs. Nothing re-implements
  `[Install]`→symlink logic. The **machine-id precondition** for the
  first-boot pass is verified in §3.2.
- **Idempotency depends on `apm` generation behavior.** If `apm install` mints a
  generation on every invocation regardless of input, the boot step will churn
  generations each boot and needs an explicit "unchanged set" guard. Verified
  in §4.3: unchanged installs exit without minting a new generation.
- **k3s does not fit the sandbox cleanly.** It must be a **baked/offline**
  infrastructure package with high host privilege (host net/cgroups, global
  kernel modules) — call this out rather than pretend it is a sandboxed
  workload. Details in [container-model.md](container-model.md).
- **Config is layered, but boot only orders units.** The enabled units consume
  configuration delivered by the layered config model in [config.md](config.md):
  TPM2-sealed credentials for secrets, schema-validated apm artifacts for
  structured config, and `EnvironmentFile=` for simple config. The boot flow
  guarantees unit ordering; package-specific config validity remains the
  package/config contract. For k3s today, config arrives via Ignition
  `storage.files` (`/etc/rancher/k3s/k3s.env`) consumed by `EnvironmentFile=` —
  documented as the current working pattern, not a decision.
- **Prune semantics are declarative.** Removing a package from `desired.toml`
  removes it from the reconciled desired package set on the next boot.

---

## 7. Testing

The flow is observable end-to-end with the existing harnesses (see the testing
findings; harness files under `lib/testing/`):

- **Eval:** assert the package module emits exactly one `aos-pkg-<name>.target`
  and that no `multi-user.target.wants` symlink is baked into EROFS for it
  (inert-in-image invariant).
- **Single-VM check:** boot with `desired.toml` declaring one package; assert
  `aos-install-packages.service` succeeded, the closure is in `/nix/store`, the
  target is enabled, and the generated service is active. Re-trigger the service
  and assert no new generation is minted
  (idempotency).
- **Fleet:** the existing `apm-e2e` pattern (registry server + client running
  `apm update` / `apm install`) extended so the client's install is driven by an
  Ignition-declared `desired.toml` rather than a manual `apm install`, proving
  the Ignition→apm bridge. k3s fleet tests stay baked/offline.

---

## See also

- [README.md](README.md) — overview of the packages model and doc set
- [container-model.md](container-model.md) — per-unit substrate, future nspawn path, k3s
- [apm-integration.md](apm-integration.md) — registry metadata, target declaration, install/enable/remove
- [config.md](config.md) — layered config and credential delivery
- [migration.md](migration.md) — migration onto the packages model and the k3s mapping
- [open-questions.md](open-questions.md) — decision register and resolved dispositions
