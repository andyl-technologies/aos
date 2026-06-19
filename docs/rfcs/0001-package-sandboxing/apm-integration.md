# Packages in the apm/registry system

> **Status:** implemented direction. This document is part of the packages doc
> set and describes how a package that exposes generated systemd units,
> permissions, config, and optional future roots is declared, delivered, signed,
> and registered through AOS's existing `apm`/registry machinery.

This doc traces the "package exposes system integration" idea against the
**real** `apm install` path. A package is the registry-installable unit
(`apm install <name>`). Some packages additionally expose generated units plus an
`aos-pkg-<name>.target` handle. The questions answered here: what manifest field(s)
declare an exposed service; how the package root is *delivered* (baked into the
closure vs. fetched as a registry artifact / NAR); how generations and upgrades
work for an exposed service package; how `apm` "exposes" the package at install
time (drops the generated units + target); and how package roots are
signed/trusted. Under the unified model every exposing package has a target plus
generated units; what differs is *privilege*, declared in a signed
`[permissions]` manifest — so the manifest carries no "container vs host" kind,
just the package's permission grants (see [`permissions.md`](permissions.md)).
Sibling docs cover the rest:
[`README.md`](README.md) (overview), [`permissions.md`](permissions.md)
(the permission manifest), [`container-model.md`](container-model.md)
(per-unit substrate, future nspawn shape, k3s as high-privilege), [`boot-activation.md`](boot-activation.md)
(Ignition + first-boot install), [`config.md`](config.md) (config delivery,
layered), [`migration.md`](migration.md), and
[`open-questions.md`](open-questions.md). For the supply-chain side — runtime
integrity (dm-verity), hardware-rooted attestation (TPM), and the registry's
provenance role that §7 below records — the authoritative design is
[`attestation.md`](attestation.md) (with [`enforcement.md`](enforcement.md) on
layered in-kernel enforcement and [`state-of-the-art.md`](state-of-the-art.md)
on the comparison).

---

## 1. What a package is *today* (the ground truth)

Everything below builds on the existing registry/apm code. No part of it is
invented for this doc.

### 1.1 Registry metadata

A package version is described by `PackageMeta`
(`crates/aos-package/src/types.rs`). The current fields:

```rust
pub struct PackageMeta {
    pub name: String,
    pub version: String,
    pub description: String,
    pub homepage: Option<String>,
    pub license: String,
    pub maintainer: String,
    pub platform: String,         // e.g. "x86_64-linux"
    pub store_path: String,       // /nix/store/...
    pub nar_hash: String,         // "sha256:..."
    pub nar_size: u64,
    pub references: Vec<String>,  // direct runtime refs (store-path hashes)
    pub source_drv: String,
    pub source_nar_hash: String,
    pub closure_size: u64,
    pub sysroot: bool,            // is this a system toplevel?
    pub previous: Option<String>, // version chain, sysroot only
    pub images: Vec<SysrootImageEntry>, // pre-compiled images, sysroot only
}
```

On disk this is the nested TOML at `packages/<letter>/<name>.toml`, parsed by
`registry/parse.rs`, in the `[package]` / `[[versions]]` /
`[versions.platforms.<platform>]` shape (see
[`../../registry/current-state.md`](../../registry/current-state.md) §1).

Two fields matter a lot for this design and are worth calling out:

- **`sysroot: bool`** — already distinguishes "this is a whole system image"
  from "this is an ordinary package."
- **`images: Vec<SysrootImageEntry>`** — already lets a registry entry point at
  *pre-compiled image artifacts* that are separate store paths from
  `store_path`:

  ```rust
  pub struct SysrootImageEntry {
      pub format: String,     // image format tag
      pub store_path: String, // a *separate* store path
      pub nar_hash: String,
      pub nar_size: u64,
  }
  ```

  This is the existing precedent for "a package can ship more than just its own
  closure." The package-root image design (below) is essentially a second use of
  this same pattern.

### 1.2 The real `apm install` path

`crates/aos-package/src/install.rs::run()` does this, in order:

1. **Resolve** the closure via `resolve_multiple()` walking `closures/<hash>`
   adjacency lists.
2. **Download** missing NARs from the registry's `[[caches]]` pointer
   (`download_nars()`).
3. **Verify** each download (`verify_download_hash()` + `verify_nar_hash()`).
4. **Import** into the local `/nix/store` (`import_nar()`).
5. **Create a new profile generation** under `/var/lib/profiles/{scope}/gen-N/`:
   - `profile.new_generation()` — bump the `state.json` counter
   - `copy_roots(prev, new_gen)` — carry forward prior roots
   - `create_gc_roots(new_gen.path, …)` — symlink `gen-N/usr/<hash>` → store path
   - `write_meta(profile, hash, installed)` — write `meta/<hash>.json`
     (`InstalledMeta`, including the `apm` extension: name, version, registry,
     `held`, `explicit`)
   - `build_fhs_tree(new_gen, roots, …)` — synthesize the FHS merge
6. **`profile.switch_to(new_gen)`** — atomically move the `current` symlink.

Profile layout (`crates/aos-package/src/profile/mod.rs`):

```
/var/lib/profiles/{scope}/
├── state.json          # { current_generation, next_generation }
├── meta/<hash>.json    # InstalledMeta per closure member
├── current -> gen-1    # atomically swapped
├── gen-1/{usr,src}/    # gc-root symlinks + source .drv
└── gen-2/...
```

**The critical observation for this whole design:** the pre-RFC `apm install`
path did *store delivery and profile bookkeeping only*. It downloaded, verified,
imported, and recorded packages, but did not touch systemd, write units, enable
targets, or start services. The RFC-0001 expose phase is the added step that
materializes generated units without disturbing steps 1–6.

One favorable ground-truth update: the systemd client surface already exists —
`crates/aos-systemd` is a complete async zbus D-Bus client (start / stop /
restart / reload / isolate, job tracking, `settle`), currently exercised only
by the `apm _test-systemd-client` test shim. The expose/enable phase is
wiring, not greenfield.

---

## 2. Declaring an exposed container in the manifest

### 2.1 Where the declaration lives — three candidate sites

| Option | Where | Pros | Cons |
|---|---|---|---|
| **A. Extend `PackageMeta`** | registry TOML `[versions.platforms.<p>]` | Registry-versioned; authenticated by the same tag signature as the rest of the metadata; visible before download | Grows the registry schema and `PackageMeta`; every consumer must tolerate the new fields |
| **B. Manifest file in the closure** | `<store_path>/.aos-manifest.toml` | Travels with the artifact; no registry schema change; built hermetically with the package | Not visible until the NAR is downloaded; trust rides on the closure hash, not the tag signature directly |
| **C. Separate registry section** | `[[manifests]]` block keyed by version+platform | Keeps `PackageMeta` lean | A second parallel schema to keep in sync with `[[versions]]` |

**Decision (Phase 0):** **Option A** for the *handles* the
installer must know before/at install (does this package expose a container?
what target name? what image artifact?), because those need to be
tag-signed and resolvable *before* the closure is fetched — and **Option B** for
the *fine-grained nspawn shape* (bind mounts, env, capabilities) that the
container-launch unit needs at runtime. This mirrors how `images:` already lives
in `PackageMeta` (signed, pre-download) while the actual rootfs bytes live in a
separate store path.

### 2.2 `PackageMeta` additions

These fields are implemented in `crates/aos-package/src/types.rs` and
`crates/aos-package/src/registry/parse.rs`. All are `#[serde(default)]` so
existing registries parse unchanged.

> **Fail-closed capability gate.**
> Existing registries still parse because the new fields default empty, but
> permission-bearing entries are strict: the platform parser rejects unknown
> fields, `min-format`/`requires-features` must be supported, and RFC-0001
> metadata must carry the required feature gate. Permission-bearing entries
> place the gate inside a structured `references` table, which pre-Phase-0
> clients reject because they only understood `references = [...]`. This lands
> before any permission-bearing package is published.

```toml
[versions.platforms.x86_64-linux]
store_path  = "/nix/store/...-myapp-1.0"
nar_hash    = "sha256:..."
# ... existing fields ...

[versions.platforms.x86_64-linux.references]
hashes = []
min-format = 1
requires-features = [
  "expose-v1",
  "expose-artifact-v1",
  "permissions-v1",
  "network-policy-v1",
  # plus "requires-v1" when expose.requires is non-empty
]

# NEW: this package exposes a systemd handle plus generated units.
[versions.platforms.x86_64-linux.expose]
target       = "aos-pkg-myapp.target"   # must equal aos-pkg-<package>.target
units        = ["myapp.service"]     # member units pulled by the target
# No "kind" field: under the unified model every exposing package gets a
# package target. Privilege is declared separately in the [permissions] manifest
# (see permissions.md); k3s is a high-privilege package with an explicit grant list.

# Optional: package root image delivered as a separate artifact (like images:).
[[versions.platforms.x86_64-linux.expose.images]]
format       = "ext4-verity"         # package root image with signed dm-verity metadata
store_path   = "/nix/store/...-myapp-package-root"
nar_hash     = "sha256:..."
nar_size     = 0

# NEW: rendered units plus manifest, produced by pkg.expose.
[versions.platforms.x86_64-linux.expose_artifact]
store_path   = "/nix/store/...-expose-myapp"
nar_hash     = "sha256:..."
nar_size     = 4096

# NEW: the declared, signed privilege manifest — defined in permissions.md.
# Empty here = a tightly-sandboxed container. k3s would list host network,
# capabilities, cgroup-delegate, host-paths, kernel-modules, etc.
[versions.platforms.x86_64-linux.permissions]
# network = "private"  (default; "host" trades the network boundary away)
# capabilities = [...]; host-paths = [...]; kernel-modules = [...]; ...
```

Mapping to Rust:

```rust
pub struct ExposeMeta {
    pub target: String,
    pub units: Vec<String>,
    pub images: Vec<SysrootImageEntry>, // reuse the existing struct
    pub requires: Vec<String>,          // service deps by package NAME (Decision 18)
    pub config: ExposeConfigMeta,       // config artifacts and credentials
    pub provides: Vec<ProvidedCapabilityMeta>,
    pub uses: Vec<RequiredCapabilityMeta>,
    // no `kind` — every exposing package is a target plus units; see PermissionsMeta
}
// added to PackageMeta as:
//   pub expose: Option<ExposeMeta>,
//   pub expose_artifact: Option<ExposeArtifactMeta>,
//   pub permissions: PermissionsMeta,   // the signed manifest, see permissions.md
```

> **Resolved (was: strawman pending Decision 1).** The earlier `expose.kind =
> "container" | "host"` field is **dropped**. Under the unified model every
> exposing package is a container, so there is no two-shape distinction to
> encode; what differs is *privilege*, carried in the separate, signed
> `[permissions]` manifest defined in [`permissions.md`](permissions.md). The
> permission manifest is **part of the package's signed registry metadata**, so
> a package cannot widen its own privileges after publish. See Decision 1 in
> [`open-questions.md`](open-questions.md), now resolved by this model.

`requires` is **package-name resolver surface**: current resolution
(`crates/aos-package/src/resolve.rs`) finds the root package by name, walks the
store-path reference graph for closure edges, and also pulls in package names
listed in `expose.requires`. Typed capability consumers in `expose.uses`
resolve their provider packages through the same package index. The target-level
`After=`/`Wants=` edges between flat siblings live in
[`container-model.md`](container-model.md) §Composition.

Reusing `SysrootImageEntry` for `expose.images` is deliberate: the package
root image is "just another pre-compiled image artifact," and the verify/download
machinery already understands that struct. `apm install` and upgrade now
explicitly resolve `expose.images[].store_path` for ordinary packages and verify
the image NAR against signed registry metadata before generation activation.

### 2.3 The runtime nspawn shape (Option B sketch)

The fine-grained launch parameters belong with the artifact, e.g.
`<package-root>/.aos-nspawn.toml`, read by the future nspawn launch unit
generator, not by
the registry resolver:

```toml
[nspawn]
network   = "veth"          # "veth" | "host"  (k3s: "host", see container-model.md)
boot      = true            # run the container's own systemd PID1
bind_ro   = ["/nix/store"]
bind_rw   = []
env_files = ["/etc/aos/myapp/config.env"]   # config delivery: see config.md
```

These fine-grained nspawn parameters are **generated from the package's
`[permissions]` manifest** (see [`permissions.md`](permissions.md)), not authored
by hand — `network`, the bind sets, capabilities, and so on each map onto a
manifest field. See [`container-model.md`](container-model.md) for the full
nspawn semantics and why the current k3s package remains host-privileged while a
future default nspawn package would get real isolation.

---

## 3. How the package root is delivered

There are two delivery models. They are not mutually exclusive — a package can
prefer one and fall back to the other.

### 3.1 Baked into the host image (build-time)

For infrastructure that ships on every machine (k3s today), the package root is
a Nix derivation built alongside the host image and referenced from the system
closure. The build pattern is the same `exportReferencesGraph`,
`mkfs.ext4 -d`, and `fakeroot` flow that `lib/build/rootfs.nix` already uses
for the host rootfs — see the implemented
[`lib/build/package-root-image.nix`](../../../lib/build/package-root-image.nix)
builder. Delivery is then "free": the artifact is already
in `/nix/store` because it is in the system closure. No registry fetch happens.

- **Pro:** zero runtime fetch, works air-gapped, integrity is the same as the
  host image.
- **Con:** every machine carries the bytes whether or not the package is
  enabled; image grows.

### 3.2 Fetched from the registry as a package artifact (install-time)

For optional/per-tenant workloads, the package root is a *separate store path*
named by `expose.images[].store_path` and fetched exactly like any other NAR:

1. `apm install` resolves `expose.images[].store_path` to its closure (via the
   same `closures/<hash>` adjacency walk).
2. `download_nars()` pulls the package-root NAR from the `[[caches]]` mirror.
3. `verify_nar_hash()` checks it against `expose.images[].nar_hash`.
4. `import_nar()` writes it to `/nix/store`.
5. `create_gc_roots()` roots it in the new generation so it survives GC.

This is **the same five-step path** as the package's own closure (§1.2). The
only new work is teaching the resolver to *also* enqueue
`expose.images[].store_path` as a root to fetch. That keeps the security story
identical: the package root is content-addressed, NAR-hashed, and gc-rooted
just like everything else.

| Aspect | Baked (§3.1) | Fetched (§3.2) |
|---|---|---|
| When delivered | host image build | `apm install` |
| Lives in closure of | system toplevel | the package generation |
| Air-gap | yes | only if cache is reachable |
| Image bloat | yes (always present) | no (on demand) |
| Integrity | host image hash | `nar_hash` + cache signature |
| Good for | k3s, base infra | optional workloads |

**Implemented producer:** package-root images are produced by
[`lib/build/package-root-image.nix`](../../../lib/build/package-root-image.nix),
which emits the `root.img` / verity tuple consumed by generated `RootImage=`
services and covered by the `expose.images[]` metadata.

---

## 4. How apm "exposes" / registers the container

This is the missing post-install step (§1.2). The working assumption: **`apm
install` performs the expose phase** (materialize unit files into the writable
`/etc` overlay + drop the target); **enabling** the target is a separate,
tightly-ordered step — see Decision 8 in
[`open-questions.md`](open-questions.md), which covers who runs expose vs.
enable. After steps 1–6 succeed for a package whose `expose` is present, the
expose phase runs:

1. **Resolve the handle.** Read `expose.target`, `expose.units`,
   `expose.images`, and the package's `[permissions]` manifest (every exposing
   service package gets a launch unit; the manifest
   decides its privilege — see [`permissions.md`](permissions.md)).
2. **Drop the launch unit.** Generate the per-unit launch service — with
   `CapabilityBoundingSet=`, `BindPaths=`, `PrivateNetwork=`,
   `PrivateUsers=`, and related directives derived from the `[permissions]`
   manifest — that points at the resolved closure/root, e.g.
   `aos-pkg-myapp.service`. **Resolved for the MVP:** AOS uses one explicit
   `aos-pkg-<name>.service` per package; the nspawn template remains only for
   the future multi-unit-init substrate. Note
   that `systemd-machined`/`machinectl` is **disabled** in the AOS systemd build
   (`pkgs/system/systemd.nix`: `-Dmachined=false`), so the
   `systemd-nspawn@.service` multiplexing that normally depends on `machined`
   may not be usable as-is; an explicit per-package unit is the safer default.
3. **Drop the target handle.** Generate `aos-pkg-<name>.target` with `Wants=` the
   launch unit and member units, matching the target/activation design in
   [`activation.md`](activation.md).
4. **Enable.** Enabling is the separate step (Decision 8, resolved):
   `systemctl preset aos-pkg-<name>.target` against the merged preset policy —
   at boot the every-boot `aos-preset.service` pass covers every unit (see
   [`boot-activation.md`](boot-activation.md) §3.2).

### 4.1 Where the unit files physically land

There is a real tension here with AOS's immutable root. Package units are
baked into the EROFS `/etc` lower as *inert regular files* and activated only by
an Ignition-written `multi-user.target.wants/...` symlink at first boot (see the
in-image inert activation described in [`activation.md`](activation.md)). But an
`apm install` that happens *after* first boot cannot rewrite
the EROFS lower. So a runtime-installed package's units must land in the
writable `/etc` overlay layer (the `/var/etc` upper of the 3-layer overlay)
rather than EROFS.

This produces two distinct exposure paths:

| Install timing | Where units land | How enabled |
|---|---|---|
| **Baked / first boot** | EROFS lower (inert) plus `aos-install-packages.service` materialization for declared packages | Ignition writes desired packages and preset policy; `aos-preset.service` derives enablement |
| **Runtime `apm install`** | `/var/etc/systemd/system.attached/...` (gc-rooted store-path symlink surfaced through the overlay) | `apm` records the preset line and starts the target |

Resolved: runtime-installed package units are materialized as gc-rooted
store-path symlinks under `/var/etc/systemd/system.attached/`, with enablement
recorded in `/var/etc/systemd/system-preset/30-aos-apm.preset`. The
`package-expose-lifecycle` VM check verifies that `system.attached` is in the
unit search path even with `portabled` disabled; package-generation switches
re-materialize the symlink and preset set, so rollback rolls units back with the
package profile.

Upstream precedent for the materialization shape: `portablectl attach` copies
matching units out of the image into a dedicated search-path directory —
`/etc/systemd/system.attached/` (persistent) or
`/run/systemd/system.attached/` (runtime) — and injects behavior via numbered
drop-ins (`10-profile.conf`, `20-portable.conf`), deliberately keeping
attached units out of admin-owned `/etc/systemd/system/`. An `apm`-owned
attach directory of the same shape is the natural answer to Decision 16:
cleanly separable, obviously machine-managed, generation-swappable.

### 4.2 The expose phase is idempotent and generation-scoped

Because exposure writes files keyed by package name, re-running `apm install`
(or an upgrade, §5) must overwrite-in-place. The natural anchor is the profile
generation: the launch unit and target are regenerated for `gen-N`, and
`switch_to(gen-N)` makes them current. A rollback to `gen-(N-1)` should restore
the previous attached symlink and preset set. Unit files are gc-rooted store
paths symlinked from the generation, not rendered text in `/var/etc`; rollback
switches the package generation, rewrites the symlinks, reloads systemd, and
restarts the target.

---

## 5. Generations and upgrades of a service package

Service packages ride the **existing** generation model (§1.2) with the package
root treated as one more gc-rooted closure member. (The `{scope}` parameter in
the profile path distinguishes the runtime apm package profile/scope from the
system profile that holds the toplevel + baked packages; verified in
`crates/aos-package/src/types.rs` and
`crates/aos-package/src/profile/mod.rs`: system-scope runtime package
generations use `/var/lib/profiles/system-packages/`, separate from the sysroot
`/var/lib/profiles/system/` — see [`boot-activation.md`](boot-activation.md)
§4.3.)

1. `apm install myapp@2.0` resolves the new `store_path` **and** the new
   `expose.images[].store_path`.
2. Both NARs are downloaded, verified, imported.
3. A new generation `gen-(N+1)` is created; `create_gc_roots()` roots both the
   package closure and the new package-root image.
4. The expose phase (§4) regenerates `aos-pkg-myapp.target` and the launch unit to
   point at the **new** package-root store path.
5. `switch_to(gen-(N+1))` flips `current`.
6. *Activation of the new root:* the running service must be restarted to pick
   up the new immutable package root. This is `systemctl restart
   aos-pkg-myapp.target` (or the launch unit). **There is no live, in-place root
   swap** — the package root is immutable per the substrate model, so an upgrade is a
   stop-old-root / start-new-root cycle. For a workload this is a clean restart;
   for k3s it drains the node (honest cost, see §6).

**Rollback** is the inverse: `switch_to(gen-(N-1))` restores the prior generation
(both store paths are still gc-rooted there) and the prior unit text, then a
restart brings the old root back. This reuses `copy_roots`/`copy_roots_for_upgrade`
(`install.rs`); expose-phase artifacts are generation-rooted and re-materialized
when the package generation switches.

**Held / explicit flags.** `ApmMeta` already records `held` (pin from upgrade)
and `explicit` (user-requested). A held service package must not be
auto-upgraded — including its package root — which the existing `held` check
covers for free, since the package root is just another member of the same
generation.

---

## 6. The high-privilege case: k3s

k3s is a **high-privilege package** — see [`permissions.md`](permissions.md)
for its manifest. It still gets the same package target and generated unit
lifecycle as other exposing packages, but its `[permissions]` manifest declares
host network, broad capabilities, cgroup delegation, host paths, and
kernel-modules. That means the target is a packaging/lifecycle wrapper, not a
security boundary. It needs host privilege that a default sandbox would deny.
The k3s-worker exposed package
(`pkgs/kubernetes/k3s-worker.nix`, via
`pkgs/kubernetes/_k3s-expose-package.nix`) already shows why:

```nix
expose = {
  kernel.modules = common.kernelModules;        # br_netfilter, vxlan, ip_set - GLOBAL
  firewall.allowedTCP = [10250];                # host kubelet port
  units."k3s.service".serviceConfig = {
    EnvironmentFile = "/etc/rancher/k3s/k3s.env";
    Delegate = "yes";                           # k3s manages its own cgroup subtree
  };
};
```

Honest consequences for the package model:

- **Kernel modules are global.** There is no per-package module namespace.
  `br_netfilter`/`vxlan`/`ip_set` load into the host kernel regardless of any
  package boundary. The package service cannot contain them.
- **Host network + cgroups.** k3s needs host networking and `Delegate=yes`; an
  isolated private-network/private-user service breaks pod networking and the
  kubelet's cgroup management. So k3s gets a high-privilege generated service,
  and that must be labeled as such — it is **not** a security boundary.
- **Config is host-side.** k3s reads `/etc/rancher/k3s/k3s.env` via
  `EnvironmentFile`. Under the layered config model, simple non-secret config
  can stay in an `EnvironmentFile=`, while secrets use TPM2-sealed credentials
  and structured config uses schema-validated apm artifacts.
- **Upgrades would kill pods under the skipped nspawn materialization.**
  Today's bare unit sets `KillMode=process` (upstream k3s packaging), so a k3s
  restart/upgrade kills only the supervisor; containerd, the shims, and all pod
  processes survive. An nspawn container always has a private PID namespace, so
  that alternate materialization would kill **everything** inside it — an
  ungraceful mass pod kill, not a drain, unless cordon+drain is orchestrated
  first. This is one reason nspawn is skipped for the MVP; see
  [`container-model.md`](container-model.md) §"The `KillMode=process`
  regression" and Decisions 11/17 in
  [`open-questions.md`](open-questions.md).

The takeaway: there is no separate "class" to encode — the package's signed
`[permissions]` manifest already tells `apm` (and an operator, via `apm info
<pkg> --permissions`) exactly how privileged the generated service is, so it knows *not*
to promise isolation for a package like k3s that has declared host network and
broad caps. The manifest replaces the dropped `expose.kind` strawman (§2.2). The
container-model details and the current per-unit high-privilege k3s shape are in
[`container-model.md`](container-model.md); the permission surface is in
[`permissions.md`](permissions.md).

---

## 7. Signing and trust for package roots

The good news: package roots inherit the **existing** registry trust model
end to end, because they are delivered as ordinary NARs (§3.2) named by
tag-signed metadata.

1. **Metadata is tag-signed.** `expose.images[].store_path` and `nar_hash` live
   in `packages/<letter>/<name>.toml`, which is part of the git tree covered by
   the signed semver/channel release tag. `registry::verify` enforces
   name-binding and the `tag -> tag -> commit` chain
   (see [`../../registry/signing-and-trust.md`](../../registry/signing-and-trust.md)
   and [`../../registry/current-state.md`](../../registry/current-state.md) §6). So a
   package-root reference cannot be substituted without breaking the release
   signature.
2. **The NAR is content-addressed.** `verify_nar_hash()` checks the downloaded
   package-root NAR against the `nar_hash` from the signed metadata. The bytes
   cannot be tampered with in transit or at the cache.
3. **The cache may add a second signature.** Generated narinfo can be Nix-cache
   signed (`aos-core::nar::cache::NarInfoSigner`,
   [`../../registry/current-state.md`](../../registry/current-state.md) §7), so a
   stock-Nix substituter with `require-sigs = true` also accepts it.
4. **TOFU + anti-rollback still apply.** First sync pins the registry's Ed25519
   key; the anti-rollback floor prevents downgrading the package — and therefore
   its package root — below a stored semver
   (see [`../../registry/current-state.md`](../../registry/current-state.md) §4–5).

**No new trust primitive is required for fetched package roots.** They are
just NARs whose hashes are committed to tag-signed metadata.

**Honest gap for *baked* roots (§3.1):** a host-image-baked package root is
covered by the host image's own integrity (UKI / system closure), *not* by a
registry tag signature, because it never transits the registry. If a deployment
mixes baked and fetched roots for the same package across a fleet, the trust
story is split-brain (image-signed vs. tag-signed). Recommendation: pick one
delivery model per package — **fetch-at-boot via apm as the default**; if
baking, document the per-package choice explicitly. Tracked in Decision 5 of
[`open-questions.md`](open-questions.md).

**Build, not audit, against TUF.** The chain above (TOFU-pinned key, tag
signatures, anti-rollback floor) is a homegrown subset of The Update Framework.
Now that the `[permissions]` manifest's security rides on it — and that the
registry is the provenance/attestation plane for the whole supply chain — the
TUF surface is **built out in full**, not merely audited: see §7.1 below and
[`attestation.md`](attestation.md) (§"Provenance & transparency") for the
authoritative design.

### 7.1 Registry role in attestation & provenance

> **Authoritative design:** [`attestation.md`](attestation.md). This section
> records only the **registry's** role and its concrete schema/CLI surface; the
> full three-artifact model (dm-verity runtime integrity + TPM measured
> attestation), the kernel-config and `systemd` `RootImage=`/`RootHash=` wiring,
> and the fleet verifier all live there. Under the
> [budget mandate](implementation-plan.md#budget-mandate) none of this is
> deferred for cost.

The registry is the **catalog / policy / provenance plane — never a runtime
signer.** This is the *same pattern* RFC-0006's registry SB-catalog plays — "the
registry records and validates SB signing facts but is **never a signer** of
them" — generalized from Secure Boot to the three package trust artifacts. The
registry plays three roles, one per artifact:

1. **Provenance host + publication anchor (artifact 1).** At `apr publish` the
   registry binds `name → version → nar-hash → manifest-hash → root-digest`,
   **tag-signs** that binding (the existing Ed25519 tag-signature chain, with
   name-binding and the anti-rollback floor), **hosts** the in-toto/SLSA
   provenance attestation that ties the NAR + `[permissions]` manifest to the
   build inputs (the `.drv` / source), and **appends the binding to the
   in-registry transparency hash chain** so clients following the same registry
   history can audit append consistency. Independent witness / Trustix /
   Rekor-style non-equivocation is future work. It decides *what may be
   distributed* and *signs the catalog entry* — it never knows a host's local
   policy (the three-layer rule of [`permissions.md`](permissions.md) is
   unchanged).
2. **Source of the signed dm-verity root hash (artifact 2).** The
   `.roothash.p7s` (PKCS#7 over the dm-verity root hash) for each
   package/generation root is a **registry-served artifact** (the new
   `root_hash_sig` field, §7.2). The registry *distributes* it; the **kernel
   enforces** it against the `.platform` keyring (populated from the UEFI db
   certificates enrolled by RFC-0006). The registry holds no verity key and
   performs no runtime check.
3. **Golden-measurements catalog (artifact 3).** The registry records, per
   package/version, the **expected measurement tuple**
   `H(name ‖ version ‖ root-digest ‖ manifest-digest)` — the same value a node
   extends into TPM **PCR 15** at activation. A fleet verifier checks a node's
   `TPM2_Quote` and replayed event log against these golden values. The registry
   is the **oracle of expected values**, exactly as it records `expected_pcr11`
   for UKIs today; it never holds a TPM, signs a quote, or is the hardware root
   of trust.

**Key-custody separation (mandatory, inherited from RFC-0006).** The registry
**publication key** (artifact 1) ≠ the **UEFI-db / verity key** (artifact 2) ≠
the **TPM AK/EK** (artifact 3). A registry compromise lets an attacker publish a
*new* signed package, but that package is still constrained by policy +
provenance checks, recorded in the same-history transparency hash chain, and
bounded by anti-rollback; the attacker **cannot forge a TPM quote** or alter a
node's measured state. Same blast-radius containment RFC-0006 designed for SB,
extended to packages. See [`attestation.md`](attestation.md) §"Custody /
separation of duties".

### 7.2 Registry / `PackageMeta` schema additions for attestation

These extend the Option-A `[versions.platforms.<p>]` block and `ExposeMeta`
sketch from §2.2. All fields are `#[serde(default)]` (back-compat with old
registries) and gated behind the **Decision 19 capability gate** (so an old apm
that cannot enforce them *refuses* rather than silently dropping them — see the
fail-open hazard in §2.2).

```toml
[versions.platforms.x86_64-linux]
store_path  = "/nix/store/...-myapp-1.0"
nar_hash    = "sha256:..."
# ... existing fields ...

# NEW: package-root digest used as the measurement input. For dm-verity roots
# this equals root_hash; for non-verity exposed packages it is derived from the
# package NAR hash so the package set is still measured completely.
root_digest   = "sha256:..."                  # package-root measurement input

# NEW (artifact 2): dm-verity root hash for this package/generation root, plus
# its PKCS#7 detached signature (.roothash.p7s). The registry DISTRIBUTES these;
# the KERNEL enforces root_hash_sig against the .platform keyring (UEFI db).
root_hash     = "sha256:..."                  # dm-verity Merkle root
root_hash_sig = "myapp-1.0.roothash.p7s"      # registry-served, kernel-enforced

# NEW (artifact 1): in-toto/SLSA provenance attestation, served alongside the
# narinfo. Binds nar_hash AND manifest-hash to the build inputs (.drv / source).
provenance    = "myapp-1.0.intoto.jsonl"      # registry-hosted attestation ref

# NEW (artifact 3): golden measurement tuple a node extends into TPM PCR 15.
# A fleet verifier checks a node's quote against this expected value.
measurement   = "sha256:..."                  # H(name ‖ version ‖ root-digest ‖ manifest-digest)
```

Mapping to Rust (proposed; added to `PackageMeta`, all defaulted):

```rust
/// Per-platform attestation/provenance facts. The registry hosts and serves
/// these; it is never the runtime signer (the kernel enforces `root_hash_sig`,
/// a TPM enforces `measurement`). All fields default for back-compat and are
/// gated behind the Decision 19 capability gate.
pub struct AttestationMeta {
    /// Digest used as the package-root input to the TPM measurement tuple.
    /// Equals `root_hash` for dm-verity roots.
    #[serde(default)]
    pub root_digest: Option<String>,
    /// dm-verity Merkle root hash over the package/generation root image.
    #[serde(default)]
    pub root_hash: Option<String>,
    /// Registry-served PKCS#7 (`.roothash.p7s`) over `root_hash`; the kernel
    /// validates it against the `.platform` keyring (UEFI db, RFC-0006).
    #[serde(default)]
    pub root_hash_sig: Option<String>,
    /// Reference to the registry-hosted in-toto/SLSA provenance attestation
    /// binding the NAR hash and the `[permissions]` manifest hash to build inputs.
    #[serde(default)]
    pub provenance: Option<String>,
    /// Golden measurement tuple `H(name ‖ version ‖ root-digest ‖ manifest-digest)`
    /// that a node extends into TPM PCR 15; the fleet verifier's expected value.
    #[serde(default)]
    pub measurement: Option<String>,
}
// added to PackageMeta as:
//   #[serde(default)]
//   pub attestation: AttestationMeta,
```

### 7.3 TUF / provenance / transparency — built, not just audited

Promoting the §7 TUF/in-toto note from *consider/audit* to *build* (full design
in [`attestation.md`](attestation.md) §"Provenance & transparency"):

- **in-toto / SLSA provenance — build.** Emit a DSSE-wrapped SLSA provenance
  attestation (current spec **v1.2**, with the Source Track) per package build,
  binding the **NAR hash AND the `[permissions]` manifest hash** to the build
  inputs; serve it from the registry alongside the narinfo (the `provenance`
  field, §7.2). The DSSE envelope is signed by an active `keys.toml` roster key,
  and consumers verify the envelope signature plus builder id before checking
  the SLSA subjects. Packages that declare RFC-0001 expose, permission, or
  BPF-LSM policy metadata must declare provenance, and retired provenance keys
  are accepted only for transparency entries below their recorded retirement
  sequence.
- **Transparency log — build.** Append every published binding to the
  in-registry `transparency/package-provenance.jsonl` hash chain. Publish
  rejects rewrites, missing entries, duplicate entries, mismatched DSSE artifact
  hashes, and staged package/store changes that are reachable from a
  provenance-bearing package but not covered by the log. The in-registry log
  gives append-chain consistency for clients following the same registry
  history; independent witness or Rekor-style compromise resistance is future
  work.
- **TUF — build the full roles, not just the rollback floor.** AOS already has
  the TUF **rollback** defense (the anti-rollback semver floor, §7.4). The
  release path now writes and verifies `root`, `targets`, `snapshot`, and
  `timestamp` metadata with role separation, thresholds, expiry, version floors,
  and key-rotation continuity checks.
- **Caveat (record, not a blocker):** cosign's OCI-1.1 *referrers* API is
  **selectable, not yet a hard default**, and **GHCR does not implement the
  referrers endpoint** — relevant only if AOS ever mirrors attestations into an
  OCI registry.

---

## 8. Summary: the delta against the real install path

The whole feature is a small, well-bounded addition to a path that already
works:

| Stage | Today | Change for exposed service packages |
|---|---|---|
| Registry metadata | `PackageMeta` | + `min-format`/`requires-features`, `expose` (target/units/images/requires/config/provides/uses), `expose_artifact`, and signed `[permissions]` manifest (permissions.md), all `#[serde(default)]` |
| Resolve | `resolve_multiple()` | also pull `expose.requires` and provider packages named by `expose.uses` |
| Download / verify / import | NAR path | also fetch and verify `expose_artifact` plus `expose.images[]` as signed secondary artifacts |
| Profile generation | gc-root + meta + FHS | also gc-root the expose artifact and any package root image |
| **Expose phase** | package install without units | materialize rendered units/drop-ins + `aos-pkg-<name>.target` into the package generation, then preset/start |
| Activation | n/a | preset-driven enablement through `30-aos-apm.preset` / `aos-preset.service` |
| Trust | tag-signed metadata + NAR hash + cache sig | **unchanged** for delivery — roots ride the same chain |
| Attestation / provenance | tag-sig + anti-rollback floor only | + `root_digest`/`root_hash`/`root_hash_sig`/`provenance`/`measurement` (§7.2); registry hosts provenance + golden values, never a runtime signer (§7.1); full TUF + transparency log (§7.3); design in [`attestation.md`](attestation.md) |

The P0/P1 schema and renderer/publish path are now implemented: package
authors declare `expose`, the build renderer emits `pkg.expose/manifest.json`,
and `apr publish --expose-manifest` writes the signed registry metadata after
revalidating the manifest.
