# Packages in the apm/registry system

> **Status:** planning. This document is part of the packages doc set and
> describes how a *package* that exposes a systemd-nspawn container is declared,
> delivered, signed, and registered through AOS's existing `apm`/registry
> machinery. It is forward-looking: most of the schema additions below do **not**
> exist yet. Where a claim could not be verified against the current code, it is
> marked *needs verification*.

This doc traces the "package exposes a container" idea against the **real**
`apm install` path. A package is the registry-installable unit (`apm install
<name>`). Some packages additionally expose a `systemd-nspawn` container plus an
`aos-pkg-<name>.target` handle. The questions answered here: what manifest field(s)
declare an exposed service/container; how the container root is *delivered*
(baked into the closure vs. fetched as a registry artifact / NAR); how
generations and upgrades work for a containerized package; how `apm` "exposes"
the container at install time (drops the template instance + target); and how
container roots are signed/trusted. Sibling docs cover the rest:
[`README.md`](README.md) (overview), [`container-model.md`](container-model.md)
(nspawn shape, k3s honesty), [`boot-activation.md`](boot-activation.md)
(Ignition + first-boot install), [`config.md`](config.md) (config delivery,
explicitly open), [`migration.md`](migration.md) (roles→packages rename), and
[`open-questions.md`](open-questions.md).

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
[`../registry/current-state.md`](../registry/current-state.md) §1).

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
  closure." The container-root design (below) is essentially a second use of
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

**The critical observation for this whole design:** `apm install` today does
*store delivery and profile bookkeeping only*. It downloads, verifies, imports,
and records — but it has **no post-install hook** that touches systemd, writes
units, enables targets, or starts machines. "Exposing a container" is exactly
that missing step. The rest of this doc is about adding it without disturbing
steps 1–6.

---

## 2. Declaring an exposed container in the manifest

### 2.1 Where the declaration lives — three candidate sites

| Option | Where | Pros | Cons |
|---|---|---|---|
| **A. Extend `PackageMeta`** | registry TOML `[versions.platforms.<p>]` | Registry-versioned; authenticated by the same tag signature as the rest of the metadata; visible before download | Grows the registry schema and `PackageMeta`; every consumer must tolerate the new fields |
| **B. Manifest file in the closure** | `<store_path>/.aos-manifest.toml` | Travels with the artifact; no registry schema change; built hermetically with the package | Not visible until the NAR is downloaded; trust rides on the closure hash, not the tag signature directly |
| **C. Separate registry section** | `[[manifests]]` block keyed by version+platform | Keeps `PackageMeta` lean | A second parallel schema to keep in sync with `[[versions]]` |

**Recommendation (planning, not decided):** **Option A** for the *handles* the
installer must know before/at install (does this package expose a container?
what target name? what image artifact?), because those need to be
tag-signed and resolvable *before* the closure is fetched — and **Option B** for
the *fine-grained nspawn shape* (bind mounts, env, capabilities) that the
container-launch unit needs at runtime. This mirrors how `images:` already lives
in `PackageMeta` (signed, pre-download) while the actual rootfs bytes live in a
separate store path. Settle this in [`open-questions.md`](open-questions.md).

### 2.2 Proposed `PackageMeta` additions (Option A sketch)

These fields are **proposed**, not implemented. All would be `#[serde(default)]`
so existing registries parse unchanged.

```toml
[versions.platforms.x86_64-linux]
store_path  = "/nix/store/...-myapp-1.0"
nar_hash    = "sha256:..."
# ... existing fields ...

# NEW: this package exposes a systemd handle + (optionally) a container.
[versions.platforms.x86_64-linux.expose]
target       = "aos-pkg-myapp.target"   # the activation handle apm registers
units        = ["myapp.service"]     # member units pulled by the target
# strawman, pending Decision 1 (package class) in open-questions.md:
kind         = "container"           # "container" | "host"  (k3s is "host"; see §6)

# NEW: container root delivered as a separate artifact (like images:).
[[versions.platforms.x86_64-linux.expose.images]]
format       = "ext4"                # "ext4" | "erofs" | "dir" | "oci" (TBD)
store_path   = "/nix/store/...-myapp-container-root"
nar_hash     = "sha256:..."
nar_size     = 0
```

Mapping to Rust (proposed):

```rust
pub struct ExposeMeta {
    pub target: String,
    pub units: Vec<String>,
    pub kind: ExposeKind,             // Container | Host — STRAWMAN
    pub images: Vec<SysrootImageEntry>, // reuse the existing struct
}
// added to PackageMeta as:  pub expose: Option<ExposeMeta>,
```

> **Strawman, pending Decision 1.** The `expose.kind = "container" | "host"`
> field above conflicts with the separate package **class** distinction
> (`workload` vs. `infrastructure`) recommended in Decision 1 of
> [`open-questions.md`](open-questions.md). Whether the manifest carries a
> two-valued `kind` here or defers to a first-class package class is **not
> resolved** — treat `kind` as a placeholder until Decision 1 lands.

Reusing `SysrootImageEntry` for `expose.images` is deliberate: the container
root is "just another pre-compiled image artifact," and the verify/download
machinery already understands that struct. *Needs verification:* whether the
existing `images:` resolution path is wired into `apm install` for non-sysroot
packages, or only consulted on the system-upgrade path. From the findings,
`images:` is documented as "sysroot only" today, so the installer change in §4
must explicitly resolve `expose.images` for ordinary packages.

### 2.3 The runtime nspawn shape (Option B sketch)

The fine-grained launch parameters belong with the artifact, e.g.
`<container-root>/.aos-nspawn.toml`, read by the launch unit generator, not by
the registry resolver:

```toml
[nspawn]
network   = "veth"          # "veth" | "host"  (k3s: "host", see container-model.md)
boot      = true            # run the container's own systemd PID1
bind_ro   = ["/nix/store"]
bind_rw   = []
env_files = ["/etc/aos/myapp/config.env"]   # config delivery: see config.md (OPEN)
```

See [`container-model.md`](container-model.md) for the full nspawn semantics and
why workload packages get real isolation while k3s gets only a nominal
container.

---

## 3. How the container root is delivered

There are two delivery models. They are not mutually exclusive — a package can
prefer one and fall back to the other.

### 3.1 Baked into the host image (build-time)

For infrastructure that ships on every machine (k3s today), the container root
is a Nix derivation built alongside the host image and referenced from the
system closure. The build pattern is the same `exportReferencesGraph` +
`mkfs.ext4 -d` + `fakeroot` flow that `lib/build/rootfs.nix` already uses for the
host rootfs — see [`container-model.md`](container-model.md) for the proposed
`lib/build/container-root.nix`. Delivery is then "free": the artifact is already
in `/nix/store` because it is in the system closure. No registry fetch happens.

- **Pro:** zero runtime fetch, works air-gapped, integrity is the same as the
  host image.
- **Con:** every machine carries the bytes whether or not the package is
  enabled; image grows.

### 3.2 Fetched from the registry as a package artifact (install-time)

For optional/per-tenant workloads, the container root is a *separate store path*
named by `expose.images[].store_path` and fetched exactly like any other NAR:

1. `apm install` resolves `expose.images[].store_path` to its closure (via the
   same `closures/<hash>` adjacency walk).
2. `download_nars()` pulls the container-root NAR from the `[[caches]]` mirror.
3. `verify_nar_hash()` checks it against `expose.images[].nar_hash`.
4. `import_nar()` writes it to `/nix/store`.
5. `create_gc_roots()` roots it in the new generation so it survives GC.

This is **the same five-step path** as the package's own closure (§1.2). The
only new work is teaching the resolver to *also* enqueue
`expose.images[].store_path` as a root to fetch. That keeps the security story
identical: the container root is content-addressed, NAR-hashed, and gc-rooted
just like everything else.

| Aspect | Baked (§3.1) | Fetched (§3.2) |
|---|---|---|
| When delivered | host image build | `apm install` |
| Lives in closure of | system toplevel | the package generation |
| Air-gap | yes | only if cache is reachable |
| Image bloat | yes (always present) | no (on demand) |
| Integrity | host image hash | `nar_hash` + cache signature |
| Good for | k3s, base infra | optional workloads |

**Honest gap:** AOS builds today are *source → derivation → NAR*, not
*rootfs → squashfs*. No container-root images are produced yet by any package.
The `lib/build/container-root.nix` builder in
[`container-model.md`](container-model.md) is **net-new** and unbuilt. Until it
exists, "fetched container root" is a schema with no producer.

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
   `expose.kind`, and (if `kind = "container"`) `expose.images`.
2. **Drop the template instance + launch unit.** Generate the nspawn launch
   service that mounts the resolved container-root image and points at the
   resolved closure, e.g. `aos-pkg-myapp@.service` (a template) plus the
   `aos-pkg-myapp@default.service` instance, or a non-templated
   `aos-pkg-myapp.service`. *Needs verification:* whether AOS prefers
   `systemd-nspawn@.service` templating or one explicit unit per package — note
   that `systemd-machined`/`machinectl` is **disabled** in the AOS systemd build
   (`pkgs/system/systemd.nix`: `-Dmachined=false`), so the
   `systemd-nspawn@.service` multiplexing that normally depends on `machined`
   may not be usable as-is; an explicit per-package unit is the safer default.
3. **Drop the target handle.** Generate `aos-pkg-<name>.target` with `Wants=` the
   launch unit and member units, matching the roles-as-targets design in
   [`../roles/targets-and-sandbox.md`](../roles/targets-and-sandbox.md).
4. **Enable.** Enabling is the separate step (Decision 8): either
   `systemctl enable --now aos-pkg-<name>.target`, or — at first boot — emit an
   Ignition `systemd.units[]` fragment that enables the target
   (see [`boot-activation.md`](boot-activation.md)).

### 4.1 Where the unit files physically land

There is a real tension here with AOS's immutable root. Today, role units are
baked into the EROFS `/etc` lower as *inert regular files* and activated only by
an Ignition-written `multi-user.target.wants/...` symlink at first boot (see
[`../roles/targets-and-sandbox.md`](../roles/targets-and-sandbox.md) §"In image
(inert)"). But an `apm install` that happens *after* first boot cannot rewrite
the EROFS lower. So a runtime-installed package's units must land in the
writable `/etc` overlay layer (the `/var/etc` upper of the 3-layer overlay)
rather than EROFS.

This produces two distinct exposure paths:

| Install timing | Where units land | How enabled |
|---|---|---|
| **Baked / first boot** | EROFS lower (inert) + Ignition `systemd.units[]` target | Ignition files stage writes the wants symlink |
| **Runtime `apm install`** | `/var/etc/systemd/system/...` (writable upper) | `apm` runs `systemctl enable --now` |

*Needs verification:* the exact writable path and whether `apm` is permitted to
write systemd units into the `/etc` overlay at runtime, and whether a generation
swap of the *package* profile should also re-materialize these units (so a
rollback of the package also rolls back its units). This is the single biggest
unresolved mechanism; tracked as Decision 16 in
[`open-questions.md`](open-questions.md).

### 4.2 The expose phase is idempotent and generation-scoped

Because exposure writes files keyed by package name, re-running `apm install`
(or an upgrade, §5) must overwrite-in-place. The natural anchor is the profile
generation: the launch unit and target are regenerated for `gen-N`, and
`switch_to(gen-N)` makes them current. A rollback to `gen-(N-1)` should restore
the previous unit text. *Needs verification:* whether unit files should be
gc-rooted store paths symlinked from the generation (clean rollback) or rendered
text in `/var/etc` (simpler, but rollback must re-render).

---

## 5. Generations and upgrades of a containerized package

Containerized packages ride the **existing** generation model (§1.2) with the
container root treated as one more gc-rooted closure member. (The `{scope}`
parameter in the profile path distinguishes the runtime apm package
profile/scope from the system profile that holds the toplevel + baked packages;
that relationship is *needs verification* against
`crates/aos-package/src/profile/mod.rs` — see
[`boot-activation.md`](boot-activation.md) §4.3.)

1. `apm install myapp@2.0` resolves the new `store_path` **and** the new
   `expose.images[].store_path`.
2. Both NARs are downloaded, verified, imported.
3. A new generation `gen-(N+1)` is created; `create_gc_roots()` roots both the
   package closure and the new container-root image.
4. The expose phase (§4) regenerates `aos-pkg-myapp.target` and the launch unit to
   point at the **new** container-root store path.
5. `switch_to(gen-(N+1))` flips `current`.
6. *Activation of the new root:* the running container must be restarted to pick
   up the new immutable root. This is `systemctl restart aos-pkg-myapp.target` (or
   the launch unit). **There is no live, in-place container-root swap** — the
   nspawn root is immutable per the container model, so an upgrade is a
   stop-old-root / start-new-root cycle. For a workload this is a clean restart;
   for k3s it drains the node (honest cost, see §6).

**Rollback** is the inverse: `switch_to(gen-(N-1))` restores the prior generation
(both store paths are still gc-rooted there) and the prior unit text, then a
restart brings the old root back. This reuses `copy_roots`/`copy_roots_for_upgrade`
(`install.rs`) — *needs verification* that the expose-phase artifacts are carried
across generations by `copy_roots` or regenerated each time.

**Held / explicit flags.** `ApmMeta` already records `held` (pin from upgrade)
and `explicit` (user-requested). A held containerized package must not be
auto-upgraded — including its container root — which the existing `held` check
covers for free, since the container root is just another member of the same
generation.

---

## 6. Where the model does NOT fit: k3s

k3s is an **infrastructure** package (`expose.kind = "host"`), not a workload.
It needs host privilege that a real sandbox would deny. The current k3s-worker
module (`modules/roles/kubernetes/k3s-worker.nix`) already shows why:

```nix
kernel.modules = common.kernelModules;          # br_netfilter, vxlan, ip_set — GLOBAL
firewall.allowedTCP = [10250];                  # host kubelet port
systemd.services.k3s = {
  wantedBy = ["multi-user.target"];
  serviceConfig = {
    EnvironmentFile = "/etc/rancher/k3s/k3s.env";
    Delegate = "yes";                            # k3s manages its own cgroup subtree
  };
};
```

Honest consequences for the package/container model:

- **Kernel modules are global.** There is no per-container module namespace.
  `br_netfilter`/`vxlan`/`ip_set` load into the host kernel regardless of any
  nspawn boundary. The "container" cannot contain them.
- **Host network + cgroups.** k3s needs `--network=host` and `Delegate=yes`; an
  isolated veth/private-users container breaks pod networking and the kubelet's
  cgroup management. So k3s gets only a *nominal* container (mount/UTS isolation
  at most), and that must be labeled as such — it is **not** a security boundary.
- **Config is host-side.** k3s reads `/etc/rancher/k3s/k3s.env` via
  `EnvironmentFile`. Whatever container it runs in must bind-mount that host path
  in. Config delivery itself is **explicitly open** — see
  [`config.md`](config.md); do not assume a credstore.
- **Upgrades drain the node.** Because the root is immutable and upgrade is a
  restart (§5), upgrading the k3s package restarts kubelet, evicting/rescheduling
  workloads. That is an operational cost, not a bug, and must be documented.

The takeaway: the manifest must carry *some* class signal so `apm` knows *not*
to promise isolation for `host`/infrastructure packages — whether that is the
strawman `expose.kind` here or the first-class package **class** from Decision 1
in [`open-questions.md`](open-questions.md) is unresolved (§2.2). The
container-model details and the exact nspawn flags for the nominal k3s container
are in [`container-model.md`](container-model.md).

---

## 7. Signing and trust for container roots

The good news: container roots inherit the **existing** registry trust model
end to end, because they are delivered as ordinary NARs (§3.2) named by
tag-signed metadata.

1. **Metadata is tag-signed.** `expose.images[].store_path` and `nar_hash` live
   in `packages/<letter>/<name>.toml`, which is part of the git tree covered by
   the signed semver/channel release tag. `registry::verify` enforces
   name-binding and the `tag -> tag -> commit` chain
   (see [`../registry/signing-and-trust.md`](../registry/signing-and-trust.md)
   and [`../registry/current-state.md`](../registry/current-state.md) §6). So a
   container-root reference cannot be substituted without breaking the release
   signature.
2. **The NAR is content-addressed.** `verify_nar_hash()` checks the downloaded
   container-root NAR against the `nar_hash` from the signed metadata. The bytes
   cannot be tampered with in transit or at the cache.
3. **The cache may add a second signature.** Generated narinfo can be Nix-cache
   signed (`aos-core::nar::cache::NarInfoSigner`,
   [`../registry/current-state.md`](../registry/current-state.md) §7), so a
   stock-Nix substituter with `require-sigs = true` also accepts it.
4. **TOFU + anti-rollback still apply.** First sync pins the registry's Ed25519
   key; the anti-rollback floor prevents downgrading the package — and therefore
   its container root — below a stored semver
   (see [`../registry/current-state.md`](../registry/current-state.md) §4–5).

**No new trust primitive is required for fetched container roots.** They are
just NARs whose hashes are committed to tag-signed metadata.

**Honest gap for *baked* roots (§3.1):** a host-image-baked container root is
covered by the host image's own integrity (UKI / system closure), *not* by a
registry tag signature, because it never transits the registry. If a deployment
mixes baked and fetched roots for the same package across a fleet, the trust
story is split-brain (image-signed vs. tag-signed). Recommendation: pick one
delivery model per package — **fetch-at-boot via apm as the default**; if
baking, document the per-package choice explicitly. Tracked in Decision 5 of
[`open-questions.md`](open-questions.md).

---

## 8. Summary: the delta against the real install path

The whole feature is a small, well-bounded addition to a path that already
works:

| Stage | Today | Change for containerized packages |
|---|---|---|
| Registry metadata | `PackageMeta` | + `expose` (target/units/kind/images), all `#[serde(default)]` |
| Resolve | `resolve_multiple()` | also enqueue `expose.images[].store_path` |
| Download / verify / import | NAR path | **unchanged** — container root is just another NAR |
| Profile generation | gc-root + meta + FHS | also gc-root the container-root image |
| **Expose phase** | *(does not exist)* | **NEW**: drop launch unit + template instance + `aos-pkg-<name>.target`, then enable |
| Activation | n/a | `systemctl enable --now` (runtime) or Ignition `systemd.units[]` (first boot) |
| Trust | tag-signed metadata + NAR hash + cache sig | **unchanged** — roots ride the same chain |

The two genuinely new pieces are (a) the **expose phase** post-install hook and
(b) where its **unit files physically land** under the immutable-root /etc
overlay (§4.1). Both, plus config delivery and the baked-vs-fetched trust split,
are the open items carried into [`open-questions.md`](open-questions.md).
