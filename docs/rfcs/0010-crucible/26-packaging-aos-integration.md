# 26 — Packaging and AOS integration

This file specifies how Crucible **builds, ships, and is tested inside AOS**. It
is the bridge between the design (the determinism contract, the patch series, the
crate workspace) and the concrete, hermetic, from-source AOS build system whose
principles are stated in the repository `CLAUDE.md`. Everything Crucible needs to
run — the engine and CLI Rust crates, the patched QEMU, the in-VM plugin, the
determinism-configured guest kernel, and the test-fixture root images — is an AOS
package built from source with no upstream binary dependency and no host tools.

Requirement IDs in this file use the prefix `PKG`. The goal this file principally
serves is **[G-7]** (hermetic, from-source build inside AOS) and the invariant
**[INV-7]** (patch inertness: AOS's production QEMU is unaffected unless sim mode
is active). The non-goal it most carefully respects is **[NG-7]** (no dependency
on RFC-0007 `ratchet`).

Cross-references: the patch series this file applies and gates is
[`11-qemu-patches.md`](11-qemu-patches.md); the plugin it co-packages is
[`12-qemu-plugin.md`](12-qemu-plugin.md); the host-side QEMU integration is
[`10-qemu-integration.md`](10-qemu-integration.md); the discovery contract the CLI
relies on is [`23-cli.md`](23-cli.md) §5; the crate workspace and its layering is
[`27-crate-structure.md`](27-crate-structure.md); the gates this file wires into
CI are defined in [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md);
the ABIs this file versions are [`13-shmem-abi.md`](13-shmem-abi.md),
[`16-guest-host-channel.md`](16-guest-host-channel.md), and
[`21-api.md`](21-api.md); the `ratchet` seam is RFC-0007.

The four canonical gates this file wires and refers to are, per
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1:
`gate:qemu-inert`, `gate:patch-microtests`, `gate:e2e-determinism`, and
`gate:abi-conformance`.

## 26.1 AOS build principles Crucible inherits (non-negotiable)

Crucible is an AOS package set; it is bound by the same build principles as every
other package in the repository, restated here so the requirements that follow are
unambiguous.

- **[PKG-1]** Every Crucible artifact — the `crucible-*` Rust crates, the patched
  QEMU, the `crucible-qemu-plugin` cdylib, the guest kernel, and the root-image
  fixtures — MUST build **hermetically from source** using only the AOS bootstrap
  toolchain and previously-built AOS packages. No upstream nixpkgs package, no
  host tool, and no pre-built binary may enter any build or test derivation. This
  is the AOS principle stated in `CLAUDE.md` ("Hermetic builds from source"),
  applied to Crucible. *Gate:* `gate:e2e-determinism` (the whole closure builds in
  CI). *Spec:* §26.1; satisfies [G-7].

- **[PKG-2]** Crucible MUST NOT introduce a `/bin/sh`, `/bin/bash`, or
  `/usr/bin/env` reference into any build phase, wrapper, or generated script;
  shell references MUST use the AOS-built `bash` from the stdenv. The single
  permitted exception is the shebang inside a guest **rootfs** init script, which
  MAY use `/bin/sh` because the rootfs builder ([PKG-15]) creates that symlink
  pointing at the AOS bash inside the image. *Gate:* `gate:e2e-determinism`,
  `aos lint`. *Spec:* §26.1; satisfies [G-7].

- **[PKG-3]** Where a tool Crucible needs at build or test time already exists as
  an AOS package (e.g. `socat`, `jq`, QEMU itself), Crucible MUST use the AOS
  package, never a host or nixpkgs version. Test harnesses that run on the host
  MUST consume AOS-built tools. *Spec:* §26.1; satisfies [G-7].

- **[PKG-4]** Crucible packages MUST follow the AOS package structure: each is a
  Nix file taking `{ mkDerivation | mkCargoPackage, fetchurl, ... }` and returning
  a derivation, with version, mirror URLs, and source hash colocated inline, and
  with `buildDeps` / `runtimeDeps` / `propagatedDeps` classified per `CLAUDE.md`.
  The Rust crates use AOS's `mkCargoPackage` / `fetchCargoDeps` (the same path
  `pkgs.aos` uses), not a bespoke builder. *Spec:* §26.1; satisfies [G-7].

- **[PKG-5]** Package **completeness** is mandatory: Crucible MUST NOT remove a
  feature from QEMU, the kernel, or any dependency to simplify the build. A
  dependency QEMU needs (glib, pixman, zlib, libslirp, and the additional libs the
  sim build requires) MUST be built correctly as an AOS package rather than
  disabled. Stubbing is permitted only for a genuinely hard bootstrapping problem
  and MUST be marked `TODO` with a tracking note. *Spec:* §26.1; satisfies [G-7].

## 26.2 The package inventory

Crucible adds the following AOS packages. The layout mirrors the existing tree:
emulation packages under `pkgs/emulation/`, the kernel fixture under
`pkgs/kernel/`, and the Rust workspace under `pkgs/tools/crucible/` consuming the
crates at `crates/`.

```text
  pkgs/emulation/qemu.nix                 production QEMU (unchanged, sim-off)
  pkgs/emulation/qemu-crucible.nix        patched QEMU (same source + series)
  pkgs/emulation/crucible-qemu-plugin.nix in-VM plugin cdylib (12)
  pkgs/emulation/qemu-crucible-patches/   the crucible-*.patch series (11)
  pkgs/kernel/linux-crucible.nix          stock fixture guest kernel (no determinism shaping)
  pkgs/tools/crucible/crucible.nix        the crucible-* Rust workspace + CLI
  pkgs/tools/crucible/fixtures/           root-image fixtures (test guests)
  pkgs/tools/crucible/_tests.nix          the AOS checks (gates) wiring (§26.9)
```

- **[PKG-6]** The Crucible package set MUST expose, as AOS packages: the patched
  QEMU (`qemu-crucible`), the plugin (`crucible-qemu-plugin`), the Rust workspace
  (`crucible`), the stock fixture guest kernel (`linux-crucible`), and the
  root-image fixtures (`crucible-fixtures`). The unpatched production QEMU
  (`pkgs/emulation/qemu.nix`) MUST remain a separate, independently-buildable
  package so a system that wants production QEMU never pulls the patched build.
  *Spec:* §26.2; satisfies [G-7], [INV-7].

- **[PKG-7]** `qemu-crucible` and `crucible-qemu-plugin` MUST be built from the
  **same pinned QEMU source** and MUST co-locate so the CLI's hermetic discovery
  ([`23-cli.md`](23-cli.md) §5) finds a matched (binary, plugin) pair. The patched
  QEMU output MUST carry a **sim-capability marker** ([PKG-22]) that discovery and
  `gate:qemu-inert` read to distinguish it from production QEMU. *Spec:* §26.2;
  satisfies [G-7], [G-8].

## 26.3 The patched QEMU package (`qemu-crucible`)

The patched QEMU is the production QEMU package's source plus the `crucible-*`
series ([`11-qemu-patches.md`](11-qemu-patches.md)). The whole point is that the
*same source* yields a binary that is upstream-identical with sim mode off
([INV-7]) and Crucible-capable with sim mode on.

- **[PKG-8]** `qemu-crucible` MUST build the **same pinned upstream QEMU source**
  as the AOS production QEMU package, applying the ordered `crucible-*` patch
  series ([PATCH-7]) at unpack time, and MUST configure the build to compile the
  sim accelerator and shmem device files the series adds (e.g.
  `accel/tcg/tcg-accel-ops-sim.c`, `block/crucible-shmem.c`). It MUST NOT fork
  QEMU's source tarball; the only delta from production QEMU is the applied series.
  *Gate:* `gate:patch-microtests`. *Spec:* §26.3; satisfies [G-7], [PATCH-7].

- **[PKG-9]** The pinned QEMU version MUST be **≥ 10.0** ([PATCH-40]) — the
  version providing the plugin time-control API the design rests on. The exact
  pinned tag and source hash MUST be recorded inline in the package and in
  [`31-decision-register.md`](31-decision-register.md). The production QEMU package
  ([`pkgs/emulation/qemu.nix`](../../../pkgs/emulation/qemu.nix), currently 10.0.0)
  MUST be advanced to the same pin (or a compatible one) so production and patched
  QEMU share a single source, satisfying the "same source" half of [INV-7].
  *Gate:* `gate:qemu-inert`. *Spec:* §26.3; satisfies [G-7], [PATCH-40].

- **[PKG-10]** The series MUST be applied as a set of committed
  `crucible-*.patch` files under `pkgs/emulation/qemu-crucible-patches/`, applied
  in a stable, significant order ([PATCH-7]: sim-accel first). The package's
  unpack phase MUST apply them with the AOS-built `patch` tool, in order, failing
  the build loudly on any reject. The committed patch set MUST match the catalog
  in [`11-qemu-patches.md`](11-qemu-patches.md) §11.3 exactly: a patch present in
  the package but absent from the catalog, or vice versa, MUST fail the packaging
  conformance check ([PATCH-10]). *Gate:* `gate:patch-microtests`. *Spec:* §26.3;
  satisfies [G-7], [PATCH-10].

- **[PKG-11]** Diagnostic-only patches (`crucible-tcg-exec-diag`,
  `crucible-virtserial-socket`; [PATCH-36]) MUST NOT be applied in the shipped
  `qemu-crucible` package. They MAY be applied in a separate developer-only
  package variant (`qemu-crucible-dev`) and even there MUST be inert by default
  (compiled out or behind a `diag=` plugin arg). *Gate:* `gate:qemu-inert`.
  *Spec:* §26.3; satisfies [INV-7], [PATCH-36].

- **[PKG-12]** `qemu-crucible` MUST be built with
  `--target-list=x86_64-softmmu,aarch64-softmmu`
  and `-smp 1` semantics in mind ([NG-1]); KVM MAY be enabled in the build but is
  never used by Crucible (it runs TCG, [G-1]). The sim build MUST NOT disable any
  feature the production QEMU build enables that the determinism corpus exercises
  (virtfs/9p, slirp, virtio) — completeness per [PKG-5]. *Spec:* §26.3; satisfies
  [G-7], [PKG-5].

### 26.3.1 Inertness, gated in the package build (INV-7)

This is the load-bearing packaging requirement: the patched binary AOS ships must
be behaviorally identical to production QEMU when sim mode is off.

- **[PKG-13]** The `qemu-crucible` package's checks MUST include `gate:qemu-inert`
  ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1.2):
  build the unpatched production QEMU and the patched `qemu-crucible` from the same
  pinned source, and run an upstream-equivalent corpus (boot, device I/O,
  migration, snapshot, QMP introspection) against the patched binary **with sim
  mode off** (no plugin loaded, no `-accel sim`, no sim flags), asserting
  byte-identical guest-visible behavior versus the unpatched reference. A patch
  that perturbs any non-sim path fails the build. *Gate:* `gate:qemu-inert`.
  *Spec:* §26.3.1; satisfies [INV-7], [PATCH-1], [PATCH-2].

- **[PKG-14]** The `qemu-crucible` package's checks MUST include
  `gate:patch-microtests` ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)
  §1.2): for the pinned QEMU, (1) the series applies cleanly in order, (2) the
  patched tree builds, and (3) every per-patch micro-test ([PATCH-4], [PATCH-8],
  [PATCH-38]) passes — each demonstrating its entropy elimination/capability in
  sim mode *and* its inertness out of sim mode ([PATCH-5]). A change to the series,
  the pin, or the generated shmem header ([SHM-4]) MUST re-run this gate. *Gate:*
  `gate:patch-microtests`, `gate:qemu-inert`. *Spec:* §26.3.1; satisfies [G-7],
  [INV-7], [PATCH-8], [PATCH-38].

### 26.3.2 The rebasable series and the regeneration pipeline

- **[PKG-15]** The committed `crucible-*.patch` files MUST be reproducible by the
  regeneration pipeline ([PATCH-37]): a Crucible build target that produces the
  patch bytes from the tracked single-purpose development branch against the
  pinned tag, deterministically (stable author/date/ordering). CI MUST regenerate
  and **fail on drift** between the committed files and the regenerated ones.
  *Gate:* `gate:patch-microtests`. *Spec:* §26.3.2; satisfies [G-7], [PATCH-37].

- **[PKG-16]** A bump of the pinned QEMU version is a **re-gated packaging event**
  ([PATCH-39]): the series is rebased onto the new tag, `gate:patch-microtests` and
  `gate:qemu-inert` are re-run, and the new QEMU build identity is re-pinned into
  the reproduction-artifact provenance ([PKG-23]). The pin MUST NOT advance without
  both gates green. *Gate:* `gate:qemu-inert`, `gate:patch-microtests`,
  `gate:e2e-determinism`. *Spec:* §26.3.2; satisfies [G-7], [PATCH-39].

## 26.4 The plugin package (`crucible-qemu-plugin`)

The plugin ([`12-qemu-plugin.md`](12-qemu-plugin.md)) is a Rust `cdylib` loaded
into QEMU via `-plugin`; it owns virtual time and the device/channel callbacks. It
is the *only* thing that activates sim mode ([PATCH-1]).

- **[PKG-17]** `crucible-qemu-plugin` MUST be built as an AOS `mkCargoPackage`
  Rust `cdylib` from the `crates/crucible-qemu-plugin` crate ([PKG-4]), linking
  only AOS-built dependencies. It MUST be built against the **same pinned QEMU
  plugin-API headers** as `qemu-crucible` so the plugin ABI version it advertises
  matches the patched binary's exported surface ([PATCH-40], §11.5–§11.6). *Gate:*
  `gate:abi-conformance`. *Spec:* §26.4; satisfies [G-7], [G-8].

- **[PKG-18]** The plugin output MUST be co-located with `qemu-crucible` (e.g. as
  a propagated dependency exposed under a stable relative path) so the CLI's
  hermetic discovery finds the matched pair without `$PATH` groping
  ([`23-cli.md`](23-cli.md) §5, [CLI-13]). The plugin MUST embed its plugin-ABI
  version and the host shmem-ABI version ([PKG-21]) so discovery can verify a match
  and fail clearly on mismatch ([CLI-14]). *Spec:* §26.4; satisfies [G-8], [G-7].

## 26.5 The crucible crate workspace package (`crucible`)

The Rust workspace ([`27-crate-structure.md`](27-crate-structure.md)) — the L0–L4
crates plus the `crucible` CLI binary — builds with AOS's cargo packaging, exactly
as `pkgs.aos` does.

- **[PKG-19]** The `crucible` package MUST build the `crucible-*` workspace with
  `mkCargoPackage` + `fetchCargoDeps` ([PKG-4]), vendoring all crate dependencies
  through `fetchCargoDeps` (no network at build time), and MUST run the
  workspace-scoped Cargo test suite (`doCheck = true`, Cargo flags rooted at
  `--workspace` with the non-Crucible AOS CLI crates explicitly excluded) — which
  includes the L0/L1 determinism unit tests and the in-process QEMU double tests
  ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §3)
  that need no real QEMU. *Gate:* `gate:layer0-determinism`,
  `gate:abi-conformance`. *Spec:* §26.5; satisfies [G-7], [G-5].

- **[PKG-20]** The `crucible` CLI MUST locate the patched QEMU and the plugin
  **hermetically**, never from the host `$PATH` ([`23-cli.md`](23-cli.md) §5,
  [CLI-13]/[CLI-14]). The package MUST make the AOS-built `qemu-crucible` +
  `crucible-qemu-plugin` paths available to the CLI by one of: baking the
  store paths in at build time (a build-time substitution like the
  `pkgs.aos` wrapper's `@PATH@`/`@SELF@` pattern), or a thin wrapper that sets
  `CRUCIBLE_QEMU` / `CRUCIBLE_PLUGIN` to the co-packaged store paths. Explicit
  `--qemu`/`--plugin` flags and the `CRUCIBLE_QEMU`/`CRUCIBLE_PLUGIN` env vars
  MUST still override, in the discovery order of [`23-cli.md`](23-cli.md) §5. The
  host's `$PATH` QEMU MUST NOT be a fallback ([CLI-13]). *Spec:* §26.5; satisfies
  [G-7], [INV-7].

## 26.6 The three ABIs: versioning in the package (G-8)

Crucible has three boundary ABIs that the package versions and conformance-tests:
the shared-memory layout ([`13-shmem-abi.md`](13-shmem-abi.md)), the guest↔host
channel ([`16-guest-host-channel.md`](16-guest-host-channel.md)), and the
control-plane RPC ([`21-api.md`](21-api.md)). They are versioned **independently**
because they evolve independently: the shmem ABI binds the plugin to the patched
QEMU and the host executor; the guest↔host channel binds an optional in-guest
agent to the plugin; the RPC binds the CLI/clients to the daemon.

- **[PKG-21]** The package MUST stamp each of the three ABIs with an explicit,
  monotonic **version** at build time, embedded in the artifacts that speak it: the
  shmem-ABI version in `crucible-qemu-plugin` and the host engine; the guest↔host
  channel version in the channel codec; the RPC ABI version in the daemon and the
  CLI. A version mismatch at runtime MUST fail loudly with a clear message
  ([CLI-14], [INV-10]), never silently degrade. *Gate:* `gate:abi-conformance`.
  *Spec:* §26.6; satisfies [G-8], [INV-10].

- **[PKG-22]** The `qemu-crucible` build MUST emit a **sim-capability marker** —
  a small, queryable artifact (a metadata file in the package output and/or an
  exported symbol/`fw_cfg`-style identifier) recording: the pinned QEMU tag, the
  applied series identity (a hash of the ordered `crucible-*.patch` set), and the
  shmem-ABI version it was built against. Discovery ([CLI-13]) and `gate:qemu-inert`
  read this marker to confirm a binary is the patched build and that its
  shmem-ABI matches the plugin's. *Gate:* `gate:abi-conformance`, `gate:qemu-inert`.
  *Spec:* §26.6; satisfies [G-8], [INV-7].

- **[PKG-23]** The shmem ABI is generated from one source of truth ([SHM-4]); the
  package build MUST treat the **generated shmem header** as a build input shared
  by `qemu-crucible` (C side) and `crucible-qemu-plugin` (Rust side), so the two
  cannot drift. A regeneration of that header MUST re-run the patch series build
  ([PATCH-38]) and `gate:abi-conformance`'s golden-vector comparison. Intentional
  ABI changes require a version bump ([PKG-21]) + regenerated golden vectors in the
  same change ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)
  §8.1). *Gate:* `gate:abi-conformance`, `gate:patch-microtests`. *Spec:* §26.6;
  satisfies [G-8], [SHM-4].

## 26.7 The determinism guest kernel and root-image fixtures

These are **test fixtures Crucible ships**, not requirements on user guests. By
[G-2] (any unmodified guest) and [INV-5] (guest non-modification), a USER guest
needs none of this: Crucible boots an arbitrary guest kernel + image with
launch-time configuration only, no guest patches, no in-guest agent. The kernel
and images here exist so Crucible's own gates have a determinism-friendly,
hermetically-built guest to run.

- **[PKG-24]** Crucible MUST ship a **stock fixture guest kernel**
  (`linux-crucible`), built from source as an AOS package via `pkgs.linuxWith`
  (the `extraConfig` fragment mechanism, not `linux.override`). It is a plain
  defconfig plus only what a minimal fixture needs to boot — the virtio drivers
  the fixtures need (virtio-blk, virtio-9p, virtio-net), ext4, and
  serial console — with **no determinism shaping**; determinism comes entirely
  from the QEMU icount + seeded-entropy boundary
  (`host-side-qemu-icount-seeded-entropy`), not from the kernel config. This
  kernel is a **fixture**; it MUST NOT be a precondition for booting a user guest
  ([G-2]).
  *Gate:* `gate:any-guest` (proves an *unmodified* third guest also boots),
  `gate:e2e-determinism`. *Spec:* §26.7; satisfies [G-7], [G-2].

- **[PKG-25]** Crucible MUST ship minimal **root-image fixtures**
  (`crucible-fixtures`) built from source (AOS-built busybox-class userland + the
  AOS bash), using the sandbox-compatible image construction the repo already uses
  (`mkfs.ext4 -d`, no `losetup`/`mount`, per `CLAUDE.md` Testing), with the rootfs
  init shebang exception of [PKG-2]. These images are the test guests the gates
  boot; they MUST be small, deterministic, and content-addressed. They MUST NOT be
  mutated at run time — Crucible boots them copy-on-write ([INV-5]). *Gate:*
  `gate:e2e-determinism`. *Spec:* §26.7; satisfies [G-7], [INV-5].

The following four requirements pin the load-bearing determinism specifics of
the **shipped test fixtures**. They are requirements on Crucible's own
fixture kernel/rootfs, **not** on user guests: by [G-2] and [INV-5] an arbitrary
user guest needs none of this (Crucible's determinism is enforced at the QEMU/host
boundary by `-seed`+icount, [PKG-13], 11), and `gate:any-guest` ([PKG-26]) proves
it. These fixtures exist only to give Crucible's gates a small, hermetic,
boot-stable guest.

- **[PKG-39]** The fixture kernel (`linux-crucible`, [PKG-24]) is **deliberately
  stock**: a plain defconfig plus only the drivers a minimal fixture guest needs
  to boot (serial console, virtio-blk/virtio-9p/virtio-net, ext4) and no loadable
  modules. It applies **no determinism shaping** — its determinism mechanism is
  `host-side-qemu-icount-seeded-entropy`, i.e. determinism is delivered entirely
  at the QEMU `-seed`+icount boundary, never from kernel-side entropy
  suppression. It MUST **NOT** require `nokaslr`, `CONFIG_RANDOM=n`, or
  RDRAND/RDSEED disabling: because all boot entropy is seeded deterministically
  host-side (E8/E9; the emulated entropy QEMU feeds is itself seeded, 11
  [PATCH-16]), KASLR/ASLR and the guest CRNG are already reproducible with the
  stock kernel, so suppressing them would only reduce fidelity to a real guest
  for no determinism gain. For boot stability the fixture disables
  auto-module-loading (`# CONFIG_MODULES is not set`, equivalently a built-in-only
  config so `request_module` does nothing) and ACPI (`# CONFIG_ACPI is not set`);
  these are boot-stability choices for a minimal fixture, not determinism
  shaping. *Gate:* `gate:e2e-determinism`. *Spec:* §26.7; satisfies [G-2], [G-7].

- **[PKG-40]** The fixture boot MUST supply the guest a **deterministic
  entropy-seed** host-side — a fixed, content-addressed byte blob handed to the
  guest as bootloader/`setup_data` RNG seed (which a stock kernel that trusts
  bootloader entropy consumes as its CRNG seed) — *unless* the
  deterministic QEMU entropy patches ([PATCH-16], `crucible-det-getrandom`, plus a
  `-cpu` model advertising no `RDRAND`/`RDSEED`) already make the guest's CRNG seed
  a pure function of the run seed, in which case a separate fixed blob is
  unnecessary. The package MUST state which mechanism is in force; the chosen
  mechanism MUST make the guest CRNG seed bit-identical across two runs of the same
  `(image, seed)`. *Gate:* `gate:e2e-determinism`. *Spec:* §26.7; satisfies [G-7].

- **[PKG-41]** The fixture rootfs model MUST be a **read-only base image plus the
  host Nix store shared into the guest via virtio-9p** ([`15-io-subnodes.md`](15-io-subnodes.md)),
  not a fat writable disk; the guest boots it copy-on-write ([INV-5], [PKG-25]).
  The ext4 fixture images MUST be built with `mkfs.ext4 -d` (sandbox-compatible, no
  `losetup`/`mount`) and with the feature flags **`-O ^has_journal,^metadata_csum,^64bit`**:
  the journal is disabled because journal replay can panic the minimal fixture
  guest, and `^metadata_csum,^64bit` keep the image within the conservative feature
  set the fixture kernel mounts cleanly. These flags are a requirement, not a
  suggestion. *Gate:* `gate:e2e-determinism`. *Spec:* §26.7; satisfies [G-7],
  [INV-5].

- **[PKG-42]** Each fixture node's **guest MAC address MUST be a deterministic
  function of the node's stable content-addressed identity** ([`06-spatial-graph.md`](06-spatial-graph.md)),
  never of spawn order or launch sequence. A spawn-order-dependent MAC assignment
  is a determinism hazard: it makes ARP tables, neighbor discovery, and any
  MAC-ordered guest behavior depend on host scheduling, breaking bit-identical
  reproduction. The MAC (and any analogous per-node identifier) MUST be derived
  from the node id so two runs assign the same MAC to the same logical node
  regardless of the order the nodes happen to start. *Gate:* `gate:e2e-determinism`.
  *Spec:* §26.7; satisfies [G-7], [INV-9].

- **[PKG-26]** The fixtures MUST include at least one **unmodified third-party
  guest** path exercised by `gate:any-guest`
  ([`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1) —
  a stock kernel + image that received none of the determinism config of [PKG-24]
  — to prove Crucible's black-box determinism does not depend on the shipped
  fixtures' cooperation ([G-2], [INV-5]). *Gate:* `gate:any-guest`. *Spec:* §26.7;
  satisfies [G-2], [INV-5].

## 26.8 CI integration: determinism gates as AOS nix checks

The gates of [`24-determinism-harness-testing.md`](24-determinism-harness-testing.md)
are wired as AOS nix checks, following the existing `nix-checks`-driven CI model
(the same model `nix-build -A checks.eval` / `checks.vm.boot` use).

- **[PKG-27]** Each Crucible gate MUST be exposed as an AOS nix check so CI runs it
  via the existing check infrastructure. The mapping is: the **pure/eval-level**
  gates (`gate:harness-lint`, `gate:layer0-determinism`, `gate:content-address`,
  `gate:replay-oracle`, the L1 `gate:layer1-injection` and `gate:abi-conformance`
  run against the in-process QEMU double, [`24`](24-determinism-harness-testing.md)
  §3) MUST be wired under `checks.eval`-class checks (fast, no VM); the
  **QEMU-backed** gates (`gate:qemu-inert`, `gate:patch-microtests`) MUST be wired
  as package checks of `qemu-crucible` ([PKG-13], [PKG-14]); the **e2e** gate
  (`gate:e2e-determinism`) MUST be wired as a VM/fleet check ([PKG-29]). *Gate:*
  all four canonical gates. *Spec:* §26.8; satisfies [G-7], [G-5].

- **[PKG-28]** The gate ordering of [PLAN-4] / [HARN-3] MUST be honored in CI: a
  higher-layer check MUST NOT run until the lower layer's gate is green
  (L0 before L1 before L2, etc.). The phase plan of
  [`32-implementation-plan.md`](32-implementation-plan.md) §"How the gates compose"
  is the authoritative ordering; the CI wiring MUST reflect it. *Spec:* §26.8;
  satisfies [G-5].

- **[PKG-29]** `gate:e2e-determinism` MUST be wired as an AOS **VM/fleet check**
  (the `lib/testing` VM/fleet harness class, alongside `checks.vm.boot` and the
  fleet checks). It runs the representative multi-VM, fault-injected scenario
  bit-identically across adversarial host conditions and reproduces it from the
  emitted artifact ([HARN-22], [HARN-23]). The check MUST build the entire Crucible
  closure (patched QEMU + plugin + CLI + kernel + fixtures) hermetically as part of
  its inputs ([PKG-1]). *Gate:* `gate:e2e-determinism`. *Spec:* §26.8; satisfies
  [G-6], [G-7].

- **[PKG-30]** Crucible's QEMU-backed and e2e checks run under **TCG, not KVM**
  ([G-1]), and therefore **MUST NOT require `requiredSystemFeatures = [ "kvm" ]`**.
  This is a deliberate departure from the existing `checks.vm.*` convention (which
  uses KVM): Crucible's determinism *forbids* KVM, so its checks run on any CI
  runner without nested virtualization. The checks MAY be slower as a result; the
  performance budget for this is [`25-performance-targets.md`](25-performance-targets.md).
  *Gate:* `gate:e2e-determinism`. *Spec:* §26.8; satisfies [G-1], [G-9].

- **[PKG-31]** The packaging conformance check MUST assert the
  catalog↔package correspondence of [PATCH-10]: the set of `crucible-*.patch` files
  in the package equals the catalog inventory in
  [`11-qemu-patches.md`](11-qemu-patches.md) §11.3, the dev-only patches are not in
  the shipped package ([PKG-11]), and every patch maps to a stated requirement
  ([PATCH-6]). *Gate:* `gate:patch-microtests`. *Spec:* §26.8; satisfies [INV-7],
  [PATCH-10].

## 26.9 The ratchet gate (NG-7): ship standalone, gate the merge

Crucible and RFC-0007 `ratchet` are conceptual cousins — both are
content-addressed, incremental, determinism-obsessed Rust graph-reduction systems
— and they plausibly share one lower-level substrate: a **content-addressed store
plus a dependency-gated invalidation primitive**, which serves ratchet's
incremental evaluation cache and Crucible's temporal graph ([`07-temporal-graph.md`](07-temporal-graph.md))
equally. But RFC-0007 is **still in flight**, and [NG-7] forbids Crucible
depending on it landing. This section specifies the seam so the future merge is
cheap and the present ships standalone.

- **[PKG-32]** Crucible MUST ship **standalone**: it MUST NOT take a build- or
  run-time dependency on any `ratchet` / RFC-0007 crate or artifact. The Crucible
  package closure MUST build and all gates MUST pass with no RFC-0007 code present
  in the tree. *Gate:* `gate:e2e-determinism`. *Spec:* §26.9; satisfies [NG-7],
  [G-7].

- **[PKG-33]** The shared substrate Crucible needs now — a **content-addressed
  store** (`hash(content) → bytes`, dedup, integrity-checked) and a
  **dependency-gated invalidation primitive** (a node is invalid iff an input's
  content hash changed) — MUST be implemented as a small, **self-contained
  Crucible-owned crate** (e.g. `crucible-cas`), vendored/reimplemented inside the
  workspace, depending on nothing from RFC-0007. It MUST be the minimum Crucible's
  temporal graph and content addressing ([INV-6]) require, not a general-purpose
  store. *Gate:* `gate:content-address`, `gate:replay-oracle`. *Spec:* §26.9;
  satisfies [NG-7], [INV-6].

- **[PKG-34]** The seam MUST carry an explicit **merge marker**: the
  `crucible-cas` crate's module docs MUST name RFC-0007 as the future home of a
  shared substrate, MUST enumerate the **narrow interface** (the trait/signature
  surface: `put`/`get`/`has` by content hash, and the invalidation query) that a
  future common crate would implement, and MUST state the conformance bar a shared
  implementation must meet to replace it (pass `gate:content-address` and
  `gate:replay-oracle` unchanged). This marker is the documented contract of the
  future integration; it is text, not a dependency. *Spec:* §26.9; satisfies
  [NG-7].

- **[PKG-45]** The ratchet seam MUST be **the same seam** for the standalone
  single-host store and the **fleet-visible content-addressed `DagStore` backend**
  of [PKG-43]: the fleet store and its dependency-gated invalidation
  ([PKG-33]) MUST sit **behind `crucible-cas`'s unchanged narrow interface**
  ([PKG-34]), so that a future RFC-0007 ratchet shared substrate slots in at the
  identical seam whether Crucible runs on one host or a fleet
  ([`35-distributed-exploration.md`](35-distributed-exploration.md)). The
  `crucible-cas` module docs MUST name the fleet-visible store and the
  dependency-gated invalidation as that shared seam, and MUST state the same merge
  bar: a shared implementation replaces it only if it passes
  `gate:content-address`, `gate:replay-oracle`, and `gate:e2e-determinism`
  unchanged. Crucible MUST still ship **standalone** with no RFC-0007 dependency
  ([NG-7], [PKG-32]); the fleet store is a Crucible-owned implementation behind the
  same interface, not an RFC-0007 import. *Gate:* `gate:content-address`,
  `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:* §26.9, §26.11; satisfies
  [NG-7], [INV-6].

- **[PKG-35]** The **future-merge plan** MUST be: when RFC-0007 lands a stable
  content-addressed-store + invalidation crate, replace `crucible-cas`'s internals
  with a thin adapter over it **behind the unchanged interface of [PKG-34]**,
  gated by re-running `gate:content-address`, `gate:replay-oracle`, and
  `gate:e2e-determinism` with no behavioral change. The merge MUST NOT alter
  Crucible's ABIs ([PKG-21]) or determinism contract; if the shared crate cannot
  pass these gates, Crucible keeps `crucible-cas` and the merge does not happen.
  Until then, no RFC-0007 dependency exists ([NG-7]). *Gate:* `gate:content-address`,
  `gate:replay-oracle`, `gate:e2e-determinism`. *Spec:* §26.9; satisfies [NG-7],
  [INV-2], [INV-6].

## 26.10 Versioning and release reproducibility

- **[PKG-36]** The Crucible release MUST version **three things independently and
  explicitly**: (1) the **Crucible software version** (the `crucible-*` workspace
  semver), (2) the **pinned QEMU tag + applied series identity** ([PKG-22]), and
  (3) the **three ABI versions** ([PKG-21]: shmem, guest↔host channel, RPC). A
  release manifest in the package output MUST record all three so a downstream
  consumer (and a reproduction artifact) can pin exactly what produced a run.
  *Gate:* `gate:abi-conformance`. *Spec:* §26.10; satisfies [G-8].

- **[PKG-37]** Every Crucible package MUST be **reproducible**: hermetic from
  source ([PKG-1]), with pinned source hashes and vendored cargo deps, so a rebuild
  of the same revision yields the same closure. The patched QEMU build identity
  ([PKG-22]) MUST be part of every reproduction artifact ([DET-40], [PKG-23]); a
  determinism run reproduces only against the **exact** QEMU build that produced it
  ([PATCH-39]). The release MUST NOT embed wall-clock timestamps or host paths that
  break bit-reproducibility of the artifacts. *Gate:* `gate:e2e-determinism`,
  `gate:qemu-inert`. *Spec:* §26.10; satisfies [G-7], [DET-40].

- **[PKG-38]** A reproduction artifact ([`23-cli.md`](23-cli.md) §4, [CLI-15])
  MUST record the full provenance triple of [PKG-36] — Crucible version, QEMU
  build identity + series hash, and the three ABI versions — so `crucible replay`
  ([`23-cli.md`](23-cli.md) §12) can refuse to replay against a mismatched build
  rather than silently produce a different run. *Gate:* `gate:e2e-determinism`.
  *Spec:* §26.10; satisfies [G-6], [G-8], [INV-10].

## 26.11 Distributed exploration: the fleet store and campaign provenance

Distributed/continuous exploration ([`35-distributed-exploration.md`](35-distributed-exploration.md))
needs two packaging-level commitments beyond the single-host build: a
fleet-visible content-addressed store the explorer hosts share, built from source
as an AOS component; and a **provenance-keyed campaign** so that a corpus never
carries findings across an incompatible build.

- **[PKG-43]** The **fleet-visible content-addressed `DagStore` backend** (the
  store explorer hosts share to publish and fetch checkpoints/ancestors, 07,
  [`35-distributed-exploration.md`](35-distributed-exploration.md)) MUST be an
  **AOS-built from-source component** ([PKG-1]) — no upstream binary, no host
  tool, no nixpkgs — and the distributed-search / continuous-campaign capability
  MUST be wired as an **AOS VM/fleet check** in the `lib/testing` VM/fleet harness
  class (alongside [PKG-29]), running **TCG-only with no `kvm` feature** ([PKG-30],
  [G-1]) so it runs on any CI runner without nested virtualization. The check MUST
  build the fleet-store component and the explorer closure hermetically as part of
  its inputs ([PKG-1]). *Gate:* `gate:e2e-determinism`, `gate:campaign-continuity`.
  *Spec:* §26.11; satisfies [G-7], [G-1], [G-6].

- **[PKG-44]** A campaign MUST be **keyed to the provenance triple** of
  [PKG-36]/[PKG-38] — the Crucible software version, the QEMU build identity +
  applied patch-series hash, and the three ABI versions ([PKG-21]). Seeding a new
  campaign (or a CI run) from a prior corpus MUST **refuse cross-provenance reuse**:
  a QEMU bump, a patch-series change, or any ABI bump ([PKG-16], [PKG-23]) starts a
  **fresh campaign lineage** rather than mixing findings produced by a different
  build (which could no longer reproduce, [PKG-38]). The refusal MUST be loud and
  recorded as a fresh-lineage baseline event ([PERF-28],
  [`31-decision-register.md`](31-decision-register.md)), never a silent merge.
  *Gate:* `gate:e2e-determinism`, `gate:campaign-continuity`. *Spec:* §26.11;
  satisfies [G-6], [G-8], [INV-10].

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is packaging / AOS integration, tracked by [PLAN-3].
> They populate the packaging slice of the plan and feed `gate:qemu-inert`,
> `gate:patch-microtests`, `gate:abi-conformance`, and `gate:e2e-determinism`.

- [x] **T-PKG-1** Establish the Crucible package inventory under
  `pkgs/emulation/`, `pkgs/kernel/`, and `pkgs/tools/crucible/` with AOS package
  structure (mkDerivation / mkCargoPackage, inline pins, dep classification), no
  host tools, no nixpkgs. — satisfies [PKG-1], [PKG-2], [PKG-3], [PKG-4], [PKG-6],
  [G-7]; spec §26.1, §26.2.
  - Completed by `checks.crucible.phase7.cruciblePackageInventory`: the AOS package
    set exposes `pkgs.qemu`, `pkgs.qemu-crucible`,
    `pkgs.qemu-crucible-reference`, `pkgs.crucible-qemu-plugin`,
    `pkgs.linux-crucible`, `pkgs.crucible`, `pkgs.crucible-fixtures`,
    `pkgs.crucible-guest`, and `pkgs.crucible-fleet-store`; the guard verifies
    builder style, inline pins/vendor hashes, dependency classification, package
    attr names, production-vs-patched QEMU separation, and absence of nixpkgs or
    `hostTools` in the Crucible package files.
- [x] **T-PKG-2** Package `qemu-crucible`: same pinned (≥ 10.0) QEMU source as
  production QEMU + ordered `crucible-*.patch` series applied at unpack, sim accel
  / shmem device files compiled in, completeness preserved; build `qemu-crucible`
  and `crucible-qemu-plugin` from the same pinned QEMU source, co-located as a
  matched pair with a sim-capability marker. — satisfies [PKG-5], [PKG-7], [PKG-8],
  [PKG-9], [PKG-10], [PKG-12]; spec §26.2, §26.3.
  - Completed by `checks.crucible.phase7.crucibleQemuPackage`: production
    `pkgs.qemu` now keeps `applyCruciblePatches = false` by default,
    `pkgs.qemu-crucible` explicitly opts into the ordered patch series and plugin
    support from the same QEMU pin, `pkgs.qemu-crucible-reference` stays unpatched
    for inertness comparison, and the plugin package consumes the matched
    `qemu-crucible` header and sim-capability marker.
- [x] **T-PKG-3** Wire `gate:qemu-inert` as a `qemu-crucible` package check:
  unpatched vs patched-sim-off byte-identical over the upstream-equivalent corpus.
  — satisfies [PKG-13]; spec §26.3.1, routes [INV-7].
  - Completed by `checks.crucible.phase2.gates.qemuInert`; the AOS package set now
    exposes `qemu-crucible-reference` from the same pinned source with
    `applyCruciblePatches = false` for the comparison.
- [x] **T-PKG-4** Wire `gate:patch-microtests` as a package check: apply-clean +
  build + every per-patch micro-test (sim-on effect + sim-off inertness), re-run on
  series/pin/header change. — satisfies [PKG-14]; spec §26.3.1.
  - Completed by `checks.crucible.phase2.gates.patchMicrotests` and verified by
    `checks.crucible.phase7.crucibleGateCiWiring`: the AOS package
    check collector exposes `qemu-crucible.checks.patch-microtests` as
    `checks.integration.qemu-crucible-patch-microtests`, and that integration
    check imports `phase2-patch-microtests.nix` with `qemuPackage = self` so
    clean apply, prefix provenance, patched build, and live drop-one semantic
    probes run against the package output on series/pin/header drift. All 41
    patches have exactly one accepted attribution method, while composition and
    structural fallback counts are enforced at zero.
- [x] **T-PKG-5** Implement the patch regeneration/drift pipeline (reproducible
  patch bytes from the tracked branch) and the QEMU-version-bump re-gate. —
  satisfies [PKG-15], [PKG-16]; spec §26.3.2.
  - Completed by `checks.crucible.phase2.qemuPatchRegeneration` and the
    `gate:patch-microtests` aggregate: `pkgs/emulation/qemu-patches/_series.nix`
    is the package-consumed manifest for the QEMU pin, source hash, ordered patch
    inventory, tracked branch bundle, deterministic branch metadata, and patch
    files. `pkgs/emulation/qemu.nix` applies that manifest order directly, derives
    a build identity from the QEMU pin, qemu.nix hash, configure flags,
    patch-series hash, and patch-branch bundle/material, and installs
    `share/aos/crucible/qemu-build-identity.env` from that manifest, while the
    regeneration gate verifies the bundle base/head and per-patch commit/tree
    list, byte-compares regenerated patch output to the committed series, and
    proves that changed QEMU build material would re-gate rather than replay under
    the old reproduction-artifact identity.
- [x] **T-PKG-6** Keep dev-only diagnostic patches out of the shipped package
  (optional `qemu-crucible-dev` variant, inert-by-default). — satisfies [PKG-11];
  spec §26.3.
  - Completed by `checks.crucible.phase1.qemuDiagnosticPatchesDevOnly` and
    `gate:patch-microtests`: the shipped `qemu-crucible` package applies no
    `crucible-tcg-exec-diag` or `crucible-virtserial-socket` patch, no
    `qemu-crucible-dev` variant is present yet, and the diagnostic surface stays
    absent unless a future explicit dev-only package adds an opt-in `diag=`
    guard and its own inertness evidence.
- [x] **T-PKG-7** Package `crucible-qemu-plugin` as an AOS `mkCargoPackage`
  cdylib built against the same pinned plugin-API headers, co-located with
  `qemu-crucible`, embedding plugin-ABI + shmem-ABI versions. — satisfies [PKG-17],
  [PKG-18]; spec §26.4.
  - Completed by `checks.crucible.phase7.crucibleQemuPluginPackage`: the phase7
    gate statically verifies that `pkgs.crucible-qemu-plugin` is defined with
    AOS `mkCargoPackage`/`fetchCargoDeps`, builds the `crucible-qemu-plugin`
    cdylib against `qemu-crucible`, probes the matched `qemu-plugin.h` header
    and QEMU plugin API version during the package build, installs both the
    canonical library and QEMU plugin search-path entry, and emits
    `nix-support/crucible-qemu-plugin-build-info` with the matched QEMU build
    identity, QEMU plugin API version/ABI label, shmem ABI version/label, and
    CLI compatibility plugin ABI marker. It also verifies that `pkgs.crucible`
    carries matched AOS QEMU/plugin runtime hints and that
    `checks.crucible.phase1.aosWorkspaceBuild` is the package-output smoke
    verifier for the built `.so`, QEMU plugin path, and ABI metadata.
- [x] **T-PKG-8** Package the `crucible` workspace + CLI with `mkCargoPackage` /
  `fetchCargoDeps`, vendored deps, `--workspace` tests (L0/L1 + double tests). —
  satisfies [PKG-19]; spec §26.5.
  - Completed by `checks.crucible.phase7.crucibleWorkspacePackage`: the
    `pkgs.crucible` package uses AOS `mkCargoPackage` + `fetchCargoDeps` with a
    fixed vendored dependency hash, builds and tests the Crucible member inventory
    through workspace-scoped Cargo flags rooted at `--workspace`, excludes the
    non-Crucible AOS CLI crates that share `crates/Cargo.toml`, keeps package
    checks enabled, runs clippy, warning-free rustdoc, and hermetic doctests in the
    package build, installs the `crucible` CLI, and emits
    `nix-support/crucible-build-info` recording the workspace flags and hermetic
    cargo-deps path.
- [x] **T-PKG-9** Implement hermetic QEMU/plugin discovery wiring in the `crucible`
  package (baked store paths or `CRUCIBLE_QEMU`/`CRUCIBLE_PLUGIN` wrapper; flag/env
  overrides; no host `$PATH` fallback). — satisfies [PKG-20]; spec §26.5,
  coordinates with [`23-cli.md`](23-cli.md) §5.
  - Completed by `checks.crucible.phase7.cruciblePackageHermeticDiscovery`: the
    package builds the CLI with compile-time AOS package-set hints for
    `qemu-crucible` and `crucible-qemu-plugin`, keeps both in the runtime
    closure, records the resolved package paths in `crucible-build-info`, and
    links to `checks.crucible.phase5.cliHermeticDiscovery` for the CLI behavior
    proof that flags override env, env overrides AOS hints, artifact markers are
    checked for QEMU/plugin identity and plugin ABI compatibility, and host
    `$PATH` QEMU is never a fallback. `checks.crucible.phase1.aosWorkspaceBuild`
    is the package-output smoke verifier for the emitted discovery metadata.
- [x] **T-PKG-10** Version the three ABIs independently in the artifacts that speak
  them, with loud mismatch failure; emit the `qemu-crucible` sim-capability marker;
  share the generated shmem header across C and Rust. — satisfies [PKG-21],
  [PKG-22], [PKG-23]; spec §26.6.
  - Completed by `checks.crucible.phase7.cruciblePackageAbiVersioning`: the
    package gate verifies that `qemu-crucible`, `crucible-qemu-plugin`, and
    `crucible` stamp the shmem ABI, guest-host channel ABI, and RPC ABI from
    their Rust source constants; QEMU's sim-capability marker records the QEMU
    tag/build identity, patch-series material, shmem ABI label, generated-header
    install path, and generated-header hash; the plugin C probe compiles against
    the same generated `crucible_shmem_abi.h` installed by QEMU; and CLI
    discovery rejects QEMU/plugin shmem ABI disagreement loudly. The gate also
    ties the package-output proof to `checks.crucible.phase1.aosWorkspaceBuild`,
    the golden-vector/version-field proof to `checks.crucible.phase2.abiConformance`,
    and the QEMU marker/build-identity proof to
    `checks.crucible.phase2.qemuPatchRegeneration` plus the patch-microtest
    aggregate.
- [x] **T-PKG-11** Wire `gate:abi-conformance` (shmem/protocol/RPC golden vectors,
  version-field checks) as an eval/double-backed AOS check. — satisfies [PKG-19],
  [PKG-21], [PKG-23]; spec §26.6, §26.8.
  - Completed by `checks.crucible.phase7.cruciblePackageAbiConformance`: the
    package gate verifies that `checks.crucible.phase2.abiConformance` is an AOS
    `pkgs.mkDerivation` check using vendored, frozen/offline Cargo execution and
    that `checks.crucible.phase2.gates.abiConformance` wraps the same gate in the
    phase ladder. It requires the shmem generated-header/layout/golden-vector
    suite, the protocol and doorbell golden-vector suites, the RPC semantic
    version/golden-vector/major-mismatch suite, and the engine test-double
    aggregate to stay wired.
- [x] **T-PKG-12** Build the stock fixture guest kernel `linux-crucible` via
  `pkgs.linuxWith` extraConfig (single-vCPU, virtio drivers, ext4, serial; no
  auto-module-load and no ACPI for boot stability; no determinism shaping — no
  nokaslr/`CONFIG_RANDOM=n`/RDRAND-disable, KASLR/ASLR left enabled and sealed
  host-side), as a fixture, not a guest precondition. — satisfies [PKG-24],
  [PKG-39]; spec §26.7.
  - Completed by `checks.crucible.phase7.crucibleLinuxKernel`: `pkgs.linux-crucible`
    is a distinct package built through `pkgs.linuxWith` extraConfig, marks itself
    fixture-only, exports the fixture kernel config/cmdline contract, keeps the
    generic `system.build.kernel = pkgs.linux` default intact, requires the
    `checks.crucible.phase2.gates.anyGuest` proof, feeds
    `checks.crucible.phase7.gates.e2eDeterminism`, and inspects the installed
    final kernel config to prove the single-vCPU/fixed-timer/virtio/serial/
    bootloader-entropy/no-modules/no-ACPI contract without requiring `nokaslr`,
    `CONFIG_RANDOM=n`, or RDRAND/RDSEED disabling.
- [x] **T-PKG-13** Build the minimal root-image fixtures `crucible-fixtures`
  from source (read-only base + virtio-9p host store share; `mkfs.ext4 -d` with
  `-O ^has_journal,^metadata_csum,^64bit`; CoW boot; rootfs init shebang
  exception), with a deterministic entropy-seed mechanism and node-id-derived guest
  MACs, plus one unmodified third-party guest path. — satisfies [PKG-25], [PKG-26],
  [PKG-40], [PKG-41], [PKG-42]; spec §26.7.
  - Completed by `checks.crucible.phase7.crucibleFixtures`: `pkgs.crucible-fixtures`
    builds a minimal source-generated ext4 root image using `fakeroot -- mkfs.ext4
    -d` and the required `-O ^has_journal,^metadata_csum,^64bit` features, exports
    a read-only base plus a qcow2 CoW preparation artifact, a launch fragment with
    `init=/init`, and a readonly virtio-9p host-store mount. It carries the
    `/bin/sh` rootfs-init exception backed by the AOS bash boot closure, ships a
    deterministic 32-byte `crucible-guest-entropy-seed.bin` artifact while
    documenting the scenario-seed fw_cfg/QEMU RNG mechanism, derives fixture node
    IDs and MAC addresses from generated root-image SHA-256 identities, and
    includes a separate unmodified generic AOS Linux guest root image with no
    in-guest Crucible payload, exercised by `checks.crucible.phase2.gates.anyGuest`.
- [x] **T-PKG-14** Wire the determinism gates as AOS nix checks with correct
  layer ordering: eval-class L0/L1/ABI gates, package-class QEMU gates, VM/fleet
  e2e gate. — satisfies [PKG-27], [PKG-28]; spec §26.8.
  - Completed by `checks.crucible.phase7.crucibleGateCiWiring`: the CI guard
    classifies the canonical determinism gates into eval-class L0/L1/ABI checks,
    package-class `checks.integration.qemu-crucible-*` checks, and the phase-7
    `checks.fleet.crucible-e2e-determinism` fleet check surface for
    `gate:e2e-determinism`. It fails if the checked canonical gate targets or
    required green-before-advance dependency edges drift from the current wiring.
    `T-PKG-15` supplies the concrete TCG-only VM/fleet runner for the e2e scenario.
- [x] **T-PKG-15** Wire `gate:e2e-determinism` as a VM/fleet check that builds the
  whole Crucible closure and runs the adversarial multi-VM + reproduce scenario,
  **without** `requiredSystemFeatures = [ "kvm" ]` (TCG only). — satisfies
  [PKG-29], [PKG-30]; spec §26.8.
  - Completed by `checks.fleet.crucible-e2e-determinism`: the fleet check is now a
    real AOS VM/fleet runner (`tests/crucible/_fleet-runner.nix`) rather than a
    surface-only gate wrapper. It assembles the **entire Crucible closure**
    hermetically as build inputs — `pkgs.crucible` (which carries `qemu-crucible`
    and `crucible-qemu-plugin` through its `runtimeDeps`), `pkgs.linux-crucible`,
    and `pkgs.crucible-fixtures` ([PKG-1], [PKG-29]) — and **executes the built
    `crucible` CLI end to end** over the built-in adversarial multi-node,
    fault-injected example corpus (`happy-path.scn`, `partition-recovery.scn`,
    `crash-restart.scn`, `fault-campaign.fam`) under the hostile host-condition
    matrix (`verify --adversarial --bisect --runs 2`), asserting bit-identical
    reductions and reproduction — the representative multi-VM + reproduce scenario
    of §26.8. The runner **never** sets `requiredSystemFeatures = [ "kvm" ]` and
    records `tcg_only=true`, `required_system_features=none`, `kvm_required=false`
    ([PKG-30], [G-1]). The phase7 e2e gate
    (`checks.crucible.phase7.gates.e2eDeterminism`, the in-process determinism
    proof of the same scenario) is consumed as a green precondition. The same
    `mkCrucibleFleetCheck` substrate is reused by the real-VM performance checks.
    Each independent reduction uses `--backend qemu` and launches the
    closure-owned `qemu-crucible` with the production plugin under TCG against
    the AOS-built kernel/root fixture before running the deterministic
    session-level scenario comparison. The runner validates the live plugin
    protocol/ABI handshake, setup acknowledgement, boot barrier, orderly exit,
    exact terminal icount, and execution fingerprint, so a missing or mismatched
    production backend fails the fleet check rather than falling back to the
    in-process double.
- [x] **T-PKG-16** Implement the packaging conformance check (catalog↔package
  correspondence, dev-only exclusion, requirement mapping). — satisfies [PKG-31];
  spec §26.8.
  - Completed by `checks.crucible.phase7.cruciblePackagingConformance`: the
    phase7 package check imports `pkgs/emulation/qemu-patches/_series.nix`,
    compares the shipped `pkgs/emulation/qemu-patches/*.patch` set to
    `series.patchFiles`, parses the §11.3 catalog rows, verifies every shipped
    manifest `catalogName` has a catalog row, verifies the documented
    catalog-only capability rows are mapped to their carrier patches, rejects
    dev-only diagnostic patches in the shipped directory/manifest/package wiring,
    and requires every manifest patch and catalog-only capability to carry a
    stated requirement token whose class/enforcement metadata matches the catalog
    row. It consumes the direct `phase2-patch-microtests.nix` aggregate for
    `checks.crucible.phase2.gates.patchMicrotests`, keeping the catalog audit
    attached to the package patch build/test gate without pulling unrelated
    green-before-advance wrappers into instantiation.
- [x] **T-PKG-17** Implement the `crucible-cas` self-contained content-addressed
  store + dependency-gated invalidation crate, depending on nothing from RFC-0007.
  — satisfies [PKG-32], [PKG-33]; spec §26.9.
  - Completed by `checks.crucible.phase7.crucibleCas`: `crucible-cas` is a
    standalone Crucible-owned workspace crate and package-inventory member with
    no RFC-0007/ratchet dependency. It provides BLAKE3 `ContentHash` keys,
    `DagStore` `put`/`get`/`has` operations, in-memory and two-level local
    backends, and an invalidation query that marks a node invalid iff an input's
    content hash changed. The crate's unit tests cover deduplicating writes,
    two-level layout and integrity validation, and dependency-gated invalidation.
- [x] **T-PKG-18** Write the ratchet-seam merge marker (module docs: future home,
  narrow interface, conformance bar) and the future-merge plan (thin adapter behind
  the unchanged interface, gate-gated), keeping Crucible standalone with no
  RFC-0007 dependency. — satisfies [PKG-34], [PKG-35], [NG-7]; spec §26.9.
  - Completed by `checks.crucible.phase7.crucibleCasRatchetSeam`: the
    `crucible-cas` module docs name RFC-0007 as the future home, enumerate the
    narrow `put`/`get`/`has` plus invalidation-query interface, record the thin
    adapter merge plan behind that unchanged interface, and state the required
    gate bar (`gate:content-address`, `gate:replay-oracle`, and
    `gate:e2e-determinism`) while preserving the current no-RFC-0007 dependency
    rule.
- [x] **T-PKG-19** Produce the release manifest versioning the three things
  (Crucible version, QEMU tag + series hash, three ABI versions) and ensure
  per-package reproducibility (pinned hashes, vendored deps, no embedded
  timestamps). — satisfies [PKG-36], [PKG-37]; spec §26.10.
  - Completed by `checks.crucible.phase7.crucibleReleaseManifest`: the
    `crucible` package now installs `release-manifest.env` and
    `release-manifest.json` recording the Crucible workspace semver, the pinned
    filtered Crucible source store identity, QEMU version/source hash/build
    identity/patch-series hash, and the shmem, guest-host channel, and RPC ABI
    versions. The gate compares those values to Rust constants and QEMU passthru
    metadata, verifies the installed manifest files, verifies pinned
    `fetchCargoDeps` and QEMU source/patch hashes, confirms the source filter
    excludes `.git`, `target`, and `result`, rejects wall-clock timestamp
    emitters in the package metadata paths, and is a dependency of
    `checks.crucible.phase7.gates.e2eDeterminism`.
- [x] **T-PKG-20** Record the full provenance triple in every reproduction artifact
  so `crucible replay` refuses a mismatched build. — satisfies [PKG-38]; spec
  §26.10, coordinates with [`23-cli.md`](23-cli.md) §4, §12.
  - Completed by `checks.crucible.phase7.reproductionProvenanceTriple`: the
    canonical reproduction artifact schema is now `crucible.reproduction-artifact.v2`
    and its pinned identity records the Crucible software version, QEMU build
    identity, QEMU patch-series hash, shmem ABI version, guest-host protocol
    version, RPC ABI version/build tag, and plugin ABI. `crucible replay`
    decodes that full identity, derives the local QEMU patch-series and shmem ABI
    from the discovered AOS QEMU/plugin markers, derives the guest-host and RPC
    ABI versions from Rust source constants, and rejects any identity mismatch
    before replay. Remote-daemon replay and mock failure artifact emission refuse
    to synthesize local-double provenance when the producer build identity is not
    available, and remote verify divergences skip side reproduction artifacts
    rather than stamping them with fallback local provenance. The gate also
    verifies the mock e2e and replay-oracle artifact identities carry the same
    provenance fields and makes
    `checks.crucible.phase7.gates.e2eDeterminism` depend on the provenance check
    alongside the release manifest check.
- [x] **T-PKG-21** Build the fleet-visible content-addressed `DagStore` backend as
  an AOS from-source component and wire the distributed-search / continuous-campaign
  capability as a TCG-only AOS VM/fleet check (no `kvm` feature), building the
  fleet-store + explorer closure hermetically. — satisfies [PKG-43]; spec §26.11;
  cross-ref [`35-distributed-exploration.md`](35-distributed-exploration.md).
  - Completed by `checks.crucible.phase7.crucibleFleetStore`: `crucible-cas`
    now exports the fleet-visible `SharedDagStore` behind the existing
    `DagStore::put`/`DagStore::get`/`DagStore::has` interface with
    location-independent identities, exclusive temp creation, and idempotent
    concurrent publish tests.
    `pkgs.crucible-fleet-store` builds the probe binary from source with
    `mkCargoPackage`/`fetchCargoDeps`, records `fleet_visible=true` and
    `aos_from_source=true` in package metadata, and exercises the shared store in
    `postInstall`. `checks.fleet.crucible-distributed-continuous-exploration`
    builds both `pkgs.crucible-fleet-store` and the `pkgs.crucible` explorer
    closure as hermetic inputs, runs the shared-store probe, and records
    `tcg_only=true`, `required_system_features=none`, and `kvm_required=false`.
    Campaign provenance lineage and cross-provenance corpus refusal remain
    covered by T-PKG-22.
- [x] **T-PKG-22** Key campaigns to the provenance triple and refuse cross-provenance
  corpus reuse (a QEMU/patch-series/ABI bump starts a fresh campaign lineage,
  recorded as a baseline event), loudly rather than silently merging. — satisfies
  [PKG-44]; spec §26.11; cross-ref [PERF-28].
  - Completed by `checks.crucible.phase7.crucibleCampaignProvenance`:
    `crucible-harness` now exposes `campaign_provenance_key` and
    `evaluate_campaign_corpus_reuse` over the same pinned build identity carried
    by reproduction artifacts. A prior corpus with the same provenance key seeds
    the existing lineage; a QEMU patch-series or ABI mismatch returns
    `RefuseCrossProvenanceReuse` with a
    `crucible.campaign.fresh-lineage-baseline.v1` fresh-lineage baseline event
    and the loud `cross-provenance-corpus-reuse-refused` reason. The guard also
    makes `checks.crucible.phase7.gates.campaignContinuity` depend on this
    provenance check while leaving the full distributed campaign-continuity gate
    red until the DCE campaign store and continuity tests are implemented.
- [x] **T-PKG-23** Extend the `crucible-cas` ratchet-seam merge marker to name the
  fleet-visible store + dependency-gated invalidation as the SAME seam behind the
  unchanged narrow interface (merge bar = gate:content-address /
  gate:replay-oracle / gate:e2e-determinism), keeping Crucible standalone (no
  RFC-0007 dependency). — satisfies [PKG-45]; spec §26.9, §26.11.
  - Completed by `checks.crucible.phase7.crucibleCasFleetRatchetSeam`: the
    `crucible-cas` module docs and constants now name `SharedDagStore` and
    `InvalidationQuery::evaluate` as the same future ratchet seam behind
    `DagStore::put`/`DagStore::get`/`DagStore::has`. The check preserves the
    merge bar (`gate:content-address`, `gate:replay-oracle`,
    `gate:e2e-determinism`), forbids any RFC-0007/ratchet dependency, and makes
    `checks.crucible.phase7.gates.fleetEquivalence` depend on the same-seam proof.
    The later distributed work-stealing and persistent campaign store remain the
    DCE tasks in §35.
