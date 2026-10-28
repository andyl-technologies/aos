# Packaging

Everything Crucible needs to run is an AOS package built hermetically from
source: the Apache-licensed controller and CLI, the patched QEMU, the in-QEMU
plugin, the GPL debugger gateway, the fixture kernel, and the fixture root
images. This page describes how those packages are built and assembled into
the `crucible` suite, how the CLI finds a matched QEMU and plugin pair without
consulting the host, how the three boundary ABIs are versioned, and how a
release keeps the patched QEMU paired with its corresponding source.

Crucible follows the repository build rules in
[`AGENTS.md`](../../../AGENTS.md): no nixpkgs, no host tools, no
`/bin/sh` outside the bootstrap chain and guest rootfs init scripts, and no
removed features. The licensing policy these packages implement is in
[../../legal/licensing.md](../../legal/licensing.md); this page describes the
mechanics, not the policy.

## Package inventory

| Attribute | Expression | License | Role |
| --- | --- | --- | --- |
| `pkgs.qemu-crucible` | `pkgs/emulation/qemu.nix` via `mkQemuPackage` with `enablePlugins = true; applyCruciblePatch = true` | GPL-2.0-only (combined work) | Patched emulator; internal component, released only through the suite. |
| `pkgs.qemu-crucible-reference` | same, `applyCruciblePatch = false` | GPL-2.0-only | Unpatched build from the same source with plugins enabled; the reference for inertness checks. |
| `pkgs.qemu` | `pkgs/emulation/qemu.nix` defaults | GPL-2.0-only | Production QEMU, independent of Crucible; a system that wants QEMU never pulls the patched build. |
| `pkgs.crucible-qemu-plugin` | `pkgs/emulation/crucible-qemu-plugin.nix` | GPL-2.0-only | Rust `cdylib` loaded into QEMU. |
| `pkgs.qemu-crucible-source` | `pkgs/emulation/qemu-crucible-source.nix` | mixed | Complete corresponding source for the patched QEMU and the plugin. |
| `pkgs.crucible-controller` | `pkgs/tools/crucible/crucible.nix` with `controllerOnly = true` | Apache-2.0 | Controller, daemon, and `crucible` CLI with no QEMU-side code in its closure. |
| `pkgs.crucible` | `pkgs/tools/crucible/crucible.nix` | aggregate | The release suite: wrapper, controller, gateway, QEMU, plugin, source, kernel, fixtures. |
| `pkgs.linux-crucible` | `pkgs/kernel/linux-crucible.nix` | GPL-2.0-only | Stock fixture guest kernel. |
| `pkgs.crucible-fixtures` | `pkgs/tools/crucible-fixtures.nix` | MIT (images contain GPL userland) | Fixture root images, entropy seed, and QEMU launch fragment. |
| `pkgs.crucible-guest` | `pkgs/tools/crucible-guest.nix` | Apache-2.0 | Static in-guest marker and typed-selectable client used by fixtures. |
| `pkgs.crucible-fleet-store` | `pkgs/tools/crucible-fleet-store.nix` | MIT | `crucible-fleet-store` binary from `crucible-store`, the fleet-visible `SharedDagStore` backend. |
| `pkgs.crucible-qemu-trace-plugin` | `pkgs/emulation/crucible-qemu-trace-plugin.nix` | GPL-2.0-only | C instruction-trace plugin used by trace-fingerprint checks. |
| `pkgs.aos-ability-crucible` | `pkgs/tools/aos-ability-crucible.nix` | Apache-2.0 | Optional AOS ability adapter for generic Crucible guest markers. |

The debugger gateway (`crucible-debug-gateway`, GPL-2.0-only) is built inside
`crucible.nix` and exposed as `passthru.debugGateway` of the suite.

```text
  crucible (suite, aggregate-release-root)
   +-- bin/crucible            wrapper -> crucible-controller/bin/crucible
   +-- crucible-controller     Apache host; disallowed from referencing QEMU side
   +-- crucible-debug-gateway  GPL RSP mediation process
   +-- qemu-crucible           internal-component, needs its source pair
   +-- crucible-qemu-plugin    built against qemu-crucible headers
   +-- qemu-crucible-source    identity-matched corresponding source
   +-- linux-crucible, crucible-fixtures, gdb, openssh
```

## One workspace, one lockfile

Every Cargo consumer (controller, debugger gateway, plugin, guest, fleet store,
and the test checks) builds from the same inputs:

- `pkgs/tools/crucible/_source.nix` filters the repository into
  `crucible-workspace-src`. It keeps `crates/`, `docs/`, `tests/crucible/`, the
  Crucible package expressions, and the few root files harness lints read,
  and drops `.git`, `target`, `.crucible`, `result`, and daemon run state.
- `pkgs/tools/crucible/_packages.nix` lists the closed set of workspace
  packages, and `_workspace.nix` turns it into Cargo workspace members through
  `pkgs/tools/aos/_workspace-slice.nix`.
- Third-party crates come from the monorepo `Cargo.lock` through the shared
  `aosWorkspaceVendor` (`fetchCargoVendor`). Crucible keeps no second
  dependency pin; `_cargo-deps-hash.nix` exposes the vendor hash for manifests.

Each package selects its members with `-p` flags. The controller excludes the
GPL-side `crucible-qemu-plugin` and `crucible-qemu-debug-gateway`; the plugin
and gateway build only themselves. Each Cargo artifact family carries a
`cargoArtifactContract` naming its license scope (`Apache-2.0` or
`GPL-2.0-only`), so prebuilt dependency artifacts are never shared across the
process boundary.

Crucible ships without any dependency on the sibling `ratchet` evaluator
engine. The content-addressed store and dependency-gated invalidation it needs
live in the Crucible-owned `crucible-store` crate. Its module docs name the
narrow seam a future shared substrate would implement (`DagStore::put`,
`DagStore::get`, `DagStore::has`, and `InvalidationQuery::evaluate`, with
`SharedDagStore` as the fleet-visible backend of the same seam). Such a
replacement must pass `gate:content-address`, `gate:replay-oracle`, and
`gate:e2e-determinism` unchanged.

## The patched QEMU

`qemu-crucible` builds the same pinned upstream tarball as production QEMU
(currently 11.1.1, from `pkgs/emulation/qemu-patches/_atomic-patch.nix`) and
applies the single atomic patch with `patch --batch --forward --fuzz=0`. The
build refuses to evaluate if the patch or its Git bundle drifts from the
recorded SHA-256. The system target list is
`--target-list=x86_64-softmmu,aarch64-softmmu`. The patch itself, its
capabilities, and its regeneration pipeline are described in
[qemu-patch.md](qemu-patch.md).

The build installs the generated shared-memory header
`crates/crucible/crucible-qemu-shmem/include/crucible_shmem_abi.h` as
`include/aos/crucible/crucible_shmem_abi.h`, so the C side and the Rust side
compile against one source of truth.

### Build identity and the sim-capability marker

Every `qemu.nix` variant writes `share/aos/crucible/qemu-build-identity.env`.
Its fields are:

```text
qemu_package=qemu-crucible
qemu_version=11.1.1
qemu_source_hash=sha256-...
qemu_nix_hash=<sha256 of qemu.nix>
qemu_configure_flags_hash=...
qemu_configure_target_list=x86_64-softmmu,aarch64-softmmu
qemu_atomic_patch_hash=...
qemu_patch_branch_ref=...            qemu_patch_branch_model=...
qemu_patch_branch_bundle_hash=...    qemu_patch_branch_material_hash=...
qemu_patch_branch_base_commit=...    qemu_patch_branch_base_tree=...
qemu_patch_branch_head_commit=...
qemu_plugins_enabled=true
qemu_crucible_atomic_patch_applied=true
qemu_sim_capability=qemu-crucible    (none for unpatched variants)
qemu_shmem_abi_version=<N>
qemu_shmem_abi=crucible-shmem-abi-v<N>
qemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h
qemu_shmem_header_hash=...
qemu_combined_work_license=GPL-2.0-only
...
qemu_build_id=<sha256 of the identity material above>
```

`qemu_build_id` is the SHA-256 of the identity material, so any change to the
source, the patch, `qemu.nix`, the configure flags, or the shared-memory header
yields a new identity. The same value is compiled into the binary as
`QEMU_CRUCIBLE_BUILD_ID`, together with `QEMU_CRUCIBLE_ATOMIC_PATCH_HASH` and
`QEMU_CRUCIBLE_SHMEM_HEADER_HASH` (passed through `--extra-cflags`). The file
doubles as the sim-capability marker
that discovery reads.

The patched output also installs per-component license files and an
`AOS-MODIFICATIONS` note under `share/licenses/qemu-crucible/`, plus a
`nix-support/aos-release-policy` file marking it an internal component (see
[Release policy](#release-policy)).

## The plugin

`crucible-qemu-plugin.nix` builds `-p crucible-qemu-plugin` with
`mkCargoPackage` against the `qemu-crucible` output. Before compiling, it:

- exports `CRUCIBLE_QEMU_BUILD_ID`, `CRUCIBLE_QEMU_ATOMIC_PATCH_HASH`, and
  `CRUCIBLE_SHMEM_HEADER_HASH` from `qemu-crucible.passthru`;
- checks that the installed `qemu-plugin.h` exports the Crucible plugin APIs
  (`qemu_plugin_read_vcpu_regs`, `qemu_plugin_rr_cursor`,
  `qemu_plugin_inject_preemption`);
- compiles a C probe that fails unless `QEMU_PLUGIN_VERSION` equals the Rust
  plugin's `QEMU_PLUGIN_API_VERSION` and `CRUCIBLE_SHMEM_ABI_VERSION` equals
  the Rust `crucible-qemu-shmem` `ABI_VERSION`.

It installs `lib/libcrucible_qemu_plugin.so` with a
`lib/qemu/plugins/crucible-qemu-plugin.so` symlink and writes
`nix-support/crucible-qemu-plugin-build-info`:

```text
package=crucible-qemu-plugin
qemu_build_id=<qemu-crucible qemu_build_id>
qemu_sim_capability_marker=<qemu-crucible>/share/aos/crucible/qemu-build-identity.env
qemu_plugin_api_version=<N>          qemu_plugin_abi=qemu-plugin-api-v<N>
shmem_abi_version=<N>                shmem_abi=crucible-shmem-abi-v<N>
shmem_generated_header_hash=...
plugin_abi=crucible-shmem-abi-v<N>
component=qemu-in-process-adapter
component_license=GPL-2.0-only
```

The plugin is GPL-side code loaded into QEMU. It may use the dual-licensed
boundary crates `crucible-qemu-protocol` and `crucible-qemu-shmem` (under
their MIT option) but no Apache-only host crate.

## The controller

`crucible-controller` builds the Apache workspace members and runs its checks
inside the package build:

- `cargo nextest` over the controller members with the
  `crucible-cli/test-double` feature (bounded to 16 test threads, with a 4,096
  open-file soft limit for the test-binary inventory);
- `cargo test -p crucible-test-support --test gate_license_boundary`;
- `cargo clippy --all-targets ... -D warnings`;
- `cargo doc` with `RUSTDOCFLAGS="-D warnings -D missing_docs"`, and hermetic
  doctests.

Cross builds compile every target and defer execution to the native build.
After the checks, `preInstall` rebuilds the installed `crucible` binary
*without* test features, and `postInstall` fails if `--help` still offers
the `double` backend or `selftest --with-qemu`. The package also installs the
`crucible-debugger-live-fixture` and `crucible-e2e-determinism-scenario`
example binaries.

The process boundary is enforced on the closure: `disallowedReferences` and
`disallowedRequisites` list `qemu-crucible`, `crucible-qemu-plugin`,
`linux-crucible`, `crucible-fixtures`, and the debugger gateway, so the build
fails if any of them enters the controller's runtime closure. Consequently the
controller binary has no baked-in QEMU path; its build info records
`qemu_package=none` and `discovery_hint=flags-or-runtime-environment`.

## The suite and hermetic discovery

The `crucible` suite installs `bin/crucible` as a Bash wrapper (AOS Bash, not
`/bin/sh`) that supplies defaults and then execs the controller:

| Variable | Default |
| --- | --- |
| `CRUCIBLE_QEMU` | `qemu-crucible/bin/qemu-system-x86_64` or `-aarch64`, matching the host |
| `CRUCIBLE_PLUGIN` | `crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so` |
| `CRUCIBLE_DEBUG_GATEWAY` | `crucible-debug-gateway/bin/crucible-debug-gateway` |
| `CRUCIBLE_NATIVE_GUEST_ARCHITECTURE` | `x86_64` or `aarch64` |
| `CRUCIBLE_KERNEL` | `linux-crucible/boot/vmlinuz-<version>` |
| `CRUCIBLE_ROOT_IMAGE` | `crucible-fixtures/share/crucible/fixtures/root/aos-minimal-root.ext4` |
| `CRUCIBLE_KERNEL_CMDLINE` | the kernel's fixture command line plus `init=/init` |

Architecture-suffixed variants (`CRUCIBLE_KERNEL_X86_64` and so on) default to
the same values. Each default uses `: "${VAR:=...}"`, so a caller's value wins.
The suite also links `gdb`, `gdbserver`, and `ssh`, and installs
`crucible-debugger-live-matrix`.

The CLI resolves QEMU and the plugin in
`crates/crucible/crucible-cli/src/cli/backend.rs`
(`discover_qemu_artifacts`). For each artifact independently, the first
present source wins:

1. the `--qemu` / `--plugin` flag;
2. the non-blank `CRUCIBLE_QEMU` / `CRUCIBLE_PLUGIN` environment variable;
3. the compile-time AOS package-set hint `CRUCIBLE_AOS_QEMU` /
   `CRUCIBLE_AOS_PLUGIN` (`option_env!`, unset in the packaged controller).

The host `$PATH` is never consulted. `validate_qemu_artifacts` then fails
closed, with a message that restates the discovery order, unless:

- both paths are readable files; QEMU is an ELF64 executable; the plugin is an
  ELF64 shared object exporting `qemu_plugin_install` and
  `qemu_plugin_version`;
- QEMU's `qemu-build-identity.env` (found at `../share/aos/crucible/` from
  `bin/`, or beside the binary) has `qemu_sim_capability=qemu-crucible`,
  `qemu_crucible_atomic_patch_applied=true`, `qemu_plugins_enabled=true`, and
  non-empty identity and ABI fields with a consistent
  `crucible-shmem-abi-v<N>` label;
- the plugin's `crucible-qemu-plugin-build-info` (at `../nix-support/` from
  `lib/`, or beside the library) has a `plugin_abi` equal to the ABI this CLI
  was compiled for;
- the plugin's `qemu_build_id` equals QEMU's, and both sides agree on the
  shared-memory ABI label, version, and generated-header hash.

`crates/crucible/crucible-qemu-host/src/artifact_identity.rs` repeats this
authentication for packaged launches as an opaque
`QemuLaunchArtifactIdentity` receipt, so a lifecycle cannot be relabeled with
a different pair.

## ABI versions

Crucible has independently versioned boundary ABIs, because each binds a
different pair of components. Packaging reads each version from its Rust
source of truth at evaluation time, so the packages cannot disagree with the
code.

| ABI | Source of truth | Label | Binds |
| --- | --- | --- | --- |
| Shared memory | `ABI_VERSION` in `crates/crucible/crucible-qemu-shmem/src/lib.rs`, plus the generated header hash | `crucible-shmem-abi-v<N>` | QEMU, plugin, and host executor |
| Guest-host channel | `crates/crucible/crucible-qemu-protocol/src/control_protocol_version.in` (read by `_control-protocol-version.nix`, which requires one positive decimal `u32`) | `crucible-guest-host-channel-v<N>` | Plugin and optional in-guest client |
| Doorbell instruction | `WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION` in `crates/crucible/crucible-qemu-protocol/src/doorbell_abi.rs` | numeric | Guest doorbell encoding on x86_64 and aarch64 |
| Control-plane RPC | `RPC_PROTOCOL_MAJOR`/`MINOR`/`PATCH` and `RPC_PROTOCOL_BUILD` in `crates/crucible/crucible-control-api/src/rpc_abi.rs` | `crucible-rpc-abi-v<M.m.p>+<build>` | CLI, clients, and daemon |
| QEMU plugin API | `QEMU_PLUGIN_API_VERSION` in `crates/crucible/crucible-qemu-plugin/src/abi.rs` | `qemu-plugin-api-v<N>` | Plugin and patched `qemu-plugin.h` |

The controller and suite build info, the plugin build info, and the release
manifest all stamp these values. A mismatch fails at discovery or at protocol
handshake rather than degrading. An intentional ABI change bumps the version
and regenerates the conformance golden vectors in the same change (see
[shmem-abi.md](shmem-abi.md) and [control-protocol.md](control-protocol.md)).

## Fixture kernel and root images

These are fixtures for Crucible's own checks. A user guest needs none of them:
determinism is enforced at the QEMU/host boundary, and `gate:any-guest`
exercises an unmodified third-party guest (see [determinism.md](determinism.md)).

### `linux-crucible`

`pkgs/kernel/linux-crucible.nix` builds a stock kernel through
`linuxFixtureWith` with an `extraConfig` fragment that adds only what the
fixtures need: the serial console (8250 on x86_64, PL011 on aarch64), virtio
PCI/blk/net/console, virtio-iommu with ACPI VIOT, 9p over virtio, and ext4.
`CONFIG_MODULES` and `CONFIG_KMOD` are off, so the kernel is built-in only
and `request_module` can do nothing. There is no determinism shaping; the
kernel's `passthru.crucibleDeterminismMechanism` is
`host-side-qemu-icount-seeded-entropy`, and no `nokaslr` or entropy
suppression is required. The fixture command line is
`console=<ttyS0|ttyAMA0> reboot=k panic=1 root=/dev/vda ro net.ifnames=0`.
The package's probe rejects a kernel whose required features are not built in
or whose output contains a module.

### `crucible-fixtures`

`pkgs/tools/crucible-fixtures.nix` produces two ext4 root images with
`fakeroot mkfs.ext4 -d` (no `losetup` or `mount`) using
`-O ^has_journal,^metadata_csum,^64bit`. Journal replay can panic a minimal
guest, and the other two flags keep the image within the feature set the
fixture kernel mounts cleanly. Images are made read-only (`0444`).

| Output path | Content |
| --- | --- |
| `share/crucible/fixtures/root/aos-minimal-root.ext4` | Fixture guest: AOS bash, coreutils, util-linux, `crucible-guest`, openssh. `/bin/sh` links to AOS bash; `/init` mounts the host store over 9p. |
| `share/crucible/fixtures/third-party-guests/generic-aos-linux-unmodified/root.ext4` | A guest without the Crucible guest client, used to show black-box operation. |
| `share/crucible/fixtures/entropy/crucible-guest-entropy-seed.bin` | A fixed 32-byte seed, checked for size at build time. |
| `share/crucible/fixtures/qemu/launch-fragment.txt` | Reference QEMU arguments: kernel, a qcow2 copy-on-write overlay over the read-only base, the host `/nix/store` shared read-only over virtio-9p with mount tag `crucible-store`, and `-fw_cfg name=opt/crucible/seed`. |
| `share/crucible/fixtures/qemu/prepare-cow-overlay` | Creates the qcow2 overlay and refuses a writable base image. |
| `share/crucible/fixtures/manifest.toml` | Image paths, SHA-256s, sizes, feature flags, entropy mechanism, and per-node identity. |

Each image's node id is `sha256:<image hash>`, and its guest MAC is derived
from that hash (`02:` followed by the first five hash bytes). Assigning MACs
in spawn order would make ARP tables and MAC-ordered guest behavior depend on
host scheduling; deriving them from content keeps them stable across runs.
The recorded entropy mechanism is `scenario-seed-fw_cfg-plus-seeded-qemu-rng`:
the guest's entropy comes from the scenario-derived `fw_cfg` seed and QEMU's
seeded RNG device (see [determinism.md](determinism.md)).

## Release manifest

`pkgs/tools/crucible/_release-manifest.nix` builds the suite's
`share/aos/crucible/release-manifest.env` and `release-manifest.json`
(`schemaVersion = 1`). Evaluation fails if any workspace package's
`Cargo.toml` version differs from the suite version. The manifest records
three independent version axes plus provenance:

| Section | Contents |
| --- | --- |
| `crucible` | Version, workspace package list and versions, Cargo vendor hash, source store name and hash. |
| `qemu` | Upstream version, URL, and hash; patch branch ref; atomic patch, bundle, and branch-material hashes; `buildId`; fixed base and patch dates. |
| `components` | Store path, license, and process-boundary role of the controller, QEMU, plugin, gateway, gdb, ssh, boundary crates, and corresponding source. |
| `abi` | Shared-memory version, label, and header hash; guest-host channel; doorbell; RPC. |
| `licensing` | Aggregate license set and `process_boundary=unix-socket-control+memfd-shared-memory-data`. |
| `publication` | `rootPackage = "crucible"`, `rawQemuAllowed = false`, `policy = "aggregate-direct-reference-pair"`. |
| `reproducibility` | `no-wall-clock-timestamps`, `no-host-paths`, the list of pinned hashes, and the QEMU build-identity fields. |

The suite's `nix-support/crucible-build-info` repeats the component paths,
licenses, and ABI versions in flat `key=value` form.

A reproduction artifact pins the same provenance in
`PinnedBuildIdentity` (`crates/crucible/crucible-test-support/src/reproduction.rs`):
engine version and ABI, artifact ABI, the content-addressed `qemu_build_id`,
the atomic patch hash, and the shared-memory, guest-host, RPC, and plugin ABI
versions. A run therefore reproduces only against the exact build that
produced it. Campaigns key their corpora on this provenance, record a
fresh-lineage baseline event, and refuse cross-provenance reuse; see the
campaign pages for details.

## Corresponding source

`qemu-crucible-source` is the complete corresponding source for the patched
QEMU and the in-process plugin. Its `share/aos/qemu-crucible-source/` tree
contains:

- `upstream/qemu-<version>.tar.xz`, the exact pinned tarball;
- `patches/`: the atomic patch, `_atomic-patch.nix`, and the deterministic Git
  bundle;
- `interfaces/crucible_shmem_abi.h`, the generated boundary header;
- `build/aos/`: a filtered AOS tree in its original layout, including
  `default.nix`, `stdenv/`, `lib/`, and `pkgs/emulation/qemu.nix`, enough to
  re-evaluate `qemu-crucible`;
- `plugin/workspace/` and `plugin/cargo-vendor/`: the filtered Crucible
  workspace and the fixed-output vendor tree for an offline plugin rebuild;
- `licenses/`: QEMU's `COPYING` and `LICENSE`, the repository license texts,
  and the patch file inventory;
- `SOURCE-MANIFEST.env` and a `README` with reconstruction steps.

The build asserts that each of these is present and non-empty, disables
stripping and reference rewriting so the sources stay byte-identical to their
inputs, and writes `nix-support/qemu-crucible-source-build-info` with the same
`qemu_build_id`.

## Release policy

Packages declare publication rules in `nix-support/aos-release-policy`
(`policy_version=1`):

| Output | Policy |
| --- | --- |
| `qemu-crucible` | `artifact_role=internal-component`, `standalone_release=false`, `release_via=crucible`, `corresponding_source_required=true`, `corresponding_source_identity=<qemu_build_id>`, `publishable=via-aggregate-only` |
| `crucible` | `artifact_role=aggregate-release-root`, `standalone_release=true`, `pair_count=1`, `pair_1_component_path`, `pair_1_corresponding_source_path`, `pair_1_identity` |
| Upstream test-suite evidence | `artifact_role=test-evidence`, `publishable=false` |

The registry enforces these rules when publishing a store path, in
`validate_store_path_release_policy` in
`crates/registry/aos-registry-authoring/src/registry_ops/store_paths.rs`. It
reads the policy of every member of the root's full runtime closure, so a
wrapper or plugin root that merely depends on `qemu-crucible` cannot bypass
the rule. If any member is an internal component, publication fails unless:

- the root is an `aggregate-release-root` with `standalone_release=true`;
- `pair_count` equals the number of restricted members, with no member paired
  twice;
- each pair names a restricted member and its exact identity;
- the root directly references both the component and its source path;
- the source's `qemu-crucible-source-build-info` contains
  `qemu_build_id=<identity>`.

A malformed policy file, a duplicate key, or an unsupported `policy_version`
also fails. Generic unpatched QEMU carries no restriction. The policy itself
is in [../../legal/licensing.md](../../legal/licensing.md#distribution-and-corresponding-source).

## Checks

Crucible's QEMU-backed and fleet checks run under TCG and do not set
`requiredSystemFeatures = [ "kvm" ]`, so they run on builders without nested
virtualization. `qemu-crucible` carries package checks
`checks.integration.qemu-crucible-patch-microtests` and
`checks.integration.qemu-crucible-qemu-inert` (the latter comparing against
`qemu-crucible-reference`). Packaging conformance lives in `phase7`:

| Check | Verifies |
| --- | --- |
| `checks.crucible.phase7.cruciblePackageInventory` | Each Crucible package expression (QEMU, plugin, kernel, suite, fixtures, guest, fleet store) uses the AOS builders, classifies its dependencies, imports no nixpkgs, and shares the vendored Cargo dependencies; the set includes `pkgs.qemu-crucible` and `pkgs.crucible-fixtures`. |
| `checks.crucible.phase7.crucibleQemuPackage` | Patched QEMU build, patch application, identity marker. |
| `checks.crucible.phase7.crucibleQemuPluginPackage` | Plugin build against the matching headers and its build info. |
| `checks.crucible.phase7.crucibleWorkspacePackage` | The controller's workspace-scoped Cargo test suite and build info. |
| `checks.crucible.phase7.crucibleLinuxKernel` | The fixture kernel contract. |
| `checks.crucible.phase7.crucibleFixtures` | Image flags, read-only base, seed, MAC derivation, manifest. |
| `checks.crucible.phase7.crucibleReleaseManifest` | Manifest fields and pinned hashes. |
| `checks.crucible.phase7.reproductionProvenanceTriple` | Reproduction artifacts carry the Crucible version, QEMU build identity plus atomic-patch hash, and the ABI versions. |
| `checks.crucible.phase7.cruciblePackagingConformance` | Only the single atomic patch ships; diagnostic-only capabilities are absent. |
| `checks.crucible.phase7.crucibleGateCiWiring` | Eval-class, package-class, and fleet gate wiring and ordering. |
| `checks.crucible.phase7.crucibleFleetStore` | The `pkgs.crucible-fleet-store` component and its fleet check, `checks.fleet.crucible-distributed-continuous-exploration`. |
| `checks.crucible.phase1.aosWorkspaceBuild` | The package set exposes `crucible`, `crucible-controller`, `crucible-qemu-plugin`, `qemu-crucible`, and `qemu-crucible-source`, and their built outputs pass a smoke test of build info, markers, and wrapper defaults. |
| `checks.crucible.phase5.cliHermeticDiscovery` | The discovery order and fail-closed pair validation. |
| `checks.crucible.phase2.abiConformance`, `checks.crucible.phase2.gates.abiConformance` | Golden vectors and versioned ABI conformance. |

`checks.crucible.phase1.qemuDiagnosticPatchesDevOnly` confirms that no
diagnostic QEMU patch ships and that no developer-only QEMU variant exists.
Gate ordering and the remaining gates are described in
[testing-and-gates.md](testing-and-gates.md).
