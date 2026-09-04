# Platform and image publication matrix

## Canonical targets

The Hub and registry use exact Nix system strings as platform identities. The
canonical public matrix is:

| Target | Packages | System images | Required runtime qualification |
| --- | --- | --- | --- |
| `x86_64-linux` | Every eligible package | Raw, QCOW2, VMDK, and dynamic VHD for every public system variant | Native package tests and x86_64 UEFI/KVM image tests |
| `aarch64-linux` | Every eligible package | Raw, QCOW2, VMDK, and dynamic VHD for every public system variant | AArch64 target tests and AArch64 UEFI image tests using declared AOS-built emulation until native hardware is available |
| `x86_64-darwin` | Every Darwin-eligible package | None | Static Mach-O checks, the Darling compatibility gate where applicable, and release qualification on supported Intel macOS |
| `aarch64-darwin` | Every Darwin-eligible package | None | Static Mach-O checks and release qualification on supported Apple Silicon macOS |

Aliases such as `amd64`, `arm64`, `linux`, `macos`, and `darwin` are accepted
only as user-interface search terms. They never appear as signed platform keys.

Darwin receives packages, package documentation, NARs, provenance, SBOM and
license records, and corresponding redistributable source. It does not receive
an AOS system toplevel, disk image, UKI, recovery bundle, Secure Boot catalog
entry, dm-verity root, or A/B update metadata. A registry parser rejects those
Linux image fields beneath a Darwin platform entry.

## What “full matrix” means

The required matrix is the Cartesian product of release targets and package
eligibility, not every discovered derivation on every operating system.

The release planner derives eligibility from a versioned, fail-closed inventory:

- portable packages are required on all four targets;
- Linux-only packages are required on both Linux architectures and are
  explicitly not applicable to Darwin;
- Darwin-only runtime support packages are required on both Darwin
  architectures;
- target-independent data may reuse one content-addressed object, but each
  signed platform entry still names and authenticates that object;
- build-only bootstrap and test roots are retained as build inputs but are not
  advertised as installable target packages; and
- a narrowly documented architecture exception may mark one architecture not
  applicable only when upstream or bootstrap constraints make that true.

[`pkgs/_platform-support.nix`](../../../pkgs/_platform-support.nix) is the
current Darwin-oriented inventory. It must become the authoritative four-target
publication inventory before the first stable release. Adding, deleting, or
renaming a discovered package without classifying every target is an evaluation
failure.

Every planned package-target cell has exactly one state:

```text
artifact       required and present with signed metadata
not-applicable excluded by a versioned eligibility rule
blocked        required but unavailable; permitted only on edge or RC releases
```

There is no implicit “missing” state. A release manifest with a missing,
duplicated, unknown, or unclassified cell is invalid.

## Release completeness

`edge` may publish an explicitly incomplete matrix so porting failures become
visible. An RC on `candidate` may carry `blocked` cells when its purpose is to
qualify the remaining work, but its Hub and CLI presentation must say that the
release is incomplete for those targets.

A final, no-suffix stable-eligible candidate has no `blocked` cells. Every
required package-target pair and every required Linux image has passed its
target gate before any production `candidate` partition moves to that release.
Stable promotion is therefore atomic across the complete matrix:

- it does not publish `x86_64-linux` first and add AArch64 later;
- it does not advance separate per-platform stable channels;
- it does not reuse a previous-platform artifact under a new package version;
  and
- it does not label a cross-compiled Darwin binary supported before its native
  macOS gate passes.

If one required platform fails, the stable release is blocked. The correction
uses a new RC or higher final patch version. Architecture-specific emergency
fixes still construct and verify the complete release matrix so the unaffected
platform entries remain explicit and byte-identical.

## Package version rules

A package version that changes in a stable-eligible release advances together
on every platform where that package is required. Platform-specific patch
content may differ, but the public package version and source identity agree.
If upstream genuinely ships different platform versions, the inventory records
separate package names or an explicit exception rather than silently skewing
one signed version.

Unchanged package-platform entries may be reused by digest from the preceding
release. Reuse avoids rebuilding the world solely to create a catalog snapshot,
but the release verifier still proves that every referenced NAR, realization
edge, document, source, SBOM component, and license record is present in the
declared production placement.

The Hub indexes availability by exact `(release, package, version, platform)`.
APM selects the consumer platform before version resolution and never falls
back to an artifact for another platform.

## Linux build and qualification

The designated maintainer host coordinates the matrix and is the native
`x86_64-linux` builder for this phase. Both Linux target sets remain hermetic:

1. `x86_64-linux` packages and images build with the native AOS toolchain.
2. `aarch64-linux` uses a distinct cross package set with Linux-native build
   tools and AArch64 target libraries and outputs.
3. Configure probes or tests that must execute target code use an explicitly
   declared AOS-built emulator or an AArch64 VM, never ambient host `binfmt`
   configuration or a host QEMU.
4. Package tests run in an AArch64 AOS guest where static inspection is
   insufficient.
5. Image qualification boots the exact downloaded AArch64 disk with AArch64
   UEFI firmware and verifies the same security and recovery contract as x86.

An emulated AArch64 test is functional evidence, not performance qualification
or independent reproducibility. Native AArch64 hardware becomes an additional
stable gate for hardware-specific drivers, firmware, performance, or errata as
soon as AOS advertises those contracts.

## Darwin build and qualification

Darwin packages are cross-built hermetically on the maintainer host using the
repository's source SDK, cctools/ld64 path, target runtimes, and Linux-native
build tools. The build graph must keep target Mach-O binaries out of the Linux
builder's executable search path.

Each Darwin artifact passes:

- Mach-O architecture, load-command, minimum-OS, install-name, rpath, symbol,
  dependency, and forbidden-Linux-closure inspection;
- package metadata, NAR, realization graph, documentation, provenance, SBOM,
  source, and license verification identical to Linux packages;
- x86_64 Darling smoke tests where the package is inside that compatibility
  contract; and
- native execution of public executables and focused library/runtime tests on
  the corresponding supported macOS architecture.

Darling is not macOS qualification, and it does not cover AArch64. Until the
release process can collect signed results from real Intel and Apple Silicon
macOS test machines, Darwin package cells remain `blocked` for stable. Those
machines are test executors, not publishers: they receive content-addressed
candidate NARs, return signed results, and never hold registry, channel, Hub,
TUF, cache, or Secure Boot signing credentials.

## Linux image matrix

Every public system variant produces one logical finalized disk per Linux
architecture. Each logical disk produces these delivery encodings:

| Artifact | `x86_64-linux` | `aarch64-linux` | Darwin |
| --- | --- | --- | --- |
| Compressed raw GPT disk and `image-info.json` | Required | Required | Not applicable |
| QCOW2 | Required | Required | Not applicable |
| VMDK | Required | Required | Not applicable |
| Dynamic VHD | Required | Required | Not applicable |
| Normal A/B UKIs | Required | Required | Not applicable |
| Recovery A/B UKIs and recovery bundle | Required | Required | Not applicable |

The x86_64 and AArch64 logical disks are different artifacts and have different
hashes, PE machine types, kernels, module closures, PCR measurements, and image
metadata. Within one architecture, all four delivery formats are derived from
the same finalized logical disk and must round-trip to it.

Signing requests bind the exact platform, PE machine type, system variant,
release, unsigned digest, key role, and SBAT generation. A valid signature for
an x86_64 UKI cannot satisfy an AArch64 manifest cell or vice versa. Firmware
PK/KEK/db certificates may be shared only when the declared hardware trust
domain and qualified firmware policy permit it; key policy remains
architecture-aware even when the certificate bytes are identical.

Each advertised format passes a platform-specific boot or import canary. A
format unsupported by its claimed hypervisor is `blocked`, not published as an
untested download. Stable cannot advertise a reduced encoding matrix unless a
new versioned policy explicitly removes that format from the supported target.

## Upload and rollout behavior

One candidate bundle contains the complete package matrix and, when
image-bearing, both Linux architecture image sets. Upload ordering is:

1. shared source, documentation, SBOM, and license objects;
2. all four package/NAR platform closures;
3. both Linux logical disks, recovery artifacts, and delivery encodings;
4. immutable registry, TUF, and release evidence; and
5. mutable discovery and channel pointers only after completeness verification.

Deduplicated objects upload once, but the manifest retains every logical
platform relationship. Staging qualification and production import operate on
the whole bundle. There is no platform-by-platform production promotion.

Channels remain registry-wide. A consumer first resolves its signed channel
release, then selects its exact platform entries. The 256 rollout partitions
control release exposure and are not multiplied into separate architecture or
operating-system partition maps.

## Current implementation gap

The repository's [`flake.nix`](../../../flake.nix) currently exposes
`x86_64-linux` and `aarch64-linux` as flake systems, while the
[system-image guide](../../maintainers/system-images.md) documents only an
`x86_64-linux` image target. Darwin cross-package composition and checks exist,
but the [Darwin package-matrix plan](../../plans/darwin-package-matrix.md) states
that the inventory is an intended result and that real macOS qualification is
still required.

Consequently, no release may be called full-matrix or stable until:

- the flake or release planner exposes deterministic package publication roots
  for all four targets;
- AArch64 Linux packages and images build and pass target execution gates;
- both Darwin package sets complete their declared dependency waves;
- real x86_64 and AArch64 macOS qualification receipts are integrated;
- the release manifest enforces the closed eligibility matrix; and
- Hub, registry, APM, documentation, SBOM, and retention paths are tested with
  all four exact platform identities.
