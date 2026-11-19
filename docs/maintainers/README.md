# Maintain AOS

This section is for people who build AOS from source or manage its images,
releases, registries, hosted Hub, or forks. Installing and operating a
published AOS image should not require any of these workflows; start from the
[user documentation](../users/README.md) instead.

Pick the task you are here for. Each table lists every page for that task, and
the first row is the place to start.

## Build and develop

| Page | Use it to |
| --- | --- |
| [Development builds](../engineering/build/development-builds.md) | Set up the development shell, `aos-dev`, and the build caches |
| [Tutorial: build and boot AOS from source](source-build-quickstart.md) | Build a custom server image and boot it under the AOS-built QEMU and UEFI firmware |
| [Build concurrency and resource pressure](build-concurrency.md) | Investigate builds that fail under high parallelism |
| [Code style guide](../engineering/code-style.md) | Apply the Rust and Nix conventions to new and modified code |
| [Engineering documentation](../engineering/README.md) | Read how each component is implemented; update the relevant page in the change that alters a design |

The sections [Build the source tree](#build-the-source-tree),
[Use the repository CLI](#use-the-repository-cli), and
[Run checks](#run-checks) below give the everyday commands.

## Review and merge contributions

| Page | Use it to |
| --- | --- |
| [Contributor authorization](contributor-licensing.md) | Decide whether a contribution may be merged; the check fails closed |
| [Review package security](package-security.md) | Review build isolation, declared privileges, service confinement, and host effects |
| [Dependency advisory gate](dependency-advisories.md) | Refresh the advisory snapshot and record dispositions for `checks.advisories` |
| [Licensing](../legal/README.md) | Find the license that applies to a component and the Crucible/QEMU boundary rules |

## Maintain packages

| Page | Use it to |
| --- | --- |
| [Upgrade packages with `aos maintain`](package-upgrades.md) | Discover upstream releases, plan and run updates in isolated worktrees, and open the pull request |
| [Package maintenance audit, 2026-09-05](package-audit-2026-09-05.md) | Read the dated record of one full maintenance sweep; it is a snapshot, not current state |

Application packages have a separate
[authoring guide](../users/aos/package-authoring.md).

## Build images

| Page | Use it to |
| --- | --- |
| [Build and customize release images](system-images.md) | Define system variants, release policy, output formats, verified boot, and image validation |
| [Maintain the AOS trust model](trust-model.md) | Review any change to a signing authority, image-baked anchor, or trust boundary |

## Publish a release

| Page | Use it to |
| --- | --- |
| [Release checklist](release-checklist.md) | Start every release here: the order of operations, manual checks, and conditions for proceeding |
| [Canonical release coordinator](canonical-releases.md) | Look up `aos maintain release` commands, the maintainer configuration, and static surfaces |
| [Release qualification](qualification.md) | Look up destinations, profiles, fitness attestations, acceptance checks, and result formats |
| [`andyl/experimental` release retention policy](release-retention-policy.md) | Read the retention policy that release plans bind by digest; do not edit it in place |

## Operate registries and the hosted Hub

| Page | Use it to |
| --- | --- |
| [Hosted registry policy and runbooks](registries.md) | Understand the main/experimental split, surfaces, and trust-root epochs |
| [`andyl/experimental` registry runbook](registry-experimental.md) | Create, release, update, rotate, reset, audit, and retire the experimental registry |
| [`andyl/main` registry runbook](registry-main.md) | Read the intended production procedure; `andyl/main` is not yet open |
| [Registry key management](registry-key-management.md) | Plan signing custody, provider integration, rotation, and recovery |
| [Deploy the hosted AOS Hub](aos-hub-deployment.md) | Deploy one validated Worker build to staging and then production |
| [Hosted AOS Hub backup and recovery](aos-hub-backup-recovery.md) | Capture recovery points, restore, and run restore exercises |

Registry producers and release automation outside the hosted registries should
continue with the [registry operator documentation](../users/registry/).

## Qualify Crucible

| Page | Use it to |
| --- | --- |
| [Crucible gate evidence scope](crucible-gate-evidence.md) | Tell component tests apart from live QEMU evidence |
| [Crucible campaign performance baseline](crucible-campaign-performance-baseline.md) | Collect and pin the reference baseline for `gate:campaign-performance` |

## Glossary

The release pages use these terms throughout. Each is defined in full by the
page linked from its entry.

| Term | Meaning |
| --- | --- |
| Registry | One trust and lifecycle domain for packages and releases: `andyl/main` or `andyl/experimental`. See [registries](registries.md). |
| Registry tier | `production` (`andyl/main`) or `testing` (`andyl/experimental` and its epochs); the tier describes the key custody and pipeline behind a registry. |
| Channel | A mutable rollout pointer inside a registry: `edge`, `candidate`, or `stable`. |
| Surface | One publication endpoint with the role `staging` or `production`; an AOS Hub deployment or a static origin. |
| Destination | One surface role and one channel, written `<role>/<channel>`, such as `production/edge`. |
| Profile | The named set of checks a destination requires: `build`, `smoke`, `functional`, or `soak`. See [profiles](qualification.md#profiles). |
| Partition, ring | A channel has 256 partitions. A ring is a cumulative partition count that a rollout reaches before it is observed and widened. |
| Soak | The minimum observation window a profile requires before a rollout completes. |
| Assurance level (A0 to A3) | How much testing backs a compatibility claim, from unassessed (A0) to qualified (A3). See [assurance levels](qualification.md#assurance-levels). |
| Fitness attestation | A signed, dated record that a recovery exercise (backup restore, key rotation, and so on) succeeded. See [fitness attestations](qualification.md#fitness-attestations). |
| Plan | The frozen, reviewed description of one release; its digest is bound by every later step. |
| Bundle | The closed, signed set of release artifacts and its manifest. |
| Journal | The append-only, hash-chained record of a release's states. |
| Porcelain, step | `aos maintain release new`, `advance`, and their siblings are the porcelain; `aos maintain release step ...` exposes each underlying operation. |
| Predecessor | The verified signed bundle of the preceding release, used for update tests and change scoping. |
| Trust-root epoch | One generation of a registry's out-of-band root; a new epoch is a new registry identity such as `andyl/experimental-v2`. |
| TUF | The Update Framework: the root, targets, snapshot, and timestamp metadata that authorize a release. |
| UKI | Unified kernel image: the signed EFI executable that carries the kernel, initrd, command line, and root hash. |
| PITR | Point-in-time recovery of the Hub's database. |
| CIAA, CLA, DCO | Andyl's employee invention-assignment agreement, the external contributor license agreement, and the Developer Certificate of Origin sign-off. See [`CONTRIBUTING.md`](../../CONTRIBUTING.md). |

## Build the source tree

AOS builds hermetically from its bootstrap tools and AOS packages. It does not
import nixpkgs. The short image commands below require an `x86_64-linux`
caller. From another system, use an x86 Linux remote builder and select the
Linux package output explicitly.

Build the golden server image in the format needed by a release pipeline:

```sh
nix build .#server-image-raw
nix build .#server-image-qcow2
```

From a non-x86 host with an x86 Linux builder:

```sh
nix build .#packages.x86_64-linux.server-image-qcow2
```

Build an individual package through its `pkg-` output:

```sh
nix build .#pkg-zlib
```

The [source-build tutorial](source-build-quickstart.md) is a maintainer and
integration workflow, not the normal installation path.

## Use the repository CLI

Run the packaged repository command through the flake:

```sh
nix run . -- describe
nix run . -- show zlib
nix run . -- test eval
```

For incremental Rust work, build in the lean Cargo shell, which does not pull
in integration-test services or the packaged CLI, and run the binary directly:

```sh
nix develop --file cargo-shell.nix -c cargo build --manifest-path crates/Cargo.toml --bin aos
crates/target/debug/aos --help
```

The shell supplies the AOS-built dependencies and embeds the required OpenSSL
runtime path. Build and invoke the independent `aos`, `apm`, or `apr` program
for the surface under test. On-host service commands belong to the private
`aos-package-runtime` binary.

The `just` recipes use a release build instead: `nix develop -c just cli-build`
writes `crates/target/release/aos`. Set `AOS_BIN` to an equivalent binary when
the target directory lives elsewhere, for example on a constrained CI or agent
filesystem.

## Run checks

Start with the core evaluation and formatting checks, using the binary built
above:

```sh
crates/target/debug/aos test eval core
crates/target/debug/aos fmt --check
crates/target/debug/aos test eval
```

`aos test eval` runs the focused pure evaluation suites, including module-ABI,
runtime-role, registry-policy, storage-profile, and config-provenance checks.
It reports each suite's progress and uses at most two Nix evaluators. Use
`aos test eval <suite>` to run one suite while iterating. The `core` suite
builds `checks.eval` for a quick local pass. The CLI stops any individual eval
suite after two minutes and reports which suite exceeded the limit.

Checks that run an executable or inspect rendered artifacts are under
`checks.build`, including config evaluation, config materialization, the
Darling harness, rendered-system checks, and discovered system variants.
Flake checks include both groups.

VM and fleet checks require a Linux builder with KVM. Package, module, image,
and CLI changes should run the narrowest relevant build or test in addition to
the evaluation checks.

## Repository map

| Path | Contents |
| --- | --- |
| [`stdenv/`](../../stdenv/) and [`pkgs/`](../../pkgs/) | Bootstrap chain, toolchain, and package graph |
| [`lib/`](../../lib/), [`modules/`](../../modules/), and [`systems/`](../../systems/) | Module framework and image variants |
| [`crates/`](../../crates/) | AOS tools, registry services, and Crucible |
| [`tests/`](../../tests/) | Evaluation, build, VM, fleet, and integration coverage |

## Runtime ability infrastructure

The [runtime abilities guide](../users/aos/runtime-abilities.md) explains module
composition, generated package artifacts, and deferred execution. The
[engineering notes](../engineering/abilities/README.md) map the implementation,
its entry points, and its limits. Infrastructure checks alone do not qualify an
image or its handlers; see [qualification](qualification.md).
