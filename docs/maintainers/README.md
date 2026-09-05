# Maintain AOS

Release operators use the shared [qualification contract](qualification.md), [release checklist](release-checklist.md), and [qualification exercises](qualification-exercises.md) for testing and production.

This section is for people changing the AOS source tree, package graph, system
modules, release images, or Rust tools. Installing and operating a published
AOS image should not require any of these workflows.

Before reviewing or merging a contribution, follow the
[contributor-authorization policy](contributor-licensing.md). It distinguishes
Andyl employee contributions covered by the company CIAA from external
contributions that require the project agreement, and defines the fail-closed
records and identity checks maintainers must preserve.

Apply the [code style guide](../code-style.md) to new and modified Rust and Nix
code. It covers Rust APIs and implementation, Dendritic Nix modules, package
expressions, comments, tests, and embedded shell.

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

The source-build [server tutorial](source-build-quickstart.md) exercises a
custom image, first-boot metadata, AOS-built QEMU, and UEFI firmware. It is a
maintainer and integration workflow, not the normal installation path.

[Build and customize release images](system-images.md) covers system variants,
release policy, output formats, and image validation.

[Deploy the hosted AOS Hub](aos-hub-deployment.md) covers manual deployment with
the packaged Wrangler and Cloudflare OAuth, isolated staging and production
configuration, validation, promotion, and rollback.

[Operate hosted registries](registries.md) defines the main/testing trust and
lifecycle split and links the per-registry runbooks. [Back up and recover the
hosted Hub](aos-hub-backup-recovery.md) covers HubDb PITR, R2, disposable shard
state, release evidence, restore, and approved testing rebuilds.

[Plan and verify canonical releases](canonical-releases.md) documents the
fail-closed four-platform release plan, source and authorization preconditions,
and offline bundle verification. It also identifies which RFC-0017 publication
phases are not yet authorized for production use.

[Maintain the AOS trust model](trust-model.md) defines the chain from source and
release authorization through verified boot, image-baked anchors, signed
registries, store realizations, and runtime measurements.

[Review package security](package-security.md) defines the maintainer's role in
package build isolation, declared privileges, generated service confinement,
host effects, and security regression testing.

## Use the repository CLI

Run the packaged repository command through the flake:

```sh
nix run . -- describe
nix run . -- show zlib
nix run . -- test eval
```

For incremental Rust work, build in the development environment and run the
binary directly:

```sh
nix develop -c just cli-build
crates/target/release/aos --help
```

The `just` recipes use that release binary. Set `AOS_BIN` to an equivalent
binary when the target directory lives elsewhere, for example on a constrained
CI or agent filesystem.

The development environment supplies the AOS-built dependencies and embeds the
required OpenSSL runtime path. Build and invoke the independent `aos`, `apm`,
or `apr` program for the surface under test. On-host service commands belong to
the private `aos-package-runtime` binary.

## Run checks

Start with the evaluation and formatting checks:

```sh
nix-build -A checks.eval
crates/target/debug/aos fmt --check
crates/target/debug/aos test eval
```

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

Application packages have a separate [authoring guide](../users/aos/package-authoring.md).
Registry producers and release automation should continue with the
[registry operator documentation](../users/registry/).
