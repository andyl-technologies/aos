# Maintainer reference: Use the AOS command-line tools

This reference covers the repository and release-engineering command surface.
Host users normally use [`apm`](packages.md) for package and generation
operations and do not need a source checkout or Nix.

The source package builds independent command-line programs with shared
libraries, deliberately separate parsers, and separate Nix outputs.

| Command | Scope |
| --- | --- |
| `aos` | Source tree, builds, checks, generated reference, Hub client |
| `apm` | Package consumption, consumer registry configuration, and installed generations |
| `apr` | Registry workspaces, authoring, signing, and publication |
| `aos-package-runtime` | Private AOS service, evaluation, and activation operations |

There are no long-form aliases: `aos package` does not exist. Producer commands
such as `publish` and `release` are not accepted below `apm registry`, and the
private runtime rejects public package-manager commands.

The package-set mapping is explicit: `pkgs.aos` contains only `aos`,
`pkgs.aos.apm` contains only `apm`, and `pkgs.aos.apr` contains only `apr`.
`pkgs.aos.packageRuntime` is private and is referenced directly by AOS service
units. The split outputs share one Cargo build but retain distinct runtime-tool
closures.

An AOS base image places only `apm` on the operator `PATH`; the repository and
registry-authoring tools are host-side programs. From a repository checkout,
run `aos` through the flake:

```sh
nix run . -- describe
nix run . -- test eval
```

Build the public command outputs independently with `nix build .#aos`,
`nix build .#apm`, or `nix build .#apr`. The development shell exposes all
three names on Linux, Intel macOS, and Apple Silicon macOS. The private runtime
has no public flake package.

Darwin packages are built from source by AOS's `x86_64-linux` cross toolchain.
A Mac must have access to an `x86_64-linux` remote builder or a trusted cache
that already contains the requested outputs. Once realized, the commands and
their dependencies are native Mach-O programs. The development shell follows
the same model: its first realization may use the remote builder, while Cargo,
Rust, Clang, Nix, Git, and subsequent incremental builds execute locally on
macOS.

The repository CLI is supported on Linux and Darwin. Bootable AOS image builds
still execute on an `x86_64-linux` builder. Package and registry commands have
the following runtime model:

| Operation | Non-AOS Linux | Darwin | AOS |
| --- | --- | --- | --- |
| Registry search, inspection, and user configuration | Supported | Supported | Supported |
| Registry authoring and publication | Supported when required local tools are present | Supported for Darwin package artifacts | Supported |
| User-profile package operations | Supported for matching platform artifacts and a compatible local store | Supported for Darwin package artifacts and a compatible local store | Supported |
| `apm ... --system` or `apr --system ...` | Only with an explicit validated `AOS_ROOT` | Only with an explicit validated `AOS_ROOT` | Supported |
| Live activation, evaluation, and boot transitions | Unsupported | Unsupported | Private `aos-package-runtime` only |

System scope fails closed before loading package state. The selected root must
identify `ID=aos` and provide a numeric `AOS_MODULE_ABI`; live runtime commands
also require the immutable `/aos-toplevel/os-release` identity.

## Work in a repository checkout

Most `aos` development commands need `nix-build` and an AOS source root with a
`default.nix`. Root discovery checks, in order:

1. `AOS_ROOT`;
2. the current directory and its parents;
3. the binary directory and its parent.

Cache, Hub, metadata, server, token, and completion commands dispatch before
repository discovery and can run without a source checkout when their own
inputs are available. Package operations belong to `apm` and registry
authoring belongs to `apr`; neither requires an AOS source checkout.

## Build and inspect source

Common repository workflows are:

```sh
# Build one package or every package.
aos build zlib
aos build --all

# Inspect package metadata and dependency structure.
aos show zlib
aos graph zlib
aos graph zlib --dot > zlib.dot
aos why-depends curl openssl

# Inspect closures and references.
aos profile closure systems.server.build.toplevel
aos profile refs curl openssl

# Enter a repository-aware Nix REPL or browse generated reference data.
aos repl
aos doc
```

`aos build zlib` builds `pkgs.zlib`; it does not install a package on the
running host. Use `apm install zlib` for that operation.

The flake output `packages.<system>.all` is the remote-build equivalent of
`aos build --all`: build it when one submitted derivation must realize every
individual `pkg-*` output for that system. For example, submit
`packages.x86_64-linux.all` to an x86_64 Linux builder. Git-backed package
sources use pinned fixed-output archives so restricted remote evaluators create
ordinary fetch derivations instead of requiring evaluation-time network access.
The aggregate remains one remote build session and does not shard its package
plan across a worker fleet. Submit independent `pkg-*` outputs as separate
builds when you want package-level cluster parallelism; their successful store
outputs remain reusable by a later `all` build.
Individual `pkg-*` outputs remain lazy: evaluating `pkg-openjdk-24`, for
example, does not inspect or realize Crucible merely to enumerate the package
set. Add new package files through `pkgs/default.nix` filesystem discovery, and
add explicit package aliases to its `packageNames` inventory, so this property
remains true.

System image production currently uses Nix directly. See
[Build and customize release images](../../maintainers/system-images.md). Do
not use `aos system build`, `aos system image`, or `aos system eval` with the
current tree; those commands still target an older attribute layout and are
not covered by the current system tests.

## Discover and download system images

`aos image` consumes the signed system-image catalog of a Hub registry and
downloads disk bytes directly. It does not require a source checkout:

```sh
aos image list --registry andyl/main --channel stable
aos image show --registry andyl/main --channel stable \
  --architecture x86_64 --target qemu-kvm
aos image download --registry andyl/main --channel stable \
  --architecture x86_64 --target qemu-kvm --output aos.qcow2
```

Use `--release` instead of `--channel` for an immutable release, or add
`--format raw|qcow2|vmdk|vhd` when the target permits several encodings.
`--package` disambiguates registries that publish more than one sysroot
package. `--hub` defaults to the public AOS Hub. `--token` or `AOS_TOKEN`
authorizes a private registry and is rejected over cleartext HTTP.

Downloads resume an existing hidden partial file with an HTTP range request.
The command enforces the signed size and SHA-256 before atomically installing
the final file; verification cannot be disabled. A partial identity file binds
resume state to its release, architecture, format, size, and hash so reusing an
output name for another image fails before additional bytes transfer.
`--no-resume` restarts the partial download. With no `--output`, the signed
useful filename is used. Transient failures retry three times by default; use
`--retries` to change that limit. An interrupted download reports the retained
partial path and exits with status 130.

All three subcommands support the global JSON output mode:

```sh
aos --json image list --registry andyl/main --channel stable
aos --json image show --registry andyl/main --release 2026.3.0 \
  --architecture x86_64 --format raw
```

`apm install PACKAGE --system --image FORMAT --output FILE` remains available
for package-oriented installation flows. Prefer `aos image` when choosing by
end-user target, release channel, or direct disk encoding.

## Run a downloaded image locally

`aos vm run` prepares a persistent writable disk from a downloaded raw or
QCOW2 image and boots it through UEFI. The verified download remains unchanged.
The command enlarges the working disk, relocates its backup GPT, retains a
per-VM OVMF variable store, and can deliver literal `host.nix` through QEMU's
native metadata channel:

```sh
nix-build -A pkgs.aos-vm -o result-aos-vm
```

```sh
./result-aos-vm/bin/aos vm run ./aos.qcow2 \
  --host-config ./host.nix \
  --disk-size-gib 16 \
  --ssh-port 2222
```

Signed configuration deployments can add
`--host-config-signature ./host.nix.sig`; the command exposes both files under
their documented QEMU `fw_cfg` names.

The opt-in `pkgs.aos-vm` host package carries the AOS-built QEMU, OVMF,
`qemu-img`, and `sgdisk` without adding emulator tooling to guest images. When
running the base package or a development binary, pass `--firmware-code` and
`--firmware-vars`, or set `AOS_OVMF_CODE` and `AOS_OVMF_VARS`, if firmware is
not installed at a conventional system path.

KVM is selected only when `/dev/kvm` is accessible; automatic selection falls
back to slower TCG emulation with a warning. Use `--accel kvm` to require
hardware acceleration. Inspect paths, resources, firmware, forwarding, and
acceleration without changing state by adding `--dry-run`. VM state lives under
`$XDG_STATE_HOME/aos/vms/<name>` (or `$HOME/.local/state/aos/vms/<name>`) unless
`--state-dir` is supplied. Its metadata binds the persistent disk to the base
image hash and requested capacity so a reused name cannot silently boot the
wrong disk.

## Run checks and maintenance commands

```sh
# Formatting and static checks.
aos fmt --check
aos fmt
aos lint
aos lint zlib

# Test layers.
aos test eval
aos test build
aos test vm
aos test fleet

# Source hashes.
aos prefetch
aos prefetch --package zlib
aos prefetch --all
```

`aos test` with no layer runs evaluation, build, VM, and fleet tests in order.
VM and fleet layers need a Linux host with KVM. `aos prefetch --update` edits
package source hashes; inspect its diff before committing.

`aos fmt` uses its embedded Alejandra formatter.

## Choose output for people or automation

Global output modes are explicit:

| Flag | Behavior |
| --- | --- |
| none | Human-readable normal output |
| `--json` | Compact JSON on standard output |
| `--quiet` | Suppress non-error printer output |
| `-v` | Verbose output |
| `--progress auto` | Use a terminal display interactively and stable lines in logs |
| `--progress tty` | Force an updating terminal display |
| `--progress plain` | Emit stable newline-delimited progress updates |
| `--progress off` | Suppress progress while retaining final results and errors |
| `--color auto` | Use color on an interactive terminal and honor `NO_COLOR` |
| `--color always` | Force terminal colors |
| `--color never` | Disable terminal colors |
| `-vv` | Also stream Nix subprocess standard error |
| `-vvv` | Also print the Nix command line |

Use `--json` for scripts:

```sh
aos --json show zlib
apm --json list --installed
apm --json update --system
```

The normal printer writes human-facing messages to standard error, while JSON
uses standard output. The CLI does not generally switch formats when output is
piped. Exceptions with intentional standard output include completion scripts,
DOT graphs, and parts of `aos doc`. `aos doc` itself opens its interactive view
only when standard output is a terminal; a pipe receives a summary.

## Generate completions

Write a completion script to the location expected by the shell:

```sh
aos completions bash > aos.bash
aos completions zsh > _aos
aos completions fish > aos.fish
```

The generated script covers the `aos` command tree. `apm` and `apr` do not
currently expose their own completion generators.

## Verify runtime attestation evidence

`apm attest verify` replays the package and generation events in the AOS CEL.
A bare `--pcr15` value verifies only event-log consistency. A full generation
decision requires an identity-pinned TPM quote, the generation record, and a
verifier-owned policy:

```sh
apm attest verify --system \
  --event-log host-evidence/aos-packages.cel \
  --quote-dir host-evidence/gen-attestation-quote \
  --nonce-file host-evidence/nonce.hex \
  --quote-identity-file verifier/quote-identities.json \
  --generation-attestation host-evidence/gen-attestation.json \
  --generation-policy-file verifier/generation-policy.json \
  --rederived-manifest verifier/rederived-manifest.json
```

The policy is strict JSON. Version 2 requires an operator-authorized PCR-12
boot-input value; version 1 is rejected because it cannot express that check.
PCR and root values come from verifier-controlled policy and catalog data, not
from the host being checked:

```json
{
  "schema": "aos.gen-attestation-policy/v2",
  "expected_pcr7": "<64 lowercase hex>",
  "expected_pcr11": "sha256:<64 lowercase hex>",
  "expected_pcr12": "<64 lowercase hex>",
  "expected_root_roothash": "<64 lowercase hex>",
  "expected_facts_hash": "sha256:<64 lowercase hex>",
  "trusted_config_keys": ["<8-hex fingerprint>"],
  "trusted_platforms": ["aws"]
}
```

The command verifies the quote against an enrolled AK/EK identity, binds the
record to its unique activation event and PCR-15 prefix, checks PCR 7, PCR 11, PCR 12,
dm-verity, facts, and host-input authorization, and reconstructs config-module
membership and realization from the signed release commit. It rejects missing,
revoked, or mismatched release receipts. `--rederived-manifest` supplies an
independently produced manifest for the final reproducibility gate and is
mandatory for image-authored configuration.

Create the quote-identity catalog only after completing the selected enrollment
workflow:

```sh
apm attest enroll \
  --quote-dir enrollment/quote \
  --label node-17 \
  --method credential-activation \
  --evidence-file enrollment/credential-activation.transcript \
  --catalog-file verifier/quote-identities.json
```

## Understand command results

Most successful commands exit `0`. Invalid syntax normally exits `2`, and
build, evaluation, download, hash, and package errors use nonzero codes suited
to their command surface. A declined package-operation confirmation exits
`100`.

Configuration activation can report a degraded result after the new generation
is live, while image staging and boot assessment have a separate A/B state.
See [Upgrade and roll back a host](upgrades.md#interpret-configuration-activation-results)
before automating system upgrades.

Continue with [Manage packages](packages.md) for `apm`, or
[Operate an AOS package registry](../registry/) for producer-side `apr`
workflows.
