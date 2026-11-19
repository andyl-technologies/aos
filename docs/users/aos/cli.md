# Use the AOS command-line tools

This reference covers the `aos` commands that work without a source checkout:
image discovery and download, local VMs, output modes, completions, native
documentation, and attestation verification. Host users normally use
[`apm`](packages.md) for package and generation operations and do not need a
source checkout or Nix. Source-tree builds, checks, and maintenance commands
are in [Use the repository CLI](../../maintainers/repository-cli.md).

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
three names. The private runtime has no public flake package.

The current repository CLI and bootable-image workflow is supported on
`x86_64-linux`. Package and registry tools have a broader portability model:

| Operation | Non-AOS Linux | Darwin | AOS |
| --- | --- | --- | --- |
| Registry search, inspection, and user configuration | Supported | Supported | Supported |
| Registry authoring and publication | Supported when required local tools are present | Supported for Darwin package artifacts | Supported |
| User-profile package operations | Supported for matching platform artifacts and a compatible local store | Supported for Darwin package artifacts and a compatible local store | Supported |
| `apm ... --system` or `apr --system ...` | Only with an explicit validated `AOS_ROOT` | Only with an explicit validated `AOS_ROOT` | Supported |
| Live activation, evaluation, and boot transitions | Unsupported | Unsupported | Private `aos-package-runtime` only |

System scope fails closed before loading package state. The selected root must
identify `ID=aos` and provide a numeric `AOS_MODULE_ABI`; live runtime commands
also require the immutable `/usr/lib/aos/toplevel/os-release` identity.

## Discover and download system images

`aos image` reads signed system-image metadata from a configured APM registry.
Git and static HTTP registries work without a Hub, source checkout, or Nix
installation. `--registry` names the local configuration shown by
`apm registry list` (see [Registry configuration](registries.md)):

```sh
apm registry list
aos image list --registry andyl --channel stable
aos image show --registry andyl --channel stable \
  --architecture x86_64 --target qemu-kvm
aos image download --registry andyl --channel stable \
  --architecture x86_64 --target qemu-kvm --output aos.qcow2
```

Use `--release` instead of `--channel` for an exact signed release, or add
`--format raw|qcow2|vmdk|vhd` when the target permits several encodings.
`--package` disambiguates registries that publish more than one sysroot package.
Channel resolution uses the client's persisted partition and rollback floor.
An explicit historical release does not change package tracking or lower that
floor. Signature verification cannot be disabled for image discovery.

Select Hub discovery explicitly with `--hub` (or `AOS_HUB`). In this mode,
`--registry` is the Hub's organization/registry slug:

```sh
aos image show --hub https://aos.andyl.org --registry andyl/main \
  --channel stable --architecture x86_64 --target qemu-kvm
```

`--token` or `AOS_TOKEN` authorizes a private Hub registry and requires Hub mode;
bearer tokens are rejected over cleartext HTTP. A failed explicit Hub request
never falls back to another registry. Portable registry discovery uses the
configured trust anchors and the selected registry's committed/client cache
chain, and rejects failed signature, freshness, or continuity checks.

`download` resumes the image NAR from the registry's CDN cache, verifies its
signed NAR identity, extracts the single regular-file output, and verifies the
signed disk byte size and SHA-256 before placing the final file. Omit
`--output` to use the useful filename from signed release metadata. Use
`--no-resume` to restart a partial transfer. Existing final files are never
overwritten.

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
aos --json image list --registry andyl --channel stable
aos --json image show --registry andyl --release 2026.3.0 \
  --architecture x86_64 --format raw
```

Use `aos --json image list` or `aos --json image show` for automation. The
record includes the store and NAR identity, ordered cache URLs, format, target
compatibility, media type, compression, exact size, SHA-256, release-signature
and boot verification states, and the associated integrity-bound
`image-delivery.json` and provider `image-info.json`. Secure Boot plus dm-verity
images also include paired recovery UKI and authenticated recovery-bundle metadata.

`apm image download PACKAGE --system --format FORMAT --output FILE` downloads
an image by its package name from the machine-wide registry configuration.
Omit `--system` to use your personal registry configuration and cache, including
on a non-AOS host. Downloading does not stage an image or change boot state.
Prefer `aos image` when choosing by end-user target, release channel, or direct
disk encoding.

## Run a downloaded image locally

`aos vm run` prepares a persistent writable disk from a downloaded raw or
QCOW2 image and boots it through UEFI. The verified download remains unchanged.
The command enlarges the working disk, relocates its backup GPT, retains
per-VM UEFI variable state, and can deliver literal `host.nix` through QEMU's
native metadata channel. The packaged runner selects QEMU and firmware for its
host architecture, so supply the corresponding image architecture:

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

The opt-in `pkgs.aos-vm` host package carries the AOS-built QEMU, UEFI firmware,
`qemu-img`, and `sgdisk` without adding emulator tooling to guest images. When
running the base package or a development binary, pass `--firmware-code` if
firmware is not installed at a conventional system path. x86_64 also accepts
an OVMF variable-store template through `--firmware-vars`; aarch64 accepts a
QEMU UEFI variable-state JSON template through the same option. The
corresponding environment variables are `AOS_OVMF_CODE` and `AOS_OVMF_VARS`.

Automatic acceleration selects KVM on Linux when `/dev/kvm` is accessible and
HVF on macOS. Linux falls back to slower TCG emulation with a warning. Use
`--accel kvm` or `--accel hvf` to require the corresponding host accelerator.
Inspect paths, resources, firmware, forwarding, and acceleration without
changing state by adding `--dry-run`. VM state lives under
`$XDG_STATE_HOME/aos/vms/<name>` (or `$HOME/.local/state/aos/vms/<name>`) unless
`--state-dir` is supplied. Its metadata binds the persistent disk to the base
image hash, architecture, and requested capacity so a reused name cannot
silently boot the wrong disk.

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

The generated script covers the `aos` command tree by default. `apm` and `apr`
have no `completions` subcommand of their own; generate their scripts with
`--command`:

```sh
aos completions bash --command apm > apm.bash
aos completions bash --command apr > apr.bash
```

## Inspect native runtime documentation

`aos docs` is an alias for `aos doc`. Native artifact inspection works without
Nix, a checkout, or a network connection:

```sh
aos docs runtime options.json
aos docs runtime transaction.json --format json
aos docs runtime transaction.json --format html --output execution.html
```

The input must be an `aos.module.documentation` reference or an
`aos.package.transaction`. Output defaults to text; global `--json` selects JSON
unless `--format` is explicit. `--output` writes a file. Runtime mode does not
accept installed-package, registry, search, or Hub selectors.

See [runtime abilities](runtime-abilities.md) for artifact generation and example
execution paths. Existing `doc package`, `doc hub`, and `ability` consumers have
not yet migrated to these native formats.

## Verify runtime attestation evidence

`apm attest verify` replays the package and generation events in the AOS
canonical event log (CEL). A bare `--pcr15` value verifies only event-log
consistency. A full generation decision requires an identity-pinned TPM quote,
the generation record, and a verifier-owned policy:

```sh
apm attest verify --system \
  --event-log host-evidence/aos-packages.cel \
  --quote-dir host-evidence/gen-attestation-quote \
  --nonce-file host-evidence/nonce.hex \
  --quote-identity-file verifier/quote-identities.json \
  --generation-attestation host-evidence/gen-attestation.json \
  --generation-policy-file verifier/generation-policy.json
```

Generation measurement retains the complete canonical record in the AOS CEL
and submits its SHA-256 digest to the TPM helper. Large records therefore do
not become command-line arguments. Use the AOS CEL for these events; they are
not also appended to systemd's supplemental userspace measurement log.

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
revoked, or mismatched release receipts.

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

A configuration transaction can commit a new generation while a service in it
fails, and image staging and boot assessment have a separate A/B state. See
[Upgrade and roll back a
host](upgrades.md#interpret-configuration-activation-results) before automating
system upgrades.

Continue with [Manage packages](packages.md) for `apm`, or
[Operate an AOS package registry](../registry/) for producer-side `apr`
workflows.
