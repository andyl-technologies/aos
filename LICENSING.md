# AOS licensing

This document is the repository's authoritative map of license scopes. A file's
SPDX identifier or an explicit license notice in its component takes precedence
over the defaults below. Third-party files retain their existing licenses.

## License map

| Scope | License |
| --- | --- |
| Original AOS code without a more specific notice | Apache-2.0 |
| `crucible-protocol` and `crucible-shmem` | MIT OR Apache-2.0 |
| `crucible-qemu-plugin` | GPL-2.0-only |
| QEMU and files derived from or linked into QEMU | QEMU's applicable upstream license, commonly GPL-2.0-only |
| AOS QEMU patch series | The license of the upstream file being modified; new GPL-covered QEMU integration is GPL-2.0-only |

The complete license texts are in [`LICENSES/`](LICENSES/). The root
[`LICENSE`](LICENSE) remains the Apache License 2.0 default for original AOS
code. The repository and AOS distributions are multi-license aggregates: the
presence of Apache-licensed code does not relicense QEMU, and this project does
not claim that all bundled software is Apache-2.0.

## Crucible/QEMU process boundary

The Apache-licensed Crucible host and QEMU are separate processes. They
communicate through a public, versioned protocol: a Unix-domain socket is the
setup and control plane, and shared memory is the high-throughput data plane.
The protocol is an interoperability contract, not a shared implementation.

`crucible-protocol` and `crucible-shmem` contain protocol and transport
definitions used on both sides of that process boundary. Their permissive
`MIT OR Apache-2.0` license lets independently licensed peers implement the same
contract. This does not change the license of either peer.

`crucible-qemu-plugin` is loaded into QEMU and calls QEMU plugin interfaces. It
is therefore part of the GPL side of the boundary and is licensed
GPL-2.0-only. Its dependency on the dual-licensed boundary crates is taken
under their MIT option, which is compatible with GPL-2.0-only. Any other code
compiled into, linked into, or
dynamically loaded by QEMU must remain within the applicable QEMU/GPL license
scope. Apache-only host crates must not link to QEMU or include QEMU headers.

Shared memory must remain protocol-shaped. It may contain fixed-width fields,
atomics, offsets, ring entries, sequence numbers, feature bits, and serialized
payloads specified by the public ABI. It must not contain native pointers,
function or callback tables, QEMU private structures, Rust-native layouts, or
other process-private objects. See the normative
[licensing and process boundary](docs/rfcs/0010-crucible/37-licensing-process-boundary.md).

## Distribution and corresponding source

AOS intends the controller, QEMU/plugin backend, and convenience suite to be
packaged as distinguishable components aggregated for installation. The legal
characterization of a particular distribution depends on the facts of that
distribution; in all cases, each component's applicable license and notices
must be honored. Package and release descriptions must list the licenses they
contain and must not describe a bundle containing QEMU as wholly Apache-2.0.

Anyone distributing a modified QEMU binary must satisfy the applicable GPL and
upstream obligations. An AOS release or public binary cache that offers the
Crucible QEMU binary must offer the complete corresponding source from an
equally accessible location. That source artifact must include the exact QEMU
source, the complete applied patch series, new QEMU/plugin integration source,
generated interface files required to build it, build/configuration scripts,
license notices, and enough identity metadata to match it to the binary. Release
automation must fail closed if the artifact or license inventory is missing.

This repository document describes project policy and is not legal advice.

## Contributions

Contributions follow the license applicable to the files changed. Original AOS
contributions require the project contributor license agreement; commits to
QEMU, its patch series, or in-QEMU code additionally require a Developer
Certificate of Origin `Signed-off-by` line. See [`CONTRIBUTING.md`](CONTRIBUTING.md)
and the [`Contributor License Agreement`](CONTRIBUTOR_LICENSE_AGREEMENT.md).
