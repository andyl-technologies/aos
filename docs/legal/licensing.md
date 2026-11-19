# AOS licensing

This document is the repository's authoritative map of license scopes. A file's
SPDX identifier or an explicit license notice in its component takes precedence
over the defaults below. Third-party files retain their existing licenses.

## License map

| Scope | License |
| --- | --- |
| Original AOS code without a more specific notice | Apache-2.0 |
| `crucible-qemu-protocol` and `crucible-qemu-shmem` | MIT OR Apache-2.0 |
| `crucible-qemu-plugin` | GPL-2.0-only |
| `crucible-qemu-debug-gateway` | GPL-2.0-only |
| `crucible-qemu-trace-plugin` | GPL-2.0-only |
| QEMU emulator as a combined work | GPL-2.0-only |
| Individual QEMU source files | The file's notice; unmarked files default to GPL-2.0-or-later under QEMU 11.1.1's `LICENSE` |
| AOS atomic QEMU patch | Modified files retain their upstream license; every created file and its license is listed in the [patch inventory](../../pkgs/emulation/qemu-patches/LICENSES.md) |

The complete license texts are in [`LICENSES/`](../../LICENSES/). The root
[`LICENSE`](../../LICENSE) remains the Apache License 2.0 default for original
AOS code and allows GitHub to identify that default accurately. The repository
and AOS distributions are multi-license aggregates: the presence of
Apache-licensed code does not relicense QEMU, and this project does not claim
that all bundled software is Apache-2.0.

## Crucible/QEMU process boundary

The Apache-licensed Crucible host and QEMU are separate processes. They
communicate through a public, versioned protocol: a Unix-domain socket is the
setup and control plane, and shared memory is the high-throughput data plane.
The protocol is an interoperability contract, not a shared implementation.

`crucible-qemu-protocol` and `crucible-qemu-shmem` contain protocol and transport
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
QEMU's combined-work license and its per-file licenses are separate metadata:
the current atomic patch creates GPL-2.0-or-later QEMU source files, while the
Rust and C Crucible QEMU plugins remain explicitly GPL-2.0-only. Packages and
corresponding-source artifacts must preserve and inventory both GPL scopes.

`crucible-qemu-debug-gateway` is a GPL-2.0-only standalone process. It owns the
persistent debugger session and connects to QEMU's private RSP socket. The
Apache controller communicates with it only through versioned Unix-socket
frames defined by the dual-licensed `crucible-qemu-protocol` crate; neither process
links or dynamically loads the other.

```text
Apache-2.0 host process                 QEMU process (applicable GPL scope)
+--------------------------+           +--------------------------+
| engine, scheduler,       |           | patched QEMU             |
| assertions, CLI          |           | crucible-qemu-plugin     |
|                          |           |                          |
| permissive protocol/SHM  |<=========>| permissive protocol/SHM  |
| implementation           |  public   | implementation           |
+--------------------------+  ABI      +--------------------------+
             Unix socket: setup/control only
             shared memory: high-throughput data plane
```

The rules below are normative for every change to Crucible, its QEMU
integration, and their packaging. `gate:license-boundary` enforces them, and
`gate:abi-conformance` additionally enforces the rules on shared-memory shape,
layout, and versioning.

### Separate processes

Apache-licensed host code and GPL-side QEMU code communicate only as separate
processes through the versioned control and shared-memory protocols.
Apache-only code must not link QEMU libraries, include QEMU headers, load into
QEMU, export QEMU callbacks, or exchange direct calls with in-QEMU code. The
plugin takes its boundary-crate dependencies under the GPL-compatible license
choice and must not depend on an Apache-only host crate.

The socket is the cold setup and control plane. It negotiates versions and
transfers descriptors; after setup completes it is quiescent, and scheduling,
clock, frame, I/O, observation, and doorbell traffic flows through shared
memory. The data path still uses futex wakes and eventfd writes to signal the
peer, but those counters carry neither timing decisions nor payloads. A
boundary refactor must not replace shared memory with per-quantum or
per-frame socket round trips merely to make the process boundary visible.

### A public shared-memory protocol

Shared memory must remain protocol-shaped. It may contain fixed-width fields,
explicitly sized atomics, checked region-relative offsets, version and feature
fields, ring geometry, sequence and generation numbers, tagged entries, and
serialized byte payloads specified by the public ABI. It must not contain
native pointers, function or callback tables, QEMU private structures,
compiler-selected Rust layouts, trait objects, or ownership of any other
process-private object.

The field semantics, byte layout, ordering rules, and versioning policy are
public. The Rust definitions remain the mechanically checked source from which
the C view is generated, but no semantic contract may exist only in Rust or
QEMU implementation internals: an independent peer built from the public
documentation and golden vectors must be able to interoperate. The
[shared-memory ABI](../engineering/crucible/shmem-abi.md) and
[control protocol](../engineering/crucible/control-protocol.md) pages document
the contract.

### Versioning and review

Every incompatible control-frame, shared-memory field, layout, atomic-ordering,
or semantic change bumps the applicable ABI major version and fails closed
against every noncurrent peer. Any addition requires an explicit version or
feature bit, and the change regenerates both language views and the golden
vectors.

A change that moves code across the boundary requires explicit
license-boundary review. CI rejects a QEMU dependency in an Apache-only crate,
an Apache-only dependency in the plugin, a missing or inconsistent component
license declaration, a forbidden shared-memory construct, and a generated ABI
mismatch.

### Guest assertions

Guest assertion definitions, evaluation, verdicts, and evidence semantics stay
in the Apache host. The optional guest doorbell is an observation protocol,
not an assertion evaluator. Any QEMU or plugin change needed to trap, read,
validate, or publish a guest observation remains GPL-side and crosses to the
host only as a versioned shared-memory or doorbell-protocol record. No QEMU
structure, guest pointer, or callback crosses the boundary.

## Distribution and corresponding source

The controller, QEMU/plugin backend, and convenience suite are packaged as
distinguishable outputs with accurate license metadata, aggregated for
installation. The legal characterization of a particular distribution depends
on the facts of that distribution; in all cases, each component's applicable
license and notices must be honored. Package and release descriptions must list the licenses they
contain and must not describe a bundle containing QEMU as wholly Apache-2.0.

Anyone distributing a modified QEMU binary must satisfy the applicable GPL and
upstream obligations. An AOS release or public binary cache that offers the
Crucible QEMU binary must offer the complete corresponding source from an
equally accessible location. That source artifact must include the exact QEMU
source, the complete applied atomic patch, new QEMU/plugin integration source,
generated interface files required to build it, build/configuration scripts,
license notices, and enough identity metadata to match it to the binary. Release
automation must fail closed if the artifact or license inventory is missing.
`qemu-crucible` is therefore an internal, non-standalone release component:
`apr publish` and `apr release --store-path` reject its store path directly.
They inspect the complete runtime closure, so publishing the plugin or an
unmarked wrapper around patched QEMU is rejected as well. Publish the
`crucible` suite root instead. Its indexed, identity-bound release policy
accounts for every restricted closure member and directly retains both
`qemu-crucible` and the matching `qemu-crucible-source` path, so both are
members of the binary-cache closure without making source a QEMU runtime
dependency. Ambiguous or incomplete binary/source pairs fail closed. Generic,
unpatched QEMU packages have no such restriction.

This repository document describes project policy and is not legal advice.

## Contributions

Contributions follow the license applicable to the files changed. External AOS
contributors require the external contributor license agreement. Current Andyl,
Inc. employees contributing within the scope of their employment are covered by
Andyl's standard CIAA and internal contribution authorization instead. Commits
to QEMU, its atomic patch, or in-QEMU code additionally require a Developer
Certificate of Origin `Signed-off-by` line for both contribution paths. See
[`CONTRIBUTING.md`](../../CONTRIBUTING.md) and the
[`External Contributor License Agreement`](external-contributor-license-agreement.md).
