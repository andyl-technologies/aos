# 37 — Crate structure

This file owns the decomposition of the reference implementation into Rust
crates: which crate owns which concern, the `no_std` boundary, the dependency
direction between crates, feature flags, the public SDK surface, and the
engineering standards every crate meets. It exists so that an implementation
can be built by several people at once without the layers leaking into each
other, and so that the parts that have no reason to touch an operating system
never do.

## Overview

The crate stack follows the layers of
[`03-architecture-overview.md`](03-architecture-overview.md) and cuts them
along the `no_std` line. Everything that is a pure function of bytes lives in
a crate with no I/O and no allocator beyond `alloc`. Everything that performs
I/O does so through two small traits so that the same library runs on a native
async runtime and on a WebAssembly host. Kernel surfaces are isolated in one
Linux-only crate, which is also the only crate permitted to contain `unsafe`
code. One binary crate composes the rest into roles.

```text
terrane-cli        the `terrane` binary: roles, configuration, protocol server
   │
   ├── terrane-fs      Linux only; kernel surfaces; the only unsafe crate
   │      │
   ├── terrane-edge    wasm32 bindings: edge buckets and edge surfaces
   │      │
   └── terrane         std; store trait, combinators, backends, GC
          │
          └── terrane-core   no_std + alloc; formats and algorithms
```

An adopting system writes its own glue crate outside this set. Glue crates
depend on `terrane` and, where they realize kernel surfaces, on `terrane-fs`.
Nothing in this set depends on a glue crate.

## Crates

### `terrane-core`

- **[CRATE-1]** `terrane-core` MUST compile with `#![no_std]` plus `alloc`
  and MUST NOT perform any I/O, read a clock, read an environment, or spawn a
  task. *Gate:* `gate:core-no-std`.
- **[CRATE-2]** `terrane-core` MUST own every format and algorithm whose
  output is part of an identity: the content-defined chunker
  ([`05-chunking.md`](05-chunking.md)), the BLAKE3 digest and identity-domain
  preimages ([`04-content-model.md`](04-content-model.md)), prolly-tree
  construction, boundary decisions, node encoding and decoding
  ([`06-tree-format.md`](06-tree-format.md)), diff and three-way merge
  ([`07-tree-algebra.md`](07-tree-algebra.md)), commit and ref record types
  ([`09-refs-and-commits.md`](09-refs-and-commits.md)), the deterministic
  CBOR profile (`reference/terrane-v1.cddl`), routing matchers and rule
  compilation ([`31-routing-rulesets.md`](31-routing-rulesets.md)),
  capability-token parsing and signature verification
  ([`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)),
  and tree schemas ([`26-surfaces.md`](26-surfaces.md)). *Gate:*
  `gate:golden-vectors`.
- **[CRATE-3]** Every golden vector in `reference/golden-vectors.md` MUST be
  reproducible by `terrane-core` alone, so that a conformance test for an
  identity never requires a store, a network, or a filesystem. *Gate:*
  `gate:golden-vectors`.
- **[CRATE-4]** `terrane-core` MUST expose encoders and decoders that operate
  on borrowed byte slices and return typed errors; it MUST NOT panic on any
  input. Decoder limits from the CBOR profile apply before any allocation
  sized by the input. *Gate:* `gate:core-fuzz`.
- **[CRATE-5]** `terrane-core` SHOULD compile for `wasm32-unknown-unknown`
  without features beyond `alloc`, so that edge implementations
  ([`38-wasm-and-edge.md`](38-wasm-and-edge.md)) share exactly the identity
  code of native ones.

### `terrane`

- **[CRATE-6]** `terrane` MUST own the store interface and its combinators
  ([`11-store-trait.md`](11-store-trait.md)), the bucket, disk, shared-dir,
  and remote backends, the repository verbs (fork, commit, merge, fold, tag,
  diff, watch), the guard ([`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)),
  tiering and topology ([`19-tiering-and-topology.md`](19-tiering-and-topology.md)),
  garbage collection ([`17-garbage-collection.md`](17-garbage-collection.md)),
  tree jobs ([`32-tree-jobs.md`](32-tree-jobs.md)), and the client and server
  halves of the wire protocol ([`18-protocol.md`](18-protocol.md)).
- **[CRATE-7]** `terrane` MUST perform all I/O through the traits
  `HttpClient` and `Clock`, plus a `LocalFs` trait that is only available
  under the `std` feature. It MUST NOT depend on a specific async runtime in
  its library target. Async operations use `async fn` in traits and return
  futures that are `Send` when the `send` feature is enabled. *Gate:*
  `gate:runtime-agnostic`.
- **[CRATE-8]** `terrane` MUST provide the features `tokio` (native runtime
  binding for `HttpClient`, `Clock`, and `LocalFs`) and `wasm` (bindings for
  a WebAssembly host's fetch and time primitives). Exactly one of the two
  MUST be enabled by a consumer that performs I/O. *Gate:*
  `gate:feature-matrix`.
- **[CRATE-9]** The `blockdev` backend ([`16-blockdev-backend.md`](16-blockdev-backend.md))
  MUST live behind the `blockdev` feature and MUST be available only with
  `std`.

### `terrane-fs`

- **[CRATE-10]** `terrane-fs` MUST own every surface whose endpoint is a
  kernel object: FUSE ([`27-surface-fuse.md`](27-surface-fuse.md)), EROFS and
  overlayfs and the block surface ([`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md)),
  and virtiofs ([`29-surface-vm.md`](29-surface-vm.md)), together with the
  host-tier mechanisms that need kernel APIs: sealing with fs-verity, backing
  registration for passthrough, project quotas, and mount inspection
  ([`14-host-tier.md`](14-host-tier.md)).
- **[CRATE-11]** `terrane-fs` MUST compile only for Linux targets and MUST
  fail at compile time, not at run time, on any other target.
- **[CRATE-12]** `terrane-fs` is the only crate in this set that MAY contain
  `unsafe` code. See §Unsafe policy.

### `terrane-edge`

- **[CRATE-13]** `terrane-edge` MUST own the bindings that make `terrane`
  run on a WebAssembly host: an `HttpClient` over the host's fetch primitive,
  a `Clock` over the host's time primitive, a bucket adapter for the host's
  object-storage binding including its conditional-write form, and the edge
  entry points for the surfaces listed in
  [`38-wasm-and-edge.md`](38-wasm-and-edge.md).
- **[CRATE-14]** `terrane-edge` MUST NOT depend on `terrane-fs`.

### `terrane-cli`

- **[CRATE-15]** `terrane-cli` MUST produce one binary named `terrane` and
  MUST implement the roles `serve`, `realize`, `fuse-worker`, `publish`, `gc`,
  and `job`. Each role is a separate process invocation; a role MUST NOT
  acquire the privileges or the network access of another role by being in
  the same binary.
- **[CRATE-16]** `terrane-cli` MUST contain no logic that another crate
  could own: argument parsing, configuration loading, role dispatch, logging
  setup, and signal handling only. Any behavior with a requirement ID
  elsewhere in this specification MUST be implemented in a library crate and
  called from `terrane-cli`.
- **[CRATE-17]** The configuration format read by `terrane-cli` MUST be the
  store-expression and exposure grammar of
  [`11-store-trait.md`](11-store-trait.md) and
  [`26-surfaces.md`](26-surfaces.md). `terrane-cli` MUST NOT define a second
  configuration vocabulary.

### Glue crates

An adopting system's crate that binds Terrane to its service manager, its
mount broker, its identity provider, or its packaging is a glue crate.

- **[CRATE-18]** A glue crate MUST NOT be a dependency of any crate in this
  set, and this set MUST NOT reference a glue crate by name. Extension
  happens by implementing the `Surface`, `Store`, `HttpClient`, `Clock`, and
  `LocalFs` traits, and by providing a token issuer, never by patching a
  crate in this set.

## Dependency direction

- **[CRATE-19]** Dependencies MUST point downward only:
  `terrane-cli` → {`terrane-fs`, `terrane-edge`, `terrane`} → `terrane-core`.
  `terrane-fs` and `terrane-edge` MUST NOT depend on each other. *Gate:*
  `gate:crate-graph`.
- **[CRATE-20]** A crate MUST NOT re-export a type from a crate it does not
  depend on, and MUST NOT define a second type for a concept a lower crate
  already defines. The five nouns are defined once, in `terrane-core`.
- **[CRATE-21]** External dependencies MUST be reviewed against the
  `no_std` boundary. `terrane-core` MUST NOT depend on any crate that requires
  `std`, a C toolchain, or platform APIs. Compression codecs are supplied to
  `terrane-core` through a trait; the concrete codec is chosen by the
  consuming crate. *Gate:* `gate:core-no-std`.

## The SDK surface

The SDK is the public API of `terrane` and `terrane-core` taken together.
An out-of-process surface ([`26-surfaces.md`](26-surfaces.md)) and an
adopting system's tooling use only this surface.

- **[CRATE-22]** The SDK MUST expose these types with the meanings given in
  [`02-glossary.md`](02-glossary.md): `Chunk`, `Object`, `Tree`, `Node`,
  `Entry`, `Commit`, `Ref`, `Root`, `Property`, `View`, `Recipe`, `Store`,
  `Repository`, `Surface`, `Exposure`, `Endpoint`, `Token`, `Grant`.
- **[CRATE-23]** The SDK MUST expose the repository verbs `fork`, `commit`,
  `merge`, `fold`, `tag`, `diff`, `watch`, `fetch`, and `push` with the
  semantics of [`09-refs-and-commits.md`](09-refs-and-commits.md) and
  [`07-tree-algebra.md`](07-tree-algebra.md), and the tree algebra `graft`,
  `split`, `flatten`, `overlay`, `filter`, and `map`.
- **[CRATE-24]** The SDK MUST expose `realize(view, hints) -> Serving` as the
  single entry point for exposing a view, and MUST NOT expose a
  surface-specific entry point that bypasses the surface registry.
- **[CRATE-25]** The SDK MUST expose the tree-job primitives `iter`,
  `shards`, `checkpoint`, and `follow` of [`32-tree-jobs.md`](32-tree-jobs.md),
  and `attrs.get` and `attrs.put` for the per-object attribute table of
  [`10-derived-data.md`](10-derived-data.md).
- **[CRATE-26]** In-process access and remote access MUST present the same
  SDK types and verbs. A `Repository` over a `remote` store MUST behave
  identically to a `Repository` over a local one, apart from latency and the
  errors of [`18-protocol.md`](18-protocol.md).
- **[CRATE-27]** Every public SDK item MUST be documented to the standard in
  §Documentation, and the SDK MUST be usable without reading any private
  module.

## Feature-flag registry

Surfaces compile in behind named features so that a build of `terrane-cli`
contains exactly the surfaces it needs and the vocabulary stays closed.

| Feature | Crate | Enables |
| --- | --- | --- |
| `std` | `terrane` | `LocalFs`, `disk`, `shared-dir`, and file buckets |
| `send` | `terrane` | `Send` bounds on async traits |
| `tokio` | `terrane` | native runtime bindings |
| `wasm` | `terrane` | WebAssembly host bindings |
| `blockdev` | `terrane` | the block-device backend |
| `redundancy` | `terrane` | `replicated` and `striped` combinators |
| `surface-fuse` | `terrane-fs` | the FUSE surface |
| `surface-erofs` | `terrane-fs` | the EROFS and overlayfs surface |
| `surface-block` | `terrane-fs` | the block surface |
| `surface-virtiofs` | `terrane-fs` | the virtiofs surface |
| `surface-nix` | `terrane` | the Nix binary-cache surface |
| `surface-reapi` | `terrane` | the Remote Execution API surface |
| `surface-gha` | `terrane` | the Actions-cache surface |
| `surface-git` | `terrane` | the git surface |
| `surface-oci` | `terrane` | the OCI Distribution surface |
| `surface-web` | `terrane` | the HTTP browse surface |

- **[CRATE-28]** Every surface in `reference/surface-registry.md` MUST have a
  feature named `surface-<name>`, and no surface MAY be compiled in without
  its feature. *Gate:* `gate:feature-matrix`.
- **[CRATE-29]** `gate:feature-matrix` MUST build and test the
  no-default-features configuration of every crate, each feature alone, and
  the all-features configuration, on every supported target.

## Unsafe policy

- **[CRATE-30]** `terrane-core`, `terrane`, `terrane-edge`, and
  `terrane-cli` MUST set `#![forbid(unsafe_code)]`. *Gate:* `gate:unsafe-audit`.
- **[CRATE-31]** Every `unsafe` block in `terrane-fs` MUST be preceded by a
  `// SAFETY:` comment stating the invariant the block relies on and where
  that invariant is established. A block whose comment cannot name the
  invariant is a conformance error. *Gate:* `gate:unsafe-audit`.
- **[CRATE-32]** `unsafe` in `terrane-fs` MUST be confined to raw kernel
  interfaces that have no safe binding: FUSE device I/O, passthrough backing
  registration, mount and mount-inspection system calls, memory mapping of
  index files, and block-device ioctls. Application logic in `terrane-fs`
  MUST be written in safe Rust over those bindings.
- **[CRATE-33]** Memory-mapped index files MUST be treated as untrusted
  input: every access is bounds-checked against the mapping length, and a
  malformed file produces an error, not undefined behavior. *Gate:*
  `gate:core-fuzz`.

## Documentation

- **[CRATE-34]** Every crate root MUST carry a crate-level overview that
  names the crate's responsibility, maps its modules, and states which files
  of this specification it implements.
- **[CRATE-35]** Every module MUST carry a module-level header. A module that
  owns an on-disk or wire format MUST show the format in a fenced, tagged
  example block.
- **[CRATE-36]** Every public item MUST carry a summary line. Every public
  function returning a result MUST document its error conditions. Every
  reachable panic MUST be documented. Fenced blocks in documentation MUST be
  tagged so that only intended examples compile as tests.
- **[CRATE-37]** Documentation MUST cite requirement IDs from this
  specification where an item exists to satisfy one, so that a reader can go
  from code to requirement and back.

## Error handling

- **[CRATE-38]** Library crates MUST model errors as typed enumerations with
  a source chain and MUST NOT use string-typed errors on any public path.
- **[CRATE-39]** Library crates MUST NOT unwrap or expect a result on a
  production path. Tests and examples MAY, where a panic is the intended
  signal. *Gate:* `gate:lint`.
- **[CRATE-40]** Every error that reaches a surface MUST map to exactly one
  entry of `reference/errno-mapping.md` or to one protocol status of
  [`18-protocol.md`](18-protocol.md). An unmapped error is a conformance
  error.
- **[CRATE-41]** Errors on authorization, verification, and fencing paths
  MUST fail closed: an error while deciding whether to allow, admit, or
  commit is a denial.

## Size and readability discipline

- **[CRATE-42]** A hand-written source file approaching one thousand lines
  SHOULD be split by responsibility; a file beyond roughly fifteen hundred
  lines MUST carry a cohesion note in its module header explaining why it is
  one file. Test modules are judged separately from the code they test.
- **[CRATE-43]** Validation, transformation, effects, and result
  construction SHOULD be visibly separated inside a function by named helpers
  or intentional blank lines. Formatting tools set the baseline; readability
  is reviewed by people.
- **[CRATE-44]** Comments MUST explain invariants, ordering rules,
  fail-closed behavior, security decisions, and non-obvious tradeoffs, and
  MUST NOT narrate syntax.

## Interactions

- [`03-architecture-overview.md`](03-architecture-overview.md) defines the
  layers this crate stack mirrors.
- [`11-store-trait.md`](11-store-trait.md) and
  [`26-surfaces.md`](26-surfaces.md) define the traits whose implementations
  the crates carry.
- [`36-testing-and-conformance.md`](36-testing-and-conformance.md) defines
  the gates named here.
- [`38-wasm-and-edge.md`](38-wasm-and-edge.md) depends on `CRATE-1`,
  `CRATE-5`, `CRATE-7`, `CRATE-8`, and `CRATE-13`.

## Informative: why the line is here

The `no_std` boundary is placed exactly at identity. If a byte contributes to
a hash, the code that produces that byte lives in `terrane-core`, where it
can be run by any implementation, on any target, against the golden vectors,
with no environment to disagree about. Everything above the line may differ
between an edge worker and a native host; nothing below it may. See
[`39-decision-register.md`](39-decision-register.md) `D-17`.
