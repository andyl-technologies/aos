# RFC-0019 testing strategy

The container feature crosses deterministic build output, runtime filesystem
semantics, package management, HTTP distribution, tenancy, storage placement,
signed releases, and garbage collection. Tests are layered so a failure names
the smallest responsible boundary.

## Pure evaluation

Evaluation checks cover:

- exactly one registered definition named `aos`;
- package-root parity with the production server golden image;
- supported AOS-to-OCI platform mapping;
- valid layer names and ordering;
- no duplicate roots or facade collisions;
- no base image or arbitrary filesystem import;
- exec-form entrypoint and command;
- users, groups, modes, and paths;
- absence of secret-bearing schema fields;
- layer and closure budgets;
- incompatible CLI/package-manager/runtime settings.

These join `checks.eval` so a definition contract regression fails before
building container bytes.

## Byte reproducibility and conformance

Build the same layer and image from equivalent inputs with different derivation
names. Compare:

- compressed layer bytes;
- descriptor JSON;
- DiffID and blob digest records;
- image config;
- platform manifest;
- multi-platform index;
- OCI layout metadata;
- OCI archive;
- Docker archive;
- closure and provenance manifests.

Audit every tar member for ordering, normalized timestamps, numeric ownership,
modes, link targets, duplicate paths, whiteouts, host paths, and forbidden
development outputs. Independently recompute compressed digests and
uncompressed DiffIDs.

Build two synthetic manifests sharing a canonical layer and prove the shared
blob digest is byte-identical while only the application delta, config, and
manifest differ.

The production coordinator is exposed as
`packages.<system>.container-aos-index`. Unlike the system-local compatibility
attribute `containerImages.aos.ociIndex`, that flake package always contains
exactly `linux/amd64` and `linux/arm64`; evaluation never substitutes the local
platform when one target cannot be built. The repository's toolchain performs
the reviewed x86_64-to-aarch64 transition and schedules post-cross stages on an
`x86_64-linux` builder, where target tools execute through the configured QEMU
binfmt handler. Building `checks.<system>.container-multi-platform` therefore
requires that handler (or an equivalent builder configuration); a declared
`extra-platforms` value alone is not evidence that execution works. Flake
evaluation and check discovery remain total without executing target binaries.
The experimental profile has parallel `container-aos-testing-*` outputs built
from `systems.aos-testing.build.defaultContainer`, including its testing-only
registry seed and warning.

Every production platform is assembled twice from equivalent inputs under
independent derivation names. The qualification compares the OCI layout and
archive, Docker archive, single-platform index, and evidence graph. The
coordinator then independently recomposes and compares the two-platform index,
combined evidence, and external-signing input bundle. The unsigned bundle is
exposed as `packages.<system>.container-aos-publication-inputs` and contains:

- `oci-layout/` and `image.oci.tar`, the exact coordinated image subject;
- `evidence-layout/` and `evidence.oci.tar`, the unsigned OCI evidence graph;
- `signature-input.json`, `signing-request.json`, and
  `publication-roots.json`.

It deliberately does not contain `container-release.json`. An external signer
must add the DSSE object to a final layout and produce the canonical signed
release sidecar. This keeps private material and claims of verified publication
outside Nix while giving the signer and VM qualification exact production
bytes. The focused evaluation surfaces are:

```text
nix eval path:.#packages.x86_64-linux.container-aos-index.drvPath --raw
nix eval path:.#checks.x86_64-linux.container-multi-platform.drvPath --raw
nix build path:.#checks.x86_64-linux.container-multi-platform --no-link -L
```

The private-key-free finalization sequence is:

```text
aos container prepare-signature PUBLICATION_INPUTS --output container-signature.pae
ssh-keygen -Y sign -f EXTERNAL_KEY -n aos-container-signature-dsse-v1 container-signature.pae
aos container finalize-signature PUBLICATION_INPUTS \
  --signer 'NAME:Ed25519:BASE64_SSH_KEY_BLOB' \
  --signature container-signature.pae.sig \
  --output FINAL_BUNDLE
```

Only the external signer receives `EXTERNAL_KEY`. Finalization verifies the
SSHSIG against the exact signer identity and PAE before creating staging state,
validates the full graph, and uses a same-directory no-replace rename. Its fixed
outputs are `FINAL_BUNDLE/layout`, `image.oci.tar`,
`container-release.json`, and `signature-input.json`.

## Local runtime

The hermetic runtime gate uses AOS-built containerd, runc, and nerdctl inside a
VM or isolated test root. It imports the archive and verifies:

- image config, argv, environment, user, working directory, and exit status;
- execution of dynamically linked AOS programs;
- CA trust and HTTPS;
- runtime-injected DNS/hosts behavior;
- writable and read-only root behavior;
- direct signal delivery to the exec-only PID 1 contract;
- documented absence of generic orphan reaping unless the runtime supplies an
  init process;
- absence of a Nix daemon and daemon socket;
- local Nix database initialization and baked-path validity;
- baked package roots surviving both Nix GC and APM GC;
- `aos`, `apm`, and `apr` multicall dispatch;
- user-scope APM install/query/execute/remove against a local registry;
- same-container restart behavior;
- explicit refusal of unsupported system/boot operations.

A separate manual compatibility check uses Docker load/run and Hub pull when a
local Docker daemon is available. Docker is not introduced as a Nix or CI host
dependency; the hermetic compatibility gate remains AOS-built nerdctl against
containerd.

The Phase-2 focused gate is `checks.container.runtime`. It executes the exact
production init transaction against a rooted local store, checks marker and
lock bytes/modes, repairs interrupted GC-root state, runs GC, audits the golden
facade and collision manifest, inspects production metadata/config, excludes
boot artifacts, and proves all published image outputs retain no Nix input
references. Rust unit tests independently cover PID-1 marker matching, stale
marker refusal, persisted and directly probed read-only state, package command
classification, and top-level host-command admission.

`tests/fleet/container-runtime.nix` is the privileged Phase-2 execution gate.
It loads the production Docker archive into AOS-built containerd, races a named
runtime `exec` against initialization, checks the exact current-PID readiness
marker and GC roots, runs direct Nix GC and APM GC, and exercises a fully
read-only named container. Its APM fixture is deliberately absent from the
container store before install: APR generates a VM-local static cache, the
container downloads its narinfo and NAR over HTTP, and the test proves store
validity, execution, restart persistence, and removal afterward. The exact
command is:

```text
nix build path:.#checks.x86_64-linux.fleet-container-runtime --no-link -L
```

The Phase-0 compatibility spike used Docker Engine 29.7.2 on `linux/amd64`.
Docker loaded a hand-assembled OCI archive containing the complete 66-path
`pkgs.aos` closure and ran `aos 0.1.0`. The equivalent AOS-built runtime
packages also build locally; execution is kept in the privileged VM gate
because an unprivileged host containerd cannot create its ttrpc endpoint in the
development sandbox.

## OCI parser and protocol

Unit, property, and integration tests cover:

- valid OCI image, index, config, artifact, and Docker schema 2 bodies;
- exact-byte preservation and digest verification;
- malformed digest/reference/media-type/platform input;
- size overflow and configured byte/count/depth limits;
- duplicate or cyclic descriptor graphs;
- config/manifest platform disagreement;
- unsupported schema 1 input;
- content negotiation and referrer filtering;
- Distribution error code and status mapping;
- upload ranges, portable hash state, finalization, cancellation, expiry, and
  retry;
- duplicate concurrent upload and cross-repository mount behavior.

The Phase-3 native client gate runs `aos-oci` layout and loopback Distribution
tests plus process-level `aos container` tests through the AOS development
environment. It covers safe archive ingestion, complete descriptor and DiffID
verification, multi-member gzip, nested exact-platform selection, resumable
range pull and chunked push, immutable-before-tag ordering, published digest
identity, in-flight cancellation, bounded bodies, redirect and Bearer-realm
confinement, hostile acknowledgements, private state ownership, symlink and
hardlink refusal, destination identity races, stale-blob exclusion, and
credential redaction. A process fixture clears `PATH`, runs outside an AOS
checkout, pulls a complete image, and pushes it to a second repository through
the CLI, proving transfer commands neither discover Nix nor invoke a container
daemon.

The focused commands are:

```text
nix develop -c cargo test --manifest-path crates/Cargo.toml -p aos-oci --tests
nix develop -c cargo test --manifest-path crates/Cargo.toml -p aos --test container_cli
nix develop -c cargo test --manifest-path crates/Cargo.toml -p aos --test container_cli_transfer
```

## Hub native integration

Native tests use the real Hub service, database implementation, surface write
port, placement selection, and router. They cover:

- public and private repository creation;
- repository-scoped bearer challenge/token exchange;
- anonymous public pull and denied private digest probing;
- push and pull by tag and digest;
- immutable release tag and mutable manual tag semantics;
- tag compare-and-swap history;
- immutable-before-pointer placement ordering;
- interruption at every publication boundary;
- one physical write for a blob referenced by multiple repositories;
- quota reservation, duplicate push, mount, deletion, and repair;
- signed sidecar indexing and provenance projection;
- native/Worker request and response parity;
- repository-aware Worker sharding;
- Connect API authorization and idempotency;
- console SSR privacy and capability handling.

Every database migration and query is exercised by the existing SQLite,
PostgreSQL, and MySQL dialect gate.

Native and Worker qualification share
`crates/aos-hub/tests/fixtures/oci-protocol-parity-v1.json`. The transcript
covers Distribution discovery and token exchange, anonymous public and denied
private reads, Basic-to-bearer private authentication, manifest/blob/tag and
referrer reads, upload completion, and ContainerService repository, tag,
manifest, publication, retention, and GC calls. The open-source workerd fixture
uses SQLite plus its injected provider; it requires GC planning and blocker
status to fail closed and deliberately does not claim R2 physical deletion.

The native transcript has an opt-in bounded hold for manual Docker
qualification. It writes machine-readable public/private tag and digest
references plus Docker-compatible credentials while listening only on
`127.0.0.1`:

```text
AOS_OCI_TRANSCRIPT_HOLD_SECONDS=900 \
AOS_OCI_TRANSCRIPT_ENDPOINTS_FILE=/tmp/aos-oci-endpoints.json \
nix develop -c cargo test --manifest-path crates/Cargo.toml \
  -p aos-hub --test oci_distribution \
  native_oci_protocol_transcript_matches_worker_v1 -- --exact --nocapture
```

The hold is zero by default and capped at 1,800 seconds. Hermetic tests never
invoke a host Docker daemon.

## Hub Nix VM integration

The focused VM check boots an AOS system with the native Hub and AOS-built
container runtime. It then:

1. provisions a local AOS registry and OCI repository;
2. publishes the Nix-built `aos` image through its real Hub endpoints;
3. verifies that tags remain absent until the complete graph is committed;
4. pulls by tag and immutable digest;
5. imports and runs the image;
6. executes `aos`, `apm`, and `apr`;
7. installs and runs a package from the local APM registry without a daemon;
8. validates private auth, range/resume, and digest-mismatch failures;
9. reuses a layer through a second synthetic manifest without registering a
   second AOS container definition;
10. deletes mutable roots, runs GC plan/apply, and proves retained release
    roots and shared blobs survive.

The shared-layer fixture is protocol test data, not a second registered image.

## Garbage-collection safety

GC tests inject mutations between every planning and deletion boundary:

- new tag after snapshot;
- signed release arrival;
- new referrer;
- active or renewed upload lease;
- placement topology change;
- stale object inventory;
- missing descriptor edge;
- changed etag/size/digest;
- one-placement deletion failure;
- retry after partial deletion;
- registry deletion racing purge.

Every ambiguous state aborts or retains data. Quota is released only after all
required placements confirm the exact object is absent.

## Regression gates

The final qualification includes existing checks for:

- pure evaluation and system structure;
- golden system image budgets;
- package registry and binary cache behavior;
- signed system-image delivery;
- Hub topology, route capability, authorization, publication, placement, and
  GC behavior;
- native and Worker parity;
- console privacy;
- contributor authorization and licensing boundaries;
- full-closure source retention, including patched-QEMU policy.

Container terminology and routes must not change the existing system-image or
native package-sandboxing contracts.
