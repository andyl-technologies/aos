# RFC-0015 testing strategy

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
