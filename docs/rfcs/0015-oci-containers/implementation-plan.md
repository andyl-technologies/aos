# RFC-0015 implementation plan

This is the canonical task list for scratch OCI containers. Tasks are checked
only after their implementation, focused tests, broader regression gates, and
one adversarial review of the containing phase are complete.

## Status

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | Contracts and executable spikes | Complete |
| 1 | OCI types and deterministic Nix builders | Complete |
| 2 | The single `aos` image and runtime contract | Not started |
| 3 | Local `aos container` CLI | Not started |
| 4 | Hub OCI catalog, storage, and pull data plane | Not started |
| 5 | Upload, publication, and signed release roots | Not started |
| 6 | Connect API, administration CLI, and console | Not started |
| 7 | Retention, GC, operations, and rollout | Not started |
| 8 | Native and VM end-to-end qualification | Not started |

## Review rule

Each phase is one larger section of work for review accounting. After its
implementation and local tests pass, run exactly one adversarial review focused
on violated invariants, unsafe assumptions, malformed inputs, race conditions,
and missing negative tests. Resolve every blocking finding before committing
the phase. Do not spend additional adversarial-review rounds on the same phase
unless its design changes materially.

Every phase is committed separately and pushed to `dplecki/aos-containers`.

## Phase 0: Contracts and executable spikes

### Design and inventory

- [x] Record the architecture, locked decisions, and non-goals in RFC-0015.
- [x] Define the single initial `aos` container and the meaning of golden-image
  parity.
- [x] Define Hub registry ownership, OCI repository ownership, deduplication
  scope, trust, tags, and channel behavior.
- [x] Define the daemonless APM/APR runtime contract and unsupported system
  operations.
- [x] Define the deterministic layer ABI and explicit reuse policy.
- [x] Define the native and VM test matrix.
- [x] Inventory every generated API/capability fixture changed by a new Hub
  service or route.
- [x] Freeze supported OCI and Docker media types and distribution error codes.
- [x] Choose bounded limits for manifest bytes, descriptor count, annotation
  bytes, graph depth, upload lifetime, and layer count.

### Spikes

- [x] Prove AOS GNU tar and gzip can emit the required stable layer bytes.
- [x] Build AOS containerd/runc/nerdctl and confirm privileged runtime execution
  belongs in the Nix VM gate; an unprivileged host containerd cannot create its
  ttrpc endpoint in the development sandbox.
- [x] Prove the current `pkgs.aos` closure can initialize a local Nix database
  and execute `apm` without a daemon.
- [x] Record host Docker availability and run an OCI/Docker compatibility smoke
  without adding a host-tool dependency to a Nix test.
- [x] Use AOS-built `jq` and coreutils for build-time canonical JSON and digest
  assembly, validated by shared Rust OCI types, avoiding a `pkgs.aos` cycle.
- [x] Add an executable Nix check for the golden layer vector, independently
  evaluated golden roots, daemonless DB initialization, and baked-root GC
  retention.

### Exit criteria

- [x] Pure evaluation proves `systems.server` package roots are available to a
  separate container evaluator without retaining the system toplevel.
- [x] Two independent hand-built spike archives have identical uncompressed and
  gzip-compressed SHA-256 digests.
- [x] One adversarial review is complete and all blocking Phase-0 findings are
  resolved.

The Phase-0 adversarial review identified seven blockers: missing GC roots,
incompatible PID-1/reaping promises, ambiguous Hub registry routing, an
incomplete artifact media allowlist, unauditable spike claims, an underspecified
layer byte ABI, and missing reference canonicalization. The final Phase-0
contracts and executable check resolve each finding; no second review round was
used.

## Phase 1: OCI types and deterministic Nix builders

### Shared OCI contracts

- [x] Add a dependency-light OCI types crate usable by native Hub, Worker,
  console, and CLI builds.
- [x] Document every public type and validate digests, media types, descriptors,
  platforms, references, annotations, and exact byte sizes.
- [x] Preserve unknown extension annotations while bounding their size.
- [x] Add canonical JSON serialization with ordered maps and no floating-point
  fields.
- [x] Add golden vectors for image config, manifest, index, descriptor, and
  Distribution error payloads.
- [x] Reject Docker schema 1 and freeze the accepted OCI/Docker schema 2 media
  type matrix.

### Nix builders

- [x] Factor structured closure inventory from `closure-info.nix` without
  weakening existing rootfs consumers.
- [x] Implement `mkClosureLayer { roots; subtractRoots; }`.
- [x] Implement the deterministic tar and gzip policy.
- [x] Compute and emit descriptor digest, compressed size, DiffID, uncompressed
  size, and closure inventory.
- [x] Implement `mkRootMetadataLayer` with collision-safe facade links and
  deterministic identities/modes.
- [x] Implement canonical image config and manifest assembly.
- [x] Implement OCI layout and deterministic OCI archive assembly.
- [x] Implement deterministic Docker archive conversion.
- [x] Implement multi-platform OCI index assembly without unpacking layers.
- [x] Ensure outputs are self-contained and do not retain input closures only
  because serialized store path names were reference-scanned.
- [x] Reuse the runtime closure audit for forbidden build/dev payloads and byte
  budgets.

### Evaluation and exports

- [x] Add the separate typed container module evaluator.
- [x] Reject base images, host roots, secrets, unsafe paths, duplicate layers,
  duplicate store paths, facade collisions, and invalid exec-form config.
- [x] Map AOS targets to OCI platforms and preserve AOS identity annotations.
- [x] Export `containerImages`, checks, and flake packages.
- [x] Enforce that only the `aos` definition is registered.

### Tests and review

- [x] Build equivalent layers and images under different derivation names and
  compare every output byte.
- [x] Audit tar ordering, modes, ownership, timestamps, links, and paths.
- [x] Verify compressed descriptors and uncompressed DiffIDs independently.
- [x] Verify changed app roots do not change unaffected canonical layers.
- [x] Run `nix-build -A checks.eval` and all new focused checks.
- [x] Complete one Phase-1 adversarial review and resolve blocking findings.

The Phase-1 adversarial review found four blockers: overlapping realized store
paths across layers, facade targets not proven present and executable, Nix/Rust
reference-parser drift, and premature package-management claims on the
intermediate image. Realized-inventory admission, closure-backed facade target
validation, shared reference vectors, and an explicitly disabled Phase-1
mutation capability resolve them. No second review round was used.

## Phase 2: The single `aos` image and runtime contract

### Golden-image parity

- [ ] Define `containers/aos.nix` as the sole registered image.
- [ ] Take package roots from
  `systems.server.config.environment.systemPackages` without copying the list.
- [ ] Assert exact package-root equality in pure evaluation.
- [ ] Include no kernel, initrd, system toplevel, boot image, systemd PID 1, or
  host service graph.
- [ ] Use the AOS release identity in OCI labels and `os-release`.

### Scratch filesystem

- [ ] Render root and group identities deterministically.
- [ ] Create `/tmp`, HOME, work, XDG, APM, profile, and Nix state directories
  with explicit modes.
- [ ] Add CA bundle aliases and TLS environment.
- [ ] Build a collision-checked PATH facade matching the golden package roots.
- [ ] Omit runtime-owned hosts, hostname, and resolver files.
- [ ] Do not declare `/nix` as a volume.

### Daemonless CLI and package management

- [ ] Include the exact full `pkgs.aos` wrapper closure.
- [ ] Embed closure registration and a single-user `nix.conf`.
- [ ] Add an idempotent init executable that initializes/loads the local Nix
  database and execs argv without shell parsing.
- [ ] Reconcile atomic GC roots for every baked golden package root before APM
  can run.
- [ ] Set the explicit container runtime marker and leave `AOS_ROOT` unset.
- [ ] Make read-only-store failures actionable.
- [ ] Make container-incompatible system/boot/TPM operations fail explicitly
  without weakening their behavior on AOS hosts.
- [ ] Document key, custom command, trust root, and SSH-agent mounts for APR.

### Runtime tests and review

- [ ] Load the OCI archive with AOS-built containerd/nerdctl and run `aos`,
  `apm`, and `apr` help/version commands.
- [ ] Execute representative commands whose helpers exercise bash, OpenSSL,
  Nix, Git/libgit2, and compression paths.
- [ ] Install, query, execute, and remove a package from a local APM registry
  without a Nix daemon.
- [ ] Restart the same container and verify package/profile state.
- [ ] Run Nix GC and APM GC, then verify every baked root and representative
  baked command remains valid.
- [ ] Verify a read-only run succeeds for baked commands and rejects mutation.
- [ ] Run a manual Docker load/run compatibility smoke where Docker is
  available.
- [ ] Complete one Phase-2 adversarial review and resolve blocking findings.

## Phase 3: Local `aos container` CLI

### Command structure

- [ ] Add `aos container` without changing `aos image` semantics.
- [ ] Dispatch non-build commands before unconditional `NixRunner` creation.
- [ ] Implement definition `list` and `show` with stable human and JSON output.
- [ ] Implement `build` with platform, output, archive-format, and remote-build
  options.
- [ ] Generalize remote builds from package attributes to exact container
  output attributes.
- [ ] Implement local layout/archive `inspect` with digest verification.
- [ ] Implement platform selection for multi-platform indexes.
- [ ] Implement daemonless `pull`, `push`, and build-plus-publish operations.
- [ ] Reuse Hub profiles and explicit-argument precedence for authentication.
- [ ] Never shell out to Docker or Podman for artifact operations.

### Tests and review

- [ ] Test command parsing, JSON envelopes, path/reference ambiguity, platform
  selection, progress, cancellation, and credential redaction.
- [ ] Test pull/push outside a repository and without Nix on PATH.
- [ ] Test interrupted and resumed blob transfer.
- [ ] Test digest mismatch before any tag update.
- [ ] Run Rust unit/integration tests through `nix develop -c` with the shared
  worktree Cargo target.
- [ ] Run the hermetic `pkgs.aos` build.
- [ ] Complete one Phase-3 adversarial review and resolve blocking findings.

## Phase 4: Hub OCI catalog, storage, and pull data plane

### Database and storage

- [ ] Add forward migrations for repositories, blobs, repository links,
  manifests, descriptor edges, tags/history, release roots, publications,
  uploads, retention, leases, and GC generations.
- [ ] Support SQLite, PostgreSQL, and MySQL with dialect tests.
- [ ] Store immutable objects below `oci/blobs/sha256/` in the registry bucket.
- [ ] Charge quota once per registry digest.
- [ ] Require repository linkage for private blob access.
- [ ] Preserve exact manifest bytes and store only bounded parsed projections.

### Distribution pull and authentication

- [ ] Implement `/v2/` discovery.
- [ ] Implement blob `GET`/`HEAD`, ranges, conditional requests, and placement
  selection.
- [ ] Implement manifest/index `GET`/`HEAD` with content negotiation.
- [ ] Implement tag listing and OCI referrer discovery.
- [ ] Implement Docker bearer challenges and short-lived repository/action
  scoped tokens.
- [ ] Map Hub `Read` to pull and public visibility to anonymous pull.
- [ ] Add repository-aware native and Worker request sharding.

### Catalog integration

- [ ] Add signed `containers/v1/index.json` parsing and validation.
- [ ] Populate immutable release roots without overloading system image tables.
- [ ] Keep old strict release readers compatible.
- [ ] Add repository, tag, manifest, platform, layer, and provenance read models.

### Tests and review

- [ ] Cover malformed manifests, excessive graphs, media negotiation, ranges,
  private digest probing, token audiences/actions, and unknown references.
- [ ] Test native/Worker route parity and sharding.
- [ ] Pull the `aos` image from a native local Hub and run it.
- [ ] Run dialect, retained-control, API/capability, and SSR privacy gates.
- [ ] Complete one Phase-4 adversarial review and resolve blocking findings.

## Phase 5: Upload, publication, and signed release roots

### Standard uploads

- [ ] Implement upload `POST`, `PATCH`, status, final `PUT`, and cancellation.
- [ ] Persist portable digest state and bounded staging sessions.
- [ ] Verify digest and size before promotion into CAS storage.
- [ ] Implement cross-repository mounts with source-pull/destination-push
  authorization.
- [ ] Handle duplicate concurrent uploads idempotently.

### Manifests and tags

- [ ] Implement manifest/index `PUT` and digest deletion.
- [ ] Validate the closed descriptor graph, platform/config agreement, bounds,
  cycles, and placement completeness.
- [ ] Implement mutable manual tag CAS and append-only history.
- [ ] Make signed release tags immutable.
- [ ] Advance a channel tag only after partition convergence.
- [ ] Keep manual pushes visibly unverified until an AOS publication binds the
  digest.

### AOS publication

- [ ] Add begin/query/commit/abort container publication operations.
- [ ] Reuse placement-aware immutable-before-pointer mechanics.
- [ ] Upload layers/configs before manifests and the index before tags.
- [ ] Bind the exact index digest and provenance into signed release metadata.
- [ ] Publish SBOM/source/license/provenance/signature referrers.
- [ ] Enforce full-closure licensing and corresponding-source gates.
- [ ] Implement `aos container push` and `aos container publish` end to end.

### Tests and review

- [ ] Inject interruption at every upload and publication boundary.
- [ ] Test tag races, stale resource versions, placement failures, and retry
  idempotency.
- [ ] Prove a tag is never observable before the complete graph is durable.
- [ ] Prove layer reuse causes one physical write and zero-byte mounts.
- [ ] Complete one Phase-5 adversarial review and resolve blocking findings.

## Phase 6: Connect API, administration CLI, and console

### Connect API

- [ ] Add a distinct `ContainerService`; do not extend `ImageService`.
- [ ] Implement repository list/get/create/update/delete.
- [ ] Implement tag list/get/resolve/tag/untag with resource versions.
- [ ] Implement manifest, platform, layer, referrer, publication, and provenance
  inspection.
- [ ] Implement retention get/set and GC plan/apply/status operations.
- [ ] Update manual method maps, proto generation, capability manifests, route
  coverage, and retained-control fixtures.

### Administration CLI

- [ ] Add `aos hub registry container` browsing commands.
- [ ] Add repository and tag mutations with plan/apply, idempotency,
  confirmation hashes, and resource-version checks.
- [ ] Add retention and GC plan/apply operations.
- [ ] Preserve the versioned Hub CLI JSON envelope and secret redaction.

### Console

- [ ] Rename the existing navigation to "System images."
- [ ] Add container repository, tag, digest, and platform pages.
- [ ] Show copyable Docker/nerdctl/AOS pull commands.
- [ ] Show config, compressed/unpacked/shared sizes, and closure layer mapping.
- [ ] Show package/release/channel provenance, verification, SBOM, source,
  licenses, signatures, and referrers.
- [ ] Show publication health, tag history, retention, GC blockers, and planned
  reclaimable bytes.
- [ ] Keep multi-gigabyte uploads out of the browser.

### Tests and review

- [ ] Cover API authorization, pagination, filtering, redaction, optimistic
  concurrency, and idempotency.
- [ ] Cover native and Worker console SSR/interaction parity.
- [ ] Cover public/private repository presentation without digest leakage.
- [ ] Complete one Phase-6 adversarial review and resolve blocking findings.

## Phase 7: Retention, GC, operations, and rollout

### Safe retention and GC

- [ ] Capture a registry OCI mutation epoch and complete placement inventory.
- [ ] Mark tags, signed roots, referrers, leases, and active uploads.
- [ ] Traverse config/layer/child/subject/referrer edges.
- [ ] Fail closed on missing edges, stale inventory, or epoch changes.
- [ ] Apply grace periods and emit a reviewable plan.
- [ ] Revalidate roots and exact placement identity before every deletion.
- [ ] Tombstone and delete with digest/size/etag preconditions.
- [ ] Release DB identity and quota only after all placements confirm deletion.
- [ ] Block repository/registry deletion while tracked or untracked OCI bytes
  remain.

### Operations

- [ ] Add bounded durable jobs for upload expiry, catalog reconciliation, blob
  verification, placement repair, and GC.
- [ ] Add metrics for logical bytes, physical bytes, reuse ratio, upload state,
  publication latency, placement health, and GC recovery.
- [ ] Add alerts and operator runbooks for digest mismatch, stuck publication,
  stale inventory, placement loss, and failed conditional deletion.
- [ ] Add compatibility documentation for Docker, Podman, nerdctl, and ORAS.
- [ ] Add rollout flags that can independently enable pull, push, signed
  publication, UI administration, and GC.

### Tests and review

- [ ] Exercise GC races with new tags, active uploads, topology changes,
  retention leases, and failed placement deletions.
- [ ] Verify quota under duplicate pushes, mounts, deletion, and repair.
- [ ] Test registry deletion only after purge and reconciliation.
- [ ] Complete one Phase-7 adversarial review and resolve blocking findings.

## Phase 8: Native and VM end-to-end qualification

### Native Hub

- [ ] Launch the AOS-built native Hub with local database and object storage.
- [ ] Create an AOS registry and its `aos` OCI repository.
- [ ] Publish the Nix-built multi-platform `aos` image.
- [ ] Pull by tag and digest with public and private authentication.
- [ ] Load and run the pulled artifact with AOS-built container tooling.
- [ ] Install and run an APM package without a Nix daemon.
- [ ] Exercise tag promotion, signed release verification, retention, and GC.

### Hub Nix VM checks

- [ ] Add a focused Hub OCI VM check using existing Hub service modules.
- [ ] Publish through the guest/native Hub path rather than a mock transport.
- [ ] Pull, load, and run `aos`, `apm`, and `apr` inside the VM runtime.
- [ ] Add private auth, range/resume, digest mismatch, multi-platform selection,
  atomic tag visibility, shared-layer, and GC negative coverage.
- [ ] Keep all harness dependencies AOS-built.

### Full gates

- [ ] Run focused Rust nextest suites through the Nix dev environment.
- [ ] Run `nix-build -A checks.eval`.
- [ ] Build every new OCI and Docker artifact twice.
- [ ] Build the hermetic `pkgs.aos`, native Hub, Worker, console, and dialect
  checks.
- [ ] Run all new native Hub and Nix VM checks.
- [ ] Run existing boot, package-registry, system-image, Hub publication,
  topology, authorization, and GC regression suites.
- [ ] Run the licensing and source-retention gates.
- [ ] Run manual Docker load/pull/run compatibility tests where Docker is
  available and record exact versions/results.
- [ ] Complete one final Phase-8 adversarial review and resolve all blocking
  findings.

### Delivery

- [ ] Update RFC status and canonical user/operator documentation.
- [ ] Confirm every phase commit is pushed to `origin/dplecki/aos-containers`.
- [ ] Create a pull request with architecture summary, migration/rollout notes,
  security and compatibility boundaries, and complete test evidence.
