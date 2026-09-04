# RFC-0019 implementation plan

This is the canonical task list for scratch OCI containers. Tasks are checked
only after their implementation, focused tests, broader regression gates, and
one adversarial review of the containing phase are complete.

## Status

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | Contracts and executable spikes | Complete |
| 1 | OCI types and deterministic Nix builders | Complete |
| 2 | The single `aos` image and runtime contract | Complete |
| 3 | Local `aos container` CLI | Complete |
| 4 | Hub OCI catalog, storage, and pull data plane | Complete (follow-ups open) |
| 5 | Upload, publication, and signed release roots | Complete |
| 6 | Connect API, administration CLI, and console | Complete |
| 7 | Retention, GC, operations, and rollout | Complete |
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

- [x] Record the architecture, locked decisions, and non-goals in RFC-0019.
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

- [x] Define `containers/aos.nix` as the sole registered image.
- [x] Take package roots from
  `systems.server.config.environment.systemPackages` without copying the list.
- [x] Assert exact package-root equality in pure evaluation.
- [x] Include no kernel, initrd, system toplevel, boot image, systemd PID 1, or
  host service graph.
- [x] Use the AOS release identity in OCI labels and `os-release`.

### Scratch filesystem

- [x] Render root and group identities deterministically.
- [x] Create `/tmp`, HOME, work, XDG, APM, profile, and Nix state directories
  with explicit modes.
- [x] Add CA bundle aliases and TLS environment.
- [x] Build a collision-checked PATH facade matching the golden package roots.
- [x] Omit runtime-owned hosts, hostname, and resolver files.
- [x] Do not declare `/nix` as a volume.

### Daemonless CLI and package management

- [x] Include the exact full `pkgs.aos` wrapper closure.
- [x] Embed closure registration and a single-user `nix.conf`.
- [x] Add an idempotent init executable that initializes/loads the local Nix
  database and execs argv without shell parsing.
- [x] Reconcile atomic GC roots for every baked golden package root before APM
  can run.
- [x] Set the explicit container runtime marker and leave `AOS_ROOT` unset.
- [x] Make read-only-store failures actionable.
- [x] Make container-incompatible system/boot/TPM operations fail explicitly
  without weakening their behavior on AOS hosts.
- [x] Document key, custom command, trust root, and SSH-agent mounts for APR.

### Runtime tests and review

- [x] Load the OCI archive with AOS-built containerd/nerdctl and run `aos`,
  `apm`, and `apr` help/version commands.
- [x] Execute representative commands whose helpers exercise bash, OpenSSL,
  Nix, Git/libgit2, and compression paths.
- [x] Install, query, execute, and remove a package from a local APM registry
  without a Nix daemon.
- [x] Restart the same container and verify package/profile state.
- [x] Run Nix GC and APM GC, then verify every baked root and representative
  baked command remains valid.
- [x] Verify a read-only run succeeds for baked commands and rejects mutation.
- [x] Run a manual Docker load/run compatibility smoke where Docker is
  available.
- [x] Complete one Phase-2 adversarial review and resolve blocking findings.

The Phase-2 adversarial review found three blocking issues: runtime-created
processes could bypass PID-1 initialization and read-only environment changes,
the VM package lifecycle pre-imported its NAR instead of proving a real cache
download, and an asserted target could mislabel bytes from a different package
set. Versioned filesystem readiness/read-only markers plus shared/exclusive
locking, a VM-local static cache with pre/post validity assertions, and strict
package-set/target equality resolve those findings. The same follow-up also
hardened facade admission against an extra duplicate provider. CA/DNS network
injection remains an explicit Phase-8 qualification item. No second review
round was used.

## Phase 3: Local `aos container` CLI

### Command structure

- [x] Add `aos container` without changing `aos image` semantics.
- [x] Dispatch non-build commands before unconditional `NixRunner` creation.
- [x] Implement definition `list` and `show` with stable human and JSON output.
- [x] Implement `build` with platform, output, archive-format, and remote-build
  options.
- [x] Generalize remote builds from package attributes to exact container
  output attributes.
- [x] Implement local layout/archive `inspect` with digest verification.
- [x] Implement platform selection for multi-platform indexes.
- [x] Implement daemonless `pull`, `push`, and build-plus-publish operations.
- [x] Reuse Hub profiles and explicit-argument precedence for authentication.
- [x] Never shell out to Docker or Podman for artifact operations.

### Tests and review

- [x] Test command parsing, JSON envelopes, path/reference ambiguity, platform
  selection, progress, cancellation, and credential redaction.
- [x] Test pull/push outside a repository and without Nix on PATH.
- [x] Test interrupted and resumed blob transfer.
- [x] Test digest mismatch before any tag update.
- [x] Run Rust unit/integration tests through `nix develop -c` with the shared
  worktree Cargo target.
- [x] Run the hermetic `pkgs.aos` build.
- [x] Complete one Phase-3 adversarial review and resolve blocking findings.

The Phase-3 adversarial review found ten blocking classes: implicit HTTP
redirects could escape credential and upload-origin policy; resumable local
state and final destinations were vulnerable to links, identity swaps, stale
blob leakage, and early `--force` deletion; cancellation and response bounds
did not cover in-flight I/O; `@tag` was accepted; nested platform selection and
published-index identity were incomplete; local verification reopened paths
unsafely; gzip processing stopped after one member; upload acknowledgements
could skip bytes; unrelated expired Hub profiles could block public pulls; and
Docker archive tags were not validated. Explicit redirect handling with
DNS-pinned nonlocal endpoints, held no-follow descriptors and owned state
markers, bounded cancellable streaming, digest-only `@` parsing, recursive
exact platform selection, exact publication results, multi-member gzip,
strict acknowledgements, origin-matched profiles, and validated Docker tags
resolve the findings. Malicious archive, symlink, hardlink, identity-race,
stale-blob, redirect, cancellation, hostile registry, and process-level
daemonless transfer tests freeze the fixes. No second review round was used.

## Phase 4: Hub OCI catalog, storage, and pull data plane

### Database and storage

- [x] Add forward migrations for repositories, blobs, repository links,
  manifests, descriptor edges, tags/history, release roots, publications,
  uploads, retention, leases, and GC generations.
- [x] Support SQLite, PostgreSQL, and MySQL with dialect tests, including a
  physical MariaDB v19-to-v20 upgrade fixture.
- [x] Store immutable objects below `oci/blobs/sha256/` in the registry bucket.
- [x] Charge quota once per registry digest.
- [x] Require repository linkage for private blob access.
- [x] Store bounded parsed catalog projections for manifests and descriptor
  graphs.
- [x] Preserve exact noncanonical manifest bytes admitted by the Phase-5 upload
  path rather than reconstructing them from parsed projections.

### Distribution pull and authentication

- [x] Implement `/v2/` discovery.
- [x] Implement blob `GET`/`HEAD`, ranges, conditional requests, and placement
  selection.
- [x] Implement manifest/index `GET`/`HEAD` with content negotiation.
- [x] Implement tag listing and OCI referrer discovery.
- [x] Implement Docker bearer challenges and short-lived repository/action
  scoped tokens.
- [x] Map Hub `Read` to pull and public visibility to anonymous pull while
  preserving route-level `hub_auth` requirements.
- [x] Add repository-aware native and Worker request sharding.

### Catalog integration

- [x] Add signed `containers/v1/index.json` parsing and validation.
- [x] Populate immutable release roots without overloading system image tables.
- [x] Keep old strict release readers compatible.
- [x] Add repository, tag, manifest, platform, layer, and provenance read models.

### Tests and review

- [x] Cover malformed manifests, excessive graphs, media negotiation, ranges,
  private digest probing, token audiences/actions, and unknown references.
- [x] Test native/Worker route parity and sharding.
- [x] Pull a cataloged fixture through the native Hub with the production OCI
  client and verify the exact resulting layout.
- [ ] Pull the production Nix-built `aos` image from a native local Hub and run
  it; this remains Phase-8 end-to-end qualification.
- [x] Run dialect, retained-control, API/capability, SSR privacy, native pull,
  Worker wasm, packaged Rust, and `checks.eval` gates.
- [x] Complete one Phase-4 adversarial review and resolve blocking findings.

The single Phase-4 adversarial review found no P0 issues. Its P1 findings were:
the MariaDB v19 release-tag text type could not satisfy the v20 binary release
foreign key; a public registry behind `hub_auth` could obtain an anonymous pull
token; a soft-deleted owning organization could still serve OCI; and a native
file-backed immutable object could be replaced by same-size bytes after catalog
admission. Numeric release identities plus a frozen physical v19 upgrade test,
route-policy-aware Hub authentication before token exchange and OCI bearer
authorization before lookup, an active-owner gate on every Distribution entry
point, and retained-descriptor hashing/snapshotting for immutable OCI paths
resolve those findings.

The P2 findings covered signed-root placement linearization, mutable public
catalog caching, and incomplete `Accept` matching. Signed release admission now
fences and transactionally rechecks the index, platform, evidence object, and
placement observations; public tag/referrer responses use `public, no-cache`;
and structured, case-insensitive `application/*` negotiation honors explicit
`q=0` exclusions. The physical fresh/upgrade SQL VM, native Distribution pull,
Worker wasm, retained-control/capability/privacy, 3,372-test packaged Rust, and
evaluation gates passed after these fixes. No second review round was used.

## Phase 5: Upload, publication, and signed release roots

Status: Complete. Broader administration, retention/GC, and final packaged
end-to-end qualification remain in Phases 6 through 8.

### Standard uploads

- [x] Implement upload `POST`, `PATCH`, status, final `PUT`, and cancellation.
- [x] Persist portable digest state and bounded staging sessions.
- [x] Verify digest and size before promotion into CAS storage.
- [x] Implement cross-repository mounts with source-pull/destination-push
  authorization.
- [x] Handle duplicate concurrent uploads idempotently.

### Manifests and tags

- [x] Implement manifest/index `PUT` and digest deletion.
- [x] Validate the closed descriptor graph, platform/config agreement, bounds,
  cycles, and placement completeness.
- [x] Implement mutable manual tag CAS and append-only history.
- [x] Make signed release tags immutable.
- [x] Advance a channel tag only after partition convergence.
- [x] Keep manual pushes visibly unverified until an AOS publication binds the
  digest.

### AOS publication

- [x] Add begin/query/commit/abort container publication operations.
- [x] Reuse placement-aware immutable-before-pointer mechanics.
- [x] Upload layers/configs before manifests and the index before tags.
- [x] Bind the exact index digest and provenance into signed release metadata.
- [x] Publish SBOM/source/license/provenance/signature referrers.
- [x] Enforce full-closure licensing and corresponding-source gates.
- [x] Implement `aos container push` and `aos container publish` end to end.

### Tests and review

- [x] Inject interruption at every upload and publication boundary.
- [x] Test tag races, stale resource versions, placement failures, and retry
  idempotency.
- [x] Prove a tag is never observable before the complete graph is durable.
- [x] Prove layer reuse causes one physical write and zero-byte mounts.
- [x] Complete one Phase-5 adversarial review and resolve blocking findings.

Phase 5 used one adversarial round for the Nix evidence boundary and one for
the transactional Hub publication section, as allowed for these distinct
larger sections. The Nix review found store-hardlink-dependent source archives,
incomplete runnable-index and closure-layer binding, insufficient output
override validation, and missing archive/JSON bounds. Hard-dereferenced source
archives with a no-hardlink assertion, exact one-platform child/blob and
ordered closure-prefix checks, strict realized-output override matching, and
bounded traversal-safe evidence assembly resolve those findings.

The transactional review found upload expiry and recovery gaps, resumable
writer reselection, losing-retry cleanup hazards, pre-admission manifest CAS
writes, cross-backend quota races, unsafe MySQL migration replay, artifact tags
pointing at their subjects, incomplete placement/channel convergence, missing
config-platform binding, and an unverified DSSE boundary. Durable cleanup and
completion leases, frozen binding revisions, attempt-unique staging keys,
validate-before-promotion admission, digest-scoped quota claims, forward-only
replay-safe session tables, artifact-root tags, complete object-by-placement
publication plans with 256-partition channel convergence, exact config-derived
platform projection, and DSSE/SSHSIG verification against the authenticated
release signer resolve them. Exact terminal operation keys also make response
loss replayable while conflicting commit/abort attempts fail closed. No second
review round was used for either section.

The final live SQL VM gate passed against SQLite, PostgreSQL 18, and MariaDB
11.4. It covers fresh schemas, the physical MariaDB v19-to-v21 upgrade, every
Phase-5 crash cut, concurrent migration startup, and concurrent first catalog
publication.

## Phase 6: Connect API, administration CLI, and console

### Connect API

- [x] Add a distinct `ContainerService`; do not extend `ImageService`.
- [x] Implement repository list/get/create/update/delete.
- [x] Implement tag list/get/resolve/tag/untag with resource versions.
- [x] Implement manifest, platform, layer, referrer, publication, and provenance
  inspection.
- [x] Implement retention get/set and define fail-closed GC plan/apply/status
  operations.
- [x] Enable GC plan/apply/status only with the complete Phase 7 deletion engine.
- [x] Update manual method maps, proto generation, capability manifests, route
  coverage, and retained-control fixtures.

### Administration CLI

- [x] Add `aos hub registry container` browsing commands.
- [x] Add repository and tag mutations with plan/apply, idempotency,
  confirmation hashes, and resource-version checks.
- [x] Add retention and fail-closed GC plan/apply commands.
- [x] Preserve the versioned Hub CLI JSON envelope and secret redaction.

### Console

- [x] Rename the existing navigation to "System images."
- [x] Add container repository, tag, digest, and platform pages.
- [x] Show copyable Docker/nerdctl/AOS pull commands from the exact ready OCI
  route rather than the control origin.
- [x] Show config, compressed/unpacked/shared sizes, and closure layer mapping.
- [x] Show package/release/channel provenance, verification, SBOM, source,
  licenses, signatures, and referrers.
- [x] Show publication health, tag history, and retention.
- [x] Show GC blockers and planned reclaimable bytes from the Phase 7 engine.
- [x] Keep multi-gigabyte uploads out of the browser.

### Tests and review

- [x] Cover API authorization, pagination, filtering, redaction, optimistic
  concurrency, and idempotency.
- [x] Cover native and Worker console SSR/interaction parity.
- [x] Cover public/private repository presentation without digest leakage.
- [x] Complete one Phase-6 adversarial review and resolve blocking findings.

Phase 6 used one adversarial review and found no P0 issues. The review found
that in-flight publication state was visible to ordinary registry readers,
v22 upgrade gates and retention backfill were stale, old image projections had
no reconciliation path, identical roots could not carry multiple release
identities, manual untag and console permission contracts disagreed with the
service, platform identity was incomplete, deletion versions were imprecise,
and signed snapshot changes did not invalidate cursors.

Publisher-only publication administration, explicit replay-safe v21-to-v22
migrations, fail-closed legacy retention preservation, durable exact-byte
projection reconciliation, release-qualified provenance, exact manual-tag CAS,
canonical `publish` UI gating, full OCI platform selectors, terminal deletion
versions, and atomic snapshot epoch advancement resolve those findings. Ready
route-derived pull references also keep copyable commands independent from the
control origin. Focused SQLite upgrade/crash/concurrency tests, complete SQL
translation for PostgreSQL and MySQL, native Connect and Distribution tests,
the signed APR publication E2E, console native/WASM checks, CLI contracts, and
Worker WASM compilation passed. No live PostgreSQL or MySQL runtime result is
claimed for this phase.

## Phase 7: Retention, GC, operations, and rollout

### Safe retention and GC

- [x] Capture a registry OCI mutation epoch and complete placement inventory.
- [x] Mark tags, signed roots, referrers, leases, and active uploads.
- [x] Traverse config/layer/child/subject/referrer edges.
- [x] Fail closed on missing edges, stale inventory, or epoch changes.
- [x] Apply grace periods and emit a reviewable plan.
- [x] Revalidate roots and exact placement identity before every deletion.
- [x] Tombstone and delete with digest/size/etag preconditions.
- [x] Release DB identity and quota only after all placements confirm deletion.
- [x] Block repository/registry deletion while tracked or untracked OCI bytes
  remain.

### Operations

- [x] Add bounded durable operations for upload expiry (`RecoverOciUploads`),
  catalog/projection reconciliation (`Reindex`), blob verification
  (`RefreshPublicationObject`), existing placement repair, provider inventory
  and capability probing (`InventoryOciProviders` and
  `ProbeOciConditionalDeletes`), and GC (`RunOciGc`).
- [x] Add metrics for logical bytes, physical bytes, reuse ratio, upload state,
  publication latency, placement health, and GC recovery.
- [x] Add alerts and operator runbooks for digest mismatch, stuck publication,
  stale inventory, placement loss, and failed conditional deletion.
- [x] Add compatibility documentation for Docker, Podman, nerdctl, and ORAS.
- [x] Add rollout flags that can independently enable pull, push, signed
  publication, UI administration, and GC.

### Tests and review

- [x] Exercise GC races with new tags, active uploads, topology changes,
  retention leases, and failed placement deletions.
- [x] Verify quota under duplicate pushes, mounts, deletion, and repair.
- [x] Test registry deletion only after purge and reconciliation.
- [x] Complete one Phase-7 adversarial review and resolve blocking findings.

### 2026-08-28 implementation checkpoint

The implemented GC path freezes the mutation epoch, hard roots, retention
policy, topology, complete provider inventory, placement and binding revisions,
delete-credential generation, and observed conditional-delete capability. Apply
revalidates those fences before tombstoning; bounded native and Worker jobs then
resume inventory, conditional deletion, and atomic catalog/quota finalization.
The Connect API, CLI, and no-SSR console expose reviewed plans, blockers, exact
counters, candidates, placement actions, and actor/idempotency/version-bound
maintenance requeue without exposing credential material.

The single Phase-7 adversarial review added bounded current-head provider
inventory, actor-bound reviewed conditional repair with durable terminal
evidence, and a separately reviewed registry purge fence with Begin, Abort,
Apply, and Status operations. Final registry deletion remains the existing
reviewed operation and is admitted only after a fresh complete post-fence
inventory proves every logical, provider, session, GC, and snapshot blocker is
zero. The review also tightened rollout information ordering, resumable
inventory progress, and low-cardinality operational metrics and alerts.

Focused descriptor, service, CLI, console, native, Worker, controller, provider,
migration, metrics/rule-contract, and WASM evidence is recorded with the
Phase-7 commit. The final remediation schedules cover late upload and
publication roots, tag-history and grace transitions, topology and credential
rotation, snapshot leases, failed and retried placement deletion, duplicate
digest admission, deterministic reservation reuse, two-placement accounting,
and post-fence purge reconciliation.

The frozen-tree qualification run passed the seven-package native compile; the
18-case generated Connect/ProtoJSON contract; the complete 20-case retained
control manifest; the 11-case native Distribution suite; the 8-case native
container-administration suite; alert-rule, metrics-exposition, and signed
publication tests; exact counter, provider identity, repair evidence, and purge
readiness projections; CLI and typed remote-path contracts; the 8-case native
console mutation suite; all 28 Worker tests; and Worker plus console
`wasm32-unknown-unknown` compilation. The database slice separately passed its
22-case focused GC suite, the reviewed purge-through-reconciliation schedule,
and PostgreSQL/MySQL dialect and migration-translation compilation. Provider
qualification separately passed bounded inventory, conditional-deletion,
cache-evidence, frozen-access, native, and Worker checks. Together these results
complete the Phase-7 race, quota, purge, and review qualification; the
production-image and VM end-to-end work remains in Phase 8.

## Phase 8: Native and VM end-to-end qualification

Slice-C evidence on 2026-08-29: a versioned 29-case OCI protocol transcript is
shared by native Hub and the deployable workerd/SQLite injected-provider
fixture. Native execution covers public/private Distribution delivery,
Basic-to-bearer exchange, uploads, tags, digests, referrers, and the
ContainerService publication/administration/GC read-plan surface. The Worker
fixture preserves the open-source workerd R2 boundary and requires physical GC
to remain blocker-gated. Its signed system-image qualification uploads the NAR
closure through `BinaryCacheService`, publishes a real provider inventory, and
uses the packaged `aos` to list, download, verify, extract, and byte-compare the
public image. Private-key-free `prepare-signature` and
`finalize-signature` porcelain now verifies an external SSHSIG over exact DSSE
PAE bytes and atomically emits the complete signed publication bundle. These
focused results do not by themselves complete the native runtime, VM, Docker,
or full-gate checklists below.

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
- [ ] Verify runtime-injected DNS/hosts files and HTTPS through the baked CA
  trust aliases from inside the scratch image.
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
