# Implementation task ledger

This ledger is the durable execution record for RFC-0021. A checked task has
passed its named tests and names the implementing commit. Commits may complete
several adjacent tasks, but a task is never checked merely because scaffolding
exists. Phase gates depend on every task in the phase unless the RFC records an
explicitly reviewed scope change.

Task identifiers are stable. Dependencies in parentheses name tasks that must
land first; `P0` probes may proceed in parallel with portable model work, but
they gate any affected runtime backend.

## P0: executable platform probes

- [ ] **SBX-P0-01** Upgrade systemd to 259.8, rebase AOS patches, and pass its
  package and VM tests.
- [ ] **SBX-P0-02** Enable and test FUSE passthrough and fs-verity kernel
  configuration on x86_64 and aarch64 (`SBX-P0-01`).
- [x] **SBX-P0-03** Check in architecture-neutral probes for pidfds,
  `openat2`, the new mount API, `statmount`, and `listmount`.
- [ ] **SBX-P0-04** Resolve libseccomp syscall support and test the nspawn
  pre-PID1 argument-filter patch (`SBX-P0-01`, `SBX-P0-03`).
- [ ] **SBX-P0-05** Prove user namespaces, prepared network-namespace entry,
  payload leader discovery, internal reboot, fixed unit properties, and
  `--settings=no` in an AOS VM (`SBX-P0-01`, `SBX-P0-04`).

  The checked-in `sandbox-nspawn-platform-proof` VM test is the first
  executable evidence slice for `SBX-P0-04` and `SBX-P0-05`. It boots the exact
  packaged nspawn with the compiled payload profile, verifies the filter on
  guest PID 1 and an independently started service, exercises argument-aware
  syscall outcomes, checks the explicit private-user map, proves inheritance
  of a service-manager-selected default-drop network namespace, and places a
  hostile matching `.nspawn` file behind `--settings=no`. The test emits the
  versioned `aos.sandbox.nspawn-platform-proof/v1` JSON record even on a failed
  capability assertion.

  The current x86_64 qualification passes at
  `/nix/store/69n613487p93gz9zhv4g6lrrhiy4rh7h-aos-fleet-test-sandbox-nspawn-platform-proof-0`.
  It reaches payload startup in the prepared namespace, observes the payload
  leader, and completes two internal reboots with namespace generations 2 and
  3. This is runtime evidence for those platform contracts, but its source
  snapshot is `e0f4e011` plus the initial uncommitted allocation work rather
  than this increment's final integrated tree. `SBX-P0-04` and `SBX-P0-05`
  remain open pending the aarch64 qualification and the remaining complete
  production transient-unit, cgroup-identity, and integration gates.
- [ ] **SBX-P0-06** Prove the tc-BPF `CLOCK_BOOTTIME` lease gate fails closed
  across daemon death and host suspend/resume (`SBX-P0-05`).
- [ ] **SBX-P0-07** Package OpenZFS 2.4 and prove snapshot, hold, clone, quota,
  send/receive, and idmapped-mount behavior.
- [ ] **SBX-P0-08** Prove immutable fs-verity and read-only ZFS publication,
  passthrough, and crash recovery (`SBX-P0-02`, `SBX-P0-07`).
- [ ] **SBX-P0-09** Prove strict physical Nix-store domains and document the
  untrusted client or narrowing-proxy contract.
- [ ] **SBX-P0-10** Select and test enforcing host MAC profiles for every
  broker, helper, supervisor, and guardian.
- [ ] **SBX-P0-11** Record native-mount and candidate-FUSE latency,
  throughput, memory, OOM, and page-cache baselines.
- [ ] **SBX-P0-12** Prove the OpenSSH forced-command execution plane and all
  forwarding denials; otherwise leave execution disabled.
- [ ] **SBX-P0-13** Publish the checked-in feature matrix and baseline report
  consumed by placement capability discovery (`SBX-P0-01`..`SBX-P0-12`).

## P1: portable model and protocols

- [x] **SBX-CORE-01** Add the `aos-sandbox-core` crate with documented modules,
  feature-independent portable dependencies, and hermetic package inclusion
  (`0ddad351c`).
- [x] **SBX-CORE-02** Implement typed resource IDs, node IDs, generations,
  assignment epochs, revisions, and incarnations (`SBX-CORE-01`;
  `0ddad351c`).
- [x] **SBX-CORE-03** Implement desired and observed sandbox, operation,
  attachment, snapshot, and assignment state machines (`SBX-CORE-02`;
  `a33eac266`).
- [x] **SBX-CORE-04** Implement resource ceilings, reservations, aggregate
  ancestry accounting, and overflow-safe admission math (`SBX-CORE-02`;
  `4c849dc51`).
- [x] **SBX-CORE-05** Implement capability verbs, selectors, attenuation,
  delegation depth, expiry, and deny-by-default evaluation (`SBX-CORE-02`;
  `ce67b873f`).
- [x] **SBX-CORE-06** Implement complete sandbox spec, policy, ancestry,
  placement, environment, view, attachment, tree, snapshot, trust, and
  signature data models (`SBX-CORE-02`; `28073bb1c..7a3f31bbe`).
- [x] **SBX-CORE-07** Implement the canonical portable CBOR profile with
  bounds, duplicate-key rejection, canonical map ordering, and domain-separated
  digests (`SBX-CORE-06`; `d53ea5e7e..bfdaf2faa`).
- [x] **SBX-CORE-08** Implement descriptor, media-type, feature, and protocol
  registries with unknown-required-feature rejection (`SBX-CORE-06`;
  `d99883388`).
- [x] **SBX-CORE-09** Implement signing and trust-envelope verification over
  canonical bytes (`SBX-CORE-07`, `SBX-CORE-08`; `9b0864f03`).
- [x] **SBX-CORE-10** Make all RFC golden vectors and negative decoder vectors
  executable tests (`SBX-CORE-07`, `SBX-CORE-09`; `8065b4eff`).
- [x] **SBX-CORE-11** Add state-machine, attenuation, accounting, canonicality,
  and fencing property tests (`SBX-CORE-03`..`SBX-CORE-09`; `c493178f5`).
- [x] **SBX-API-01** Add complete `aos.sandbox.v1` protobuf resource and error
  messages to `aos-proto` (`SBX-CORE-06`; `e8ac32d7c`).
- [x] **SBX-API-02** Add create/get/list/update/delete, lifecycle, execution,
  view, attachment, snapshot, and descendant RPCs (`SBX-API-01`;
  `d7ac92b03`).
- [x] **SBX-API-03** Add resumable watch cursors, operation resources,
  idempotency keys, and compatibility fixtures (`SBX-API-02`;
  `37dde6aee`).
- [x] **SBX-BPROTO-01** Define bounded, fixed local host, storage, mount,
  network, guardian, and guest-agent protocol schemas (`SBX-CORE-08`;
  `af419c775`).
- [x] **SBX-BPROTO-02** Implement descriptor-role and peer-credential
  validation with malformed-message fuzz targets (`SBX-BPROTO-01`).
- [x] **SBX-BPROTO-03** Simulate multi-node assignment and ownership-lease
  fencing, including stale coordinator and partition cases (`SBX-CORE-03`).
- [ ] **SBX-BPROTO-04** Implement the local broker session protocol: bounded
  version and required-feature negotiation, closed method envelopes, exact
  descriptor-role tables, signed audience-specific authorization plans,
  ownership leases, response ceilings, and observe/inventory dispatch
  (`SBX-BPROTO-01`..`SBX-BPROTO-03`).

## P2: durable control and privilege boundaries

- [x] **SBX-JRN-01** Implement checksummed, versioned desired-state and
  operation journal records with atomic durability rules (`SBX-CORE-03`;
  `addc42e92`).
- [x] **SBX-JRN-02** Implement idempotency indexing, transactions, replay,
  compaction, and bounded corruption recovery (`SBX-JRN-01`; `addc42e92`).
- [x] **SBX-CTRL-01** Implement the unprivileged single-node reconciler and
  effect ledger (`SBX-JRN-02`, `SBX-BPROTO-01`; `8eb2d4ee8`).
- [x] **SBX-CTRL-02** Add crash injection at every record/effect boundary and
  prove convergence (`SBX-CTRL-01`; `ec3a23d4f`).
- [ ] **SBX-CTRL-03** Implement and package the unprivileged node controller,
  public client service, broker catalog publisher, assignment-plan compiler,
  and production reconciler loop (`SBX-CTRL-02`, `SBX-BPROTO-04`).
- [x] **SBX-SD-01** Extend `aos-systemd` with typed transient sandbox unit,
  cgroup, freeze/thaw, leader, and observation operations (`d1e40ea28`).
- [x] **SBX-LINUX-01** Add safe, owned pidfd, namespace FD, `openat2`, mount FD,
  idmap, `statmount`, and `listmount` wrappers (`SBX-P0-03`; `362732f96`).
- [ ] **SBX-HOST-01** Implement the root-only fixed host broker, one-shot
  workers, complete session dispatch, and authoritative runtime inventory
  (`SBX-BPROTO-04`, `SBX-SD-01`, `SBX-LINUX-01`).
- [ ] **SBX-STOR-01** Implement the root-only fixed storage broker with opaque
  handles and typed ZFS verbs (`SBX-BPROTO-04`, `SBX-P0-07`).
- [ ] **SBX-MOUNT-01** Implement the root-only descriptor mount broker and
  short-lived namespace helper with durable handle identity and authoritative
  mount inventory (`SBX-BPROTO-04`, `SBX-LINUX-01`).
- [ ] **SBX-NET-01** Implement the root-only typed network broker and fixed
  default-drop lease gate (`SBX-BPROTO-04`, `SBX-P0-06`).
- [ ] **SBX-GUARD-01** Implement the per-assignment ownership-lease guardian
  with fail-stop systemd and network coupling (`SBX-HOST-01`, `SBX-NET-01`).
- [ ] **SBX-BOUND-01** Add MAC, seccomp, privilege, hostile-parser, and residual
  resource inventory tests for every boundary (`SBX-HOST-01`..`SBX-GUARD-01`).

## P3: bootable runtime and execution

- [ ] **SBX-RT-01** Add the sandbox-root builder, guest module, seed image, and
  independently packaged guest agent.
- [ ] **SBX-RT-02** Implement workspace/root allocation, subordinate identity
  allocation, quotas, and incarnation metadata (`SBX-STOR-01`).
- [ ] **SBX-RT-03** Implement prepared private networking and default-drop veth
  setup (`SBX-NET-01`).
- [ ] **SBX-RT-04** Implement the nspawn backend and fixed transient unit
  compilation without machined authority (`SBX-RT-01`..`SBX-RT-03`).
- [ ] **SBX-RT-05** Implement readiness, authenticated forced-command
  execution, terminal resize, signals, exit observation, and audit linkage
  (`SBX-P0-12`, `SBX-RT-04`).
- [ ] **SBX-RT-06** Reconcile internal reboot, PID 1 restart, daemon restart,
  OOM, cgroup, and device-policy transitions (`SBX-CTRL-01`, `SBX-GUARD-01`).
- [ ] **SBX-RT-07** Pass create/start/execute/stop/delete VM tests as an
  unprivileged client with machined disabled (`SBX-RT-01`..`SBX-RT-06`).

## P4: native views and sandbox hierarchy

- [ ] **SBX-VIEW-01** Implement durable source handles, immutable view
  revisions, attachment objects, destination slots, and leases.
- [ ] **SBX-VIEW-02** Compile and install detached idmapped native mounts using
  only descriptors (`SBX-VIEW-01`, `SBX-MOUNT-01`).
- [ ] **SBX-VIEW-03** Implement atomic attachment replacement, post-attach
  verification, detach, revocation, and reboot replay (`SBX-VIEW-02`).
- [ ] **SBX-VIEW-04** Implement crash-consistent workspace snapshot manifests
  for stable descendant inspection (`SBX-STOR-01`, `SBX-VIEW-01`).
- [ ] **SBX-TREE-01** Implement parent/child creation, cycle prevention,
  explicit inspection grants, and descendant authority attenuation
  (`SBX-CORE-04`, `SBX-CORE-05`).
- [ ] **SBX-TREE-02** Enforce aggregate ancestry reservations and placement
  affinity without ambient ancestor access (`SBX-TREE-01`).
- [ ] **SBX-VIEW-05** Pass live/stable inspection, replacement, race, reboot,
  and hard-revocation VM tests (`SBX-VIEW-02`..`SBX-TREE-02`).

## P5: environments, Git, and shared caches

- [ ] **SBX-ENV-01** Implement immutable project-environment generations,
  activation transactions, execution pinning, and GC roots.
- [ ] **SBX-ENV-02** Implement read-only Nix-store presentation and the
  constrained build capability (`SBX-P0-09`, `SBX-VIEW-03`).
- [ ] **SBX-CACHE-01** Implement cache disclosure domains, immutable blob
  admission, transactional publication, quotas, pins, eviction, and scrubbing.
- [ ] **SBX-CACHE-02** Prove cross-domain non-disclosure and same-domain backing
  inode/page-cache sharing (`SBX-CACHE-01`, `SBX-P0-08`).
- [x] **SBX-PUB-01** Implement assignment-independent project publisher plans,
  canonical codecs, dedicated signature purpose, pinned verification, and
  compatibility/rejection vectors (`769028c30`; part of `SBX-CACHE-01`).
- [ ] **SBX-PUB-02** Implement controller-resolved challenge-bound admission,
  the exact request-commitment preimage, retained completion permits, and atomic
  reservation/residency accounting; preserve outstanding obligations through
  revocation and controller failover (`SBX-PUB-01`).
- [ ] **SBX-PUB-03** Implement the networkless domain-publisher service,
  authenticated local protocol, protected root registry, service identity,
  and enforcing isolation configuration (`SBX-PUB-02`, `SBX-P0-10`).
- [ ] **SBX-PUB-04** Integrate fresh-inode verification/sealing and no-replace
  naming with durable publisher transactions and committed-catalog visibility;
  gate returned backing descriptors on independent read authority
  (`SBX-PUB-03`, `SBX-P0-08`).
- [ ] **SBX-PUB-05** Qualify crash/restart, revocation during blocked kernel
  effects, duplicate receipts, retained uncertain charges, old-executor fencing,
  domain isolation, and catalog disclosure in real service/VM tests
  (`SBX-PUB-04`).
- [ ] **SBX-GIT-01** Implement independent repositories plus constrained Git
  protocol v2 inspection and synchronization endpoints.
- [ ] **SBX-GIT-02** Implement sanitized immutable-pack acceleration and cheap
  fork capability advertisement (`SBX-GIT-01`, `SBX-CACHE-01`).
- [ ] **SBX-ENV-03** Pass concurrent sibling build, atomic environment advance,
  pinned execution, Git, corruption, and cache isolation tests.

## P6: durable lifecycle

- [ ] **SBX-LIFE-01** Implement dependency-closure quiesce/freeze barriers and
  coordinated multi-dataset snapshot transactions.
- [ ] **SBX-LIFE-02** Implement self-contained/external snapshot manifests,
  dependency validation, holds, and resumable transfer state.
- [ ] **SBX-LIFE-03** Implement fork and restore with new incarnations and no
  stale descriptor or lease reuse (`SBX-LIFE-01`, `SBX-LIFE-02`).
- [ ] **SBX-LIFE-04** Implement memory-resident suspend/resume and
  hibernate-as-snapshot-plus-stop (`SBX-LIFE-01`).
- [ ] **SBX-LIFE-05** Implement topological deletion, tombstones, cancellation,
  deferred reap, and iterative non-recursive cleanup.
- [ ] **SBX-LIFE-06** Implement complete boot inventory and reconciliation for
  runtime, mount, storage, network, cache, and transfer resources.
- [ ] **SBX-LIFE-07** Pass exhaustive lifecycle crash, open-FD, conflict,
  cascade, reboot, and stale-handle tests (`SBX-LIFE-01`..`SBX-LIFE-06`).

## P7: network and policy profiles

- [ ] **SBX-POL-01** Compile public policy independently into authority,
  namespace, hard resource, and advisory optimization plans.
- [ ] **SBX-NET-02** Implement per-sandbox identity, project service discovery,
  mediated egress, explicit ingress, quota, and anti-spoofing policy.
- [ ] **SBX-POL-02** Implement atomic policy replacement with hard-feature
  admission and explicit advisory degradation (`SBX-POL-01`, `SBX-NET-02`).
- [ ] **SBX-NET-03** Pass positive/negative connectivity, exhaustion, stale
  identity, replacement, sibling, and ancestry isolation tests.

## P8: portable trees and immutable FUSE

- [ ] **SBX-FS-01** Implement streaming canonical-tree validation and compiler
  limits for names, depth, nodes, extents, xattrs, ACLs, and sparse files.
- [ ] **SBX-FS-02** Implement the replaceable node-local mmap index with lazy
  inode assignment and architecture-neutral conformance tests (`SBX-FS-01`).
- [ ] **SBX-FS-03** Package the selected FUSE library hermetically and implement
  isolated per-view workers (`SBX-P0-11`, `SBX-FS-02`).
- [ ] **SBX-FS-04** Implement backing-file registration and passthrough with
  exact permission, ID, ACL, immutability, and revocation checks (`SBX-FS-03`).
- [ ] **SBX-FS-05** Implement bounded fallback reads, immutable remote fetch,
  request cancellation, deadlines, retries, and integrity verification.
- [ ] **SBX-FS-06** Implement admission-controlled memory/disk caches, pin
  budgets, registration ceilings, eviction, negative cache, and backpressure.
- [ ] **SBX-FS-07** Implement worker restart, poisoned-publication quarantine,
  cache repair, and attachment reconciliation.
- [ ] **SBX-FS-08** Prove million-entry working-set memory, OOM containment,
  cache identity/isolation, worker crash, and native-I/O performance gates.

## P9: multi-node, user interfaces, and release gates

- [ ] **SBX-MULTI-01** Implement authenticated node capability discovery,
  placement, assignment epochs, ownership leases, and draining.
- [ ] **SBX-MULTI-02** Implement immutable snapshot transfer, integrity checks,
  resumability, and dependency-aware restore (`SBX-LIFE-02`).
- [ ] **SBX-MULTI-03** Implement resumable ordered watch across coordinators and
  preserve compatible protocol/format versions during rolling upgrades.
- [ ] **SBX-MULTI-04** Pass partitions, stale coordinator, lease expiry,
  interrupted transfer, missing dependency, and rolling-upgrade tests.
- [ ] **SBX-CLI-01** Add the complete `aos sandbox` command family over only the
  public client API.
- [ ] **SBX-CLI-02** Add tree/status/event views, structured output, stable exit
  behavior, and shell completions.
- [ ] **SBX-SKILL-01** Add generic sandbox lifecycle and inspection skills that
  invoke the stable CLI and disclose no private daemon interface.
- [ ] **SBX-OBS-01** Add correlated operations, structured audit events,
  metrics, health, residual-resource inventory, and operator recovery tools.
- [ ] **SBX-GATE-01** Pass format/protocol compatibility, fuzz, property,
  adversarial security, VM, multi-architecture, performance, and hermeticity
  gates.
- [ ] **SBX-GATE-02** Publish migration, rollback, operations, and threat-model
  documentation and enable the production feature gate (`SBX-GATE-01`).

## Progress log

Add one line per pushed implementation commit, listing the task identifiers it
completes. The Git history remains authoritative for code details.

- `f48a7ad4e` — `SBX-P0-03`: hermetic architecture-neutral probes for the
  pidfd family, `openat2`, `open_tree`, `open_tree_attr`, `move_mount`,
  `fsopen`/`fsconfig`/`fsmount`/`fspick`, `mount_setattr`, `statmount`, and
  `listmount`, with structured presence and errno reporting.
- `0ddad351c` — `SBX-CORE-01`, `SBX-CORE-02`: portable crate, opaque
  identities, exact binary/human encodings, and monotonic fencing counters.
- `a33eac266` — `SBX-CORE-03`: closed resource transition graphs, irreversible
  desired deletion, terminal operation outcomes, and stale observation
  rejection by generation and sequence.
- `4c849dc51` — `SBX-CORE-04`: explicit resource dimensions and ceilings,
  checked reserve/commit/release accounting, isolated advisory capacity, and
  atomic inclusive ancestry transactions.
- `ce67b873f` — `SBX-CORE-05`: closed resource/operation registries, portable
  selectors, channel-bound online capability evaluation, and strict grant,
  time, assignment, revocation, depth, fanout, and resource attenuation.
- `28073bb1c` — `SBX-CORE-06`: portable metadata, ACL, xattr, sparse content,
  directory, tree, and final-tree delta models.
- `b78b57274` — `SBX-CORE-06`: immutable/live filesystem views, disclosure
  domains, ordered presentation programs, and immutable environments.
- `b9cd2260d` — `SBX-CORE-06`: closed identity, resource, network, attachment
  slot, and complete portable sandbox specification models.
- `9fddb1805` — `SBX-CORE-06`: normalized effective policy, delegable grant
  subsets, enforcement limits, revocation, explanations, and optimization.
- `37fb085f9` — `SBX-CORE-06`: execution-independent snapshots, portable
  checkpoints, non-secret retention receipts, and typed external dependencies.
- `bc5d4fbe8` — `SBX-CORE-06`: trust policies, immutable signer generations,
  signature statements, purpose/usage binding, and exact signature bytes.
- `7a3f31bbe` — `SBX-CORE-06`: bounded ancestry, semantic placement requests,
  fenced assignments, closed mount attributes, and attachment intent/leases.
- `d53ea5e7e`, `bfdaf2faa` — `SBX-CORE-07`: allocation-bounded deterministic
  CBOR, canonical set/map ordering, exact codecs for every portable v1 object,
  domain-separated descriptors, and executable root format vectors.
- `d99883388` — `SBX-CORE-08`: closed media-type, descriptor-role, feature,
  signature-purpose, and independent protocol-domain registries with
  fail-closed decoding and negotiation.
- `9b0864f03` — `SBX-CORE-09`: domain-separated Ed25519 signing and strict
  verification bound to canonical trust-policy bytes, subject role, exact key
  generation and fingerprint, scope, purpose, and validity interval.
- `8065b4eff` — `SBX-CORE-10`: executable raw-content, empty-directory,
  signature-statement, preimage, and signature vectors plus deterministic-CBOR
  rejection vectors and signed/unsigned integer extrema.
- `c493178f5` — `SBX-CORE-11`: deterministic exhaustive operation-bitmap
  attenuation, bounded-account admission/release, portable-mode canonicality,
  terminal-state, and generation/sequence fencing properties.
- `e8ac32d7c` — `SBX-API-01`: backend-neutral public sandbox, execution,
  view, attachment, snapshot, capability, operation, event, node-capability,
  pagination, watch, policy-plan, condition, and closed error resources.
- `d7ac92b03` — `SBX-API-02`: complete public sandbox, descendant, policy,
  lifecycle, execution, filesystem-view, attachment, snapshot, capability,
  operation, watch, and node-capability RPC registry with mutation fences.
- `37dde6aee` — `SBX-API-03`: operation resources, mutation idempotency and
  compare-and-swap fields, resumable watch cursor/watermark semantics, and a
  build-enforced additive v1 compatibility floor.
- `af419c775` — `SBX-BPROTO-01`: separately versioned, fixed-function local
  host, storage, mount, network, guardian, and guest-agent protocols with
  authenticated envelopes, assignment fences, opaque handles, and inventory.
- `729195700` — `SBX-BPROTO-02`: bounded hostile-message decoding, kernel peer
  credential and broker-audience binding, assignment-fence and closed
  descriptor-role validation, and deterministic malformed-message fuzz entry
  points across every privileged local request.
- `e82e16095` — `SBX-BPROTO-03`: durable assignment comparison, conservative
  boot-bound ownership deadlines, exact renewal and stop-proof fencing, and
  atomic shared-endpoint transfer simulations covering partitions, stale
  coordinators, equivocation, reboot, and partial-transfer rollback.
- `addc42e92` — `SBX-JRN-01`, `SBX-JRN-02`: exclusively owned, versioned and
  checksummed transaction journal with synchronous commits, immutable
  idempotency decisions, bounded replay/materialization, fail-closed complete
  corruption handling, torn-tail recovery, and atomic bounded compaction.
- `8eb2d4ee8` — `SBX-CTRL-01`: atomic desired-state, operation, idempotency,
  and ordered-effect admission; durable pre-effect intent and receipts;
  restart observation of ambiguous effects; bounded retry/block evidence; and
  fair nonterminal operation scheduling over fixed effect domains.
- `ec3a23d4f` — `SBX-CTRL-02`: exhaustive transaction-frame and durable-effect
  restart matrices, including the external-apply-before-receipt ambiguity,
  prove atomic recovery and convergence without duplicate effect application.
- `b024bb612`..`eda7b29b9` — foundation toward `SBX-HOST-01`: bounded
  sequence-packet ingress, closed runtime decoding, exact assignment-bound
  atomic launch catalogs, durable fencing and replay, typed one-shot systemd
  effects, pidfd/cgroup leader and controller identity checks, safe bounded
  errors, hermetic hostd packaging, and hardened systemd socket activation.
  Complete session dispatch and authoritative runtime inventory remain open.
- `393b76e17`..`39dd3381c` — foundation toward `SBX-MOUNT-01`: closed request
  decoding, durable request fencing and replay, descriptor catalogs, detached
  mounts, sealed helper plans, fixed-FD helper spawning, namespace mutation,
  peer-authenticated daemon ingress, hermetic packaging, and hardened systemd
  integration. Durable handle identity, exact topology verification, complete
  session dispatch, and authoritative inventory remain open.
- `d9dad8faa`, `25b015ddf` — foundation toward `SBX-BPROTO-04`,
  `SBX-HOST-01`, and `SBX-MOUNT-01`: bounded two-packet session negotiation,
  session-bound method admission, exact empty descriptor tables, canonical
  success/error envelopes, and closed response ceilings for the implemented
  host and mount methods. Signed plans, leases, and inventory dispatch remain
  open.
- `22e19a5cf`, `461bea8c3` — foundation toward `SBX-MOUNT-01`: one stable
  handle across preparation and publication plus a pluggable synchronous
  systemd descriptor-store keeper with canonical names, restart adoption,
  removal, processing barriers, and bounded service configuration. The Mount
  keeper does not yet perform complete manager readback: on systemd 259.8 a
  successful barrier does not prove that an add or removal survived capacity,
  allocation, or descriptor-inspection failure. Acceptance readback, daemon
  adoption, and durable resource reconciliation remain open.
- `bf0e7dcc6` — foundation toward `SBX-MOUNT-01` and `SBX-LIFE-06`: strict
  current-kernel boot identity for rejecting numerically reused mount IDs after
  reboot.
- `c52198db8` — foundation toward `SBX-MOUNT-01`: release no longer depends on
  a catalog entry, while teardown lookup accepts the action's intentionally
  absent view descriptor.
- `dd9eaadaf` — foundation toward `SBX-BPROTO-04`, `SBX-MOUNT-01`, and
  `SBX-LIFE-06`: separately negotiated authoritative mount-resource inventory
  with complete bounded lifecycle evidence, boot and journal ordering,
  canonical identities, and reciprocal replacement validation. Broker
  dispatch and durable state projection remain open.
- `2cec65370` — foundation toward `SBX-MOUNT-01` and `SBX-LIFE-06`: restart
  reconciliation now compares retained descriptor custody against exact mount
  identity before allowing durable resources to remain usable.
- `9d67adcc3` — foundation toward `SBX-BPROTO-04`: canonical signed broker
  plans bind one node, assignment, audience, protocol, exact semantic verbs,
  opaque targets, request commitments, ceilings, trust generation, and
  revocation scope. Ownership-lease intersection, request admission, and
  broker dispatch enforcement remain open.
- `9a2d91b94` — foundation toward `SBX-HOST-01`, `SBX-RT-02`, and `SBX-RT-04`:
  the host broker compiles only a fixed nspawn command, exact transient-unit
  profile, catalogued nonoverlapping identity allocation, and bounded resource
  policy. Production launch remains unavailable until executable, MAC,
  namespace, immutable-pin, and post-launch identity probes mint readiness.
- `017edc0e3` — foundation toward `SBX-MOUNT-01`, `SBX-VIEW-03`, and
  `SBX-LIFE-06`: durable mount resources now preserve exact descriptor custody,
  pre-effect lifecycle intent, boot-scoped kernel identity, reciprocal atomic
  replacement, bounded authoritative inventory, and restart reconciliation.
  Broker authorization admission and end-to-end namespace VM tests remain
  open.
- `a29f16196` — foundation toward `SBX-BPROTO-04`, `SBX-GUARD-01`, and
  `SBX-MULTI-01`: signed authority-wall ownership leases, monotonic renewal
  fencing, conservative boot-bound local deadlines, exact plan/request/lease
  intersection, and a bounded corruption-detecting local record. Production
  brokers must still authenticate the record under a node-local key and
  atomically consume the non-authorizing intersection before any effect.
- `26911b96c` — foundation toward `SBX-MOUNT-01` and `SBX-LIFE-06`: durable
  recovery and wire inventory now share one boot-scoped replacement theorem;
  stale terminal history cannot claim current slots or hide dangling,
  cross-boot, or nonreciprocal edges, and descriptor-store keys are canonical
  to mount handles. Bounded tombstone retirement remains open.
- `0f7688335` — foundation toward `SBX-BPROTO-04`, `SBX-HOST-01`, and
  `SBX-MOUNT-01`: host and mount protocol 1.1 carries an exact bounded signed
  plan/lease quartet as explicitly untrusted input; effect methods fail closed
  without the negotiated feature while legacy 1.0 remains
  observation/inventory-only. Broker signature verification, semantic matching,
  durable intersection admission, and immediate pre-effect expiry checks remain
  open.
- `d60256506` — foundation toward `SBX-BPROTO-04` and `SBX-MOUNT-01`: the mount
  audience now verifies protected signed-plan and ownership-lease anchors,
  commits exact catalog/request/lease intersections under a node-local MAC,
  fences ownership-key lineage and replay, and rechecks one conservative
  plan/lease/request `CLOCK_BOOTTIME` deadline in both the broker and the sealed
  namespace helper immediately before every irreversible operation. Equivalent
  admission and dispatch remain open for the other privileged audiences, and
  the mount broker still requires its end-to-end namespace VM proof.
- `c78c88d76` — foundation toward `SBX-BPROTO-04`: exact grants are canonicalized
  by verb, target, and argument commitment, so one signed assignment plan can
  authorize multiple distinct create semantics without ambiguity; portable
  signed semantics exclude node-local response and `CLOCK_BOOTTIME` attenuation.
- `4a2ac51da` — foundation toward `SBX-BPROTO-04` and `SBX-CTRL-03`: bounded
  outbound effect envelopes now preserve the exact canonical plan, plan
  signature, ownership lease, and lease signature bytes while enforcing closed
  methods, descriptor tables, individual artifact ceilings, and the final
  encoded packet bound. Controller compilation and broker dispatch remain open.
- `ba8924eaf` — foundation toward `SBX-BPROTO-04`, `SBX-CTRL-03`,
  `SBX-HOST-01`, and `SBX-MOUNT-01`: a shared privileged-broker authority crate
  owns protected trust loading, signed plan/lease intersection, paired-clock
  expiry, and location-authenticated durable fences/effects while preserving
  existing mount record bytes. The public-only controller preparation path
  freezes exact plan and lease bytes, emits core-defined signing messages for
  external protected signers, and rejects mismatched or invalid returned
  signatures without importing private keys.
- `31f2937c0` — executable evidence toward `SBX-P0-04` and `SBX-P0-05`: a
  hermetic nspawn isolation probe checks the exact systemd 259.8 boundary,
  pre-PID1 argument filters, hostile-settings suppression, explicit user
  mapping, prepared networking, and machined independence. The QEMU guest and
  an existing control test both timed out before agent readiness with blank
  serial output, so neither phase-0 task is claimed complete.
- `fa3136b70` — foundation toward `SBX-BPROTO-04`, `SBX-STOR-01`, and
  `SBX-NET-01`: the append-only signed-plan registry now assigns closed Storage
  and Network audiences, protocols, verbs, target shapes, and independently
  domain-separated authenticated record formats. Guardian remains deliberately
  lease-direct rather than acquiring an invented broker-plan audience.
- `e1db7c938` — executable evidence toward `SBX-P0-07`: the kernel-matched
  OpenZFS 2.4 proof covers snapshot holds, clone identity, enforced quota,
  reservation accounting, send/receive GUID continuity, and a real idmapped
  ZFS mount. Its C probe and full system closure build, but the shared QEMU
  guest-readiness timeout prevented runtime evidence; aarch64 also remains
  outstanding, so the task stays open.
- `7d1f57a5e` — foundation toward `SBX-BPROTO-04`, `SBX-HOST-01`, and
  `SBX-MOUNT-01`: enabled host and mount brokers require the complete protected
  authority set through fixed systemd credential handles. Only external
  credential names enter the Nix closure, malformed or partial configuration
  fails evaluation, and obvious cross-domain journal-key source reuse is
  rejected.
- `f119f7237` — foundation toward `SBX-BPROTO-04` and `SBX-HOST-01`: host
  effects now consume the negotiated signed-plan/lease quartet, use a public
  controller-reusable portable semantic compiler, atomically persist
  location-MACed fence and effect records, authenticate and cross-link the full
  recovered state graph, preserve exact completed replay after deadlines, and
  recheck paired-clock authority immediately before each systemd mutation.
  Production launch remains unavailable until stable pin handoff and
  post-launch identity evidence are implemented; observe and inventory dispatch
  also remain open.
- `b0a41d107` — foundation toward `SBX-BPROTO-04` and `SBX-HOST-01`: host
  observation and complete runtime inventory now dispatch under both protocol
  1.0 and 1.1, reject authorization carriers, require exact durable identity,
  order and bound authoritative systemd observations, and commit observation
  sequences only after complete success. The protocol permits a canonical
  empty successful body only for an empty host inventory. Production launch
  remains gated on stable pin handoff and post-launch identity evidence.
- `727da7f3e` — executable evidence toward `SBX-P0-02`: an
  architecture-neutral Linux UAPI probe now fails closed unless fs-verity can
  enable, measure, and prevent writable reopen and FUSE passthrough can
  register an exact backing descriptor and serve matching bytes without a
  userspace read. The probe and both-architecture Kconfig resolution build;
  the task remains open pending x86_64 and aarch64 VM runtime evidence.
- `371f6d0e0` — foundation toward `SBX-HOST-01`: launch catalog resolution now
  retains type-checked workspace and network-namespace descriptors across the
  complete asynchronous systemd start and final observation. Descriptor
  identity substitution and host-network selection fail closed. Apply remains
  unadvertised because current path-valued systemd/nspawn transport does not
  yet consume those pins and no protected boot-local readiness attestation is
  available.
- `fbf7b6b53` — foundation toward `SBX-STOR-01`: storage request authority now
  binds opaque handles to exact catalogued dataset and snapshot GUIDs, policy
  domains, holds, child and ancestor quota policy, and complete typed
  postconditions. The resulting ZFS transaction program is deliberately not
  runnable: a future helper must hold the protected catalog lock continuously
  across GUID/name/hold preconditions, mutation, observation, and durable
  catalog update before any effect can be enabled.
- `14cbe6fe3` — foundation toward `SBX-CTRL-03`: a bounded canonical assignment
  manifest now owns the complete controller-known identity, ancestry, node,
  generation, immutable input, feature, policy, and reservation preimage and
  derives its assignment digest internally. Fixed schema collection ceilings
  apply before allocation, node-local names have no carrier, lease renewal is
  outside the digest, and the existing free-digest placement path has an
  explicit migration through the canonical manifest.
- `dad861f3f` — foundation toward `SBX-HOST-01`: systemd launch compilation now
  carries owned descriptor tokens for the pinned nspawn executable, workspace,
  and network namespace instead of reopenable catalog paths. Initial and replay
  observations require the same executable, network, leader, and liveness
  proof; every ambiguous or failed proof unconditionally attempts kill and stop
  containment while retaining the pins. Production Apply remains unadvertised
  pending protected boot-local readiness and payload-root evidence.
- `ccf1f0891` — foundation toward `SBX-BPROTO-04`, `SBX-CTRL-03`, and
  `SBX-STOR-01`: the portable storage semantic compiler now lives at the shared
  protocol boundary and accepts only bounded wire input, opaque catalog
  commitment, and portable handles. Storage adds node-local resolved-object and
  policy equivalence without leaking backend names, GUIDs, keys, or paths into
  portable authority; the existing canonical commitment remains byte-exact.
- `8dde225a9` — foundation toward `SBX-CTRL-03` and `SBX-MULTI-01`: ownership
  acquisition and renewal now cross an explicit linearizable-authority boundary
  with a fixed canonical claim, request idempotency, expected-absence acquire,
  and exact generation/digest compare-and-swap renewal. Generation, validity,
  skew, and nonce remain issuer facts; returned bytes become usable only after
  canonical signature, trust, context, liveness, duration, and advancement
  verification. A production durable authority backend remains open.
- `673df1774` — foundation toward `SBX-BPROTO-04` and `SBX-CTRL-03`: portable
  host canonicalization now lives at the shared protocol boundary with its
  existing commitment preserved, and controller dispatch separates immutable
  signed-plan templates from lease- and local-deadline-bound attempts. The
  controller artifacts are explicitly non-authorizing: privileged brokers must
  still decode hostile bodies, resolve catalogs, recompute semantics, verify
  protected clocks, and durably admit the complete authority intersection.
- `70c466d49` — foundation toward `SBX-P0-04` and `SBX-HOST-01`: hostd can
  optionally ingest a bounded root-owned systemd credential bound to the
  current boot and exact nspawn store object, with a durable global publisher
  generation/digest watermark. Missing evidence preserves Observe/Inventory;
  present invalid or stale evidence fails closed. Apply remains unadvertised
  because the phase-0 digests are publisher claims, supervisor pidfd namespace
  access is unproven under the hardened unit, and payload-root identity is not
  yet observed.
- `aaeefc150` — foundation toward `SBX-BPROTO-04`, `SBX-CTRL-03`, and
  `SBX-MOUNT-01`: portable mount canonicalization now lives at the shared
  protocol boundary while preserving the existing commitment bytes. The mount
  catalog remains a node-local resolution facade, so controller authority does
  not acquire backend paths, descriptor identities, or other host facts.
- `ca65218e4` — foundation toward `SBX-CTRL-03`: the controller journal now
  publishes proposal, prepared authority, and current authority as one complete
  cross-linked transaction. Recovery bounds and structurally revalidates the
  audience set, manifest, lease, plan, and dispatch template, recomputes inner
  and outer digests, and rejects rollback, equivocation, and partial state.
  This is structural recovery only; each protected broker must still perform
  cryptographic verification against its own trust anchors.
- `8ced2381e` — foundation toward `SBX-P0-04` and `SBX-HOST-01`: launch
  reconciliation now discovers exactly one direct nested PID 1 from the fixed
  payload cgroup subtree, pins it with a pidfd, and checks bounded stable cgroup,
  TGID, parent, namespace, liveness, and point-in-time root evidence against the
  owned launch descriptors. Procfd aliases remain owned through initial
  activation and proof, with automatic restart disabled and inactive units
  collected. Apply remains unadvertised: deployed pidfd namespace access and
  root continuity against a later root change are still explicit blockers.
- `6f8835512` — foundation toward `SBX-STOR-01`: a bounded, exclusively locked
  storage journal now durably records authenticated Prepared, Ambiguous, and
  Committed phases for up to 1,024 operations. Recovery never returns runnable
  mutation arguments, exact completed requests replay, rollback and catalog
  forks fail closed, and observation assertions are bound to the exact request,
  mutation, input catalog, and postcondition before commit. The assertion type
  is not proof of ZFS inspection; the privileged observation/execution helper,
  protected key lifecycle, and broker admission path remain open.
- `ab36dc2b9` — foundation toward `SBX-BPROTO-04`, `SBX-CTRL-03`,
  `SBX-STOR-01`, and `SBX-NET-01`: additive Storage and Network Apply and
  Inventory method tags now have a closed protocol/method/role/carrier matrix.
  Apply requires the signed authority carrier, Inventory rejects it, the two
  local brokers accept no descriptor carriers, and cross-protocol or
  non-controller replay fails closed. Protocol 1.1 enables signed effects while
  1.0 remains inventory-only. A future remote transport must authenticate the
  broker audience and define a separately versioned non-SCM_RIGHTS carrier
  profile; local descriptor integers are never portable.
- `ffb886353` — foundation toward `SBX-CTRL-03`: an unprivileged controller
  boundary now bounds candidate request bytes before parsing, requires an
  injected endpoint compiler to retain the service-computed scoped digest,
  atomically admits durable work with exact replay under saturation, and runs
  fair fixed-size reconciliation quanta without a volatile queue. Public and
  coordinator transports, a recovery-built capacity index, durable fairness
  across repeated restarts, and broker execution remain open.
- `58433c809` — foundation toward `SBX-P0-04` and `SBX-HOST-01`: the closed
  launch specification now witnesses payload-root continuity from the pinned
  reviewed nspawn binary, removal of `CAP_SYS_ADMIN` and `CAP_SYS_CHROOT`, NNP,
  and inherited generic plus final compiled syscall filters. The compiled AOS
  filter now redundantly denies `chroot`, and its patched C test passes. A
  retained hostd self-probe checks pidfd namespace ioctls under the hardened
  service without adding capabilities. Apply remains unavailable because
  shifted-payload ptrace access and independent deployed-profile verification
  are still blockers.
- `23220e41a` — foundation toward `SBX-STOR-01`: exact resolved storage
  semantics, signed plan, and ownership lease can now be admitted into one
  journal transaction containing the authenticated fence, non-authorizing
  admission intent, and storage operation. Recovery authenticates and
  cross-links all locations and surfaces pending or ambiguous work without
  live readmission. Storage Apply remains unadvertised; no ZFS observation or
  execution path exists yet.
- `c5169944c` — foundation toward `SBX-BPROTO-04`, `SBX-CTRL-03`, and
  `SBX-NET-01`: a shared portable Network V1 compiler now owns closed action
  shapes, opaque handles, bounded canonical endpoint sets, and exact
  assignment/resource grant semantics. Lease digest, lease generation,
  fail-stop BOOTTIME, and transport fields remain validated attempt-local facts
  outside the reusable signed-plan commitment; a future netd must compare them
  with the separately verified lease and durable fence immediately before an
  effect.
- `1b9c9e869` — foundation toward `SBX-CTRL-03`: durable current-authority
  recovery now retains typed immutable lease and per-audience template
  artifacts alongside their exact bytes after one structural parse. Dispatch
  selection re-reads the current record, requires the caller's expected
  publication and template digests, rejects audience or renewal substitution,
  and injects only fresh local deadline attenuation through the reconciler's
  sole journal owner. The resulting packet is explicitly non-authorizing until
  a protected broker verifies it and resolves its descriptor catalog.
- `eb6a61600` — foundation toward `SBX-STOR-01`: the crate-private storage
  helper now proves the exact durable request, mutation, catalog bytes, and
  derived postcondition before any privileged observation, repeats that proof
  immediately before the durable Ambiguous transition, holds the transaction
  lock across observation and the single injected execution, and commits only
  after complete child-and-ancestor re-observation. Ambiguous recovery remains
  observation-only, and no production ZFS adapter or Apply advertisement exists.
- `99236454d` — foundation toward `SBX-CORE-03`, `SBX-CTRL-03`, and the
  privileged brokers: the journal now has a fail-closed production opener for
  root-owned state. It anchors absolute traversal at `/`, validates every
  component through retained no-follow directory descriptors, rejects writable
  ancestors, and requires exact 0700 directory plus 0600 single-link journal
  and lock files. Protected compaction uses one bounded, exclusively created
  per-journal temporary slot with fd-relative cleanup, rename, and directory
  synchronization, so pathname substitution and repeated crash debris cannot
  silently weaken durable authority. Unsupported `openat2` enforcement is a
  typed hard failure; callers must not fall back to the ordinary journal API.
- `e70140365` — foundation toward `SBX-STOR-01`: production storage state now
  opens its journal exclusively through the root-anchored protected API. The
  prior pathname metadata preflight and post-open chmod sequence are removed;
  ordinary journal opening survives only in a test-only fixture, and protected
  rejection has no fallback path.
- `b9fae359c` — foundation toward `SBX-BPROTO-04`, `SBX-STOR-01`, and
  `SBX-NET-01`: the shared broker authority now seals bounded
  application-domain local records at exact namespace/key locations and checks
  payload bounds before allocation. Fence and effect sealing also rejects a
  durable location that disagrees with the record's intrinsic sandbox or
  request identity, preventing trusted-code relocation from producing a valid
  authenticated cross-link.
- `ff3d3c4e7` — foundation toward durable ownership recovery in
  `SBX-CTRL-03`: exact canonical historical lease and signature bytes can now
  be authenticated against a pinned historical trust anchor and an
  integrity-bound acceptance instant. The verifier reproduces the live
  skew-safe wall-clock interval but deliberately carries no BOOTTIME or current
  liveness; its distinct non-authorizing proof type cannot directly satisfy an
  API requiring a freshly checked lease, although its exact canonical artifacts
  may be submitted to that API for independent protected-clock verification.
  Chain ordering, unique-head recovery, and anchor-history selection
  remain obligations of the protected durable authority backend.
- `a662b3c6d` — foundation toward `SBX-NET-01`: a root network crate now
  verifies signed Network-audience authority and atomically retains a bounded,
  authenticated, losslessly recoverable PREPARE intent with exact protected
  profile, endpoint-policy, and reserved-handle resolution. The durable V1
  schema accepts only Prepared/NetworkPrepare; it does not speculate about
  existing kernel-resource identity or effect phases. A distinct protected
  catalog publisher has no production implementation yet, all existing-resource
  actions fail before admission, durable history is not advertised as current
  inventory, and the service advertises no methods.
- `008bd8981` — foundation toward `SBX-CTRL-03` and `SBX-MULTI-01`: the
  protected ownership-authority backend now durably separates unsigned intent
  from issuer completion, reserves completion capacity before issuance, and
  requires exact idempotent issuer replay after a crash. Completion samples a
  protected clock after the issuer round trip and atomically records the exact
  signed response plus current pointer. Bounded recovery authenticates every
  historical response against one pinned authority generation, reconstructs a
  unique linear chain per sandbox, and rejects rollback, forks, disconnected
  history, foreign namespaces, and deleted, relocated, or cross-sandbox-swapped
  heads. Recovered heads remain explicitly non-authorizing; controller
  integration, key-generation migration, release, transfer, and epoch rollover
  remain open. The crate passes 71 unit tests, strict all-target Clippy, and
  rustdoc with warnings denied.
- `6b6db8035` — correction toward `SBX-CTRL-03` and `SBX-MULTI-01`: ownership
  completion now treats protected paired-clock sampling as a fallible boundary
  after the issuer round trip and before any completed entry or current pointer
  is published. If sampling fails after issuer success, only the durable intent
  remains; reopen plus explicit resume requires the issuer's exact idempotent
  response and completes without a second issuance. Automatic recovery still
  never contacts the issuer. The crate passes 72 unit tests and the same strict
  Clippy, rustdoc, formatting, and diff gates.
- `50a48d3a1` — foundation toward `SBX-BPROTO-04`, `SBX-CTRL-03`, and
  `SBX-MULTI-01`: a separately versioned, transport-neutral ownership protocol
  now negotiates an exact authority epoch, closed methods, hard bounds, and
  fresh client/server nonce transcript. Begin, explicit completion/resume, and
  query preserve one immutable request binding; the signed transaction receipt
  binds that claim and exact lease so four-artifact replay cannot substitute a
  lease, signature, receipt, or authority epoch. Hostile carrier decoders have
  an explicit validation boundary, recovered and caller-clock-checked artifacts
  remain non-authorizing, and the durable authority plus controller publication
  use distinct V2 formats that reject legacy V1 state with `MigrationRequired`.
  The normative fixed-binary profile and executable golden vectors agree. The
  focused suites pass 230 unit tests plus doctests, strict all-target Clippy,
  warning-denied rustdoc, formatting, and adversarial review.
- `b30d68311` — foundation toward `SBX-CTRL-03` and `SBX-MULTI-01`: controller
  admission can now persist a canonical ownership claim and self-contained,
  lease-independent authority-publication draft in the same transaction as
  desired state, the operation, every planned effect, and idempotency. Durable
  operation provenance prevents a missing gate from becoming runnable;
  ordinary reconciliation skips ownership-pending effects. Explicit release
  requires the receipt's exact action, request ID, claim digest, authority,
  lease, and draft, then atomically installs the permanent prepared publication
  and current pointer with the accepted operation and activated gate. Recovery
  requires the permanent record plus the exact current publication or a valid
  same-authority successor. Controller publication moves from the earlier V2
  foundation to an isolated, closed V3 namespace; V1/V2 state requires explicit
  migration, while unknown, malformed, substituted, orphaned, or colliding V3
  state fails closed. The implementation passes 105 unit tests plus doctests,
  strict all-target Clippy, warning-denied rustdoc, formatting, and adversarial
  review. The production explicit authority-resume path remains open.
- `042ed7be3` — foundation toward `SBX-CTRL-03` and `SBX-MULTI-01`: the public
  controller can now explicitly resume a durably ownership-gated operation.
  Pending work always queries its exact request-ID and claim digest first,
  begins only confirmed-absent intent, and completes only a confirmed-pending
  transaction. The client pins one immutable negotiated authority, method set,
  and request/response/duration bounds; independently decoded response fields
  remain hostile until exact transcript, method, and transaction validation.
  Completed responses are cryptographically checked as four exact artifacts,
  bound to the canonical claim and publication draft, and released only through
  the crate-private atomic activation bridge. Restarted activated replay makes
  no session, network, or clock call. Unavailable, malformed, forged, stale,
  and clock-observation failures do not publish authority or release the gate,
  and retry starts with Query. The local paired-clock observation is explicitly
  non-authorizing; every privileged broker must reverify protected current time
  and all fences immediately before an effect. Recovery behavior now comes only
  from the protocol's canonical error mapping, including wrong-authority-epoch
  replanning. The implementation passes 114 sandbox unit tests, one downstream
  public-API integration test, 14 ownership-protocol tests, all doctests, strict
  Clippy, warning-denied rustdoc, formatting, and adversarial review.
- `b2a56efd2` — foundation toward `SBX-BPROTO-04`, `SBX-CTRL-03`, and
  `SBX-MULTI-01`: a transport-neutral service now maps the negotiated ownership
  protocol onto the protected durable authority. Query observes only an exact
  request-ID/claim-digest binding, Begin durably records unsigned intent, and
  CompleteOrResume rechecks that binding under the same exclusive borrow before
  allowing a still-pending transaction to contact the issuer and protected
  authority clock. Completed Begin, Query, and completion replay return the
  exact historical four artifacts without issuer or clock calls. A same-TCB
  in-process adapter composes this service with the node controller without
  claiming a process security boundary; future local or remote carriers retain
  peer authentication, pre-allocation framing bounds, and hostile decoding.
  Negotiation accepts the protocol's full sufficient response-ceiling range
  while binding each exchange to the selected value. A dual-journal integration
  test activates through the real controller and durable authority, reopens
  both journals, and proves replay performs no additional issuance or protected
  clock read. The slice passes 117 sandbox unit tests, one downstream API test,
  doctests, strict Clippy, warning-denied rustdoc, formatting, and independent
  adversarial review.
- `09bac05fe` — foundation toward `SBX-BPROTO-04`, `SBX-CTRL-03`, and
  `SBX-HOST-01`: Host protocol 1.2 adds a strictly read-only
  `QueryRuntimeEffect` operation carrying the exact original 1.1-or-1.2 Apply
  body and signed authorization quartet with zero descriptors. The broker
  reauthenticates historical admission, durable fence, effect, derived runtime
  handle, and byte-exact receipt, then reports `Absent`, `Pending`, or
  `Complete` without admitting state, resolving a catalog, writing the journal,
  or invoking a worker. A hostile response decoder enforces the closed status
  and receipt shape. Host 1.2 negotiates a query-specific packet ceiling with
  bounded wrapper headroom while retaining the full legacy 1.1 Apply ceiling;
  only Query may use the additive band. Host StateWire V3 binds every current
  fence to the exact latest admitting request ID, so deleting a later request
  cannot be hidden by an older request with byte-identical assignment authority;
  nonempty V1/V2 authority state requires explicit migration. Protocol 1.0/1.1
  remain closed to Query, and Apply authorization semantics remain pinned to
  1.1 independently of the 1.1/1.2 carrier. The slice passes 140 core, 59
  protocol, and 65 host tests plus proto/doctests, strict Clippy,
  warning-denied rustdoc, formatting, and two-round adversarial review. A
  controller broker client and effect-template binding remain open.
- `a12219f4f` — foundation toward `SBX-FS-01` and `SBX-FS-02`: a new
  backend-neutral filesystem-view crate now streams exact authenticated
  portable tree objects through an iterative, cycle-checking graph compiler
  into a deterministic architecture-neutral structural index. Graph expansion,
  decoded objects, queued paths and ancestors, hard-link membership, output
  records, and hostile index collections are all admitted before allocation
  under compiler-authoritative byte and count ceilings. Staging is a consuming
  fresh-empty capability; failed or rootless output cannot become a staged
  index. Validation requires an authenticated index descriptor and exact
  tree/root/compiler/feature cross-links, then returns a non-cloneable proof
  borrowing the precise immutable bytes rather than a replayable detached
  token. Portable owners and ACL qualifiers remain structural data; exact ID
  translation is separately cache-partitioned and rejects gaps, overflow, and
  unsupported ACLs. Fixed index and hard-link digest vectors pin the derived
  formats. The slice passes 28 filesystem-view and 140 sandbox-core unit tests,
  doctests, strict all-target Clippy, warning-denied rustdoc, formatting, and
  two-round independent adversarial review. mmap lookup, lazy inode
  instantiation, cache management, FUSE request handling, sealed publication,
  and mount realization remain open, so both task boxes remain unchecked.
- `530462b7b` — prerequisite toward `SBX-BPROTO-04` and `SBX-HOST-01`: the
  Linux boundary now owns a nonblocking, close-on-exec connected Unix
  `SOCK_SEQPACKET` transport with exact `MSG_PEEK | MSG_TRUNC` admission before
  allocation and exact consuming receive. A fixed ancillary buffer accepts
  exactly one kernel-authorized credentials/pidfd subject pair and rejects,
  closes, and revokes the connection for rights, unknown, duplicate, malformed,
  truncated, or length-drifting control data. Socket adoption rejects listeners
  and unconnected endpoints, then separately pins the connection establisher
  through correlated `SO_PEERCRED` and Linux 6.18 `SO_PEERPIDFD`. The public
  types explicitly distinguish connection-establisher identity from a
  delegable endpoint's later executor and from a per-record subject whose
  credentials a capable process may nominate; none is mislabeled execution
  provenance. Unsafe C UAPI handling remains confined to the private UAPI
  module with descriptor ownership established before fallible validation. The
  slice passes 35 live-kernel unit tests, strict all-target Clippy,
  warning-denied rustdoc, formatting, and two-round independent adversarial
  review. Carrier framing, transcript authentication, systemd unit binding,
  service deployment, and the controller client remain open.
- `d5a36f038` — foundation toward `SBX-CTRL-03`, `SBX-BPROTO-04`, and
  `SBX-HOST-01`: ownership-gated effects now use an opaque V2 plan derived
  solely from one exact publication-draft template and bound to operation,
  ordered step, Host audience/method, descriptor-free body, and portable
  semantics. The reconciler selects authority and durably records the selected
  publication, binding, lease facts, attenuation scalars, deadline-bearing
  body, and complete Apply packet before broker I/O. Restart queries that exact
  attempt; Pending or indeterminate transport retains it, while only
  authenticated Absent permits a newly selected attempt that is itself
  committed before Apply. Historical validation is anchored at the activated
  publication and remains independent of today's current pointer. Host
  completion tokens bind the exact effect and packet, and stored observations
  are deterministically revalidated for canonical shape, assignment fence, and
  derived runtime handle before recovery. Non-Host, non-Apply, descriptor
  effects, cross-attempt receipts, operation/step swaps, crafted V2 policy
  violations, and unsupported legacy gated V1 state fail closed before
  executor I/O; the public raw attempt-selection path is removed. The
  unreleased V2 format deliberately persists no unauthenticated clock
  provenance or boot identity, and V1 bytes remain golden-stable in all four
  states. The slice passes 129 sandbox and 59 broker-protocol unit tests, a
  downstream API test, doctests, strict all-target Clippy, warning-denied
  rustdoc, formatting, and multi-round independent adversarial review. The
  production seqpacket client, systemd service binding, and Host Apply
  advertisement remain open.
- `d96752e94` — further foundation toward `SBX-FS-02`: structural-index V2
  retains V1's validated record encoding and adds a fixed-width canonical
  child-lookup table under a distinct media type. Entries sort by parent,
  full domain-separated SHA-256 component digest, and record ID; lookup uses a
  binary lower bound and then requires byte-exact parent and component matches,
  so digest collisions cannot change correctness. Validation reconstructs the
  table from exact record starts and requires byte-for-byte equality, rejecting
  omissions, duplicates, forged offsets, and alternate orderings before a
  lazy borrowed node view is exposed. V1 remains golden-compatible and
  validation-only. Compilation pre-admits retained lookup storage together
  with graph queues, record scratch, hard-link state, and the finish-time
  sorting copy under the aggregate working-memory ceiling. The slice passes 33
  unit tests, one doctest, strict all-target crate-local Clippy,
  warning-denied rustdoc, formatting, and independent adversarial review.
  Immutable backing-file opening/sealing, mapping lifetime, per-connection
  inode assignment, FUSE authority, and `FORGET` handling remain open, so
  `SBX-FS-02` remains unchecked.
- `84724b62a` — further foundation toward `SBX-FS-02`, `SBX-P0-08`, and
  `SBX-FS-07`: the generic Linux boundary now distinguishes transient fully
  sealed memfds from durable fs-verity files and lends a read-only shared
  mapping only through a consuming higher-ranked callback. Safe code cannot
  let mapped bytes or lifetime-bound device/inode diagnostics outlive the
  mapping. Memfd admission requires the complete write/grow/shrink/seal set;
  `F_SEAL_FUTURE_WRITE` and ordinary read-only files are insufficient. Durable
  path adoption opens once beneath a pinned root, requires an independently
  authenticated SHA-256 or SHA-512 fs-verity measurement, and measures, maps,
  re-observes, and remeasures that same descriptor. Exact expected length and
  the mapped-byte ceiling are checked before `mmap`; unlink does not revoke an
  existing pin, and verity corruption on a later page fault is explicitly a
  worker-fatal `SIGBUS`, not a recoverable Rust error. The boundary remains
  independent of filesystem object semantics and includes fixed Linux 6.18
  flexible-ioctl layout assertions. The slice passes 40 Linux unit tests, one
  compile-fail lifetime doctest, strict crate-local all-target Clippy,
  warning-denied rustdoc, formatting, and independent adversarial review.
  Publisher enable/fsync/no-replace/catalog transactions, successful VM
  fs-verity exercise, mapped-byte reservation pins, worker composition,
  quarantine recovery, and FUSE lifecycle remain open.
- `5e1e33c6d` — further foundation toward `SBX-FS-02`: a V2-only
  connection-scoped inode table now pins root at node 1, assigns monotonic
  never-reused node IDs after positive lookup, retains no state for negative
  lookup, coalesces only validated hard-link groups, and keeps identical
  ungrouped records distinct. Two explicit fixed-slot maps preserve the live
  node/semantic bijection using a producer-unpredictable per-connection keyed
  hash plus exact semantic comparison. Live load is bounded at one half and
  occupied-plus-tombstone load at three quarters, preventing chosen clustering
  and per-operation churn rebuilds. Growth and compaction pre-admit old plus
  replacement storage, incorporate the allocator-returned first capacity
  before the second allocation, and commit only after both actual capacities
  fit. Aggregate lookup references have their own ceiling. Bounded batch
  `FORGET` sorts and coalesces caller scratch without allocation, preflights
  every reverse-map removal and counter, then applies atomically with no
  fallible mutation branch; stale, zero, over-forget, duplicate-overflow, and
  mixed-invalid batches leave inode state unchanged. Public node views remain
  tied to a validation-proof borrow while the private retained lifetime is
  available only to the table that owns that proof. The slice passes 41 unit
  tests, one compile-fail doctest, strict crate-local all-target Clippy,
  warning-denied rustdoc, formatting, and independent adversarial review. Open
  handles, kernel FUSE framing/conformance, mapped-byte reservations, and
  worker lifecycle remain open, so `SBX-FS-02` remains unchecked.
- `75dba477c` — further foundation toward `SBX-FS-02` and `SBX-FS-04`:
  the connection-scoped inode table now reserves bounded file-open identities
  before external backing work, transitions them explicitly from pending to
  active, and pins zero-lookup-reference nodes until abort or final release.
  Typed handles carry a redacted unique-connection brand while fixed slots and
  the future FUSE wire retain only monotonic, never-reused raw integers; raw
  values become typed only after lookup in the authoritative connection table.
  Foreign branded handles, forged or replayed reservations, pending-as-active,
  stale, and double-release transitions fail closed. A third fixed-slot map has
  an independent live-handle ceiling and participates in retained plus
  replacement heap admission. Allocation, growth, compaction, abort, release,
  and final inode reap preflight every fallible counter and reverse-map check
  before mutation. Dropping a pending token deliberately leaves a bounded pin
  until connection teardown. Sustained churn, exact tombstone reuse, foreign
  handle collisions, allocation and replacement peaks, and injected pin,
  pending-counter, and reverse-map corruption are covered by 52 unit tests.
  The slice also passes one compile-fail doctest, strict crate-local all-target
  Clippy, warning-denied rustdoc, formatting, and independent adversarial
  review. Directory handles, semantic content access, kernel FUSE framing,
  broker-owned backing registration, and worker lifecycle remain open, so
  `SBX-FS-02` and `SBX-FS-04` remain unchecked.
- `b326cce76` — package-only foundation toward `SBX-P0-11` and `SBX-FS-03`:
  libfuse 3.18.2 is now built hermetically from its pinned release source as a
  Linux-only AOS package. The output contains the shared library, complete
  public headers, and package metadata, but no mount helper, setuid program,
  utility, init script, udev rule, policy file, or static archive. Its exact
  file and symlink manifest, `libfuse3.so.4` SONAME, `FUSE_3.17` custom-I/O and
  passthrough symbol versions, compatible low-level declarations, and exact
  self-plus-glibc runtime closure are checked. The final closure is 14,974,648
  bytes and all five focused package/VM gates pass. The package is
  LGPL-2.1-only; GPL-only utility sources are neither built nor installed.
  This deliberately does not select libfuse as the production authority
  boundary: broker-supplied custom-FD INIT/teardown ownership, exact AOS Linux
  6.18.33 UAPI parity, cancellation behavior, and comparative resource and
  latency measurements remain required. A full repository eval was stopped
  after expanding into hundreds of unrelated rebuilds, and the existing
  package-platform-support check remains blocked by unrelated excluded-resource
  inventory failures. `SBX-P0-11` and `SBX-FS-03` remain unchecked.
- `17162fea3` — further foundation toward `SBX-FS-02`: structural-index V3
  preserves the locked V1/V2 record and lookup bytes under a distinct media
  type, then adds a canonical fixed-width directory table with authenticated
  root and per-occurrence link counts. Validation reconstructs exact parent,
  sibling order, record start, record ID, and `nlink` bytes after hard-link
  semantics pass. Borrowed directory ranges perform two binary searches and
  support allocation-free O(1) ordinal seek; exact link count is one range
  search plus a verified direct slot. Graph compilation now emits V3 while
  legacy builders remain test-only for golden compatibility. Builder-local and
  graph-aggregate ceilings cross one API: requested storage is admitted before
  allocation, actual entry, record-scratch, lookup, directory, and hard-link
  capacities are checked before the next allocation or write, and the actual
  finish peak returns to the compiler summary. A checked 248-byte stack encoder
  writes the header last. Forced-capacity and refusal tests prove both local and
  aggregate boundaries, alongside empty, foreign, high-fanout, reversed walk,
  cross-parent hard-link, output-limit, version/media, reserved-field, ordering,
  offset, ID, and link-count cases. The final direct workspace-toolchain run
  passes 62 unit tests, one compile-fail doctest, strict Clippy, warning-denied
  rustdoc, and formatting; the final project-shell rerun was interrupted after
  its shared Nix eval cache remained busy without reaching Cargo. Borrowed
  semantic body views, FUSE cookies/`READDIRPLUS`, target-ABI link-count
  translation, directory handles, and worker lifecycle remain open, so
  `SBX-FS-02` remains unchecked.
- `1c622188c` — mechanically splits the structural-index implementation into a
  72-line public facade and focused builder, validation, borrowed-view, wire,
  and test modules before further filesystem work. Public and crate-visible
  paths, all 95 production declarations, all 114 production functions, all 33
  test helpers, and V1/V2/V3 golden bytes and digests remain unchanged. The
  only visibility expansion is sibling-private `pub(super)` access inside the
  private index module. The refactor passes 62 unit tests, one compile-fail
  doctest, strict Clippy, warning-denied rustdoc, scoped formatting, and an
  independent adversarial inventory comparison. Explicit imports and a leaf
  wire layer remain desirable cleanup; the current production modules are each
  below the repository's 1,000-line design signal.
- `5b0479e51` — further qualifies the package-only `SBX-P0-11` and
  `SBX-FS-03` foundation. Independently compiled reports now require libfuse
  3.18.2's private protocol header and the AOS Linux 6.18.33 UAPI to agree on
  ABI 7.45, input/output and INIT layouts, passthrough flags, backing ioctls,
  and the signed backing identifier. A helper-free socketpair gate uses public
  custom I/O and the public owning session loop to inject an exact extended
  INIT request, verify the exact 80-byte response and passthrough stack-depth
  negotiation, cover rejected handoff paths, bound blocking waits, and prove
  accepted-descriptor closure plus one destroy callback. The final fixed-up
  package tree is compared as a NUL-delimited exact manifest, including
  symlink targets and target-platform metadata, with independent traversal
  failures and special files rejected. All seven package, ABI, protocol,
  SONAME, symbol, link, closure, and manifest gates pass under the hermetic AOS
  package set, followed by independent adversarial review. This does not test
  a real `/dev/fuse`, count internal `close(2)` calls, issue backing ioctls, or
  prove kernel passthrough I/O; those broker and VM gates remain open, so
  `SBX-P0-11` and `SBX-FS-03` remain unchecked.
- `63dd51aec` — further foundation toward `SBX-FS-02`: authenticated V1,
  V2, and V3 records now expose allocation-free borrowed directory, symlink,
  whole-file, sparse-file, extent, xattr, ACL, hard-link, descriptor, and
  logical-size semantics without materializing the owned portable model or
  changing any wire byte. Returned lifetimes remain bound to the non-cloneable
  validation proof. V1 root offsets, V2 point-lookup slots, and V3 canonical
  directory slots independently authenticate node identity before every fixed
  field and the exact record bytes are compared and reparsed. Forged artifact,
  ID, offset, parent, depth, ordinal, kind, mode, identity, timestamp, name,
  and record-body handles fail across all formats. Counts, lengths, slices,
  ACLs, sparse arithmetic, descriptor roles, and trailing bytes fail closed.
  A single-threaded harness-free allocator instrument proves public semantic
  authentication, parsing, and iteration perform zero allocation. The slice
  passes 66 unit tests, the allocator binary, two compile-fail lifetime tests,
  strict Clippy, warning-denied rustdoc, scoped formatting, and two independent
  adversarial reviews. FUSE cookie translation, borrowed presentation mapping,
  inode-to-record access, connection dispatch, and kernel realization remain
  open, so `SBX-FS-02` remains unchecked.
- `c24786738` — further foundation toward `SBX-FS-02` and `SBX-FS-03`:
  portable component validation now accepts borrowed kernel/protocol bytes
  without allocation and is the single implementation used by owned names.
  Exact byte lookup retains full-digest partitioning and byte comparison, while
  the inode table exposes the same borrowed path. A `LiveInode` capability
  reauthenticates the record against V2/V3 format structure, recomputes its
  semantic identity and keyed reverse mapping, and immutably borrows the table
  while record, semantic, or V3 directory views exist. Parent lookup, semantic
  reuse, `getattr`, file-open reservation, and active-open observation all use
  that same proof; same-artifact record substitution fails before references,
  pins, handles, heap, or monotonic IDs change. Pending reservations expose a
  raw reply identity without transitioning state; the originating table still
  resolves it as pending, active after activation, or stale after abort. The
  slice passes 140 core tests, 74 filesystem tests, the harness-free allocator
  binary, seven compile-fail doctests, strict Clippy, warning-denied rustdoc,
  scoped formatting, and independent adversarial review. Directory-handle and
  cookie state, borrowed presentation translation, worker dispatch, and the
  real kernel connection remain open, so neither task is checked.
- `b59a71d8c` — mechanically splits the connection inode implementation before
  directory-handle state is added. The 873-line facade retains shared node,
  lookup, `FORGET`, accounting, and public contracts; a 573-line module owns
  file-open identities and transitions; a 215-line module owns the keyed
  node/semantic fixed-slot maps; and the existing test corpus moves separately.
  Public paths, declarations, functions, constants, hash domains, probing,
  rehashing, test-only refusal hooks, all 27 inode tests, and compile-fail
  lifetime proofs remain unchanged. The refactor passes all 74 filesystem
  tests, the allocator binary, six compile-fail doctests, strict Clippy,
  warning-denied rustdoc, scoped formatting, and independent inventory review.
  Explicit imports in the open module remain cleanup debt; directory-handle
  implementation and worker composition remain open.
- `d8568ef71` — further foundation toward `SBX-FS-02` and `SBX-FS-03`: the
  connection inode table now provides opt-in, separately bounded directory
  handles whose raw identities share the file-handle monotonic namespace.
  Non-copyable authenticated reservations pin their inode before external
  work, then activate or abort explicitly; branded active handles reject
  foreign, pending, stale, and wrong-kind use. Each handle caches a
  reauthenticated V3 ordinal range and exposes allocation-free, stateless
  `READDIR` iteration with exact dot, dot-dot, child, and EOF cookies, including
  signed-offset and target-`usize` bounds. Directory, aggregate-handle, and
  retained-plus-replacement heap ceilings fail before mutation; release
  preflights range identity, reverse maps, pins, counters, and reap state.
  High-fanout and byte-name pagination, rewind, V2 rollback, ID sharing,
  allocation refusal, churn, tombstones, `FORGET`, corruption, and connection
  teardown semantics pass 80 filesystem tests, the harness-free allocator
  binary, seven compile-fail doctests, strict Clippy, warning-denied rustdoc,
  scoped formatting, and independent adversarial review. Attribute
  presentation, protocol dispatch, and a real kernel FUSE connection remain
  open, so neither task is checked.
- `c50405864` — further foundation toward `SBX-FS-02` and `SBX-FS-03`: a
  validation-scoped sequential iterator exposes every V1/V2/V3 record without
  allocation, and a V3-only prepared-presentation capability scans the exact
  immutable index before worker readiness. Admission bounds retained identity
  map capacity, records, and aggregate ACL entries; validates every owner and
  named qualifier; preserves translated ACL canonical order; and narrows every
  authenticated link count to the target FUSE ABI. Identity maps validate
  disjoint destination ranges in place in `O(n log n)`, restore portable order
  for binary lookup, and allocate no scratch. The cache identity binds the
  exact index descriptor, identity/ACL plan, generation, and policy digest,
  while live user-namespace descriptors, mount flags, and kernel ACL proof
  remain connection-local broker state. Hot record authentication, attributes,
  xattrs, and lazy ACL translation allocate nothing and reject same-artifact
  structural/scalar substitution. The slice passes 86 filesystem tests, the
  harness-free allocator binary, eight compile-fail doctests, strict Clippy,
  warning-denied rustdoc, scoped formatting, and independent adversarial
  review. FUSE protocol dispatch, connection ownership, cancellation, backing
  registration, and kernel runtime proof remain open, so neither task is
  checked.
- `315e57b22` — strengthens executable evidence toward `SBX-P0-04` and
  `SBX-P0-05` without claiming runtime completion. The nspawn fleet proof now
  launches through retained root and executable descriptors, uses a prepared
  default-drop network namespace and shifted user namespace, masks machined,
  and asserts hostile settings are absent. A bounded host observer owns
  recursive payload discovery and retains supervisor, payload, root, cgroup,
  and namespace descriptors; Linux 6.18 `PIDFD_GET_INFO` binds thread-group,
  parent, cgroup, executable, command markers, and liveness before publication,
  before action, and after transition. Internal reboot is requested only
  through the retained payload pidfd. The prior namespace generation remains
  pinned until a distinct successor is fully authenticated under the same
  supervisor, root, network, and cgroup boundary. Discovery has per-scan work
  ceilings and one `CLOCK_BOOTTIME` deadline, and signal waiting is race-free.
  Exact fleet evaluation, hermetic warnings-as-errors C builds, generated unit
  and Python construction, Alejandra, diff checks, and three adversarial repair
  rounds pass. The VM body has not run on x86_64 or aarch64, and the proof is
  still not the production transient-unit, full-argv, MAC, or guardian path;
  therefore both tasks remain unchecked.
- `38fb4bab7` — further foundation toward `SBX-FS-02` and `SBX-FS-03`: a
  backend-neutral single-connection metadata worker now composes the exact V3
  index, prepared presentation, inode table, directory handles, and reusable
  reply scratch. INIT-gated typed operations cover lookup, batch `FORGET`,
  `GETATTR`, `READLINK`, two-phase `OPENDIR`, stateless paged `READDIR`, and
  `RELEASEDIR`; mutation, file-data, xattr, and `READDIRPLUS` requests fail
  through a closed error vocabulary. Per-connection and per-request entry,
  variable-byte, typed-output, scratch-heap, and `FORGET` ceilings fail before
  allocation or attacker-sized sorting. Lookup performs all presentation,
  budget, and cancellation work before its final fallible inode commit.
  `FORGET` uses an exclusive non-replayable prepared transaction whose final
  cancellation check is immediately followed by one infallible mutation.
  `READDIR` copies only complete fitting records, retains the prior cookie when
  the next record does not fit, preserves byte names, and never interns
  children. The allocator harness proves zero-allocation hot metadata paths;
  90 filesystem tests, ten compile-fail doctests, strict Clippy,
  warning-denied rustdoc, scoped formatting, and independent adversarial repair
  pass. This core neither parses FUSE wire records nor owns a kernel connection,
  cancellation carrier, backing descriptor, or external resource, so
  `SBX-FS-03` remains unchecked.
- `e02d1f2e9` — further foundation toward `SBX-HOST-01`, `SBX-RT-06`, and
  `SBX-LIFE-06`: the typed systemd client now discovers the complete canonical
  sandbox-unit namespace in two independently collected, uncached passes.
  Exact lowercase nonzero incarnation names, listing filters, aliases, object
  paths, `Unit.Id`, invocation IDs, cgroups, supervisor PIDs, freezer and unit
  states, duplicates, jobs, strings, properties, units, and aggregate decoded
  bytes are bounded and cross-checked. Prefix lookalikes retain their complete
  bounded raw listing row as explicit conflict evidence, while canonical units
  unknown to the caller's stable expected identity set become quarantine
  evidence; missing and matched results are deterministic. Reload, transport,
  disappearance, substitution, or any two-pass mismatch returns a typed
  indeterminate outcome requiring rescan. The API documents that zbus performs
  typed allocation after its outer message ceiling and that equal passes cannot
  exclude ABA; snapshots remain observation only and cannot authorize adoption,
  kill, or another lifecycle effect. Ten unit and 25 hostile D-Bus integration
  tests, strict Clippy, warning-denied rustdoc, formatting, and independent
  adversarial repair pass. Host-state reconciliation and production lifecycle
  action remain open, so all three tasks stay unchecked.

- `9af29efe8` — closes a restart-identity ambiguity toward `SBX-HOST-01`
  and `SBX-LIFE-06`: current fences and retained request history reserve each
  incarnation to exactly one sandbox. Admission rejects a collision before
  persistence or effects, and authenticated broker startup rejects collided
  history assembled from otherwise valid sealed records. Same-sandbox history
  remains legal, while advancing to a successor does not release the old
  incarnation for another sandbox. All 68 host unit tests, one integration
  test, scoped strict Clippy, rustdoc, and formatting pass. Dependency-wide
  Clippy encounters master's generated Hub `HashMap` lint errors in
  `aos-proto`; the scoped check uses `--no-deps` and does not waive host lints.
- `a77927576` — further adapter work toward `SBX-FS-03`: explicit synchronous
  OPENDIR commit-after-reply semantics share the existing activation logic.
  The adapter publishes the pending raw handle, activates only after success
  and before another dispatch, and treats any post-reply activation error as
  fatal without cancellation, retry, or a second reply. Failed publication
  instead aborts the pending reservation. All 92 filesystem unit tests, the
  allocator harness including post-reply activation, ten compile-fail
  doctests, strict Clippy, rustdoc, and formatting pass. The external reply
  remains an adapter-owned ordering obligation, not a fact the core can prove.
- `4da505397` — closes metadata-adapter gaps toward `SBX-FS-03`: directory
  requests can validate the kernel-supplied inode/handle association before
  reading or releasing state, including after the last lookup reference is
  forgotten while an open pin remains. Ordinary singleton `FORGET` uses the
  same bounded atomic preflight as batching without requiring the optional
  batch feature. Wrong, pending, stale, and replayed identities, failed
  admission, underflow, and cancelled precommit retain their state. All 91
  filesystem unit tests, the allocator harness exercising these APIs, ten
  compile-fail doctests, strict Clippy and rustdoc, and formatting pass using
  the realized AOS development environment. Real transport and kernel
  integration remain open.
- `28e7d6180` — merges master while preserving the sandbox Linux UAPI build
  check alongside master's bootstrap, cross-platform, and image checks. That
  merge renamed the sandbox RFC from RFC-0019 to RFC-0020 because master
  assigned RFC-0019 to OCI containers. The RFC is now RFC-0021. Directory
  links and textual RFC references changed; portable protocol identifiers,
  wire versions, and golden commitments did not.

- `38d22a948` — implements the narrow C transport library toward `SBX-FS-03`
  using packaged libfuse public APIs. A fixed-width versioned ABI carries
  synchronous borrowed callbacks and bounded scalar/buffer outputs; the
  library borrows the caller's FUSE descriptor and owns a close-on-exec
  duplicate. A single-threaded loop bounds metadata reply storage, qualifies
  INIT, preserves complete directory records and progressing cookies, and
  terminates on failed or partial record writes, malformed successful core
  outputs, fatal callbacks, and invalid OPENDIR responder use. Fatal batch
  FORGET fallback suppresses later core calls. Reply writes use absolute
  `CLOCK_BOOTTIME` deadlines while idle receive remains cancellation-aware
  without expiring an unused mount. Argument storage, descriptors, and callback
  teardown have explicit ownership. Adversarial fixture tests, exact closure
  and output manifest checks, installed link/ABI, exported-symbol and SONAME
  Firecracker tests, Nix parsing, and scoped Alejandra pass after independent
  review and repairs. Successful protocol fixtures use trusted socket records;
  a real `/dev/fuse` mount, cross-identity kernel permission proof, Rust adapter,
  file data, and worker process integration remain open. No task is checked
  from the library alone.

- `0646bf819` — qualifies protected journal creation, locking, compaction,
  and replay under actual UID/GID 1000 in an AOS Linux 6.18.33 VM, with cleared
  supplementary groups. Exact error checks reject a second live opener,
  UID/GID 1001, and an otherwise private leaf beneath writable ancestry.
  The unpublished fixture uses declared AOS protobuf generation and AOS
  coreutils credential switching while preserving the guest's root directory.
  Independent review, scoped Clippy/formatting, hermetic build, and headless
  runtime pass. Result: `jdijqmzicwl6wwvav3d3rhkmyrkdskgf-aos-vm-test-sandbox-service-journal-0`.
- `00dfcc4e4` — qualifies no-replace naming on the same AOS kernel. Exact
  `SameName` and `DestinationExists` errors preserve ownership and conflicting
  files; retry to a free basename succeeds. Final inode/bytes/measurement match,
  the private name returns `ENOENT`, final backing admission succeeds, and a
  writable open returns `EPERM`. All seventeen materialization/naming assertions
  and prior capability/fake-FUSE/backing proofs pass after independent review.
  Result: `i9axckxkz2kaizgszd7v42bhwwzg1n9n-aos-vm-test-sandbox-filesystem-kernel-capabilities-0`.
  Real power-loss recovery, authoritative catalog integration, and aarch64
  qualification remain open.
- `6ca7dccf6` — adds same-directory no-replace naming for sealed private files.
  Private and every returned success/error token borrow the actual creating
  root, keeping its descriptor alive rather than relying on numeric identity.
  Exact `EEXIST` is a pre-effect conflict; other rename errors are explicitly
  ambiguous. Post-rename errors retain the inode pin and both candidate names.
  Parent fsync is bracketed by exact name/inode/measurement validation. No
  failure deletes, adopts, rolls back, or commits catalog authority. All 56
  Linux unit tests, eight ownership doctests, strict Clippy, rustdoc, and
  independent review pass; the fault seam checks post-rename ordering and
  stopping behavior. Positive real-kernel naming and crash-recovery qualification
  remain separate gates.
- `6178aa02a` — qualifies adversarial proof provenance and fresh-inode sealing
  on AOS Linux 6.18.33 x86_64. An unprivileged ordinary FUSE daemon fabricates
  a complete measurement accepted by the coordinator's raw ioctl; both Rust
  admission APIs reject its filesystem before another measurement request.
  Exact counters prove one ioctl, two STATFS, three ordinary opens, zero READ,
  and no backing registration. The materialization fixture verifies all twelve
  creation assertions, including independent streamed descriptor verification,
  fresh inode identity, source-offset preservation, verified backing reopening,
  exact `EPERM`/`EEXIST` outcomes, quota-before-create, and retained unsealed
  callback failures. All original capability/backing proofs remain passing.
  Strict GCC, scoped Clippy/rustdoc/formatting, and independent review pass.
  Result: `i2sqah03hmvs9dsrfxhyv82nwpavqgz5-aos-vm-test-sandbox-filesystem-kernel-capabilities-0`.
  Canonical naming, publisher catalog/authority, and aarch64 remain open.
- `403bd0085` — implements fresh private-inode materialization and sealing
  beneath a retained, exact-service-owner 0700 kernel-filesystem root. Bounded
  positional copying preserves the source offset, checkpoints read/write
  retries, and feeds only fully written chunks to caller verification. The
  writable destination never escapes; data sync and same-inode read-only
  reopen precede writer closure, fixed SHA-256/4096 fs-verity enablement,
  measurement rechecks, and inode/directory fsync. Every post-create failure
  retains non-authorizing artifact evidence for recovery; no cleanup, adoption,
  replacement, or canonical publication is performed. All 54 Linux unit tests,
  four ownership doctests, strict Clippy, rustdoc, and independent review pass.
  Positive real-kernel creation and publisher authority integration remain open.
- `c4e801616` — qualifies the public Rust owned-backing and mapping admission
  APIs on exact AOS Linux 6.18.33 x86_64. The narrow unpublished fixture verifies
  bytes, EOF, identity, mapping compatibility, and retained-pin reads after
  unlink, and rejects wrong measurements/sizes, exceeded ceilings, symlinks,
  and unsealed same-content files. The existing fs-verity/passthrough proof
  continues to pass. Independent review, scoped build/lint/format checks, and
  installed linkage checks pass; runtime dependencies are only AOS libc and
  its loader. Result:
  `pgpcl9lp5mkb9z3xgxn7jzdb0c0hn5iz-aos-vm-test-sandbox-filesystem-kernel-capabilities-0`.
  This does not prove publisher authority, aarch64 behavior, or the adversarial
  emulated-verity FUSE runtime case.
- `dece711df` — opens protected journals for a configured dedicated service
  UID without exposing the ancestry-skipping test helper. Rooted no-symlink
  traversal admits root ancestors followed by a one-way transition to the exact
  service owner; writable ancestors and ownership reentry fail closed. The
  final directory remains exact-owner 0700 and all retained-directory journal,
  lock, and replacement checks remain exact-owner 0600. UID zero preserves the
  root-only boundary. All 132 sandbox unit tests (including 24 journal tests),
  strict scoped Clippy, warning-denied rustdoc, and independent review pass.
  Real service-UID VM qualification remains open; no credential change,
  authenticated ownership assertion, or rollback protection is implied.
- `81247127a` — adds owned, read-only fs-verity backing admission without
  mapping the full file. Exact-size ceilings precede opening; filesystem type,
  measurement, size, and identity are checked on the same pinned descriptor.
  Both backing and existing mapping admission now reject forwarded/emulated
  ioctl proofs: only audited kernel ext4, Btrfs, and F2FS implementations are
  admitted. Regular-file candidate opening is nonblocking and cannot acquire
  a controlling terminal before type rejection. All 47 Linux unit tests, four
  ownership doctests, strict scoped Clippy, rustdoc, and independent review pass.
  This is not publication/disclosure authorization, revocation, or positive
  real-kernel Rust backing admission evidence.
- `f72bbee84` — adds a bounded incremental verifier for the exact existing v1
  object-descriptor framing. It retains no payload, rejects overrun before
  hashing, permanently poisons on length failure, and checks exact length and
  digest at completion. One-shot golden framing remains unchanged. All 145
  core unit tests, one doctest, strict Clippy, rustdoc, and independent review
  pass. Full-file publisher effects and authority remain open.
- `9b0820b33` — qualifies the actual Rust metadata worker toward `SBX-FS-03`
  on AOS Linux 6.18.33 x86_64. A narrow, unpublished fixture compiles a canonical
  tree, validates its index and presentation, and calls the public scoped runner
  on inherited FUSE/cancellation descriptors. The existing C mount/client
  coordinator transfers only the three selected non-stdio descriptors across
  exec. Real-kernel metadata, identity/mode/size/link-count/timestamp semantics,
  stable pinned lookup identity, cross-UID DAC, read-only behavior, idle
  survival, cancellation, borrowed descriptor retention, worker exit,
  disconnection, and normal unmount pass. The Rust proof deliberately omits
  unobservable callback/release/destruction counts. The original C gate also
  passes after the coordinator changes. Independent review and formatting pass;
  the fixture runtime closure contains only itself, transport, libfuse, and
  glibc. Result: `dd9f2622xafcd7m9cqfx5myic5ppjaya-aos-vm-test-aos-fuse-transport-kernel-rust-metadata-0`.
  File-data operations, production broker integration, and aarch64 remain open.
- `52e220a01` — repairs master-integration drift in existing OCI migration
  tests without changing production migrations. Uniqueness-checked SQL markers
  select the intended migrations independently of insertion order; the
  concurrent-upgrade fixture derives its pre-GC boundary and terminal version.
  All six focused schema, dialect, concurrency, and replay regressions pass.
- `cf3138c2b` and `1b4978377` — move metadata ABI representability failure
  before FUSE initialization. Backend-neutral prepared-presentation admission
  bounds the record scan before traversal and checks translated scalar IDs,
  link counts, sizes, rounded allocation units, timestamps, names, symlink
  targets, and directory cookies, including synthetic `.` and `..` names.
  The connection delegate checks cancellation/deadline before work, on each
  record, and at completion. The Linux adapter supplies exact C scalar ranges
  and an independent startup-record ceiling before INIT or C entry; dynamic
  inode IDs require a full-width `ino_t` independently of the immutable scan.
  All 95 core unit tests, the zero-allocation harness, ten core doctests, ten
  adapter fixtures and its ownership doctest, strict scoped Clippy, rustdoc,
  formatting, and independent adapter review pass. No publication-proof cache
  or detached authorization token is introduced.
- `e92a74fe6` — real-kernel qualification toward `SBX-FS-03`: a fixed metadata
  fixture links the installed C transport and mounts `/dev/fuse` in a private
  mount namespace. The headless Firecracker gate passes on AOS Linux 6.18.33
  x86_64, proving metadata/directory/symlink operations, kernel-reported mount
  flags, cross-UID DAC with dropped credentials, read-only enforcement, idle
  survival, cancellation, borrowed descriptor retention, exactly-once destroy,
  disconnected-mount behavior, and normal unmount. The same C probe has a
  full-system fleet test, whose runtime result remains pending. This is neither
  real-kernel Rust-worker evidence nor aarch64 qualification. The passed result
  is `cjzf7m6x3gnfqrzq01lw9ggfan286im3-aos-vm-test-aos-fuse-transport-kernel-metadata-0`.
- `b619f4e29` — connects the metadata worker to the installed transport through
  a Linux-only Rust adapter toward `SBX-FS-03`. Its safe runner consumes the
  connection and borrows scratch, presentation/index storage, and descriptors
  for one synchronous call. The private C ABI checks layout and bounded buffer
  conversions; callback panics poison the connection and never unwind into C.
  OPENDIR commits only after successful reply publication. Failed FORGET or
  RELEASEDIR discards the connection because kernel cleanup is not retryable.
  Typed-page and wire-byte budgets remain distinct, and neither can silently
  produce false EOF. Seven fixtures, the ownership compile-fail doctest,
  strict Clippy, warning-denied rustdoc, formatting, and independent review
  pass. A separate consumer verifies installed dynamic linkage and exact runtime
  search paths with `LD_LIBRARY_PATH` unset. Hermetic test build inputs and the
  development shell include the transport without expanding unrelated installed
  CLI runtime closures. Real-kernel Rust-worker qualification, whole-index ABI
  admission, data reads, and process integration remain open.
- `dc3d9599c` — prevents false directory EOF when a nonempty metadata page
  cannot fit its first complete packed FUSE record. Zero- and one-byte request
  buffers return `EINVAL`, and a later adequate buffer still returns the
  expected progressing cookies. The fake-core regressions, installed link,
  exported-symbol, SONAME, and exact runtime-closure checks pass.
- `98fdc84af` — further work toward `SBX-HOST-01` and `SBX-LIFE-06`: the host
  broker joins authenticated durable witnesses and retained obsolete-incarnation
  history with a structurally revalidated systemd discovery snapshot. Reports
  distinguish current matches, missing current units, historical residuals,
  unobserved history, unknown-unit quarantine, and raw prefix conflicts. Intent
  and durable receipt status remain separate from observed runtime state. The
  join performs no worker calls, does not establish snapshot provenance, and
  cannot authorize adoption or cleanup. Shared canonical unit-name parsing and
  conflict-job regressions align validation with the discovery producer. All
  74 host unit tests, one host integration test, ten systemd unit tests, 25
  D-Bus integration tests, scoped strict Clippy, warning-denied rustdoc, and
  formatting pass. Full boot reconciliation remains open.
- `ab50360bc` — repairs the existing container-publication test fixture after
  master added deployment and release-evidence fields to `AppState`. Its
  complete test target compiles through the realized AOS development shell.
  This removes a package-build blocker; it is not VM runtime evidence.
- `95bdfb35c` — foundation toward `SBX-NET-01`: a protected node-local policy
  catalog resolves exact portable Network profiles, endpoint commitments, and
  collision-resistant reserved namespace handles under signed assignment
  authority. No kernel effect or inventory is claimed.
- `6cf194000` — foundation toward `SBX-NET-01` and `SBX-LIFE-06`: Network
  preparation now retains authenticated Prepared, Ambiguous, and Committed
  effect phases, making restart recovery observation-only after an effect may
  have occurred.
- `94b21b0b2` — foundation toward `SBX-NET-01` and `SBX-LIFE-06`: exact
  committed preparations can publish kernel-verified, pinned, default-drop
  namespaces into a protected current-resource catalog and authoritative
  current-boot inventory.
- `0772770f3` — foundation toward `SBX-NET-01` and `SBX-LIFE-06`: the packaged,
  systemd-activated Network service exposes authenticated read-only inventory
  through protocol 1.2 while continuing to withhold Apply.
- `4cb0100c0`, `462567f52` — foundation toward `SBX-NET-01` and `SBX-LIFE-06`:
  protected Network rows retain monotonic arm, renewal, fence, disarm, and
  irreversible retirement state, with each transition bound to an exact typed
  helper-reported postcondition and lease tuple. Kernel mutation dispatch and
  guardian scheduling remain open.
- `e0f4e011e` — foundation toward `SBX-NET-01`, `SBX-POL-01`, and
  `SBX-NET-02`: Network preparation retains bounded typed packet programs,
  canonical endpoint flows, and fixed enforcement and lease-gate artifact
  commitments. Address and link allocation and kernel effects remain open.

The headless `checks.vm.sandbox-filesystem-capability` gate now passes on
x86_64 AOS Linux 6.18.33, independently of full-system services. It qualifies
fs-verity enable/measurement, exact `EPERM` denial of writable opens, and FUSE
7.45 backing-file registration with successful passthrough reads and zero
userspace READ requests. Qualification repaired the probe's explicit verity
block size and negotiated FUSE receive-buffer contract; both harnesses use
4 KiB ext4 blocks. The passed result is
`a5p54a08v9v6g2rma13blw5bxzcr2y54-aos-vm-test-sandbox-filesystem-kernel-capabilities-0`.
This does not establish aarch64 support, production backing authorization, or
full-system boot readiness; `SBX-P0-02` remains open.

The post-`727da7f3e` x86_64 `sandbox-filesystem-capability-proof` rerun built the
complete hermetic Rust closure, AOS system, initrd, and VM disk and launched
QEMU with KVM. The guest agent timed out before readiness with a blank serial
log, so the fs-verity/FUSE runtime body never executed and `SBX-P0-02` remains
open. This is recorded as a VM boot-boundary failure, not capability evidence.

The subsequent pre-merge rerun
(`s69hf4byw1z836lmagab4b1jw9b32f1h-aos-fleet-test-sandbox-filesystem-capability-proof-0.drv`)
also timed out before the test body. Inspection of its retained full serial log
showed successful kernel boot followed by credential recovery rejecting the
offline `/sysroot` identity and entering initrd emergency mode; the printed
tail concealed the earlier failure. Master includes target-root symlink
resolution and Nix-overlay ordering fixes for this path. A post-merge runtime
rerun is required before either fix counts as platform evidence.

The post-merge run
(`rchvf07nymqvpb3ihp87af8ym7rk59cv-aos-fleet-test-sandbox-filesystem-capability-proof-0.drv`)
completed the hermetic AOS package build/check and reached full-system guest
readiness. Credential recovery succeeds in both initrd and the booted system.
The test body passed fs-verity and failed passthrough because its captured probe
predates `44e0abf1d`'s receive-buffer repair. That failure cancelled the sibling
metadata fleet gate after readiness. Its independent rerun now passes:
`gpxfkbl9xdb3bfjjzlg2i46iyfcrrf0r-aos-fleet-test-sandbox-fuse-transport-proof-0`.
The installed C transport therefore has both headless and full-system x86_64
metadata runtime evidence. This resolves the observed boot blocker, not the
complete filesystem capability fleet gate or dual-architecture qualification.

### Project publisher authorization checkpoint

- `6c40f8928` merges current master through `e1eedbfcf`, retaining the
  migration-order-independent fixture repairs. All six focused migration tests
  pass in the cached AOS development shell.
- `769028c30` completes `SBX-PUB-01`: project-only raw-content publication plans
  bind distinct publisher-instance/reservation identities, the complete content
  descriptor, source and request commitments, holder/channel, domain isolation
  policy, controller/policy/revocation/root-registry generations, byte ceilings,
  and validity. Canonical CBOR, fixed object/signature vectors, and an opaque
  non-cloneable verification result authenticate these exact static bindings.
  The new signature purpose/key usage is appended at portable code 6, while
  the independent publisher protocol starts at 1.0. Existing broker encodings
  and authenticated journal vectors remain unchanged; both broker formats
  reject publisher authority rather than acquire a publisher audience/code.

Validation for this checkpoint: 170 core and 19 broker unit tests, three
compile-fail doctests, scoped all-target Clippy with warnings denied, core
rustdoc with warnings denied, and both crates' formatting checks pass.
`cargo check --workspace --all-targets --locked` also passes, with unrelated
existing warnings. The cached master shell requires the realized AOS FUSE
transport's pkg-config directory supplied explicitly for that broad check;
no host library or substitute package was used. Independent model/schema and
verifier reviews found no remaining blocker.

This does not complete `SBX-CACHE-01`. Static verification cannot prove current
authority or authorize any materialization, rename, catalog, or read effect.
`SBX-PUB-02` next connects controller-resolved admission, the exact separate
request-hash preimage, retained completion permits, and durable resource state;
the service, protected root-registry integration, committed catalog visibility,
and real-service crash/revocation qualification remain explicitly open.

### Challenge-bound admission and protected-signing checkpoint

`d328e02db` advances `SBX-PUB-02` with the exact canonical admission preimage,
not an online authority service. The 11-field protocol request includes the
capability handle, logical cache resource, 32-byte publisher challenge, and all
proposed plan fields except the derived commitment. Construction and decoding
recompute that commitment; no self-referential hash or supplied commitment is
accepted. The decoder applies a fixed 32 KiB ceiling before allocation even
with permissive generic CBOR limits. Golden, truncation, bounds, and exhaustive
admissible-field mutation tests cover the exact preimage and resulting plan.

The controller's publisher signing preparation reuses its existing immutable
artifact, protected-signing-message, and returned-signature verification code.
The signed result remains opaque and non-cloneable and grants no effect
authority. A public-model integration path proves request → plan → protected
signing preparation → signature completion → core authentication → exact
request binding, including rejection when only capability, cache resource, or
challenge changes. Existing broker/lease preparation is unchanged.

This checkpoint passes 181 core and 136 controller unit tests, one controller
integration test, five compile-fail doctests, scoped strict all-target Clippy,
warning-denied rustdoc for both crates, changed-file formatting checks, and the
locked all-target workspace compile check. The latter retains unrelated
existing warnings and uses only the cached AOS environment/transport described
above. Independent request/codec/signing reviews found no remaining blocker.

`SBX-PUB-02` remains open. Inspection found no production capability lookup,
project-policy/revocation/source-authority store, publisher-instance registry,
or reservation ledger to attach to the existing injected controller compiler.
The next implementation must add those protected durable records and typed
admission methods around the controller's sole journal writer. The first
service flow authenticates publisher challenge registration separately from
the holder's request; forwarded channel hashes and publisher peer credentials
cannot substitute for holder possession. Challenge consumption, signed-decision
persistence, current-state rechecks, retained permits, reservation/residency
accounting, and authoritative completion/recovery evidence are still required.

### Protected capability-registry checkpoint

`SBX-PUB-02` now has a concrete controller-owned capability registry in journal
namespace 7. It persists full validated capability records under family-prefixed
immutable handles, with irreversible equal-size revocation tombstones. Loading
requires retained protected-opener provenance and validates the entire bounded
materialized registry. Subsequent lookups use the journal index directly instead
of retaining a second registry-sized map. Encoding is bounded while serializing,
not after constructing an unrestricted byte buffer. The controller exposes this
through an exclusive borrow of its sole journal writer.

This is trusted administration and durable lookup, not authenticated admission.
The facade must be the controller's sole writer for this namespace; generic
journal writes are trusted low-level operations, not a validated capability
transition protocol. Internal versioned JSON is not a portable network format.
Individual handle revocation does not replace policy/scope-generation checks or
cancel a retained completion permit. Durable append headroom for maintenance
still needs reservation before production admissions are enabled.

Adversarial review identified that an ambiguous journal write can leave old
materialized diagnostic values readable. Authority consumers now have an explicit
health guard: a failed revocation must deny reads even after facade reconstruction
until protected reopen/replay resolves durable state. Namespace scans use ordered
ranges so capability recovery does not walk unrelated desired-state records.
The same review found stale-read paths in existing authority-publication replay
and cached reconciler validation. Both now reject poisoned journals before replay,
authority lookup, or executor observation/application. Real append/compaction
failure tests cover facade reconstruction and cached/uncached reconciliation;
diagnostic journal getters deliberately retain their non-authoritative contract.

Project policy and revocation-generation heads, source-authority records,
publisher-instance/root registries, authenticated two-channel challenge matching,
reservation/residency accounting, retained permits, production services, and
runtime qualification remain required. `SBX-PUB-02` remains unchecked.

Validation: 149 controller and 181 core unit tests, one controller integration
test, and five compile-fail doctests pass. Scoped all-target Clippy with warnings
denied and changed-file formatting checks pass. The fixed internal record golden
is 1,068 bytes with SHA-256
`a7eb0f1c0e6306a04252c17046788aa1680081b4405fea31f8791c629982e331`.
Independent registry and existing effect-path reviews found no remaining blocker.
Warning-denied rustdoc and the locked all-target workspace compile check also
pass on `40f419b57`. The latter uses the cached AOS environment and realized AOS
FUSE transport pkg-config path, with unrelated existing workspace warnings.

### Current publisher policy and generation state

This `SBX-PUB-02` increment adds protected policy state in journal namespace
8, isolated from capability records while sharing the same atomic journal
transactions. Canonical resolved `Policy` bytes supply the real grants, resource
profile, and cache domain; their exact descriptor is derived, not accepted as a
claim. Project revisions and current heads update atomically under exact
compare-and-swap and checked contiguous generations. Replay retains and validates
the revision history instead of trusting a bare current-generation number.

Immutable logical cache-resource bindings select project, cache domain, and
isolation policy. Controller-authority and independent revocation-scope heads
have their own monotonic histories. The controller principal is the capability
audience and cannot be silently replaced during a generation update. This does
not register a publisher execution or a publication root. Current policy and
capability grants still need an authenticated, atomic admission evaluator;
capability validation alone does not compare policy digest or revocation scope.

Source-evidence review selected authenticated producer-output submission through
registered export slots as the first concrete ingress path. A release decision
must explicitly authorize submitted bytes entering the destination project
domain. Source path, FD possession, inode identity, and byte digest are not proof
of confidentiality or execution provenance. Source evidence must precede and
remain outside the request commitment that later cites it. The actual slot
registry, authenticated release-policy evaluation, durable evidence/lifetime,
and existing-object promotion path remain unimplemented; no administrative
source-digest installer substitutes for them.

Validation passes: 155 controller and 181 core unit tests, one integration
test, five compile-fail doctests, scoped strict all-target Clippy, warning-denied
rustdoc, changed-file formatting, and the locked all-target workspace compile
check. The latter uses the same cached AOS toolchain/transport and retains
unrelated existing workspace warnings. Fixed goldens cover all seven durable
record families, with malformed, truncated, and trailing-byte rejection. Replay
tests cover missing/orphaned history, substituted heads, principal rebinding,
generation exhaustion, CAS failures, and enforced input/store bounds. A real
failed-write regression denies every policy resolver until protected replay.
Independent implementation and source-boundary reviews found no remaining
blocker for this persistence increment. `SBX-PUB-02` remains unchecked.

### Authenticated local ingress integration

Master through `c6d076d48` is merged in `9ec715cad`. Its exact development
environment works offline; the merged workspace passes the locked all-target
compile check with the existing realized AOS FUSE transport pkg-config path.
Unrelated existing workspace warnings remain. This environment avoids rebuilding
the feature branch's packaged CLI for each incremental Cargo invocation.

The next local ingress increment adopts only listeners already configured for
kernel record credentials and PIDFDs, then checks those options independently on
every accepted child. Source inspection of Linux 6.18.33 and systemd 259.8 found
that enabling options after acceptance cannot establish the necessary
pre-connection invariant. The RFC's record-subject carrier now explicitly
requires listener activation (`Accept=no`) and rejects early unconfigured
connections without invalidating the healthy listener. This is transport
identity, not a principal registry, source-release decision, or admission grant.
Existing host/mount descriptor-passing transports remain a separate contract.

Their audit also found a numeric-PID reopening gap between `SO_PEERCRED` and
`pidfd_open`. Both now retain the socket's `SO_PEERPIDFD`; verification borrows
that unforgeable identity and reads fresh process/cgroup information. An accepted
peer that exits before identity capture is rejected without terminating the
service. The legacy connection remains delegable, and its ordered `SCM_RIGHTS`
protocol is unchanged. Per-record holder authentication is not inferred from
this migration.

Validation passes: 66 Linux-boundary, 76 host-broker, and 61 mount-broker unit
tests, two integration tests, twelve doctests, strict all-target Clippy for the
three changed crates, warning-denied rustdoc, changed-file formatting, and the
locked all-target workspace compile check. The workspace retains unrelated
existing warnings. New real-socket tests cover pre-accept messages, missing
options, stale queued children followed by usable connections, forbidden rights,
oversized records, unchanged flags during borrowed peer capture, and descriptor
cleanup. Safe subprocess fixtures prove a live delegated writer differs from
the connector and a reaped connector yields `ESRCH` despite a retained live
client endpoint. Actual host and mount services reject stale connectors and
handle the next connection without backend effects. Compile-fail tests reject
fabricated credential records and escaping borrowed peer proofs.

These kernel tests ran on host Linux 6.18.44. The exact AOS Linux 6.18.33 source
was inspected for option inheritance, but these new tests are not yet AOS VM or
dual-architecture qualification. Production principal/session mapping, registered
source ingress, and online publisher admission remain open; `SBX-PUB-02` is not
checked by this transport increment.

### Retained cgroup scope for local identities

The Linux boundary now admits only genuine cgroup-v2 directories into typed
resolution roots and retained anchors. The supported 64-bit profile preserves
the full kernfs ID reported by PIDFD information. Fresh `cgroup.procs` opens
observe active kernfs state; directory link counts cannot substitute for them.
Exact membership and proper-descendant membership are distinct operations. A
bounded relative hint selects a descendant through strict kernel-beneath,
no-mount-crossing resolution, then fresh PIDFD information must match that exact
retained candidate. No `/proc/PID/cgroup` parsing, numeric PID reopening, global
scan, principal derivation from UIDs/inodes, or cgroup mutation occurs in these
production APIs.

Before/after process observations reject observed PID/thread-group/cgroup
changes, and final liveness rejects exit. These are snapshots: migration away
and back between observations, later migration, and later effects are not
fenced. The host and mount broker startup paths now require typed cgroup roots;
their peer proofs retain the observed cgroup directory and borrow the pinned
socket establisher. The host runtime worker's separate verification path is not
silently claimed to have migrated with the service verifier.

The principal/session audit found no authoritative UID-to-principal or live
payload-cgroup registry to reuse. The first producer channel must instead be
provisioned for an explicit holder/capability/project/sandbox/incarnation/epoch
tuple and retained payload-cgroup anchor. The publisher needs its independent
configured service principal and fresh execution registration. Live session
tables, server-minted channel bindings, challenge joins, source slots/release
decisions, and reservation accounting remain implementation requirements.
`SBX-PUB-02` remains open.

Validation passes: 68 Linux-boundary, 76 host-broker, and 61 mount-broker unit
tests, two integration tests, twelve doctests, scoped strict Clippy,
warning-denied rustdoc, changed-file formatting, and the locked all-target
workspace compile check. The workspace check retains unrelated existing
warnings. The read-only host test exercised both exact and hinted descendant
membership on Linux 6.18.44, with fake-filesystem, traversal, wrong-object, and
overlong-hint rejection. Independent source and implementation reviews found no
remaining blocker for this observation component. Deletion/recreation,
concurrent migration, bind-mount grafts, and dual-architecture behavior still
require dedicated AOS VM qualification; ordinary host tests and source review
do not substitute for those gates.

### Controller-issued local holder channels

The controller now has a trusted administrative provisioning path for an
explicit holder/project/sandbox/incarnation/assignment/cache-resource tuple
and retained cgroup anchor. It does not infer a principal from a UID or PID,
and its caller must authorize that runtime mapping. A fixed-capacity volatile
session table reserves a slot and configures both socket-pair endpoints for
kernel record subjects before exposure. Fallible kernel randomness supplies
new session/capability identities and role-separated channel bindings.

Issuance resolves the current protected policy, exact project-cache resource,
controller head, and revocation head under the sole journal writer. The
derived capability contains exactly one nondelegable cache-publish grant,
with validity bounded by policy and trusted paired-clock observations. A
versioned capability envelope atomically retains the full claims and explicit
issuance evidence, including the live session identity, boot/clock provenance,
policy/controller generations, and resource isolation commitment. Existing
version-one records retain their byte encoding; revocation retains audit data.

Only a successful durable commit followed by fresh clock and cgroup checks
activates the reserved slot and exposes its endpoint. Failures close pending
endpoints; a post-commit failure can retain an audited capability without a
live session. Restart starts with an empty table and cannot reconstruct
channel possession from journal records. Incoming records use bounded framing
and kernel-subject PIDFD membership under the provisioned anchor; successful
records borrow their session, excluding concurrent table invalidation. Fatal
framing, transport, or membership errors close the local channel.

These are issuance and live channel/scope foundations, not completed online
admission. Every use still needs current capability, policy, revocation,
assignment and resource checks. Production runtime-to-principal provisioning,
endpoint delivery, publisher execution registration, challenge joining,
source-slot/release decisions, accounting, and retained completion permits
remain open. `SBX-PUB-02` is not complete.

Packaging qualification found that the ordinary Nix sandbox exposes procfs
but not `/sys/fs/cgroup`. Real-cgroup tests now require the explicit
`kernel-tests` feature; pure framing, scope, policy, and journal tests remain
in the default suite. `checks.vm.sandbox-local-identity` compiles the enabled
fixtures from AOS sources, runs the default library suites inside the build
sandbox, then executes the kernel fixtures in a headless AOS VM. The guest
mounts its own cgroup-v2 hierarchy and moves only its test shell into a proper
descendant, exercising both exact and hinted membership. Every selected test
filter must discover tests before execution. This is not a runtime skip or
permission to expose host cgroups to a package build.

Validation passes: 359 default unit tests (160 controller, 67 Linux boundary,
73 host, 59 mount), three integration tests, sixteen doctests, all-feature
strict Clippy, warning-denied rustdoc, changed-file formatting, and the locked
all-target workspace check. The latter retains unrelated existing warnings.
The named VM derivation also runs those 359 default library tests inside the
actual Nix build sandbox, then passes all seventeen selected kernel tests on
AOS Linux 6.18.33 x86_64, including the broker subprocess fixtures. This closes
the exact-AOS-kernel gap for the carried exact/descendant cgroup and stale-peer
cases, not cgroup mutation/migration races, aarch64 qualification, or full
production runtime provisioning. Independent implementation and packaging
reviews found no remaining blocker for this increment.

### Exact-process publisher execution and pending challenge registration

Publisher registration now accepts an explicitly configured service mapping
through a listener whose kernel record-subject options precede connection
exposure. The controller pins the original connector and its exact retained
cgroup, mints a fresh execution identity and channel binding, and commits
immutable execution audit facts before sending the fixed instance greeting.
Neither the configured socket path nor Unix credentials supply a principal.
The retained PIDFD identifies process lifetime, not executable-image provenance.

The fixed-capacity session table rejects delegated writers even within the
same cgroup. Fatal transport or identity failures close the channel but retain
the original process pin and principal/node reservation. Post-commit failures
and indeterminate journal errors also retain a retired reservation. Only
observed exit releases that volatile slot; it does not release durable
accounting or transfer completion permits. Restart never reconstructs a live
execution from diagnostic PID, cgroup, boot, or channel fields.

Namespace-nine execution and pending-challenge records use independently
versioned, canonical bounded encodings. Execution identities cannot be
reinstalled, even with identical facts. Challenge retries must retain exact
original facts; changed keys are rejected, and expired keys remain retained
under finite lifetime quotas. The controller reads canonical challenge requests
only from the original publisher's authenticated session, matches the complete
execution/resource target, and resolves current protected policy, controller,
and revocation heads. Wall and boottime deadlines are independently checked
before and after commit; an exact retry cannot reset either deadline. The
holder channel named in a request is not the publisher's channel and remains
an unverified claim until the separate holder-channel join.

These records are audit state, not publication admission, source provenance,
challenge consumption, reservations, or signing
authority. Future admission must consume a challenge atomically with its
decision and accounting. Production publisher dispatch, the holder-channel
join, root-registry validation, source-slot/release decisions, and completion
permits remain open; `SBX-PUB-02` remains incomplete.

Validation passes: 368 default unit tests (167 controller, 69 Linux boundary,
73 host, 59 mount), three integration tests, and seventeen doctests. The
all-feature four-crate suite passes 401 unit tests, the same integration
tests and doctests, with serial kernel-fixture execution. Subprocess fixtures
can temporarily inherit unrelated descriptors between fork and exec; running
them concurrently with close/flock assertions produced transient failures.
The explicit kernel gate runs serially, while default hermetic tests exclude
these fixtures. No production behavior or journal-lock checks were weakened
to accommodate that test-process interaction.

All-feature scoped strict Clippy, warning-denied rustdoc, changed-file
formatting, and the locked all-target workspace check pass. The workspace
check retains unrelated existing warnings. Independent registration/session
and challenge reviews found no remaining blocker for this increment.

The final `checks.vm.sandbox-local-identity` derivation passes all 368 default
library tests inside the actual Nix build sandbox and all 31 selected kernel
test entries, including subprocess fixtures, on AOS Linux 6.18.33 x86_64.
It exercises same-cgroup delegated-writer rejection, pinned-process exit,
immutable challenge retries, stale heads, policy-clamped frozen-wall deadlines,
and failed journal append retention through the real registration path.
Cgroup mutation/migration races, aarch64, production runtime provisioning,
and publication admission/effects remain unqualified by this gate.

### Live payload-scope handoff (in progress)

Host 1.2 `ObservePayloadScope` now carries a fresh signed query against the
exact installed plan/lease fence. The broker exports only launch-retained
payload PID-1 and cgroup objects after refreshing the same invocation,
supervisor, root, namespaces, and subtree membership. Process-local scope
handles and strong pins are not reconstructed from receipts after restart.
Failed state commits latch the broker unhealthy and retire retained pins.

The response transfers a closed pidfd/cgroup descriptor pair with bounded
metadata. Final delivery rechecks the accepted controller, live authority,
and kernel pins; the descriptor send is nonblocking and never retries stale
checks. The controller authenticates actual response subjects against trusted
host-service configuration, including when the listener creator differs from
the responder under socket activation. Descriptor validation establishes
kernel identity and membership; strong payload verification is a host
attestation, not an inference from descriptor types.

Validation passes: 477 all-feature unit tests across controller, Host, Linux,
mount, and protocol crates, three integration tests, and eighteen doctests,
with serial kernel-fixture execution. This includes the saturated-send-queue
regression. All-target all-feature strict Clippy, warning-denied rustdoc,
changed-file formatting, and the locked all-target workspace check pass;
the workspace check retains unrelated existing warnings.

The updated `checks.vm.sandbox-local-identity` derivation passes all 380 default
library tests inside the Nix build sandbox and all 38 selected kernel test
entries in AOS Linux 6.18.33 x86_64. The new fixtures qualify actual responder
identity under socket activation and closed descriptor-carrier behavior, not
the strong payload attestation of a real launched sandbox.
End-to-end production runtime provisioning, real strong
payload handoff qualification, holder-channel delivery/admission, and
publication effects remain open; this does not complete `SBX-PUB-02`.

### Joining independently authenticated holder and publisher channels

The controller now reads the holder's actual local-channel record and joins
its complete canonical request to the immutable pending challenge registered
by the separately authenticated publisher. A non-cloneable borrowed context
retains the holder record, original live publisher execution, and exclusive
protected journal access. A request copied onto another holder channel fails
even when both channels name the same principal. Readable publisher packets
remain queued; liveness checks do not consume a second challenge.

Joining resolves the active capability and V2 issuance evidence and checks
the exact holder/channel/session/resource/runtime snapshot, current policy and
controller heads, revocation scope and generation, individual tombstones,
resource/domain/isolation mapping, boot, clock provenance, and fixed challenge
and capability wall/boottime deadlines. Both channels are checked for shutdown
as well as live scoped kernel identity. Any failed recheck permanently poisons
the join and closes holder ingress; failed publisher observations retire the
transport while retaining its original execution reservation.

This does not consume a challenge, write an admission decision, reserve
publication capacity, sign a plan, or grant a completion permit. The runtime
fields establish consistency with issuance, not current assignment authority:
the controller still needs a protected typed current-assignment/holder mapping
and fresh runtime proof. Source release, protected root currentness, atomic
accounting/consumption, and production delivery/dispatch remain open, so
`SBX-PUB-02` remains unchecked. Existing durable and wire encodings are unchanged.

The five-crate serial all-feature suite passes 492 unit tests, three integration
tests, and nineteen doctests. Strict all-target/all-feature Clippy and
warning-denied controller rustdoc pass. Changed-file formatting and the locked
all-target workspace check pass; unrelated workspace warnings remain.
The final `checks.vm.sandbox-local-identity` derivation passes 381 default
library tests inside the Nix sandbox and all 52 selected kernel test entries
on AOS Linux 6.18.33 x86_64, including thirteen holder-join cases and the
poisoned-journal regression. It does not qualify current assignment authority,
real payload endpoint delivery, source release, or publication effects.

### Protected runtime holder decisions

Publication preparation and recovery now retain the complete canonical
assignment manifest and expose its lease-independent source-draft digest,
without changing publication bytes. Round-trip assertions cover those retained
facts. Journal namespace 10 is reserved for runtime-authority pending intents,
immutable holder decisions, and ordered current heads; previous namespace codes
remain unchanged.

An ownership-gated operation can now admit a typed holder intent. Its V3 operation
record independently commits the exact holder, decision kind, and expected
revision; V1/V2 operation records and V1 ownership gates retain their encodings.
Admission commits the pending intent with the operation and effects. Activation
rechecks the expected revision and atomically commits the immutable holder
decision, current head, ownership publication, and gate release. Legacy operations
cannot silently replace a sandbox's established holder decision.

Protected replay checks both directions between operations, pending intents,
activated decisions, and publications, as well as complete monotone revision
history. Removing an activated binding and head cannot turn the sandbox into a
never-bound sandbox. Historical idempotent replay cannot repoint the current head.
The publication namespace is validated once per complete runtime-authority replay,
with direct exact-current checks for each sandbox head.

The five-crate default-feature suite passes 513 unit tests, one integration test,
and eighteen doctests, including competing intents, protected reopen, missing
records, V3 provenance, and renewal/history regressions. Controller strict
all-target/all-feature Clippy passes with dependency linting excluded; including
dependencies reports existing disallowed `HashMap` use in generated protobuf
code. Warning-denied controller rustdoc, changed-file formatting, and diff checks
pass. This increment has not rerun kernel/VM qualification.

These durable decisions are not live authorization. Fresh runtime proof and
session issuance against the current holder mapping remain open. Revocation was
not enabled in this increment; its action-aware integration follows below.
`SBX-PUB-02` remains unchecked.

### Canonical runtime templates and holder revocation

Host Stop is an existing action inside `ApplyRuntime`, not a separate RPC. The
controller now admits revocation only with exactly one descriptor-free Stop
effect whose full assignment fence and canonical argument commitment match its
selected signed-plan template. Freeze, Thaw, Kill, and multiple-effect plans
cannot stand in for this transition. Protected replay repeats this check against
the exact admitted effect, not merely the runtime-intent state tag. Admission and
replay also require the tombstone to retain its predecessor's full assignment;
stopping a replacement runtime cannot stand in for stopping the current one.

A distinct inert runtime-template type validates deadline-free Host inputs
without fabricating peer credentials or clock readings. It shares action, fence,
and launch-plan validation and canonical semantic encoding with the live request
path, but cannot be passed to a broker as a peer-validated request. Existing wire
encodings and canonical semantic commitments are unchanged.

Revocation atomically commits an ordered holder tombstone with ownership
publication and gate activation, before executor I/O. This immediately removes
the holder mapping even if Stop later fails; it does not assert that the runtime
has stopped. The effect ledger continues to own dispatch and completion.
Protected reopen and idempotent replay retain the tombstone. Fresh runtime proof,
current-holder session issuance, and full lifecycle qualification remain open.

The six-crate default-feature suite, including the Host broker, passes 597 unit
tests, two integration tests, and 21 doctests. Regressions cover live/template
semantic parity for every runtime action, malformed inert inputs, rejection of
non-Stop revocation plans, and durable revocation before executor I/O.
Controller/protocol strict all-target/all-feature Clippy (`--no-deps`),
warning-denied rustdoc, changed-file formatting, and diff checks pass. This
increment has not rerun kernel/VM qualification.

### Retained runtime-observation request provenance

`ObservedPayloadScope` now retains the exact structurally validated plan, lease,
and detached signatures sent on its authenticated Host exchange, plus the
original request's BOOTTIME deadline. Consumers can distinguish lease renewals
and plan changes even when the echoed assignment fence is unchanged. The
original host execution and payload pins remain owned by the observation.

These borrowed artifacts remain untrusted inputs to separate controller
authorization. Neither retaining them nor rechecking kernel membership proves
current ownership, refreshes expiry, or authorizes a holder. Protected-current
publication comparison, fresh lease verification, and current-holder issuance
are still required; `SBX-PUB-02` remains unchecked. The request deadline is not
the transport watchdog and is not advertised as a verified lease expiry.

Controller default-feature validation passes 185 unit tests, one integration
test, and seven doctests. Strict controller all-target/all-feature Clippy
(`--no-deps`), warning-denied rustdoc, changed-file formatting, and diff checks
pass. This increment does not qualify the full Host observation-to-session flow
or rerun kernel/VM tests.

### Protected current-runtime observation acquisition

The controller now has a distinct acquisition API that accepts an authenticated
holder selector, not caller-selected assignment, lease, plan, or cgroup facts.
Under one exclusive journal borrow it resolves the current Bound holder and
publication, recovers the exact activated ownership claim, cryptographically
reverifies the lease and transaction receipt, and verifies the selected Host 1.2
plan against independently configured trust anchors. The signed plan must grant
the exact payload-scope query and its request bounds. The real authenticated
Host exchange alone constructs the non-cloneable `CurrentRuntimeScope`.

The scope retains the complete Host and payload observation. Its fixed deadline
is bounded by conservative lease expiry (including skew and safety margin),
signed-plan expiry, and a configured lifetime of at most 30 seconds. Rechecks
repeat protected current selection, signatures, kernel observations, and clock
checks without extending validity. They reject even same-holder renewal or ABA
rebind through exact immutable revision comparison. Independent kernel BOOTTIME
checks prevent stale adapter samples from extending an observation.

Protected preflight regressions cover reopen, absent/unprotected state, holder
and node mismatch, tombstones, renewal, same-holder revoke/rebind, missing Host
grants, substituted trust keys, conservative expiry, clock rollback/divergence,
and arithmetic overflow. They exercise real signatures and protected journal
replay but intentionally do not construct a live Host proof from fixture clocks.

Current-holder session issuance, durable issuance provenance, admission-time
runtime refresh, and full Host-to-session kernel/VM qualification remain open.
The existing trusted-administration issuance API is unchanged and is not
silently promoted to current-runtime authorization. `SBX-PUB-02` remains
unchecked; no durable record or wire encoding changes in this increment.

The controller, core, local protocol, and ownership protocol default-feature
suites pass 452 unit tests, one integration test, and twelve doctests. Strict
controller all-target/all-feature Clippy (`--no-deps`), warning-denied rustdoc,
changed-file formatting, and diff checks pass. No kernel/VM tests were rerun.

### Current-runtime-backed local session issuance

`provision_current_runtime_ingress` now consumes the acquired runtime scope and
derives holder, project, sandbox, incarnation, and epoch from its protected
binding. Current cache policy determines the nondelegable grant. The prepared
session retains the complete Host/payload observation and trust context, not
an extracted cgroup descriptor. Runtime authority and execution checks bracket
the durable commit; final capability and observation time bounds are checked
before activation. A post-commit failure drops the undisclosed endpoints and
can leave only an audited capability without a live channel.

Capability record version three adds immutable observation provenance and
references the exact historical holder decision, publication, assignment, and
lease. Replay validates complete protected runtime history before resolving
those references. It accepts legitimate later renewal or tombstones without
pretending that the old issuance decision is current authority. Capability
revocation preserves all provenance with no increase in record size. Versions
one and two retain their exact encodings and remain distinguishable from this
runtime-backed path.

Incoming runtime-issued holder records reobserve the original Host and payload
pins as well as the actual record subject. Publisher request joining compares
the complete retained runtime-origin evidence against the durable issuance
record, rejecting missing, substituted, or cross-profile provenance. This
still establishes origin consistency, not current publication permission.

New audit regressions cover a fixed version-three golden, closed and bounded
encoding, timing and identity substitution, historical-link substitution,
missing runtime history, renewal, revocation, compaction, and protected reopen.
They deliberately use audit fixtures rather than fabricated live runtime
proofs. Actual Host-backed acquisition, issuance, delivery, and failure-path
kernel/VM qualification remain required.

A channel can outlive its original issuance observation. The fresh runtime join
described below does not renew that observation or complete publisher admission.
`SBX-PUB-02` remains unchecked.

The four-crate default-feature suites pass 457 unit tests, one integration
test, and thirteen doctests. Historical runtime replay has an independently
configurable bound, with an exhaustion regression. Strict controller
all-target/all-feature Clippy (`--no-deps`), warning-denied rustdoc, changed-file
formatting, and diff checks pass. Workspace all-target checking passes with
warnings in unrelated crates. Kernel/VM tests have not been rerun.

### Fresh runtime evidence for publisher request joins

`JoinedPublisherRequest::bind_current_runtime` now performs an actual Host
exchange selected from the authenticated session's holder and sandbox. It
returns a distinct `RuntimeJoinedPublisherRequest`, retaining the fresh scope,
original holder record, live publisher connection, and exclusive journal borrow.
Administrative session origins cannot be promoted through this path.

Complete bounded protected history must connect the exact original binding to
the exact current head through only bound decisions for the same holder and
full assignment manifest. Lease/publication renewal can preserve that chain;
revocation, holder replacement, and assignment changes cannot. Endpoint equality
alone is insufficient, including same-holder revoke/rebind ABA. Both retained
observations must still name the same live Host and payload processes, runtime
and scope handles, assignment fence, and pinned cgroup. Boot, clock provenance,
observation ordering, and local publisher node must also agree.

Rechecks retain the fresh scope's fixed deadline and exact revision. A failure
poisons the joined context and closes holder ingress. The old observation's
deadline is neither renewed nor substituted for capability lifetime. No source
release, root authority, operation authorization, reservation, challenge
consumption, signing, or completion permission follows from this join.

Protected-history regressions cover renewal, stale/reversed endpoints,
revocation/rebind ABA, holder-replacement ABA, compaction, and reopen. These
tests validate structural continuity, not real Host acquisition or live session
promotion. End-to-end Host/worker/kernel/VM qualification remains open.

Validation: the four-crate default suites pass 460 unit tests, one integration
test, and fourteen doctests, including a compile-fail barrier against promotion
without acquisition. Warning-denied all-feature controller rustdoc and workspace
all-target checking pass; the latter retains unrelated workspace warnings.
Strict all-target/all-feature controller Clippy (`--no-deps`), changed-file
formatting, and diff checks also pass.

### Production compiler and worker VM qualification

`checks.fleet.sandbox-host-worker` builds an explicitly selected, ignored
kernel test against the real packaged nspawn. It exercises the production
launch compiler and `SystemdOneShotWorker`, with pinned workspace and network
objects, shifted identity allocation, and fixed resource limits. Its assertions
cover distinct supervisor and payload pins, retained-scope refresh, freeze,
thaw, stop, dead-process confirmation, and rejection of the stopped scope.
Ordinary host tests do not execute this privileged fixture.

The fixture deliberately supplies an inert guardian dependency. It does not
prove ownership expiry, deployed MAC enforcement, the hardened Host service,
controller acquisition, session delivery, or publisher admission. It cannot
construct production `BackendReadiness`. The production supervisor context
`aos_nspawn_t` still has no deployed policy definition in this checkout.
These requirements and full Host-to-session qualification remain open.

The existing platform proof's masked-unit assertions now account for
`systemctl is-enabled` returning status one for `masked-runtime`. Both VM
fixtures use the AOS nftables executable's actual `sbin/nft` installation path;
the initial runs exposed these fixture failures before worker qualification.

Validation: the new fixture's 79 default Host unit tests and strict
all-target/all-feature Host Clippy (`--no-deps`) pass. The packaged workspace
build and its check phase pass. The worker VM reached production launch and
failed: nspawn could not resolve the launcher's pinned workspace through
`/proc/<launcher>/fd/<root>` (`Permission denied`). Its error also reported
incomplete fail-stop cleanup after the failed transient unit was collected.
Descriptor delivery under the closed supervisor capability profile and
already-absent rollback handling require follow-up; the test remains red.

The combined run stopped on a platform-fixture assertion that incorrectly
unpacked the driver's three-value byte result. That assertion is corrected
against the driver implementation but has not been rerun. The worker result
above comes from a subsequent standalone realization of its already-built
derivation. Neither VM gate is claimed as passed. The full evaluation check
passed before the final fixture-path and stopped-pin assertion edits.
No implementation task is checked off by this prerequisite.

### Descriptor-backed root mount transfer and collected-unit reconciliation

The production transient-unit compiler now transfers one root mount through
`ExtraFileDescriptors` with the fixed `aos-sandbox-root-mount-v1` role. The
paired AOS nspawn option consumes that role and arity, excludes the setup
descriptor from payload activation, and requires the closed private-user
directory profile. Root identity checks and an inode-based exclusive lock do
not reopen a replaceable host pathname. Each boot imports a cloned detached
tree through `move_mount`, retaining a detached replacement for another boot.
The OS-tree check runs only after attachment in the private mount namespace.
Private temporary directories and a bounded nspawn runtime tmpfs replace the
old pathname-based writable exception; no supervisor capabilities are added.

The privileged workspace publisher must supply the detached mount. Host stays
capability-free. The current file catalog verifies metadata and attached pins,
but it does not implement that live, assignment-bound publisher handoff.
Production readiness remains unavailable. The VM explicitly prepares the
detached tree as a prerequisite fixture, not as a substitute publisher service.

The worker now requires both manager absence and kernel cgroup absence before
reporting an absent runtime. The cgroup-v2 anchor is checked before and after
the missing-child observation. Failed kill/stop calls can reconcile a collected
unit only through a fresh absent observation; the original launch error is
still returned. Loaded states, remaining cgroups, and unavailable observations
keep containment indeterminate. `NoSuchUnit` recognition matches only systemd's
exact D-Bus error name, not a substring or another error domain.

Regressions cover root descriptor ownership in the D-Bus property, role and
arity rejection, setup-environment removal, pathname replacement, inode-lock
contention, close-on-exec flags, cleanup-state combinations, and misleading
error names. The worker VM adds a first-PID-1 executable that rejects inherited
setup descriptors and `LISTEN_*` environment before executing guest systemd.

The intermediate VM run proved descriptor delivery but failed legacy binding
of an attached root from another mount namespace. That evidence led to the
detached-mount contract above. The updated VM reached namespace setup, where
the outer helper was terminated with `SIGSYS`; the denied syscall has not yet
been identified. Collected-unit cleanup returned the original launch failure
without an incomplete-cleanup qualifier. The fixture now retains kernel and
audit diagnostics for a follow-up run. No VM pass or production Host
qualification is claimed. Publisher integration, enforcing MAC, ownership
expiry, and complete Host-to-session qualification remain open.

Validation: 94 Host/systemd unit tests, 25 integration tests, two doctests, and
strict all-target/all-feature Host/systemd Clippy pass. The patched systemd
build passes its root-descriptor C tests, and the first-PID-1 fixture compiles
with warnings denied. The packaged workspace build and checks pass. The full
evaluation check passed before the final detached-mount transfer edits; the
worker and platform VM diagnostics are being rerun against the current tree.

### Idmapped-root syscall and guest fixture follow-up

The diagnostic worker VM identified the namespace helper's fatal seccomp
record as x86-64 syscall 467 (`open_tree_attr`). The packaged systemd uses this
operation when preparing the required root idmap; it belongs to `@mount`, not
the inherited `@system-service` set. An intermediate explicit allowance got
past this denial but exposed `EBUSY` in upstream's pathname remap: it attempts
to unmount a root that already contains the prepared Nix-store submount.
The descriptor profile now applies its fixed idmap with the already-allowed
`mount_setattr` while the root is still detached, then attaches it once. It
does not recursively change child idmaps or discard read-only mount boundaries.
The extra syscall allowance is no longer needed and is not retained. A D-Bus
property regression keeps both `open_tree_attr` and the broad `@mount` set out
of the supervisor allowance; the separate payload denial also stays intact.

The platform VM reached guest PID 1, then refused its empty `/usr` fixture.
Both test roots now publish the standard `/usr/lib/os-release` file and an
`/etc/os-release` symlink. The platform fixture also places `CollectMode` in
the unit section and removes an obsolete static `CPUAccounting` setting.
These are fixture repairs, not production guest-root completion. Diagnostics
now retain a bounded kernel tail and seccomp audit records instead of every
audited exec on the test node.

After these fixture repairs, the platform VM booted the guest and reached its
cgroup assertion. The observed path exposed a production canonicalization bug:
systemd places the hyphenated `aos-sandboxes.slice` beneath `aos.slice`.
Production parsing, cgroup-absence checks, and mock observations now use that
exact hierarchy. The worker VM additionally creates an empty runtime cgroup
with no manager unit and requires absence observation to fail, then removes
the fixture cgroup and requires it to succeed. Guest PID 1 now checks that the
prepared Nix-store mount still has its read-only flag after root setup.

The full evaluation check passed for `1deded69a`. The diagnostic worker fixture
initially hit a `rustc` allocator abort while compiling `aos-proto`; an exact
derivation retry with eight build jobs passed, including its 82 Host unit
tests. After the detached-idmap and cgroup-path changes, 94 Host/systemd unit
tests, 25 integration tests, two doctests, strict Host/systemd Clippy, the
patched systemd build/checks, and the full evaluation check pass.

The updated worker VM passed its remaining-cgroup absence regression and
reached the first guest executable. Its setup-descriptor/environment and
read-only Nix-store checks passed, but exec of guest systemd returned `ENOENT`.
Inspection found that the fixture's undeclared runtime executable reference
had been scrubbed to an `eeee...` store hash. The fixture now declares systemd
as a runtime dependency, and its root builder checks the final installed
binary for the exact executable path. The platform VM passed initial payload
and corrected cgroup assertions, then failed while waiting for its observer
report; observer journal and cgroup-tree diagnostics are added for that run.
The repaired VM gates are being rerun; neither gate is yet green.

### Inherited startup denials and observer leaf identity

With the executable reference retained, the worker reached guest systemd.
Its startup `reboot(RB_DISABLE_CAD)` probe was terminated by the inherited
supervisor filter (`SIGSYS`, x86-64 syscall 169). An intermediate allowance
passed that probe but exposed the same fatal-denial issue on systemd's BPF
probe. The supervisor now applies an ordered errno-denial overlay after its
closed allowlist: both `bpf` and `reboot` remain forbidden with `EPERM`.
Other unknown syscalls retain the default kill action. This avoids granting
BPF operations to the `CAP_SYS_ADMIN`-bearing supervisor. The payload's
separate denials remain intact, and neither process gains `CAP_SYS_BOOT`. The first
guest executable explicitly tests the nonfatal denial before exec, and the
property regression checks the layered syscall/capability contract.

The platform observer's cgroup-tree diagnostic confirmed guest PID 1 in
`payload/init.scope`. The fixture was comparing its pidfd cgroup identity
against the payload subtree root. It now opens the exact `init.scope` child
relative to the payload descriptor, disallows a final symlink, and compares
the pidfd identity and strict `/proc` membership with that leaf before and
after observation. Discovery still searches the full payload subtree and
rejects ambiguous candidates. The production Rust worker already handles
descriptor-checked descendant membership; this correction is to the separate
platform fixture, not a relaxation of production scope checks. The fixture's
pidfd namespace ioctls also now pass an explicit zero third argument, as
required by the kernel ABI, instead of leaving a variadic argument undefined.

The resulting VM run boots the production worker's payload to its default
target and passes the platform observer's initial and restarted identity
checks. Worker observation then exposed incorrect generated D-Bus property
names: `InvocationId` instead of `InvocationID`, and the analogous `MainPid`
instead of `MainPID`. Proxy and independent fake-service declarations now
name these wire properties explicitly. The platform gate times out waiting
for guest reboot; its timeout path now captures runtime and observer journals
and the live cgroup tree. Neither failure is treated as qualification.

The latest all-feature Host/systemd suites pass 97 unit tests, 26 integration
tests, and two doctests; the explicitly VM-only test remains ignored outside
its fleet fixture. Strict all-target/all-feature Clippy with `--no-deps` and
Rust/Nix formatting checks pass. A dependency-inclusive Clippy invocation
fails on generated `aos-proto` HashMap fields under the repository's ordered
container lint. The updated VM gates are being rerun and are not yet qualified.

### Production namespace ioctl ABI and reboot evidence

The worker VM passed the corrected manager-property reads, then rejected a
pidfd namespace ioctl with `EINVAL`. The production Rust UAPI wrapper also
omitted the scalar third argument. It now passes an explicit zero of the
correct C unsigned-long type, and does the same for `NS_GET_NSTYPE`. The
worker VM qualification first requires successful acquisition and type
validation of all five supported namespaces from its own pidfd. It cannot
treat `EINVAL` or unavailable namespace support as a portable-test skip.

The platform reboot diagnostic shows guest systemd reaching its reboot path,
then nspawn exiting with status 133. Upstream deliberately requests a whole
service restart when `--keep-unit` is active. That contradicts the required
retained-supervisor/internal-payload-reboot behavior; `Restart=no` and the
observer's exact supervisor identity checks remain unchanged. This requires
explicit lifecycle implementation, not a longer timeout or accepting a new
supervisor as the same execution. The worker VM is rerunning after the Rust
ABI correction; no readiness or reboot qualification is claimed.

The full evaluation/system-structure check passes for `9fbea39b3`. The shared
CLI package initially failed its test run without naming a failing test in
the build log; the same derivation passed on the evaluation run. The worker
VM retry then passed its mandatory five-namespace probe and reached payload
discovery, which returned `EBADF`. A focused regression reproduced the cause:
`Dir::read_from` preserves the anchor's `O_PATH` flag, which is invalid for
directory enumeration. The scanner now opens only `.` relative to the retained
anchor with readable directory flags. The regression also renames the pinned
tree and replaces its old pathname, proving the scan still visits the original
root and descendant. Host/systemd all-feature tests pass 98 unit tests,
26 integration tests, and two doctests after this correction. The VM gate
still requires a rerun; no production readiness is enabled.

### Production worker VM milestone

The x86_64 `checks.fleet.sandbox-host-worker` gate now passes after the
readable-directory correction. It requires all five pidfd namespace ioctls,
rejects manager-only absence while a kernel cgroup remains, launches through
the production compiler/worker, distinguishes supervisor and payload PID 1,
rechecks the retained root/network/cgroup proof, refreshes the payload scope,
freezes and thaws it, stops both processes, and rejects retained proofs after
stop. The first guest executable also checks descriptor/environment scrubbing,
the read-only Nix-store submount, and nonfatal reboot-probe denial.

The shared package test runner again returned an unnamed failure before VM
boot on the first rebuild. The `aos` package now selects its existing CI
Nextest profile, which inherits default test settings and adds a JUnit report
to retained build directories. That packaged suite and the subsequent VM gate
passed. The earlier intermittent package failure is not attributed to a test
without evidence.

This gate uses a privileged qualification fixture and an inert ownership
guardian. It does not qualify the deployed capability-less Host, enforcing
MAC, publisher delivery, lease expiry, internal reboot, aarch64, or complete
controller-to-guest execution. `BackendReadiness` remains unavailable and all
tasks depending on those proofs remain open.

### Retained-supervisor shutdown-intent foundation

The systemd patch series now builds and runs a focused shutdown-intent state
machine test. Only an exact `X_SYSTEMD_SHUTDOWN=reboot` and `EXIT_STATUS=0`
pair can request a reboot. Missing, duplicate, malformed, nonzero, or
conflicting shutdown fields latch inhibition for that boot. Repeating a valid
notification is idempotent; unrelated readiness/status notifications do not
change intent. The decision additionally requires a clean actual exit and no
host stop request. Tests cover all of these cases and independent per-boot
state. The helper's caller contract requires authentication against the pinned
payload PID 1; these pure tests do not prove that transport binding.

This is preparation, not runtime reboot support. Event-loop integration must
authenticate notifications, drain pending shutdown records before reaping
PID 1, give host stop precedence, and reset the empty payload cgroup with
bounded descriptor-relative cleanup before another boot. Removing the old
payload root is necessary to discard guest-written cgroup limits/controllers
while retaining the supervisor and unit. The existing owned-root descriptor
implementation already clones a fresh mount tree inside each boot iteration;
that behavior still needs repeated-boot VM evidence under the production
capability and seccomp profile. `SBX-RT-06` and lifecycle qualification remain
open; runtime behavior and `BackendReadiness` are unchanged by this patch.

### Retained-supervisor reboot integration

The next systemd patch integrates that state machine behind the explicit
`aos-sandbox-lifecycle-v1` profile, selected by the fixed Rust launch compiler.
The profile requires boot mode, the retained delegated unit, fixed shifted
user namespaces, private PID/IPC/UTS/cgroup namespaces, disabled settings and
registration, the payload seccomp profile, no-new-privileges, and no
`CAP_SYS_BOOT`. It rejects nspawn-managed network changes. The upstream
keep-unit exit-133 behavior remains unchanged without this profile.

Shutdown notifications are authenticated against the pinned payload PID 1.
Before reaping it, a bounded drain handles notifications that lost the event
dispatch race to SIGCHLD. A reboot requires an actual successful process exit,
not upstream's broader success normalization for namespace-shutdown signals.
Host stop requests are latched across boots, prioritized in the event loop,
and checked again before another payload starts.

Before a reboot, the supervisor verifies an empty payload subtree and removes
its cgroup root and descendants using descriptor-relative, no-follow traversal.
The traversal bounds depth, directories, entries, name bytes, and elapsed time;
oversized or incomplete cgroup-events input is rejected. Errors prevent another
boot. Recreating the payload root discards guest-written limits and controller
settings without replacing the enclosing unit or supervisor. Unit tests cover
the empty-state parser and non-cgroup filesystem refusal without mutation.

The first integrated x86_64 platform VM run passes two successive reboots with
`CAP_SYS_BOOT` dropped and reboot syscalls denied. It retains supervisor and
invocation identity, observes new payload PID/mount/PID/user namespace identity,
and verifies new payload-root cgroup inodes and default `pids.max` after setting
the old root's limit. The production compiler/worker launch-refresh-stop VM also
passes with the lifecycle flag selected. The final hardened source, including
the actual-exit, bounded-complete-read, and explicit namespace checks plus a
post-reboot host stop assertion, passes both VM gates and the full
`checks.eval` gate. Focused Host/systemd all-feature tests, strict Clippy, and
formatting checks also pass. The earlier evaluation failure was a `rustc`
segmentation fault compiling `aos-proto`, not a test failure; the bounded-core
rerun completes successfully.

The repeated-boot platform fixture still uses its directory pin holder, not the
production detached-root descriptor handoff. Repeated owned-root boots, Host
namespace-generation reconciliation and attachment replay, concurrent host-stop
tests, enforcing MAC, and lease/publisher qualification remain required.
`SBX-RT-06`, end-to-end readiness, and `BackendReadiness` remain open.

### Repeated production owned-root boots

The production compiler/worker VM now also passes two guest-triggered internal
reboots through the owned detached-root descriptor handoff. Every boot reruns
the first-exec descriptor/environment scrubbing and read-only Nix-store checks.
The test retains the supervisor and invocation, rejects each old payload proof,
and reconciles the new payload through the existing launch path using freshly
resolved executable, root, and network pins. Each new payload has a different
cgroup and mount/PID/user namespace identity while the network remains pinned.
Reconciliation does not start another unit or consume a forward-effect guard;
the final stop still terminates the retained supervisor and latest payload.

The guest marker only schedules this fixture; production kernel verification
establishes identity. Focused Rust tests, strict Clippy, formatting, and the
`checks.fleet.sandbox-host-worker` VM gate pass. This closes the repeated
owned-root boot proof noted above, not controller namespace-generation
reconciliation, attachment replay, enforcing MAC, or lease/publisher delivery.

### Reconciliation containment authority

Launch reconciliation now rechecks the live effect guard before containing a
pre-existing unit whose initial observation or identity proof fails. Those
read-only failures are not evidence that this call already attempted a launch;
an expired request must not gain kill/stop authority from them. Successful
no-op reconciliation still consumes no forward-effect authority. Once a launch
or guarded containment attempt begins, mandatory cleanup remains independent
of later expiry.

Regression tests cover initial observation failure and pre-existing identity
mismatch with both accepted and expired guards, including exact zero-mutation
assertions for denied containment. The post-start expiry test still requires
kill and stop. All-feature Host tests and strict Clippy pass. This narrows the
older ledger's unconditional pre-existing containment behavior; it does not
adopt an unverified unit or weaken post-attempt fail-stop cleanup.

### Protected runtime-generation history

The controller can now consume a real `CurrentRuntimeScope` to track a durable
generation within a sandbox incarnation. Reobserving the same Host runtime,
scope handle, payload PID, leaf cgroup, and retained anchor preserves its
number, including across ordinary holder/lease renewal. A distinct scope
advances the generation; reuse of a historical handle, or reuse with changed
execution facts, fails closed. A Host restart may conservatively require a
new generation even if the underlying namespaces did not change.

Journal namespace 11 stores fixed-width, versioned audit records and exact
latest-generation heads in one transaction. Replay requires contiguous,
hash-linked history and checks every originating binding against protected
runtime-authority history. The fixed capacity is 4096 historical generations
across all sandbox incarnations; no implicit pruning is supported. Older
builds reject the new namespace rather than reinterpret it. Reconciliation
validates retained generation state before dispatching effects.

The non-cloneable result retains the original live Host/payload proof and its
non-renewable deadline. Tracking checks current authority before and after
commit; later use must recheck both that proof and the protected generation
head. Stored PID/cgroup identifiers and digests are audit evidence, never
reconstructed live authority. Failure after commit can leave an inert record
without returning a live result.

Twelve new inert-ledger regressions cover exact codec bounds and corruption,
scope reuse, renewal and revocation history, restart and compaction, corrupt
heads and binding references, capacity, and rejection before reconciler
effects. Default-feature tests, serial all-feature sandbox tests, API/doc tests,
and strict Clippy pass. Parallel all-feature reruns intermittently failed
existing descriptor-close and journal-lock assertions while subprocess
fixtures ran; the kernel-test harness already uses serial execution.
These are not live controller/Host reboot tests. Recording or recovering a
generation does **not** mark attachment replay complete, issue an endpoint,
or enable backend readiness. The observed execution number is not by itself
the signed assignment's expected namespace generation: matching and publishing
that binding remains part of the replay integration. Controller-driven
attachment replay and its live reboot qualification remain open under
`SBX-RT-06` and `SBX-VIEW-03`.

The full `checks.eval` attempt built the release CLI but failed its workspace
test phase: 4442 tests passed and two unrelated Hub tests failed. The OCI
multi-platform roundtrip test exhausted its upload-cancellation retry deadline;
the concurrent pre-GC migration test encountered a SQLite database lock.
No sandbox test failed in that hermetic run. Isolated Hub reruns in the shared
incremental target stopped before execution because a cached protocol build
script referenced another worktree's Hub API manifest. The full evaluation
gate is therefore not qualified by this increment; no unrelated Hub code or
test assertions were changed to bypass these failures.

### Physical scope continuity across assignment updates

The Host now preserves a payload scope handle across separately admitted
assignment updates only when both retained kernel proofs identify the same
sandbox incarnation, supervisor invocation, live payload, root, cgroup,
mount namespace, and network namespace. Full launch verification is required
to transfer the pins to another assignment key; a supervisor-only observation
cannot do so. Stopped, dead, replaced, or uncheckable old executions do not
establish continuity. Old runtime handles still fail the durable current-fence
checks, and a preserved scope handle grants no authority by itself.

The controller's observed-generation comparison now treats the signed
assignment's runtime handle as an alias rather than physical identity. The
origin alias remains in the immutable audit record, and replay recomputes it
from the protected historical assignment binding. A regression supplies
substituted origin facts with mutually consistent record/head hashes and
requires rejection. Publisher/session authorization continuity checks remain
unchanged; physical continuity does not renew or transfer an old grant.

This removes a potential feedback loop in namespace-target publication:
updating an assignment digest need not itself mint another physical scope
and advance the observed execution counter again. The distinct observed
counter and signed namespace-target binding still require explicit controller
integration before attachment replay; this increment does not equate them or
qualify readiness.

The production worker VM passes with real retained kernel pins: synthetic
assignment metadata changes preserve physical scope, a mismatched supervisor
invocation does not, two guest-triggered reboots each reject the old scope,
and stopping the payload invalidates continuity. The metadata substitution
tests physical identity only; it does not qualify signed assignment admission
or controller-driven attachment replay.

Serial all-feature validation passes 258 sandbox and 88 Host unit tests,
plus API/doc tests; the privileged worker test is separately qualified in
`checks.fleet.sandbox-host-worker`. Strict Clippy, Rust formatting, and diff
checks pass. The final-source `checks.eval` and Host worker VM gates pass.
An earlier final-source build failed the unrelated OCI roundtrip test's
upload-cancellation deadline; its exact retained binary passed in isolation,
and the full workspace test phase passed on retry without code changes.

### Same-owner signed assignment advancement

Ownership protocol 1.1 adds a distinct `Advance` action for changing the
assignment digest and increasing desired generation without changing node,
sandbox, incarnation, or assignment epoch. It requires the exact prior lease
generation/digest and a newer issued lease. Renewal still preserves assignment
semantics and now explicitly checks the receipt-authenticated desired
generation. Admission, post-issuance validation, and historical chain recovery
share the same transition rules; pending advancement excludes competing renewals
and updates for that sandbox.

Acquire/renew claim and receipt bytes remain unchanged. Advance claims use
the previously unknown action code 3, and advance receipts require protocol
minor 1. A 1.0 session cannot submit, query, or resume an advance transaction.
Older journal readers reject the new action rather than reinterpret it.
Completed replay returns the original four artifacts without consulting an
issuer or manufacturing current authority.

Regression coverage includes exact claim/receipt version binding, malformed
prior fences, owner and generation substitutions, signed but invalid historical
chains, pending-operation conflicts, the external-issued/local-uncommitted
crash window, renewal after advancement, compaction/reopen, and old-session
rejection before issuance. The controller/in-process-service composition test
publishes a signed namespace target change from 8 to 9 at desired generation 8,
reopens both journals, verifies the recovered current manifest and advance
receipt, and replays both operations without contacting the issuer again.
This uses an inert descriptor-free Stop template, not live attachment replay.

This advances `SBX-CTRL-03` and removes an ownership-publication dependency for
`SBX-RT-06`/`SBX-VIEW-03`. The controller still needs to bind observed runtime
generations to signed namespace targets and drive descriptor-backed attachment
replay. Migration, endpoint fencing, production ownership issuance/deployment,
and backend readiness are not qualified by same-owner advancement. A new lease
alone does not install broker fences, update the guardian, or revoke old grants.

Validation passes the serial all-feature sandbox, ownership-protocol, and core
test suites, API/doc tests, strict Clippy for all targets of those crates,
Rust formatting, and diff checks. The hermetic `checks.eval` gate passes,
including the release CLI build, full workspace test phase, configuration
evaluation, and system-structure checks. No live Host or attachment VM
qualification is claimed for this protocol/publication increment.

### Privileged Host-to-Mount scope acquisition (in progress)

The Host broker can now export a launched payload's root and namespaces
directly to the privileged Mount broker, without sending those descriptors
through the node controller. Host protocol 1.3 adds a RootMount-only query
with an exact retained-scope grant. Mount protocol 1.2 adds a read-only catalog
preparation request: the controller supplies a prospective Mount operation and
the complete authorized Host query, Mount performs the Host exchange, and the
controller receives only the resulting opaque catalog commitment. Existing
controller Host observations retain their two-descriptor protocol.

The deployed Host socket gives the root group access without adding a
DAC-override capability to Mount. Host service-cgroup verification still
separates the RootMount and controller method sets. A query for a replaced
scope fails rather than acquiring the replacement under old authority. Mount
keeps successful observations only in a bounded memory registry. It derives
the destination beneath the Host root, matches it to the protected catalog
pin, and rejects a changed scope under the same assignment and namespace
generation. Restart requires preparation again before replay.

This advances `SBX-HOST-01` and the live resource handoff needed by
`SBX-VIEW-03`. The controller still needs to call preparation while compiling
plans, sign the returned catalog commitment, and drive attachment replay. The
root-owned catalog publisher also remains a prerequisite; the current file
format consumes its already pinned sources and slots but does not create them.

Validation passes the Host, Mount, Linux transport, protocol, and core crate
suites, strict Clippy, formatting, diff checks, and the local-identity VM
fixture. Preparation regressions cover 1.2-only negotiation, nested request
and authority binding, live descriptor-backed resolution, exact refresh, and
changed-scope rejection. The root-only VM exercises the complete five-FD Host
exchange and prepared catalog with kernel descriptor identities. The synthetic
responder does not qualify Host launch attestation, production catalog
publication, controller plan signing, or end-to-end attachment replay.

### Observed-to-signed namespace target allocation

The controller now keeps the local observed runtime sequence distinct from the
namespace generation carried by signed assignment authority. The first live
observation for an incarnation seeds a protected allocation from the current
manifest. Later observed generations advance that target by the same positive
delta, so skipped unused observations cannot alias an earlier namespace target.
Immutable allocation records reference the exact runtime-generation audit
digest and form their own hash-linked, per-incarnation history and exact head.

If current authority still names an older target, the controller returns an
inert advancement proposal containing the required target and both audit
identities. It does not return a live target. The caller must complete the
authorized same-owner assignment advancement, reacquire and retrack the Host
proof, and bind it again. Only an exact current manifest target can produce the
non-cloneable `CurrentNamespaceTarget`; later checks repeat live runtime,
runtime-head, allocation-head, and signed-manifest validation. Restart cannot
reconstruct it from the journal.

Journal namespace 12 uses fixed-width `AOSNST01` records, a bounded 4096-record
history, and fail-closed cross-reference validation before reconciliation.
Codec, substitution, replay, compaction, monotonic-delta, overflow, capacity,
and corrupt-ledger regressions are present. This supplies the fencing bridge
needed before controller Mount preparation, but does not yet issue the Host
RootMount grant, call Mount, sign a Mount Apply plan, replay attachments, or
qualify backend readiness.

Validation passes the serial all-feature sandbox suite (273 unit tests, the
public API test, and 12 doctests), strict Clippy for every sandbox target,
formatting, and diff checks. The hermetic `checks.eval` gate also passes,
including the release CLI build, full workspace test phase, configuration
evaluation, and system-structure checks. This allocation-only increment does
not claim live Host, Mount, or attachment VM qualification.

### Controller-bound Mount catalog preparation

The controller now consumes a live `CurrentNamespaceTarget` and a fence-free
Mount intent to construct the complete preparation exchange. Assignment facts,
namespace generation, request identity, deadline, deterministic runtime handle,
and opaque payload-scope handle all derive from current protected and retained
state. Caller-supplied context is rejected. One request ID, assignment fence,
and exclusive deadline bind the outer Mount request, prospective Apply, and
authorized Host RootMount query.

The Host query reuses the exact current publication plan and ownership lease,
but only after controller verification finds its distinct RootMount grant.
Signed authority stays at protocol 1.1 while the Host payload and RootMount
carriers require 1.2 and 1.3 respectively; the controller and Host now agree on
that split. The Mount client authenticates the actual response writer against a
trusted service cgroup and accepts no descriptors or outer authorization.

The volatile result retains its live namespace target, Mount-produced catalog
commitment, inherited deadline, portable semantic grant identity, and
deadline-free Apply body. A separately supplied Mount plan is reverified under
the pinned controller trust anchor, exact current assignment and ownership
authority, then matched to that catalog-dependent grant. Neither preparation
nor plan binding writes the journal or dispatches an effect. Restart
re-preparation, attachment replay, root-owned catalog publication, and backend
readiness remain outstanding.

Validation covers strict all-target, all-feature clippy for both changed crates;
276 sandbox unit tests, the downstream sandbox API test, 70 protocol unit
tests, 13 sandbox doctests, and the protocol doctest. The complete test set
passes with one test thread. An unconstrained parallel run also passed every
new preparation and protocol test, but exposed the existing timing sensitivity
in two unrelated Unix-socket close-observation tests; no result from that run is
used as positive evidence. `nix-build -A checks.eval` passes, including the
release CLI build, full workspace test phase, configuration evaluation, and
system-structure checks.

### Durable controller Mount attempt admission

The controller can now turn a live prepared catalog and its separately signed
Mount plan into a durable-before-I/O attempt. Admission rechecks the current
runtime and namespace heads, re-verifies the Mount plan against the exact
current ownership lease, limits the attempt to both lease and catalog
lifetimes, and commits the exact template body, deadline-bearing Apply body,
authorization packet, catalog commitment, and immutable namespace-allocation
reference before returning the packet. Reusing a request identity replays only
byte-identical state; any changed lease, deadline, plan, catalog, body, or
packet conflicts.

Journal namespace 13 uses the versioned, digest-protected `AOSMTA01` format.
Replay is bounded by both record count and retained bytes and revalidates the
Mount protobuf, authorization envelope, canonical plan and lease encodings,
signature-statement subjects, assignment fence, catalog-derived semantics,
template digest, and the complete runtime-generation-to-namespace-allocation
chain. Corruption blocks reconciliation before an executor is consulted. The
returned `DurableCurrentMountAttemptV1` remains non-cloneable and retains the
live preparation; its deadline and all live heads are checked again before use.

This increment performs no Mount socket I/O and does not mark an attachment
installed or ready. Restart deliberately cannot reconstruct a dispatch token:
Mount's descriptor catalog is volatile, so recovery still needs authenticated
inventory, fresh catalog preparation and planning, and an attachment state
machine capable of adopting or removing broker-proven intermediate mounts.

Validation passes all 285 sandbox unit tests, the downstream public API test,
and 14 doctests with one test thread, plus strict all-target/all-feature Clippy,
Rust formatting, and diff checks. The hermetic `checks.eval` gate passes its
release build, full workspace test phase, configuration evaluation, and system
structure checks. No live Mount dispatch or attachment VM qualification is
claimed by this admission-only increment.

### Authenticated Mount Apply and durable success correlation

The controller can now transmit an already durable current Mount attempt over a
single-use Mount 1.2 client. The client requires signed-plan/lease negotiation,
authenticates the actual hello and response writers against the configured
service cgroup and credentials, and sends the byte-exact admitted authorization
packet. Successful `MountResult` decoding rejects unknown fields, inner errors,
Apply-body substitution, and every mismatched attachment, view, source
generation, state, or handle. CREATE handle derivation is shared by the
protocol validator and privileged broker so the two sides cannot drift.

Successful responses enter journal namespace 14 as bounded, digest-protected
`AOSMTC01` records that cross-reference the exact `AOSMTA01` attempt digest.
The controller commits and reloads this receipt before returning a non-cloneable
live completion token, then rechecks current namespace authority. Completion
corruption or an orphaned result blocks ordinary reconciliation before executor
access. An exact re-dispatch replays only the same success bytes.

This is success correlation, not attachment readiness. A request can become
durable inside Mount and then lose its reply or return a retryable backend
error. Such outcomes remain non-terminal and require the separately
authenticated resource inventory and attachment desired-state reconciler still
to be implemented; no absence, rollback, or cleanup inference is made from the
transport result alone.

Validation passes all 289 sandbox unit tests, its downstream public API test
and 14 doctests; all 73 protocol unit tests and its doctest; and all 62 default
Mount broker unit tests with one test thread. Strict all-target/all-feature
Clippy passes for all three changed crates. The Mount crate's all-feature run
also reaches its root-only Host scope fixture, whose explicit non-root guard
rejects this development environment; that VM-only exchange is not claimed as
positive evidence here. The hermetic `checks.eval` gate passes its release
build, full workspace tests, configuration evaluation, and system structure
checks.

### Authenticated Mount resource inventory snapshot

The controller can now query the complete `InventoryMountResources` table over
a dedicated Mount 1.2 session. The client authenticates the actual hello and
response writers against the configured service execution, admits only the
closed read-only method with an empty descriptor table, and validates every
bounded resource, lifecycle, kernel identity, recipe, and replacement
correlation before the response reaches controller state.

The exact query and response become the latest durable `AOSMTI02` snapshot in
journal namespace 15. Its response ceiling leaves explicit room below the
journal's 16 MiB record-frame limit while carrying the protocol's complete
1,024-row inventory. Snapshot replacement rejects broker journal rollback,
same-sequence resource equivocation, request-ID reuse, and a single broker
instance claiming two kernel boots. Corrupt records block ordinary controller
reconciliation before executor access. The record binds the complete validated
namespace-target, Mount-attempt, and completion set that existed before the
query, so a later controller mutation makes the snapshot stale rather than
letting pre-intent absence masquerade as a current observation.

This increment establishes authenticated durable observation, not a cleanup
decision or attachment-ready state. Live service exchange and reboot behavior
still require the Mount namespace VM qualification.

Validation passes all 294 sandbox unit tests, its downstream public API test,
and 14 doctests. Strict all-target/all-feature Clippy passes for the changed
crate. The hermetic `checks.eval` gate passes the release build, full workspace
tests, configuration evaluation, and system structure checks.

### Current-target Mount inventory reconciliation

The controller can now consume a current live namespace target and a fresh
durable inventory snapshot to compare every exact attempt for that target with
Mount's complete table. Resource handles are derived from or taken from the
original request, never from paths or list position. Any binding fence,
namespace generation, attachment, destination slot, view, source generation,
attributes, or replacement-predecessor substitution fails the comparison.

The retained report classifies each attempt in stable request-ID order as not
observed, exact pending, exact faulted, successful without a controller
receipt, superseded by another operation, or completed with a durable receipt.
It separately exposes current-bound Mount handles with no local attempt. The
snapshot must remain latest and its controller-state commitment must still
match before and after comparison; the live target is likewise rechecked on
both sides. The report retains that non-cloneable target for the next planning
step.

The classifications are evidence, not policy. In particular, absence does not
authorize retry, an untracked handle does not authorize deletion, and a Mount
completion does not establish post-attach readiness. Attachment desired state,
fresh planning, cleanup authorization, and final kernel verification remain
separate work.

Validation passes all 301 sandbox unit tests, its downstream public API test,
and 14 doctests. Strict all-target/all-feature Clippy passes for the changed
crate. The hermetic `checks.eval` gate passes the release build, full workspace
tests, configuration evaluation, and system structure checks.

### Generation-fenced attachment desired state

The controller can now persist one complete attachment intent while retaining
and rechecking the exact current namespace target on both sides of the commit.
Creation requires expected absence and generation 1. Replacement and release
require the exact predecessor record digest and the next generation; consumer
identity and destination slot remain stable, released identities cannot be
recreated, and two present attachments cannot occupy one slot in the same
consumer namespace generation. Operation IDs are unique across the retained
attachment history, while an exact operation, request digest, predecessor, and
intent replay is idempotent.

Journal namespace 16 retains every generation as a bounded, immutable
`AOSATD01` record. Each record carries canonical attachment CBOR, the normalized
request digest, operation identity, presence or release state, and the exact
predecessor digest in its own hash preimage. Replay validates the full chain,
record keys, canonical semantic decoding, current slot uniqueness, a 65,536
generation ceiling, and a 256 MiB retained-byte ceiling. Corruption blocks
ordinary reconciliation before executor access, and compaction/restart retains
release tombstones.

The portable attachment codec now covers every identity and generation, source
view and optional live incarnation, descriptor, destination slot, consistency,
mutation, closed mount attributes, and lease. Construction and decoding reject
zero sentinels, wrong descriptor roles, mutation/read-only mismatches, missing
`nosuid` or `nodev`, and invalid lease intervals. Mount inventory controller
commitments advance to domain v3 and include the exact attachment desired-state
namespace, so any later desired mutation makes a pre-mutation snapshot stale.

This advances `SBX-VIEW-01` but does not complete it: durable source handles,
view-revision publication, lease-expiry scheduling, realization planning,
atomic Mount replacement, post-attach verification, cleanup, and reboot replay
remain separate work. Desired state is not effect authority and does not mark
an attachment ready.

Validation passes all 264 sandbox unit tests, its downstream public API test,
and 14 doctests; all 186 core unit tests and its 3 doctests also pass. Strict
all-target/all-feature Clippy passes for both changed crates. The hermetic
`checks.eval` gate passes its release build, full workspace tests,
configuration evaluation, and system structure checks.

### Complete Mount source recipe and generation fences

Every Mount operation now distinguishes the current desired attachment
generation authorizing the action from the generation of the physical resource
recipe it creates or addresses. Creation, install, and replacement require the
two to agree; detach and release may name an older resource only while carrying
an equal or newer desired generation. Both generations are part of request
validation, portable signed semantics, root-owned catalog matching and
commitments, sealed helper plans, success receipts, broker checks, and
controller correlation. A recipe-identical older generation therefore cannot
satisfy newer desired state, while cleanup no longer has to mislabel an old
resource as the current generation.

The immutable recipe also retains the logical source-view ID, exact source-view
generation, optional local-live source incarnation, closed source consistency,
view descriptor, and the complete mount policy. The recursive clone bit now
survives validation, canonical authority, broker persistence, inventory, and
the actual detached-mount syscall instead of being silently dropped.
Transactional service projections remain outside the native Mount broker.
Inventory replacement edges require strict assignment and resource generation
advancement, and controller reconciliation applies the same rule without
requiring the predecessor and successor to have an impossible equal assignment
fence.

The desired attachment lease ID and wall-clock interval are carried and bound
by Apply, catalog commitments, signed semantics, and the exact success receipt.
They are operation authority rather than physical recipe state, so inventory
does not manufacture or extend lease authority. Source, generation, recursive,
and lease substitutions fail closed across protocol, authorization, result,
catalog, durable broker state, and reconciliation tests.

The changed canonical Mount semantics, static and Host-backed catalog
commitments, sealed helper plans, and durable broker-resource envelope advance
their embedded format versions. Older durable resource envelopes are not
silently decoded under the stronger schema. This corrects Mount 1.2 on this
unmerged implementation branch; it does not claim a migration path from an
already deployed Mount resource journal.

Validation passes all 266 sandbox unit tests, its downstream public API test,
and 14 doctests; all 63 Mount broker unit tests, its helper integration test,
and two doctests; and all 76 protocol unit tests and its doctest. Strict
all-target/all-feature Clippy passes for all three changed crates, and Rust
formatting and diff checks pass. The hermetic `checks.eval` attempt built the
release CLI and ran 4,519 workspace tests: 4,518 passed and the unrelated
`aos-hub` OCI cancellation test timed out in its retry window. That exact test
passed in isolation in 1.95 seconds; the timeout is retained as a visible gate
caveat rather than represented as a successful full gate.

### Plan exact current attachment realization

The controller now combines one exact current attachment desired generation
with a fresh authenticated Mount inventory and retained live namespace target.
It rechecks the desired head and inventory commitment on both sides of
planning, projects durable attempts with their attachment, slot, desired, and
resource generations, and returns one closed next-step description. Present
state can prepare a detached resource, install it, atomically replace a
strictly older fenced predecessor, or require post-attach verification.
Released or expired state drains prepared and replacement-predecessor resources
before detaching an installed generation and never rewrites the resource
generation as current desired state.

Exact pending attempts produce a wait observation, and Mount faults preserve
their phase and sanitized digest. Same-slot foreign resources, substituted
recipes, stale namespaces, non-advancing predecessor fences, competing
operations, released-generation resurrection, and untracked intermediate
transitions report closed conflicts rather than guessed effects. Transactional
service projections are explicitly routed away from native Mount planning.
Lease issue and exclusive expiry times are evaluated from the protected clock;
an expired empty realization cannot be reported ready.

This planner is descriptive and retains no descriptor, catalog commitment,
signed plan, or cleanup authority. The next increment must make Mount
preparation consume this exact plan, add exact pending-attempt replay, and
durably record post-attach verification before any attachment becomes `Ready`.

Validation passes all 316 sandbox unit tests, its downstream public API test,
and 14 doctests with one test thread. The focused reconciliation regressions
also substitute every mutable physical recipe field through the real inventory
decoder. Strict all-target/all-feature Clippy, Rust formatting, and diff checks
pass. The hermetic `checks.eval` gate passes the release build, full workspace
test phase, configuration evaluation, and system-structure checks.

### Execute exact attachment Mount actions

The controller can now consume one current attachment reconciliation result and
prepare its exact native Mount effect without accepting a caller-authored
protobuf. CREATE fields come from current desired state. INSTALL and REPLACE
address the exact inventoried resource recipe. DETACH and RELEASE reproduce the
older physical recipe while carrying the current desired generation and lease,
so cleanup neither rewrites history nor borrows authority from inventory. Only
the five Mount effect actions are accepted; observations, conflicts, faults,
waits, and transactional-service routing fail closed at this boundary.

The workflow retains desired state, the complete authenticated inventory
snapshot, the selected action, and live namespace authority through descriptor
catalog preparation and separate signed-plan binding. It re-runs the exact
planner and all currentness checks immediately before durable admission.
Admission necessarily advances the controller-state commitment and makes that
older inventory snapshot stale. The non-cloneable admitted token therefore
retains the desired generation, lease mode, lower-level Mount token, and live
namespace authority through dispatch. A concurrent desired-state change after
broker I/O cannot erase evidence: the exact successful receipt is committed
before a stale live completion is withheld.

RELEASE now has an explicit catalogless path. It derives its fence and lifetime
from the current target and must match a separately signed Mount plan, but it
does not ask Host or Mount to reacquire namespace descriptors. Durable Mount
attempts advance to `AOSMTA02`; a flag distinguishes the required catalog
commitment on CREATE, INSTALL, REPLACE, and DETACH from the required all-zero
catalog field on RELEASE. The codec, canonical-semantics check, and success
receipt validation reject action/catalog substitution and legacy `AOSMTA01`
records rather than silently reinterpreting them.

This closes action derivation and first-issue execution, not attachment
readiness or crash replay. A pending exact attempt still needs authenticated
query/resume policy after restart, and an installed resource still requires a
durable post-attach kernel verification record before the attachment or sandbox
can become `Ready`.

Validation passes all 321 sandbox unit tests, its downstream public API test,
and 14 doctests with one test thread. Strict all-target/all-feature Clippy,
warnings-as-errors rustdoc, targeted Rust formatting, and diff checks pass. The
hermetic `checks.eval` gate passes the release build, full workspace test phase,
configuration evaluation, and system-structure checks.

### Durable post-attach verification and attachment readiness

An installed Mount inventory row can now become attachment-ready only through
a separate durable verification transition. The controller consumes the exact
closed `Verify` reconciliation, rechecks desired state, the complete inventory
commitment, and live namespace target, then commits an immutable `AOSATV01`
record. The record binds the desired generation and record digest, historical
namespace-allocation reference, current assignment tuple, inventory snapshot
and query, Mount handle and resource revision, resource boot identity, complete
kernel mount observation, and canonical desired-recipe and full-resource
digests. Root and mount-point bytes, unique and parent mount IDs, mount namespace,
device and superblock identity, VFS attributes, propagation, and identity-map
commitment all remain explicit durable evidence.

Journal namespace 17 retains bounded generation history and validates every
desired-state and namespace-allocation cross-reference on replay. The Mount
inventory controller-state commitment advances to domain v4 and includes this
namespace, so recording verification necessarily stales its source inventory.
A later authenticated inventory yields `Ready` only when the exact current
desired resource reproduces the durable record under the same live target.
Missing or changed verified state reports a closed verification conflict rather
than silently recreating or re-verifying the generation. Explicit release and
lease expiry still drain the resource and do not treat readiness as authority.

Focused attachment tests cover byte-exact codec mutation and truncation,
sentinel and unsafe-path rejection, exact replay conflict, orphaned history,
startup fail-closed validation, and exact-ready versus changed/missing resource
planning. Validation passes all 327 sandbox unit tests, its downstream public
API test, and 14 doctests with one test thread. Strict all-target/all-feature
Clippy, warnings-as-errors rustdoc, Rust formatting, and diff checks pass. The
hermetic `nix-build -A checks.eval --cores 8` gate passes the release build, all
4,537 workspace tests, configuration evaluation, and system-structure checks.
An initial unconstrained run exposed a pre-existing SQLite lock race in one Hub
test, and its first retry gave one `rustc` process SIGSEGV under 128-way build
parallelism. The exact Hub test passed independently, and the concurrency-capped
hermetic rerun passed without changing source or test scope.

### Restart-safe exact pending attachment Mount resumption

The controller can now resume one already admitted attachment Mount operation
after losing its in-memory dispatch token. Recovery begins only from a current
attachment reconciliation whose authenticated complete inventory reports the
exact local request as pending. It loads the immutable `AOSMTA02` attempt by
request ID and current namespace-allocation reference, checks the inventory's
derived or supplied Mount handle, and preserves the original action, Apply body,
request identity, semantic commitment, and exclusive BOOTTIME deadline.

Catalog-backed operations repeat the Host-to-Mount preparation exchange using
the original request and must reproduce the durable catalog commitment. RELEASE
reconstructs only its catalogless preparation. The preparation reports the
required original plan digest so the caller can select the exact signed
artifact. That plan and signature must still verify under current trust and
assignment state; same-generation plan replacement is rejected because Mount's
durable authority fence admits only the original plan digest. The current
ownership lease may be an exact replay or a monotonic renewal. A stale lease,
equal-generation equivocation, changed plan or template, changed catalog or
namespace, modified body or deadline, and expired authority all fail before
dispatch.

Resumption does not write a second controller admission record. It builds a
volatile envelope containing the exact original plan and Apply request with the
current lease, then uses the ordinary authenticated Mount client and durable
completion path. Mount's request-ID and request-digest idempotency fence resumes
the pending worker or replays a completed receipt without allocating a second
resource. If the original deadline has elapsed, recovery remains fail-closed;
the controller does not manufacture a replacement operation from ambiguous
pending state.

Focused regressions prove that reconstruction changes only a monotonic ownership
lease and volatile envelope fields, rejects every durable request, plan,
catalog, namespace, semantic, and deadline substitution, and recreates the
deadline-bearing protobuf from only the exact canonical deadline-free body.
Validation passes all 329 sandbox unit tests, two downstream public API tests,
and 14 doctests with one test thread. Strict all-target/all-feature crate-local
Clippy with warnings denied, warnings-as-errors rustdoc, targeted Rust
formatting, and diff checks pass. The hermetic
`nix-build -A checks.eval --cores 8` gate passes the release build, full
workspace test phase with all 4,540 tests passing and five skipped,
configuration evaluation, and system-structure checks.

### Durable filesystem-view revision authority

The controller can now publish a logical filesystem view before any attachment
names it. Journal namespace 18 retains bounded, immutable `AOSVRS01` revision
history keyed by exact `ViewId` and revision. Each record binds the canonical
portable `View` bytes, their domain-separated object descriptor, the path-free
logical source handle, normalized request digest, operation identity, and exact
predecessor digest. Creation requires revision one and expected absence;
successors are contiguous compare-and-swap revisions. Release carries the last
view unchanged, cannot resurrect the identity, and preserves historical
revisions through compaction and restart. The controller exposes commit,
current-revision, and exact-revision APIs, while the core crate now exposes the
existing canonical view codec needed by downstream clients to derive the same
descriptor.

Attachment admission now requires its source view identity, source revision,
descriptor, consistency class, and mutation mode to match one exact available
published revision. Missing, released, substituted, or semantically widened
references fail before the attachment commit. Restart validation checks every
historical attachment reference against the immutable view ledger in one
bounded scan, so an orphaned or rewritten reference blocks reconciliation
before broker I/O. A view with a present attachment cannot be released. After
attachment release, view release additionally requires a fresh authenticated
Mount inventory proving that no physical resource for any revision of that
view remains; the Mount controller-state commitment advances to domain v5 and
now includes the full view-revision namespace.

Focused validation passes all 339 sandbox unit tests, three downstream public
API tests, and 14 doctests with one test thread. Strict crate-local Clippy with
warnings denied, warnings-as-errors rustdoc, targeted Rust formatting, and diff
checks pass. The hermetic `nix-build -A checks.eval --cores 8` gate passes the
release build, full workspace test phase, configuration evaluation, and
system-structure checks. This advances `SBX-VIEW-01` but does not complete it:
node-local broker resolution to pinned OS source descriptors, live-export
authority and incarnation validation, lease-expiry scheduling, complete view
release/reaping orchestration, and live Mount namespace VM qualification
remain.

### Namespace-bound destination-slot authority

The controller can now create a logical destination slot only while retaining
current authority for the sandbox namespace that will own it. Journal namespace
19 stores a fixed-size `AOSSLT01` creation record binding the slot ID to the
exact sandbox, incarnation, and namespace generation derived from that live
target. A compare-and-swap successor can release the slot, after which its
identity is a permanent tombstone and cannot be rebound to another target or
resurrected. The record contains no host path or descriptor and grants no Mount
authority.

Attachment admission now requires the named slot to be available and bound to
the attachment's exact consumer. Restart validation checks every historical
attachment generation against the immutable creation record, so missing,
rewritten, cross-incarnation, or cross-namespace slot references block ordinary
reconciliation before broker I/O. A present attachment prevents slot release.
After any attachment history, release additionally requires fresh authenticated
Mount inventory proving that no physical resource still names the slot. The
inventory controller-state commitment advances to domain v6 and includes the
complete slot namespace, so slot creation or release immediately makes an older
snapshot stale.

Focused validation passes all 347 sandbox unit tests, four downstream public
API tests, and 14 doctests with one test thread. Strict all-target/all-feature
crate-local Clippy with warnings denied, warnings-as-errors rustdoc, targeted
Rust formatting, and diff checks pass. The hermetic `checks.eval` gate passes
the release build, all 4,664 workspace tests with five skipped, configuration
evaluation, and system-structure checks. This advances `SBX-VIEW-01` but does
not complete it: portable-spec declaration proof, node-local resolution to a
broker-owned pinned destination descriptor, slot materialization and reaping,
lease-expiry scheduling, and live Mount namespace VM qualification remain.

### Portable sandbox-spec declaration authority

The controller can now publish and retrieve the canonical portable sandbox
specification named by assignment authority. Journal namespace 20 stores a
bounded, immutable `AOSSPS01` record keyed by the specification's exact
domain-separated object digest and encoded size. Each record retains canonical
specification bytes, their decoded semantics, operation identity, normalized
request digest, and an independently checked record digest. Exact replays
survive restart and compaction; descriptor collisions, operation reuse,
noncanonical bytes, malformed records, and count or retained-byte exhaustion
fail closed before new state is admitted.

Destination-slot records advance to the fixed-size `AOSSLT02` schema. Creation
derives the sandbox-spec descriptor from the retained current namespace target,
requires that exact published specification to declare the slot ID, and binds
the descriptor beside the sandbox, incarnation, and namespace generation.
Release preserves the creation descriptor even when assignment authority has
since advanced to another specification. Restart validation checks every
historical slot creation against the immutable specification ledger in one
bounded scan, so a missing, rewritten, or non-declaring specification blocks
ordinary reconciliation before executor or broker I/O.

Focused validation passes all 356 sandbox unit tests, five downstream public
API tests, and 14 doctests with one test thread. Strict all-target/all-feature
crate-local Clippy with warnings denied, warnings-as-errors rustdoc, targeted
Rust formatting, and diff checks pass. The hermetic
`nix-build -A checks.eval --cores 8` gate passes the release build, all 4,674
workspace tests with five skipped, configuration evaluation, and
system-structure checks. This closes the portable-spec declaration-proof
portion of `SBX-VIEW-01`; node-local resolution to a broker-owned pinned
destination descriptor, slot materialization and reaping, lease-expiry
scheduling, and live Mount namespace VM qualification remain.

### Crash-recoverable destination-slot materialization

Mount can now turn one exact portable destination-slot declaration into a
broker-owned directory beneath its private attachment-anchor root. The
`DestinationSlotBindingV1` API accepts no caller path: it derives a catalog
location from the sandbox, incarnation, namespace generation, and slot ID, and
derives the fixed payload location under `run/aos/attachments`. Construction
reproduces the canonical sandbox-spec descriptor and requires that exact
specification to declare the slot before any node-local effect is possible.
Catalog validation now rejects a protected destination pin that does not use
the broker-derived catalog location.

Journal namespace 21 stores fixed-size `AOSMSL01` resources through durable
`Materializing`, `Ready`, `Reaping`, and `Released` phases. Materialization
commits intent before creating the directory and commits its exact device,
inode, and kernel-unique attachment-anchor mount ID before returning a live
close-on-exec `O_PATH` pin. Same-boot recovery accepts only the exact retained
directory; absence, replacement, changed ownership or mode, and mount crossing
fail closed. Interrupted creation resumes from either side of `mkdirat`.
Operation IDs remain unique across all retained resources, exact requests
replay, conflicting bindings do not redirect an existing slot, and released
identities remain permanent tombstones.

Reaping compares the caller's expected ready-record digest and checks the
complete Mount resource table both before and after durable reap admission
under the caller's mutation serialization. Admission closes new resolution
before `unlinkat`; an interrupted removal resumes from either directory state.
A stale-boot resource exposes no descriptor and can advance only to its
permanent tombstone after proving that no path or Mount resource remains.

Focused validation covers canonical declaration and path derivation, exact
identity and descriptor replay, operation and binding conflicts, both
materialization crash boundaries, both removal states, pre- and post-admission
usage checks, same-boot absence and inode substitution, stale-boot cleanup, and
every fixed record byte. All 356 sandbox unit tests, five downstream API tests,
74 host-runnable Mount unit tests, the helper integration test, strict
all-target/all-feature Clippy, warnings-as-errors rustdoc, and Rust formatting
pass. The hermetic `nix-build -A checks.eval --cores 8` gate passes the release
build, all 4,674 workspace tests with five skipped, configuration evaluation,
and system-structure checks. Its first test run encountered the repository's
known concurrent SQLite-open race in one Hub test; that exact test and the
complete hermetic retry passed without a source change.

This advances the node-local destination half of `SBX-VIEW-01` without granting
authority by itself. The signed Mount protocol and service still need to admit
the exact portable declaration, own catalog publication and resource-table
serialization, install the attachment anchor read-only before payload launch,
and orchestrate lease-expiry reaping. Source-handle resolution, live namespace
VM qualification, and end-to-end attachment lifecycle coverage also remain.

### Signed Mount destination-slot authority

Mount protocol 1.3 now exposes a signed destination-slot effect method and a
separate peer-authenticated inventory method. Materialization carries the exact
canonical sandbox specification, its independently reproduced descriptor, the
declared slot ID, namespace generation, and current assignment fence. Reaping
additionally names the exact ready-record digest and preserves the immutable
creation fence separately from newer assignment authority. The validator
accepts that resource fence only for the same sandbox and incarnation and only
when it exactly matches or strictly precedes the current epoch and desired
generation; equal-generation digest substitution fails closed.

Portable canonical semantics commit every action, assignment, specification,
slot, resource, and historical-fence field. Append-only broker verbs 29 and 30
name materialization and reap, while Mount-local authenticated effect codes 6
and 7 preserve those operations across journal recovery without crossing
broker domains. Common signed-plan admission now accepts registered compatible
protocol versions from 1.1 onward, allowing the 1.3 plan to remain version-bound
while Storage and Network stay capped at their registered 1.1 maximum.

The production Mount broker opens the existing private catalog root as the
destination-slot anchor store. It atomically persists the signed assignment
fence, request-ID consumption, and authenticated effect intent before entering
the materializer, rechecks lease and plan authority immediately before each
filesystem boundary, and persists a validated lifecycle receipt for exact
replay. A complete inventory exposes the original binding, specification
descriptor, operation correlations, physical device/inode/mount identity,
lifecycle, and exact record digest. Reap checks the same serialized native Mount
resource table before and after its own durable admission, so installed or
draining resources prevent directory removal.

Focused tests cover exact replay across broker restart, complete inventory,
newer-authority teardown of an older immutable binding, historical-fence
substitution, signature and semantic substitution, domain-separated effect
record round trips, protocol-1.3-only method negotiation, and installed Mount
state blocking reap. The changed sandbox, portable core, common broker,
protocol, and Mount crates pass 676 unit tests. Strict all-target/all-feature
Clippy with warnings denied (excluding dependency linting), warnings-as-errors
rustdoc, targeted Rust formatting, and diff checks pass. The hermetic
`nix-build -A checks.eval --cores 8` gate passes the release build, complete
workspace test phase, configuration evaluation, and system-structure checks.

This completes signed broker admission, durable destination-slot effects, and
lossless inventory for this portion of `SBX-VIEW-01`. It does not yet publish
the catalog JSON entry that connects a source descriptor and Host namespace
scope to the materialized destination identity. Controller-side catalog
publication, read-only attachment-anchor installation before payload launch,
lease-expiry scheduling, source-handle resolution, live namespace VM
qualification, and end-to-end attachment reconciliation remain.

### Atomic Host-backed Mount catalog publication

Mount catalog preparation can now publish the missing protected JSON entry
inside the root broker after it verifies the complete resource tuple. Source
pins use a fixed path derived from the source view, source generation,
consistency scope, optional live incarnation, and exact view-revision digest.
The destination pin and payload path are derived independently from sandbox,
incarnation, namespace generation, and slot identity. No controller path or
descriptor enters the request.

The broker first prefers an exact existing entry and fails closed if any of its
recorded identities changed. If no entry matches, it resolves the derived
source, proves that the Host-root destination is the same inode as the
broker-owned slot, binds the retained Host runtime and payload-scope handles,
root identity, mount namespace, and user namespace, and atomically replaces
`catalog.json` through a write, file sync, rename, and directory sync. Exact
publication replay leaves the generation unchanged; replacement advances it
and therefore changes the catalog commitment. The single-threaded Mount service
serializes preparation with destination-slot and native Mount mutations.

Host scope custody is now keyed by sandbox, incarnation, and namespace
generation rather than assignment generation. Both the volatile registry and
the published entry reject a changed runtime handle, payload-scope handle,
root, mount namespace, or user namespace under the same namespace generation,
including across same-node assignment advancement and broker restart. Legacy
static path-backed entries remain readable, while newly published entries
explicitly omit reopenable Host namespace and root paths.

Focused tests cover deterministic source naming, static/prepared schema
separation, stable ordered upsert, interrupted-next-file replacement, exact
readback, private file mode, and catalog commitment changes. All 80
host-runnable Mount unit tests and strict all-target/all-feature Clippy pass.

This closes catalog entry publication once both physical endpoints already
exist. It deliberately does not create or authorize the source pin, install the
broker-owned attachment anchor into the payload root, or solve the pre-launch
ordering needed to make that anchor available before workload execution.
Source-handle resolution/materialization, anchor installation, controller
destination-slot lifecycle dispatch, lease-expiry scheduling, live namespace
VM qualification, and end-to-end reconciliation remain.

### Durable controller destination-slot inventory

The node controller can now authenticate Mount's complete protocol 1.3
destination-slot inventory and retain the exact query and response as its
latest durable observation. The fixed `AOSDSI01` record commits the request
identity, complete broker response, and a digest of the controller namespaces
that govern namespace targets, view revisions, logical slots, attachment
intent, verification, and Mount attempts. Any relevant controller mutation
therefore makes an older snapshot unusable before follow-up planning.

Snapshot replacement rejects reused request identities, broker journal
rollback, same-sequence resource equivocation, and a changed kernel boot under
one broker-process identity. Reconciler startup validates the new append-only
journal namespace before operation replay or executor I/O. Inventory remains
observation evidence: the returned opaque value carries no namespace
descriptor and grants no signed broker authority.

One current logical slot can be compared with that fresh snapshot to classify
materialization, interrupted materialization, ready state, reap, interrupted
reap, or terminal release. The comparison requires exact sandbox,
incarnation, namespace generation, sandbox-specification descriptor, creation
operation, and release operation correlations. A reused slot ID with a
different binding or operation fails closed instead of being treated as an
absent resource. Released logical intent deliberately finishes an interrupted
materialization before asking Mount to reap the resulting exact resource.

Focused tests cover every available and released lifecycle classification,
the closed durable codec, rollback and equivocation, stale controller state,
binding and operation substitution, successful opaque-result retention, and
fail-closed reconciler startup. All 321 sandbox unit tests and six downstream
API tests pass. Strict all-target/all-feature Clippy with warnings denied,
warnings-as-errors rustdoc, targeted Rust formatting, and diff checks pass. The
hermetic `nix-build -A checks.eval --cores 8` gate passes the release build,
complete workspace test phase, configuration evaluation, and system-structure
checks.

This supplies restart-safe evidence for controller-side destination-slot
orchestration but does not yet prepare, sign, persist, dispatch, or complete a
materialize or reap request. Source-handle resolution/materialization,
read-only attachment-anchor installation before payload launch, controller
slot-effect dispatch, lease-expiry scheduling, live namespace VM
qualification, and end-to-end attachment reconciliation remain.

### Durable signed controller destination-slot effects

The node controller can now carry a reconciled materialize or reap decision
through exact signed Mount 1.3 dispatch. It derives every portable request
field from the current logical slot, its retained canonical sandbox
specification, fresh authenticated destination-slot inventory, and a live
namespace target. A separately supplied signed plan must grant those exact
canonical semantics under the current assignment. Preparation stays volatile
and non-authorizing until admission rechecks every input and commits the
complete deadline-bearing packet before Mount I/O.

Journal namespaces 23 and 24 retain fixed, digest-protected
`AOSDSE01` attempts and `AOSDSC01` successful receipts. An attempt binds the
logical operation, immutable namespace-target allocation, specification,
assignment, semantics, signed plan, original exclusive deadline, lease,
request body, packet, and the complete prior ready-resource identity needed by
a reap. Recovery starts only from a fresh inventory row reporting the exact
pending materialization or reap. It reproduces the original body, plan, and
deadline while allowing only a monotonically newer current ownership lease;
missing, completed, substituted, expired, or differently correlated state
fails closed without dispatch.

The dispatch client negotiates only the destination-slot method, authenticates
the actual Mount hello and response writers against the retained service
cgroup, and accepts only a terminal receipt for the admitted request and exact
resource. The controller commits that receipt before returning a live
completion token. Attempt and completion records participate in the Mount
inventory controller-state digest, now domain v7, so their admission
immediately invalidates older planning snapshots. Startup validates both new
namespaces and all logical, specification, namespace-target, attempt,
completion, and materialization cross-links. Request identities cannot cross
between ordinary Mount attempts and destination-slot attempts.

Mount recovery also repairs a stale-boot `Materializing` row whose path was
already proved absent: it durably rebinds only the same exact operation and
request to the current boot before retrying directory creation. This closes
the otherwise stuck pre-`mkdirat` reboot boundary without making stale
physical identity usable.

Focused tests cover every attempt and completion byte, recomputed field
substitution, immutable pending reconstruction, materialization cross-links,
action correlation, materialize and reap receipts, capacity bounds,
cross-domain request IDs, fail-closed startup, and stale-boot interrupted
materialization. All 375 sandbox unit tests, seven downstream API tests,
14 sandbox doctests, 81 host-runnable Mount unit tests, the Mount helper
integration test, and Mount doctests pass. Strict all-target/all-feature
crate-local Clippy, warnings-as-errors rustdoc, targeted Rust formatting, and
diff checks pass. The all-feature Mount unit run additionally passes 83 tests;
its sole host failure is the existing root-VM-only Host-scope fixture, which
intentionally refuses to run outside that environment.

This completes controller-side signed admission, durable dispatch, exact
pending recovery, and receipt recording for destination-slot effects. It does
not yet install the broker-owned attachment anchor into a payload root,
materialize source handles, schedule attachment-lease expiry, or resolve
stale ready destination slots after a host reboot. Live namespace VM
qualification and an end-to-end attachment lifecycle also remain.

### Pre-launch assignment-bound destination slots

Destination-slot creation and materialization no longer require an already
running payload. The controller can acquire a short-lived
`CurrentAssignmentTarget` directly from the protected bound-holder decision,
current authority publication, verified ownership lease, and paired clock. It
derives the sandbox, incarnation, reserved namespace generation, and canonical
sandbox-specification descriptor exclusively from the signed assignment. The
target carries no Host process, root, cgroup, or namespace observation and
therefore cannot claim runtime readiness.

Logical slot admission and signed Mount 1.3 destination-slot effects now
consume that assignment target. Their pre- and post-commit checks preserve one
fixed deadline while allowing only an uninterrupted same-holder renewal chain
with the identical canonical assignment. Revocation, holder replacement,
same-holder rebind after revocation, assignment substitution, clock divergence,
or expiry invalidates the live target. A caller that already holds a live
runtime or namespace proof may deliberately discard its execution evidence and
retain only the more limited assignment target.

Durable destination-slot attempts use the new `AOSDSE02` record. It replaces
the impossible pre-launch namespace-allocation reference with an exact
runtime-authority binding revision and digest. Startup validates the complete
runtime-authority namespace, requires the retained origin to be a bound holder,
and cross-checks its incarnation, epoch, desired generation, assignment digest,
reserved namespace generation, and sandbox specification against the exact
request. Recovery reacquires fresh assignment authority and proves an
uninterrupted origin-to-current chain; durable bytes never reconstruct live
authority. Existing `AOSDSE01` rows require migration rather than being
reinterpreted under the stronger format.

Focused tests cover acquisition without Host I/O, fixed assignment-derived
identities, same-holder renewal, revocation and rebind rejection, the complete
version-two attempt codec, and the downstream public slot API. All 377 sandbox
unit tests, seven downstream integration tests, and 15 doctests pass. Strict
all-target/all-feature crate-local Clippy, warnings-as-errors rustdoc, targeted
Rust formatting, and diff checks pass. The hermetic
`nix-build -A checks.eval --cores 8` gate passes the release build, complete
workspace test phase, configuration evaluation, and system-structure checks.

This removes the circular dependency that previously required payload
observation before creating the attachment anchor that must precede payload
launch. It does not yet install the broker-owned anchor read-only into the
payload root or materialize a source pin. Host launch-resource integration,
source-handle resolution, lease-expiry scheduling, stale-ready recovery, live
namespace VM qualification, and end-to-end attachment reconciliation remain.

### Fail-closed stale destination-slot identity

Controller destination-slot reconciliation now distinguishes a physically
ready row from a usable current-boot resource. A `Ready` record whose retained
kernel boot ID differs from the complete Mount inventory's current boot is
classified as `StaleReady`, retaining only its exact resource digest for a
future authorized recovery transition. It is never returned as `Ready` and
therefore cannot be published into a new payload launch or used as evidence
that its old device, inode, and mount identities are live.

The comparison is repeated when the opaque reconciliation value is consumed,
so replacing the retained inventory or changing controller state cannot turn
stale physical evidence into current authority. Released logical slots may
still reap an exact stale row through the existing no-path cleanup path; an
available logical slot remains blocked until the protocol gains an explicit
crash-recoverable rematerialization operation.

Focused validation covers both same-boot `Ready` and cross-boot `StaleReady`
classification through a durable authenticated snapshot. The complete
`aos-sandbox` all-feature test suite, strict all-target Clippy, warnings-as-errors
rustdoc, and hermetic `checks.eval` passed; the latter produced
`/nix/store/fr976ivn9i0cva6id2zzmw1svaj7akjf-aos-eval-and-system-structure-checks-0`.
This closes the unsafe classification half of stale-ready reboot handling
without claiming that repair is implemented. The authorized rematerialization
transition, read-only attachment-anchor launch installation, source
materialization, lease-expiry scheduling, live namespace VM qualification,
and end-to-end attachment reconciliation remain.

### Crash-recoverable stale destination-slot rematerialization

Mount protocol 1.4 now carries an explicit `REMATERIALIZE` action for an exact
stale ready destination-slot record. The controller derives a domain-separated
operation ID from the logical slot, predecessor record digest, and current
kernel boot. Its signed grant is resource-scoped to that predecessor while the
request separately carries current assignment authority and the immutable
creation fence. A stale row can therefore advance only through one authorized
replacement; it is never reinterpreted as current physical evidence.

Mount checks the exact stale digest, original binding, complete native-resource
table, and path absence before committing a current-boot `Materializing`
intent. It repeats the usage check and rechecks signed authority before
`mkdirat`, then records and pins the new device, inode, and mount identity.
Exact retries resume an admitted intent or replay the completed result. The
original creation correlation remains immutable, and inventory adds the latest
rematerialization operation, request digest, and predecessor digest so recovery
can distinguish initial materialization, pending replacement, completed
replacement, and a later reap. Repeated host reboots can replace successive
stale ready records without losing the original creation lineage.

The durable Mount row advances to fixed `AOSMSL02` bytes, and controller
destination-slot attempts advance to fixed `AOSDSE03` bytes so a later reap or
rematerialization retains any prior replacement correlation. Older
`AOSMSL01` and `AOSDSE02` records require migration and fail closed rather than
being reinterpreted under the stronger formats. Broker verb and local effect
codes remain append-only.

Focused validation covers protocol action shape and resource-scoped semantics,
inventory correlation shape and global operation uniqueness, deterministic
stale classification, current-boot pending recovery, released-while-pending
recovery, attempt and completion substitution, durable admission interruption,
exact replay, chained replacement, broker authorization, and predecessor
substitution. All 380 sandbox unit tests, seven downstream API tests, 15
sandbox doctests, 186 core tests, 83 protocol tests, 19 broker tests, 85
host-runnable Mount unit tests, the Mount helper integration test, and Mount
doctests pass. The single omitted Mount test is the existing root-VM-only
Host-scope fixture. Strict all-target/all-feature crate-local Clippy,
warnings-as-errors rustdoc, targeted Rust formatting, and diff checks pass.
The hermetic `nix-build -A checks.eval --cores 8` gate passes at
`/nix/store/yknpajzkyc5gl5i6n7lgk97h6wbhs1mb-aos-eval-and-system-structure-checks-0`.

This closes stale-ready reboot recovery. Read-only attachment-anchor launch
installation, source-handle materialization, lease-expiry scheduling, live
namespace VM qualification, and end-to-end attachment reconciliation remain.

### Assignment-bound attachment anchors at launch

Host protocol 1.3 launch plans now require one nonzero broker-minted
attachment-anchor handle, and the signed Host semantics bind that handle
independently from ordinary attachment handles. The Host catalog maps it to
one exact assignment and the broker-derived sandbox, incarnation, and
namespace-generation directory. Resolution pins that directory and rechecks
its device, inode, kernel-unique mount ID, root ownership, and fixed mode before
the launch compiler can consume it. Host 1.1 and 1.2 carriers remain compatible
and reject the new field instead of silently ignoring it.

The transient unit passes the root and attachment anchor as two exact named
setup descriptors. The packaged nspawn accepts the anchor only with the AOS
descriptor-root profile, consumes both setup descriptors before collecting
payload activation descriptors, and retains the broker descriptor only in the
supervisor for internal launch attempts. For each payload start it recursively
clones the anchor, applies the payload user-namespace idmap plus read-only,
`nosuid`, `nodev`, and `noexec` attributes, and installs it at
`/run/aos/attachments`. Installation occurs after nspawn has mounted the final
`/run`, applied custom mounts, and configured cgroups, but before it switches
root or forks payload PID 1. Target creation and installation reject symlinks,
wrong mapped-root ownership or mode, and an existing mountpoint.

Mount's broker-side namespace-generation anchor is root-writable mode `0755`
behind assignment-specific mode-`0700` ancestors, while payload slot
directories are traversal-only mode `0555`. This lets Mount materialize and
reap slots and lets non-root workloads traverse declared destinations; only
the separately cloned payload mount is recursively read-only.

Focused validation passes all 87 default-feature Host tests and two doctests,
85 protocol tests and one doctest, 83 Mount tests plus its helper integration
test and two doctests, and 38 systemd crate tests. The patched systemd 259.8
package builds hermetically and passes its nspawn unit and packaged option
checks. Two `nix-build -A checks.eval --cores 8 --no-out-link` runs compiled
the complete hermetic workspace but did not produce a successful gate: the
first passed 4,709 of 4,711 tests before an unrelated Hub SQLite-lock race and
OCI upload-cancellation deadline, and the retry passed 4,710 before only the
same load-sensitive OCI deadline remained. That exact OCI test passed alone in
1.07 seconds through `nix develop -c cargo test`; no changed sandbox or systemd
test failed in either full run.

This closes initial pre-PID1 installation of a resolved destination anchor but
does not claim end-to-end attachment readiness. Controller publication of the
combined Host catalog, source-handle materialization, native attachment replay,
lease-expiry scheduling, and live namespace VM qualification remain. A retained
internal guest reboot also needs an explicit handoff for the next
namespace-generation anchor before it can satisfy the RFC's reboot-replay
invariant; reusing the initial descriptor is not treated as that proof.

### Root-owned Host catalog publication

The Host crate now provides the privileged publication endpoint for complete
launch-resource snapshots. It opens only a root-owned catalog directory with no
group or other write bits, takes an exclusive lock through an independent
directory description, and accepts either an exact byte-for-byte replay or the
immediate successor generation. Rollback, generation skips, same-generation
equivocation, concurrent writers, malformed current state, symlink redirection,
and a current catalog without owner-only regular-file protection fail closed.

Publication preserves subordinate-identity custody across generations. A live
range may remain only with the same workspace handle, sandbox, and incarnation,
or advance to an exact retired-allocation tombstone. Existing tombstones remain
canonical and cannot disappear. Snapshot overlap checks then prevent either
complete or partial reuse. The current interface deliberately retains every
tombstone: reclaiming one still requires a future cleanup-evidence input proving
that no runtime, namespace descriptor, mount, or backing dataset survives.

The publisher removes an interrupted fixed staging name, creates a mode-`0600`
file without following links, writes and fsyncs the complete bounded encoding,
atomically renames it over `catalog.json`, fsyncs the directory, and performs an
exact protected-file readback while still holding the writer lock. It does not
mint handles or physical identities; trusted reconciliation must still derive
the snapshot from authoritative workspace, network, and Mount state.

Focused publication coverage exercises stale staging recovery, exact replay,
generation conflicts, writer serialization, file protection, canonical
tombstones, holder/incarnation substitution, partial overlap, retirement, and
tombstone preservation. The complete default-feature Host suite passes 93 unit
tests, its public semantics integration test, and two compile-fail doctests;
warning-denied Host rustdoc, strict all-target/all-feature Host Clippy without
dependency linting, and diff checks pass. The all-feature host-side unit run
still includes a root-VM-only peer-cgroup fixture and therefore is not a valid
non-root check. A full final-source `nix-build -A checks.eval --cores 8
--no-out-link` compiled the changed Host crate and ran 4,717 workspace tests;
4,716 passed and five were skipped, but the check remained red because the
unrelated Hub OCI distribution cancellation test exhausted its 30-second retry
window. No sandbox catalog test failed.

This advances `SBX-CTRL-03`, `SBX-HOST-01`, and `SBX-RT-02`, but does not connect
the endpoint to the controller. Combined catalog projection still depends on
production workspace and network realizers and an authenticated privileged
publication dispatch. Backend readiness, cleanup-authorized identity reclaim,
source-handle materialization, native attachment replay, lease-expiry
scheduling, internal-reboot anchor handoff, and live namespace VM qualification
remain open.

### Authenticated Host catalog publication dispatch

Host protocol 1.4 now exposes the protected catalog publisher only to the fixed
node-controller peer. The request envelope binds one nonzero catalog generation,
exact byte length, SHA-256 digest, and a single `HOST_CATALOG` descriptor role.
The complete catalog travels in a fully write/grow/shrink/seal-protected memfd,
so the existing bounded sequence-packet carrier never has to embed a catalog of
up to sixteen MiB in one socket record. Host maps only the declared bounded
length, verifies the complete seal set and digest, requires the unique compact
JSON encoding and declared generation, and then invokes the existing atomic
publisher. Its response accounts for the closed request descriptor and confirms
the exact visible generation and digest as either a new publication or an
idempotent replay.

The controller-side one-shot client validates the caller's BOOTTIME deadline,
negotiates only the new method, and authenticates every Host response through
kernel record credentials, a retained pidfd, and exact membership in the
deployment-selected service cgroup. It verifies the same Host execution again
immediately before transferring the sealed catalog and around the final reply,
then accepts success only when the descriptor disposition, generation, and
digest exactly match its draft. Host 1.1 through 1.3 remain compatible for their
existing methods, and Host Apply accepts the 1.4 carrier without changing its
1.1 signed semantics. The packaged host daemon opens the same protected root
for its reader and publisher and advertises publication only when that publisher
is configured.

Focused coverage includes protocol-version and descriptor-role separation,
bounded request and receipt decoding, canonical Host JSON rejection, sealed-file
generation and digest matching, protected published/replay receipts, 1.1-through-
1.4 Apply compatibility, and a three-MiB in-process catalog transfer that
authenticates the responding service and verifies the mapped bytes. All 339
hermetic `aos-sandbox` tests pass; its 340th real-cgroup exchange passes in the
explicit all-feature kernel suite. All 95 `aos-sandbox-host` and 88
`aos-sandbox-protocol` library tests also pass. Strict all-target/all-feature
crate-local Clippy without dependency linting, warnings-as-errors rustdoc,
targeted Rust formatting, and diff checks pass. The hermetic
`nix-build -A checks.eval --cores 8 --no-out-link` gate passes all 4,724
workspace tests, with five skipped, and every system-structure check at
`/nix/store/hmbrk37j1qgmvgss5wvf5i5rzkqvc8w8-aos-eval-and-system-structure-checks-0`.

This supplies the authenticated privileged dispatch left open by the preceding
increment and advances `SBX-BPROTO-04`, `SBX-CTRL-03`, and `SBX-HOST-01`. It does
not yet build or schedule the complete catalog from production reconciler state:
combined projection still depends on workspace and network realizers plus the
existing Mount inventory. Backend readiness, cleanup-authorized identity
reclaim, source-handle materialization, native attachment replay, lease-expiry
scheduling, internal-reboot anchor handoff, and live namespace VM qualification
remain open.

### Authenticated Mount attachment-anchor inventory

Mount protocol 1.5 now reports the broker-owned attachment anchor behind every
current-boot namespace generation that contains a Ready destination slot. Each
strictly ordered row carries the sandbox, incarnation, namespace generation,
boot identity, generation-directory device and inode, and kernel-unique mount
ID. A domain-separated handle commits that complete physical identity for later
use in a Host launch plan. Response validation requires exactly one row for
every current Ready generation, rejects orphan, duplicate, reordered,
stale-boot, and slot-inconsistent rows, and independently recomputes every
handle. Mount 1.4 remains wire compatible and rejects the new field rather than
silently accepting incomplete anchor evidence.

The Mount broker revalidates each live slot pin and its fixed generation
directory while it holds the destination-slot store, groups slots only when
their anchor device and mount identity agree, and binds the response to the
negotiated session version. The controller now queries 1.5, stores the exact
authenticated response in its existing self-authenticating snapshot record,
and exposes a logical-generation lookup over the validated anchor table.
Retained 1.4 records remain recoverable for a one-way upgrade. A 1.5-to-1.4
downgrade, slot change at the same journal sequence, or same-version anchor
equivocation on the same boot at that sequence fails closed. A broker restart
on a new boot may report those former Ready slots without current anchors.

Focused validation covers the frozen handle derivation, version separation,
current-versus-stale boot completeness, physical cross-links, broker directory
revalidation, controller lookup, one-way snapshot upgrade, downgrade rejection,
same-sequence reboot recovery, and same-boot anchor equivocation. All 340
controller, 186 core, 84 Mount, and 90 protocol library tests pass. The four
changed crates also pass all-target, all-feature compilation, strict crate-local
Clippy without dependency linting, warnings-as-errors rustdoc, Rust formatting,
and diff checks. The hermetic `nix-build -A checks.eval --cores 8 --no-out-link`
gate passes.

This advances `SBX-BPROTO-04`, `SBX-CTRL-03`, and `SBX-MOUNT-01`. It supplies
the authoritative Mount half of attachment-anchor catalog projection, but does
not yet combine it with current assignment, workspace, network, and identity
allocation evidence or publish a production launch catalog. Source-handle
materialization, native attachment replay, lease-expiry scheduling,
internal-reboot anchor handoff, and live namespace VM qualification remain
open.

### Shared Host launch-catalog payload schema

The complete Host launch-catalog payload now lives in the node-local protocol
crate shared by the unprivileged controller and root Host broker. Workspace,
network, identity-allocation, attachment-anchor, and allocation-tombstone
records retain the same strict compact JSON representation and sixteen-MiB
bound. Constructors and canonical decoding enforce fixed publisher paths,
assignment and physical-identity completeness, strict handle ordering,
nonoverlapping subordinate identity ranges, and Mount-derived anchor paths.
Read-only accessors let either process inspect those validated semantics without
exposing mutable fields or linking the controller against the privileged Host
implementation.

Host continues to own all privileged behavior: root-directory protection,
generation continuity, identity-allocation tombstone continuity, atomic
publication, physical pin reopening, and launch-time identity verification.
The shared module contains no filesystem access, descriptor acquisition, or
authority minting. Host maps its validation failures into the existing catalog
error surface and re-exports the moved record types, preserving its public Rust
API while the sealed-memfd wire bytes remain compatible.

Focused validation covers canonical shared-schema round trips, unknown and
noncanonical JSON rejection, handle ordering and identity overlap, derived
attachment-anchor paths, the existing Host publication transition suite, and
the existing Host service publication path. Protocol and Host all-target,
all-feature compilation, strict crate-local Clippy without dependency linting,
warnings-as-errors rustdoc, Rust formatting, and diff checks pass.

This removes the implementation-crate dependency that previously blocked
controller-side catalog projection and advances `SBX-BPROTO-04`, `SBX-CTRL-03`,
and `SBX-HOST-01`. It does not claim combined production publication: Storage
and Network still need authoritative current-resource inventories, and the
controller still needs durable whole-catalog generation and tombstone
reconciliation before it can schedule the existing Host 1.4 dispatch.

### Version-separated Storage and Network resource inventory contracts

Storage and Network protocol 1.2 now define distinct authoritative-resource
inventory methods instead of extending the legacy action-summary responses in
place. A 1.1 peer can continue to negotiate the original summaries, but cannot
request either new method or interpret an empty response as a complete physical
snapshot. Both new methods remain authority-free and descriptor-free: the fixed
node controller may observe broker-owned state, but receives no live kernel
descriptor and gains no mutation authority.

Storage snapshots bind every current launchable workspace handle to its exact
assignment fence, portable root image, current-boot root-pin device and inode,
nonzero ZFS dataset GUID, nonoverlapping subordinate identity range, and a
complete broker observation digest. The validator requires bounded strict
handle order, unique physical pins and dataset GUIDs, and derives the only
admissible root path from the handle beneath the fixed Host workspace-pin root.
Snapshot metadata carries the current boot, broker instance, protected catalog
generation, and next durable journal boundary.

Network snapshots likewise bind each current namespace handle to its exact
assignment, current-boot namespace device and inode, closed lifecycle and lease
shape, and observation digest. Default-drop and armed namespaces are explicitly
launchable; fenced namespaces remain visible for cleanup but cannot be projected
into a Host launch catalog. Physical namespace identities and handles are
unique, and the only admissible pin path is derived beneath the fixed Host
network-pin root.

Focused validation covers Storage and Network 1.1/1.2 negotiation separation,
request-header version binding, strict ordering, current-boot enforcement,
duplicate physical resources, overlapping identity ranges, invalid lifecycle
and lease combinations, fixed pin derivation, response ceilings, and nested
hostile-field validation. The protobuf, core registry, and protocol library
suites pass, along with Rust formatting and diff checks.

This advances `SBX-BPROTO-04`, `SBX-CTRL-03`, `SBX-STOR-01`, and `SBX-NET-01`
without claiming an authoritative producer. Storage still needs to publish
these rows from verified ZFS postconditions and protected root pins; Network
still needs its kernel effect/observer and durable lifecycle index. The
controller still needs authenticated one-shot clients, durable snapshot
continuity, and exact projection into the shared Host catalog schema.

### Durable controller acquisition of Storage and Network inventories

The unprivileged controller now has separate one-shot clients for the Storage
and Network 1.2 resource methods. Deployment supplies each expected service
UID, GID, and retained exact cgroup. The client authenticates the actual hello
writer through kernel record credentials and a live pidfd, rechecks that same
execution immediately before request transfer, and requires the response writer
to be the identical process before and after validation. Negotiation admits only
the one authority-free inventory method, and both sessions accept no descriptor
carrier.

Exact request and response bytes become durable in domain-separated `AOSBRI01`
latest-snapshot records under independent append-only journal namespaces. Each
record also commits the complete materialized controller state outside the two
new inventory keyspaces, so independently queried Storage and Network snapshots
can be proven to postdate the same state without one snapshot invalidating the
other. Public snapshot types expose only validated inventory, request and record
identity, outcome, and an explicit currentness recheck; they do not recreate a
socket, descriptor, or mutation permit after restart.

Per-broker continuity rejects request-ID reuse, journal or catalog-generation
rollback, same-sequence or same-generation resource equivocation, and one broker
instance identity appearing across Linux boots. An exact replay is idempotent,
while a newly authenticated broker process may refresh unchanged resources at
the same durable boundary. Startup validation rejects malformed, oversized,
cross-domain, truncated, or digest-substituted records before controller
reconciliation can proceed.

Focused validation covers bytewise and truncation corruption, independent
Storage and Network recovery, rollback and equivocation, broker restart and
cross-boot identity, request reuse, controller-state change, and replacement of
an older durable snapshot. All 347 controller library tests pass, along with
all-target, all-feature compilation, strict crate-local Clippy without
dependency linting, warnings-as-errors rustdoc, Rust formatting, and diff
checks.

This advances `SBX-BPROTO-04` and `SBX-CTRL-03` without claiming catalog
publication or broker production. The controller still needs to combine these
snapshots with exact current assignment, Mount attachment, identity-tombstone,
and Host generation evidence and atomically dispatch the resulting shared
catalog. Storage and Network still need root-side authoritative snapshot
producers backed by their protected journals and verified kernel resources.

### Crash-recoverable controller projection of the Host catalog

The unprivileged controller now projects its complete protected current-binding
set through mutually current Storage, Network, Mount, and destination-slot
snapshots into the shared Host catalog schema. Each launchable assignment must
have one exact workspace, one launchable network namespace, every declared
destination slot Ready under the current boot, the corresponding Mount-owned
attachment anchor, and every currently desired attachment backed by unchanged
durable installed-resource verification. An incomplete new assignment is
omitted, while loss of resources for a published current incarnation blocks a
successor instead of retiring its live subordinate identity allocation.

Catalog publication is now an explicit durable effect. The controller commits
the complete canonical successor as an `AOSHCR01` pending record before Host
I/O, including its source snapshot commitments and predecessor catalog digest.
Recovery returns those exact bytes without consulting newer broker state. Only
an authenticated Host 1.4 published-or-replayed receipt for the same generation
and SHA-256 digest atomically advances the pending record to current. Changed,
missing, malformed, unrelated-predecessor, generation-skipping, and oversized
history fails closed during controller startup. The durable payload ceiling
reserves the reconciliation wrapper, key, and journal framing beneath the
journal's fixed sixteen-MiB record limit.

Successor generation is skipped when projection reproduces the current catalog
exactly. Real successors retain all prior identity tombstones, retire every
removed workspace allocation, and regenerate live allocation evidence for the
new catalog generation. An assignment update within the same incarnation must
first supply complete resources under the existing workspace handle and range;
otherwise the controller keeps the prior catalog rather than creating a
tombstone that would make the live range unusable.

Focused validation covers closed record decoding, byte corruption, durable
framing capacity, predecessor substitution, exact unchanged projection,
identity retirement and tombstone continuity, complete broker joins,
incomplete-resource retention across both unchanged and successor assignments,
exact pending recovery, and confirmation-only current advancement. The
complete all-feature controller suite passes all 400 library tests, eight
downstream API tests, and 15 doctests. Strict all-target/all-feature
crate-local Clippy without dependency linting, warnings-as-errors rustdoc,
Rust formatting, and diff checks pass. The hermetic `nix-build -A checks.eval
--cores 8 --no-out-link` gate passes the complete workspace build and test
closure plus every system-structure check at
`/nix/store/4hqcpkp0dv78i1dv6d6zdvpjazamqszl-aos-eval-and-system-structure-checks-0`.

This closes the controller-side whole-catalog projection and scheduling gap in
`SBX-CTRL-03` without claiming that production brokers can yet populate it.
Storage still needs an authoritative workspace producer backed by verified ZFS
postconditions and root pins; Network still needs its kernel effect, protected
lifecycle index, and authoritative namespace producer. Cleanup-authorized
identity reclamation, source-handle materialization, native attachment replay,
lease-expiry scheduling, internal-reboot anchor handoff, and live namespace VM
qualification also remain open.

### Recoverable Storage result identity

Storage transaction results now retain the exact ZFS object GUID required by
their typed postcondition and the opaque resource identities needed by every
subsequent operation. Create and clone results mint a workspace handle with a
broker-secret HMAC over the exact operation, request, observed GUID, result
catalog, and handle kind. Snapshot results retain the source workspace handle
and mint a separately domain-separated immutable-version handle. Hold, release,
quota, and exact destroy results reproduce only the already-catalogued handles
they addressed. Missing or zero capture GUIDs, a changed GUID for an existing
object, and a GUID reported for an absence postcondition all fail before the
result can become durable.

The authenticated `AOSSTX01` record is version three and commits the optional
workspace handle, version handle, and observed GUID in a closed fixed-width
result extension. Version-two records remain readable without fabricating
identities that they never stored. The same operation replay returns the exact
minted values after restart, while malformed presence bits, zero sentinels, or
a version handle without its workspace are rejected.

Resolved Storage catalog bytes are now independently recoverable as typed
plans. Format version two adds the owning dataset GUID omitted by snapshot-
based operations and the exact project-ancestor handle omitted by the former
format. A strict bounded decoder reconstructs all eight operation variants
only through their checked constructors and then requires byte-for-byte
canonical re-encoding, including the redundant postcondition. The transaction
store accepts a recovery entry only while every operation, phase, mutation,
assignment, request, and catalog binding still names the exact current record.
Format-one bytes remain distinguishable and digest-checkable as history, but
fail typed recovery instead of inventing missing inputs.

Focused validation covers all eight catalog-operation round trips, legacy and
trailing bytes, redundant-field corruption, capture/existing/absence GUID
shape, keyed workspace and version handles, exact replay, and version-two
journal recovery. All 33 Storage library tests pass. Strict all-target,
all-feature crate-local Clippy without dependency linting, warnings-as-errors
rustdoc, Rust formatting, and diff checks pass. Full hermetic evaluation also
passes at
`/nix/store/kqqx0awkw17vzdivd1pd82bq0clcd4iz-aos-eval-and-system-structure-checks-0`.

This advances `SBX-STOR-01` and `SBX-LIFE-06` without claiming runnable ZFS
effects or authoritative workspace publication. Storage Apply remains
unadvertised: the fixed process backend, protected resource catalog and root
pin lifecycle, inventory response producer, service packaging, and controller
Apply orchestration are still required.

### Protected Storage workspace catalog and authoritative inventory

Storage now owns a protected, append-only workspace catalog that can populate
the registered 1.2 authoritative inventory contract. A generation-one head
fixes the trusted subordinate-identity pool. Every later publication advances
the head atomically with one canonical workspace row that retains the opaque
workspace handle, nonzero ZFS dataset GUID, creation correlation, exact
assignment, portable root-image descriptor, boot-scoped root-pin identity,
nonoverlapping subordinate-identity range, and domain-separated resource
digest. First-fit
allocation considers every retained row, including retired tombstones, so a
range is never silently recycled.

Publication capabilities can be constructed only from an exact committed
create or clone result recovered from the authenticated transaction store.
Storage now seals a second copy of the admitted assignment fence for the exact
operation-keyed journal location, atomically with the current fence, effect
intent, and mutation intent. Recovery authenticates this operation-scoped
fence rather than consulting a newer sandbox fence, then requires the canonical
assignment manifest and decoded sandbox specification to reproduce its
assignment digest, node, spec descriptor, environment, root view, and private
user-namespace range. This prevents an old result from being rebound after the
sandbox's current assignment advances.

The catalog opens only a root-owned, non-writable real pin root and resolves
the fixed lowercase-hex handle component through descriptor-relative,
no-follow directory opens. Publication records the observed device/inode;
same-boot replacement fails closed. After a reboot, stale active rows remain
reserved but disappear from inventory until the exact original publication
refreshes them with a new verified pin, preserving their GUID, assignment, and
identity range. Retirement accepts only an authenticated committed exact
dataset destruction at or after the workspace's creation result and requires
the fixed pin to be absent before converting the row to a permanent tombstone.

Each inventory call revalidates every current-boot pin, emits rows in strict
handle order with the protected journal boundary and broker-process identity,
and decodes its own bounded protobuf through the public Storage 1.2 validator
before returning bytes. Focused validation covers operation-fence relocation,
manifest/spec substitution, initialization and restart, replay, allocation and
exhaustion, assignment rebinding, retirement continuity, permanent range
retention, cross-boot omission and refresh, pin replacement and unsafe modes,
pool changes, and corrupt catalog heads. All 41 Storage tests and all 19 shared
broker tests pass, together with strict crate-local Clippy, warnings-as-errors
rustdoc, Rust formatting, and diff checks. The first full hermetic gate ran all
4,758 workspace tests but encountered the unrelated transient
`aos-hub::oci_distribution::manifest_admission_stages_before_validation_and_claims_each_digest_once`
503; the unchanged isolated test then passed. A clean final
`nix-build -A checks.eval --cores 8 --no-out-link` rerun passes the complete
workspace test phase, configuration evaluation, and system-structure checks at
`/nix/store/4jz5dy102dkh8nv6hn72dnpgnkidphzw-aos-eval-and-system-structure-checks-0`.

This advances `SBX-STOR-01` and `SBX-LIFE-06` through authoritative workspace
production without claiming runnable Storage effects. Storage Apply remains
unadvertised until the fixed ZFS process backend, privileged postcondition and
pin materializer, long-running service packaging, and controller Apply
orchestration are complete. Network still needs its protected lifecycle and
kernel namespace producer before whole-catalog launch can become operational.

### Protected Network preparation-policy catalog

Network now owns the protected pre-effect catalog required to turn one exact
portable assignment into a node-local preparation resolution. Trusted node
configuration supplies a nonempty, generation-fenced policy catalog whose
head and digest bind the owning node together with every portable profile,
required feature, logical endpoint, local policy-program digest, and endpoint-
policy binding. The catalog matches the assignment manifest to that node, its
canonical sandbox specification, environment, root view, and Network profile
before reserving anything; Host networking is excluded because it creates no
private namespace, while an isolated profile correctly admits an empty
endpoint set.

Each reservation is append-only for a sandbox incarnation and retains the
canonical manifest and specification, exact assignment, selected policy
generation and objects, resolution binding, and a domain-separated record
digest. The opaque future namespace handle is derived under the Network
authority key from the complete reservation preimage. Exact retry and restart
return that handle, while assignment advancement, incarnation rebinding,
handle collision, and catalog exhaustion fail closed. Admission tokens now MAC
the assignment together with the resolution, so a valid token cannot be moved
to a different request or sandbox generation.

Recovery validates canonical bounded JSON rows and all cross-record identities
against the durable policy head before it may initialize or roll that head
forward. Policy rollback, equal-generation forks, missing heads, duplicate
assignment incarnations, malformed rows, and a reservation claiming a future
policy generation are rejected. The future-generation test also proves that a
failed attempt to open under a newer trusted policy cannot conceal the row or
advance the old head.

Focused validation covers isolated and endpoint-bearing profiles, policy-
digest inputs, exact replay and restart, assignment and token relocation,
policy advancement and rollback, cross-node catalog and assignment relocation,
corrupt future-generation rows, profile and portable-input mismatch, and
protected-directory enforcement. All 26 Network
tests and doctests pass, together with strict all-target/all-feature crate-local
Clippy, warnings-as-errors rustdoc, Rust formatting, and diff checks. The final
`nix-build -A checks.eval --cores 8 --no-out-link` gate passes the complete
workspace test phase, configuration evaluation, and system-structure checks.

This advances `SBX-NET-01` through protected policy resolution and durable
handle reservation without claiming a kernel resource. Network Apply and
Inventory remain unadvertised until the fixed namespace/veth and policy
helper, verified effect postconditions, protected lifecycle index, current-
namespace observer, long-running service packaging, and controller Apply
orchestration are complete.

### Crash-recoverable Network preparation effects

Network preparation now has an authenticated three-phase transaction instead
of a Prepared-only intent. Admission derives a domain-separated effect identity
from the exact request bytes and complete protected preparation resolution,
then atomically retains Prepared with the current assignment fence, pending
effect intent, and a second assignment fence sealed for that request's durable
location. A helper must synchronously publish Ambiguous before it may attempt a
namespace, veth, or policy effect; recovery never converts that phase back into
permission to reissue the effect.

Only an Ambiguous transaction can commit a typed observation. The result binds
the request, transport, effect, preparation catalog, reserved opaque handle,
current Linux boot, nonzero `nsfs` device and inode, and the helper's complete
observation digest. Another request cannot commit the same physical namespace
identity in that boot. Exact retry returns either the unfinished phase and
effect digest for observation-only recovery or the prior committed result; it
cannot flatten both cases into an instruction to prepare again.

The request-scoped fence keeps committed authority independently recoverable
after the sandbox's current assignment fence advances. Recovery rejects
missing, moved, tampered, orphaned, or inconsistent current fences, operation
fences, effects, and operation records, as well as duplicate reserved handles
or committed physical namespaces. Version-one Prepared records remain readable
under their original current fence but cannot cross the effect boundary without
an explicit migration that supplies the operation-scoped authority they never
stored.

Focused validation covers exact transition order, premature completion,
effect-identity mismatch, Ambiguous restart, exact committed replay and typed
catalog recovery, result substitution, physical namespace collision, legacy
record recovery, assignment-fence advancement, authority-link corruption, and
bounded operation recovery. All 32 Network tests and doctests pass, together
with strict all-target/all-feature crate-local Clippy, Rust formatting, and diff
checks. The full `nix-build -A checks.eval --cores 8 --no-out-link` gate passes
the complete workspace test phase, configuration evaluation, and system-
structure checks at
`/nix/store/9sbww0cxlb0a1j6sgilk11av0yynqvv4-aos-eval-and-system-structure-checks-0`.

This advances `SBX-NET-01` and `SBX-LIFE-06` through durable one-shot effect
identity and recoverable physical result identity without claiming that a
kernel object was actually produced. Network Apply and Inventory remain
unadvertised: the fixed privileged namespace/veth and policy helper, complete
typed kernel postcondition verifier, protected current-resource lifecycle
catalog, inventory producer, service packaging, and controller orchestration
are still required.

### Authoritative Network namespace inventory

Network now has a protected current-resource catalog that can turn an exact
committed preparation result into an authoritative default-drop namespace row.
The admission coordinator first proves that the result is the current committed
operation record and recovers its exact protected resolution. The separate
preparation catalog must then reproduce that resolution and its retained
portable assignment; a caller-supplied manifest, substituted resolution, or
unretained handle cannot manufacture publication authority.

Publication reopens the fixed handle-derived pin beneath
`/run/aos/sandbox-pins/netns` through the descriptor-safe Linux boundary and
requires a kernel-verified Network `nsfs` descriptor. The current boot and
device/inode identity must exactly match the committed result before a
canonical versioned row and generation head are atomically journaled. Request
IDs, handles, sandbox incarnations, and physical namespaces cannot be rebound.
Exact same-boot retry is idempotent. Rows from earlier boots remain durable
collision evidence but are omitted from current inventory and cannot be
silently refreshed from an old committed observation.

Each inventory call validates the complete retained set, reopens every
current-boot typed pin, emits rows in strict handle order with the protected
journal boundary and broker-process identity, and decodes its own bounded
protobuf through the public Network 1.2 validator. The resource digest commits
the source preparation/result correlation, assignment, physical namespace,
default-drop lifecycle, and empty lease state.

Focused validation covers exact publication and replay, canonical restart,
fixed pin derivation, stale-boot omission, result substitution, assignment and
physical-identity rebinding, pin replacement, committed-identity mismatch,
unsafe roots, impossible catalog heads, exact preparation lookup, and
production rejection of ordinary non-`nsfs` files. All 38 Network tests and
doctests pass, together with strict all-target/all-feature crate-local Clippy,
warnings-as-errors rustdoc, Rust formatting, and diff checks. The full
`nix-build -A checks.eval --cores 8 --no-out-link` gate passes the complete
workspace test phase, configuration evaluation, and system-structure checks at
`/nix/store/m8sv964rm7zfj2hrk8lwfh12yvlb4a9h-aos-eval-and-system-structure-checks-0`.

This advances `SBX-NET-01` and `SBX-LIFE-06` through authoritative namespace
inventory production without claiming executable Network effects or a complete
service. Apply and Inventory remain unadvertised until the fixed privileged
namespace/veth and policy helper, complete postcondition observation, remaining
lease/fence/destroy lifecycle transitions, session dispatch, service packaging,
and controller Apply orchestration are ready.

### Authenticated Network inventory service

The authoritative Network catalog is now reachable by the node controller
through an independently packaged, systemd-activated `aos-netd` service. The
Network 1.2 handshake advertises only the resource-inventory method. The server
accepts exactly one authorization-free, descriptor-free inventory request per
connection, returns the complete physically revalidated catalog, and maps
private catalog failures to a bounded integrity error without exposing journal
or pin details. Apply remains absent from negotiation.

Authentication is bound to every record rather than only connection setup.
Both the hello and request must carry kernel-generated credentials and a pidfd
for the configured controller UID, GID, exact retained
`aos-control.slice/aos-sandboxd.service` cgroup, and same live process. The
service rechecks that execution before observing the protected catalog and
again before replying. A fixed `CLOCK_BOOTTIME` exchange deadline bounds idle
children, while rejected peers and malformed requests cannot terminate the
listener.

The deployment gives the controller-owned `0600` Unix sequenced-packet socket
both identity-reporting options before it becomes reachable. Its explicit send
buffer accommodates the complete bounded namespace catalog. The root-only
inventory process receives no network-administration capabilities, has a
private Network namespace, and exposes only `AF_UNIX`; protected state and the
fixed namespace-pin root remain its only resource authority. Startup fails
closed unless systemd supplies the exact single descriptor-3 activation
contract and the configured controller cgroup and protected catalog are live.

Qualification covers the pure module/socket hardening contract, hermetic
package construction, and a real-cgroup kernel exchange through the production
controller client. The end-to-end test records the authenticated response as a
durable protected controller snapshot rather than stopping at raw protocol
bytes. All 40 Network tests and doctests, strict all-target/all-feature
crate-local Clippy, warnings-as-errors rustdoc, Rust formatting, package build,
the shared sandbox-local-identity VM test, and full hermetic evaluation pass.
The final evaluation result is
`/nix/store/zxs86igd4sm2vsqw175im9dwwcxpvdcy-aos-eval-and-system-structure-checks-0`.

This advances `SBX-NET-01` and `SBX-LIFE-06` through a deployable read-only
inventory boundary. It does not complete `SBX-NET-01`: the privileged
namespace/veth and policy helper, verified Apply dispatch, lease/fence/destroy
lifecycle, and controller Apply orchestration remain unimplemented.

### Durable Network namespace lifecycle

Network namespace inventory can now represent the complete closed lifecycle
instead of only initial default-drop publication. A helper-verified transition
compare-and-swaps the exact prior resource digest, opaque handle, Linux boot,
namespace device/inode, and complete postcondition observation before the
protected catalog advances. The observation carries a closed helper-reported
state: Arm and renew require Armed with the exact requested lease tuple;
guardian fencing requires Fenced with the exact retained active tuple; disarm
requires DefaultDrop; and destroy requires Absent. Both this typed state and
the opaque complete-observation digest enter the transition commitment. Arm
installs only a strictly newer ownership-lease generation; renew requires an
already armed row and advances the same high-water fence. Guardian fencing
retains the last active lease tuple as containment evidence, while disarm
returns Armed or Fenced state to default-drop without erasing the generation
fence.

Destroy is irreversible and requires the fixed handle-derived pin to be
absent. On the current boot, only DefaultDrop or Fenced state can retire, so a
missing pin cannot turn an Armed namespace into cleanup authority. After a
reboot, verified absence may retire any stale non-retired row because its
boot-scoped namespace and deadline cannot remain live. Retired rows remain in
the protected catalog as collision evidence, never re-enter inventory, and
make startup and every inventory call fail if their fixed pin reappears.

Canonical resource-record format two commits creation correlation, the current
observation, closed lifecycle, active lease tuple, lease-generation/digest
high-water mark, and most recent transition identity. Existing canonical
format-one default-drop rows remain readable under their original resource
digest and upgrade only when a transition commits. Exact immediate retry
replays without another generation, while changed prior state, physical
identity, transition semantics, request binding, pin identity, or lifecycle
order fails closed.

Focused validation covers arm, monotonic renewal, guardian fence, disarm,
stale-generation rejection, same-boot Armed retirement rejection, cross-boot
retirement, permanent tombstones, exact replay and restart, typed-pin loss,
request reuse, stale compare-and-swap evidence, corrupt lease high-water state,
action/postcondition substitution, exact observed lease-tuple matching, and
byte-exact format-one recovery and upgrade. All 46 locally runnable Network
library tests and its doctests pass; the all-feature root qualification test is
unchanged and requires a writable root filesystem unavailable in the managed
worktree. Strict all-target/all-feature crate-local Clippy,
warnings-as-errors rustdoc, Rust formatting, and diff checks pass. The full
`nix-build -A checks.eval --cores 8 --no-out-link` gate passes the complete
workspace test phase, configuration evaluation, and system-structure checks at
`/nix/store/4bvc4ywxlnqh2pw1kmg2wgwwk8az5hi6-aos-eval-and-system-structure-checks-0`.

This advances `SBX-NET-01` and `SBX-LIFE-06` through durable namespace state
transitions without claiming kernel effects. Network Apply remains
unadvertised: the privileged namespace/veth, policy, lease-gate, and
postcondition helper; authenticated mutation dispatch; guardian scheduling;
and controller Apply orchestration remain unimplemented.

### Typed node-local Network packet policy

Network preparation policy now retains the bounded typed packet program that
its previously opaque profile and endpoint digests represented. A program
selects one portable Network kind, the fixed reviewed enforcement artifact,
the fixed tc-BPF lease-gate artifact where a veth is required, and an exact
canonical logical-endpoint set. Each endpoint contains a nonempty canonical
set of typed ingress or egress TCP, UDP, ICMPv4, or ICMPv6 flows with canonical
remote prefixes and destination-port ranges. Host bits, invalid prefix lengths,
port zero, reversed ranges, protocol/address-family disagreement, duplicates,
sentinel identities, excess collections, Host networking, and incompatible
profile shapes fail closed. Isolated policy permits no endpoint or lease gate;
Outbound admits only egress flows, and Published admits only ingress flows.

Domain-separated endpoint and program commitments cover the exact typed flows,
portable kind, and enforcement artifacts. Root policy construction derives the
profile and endpoint digests from those objects instead of accepting unrelated
caller assertions. A retained preparation can recover the current trusted
program only when the durable reservation, portable specification, handle,
profile digest, and every endpoint digest reproduce one exact association.
Substitution during policy roll-forward is rejected.

Focused validation covers canonical IPv4 and IPv6 prefixes including `/32`
and `/128`, protocol and port shapes, strict public typed ordering, duplicate
flows, kind/gate/direction constraints, artifact and flow commitment changes,
portable endpoint mismatch, exact retained-program recovery, and roll-forward
substitution. All 50 locally runnable Network library tests and doctests pass,
together with strict all-target/all-feature crate-local Clippy,
warnings-as-errors rustdoc, Rust formatting, and diff checks. The full
`nix-build -A checks.eval --cores 8 --no-out-link` gate passes the complete
workspace test phase, configuration evaluation, and system-structure checks at
`/nix/store/cbcbv9dczar4c7nkq9xnvdffdfkbrxf6-aos-eval-and-system-structure-checks-0`.

This advances `SBX-NET-01`, `SBX-POL-01`, and `SBX-NET-02` through exact packet
policy resolution without claiming those tasks complete. It does not allocate
addresses or routes, derive link/MAC/ifindex identity, execute or observe
netlink, nftables, or BPF state, implement service discovery or quota, advertise
Apply, schedule the guardian, prove the `CLOCK_BOOTTIME` gate required by
`SBX-P0-06`, or orchestrate the controller lifecycle.

### Durable Network namespace allocation plans

Network preparation now resolves each isolated or veth-backed policy profile
to a complete durable pre-effect namespace plan. Root configuration supplies a
bounded MTU, locally administered unicast MAC prefix, at most one canonical
IPv4 and IPv6 pair-allocation pool, and canonical route destinations. The
append-only preparation catalog assigns one global lifetime allocation
generation and deterministically derives fixed 15-byte creation labels,
distinct host and sandbox MACs, `/31` IPv4 or `/127` IPv6 point-to-point pairs,
and each route's matching host-peer gateway. Isolated profiles retain an exact
loopback-only plan. Overlapping nonidentical pools across profiles are rejected,
and recovered generations, labels, MACs, and IP addresses must remain unique.

The profile commitment now binds both the complete typed packet program and
the allocation policy. A reservation and its allocation record commit
atomically in the protected journal; the allocation row retains the exact
policy inputs and program artifacts needed to reconstruct and authenticate the
plan after restart. Recovery rederives the packet-program digest from the
retained Network kind, enforcement and lease-gate artifacts, and ordered
endpoint commitments, verifies the plan kind against the retained portable
specification, and rejects allocation-policy, program-artifact, plan-digest,
identity, or route substitution.

A separate allocation head commits the operator-selected legacy handle set and
thereafter distinguishes those rows from a current journal whose plan was
removed. Ordinary startup never invents a plan for an old reservation. The
explicit one-time operator migration accepts structurally valid retained
reservations only when they reproduce the program-only profile commitment and
the journal has no allocation rows or allocation head. This validates the
migration shape, not external historical provenance. Because the allocation-
aware profile changes the trusted catalog digest, the upgrade policy generation
must advance; supplying it at the historical generation is a policy fork and
fails closed. The upgrade policy must retain every original typed packet
program and endpoint commitment until migration completes. Migrated legacy
handles retain no plan and remain ineligible for implicit execution.

Focused validation covers IPv4 and IPv6 pool capacity, direct public-enum
attempts to bypass canonical prefix construction, MTU and MAC policy, exact
generation-derived labels/MACs/addresses/routes, isolated shape, overlapping
pools, cross-reservation uniqueness, canonical record recovery, allocation and
program substitution, missing-plan tamper detection, and a fixture reproducing
the historical pre-allocation journal shape. All 58 locally runnable Network
tests and the binary target pass. The all-feature-only real-cgroup
qualification test cannot create its root-level temporary directory on this
managed read-only root filesystem. Strict all-target/all-feature crate-local
Clippy without dependency linting, warnings-as-errors rustdoc, Rust formatting,
and diff checks pass. The full hermetic evaluation gate was not rerun for this
increment.

This advances `SBX-NET-01` and `SBX-RT-03` through deterministic durable
allocation planning without claiming either task complete. No namespace,
veth, address, route, firewall, or lease-gate kernel effect is executed or
observed. Apply dispatch, kernel ifindex/peer/postcondition identity, address
reuse, service discovery, quota, anti-spoof enforcement, guardian scheduling,
controller orchestration, and the `SBX-P0-06` live lease-gate proof remain open.

### Architecture-aware fleet qualification preparation

The fleet harness can now describe x86_64 and AArch64 QEMU guests without
asking target binaries to execute on the x86_64 derivation builder. The
AArch64 profile is deliberately limited to direct-kernel, TPM-less functional
tests under `qemu-system-aarch64 -machine virt,accel=tcg -cpu cortex-a57` with
the `ttyAMA0` console. The existing x86_64 profile remains q35/KVM/host CPU
with `ttyS0`.

Manifest loading normalizes missing platform fields from the selected profile,
so an architecture-only AArch64 manifest constructs an AArch64 machine rather
than silently falling back to x86 values. Both manifest validation and direct
`QemuMachine` construction reject incoherent executable, machine, accelerator,
CPU, or console combinations. Legacy manifests without an architecture retain
the established x86_64 defaults.

The harness uses `pkgs.buildPackages` for the test derivation, QEMU, Python,
test driver, metadata/image preparation tools, and generated manifest inputs.
Guest kernels, initrds, disks, services, and runtime closures still come from
the target package set. KVM is required only by the x86 profile; the AArch64
TCG profile publishes no KVM system-feature requirement. Interactive launchers
remain x86-only and fail clearly if requested from the AArch64 harness.

Two cross-evaluation defects uncovered by this work were corrected without
changing target content:

- Hub image UKI/raw/image artifacts are target data referenced directly by
  their phase scripts, not executable `buildDeps`. Their path interpolation
  preserves the derivation inputs and closure.
- Crucible resolves Rust, pkg-config, and protobuf build tools from
  `buildPackages` for every cross build. Target OpenSSL/runtime inputs and all
  Crucible license scopes, protocol boundaries, source inputs, and execution
  gates are unchanged.

Focused verification passed the following checks:

- `nix-build -A checks.integration.aos-test-driver-unit --no-out-link`
  passed 10 profile/compatibility tests, including direct construction
  rejection before launch side effects, at
  `/nix/store/kydmgw40cnrkn91sdnijj59n6x3snymg-aos-test-driver-unit-0`.
- `nix-build -A checks.integration.aos-test-driver-pyrefly --no-out-link`
  passed with zero errors at
  `/nix/store/rkhdk3cm5acn5527079ssv9qm1r3kvrx-aos-test-driver-pyrefly-0`.
- `nix-instantiate -A checks.fleet.sandbox-nspawn-platform-proof` preserved
  normal x86 fleet evaluation at
  `/nix/store/c5almkwwi49a884w3sq3jxfp0xydhklj-aos-fleet-test-sandbox-nspawn-platform-proof-0.drv`.
- `nix-instantiate -A checks.build.linux-cross-smoke` passed the focused
  target-data and Crucible build-tool evaluation assertions at
  `/nix/store/5zjdgc8gibmsaix8ij7qcfn1kifyycpk-linux-cross-smoke-aarch64-0.drv`.
- Alejandra checks and `git diff --check` passed for the scoped changes.

An AArch64 fleet VM has not been built or booted, so the nspawn platform proof
is not qualified on AArch64 yet. Full derivation evaluation now reaches the
repository-wide frozen package inventory and stops because Darling correctly
supports only x86_64 Linux while the current inventory/base-library path still
tries to evaluate it for AArch64:

```text
darling-0-unstable-2026-08-19 is not supported on aarch64-linux
```

The dedicated AArch64 fleet check was therefore not published in this
increment. The next audit must reconcile Linux architecture classifications
with the frozen base-library package set before measuring the build plan or
running the TCG guest proof. No production service or base-library behavior was
stubbed to bypass this boundary. `SBX-P0-04` and `SBX-P0-05` remain open.

### Architecture-aware inventory and target-data qualification

The frozen base-library inventory now applies the authoritative architecture
policy to registered package names before it evaluates package derivations.
This keeps architecture-incompatible thunks out of the target inventory while
preserving compatible packages, derivation aliases, metadata, and the legacy
behavior of callers without an architecture policy. Linux target selection now
honors the same architecture list already enforced for Darwin, including
Darling's explicit x86_64-only classification.

Two target-data paths no longer try to execute AArch64 programs on the x86_64
builder. `glibc-locales` runs build-side `localedef` against the matching target
glibc locale sources, and cross glibc retains those sources in its `bin` output
just like native glibc. `passt` takes its compile-time page size from the AOS
target-platform contract instead of running target `getconf`, and its install
phase executes the produced binary only for native builds. The Linux platform
contract records the 4 KiB page size used by every supported AOS kernel,
including `ARM64_4K_PAGES` on AArch64.

Focused verification passed the following checks:

- The systemd inventory and package-platform regression checks passed at
  `/nix/store/lk9jjq9vj34p0j2hc3r5iqkzmf0di0m7-systemd-lib-check-0` and
  `/nix/store/xm6yfq3j5f15jz2lpa7fy2x8i992ylv7-package-platform-support-check-0`.
- The direct AArch64 `glibc-locales` build passed at
  `/nix/store/j30ivhbvzl3slf6jwanbvnghrvxdvhnp-glibc-locales-2.39.0`.
  The cross smoke check also verified the target locale sources, build-side
  tool dependency, target platform, scheduler, and 4 KiB page-size contract at
  `/nix/store/zpacnaqvd7llqdnr7didx6vxarb40n00-linux-cross-smoke-aarch64-0`.
- Native and AArch64 `passt` builds passed at
  `/nix/store/0n9k6scaap5v07nhsv06s40w9kiy0ilm-passt-2026_07_28.f8df3f1`
  and
  `/nix/store/dbyfssshnx5id0p3lxrrxz00r7vd8saw-passt-2026_07_28.f8df3f1`.
  The target binary is a little-endian AArch64 ELF, and the build used
  `PAGE_SIZE=4096` with AArch64 seccomp syscall definitions.
- The native `sandbox-nspawn-platform-proof` booted the full guest and checked
  the guest-reported page size plus both `passt` and `pasta` versions. All tests
  passed at
  `/nix/store/2zr7k5s5s920jzkllkp0rfzrm5jqiymm-aos-fleet-test-sandbox-nspawn-platform-proof-0`.
- Alejandra checks passed for the ten scoped Nix files, and `git diff --check`
  passed for the integration worktree.

The AArch64 fleet expression now advances beyond Darling, locale generation,
and `passt`, but it still cannot instantiate the complete guest. PostgreSQL
currently treats target `clang` as a build executable and fails the derivation
contract because it cannot execute on the x86_64 builder. PostgreSQL's broader
host-tool/target-library split, cross configure tuple, language configuration,
JIT inputs, and installed PGXS metadata need a feature-preserving audit before
the AArch64 VM can run. No PostgreSQL feature was disabled or bypassed here.
The AArch64 guest proof remains unqualified, so `SBX-P0-04` and `SBX-P0-05`
remain open.

### AArch64 libcap-ng kernel and artifact qualification

The AArch64 `libcap-ng` package now takes Linux syscall headers from the target
package set and checks at configure time that `__NR_gettid` is the AArch64
value 178. Native Python drives generation, while native Bash executes the
target `python3-config` script to report target ABI metadata. The installed
extension and runtime dependency remain AArch64. The package phases do not run
target tests on the build kernel or perform a native install-time import; the
dependent guest executes the target tests instead.

A private payload builds every configured upstream C test and the Python
binding test without executing them, then a source-built AArch64 Linux 6.18.33
guest runs those exact artifacts under the source-built QEMU 10.0.0 system
emulator with TCG. The guest performs raw and libc `capget`, bounding and
ambient `prctl`, `/proc` capability, and `libcap-ng` process probes before the
test suite. It runs all nine configured C test programs in the applicable root
and unprivileged matrix, plus Python import and binding tests. The public
package depends on that result and rebuilds independently.

The payload and public package both restore GNU deterministic headers on the
two static archives after the generic strip phase. The public build then
removes only the payload's private test tree from a comparison copy, normalizes
the equal-length self store prefix in regular-file contents and symlink
targets, and recursively compares it with the public install. This comparison
establishes regular-file contents, directory entries, file types, and symlink
targets; `diff -r` does not independently establish inode metadata or mode
equality.

The current candidate's qualified payload is
`/nix/store/91yaxlypnan5zm8yalcdcy26yljcfl8j-libcap-ng-0.9.5`. Its guest result
is
`/nix/store/kvv46d2xgplvdajxiy27il6mdwkp5asx-libcap-ng-aarch64-guest-qualification-0.9.5`,
which emitted exactly one `LIBCAP_GUEST_RESULT:PASS`. The independently built
public package completed its recursive comparison at
`/nix/store/clqvz2j7isz0rxgdwjg7zffaf7a2qzha-libcap-ng-0.9.5`. Both archive
sets report UID and GID zero with epoch timestamps, all three installed Python
bytecode files use hash-based invalidation, and the target library contains
three `gettid` syscall arguments with value 178 and none with the x86_64 value
186.

This qualifies the AArch64 capability-library boundary used by the fleet
closure. In an earlier candidate, PostgreSQL built for AArch64 and passed
target-runner lifecycle, language-extension, and LLVM JIT checks at
`/nix/store/wa20y37xrjv4adg2hr3jkw3lw99z3wn9-postgresql-18.4`. The aggregate
Linux cross smoke gate has since passed from the current candidate at
`/nix/store/j0px4qp5f55x13mw1dwl7hq25xgqr028-linux-cross-smoke-aarch64-0`,
from derivation
`/nix/store/khgpg1smg87bl9zzjkvb9fjxrj0a5zm4-linux-cross-smoke-aarch64-0.drv`.
The earlier PostgreSQL result remains evidence for its package corrections,
but is not claimed as an exact-current-source realization after the later
cross-stdenv changes.

A prior AArch64 LLVM qualification snapshot installed its triple-specific Clang
configuration at `/nix/store/nk6dg20ixrybji174awr6nq1hb1vl1zq-llvm-22.1.0`.
Plain `clang` and `clang++` invocations load that configuration without an
explicit `--config`, select the target headers, startup objects, dynamic
loader, GCC runtimes, and installed target `ld.lld`, and produce runnable
AArch64 C and C++ programs. The C++ dependency closure resolves
`libstdc++`, `libm`, `libgcc_s`, `libc`, and the loader entirely to AArch64
objects.

Subsequent dependency qualification corrected two build-machine/target splits
uncovered while assembling the complete fleet closure. Cross `libgpg-error`
preserves its package-local flexible-array hardening exception when compiling
the native `yat2m` documentation generator; the installed library, utilities,
and metadata remain target artifacts. The focused AArch64 package build passed
at `/nix/store/i4jf7wn5qj673l4kgzf4a5wq9m9ana66-libgpg-error-1.61`, including
nonempty generated manual output.

Cross `libgcrypt` now executes the target `gpgrt-config` script through the
native configure shell while resolving the target package metadata. Its own
native `yat2m` generator preserves the same package-local flexible-array
exception on Linux cross builds. Configure accepted `libgpg-error` 1.61 and
retained the AArch64 NEON, ARMv8 crypto, SVE, and SVE2 paths. The focused build
passed at `/nix/store/al56amn4gnfa4zfhn8n65jzpria1f1rd-libgcrypt-1.12.2`;
`libgcrypt.so.20` and its dependency closure are AArch64, and the generated
`hmac256` manual is nonempty.

The current candidate's dedicated GCC runtime gate passed at
`/nix/store/6b5b39vrl6xrzplygskgcfsyg0i7awvm-linux-cross-runtime-aarch64-0`,
from derivation
`/nix/store/rv41f7maxy9fb3ca29k6w2v3a9ypwai0-linux-cross-runtime-aarch64-0.drv`.
It links static C and C++ math probes, links a dynamic C++ probe against the
packaged five-library target runtime set, and checks the exact AArch64
interpreter and dependency closure. The stronger dedicated LLVM gate also
passed at
`/nix/store/g99k5mz2vfcxl2y9ql8np2nnqvkr3zg4-linux-cross-llvm-aarch64-0`
from derivation
`/nix/store/7mfwq5km4vlhfzxr3cabqqnsp6x8sf2a-linux-cross-llvm-aarch64-0.drv`.
It checks the installed target configuration, executes C and C++ outputs,
including an `--as-needed` variant, and verifies the exact AArch64 interpreter,
runtime paths, and `NEEDED` sets through the loader. Its full-system TCG guest
emitted exactly one `LLVM_GUEST_RESULT:PASS`; the host-side result
also verifies one installed `ld.lld` invocation and one Clang `-cc1`
invocation in each compiler trace, with no QEMU user-mode emulator reference.

The current candidate's AArch64 `aos` package passed at
`/nix/store/7h2d12s3hrsaz8py3lnv7xsjwb46dh9m-aos-0.1.0`, from derivation
`/nix/store/85avnpxfy93qd2d2aasy6zfm8dxqcp86-aos-0.1.0.drv`. Its linker policy
uses target OpenSSL, SQLite, and zlib search paths and runtime paths, adding
`-rpath-link` only for Linux targets. The `aos`, `apm`, and `apr` entry points
ran through the AArch64 target runner, and their ELF interpreters, `NEEDED`
sets, runtime paths, and split output closures were checked. This is package
and command-startup evidence, not an end-to-end fleet result.

Two subsequent commits close additional cross-build tool-role gaps. Commit
`85c9a716a` pins Kbuild target tools separately from native host compilers,
linkers, pkg-config, `depmod`, and host libraries. The native and AArch64 Linux
6.18.33 builds passed at derivations
`/nix/store/cfy4d7j443k5hq341dwfkywlfm914g6j-linux-6.18.33.drv` and
`/nix/store/q838hxgc1d9dcyyynjv0hsljh5m05i6w-linux-6.18.33.drv`.
The AArch64 image, `vmlinux`, and module are target objects with BTF and module
metadata, while the installed `resolve_btfids`, `extract-cert`, `fixdep`,
`conf`, and `modpost` helpers are native objects with native-only runtime
paths.

Commit `023dcfa87` applies the same split to Git's build shell, gettext, and
optional language tools, seeds only the two target-libc configure answers
validated by an AArch64 runner probe, and preserves curl-backed HTTP and IMAP
support without executing target `curl-config`. The focused AArch64
`git-minimal` build passed at
`/nix/store/z1h6w8lbkj6xaadbi03c2fmnx4c9l3dx-git-minimal-2.48.1`.
Its target-runner report identifies AArch64, the target Bash, and libcurl
8.12.1; repository initialization, object hashing, revision parsing, and the
HTTP remote-helper capability exchange passed. Native build-time Bash and
gettext paths are absent from the output and its closure. This is focused
`git-minimal` Linux qualification, not full Git or Darwin qualification.

Commit `562f2fc942137a7357dee099a645eaf13e3369ea` closes two target-runtime
linkage gaps found while realizing the complete fleet closure. OpenSSH now
retains Linux `libxcrypt` as the provider for its direct `libcrypt.so.2`
dependency. Cross-Linux Nix uses native `patchelf` only during the build to
restore its declared target-library search roots before the standard fixup
shrinks each installed ELF's runtime path to actual providers. No OpenSSH or
Nix feature was disabled.

The exact AArch64 package outputs passed at
`/nix/store/p38iskqqjhawy2qqmy56zz442aqw843v-openssh-10.3p1`, from
derivation
`/nix/store/b8d592makjhznbgqjx8cpsqvpxy29acz-openssh-10.3p1.drv`, and
`/nix/store/hrcsiy22r1mhj5v87wvxr55as0ba7ig3-nix-2.24.12`, from derivation
`/nix/store/0cn915sdbp8nzl6g8msdqrwx930l9cy0-nix-2.24.12.drv`. A full target
ELF audit checked 14 OpenSSH objects and 56 direct dependency edges, plus eight
Nix objects and 75 edges, with no unresolved dependency, wrong-machine
provider, or SONAME mismatch. Their final runtime paths contain only target
runtime providers and Nix's own library output. No native `patchelf`,
build-machine object, or header-only output appears in those runtime paths. In
a clean environment without `LD_LIBRARY_PATH`, the AOS AArch64 user-mode
runner executed `ssh -V`, `sshd -V`, `nix --version`, and
`nix eval --expr '1 + 1'`, which returned 2. This is focused package
runtime-link and command-startup evidence, not an end-to-end fleet result.

The system-image generators now make the same build-machine/target split.
Native Python produces the composefs dump; native `mkcomposefs` and
`fsck.erofs` create and validate its EROFS metadata image; and native `sed`
generates the activation script. The Bash, coreutils, util-linux, EROFS, APM,
and systemd paths substituted into that script remain AArch64 target paths.
The target composefs library also restores the target OpenSSL runtime path
after Meson removes build paths during installation, and asserts that the
patched library directly needs `libcrypto.so.3`. No composefs feature or
system-image validation step was disabled.

The exact native and target composefs packages passed at
`/nix/store/fskm17i70p2zni1plk3snqafy7d7qppy-composefs-1.0.8` and
`/nix/store/i3wkmnrfygmjvn3mr8vl5f74ysq42pfh-composefs-1.0.8`. All four
target ELF objects are AArch64; the shared library directly needs
`libcrypto.so.3` and its runtime path contains the target OpenSSL and glibc.
In a clean environment, native `mkcomposefs` and the target binary under the
AArch64 runner produced byte-identical, `fsck.erofs`-valid images with SHA-256
`a54c35c03aa70cb08f43351c954ba176c596c761051e761329eca91bca317676` from
the same source tree.

The coherent candidate evaluates the complete fleet proof as
`/nix/store/l6rgwy2zf9whpjv7al6rsjzcha2hicr7-aos-fleet-test-sandbox-nspawn-platform-proof-0.drv`.
Its generator derivations reference the exact native Python, composefs,
EROFS, and sed outputs, whose executable objects are all x86-64, while the
five already-built substituted target tool packages are all AArch64. The first
realization stopped earlier in the candidate's AOS package when the native
Rust 1.93.1 compiler aborted with `malloc(): unaligned fastbin chunk detected`.
That was a host compiler-process failure, not a passing fleet result. An exact
same-source retry with two build cores subsequently built the AOS package and
entered the fleet VM, where the AArch64 nspawn probe failed because it had been
compiled with native x86-64 syscall numbers: `clone` 56, `unshare` 272, and
`setns` 308. Its `clone3` value 435 matched only coincidentally. The result
diagnosed a target-header dependency-role defect in the probe build, not a
seccomp-policy failure or a passing AArch64 fleet result.

Commit `0e8d089c034fb7b770272c61d65f43a846728f46` repairs the probe build
boundary so nspawn, filesystem-capability, and ZFS qualification probes take
Linux UAPI headers from the target package role. The nspawn probe also adds
compile-time ABI guards and errno-bearing diagnostics. Its native observer and
payload passed as
`/nix/store/25ljr8day8h24k01jhv5d61dlwbfydh7-aos-nspawn-host-observer-1.drv`
to `/nix/store/4p9wqk0bga3vd2g65lpz39hnxpx2c912-aos-nspawn-host-observer-1`
and
`/nix/store/viwciajb8jxzqis8nkzz9ysnibjkrr37-aos-nspawn-platform-probe-1.drv`
to `/nix/store/gidag2xf1h0ry61x35gkd3ciwzn9pzb0-aos-nspawn-platform-probe-1`.
The corresponding AArch64 builds passed as
`/nix/store/14zpl0wda73jfc6la3byvhjkrvqjwwkn-aos-nspawn-host-observer-1.drv`
to `/nix/store/j28qm7a445fza22864d6k830rzhmrf82-aos-nspawn-host-observer-1`
and
`/nix/store/ihkyfrg6amzrj5lba883lrvzc41qcmp2-aos-nspawn-platform-probe-1.drv`
to `/nix/store/fcciavyk3ka8cvcyymx47ryjywd0pkmr-aos-nspawn-platform-probe-1`.
The target executables are AArch64 ELF objects, and their derivation
environments reference only the target-role kernel headers rather than a native
header input. This is compile-only evidence. The corrected combined AArch64 VM
candidate is
`/nix/store/4r7qnik9mqknfrafzxkls0nlcq04s2yh-aos-fleet-test-sandbox-nspawn-platform-proof-0.drv`;
it has not yet produced a passing runtime result in this record.

Commit `413db34d6e0112d39530daf16dbf9a137d17b06c` selects the Discoverable
Partitions Specification root GUID from the guest architecture, fails closed
for an unclassified architecture, and checks the emitted root A/B names and
GUIDs from `sfdisk --json`. Both focused disk images were actually built. The
native derivation
`/nix/store/q9rysm0ln5jq8yzd597bp72qpr26sb16-vm-disk-aos-disk-0.drv`
produced
`/nix/store/qvk3ng1g2c0lkp3xqdc0idmnkn7l80xm-vm-disk-aos-disk-0`; its
`root-a` and `root-b` partitions each have 4,542,464 sectors and type
`4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709`. The AArch64 derivation
`/nix/store/cyn0b1rzlsca0bzl5iycfnljkhg17iza-vm-disk-aos-disk-0.drv`
produced
`/nix/store/8jb6iv8gbjh8v3sq30gax0iz856cn4k1-vm-disk-aos-disk-0`; its
`root-a` and `root-b` partitions each have 6,594,560 sectors and type
`B921B045-1DF0-41C3-AF44-4C6F280D3FAE`. The remaining partition layout was
preserved. This is focused disk-construction evidence; it does not qualify the
AArch64 nspawn runtime.

Commit `1f6ae6fee` makes bounded payload discovery tolerate only transient
`ENOENT` churn from six named descendant scan operations while the original
supervisor remains pinned and authenticated. An exact-root open or read may be
retried only after the old payload pidfd is dead, and a partial scan cannot
publish a successor. The repository regression exercises all admitted
operations plus live-old-payload, wrong-root operation, prefix-collision,
unknown-operation, non-`ENOENT`, supervisor-loss, and partial-result controls.

The focused observer derivations ran that regression with warnings denied on
both architectures. Native
`/nix/store/xf2hw0ijglypp3lh35mlpkqgrqgpb0gj-aos-nspawn-host-observer-1.drv`
passed and produced
`/nix/store/jqr1n92chha5295bb999c8wc8snx7rm5-aos-nspawn-host-observer-1`.
AArch64
`/nix/store/mn9xw865fzgkmc7avjzm02qlv5zin1lz-aos-nspawn-host-observer-1.drv`
passed under the AOS user-mode runner and produced
`/nix/store/0nirx7sz2ffarl707rsrrfxcyihymwrx-aos-nspawn-host-observer-1`.

The same reviewed observer candidate's complete AArch64 fleet derivation
`/nix/store/sk67b8dyx9p6d043z3wrk62s1253hbf5-aos-fleet-test-sandbox-nspawn-platform-proof-0.drv`
passed under TCG and produced
`/nix/store/iix8vnrkz840jin404q56nxyafkdmarz-aos-fleet-test-sandbox-nspawn-platform-proof-0`.
Its corresponding native KVM guard
`/nix/store/3c1i3nl6za01aamr0syjxasa5c6cmwwy-aos-fleet-test-sandbox-nspawn-platform-proof-0.drv`
also passed and produced
`/nix/store/ja4vmlhp9i1pwj7va4s27kqgfsqdfyg1-aos-fleet-test-sandbox-nspawn-platform-proof-0`.
Both runs booted the packaged systemd 259.8 and nspawn, kept machined masked,
authenticated three payload generations beneath one stable
supervisor/root/network boundary, proved fresh payload cgroup and mount/PID/user
namespace identities after each reboot, rejected the configured stale cgroup
state, and rechecked the syscall, user-map, hostile-settings, descriptor-pin,
unit-property, and page-size contracts.

These immutable runs qualify the checked-in nspawn platform fixture on x86_64
and AArch64 for the reviewed observer candidate: commit `b649cc079` plus exactly
the three observer files later recorded by `1f6ae6fee`. The separately qualified
runtime-link changes in `562f2fc94` were not inputs to these fleet derivations,
so an exact integrated-tree realization remains outstanding. The fixture also
remains distinct from the production detached-root transient-unit compiler,
controller cgroup-identity reconciliation, enforcing MAC, guardian, and
publisher paths. `SBX-P0-04` and `SBX-P0-05` therefore remain open.

### Production Host worker cross-architecture qualification (in progress)

The current integrated `checks.fleet.sandbox-host-worker` candidate includes
the reviewed target-aware Rust-test fixture discovery and a unit regression
which rejects nonleader process churn without weakening exact payload snapshot
equality. Its diagnostic-free immutable source is
`/nix/store/f5d57l3a2a7qs4zzpsf61l99arsb2h5p-aos-workspace-src`; the Host worker
source has SHA-256
`436c4477b2e9f0712d7de50293e8d9e6c247cc537a90cb83d84d9d6757d48a6d`.
The native derivation
`/nix/store/1794v6540fpjqf2nxw2yglbl99yn6dwi-aos-fleet-test-sandbox-host-worker-0.drv`
passed under KVM and produced
`/nix/store/csbj5xn0hy638qn3v84sw5agmx6xq3l5-aos-fleet-test-sandbox-host-worker-0`.
The exact AArch64 derivation
`/nix/store/shggg3k6dn036flsq38wa05cadwxibm2-aos-fleet-test-sandbox-host-worker-0.drv`
reached the production kernel test but failed during payload discovery with
`pidfd_open failed: No such process (os error 3)`.

A source-only diagnostic candidate added bounded error context to that existing
failure return without retrying, filtering candidates, changing snapshot
equality, or altering the success path. Its immutable source is
`/nix/store/r4n4j6j3dj1lv05pbfn3wkm42cyihd7k-aos-workspace-src`; the Host worker
source has SHA-256
`7ed1af98d5cf9d6622810d3330e03ac231cc41cc6ee0cd721021420e7cc3a9f9`.
The exact AArch64 diagnostic derivation
`/nix/store/jny16hgk6m38y0wwfidjz76z6qvc95zv-aos-fleet-test-sandbox-host-worker-0.drv`
passed all three payload generations, two internal reboots, and final stop,
producing
`/nix/store/ig4digifd0ynvqdxmr1dqrr46npycwc9-aos-fleet-test-sandbox-host-worker-0`.
Because the failure did not recur, no diagnostic record was emitted and the
identity of the disappearing snapshot candidate remains unknown. The
diagnostic was not promoted to the working-tree Host worker. The fixture's
repeated external 50-millisecond `sleep` child is a source-supported race
hypothesis, not an established cause. This evidence therefore does not qualify
the intermittent AArch64 production-worker path; the inert guardian limitation
also remains, and `SBX-P0-04` and `SBX-P0-05` stay open.

### Production Storage worker and deadline qualification (in progress)

An earlier Storage qualification increment added a fixed typed,
systemd-contained mutation worker. At that iteration, the worker ran as a
dynamic non-root identity with `CAP_SYS_ADMIN`,
compiled an independent fixed ZFS argument vector, admitted a closed environment
and descriptor set, bounded captured output, authenticated the worker exchange,
and checked the broker deadline around worker I/O. It also added exact ZFS
`list`, `get`, and `holds` observation plans, strict worker-local parsers and a
pre/post-state evaluator, typed v2 observation verbs and results, and a private
`SystemdZfsProcessBackend` adapter under the existing store-lifetime lock.

At the committed `e44660eb0` baseline, the worker and observer use poll-based
pidfd liveness so cross-UID monitoring does not depend on
`pidfd_send_signal(0)` and its `CAP_KILL` permission check. Nix-backed reruns at
that baseline pass 56 Storage library tests with one real-systemd test ignored,
and 92 Linux boundary tests with two privileged tests ignored. The scoped
formatter check, all-target no-dependency Clippy with warnings denied,
warning-denied rustdoc without dependencies, and diff whitespace check all
pass.

This evidence does not qualify the production path or worker VM. No production
coordinator or `storaged` construction path exposes the concrete process
backend, and Apply remains unadvertised. The earlier worker diagnostic predates
the liveness fix and is not qualification evidence. A fresh integrated
cross-UID VM build has emitted its top derivation but has not produced a passing
runtime result. That run must still exercise the real worker boundary and
deadline behavior. `SBX-STOR-01` remains open, and no completion is claimed for
`SBX-P0-07`.

### Authenticated Storage physical catalog transitions (in progress)

The local commit `1913849fe` adds a coordinator-owned authenticated physical
catalog provider in
[`catalog_transition.rs`](../../../crates/aos-sandbox-storage/src/catalog_transition.rs).
It bootstraps only from an explicit complete protected snapshot; it does not
infer authority from ambient ZFS discovery. Before a mutation can cross into
Ambiguous state, the provider records the worst-case transition bound and runs
an ordered, non-mutating journal-capacity preflight for the physical
transition, catalog head, and Committed records. The sole controller holds the
store-lifetime lock and must perform no unmodeled intervening commits; the
preflight does not itself reserve journal bytes. The provider then joins the
three records atomically under that lock.

Recovery validates a unique connected transition chain and independently
recomputes its resulting state. Every transition must join the authenticated
request, mutation, catalog generation, and physical object GUID; semantic
conflicts and branches fail closed even when their individual records are
authenticated. The provider and
[`state.rs`](../../../crates/aos-sandbox-storage/src/state.rs) distinguish
legacy v2/v3 operation records from the new v4 catalog-bearing form and poison
cached authority after a commit failure so a later request cannot continue
from a possibly divergent in-memory view.

The current Storage library suite passes 65 tests with one real-systemd test
ignored. Coverage includes deterministic post-durable-error and reopen cases,
capacity preflight, transition-chain reconstruction, state recomputation,
and authenticated conflict and branch rejection. Crate-local all-target Clippy
without default features or dependency linting passes with warnings denied;
warning-denied rustdoc, Rust formatting, and diff whitespace checks also pass.

This remains foundation toward `SBX-STOR-01`, not its completion. No production
coordinator or `storaged` startup path yet provisions the trusted bootstrap
publisher, journal authentication key, and protected trust anchors; constructs
this authority under the same lifetime lock; or exposes the production broker
handler. The legacy migration source, root-pin and workspace publication, and
Storage Apply advertisement also remain unimplemented. The real worker VM
handles are still pre-QEMU, so neither the production mutation boundary nor
`SBX-P0-07` has runtime qualification. Both tasks remain open.

### Protected Storage runtime construction (in progress)

The Storage runtime now reads protected broker authority and its journal key
from one retained directory descriptor and persists a non-secret binding over
the exact audience, trust policies, selected public keys, revocation scope,
node, and journal key ID. A locked runtime-specific state opener distinguishes
a physically unused journal from any retained or deleted history. First boot
atomically commits that binding with the complete protected physical genesis
only when the genesis satisfies the separate monotonic minimum; every nonempty
restart instead authenticates the current head against the minimum and checks
the immutable genesis and protected configuration. This single read does not
make replacement of the separate credential files an atomic live-rotation
protocol; provisioning must publish a complete directory before restart.

Prepared effects re-open their exact durable operation fence, effect intent,
current assignment fence, and catalog semantics after physical
pre-observation. Trusted time is checked immediately before Ambiguous and again
after its durable commit. A superseded current fence prevents dispatch while
the record remains Prepared; failure or exact expiry at the second clock sample
leaves Ambiguous and recovery performs observation only. Runtime construction
also runs observation-only startup recovery, but an empty recovery queue is
classified as integration-incomplete. Storage Apply remains unadvertised until
the root-pin materializer, workspace publication, catalog ingress, service
transport, and their startup proof are composed.

The current Storage library suite passes 74 tests with one real-systemd test
ignored. Focused coverage includes first-boot versus rollback-floor handling,
authority-only and deleted journal history, protected binding and physical
genesis substitution, an evolved current head above the static genesis,
superseded current authority after pre-observation, and both source failure and
actual deadline expiry at the second clock sample with zero mutation dispatch.
The broker configuration regression independently changes every public-binding
input. Crate-local all-target Clippy without dependency linting passes with
warnings denied; warning-denied rustdoc, Rust formatting, and diff whitespace
checks also pass. The ignored systemd test and the long-running worker builds
provide no guest qualification, so `SBX-STOR-01` and `SBX-P0-07` remain open.

### Recoverable Storage workspace publication intent (in progress)

Workspace-creating Storage admissions now atomically retain an authenticated
publication intent beside the Prepared operation. The new record binds the
exact operation and request catalog to the admitted assignment digest,
portable root-image descriptor, and a concrete subordinate-identity range.
The composed runtime, rather than the request caller, chooses that range under
the fixed transaction-then-workspace journal lock order. Allocation considers
both catalog rows and every retained transaction intent; exact replay reuses
the original range, while admitted Prepared operations that are later rejected
or interrupted keep their reservation so it cannot be silently reassigned.
The protected runtime configuration also binds the identity-pool envelope, and
overlap or out-of-pool substitutions fail before a new journal transaction is
written. This changes the persisted runtime-configuration binding: an existing
journal initialized with the earlier authority-only binding fails closed.
There is no automatic migration or blanket state-deletion procedure.

Startup derives the current workspace projection from the authenticated
physical catalog and exact committed transaction results. Bootstrap datasets
are excluded. Committed create and clone results produce active publication
actions; a later exact committed dataset destruction replaces the creation
with a retirement action. Cross-journal convergence requires one action per
retained workspace, rejects orphan or duplicate catalog rows, and is
idempotent after restart. A missing or rolled-back workspace journal can
therefore reconstruct the authenticated original range even when active and
retired actions arrive in a different order. Active reconstruction still
requires the matching fixed root pin, while retirement requires that pin to be
absent and retains a terminal row without inventing a pin identity. The
version-one physical catalog wire format is unchanged.

The current Storage library suite passes 82 tests with one real-systemd test
ignored. Coverage includes publication-intent authentication and canonical
decoding, atomic cross-link recovery, exact replay and overlap rejection,
physical create-to-retire projection, missing-journal retirement recovery,
reordered active/retired convergence, retained-range allocation, and
exhaustion. Crate-local all-target Clippy without default features or
dependency linting passes with warnings denied; warning-denied library rustdoc,
Rust formatting, and diff whitespace checks also pass.

This increment does not make Storage Apply runnable. The runtime deliberately
remains `IntegrationIncomplete`: no production component yet materializes and
removes the fixed root pin around committed create and destroy effects, and no
long-running broker service, controller Apply path, or passing integrated
worker VM qualifies the composition. Storage Apply remains unadvertised, and
`SBX-STOR-01` and `SBX-P0-07` remain open.

### Authenticated Storage root-pin attempts (in progress)

Storage now records root-pin work as a separate authenticated effect instead
of treating a committed ZFS mutation as publication authority. Each bounded
attempt binds its action, ordinal, parent operation and committed creation
result, current operation fence and assignment, retained identity range, exact
dataset name and GUID, host boot and mount-namespace identity, protected clock
provenance, and exclusive `CLOCK_BOOTTIME` deadline. A broker-local subordinate
receipt additionally binds that attempt to the exact still-pending controller
effect. Startup verifies every retained receipt before deriving authoritative
workspace projection.

An Ensure or RemoveAndDestroy attempt is durably Ambiguous before its one-shot
dispatch can be returned. Recovery never redispatches the attempt: exact
dataset and pin observations can satisfy publication or retirement, while a
missing required pin is classified as needing a separately authorized repair.
RemoveAndDestroy atomically records both the Storage operation's Ambiguous
transition and the pin attempt. Before either change, one ordered capacity
preflight covers that initial transaction, worst-case physical completion, and
the final satisfied-pin record. Exhaustion therefore leaves the destruction
Prepared with no new attempt.

Workspace projection is now proof-gated. An active creation is launchable only
when its latest attempt is a satisfied Ensure. A retirement is emitted only
after the matching RemoveAndDestroy is satisfied, and its historical creation
identity is reconstructed without misclassifying that retired workspace as an
active publication. Attempt selection uses the greatest authenticated ordinal,
not record-key order.

An independent full Storage library run on this increment executed 92 tests:
91 passed, none failed, and the real-systemd worker test remained intentionally
ignored. Coverage includes real subordinate-receipt round trip, receipt tamper
and parent relocation rejection, exact-deadline failure after the durable
Ambiguous transition, cold-Ambiguous restart without redispatch, combined
destroy-capacity failure, reversed attempt-ID ordering, and an authenticated
Ensure-to-Remove retirement lifecycle. Rust formatting and the diff whitespace
check pass for the current source.

This is durable authority and recovery foundation only. No descriptor-backed
kernel observer or privileged root-pin worker yet performs or proves the mount
effect, RemoveAndDestroy is not wired to one host-mount-namespace worker, and a
fresh repair admission is not implemented. The runtime remains
`IntegrationIncomplete`, Storage Apply remains unadvertised, and
`SBX-STOR-01` and `SBX-P0-07` remain open.

### Descriptor-backed Storage root-pin execution (in progress)

The current source composes root-pin attempts with separate systemd effect and
observation helpers. The broker retains the initial host mount namespace and
the fixed root-owned workspace-pin directory, transfers those descriptors in
fixed roles, authenticates the complete durable attempt and ZFS catalog inside
the one-shot helper, and requires the helper process to remain in its exact
reserved cgroup. Ensure uses the descriptor-first `fsopen`/`fsconfig`/`fsmount`
path. RemoveAndDestroy performs an ordinary unmount and the exact ZFS destroy
inside the same authenticated worker. A root-owned replay claim precedes the
first target mutation. Every post-request failure is ambiguous, cancels the
whole worker cgroup, and is never dispatched again.

Ambiguous recovery uses a distinct observer service. It authenticates the
historical operation fence and attempt while independently requiring current
host authority, but owns no replay ledger, protected effect clock, mount
construction, unmount, or ZFS mutation call path. Its systemd syscall profile
admits the required mount-namespace `setns` and explicitly denies mount and
chroot mutation. Exact read-only dataset and descriptor-backed mount evidence
may complete only the already-authorized publication or retirement. Startup
also cancels and proves empty every reserved root-pin, observer, and generic
ZFS worker cgroup before physical observation.

systemd 259 implements `RestrictSUIDSGID=true` by returning `ENOSYS` for every
`openat2` call because the creation mode is indirect. The three fixed workers
therefore leave that filter disabled rather than weakening mandatory
descriptor-relative `openat2` resolution. The generic worker remains inside
its systemd mount view; the pin helpers open their authority and replay roots
before entering the retained host mount namespace, and the current typed code
creates only `0700` pin slots and `0600` replay records through retained roots.
Those constraints, the narrow capability sets, `NoNewPrivileges`, and the
closed syscall and request profiles are not equivalent setid-creation
enforcement after `setns`. Production enablement still requires enforcing MAC
and actual forbidden-syscall, setid-creation, and host-write negative tests;
Storage Apply remains unadvertised until that residual exposure is closed.

A current-source Storage library run passes 114 tests with two real-systemd
tests ignored. All Storage targets, including both new helper executables, pass
`cargo check`; warning-denied rustdoc and all-target, no-dependency strict
Clippy also pass.

The current x86_64 platform gate passes at
`/nix/store/17hh1aziqcbbafm7zzj01qlmmn2yxna3-aos-fleet-test-sandbox-zfs-platform-proof-0`.
It boots Linux 6.18.33 with the matching OpenZFS 2.4.0 userland and kernel
module, and proves snapshot, hold and blocked destroy, clone identity, quota
and reservation properties, reservation accounting, enforced quota through
`EDQUOT`, send/receive snapshot identity, and an idmapped ZFS mount. The idmap
proof preserves canonical root ownership on disk while checking translated
ownership from both the host and sandbox views, including a file created
through the mapped mount.

The same gate proves descriptor-first `fsopen`/`fsconfig`/`fsmount` ZFS
construction twice, including source and filesystem-root identity without
changing the dataset GUID or its `mountpoint=none,canmount=off` properties.
libzfs directly retains the AOS `libgcc_s.so.1` unwind runtime required by
pthread cancellation, and the successful send/receive runs under a shell
boundary that is first shown to propagate a failing pipeline producer. The
test finally requires the exact healthy-pool result, unmounts both constructed
views, destroys the pool, and successfully observes its absence from the full
post-destroy pool inventory. The exact derivation is
`/nix/store/zqmhmz4gpxig7fpkivm24iz3n2ccicyx-aos-fleet-test-sandbox-zfs-platform-proof-0.drv`.

This qualifies the native x86_64 OpenZFS substrate only. The AArch64 fleet VM,
installed root-pin worker lifecycle, runtime observer syscall-denial proof,
pre-dispatch expiry with zero mount/ZFS/replay attempts, whole-cgroup
descendant termination, and crash recovery remain unqualified. `SBX-P0-07`,
`SBX-P0-08`, and `SBX-STOR-01` therefore remain open; the runtime stays
`IntegrationIncomplete` and Storage Apply remains unadvertised.

### Nested broker identity and generic Storage worker qualification (in progress)

Commit `227f64e36` corrects the fixed Host and Mount broker peer profiles to
the actual nested systemd hierarchy under `aos.slice/aos-control.slice`.
Verification still resolves one exact cgroup through retained cgroup v2
custody and matches the accepted socket peer's pidfd and PID against that
membership. Same-named flattened and alternate-slice cgroups are explicit
negative controls; they do not grant controller or RootMount authority. The
cross-UID pidfd liveness fixture also keeps its private control marker separate
from libtest's status stream without changing the production liveness check.

The exact `checks.vm.sandbox-local-identity` derivation
`/nix/store/68za5y1zbr7a236y7kc7l45c40c4kiqm-aos-vm-test-sandbox-local-identity-0.drv`
passes at
`/nix/store/c39mazsk4i2rq3x3js8qsfznm4355za3-aos-vm-test-sandbox-local-identity-0`.
It qualifies real socket activation, realm membership, the cross-UID pidfd
path, the distinct RootMount peer, and the flattened and alternate-hierarchy
decoys. This is local peer-identity evidence, not Storage Apply or end-to-end
runtime qualification.

The subsequent generic Storage worker gate
`/nix/store/irv1qrw858f0ps79s4mljz2zqbjnq52s-aos-fleet-test-sandbox-zfs-worker-0.drv`
failed after both guests booted. The real worker's mandatory `openat2` returned
`ENOSYS`: systemd 259.8 unconditionally installs the
`RestrictSUIDSGID` creation filter for `DynamicUser`, even when the unit text
sets `RestrictSUIDSGID=false`. This independently confirmed that adding
`openat2` to `SystemCallFilter` cannot repair the failure. The current pending
qualification replaces only the generic worker's dynamic identity with fixed
non-root UID/GID 992, disables core dumps before request handling, and limits
its activation socket to one simultaneous connection. All other capability,
namespace, descriptor, syscall, cgroup, peer, and fail-stop checks remain.

The pending fleet assertions require the fixed account and effective unit
properties, process ownership, one active worker and cgroup, refusal counters
for a concurrent client while that worker and a descendant remain live,
whole-cgroup drain, and a fresh successful dispatch afterward. No passing VM
result exists yet for this static-worker revision. Mandatory MAC enforcement
and negative gates for forbidden syscalls, setid creation, and host writes --
including after entering the retained host mount namespace -- remain required
production work rather than a permanent qualification exception. Storage
Apply therefore remains unadvertised, and `SBX-STOR-01`, `SBX-P0-07`, and
`SBX-P0-08` remain open.

### Signed Storage catalog preparation retention (in progress)

The local commit `1d36f09ae` advances `SBX-STOR-01` with a library coordinator
path for independently authorized `PrepareCatalog`. The coordinator decodes
the canonical protocol 1.3 request, validates its signed preparation grant,
requires exact trusted inventory and durable catalog-head bindings, invokes a
protected resolver, and seals the resulting non-authorizing receipt and
retained record. The store commits that record with its current fence, effect
intent, and operation fence in one catalog-head compare-and-swap transaction.
Preparation performs no physical ZFS effect and does not advance the catalog
head.

Exact replay authenticates the retained record and authority links at their
durable locations, then binds the request, operation, plan, lease, host boot,
and exclusive deadline. Same-operation equivocation, stale inventory or head,
tamper, and missing links fail closed. Apply now requires the exact retained
catalog and assignment, rechecks an unconsumed preparation's boot, deadline,
head, and current signed authority, independently validates the Apply grant,
and atomically records the Apply binding while beginning the existing durable
mutation transaction. Startup authenticates both unconsumed preparations and
the Apply cross-links of consumed preparations before recovery proceeds.

An exact archive of the six-file staged increment, identified by binary-diff
SHA-256
`9600b5a4abc99e067e547ea32c020963da64130d498a7dd228ef1cfe1880e59f`,
passes Rust formatting and the scoped Storage tests: 101 library tests passed,
none failed, and one real-systemd test was ignored; the worker binary and
doctest targets contained no tests. Strict all-target, no-dependency Clippy
with warnings denied is not green at the parent baseline. The exact parent
reported 24 library and 10 test-target diagnostics, while the increment reports
the same 24 library diagnostics and 9 test-target diagnostics. Normalizing
shifted line numbers leaves no increment-only diagnostic; the increment removes
one existing `clone_on_copy` test diagnostic, and the existing
`large_enum_variant` layout report remains 1720 bytes versus 696 bytes. This is
differential no-regression evidence, not a passing lint result.

This increment provides no worker-VM or end-to-end production qualification.
The ignored real-systemd test remains ignored, no passing VM result is claimed,
and the runtime still does not advertise Storage Apply. The complete production
handler, protected resolver provisioning, and integrated lifecycle remain open;
`SBX-STOR-01` is not complete.

### Exact Storage worker quiescence foundation (in progress)

The current source retains an authenticated `cgroup.events` descriptor before
dispatch and distinguishes a populated subtree, an empty active subtree, and
retirement of that exact cgroup lifetime. Only `ENODEV` from the retained
kernfs descriptor is accepted as retirement; every other read failure remains
an error. The generic ZFS and workspace-pin paths require exact worker pidfd
death plus an empty or retired subtree, cancel the complete unit through
`cgroup.kill`, and fail-stop the executor when cancellation cannot be proved.
The Network worker consumes the same typed population contract.

The exact `checks.vm.sandbox-local-identity` derivation
`/nix/store/dvq6cfmfbdby12w6vz4ag37rma5jdd9a-aos-vm-test-sandbox-local-identity-0.drv`
passes at
`/nix/store/njw7w3cgq8c6xfd8ng0izq7qf1v7b288-aos-vm-test-sandbox-local-identity-0`.
Its new kernel test proves empty and populated states through a live descendant,
the kernel's refusal to remove populated ancestry, exact pidfd death, retained
retirement after removal, same-path recreation with a different kernel ID, and
continued retirement of the old retained monitor. The remaining local-identity
guest groups also pass, including the existing cgroup membership, cross-UID
pidfd, descriptor-subject, runtime-scope, local-session, provisioning,
publisher-session, publisher-control, journal, peer, and service checks.

The retained-population foundation is committed as `48705328b0`. Its exact
isolated-candidate VM derivation
`/nix/store/cy2h106saazdm7r0cnb0h26yjrwaanqa-aos-vm-test-sandbox-local-identity-0.drv`
passes at
`/nix/store/d16sxl8jd9sm9p00bpaxgxjl7033l4k2-aos-vm-test-sandbox-local-identity-0`.
The focused kernel checks cover live-descendant population, exact pidfd death,
retained retirement, and same-path recreation; the existing exact membership
check and every selected guest group pass in the same run.

Commit `a4a5ab1501e2b4cbc055c158359fb4e072dc9fd4` separately hardens the
descriptor-subject channel foundation. Its isolated focused run passes all 14
descriptor-subject tests, including invalid-capacity inertness, the full 4096
byte bilateral transfer, idempotent close with retained peer identity and
capacity rejection, and a delegated writer whose observed subject differs from
the cached connector peer. This unit-level result does not qualify a full
Network or Storage worker path.

This is focused kernel lifecycle evidence, not a passing integrated Storage
worker result. In the exact full worker derivation
`/nix/store/p0r0fhmyz49aa7jdgmhc5x258k6pg0cx-aos-fleet-test-sandbox-zfs-worker-0.drv`
both guests booted and passed the readiness and socket-policy checks. The real
guest then passed create, snapshot, hold, clone, quota, clone destruction, hold
release, snapshot destruction, and workspace destruction through the production
generic worker. Every operation also passed the broker's exact pidfd and worker
cgroup quiescence check before the next operation began. The test then failed in
the standalone mount-namespace and Landlock boundary probe before reaching the
descriptor-backed workspace-pin flow. The diagnostic rerun
`/nix/store/s22wxscc8mdjrf692bzbbbv32ffgcyri-aos-fleet-test-sandbox-zfs-worker-0.drv`
proved that the probe failed while opening `/proc/1/ns/mnt`: Landlock's ptrace
check denies that post-restriction procfs magic-link lookup, before `setns` is
reached. A focused rerun at
`/nix/store/3q87dmv4kwsvw2cvjcr8y50aw3fyzm3m-aos-fleet-test-sandbox-storage-boundary-focused-0`
passes with systemd preopening the namespace descriptor. It authenticates the
descriptor before `setns` and retains the existing Landlock, seccomp, set-ID,
and mount denials. That run only proves aggregate fail-closed handling for the
malformed descriptor fixtures. A first build of the strengthened focused
derivation with independently valid extra, misnamed, and wrong-filesystem
fixtures did not reach the VM: its immutable top-level derivation
`/nix/store/jm0hka3mc2yl4n6xyckmczpapmi766b7-aos-fleet-test-sandbox-storage-boundary-focused-0.drv`
failed in an upstream `aos` package check after 4,795 of 4,796 tests passed. The
unrelated failing Hub test was
`manifest_admission_stages_before_validation_and_claims_each_digest_once`, where
one concurrent request returned 503 after its bounded digest-claim convergence
window while the other returned 201. The exact Hub test then passed alone, and
an unchanged retry passed all 4,796 package tests and the strengthened focused
VM at
`/nix/store/z29xpp0wwam2p34jnf56lvq3ckvflmpl-aos-fleet-test-sandbox-storage-boundary-focused-0`.
That VM proves the missing, extra, misnamed, and wrong-filesystem descriptor
contracts independently fail closed with their exact diagnostics, while the
positive systemd-preopened descriptor path still passes. The intermittent Hub
failure's specific cause remains unresolved, and the descriptor-backed
workspace-pin flow remains pending.
Storage Apply remains unadvertised, and no completion is claimed for
`SBX-STOR-01`, `SBX-P0-07`, or `SBX-P0-08`.

### Typed Storage pin proof and live workspace publication (in progress)

The workspace catalog now persists the exact satisfied Ensure proof rather than
reconstructing publication authority from mutable filesystem metadata. Catalog
format 2 binds that proof into a new resource-digest domain. Active publish,
recovery, replay, and inventory revalidate the proof's boot, host namespace,
mount point, ZFS name and GUID; the live `O_PATH` directory type, device and
inode; the distinct parent and unique mount ID; and a bounded mount-inventory
entry whose root, filesystem, source and device match. A reopened descriptor
and second inventory pass must agree before publication is accepted. Format 1
rows remain decodable only for historical retirement reconstruction and cannot
authorize a fresh active publication.

Custody checks now distinguish the protected empty mount slot from the mounted
filesystem root. The unmounted slot must remain under the exact protected
parent mount, root-owned, and not group- or other-writable. Once the independently
proved ZFS mount occupies that slot, its root owner and mode are guest data and
may change without invalidating the mount identity. Regression coverage rejects
an unmounted UID 992 or mode `0777` slot, accepts those attributes on an exact
mounted root, rejects same-device/inode substitutions with a changed mount ID,
and rejects boot, namespace, source, inode, proof, and legacy-envelope
substitutions. It preserves the existing cross-workspace device/inode alias
check. This does not authorize recursive ownership repair or add `CAP_CHOWN`.

A Nix-development-shell run of the current Storage library suite executed 135
tests: 133 passed, none failed, and two real-systemd tests were ignored. The
focused catalog suite independently passed all 12 tests. These source tests
include exact mount-proof persistence and restart validation, mutable mounted
root attributes, and the protected-state tempfile regression. They do not by
themselves qualify the installed services.

The immutable integrated attempt was
`/nix/store/cjk5b9f36y65zqwv1dnmi9z7pijxsas5-aos-fleet-test-sandbox-zfs-worker-0.drv`,
with workspace source
`/nix/store/8ar75jf7wdkgdgshgjvrixspwr863cqp-aos-workspace-src`, manifest
`/nix/store/0j8rngdx198bdz1kis9c4b4vh5hhdmkp-aos-fleet-test-sandbox-zfs-worker-manifest.json.drv`,
and generated test
`/nix/store/13y6283vqi8wqh4nlfrzh85p9qi8mnca-aos-fleet-test-sandbox-zfs-worker-test.py.drv`.
Its real guest passed the production
`broker::tests::systemd_workspace_pin_vm_client`: create and satisfied Ensure,
root-owned catalog publish with one decoded inventory entry, catalog drop and
reopen with exact replay, RemoveAndDestroy and retirement to an empty inventory,
a second drop and reopen preserving that empty inventory, and stale-fence
effect-worker rejection followed by exact read-only observer evidence yielding
`AwaitFreshRepair` without a replay claim. The filtered Rust result was one
passed, zero failed, and 134 filtered out.

The complete fleet derivation is nevertheless red. Its later fault guest proved
the fast dispatch and whole-cgroup timeout/drain cases, but the timed-out
Accept=yes worker left the client oneshot successful and inactive. PID 1 then
collected that static `aos-storaged.service`. The next named
`systemctl reset-failed` therefore failed with
`Unit aos-storaged.service not loaded` before the broker-kill, overlapping
client, and final fresh-dispatch tail. This is a fixture unit-GC/reset race, not
a failure of the earlier catalog branch.

The fixture-only correction reloads and validates the exact static unit, admits
only `inactive` or `failed`, and resets that named unit only when it is actually
failed; it does not ignore errors or reset unrelated units. Its generated
Python passed syntax compilation with the AOS-built Python 3.14.3 interpreter.
The immutable successor was
`/nix/store/l1frvml9kzz0rnzmmjqyacv2jxfdyq0j-aos-fleet-test-sandbox-zfs-worker-0.drv`,
with source
`/nix/store/8qq8ywpbs9251s92xaalcwbi8y4rw78h-aos-workspace-src`. It did not
reach either payload: the fault and real guests reached their stage-2 systems
only after roughly 90 and 103 seconds, respectively, then started
`aos-eval.service` at guest uptimes 94.647 and 107.044 seconds. The fault agent
failed to become ready before the 180-second manifest boot timeout while both
evaluations were still running. The predecessor reached the same evaluation
path near guest uptime six seconds and did not start its identical test-agent
unit until evaluation converged near guest uptime 113 seconds. The two
manifests retain the same kernel, QEMU, KVM, CPU, memory, vCPU, network, agent,
and timeout configuration; their normalized evaluation scripts are identical,
with raw differences limited to workspace-derived store paths. The delayed
pre-stage-2 boot is therefore consistent with transient host scheduling rather
than the fixture correction, but that is not established as its cause and the
red run provides no evidence for or against that correction. One unchanged
retry of the same immutable derivation,
source, manifest, and 180-second timeout brought both agents ready roughly 116
seconds after launch and passed the complete fault and real payloads. It
realized
`/nix/store/qv8ac0yfmabqkwmks9kmi85wf3l1s36g-aos-fleet-test-sandbox-zfs-worker-0`.
This qualifies the fixture correction and the integrated branches covered by
that exact fleet test while preserving the initial timeout as an unexplained
boot-timing failure.
Fresh repair admission is described in the following Storage sections.
One-time new-dataset ownership initialization remains unimplemented. Storage
Apply stays unadvertised and `SBX-STOR-01`,
`SBX-P0-07`, `SBX-P0-08`, and `SBX-P0-10` remain open.

### Storage workspace root-pin repair recovery (in progress)

Storage protocol 1.4 reserves controller method 21 for
`RepairWorkspacePin`. The method requires the standard authorization carrier,
accepts no descriptors, and carries only the request header, assignment fence,
nonzero 16-byte repair operation ID, and exact 32-byte workspace handle.
Dataset names, GUIDs, mount points, observations, and attempt ordinals remain
protected broker facts. The portable authorization registry assigns the
resource-targeted `StorageRepairWorkspacePin` verb global code 33; the
Storage-local authenticated Effect codec assigns it append-only code 9.
Peers below Storage 1.4 cannot negotiate the method or decode its canonical
semantics.

The repair compiler produces one fixed 183-byte, nine-TLV canonical semantic
record. Its domain-separated golden commitment is
`bc961c0e3b743447891a8997ee6fcd57359ef7e90722454bd9f8dacd61ddf5c2`.
Every assignment-fence field, operation ID, and workspace handle changes that
commitment; zero or wrong-width identities, unknown fields at either protobuf
level, action-field smuggling, older protocol versions, and noncanonical bytes
fail closed.

Durable repair history uses append-only journal namespace 35. Its
location-authenticated intent retains the exact original Pending Effect bytes
and digest, operation fence, repair and creation identities, committed creation
result and publication record digests, workspace handle, predecessor Ensure
attempt and phase, and the new adjacent attempt identity and ordinal. Recovery
authenticates every retained repair intent, including satisfied and retired
history, before ordinary Effect or workspace-inventory access. It requires
contiguous ordinals and exact predecessor and reverse one-to-one joins. A
superseded attempt cannot complete late, and an admitted repair is always
observation-only after restart; its historical authority is never
redispatched.

The dedicated `AOSZRPO1`/`AOSZRPR1` recovery exchange contains no effect grant.
It binds a kernel-generated challenge, independently authenticated repair,
attempt and publication records, the canonical creation catalog, the
historical attempt scope, and a freshly descriptor-derived boot and
mount-namespace scope. The fixed
single-threaded observer independently opens the authenticated records after
entering the retained namespace, performs bounded ZFS and exact mount
inventory, and returns the probe digest with typed evidence. Broker completion
rechecks the latest attempt, active workspace projection, and raw record
digests. Exact absence remains `AwaitFreshRepair` without a journal write;
same-scope exact presence may satisfy the retained attempt; cross-boot presence,
stale probes, changed history, mismatch, and copied-journal substitution fail
closed. The ordinary observer selects only the latest attempt and excludes
repair Ensure attempts, while still recovering a latest
`RemoveAndDestroy` attempt.

Commit `5c0be1b2217f37b3c49e2cc7fc7fad74b083cb46` records this protocol and
recovery slice. Its isolated 19-path candidate was based on
`c67406e76c5189987edfb4d0fea0d4960cc53281`, had binary-diff SHA-256
`2e8efe35b18f51573e6d4c2e8bc35a80d83020f17c79a853d7f628233ed063ec`
and tree `241c98d2f9a790c67d228d57c68e0268b613a0a2`, and passed 824 library
tests across `aos-sandbox`, broker, core, protocol, and Storage. No test failed;
the only two ignored tests require the installed real-systemd Storage workers.
That run includes the append-only namespace-35 journal check, fixed protocol
golden, session negotiation and carrier boundaries, authenticated repair codec
and bit-flip rejection, repair-history reopen and substitution checks, startup
authority ordering, latest-attempt selection, and same- and cross-scope
observer completion cases.

This slice does not implement fresh repair admission, the pre-admission
descriptor-backed observation contract, atomic fence/Effect/intent/attempt
commit, immediate mutating-worker dispatch, controller orchestration, or a
production RPC handler. The new method remains unadvertised, no dedicated
repair recovery VM has run, and a post-commit recovery envelope must not be
reused as pre-commit authority. Storage Apply remains unadvertised.
New-dataset ownership initialization and its separate capability decision also
remain open; no
`SBX-STOR-01`, `SBX-P0-07`, `SBX-P0-08`, or `SBX-P0-10` checkbox is closed.

### Fresh Storage workspace root-pin repair execution (in progress)

Commit `23ee70104fd313ba3497a07a263fa3d2cec2d0af` implements the
fresh admission and immediate one-shot execution path that follows the
recovery foundation above. `StorageBrokerRuntime::repair_workspace_pin` accepts
only the raw Storage 1.4 request, standard authorization artifacts, negotiated
version, peer identity and policy, and a protected-clock provider. Callers
cannot select an observation, catalog, dataset name or GUID, attempt ordinal,
host scope, or pin proof. The method resolves an exact durable replay before
probing; such a retry returns `ObservationRequired` and never reaches an
observer or mutator.

For a new operation, the broker derives the globally latest Ensure attempt and
active creation from authenticated state. Both an ordinal-one creation Ensure
and an ordinal-two-or-later repair Ensure may be predecessors, whether their
phase is Ambiguous or Satisfied. A retired creation, `RemoveAndDestroy`
predecessor, nonmatching repair chain, or exhausted four-attempt bound fails
closed. The noncommitting `AOSZRPA1`/`AOSZRPS1` exchange carries a fresh
challenge, prospective request commitments, exact current records, creation
catalog, and historical and descriptor-derived current host scopes. Its fixed
observer independently authenticates the records after entering the retained
mount namespace and must return the exact dataset with an absent pin. Only the
systemd client can wrap that result in the move-only fresh value, and only
after exact child identity, natural exit, and whole-cgroup quiescence have been
proved.

The coordinator consumes that fresh value while the sole transaction-store
lock remains held, resamples the protected clock, redecodes and reauthorizes the
raw request, rereads the latest attempt and every linked raw record, rechecks
the active creation and current fence, and performs the final before-effect
check. It then atomically commits five records: the sandbox-keyed current
fence, request-keyed Pending Effect, operation-keyed authority fence,
location-authenticated repair intent, and adjacent Ambiguous Ensure attempt.
The same preflight reserves the exact later two-record completion shape before
any of those records become durable. Exact readback and post-commit fence,
clock, receipt, catalog, publication, and repair-intent checks poison the
in-memory authority source on any uncertainty.

The distinct `AOSZRPW1` worker request encloses the existing framed pin
transport plus the repair and creation-publication records. The privileged
worker independently accepts only a move-only authenticated
ordinal-two-or-later Ensure. It authenticates the original Pending repair
Effect, equal current and operation fences, attempt receipt, repair intent,
committed creation result, publication identity range, and canonical creation
catalog, and revalidates its transferred host descriptors. It requires the
exact dataset and absent pin before its durable replay claim, checks the
protected current fence and clock on both sides of that claim, materializes the
fixed handle-derived pin, and observes the exact postcondition. Ordinary
creation semantics cannot authorize this envelope, and restart never
redispatches it.

Fresh execution and recovery completion now share a repair-specific durable
finish. One journal transaction changes the exact attempt to Satisfied with
the observed proof and the live Effect to Complete with a deterministic receipt
bound to the attempt's stable authority digest. The store reads both records
back exactly before updating its cache. Startup authentication permits only
Ambiguous/Pending or Satisfied/Complete and independently reconstructs the
completion receipt; Satisfied/Pending, Ambiguous/Complete, and an otherwise
correctly sealed Complete Effect with an arbitrary receipt fail closed. An
injected error returned after the atomic journal commit poisons the live cache,
while protected reopen recovers and authenticates both completed records.

At the isolated ten-path implementation checkpoint, the pinned realized
development shell passed all 150 then-current `aos-sandbox-storage` library
tests with no failure. Two installed-systemd tests remained ignored in that
source-level run. Coverage included the initial and repeat pre-admission shapes,
exact dataset/Absent requirement, malformed local wire records, real-HMAC
worker authentication and fence, predecessor, receipt, and publication
substitutions, asymmetric completion rejection, atomic completion after an
injected post-commit error, and completed reopen. That implementation has tree
`7fc14cbbbddb238cbaa19b74a084c924d995668e`, binary-diff SHA-256
`79c1d727318a5affe569eacad851e577df75efd428a9237933183a4860530e00`,
and adds 3,253 lines while removing 42.

Successor commit `d4effbf1b525a4c94fc2a1dfaae8eee67b420917` makes active
publication follow the globally latest workspace pin attempt while recovering
a retired creation from its latest satisfied Ensure, including an authenticated
repair effect. The pinned realized development shell then ran 153 Storage
library tests: 151 passed, none failed, and the two installed-systemd tests were
ignored. The added regressions cover foreign and pending latest attempts,
repaired active publication, repaired retirement, and authenticated reopen.

One immutable fleet attempt stopped at the non-test Storage build because
`repair_intent_record` was imported only under `cfg(test)`; commit
`6384e28d8240ee33f38ffe38e99bb30b5e81fb18` fixed that production import. The
next immutable attempt,
`/nix/store/aih2zmfgni1w27mw31xi863qjq7yrs0n-aos-fleet-test-sandbox-zfs-worker-0.drv`,
built and booted both guests and invoked the public repair path through fresh
observation, atomic admission, the repair worker, and durable completion. It
then failed the repaired catalog assertion with zero workspaces instead of one.
Its guest log also recorded post-acknowledgement observer failure when an exact
cgroup membership read was denied after mount-namespace entry. These remain
diagnostic failures rather than passing evidence.

The immutable successor
`/nix/store/xl529aw58l7287pycn62ijdy6jn4jhml-aos-fleet-test-sandbox-zfs-worker-0.drv`
captures the active-publication correction plus an explicit Landlock read rule
for the detached cgroup mount. Its boundary probe retains its own cgroup
descriptor before mount-namespace entry, then proves that `cgroup.procs`
remains readable while `cgroup.kill` remains non-writable through constrained
`openat2`. The first realization stopped before VM launch when the native
artifacts derivation aborted with `SIGABRT` and a `stack smashing detected`
report while compiling vendored `worker` 0.8.5. One bounded retry of that exact
captured derivation, without recapture or source changes, did not reproduce the
failure. The native artifacts and downstream AOS checks completed, and both
installed-systemd guests booted. The full fleet body passed repair, exact retry
without another worker activation, authenticated journal and catalog reopen,
and teardown with the repaired bind unmounted, dataset destroyed, and worker
cgroups unpopulated. The final realized output is
`/nix/store/p4pbsi6zpwmzya824s90psq6xmprawd2-aos-fleet-test-sandbox-zfs-worker-0`.

Follow-up commit `487997afc` adds a test-only failure seam at the exact repair
admission boundary. The installed test makes the one five-record admission
transaction durable, then injects the error before the coordinator updates its
materialized cache or constructs the worker dispatch. The journal snapshot
sequence advances by seven frames -- transaction begin, five semantic records,
and transaction commit -- and the runtime returns
`StorageRuntimeError::Recovery`. The fresh admission observer is activated
once, while the worker acceptance count, durable replay-claim count, and pin
remain unchanged.

A full runtime reopen from the same protected transaction and workspace-catalog
paths authenticates the ordinal-two `Ambiguous` attempt, `Pending` Effect,
repair-intent links, and equal decoded current and operation fences. Startup
activates only the repair observer, retains
`StorageRuntimeReadiness::RecoveryPending`, and converges to an empty workspace
inventory without changing the journal, worker count, or claim count. An exact
retry returns `WorkspacePinRepairExecutionOutcomeV1::ObservationRequired` with
zero observer, worker, claim, and journal deltas. A separately authorized
generation-eight repair then advances to ordinal three, activates the observer
and worker once each, creates exactly one replay claim, and reaches a
`Satisfied` attempt with a `Complete` Effect and an active catalog row. The
final authenticated journal and catalog reopen preserves both the interrupted
and successful repair histories.

The pinned development-shell library run compiled 153 Storage tests: 151
passed, none failed, and the two installed-systemd tests were ignored. The
immutable fleet derivation
`/nix/store/xd434nanxn33jppnr504ybsw9qyd37ig-aos-fleet-test-sandbox-zfs-worker-0.drv`
captured those exact sources and then ran both ignored paths against the
installed units. Both guests booted and the complete fleet body passed,
including the expected three replay claims, drained worker and observer units
and cgroups, the repaired mount check, and final unmount and dataset cleanup.
The realized output is
`/nix/store/d8916bb66gmp7gla38k4i41v43s82xcy-aos-fleet-test-sandbox-zfs-worker-0`.

This qualifies post-commit injected-failure and restart evidence, not literal
process-kill proof. Controller orchestration and the production RPC handler
also remain absent. New-dataset ownership initialization and its separate
capability decision remain open; Storage Apply stays unadvertised and no
`SBX-STOR-01`, `SBX-P0-07`, `SBX-P0-08`, or `SBX-P0-10` checkbox is closed.

### Set-ID creation guard source feasibility (design only)

A read-only source audit bounded one possible BPF-LSM SetidGuard, but does not
replace the required enforcing MAC policy in `SBX-P0-10`. The immutable Linux
6.18.33 archive is
`/nix/store/23av28lf5a6sm73qn0qvhpip0b1nfw1l-linux-6.18.33.tar.xz`, with
SHA-256
`6f16ff302599f6fe34742890322cf0775703105fbd8767449682fca6af0fb782`.
`fs/namei.c:3422-3458` strips SGID conditionally and applies the umask before
filesystem creation, but does not itself strip SUID. Named creation has the
returning `inode_create` hook; `O_TMPFILE` instead calls the filesystem's
`tmpfile` operation at `fs/namei.c:4026` and only then invokes the void
`inode_post_create_tmpfile` hook at `fs/namei.c:4042`, as declared by
`include/linux/lsm_hook_defs.h:123-126`. A later `security_file_open` rejection
at `fs/open.c:942` reaches the failed-open cleanup at
`fs/namei.c:4114-4150`. It can therefore prevent an `O_TMPFILE` descriptor or
linkable artifact from reaching the caller, but cannot satisfy a literal
no-inode-allocation rule.

That distinction is observable in the immutable OpenZFS 2.4.0 archive
`/nix/store/8062ray287njrihgsasw4zyi2749r5da-zfs-2.4.0.tar.gz`, with SHA-256
`7bdf13de0a71d95554c0e3e47d5e8f50786c30d4f4b63b7c593b1d11af75c9ee`.
`module/os/linux/zfs/zpl_inode.c:282-348` creates the tmpfile into ZFS's
unlinked set before `finish_open_simple`. Thus a `file_open` denial leaves no
reachable or persistent artifact after cleanup, while transient allocation
still occurred. If the production requirement is literally no creation, the
stock hook surface is insufficient; it needs a returning pre-filesystem hook
or trusted pre-filesystem mediation that validates the requested mode while
denying the effect worker any unmediated `openat2`, such as a final seccomp
policy installed after bootstrap.

Per-task policy identity is also source-feasible, not yet qualified. Linux
initializes the child's BPF task-storage pointer before the returning
`security_task_alloc` hook and aborts the clone if that hook fails
(`kernel/fork.c:2146-2168`, `security/security.c:3228-3237`). The base helper
dispatcher exposes cgroup- and task-storage lookup, creation, and deletion
helpers (`kernel/bpf/helpers.c:2048-2070`), while
`Documentation/bpf/map_cgrp_storage.rst:15-34,92-105` documents preallocation
by cgroup fd and the possible null lookup. This supports a design in which a
separate trusted loader registers an exact worker cgroup, an exec hook seeds a
task tag, `task_alloc` copies only an existing parent tag, and policy hooks
fail closed when either identity is absent. Every selected hook still needs
compile, verifier, inheritance, stale-cgroup, exec, clone, and VM-negative
proof before that design can be accepted.

There is no `BPF_F_RDONLY_USER` flag. `BPF_F_RDONLY` restricts syscall-side
access through an opened map descriptor, while `BPF_F_RDONLY_PROG` restricts
program-side access (`include/uapi/linux/bpf.h:1379-1402`). Neither makes the
map immutable: a process with `CAP_SYS_ADMIN` can reacquire a map by ID with a
writable descriptor (`kernel/bpf/syscall.c:4843-4858`). The current Network
effect worker retains `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, and
`CAP_NET_ADMIN`, so an acceptable design must move loading and map mutation to
a separate trusted service, remove the BPF and map-reopen authorities from the
effect worker, and deny its BPF object-management paths. `CAP_NET_ADMIN` is a
separate namespace-networking authority and is not implicated merely by the
map-FD issue. This bounded guard would still cover only the set-ID gap.
Dedicated enforcing domains and host-path allowlists, plus set-ID creation and
modification, forbidden-syscall, and post-namespace-entry host-write negatives,
remain mandatory. No `SBX-P0-10` checkbox is closed.

### Canonical Network kernel plan (in progress)

The Network broker can now compile one exact assignment, namespace allocation,
and packet-policy program into a bounded, architecture-neutral pre-effect
artifact. The V1 decoder independently admits closed actions, publication
requirements, enums, counts, reserved fields, and semantic digest cross-links,
then requires canonical byte-for-byte re-encoding. The artifact records that
namespace publication needs retained descriptor custody; it does not encode
descriptor numbers, paths, netlink messages, BPF commands, or loader-selected
programs.

The focused `aos-sandbox-network` kernel-plan suite passes six tests. Coverage
includes the shared published-IPv4 golden vector and malformed mutation corpus,
loopback-only isolation without a veth or tail, dual-stack allocation with an
IPv6 route and flow, exact reserved and length fields, and a duplicate-family
attack with its namespace digest recomputed. A Nix-backed current-source run of
the complete Network library suite passes all 76 tests, including these six and
the custody tests described below. The scoped formatter, all-target
no-dependency Clippy with warnings denied, and warning-denied rustdoc checks
pass. The canonical focused reproduction command is:

```text
nix develop -c cargo test --manifest-path crates/Cargo.toml -p aos-sandbox-network --lib kernel_plan
```

The complete current-source run used a realized AOS development-shell
derivation and the workspace manifest; it does not rely on a bare host Cargo
environment.

The checked-in structural C reader at
`tests/sandbox/network-kernel-plan-codec.c` accepts the same golden vector and
rejects the same mutation file when compiled with the AOS C wrapper under
`-std=c17 -Wall -Wextra -Werror`. Header size and offset assertions also pass
direct Clang syntax checks for `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu`. These are scoped manual results, not a hermetic
gate: a focused Nix conformance check must still compile and run the native C
reader and compile both target-header views. The C reader is deliberately only
a format-conformance oracle and must not become the privileged semantic
admission path.

No privileged Network worker, authenticated descriptor transfer, durable
namespace custody, netlink mutation, or mandatory packet-policy installation is
implemented by this increment. Apply remains unadvertised. The related Network
runtime and end-to-end qualification tasks remain open.

### Restart-retained Network namespace custody (in progress)

The Network library now has a typed systemd descriptor-store adapter for
restart-retained network namespace custody. It derives one reversible canonical
store name from each namespace handle, takes ownership of systemd activation
descriptors, independently retypes every descriptor as an `nsfs`
`CLONE_NEWNET` namespace, rejects the trusted host namespace and duplicate
physical identities, and requires activation to match the exact complete
protected replay set. The simultaneous custody ceiling is 1024 namespaces so
the complete `LISTEN_FDNAMES` value remains below Linux's per-string exec
limit.

Each add and removal sends a bounded `FDSTORE` or `FDSTOREREMOVE` notification,
waits for a processing barrier, then takes a complete
`DumpUnitFileDescriptorStore` snapshot and service-property readback. The
adapter reports success only when the expected name-to-FD identity mapping,
`FileDescriptorStoreMax`, and current descriptor count are exact. An unreadable
or divergent post-mutation snapshot poisons the adapter until restart because
the mutation may have taken effect even though its outcome cannot be proven.
The manager inspector uses the fixed local system-bus socket and a cancellable
worker so a missing bus or stalled authentication handshake cannot leave an
unbounded thread behind.

The systemd service configuration reserves the matching descriptor-store and
file-descriptor capacity, preserves the descriptor store across service exit,
allows notifications only from the main process, orders the broker after the
local D-Bus socket, and rejects enabling the broker when the AOS D-Bus service
is disabled. Evaluation confirms the default capacity of 1024,
`FileDescriptorStorePreserve=yes`, `LimitNOFILE=1152`, and
`NotifyAccess=main`; bounds of 0 and 1025 fail closed.

Twelve focused custody tests and the complete 76-test Network library suite
pass in the AOS development shell. Coverage includes activation ownership and
retyping, host and duplicate-namespace rejection, exact protected replay,
zero-handle rejection before activation or mutation, capacity rejection,
complete add/remove readback, poisoning after ambiguous mutation, malformed
manager rows, a missing system bus, and a stalled local authentication
handshake. Scoped formatting, all-target no-dependency Clippy with warnings
denied, and warning-denied rustdoc checks also pass.

This is a custody primitive, not an integrated Network runtime. `aos-netd`
does not yet adopt activation descriptors or store newly created namespaces,
and the real systemd path has not demonstrated capacity rejection, add/remove
acceptance, restart recovery, or deliberate stop/start semantics. SELinux
authorization for the manager inspection API and the protected-catalog policy
remain to be qualified. Authenticated worker descriptor transfer, namespace and
veth mutation, netlink/nftables effects, BPF installation, and authoritative
publication also remain open. Apply remains unadvertised.

### Exact Network kernel observation foundation (in progress)

The Network library now carries a concrete, namespace-qualified observation
model and an exact comparator for one complete kernel plan. It distinguishes
equal host and sandbox interface indexes, admits no extra sandbox links,
addresses, routes, nftables chains or rules, and binds route table, type,
scope, protocol, metric and preferred-source fields. Nftables comparison
requires the fixed base-chain hooks and default-drop policies, inverted
local-address anti-spoof DROP guards before endpoint ACCEPT rules, exact flow
positions, and measured-versus-loader artifact and policy commitments. The
lease gate comparison binds the installed object digest, loader provenance,
map schemas, TCX links, program tags, referenced maps, concrete interface and
the current two-direction lifecycle state. Two individually valid snapshots
must also have the same versioned observation digest.

The installed C BPF observer opens one plan-derived pin root through retained
`openat2` directory custody, validates root-owned protected ancestry and the
exact four-pin inventory, and opens each map and TCX link relative to that
held directory using `BPF_F_PATH_FD`. It validates map ABI and reserved fields,
the exact queried TCX link IDs, attached program IDs and tags, and both
programs' exact map relationship before emitting a closed JSON record. A
nonzero completion discards all output, including a syntactically complete
record.

The Rust reader measures the fixed observer executable and lease-gate object
through retained readable descriptors. It admits only normalized hash-named
Nix store paths resolved component-by-component without symlinks or magic
links. Root and `/nix` reject group/other writes; the deployed root-owned
sticky group-writable `/nix/store` contract protects existing root-owned
entries; and every store-output directory, descendant and artifact rejects all
write bits. Retained ancestry and artifact identities, bytes and current fixed
path association are revalidated before and after the bounded helper process.
The JSON decoder independently rejects unknown fields, oversized records,
noncanonical hexadecimal values, invalid versions and booleans, wrong map
schemas or attachment types, zero tags, and inconsistent graph identities.

The same retained-artifact boundary now drives an immutable AOS `iproute2`
binary for read-only rtnetlink inventory. Host observation accepts only the
plan-derived veth name. Sandbox observation deliberately dumps every link and
address, IPv4 and IPv6 routes from every table, and both policy-rule families.
Each command has a fixed timeout and output ceiling; nonzero, timed-out,
oversized, malformed, or non-newline-terminated output is discarded. The
closed decoder rejects unmodeled behavioral fields, non-permanent or tentative
addresses, unexpected link roles, route attributes, tables, protocols, scopes,
metrics, flags, and nonbaseline policy rules.

The comparator includes the complete fresh-namespace local-table baseline:
IPv4 loopback local and broadcast routes, IPv6 loopback local route, each
assigned-address local route, and the veth IPv6 `ff00::/8` multicast route. It
also binds the five default IPv4/IPv6 table-lookup rules. Family-specific Linux
defaults are explicit: IPv4 connected and static routes retain metric zero;
IPv6 connected and multicast routes use metric 256 and IPv6 static routes use
metric 1024. A checked raw Linux 6.18.44 fixture captured with the AOS
`iproute2` 6.18.0 executable is decoded and compared against an independently
specified dual-stack plan in the full stable-snapshot validator. This is
host-kernel behavior evidence, not AOS guest qualification.

The native observer package builds hermetically with warnings denied at
`/nix/store/miyxja70mcfcx4dp7mp6x6dxj7r7h7bl-aos-sandbox-network-observer-1`.
The AArch64 derivation evaluates with the target Linux headers explicitly ahead
of ambient build-machine include paths. Rust formatting passes, the complete
Network library suite passes all 97 tests, and the real systemd-custody fixture
compiles with a root-guest command that constructs the reader from the
installed observer and BPF object. That new command has not yet run in a guest;
the existing long fleet realization predates it. Scoped all-target Clippy with
dependency linting disabled passes with warnings denied.

This remains observation foundation only. The rtnetlink reader does not yet
prove each reported peer network-namespace ID against the retained authorized
namespace descriptor with `RTM_GETNSID`; a matching peer interface index and a
present namespace ID are not sufficient identity proof. No nftables reader,
authenticated single-thread namespace worker, double-snapshot production
composition, or root-guest positive BPF observation has qualified the path. No
namespace, veth, route, nftables or BPF mutation is implemented, and Apply
remains unadvertised. The Network runtime and end-to-end qualification tasks
remain open.

### Network custody and observer qualification (in progress)

The current source closes the descriptor-backed observation gaps above. A safe
`RTM_GETNSID` wrapper now derives the local namespace ID only from a retained
peer descriptor. The single-threaded observer validates protected lifecycle
publication against systemd activation custody, proves the host and sandbox
veth ends through reciprocal descriptor-derived namespace IDs, and restores
the retained initial-host namespace after every successful transition. Failure
to restore terminates the worker instead of returning from an unknown network
namespace. The composed stable snapshot reads rtnetlink, the exact
`inet aos_sandbox` nftables table, and the retained lease-gate BPF graph twice
before admitting one observation.

The real-systemd x86_64 fleet gate now passes isolated and managed observer
paths from signed admission through protected preparation, operation, namespace
catalog, retained nsfs custody, real `iproute2` and nftables inventory, and
observer-scoped BPF pins. Its false-peer control preserves the expected link
indexes, reciprocal peer indexes, names, MAC addresses, MTUs, veth kind, and
complete flags while moving the physical peers into two unauthorized
namespaces. The observer rejects that substitution as `PeerMismatch` only after
proving restoration to the initial host namespace. The gate also covers
immutable observer and BPF-object custody and rejects writable or symlinked
substitutes.

The same gate qualifies descriptor-store acceptance and exact readback,
idempotent replay, retention across process crash and service restart,
fail-closed deliberate stop/start when the protected pin is absent, actual
manager-capacity partial acceptance, and post-mutation denial, malformed-row,
and inconsistent-count ambiguity followed by process-lifetime poisoning. A
systemd dump path is treated only as diagnostic text because `fd_get_path()`
may report an nsfs name, bind path, or deleted bind path; the adapter continues
to require a read-only typed namespace descriptor and exact device/inode
identity. Same-name identity substitution is ambiguous and poisons subsequent
operations.

The exact fleet derivation
`/nix/store/pf9g9323wa9k5hhjxj820hnbp93faldi-aos-fleet-test-sandbox-network-namespace-custody-0.drv`
passes at
`/nix/store/9lkq2p5v8cxxmda8zcflz5nz8nvxk3f0-aos-fleet-test-sandbox-network-namespace-custody-0`.
The complete Network all-target suite passes 138 library tests and the
`aos-netd` binary test; the 13 focused namespace-store tests, Rust formatting,
and all-target no-dependency Clippy with warnings denied also pass.

Commit `e508b0c321` records this observer slice. Its closed nftables decoder now
requires the exact mandatory table name on the table object and the exact table
identity on every chain and rule. A regression first accepts the complete
pinned nftables 1.1.1 fixture after reserialization, then independently rejects
wrong, absent, and non-string identities at all three object kinds for the
identity-specific reason.

An isolated materialization of the exact committed candidate passed 139
Network library tests, the `aos-netd` binary test, the systemd-custody fixture
test, and 101 Linux boundary tests. The Linux run intentionally ignored
`pidfd::tests::liveness_target_fixture` and
`process::tests::isolated_nondefault_sigchld_case`; their names remain explicit
qualification limits rather than claims of blanket privileged-kernel coverage.
All three packages also passed all-target no-dependency Clippy with warnings
denied. The five-VM fleet result above qualifies the stated privileged custody
and observer scenarios separately.

This qualifies the current custody and read-only observer composition, not
Network Apply. No production namespace/veth/address/route/nftables/BPF mutator,
authenticated Apply handler, controller dispatch and orchestration, guardian
coupling, or full production lifecycle end-to-end test exists yet. Apply
remains unadvertised, and `SBX-NET-01`, `SBX-NET-02`, `SBX-NET-03`, and
`SBX-P0-06` remain open.

### Kernel-matched SELinux policy artifact (offline qualification)

Commit `1d2929acd` adds a separately selectable production refpolicy variant
and an offline final-policy builder without changing the legacy `refpolicy`
derivation. The unchanged legacy package still evaluates to
`/nix/store/lcbmhc52nh7h23vjjbk1q56f934msnv5-refpolicy-2.20240916.drv`.
The production variant patches the upstream class map for the pinned Linux
6.18.33 source and sets reject-unknown before building the complete upstream
module set. It does not link the legacy AOS `kernel_t`/`unlabeled` compatibility
module.

The final-policy derivation
`/nix/store/07g2yzmviih7g2g07mf5yrpdjp7b7bhv-aos-selinux-production-policy-1.drv`
passed at
`/nix/store/zr1c2l77vy9xhygrwg17szvy94ciwc32-aos-selinux-production-policy-1`.
It extracts 96 ordered kernel class rows directly from the pinned kernel source,
decodes the linked policy binary, requires every complete kernel permission
sequence as an ordered prefix, permits only trailing userspace extensions, and
requires exactly `handleunknown reject`. The installed policy version 33 binary
has SHA-256
`9326fa5f862657abd0f73cdd9439114e3c1f5f3f4c3c481bce1fc0df8e6c5a93`.
The same build compiles the aggregated upstream file contexts while validating
every context against that binary policy.

The negative gate removes the real `io_uring.allowed` pair from the decoded
policy. The comparator rejects the deficient source for the exact ordered-
permission reason; `secilc` produces a nonempty compiled binary policy, which
`checkpolicy` decodes before the same comparator rejects it for the same reason.
Comparator unit coverage passes five fail-closed cases. The supporting `secilc`
package installs all three upstream binaries and all three validated and
rendered manual pages from AOS-built source dependencies.

This is an offline build and compatibility qualification only. No system selects
the new artifact, loads it during boot, labels the initrd, composefs root, or
writable state, enters an enforcing domain, or grants an inspector capability.
`SBX-P0-10` remains open.

### Immutable EROFS SELinux labels (offline qualification)

Commit `7140224de` adds a deterministic SELinux context planner and exact image
inspection gates for the two EROFS builders used by AOS. The planner walks the
complete input tree, preserves inode kinds and hard-link identity, resolves
symlink components within the image namespace, and consults the production
policy's file contexts. It propagates specific labels through conventional
aliases and uses bounded ELF classification only as a fallback for otherwise
unmatched Nix-store regular files. It emits both an exact file-contexts input
and a versioned path/kind/context map. The gate compiles that generated input
against the production binary policy and requires persistent libselinux lookup
of every planned entry before building an image.

The immutable derivation
`/nix/store/12r6khvaw31vqfjxmbhc2kvlax9w4x51-selinux-erofs-labels-check-0.drv`
passed at
`/nix/store/9xcayr2jkqw39jl30gdd9vmshhq5fqvl-selinux-erofs-labels-check-0`.
It labels and verifies a 25-inode generic `mkfs.erofs` image containing actual
AOS coreutils, glibc, and systemd executables, aliases, a hard-link pair, and
paths containing spaces and tabs. A second round trip builds a different small
fixture and context map under the same schema, feeds it through the optional
composefs dump input, builds a real composefs EROFS image, and requires exact
equality of the complete observed path, inode-kind, and `security.selinux` map.
The gate retains the generic image, both context maps, and the composefs input
and observed dumps. The package-platform inventory gate also passed at
`/nix/store/b4vpz7sbzlya62vmbppqdn4say3i6kin-package-platform-support-check-0`.

The verifiers deliberately preserve each pinned builder's byte convention.
erofs-utils 1.8.10 writes `strlen(context)` bytes for `--file-contexts`, without
a trailing NUL. The composefs 1.0.8 dump contract represents the conventional
terminator as `\x00`, and `mkcomposefs` preserves that supplied length. Linux
6.18.33 reads the stored xattr length and uses `kmemdup_nul()` before parsing,
so it accepts either representation. The gates nevertheless require the exact
producer-specific encoding instead of stripping or adding bytes during
verification.

This checkpoint qualifies deterministic source planning and byte-exact offline
image construction only. At this point, production system and initrd builders
did not consume the plan, and no boot path selected or loaded the policy,
labeled writable state, entered enforcing service domains, or granted a
narrowly authorized inspection component. It therefore qualified no part of
`SBX-P0-10`, which remained open.

### Nullable production `/etc` label wiring (offline prerequisite)

Commit `e89f3a3f3` wires the exact planner into the production `/etc` composefs
builder behind the internal nullable `system.build.immutableSelinuxPolicy`
input. Its default is null and retains the legacy unlabeled dump and EROFS
derivations. A non-null policy first renders an unlabeled composefs dump as the
single authoritative inode inventory, resolves every image path at its runtime
`/etc` mount prefix, compiles and round-trips the resulting exact file-context
database, applies the internal-path context map to a second dump of the same
configuration, and verifies the completed EROFS image against that map before
publishing it.

The shared dump parser now rejects noncanonical paths and numbers, duplicate
paths or xattrs, absent or non-directory parents, and malformed inode metadata.
Planner admission additionally rejects unsupported inode kinds and ambiguous
hard-link identity. Mount-prefix handling keeps map keys internal but uses
runtime paths for policy lookup, Nix-store classification, alias target
resolution, dynamic-loader authority, and pseudo-filesystem exceptions. Thus an
internal `/nix/store` subtree in the `/etc` image is correctly treated as
runtime `/etc/nix/store`, while a default-root dump still rejects a store
regular inode that lacks an authoritative source for ELF classification.

The immutable check derivation
`/nix/store/3ypdzi1hpdj7pcaxc1m7d6vagqbjbv6y-selinux-erofs-labels-check-0.drv`
passed at
`/nix/store/kp17x8kwf5hd8ax93xl7jir7j7cm4flv-selinux-erofs-labels-check-0`.
It extends the real server module twice: an explicit forced-null instance builds
an actual legacy `/etc` EROFS whose observed dump contains no SELinux xattrs,
and an explicit production-policy instance builds and exactly verifies a
labeled `/etc` EROFS. The retained labeled dump records the image-internal
`/selinux/runtime-prefix-fixture` symlink as `selinux_config_t`, proving that
policy lookup used runtime `/etc/selinux/runtime-prefix-fixture` rather than an
incorrect image-root path. The gate passed 35 planner, eight dump-verifier,
seven EROFS-verifier, and five composefs-dump-builder tests. It retains both
module-observed dumps, the generic EROFS fixture, exact compiled contexts, and
the composefs codec evidence beneath `share/aos/selinux-erofs-labels/`.

This is production-builder plumbing and offline image evidence, not enforcing
boot qualification. No production profile sets the nullable input; the initrd,
root filesystem, and writable state remain outside this integration; and no
boot path loads the policy, proves enforcing mode before mutable startup, enters
service domains, or grants the proposed narrow inspection authority.
`SBX-P0-10` and end-to-end enforcing-host-MAC qualification remain open.

### Per-assignment Guardian authority and timer foundation (partial)

Commit `fefe8993f` records the first isolated Guardian foundation. The portable
registry assigns Guardian audience and protocol code 4 and sparse
`GuardianArm` verb 34; Storage now independently assigns verb 33 to its
resource-targeted root-pin repair operation. The
controller-signed plan must contain exactly one assignment-target arm grant.
Its fixed 160-byte semantic commitment binds the complete assignment tuple,
node, current host boot ID, and the exact authority-signed ownership-lease
generation and digest. Generic publication and effect-ledger paths explicitly
reject the Guardian audience rather than inventing a dispatch code or routing
it through an existing privileged broker.

The capability-empty per-assignment binary accepts four exact signed authority
artifacts plus pinned trust-policy, public-key, revocation-scope, and node
descriptors. It verifies both signatures and every plan/lease cross-link,
enforces desired-state and lease high-water marks across boots, rejects
same-generation equivocation, and derives the earliest exclusive deadline from
the plan and lease using a paired wall-clock and `CLOCK_BOOTTIME` sample. A
fresh current-boot plan may reuse the same exact still-current lease after
reboot; persisted state alone is never authority.

Before reporting READY, the process holds an exclusive nonblocking state lock
and commits a fixed-width record by exclusive temporary creation, write, file
`fsync`, rename, directory `fsync`, and exact readback with a predecessor
digest check. Its type states prevent readiness before durable persistence.
The runtime rechecks the committed record and current clock immediately before
READY, then waits against the absolute boot-time deadline.

The typed systemd adapter transfers exactly ten named read-only descriptors,
uses one incarnation-derived 0700 `StateDirectory`, `DynamicUser`, empty
capability sets, `Restart=no`, `AF_UNIX` only, and denies socket bind, listen,
connect, and accept operations. The system bus is inaccessible and the public
adapter exposes only Guardian start, not a general unit-management API. The
test asserts the exact ordered D-Bus signature of every emitted transient
property against systemd 259.8, including `StateDirectory` as `as`,
`ProtectHome` as `s`, and `RestrictNamespaces` as a zero-valued `t` mask.

One exact pinned-development-shell run of the nine affected packages passed
after the final transient-property type corrections. It covers 188 core tests,
three Guardian unit tests, nine Guardian integration tests, 359 sandbox tests,
15 systemd unit tests, 25 systemd client tests, the broker, Host, Mount,
Network, and Storage suites, and all selected doctests.

This is an authority-verification, durable-deadline, and typed-unit foundation,
not Guardian completion. The payload unit compiler already emits typed
`BindsTo=`/`After=` properties naming its Guardian, but no production
Host/controller path delivers the Guardian descriptor set, starts it before the
payload, or exercises that dependency. Expiry has no production early-freeze
request or Network default-drop coupling, renewal is not orchestrated, and no
VM test proves expiry or Guardian death stops a payload. The early-freeze
margin, hard-deadline path, and kernel lease gate remain separate dependencies.
`SBX-GUARD-01`, the dependent runtime tasks, and end-to-end qualification all
remain open.

### Guardian-bound Host dispatch and effect recovery (partial)

Commit `3149a1f3a` adds the controller-side protocol and durable-dispatch half
of Guardian-gated launch. Host protocol 1.5 adds a launch-only companion that
carries exactly one canonical Guardian plan and detached signature. Templates,
non-Launch actions, and other Host versions reject the companion, while a live
Host 1.5 Launch requires it. The enclosing Host authorization quartet remains
the only carrier for the exact ownership lease and lease signature. Host 1.4
Launch stays structurally decodable for compatibility, but production
publication selection refuses to dispatch a pre-1.5 Launch.

After current publication and lease selection, the reconciler constructs a
`GuardianPlanRequestV1` that binds the Host assignment, node, desired
generation, ownership signer, current host boot, and exact lease generation and
digest. The executor's narrow signing hook may return a signed Guardian 1.0
plan; the controller then reselects current state and rejects every stale or
substituted result. The accepted plan has one assignment-target `GuardianArm`
grant covering the 160-byte binding with zero actual descriptors. Its expiry
and the ownership lease jointly cap the Host BOOTTIME deadline, including the
one-wall-tick reserve required by Guardian sampling order. The controller
inserts the exact Guardian pair, rechecks the expanded body against the Host
grant and packet ceiling, and preserves the same lease pair in the outer Host
envelope.

The authority-bearing effect record advances from V2 to V3 to retain the host
boot paired with its preparation wall-time and BOOTTIME scalars. An ambiguous
V3 Applying attempt must match a fresh executor boot before observation or
Apply I/O. Recovery redecodes the nested Guardian plan, rederives its complete
boot-and-lease binding, rebuilds the Host body and outer packet, and compares
the whole attempt with durable bytes. Completed V3 history remains readable
across reboot. A Planned V2 record has no dispatch and advances directly to a
fresh boot-bearing V3 attempt. A dispatch-bearing completed or permanently
blocked V2 record remains historical input but cannot be re-encoded; a
dispatch-bearing V2 Applying record fails with `MigrationRequired` before I/O.
Generic V1 effects and the existing V2 binding digest stay unchanged.

Initial dispatch and authenticated `Absent` retry use the same ordering:
select current, request the exact Guardian signature, reselect current, commit
the composite attempt, then permit Host I/O. A refreshed attempt is durable
before Apply, so crash recovery queries that exact replacement. `Pending` and
transport ambiguity retain the existing packet and never authorize an
unrecorded replacement.

Pinned development-shell validation passes all 368 `aos-sandbox` library
tests, all 190 core tests, all 116 protocol tests, and the complete Guardian
package run with one library test and nine integration tests. Coverage includes
real Ed25519 Host and Guardian plans, boot and Guardian-expiry substitution,
lease renewal with stale-plan rejection, initial and Absent-retry ordering,
durable body/packet/boot mutation, V2 migration and historical compatibility,
and completed V3 recovery across reboot.

Commit `803ba708a` adds the descriptor-custody boundary needed by the future
Host handoff. A Linux helper creates anonymous dynamic credentials with the
complete write, grow, shrink, and seal seals, then reopens them read-only
without retaining a writable description. The typed systemd adapter accepts
exactly ten ordered descriptors: six creator-owned, singly linked, read-only
protected files with exact mode and repeated content/metadata checks, followed
by four anonymous fully sealed read-only credentials. It revalidates every
retained snapshot immediately before D-Bus transfer. The Guardian startup path
proves it is single-threaded, rejects any inherited descriptor outside stdio
and the exact ten-name activation set, and duplicates descriptors without
taking ownership of the caller's raw descriptor number. Focused and complete
development-shell runs passed 113 Linux tests plus eight doctests, 42 systemd
tests, and 14 Guardian tests, including exact-binary missing, renamed, and
extra-descriptor startup failures. This is source-level custody validation;
Host does not yet retain the six protected input descriptors or assemble the
four request artifacts into this typed set.

Commit `b26875ac0` adds Host state format 4 and a pure Guardian/Stop transition
model without enabling effects. Each future launch record retains the exact
dynamic artifact bytes, six protected-input snapshots, a content-digested
pinned executable identity, and a recomputed attempt binding. Its closed phases
distinguish authorization, issued Guardian and payload starts, current-job
Guardian readiness, worker proof, exact-owned cleanup, and historical
completion. An arbitrary active unit cannot become readiness evidence. The
Stop model separately records authorized planning and an issued frozen target
set, so expiry permits only completion of already-issued exact operations;
every stop rechecks the current binding and invocation, payload-before-Guardian
progress never rewinds, foreign or indeterminate observations quarantine, and
recording cleanup completion requires both units currently absent. Later
replay of a completed record is a historical receipt, not a claim of current
liveness. Exhaustive pair matrices cover exact, wrong-invocation,
wrong-binding, indeterminate, and absent observations in every cleanup phase.
Host carriers 1.1 through 1.4 continue to use signed Host 1.1 authority, while
the future matrix assigns only Host 1.5 Launch to signed 1.5 authority and
leaves lifecycle actions at signed 1.1. Apply and Query share that selector.
Versions 1 through 3 migrate only with empty fence and request tables, and
production reopen explicitly rejects the future execution variants because
their domain-separated protected-authority authentication is not integrated
yet. Focused validation passed all 17 transition tests, the migration test, the
Apply/Query carrier matrix, and the authenticated-reopen tamper test.

Commit `fe8b6f661` preserves the six public Guardian authority descriptors from
the exact opens used to construct protected Host authority. The retained typed
set excludes `journal-mac-key` and records device, inode, mode, owner, link
count, size, modification/change timestamps, and the exact repeated-read
SHA-256 content snapshot. Its all-or-nothing borrowed accessor revalidates
those properties and content before a future handoff. Directly constructed
test authority deliberately has no descriptor custody. Journal namespace 36
is appended as `HostExecution`; the Host adapter seals nonempty execution
payloads under the fixed `AOSHOSTEXECV0001` domain and exact nonzero 16-byte
request key, with the existing authenticated-record bounds. Tamper, request
relocation, domain substitution, zero identity, empty payload, and oversized
payload fail closed.

The pinned development shell passed the production Broker/Host library and
Host binary check, all 24 Broker and 118 Host library tests, and focused runs
of eight protected-configuration tests, the namespace compatibility test, and
three Host custody/MAC tests. The retained-FD regressions use actual
descriptors with successful positive controls, then reject an equal-length
in-place rewrite and atomic replacement that drops the retained inode's link
count to zero. Their ordinary cargo-test hook uses unprivileged metadata
inspection in place of the protected-object gate; it still exercises retained
descriptors, repeated reads, `fstat`, and original-snapshot comparison. This is
not a root-provisioned or VM transfer test.

This remains controller and source-level Host progress. The signing hook
defaults to unavailable and has no production controller authority adapter.
The Host 1.5 carrier guard and format-4 live reopen gate remain closed. Host now
retains and can revalidate the static protected descriptors and can authenticate
a bounded execution record, but no live path consumes either foundation,
assembles and transfers the dynamic credentials, starts the exact Guardian
before the payload, observes manager-retained launch bindings, or performs the
final protected before-effect checks for both starts. Live exact-unit retry and
compensation, composite Stop integration, renewal, early freeze, Network
default-drop coupling, and a VM test proving expiry or Guardian death contains
the payload also remain open. No `SBX-GUARD-01` or end-to-end Host task is
closed by these slices.

### Qualified fleet firmware-variable stores (harness foundation)

Commit `a0e888953` adds opt-in image-machine firmware-variable seeds and
exported stores to the fleet schema, validator, harness, and QEMU driver.
Kernel-boot seeds and exports and unsafe export names fail evaluation. After a
successful test, export waits for an accepted guest shutdown and natural
status-zero QEMU exit, then requires a regular non-symlink store of the seed's
exact size before installing it read-only. Non-export cleanup behavior is
unchanged.

All 22 focused Python driver tests pass. The final schema derivation
`/nix/store/qwclvnsrhzr5py4whaf2cavyz4r8gzic-fleet-spec-check-0.drv` passes
all nine assertions at
`/nix/store/vp9khjcbdwn3z5mvlfnpyy1al5lpwbx5-fleet-spec-check-0`. Capture-only
evaluation produced enrollment derivation
`/nix/store/x8kn05rrlg15zgap8y87lb6hj941cjdm-aos-fleet-test-secure-boot-enrolled-vars-0.drv`
and strict gate
`/nix/store/d5dz3jcpb71bpgsann7g9g52kv3g65j6-aos-fleet-test-selinux-stage0-admission-0.drv`;
the strict manifest depends on that exact enrollment producer.

At this capture-only checkpoint, neither VM output was realized. Firmware
enrollment, exported-store reproducibility, and the three-machine immutable
SELinux admission gate therefore remain pending. This harness foundation alone
qualifies no stage-0 boot or enforcing host-MAC behavior, and `SBX-P0-10`
remains open.
