# Implementation task ledger

This ledger is the durable execution record for RFC-0020. A checked task has
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
  capability assertion. These tasks remain open until the same gate also
  covers payload-leader discovery, internal reboot, the production transient
  unit compiler, cgroup identity, and both supported architectures. The first
  execution attempt and the existing `boot-basics` control both timed out at
  the pre-test guest-agent readiness boundary, so the build/evaluation result
  does not yet count as runtime evidence.
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
  removal, barriers, and bounded service configuration. Daemon adoption and
  durable resource reconciliation remain open.
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
  check alongside master's bootstrap, cross-platform, and image checks. The
  sandbox RFC is now RFC-0020 because master assigned RFC-0019 to OCI
  containers. Directory links and textual RFC references change; portable
  protocol identifiers, wire versions, and golden commitments do not.

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
