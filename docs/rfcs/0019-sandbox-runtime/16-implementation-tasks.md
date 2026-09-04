# Implementation task ledger

This ledger is the durable execution record for RFC-0019. A checked task has
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
