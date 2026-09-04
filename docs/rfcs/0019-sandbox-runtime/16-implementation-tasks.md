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

The post-`727da7f3e` x86_64 `sandbox-filesystem-capability-proof` rerun built the
complete hermetic Rust closure, AOS system, initrd, and VM disk and launched
QEMU with KVM. The guest agent timed out before readiness with a blank serial
log, so the fs-verity/FUSE runtime body never executed and `SBX-P0-02` remains
open. This is recorded as a VM boot-boundary failure, not capability evidence.
