# 24 — Determinism Harness & Testing

This file specifies **how Crucible proves it is deterministic** and keeps it that
way. It is the authoritative home of two things the rest of the RFC leans on:

1. **The canonical gate catalog** — the named CI checks every other topic file
   references by ID (e.g. `gate:replay-oracle`). The gate names defined here are
   normative and verbatim; a reference elsewhere that does not appear in §1 is a
   defect.
2. **The layered test strategy** — what is tested at each layer L0–L4, the
   in-process QEMU test double that lets most of it run in milliseconds, the
   execution fingerprint, divergence bisection, adversarial determinism testing,
   ABI conformance and fuzzing, the harness self-determinism lint, the QEMU patch
   micro-tests and inertness gate, and the end-to-end acceptance gate.

The testing strategy is itself foundation-first ([G-5]): the harness is built
*before* the things it tests, because a determinism contract is only as real as
the check that fails when it is violated. Requirements here carry the `HARN-`
prefix.

Forward references: the determinism contract is [`04-determinism-contract.md`](04-determinism-contract.md);
the execution model and replay oracle are [`05-execution-model.md`](05-execution-model.md)
and [`07-temporal-graph.md`](07-temporal-graph.md); the reproduction artifact is
[`06-spatial-graph.md`](06-spatial-graph.md) and [`23-cli.md`](23-cli.md); the
QEMU patch series is [`11-qemu-patches.md`](11-qemu-patches.md); the plugin,
shmem ABI, and protocol are [`12-qemu-plugin.md`](12-qemu-plugin.md),
[`13-shmem-abi.md`](13-shmem-abi.md), and [`14-protocol.md`](14-protocol.md); the
I/O sub-nodes and guest↔host channel are [`15-io-subnodes.md`](15-io-subnodes.md)
and [`16-guest-host-channel.md`](16-guest-host-channel.md); the layer map is
[`27-crate-structure.md`](27-crate-structure.md); the harness lint lives with the
engineering standards in [`28-engineering-standards.md`](28-engineering-standards.md).

---

## 1. The gate catalog (authoritative)

A **gate** is a named, automated CI check that must be green before the phase it
guards is allowed to advance ([`00-conventions.md`](00-conventions.md) §"Phase
gates"). Gates are the mechanism by which "get the foundation completely correct
first" ([G-5]) is *enforced* rather than hoped for. Each gate below names what it
runs, its pass/fail criterion, the layer/phase it guards, and the
invariants/requirements it enforces.

- **[HARN-1]** The gate names in the following table are **canonical and
  normative**. Every gate referenced anywhere in this RFC MUST appear in this
  table verbatim; every gate in this table MUST be implemented as a CI target of
  the same name and MUST be wired into the phase plan in
  [`32-implementation-plan.md`](32-implementation-plan.md). A gate that no
  requirement references, or a referenced gate not defined here, is a doc-lint
  failure ([`28-engineering-standards.md`](28-engineering-standards.md)).

### 1.1 Canonical gate index

| Gate | Layer/phase guarded | Primary invariants/requirements | One-line criterion |
| --- | --- | --- | --- |
| `gate:harness-lint` | All crucible crates (Phase 0, runs on every PR) | INV-9; HARN-24..26 | No banned nondeterminism source compiles in the engine. |
| `gate:layer0-determinism` | L0 deterministic core | INV-4, INV-8; HARN-3 | The sim runtime/scheduler primitives reduce identically twice. |
| `gate:single-vm-fingerprint` | L2 single VM (Contract A) | DET (Contract A), INV-4; HARN-4, HARN-7 | One VM's execution fingerprint is bit-identical across runs. |
| `gate:layer1-injection` | L1 co-sim transport (Contract B) | INV-3; HARN-5, HARN-8 | Cross-node injection icount is a pure function of virtual time. |
| `gate:content-address` | L1/L3 content-addressed store | INV-6; HARN-11 | Equal content hashes equal; unequal content does not collide. |
| `gate:replay-oracle` | L3 temporal graph | INV-1, INV-2; HARN-12, HARN-13 | Fat-checkpoint hash == thin (replay-from-ancestor) hash. |
| `gate:divergence-bisect` | Cross-layer diagnostic | INV-10; HARN-9, HARN-10 | A seeded divergence is localized to its first differing step. |
| `gate:scheduler-liveness` | L3 scheduler actor | INV-8; HARN-18 | The scheduler always reaches quiescence or its time limit; no deadlock/livelock. |
| `gate:control-responsive` | L4 control plane | INV-8; HARN-19 | A control op is acknowledged within a bounded number of quanta. |
| `gate:any-guest` | L2 guest boot | INV-5, G-2; HARN-6 | An unmodified guest boots deterministically with no image mutation. |
| `gate:qemu-inert` | AOS QEMU package + patch series | INV-7, G-7; HARN-20, HARN-21 | Sim-off QEMU is behaviorally identical to upstream; each patch has a passing micro-test. |
| `gate:abi-conformance` | L1 boundary ABIs | G-8; HARN-32, HARN-33, HARN-34 | Shmem layout, protocol, and RPC match frozen golden vectors. |
| `gate:license-boundary` | Repository and Crucible/QEMU boundary (Always) | BOUND-1..BOUND-12 | `crucible-harness` rejects dependency, license-scope, protocol-shape, package-source, or corresponding-source violations. |
| `gate:patch-microtests` | QEMU patch series (per-patch) | INV-7; HARN-20 | Every patch in the series has a focused, passing behavioral test. |
| `gate:adversarial-determinism` | Cross-layer (Phase ≥ L2) | INV-1, INV-4, INV-9; HARN-11 | N runs under hostile host conditions yield byte-identical canonical logs. |
| `gate:e2e-determinism` | Final acceptance (all layers) | All headline invariants; HARN-22, HARN-23 | A representative multi-VM, fault-injected scenario runs bit-identically across adversarial conditions and reproduces from its artifact. |
| `gate:basic-block-coverage` | L2/L3 coverage observation | INV-4, INV-7; ADV-21, PLUG-35..PLUG-37 | An opt-in loaded-QEMU run emits the expected guest-PC/block-length coverage stream with no fingerprint effect; off mode installs no callback. |
| `gate:perf-bench` | Cross-layer (Phase ≥ L2), regression | G-9; PERF-1..PERF-34 | Cost-model metrics meet their baselines and no metric regresses beyond threshold. Unlike every other gate this is a *regression* gate (per-metric baselines), not a byte-identity check; it MUST never trade determinism for speed (defined in [`25-performance-targets.md`](25-performance-targets.md) §25.11). |
| `gate:fleet-equivalence` | Cross-layer (Phase ≥ L3) | DCE-16, DCE-17, DCE-20; G-6 | Single-host and fleet search over the same `(family, seed, budget)` discover the same content-addressed finding-set with byte-identical artifacts; discovery order may differ. |
| `gate:campaign-continuity` | Cross-layer (Phase ≥ L3) | DCE-11, DCE-12, DCE-26; PERF-28 | Seeding run N+1 from run N's campaign reproduces each corpus entry bit-identically, accumulated coverage is monotone non-decreasing across runs, and cross-provenance reuse is refused. |
| `gate:signal-fault-system` | Cross-layer (Phase 7) | RFC-0013 executable contract | The closed signal-driven network, storage/9p, and node fault system has exhaustive per-kind evidence, live-boundary coverage, replay identity, documentation, and no retired or specification-only executable path. |

The first twelve names — `gate:layer0-determinism`, `gate:single-vm-fingerprint`,
`gate:layer1-injection`, `gate:replay-oracle`, `gate:divergence-bisect`,
`gate:any-guest`, `gate:content-address`, `gate:qemu-inert`,
`gate:scheduler-liveness`, `gate:control-responsive`, `gate:harness-lint`, and
`gate:e2e-determinism` — are the names the spine and other topic files already
reference. `gate:abi-conformance`, `gate:patch-microtests`,
`gate:adversarial-determinism`, and `gate:perf-bench` (the last owned by
[`25-performance-targets.md`](25-performance-targets.md)) are added here and are
equally canonical. `gate:basic-block-coverage` is the Phase-6 coverage boundary;
it remains red until its loaded-QEMU proof is green. `gate:fleet-equivalence`
and `gate:campaign-continuity` (owned
by [`35-distributed-continuous-exploration.md`](35-distributed-continuous-exploration.md))
are likewise canonical.

`gate:signal-fault-system` is the terminal fault-system acceptance gate. It
aggregates the closed effect registry, production adapter capability manifests,
live boundary tests, replay/search evidence, documentation coverage, and the
repository guard that rejects retired fault APIs and executable sensor effects.

`gate:license-boundary` is an **Always** gate owned by `crucible-harness`; it
runs on every boundary-affecting change and at release construction.

- **[HARN-2]** A gate MUST be a *pure* check: given the same source tree and the
  same seed corpus it MUST produce the same pass/fail verdict on any machine.
  Gates MUST NOT depend on wall-clock thresholds, host core count, or network
  access. A gate that is flaky is treated as failing and blocks the phase until
  the flake's root cause (a residual nondeterminism) is eliminated — never
  retried or quarantined ("prefer root-cause over workaround").

### 1.2 Per-gate detail

#### `gate:harness-lint`

- **Runs:** the harness self-determinism lint (§9) over all `crucible-*` crates —
  a custom static analysis plus a curated `clippy`/`dylint` lint set that bans
  ordering-significant nondeterminism (unordered map iteration on ordered paths,
  host wall-clock/thread-RNG in the engine, unordered `select`).
- **Pass/fail:** zero findings. A single finding fails the gate.
- **Guards:** runs on every PR before any other gate (cheapest, catches the
  largest class of regressions at the source). **Enforces:** INV-9.

#### `gate:layer0-determinism`

- **Runs:** the L0 (`crucible-sim`, `crucible-assert`) determinism suite — the
  runtime/scheduler primitives are driven through a fixed decision sequence twice
  and the resulting canonical state digests compared, plus property tests on the
  scheduler's ordering and the decision RNG's stability under entity addition.
- **Pass/fail:** the two digests are byte-identical and all properties hold.
- **Guards:** L0; must be green before L1 is built on it. **Enforces:** INV-4,
  INV-8 (the scheduling primitive level).

#### `gate:single-vm-fingerprint`

- **Runs:** the single-VM execution-fingerprint comparison (§4) — boot one
  unmodified guest under sim mode twice with a fixed `(image, kernel cmdline,
  seed, injected-input sequence)` and compare the periodic icount + register +
  memory-region fingerprints.
- **Pass/fail:** every fingerprint sample matches between the two runs; the final
  fingerprint matches; icount totals match. Any mismatch fails and triggers
  bisection (§5) to localize.
- **Guards:** L2, Contract A. **Enforces:** the per-VM determinism contract
  ([`04-determinism-contract.md`](04-determinism-contract.md), Contract A), INV-4.

#### `gate:layer1-injection`

- **Runs:** the cross-node injection-determinism suite (§4.4) — drive frames
  through the shmem SPSC queues + protocol (against the in-process QEMU double,
  §3) and assert that the *icount at which each frame is observed by the
  receiving node* is a pure function of `(virtual_time, consumer node_id, producer node_id, sequence)`,
  independent of how the host interleaves producers.
- **Pass/fail:** identical observed-injection-icount vectors across all tested
  host interleavings.
- **Guards:** L1, Contract B. **Enforces:** INV-3.

#### `gate:content-address`

- **Runs:** the content-addressing suite — hash stability (same bytes → same id
  across runs/machines), collision-resistance sampling, and the property that
  structurally-equal scenario components / snapshots / log segments / schedule
  deltas hash equal while any single-byte change does not.
- **Pass/fail:** stability and equality properties hold; no observed collisions
  in the corpus.
- **Guards:** L1/L3 store. **Enforces:** INV-6.

#### `gate:replay-oracle`

- **Runs:** the replay-oracle structural test (§6) — for a corpus of checkpoints
  (fixed + randomly sampled during search), materialize each fat checkpoint and
  independently reconstruct it by re-reducing from an ancestor along the same
  schedule, then compare by content hash.
- **Pass/fail:** `hash(fat) == hash(reduce-from-ancestor)` for every checkpoint
  in the corpus.
- **Guards:** L3 temporal graph; this is the load-bearing correctness gate for
  the data model. **Enforces:** INV-1, INV-2.

#### `gate:divergence-bisect`

- **Runs:** the divergence-bisection tool (§5) against deliberately-perturbed
  runs (a seeded fault injected into one of two otherwise-identical runs) and
  asserts the tool reports the *correct* first differing decision/instruction and
  emits a usable both-sides state dump.
- **Pass/fail:** for every seeded perturbation, the reported first-divergence
  point equals the known injection point (within one fingerprint window, then
  refined to the exact instruction).
- **Guards:** cross-layer diagnostic; gates that INV-10's "localize, never smooth
  over" promise actually works. **Enforces:** INV-10.

#### `gate:scheduler-liveness`

- **[HARN-18]** `gate:scheduler-liveness` MUST drive the single authoritative
  scheduler (INV-8) over generated scenarios and assert it always terminates in
  `Quiescent` or `TimeLimitReached`, never deadlocks (all nodes blocked with a
  due event) or livelocks (advancing without progress), and that it yields between
  quanta (no held lock spans a node advance). Pass/fail: every generated scenario
  reaches a terminal result within a deterministic quantum budget. **Guards:** L3
  scheduler. **Enforces:** INV-8 (liveness half).

#### `gate:control-responsive`

- **[HARN-19]** `gate:control-responsive` MUST issue control operations (pause,
  snapshot, fork, inject, query) against a running session and assert each is
  acknowledged within a bounded number of scheduler quanta — possible because the
  scheduler yields at quantum boundaries (INV-8, no long-held locks). The bound is
  measured in **quanta, not wall-clock** (per [HARN-2]). **Guards:** L4 control
  plane. **Enforces:** INV-8 (responsiveness half).

#### `gate:basic-block-coverage`

- **Runs:** an opt-in loaded-QEMU execution that registers the plugin's TB
  translation, execution, and flush callbacks, exports guest PC and block length
  through the versioned coverage ring, and consumes that stream in the engine.
- **Pass/fail:** the observed stream matches the fixed execution corpus, off mode
  registers no callback, and enabling coverage changes neither canonical state nor
  any execution fingerprint. The acceptance projection includes a chained
  SHA-256 execution trajectory over instruction, all-vCPU register, memory/device
  event, RAM-boundary, and RR state; 64-bit rolling hashes remain diagnostics and
  are excluded from acceptance and content addressing. Model-only or
  callback-stub evidence cannot turn the gate green.
- **Guards:** the L2 plugin-to-L3 exploration boundary. **Enforces:** INV-4,
  INV-7, ADV-21, and PLUG-35..PLUG-37.

#### `gate:any-guest`

- **[HARN-6]** `gate:any-guest` MUST boot an unmodified guest fixture matrix
  under sim mode and assert (a) deterministic boot fingerprints for the
  black-box profile(s) claimed by the gate (§4), (b) the on-disk base image is
  byte-unchanged after guest-visible CoW runs (CoW overlays only), and (c) no
  Crucible-placed content is required in-guest for core operation. The initial
  Phase-2 gate covers a generic AOS Linux kernel/initramfs fixture under diskless
  and guest-visible CoW-block launch profiles; broader off-the-shelf guest
  images/kernels are acceptance hardening and must not be claimed until they are
  in the executable matrix. Pass/fail is scoped deterministic boot **and** zero
  base-image mutation **and** no required in-guest agent. **Guards:** L2 boot.
  **Enforces:** INV-5, G-2.

#### `gate:qemu-inert`

- **Runs:** the inertness suite (§10) — build the AOS QEMU package from the same
  patched source and exercise it with sim mode **off**, comparing its observable
  behavior against an unpatched reference build over a behavioral corpus (boot,
  device I/O, migration, snapshot, QMP surface).
- **Pass/fail:** sim-off behavior is identical to the unpatched reference across
  the corpus; the plugin is not loaded and no sim flag is set.
- **Guards:** the AOS QEMU package + patch series. **Enforces:** INV-7, G-7.

#### `gate:abi-conformance`

- **Runs:** the boundary-ABI conformance suite (§8) — compare the live shmem
  layout, guest↔host protocol framing, and control-plane RPC schema against
  frozen golden vectors, and assert version fields match and unknown-version
  handling is correct.
- **Pass/fail:** byte-for-byte match against the golden vectors for the current
  ABI version; intentional ABI changes require a version bump + regenerated
  golden vectors in the same PR.
- **Guards:** L1 boundary ABIs. **Enforces:** G-8.

#### `gate:patch-microtests`

- **Runs:** each QEMU patch's focused micro-test (§10), aggregated.
- **Pass/fail:** every patch in the series has at least one passing micro-test
  that exercises exactly the behavior the patch adds and fails on stock QEMU.
- **Guards:** the patch series, per-patch. **Enforces:** INV-7 (each patch is
  individually justified and tested; see also the per-patch gates in
  [`11-qemu-patches.md`](11-qemu-patches.md)).

#### `gate:adversarial-determinism`

- **Runs:** the adversarial determinism suite (§7) — run a fixed scenario `N`
  times under deliberately hostile host conditions (randomized host thread
  scheduling, wall-clock jitter, varied host core counts, induced I/O stalls) and
  compare canonical event logs and fingerprints.
- **Pass/fail:** all `N` canonical logs and final fingerprints are byte-identical.
- **Guards:** cross-layer, once L2 exists. **Enforces:** INV-1, INV-4, INV-9 (the
  determinism that *survives* hostile conditions).

#### `gate:e2e-determinism`

- **Runs:** the end-to-end acceptance scenario (§11) — a representative multi-VM,
  fault-injected scenario run under the adversarial conditions of
  `gate:adversarial-determinism`, plus a reproduction step that re-runs from the
  emitted artifact on a *different* machine profile.
- **Pass/fail:** bit-identical canonical logs/fingerprints across adversarial
  runs **and** bit-identical reproduction from the artifact.
- **Guards:** final acceptance; the terminal Phase 7 final-acceptance
  determinism gate
  ([`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md)
  §Acceptance). **Enforces:** the whole headline contract.

---

## 2. The layered test strategy

Crucible is layered L0–L4 ([`27-crate-structure.md`](27-crate-structure.md)).
Each layer has its **own** determinism gate that must be green before anything is
built on top of it ([G-5]). This section spells out *what is tested at each layer
and how*; the gate names above bind to it.

- **[HARN-3]** Each layer L0–L4 MUST have a determinism gate that is green before
  any higher layer's tests are allowed to run in the phase plan. A higher-layer
  test MUST NOT be used to "cover" a lower-layer determinism property; the lower
  layer's gate owns it. (This is the testing-side expression of [PLAN-4].)

```text
  L4  control plane     gate:control-responsive   — ops acked within a quantum bound
                        gate:scheduler-liveness*   — (*scheduler is L3 but the actor
                                                     boundary is exercised from L4)
  L3  engine            gate:replay-oracle         — fat == thin by hash
                        gate:scheduler-liveness    — always terminates, yields
                        gate:content-address       — equal content, equal id
  L2  QEMU integration  gate:single-vm-fingerprint — one VM bit-identical (Contract A)
                        gate:any-guest             — unmodified guest, no mutation
                        gate:qemu-inert            — sim-off == upstream
  L1  co-sim transport  gate:layer1-injection      — injection icount is pure (Contract B)
                        gate:abi-conformance       — shmem/protocol/RPC golden vectors
  L0  deterministic core gate:layer0-determinism   — primitives reduce identically
  ──  cross-cutting     gate:harness-lint, gate:divergence-bisect,
                        gate:adversarial-determinism, gate:e2e-determinism
```

**L0 — deterministic core (`crucible-sim`, `crucible-assert`).** Tested entirely
in-process, no QEMU. The scheduler primitives, the decision RNG, the
content-addressed digest helpers, and the assertion evaluator are driven through
fixed decision sequences and compared by canonical digest. Property tests cover:
decision-RNG stability under entity insertion (the per-entity stream is forked by
name-hash so adding a node does not perturb others — §4.5), total-order stability
of the cross-node event keying `(virtual_time, consumer node_id, producer node_id, sequence)`, and ordered
iteration on every ordering-significant collection. **Gate:**
`gate:layer0-determinism`. Runs in milliseconds.

**L1 — co-sim transport (`crucible-shmem`, `crucible-protocol`,
`crucible-device`).** Tested against the in-process QEMU double (§3): the shmem
region, SPSC frame queues, protocol codec, and I/O sub-nodes are exercised
without real QEMU. Two suites: injection determinism (`gate:layer1-injection`,
INV-3) and ABI conformance (`gate:abi-conformance`, G-8) plus SPSC property tests
and codec/wire fuzzing (§8). **Gate:** `gate:layer1-injection`,
`gate:abi-conformance`, `gate:content-address`.

**L2 — QEMU integration (`crucible-qemu`, `crucible-qemu-plugin`,
`crucible-guest`).** The first layer that requires real QEMU. Single-VM
fingerprint determinism (`gate:single-vm-fingerprint`, Contract A),
unmodified-guest boot and non-mutation (`gate:any-guest`), and patch inertness
(`gate:qemu-inert`, `gate:patch-microtests`). Slower (boots a guest), so the
suite uses small boot-to-ready images and is structured so the cheap in-process
layers catch most regressions first.

**L3 — engine (`crucible`).** The temporal graph, scheduler, faults, assertions.
The replay oracle (`gate:replay-oracle`, INV-1/INV-2) is the headline structural
test; scheduler liveness (`gate:scheduler-liveness`, INV-8) and content
addressing (`gate:content-address`, INV-6) round it out. Most of L3 runs against
the in-process double so the oracle and scheduler are exercised in milliseconds;
a smaller slice runs against real QEMU for fidelity.

**L4 — control plane (`crucible-session`, `crucible-api`, `crucible-daemon`,
`crucible`).** The session actor, API, daemon, and CLI.
`gate:control-responsive` (INV-8 responsiveness) and the API/RPC half of
`gate:abi-conformance`. Tested against the in-process double so a full
session/fork/snapshot/inject API exercise runs without booting a guest.

---

## 3. The in-process QEMU test double

The single biggest stability multiplier in the harness is a **fake plugin-side**
that speaks the same shmem + IPC protocol as the real `crucible-qemu-plugin`
([`12-qemu-plugin.md`](12-qemu-plugin.md)) **without launching real QEMU**. It
lets host orchestration, scheduling, transport, save/restore, fork, and the API
all be tested deterministically in milliseconds rather than the seconds a guest
boot costs. Because almost every higher-layer determinism property is *about how
the host orchestrates nodes*, not about the guest's instruction stream, the
double covers the overwhelming majority of the test surface.

- **[HARN-14]** Crucible MUST provide an in-process QEMU test double (the
  **`SimDouble`**) that implements the *plugin side* of the shmem ABI
  ([`13-shmem-abi.md`](13-shmem-abi.md)) and the IPC protocol
  ([`14-protocol.md`](14-protocol.md)) exactly as the real plugin does, so that
  the host engine cannot distinguish a `SimDouble` node from a real QEMU node
  through those interfaces. The host's node abstraction MUST be defined against
  the ABI/protocol boundary, never against a QEMU-specific type, so the double is
  a drop-in.

### 3.1 What the double models

A `SimDouble` stands in for one VM (or one I/O sub-node) and presents:

- **The shmem region** — the real `#[repr(C)]` layout
  ([`13-shmem-abi.md`](13-shmem-abi.md)): per-node clock cell (icount /
  virtual-time), status word, and the SPSC frame queues. The double reads and
  writes these fields with the same memory ordering the real plugin uses, so the
  host's lock-free producer/consumer logic is exercised against a faithful peer.
- **Virtual-time advancement** — instead of executing guest instructions, the
  double advances its icount cell by a **scripted instruction budget** per
  quantum. A node's behavior is defined by a small program: "consume `k`
  instructions to reach the next horizon, then read inbound frames, then post
  outbound frames at icount `c`." This makes the double's contribution to the
  schedule a pure function of its script + the frames it receives.
- **The IPC protocol** — the double answers the same control messages the real
  plugin does (advance-to-horizon, set time control, snapshot, restore, query
  fingerprint), with the same framing and the same version fields.
- **Device/channel callbacks** — for I/O sub-node doubles, deterministic
  completion events (disk/9p) at scripted icounts, mirroring
  [`15-io-subnodes.md`](15-io-subnodes.md).
- **A synthetic fingerprint** — the double computes an execution fingerprint
  (§4) over its *scripted* state (a running hash of its icount, a small synthetic
  register file, and a synthetic memory region it mutates deterministically) so
  the fingerprint plumbing, the comparison logic, and bisection can all be tested
  against the double.

### 3.2 The double's contract (fidelity requirements)

- **[HARN-15]** The `SimDouble` MUST use the *same* shmem layout structs, the
  *same* SPSC queue implementation, and the *same* protocol codec as the real
  plugin (shared crate, not a re-implementation). Anything bespoke to the double
  MUST be confined to the *behavior generator* (the instruction-budget script and
  synthetic fingerprint), never the wire/memory format. A golden-vector mismatch
  between double and real plugin is an `gate:abi-conformance` failure.

- **[HARN-16]** For any scenario expressible with both real QEMU nodes and
  `SimDouble` nodes (i.e. one whose guest behavior is reducible to an
  instruction-budget script), the **host-observable schedule** — the canonical
  event log restricted to host-side ordering events (frame deliveries, horizon
  advances, I/O completions, snapshots) — MUST be identical whether the node is a
  double or real QEMU. This is the property that makes the double a *faithful*
  stand-in and is asserted by a cross-check suite in CI.

- **[HARN-17]** The double MUST be deterministic under [HARN-2]: its scripted
  advancement and synthetic fingerprint MUST be pure functions of its script and
  its received frames, with no host wall-clock, thread RNG, or unordered
  iteration. The double therefore participates in `gate:harness-lint` like any
  engine code.

### 3.3 What the double makes cheap to test

```text
  property under test                tested via SimDouble?   why
  ─────────────────────────────────  ─────────────────────  ───────────────────────
  scheduler quantum ordering         yes                     pure host logic
  cross-node injection icount        yes                     INV-3 is host-side
  SPSC queue correctness             yes                     real queue impl
  protocol framing / versioning      yes                     real codec
  snapshot / restore round-trip      yes                     host serializes node state
  fork (CoW share with ancestor)     yes                     temporal-graph op
  replay oracle (fat == thin)        yes                     re-reduce double's script
  control-plane responsiveness       yes                     no boot needed
  per-VM instruction determinism     NO — needs real QEMU    Contract A is intrinsic
  guest non-mutation                 NO — needs real QEMU    on-disk image behavior
  patch inertness                    NO — needs real QEMU    QEMU behavior
```

The rule of thumb: anything whose determinism lives in the *host's orchestration*
is tested against the double in milliseconds; only the three intrinsic-QEMU
properties (Contract A instruction determinism, guest non-mutation, patch
inertness/inertness) require booting real QEMU. This keeps the inner CI loop fast
and the slow loop small. Forward refs: [`12-qemu-plugin.md`](12-qemu-plugin.md),
[`13-shmem-abi.md`](13-shmem-abi.md), [`14-protocol.md`](14-protocol.md).

---

## 4. The execution fingerprint

Comparing two runs by their full instruction streams is correct but expensive.
The **execution fingerprint** is a cheap, deterministic digest taken *periodically*
so divergence is detected with bounded extra cost and localized with bisection
(§5). It is the workhorse behind `gate:single-vm-fingerprint` and the per-node
half of `gate:adversarial-determinism`. Forward ref:
[`04-determinism-contract.md`](04-determinism-contract.md).

### 4.1 What a fingerprint sample contains

- **[HARN-4]** A single-VM execution fingerprint sample MUST be a content hash
  over, at minimum: (a) the node's current **icount**, (b) the architectural
  **register file** (GPRs, flags, IP/PC, segment/control registers relevant to
  the ISA), and (c) a hash of **memory** — either the full guest RAM rolled into
  the digest at coarse cadence, or a configured set of memory regions at fine
  cadence. The sampled set MUST be fixed for a given run configuration so two runs
  sample identically.

```text
  FingerprintSample {
    icount:        u64,          // QEMU executed-instruction count at sample
    regs_hash:     Hash,         // hash of the architectural register file
    mem_hash:      Hash,         // hash of guest RAM or configured regions
    seq:           u64,          // monotonically increasing sample index
  }
  // The run fingerprint is the rolling hash:
  //   fp_0 = H(seed_tag)
  //   fp_n = H(fp_{n-1} || sample_n)
```

- **[HARN-7]** Fingerprint sampling MUST be driven by **icount**, never by host
  wall-clock: a sample is taken every `period` instructions (and at well-defined
  event boundaries — horizon advances, frame deliveries, faults) so the sample
  *positions* are themselves deterministic. Sampling MUST NOT perturb the guest's
  instruction stream (it is observation-only, via QMP / the plugin's read-only
  hooks). The sampled values are obtained through the plugin
  ([`12-qemu-plugin.md`](12-qemu-plugin.md)) or QMP and are observational entries
  ([`19-observability-event-log.md`](19-observability-event-log.md) distinguishes
  observational from canonical).

### 4.2 How the fingerprint is used

- A run produces a **fingerprint stream**: the ordered sequence of samples, plus
  the rolling run fingerprint. Two runs are bit-identical iff their fingerprint
  streams are identical.
- The full memory hash is taken at a coarse cadence (e.g. at each horizon or
  every `M` samples) to bound cost; register + icount are taken at the fine
  cadence. The cadences are part of the run config and recorded in the artifact.

### 4.3 Testing Contract A (single-VM) with the fingerprint

- **[HARN-5]** `gate:single-vm-fingerprint` MUST boot one unmodified guest under
  sim mode twice with a fixed `(image, kernel cmdline, seed, injected-input
  sequence)` and assert the two fingerprint streams are byte-identical, including
  identical final icount. A mismatch MUST fail the gate and emit both fingerprint
  streams plus the divergence-bisection result (§5).

### 4.4 Testing Contract B (multi-VM injection) with the fingerprint

- **[HARN-8]** `gate:layer1-injection` MUST assert Contract B: for a multi-node
  scenario, the **icount at which each external input is delivered to a receiving
  node** is a pure function of `(virtual_time, consumer node_id, producer node_id, sequence)` and is
  independent of host thread interleaving. The gate drives the scenario against
  the in-process double (§3) under multiple host interleavings (§7) and asserts
  identical **observed-injection-icount vectors** — i.e. for each delivered
  frame, the receiver's icount at the instant of observation is the same in every
  interleaving. Combined with Contract A (each VM's stream is intrinsically
  deterministic), this gives whole-system instruction-level determinism (INV-3 +
  INV-4).

### 4.5 Decision RNG stability (supporting property)

- **[HARN-31]** Fingerprint and injection determinism both rest on the decision
  RNG being **order-independent**: per-entity RNG streams MUST be derived by
  forking from the seed by entity name-hash (so adding or renaming a node does not
  perturb other nodes' streams), and this property MUST be a property test in the
  L0 suite (`gate:layer0-determinism`). See
  [`04-determinism-contract.md`](04-determinism-contract.md) and
  [`08-scheduling.md`](08-scheduling.md) for the decision model.

---

## 5. Divergence bisection

When two runs diverge, the harness must answer *where first* — not "the logs
differ somewhere." Divergence bisection is the tool that, given two diverging
runs, **localizes the first differing decision/instruction** and dumps both VMs'
state there. This is what makes INV-10 ("localize, never smooth over") real and
turns "hunt down new nondeterminism" from days into minutes. Gate:
`gate:divergence-bisect`.

- **[HARN-9]** Given two runs of the same `(ScenarioDef, seed, Schedule)` that
  produce different fingerprint streams, the bisection tool MUST report the
  **first** sample index at which they differ and, by refining within that
  fingerprint window, the **first differing instruction (icount)** and the
  responsible node. It MUST then emit a **both-sides state dump** at that point:
  icount, full register file, the differing memory region(s), and the last `N`
  canonical events leading up to it on each side.

### 5.1 Algorithm

```text
  bisect(run_a, run_b):
    # 1. Coarse: walk the two fingerprint streams in lock-step.
    find smallest seq s where sample_a[s].rolling_fp != sample_b[s].rolling_fp
    if none: runs are identical (or differ only after the shorter ends) -> report
    window = [ sample[s-1].icount , sample[s].icount ]   # divergence is in here

    # 2. Fine: binary-search the icount window by re-running each side to a
    #    target icount and sampling a full fingerprint there. Because each run
    #    is deterministic and resumable from a checkpoint (one execution model,
    #    instantiate), re-running to an arbitrary icount is cheap and exact.
    lo, hi = window
    while hi - lo > 1:
      mid = (lo + hi) / 2
      fp_a = resume(run_a, to_icount=mid).fingerprint()
      fp_b = resume(run_b, to_icount=mid).fingerprint()
      if fp_a == fp_b: lo = mid else: hi = mid
    first_diff_icount = hi

    # 3. Dump: resume both sides to lo (last-agreeing) and to first_diff_icount,
    #    diff register files and memory, attach last-N canonical events.
    emit DivergenceReport { node, first_diff_icount, regs_diff, mem_diff,
                            last_events_a, last_events_b }
```

The binary search relies directly on the one-execution-model property ([G-4]):
because `instantiate` can produce a runnable state at any icount by resuming from
the nearest checkpoint and replaying, the bisection can re-evaluate either run at
an arbitrary point without re-running from boot.

- **[HARN-10]** Bisection MUST be a pure function of the two runs' artifacts (no
  host-timing dependence) and MUST itself be deterministic: re-running bisection
  on the same pair MUST report the same first-divergence point. The
  `gate:divergence-bisect` check seeds a *known* divergence (inject a single
  fault into one of two identical runs at a known icount) and asserts the tool
  reports exactly that icount/node.

---

## 6. The replay oracle as a structural test

The replay oracle is the structural correctness check of the temporal graph
(INV-2): a **fat** checkpoint (materialized snapshot) MUST hash equal to its
**thin** derivation (the same checkpoint reconstructed by re-reducing from any
ancestor along the same schedule). It is an invariant of the *data model*, so it
is testable cheaply and continuously. Gate: `gate:replay-oracle`. Forward refs:
[`05-execution-model.md`](05-execution-model.md),
[`07-temporal-graph.md`](07-temporal-graph.md).

- **[HARN-12]** `gate:replay-oracle` MUST, for each checkpoint in a corpus,
  compute (a) `hash(materialize(fat_checkpoint))` and (b)
  `hash(reduce(ScenarioDef, Schedule[0..t]))` reconstructed from an ancestor, and
  assert they are equal. The hash MUST be over the *canonical* state
  (architectural state + device overlays + scheduler state + canonical log
  prefix), excluding observational entries
  ([`19-observability-event-log.md`](19-observability-event-log.md)).

- **[HARN-13]** The oracle MUST run both **deterministically in CI** over a fixed
  checkpoint corpus and **randomly during state-space search / fuzzing**: each
  time the search materializes a fat checkpoint, it MUST (at a configurable
  sampling rate) also reconstruct it thin and compare, so the invariant is
  continuously exercised on real explored states, not just the curated corpus. A
  mismatch is a hard failure and triggers bisection (§5) between the fat and thin
  reconstructions. Forward ref: state-space search and fuzzing in
  [`22-advanced-features.md`](22-advanced-features.md).

Because the oracle is exercised against the in-process double (§3), the bulk of
the corpus runs in milliseconds: the double's "instruction stream" is its script,
so reducing-from-ancestor is fast and exact.

---

## 7. Adversarial determinism testing

Determinism that holds only when the host happens to be quiet is not real
determinism. The adversarial suite runs a fixed scenario `N` times under
deliberately **hostile** host conditions and requires byte-identical canonical
event logs and fingerprints. Gate: `gate:adversarial-determinism`.

- **[HARN-11]** `gate:adversarial-determinism` MUST run each scenario in its
  corpus under a matrix of hostile host conditions and assert byte-identical
  **canonical** event logs and final fingerprints across all of them. The
  hostile conditions MUST include at least:
  - **Randomized host thread scheduling** — vary executor worker counts and inject
    randomized yields / priority perturbation so the host interleaves node
    advancement differently each run.
  - **Wall-clock jitter** — perturb host wall-clock readings (skew, coarsen,
    advance non-monotonically within allowed bounds) to surface any accidental
    dependence on real time; a determinism leak here fails loudly per INV-10.
  - **Varied host core counts** — run on 1, 2, and many cores; parallelism up to
    the lookahead budget MUST NOT change the result.
  - **Induced I/O stalls** — delay host-side I/O (snapshot writes, store reads) to
    decouple host timing from virtual timing.

  The *canonical* log is compared (observational entries are excluded by schema,
  not by a flag — [`19-observability-event-log.md`](19-observability-event-log.md)).
  Any difference fails the gate and is fed to bisection (§5).

This suite is where most real nondeterminism leaks are caught, because it is the
only one that actively *tries* to break determinism rather than passively
comparing two quiet runs. It runs against both the in-process double (fast,
broad) and a small real-QEMU slice (fidelity).

---

## 8. ABI conformance + fuzzing

The three boundary ABIs — the shared-memory layout, the guest↔host protocol, and
the control-plane RPC — are versioned data contracts ([G-8]) and are guarded by
golden vectors plus property/fuzz testing. Gates: `gate:abi-conformance`,
`gate:content-address`. Forward refs: [`13-shmem-abi.md`](13-shmem-abi.md),
[`14-protocol.md`](14-protocol.md), [`16-guest-host-channel.md`](16-guest-host-channel.md),
[`21-api.md`](21-api.md).

### 8.1 Golden vectors

- **[HARN-32]** Each boundary ABI MUST have a **frozen golden-vector** corpus
  checked into the repo: a set of canonical encodings (the shmem region byte
  layout for representative state, encoded protocol frames, encoded RPC
  messages). `gate:abi-conformance` MUST encode the same logical values and
  compare byte-for-byte against the golden vectors, and MUST verify the version
  field. An intentional ABI change MUST bump the version and regenerate the golden
  vectors in the same change (so a silent layout drift fails CI).

### 8.2 SPSC queue property tests

- **[HARN-33]** The single-producer/single-consumer frame queue
  ([`13-shmem-abi.md`](13-shmem-abi.md)) MUST be covered by concurrency property
  tests using a model checker for memory orderings (loom-style exhaustive
  interleaving) and randomized property tests (proptest-style): no lost frame, no
  duplicated frame, FIFO order preserved, correct full/empty behavior, and
  correct behavior under wraparound. These tests run in-process (no QEMU) and are
  part of the L1 gate set.

### 8.3 Codec and wire fuzzing

- **[HARN-34]** The protocol codec and the 9p/blk wire handlers
  ([`15-io-subnodes.md`](15-io-subnodes.md)) MUST be fuzzed: a structure-aware
  fuzzer feeds malformed and adversarial inputs and asserts the decoder never
  panics, never reads out of bounds, and either decodes deterministically or
  rejects cleanly. A round-trip property (`decode(encode(x)) == x`) MUST hold for
  all well-formed inputs. Fuzz findings are added to the regression corpus.

---

## 9. The harness self-determinism lint

Crucible's own host code must be deterministic (INV-9). The cheapest, broadest
defense is a static lint that **bans the constructs that introduce ordering
nondeterminism** before they ever reach a runtime test. Gate: `gate:harness-lint`.
Forward ref: [`28-engineering-standards.md`](28-engineering-standards.md).

- **[HARN-24]** `gate:harness-lint` MUST run on all `crucible-*` crates on every
  PR and MUST fail on any of:
  - **Unordered map iteration on an ordering-significant path** — iterating a
    `HashMap`/`HashSet` (or any hash-ordered container) where the iteration order
    affects engine state, the schedule, or the canonical log. Ordered containers
    (`BTreeMap`/`BTreeSet`/`IndexMap` with a fixed order) MUST be used instead.
  - **Host wall-clock in the engine** — `std::time::Instant::now` /
    `SystemTime::now` (or equivalents) on any path that influences `State`.
    Wall-clock is permitted only for observational logging, behind a type that
    cannot feed canonical state.
  - **Thread / global RNG in the engine** — `rand::thread_rng`, `getrandom`, and
    similar; all randomness MUST come from the seeded decision RNG.
  - **Unordered `select`** — a `select`/`select!` whose branch choice on
    simultaneous readiness is nondeterministic on an ordering-significant path; a
    deterministic, priority-ordered selection MUST be used.

- **[HARN-25]** The lint MUST be enforced (not advisory): a finding fails the
  gate. Where a construct is legitimately safe (e.g. a `HashMap` whose iteration
  order never escapes), the exception MUST be explicit and annotated (a documented
  allow with rationale), so every use is either banned or justified — never
  silently tolerated.

- **[HARN-26]** Because no lint catches everything, `gate:harness-lint` is the
  *first* line of defense and is backed by the runtime gates
  (`gate:layer0-determinism`, `gate:adversarial-determinism`) as the second line:
  a determinism leak the lint misses MUST still be caught at runtime and localized
  by bisection (§5). The combination — ban at compile time, detect at runtime,
  localize on detection — is the INV-9/INV-10 defense in depth.

---

## 10. QEMU patch micro-tests + inertness gate

The AOS QEMU package is patched to support sim mode, but those patches MUST be
**inert** unless sim mode is active (INV-7), and each patch MUST be individually
justified by a focused test. Gates: `gate:qemu-inert`, `gate:patch-microtests`.
Forward ref: [`11-qemu-patches.md`](11-qemu-patches.md).

- **[HARN-20]** Every patch in the QEMU patch series MUST have a focused
  micro-test that (a) exercises exactly the behavior the patch adds (with sim mode
  on) and (b) demonstrates that the behavior is absent on stock/unpatched QEMU.
  `gate:patch-microtests` aggregates these; the patch series is not allowed to
  grow a patch without a corresponding micro-test (per-patch gates are also
  enumerated in [`11-qemu-patches.md`](11-qemu-patches.md)).

- **[HARN-21]** `gate:qemu-inert` MUST demonstrate that the AOS QEMU built from
  the patched source, run with **sim mode off** (plugin not loaded, no sim
  flags), is behaviorally identical to an unpatched reference build across a
  behavioral corpus (boot a stock image, device I/O, snapshot/restore, migration
  surface, the QMP command set). Pass/fail is identical observable behavior; any
  difference is a violation of INV-7 and blocks the AOS QEMU package from shipping.
  This is what lets AOS use one QEMU for both production and simulation (G-7).

The inertness corpus is hermetic and from-source per AOS build principles: the
reference build, the patched build, and the test guest images are all built in the
AOS build system, no upstream binaries.

---

## 11. The end-to-end determinism gate

`gate:e2e-determinism` is the **final acceptance determinism gate** (part of the
terminal Phase 7 gate set, [`01-goals-nongoals-invariants.md`](01-goals-nongoals-invariants.md)
§Acceptance). It is the only gate that exercises the whole system end to end and
is the concrete meaning of "Crucible is deterministic to this RFC."

- **[HARN-22]** `gate:e2e-determinism` MUST run a **representative multi-VM,
  fault-injected scenario** (several VM nodes + I/O sub-nodes, a fault plan
  exercising partition/loss/latency/crash, and a property set with always /
  eventually / sometimes assertions) under the adversarial host conditions of
  `gate:adversarial-determinism` (§7) and assert that all runs produce
  byte-identical canonical event logs and final fingerprints. This is the
  whole-system expression of INV-1/INV-3/INV-4.

- **[HARN-23]** `gate:e2e-determinism` MUST additionally emit a **reproduction
  artifact** (§12) from one run and re-execute the scenario from that artifact on
  a *different machine profile* (different core count, different host scheduling),
  asserting the reproduction is byte-identical to the original. A scenario that
  passes the adversarial comparison but cannot be reproduced from its artifact
  fails the gate.

---

## 12. Reproduction artifacts

A failure is only useful if it reproduces. Every failing run MUST emit a
**self-contained reproduction artifact** that reproduces the run bit-identically
on another machine. This is the concrete form of [G-6] ("reproduce-then-explore")
and the input to bisection (§5). Forward refs:
[`06-spatial-graph.md`](06-spatial-graph.md), [`23-cli.md`](23-cli.md).

- **[HARN-27]** Any gate failure (and any explicit user request) MUST be able to
  emit a reproduction artifact that is the self-contained tuple **`(seed,
  ScenarioDef, Schedule)`** — the root seed, the content-addressed scenario
  definition (or its content hashes plus a way to resolve them hermetically), and
  the totally-ordered schedule of decisions — sufficient to reproduce the run
  bit-identically with no other input.

```text
  ReproArtifact {
    crucible_version:  SemVer,        // engine + ABI versions (G-8)
    qemu_build_id:     Hash,          // the AOS QEMU package identity
    seed:              u64,           // root entropy (INV-1)
    scenario_hash:     Hash,          // content id of the ScenarioDef (INV-6)
    schedule:          [Decision],    // the totally-ordered decisions (INV-3)
    fingerprint_tail:  [Sample],      // last-N fingerprints for fast triage
    sampling_config:   { fine, coarse, regions },  // so fingerprints align
  }
```

- **[HARN-28]** Reproduction MUST be **machine-independent**: re-running from a
  reproduction artifact on a different host (different core count, scheduler,
  wall-clock) MUST produce a byte-identical canonical log and fingerprint stream.
  The artifact MUST pin the engine/ABI versions and the AOS QEMU build identity so
  a reproduction that would silently use a different binary fails loudly rather
  than reproducing something else. This is asserted directly by [HARN-23] within
  `gate:e2e-determinism`.

- **[HARN-29]** A reproduction artifact MUST be **content-addressed and small**:
  it references scenario components and (where useful) checkpoints by content hash
  (INV-6) rather than embedding them, so artifacts are cheap to store, attach to a
  failing CI run, and share. The CLI surfaces produce/reproduce
  ([`23-cli.md`](23-cli.md)); the schedule and seed are the only run-specific data
  that must travel.

---

## 13. How the gates compose into the phase plan

The gates are layered exactly as the system is, and the phase plan
([`32-implementation-plan.md`](32-implementation-plan.md)) orders the foundation
first ([G-5], [PLAN-4]). Phase 0 additionally has the non-catalog
`phase0:blockers` spike aggregate described by [`30-risks-spikes.md`](30-risks-spikes.md)
and [`32-implementation-plan.md`](32-implementation-plan.md):

```text
  phase0  phase0:blockers                    (S1/S2/S4/S3 plus S11 for G-10)
  phase0  gate:harness-lint                  (every PR, always on)
  phase1  gate:harness-lint                  (first phase exit gate)
  phase1  gate:license-boundary               (component and process boundary)
  phase1  gate:layer0-determinism            (L0 core)
  phase1  gate:content-address               (store)
  phase1  gate:replay-oracle                 (double-backed replay)
  phase1  gate:single-vm-fingerprint         (double-backed fingerprint)
  phase1  gate:divergence-bisect             (diagnostic, exercised on doubles)
  phase2  gate:abi-conformance               (L1 ABIs)
  phase2  gate:layer1-injection              (L1 injection preflight)
  phase2  gate:patch-microtests              (patch series)
  phase2  gate:qemu-inert                    (sim-off QEMU behavior)
  phase2  gate:single-vm-fingerprint         (Contract A, real QEMU)
  phase2  gate:any-guest                     (unmodified guest)
  phase3  gate:layer1-injection              (Contract B)
  phase3  gate:scheduler-liveness            (scheduler actor)
  phase3  gate:adversarial-determinism       (modeled hostile-condition matrix)
  phase4  gate:replay-oracle                 (full temporal graph)
  phase4  gate:e2e-determinism               (mock backend)
  phase5  gate:control-responsive            (control plane)
  phase6  gate:replay-oracle                 (active search)
  phase6  gate:basic-block-coverage           (loaded-QEMU coverage boundary)
  phase7  gate:perf-bench                    (performance regression)
  phase7  gate:e2e-determinism               (final acceptance)
  phase7  gate:fleet-equivalence             (distributed equivalence)
  phase7  gate:campaign-continuity           (coverage ratchet)
  phase7  gate:signal-fault-system           (complete signal fault system)
```

- **[HARN-30]** A phase's gate(s) MUST be green before the next phase's tasks are
  worked, and `gate:signal-fault-system` MUST remain the terminal Phase 7 gate,
  after `gate:e2e-determinism` and the other production acceptance gates. The in-process double (§3) is what makes the Phase 1 foundation and
  Phase 4 mock end-to-end checks fast enough to iterate on, and must therefore
  be built in Phase 1 before the layers that depend on it.

---

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md); these are the tasks
> whose primary area is this file, tracked by [PLAN-3]. They are
> **Phase-1-and-earlier foundation tasks**: the harness comes first.

- [x] **T-HARN-1** Define the canonical gate catalog as CI targets (one target
  per gate name in §1.1) and wire them into the phase plan; add the doc-lint that
  fails on any referenced-but-undefined or defined-but-unreferenced gate. —
  satisfies [HARN-1], [HARN-2]; spec §1.
- [x] **T-HARN-2** Implement `gate:harness-lint`: the custom static analysis +
  curated lint set banning unordered map iteration on ordered paths, host
  wall-clock/thread-RNG in the engine, and unordered `select`; enforce on all
  `crucible-*` crates on every PR. — satisfies [HARN-24], [HARN-25], [HARN-26];
  spec §9.
- [x] **T-HARN-3** Build the in-process QEMU test double (`SimDouble`): plugin-side
  shmem ABI + IPC protocol, instruction-budget behavior generator, synthetic
  fingerprint; share the real shmem/queue/codec crates. — satisfies [HARN-14],
  [HARN-15], [HARN-17]; spec §3.
  - Completed by `crucible::SimDouble` and
    `checks.crucible.phase1.simDouble`: the double is compiled behind the
    `test-double` feature, enables the shared `crucible-shmem` and
    `crucible-protocol` crates only for that feature, builds its plugin-side
    region from the canonical `RegionAllocation` model, drains and emits frames
    through the real directed SPSC accessors, accepts host control frames through
    the real protocol decoder and lifecycle validator, replies with real
    plugin-frame encodings, validates setup against the shared shmem header
    checks, respects the same lookahead delivery ceiling rule as the QEMU
    quantum path, drains inbound frames by the canonical `(delivery_icount,
    src_node, seq)` key, advances by a deterministic instruction-budget script,
    and hashes a synthetic register/memory fingerprint with no wall-clock,
    thread RNG, or unordered map dependency.
- [x] **T-HARN-4** Implement the double↔real-plugin host-observable-schedule
  cross-check suite. — satisfies [HARN-16]; spec §3.2.
  - Completed by `checks.crucible.phase1.hostObservableSchedule` and
    `checks.crucible.phase2.qemuLivePluginQuantum`. The
    `host_observable_schedule_cross_checks_sim_double_against_plugin_projection`
    unit test proves the callback-model half: `crucible::SimDouble` records a
    typed host-observable schedule vocabulary for horizon advances, inbound
    SPSC frame deliveries, outbound SPSC frame emissions, I/O completions, and
    snapshots; the QEMU plugin test constructs the matching callback-model
    projection through
    `PluginIdleHotLoop`, `PluginVirtualClock`, `PluginNetworkRx`, and
    `PluginNetworkTx` before asserting byte-for-byte schedule equality, with the
    plugin-to-engine dependency documented as a test-only HARN-16 cross-check.
    The installed production plugin gate records every completed busy, idle,
    and idle-jump quantum in that same typed vocabulary, requires the host-load
    run to reproduce the schedule exactly, builds a `SimInstructionScript` from
    the live reached-icount sequence, replays the exact requested horizons
    through `SimDouble`, and compares the versioned, length-prefixed canonical
    schedule bytes. The live gate fails on a backward step, unsupported event,
    outcome mismatch, setup failure, or first byte-level schedule difference.
- [x] **T-HARN-5** Implement the L0 determinism suite and `gate:layer0-determinism`
  (twice-reduce digest compare + scheduler-ordering and decision-RNG-stability
  property tests). — satisfies [HARN-3], [HARN-31]; spec §2, §4.5.
- [x] **T-HARN-6** Implement the execution fingerprint (icount + register +
  memory-region rolling hash) with icount-driven, observation-only sampling via
  plugin/QMP. — satisfies [HARN-4], [HARN-7]; spec §4.
  - Completed by `checks.crucible.phase2.qemuLivePluginFingerprint`: the live
    Rust plugin samples all-vCPU registers, the RR cursor, writable RAM, and
    non-RAM VMState at fixed cadence boundaries plus a frame delivered through
    the production inbound ring and a fault applied through the production
    preemption mailbox. Every event is acknowledged before its sample is
    accepted.
- [x] **T-HARN-7** Implement `gate:single-vm-fingerprint` (Contract A: boot one
  unmodified guest twice, compare fingerprint streams; on mismatch emit streams +
  bisection result). — satisfies [HARN-5]; spec §4.3.
  - Completed by the same live gate. The ordinary pass boots one unmodified
    fixed guest twice and proves identical streams under second-run host load.
    The negative-control pass forces a real QEMU divergence, performs
    ordinal-aware RESTART refinement to the exact first differing instruction,
    and emits both sides' complete architectural register bytes, paired
    differing RAM ranges, complete non-RAM VMState, and a stable dump content
    address. Snapshot restore remains policy-disabled.
- [x] **T-HARN-8** Implement `gate:layer1-injection` (Contract B: identical
  observed-injection-icount vectors across host interleavings, against the
  double). — satisfies [HARN-8]; spec §4.4.
- [x] **T-HARN-9** Implement the divergence-bisection tool (coarse fingerprint
  walk → fine icount binary search via resume → both-sides state dump). —
  satisfies [HARN-9], [HARN-10]; spec §5.
- [x] **T-HARN-10** Implement `gate:divergence-bisect` (seed a known divergence;
  assert the tool localizes exactly that icount/node, deterministically). —
  satisfies [HARN-10]; spec §5.1.
- [x] **T-HARN-11** Implement `gate:content-address` (hash stability, equal
  content ⇒ equal id, single-byte change ⇒ different id, collision sampling). —
  satisfies [HARN-11]; spec §1.2.
- [x] **T-HARN-12** Implement the replay oracle and `gate:replay-oracle`
  (fat-hash == thin-from-ancestor-hash over a fixed corpus, canonical-state hash
  excluding observational entries). — satisfies [HARN-12]; spec §6.
- [x] **T-HARN-13** Wire random in-search oracle sampling: each materialized fat
  checkpoint is also reconstructed thin and compared at a configurable rate during
  search/fuzzing; mismatch triggers bisection. — satisfies [HARN-13]; spec §6.
  Completed by `crucible_harness::replay_oracle`'s `ReplayOracleSamplingConfig`,
  `ReplayOracleSearchMaterialization`, `ReplayOracleSearchSamplingReport`,
  `check_sampled_search_replay_oracle`, `SearchReplayOracleSamplingConfig`,
  `TemporalGraph::search_with_replay_oracle_sampling`,
  `EngineError::SearchReplayOracleMismatch`,
  `check_sampled_search_replay_oracle_with_bisection`,
  `checks.crucible.phase1.gates.replayOracle`, and
  `checks.crucible.phase1.gates.divergenceBisect`: active graph search samples
  actual fat materializations inline, reconstructs each selected checkpoint
  through thin replay, compares the canonical fat/thin case at the configured
  deterministic sampling rate, rejects invalid rates, and surfaces sampled
  mismatches as hard failures with bisection requests; the divergence gate
  localizes the sampled fat/thin mismatch to an exact icount/decision when
  diagnostic streams are available.
- [x] **T-HARN-14** Implement `gate:scheduler-liveness` (every generated scenario
  reaches Quiescent/TimeLimitReached within a quantum budget; no held lock spans a
  node advance). — satisfies [HARN-18]; spec §1.2.
- [x] **T-HARN-15** Implement `gate:control-responsive` (control ops acked within
  a bounded number of quanta against a running session, measured in quanta not
  wall-clock). — satisfies [HARN-19]; spec §1.2.
  Completed by `checks.crucible.phase5.gates.controlResponsive`: the session
  target drives a live running actor and observes snapshot, fork, inject, query,
  and pause acknowledgements within one post-request quantum; the test also
  verifies that snapshot, fork, inject, and query reach `QuantumRequest.control`
  before their acknowledgements are published, while pause is acknowledged as an
  actor boundary state transition. `crucible-api::control_responsive` exposes
  the wall-clock-free
  `ControlResponsiveSessionProbe` route and rejects non-running, missing,
  rejected, backward, or over-bound evidence. The daemon target issues through
  `DaemonControlResponsiveRoute` and validates the same API contract; the
  canonical gate catalog plus gate-target map now mark the session, API, and
  daemon `gate_control_responsive` targets implemented.
- [x] **T-HARN-16** Implement the initial `gate:any-guest` executable matrix (one
  unmodified generic AOS Linux fixture across diskless and guest-visible
  CoW-block launch profiles; diskless boot fingerprints deterministic; CoW base
  image byte-unchanged; no required in-guest agent). — satisfies the initial
  scoped [HARN-6] gate, [G-2]; spec §1.2.
  Completed by `checks.crucible.phase2.gates.anyGuest`: a generic AOS Linux
  kernel/initramfs fixture runs under diskless and guest-visible CoW-block launch
  profiles twice on real QEMU with the host-side trace plugin, the diskless cadence fingerprint streams match exactly
  through the host QMP-quit window after a generic serial completion marker, both
  CoW traces pass structural validation while the profile writes through
  `/dev/vda` and leaves the copied base image byte-identical, and the optional
  white-box path is consumed as a separate unused, non-perturbing host/plugin
  contract. Broader off-the-shelf guest image coverage remains outside this
  completed initial matrix.
- [x] **T-HARN-17** Freeze the boundary-ABI golden vectors (shmem layout,
  protocol frames, RPC messages) and implement `gate:abi-conformance` with version
  checks and the bump-on-change rule. — satisfies [HARN-32], [G-8]; spec §8.1.
  Completed by `checks.crucible.phase2.gates.abiConformance`: the gate aggregates
  the shmem generated-header/layout fixture, protocol frame golden vectors, and
  the RPC golden-vector corpus, with explicit version constants, byte-for-byte
  live encoder comparisons, and typed RPC major-mismatch rejection. The full API
  reference-client lifecycle conformance suite remains T-API-13.
- [x] **T-HARN-18** Implement the SPSC queue concurrency model-checker + property
  tests (no loss/dup, FIFO, full/empty, wraparound). — satisfies [HARN-33];
  spec §8.2.
- [x] **T-HARN-19** Implement the protocol-codec and 9p/blk wire fuzzers with the
  round-trip property and a regression corpus. — satisfies [HARN-34]; spec §8.3.
  Completed by `checks.crucible.phase2.protocolCodecFuzz`: the gate now runs the
  existing structure-aware `crucible-protocol::codec_fuzz` target plus the
  `crucible-qemu-plugin::io_wire_fuzz` target, both through
  `gate:abi-conformance`. The I/O target carries a seeded regression corpus for
  malformed/adversarial block request payloads, block response payloads, and raw
  9p message envelopes; asserts no panic through `catch_unwind`; checks
  channel-specific typed rejection or deterministic decode; enforces a fixed
  negotiated 9p `msize`; emits a well-formed synthetic 9p error response for
  arbitrary 9p bytes; and verifies `decode(encode(x)) == x` for generated
  well-formed block requests, block responses, and 9p envelopes. Full 9p
  filesystem semantics and block sub-node execution remain owned by the
  `15-io-subnodes.md` implementation tasks.
- [x] **T-HARN-20** Implement the per-patch QEMU micro-test framework and
  `gate:patch-microtests` (each patch has a focused test absent on stock QEMU). —
  satisfies [HARN-20]; spec §10.
  Completed by `checks.crucible.phase2.gates.patchMicrotests`: every carried
  patch has prefix provenance plus exactly one live drop-one attribution method,
  and the aggregate rejects composition and structural fallback classifications.
- [x] **T-HARN-21** Implement `gate:qemu-inert` (sim-off patched QEMU behaviorally
  identical to an unpatched reference over the behavioral corpus, all from-source).
  — satisfies [HARN-21]; spec §10.
  - Completed by `checks.crucible.phase2.gates.qemuInert`, which builds both QEMU
    variants from the pinned source and compares raw boot/device-I/O serial,
    bound block/9p/virtio-rng execution output, QMP capability/state,
    full-stream migration digests, and concluded snapshot save/load outcomes
    with sim mode off. The curated corpus spans guest execution, device I/O,
    management, transfer, and restore compatibility. Only unordered QMP
    collections and QMP transport metadata are normalized; a marker-projection
    negative control proves raw serial comparison remains authoritative.
- [x] **T-HARN-22** Implement the adversarial host-condition harness (randomized
  host scheduling, wall-clock jitter, varied core counts, induced I/O stalls) and
  `gate:adversarial-determinism` (byte-identical canonical logs/fingerprints). —
  satisfies [HARN-11]; spec §7.
  Completed by `checks.crucible.phase3.gates.adversarialDeterminism`: the gate
  runs a fixed adversarial scenario corpus through the shared
  `canonical_host_adversary_matrix`, covering randomized task order, logical
  affinity, load/yield jitter, varied worker counts, producer/consumer skew, and
  modeled host I/O stalls while asserting byte-identical canonical logs and final
  fingerprints. It also carries negative controls for profile-dependent logs,
  fingerprints, observer output, and empty evidence; shared artifact
  machine-profile reproduction is completed by T-HARN-25. This hostile-profile
  proof is composed with the live-QEMU production fleet run in
  `checks.fleet.crucible-e2e-determinism`, which executes each independent
  reduction through the packaged QEMU/plugin probe before comparing the
  session-level canonical evidence.
- [x] **T-HARN-23** Build the representative multi-VM fault-injected e2e scenario
  and implement `gate:e2e-determinism` (adversarial comparison + cross-machine
  reproduce-from-artifact). — satisfies [HARN-22], [HARN-23]; spec §11.
  Completed by `checks.crucible.phase7.gates.e2eDeterminism` and
  `checks.fleet.crucible-e2e-determinism`: the `crucible-cli` gate target runs
  the representative self-contained e2e artifact
  through the shared harness final-acceptance route, exercises the canonical
  adversarial host profile matrix, verifies byte-identical logs/fingerprints,
  replays from the artifact on different machine profiles, and rejects build
  identity drift and missing cross-machine-profile coverage. The phase4
  scheduler/mock gate remains the lower-layer e2e coverage; this phase7 target
  closes the package-owned final acceptance target for the shared mock artifact
  route without adding new CLI subcommand semantics. The versioned shared
  artifact format and CLI produce/replay seam are completed by T-HARN-24; the
  shared artifact machine-profile verifier is completed by T-HARN-25.
  Production closure evidence is provided by `checks.fleet.crucible-e2e-determinism`,
  which runs every independent reduction with `--backend qemu`, launches the
  closure-owned patched QEMU and production plugin under TCG against the
  AOS-built kernel/root fixture, then requires byte-identical canonical logs
  across the adversarial profile matrix and successful reproduce/bisect
  outcomes. The phase-7 Nix gate is green-before-advance and the fleet check
  consumes its raw result as a required precondition.
- [x] **T-HARN-24** Implement the reproduction-artifact format `(seed,
  ScenarioDef, Schedule)` with pinned engine/ABI/QEMU identities and
  content-addressed component references, plus produce/reproduce wiring into
  failures and the CLI. — satisfies [HARN-27], [HARN-29]; spec §12.
  Completed by `checks.crucible.phase7.reproductionArtifactFormat`:
  `crucible_harness::reproduction` now defines the versioned canonical text
  artifact format with `(seed, ScenarioDef reference, Schedule)`, stable
  `cas:crucible-hash:` component references, inline payload records for small
  self-contained components, pinned engine/artifact/QEMU/plugin identity fields,
  schedule-order and digest validation, canonical encode/decode support, and a
  representative mock e2e producer that carries its ScenarioDef material. The
  `crucible` CLI now validates artifacts through `replay <artifact>` and has a
  failure-artifact writer that emits the artifact plus parseable replay/debug
  command lines. This completes the mock format and CLI validation seam.
  T-HARN-25 adds the shared mock machine-profile verifier and identity-mismatch
  replay failure; BLAKE3/DagStore-backed durable identities and real AOS fleet
  reproduction remain packaging work.
- [x] **T-HARN-25** Implement machine-independent reproduction verification
  (re-run from artifact on a different host profile ⇒ byte-identical) and fail
  loudly on engine/ABI/QEMU identity mismatch. — satisfies [HARN-28]; spec §12.
  Completed by `checks.crucible.phase7.machineIndependentReproduction`:
  `crucible_harness::reproduction` now verifies versioned artifacts by decoding
  canonical `(seed, ScenarioDef reference, Schedule)` bytes, checking the pinned
  engine/artifact/QEMU/plugin identity, loading recorded producer canonical-log
  and final-fingerprint evidence, the source producer artifact digest, and
  recorded decision payloads from content-addressed artifact components,
  recomputing the producer artifact digest from the decoded ScenarioDef payload
  plus recorded decisions/backend identity, replaying through the host-adversary
  fixture on a baseline and at least one different machine profile,
  reconstructing the canonical mock e2e log from the versioned artifact, and
  requiring every replay to match the producer evidence byte-for-byte. The
  `crucible` CLI now rejects replay artifacts whose pinned identity differs
  from the selected local replay identity with exit code 3, including QEMU build
  identity drift. This closes the shared mock artifact machine-profile route;
  physical AOS VM/fleet reproduction remains with the packaging and fleet gates.
- [x] **T-HARN-26** Wire the full gate ordering into the phase plan and enforce
  green-before-advance, with `gate:signal-fault-system` terminal and the `SimDouble`
  available from Phase 1. — satisfies [HARN-3], [HARN-30]; spec §13.
  Completed by `checks.crucible.phase1.phaseGateOrdering`:
  `crucible_harness::phase_plan` now records every ordered phase-gate
  occurrence from §13 separately from the one-row canonical gate catalog,
  including repeated gates such as `gate:replay-oracle` and
  `gate:e2e-determinism`. The model exposes green-before-advance validation by
  Nix attr path, validates the canonical plan against unknown catalog gates,
  duplicate attr paths, out-of-order phases, missing phase exits, bad terminal
  markers, and SimDouble-before-Phase-1 dependencies, and marks the Phase 7
  `gate:signal-fault-system` occurrence as the terminal final-acceptance gate.
  `tests/crucible/default.nix` now wraps gate attrs with
  green-before-advance derivations so later gate occurrences build only after
  prior gate occurrences and the required Phase 1 `SimDouble` check are green.
  The `phase_plan` integration test cross-checks the Rust ordering against this
  section's table and `tests/crucible/default.nix`, proves Phase 1 exposes the
  `SimDouble` check before double-backed Phase 1 and Phase 4 gates depend on it,
  verifies HARN-3 lower-layer-before-higher-layer gate precedences, and carries
  synthetic negative controls for missing terminal e2e, invalid terminal
  placement, early SimDouble dependency, unknown gates, and layer-order drift.
- [x] **T-HARN-27** Remove the self-referential checklist assertion from gate
  checks: a check MUST NOT prove its task by asserting that the task's own
  checkbox is ticked. Checkbox state is bookkeeping and MUST NOT appear in a
  check's evidence set.
  — satisfies [HARN-24], [HARN-25]; spec §7.
  - Defect (audit 2026-07-28): roughly 350 check files under `tests/crucible/`
    assert `- [x] **T-<AREA>-n**` against the RFC for the very task they certify.
    The assertion passes because the task is marked done, so it enforces the
    conclusion rather than the evidence, and it can only fail when someone
    corrects the checklist. This is the mechanism by which a 569/569 checklist
    coexisted with a check tree that did not evaluate.
  - Plan: (1) delete the `- [x] **T-...**` needle from every check that certifies
    that task, keeping needles that assert a *different* task's state only where
    a real ordering dependency exists; (2) replace each with an assertion over
    the artifact the task produces (a symbol, a result line, a gate output);
    (3) add a harness-lint rule rejecting any needle matching `- [x] **T-` in a
    check whose `taskIds` contains that id.
  - Note: the inverse needle (`- [ ] **T-...**`, asserting a task is still open)
    is equally self-referential and is removed by the same rule; the
    `openTaskIds` ledger already records that state.
  - Gate: `gate:harness-lint` fails on any surviving self-referential needle.
  - Completed by `checks.crucible.phase1.gates.harnessLint`: every checklist-state
    evidence assertion was removed from the Nix checks, and the Rust harness lint
    rejects both checked and open task-state needles with a synthetic negative
    control.

- [x] **T-HARN-28** Add a reference-integrity lint over the harness and the RFC:
  every source needle MUST resolve in the file it names, every
  `checks.crucible.*` attribute named in prose MUST exist, and every count
  asserted in prose MUST match its source of truth.
  — satisfies [HARN-24], [HARN-26]; spec §7.
  - Defect (audit 2026-07-28): needles silently rot when code moves. After the
    white-box doorbell tests moved from
    `crucible-qemu-plugin/src/whitebox_doorbell.rs` to
    `whitebox_doorbell/tests.rs`, eighteen needles in
    `phase4-guest-host-channel-determinism.nix` and
    `phase4-guest-host-app-random-doorbell.nix` kept naming the parent file;
    both checks now throw at evaluation for that reason alone, while their own
    shell scripts already address the tests at the new path. Separately,
    [`11-qemu-patches.md`](11-qemu-patches.md) cites
    `checks.crucible.phase2.qemuAarch64DetIpiAdapter`, which does not exist (the
    check is an anonymous inline import), and describes "the 40-patch series"
    while `pkgs/emulation/qemu-patches/_series.nix` carries 42.
  - Plan: (1) a lint that, for every `failuresFor "<path>"` block, asserts
    `<path>` exists and that each needle occurs in it — turning a silent
    false-negative into a build failure; (2) a lint resolving every
    `checks.crucible.*` / `checks.fleet.*` attribute path named in the RFC against
    the evaluated check set; (3) a lint comparing patch-series counts in prose
    against `_series.nix`. Fix the eighteen needles and the two prose defects as
    part of landing it.
  - Gate: `gate:harness-lint` fails on an unresolvable needle, attribute path, or
    count.
  - Completed by `checks.crucible.referenceIntegrity` and
    `checks.crucible.phase1.gates.harnessLint`: the Nix check walks the complete
    Crucible and fleet check trees under `tryEval`, resolves every check
    attribute named by the RFC, and derives the documented patch count from the
    series manifest. The Rust lint rejects missing `failuresFor` source paths,
    checklist-state evidence, and completed/open task metadata inversions; its
    synthetic negative controls prove both task-state inversions fail. The
    repaired source needles, named check reference, and patch-count prose all
    pass the full-tree evaluation.

- [x] **T-HARN-29** Certify that CLI reproduction artifacts replay through
  independent packaged-QEMU processes rather than only through the model
  reducer. — satisfies [HARN-12], [HARN-24], [HARN-28]; spec §6, §7.
  - The gate creates a v3 artifact from a real two-VM QEMU timeout, retains its
    canonical trace and terminal savepoint, and requires fresh-QEMU ordinary,
    `--check`, `--to`, and identical-artifact `--bisect` invocations to pass.
  - The artifact identity pins QEMU, patch-series, plugin, shmem, guest-host,
    RPC, engine, and artifact ABIs. Its live evidence comparison covers the
    exact terminal tuple, canonical QEMU event bytes, and the declared full or
    terminal-all-node fingerprint scope after the pure model preflight. Generic
    run/verify/fuzz/fork recipes also replay separate closed, ordered startup and
    initial controls and compare all acknowledgements produced by the fresh
    session.
  - Completed by `checks.crucible.phase5.cliReplayCheck`; the check depends on
    the existing replay-oracle and end-to-end determinism gates and runs the
    packaged production CLI, QEMU, plugin, kernel, root image, and initramfs.
    A closed-producer contract matrix separately covers run/verify/search/fuzz/
    fork recipe admission and the fail-closed branch, lifecycle, fingerprint,
    choice-order, and unsupported-control rules.
