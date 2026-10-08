# Qualification, regression, and performance plan

This plan implements the target obligations in
[RFC-0025 conformance](../../rfcs/0025-crucible-node-contract/08-conformance.md).
It is nonnormative. Suites and cases below are proposed work, not passing test
results. Existing files are identified separately. The
[phased plan](phased-implementation.md) defines task dependencies and exits.

## 1. Acceptance units and evidence

Qualify a concrete implementation, adapter, patches, CPU/platform/device model,
port profile, mode, state format, threading/mapping constraints, and harness
revision. Do not qualify an entire product family by testing one executable
name. Keep these evidence categories distinct:

- Protocol conformance and parser safety.
- Exact or quantized timing behavior.
- Repeatability and conditional transcript replay.
- Architectural, complete modeled live, and complete modeled durable capture.
- Branch isolation and required role/device parity.
- Performance under a declared workload and environment.

A model test cannot replace a live native test. Boot liveness cannot establish
microstate preservation. A hash of a serializer's own output cannot show that
the serializer included omitted state. A physical-device publication gate cannot
show that the physical hardware stopped.

Acceptance records enumerate every applicable RFC requirement and record pass,
fail, unsupported, not applicable, and not executed separately. Unsupported
optional facets are valid admission outcomes. Missing required parity, exact
preservation, or selected-mode behavior blocks that profile. No unresolved
failure or unexecuted applicable requirement may be silently counted as passing.

## 2. Existing regression foundation

The existing [determinism harness catalog](../../rfcs/0010-crucible/24-determinism-harness-testing.md)
defines canonical gate names and their scopes. A new node-contract suite needs
its own implementation and wiring; referencing an old gate is not proof that
the new property is already covered.

| Area | Existing source to reuse | Application to implementation phases |
| --- | --- | --- |
| Pure identity and determinism | [Layer-0 determinism](../../../tests/crucible/phase1-layer0-determinism.nix), [content address](../../../tests/crucible/phase1-content-address.nix), [spatial canonicalization](../../../tests/crucible/phase1-spatial-canonicalization.nix) | Golden bytes, unchanged old graph identities, canonical event order in P1/P2 |
| Replay and campaign semantics | [Replay oracle](../../../tests/crucible/phase1-replay-oracle.nix), [campaign model](../../../tests/crucible/phase1-campaign-model.nix), [campaign continuity](../../../tests/crucible/phase7-crucible-campaign-continuity.nix) | Shared driver extraction and separate new nondeterministic policy |
| Exact ceilings and conservative scheduling | [RUN ceiling](../../../tests/crucible/phase3-scheduler-run-ceiling.nix), [lookahead](../../../tests/crucible/phase3-scheduler-lookahead.nix), [exact local event](../../../tests/crucible/phase3-scheduler-exact-local-event.nix), [conservative PDES](../../../tests/crucible/phase3-scheduler-conservative-pdes.nix) | Preserve current proofs, then extend across all causal ports |
| Same-time order and liveness | [Event order](../../../tests/crucible/phase3-scheduler-event-order.nix), [liveness](../../../tests/crucible/phase3-scheduler-liveness.nix), [concurrency](../../../tests/crucible/phase3-scheduler-concurrency.nix), [idle fast-forward](../../../tests/crucible/phase3-scheduler-idle-fast-forward.nix) | Passive-node semantics, composite owner exclusion, no host-order dependence |
| Native exact stops and restore | [Exact preemption](../../../tests/crucible/phase2-qemu-exact-preemption-live.nix), [exact snapshot/restore](../../../tests/crucible/phase2-qemu-exact-snapshot-restore.nix), [restore reachability](../../../tests/crucible/phase2-qemu-exact-restore-reachability.nix) | Preserve QEMU native authority during extraction; add independent gem5 tests |
| Live devices | [Block guest](../../../tests/crucible/phase2-qemu-live-block-io-guest.nix), [network guest](../../../tests/crucible/phase2-qemu-live-network-io-guest.nix), [plugin 9p](../../../tests/crucible/phase2-plugin-9p-io.nix), [block realization](../../../tests/crucible/phase2-qemu-live-block-realization.nix) | Real transport and frontend/host-owner parity, not a scripted reply |
| Faults and end-to-end | [Signal fault system](../../../tests/crucible/phase7-signal-fault-system.nix), [end-to-end determinism](../../../tests/crucible/phase7-e2e-determinism.nix), [debugger architectures](../../../tests/crucible/phase7-debugger-live-architectures.nix) | New role/profile fault support, architecture-specific evidence |
| Process and license boundary | [ABI conformance](../../../tests/crucible/phase2-abi-conformance.nix), [license boundary](../../../tests/crucible/phase1-license-boundary.nix), [crate layer graph](../../../tests/crucible/phase1-crate-layer-graph.nix), [package ABI versioning](../../../tests/crucible/phase7-crucible-package-abi-versioning.nix) | Any boundary/schema change; no new runtime dependency cycles |
| Production release path | [Production evidence](../../../tests/crucible/phase9-campaign-mode-production-evidence.nix), [release acceptance](../../../tests/crucible/phase9-campaign-release-acceptance.nix) | Bind selected implementation and required evidence in final rollout |

Use `aos-dev` to discover and run the repository's check targets. Build and run
through AOS-provided tools and local builders. Future Rust edits also run
`checks.rust.aos-test-targets`, which compiles unit and integration targets that
a library-only test invocation would miss. Changes affecting public process
protocols run `gate:abi-conformance` and `gate:license-boundary`, with matching
native source artifacts where required.

For this documentation-only change, validate links, source references,
requirement allocation, example vectors, and consistency. It does not require
executing native qualification or claiming any new backend support.

## 3. Proposed suites and minimum cases

The suite letters match the RFC. Case identifiers below identify planned
engineering fixtures; they are not additional normative requirement IDs.

### 3.1 Suite B — Base, admission, lifecycle, and ownership

| Case | Exercise | Independent acceptance observation |
| --- | --- | --- |
| B-01 | Minimal node without optional facets; valid combined facets | Only negotiated facets route; discovery alone cannot mutate state |
| B-02 | Descriptor/configuration changes between prepare and activation | Binding mismatch refuses before guest/hardware mutation |
| B-03 | Duplicate owners/nodes, dangling ports, incompatible protocols/modes | Whole graph refuses with the implicated connection or owner |
| B-04 | Several logical nodes share one execution/capture owner | Conflicting work cannot run twice; capture covers state once |
| B-05 | Out-of-order lifecycle, stale tokens, repeated cancellation | Original operation retained; no duplicated effect or premature release |
| B-06 | Unknown observations versus known absence of work | Unknown state supplies no invented positive lookahead |
| B-07 | Timeout or disconnected owner after uncertain submission | Candidate quarantines; original effect certainty remains visible |

B-02 and B-03 inspect externally visible state before and after refusal, not
only an error string. B-04 includes owner aliases reached through different roles.

B-02 also fails preparation and owner-ready publication at each initial
activation boundary. No ordinary execution begins before the committed world
activation record covers the complete owner roster; grants with stale or
unknown owner-ready generations cannot execute. Test the same barrier for fresh
initialization and restore, without assuming simultaneous physical startup.

### 3.2 Suite E — Exact scheduling and mixed causal graphs

Test immediate legal stops, early output, earlier native timers, pending input,
idle wake, and arithmetic limits. Partition the same admitted input stream into
one long grant and many short grants; compare final state and ordered traces.
Probe immediately before and after each legal boundary.

E-01 verifies actual advancement never crosses an admitted ceiling. E-02 covers
same-time ordering and native event ordinals. E-03 covers resolutions that cannot
represent a requested boundary, checked arithmetic overflow, zero-lookahead
cycles, and missing producer bounds. Refusal or a truthful legal earlier stop
is acceptable; rounded receipts are not.

For `superdense-v1`, E-02/E-03 explicitly include phase closure, a causal chain
whose endpoint names sort in reverse causal order, converging and nonconverging
zero-time feedback, microstep overflow, and capture within a microstep/phase.
Boundary-settlement grants must execute only their admitted position range at
one physical instant and refuse any operation that would execute a later tick.
An administrative park at a tick cannot masquerade as a committed semantic
prefix. Restored ordering must preserve publication and delivery positions
independently, including sampled quantized boundary reactions.

Test node-wide public sequences across ports, lanes, and fanout recipients while
retaining native FIFO/request/transport sequence provenance separately. An
output discovered by native reaction work remains pending at its next-microstep
publication position; it cannot enter an already closed publication phase.
Include these distinctions in restored event/receipt comparisons.

E-04 makes one producer deliberately slow while a receiving compute node is
fast. Test both directions and every applicable port family: network, block,
filesystem, interrupt, clock alarm, and custom service. The receiver must not
cross an unexcluded incoming event. E-05 repeats with composite owners, pending
queues at capture, and adversarial host completion order. E-06 verifies passive
disk/link/clock behavior does not create artificial progress or pin a frontier
without a causal dependency.

The current QEMU control and Source paths retain their authentic stop and input
owners. Fixtures deliberately present copied receipts, foreign generations,
changed inventories, and uncertain acknowledgments, and verify they cannot be
promoted into native authority by the new facade.

### 3.3 Suite Q — Quantized execution and physical containment

Q-01 exercises readiness, grant authorization, input sampling, authorized
activity, polling, output buffering, close acknowledgment, boundary commit,
and next-window authorization. It verifies that no next window starts early
and no event enters committed history.

Q-02 covers a delayed exact producer, coarse input at both window boundaries,
fine events between exact peers, cancellation during closure, lost closure
response, duplicate acknowledgment, output saturation, and late observations.
Q-03 applies every admitted wall-deadline policy. Stall, failure, or declared
sampling policy may be appropriate; silent timestamp reassignment is not.

Q-04 independently observes pause capabilities: execution pause, clock pause,
interaction gating, and continuing physical activity. A held adapter queue is
not evidence of a stopped USB device. Q-05 attempts every possible I/O bypass,
including background kernel/device effects, and verifies complete containment
or profile refusal.

KVM adds x86 and ARM fixtures for guest-visible clocks, paravirtual clocks,
timer phase, interrupt injection, vCPU halting, multi-vCPU run/stop, idle
advance, DMA, and storage/network completions. Vary host contention and measure
stop latency distributions, but never use a measured maximum as proof of an
exact logical ceiling. Capturing architecture and devices does not capture the
physical processor's caches, predictor, or pipeline.

Audit each architecture's trapping/scaling/offset/emulation/patch options before
claiming controller-clock support. Tests include clock-polling progress, alternate
guest clock selection, clocks during vCPU stop overshoot, and clocks while a
closed window waits for slower peers. Any unmediated required source refuses
the profile rather than silently returning host time.

### 3.4 Suite R — Repeatability, provenance, and conditional replay

R-01 varies host scheduling, batching, threading within the admitted scope, and
grant partitioning. Repeatable profiles compare ordered events, independent
state witnesses, and final outputs. Negative controls alter seed, input, or
configuration and must be detected.

R-02 records complete admitted boundary interactions, including inbound
requests, payloads, order, effective coordinates, storage changes, completions,
interrupts, and control outcomes. Replay the original accepted interaction and
refuse changed requests, missing events, different ordering, and changed shared
side-effect dependencies. Transcript limits and missing coverage fail explicitly.

R-03 runs an interacting KVM or physical node and checks world nondeterministic
provenance, observed-attempt identity, and ineligibility for deterministic
memoization or replay. R-04 verifies that a captured transcript enables only its
conditional replay contract, not arbitrary counterfactual branches or recovery
of physical timing that was never measured.

### 3.5 Suite S — Complete state and independent continuation paths

Inventory every realized mutable state domain and generate a fixture with
nonempty difficult state for each. The inventory includes:

| Domain | Required difficult-state examples when realized |
| --- | --- |
| CPU | Live speculation, ROB/IQ/LSQ, renaming, pipeline latches, predictor history, microcode, exceptions, outstanding memory operations |
| Cache/coherence | Dirty lines, replacement policy, MSHRs, write queues, transient states, retries, in-flight coherence traffic |
| Translation and memory | Pending page walks, TLB replacement, request queues, open rows, refresh phase, arbitration, DMA |
| Events and clocks | Pending callback payloads, cancellation/reinsert history, same-time tie order, timer phase, time anchors |
| Devices | Virtqueue indices, descriptors, pending buffers, DMA, interrupt/completion state, reset and feature negotiation |
| Host models | Block overlay, 9p fids/tree/visibility, link queues, latency RNG, accelerator work and cancellation |
| Coordinator | Pending inputs/outputs, logical mappings, causal bounds, admission generations, choices, PRNG positions, trigger/fault/lifecycle state |
| External resources | Writable mappings/files, sockets, service queues, ownership leases, replay position, and declared live dependencies |

S-01 compares independently observed state immediately before capture and
after capture without restoration. No hidden tick movement, retirement,
cache flush, writeback, draining, or RNG change is permitted for complete exact
capture.

S-02 compares these distinct paths from the same admissible cut:

1. Uninterrupted continuation.
2. Capture followed by continuation without restore.
3. Restore in the original process where supported.
4. Restore in a fresh process.
5. Live branch with identical inputs.
6. Live divergent branches with parent/sibling isolation.
7. Durable restoration after the original owner and its live resources are gone.

Complete durable-state profiles must pass path 7. Live COW support does not
substitute for it. Physical architectural profiles use their explicitly weaker
equivalence and never inherit a modeled-state claim.

S-03 deliberately omits, mutates, or reorders each state domain to verify the
oracle can detect incomplete preservation. Instrumentation observes pipeline,
memory, events, and future commits independently of the serializer. Test
coverage asserts difficult queues and transient states were actually nonempty;
empty or drained state cannot accidentally pass.

S-04 exercises shared files/maps, disk writes, sockets, external services,
threads, and output streams in divergent branches. S-05 removes or changes an
owner artifact, implementation, CPU model, device, state version, or connection
and proves refusal before activation. S-06 injects prepare/restore failure at
each owner and connection boundary and verifies atomic world quarantine.

For gem5, retain native event-bin ordering as well as timestamp and priority.
Stopping between completed native callbacks is not an excuse to drain pipeline
or memory state. A stock checkpoint/re-execution path is a negative reference,
not the accepted full-state implementation.

### 3.6 Suite P — Process protocol, security, and retry

Implement an independent peer for the specified CNP/1 framing and canonical
identity vectors. P-01 splits and coalesces stream reads, tests duplicate JSON
keys, malformed UTF-8, nesting, byte bounds, unknown required methods, version
mismatch, and canonical content identities.

P-02 changes session, incarnation, owner roster, realization binding, operation
ID, and admitted input identity. P-03 disconnects before submission, during
partial transmission, after acceptance, after effects, and before response.
Reconnect only to the original surviving incarnation under its negotiated
recovery rules; a restart is a new incarnation. Retry must recover the original
operation or report uncertainty, never repeat an effect because its response
was lost.

P-04 exercises operation and content-transfer quotas, digest mismatch, incomplete
blobs, untrusted state artifacts, path/socket access control, and resource
exhaustion. P-05 checks that process messages cannot grant native permissions
merely by copying a structurally valid receipt. Shared-memory extensions keep
checked offsets and explicit versions; pointers and process-native object
layouts are invalid payloads.

### 3.7 Suite F — Roles, parity, and progression

F-01 runs every supported role's operations, faults, backpressure, reset,
feature negotiation, and state capture with real guest or external interaction.
F-02 maintains a full parity ledger for supported compute profiles: root-image
and modeled block, 9p, network, entropy, serial, debug, custom accelerator,
doorbells, platform firmware, clocks, and interrupts. Missing required features
fail the profile rather than being marked optional retroactively.

F-03 qualifies x86-64 and AArch64 separately, including capture with real pending
device traffic. F-04 runs cold KVM, QEMU-SIM, and gem5 progression using portable
guest artifacts and independent realization identities. Any architectural
conversion has its own nonexact initialization tests, lineage, and refusal rules.
F-05 exercises clock-node alarms and faults without changing coordinator time,
and link shaping/reordering without treating adapter completion order as
canonical delivery order.

## 4. Performance measurement

Correctness qualification runs first. Performance measurements preserve its
configuration and disabled instrumentation preset. Record guest artifacts,
QEMU/native executable, plugin/adapter, model, clocks, devices, grants, host
affinity, toolchain, and source identities. Alternate baseline/candidate runs
locally and retain all samples and failures. Report distributions and paired
ratios, with startup, execution, capture, restore, and teardown intervals
defined separately. Profiling and flame graphs are diagnostic runs, not timing
samples.

The current [authenticated Linux readiness runner](../../../tests/crucible/tcg-linux-boot-performance.py)
provides useful QEMU/SIM regression witnesses: raw and logical coordinates,
registers, sampled RAM, serial data, markers, and actual timer evidence. Use it
for abstraction overhead while preserving its fixture and authentication.
Boot alone is insufficient: include request-heavy block/9p, network exchanges,
idle timers, many-node dispatch, and capture/restore to detect coordination cost.

The [serial comparison runner](../../../tests/crucible/tcg-linux-serial-performance.py)
at the audited base explicitly uses ordinary TCG icount at 1 ns/instruction
and SIM at 50 ps/instruction. It is not a matched-time comparison. The existing
matched same-ELF 50 ps SIM/TCG comparison work must be located and preserved or
integrated as a separate prerequisite when implementation begins. Do not alter
that strict workload to accommodate gem5 or KVM, and do not relabel the 1 ns
runner as matched. A modified baseline carries its actual prerequisites.

New provider comparisons declare fidelity and work differences. gem5 detailed
modeling measures a different cost from fixed-time instruction execution; KVM
boot may execute different work and clocks. Such ratios can describe workload
runtime, but not equivalent instruction throughput. Report same-binary
sim/non-sim comparisons separately from cross-provider profiles.

Keep small measured wins, quantify their uncertainty, and compare the final
combined implementation directly with a frozen `origin/master` baseline. Do not
multiply unrelated percentage wins to invent a total. A neutral facade should
have no per-instruction callback, allocation, or synchronization; inspect its
profiles as well as wall time. Set profile-specific acceptance budgets before
interpreting measured regressions.

Raw profiles, dumps, and logs remain local. PRs contain concise reproducible
summaries and artifact identities; do not add large evidence to source history
or use release assets as a raw-test-document store.

## 5. Requirement allocation and acceptance traceability

The allocation below covers every requirement family. It identifies work and
planned suite ownership, not executed evidence. The per-ID snapshot in
[requirement-map.tsv](requirement-map.tsv) enumerates the current RFC definitions,
their source chapter, assigned tasks/suites, and `planned` status. Refresh it
when requirements change and verify set equality with the final RFC. Implemented
acceptance records later replace allocation with concrete executed case IDs,
evidence identity, result, and justified applicability.

The definition inventory scans Markdown recursively, including normative schema
references under the RFC's `reference/` directory. The `chapter` column stores
paths relative to the RFC directory, and `line` identifies the definition at
the snapshot revision. Schema tables and their incorporated obligations also
need field-level vector and refusal coverage; counting requirement IDs alone
does not establish that every table rule was exercised.

| Requirement family | Principal task allocation | Applicable planned suites |
| --- | --- | --- |
| `CN-MODEL-*` | T-CN-03, T-CN-06..14 | B, E, S; identity and owner review |
| `CN-NODE-*` | T-CN-03..05, T-CN-10..14, T-CN-24, T-CN-29 | B, E, Q, S, P, F |
| `CN-PORT-*` | T-CN-08, T-CN-11..13, T-CN-20, T-CN-26 | B, E, Q, S, F |
| `CN-CAP-*` | T-CN-06..08, T-CN-21, T-CN-27, T-CN-31 | B, R, S, F; qualification-scope review |
| `CN-TIME-*` | T-CN-09..14, T-CN-16, T-CN-22, T-CN-26 | E, Q, S |
| `CN-QUANT-*` | T-CN-24..28, T-CN-30 | Q, R, S, F |
| `CN-STATE-*` | T-CN-07, T-CN-14..19, T-CN-27 | S, P, B |
| `CN-REPLAY-*` | T-CN-07, T-CN-27..28 | R, S; cache/search admission review |
| `CN-IPC-*` | T-CN-06..10, T-CN-16, T-CN-24, T-CN-29, T-CN-31 | P, B, E, Q, S |
| `CN-SEC-*` | T-CN-08, T-CN-29..32 | P, B, S; license/resource review |
| `CN-PROFILE-*` | T-CN-11..13, T-CN-15..23, T-CN-25..30 | F, E, Q, S, R |
| `CN-TEST-*` | T-CN-01, T-CN-14..32 | All suites; acceptance and performance review |
| `CN-EXT-*` | T-CN-06..09, T-CN-29..32 | P, B, F; extension and compatibility review |

The allocation deliberately gives foundational semantics several suites. For
example, canonical identity is tested by protocol vectors and state refusal;
owner exclusivity is tested by lifecycle, concurrency, and capture. Passing one
suite does not imply all classes or all requirements in a family passed.

## 6. Review and rollout record

Each implementation PR records source changes, preserved/migrated formats,
new admitted profile scope, passing and failing cases, remaining unexecuted
requirements, and matched performance impact. Release admission consumes only
accepted complete records for the requested classes. Scientific validation of
a gem5 CPU/memory model remains a separate effort from interface conformance.

Final review checks that old deterministic workflows remain valid; new mixed
worlds cannot bypass causal barriers; complete-state profiles have durable proof;
quantized profiles have truthful containment; and vendor-specific extensions
are explicit, versioned, bounded, and covered by their own cases.
