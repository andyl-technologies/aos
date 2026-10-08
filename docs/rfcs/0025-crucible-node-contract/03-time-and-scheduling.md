# RFC-0025: Time and Scheduling

## 1. Scope

This chapter specifies coordinator time, causal authorization, exact advancement,
and scheduling roles for all public simulation nodes. Compute, storage, clock,
link, and external-device nodes participate through the same ownership and event
rules. Their progression mechanisms need not be the same.

The quantized contract is specified in
[Quantized and Physical Nodes](04-quantized-and-physical-nodes.md). Node
declarations, ports, capability negotiation, and graph admission are specified in
[Ports, Capabilities, and Admission](02-ports-capabilities-and-admission.md).
Provider operations carry the logical records defined here according to
[Provider Protocol and Security](06-provider-protocol-and-security.md).

An exact timing claim is independent of a repeatability or state-preservation
claim. A provider can honor every execution ceiling while computing
nondeterministic results. Conversely, reproducible output at coarse boundaries
does not demonstrate exact event timing.

## 2. Coordinates and Units

**[CN-TIME-1]** The coordinator's canonical simulation instant MUST be an unsigned
64-bit integer number of picoseconds since the world's simulation epoch.
Simulation durations MUST use the same unit and integer representation.
Arithmetic, epoch projection, and unit conversion MUST be checked for overflow.
Overflow MUST refuse the operation before time or event state is mutated.

One nanosecond is 1,000 canonical ticks. One microsecond is 1,000,000 canonical
ticks. The canonical unit describes the protocol coordinate, not the fidelity of
any CPU or device model. A node can declare a coarser representable resolution.
An implementation requiring finer resolution cannot silently round to
picoseconds while claiming preservation of its native timing semantics.

**[CN-TIME-2]** Simulation instants, simulation durations, retired instruction
counts, model cycle counts, host monotonic timestamps, and physical-device
timestamps MUST be distinct typed quantities. A retirement witness MUST NOT be
used as simulation time without the selected model's explicit conversion.
A node's reported logical time MUST NOT be reconstructed from retirement when
idle advancement, variable instruction cost, or independent device progress can
change that relationship.

For example, a fixed instruction-cost profile may charge 50 picoseconds for a
retired instruction. That is a property of that profile. An out-of-order CPU
model can retire several instructions at one modeled cycle or retire none while
memory requests advance. A disk can advance to a completion without retiring any
instruction. All three use the same simulation coordinate.

**[CN-TIME-3]** A node-local simulation coordinate MAY have a checked epoch offset
from world time. The realized binding MUST identify that mapping. Rebase on
restore or lifecycle transition MUST preserve the committed world instant and
the distinction between world-relative deadlines and node-local deadlines.
A guest clock fault MUST NOT change coordinator time or silently rebase causal
event timestamps.

Changing guest-visible time, pausing a guest clock, and advancing the scheduler
coordinate are separate operations. A clock node can model drift or a faulty
reading while the coordinator's shared timeline remains monotone. The shared
timeline is not itself an ordinary guest clock node and cannot be reset by a
scenario's clock fault.

**[CN-TIME-4]** Exact resolution MUST describe the node's supported execution and
input-boundary representation, including phase relative to the world epoch.
A capability MUST NOT promise an arbitrary picosecond stop merely because the
wire format can encode that instant. The provider MUST reject a nonrepresentable
request or use a separately negotiated, explicit input-blocked boundary park.

A regularly aligned node may use a resolution `r` and phase `p`, with admissible
instants `p + n*r` for nonnegative integers `n`. A model with nonuniform admissible
boundaries needs a qualified successor/predecessor operation or an equivalent
explicit contract. Its event timestamps can be finer than its CPU stop grid only
if the provider can preserve the necessary ordering without executing past them.

## 3. Progress, Closure, and Scheduling Roles

The coordinator distinguishes a node's execution position from what is known
about its future production of events. For exact nodes these often coincide;
they are not interchangeable concepts.

**[CN-TIME-5]** Each node MUST expose a scheduling role sufficient to distinguish
active advancement, event-driven advancement, and autonomous observation.
Progress reports MUST distinguish the reached execution position, the closed
event prefix, pending input custody, and the lower bound on not-yet-published
output. Absence of a queued event MUST NOT be interpreted as proof that no future
event can occur.

An active compute node advances through modeled execution. An event-driven disk
may compute a response on arrival and hold it until a future delivery instant.
A modeled clock may expose an alarm without consuming CPU instructions. An
autonomous adapter may have no controllable physical execution position at all;
its observation-window contract is defined in the next chapter.

**[CN-TIME-6]** Event-driven nodes MUST NOT pin the global progress frontier at a
stale cursor solely because they have not received work. Their safe participation
MUST be derived from pending events, closed input windows, and qualified future
output bounds. A node MUST NOT be advanced by fabricated no-op RUNs solely to
make a minimum-of-cursors calculation move.

An idle link with no packets can certify its currently closed input prefix. Its
possible future output is then constrained by upstream production and link
latency. It does not need its own clock tick at every compute quantum. The same
rule permits a disk to have no pending completion while remaining ready to
receive a request.

**[CN-TIME-7]** World progress MUST account for unresolved event production and
delivery rather than taking an unconditional minimum of every public node's
local cursor. A frontier committed through an instant MUST have a proof that no
unresolved participant can subsequently publish an event required before that
frontier. Terminal or inactive nodes MAY be excluded only according to their
declared lifecycle and output-closure semantics.

This requirement does not prescribe one data structure. A conservative
coordinator can use per-port lower bounds, closed windows, and a dependency graph
to derive the frontier. It cannot exclude a physically running node merely by
marking its adapter idle.

## 4. Exact Grants

An exact grant is an immutable coordinator authorization for one state owner to
execute within a bounded simulation interval. Authorization and evidence of
actual execution are distinct records.

**[CN-TIME-8]** An exact grant MUST bind the world realization, node or jointly
owned node set, owner generation, grant identity, start coordinate, limit,
boundary policy, complete input authorization, and selected operating mode.
Retries MUST retain the same identity and MUST NOT duplicate inputs or effects.
A provider MUST NOT widen a grant, choose another node, or derive a new grant
from host completion order.

The basic executable interval is `[start, limit)`. Work at `limit` is not
authorized by the grant. A provider may reach a parked position at `limit` while
retaining all execution that would observe events there blocked. Settlement and
a new grant authorize subsequent execution.

**[CN-TIME-9]** An exact provider MUST NOT execute any state transition requiring
input or arbitration at or beyond its granted limit. It MUST return an
authenticated reached position and stop reason, including any retained
input-blocked boundary. A returned scalar equal to the limit MUST NOT substitute
for proof that the provider stopped before executing boundary-dependent work.

Stopping before the limit is permitted for an actual output, selectable request,
timer or device arbitration, lifecycle event, or an authenticated tighter bound.
The provider retains native custody while the coordinator resolves that cause.
An unexplained early pause cannot be relabeled as completed advancement.

**[CN-TIME-10]** A grant MAY authorize idle advancement only when the complete
input and wake inventory proves no runnable or externally visible transition
will be skipped. The provider MUST retain the physical execution position
separately where logical idle advancement does not change it. Idle advancement
MUST stop at the earliest timer, completion, input, control, or scenario boundary
relevant to that node.

A sleeping compute node with a timer at 8 microseconds can advance logical time
to that timer if an upstream node cannot deliver earlier input. The existence of
the timer alone does not establish the latter fact.

**[CN-TIME-11]** Receipt validation MUST precede event publication and committed
world mutation. Validation MUST check the actual owner, grant generation,
requested bounds, monotone reached position, boundary condition, output sequence
and timestamps, and complete stop evidence required by the selected mode.
An invalid or uncertain receipt MUST quarantine the unresolved execution owner;
it MUST NOT be repaired by inventing progress or replaying uncertain effects.

The provider protocol defines how the identity and custody checks cross a
process boundary. The scheduler must retain these checks when the underlying
implementation changes from QEMU to gem5 or a modeled host node.

## 5. Earliest Potential Input

For a directed causal connection from producer port `P` to consumer port `C`, let
`L(P)` be an inclusive lower bound on future output timestamps not yet delivered
to the coordinator. Let `d(P,C)` be the qualified minimum delivery latency under
the currently effective connection policy. The earliest potential arrival is
`A(P,C) = L(P) + d(P,C)`.

**[CN-TIME-12]** The coordinator MUST derive input authorization from every
effective causal input path, including paths with no currently queued event.
For an exact consumer, future producer lower bounds, pending concrete input,
native timer/device bounds, and scenario control bounds MUST all constrain its
grant. Unknown or stale bounds MUST prevent advancement that relies on them.

**[CN-TIME-13]** A producer lower bound MUST identify its owner generation, port,
world binding, closed production prefix, and timestamp equality convention.
A lower bound MUST remain valid until superseded by a causally stronger bound or
invalidated before further grants. The coordinator MUST NOT manufacture a
positive lower bound from an empty queue, a measured average latency, or a
provider's advertised timestamp resolution.

An inclusive lower bound of 500 picoseconds permits an unseen output exactly at
500. A statement that the producer is closed through 500 permits a stronger
bound, but only if the provider guarantees that equality is closed too. Those
statements need different representations or explicit bound kinds.

**[CN-TIME-14]** Minimum latency MUST be a semantic guarantee of the effective
connection, not a nominal throughput or wall-clock transport estimate.
Partition, heal, latency faults, and topology changes MUST update authorization
atomically before any grant can rely on the new graph. Events already in custody
MUST retain their original modeled delivery policy unless a scenario operation
explicitly changes those events.

A host socket can deliver bytes quickly while the modeled link holds them for
2 microseconds. Conversely, a slow host socket is not safe logical lookahead;
its delay might disappear on the next attempt.

**[CN-TIME-15]** For a consumer that cannot park at a not-yet-resolved input
boundary, the authorized executable stop MUST be the greatest supported stop
strictly before the earliest potential arrival. For a regular grid, it is
`max { p + n*r | p + n*r < A }`. The result MUST also respect all other limits.
If no supported stop advances the consumer, the coordinator MUST wait, resolve
due work, or refuse; it MUST NOT round upward or insert latency.

**[CN-TIME-16]** Parking exactly at a possible arrival MAY be used only when the
realized provider explicitly supports an input-blocked park there. Such a park
MUST prohibit execution dependent on that boundary until complete input
arbitration is acknowledged. It MUST NOT close the consumer's semantic execution
through that instant or prove an unseen producer has emitted nothing there.

These two rules separate an execution ceiling from a convenient timestamp. An
ordinary completed stop strictly before an unknown arrival and an unresolved
input-blocked park at that arrival convey different authority.

### 5.1. Worked Example: Different Exact Resolutions

An exact producer is closed before 1,050 picoseconds. Its unseen output can occur
at 1,050. The connection's minimum latency is 200 picoseconds, giving earliest
arrival 1,250. The consumer supports stops every 100 picoseconds with phase zero.

```text
world ps:       1000   1050   1100   1200   1250   1300
producer:              earliest unknown output
connection:            |---------- 200 ps ----------|
consumer grid:    *             *      *             *
ordinary limit:                       1200
unknown arrival:                             1250
```

The greatest ordinary safe stop is 1,200, not 1,300. The remaining 50 picoseconds
does not permit the provider to run until 1,300 and retrospectively timestamp the
output as 1,250. If the producer subsequently closes through 1,300, a stronger
input bound may allow further progress. If a concrete input really arrives at
1,250 and the consumer cannot accept that coordinate, the selected exact
connection is inadmissible unless its declared semantics permit an explicit
delivery conversion. Timestamp coercion is not an implicit remedy.

### 5.2. Worked Example: A Faster Consumer Must Wait

Two compute nodes are at 0. Their directed connection has 1,000 picoseconds of
minimum latency. The fast consumer wishes to reach 10,000 while the slow producer
has not advanced beyond its initial production position.

```text
producer known progress:  0 -------- executing slowly --------> unknown
potential output:        0
earliest arrival:       1000
consumer request:        0 ----------------------------------> 10000
authorized stop:         0 ----> greatest admissible stop <1000
```

The consumer cannot receive a 10,000 grant merely because its own CPU is fast or
because the producer's output queue is presently empty. As the producer returns
qualified progress, the coordinator can extend the consumer's safe window.
Buffering consumer outputs after an unauthorized run would not undo its internal
decisions made without an earlier input.

## 6. Same-Time Events and Zero-Latency Paths

**[CN-TIME-17]** External event delivery MUST use a canonical total order with
the simulation instant first and stable consumer, producer, and sequence
identities as tie-breakers. Host collection order, thread completion order,
socket arrival order, and memory address MUST NOT determine that order.
Each producer sequence MUST survive capture and restore without renumbering.

The compatibility baseline orders admitted deliveries by
`(instant, consumer identity, producer identity, sequence)`. A transport's own
authoritative FIFO order remains part of the producing node's semantics. A
coordinator must not reorder a live FIFO to imitate a complete modeled arrival
batch that it did not actually collect.

**[CN-TIME-18]** The coordinator MUST distinguish arrival collection, node-local
evaluation, publication, delivery arbitration, and subsequent execution.
At an unresolved input boundary, all authorized due inputs MUST be staged and
acknowledged before dependent execution resumes. A model requiring a same-time
phase or microstep order MUST bind that policy in the realized world and saved
continuation; it MUST NOT introduce an implicit phase change based on payload
class or provider implementation.

Boundary settlement is not permission to execute arbitrary zero-time work. A
node's native equal-timestamp event order is also part of its preserved state;
the public canonical order does not replace or reconstruct that internal order.

**[CN-TIME-19]** Zero-latency cycles MUST be refused unless the realized graph
selects a qualified same-time arbitration policy. Such a policy MUST define
microstep identity, deterministic tie-breaking, finite convergence or explicit
nonconvergence failure, and how input closure is established. Advancing time by
one tick to break a cycle MUST NOT occur implicitly.

Acyclic zero-latency paths can be evaluated in a defined topological same-time
order. Cyclic combinational device graphs may require a fixed-point policy. An
arbitrary microstep limit is an operational nonconvergence guard, not evidence
that a stable physical state exists or a guest assertion failed.

## 7. Concurrency and Composite Owners

**[CN-TIME-20]** Scheduler concurrency MUST be authorized by causal independence
and execution ownership, not merely distinct public node IDs. A provider
realizing several public node facets in one simulator MUST expose their shared
execution and capture owner. The coordinator MUST NOT issue conflicting grants
or captures to those facets concurrently.

A CPU facet, interrupt-controller facet, and memory-controller facet can be
publicly addressable nodes while sharing a gem5 event queue and continuation.
They can advertise a joint grant that describes the participating set. They
cannot each mutate that shared queue under independent simultaneous grants.

**[CN-TIME-21]** Concurrent execution MAY change host completion order but MUST
NOT change the canonical publication and resolution order. All worker results
MUST remain retained until the coordinator validates the round, incorporates
earlier outputs, and commits effects in its defined order. A worker limit MUST
NOT become an unrecorded semantic choice.

The coordinator may dispatch same-frontier owners in parallel where their bounds
prove no earlier dependency. An early producer output can require other owners
to remain held pending arbitration. Completing one host future does not justify
publishing that owner's events ahead of the canonical scheduler decision.

**[CN-TIME-22]** Grant cancellation, tighter readmission, input settlement, and
capture MUST preserve owner exclusivity until physical stop is acknowledged.
A cancellation request is not a stopped receipt. If stop or effect custody is
uncertain, all connected commitments affected by that uncertainty MUST remain
uncommitted or be terminated according to the failure-containment policy.

## 8. Lifecycle, Clocks, and Capture

**[CN-TIME-23]** Deactivation and reactivation MUST declare which clocks and
pending events continue, pause, or become invalid. Global deliveries and scenario
deadlines MUST NOT be shifted solely because one compute node was powered off.
Preserved node-local timer durations MAY move on reactivation only under an
explicit lifecycle clock policy with checked arithmetic.

**[CN-TIME-24]** A clock node MUST expose its guest-visible clock behavior and
alarms through admitted ports. It MUST NOT seize coordinator timing authority.
CPU timestamp instructions, paravirtual clocks, device counters, RTCs, and timer
interrupts MUST be covered by the realized compute/clock ownership map before a
provider advertises coherent clock control.

**[CN-TIME-25]** An exact world capture MUST preserve causal bounds, mappings,
pending deliveries, producer sequences, same-time phases, retained owner
generations, and node state at a compatible world cut. Capture MUST NOT close an
unresolved producer window by assumption, execute hidden drain work, or replace
internal event order with a timestamp-only reconstruction.

The complete preservation and implementation binding rules are specified in
[State and Replay](05-state-and-replay.md). Meeting this chapter's exact timing
rules is necessary for exact event coordination; it does not establish that a
provider can serialize its caches, speculative state, device transients, or
pending continuation.

## 9. Refusal and Operational Failure

**[CN-TIME-26]** The coordinator MUST distinguish causal contract refusal and
provider execution failure from an application finding. Missing bounds,
unrepresentable exact input, illegal time regression, invalid owner receipt,
same-time nonconvergence, and arithmetic overflow MUST carry explicit operational
outcomes. They MUST NOT be emitted as guest assertion failures or silently
converted into a weaker operating mode.

Waiting for a slow producer is normal scheduling behavior. Waiting indefinitely
on an impossible graph is not: admission and runtime liveness diagnostics should
identify the blocking paths without changing their semantics. Host watchdogs can
terminate an attempt, but cannot supply simulation time or proof of progress.
