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

The protocol represents a position as `{ time_ps, microstep, phase }` under the
selected ordering profile. A time-window limit at physical tick `H` is the
position `(H, 0, boundary-control)`: its half-open bound excludes every semantic
position at `H`. A boundary-settlement grant instead names a bounded range of
positions at one physical tick. These forms share a representation but confer
different permission.

**[CN-TIME-8]** An exact grant MUST bind the world realization, node or jointly
owned node set, owner generation, grant identity, start coordinate, limit,
boundary policy, complete input authorization, and selected operating mode.
Retries MUST retain the same identity and MUST NOT duplicate inputs or effects.
A provider MUST NOT widen a grant, choose another node, or derive a new grant
from host completion order.

The basic executable interval is `[start, limit)`. No semantic transition at
`limit` is authorized by that grant, whether or not it requires external input.
A provider may report an administrative parked position at `limit`, but that
park MUST change no modeled state or consume any due event there. An explicit
boundary-settlement authorization and, where applicable, a new execution grant
authorize subsequent work.

**[CN-TIME-9]** An exact provider MUST NOT execute any semantic transition at or
beyond its granted limit. It MUST return an
authenticated reached position and stop reason, including any retained
input-blocked boundary. A returned scalar equal to the limit MUST NOT substitute
for proof that the provider stopped before executing any transition there.

A semantic transition is any modeled state mutation, event consumption,
instruction retirement, observation-dependent decision, or visible effect. Its
coordinate is the modeled instant and superdense microstep/phase at which the
change occurs, not when its host callback starts or returns. A private pipeline
event remains semantic work even when no public port reports it.

**[CN-TIME-27]** An atomic modeled step with effects spanning a granted limit
MUST be refused before those effects occur, or divided into qualified,
preservable in-flight transitions whose individual coordinates obey the grant.
An implementation MUST NOT execute across a limit and then clamp the reported
time or buffer only the public output. Internal native events wholly inside an
authorized window MAY execute without a host stop after every event; all
externally relevant arbitration and output bounds still apply.

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

**[CN-TIME-17]** The target baseline event-order profile MUST be
`superdense-v1`, ordered by `(instant, microstep, phase, consumer identity,
producer identity, sequence)`. Microstep MUST be an unsigned 64-bit integer.
The fixed phases in increasing order are `boundary-control = 0`,
`publication = 1`, `delivery = 2`, and `reaction = 3`. Host collection order,
thread completion order, socket arrival order, and memory address MUST NOT
determine this order. Each producer sequence MUST survive capture and restore
without renumbering.

**[CN-TIME-35]** The sequence used in the public ordering key MUST be monotone
and unique across all events from one producer node, including all output ports,
lanes, connections, and per-recipient fanout deliveries. The producer's sequence
allocation state MUST be preserved with its continuation. Native FIFO sequence,
request identity, and transport epoch MUST remain separate retained provenance;
their narrower scope MUST NOT be substituted for the public node-wide sequence.
Fanout deliveries MUST retain their common publication lineage while using
distinct public sequence identities.

A superdense coordinate describes ordered work at one physical simulation tick.
It does not add picoseconds to that tick. Root events at an instant use microstep
zero: coordinator controls occupy phase zero, already produced publications
phase one, due input delivery phase two, and independent native alarms or node
reactions phase three. A reaction to an admitted event MUST NOT be classified as
an independent root merely because its provider received it through a different
operation.

**[CN-TIME-18]** Every semantic reaction at `(t, m, phase)` that emits another
event at `t` MUST assign that publication microstep at least `m + 1`.
This applies to input and control reactions, independently armed native alarms,
internal model events, device completion evaluation, and execution that
discovers an output. The baseline assigns exactly one microstep after the
greatest same-time causal parent; its delivery uses phase two of that new
microstep. An independent native alarm at `(t, 0, reaction)` therefore publishes
a same-time interrupt at `(t, 1, publication)`, never retroactively in phase one
of microstep zero.

A publication delivered through a direct zero-delay connection MAY use delivery
phase two of the publication's existing microstep: this is transfer of an
already produced event, not a new reaction emission. A modeled link or device
that evaluates a delivery and emits a new event follows the next-microstep rule.
An event scheduled at a strictly later physical instant becomes a root there,
unless it already has a retained same-time causal coordinate. An earlier
evaluation can thus retain a future root publication; evaluating a native event
at the publication's own instant cannot claim that earlier-origin exemption.

No reaction can precede its cause in the public order. Distinct unrelated events
within one microstep and phase use endpoint and sequence ties. An authoritative
native FIFO remains part of the producing node's semantics; the public order
does not authorize reordering that FIFO or reconstructing a simulator's private
equal-time queue.

**[CN-TIME-19]** Zero-latency cycles MAY be admitted under `superdense-v1` only
when the participant set supports complete microstep closure and the world binds
a finite maximum microstep count per instant. If the cycle does not quiesce
within that count, execution MUST end with operational nonconvergence failure.
The coordinator MUST NOT implicitly advance physical time, suppress events, or
claim a fixed point to break the cycle. Microstep arithmetic overflow MUST fail
before the resulting event is published.

**[CN-TIME-28]** At each microstep, the coordinator MUST complete a phase before
committing a later phase that could observe its effects. Closure MUST prove that
no authorized participant can subsequently publish earlier-phase work at that
coordinate. Input deliveries at one phase MUST be collected and canonically
staged before its dependent reaction phase executes. An instant is globally
closed only after all same-time causal microsteps and required owner receipts
are resolved, with no unresolved same-time source remaining.

**[CN-TIME-32]** A producer's physical tick alone MUST NOT be treated as proof of
closure of every microstep at that tick. Bounds and receipts MUST identify
whether they close a prefix before
a superdense coordinate, through a phase, through a microstep, or through the
whole instant. Future grants cannot reinterpret the weaker claim as the stronger
one. Provider-private events may remain internal where their execution cannot
produce unresolved public work in an already closed phase. Private event
ordering and causal ancestry MUST remain sufficient to assign any resulting
public emission to the correct unclosed microstep.

**[CN-TIME-33]** An ordinary `exact_run` MUST NOT close all phases at each tick
merely by reaching that tick. If native execution discovers an output during
reaction work at
`(t, m, reaction)`, the retained publication belongs to microstep `m + 1` and
remains pending until its phase is authorized and committed. The returned receipt
MUST identify that reaction position, pending publication membership, and actual
closure prefix. It MUST NOT insert the output into a publication phase already
closed earlier in the run. A provider unable to establish this ordering MUST
refuse the applicable same-time capability before execution.

**[CN-TIME-29]** Due work at an execution limit MUST use an explicit
boundary-settlement grant naming the instant, authorized microstep/phase range,
complete relevant input authorization, and execution owner. Settlement MAY
permit admitted reaction work at that instant but MUST NOT authorize execution
at a later physical tick. A provider unable to separate settlement from later
execution MUST refuse that operation. A parked receipt alone supplies no such
permission.

**[CN-TIME-31]** Exact execution and boundary-settlement grants MUST carry
ordered start and limit positions and apply half-open position semantics.
An `exact_run` physical time ceiling MUST exclude all positions at its ceiling
tick; `boundary_settle` MUST restrict work to the authorized position range at
one tick. A receipt MUST distinguish an administrative park at the physical
ceiling from a committed semantic prefix there. Position fields MUST NOT permit
an implementation to reinterpret a time-window grant as unlimited settlement.

**[CN-TIME-30]** Realization identity, grants, receipts, causal bounds, pending
events, transcripts, and captures MUST bind the event-order profile and retained
microstep/phase fields. The legacy positive-latency order
`(instant, consumer, producer, sequence)` MAY be supported only as a separately
versioned compatibility profile whose admission excludes cross-owner same-time
reactions that need causal microsteps. A new codec and compatibility binding MUST
be used for `superdense-v1`; missing fields MUST NOT be inferred from endpoint
order or silently assigned zero during restore.

**[CN-TIME-34]** A publication's position and its destination delivery position
MUST be retained as distinct lifecycle evidence. A direct same-time transfer
publishes in phase one and is
delivered in phase two of the same microstep. The event's retained identity and
causal parent membership connect those records; a codec MUST NOT overwrite the
publication position to hide how its delivery was authorized. Same-time fanout
retains each recipient's delivery identity and the common publication lineage.

### 6.1. Worked Example: Reverse Lexical Chain

Suppose a root event from `Z` is delivered to `B` at tick 100. Its reaction emits
an event to `A` with zero modeled latency. Endpoint names sort `A < B < Z`.

```text
cause:       (100, 0, delivery, B, Z, 0)
reaction:    (100, 0, reaction, B, B, 0)
effect:      (100, 1, publication, A, B, 0)
delivery:    (100, 1, delivery, A, B, 0)
```

Sorting only by tick and endpoint would place the effect on `A` ahead of the
cause on `B`. The superdense fields put the entire causal step before its effect
without changing tick 100. The intermediate publication's endpoint denotes its
declared recipient; for a fanout publication the profile retains a distinct
delivery identity per recipient, with the same causal publication membership.

### 6.2. Worked Example: Zero-Time Feedback

If `A` then responds to `B` at the same tick, its output belongs to microstep two.
Further responses alternate through later microsteps. If the world permits at
most 32 microsteps at one instant, a required microstep 32, where numbering starts
at zero, terminates the attempt as nonconvergent before publication. Capture of
tick 100 between microsteps MUST retain the unresolved chain and exact closure
prefix; capture must not label the instant globally closed. A conformance test
must exercise reversed endpoint names, a finite feedback chain, and an infinite
feedback loop with this operational outcome.

### 6.3. Worked Example: Native Timer Output

A timer was armed earlier for tick 200. Firing the timer is independent root
reaction work at `(200, 0, reaction)`. If that firing creates an interrupt on a
public port, its publication belongs to `(200, 1, publication)` and its direct
zero-delay delivery to `(200, 1, delivery)`. The coordinator cannot put it into
`(200, 0, publication)` after closing that phase, even if no application input
caused the timer to fire. The conformance fixtures cover this case and output
discovered by ordinary native execution after an earlier same-time phase closed.

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
