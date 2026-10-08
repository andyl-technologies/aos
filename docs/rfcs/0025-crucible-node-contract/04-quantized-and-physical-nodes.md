# RFC-0025: Quantized and Physical Nodes

## 1. Purpose and Limits

Quantized operation allows hardware-accelerated compute and autonomous physical
devices to participate in a coordinator-controlled simulation. The coordinator
controls when inputs become logically visible and when outputs can affect other
nodes. It does not claim instruction-exact stopping or preservation of a physical
CPU's hidden state.

The mode applies equally to a KVM compute node and an external device adapter
when their realized capabilities support it. KVM is an example implementation,
not part of the public node type. A physical device can remain active while its
adapter closes logical observation windows; that distinction must be explicit.

An existing exact scheduler's subdivision budget is not this mode. A budget
that limits an exact RUN still relies on an exact execution ceiling. Quantized
operation instead defines input sampling, output publication, window closure,
and nondeterministic execution within a logical interval.

## 2. Quantum Grids

**[CN-QUANT-1]** Each quantized node MUST bind a positive quantum duration `Q`,
an epoch phase `P`, and its boundary publication policy in the realized world.
Boundary `B_k` is `P + k*Q`, and quantum `k` is `[B_k, B_(k+1))`.
Boundary arithmetic MUST use checked canonical picosecond integers.
The grid MUST NOT change during an attempt without an explicit versioned
transition that closes affected windows and changes continuation identity.

The quantum number names logical work, not a host timer expiration. A one
microsecond quantum can consume milliseconds of host time because another node
is simulating a detailed CPU. Conversely, a hardware node can execute much more
native CPU work in the granted host budget than a modeled CPU executes in the
same logical interval.

**[CN-QUANT-2]** A quantized grant MUST distinguish its logical interval from any
host execution budget, pacing ratio, operational deadline, and measured physical
progress. Native retirement, CPU cycles, elapsed wall time, and guest clock
readings MUST NOT be asserted to equal the logical interval unless a separate
qualified capability establishes that relationship.

The scenario can choose a smoke-test policy such as a bounded host execution
slice per logical quantum. Host scheduling and physical execution then affect
the amount of work completed. The resulting nondeterminism is part of the
accepted mode. A controller-owned clock can provide stable logical readings
without making the native execution trajectory deterministic.

## 3. Sampling and Publication Semantics

**[CN-QUANT-3]** Before activating quantum `k`, the coordinator MUST close and
order the complete input batch visible at `B_k`. The node MUST acknowledge
staging that batch before any dependent work in the interval executes.
No input first discovered after activation may be retroactively inserted into
that start batch.

**[CN-QUANT-4]** In the baseline policy, node outputs produced during quantum
`k` MUST become logically publishable no earlier than `B_(k+1)`.
The provider MUST retain those outputs until a valid window-close receipt and
coordinator publication decision. Their native observation timestamps MAY be
retained as evidence but MUST NOT replace the declared logical boundary.

The baseline defines a temporal membrane around the participant. It does not
pretend every output physically occurred at the end of the interval. An
implementation may define a finer, qualified subwindow policy, but that policy
is a distinct capability and requires its own complete input closure and causal
authorization. The baseline cannot acquire finer timing through ad hoc timestamp
rounding.

**[CN-QUANT-5]** A connection to a quantized consumer MUST explicitly select an
input conversion rule. The baseline rule samples an event at the earliest
consumer boundary at or after its modeled arrival that has not yet activated.
Exact-boundary arrivals MUST be included in that boundary's complete batch.
The coordinator MUST NOT execute the next interval before equal-boundary
producer windows and due deliveries are settled.

The conversion adds a defined delay. It is not exact delivery at the source
timestamp. A scenario requiring exact 325-picosecond delivery cannot silently
accept sampling at 1,000 picoseconds. Graph admission must either obtain explicit
acceptance of the quantized conversion or refuse that connection.

**[CN-QUANT-6]** All events in a sampled boundary batch MUST retain original
producer identity, logical publication timestamp, connection conversion, and
sequence. Batch ordering MUST use the world's canonical policy. Coalescing,
dropping, saturation, and replacement of pending observations MUST be explicit
port semantics; a full adapter buffer MUST NOT silently discard state.

An output can therefore carry three distinct timestamps: physical observation,
logical publication, and sampled consumer delivery. The physical timestamp may
be unknown or uncertain. Only declared conversions determine the latter two.

## 4. Grant and Acknowledgment State Machine

The following states describe one node's baseline quantum participation. The
provider protocol may carry these as several operations, but must preserve the
same transition and ownership semantics.

```text
                 authorize complete start batch
     Closed(k-1) --------------------------------> Prepared(k)
                                                        |
                                                stage inputs ACK
                                                        |
                                                        v
                                                    Armed(k)
                                                        |
                                                 activate grant
                                                        |
                                                        v
                                                    Active(k)
                                                        |
                                          request stop/window close
                                                        |
                                                        v
                                                    Closing(k)
                                                        |
                                         owner + output closure ACK
                                                        |
                                                        v
                                                ClosedPending(k)
                                                        |
                                        validate and publish at B_(k+1)
                                                        |
                                                        v
                                                    Closed(k)

     Any uncertain active/closing transition -> ContainedFailure
```

**[CN-QUANT-7]** A quantum grant MUST bind realization identity, participating
node set, shared execution owner, owner generation, grid, quantum number,
logical interval, immutable start input batch, accepted mode, and operational
budget policy. A provider MUST accept a grant only from the applicable authorized
coordinator and MUST reject stale, conflicting, or widened grants.

**[CN-QUANT-8]** The provider MUST acknowledge input staging separately from
execution activation. Activation MUST NOT occur before the coordinator's grant
is fully input-authorized. Duplicate staging or activation requests MUST be
idempotent under the same grant identity; a changed batch under that identity
MUST be refused before further execution.

**[CN-QUANT-9]** At most one quantum MAY be active for a given execution owner in
the baseline contract. Public node facets sharing one simulator or physical
device MUST share that exclusivity. Preparation of later work MUST NOT cause
physical execution, input consumption, or logical publication for a future
quantum.

**[CN-QUANT-10]** A window-close receipt MUST bind the original grant, actual
owner generation, acknowledged execution or observation boundary, complete
ordered output batch, and disposition of all in-flight operations.
The receipt MUST distinguish a paused execution engine from a closed adapter
observation window whose physical device continues operating.

**[CN-QUANT-11]** The coordinator MUST validate closure before publishing outputs
or activating the next quantum. Outputs MUST remain in retained custody until
their publication is acknowledged or the attempt is contained.
A request to stop, an expired host timer, or an empty transport queue MUST NOT be
treated as a valid closure acknowledgment.

**[CN-QUANT-12]** A duplicate close, receipt, or publication acknowledgment MUST
recover the same retained result without rerunning native work or duplicating
effects. Loss of the provider after uncertain physical execution MUST NOT be
recovered by automatically rerunning the quantum against external state.

This state machine deliberately separates physical completion from semantic
commitment. A fast KVM node can finish its host slice and wait in
`ClosedPending(k)` while a gem5 producer is still calculating. Its output becomes
visible only when the world has a safe publication boundary.

## 5. Safe Progress Relative to Slower Producers

**[CN-QUANT-13]** A quantized node MUST NOT activate an interval while a producer
can still supply an input required in that interval's start batch.
Authorization MUST consider all relevant ports and effective connections,
including quiet producers with unresolved windows. Node speed, host deadline,
and lack of observed traffic MUST NOT replace producer closure.

**[CN-QUANT-14]** An exact consumer of quantized output MUST use the quantized
producer's earliest possible publication boundary plus the connection's qualified
minimum latency as a causal bound. It MUST NOT advance past that bound until the
producer closes the window and the coordinator resolves the actual output set.
A boundary with no output becomes safe only after a qualified empty closure.

**[CN-QUANT-15]** Quantization MUST apply at the declared connection boundary;
it MUST NOT coarsen unrelated exact node execution or exact-to-exact traffic.
An exact node MAY process finer events within a granted safe window, provided
it stops or input-parks before unresolved quantized publication can affect it.

### 5.1. Two-Way Mixed Example

Let `K` be a quantized compute node with `Q = 1,000,000 ps` and phase zero.
Let `G` be an exact detailed CPU node with 10-picosecond execution resolution.
Both directions have 100,000 picoseconds of modeled minimum latency.

```text
world ps:     0           1000000  1100000             2000000
K interval:   [ quantum 0 )        [ quantum 1 starts at 1000000 ]
K output:                   publish
K -> G:                     |--d-->| earliest arrival
G exact:      fine events ... stop before 1100000 until K closes
G -> K:       output at 300000 + 100000 = arrival 400000
K sampling:   arrival 400000 is staged at boundary 1000000
```

`K` may run quantum 0 only after its initial input batch at zero is complete.
It may finish its native slice quickly, but cannot activate quantum 1 until
`G` has closed all production that could arrive for sampling at 1,000,000.
In this example that requires an adequate bound on `G` through the source times
that can arrive by 1,000,000, accounting for equality and the 100,000 latency.

`G` can continue its fine internal events while protected by `K`'s earliest
possible publication at 1,000,000 plus latency. Without input-blocked parking,
its regular 10-picosecond grid permits an ordinary safe stop at 1,099,990.
Once `K` closes and its actual output is delivered at 1,100,000, `G` can receive
that event and advance further. No system-wide one-microsecond event grid is
introduced.

The `G` output at 300,000 arrives at `K` at 400,000 but cannot alter already-active
quantum 0. The selected sampling rule assigns it to `K`'s complete start batch
at 1,000,000. That is an explicit coarse input semantic accepted by the scenario.

### 5.2. Two Quantized Peers

For two zero-phase nodes using the same quantum and zero modeled connection
latency, the baseline forms a one-quantum interaction delay:

```text
boundary:       B0              B1              B2
node A:         sample/run 0    sample/run 1     sample/run 2
node B:         sample/run 0    sample/run 1     sample/run 2
A output 0:                    publish -> B input 1
B output 0:                    publish -> A input 1
```

Both quantum-0 output windows must close before either quantum-1 input batch is
committed. Zero transport latency does not allow output from the middle of one
active quantum to influence its peer's same quantum. This is a deliberate
boundary model, not a claim of continuous-time hardware interaction.

**[CN-QUANT-16]** Equal-boundary publication and next-interval input sampling
MUST complete under one defined coordinator arbitration order. Mutual end-output
to-next-start connections MUST NOT require either peer to start the next quantum
to close the preceding one. A connection policy introducing same-boundary
feedback MUST use the qualified same-time arbitration rules of the exact timing
chapter or be refused.

## 6. Different Grids and Phases

**[CN-QUANT-17]** A connection between different quantized grids MUST bind the
source publication rule, modeled latency, destination sampling rule, and
equality policy. The coordinator MUST compute the earliest unactivated
destination boundary at or after the modeled arrival using checked arithmetic.
There is no implicit requirement that the entire world use a common quantum.

For a destination grid with phase `P` and duration `Q`, sampling an arrival `a`
uses the least admissible boundary `b >= a`. If `a <= P`, the first boundary is
`P`; otherwise the checked quotient/remainder calculation determines the first
boundary at or after `a`. This conversion must not be implemented by overflowing
`a + Q - 1`.

### 6.1. Worked Example: Offset Destination

A source publishes at 1,000 picoseconds. Latency is 150. The destination uses
boundaries 250, 750, 1,250, 1,750, with `Q = 500` and `P = 250`.

```text
source publication:          1000
modeled arrival:             1150
destination boundaries: 750        1250        1750
sampled destination input:        1250
added sampling delay:               100 ps
```

If the source instead produces a modeled arrival exactly at 1,250, it belongs to
the start batch at 1,250. The destination cannot activate that batch while the
source window capable of such arrival remains unresolved. If a provider has
already activated it despite the missing bound, the failure is a violated
contract, not permission to move the input to 1,750.

**[CN-QUANT-18]** A grid conversion MUST NOT silently reinterpret the source's
minimum latency or turn a physical observation uncertainty interval into an exact
timestamp. Connections requiring a maximum logical delivery delay MUST be
admitted only if the declared grids, sampling policy, buffer policy, and producer
closure behavior can satisfy that bound.

## 7. Host Budgets, Pacing, and Missed Deadlines

Host runtime budgets are operational controls. They can request a hardware node
to stop after an elapsed host duration, a permitted work amount, or a
profile-defined marker. They cannot prove an exact simulation stop by themselves.

**[CN-QUANT-19]** A host budget MUST state its clock source, measurement scope,
stop mechanism, permitted overrun policy, and diagnostic progress measurements.
A measured or configured stop latency MUST NOT be advertised as a hard bound
unless independently qualified as such. CPU quota exhaustion or a timer kick
MUST NOT authorize the provider to acknowledge physical pause before it occurs.

**[CN-QUANT-20]** Meeting a wall-clock deadline MUST be a separate capability and
admission requirement from preserving logical causality. A world MAY execute
slower than real time while preserving the declared quantized interaction model.
A physical participant that requires real-time service MUST refuse admission
when the realized execution policy cannot meet its qualified requirements.

**[CN-QUANT-21]** A missed operational deadline MUST have a declared outcome:
stall while retaining custody, contain and cancel the attempt, or fail the
operational execution. It MUST NOT silently shift a logically due event into a
committed later window. The miss alone MUST NOT be reported as an application
assertion failure.

A scenario can deliberately assert that an application responds within a
modeled interval. That finding requires evidence under the admitted timing
contract. Host starvation while a detailed simulator runs is not automatically
evidence of the application's modeled deadline failure.

**[CN-QUANT-22]** Cancellation MUST retain owner exclusivity until physical stop
or observation containment is acknowledged. Unstoppable or disconnected hardware
MUST be isolated from affected scenario connections before cancellation can
release their authority. Uncertainty about an externally issued write MUST NOT
be resolved by retrying it as though no write happened.

## 8. Clock Control and KVM-Class Compute

**[CN-QUANT-23]** A hardware-accelerated compute realization advertising
controller-owned guest time MUST cover all admitted guest-visible time sources
and timer effects in its ownership map. Changing one paravirtual clock while
timestamp instructions or device timers continue on a different timeline MUST
NOT satisfy a coherent clock-control capability.

Coverage includes the architecture's counters, paravirtual clocks, interrupt
timers, emulated device timers, RTC behavior, and modeled devices. The selected
policy can be continuously paced, frozen between grants, or advanced at
boundaries, but the guest-visible consequences must be explicit and qualified.

**[CN-QUANT-24]** Setting a counter offset, frequency, or guest clock epoch MUST
NOT be represented as instruction-exact execution control. A KVM-class provider
MUST NOT advertise an exact grant ceiling from ordinary host timer kicks,
signals, or measured average exit latency. It MAY expose exact timing only after
the complete realization qualifies an execution mechanism satisfying the exact
contract independently of those measurements.

**[CN-QUANT-25]** Clock jumps and idle skipping MUST be different operations.
A clock jump changes observed time without executing skipped guest work and
MUST be a declared scenario effect. Idle skipping MAY occur only when complete
wake and input closure prove that no runnable transition is skipped.
Clock control alone MUST NOT imply deterministic CPU execution or exact future
continuation after capture.

The amount of native execution during a logical quantum is intentionally
nondeterministic in the baseline hardware mode. Physical caches, scheduling,
interrupt timing, and execution resources can change it. A stable logical clock
does not remove those dependencies.

## 9. Autonomous and External Physical Devices

**[CN-QUANT-26]** An external-device adapter MUST declare the scope it mediates:
commands, observations, physical side effects, and connections to other
participants. It MUST distinguish physical pause, input isolation, observation
window closure, and buffered logical publication. Closing an adapter window
MUST NOT be claimed to stop an autonomous device's internal activity.

**[CN-QUANT-27]** Physical effects outside mediated scope MUST NOT influence
other scenario nodes through undeclared paths. Direct shared memory, DMA,
uncontrolled network paths, shared mutable storage, passthrough interrupts, and
physical couplings MUST be isolated, represented as admitted connections, or
cause refusal of the claimed causal contract.

A USB adapter can retain a device response until a logical boundary while the
device's internal firmware keeps running. It can satisfy observation publication
semantics if every relevant interaction is mediated. It cannot claim that the
response's physical generation time equals the publication boundary, or that a
physical actuator affecting another participant has been delayed merely because
its software acknowledgment was buffered.

**[CN-QUANT-28]** A physically irreversible command MUST have an explicit
physical issue policy separate from logical publication. If issue occurs during
an active window, its causal influence MUST remain within the admitted mediated
scope or be modeled as an autonomous physical effect with appropriate timing
uncertainty. Transactional rollback MUST NOT be claimed for an effect that the
provider cannot reverse.

**[CN-QUANT-29]** Autonomous observation windows MUST bind their physical
observation interval, clock provenance, closure mechanism, and classification
rule for observations racing a boundary. Uncertain observations MUST retain
uncertainty or be assigned according to an explicit accepted coarse policy.
Transport receipt time MUST NOT be relabeled as precise physical occurrence.

An adapter may close successive observation windows while awaiting logical
publication, subject to bounded storage and the scenario's accepted policy.
Those physical windows are not extra logical grants. The device may have evolved
while the logical world was stalled, and its next interaction must retain that
fact rather than pretending the device was frozen.

**[CN-QUANT-30]** Backpressure and observation retention MUST be qualified for
the selected physical participant. If the adapter cannot retain a required
observation while slower producers catch up, it MUST refuse admission or use an
explicitly accepted loss/aggregation policy. Exhausting an advertised retention
bound MUST produce a defined operational outcome before causal guarantees are
silently lost.

## 10. Capture, Determinism, and Conditional Replay

**[CN-QUANT-31]** A quantized capture MUST identify every closed, prepared,
active, closing, and unpublished window, together with input batches, output
custody, grids, owner generations, and physical pause or observation status.
An exact world capture MUST be refused if any participating owner cannot preserve
the required continuation or isolate its external effects at that cut.

A closed logical window is a useful capture boundary, not proof that a physical
CPU or external device is exactly restorable. A weaker smoke-test snapshot must
declare its architectural/device scope and possible future nondeterminism under
the state contract. It cannot masquerade as the same exact capture type.

**[CN-QUANT-32]** Any admitted nondeterministic participant MUST taint the
interacting world's determinism guarantee unless a stronger isolation or
recorded-boundary qualification proves otherwise. Quantized boundary ordering
MUST NOT by itself restore a deterministic-world claim.

**[CN-QUANT-33]** Conditional replay MAY replace a nondeterministic participant
with its recorded boundary behavior only when the recording retains all relevant
inputs, outputs, timing conversions, sequences, external side effects, and
closure decisions. Replay MUST verify the required inbound interaction prefix
and refuse divergence. It MUST NOT claim validity for arbitrary counterfactual
input or reconstruct unrecorded physical occurrence timing.

**[CN-QUANT-34]** Native clock policy, host budget policy, boundary conversion,
recording status, and accepted nondeterminism MUST be included in execution
identity and reproduction metadata. A quantized attempt MUST NOT populate a
deterministic result cache under a planned scenario/configuration identity alone.

## 11. Required Admission and Runtime Refusals

The admission layer must detect incompatible declarations before physical
activation. Runtime checks remain necessary because a qualified participant can
fail or lose custody after admission.

**[CN-QUANT-35]** The executor MUST refuse unsupported exact input requirements,
incomplete start batches, unknown producer windows, undeclared grid conversion,
hidden effect paths, unsupported physical retention, unqualified clock coverage,
and requested capture stronger than the participant supports. Runtime receipt
violations, late input to an activated boundary, and uncertain physical ownership
MUST terminate or contain the affected attempt according to policy.

**[CN-QUANT-36]** A refusal or failure MUST retain the requested and admitted
mode, node and port identities, relevant quantum/grant identity, blocking bound
or window, and the operational classification. The executor MUST NOT silently
fall back to coarse timing, cold restart, lossy buffering, or unrecorded physical
execution to finish a scenario.

These refusals make the mode useful: a fast node can finish work early and wait,
an exact node can use finer safe windows, and a physical device can advertise
only the scope it actually controls. Every connected participant remains subject
to the same prohibition on outrunning an input its admitted semantics require.
