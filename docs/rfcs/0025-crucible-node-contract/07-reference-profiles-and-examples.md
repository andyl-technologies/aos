# 7. Reference Profiles and Interoperable Examples

## 7.1. Status and interpretation

This chapter specifies target provider profiles. A profile states requirements
for an implementation to claim a particular contract; its presence in this RFC
does not establish that a packaged provider has passed qualification. The
conformance evidence required by [Chapter 8](08-conformance.md) identifies the
implemented build, configuration, devices, and permitted operating modes.

The examples illustrate composition rather than production deployment files.
Declaration fragments omit required identities, resource limits, content
references, and other fields where explicitly stated. They are not complete
manifests, deployable configurations, or capability advertisements.

**[CN-PROFILE-1]** A provider claiming a reference profile MUST implement every
requirement of that profile for its admitted configuration. It MUST NOT replace
a required device, state domain, or execution guarantee with an unsupported
capability entry while retaining the profile claim. A partial development
implementation MAY expose its implemented subset under a distinct identity.

**[CN-PROFILE-2]** Profile conformance MUST bind the implementation, configuration,
role set, ports, execution owners, capture owners, and capability manifest.
Changing any admitted contract MUST cause re-admission or refusal according to
[Chapter 2](02-ports-capabilities-and-admission.md). Equal instruction-set names
or equal executable hashes do not establish equal execution modes.

The examples use picoseconds as the common coordinate. Quantities described as
cycles, architectural counter values, or retired instructions are distinct
measurements. Providers perform explicitly admitted conversions; the
coordinator does not derive elapsed time from a universal instruction cost.

## 7.2. Reference profile matrix

| Profile | Roles and principal ports | Execution and state requirements |
| --- | --- | --- |
| Host block | Block service; request and completion ports | Deterministic service, exact logical completion, complete model capture and isolated fork |
| Host 9p | Filesystem service; request and reply ports | Deterministic namespace/session behavior, exact visibility, complete model capture and isolated fork |
| Host link | Network transport; frame ingress and egress | Declared lookahead, exact delivery ordering, complete link/queue/fault capture |
| Host clock | Clock source; read/control/alarm ports | Declared clock mapping, exact alarms, complete transform and synchronization capture |
| QEMU-SIM exact machine | Compute composite and declared device frontends | Exact admitted boundaries, repeatable execution, exact durable continuation and isolated fork |
| gem5 detailed exact machine | Compute composite and declared device frontends | Detailed configured timing, exact admitted boundaries, full modeled state preservation and supported-device parity |
| KVM quantized machine | Compute composite and declared device frontends | Acknowledged coarse windows, controlled clock contract, explicit nondeterminism and consistent exposed-state capture |
| Mediated physical USB adapter | External-device mediation; USB transfer/control ports | Bounded publication, physical observation provenance, no claim to pause or rewind the physical endpoint |

"Exact" in the machine profiles covers the declared execution boundary and
modeled state. It does not mean a timing model accurately reproduces every
commercial processor. A deterministic fixed-cost machine and a deterministic
pipeline model can both conform to exact state preservation while producing
different guest timing and different executed instruction sequences.

## 7.3. Host-modeled block and filesystem services

The block node owns immutable image identity, private mutable media state,
volatile write state, durability frontiers, request identities, queue ordering,
fault rules, and pending responses. The guest-facing controller belongs to a
compute composite and communicates with this node through a typed connection.
The filesystem node similarly owns its namespace, session and fid state,
visibility policy, object versions, outstanding operations, and pending replies.

Neither host service obtains guest-visible timing from host wall-clock duration.
It may compute a response before its modeled completion coordinate, but that
response remains invisible until the coordinator admits delivery. Host work
completion and modeled operation completion are distinct events.

**[CN-PROFILE-3]** A host block or filesystem provider MUST retain request and
completion identity across compute, fault evaluation, deferral, capture, restore,
and delivery. Backpressure MUST retain the original response and ordering key;
it MUST NOT allocate a replacement identity or silently discard a completion.

The finite admitted block operation set specifies read, write, flush, discard,
length/configuration queries, barriers, and any additional advertised operation.
Its contract defines sector geometry, range validation, partial-error behavior,
volatile state, durable completion, and reset/power-loss treatment. A flush reply
does not imply durability unless the admitted durability contract says so.

The filesystem contract identifies the wire dialect, operation set, bounds,
namespace rules, permissions, cancellation semantics, and visibility ordering.
Serving an uncontrolled host directory is not equivalent to serving a pinned
modeled tree, even if a simple file-read test succeeds on both.

**[CN-PROFILE-4]** Each service MUST expose a finite operation and fault capability
set with its supported phases and evidence schema. Unsupported operations MUST
receive the admitted protocol error or fail admission; providers MUST NOT
substitute host passthrough. An exact capture MUST include queued operations,
pending fault opportunities, completed-but-undelivered responses, and all state
that determines their future payload, timing, visibility, or persistence.

The same semantic block node can be connected to a QEMU or gem5 controller.
Changing the controller binding does not permit reuse of a foreign machine
snapshot. The host service's own snapshot can be reused only when its owner,
implementation, admitted bindings, and capture contract independently permit it.

## 7.4. Host-modeled network link

A link owns the modeled transmission, queue policy, serialization progress,
fault state, sequence allocation, and in-flight deliveries. Its endpoints are
typed ports; they need not belong to compute machines. A single logical
bidirectional link can contain two directed services while retaining a declared
shared random stream or shared-medium state.

**[CN-PROFILE-5]** A link MUST declare its guaranteed minimum externally visible
latency or other conservative advancement contract. It MUST preserve original
frame identity, payload, fault continuation, and delivery ordering through
capture and fork. A minimum latency MUST NOT be invented to avoid a zero-delay
causal dependency.

A loss decision, duplicate, corruption, queue overflow, or availability change
produces evidence according to its admitted fault schema. Link-model decisions
are coordinator-visible behavior. Host socket readiness is a transport fact,
not a model decision and not a source of link latency.

Changing a live link policy can change lookahead. The coordinator applies the
new bound at the admitted boundary before granting further execution. Pending
frames retain or re-evaluate previously selected policy only as explicitly
specified by the transition contract.

## 7.5. Host-modeled clock node

A public clock node represents a source visible to consumers: an oscillator,
counter, RTC, synchronization source, or device-specific timebase. Its modeled
state can include phase, frequency ratio, epoch, drift contributors, source
selection, monotonicity handling, alarms, synchronization exchanges, and faults.

The common simulation coordinate is not another such device. SharedTimeline
and SimInstant belong to the coordinator. A clock node maps that coordinate to
an observed reading and maps programmed alarms back to admitted event bounds.

**[CN-PROFILE-6]** A clock node MUST NOT become an alternate authority for the
coordinator frontier. Changing a guest-visible clock MUST NOT move common time
backward or weaken an outstanding execution grant. Its declared alarm mapping
MUST prevent the provider from passing an externally visible alarm boundary.

For example, a source running at 4 GHz exposes four counter increments per
nanosecond while a compute model may complete no instruction during that span.
A source with a declared +100 ppm drift has a different rational mapping.
Neither relationship implies a universal instruction-retirement rate.

Reads, synchronization, clock faults, and alarm changes participate in the
same port/event ordering as other interactions. A source that permits wrapping
or backward readings declares that behavior without changing coordinator time.
Capture includes the last observed value when monotonic clamping depends on it.

## 7.6. Supported machine/device parity

The common machine profiles cover the Crucible-supported machine and device
profiles for each ISA. They do not require implementation of every peripheral
available in upstream QEMU. Profile versions enumerate supported combinations,
including optional devices, supported transports, and feature limits.

The initial parity roster corresponds to the supported q35 x86-64 and `virt`
AArch64 machine families. The selected manifest pins a specific version and
realized device inventory; the family name alone is not a compatibility key.
For q35 this includes the memory/PCI host, LPC, DMA, CMOS/RTC, PIC/IOAPIC/APIC,
PIT/HPET, speaker, keyboard/mouse controller, port92, AHCI, SMBus/EEPROM and
firmware-discovery state where realized. The Arm roster includes its selected
GIC, architectural timer, PL011, PL031, flash, PCI host, GPIO and firmware
discovery devices. The common optional attachment roster adds virtio block,
9p, network, entropy, debugger serial and the co-simulation accelerator.

This is a bounded compatibility commitment, not permission to omit a realized
but unused chipset device. Complete profile definitions bind addresses, IDs,
feature sets and behavior; these illustrative lists do not replace them.

**[CN-PROFILE-7]** A common machine profile MUST enumerate the guest-visible ABI
of every realized device, including devices supplied by the platform rather
than explicit scenario attachment. A provider claiming parity MUST implement
that ABI and the scenario-facing service contract. It MUST NOT silently replace
virtio-net with an unrelated Ethernet controller, virtio-blk with IDE, or one
platform's firmware/device map with another platform's map.

The parity inventory includes the following categories:

| Category | Required contract coverage |
| --- | --- |
| x86-64 platform | Admitted CPU features, memory/PCI map, firmware tables, APIC/PIC/IOAPIC routing, RTC, PIT, HPET, ACPI timer, and declared chipset devices |
| AArch64 platform | Admitted CPU features, memory/PCI map, firmware/DT discovery, GIC, architectural timer, UART/RTC, flash and declared GPIO/platform devices |
| Block frontends | Guest IDs/configuration, negotiated features, queues, DMA, status, flush/barrier/durability interpretation, discard and reset |
| Network frontends | Guest IDs/configuration, features, framing, queues, offloads, RX backpressure, TX completion and interrupt behavior |
| Filesystem frontends | Transport features, mount identity, request/reply framing, cancellation, queue/reset state and host namespace/session semantics |
| Entropy/firmware input | Admitted fw_cfg or equivalent ABI, seed contents, RNG stream/state, rate limits and pending requests |
| Serial/debug channels | UART or virtio-console ABI, output ordering, declared input policy, named ports and activation/introspection behavior |
| Co-simulation accelerator | Custom device ABI, job schema, submission/cancellation, queues, DMA, completion, reset and fault effects |
| Whitebox channels | Frozen ISA doorbell/register ABI, memory validation, markers, selectable requests, application randomness and pending replies |

Modern virtio support, where required by a selected profile, includes the
transport capability layout, feature negotiation, queue configuration and reset,
descriptor validation, DMA ordering, interrupts and completion semantics. A
provider must not infer modern transport support from a legacy device's ability
to boot one guest driver. Optional transport variants have separate identities.

**[CN-PROFILE-8]** Frontend parity MUST include pending state and observable
ordering, not just register access and successful I/O. Required capture coverage
includes negotiated features, virtqueue state, outstanding DMA, pending IRQs,
barriers, reset transitions, frontend-owned requests, and host-owned service
continuations. Device faults MUST produce the declared phase-specific effects
and evidence, including memory/DMA and interrupt consequences.

Guest ABI, modeled behavior, and timing fidelity are separate contracts.
Different admitted timing models can share a device ABI while exposing different
modeled DMA or bus latency. Such differences must be declared and qualified.
Uncontrolled host timing is not an alternative detailed device timing model.

## 7.7. QEMU-SIM exact composite

The QEMU-SIM provider exposes a compute composite with internal CPU, memory,
interrupt, bus and guest-device children. The native execution owner advances
that composite atomically within the admitted grant. Host-modeled disks,
filesystems and links are external participants unless a particular manifest
explicitly binds them into the same state owner.

The profile admits only configurations whose complete native timing and input
boundaries can be observed and controlled. Fixed-cost instruction timing is one
versioned timing model, not part of the universal node shape. The profile binds
the accelerator/mode, ISA, CPU model, machine ABI, clock model and source build.
Uncontrolled host input, mutable unpinned backing, unowned asynchronous workers,
or unsupported device/capture paths make a configuration ineligible for this
exact profile; mode admission cannot infer safe behavior from an unused path.

**[CN-PROFILE-9]** The exact QEMU-SIM profile MUST provide repeatable execution,
exact modeled-state continuation after persistent capture/restore, and isolated
fork of admitted mutable state and resources. A live template fork alone MUST
NOT be advertised as durable capture. No execution or capture operation may
independently advance an internal child of the same composite owner.

Native QEMU/plugin frontend code remains in its applicable GPL-compatible
scope. Apache host services communicate only through the versioned process
protocols. The common node manifest does not authorize linking Apache-only
crates into QEMU or transferring private native structures across shared memory.

## 7.8. gem5 detailed exact composite

The gem5 exact profile uses the same semantic compute/device node shapes. Its
provider binding selects the native CPU model, ISA frontend, memory hierarchy,
coherence protocol, device timing models, implementation and configuration.
These choices contribute to identity and qualification independently.
Admitted event-queue/thread arrangements, host dependencies, PRNG initialization,
memory mappings and external resources are explicit configuration restrictions.
Only combinations with qualified event ordering and capture coverage claim the
exact profile; supporting a CPU model in a standalone simulator is insufficient.

The target x86-64 and AArch64 profiles require the full supported machine/device
parity described above. An integration limited to kernel boot or architectural
register checkpoints does not satisfy this profile.

**[CN-PROFILE-10]** A gem5 exact capture MUST preserve every modeled state domain
that affects future execution, observations, or timing. It MUST retain exact
event ordering and pending work without drain, writeback, warm-up, or elapsed
simulation inserted by the capture operation. It MUST support persistent
restoration and isolated fork for the admitted configuration.

The required domains include architectural and speculative register state,
decoder/microcode state, pipeline buffers, rename/retirement state, instruction
and load/store queues, branch prediction, caches and replacement metadata,
TLBs and page walks, coherence transients, memory-controller scheduling and
refresh state, native event queues, PRNG state, devices, DMA and interrupts.
References and sharing in the native object graph must be restored consistently.

Stock gem5 checkpointing is not evidence for this requirement. In the audited
upstream revision, the Python checkpoint path drains and writes memory back;
O3 thread serialization preserves architectural thread context, and classic
cache serialization does not preserve cache contents. These are narrower
operations than this target profile's exact continuation requirement.
See the pinned [checkpoint path][gem5-checkpoint],
[O3 thread serializer][gem5-o3-state], and [cache serializer][gem5-cache-state].

Stock gem5's external 9p proxy also warns that checkpointing a used device can
lose state. A conforming adapter must implement the required owned filesystem
continuation rather than treating this warning as an acceptable parity limit.
See the pinned [9p serialization implementation][gem5-ninep-state].

A no-drain in-memory process fork may be useful implementation machinery, but
does not alone establish persistent capture. It must also isolate descriptors,
shared mappings, writable backing, workers and external services. An exact
profile cannot rely on unrecorded state in a surviving seed process after that
process is gone.

## 7.9. KVM quantized composite

The KVM profile preserves the compute/device shape while selecting hardware
execution with a distinct execution guarantee. It uses admitted coarse windows
and acknowledged stopping/publication boundaries. This is useful for smoke
tests and application/image validation, without claiming instruction-exact
repeatability or detailed physical CPU state preservation.

**[CN-PROFILE-11]** A KVM provider MUST declare its quantum, window-phase policy,
clock model, stop acknowledgement, publication rules, exposed-state capture and
nondeterminism scope. Assigning a timestamp to a response MUST NOT be treated
as evidence that hardware execution obeyed an exact simulated-time ceiling.
Physical CPU caches, predictors and pipelines MUST NOT be advertised as captured
modeled state when the provider cannot observe and restore them.

The admitted clock contract covers all enabled guest clock/counter and timer
sources. A fixed RTC epoch alone is insufficient. The implementation must
define suspension, resumed rate/offset behavior, timer injection, and how guest
polling progresses while the virtual execution window is active.

Consistent capture requires actual stopped vCPUs, completed architectural I/O
exit state, interrupt/device state, RAM, storage bindings, transport custody and
clock origins. The capture declares the possibility of different future timing
and execution. Fork restoration creates independent resources rather than
assuming inherited hardware VM descriptors establish an isolated child.

**[CN-PROFILE-12]** Idle advancement MAY occur only when the admitted provider
establishes complete idle and deadline knowledge. Executing faster to a boot
marker is not idle advancement. Neither operation authorizes cross-provider
snapshot restore or upgrades a hardware-executed prefix to deterministic replay.

## 7.10. Mediated physical USB adapter

This profile enrolls a mediation node around an actual USB endpoint. Typed
transfer and control ports describe the selected USB protocols, endpoints,
ordering and flow control. The adapter owns its observed/control queues and
publication policy; it does not own the physical device's internal execution.

**[CN-PROFILE-13]** A mediated physical adapter MUST declare which interactions
are controlled and which observations originate externally. Pausing the adapter
MUST NOT be reported as pausing the physical endpoint. Capturing an adapter
queue MUST NOT be advertised as an exact capture of the physical device.

For example, pausing publication from a USB temperature sensor stops the
scenario from receiving measurements but does not stop sensing. Observations
arriving during the pause follow the declared queue/overflow policy. Resume
cannot retroactively assign controlled production times to those measurements.

Captured observations can later be supplied by a replay node from an immutable
trace. This is a new provider binding with conditional reproducibility. It does
not prove that re-running the physical sensor will produce the same readings.
Outbound commands that change a device are recorded as external effects; a
logical branch cannot undo a command already delivered to real hardware.

**[CN-PROFILE-14]** A scenario requiring exact physical-device rewind or isolated
physical branching MUST be refused unless that endpoint has an independently
qualified mechanism implementing those guarantees. Observation buffering and
trace replay MUST NOT be substituted for such a mechanism.

## 7.11. Ownership declarations

The following views summarize bindings; complete declarations additionally carry
the identities and limits specified by Chapters 1, 2 and 6. An execution owner
can service several semantic children without creating another OS process.

| Semantic node | Execution owner | Capture owner | Ownership boundary |
| --- | --- | --- | --- |
| `compute-a` | Native machine A | Native machine A | CPU, RAM, internal clocks/controllers/frontends |
| `compute-b` | Native machine B | Native machine B | CPU, RAM, internal clocks/controllers/frontends |
| `shared-disk` | Host storage service | Host storage service | Shared medium, durability and authoritative request state |
| `wire-ab` | Host link service | Host link service | Link policy, shared RNG, queues and deliveries |
| `reference-clock` | Host clock service | Host clock service | Public source mapping, alarms and fault/synchronization state |

This JSON is a partial selected realization view using Chapter 2's declaration
names. Identity references, model configuration, schema references, selected
capabilities, cancellation, connection limits and several required port fields
are omitted. It is neither a complete manifest nor a CNP message. The two
controllers connect to this one storage port under an explicitly admitted
multiple-client arbitration contract.

```json
{
  "id": "shared-disk",
  "roles": ["storage"],
  "operating_contract": { "timing": "exact" },
  "execution_owner": "storage-owner",
  "capture_owner": "storage-owner",
  "ports": [
    {
      "port_id": "block",
      "interface_id": "core.block/1",
      "lanes": [
        {
          "lane_id": "request",
          "direction": "input",
          "protocol_id": "core.block/1",
          "semantic_version": "1.0.0",
          "payload_bounds": { "maximum_message_bytes": "65536" },
          "queue_bounds": { "maximum_messages": "32" },
          "flow_control": "credit",
          "ordering": "per-client-fifo",
          "visibility": "exact",
          "minimum_lookahead": "0"
        },
        {
          "lane_id": "completion",
          "direction": "output",
          "protocol_id": "core.block/1",
          "semantic_version": "1.0.0",
          "payload_bounds": { "maximum_message_bytes": "65536" },
          "queue_bounds": { "maximum_messages": "32" },
          "flow_control": "credit",
          "ordering": "correlated-completion",
          "visibility": "exact",
          "minimum_lookahead": "1000"
        }
      ]
    }
  ]
}
```

The illustrated 1,000 ps completion lookahead is a model restriction: every
operation admitted in this view has at least that delay. A profile permitting
zero-delay status or cancellation replies must select a corresponding zero
bound or a separately bounded lane; the example is not a universal disk bound.

**[CN-PROFILE-15]** Every mutable state domain MUST have one authoritative capture
owner. Internal children reference their composite capture rather than creating
duplicate restore authority. Imported queue observations, frontend metadata and
coordinator event records MUST NOT be used to instantiate another authoritative
copy of the same host device state.

Persistent capture is a graph-wide operation over a consistent cut. Each owner
is captured once and referenced by every dependent child. Persistent restore
validates the whole graph before activating resources, restores each owner once,
and reconnects transport bindings without replaying already committed effects.
Fork creates private mutable state while allowing immutable content sharing.

## 7.12. Worked exact mixed-provider exchange

Let `compute-a` use the QEMU-SIM exact binding and `compute-b` the gem5 detailed
exact binding. Their ports carry the same admitted Ethernet frame schema.
Their private CPU/device states and fingerprints have different implementations.
Both participate in one common timeline and the same host link node.

At common time 1,250 ps, A emits frame F. The admitted directed link adds a
minimum and selected delivery latency of 300 ps. The link retains F and its
delivery key at 1,550 ps. B cannot advance past that dependency before consuming
the delivery at its admitted input boundary.

Suppose B processes the packet and emits reply G at 1,800 ps. A 300 ps reverse
link schedules G at 2,100 ps. A's next grant is constrained by that reply and
all other native/input bounds. B may have stalled during this interval; no
instruction-count equality between A and B is required.

**[CN-PROFILE-16]** Mixed exact providers MUST obey the same cross-node event
ordering and grant semantics. Matching timestamps MUST NOT substitute for
authentic input custody or stopped-boundary evidence. Provider-specific internal
ordering MUST be preserved within the composite and must produce external
events consistent with the admitted common ordering contract.

Capturing at the resulting cut captures A, B and the link once per owner, plus
coordinator state. A frame still in a frontend TX queue, a frame held by the
link, and a frame already admitted to RX are distinct custody states. A capture
must preserve which owner actually holds F or G; it must not deliver another
copy simply because the same payload appears in observation evidence.

## 7.13. Worked quantized bidirectional exchange

Let K use a KVM quantized binding with a 1,000,000 ps publication quantum. Let S
use an exact provider whose local model can advance at picosecond boundaries.
S remains an exact participant; interactions through K's ports have the
separately admitted coarse timing contract.

For illustration, a coarse connection projects an eligible logical delivery t
to the next declared boundary, `ceil(t / 1,000,000) * 1,000,000` ps. It preserves
the eligible coordinate and records the projection; it does not relabel that
eligible coordinate as an exact hardware production time.

S emits at 1,250,000 ps and the modeled link supplies 250,000 ps latency.
Eligible delivery is 1,500,000 ps; the admitted K-facing delivery boundary is
2,000,000 ps. K receives it while stopped, before its next admitted execution
window, after the coordinator establishes complete input closure for that
boundary. The extra 500,000 ps is declared quantization, not hidden host delay.
If that window was already activated, the provider refuses the late input;
it does not silently move it to the next boundary.

If K reports an output under its 2,000,000-to-3,000,000 ps window, the adapter
publishes it according to that window's acknowledged boundary contract. With
publication at 3,000,000 ps and 250,000 ps link latency, S-facing eligibility is
3,250,000 ps. The fine consumer can accept the packet at exactly that coordinate
after complete closure authenticates K's publication. Coarse producer
publication does not force S's other events onto K's grid. An additional
connection quantizer, if explicitly modeled, would be a distinct admitted
projection rather than an implicit consequence of K's mode.

**[CN-PROFILE-17]** Coarse interactions in either direction MUST carry the admitted
projection/window policy and nondeterministic provenance. The coordinator MUST
prevent a fine participant from crossing a possible incoming coarse event
without the conservative closure required by Chapter 4. An absent published
output is not proof that an active hardware window cannot produce one.

The ceiling formula alone is not a safe advancement algorithm. The connection
also needs the declared lookahead, window closure, ordering and progress rules.
Zero-delay cycles require explicit causal serialization or another admitted
solution; rounding timestamps does not create positive causal lookahead.

## 7.14. Shared storage and composite capture example

A and B can attach separate guest controllers to `shared-disk`. Both controllers
forward requests to one authoritative host storage participant. The disk's
ordering/durability/fault contract handles concurrent requests; two frontend
connections do not create two independently writable copies of the medium.

A composite capture includes A's controller state and A's pending frontend
request references. B's capture includes the corresponding B state. The disk
capture includes the shared medium, pending requests and responses, durability
frontiers and faults. The connection captures account for transport ownership.
Each domain has one owner; cross-references are checked identities.

A branch that mutates the shared disk must isolate that branch's storage owner
from its parent and sibling branches. Within the branch, both A and B remain
attached to the same isolated disk owner. Sharing immutable base image bytes
does not authorize sharing the branch's writable overlay or queues.

## 7.15. Fresh-root performance-to-fidelity progression

A workload can run first under KVM smoke, then QEMU-SIM exact, then gem5 detailed
exact using the same source image and application inputs where their admitted
machine profiles permit them. These are fresh execution roots, with separate
provider manifests and evidence. Each run's observations carry its actual
timing, determinism, capture and ancestry contract.

**[CN-PROFILE-18]** A provider change MUST NOT be implemented as implicit restore
of a stateful artifact created by another implementation or execution mode.
Foreign provider/model/configuration identities MUST be refused before state
mutation. An explicit conversion or warm-up workflow, if supported, creates a
new root and records its source and weaker initialization lineage.

The following is a complete CNP/1 error-envelope example for a refused `begin`
request with kind `prepare_restore`. The request selected operation `restore-a`; this
response retains its operation and request identities. It reports that the
operation did not start, rather than leaving the coordinator to infer whether
state or external effects changed. The error details and extensions are empty.

```json
{
  "protocol": "CNP/1",
  "message": "response",
  "session_id": "session-a",
  "incarnation_id": "provider-a",
  "node_id": null,
  "execution_owner_id": null,
  "capture_owner_id": "machine-owner-a",
  "request_id": "request-17",
  "operation_id": "restore-a",
  "sequence": "18",
  "method": "begin",
  "body": {
    "status": "error",
    "operation_state": "not_started",
    "error": {
      "code": "STATE_BINDING_MISMATCH",
      "message": "state implementation binding differs",
      "effect": "not_started",
      "retryable": false,
      "details": {}
    },
    "extensions": {}
  },
  "extensions": {}
}
```

A KVM boot prefix followed by a detailed warm-up can be useful but is not the
same as an uninterrupted detailed execution. Warm-up establishes declared
initial microarchitectural state; it does not recover an unknowable physical
cache or predictor history. Future repeatability is conditional on that root.

The progression measures separate questions: whether the image boots and runs,
whether a scenario is repeatable under controlled execution, and how the chosen
processor/memory/device timing model affects behavior. No profile or example
implies that a more detailed model is faster or that boot success establishes
device, timing, snapshot, fault or interoperability conformance.

[gem5-checkpoint]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/python/m5/simulate.py#L401
[gem5-o3-state]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/cpu/o3/thread_state.cc#L57
[gem5-cache-state]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/mem/cache/base.cc#L2057
[gem5-ninep-state]: https://github.com/gem5/gem5/blob/f5c5a6e390f55dd5984977815bf9d0bd05da6945/src/dev/virtio/fs9p.cc#L230
