# Native QEMU construction epoch

The native initialization channel owns a finite, original construction callback
cut. It allows QEMU to finish enrolled administrative startup work before a
node can supply complete readiness evidence. Its result is separate from a
simulation execution grant, input delivery, world activation, physical pause,
or snapshot restoration.

## Original authority and process boundary

The installed provider authenticates the accepted Realize request and selected
construction policy. It pins their digests, the complete prepared owner scope,
the permitted callback classes, and the finite callback budget before QEMU
creates its startup coroutine. The public preparation includes the Realize
operation identity as well as the envelope digest; its commitment covers every
field and the unchanged original native preparation frame.

The early QEMU option has the closed form
`-crucible-node-initialization v1:<272 lowercase hexadecimal digits>`. Its 136
bytes contain scope, initialization commitment, original Realize digest, policy
digest, and little-endian class and budget fields. The source pre-parser runs
before subsystem initialization. Later GPL registration must match every early
field; it cannot adopt a late pin. Fresh construction refuses incoming state,
loadvm and preconfiguration paths.

The Apache host and GPL controller remain separate processes. Native callback
pointers, coroutine objects, timer lists and QEMU data structures stay GPL-side.
The public datagram edition uses separately encoded, bounded scalar records.
The V5 native resource manifest extends the unchanged V4 prefix with the actual
registered initialization commitment and bit 16. A declaration in plugin
arguments alone cannot produce that manifest.

## Finite enrolled callback classes

The initial class mask contains these source-specific single bits:

| Bit | Class | Required native predicate |
| --- | --- | --- |
| 1 | QMP dispatcher startup | Original never-entered dispatcher, no realized monitors or monitor I/O thread, no external monitor requests |
| 2 | Empty coroutine notification | Actual original scheduler notification with an empty coroutine list and counter |
| 4 | IDE zero-error restart | Actual original IDE bus restart with error status zero and no modeled pending operation |

A nonempty QMP startup scheduler is not an empty notification. Its coroutine
requires the real process home thread. Configured QMP monitors remain refused
until their producer roots have an authentic fence; an empty request count is
insufficient. Arbitrary BH callbacks, pending DMA/PIO, unrelated coroutine work,
clock advancement, timers and descriptor dispatch are outside this permit.

The native source selects at most 64 original callbacks while retaining HOLD.
Each row names the actual callback object, its original positive arm generation,
its owner context and its class. Rows preserve source context and queue order;
callback identifiers need not be numerically increasing. Original objects and
contexts remain pinned. A later arm of the same object is a different cut.

The cut digest is SHA-256 over the following exact preimage:

```text
"crucible.qemu-native-initialization-cut.v1\0"
scope[32] | commitment[32] | hold_generation:le-u64 | row_count:le-u32
row[row_count]: class:le-u32 | flags:le-u32=0 | callback_id:le-u64
                arm_generation:le-u64 | context_id:le-u64
```

The HOLD generation identifies retained custody lifetime. It does not identify
an immutable observation. The original cut digest and command identity remain
necessary even while the same HOLD generation continues.

## Home-thread delegation

The RR owner publishes one retained initialization command and prepares a
separately scoped home-thread admission under BQL. The source wakes the actual
main context without enqueuing an ordinary BH. The real top of the main-loop
iteration executes the selected helper before poll, timers, descriptor work or
unrelated callback dispatch. It does not authorize a main-loop iteration or a
generic admission-gate release.

The helper validates the entire original cut before the first effect: original
global transition generation, each callback arm, pending flags, class and native
predicate must still match. It removes and invokes only the retained callback
objects. An IDE callback may enqueue deletion of its own original object; the
helper retires only that same deletion tombstone. Unexpected successor work or
unbalanced admission produces unknown effects and retains unresolved custody.

Guest raw retirement count and virtual time must remain zero. The source
compares these actual counters before and after delegation. Callback completion
alone does not prove complete device, IRQ, input, output or worker closure.

## Public journal records

Native datagram edition 2 adds closed kinds 14 through 20. Existing edition 1
kinds and bytes remain unchanged and refuse all initialization records.

| Kind | Record | Public scalar size |
| --- | --- | --- |
| 14 | PrepareInitialization | Bounded complete preparation |
| 15 | QueryInitialization | 64 bytes |
| 16 | InitializationCut | 120-byte summary plus 32-byte rows |
| 17 | Initialize | 184 bytes |
| 18 | InitializationStopped | 160 bytes |
| 19 | AcknowledgeInitialization | 104 bytes |
| 20 | InitializationAcknowledged | 104 bytes |

Public scalars are big endian. The GPL-local command is a distinct 152-byte C
record because its commitment is separately pinned at source registration.
Native representations are not transmitted as public struct bytes.

The source and both process journals retain one original cut, command and
result. Repeating a command recovers its original result and never invokes a
new cut. A changed sequence, scope, policy, allowance, arm, cut or result fails
closed. Host ACK transmission retains original custody; only the matching
native reply settles that journal. Identical ACK retries return the same
settlement. Ordinary execution transport remains blocked until an Applied
result and original initialization ACK are both present. This transport gate
still grants no simulation-node capability or world activation.

The closed source results are Applied, Unsupported, Stale, Invalid and
EffectsUnknown. Pre-effect refusals report zero applied callbacks.
EffectsUnknown retains original data, refuses ACK and future execution, and
requires independent supervision. It is not a physical containment receipt.
Initial source query refusal currently withholds a cut and requires supervisor
timeout handling; it must not be converted into a fabricated cut or Ready
attestation.

## Evidence and remaining qualification

The GPL initializer getter is an authentic source seam before the ordinary
execution getter. It retains the actual initial CPU, timer and writer
observations there. Reader queries recover those historical pre-cleanup bytes;
cleanup does not overwrite them or make their same HOLD generation a fresh
snapshot. Later execution stop observations use their original execution
sequence and complete command digest.

Portable tests cover closed editions and lengths, all truncations, original
Realize and policy binding, native order, arm changes, stale identity, authentic
empty cuts and unknown-effect status. Model-only GPL and socket tests verify
once-only observation, unchanged command retries, retained original results,
changed-receipt quarantine and ACK custody. These tests qualify no native
adapter.

The actual process probe uses a PC construction epoch with its original QMP
startup and two IDE callbacks. It compares their native identifiers to the
initial held writer cut, requests finite home cleanup, verifies original result
and ACK retries, preserves the unread legacy FIFO, and then checks exclusive
retirement windows. Prototype source identities are mechanism evidence, not
installed package qualification.

A whole RFC-0025 QEMU profile still requires complete native input/output and
IRQ/device source closure, superdense phase settlement with original timer-arm
birth and finite callback cuts, qualified halted-idle behavior, and complete
capture/fork/restore of controller workers, socket journals and native pending
state. Administrative Applied cannot substitute for any of these obligations.
