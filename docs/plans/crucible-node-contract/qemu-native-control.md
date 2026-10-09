# Native QEMU control integration

The strict native controller is an opt-in process protocol. Its scalar stops,
CPU park observations, and virtual timer inventory are mechanical evidence.
They do not qualify a complete RFC-0025 QEMU node. In particular, no adapter may
convert these records into all-owner readiness, an exact capture, an input
closure, a producer lower bound, or a successful same-time settlement.

## Process and ownership boundary

The Apache host owns one endpoint of a connected Unix datagram pair. It passes
the other endpoint, separately from ControlV3, shared memory, and the wake FD,
to the GPL plugin during supervised process preparation. The prepared scope
binds the session, incarnation, activation, node, owner, owner and world
generations, and complete owner and world binding identities. Its canonical
BLAKE3 digest is pinned in the plugin launch arguments and the native V4 resource
manifest. A pathname connection or a matching string is not that custody chain.

ControlV3 setup and the existing shared-memory header remain unchanged. Native
control registration is independent and optional. With registration absent,
the existing execution and fault paths retain their prior behavior. With it
present, legacy scalar execution ceilings, idle jumps, and time-advance controls
cannot authorize modeled work. The shared-memory fault FIFO remains unread
until an actual native staged input contract exists; retaining a queued legacy
command does not apply it.

The GPL controller retains its actual protocol reader, original command
journal, native receipts, initial CPU observation, and timer objects. Its V4
manifest includes the real connected descriptor and reader resource. Native
migration, ordinary snapshots, and retained hot-fork remain refused: duplicating
a descriptor or QEMU memory does not preserve a fresh owner scope and journal.

## Original execution custody

`crucible-protocol::node_control` defines pointer-free, independently versioned
frames. The header is `CNQEMU01`, a big-endian 16-bit version and kind, and a
big-endian 32-bit body length. The body limit is 4096 bytes. Native ABI structs
and callbacks exist only inside the GPL plugin and QEMU processes; they are
never copied as Rust or C layouts into this public protocol.

An original command binds its complete scope, operation, grant, input epoch,
input batch identity/hash, input cutoff, start, and exclusive limit. Retries must
preserve all fields. An accepted owner has at most one unresolved command.
Native stop facts retain actual retirement separately from the logical clock
and instruction-service credit. A transmitted host ACK releases no host
custody until the matching original native acknowledgement arrives. Both sides
retain original tombstones rather than accepting a reused sequence as new work.

The source implementation supports the narrow phase-zero execution mechanics.
It parks before retirement or timer service at an exclusive limit, and its
administrative clock park does not reset the original retirement service
anchor. Unsupported idle, nonzero-microstep, and BoundarySettle requests stay
explicitly unsupported. Pending-source inventory remains unknown in scalar
stop facts.

## CPU park observation

Frames 7 and 8 retrieve an original CPU-only preparation observation. The GPL
plugin queries QEMU on its actual BQL-held RR getter seam, never on its reader
thread. QEMU checks finalized machine preparation, the fixed realized CPU
roster, real CPU thread ownership and stopped execution state, the original V4
scope, and the actual socket identity. It hashes the tagged ascending actual
CPU index roster with SHA-256.

Coverage bit zero means CPU park only. No bit asserts input, timer, IRQ, device,
output, or complete state-domain closure. The observation is retained once;
recovering it after later execution returns the same historical clock and
retirement count. It is not current suspension evidence and cannot activate a
world.

## Original timer objects and slices

Frames 9 and 10 request checked slices of an already retained original timer
object. A request selects the prepared scope, an original stopped command
sequence (zero for the initial CPU park), and a byte offset. It never causes the
reader thread to query or resample native timers.

On the actual native getter or stop callback, QEMU acquires every bounded
virtual-list queue lock and then its timer custody lock. The coherent query
includes empty lists and queued timers in native FIFO order. Active virtual
callbacks, unsupported/deferred timer state, overflow, or exceeded bounds
prevent an observation. Each timer has a stable process-local identity and a
distinct original arm generation; equal identity and expiry cannot conceal
rearming. IDs are counters, not native pointers. Observing an Aio list does not
authorize its dispatch on the RR thread.

The GPL plugin copies the successful cut into canonical `CNTIMER1` bytes:
prepared scope digest, original sequence and command digest, actual clock,
mutation generation, list and timer counts, ordered list rows, and ordered arm
rows. The initial sequence requires a zero command digest. A stopped-command
object requires its exact original digest and clock. Local validation checks
counts, identities, native FIFO ordinals, monotone expiry order, and original
arm generations. There are at most 64 lists and 4096 timer arms, and at most
198000 bytes per object.

A slice contains the original scope, sequence, whole-object BLAKE3 digest,
total length, checked offset, and at most 3000 bytes. Full socket capacity leaves
original custody intact. Identical retries and duplicate old slices recover
unchanged bytes. The host exposes an observation only after assembling the
complete bounded object, verifying its hash, decoding its closed structure,
and matching the original scope, command, and clock. Changed digests, lengths,
bytes, skipped offsets, or foreign cuts are refused without replacing original
evidence. Original objects survive command acknowledgement. GPL retention is
bounded at 16 MiB; host retention reserves at most 80 bounded objects. Exhaustion
does not evict old custody or manufacture a new observation.

## Remaining native qualification

A qualified `SimulationNode` requires an authenticated complete execution and
capture owner inventory, actual initial/restore readiness, and concrete
producer/input/output closure. Timer objects are one component of that work.
IRQ, reset, CPU exception, bottom-half, device-worker, staged input, and retained
output sources still need original identity and custody under the same native
cut. Complete scope coverage must come from the native realization inventory,
not from a host declaration that unsupported sources are absent.

BoundarySettle additionally needs a native superdense causal context: timer-arm
birth positions, a finite original arm cut, callback phase authorization, and
retained publications at their proper subsequent positions. Draining all timers
with the same physical timestamp would incorrectly consume callback rearming
at later microsteps. Timer counts and an empty queue do not establish that
closure. Idle advancement similarly requires authenticated future-source
bounds. Exact capture and fork need preservation/rebinding of the original
plugin journal, timers and arm identities, input buffers, outputs, descriptors,
worker custody, and fresh authority; the existing refusal stays until that
complete state is implemented and tested.
