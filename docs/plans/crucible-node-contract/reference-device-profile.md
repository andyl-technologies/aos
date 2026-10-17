# Controlled checksum device reference profile

The `crucible-node-provider` package includes a source-built
`crucible-reference-device` executable and a `reference_device::ReferenceDevice`
driver. This is a non-compute device reference for T-CN-24/T-CN-30. It exercises
actual separate-process execution, immutable input cuts, quantized output custody
and native reclamation. It does not qualify KVM or autonomous physical hardware.

## Device behavior and ownership

One child owns a rolling 64-bit checksum. For each input byte `b`, the transition
is `checksum = checksum * 257 + b`, with arithmetic modulo `2^64`. A completed
window produces exactly one record containing its byte count and the cumulative
checksum. Empty input produces a record without changing the checksum.

The child has no guest CPU, timers, autonomous workers, DMA or external network
and storage effects. Its only modeled effect path is its private control socket.
After batch computation, it waits for commands. A close response acknowledges
application-level park of this controlled command loop; it does not claim OS
thread suspension or pause of external hardware. It has no exact full-state
capture profile. Its functional transition is repeatable, while host budget
failure and scheduling measurements remain operational evidence.

The driver creates a mode-0700 socket directory, spawns an explicitly selected
absolute executable with a cleared environment, and checks readiness against
its actual child PID using Linux `SO_PEERCRED`, then checks the protocol's
owner/incarnation/generation. The enclosing host must
first authenticate the executable and bind its implementation identity. A
self-reported PID is not authentication of an arbitrary vendor process.

## Window transaction

1. The host obtains coordinator authorization for a complete immutable start
   batch, including slower producer frontiers and equal-boundary settlement.
   It binds the original owner, incarnation, generation, window, batch, quantum,
   superdense start position, root publication position and elapsed host budget.
2. `stage` sends the bounded input and waits for a matching staging response.
   Staging performs no checksum transitions. A changed duplicate or different
   batch while a window is retained is refused.
3. `activate` permits exactly that batch's checksum transitions. The total elapsed
   request deadline covers transport and scheduling as well as device work.
   This deadline requests containment on overrun; it is not instruction-exact
   stopping or a qualified hard wall-time service guarantee.
4. `close` obtains the real child's park acknowledgment and complete output.
   The retained receipt carries the original fixed logical publication boundary
   and separate measured host nanoseconds. Duplicate activation and close do not
   rerun the checksum.
5. The host authenticates the receipt against retained driver custody and waits
   for world publication authorization. The device cannot stage another window
   while its previous output remains unpublished.
6. `acknowledge_publication` releases the original output only after coordinator
   acknowledgment, then permits the next consecutive quantum. Retired window IDs
   remain fenced for this incarnation. This initial implementation retains at
   most 65,536 such tombstones and refuses exhaustion; it does not silently reuse
   identities or discard output.

The driver does not replace causal graph admission or validate a world's quantum
and phase policy by itself. The `SimulationNode` adapter must validate the opaque
host operation authority, immutable native route, realized grid and publication
settlement. Receipt-shaped JSON cannot authorize execution or publication.

## Transport and failure scope

The private device subprotocol uses the existing length-prefixed strict JSON
framing with a 65,536-byte frame ceiling. Input is capped at 4,096 bytes and one
window is retained per child. Fields use canonical contract IDs, decimal integer
strings and superdense positions. This is native device plumbing, not a CNP/1
handshake or standalone external-provider authorization service. Public CNP/1
service qualification requires its own composition and conformance tests.

Each request has a total monotonic deadline; partial reads and writes cannot reset
that allowance. A malformed response, disconnected child or uncertain request
permanently fences the socket and requests termination. `quarantine` disconnects
the only effect path and polls for actual process reaping. A false result retains
quarantined ownership and requires further polling. Previously retained input and
unpublished output obligations are not rerun or silently acknowledged.

A mandatory supervisor reserves one of 64 finite capsules before process spawn.
Drop transfers the child handle and complete retained window into its original
capsule; a persistent reaper disconnects and terminates the controlled child.
Failed kill or status checks retain the capsule. Reaped windows preserve their
original input, observed output and close receipt until explicit host-authorized
containment disposition. Exhaustion refuses new launches before spawn, and
cannot prevent an existing driver from transferring custody. Drop itself is
never a reclamation receipt. Normal adapters may discharge their retained window
with `acknowledge_containment` only after actual reaping and world disposition;
dropped adapters use the supervisor's authenticated inventory and acknowledgment.

## Local validation

Source-built integration tests launch the actual executable and exercise:

- Duplicate stage/activation/close/publication acknowledgment and cumulative
  state across consecutive windows.
- Changed immutable input, premature close/release, output custody blocking the
  next window, forged receipts and retired-window reuse.
- Oversized input and stale owner/generation/quantum refusal before execution.
- Total-budget expiry with socket containment, actual child reaping and refusal
  to retry uncertain execution.
- Quarantine while an unpublished output remains retained; malformed commands
  causing actual child failure; dropped-child reaping; complete unpublished
  window transfer to supervision; finite reservation backpressure.

These driver tests do not establish mixed-world causality or public vendor
transport qualification. The enclosing adapter must pass the node runtime's
opaque-grant, native-receipt, cancellation, reclamation and boundary publication
checks before this profile is advertised as admitted support.
