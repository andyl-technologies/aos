# Exact host-world state operations

The local node daemon provides whole-world capture and restoration for its
installed synchronous clock profile and qualified finite request-source/storage
topologies. A capture includes the authentic
native continuation envelopes, original runtime operations and acknowledgements,
causal scheduler, coherent cut, event ordinal, backend bindings, and complete
immutable implementation closure. Restoration uses fresh owner incarnations and
higher owner and world generations while preserving the original logical state.

The reference checksum device advertises `CaptureScope::None`. A state request
containing that device, a connected network model, or an unsupported provider is
refused before native allocation. Clock capture does not qualify guest CPUs,
physical devices, reference-device continuation, or architectural RAM snapshots.
The storage scope is fault-free immutable `HostScripted` requests connected to
native Block or read-only 9p models. Complete capture preserves dirty Block COW
state, original staged input and FIFO custody, delayed responses, and 9p session,
fid and tag state. Mutating 9p requests retain their native `EROFS` behavior;
preservation does not grant filesystem write support.

## Installation and finite custody

Installed policy edition 1 retains the observation-only daemon and its original
capacity. Edition 2 explicitly enables the separate exact-state actor:

```json
{
  "format": "crucible.node-daemon-policy",
  "version": 2,
  "state_directory": "/private/node-service",
  "socket": "/private/node-service/node.sock",
  "device_executable": "/installed/crucible-reference-device",
  "expected_device": "<ContentRef from authenticated package inventory>",
  "control_timeout_ms": 3000,
  "maximum_worlds": 4,
  "maximum_host_state_worlds": 2,
  "maximum_pending_requests": 4
}
```

The optional `immutable_artifacts` registry also uses private operator policy: each
entry contains an absolute source `path` and independently expected `ContentRef`.
Both actors enroll the entire registry before admission; remote selections carry
content references only and cannot install paths. Enrollment requires actual
NOFOLLOW regular files matching those bytes, at most 64 entries, 4 MiB per file,
and 16 MiB total. Explicit archive-only enrollment is described below.

The expected device reference uses the same installed policy contract as
[ordinary observations](node-operations.md). The observation and exact-state
actors have separately bounded queues and custody slots. The state actor requires
at least two slots because restoration reserves original staging and runtime
custody before native allocation. Its persistent namespace permits at most 4096
original operation records. Archive content has a 512 MiB per-object ceiling and
1 GiB complete-closure ceiling, including the actual owning daemon executable.

Both actors register independent retention owners before admission. Shutdown
stops admission and retains the exclusive private state lock until every original
native obligation is authentically reclaimed. The local API exposes no deletion.
Archive files remain in the separately owned private host realm; CAS collection
retains the original state-operation requests, records, and durable activations.

## Capture and restore

Compile the clock-only selection using the owning daemon. Both state commands
require the same installed selection and original scenario bytes:

```text
crucible node compile --socket /private/node-service/node.sock \
  --selections clocks.json --output scenario.json

crucible node capture --socket /private/node-service/node.sock \
  --execution 33333333333333333333333333333333 \
  --selections clocks.json --scenario scenario.json --horizon-ps 100

crucible node state-status --socket /private/node-service/node.sock \
  --execution 33333333333333333333333333333333
```

Capture reserves the original nonce durably before activation and returns its
reservation. Read `state-status` until the original record contains
`state.status = "completed"`, then save that complete JSON record as
`captured.json`. Its artifact is a host-authenticated complete archive rather than
a provider claim or client-supplied native image.

```text
crucible node restore --socket /private/node-service/node.sock \
  --execution 44444444444444444444444444444444 \
  --selections clocks.json --scenario scenario.json \
  --source captured.json --horizon-ps 200

crucible node state-status --socket /private/node-service/node.sock \
  --execution 44444444444444444444444444444444
```

The original source is authenticated in the private archive before preparation.
The installed factory independently verifies the complete selected model codec, executable,
model, configuration, coordinator coverage, and source custody. Fresh admission
uses the same durable world binding and increased generations. The whole-world
activation is durable before execution; the returned capture preserves the
continued cut and original event ordinal plus actual newly committed operations.
Selecting the original cut performs no new clock execution.

Retained input buffers receive authorization for the fresh owner incarnation.
Each new acknowledgement proof pins the exact original acknowledgement and
source capture. Staging and batch identities, payload bytes, causal coordinates,
and consumption prefixes stay unchanged; restoration does not stage or consume
the original input again. Retained execution outcomes acquire the same fresh
owner route, while their original operation identities, requests, scheduling
facts, proof references, and immutable receipt bodies remain unchanged.

## Original identity and restart

Each exact-state request uses local control edition 2. Legacy observation commands
retain edition 1. A state nonce belongs to its complete original request,
including the exact scenario bytes, selection, source archive, and horizon.
Changing those inputs under the same nonce is refused. Repeating a request returns
the unchanged original reservation or result; it never creates another native
permit. State and observation operations use distinct native identity domains
even when their public nonces happen to match.

A daemon restart reads the original record without dispatching it. An unresolved
reservation is preserved as unresolved; a new actor cannot inherit the original
execution permission. A fresh restore requires a new nonce and a completed,
authenticated source archive. A refused operation preserves its original custody
and does not become retry permission.

The archive authentication key is kernel-generated and retained in a private
0600 regular file under the 0700 archive directory. It never crosses the local
socket or enters request, report, scenario, or artifact identities. Backup and
installation migration must retain that key separately from public capture
references. A different host realm, changed backend binary or model, corrupted
closure, unsupported state edition, or unavailable qualification is refused.

## Explicit archive-only source enrollment

Policy edition two accepts an independently authenticated content expectation
without enrolling a file path:

```json
{
  "mode": "archive_only",
  "expected": {
    "hash": {
      "algorithm": "blake3-256",
      "domain": "cnp.blob.v1",
      "digest": "..."
    },
    "length": "4096",
    "media_type": "application/octet-stream"
  }
}
```

The `expected` field must contain the complete real content reference supplied by
the operator's authenticated inventory; the abbreviated digest above is only
illustrative. This mode never treats a missing or changed path as a fallback.
An ordinary `{"path":...,"expected":...}` entry continues to measure that exact
file before endpoint admission. Either entry remains private installation policy;
remote scenario selections cannot enroll artifacts or choose source paths.

Fresh native construction refuses an archive-only source. Restore can materialize
it only after authenticating the original whole-world archive, matching the
operator's independent expectation and verifying the complete captured content.
The temporary native source remains owned by the original restoration custody.
Archive-only enrollment cannot confer durable preservation on an unqualified
model. The installed signer independently verifies the finite request script,
storage inputs and complete original native/runtime/coordinator custody before
materializing a supported continuation.
