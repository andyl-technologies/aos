# Installed public reference-provider adapter

The public reference provider and its controlled checksum companion remain
separate owned processes. The controller authenticates the actual Unix peer
PID and UID, independently measures its executable through the native process
handle, and admits the closed Hello exchange through the trusted installation
verifier. A vendor-supplied manifest, receipt reference, or successful blob
transfer does not establish native execution authority.

## Dynamic control evidence

The distinct public byte-linked profile advertises `cnp.control-evidence/1`.
The original public checksum profile retains its existing advertisement and
traffic. A controller selecting the new behavior must negotiate this feature
before realization. The feature uses the baseline provider-origin
`BlobBegin`, `BlobChunk`, and `BlobFinish` methods; it does not add a content
lookup method.

After a completed Realize, Activate, Input, WorldActivate, Begin, Poll,
Observe, QuantumClose, Abort, or Release response, the provider transfers all
new locally retained content referenced by that response. It traverses
canonical JSON records and sends dependencies before their referring objects.
It omits exact profile content and private bootstrap objects already owned by
the admitting controller. Independently measured executable artifacts are
also omitted. All other missing or mismatched local references refuse the
transfer. A digest cannot acquire a different length, media type, or hash domain.

The closure is bounded by 4096 objects, 64 dependency levels, the source
provider's installed content-byte ceiling, and the negotiated frame, nesting,
chunk, correlation and original-request journal ceilings. Transfers retain
original request IDs and fixed chunk cuts across authenticated same-incarnation
reconnects. A finished transfer proves immutable byte custody only. Output
publication and semantic input consumption retain their independent original
owner receipts and journal obligations.

With this feature selected, these response-derived closures replace the
legacy observation-window's additional implicit content transfers. Therefore
the controller can finish receiving every response root without leaving an
unannounced tail of transfers ahead of its next command. The original profile's
observation transfer order remains unchanged.

## Controller custody and time bounds

The client records the original controller request before publishing it.
Connection sequence is the only field refreshed on a replacement stream.
Changed original material refuses locally; a received outcome remains associated
with its original request. Accepted responses release transport correlation
credit without releasing original operation custody. EOF or partial writes
leave originals under the mandatory supervisor rather than allocate substitutes.

Client content has independent finite byte, object, chunk and transfer-identity
ceilings. A complete advertised length is reserved before chunks are accepted.
Chunks are contiguous or exactly match their retained original range. Finish
checks complete bytes against the original ContentRef before acknowledging
custody. Completed content and retry ledgers share one immutable allocation.

Host monotonic time bounds blocking transport only. All clones share one
absolute exchange deadline; byte progress never renews it. Receiving a response
and then its promised evidence tightens the original deadline instead of
starting another budget. This operational cutoff never supplies modeled time,
event ordering, execution progress, persisted state or determinism guarantees.

## Evidence scope

`tests/client_reference.rs` launches the actual source-built public provider
and companion through the private version-two byte-linked bootstrap. It
authenticates measured peer identity, receives the full native gate receipt
closure, checks original receipt and owner scope, verifies the real companion's
kernel parent relationship, distinguishes unchanged and changed original
requests, and confirms companion disappearance after native abort and reap.

These checks establish local public protocol and retained-resource behavior.
They do not qualify exact execution, preservation, deterministic replay,
physical pause, CPU fidelity, or a generic third-party provider. Common runtime
selection, connected-world operation and opaque host admission remain separate
integration obligations.
