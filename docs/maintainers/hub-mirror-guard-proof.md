# Mirror final physical guard proof

Native catalogue publication requires an independently authenticated fresh
readback from the physical `HybridObjectGuard` that still holds the final key.
The producer's storage-work response is insufficient. The guard reads the
retained full original, full positive progress and exact provider completion
receipt under the same per-key exclusion used by direct uploads and legacy
writes. It performs no provider HEAD, body read, mutation or fence clearing.

The request binds the copy operation, current authority and full protected
profile pins, complete expected progress, source and deployed script identities,
fresh 32-byte nonce, bounded UTC uncertainty and a deadline of at most 30 seconds.
The separately signed reply binds the canonical full request digest and returns
one complete retained progress, including final key, SHA, size, strong ETag and
provider incarnation. Both envelopes are bounded to 256 KiB. Native retains an
opaque verified proof and rechecks its full identity and deadline immediately
before the checked SQL transaction. The pinned uncertainty projects the raw SQL
clock; neither a wait nor a retry renews the original proof.

## Authentication and execution

`HUB_MIRROR_GUARD_KEY` is an independently authorized guard-role key and must
differ from `HUB_STORAGE_WORK_KEY` and any controlled producer key. The existing
authorized direct guard key may serve this role. Request and reply MAC domains
are distinct from each other, producer controls, direct guard controls and
reviewer acceptance signatures. The issuer source and script pins come from an
independently verified installation or acceptance; a reply cannot select its
own trusted issuer.

The production route is `/_internal/storage/mirror-final-guard`. A `do-e2e`
controlled route uses `/__hub/mirror-candidate-guard`, requires the exact
`.aos-mirror-qualification/<32 lowercase hexadecimal characters>/final` placement
prefix and a script identity derived from the actual compiled source. Controlled
proof cannot authorize an ordinary destination or claim hosted acceptance.

## Unknown outcomes and historical recovery

A held owner without its exact positive completion receipt cannot mint proof.
A different pending mutation or any pending legacy delete refuses lookup. An
exact positive completion receipt may be read after a crash before its matching
pending marker was cleared; lookup leaves the marker unchanged. Released or
archived owners cannot authorize a new catalogue commit. Exact already committed
SQL replay returns its retained result and has no new physical effect or lookup.
Only successful atomic Native publication permits acknowledgement and archive.

Producer acceptance expiry refuses new admission and provider dispatch, including
dispatch after capacity waits. It does not erase journals or disable read-only
held-final proof, exact positive publication replay or independently authenticated
Native commit acknowledgement. Historical direct readback similarly reads only
the retained final record. Source and baseline operations that need ordinary
provider authority still require valid qualification and current grants.

## Buffer classes and qualification scope

All Zstandard NAR production and verification uses the single bulk buffer slot,
including small compressed objects: legitimate frames may advertise a decoder
window larger than their plain content. Only bounded SHA-256 objects or
uncompressed NARs whose encoded and plain sizes are at most 256 KiB use the two
reserved metadata buffer slots. Whole-worker observations must include the
bulk verifier, both metadata producers, Rust and JavaScript copies, SDK buffers
and decoder allocations. Nominal part bytes alone do not establish hosted
128 MiB safety. Existing none/Zstandard acceptance does not qualify a new Git
pack parser or inspection workflow.

Contract, SQLite restart and source compilation checks verify these protocol
rules. Actual controlled provider roundtrips and independently reviewed hosted
measurements remain separate qualification gates.
