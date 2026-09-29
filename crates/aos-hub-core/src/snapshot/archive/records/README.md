# Database capture records

This is a connected Native SQLite database-capture and offline record-verification
workflow over the existing reader, classifier, private capture, encrypted framing
and signed-root protocols. It does not implement a CLI, filesystem orchestration,
provider access, SQL insertion, serving, job activation or whole-Hub restoration.

## Producer

`capture_sqlite` consumes an existing `SqliteSnapshotReader`, caller-owned private
sinks, explicit dedicated archive signing/wrapping custody and a trusted fresh
CSPRNG. Source audit runs before either sink is touched. The same pinned read then
enumerates all current tables, classifies every row and checks observed row counts
against the source audit. Source database/WAL contents and journal mode are not
modified. Ordinary SQLite read locks/WAL shared-memory coordination are allowed.

Each table has explicit start/end records, including empty tables. Retained rows
have ordered start/cell/end records; exact private originals occupy the paired
private stream in dependency order. Authentication-transient and source-lineage
rows have explicit omission counts without their raw values. Durable operation,
lease, authority and replay state follows the classifier's retained disposition;
no epoch, namespace, intent, incarnation, timestamp or terminal state is rewritten.

Both streams have closed `database_capture/v1` headers and logical end records.
The producer finishes both encrypted streams before signing their actual counts
and hashes. The enclosing root retains its exact `framing_only` profile. Failure
returns no completed output/root and may leave incomplete ciphertext in caller
sinks. Retry needs fresh archive identity and keys; RNG freshness remains trusted
caller responsibility, including when reproducing seeded test fixtures.

## Verifier

`verify_database_capture` pins signer trust before unwrapping, owns both actual
frame decoders and performs a bounded one-row join. It checks current schema and
classification identity, every table/order/disposition/count, exact private-cell
locators/types/digests/lengths and reconstructed row reclassification. It requires
both logical ends, authenticated frame END, clean EOF and actual signed-summary
matches before returning `VerifiedDatabaseCaptureRecords`.

Callbacks receive provisional reconstructed private rows. They own confidentiality
and may not authorize serving or commit a restore from an individual callback;
a later error invalidates the overall verification. Callback error detail is
redacted. Blocking I/O/callback liveness and immutable input custody are caller
obligations. No row/key/private-sink Debug or automatic private serialization is
exposed. Owned serialized/line buffers are zeroizing; there is no perfect-erasure
claim for scalar/library/caller copies.

The receipt establishes grammar, exact per-row reconstruction and count
consistency with authenticated exporter declarations. Source integrity/CHECK/FK
facts are **declarations**, not a repeated independent source audit. Count equality
cannot prove unique primary keys or global SQL/application/object closure. A
regression deliberately demonstrates that repeating a valid row while preserving
counts still passes this narrow record proof. Private scratch-database replay must
reject that substitution before any stronger database-recovery acceptance.

Original source-sealing key provenance, provider object closure, credential
custody, live external journal continuity, old-writer fencing and runtime
activation remain separate unproved dependencies. PostgreSQL and Worker readers
are also pending. No flags or reports claim whole-Hub completeness or activation.

## Bounds and encoding

Records use closed JSON objects followed by exactly one LF. No generic JSON tree
is parsed in production. Control records have a 16KiB encoded cap; cell records
have a 6MiB plus 16KiB cap, admitting the worst sixfold escaping of a legitimate
1MiB source TEXT cell and twofold BLOB hex expansion. Current original-cell and
reconstructed-row bounds remain 1MiB and 8MiB. Counters are canonical unsigned
decimal strings with checked arithmetic; source table counts cannot exceed SQLite
signed COUNT bounds. Source metadata singleton tables require one source row.
Migration/classification digests and the finite catalogue pin exact schema shape.

Cell records prevent a whole escaped row/table/archive from accumulating in RAM.
The reader holds one bounded line and one encrypted-frame plaintext chunk, while
row reconstruction holds at most the classified/current row and private originals.
Integers, TEXT, BLOB, NULL and finite REAL scalar encodings reuse reviewed scalar
rules; current schema does not admit REAL rows. Logical records can cross frame
boundaries. Truncation, blank/unterminated/trailing lines and extra records reject.

## Next usable operator boundary

Add secure private filesystem orchestration and explicit database-capture
export/verify commands over these caller-owned sinks/readers. For a stronger
verify/import foundation, replay exact retained rows into an isolated fresh
private database using compiled schema and enforce PK/unique/CHECK/retained FK
closure. Never call serving initialization or execute restored jobs. Whole-Hub
closure, topology rebinding and activation require their own reviewed contracts.
