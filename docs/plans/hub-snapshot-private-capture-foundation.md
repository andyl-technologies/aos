# Snapshot private-cell capture foundation

This implementation adds exact private-cell pairing and one-row reconstruction
above the current-schema classifier. It is a pure bounded value seam, not a
whole-Hub archive, import, SQL executor, source-sealer, or activation command.

## Private boundary

`SnapshotClassifier::capture_private_row` first applies the existing complete
classification contract and its one-MiB cell/eight-MiB row limits. It returns
classified metadata and only the exact originals corresponding to declared
private dependencies. Authentication-transient and source-lineage dispositions
produce no private originals. It does not turn transient authentication state
into retained credentials.

`CapturedSnapshotRow`, `PrivateSnapshotCell` and `ReconstructedSnapshotRow` have
redacted `Debug` implementations and no `Serialize`/`Deserialize` implementation.
Originals and reconstructed rows can be inspected only through deliberately
named private callbacks; the scalar writer also requires an explicit private
sink. Those callbacks/writers are confidentiality boundaries. Callers must not
serialize their contents to public archives, diagnostics, or unrestricted APIs.
No memory-erasure, encryption, authentication or key-custody guarantee is made.

The scalar writer emits a closed version-one envelope:

```json
{"version":1,"scalar":{"kind":"integer","value":"-9223372036854775808"}}
```

Integers must be canonical signed i64 decimal strings. REAL values preserve
finite IEEE-754 bits, including negative zero, as exactly sixteen lowercase hex
digits. BLOBs use even-length lowercase hex, text preserves exact UTF-8 bytes,
and NULL admits only its `kind` member. Unknown or duplicate members, unsupported
versions/kinds, JSON numeric payloads, integer overflow/noncanonical spellings,
nonfinite reals, and malformed hex fail with value-free errors. The current
production schema admits no REAL columns: finite REAL codec qualification does
not expand current SQL row admission.

Original payload size remains separate from encoded size. One MiB of text may
require six MiB of JSON escaping; a one-MiB BLOB may require two MiB of hex. The
private scalar envelope cap is six times the cell limit plus fixed envelope
allowance. The decoder checks the input cap before parsing, then the decoded
payload cap, typed digest and declared payload length. Table/column/key binding
is fully checked by the classifier during reconstruction; this decoder alone
is not source-schema or source-provenance admission.

## Exact reconstruction

`SnapshotClassifier::reconstruct_private_row` accepts one classified retained row
and its private originals, in the canonical dependency order produced by the
classifier. It checks counts before cloning payloads, enforces unique declarations
and originals, and matches table, PK digest, column, reason, typed-cell digest
and original payload length one-to-one. Missing, extra, reordered, cross-row,
wrong-column and altered originals reject. Each public scalar also receives the
same canonical/bounded decoding checks; total reconstructed source payload is
bounded before classification.

The classifier's existing schema order, typed digests, primary-key derivation,
SQL storage-class rules, dynamic-setting rules and JSON admission are reused.
The reconstructed row is reclassified and must exactly equal the supplied
metadata, including dependency order. A caller cannot replace a private cell
with a public scalar and retain matching classification. Original JSON text is
not parsed and reserialized for reconstruction; immutable history bytes and
confirmation hashes remain unchanged.

This validates internal consistency, not artifact authenticity. A later archive
layer must authenticate metadata and originals against trusted source provenance.
The method never inserts SQL, initializes a sealer, decrypts source secrets,
adopts a namespace, executes pending jobs, or changes provider-effect fences.

## Qualification and pending work

Focused tests cover actual production-initialized SQLite values, min/max i64,
BLOB/NULL/empty values, opaque history and immutable secret-bearing plans,
composite-PK association, finite REAL bit identity, missing/extra/duplicate/
reordered/swapped originals, metadata/dependency/type tampering, malformed and
unknown scalar encodings, worst-case escaped text/hex bounds, source/reconstructed
row limits, omitted dispositions, and value-free errors/Debug output.

This foundation does not implement encrypted frames, signed archive manifests,
filesystem output/cleanup, export/import CLI, source sealing-key provenance,
SQL/application/object closure, PostgreSQL/Workers snapshot readers or provider
activation. Existing authority/guard/terminal state is neither executed nor
rewritten. Those contracts remain explicit prerequisites for a restorable
whole-Hub snapshot.
