# Dedicated External workflow accounting

`_hub-external-workflow-accounting.py` consumes the selected External OCI and
placement Copy window. It reuses the shared compiled body decoder, the Native
application-frame and transport observers, and the existing catalogue and
provider parsers. It grants no permission and performs no provider operation.

## Called interface

```python
assessment = consume_external_workflow_evidence(
    native, worker, tools, prepared, processes, workflow, business, read_sql,
    read_private=read_private,
)
```

The fixture installer selects this module as `tools.externalWorkflowAccounting`.
The installed directory must also contain these unchanged selected siblings:

- `_hub-managed-workflow-accounting.py` for the actual ingress frame/check join;
- `_hub-external-copy-window.py` for the existing catalogue, completed-operation
  and full object-presence predicates;
- `_hub-direct-boundary.py` and `_hub-direct-runtime-observations.py` for the
  existing closed provider observation parser.

`tools.workerSourcePath` and `tools.storageCodecSourceSha256` must identify the
actual common source and selected decoder. The decoder source commitment is the
existing ordered concatenation of `main.rs`, `files.rs`, `classify.rs`,
`storage_work.rs`, `ingress.rs` and `controls.rs`. No historical executable is
relabelled by this consumer.

`workflow` is the called External epoch collector's complete result: eight fixed
proxy/header windows, exclusive original/received membership, separate actual
stock/helper log epochs, the current decoder and Native observations, and the
complete provider window. Every Native outbound and Worker original row belongs
to exactly one epoch. Unmatched attempts, ingress events, final-context receipts,
startup rows without decoding, missing bodies and duplicate call ownership are
retained as incomplete observations or refused. Identical requests cannot share
one successful transport receipt.

`business` is the actual called publication/copy controller result. Its helper
input and post-constructor readiness, installed Direct file references,
controlled OCI candidate, publication/reindex commit, Copy catalogue and exact
replicate/repair originals are independently retained. A successful status or a
signature hash alone cannot replace those inputs.

`read_private(machine, path, maximum)` reopens exact owner-private guest bytes.
The accepted reference forms are only `{file, sha256, byteSize}` and the existing
setup reader's `{path, sha256, bytes}`. No bearer, guard key, request body or raw
signature is included in the returned summary.

`read_sql(query, label)` executes the supplied bounded read-only repeatable-read
transaction using the selected credential-file database URI and source-built
psql. It returns `{value, receipt}` with the raw private result reference, query
and executable/database hashes, and actual before/after Native/helper process
pins. The consumer reopens the raw result and matches the query and process.
It selects current writer/placement/binding/authority metadata and immutable
upload selectors only. These rows cannot reconstruct a past actor decision,
expired completing claim or provider permission.

## Independent report dimensions

| Field | Exact meaning |
| --- | --- |
| `complete` | Every selected original has a supported, source-bound full-body classification and any content partition has its required actual Native observation. No unsupported, substituted or omitted row is removed. |
| `capturedObjectByteUpperBound` | Sum of the decoder's full captured raw request/reply object partitions. Metadata-only bodies bound possible object bytes without inventing a consumed-body count. |
| `selectedDataBytes`, `semanticProjectionBytes` | Separately classified selected query data and bounded semantic OCI projections; neither is a TLS or billing count. |
| `capturedApplicationBodies` | Exact full captured original-request and reply body sizes, independently of Native consumption. |
| `nativeConsumptionComplete` | Each selected body partition also has an actual joined Native frame/chunk observation. A known metadata upper bound does not set this field. |
| `nativeControlBoundaryObjectBytes` | Raw object partitions on the selected Native boundaries, only when their actual observations are complete. Native response frames are offered bytes, not proof of client delivery. |
| `bodyPartitions[].checkedOutcome`, `existingFinalCheck` | Actual source-point accepted/refused/typed-check outcome and any existing final caller check. Writer checks do not become IAM; Delete checks do not become Publish permission. |
| `currentSqlAssociation` | Actual current writer/immutable-upload association and its retained query result. It is not a historical authorization proof. |
| `copyAssociation` | Reopened catalogue, full before/after presence, reviewed operation/replay and per-original path/digest/size association. It grants no current claim or physical authority. |
| `purposeObservation` | Association to the actual unchanged Direct loader and confined test-only OCI constructor's input/readiness/process. It is neither Managed acceptance nor Hosted qualification. |
| `providerPartition` | Every retained provider row is reparsed, counted by the actual selected caller address, and matched to its projection. Repeated paths have no invented per-call attribution. |
| `associationFailures` | Failures of independent state/purpose/provider associations. They do not erase independently measured body shapes or counts. |
| `independentAssociationsComplete` | No association failure in this consumer; this reporting condition grants no authority and establishes no past IAM. |
| `outsideNativeLifetimes`, `nativeBulkBytes` | The dedicated issuer is outside these four proxy roles. The whole-machine aggregate remains `None`; selected-boundary evidence cannot qualify that missing lifetime. |

The local caller retains the full assessment before applying its finite body
gate: `complete is True` and `capturedObjectByteUpperBound == 0` establish a
supported captured-body upper bound for this selected Native boundary corpus.
It must describe that scope. `nativeConsumptionComplete` distinguishes actual
observed counts from an upper bound. Current SQL, source-point decisions, purpose
and provider associations keep their own outcomes; unavailable per-call provider
attribution or later SQL cannot rewrite an earlier measured body.

Neither this body gate nor `complete` means whole-machine Native zero, accepted
storage authority, Hosted provider behavior or fleet qualification. The whole
runtime consumer needs real matching issuer process/interval/transport/source
evidence before extending the aggregate beyond these selected roles. Missing
observations remain unknown. No success flag or configured zero fills that gap.

Fully captured source-owned metadata/refusal bodies may support an actual
consumed prefix without successful Native acceptance. Content-bearing partial
replies remain unresolved: the full decoded content count cannot be borrowed
without an independently established byte-offset partition. Worker-completed
upstream responses never stand for Native-consumed downstream replies.

## Bounds and focused checks

The observation inventory admits at most 204,704 originals, with unchanged
per-call decoder and 8 MiB captured-body ceilings. Current SQL selection is
bounded to 512 distinct writer/upload selectors; each raw result is at most
1 MiB. Provider input is streamed one row at a time, bounded to 512 MiB total,
204,704 rows and 48 KiB per retained row; the reused closed provider parser has
its own smaller intrinsic row limit. Original log inode/prefix continuity,
raw SHA/count and every projected row must match.

Each retained body/association summary is serialized and bounded before append:
at most 4 KiB per item and 240 MiB collectively including array separators.
The exact final serialized report must fit 256 MiB before the caller persists
it. Failure summaries and scalar fields use the remaining bounded space.
Overflow refuses completion and preserves the original capture files. These
are content/serialization limits, not measured Python RSS or protocol budgets.
Existing corpus/decoder limits, stock publication sizes and qualification gates
are unchanged.

Run the focused source checks with the selected AOS Python:

```text
<selected-python>/bin/python3 -B tests/fleet/_hub-external-workflow-accounting-tests.py -v
```

The controlled cases exercise real private file reads and the published closed
decoder/event/provider/SQL/API schemas: matching observations, substitution,
replay, epoch ownership, partial content, expected refusal, query/process pins,
catalogue/presence, provider prefix continuity and an actual consumer overflow.
They execute no business upload, Rust artifact verification, SQL server,
provider request, VM or Hosted qualification.
