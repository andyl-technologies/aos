# Called Managed inventory and GC window

`tests/fleet/_hub-managed-gc-window.py` supplies
`run_managed_gc_window(native, worker, client, database_machine, tools, prepared,
processes, boundaries, controls, setup, container_source, publication,
producer_coordinates, refresh_token)` for the normal five-VM controller. Fleet
pair setup and routing remain in the calling controller. This module installs
no credentials, issuer policy, provider acceptance or capability.

## Inputs and dependencies

The caller supplies the fresh Managed pair's actual `prepared.captureSelection`
(`run`, `sourceDigest`, `nativeAddress`) and exactly four process pins:
`native`, `worker`, `nativeProxy`, `workerProxy`. `boundaries.codecSelection` and
`boundaries.codecProvenance` must name the reviewed current compiled general
StorageWork codec and its matching Native/Worker/source tuple. A historical
observer is not a substitute.

The current tuple is checked against the supplied original process selection
before producing additional objects. Every finished window then rechecks actual
capture source/executable joins. Up to 4,096 complete requests and 16 MiB of
captured body bytes fit a window; at most 32 windows and 4,096 typed exchanges
are retained for this confined workflow. Exceeding those limits stops it.

The controller includes the actual `begin_managed_storage_window`,
`finish_managed_storage_window`, `classify_managed_storage_capture` and
`read_managed_runner_command` helpers. Finish reuses the exact original begin
label; it cannot select a different log window. The selected current codec
classifies each captured execute request before the adapter exposes a typed
plan and result. Non-execute controls keep their original/source/handler
references and cannot become deletion evidence.

The installed module paths are:

| Tool field | Module |
| --- | --- |
| `managedGcHelper` | `_hub-managed-gc.py`, packaged beside `_hub-inventory-gc.py` |
| `managedGcSql` | `_hub-managed-gc-sql.py` |
| `managedGcCollector` | `_hub-managed-gc-observer.py` |
| `managedContainerProducer` | `_hub-managed-container.py` with the untagged index producer |

These modules must retain their real immutable source paths. The GC helper
imports its inventory sibling through `__file__`; installing it as an isolated
file without that sibling is insufficient.

The selected placement prefix is exactly
`qualification/oci-terminal-cleanup/<32-character lowercase hexadecimal run>`.
SQL selection requires the actual placement and `coordinates.gcPrefix` to match
that run-derived prefix. Sharing this placement with terminal cleanup does not
share request scopes or grant cleanup authority; each workflow keeps its own
current capability, immutable claim and observer requirements.

## Actual workflow

The SQL projector resolves actual registry/binding stable IDs to the exact
Managed placement. A bounded read-only PostgreSQL transaction observes current
placement, binding and mutation pins. The independently valid credential-free
Managed ConditionalDelete capability is retained before opening the scoped GC
windows. Its reserved-key PutProbe/DeleteProbe operations remain a separate
prerequisite; they are not silently discarded from an opened business window
or described as metadata-only GC traffic.

The real producer then puts and reads back a distinct untagged OCI index whose
children come from the already published signed index. Normal maintenance must
establish current hashed inventory before the ordinary API review selects that
exact candidate. The same retained index is tagged only after review. Apply
must refuse the now-stale root closure, and a complete actual transport window
must contain no deletion request for the reviewed keys.

A separate real 256-byte blob supplies the positive candidate. Current
inventory, exact reviewed actions and a provider/guard snapshot precede Apply.
Each completed action is joined with its actual offered plan, consumed result,
compiled validation receipt, current action/evidence SQL, scoped awaited SDK
calls, independent R2 snapshot and retained same-key guard receipt. Missing or
ambiguous exchanges stop the workflow; no caller-created success flag fills a
gap. Every SQL observation keeps its private raw file, hash, count and query
commitment; an existing output is never replaced.
The credential-free fresh database URL is passed explicitly to `psql`; a URL
in `PGDATABASE` alone is not expanded by this invocation. Private stderr is
retained on failure, while public controller errors omit the connection URL.

Exact API replay reuses the original Apply. Physical replay separately uses the
actual stored positive claim and its exact receipt digest. A healthy matching
guard request with no SDK invocation and an unchanged stored receipt/provider
snapshot is necessary to establish no redispatch. Empty logs, dropped requests,
unknown replies or missing terminal brackets do not prove zero calls.

## Scope of evidence

The SDK collector covers `managed_inventory_range` and `managed_gc_guard`
requests only. The Node R2 snapshot and guard inspection are independent stored
state observations, not universal SDK call telemetry. Terminal OCI chunk
cleanup has a different owner and is outside this window.

The adapter leaves `nativeBulkBytes` unknown. Actual current compiled body
classification and original/received transport joins remain mandatory; a
result's `source_bytes` field alone cannot establish Native bulk forwarding.
No External provider version or Delete capability is fabricated. Managed R2
upload versions retain their real SDK meaning and are not S3 `versionId`s.

Local controller tests exercise controlled capture/codec joins and actual
private PostgreSQL projection/custody. Those gates establish fixture source
behavior. They do not establish a completed five-VM GC run, Hosted provider
qualification, an installed current codec tuple or an OCI artifact's Delete
authority. Actual runtime receipts must come from the selected composed tuple.
