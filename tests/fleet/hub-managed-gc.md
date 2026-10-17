# Managed R2 inventory and GC in the selected fleet

`_hub-managed-gc.py` is an additive helper for the existing five-VM controller.
It has no automatic main-flow activation, artifact build, provider installation
or direct provider DELETE entry point. Local tests exercise controlled evidence
refusals and compile the bounded SELECTs against actual immutable schema DDL.
They do not establish an actual publication, probe, inventory or GC result.

## Separate provider authorities

The selected Garage S3 fixture remains External. Its current implementation
does not supply selectable immutable versions or verified conditional DELETE;
the External positive case remains unsupported. Do not convert an internal
Garage UUID or an opaque Workers R2 upload version into an S3 `versionId`.

The Managed case uses the separately persisted Miniflare R2 bucket already
declared by the five-VM fixture. Registry creation reads the actual instance
default binding and requires `deploymentR2`, then creates a new explicit
placement, scans it and promotes its genuine writer through reviewed public
decisions. No existing placement is overwritten or adopted by this helper.

Before publication, the normal controller must install a new matching OCI-only
SDK tuple under the actual source/script/NAR, namespace, Clock, independent
reviewer, installer and Worker loader checks. That artifact qualifies its OCI
scope only. New GC effects use the actual deployment-owned R2 StorageWork route:
its signed plan is verified for the deployment and deadline, then the full-key physical
guard enforces the exact frozen claim. Native independently requires the real
conditional-delete probe's valid SQL capability at the exact binding resource
version and write revision. This route does not load a generic Managed Direct
provider acceptance profile.

Managed capability credentials are genuinely NULL because deployment-owned R2
does not use an External Delete credential. NULL is not a credential bypass for
an External binding. The helper neither manufactures these records nor treats
the OCI tuple as Delete authority.

## Actual workflow

1. Retain a genuine Distribution publication with a live tagged manifest and
   its config/layer closure, plus a separate unrooted object published through
   the actual Worker producer. The controller owns the real HTTP exchanges,
   actor, digest, object-key and SQL joins; the helper does not seed OCI rows or
   put final objects through `mf.getR2Bucket`.
2. Apply the real retention policy through `ContainerService`. Zero fixture
   grace/history bounds still retain mandatory live tags, signed roots, active
   uploads and referrers. Wait for the production bounded inventory collector
   at the current registry mutation epoch; require all observed hashes and real
   R2 upload versions, exact placement/binding pins and the independent probe.
3. `review_managed_gc` obtains the actor-bound plan and confirmation, then reads
   its actual candidate/action pages. It requires the exact unrooted set and
   excludes the tagged root closure. The fixture is bounded to 32 actions and
   refuses pagination beyond its selected page rather than dropping evidence.
4. Root a candidate with a genuine Distribution operation after review.
   `refuse_root_change` requires an authoritative Apply refusal and actual
   complete Native storage transport observation with no Delete plan offered
   for the reviewed keys. A placement
   revision change alone does not invalidate an already issued 30-second
   Worker plan: its eventual Native SQL refusal is a distinct result. Do not
   claim zero provider dispatch from that SQL change.
5. Recollect current inventory and review a fresh original. Apply normally and
   let the production controller acquire the genuine action claim. Join actual
   final SQL evidence to each consumed `DeleteIfMatches` plan/result, preceding
   exact SDK HEAD, acknowledged SDK DELETE, independent persisted-provider
   absence and exact permanent physical guard receipt. A pending/unknown turn
   or absent join refuses the positive assessment.
6. Replay the same Apply and idempotency key; require the same SQL operation.
   Separately replay only each actually retained positive claim through the
   private existing same-key guard. Require actual healthy matching brackets
   with zero SDK calls and unchanged persisted absence/receipt bytes. No missing
   claim is submitted, no signed plan is fabricated and no journal is cleared.

Terminal private-upload cleanup belongs to its separate implementation. A
canonical object GC claim is not an upload cleanup original.

## Observation interface

Fleet owns the future additive normal-flow/runner hook. `begin()` and `finish()`
must collect the installed Worker's actual scoped request records. No
initialized counters qualify this interface. A call is retained only with its
real result; thrown/unsettled calls cannot appear as `resolved`.
The collector must bound bytes before decoding; a window is limited to 4,096
records and 1 MiB, without raw object bodies. Each request allows at most 32 SDK
calls, 4 KiB per record and 256 KiB total. The collector requires complete actual
brackets for at most 64 expected selectors from authenticated requests/results.

```json
{
  "coverage": "scoped_requests_complete",
  "captureId": "actual-32-lowercase-hex-capture",
  "brackets": [{"requestId": "actual-request-id", "scope": "managed_gc_guard",
                "key": "actual-full-provider-key", "subjectId": "actual-action-id", "invoked": 2}],
  "backingIdentity": "sha256-of-retained-installed-namespace-and-persistence-observation",
  "calls": [
    {
      "callId": "actual-request-id:1",
      "requestId": "actual-request-id", "scope": "managed_gc_guard",
      "subjectId": "actual-action-id", "range": null,
      "sequence": 2,
      "method": "head",
      "key": "actual-full-provider-key",
      "result": {"version": "actual-R2-upload-version", "etag": "actual-strong-HTTP-ETag", "size": 42}
    },
    {
      "callId": "actual-request-id:2",
      "requestId": "actual-request-id", "scope": "managed_gc_guard",
      "subjectId": "actual-action-id", "range": null,
      "sequence": 4,
      "method": "delete",
      "key": "actual-full-provider-key",
      "result": {"kind": "resolved"}
    }
  ]
}
```

`snapshot(keys, actionIds)` independently reads the pinned `mf.getR2Bucket`
mapping and actual persisted `HybridObjectGuard` KV. The backing commitment must
identify the same installed bucket mapping, guard namespace, persistence root
and runtime tuple in both sources. Snapshot reads are not added to the Worker
SDK mutation window. The observer must retain their own actual read provenance.

```json
{
  "backingIdentity": "same-actual-64-lowerhex-observation-commitment",
  "objects": {"actual-full-provider-key": null},
  "guards": {
    "actual-full-provider-key": {
      "guardName": "actual-deployment-id:sha256-of-exact-full-key",
      "pendingDelete": null,
      "pendingMutation": null,
      "deleteReceipts": {
        "actual-SQL-action-id": {
          "claim": {
            "claim_id": "actual-SQL-action-id",
            "expected_etag": "actual-strong-HTTP-ETag",
            "expected_size": 42,
            "expected_hash": "actual-canonical-sha256-digest",
            "expected_provider_version": "actual-R2-upload-version"
          },
          "outcome": {"kind": "deleted", "etag": "actual-strong-HTTP-ETag"}
        }
      }
    }
  }
}
```

These are format sketches, not usable authority or accepted evidence. The
current Managed guard derives its name from the exact deployment ID and full
key SHA and retains `delete-receipt:<actionId>` before releasing its pending
turn. Its R2 DELETE is key-only, protected by the permanent same-key turn and
the exact SDK HEAD version/ETag/size comparison. It is not an S3 conditional
request and must not be reported as one.

The SQL projector uses only SELECT and bounded genuine rows. Its completed
action/evidence rows must be joined to the retained original and actual offered
and consumed bodies through the same-source compiled general storage observer.
Transport payload counts require those real byte captures; `source_bytes=0`
in a result, a helper assertion or an SDK counter does not establish zero
Native bulk forwarding. Missing authentication, context, purpose, original,
SQL or provider joins remain unknown, never a default success.

## Scoped SDK and retained-state observations

The do-e2e-only `HUB_MANAGED_GC_SDK_OBSERVER` configuration selects a capture ID
and exact dedicated key prefix. The installed Worker records real entry and
terminal brackets for `managed_gc_guard` and `managed_inventory_range` requests,
plus each actual awaited HEAD, ranged GET or DELETE at those callers. It covers
neither every R2 call nor Broker terminal-upload cleanup. SDK invocation is not
proof of an effect; actual result metadata and separate stored outcomes matter.
Unknown results, cancellation, dropped requests, overflow, missing records or a
missing healthy terminal leave the request incomplete. Console emission alone
is not acknowledged capture. The bounded collector requires actual matching
requests and all their records; an empty record list cannot attest zero calls.

The private runner pairs these records with actual `mf.getR2Bucket` snapshots
of the same durable bucket and the existing physical guard namespace. The
`/_e2e/managed-gc-state` POST route exists only in the do-e2e build and requires
the existing exact full-key header/guard identity, selected capture/prefix and
at most 32 explicit claim IDs. Under the physical-key gate it reads only those
retained receipts and pending fences. It performs no writes or provider calls
and grants no claim, dispatch, signing or drain authority. Its closed request
is `{"version":1,"capture_id":"<32 lowercase hex>","claim_ids":["<actual action>"]}`.
The reply contains `guardName`, `deleteReceipts`, `pendingDelete` and
`pendingMutation`, together with the selected capture ID and key.

An idempotent API Apply replay may return the original SQL operation without
reaching the physical guard. That is API evidence only. The distinct physical
replay callback must submit only the exact positive claim actually returned by
the prior persisted inspection to the existing same-key guard, retain its
actual healthy bracket, and show zero SDK calls plus unchanged receipt/provider
state. Missing or changed receipts cannot authorize this callback. Root-change
refusal uses the actual closed Native storage transport window to establish
that no Delete plan was offered; an empty scoped SDK log is insufficient.
The final normal-flow runner, installed tuple and real execution remain pending.
