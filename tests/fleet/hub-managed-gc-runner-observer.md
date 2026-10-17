# Confined Managed GC runner observations

The additive `_hub-managed-gc-runner-observer.cjs` factory takes the actual
installed Miniflare runtime/options/configuration bytes, a fixed capture
selection and both existing actual namespace callbacks. Fleet owns the private
socket glue and fresh Managed Native/Worker pair orchestration. This helper
performs no SQL, credential provisioning, acceptance signing or capability
admission. Its local tests use controlled callbacks and stub responses only.

The factory retains the first complete R2 and guard reports without dropping
fields. `backingIdentity` is SHA-256 of the original serialized R2 report.
Before/after readbacks compare every R2 field except `observedAt`; guard reports
also retain `objectIds` as dynamic actual state while comparing every stable
field. Guard creation may legitimately add an object ID. A source, namespace,
configuration or process change refuses the request. Actual installed callback
provenance and runtime tuple must be joined separately.

The snapshot request is closed and limited to 32 unique selected keys and 32
unique explicit claim IDs:

```json
{"version":1,"kind":"managed-gc-snapshot","keys":["<exact selected key>"],"claimIds":["<actual SQL action ID>"]}
```

The result retains `backingIdentity`, both original namespace reports as base64,
fresh before/after namespace reports, actual `objects` metadata and actual
`guards` inspection replies. `guardReads` preserves exact consumed inspection
bytes/hash and the actual namespace stub ID. Independent Node R2 HEAD reads do
not observe the Worker's business SDK calls and supply no completeness field.
Each guard name is the actual deployment ID plus `:` plus SHA-256 of the exact
full key. The existing read-only do-e2e inspection supplies receipts/pending
state under that physical guard. Missing receipts remain null, not positives.

The distinct physical replay request is closed:

```json
{"version":1,"kind":"managed-gc-positive-replay","key":"<exact selected key>","claimId":"<actual action ID>","receiptSha256":"<SHA256 of prior actual receipt JSON>"}
```

At most 32 positive commitments actually read by this factory are retained.
Replay requires a prior positive snapshot, freshly re-reads the exact receipt,
requires the same actual `Deleted` original with no pending fences, then sends
only that stored typed claim to the existing same-key guard. It cannot submit a
new or missing claim. The actual response and unchanged guard readback are
retained. SDK zero-call evidence requires the installed Rust observer's healthy
matching request brackets; this callback cannot provide it. Public API Apply
idempotency is a separate result.

The private runner must bound input/output and use its existing owner-private
socket custody. Snapshots are limited to 1 MiB; each guard response to 128 KiB.
Uncertain, cancelled, stale or malformed observations refuse qualification.
No actual Worker artifact, SDK/provider execution or five-VM GC result is
qualified by source acceptance or these controlled tests.
