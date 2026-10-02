# One genuine stale-placement read

This additive fixture tests the Native stale-result fence. It does not require
an already-admitted Worker read to be revoked immediately by a SQL placement
resource-version change. Provider reads that remain eligible before the real
physical lease cutoff are retained and counted independently.

The ordinary packaged command is:

```text
aos-hub index <actual-registry-slug> --topology hybrid
```

Use the selected Native installation's actual PostgreSQL, Worker origin,
deployment and private storage-work key configuration. Hybrid indexing already
checks Worker readiness and uses `HybridSurfaceProvider`. Its first index read
is `InspectMetadata { path: "info/refs" }`. After receiving the signed Worker
result, `HybridSurfaceFetch::execute` re-reads the placement and binding from
Native SQL and rejects a changed resource version before returning content to
the shared indexer.

## Confined hold adapter

Install `_hub-direct-stale-placement-hold.mjs` in the fresh test-only outbound
proxy, between the existing Native-original and Worker-received capture
boundaries. The existing proxy owns strict TLS forwarding, configured origin,
Host/audience, exact opaque signature and actual body-byte preservation. This
adapter does not create a listener, perform upstream requests, authenticate
HMACs or mint a plan. It is not a generic fault router.

Derive its closed selection from the actual current SQL placement and binding:

```json
{
  "version": 1,
  "originHost": "<actual configured Worker host>",
  "deployment_id": "<actual deployment>",
  "placement_id": 3,
  "placement_resource_version": 4,
  "binding_id": 5,
  "binding_resource_version": 6,
  "binding_kind": "deployment_r2",
  "placement_prefix": "<actual physical placement prefix>"
}
```

The numeric values above describe the schema, not fixture constants. Require
the independent SQL reader to join the selected registry/name to these exact
IDs, revisions, binding kind and prefix. IDs outside JavaScript's safe integer
range are unsupported by this confined fixture; they must not be rounded.

The proxy calls `await hold.beforeDispatch(request, originalBody)` before
opening the upstream request. A false result means the request was not selected
and ordinary forwarding continues. One matching canonical, bounded POST to
`/_internal/storage/v1/execute` waits; other operations and contexts do not
enter the barrier. Duplicate JSON fields, changed representation, wrong
transport shape and an expired selected plan refuse. The adapter stores the
exact body, selected transport/signature and held-state records in an existing
owner-private directory using exclusive 0600 files and file/directory fsync.

Use the fresh proxy's owner-private control channel to expose only `status()`
and `release(requestSha256)`. That channel must retain peer process identity
and exact source/configuration provenance. Its installation is a final fixture
composition dependency, not supplied by an unauthenticated public endpoint.
No SDK or provider authority is granted by a control message.

The closed status contains version, state, request/signature/plan-ID SHA-256,
decimal body bytes, original expiry in Unix seconds and actual observation
time in Unix milliseconds. A signature hash is not an authentication result.
Worker authentication must be joined to the actual received bytes and protected
handler evidence after dispatch.

`release` accepts only the same held request and real unexpired original.
It records release before allowing the caller's same body/header values to
continue. It checks for body/header changes across the wait. A second release
or another matching request refuses. Expiry and owner close retain the original
without automatic dispatch, retry, replacement or deletion. Neither a release
record nor a rejected promise establishes physical upstream dispatch or drain.

## Genuine revision and Native result

`advance_held_stale_placement` reads the retained owner-private original and
checks its exact hash/count, selected operation and original expiry. Using the
existing authenticated controls, it performs:

1. `TopologyService.GetPlacement` for the independently selected registry/name.
2. `PlanUpdatePlacement` pinned to that exact resource version, with only
   `updateMask: ["read_order"]` and the next actual `readOrder`.
3. The existing reviewed Apply path using only Native's returned plan ID and
   confirmation hash.
4. Fresh `GetPlacement`, checking the advanced resource version, exact new
   read order, unchanged prefix/binding/name and unchanged desired read policy.

The fixture does not change `desiredReadEnabled`, create a fake topology plan
or alter the original clock. The private control request/reply files and SQL
before/after pins must remain in the final evidence. If the real Plan/Apply
sequence outlasts the original deadline, retain the actual SQL mutation and
expired original; do not recreate or release it as a passing case.

Release the original once, wait for the actual packaged index child, and
retain its PID/start identity, exact installed executable/source/configuration,
stdout, stderr and terminal exit. `assert_stale_index_refusal` requires a real
nonzero, non-timeout exit with the current-SQL fence error and unchanged
authoritative index projection. The helper requires all 25 fixed outputs of
`registry_index_observations`, including nonempty package/release/channel data.
Only the index row's state/error may change, from fresh/no-error to failed with
the exact fence error. All remaining index fields and every other projection
must stay equal. Both complete snapshots receive retained commitments; no
arbitrary output field or row can be excluded.

These checks do not authenticate CLI stderr or dictionaries. Final acceptance
also needs the installed-source/process joins, genuine Native original and
Worker-received body/signature joins, actual protected handler result, current
SQL pins and complete provider observation window. Provider request counts and
`nativeBulkBytes` remain null in these helpers. A different binding-generation
pre-dispatch case requires a genuine acknowledged authority/control-floor
transition; this fixture supplies no such revocation.

## Local gates and remaining composition

Controlled Node tests exercise an actual loopback request waiting before its
callback dispatch, byte/signature preservation, one release, changed-body
refusal, actual UTC expiry and retained unknown close. Python tests exercise
exact metadata API request construction, private original custody, current-RV
refusal and authoritative projection checks. They do not execute Native,
Worker, TLS, PostgreSQL, authenticated Plan/Apply or provider storage.

Before runtime, compose the proxy callback/private control channel and genuine
packaged index process into the reviewed five-machine fixture. Its failure
window is separate from the normal throughput window and uses a fresh output
directory. Preserve the main three 2 GiB objects, 12,535 metadata objects,
normal publisher and all existing latency/capture gates. The genuinely
installed Worker/profile source-mismatch producer remains a separate pending
case; a changed source hash dictionary cannot stand in for it.
