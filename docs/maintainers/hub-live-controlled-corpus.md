# Controlled live delivery corpus

The live stream and metadata query need a newly captured `do-e2e` Worker. An
older direct-upload or mirror artifact does not exercise these routes. The
controlled runner creates no reviewer signature or production acceptance.

Use `pkgs/tools/aos-hub-live-runtime-http-e2e.mjs` for the measured physical
HTTP/TLS corpus. It launches the actual Rust Worker and a bounded TLS upstream
fixture with exact request-sequence and socket observations. Invoke it with the
explicit source-built Node path and a fresh private fixture directory. The
directory's `live-runtime.json` supplies these closed inputs:

```json
{
  "dist": "/nix/store/...-worker-dist",
  "workerd": "/nix/store/...-workerd/bin/workerd",
  "providerFixture": "/nix/store/...-fixture/provider.mjs",
  "sourceDigest": "<64 lowercase hexadecimal characters>",
  "wasmSha256": "<exact index.wasm SHA-256>",
  "shimSha256": "<exact shim.mjs SHA-256>",
  "scriptVersion": "<actual installed script identity>",
  "runId": "<32 lowercase hexadecimal characters>",
  "workerPort": 18796,
  "sourcePort": 18797,
  "sourceCa": "/nix/store/.../fixture-ca.crt",
  "sourceCertificate": "/nix/store/.../fixture-server.crt",
  "sourceKey": "/nix/store/.../fixture-server.key",
  "vars": {}
}
```

The private `vars` include the actual protected raw managed profile and private
policy used by the fixture. Their candidate source and script variables must
match the selected artifact. The controlled stream key, query key, storage-work
key and production ingress key have distinct roles. The query route requires
`HUB_MIRROR_LIVE_QUERY_CANDIDATE_KEY`; it is excluded from an ordinary Worker.
These fixture keys provide no hosted activation or publication authority.

After `live-ready.json` appears, invoke `aos-hub-live-runtime-run.mjs` with the
same directory. Its separate private `live-plan.json` selects `streamKeyFile`,
`queryKeyFile` and `target`. The key files contain the exact installed bytes,
without implicit trimming. The target supplies the real controlled profile
digest and positive registry, mirror, placement, write and binding coordinates.
This context is a controlled request, not a fabricated Native IAM grant.

The physical HTTP/TLS path passed all thirteen controlled cases on the captured
Rust artifact. The cancellation case deliberately resets the exact matched
client TCP connection before cancelling its response reader, at 65,536 consumed
bytes. It requires cancellation of that original upstream response before EOF;
the socket and source observations must precede fixture teardown. The retained
ordinary reader-cancellation comparison did not show prompt upstream
cancellation and is not counted as a passing cancellation observation.

`aos-hub-live-runtime-e2e.mjs` is a separate service-binding diagnostic. Its
upstream has no physical HTTP/TLS socket. A comparison with incoming request
signals enabled passed twelve cases but failed the exact source-cancellation
callback predicate, despite client reset and fresh capacity reuse. That failure
is retained; the service-binding path does not establish upstream cancellation
or substitute for the physical HTTP/TLS corpus. Its checked-in launcher remains
unchanged by this scope correction.

The runner executes thirteen cases, including two metadata reads during an
open bulk response, client cancellation, expiry after an admission wait, and
the actual shared bounded query executor. It hashes client bytes incrementally
and retains only bounded query bodies. Query replies must authenticate in their
separate domain and match the full original, fresh nonce, body SHA and source
byte count. Streaming a small body cannot substitute for that query evidence.

Each captured original selects a unique source request sequence after its
pre-send watermark. Earlier cancelled streams cannot satisfy a later overlap.
The overlap case retains its actual partial bulk bytes and cancellation plus
both metadata control IDs. Refusal cases require the intended source status,
encoding and length observations; the three zero-dispatch cases also require
an actual HTTP refusal. A startup refusal cannot stand in for upstream negative
coverage, and an HTTP 200 with no source dispatch cannot count as a refusal.
Redirect refusal additionally requires exactly its one intended source dispatch;
following the redirect into a foreign source and then refusing is a failure.

Exact controls, bounded query replies, upstream pulls, cancellation and failed
cases remain in the private fixture directory. Process identity uses PID and
start ticks before optional memory sampling. Process RSS and Wasm allocation
are labeled as controlled observations; they do not establish the hosted
128 MiB budget. No provider cleanup or publication operation is dispatched.

Every report keeps production qualification `UNKNOWN`. The standalone
candidate does not prove current Native IAM, token revocation, nondefault
credential/refspec refusal, absence of Native bulk transport, or authenticated
production handler completion. Those require their actual Native SQL/control
receipts joined to the final artifact. Native authorization header bytes,
bounded internal query output, and raw upstream/client bytes remain separate.

The fixture source tests and JavaScript syntax checks validate harness code
only. A live runtime result requires executing this corpus against the newly
captured artifact and retaining the failures and original source identities.
