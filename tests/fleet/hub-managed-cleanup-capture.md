# Managed cleanup reply-loss capture

The separate Managed pair may select `managedCleanupLossUpstream =
"http://127.0.0.1:4660"` before any process, configuration, Clock or purpose
observations. The default is `null`; other upstream values refuse evaluation.
Only `POST /_internal/storage/managed-oci-cleanup/v1` is intended for the
listener. The proxy preserves the canonical Host, offered body, cleanup MAC,
actual `x-aos-storage-call-id` and its own `x-aos-fleet-request-id`. These IDs
are correlation only and confer no permission. Every other route keeps the
ordinary upstream. The listener must independently refuse unsupported methods,
queries, chunked bodies and malformed or missing controls.

The process owner must start and validate the actual pinned listener before
Clock observations or cleanup traffic. Its ready record binds the listener's
PID, start ticks, owner UID, configuration and source hashes, listen address
and fixed route. Readiness is bind/listen evidence, not proof of authentication
or completed provider work. The existing process owner retains the actual
ready record and checks it against its independent launch pin.

The listener accepts one Content-Length of 1 through 16,384 bytes and one
`x-aos-managed-oci-cleanup-signature`; the reply is also bounded to 16,384
bytes. It forwards through the selected Worker TLS address with localhost SNI
and actual selected CA. A one-shot arm must bind the actual SQL original,
profile, helper input and original deadline. Only the same-source production
request/reply validators may authenticate a fully consumed reply before the
listener resets the downstream connection without sending reply bytes.
Missing, truncated, refused or unauthenticated replies remain unknown.

The Managed Native-outbound and Worker-received proxies retain the exact
request/reply cleanup MACs in their owner-private version4 header logs. Shared
summaries contain only file references, hashes and byte counts. Historical
version2/version3 records remain closed and unchanged; ordinary External
proxy configurations retain version3. No bearer, cookie, CSRF or provider
credential is selected. Cleanup capture remains unsupported by the general
Copy/OCI acceptance classifier until the separately reviewed exact cleanup
codec and independent handler/current SQL/purpose/provider joins exist.
Consequently these captures cannot establish Native bulk bytes of zero.

The proxy does not implement loss, arm the listener, authenticate a MAC, or
renew a cleanup deadline. All original body/header records and incomplete
outcomes remain retained for the actual selected controller to join. Fixture
application-body counts are distinct from TLS framing and provider billing.
