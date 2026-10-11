# Terminal OCI chunk cleanup

Terminal upload cleanup uses each retained `oci_upload_chunks` row and its
actual terminal `oci_upload_sessions` original. Chunk rows remain in SQL after
cleanup. The existing all-upload compare-and-swap clears staging locators only
after every chunk has an authenticated positive physical receipt.

## Managed R2

The Native adapter requires the exact current deployment R2 placement, binding
and write revision, plus an independently validated Delete capability. An
OCI-only SDK anchor artifact does not grant Delete permission. New effects
also require the ordinary accepted Managed provider profile.

A fresh signed control lasts at most thirty seconds. Its stable operation
identity binds the terminal upload, immutable chunk and current Delete
capability. The existing physical key guard conditionally reads the actual R2
object, compares its opaque R2 version, size and strong ETag, and streams the
full SHA-256 beside storage. That R2 version is not an S3 `versionId`.

The guard persists its exact pending mutation before the key-only R2 delete.
Its SDK owner retains the physical key and provider capacity through actual
promise settlement. An exact durable positive receipt is returned under the
independent guard role. A cold retry reads that same receipt before any HEAD,
GET or DELETE, including after producer acceptance expires. A pending record
without the positive receipt remains unknown and cannot redispatch.

## External S3 or R2 through the S3 API

External cleanup additionally requires current, independently qualified Delete
credential custody and a real provider version on the retained positive OCI
chunk closure. The provider must honor the exact version and strong `If-Match`
precondition, and return the exact positive conditional-delete acknowledgement.
An absent HEAD, delete marker, versionless response or changed credential does
not settle cleanup. Historical credential rotation has no terminal-upload hold
and therefore refuses.

The pinned Garage 2.3 implementation does not provide this versioned conditional
read/delete contract. Its PUT-generated version header cannot qualify cleanup.
The controlled External OCI business pilot is separate from conditional cleanup
evidence; neither that pilot nor source checks qualify a hosted provider.

Local providers retain their existing cleanup hook. Provider memory, CPU,
consumption and hosted qualification require their own actual observations.
