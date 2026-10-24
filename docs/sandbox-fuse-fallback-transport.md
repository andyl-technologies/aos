# Dormant bounded FUSE fallback transport

The separate C ABI V2 carries fallback-only regular-file OPEN, READ and
RELEASE. It embeds the unchanged V1 metadata operation and limit tables;
`aos_fuse_transport_run` and the production metadata runner remain V1.
The outer version/profile, embedded version, sizes and reserved flags are
checked exactly. No passthrough, ACL, xattr, sparse allocation or `SEEK_HOLE`
profile is enabled.

Rust reuses the existing dormant callback reducer, protected registration
journal and worker data plane. OPEN retains its pending worker pin until
durable exact readback precedes the actual C reply. Ambiguous publication
faults the session and retains the pin for teardown. READ verifies the whole
containing object before copying its requested slice to C's private reply
buffer; failed prefixes never become an error reply body. C captures one
absolute BOOTTIME deadline before file callback work and uses that same bound
for reply polling and retry. Positioned file I/O is cooperatively checked,
not preempted; an overdue operation cannot publish a late successful reply.

The resident reader has no production constructor. Repository fixtures own
real fs-verity-sealed backing FDs and use the existing exact object-descriptor
verifier, including media type and encoded size. At most 32 objects, two
retained FDs per object, 64 MiB per object and one 64 KiB verification buffer
are admitted. Resident object I/O opens no backing path, fetches no object and
retains no new backing FD.
This backing proves immutable bytes and inode identity, not consumer access.

The existing fake-core tests and six-record Rust/kernel fixture are extended,
not replaced. Prepared cases cover mixed ABI/profile refusal, exact and stale
handles, whole-object digest/size failures, no partial replies, EOF, sparse
byte holes, cancellation, bounded buffers/retries, ambiguous OPEN and
terminal teardown. The optional installed fixture seals its own one-byte
object and checks READ/EOF, mapped-owner mode-000 denial, different-UID and
capability-empty same-worker-UID DAC, cancellation, descriptor retention,
worker exit, disconnect and unmount. Sparse byte-planner tests do not qualify
sparse allocation or `SEEK_HOLE`. Mount DAC does not establish worker memory,
`/proc` FD, service or MAC isolation. This checkpoint has not yet compiled or
run these cases; it is not a production or installed qualification claim.

## Remaining production owner joins

Two authority seams remain mandatory, not waived by these fixtures:

- The existing Publisher/worker backing owner must authenticate the exact
  worker-consumer session, current policy/read grant, projected object and
  catalog publication before handing an owned `FsVerityBacking` to the
  reader. `PublisherDomainService::serve_publisher_open_for_read` currently
  serves publisher-self only. Its exact current request/catalog and received
  FD checks can be reused, but that session cannot be relabeled a consumer.
  The next interface needs an owner-minted, move-only consumer admission
  bound to the prepared worker/lease and exact object, with closure of that
  authority and retained FD on teardown. A public raw-proof or reader factory
  is not an acceptable substitute.
- The existing Mount owner must bind the exact connected `/dev/fuse`
  open-file description to its protected view/attachment, worker attempt,
  lease and mount permission observation before transferring it to this
  runner. The current Mount-qualified metadata candidate receives a separate
  connected FD whose exact custody is not bound by its qualification. The
  owner interface must retain that joint custody through publication,
  cancellation and teardown, and reject substituted, cloned-for-another-
  connection, stale or incorrectly configured descriptors.

Neither interface is implemented by this dormant slice. Public FUSE backend
readiness and Acquire remain closed; no new source/pin authority, trust
service, key or privileged capability is introduced.
