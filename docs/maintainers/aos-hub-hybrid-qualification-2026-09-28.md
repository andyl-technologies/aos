# Hybrid Hub fleet qualification: 2026-09-28

The four-VM fleet gate passed on implementation commit `6e81197430` using:

```sh
nix-build -A checks.fleet.hub-hybrid --no-out-link --keep-failed
```

Its result is
`/nix/store/vnmpgyxf72n802q0nghmbs7pv1pbgfsl-aos-fleet-test-hub-hybrid-0`.
The prerequisite shared application gate passed 3,966 tests, with six skipped.
Client, PostgreSQL Native Hub, the pinned Worker runner with R2 emulation, and
Garage S3 ran on separate VMs. All measurements below are from this local fleet.

## Current OCI requalification

The expanded container corpus uses the real signed AOS base image and its
complete source evidence. Its latest completed fleet attempt failed with HTTP
503 during manifest admission; it does not qualify nonempty container parity.
Runnable manifest admission still requested an ordinary stream for layer
metadata, and Hybrid's bounded reader did not admit OCI config blobs.

Native now queries small OCI configs and manifests through Worker ranges,
with a 4 MiB hard limit, the caller's semantic limit, and a fixed size and strong
ETag across all ranges. Layer metadata uses the existing inspection port.
Public object streams remain Worker-owned. All 21 Native storage client tests
passed, including new range, size-limit, changed-version and frozen-address
regressions. All 13 Native OCI Distribution integration tests also passed.

Frozen R2 GC now retains the claim's original prefix and placement version,
even after the current placement and capability observation advance. It
reopens only the matching binding and immutable write revision. Frozen absence
checks use Worker HEAD requests. External S3 cleanup remains unimplemented.

The full four-VM rerun using these corrections is pending. It must compare
nonempty container projections across Hybrid, Native-only and Workers-only;
the earlier empty-container comparison below remains a narrower qualification.

## Qualified paths

The run passed signed publication of two releases and a stable channel,
standalone Native indexing through the Worker, S3 metadata batches, large
multipart create/abort/complete, bounded writes, ranged OCI reads, binding
revocation, replay rejection, and Native-authorized Worker streaming.
Reviewed R2 cache GC passed physical deletion and protection of newly rooted
objects. Native and database outage/recovery checks passed.

Fresh Native-only and Worker-only deployments published the same signed
registry. Their indexed contents matched Hybrid across 25 table projections;
each deployment's local generation and retention digest were checked separately.
The canonical comparison SHA-256 was
`3b8e4407fc5d4808a2ee0509be6fb101345c5d1a2046f57710d67cf1033617a7`.
The corpus contained one package, two releases and one channel. Its five typed
container projections were empty, so this comparison does not qualify
nonempty typed container indexing parity. OCI transfer checks passed separately.

## Local latency and concurrency

| Measurement | Result |
| --- | ---: |
| Authenticated page baseline p95 | 21.078 ms |
| Authenticated page baseline p99 | 25.622 ms |
| Authenticated page p95 during parallel uploads | 13.085 ms |
| Loaded/baseline page p95 ratio | 0.621 |
| Direct Native page p95 during uploads | 16.176 ms |
| Parallel uploads | Eight, each 4 MiB |
| Upload p50 / maximum | 2.243 / 3.055 seconds |
| SQL pool limit / maximum open / maximum busy | 10 / 10 / 2 |

The baseline used 100 page requests; loaded Worker and direct Native samples
used 25 requests each. The run met the local upload isolation target.
These numbers do not establish
Cloudflare/GCP latency, placement, Worker CPU limits, or production capacity.

## Application byte accounting

Across 1,038 completed storage-work calls:

| Counter | Bytes |
| --- | ---: |
| Offered Native-to-Worker plans, including retries | 485,082 |
| Validated Worker-to-Native results | 878,158 |
| Object data processed at the Worker | 220,664,326 |

Cold indexing used 12 calls for release 1.0.0, seven for release 2.0.0, and
22 shared calls. An unchanged refresh used ten shared calls, offering 9,151
plan bytes and receiving 221,231 validated result bytes.

These application counters exclude framing and are not billed wire measurements.
Offered bytes do not prove delivery; validated result totals exclude rejected
responses. Storage-source counts may include repeated reads. Retain separate
error/cancellation accounting and provider telemetry for hosted qualification.

## Remaining qualification and implementation

### Subsequent Native image and database qualification

The dedicated Native service and bootstrap images passed
`checks.fleet.hub-native-container`. The authoritative result is
`/nix/store/j3ksy398zradsf8br1g04bsdcmjxgacw-aos-fleet-test-hub-native-container-0`.
Its shared application prerequisite passed 3,966 tests, with six skipped.
The VM loaded both real images, initialized the root through the bootstrap image,
authenticated with that initial password, changed the password, and retained the
authenticated session after a service restart. It also required each exact
hybrid startup rejection for missing PostgreSQL, JWT, and instance sealing keys.
The cold-container execution budget is 120 seconds; application checks and
request deadlines are unchanged. Container evaluator checks passed separately.

The production PostgreSQL-enabled Native binary from the OCI artifact also
migrated the actual new staging Cloud SQL database. Corrected direct readback
confirmed schema version 1, 260 tables, and zero users. Repeat initialization
passed without resetting the database. Companion infra commit `63f1a360`
records that evidence. Root administrator creation awaits explicit approval;
this database migration does not qualify Cloud Run mounts or a hosted paired API.

The one-shot diagnostic subsequently ran the actual Native OCI image on Cloud
Run through the bootstrap identity and immutable database secret version 1.
Execution `aos-hub-credential-probe-kc95r` completed with one successful task and
no failed tasks. Independent database readback again confirmed schema version 1,
260 tables and zero users. The image upload used an operator monolithic upload
with exact platform manifest and index readback; it was not a signed serving
release.

That image's database URL loader used ordinary file reads, so the execution
qualified the secret mount and SQL connector but did not enforce Native's
credential ownership, permission and link checks. The new loader shares the
bounded private credential reader used by Native signing keys. Three focused
tests passed for private URLs, insecure or linked files, invalid UTF-8 and empty
input without rendering credentials in errors. The shared application gate
subsequently passed all 3,971 tests, with six skipped.

The stricter image's platform manifest is
`sha256:cdda6348df55191f3c16d368ee5856ffdca6d773c27304ab8467b4da52053e09`.
Companion infra commit `bcbbadb3` passed its four required gates and three
locked-provider fixtures. Its exact plan preserved all 46 foundation resources
and updated only the diagnostic job's image. Apply
`20260928T160217Z-b9c53351fa008964` succeeded. Execution
`aos-hub-credential-probe-sfcwz` then completed with one successful task and
zero failures, enforcing the shared reader's file checks before SQL access.
Independent read-only SQL again confirmed schema version 1, 260 tables and
zero users. This qualifies the actual database credential mount and connector;
serving credentials, a Native endpoint and Worker pairing remain pending.

Cloud Run reported about four minutes of startup for this one-shot execution.
The task's reported start and completion were 4.316 seconds apart. Neither
measurement establishes authenticated-page latency or a cold database migration.

### Native settings browser qualification

The Native build containing the empty-registry console correction passed all
123 settings checks in real Chrome against the complete reviewed API fixture.
The binary was
`/nix/store/c2g0rsr1m61x526qcp5dviy2yb1wkaxv-aos-hub-0.1.0/bin/aos-hub`.
The initial registry overview rendered the publication prerequisite without
issuing `GetRegistryMetadata`; indexed registries retain their metadata editor
and API error handling. Instance appearance, branding review, organization and
registry configuration, and cache GC policy review also passed.

This manual run used isolated Native SQLite, not the hosted Hybrid deployment.
Its report and screenshots are retained at
`/tmp/hub-native-empty-registry-browser-qualified`. Hybrid browser qualification
remains pending.

### OCI upload request framing

The private diagnostic image upload exposed an empty-request framing failure:
Artifact Registry rejected the upload-start request with HTTP 411. A real
loopback regression reproduced that failure over HTTP/1.1; HTTP/2 already
passed. Explicit zero content length for empty Distribution request bodies
resolved the regression. All 53 OCI unit, layout, signing and registry tests
passed, including resumability, cancellation and credential containment.

The next hosted request reached upload data and returned HTTP 405. Artifact
Registry requires [monolithic uploads](https://docs.cloud.google.com/artifact-registry/docs/reference/docker-api);
the CLI uses chunked uploads. The framing correction does not establish complete
Artifact Registry push compatibility or qualify a hosted Hub deployment.

The dedicated GCP project, PostgreSQL and credential resources are provisioned,
but no paired Native serving endpoint or public hybrid Worker route is deployed.
Signed delivery setup, serving credentials, root administrator initialization,
origin shielding and real cross-cloud latency/byte measurements remain pending.

Frozen external S3 physical GC, safe retirement of obsolete object coordination
state, and whole-Hub snapshot/restore also remain to be implemented. This successful fleet
run is one acceptance checkpoint; it does not complete RFC-0023.

See the [deployment procedure](aos-hub-hybrid-deployment.md) and
[RFC acceptance gates](../rfcs/0023-hub-hybrid-topology/06-implementation-and-validation.md).
