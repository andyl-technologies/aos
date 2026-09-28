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

The dedicated GCP project, PostgreSQL and credential resources are provisioned,
but no paired Native serving endpoint or public hybrid Worker route is deployed.
Signed delivery setup, SQL credentials, private credential mounts, initialization,
origin shielding and real cross-cloud latency/byte measurements remain pending.

Frozen external S3 physical GC, durable delete-receipt expiration/cleanup, and
whole-Hub snapshot/restore also remain to be implemented. This successful fleet
run is one acceptance checkpoint; it does not complete RFC-0023.

See the [deployment procedure](aos-hub-hybrid-deployment.md) and
[RFC acceptance gates](../rfcs/0023-hub-hybrid-topology/06-implementation-and-validation.md).
