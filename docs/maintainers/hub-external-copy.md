# External S3 replication and repair

Hybrid placement scans can copy between different prefixes on the same External
S3 binding. Native selects the retained topology operation and both current SQL
placements; Worker reads and writes object bytes. Cross-binding transfer remains
unsupported. Missing capability returns an error without a Native byte fallback.

## Installed authority

`HUB_EXTERNAL_COPY_CONSUMER` is a version 1 JSON configuration with at most 16
binding domains. Each domain names the actual issuer installation, producer
profile digest, provider evidence commitment, independently installed Read,
List and Write cohorts, multipart part size, provider concurrency and listing
limits. Its canonical commitment is retained in every copy original. Changing
that commitment cannot rewrite or resume an older unknown provider turn.

Read requires conditional HEAD and range GET against a genuine immutable
provider version. List requires its own List cohort. Write requires multipart
Create, Part, Complete and Abort. The shared contract represents separately
qualified versioned PUT for empty objects, but this connected executor currently
refuses empty copies. Parts are 5–64 MiB, provider concurrency is 3–32, and listing
pages contain at most 256 objects. A smaller installed listing bound is
preserved across authenticated cursors and does not end a scan early.

Provider contract flags and an evidence digest are configuration checks, not
measurements. An operator must establish the actual provider behavior before
installing a domain. Direct-upload, private-stage or deletion qualification does
not qualify copying. This implementation does not provision credentials or
create an issuer association.

## Retained effects and recovery

The existing permanent physical-key guard stores the exact source version,
ETag, size, known catalogue SHA-256, destination pins, multipart upload ID,
part receipts and positive completion. The compact head points to that retained
original. Every new effect checks the original, current Native claim and
purpose-specific lease; generic mutation and staging cannot bypass an active
or unknown copy owner.

Source ranges use the retained version and If-Match. Worker hashes the stream
and refuses Complete when known content differs. Native accepts only bounded
metadata and rechecks the selected active catalogue object before reporting a
positive copy or committing ordinary placement-scan presence.

A lost provider acknowledgement remains unknown after process restart and lease
expiry. Read-only discovery returns the genuine retained original and compact
progress; it grants no dispatch or settlement authority. Retrying the logical
operation cannot repeat an unknown Create. A retained positive may replay
without provider mutations when its immutable source and current catalogue
still agree. An older positive without the known catalogue SHA is not silently
upgraded into a qualified copy.

Listing retains the exact signed provider prefix and cursor. Its guard floor
uses the canonical nonempty prefix boundary; source object keys are never
normalized. An entirely empty binding, placement and query prefix would select
the bucket root, for which this copy listing control currently has no guard
scope. Such a scan is explicitly refused. Managed R2 uses its existing adapter.

## Controlled evidence

The connected fixture exercised real Native SQL and operation Retry, a Native
issuer, persistent Worker guards across two process kills, and a versioned TLS
provider fixture. It copied an 8 MiB known object, committed scan presence,
preserved all mutation counters on cold positive replay, refused changed
content before any Complete request, retained an unknown Create, and scanned
130 objects with an installed page bound of 128. Catalogue, surface, path,
listed-version and cursor changes were also refused.

The observed Native transport carried 90,844 request payload bytes and 89,102
reply payload bytes over 67 calls, including separately classified operator
credential staging. No object-body forwarding call occurred. These are
application payload counts, not encrypted wire-byte measurements.

This is controlled workflow evidence. It does not qualify a hosted provider,
full fleet, throughput, cross-binding or empty copies, bucket-root scans or
issuer cold recovery. Earlier failed attempts remain retained separately.
