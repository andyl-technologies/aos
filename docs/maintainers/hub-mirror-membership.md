# Storage-local mirror Git membership

Hybrid closure discovery uses `InspectMirrorMembership` for at most 64 sorted,
unique SHA-256 OIDs. Native selects the current registry, mirror source,
placement, binding and protected managed profile from SQL and checks those
same generations after the result. Canonical loose objects retain precedence.
Encoded pack/index bodies have no Native fallback.

The Worker consumes the pair through bounded BYOB reads and verifies the
complete pack, companion index, CRCs, offsets, OIDs and resolved delta graph.
`finish_catalogue` exposes only sorted OID, kind and decoded-size summaries
after that verification succeeds. A negative answer proves absence from that
exact verified pair, not absence from other candidates or the registry.

## Bounds and cache lifecycle

The existing parser limits remain 8 MiB encoded pack, 4 MiB encoded index,
12 MiB simultaneously live decoded graph, 4 MiB decoded object and 65,536
objects. The complete semantic catalogue must additionally fit 8 MiB. An
unsupported count, size or format is an explicit refusal; there is no
truncation or whole-pack transport fallback.

The private Durable Object cache commits the actual compiled source and full
Native plan authority, including source/configuration generations and the
protected profile. Each header retains exact pair hashes, sizes, strong ETags,
pack trailer and complete page coverage. Repeat queries may require the prior
source commitment. A changed commitment refuses reuse.

Pages contain at most 256 summaries and 48 KiB each. Their digests are retained
in the complete header, which is written last. The cache has a fixed 600-second
lifetime from preparation; reads do not renew it. Alarm cleanup removes only
semantic cache data, never provider objects, journals or permissions. Missing
headers require fresh full verification. Missing or changed selected pages
refuse the query and cannot become negative membership.

Full pair parsing holds the single Bulk buffer admission. Cache reads hold a
metadata admission and load one bounded page at a time, even when the query
spans many pages. Fresh producer and parser qualification horizons are checked
after waits. Hot membership and inventory reads retain the exact original
plan audience and short deadline through every buffer and storage wait. Cold
immutable verification has a finite deadline 600 seconds after the original
plan issue time; a reply or cache access never renews it. These admission
bounds do not establish whole-isolate memory or
hosted runtime qualification; those require independent actual measurements.

## Controlled evidence

The source-built `do-e2e` runner has a separate query MAC purpose and reserved
candidate placement. It uses the same parser, cache pages and Native consumer,
with actual raw material pins rather than a production acceptance fallback.
The fixture can deliberately remove a semantic page/header, substitute a
source commitment or move the durable cache timestamp into the past. The
timestamp fault exercises fixed-expiry handling; it is not an elapsed hosted
TTL measurement.

Retained connected evidence must distinguish actual pair request counts,
cache hits across Durable Object restart, complete closure parity, refusal of
substituted pins, and fresh recomputation after expiry. Controlled evidence
does not activate managed production mirror or pack-inspection acceptance.
