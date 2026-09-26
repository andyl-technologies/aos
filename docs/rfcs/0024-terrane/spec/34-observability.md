# 34 — Observability

This file owns what an implementation exposes so that an operator can answer
"why was this read slow", "why did this rule fire", "how far along is this
backfill", "is this backend healthy", and "who changed this entry" without
reading code. It defines decision logs, request tracing across tiers, status
surfaces, metrics, and audit through the commit graph. The vocabulary of the
status surface is deliberately git's, because the model is git's.

## Model

Terrane has four kinds of things worth observing, and each has a natural
record:

| Concern | Record | Where it lives |
| --- | --- | --- |
| a request's path through tiers | a trace with one span per hop | per request, exported |
| a policy decision | a decision log entry | per exposure, queryable |
| the state of a store or tree | status: refs, completeness, residency, health | on demand |
| who changed what | the commit graph and provenance | in the store itself |

Nothing in this file adds mutable state to a store. Audit is a walk of
commits; status is derived; traces and logs are emitted, not stored in the
bucket.

## Request tracing across hops

- **[OBS-1]** Every request over the [wire protocol](18-protocol.md) MUST
  carry a trace context (W3C Trace Context `traceparent` and `tracestate`
  headers, or their equivalent in the transport's metadata) and MUST
  propagate it to every tier it consults, including presigned bulk reads
  where the transport allows a header. *Gate:* `gate:obs-trace-propagation`.
- **[OBS-2]** Each tier MUST add one span per hop with: the store expression
  node that served it, its [locality](19-tiering-and-topology.md), the
  outcome (`hit`, `miss`, `error`), bytes returned, and elapsed time. A
  response MUST include the hop count and the per-hop latency list in its
  trailer or metadata so a client can log it without a tracing backend.
  *Gate:* `gate:obs-hop-latency`.
- **[OBS-3]** A [realizer](26-surfaces.md) MUST attribute page faults and
  opens it serves to a trace when a request context is available (for
  example, a control-socket request that triggered materialization), and
  MUST otherwise emit per-exposure aggregate counters rather than per-fault
  spans, so tracing never sits on the fault path.

## Decision logs

- **[OBS-4]** Every fired [ruleset](31-routing-rulesets.md) rule MUST produce
  a decision-log entry containing: exposure id, evaluation point, path, the
  object hash if known, rule id, action, and whether the result came from a
  memo. *Gate:* `gate:obs-decision-log`.
- **[OBS-5]** Decision logs MUST be queryable per exposure for the lifetime
  of the exposure plus a configured retention, filtered by path prefix, rule
  id, and action. `guard` decisions MUST be retained at least as long as any
  other decision.
- **[OBS-6]** A `guard{deny}` decision MUST also be emitted as a security
  event with the token identity that was denied
  ([`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)).

## Status

- **[OBS-7]** An implementation MUST provide a status surface, over both the
  command line and the protocol, with these operations and this vocabulary:

  | Operation | Reports |
  | --- | --- |
  | `status <ref>` | current commit, writer epoch, home, profile, per-property completeness, dirty state of any writable exposure of it |
  | `log <ref>` | reflog and commit graph with provenance |
  | `diff <a> <b>` | entry-level differences, with `--stat` summary |
  | `show <commit\|object\|tree>` | the decoded object |
  | `where <view>` | residency by tier and locality as a histogram of bytes |
  | `tiers` | the store expression with per-tier health, hit ratio, residency, capacity |
  | `jobs` | every job branch with cursors, counts, and completeness ([`32-tree-jobs.md`](32-tree-jobs.md)) |
  | `gc` | current cycle, roots counted, marked bytes, sweep candidates, tombstones pending |
  | `exposures` | every running exposure with surface, endpoint, view, mode, and lag |

  *Gate:* `gate:obs-status-surface`.
- **[OBS-8]** `status` MUST report, per property that requires derived data,
  the [completeness](08-properties.md) fraction and the count of entries
  missing it, computed or cached with a stated staleness.
- **[OBS-9]** `tiers` MUST report, per backend, whether the
  [conditional-write probe](13-bucket-layout.md) passed, when it last ran,
  and whether the backend is currently accepted as a ref authority.
- **[OBS-10]** `exposures` MUST report, for each `follow` reader
  ([`20-consistency.md`](20-consistency.md)), the commit it currently
  presents and its lag behind the ref's head in commits and seconds.

## Metrics

- **[OBS-11]** An implementation MUST export at least the following metrics,
  labelled by store expression node and, where applicable, by exposure:

  | Metric | Kind | Labels |
  | --- | --- | --- |
  | `terrane_reads_total` | counter | tier, outcome |
  | `terrane_read_bytes_total` | counter | tier, outcome |
  | `terrane_read_latency_seconds` | histogram | tier |
  | `terrane_hops` | histogram | surface |
  | `terrane_residency_bytes` | gauge | tier |
  | `terrane_evictions_total` | counter | tier, reason |
  | `terrane_pins` | gauge | tier |
  | `terrane_reservation_bytes` | gauge | tier |
  | `terrane_ref_watch_lag_seconds` | gauge | ref |
  | `terrane_commits_total` | counter | ref, outcome |
  | `terrane_commit_latency_seconds` | histogram | ref, durability |
  | `terrane_merge_latency_seconds` | histogram | kind |
  | `terrane_merge_entries_visited` | histogram | kind |
  | `terrane_gc_cycle` | gauge | store |
  | `terrane_gc_swept_bytes_total` | counter | store |
  | `terrane_gc_marked_bytes` | gauge | store |
  | `terrane_backend_health` | gauge | backend |
  | `terrane_conditional_write_supported` | gauge | backend |
  | `terrane_rules_fired_total` | counter | exposure, family, action |
  | `terrane_job_entries_total` | counter | job, outcome |
  | `terrane_property_completeness` | gauge | ref, property |

  *Gate:* `gate:obs-metrics`.
- **[OBS-12]** Metric names, kinds, and label sets are part of the
  specification; an implementation MAY add metrics but MUST NOT change the
  meaning of a listed one.

## Audit through the commit graph

- **[OBS-13]** The answer to "who changed this entry, when, under what
  authority" MUST be derivable from the commit graph and
  [provenance](23-provenance-and-trust.md) alone: an implementation MUST
  provide `blame <ref> <path>` returning the commit that introduced the
  entry's current object, its provenance, and the fold chain if the entry
  arrived by merge. *Gate:* `gate:obs-blame`.
- **[OBS-14]** Ref changes MUST be recorded in the reflog with the token
  identity that performed them, so a ref's history is auditable even when
  a commit's tree is unchanged (tags, rollbacks, forced updates).
- **[OBS-15]** An implementation MUST NOT require an external event store to
  satisfy [OBS-13] or [OBS-14]. External exporters are optional.

## Logging

- **[OBS-16]** Structured logs MUST include the trace id when one is present
  and MUST NOT include token contents, presigned URLs, or chunk plaintext.
- **[OBS-17]** Log events for security-relevant outcomes (denied access,
  fenced writer, failed verification, quarantined object, conditional-write
  probe failure) MUST be emitted at a level that is never suppressed by
  default configuration.

## Interactions

- [`18-protocol.md`](18-protocol.md) carries trace context and hop metadata.
- [`19-tiering-and-topology.md`](19-tiering-and-topology.md) feeds cost
  vectors from the same measurements that [OBS-2] exposes.
- [`20-consistency.md`](20-consistency.md) defines the lag [OBS-10] reports.
- [`31-routing-rulesets.md`](31-routing-rulesets.md) produces decision logs.
- [`32-tree-jobs.md`](32-tree-jobs.md) produces job status.
- [`35-performance-targets.md`](35-performance-targets.md) is measured with
  the metrics defined here.
