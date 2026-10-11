# Lease renewal coordination and qualification

The External stage executor coordinates identical renewal misses inside one
Worker isolate. This optimization creates no fleet-wide cache, provider
permission, new epoch or settlement receipt. Every ordinary effect still checks
the exact authenticated lease against its permanent addressed guard.

## Runtime bounds

The renewal helper uses the existing consumer/cache ceiling of 32 exact
cohorts. Each pending cohort admits one owner and at most 32 followers; excess
admissions refuse. The coordination key commits the original installation,
physical cache prefix, issuer key ID/public verifier, timing profile, selected
clock uncertainty, full cohort and renewal-material commitment. Transport key
separation is checked before cache or pending-flight reuse.

Only the owner polls the authenticated issuer request. Each follower creates a
50 ms timer in its own invocation. Futures, Promises and wakers are never shared
between Durable Object invocations. A follower retains the owner's original
exclusive request expiry or its own earlier deadline, never a refreshed window.
Conservative current time is checked after waits and before token return. The
owner also races its original request against these timers.

An owner error, timeout or cancellation makes that flight unavailable until its
original deadline, at most 30 seconds. No waiting or newly arriving caller takes
over that flight. At expiry a new call can create a distinct fresh request;
removing isolate coordination does not resolve a lost issuance, drain remote
work, roll back the issuer's history or clear a physical unknown journal.

The existing five-second early-refresh margin applies to cache reuse. A freshly
verified token with a shorter attestation-capped lifetime can still be returned
while conservatively fresh; that token is not made cache-eligible by coalescing.

## Evidence still required

The existing fleet lifecycle helper measures two genuinely configured cohorts
through the selected shared `issuer_prepare`/`issuer_verify` codecs and actual
Worker-to-Native transport. Its original cutoff and cold-refusal scope is
unchanged. Two cohorts do not establish the maximum-32-cohort workload.

Native helper tests exercise the production coordination state machine with
controlled issue closures. They check one owner under concurrent misses, 32
independent pending cohorts, follower admission, scope/custody substitutions,
original deadlines, short capped tokens and cancellation without takeover.
Those closure counts are not issuer RPC, signature CPU or durable-commit
measurements. Wasm compilation establishes no workerd scheduling qualification.

For the final selected runtime tuple, retain the following actual observations:

| Requirement | Required observations | Current limitation |
| --- | --- | --- |
| Maximum cohort traffic | All 32 independently configured cohorts, exact source/configuration, isolate identities, owner dispatch and issuer request/reply joins | The current fleet configuration has two cohorts |
| TTL extremes and cap | Selected profile lifetime/clock bounds, original requested horizon, signed issue/expiry times and exact attestation cap | A separate minimum TTL is not configured; never invent a smaller qualification policy |
| Renewal interval | Per-isolate/cohort issue times and actual RPC counts over a retained traffic window | Measure `R`; neither `C/T` nor the early-refresh margin proves an observed rate |
| Cold fanout and retries | Actual region/isolate startup identities, simultaneous requests, refusal/backpressure counts and original retry windows | A deployment fanout or issuer budget is not declared by this helper |
| Issuer budget | Actual queue/latency p50/p95/p99, offered/consumed metadata bytes, issuance history and independently attributed CPU/commit observations | Missing measurements remain unresolved; sequence advancement is not total SQLite commit count |
| Outage through expiry | Actual failed issuer requests, retained token expiry, final dispatch refusal and zero new provider dispatches | Helper cancellation is not a provider-outage or drain proof |

There is no declared jitter policy here. Coalescing alone qualifies neither
jitter, cold-start scale, clock behavior nor issuer budget/headroom. Do not
choose smaller cohort or fanout limits to turn incomplete measurements into
acceptance. Actual workerd and Hosted platform CPU, scheduling, memory, ingress,
clock, region fanout and durable-storage behavior need their respective measured
qualification. Missing values remain unknown.
