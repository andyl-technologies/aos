# Local issuer scale observations

The source fixture in `tests/fleet/_hub-direct-issuer-scale.py` declares a
prospective local workload. It does not install a publication, approve a clock,
change runtime limits, sign acceptance or qualify a provider. Actual execution
requires a reviewed source/package tuple and genuine operator setup.

## Workload and targets

Each test profile selects 32 exact configured cohorts, four fresh isolated
workerd processes and at most 32 followers per cohort. Observe two actual
renewals at each maximum-lifetime input, 8 seconds and 120 seconds, plus an
issuer outage through actual token expiry. Failed or cancelled owners must not
retry inside their original immutable request window, bounded to 30 seconds.

The selected executor uncertainty is 2 seconds only if the actual operator
setup, publication and issuer policy validate it. Native's clock qualification
is separate: configured uncertainty plus positive commit latency plus one
rounding second must fit the issuer profile. With 2-second Native uncertainty
and the minimum 1-second commit-latency input, the issuer profile must permit at
least 4 seconds. Parsing either value does not qualify a clock.

Different immutable timing profiles require distinct genuinely fresh physical
namespaces and issuer stores. Never reset or adopt an existing journal to obtain
a fresh case. The existing 5-second cache reuse margin remains unchanged; a
short profile can be ineligible for warm reuse. Retain that actual outcome.

The local targets are warm p95 below 100 ms and p99 below 250 ms, cold p95 below
500 ms and p99 below 1 second, and whole dedicated-issuer CPU at most 50 percent
of its actual allocated CPU under the complete declared workload. Report sample
counts, errors, actual renewal count R and actual RPC counts. A two-cohort run
cannot substitute for this geometry, and coalescing alone establishes no jitter,
headroom, fleet fanout or hosted qualification.

## Explicit private recorder

`aos-hub-authority serve --qualification-observation <private-file>` opts into
local recording while preserving the normal journal, keys and policy. Omission
uses the existing unobserved opening and serving paths. The separate closed
configuration contains:

```json
{
  "run_id": "<32 lowercase hex>",
  "selected_source_sha256": "<64 lowercase hex>",
  "executable_sha256": "<64 lowercase hex>",
  "authority_configuration_sha256": "<64 lowercase hex>",
  "output": "/absolute/private-observation-directory/new-run.jsonl"
}
```

The executable is hashed through its actual running `/proc/self/exe` descriptor.
The opening record captures the actual PID and `/proc/self/stat` start ticks;
the collector requires the independently captured matching process lifetime.
The authority configuration pin hashes its loaded canonical Rust serialization.
The source digest is an independently selected input: the collector still needs
the exact build-to-executable provenance. The recorder does not infer source
identity from a supplied digest.

The output directory must already be owner-private mode 0700 and separate from
the journal directory and Hub root. The recorder creates one new mode 0600 file
without following a symlink or replacing an old run. Its limits are 1 KiB per
record, 262,144 records and 256 MiB total. These are recording limits, not reduced
runtime workload limits. Overflow, partial writes or changed custody invalidate
the observation window.

Records contain only fixed event names, nonce and body/installation commitments,
byte counts, timestamps, durations and outcome labels. They contain no key,
full request/publication/cohort, token, signature or provider credential. Logging
failure does not change an issuer authority result or manufacture success.

The optional local serving path handles Ctrl-C as orderly HTTP shutdown before
terminal recording. Immutable request handles remain held by any late blocking
journal work. A still-held handle prevents a healthy terminal record; shutdown
never asserts that an indeterminate write or remote provider effect settled.
Abrupt termination or a missing tail remains incomplete measurement. The optional
server reports recorder completion failure through its exit status. Visible
footer bytes alone do not prove that the final sync succeeded: the collector
retains `durableRecorderCompletion: null` until an independently captured
successful terminal exit is joined to this exact process lifetime and file.

## Measurements and missing joins

The recorder measures the actual issuer gate wait. Its synchronous signature
callbacks bracket the Ed25519 call after message validation/serialization, for
lease and reply purposes separately. Native samples safe thread CPU on the same
thread with no await between samples. Missing, backwards or invalid samples are
absent, never zero. Whole process CPU is a separate sample over the explicitly
recorded monotonic window, never CPU per signature.

Every recorded transaction outcome follows the actual SQLite commit call.
Read-only, clock/session, lease, control and recovery transactions are labeled
separately. An error is indeterminate, and a post-commit file check remains
mandatory. Journal sequence increments and WAL size are not commit counters.
Clock/startup transactions can lack a request join while contributing to the
clearly labeled process totals.

The collector validates private file custody, exact sequence/tail counts,
immutable per-request pins and closed event shapes. Its output retains
`qualification: null`. Actual issuer transport/body/signature joins, current
operator/publication validation, four independent workerd lifetimes, expiry,
cohort renewal transitions, outage and allocated CPU evidence must be added by
the reviewed runtime collector. Missing measurements must be obtained at those
real seams; a caller PASS or synthetic count cannot replace them.

Focused format and concurrency tests establish source behavior only. No package,
runtime, hosted provider, clock, maximum-scale budget or full fleet result is
implied by those tests.
