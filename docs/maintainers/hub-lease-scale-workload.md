# Local lease-scale workload

This fixture exercises the published renewal helper through the protected,
`do-e2e`-only lease-scale probe. It does not install runtime acceptance, validate
provider capability, or qualify Hosted execution. Source tests use explicitly
controlled projection files and local HTTP stubs. Their results are separate
from an actual issuer/workerd workload.

## Declared prospective local policy

The selected policy is `LOCAL_LEASE_SCALE_POLICY` in
`tests/fleet/_hub-direct-issuer-scale.py`. It requires 32 exact cohorts, four
fresh isolated workerd processes, and at most 32 followers for each cohort's
owner. Every full wave offers **4 × 32 × 33 = 4,224** distinct protected probe
originals concurrently. No smaller admission limiter is substituted.

The two maximum-lifetime cases are 8 and 120 seconds. Each preserves two actual
renewal candidates, followed by issuer outage through the last actual token
expiry. A separate capped120 case uses its own fresh authority, namespace,
physical store, and issuer journal. It requests the existing 120-second profile
under an independently selected shorter attestation. Returned expiry must equal
the actual attestation bound; subsequent calls must observe actual HTTP refusal
beyond that expiry. The capped case does not replace either full TTL workload.

These are prospective test inputs, not existing production limits or clock
qualification. The actual operator and Rust validators must accept each profile.
The selected consumer uncertainty is two seconds. Native's uncertainty, positive
commit-latency bound and rounding allowance remain separate policy inputs and
must satisfy its existing issuer validation. Profiles and namespaces are never
changed by resetting or adopting a used journal.

The current five-second cache refresh margin stays unchanged. An 8-second token
may have no eligible warm interval. The fixture records actual misses rather
than changing that margin or treating a successful reply as a cache hit. The
existing implementation has no separately configured random renewal jitter;
actual dispatch timing can show dispersion, not a measured jitter policy.

Local budget targets are warm issuer p95 below 100 ms and p99 below 250 ms;
cold issuer p95 below 500 ms and p99 below one second; and whole dedicated-issuer
CPU at most 50% of its actual allocated CPU under the declared workload.
Measurements must name their intervals, allocation, sample counts and errors.
Process CPU is never converted into an inferred per-signature CPU sample.

## Genuine setup and called workflow

`tests/fleet/_hub-direct-issuer-scale-setup.py` exposes:

- `bootstrap_scale_bindings`: 16 normal root Plan/Apply binding originals and
  all five credential purposes. It retains initial unstaged refusal, exact
  operator staging, explicit retry and genuine controller completion.
- `admit_scale_authority`: one reviewed physical authority, 16 actual current
  binding associations, an exact current credential attestation and sorted
  admission. Its evidence commitments are independently selected inputs;
  Root Plan/Apply remains the authority.
- `export_scale_associations`: the actual source-built bootstrap command,
  once for each association into a **new** private output directory.
- `project_scale_exports`: 16 actual private canonical exports, four distinct
  process labels and exactly 32 read/write cohorts. Every export must carry
  byte-identical full SQL publication bytes. The production 128 KiB consumer
  bound is enforced without truncation or replacement of the publication.

`tests/fleet/_hub-direct-issuer-scale-workload.py` exposes
`run_selected_scale_cases`. The final Fleet controller calls it with three
independently selected cases in order: `ttl-8`, `ttl-120`, `cap-120`.
Its `prepare_case` callback performs the genuine setup above, runs the ordinary
issuer bootstrap, and starts four actual selected fresh workerd processes. It
returns exact source, configuration, process/cohort context, private control key,
output root and a scoped issuer-stop callback. Those returned dictionaries alone
are not authenticated observations or qualification.

The existing issuer provisioning and Worker lifecycle helpers have singleton
roots. The scale controller must provide separate per-case issuer roots and
per-process persistence/configuration/log/socket paths. It must not overwrite
their singleton `worker.pid`, acceptance socket or used journal. The ordinary
Worker runner serves TLS: select its actual CA bytes/digest and certificate
hostname. `loopback_http` is an explicitly selected controlled transport, not a
fallback from failed TLS.

All four configurations install the real selected exported consumer and
`HUB_LEASE_SCALE_FIXTURE`, plus `HUB_LEASE_SCALE_OBSERVE="1"`. The compiled source
must include the published probe and dispatch observer. Every module/source,
process PID/start lifetime, configuration, issuer store and physical namespace
is captured before workload dispatch and rechecked after waits. Incompatible
cases must have distinct selected stores and authorities before setup begins.

The normal issuer bootstrap initializes a genuinely fresh journal from the
current exported full publication. It does not install signed readiness or
validated SQL flags. Provider credential validation is a separate genuine
setup prerequisite; do not run it or any workload before the final reviewed
source/package tuple and setup inputs are selected.

## Workload and capture joins

The first full wave is cold. The next is labelled `reuse-candidate`, not warm.
Two renewal-candidate waves wait beyond actual returned lease expiry. Positive
metadata must cover every selected process/cohort; missing or unknown calls
remain retained outcomes. During outage, only the recorded issuer process is
stopped. Its existing TLS proxy stays available, and every offered original is
sent once. Fresh waves are spaced beyond the previous immutable request window.
There is no automatic same-original retry, owner takeover, resource cleanup or
claim that an abandoned remote issuance drained.

The source observer emits bounded `aos_lease_scale_issuer_dispatch` records
immediately before actual issuer Fetch. Join their exact owner nonce, request
SHA/bytes, source/configuration/cohort and original issue/expiry to the existing
issuer TLS proxy's privately captured request/reply files. An attempt that never
reaches that proxy remains an actual unmatched attempt; proxy receipt counts
cannot substitute for all attempted Fetches. Missing/malformed observation
context marks the measurement incomplete, and missing records never imply zero.

Use the actual Native qualification recorder to join authenticated request
nonce/body commitments, signing gate queue waits, synchronous signing wall and
thread CPU samples, and acknowledged SQLite transactions. Retain refusal and
indeterminate transaction outcomes. The closed recorder file also needs its
actual terminal process result: a footer alone does not establish successful
durable completion. Use the existing bounded private capture helpers; no new
proxy or copied signature validator is needed.

Join positive probe lease digests to actual signed issuer replies, using the
selected source-built shared issuer codec. Preserve actual request/reply bytes,
cohort/current publication, token sequence/expiry, context, signing and commit
results. Report actual RPCs, successful issuances, renewals, failures, bytes and
latency samples. Cache-hit and coalescing ratios require complete independently
joined process windows, not merely 200 responses or offered request totals.

The workload deliberately leaves RPC/signing/commit fields absent until those
independent joins finish. The final workload must complete these measurements;
the placeholder fields are not an accepted permanent substitute. Neither probe
metadata nor a supplied context authorizes provider dispatch. Native bulk bytes,
Hosted clock/memory/CPU limits, whole-isolate headroom and deployment/fleet scale
remain separate observations; this fixture creates no zero-byte claim for them.

All raw controls and outcomes stay under exclusive owner-private file custody.
Each complete wave retains all 4,224 outcomes, at most 8 KiB per row and 64 MiB
per file. A write overflow leaves incomplete evidence, not a partial PASS.
The final controller retains the original signed controls, process/module
receipts and healthy or failed terminal states before producing a public numeric
report. No key, token or raw private body is logged by the dispatch observer.
