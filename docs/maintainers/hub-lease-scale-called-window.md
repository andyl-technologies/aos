# Called local lease-scale window

The Fleet entry point is
`run_direct_lease_scale_window(client, native, worker, database_machine, tools,
database_host, artifacts)`. Call it after the original issuer's terminal cold
refusal has stopped its recorded process. Its retained resource, journal and
refusal are inspected; Native port 8444 must actually refuse a connection before
each separate case starts. The existing 8443 proxy stays alive. No original
journal is reopened, initialized again, recovered or taken over.

## Selected tools and resources

Append `_hub-direct-issuer-scale-main.py` to the existing Fleet controller.
Select separate immutable files in `tools["leaseScaleSources"]` for `setup`,
`workload`, `process`, `runtime`, `joins` and `collector`; each reference has
exact `path` and `sha256` fields. The main adapter executes their independent
namespaces to preserve existing fixture globals. Files are limited to 128 KiB.
Do not concatenate their implementation into the controller's global namespace.

Import `_hub-lease-scale-reply-codec.nix` with `pkgs` from the same independently
reviewed immutable runtime source. It builds `bin/lease_scale_observe` with the
Native package's exact source, Cargo vendor and environment. Retain its actual
ELF hash, store/deriver identity, example and Cargo.lock hashes, and runtime
library closure. `tools["leaseScaleReplyCodec"]` has `path`, `sha256` and
`sourceDigest`. The latter is SHA-256 of the exact Native package input store
path, and must equal the selected Native observer source digest. Evaluation or
a historical debug executable is insufficient build provenance. Do not build
the fixture separately from a stale source tuple.

Other tool references reuse the current Fleet Python, Node, workerd, runner,
Miniflare, Hub, authority/bootstrap, OpenSSL, PostgreSQL, curl and TLS inputs.
Supply `leaseScaleCertificateFile` and `leaseScaleCertificateSha256` for the
actual selected CA file on Worker. Probe clients load only those exact CA bytes
and verify `localhost`; they do not use ambient trust or disable TLS verification.
The actual realized artifact/source receipt must include the confined do-e2e
probe and dispatch observer. An ordinary Worker refuses the probe route.

The independent `lease-scale-policy` checkpoint selects the original terminal
reference and three genuinely different cases: ttl-8, ttl-120 and cap-120. Each
uses a distinct authority, namespace, issuer store, provider store and private
Worker root. Issuer and Worker roots are new single children of
`/var/lib/hybrid-lease-scale`; existing case roots refuse. The common parent is
checked for canonical owner-private custody. Sixteen new bindings with eighty
immutable credential references undergo actual queued credential validation,
root Plan/Apply, current restricted SQL readback and sixteen normal exports.
One exact full publication must match all exports. The unchanged consumer cap
of 128 KiB refuses overflow rather than truncating it. The physical authority
checkpoint additionally inspects all four actual empty namespaces and current
artifact/configuration pins before admission.

## Work and immutable owner waits

The policy keeps all 32 cohorts, four fresh workerd processes and 33 simultaneous
requests per cohort/process: 4,224 offered originals per complete wave. There
is no owner retry inside its immutable request window. The 8s and 120s profiles
and the selected 2s consumer uncertainty are prospective local inputs; normal
issuer/operator validation must genuinely accept their distinct constraints.
An 8s token may be cache-ineligible under the existing margin. Do not tune that
margin or report HTTP 200 as a warm cache hit.

Each TTL case retains cold and reuse-candidate waves, two renewal candidates and
outage through actual expiry. Before replacement, the called wait adapter reads
complete actual Worker dispatch log prefixes with pinned process lifetimes,
source, configuration and cohort. All 128 process/cohort owners are required.
It waits until the greater of the actual token boundary plus one second and the
last actual immutable issuer owner expiry plus one second. A short token cannot
license retry of its still-retained 30s owner. Missing or overlapping owner
coverage refuses the wait. Actual owner originals, log prefix digests, requested
boundaries and wait start/completion UTC remain in the private result. They are
not guessed from successful probe responses. The separate capped120 case joins
its actual returned expiry to the independently selected attestation bound.

## Independent observations and limits

Every child has an exact executable/input inventory, PID/start-time readback,
private log, supervisor-owned terminal wait and fresh resource root. Scoped
signals use a pinned pidfd after rechecking lifetime. Issuer shutdown uses SIGINT
so the explicit observer can acknowledge its closed file; absent or failed
terminal/footer evidence stays unresolved. There is no broad process cleanup.

The collector keeps actual Worker pre-Fetch attempts distinct from proxy arrivals,
consumed replies, Native work and probe consumers. Attempt/request hashes and
sizes, owner nonce, selected cohort, reply hashes and actual shared-codec signature
verification must join exclusively. Successful issuance also requires the exact
Native lease/reply signing events, acknowledged lease commit and completion.
Unreceived attempts, transport failures and refusals remain actual outcomes.
The historical codec accepts no new time, emits no token/key and confers no live
permission. Actual Worker token/current-cutoff checks remain separate evidence.

Warm/cold issuer budgets use actual Native work samples, never inferred HTTP hit
rates. Keep p95/p99, queue wait, signing wall/thread CPU, missing samples,
acknowledged commits and real control bytes. The whole serving-window CPU average
includes owner waits, TTL waits and outage. It remains separately labeled and
cannot establish the loaded CPU target.

Each exact offered wave additionally requests real issuer process CPU samples
before and after its unchanged 4,224-call executor. The existing private controller
handshake has at most 32 sequential endpoint originals, with a fresh nonce, exact
wave-original digest, selected source and both PID/start-time pins. Complete
private files are published atomically without replacement. Controller-retained
raw endpoint acknowledgments must match the workload copies exclusively. Missing
acknowledgments are not retried or replaced with zero counters.

Both endpoints recheck the issuer executable/configuration files, PID/start-time,
full arguments, affinity and every visible ancestor cgroup quota. A hidden root,
changed allocation, vanished issuer or regressed counter gives an unknown result.
The numerator uses actual user plus system tick deltas with a conservative two-tick
upper allowance. The denominator uses the actual offered-wave monotonic duration
minus twice its measured clock resolution. CPU sampling handshakes and owner/TTL
waits do not enlarge that denominator. Every retained request body/hash/original
and both raw endpoints must join the exact wave. No process average is interpreted
as CPU for an individual signature. Outage or missing samples cannot satisfy a
loaded budget.

The prospective targets remain warm p95 <100 ms/p99 <250 ms, cold p95 <500 ms/p99
<1 s, and whole dedicated-issuer CPU during each offered wave at most 50% of its
observed allocation. Missing latency, queue/signing CPU or loaded process samples
stay unknown. Their actual acceptance is a separate review; an observed failed
budget remains a failure even if the serving-window average is lower.

Closed private logs and wave files cross machine-agent transport in chunks of at
most 4 MiB, each checked against the complete original identity and final digest.
This avoids its 16 MiB frame ceiling. Recorder logs remain bounded to 256 MiB,
wave files to 64 MiB, raw issuer body corpus to 512 MiB and codec pairs to 64 MiB.
Collector/controller Python heap overhead and whole-workerd isolate headroom are
not measured by these bounds. Same-second ordering remains ambiguous when the
issuer's integer UTC cannot establish whether a consuming wave reused an owner.

Source tests and the Core example gate establish fixture correctness only.
No actual 32-cohort workload, jitter, maximum-fleet ratio, Hosted clock, provider
capacity, Native bulk-zero or whole-isolate memory qualification follows from
those tests, a configuration, an invocation marker or supplied dictionary.
