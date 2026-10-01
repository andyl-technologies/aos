# Hybrid Hub fleet qualification: 2026-09-28

## Latest qualification scope

The latest coherent provider-version implementation passed the real SQLite,
PostgreSQL and MariaDB VM gate, including migration 002, populated inventory,
reviewed GC identities, cache presence reuse and atomic inventory publication.
The result is
`/nix/store/zra97jh7crfzwjm4nzvcvz90iyvrd0vm-aos-vm-test-aos-hub-live-sql-dialects-0`.

Independent review then found and corrected two Native adapter regressions:
external S3 inventory HEAD and range-hash replies legitimately omit R2 upload
versions. Five focused signed-loopback control tests pass with real SQLite
bindings and placements. External versionless replies remain valid, deployment
R2 HEAD requires a version, and range replies must match their signed expected
version. These adapter corrections postdate the SQL artifact above; the SQL
migration and controller source are unchanged.

The ordinary production Worker artifact
`/nix/store/5z39dr462qyi6z4ykxnm6ba1l7phkkd9-aos-hub-worker-dist-0.1.0`
passed 14 actual workerd checks with persistent Miniflare R2 and SQLite Durable
Objects. A test wrapper injects pending state, provider faults and effect
counters; normal signed HEAD and hash operations use the production handlers.
Checks include identical-byte replacement rejection, exact-version deletion,
terminal and legacy replay, missing-version rejection, unknown-outcome fences,
range identity and forward migration from persisted baseline storage. These
are local runtime checks; they establish no live Cloudflare provider guarantee.

An earlier full fleet attempt failed at the Native-only parity ingress route.
A focused fresh-VM reproduction proved the corrected fixture route returns
HTTP 200 through ordinary control APIs. The consolidated current-source attempt
passed 4,026 shared tests with six skipped, signed publication and indexing,
external S3 workflows, parallel uploads, and a 26-object inventory with no hash
mismatches. It subsequently failed with HTTP 503 because its direct signed
deletion probe omitted the newly required R2 provider upload version. The
failure occurred before the full nonempty SQL and typed projection comparison
completed. Fixture correction and that complete parity remain unqualified.

The earlier failed fleet also missed the RFC's public latency target: baseline p95
was 17.968 ms and concurrent-upload p95 was 169.995 ms, a 9.46-fold increase.
Direct Native p95 was 8.790 ms. Reported Worker handler p95 was 6 ms, but it
excludes TLS and admission. The loaded curl `time_appconnect` p95 of 97.737 ms
is cumulative time from request start through TLS completion, not isolated
handshake time. Emulator and client contention remain hypotheses; independent
percentiles do not establish causality.

The same attempt recorded 2,942,396 bytes of offered Native-to-Worker plans,
5,800,451 bytes of inbound results and 8,425,239,271 bytes processed beside
storage. These are local payload counters, not GCP billing measurements.
The current fleet's cold-request measurement passed its local relative target:
baseline p95 was 16.289 ms and concurrent-upload p95 was 13.747 ms, a ratio of
0.844. It recorded 2,155,361 bytes of offered plans, 4,222,271 bytes of inbound
results and 6,176,579,982 bytes processed beside storage across 4,155 exchanges.
Those counters precede the later failure and do not establish complete parity
or billed provider bandwidth.

The separate current browser run measured the same authenticated page over
reused connections, with browser response caching disabled. All 25 loaded
samples overlapped all eight unthrottled 4 MiB uploads; all 50 measured responses
were HTTP 200, and the uploads produced eight Native completion receipts.
Baseline p95 was 5.278 ms and loaded p95 was 9.082 ms, a 1.721 ratio. Loaded p99
was 17.178 ms. The absolute targets pass, but the 25% relative target fails.
Original stopped-disk log recovery then bound all 55 sequential browser
requests, including warmups, to their Worker request spans. The unique upload
batch admission separates the 30 warmup/baseline requests from the 25 loaded
requests. The 9.082 ms and 17.178 ms samples each record 1 ms of Worker handler
time, including 1 ms of origin wait, with Native time below the integer
millisecond resolution. Their browser transport intervals after request send
remain longer than those spans. The delay lies outside the instrumented
application spans, on the local browser-to-Worker admission/return path.
SOCKS, VM networking, Miniflare ingress/return and shared-host contention are
possible contributors; the exact component is not established. This compares
matched requests, without subtracting independent percentiles. Empirical p99
from 25 samples is the maximum observation.

Current full fleet parity and hosted qualification remain outstanding. These
local measurements do not establish production acceptance.

The current ARM Native artifact
`/nix/store/xmm1sx1l2qj8vsxns5nj1dcp83i9dic4-aos-hub-0.1.0`
passed actual AOS QEMU 11.1.1 execution: SQLite initialization, HTTP health,
login, session issuance and the authenticated instance page. Its captured
source matches all 49 qualified file hashes and all 2,373 filtered workspace
files at `429cae6cf3`. PostgreSQL is compiled into the artifact but was not
exercised on ARM; Hybrid, TLS and hosted behavior are outside this ARM result.
Earlier results below retain their original artifact scope.

The focused GC browser check found candidate digests and action object keys
overflowing their panels. Scoped wrapping and separate metadata lines correct
that layout. Newly built ordinary Native
`/nix/store/wi89vzvf1ppq0vcikw6d9k53v6gjsdhq-aos-hub-0.1.0` and Worker
`/nix/store/zai2xfsv1zr5li0xm4ddhc093pcaabi6-aos-hub-worker-dist-0.1.0`
passed all 11 focused browser checks, with no JavaScript, console or network
errors. Real Worker/R2 upload, sealed inventory and Native reviewed-plan APIs
produce the provider version rendered in both desktop and narrow GC views;
the browser test creates a plan without applying deletion.

At desktop width 1,440 px, document client and scroll widths are both 1,425 px;
at narrow width 390 px, document and body widths are 390 px. Candidate and
action contents remain inside their panels, and settings navigation responds
to each viewport. Both screenshots were inspected. The new Native capture has
the same 2,373 source files as the previous capture, with only console CSS
changed. All 49 qualified incarnation file hashes remain unchanged. This
focused layout result does not replace the retained performance measurements
or qualify full parity or hosted behavior.

## Earlier fleet qualification

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

### Ambiguous R2 deletion recovery fence

The object guard now rejects a second physical delete when its persistent
pending claim has no terminal receipt. It does so before another provider HEAD
or DELETE; visible writes remain blocked. Terminal receipts still replay after
restart or a later mutation, and changed claim identities are rejected.
Two focused Worker state tests passed, including serialized crash recovery,
and the Worker `wasm32-unknown-unknown` check passed. These are state-contract
and compilation checks, not an injected provider failure or hosted R2 test.
Automatic provider settlement and safe receipt retirement remain incomplete.

The guard now persists all visible deployment-R2 mutations: empty PUT,
multipart completion and staging DELETE, alongside the existing claimed DELETE.
Storage-work HEAD enters that same guard, so an unfinished mutation cannot
authorize an absence-based GC decision. Eight focused state tests and Worker
Wasm compilation passed. The actual rebuilt production Worker also passed six
Miniflare scenario groups with persistent Durable Object storage and real R2
emulation: restart fences, lost provider acknowledgements, receipt-before-unlock
faults, exact multipart replay, replacement preservation, legacy records and
signed storage-work HEAD routing. Provider effects were counted only after
checking their durable pending fence. The previous Worker failed the negative
control by reporting absence despite a persisted unfinished mutation.
The qualified artifact is
`/nix/store/8b1sx37sryrsskpwrx2mb8d2lklz95s9-aos-hub-worker-dist-0.1.0`.
These checks cover the object protocol in the runner; they establish no hosted
R2 settlement guarantee. External S3 coordination, identical-recreation
incarnation checks, workflow-wide retained identities and safe retirement remain
pending.

The separate external cleanup wire contract now admits an exact OCI-key HEAD
or conditional DELETE with one retained delete credential. Seven core tests
passed for scope, credential fingerprint, lifetime/lease, replay identity,
signature domain separation, unknown operations and bounded envelopes. Native
claim issuance and Worker execution were initially unwired.

The exact-claim external HEAD path is now implemented. Native revalidates the
applying run, mutation epoch, frozen address, lease, token, retained credential
and hold before issuance and after accepting a bounded correlated reply. Worker
uses only the retained delete credential for one exact-key HEAD, never publishes
it as current binding authority, and disables redirects. Only exact HTTP 404
establishes absence; HTTP 403, redirects and provider errors fail closed.
Eight wire/reply tests, four Native request tests, one real reviewed GC lifecycle
test, six controller regressions and two deployment-R2 compatibility tests pass.
Five Worker authorization/result tests, Native compilation and Worker Wasm
compilation also pass. Tests include credential-head rotation, invalid retained
credentials and response-time claim changes. These focused tests establish no
live provider permission or physical deletion; conditional external GC and
provider qualification remain pending.

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
checks use Worker HEAD requests. Exact-claim external S3 metadata observations
are implemented as described above; external conditional deletion remains pending.

The full four-VM rerun using these corrections is pending. It must compare
nonempty container projections across Hybrid, Native-only and Workers-only;
the earlier empty-container comparison below remains a narrower qualification.

The next completed run passed all 3,976 shared tests (six skipped), but again
failed with HTTP 503 at manifest admission. An additional missing path remains:
the Hybrid frozen OCI staging writer accepts probe objects only, while manifest
admission writes a new staged control document before validating its graph.
That bounded write must be implemented before nonempty parity can pass.

The implementation now stages Hybrid manifests at Worker ingress. Native
reserves quota and the exact frozen cleanup address before the Worker writes
R2; completion sends the original bounded document inbound once, verifies
storage evidence and then uses the existing graph and catalog admission path.
No manifest body is echoed outbound from Native. Twelve focused shared OCI
upload/recovery tests passed, including four new manifest cases for the 4 MiB
boundary, interrupted-write cleanup, exact ownership/body/storage evidence,
quota rejection and private completion identities. All 21 Native storage tests
passed, including rejection of a paired Worker without manifest staging.
The Worker handler passed Wasm compilation. All 13 real-TCP Native OCI tests
also passed. The rebuilt shared application prerequisite passed all 3,980 tests,
with six skipped. The completed four-machine run successfully staged the real
signed AOS container and completed publication. Index freshness then failed:
the fixture attached the `aos` container without including its `aos` package in
the signed package tree. Read-only SQL from an isolated copy of the retained
Native disk confirmed this exact rejection. The fixture is being corrected;
nonempty container parity remains unqualified.

The corrected package-tree run passed all 3,983 shared tests, with six skipped,
and successfully indexed the signed container in Hybrid. Standalone operator
indexing reported two packages, two releases and one stable channel at
`386d6f732d5b9588f2a6191b80688e801590d08e09c8f38e1249da92fa85f959`.
Local authenticated-page p95 was 23.222 ms before parallel uploads and 12.181 ms
during them; direct Native p95 was 9.734 ms during uploads. This capture predates
console reference normalization and its additional startup readiness fence.

That run stopped at the fixture's assertion that the entire inventory used at
most sixteen checkpoints. Sixteen is the collector's per-dispatch budget; it
checkpoints one canonical OCI object per page and resumes across dispatches.
Read-only SQL from an isolated copy of the retained Native disk confirmed a
complete inventory with 26 checkpoints, 26 distinct objects, 26 observed hashes
and zero digest mismatches. The fixture now checks those cardinality and hash
invariants and requires continuation beyond one dispatch. Controller budgets
are unchanged. Full nonempty comparison with Native-only and Workers-only
remains pending in the rerun that also includes the corrected console bundle.

A separate four-VM browser attempt passed the captured transport setup, then
timed out on Chrome's first navigation through a disposable SOCKS bridge. It
completed zero browser assertions and does not qualify the Hybrid UI. The
earlier Native-only Chrome result below remains separate evidence.

The next browser attempt added an independent SOCKS HTTPS probe. That probe
timed out before Chrome started, with no destination reaching the guest proxy.
It completed zero browser checks and isolates a bridge transport problem;
it does not establish a failure in the Hub's browser application.

The fifth browser attempt admitted only QEMU's debug gateway on the disposable
client NIC. Its independent SOCKS HTTPS probe returned HTTP 200. Chrome rendered
the password form and authenticated, but the management UI could not mount:
Native's HTML requested console assets with hash `bd7cd34f`, while the Worker's
bundle used `8775c40f`. Both asset requests returned HTTP 404. Only one browser
assertion completed; this run does not qualify the Hybrid UI.

Both runtimes consumed the same console package. Native's ELF reference cleanup
changed diagnostic store paths inside its embedded browser Wasm; standalone
Worker assets retained the original bytes. Repeating that exact fixed-width
transformation reproduced Native's hash. The console package now normalizes
these references before either runtime hashes or embeds it. A rebuilt runtime
pair and a successful browser rerun are required to qualify the correction.

The normalized console package built successfully as
`/nix/store/45la5qn84262x0k8x8z36gs1s7rg9ks3-aos-hub-console-dist-0.1.0`.
Its JavaScript, Wasm and CSS match the previous package with only diagnostic
store hashes normalized; repeating cleanup leaves every byte unchanged. The
resulting asset hash is `bd7cd34f`, matching the Native page. The rebuilt Native
package `/nix/store/1vzzy2mh76z966q7w7xyn2jgcz86sm5s-aos-hub-0.1.0` and Worker
package `/nix/store/c5yj69yhx5iirhz01piqgny6vqaczcry-aos-hub-worker-dist-0.1.0`
both embed those exact JavaScript, Wasm and CSS bytes after package cleanup.
The Worker's immutable static files match them too. Native's version command
passed. This pair predates the additional readiness fence; successful Chrome
execution remains pending.

Hybrid serving now checks the authenticated Worker capability's console bundle
identity before opening Native's listener. A missing or different identity
fails readiness; storage-only clients retain the independent storage-contract
probe. All 21 Native storage client tests passed, including matching, different
and omitted bundle identities. The Worker passed Wasm compilation. These
focused checks do not qualify a running pair with the new readiness fence.

The sixth and seventh four-VM Chrome attempts loaded all four normalized
console assets successfully from the Worker under `bd7cd34f`, with no JavaScript
or console errors. Login and the browser session-token exchange returned HTTP
200, but the settings workflow never rendered. The seventh report captured
the page's "Permission required" heading. Both Hybrid hops were stripping
`x-aos-console-route`; Native therefore returned an empty route permission set
despite the authenticated root session. These attempts completed one assertion
each and do not qualify the Hybrid settings application.

Both hops now preserve this application input while sharing the reserved
transport-header filter. Three Native ingress tests passed, including actual
middleware preservation of the route/CSRF/Origin inputs and replacement or
removal of spoofed transport evidence. Worker Wasm compilation passed. The
updated production pair built successfully as Native
`/nix/store/v98kdfn549m05f2sfjgzblps2bpbhgv0-aos-hub-0.1.0` and Worker
`/nix/store/jydik3cphgzjv5k98hng2c9sp2f405vk-aos-hub-worker-dist-0.1.0`.
Independent byte checks confirmed the normalized JavaScript, Wasm and CSS in
both binaries and Worker static files, with asset identity `bd7cd34f`.
The browser
helper now records failed-page headings and structural state without form
values, session metadata or response bodies.

The ninth Chrome attempt used that exact runtime pair on four previously built
fleet OS images. It passed 41 assertions, including login, management scope,
appearance, all six branding fields, SPA titles/back navigation and public
branding, with zero skips and no JavaScript, console or recorded network errors.
It stopped after the test navigated to public browse while a settings read was
still outstanding. The public navigation now uses the same request-completion
wait as other ordinary document navigations. A full browser pass remains
pending; the deliberate intercepted-response cancellation test is unchanged.

The tenth attempt passed 77 checks, including branding restoration and the
deliberate response-interruption test. It skipped saved delivery progress because
the fixture had no persisted workflow, then failed to select a delivery endpoint.
Endpoint, gateway and network-policy list requests returned HTTP 500 on Native
PostgreSQL. Their shared SQL predicates treat a bound integer as a boolean;
PostgreSQL rejects this form while SQLite permits it. All three predicates now
compare the integer explicitly with `1`. The extended shared contract passed
on SQLite, actual PostgreSQL 18.6 and actual MariaDB 12.3.3 in the hermetic
Firecracker gate, including nonempty owned/granted selectors, grant opt-in,
deduplication, cursor continuation and revoked grants. Its output is
`/nix/store/hk80syc6fh6l5xpglq4zaavg15h42y1f-aos-vm-test-aos-hub-live-sql-dialects-0`.
The first attempt failed because the new fixture created a second instance
default binding; the corrected test reuses the existing binding. The production
correction is unchanged. A rebuilt runtime pair passes independent console-byte
checks, and the remaining browser checks are being rerun. Neither focused
database execution nor the earlier 77-check attempt establishes a full UI pass.

The eleventh Hybrid Chrome run passed all 123 executed checks, with no
JavaScript, console or recorded network errors. One check was skipped because
the disposable fixture had no persisted delivery workflow. It covered login,
management scopes, appearance, fonts, branding review/apply/restore, SPA/back
navigation, interrupted asynchronous work, organization and registry settings,
guided delivery planning, cache integrations, retention and GC policy planning.
Native PostgreSQL, Worker/Miniflare, S3 and client ran on separate VMs. The
fixture used a narrowly pinned TLS certificate and an independent successful
SOCKS HTTPS probe before Chrome.

This operator qualification mounted the exact rebuilt Native package
`/nix/store/zy178y20zs9pamglvjq7kvmwp5d0lrv3-aos-hub-0.1.0` and Worker package
`/nix/store/3f56014z8g08942563mndgzkqlc62sr5-aos-hub-worker-dist-0.1.0` onto
previously captured fleet OS images while preserving the service policy. Native's
version command and independent console-byte checks passed for both runtimes
and edge assets under `bd7cd34f`. This qualifies the exercised browser paths;
it is distinct from the pending current-source hermetic full nonempty fleet,
saved-workflow resume coverage and hosted provider qualification.

The next full nonempty fleet capture passed the 26-object inventory continuation
check and again indexed two packages, two releases and one signed channel.
Authenticated-page p95 was 15.486 ms at baseline and 12.524 ms during eight
parallel uploads. Across 3,361 completed storage calls, Native received
2,201,629 bytes of results while the Worker processed 5,183,383,183 source bytes.
These are local application payload measurements, not hosted provider billing.
The run stopped at its warm-refresh fixture before the three-runtime comparison:
container catalogs deliberately disable release reuse to revalidate placement
evidence. The fixture now exercises cold and unchanged warm indexing on a
separate signed metadata-only registry and also requires repeated container
revalidation. Its Nix evaluation, rendered Python and formatting checks passed;
the corrected full fleet remains pending.

The subsequent full fleet attempt passed all 4,004 shared application tests
(six skipped), the signed Hybrid container publication and indexing, the
26-object inventory and physical cache GC, external S3 operations and
outage/recovery checks. Its separate metadata-only registry passed cold and
unchanged warm indexing. Authenticated-page p95 was 20.8 ms before eight parallel
uploads and 13.483 ms during them; direct Native p95 was 11.837 ms. Across 5,932
completed storage calls, offered outbound plans totaled 3,000,304 bytes,
validated inbound results totaled 5,804,773 bytes, and the Worker processed
8,432,475,320 source bytes. These remain local application payload measurements.

That attempt stopped before the three-runtime comparison: the Native-only
fixture passed signing seeds directly from the world-readable Nix store, and
Native correctly rejected their permissions before opening its listener.
The fixture now installs owner-private copies. Reproducing both launches with
the exact failed-fleet Native binary confirmed the original rejection and
successful TLS-verified health after the repair. This startup reproduction
does not establish full nonempty parity; the corrected full rerun is pending.

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
records that evidence. At that checkpoint, root creation awaited approval; its
subsequent approved initialization is recorded below. This database migration
does not qualify Cloud Run mounts or a hosted paired API.

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
`/tmp/hub-native-empty-registry-browser-qualified`. Hybrid browser results are
recorded above.

### ARM Native artifact qualification

The PostgreSQL-enabled Native package cross-build passed for `aarch64-linux`.
The result is
`/nix/store/xa8fdjn5xpa23m6h2067j0kkgy0k1bdx-aos-hub-0.1.0`.
Executing its binary through the AOS-built `qemu-aarch64` returned
`aos-hub 0.1.0` successfully. This capture predates the private receipt-file
reader and console reference normalization. It qualifies compilation and
startup of that artifact.

The current Native source at `9f633298b4` subsequently cross-built as
`/nix/store/kpvy8whncbmqmc4yfyp67cim5clhwxhy-aos-hub-0.1.0`. Its captured
workspace matches all 2,292 non-Worker source files at that commit. AOS-built
QEMU 11.1.1 executed the actual aarch64 ELF, version command, SQLite migration
and root initialization, then served health and login pages. Password login
returned HTTP 303 with a session cookie and the authenticated instance page
returned HTTP 200; the server remained running. Generated credentials were
removed and the test process stopped. This qualifies standalone Native with
SQLite under ARM emulation. ARM PostgreSQL, Hybrid and browser workflows remain
unqualified.

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
After explicit operator approval, the staging root account for
`dylan@andyl.com` was initialized against the actual Cloud SQL database using
the qualified Native binary from the strict credential image. Its generated
password is retained only in encrypted Secret Manager as numeric version `1`
of `aos-hub-bootstrap-root-password`. A loopback-only Native process verified
the instance-owner membership, password login, authenticated console shell,
CSRF token and logout; the diagnostic session was revoked and both the Native
process and SQL connector were stopped. No credential values were logged.

The route-reservation key ring and independent release and channel receipt
signing seeds were subsequently provisioned as enabled numeric version `1` of
their existing encrypted aliases. Preflight verified the single regional CMEK
replica, exact Native accessor grant and absence of prior versions. Each key
has 256 bits of entropy; exact stored-byte and CRC32C readback passed in memory.
No secret values entered source, state, command arguments or logs. These
credentials have not yet been mounted in a serving revision.

The remaining serving configurations are now enabled numeric version `1`, with
exact stored-byte readback: `domain-probe-signers`, `release-publication-keys`
and `qualification-keys`. The initial domain manifest has no entries because
the new Hub has no custom-domain terminators; it cannot sign a domain proof.
Publication trust names the actual Native receipt public key as
`aos-hub-hybrid-staging-release-receipt-v1`. The separate qualification verifier
is `aos-hub-hybrid-staging-qualification-v1`; its generated private seed is
retained encrypted under the staging CMEK. No qualification receipt was issued.
These versions configure verification authority and do not establish that a
release passed qualification.

A dedicated archive identity was also generated, with only its public recipient
available to registration source. Its private identity was encrypted under the
same staging CMEK and the plaintext file removed. Publishing that encrypted
identity to its dedicated Secret Manager resource remains pending the reviewed
delivery authority registration. Neither private identity is a Native serving
credential.

Native receipt signing seeds now use the same private credential reader as the
database and other signing keys. Temporary encoded buffers are zeroized after
initialization. Three focused tests passed for private seed reads, insecure
permissions, symbolic and hard links, invalid UTF-8 and empty material without
disclosing contents. This does not qualify a hosted receipt-key mount.

This qualifies the database account, not a Cloud Run bootstrap execution or
public Hybrid deployment. Signed serving delivery, credential mounts, origin
shielding and real cross-cloud latency/byte measurements remain pending.

## External storage authority foundation

Migration 003 adds eight tables for permanent physical storage authorities,
globally reserved endpoint aliases, exact binding revisions, credential
attestations, monotonic admission and control delivery records. The production
baseline and migration 002 remain byte for byte unchanged. No existing binding
is automatically adopted, and this migration enables no destructive capability.

The reviewed database primitives passed ten focused SQLite tests, including
atomic binding-coordinate validation and an exact concurrent decision replay.
The broader dialect contract passed all three live PostgreSQL, MariaDB and
SQLite cases in the hermetic VM gate. Those cases exercise all eight new tables,
alias reservation rollback, reviewed decisions, admission, retirement and
rejection of stale remote watermarks. Worker migration translation passed, and
the ordinary Worker Wasm library compiled with the additive schema and types.

The VM output is
`/nix/store/cgvrj3d4skrnx93dvxgjvnfjqk0zyshh-aos-vm-test-aos-hub-live-sql-dialects-0`.
Its captured source includes the reviewed authority implementation and portable
contract. This qualifies the SQL foundation; it does not qualify an authenticated
remote adapter, operator RPC, provider execution, or external DELETE. A stored
SQL acknowledgment does not replace a fresh authenticated executor watermark.
The full fleet run captured before this migration retains its original scope.

### Reviewed authority API and immutable prefix ceiling

The first typed root operator API provided `PlanDecision`, `ApplyDecision` and
`GetAuthority`. Eight focused Native tests passed for current root authorization,
revocation, exact actor/request replay, concurrent decisions, expiration and all
five decision families. Shared routing and generated protobuf descriptor tests
each pass, and the ordinary Worker Wasm library compiles.

Creation requires an explicit immutable `qualified_managed_prefix`; an empty
string deliberately permits the whole bucket, while an absent value rejects.
Thirteen focused database tests pass. Attestations can narrow that ceiling or
reopen within it, but cannot expand it or settle existing mutation fences.
Legacy creation records without the field fail closed; migration bytes remain
unchanged.

The integrated source passed all three live PostgreSQL, MariaDB and SQLite
contracts in
`/nix/store/ni4pbgxsm621bxjwv6br9kp8gr9rqrwa-aos-vm-test-aos-hub-live-sql-dialects-0`.
The captured source is
`/nix/store/byqzw7awkfgx6ir3n10w19xk991xr6h6-aos-hub-dialect-test-src`.
These results qualify desired SQL state and operator authorization. Responses
remain pending reconciliation; no provider access or external DELETE is admitted
by this API or by a stored SQL acknowledgment.

The subsequent full CLI test gate rejected that API's retained-method contract
before the Native operations VM booted. A focused reproduction found four
violations: the paired method names were not canonical, the plan response was
not `TopologyPlanResponse`, the plan request lacked canonical idempotency and
resource-version fields, and apply accepted mutable decision input. The
validator remains unchanged. The earlier focused tests do not establish full
API conformance.

The integrated correction exposes `PlanStorageAuthorityDecision` and
`StorageAuthorityDecision` with the canonical plan/apply contract. Plans return
`TopologyPlanResponse` and persist a closed version-one envelope binding the
typed decision and expected resource version. Apply accepts only the plan ID,
confirmation and idempotency key. Its immutable creation-fact fence and decision
result commit atomically; exact completed replay still requires current root
permission.

The independently reviewed correction passed 29 focused cases: ten operator
tests, the actual retained-method classifier integration test, two snapshot
envelope tests and sixteen database authority tests. All fifteen integrated
file hashes match the qualified source. The combined source passed the ordinary
Worker build, 38 signed HTTP cases and inspection of 2,109 SQLite journal values.
The full packaged CLI gate passed all 4,195 tests, with six skipped, in 51.241
seconds, and the Native operations VM completed its operator lifecycle.

A fresh portable fixture uses the canonical review envelope for all five
decision families and asserts exact completed result replay. All three live
SQLite, PostgreSQL and MariaDB contracts passed in 4.76 seconds, including the
alias/attestation checked creation-fact fence. Its VM output is
`/nix/store/r91jy7v0y5ybymx8qk76lkqy89cxschz-aos-vm-test-aos-hub-live-sql-dialects-0`.
The complete captured source differs from the earlier combined SQL source only
in this test fixture.

Frozen external S3 physical GC, safe retirement of obsolete object coordination
state, and whole-Hub snapshot/restore also remain to be implemented. These SQL
and focused API results are acceptance checkpoints; they do not complete
RFC-0023.

### Worker authority journal and SQL publication

The combined working source passed 38 signed HTTP cases against actual
`workerd`, plus direct inspection of the retained SQLite journal. All 2,109
stored values use the closed version-one JSON string format. Tests cover exact
signed 64-bit integers, restart and replay, bounded request/publication sizes,
denial across skipped generations, conflicting predecessor digests and terminal
retirement. The Worker Wasm digest is
`9ee9e07fe2fb97c8e0d1321c4b1d5c0698000dae28951725765a370ceb72d623`.

The same captured SQL source passed three live SQLite, PostgreSQL and MariaDB
contracts, including full publication, conflicting acknowledgment and refusal
of superseded publication after retirement. The VM output is
`/nix/store/398kywgwpf1idrmqaw27ncdzqm4kb4wa-aos-vm-test-aos-hub-live-sql-dialects-0`.
These results precede the canonical operator API correction. They establish
metadata protocol and journal behavior; no provider I/O, hosted ownership,
object HTTP capability or external DELETE was exercised by these cases.

Repeating the same 38 HTTP cases and SQLite gate against the corrected combined
source passed. All 44 captured source hashes, the ordinary Worker artifact and
45 evidence-file hashes were verified. Its Worker Wasm digest is
`8a4ba62cb5a3b5c46405d90ee6f7a22af08852d3e25b4abb8f5835f678b8a823`.

### Latest fleet failure

The corrected Worker ingress fleet run reached Hybrid and Native publication
and indexing, but Workers-only staging failed with a connection reset on an OCI
blob request. A fresh request check against the exact Worker artifact passed
anonymous and scoped missing-blob HEAD requests and subsequent `/v2/` readiness.
It did not reproduce or explain the reset. Retained VM diagnostics are ongoing.
The complete 25-table and five-projection parity gate was not reached, and the
three corresponding fleet fixture changes remain uncommitted.

Retained-state replay localized the reset to the server-side TLS connection:
it reset 13.36 ms after returning upload completion, before the next HEAD
entered Worker code. One fresh authenticated HEAD returned 404 and `/v2/`
returned 200 on the same live runtimes. Exact runtime source does not establish
a 60-second connection limit; the response/connection-close cause remains
unresolved. These diagnostic runs do not qualify a runtime fix or full parity.

## Native SQLite snapshot input

The read-only input reader passed sixteen focused tests against the integrated
source. It validates the complete current catalogue without initializing or
migrating the source and pins one transaction across all bounded pages. Actual
SQLite tests cover concurrent WAL changes, unchanged database/WAL bytes, exact
value classes, oversized lineage markers, schema drift, page/cell bounds and
lock release on drop or task cancellation. The integrated test run took 9.71
seconds, with no failed or skipped reader tests.

This qualifies only Native SQLite database input. Authenticated export, import,
provider object closure, restored activation,
Worker and PostgreSQL snapshot readers remain pending. Normal SQLite WAL lock
and shared-memory coordination is allowed; no zero-filesystem-write claim is
made.

## Snapshot row classification

The independently reviewed classifier covers all 267 current production tables
and 2,586 columns. Its explicit contract rejects unknown schema, configuration
keys and registered document formats. Credential material, unrestricted
context, configured credential-bearing URLs, upload tail bytes and persisted
error bodies become exact private-cell restoration dependencies. Durable
leases, mutation fences, terminal receipts and authority history remain retained.

The integrated source passed 42 focused tests: 26 classifier tests and the
sixteen reader tests above, with no failures or skips, in 11.93 seconds. Coverage
includes the actual production initializer, declared foreign-key closure for
excluded tables, lossless values, private payload omission and real bounded
reader pages. Complete application and object closure remains unqualified.

This is a row classification seam. Private dependencies require a separate
restoration mechanism; export archives, signing, import, topology conversion
and activation remain pending. Historical watermarks are evidence and do not
grant fresh provider admission. See the
[classification contract](../plans/hub-snapshot-classification-foundation.md).

### Bounded private-cell capture

The independently reviewed capture seam pairs classified metadata with exact
private originals and reconstructs one row only after matching every declared
table, primary key, column, type, digest, reason and payload length. Full
reclassification rejects modified public metadata. Private wrappers have
redacted debug output and no automatic serialization; raw callbacks and writers
are explicit private boundaries.

The frozen source passed 63 snapshot tests in 10.16 seconds: nineteen new
capture tests, 26 classifier tests, sixteen reader tests and two canonical
authority-envelope tests. Closed scalar decoding rejects arbitrary JSON trees,
and reconstruction checks the cumulative row budget before cloning public
payloads. The four capture files and all fifteen canonical prerequisite hashes
were verified during integration. All 63 snapshot cases also passed inside the
full packaged CLI gate above; the Native operations VM passed on that combined
source.

This establishes exact reconstruction and checksum consistency, not source
authenticity, archive encryption, SQL import or activation. See the
[capture contract](../plans/hub-snapshot-private-capture-foundation.md).

See the [deployment procedure](aos-hub-hybrid-deployment.md) and
[RFC acceptance gates](../rfcs/0023-hub-hybrid-topology/06-implementation-and-validation.md).

## Bounded OCI HEAD transport recovery

The current client adds one application-level transport retry for a bodyless
Distribution HEAD that fails before any response with a typed closed-connection
cause. It excludes connection establishment, timeouts, redirects and body
failures, status responses and provider-effect methods. The logical request
retains its original URL, normalized scopes, caller headers and authorization
across transport replay. An explicit authentication challenge can replace its
token through the existing authentication flow. Cancellation is checked before
dispatch and takes priority while awaiting each attempt.

The frozen two-file patch is
`daa49725c5a41946d7ccfac945525fb27c1d51ed9bf01b32cd6b1b7ae0df7bb6`.
Its author receipt is `/tmp/hub-oci-head-recovery/qualification-receipt.json`
(`2710ffb40d73356644e6a197d8d2f2f69c90b81e07eb80e94039c401359c3e88`);
the independent review is `/tmp/hub-oci-head-recovery-independent-review.json`
(`f4fb4f2f0b83d0d3f8d41b6ca33c14188b90ea006a29929feaf01119f3a23946`).
Root verified the patch, five unchanged base inputs, exact final source hashes,
actual log hashes and successful exit files before integration.

Eleven focused local socket/framing tests and 29 existing registry tests pass.
Actual TCP faults consume the complete request before reset. They qualify
successful recovery, repeated-reset refusal, exact token replay despite a
concurrent token-cache refresh, cancellation, independent authentication budgets,
nonretrying status responses, and one consumed provider-effect POST without an
added retry. The tests retain production reqwest retry settings. Its existing
safe HTTP/2 protocol-NACK retries remain: the new limit is one added application
retry, not an absolute two-physical-attempt bound for every HTTP/2 request.

The current frozen production CLI source is
`/nix/store/rd9vxbqzpnlbb8fbdxmhcm2zsms956a1-aos-workspace-src`.
All 46 captured authority, snapshot and OCI source hashes match the integrated
source; the structured-attribute derivation source was checked explicitly.
The full packaged CLI gate passes **4,204 tests, six skipped, 49.945 seconds**.
Capture and logs are `/tmp/hub-head-recovery-current-source-capture.json` and
`/tmp/hub-head-recovery-current-fleet.log`.

The full four-VM fleet remains in progress at this checkpoint. This client
recovery does not establish the original server-close cause, full runtime parity,
hosted provider behavior or performance acceptance. The retained pre-003 reset
and upload-isolation misses remain historical evidence.


## Encrypted snapshot byte framing

The independently reviewed framing foundation passes 21 focused tests on its
frozen source. Integration verified all four file hashes, the prerequisite
manifest, the patch and the actual passing log. The qualification receipt is
`/tmp/hub-snapshot-frames-qualified.json`
(`e16cd9953c067504a4fc71368ab267e1738b1f2f997998c15ef0273f1a6191f6`).

The fixed versioned format binds archive identity and stream role, encrypts
bounded DATA frames, and authenticates a terminal commitment covering frame
count, byte count and preceding ciphertext. Complete-stream acceptance requires
that END commitment and clean EOF. Tampering, truncation, reordering, excess
limits and failed I/O poison the stream. Writer keys are one-use values generated
through an explicitly trusted cryptographic random source; decryption-key import
cannot create a writer key. Owned private buffers zeroize and debug output is
redacted, without a perfect library/caller-copy erasure claim.

This qualifies arbitrary-byte framing only. Typed records, logical end markers,
signed archive roots, whole-Hub closure, filesystem custody, export/import and
activation remain pending. The current full fleet capture predates these framing
files and is not their qualification evidence.

## Current upload-batch measurement

The current four-VM run records public authenticated page p95 of **15.656 ms**
before the batch and **101.280 ms** during the eight-upload batch, ratio
**6.469**, missing the relative target. Direct Native p95 is **7.367 ms**;
the measured Worker handler interval p95 is **3 ms**. Curl cumulative TLS
completion p95 is **97.871 ms**, including earlier connection setup; it is not
an isolated handshake duration. Independently computed percentiles cannot be
subtracted to attribute delay. The application is warmed before baseline and
each curl sample opens a fresh connection. The fixture starts uploads alongside
page samples but does not establish that every sample overlaps an active PUT.

Exact pinned runner inspection confirms public HTTPS already belongs to
workerd's C++ TLS listener. Its Node loopback service is not a public TLS proxy.
Local R2 emulation shares the runtime; contention is a hypothesis requiring
resource evidence. This result does not establish hosted behavior, upload
isolation acceptance or a production cause. Historical misses remain retained.


## Signed storage epoch-lease foundation

The independently reviewed pure lease protocol passes 25 focused tests and a
core wasm32 compilation. Integration verified five exact source hashes, current
base inputs, the patch and terminal logs. Author receipt
`/tmp/hub-authority-epoch-lease/qualification-receipt.json`
(`c65654cb2103686bebe9988ad203dc5a6c838022a929a35b58d869a7c9a438eb`)
and independent receipt
`/tmp/hub-authority-epoch-lease-independent-final-review.json`
(`f4f1a9a50908996978bd8f0442e77f7483c139f500dbe194bcf72db868bb6257`)
bind this scope.

Closed Ed25519 leases bind exact admitted cohort projections and qualified time
policy. Async journal compare-and-swap acknowledgments precede signing and
return; a final clock check follows the last await. Cancellation or a lost reply
can retain issuance sequence and maximum expiry conservatively without returning
a token. Permanent physical-key floors refuse stale epochs, payload forks and
post-retirement admission. Bounded cutoff stops lease admission only: it never
settles provider effects or retires object receipts.

This enables no live issuer or provider dispatch. Real durable serialization,
publication provenance, issuer-only key custody, Worker/Native adapter wiring and
clock-policy qualification remain pending. The conservative authority-wide
sequence floor can cause one cohort to force another's early renewal at a touched
key; scalable cache amortization is unqualified. The current full fleet capture
predates these files and is not their qualification evidence.


## Read-only snapshot source audit

The source audit passes **33 tests, zero failures, 18.10 seconds**: sixteen
existing reader cases, nine audit cases and eight compiled-CHECK cases. It keeps
the original read transaction pinned through integrity checks, all **634**
production CHECK expressions, declared foreign keys and exact table counts.
Cancellation consumes the reader and signals actual SQLite VM interruption;
a regression test aborts the public future during a real progress callback and
then reacquires an exclusive source lock. Success removes that callback before
returning the same usable reader. Database/WAL bytes remain unchanged in the
source tests. Errors reduce diagnostics to booleans and omit private row values.

SQLite intentionally discards CHECK expression trees when it parses a read-only
schema. Integrity PRAGMA alone accepted a deliberately invalid production row.
The audit therefore evaluates exact expressions from the independently compiled
production catalogue after full source-schema equality validation. Newline-wrapped
NOT predicates preserve CHECK's NULL-pass behavior and collation. The corpus
includes whitespace-separated CHECK declarations and rejects malformed envelopes
and excessive expression/catalogue bounds before copying.

Frozen qualification is `/tmp/hub-snapshot-source-audit-qualification.json`
(`4e2dcdbc192a6967374efb8906a711dd6451117e1be8c2f21cba191f2b8e563f`);
independent acceptance is `/tmp/hub-snapshot-source-audit-independent-final.json`
(`cc20f715b3400f7c320fb23e51208127f92c4ae2940efcecf608a6d1faddee0b`).
Integration verified all five files, nine prerequisites, source bases, actual
terminal logs and the exact patch. Historical failed probes remain retained.

The progress budget bounds approximate SQLite VM work and elapsed observations,
not physical I/O or a hard wall-clock deadline. Source integrity and declared
constraints do not establish artifact authenticity, independent archive FK proof,
application/object closure or activation. The current full fleet predates this
source-audit increment and is not its qualification evidence.


## Signed snapshot declarations and separate key custody

The signed declaration layer passes **21 focused tests** with independent review.
Its closed canonical root binds fixed metadata/private stream roles, archive ID,
framing summaries and wrapped keys. Verification requires externally pinned
Ed25519 keys and the exact signer ID before key unwrapping. Encrypted inner key
records bind archive, role, wrapping ID and suite. Metadata-only verification
requires only its selected wrapping key; pair recovery additionally checks both
roles' key separation. Reader-only recovered keys cannot create stream writers.

Qualification is `/tmp/hub-snapshot-root-qualified.json`
(`485215c29a17cc8c785aa576d4bb1db0fa4a6045f2f700089f98bae5e8b876f6`);
independent review is `/tmp/hub-snapshot-root-independent-review.json`
(`9ba112bbeb2fab04d7a0d882914c035e3630cfb8df73ebd0c63952a971048812`).
Integration verified four exact files, eight prerequisites, the patch and the
actual passing log. Known key exclusions are explicit and bounded; absent source
or other-role material cannot establish global key separation. Owned private
buffers and errors are redacted, without perfect erasure or entropy guarantees.

The only profile is `framing_only`. The signature authenticates declared
summaries; it does not inspect files or establish their decoder provenance.
Actual stream reconciliation, typed logical records, source authenticity,
whole-Hub closure, filesystem orchestration, export/import and activation remain
pending. The current full fleet predates this increment.


## Completed four-VM runtime parity

The ordinary four-VM fleet captured after OCI HEAD recovery completed with
**exit 0 and result PASS**. It uses separate client, Worker, Native/PostgreSQL and
S3 machines, production artifacts and real signed publication APIs. Hybrid,
Native-only and Workers-only publish the same externally signed base-image
corpus; all **25 compared tables** match exactly. The five required container
projections are nonempty: one root, 96 closure members, six evidence rows, one
provenance row and twelve layer rows. Both releases and the stable channel match,
including 256 channel partitions. The canonical compared-row digest is
`2e0e978994372c1dc9baae41691b352124cba57a399a953bbd4eb67c26fefbd8`.

This run also passes Hybrid external S3 multipart/read/write/range/outage and
recovery workflows, signed indexing, metadata-only refresh, 26-object sealed
inventory, eight parallel uploads and physical R2 cleanup. Native-to-Worker
payload counters record 2,608,047 offered plan bytes and 5,702,662 inbound result
bytes over 4,890 completed calls, versus 8,759,808,096 object bytes processed at
Worker. These local payload counters do not establish provider billing.

The exact fleet derivation is
`/nix/store/61wgvyzrlvajr3zb39i9j58lm3nqnfp4-aos-fleet-test-hub-hybrid-0.drv`;
its passing output is
`/nix/store/wx36rcq4iny4asb7m0x0k5cjlldphy9f-aos-fleet-test-hub-hybrid-0`.
The final receipt is `/tmp/hub-head-recovery-current-fleet-qualification.json`
(`79ed3aed211efa10546b2b5d41a48fd5be8220b8b8f8041c703c4421e0e5cafd`).
The three fixture hashes remain byte-identical to their prebuild capture and are
now eligible to commit. The source and actual logs qualify the pre-framing,
pre-lease and pre-audit runtime capture, including the 4,204-test CLI gate.

Workflow correctness passes; the relative upload-batch latency target still
misses by 6.469 times baseline. The synthetic performance and earlier server-reset
cause remain unresolved, and hosted behavior remains unqualified. A separate
ordinary CLI/Native/Worker build is checking the newly integrated snapshot and
lease source: all 60 captured source hashes match, but its terminal result is
pending at this checkpoint.

## Completed integrated runtime build

The subsequent ordinary production build completed with exit 0: **4,288 CLI
tests passed, six skipped**, followed by successful Native PostgreSQL and Worker
artifact builds. All 60 captured source files match in each of the three actual
production source inputs. This includes the committed source-audit, encrypted
framing, signed-root and disabled epoch-lease foundations.

The source-bound receipt is
`/tmp/hub-snapshot-lease-integrated-runtime-qualification.json`
(`2313d2f5ac44455b6899f849cc6d9e9c1b98e61f0bbf4b46cadc5578e7e2d0f9`).
The resulting CLI, Native and Worker outputs are respectively
`/nix/store/0xh6crxghaqjfdqfjp8f0iihxfcwr3jd-aos-0.1.0`,
`/nix/store/460kzmps304zi0rfx6lasblrndk18hjc-aos-hub-0.1.0` and
`/nix/store/lpmqbp648rrnq08pjcrh4x698wdnfznm-aos-hub-worker-dist-0.1.0`.
This establishes the full CLI test gate and ordinary artifact compilation;
updated fleet, ARM and hosted qualification remain pending. The recorded
upload-batch performance miss remains unresolved.

## Overlapping lease cache correction

The pure per-object admission floor now permits older, still-valid tokens in
the exact already observed admitted epoch. It retains the maximum sequence and
its exact payload digest without regressing either. Advancing to a new epoch
requires a sequence above that maximum; equal-maximum forks, epoch/publication
forks, denial, retirement, expiry and clock rollback still fail closed. Cohort,
full object key and permitted effect checks remain required.

All **29 focused tests pass**, including overlapping read/write scopes,
out-of-order renewals, restart, epoch advancement, cancellation and lost
acknowledgements. Exact qualification is
`/tmp/hub-lease-cache-floor-qualified.json`
(`8e31b0a92c26aa978d618ee32a947c6bd693faf4f1ffe5650362d2c08f229378`);
independent review is
`/tmp/hub-lease-cache-floor-independent-review/receipt.json`
(`7aa8f7c3ff969786c84644c6ed1a4ea869d2d5ddb2bc3184842ce258b1264991`).
Integration verifies both exact files, seven prerequisite hashes and the actual
test log. Bounded state cannot detect forks at forgotten lower sequences:
irreversible live issuer CAS and exclusive signing custody remain prerequisites.
This qualifies the cache model correction, without provider enablement or
measured renewal amortization. The in-flight fleet predates this correction.

## Connected encrypted database records

The actual read-only SQLite reader now feeds source audit, classification,
private-cell capture, paired encrypted records and a signed root in one pinned
transaction. The `database_capture/v1` grammar accounts for all 267 tables,
including empty tables and explicit transient/lineage omissions. Verification
reconstructs and reclassifies exact private rows with bounded ordered cells;
completion requires logical ends, both authenticated frame ENDs, clean EOF and
both actual summaries matching the trusted signed root.

All **146 focused snapshot tests pass**: 24 new record cases and 122 prerequisite
regressions. Cases include actual source immutability and concurrent source
changes, worst-case escaping of a one-MiB cell, extreme signed integers,
distinct-archive splice rejection, invalid signed grammar and capture limits.
The source-bound producer receipt is `/tmp/hub-snapshot-records-qualified.json`
(`b47de1decf1f4373d4280ffcfb6a3e202eb2d8448363683c50f2647ed69a1328`);
independent acceptance is `/tmp/hub-snapshot-records-independent-final.json`
(`c58e36788bb8341131aa9e6877aeedb5042b152ec00ac66dbf592d7210446f0f`).
Integration verifies ten exact files and all 261 frozen prerequisites: 259 still
match shared source, while the two lease files have the separately reviewed
29-test correction above. This does not create a combined-source test result.
The minimal Native wrapper is source-reviewed, pending a current Hub build.

The signed root retains `framing_only`. Callbacks expose provisional private
rows before completion and cannot authorize restore. Source audit facts are
authenticated exporter declarations. A deliberate duplicate-primary-key test
demonstrates that grammar and count consistency do not establish uniqueness or
global SQL constraints. Scratch-database replay, filesystem/CLI orchestration,
PostgreSQL/Worker readers, source-key custody, application/object closure,
whole-Hub import and activation remain pending. The in-flight fleet predates
this increment.

## Private SQLite snapshot constraint verification

The Native verifier now reconstructs authenticated records in private in-memory
SQLite using only an opaque catalogue compiled from the current production
schema. It inserts exact typed cells, checks readback, and waits for both paired
streams' authenticated END and clean EOF before full integrity, foreign-key,
omission and lineage checks. No archive SQL or source database seeds are run.
Cancellation closes the connection before a report can escape.

All **19 focused tests pass** against AOS SQLite 3.53.4. They include correctly
signed duplicate primary keys, UNIQUE and CHECK violations, missing foreign
keys, valid child-before-parent insertion, extreme scalar values, truncated or
trailing streams, cancellation and selected resource limits. Producer receipt
`/tmp/hub-snapshot-scratch-qualified.json`
(`df2d50d331593d814d2c87ed8de89a84c423f6276e6fabd0f5bfa5b70f0828e8`)
and independent review `/tmp/hub-snapshot-scratch-independent-review.json`
(`310b9f2f35033f8b9f69f9f9ea118c2ebb9f27dda584da532ca733a001b33abb`)
bind the exact ten integrated files. All 26 prerequisites match, with the
disclosed additive Native journal module declaration retained during integration.
That declaration was not in the focused candidate; combined qualification is
still required.

This proves retained SQL constraints for the admitted snapshot format. It does
not prove application or storage-object completeness, source-key custody,
external authority restoration, import or activation. Limits bound selected
pages, payloads and SQLite work, not total heap or blocked I/O duration.

## Shared issuer control and retained Native journal

The shared issuer control protocol adds bounded authenticated requests, compact
signed replies, exact installation and applied-receipt checks, and denied-gap
transitions that preserve sequence, committed expiry and terminal retirement.
Its final six source files pass all **38 focused tests**, including the earlier
same-epoch lease overlap regressions. Independent pure-only acceptance is
`/tmp/hub-live-authority-issuer-pure-independent-review/receipt.json`
(`e101cfdf99b929d9bff23544e91b3c264ac31896276cfeb1f4d214c2400e9355`),
bound to the final protocol manifest
`9c7a0faae6c0bfd3c1d5643ec32e7ebbd2651d0e77fa40b222e407c8276ad4ed`.

The separate Native adapter stores one authority's real journal, publication
and receipts in an explicitly initialized private SQLite file outside Hub SQL
and `HUB_ROOT`. Serving opens only an existing exact installation. Actual
transactions compare the full expected state and commit with EXTRA synchronous
durability before acknowledgment; cancellation and lost replies never undo a
possibly committed sequence. File, parent, ancestor, schema and immutable
installation checks reject replacement or missing history rather than creating
fresh authority.

All **19 Native adapter tests pass** against those exact final protocol bytes:
restart, concurrent CAS, denial, lost acknowledgment, cancellation, lossless
integers, corrupt/missing state and file/ancestor replacement. The actual test
ELF links AOS SQLite 3.53.4 and OpenSSL 4.0.2 through its baked store RPATH.
Producer receipt is
`/tmp/aos-authority-sqlite-journal/qualification-receipt-v3.json`
(`5027a6fcd6c8359a21d78b1d3f339391184aad15d96408a33da4c3e8d7e2f546`);
corrected independent binding is
`/tmp/aos-authority-sqlite-journal-independent-v3-revision2.json`
(`1f5e948c751a18b3ad75ba6f7a5066b0f22c6bd86915554075d893efc62e0b47`).
The correction updates a documentation pointer; qualified source, test log,
patch and linkage bytes are unchanged.

Integration checks twelve source hashes and preserves the existing snapshot
module while adding the Native journal declaration. That contextual library
edit is not an exact combined-library nineteen-test claim; ordinary integrated
artifact qualification remains required. No HTTP original-operation replay,
provider dispatch, hosted disk/clock, power-loss or rollback recovery is proved.
The dedicated Native issuer process may eventually hold the issuer seed;
ordinary Hub/SQL publisher and executor roles must not hold it. Its separate
HTTP/schema/clock increment and the live Worker adapter remain pending.

## Paired performance diagnostic fleet failure

The frozen diagnostic fleet's packaged CLI prerequisite passes **4,288 tests**
with six skipped. The four actual VMs boot and pass the external S3 metadata,
multipart, outage/recovery, range and binding-replay prelude. The run then stops
before the baseline at `worker_process_counters`: the new bounded sampler
returns `fleet process counter snapshot failed`. No baseline, loaded latency,
final parity or new performance result is produced.

The failed derivation is
`/nix/store/3zh4krc785l0dn8ip0gzgkb9fviki8bk-aos-fleet-test-hub-hybrid-0.drv`;
root session 20159 returns exit 1. Full driver evidence is retained in
`/tmp/hub-paired-perf-live-driver.log` and the build directory
`/nix/var/nix/builds/nix-435670-3462360238/build`. The actual guest sampler
failure is reproduced in a bounded real Worker guest probe: the kernel omits
`/proc/PID/task/PID/children` while executable identity, process stat, scheduler
and I/O counters are present. The correction discovers children through a
bounded parent-stat scan when that interface is absent, preserving exact
executable, parent and lifetime checks. Optional unavailable counters are null
with an explicit reason, never fabricated zeros. All **15 focused tests**, the
actual Worker VM probe and evaluated Nix driver syntax pass. Producer receipt
`/tmp/hub-perf-sampler-fix/receipt.json`
(`053880aa979866bf3b0fa68f6f06f8b8593c5959294e3f565c05549ef4b09d62`)
and root independent source/evidence review bind the three corrected helper
files. The fresh-connection counts, concurrent upload size/count and numerical
latency gates remain unchanged. No new full fleet latency result is available.
The earlier 6.469 latency miss remains
unresolved. This frozen fleet predates the lease-floor, encrypted-record and
issuer/journal increments above.

## Offline Native snapshot commands

The existing Native binary now dispatches `snapshot capture-sqlite` and
`snapshot verify` before database configuration or serving initialization.
Explicit private key/trust files and a literal local SQLite path are required.
Capture writes private paired streams and the signed root to a retained staging
directory, verifies readback, syncs files and directories, then publishes without
replacing an existing output. A failed durability acknowledgment after publication
keeps the published archive and reports uncertainty.

The isolated ordinary Native binary builds successfully. Actual tests pass:
**14 workflow**, **11 existing credential-loader**, **two parser** and **ten
binary privacy/preflight probes**. The strict archive reader retains its owner
and ancestor checks; the initial sandbox UID-mapping failure is preserved and
the qualified synthetic tests run in the actual host UID namespace. Producer
receipt `/tmp/hub-snapshot-cli-qualified.json`
(`44640e39ec92cb9bcc79ae64b6b4fa247bb427980c0d598cf7ffc509f3d7dc00`)
and independent final receipt
`/tmp/hub-snapshot-cli-independent-review/final-receipt.json`
(`4568ab1a2e7a99f09478225a53bdec11d3452e1dd00f416f11b6f28e6a26ccd1`)
bind the candidate. Eight integrated files match exactly; the ninth preserves
the separately qualified public scratch module. Of 2,339 prerequisites, 2,331
still match; eight have the independently qualified issuer/journal/scratch
changes described above. Combined artifact qualification remains pending.

These commands currently report `records_and_reconstruction` and retain the
signed `framing_only` profile. Wiring the stronger scratch verifier into the
commands follows separately. They provide no PostgreSQL/Worker reader, complete
storage-object/application closure, import or activation. Path-based opens
cannot defeat malicious same-owner replacement, and cooperative cancellation
does not bound blocked I/O.

## Live issuer runtimes and snapshot constraint enforcement

The dedicated Worker issuer retains publication, journal and original-operation
receipts in an addressed SQLite Durable Object. Permanent activation prevents
erased history from becoming fresh authority. The issuer seed is absent from
ordinary executor bindings; issuance requires an explicit operator timing profile.
Exact isolated source passes 38 unchanged core tests, two Worker deadline tests
and 16 persistent real Worker lifecycle groups, including lost acknowledgments,
restart, erased history and post-signing deadline refusal. Producer receipt
`/tmp/hub-live-authority-issuer/qualification-receipt-v2.json`
(`222ffce5c43c46261bea81c1e4794c2964c46d8b875e8e432fcb94c017698b88`)
and independent receipt
`/tmp/hub-live-authority-issuer-independent-review/final-v2-receipt.json`
(`84ab7dbcffded8b3b6b97146fd76e89cb810d22b20ba9386750773a87d67600a`)
bind the eight exact integrated Worker/package paths and six unchanged core
prerequisites. This is local dev-profile qualification; optimized and hosted
acceptance remain separate. Renewals still rehash and rewrite publication chunks.

The Worker package now invokes wasm-bindgen's initializer after its module cycle
completes. The missing initializer made an ordinary JavaScript Error trap at the
SDK boundary. An isolated reproduction and actual lifecycle regressions cover
the repair without adding error normalization or production test hooks.

The separate `aos-hub-authority` Native process exposes bounded authenticated
HTTP operations over the schema-two retained journal. Its 12 core control,
15 actual HTTP and 19 journal tests pass. The genuine x86_64 hermetic package
builds, installs exactly that executable and passes packaged help. Producer
`/tmp/aos-native-authority-server/qualification-receipt-final.json`
(`233a931d987b4506f661f0b18582c64e0c57feecdcf2fa6a05390dfa0124fa20`)
and independent final artifact receipt
`/tmp/aos-native-authority-server-independent-review-corrected/final-artifact-receipt.json`
(`56f77265cbe7c110f2582583eed684f482f4b1664165eb78bb23e4d54468d92b`)
bind the source, build and executable inventory. All 18 integration hashes match;
two contextual edits preserve existing SQLite hooks and snapshot exports. The
ordinary Hub retains PostgreSQL and explicitly builds its two existing binaries.

A retained unresolved Native clock session refuses another serving process before
listener creation, including when issuance is disabled. Operator clock-session
resolution, hosted clock/disk qualification, power-loss tests and provider
dispatch remain pending. Schema one is not silently migrated or replaced.

Snapshot capture readback and verify now require retained SQL primary key,
uniqueness, CHECK and foreign-key constraints, typed readback and integrity checks
in private in-memory SQLite. Rollback and close precede reporting or publication.
The six exact integrated paths pass 22 workflow tests, three parser tests and
20 actual binary probes. Correctly signed PK/UNIQUE/CHECK/FK violations are
refused; valid capture/verify, limits, cleanup and privacy pass. Producer
`/tmp/hub-snapshot-cli-scratch-qualified.json`
(`d496c9c164bc3a2e7ccb612501bc4ab6ccdcc10b46fdfc3b8141dbf31d4aa327`)
and independent receipt
`/tmp/hub-snapshot-cli-scratch-independent-review/receipt.json`
(`52606bdad864db8e2eed25f18403ad6878056b75d120238696aa98e5738512dd`)
bind the source, evidence and ordinary dev binary. Report version two uses
`retained_sqlite_constraints`; the signed root remains `framing_only`. Lineage
markers are synthetic. Five recovery requirements remain: application/object
closure, original sealing keys, external credentials, external journal continuity
and writer fencing/activation. Five explicit limits bound admitted work;
cancellation remains cooperative. Earlier records-only evidence is retained.

These independently qualified increments do not establish combined packaged,
full fleet, provider or hosted acceptance. Those gates remain pending.

## Repeatable optimized Worker issuer check

`checks.build.hub-authority-issuer` runs the ordinary optimized Worker package
with disposable JavaScript persistence-fault wrappers. All 40 original assertions
and fault definitions are preserved. Its genuine hermetic run passes all 16
lifecycle groups, output
`/nix/store/zlydzzzlddj3vj4w2npqksl58p7fhp9s-hub-authority-issuer-lifecycle-check-1`.
Producer receipt `/tmp/hub-authority-issuer-check/qualification-receipt.json`
(`10d4950e42afdf144b55493ef7613ae8e743c083ef5a35d4c0baebb01c7547e6`)
and root source/evidence review verify the four integration hashes, real result,
transcript and optimized artifact hashes. This captured source uses the unchanged
pure issuer prerequisites before the three additive Native time-verifier changes;
it does not qualify the current combined workspace. Hosted clocks, deployment
keys, provider dispatch, performance and Native interoperability remain excluded.

## Bounded upload hashing uses native WebCrypto

Six already-buffered upload routes now use native WebCrypto SHA-256 with their
existing route limits and the existing 20 MiB maximum. The helper checks bounds
before copying into JavaScript-owned memory, awaits without a borrowed Wasm
view, validates an exact 32-byte digest and returns value-free errors without
software fallback. Portable incremental/streaming hashes and publication semantic
validation remain intact.

Four actual helper groups and four ordinary production cache-upload groups pass:
known hashes through 20 MiB, cap-before-call refusal, native failure/type/length
checks, Wasm memory growth across a delayed digest, exact R2 bytes, restart,
over-ticket refusal and failed hashing before origin admission or storage writes.
The origin sees only bounded metadata (0/107/92 bytes for the successful 4 MiB
case). Producer `/tmp/hub-worker-native-digest/qualification-receipt.json`
(`92f535acf8025473250911f9f3db17776423a8ab2c2e20954f98e09d2b2cff2d`)
and independent receipt `/tmp/hub-worker-native-digest/independent-review/receipt.json`
(`6049497d1f467acf7308307f272cb796e7a1ffe470d4dea2c965a5b40b969455`)
bind the exact three integrated paths. This local dev-profile gate proves no
optimized, full fleet, hosted or throughput acceptance.

The earlier dev issuer raw compiler intermediate was overwritten when its hot
target was reused. Its original receipt is unchanged; the final processed Wasm,
shim and runtime evidence remain intact, as disclosed in
`/tmp/hub-live-authority-issuer/final-v2-intermediate-retention-disclosure.json`.
The separate optimized check retains its own immutable ordinary artifact.

## Retained multipart descriptors use explicit byte offsets

Retained file descriptors now read each multipart range at an explicit offset.
The previous clone/seek reader shared the descriptor cursor: a regression against
that implementation failed when its cursor moved from 21 to 16. The corrected
reader passes six actual Linux tests, including 32 concurrent ranges while a
separate descriptor moves the shared cursor, exact retries and short-file errors.
The existing multipart protocol, admission, buffers and concurrency are unchanged.

Producer `/tmp/hub-direct-upload-range-v2-qualified.json`
(`202a1753ccf071471dd166398ccc7e08ad192e08d67e69ee17d0049db2354b40`)
and independent review `/tmp/hub-direct-upload-range-v2-independent-review.json`
(`fe226a9d775bc0433d85f0d2a64abceea6391a4003ed4bc8387209519c55584d`)
bind the exact integrated file. Unix preserves the cursor. The Windows explicit
offset implementation advances it; its pinned standard-library/API contract was
reviewed, but no Windows build or runtime test was performed. This increment does
not enable direct uploads or establish provider, throughput or combined acceptance.

## Retained external metadata effects

The external object consumer supports bounded metadata PUT and explicitly
historical guarded HEAD. It retains a compact effect intent before dispatch,
performs provider I/O outside the object Durable Object, and persists terminal
receipts atomically. Lost acknowledgments and uncertain provider results remain
fenced through restart. Historical HEAD replay cannot settle an uncertain write
or prove current object presence. Configured external aliases refuse the older
hybrid work, credential-probe and cleanup escape paths before provider I/O.

The frozen component passes 25 pure tests and 16 actual persistent Worker fault
groups using controlled S3-compatible Fetch. Producer
`/tmp/hub-external-object-consumer/qualified.json`
(`757c4758d6562e1def94bd02cca42fbf517c972dbc73de8dfde0d5aa2d6446ea`)
and independent final review
`/tmp/hub-external-object-consumer/independent-source-review/final-runtime-receipt.json`
(`e4614dff3b707beeb7877413059ef163a4e9ad337d48bd84c78310ba39f585e0`)
bind the ordinary dev-profile artifact and fault evidence. Root integration
checks 11 exact postimages; two contextual merges preserve the qualified native
digest helper and its six upload call sites. Existing qualified Native time
helpers and the unrelated release dependency change remain intact.

This increment does not enable provider credentials or establish current combined
runtime acceptance. Multipart staging/promotion, retained Native callers, all
alternate writers and historical capabilities, permanent provider exclusivity,
hosted clocks and actual provider qualification remain required before activation.

## Historical checkpoint: staging prerequisites and deployment block

The independent infrastructure prerequisites merged after their required checks
passed. A separate delivery authority project was provisioned with encrypted
state retained. Its reviewed plan selected eight creates and no updates,
replacements or deletes; apply succeeded. The recovery secret container exists,
but its identity payload is not published. This prerequisite does not deploy or
qualify a serving revision.

The subsequent execution-engine publication stopped before publication at its
capacity guard. A read-only inventory found 1,904 existing Cloud Run jobs against
the configured limit of 2,000: 96 slots are available, while the complete new
generation requires 99. Read-only retirement inspection produced no eligible
plans; a captured generation was blocked because a job was absent before its
first retirement claim. No jobs were deleted and no capacity or
retirement guard was bypassed. The hosted Worker/Native pair remains unqualified.

The four direct-upload RFC sections now describe intended behavior, including
private staging, bounded controls, stable operation identity, verified provider
closure and concurrent metadata staging with publication barriers. Their commit
does not enable a direct-upload endpoint or qualify the running release transfer.

## Native upload body boundary and storage-local narinfo projection

The Native hybrid ingress authenticates its signed method, path and upload phase
before polling an upload body. It selects the exact resource authority and
applies route-specific encoded limits before decoding bounded controls. Legacy
raw `RegisterCacheNarinfos` and `ReportCacheNarinfos` requests return 415 in hybrid
mode before reading their bodies, including requests with a misleading signed
phase. Their standalone behavior is unchanged. All hybrid callers must use the
new direct upload flow before this topology is enabled for publication.

The Worker parses narinfo beside storage and sends a closed semantic projection.
Original byte SHA-256 and size remain distinct from the projection. Native
validates the admitted cache path and the selected Nix signing key; the bounded
projection reserves room in its outer control envelope.

Producer `/tmp/hub-native-direct-sessions/guard-narinfo-qualified-final-v2.json`
(`ab48d005e28654d615c6b354532a91affb8f6bf8704a2217b98c7f0a6115b180`)
and independent review
`/tmp/hub-native-direct-sessions/independent-review/receipt.json`
(`a801ebd449dce39a52d74588c9713b7c04b1050610089fc796ef14a496b42209`)
bind eleven Native boundary tests and seven narinfo tests. The original failed
compiler capture and original receipt remain retained. The receipt superseder
only corrects stale scope text.

The matching Worker signer and projection producer pass ordinary default-feature
Wasm compilation with the same ten Native/core prerequisites. Receipt
`/tmp/hub-upload-projection-companion/worker-build-qualified.json`
(`c97b92792b283198242b07e7ba4ef3f6de6f8c1dfd2d052da0cc54779ee7dea6`)
binds the exact compiler input. Root integration verifies all eleven postimages
in `/tmp/hub-native-direct-sessions/root-integration-review.json`.
This partial boundary does not qualify OCI compact completion, direct sessions,
migration 004, provider uploads, combined runtime acceptance or hosted throughput.

## Shared direct upload protocol and signing foundation

The shared protocol now declares seven bounded direct upload RPCs, authenticated
transport discovery, exact part/checksum commitments, sparse resume pages and
compact completion manifests. Protected controls bind the immutable actor UUID,
numeric actor slot, deployment, original operation and placement snapshot. Fresh
storage capability challenges use separate request/reply domains and exact nonce,
audience, selector and deadline correlation. Reserved staging keys cannot become
public final keys. These types do not persist actor reservations or implement
the connected Native, broker or client workflows.

Frozen receipt `/tmp/hub-direct-upload-core/frozen-v3/qualification.json`
(`8f31caf59ab6d18c4d1eb4d2bb6e03db57bf06e072a6d948c17820982344a9f6`)
binds 16 portable, ten core, 16 SigV4 and six multipart XML tests, core Wasm
compilation and actual generated Connect checks. It records 2,447 compiler inputs
and preserves all 421 existing API method/capability entries while adding seven.
The descriptor count is now 428; the previous declared count was stale.

Root review covers the actor, capability, admission, private-key, signing and XML
boundaries. `/tmp/hub-direct-upload-core/root-integration-review.json` verifies
all 38 non-lock postimages. The contextual lock change adds four dependencies
already present in the workspace and preserves the current release-signer graph;
no registry package version changes. Git patch framing was normalized separately
without changing source bytes. Actual provider checksums, CORS, private staging,
closure/promotion, connected callers and hosted throughput remain unqualified.

## Historical checkpoint: Native staging contract bootstrap

The infrastructure bootstrap change replaces a dependency on the later typed
delivery document with reads of three existing artifact repository resources.
The Google provider exposes the full resource path as `id` and the short name as
`name`; both identities, format and ownership labels are verified. The first
live plan's incorrect name assumption and a later development-shell ADC discovery
failure remain retained. The successful retry explicitly selects an already
authenticated credential file.

The reviewed plan is promotable: 46 foundation no-ops, zero Google resource
changes and one nonsensitive contract output. Apply succeeds with existing
encrypted state preserved. All four local gates, seven module fixtures, the
complete OpenTofu module policy check and the then-configured automation gate
pass. AOS builds and qualification run locally; GitHub Actions is not required.
The bootstrap change has not been merged; merge approval is pending. This does not
deploy a serving revision or resolve the separate execution-engine publication
capacity block.

## Direct broker deployment configuration

The hybrid renderer accepts bounded closed JSON files for managed R2 public
coordinates and transport clock evidence. An external-only broker can select
the transport clock independently of managed R2 signing. Both configurations
bind the exact deployment; selecting both requires equal clock facts. Signing
secrets are installed separately in the Worker. The default profile omits the
new broker binding.

Receipt `/tmp/hub-direct-upload-renderer-clock-v2/qualification.json`
(`6a4d887b56a86ff86a80e853330bf3c1ad81cb1d500a846cd2118ba4a7aa2b2a`)
binds 25 library tests (eight direct configuration and 17 ordinary regressions),
the actual Native Hub binary build, and three actual CLI invocations. The CLI
checks default omission, external-only clock rendering and deployment mismatch
refusal. All 2,874 captured source inputs remain unchanged. This qualifies
configuration rendering, not the Worker broker export, provider policy, clock
evidence or a hosted transfer.

The preceding S3 resolver increment exposes the existing exact physical key
composition for private staging inspection. Fourteen focused tests pass; no URL
decoding or provider effects are added. A separate code generator correction
resolves its source root at execution time when Cargo reuses a compiled build
script across checkouts. The actual build and five moved-root cases pass,
including invalid API/capability manifests and stale browser exception refusal.
Receipt `/tmp/hub-proto-build-runtime-root/qualification.json` records those
checks. These increments do not establish upload throughput or combined fleet
acceptance.
