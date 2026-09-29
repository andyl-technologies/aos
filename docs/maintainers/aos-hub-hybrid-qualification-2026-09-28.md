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

The typed root operator API now provides `PlanDecision`, `ApplyDecision` and
`GetAuthority`. Eight focused Native tests pass for current root authorization,
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

Frozen external S3 physical GC, safe retirement of obsolete object coordination
state, and whole-Hub snapshot/restore also remain to be implemented. This successful fleet
run is one acceptance checkpoint; it does not complete RFC-0023.

See the [deployment procedure](aos-hub-hybrid-deployment.md) and
[RFC acceptance gates](../rfcs/0023-hub-hybrid-topology/06-implementation-and-validation.md).
