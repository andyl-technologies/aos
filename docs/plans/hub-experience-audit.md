# Hub experience audit

This follows the settings-workflow implementation in PR #240. Review each
page for purpose, discovery, useful controls, permission-aware actions, empty
and failure states, form alignment, responsive layout, and request cost.
A page is complete only after its final behavior is verified, not just edited.

## Constraints

- CLI tools remain usable with bare HTTP/Git registries. Hub APIs are optional
  enhancements, never a prerequisite for public metadata or artifact access.
- Retain signed publication, review/apply, ownership, and current-generation
  authorization boundaries. Advanced editors complement guided workflows.
- Staging is authorized; retain live database `hub`, secrets, bindings, and
  `--oci-pull-enabled` unless a deliberate reviewed change requires otherwise.
- Record measured performance; never infer hosted speed from native timings.

## Settings pages

| Scope | Page | Path suffix | Review / verification |
| --- | --- | --- | --- |
| Instance | Overview | `(root)` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Bindings | `bindings` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Create binding | `bindings/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Domains | `domains` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Add domain | `domains/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Network policies | `network-policies` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Create network policy | `network-policies/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Endpoints | `endpoints` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Create endpoint | `endpoints/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Gateways | `gateways` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Create gateway | `gateways/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Topology defaults | `topology-defaults` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Identity & signup | `identity-and-signup` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Access tokens | `tokens` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Resource defaults | `resource-defaults` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Branding | `branding` | Reviewed desktop/narrow; final 519-check sweep passed |
| Instance | Operations | `operations` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Overview | `(root)` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Projects | `projects` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Create project | `projects/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Registries | `registries` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Create registry | `registries/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Binary caches | `caches` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Create binary cache | `caches/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Bindings | `bindings` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Create binding | `bindings/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Domains | `domains` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Add domain | `domains/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Network policies | `network-policies` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Create network policy | `network-policies/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Endpoints | `endpoints` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Create endpoint | `endpoints/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Gateways | `gateways` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Create gateway | `gateways/new` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Topology defaults | `topology-defaults` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Identity & access | `identity-and-access` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Members | `members` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | SSO | `sso` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Signing keys | `signing-keys` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Access tokens | `tokens` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Webhooks | `webhooks` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Operations | `operations` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Audit log | `audit-log` | Reviewed desktop/narrow; final 519-check sweep passed |
| Organization | Danger zone | `danger` | Reviewed desktop/narrow; final 519-check sweep passed |
| Registry | Overview | `(root)` | Reviewed desktop/narrow; clearer public links and action spacing; final page sweep passed |
| Registry | Storage & replicas | `placements` | Reviewed desktop/narrow; fixed task selector alignment and summary wrapping; final page sweep passed |
| Registry | Delivery | `delivery` | Reviewed desktop/narrow; final expanded page sweep passed |
| Registry | Binary caches | `caches` | Reviewed desktop/narrow; real cache links, corrected help column and action spacing; final page sweep passed |
| Registry | Identity & access | `access` | Reviewed desktop/narrow; clearer roles, tokens, signing and ownership guidance; final page sweep passed |
| Registry | Signing keys | `signing-keys` | Reviewed desktop/narrow; read-first inventory and gated editors; final expanded page sweep passed |
| Registry | Access tokens | `tokens` | Reviewed desktop/narrow; read-first inventory and gated issuance; final expanded page sweep passed |
| Registry | Containers | `containers` | Reviewed desktop/narrow; disabled GC caused503 and overflow; capability gate fixed, final page sweep passed |
| Registry | Upstream mirror | `mirror` | Reviewed desktop/narrow; added status/empty state, gated editor and useful timestamp; final page sweep passed |
| Registry | Configuration history | `configuration` | Reviewed desktop/narrow; moved ID inspector into disclosure and clarified history types; final page sweep passed |
| Registry | Change requests | `change-requests` | Reviewed desktop/narrow; clearer merge guidance; corrected audit URL; final page sweep passed |
| Registry | Publications | `publish-history` | Reviewed desktop/narrow; history first, advanced manifest editor and clearer purpose; final page sweep passed |
| Registry | Operations & health | `operations` | Reviewed desktop/narrow; readable timestamps and failure presentation; final page sweep passed |
| Registry | Danger zone | `danger` | Reviewed desktop/narrow; confirmation overlapped input; full-width confirmation fixed, final page sweep passed |
| Cache | Overview | `(root)` | Reviewed desktop/narrow; final 519-check sweep passed |
| Cache | Storage & replicas | `placements` | Reviewed desktop/narrow; final 519-check sweep passed |
| Cache | Delivery | `delivery` | Reviewed desktop/narrow; final 519-check sweep passed |
| Cache | Objects & closures | `objects` | Reviewed desktop/narrow; final 519-check sweep passed |
| Cache | Integrations | `integrations` | Reviewed desktop/narrow; final 519-check sweep passed |
| Cache | Identity & access | `access` | Reviewed desktop/narrow; final 519-check sweep passed |
| Cache | Signing keys | `signing-keys` | Reviewed desktop/narrow; final 519-check sweep passed |
| Cache | Access tokens | `tokens` | Reviewed desktop/narrow; final 519-check sweep passed |
| Cache | Retention | `retention` | Reviewed desktop/narrow; final 519-check sweep passed |
| Cache | Garbage collection | `garbage-collection` | Reviewed desktop/narrow; final 519-check sweep passed |
| Cache | Operations & health | `operations` | Reviewed desktop/narrow; final 519-check sweep passed |
| Cache | Danger zone | `danger` | Reviewed desktop/narrow; final 519-check sweep passed |

Read-only Packages, Documentation, Images, and Channels catalogs are leaving
settings navigation. Their old settings URLs redirect to canonical registry
browse pages, which retain those end-user capabilities.

## Review areas and outcomes

| Area | Outcome |
| --- | --- |
| Shared layout | Reviewed every settings page closed/expanded at desktop and narrow widths; corrected form columns, help, action rows, identity wrapping, disclosures, and GC status stacking. |
| Topology | Guided delivery/storage/cache relationships and scoped batch reads; hosted topology SQL calls fell from 38 to 23 for unchanged inventory. |
| Public overview | Setup commands precede detailed trust/cache/readme information; warnings remain visible. |
| Packages | Preserve search, sorting, and signed snapshot selection; explicit unavailable states; pagination above and below results. |
| Documentation | Dedicated lazy document reads, exact digest links, stable section anchors, and preserved search/kind pagination. |
| Containers | Digest-pinned pull examples, working public route, useful filter spacing and distinct empty states; populated staging inventory unavailable. |
| Images | Independent APM usage and optional exact Hub commands; portable signed CLI list/show/download; populated staging inventory unavailable. |
| Channels | Clear release/rollout guidance and signed client commands; public stable channel verified. |
| CLI integration | Strict documentation modes, portable signed image resolution, and deferred OCI profile authentication; managed control-plane mutations retain Hub authority. |

## Verification record

Earlier implementation evidence is in `hub-settings-workflows.md`. New page
sweep and final integration results will be recorded here as they complete.

### Individual browser review, before final rebuild

Native fixture source `9a4fd29e6` passed all 29 workflow checks with embedded
console assets. The initial full page sweep found a missing instance binding
creation route and stopped at that defect. Separate scope sweeps continued
the review while the route was fixed. Registry advanced container maintenance
exposed disabled-rollout 503s; the shell now reports availability before the
console loads these controls. The final browser sweep below verifies both fixes; neither failure was waived.

Registry evidence: `/tmp/aos-hub-settings-registry-review-9a4fd29e6/`,
`/tmp/aos-hub-settings-registry-rest-9a4fd29e6/`, and
`/tmp/aos-hub-settings-registry-activity-9a4fd29e6/`.
Cache evidence: `/tmp/aos-hub-settings-final-cache-9a4fd29e6/`.
The final audit captures closed and expanded views at desktop and narrow widths
for every canonical page; the four former catalog routes are checked separately.


### Final settings integration at `fb0e89eae`

The fresh native Hub fixture passed 29 integration checks. Chrome passed 99
functional checks, with no skips, including real retention registry selection,
GC policy review, and invalidation of a stale review after editing. The full
route sweep passed 519 checks across 73 canonical settings pages and four
legacy catalog redirects, producing 292 closed/expanded desktop/narrow
screenshots. It recorded no page failures, JavaScript exceptions, console errors,
or unexpected failed requests. Four narrowly identified optional-resource 404s
represent absent identity-provider, signing-usage, and mirror configuration.
They are not a general error suppression rule.

Evidence: `/tmp/aos-hub-settings-functional-fb0e89eae/report.json` and
`/tmp/aos-hub-settings-verified-fb0e89eae/report.json`. The instance/organization
visual findings are detailed in `hub-settings-instance-org-review.md`.

The sweep uses an instance owner. Navigation permissions additionally have 30
passing contract checks; a restricted-user browser session was not exercised.
The final presentation correction stacks the GC generation status on narrow
screens (`50e96fb7b`); the packaged native/browser run at `a02b6f4da` below
verifies the rebuilt correction.

Public pages now prioritize setup, preserve package filters/sort/snapshot
selection, distinguish unavailable snapshots, use stable documentation anchors,
load documentation only when requested, pin container pull examples to a digest,
and show an independent APM image command. Public browse tests (26), documentation
model tests (14), exact documentation lookup tests (7), and the signed-snapshot
listing regression passed. Public browser review and hosted verification passed as recorded below.

The explicit `aos doc hub` mode requires a valid Hub origin and registry;
installed and package documentation remain independent. Five real-process tests
passed, including offline installed documentation and no silent authentication
fallback. Portable image resolution and its trust-continuity tests passed; the final
combined CLI and existing APM registry suites are recorded separately below.


### Hosted verification at `fb0e89eae`

Deployed `/nix/store/7h658njln1vjps354grl0rnz99qp9dwb-aos-hub-cloudflare-0.1.0`
to the existing staging Worker. `/.well-known/aos-deployment` returns
`staging-fb0e89eaed29ca003d7c53310baa3c89707ae1f2`. Database `hub`, domains,
bindings, secrets, and the OCI pull rollout setting were preserved. Both pre-
and postdeployment recovery bookmarks were captured without resetting data.

Authenticated topology returned the same two placements, two routes, three
advertisements, and one canonical endpoint in all three requests. SQL calls
fell from 38 to 23 (39.5%). Request times were 1.875, 1.081, and 1.540 seconds,
compared with the earlier 2.06-2.47 seconds. These are small sequential samples,
not a load test. Workflow inventory returned 200 in 1.706, 0.638, and 0.694
seconds (10 SQL calls each); container inventory returned 200 in 0.535, 0.430,
and 0.902 seconds (9 calls each). Those two inventories remain empty.
Evidence: `/tmp/aos-staging-authenticated-settings-fb0e89eae/report.json`.

The public `aos-hub` package page returns 200 and now links to documentation
instead of embedding its entire fetched document. The recorded response fell
from 11,598 to 8,216 bytes; the postdeployment request took 0.436 seconds.
Documentation remains available through its dedicated page and exact digest link.
Signed-in browser evidence remains the native fixture; CLI OAuth verification
is not a browser login.


### Final public refinements and console build

The six public staging pages passed desktop/narrow browser checks, with no
page overflow or captured errors. Packages (265 entries), documentation (266),
and the stable channel (256/256 rollout buckets) exercised real content.
Containers and Images were empty, so their populated detail views were not
verified on staging. Evidence: `/tmp/aos-hub-public-staging-fb0e89eae/report.json`.
This review prompted pagination above and below package/documentation lists,
container filter spacing, and precise filtered versus unfiltered empty states
(`a02b6f4da`). All 75 core web tests then passed, including the corrected
canonical-settings versus legacy-catalog route assertion.

The console-only release profile now uses size optimization, ThinLTO, one
codegen unit, and stripped debug info, with matching dependency cache settings.
On identical source and tool versions, WASM fell from 16,258,602 to 15,364,367
bytes; deterministic gzip-9 output fell from 2,748,437 to 2,183,452 bytes (20.6%).
The optimized assets passed all 99 functional and 519 route checks through a
documented loopback proxy that replaced only console assets against the native
fixture. No unexpected request, JavaScript, or console failures occurred.
Evidence: `/tmp/aos-console-size-thin-browser/` and
`/tmp/aos-console-size-report.json`. This proxy verification is distinct from
an embedded native artifact or hosted transfer measurement.

The subsequent Nix distribution including the narrow GC correction built at
`/nix/store/xfh7g357shi1hs0vxybf7dmk9nr1y9fs-aos-hub-console-dist-0.1.0`;
its WASM is 15,365,452 bytes. Staging's previous console transfers 2,741,353 bytes
with actual `Content-Encoding: gzip`. The deployed measurement below verifies the final transfer size.


### Final packaged and hosted Hub at `a02b6f4da`

Built the committed Hub/server/UI snapshot from `git archive a02b6f4da` while
later CLI-only work continued separately. The final installer is
`/nix/store/qycc6qsyvf0507y5vqx3lhmxs8wadslf-aos-hub-cloudflare-0.1.0`.
Its exact native executable passed 29 fresh-process integration checks and 99
Chrome functional checks. The narrow GC review screenshot was inspected and
confirms the corrected stacked label/status layout. Evidence:
`/tmp/aos-hub-final-native-a02b6f4da.log` and
`/tmp/aos-hub-final-functional-a02b6f4da/report.json`.

Staging now serves `staging-a02b6f4da6713b549c28a0488c531e1aa0f69b25`.
The database, domains, bindings, secrets, and OCI pull availability were
preserved, and fresh pre/postdeployment recovery bookmarks were captured.
Final authenticated reads all returned 200. The topology inventory is unchanged
and uses 23 SQL calls; final request times were 1.332, 1.069, and 0.998 seconds.
Workflow and container inventories still use 10 and 9 calls respectively.
Evidence: `/tmp/aos-staging-authenticated-final-a02b6f4da/report.json`.

Served Worker JS, CSS, and decompressed WASM match the final distribution bytes.
Actual gzip transfer fell from 2,741,353 to 2,182,580 bytes (20.4%). The measured
WASM request took 1.525 seconds versus 2.147 seconds in the earlier single
request; the size reduction is verified, while these timings are not a load-time
benchmark. Evidence: `/tmp/aos-hub-final-served-assets-a02b6f4da.json`.

The native asset identity is `85afbf0a` and the Worker identity is `40dde7a0`.
Native package scrubbing replaces 71 embedded vendor-path store hashes with
fixed-length placeholders in WASM diagnostic strings. Normalizing that single
vendor hash makes the bytes identical; code, JS, CSS, and public browse assets
match. Each runtime serves its own correct content-addressed filenames.


The final public staging pass additionally passed 48 checks with 16 inspected
screenshots at 1440px and 390px. Actual package filtering, snapshot selection,
and top/bottom pagination preserve filter, sorting, and release selection.
A 167-result documentation search preserves query and kind through both pagers.
Container filter spacing and distinct unpublished/no-match states are verified.
There were no observed page overflows, JavaScript exceptions, console errors,
or HTTP errors. Evidence: `/tmp/aos-staging-public-final/summary.json`,
`report.json`, and `supplement-report.json` in the same directory.

### Portable image CLI integration

`bfcae06c5` adds signed image discovery through configured APM Git/HTTP registries
and verified NAR extraction directly to an output file. Hub selection remains
optional and explicit. Independent review found and corrected two trust-state
edge cases: exact release equality is enforced before cache/key publication,
and live selectors retain a TUF root reference separately from selected-commit
ancestry. Neither selector changes nor historical selection lower shared live
rollback floors or rewrite APM configuration.

The final real-process regression passed against a signed static HTTP origin
and binary cache, with no Hub, Nix executable, Git executable, or checkout in the
consumer environment. It covers multiple architectures, ambiguous selection,
format/target filters, verified download, historical releases, new channels,
configured TUF state, rollback refusal, corrupted content, explicit Hub 401
without fallback, and signed retag rejection without changing published cache,
keys, or state. The earlier 77 focused state/parser/NAR tests also passed.
Evidence: `/tmp/aos-portable-image-trust-final.log`.


### Combined CLI and bare-registry preservation

After image and OCI integration, all 12 CLI process tests passed (five
documentation, one comprehensive signed-image scenario, two container admission,
and four container transfer/publication tests). Six container parser tests and
29 OCI protocol tests passed. The existing APM registry end-to-end suite passed
15 tests with no failures; one pre-existing Git-version matrix test requires
separately pinned Git binaries and remains ignored. It covers Git/static HTTP,
release/upload/channel synchronization, freshness/rollback defenses, and
pack/delta paths. Evidence: `/tmp/aos-root-registry-e2e-final.log`.

These results are from `569c914d7`, before integrating upstream's subsequently
merged CLI/module refactors. Any checks after that integration are recorded
separately.
