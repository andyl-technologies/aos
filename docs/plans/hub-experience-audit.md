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

## Next passes

| Area | Work and evidence |
| --- | --- |
| Shared layout | Consistent form columns, full-width textareas, action rows, help, cards, and disclosures; desktop and narrow browser audit. |
| Topology | Guided delivery/storage/cache relationships; remove repeated remote SQL reads. Baseline GetSurfaceTopology: 2.06-2.47 s, 38 SQL calls for 2 routes/2 placements. |
| Public overview | Verify useful install/use entry points, status, discoverability, and empty states. |
| Packages | Verify search, version/platform selection, install commands, and bare-registry paths. |
| Documentation | Verify discovery, reading/navigation, version context, examples, and configuration guidance. |
| Containers | Verify repository/tag/digest discovery and copyable pull commands; public route fixed by OCI pull rollout. |
| Images | Verify platform/format selection, verified downloads, and machine-use guidance. |
| Channels | Verify rollout explanation, release selection, and client commands. |
| CLI integration | Trace and test optional Hub enhancement and independent HTTP/Git fallbacks. |

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
One final presentation correction stacks the GC generation status on narrow
screens (`50e96fb7b`); rebuilt-asset verification of that correction is pending.

Public pages now prioritize setup, preserve package filters/sort/snapshot
selection, distinguish unavailable snapshots, use stable documentation anchors,
load documentation only when requested, pin container pull examples to a digest,
and show an independent APM image command. Public browse tests (26), documentation
model tests (14), exact documentation lookup tests (7), and the signed-snapshot
listing regression passed. Public browser review and hosted verification remain
in progress.

The explicit `aos doc hub` mode requires a valid Hub origin and registry;
installed and package documentation remain independent. Five real-process tests
passed, including offline installed documentation and no silent authentication
fallback. Portable image resolution and its trust-continuity tests remain in
progress.


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
