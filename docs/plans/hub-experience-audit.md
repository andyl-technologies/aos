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
| Instance | Overview | `(root)` | Review in progress |
| Instance | Bindings | `bindings` | Review in progress |
| Instance | Create binding | `bindings/new` | Review in progress |
| Instance | Domains | `domains` | Review in progress |
| Instance | Add domain | `domains/new` | Review in progress |
| Instance | Network policies | `network-policies` | Review in progress |
| Instance | Create network policy | `network-policies/new` | Review in progress |
| Instance | Endpoints | `endpoints` | Review in progress |
| Instance | Create endpoint | `endpoints/new` | Review in progress |
| Instance | Gateways | `gateways` | Review in progress |
| Instance | Create gateway | `gateways/new` | Review in progress |
| Instance | Topology defaults | `topology-defaults` | Review in progress |
| Instance | Identity & signup | `identity-and-signup` | Review in progress |
| Instance | Access tokens | `tokens` | Review in progress |
| Instance | Resource defaults | `resource-defaults` | Review in progress |
| Instance | Branding | `branding` | Review in progress |
| Instance | Operations | `operations` | Review in progress |
| Organization | Overview | `(root)` | Review in progress |
| Organization | Projects | `projects` | Review in progress |
| Organization | Create project | `projects/new` | Review in progress |
| Organization | Registries | `registries` | Review in progress |
| Organization | Create registry | `registries/new` | Review in progress |
| Organization | Binary caches | `caches` | Review in progress |
| Organization | Create binary cache | `caches/new` | Review in progress |
| Organization | Bindings | `bindings` | Review in progress |
| Organization | Create binding | `bindings/new` | Review in progress |
| Organization | Domains | `domains` | Review in progress |
| Organization | Add domain | `domains/new` | Review in progress |
| Organization | Network policies | `network-policies` | Review in progress |
| Organization | Create network policy | `network-policies/new` | Review in progress |
| Organization | Endpoints | `endpoints` | Review in progress |
| Organization | Create endpoint | `endpoints/new` | Review in progress |
| Organization | Gateways | `gateways` | Review in progress |
| Organization | Create gateway | `gateways/new` | Review in progress |
| Organization | Topology defaults | `topology-defaults` | Review in progress |
| Organization | Identity & access | `identity-and-access` | Review in progress |
| Organization | Members | `members` | Review in progress |
| Organization | SSO | `sso` | Review in progress |
| Organization | Signing keys | `signing-keys` | Review in progress |
| Organization | Access tokens | `tokens` | Review in progress |
| Organization | Webhooks | `webhooks` | Review in progress |
| Organization | Operations | `operations` | Review in progress |
| Organization | Audit log | `audit-log` | Review in progress |
| Organization | Danger zone | `danger` | Review in progress |
| Registry | Overview | `(root)` | Reviewed desktop/narrow; clearer public links and action spacing; final rerun pending |
| Registry | Storage & replicas | `placements` | Reviewed desktop/narrow; fixed task selector alignment and summary wrapping; final rerun pending |
| Registry | Delivery | `delivery` | Reviewed desktop and automated narrow metrics; final expanded visual review pending |
| Registry | Binary caches | `caches` | Reviewed desktop/narrow; real cache links, corrected help column and action spacing; final rerun pending |
| Registry | Identity & access | `access` | Reviewed desktop/narrow; clearer roles, tokens, signing and ownership guidance; final rerun pending |
| Registry | Signing keys | `signing-keys` | Reviewed desktop/narrow; read-first inventory and gated editors; final expanded rerun pending |
| Registry | Access tokens | `tokens` | Reviewed desktop/narrow; read-first inventory and gated issuance; final expanded rerun pending |
| Registry | Containers | `containers` | Reviewed desktop/narrow; disabled GC caused503 and overflow; capability gate fixed, final rerun pending |
| Registry | Upstream mirror | `mirror` | Reviewed desktop/narrow; added status/empty state, gated editor and useful timestamp; final rerun pending |
| Registry | Configuration history | `configuration` | Reviewed desktop/narrow; moved ID inspector into disclosure and clarified history types; final rerun pending |
| Registry | Change requests | `change-requests` | Reviewed desktop/narrow; clearer merge guidance; corrected audit URL; final rerun pending |
| Registry | Publications | `publish-history` | Reviewed desktop/narrow; history first, advanced manifest editor and clearer purpose; final rerun pending |
| Registry | Operations & health | `operations` | Reviewed desktop/narrow; readable timestamps and failure presentation; final rerun pending |
| Registry | Danger zone | `danger` | Reviewed desktop/narrow; confirmation overlapped input; full-width confirmation fixed, final rerun pending |
| Cache | Overview | `(root)` | Review in progress |
| Cache | Storage & replicas | `placements` | Review in progress |
| Cache | Delivery | `delivery` | Review in progress |
| Cache | Objects & closures | `objects` | Review in progress |
| Cache | Integrations | `integrations` | Review in progress |
| Cache | Identity & access | `access` | Review in progress |
| Cache | Signing keys | `signing-keys` | Review in progress |
| Cache | Access tokens | `tokens` | Review in progress |
| Cache | Retention | `retention` | Review in progress |
| Cache | Garbage collection | `garbage-collection` | Review in progress |
| Cache | Operations & health | `operations` | Review in progress |
| Cache | Danger zone | `danger` | Review in progress |

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
console loads these controls. These findings are fixes awaiting final browser
verification, not waived test failures.

Registry evidence: `/tmp/aos-hub-settings-registry-review-9a4fd29e6/`,
`/tmp/aos-hub-settings-registry-rest-9a4fd29e6/`, and
`/tmp/aos-hub-settings-registry-activity-9a4fd29e6/`.
Cache evidence: `/tmp/aos-hub-settings-final-cache-9a4fd29e6/`.
The final audit captures closed and expanded views at desktop and narrow widths
for every canonical page; the four former catalog routes are checked separately.
