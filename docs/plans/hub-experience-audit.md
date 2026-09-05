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
| Registry | Overview | `(root)` | Review in progress |
| Registry | Storage & replicas | `placements` | Review in progress |
| Registry | Delivery | `delivery` | Review in progress |
| Registry | Binary caches | `caches` | Review in progress |
| Registry | Identity & access | `access` | Review in progress |
| Registry | Signing keys | `signing-keys` | Review in progress |
| Registry | Access tokens | `tokens` | Review in progress |
| Registry | Containers | `containers` | Review in progress |
| Registry | Upstream mirror | `mirror` | Review in progress |
| Registry | Configuration history | `configuration` | Review in progress |
| Registry | Change requests | `change-requests` | Review in progress |
| Registry | Publications | `publish-history` | Review in progress |
| Registry | Operations & health | `operations` | Review in progress |
| Registry | Danger zone | `danger` | Review in progress |
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
