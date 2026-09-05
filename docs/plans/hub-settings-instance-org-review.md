# Hub instance and organization settings review

This record covers the page-by-page visual review of instance and organization
settings after the workflow-first reorganization. It separates evidence from
the `9a4fd29e6` fixture from the final rerun that must use the combined build.

## Evidence and method

- `/tmp/aos-hub-instance-org-manual-full-9a4fd29e6` contains 124 screenshots
  and `report.json` for all 31 non-create instance and organization pages.
  Each page was captured at a 1425-1440 pixel desktop viewport and a 390 pixel
  narrow viewport, first with disclosures closed and then with available
  disclosures open.
- `/tmp/aos-hub-instance-org-create-review-9a4fd29e6` contains 32 screenshots
  and `report.json` for the eight routable infrastructure create pages: domain,
  network policy, endpoint, and gateway at both instance and organization
  scope. All 58 checks passed with no rendered errors, horizontal overflow,
  JavaScript exceptions, or console errors.
- The non-create run recorded no JavaScript or console errors. Eight viewport
  checks failed: narrow domain and endpoint summaries, and expanded webhook and
  audit content at both relevant widths. These are the defects described below,
  rather than final-build regressions.
- The canonical 73-page run in
  `/tmp/aos-hub-settings-final-pages-9a4fd29e6` stopped when the server did not
  route `/-/instance/bindings/new`. That route and the fixes below require a
  combined rebuild and final rerun.

Every completed visual check included the rendered scope heading, loading
completion, inline error state, horizontal viewport bounds, and closed/open
disclosure states. The review also checked purpose copy, primary action order,
permission-dependent controls in source, Cancel navigation on standalone create
pages, and reviewed-mutation labels.

## Instance pages

| Path | Page review | Result at reviewed fixture |
| --- | --- | --- |
| `/-/instance` | Overview | Clear scope summary and resource cards; desktop and narrow layouts pass. |
| `/-/instance/bindings` | Bindings | Primary inventory and Create action are clear. Expanded provider, credential, grant, and deletion controls are appropriately technical. The compact status labels need the shared spacing treatment. |
| `/-/instance/bindings/new` | Create binding | Source review confirms purpose copy, provider-specific fields, Cancel, and **Review creation**. Live capture is pending the server-route rebuild. |
| `/-/instance/domains` | Domains | Empty state and Add domain action are clear; no fixture-owned domain exercises the card here. |
| `/-/instance/domains/new` | Add domain | One-purpose form, immutable-hostname help, Cancel, and **Review creation** all pass desktop and narrow review. |
| `/-/instance/network-policies` | Network policies | Granted public policy reads clearly and immutable revisions remain disclosed. The owned deletion panel used the internal term “boundary”; corrected to “network policy.” |
| `/-/instance/network-policies/new` | Create network policy | Provider identity is established before revision policy. Conditional fields, Cancel, and **Review creation** pass both widths. |
| `/-/instance/endpoints` | Endpoints | Empty state and Create endpoint action are clear. |
| `/-/instance/endpoints/new` | Create endpoint | Guided named-resource choices, missing-domain prerequisite, pinned revision fields, multiline probe control, Cancel, and review gating pass both widths. |
| `/-/instance/gateways` | Gateways | Empty state and Create gateway action are clear. |
| `/-/instance/gateways/new` | Create gateway | Named binding and endpoint choices, pinned endpoint generation, delivery paths, Cancel, and review gating pass both widths. |
| `/-/instance/topology-defaults` | Topology defaults | Effective future defaults precede the disclosed editor and explicitly exclude existing resources. Empty configuration version rendered as a blank value; corrected to **Not yet saved**. |
| `/-/instance/identity-and-signup` | Identity & signup | Effective posture and editable login/signup policy remain primary and readable at both widths. |
| `/-/instance/tokens` | Access tokens | Empty state, bounded credential purpose, and lazy issuance form are consistent with organization tokens. |
| `/-/instance/resource-defaults` | Resource defaults | Legitimate instance defaults remain visible as the primary form with accurate inheritance guidance. |
| `/-/instance/branding` | Branding | Purpose, public-name fields, and optional presentation values are aligned and readable at both widths. |
| `/-/instance/operations` | Operations | State filter, scope, operation summary, and timestamp presentation are compact and understandable. |

## Organization pages

| Path | Page review | Result at reviewed fixture |
| --- | --- | --- |
| `/-/org/workflow-test` | Overview | Counts and task-oriented resource cards explain the organization scope; the profile editor remains disclosed. |
| `/-/org/workflow-test/projects` | Projects | Purpose, empty state, and Create project action are clear. |
| `/-/org/workflow-test/projects/new` | Create project | Owned by the shared resource-page pass. Final live capture must confirm the added Cancel action and review label. |
| `/-/org/workflow-test/registries` | Registries | Inventory purpose and organization-root behavior are clear. |
| `/-/org/workflow-test/registries/new` | Create registry | Owned by the shared resource-page pass. Final live capture must confirm Cancel and **Review creation**. |
| `/-/org/workflow-test/caches` | Binary caches | Independent cache ownership and registry-stack relationship are clear. |
| `/-/org/workflow-test/caches/new` | Create binary cache | Owned by the shared resource-page pass. Final live capture must confirm Cancel and **Review creation**. |
| `/-/org/workflow-test/bindings` | Bindings | The granted instance binding is distinguished from owned resources. Closed state is concise; advanced provider/grant controls are disclosed. The compact status labels need the shared spacing treatment. |
| `/-/org/workflow-test/bindings/new` | Create binding | Source review matches the instance form. Final live capture is pending the server-route rebuild. |
| `/-/org/workflow-test/domains` | Domains | Current hostname and DNS/TLS state are useful in the summary; editors appear only when expanded. The long stable ID overflowed at 390 pixels; fixed in shared summary wrapping. |
| `/-/org/workflow-test/domains/new` | Add domain | Purpose, hostname help, Cancel, and **Review creation** pass both widths. |
| `/-/org/workflow-test/network-policies` | Network policies | Granted public policy is correctly read-only and its immutable revision remains inspectable. Delete terminology was corrected for owned policies. |
| `/-/org/workflow-test/network-policies/new` | Create network policy | Conditional identity form, Cancel, and **Review creation** pass both widths. |
| `/-/org/workflow-test/endpoints` | Endpoints | Summary shows lifecycle state and expands into generations, grants, and deletion. It incorrectly rendered an opaque domain ID as an HTTPS hostname and overflowed at 390 pixels. The identity now says **Managed domain**, and shared summary wrapping handles the ID. |
| `/-/org/workflow-test/endpoints/new` | Create endpoint | Named prerequisites and pinned revisions are clear; empty-domain guidance and disabled review prevent an invalid plan. Both widths pass. |
| `/-/org/workflow-test/gateways` | Gateways | Binding grouping and lifecycle state make the storage-to-endpoint relationship visible; advanced generation controls remain disclosed. |
| `/-/org/workflow-test/gateways/new` | Create gateway | Guided storage/endpoint selection, path fields, Cancel, and review gating pass both widths. |
| `/-/org/workflow-test/topology-defaults` | Topology defaults | Effective defaults are primary, configuration metadata is secondary, and mutation controls are disclosed. Blank version handling was corrected. |
| `/-/org/workflow-test/identity-and-access` | Identity & access | Service-account purpose and empty state are clear; creation is lazy and explains the follow-on membership/token tasks. |
| `/-/org/workflow-test/members` | Members | Direct-grant lookup is primary, invitation onboarding is separate, and the expanded invitation form remains readable at 390 pixels. |
| `/-/org/workflow-test/sso` | SSO | Effective sign-in policy precedes essential OIDC fields. Claims and account mapping are advanced; domain claiming is a separate reviewed task. Both widths pass. |
| `/-/org/workflow-test/signing-keys` | Signing keys | External-custody purpose, ownership scopes, enrollment, and rotation/retirement states are explicit and responsive. |
| `/-/org/workflow-test/tokens` | Access tokens | Scope boundary, short-lived credential purpose, empty state, and lazy issuance form are clear. |
| `/-/org/workflow-test/webhooks` | Webhooks | Signed-delivery purpose and empty state are clear. Expanded event names overlapped on desktop and overflowed narrow layout; event options now use the wrapping compact-row treatment. |
| `/-/org/workflow-test/operations` | Operations | Scope-aware durable work, state filter, status, and human UTC timestamp are concise. |
| `/-/org/workflow-test/audit-log` | Audit log | Actor, scope, result references, and raw detail are appropriately separated. Raw Unix seconds and unbounded JSON produced extreme overflow; timestamps now use the shared UTC formatter and detail uses the bounded JSON view. |
| `/-/org/workflow-test/danger` | Danger zone | Destructive purpose, fail-closed dependency explanation, typed confirmation, and disabled review state are clear at both widths. |

## Final rerun

The combined console build must repeat the canonical route sweep after it
includes the binding-create route, shared narrow summary/header fixes, shared
resource create Cancel actions, and commit `79893f713`. Acceptance requires:

1. Every instance and organization navigation and create route renders at both
   desktop and 390 pixel widths.
2. Closed and expanded states have no horizontal overflow or overlapping
   controls.
3. No unexpected inline errors, failed console asset/RPC requests, console
   errors, or JavaScript exceptions occur.
4. The corrected managed-domain endpoint label, webhook filter, audit timestamp
   and detail, network-policy deletion label, and unsaved defaults version are
   visible in the final screenshots.
