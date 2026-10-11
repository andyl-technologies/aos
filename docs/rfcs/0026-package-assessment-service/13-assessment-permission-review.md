# Assessment permission policy for review

**Status:** Proposed; no permission definitions or role grants have been
installed. This appendix specifies the exact policy needed to admit public
RFC-0026 service calls and qualify Native, Worker, Hybrid and browser behavior.
It does not authorize deployment, change existing memberships or mint credentials.

## Proposed permission definitions

| Wire permission | Scope and authority |
| --- | --- |
| `assessment.read` | Read an authorized resource's assessment inventory, immutable results, scan receipts, status, advisory associations, schedules, alerts, subscriptions, delivery status and event replay. Read access cannot start provider work. |
| `assessment.scan` | Request, cancel or explicitly retry a scan in the selected resource under current read access, inventory, policy and finite source allowance. |
| `assessment.schedule.manage` | Review and apply recurring scan selection and cadence within the selected resource and administrator limits. Service-backed delegation independently requires the selected service account's current read and scan authority. |
| `assessment.alert.acknowledge` | Acknowledge one exact issue episode and revision. Acknowledgement cannot resolve a finding, change applicability or satisfy a release gate. |
| `assessment.subscription.manage` | Review and apply scoped notification selectors, expiry and an independently admitted destination. The actor must also have current read access to the subscribed resource. |
| `assessment.evidence.export` | Export permitted retained evidence from the selected resource. This grants no permission to read another partition or export secrets, private claims or protected raw provider bodies. |
| `assessment.evidence.import` | Submit a bundle for bounded scoped validation. Import cannot establish source, publisher or release authority or advance an assessment head by itself. |
| `assessment.disposition.review` | Review explicit component, advisory, artifact, policy, release and time scopes through the disposition workflow. The decision remains subject to the independent release-policy and evidence requirements. |

These names become closed variants in the shared pure IAM kernel, with exact
wire parsing and serialization. Native and Worker use the same definitions and
authorization decision. Unknown permissions continue to deny access.

## Exact proposed default role matrix

A check mark grants the permission; an em dash does not. Existing non-assessment
permissions and memberships remain unchanged.

| Permission | Owner | Admin | Maintainer | Developer | Viewer |
| --- | :---: | :---: | :---: | :---: | :---: |
| `assessment.read` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `assessment.scan` | ✓ | ✓ | ✓ | ✓ | — |
| `assessment.schedule.manage` | ✓ | ✓ | — | — | — |
| `assessment.alert.acknowledge` | ✓ | ✓ | ✓ | ✓ | — |
| `assessment.subscription.manage` | ✓ | ✓ | — | — | — |
| `assessment.evidence.export` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `assessment.evidence.import` | ✓ | ✓ | ✓ | ✓ | — |
| `assessment.disposition.review` | ✓ | — | ✓ | — | — |

The existing roles represent distinct responsibilities. Administration of
configuration does not independently grant a release/security disposition;
the proposed disposition grant follows the publishing Maintainer role and the
Owner role. A role's rank is not a substitute for its exact permission set.

Adding these grants changes the capabilities of existing members holding those
roles in their already admitted scopes. In particular, Developer may consume
bounded scan allowance, Viewer may export permitted evidence, and Maintainer
may review dispositions. This expansion requires explicit policy approval.

## Scope, execution and compatibility constraints

- Existing non-reusable resource identities and admitted ancestor closures
  remain the authorization boundary. Registry slugs, finding IDs, digests and
  continuation handles confer no access.
- No fallback to ordinary `read`, public registry visibility, an Owner shortcut
  or a temporary permissive route substitutes for an assessment permission.
- Every public read and continuation rechecks current membership and credential
  authority. Retained list observations remain historical evidence.
- Scan admission, claims, source work, schedule advancement, result publication
  and notification effects retain their separate current-authority fences.
- Existing session and reviewed service credential expiries are preserved.
  Installing permission definitions cannot renew a token, extend a review,
  grant a service account membership or revive a revoked principal.
- The console derives availability from the same exact permissions and keeps
  unavailable operations hidden or explicitly denied. Client visibility is
  never the server's authorization check.
- Import/export and disposition permissions do not make unfinished workflows
  available. Those services require their own contract and qualification.

## Acceptance checks before enabling public use

1. Assert the exact positive and negative role/permission matrix, stable wire
   parsing, unknown permission refusal and unchanged existing permissions.
2. Qualify current-authority public service calls in Native and Worker, with
   Hybrid forwarding preserving principal, scope and operation binding.
3. Test unrelated scopes, revoked/expired credentials, membership replacement,
   registry reincarnation and permission changes during a bounded observation
   or before a queued physical effect. They must refuse without disclosure or
   new side effects.
4. Exercise the real remote CLI and browser workflows against public handlers,
   including scan completion, independent coverage, schedule/subscription
   review, alerts, notifications, replay and retained-page continuation.
5. Keep isolated SQL/transport fixture results separate from public IAM proof.
   A passing private fixture cannot authorize production service access.

Approval of this exact source policy permits implementation and tests. It does
not authorize changing a live membership, resetting a database or deploying
an incomplete service. Until approval, public assessment calls remain denied.
