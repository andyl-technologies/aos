# Install package assessment

Package assessment uses the same engine, provider parsers and canonical result
contracts as local `aos maintain` execution. Hub controllers assess authenticated
published package metadata from the Hub database. Package declarations select
supported source profiles and explicit security identities. Operator configuration
selects credentials, quota domains, evidence storage and physical placement.

This implementation is a draft. Assessment IAM grants are awaiting policy review;
installing a controller does not grant authenticated callers assessment permissions.
Packages without explicit authenticated scan declarations remain unassessed.
Missing source mappings and incomplete source responses remain coverage gaps.

## Native controller

Supply an owner-private JSON file with `aos-hub serve
--assessment-config-file /etc/aos-hub/assessment.json`. The deployment ID must
match the active Hub installation. Registry partitions are exact, non-reusable
registry scope keys obtained from the Hub; display names cannot substitute for them.

```json
{
  "schema": "aos.assessment-installation/v1",
  "executor": {
    "kind": "native",
    "evidenceRoot": "/var/lib/aos-hub/assessment-evidence"
  },
  "routes": {
    "schema": "aos.assessment-source-routes/v1",
    "deploymentId": "hub-installation-1",
    "coordinatorId": "assessment-coordinator",
    "executorId": "assessment-native",
    "routes": [{
      "partition": "REPLACE_WITH_EXACT_REGISTRY_SCOPE_KEY",
      "provider": "github-tags",
      "budgetKey": "github-public",
      "expiresAt": "2027-01-01T00:00:00Z",
      "limits": {
        "responseBytes": 8388608,
        "sourceBytes": 67108864,
        "resultBytes": 262144,
        "normalizedEntries": 128,
        "requests": 1,
        "concurrency": 1,
        "connectSeconds": 10,
        "requestSeconds": 45
      }
    }]
  },
  "budgets": [{
    "key": "github-public",
    "windowSeconds": 3600,
    "allowance": 100,
    "minIntervalSeconds": 0
  }],
  "credentials": {
    "schema": "aos.assessment-source-credentials/v1",
    "grants": []
  },
  "policy": {
    "schema": "aos.assessment-policy/v1",
    "upstreamMaxAgeSeconds": 86400,
    "advisoryMaxAgeSeconds": 86400,
    "requiredAdvisorySources": [],
    "requireDependencyCoverage": true
  },
  "secretVersions": {},
  "pollSeconds": 5,
  "coordinatorConcurrency": 2,
  "sourceTtlSeconds": 3600
}
```

Routes and quota domains must be sorted and unique. Every routed quota domain
must have exactly one installed budget. Share a provider/account budget across
its routes so fan-out cannot multiply its allowance. Restarting a controller
preserves consumption; uncertain physical outcomes are never refunded.

Authenticated source routes refer to immutable credential grants. Grants constrain
provider, partition, source scope, secret binding and expiry. Native
`secretVersions` maps each selected binding to an immutable installed secret
version. Neither package metadata nor a scan request can provide credential bytes.
The grant must cover the complete issued physical invocation deadline.

## Worker and Hybrid placement

The deployment commands accept `--assessment-profile-file` containing the closed
`aos.assessment-edge-profile/v1` contract. The physical profile includes:

```json
{
  "schema": "aos.assessment-edge-profile/v1",
  "deploymentId": "hub-installation-1",
  "coordinatorId": "assessment-coordinator",
  "executorId": "assessment-worker",
  "evidenceBucket": "hub-assessment-evidence",
  "sourceTtlSeconds": 3600,
  "credentials": {
    "schema": "aos.assessment-source-credentials/v1",
    "grants": []
  }
}
```

The evidence bucket must differ from the deployment's registry surface bucket.
The generated profile installs `ASSESSMENT_EVIDENCE` and the per-reservation
`ASSESSMENT_PROVIDER_TASKS` Durable Object. Raw provider bodies remain in R2.
SQL stores compact normalized evidence, authority, quota and operation state.

Supply the dedicated work key through `--assessment-work-key-file`. Its material
must be at least 32 bytes and separate from other control keys. Initial installation
requires this key; updates preserve it when omitted. Hybrid's Native controller
must use the matching key, deployment ID and service identities. Select its
`executor` as `kind: "worker"`, with the exact paired HTTPS `origin` and absolute
private `workKeyFile`; leave Native `secretVersions` empty. Hybrid never substitutes
direct Native HTTP when the paired Worker is unavailable.

For authenticated sources, `--assessment-source-secrets-file` reads an
owner-private JSON map from selected `ASSESSMENT_` binding names to absolute
owner-private secret files. Secrets travel to Worker secret delivery on stdin
and are excluded from generated configuration. Omitted existing bindings are
preserved. Credentials outside the reviewed profile are refused.

Worker-only deployments additionally include a `worker` member in the edge
profile. Its `aos.assessment-worker-installation/v1` contract contains `routes`,
`budgets`, `credentials` and `policy` with the same shapes as the Native example.
Pairing and credential declarations must exactly match the physical profile.
This installs the shared logical controller and a separate one-minute assessment
tick. The existing fifteen-minute general maintenance tick remains independent.
Hybrid edge profiles reject this member because Native owns coordination and SQL.

## Reviewed recurring scans

The remote CLI exposes `aos hub maintain schedules` and
`aos hub maintain schedule`; the web console exposes the same reviewed schedules.
A schedule pins an exact registry scope, explicit nonempty package selectors,
profiles, freshness, limits, cadence and review expiry. Creation and replacement
use optimistic revisions. Disabling or replacing a review fences already queued
work. Each physical effect rechecks the original principal, current scan and
schedule permissions, credential state, registry incarnation and review revision.

The original authenticated credential expiry caps the schedule review. Scheduling
does not silently turn a short-lived credential into permanent execution authority.
Missed slots coalesce into one scan; deterministic jitter spreads subsequent slots.
Manual and recurring requests share the durable scan journal and result contracts.
Acknowledgements remain attention state and cannot suppress vulnerability evidence.

## Reviewed notification subscriptions

`aos hub maintain notification-destination` reads the exact registered webhook
commitment for a registry and review expiry. The webhook must be active and owned
by that registry's organization. `aos hub maintain subscription` creates, replaces
or disables a closed subscription review; `aos hub maintain subscriptions` reads
its public projection. The web console exposes these same controls. Generic
webhook wildcards do not subscribe to assessment events.

A subscription chooses explicit event kinds, issue families, all attention or
confirmed attention, and immediate delivery or a UTC digest window of 60 through
86,400 seconds. It binds the exact destination revision and digest. The effective
review expiry is capped by the original authenticated credential expiry. Replaying
an identical write preserves that original authority; replacing or disabling a
review revokes its pending and leased deliveries. A disabled or rotated destination
does not prevent an unchanged subscription from being disabled.

Native controller configuration accepts an optional `notifications` member:

```json
{
  "installation": {
    "schema": "aos.assessment-notification-installation/v1",
    "deploymentId": "hub-installation-1",
    "coordinatorId": "notification-coordinator",
    "executorId": "notification-native",
    "destinations": [{
      "destination": "REPLACE_WITH_EXACT_REVIEWED_DESTINATION_DOCUMENT",
      "budgetKey": "notification:registered-account"
    }],
    "budgets": [{
      "key": "notification:registered-account",
      "windowSeconds": 3600,
      "allowance": 100,
      "minIntervalSeconds": 1
    }]
  }
}
```

Replace the destination placeholder with the complete destination document returned
by the review command, including the exact review expiry and credential fingerprint.
Sort grants by resource scope and destination reference, and budgets by key. Each
required quota must be declared exactly once. The configured immutable signing-key
version must also be available through the Native secret-version resolver.
Installation grants no subscription permission. Current read and subscription
management authority are rechecked before every effect and receipt admission.

Bodies contain compact committed event facts. They exclude raw advisory text,
source URLs, provider credentials and acknowledgement notes. A digest freezes at
most 50 events; retries preserve those exact bytes and event identities. Every new
attempt consumes one shared notification quota unit, including uncertain attempts.
Callbacks use HTTPS with pinned public DNS, refuse redirects, and do not retain
response bodies. Destination acceptance means a 2xx HTTP response, rather than
confirmation of any downstream action.

Receivers verify `X-AOS-Signature-Version`, `X-AOS-Signing-Key-Version`,
`X-AOS-Timestamp`, `X-AOS-Delivery-ID` and `X-AOS-Signature` against the exact
canonical body. The shared `CallbackSignature::verify` implementation enforces the
HMAC domain, immutable key version and timestamp window. Receivers also deduplicate
stable delivery and original event identities. Retryable transport outcomes use
bounded backoff; attempts stop after 20 tries or seven days, or when review
revocation prevents another effect.

The edge assessment profile accepts a separate `notifications` installation:

```json
{
  "schema": "aos.assessment-worker-notification-installation/v1",
  "installation": "REPLACE_WITH_SHARED_NOTIFICATION_INSTALLATION",
  "egressGatewayUrl": "https://egress.example/v1/fetch",
  "secretBindings": [{
    "versionReference": "worker://assessment/notification/v1",
    "binding": "ASSESSMENT_NOTIFICATION_CALLBACK_V1"
  }]
}
```

Replace the installation placeholder with the same reviewed grants, budgets and
notification pairing used by the coordinator. Sort key versions, and declare
exactly the versions referenced by those grants. Source and callback bindings and
quota domains are separate. Notification coordinator/executor identities have their
own bindings and can differ from provider identities.

Both Worker and Hybrid deploy commands accept
`--assessment-notification-work-key-file` and
`--assessment-notification-secrets-file`. The latter is an owner-private JSON map
from the selected callback bindings and `HUB_EGRESS_GATEWAY_KEY` to absolute private
files. The work key must match Native's `notifications.workKeyFile` in Hybrid and
must differ from provider, ingress, storage and callback keys. A deployment checks
callback key fingerprints and independently challenges the gateway's notification
contract before delivering secrets or publishing the Worker. Updates require the
gateway key file for that check; other omitted deployed secrets are preserved.

Worker callbacks require the connect-time public-address gateway, which must support
`aos-hardened-egress-assessment-notification-v1`. There is no direct Fetch or Native
callback fallback. Hybrid uses the already configured exact Native origin for fresh
SQL confirmation; Worker-only uses the Hub database object and the same shared SQL
checks. A dispatch grant lasts at most five seconds and requires authority through
the complete physical timeout. Per-attempt durable objects pin work before any
effect. Completed replay returns the exact receipt; interrupted replay cannot
dispatch again. Uncertain retries wait until the original dispatch deadline.

Assessment permission policy remains pending, so this draft does not yet provide
authorized end-user delivery through these controls. The callback Worker fleet
suite exercises physical execution and durable replay with paired protocol fixtures;
it does not establish public service IAM admission.
