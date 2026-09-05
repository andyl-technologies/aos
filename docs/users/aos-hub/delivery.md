# Set up a delivery destination

A delivery destination connects a registry or cache to a client URL. The Hub
coordinates its hostname, endpoint, storage gateway, and route through one
reviewed workflow. An existing CDN attachment and storage placement are
prerequisites. The Hub does not create a provider account or provision an
arbitrary CDN attachment for you.

Open the surface's **Delivery** settings to see the destinations currently
selected for clients and start setup. Choose storage, an existing endpoint or
a hostname and provider attachment, access policy, and client audiences.
Review setup before applying it. You can leave the page and resume the saved
workflow later as the operator who reviewed it.

Preparation creates a route that can be probed. It does not replace the
currently advertised destination. Complete provider configuration, inspect
linked verification operations, and resolve the workflow's blockers. When
verification succeeds, review activation and apply that separate plan. All
selected audiences switch together.

## Ownership and shared infrastructure

The destination belongs to the same owner as its surface. Its storage and
endpoint may belong to another owner when that owner has explicitly granted
their use to the destination's scope. An organization role does not grant
administration of an instance-owned binding or endpoint. Ask the resource
owner to grant the exact dependency identified by a blocker, then resume.

Advanced resource editors remain available. They change the same resources
that the workflow uses. Changes to reviewed prerequisites, route generations,
audience selections, or verification can invalidate a plan; reload state and
review again. A setup whose immutable prerequisites have changed requires a
new setup plan.

## Use the CLI

The `aos hub delivery` commands use the same workflow as the console. This
example selects an existing endpoint generation for a cache. Replace the
scope, endpoint, and placement with identities from your Hub; the scope is
the immutable owner scope, not an organization slug.

```json
{
  "surface": { "cacheSlug": "acme/builds" },
  "ownerScopeKey": "org:0123456789abcdef0123456789abcdef",
  "existingEndpoint": {
    "endpointId": "endpoint:builds-cdn",
    "generation": "1"
  },
  "placementName": "primary",
  "clientBasePath": "/",
  "accessPolicy": { "public": true },
  "capabilities": { "servesCache": true },
  "audiences": ["nix_cache"]
}
```

`clientBasePath` is the CDN URL prefix. The placement's object prefix is
appended to it; review the complete destination URL in the setup plan.
Save the document as `delivery.json`, then review the returned effects:

```sh
aos --json hub delivery plan --intent-file delivery.json --idempotency-key setup-review-1
aos --json hub delivery apply --plan-id '<plan-id>' --confirm-hash '<hash>' --idempotency-key setup-apply-1 --yes
aos --json hub delivery list --surface cache:acme/builds
aos --json hub delivery show '<workflow-id>'
```

The response includes progress, resource identities, operation references,
blockers, and a `resourceVersion`. Resume after resolving external
prerequisites, using the current version. Reuse the same request and
idempotency key when retrying a lost response.

```sh
aos --json hub delivery resume '<workflow-id>' --if-version '<version>' --idempotency-key setup-resume-1
aos --json hub delivery activate plan '<workflow-id>' --if-version '<version>' --idempotency-key activation-review-1
aos --json hub delivery activate apply --plan-id '<activation-plan-id>' --confirm-hash '<hash>' --idempotency-key activation-apply-1 --yes
```

Use the activation plan's ID and hash for the last command. Verification is
checked again when applying; a previously successful probe cannot authorize
a different configuration or a partial audience switch.
