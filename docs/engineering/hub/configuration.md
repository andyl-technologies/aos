# Hub configuration changes and webhooks

A Hub manages two kinds of configuration. State that exists only in the Hub —
organizations, projects, memberships, roles, token metadata, visibility,
bindings, instance settings — lives in the SQL system of record. A registry's
signed configuration — `registry.toml`, `keys.toml`, and `packages/` — lives in
its committed git tree, which consumers trust only when a roster key signs it.
This page describes how each kind changes and how changes notify subscribers.
Topology resources (bindings, placements, routes, and the rest) use their own
plan/apply protocol, described in [control-plane.md](control-plane.md).

## SQL change-sets

Every SQL-backed identity and membership mutation is a reviewed, revertible
change-set (`crates/hub/aos-hub-service/src/config/mod.rs`), recorded in the
append-only `change_requests`, `change_request_revisions`, and `audit_log`
tables:

1. `open_draft` creates a `draft` change-set with a UUID v4 change id.
2. `stage` appends a revision: a full before and after JSON snapshot of one
   object.
3. `review` renders the staged revisions as semantic field diffs; nested
   objects render as compact JSON strings.
4. `apply` runs each revision's live mutation inside one transaction, stamps
   the change-set `applied`, and writes one audit row carrying the change id.

`revert` is a snapshot-targeted forward revert: it drafts a new change-set
whose revisions target each original revision's `old_json` (a create reverts to
a delete, a delete to a create, an update to an update back to the old
snapshot). The revert re-enters `apply`, so it is re-validated, and a revision
whose live state has diverged from the original `new_json` is reported as a
conflict rather than overwritten. Security objects are revert-exempt by type:
reverting a token produces an "issue replacement" note and never resurrects a
revoked secret, and reverting a membership deletion produces an invitation
rather than a silent re-admission.

`RegistryConfigurationService` exposes the change-set log read-only to callers
with `audit.read` on the scope.

## Git-backed change requests

A web or API edit to a registry's committed configuration cannot be applied
directly, because consumers follow only roster-signed tags and partitions. The
Hub instead commits the edit as a draft (`crates/hub/aos-hub-service/src/gitwrite.rs`):

1. It loads the tracked branch's head tree, replaces the edited blob, and
   re-hashes the tree, carrying the rest byte-for-byte.
2. It builds a commit whose parent is that head and whose message carries an
   `AOS-Change-Id: <change_id>` trailer.
3. It signs the commit with the per-instance draft-signing key as a
   `gpgsig-sha256` header. That key is deliberately absent from every roster,
   so the draft never verifies for consumers.
4. It writes the blob, tree, and commit as loose objects and the ref
   `refs/hub/changes/<change_id>` through the surface-write port. This is a
   ref, not a branch, so the indexer and consumers never follow it.
5. It records a `draft` git-backed change-set, a revision with the old and new
   file contents, and an audit row.

```text
refs/hub/changes/<change_id>   = <draft commit oid>
```

A maintainer promotes the draft with `apr change merge <change_id>`, which
fetches it, shows the diff, re-signs the same tree with a roster key, and
pushes. When the indexer later finds a verified head commit whose
`AOS-Change-Id` trailer names a known draft, it marks that change request
`applied`; a commit without a known trailer is audited as a direct publish.
`apr change list` and `apr change show` read the same drafts, and `GitService`
serves the committed history and config diffs to the console and remote `apr`.

## Webhooks

When a registry changes through a Hub-mediated path, the Hub commits a webhook
event to the topology outbox in the same transaction
(`crates/hub/aos-hub-model/src/webhook.rs`). Each event is fanned out to the
organization's active subscriptions and delivered at least once; the outbox,
leases, retry budget, and limits are specified under
[Webhook durability and delivery identity](#webhook-durability-and-delivery-identity).

| Event type | Raised when |
|---|---|
| `index.completed` | A registry finishes (re)indexing. |
| `channel.advanced` | A channel's partitions move to a release. |
| `release.published` | A new release tag is indexed. |

Each delivery carries the event type in `X-AOS-Event`, a stable
`X-AOS-Delivery-ID` that every retry repeats, and
`X-AOS-Signature: sha256=<hex>`, the HMAC-SHA256 of the exact body bytes, which
subscribers verify in constant time. Subscriptions are managed through
`WebhookService` with `members.manage` on the organization, and the API never
accepts or returns signing material: a subscription names an operator-managed
secret version.

### Webhook durability and delivery identity

Code: the event taxonomy, signing, and retry policy are in
`crates/hub/aos-hub-model/src/webhook.rs`; events are committed to the outbox
by `crates/hub/aos-hub-service/src/webhook.rs`. The event types, request
headers, and subscription management are described above; this section is the
delivery mechanism.

A topology mutation inserts its immutable `topology_event_outbox` row in the
same checked transaction as the mutation. A bounded materializer converts each
event into its audit record and one `webhook_deliveries` row per matching active
organization subscription. `(webhook_id, outbox_event_id)` is unique, so a
materializer retry cannot fan out the same event twice. Operational registry
events such as index completion also enter this outbox under a deterministic
semantic identity, so producer retries converge before subscription fanout.

Every delivery receives an immutable `delivery_id`. Queue messages contain only
that identifier; the consumer reloads the current durable row, wins a bounded
lease with a fresh fencing token (a value a commit must present, so a holder
whose lease was taken over cannot commit), and may commit an outcome only with
that token. Active duplicate consumers do no work. An expired lease is
recoverable
after a process or isolate crash. Native Hub performs a bounded periodic claim;
Worker Cron materializes a bounded event batch, enqueues the resulting stable
identifiers, and also claims a bounded due batch as a backstop. Thus Queue
redelivery and Cron overlap are safe and an unavailable Queue cannot strand a
committed delivery.

Delivery is at least once. A crash after the receiver accepts the HTTP request
but before Hub commits `delivered` can repeat the POST, so receivers deduplicate
on `X-AOS-Delivery-ID`. All retries retain that value. Non-2xx responses,
transport failures, and temporarily unavailable secret or egress providers
consume the same bounded attempt budget and exponential backoff in both
runtimes; an unsafe URL or credential-fingerprint drift is terminal. The
database caps payloads at 1 MiB, claim batches at 100 rows, leases at 300
seconds, and retained subscriptions at 100 per organization.

Webhook configuration persists only the immutable provider version reference
and required SHA-256 fingerprint. A delivery resolves that exact version on
demand, verifies the fingerprint, signs the body, drops the plaintext owner,
and only then awaits network I/O. The plaintext secret is absent from plans,
API and CLI responses, revision history, audit data, topology events, queue
messages, and logs.
