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
(`crates/hub/aos-hub-model/src/webhook.rs`). A materializer fans each event out
to active subscriptions, and native and Worker delivery loops send the durable
deliveries at least once with a bounded backoff schedule.

| Event type | Raised when |
|---|---|
| `index.completed` | A registry finishes (re)indexing. |
| `channel.advanced` | A channel's partitions move to a release. |
| `release.published` | A new release tag is indexed. |

Each delivery carries the event type in `X-AOS-Event` and
`X-AOS-Signature: sha256=<hex>`, the HMAC-SHA256 of the exact body bytes, which
subscribers verify in constant time. Subscriptions are managed through `WebhookService` with
`members.manage` on the organization, and the API never accepts or returns
signing material: a subscription names an operator-managed secret version.
