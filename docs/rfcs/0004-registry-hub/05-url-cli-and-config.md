### URL design — one URL, three audiences

```text
https://hub.example.com/
  {org}/                          org page
  {org}/{project…}/               project pages (nested)
  {org}/{project…}/{registry}/    ← THE registry URL
```

The registry URL is simultaneously:

1. **HTML** for browsers (negotiated on `Accept` / known machine
   paths): the registry home — packages, channels, trust keys,
   freshness, setup snippets.
2. **A git dumb-HTTP origin**: `…/{registry}/info/refs`, `/HEAD`,
   `/objects/…`, `/channels/…`, `/releases/…` — served by 302-redirect
   (native) or zero-egress R2 proxy (Workers), preserving the
   immutable/60-second cache-header split the upload pipeline already
   defines. So `url = "https://hub.example.com/acme/infra/prod/"` in
   `registries.d/<name>.toml` just works — signature verification,
   channel resolution, delta fetch, all of it.
3. **A Nix binary cache**: `…/{registry}/nix-cache-info`,
   `/{hash}.narinfo`, `/nar/…` — same facade. Any Nix installation can
   point a substituter at it. The backwards-compatibility requirement
   is satisfied structurally, not as a feature. One honest caveat:
   plain-Nix compatibility is unconditional only for *public*
   registries — Nix's substituter auth is netrc-based, so for private
   registries the facade also accepts HTTP basic auth with a token as
   the password (the netrc bridge); `apm`/`aos-cache` use bearer
   tokens natively.

Private registries enforce bearer-token auth on the machine paths —
which `apm` and `aos-cache` already know how to send.

### CLI convergence — the "like magic" contract

The magic is protocol reuse, not new glue:

- **`apr origin upload` and `apr cache generate --upload-url` work
  against the hub unchanged.** The hub implements the existing AOS-mode
  upload surface (`/oauth2/token`, `/query-missing`,
  `PUT /store/{hash}`, `/upload-pack` — the endpoints in
  `crates/aos-server/src/routes.rs` that
  `crates/aos-cache/src/backend/http.rs` already targets), scoped per
  registry. A maintainer's existing
  `apr release --upload-url https://hub.example.com/acme/infra/prod
  --token aos_…` pipeline needs zero new flags.
- **Publish-completion hook**: when the mutable pointers land
  (`info/refs`, `channels/**`, `nix-cache-info`), the hub indexes the
  new state inline and triggers presence validation — no S3-event
  plumbing in the managed path. Out-of-band uploads (direct to R2) are
  picked up by the scheduled indexer re-walking the surface exactly as
  an `apm` client would.
- **`apr login https://hub.example.com`** — device-code flow, token
  lands in `[registry.upload_auth]`.
- **`apr create --remote https://hub.example.com/acme/infra/prod`**
  provisions the registry via `RegistryService` and writes local
  `registries.d` config plus upload auth in one step.
- **Setup snippets everywhere**: every registry page shows the exact
  `apr add` command, the `aos.apm.registries.<name>` module stanza with
  trust keys filled in (`modules/base/apm-registries.nix`), and the
  plain-Nix `substituters` + `trusted-public-keys` lines.
- **Signing stays client-side by default.** Maintainers' Ed25519 keys
  sign locally; the hub orchestrates but is not in the TCB. Optionally,
  an org enrolls a **hosted signing key** (encrypted at rest, every use
  audited) so the hub itself can advance channels, re-sign tags, and
  apply web-edited config directly. Both modes are explicit in the UI
  ("signed by alice@ locally" vs "signed by hosted key acme-release").

### Configuration management

Half the configuration is already a git repo, so the unifying model is:
**every change is a reviewed change-set with a stable `change_id`
(ULID), a renderable diff, and a revert path** — implemented per store:

**Git-backed config** (`registry.toml`, `keys.toml`, `packages/`): the
change *is* a commit, but consumers only trust roster-signed state, so
web edits have exactly two honest paths, mapping onto the hosted-key
stance above:

1. **Default (BYO-key orgs): web edits are change requests.** The hub
   commits the edit to `refs/hub/changes/<change_id>`, signed by a
   per-instance **draft-signing key** that is *not* in the roster (and
   is deliberately named to be unconfusable with *hosted* keys — the
   draft-signing key carries no consumer trust at all; clients follow
   only signed tags/partitions, never branches). Promotion happens when
   a maintainer reviews and signs locally: `apr change merge
   <change_id>` fetches the draft, shows the diff, signs with a roster
   key, pushes. The web UI is a full authoring/review surface; roster
   keys never leave maintainers' machines.
2. **Hosted-key orgs**: the hub applies and signs directly; every use
   audited.

Commit change requests cannot carry **signed-tag operations** (channel
advances, release tags — tag objects, not commits). For those, BYO-key
orgs get **prepared operations**: the hub records the exact intent
(channel, partitions, target release) as a pending change-set, and the
maintainer executes `apr channel advance --from-hub <change_id>`, which
fetches the intent, verifies it matches what was reviewed, signs the
partition tags locally, and pushes. Same review UX, same audit trail,
signature still client-side. Direct web-button advances remain a
hosted-key-org feature.

Consequence: without hosted keys, web editing of registry config is
change-request-only — which is why a *minimal* change-request feature
(single-commit change, no threaded review) is promoted into phase 3
rather than "later".

**SQL-backed config** (orgs, projects, members, roles, tokens,
visibility, frontends, bindings): an append-only revision log —

```sql
config_changesets(change_id PK, actor, scope, status,   -- draft|applied|reverted
                  created_at, applied_at, reverted_by_change_id)
config_revisions(id PK, change_id, object_type, object_id,
                 op,                  -- create|update|delete
                 old_json, new_json,  -- full object snapshots
                 seq)
```

Rows are never updated; diffs render from the snapshots (semantic
field-level, not raw JSON). **Revert is a snapshot-targeted *forward*
change**, not a literal restore: reverting change-set C drafts a new
change-set targeting each object's `old_json`, which re-enters the same
validation/authz/review pipeline — surfacing a conflict if the object
changed since C, and respecting invariants (uniqueness, last-owner
rule). Security objects are revert-exempt by type: a token revocation
never reverts into a live credential (renders as "issue a replacement
token"); member removal reverts to a fresh *invitation*; secrets are
never carried in revision rows.

**Editing UX** — terraform-plan shaped, uniform across both stores:
form edits accumulate into a persistent, shareable **draft**
change-set; one **review** screen renders git parts as real TOML diffs
(via `GitService` against the draft branch) and SQL parts as field
diffs, with a plain-language impact summary ("3 hosts currently resolve
`stable` through this registry will lose anonymous read"); **apply** is
atomic per store (one transaction / one commit) and the diff screen
becomes the permanent revision page. Drafts/review/apply work as plain
forms + redirects — the producer console keeps the no-JS ethos, JS only
enhances. Confirmation gates beyond review: visibility flips (type the
registry name + sudo re-auth), member removal (shows minted-token
count — "also deadens 3 tokens"), token revocation (shows
`last_used_at`), key retirement (wizard-only, enforces the
overlap/`--vouched-by` sequence), channel advance (preview + floor
hard-block), deletes (type full path, soft-delete grace window, owner +
sudo).

**Cross-referencing** — one join key everywhere: hub-authored commits
embed an `AOS-Change-Id: <ulid>` trailer; audit rows carry `change_id`
plus resulting commit/tag hashes; the indexer matches trailers while
re-walking the surface and synthesizes an `external` audit entry
(actor = signing-key fingerprint, resolved to a roster identity where
possible, visually distinct: "observed on surface" vs "performed via
hub") for commits without one — the audit feed is complete over managed
*and* out-of-band changes without pretending the hub mediated the
latter.

