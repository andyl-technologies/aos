# Campaign store maintenance

This page covers inspecting, verifying, garbage-collecting, and
repacking an explicit composed campaign store. It is part of
[Operating lazy campaigns](campaigns.md).

## Inspect and collect a composed store

For an explicit `--campaign-store STORE` deployment, use that same strict
deployment file for inspection. These `store` commands operate on the supplied
graph; they do not infer the built-in SQLite store from `--campaign-state`.
`status` authenticates and describes the admitted graph
without reading object bodies. `ensure` streams one exact content ID through
authenticated EOF, and `verify` authenticates every bounded physical placement
under a stable generation:

```sh
crucible --format json store status "$STORE"
crucible --format json store ensure "$CONTENT_ID" --in "$STORE"
crucible --format json store verify "$STORE"
```

These commands do not grant campaign-ref or deletion authority. An ID appearing
in a campaign report is still subject to the operation's ordinary campaign
authorization before it is disclosed.

Garbage collection is a stopped-owner operation. Stop the campaign daemon and
packaged executor cleanly, retain the state directory and store deployment
unchanged, and place the journal outside every configured store leaf. Plan
first; inspect and preserve its exact plan identity before apply:

```sh
crucible --format json store gc \
  --state "$CAMPAIGN_STATE" \
  --policy "$CAMPAIGN_POLICY" \
  --store "$STORE" \
  --journal "$GC_JOURNAL" \
  plan

crucible --format json store gc \
  --state "$CAMPAIGN_STATE" \
  --policy "$CAMPAIGN_POLICY" \
  --store "$STORE" \
  --journal "$GC_JOURNAL" \
  apply
```

To retire the plan instead of applying it, run this alternative. Any later
collection must use a fresh journal path.

```sh
crucible --format json store gc \
  --state "$CAMPAIGN_STATE" \
  --policy "$CAMPAIGN_POLICY" \
  --store "$STORE" \
  --journal "$GC_JOURNAL" \
  cancel
```

`plan` is non-destructive and reopens only the exact same durable journal.
`cancel` durably retires a planned journal and can be repeated safely. Apply
then refuses that journal before deletion; preserve it and use a new journal
path for any later collection. After authenticating the stopped owner, cancel
opens only that journal and leaves store recovery debris and unrelated
operational state untouched. Plan and apply use existing-state, no-repair
opens for the ref, ledger, exact-pin, transfer, and physical-generation fences;
apply refuses a stale plan before deletion. An interrupted apply leaves
recovery evidence; do not remove the journal or edit its files. After a
successful apply, rerun `store verify`,
authenticate a known retained object with `store ensure`, restart the daemon,
and confirm the exact campaign head. The process-level operator regression
performs this sequence against the generated worked-network fixture and also
proves cancellation retains an authenticated orphan before a fresh plan
reclaims it while the running campaign survives restart.

Reclaim sparse physical bytes from one configured packed leaf with a separate,
durable plan file:

```sh
crucible --format json store transform packed \
  --store "$STORE" \
  --node "$PACKED_NODE" \
  --journal "$REPACK_JOURNAL" \
  plan

crucible --format json store transform packed \
  --store "$STORE" \
  --node "$PACKED_NODE" \
  --journal "$REPACK_JOURNAL" \
  apply
```

Keep the deployment and journal directory unchanged between commands. Apply rejects a
stale generation before changing pack files. Retrying the same applied plan is
idempotent, and readers that already opened an old pack remain valid through
the generation switch.

Three further maintenance subcommands exist. `store credentials refresh STORE`
reloads the current credential files and validates every bound capability.
`store cleanup incomplete-packs` takes `--state`, `--policy`, `--store`, and
an optional `--node`, and reclaims complete and staging packs absent from the
authenticated index; the state directory's owner lock must be free.
`store repair placement CONTENT_ID --in STORE --source NODE --target NODE
--state PATH --policy PATH` restores one physical placement from an
independently authenticated peer and refuses a running service. Exact options
are in the [`store` reference](reference-cli.md#store).
