# Operating lazy campaigns

Crucible campaigns retain a content-addressed exploration graph and advance it
through one local coordinator, planner, and executor. They are useful when an
ordinary bounded `search` is too short-lived: the campaign can pause, restart,
resume, accept additive operator branches, retain findings, and explain why an
attempt was admitted.

The current implementation is deliberately single-host. It does not provide
multi-host executor fanout. A campaign repository has one authoritative local
reference owner, while immutable objects may use a composed local store.

## What is implemented

The checked local API currently provides:

- verified scenario, configuration, and generator import;
- named campaign creation and derivation;
- resume, pause, stop, unseal, budget, steering, pin, and unpin mutations;
- finite, generated, and exhaustive additive branch requests;
- snapshot, graph, choice, frontier, finding, and comparison queries;
- proof-bearing choice, finding, and attempt explanations; and
- one packaged deterministic planner attached to one authenticated local
  executor endpoint.

The daemon can either attach `--campaign-runtime` to an independently owned
`--campaign-executor-socket` or own a packaged local QEMU executor at that
socket. Packaged mode composes a fixed worker pool, repository admission,
durable assignment ledger, checkpoint store, resource owner, and loopback
listener into the campaign service lifecycle. It advertises only the concrete
fresh/thin-replay path; exact-resume worker selection still fails closed. Do not
interpret this single-host composition as multi-host readiness.

## Build and validate inputs

Build the complete suite first:

```sh
nix build .#pkg-crucible
```

Campaign creation uses content identities, not large artifact bodies in a
control message. Import manifests therefore list dependency-ordered canonical
scenario/configuration pairs and generator records. Validate every manifest
offline before opening repository state:

```sh
./result/bin/crucible campaign validate-import campaign-import.toml \
  --format json
```

Validation derives the exact stored identities, rejects symlinks and oversized
files, and does not contact a daemon. The manifest accepted by `serve` is the
same strict format. The currently authoritative field grammar is shown by the
`CampaignImportManifest` decoder in the CLI and frozen by its tests; RFC-0016's
[worked network campaign](../../rfcs/0016-crucible-campaigns/13-worked-network-campaign.md)
explains the modeled network policy, but its future-looking snippets are not a
substitute for `crucible campaign --help`.

## Start the single-host owner

The campaign endpoint is a managed Unix socket. Its state directory, peer
policy, component authority keys, and any initial imports must be fixed before
the socket becomes visible:

```sh
./result/bin/crucible serve \
  --listen 127.0.0.1:9443 \
  --trusted-unauthenticated-bind \
  --campaign-socket /run/user/1000/crucible/campaign.sock \
  --campaign-state ./campaign-state \
  --campaign-policy ./campaign-peers.toml \
  --campaign-component-authority ./campaign-authority.toml \
  --campaign-import-manifest ./campaign-import.toml
```

Use a private directory and the default owner-only socket mode. The listener
authenticates the kernel peer credentials and then applies the configured
principal policy. A principal string in a request is not authentication by
itself.

To attach the long-lived canonical planner/runtime, also supply an existing
campaign and authenticated executor socket:

```text
--campaign-runtime CAMPAIGN
--campaign-executor-socket PATH
```

The executor socket must already be owned with the required strict permissions
and must advertise a compatibility profile and resource ceiling that admit the
campaign lineage. Attachment fails before planner-basis publication when those
facts disagree.

To let the same daemon own that executor, add `--production-qemu` and an
owner-only packaged-executor deployment file:

```sh
./result/bin/crucible serve \
  --listen 127.0.0.1:9443 \
  --trusted-unauthenticated-bind \
  --production-qemu \
  --campaign-socket /run/user/1000/crucible/campaign.sock \
  --campaign-state ./campaign-state \
  --campaign-policy ./campaign-peers.toml \
  --campaign-component-authority ./campaign-authority.toml \
  --campaign-runtime network-recovery \
  --campaign-executor-socket /run/user/1000/crucible/executor.sock \
  --campaign-packaged-executor ./campaign-executor.toml
```

The version-1 deployment file is strict TOML, must be an exact-owner regular
file with mode `0600`, and is bounded to 64 KiB:

```toml
schema = "crucible.campaign-packaged-executor"
version = 1
cgroup_root = "/sys/fs/cgroup/crucible"
run_root = "/var/lib/crucible/attempts"
attempt_namespace = "campaign-local"
first_project_id = 10000
project_id_count = 4
child_user_id = 2000
child_group_id = 2000
maximum_tasks = 64
maximum_inodes = 4096
finish_timeout_ms = 30000
maximum_slots = 2
maximum_vcpus = 4
maximum_resident_bytes = 1073741824
maximum_disk_bytes = 2147483648
maximum_execution_quanta = 100000
maximum_checkpoint_bytes = 1073741824
worker_count = 2
host_architecture = "x86_64"
qemu_profile = "deterministic-tcg-v1"
```

The project-ID count must cover every slot, the worker count cannot exceed the
slot ceiling, and the checkpoint ceiling cannot exceed writable-disk capacity.
The configured lifecycle run root is partitioned into stable fixed-worker
subdirectories so recovery state is not shared between concurrent workers.

## Create and inspect a campaign

Creation records refer to artifacts already admitted by the verified importer.
The lineage and policy arguments are canonical binary records:

```sh
./result/bin/crucible campaign \
  --socket /run/user/1000/crucible/campaign.sock \
  --principal operator \
  create network-recovery \
  --lineage ./lineage.bin \
  --policy ./policy.bin \
  --format json
```

The response contains the immutable genesis snapshot. Save exact IDs from JSON
instead of scraping tables. Status and watch authenticate one exact head and
lifecycle projection:

```sh
./result/bin/crucible campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator status network-recovery --format json

./result/bin/crucible campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator watch network-recovery \
  --after "$SNAPSHOT" --format json
```

`watch` is advisory and coalescing: sequence gaps do not imply lost immutable
history. Use `snapshot` for an exact historical body.

## Run, pause, and resume

Every mutation against an existing campaign carries the exact expected
snapshot and an idempotent command identity. Generate a new command identity
for a new intent; retry the same bytes with the same identity after an
indeterminate transport result.

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  resume network-recovery --expected "$SNAPSHOT" --command "$COMMAND"

crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  pause network-recovery --expected "$NEXT" --command "$PAUSE_COMMAND" \
  --active drain
```

Run each command with `--help` before scripting it. Pause policies are semantic:
`drain` waits for admitted work, `retry` preserves canceled work as retryable,
and `checkpoint` requires the executor's guarded exact-checkpoint path.

## Inspect authenticated progress

All page cursors are bound to the exact immutable snapshot. A cursor from one
snapshot is invalid for another. Machine consumers should page until the
authenticated response reports EOF rather than inferring EOF from a short page.

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  frontier network-recovery --snapshot "$SNAPSHOT" --limit 256 --format jsonl

crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  findings network-recovery --snapshot "$SNAPSHOT" --limit 256 --format jsonl
```

Object bodies require their own authorization even when an ID appeared in a
graph page. Use `graph-object`, `choice-object`, or `frontier-object`; do not
read repository files directly.

## Explain a decision or finding

`explain-attempt` authenticates the attempt, its execution-basis admission,
branch selection and proposal, optional completion, and—when a planner issued
the proposal—the accepted planner step. JSON version 2 includes exact
fixed-point guidance terms and coordinator accounting:

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  explain-attempt network-recovery \
  --snapshot "$SNAPSHOT" --attempt "$ATTEMPT" --format json
```

Use `explain` for a choice/frontier legality join and `explain-finding` for the
representative observation plus original reproduction. Each operation rejects
individually valid records whose cross-object basis does not agree.

## Recovery rules

- Preserve the campaign state directory and every configured immutable leaf as
  one operational unit.
- Do not edit campaign refs, assignment ledgers, checkpoint journals, or GC
  journals by hand.
- After an ambiguous mutation, retry the identical request before issuing a new
  command identity.
- After restart, let the repository authenticate and rebuild its validation
  checkpoint before treating the endpoint as ready.
- A retained exact checkpoint remains usable only while its semantic pin and
  operational selection journal agree.

Use [Troubleshooting](troubleshooting.md) for general backend and identity
errors. For protocol or repository integrity failures, preserve the state
directory and logs; repeated retries are not a repair procedure.
