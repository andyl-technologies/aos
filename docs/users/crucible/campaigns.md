# Operating lazy campaigns

Crucible campaigns retain a content-addressed exploration graph and advance it
through one local coordinator, planner, and executor. They are useful when an
ordinary bounded `search` is too short-lived: the campaign can pause, restart,
resume, accept additive operator branches, retain findings, and explain why an
attempt was admitted.

The current implementation is deliberately single-host. It does not provide
multi-host executor fanout. A campaign repository has one authoritative local
reference owner. The built-in store uses a SQLite immutable-object leaf and
durable directory refs; an explicit store deployment may use a composed graph.

The repository defines release qualification in the
[automated packaged-QEMU matrix](../../engineering/crucible/campaigns/performance-and-validation.md#release-acceptance).
Its determinism gate exercises a three-VM nginx, curl, and I/O-probe scenario under
live TCG with same-host one-, two-, and four-core profiles and bounded scheduling
and I/O jitter. It checks byte-identical artifacts and results. Separate
product gates exercise the five-VM Envoy campaign and its finding lifecycle.
The presence of a gate does not establish that a particular package revision
passed it; retain the matching result when qualifying a deployment.

## Guide pages

| Page | Contents |
| --- | --- |
| [Campaign inputs](campaigns-inputs.md) | Generating the reference fixture and compiling and validating scenario, schedule, lineage, and policy inputs. |
| [Campaign owner and host setup](campaigns-host.md) | Starting the single-host owner, attaching executors, the packaged-executor deployment file, and host resources. |
| [Operating a campaign](campaigns-operating.md) | Creating, running, pausing, inspecting, explaining, and branching a campaign, with the command summary. |
| [Campaign store maintenance](campaigns-store.md) | Inspecting, verifying, collecting, and repacking a composed store. |

## What is implemented

The checked local API currently provides:

- verified scenario, configuration, and generator import;
- named campaign creation and derivation;
- explicitly authorized, bounded enumeration of current campaign heads;
- resume, pause, stop, unseal, budget, steering, pin, and unpin mutations;
- finite, generated, and exhaustive additive branch requests;
- snapshot, graph, choice, frontier, finding, report, and comparison queries;
- proof-bearing choice, finding, and attempt explanations; and
- a bounded set of packaged deterministic planner runtimes attached to one or
  more authenticated local executor endpoints.

The daemon can either attach `--campaign-runtime` to an independently owned
`--campaign-executor-socket` or own a packaged local QEMU executor at that
socket. Packaged mode composes a fixed worker pool, repository admission,
durable assignment ledger, checkpoint store, resource owner, and loopback
listener into the campaign service lifecycle. It advertises only the concrete
materialization paths it owns: packaged startup captures and authenticates one
baked genesis for every scenario in its closed catalog, installs one fixed
replay-oracle promotion owner per semantic worker, and advertises exact restore
only after that nonempty owner set exists.
Raw `NotRun` checkpoints remain ineligible until promotion succeeds. Do not
interpret this single-host composition as multi-host readiness.

Ordinary local QEMU `run` commands use the same campaign owner for the default
to-completion path. The deployment capability is resolved in this order:

1. the global `--campaign-deployment PATH` option;
2. `CRUCIBLE_CAMPAIGN_DEPLOYMENT`; then
3. `/etc/crucible/packaged-executor.toml`, when that file exists.

The selected packaged-executor file still passes the strict ownership, mode,
cgroup, project-quota, and resource-limit checks described below. If no
capability is available, the command fails before launching QEMU and names all
three configuration methods. Standard local production-QEMU
`save` commands use the same resolution order and campaign owner for
virtual-time, marker, quiescence, and property boundaries. Standard unattended
resume and unchanged forks targeting virtual time or stopped completion also
use campaign ownership. Interactive control, quiescence/property continuations,
and divergent recipes use their explicit current session owner.

A campaign-backed virtual-time save executes the semantic attempt and then
replays that attempt once to capture and authenticate the exact reached
boundary. Its temporary physical checkpoint closure is removed before the CLI
reports success. The durable output is a version-6 savepoint handle and a
version-3 logical `LocalDagStore` closure index. Both retain the authenticated
campaign replay closure needed by standard resume, including
typed guest selections. The extra capture replay has real QEMU execution and
I/O cost, and the emitted handle does not provide native exact-resume
acceleration.

A failure artifact produced by this path records `campaign-run` as its typed
producer. Replaying that artifact resolves the deployment capability again and
re-materializes its authenticated schedule through the campaign owner. Every
campaign-owned artifact carries its authenticated replay closure; a missing
closure fails closed. Distinct current `verify`, `search`, and `fuzz` producers
retain their declared execution owner.

Campaign findings can also enter the shared daemon session lifecycle directly.
The default command restores the cheapest complete retained checkpoint as an
exclusive read-only session and opens the mediated GDB relay:

```sh
./result/bin/crucible [daemon TLS flags] \
  campaign --socket /run/crucible/campaign.sock --principal operator \
  debug CAMPAIGN --snapshot SNAPSHOT --finding FINDING --node NODE
```

Add `--writable` to request a private derivative. The daemon first admits the
same authenticated restore read-only, attaches the selected node, records an
explicit non-canonical branch through the common session primitive, verifies
that the campaign source stayed bit-identical, and only then enables mutation
and opens the GDB relay. Output names the retained checkpoint, configuration,
session reference, and exact branch identity. The derivative stays in the live
session registry after the relay disconnects, so later `debug --session
<id:epoch:seed>` commands can address it until an explicit session destroy.
The daemon also retains the exact campaign request and authenticated finding
proof in its owner-only state inventory. After daemon restart it validates that
basis and the exact checkpoint again, restores the session with a new session
reference, and exposes it through the ordinary session list. Explicit session
destroy removes the inventory entry. The campaign state lock prevents a second
daemon from recovering the same session concurrently. Restart restores the
authenticated canonical checkpoint read-only; changes made on a previous
non-canonical branch are intentionally not durable, so request a new writable
fork when needed. The branch remains
excluded from campaign replay-oracle and seed/scenario/schedule reproduction
artifacts.

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
