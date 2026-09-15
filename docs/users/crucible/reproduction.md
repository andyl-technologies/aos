# Reproduction and branching

Crucible's central operating rule is to preserve the scenario, seed, and
recorded schedule together. A seed can reproduce deterministic choices made
from that seed, but a failure artifact is the stronger handoff: it also pins the
resolved schedule and producer build identity.

## Verify repeated execution

`verify` runs independent reductions and compares their canonical logs and
fingerprint streams:

```sh
./result/bin/crucible \
  --seed 0x2a \
  verify scenario.toml \
  --runs 5
```

Add `--adversarial` to exercise the hostile host-condition matrix and `--bisect`
to identify the first divergent state if reductions disagree:

```sh
./result/bin/crucible \
  --seed 0x2a \
  verify scenario.toml \
  --runs 8 \
  --adversarial \
  --bisect
```

A divergence exits with status `1`. When producer provenance is available,
Crucible writes side artifacts for the disagreeing executions.

To compare two existing artifacts without running the scenario again:

```sh
./result/bin/crucible verify --compare run-a.crucible run-b.crucible
```

Artifact comparison uses the identities embedded in those artifacts. It does
not select or execute the locally available backend. The two producer identities
must match each other, so repeated comparisons of unchanged inputs produce
stable evidence even when the comparison host does not have that producer
backend installed.

## Failure artifacts

A non-passing `run`, `search`, or `fuzz` result normally writes a self-contained
`.crucible` artifact below `--artifact-dir`; collect-mode exploration writes one
artifact per retained finding, and `verify` writes paired side artifacts when
both divergent reductions carry producer provenance. It records:

- the resolved seed;
- engine, protocol, QEMU, atomic-patch, and plugin identity;
- canonical scenario material;
- the recorded decision schedule;
- canonical log and fingerprint evidence; and
- embedded model-reproduction material where the producer supplied it.

Streamed event summaries retained in run evidence identify the event's original
sequence, virtual-time and instruction-count coordinate, source, causal class,
and a bounded set of diagnostic attributes. Fault summaries include their kind,
tag, targets, and description; assertion summaries include their assertion id
and state. Each production VM emits an initial `Started` lifecycle observation
at the initial admitted scheduler boundary before the first assertion
evaluation, so an invalid `Always` predicate can produce an immediate violation
instead of remaining unknown. A terminal verdict at that boundary does not
advance a guest. Guest byte payloads remain redacted and are represented only by their
length. These coordinates distinguish repeated scheduler boundaries and make a
fault or violated assertion findable without exposing console or channel data.

In table mode, the failure footer prints copy-pasteable `replay` and `debug`
commands. For commands that produce one artifact, JSON/JSONL records its digest
in the final outcome but does not add the host path to the canonical log; locate
the matching `repro-*.crucible` file below `--artifact-dir`.

For repeated `verify` runs, Crucible also retains one successful reproduction
artifact for every independent reduction. The files use the
`repro-passed-reduction-<index>-<digest>.crucible` form below `--artifact-dir`.
Each `verify-run` row records that reduction's artifact digest. The final
outcome artifact digest authenticates the ordered set of retained artifacts,
so it does not correspond to one file name.
Each artifact can be replayed independently, so CI can produce an artifact
under one host scheduling profile and replay it under another while requiring
the live terminal tuple, event stream, and execution-fingerprint stream to
match exactly. Remote verification reports that artifact retention was skipped
when the daemon does not provide producer provenance.

Search and fuzz also emit a signed `.crucible-findings` ledger that can be passed
directly to `triage`. Use `--findings-out <path>` for a fixed ledger location;
otherwise it is content-addressed below `<artifact-dir>/findings`.

## Replay

Replay validates the artifact schema and requires an exact producer/consumer
build-identity match. Current production artifacts use the v3 schema; v2
artifacts are rejected instead of falling back to model-only replay. A v3 QEMU
artifact contains the compact scenario, typed schedule, pure model proof, live
replay recipe, canonical QEMU event bytes, and typed execution-fingerprint
evidence. Run, verify, and fuzz artifacts retain the full sample stream. Search
artifacts retain a declared terminal snapshot containing exactly one
sample for every VM node:

```sh
./result/bin/crucible replay .crucible/repro-failed-<digest>.crucible
```

Replay first executes the required pure `reduce(ScenarioDef, Schedule)`
preflight. It then launches fresh guest VMs through the packaged QEMU/plugin
backend, reapplies recorded branch, fault, and network inputs, executes the
recorded non-interactive startup and initial controls, and
requires the terminal tuple, event stream, and fingerprint stream to match the
producer byte-for-byte. There is no production model-only success path.
Virtual-time- and quantum-bounded runs advance through exact paused quantum
boundaries, so frontend polling latency cannot change the recorded terminal
quantum between production and replay.

Interactive failure-artifact capture is not supported yet. Crucible rejects it
instead of recording command names without the exact decision/frontier timing
needed to replay them.

Compare the artifact's canonical log with a retained log file:

```sh
./result/bin/crucible \
  replay failure.crucible \
  --check original.jsonl
```

The comparison is byte-for-byte. The file must use the canonical JSONL entry
encoding written by `--trace`, not a table rendering. The live QEMU replay and
its embedded event/fingerprint comparisons still run before this retained-log
check.

Bisect two artifacts:

```sh
./result/bin/crucible \
  replay failing.crucible \
  --bisect passing.crucible
```

Both artifacts are independently replayed through fresh QEMU sessions before
bisection compares their canonical evidence. A `--check` mismatch or bisection
divergence exits with status `1`.

With `--to <savepoint>`, Crucible completes the same live artifact replay, then
proves that the requested savepoint is a typed schedule prefix and validates its
materialization through the replay oracle. The savepoint handle or checkpoint
object must remain available in the selected store. A v3 artifact's own
terminal checkpoint hash is self-contained: Crucible reconstructs that target
from the embedded scenario, schedule, and recorded frontier when the store does
not contain a separate checkpoint object.

## Savepoints

`save` runs to a deterministic boundary, materializes a checkpoint, validates
it against the replay oracle, and exports a `.crucible-savepoint` handle.

Save at virtual time:

```sh
./result/bin/crucible \
  save scenario.toml \
  --at virtual-time \
  --max-virtual-time 20s \
  --label before-election
```

Virtual-time saves pause after each scheduler quantum and export only at the
exact requested coordinate. A backend that cannot advance virtual time or that
steps past the coordinate fails the command instead of exporting an ambiguous
handle. Zero-time boot quanta are allowed within a bounded progress window.

Other boundaries are:

```sh
--at quiescence
--at property --property <assertion-name>
--at marker --marker <guest-marker-name>
```

Session-owned quiescence, property, and marker saves continue across scheduler
quanta until a one-shot suspending breakpoint observes the requested evidence.
Campaign-backed local-QEMU saves use the corresponding authenticated semantic
stop. A property selector stops on the named assertion's violated phase. Marker
and property selectors also stop at quiescence and fail without exporting a
handle when the requested evidence never appeared. `--max-virtual-time` is
accepted only with `--at virtual-time`; combining it with another boundary is a
usage error. Live QEMU boundary observation can wait for the backend's
production completion window and is not limited by the control stream's short
acknowledgement poll.

Session-owned savepoint handles use schema `crucible.savepoint-handle.v5`. They
include a `selector` line naming the property violation or guest marker (or
`none`) and a `boundary-proof` line with the exact breakpoint or virtual-time
coordinate.
Breakpoint proofs use positional fields `breakpoint`, ID, `suspend`, frontier,
and quantum, followed by a `boundary-predicate` line containing the predicate's
content address and canonical payload. Coordinate proofs use `coordinate`,
frontier, and quantum with `boundary-predicate none`. The canonical trace
contains a matching `save_boundary_proof` entry; selector names there are
percent-encoded so spaces and punctuation cannot resemble additional fields.
This lets an agent audit which selector fired and where, instead of inferring it
from generic `set-breakpoint` acknowledgements.

Campaign-backed marker save handles also use schema
`crucible.savepoint-handle.v5`. Their campaign owner stops on an authenticated
named boundary without creating a session breakpoint, and their
`boundary-proof` uses positional fields
`campaign-marker-event`, retained event sequence, event content hash, source
node, retired icount, frontier, and quantum. The predicate line binds the
event to the selected guest marker. The reader reconstructs the canonical event,
checks its content hash, and verifies that the embedded scenario enables the
source node's white-box channel. The campaign owner authenticates actual event
observation while capturing the save; later reads verify the self-contained
event record and its scenario relationship. Current session and campaign
virtual-time or marker saves write v5 handles and retain the content-addressed
canonical campaign replay closure needed for delivery-order, random-draw,
preemption, and typed Selection schedules. The local QEMU Campaign owner
authenticates that closure before it opens attempt resources. Override
decisions fail before handle or closure storage because the portable format
does not carry their replay authority. Application-random choices are retained
as authenticated random-draw and Selection decisions. Older handle schemas are
rejected during decoding.

Campaign-backed quiescence and property saves use schema
`crucible.savepoint-handle.v6`. Their `boundary-proof` line contains
`campaign-observation`, followed by the content digest and canonical bytes of
the observation-stop proof and then the content digest and canonical bytes of
the retained raw measurement evidence. Admission checks that the two records
name the same configuration, absolute quantum, frontier, event-log prefix, and
quiescence or assertion transition. Local-QEMU resume then replays the embedded
schedule from scenario genesis, reproduces that exact observation and raw
evidence, and only then captures a transient exact descriptor. The Campaign
owner restores the descriptor into an `AfterAttempt` continuation and removes
the transient checkpoint store after the workflow completes. A caller that
rewrites both portable records coherently therefore still fails against the
independently reconstructed source attempt. There is no remote, session, direct
checkpoint, or nearest-checkpoint fallback for these portable handles.

If a selector does not fire before quiescence, Crucible creates no handle and
returns exit 3. With `--trace <path>`, it still writes the commands and state
updates observed before rejection, followed by `save_boundary_failure` and an
error `final_outcome`. This is useful for confirming that the selector and guard
were installed and driven; it is not a savepoint or reproduction artifact.
`planned_session_command` and `planned_api_call` rows describe the declared
workflow, while `interactive_ack` rows identify commands actually accepted.
Marker failures label their boundary mode `marker (quiescence-guarded)`.

Use `--out <path>` to choose the handle path. Otherwise it is written below
`--artifact-dir`. Crucible does not export a handle if replay-oracle validation
fails.

## Resume

Resume accepts an authenticated `.crucible-savepoint` handle:

```sh
./result/bin/crucible \
  resume .crucible/savepoint-before-election-<digest>.crucible-savepoint
```

The handle carries the authenticated scenario, schedule closure, frontier, and
boundary evidence. It carries no durable physical QEMU checkpoint. Resume
authenticates the complete portable closure, replays the source attempt from
scenario genesis, and compares the observed boundary with the retained proof.
After an exact match, it captures a workflow-local descriptor, restores a fresh
QEMU process, and admits the continuation through the Campaign owner.

`resume` supports the applicable `--until`, `--max-virtual-time`, and `--watch`
controls. Watch output reports Campaign and attempt status.

## Campaign branching

Use `crucible campaign branch` to add a bounded decision at an authenticated
Campaign opportunity. The command preserves the source snapshot and records a
portable Campaign-owned successor; see [Campaigns](campaigns.md).
## Artifact portability

Reproduction deliberately fails on a build-identity mismatch. Move the matching
Crucible package closure with an artifact, or rebuild the exact revision that
produced it. A newer binary is not automatically a valid replay consumer even
when its artifact schema is compatible. Initial production lifecycle
observations are part of harness engine ABI v2; artifacts carrying the earlier
engine ABI are rejected as identity mismatches rather than compared against the
new event stream.
