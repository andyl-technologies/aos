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
- explicitly authorized, bounded enumeration of current campaign heads;
- resume, pause, stop, unseal, budget, steering, pin, and unpin mutations;
- finite, generated, and exhaustive additive branch requests;
- snapshot, graph, choice, frontier, finding, and comparison queries;
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
`save --at virtual-time --max-virtual-time DURATION` commands use the same
resolution order and campaign owner. Marker saves, standard unattended resume,
and unchanged forks targeting virtual time or stopped completion also use
campaign ownership. Quiescence and property saves, interactive control,
quiescence/property forks, and divergent fork recipes remain on their compatible
session paths.

A campaign-backed virtual-time save executes the semantic attempt and then
replays that attempt once to capture and authenticate the exact reached
boundary. Its temporary physical checkpoint closure is removed before the CLI
reports success. The durable output is a version-5 savepoint handle and a
version-3 logical `LocalDagStore` closure index. Both retain the authenticated
campaign replay closure needed by standard resume and unchanged fork, including
typed guest selections. The extra capture replay has real QEMU execution and
I/O cost, and the emitted handle does not provide native exact-resume
acceleration.

A failure artifact produced by this path records `campaign-run` as its typed
producer. Replaying that artifact resolves the deployment capability again and
re-materializes its authenticated schedule through the campaign owner. An
older unattended `run` artifact also uses the campaign owner when it records
the standard startup/query controls, uses a non-property terminal mode without
coverage, and its schedule contains only delivery-order, RNG-draw, and
preemption decisions. This exact subset needs no separate choice records, so
replay synthesizes the canonical empty choice closure. Older `run` contracts
with session-specific controls, property or coverage semantics, overrides,
legacy application randomness, or typed selections retain session replay, as do
`verify`, `search`, and `fuzz` artifacts. An unchanged `fork` artifact carrying
an authenticated campaign closure replays through the campaign owner; legacy,
reseeded, and overridden fork artifacts keep their session replay semantics.

## Build and validate inputs

Build the complete suite first:

```sh
nix build .#pkg-crucible
```

Generate the RFC-0020 worked-network reference fixture into a new private
directory:

```sh
./result/bin/crucible campaign fixture worked-network \
  --output ./worked-network-fixture \
  --format json
```

The generator refuses to overwrite an existing directory. It writes owner-only
canonical scenario, schedule, lineage, policy, and dependency-ordered generator
files, then validates the emitted import manifest before returning success. The
fixture contains the RFC topology (three routers and two traffic endpoints),
semantic recovery boundaries, measurement contracts, safety properties, and a
progressive-PUCT policy. Its VM records deliberately carry no product kernel or
root-image references: this checked fixture exercises the complete
import/create/control-plane path, while the final §14 operator flight must use a
separately authored scenario containing the actual supported product build.

Campaign creation uses content identities, not large artifact bodies in a
control message. Import manifests therefore list dependency-ordered canonical
scenario/configuration pairs and generator records. Validate every manifest
offline before opening repository state:

```sh
./result/bin/crucible campaign validate-import \
  ./worked-network-fixture/import.toml \
  --format json
```

Validation derives the exact stored identities, rejects symlinks and oversized
files, and does not contact a daemon. The manifest accepted by `serve` is the
same strict format. The currently authoritative field grammar is shown by the
`CampaignImportManifest` decoder in the CLI and frozen by its tests; RFC-0020's
[worked network campaign](../../rfcs/0020-crucible-campaigns/13-worked-network-campaign.md)
explains the modeled network policy represented by the generated fixture; its
future-looking execution narrative is not a substitute for
`crucible campaign --help`.

Compile a full canonical Crucible scenario TOML into a new importable genesis
bundle when starting from an authored scenario rather than the reference
fixture:

```sh
./result/bin/crucible campaign scenario compile ./scenario.toml \
  --output ./scenario-bundle \
  --format json
./result/bin/crucible campaign validate-import \
  ./scenario-bundle/import.toml \
  --format json
```

The compiler accepts the same strict current scenario schema used by ordinary
Crucible runs, including topology, events, properties, measurements, and
selectable declarations. Input and each resulting import body are bounded by
the 32 MiB campaign-import limit. The output directory is installed atomically
and is never replaced. It contains `scenario.bin`, an empty genesis
`schedule.bin`, and an absolute-path `import.toml`. The report gives the exact
semantic scenario/genesis IDs and their verifier-derived scenario and
configuration artifact IDs; use those four values in the lineage manifest.

To import a recorded non-genesis configuration, pair the same canonical
scenario TOML with a nonempty compact Schedule V2:

```sh
./result/bin/crucible campaign schedule compile ./decisions.toml \
  --output ./schedule.bin \
  --format json
./result/bin/crucible campaign configuration compile ./scenario.toml \
  ./schedule.bin \
  --output ./configuration-bundle \
  --format json
./result/bin/crucible campaign validate-import \
  ./configuration-bundle/import.toml \
  --format json
```

Configuration compilation accepts at most 32 MiB for each input, requires the
schedule to round-trip byte-for-byte through the current canonical Schedule V2
codec, and rejects an empty schedule or an unresolved campaign `Selection`.
Selections require repository-backed opportunity/domain authentication and are
therefore imported through the daemon rather than asserted by an offline
author. The compiler derives and independently decodes the exact configuration
artifact before atomically installing the same three-file, no-replace import
bundle. Its report includes the scenario and configuration semantic IDs,
verifier-derived artifact IDs, and decision count.

When a Schedule V2 is not already recorded, `campaign schedule compile` accepts
a strict version-one TOML decision list. It supports the four current offline-
authorable decision shapes and both preemption actions:

```toml
schema_version = 1

[[decisions]]
kind = "delivery-order"
at_ticks = 100

[[decisions.order]]
virtual_time_ticks = 100
consumer = { node = "server", kind = "vm" }
producer = { node = "network", kind = "network" }
sequence = 7

[[decisions]]
kind = "rng-draw"
stream_domain = "crucible.network.loss"
stream_name = "client--server"
value = 42

[[decisions]]
kind = "override"
point = "scheduler.network.delivery"
choice = "drop"

[[decisions]]
kind = "preemption"
node = "server"
retired = 100000
action = "vcpu-switch"
from_vcpu = 0
to_vcpu = 1
```

An interrupt preemption instead uses `action = "interrupt-at"` with
`target_vcpu` and `irq`. The manifest and output are each bounded to 32 MiB;
the manifest contains 1 through 65,536 decisions, each delivery order contains
1 through 65,536 events, and authored strings are bounded to 4,096 bytes without
NUL or line breaks. The compiler rejects unknown fields and variants, re-decodes
and byte-compares the canonical Schedule V2, and never replaces an existing
output. It does not author legacy `AppRandom` or campaign `Selection` decisions.
Selections require authenticated opportunity/domain/origin resolution, and
runtime replay remains the final authority that an authored scheduling point is
valid for the scenario.

Author the campaign lineage and policy as strict TOML and compile both offline
before creating the campaign:

```sh
./result/bin/crucible campaign lineage compile ./lineage.toml \
  --output ./lineage.bin \
  --format json
./result/bin/crucible campaign policy compile ./policy.toml \
  --scenario ./scenario.toml \
  --output ./policy.bin \
  --format json
./result/bin/crucible campaign validate --policy ./policy.bin --format json
```

The lineage compiler reads at most 1 MiB. Its version-one format binds the
semantic scenario and genesis configuration to their exact imported artifact
IDs and fixes every execution-compatibility version:

```toml
schema_version = 1
scenario = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
scenario_content = "crucible.campaign.scenario-artifact@scenario-v1-CONTENT_HASH"
genesis = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
genesis_content = "crucible.campaign.configuration-artifact@configuration-v1-CONTENT_HASH"
crucible_version = "crucible-0.1.0"
qemu_build = "qemu-10.0-crucible"
scenario_schema = 3
exact_closure_schema = 4

[protocol_versions]
control = 2
shared-memory = 5
```

`exact_closure_schema` names the executor's exact-checkpoint format, not the
genesis configuration payload format. The current packaged executor requires
closure version 4; imported Crucible configuration payloads use version 2 and
are independently authenticated by `genesis_content`. A different requested
closure version is rejected before the packaged executor acquires host
resources. Existing immutable lineage records are not rewritten at startup.

The lineage and policy compilers reject unknown fields, noncanonical
identities, and invalid typed values before creating output. They write new
owner-only files durably and never replace existing paths. Each report contains
the exact canonical record ID and encoded byte count. The policy compiler reads
at most 16 MiB and also rejects duplicate semantic keys, invalid exact
arithmetic, and unsupported explorer parameters. A version-one policy manifest
has the following field shape; replace the example scenario and
artifact/generator identities with exact values derived from your verified
import closure:

```toml
schema_version = 1
scenario = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
campaign_seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
mode = "strict"
stop_conditions = ["scenario-complete"]
admit_scenario_defaults = false
intervention_learning = "exclude"

[explorer]
kind = "tree-search"
exploration_weight_micros = 1250000
novelty_bonus_micros = 250000
fairness_bonus_micros = 100000

[explorer.widening]
k_numerator = 2
k_denominator = 1
alpha_numerator = 1
alpha_denominator = 2
initial_children = 2
maximum_children = 64
minimum_visits_per_child = 1

[[choices]]
selector = { kind = "tags", all = ["latency", "network"] }
generator = "crucible.campaign.candidate-generator-spec@policy-v1-CONTENT_HASH"
required = true

[[objectives]]
measurement = "recovery-time"
goal = "minimize"
weight_micros = 1000000

[[guidance]]
signal = "coverage-rarity"
weight_micros = 500000

[fairness]
breadth_first_percent = 10
novelty_reserve = 4

[retention]
retain_all_findings = true
survivor_limit = 32
exact_findings = true
exact_user_pins = true
```

Version two adds finite statistical sampling and optional sequential Monte
Carlo stages. The ordinary policy fields remain required; statistical policies
normally use an exhaustive explorer whose cardinality covers the declared
support. This excerpt shows the added fields:

```toml
schema_version = 2
mode = "statistical"

[statistical_sampling]
estimand_endpoints = [0]

[[statistical_sampling.distributions]]
model = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
target = [
  { mass = 1, value = { kind = "boolean", value = false } },
  { mass = 3, value = { kind = "boolean", value = true } },
]
proposal = [
  { mass = 1, value = { kind = "boolean", value = false } },
  { mass = 1, value = { kind = "boolean", value = true } },
]

[[statistical_sampling.draws]]
coordinate = 0
opportunity = "crucible.campaign.choice-opportunity@campaign-fact-v1-CONTENT_HASH"
opportunity_semantics = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
domain = "crucible.campaign.choice-domain@campaign-fact-v1-CONTENT_HASH"
model = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
stop = "next-choice"

[sequential_monte_carlo]
particle_count = 1

[[sequential_monte_carlo.distributions]]
model = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
target = [
  { mass = 1, value = { kind = "unsigned", value = 0 } },
  { mass = 1, value = { kind = "unsigned", value = "18446744073709551615" } },
]
proposal = [
  { mass = 1, value = { kind = "unsigned", value = 0 } },
  { mass = 1, value = { kind = "unsigned", value = "18446744073709551615" } },
]

[[sequential_monte_carlo.stages]]
stage = 1
parent_stage = 0
declaration = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
domain = "234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1"
instance = "after-initial-choice"
model = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
stop = "terminal"

[sequential_monte_carlo.resampling]
algorithm = "systematic-v1"
effective_sample_size_threshold = { numerator = 1, denominator = 2 }
```

Finite draw declarations carry both the exact opportunity and domain artifact
IDs and the opportunity's semantic ID. The repository authenticates all three
against each selected proposal before admitting it to an estimate. An SMC
stage instead names semantic selectable and domain IDs plus an instance label,
because its exact opportunity is discovered from the parent particle at
runtime. Distribution model IDs are semantic hashes shared by the declaration
and its pinned target and proposal masses.

Statistical fields represented by unsigned 64-bit integers accept ordinary
TOML integers. To author a value above TOML's signed 64-bit integer ceiling,
use an unpadded quoted decimal string as shown above. This form applies to
unsigned choice values, masses, draw coordinates and parents, estimand
endpoints, and exact-rational numerators and denominators. Schema version one
rejects either statistical section.

`intervention_learning` defaults to `exclude`, which retains operator- and
debugger-derived observations while keeping them out of adaptive guidance and
Beam survivor ranking. Set it to `include-in-guidance` only when that feedback
is intended; the opt-in is recorded in the version-two policy identity and in
planner proposal explanations. The opt-in does not make interventions eligible
for statistical estimators.

A choice `selector` may remain a plain stable declaration name, which preserves
the original offline format and needs no scenario file. With `--scenario`, it
may instead be `{ kind = "selectable", id = "..." }` or a conjunction
`{ kind = "tags", all = ["...", "..."] }`. The supplied scenario must have
the exact semantic ID named by the policy. An exact ID must occur in that
scenario; a tag conjunction contains 1 through 16 unique canonical tags and
must match exactly one declaration. The compiler resolves either expression to
that declaration's stable name before constructing the existing canonical
`CampaignPolicy`, so equivalent name, ID, and tag forms produce byte-identical
policy records. Missing scenario context, absent IDs, ambiguous predicates,
duplicate tags, and scenario drift fail before output is created.

`campaign validate --policy FILE` performs the final bounded canonical policy
decode, byte-for-byte re-encode, and content-ID derivation offline. It never
opens a daemon or repository. After campaign creation, use the connected form
to authenticate the exact current owner projection:

```text
./result/bin/crucible campaign \
  --socket /run/crucible/campaign.sock \
  --principal operator \
  validate network-recovery \
  --format json
```

That form uses the same checked `GetCampaign` request as status inspection and
reports the authenticated snapshot, lineage, policy, and lifecycle state. The
explicit `--policy` flag keeps offline file validation unambiguous with campaign
names that contain slash-separated segments.

`mode` is `strict`, `streaming`, or `statistical`; objective goals are
`minimize` or `maximize`. The explorer may instead be `kind = "beam"` with
`width` and `novelty_reserve`, or `kind = "exhaustive"` with
`maximum_cardinality`. Every choice generator is an exact canonical generator
record ID and must already occur in the daemon's verified import closure.

## Start the single-host owner

The campaign endpoint is a managed Unix socket. Its state directory, peer
policy, optional component authority keys, and any initial imports must be fixed
before the socket becomes visible. This control-only setup creates a policy for
the current Unix peer and exercises creation, inspection, derivation, and
lifecycle mutations without planner or debugger component authority:

```sh
nix build .#pkg-jq -o result-jq

FLIGHT="$(mktemp -d)"
install -d -m 700 "$FLIGHT/state" "$FLIGHT/socket"
UID_NOW="$(id -u)"
GID_NOW="$(id -g)"
cat >"$FLIGHT/campaign-peers.toml" <<EOF
schema = "crucible.campaign-local-policy"
version = 1

[[bindings]]
user_id = $UID_NOW
group_id = $GID_NOW
principal = "operator"

[[grants]]
principal = "operator"
operation = "create-campaign"
campaign = "*"

[[grants]]
principal = "operator"
operation = "derive-campaign"
campaign = "*"

[[grants]]
principal = "operator"
operation = "get-campaign"
campaign = "*"

[[grants]]
principal = "operator"
operation = "get-campaign-status"
campaign = "*"

[[grants]]
principal = "operator"
operation = "get-campaign-snapshot"
campaign = "*"

[[grants]]
principal = "operator"
operation = "list-campaigns"
campaign = "*"

[[grants]]
principal = "operator"
operation = "apply-campaign-command"
campaign = "*"
EOF
chmod 600 "$FLIGHT/campaign-peers.toml"

./result/bin/crucible campaign fixture worked-network \
  --output "$FLIGHT/fixture" --format json

start_campaign_server() {
  ./result/bin/crucible serve \
    --listen 127.0.0.1:0 \
    --trusted-unauthenticated-bind \
    --campaign-socket "$FLIGHT/socket/campaign.sock" \
    --campaign-state "$FLIGHT/state" \
    --campaign-policy "$FLIGHT/campaign-peers.toml" \
    --campaign-import-manifest "$FLIGHT/fixture/import.toml" \
    >"$FLIGHT/serve.log" 2>&1 &
  SERVER_PID=$!

  READY_ATTEMPTS=100
  while ! ./result/bin/crucible campaign \
    --socket "$FLIGHT/socket/campaign.sock" \
    --principal operator list --limit 1 --pages 1 --format json \
    >/dev/null 2>&1; do
    READY_ATTEMPTS=$((READY_ATTEMPTS - 1))
    if ! kill -0 "$SERVER_PID" 2>/dev/null || [ "$READY_ATTEMPTS" -eq 0 ]; then
      kill "$SERVER_PID" 2>/dev/null || true
      wait "$SERVER_PID" 2>/dev/null || true
      cat "$FLIGHT/serve.log" >&2
      return 1
    fi
    sleep 0.1
  done
}

campaign() {
  ./result/bin/crucible campaign \
    --socket "$FLIGHT/socket/campaign.sock" \
    --principal operator "$@"
}

start_campaign_server
```

The readiness loop probes the service instead of treating socket existence as
readiness. The daemon owns stale-socket recovery; do not remove its socket by
hand. Run the daemon and the client commands from the same login context so
their kernel credentials continue to match the policy's UID/GID binding.

Continue in that shell to create a source campaign, derive an independent head,
and drive the source through start and pause. Each mutation consumes the exact
snapshot returned by the preceding accepted operation. The fixed 64-digit
command values are idempotency keys; use a new value for each new mutation:

```sh
JQ=./result-jq/bin/jq
START_COMMAND=1111111111111111111111111111111111111111111111111111111111111111
STALE_COMMAND=2222222222222222222222222222222222222222222222222222222222222222
PAUSE_COMMAND=3333333333333333333333333333333333333333333333333333333333333333
RESUME_COMMAND=4444444444444444444444444444444444444444444444444444444444444444

campaign create flight-source \
  --lineage "$FLIGHT/fixture/lineage.bin" \
  --policy "$FLIGHT/fixture/policy.bin" \
  --format json >"$FLIGHT/create.json"
SOURCE_CREATED="$($JQ -er '.snapshot' "$FLIGHT/create.json")"

campaign derive flight-source --snapshot "$SOURCE_CREATED" flight-derived \
  --format json >"$FLIGHT/derive.json"
DERIVED_SNAPSHOT="$($JQ -er '.new_snapshot' "$FLIGHT/derive.json")"
campaign snapshot flight-derived --snapshot "$DERIVED_SNAPSHOT" --format json \
  >"$FLIGHT/derived-snapshot.json"

campaign start flight-source \
  --expected "$SOURCE_CREATED" --command "$START_COMMAND" \
  --format json >"$FLIGHT/start.json"
SOURCE_RUNNING="$($JQ -er '.new_snapshot' "$FLIGHT/start.json")"

if campaign pause flight-source \
  --expected "$SOURCE_CREATED" --command "$STALE_COMMAND" \
  --format json >"$FLIGHT/stale.json" 2>"$FLIGHT/stale.err"; then
  echo "stale campaign mutation was unexpectedly accepted" >&2
  exit 1
fi
case "$(cat "$FLIGHT/stale.err")" in
  *"campaign request used stale snapshot"*) ;;
  *)
    echo "campaign mutation failed for a reason other than a stale snapshot" >&2
    cat "$FLIGHT/stale.err" >&2
    exit 1
    ;;
esac

campaign pause flight-source \
  --expected "$SOURCE_RUNNING" --command "$PAUSE_COMMAND" \
  --format json >"$FLIGHT/pause.json"
SOURCE_PAUSED="$($JQ -er '.new_snapshot' "$FLIGHT/pause.json")"
```

Stop the owner cleanly, restart it over the same state directory, and repeat
the pause request to prove idempotent recovery before resuming from the current
paused snapshot:

```sh
kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
start_campaign_server

campaign list --limit 32 --pages 1 --format json >"$FLIGHT/list-after-restart.json"
campaign status flight-source --format json >"$FLIGHT/status-after-restart.json"

campaign pause flight-source \
  --expected "$SOURCE_RUNNING" --command "$PAUSE_COMMAND" \
  --format json >"$FLIGHT/pause-replay.json"
REPLAYED_PAUSED="$($JQ -er '.new_snapshot' "$FLIGHT/pause-replay.json")"
test "$REPLAYED_PAUSED" = "$SOURCE_PAUSED"

campaign resume flight-source \
  --expected "$SOURCE_PAUSED" --command "$RESUME_COMMAND" \
  --format json >"$FLIGHT/resume.json"
SOURCE_RESUMED="$($JQ -er '.new_snapshot' "$FLIGHT/resume.json")"
campaign snapshot flight-source --snapshot "$SOURCE_RESUMED" --format json \
  >"$FLIGHT/resumed-snapshot.json"

kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
```

`create` reports `.snapshot`; `derive` and lifecycle mutations report
`.new_snapshot`. A request with a fresh command ID and an old `--expected`
snapshot is stale and must fail, while replaying the exact old command after a
restart returns its original accepted head. The readiness loop makes at most
100 service probes and prints the server log instead of waiting forever; each
probe remains subject to the client's own transport deadline.

For a fixed installation, use private state and socket directories and the
default owner-only socket mode:

```sh
./result/bin/crucible serve \
  --listen 127.0.0.1:9443 \
  --trusted-unauthenticated-bind \
  --campaign-socket /run/user/1000/crucible/campaign.sock \
  --campaign-state ./campaign-state \
  --campaign-policy ./campaign-peers.toml \
  --campaign-import-manifest ./worked-network-fixture/import.toml
```

The listener authenticates the kernel peer credentials and then applies the
configured principal policy. A principal string in a request is not
authentication by itself. The optional component-authority file is a
mode-`0600`, exact 72-byte binary record (`CRUCCA01`, one nonzero 32-byte
planner key, then one distinct nonzero 32-byte debugger key); it is not TOML.
Supply it as `--campaign-component-authority ./campaign-authority.bin` only when
attaching planner/runtime or debugger components.

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

Packaged mode may instead select the complete authenticated local catalog with
`--campaign-runtime-all`. Discovery reads one stable page and fails closed when
the catalog is empty or contains more than 256 campaigns; it never silently
truncates the startup set.

Embedded deployments may retain the service's bounded post-bind attachment
handle and supply either an already connected, authenticated executor stream or
the same exact endpoint capability used at startup. The latter authenticates
the secure parent namespace, socket owner/mode and before/after inode, and peer
credentials under a finite absolute connect deadline after reserving the
campaign and one of 256 runtime slots. The handle carries neither repository
nor component-authority access and closes with the service owner. The
authenticated local listener exposes the same bounded capability to an exact
authorized principal. Attach after bind with:

```sh
crucible campaign \
  --socket /run/user/1000/crucible/campaign.sock \
  --principal operator \
  attach CAMPAIGN \
  --executor-socket /run/user/1000/crucible/executor.sock
```

The result reports whether the request installed a runtime or exactly replayed
one, the request digest, and the current attached-runtime count. Exact replay
does not reconnect to the executor. A changed endpoint for an already attached
campaign fails as command reuse rather than replacing the live runtime.

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
  --campaign-component-authority ./campaign-authority.bin \
  --campaign-runtime-all \
  --campaign-executor-socket /run/user/1000/crucible/executor.sock \
  --campaign-packaged-executor ./campaign-executor.toml
```

All packaged-mode runtime entries name the same executor socket and share its
fixed workers and aggregate resource ceiling. The daemon sorts and
authenticates the complete campaign set before acquiring QEMU host resources.
Every campaign must have the same exact Crucible/QEMU compatibility profile.
Distinct scenario artifacts are decoded under a 128 MiB aggregate canonical-
body limit before host acquisition, receive separate native baked-genesis
entries, and route exact promotion by World/scenario identity. A later dynamic
attachment through the packaged endpoint must use a scenario already present
in that startup catalog; otherwise restart with the enlarged catalog or use a
separate pool. The durable store locality derives from `--campaign-state`, so
reordering or adding a compatible campaign does not change the pool identity.

Packaged CLI mode defaults to a scheduler rendezvous every 1,000,000 guest
instructions. This caps each RUN without reducing the terminal run ceiling,
allowing condition evaluation, checkpoint requests, and resource checks between
slices. `--qemu-rendezvous-icount N` explicitly overrides the interval; ordinary
non-packaged sessions retain their existing default. Keep the chosen execution
settings stable when replaying a campaign. A larger interval trades fewer host
handshakes for slower boundary-level control. Existing quantum budgets still
apply; this is an instruction bound, not a wall-clock response guarantee.

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

The host must provide a dedicated cgroup-v2 root with the `cpu`, `memory`, and
`pids` controllers enabled for children. CPU accounting alone is insufficient:
the kernel must expose `cpu.max` (`CONFIG_CFS_BANDWIDTH`). The storage root must
be an empty, supervisor-owned mode-`0700` directory on ext4 with active project
quotas, with the configured project-ID range reserved exclusively for this
allocator. ZFS and an ordinary temporary directory do not satisfy this
contract. The AOS kernel builds in CPU bandwidth control and project-quota
support; the operator still provisions the dedicated roots and enables the
mount's project quotas. The supervisor must also be authorized to place
processes in the cgroup and switch to the distinct non-root child credentials.

`checks.crucible.phase4.qemuHostOwnerVm` exercises this boundary in a disposable
VM, including real guarded QEMU/image-helper launch and resource cleanup,
without reconfiguring the build host. It does not certify a complete campaign
or replace the recovery and operator acceptance flights.

`checks.crucible.phase4.packagedCampaignVm` additionally runs public CLI
compilation, import, creation, and production service restart with real native
baked-genesis capture. It also grants budget, starts the initial discovery,
authenticates its immediate modeled terminal-success observation, and verifies
orderly shutdown. It does not certify guest-driven branching, checkpoint-pause
recovery, or hot-fork execution. Private QEMU debugger sockets are relative to each
guarded generation directory; the gateway resolves the actual returned path.

On service shutdown, the executor stops admission, signals cancellation, and
waits up to thirty seconds for semantic-worker cleanup. A `cleanup is pending`
error means unresolved work still owns its capacity, ledger, repository, and
executor endpoint lock; it is not a successful shutdown. Endpoint reuse remains
blocked until those workers finish. Permanent fail-closed retention needs
operator recovery, not deletion of the lock file or reuse of charged resources.
The thirty-second wait bounds worker cleanup, not arbitrary host filesystem I/O.

## Create and inspect a campaign

Creation records refer to artifacts already admitted by the verified importer.
The lineage and policy arguments are canonical binary records:

```sh
./result/bin/crucible campaign \
  --socket /run/user/1000/crucible/campaign.sock \
  --principal operator \
  create network-recovery \
  --lineage ./worked-network-fixture/lineage.bin \
  --policy ./worked-network-fixture/policy.bin \
  --start-command "$START_COMMAND" \
  --format json
```

`--start-command` is optional. When present, creation is followed by a separate
idempotent start against the exact returned genesis snapshot; the version-2
acceptance report contains both results. The two mutations are retry-safe but
not atomic, so retry the same create/start inputs if creation succeeds and the
start response is indeterminate. Save exact IDs from JSON instead of scraping
tables.

Enumerate the authenticated current heads visible to a principal with an
explicit all-campaign grant:

```sh
./result/bin/crucible campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator list --limit 32 --pages 8 --format json
```

An exact-name policy grant does not permit namespace discovery. Listing follows
stable campaign-name pages and returns the exact resume cursor when the page
budget ends before observed EOF. It admits at most 256 pages, 65,536 aggregate
entries, and 128 MiB of canonical responses. Campaign refs may change between
pages, so the result is a coalesced inventory rather than an immutable
cross-page snapshot; every returned head and lifecycle projection is still
authenticated independently.

Status and watch authenticate one exact head and lifecycle projection:

```sh
./result/bin/crucible campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator status network-recovery --format json

./result/bin/crucible campaign --socket "$CAMPAIGN_SOCKET" \
  --principal operator watch network-recovery \
  --after "$SNAPSHOT" --format json
```

`watch` is advisory and coalescing: sequence gaps do not imply lost immutable
history. Use `snapshot` for an exact historical body.

Derive a new name from one authenticated current or historical snapshot with
the source policy or an explicitly supplied compiled policy:

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  derive network-recovery --snapshot "$SNAPSHOT" network-recovery-streaming \
  --policy ./streaming-policy.bin --format json
```

The current implementation lets the supplied policy retain the source mode or
migrate `strict` to `streaming` and `streaming` to `strict`. It rejects
derivations that enter or leave statistical mode. `steer policy` on an existing
campaign name remains a same-mode operation; derive a new name to change
between strict and streaming. Broader cross-mode statistical derivation remains
open design and implementation work.

Derivation shares the exact immutable history reachable from the selected
source snapshot and leaves the source name unchanged. A streaming-to-strict
derivation reconstructs the authenticated contiguous completion prefix. Any
inherited attempts completed beyond an open lower admission ordinal remain
recorded, but strict publication waits for the hole; after it closes, ordering
advances across those already-completed ordinals. This behavior also applies
when streaming inherited a nonzero strict sequence position. Retry the exact
same source snapshot, target name, and policy after an indeterminate result.

## Run, pause, and resume

Every mutation against an existing campaign carries the exact expected
snapshot and an idempotent command identity. Generate a new command identity
for a new intent; retry the same bytes with the same identity after an
indeterminate transport result.

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  start network-recovery --expected "$SNAPSHOT" --command "$START_COMMAND"

crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  resume network-recovery --expected "$SNAPSHOT" --command "$COMMAND"

crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  pause network-recovery --expected "$NEXT" --command "$PAUSE_COMMAND" \
  --active drain
```

`start` and `resume` apply the same checked lifecycle transition. Use `start`
for the first transition from a newly created campaign and `resume` after a
pause; their reports preserve that operator intent.

With a packaged runtime attached, a Running campaign with an empty frontier
needs an attempt grant before it can discover its first choice:

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  budget network-recovery --expected "$SNAPSHOT" --command "$BUDGET_COMMAND" \
  add 1 --proposals 1
```

Read the updated head before issuing the next mutation. The coordinator records
one genesis discovery with an empty branch path and `next-choice` stop; a modeled
terminal verdict may complete it sooner. This admission survives restart and
does not repeat. A proposal-only grant does not fund discovery. Campaign-wide
grant enforcement for later planner issuance remains under verification; this
first-attempt check does not certify that broader limit.

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

To compare every PUCT candidate served across a bounded planner scan, start at
the newest accepted planner step reported by `explain-attempt`:

```sh
crucible campaign --socket "$CAMPAIGN_SOCKET" --principal operator \
  rankings network-recovery \
  --snapshot "$SNAPSHOT" --step "$PLANNER_STEP" --pages 16 \
  --branch-point "$BRANCH_POINT" --top 20 --format json
```

Each page authenticates one step under the snapshot's coordination root and
recomputes scores from its complete retained request. The report is globally
best-first across the returned pages. If `next_step` is present, repeat from
that step to continue beyond the selected page bound. The command stops at a
different policy, engine, policy artifact, or planning view instead of merging
incomparable score bases. `--branch-point` and `--source` accept exact canonical
IDs and filter only after response authentication; `--top` truncates only after
global ordering. JSON and JSONL use
`crucible.cli.campaign-rankings.v2`, echo the filter basis, and report the
number of matching candidates before truncation.

## Inspect and collect a composed store

When the daemon uses `--campaign-store STORE`, use that same strict deployment
file for inspection. `status` authenticates and describes the admitted graph
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

`plan` is non-destructive and reopens only the exact same durable journal.
`apply` reacquires the ref, ledger, exact-pin, transfer, and physical-generation
fences and refuses a stale plan before deletion. An interrupted apply leaves
recovery evidence; do not remove the journal or edit its files. After a
successful apply, rerun `store verify`, authenticate a known retained object
with `store ensure`, restart the daemon, and confirm the exact campaign head.
The process-level operator regression performs this sequence against the
generated worked-network fixture and also proves an authenticated orphan is
reclaimed while the running campaign survives restart.

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
