# Campaign inputs

This page covers building the suite, generating the worked-network
reference fixture, and compiling and validating the scenario, schedule,
lineage, and policy inputs a campaign is created from. It is part of
[Operating lazy campaigns](campaigns.md).

## Build and validate inputs

Build the complete suite from the repository root in `nix develop` or its
direnv environment:

```sh
aos-dev build package crucible
```

Generate the worked-network reference fixture into a new private
directory:

```sh
./result/bin/crucible campaign fixture worked-network \
  --output ./worked-network-fixture \
  --format json
```

The generator refuses to overwrite an existing directory. It writes owner-only
canonical scenario, schedule, lineage, policy, and dependency-ordered generator
files, then validates the emitted import manifest before returning success. The
fixture contains the reference topology (three routers and two traffic endpoints),
semantic recovery boundaries, measurement contracts, safety properties, and a
progressive-PUCT policy. Without boot-artifact options, its VM records carry no
kernel or root-image references and exercise the import/create/control-plane
path. For the five-VM AOS Envoy workload, build `.#pkg-linux` and
`.#crucible-envoy-network-guest`, then pass their kernel and immutable
`root.ext4` through `--kernel` and `--root-image`. Pass the suite's matched
QEMU and plugin through `--qemu` and `--plugin` so the generated lineage uses
their authenticated build identity and current protocol versions. This binds
all five VM roles to the actual guest image and produces new scenario, lineage,
and policy identities.
[Release acceptance](../../engineering/crucible/campaigns/performance-and-validation.md#release-acceptance)
requires separate packaged gates for this five-VM Envoy workload and for the
same-host deterministic replay profiles.

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
`CampaignImportManifest` decoder in the CLI and frozen by its tests. The
[worked network fixture](../../engineering/crucible/campaigns/worked-network-fixture.md)
page describes the topology, selectables, measurements, and policy the
generated fixture contains; it is not a substitute for
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
scenario TOML with a nonempty compact Schedule V4:

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
schedule to round-trip byte-for-byte through the current canonical Schedule V4
codec, and rejects an empty schedule or an unresolved campaign `Selection`.
Selections require repository-backed opportunity/domain authentication and are
therefore imported through the daemon rather than asserted by an offline
author. The compiler derives and independently decodes the exact configuration
artifact before atomically installing the same three-file, no-replace import
bundle. Its report includes the scenario and configuration semantic IDs,
verifier-derived artifact IDs, and decision count.

When a Schedule V4 is not already recorded, `campaign schedule compile` accepts
a strict version-two TOML decision list. It supports the four current offline-
authorable decision shapes and both preemption actions:

```toml
schema_version = 2

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
at_tick = 100000
action = "vcpu-switch"
from_vcpu = 0
to_vcpu = 1
```

An interrupt preemption instead uses `action = "interrupt-at"` with
`target_vcpu` and `irq`. `at_tick` is the exact logical picosecond tick;
retired instruction counts are diagnostic witnesses, not scheduling coordinates.
The manifest and output are each bounded to 32 MiB;
the manifest contains 1 through 65,536 decisions, each delivery order contains
1 through 65,536 events, and authored strings are bounded to 4,096 bytes without
NUL or line breaks. The compiler rejects unknown fields and variants, re-decodes
and byte-compares the canonical Schedule V4, and never replaces an existing
output. It does not author raw app-random or campaign `Selection` decisions.
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
qemu_build = "qemu-11.1.1-crucible"
scenario_schema = 3
exact_closure_schema = 5

[protocol_versions]
control = 3
shared-memory = 5
```

`exact_closure_schema` names the content-addressed production-root envelope
schema, distinct from the exact checkpoint manifest and the genesis
configuration payload format. The current packaged executor requires
root-envelope version 5, as in the example above; imported Crucible
configuration payloads are independently authenticated by `genesis_content`. A different requested root-envelope version
is rejected before the packaged executor acquires host resources. Existing
immutable lineage records are not rewritten at startup.

The lineage and policy compilers reject unknown fields, noncanonical
identities, and invalid typed values before creating output. They write new
owner-only files durably and never replace existing paths. Each report contains
the exact canonical record ID and encoded byte count. The policy compiler reads
at most 16 MiB and also rejects duplicate semantic keys, invalid exact
arithmetic, and unsupported explorer parameters. A current version-three policy
manifest has the following field shape; replace the example scenario and
artifact/generator identities with exact values derived from your verified
import closure:

```toml
schema_version = 3
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

[attempt_timeout]
virtual_time_picoseconds = 10000000000000
execution_quanta = 1000000
host_completion_watchdog_ms = 120000

[fairness]
breadth_first_percent = 10
novelty_reserve = 4

[retention]
retain_all_findings = true
survivor_limit = 32
exact_findings = true
exact_user_pins = true
```

`[attempt_timeout]` is optional. When present, it requires a positive absolute
virtual-time coordinate in picoseconds, a positive execution-quantum bound, or
both. The example sets a 10-second virtual-time deadline. Reaching a modeled bound
records an authenticated `PolicyTimeout` outcome in the campaign Observation,
subject to terminal and assertion outcome precedence. Campaign logic can
handle that result; no timer event is delivered inside the guest.

`host_completion_watchdog_ms` is an optional operational safeguard for a
stalled executor; it must accompany a modeled
bound and be a positive unsigned millisecond count. Quote a canonical decimal
value when it exceeds TOML's signed 64-bit integer range. Its expiry aborts
the attempt as a host failure, not a guest timeout or a replayable campaign
finding. The watchdog never decides a guest outcome. Version two authored
policy TOML is rejected; compile the current version-three manifest to produce
the canonical version-five policy record.

The current format supports finite statistical sampling and optional sequential
Monte Carlo stages. The ordinary policy fields remain required; statistical
policies normally use an exhaustive explorer whose cardinality covers the
declared support. The following optional fields belong to the same version-three
manifest:

```toml
schema_version = 3
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
endpoints, and exact-rational numerators and denominators. Both statistical
sections require the current authored schema version three.

`intervention_learning` defaults to `exclude`, which retains operator- and
debugger-derived observations while keeping them out of adaptive guidance and
Beam survivor ranking. Set it to `include-in-guidance` only when that feedback
is intended; the opt-in is recorded in the canonical version-five policy
identity and in planner proposal explanations. The opt-in does not make
interventions eligible for statistical estimators.

A choice `selector` may be a plain stable declaration name, which needs no
scenario file. With `--scenario`, it
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
