# Worked example: adaptive network recovery campaign

This example follows a networking product through two disruptions. It shows
how a guest-defined response, environment faults, measurements, progressive
widening, cheap local forks, and durable replay compose into one campaign.

The syntax is illustrative. The normative contracts are the data model and
protocols in the preceding documents.

The implementation promotes this example into the realistic reference fixture
for the independent operator, destructive recovery, finding handoff, and
long-running dogfood flights in
[`14-manual-validation-and-dogfooding.md`](14-manual-validation-and-dogfooding.md).
Final acceptance uses the actual supported product build and public interfaces,
not an echo guest or scripted presentation of these expected results.

## Question under test

Suppose a routed network has converged and the product receives the fault
signal defined by RFC-0014 after a transport disruption. The product can alter
its recovery strategy in the guest. Crucible can independently alter the shape
of the disruption and later faults in the environment.

The campaign asks:

1. Which combinations recover fastest without transient blackholes or control
   plane instability?
2. Which apparently good first responses remain robust when a second fault
   arrives during or shortly after recovery?
3. Which combinations are Pareto-optimal for convergence time, packet loss,
   and control-plane work?

This is a search question, not initially a population estimate. The campaign
may later run a separate statistical confirmation policy over selected regions.

## Scenario topology and boundaries

The scenario contains three product routers, two traffic endpoints, a virtual
network fabric, and a host-side observer. It declares these semantic
boundaries:

- `network.converged`: the initial routing and forwarding invariants hold;
- `fault.transport.ready`: every participant is quiescent immediately before
  the first disruption;
- `fault.transport.signaled`: the RFC-0014 fault signal has been delivered;
- `recovery.measured`: the first recovery window has ended and measurements
  are committed;
- `fault.followup.ready`: survivors are eligible for a second disruption; and
- `campaign.complete`: terminal properties and measurements are committed.

`fault.transport.ready` and `fault.followup.ready` are fork-safe scenario
boundaries. They are not merely guest log messages: the host verifies that all
VMs, the virtual fabric, observation streams, and logical time have reached the
declared boundary.

## Selectables

### Guest response choices

When the product receives the fault signal, its guest agent publishes a group
of application choices:

```text
choice recovery.strategy: discrete {
  retain_and_probe,
  withdraw_then_relearn,
  restart_adjacency,
  recompute_all
}

choice recovery.hold_down_us: integer [0, 5_000_000] unit=us
choice recovery.retry_limit: integer [0, 12] unit=count
choice recovery.fast_reroute: boolean
```

The group has atomic selection semantics: the application receives one
validated selection envelope and acknowledges it before the selection
deadline. The recorded envelope is sufficient to replay the same response even
if the adaptive scheduler later changes its proposal policy.

The large hold-down interval is not enumerated. Its candidate generator begins
with semantic anchors such as zero, the product default, configured protocol
timers, and the upper bound. Progressive widening adds logarithmic, midpoint,
and locally refined values as evidence accumulates.

### Environment fault choices

At the same semantic decision point, the virtual network adapter exposes:

```text
choice fault.kind: discrete {
  link_down,
  packet_loss,
  latency_step,
  asymmetric_partition
}

choice fault.loss_bps: integer [0, 10_000] unit=basis_points
choice fault.latency_us: integer [0, 2_000_000] unit=us
choice fault.duration_us: integer [1_000, 30_000_000] unit=us
choice fault.affected_path: discrete {primary, backup, both}
```

Constraints remove meaningless products. For example, `loss_bps` is active for
packet-loss faults, while `latency_us` is active for latency steps. The
constraint result and schema version are part of the proposal evidence.

The second fault uses the same definitions but derives different
`ChoiceOpportunityId` values from the later parent and phase. It may also admit a
disk stall or guest memory-fault selectable if the scenario declares those
environment adapters. They enter the same path and policy; no special
cross-fault scheduler is required.

## Measurements and properties

The observer commits a measurement only when its declared start and end
boundaries have been reached. The first recovery observation includes:

```text
recovery_time_us
traffic_loss_packets
traffic_reordered_packets
route_churn_count
adjacency_resets
control_plane_cpu_us
peak_queue_depth
```

The scenario also evaluates hard properties:

- no persistent forwarding loop;
- no packet reaches a forbidden destination;
- no control-plane process crashes or deadlocks;
- the product either converges or declares a bounded terminal failure; and
- every delivered selection is acknowledged exactly once.

A property violation dominates performance objectives and immediately creates
a finding. A timeout is an explicit censored or terminal observation according
to the measurement schema; it is never silently converted to a poor numeric
score.

## Campaign policy

An illustrative campaign policy is:

```toml
schema = "crucible.campaign/v1alpha1"
scenario = "network-recovery.toml"
mode = "strict"
seed = 802750664550812378

[budget]
attempts = 100000
wall_time = "8h"
concurrency = 256

[exploration]
algorithm = "progressive-puct"
widening_coefficient = "2"
widening_exponent = "1/2"
exploration_constant = "7/5"
novelty_weight = "1/4"

[[objectives]]
name = "recovery_time_us"
direction = "minimize"

[[objectives]]
name = "traffic_loss_packets"
direction = "minimize"

[[objectives]]
name = "control_plane_cpu_us"
direction = "minimize"

[selection]
pareto_front = true
beam_width = 128

[realization]
prefer = "hot-fork"
durable_on = ["finding", "pareto-admission", "hibernate"]

[retention]
findings = "forever"
pareto = "30d"
other_exact_checkpoints = "24h"
```

Rational strings make scheduler constants independent of host floating-point
behavior. The scenario's selectable declarations and the policy's candidate
generator versions are pinned in the campaign snapshot.

## Execution narrative

### 1. Bake the common prefix

The daemon executes the scenario once through boot, configuration, traffic
warm-up, and initial convergence. At `fault.transport.ready`, it asks every QEMU
member and the fabric to prepare a fork-safe world.

If the declared device profile supports hot fork, the daemon retains an
immutable local template. If any member cannot prepare safely, it emits an
explanatory operational event and creates an exact checkpoint closure instead.
The semantic node is the same in either case.

### 2. Discover branch points and open only useful alternatives

The planner does not compute the Cartesian product of every guest and
environment value. Each selectable's candidate generator emits a small,
deterministic set of anchors. Constraints compose compatible candidates into
proposals, and the policy admits only enough proposals to fill available
capacity and its initial widening allowance.

At the pending selection boundary, each typed `ChoiceOpportunity` is paired
with the authenticated parent configuration to create a `BranchPoint`. The
campaign's requests, proposals, observations, statistics, and candidate-source
continuations for that location form its `ExpansionState`. They do not alter the
parent scenario state.

Conceptually, the frontier begins like this:

```text
fault.transport.ready @ configuration C0
└── ◇ first-disruption response/fault branch group
    ├── link_down / retain_and_probe / default timers
    ├── link_down / withdraw_then_relearn / default timers
    ├── packet_loss=100bps / retain_and_probe / default timers
    ├── latency=10ms / retain_and_probe / default timers
    └── generated continuation: more fault and response candidates
```

The final line is compact continuation state, not thousands of queued branch
records. It records exactly how to generate the next candidate when widening
or capacity asks for one.

An operator investigating a suspected timer threshold can add a bounded finite
source without replacing that continuation:

```text
crucible campaign branch network-recovery \
  --at C0 \
  --point recovery.hold_down_us \
  --values 18000,20000,22000 \
  --attempts 3
```

The legal hold-down domain still contains millions of values; only the request
has cardinality three. The three values are pulled under ordinary daemon
backpressure. If `20000` was already proposed by the adaptive generator, both
causes appear in the explanation for one semantic edge and no duplicate child
is admitted.

### 3. Realize branch attempts as private QEMU children

For each newly admitted semantic attempt, the daemon requests a child from the
prepared world. Guest RAM is initially shared as copy-on-write pages. The child receives
new sockets, rings, epochs, run directories, overlay disks, process identities,
and fabric endpoints before it becomes runnable. The parent remains frozen.

Forking a multi-router world is atomic: all child VMs and the fabric are
published, or the partial child is discarded. A child cannot see a sibling's
control messages, observation writes, or disk updates.

### 4. Apply one recorded joint selection

The child fabric applies its environment selection at the fault boundary. The
host delivers the RFC-0014 signal. The guest agent presents the application
selection to the product and records the acknowledgment. Logical time then
resumes.

The branch path now contains both kinds of decision:

```text
environment: packet_loss=500bps, duration=800ms, path=primary
guest: strategy=retain_and_probe, hold_down=20ms, retries=3, frr=true
```

There is no hidden mutable scheduler input. Exact replay reuses these values;
the target and proposal distributions remain attached as explanatory evidence.

### 5. Commit feedback and widen selectively

At `recovery.measured`, the attempt commits properties and measurements. The
policy updates visit counts, objective summaries, novelty evidence, and the
Pareto projection. In strict mode, it performs this update only at the declared
barrier and sorts facts canonically, so deliberately permuting worker
completion order produces the same next planner step.

Suppose low packet loss with short `retain_and_probe` hold-downs appears
promising but exhibits occasional route churn. The policy can:

- spend more visits on that region to distinguish noise from signal;
- widen the hold-down generator around observed breakpoints;
- retain alternatives with slower convergence but lower loss on the Pareto
  front; and
- increase priority for novel fault shapes or near-property failures.

That feedback generates new proposals from suspended source continuations. It does not
mutate prior paths or invent a node before a concrete candidate is admitted.

### 6. Continue survivors through a second fault

Branches admitted to the beam continue to `fault.followup.ready`. Each survivor
now becomes a potential template with its own continuation for second-fault
choices. The campaign graph can be wide at the first disruption and deep for a
small set of good or suspicious recoveries.

One possible fragment is:

```text
initial convergence
└── primary loss 5% + retain/probe 20ms
    ├── recovered in 85ms; follow-up backup link-down
    │   ├── stable in 42ms
    │   └── property failure: transient forwarding loop
    ├── recovered in 85ms; follow-up disk stall
    │   └── stable in 61ms
    └── continuation: more follow-up timings and severities
```

The policy may favor the property-adjacent child, the best Pareto children, or
underexplored siblings. These are explicit objective and guidance terms, not
worker-specific heuristics.

### 7. Preserve evidence before reclaiming execution state

When the forwarding-loop property fails, the daemon commits a self-contained
finding. It pins the exact path, selections, observations, protocol transcript,
provenance, and an exact checkpoint closure at the nearest useful midpoint. The
hot child may then exit without losing the debugger entry point.

Ordinary losing branches can retain only facts and a thin recipe after their
short exact-checkpoint retention window. Pareto branches remain pinned
according to policy. Content-addressed RAM and disk extents deduplicate common
state across them.

## User interaction

The operator creates and runs the campaign:

```text
crucible campaign create network-recovery.campaign.toml
crucible campaign run network-recovery --daemon
crucible campaign status network-recovery
```

A useful status view emphasizes semantic progress:

```text
Campaign: network-recovery        Mode: strict       Snapshot: 7f4d…
Attempts: 18,432 / 100,000        Running: 251       Ready: lazy
Branch points: 3,981              Continuations: 612 Findings: 4
Realizations: 37 hot templates, 29 exact closures, 3,915 recipes
Pareto front: 23 paths            Store: 48 GiB logical / 9.7 GiB physical

Top frontier reasons
  84  exploitation: low loss and recovery time
  67  novelty: asymmetric second-fault timing
  55  risk: near forwarding-loop violation
  45  widening: hold_down_us around 18–27 ms
```

The operator can inspect why a branch was proposed and compare survivors:

```text
crucible campaign frontier network-recovery --explain
crucible campaign compare network-recovery --pareto
crucible campaign graph network-recovery --around finding:loop-004
```

Branch-point inspection distinguishes the operator's finite request from the
policy generator, reports their remaining candidates independently, and shows
their shared edge for any duplicate value. The operator request is labeled an
intervention when its proposal is the attempt's execution basis: it contributes
to bug-finding and performance comparison, but a later statistical report
excludes it unless a confirmation policy explicitly models that selection
mechanism. If the policy had already admitted the attempt, the operator proposal
is only an additional cause and does not reclassify the original sample.

Steering creates a new policy snapshot. For example, an operator may add a
budget to the route-churn region or pin a suspected branch. The previous
planner steps retain the policy, planner artifact, invocation, bounded planning
view, budget, and coordinator validation under which they were accepted.

In local mode the coordinator submits each admitted attempt through
`ExecutorService`. The executor chooses a hot sibling fork when the parent is
resident and otherwise uses exact restore or thin replay. It publishes the
observation and optional exact-closure objects and returns their IDs; the
coordinator authenticates and recomputes them before advancing the campaign.
Running the fixture through direct and loopback-RPC component adapters produces
the same canonical campaign snapshots.

## Replay, hibernation, and offline transfer

To debug the loop, the operator requests the finding's midpoint:

```text
crucible campaign replay network-recovery --finding loop-004 --pause-before failure
crucible debug attach --finding loop-004
```

Crucible restores the exact closure, replays recorded selections, and verifies
the prefix before exposing mediated stepping and inspection. Debug actions form
a derived session and do not alter the canonical finding.

The same storage representation supports longer-lived operations:

```text
crucible campaign hibernate network-recovery --durability archive
crucible campaign resume network-recovery
crucible campaign export network-recovery --snapshot 7f4d… --to archive
```

Hibernation converts required hot templates into exact closures, publishes all
objects, atomically advances the snapshot, and only then releases host-local
processes. `archive` is a configured logical store or durability policy; it may
compose directory, packed local, and S3-compatible leaf drivers without
changing the command or campaign identity. Offline transfer walks the closure,
copies only missing logical objects, verifies them, and requires the complete
execution closure locally before restore. No remote worker or demand pager is
part of this RFC.

## What the result can claim

At the end of this search policy, Crucible may claim:

- the exact tested paths and their reproducible outcomes;
- the best observed and Pareto-optimal paths under the pinned measurements and
  budget;
- property violations with replayable evidence;
- deterministic planner behavior if strict-mode validation passed; and
- which declared candidates or finite domains were covered.

It may not claim exhaustive coverage of the integer products merely because
progressive widening stopped, nor estimate real-world probabilities from the
adaptive sample without a declared target model and valid estimator. A later
confirmation campaign can derive from selected checkpoints and use a fixed or
recorded probabilistic policy to make those statistical claims.

## Why the pieces form one model

This campaign has one scenario graph, one typed choice vocabulary, one record
of realized selections, one lazy frontier, and one immutable evidence history.
Cheap QEMU forks make broad local exploration practical; exact closures make
important states durable and portable; adaptive scheduling decides where the
next semantic branch is valuable; and guest measurements close the feedback
loop. None of those mechanisms substitutes for another, and none changes the
semantic path being explored.
