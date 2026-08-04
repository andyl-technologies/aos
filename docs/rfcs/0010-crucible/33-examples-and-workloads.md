# 33 — Worked examples and workload generation

This file is the **developer-experience proof** of Crucible: a set of complete,
end-to-end worked example scenarios, followed by the **workload / traffic-generation
story** for a harness whose only first-class participants are QEMU guests and I/O
sub-nodes. Where the rest of the RFC specifies *mechanisms* layer by layer, this
file shows those mechanisms *composed* into the scenarios a developer actually
writes, and answers the question a reader of 06 / 17 / 17a / 18 / 23 will ask
next: "what does a real test look like, and where does the load come from?"

Two things make this file unusual in the RFC. First, it is **mostly
illustrative**: Part A is a gallery of concrete scenarios drawn entirely from the
primitives already specified elsewhere, so its normative content is thin —
`EX`-prefixed requirements pin only the properties the examples *must* preserve
(zero guest-side authorability, reproducibility, the repro→explore loop), not new
mechanism. Second, Part B *is* normative: it fixes the workload model
(`WL`-prefixed requirements), because "where does traffic come from" is a genuine
design decision for a guest-VM-only harness, and getting it wrong (bolting on a
host-side traffic injector) would silently reintroduce nondeterminism and break
the any-guest contract.

Requirement IDs in this file use two prefixes: `EX` for the worked-example
invariants (Part A) and `WL` for the workload model (Part B). RFC-2119 keywords
carry their [`00-conventions.md`](00-conventions.md) meaning. The canonical gates
referenced — `gate:any-guest`, `gate:e2e-determinism`, `gate:replay-oracle`,
`gate:divergence-bisect`, `gate:single-vm-fingerprint`, `gate:content-address`,
`gate:scheduler-liveness` — are defined in
[`24-determinism-harness-testing.md`](24-determinism-harness-testing.md) §1.1.

Code blocks here are **illustrative sketches** per
[`00-conventions.md`](00-conventions.md) §"Code sketches in this RFC": the TOML
shows the serializable scenario form (06 §6.1), the `rust,illustrative` blocks
show the code-first builder (06 §6, 17a §17a.10), and `text` blocks show CLI
sessions and mappings. The authority is always the prose requirement; a sketch
that disagrees with one is a defect in the sketch.

Cross references: the `ScenarioDef` and its builder/serialized form are
[`06-spatial-graph.md`](06-spatial-graph.md); the trigger/condition vocabulary is
[`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md); the fault
taxonomy is [`17-fault-injection.md`](17-fault-injection.md); the assertion
vocabulary is [`18-assertions-properties.md`](18-assertions-properties.md); the
CLI is [`23-cli.md`](23-cli.md); search/fuzz/fork/save are
[`22-advanced-features.md`](22-advanced-features.md); the seeded firmware entropy
boundary is [`04-determinism-contract.md`](04-determinism-contract.md) and
[`26-packaging-aos-integration.md`](26-packaging-aos-integration.md); the optional
white-box channel is [`16-guest-host-channel.md`](16-guest-host-channel.md).

---

## Part A — Worked example scenarios

The five examples below progress from the simplest possible run (one client, one
server, no faults) to a full coverage-guided fault campaign with a reproduced,
bisected failure. Every example is authored with **zero guest-side components**:
no in-guest agent, no marker injection, no image modification, any kernel. The
guest runs an ordinary binary (an HTTP server, a client loop, a replicated
store); Crucible observes it entirely from outside via the black-box leaf
conditions of 17a (`ConsoleMatch`, `NetworkMatch`, `CoveragePoint`, `NodeState`,
`IoPattern`, `Quiescent`). Each example calls this out explicitly under **Any
kernel**.

### A.0 The example contract (normative)

- **[EX-1]** Every worked example in this file MUST be authorable and runnable
  with **zero guest-side components**: no in-guest agent, no marker emission, no
  guest image modification, and no guest kernel patch ([G-2], [G-3], [INV-5]).
  Readiness, fault triggering, property checking, and pass/fail MUST be expressed
  only with black-box observable conditions (17a §17a.2 leaves other than
  `GuestMarker`). An example MUST remain functional and deterministic with the
  white-box channel compiled out ([TRIG-2], [TRIG-31]). *Gate:* `gate:any-guest`,
  `gate:e2e-determinism`. *Spec:* §A.

- **[EX-2]** Every worked example MUST be reproducible bit-identically from its
  `(seed, ScenarioDef, Schedule)` reproduction artifact (06 §7.1): running
  `crucible run` and then `crucible replay <artifact>` (or `crucible verify
  --runs N`) MUST produce byte-identical canonical event logs and fingerprint
  streams ([G-1], [G-6], [INV-1], [INV-2]). The examples double as test fixtures
  for the determinism gates (see the `T-EX-*` checklist). *Gate:*
  `gate:e2e-determinism`, `gate:replay-oracle`. *Spec:* §A.

- **[EX-3]** The worked examples MUST be shipped as a built-in scenario corpus
  exercised by `crucible selftest` (23 §8) and the harness gates (24), so the
  developer-facing examples and the CI fixtures are the *same* artifacts — an
  example that stops reproducing is a gate failure, not stale documentation.
  *Gate:* `gate:e2e-determinism`, `gate:content-address`. *Spec:* §A.

### A.1 Happy path — client/server across a link, run to quiescence

**What it shows.** The minimum viable Crucible scenario: two VM nodes — an HTTP
server and a client that issues a fixed batch of requests — wired by one link.
Readiness is detected by an **observable** console banner; success is an
**observable** assertion that the client's request loop completed; the run ends
at **quiescence**. No faults.

**Any kernel.** The server is an unmodified HTTP daemon image; the client is an
unmodified image whose init runs a request loop (see Part B, `WL`). Crucible
never enters either guest. Readiness is the server's own startup banner on the
serial console (`ConsoleMatch`); completion is the client application's own
success result on the serial console (`ConsoleMatch`) plus `Quiescent`. This
remains valid when the application protocol is encrypted: wire observations may
diagnose connectivity, but they are not evidence that the client accepted a
response.

Serializable form (06 §6.1):

```toml
# happy-path.scn — two-node client/server, no faults, run to quiescence.
# Every condition is BLACK-BOX OBSERVABLE; nothing runs inside either guest.

[scenario]
seed = "0x000000000000002a00000000000000000000000000000000000000000000000000"

# ── World: two VM nodes + one link (06 §3) ─────────────────────────────────
[[world.node]]
id = "server"
arch = "x86_64"
kernel = "blake3:9f86d0..."          # content-addressed (06 §8); any kernel
root_image = "blake3:2c26b4..."      # unmodified HTTP-daemon image
cmdline = "console=ttyS0 quiet crucible.workload=httpd port=8080"
memory_mib = 256
icount_shift = 7
ready_point = { kind = "console_marker", marker = "listening on 0.0.0.0:8080" }

[[world.node]]
id = "client"
arch = "x86_64"
kernel = "blake3:9f86d0..."
root_image = "blake3:7d8f3a..."      # unmodified client-loop image (Part B WL-1)
# the client's request count + target are scenario params on the cmdline (WL-9)
cmdline = "console=ttyS0 quiet crucible.workload=httpget target=server:8080 count=100"
memory_mib = 256
icount_shift = 7
ready_point = { kind = "console_marker", marker = "client ready" }

[[world.link]]
endpoints = ["client", "server"]
latency = "5ms"                       # >= MIN_LINK_LATENCY ([SPAT-11])
jitter = "1ms"
loss = 0.0

# ── Plan: empty (no faults — happy path) ───────────────────────────────────
# (the Plan component is present but carries no fault entries)

# ── Properties: all observable ─────────────────────────────────────────────
[[properties.assertion]]
name = "no-crashes"
kind = "always"
predicate = { not = { node_state = { node = "client", state = "crashed" } } }

[[properties.assertion]]
name = "all-requests-succeed"
kind = "eventually"
# trigger: the client reports that its request loop started
trigger  = { once = { console_match = { node = "client", regex = "CLIENT_STARTED" } } }
# property: the client reports exactly `count` successful responses, then exits 0
property = { all_of = [
  { console_match = { node = "client", regex = "CLIENT_RESULT requests=100 successful=100 failed=0" } },
  { node_state = { node = "client", state = "exited" } },
] }
deadline = "60s"

# ── pass once the client is done and the system has settled ────────────────
[[event]]
id = "pass-on-quiescence"
trigger = { all_of = [
  { assertion_state = { name = "all-requests-succeed", state = "satisfied" } },
  { quiescent = {} },
] }
action  = { pass = {} }
```

Equivalent code-first builder (06 §6, 17a §17a.10):

```rust,illustrative
let scenario = ScenarioBuilder::new()
    .node("server", VmDef::x86_64()
        .kernel(kernel_blob).root_image(httpd_blob)
        .cmdline("console=ttyS0 quiet crucible.workload=httpd port=8080")
        .memory_mib(256).icount_shift(7)
        .ready_point(ReadyPoint::ConsoleMarker { marker: "listening on 0.0.0.0:8080".into() }))
    .node("client", VmDef::x86_64()
        .kernel(kernel_blob).root_image(client_blob)
        // workload parameters ride on the cmdline → part of the hash (WL-9)
        .cmdline("console=ttyS0 quiet crucible.workload=httpget target=server:8080 count=100")
        .memory_mib(256).icount_shift(7)
        .ready_point(ReadyPoint::ConsoleMarker { marker: "client ready".into() }))
    .link("client", "server", LinkDef::lan().latency_ms(5).jitter_ms(1).loss(0.0))
    .properties(Properties::builder()
        .always("no-crashes", Predicate::not(Condition::node_state("client", NodeLifecycle::Crashed)))
        .eventually("all-requests-succeed",
            /* trigger  */ Condition::console_match("client", regex("CLIENT_STARTED")).once(),
            /* property */ Condition::all_of([
                Condition::console_match("client",
                    regex("CLIENT_RESULT requests=100 successful=100 failed=0")),
                Condition::node_state("client", NodeLifecycle::Exited),
            ]),
            /* deadline */ secs(60)))
    .plan(EventGraph::builder()
        .event("pass-on-quiescence")
            .when(Condition::all_of([
                Condition::assertion_state("all-requests-succeed", AssertionPhase::Satisfied),
                Condition::quiescent(),
            ]))
            .action(Action::pass())
        .build()?)
    .seed(Seed::from_u64(42))
    .build()?;   // validates (06 §9), canonicalizes (06 §8), content-addresses
```

**Run + verify (determinism):**

```text
  $ crucible run happy-path.scn
  crucible: seed = 0x000...02a (pinned in scenario)
  crucible: backend = qemu (patched QEMU + plugin discovered)
  ... event log (jsonl) ...
  crucible: PASSED in 8.412s virtual time (0.7s wall), 2 nodes, 0 violations

  # prove it is deterministic: 5 independent reductions, byte-identical
  $ crucible verify happy-path.scn --runs 5 --adversarial
  crucible: 5/5 runs byte-identical (canonical log + fingerprint stream)
  crucible: DETERMINISTIC
```

**Expected outcome.** `PASSED`; `verify` reports byte-identical runs even under
the adversarial host matrix (24 §7). **Reproduce:** the scenario pins its seed,
so `crucible run happy-path.scn` is already reproducible; `crucible replay` of any
emitted artifact lands at the same state ([EX-2]).

Implementation note (T-EX-1): `crucible::example_corpus` ships the
`happy-path.scn` corpus fixture as a content-addressed `ScenarioDefForm` with two
unmodified guest images, in-guest `httpd`/`httpget` workload command-line
parameters, console-marker readiness, black-box network/lifecycle/quiescence
predicates, and no `GuestMarker` or white-box dependency. The local corpus runner
uses the checked `EventLog` condition-prefix path to append deterministic
observable events, fires the `pass-on-quiescence` graph event, captures a
reproduction artifact whose schedule carries the canonical observation script,
and `verify_example_scenario_runs` asserts independent runs have byte-identical
canonical event-log bytes and fingerprint streams. `crucible selftest` invokes
the same built-in corpus verifier.

### A.2 Partition recovery — the canonical fault scenario

**What it shows.** The signature distributed-systems test: a replicated store on
three nodes; once the cluster is **observably** healthy, inject a network
partition; **heal it via a relative timer 10s later** (10s after the partition was
*observed* to take effect, not a fixed wall instant — the thing pure-time
scheduling cannot express, 17a §17a.5); assert the cluster **eventually converges
after the heal**. This is the worked example 17a §17a.5.1 sketches, completed with
its `Properties` and three-node topology.

**Any kernel.** The store is an unmodified replicated-database image. Readiness is
each replica's "ready to accept connections" banner (`ConsoleMatch`) AND a
black-box coverage point on the cluster-join path (`CoveragePoint`, zero
instrumentation). The partition is a `Fault::Partition` over still-declared links
(17, no topology mutation). Recovery is an observed reconciliation frame on the
wire (`NetworkMatch`) plus `Quiescent`. Nothing inside any guest participates.

The full trigger graph:

```text
  ENTRYPOINT (genesis)
     │  start the three baked replicas (all declared, baked once per World)
     ▼
  event "wait-ready"  trigger = AllOf[
     ConsoleMatch(db-0, "ready to accept"),     ── observable ──┐
     ConsoleMatch(db-1, "ready to accept"),                     │ both replicas up
     ConsoleMatch(db-2, "ready to accept"),                     │  AND
     Once(CoveragePoint(db-0, "cluster_join_complete")) ]  ─────┘ join path ran
        action = Group[ InjectFault("split", Partition(db-0 | db-1,db-2)),
                        ArmTimer("heal-after", 10s) ]   ── relative timer armed
     │
     ▼  (10 virtual-s AFTER "wait-ready" actually fired — run-dependent anchor)
  event "heal"        trigger = Timer("heal-after")
        action = HealFault("split")
     │
     ▼
  event "pass"        trigger = AllOf[
     Once(NetworkMatch(db-0--db-1, "reconcile_ack")),   ── recovery observed
     Quiescent ]                                          ── system settled
        action = Pass
```

Serializable form (the event graph is the `Plan` component, 17a §17a.7):

```toml
# partition-recovery.scn — 3-node replicated store, partition + relative-timer heal.
# Every trigger is BLACK-BOX OBSERVABLE; zero guest-side components.

[scenario]
seed = "0x0000000000000063...0000"     # 99

# ── World: 3 replicas in a triangle (06 §3) ────────────────────────────────
[[world.node]]
id = "db-0"
arch = "x86_64"
kernel = "blake3:9f86d0..."
root_image = "blake3:store0..."        # unmodified replicated-store image
cmdline = "console=ttyS0 store.peers=db-1,db-2"
memory_mib = 512
icount_shift = 7
ready_point = { kind = "console_marker", marker = "ready to accept connections" }
# db-1, db-2 emitted in canonical order with .like("db-0") templates

[[world.link]]
endpoints = ["db-0", "db-1"]
latency = "5ms"
[[world.link]]
endpoints = ["db-1", "db-2"]
latency = "5ms"
[[world.link]]
endpoints = ["db-0", "db-2"]
latency = "5ms"

# ── Plan == event graph (17a §17a.7) ───────────────────────────────────────
[[event]]
id = "wait-ready"
trigger = { all_of = [
  { console_match = { node = "db-0", regex = "ready to accept connections" } },
  { console_match = { node = "db-1", regex = "ready to accept connections" } },
  { console_match = { node = "db-2", regex = "ready to accept connections" } },
  { once = { coverage_point = { node = "db-0", symbol = "cluster_join_complete" } } },
] }
action = { group = [
  { inject_fault = { tag = "split", fault = "partition",
                     a = "db-0", b = "db-1", direction = "bidirectional" } },
  { arm_timer = { name = "heal-after", after = "10s" } },
] }

[[event]]
id = "heal"
trigger = { timer = { name = "heal-after" } }    # 10 virtual-s AFTER wait-ready fired
action  = { heal_fault = { tag = "split" } }

[[event]]
id = "pass-on-converge"
trigger = { all_of = [
  { once = { network_match = { link = "db-0--db-1", predicate = "reconcile_ack" } } },
  { quiescent = {} },
] }
action  = { pass = {} }

# ── Properties: invariant during split + bounded convergence after heal ────
[[properties.assertion]]
name = "no-split-brain"
kind = "always"                        # never two leaders, even mid-partition
predicate = "at_most_one_leader"

[[properties.assertion]]
name = "converges-after-heal"
kind = "eventually"
trigger  = { assertion_state = { name = "split-active", state = "satisfied" } }
property  = { network_match = { link = "db-0--db-1", predicate = "raft_log_match" } }
deadline  = "30s"
```

**Run:**

```text
  $ crucible run partition-recovery.scn
  crucible: seed = 0x0000...063 (pinned)
  ... wait-ready fires at vt=3.140s; partition injected; heal-after armed ...
  ... heal fires at vt=13.140s (10s after wait-ready); reconcile observed ...
  crucible: PASSED in 19.270s virtual time, 3 nodes, 0 violations
```

**Expected outcome.** `PASSED`: `no-split-brain` holds throughout the partition,
and `converges-after-heal` is satisfied within 30 virtual seconds of the split.
The **relative-timer** anchor (10s after the *observed* readiness) makes the
inject→heal *phase* the same shape regardless of when readiness happens in any
given run. **Reproduce:** `crucible verify partition-recovery.scn --runs 3` is
byte-identical; a hypothetical convergence failure would print a `crucible replay`
line for the exact `(seed, scenario, schedule)` that exhibited it.

Implementation note (T-EX-2): `crucible::example_corpus` ships the
`partition-recovery.scn` corpus fixture as a three-node, three-link
content-addressed `ScenarioDefForm` with unmodified store images and no guest
component dependency. Its `wait-ready` event uses only observable console and
basic-block coverage leaves, then applies a grouped `InjectFault("split",
Isolate(db-0))` plus `ArmTimer("heal-after", 10s)` action through the
`SingleScheduler` trigger-action path, which models the `db-0 | db-1,db-2`
split under one stable heal tag. The runner appends the host-visible
`split-active` assertion-state transition only after the assertion evaluator
reports the injected split active, advances to the timer boundary for
`HealFault("split")`, and passes only after the split-active state, healed fault
state, an observed `reconcile_ack` frame, and quiescence all hold.
`no-split-brain` is represented as the black-box absence of `split_brain=true`
network evidence, while `converges-after-heal` is triggered by the
`split-active` assertion state and satisfied by `raft_log_match`; the captured
reproduction schedule replays to byte-identical canonical event-log bytes and
fingerprint streams.

### A.3 Node crash + restart — convergence after a mid-run crash

**What it shows.** Crash a node mid-run, restart it from its baked ready point,
and assert the cluster reconverges. The crash is triggered on an **observable**
condition (the leader has been observed to commit a write), and restart is the
heal of the crash fault with a `FromReadyPoint` restart policy (17 §17.4.3),
choreographed by `StartNode` — a *baked declared node*, not a topology mutation
(17a §17a.4.1).

**Any kernel.** Crash is `Fault::Crash` (the modeled VM reset, 17), restart is
the scheduler bringing the *already-declared, already-baked* node back from its
ready snapshot (05 §6); convergence is observed on the wire. No guest cooperation.

```toml
# crash-restart.scn — crash db-1 right after it commits, restart, reconverge.

[scenario]
seed = "0x0000000000000007...0000"

# World: 3 replicas (as A.2); links omitted for brevity (identical triangle)

[[event]]
id = "crash-after-commit"
# observable trigger: db-1 performed a durable WAL write (IoPattern), proving it
# was an active committing replica before we kill it.
trigger = { all_of = [
  { node_state = { node = "db-1", state = "started" } },
  { once = { io_pattern = { node = "db-1", kind = { block_write = { region = "wal" } } } } },
] }
action  = { inject_fault = { tag = "kill", fault = "crash",
                             node = "db-1", restart = "from_ready_point" } }

[[event]]
id = "restart"
# restart 5 virtual-s after the crash was injected (relative timer)
trigger = { after = { duration = "5s", of = "crash-after-commit" } }
action  = { group = [
  { heal_fault = { tag = "kill" } },          # clears the crash fault
  { start_node = { node = "db-1" } },          # re-activate the baked node (17a §17a.4.1)
] }

[[event]]
id = "pass-on-reconverge"
trigger = { all_of = [
  { node_state = { node = "db-1", state = "started" } },   # came back up
  { once = { network_match = { link = "db-0--db-1", predicate = "raft_log_match" } } },
  { quiescent = {} },
] }
action  = { pass = {} }

[[properties.assertion]]
name = "data-not-lost"
kind = "always"
predicate = "committed_writes_durable"     # the committed write survives the crash

[[properties.assertion]]
name = "reconverges"
kind = "eventually"
trigger  = { node_state = { node = "db-1", state = "crashed" } }
property  = { network_match = { link = "db-0--db-1", predicate = "raft_log_match" } }
deadline  = "40s"
```

**RestartPolicy.** The `restart = "from_ready_point"` on the crash fault (17
§17.4.3 / [FAULT-20] `FromReadyPoint`) names *where* a restarted node resumes:
its baked genesis snapshot (05 §6), so a restart is a deterministic re-`bake`
resume, not a fresh boot with new entropy. Alternatives the policy offers are
`Manual` (stay down until a `StartNode` fires, as used above for explicit
choreography) and `None` (a terminal crash). The example uses an explicit
`HealFault` + `StartNode` group to make the restart point a first-class event the
event graph can also gate further work on.

**Expected outcome.** `PASSED`: `data-not-lost` holds across the crash and
`reconverges` is satisfied within 40 virtual seconds of the crash. **Reproduce:**
deterministic; the crash icount, the 5s restart offset, and the reconvergence are
all functions of `(scenario, seed, schedule)`.

Implementation note (T-EX-3): `crucible::example_corpus` ships the
`crash-restart.scn` corpus fixture as a three-node, three-link
content-addressed `ScenarioDefForm` with unmodified store images and no guest
component dependency. Its `crash-after-commit` event uses only black-box
host-visible lifecycle and deterministic block-write observations to prove
`db-1` was a committing replica before injecting `InjectFault("kill",
Crash(db-1, FromReadyPoint))`; the replay fixture records the WAL region in the
I/O payload. The runner builds idle VM scheduler nodes and bidirectional
lookahead edges from the declared world so the crash action exercises the normal
node-crash scheduler path, removes the four directed edges incident to `db-1`,
and restores them on heal. After trigger actions enqueue crash/heal topology
effects, the runner applies those queued topology changes at the checked
boundary before evaluating `Quiescent`, so the leaf consumes real
scheduler-owned quiescence evidence rather than a synthetic default. It records
the scheduler crash/restart/topology applications produced by
`apply_trigger_firings`, then appends causal lifecycle facts from the applied
trigger actions rather than scripting crash/restart outcomes in the replay
schedule.
The `restart` event uses the `After(5s, "crash-after-commit")` trigger and a
`HealFault("kill")` + `StartNode(db-1)` action group; the resulting restart
lifecycle fact is likewise derived from the applied `StartNode` while the
scheduler restart application proves the crash fault healed with
`FromReadyPoint`. `data-not-lost` is represented as an `Always` black-box safety
assertion against `data_lost=true` evidence, while the pass event requires
positive `committed_write_survived=true` and `raft_log_match` convergence
frames. The captured reproduction schedule contains only the started/WAL-write
trigger observation, the relative restart boundary, and the convergence frame,
and replays to byte-identical canonical event-log bytes and fingerprint streams
across five independent local reductions.

### A.4 Fault campaign / exploration — a parameterized family, fuzzed with coverage

**What it shows.** Move from one scenario to a *space* of scenarios: a
`ScenarioFamily` (06 §7) parameterized over seed, fault density, and topology
size; `crucible fuzz` samples it under basic-block **coverage feedback** (22 §22.6,
zero instrumentation); a discovered failure reduces to a **self-contained
reproduction artifact**; `crucible replay` reproduces it **bit-identically**; and
`save` / `resume` / `fork` let the developer walk the neighborhood of the failure.

**Any kernel.** The family generates a `Plan` of random faults (partition / loss /
crash / latency, 17) over a generated topology, scaled by `fault_density`. Faults
perturb *modeled* behavior only (17 [FAULT-1]); coverage comes from the plugin's
TCG-exec hook (12, 22) over the unmodified binary; the only guest-observable input
is the workload (Part B). No guest-side component anywhere.

```rust,illustrative
/// A family over the partition-recovery world: same store image, generated
/// fault campaigns at a range of densities and cluster sizes (06 §7).
let family = ScenarioFamily {
    space: FamilySpace {
        seeds:         SeedSpace::DrawFromMeta { n: 10_000 },
        fault_density: 0.05..=0.50,        // faults per virtual second
        topology_size: 3..=7,              // 3..7 replicas
    },
    instantiate: Box::new(|p: &FamilyParams| {
        ScenarioBuilder::new()
            .ring_of_stores(p.topology_size, store_blob, kernel_blob)   // helper emits World
            .plan(random_fault_campaign(p.seed, p.fault_density))        // generated Plan (17)
            .properties(replicated_store_correctness())                  // reused Properties suite
            .seed(p.seed)
            .build()
    }),
};
```

```text
  # coverage-guided fuzzing over the family (23 §13, 22 §22.7)
  $ crucible fuzz --family store-family.fam --runs 10000 --coverage basic-block
  crucible: sampling family (seed-space draw + density/size), guided by BB coverage
  ... 6,213 runs, 41,902 new basic blocks, 0 violations ...
  crucible: FAILED — run #6214 violated "no-split-brain" (two leaders, vt=22.41s)
  crucible: wrote reproduction artifact ./.crucible/repro-aa31fe.crucible (5.0 KiB)
  crucible: reproduce with:
      crucible replay ./.crucible/repro-aa31fe.crucible

  # the artifact is self-contained: pinned ScenarioDef (with content-addressed
  # images), the exact seed, and the recorded Schedule (06 §7.1). No reference to
  # the family is needed (SPAT-27).
  $ crucible replay ./.crucible/repro-aa31fe.crucible --check ./.crucible/run-6214.log
  crucible: pinned QEMU build + plugin ABI match host
  crucible: replayed bit-identically; --check log byte-identical
  crucible: FAILED — "no-split-brain" violated at vt=22.41s (reproduced exactly)
```

**Walking the neighborhood with save / resume / fork:**

```text
  # save a checkpoint just before the violation, oracle-validated (23 §9, INV-2)
  $ crucible save ./.crucible/repro-aa31fe.crucible --at 22.0s --label pre-violation
  crucible: savepoint sv-7c12 materialized (fat==thin oracle PASSED), exported

  # resume from it (start ≡ resume; an ordinary session at a non-genesis config)
  $ crucible resume sv-7c12 --interactive
  crucible[paused @ vt=22.0s]> step --to 22.5s
  crucible[paused @ vt=22.5s]> query leaders
      db-0: leader(term=4)   db-3: leader(term=4)    ← the split-brain, frozen

  # fork the SAME prefix down a different schedule to test a hypothesis:
  # does delivering the delayed vote first avoid the double election?
  $ crucible fork sv-7c12 --override 'deliver_order@22.13s=db-3-vote-first' --label hyp-a
  crucible: forked child (CoW-shared with parent); appended overridden decision
  crucible: PASSED — no split-brain under the alternate delivery order
```

**Expected outcome.** Fuzzing finds a `no-split-brain` violation; the artifact
reproduces it bit-identically on any host; `save`/`resume`/`fork` let the
developer freeze the pre-failure state, inspect it, and test a fix hypothesis by
overriding one decision — all on the *one* temporal graph (22 [ADV-2]), no second
execution path. **Reproduce:** the artifact is the reproduction; `replay --check`
proves byte-identity.

### A.5 Determinism check — `verify` under adversarial host conditions, and a divergence report

**What it shows.** The determinism gate made operator-facing: `crucible verify
--runs N --adversarial` runs the same `(ScenarioDef, seed)` N times under the
hostile host-condition matrix (randomized host scheduling, wall-clock jitter,
varied core counts; 24 §7) and asserts byte-identity. If anything diverges, the
**divergence-bisection** tool (24 §5) localizes the *first* differing event and
prints a report.

**Any kernel.** `verify` is pure host-side comparison of canonical event logs and
fingerprint streams (24 §4); it requires nothing in any guest. It works on the
A.1–A.4 scenarios unchanged.

```text
  $ crucible verify partition-recovery.scn --runs 16 --adversarial --bisect
  crucible: 16 reductions under the hostile host matrix (sched jitter, core 1..16)
  crucible: 16/16 byte-identical — DETERMINISTIC
```

A divergence report (what a *bug* in a patch or the engine would produce):

```text
  $ crucible verify flaky.scn --runs 8 --adversarial --bisect
  crucible: divergence detected: runs {1,3,5,7} disagree with {2,4,6,8}
  crucible: bisecting to the first differing event...

  ── DIVERGENCE REPORT ──────────────────────────────────────────────────────
  first differing event: event-log index 4,182  (both runs identical for 0..4181)
    node:            db-1
    virtual_time:    14.802000ms-equivalent (icount 1,894,221,004)
    kind:            message_delivered
    run A (1,3,5,7): deliver_icount = 1,894,221,004   src=db-0 seq=51  len=240
    run B (2,4,6,8): deliver_icount = 1,894,221,007   src=db-0 seq=51  len=240
    Δ:               deliver_icount differs by 3 instructions

  fingerprint divergence: db-1 register/memory hash first differs at
    icount 1,894,221,004 (run A: 0x9f3c..  run B: 0x7d12..)

  likely cause class: INJECTION-DETERMINISM (Contract B) — a cross-node delivery
    icount is not a pure function of virtual time (INV-3). Suspect a host-timing
    race in the injection path, NOT intra-VM (Contract A fingerprints agree up to
    the delivery). See 04 §Contract-B, 08 §8.9.4.

  both-sides artifacts written:
    run A: ./.crucible/diverge-A-9f3c.crucible
    run B: ./.crucible/diverge-B-7d12.crucible
  ────────────────────────────────────────────────────────────────────────────
```

**Expected outcome.** For a correct system, `verify --adversarial` is always
`DETERMINISTIC` (exit 0). The report above is the *diagnostic* shape: it bisects
to the first differing event, names the node / virtual-time / icount, classifies
the likely contract that was violated (Contract A intra-VM vs Contract B
injection, 04), and writes a both-sides artifact pair so the divergence itself is
reproducible. **Reproduce:** the two artifacts replay each side; `crucible replay
--bisect A B` re-derives the report.

---

## Part B — Workload / traffic generation

Part A's examples all assume *something is generating load* — the client issues
requests, the store replicates writes. This part specifies **where that load
comes from** in a harness whose only first-class participants are QEMU guests and
I/O sub-nodes. The short answer, and the load-bearing design decision, is: **the
workload runs inside the guest**, as part of the guest program, and Crucible
shapes it through scenario parameters and the timing of faults/events — *not*
through any host-side traffic injector.

### B.1 Workloads run in-guest; there is no host-side traffic injector

In a guest-VM simulator, the only thing that can issue an HTTP request to a guest
server, or a write to a guest store, *over the modeled network*, is **another
guest**. The traffic a test exercises is produced by a guest binary doing real
work: an HTTP daemon serving, a client loop requesting, a benchmark driving a
store. Crucible observes that traffic black-box (frames crossing links, I/O at
sub-nodes, console output) and steers the run around it (faults, node start/stop,
property checks) — but it never *originates* application traffic itself.

This is a deliberate departure from a different harness model — common in
*in-process* async-Rust simulators — where the harness owns host-side **workload
generator** objects that synthesize record batches and feed them into the system
under test. That model is intentionally **not carried** into Crucible, for reasons
that are specific to a guest-VM harness:

1. **There is no in-process system under test to feed.** Crucible's "node" is a
   *guest VM*, never an in-process task standing in for a service ([NG-2]). A
   host-side generator would have to *inject* its synthetic traffic across the
   QEMU device boundary into the guest — which means inventing a host→guest data
   path that is exactly the kind of out-of-band poke at the guest that [G-2] /
   [INV-5] forbid (it would require the guest to cooperate to receive it, or a
   bespoke injection device that is itself a new nondeterminism surface).
2. **It would re-introduce host nondeterminism.** A host-side generator that
   computes "how many records since the last tick" from a host clock, or draws
   payloads from a host RNG (as the rejected model does), feeds host wall-clock
   and host entropy into the run — precisely the nondeterminism the whole system
   eliminates ([INV-1], [INV-9]). Even seeded, its *timing* would be a function of
   when the host loop happened to call it, not of virtual time.
3. **In-guest load is already deterministic for free.** A workload that runs
   inside the guest is just more guest instructions; it is already covered by
   intra-VM hermeticity (Contract A, 04) and the seeded firmware entropy boundary
   (B.2). Putting the load *inside* the determinism boundary makes it
   reproducible with no new machinery; putting it *outside* creates a new
   boundary to seal.

- **[WL-1]** Application workloads (the traffic and I/O a scenario exercises) MUST
  run **in-guest**: produced by a guest binary doing real work (server, client
  loop, benchmark), observed black-box by Crucible. Crucible MUST NOT originate
  application traffic to a guest, and MUST NOT provide a host-side traffic
  injector that synthesizes and feeds application records into a guest across the
  device boundary. The "node" that produces load MUST be a guest VM, never a
  host-side generator object or an in-process stand-in ([NG-2]). *Gate:*
  `gate:any-guest`, `gate:e2e-determinism`. *Spec:* §B.1.

- **[WL-2]** A workload MUST NOT require modifying the guest image or adding an
  in-guest agent beyond the ordinary guest program the scenario already runs: a
  stock server image and a stock client image (each running its normal binary)
  MUST suffice to author a complete load-bearing scenario ([G-2], [G-3]). Any
  in-guest workload runner is *part of the guest program under test*, selected by
  scenario parameters (B.4), not content Crucible injects for its own operation
  ([INV-5]). *Gate:* `gate:any-guest`. *Spec:* §B.1, §B.4.

- **[WL-3]** Crucible's role in a workload MUST be limited to **observation and
  steering**: observing the traffic (frames, I/O, console — 17a leaves) and
  steering the run *around* it (faults 17, node start/stop 17a §17a.4.1, property
  checks 18). The engine MUST NOT inject, rate-limit at the application layer, or
  otherwise originate application-level records; application-layer load is the
  guest's job and link-level perturbation (bandwidth/latency/loss faults, 17) is
  the only layer at which Crucible shapes traffic. *Gate:* `gate:e2e-determinism`.
  *Spec:* §B.1, §B.3.

Implementation note (T-WL-1): the engine exposes a closed `GuestWorkloadBinary`
model for `httpd`, the client request loop (`httpget`), and benchmark (`bench`)
guest binaries, and encodes the selected binary only as the hashed
`crucible.workload=...` scenario parameter on the guest command line. The
`checks.crucible.phase4.workloadModel` gate also lints that no
application-traffic origination path exists in the engine: Crucible's workload
role is observation and steering only.

### B.2 Deterministic seeding of in-guest load rides the entropy boundary

An in-guest workload that draws on randomness — random request targets, random
payloads, a randomized think-time loop — must be reproducible. It is, **for free**,
because of the seeded firmware entropy boundary already specified for everything
else (04, 26): the scenario's `Seed` flows deterministically into the guest's
entropy source (seeded virtio-rng / firmware RNG state at boot), so a guest RNG
draw is a pure function of `(ScenarioDef, Seed, Schedule)` — *without any guest
change*. A guest that reads `/dev/urandom`, `RDRAND`, or a seeded PRNG initialized
from the kernel entropy pool gets a reproducible stream because the *entropy it
draws from* is reproducible.

The critical rule: **in-guest workload determinism rides on the same entropy
boundary as everything else.** A workload MUST NOT open a *new* nondeterminism
source (a second RNG seeded from host time, a network-derived nonce that is not
itself deterministic, a guest-side wall-clock read that escapes virtual time). If
it draws entropy, it draws it through the boundary the run already seals; then it
is automatically reproducible and contributes nothing new to seal.

For the rare guest that wants an **explicit** workload seed (so two scenarios that
differ only in load pattern can be authored without changing the global `Seed`),
the OPTIONAL white-box channel (16) MAY deliver one — but this is never required:
the cmdline/config parameterization of B.4 already lets the scenario pass a
workload seed as plain configuration, content-addressed into the scenario hash,
with no white-box dependency.

- **[WL-4]** An in-guest workload that draws on guest randomness MUST be
  reproducible via the **seeded firmware entropy boundary** (04, 26): the
  scenario's `Seed` MUST flow deterministically into the guest's entropy source at
  boot, so a guest RNG draw is a pure function of `(ScenarioDef, Seed, Schedule)`
  with **zero guest modification**. A reproducible in-guest workload MUST require
  no guest change beyond running its ordinary binary ([G-2]). *Gate:*
  `gate:any-guest`, `gate:single-vm-fingerprint`. *Spec:* §B.2; cross-ref 04, 26.

- **[WL-5]** In-guest workload determinism MUST ride on the **same** entropy
  boundary as the rest of the run: a workload MUST NOT introduce any new
  nondeterminism source — no RNG seeded from host wall-clock, no host-entropy
  draw, no virtual-time-escaping host-clock read. Any randomness a workload
  consumes MUST come through the seeded boundary the run already seals ([INV-1],
  [INV-10]); a workload that would open a new entropy source is a determinism
  defect that MUST fail loudly, not be smoothed over. *Gate:* `gate:e2e-determinism`,
  `gate:divergence-bisect`. *Spec:* §B.2; routes [INV-1], [INV-10].

- **[WL-6]** A guest that wants an **explicit** workload seed (independent of the
  global `Seed`) MUST be able to receive one as plain scenario configuration
  (cmdline / config file, B.4), content-addressed into the scenario hash, with no
  white-box dependency. The OPTIONAL white-box channel (16) MAY additionally
  deliver a workload seed for guests that opt in, but an explicit workload seed
  MUST NOT be *required* and MUST NOT be the only delivery path — the black-box
  configuration path MUST always suffice ([G-3], [TRIG-3]). *Gate:* `gate:any-guest`.
  *Spec:* §B.2, §B.4.

Implementation note (T-WL-2): the workload entropy-boundary proof composes the
closed `GuestWorkloadBinary` selector with the QEMU deterministic launch profile.
The `checks.crucible.phase4.workloadEntropyBoundary` gate asserts that guest
RNG-backed workload bytes reproduce from the scenario-derived `fw_cfg` seed and
seeded `virtio-rng` device, consumes the phase-1 booted guest's selected
`crucible-httpget-workload` `WORKLOAD_RNG_HEX` transcript, and verifies that a
host entropy source fails loudly before QEMU spawn.

Implementation note (T-WL-3): `GuestWorkloadSeed` delivers an explicit workload
seed as plain black-box scenario configuration with `wseed=0x...` on the guest
command line. That command line is already part of the content-addressed
`WorldNode` material, so changing the workload seed changes the scenario
identity without changing the global `Seed`; the white-box path is never required
for this delivery mode.

### B.3 Expressing load patterns with Crucible primitives

The four classic load shapes a distributed test wants — **steady**, **spike**,
**cardinality growth**, and **correlated failure** — are, in Crucible, *not*
host-side generator classes. Each is a property of **the guest program plus the
scenario parameters**: the guest produces the base load; the *shape* comes from
how the scenario times faults and node lifecycle and from the workload parameters
it passes in (B.4). The harness shapes load through its existing primitives — it
does not add a load-generation subsystem.

How each classic pattern maps onto Crucible:

- **Steady** — a guest load loop at a fixed rate. Pure in-guest: the guest issues
  requests at its configured rate (a scenario parameter, B.4); Crucible just runs
  it to quiescence and checks properties. The "generator" is the guest binary's
  own request loop; the rate is configuration, not a host object.

- **Spike** — a guest load loop whose **rate is a function of virtual time**, *or*
  a fault-timed burst. Two equivalent spellings: (a) the guest program ramps its
  own rate on its own (virtual-time-derived) clock — the spike is in-guest and
  reproducible because the guest's clock is virtual-time-derived; or (b) the
  scenario holds a second load-node *inactive* (a baked node) and `StartNode`s it
  at a chosen virtual time (17a §17a.4.1), adding a burst of additional traffic at
  that instant — the spike is a *node-lifecycle event*, not a host generator.

- **Cardinality growth** — a guest workload that introduces new distinct keys over
  (virtual) time. Purely in-guest and parameterized: the guest's key-generation
  policy (initial cardinality, growth rate, cap) is workload configuration (B.4);
  the growth rides the guest's virtual-time clock so it is reproducible.
  Crucible's role is to *observe* the resulting traffic/I/O cardinality (e.g.
  `IoPattern` on distinct regions, `NetworkMatch` on distinct keys) and check
  properties about it.

- **Correlated failure** — a **fault campaign** (17, A.4). Where the rejected
  host-side model "converts a fraction of records to errors during a window," the
  Crucible-native expression is a `Plan` that injects correlated faults
  (partition + loss + crash across several nodes) over a virtual-time window, so
  the *system* produces correlated failures in response to a real perturbation,
  not a generator stamping synthetic error records. Correlated failure is the
  canonical use of a fault campaign and of the family fuzzing of A.4.

The mapping, as a table:

```text
  classic pattern        Crucible mechanism (no host-side generator)
  ─────────────────────  ─────────────────────────────────────────────────────────
  steady                 in-guest load loop at a fixed configured rate (B.4 param);
                         run to quiescence + check properties
  spike                  (a) in-guest loop whose rate = f(virtual time), OR
                         (b) StartNode a baked load-node at a chosen virtual time
                             (17a §17a.4.1) → a timed burst as a lifecycle event
  cardinality growth     in-guest key-generation policy parameterized
                         (init / growth-rate / cap, B.4) on the guest's virtual-
                         time clock; Crucible OBSERVES the cardinality (IoPattern /
                         NetworkMatch) and checks properties
  correlated failure     a fault CAMPAIGN in the Plan (17): correlated partition +
                         loss + crash over a virtual-time window; A.4 family fuzzing
```

Implementation note (T-WL-4): `GuestWorkloadPattern` and
`GuestWorkloadSpikeMode` encode `load_pattern=...` and `spike_mode=...` as plain
guest cmdline scenario parameters. `GuestWorkloadLoadPatternFixture` provides
steady, spike-via-virtual-time-rate, spike-via-`StartNode`, cardinality-growth,
and correlated-failure examples. The spike burst fixture is an `EventGraph`
plan that holds the burst node with `NotYetJoined`, then heals that hold and
fires `StartNode` at virtual time; the correlated-failure fixture is a
`FaultPlan` campaign. No application-load-generation subsystem is introduced.

Implementation note (T-WL-5): `GuestWorkloadTimeSource` encodes
`load_time_source=virtual_time` for time-varying load shapes. World validation
rejects unsupported time-source values, rejects a time source on non-time-varying
patterns, and requires the virtual-time source for spike and cardinality-growth
patterns. The spike and cardinality-growth fixtures are asserted reproducible by
byte-identical world, plan, compact-binary scenario, canonical-TOML scenario, and
`ScenarioDef::id` material across independent fixture construction.

- **[WL-7]** The classic load shapes (steady, spike, cardinality growth,
  correlated failure) MUST be expressible as properties of the **guest program
  plus scenario parameters**, not as host-side generator subsystems: steady = an
  in-guest loop at a configured rate; spike = an in-guest rate that is a function
  of virtual time, or a fault-/lifecycle-timed burst (`StartNode` of a baked node,
  17a §17a.4.1); cardinality growth = a parameterized in-guest key policy on the
  guest's virtual-time clock; correlated failure = a fault campaign in the `Plan`
  (17). Crucible MUST NOT add an application-load-generation subsystem to express
  any of these. *Gate:* `gate:e2e-determinism`, `gate:any-guest`. *Spec:* §B.3.

- **[WL-8]** A load shape that varies over time (spike, cardinality growth) MUST
  derive its variation from **virtual time** (the guest's virtual-time-derived
  clock, or a scenario event scheduled in virtual time), never from host
  wall-clock, so the shape is a pure function of `(ScenarioDef, Seed, Schedule)`
  and reproduces bit-identically ([INV-1], [INV-4]). A burst expressed as a
  `StartNode` of a baked load-node MUST schedule that activation in virtual time
  (17a §17a.4.1, [TRIG-23]). *Gate:* `gate:e2e-determinism`. *Spec:* §B.3;
  cross-ref 17a §17a.4.1.

- **[WL-9]** A correlated-failure load pattern MUST be expressed as a fault
  campaign over the `Plan` (17) — correlated faults over a virtual-time window
  perturbing the *modeled* world ([FAULT-1]) — so the failures are a deterministic
  consequence of injected perturbations recorded as `Decision`s (where
  probabilistic) in the `Schedule`, not synthetic error records minted by a
  generator. The family-fuzzing path (A.4, 22) MUST be the supported way to
  *explore* correlated-failure campaigns. *Gate:* `gate:e2e-determinism`,
  `gate:replay-oracle`. *Spec:* §B.3, §B.4; cross-ref 17, 22.

### B.4 Parameterization: workload params live in the ScenarioDef

A workload's *parameters* — request rate, request count, target, payload size,
key cardinality and growth, an explicit workload seed — are **scenario
configuration**, delivered to the guest by one of two content-addressed, hashed
channels, and therefore part of the `ScenarioDef`'s identity (06 §2, §8):

1. **Kernel command line** (`VmDef::cmdline`, 06 §3.1). Small scalar parameters
   ride the cmdline (`crucible.workload=httpget target=server:8080 count=100
   rate=50`). The cmdline is already part of the determinism input ([DET-3]) and
   hashed verbatim into the scenario (06 §3.1), so changing a workload parameter
   is a different scenario with a different `id`.

2. **A config file delivered via the read-only rootfs or a 9p sub-node** (15). A
   larger or structured workload config (a request schedule, a key-distribution
   table) is delivered as a file: either baked into the content-addressed
   `root_image` (06 §3.1) or served by a read-only 9p sub-node (15) with
   deterministic QIDs and sorted enumeration. Either way the content is
   content-addressed (06 §8) and part of the scenario hash.

Both channels are **read-only** to the guest and **content-addressed**, so the
workload configuration is reproducible and the same scenario hashes identically on
every host (06 §8, [SPAT-25]). A workload parameter is *never* delivered by a
host-side runtime poke; it is part of the immutable definition the run reduces.

```toml
# A workload parameterized entirely by content-addressed scenario config.
[[world.node]]
id = "client"
arch = "x86_64"
kernel = "blake3:9f86d0..."
root_image = "blake3:client-with-cfg..."   # config baked in, content-addressed
# scalar params on the cmdline (hashed verbatim, 06 §3.1)
cmdline = "console=ttyS0 crucible.workload=bench rate=200 count=50000 wseed=0x1234"

# OR: a structured config served read-only over 9p (15), content-addressed
[[world.node]]
id = "client-9p"
# ... vm fields ...
[world.node.io.ninep]                       # a read-only 9p sub-node (15)
export = "blake3:workload-cfg-tree..."      # content-addressed config tree
mount  = "/etc/workload"
```

- **[WL-10]** Workload parameters (rate, count, target, payload size, key
  cardinality/growth, an explicit workload seed) MUST live in the `ScenarioDef`
  and be delivered to the guest by a content-addressed, hashed channel — the
  kernel command line (06 §3.1) for scalars, or a config file delivered via the
  content-addressed read-only rootfs or a read-only 9p sub-node (15) for
  structured config. They MUST be part of the scenario's content hash (06 §2, §8):
  changing a workload parameter MUST produce a different `ScenarioDef::id`.
  *Gate:* `gate:content-address`. *Spec:* §B.4; cross-ref 06 §3.1, §8, 15.

- **[WL-11]** Workload-parameter delivery MUST be **read-only** to the guest and
  carry only content-addressed references (no host-varying paths), so a
  parameterized workload is portable across hosts and embeddable in a
  self-contained reproduction artifact (06 §7.1, [SPAT-25]). A workload parameter
  MUST NOT be delivered by a host-side runtime poke after boot; it is part of the
  immutable definition the run reduces ([INV-1], [INV-5]). *Gate:*
  `gate:content-address`, `gate:any-guest`. *Spec:* §B.4; cross-ref 06 §7.1.

- **[WL-12]** A change to any workload parameter MUST be observable as a scenario
  identity change and therefore reproducible: two runs that differ only in a
  workload parameter MUST be two distinct, individually reproducible scenarios
  ([SPAT-4]), and a workload variation discovered by family fuzzing (A.4, [WL-9])
  MUST reduce to a self-contained reproduction artifact carrying the concrete
  parameterized `ScenarioDef` (06 §7.1, [SPAT-27]). *Gate:* `gate:replay-oracle`,
  `gate:content-address`. *Spec:* §B.4; cross-ref 06 §7.1, 22.

Implementation note (T-WL-6): `GuestWorkloadScalarParameter` models the supported
cmdline scalar keys (`target`, rate/count/payload-size, and key-cardinality
policy), and `GuestWorkloadConfigTreeRef` models structured config as a
content-addressed `wcfg=...` reference delivered by read-only rootfs or read-only
9p. `World::workload_config_trees()` exposes the validated world-level
config-tree bindings derived from hashed node config. World validation rejects
duplicate scalar keys, empty scalar values, non-content-addressed config exports,
non-portable guest mount paths, duplicate config-tree refs, rootfs config refs
whose export does not match the node's read-only `root_image`, and any delivery
mode outside `readonly_rootfs`/`readonly_9p`. The fixtures assert parameter
changes alter `ScenarioDef::id`, round-trip through canonical TOML and compact
binary, and capture as self-contained reproduction artifacts.

### B.5 The workload story, restated

```text
WORKLOADS RUN IN-GUEST (WL-1,2,3): the guest binary does the work; Crucible
  OBSERVES (frames/I/O/console) and STEERS (faults, node start/stop, properties).
  NO host-side traffic injector — that in-process model is intentionally not
  carried (it would need a host→guest poke and re-add host nondeterminism).

DETERMINISTIC SEEDING (WL-4,5,6): in-guest randomness rides the SAME seeded
  firmware entropy boundary as everything else (04/26) — reproducible with ZERO
  guest change. No new entropy source. Optional explicit workload seed via plain
  config (cmdline/file) or the optional white-box channel; never required.

LOAD PATTERNS = guest program + scenario params (WL-7,8,9):
  steady             in-guest loop at a configured rate
  spike              in-guest rate = f(virtual time)  OR  StartNode a baked
                     load-node at a virtual time (timed burst, lifecycle event)
  cardinality grow   parameterized in-guest key policy on the guest's VT clock;
                     Crucible observes cardinality, checks properties
  correlated failure a FAULT CAMPAIGN in the Plan (17) + family fuzzing (22)
  (all variation derives from VIRTUAL TIME — never host wall-clock)

PARAMETERIZATION (WL-10,11,12): params live in the ScenarioDef, delivered
  read-only + content-addressed (cmdline OR rootfs/9p config file), part of the
  scenario hash. Changing a param = a different, individually reproducible scenario.
```

---

## Cross-file assumptions this file relies on

- The `ScenarioDef = (World, Plan, Properties, Seed)` shape, its code-first
  builder, its serialized TOML form, and `ScenarioFamily` are
  [`06-spatial-graph.md`](06-spatial-graph.md); this file composes them, it does
  not redefine them.
- Every condition used in the examples (`ConsoleMatch`, `NetworkMatch`,
  `CoveragePoint`, `NodeState`, `IoPattern`, `Quiescent`, `At`/`After`/`Timer`,
  `AssertionState`, `AllOf`/`Once`) and the `Action` set (`InjectFault`/`HealFault`,
  `ArmTimer`, `StartNode`/`StopNode`, `Pass`, `Group`) is
  [`17a-conditions-and-triggers.md`](17a-conditions-and-triggers.md).
- The faults (`Partition`, `Crash` with its `RestartPolicy`, `MessageLoss`,
  `LatencyBump`) are [`17-fault-injection.md`](17-fault-injection.md); the
  assertion quantifiers (`Always`, `Eventually`) are
  [`18-assertions-properties.md`](18-assertions-properties.md).
- The CLI verbs (`run`, `verify`, `save`, `resume`, `fork`, `replay`, `fuzz`,
  `selftest`), exit codes, and the failure-time repro-command ergonomics are
  [`23-cli.md`](23-cli.md); the search/fuzz/save/fork/oracle machinery is
  [`22-advanced-features.md`](22-advanced-features.md).
- The seeded firmware entropy boundary the in-guest workload determinism rides on
  is [`04-determinism-contract.md`](04-determinism-contract.md) and
  [`26-packaging-aos-integration.md`](26-packaging-aos-integration.md); the
  read-only 9p config channel is [`15-io-subnodes.md`](15-io-subnodes.md); the
  optional white-box channel is [`16-guest-host-channel.md`](16-guest-host-channel.md).

## Implementation checklist

> The checklist task text below is authoritative for this topic; phase ordering lives in
> [`32-implementation-plan.md`](32-implementation-plan.md). The copies below are
> the tasks whose primary area is this file ([PLAN-3]); they are kept in
> sync with the master plan's order/digest by the doc lint
> ([`28-engineering-standards.md`](28-engineering-standards.md)). They are
> sequenced after the layers they exercise (06 spatial graph, 17/17a faults &
> triggers, 18 assertions, 22 advanced features, 23 CLI) — the examples are the
> end-to-end fixtures those layers' gates run against.

- [x] **T-WL-1** Implement and document the in-guest workload model: the supported
  guest workload binaries (httpd, client loop, benchmark) selected by scenario
  parameter, with NO host-side traffic injector; add a lint/test that no
  application-traffic origination path exists in the engine. — satisfies [WL-1],
  [WL-2], [WL-3]; spec §B.1.
  Completed by `checks.crucible.phase4.workloadModel`: the engine has a closed
  `GuestWorkloadBinary` vocabulary, encodes selection as hashed guest cmdline
  scenario config, and rejects host-side application-traffic injector API shapes.
- [x] **T-WL-2** Verify in-guest workload determinism over the seeded firmware
  entropy boundary: a guest workload that draws on guest RNG reproduces
  bit-identically across runs with zero guest modification, and a workload that
  opens a new entropy source fails the determinism gate loudly. — satisfies
  [WL-4], [WL-5]; spec §B.2; cross-ref 04, 26.
  Completed by `checks.crucible.phase4.workloadEntropyBoundary`: the workload
  entropy test proves same-seed selected `crucible-httpget-workload`
  `WORKLOAD_RNG_HEX` transcripts are byte-identical, changed scenario seeds
  change the guest RNG stream, the phase-1 booted guest entropy gate remains
  wired in, and host/unseeded entropy mutations fail loudly.
- [x] **T-WL-3** Implement explicit-workload-seed delivery via plain content-
  addressed config (cmdline/file) and, optionally, the white-box channel; assert
  the black-box config path always suffices and the white-box path is never
  required. — satisfies [WL-6]; spec §B.2, §B.4.
  Completed by `checks.crucible.phase4.workloadSeed`: `GuestWorkloadSeed`
  renders as the plain `wseed=0x...` guest cmdline parameter, is validated in
  `WorldNode` parsing, changes scenario identity through content-addressed world
  material while leaving global `Seed` unchanged, and builds with
  `WhiteBoxPolicy::Disabled`.
- [x] **T-WL-4** Implement the four load-pattern mappings (steady / spike via
  VT-rate or `StartNode` burst / cardinality growth / correlated-failure campaign)
  as guest-program-plus-scenario-parameter constructions with no load-generation
  subsystem; provide a fixture per pattern. — satisfies [WL-7], [WL-9]; spec §B.3.
  Completed by `checks.crucible.phase4.workloadLoadPatterns`: the model exposes
  validated `load_pattern=...` and `spike_mode=...` guest cmdline scenario
  parameters, fixture constructors for every classic pattern, a virtual-time
  rate spike fixture, a `StartNode` burst fixture, and a correlated-failure
  `FaultPlan` campaign without adding a host load-generation subsystem.
- [x] **T-WL-5** Enforce that all time-varying load shapes derive from virtual time
  (guest VT clock or VT-scheduled events), never host wall-clock; assert spike and
  cardinality-growth fixtures reproduce bit-identically. — satisfies [WL-8]; spec
  §B.3; cross-ref 17a §17a.4.1.
  Completed by `checks.crucible.phase4.workloadVirtualTimeShapes`:
  `GuestWorkloadTimeSource` admits only `virtual_time`, fixture nodes render
  `load_time_source=virtual_time` for spike/cardinality-growth patterns, world
  validation rejects host-wall-clock or missing/stray time-source configuration,
  and the spike/cardinality fixtures reproduce byte-identical canonical scenario
  material across independent construction.
- [x] **T-WL-6** Implement content-addressed workload parameterization (cmdline
  scalars + read-only rootfs/9p config tree), part of the scenario hash, read-only
  to the guest; assert a parameter change yields a different `ScenarioDef::id` and
  an individually reproducible scenario. — satisfies [WL-10], [WL-11], [WL-12];
  spec §B.4; cross-ref 06 §3.1, §8, §7.1, 15.
  Completed by `checks.crucible.phase4.workloadParameterization`:
  supported workload scalar keys render as immutable cmdline scenario config,
  structured config trees render as content-addressed read-only `wcfg` refs for
  rootfs/9p delivery, world validation rejects mutable/host-path/duplicate
  parameterization, and changed scalar or config-tree values produce distinct
  individually reproducible `ScenarioDef` material.
- [x] **T-EX-1** Ship the happy-path client/server scenario (A.1) as a built-in
  corpus fixture, authored with zero guest-side components; assert `run` PASSES and
  `verify --runs N` is byte-identical. — satisfies [EX-1], [EX-2], [EX-3]; spec
  §A.1.
  Completed by `checks.crucible.phase7.happyPathExample`: the built-in
  `happy-path.scn` fixture is exported from `crucible::example_corpus`, uses only
  black-box console/network/lifecycle/quiescence predicates with white-box
  disabled, runs to the `pass-on-quiescence` event, captures a replayable
  reproduction artifact with the canonical observation script in its schedule,
  is exercised by `crucible selftest`, and verifies five independent local
  reductions as byte-identical.
- [x] **T-EX-2** Ship the partition-recovery scenario (A.2) with the full
  observable trigger graph (AllOf readiness + relative-timer heal + observable
  convergence) as a corpus fixture; assert `no-split-brain`/`converges-after-heal`
  and byte-identical reproduction. — satisfies [EX-1], [EX-2], [EX-3]; spec §A.2;
  cross-ref 17a §17a.5.1.
  Completed by `checks.crucible.phase7.partitionRecoveryExample`: the built-in
  `partition-recovery.scn` fixture is exported from `crucible::example_corpus`,
  uses the observable readiness graph, grouped partition injection plus
  relative timer, timer-driven heal, and observable convergence pass event, checks
  `no-split-brain`/`converges-after-heal`, captures a replayable multi-step
  reproduction schedule, is exercised by `crucible selftest`, and verifies five
  independent local reductions as byte-identical.
- [x] **T-EX-3** Ship the crash+restart scenario (A.3) exercising `Fault::Crash`
  with a `FromReadyPoint` restart policy and `StartNode` choreography; assert
  `data-not-lost`/`reconverges` and reproduction. — satisfies [EX-1], [EX-2],
  [EX-3]; spec §A.3; cross-ref 17 §17.4.3, 17a §17a.4.1.
  Completed by `checks.crucible.phase7.crashRestartExample`: the built-in
  `crash-restart.scn` fixture is exported from `crucible::example_corpus`, uses
  the observable WAL-write crash trigger, `Fault::Crash` with
  `RestartPolicy::FromReadyPoint`, an `After`-anchored `HealFault` +
  `StartNode` restart event, derived crash/restart lifecycle facts, and
  scheduler crash/restart/topology application evidence for the declared
  triangle; it checks `data-not-lost` as an `Always` black-box safety assertion
  and `reconverges` as crash-triggered bounded liveness, is exercised by
  `crucible selftest`, and verifies five independent local reductions as
  byte-identical.
- [x] **T-EX-4** Ship the fault-campaign `ScenarioFamily` (A.4) and wire it into
  `crucible fuzz` with basic-block coverage; verify a planted/discoverable failure
  reduces to a self-contained artifact that `crucible replay` reproduces
  bit-identically, and that `save`/`resume`/`fork` walk the neighborhood. —
  satisfies [EX-1], [EX-2], [EX-3]; spec §A.4; cross-ref 22, 06 §7.
  Completed by `checks.crucible.phase7.faultCampaignExample`: the built-in
  `fault-campaign.fam` fixture exports a deterministic `ScenarioFamily`
  over seed, fault density, topology size, and topology shape; `crucible fuzz
  --family fault-campaign.fam` runs the local proof path with unified event-log
  basic-block coverage feedback, evaluates a planted black-box
  `split_brain=true` observation into a violated `no-split-brain`
  `HostAssertionReport`, captures that discoverable finding as a
  self-contained reproduction artifact whose schedule carries the violation
  observation, reconstructs the replay-side assertion log from that artifact,
  validates replay byte-identity through the unified temporal graph, and proves the
  pre-failure neighborhood can be saved, resumed, and forked through the same
  graph path. Generic file/hash fuzz execution remains tracked by T-CLI-13.
- [x] **T-EX-5** Wire the example corpus into `crucible verify --adversarial` and
  the divergence-bisection report (A.5): assert all examples are DETERMINISTIC
  under the hostile host matrix, and golden-test the divergence-report shape on a
  deliberately seeded divergence. — satisfies [EX-2], [EX-3]; spec §A.5; cross-ref
  24 §5, §7.
  Completed by `checks.crucible.phase7.adversarialExampleVerify`: `crucible
  verify` now resolves shipped example names (including the fault-campaign sample)
  through the ordinary adversarial reduction planner, which applies the hostile
  host-condition profiles to the control-client observation path; the CLI golden
  test also asserts the `verify-divergence`/`verify-bisect-state` report shape on
  a deliberately seeded partition-recovery divergence.
