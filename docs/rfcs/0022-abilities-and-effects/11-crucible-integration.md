# AOS as a first-class Crucible guest

## Ownership and dependency direction

Crucible remains guest-agnostic. AOS owns the integration that maps ability
execution into Crucible's generic guest assertions, markers, choices, and
measurements. This RFC requires no AOS-specific behavior in Crucible's engine,
assertion evaluator, scheduler, campaign model, or QEMU/plugin implementation.

```text
AOS ability executor and provider implementations
  -> optional AOS Crucible integration
    -> generic Crucible guest protocol
      -> generic assertions, choices, measurements, exploration, and replay
```

The production ability executor runs without Crucible. Its integration is
explicitly enabled for executions inside a Crucible environment. AOS can be
deeply instrumented throughout its real execution path while every concept
specific to abilities, grants, generations, publication, and compensation
remains on the AOS side.

| Owner | Responsibility |
| --- | --- |
| AOS executor/providers | Execute the real transition and expose defined observation/choice hooks |
| AOS guest integration/test code | Interpret AOS state, evaluate application-specific conditions, offer legal choices, and apply selected guest behavior |
| AOS scenario/test tooling | Declare generic properties, expected guest declarations, environment faults, and exploration domains |
| Crucible | Validate generic protocol input; evaluate temporal assertion semantics; select, record, schedule, explore, and replay through its public interfaces |
| QEMU/plugin | Transport and observe generic guest interactions through the versioned process boundary |

An assertion ID such as `aos.activation.validated-before-publication` is opaque
to Crucible. It does not install a special predicate that understands APM.
Likewise, an AOS-selected fault response has meaning to the guest adapter, not
to a new Crucible ability-operation dispatcher.

## Explicit dependency on pending PR #194

[PR #194](https://github.com/andyl-technologies/aos/pull/194), implementing
single-host Crucible campaigns, is **open, draft, and not merged** at the
revision reviewed for this section:
`e6387cab973e5de6e1c55d57f59a588cd1424392`. The links below pin that revision so
pending features cannot be mistaken for facilities in this RFC's master
baseline. All AOS ability integration described here is itself proposed work.

| Integration feature | Crucible dependency | Availability rule |
| --- | --- | --- |
| Basic guest assertion observations and named markers | Existing [assertion/guest-channel model](../0010-crucible/18-assertions-properties.md) | Does not inherently require the new campaign engine; qualify the AOS adapter against the supported baseline protocol |
| Existing modeled environment faults | Existing [signal-fault interfaces](../0014-signal-driven-fault-model/README.md) | Use only admitted fault adapters and supported execution profiles |
| Typed guest declarations, narrowed choice domains, reply-bearing requests, and pending-choice continuation | PR #194 [selectable protocol](https://github.com/andyl-technologies/aos/blob/e6387cab973e5de6e1c55d57f59a588cd1424392/docs/rfcs/0020-crucible-campaigns/02-selectables-and-choice-protocol.md) | Depends on the pending protocol and its public execution/replay qualification |
| Structured guest measurement windows and campaign observation evidence | PR #194 [measurement contract](https://github.com/andyl-technologies/aos/blob/e6387cab973e5de6e1c55d57f59a588cd1424392/docs/rfcs/0020-crucible-campaigns/08-observability-measurement-debugging.md) | Depends on the pending measurement path and admitted source types |
| Durable adaptive branching, feedback, findings, and campaign pause/restart | PR #194 [campaign model](https://github.com/andyl-technologies/aos/blob/e6387cab973e5de6e1c55d57f59a588cd1424392/docs/rfcs/0020-crucible-campaigns/README.md) | Depends on the pending campaign implementation and acceptance gates |
| New exact-time trigger/frontier behavior used by a scenario | PR #194 scheduler changes | Qualify that exact feature/profile; do not infer support from baseline marker delivery |
| Hot-fork acceleration at a choice boundary | PR #194 [checkpoint tiers](https://github.com/andyl-technologies/aos/blob/e6387cab973e5de6e1c55d57f59a588cd1424392/docs/rfcs/0020-crucible-campaigns/05-hot-fork-and-checkpoints.md) | Optional optimization; requires explicit profile and whole-world capability admission |

The PR reports implemented components and successful flights while retaining
open acceptance work. Its complete public guest-choice/branch/observe/pause/
restart campaign flight, remaining whole-world hot-fork work, and sustained
product/operator acceptance are not closed by this RFC. Consult the pinned
[implementation plan](https://github.com/andyl-technologies/aos/blob/e6387cab973e5de6e1c55d57f59a588cd1424392/docs/rfcs/0020-crucible-campaigns/11-implementation-plan.md)
before enabling dependent AOS tests. Merge alone is not evidence that every
optional execution profile has passed its gates.

A scenario requesting an unavailable protocol or feature must fail admission
or be recorded as unsupported under the test policy. It cannot silently omit
required assertions or choices and report a pass. Baseline assertions and
ordinary VM/fleet tests can proceed independently of pending campaign work.

## Executor hooks and packaging

Provide an optional AOS-owned adapter, illustratively `aos-ability-crucible`,
that consumes shared ability types and executor observation/choice hooks and
uses the generic guest interface. Keep this dependency out of the pure model,
validator, inspector, and normal runtime configuration. The adapter does not
replace planning, authorization, publication, or recovery with test equivalents.

A Crucible test profile explicitly enables the adapter and declares its expected
protocol features. An untrusted environment variable must not enable arbitrary
fault responses. When enabled, required registration and compatibility checks
must succeed before the scenario's ready point; an unavailable integration is
a test setup failure. When disabled, production execution needs no Crucible
connection or handshake.

Observation hooks report AOS facts at defined boundaries. Choice hooks are
separately identified because they intentionally permit modeled interventions.
Do not add a second privileged command API behind either hook. Identifiers,
domains, and instance keys obey the generic protocol's bounds, registration
rules, and replay identity requirements.

An instrumented binary has its own exact artifact identity. Guest instructions
and protocol calls can affect execution cost; adding instrumentation need not
leave a binary's fingerprint unchanged. For one fixed instrumented build and
recorded schedule, observation/checking follows Crucible's determinism contract.
Assertions do not themselves select faults; explicit triggers and choice
responses may affect the run.

## Assertions remain AOS-authored guest behavior

AOS interprets its plan, grants, state, and observations and reports generic
assertion conditions. Crucible applies the supported temporal semantics and
retains verdicts and reproduction evidence. It never needs a host-side decoder
for an AOS activation journal or an ability-specific predicate language.

Useful AOS assertions include validation preceding publication of the same
candidate, rejection without protected mutation, preservation of other
consumers' resources, promised revocation behavior, and recovery reaching a
defined terminal state. Some checks derive from contracts; application-specific
correctness still requires authored probes and assertions.

Use the generic protocol's supported forms. If a desired property cannot be
expressed, simplify the AOS-side observation/monitor or defer that property.
An AOS-specific extension to Crucible is outside this design. An independently
motivated generic protocol enhancement would need its own Crucible review.

Bound per-transaction monitors and their lifecycle. Report missing observations,
never-reached required boundaries, and interrupted/incomplete checks according
to the declared generic semantics. A conditional property whose trigger never
fires is not evidence that the intended transition ran. After guest restart,
restore or reconstruct the AOS-side state needed for checks and keep attempts
and resource incarnations distinct.

Independent observations remain essential. An AOS test client can check that
nginx serves the new response, durable records survived, or a revoked consumer's
access fails, and report results through the same generic guest interface. The
client may occupy another simulated node. Crucible's model observations remain
authoritative for modeled events such as fault application; duplicate guest
counters do not replace them.

## Fault choices and meaningful operation boundaries

AOS maps operation context into generic typed declarations and runtime choice
opportunities. Logical transaction/operation/attempt keys provide stable context;
arbitrary PIDs or a global occurrence counter are insufficient semantic
identities. Offered domains contain only alternatives the hook can implement
and that the scenario admitted.

Examples include a validation-provider rejection before effects, a modeled
provider delay, or loss of a response after a committed operation. The AOS
adapter understands and applies guest-side alternatives. Environmental storage,
network, and node faults continue through Crucible's generic modeled fault
interfaces. No fault targets real host resources outside that modeled world.

Distinguish rejection before an effect, partial completion, and completion with
a lost acknowledgement. Each needs a different implementation and expected
recovery path. A synthetic failure tests the consumer's handling of that
response; it does not establish the underlying storage's crash semantics.
Do not fabricate success or weaken grants unless an explicitly declared test
models a faulty provider, with its claim limited accordingly.

A marker is an observation, not automatically a stopping barrier. Precise
interruption before the next guest operation requires a supported synchronization
contract. PR #194's reply-bearing pending-choice path is a potential boundary:
the guest remains stopped until a selected value or rejection is supplied.
Which guest/node execution is stopped and when an environmental fault applies
must be established by the generic protocol and scenario, not assumed from an
AOS phase name. Timed behavior uses modeled time and admitted scheduling rules,
never host wall-clock sleeps or unrecorded host actions.

## Campaign guidance, replay, and checkpoints

AOS scenario tooling can expose bounded choices around shared resources,
provider replacement, revocation, and commit/recovery boundaries. It can supply
generic coverage markers and measurements for recovery duration, attempts, and
availability. Crucible explores the admitted domains and returns generic
observations/findings. AOS tooling joins those records to its own ability graph
for explanation; Crucible acquires no ability-graph dependency.

Correctness remains a property verdict, even when measurements guide exploration.
Campaign results cover recorded scenarios and profiles; adaptive search is not
an exhaustive proof or a production failure-rate estimate.

An AOS operation boundary is not automatically a checkpoint-safe whole-world
boundary. Guest state, disks, pending replies, monitor continuation, modeled
network/providers, and observation cursors must satisfy Crucible's snapshot
contract. A live external service outside the captured world cannot be assumed
reproducible. Hot fork requires the pending PR's qualified capability; supported
exact restore or thin replay is sufficient for the initial integration.

## First integration and acceptance

Start with one real nginx update and independent response/state probes. Exercise
one precisely defined interruption boundary, retain the partial outcome, and
reproduce its recovery through a supported generic Crucible path. Add typed
choice exploration and structured measurements only when their PR #194
dependencies are available and qualified.

Acceptance must demonstrate that the normal executor works with integration
disabled; enabled tests reject missing required declarations; assertions and
probes detect a deliberately introduced violation; reached fault boundaries
and selections are recorded; replay reconstructs the same opportunity and
outcome; and the AOS inspector explains findings from retained records.
Pending-request restart/restore and campaign pause/resume require their own
dependent flights. Hot fork is not a prerequisite for this first integration.

Use the existing release qualification and evidence rules. Crucible's generic
assertion semantics and verdict evaluation remain Apache host-side; QEMU/plugin
transport stays across the versioned process boundary. No AOS-specific QEMU
types, callbacks, headers, or native objects are introduced by this integration.
