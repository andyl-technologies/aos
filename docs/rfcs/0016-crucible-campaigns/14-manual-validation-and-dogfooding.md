# 14 — Manual validation, dogfooding, and real-usage acceptance

Automated conformance is necessary but cannot establish that campaigns are
operable. Campaigns coordinate scenario authoring, guest integration, thousands
of executions, adaptive decisions, large retained artifacts, incident triage,
and destructive lifecycle operations. A system can satisfy its codecs and
replay oracle while remaining confusing, fragile, or unsafe in the hands of an
operator.

This file defines release-blocking manual validation. It is not an informal
demo and not permission to accept behavior that lacks an automated gate. Each
manual flight uses a pinned build and scenario, follows a reviewable runbook,
retains an evidence bundle, and turns every discovered defect into a tracked
reproduction and, where practical, an automated regression.

## 14.1 What manual validation must prove

Manual validation answers questions that component and integration tests do not:

- Can an application developer expose useful choices and measurements without
  understanding Crucible internals?
- Can an operator create, observe, steer, pause, hibernate, resume, and stop a
  large campaign using only supported interfaces?
- Can another person understand why a branch ran and why it survived?
- Can an investigator move from a finding to a useful paused midpoint and
  reproduce the failure without access to the original daemon?
- Do resource pressure and partial failure produce safe, comprehensible
  behavior rather than an apparently hung or corrupted campaign?
- Does the content-addressed storage model make retention, transfer, and
  deletion predictable in realistic operation?
- Does the feature remain usable for hours or days, after shift handoffs,
  daemon restarts, host maintenance, and policy revisions?

- **[CMAN-1]** Campaign implementation MUST NOT be declared complete solely from
  automated gates. Every release candidate that enables campaigns or hot fork
  by default MUST pass the manual acceptance gates in this file.
- **[CMAN-2]** Manual acceptance MUST exercise supported public CLI, API, guest,
  and debugger surfaces. Direct database/object edits, private daemon RPCs,
  ad-hoc QMP mutations, and source-level state repair invalidate the flight.

## 14.2 Validation layers

Manual validation is progressive. A later layer includes the earlier layers'
critical paths but increases realism, duration, and independence.

| Layer | Purpose | Typical duration | Frequency |
| --- | --- | --- | --- |
| Tabletop | Review the runbook, failure boundaries, evidence, and operator decisions before code is enabled | 60–90 minutes | At RFC and protocol revisions |
| Developer flight | Exercise one newly implemented vertical slice using public surfaces | 30–120 minutes | Every implementation phase |
| Operator acceptance | Complete the standard lifecycle with a realistic product fixture | 4–8 hours | Before a phase is considered usable |
| Destructive recovery drill | Interrupt processes, storage, credentials, and host lifecycle at declared points | 4–8 hours | Before persistence/hot fork is enabled |
| Dogfood campaign | Run and steer a useful campaign under representative scale and pressure | 24–72 hours | At major milestones and release candidates |
| Independent handoff | Give only exported artifacts and docs to a second operator/investigator | 2–4 hours | Before release |

Developer flights find integration problems early; they do not substitute for
operator acceptance. A feature author may drive a developer flight but may not
be the only operator signing the final flight.

- **[CMAN-3]** Final operator acceptance MUST include a driver who did not
  implement the feature under test and a reviewer who can challenge expected
  behavior. The implementation author may observe and answer product questions
  but MUST NOT perform hidden repair.
- **[CMAN-4]** Every flight MUST identify its layer, intended claims, timebox,
  participants, build/provenance, host profile, scenario, policy, starting store
  state, and allowed fault actions before execution begins.

## 14.3 Realistic reference environment

The release fixture is the network recovery campaign in
[`13-worked-network-campaign.md`](13-worked-network-campaign.md), promoted from
an illustrative example to an executable operator fixture. The public
`crucible campaign fixture worked-network --output DIR` command produces its
canonical import/create/control-plane basis. Final operator evidence replaces
the intentionally artifact-free VM definitions with the actual supported
product build while preserving the declared topology, boundaries,
measurements, properties, and policy shape. The release flight contains:

- at least three product router VMs and two traffic endpoints;
- the actual supported product build and guest integration library, not a stub
  that merely echoes selections;
- real configuration/bootstrap work and convergence before the fork boundary;
- a continuous mix of traffic that can detect loss, reordering, forbidden
  delivery, loops, and recovery;
- typed guest response choices and typed environment loss, latency, partition,
  duration, target, and follow-up fault choices;
- guest semantic markers for convergence plus model-derived network evidence;
- a known injectable defect or deliberately unsafe response used to prove the
  complete finding/debug path;
- enough state and guest RAM for COW and checkpoint behavior to be meaningful;
  and
- an immutable local base image and branch-private overlay disks.

The fixture may also include a storage stall or guest memory fault as a
cross-domain follow-up. Toy single-process fixtures remain appropriate for
automated gates and developer flights, but they cannot satisfy final operator
acceptance.

Two supported host profiles are recorded:

1. a constrained development host that forces backpressure and exact/thin
   fallback; and
2. a campaign host sized to sustain the declared high-parallelism flight.

Kernel, CPU topology, NUMA layout, memory, filesystem, free space, limits,
QEMU/plugin build, store backend, and network isolation are captured in the
evidence manifest. The campaign uses modeled networking only; ambient host
network behavior is not smuggled into scenario results.

- **[CMAN-5]** Final acceptance MUST run an actual product workload on every
  advertised QEMU fork capability profile and MUST include one constrained host
  that exercises backpressure and fallback.
- **[CMAN-6]** Any mock or injected failure used by a flight MUST be declared in
  advance and limited to the dependency being tested. The scenario execution,
  guest choices, measurements, campaign store, and public operator surfaces
  remain production implementations.

## 14.4 Flight evidence bundle

Every manual flight publishes one content-addressed evidence bundle beside its
campaign snapshot. It contains:

```text
manual-flight-manifest
  flight ID, layer, runbook version, build and provenance
  participants and independent-review acknowledgements
  host and store profiles
  scenario, policy, seed, budget, and starting snapshot
  ordered operator command journal with exit status
  canonical campaign snapshots at named checkpoints
  selected status/frontier/explain/compare output
  operational telemetry and resource-pressure timeline
  expected and observed finding/replay identities
  destructive-action injection records
  component mode, hibernate/export/import/transfer/GC plans and results
  defects, surprises, documentation gaps, and workarounds
  final claim checklist and sign-offs
```

The command journal records commands and semantic results, not credentials or
secret environment contents. Screenshots or terminal recordings may accompany
the bundle for usability review, but structured command/API output is the
authoritative evidence. Secrets, guest memory, packet payloads, and customer
data follow the export policy in §09.

Each runbook step has one of four outcomes:

- `pass`: expected semantic and operator-visible behavior occurred;
- `fail`: a required claim was contradicted;
- `blocked`: an external prerequisite prevented the claim from being tested;
  or
- `observation`: non-gating feedback with an explicit disposition.

There is no “pass with unexplained workaround.” A workaround is a defect or a
runbook prerequisite and must be classified before sign-off.

- **[CMAN-7]** A manual gate MUST retain its runbook, command journal, relevant
  campaign snapshots, exact/thin reproduction artifacts, operational telemetry,
  defect list, and signed result. A prose assertion that testing occurred is not
  sufficient evidence.
- **[CMAN-8]** Evidence capture MUST redact secrets without omitting the
  semantic identities needed to reproduce and audit the flight.

## 14.5 Standard lifecycle flight

This is the minimum useful journey through the product.

### Author and validate

The application integrator adds guest recovery selectables and convergence
markers using the public guest library. The scenario author declares expected
catalogs, environment selectables, measurements, properties, and bounds. A
fresh operator:

1. validates an intentionally incorrect guest domain and uses the diagnostic to
   fix it;
2. validates the corrected scenario and campaign policy;
3. inspects the resolved choice catalog, units, defaults, constraints, objective
   directions, stop boundaries, retention, and projected resource budget; and
4. confirms that the policy distinguishes search claims from statistical
   claims.

No source code or daemon log should be required to explain a validation error.

### Create and run

The operator creates the named campaign, starts the daemon, waits for the common
converged prefix, and watches the first branches. During execution the operator
must be able to answer from supported status and inspection commands:

- what is running versus only logically open;
- what capacity or budget is limiting progress;
- which realization tier each active branch uses and why;
- how much logical and physical storage is retained;
- whether a choice domain is exhausted, waiting for feedback, or merely
  budget-pruned; and
- why the scheduler selected each of several representative proposals.

### Pause and resume

The operator pauses while children are active. The daemon drains or records
attempts according to policy, publishes a complete snapshot, and reaches a
stable paused state within its declared control responsiveness bound. The
operator restarts the daemon, resumes, and verifies that facts are neither lost
nor credited twice and that the lazy frontier continues from the same state.

### Steer without rewriting history

While the campaign remains useful, the operator grants an additional bounded
budget, adds a three-value finite branch request to a large integral domain,
increases generated exploration around a route-churn region, pins one suspicious
branch, and activates a revised survivor policy. Inspection must show the finite
and generated sources independently, deduplicate a value proposed by both onto
one semantic edge, show the old planner steps under the old policy, and show
subsequent steps under the new policy. Strict-mode history remains reproducible;
no prior request or proposal changes reason.

### Stop and seal

The operator requests a graceful stop, reviews remaining attempts and retained
objects, seals the campaign, and produces a report distinguishing explored,
exhausted, pruned, failed, and unvisited space. Reopening, if allowed by policy,
creates an explicit state transition.

- **[CMAN-9]** Final acceptance MUST complete author/validate, create/run,
  inspect/explain, pause/restart/resume, steer, stop/seal, and report through
  public surfaces without internal state repair.
- **[CMAN-10]** At least two representative planner decisions—one exploitative
  and one widening/novelty decision—MUST be independently reconstructed from the
  displayed evidence and match the canonical planner record.

## 14.6 Finding-to-debug and independent handoff flight

The fixture's known defect proves the incident workflow:

1. the running campaign identifies the property violation and publishes a
   finding before reclaiming the child;
2. the operator inspects the signature, causal selections, measurement window,
   nearest retained midpoint, and storage closure;
3. minimization produces a smaller reproducer or a localized explanation of why
   no reduction was accepted;
4. replay from thin state reproduces the signature without campaign daemon
   state;
5. replay from the exact midpoint reaches the declared pause point and verifies
   the prefix;
6. the investigator performs read-only register, memory, event, signal,
   selection, and metric inspection;
7. a supported selection override creates a new canonical branch, while an
   arbitrary debugger write creates a clearly labeled non-canonical session;
   and
8. neither session mutates the original finding or checkpoint.

For independent handoff, a second investigator receives only documented build
requirements and the exported finding bundle. They do not receive the original
campaign directory, daemon process, shell history, or verbal reconstruction.
They must reproduce the signature, reach the midpoint, and explain the selected
fault and guest response from the bundle.

- **[CMAN-11]** Final acceptance MUST prove finding publication, minimization,
  thin replay, exact-midpoint debugging, canonical/non-canonical debugger branch
  labeling, and immutable retained evidence.
- **[CMAN-12]** An independent investigator MUST reproduce and explain at least
  one finding solely from its exported bundle and published documentation.

## 14.7 Component-boundary, hibernation, and maintenance flight

The operator first runs the same bounded campaign once through the direct
coordinator/executor client and once with those components separated over the
supported same-host RPC transport. Canonical snapshots, attempts, observations,
findings, and explanations must match. The operator then independently restarts
the coordinator and executor, confirms resubmission of incomplete attempts, and
uses only `CampaignService` for ordinary campaign control.

The operator next hibernates a running campaign with hot templates and active
lazy continuations:

1. request hibernation under a configured logical durability policy;
2. observe required hot templates become exact closures;
3. verify all required objects before the campaign ref advances;
4. terminate all QEMU and daemon processes;
5. reboot the source host or clear its ephemeral campaign cache;
6. resume and verify graph, policy, frontier, observations, pins, budgets, and
   attempt accounting;
7. continue far enough to prove descendant feedback reopens an ancestor;
8. export an executable or debug closure and inspect its sensitive-data report;
9. import from another configured store into a clean compatible maintenance
   environment or store namespace;
10. resume or debug there and compare the authenticated configuration; and
11. attempt restore with deliberately incompatible provenance and confirm
    fail-closed diagnostics before guest resume.

Transfer volume is compared with logical closure size and known destination
objects. A sibling transfer should reuse its shared base. Resume latency is
operational, but missing data must not advance virtual time or alter the result.

- **[CMAN-13]** Manual persistence acceptance MUST include complete process
  termination and loss of ephemeral caches between hibernate and resume. A
  pause that leaves the original processes alive is insufficient.
- **[CMAN-14]** Maintenance transfer MUST prove missing-object reuse,
  authentication, compatible restore, incompatible-provenance rejection, and
  preservation of a recoverable source until destination validation succeeds.

## 14.8 Destructive recovery drills

The destructive drill injects failures at documented semantic or publication
boundaries. Every injection records the expected prior valid state, action,
operator-visible symptom, permitted automatic response, manual recovery, and
post-recovery invariant.

Required injections include:

| Injection | Expected operator-visible result |
| --- | --- |
| Kill one running child | Attempt is retried or localized; no partial graph edge or reward appears |
| Kill the coordinator before observation commit | Restart projects from facts, discards stale reservations, and safely resubmits the attempt |
| Kill the local executor while the coordinator remains live | Coordinator reports operational failure and idempotently resubmits without creating a modeled result |
| Kill the daemon during snapshot publication | Named ref resolves to the complete old or complete new snapshot |
| Reboot with a paused or hibernating campaign | Supported recovery path identifies exactly what is resumable |
| Exhaust campaign-store space during exact capture | Prior ref and finding remain valid; partial staging is reclaimable |
| Remove an archival leaf during multipart upload | Upload resumes or aborts idempotently without publishing an incomplete closure or satisfying durability |
| Expire store credentials during read/write | Status distinguishes authorization from absence/corruption and preserves state |
| Corrupt one tier copy while another remains valid | Status distinguishes corruption from a miss, refuses corrupt bytes, and follows the declared repair/fallback policy |
| Interrupt pack/index publication or repacking | Old index generation remains readable; incomplete packs remain unreachable and reclaimable |
| Fail one VM during atomic world fork | No partial world becomes visible; template remains usable or is invalidated explicitly |
| Alias one child ring or disk overlay in a fault build | Child readiness rejects the resource before guest execution |
| Exceed process, memory, or descriptor budget | Backpressure/demotion is visible; strict semantic priority remains unchanged |
| Request cancellation during child creation | Outcome and accounting are explicit; no orphan runtime remains |

Fault builds may expose a narrow test hook to inject a particular publication
or fork-stage failure. The hook is not a private repair path and must be absent
or disabled in production artifacts. Operators still observe and recover using
public surfaces.

- **[CMAN-15]** Destructive acceptance MUST exercise every failure class in the
  table on both the constrained host and each backend whose failure semantics it
  targets. Recovery MUST preserve the last authenticated campaign state and
  leave no unexplained live child or retained writable resource.
- **[CMAN-16]** Any recovery requiring object deletion, reservation editing, ref
  rewriting, or process signaling outside documented commands is a release-
  blocking operability defect.

## 14.9 Massive-parallelism and long-soak dogfood

The dogfood flight is not merely “leave the daemon running.” It operates a
campaign useful enough that adaptive decisions and retention matter.

The reference flight:

- runs for at least 24 hours; a release candidate target is 72 hours;
- creates and retires at least 10,000 hot children and reaches at least three
  generations of promoted templates;
- sustains the host's declared useful concurrency for repeated intervals;
- includes one million admitted lightweight attempts or the implementation
  phase's reviewed scale equivalent;
- includes a huge integral domain, progressive feedback, dormant ancestors,
  Pareto survival, minimization, and a second fault path;
- crosses at least one planned daemon restart and one operator handoff;
- deliberately enters CPU, RAM/dirty-page, descriptor, and store-throughput
  pressure without exhausting the host outside configured limits;
- hibernates and resumes at least once;
- produces both an expected finding and useful non-failing Pareto candidates;
  and
- finishes with a reviewable retention and GC plan.

Operators inspect the frontier throughout the soak and sample explanations from
early, middle, and late policy states. They record stale or misleading status,
control latency, unexplained idle capacity, unfair starvation, surprising
storage growth, fallback churn, and any need to consult raw daemon logs.

The end-of-flight resource audit checks processes, threads, descriptors, shared
memory, overlay files, cgroups, staging uploads, object pins, and physical store
growth against the campaign's canonical and operational accounting.

- **[CMAN-17]** A dogfood flight MUST demonstrate sustained useful parallelism,
  bounded active resources, lazy dormant width, deep template promotion,
  pressure fallback, operator steering, and clean final resource accounting.
- **[CMAN-18]** A soak with no findings or crashes still fails acceptance if the
  operator cannot explain idle capacity, branch admission, fallback, retention,
  or storage growth from supported campaign views.

## 14.10 Retention and garbage-collection flight

Starting from the completed dogfood campaign, the operator:

1. pins a finding, a Pareto branch, one user-selected midpoint, and a metadata-
   only historical snapshot;
2. requests metadata, finding, debug, executable, and mirror closure plans
   and compares their closure sizes;
3. derives a second campaign sharing objects, then produces a store-wide GC
   plan while a transfer, write-back journal, and attempt protection root are
   active;
4. confirms the plan retains every expected root and identifies cache-only
   exact closures separately from semantic objects;
5. intentionally proposes unpinning the last fast-debug closure and verifies
   the impact warning;
6. cancels the first plan without deletion;
7. changes one pin and the physical inventory generation, regenerates the plan,
   and confirms the old plan is stale;
8. repacks a sparse pack while concurrent readers verify live logical objects;
9. applies the new plan after its grace/confirmation boundary; and
10. replays every retained finding and inspects both derived campaigns and
    metadata-only history afterward.

The hermetic public-process regression is the automated precursor to this
flight. It generates and validates the worked-network fixture, imports it before
endpoint bind, creates and starts the campaign, authenticates live store status,
one retained object, and the complete physical inventory, then stops the owner
and runs public GC plan/apply over an authenticated orphan. It finally
reauthenticates the retained scenario and exact running head after restart. This
proves the porcelain and ownership sequence, but it does not substitute for the
multi-ref, active-transfer, stale-plan, repack, finding-replay, or independent-
operator evidence required below.

- **[CMAN-19]** Manual GC acceptance MUST prove plan/apply separation, stale-plan
  rejection, protection of in-flight roots, explicit loss-of-acceleration
  warnings, and successful replay of all retained findings after collection.

## 14.11 Usability and documentation acceptance

The fresh operator performs the standard flight from the checked-in runbook and
public `--help`/documentation. The feature author may clarify the meaning of the
product under test but may not provide an undocumented Crucible command or
interpret an opaque internal identifier.

The acceptance review records whether the operator can:

- discover the next safe action without reading source;
- distinguish scenario, policy, snapshot, configuration, proposal, attempt,
  finding, and materialization identities;
- understand why work is or is not progressing;
- estimate the consequence of a budget, retention, hibernate, export, or GC
  command before executing it;
- recognize canonical versus operational and canonical versus debugger-derived
  state;
- locate the exact evidence behind a finding or planner explanation; and
- recover from each documented destructive drill without tribal knowledge.

Release acceptance permits at most one non-blocking documentation clarification
per independent flight. Any wrong destructive action encouraged by the CLI,
silent ambiguity about data loss, inability to locate a finding's evidence, or
need for internal state repair is release-blocking. Cosmetic feedback may be
deferred only with an issue and explicit reviewer disposition.

- **[CMAN-20]** Final sign-off MUST include an independent operator's completed
  task checklist, unresolved-defect disposition, documentation changes, and
  explicit approval from the campaign model, QEMU boundary, storage, guest API,
  and operations owners. A failed or blocked safety/recovery task prevents
  release.

## 14.12 Explicit branch and derivation acceptance

The operator performs this flight at a pending guest integer opportunity whose
legal domain is much larger than the active worker pool:

1. inspect the opportunity, its parent `BranchPoint`, generated source,
   expansion statistics, and available realization tiers;
2. issue a finite request with the same stop condition for three values,
   including one already admitted by the generated source;
3. confirm publication creates one request/continuation, not three immediate
   worker jobs or QEMU children;
4. grant capacity one slot at a time and observe lazy proposal/attempt creation;
5. confirm the duplicate value has two causes but one branch edge, execution,
   child configuration, and reward credit;
6. confirm the original generated continuation remains open and resumes after
   feedback;
7. try `branch --all` against the huge domain and verify rejection before a
   request or snapshot is published;
8. derive two otherwise identical strict runs with hot fork enabled and
   disabled, proving edge and result identity is independent of realization
   tier;
9. inspect a retained checkpoint with no pending opportunity and confirm it is
   not presented as a branch point;
10. derive a new campaign from the snapshot with a revised policy and confirm
    that it shares objects without adding an edge to the source campaign; and
11. run a statistical report and confirm an operator execution basis is
    excluded or separately labeled unless a predeclared estimator admitted it,
    while a later duplicate operator cause does not reclassify an earlier valid
    policy sample.

The flight uses `branch`, `derive`, and supported debug-selection surfaces. It
records any deprecated `fork` alias output only to verify that the UI translates
it unambiguously to `branch`; no evidence may use “fork” without saying whether
it means semantic branch, campaign derivation, or QEMU hot fork.

- **[CMAN-21]** Operator acceptance MUST prove additive finite and generated
  sources, lazy admission, duplicate-edge/credit deduplication, huge-domain
  `--all` rejection, and statistical intervention labeling through supported
  public views.
- **[CMAN-22]** Operator acceptance MUST prove that branch, derive, hot-fork
  realization, and debug mutation have distinct effects and terminology, and
  that checkpoint and branch-point presence are independent.

## 14.13 Phase-by-phase manual gates

Manual validation begins before the final CLI phase:

| Implementation phase | Required manual evidence |
| --- | --- |
| Phase 0 | Tabletop of the lifecycle, destructive drill, claims, and evidence manifest |
| Phase 1 | Offline create/inspect/derive/stale-command/pause snapshot flight using canonical objects and linear ancestry |
| Phase 2 | Real guest registers choices, blocks for selections, rejects mismatch, and replays replies. The automated `checks.crucible.phase2.qemuLiveSelectableProduct` exact-restore flight is a prerequisite, not a substitute for the signed operator record. |
| Phase 3 | Human cross-check of guest markers, modeled network evidence, metric windows, objectives, and finding evidence |
| Phase 4 | Direct/RPC component equivalence plus local operator flight through lazy widening, additive finite branching, edge deduplication, backpressure, independent coordinator/executor restart, steering, and explanation |
| Phase 5 | Hibernate/resume, composed-backend outage, tier promotion/eviction, packing/repacking, archival transfer, import, corruption, pin, and store-wide GC flights |
| Phase 6 | Lab audit of QEMU quiescence, mappings, descriptors, rings, disks, COW dirties, fallback, and repeated children |
| Phase 7 | Atomic multi-machine hot fork, massive-parallelism pressure, deep templates, and 24-hour dogfood flight |
| Phase 8 | Independent public-porcelain branch/derive terminology, statistical-intervention, usability, and finding-handoff flight |
| Phase 9 | Full 72-hour release-candidate flight, destructive drill, maintenance transfer, cleanup, and sign-off |

An implementation phase may land behind an inactive development capability
before its operator flight. It may not be described as usable, become a default,
or satisfy the next release milestone until its manual evidence is accepted.

## 14.14 Runbook template

Each checked-in manual runbook uses this structure:

```text
Flight ID and version
Claim(s) under test
Implementation phase and manual gate
Driver, reviewer, observers, and owner sign-offs
Pinned build/provenance and supported capability profile
Host/store/scenario/policy prerequisites
Starting snapshot and expected retained roots
Safety constraints and authorized destructive actions
Ordered public commands/actions
Expected semantic result and operator-visible evidence per step
Required snapshots, exports, telemetry, and reproduction artifacts
Forbidden shortcuts and invalidating conditions
Cleanup and resource audit
Observed result: pass/fail/blocked/observation
Defects, documentation gaps, workarounds, and regression disposition
Final claims and signatures
```

Runbooks are versioned with the implementation and reviewed like protocol
fixtures. A material UI, command, storage, or recovery change updates the
affected runbook and requires the corresponding flight before release.

## 14.15 Relationship to automated testing

Manual and automated validation form a loop:

1. automated gates establish canonical behavior and inject precise failures;
2. manual flights establish that users can invoke, understand, and recover from
   that behavior under realistic conditions;
3. every deterministic defect found manually gains a minimized fixture and
   automated regression where practical;
4. every operability defect gains a runbook or interface change plus a repeated
   independent flight; and
5. accepted evidence pins the exact automated gate results and build under test.

Manual sign-off never waives a failing equivalence, ABI, determinism, storage,
or license gate. Conversely, green automation never waives a failed operator,
recovery, dogfood, or handoff flight.

The release checklist names three manual gates:

```text
gate:campaign-operator-acceptance
gate:campaign-destructive-recovery
gate:campaign-dogfood
```

These gates are satisfied by reviewed evidence-bundle identities, not by an
unstructured CI Boolean. Their manifests are machine-checkable for required
steps, artifacts, build identity, result states, defect dispositions, and owner
sign-offs; the actual human observations remain part of the reviewed bundle.
