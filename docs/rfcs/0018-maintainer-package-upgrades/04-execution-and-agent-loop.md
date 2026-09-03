# Execution and agent repair loop

## Run state machine

One run executes one closed campaign from one clean base commit. A campaign has
one or more unit/component target vectors. Its normal states are:

```text
observed
  -> selected
  -> planned
  -> worktree-ready
  -> materializing
  -> policy-valid
  -> quick-gated
  -> repairing
  -> candidate-accepted
  -> committed
  -> final-gated
  -> ready-for-pr
  -> pr-published
  -> awaiting-remote-authorization
  -> merge-eligible-observed
  -> merged-observed
  -> release-handoff
```

Side or terminal states are:

```text
no-change       no acceptable newer candidate exists
superseded      a newer compatible candidate replaces an unreviewed run
blocked-human   scope, legal, policy, or design input is required
quarantined     source identity or assurance evidence conflicts
rejected        the maintainer rejects the candidate or patch
abandoned       the maintainer intentionally stops and retains evidence
failed          a terminal policy/infrastructure failure exhausts its budget
```

State transitions are pure and append-only. Filesystem, Nix, network, agent,
test, and Git effects implement a transition's typed intent, then append its
result. Resume never infers a success from missing state.

## Attempts

Every source-tree generation is a reconstructible attempt:

- attempt zero is the deterministic materialization;
- an accepted agent patch creates the next attempt;
- an adopted maintainer edit creates a human attempt;
- a rebase, target change, or history rewrite creates a new plan generation;
- each attempt records its parent head/tree, canonical patch, file manifest,
  necessary new text content, and invalidates dependent gates.

Attempts are content-addressed local records protected from accidental
corruption by the journal chain and durable tip; they are not cryptographically
immutable against the maintainer account. Logs can be garbage-collected by
retention policy, but their digest, exit class, attempt association, and
disposition remain in the journal.

## Deterministic transaction

The first attempt does not use an agent:

1. validate the closed campaign plan, inventory envelope, base commit/tree,
   frozen coordinator identity, local lock, and clean isolated worktree;
2. fetch every selected component source slot through the bounded resolver;
3. verify origin/redirect/checksum/signature policy and compute hashes;
4. use the syntax-aware compare-and-swap writer to update current-version and
   source-hash fields;
5. materialize secondary fixed-output artifacts in declared dependency order;
6. update their hash fields and only generated lock/vendor inputs whose path,
   format, expected preimage, transformation, and postcondition are in the plan;
7. run `aos fmt` and reject formatting outside the plan's paths;
8. re-evaluate maintenance inventories and package/check graphs before and
   after the edit;
9. require the exact planned authored-field/generated-output delta, then match
   recomputed URLs, derivations, artifacts, checks, and impact to the allowed
   derived-effect closure;
10. validate path, file type, mode, symlink, submodule, size, dependency,
    feature, test, and license diff policy;
11. calculate the quick and final gate plans;
12. run quick validation and record the attempt.

For ordinary `fetchurl`, download and hash the resolved target directly. For a
declared secondary fixed-output derivation, the materializer may use an
empty-hash/mismatch repair when the AOS builder requires it, but the operation
is typed and ordered. This follows the useful pattern in nix-update's pinned
[dependency hash implementation](https://github.com/Mic92/nix-update/blob/4f9f53413ba6e8b19de1b3a0500f17910320eda4/nix_update/dependency_hashes.py)
without importing nix-update or nixpkgs.

Preparation that must retrieve dependency data runs only inside the mandatory
local confinement backend with destination policy and package-manager-specific
script/rule restrictions. It produces a fixed content-addressed input. The
normal AOS package build consumes that input with network disabled. No package
gains ambient network access. If the configured host cannot enforce the required
filesystem/process/network boundary for a materializer, that kind is unavailable
and the run stops action-required.

## Mutation gateway

Every deterministic or agent-proposed patch passes the same local gateway. It
checks:

- expected plan, base, worktree HEAD, and parent tree;
- allowed owner paths and schema-defined semantic fields;
- exactly-one-match and expected-old-value conditions;
- path traversal, symlink, submodule, binary, file-mode, and file-kind rules;
- maximum changed files, lines, bytes, and generated-output sizes;
- forbidden automation, release, signing, licensing-policy, and unrelated
  package paths;
- dependency additions/removals, feature changes, test changes, and license
  changes;
- Nix syntax, formatting, inventory validity, and before/after semantic delta;
- risk escalation and new human gates.

Automatic gateway acceptance is limited to declared version/source/artifact
fields, declared generated-output transformations, and package-specific
machine-checkable invariants. Changes to patches, phases, feature/configure
flags, dependency shape, hardening, tests, licenses, or security-sensitive
metadata always block for maintainer inspection and a new approved plan
generation, even if the agent was permitted to propose them. General syntax and
test success cannot prove that such a change preserved intent.

The gateway can accept, reject, or escalate/block. It cannot silently rewrite a
proposal into something close to the plan. A rejection becomes structured input
for the next inspection or repair attempt.

## Failure taxonomy

Classify failure before deciding whether an agent can help:

| Failure | Default action |
| --- | --- |
| Provider unavailable or rate-limited | Retry within budget or stop `unknown` |
| Ambiguous/disagreeing upstream identity | Quarantine for maintainer source review |
| Same identity with changed bytes | Quarantine as a supply-chain anomaly |
| Plan/base/expected-value mismatch | Expire and re-plan; never guess |
| Unknown/dynamic Nix mutation | Assisted/manual; no regex fallback |
| Resolver/materializer implementation failure | Tool failure; do not ask an agent to mask it |
| Patch no longer applies | Agent-eligible inside patch/package scope |
| Compile/package-test failure | Agent-eligible with bounded sanitized logs |
| New required dependency | Agent may prepare a proposal; maintainer must approve a new multi-unit campaign plan |
| License/bootstrap/QEMU/release-boundary change | Block for the required human workflow |
| Flaky or unavailable host capability | Retry/classify under test policy; never edit tests to hide it |
| Agent budget exhausted | Stop `blocked-human` with the best current worktree and dossier |

An agent never repairs infrastructure or trust-policy failures by changing the
package.

## Agent eligibility

Useful agent tasks include:

- rebasing or replacing a downstream patch;
- adapting flags, paths, or phases to an upstream build-system change;
- fixing legitimate compiler or API incompatibilities;
- preparing a complete AOS package for an approved new dependency;
- updating package-authored tests for a reviewed interface change;
- analyzing release notes and compatibility implications;
- reducing a build failure to a clear maintainer decision.

The agent is not used for:

- upstream/project authority;
- version ordering or release selection;
- source download, hash, signature, checksum, or provenance conclusions;
- expanding its own paths or dependency scope;
- accepting its patch;
- deciding that a test passed or is unnecessary;
- committing, pushing, creating a PR, merging, signing, or releasing.

`--agent none` follows exactly the same deterministic transaction and stops with
typed manual repair instructions. A run can switch from no-agent to an approved
local agent profile without changing its plan authority.

## Agent task envelope

Each repair receives a closed `aos.package-update-agent-task/v1`:

- run, plan, attempt, base, HEAD, and tree digests;
- unit, members, target, classification, lifecycle, and risk;
- exact typed failure and bounded sanitized log excerpts;
- read-only repository/source context selected by policy;
- permitted files, file kinds, and semantic scope;
- allowed query/test operations;
- forbidden paths and operations;
- required validation after a proposal;
- remaining attempts, elapsed time, compute, disk, output, and token budget;
- an explicit declaration that upstream content and logs are untrusted data.

The agent returns a closed result containing a proposed patch, explanation,
requested scope changes, claimed tests for context only, and usage. Only the
gateway and AOS test runner determine whether the patch is valid.

## Agent filesystem view

Do not give the agent a writable Git worktree or `.git` control. Construct a
bounded disposable view inside the verified local confinement backend from:

- the planned package owner and declared shared files;
- approved patch/test files;
- selected dependency interfaces;
- bounded source/release documentation;
- current sanitized failure output.

The agent emits a patch against that view. The maintainer tool terminates and
reaps the complete confined worker process tree before applying the patch to the
real run worktree. Gateway validation and expected-tree checks happen outside
the worker. The containment boundary—not environment filtering—prevents the
agent from creating commits, changing refs, reading unrelated working files, or
bypassing the journal.

When broader repository context is necessary, the agent requests a typed path
expansion. The tool displays the reason and requires maintainer approval before
creating a new task envelope. Approval does not automatically authorize writes
to the newly readable path.

## Agent tools

Expose typed operations, not a general maintainer shell:

- read a bounded approved file or source excerpt;
- search approved paths with result and size limits;
- propose a patch;
- request an AOS parse, format-check, evaluation, package build, or named test;
- receive bounded, secret-scrubbed results;
- request scope expansion with a structured reason;
- stop with a maintainer question.

The controller command executes Nix/build/test actions outside the agent
process, records the exact invocation, and returns only bounded results. The
agent cannot acquire a shell inside the maintainer's general checkout, invoke
Git, contact GitHub, or reach RFC-0017 release commands.

## Forbidden repairs

The mutation policy rejects proposals that obtain green status by:

- disabling an upstream feature;
- removing a required build/runtime dependency;
- weakening hardening, sandboxing, source assurance, or closure checks;
- skipping, deleting, broadening tolerances in, or making tests non-failing;
- enabling network access in a hermetic build;
- importing host tools or nixpkgs;
- altering update risk/classification to escape a gate;
- editing contributor authorization, QEMU licensing, release, signing, or
  publication policy;
- adding unreviewed binaries, submodules, generated archives, or large opaque
  files.

If a new dependency is legitimate, package it completely in AOS and create a
new plan generation with explicit maintainer-approved scope. If a test or
feature really must change, the evidence calls it out as a human-reviewed
semantic change rather than an automatic repair.

## Iteration policy

One accepted patch creates one attempt. After acceptance:

1. recalculate inventory, dependency/check graph, semantic diff, and risk;
2. invalidate every result not bound to the new tree/commit;
3. run the narrow failing gate first for feedback;
4. run the complete quick gate set when it passes;
5. update status/evidence and present the next action;
6. continue only within the plan and remaining budget.

Default budgets differ by risk. Low and normal units can receive a small number
of bounded repair attempts. High-risk units get fewer automatic attempts and
earlier maintainer review. Exceptional units are human-led; agent assistance is
enabled only for a separately approved task.

The objective is the smallest policy-conforming, understandable patch—not green
status at any cost.

## Superseding and target changes

A newer patch release may supersede an unreviewed run only when:

- it remains in the same stream;
- policy permits automatic superseding;
- the current branch has no unadopted human work;
- a new immutable discovery snapshot and plan generation are created;
- all edits and tests restart from the new target.

Never retarget an actively reviewed change across a major, branch, channel, or
lifecycle boundary. Concurrent major units remain independent.

## Rebasing and human edits

Rebasing onto a newer protected base invalidates source-commit and test
evidence. The tool creates a new plan generation, revalidates semantic scope,
and reruns quick/final gates.

Unrecognized worktree changes stop automation. The maintainer may inspect and
adopt them as a human attempt or restore them manually. The tool never resets,
deletes, or overwrites them.

## Interruption and recovery

Each effect writes an intent with expected inputs, produces temporary output,
then atomically records completion. Resume handles:

- a completed idempotent effect whose journal append was interrupted;
- a partial temporary download/materialization that must be discarded or
  resumed by verified range identity;
- a killed Nix/test child whose exit is unknown;
- an agent response without an accepted patch;
- a candidate commit without final test evidence;
- a pushed branch whose PR creation failed;
- a remote branch whose head no longer matches local state.

Ambiguity stops for inspection. Recovery never marks an unobserved action
successful and never repeats a Git write without expected-head protection.

## PR preparation

The generated PR has stable sections:

- campaign, ordered units, families, streams, members, component vectors, and
  package current/target identities;
- primary upstream and Repology advisory evidence;
- source/artifact/checksum/signature changes;
- dependency, patch, feature, test, license, and platform changes;
- risk and affected graph;
- deterministic and agent-assisted repair summary;
- final Git head and complete gate results;
- explicit human/specialist checks and unresolved warnings;
- local evidence digest and reproduction commands.

Commit messages and PR text contain no AI attribution, provider/model name,
generated-by marker, or agent session link. They may accurately say that a
bounded automated repair changed specific files when that distinction helps
review, without attributing authorship to a vendor.

The updater never marks a change merged or handed to the release flow merely
because it was published. It observes the eventual reviewed merge, binds that
identity to the run, and records that RFC-0017 can independently consume the
protected commit.

Local identity/signature checks are preflight only. After publication the run
is `awaiting-remote-authorization`; a later foreground `status`/`inspect`
observation can record the repository's fail-closed contributor-authorization,
review, and other exact-head checks. Only then can it become
`merge-eligible-observed`. The local tool never renders its preflight as an
authoritative contributor-authorization success.
