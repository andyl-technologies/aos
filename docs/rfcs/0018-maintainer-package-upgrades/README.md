# RFC-0018: Local maintainer package upgrades

- **Status:** Proposed (design-only).
- **Date:** 2026-09-03.
- **Audience:** AOS package, build, test, CLI, and release maintainers.
- **Execution environment:** An interactive maintainer checkout and the
  maintainer's configured AOS/Nix build environment. No background component is
  required.
- **Depends on:** RFC-0017's protected-source publication boundary, but not its
  release transaction or credentials.

## Summary

AOS gains a local-first `aos maintain` workflow that lets a maintainer discover
upstream releases, plan and perform package updates in isolated Git worktrees,
use a bounded agent to repair non-mechanical failures, run the required package
and repository tests, inspect every intermediate result, resume interrupted
work, and explicitly publish a branch and pull request.

The atomic object is an **update unit**, not a Nix package attribute or source
file. One unit may feed several package outputs; one upstream family may have
several simultaneously maintained units. For example, `bazel-7`, `bazel-8`,
and `bazel-9` can all ship in one AOS point release while each tracks only the
latest acceptable release in its own major line.

A versioned `mkUpstream` declaration colocates each unit's upstream identity,
current version, source and generated-input hashes, maintained stream, and
automation policy with the package source. Pure Nix evaluation emits a closed
maintenance inventory. The Rust tool consumes that inventory, queries declared
primary upstreams, treats Repology as an advisory signal, and writes only
schema-defined literal fields through a syntax-aware compare-and-swap editor.

Deterministic mechanics run before agent assistance. The tool selects the
candidate, fetches sources, computes hashes, regenerates declared fixed-output
inputs, formats, evaluates, calculates impact, and runs quick gates. An agent is
invoked only for bounded package repair such as patch refresh or upstream build
changes. It receives no Git, GitHub, release, signing, or unrelated filesystem
authority. The maintainer remains in control of scope, commits, publication,
and merge.

The completed flow is:

```text
declared upstream + Repology advisory observation
                         |
                         v
                local discovery snapshot
                         |
                         v
                  closed update plan
                         |
                         v
             isolated local Git worktree
                         |
                         v
        deterministic version/hash/input update
                         |
                         v
              bounded agent repair loop
                         |
                         v
        quick gates -> complete final-head gates
                         |
                         v
               maintainer inspection/commit
                         |
                         v
             explicit branch push and PR
                         |
                         v
                 human review and merge
                         |
                         v
        RFC-0017 protected-source release flow
```

## Decisions at a glance

| Question | Decision |
| --- | --- |
| Where does the workflow run? | From `aos maintain` in a real maintainer checkout. |
| Is a long-running process required? | No. Every operation is a resumable foreground command. |
| Does AOS use nixpkgs or a nixpkgs updater? | No. The package API, fetchers, inventory, updater, tests, and execution are AOS-owned. |
| What is updated atomically? | An explicit update unit, potentially with several members, source slots, and fixed-output artifacts. |
| How do concurrent major versions work? | Each maintained stream is a separate unit in one upstream family; family membership does not force grouping. |
| Is Repology authoritative? | No. It is a cached advisory signal; the package-declared primary upstream is authoritative. |
| How are Nix files changed? | Through standardized literal metadata and a syntax-aware expected-value editor; never by filename guessing or broad regex. |
| When is an agent used? | Only after deterministic materialization, for a typed package failure and bounded write scope. |
| Can the agent weaken features or tests? | No. Such a proposal is a policy failure. New required dependencies must be complete AOS packages. |
| What makes a run complete? | All policy-selected package/target/impact gates and every `aos test` layer pass on the exact final head. |
| Who publishes the PR? | The maintainer, through an explicit final command using their normal Git identity and authentication. |
| Can the tool merge or release? | No. Human review authorizes merge; RFC-0017 independently rebuilds and publishes from protected source. |

## Load-bearing invariants

1. **Local first.** Inventory, discovery, planning, editing, repair, testing,
   inspection, resumption, and PR preparation work as foreground CLI commands.
2. **AOS is self-contained.** No nixpkgs package, module, updater, host tool, or
   build dependency enters the workflow. External tools are research precedents
   only.
3. **Package declarations are authoritative.** Upstream identity, release
   stream, source inputs, and automation classification are explicit AOS data.
4. **Every package is classified.** Missing or contradictory ownership is
   eventually an evaluation failure, following the precedent of the platform
   inventory.
5. **Automatic edits are constrained.** Writable values are schema-defined
   literals identified by update unit, owner path, field ID, and expected old
   value.
6. **Discovery is not authority.** Repology and other advisory data can find or
   challenge a candidate but cannot select source bytes or override policy.
7. **Mechanics precede inference.** An agent never replaces deterministic
   version policy, downloading, hashing, graph calculation, formatting, or
   validation.
8. **Untrusted code has no maintainer credentials.** Upstream builds and agent
   tools cannot access Git/GitHub, signing, release, SSH-agent, or unrelated
   host credentials.
9. **Work is inspectable and resumable.** Every effect has durable local state,
   immutable evidence, an expected input, and an idempotent recovery rule.
10. **Green is commit-specific.** Any edit or rebase invalidates prior results;
    unavailable or indeterminate required tests leave the run incomplete.
11. **The maintainer owns publication.** Branch push and PR creation are
    explicit, reviewable final operations. The tool never merges or releases.
12. **Update and release evidence remain separate.** RFC-0017 evaluates the
    merged protected source and repeats its own complete release transaction.

## Documents

| File | Contents |
| --- | --- |
| [`00-goals-and-model.md`](00-goals-and-model.md) | Goals, non-goals, terminology, package archetypes, and workflow model |
| [`01-package-contract-and-inventory.md`](01-package-contract-and-inventory.md) | `mkUpstream`, maintained streams, source/artifact slots, classification, inventory, and mutation identity |
| [`02-local-tool-architecture.md`](02-local-tool-architecture.md) | Rust boundaries, CLI, local state, worktrees, effects, output contracts, and Git handoff |
| [`03-discovery-and-version-policy.md`](03-discovery-and-version-policy.md) | Primary providers, Repology, candidate records, version schemes, source verification, grouping, and risk |
| [`04-execution-and-agent-loop.md`](04-execution-and-agent-loop.md) | Deterministic transaction, state machine, failure taxonomy, agent capabilities, and recovery |
| [`05-validation-and-evidence.md`](05-validation-and-evidence.md) | Quick/final tests, affected graph, exceptional gates, evidence, reporting, and metrics |
| [`06-maintainer-machine-security.md`](06-maintainer-machine-security.md) | Local threat model, process isolation, credential handling, worktree protection, and publication safeguards |
| [`07-implementation-plan.md`](07-implementation-plan.md) | Pull request sequence, migration, pilots, acceptance criteria, and rollout |
| [`08-decisions-and-open-questions.md`](08-decisions-and-open-questions.md) | Locked decisions, rejected alternatives, and implementation-time questions |

## Relationship to RFC-0017

[RFC-0017](../0017-canonical-hub-publishing/README.md) starts from a reviewed,
protected source commit and performs a monotonic release transaction. Package
upgrade work is iterative: versions, sources, patches, inputs, and tests may
change many times before a merge exists. The two workflows therefore have
separate plans, journals, states, and credentials.

They share stable package/update-unit and source identity so a release can say
which upstream unit produced a package. They do not share build authority. An
update dossier helps reviewers decide whether to merge; the release flow
independently resolves, rebuilds, qualifies, and publishes the merged source.

## External design basis

Repology's project/status model is useful for stale-package discovery, but its
API is rate-limited, requires an identifying user agent for bulk use, and does
not promise stability. See the pinned
[Repology API source](https://github.com/repology/repology-rs/blob/4f10afe4209e8d8e28d9622090a6ddded4a901fc/repology-webapp/templates/api.html).

Renovate demonstrates useful datasource/manager/versioning separation, but its
Nix manager updates flake inputs rather than AOS package expressions. See the
[Renovate Nix manager](https://docs.renovatebot.com/modules/manager/nix/).
nix-update demonstrates fixed-output hash repair and secondary-input ordering,
but AOS does not adopt its nixpkgs/Python runtime or source writer. See its
pinned [README](https://github.com/Mic92/nix-update/blob/4f9f53413ba6e8b19de1b3a0500f17910320eda4/README.md).

OWASP's prompt-injection guidance says there is no foolproof model-level
prevention and recommends least privilege, external-content separation,
deterministic validation, and human approval. See
[LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).
The agent design assumes upstream text and build output can manipulate the model
and relies on hard local capabilities rather than prompt instructions alone.
