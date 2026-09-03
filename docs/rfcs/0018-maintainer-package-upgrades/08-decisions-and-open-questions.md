# Decisions and open questions

## Locked decisions

1. The product is foreground, local-first maintainer tooling exposed through
   `aos maintain`; no background component is required.
2. AOS owns the package update contract, inventory, provider adapters, source
   editor, materializers, validation, journal, evidence, and Git handoff.
3. No nixpkgs package/module/updater or host-tool dependency enters package or
   test derivations. External updater projects are precedents only.
4. The atomic policy object is an update unit, not a package attribute or file.
   A unit may contain several independently versioned components.
5. Execution is a campaign: an ordered set of one or more units sharing one
   base, worktree, plan, journal, gate set, evidence dossier, and PR.
6. Family, stream, unit, member, component, source, artifact, cohort, and
   campaign are distinct identities/relationships.
7. Concurrent major/LTS lines have separate update units and release policies
   and may coexist in one AOS point release.
8. A new upstream major does not automatically replace, retire, or mutate an
   existing stream.
9. `mkUpstream` colocates authoritative package projection and per-component
   current/discovery/policy/source/artifact data with the values it controls.
10. Component candidates are selected independently, checked as a complete
    compatible vector, then projected deterministically to the package version.
11. Pure Nix evaluation emits canonical content only. The Rust command wraps it
    in a repository envelope binding remote, clone/common-dir, commit/tree or
    dirty content, inventory, target set, and frozen controller identity.
12. The maintenance universe reconciles all supported lint/build/release roots,
    aliases, generated/local/frozen helpers, and stdenv/package-set roots.
13. Every AOS fixed-output/source constructor exposes typed identity and builder
    parameters. A graph audit accounts for every reachable fixed-output input.
14. Every package is eventually classified automatic, assisted, manual, frozen,
    local, generated, or alias; missing/contradictory coverage fails evaluation.
15. Automatic fields are standardized literals. Mutation proves both the exact
    authored delta and the closed set of permitted derived evaluation effects.
16. Generated outputs additionally declare path, format, preimage, typed
    transformation, and postcondition. No arbitrary update script is accepted.
17. Nix source positions are diagnostic only. Line numbers, filename guessing,
    global text replacement, and broad regex are not mutation authorities.
18. Package-declared primary upstreams are authoritative. Repology is a cached
    advisory/discrepancy signal with a host-wide local rate budget.
19. Every provider proves coverage through the current identity or declared
    stream bound. Truncation, outage, ambiguity, incompatible parsing, or stale
    required evidence is unknown, not current.
20. Stream selection uses a closed version-range, channel, immutable VCS-lineage,
    or manual selector. Force-pushed or unreachable VCS identity quarantines.
21. Raw provider identity, upstream identity, comparison identity, and package
    projection are distinct. A projection collision quarantines unless covered
    by an explicit canonical-alias policy.
22. Observation freshness and release stabilization are separate clocks with a
    declared time basis. A missing required timestamp is unknown.
23. Source URL templates are a typed AST with component-aware encoding; version
    data cannot change URL scheme, authority, or other structural fields.
24. Same upstream identity with changed bytes is quarantined rather than
    silently rehashed.
25. Source results say `verified-authentic`, `origin-integrity`, `failed`, or
    `unknown`; transport plus content hash alone is not described as authentic.
26. Plans bind base/envelope/controller, ordered campaign units, complete
    component vectors, observations, exact fields/paths, materializers, risk,
    gates, and budgets before effects.
27. Deterministic version/source/hash/artifact/format/eval/graph/test work runs
    before agent assistance.
28. Candidate evaluation, materialization, agent tools, and tests require a
    verified local confinement backend; environment filtering is not isolation.
29. Candidate Nix evaluation is empty-environment, pure/restricted, import-
    bounded, IFD-disabled, network-disabled, resource-bounded, and confined.
30. Agent assistance is optional, provider-neutral, bounded to a typed failure,
    and disabled entirely with `--agent none`.
31. The agent receives neither writable Git metadata nor GitHub, signing,
    release, SSH-agent, or unrelated filesystem authority.
32. Every agent patch passes the same deterministic mutation, semantic-diff,
    path, feature, dependency, test, license, and risk gateway.
33. The agent cannot select upstream authority, expand scope, accept a patch, or
    declare a gate successful. Changes to patches, phases, flags, dependencies,
    hardening, tests, or licenses always require a new human-approved plan.
34. New required dependencies are complete AOS packages and require an explicit
    multi-unit campaign approved by the maintainer.
35. Local state is durable, bounded, corruption-detecting, inspectable, and
    resumable. Each retained attempt includes enough patch/file content to be
    reconstructed; it is not claimed tamper-proof against the maintainer.
36. Each campaign uses an isolated worktree and a `dplecki/upgrade-*` branch with
    expected-head/tree checks. Human work is never overwritten.
37. Final validation runs all required unit/component/target/impact gates and
    every `aos test` layer on the exact candidate commit.
38. Missing confinement, KVM, target, builder, or test capability leaves an
    explicit action-required result; validation is never silently narrowed.
39. The frozen base controller owns the run. Candidate `pkgs.aos` is tested as
    an artifact and never becomes the coordinator executing later phases.
40. The maintainer accepts and commits the final tree with their configured Git
    identity/signing policy. The tool does not synthesize DCO sign-off.
41. Local preflight checks identity and signature policy but records contributor
    authorization as `pending-remote`; only an exact-head remote observation can
    record `merge-eligible-observed`.
42. Branch push and PR creation are an explicit final, hook-free, one-shot
    `publish-pr` action using sanitized Git configuration, an exact refspec,
    displayed remote effect, and expected remote head.
43. The tool cannot force-push, merge, tag, release, publish packages, or invoke
    RFC-0017 release authority.
44. Commit/PR text contains no AI/vendor/model attribution, generated-by text,
    or agent session links.
45. Update evidence is reviewer evidence, not release provenance. RFC-0017
    independently rebuilds and qualifies the merged protected source.

## Rejected alternatives

### Use nixpkgs or nixpkgs tooling as the updater

Rejected because AOS is a self-contained package/build universe. Depending on
nixpkgs would violate hermeticity and make AOS's package contract subordinate to
another distribution's builders and conventions.

### Configure Renovate as the control plane

Rejected because its Nix manager addresses flake inputs, while AOS updates are
semantic transactions over versions, several source/generated hashes, patches,
dependencies, platforms, and AOS-specific tests. Custom regex and post-update
commands would leave the real updater in opaque glue and create two state
machines.

### Execute nix-update or nixpkgs-update

Rejected as runtime architecture because their environments and package
semantics are not AOS's. Their failure handling and fixed-output algorithms can
inform reviewed AOS-native implementations.

### Let Repology select the version and URL

Rejected because Repology aggregates repository records, normalizes versions,
can report several newest/untrusted values, and does not provide authoritative
AOS source identity. It is an advisory observation only.

### Treat a bounded provider result page as complete

Rejected because releases from other streams may fill the page and hide the
current or next in-policy identity. An adapter must prove coverage through the
current identity or stream bound; otherwise the result is unknown.

### Compare every package with the family's global newest release

Rejected because concurrent major, LTS, bootstrap, and security-only lines are
intentional. Selection occurs inside each declared maintained stream.

### Treat one package attribute as one update

Rejected because shared sources feed multiple attributes, aliases are not
independent upstreams, and one package can contain several source/generated
inputs.

### Treat a multi-component package as one scalar version

Rejected because components can advance independently and can have different
providers, release policies, source identities, and failure states. Selection
produces a complete component vector; a separate typed projection derives the
package version.

### Run cohort members as independent updates

Rejected because compiler/toolchain cohorts and newly required dependencies can
be valid only as a group. Their ordered units use one campaign transaction and
cannot produce individually publishable partial results.

### Keep update metadata in one central hand-written map

Rejected because it would drift from the source values it edits and duplicate
ownership. Package/shared-source declarations are canonical; the central
inventory is generated and validated.

### Infer update policy from URLs and filenames

Rejected because names cannot express project mapping, maintained streams,
prerelease policy, shared ownership, generated hashes, or dynamic/composite
sources reliably.

### Claim a Git commit from pure Nix evaluation

Rejected because pure evaluation cannot authoritatively identify the repository
or account for dirty content. Nix emits content; the foreground Rust command
adds the repository and frozen-controller envelope.

### Audit only declared source slots

Rejected because an undeclared reachable fixed-output derivation would be
invisible precisely when the contract is incomplete. Every AOS source
constructor is instrumented and the evaluated input graph is reconciled with
the declared slots.

### Use source positions or regex as the editor

Rejected because evaluation wrappers and `inherit` obscure lexical origins,
while regex can update the wrong hash/version in multi-input files. Automatic
updates use a constrained literal syntax and syntax tree.

### Run arbitrary package-authored update scripts

Rejected because scripts become an unbounded execution and mutation interface.
Reusable work becomes a reviewed typed AOS materializer; one-off complexity is
assisted or manual.

### Ask the agent to perform the whole update

Rejected because release selection, source identity, hashing, semantic scope,
and test completion are deterministic or human authorities. Agent use begins
only with a typed repair failure.

### Give the agent the writable worktree and normal shell

Rejected because prompt-injected source/log text could manipulate Git, read
unrelated files, obtain credentials, or bypass the journal. The agent uses a
bounded disposable view and returns a patch to a deterministic gateway.

### Treat environment filtering as process isolation

Rejected because hostile candidate code can inspect processes, filesystems,
sockets, credentials, and descendants without an operating-system boundary.
Sensitive execution requires the verified local confinement contract.

### Make passing affected tests sufficient for completion

Rejected because affected selection is optimized feedback, not a complete
repository guarantee. The final exact head runs every required AOS test layer
and platform/risk gate.

### Mark unavailable tests skipped

Rejected because lack of host capability is not evidence of success. The run
remains incomplete with an actionable missing-capability report.

### Disable upstream features to avoid new dependencies

Rejected by AOS package completeness. New dependencies are built as complete
AOS packages and reviewed as expanded scope.

### Automatically commit, push, or open a PR as part of `run`

Rejected because source repair and maintainer publication have different
credential and review boundaries. Acceptance, commit, and `publish-pr` are
explicit stages.

### Automatically merge a green update

Rejected. Complete evidence informs human review but does not replace it.

### Reuse the RFC-0017 release plan or journal

Rejected because update work is mutable and iterative while a release begins
from a protected source commit and advances monotonically. They share identity,
not state or authority.

## Open implementation questions

These do not change the load-bearing architecture but must be resolved by the
named implementation PR with fixtures and a recorded decision.

### Exact Nix schema ergonomics

Finalize `mkUpstream` field names, whether current version forms can use a
short form when identical, and the `forPackage` member interface during PR 2.
The resulting inventory semantics and literal mutation boundary are fixed even
if author-facing spelling improves.

### Syntax tree library

Select and pin a Rust Nix parser that preserves trivia/comments and can identify
the constrained attrset reliably. The PR 6 fixture corpus—not library API
preference—decides suitability. The writer must remain replaceable behind a
small semantic edit interface.

### Canonical local journal representation

Decide whether append-only canonical NDJSON plus rebuildable JSON indexes is
sufficient or whether a local SQLite projection materially improves queries.
The canonical event records, digests, retained attempt material, locking,
recovery, flush/rename/directory-sync protocol, and export format do not depend
on the projection choice.

### Local confinement implementation

Validate the exact Linux namespace/subordinate-UID/syscall/cgroup construction
and the Darwin disposable-VM transport in PR 7. The externally enforced
filesystem, process, credential, network, resource, teardown, and restricted-
evaluation contract is fixed; a platform remains action-required until its
implementation passes the hostile fixture suite.

### Initial provider coverage

Use the completed inventory census to select adapters that cover the greatest
number/risk of maintainable units. Do not implement a provider merely because
another updater supports it.

### Signature and checksum policy details

Inventory current upstream verification practices, then define per-component
anchor requirements and transition behavior within the fixed
`verified-authentic`/`origin-integrity`/`failed`/`unknown` outcome vocabulary. A
package losing a previously required verification path must quarantine.

### Freeze review policy

Choose default review intervals and owners for bootstrap/historical/security-
only units. An expired freeze is always visible; the interval can vary by risk.

### Risk thresholds and reverse-dependency canaries

Calibrate risk weights, closure thresholds, stable sampling, and repeat-build
requirements with pilot timing/results. The risk floor and monotonic escalation
rules are fixed.

### Candidate commit history

Decide whether accepted repair attempts remain as separate commits or are
squashed before final validation. In either case, tests bind to the exact head
eventually pushed, and publication cannot rewrite a tested head afterward.

### GitHub authentication surface

Choose the local authentication mechanism for `publish-pr` that fits existing
AOS dependencies and maintainer practice. The command must remain a one-shot
publisher with sanitized Git configuration, disabled hooks, exact refspec,
expected remote head, and no merge/tag/release operation.

### Agent model adapter

Select the first provider-neutral request/response boundary and credential
source. Agent tools must remain behind AOS capabilities, and `--agent none`
must retain full deterministic behavior.

### Full-suite resource policy

Measure local CPU, disk, elapsed time, and KVM/target requirements during the
pilot. Improve caching and gate ordering without reducing final completeness.
Missing capability remains action-required.

### Repology mapping review UX

Determine how `scan` presents ambiguous projects and records a reviewed mapping
change in package metadata. The mapping remains explicit source code, not
mutable hidden local state.

### Event/log retention defaults

Set bounded defaults from pilot data, with longer retention for merged,
rejected, quarantined, and exceptional runs. Cleanup must preserve the minimum
identity/result/digest tombstone.

## Deferred extensions

- Additional typed ecosystem/provider/materializer adapters.
- Security advisory correlation and update priority, without making an advisory
  database authoritative for source identity.
- A static AOS package/version feed generated from RFC-0017 release inventory
  for Repology ingestion.
- Independently authenticated test-result statements.
- Richer terminal UI over the same command/result schemas.

Each extension must first work through the foreground local command and retain
the same plan, capability, evidence, and human-publication boundaries.
