# Decisions and open questions

## Locked decisions

1. The product is foreground, local-first maintainer tooling exposed through
   `aos maintain`; no background component is required.
2. AOS owns the package update contract, inventory, provider adapters, source
   editor, materializers, validation, journal, evidence, and Git handoff.
3. No nixpkgs package/module/updater or host-tool dependency enters package or
   test derivations. External updater projects are precedents only.
4. The atomic maintenance object is an update unit, not a package attribute or
   file.
5. Family, stream, unit, member, component, artifact, and cohort are distinct
   identities/relationships.
6. Concurrent major/LTS lines have separate update units and release policies
   and may coexist in one AOS point release.
7. A new upstream major does not automatically replace, retire, or mutate an
   existing stream.
8. `mkUpstream` colocates authoritative upstream/current/source/artifact/policy
   data with the source values it controls.
9. Pure Nix evaluation emits a closed canonical maintenance inventory consumed
   by a pure Rust model.
10. Every package is eventually classified automatic, assisted, manual, frozen,
    local, generated, or alias; missing/contradictory coverage fails evaluation.
11. Automatic fields are standardized literals. Mutation uses unit/owner/field
    identity and expected old values through a syntax-aware editor.
12. Nix source positions are diagnostic only. Line numbers, filename guessing,
    global text replacement, and broad regex are not mutation authorities.
13. Package-declared primary upstreams are authoritative. Repology is a cached
    advisory/discrepancy signal.
14. Provider outages, mapping ambiguity, parse incompatibility, and stale
    required evidence are unknown, not current.
15. Same upstream identity with changed bytes is quarantined rather than
    silently rehashed.
16. Plans bind base, inventory, observations, current/target identity, exact
    fields/paths, materializers, risk, gates, and budgets before effects.
17. Deterministic version/source/hash/artifact/format/eval/graph/test work runs
    before agent assistance.
18. Agent assistance is optional, provider-neutral, bounded to a typed failure,
    and disabled entirely with `--agent none`.
19. The agent receives neither writable Git metadata nor GitHub, signing,
    release, SSH-agent, or unrelated filesystem authority.
20. Every agent patch passes the same deterministic mutation, semantic-diff,
    path, feature, dependency, test, license, and risk gateway.
21. The agent cannot select upstream authority, expand its own scope, weaken
    features/tests/hermeticity, accept a patch, or declare a gate successful.
22. New required dependencies are complete AOS packages and require a new
    maintainer-approved plan scope.
23. Local state is durable, bounded, append-only at its journal boundary,
    inspectable, and resumable without a resident process.
24. Each run uses an isolated worktree and a `dplecki/upgrade-*` branch with
    expected-head/tree checks. Human work is never overwritten.
25. Final validation runs all required package/target/impact gates and every
    `aos test` layer on the exact candidate commit.
26. Missing KVM, target, builder, or test capability leaves an explicit
    action-required result; validation is never silently narrowed.
27. The maintainer accepts and commits the final tree with their configured Git
    identity/signing policy. The tool does not synthesize DCO sign-off.
28. Branch push and PR creation are an explicit final `publish-pr` action with
    a displayed remote effect and expected remote head.
29. The tool cannot force-push, merge, tag, release, publish packages, or invoke
    RFC-0017 release authority.
30. Commit/PR text contains no AI/vendor/model attribution, generated-by text,
    or agent session links.
31. Update evidence is reviewer evidence, not release provenance. RFC-0017
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

### Compare every package with the family's global newest release

Rejected because concurrent major, LTS, bootstrap, and security-only lines are
intentional. Selection occurs inside each declared maintained stream.

### Treat one package attribute as one update

Rejected because shared sources feed multiple attributes, aliases are not
independent upstreams, and one package can contain several source/generated
inputs.

### Keep update metadata in one central hand-written map

Rejected because it would drift from the source values it edits and duplicate
ownership. Package/shared-source declarations are canonical; the central
inventory is generated and validated.

### Infer update policy from URLs and filenames

Rejected because names cannot express project mapping, maintained streams,
prerelease policy, shared ownership, generated hashes, or dynamic/composite
sources reliably.

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
The canonical event records, digests, locking, recovery, and export format do
not depend on the projection choice.

### Initial provider coverage

Use the completed inventory census to select adapters that cover the greatest
number/risk of maintainable units. Do not implement a provider merely because
another updater supports it.

### Signature and checksum policy vocabulary

Inventory current upstream verification practices, then define typed
`required`, `optional-recorded`, `not-offered`, and transition behavior. A
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
AOS dependencies and maintainer practice. The command must isolate credentials,
support an expected remote head, and expose no merge/tag/release operation.

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
